//! A gRPC service with a bidirectional streaming method, in a Wasm guest.
//!
//! ```text
//!   client ──frame──▶ ┌──────────┐ ──frame──▶ client
//!   client ◀─frame─── │  Session │ ◀─frame─── client
//!                     └──────────┘
//!            one task, both directions, neither waiting for the other
//! ```
//!
//! # Why this is possible at all
//!
//! `wasi:http/incoming-handler` looks request/response, and half of it is: the
//! guest is called once and returns once. But `response-outparam.set` is
//! documented to *"allow execution to continue after the response has been
//! sent"*, and `incoming-request.consume` borrows rather than consumes — so
//! the request body and the response body are two independent resource trees
//! the guest may hold at the same time. The response head goes out first, and
//! everything after it is a conversation.
//!
//! [`Session`] is where that happens. It is an `http_body::Body` that owns the
//! *request* body: every time the host asks it for the next response frame it
//! first reads whatever the client has sent, answers it, and hands back the
//! answer. One task alternating, rather than two running — which is enough for
//! a request/response signing protocol and is worth naming as the limit it is.
//!
//! # What this is not
//!
//! There is no cryptography here. The messages are shaped like signing-session
//! traffic so the transport and the authorization can be settled before a key
//! depends on either, and `Sign` echoes rather than signs.

mod framing;

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use framing::{frame, Deframer};
use http_body::{Body as HttpBody, Frame};
use prost::Message as _;
use wstd::http::{Body, Error, HeaderMap, Request, Response, StatusCode};

// --- the wire format, mirroring proto/enclave/cosign/v1/session.proto -------

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum Kind {
    Unspecified = 0,
    Hello = 1,
    Round = 2,
    Finish = 3,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ClientMsg {
    #[prost(string, tag = "1")]
    pub session_id: String,
    #[prost(uint64, tag = "2")]
    pub seq: u64,
    #[prost(enumeration = "Kind", tag = "3")]
    pub kind: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub payload: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ServerMsg {
    #[prost(string, tag = "1")]
    pub session_id: String,
    #[prost(uint64, tag = "2")]
    pub seq: u64,
    #[prost(enumeration = "Kind", tag = "3")]
    pub kind: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub payload: Vec<u8>,
}

// --- gRPC status codes this service uses ------------------------------------

const GRPC_OK: u32 = 0;
const GRPC_INVALID_ARGUMENT: u32 = 3;
const GRPC_PERMISSION_DENIED: u32 = 7;
const GRPC_UNIMPLEMENTED: u32 = 12;
const GRPC_UNAVAILABLE: u32 = 14;

/// What the guest does with each message it receives.
///
/// The variants past `Echo` exist to be tested against, the way `/hang` and
/// `/trickle` do in `examples/guest-http`: they are behaviours a host cannot
/// provoke from outside, so the guest has to offer them deliberately.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Answer every message as it arrives. The real shape.
    Echo,
    /// Answer once, then end with a non-zero status — so a test can read a
    /// failure out of the trailers rather than out of the head.
    Refuse,
    /// Answer once, then burn CPU forever. The runtime's epoch watchdog must
    /// still stop this, which is what keeps "a stream may run long" from
    /// becoming "anything may run forever".
    Spin,
    /// Write without ever reading, so a client that does not drain finds out
    /// that the guest stops rather than buffering.
    Firehose,
}

enum Phase {
    Talking,
    Trailers,
    Done,
}

struct Session {
    /// The request body, held for the life of the response. This is the whole
    /// trick, and it is specified behaviour rather than a trick: see the module
    /// docs.
    inbound: http_body_util::combinators::UnsyncBoxBody<Bytes, Error>,
    deframer: Deframer,
    /// Answers waiting to go out. Bounded by what the client has sent, except
    /// in `Firehose`, which is the point of that mode.
    outbound: VecDeque<Bytes>,
    mode: Mode,
    phase: Phase,
    status: (u32, String),
    answered: u64,
}

impl Session {
    fn new(
        inbound: http_body_util::combinators::UnsyncBoxBody<Bytes, Error>,
        mode: Mode,
    ) -> Self {
        let mut session = Session {
            inbound,
            deframer: Deframer::default(),
            outbound: VecDeque::new(),
            mode,
            phase: Phase::Talking,
            status: (GRPC_OK, String::new()),
            answered: 0,
        };
        if mode == Mode::Firehose {
            // Queued up front and never read from the client, so the only
            // thing regulating this is whether anybody is draining it.
            for seq in 0..64 {
                session.outbound.push_back(frame(
                    &ServerMsg {
                        session_id: "firehose".into(),
                        seq,
                        kind: Kind::Round as i32,
                        payload: vec![0xab; 1024],
                    }
                    .encode_to_vec(),
                ));
            }
        }
        session
    }

    fn finish(&mut self, code: u32, message: &str) {
        self.status = (code, message.to_string());
        self.phase = Phase::Trailers;
    }

    fn trailers(&self) -> HeaderMap {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", self.status.0.to_string().parse().unwrap());
        if !self.status.1.is_empty() {
            trailers.insert("grpc-message", self.status.1.parse().unwrap());
        }
        trailers
    }

    /// One answer for one message.
    fn answer(&mut self, msg: ClientMsg) -> ServerMsg {
        self.answered += 1;
        ServerMsg {
            session_id: msg.session_id,
            seq: msg.seq,
            kind: match msg.kind {
                k if k == Kind::Hello as i32 => Kind::Hello as i32,
                k if k == Kind::Finish as i32 => Kind::Finish as i32,
                _ => Kind::Round as i32,
            },
            // Echoed, not signed. A cosigner would do its round here — and
            // would first need per-message approval, which nothing in this
            // guest can obtain: verifying an assertion needs state that lives
            // in the runtime, and there is no host function to ask through.
            // See the `.proto` beside this file.
            payload: msg.payload,
        }
    }
}

impl HttpBody for Session {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let this = self.get_mut();
        loop {
            // Anything already answered goes out first. Each of these becomes
            // one write on the response stream, and the host's outgoing buffer
            // holds two chunks — so a client that is not reading stops this
            // body being polled rather than letting it grow.
            if let Some(ready) = this.outbound.pop_front() {
                return Poll::Ready(Some(Ok(Frame::data(ready))));
            }

            match this.phase {
                Phase::Trailers => {
                    this.phase = Phase::Done;
                    return Poll::Ready(Some(Ok(Frame::trailers(this.trailers()))));
                }
                Phase::Done => return Poll::Ready(None),
                Phase::Talking => {}
            }

            if this.mode == Mode::Firehose {
                // Everything it had to say has now gone out.
                this.finish(GRPC_OK, "");
                continue;
            }

            if this.mode == Mode::Spin && this.answered > 0 {
                // No await point, no I/O, forever. Only the epoch can end this.
                #[allow(clippy::empty_loop)]
                loop {
                    std::hint::spin_loop();
                }
            }

            // Nothing to write, so read. This alternation *is* the concurrency
            // model: one task, driven by the reactor's single `poll` over every
            // pollable it holds.
            match Pin::new(&mut this.inbound).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                // The client half-closed — which is an orderly end only if it
                // came between messages. A half-close with bytes still stranded
                // in the deframer is a truncated frame, and reporting OK for it
                // would tell the client its last message was received when it
                // was not. The close looked clean at the HTTP layer; the gRPC
                // stream did not end cleanly, and the trailers are the only
                // place that difference can be said.
                Poll::Ready(None) => {
                    if this.deframer.is_empty() {
                        this.finish(GRPC_OK, "");
                    } else {
                        this.finish(
                            GRPC_INVALID_ARGUMENT,
                            "the stream ended part-way through a message",
                        );
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    this.finish(GRPC_UNAVAILABLE, &e.to_string());
                }
                Poll::Ready(Some(Ok(incoming))) => {
                    let Some(data) = incoming.data_ref() else {
                        // Request trailers. gRPC clients send none, and there
                        // is nothing this service would do with them.
                        continue;
                    };
                    this.deframer.push(data);
                    loop {
                        match this.deframer.next() {
                            Ok(Some(message)) => match ClientMsg::decode(message) {
                                Ok(msg) => {
                                    if this.mode == Mode::Refuse {
                                        let reply = this.answer(msg);
                                        this.outbound.push_back(frame(&reply.encode_to_vec()));
                                        this.finish(
                                            GRPC_PERMISSION_DENIED,
                                            "this session is not authorized to sign",
                                        );
                                        break;
                                    }
                                    let reply = this.answer(msg);
                                    this.outbound.push_back(frame(&reply.encode_to_vec()));
                                }
                                Err(e) => {
                                    this.finish(
                                        GRPC_INVALID_ARGUMENT,
                                        &format!("undecodable ClientMsg: {e}"),
                                    );
                                    break;
                                }
                            },
                            Ok(None) => break,
                            Err(malformed) => {
                                this.finish(GRPC_INVALID_ARGUMENT, &malformed.to_string());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// gRPC is always HTTP 200; the real status is in the trailers.
fn grpc_response(session: Session) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc+proto")
        // Load-bearing on HTTP/1.1: hyper's encoder drops trailers outright
        // unless the response declares which ones it will send. Harmless on
        // HTTP/2, where trailers need no announcement.
        .header("trailer", "grpc-status, grpc-message")
        .body(Body::from_http_body(session))
        .expect("response is well formed")
}

/// An unknown method is a gRPC status, not an HTTP one — a client reading only
/// the head would otherwise see a perfectly successful call.
fn unimplemented() -> Response<Body> {
    use http_body_util::BodyExt as _;
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", GRPC_UNIMPLEMENTED.to_string().parse().unwrap());
    trailers.insert("grpc-message", "no such method".parse().unwrap());
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc+proto")
        .header("trailer", "grpc-status, grpc-message")
        .body(Body::from_http_body(
            http_body_util::Empty::<Bytes>::new()
                .map_err(|e: std::convert::Infallible| match e {})
                .with_trailers(async move { Some(Ok::<_, Error>(trailers)) }),
        ))
        .expect("response is well formed")
}

#[wstd::http_server]
async fn main(req: Request<Body>) -> Result<Response<Body>, Error> {
    let path = req.uri().path().to_string();
    let mode = match path.as_str() {
        "/enclave.cosign.v1.SigningSession/Sign" => Mode::Echo,
        "/enclave.cosign.v1.SigningSession/Refuse" => Mode::Refuse,
        "/enclave.cosign.v1.SigningSession/Spin" => Mode::Spin,
        "/enclave.cosign.v1.SigningSession/Firehose" => Mode::Firehose,
        _ => return Ok(unimplemented()),
    };
    let inbound = req.into_body().into_boxed_body();
    Ok(grpc_response(Session::new(inbound, mode)))
}
