//! Outbound connections the runtime holds on a guest's behalf.
//!
//! # The problem this exists for
//!
//! A guest has no execution context of its own. An instance is created to serve
//! one invocation and dropped at the end — [`ServeHandle::verify_instantiates`]
//! says why in as many words — so it cannot own a socket that outlives the call,
//! and nothing inside it can reconnect, because between invocations there is no
//! "inside it".
//!
//! That left two ways to reach a guest, and neither serves a counterparty that
//! wants to *initiate*:
//!
//! - an inbound request, which the gate binds to a WebAuthn assertion, so the
//!   caller must hold the tenant's passkey;
//! - the task queue, which is a clock. A timer can start work; it cannot be
//!   spoken to.
//!
//! A service holding half of a threshold key has neither. It has no passkey for
//! the tenant whose money it is party to, and asking it to wait for the next
//! tick is not a conversation.
//!
//! So the runtime keeps the connection and the guest stays stateless: each
//! message the far side sends becomes one invocation, exactly as a task run is
//! one invocation. The guest replies from inside that call, and may send
//! unprompted from any invocation it is already in.
//!
//! # What it is on the wire
//!
//! Server-sent events for what arrives, `POST` for what is sent — two HTTP
//! shapes rather than one socket, because that is what the egress path already
//! carries and what a service can serve without a WebSocket stack. The logical
//! channel is bidirectional; the transport is ordinary.
//!
//! ```text
//!   runtime ──GET  /escrow/stream?id=…──▶ service     held open, events arrive
//!   runtime ──POST /escrow/send─────────▶ service     one message, one request
//!      │
//!      └── per event: invoke the guest's `on-message`, send back what it returns
//! ```
//!
//! # What it does not promise
//!
//! Delivery is **at least once** in both directions: a reconnect may redeliver,
//! and a `POST` whose response was lost may have arrived. Handlers deduplicate
//! by their own identifiers, exactly as task handlers deduplicate by run id.
//! Ordering holds within one connection and not across a reconnect.
//!
//! # What bounds it
//!
//! Nothing, deliberately — that is the point. The *guest* invocation each
//! message causes is bounded like any other, but the connection itself is the
//! runtime's and outlives every one of them. A reconnect after a network
//! failure or a runtime restart needs no guest and no timer: the record is on
//! the filesystem, and the supervisor reads it at boot.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use s3fs_core::{Fs, Inode, OpenFlags};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};

use crate::serve::egress::Origin;
use crate::tenant::ensure_dir;

const DIR: &str = "/runtime/streams";
const MAX_RECORD: usize = 8 * 1024;
/// One message, in either direction. Large enough for a key package and a
/// transaction; small enough that a peer cannot make the runtime hold a lot.
pub const MAX_MESSAGE: usize = 256 * 1024;
/// How many connections one tenant may ask the runtime to hold. Each is a
/// socket and a supervisor; a tenant that could ask for unboundedly many could
/// exhaust the process on everyone else's behalf.
const PER_TENANT: usize = 8;

/// Reconnection backoff. Starts quick, because the common failure is a service
/// restarting, and settles long, because the uncommon one is a service that is
/// gone and there is no point hammering it.
const BACKOFF: [Duration; 6] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(15),
    Duration::from_secs(60),
    Duration::from_secs(300),
];

/// What is written down, and all of it but `generation`. A connection is a
/// standing instruction, not a session: there is no state worth keeping about
/// one that is currently up.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamRecord {
    pub version: u8,
    #[serde(with = "hex_tenant")]
    pub tenant: [u8; 16],
    pub id: String,
    /// Scheme, host and port. Admitted by the image's allowlist when opened and
    /// again on every reconnect — a list narrowed between them takes effect.
    pub origin: String,
    /// Which `open` made this record; zero for one read back at boot. A close
    /// and a reopen that land between two supervisor passes leave a record
    /// equal in every field that is written down, and the pass must still see
    /// a new instruction: the old connection belongs to the old one, and the
    /// close took its status with it.
    #[serde(skip)]
    generation: u64,
}

impl StreamRecord {
    fn key(&self) -> String {
        self.wire_id()
    }

    /// What the far side is told this connection is called.
    ///
    /// The tenant, then the guest's own id — **not** the guest's id alone, and that is not
    /// cosmetic. A stream id is tenant-*local*: a guest derives it from something about the
    /// counterparty, so every tenant that guest serves opens a connection under the very same
    /// name. A service seeing only that could not tell one customer's held connection from
    /// another's, and — because a message sent to it arrives as a POST of its own, with no
    /// connection identity in it — could not tell which connection a message belonged to either.
    /// It would answer down whichever it happened to have, which is to say the wrong customer's.
    ///
    /// That is not hypothetical: it is what happened, and the symptom was one wallet's service
    /// being told about an escrow a different wallet holds.
    ///
    /// The tenant is opaque and the far side already knows far more about who it is talking to —
    /// it holds half of their escrow key — so this reveals nothing it did not have.
    pub fn wire_id(&self) -> String {
        format!("{}-{}", hex::encode(self.tenant), self.id)
    }
}

/// What a caller can see about a connection. Deliberately thin: whether it is
/// up, and enough history to tell "never worked" from "flapping".
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StreamStatus {
    pub connected: bool,
    pub connects: u64,
    pub failures: u64,
    pub last_error: Option<String>,
}

#[derive(Default)]
struct Live {
    status: StreamStatus,
}

/// The registry, and the supervisor that keeps its instructions true.
pub struct StreamRegistry {
    fs: Arc<Fs>,
    dir: Arc<Inode>,
    records: Mutex<BTreeMap<([u8; 16], String), StreamRecord>>,
    live: Mutex<BTreeMap<([u8; 16], String), Live>>,
    /// Woken when a record appears or goes. `notify_one`, never `notify_waiters`: there is exactly
    /// one consumer — the supervisor loop — and it is not registered as a waiter while it is
    /// collecting records and spawning. `notify_waiters` would drop a wakeup that landed in that
    /// window, and the connection would then wait out the poll below before it was ever dialled.
    /// `notify_one` leaves a permit, so the next `notified()` returns at once.
    changed: Notify,
    egress: Mutex<Option<crate::serve::EgressPolicy>>,
    messages: AtomicU64,
    /// The next [`StreamRecord`] generation. Starts at 1, above every record
    /// read back at boot.
    generations: AtomicU64,
}

/// What a guest's `enclave:streams/connection` calls are bound to. As with
/// tasks, the tenant comes from the invocation and is never a parameter.
#[derive(Clone)]
pub struct StreamContext {
    pub registry: Arc<StreamRegistry>,
    pub tenant: [u8; 16],
    /// Mutations require an interactive invocation, for the same reason task
    /// mutations do: work arriving over a connection must not be able to grant
    /// itself more connections.
    pub interactive: bool,
}

impl StreamRegistry {
    pub async fn open_registry(fs: Arc<Fs>) -> Result<Arc<Self>> {
        let runtime = ensure_dir(&fs, &fs.root(), "runtime").await?;
        let dir = ensure_dir(&fs, &runtime, "streams").await?;
        let registry = Arc::new(Self {
            fs,
            dir,
            records: Mutex::new(BTreeMap::new()),
            live: Mutex::new(BTreeMap::new()),
            changed: Notify::new(),
            egress: Mutex::new(None),
            messages: AtomicU64::new(0),
            generations: AtomicU64::new(1),
        });

        // Everything standing, read back before anything is served. A record on
        // disk is the whole of a connection's existence, so this is also the
        // answer to "what reconnects after a restart": this loop.
        let mut records = registry.records.lock().await;
        for entry in registry.fs.read_dir(&registry.dir).await? {
            if entry.name.ends_with(".tmp") {
                registry.fs.unlink(&registry.dir, &entry.name).await?;
                continue;
            }
            let h = registry
                .fs
                .open(&format!("{DIR}/{}", entry.name), OpenFlags::read_only())
                .await?;
            let bytes = registry.fs.pread(&h, 0, MAX_RECORD + 1).await;
            registry.fs.close(&h).await?;
            let bytes = bytes?;
            ensure!(bytes.len() <= MAX_RECORD, "oversized stream record");
            let record: StreamRecord =
                serde_json::from_slice(&bytes).context("decoding a stream record")?;
            ensure!(
                record.version == 1 && valid_id(&record.id) && record.key() == entry.name,
                "malformed stream record {}",
                entry.name
            );
            records.insert((record.tenant, record.id.clone()), record);
        }
        drop(records);
        Ok(registry)
    }

    /// The origins a guest may be connected to. Set once the image's policy is
    /// known, and consulted on every connect rather than only at `open`.
    pub async fn set_egress(&self, egress: crate::serve::EgressPolicy) {
        *self.egress.lock().await = Some(egress);
    }

    pub async fn open(&self, tenant: [u8; 16], id: String, origin: String) -> Result<()> {
        ensure!(valid_id(&id), "a stream id is 1..=64 of [A-Za-z0-9_-]");
        let parsed = Origin::parse(&origin).context("that is not an origin")?;
        self.admit(&parsed)
            .await
            .context("this image does not allow a connection to that origin")?;

        let mut records = self.records.lock().await;
        if let Some(existing) = records.get(&(tenant, id.clone())) {
            // Idempotent for the same instruction; an error for a different one,
            // because silently moving a connection would move a conversation.
            ensure!(
                existing.origin == origin,
                "a stream with that id is already open to {}",
                existing.origin
            );
            return Ok(());
        }
        ensure!(
            records.keys().filter(|(t, _)| *t == tenant).count() < PER_TENANT,
            "a tenant may hold at most {PER_TENANT} connections"
        );
        let record = StreamRecord {
            version: 1,
            tenant,
            id,
            origin,
            generation: self.generations.fetch_add(1, Ordering::Relaxed),
        };
        self.publish(&record).await?;
        records.insert((record.tenant, record.id.clone()), record);
        drop(records);
        self.changed.notify_one();
        Ok(())
    }

    pub async fn close(&self, tenant: [u8; 16], id: &str) -> Result<()> {
        let mut records = self.records.lock().await;
        if let Some(record) = records.remove(&(tenant, id.to_string())) {
            match self.fs.unlink(&self.dir, &record.key()).await {
                Ok(()) | Err(s3fs_core::FsError::NotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }
        drop(records);
        self.live.lock().await.remove(&(tenant, id.to_string()));
        self.changed.notify_one();
        Ok(())
    }

    pub async fn status(&self, tenant: [u8; 16], id: &str) -> Result<StreamStatus> {
        let records = self.records.lock().await;
        ensure!(
            records.contains_key(&(tenant, id.to_string())),
            "no such stream"
        );
        drop(records);
        Ok(self
            .live
            .lock()
            .await
            .get(&(tenant, id.to_string()))
            .map(|l| l.status.clone())
            .unwrap_or_default())
    }

    /// One message to the far side.
    ///
    /// A plain request, not a write into the held connection: the held one
    /// carries what arrives. Failing when the connection is down is deliberate —
    /// only the caller knows whether a message is still worth sending when the
    /// far side has not been there.
    pub async fn send(&self, tenant: [u8; 16], id: &str, payload: Vec<u8>) -> Result<()> {
        ensure!(
            payload.len() <= MAX_MESSAGE,
            "message exceeds {MAX_MESSAGE} bytes"
        );
        let record = {
            let records = self.records.lock().await;
            records
                .get(&(tenant, id.to_string()))
                .cloned()
                .context("no such stream")?
        };
        let connected = self
            .live
            .lock()
            .await
            .get(&(tenant, id.to_string()))
            .is_some_and(|l| l.status.connected);
        ensure!(
            connected,
            "that stream is not connected; the message was not sent"
        );

        let origin = Origin::parse(&record.origin)?;
        let egress = self.admit(&origin).await?;
        let held = egress
            .send_direct(
                origin,
                hyper::Request::builder()
                    .method(hyper::Method::POST)
                    .uri(format!(
                        "{}/escrow/send?id={}",
                        record.origin,
                        record.wire_id()
                    ))
                    .header("content-type", "application/octet-stream")
                    .body(body_from(payload))?,
                Duration::from_secs(30),
            )
            .await
            .map_err(|e| anyhow::anyhow!("sending on {id}: {e:?}"))?;
        ensure!(
            held.response.status().is_success(),
            "the far side refused a message: {}",
            held.response.status()
        );
        Ok(())
    }

    /// The allowlist, if it admits `origin` — checked on every connect and every
    /// send, not only at `open`, so a list narrowed by a redeploy takes effect on
    /// connections that were already standing.
    async fn admit(&self, origin: &Origin) -> Result<Arc<crate::serve::EgressAllowlist>> {
        match self.egress.lock().await.clone() {
            Some(crate::serve::EgressPolicy::Allowlist(list))
                if list.origins().any(|o| o == origin) =>
            {
                Ok(list)
            }
            _ => bail!("{origin:?} is not an origin this image allows"),
        }
    }

    async fn publish(&self, record: &StreamRecord) -> Result<()> {
        let bytes = serde_json::to_vec(record)?;
        ensure!(bytes.len() <= MAX_RECORD, "stream record exceeds limit");
        let temp = format!("{}.tmp", record.key());
        match self.fs.unlink(&self.dir, &temp).await {
            Ok(()) | Err(s3fs_core::FsError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        let h = self
            .fs
            .open(&format!("{DIR}/{temp}"), OpenFlags::create_new())
            .await?;
        let write = self.fs.pwrite(&h, 0, &bytes).await;
        let close = self.fs.close(&h).await;
        write?;
        close?; // close commits the contents before publication
        self.fs
            .rename(&self.dir, &temp, &self.dir, &record.key())
            .await?;
        Ok(())
    }

    /// How many messages have been delivered to a guest. For tests and for an
    /// operator wanting to know whether a connection is doing anything.
    pub fn delivered(&self) -> u64 {
        self.messages.load(Ordering::Relaxed)
    }

    /// Keep every standing instruction true, for as long as the process lives.
    ///
    /// One supervisor per record, started when the record appears and stopped
    /// when it goes. Each holds a connection, hands what arrives to the guest,
    /// and — the part no guest could do for itself — comes back after a failure.
    ///
    /// **This is what reconnects.** Not sealed state, which only says a
    /// connection should exist, and not a timer, which was the thing worth
    /// removing. A supervisor is a live task in the runtime: when its connection
    /// drops it waits out the backoff and dials again, whether or not anybody is
    /// using the wallet, and it starts at boot from the records on disk.
    pub async fn run(self: Arc<Self>, guest: Arc<crate::serve::ServeHandle>) -> Result<()> {
        let mut live: BTreeMap<([u8; 16], String), (StreamRecord, tokio::task::JoinHandle<()>)> =
            BTreeMap::new();
        loop {
            let wanted: Vec<StreamRecord> = self.records.lock().await.values().cloned().collect();

            // Start what is new, and restart what changed: a close and reopen
            // that land between two passes here leave the same key naming a
            // different record — another origin, or the same one from a later
            // `open` — and the old supervisor knows nothing of it.
            for record in &wanted {
                let key = (record.tenant, record.id.clone());
                match live.get(&key) {
                    Some((r, h)) if r == record && !h.is_finished() => continue,
                    Some((_, h)) => h.abort(),
                    None => {}
                }
                let registry = self.clone();
                let guest = guest.clone();
                let record = record.clone();
                let task = {
                    let record = record.clone();
                    tokio::task::spawn(async move { registry.supervise(guest, record).await })
                };
                live.insert(key, (record, task));
            }

            // Stop what is no longer asked for. Aborting drops the connection,
            // which is the whole of "close".
            live.retain(|key, (_, handle)| {
                let keep = wanted.iter().any(|r| (r.tenant, r.id.clone()) == *key);
                if !keep {
                    handle.abort();
                }
                keep
            });

            // Nothing to poll: a record appearing or going notifies, and a
            // supervisor that exits leaves a finished handle for the next pass.
            tokio::select! {
                _ = self.changed.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
        }
    }

    /// One connection, held and re-held.
    async fn supervise(
        self: &Arc<Self>,
        guest: Arc<crate::serve::ServeHandle>,
        record: StreamRecord,
    ) {
        let key = (record.tenant, record.id.clone());
        let mut failures = 0usize;
        loop {
            match self.connect_once(&guest, &record).await {
                Ok(()) => {
                    // The far side closed cleanly. Not an error, but not a
                    // reason to hammer it either — a service that ends the
                    // stream every time should not become a busy loop.
                    failures = 0;
                    self.note(&key, |s| s.connected = false).await;
                    tokio::time::sleep(BACKOFF[0]).await;
                }
                Err(e) => {
                    let message = format!("{e:#}");
                    tracing::debug!(id = %record.id, error = %message, "stream connection ended");
                    self.note(&key, |s| {
                        s.connected = false;
                        s.failures += 1;
                        s.last_error = Some(message);
                    })
                    .await;
                    let wait = BACKOFF[failures.min(BACKOFF.len() - 1)];
                    failures += 1;
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }

    /// Hold one connection until it ends, handing each event to the guest.
    async fn connect_once(
        self: &Arc<Self>,
        guest: &Arc<crate::serve::ServeHandle>,
        record: &StreamRecord,
    ) -> Result<()> {
        use http_body_util::BodyExt;

        let origin = Origin::parse(&record.origin)?;
        let egress = self.admit(&origin).await?;
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(format!(
                "{}/escrow/stream?id={}",
                record.origin,
                record.wire_id()
            ))
            .header("accept", "text/event-stream")
            .body(empty_body())?;

        // A long first-byte timeout: a service with nothing to say yet is the
        // normal case, not a broken one.
        //
        // `held` is kept for the whole of the read loop below, and that is not
        // tidiness: it owns the task driving the connection, and dropping it
        // ends the body. See [`crate::serve::egress::HeldResponse`].
        let mut held = egress
            .send_direct(origin, request, Duration::from_secs(60))
            .await
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        ensure!(
            held.response.status().is_success(),
            "the service refused the stream: {}",
            held.response.status()
        );

        let key = (record.tenant, record.id.clone());
        self.note(&key, |s| {
            s.connected = true;
            s.connects += 1;
            s.last_error = None;
        })
        .await;

        let mut framer = SseFramer::default();
        while let Some(frame) = held.response.frame().await {
            let frame = frame.map_err(|e| anyhow::anyhow!("reading the stream: {e:?}"))?;
            let Some(chunk) = frame.data_ref() else {
                continue;
            };
            for event in framer.push(chunk)? {
                self.messages.fetch_add(1, Ordering::Relaxed);
                // The guest answers, and what it answers goes back. An error is
                // NOT sent: a guest that failed has said nothing it wants the
                // far side to act on, and the message will arrive again.
                match guest
                    .run_message(self, record.tenant, &record.id, &event.id, event.data)
                    .await
                {
                    Ok(reply) if !reply.is_empty() => {
                        if let Err(e) = self.send(record.tenant, &record.id, reply).await {
                            tracing::debug!(id = %record.id, error = %format!("{e:#}"), "reply not sent");
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::debug!(id = %record.id, error = %format!("{e:#}"), "guest refused a message");
                    }
                }
            }
        }
        Ok(())
    }

    async fn note(&self, key: &([u8; 16], String), f: impl FnOnce(&mut StreamStatus)) {
        let mut live = self.live.lock().await;
        f(&mut live.entry(key.clone()).or_default().status);
    }
}

/// Server-sent events, reassembled from however the bytes arrive.
///
/// The same problem the cosigner's own SSE reader solves against arkd: a frame
/// boundary is not an event boundary, and an event is not complete until a blank
/// line. Kept here rather than shared because the runtime must not depend on a
/// guest's crates.
#[derive(Default)]
struct SseFramer {
    buffer: String,
}

struct SseEvent {
    id: String,
    data: Vec<u8>,
}

impl SseFramer {
    fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>> {
        self.buffer
            .push_str(std::str::from_utf8(chunk).context("a stream frame was not UTF-8")?);
        // The spec admits CRLF, CR and LF as line endings. Fold them to LF
        // here, holding back a trailing CR that may be half of a CRLF the
        // next read completes.
        if self.buffer.contains('\r') {
            let hold = self.buffer.ends_with('\r');
            let mut norm = self.buffer.replace("\r\n", "\n").replace('\r', "\n");
            if hold {
                norm.pop();
                norm.push('\r');
            }
            self.buffer = norm;
        }
        ensure!(
            self.buffer.len() <= MAX_MESSAGE * 2,
            "an unterminated event exceeded the message ceiling"
        );
        let mut out = Vec::new();
        while let Some(end) = self.buffer.find("\n\n") {
            let block: String = self.buffer.drain(..end + 2).collect();
            let mut id = String::new();
            let mut data = String::new();
            for line in block.lines() {
                if let Some(v) = line.strip_prefix("id:") {
                    id = v.trim().to_string();
                } else if let Some(v) = line.strip_prefix("data:") {
                    data.push_str(v.trim());
                }
            }
            if data.is_empty() {
                continue; // a heartbeat, or a comment
            }
            let bytes = base64_decode(&data).context("event data was not base64")?;
            ensure!(
                bytes.len() <= MAX_MESSAGE,
                "event exceeds the message ceiling"
            );
            // An event with no id of its own gets one from its content, so a
            // guest deduplicating by id still can.
            if id.is_empty() {
                id = hex::encode(&nitro_attestation::sha256(&bytes)[..16]);
            }
            out.push(SseEvent { id, data: bytes });
        }
        Ok(out)
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

fn empty_body() -> wasmtime_wasi_http::p2::body::HyperOutgoingBody {
    use http_body_util::{BodyExt, Empty};
    Empty::<bytes::Bytes>::new()
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed_unsync()
}

fn body_from(bytes: Vec<u8>) -> wasmtime_wasi_http::p2::body::HyperOutgoingBody {
    use http_body_util::{BodyExt, Full};
    Full::new(bytes::Bytes::from(bytes))
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed_unsync()
}

/// The same alphabet a task id uses, and for the same reason: an id ends up in
/// a filename and in a URL.
pub fn valid_id(s: &str) -> bool {
    (1..=64).contains(&s.chars().count())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

mod hex_tenant {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("a tenant id is 16 bytes"))
    }
}

/// The ABI is defined in wit/stream/stream.wit. No tenant id is accepted.
pub fn add_to_linker(
    linker: &mut wasmtime::component::Linker<crate::state::State>,
) -> wasmtime::Result<()> {
    use crate::state::State;

    fn context(state: &State, mutation: bool) -> Result<StreamContext> {
        let ctx = state
            .streams
            .clone()
            .context("streams require an authenticated tenant")?;
        ensure!(
            !mutation || ctx.interactive,
            "work arriving over a connection cannot open more connections"
        );
        Ok(ctx)
    }

    let mut c = linker.instance("enclave:streams/connection@0.1.0")?;
    c.func_wrap_async("stream-open", |store, (id, origin): (String, String)| {
        Box::new(async move {
            let result = async move {
                let ctx = context(store.data(), true)?;
                ctx.registry.open(ctx.tenant, id, origin).await
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;
    c.func_wrap_async("stream-close", |store, (id,): (String,)| {
        Box::new(async move {
            let result = async move {
                let ctx = context(store.data(), true)?;
                ctx.registry.close(ctx.tenant, &id).await
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;
    // Not a mutation: replying to what arrived is the whole point, and a guest
    // invoked BY a message must be able to answer it.
    c.func_wrap_async("stream-send", |store, (id, payload): (String, Vec<u8>)| {
        Box::new(async move {
            let result = async move {
                let ctx = context(store.data(), false)?;
                ctx.registry.send(ctx.tenant, &id, payload).await
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;
    c.func_wrap_async("stream-status", |store, (id,): (String,)| {
        Box::new(async move {
            let result: Result<String> = async move {
                let ctx = context(store.data(), false)?;
                Ok(serde_json::to_string(
                    &ctx.registry.status(ctx.tenant, &id).await?,
                )?)
            }
            .await;
            Ok((result.map_err(|e| e.to_string()),))
        })
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3fs_core::backend::memory::MemoryBackend;
    use s3fs_core::{Config, MasterSecret};

    async fn registry() -> (Arc<StreamRegistry>, Arc<Fs>) {
        let backend = Arc::new(MemoryBackend::new());
        let fs = Fs::create(
            backend.clone(),
            backend.clone(),
            &MasterSecret::from_bytes([7; 32]),
            [8; 16],
            Arc::new(Config::default()),
        )
        .await
        .unwrap();
        crate::tenant::tenant_root_by_id(&fs, [1; 16])
            .await
            .unwrap();
        let r = StreamRegistry::open_registry(fs.clone()).await.unwrap();
        r.set_egress(crate::serve::EgressPolicy::Allowlist(Arc::new(
            crate::serve::egress::EgressAllowlist::parse(&["https://svc.example"]).unwrap(),
        )))
        .await;
        (r, fs)
    }

    #[tokio::test]
    async fn an_origin_the_image_does_not_allow_is_refused() {
        let (r, _fs) = registry().await;
        let err = r
            .open([1; 16], "esc".into(), "https://elsewhere.example".into())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("does not allow"), "{err:#}");
    }

    /// Two tenants opening a connection under the same local id must be distinguishable by the
    /// far side, which sees only what is on the wire.
    #[tokio::test]
    async fn one_id_from_two_tenants_is_two_names_on_the_wire() {
        let a = StreamRecord {
            version: 1,
            tenant: [1; 16],
            id: "svc-abc".into(),
            origin: "https://svc.example".into(),
            generation: 0,
        };
        let b = StreamRecord {
            tenant: [2; 16],
            ..a.clone()
        };
        assert_ne!(
            a.wire_id(),
            b.wire_id(),
            "a service cannot tell two customers apart if their connections share a name"
        );
        assert!(a.wire_id().ends_with("-svc-abc"), "{}", a.wire_id());
        // And it is the same name the record is filed under, so there is one identity and not two.
        assert_eq!(a.wire_id(), a.key());
    }

    /// A wakeup that lands while the supervisor loop is between iterations must not be lost.
    ///
    /// This is not hypothetical: `notify_waiters` dropped exactly this one, and the effect was a
    /// guest opening a connection and finding it still down thirty seconds later — long past any
    /// patience a call has. `notify_one` leaves a permit, so the wakeup keeps.
    #[tokio::test]
    async fn a_wakeup_that_lands_between_iterations_is_not_lost() {
        let (r, _fs) = registry().await;
        // Nobody is waiting on `changed` yet — the supervisor loop is not running at all, which is
        // the strongest version of "between iterations".
        r.open([1; 16], "svc".into(), "https://svc.example".into())
            .await
            .unwrap();

        // The wakeup is still there to be collected.
        tokio::time::timeout(Duration::from_millis(50), r.changed.notified())
            .await
            .expect("the wakeup from `open` must survive until somebody waits for it");
    }

    #[tokio::test]
    async fn opening_the_same_instruction_twice_is_a_no_op_and_a_different_one_is_an_error() {
        let (r, _fs) = registry().await;
        r.open([1; 16], "esc".into(), "https://svc.example".into())
            .await
            .unwrap();
        r.open([1; 16], "esc".into(), "https://svc.example".into())
            .await
            .expect("the same instruction again changes nothing");

        r.set_egress(crate::serve::EgressPolicy::Allowlist(Arc::new(
            crate::serve::egress::EgressAllowlist::parse(&[
                "https://svc.example",
                "https://other.example",
            ])
            .unwrap(),
        )))
        .await;
        let err = r
            .open([1; 16], "esc".into(), "https://other.example".into())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("already open"), "{err:#}");
    }

    /// The answer to "what reconnects after a restart": the record, read back.
    #[tokio::test]
    async fn a_connection_survives_a_fresh_mount() {
        let (r, fs) = registry().await;
        r.open([1; 16], "esc".into(), "https://svc.example".into())
            .await
            .unwrap();
        drop(r);

        let reopened = StreamRegistry::open_registry(fs).await.unwrap();
        let records = reopened.records.lock().await;
        let record = records
            .get(&([1; 16], "esc".to_string()))
            .expect("the instruction came back with no guest involved");
        assert_eq!(record.origin, "https://svc.example");
    }

    #[tokio::test]
    async fn closing_forgets_it_and_is_idempotent() {
        let (r, fs) = registry().await;
        r.open([1; 16], "esc".into(), "https://svc.example".into())
            .await
            .unwrap();
        r.close([1; 16], "esc").await.unwrap();
        r.close([1; 16], "esc")
            .await
            .expect("closing twice is fine");

        let reopened = StreamRegistry::open_registry(fs).await.unwrap();
        assert!(reopened.records.lock().await.is_empty());
    }

    #[tokio::test]
    async fn a_tenant_cannot_hold_unboundedly_many() {
        let (r, _fs) = registry().await;
        for i in 0..PER_TENANT {
            r.open([1; 16], format!("esc{i}"), "https://svc.example".into())
                .await
                .unwrap();
        }
        let err = r
            .open([1; 16], "one-too-many".into(), "https://svc.example".into())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("at most"), "{err:#}");

        // Another tenant is unaffected: the cap is per tenant, not global.
        crate::tenant::tenant_root_by_id(&r.fs, [2; 16])
            .await
            .unwrap();
        r.open([2; 16], "esc".into(), "https://svc.example".into())
            .await
            .expect("one tenant's quota is not another's");
    }

    #[tokio::test]
    async fn sending_on_a_stream_that_is_down_says_so_rather_than_dropping_it() {
        let (r, _fs) = registry().await;
        r.open([1; 16], "esc".into(), "https://svc.example".into())
            .await
            .unwrap();
        let err = r.send([1; 16], "esc", vec![1, 2, 3]).await.unwrap_err();
        assert!(format!("{err:#}").contains("not connected"), "{err:#}");
    }

    // --- Framing -------------------------------------------------------------
    //
    // A frame boundary is not an event boundary. These are the cases that would
    // otherwise show up as a guest being handed half a message.

    fn b64(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn an_event_split_across_reads_is_reassembled() {
        let mut f = SseFramer::default();
        let whole = format!("id: m1\ndata: {}\n\n", b64(b"hello"));
        let (a, b) = whole.split_at(9);
        assert!(
            f.push(a.as_bytes()).unwrap().is_empty(),
            "half an event is no event"
        );
        let out = f.push(b.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "m1");
        assert_eq!(out[0].data, b"hello");
    }

    /// The spec admits CRLF and CR as line endings, and a real server sends
    /// them — including a CRLF cut between two reads.
    #[test]
    fn crlf_and_cr_terminated_events_are_delivered() {
        let mut f = SseFramer::default();
        let crlf = format!("id: m1\r\ndata: {}\r\n\r\n", b64(b"one"));
        let (a, b) = crlf.split_at(crlf.len() - 3); // split inside the final CRLF
        assert!(f.push(a.as_bytes()).unwrap().is_empty());
        let out = f.push(b.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "m1");
        assert_eq!(out[0].data, b"one");

        // A chunk-final CR is held back — it may be half a CRLF — so the
        // CR-terminated event is followed by the start of the next line.
        let cr = format!("data: {}\r\r: hb\r", b64(b"two"));
        let out = f.push(cr.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].data, b"two");
    }

    #[test]
    fn several_events_in_one_read_all_come_out_in_order() {
        let mut f = SseFramer::default();
        let chunk = format!(
            "id: a\ndata: {}\n\nid: b\ndata: {}\n\n",
            b64(b"one"),
            b64(b"two")
        );
        let out = f.push(chunk.as_bytes()).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].data, b"one");
        assert_eq!(out[1].data, b"two");
    }

    /// Heartbeats keep a quiet connection alive and are not messages.
    #[test]
    fn a_heartbeat_is_not_delivered_to_the_guest() {
        let mut f = SseFramer::default();
        assert!(f.push(b": keep-alive\n\n").unwrap().is_empty());
        assert!(f.push(b"\n\n").unwrap().is_empty());
    }

    /// A guest deduplicates by id, so an event without one still needs a stable
    /// handle — the same bytes must give the same id.
    #[test]
    fn an_event_with_no_id_gets_a_stable_one_from_its_content() {
        let mut f = SseFramer::default();
        let first = f
            .push(format!("data: {}\n\n", b64(b"x")).as_bytes())
            .unwrap();
        let second = f
            .push(format!("data: {}\n\n", b64(b"x")).as_bytes())
            .unwrap();
        let third = f
            .push(format!("data: {}\n\n", b64(b"y")).as_bytes())
            .unwrap();
        assert_eq!(first[0].id, second[0].id, "the same message is the same id");
        assert_ne!(first[0].id, third[0].id);
    }

    #[test]
    fn an_unterminated_event_cannot_grow_without_limit() {
        let mut f = SseFramer::default();
        // The buffer must admit one whole event — base64 is about 4/3 the bytes,
        // plus its field names — so the ceiling is above MAX_MESSAGE and a test
        // for it has to actually exceed it.
        let big = "d".repeat(MAX_MESSAGE);
        assert!(
            f.push(big.as_bytes()).is_ok(),
            "one max-size event must fit"
        );
        let err = loop {
            match f.push(big.as_bytes()) {
                Ok(_) => continue,
                Err(e) => break e,
            }
        };
        assert!(
            format!("{err:#}").contains("unterminated"),
            "a peer that never terminates an event must not be able to fill memory: {err:#}"
        );
    }

    #[test]
    fn data_that_is_not_base64_is_an_error_rather_than_a_guess() {
        let mut f = SseFramer::default();
        assert!(f.push(b"id: m\ndata: not base64!!\n\n").is_err());
    }

    #[tokio::test]
    async fn an_id_that_would_not_be_a_filename_is_refused() {
        let (r, _fs) = registry().await;
        for bad in ["", "../escape", "has space", &"x".repeat(65)] {
            assert!(
                r.open([1; 16], bad.into(), "https://svc.example".into())
                    .await
                    .is_err(),
                "{bad:?} should not be a stream id"
            );
        }
    }

    async fn guest(fs: Arc<Fs>) -> Arc<crate::serve::ServeHandle> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../examples/guest-http/target/wasm32-wasip2/release/guest-http.wasm");
        let bytes = std::fs::read(path).expect("build examples/guest-http for wasm32-wasip2");
        let (logs, _collector) = crate::guest_io::start(Arc::new(crate::TracingLogSink));
        let env = crate::GuestEnvironment::new(
            fs,
            Box::new(crate::clock::HostClock),
            Arc::new(nitro_nsm::fake::FakeNsm::new()),
            &[],
            &[],
            logs,
        )
        .unwrap();
        let engine = crate::ServeHandle::engine_with_watchdog().unwrap();
        Arc::new(crate::ServeHandle::new(&engine, &bytes, env).unwrap())
    }

    /// Accept one connection and hold it open as an event stream.
    async fn serve_one(listener: &tokio::net::TcpListener) -> tokio::net::TcpStream {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 8192];
        let _ = socket.read(&mut request).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n: hello\n\n")
            .await
            .unwrap();
        socket
    }

    /// A reopen gets a connection of its own, whether to a new origin or to
    /// the same one.
    ///
    /// The same-origin half is the one that broke. A close and a reopen
    /// between two supervisor passes left a record equal to the old one, so
    /// the old connection stayed up — with its status gone, which made `send`
    /// refuse on it, and with it every reply to a message that arrived.
    #[tokio::test]
    #[ignore = "requires built guest-http component"]
    async fn a_reopened_stream_gets_a_new_connection() {
        let a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_a = format!("http://{}", a.local_addr().unwrap());
        let origin_b = format!("http://{}", b.local_addr().unwrap());
        let (r, fs) = registry().await;
        r.set_egress(crate::serve::EgressPolicy::Allowlist(Arc::new(
            crate::serve::egress::EgressAllowlist::parse(&[origin_a.as_str(), origin_b.as_str()])
                .unwrap(),
        )))
        .await;
        let supervisor = tokio::spawn(r.clone().run(guest(fs).await));
        let wait = Duration::from_secs(5);

        r.open([1; 16], "esc".into(), origin_a.clone())
            .await
            .unwrap();
        let _first = tokio::time::timeout(wait, serve_one(&a))
            .await
            .expect("never connected");

        r.close([1; 16], "esc").await.unwrap();
        r.open([1; 16], "esc".into(), origin_a).await.unwrap();
        let _second = tokio::time::timeout(wait, serve_one(&a))
            .await
            .expect("reopened to the same origin, and the old connection was kept");

        r.close([1; 16], "esc").await.unwrap();
        r.open([1; 16], "esc".into(), origin_b).await.unwrap();
        let _third = tokio::time::timeout(wait, serve_one(&b))
            .await
            .expect("reopened to a new origin, and it was never dialled");

        supervisor.abort();
    }
}
