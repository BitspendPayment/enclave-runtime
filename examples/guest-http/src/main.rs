//! A guest that answers HTTP requests out of the Merkle-anchored filesystem.
//!
//! This is the end-to-end signal for the serving path, and it is deliberately
//! stateful: `/counter` reads a file, increments it and writes it back, so a
//! second request proves the runtime carried a *committed* filesystem across
//! requests rather than handing each instance a fresh view. A stateless
//! handler would pass even if every request got its own empty store.
//!
//! What it never does is as informative as what it does. There is no listener,
//! no socket, no certificate and no outbound request anywhere in this file —
//! the runtime terminates TLS and hands over a parsed request. The guest's
//! entire view of the network is the `Request` argument.
//!
//! ```console
//! $ curl localhost:8080/           # what this guest is
//! $ curl localhost:8080/counter    # increments, persists
//! $ curl localhost:8080/env        # what the environment policy let through
//! $ curl -X POST --data-binary @f localhost:8080/files/notes.txt
//! $ curl localhost:8080/files/notes.txt
//! ```

use std::cell::Cell;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

use wstd::http::{Body, Error, Request, Response, StatusCode};

/// Where this guest keeps its state. A directory rather than the root, so it
/// is obvious in a bucket listing which objects came from the example.
const STATE_DIR: &str = "/http-example";

thread_local! {
    /// A counter that touches no storage at all.
    ///
    /// `/counter` proves the *filesystem* carried state between requests. This
    /// proves the opposite, and it is the more important of the two: a fresh
    /// instance has fresh memory, so `/memory` must answer 1 forever. Any other
    /// answer means two requests reached the same instance, and the boundary
    /// between two clients has quietly moved out of the runtime and into this
    /// file.
    static IN_MEMORY: Cell<u64> = const { Cell::new(0) };
}

#[wstd::http_server]
async fn main(mut req: Request<Body>) -> Result<Response<Body>, Error> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    let result = match (method.as_str(), path.as_str()) {
        ("GET", "/") => Ok(text(StatusCode::OK, banner())),
        ("GET", "/counter") => counter().map(|n| text(StatusCode::OK, format!("{n}\n"))),
        ("GET", "/memory") => Ok(text(
            StatusCode::OK,
            format!(
                "{}\n",
                IN_MEMORY.with(|c| {
                    c.set(c.get() + 1);
                    c.get()
                })
            ),
        )),
        ("GET", "/env") => Ok(text(StatusCode::OK, environment())),
        // Whatever the runtime says about the caller. A guest can only ever
        // read this header, never write it, and the runtime overwrites it on
        // every request — so what arrives here is the runtime's word, not the
        // client's.
        ("GET", "/whoami") => Ok(text(
            StatusCode::OK,
            match req.headers().get("x-enclave-tenant") {
                Some(v) => format!("{}\n", v.to_str().unwrap_or("(not utf-8)")),
                None => "(anonymous)\n".to_string(),
            },
        )),
        ("POST", p) | ("PUT", p) if p.starts_with("/files/") => {
            let body = req.body_mut().bytes_contents().await?;
            write_file(&p["/files/".len()..], &body)
        }
        ("GET", p) if p.starts_with("/files/") => read_file(&p["/files/".len()..]),
        // A guest that does **not** validate the path, on purpose.
        //
        // `/files/` sanitises; this deliberately does not, so a test can point
        // it at `../../` or `/tenants/someone-else` and see what the *runtime*
        // does. That is the whole question for a tenant: separation has to be
        // the capability layer's, not this file's, and the only way to show it
        // is with a guest that is not helping.
        ("GET", p) if p.starts_with("/escape/") => {
            let target = &p["/escape/".len()..];
            match fs::read(target) {
                Ok(bytes) => Ok(text(
                    StatusCode::OK,
                    format!("read {} bytes from {target}\n", bytes.len()),
                )),
                Err(e) => Ok(text(
                    StatusCode::NOT_FOUND,
                    format!("refused {target}: {e}\n"),
                )),
            }
        }
        // Known values on both streams, for the runtime's guest-logging
        // tests. Every case the line framer has to get right is here, written
        // the way a guest would actually write it: a line built from two
        // `print!`s, a blank line, CRLF, bytes that are not UTF-8, something
        // on stderr, and a final line with no terminator at all.
        //
        // Flushed explicitly. Rust's stdout is line buffered and a component's
        // `handle` returning is not process exit, so without this the tail
        // would sit in the guest's own buffer and never reach the host.
        ("GET", "/log") => {
            use std::io::Write;
            let mut out = std::io::stdout();
            let _ = out.write_all(b"first ");
            let _ = out.write_all(b"line\n");
            let _ = out.write_all(b"\n");
            let _ = out.write_all(b"windows\r\n");
            let _ = out.write_all(b"invalid \xff\xfe bytes\n");
            let _ = out.write_all(b"no trailing newline");
            let _ = out.flush();

            let mut err = std::io::stderr();
            let _ = err.write_all(b"on stderr\n");
            let _ = err.flush();

            Ok(text(StatusCode::OK, "logged\n".to_string()))
        }
        // A guest that never returns and never sets a response. Deliberately
        // here rather than in a test fixture: it is the one behaviour a host
        // cannot provoke from the outside, and without it the runtime's
        // watchdog has nothing to be tested against.
        ("GET", "/hang") =>
        {
            #[allow(clippy::empty_loop)]
            loop {
                std::hint::spin_loop();
            }
        }
        _ => Ok(text(
            StatusCode::NOT_FOUND,
            format!("no route for {method} {path}\n"),
        )),
    };

    // A guest failure is a 500 with the reason, not a trap. Trapping would
    // take down the instance and tell the client nothing, and inside an
    // enclave the console is the only other place the reason could go.
    Ok(result.unwrap_or_else(|e| text(StatusCode::INTERNAL_SERVER_ERROR, format!("error: {e}\n"))))
}

fn text(status: StatusCode, body: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(body.into())
        .expect("response is well formed")
}

fn banner() -> String {
    let mut out = String::from("guest-http on a Merkle-anchored filesystem\n\n");
    out.push_str("GET  /counter          increment and return a persisted counter\n");
    out.push_str("GET  /env              environment the runtime policy allowed\n");
    out.push_str("POST /files/<name>     write a file\n");
    out.push_str("GET  /files/<name>     read it back\n\n");
    match fs::read_dir(STATE_DIR) {
        Ok(entries) => {
            let _ = writeln!(out, "files: {}", entries.count());
        }
        Err(_) => out.push_str("files: none yet\n"),
    }
    out
}

/// Read-modify-write against the block store.
///
/// The proof that matters: run it twice and the number goes up. That can only
/// happen if the first request's write was committed and the second request's
/// fresh instance read the committed state.
fn counter() -> Result<u64, String> {
    fs::create_dir_all(STATE_DIR).map_err(|e| format!("creating {STATE_DIR}: {e}"))?;
    let path = format!("{STATE_DIR}/counter");

    let current: u64 = match fs::read_to_string(&path) {
        Ok(s) => s.trim().parse().unwrap_or(0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(format!("reading {path}: {e}")),
    };
    let next = current + 1;

    // `sync_all` rather than relying on drop: the runtime commits a
    // transaction on flush, and a response that reports a number the store has
    // not accepted yet would be a lie the next request exposes.
    let mut f = fs::File::create(&path).map_err(|e| format!("creating {path}: {e}"))?;
    f.write_all(format!("{next}\n").as_bytes())
        .map_err(|e| format!("writing {path}: {e}"))?;
    f.sync_all().map_err(|e| format!("syncing {path}: {e}"))?;
    Ok(next)
}

fn environment() -> String {
    let mut vars: Vec<_> = std::env::vars().collect();
    vars.sort();
    if vars.is_empty() {
        return "(the runtime passed no variables)\n".to_string();
    }
    let mut out = String::new();
    for (k, v) in vars {
        let _ = writeln!(out, "{k}={v}");
    }
    out
}

fn write_file(name: &str, body: &[u8]) -> Result<Response<Body>, String> {
    let path = safe_path(name)?;
    fs::create_dir_all(STATE_DIR).map_err(|e| format!("creating {STATE_DIR}: {e}"))?;
    let mut f = fs::File::create(&path).map_err(|e| format!("creating {}: {e}", path.display()))?;
    f.write_all(body)
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    f.sync_all()
        .map_err(|e| format!("syncing {}: {e}", path.display()))?;
    Ok(text(
        StatusCode::CREATED,
        format!("wrote {} bytes to {}\n", body.len(), path.display()),
    ))
}

fn read_file(name: &str) -> Result<Response<Body>, String> {
    let path = safe_path(name)?;
    match fs::read(&path) {
        Ok(bytes) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(bytes.into())
            .expect("response is well formed")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(text(
            StatusCode::NOT_FOUND,
            format!("no such file: {name}\n"),
        )),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

/// Keep a request-supplied name inside [`STATE_DIR`].
///
/// The preopen the runtime grants is the filesystem *root*, so `..` in a path
/// from a client would escape this guest's directory and reach anything else
/// stored in the same filesystem. WASI's capability model stops a guest
/// leaving its preopen; it does not stop a guest wandering around inside it.
fn safe_path(name: &str) -> Result<PathBuf, String> {
    if name.is_empty() {
        return Err("empty file name".into());
    }
    let candidate = Path::new(name);
    if candidate
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(format!("rejected path {name:?}: must be a plain file name"));
    }
    Ok(Path::new(STATE_DIR).join(candidate))
}
