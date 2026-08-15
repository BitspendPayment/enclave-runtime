//! `guest-fsdemo` — Wasm component that exercises `wasi:filesystem`
//! end-to-end, including running a real SQLite database on top of it.
//!
//! Build:
//! ```bash
//! # Requires wasi-sdk for the bundled SQLite C build:
//! #   curl -sLO https://github.com/WebAssembly/wasi-sdk/releases/\
//! #     download/wasi-sdk-25/wasi-sdk-25.0-x86_64-linux.tar.gz
//! #   mkdir -p ~/wasi-sdk && tar xf wasi-sdk-25.0-x86_64-linux.tar.gz \
//! #     -C ~/wasi-sdk --strip-components=1
//! CC_wasm32_wasip2=$HOME/wasi-sdk/bin/clang \
//! AR_wasm32_wasip2=$HOME/wasi-sdk/bin/ar \
//! CFLAGS_wasm32_wasip2="--sysroot=$HOME/wasi-sdk/share/wasi-sysroot \
//!     -DSQLITE_THREADSAFE=0 -DHAVE_USLEEP=1" \
//! cargo build --release --target wasm32-wasip2
//! ```
//!
//! Run via `enclave-runtime` against MinIO or AWS. The component prints
//! `OK` on success or `FAIL: ...` on the first failure.

use std::fs;
use std::io::{Read, Write};

fn run() -> std::io::Result<()> {
    let root = "/";

    let dir = format!("{root}data");
    let _ = fs::remove_dir(&dir);
    fs::create_dir(&dir)?;

    let path = format!("{dir}/hello.txt");
    let mut f = fs::File::create(&path)?;
    f.write_all(b"hello, ")?;
    f.write_all(b"wasm world")?;
    f.sync_all()?;
    drop(f);

    let mut f = fs::File::open(&path)?;
    let mut body = String::new();
    f.read_to_string(&mut body)?;
    if body != "hello, wasm world" {
        return Err(std::io::Error::other(format!(
            "read mismatch: {body:?}"
        )));
    }

    // Step 4: read_dir
    let mut names: Vec<String> = fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    if names != vec!["hello.txt"] {
        return Err(std::io::Error::other(format!(
            "read_dir mismatch: {names:?}"
        )));
    }

    // Step 5: rename file (file rename is supported; dir rename isn't yet)
    let renamed = format!("{dir}/hi.txt");
    let _ = fs::remove_file(&renamed);
    fs::rename(&path, &renamed)?;
    let mut after_rename = String::new();
    fs::File::open(&renamed)?.read_to_string(&mut after_rename)?;
    if after_rename != "hello, wasm world" {
        return Err(std::io::Error::other("content lost across rename"));
    }

    // Step 6: SQLite. Our wasi:filesystem now hosts a real database — open,
    // create a table, insert some rows, query, close. SQLite hammers fsync
    // and small reads/writes, so this is a tougher test than std::fs alone.
    let db_path = format!("{dir}/demo.db");
    let _ = fs::remove_file(&db_path);
    {
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| std::io::Error::other(format!("sqlite open: {e}")))?;
        // We don't implement file locking. Tell SQLite this is the only
        // process so it skips lock syscalls. Use in-memory journal to avoid
        // sidecar files. `synchronous` is a setter pragma (no return rows),
        // so we run it via execute_batch alongside the others.
        conn.execute_batch(
            "PRAGMA locking_mode = EXCLUSIVE;\
             PRAGMA journal_mode = MEMORY;\
             PRAGMA synchronous = FULL;",
        )
        .map_err(|e| std::io::Error::other(format!("sqlite pragmas: {e}")))?;
        conn.execute_batch(
            "CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT NOT NULL);
             INSERT INTO notes(body) VALUES ('one'), ('two'), ('three');",
        )
        .map_err(|e| std::io::Error::other(format!("sqlite write: {e}")))?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notes", [], |row| row.get(0))
            .map_err(|e| std::io::Error::other(format!("sqlite count: {e}")))?;
        if count != 3 {
            return Err(std::io::Error::other(format!(
                "sqlite count mismatch: {count}"
            )));
        }
    }
    // Re-open and verify the data persisted (i.e. our sync actually flushed
    // to S3 and the next open's reads see it).
    {
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| std::io::Error::other(format!("sqlite reopen: {e}")))?;
        conn.execute_batch("PRAGMA locking_mode = EXCLUSIVE;")
            .map_err(|e| std::io::Error::other(format!("sqlite reopen pragma: {e}")))?;
        let bodies: Vec<String> = conn
            .prepare("SELECT body FROM notes ORDER BY id")
            .and_then(|mut s| {
                s.query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<_>>()
            })
            .map_err(|e| std::io::Error::other(format!("sqlite read: {e}")))?;
        if bodies != vec!["one", "two", "three"] {
            return Err(std::io::Error::other(format!(
                "sqlite content mismatch: {bodies:?}"
            )));
        }
    }

    // Step 7: cleanup
    fs::remove_file(&db_path)?;
    fs::remove_file(&renamed)?;
    fs::remove_dir(&dir)?;

    if fs::metadata(&renamed).is_ok() {
        return Err(std::io::Error::other("file still exists after delete"));
    }
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => println!("OK"),
        Err(e) => {
            eprintln!("FAIL: {e}");
            std::process::exit(1);
        }
    }
}
