//! A minimal guest that exercises the filesystem and the guest environment.
//!
//! Its job is to be the end-to-end signal that `enclave-runtime` works:
//! `wasi:filesystem` really is backed by the block store, and the environment
//! policy really does deliver variables. It uses nothing but `std`, so it
//! builds with a plain Rust toolchain — `guest-fsdemo` needs a 100 MB C
//! toolchain for its bundled SQLite, which keeps it out of the fast CI path.
//!
//! Run twice against the same buckets, it also proves durability: the second
//! run finds what the first committed.
//!
//! Prints `OK` and exits 0 on success; prints `FAIL: …` and exits 1 otherwise.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};

fn main() {
    match run() {
        Ok(()) => println!("OK"),
        Err(e) => {
            println!("FAIL: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    // The environment is the reason this guest exists as much as the
    // filesystem is: an enclave guest is configured entirely through it.
    let marker = std::env::var("SMOKE_MARKER").unwrap_or_else(|_| "<unset>".to_string());
    println!("env SMOKE_MARKER={marker}");

    // Nothing under these prefixes may ever reach a guest by inheritance:
    // they are the runtime's own configuration and its credentials.
    for (name, _) in std::env::vars() {
        if name.starts_with("AWS_") || name.starts_with("S3FS_") {
            return Err(format!("runtime variable {name} leaked into the guest"));
        }
    }

    // Whatever the runtime's clock says. Inside an enclave this is the PTP
    // hardware clock, which is the point: it reaches the guest through
    // wasi:clocks/wall-clock like any other time source.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock before the epoch: {e}"))?;
    println!("wall clock {}.{:09}", now.as_secs(), now.subsec_nanos());
    if now.as_secs() < 1_577_836_800 {
        return Err(format!("wall clock reads {}, before 2020", now.as_secs()));
    }

    let dir = "/smoke";
    if fs::metadata(dir).is_err() {
        fs::create_dir(dir).map_err(|e| format!("create_dir {dir}: {e}"))?;
    }

    // A fresh file each run, plus a persistent one that must survive.
    let scratch = format!("{dir}/scratch.bin");
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();

    {
        let mut f = fs::File::create(&scratch).map_err(|e| format!("create: {e}"))?;
        f.write_all(&payload).map_err(|e| format!("write: {e}"))?;
        f.sync_all().map_err(|e| format!("sync: {e}"))?;
    }

    let read_back = fs::read(&scratch).map_err(|e| format!("read: {e}"))?;
    if read_back != payload {
        return Err(format!(
            "content mismatch: wrote {} bytes, read {}",
            payload.len(),
            read_back.len()
        ));
    }

    // Seek and overwrite in the middle: exercises the copy-on-write rebuild
    // rather than a whole-file replacement.
    {
        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&scratch)
            .map_err(|e| format!("reopen: {e}"))?;
        f.seek(SeekFrom::Start(12_345))
            .map_err(|e| format!("seek: {e}"))?;
        f.write_all(b"PATCHED").map_err(|e| format!("patch: {e}"))?;
        f.sync_all().map_err(|e| format!("sync patch: {e}"))?;

        let mut buf = [0u8; 7];
        f.seek(SeekFrom::Start(12_345))
            .map_err(|e| format!("seek back: {e}"))?;
        f.read_exact(&mut buf).map_err(|e| format!("reread: {e}"))?;
        if &buf != b"PATCHED" {
            return Err("in-place patch did not read back".to_string());
        }
    }

    // Rename, which is one atomic directory-entry move in this filesystem.
    let renamed = format!("{dir}/renamed.bin");
    let _ = fs::remove_file(&renamed);
    fs::rename(&scratch, &renamed).map_err(|e| format!("rename: {e}"))?;
    if fs::metadata(&scratch).is_ok() {
        return Err("the old name still resolves after rename".to_string());
    }

    // Durability across runs: append a line, then count them. Run N must see
    // N lines, which only holds if commits really are reaching the store.
    let ledger = format!("{dir}/runs.txt");
    let previous = fs::read_to_string(&ledger).unwrap_or_default();
    let run_number = previous.lines().count() + 1;
    let updated = format!("{previous}run {run_number}\n");
    {
        let mut f = fs::File::create(&ledger).map_err(|e| format!("ledger create: {e}"))?;
        f.write_all(updated.as_bytes())
            .map_err(|e| format!("ledger write: {e}"))?;
        f.sync_all().map_err(|e| format!("ledger sync: {e}"))?;
    }
    println!("run {run_number}");

    let entries = fs::read_dir(dir)
        .map_err(|e| format!("read_dir: {e}"))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if !entries.iter().any(|n| n == "runs.txt") {
        return Err(format!("ledger missing from listing: {entries:?}"));
    }

    Ok(())
}
