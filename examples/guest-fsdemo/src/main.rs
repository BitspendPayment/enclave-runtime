//! `guest-fsdemo` — Wasm component that exercises `wasi:filesystem`
//! end-to-end.
//!
//! Build with:
//! ```bash
//! cargo build --release --target wasm32-wasip2
//! ```
//!
//! Run with the s3fs-runner pointed at MinIO or AWS. The component prints
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

    // Step 6: delete the file and the directory.
    // (Symlinks are tested separately by the s3fs-core MinIO integration
    // suite; std::os::wasi::fs::symlink_path is unstable behind `wasi_ext`
    // so we don't exercise it from the guest in v1.)
    fs::remove_file(&renamed)?;
    fs::remove_dir(&dir)?;

    // Verify deletion: stat should now return NotFound.
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
