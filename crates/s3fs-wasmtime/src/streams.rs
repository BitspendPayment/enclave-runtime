//! `wasi:io/streams` impls over `s3fs-core::Fs::pread` / `pwrite`.
//!
//! The strategy keeps the synchronous `read`/`write`/`check_write`/`flush`
//! trait methods cheap by deferring all real I/O to `Pollable::ready()`,
//! which IS async — write/read just queue a request and ready does the
//! actual `pwrite`/`pread` await. Guests that follow the standard WASI
//! pattern (write → poll/block → check_write → write) drive this correctly.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use s3fs_core::{FileHandle, Fs};
use wasmtime_wasi::p2::{InputStream, OutputStream, Pollable, StreamError, StreamResult};

use crate::error_map::from_fs;

/// Soft cap on `check_write` permits. Big enough to fit a typical write
/// buffer in one shot.
const WRITE_PERMIT: usize = 64 * 1024;

#[derive(Debug)]
pub struct S3OutputStream {
    fs: Arc<Fs>,
    handle: Arc<FileHandle>,
    position: u64,
    pending: Option<Bytes>,
    last_error: Option<wasmtime::Error>,
    closed: bool,
}

impl S3OutputStream {
    pub fn write_at(fs: Arc<Fs>, handle: Arc<FileHandle>, offset: u64) -> Self {
        Self {
            fs,
            handle,
            position: offset,
            pending: None,
            last_error: None,
            closed: false,
        }
    }
}

#[async_trait]
impl Pollable for S3OutputStream {
    async fn ready(&mut self) {
        if let Some(bytes) = self.pending.take() {
            let len = bytes.len();
            match self.fs.pwrite(&self.handle, self.position, &bytes).await {
                Ok(written) => {
                    debug_assert_eq!(written, len);
                    self.position += written as u64;
                }
                Err(e) => {
                    self.last_error = Some(wasmtime::Error::msg(format!(
                        "{:?}",
                        from_fs(e)
                    )));
                }
            }
        }
    }
}

impl OutputStream for S3OutputStream {
    fn check_write(&mut self) -> StreamResult<usize> {
        if self.closed {
            return Err(StreamError::Closed);
        }
        if let Some(e) = self.last_error.take() {
            return Err(StreamError::LastOperationFailed(e));
        }
        if self.pending.is_some() {
            // Caller must wait on `ready()` before writing more.
            return Ok(0);
        }
        Ok(WRITE_PERMIT)
    }

    fn write(&mut self, bytes: Bytes) -> StreamResult<()> {
        if self.closed {
            return Err(StreamError::Closed);
        }
        if self.pending.is_some() {
            return Err(StreamError::trap(
                "write called before check_write returned a positive permit",
            ));
        }
        if bytes.is_empty() {
            return Ok(());
        }
        self.pending = Some(bytes);
        Ok(())
    }

    fn flush(&mut self) -> StreamResult<()> {
        // Pending writes are drained by `ready()`. We don't sync to S3 here —
        // the guest must call `descriptor.sync()` explicitly for durability.
        Ok(())
    }
}

#[derive(Debug)]
pub struct S3InputStream {
    fs: Arc<Fs>,
    handle: Arc<FileHandle>,
    position: u64,
    /// Pending request size — set by `read`, consumed by `ready`.
    pending: Option<usize>,
    /// Result of the last fetch, surfaced on next `read`.
    buffered: Option<Bytes>,
    last_error: Option<wasmtime::Error>,
    eof: bool,
}

impl S3InputStream {
    pub fn read_at(fs: Arc<Fs>, handle: Arc<FileHandle>, offset: u64) -> Self {
        Self {
            fs,
            handle,
            position: offset,
            pending: None,
            buffered: None,
            last_error: None,
            eof: false,
        }
    }
}

#[async_trait]
impl Pollable for S3InputStream {
    async fn ready(&mut self) {
        if self.buffered.is_some() || self.eof || self.last_error.is_some() {
            return;
        }
        let size = self.pending.take().unwrap_or(WRITE_PERMIT);
        match self.fs.pread(&self.handle, self.position, size).await {
            Ok(b) => {
                if b.is_empty() {
                    self.eof = true;
                } else {
                    self.position += b.len() as u64;
                }
                self.buffered = Some(b);
            }
            Err(e) => {
                self.last_error = Some(wasmtime::Error::msg(format!("{:?}", from_fs(e))));
            }
        }
    }
}

impl InputStream for S3InputStream {
    fn read(&mut self, size: usize) -> StreamResult<Bytes> {
        if let Some(e) = self.last_error.take() {
            return Err(StreamError::LastOperationFailed(e));
        }
        if let Some(buf) = self.buffered.take() {
            if buf.is_empty() && self.eof {
                return Err(StreamError::Closed);
            }
            if buf.len() <= size {
                return Ok(buf);
            }
            let split = buf.slice(0..size);
            self.buffered = Some(buf.slice(size..));
            return Ok(split);
        }
        if self.eof {
            return Err(StreamError::Closed);
        }
        self.pending = Some(size);
        Ok(Bytes::new())
    }
}
