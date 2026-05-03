//! `FsError` — the engine's internal error type.
//!
//! Translation to WASI Preview 2 `wasi:filesystem/types::error-code` happens in
//! the `s3fs-wasmtime` crate. Inside the engine we keep error variants close to
//! POSIX-flavored categories so call sites are obvious.

use thiserror::Error;

/// Filesystem-engine error. Variants are picked to map cleanly onto
/// `wasi:filesystem/types::error-code` while staying intelligible inside the
/// engine itself.
#[derive(Debug, Error)]
pub enum FsError {
    #[error("not found")]
    NotFound,

    #[error("access denied")]
    AccessDenied,

    #[error("already exists")]
    AlreadyExists,

    #[error("is a directory")]
    IsDirectory,

    #[error("not a directory")]
    NotDirectory,

    #[error("directory not empty")]
    NotEmpty,

    #[error("name too long")]
    NameTooLong,

    #[error("illegal byte sequence in path or key")]
    IllegalByteSequence,

    #[error("file too large")]
    FileTooLarge,

    #[error("operation not supported")]
    NotSupported,

    #[error("operation not permitted")]
    NotPermitted,

    #[error("invalid argument: {0}")]
    Invalid(&'static str),

    #[error("out of memory")]
    OutOfMemory,

    #[error("symlink loop or recursion limit exceeded")]
    Loop,

    #[error("cross-device link or rename")]
    CrossDevice,

    #[error("bad descriptor")]
    BadDescriptor,

    #[error("would block")]
    WouldBlock,

    /// Optimistic-concurrency conflict, e.g. a conditional `PutObject`
    /// returned `PreconditionFailed`. Translation depends on context (caller
    /// decides whether to map to `Exist`, `WouldBlock`, or `Invalid`).
    #[error("precondition / CAS conflict")]
    Conflict,

    #[error("i/o timeout")]
    IoTimeout,

    #[error("i/o error: {0}")]
    Io(String),

    #[error("network error: {0}")]
    Network(String),
}

impl FsError {
    /// `true` if the error is plausibly transient and worth retrying with
    /// backoff (network blips, throttling, 5xx). Persistent errors like
    /// `NotFound` or `AccessDenied` return `false`.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            FsError::IoTimeout | FsError::Network(_) | FsError::WouldBlock
        )
    }
}

/// Convenience alias used throughout the crate.
pub type FsResult<T> = Result<T, FsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_stable() {
        assert_eq!(FsError::NotFound.to_string(), "not found");
        assert_eq!(
            FsError::Loop.to_string(),
            "symlink loop or recursion limit exceeded"
        );
        assert_eq!(
            FsError::Invalid("bad part number").to_string(),
            "invalid argument: bad part number"
        );
    }

    #[test]
    fn is_transient_categorisation() {
        assert!(FsError::IoTimeout.is_transient());
        assert!(FsError::Network("dns".into()).is_transient());
        assert!(FsError::WouldBlock.is_transient());

        assert!(!FsError::NotFound.is_transient());
        assert!(!FsError::AccessDenied.is_transient());
        assert!(!FsError::Loop.is_transient());
        assert!(!FsError::Conflict.is_transient());
    }
}
