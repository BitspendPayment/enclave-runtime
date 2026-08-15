//! Error mapping between `s3fs_core::FsError` and the WIT
//! `wasi:filesystem/types/error-code` enum.
//!
//! `S3WasiFsError` is the trappable wrapper bindgen wants — it holds either
//! a clean `ErrorCode` value (returned to the guest) or an `anyhow::Error`
//! (which becomes a trap).

use s3fs_core::FsError;
use wasmtime_wasi::TrappableError;

use crate::wasi::bindings::wasi::filesystem::types::ErrorCode;

/// The host-side error type the bindgen-generated traits return.
pub type S3WasiFsError = TrappableError<ErrorCode>;

/// Convenience alias.
pub type S3WasiFsResult<T> = Result<T, S3WasiFsError>;

/// Translate an `s3fs_core::FsError` to a WIT `error-code`. Categories that
/// don't have a clean WIT equivalent fall back to `Io`.
pub fn from_fs(e: FsError) -> ErrorCode {
    match e {
        FsError::NotFound => ErrorCode::NoEntry,
        FsError::AccessDenied => ErrorCode::Access,
        FsError::AlreadyExists => ErrorCode::Exist,
        FsError::IsDirectory => ErrorCode::IsDirectory,
        FsError::NotDirectory => ErrorCode::NotDirectory,
        FsError::NotEmpty => ErrorCode::NotEmpty,
        FsError::NameTooLong => ErrorCode::NameTooLong,
        FsError::IllegalByteSequence => ErrorCode::IllegalByteSequence,
        FsError::FileTooLarge => ErrorCode::FileTooLarge,
        FsError::NotSupported => ErrorCode::Unsupported,
        FsError::NotPermitted => ErrorCode::NotPermitted,
        FsError::Invalid(_) => ErrorCode::Invalid,
        FsError::OutOfMemory => ErrorCode::InsufficientMemory,
        FsError::Loop => ErrorCode::Loop,
        FsError::CrossDevice => ErrorCode::CrossDevice,
        FsError::BadDescriptor => ErrorCode::BadDescriptor,
        FsError::WouldBlock => ErrorCode::WouldBlock,
        // PreconditionFailed (CAS conflict) — surface as Exist for `O_EXCL`-
        // style failures; callers that want different semantics can re-map
        // before this point.
        FsError::Conflict => ErrorCode::Exist,
        // Verification failures. WASI has no "the storage lied to us" code, so
        // these surface as `Io` — the guest sees an unreadable filesystem
        // rather than plausible-looking wrong bytes, which is the whole point.
        FsError::Integrity(_) | FsError::Rollback { .. } => ErrorCode::Io,
        FsError::IoTimeout => ErrorCode::Io,
        FsError::Io(_) | FsError::Network(_) => ErrorCode::Io,
    }
}

/// Helper used throughout the host impls: convert any `Result<T, FsError>`
/// into the trappable wrapper bindgen expects.
pub trait IntoS3WasiResult<T> {
    fn into_wasi(self) -> S3WasiFsResult<T>;
}

impl<T> IntoS3WasiResult<T> for Result<T, FsError> {
    fn into_wasi(self) -> S3WasiFsResult<T> {
        self.map_err(|e| S3WasiFsError::from(from_fs(e)))
    }
}
