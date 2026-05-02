//! Path resolution and key encoding.
//!
//! WASI Preview 2 uses openat-style paths: every operation is relative to a
//! directory descriptor, with no ambient absolute paths. This module enforces
//! that contract and produces clean S3 keys from guest-supplied relative paths.
//!
//! Containment: `..` may pop above the descriptor's current directory but not
//! above the preopen root the descriptor was derived from. Paths attempting
//! such an escape return [`FsError::NotPermitted`].
//!
//! Encoding: forward-slash maps directly to S3 key separator. NUL and control
//! bytes are rejected as illegal byte sequences. Per-segment length is capped
//! at 255 (POSIX `NAME_MAX`); total resolved key length at 1024 (S3 limit).

use crate::errors::{FsError, FsResult};

/// POSIX `NAME_MAX`.
pub const MAX_SEGMENT_LEN: usize = 255;

/// S3 object-key length limit.
pub const MAX_KEY_LEN: usize = 1024;

/// Maximum stored target body for a symlink. Far longer than any sane path.
pub const MAX_SYMLINK_TARGET_LEN: usize = 4 * 1024;

/// Validate a single path segment (a slash-free name).
///
/// Rejects:
/// - empty string, `.`, `..` (reserved; handled by the resolver, never stored)
/// - segments longer than [`MAX_SEGMENT_LEN`]
/// - NUL (`0x00`) and any other control byte (`0x01..=0x1F` or `0x7F`)
pub fn validate_segment(name: &str) -> FsResult<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(FsError::Invalid("reserved or empty path segment"));
    }
    if name.len() > MAX_SEGMENT_LEN {
        return Err(FsError::NameTooLong);
    }
    for &b in name.as_bytes() {
        if b == 0 || b < 0x20 || b == 0x7F {
            return Err(FsError::IllegalByteSequence);
        }
    }
    Ok(())
}

/// Resolve a guest-supplied relative path against a descriptor's current
/// directory key, with preopen-root containment enforced.
///
/// - `preopen_root`: bucket-relative key prefix where the preopen was rooted.
///   Must not start or end with `/`. May be empty (preopen at bucket root).
/// - `base_key`: bucket-relative key for the descriptor's current directory.
///   Must begin with `preopen_root` (debug-asserted). Empty means the preopen
///   root itself.
/// - `rel_path`: guest-supplied path. Must not be absolute. May contain `.`,
///   `..`, and multiple consecutive `/`.
///
/// Returns the resolved bucket-relative key with no leading slash, no trailing
/// slash, and no `.`/`..` components.
pub fn resolve_at(preopen_root: &str, base_key: &str, rel_path: &str) -> FsResult<String> {
    if rel_path.starts_with('/') {
        return Err(FsError::NotPermitted);
    }

    let mut stack: Vec<&str> = base_key.split('/').filter(|s| !s.is_empty()).collect();
    let floor = preopen_root.split('/').filter(|s| !s.is_empty()).count();

    debug_assert!(
        stack.len() >= floor,
        "base_key {:?} must extend preopen_root {:?}",
        base_key,
        preopen_root
    );

    for seg in rel_path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if stack.len() <= floor {
                return Err(FsError::NotPermitted);
            }
            stack.pop();
            continue;
        }
        validate_segment(seg)?;
        stack.push(seg);
    }

    let resolved = stack.join("/");
    if resolved.len() > MAX_KEY_LEN {
        return Err(FsError::NameTooLong);
    }
    Ok(resolved)
}

/// Append a trailing `/` to a key for use as an explicit directory marker.
/// Returns the empty string unchanged (the bucket root needs no marker).
pub fn dir_marker_key(key: &str) -> String {
    if key.is_empty() || key.ends_with('/') {
        key.to_string()
    } else {
        let mut s = String::with_capacity(key.len() + 1);
        s.push_str(key);
        s.push('/');
        s
    }
}

/// Strip a single trailing `/` if present. Used when normalising directory
/// keys back to their plain form.
pub fn strip_trailing_slash(key: &str) -> &str {
    key.strip_suffix('/').unwrap_or(key)
}

/// Split a resolved key into `(parent_dir_key, basename)`.
///
/// `parent_dir_key` is empty if the key has no parent (top-level under the
/// preopen root). `basename` is empty for the empty key.
pub fn split_parent(key: &str) -> (&str, &str) {
    match key.rfind('/') {
        Some(idx) => (&key[..idx], &key[idx + 1..]),
        None => ("", key),
    }
}

/// Join a `bucket_prefix` with an internal mount-relative key to get the key
/// that should be sent on the wire to the backend.
///
/// - Empty `prefix` → `key` unchanged.
/// - Empty `key` → `prefix` unchanged.
/// - Otherwise: `"{prefix}/{key}"` with no double slash.
pub fn join_prefix(prefix: &str, key: &str) -> String {
    let prefix = strip_trailing_slash(prefix);
    if prefix.is_empty() {
        return key.to_string();
    }
    if key.is_empty() {
        return prefix.to_string();
    }
    let mut s = String::with_capacity(prefix.len() + 1 + key.len());
    s.push_str(prefix);
    s.push('/');
    s.push_str(key);
    s
}

/// Validate a stored symlink-target body. Targets are themselves treated as
/// guest paths and resolved at follow-time, but the byte-level body must be
/// short and free of illegal characters.
pub fn validate_symlink_target(target: &str) -> FsResult<()> {
    if target.is_empty() {
        return Err(FsError::Invalid("empty symlink target"));
    }
    if target.len() > MAX_SYMLINK_TARGET_LEN {
        return Err(FsError::NameTooLong);
    }
    for &b in target.as_bytes() {
        if b == 0 {
            return Err(FsError::IllegalByteSequence);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- validate_segment ----------

    #[test]
    fn validate_segment_rejects_reserved() {
        assert!(matches!(validate_segment(""), Err(FsError::Invalid(_))));
        assert!(matches!(validate_segment("."), Err(FsError::Invalid(_))));
        assert!(matches!(validate_segment(".."), Err(FsError::Invalid(_))));
    }

    #[test]
    fn validate_segment_rejects_long_names() {
        let s = "a".repeat(MAX_SEGMENT_LEN + 1);
        assert!(matches!(validate_segment(&s), Err(FsError::NameTooLong)));
        // Boundary: exactly MAX_SEGMENT_LEN is fine.
        let s = "a".repeat(MAX_SEGMENT_LEN);
        assert!(validate_segment(&s).is_ok());
    }

    #[test]
    fn validate_segment_rejects_nul_and_control() {
        assert!(matches!(
            validate_segment("foo\0bar"),
            Err(FsError::IllegalByteSequence)
        ));
        assert!(matches!(
            validate_segment("foo\nbar"),
            Err(FsError::IllegalByteSequence)
        ));
        assert!(matches!(
            validate_segment("foo\x7Fbar"),
            Err(FsError::IllegalByteSequence)
        ));
    }

    #[test]
    fn validate_segment_accepts_unicode() {
        assert!(validate_segment("héllo.txt").is_ok());
        assert!(validate_segment("файл").is_ok());
        assert!(validate_segment("文件.json").is_ok());
    }

    // ---------- resolve_at: basic shapes ----------

    #[test]
    fn resolve_simple_relative() {
        assert_eq!(resolve_at("", "", "foo.txt").unwrap(), "foo.txt");
        assert_eq!(resolve_at("", "", "a/b/c.txt").unwrap(), "a/b/c.txt");
    }

    #[test]
    fn resolve_extends_base() {
        assert_eq!(
            resolve_at("", "dir/sub", "file.txt").unwrap(),
            "dir/sub/file.txt"
        );
    }

    #[test]
    fn resolve_collapses_double_slashes() {
        assert_eq!(resolve_at("", "", "a//b///c").unwrap(), "a/b/c");
    }

    #[test]
    fn resolve_skips_dot_components() {
        assert_eq!(resolve_at("", "dir", "./file").unwrap(), "dir/file");
        assert_eq!(resolve_at("", "dir", "a/./b/./c").unwrap(), "dir/a/b/c");
        assert_eq!(resolve_at("", "dir", ".").unwrap(), "dir");
    }

    #[test]
    fn resolve_pops_on_dotdot() {
        assert_eq!(resolve_at("", "dir/sub", "../sibling").unwrap(), "dir/sibling");
        assert_eq!(resolve_at("", "a/b/c", "../../x").unwrap(), "a/x");
    }

    #[test]
    fn resolve_empty_path_returns_base() {
        assert_eq!(resolve_at("", "dir/sub", "").unwrap(), "dir/sub");
    }

    // ---------- resolve_at: containment ----------

    #[test]
    fn rejects_absolute_path() {
        assert!(matches!(
            resolve_at("", "dir", "/etc/passwd"),
            Err(FsError::NotPermitted)
        ));
        assert!(matches!(
            resolve_at("data", "data/foo", "/escape"),
            Err(FsError::NotPermitted)
        ));
    }

    #[test]
    fn rejects_dotdot_escape_above_preopen_root() {
        // preopen at "data", descriptor at "data/foo", trying to escape:
        assert!(matches!(
            resolve_at("data", "data/foo", "../../escape"),
            Err(FsError::NotPermitted)
        ));
        // But popping just back to the preopen root is fine:
        assert_eq!(
            resolve_at("data", "data/foo", "..").unwrap(),
            "data"
        );
        // And popping to a sibling within the preopen is fine:
        assert_eq!(
            resolve_at("data", "data/foo/bar", "../sib").unwrap(),
            "data/foo/sib"
        );
    }

    #[test]
    fn dotdot_at_preopen_root_is_rejected() {
        assert!(matches!(
            resolve_at("", "", ".."),
            Err(FsError::NotPermitted)
        ));
        assert!(matches!(
            resolve_at("data", "data", ".."),
            Err(FsError::NotPermitted)
        ));
    }

    // ---------- resolve_at: limits ----------

    #[test]
    fn rejects_segment_too_long() {
        let long = "a".repeat(MAX_SEGMENT_LEN + 1);
        assert!(matches!(
            resolve_at("", "", &long),
            Err(FsError::NameTooLong)
        ));
    }

    #[test]
    fn rejects_total_key_too_long() {
        // Build a path where each segment is valid but the total exceeds 1024.
        let seg = "a".repeat(MAX_SEGMENT_LEN); // 255
        let path = std::iter::repeat(seg.as_str())
            .take(5) // 5*255 + 4 separators = 1279 > 1024
            .collect::<Vec<_>>()
            .join("/");
        assert!(matches!(
            resolve_at("", "", &path),
            Err(FsError::NameTooLong)
        ));
    }

    #[test]
    fn rejects_nul_byte_in_segment() {
        assert!(matches!(
            resolve_at("", "", "foo/bar\0baz"),
            Err(FsError::IllegalByteSequence)
        ));
    }

    // ---------- helpers ----------

    #[test]
    fn dir_marker_appends_slash() {
        assert_eq!(dir_marker_key("foo"), "foo/");
        assert_eq!(dir_marker_key("foo/"), "foo/");
        assert_eq!(dir_marker_key(""), "");
    }

    #[test]
    fn strip_trailing_slash_works() {
        assert_eq!(strip_trailing_slash("foo/"), "foo");
        assert_eq!(strip_trailing_slash("foo"), "foo");
        assert_eq!(strip_trailing_slash(""), "");
        assert_eq!(strip_trailing_slash("/"), "");
    }

    #[test]
    fn split_parent_basic() {
        assert_eq!(split_parent("a/b/c"), ("a/b", "c"));
        assert_eq!(split_parent("foo"), ("", "foo"));
        assert_eq!(split_parent(""), ("", ""));
    }

    #[test]
    fn join_prefix_handles_empties_and_trailing_slashes() {
        assert_eq!(join_prefix("", "foo/bar"), "foo/bar");
        assert_eq!(join_prefix("data", ""), "data");
        assert_eq!(join_prefix("data", "foo"), "data/foo");
        assert_eq!(join_prefix("data/", "foo"), "data/foo"); // trailing slash collapsed
        assert_eq!(join_prefix("", ""), "");
    }

    // ---------- validate_symlink_target ----------

    #[test]
    fn symlink_target_rejects_empty_and_long() {
        assert!(matches!(
            validate_symlink_target(""),
            Err(FsError::Invalid(_))
        ));
        let s = "a".repeat(MAX_SYMLINK_TARGET_LEN + 1);
        assert!(matches!(
            validate_symlink_target(&s),
            Err(FsError::NameTooLong)
        ));
    }

    #[test]
    fn symlink_target_rejects_nul() {
        assert!(matches!(
            validate_symlink_target("a\0b"),
            Err(FsError::IllegalByteSequence)
        ));
    }

    #[test]
    fn symlink_target_accepts_relative_and_absolute() {
        // Validation is purely byte-level; relative-vs-absolute is decided at
        // follow-time by the resolver.
        assert!(validate_symlink_target("../sibling").is_ok());
        assert!(validate_symlink_target("/abs/path").is_ok());
        assert!(validate_symlink_target("plain.txt").is_ok());
    }
}
