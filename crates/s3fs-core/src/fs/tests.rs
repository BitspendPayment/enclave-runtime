//! POSIX-semantics tests for [`Fs`].
//!
//! The store layer is covered in `store::*`; these exercise the filesystem
//! behaviour built on top of it, and in particular the semantics that the
//! previous path-to-key engine could not provide.

use super::*;
use crate::backend::memory::MemoryBackend;

/// Two buckets that survive a remount, mirroring the deployment split.
struct Harness {
    data: Arc<MemoryBackend>,
    roots: Arc<MemoryBackend>,
    config: Arc<Config>,
}

impl Harness {
    fn new() -> Self {
        Harness {
            data: Arc::new(MemoryBackend::new()),
            roots: Arc::new(MemoryBackend::new()),
            // Small records so multi-record files are cheap to write, and no
            // retention so a test can inspect the buckets freely.
            config: Arc::new(
                Config::builder()
                    .record_size(4096)
                    .root_retention(None)
                    .build(),
            ),
        }
    }

    async fn mount(&self) -> Arc<Fs> {
        Fs::mount(
            self.data.clone(),
            self.roots.clone(),
            &MasterSecret::from_bytes([21u8; 32]),
            [9u8; 16],
            self.config.clone(),
            None,
        )
        .await
        .unwrap()
    }
}

async fn fs() -> Arc<Fs> {
    Harness::new().mount().await
}

async fn write_file(fs: &Fs, path: &str, data: &[u8]) {
    let h = fs.open(path, OpenFlags::create_new()).await.unwrap();
    fs.pwrite(&h, 0, data).await.unwrap();
    fs.close(&h).await.unwrap();
}

async fn read_file(fs: &Fs, path: &str) -> Vec<u8> {
    let h = fs.open(path, OpenFlags::read_only()).await.unwrap();
    let size = h.size().await;
    let out = fs.pread(&h, 0, size as usize).await.unwrap();
    fs.close(&h).await.unwrap();
    out.to_vec()
}

async fn names(fs: &Fs, dir: &Arc<Inode>) -> Vec<String> {
    fs.read_dir(dir)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect()
}

// ---- mount and namespace ---------------------------------------------------

#[tokio::test]
async fn a_fresh_mount_has_an_empty_root_directory() {
    let fs = fs().await;
    let root = fs.root();
    assert_eq!(fs.stat(&root).await.unwrap().kind, InodeKind::Directory);
    assert_eq!(names(&fs, &root).await, Vec::<String>::new());
}

#[tokio::test]
async fn mkdir_then_list() {
    let fs = fs().await;
    let root = fs.root();
    fs.mkdir(&root, "b").await.unwrap();
    fs.mkdir(&root, "a").await.unwrap();

    assert_eq!(names(&fs, &root).await, vec!["a", "b"]);
    let a = fs.lookup_at(&root, "a").await.unwrap();
    assert_eq!(fs.stat(&a).await.unwrap().kind, InodeKind::Directory);
}

#[tokio::test]
async fn mkdir_refuses_a_name_already_in_use() {
    let fs = fs().await;
    let root = fs.root();
    fs.mkdir(&root, "dup").await.unwrap();
    assert!(matches!(
        fs.mkdir(&root, "dup").await,
        Err(FsError::AlreadyExists)
    ));
}

#[tokio::test]
async fn nested_directories_resolve() {
    let fs = fs().await;
    let root = fs.root();
    let a = fs.mkdir(&root, "a").await.unwrap();
    let b = fs.mkdir(&a, "b").await.unwrap();
    fs.mkdir(&b, "c").await.unwrap();

    let c = fs.lookup_at(&root, "a/b/c").await.unwrap();
    assert_eq!(fs.stat(&c).await.unwrap().kind, InodeKind::Directory);
    assert!(matches!(
        fs.lookup_at(&root, "a/nope/c").await,
        Err(FsError::NotFound)
    ));
}

#[tokio::test]
async fn dotdot_walks_up_and_stops_at_the_root() {
    let fs = fs().await;
    let root = fs.root();
    let a = fs.mkdir(&root, "a").await.unwrap();
    fs.mkdir(&a, "b").await.unwrap();
    write_file(&fs, "/marker", b"x").await;

    let up = fs.lookup_at(&root, "a/b/../..").await.unwrap();
    assert_eq!(up.objid(), root.objid());

    // `..` past the root must not escape the mount.
    let clamped = fs.lookup_at(&root, "../../../marker").await.unwrap();
    assert_eq!(fs.stat(&clamped).await.unwrap().size, 1);
}

#[tokio::test]
async fn dot_components_are_ignored() {
    let fs = fs().await;
    let root = fs.root();
    fs.mkdir(&root, "a").await.unwrap();
    write_file(&fs, "/a/f", b"hi").await;
    assert_eq!(read_file(&fs, "/./a/./f").await, b"hi");
}

// ---- files -----------------------------------------------------------------

#[tokio::test]
async fn write_then_read_back() {
    let fs = fs().await;
    write_file(&fs, "/hello.txt", b"hello world").await;
    assert_eq!(read_file(&fs, "/hello.txt").await, b"hello world");
}

#[tokio::test]
async fn a_writer_sees_its_own_unsynced_writes() {
    let fs = fs().await;
    let h = fs.open("/f", OpenFlags::create_new()).await.unwrap();
    fs.pwrite(&h, 0, b"abcdef").await.unwrap();
    assert_eq!(
        fs.pread(&h, 2, 3).await.unwrap(),
        Bytes::from_static(b"cde")
    );
    fs.close(&h).await.unwrap();
}

#[tokio::test]
async fn writes_spanning_many_records_round_trip() {
    let fs = fs().await;
    // 10 records at 4 KiB, written in one call.
    let data: Vec<u8> = (0..40960u32).map(|i| (i % 251) as u8).collect();
    write_file(&fs, "/big", &data).await;
    assert_eq!(read_file(&fs, "/big").await, data);
}

#[tokio::test]
async fn a_write_in_the_middle_leaves_the_rest_intact() {
    let fs = fs().await;
    let data = vec![0xaau8; 12288];
    write_file(&fs, "/f", &data).await;

    let h = fs.open("/f", OpenFlags::read_write()).await.unwrap();
    fs.pwrite(&h, 5000, b"PATCH").await.unwrap();
    fs.close(&h).await.unwrap();

    let mut expected = data.clone();
    expected[5000..5005].copy_from_slice(b"PATCH");
    assert_eq!(read_file(&fs, "/f").await, expected);
}

#[tokio::test]
async fn sparse_writes_read_back_as_zeros() {
    let fs = fs().await;
    let h = fs.open("/sparse", OpenFlags::create_new()).await.unwrap();
    fs.pwrite(&h, 100_000, b"end").await.unwrap();
    fs.close(&h).await.unwrap();

    let out = read_file(&fs, "/sparse").await;
    assert_eq!(out.len(), 100_003);
    assert!(out[..100_000].iter().all(|&b| b == 0));
    assert_eq!(&out[100_000..], b"end");
}

#[tokio::test]
async fn reads_past_the_end_return_nothing() {
    let fs = fs().await;
    write_file(&fs, "/f", b"12345").await;
    let h = fs.open("/f", OpenFlags::read_only()).await.unwrap();
    assert_eq!(fs.pread(&h, 5, 10).await.unwrap().len(), 0);
    assert_eq!(
        fs.pread(&h, 3, 10).await.unwrap(),
        Bytes::from_static(b"45")
    );
}

#[tokio::test]
async fn append_writes_at_the_end() {
    let fs = fs().await;
    write_file(&fs, "/log", b"one").await;
    let h = fs
        .open(
            "/log",
            OpenFlags {
                write: true,
                append: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    // The offset is ignored for an append handle.
    fs.pwrite(&h, 0, b"-two").await.unwrap();
    fs.close(&h).await.unwrap();
    assert_eq!(read_file(&fs, "/log").await, b"one-two");
}

#[tokio::test]
async fn exclusive_create_refuses_an_existing_file() {
    let fs = fs().await;
    write_file(&fs, "/f", b"x").await;
    assert!(matches!(
        fs.open("/f", OpenFlags::create_new()).await,
        Err(FsError::AlreadyExists)
    ));
}

#[tokio::test]
async fn opening_a_missing_file_without_create_fails() {
    let fs = fs().await;
    assert!(matches!(
        fs.open("/nope", OpenFlags::read_only()).await,
        Err(FsError::NotFound)
    ));
}

#[tokio::test]
async fn truncate_on_open_empties_the_file() {
    let fs = fs().await;
    write_file(&fs, "/f", b"content").await;
    let h = fs
        .open(
            "/f",
            OpenFlags {
                read: true,
                write: true,
                truncate: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(h.size().await, 0);
    fs.close(&h).await.unwrap();
    assert_eq!(read_file(&fs, "/f").await, b"");
}

#[tokio::test]
async fn set_size_truncates_and_grows() {
    let fs = fs().await;
    write_file(&fs, "/f", b"0123456789").await;

    let h = fs.open("/f", OpenFlags::read_write()).await.unwrap();
    fs.set_size(&h, 4).await.unwrap();
    fs.close(&h).await.unwrap();
    assert_eq!(read_file(&fs, "/f").await, b"0123");

    // Growing is free: the new region is a hole, at any size.
    let h = fs.open("/f", OpenFlags::read_write()).await.unwrap();
    fs.set_size(&h, 1_000_000).await.unwrap();
    fs.close(&h).await.unwrap();

    let out = read_file(&fs, "/f").await;
    assert_eq!(out.len(), 1_000_000);
    assert_eq!(&out[..4], b"0123");
    assert!(out[4..].iter().all(|&b| b == 0));
}

#[tokio::test]
async fn a_regrown_file_does_not_resurrect_old_bytes() {
    let fs = fs().await;
    write_file(&fs, "/f", b"secretsecret").await;
    let h = fs.open("/f", OpenFlags::read_write()).await.unwrap();
    fs.set_size(&h, 2).await.unwrap();
    fs.set_size(&h, 12).await.unwrap();
    fs.close(&h).await.unwrap();

    let out = read_file(&fs, "/f").await;
    assert_eq!(&out[..2], b"se");
    assert!(out[2..].iter().all(|&b| b == 0), "stale data reappeared");
}

// ---- durability ------------------------------------------------------------

#[tokio::test]
async fn committed_state_survives_a_remount() {
    let h = Harness::new();
    let fs = h.mount().await;
    fs.mkdir(&fs.root(), "dir").await.unwrap();
    write_file(&fs, "/dir/file", b"durable").await;
    drop(fs);

    let fs = h.mount().await;
    assert_eq!(read_file(&fs, "/dir/file").await, b"durable");
    assert_eq!(names(&fs, &fs.root()).await, vec!["dir"]);
}

/// Dropping a handle without syncing loses the writes — but the filesystem is
/// still a consistent, verified state, never a torn one.
#[tokio::test]
async fn unsynced_writes_are_lost_but_leave_a_consistent_state() {
    let h = Harness::new();
    let fs = h.mount().await;
    write_file(&fs, "/f", b"committed").await;

    let handle = fs.open("/f", OpenFlags::read_write()).await.unwrap();
    fs.pwrite(&handle, 0, b"UNCOMMITTED").await.unwrap();
    drop(handle); // no close, no sync
    drop(fs);

    let fs = h.mount().await;
    assert_eq!(read_file(&fs, "/f").await, b"committed");
}

#[tokio::test]
async fn every_mutation_advances_the_root_sequence() {
    let fs = fs().await;
    let start = fs.store().root().await.unwrap().seq;

    fs.mkdir(&fs.root(), "a").await.unwrap();
    write_file(&fs, "/a/f", b"x").await;

    let end = fs.store().root().await.unwrap().seq;
    assert!(end > start, "mutations must produce new anchored roots");
}

// ---- rename ----------------------------------------------------------------

#[tokio::test]
async fn rename_within_a_directory() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/old", b"data").await;

    fs.rename(&root, "old", &root, "new").await.unwrap();
    assert_eq!(names(&fs, &root).await, vec!["new"]);
    assert_eq!(read_file(&fs, "/new").await, b"data");
    assert!(matches!(
        fs.lookup_at(&root, "old").await,
        Err(FsError::NotFound)
    ));
}

#[tokio::test]
async fn rename_across_directories() {
    let fs = fs().await;
    let root = fs.root();
    let a = fs.mkdir(&root, "a").await.unwrap();
    let b = fs.mkdir(&root, "b").await.unwrap();
    write_file(&fs, "/a/f", b"moved").await;

    fs.rename(&a, "f", &b, "g").await.unwrap();
    assert_eq!(names(&fs, &a).await, Vec::<String>::new());
    assert_eq!(names(&fs, &b).await, vec!["g"]);
    assert_eq!(read_file(&fs, "/b/g").await, b"moved");
}

/// The property the previous engine could not offer: a rename is one commit,
/// so no observer ever sees the entry under both names or under neither.
#[tokio::test]
async fn rename_is_a_single_commit() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/old", b"data").await;

    let before = fs.store().root().await.unwrap().seq;
    fs.rename(&root, "old", &root, "new").await.unwrap();
    let after = fs.store().root().await.unwrap().seq;
    assert_eq!(after, before + 1, "rename must be exactly one commit");
}

#[tokio::test]
async fn renaming_a_directory_moves_its_whole_subtree() {
    let fs = fs().await;
    let root = fs.root();
    let a = fs.mkdir(&root, "a").await.unwrap();
    fs.mkdir(&a, "sub").await.unwrap();
    write_file(&fs, "/a/sub/deep", b"deep").await;

    // A directory rename is one entry move, not a recursive copy.
    let before = fs.store().root().await.unwrap().seq;
    fs.rename(&root, "a", &root, "z").await.unwrap();
    assert_eq!(fs.store().root().await.unwrap().seq, before + 1);

    assert_eq!(read_file(&fs, "/z/sub/deep").await, b"deep");
}

#[tokio::test]
async fn renaming_a_directory_repoints_its_parent_link() {
    let fs = fs().await;
    let root = fs.root();
    let a = fs.mkdir(&root, "a").await.unwrap();
    let b = fs.mkdir(&root, "b").await.unwrap();
    let moved = fs.mkdir(&a, "moved").await.unwrap();

    fs.rename(&a, "moved", &b, "moved").await.unwrap();

    // `..` from inside the moved directory must lead to its new parent.
    let up = fs.lookup_at(&moved, "..").await.unwrap();
    assert_eq!(up.objid(), b.objid());
}

#[tokio::test]
async fn rename_replaces_an_existing_file() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/src", b"new").await;
    write_file(&fs, "/dst", b"old").await;

    fs.rename(&root, "src", &root, "dst").await.unwrap();
    assert_eq!(names(&fs, &root).await, vec!["dst"]);
    assert_eq!(read_file(&fs, "/dst").await, b"new");
}

#[tokio::test]
async fn rename_refuses_mismatched_kinds_and_non_empty_targets() {
    let fs = fs().await;
    let root = fs.root();
    fs.mkdir(&root, "dir").await.unwrap();
    fs.mkdir(&root, "full").await.unwrap();
    write_file(&fs, "/full/inside", b"x").await;
    write_file(&fs, "/file", b"x").await;

    assert!(matches!(
        fs.rename(&root, "file", &root, "dir").await,
        Err(FsError::IsDirectory)
    ));
    assert!(matches!(
        fs.rename(&root, "dir", &root, "file").await,
        Err(FsError::NotDirectory)
    ));
    assert!(matches!(
        fs.rename(&root, "dir", &root, "full").await,
        Err(FsError::NotEmpty)
    ));
}

#[tokio::test]
async fn renaming_onto_itself_is_a_no_op() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/f", b"x").await;
    fs.rename(&root, "f", &root, "f").await.unwrap();
    assert_eq!(read_file(&fs, "/f").await, b"x");
}

// ---- unlink and rmdir ------------------------------------------------------

#[tokio::test]
async fn unlink_removes_a_file() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/f", b"x").await;
    fs.unlink(&root, "f").await.unwrap();

    assert_eq!(names(&fs, &root).await, Vec::<String>::new());
    assert!(matches!(
        fs.lookup_at(&root, "f").await,
        Err(FsError::NotFound)
    ));
    assert!(matches!(
        fs.unlink(&root, "f").await,
        Err(FsError::NotFound)
    ));
}

#[tokio::test]
async fn rmdir_requires_an_empty_directory() {
    let fs = fs().await;
    let root = fs.root();
    fs.mkdir(&root, "d").await.unwrap();
    write_file(&fs, "/d/f", b"x").await;

    assert!(matches!(fs.rmdir(&root, "d").await, Err(FsError::NotEmpty)));
    fs.unlink(&fs.lookup_at(&root, "d").await.unwrap(), "f")
        .await
        .unwrap();
    fs.rmdir(&root, "d").await.unwrap();
    assert_eq!(names(&fs, &root).await, Vec::<String>::new());
}

#[tokio::test]
async fn unlink_and_rmdir_refuse_the_wrong_kind() {
    let fs = fs().await;
    let root = fs.root();
    fs.mkdir(&root, "d").await.unwrap();
    write_file(&fs, "/f", b"x").await;

    assert!(matches!(
        fs.unlink(&root, "d").await,
        Err(FsError::IsDirectory)
    ));
    assert!(matches!(
        fs.rmdir(&root, "f").await,
        Err(FsError::NotDirectory)
    ));
}

// ---- symlinks --------------------------------------------------------------

#[tokio::test]
async fn symlink_round_trips_and_resolves() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/target", b"pointed-at").await;
    fs.symlink_at(&root, "link", "target").await.unwrap();

    assert_eq!(fs.readlink_at(&root, "link").await.unwrap(), "target");
    assert_eq!(read_file(&fs, "/link").await, b"pointed-at");

    // Without following, the link itself is what resolves.
    let raw = fs.lookup_at_no_follow(&root, "link").await.unwrap();
    assert_eq!(fs.stat(&raw).await.unwrap().kind, InodeKind::Symlink);
}

#[tokio::test]
async fn symlinks_resolve_through_directories() {
    let fs = fs().await;
    let root = fs.root();
    let a = fs.mkdir(&root, "a").await.unwrap();
    fs.mkdir(&a, "real").await.unwrap();
    write_file(&fs, "/a/real/f", b"deep").await;
    fs.symlink_at(&root, "shortcut", "a/real").await.unwrap();

    assert_eq!(read_file(&fs, "/shortcut/f").await, b"deep");
}

#[tokio::test]
async fn an_absolute_symlink_resolves_from_the_root() {
    let fs = fs().await;
    let root = fs.root();
    fs.mkdir(&root, "d").await.unwrap();
    write_file(&fs, "/d/f", b"abs").await;
    let d = fs.lookup_at(&root, "d").await.unwrap();
    fs.symlink_at(&d, "link", "/d/f").await.unwrap();

    assert_eq!(read_file(&fs, "/d/link").await, b"abs");
}

#[tokio::test]
async fn a_symlink_loop_is_bounded() {
    let fs = fs().await;
    let root = fs.root();
    fs.symlink_at(&root, "a", "b").await.unwrap();
    fs.symlink_at(&root, "b", "a").await.unwrap();

    assert!(matches!(fs.lookup_at(&root, "a").await, Err(FsError::Loop)));
}

#[tokio::test]
async fn a_long_symlink_target_spills_to_blocks_and_reads_back() {
    let fs = fs().await;
    let root = fs.root();
    // Longer than the dnode's inline capacity, so it must use data blocks.
    let target = format!("/{}", "x".repeat(INLINE_CAP + 50));
    fs.symlink_at(&root, "long", &target).await.unwrap();
    assert_eq!(fs.readlink_at(&root, "long").await.unwrap(), target);
}

#[tokio::test]
async fn readlink_refuses_a_regular_file() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/f", b"x").await;
    assert!(fs.readlink_at(&root, "f").await.is_err());
}

// ---- attributes ------------------------------------------------------------

#[tokio::test]
async fn stat_reports_real_metadata() {
    let fs = fs().await;
    write_file(&fs, "/f", b"12345").await;
    let ino = fs.lookup_at(&fs.root(), "f").await.unwrap();
    let a = fs.stat(&ino).await.unwrap();

    assert_eq!(a.kind, InodeKind::RegularFile);
    assert_eq!(a.size, 5);
    assert_eq!(a.nlink, 1);
    assert_eq!(a.mode, DEFAULT_FILE_MODE);
}

/// Timestamps live in the dnode, so there is no S3 `LastModified` to disagree
/// with and no self-copy to persist them.
#[tokio::test]
async fn set_times_persists_exactly() {
    let fs = fs().await;
    write_file(&fs, "/f", b"x").await;

    let when = crate::inode::from_nanos(1_700_000_000_000_000_000);
    let h = fs.open("/f", OpenFlags::read_write()).await.unwrap();
    fs.set_times(&h, Some(when), Some(when)).await.unwrap();
    fs.close(&h).await.unwrap();

    let ino = fs.lookup_at(&fs.root(), "f").await.unwrap();
    let a = fs.stat(&ino).await.unwrap();
    assert_eq!(a.mtime, when);
    assert_eq!(a.atime, when);
}

#[tokio::test]
async fn set_times_at_works_without_a_handle() {
    let fs = fs().await;
    let root = fs.root();
    fs.mkdir(&root, "d").await.unwrap();

    let when = crate::inode::from_nanos(1_234_567_890);
    fs.set_times_at(&root, "d", None, Some(when), true)
        .await
        .unwrap();

    let d = fs.lookup_at(&root, "d").await.unwrap();
    assert_eq!(fs.stat(&d).await.unwrap().mtime, when);
}

/// Object ids are never reused, so identity holds across a remount — which is
/// what `is-same-object` and `metadata-hash` need in order to be exact.
#[tokio::test]
async fn identity_is_stable_across_a_remount() {
    let h = Harness::new();
    let fs = h.mount().await;
    write_file(&fs, "/f", b"x").await;
    let before = *fs.lookup_at(&fs.root(), "f").await.unwrap();
    drop(fs);

    let fs = h.mount().await;
    let after = *fs.lookup_at(&fs.root(), "f").await.unwrap();
    assert_eq!(before, after);
}

// ---- validation ------------------------------------------------------------

#[tokio::test]
async fn bad_names_are_rejected() {
    let fs = fs().await;
    let root = fs.root();
    assert!(fs.mkdir(&root, "with\0nul").await.is_err());
    assert!(fs.mkdir(&root, &"x".repeat(300)).await.is_err());
    assert!(fs.mkdir(&root, "").await.is_err());
}

#[tokio::test]
async fn opening_with_neither_read_nor_write_is_rejected() {
    let fs = fs().await;
    assert!(matches!(
        fs.open("/f", OpenFlags::default()).await,
        Err(FsError::Invalid(_))
    ));
}

#[tokio::test]
async fn writing_to_a_read_only_handle_is_refused() {
    let fs = fs().await;
    write_file(&fs, "/f", b"x").await;
    let h = fs.open("/f", OpenFlags::read_only()).await.unwrap();
    assert!(matches!(
        fs.pwrite(&h, 0, b"nope").await,
        Err(FsError::BadDescriptor)
    ));
}

#[tokio::test]
async fn opening_a_directory_for_writing_is_refused() {
    let fs = fs().await;
    fs.mkdir(&fs.root(), "d").await.unwrap();
    assert!(matches!(
        fs.open("/d", OpenFlags::write_only()).await,
        Err(FsError::IsDirectory)
    ));
}

#[tokio::test]
async fn resolving_through_a_file_is_refused() {
    let fs = fs().await;
    write_file(&fs, "/f", b"x").await;
    assert!(matches!(
        fs.lookup_at(&fs.root(), "f/inside").await,
        Err(FsError::NotDirectory)
    ));
}

// ---- integrity end to end --------------------------------------------------

/// The whole point of the design, exercised through the public API: corrupt a
/// slab and the filesystem refuses to serve the bytes rather than returning
/// plausible-looking wrong ones.
#[tokio::test]
async fn tampered_storage_is_refused_at_the_filesystem_layer() {
    use crate::backend::PutBlobInput;

    let h = Harness::new();
    let fs = h.mount().await;
    write_file(&fs, "/f", &vec![0x5au8; 8192]).await;
    drop(fs);

    // Flip a byte in every slab the data bucket holds.
    for key in h.data.keys() {
        let mut body = h.data.get_blob(&key, None).await.unwrap().body.to_vec();
        body[0] ^= 0xff;
        h.data
            .put_blob(PutBlobInput::new(key, Bytes::from(body)))
            .await
            .unwrap();
    }

    let fs = h.mount().await;
    let result = async {
        let handle = fs.open("/f", OpenFlags::read_only()).await?;
        fs.pread(&handle, 0, 8192).await
    }
    .await;
    assert!(
        matches!(result, Err(FsError::Integrity(_))),
        "expected an integrity failure, got {result:?}"
    );
}

// ---- hard links ------------------------------------------------------------

#[tokio::test]
async fn a_hard_link_shares_one_object() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/original", b"shared").await;

    fs.link_at(&root, "original", &root, "alias", true)
        .await
        .unwrap();

    assert_eq!(names(&fs, &root).await, vec!["alias", "original"]);
    assert_eq!(read_file(&fs, "/alias").await, b"shared");

    // Both names must be the same object, not a copy of it.
    let a = fs.lookup_at(&root, "original").await.unwrap();
    let b = fs.lookup_at(&root, "alias").await.unwrap();
    assert_eq!(*a, *b);
    assert_eq!(fs.stat(&a).await.unwrap().nlink, 2);
}

#[tokio::test]
async fn a_write_through_one_link_is_visible_through_the_other() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/a", b"before").await;
    fs.link_at(&root, "a", &root, "b", true).await.unwrap();

    let h = fs.open("/b", OpenFlags::read_write()).await.unwrap();
    fs.pwrite(&h, 0, b"after!").await.unwrap();
    fs.close(&h).await.unwrap();

    assert_eq!(read_file(&fs, "/a").await, b"after!");
}

#[tokio::test]
async fn unlinking_one_link_leaves_the_other() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/a", b"content").await;
    fs.link_at(&root, "a", &root, "b", true).await.unwrap();

    fs.unlink(&root, "a").await.unwrap();
    assert_eq!(read_file(&fs, "/b").await, b"content");

    let b = fs.lookup_at(&root, "b").await.unwrap();
    assert_eq!(fs.stat(&b).await.unwrap().nlink, 1);
    assert!(matches!(
        fs.lookup_at(&root, "a").await,
        Err(FsError::NotFound)
    ));

    // Removing the last link really does remove the object.
    fs.unlink(&root, "b").await.unwrap();
    assert_eq!(names(&fs, &root).await, Vec::<String>::new());
}

#[tokio::test]
async fn hard_links_survive_a_remount() {
    let h = Harness::new();
    let fs = h.mount().await;
    let root = fs.root();
    write_file(&fs, "/a", b"durable").await;
    fs.link_at(&root, "a", &root, "b", true).await.unwrap();
    drop(fs);

    let fs = h.mount().await;
    let a = fs.lookup_at(&fs.root(), "a").await.unwrap();
    let b = fs.lookup_at(&fs.root(), "b").await.unwrap();
    assert_eq!(*a, *b);
    assert_eq!(fs.stat(&a).await.unwrap().nlink, 2);
}

#[tokio::test]
async fn links_can_cross_directories() {
    let fs = fs().await;
    let root = fs.root();
    let d = fs.mkdir(&root, "d").await.unwrap();
    write_file(&fs, "/f", b"x").await;

    fs.link_at(&root, "f", &d, "linked", true).await.unwrap();
    assert_eq!(read_file(&fs, "/d/linked").await, b"x");
}

/// A hard link to a directory would turn the namespace into a graph, and the
/// dnode's parent link has room for exactly one answer.
#[tokio::test]
async fn a_directory_cannot_be_hard_linked() {
    let fs = fs().await;
    let root = fs.root();
    fs.mkdir(&root, "d").await.unwrap();
    assert!(matches!(
        fs.link_at(&root, "d", &root, "alias", true).await,
        Err(FsError::NotPermitted)
    ));
}

#[tokio::test]
async fn link_refuses_an_occupied_name_or_a_missing_source() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/a", b"x").await;
    write_file(&fs, "/b", b"y").await;

    assert!(matches!(
        fs.link_at(&root, "a", &root, "b", true).await,
        Err(FsError::AlreadyExists)
    ));
    assert!(matches!(
        fs.link_at(&root, "nope", &root, "c", true).await,
        Err(FsError::NotFound)
    ));
}

#[tokio::test]
async fn linking_a_symlink_can_target_the_link_itself() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/target", b"data").await;
    fs.symlink_at(&root, "sym", "target").await.unwrap();

    // Without following, the new name is a second link to the symlink object.
    fs.link_at(&root, "sym", &root, "sym2", false)
        .await
        .unwrap();
    assert_eq!(fs.readlink_at(&root, "sym2").await.unwrap(), "target");

    // Following, it is a second link to the file the symlink points at.
    fs.link_at(&root, "sym", &root, "direct", true)
        .await
        .unwrap();
    let direct = fs.lookup_at_no_follow(&root, "direct").await.unwrap();
    assert_eq!(fs.stat(&direct).await.unwrap().kind, InodeKind::RegularFile);
}

// ---- unlink while open -----------------------------------------------------

/// POSIX keeps an unlinked file alive until the last descriptor closes. The
/// previous engine could not do this at all.
#[tokio::test]
async fn an_unlinked_file_stays_readable_through_an_open_handle() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/doomed", b"still here").await;

    let h = fs.open("/doomed", OpenFlags::read_only()).await.unwrap();
    fs.unlink(&root, "doomed").await.unwrap();

    // The name is gone...
    assert!(matches!(
        fs.lookup_at(&root, "doomed").await,
        Err(FsError::NotFound)
    ));
    // ...but the handle still works.
    assert_eq!(
        fs.pread(&h, 0, 10).await.unwrap(),
        Bytes::from_static(b"still here")
    );
    fs.close(&h).await.unwrap();
}

#[tokio::test]
async fn an_unlinked_file_is_still_writable_through_its_handle() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/doomed", b"old").await;

    let h = fs.open("/doomed", OpenFlags::read_write()).await.unwrap();
    fs.unlink(&root, "doomed").await.unwrap();
    fs.pwrite(&h, 0, b"new").await.unwrap();
    assert_eq!(
        fs.pread(&h, 0, 3).await.unwrap(),
        Bytes::from_static(b"new")
    );
    fs.close(&h).await.unwrap();
}

#[tokio::test]
async fn the_object_is_freed_when_the_last_handle_closes() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/doomed", b"x").await;
    let ino = fs.lookup_at(&root, "doomed").await.unwrap();

    let h = fs.open("/doomed", OpenFlags::read_only()).await.unwrap();
    fs.unlink(&root, "doomed").await.unwrap();
    assert!(fs.stat(&ino).await.is_ok(), "still alive while open");

    fs.close(&h).await.unwrap();
    assert!(
        matches!(fs.stat(&ino).await, Err(FsError::NotFound)),
        "the last close must free it"
    );
}

#[tokio::test]
async fn the_object_survives_until_every_handle_closes() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/doomed", b"x").await;
    let ino = fs.lookup_at(&root, "doomed").await.unwrap();

    let a = fs.open("/doomed", OpenFlags::read_only()).await.unwrap();
    let b = fs.open("/doomed", OpenFlags::read_only()).await.unwrap();
    fs.unlink(&root, "doomed").await.unwrap();

    fs.close(&a).await.unwrap();
    assert!(fs.stat(&ino).await.is_ok(), "one handle remains");
    fs.close(&b).await.unwrap();
    assert!(matches!(fs.stat(&ino).await, Err(FsError::NotFound)));
}

/// A closed file with no remaining handles is freed immediately, not deferred.
#[tokio::test]
async fn unlinking_a_closed_file_frees_it_at_once() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/f", b"x").await;
    let ino = fs.lookup_at(&root, "f").await.unwrap();

    fs.unlink(&root, "f").await.unwrap();
    assert!(matches!(fs.stat(&ino).await, Err(FsError::NotFound)));
}

/// If the object gets a new name before the last close, it must not be freed.
#[tokio::test]
async fn relinking_before_the_last_close_cancels_the_free() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/f", b"rescued").await;

    let h = fs.open("/f", OpenFlags::read_only()).await.unwrap();
    fs.link_at(&root, "f", &root, "rescue", true).await.unwrap();
    fs.unlink(&root, "f").await.unwrap();
    fs.close(&h).await.unwrap();

    assert_eq!(read_file(&fs, "/rescue").await, b"rescued");
}

#[tokio::test]
async fn a_file_replaced_by_rename_stays_readable_while_open() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/victim", b"victim data").await;
    write_file(&fs, "/src", b"src data").await;

    let h = fs.open("/victim", OpenFlags::read_only()).await.unwrap();
    fs.rename(&root, "src", &root, "victim").await.unwrap();

    assert_eq!(read_file(&fs, "/victim").await, b"src data");
    assert_eq!(
        fs.pread(&h, 0, 11).await.unwrap(),
        Bytes::from_static(b"victim data"),
        "the replaced file must remain readable through its handle"
    );
    fs.close(&h).await.unwrap();
}

// ---- snapshots -------------------------------------------------------------

/// Every root record is a snapshot, because copy-on-write never overwrites the
/// blocks an older root names.
#[tokio::test]
async fn a_snapshot_shows_the_state_at_its_sequence() {
    let fs = fs().await;
    write_file(&fs, "/f", b"version one").await;
    let first = fs.store().root().await.unwrap().seq;

    let h = fs.open("/f", OpenFlags::read_write()).await.unwrap();
    fs.pwrite(&h, 0, b"version two").await.unwrap();
    fs.close(&h).await.unwrap();

    assert_eq!(read_file(&fs, "/f").await, b"version two");

    let snap = fs.open_snapshot(first).await.unwrap();
    let ino = snap.lookup(&snap.root(), "f").await.unwrap();
    assert_eq!(
        snap.read(&ino, 0, 11).await.unwrap(),
        Bytes::from_static(b"version one")
    );
    assert_eq!(snap.info().seq, first);
}

#[tokio::test]
async fn a_snapshot_still_holds_a_since_deleted_file() {
    let fs = fs().await;
    let root = fs.root();
    write_file(&fs, "/gone", b"recoverable").await;
    let before_delete = fs.store().root().await.unwrap().seq;
    fs.unlink(&root, "gone").await.unwrap();

    assert!(matches!(
        fs.lookup_at(&root, "gone").await,
        Err(FsError::NotFound)
    ));

    let snap = fs.open_snapshot(before_delete).await.unwrap();
    let ino = snap.lookup(&snap.root(), "gone").await.unwrap();
    assert_eq!(
        snap.read(&ino, 0, 11).await.unwrap(),
        Bytes::from_static(b"recoverable")
    );
}

#[tokio::test]
async fn snapshots_list_newest_first_with_distinct_merkle_roots() {
    let fs = fs().await;
    for i in 0..4u32 {
        write_file(&fs, &format!("/f{i}"), b"x").await;
    }

    let snaps = fs.snapshots(3).await.unwrap();
    assert_eq!(snaps.len(), 3);
    assert!(
        snaps.windows(2).all(|w| w[0].seq > w[1].seq),
        "newest first"
    );
    // Each commit changes the filesystem, so each root covers a different tree.
    let roots: std::collections::HashSet<_> = snaps.iter().map(|s| s.merkle_root).collect();
    assert_eq!(roots.len(), snaps.len());
}

#[tokio::test]
async fn snapshot_listing_stops_at_the_genesis_root() {
    let fs = fs().await;
    write_file(&fs, "/f", b"x").await;

    // Asking for more than exist yields what exists, ending at sequence 0.
    let snaps = fs.snapshots(1000).await.unwrap();
    assert_eq!(snaps.last().unwrap().seq, 0);
    assert!(fs.snapshots(0).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_snapshot_can_list_directories_and_stat() {
    let fs = fs().await;
    let root = fs.root();
    fs.mkdir(&root, "d").await.unwrap();
    write_file(&fs, "/d/a", b"12345").await;
    let seq = fs.store().root().await.unwrap().seq;
    fs.unlink(&fs.lookup_at(&root, "d").await.unwrap(), "a")
        .await
        .unwrap();

    let snap = fs.open_snapshot(seq).await.unwrap();
    let d = snap.lookup(&snap.root(), "d").await.unwrap();
    let entries: Vec<_> = snap
        .read_dir(&d)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(entries, vec!["a"]);

    let a = snap.lookup(&snap.root(), "d/a").await.unwrap();
    assert_eq!(snap.stat(&a).await.unwrap().size, 5);
}

/// Opening a snapshot must not disturb the live mount's rollback floor —
/// otherwise reading history would be a way to make the store rewind.
#[tokio::test]
async fn opening_a_snapshot_does_not_lower_the_rollback_floor() {
    let fs = fs().await;
    write_file(&fs, "/a", b"x").await;
    write_file(&fs, "/b", b"x").await;

    let floor = fs.store().roots().expected_seq();
    let _snap = fs.open_snapshot(0).await.unwrap();
    assert_eq!(fs.store().roots().expected_seq(), floor);

    // And the live mount is untouched.
    assert_eq!(read_file(&fs, "/b").await, b"x");
}
