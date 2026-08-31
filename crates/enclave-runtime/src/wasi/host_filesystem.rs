//! `wasi:filesystem/types::Host` and the per-resource trait implementations.
//!
//! For v1 we implement everything the Compatibility Matrix marks as ✅ or ⚠️
//! using the synchronous `descriptor.read` / `descriptor.write` paths.
//! Stream-based ops (`read-via-stream`, `write-via-stream`,
//! `append-via-stream`) currently return `error-code::unsupported`; wiring
//! them through `wasmtime-wasi`'s stream machinery is reserved for a follow-
//! up.

use s3fs_core::{Attrs, Inode, InodeKind, OpenFlags};
use wasmtime::component::Resource;
use wasmtime::Result;
use wasmtime_wasi::p2::bindings::io::streams::{InputStream, OutputStream};

use crate::wasi::bindings::wasi::filesystem::types::{
    self as wit, Descriptor as WitDescriptor, DescriptorFlags, DescriptorStat, DescriptorType,
    DirectoryEntry, DirectoryEntryStream as WitDirectoryEntryStream, ErrorCode, Filesize,
    HostDescriptor, HostDirectoryEntryStream, MetadataHashValue, NewTimestamp,
    OpenFlags as WitOpenFlags, PathFlags,
};
use crate::wasi::descriptors::{Descriptor, DirectoryEntryStream};
use crate::wasi::error_map::{from_fs, IntoS3WasiResult, S3WasiFsError, S3WasiFsResult};
use crate::wasi::view::S3FsCtxView;

// ---------------------------------------------------------------------------
// types::Host
// ---------------------------------------------------------------------------

impl wit::Host for S3FsCtxView<'_> {
    fn convert_error_code(&mut self, err: S3WasiFsError) -> Result<ErrorCode> {
        err.downcast()
    }

    async fn filesystem_error_code(
        &mut self,
        _err: Resource<wasmtime_wasi::p2::bindings::io::error::Error>,
    ) -> Result<Option<ErrorCode>> {
        // Streams are not yet wired up; nothing to inspect.
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn get_descriptor_owned(
    table: &mut wasmtime::component::ResourceTable,
    fd: &Resource<WitDescriptor>,
) -> Result<Descriptor> {
    // Clone via match — both variants are cheap (Arc clones).
    let d = table.get(fd).map_err(wasmtime::Error::from)?;
    Ok(match d {
        Descriptor::File { handle, parent } => Descriptor::File {
            handle: handle.clone(),
            parent: parent.clone(),
        },
        Descriptor::Dir { inode } => Descriptor::Dir {
            inode: inode.clone(),
        },
    })
}

fn descriptor_type_for(kind: InodeKind) -> DescriptorType {
    match kind {
        InodeKind::RegularFile => DescriptorType::RegularFile,
        InodeKind::Directory => DescriptorType::Directory,
        InodeKind::Symlink => DescriptorType::SymbolicLink,
    }
}

/// Every field here is now read straight from the dnode. The link count used
/// to be hardcoded to 1 and the three timestamps were all the same value,
/// because the previous engine had nowhere to keep them.
fn stat_from_attrs(attrs: &Attrs) -> DescriptorStat {
    DescriptorStat {
        type_: descriptor_type_for(attrs.kind),
        link_count: u64::from(attrs.nlink),
        size: attrs.size,
        data_access_timestamp: Some(systemtime_to_wit(attrs.atime)),
        data_modification_timestamp: Some(systemtime_to_wit(attrs.mtime)),
        status_change_timestamp: Some(systemtime_to_wit(attrs.ctime)),
    }
}

fn systemtime_to_wit(
    t: std::time::SystemTime,
) -> wasmtime_wasi::p2::bindings::clocks::wall_clock::Datetime {
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    wasmtime_wasi::p2::bindings::clocks::wall_clock::Datetime {
        seconds: d.as_secs(),
        nanoseconds: d.subsec_nanos(),
    }
}

/// Convert a WIT `new-timestamp` to `Option<SystemTime>` per WASI semantics:
/// - `NoChange` → `None` (don't update this field)
/// - `Now` → `Some(now)`
/// - `Timestamp(dt)` → `Some(epoch + dt.seconds + dt.nanoseconds)`
fn wit_timestamp_to_systemtime(
    ts: NewTimestamp,
    clock: &crate::clock::WallClockAdapter,
) -> Option<std::time::SystemTime> {
    use wasmtime_wasi::HostWallClock;
    match ts {
        NewTimestamp::NoChange => None,
        // The runtime's clock, not the host's: a guest that reads
        // `wall-clock` and then calls `set-times` with "now" must not see two
        // different answers.
        NewTimestamp::Now => Some(std::time::UNIX_EPOCH + clock.now()),
        NewTimestamp::Timestamp(dt) => {
            Some(std::time::UNIX_EPOCH + std::time::Duration::new(dt.seconds, dt.nanoseconds))
        }
    }
}

fn open_flags_from_wit(flags: WitOpenFlags) -> OpenFlags {
    OpenFlags {
        // read/write come from descriptor-flags, not open-flags, in P2.
        read: false,
        write: false,
        append: false,
        truncate: flags.contains(WitOpenFlags::TRUNCATE),
        create: flags.contains(WitOpenFlags::CREATE),
        exclusive: flags.contains(WitOpenFlags::EXCLUSIVE),
    }
}

/// Split a relative path into `(parent_path, basename)` for `*-at` ops.
fn split_at_path(p: &str) -> (&str, &str) {
    match p.rfind('/') {
        Some(i) => (&p[..i], &p[i + 1..]),
        None => ("", p),
    }
}

async fn resolve_parent(
    fs: &s3fs_core::Fs,
    scope: &std::sync::Arc<s3fs_core::Inode>,
    base: &std::sync::Arc<s3fs_core::Inode>,
    parent_path: &str,
) -> S3WasiFsResult<std::sync::Arc<s3fs_core::Inode>> {
    if parent_path.is_empty() {
        Ok(base.clone())
    } else {
        fs.lookup_within(scope, base, parent_path)
            .await
            .map_err(|e| S3WasiFsError::from(from_fs(e)))
    }
}

// ---------------------------------------------------------------------------
// HostDescriptor — every method in the WIT
// ---------------------------------------------------------------------------

impl HostDescriptor for S3FsCtxView<'_> {
    async fn read_via_stream(
        &mut self,
        fd: Resource<WitDescriptor>,
        offset: Filesize,
    ) -> Result<Resource<InputStream>, S3WasiFsError> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let handle = match d {
            Descriptor::File { handle, .. } => handle,
            Descriptor::Dir { .. } => return Err(S3WasiFsError::from(ErrorCode::IsDirectory)),
        };
        let s: wasmtime_wasi::p2::DynInputStream = Box::new(
            crate::wasi::streams::S3InputStream::read_at(self.fs.clone(), handle, offset),
        );
        let res = self
            .table
            .push(s)
            .map_err(|e| S3WasiFsError::trap(wasmtime::Error::from(e)))?;
        Ok(res)
    }

    async fn write_via_stream(
        &mut self,
        fd: Resource<WitDescriptor>,
        offset: Filesize,
    ) -> Result<Resource<OutputStream>, S3WasiFsError> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let handle = match d {
            Descriptor::File { handle, .. } => handle,
            Descriptor::Dir { .. } => return Err(S3WasiFsError::from(ErrorCode::IsDirectory)),
        };
        let s: wasmtime_wasi::p2::DynOutputStream = Box::new(
            crate::wasi::streams::S3OutputStream::write_at(self.fs.clone(), handle, offset),
        );
        let res = self
            .table
            .push(s)
            .map_err(|e| S3WasiFsError::trap(wasmtime::Error::from(e)))?;
        Ok(res)
    }

    async fn append_via_stream(
        &mut self,
        fd: Resource<WitDescriptor>,
    ) -> Result<Resource<OutputStream>, S3WasiFsError> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let handle = match d {
            Descriptor::File { handle, .. } => handle,
            Descriptor::Dir { .. } => return Err(S3WasiFsError::from(ErrorCode::IsDirectory)),
        };
        let offset = handle.size().await;
        let s: wasmtime_wasi::p2::DynOutputStream = Box::new(
            crate::wasi::streams::S3OutputStream::write_at(self.fs.clone(), handle, offset),
        );
        let res = self
            .table
            .push(s)
            .map_err(|e| S3WasiFsError::trap(wasmtime::Error::from(e)))?;
        Ok(res)
    }

    async fn advise(
        &mut self,
        _fd: Resource<WitDescriptor>,
        _offset: Filesize,
        _length: Filesize,
        _advice: wit::Advice,
    ) -> S3WasiFsResult<()> {
        Ok(())
    }

    async fn sync_data(&mut self, fd: Resource<WitDescriptor>) -> S3WasiFsResult<()> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        match d {
            Descriptor::File { handle, .. } => self.fs.sync(&handle).await.into_wasi(),
            Descriptor::Dir { .. } => Err(S3WasiFsError::from(ErrorCode::IsDirectory)),
        }
    }

    async fn get_flags(&mut self, _fd: Resource<WitDescriptor>) -> S3WasiFsResult<DescriptorFlags> {
        Ok(DescriptorFlags::READ | DescriptorFlags::WRITE | DescriptorFlags::DATA_INTEGRITY_SYNC)
    }

    async fn get_type(&mut self, fd: Resource<WitDescriptor>) -> S3WasiFsResult<DescriptorType> {
        let inode = self
            .table
            .get(&fd)
            .map_err(|e| S3WasiFsError::trap(wasmtime::Error::from(e)))?
            .inode()
            .clone();
        let attrs = self.fs.stat(&inode).await.map_err(from_fs)?;
        Ok(descriptor_type_for(attrs.kind))
    }

    async fn set_size(
        &mut self,
        fd: Resource<WitDescriptor>,
        size: Filesize,
    ) -> S3WasiFsResult<()> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let handle = match d {
            Descriptor::File { handle, .. } => handle,
            Descriptor::Dir { .. } => return Err(S3WasiFsError::from(ErrorCode::IsDirectory)),
        };
        self.fs.set_size(&handle, size).await.into_wasi()
    }

    async fn set_times(
        &mut self,
        fd: Resource<WitDescriptor>,
        data_access_timestamp: NewTimestamp,
        data_modification_timestamp: NewTimestamp,
    ) -> S3WasiFsResult<()> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let handle = match d {
            Descriptor::File { handle, .. } => handle,
            Descriptor::Dir { .. } => return Err(S3WasiFsError::from(ErrorCode::IsDirectory)),
        };
        let atime = wit_timestamp_to_systemtime(data_access_timestamp, self.clock);
        let mtime = wit_timestamp_to_systemtime(data_modification_timestamp, self.clock);
        self.fs.set_times(&handle, atime, mtime).await.into_wasi()
    }

    async fn read(
        &mut self,
        fd: Resource<WitDescriptor>,
        length: Filesize,
        offset: Filesize,
    ) -> S3WasiFsResult<(Vec<u8>, bool)> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let handle = match d {
            Descriptor::File { handle, .. } => handle,
            Descriptor::Dir { .. } => return Err(S3WasiFsError::from(ErrorCode::IsDirectory)),
        };
        let bytes = self
            .fs
            .pread(&handle, offset, length as usize)
            .await
            .map_err(|e| S3WasiFsError::from(from_fs(e)))?;
        let eof = bytes.is_empty() || (bytes.len() as u64) < length;
        Ok((bytes.to_vec(), eof))
    }

    async fn write(
        &mut self,
        fd: Resource<WitDescriptor>,
        buffer: Vec<u8>,
        offset: Filesize,
    ) -> S3WasiFsResult<Filesize> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let handle = match d {
            Descriptor::File { handle, .. } => handle,
            Descriptor::Dir { .. } => return Err(S3WasiFsError::from(ErrorCode::IsDirectory)),
        };
        let n = self
            .fs
            .pwrite(&handle, offset, &buffer)
            .await
            .map_err(|e| S3WasiFsError::from(from_fs(e)))?;
        Ok(n as u64)
    }

    async fn read_directory(
        &mut self,
        fd: Resource<WitDescriptor>,
    ) -> S3WasiFsResult<Resource<WitDirectoryEntryStream>> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let dir = match d {
            Descriptor::Dir { inode } => inode,
            Descriptor::File { .. } => return Err(S3WasiFsError::from(ErrorCode::NotDirectory)),
        };
        let entries = self
            .fs
            .read_dir(&dir)
            .await
            .map_err(|e| S3WasiFsError::from(from_fs(e)))?;
        let res = self
            .table
            .push(DirectoryEntryStream::new(entries))
            .map_err(|e| S3WasiFsError::trap(wasmtime::Error::from(e)))?;
        Ok(res)
    }

    async fn sync(&mut self, fd: Resource<WitDescriptor>) -> S3WasiFsResult<()> {
        self.sync_data(fd).await
    }

    async fn create_directory_at(
        &mut self,
        fd: Resource<WitDescriptor>,
        path: String,
    ) -> S3WasiFsResult<()> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let base = d.at_base();
        let (parent_path, name) = split_at_path(&path);
        let parent = resolve_parent(self.fs, self.scope, &base, parent_path).await?;
        self.fs.mkdir(&parent, name).await.map(|_| ()).into_wasi()
    }

    async fn stat(&mut self, fd: Resource<WitDescriptor>) -> S3WasiFsResult<DescriptorStat> {
        let inode = self
            .table
            .get(&fd)
            .map_err(|e| S3WasiFsError::trap(wasmtime::Error::from(e)))?
            .inode()
            .clone();
        let attrs = self.fs.stat(&inode).await.map_err(from_fs)?;
        Ok(stat_from_attrs(&attrs))
    }

    async fn stat_at(
        &mut self,
        fd: Resource<WitDescriptor>,
        path_flags: PathFlags,
        path: String,
    ) -> S3WasiFsResult<DescriptorStat> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let base = d.at_base();
        let follow = path_flags.contains(PathFlags::SYMLINK_FOLLOW);
        let attrs = self
            .fs
            .stat_at(&base, &path, follow)
            .await
            .map_err(from_fs)?;
        Ok(stat_from_attrs(&attrs))
    }

    async fn set_times_at(
        &mut self,
        fd: Resource<WitDescriptor>,
        path_flags: PathFlags,
        path: String,
        data_access_timestamp: NewTimestamp,
        data_modification_timestamp: NewTimestamp,
    ) -> S3WasiFsResult<()> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let base = d.at_base();
        let follow = path_flags.contains(PathFlags::SYMLINK_FOLLOW);
        let atime = wit_timestamp_to_systemtime(data_access_timestamp, self.clock);
        let mtime = wit_timestamp_to_systemtime(data_modification_timestamp, self.clock);
        self.fs
            .set_times_at(&base, &path, atime, mtime, follow)
            .await
            .into_wasi()
    }

    async fn link_at(
        &mut self,
        fd: Resource<WitDescriptor>,
        old_path_flags: PathFlags,
        old_path: String,
        new_descriptor: Resource<WitDescriptor>,
        new_path: String,
    ) -> S3WasiFsResult<()> {
        let old_d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let new_d =
            get_descriptor_owned(self.table, &new_descriptor).map_err(S3WasiFsError::trap)?;
        let old_base = old_d.at_base();
        let new_base = new_d.at_base();
        let (parent_path, name) = split_at_path(&new_path);
        let new_parent = resolve_parent(self.fs, self.scope, &new_base, parent_path).await?;

        self.fs
            .link_within(
                self.scope,
                &old_base,
                &old_path,
                &new_parent,
                name,
                old_path_flags.contains(PathFlags::SYMLINK_FOLLOW),
            )
            .await
            .into_wasi()
    }

    async fn open_at(
        &mut self,
        fd: Resource<WitDescriptor>,
        path_flags: PathFlags,
        path: String,
        open_flags: WitOpenFlags,
        descriptor_flags: DescriptorFlags,
    ) -> S3WasiFsResult<Resource<WitDescriptor>> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let base = d.at_base();

        let mut flags = open_flags_from_wit(open_flags);
        flags.read = descriptor_flags.contains(DescriptorFlags::READ);
        flags.write = descriptor_flags.contains(DescriptorFlags::WRITE);

        let want_dir = open_flags.contains(WitOpenFlags::DIRECTORY);

        // O_NOFOLLOW (path-flags::symlink-follow cleared): if the leaf is a
        // symlink, return Loop per WASI spec rather than following.
        if !path_flags.contains(PathFlags::SYMLINK_FOLLOW) {
            // Probe the leaf without following. NotFound is fine — open_at
            // may be creating. Actual symlink → Loop.
            if let Ok(probe) = self
                .fs
                .lookup_within_no_follow(self.scope, &base, &path)
                .await
            {
                if matches!(
                    self.fs.stat(&probe).await.map(|a| a.kind),
                    Ok(InodeKind::Symlink)
                ) {
                    return Err(S3WasiFsError::from(ErrorCode::Loop));
                }
            }
        }

        let handle = self
            .fs
            .open_within(self.scope, &base, &path, flags)
            .await
            .map_err(|e| S3WasiFsError::from(from_fs(e)))?;

        let is_dir = matches!(
            self.fs.stat(&handle.inode).await.map_err(from_fs)?.kind,
            InodeKind::Directory
        );
        let descriptor = if is_dir {
            // Don't keep a file handle for a directory.
            self.fs
                .close(&handle)
                .await
                .map_err(|e| S3WasiFsError::from(from_fs(e)))?;
            Descriptor::Dir {
                inode: handle.inode.clone(),
            }
        } else {
            if want_dir {
                self.fs
                    .close(&handle)
                    .await
                    .map_err(|e| S3WasiFsError::from(from_fs(e)))?;
                return Err(S3WasiFsError::from(ErrorCode::NotDirectory));
            }
            Descriptor::File {
                parent: self
                    .fs
                    .parent_within(self.scope, &handle.inode)
                    .await
                    .map_err(from_fs)?,
                handle,
            }
        };

        let res = self
            .table
            .push(descriptor)
            .map_err(|e| S3WasiFsError::trap(wasmtime::Error::from(e)))?;
        Ok(res)
    }

    async fn readlink_at(
        &mut self,
        fd: Resource<WitDescriptor>,
        path: String,
    ) -> S3WasiFsResult<String> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let base = d.at_base();
        let (parent_path, name) = split_at_path(&path);
        let parent = resolve_parent(self.fs, self.scope, &base, parent_path).await?;
        self.fs.readlink_at(&parent, name).await.into_wasi()
    }

    async fn remove_directory_at(
        &mut self,
        fd: Resource<WitDescriptor>,
        path: String,
    ) -> S3WasiFsResult<()> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let base = d.at_base();
        let (parent_path, name) = split_at_path(&path);
        let parent = resolve_parent(self.fs, self.scope, &base, parent_path).await?;
        self.fs.rmdir(&parent, name).await.into_wasi()
    }

    async fn rename_at(
        &mut self,
        fd: Resource<WitDescriptor>,
        old_path: String,
        new_descriptor: Resource<WitDescriptor>,
        new_path: String,
    ) -> S3WasiFsResult<()> {
        let old_d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let new_d =
            get_descriptor_owned(self.table, &new_descriptor).map_err(S3WasiFsError::trap)?;
        let old_base = old_d.at_base();
        let new_base = new_d.at_base();
        let (op, oname) = split_at_path(&old_path);
        let (np, nname) = split_at_path(&new_path);
        let old_parent = resolve_parent(self.fs, self.scope, &old_base, op).await?;
        let new_parent = resolve_parent(self.fs, self.scope, &new_base, np).await?;
        self.fs
            .rename(&old_parent, oname, &new_parent, nname)
            .await
            .into_wasi()
    }

    async fn symlink_at(
        &mut self,
        fd: Resource<WitDescriptor>,
        old_path: String,
        new_path: String,
    ) -> S3WasiFsResult<()> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let base = d.at_base();
        let (parent_path, name) = split_at_path(&new_path);
        let parent = resolve_parent(self.fs, self.scope, &base, parent_path).await?;
        self.fs
            .symlink_at(&parent, name, &old_path)
            .await
            .map(|_| ())
            .into_wasi()
    }

    async fn unlink_file_at(
        &mut self,
        fd: Resource<WitDescriptor>,
        path: String,
    ) -> S3WasiFsResult<()> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let base = d.at_base();
        let (parent_path, name) = split_at_path(&path);
        let parent = resolve_parent(self.fs, self.scope, &base, parent_path).await?;
        self.fs.unlink(&parent, name).await.into_wasi()
    }

    async fn is_same_object(
        &mut self,
        a: Resource<WitDescriptor>,
        b: Resource<WitDescriptor>,
    ) -> Result<bool> {
        // Object ids are never reused and the generation distinguishes a
        // reused slot, so this is exact rather than a hash of an ETag.
        let da = **self.table.get(&a)?.inode();
        let db = **self.table.get(&b)?.inode();
        Ok(da == db)
    }

    async fn metadata_hash(
        &mut self,
        fd: Resource<WitDescriptor>,
    ) -> S3WasiFsResult<MetadataHashValue> {
        let inode = self
            .table
            .get(&fd)
            .map_err(|e| S3WasiFsError::trap(wasmtime::Error::from(e)))?
            .inode()
            .clone();
        Ok(metadata_hash_for(&inode))
    }

    async fn metadata_hash_at(
        &mut self,
        fd: Resource<WitDescriptor>,
        _path_flags: PathFlags,
        path: String,
    ) -> S3WasiFsResult<MetadataHashValue> {
        let d = get_descriptor_owned(self.table, &fd).map_err(S3WasiFsError::trap)?;
        let base = d.at_base();
        let follow = _path_flags.contains(PathFlags::SYMLINK_FOLLOW);
        let target = self
            .fs
            .resolve_for_hash(&base, &path, follow)
            .await
            .map_err(from_fs)?;
        Ok(metadata_hash_for(&target))
    }

    async fn drop(&mut self, fd: Resource<WitDescriptor>) -> Result<()> {
        let d = self.table.delete(fd)?;
        if let Descriptor::File { handle, .. } = d {
            // Best-effort close, which flushes a writable handle.
            let _ = self.fs.close(&handle).await;
        }
        Ok(())
    }
}

/// Identity, not content: the object id and its generation. WASI only
/// requires that the value differ when the objects differ, and this pair is
/// exactly that — stable across mounts, and never recycled.
fn metadata_hash_for(inode: &Inode) -> MetadataHashValue {
    MetadataHashValue {
        lower: inode.objid(),
        upper: inode.gen,
    }
}

// ---------------------------------------------------------------------------
// HostDirectoryEntryStream
// ---------------------------------------------------------------------------

impl HostDirectoryEntryStream for S3FsCtxView<'_> {
    async fn read_directory_entry(
        &mut self,
        stream: Resource<WitDirectoryEntryStream>,
    ) -> S3WasiFsResult<Option<DirectoryEntry>> {
        let s = self
            .table
            .get_mut(&stream)
            .map_err(|e| S3WasiFsError::trap(wasmtime::Error::from(e)))?;
        if s.cursor >= s.entries.len() {
            return Ok(None);
        }
        let entry = &s.entries[s.cursor];
        let dir_entry = DirectoryEntry {
            type_: descriptor_type_for(entry.kind),
            name: entry.name.clone(),
        };
        s.cursor += 1;
        Ok(Some(dir_entry))
    }

    async fn drop(&mut self, stream: Resource<WitDirectoryEntryStream>) -> Result<()> {
        let _ = self.table.delete(stream)?;
        Ok(())
    }
}
