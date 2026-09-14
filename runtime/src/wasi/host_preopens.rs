//! `wasi:filesystem/preopens::Host` — exposes the single root descriptor.

use wasmtime::component::Resource;
use wasmtime::Result;

use crate::wasi::bindings::wasi::filesystem::preopens::Host;
use crate::wasi::bindings::wasi::filesystem::types::Descriptor as WitDescriptor;
use crate::wasi::descriptors::Descriptor;
use crate::wasi::view::S3FsCtxView;

impl Host for S3FsCtxView<'_> {
    async fn get_directories(&mut self) -> Result<Vec<(Resource<WitDescriptor>, String)>> {
        // The scope, not the filesystem root. This is the only descriptor a
        // guest is ever handed for free, so it is the only place a tenant's
        // view of `/` has to be established — everything else is derived from
        // it by resolution that cannot leave it.
        let root = self.scope.clone();
        let descriptor = self.table.push(Descriptor::Dir { inode: root })?;
        Ok(vec![(descriptor, self.fs.config.mount_path.clone())])
    }
}
