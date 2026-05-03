//! `wasi:filesystem/preopens::Host` — exposes the single root descriptor.

use wasmtime::Result;
use wasmtime::component::Resource;

use crate::bindings::wasi::filesystem::preopens::Host;
use crate::bindings::wasi::filesystem::types::Descriptor as WitDescriptor;
use crate::descriptors::Descriptor;
use crate::view::S3FsCtxView;

impl Host for S3FsCtxView<'_> {
    async fn get_directories(&mut self) -> Result<Vec<(Resource<WitDescriptor>, String)>> {
        let root = self.fs.root();
        let descriptor = self.table.push(Descriptor::Dir { inode: root })?;
        Ok(vec![(descriptor, self.fs.config.mount_path.clone())])
    }
}
