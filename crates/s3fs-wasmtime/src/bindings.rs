//! `wasmtime::component::bindgen!` invocation against the vendored WASI 0.2.3
//! WIT. Generates the host traits we then implement in `host_*.rs`.
//!
//! `with:` reuses `wasmtime-wasi`'s pre-generated bindings for `wasi:io` and
//! `wasi:clocks` so streams interoperate with the rest of the runtime, then
//! plugs our own resource types in for `wasi:filesystem/types/descriptor`
//! and `wasi:filesystem/types/directory-entry-stream`.

wasmtime::component::bindgen!({
    path: "../../wit",
    world: "s3fs-host",
    async: true,
    trappable_imports: true,
    trappable_error_type: {
        "wasi:filesystem/types/error-code" => crate::error_map::S3WasiFsError,
    },
    with: {
        "wasi:io":     wasmtime_wasi::bindings::io,
        "wasi:clocks": wasmtime_wasi::bindings::clocks,
        "wasi:filesystem/types/descriptor":             crate::descriptors::Descriptor,
        "wasi:filesystem/types/directory-entry-stream": crate::descriptors::DirectoryEntryStream,
    },
});
