//! `wasmtime::component::bindgen!` invocation against the vendored WASI 0.2.6
//! WIT. Generates the host traits we then implement in `host_*.rs`.
//!
//! `with:` reuses `wasmtime-wasi`'s pre-generated bindings for `wasi:io` and
//! `wasi:clocks` so streams interoperate with the rest of the runtime, then
//! plugs our own resource types in for `wasi:filesystem/types/descriptor`
//! and `wasi:filesystem/types/directory-entry-stream`.

wasmtime::component::bindgen!({
    path: "../../wit",
    world: "s3fs-host",
    imports: { default: async | trappable },
    trappable_error_type: {
        "wasi:filesystem/types.error-code" => crate::wasi::error_map::S3WasiFsError,
    },
    with: {
        "wasi:io/poll":     wasmtime_wasi::p2::bindings::io::poll,
        "wasi:io/streams":  wasmtime_wasi::p2::bindings::io::streams,
        "wasi:io/error":    wasmtime_wasi::p2::bindings::io::error,
        "wasi:clocks/wall-clock": wasmtime_wasi::p2::bindings::clocks::wall_clock,
        "wasi:filesystem/types.descriptor":             crate::wasi::descriptors::Descriptor,
        "wasi:filesystem/types.directory-entry-stream": crate::wasi::descriptors::DirectoryEntryStream,
    },
});
