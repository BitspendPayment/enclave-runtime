//! The linker a guest sees: all of `wasmtime-wasi`, plus the runtime's own
//! interfaces.
//!
//! `wasi:filesystem` is `wasmtime-wasi`'s, over the one directory a guest is
//! preopened — its tenant's dataset on the pool, see [`crate::zfs`]. There used
//! to be a filesystem of our own here, and with it a hand-copied list of every
//! other WASI interface that had to be diffed against upstream on each bump.
//! Both are gone: the upstream entry point registers the whole set.

use wasmtime::component::Linker;
use wasmtime::Result;

use crate::state::State;

/// The full linker a guest sees.
pub fn build_linker(engine: &wasmtime::Engine) -> Result<Linker<State>> {
    let mut linker: Linker<State> = Linker::new(engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    crate::tasks::add_to_linker(&mut linker)?;
    crate::stream::add_to_linker(&mut linker)?;
    crate::notify::add_to_linker(&mut linker)?;
    Ok(linker)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not a completeness check — nothing can be, from here. It only catches
    /// the coarse failure where two interfaces collide.
    #[test]
    fn the_linker_builds_without_duplicate_registrations() {
        let engine = wasmtime::Engine::default();
        build_linker(&engine).expect("linker must build");
    }
}
