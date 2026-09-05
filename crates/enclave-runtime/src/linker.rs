//! WASI linker wiring: everything `wasmtime-wasi` provides *except*
//! `wasi:filesystem`, which [`crate::wasi`] takes over.
//!
//! ## This is a maintenance hazard, deliberately isolated
//!
//! [`add_wasi_minus_filesystem`] is a copy of
//! `wasmtime_wasi::p2::add_to_linker_with_options_async` with the two
//! `filesystem::*` lines removed. Upstream offers no "everything but one
//! interface" entry point, so there is no way to express this except by
//! restating the list.
//!
//! The failure mode is quiet: a `wasmtime-wasi` bump that adds an interface
//! leaves it missing here, and the only symptom is a guest that fails to
//! instantiate with an unresolved import — at run time, in whatever
//! environment happens to try it first. `wasmtime::component::Linker` exposes
//! no way to enumerate what has been registered, so no unit test can prove
//! this list is complete.
//!
//! What mitigates it is that `wasmtime-wasi` is pinned to an exact version, so
//! the list cannot change under us without someone editing a manifest. If you
//! bump it, diff this function against the upstream one.
//!
//! There used to be a second mitigation — CI ran a `wasi:cli/command` guest
//! that imported the full command world, so a missing interface failed that
//! job. It went with the command runner. The runtime serves `wasi:http/proxy`
//! and nothing else now, so the full `wasi:cli` surface is registered because
//! a proxy guest may still reach for parts of it, not because anything
//! requires all of it.

use wasmtime::component::{HasData, Linker, ResourceTable};
use wasmtime::Result;
use wasmtime_wasi::cli::{WasiCli, WasiCliView};
use wasmtime_wasi::clocks::{WasiClocks, WasiClocksView};
use wasmtime_wasi::random::{WasiRandom, WasiRandomView};
use wasmtime_wasi::sockets::{WasiSockets, WasiSocketsView};
use wasmtime_wasi::WasiView;

use crate::state::State;

/// Marker for `wasi:io` interfaces, which need `&mut ResourceTable`.
struct HasIo;
impl HasData for HasIo {
    type Data<'a> = &'a mut ResourceTable;
}

/// Add every `wasmtime-wasi` interface except `wasi:filesystem`.
pub fn add_wasi_minus_filesystem(linker: &mut Linker<State>) -> Result<()> {
    use wasmtime_wasi::p2::bindings::{cli, clocks, random, sockets};
    use wasmtime_wasi_io::bindings::wasi::io;
    let l = linker;
    let options = wasmtime_wasi::p2::bindings::LinkOptions::default();

    // wasi:io (async)
    io::error::add_to_linker::<State, HasIo>(l, |t| t.ctx().table)?;
    io::poll::add_to_linker::<State, HasIo>(l, |t| t.ctx().table)?;
    io::streams::add_to_linker::<State, HasIo>(l, |t| t.ctx().table)?;

    // sockets (async)
    sockets::tcp::add_to_linker::<State, WasiSockets>(l, State::sockets)?;
    sockets::udp::add_to_linker::<State, WasiSockets>(l, State::sockets)?;

    // clocks
    clocks::wall_clock::add_to_linker::<State, WasiClocks>(l, State::clocks)?;
    clocks::monotonic_clock::add_to_linker::<State, WasiClocks>(l, State::clocks)?;

    // random
    random::random::add_to_linker::<State, WasiRandom>(l, State::random)?;
    random::insecure::add_to_linker::<State, WasiRandom>(l, State::random)?;
    random::insecure_seed::add_to_linker::<State, WasiRandom>(l, State::random)?;

    // cli
    cli::exit::add_to_linker::<State, WasiCli>(l, &(&options).into(), State::cli)?;
    cli::environment::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::stdin::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::stdout::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::stderr::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::terminal_input::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::terminal_output::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::terminal_stdin::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::terminal_stdout::add_to_linker::<State, WasiCli>(l, State::cli)?;
    cli::terminal_stderr::add_to_linker::<State, WasiCli>(l, State::cli)?;

    // sockets (non-async)
    sockets::tcp_create_socket::add_to_linker::<State, WasiSockets>(l, State::sockets)?;
    sockets::udp_create_socket::add_to_linker::<State, WasiSockets>(l, State::sockets)?;
    sockets::instance_network::add_to_linker::<State, WasiSockets>(l, State::sockets)?;
    sockets::network::add_to_linker::<State, WasiSockets>(l, &(&options).into(), State::sockets)?;
    sockets::ip_name_lookup::add_to_linker::<State, WasiSockets>(l, State::sockets)?;

    Ok(())
}

/// The full linker a guest sees: WASI, plus `wasi:filesystem` backed by the
/// block store.
pub fn build_linker(engine: &wasmtime::Engine) -> Result<Linker<State>> {
    let mut linker: Linker<State> = Linker::new(engine);
    add_wasi_minus_filesystem(&mut linker)?;
    crate::wasi::add_filesystem_to_linker(&mut linker)?;
    Ok(linker)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not a completeness check — nothing can be, from here. It only catches
    /// the coarse failure where two interfaces collide or the filesystem
    /// override conflicts with a leftover `wasmtime-wasi` registration.
    #[test]
    fn the_linker_builds_without_duplicate_registrations() {
        let engine = wasmtime::Engine::default();
        build_linker(&engine).expect("linker must build");
    }
}
