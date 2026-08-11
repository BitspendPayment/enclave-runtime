//! Bringing up enclave networking over vsock.
//!
//! A Nitro enclave has no network interface. Its only channel to the outside
//! is `AF_VSOCK` to the parent instance, which means nothing that speaks TCP
//! — not the AWS SDK, not an ACME client, not a TLS listener — works until
//! something turns that channel into an interface.
//!
//! ```text
//!   parent instance (untrusted)          enclave (attested)
//!   ┌──────────────────────────┐         ┌────────────────────────┐
//!   │ gvproxy                  │ vsock   │ gvforwarder            │
//!   │  --listen vsock://:1024  │◀───────▶│  -url vsock://3:1024   │
//!   │  192.168.127.1 gw + DNS  │ CID 3   │  tap0 192.168.127.2    │
//!   └──────────────────────────┘  :1024  └────────────────────────┘
//! ```
//!
//! `gvproxy` is a user-mode network stack: it terminates the enclave's
//! ethernet frames on the parent and forwards them, giving the enclave a
//! gateway, DHCP and DNS at `192.168.127.1`. This is what nitriding and
//! ArkLabs both do, and the reason is worth stating: with a real interface,
//! ordinary networking code works unmodified. The alternative — a vsock
//! connector threaded through the AWS SDK and the ACME client — means two
//! bespoke transports to write and maintain, and neither library expects it.
//!
//! ## What this does and does not give away
//!
//! The parent sees ciphertext. Traffic to S3, KMS and an ACME provider is TLS
//! from inside the enclave, terminated at the far end, so gvproxy carries
//! bytes it cannot read. What the parent *does* learn is metadata — who the
//! enclave talks to, when, and how much — and it can of course refuse to carry
//! anything. Neither is new: it already controls whether the enclave runs.
//!
//! What would be new, and is not done here, is trusting the parent's DNS. A
//! parent that answers DNS can point the enclave at its own endpoint, which is
//! precisely why every outbound connection is TLS with certificate validation
//! and why the S3 data is encrypted under keys the parent never holds.

use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// The parent instance's context ID. Fixed by AWS.
pub const PARENT_CID: u32 = 3;
/// Port `gvproxy` listens on for the enclave's frames, matching its own default.
pub const GVPROXY_PORT: u32 = 1024;
/// The gateway gvproxy presents. Also its DNS server and HTTP API.
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 1);
/// The address gvproxy's DHCP hands the enclave.
pub const ENCLAVE_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 2);

/// Where the forwarder binary lives inside the enclave image.
pub const DEFAULT_GVFORWARDER: &str = "/usr/local/bin/gvforwarder";

/// How the enclave reaches the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Do nothing. Correct outside an enclave, where the host already has an
    /// interface, and for a guest that needs no outbound access.
    None,
    /// Run `gvforwarder` against the parent's `gvproxy`.
    Gvproxy,
}

impl NetworkMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" | "off" | "host" => Ok(NetworkMode::None),
            "gvproxy" | "tap" | "vsock" => Ok(NetworkMode::Gvproxy),
            other => Err(format!("expected one of none, gvproxy; got {other:?}")),
        }
    }
}

/// A running `gvforwarder`, killed when dropped.
///
/// Held rather than detached so that the forwarder dies with the runtime. A
/// surviving child would keep the tap device up around a runtime that had
/// exited, which on a restart looks like an interface that exists but carries
/// nothing.
#[derive(Debug)]
pub struct Network {
    child: Option<Child>,
}

impl Drop for Network {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Configuration for [`bring_up`].
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub mode: NetworkMode,
    pub gvforwarder: PathBuf,
    pub parent_cid: u32,
    pub port: u32,
    /// How long to wait for the gateway to answer before giving up.
    pub timeout: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            mode: NetworkMode::None,
            gvforwarder: PathBuf::from(DEFAULT_GVFORWARDER),
            parent_cid: PARENT_CID,
            port: GVPROXY_PORT,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Start the forwarder and wait until the network actually carries traffic.
///
/// Returns `None` for [`NetworkMode::None`], so callers need no branch.
pub fn bring_up(config: &NetworkConfig) -> Result<Option<Network>> {
    if config.mode == NetworkMode::None {
        return Ok(None);
    }

    // DNS first: gvforwarder brings the interface up and takes an address by
    // DHCP, but nothing writes resolv.conf, and a runtime that can route but
    // not resolve fails later with errors that name the wrong problem.
    write_resolv_conf().context("configuring DNS for the enclave")?;

    let url = format!("vsock://{}:{}/connect", config.parent_cid, config.port);
    tracing::info!(
        gvforwarder = %config.gvforwarder.display(),
        %url,
        "bringing up enclave networking"
    );

    let child = Command::new(&config.gvforwarder)
        .arg("-url")
        .arg(&url)
        // No `-debug`: it dumps a decode of every frame, which buries the DHCP
        // client's output — and the DHCP client is what usually fails.
        // Inherited, not discarded. If the forwarder cannot create its tap
        // device it says so and exits, and the only symptom visible from here
        // is the gateway never answering — a timeout thirty seconds later
        // that names the parent's gvproxy, which is usually running fine.
        // Inside an enclave the console is the only place a diagnosis can go.
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            format!(
                "starting {} — it ships inside the enclave image, so a failure here \
                 usually means the image was built without it",
                config.gvforwarder.display()
            )
        })?;

    let network = Network { child: Some(child) };

    wait_for_gateway(config.timeout).with_context(|| {
        format!(
            "the enclave network never came up. The parent instance must be running \
             `gvproxy --listen vsock://:{}`; without it the forwarder connects to nothing.",
            config.port
        )
    })?;

    tracing::info!(address = %ENCLAVE_ADDRESS, gateway = %GATEWAY, "enclave networking is up");
    Ok(Some(network))
}

/// gvproxy answers DNS on the gateway address.
fn write_resolv_conf() -> Result<()> {
    let contents = format!("nameserver {GATEWAY}\n");
    // An enclave image is whatever the ramdisk contains, and a minimal one may
    // have no /etc at all — the failure is then `No such file or directory`
    // against a path that looks like it must exist, several layers below
    // anything that mentions DNS.
    std::fs::create_dir_all("/etc").context("creating /etc")?;
    std::fs::write("/etc/resolv.conf", contents).context("writing /etc/resolv.conf")
}

/// Wait for the gateway to accept a connection.
///
/// Readiness is a successful TCP connection to gvproxy's own HTTP API, not a
/// sleep: DHCP takes an unpredictable moment, and a fixed delay is either too
/// short on a slow boot or wasted on a fast one. gvproxy serves its API on the
/// gateway address, so an accepted connection means frames are crossing the
/// vsock in both directions.
fn wait_for_gateway(timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let target = SocketAddrV4::new(GATEWAY, 80);
    let mut last: Option<std::io::Error> = None;

    while Instant::now() < deadline {
        match TcpStream::connect_timeout(&target.into(), Duration::from_millis(500)) {
            Ok(_) => return Ok(()),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    match last {
        Some(e) => Err(anyhow::Error::from(e))
            .with_context(|| format!("gateway {GATEWAY} did not answer within {timeout:?}")),
        None => anyhow::bail!("gateway {GATEWAY} did not answer within {timeout:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_parse_the_documented_values() {
        assert_eq!(NetworkMode::parse("none"), Ok(NetworkMode::None));
        assert_eq!(NetworkMode::parse("gvproxy"), Ok(NetworkMode::Gvproxy));
        assert_eq!(NetworkMode::parse("TAP"), Ok(NetworkMode::Gvproxy));
        assert!(NetworkMode::parse("bridge").is_err());
    }

    /// The default must do nothing: `s3fs-runner` and every test run outside
    /// an enclave, where spawning a forwarder would fail or, worse, succeed.
    #[test]
    fn the_default_touches_nothing() {
        assert_eq!(NetworkConfig::default().mode, NetworkMode::None);
        assert!(bring_up(&NetworkConfig::default()).unwrap().is_none());
    }

    /// The CID and port are fixed by AWS and by gvproxy respectively. Getting
    /// either wrong produces a forwarder that connects to nothing and a
    /// timeout thirty seconds later, so pin them.
    #[test]
    fn the_vsock_endpoint_is_the_one_gvproxy_listens_on() {
        let config = NetworkConfig::default();
        assert_eq!(config.parent_cid, 3, "the parent instance is always CID 3");
        assert_eq!(config.port, 1024, "gvproxy's default vsock port");
    }

    #[test]
    fn a_missing_forwarder_names_the_path_and_the_likely_cause() {
        let config = NetworkConfig {
            mode: NetworkMode::Gvproxy,
            gvforwarder: PathBuf::from("/enclave/definitely-absent-forwarder"),
            ..Default::default()
        };
        // Writing /etc/resolv.conf may fail first when not running as root;
        // either way the error must name something actionable.
        let err = bring_up(&config).unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("definitely-absent-forwarder") || text.contains("resolv.conf"),
            "unhelpful error: {text}"
        );
    }
}
