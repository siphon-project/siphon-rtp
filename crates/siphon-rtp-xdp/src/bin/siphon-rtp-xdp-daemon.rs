//! `siphon-rtp-xdp-daemon` — the siphon-rtp media engine daemon over the **XDP/AF_XDP kernel
//! datapath**.
//!
//! This binary lives in the excluded `crates/siphon-rtp-xdp` workspace — the *only* place the
//! eBPF/aya toolchain is pulled in — and depends **up into** the stable engine
//! (`siphon-rtp-engine`), never the other way round. It reuses the engine's entire CLI/TOML surface
//! ([`EngineArgs`] + `FileConfig`) and adds just the two `--xdp-*` knobs, then:
//!
//! 1. decides purely from config whether XDP is even a candidate ([`choose_datapath`]);
//! 2. probes the host's XDP capability and tries native then generic-SKB attach
//!    ([`try_build_xdp_datapath`]);
//! 3. on **any** failure logs and falls back to the always-available `UdpLoopbackDatapath` — never a
//!    hard failure (the rtpengine posture: use the kernel fast path when the box supports it, degrade
//!    cleanly otherwise, docs/security-and-nat.md §11.1);
//! 4. hands whichever backend it built to `siphon_rtp_engine::run_with_datapath`, the same generic
//!    runner the default UDP `siphon-rtp` binary uses — so control, TURN, dispatch, sweep, metrics,
//!    and NG behave identically over either datapath.

use std::net::{IpAddr, Ipv4Addr};

use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches, Parser};
use siphon_rtp_engine::config::{resolve_defaulted, resolve_optional, FileConfig};
use siphon_rtp_engine::daemon::{
    build_udp_datapath, init_tracing, resolve_port_range, run_with_datapath,
};
use siphon_rtp_engine::{EngineArgs, RunConfig};

// Allocator parity with the default `siphon-rtp-engine` binary: this daemon drives the same
// memory-leak-gated runner, so it links jemalloc — the allocator the leak gate measures
// `stats.allocated` on. The one accepted `-sys` dep; pure Rust over the already-linked jemalloc.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// siphon-rtp media engine daemon over the XDP/AF_XDP kernel datapath.
#[derive(Parser, Debug)]
#[command(name = "siphon-rtp-xdp-daemon", version, about)]
struct Cli {
    /// Every knob the default UDP `siphon-rtp` binary accepts, shared verbatim.
    #[command(flatten)]
    engine: EngineArgs,

    /// Attach the XDP/AF_XDP kernel datapath to this NIC (e.g. `eth0`) — the kernel media fast path.
    /// Requires a routable IPv4 `--relay-bind-ip` (the XDP path is IPv4-only and keys flows on the
    /// engine's relay address). Unset, or any probe/attach failure, falls back cleanly to the
    /// always-available UDP-loopback datapath — the daemon never hard-fails on the XDP path
    /// (docs/security-and-nat.md §11.1).
    #[arg(long, value_name = "NAME")]
    xdp_interface: Option<String>,

    /// NIC queue the XDP/AF_XDP socket binds (RX/TX). Only used when `--xdp-interface` selects the XDP
    /// datapath; the first cut drives a single media queue (0).
    #[arg(long, default_value_t = DEFAULT_XDP_QUEUE)]
    xdp_queue: u32,
}

/// Built-in default NIC queue for `--xdp-queue`: a single media RX/TX queue (the first-cut XDP
/// posture; multi-queue spreading is a later step).
const DEFAULT_XDP_QUEUE: u32 = 0;

/// The datapath the daemon selects at startup, decided purely from config (no I/O). This is only the
/// *candidacy* decision — whether XDP is even worth probing; the actual attach can still fail and
/// fall back to UDP at runtime (see [`try_build_xdp_datapath`]). Pure and unit-tested so the policy
/// is checked without a NIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatapathChoice {
    /// Use the always-available UDP-loopback backend.
    Udp,
    /// XDP is a candidate — probe + attach it, falling back to UDP on any failure.
    TryXdp,
}

/// Decide the startup datapath from config alone. XDP is a candidate only when **both** hold:
/// - `--xdp-interface` names a non-empty NIC to attach to;
/// - `--relay-bind-ip` is a **routable IPv4** address ([`is_routable_relay_v4`]) — the XDP fast path
///   is IPv4-only and keys/advertises flows on the engine's relay address, which is meaningless on
///   loopback / a `0.0.0.0` wildcard / IPv6 (docs/security-and-nat.md §11.1: advertise a reachable
///   address, never the private/loopback one).
///
/// Anything else selects UDP-loopback. This does no I/O: a `TryXdp` result must still clear the
/// capability probe and the AF_XDP bind before it is actually used, else the daemon degrades to UDP.
fn choose_datapath(xdp_interface: Option<&str>, relay_bind_ip: Option<IpAddr>) -> DatapathChoice {
    match (xdp_interface, relay_bind_ip) {
        (Some(interface), Some(IpAddr::V4(ip)))
            if !interface.is_empty() && is_routable_relay_v4(ip) =>
        {
            DatapathChoice::TryXdp
        }
        _ => DatapathChoice::Udp,
    }
}

/// Whether `ip` is a usable relay address to advertise to real peers and key XDP flows on: a specific
/// unicast IPv4 — not loopback, unspecified (`0.0.0.0`), multicast, or broadcast. The XDP backend
/// needs exactly this: a concrete engine-local IPv4 as its `local_ip` (docs/security-and-nat.md
/// §11.1). Used only to gate XDP selection; the UDP-loopback fallback imposes no such constraint.
fn is_routable_relay_v4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
}

/// Probe for and construct the XDP/AF_XDP datapath, or return `None` to fall back to UDP-loopback.
/// Only reached after [`choose_datapath`] returns [`DatapathChoice::TryXdp`] (interface + routable
/// IPv4 relay). Never a hard failure: a missing interface, a non-IPv4 relay address, no host XDP
/// capability, or an attach/bind failure logs and returns `None` so the daemon degrades cleanly to
/// UDP-loopback (the rtpengine posture).
///
/// Attach preference: native/driver XDP first (lowest overhead), then generic SKB mode (any kernel
/// ≥ 5.10, incl. veth). `local_ip` is the routable IPv4 `--relay-bind-ip` — the address the XDP
/// backend advertises and keys flows on (docs/security-and-nat.md §11.1). This is startup-path code,
/// not a per-packet hot path, so no criterion bench is required.
fn try_build_xdp_datapath(
    interface: Option<&str>,
    relay_bind_ip: Option<IpAddr>,
    queue: u32,
) -> Option<siphon_rtp_xdp::XdpDatapath> {
    use siphon_rtp_xdp::{xsk, AttachMode, Loader, XdpDatapath};

    // `choose_datapath` already established these invariants; re-derive the concrete values, and
    // decline (logging) if the interface or relay address is somehow not usable so we never attach the
    // IPv4-only fast path without an engine-local relay IPv4 to key flows on.
    let interface = interface?;
    let local_ip = match relay_bind_ip {
        Some(IpAddr::V4(ip)) if is_routable_relay_v4(ip) => ip,
        _ => {
            tracing::warn!(
                target: "siphon_rtp::datapath",
                "XDP requested but --relay-bind-ip is not a routable IPv4 relay address; \
                 using UDP-loopback"
            );
            return None;
        }
    };

    // Capability probe: can this host load + attach XDP at all (load + SKB-attach to `lo`)? A clean
    // "not supported" signal, distinct from the per-interface attach failures handled below.
    if !siphon_rtp_xdp::xdp_supported() {
        tracing::warn!(
            target: "siphon_rtp::datapath",
            interface,
            "XDP not supported on this host (load/attach probe failed); using UDP-loopback"
        );
        return None;
    }

    // Try native/driver XDP first, then generic SKB mode. A failed attempt drops its loader (which
    // detaches the program), so the next mode starts clean; total failure falls back to UDP-loopback.
    for mode in [AttachMode::Native, AttachMode::Skb] {
        let loader = match Loader::load(interface, mode) {
            Ok(loader) => loader,
            Err(error) => {
                tracing::debug!(target: "siphon_rtp::datapath", interface, ?mode, %error, "XDP attach failed; trying next mode");
                continue;
            }
        };
        match XdpDatapath::new(
            loader,
            interface,
            queue,
            local_ip,
            xsk::XskConfig::default(),
        ) {
            Ok(datapath) => {
                tracing::info!(
                    target: "siphon_rtp::datapath",
                    interface,
                    queue,
                    local_ip = %local_ip,
                    ?mode,
                    "XDP/AF_XDP datapath selected (kernel fast path)"
                );
                return Some(datapath);
            }
            Err(error) => {
                tracing::debug!(target: "siphon_rtp::datapath", interface, ?mode, %error, "AF_XDP bind failed; trying next mode");
            }
        }
    }

    tracing::warn!(
        target: "siphon_rtp::datapath",
        interface,
        "XDP unavailable after native + SKB attempts; using UDP-loopback"
    );
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse via `ArgMatches` (not just the typed struct) so the precedence merge can tell an explicit
    // flag from a defaulted one (`ValueSource::CommandLine`). `--help`/`--version`/parse errors exit
    // exactly as `Cli::parse()` would.
    let matches = Cli::command().get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(error) => error.exit(),
    };
    let Cli {
        engine,
        xdp_interface: cli_xdp_interface,
        xdp_queue: cli_xdp_queue,
    } = cli;

    // Load the optional `--config` TOML file. A missing/malformed file is fatal: fail loudly before
    // the subscriber exists (no tracing yet) rather than starting with a half-applied config.
    let file = match &engine.config {
        Some(path) => match FileConfig::load(path) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("siphon-rtp-xdp-daemon: {error}");
                std::process::exit(1);
            }
        },
        None => FileConfig::default(),
    };

    // Resolve the two XDP knobs with the same precedence the engine applies (explicit CLI > file >
    // default), using the engine's shared resolvers, before `RunConfig::resolve` consumes `engine`.
    let explicit = |id: &str| matches.value_source(id) == Some(ValueSource::CommandLine);
    let xdp_interface = resolve_optional(cli_xdp_interface, file.xdp_interface.clone());
    let xdp_queue = resolve_defaulted(
        cli_xdp_queue,
        explicit("xdp_queue"),
        file.xdp_queue,
        DEFAULT_XDP_QUEUE,
    );

    // Merge CLI over file over default, once, up front. Everything below reads `config`.
    let config = RunConfig::resolve(engine, &matches, file);
    init_tracing(&config);

    // Optional deterministic media-port range (`--port-min`/`--port-max`). Both-or-neither and
    // min <= max; a half-set or inverted range is a fatal config error (fail loudly, before serving).
    let port_range = match resolve_port_range(config.port_min, config.port_max) {
        Ok(range) => range,
        Err(error) => {
            tracing::error!("{error}");
            std::process::exit(1);
        }
    };

    // Select the datapath: probe + attach the XDP fast path when a NIC + routable IPv4 relay address
    // are configured; on any probe/attach failure `try_build_xdp_datapath` logs and returns `None`, so
    // we fall through to the always-available UDP-loopback backend (docs/security-and-nat.md §11.1).
    match choose_datapath(xdp_interface.as_deref(), config.relay_bind_ip) {
        DatapathChoice::TryXdp => {
            if let Some(xdp) =
                try_build_xdp_datapath(xdp_interface.as_deref(), config.relay_bind_ip, xdp_queue)
            {
                return run_with_datapath(xdp, config).await;
            }
        }
        DatapathChoice::Udp => {}
    }
    let datapath = build_udp_datapath(&config, port_range);
    run_with_datapath(datapath, config).await
}

#[cfg(test)]
mod tests {
    use super::{choose_datapath, is_routable_relay_v4, DatapathChoice};
    use std::net::{IpAddr, Ipv4Addr};

    /// Build an IPv4 [`IpAddr`] from octets (test helper — keeps the selection cases terse).
    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn datapath_choice_without_interface_is_udp() {
        // No interface named → UDP.
        assert_eq!(
            choose_datapath(None, Some(v4(203, 0, 113, 7))),
            DatapathChoice::Udp
        );
        // An empty interface name counts as unset.
        assert_eq!(
            choose_datapath(Some(""), Some(v4(203, 0, 113, 7))),
            DatapathChoice::Udp
        );
    }

    #[test]
    fn datapath_choice_requires_a_routable_v4_relay_ip() {
        // No relay address at all: nothing for the IPv4-only fast path to key/advertise on.
        assert_eq!(choose_datapath(Some("eth0"), None), DatapathChoice::Udp);
        // Loopback and the 0.0.0.0 wildcard are not routable relay addresses.
        assert_eq!(
            choose_datapath(Some("eth0"), Some(v4(127, 0, 0, 1))),
            DatapathChoice::Udp
        );
        assert_eq!(
            choose_datapath(Some("eth0"), Some(v4(0, 0, 0, 0))),
            DatapathChoice::Udp
        );
        // An IPv6 relay address: the XDP fast path is IPv4-only.
        assert_eq!(
            choose_datapath(
                Some("eth0"),
                Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
            ),
            DatapathChoice::Udp
        );
    }

    #[test]
    fn datapath_choice_full_config_tries_xdp() {
        // A named interface + a routable IPv4 relay address → probe XDP.
        assert_eq!(
            choose_datapath(Some("eth0"), Some(v4(203, 0, 113, 7))),
            DatapathChoice::TryXdp
        );
    }

    #[test]
    fn routable_relay_v4_accepts_unicast_rejects_special() {
        // Documentation-range unicast addresses are routable relay addresses.
        assert!(is_routable_relay_v4(Ipv4Addr::new(203, 0, 113, 7)));
        assert!(is_routable_relay_v4(Ipv4Addr::new(198, 51, 100, 1)));
        // Loopback / unspecified / broadcast / multicast are not.
        assert!(!is_routable_relay_v4(Ipv4Addr::LOCALHOST));
        assert!(!is_routable_relay_v4(Ipv4Addr::UNSPECIFIED));
        assert!(!is_routable_relay_v4(Ipv4Addr::BROADCAST));
        assert!(!is_routable_relay_v4(Ipv4Addr::new(224, 0, 0, 1)));
    }
}
