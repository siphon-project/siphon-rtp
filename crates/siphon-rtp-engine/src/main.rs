//! siphon-rtp-engine binary: start the control server (and the built-in TURN server) over the
//! capability-selected datapath.
//!
//! The always-available UDP-loopback backend is the default; the XDP/AF_XDP kernel fast path is
//! selected at startup when the `xdp` feature is compiled in AND `--xdp-interface` names a NIC AND a
//! routable IPv4 `--relay-bind-ip` is configured (the XDP fast path is IPv4-only and keys flows on
//! the engine's relay address). Selection is a capability probe with graceful fallback: on any
//! failure — no capability, attach/bind fails, not IPv4 — the daemon logs and uses UDP-loopback,
//! never a hard failure (the rtpengine posture: use the kernel fast path when the box supports it,
//! degrade cleanly otherwise). [`run_with_datapath`] is generic over the selected backend, so every
//! subsystem (control server, TURN, redirect dispatcher, sweeper, metrics, NG) runs identically over
//! either. The TURN server (`turn:`/`turns:`, a coturn replacement) shares that one datapath, so its
//! relay ports come from the same bounded pool and its allocations expire on the same logical clock.

mod config;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use clap::parser::ValueSource;
use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser};
use config::{resolve_defaulted, resolve_optional, FileConfig};
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::{Datapath, RxPacket};
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_engine::{cluster, metrics, server, shutdown, ClientId, Engine};
use siphon_rtp_hep::exporter::HepExporter;
use siphon_rtp_turn::{tls, NoFastPath, SystemUnixClock, Turn, TurnConfig};
use tokio::net::{TcpListener, UdpSocket};
use tracing_subscriber::EnvFilter;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// siphon-rtp media engine daemon.
#[derive(Parser, Debug)]
#[command(name = "siphon-rtp-engine", version, about)]
struct Args {
    /// Optional TOML config file (rtpengine-style declarative config). Any value the file sets
    /// overrides the built-in default; an explicit CLI flag still overrides the file. See
    /// `config.example.toml` for the schema. A missing or malformed file is a fatal startup error.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// JSON-over-TCP control listen address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    control: SocketAddr,

    /// rtpengine NG/bencode control listen address (UDP) — lets SIPhon / Kamailio / OpenSIPS drive
    /// the engine over the rtpengine protocol unchanged. Off unless given (rtpengine default :22222).
    #[arg(long)]
    ng: Option<SocketAddr>,

    /// TURN UDP listen address (`turn:`). TURN is enabled when `SIPHON_RTP_TURN_REALM` and
    /// `SIPHON_RTP_TURN_SECRET` are set; at least one `--turn-*` listener must then be given.
    #[arg(long)]
    turn_udp: Option<SocketAddr>,
    /// TURN TCP listen address (`turn:` over TCP, RFC 6062).
    #[arg(long)]
    turn_tcp: Option<SocketAddr>,
    /// TURN TLS listen address (`turns:`). Requires `--turn-tls-cert` and `--turn-tls-key`.
    #[arg(long)]
    turn_tls: Option<SocketAddr>,
    /// PEM certificate-chain file for the `turns:` listener.
    #[arg(long)]
    turn_tls_cert: Option<PathBuf>,
    /// PEM private-key file for the `turns:` listener.
    #[arg(long)]
    turn_tls_key: Option<PathBuf>,
    /// Public IP to advertise in XOR-RELAYED-ADDRESS when the relay socket's bound IP is not the
    /// reachable one (e.g. a NAT'd host). Defaults to the datapath-assigned address.
    #[arg(long)]
    turn_relay_ip: Option<IpAddr>,

    /// Bind relay/media sockets to this IP instead of loopback — the production posture so the relay
    /// is reachable by real peers (docs/security-and-nat.md §11.1). With a `0.0.0.0` bind or a NAT'd
    /// host, pair with `--turn-relay-ip` to advertise the reachable address.
    #[arg(long)]
    relay_bind_ip: Option<IpAddr>,

    /// Lowest media port the datapath may bind. Set together with `--port-max` to draw media ports
    /// from a bounded, firewallable range (rtpengine `port-min` parity) instead of OS-ephemeral
    /// ports — required for HA takeover (a standby re-binds the same port). Off unless both are set.
    #[arg(long)]
    port_min: Option<u16>,

    /// Highest media port the datapath may bind. Set together with `--port-min`.
    #[arg(long)]
    port_max: Option<u16>,

    /// Prometheus metrics + health HTTP listen address. Off unless given. Exposes `GET /metrics`
    /// (OpenMetrics text), `GET /healthz` (liveness), and `GET /readyz` (readiness).
    #[arg(long)]
    metrics_addr: Option<SocketAddr>,

    /// Per-connection control request cap (requests/second). 0 disables the limit. The default is
    /// generous for a legitimate SIPhon controller; floods beyond it are rejected, not processed.
    #[arg(long, default_value_t = server::DEFAULT_MAX_CONTROL_RPS)]
    max_control_rps: u64,

    /// Reap a call after this many seconds with no accepted media (dead-path detection,
    /// docs/security-and-nat.md §4 layer 6). Advanced on the same logical clock as the sweeper.
    #[arg(long, default_value_t = DEFAULT_MEDIA_TIMEOUT_SECS)]
    media_timeout_secs: u64,

    /// Bounded grace period (seconds) to drain live calls on SIGTERM/SIGINT before exiting. The
    /// daemon stops accepting new control connections immediately, then waits up to this long for
    /// the live session count to reach 0.
    #[arg(long, default_value_t = DEFAULT_SHUTDOWN_GRACE_SECS)]
    shutdown_grace_secs: u64,

    /// Stable cluster node identifier reported by the `load` / `node_info` control commands so a SIP
    /// dispatcher can tell engines apart. Defaults to the host's `HOSTNAME` (else `siphon-rtp`).
    #[arg(long)]
    node_id: Option<String>,

    /// Advertised maximum concurrent sessions for cluster load reporting (`0` = unlimited). Drives
    /// the normalized load score a dispatcher ranks nodes by; it does not itself cap admission (the
    /// per-client quota and the datapath port pool do that).
    #[arg(long, default_value_t = DEFAULT_MAX_SESSIONS)]
    max_sessions: u64,

    /// Attach the XDP/AF_XDP kernel datapath to this NIC (e.g. `eth0`) — the kernel media fast path.
    /// Requires a build with the `xdp` feature AND a routable IPv4 `--relay-bind-ip` (the XDP path is
    /// IPv4-only and keys flows on the engine's relay address). Unset, a build without the feature, or
    /// any probe/attach failure falls back cleanly to the always-available UDP-loopback datapath — the
    /// daemon never hard-fails on the XDP path (docs/security-and-nat.md §11.1).
    #[arg(long, value_name = "NAME")]
    xdp_interface: Option<String>,

    /// NIC queue the XDP/AF_XDP socket binds (RX/TX). Only used when `--xdp-interface` selects the XDP
    /// datapath; the first cut drives a single media queue (0).
    #[arg(long, default_value_t = DEFAULT_XDP_QUEUE)]
    xdp_queue: u32,
}

/// The daemon's runtime configuration after merging the CLI with the optional `--config` file.
///
/// Every field is fully resolved (no more precedence to apply): an explicit CLI flag beat the file,
/// the file beat the built-in default. `main` and [`spawn_turn`] read from here, never from the raw
/// `Args`, so there is exactly one place the precedence rule is applied — [`Resolved::resolve`].
struct Resolved {
    control: SocketAddr,
    ng: Option<SocketAddr>,
    relay_bind_ip: Option<IpAddr>,
    port_min: Option<u16>,
    port_max: Option<u16>,
    metrics_addr: Option<SocketAddr>,
    max_control_rps: u64,
    media_timeout_secs: u64,
    shutdown_grace_secs: u64,
    turn_udp: Option<SocketAddr>,
    turn_tcp: Option<SocketAddr>,
    turn_tls: Option<SocketAddr>,
    turn_tls_cert: Option<PathBuf>,
    turn_tls_key: Option<PathBuf>,
    turn_relay_ip: Option<IpAddr>,
    /// Only carried through for the log filter: the file may set it, but the process environment
    /// (`RUST_LOG` / the default-env filter) always wins, so it is applied before anything is logged.
    log_filter: Option<String>,
    /// Cluster node id (`load` / `node_info`); `None` here means "fall back to `HOSTNAME`" at build.
    node_id: Option<String>,
    /// Advertised maximum concurrent sessions for cluster load reporting (`0` = unlimited).
    max_sessions: u64,
    /// XDP/AF_XDP attach interface (`--xdp-interface`); `None` = UDP-loopback. Consulted by the
    /// datapath selection ([`choose_datapath`]); only acted on in a build with the `xdp` feature.
    xdp_interface: Option<String>,
    /// XDP/AF_XDP NIC queue (`--xdp-queue`, default 0). Only read when the `xdp` feature builds the
    /// backend in; kept unconditionally so the config surface is identical across builds.
    #[cfg_attr(not(feature = "xdp"), allow(dead_code))]
    xdp_queue: u32,
}

impl Resolved {
    /// Merge parsed CLI `args` (plus clap's `matches`, to tell an explicit flag from a defaulted
    /// one) with the optional config `file`, applying the precedence rule documented on the
    /// [`crate::config`] module: explicit CLI > file > default.
    fn resolve(args: Args, matches: &ArgMatches, file: FileConfig) -> Self {
        // A flag counts as "explicit" only when clap sourced it from the command line — a value left
        // at its clap default must not mask a file setting.
        let explicit = |id: &str| matches.value_source(id) == Some(ValueSource::CommandLine);

        Self {
            control: resolve_defaulted(
                args.control,
                explicit("control"),
                file.control,
                default_control(),
            ),
            ng: resolve_optional(args.ng, file.ng),
            relay_bind_ip: resolve_optional(args.relay_bind_ip, file.relay_bind_ip),
            port_min: resolve_optional(args.port_min, file.port_min),
            port_max: resolve_optional(args.port_max, file.port_max),
            metrics_addr: resolve_optional(args.metrics_addr, file.metrics_addr),
            max_control_rps: resolve_defaulted(
                args.max_control_rps,
                explicit("max_control_rps"),
                file.max_control_rps,
                server::DEFAULT_MAX_CONTROL_RPS,
            ),
            media_timeout_secs: resolve_defaulted(
                args.media_timeout_secs,
                explicit("media_timeout_secs"),
                file.media_timeout_secs,
                DEFAULT_MEDIA_TIMEOUT_SECS,
            ),
            shutdown_grace_secs: resolve_defaulted(
                args.shutdown_grace_secs,
                explicit("shutdown_grace_secs"),
                file.shutdown_grace_secs,
                DEFAULT_SHUTDOWN_GRACE_SECS,
            ),
            turn_udp: resolve_optional(args.turn_udp, file.turn_udp),
            turn_tcp: resolve_optional(args.turn_tcp, file.turn_tcp),
            turn_tls: resolve_optional(args.turn_tls, file.turn_tls),
            turn_tls_cert: resolve_optional(args.turn_tls_cert, file.turn_tls_cert),
            turn_tls_key: resolve_optional(args.turn_tls_key, file.turn_tls_key),
            turn_relay_ip: resolve_optional(args.turn_relay_ip, file.turn_relay_ip),
            log_filter: file.log_filter,
            node_id: resolve_optional(args.node_id, file.node_id),
            max_sessions: resolve_defaulted(
                args.max_sessions,
                explicit("max_sessions"),
                file.max_sessions,
                DEFAULT_MAX_SESSIONS,
            ),
            xdp_interface: resolve_optional(args.xdp_interface, file.xdp_interface),
            xdp_queue: resolve_defaulted(
                args.xdp_queue,
                explicit("xdp_queue"),
                file.xdp_queue,
                DEFAULT_XDP_QUEUE,
            ),
        }
    }
}

/// Validate the optional media-port range: both `--port-min` and `--port-max` must be set together
/// and satisfy `min <= max`. Returns `Ok(None)` when neither is set (OS-ephemeral ports), `Ok(Some)`
/// for a valid range, and a human-readable `Err` for a half-set or inverted range (fatal at startup).
/// Pure and unit-tested.
fn resolve_port_range(
    port_min: Option<u16>,
    port_max: Option<u16>,
) -> Result<Option<(u16, u16)>, String> {
    match (port_min, port_max) {
        (None, None) => Ok(None),
        (Some(min), Some(max)) if min <= max => Ok(Some((min, max))),
        (Some(min), Some(max)) => Err(format!(
            "invalid media port range: --port-min ({min}) must be <= --port-max ({max})"
        )),
        (Some(_), None) => Err("--port-min set without --port-max".to_string()),
        (None, Some(_)) => Err("--port-max set without --port-min".to_string()),
    }
}

/// The datapath the daemon selects at startup, decided purely from config (no I/O). This is only the
/// *candidacy* decision — whether XDP is even worth probing; the actual attach can still fail and
/// fall back to UDP at runtime (see the `xdp`-gated `try_build_xdp_datapath`). Pure and unit-tested so
/// the policy is checked without a NIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatapathChoice {
    /// Use the always-available UDP-loopback backend.
    Udp,
    /// XDP is a candidate — probe + attach it, falling back to UDP on any failure.
    TryXdp,
}

/// Decide the startup datapath from config alone. XDP is a candidate only when **all** hold:
/// - the `xdp` feature is compiled in (`feature_on`), so the backend exists to select;
/// - `--xdp-interface` names a non-empty NIC to attach to;
/// - `--relay-bind-ip` is a **routable IPv4** address ([`is_routable_relay_v4`]) — the XDP fast path
///   is IPv4-only and keys/advertises flows on the engine's relay address, which is meaningless on
///   loopback / a `0.0.0.0` wildcard / IPv6 (docs/security-and-nat.md §11.1: advertise a reachable
///   address, never the private/loopback one).
///
/// Anything else selects UDP-loopback. This does no I/O: a `TryXdp` result must still clear the
/// capability probe and the AF_XDP bind before it is actually used, else the daemon degrades to UDP.
fn choose_datapath(
    feature_on: bool,
    xdp_interface: Option<&str>,
    relay_bind_ip: Option<IpAddr>,
) -> DatapathChoice {
    match (feature_on, xdp_interface, relay_bind_ip) {
        (true, Some(interface), Some(IpAddr::V4(ip)))
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
/// §11.1). Used only to gate XDP selection; the UDP-loopback path imposes no such constraint.
fn is_routable_relay_v4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
}

/// Built-in default for `--control` (kept in one place so the CLI default and the precedence
/// fallback can never drift). Parsing a compile-time-constant literal that is always valid.
fn default_control() -> SocketAddr {
    SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 8080))
}

/// Built-in default for `--max-sessions` (mirrors the clap `default_value_t`). `0` = unlimited: the
/// node advertises no session cap and its load score is driven by CPU alone until one is configured.
const DEFAULT_MAX_SESSIONS: u64 = 0;

/// Built-in default NIC queue for `--xdp-queue` (mirrors the clap `default_value_t`): a single media
/// RX/TX queue (the first-cut XDP posture; multi-queue spreading is a later step).
const DEFAULT_XDP_QUEUE: u32 = 0;

/// Default cluster node id when neither `--node-id` nor the config file set one: the host's
/// `HOSTNAME` environment variable if present and non-empty, otherwise the literal `siphon-rtp`.
fn default_node_id() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "siphon-rtp".to_string())
}

/// Built-in default for `--media-timeout-secs` (mirrors the clap `default_value_t`).
const DEFAULT_MEDIA_TIMEOUT_SECS: u64 = 30;
/// Built-in default for `--shutdown-grace-secs` (mirrors the clap `default_value_t`).
const DEFAULT_SHUTDOWN_GRACE_SECS: u64 = 25;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse the CLI via `ArgMatches` (not just the typed struct) so the precedence merge can tell an
    // explicit flag from a defaulted one (`ValueSource::CommandLine`). `matches`/`from_arg_matches`
    // here handle `--help`/`--version`/parse errors exactly as `Args::parse()` would.
    let matches = Args::command().get_matches();
    let args = match Args::from_arg_matches(&matches) {
        Ok(args) => args,
        Err(error) => error.exit(),
    };

    // Load the optional `--config` TOML file. A missing/malformed file is fatal: fail loudly before
    // the subscriber exists (no tracing yet) rather than starting with a half-applied config.
    let file = match &args.config {
        Some(path) => match FileConfig::load(path) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("siphon-rtp-engine: {error}");
                std::process::exit(1);
            }
        },
        None => FileConfig::default(),
    };

    // Merge CLI over file over default, once, up front. Everything below reads `config`, not `args`.
    let config = Resolved::resolve(args, &matches, file);

    // Log filter precedence: the process environment (`RUST_LOG` / the default-env filter) wins; the
    // config file's `log_filter` is the next fallback; then a built-in `info`. This keeps env-based
    // overrides working while letting the config file set a default filter for operators.
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| match &config.log_filter {
            Some(directive) => {
                EnvFilter::try_new(directive).unwrap_or_else(|_| EnvFilter::new("info"))
            }
            None => EnvFilter::new("info"),
        });
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    // Optional deterministic media-port range (`--port-min`/`--port-max`). Both-or-neither and
    // min <= max; a half-set or inverted range is a fatal config error (fail loudly, before serving).
    let port_range = match resolve_port_range(config.port_min, config.port_max) {
        Ok(range) => range,
        Err(error) => {
            tracing::error!("{error}");
            std::process::exit(1);
        }
    };

    // Select the datapath from config (pure decision; see `choose_datapath`) and hand the chosen
    // backend to the generic `run_with_datapath`. The always-available UDP-loopback backend is the
    // default; the XDP/AF_XDP kernel fast path is chosen only under the `xdp` feature with a NIC + a
    // routable IPv4 relay address, and only after its capability probe + AF_XDP bind succeed. On any
    // XDP failure the daemon logs and falls back to UDP-loopback — never a hard failure. Endpoints bind
    // loopback by default; `--relay-bind-ip` binds a routable IP so the relay reaches real peers
    // (docs/security-and-nat.md §11.1). A configured port range draws media ports from a bounded,
    // firewallable window (and enables same-port HA takeover) instead of OS-ephemeral ports.
    let bind_ip = config
        .relay_bind_ip
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    match choose_datapath(
        cfg!(feature = "xdp"),
        config.xdp_interface.as_deref(),
        config.relay_bind_ip,
    ) {
        // XDP is a candidate: probe + attach the kernel fast path and run over it on success. On any
        // failure `try_build_xdp_datapath` logs the reason and returns `None`, so we fall through to
        // the UDP-loopback backend (the rtpengine posture: use the kernel fast path when the box
        // supports it, degrade cleanly otherwise). The arm is `xdp`-gated — feature-off can never
        // yield `TryXdp`, so the default build only ever matches the `_` fall-through to UDP-loopback.
        #[cfg(feature = "xdp")]
        DatapathChoice::TryXdp => {
            if let Some(xdp) = try_build_xdp_datapath(&config) {
                return run_with_datapath(xdp, config).await;
            }
        }
        _ => {}
    }
    let datapath = build_udp_datapath(&config, port_range, bind_ip);
    run_with_datapath(datapath, config).await
}

/// Build the always-available UDP-loopback datapath from the resolved config: a `--port-min`/
/// `--port-max` range draws media ports from a bounded, firewallable window (and enables same-port HA
/// takeover); otherwise a `--relay-bind-ip` binds a routable IP instead of loopback; neither set falls
/// back to OS-ephemeral loopback ports (the NIC-free default). `bind_ip` is `relay_bind_ip` or loopback.
fn build_udp_datapath(
    config: &Resolved,
    port_range: Option<(u16, u16)>,
    bind_ip: IpAddr,
) -> UdpLoopbackDatapath {
    match port_range {
        Some((min, max)) => UdpLoopbackDatapath::with_port_range(bind_ip, min, max),
        None => match config.relay_bind_ip {
            Some(ip) => UdpLoopbackDatapath::with_bind_ip(ip),
            None => UdpLoopbackDatapath::new(),
        },
    }
}

/// Advance a datapath backend's **logical** clock. The daemon's media-timeout sweeper drives this one
/// tick per wall second; both backends derive `now_ticks` from this logical clock (never
/// `Instant::now()`), so the sweep stays deterministic under test. `advance_clock` is an *inherent*
/// method on each concrete backend rather than a [`Datapath`] trait method; this local shim lets the
/// generic [`run_with_datapath`] drive it without widening the shared datapath seam. Inherent methods
/// win over trait methods, so concrete call sites (the engine's own tests) are unaffected.
trait AdvanceClock {
    /// Advance the backend's logical clock by `ticks`.
    fn advance_clock(&self, ticks: u64);
}

impl AdvanceClock for UdpLoopbackDatapath {
    fn advance_clock(&self, ticks: u64) {
        UdpLoopbackDatapath::advance_clock(self, ticks);
    }
}

#[cfg(feature = "xdp")]
impl AdvanceClock for siphon_rtp_xdp::XdpDatapath {
    fn advance_clock(&self, ticks: u64) {
        siphon_rtp_xdp::XdpDatapath::advance_clock(self, ticks);
    }
}

/// Run every post-datapath subsystem over the selected `datapath`: the cluster/engine, control server,
/// built-in TURN server, the single redirect dispatcher, the media-timeout + TURN sweeper, the
/// optional metrics/HEP/NG front-ends, and the graceful-shutdown drain. Generic over the datapath
/// backend `D`, so the UDP-loopback and XDP/AF_XDP paths run through identical wiring — the selection
/// in `main` is the only place the two differ. Behaviour-preserving for the UDP path (the engine
/// integration tests exercise it unchanged).
async fn run_with_datapath<D>(
    datapath: D,
    config: Resolved,
) -> Result<(), Box<dyn std::error::Error>>
where
    D: Datapath + AdvanceClock + Clone + Send + Sync + 'static,
{
    // Cluster state for the `load` / `node_info` / `drain` control commands. The node id falls back
    // to the host's `HOSTNAME` (else `siphon-rtp`); the advertised media address is the routable
    // relay bind IP (skipping a `0.0.0.0` wildcard, which is not a reachable address to hand a peer).
    let node_id = config.node_id.clone().unwrap_or_else(default_node_id);
    let media_addresses = config
        .relay_bind_ip
        .filter(|ip| !ip.is_unspecified())
        .map(|ip| vec![ip.to_string()])
        .unwrap_or_default();
    let cluster = Arc::new(cluster::ClusterState::new(
        node_id.clone(),
        config.max_sessions,
        media_addresses,
    ));
    tracing::info!(
        node_id = %node_id,
        max_sessions = config.max_sessions,
        "cluster node identity registered"
    );
    let engine = Arc::new(Engine::new(datapath.clone()).with_cluster(cluster.clone()));

    // Best-effort host-CPU sampler feeding the `load` command's load score (~1 Hz, off-reactor).
    cluster::spawn_cpu_sampler(cluster, cluster::DEFAULT_CPU_SAMPLE_INTERVAL);

    let listener = TcpListener::bind(config.control).await?;
    tracing::info!(control = %config.control, "siphon-rtp-engine control server listening");

    // Optional control-plane shared secret, read from the environment so it never appears in argv.
    let control_secret = std::env::var("SIPHON_RTP_CONTROL_SECRET").ok();
    if control_secret.is_some() {
        tracing::info!("control connections require authentication");
    }

    // The built-in TURN server (coturn replacement), if configured. It no longer drains the
    // datapath's Redirect stream itself — the unified dispatcher below feeds it its relay packets.
    let (turn, turn_relay) = spawn_turn(Arc::new(datapath.clone()), &config).await?;

    // The single redirect dispatcher: own `datapath.rx()` and route each redirected datagram by
    // EndpointId to the SRTP bridge or (when running) the TURN relay — the sole consumer of the
    // shared Redirect stream (docs/security-and-nat.md §11; the datapath's single-dispatcher rule).
    tokio::spawn(run_redirect_dispatcher(
        datapath.rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        turn_relay,
    ));

    // Media-timeout sweep: advance the logical clock ~1 tick/second, reap calls idle past the
    // timeout (docs/security-and-nat.md §4 layer 6), and reap expired TURN allocations on the same
    // clock (§11).
    let sweeper = engine.clone();
    let turn_sweeper = turn.clone();
    let timeout_ticks = config.media_timeout_secs;
    tracing::info!(
        media_timeout_secs = timeout_ticks,
        "media-timeout sweeper enabled"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            ticker.tick().await;
            sweeper.datapath().advance_clock(1);
            for call_id in sweeper.reap_idle(timeout_ticks).await {
                tracing::warn!(%call_id, "media timeout — call reaped");
            }
            let reaped = sweeper.reap_idle_conferences(timeout_ticks).await;
            if reaped > 0 {
                tracing::warn!(
                    participants = reaped,
                    "media timeout — conference participants reaped"
                );
            }
            if let Some(turn) = &turn_sweeper {
                turn.reap();
            }
        }
    });

    // Optional Prometheus metrics + health HTTP endpoint. Hand-rolled HTTP/1.1 (no hyper/axum) over
    // a dedicated TcpListener; `/metrics` renders the engine's control counters + live gauges.
    if let Some(metrics_addr) = config.metrics_addr {
        let metrics_listener = TcpListener::bind(metrics_addr).await?;
        tracing::info!(metrics = %metrics_addr, "metrics + health HTTP endpoint listening");
        let metrics = engine.metrics();
        let gauge_engine = engine.clone();
        let live = move || {
            let conference = gauge_engine.conference();
            let cluster = gauge_engine.cluster();
            let sessions = gauge_engine.session_count() as u64;
            let max_sessions = cluster.max_sessions();
            let cpu_permille = cluster.cpu_permille();
            metrics::LiveGauges {
                sessions,
                conference_rooms: conference.room_count() as u64,
                conference_participants: conference.participant_count() as u64,
                max_sessions,
                transcode_sessions: gauge_engine.transcode_session_count() as u64,
                load_permille: cluster::load_permille(sessions, max_sessions, cpu_permille),
                cpu_permille,
                draining: cluster.is_draining(),
            }
        };
        tokio::spawn(metrics::serve_metrics(metrics_listener, metrics, live));
    }

    // Optional HEP telemetry export of relayed RTCP to a VoIPmonitor / Homer collector, enabled by
    // SIPHON_RTP_HEP_COLLECTOR=<ip:port> (+ optional SIPHON_RTP_HEP_AGENT_ID).
    if let Ok(collector) = std::env::var("SIPHON_RTP_HEP_COLLECTOR") {
        match collector.parse::<SocketAddr>() {
            Ok(addr) => match HepExporter::connect(addr).await {
                Ok(exporter) => {
                    let agent_id = std::env::var("SIPHON_RTP_HEP_AGENT_ID")
                        .ok()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0);
                    tracing::info!(collector = %addr, "HEP RTCP export enabled");
                    tokio::spawn(engine.clone().run_rtcp_export(exporter, agent_id));
                }
                Err(error) => tracing::warn!(%error, "HEP export disabled: connect failed"),
            },
            Err(_) => tracing::warn!("SIPHON_RTP_HEP_COLLECTOR is not a valid socket address"),
        }
    }

    // Optional rtpengine NG/bencode control front-end (UDP) — the drop-in for SIPhon/Kamailio/
    // OpenSIPS. NG is unauthenticated by design (trusted control network); the per-client call
    // quota still applies via one dedicated NG client id. DTMF events go out-of-band (a later step).
    if let Some(ng_addr) = config.ng {
        let ng_socket = UdpSocket::bind(ng_addr).await?;
        tracing::info!(ng = %ng_addr, "rtpengine NG control listening");
        let ng_engine = engine.clone();
        tokio::spawn(async move {
            const NG_CLIENT: ClientId = ClientId(u64::MAX);
            let handler = move |command| {
                let engine = ng_engine.clone();
                async move { engine.handle(NG_CLIENT, command).await }
            };
            if let Err(error) = siphon_rtp_ngcompat::server::serve(ng_socket, handler).await {
                tracing::error!(%error, "NG control listener stopped");
            }
        });
    }

    // Graceful shutdown: a watch-backed flag tripped on the first SIGTERM/SIGINT. The accept loop
    // selects on it and stops admitting new control connections; the daemon then drains live calls
    // for a bounded grace period before returning from main so every Drop (sockets, actors) runs.
    let (shutdown_trigger, shutdown_flag) = shutdown::channel();
    tokio::spawn(async move {
        shutdown::wait_for_signal().await;
        tracing::info!("shutdown signal received; draining");
        shutdown_trigger.trigger();
    });

    // Run the control accept loop until shutdown is requested (or the listener errors).
    server::serve_with_options(
        engine.clone(),
        listener,
        control_secret,
        shutdown_flag,
        config.max_control_rps,
    )
    .await?;

    // Drained out of the accept loop: no new connections are admitted. Wait up to the grace period
    // for in-flight calls to finish before returning (and tearing everything down).
    drain_sessions(
        &engine,
        std::time::Duration::from_secs(config.shutdown_grace_secs),
    )
    .await;
    tracing::info!("siphon-rtp-engine shutting down");
    Ok(())
}

/// Poll the live session count down to zero, up to `grace`. Logs how many calls remained if the
/// grace period elapses first (they are then torn down abruptly on return). Deterministic-friendly:
/// a 0 session count returns immediately; a 0 grace skips the wait entirely.
async fn drain_sessions<D>(engine: &Engine<D>, grace: std::time::Duration)
where
    D: Datapath + Clone + Send + 'static,
{
    if engine.session_count() == 0 || grace.is_zero() {
        return;
    }
    tracing::info!(
        sessions = engine.session_count(),
        grace_secs = grace.as_secs(),
        "draining live sessions before exit"
    );
    let deadline = tokio::time::Instant::now() + grace;
    let mut poll = tokio::time::interval(std::time::Duration::from_millis(200));
    loop {
        poll.tick().await;
        let remaining = engine.session_count();
        if remaining == 0 {
            tracing::info!("all sessions drained");
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            tracing::warn!(
                remaining,
                "grace period elapsed; exiting with sessions still live"
            );
            return;
        }
    }
}

/// Build and start the TURN server when `SIPHON_RTP_TURN_REALM` + `SIPHON_RTP_TURN_SECRET` are set,
/// spawning whichever of the UDP/TCP/TLS listeners are configured. Returns `None` when TURN is off.
/// Generic over the datapath backend so TURN shares whichever one the daemon selected.
async fn spawn_turn<D>(
    datapath: Arc<D>,
    settings: &Resolved,
) -> Result<(Option<Turn>, Option<flume::Sender<RxPacket>>), Box<dyn std::error::Error>>
where
    D: Datapath + 'static,
{
    let (Some(realm), Some(secret)) = (
        std::env::var("SIPHON_RTP_TURN_REALM").ok(),
        std::env::var("SIPHON_RTP_TURN_SECRET").ok(),
    ) else {
        return Ok((None, None));
    };

    let mut config = TurnConfig::new(realm.clone(), secret.into_bytes());
    config.relay_address = settings.turn_relay_ip;
    // TURN's relay packets are fed by the redirect dispatcher (it shares datapath.rx() with the SRTP
    // bridge), not drained by TURN directly. Drop-newest on a full mailbox — late media is worthless.
    let (relay_tx, relay_rx) = flume::bounded(2048);
    let turn = Turn::spawn_with_relay_source(
        datapath,
        config,
        Arc::new(SystemUnixClock),
        Box::new(NoFastPath),
        relay_rx,
    )?;
    tracing::info!(realm, "TURN server enabled (coturn replacement)");

    if let Some(addr) = settings.turn_udp {
        let socket = UdpSocket::bind(addr).await?;
        tracing::info!(turn_udp = %addr, "TURN UDP listening");
        let turn = turn.clone();
        tokio::spawn(async move {
            let _ = turn.serve_udp(socket).await;
        });
    }
    if let Some(addr) = settings.turn_tcp {
        let tcp = TcpListener::bind(addr).await?;
        tracing::info!(turn_tcp = %addr, "TURN TCP listening");
        let turn = turn.clone();
        tokio::spawn(async move {
            let _ = turn.serve_tcp(tcp).await;
        });
    }
    if let Some(addr) = settings.turn_tls {
        let (Some(cert), Some(key)) = (&settings.turn_tls_cert, &settings.turn_tls_key) else {
            return Err("turns: (--turn-tls) requires --turn-tls-cert and --turn-tls-key".into());
        };
        tls::install_crypto_provider();
        let acceptor = tls::acceptor_from_pem(cert, key)?;
        let tls_listener = TcpListener::bind(addr).await?;
        tracing::info!(turn_tls = %addr, "TURN TLS listening");
        let turn = turn.clone();
        tokio::spawn(async move {
            let _ = turn.serve_tls(tls_listener, acceptor).await;
        });
    }

    if settings.turn_udp.is_none() && settings.turn_tcp.is_none() && settings.turn_tls.is_none() {
        tracing::warn!(
            "TURN is configured but no --turn-udp/--turn-tcp/--turn-tls listener was given"
        );
    }
    Ok((Some(turn), Some(relay_tx)))
}

/// Probe for and construct the XDP/AF_XDP datapath from config, or return `None` to fall back to
/// UDP-loopback. Only compiled under the `xdp` feature, and only reached after [`choose_datapath`]
/// returns [`DatapathChoice::TryXdp`] (feature on + interface + routable IPv4 relay). Never a hard
/// failure: no capability, a non-IPv4 relay address, or an attach/bind failure logs and returns `None`
/// so the daemon degrades cleanly to UDP-loopback (the rtpengine posture).
///
/// Attach preference: native/driver XDP first (lowest overhead), then generic SKB mode (any kernel
/// ≥ 5.10, incl. veth). `local_ip` is the routable IPv4 `--relay-bind-ip` — the address the XDP backend
/// advertises and keys flows on (docs/security-and-nat.md §11.1). This is startup-path code, not a
/// per-packet hot path, so no criterion bench is required.
#[cfg(feature = "xdp")]
fn try_build_xdp_datapath(config: &Resolved) -> Option<siphon_rtp_xdp::XdpDatapath> {
    use siphon_rtp_xdp::{xsk, AttachMode, Loader, XdpDatapath};

    // `choose_datapath` already established these invariants; re-derive the concrete values, and
    // decline (logging) if the relay address is somehow not a routable IPv4 so we never attach the
    // IPv4-only fast path without an engine-local relay IPv4 to key flows on.
    let interface = config.xdp_interface.as_deref()?;
    let local_ip = match config.relay_bind_ip {
        Some(IpAddr::V4(ip)) if is_routable_relay_v4(ip) => ip,
        _ => {
            tracing::warn!(
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
                tracing::debug!(interface, ?mode, %error, "XDP attach failed; trying next mode");
                continue;
            }
        };
        match XdpDatapath::new(
            loader,
            interface,
            config.xdp_queue,
            local_ip,
            xsk::XskConfig::default(),
        ) {
            Ok(datapath) => {
                tracing::info!(
                    interface,
                    queue = config.xdp_queue,
                    local_ip = %local_ip,
                    ?mode,
                    "XDP/AF_XDP datapath selected (kernel fast path)"
                );
                return Some(datapath);
            }
            Err(error) => {
                tracing::debug!(interface, ?mode, %error, "AF_XDP bind failed; trying next mode");
            }
        }
    }

    tracing::warn!(
        interface,
        "XDP unavailable after native + SKB attempts; using UDP-loopback"
    );
    None
}

#[cfg(test)]
mod tests {
    use super::{choose_datapath, is_routable_relay_v4, resolve_port_range, DatapathChoice};
    use std::net::{IpAddr, Ipv4Addr};

    /// Build an IPv4 [`IpAddr`] from octets (test helper — keeps the selection cases terse).
    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn port_range_neither_set_is_ephemeral() {
        assert_eq!(resolve_port_range(None, None), Ok(None));
    }

    #[test]
    fn port_range_valid_window_resolves() {
        assert_eq!(
            resolve_port_range(Some(30000), Some(40000)),
            Ok(Some((30000, 40000)))
        );
        // A single-port range (min == max) is valid.
        assert_eq!(
            resolve_port_range(Some(50000), Some(50000)),
            Ok(Some((50000, 50000)))
        );
    }

    #[test]
    fn port_range_half_set_is_an_error() {
        assert!(resolve_port_range(Some(30000), None).is_err());
        assert!(resolve_port_range(None, Some(40000)).is_err());
    }

    #[test]
    fn port_range_inverted_is_an_error() {
        let error = resolve_port_range(Some(40000), Some(30000)).expect_err("inverted range");
        assert!(
            error.contains("must be <="),
            "message names the constraint: {error}"
        );
    }

    // ── Datapath selection policy (pure; no NIC) ────────────────────────────────────────────────

    #[test]
    fn datapath_choice_feature_off_is_always_udp() {
        // A build without the `xdp` feature never selects XDP, even with a perfect interface + relay.
        assert_eq!(
            choose_datapath(false, Some("eth0"), Some(v4(203, 0, 113, 7))),
            DatapathChoice::Udp
        );
    }

    #[test]
    fn datapath_choice_without_interface_is_udp() {
        // Feature on but no interface named → UDP.
        assert_eq!(
            choose_datapath(true, None, Some(v4(203, 0, 113, 7))),
            DatapathChoice::Udp
        );
        // An empty interface name counts as unset.
        assert_eq!(
            choose_datapath(true, Some(""), Some(v4(203, 0, 113, 7))),
            DatapathChoice::Udp
        );
    }

    #[test]
    fn datapath_choice_requires_a_routable_v4_relay_ip() {
        // No relay address at all: nothing for the IPv4-only fast path to key/advertise on.
        assert_eq!(
            choose_datapath(true, Some("eth0"), None),
            DatapathChoice::Udp
        );
        // Loopback and the 0.0.0.0 wildcard are not routable relay addresses.
        assert_eq!(
            choose_datapath(true, Some("eth0"), Some(v4(127, 0, 0, 1))),
            DatapathChoice::Udp
        );
        assert_eq!(
            choose_datapath(true, Some("eth0"), Some(v4(0, 0, 0, 0))),
            DatapathChoice::Udp
        );
        // An IPv6 relay address: the XDP fast path is IPv4-only.
        assert_eq!(
            choose_datapath(
                true,
                Some("eth0"),
                Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
            ),
            DatapathChoice::Udp
        );
    }

    #[test]
    fn datapath_choice_full_config_tries_xdp() {
        // Feature on + a named interface + a routable IPv4 relay address → probe XDP.
        assert_eq!(
            choose_datapath(true, Some("eth0"), Some(v4(203, 0, 113, 7))),
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
