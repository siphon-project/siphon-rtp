//! siphon-rtp-engine binary: start the control server (and the built-in TURN server) over the
//! capability-selected datapath.
//!
//! M1 binds the UDP-loopback backend unconditionally; XDP/AF_XDP selection by capability
//! detection (NET_ADMIN/BPF probe → graceful fallback) lands with the XDP backend. The TURN server
//! (`turn:`/`turns:`, a coturn replacement) shares that one datapath, so its relay ports come from
//! the same bounded pool and its allocations expire on the same logical clock.

mod config;

use std::net::{IpAddr, SocketAddr};
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
        }
    }
}

/// Built-in default for `--control` (kept in one place so the CLI default and the precedence
/// fallback can never drift). Parsing a compile-time-constant literal that is always valid.
fn default_control() -> SocketAddr {
    SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 8080))
}

/// Built-in default for `--max-sessions` (mirrors the clap `default_value_t`). `0` = unlimited: the
/// node advertises no session cap and its load score is driven by CPU alone until one is configured.
const DEFAULT_MAX_SESSIONS: u64 = 0;

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

    // M1: the always-available NIC-free backend. XDP backend slots in behind the same trait. The
    // engine and the TURN server share one datapath (cloning shares the pool + logical clock).
    // Endpoints bind loopback by default; `--relay-bind-ip` binds a routable IP so the relay reaches
    // real peers (docs/security-and-nat.md §11.1).
    let datapath = match config.relay_bind_ip {
        Some(ip) => UdpLoopbackDatapath::with_bind_ip(ip),
        None => UdpLoopbackDatapath::new(),
    };

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
            metrics::LiveGauges {
                sessions: gauge_engine.session_count() as u64,
                conference_rooms: conference.room_count() as u64,
                conference_participants: conference.participant_count() as u64,
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
async fn spawn_turn(
    datapath: Arc<UdpLoopbackDatapath>,
    settings: &Resolved,
) -> Result<(Option<Turn>, Option<flume::Sender<RxPacket>>), Box<dyn std::error::Error>> {
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
