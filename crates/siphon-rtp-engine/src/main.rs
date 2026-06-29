//! siphon-rtp-engine binary: start the control server (and the built-in TURN server) over the
//! capability-selected datapath.
//!
//! M1 binds the UDP-loopback backend unconditionally; XDP/AF_XDP selection by capability
//! detection (NET_ADMIN/BPF probe → graceful fallback) lands with the XDP backend. The TURN server
//! (`turn:`/`turns:`, a coturn replacement) shares that one datapath, so its relay ports come from
//! the same bounded pool and its allocations expire on the same logical clock.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::{Datapath, RxPacket};
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_engine::{server, ClientId, Engine};
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();

    // M1: the always-available NIC-free backend. XDP backend slots in behind the same trait. The
    // engine and the TURN server share one datapath (cloning shares the pool + logical clock).
    // Endpoints bind loopback by default; `--relay-bind-ip` binds a routable IP so the relay reaches
    // real peers (docs/security-and-nat.md §11.1).
    let datapath = match args.relay_bind_ip {
        Some(ip) => UdpLoopbackDatapath::with_bind_ip(ip),
        None => UdpLoopbackDatapath::new(),
    };
    let engine = Arc::new(Engine::new(datapath.clone()));

    let listener = TcpListener::bind(args.control).await?;
    tracing::info!(control = %args.control, "siphon-rtp-engine control server listening");

    // Optional control-plane shared secret, read from the environment so it never appears in argv.
    let control_secret = std::env::var("SIPHON_RTP_CONTROL_SECRET").ok();
    if control_secret.is_some() {
        tracing::info!("control connections require authentication");
    }

    // The built-in TURN server (coturn replacement), if configured. It no longer drains the
    // datapath's Redirect stream itself — the unified dispatcher below feeds it its relay packets.
    let (turn, turn_relay) = spawn_turn(Arc::new(datapath.clone()), &args).await?;

    // The single redirect dispatcher: own `datapath.rx()` and route each redirected datagram by
    // EndpointId to the SRTP bridge or (when running) the TURN relay — the sole consumer of the
    // shared Redirect stream (docs/security-and-nat.md §11; the datapath's single-dispatcher rule).
    tokio::spawn(run_redirect_dispatcher(
        datapath.rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        turn_relay,
    ));

    // Media-timeout sweep: advance the logical clock ~1 tick/second, reap calls idle past the
    // timeout (docs/security-and-nat.md §4 layer 6), and reap expired TURN allocations on the same
    // clock (§11).
    let sweeper = engine.clone();
    let turn_sweeper = turn.clone();
    tokio::spawn(async move {
        const TIMEOUT_TICKS: u64 = 30; // ~30 s of silence
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            ticker.tick().await;
            sweeper.datapath().advance_clock(1);
            for call_id in sweeper.reap_idle(TIMEOUT_TICKS).await {
                tracing::warn!(%call_id, "media timeout — call reaped");
            }
            if let Some(turn) = &turn_sweeper {
                turn.reap();
            }
        }
    });

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
    if let Some(ng_addr) = args.ng {
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

    server::serve_with_auth(engine, listener, control_secret).await?;
    Ok(())
}

/// Build and start the TURN server when `SIPHON_RTP_TURN_REALM` + `SIPHON_RTP_TURN_SECRET` are set,
/// spawning whichever of the UDP/TCP/TLS listeners are configured. Returns `None` when TURN is off.
async fn spawn_turn(
    datapath: Arc<UdpLoopbackDatapath>,
    args: &Args,
) -> Result<(Option<Turn>, Option<flume::Sender<RxPacket>>), Box<dyn std::error::Error>> {
    let (Some(realm), Some(secret)) = (
        std::env::var("SIPHON_RTP_TURN_REALM").ok(),
        std::env::var("SIPHON_RTP_TURN_SECRET").ok(),
    ) else {
        return Ok((None, None));
    };

    let mut config = TurnConfig::new(realm.clone(), secret.into_bytes());
    config.relay_address = args.turn_relay_ip;
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

    if let Some(addr) = args.turn_udp {
        let socket = UdpSocket::bind(addr).await?;
        tracing::info!(turn_udp = %addr, "TURN UDP listening");
        let turn = turn.clone();
        tokio::spawn(async move {
            let _ = turn.serve_udp(socket).await;
        });
    }
    if let Some(addr) = args.turn_tcp {
        let tcp = TcpListener::bind(addr).await?;
        tracing::info!(turn_tcp = %addr, "TURN TCP listening");
        let turn = turn.clone();
        tokio::spawn(async move {
            let _ = turn.serve_tcp(tcp).await;
        });
    }
    if let Some(addr) = args.turn_tls {
        let (Some(cert), Some(key)) = (&args.turn_tls_cert, &args.turn_tls_key) else {
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

    if args.turn_udp.is_none() && args.turn_tcp.is_none() && args.turn_tls.is_none() {
        tracing::warn!("TURN is configured but no --turn-udp/--turn-tcp/--turn-tls listener was given");
    }
    Ok((Some(turn), Some(relay_tx)))
}
