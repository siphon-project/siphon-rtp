//! The reusable daemon runtime: CLI/config surface plus [`run_with_datapath`], which drives every
//! post-datapath subsystem (control server, built-in TURN, redirect dispatcher, media-timeout
//! sweeper, metrics/HEP/NG front-ends, graceful drain) over **any**
//! [`siphon_rtp_datapath::Datapath`] backend.
//!
//! This is the seam that keeps the XDP fast path out of the engine crate. The default UDP-only
//! `siphon-rtp` binary ([`crate`]'s own `main`) builds a [`UdpLoopbackDatapath`] and calls
//! [`run_with_datapath`]; the separate `siphon-rtp-xdp-daemon` binary — which lives in the excluded
//! `crates/siphon-rtp-xdp` workspace and is the *only* place the eBPF/aya toolchain is pulled in —
//! probes and attaches the kernel datapath, then calls this same runner. Both share one CLI/TOML
//! surface via [`EngineArgs`] + [`FileConfig`] + [`RunConfig`], so the two binaries never drift.
//!
//! `run_with_datapath` advances the media-timeout sweep's logical clock through the additive
//! [`Datapath::advance_clock`] trait method (a no-op default on real-time backends), so the runner
//! stays fully generic without a shim trait that would hit the orphan rule for the out-of-crate
//! `XdpDatapath`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::parser::ValueSource;
use clap::ArgMatches;
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::{Datapath, RxPacket};
use siphon_rtp_hep::exporter::HepExporter;
use siphon_rtp_turn::{tls, NoFastPath, SystemUnixClock, Turn, TurnConfig};
use tokio::net::{TcpListener, UdpSocket};
use tracing_subscriber::EnvFilter;

use crate::config::{resolve_defaulted, resolve_optional, FileConfig, InterfaceConfig};
use crate::interface::{InterfaceEntry, InterfaceTable};
use crate::media_fetch::{self, MediaFetchLimits};
use crate::srtp_bridge::run_redirect_dispatcher_with_text;
use crate::{cluster, metrics, server, shutdown, ClientId, Engine};

/// The engine's shared CLI surface, common to every datapath binary. Kept a **flattenable**
/// `clap::Args` (not a top-level `Parser`) so both the default UDP `siphon-rtp` binary and the
/// `siphon-rtp-xdp-daemon` binary embed it verbatim via `#[command(flatten)]` and only the XDP
/// daemon adds its two extra `--xdp-*` knobs. Resolved against an optional `--config` file into a
/// [`RunConfig`] by [`RunConfig::resolve`].
#[derive(clap::Args, Debug)]
pub struct EngineArgs {
    /// Optional TOML config file (rtpengine-style declarative config). Any value the file sets
    /// overrides the built-in default; an explicit CLI flag still overrides the file. See
    /// `config.example.toml` for the schema. A missing or malformed file is a fatal startup error.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// JSON-over-TCP control listen address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub control: SocketAddr,

    /// rtpengine NG/bencode control listen address (UDP) — lets SIPhon / Kamailio / OpenSIPS drive
    /// the engine over the rtpengine protocol unchanged. Off unless given (rtpengine default :22222).
    #[arg(long)]
    pub ng: Option<SocketAddr>,

    /// TURN UDP listen address (`turn:`). TURN is enabled when `SIPHON_RTP_TURN_REALM` and
    /// `SIPHON_RTP_TURN_SECRET` are set; at least one `--turn-*` listener must then be given.
    #[arg(long)]
    pub turn_udp: Option<SocketAddr>,
    /// TURN TCP listen address (`turn:` over TCP, RFC 6062).
    #[arg(long)]
    pub turn_tcp: Option<SocketAddr>,
    /// TURN TLS listen address (`turns:`). Requires `--turn-tls-cert` and `--turn-tls-key`.
    #[arg(long)]
    pub turn_tls: Option<SocketAddr>,
    /// PEM certificate-chain file for the `turns:` listener.
    #[arg(long)]
    pub turn_tls_cert: Option<PathBuf>,
    /// PEM private-key file for the `turns:` listener.
    #[arg(long)]
    pub turn_tls_key: Option<PathBuf>,
    /// Public IP to advertise in XOR-RELAYED-ADDRESS when the relay socket's bound IP is not the
    /// reachable one (e.g. a NAT'd host). Defaults to the datapath-assigned address.
    #[arg(long)]
    pub turn_relay_ip: Option<IpAddr>,
    /// PEM certificate chain presented to the lawful-interception Mediation Function (ETSI
    /// TS 103 221-2 X3). Interception needs this, `--x3-client-key` and `--x3-ca`; without all
    /// three, `attach_x3` is refused rather than silently delivering nowhere.
    #[arg(long)]
    pub x3_client_cert: Option<PathBuf>,
    /// PEM private-key file for `--x3-client-cert`.
    #[arg(long)]
    pub x3_client_key: Option<PathBuf>,
    /// PEM CA file the Mediation Function's own certificate is verified against (a private PKI).
    #[arg(long)]
    pub x3_ca: Option<PathBuf>,
    /// Network Function ID on every delivered PDU (conditional attribute 6).
    #[arg(long)]
    pub x3_network_function_id: Option<String>,
    /// Interception Point ID on every delivered PDU (conditional attribute 7).
    #[arg(long)]
    pub x3_interception_point_id: Option<String>,
    /// Intercepted packets buffered per interception before content is dropped.
    #[arg(long)]
    pub x3_buffer_packets: Option<usize>,
    /// Idle seconds before a keepalive PDU is sent on the delivery connection.
    #[arg(long)]
    pub x3_keepalive_secs: Option<u64>,

    /// Bind relay/media sockets to this IP instead of loopback — the production posture so the relay
    /// is reachable by real peers (docs/security-and-nat.md §11.1). With a `0.0.0.0` bind or a NAT'd
    /// host, pair with `--advertise-ip` to advertise the reachable address in SDP.
    #[arg(long)]
    pub relay_bind_ip: Option<IpAddr>,

    /// Public IP advertised in offer/answer SDP `c=`/`m=`/`o=` (and ICE candidate) when the relay is
    /// bound to a private/NAT'd address — the single-interface 1:1-NAT case (e.g. an AWS Elastic IP).
    /// Same port; the socket still binds `--relay-bind-ip`. Emit-only: it does not affect the socket
    /// bind, the source gate, the in-kernel symmetric-RTP latch, or TURN (use `--turn-relay-ip` for
    /// that). For a multi-network internal/external split use `[[interface]]` + the control
    /// `direction` instead.
    #[arg(long)]
    pub advertise_ip: Option<IpAddr>,

    /// Lowest media port the datapath may bind. Set together with `--port-max` to draw media ports
    /// from a bounded, firewallable range (rtpengine `port-min` parity) instead of OS-ephemeral
    /// ports — required for HA takeover (a standby re-binds the same port). Off unless both are set.
    #[arg(long)]
    pub port_min: Option<u16>,

    /// Highest media port the datapath may bind. Set together with `--port-min`.
    #[arg(long)]
    pub port_max: Option<u16>,

    /// Prometheus metrics + health HTTP listen address. Off unless given. Exposes `GET /metrics`
    /// (OpenMetrics text), `GET /healthz` (liveness), and `GET /readyz` (readiness).
    #[arg(long)]
    pub metrics_addr: Option<SocketAddr>,

    /// Per-connection control request cap (requests/second). 0 disables the limit. The default is
    /// generous for a legitimate SIPhon controller; floods beyond it are rejected, not processed.
    #[arg(long, default_value_t = server::DEFAULT_MAX_CONTROL_RPS)]
    pub max_control_rps: u64,

    /// Reap a call after this many seconds with no accepted media (dead-path detection,
    /// docs/security-and-nat.md §4 layer 6). Advanced on the same logical clock as the sweeper.
    #[arg(long, default_value_t = DEFAULT_MEDIA_TIMEOUT_SECS)]
    pub media_timeout_secs: u64,

    /// Bounded grace period (seconds) to drain live calls on SIGTERM/SIGINT before exiting. The
    /// daemon stops accepting new control connections immediately, then waits up to this long for
    /// the live session count to reach 0.
    #[arg(long, default_value_t = DEFAULT_SHUTDOWN_GRACE_SECS)]
    pub shutdown_grace_secs: u64,

    /// Bound (milliseconds) on DNS + TCP connect + TLS for a `play_media` fetch from an http(s)
    /// URL, per redirect hop.
    #[arg(long, default_value_t = media_fetch::DEFAULT_CONNECT_TIMEOUT_MS)]
    pub media_fetch_connect_timeout_ms: u64,

    /// Bound (milliseconds) on the wait for response headers on a `play_media` URL fetch.
    #[arg(long, default_value_t = media_fetch::DEFAULT_FIRST_BYTE_TIMEOUT_MS)]
    pub media_fetch_first_byte_timeout_ms: u64,

    /// Bound (milliseconds) on a whole `play_media` URL fetch — every redirect hop and the body
    /// read together. A fetch that outlives it ends the playback with `PlayFinished{error}`.
    #[arg(long, default_value_t = media_fetch::DEFAULT_TOTAL_TIMEOUT_MS)]
    pub media_fetch_timeout_ms: u64,

    /// Largest `play_media` URL response body accepted, in bytes. Checked against Content-Length
    /// up front and enforced again while reading, so a chunked response cannot exceed it either.
    #[arg(long, default_value_t = media_fetch::DEFAULT_MAX_BODY_BYTES)]
    pub media_fetch_max_bytes: usize,

    /// Redirect hops a `play_media` URL fetch follows before giving up. Every hop is re-checked
    /// against the scheme rule and the allow-list.
    #[arg(long, default_value_t = media_fetch::DEFAULT_MAX_REDIRECTS)]
    pub media_fetch_max_redirects: u8,

    /// Restrict `play_media` URL fetches to these hosts (repeat the flag for several; exact,
    /// case-insensitive match, no wildcards). Unset means **unrestricted** — the engine will fetch
    /// any host it can route to, from its own network position. Set this, or an egress policy, when
    /// the control plane is not fully trusted.
    #[arg(long)]
    pub media_fetch_allow_host: Vec<String>,

    /// STUN server to ask for a server-reflexive ICE candidate during gathering (RFC 8445 §5.1.1.2).
    /// Repeat the flag for several. The built-in TURN server answers Binding requests (RFC 8656 §12),
    /// so `--turn-udp`'s address works here.
    ///
    /// Only useful when the engine itself sits behind a NAT it cannot be addressed through. On a
    /// routable media address the reflexive probe returns the address already advertised and is
    /// pruned as redundant (RFC 8445 §5.1.3) — so leaving this unset keeps call setup free of any
    /// network round trip.
    #[arg(long)]
    pub stun_server: Vec<SocketAddr>,

    /// Run a full RFC 8445 ICE agent on ICE legs (checklists, connectivity checks, role conflict
    /// resolution, peer-reflexive discovery, nomination) instead of the ICE-lite responder.
    ///
    /// Off by default: ICE-lite is a valid and simpler posture for a server on a routable address,
    /// and it is what the engine advertises. With this on, media on an ICE leg does not start until
    /// ICE has selected a pair — which is the point, but it is a behaviour change.
    #[arg(long, default_value_t = false)]
    pub ice_full: bool,

    /// Actively probe ICE legs for consent freshness (RFC 7675) instead of only answering their
    /// checks, tearing a call down when its peer stops responding on the validated path.
    ///
    /// Off by default on purpose: RFC 7675 §4 says an ICE-**lite** agent does not generate consent
    /// checks, and `a=ice-lite` is what the engine advertises today, so initiating them is a
    /// deviation the operator opts into. Requires a datapath with the full-agent seam (the UDP
    /// backend); the XDP fast path logs a warning and keeps responder-only behaviour.
    #[arg(long, default_value_t = false)]
    pub ice_consent: bool,

    /// Seconds between ICE consent checks on a validated pair (RFC 7675 §5.1 recommends ~5 s,
    /// randomised). Only used with `--ice-consent`.
    #[arg(long, default_value_t = DEFAULT_CONSENT_INTERVAL_SECS)]
    pub consent_interval_secs: u64,

    /// Seconds without a correlated consent response after which the pair is declared dead and the
    /// call is torn down (RFC 7675 §5.1: 30 s). Only used with `--ice-consent`.
    #[arg(long, default_value_t = DEFAULT_CONSENT_TIMEOUT_SECS)]
    pub consent_timeout_secs: u64,

    /// Stable cluster node identifier reported by the `load` / `node_info` control commands so a SIP
    /// dispatcher can tell engines apart. Defaults to the host's `HOSTNAME` (else `siphon-rtp`).
    #[arg(long)]
    pub node_id: Option<String>,

    /// Advertised maximum concurrent sessions for cluster load reporting (`0` = unlimited). Drives
    /// the normalized load score a dispatcher ranks nodes by; it does not itself cap admission (the
    /// per-client quota and the datapath port pool do that).
    #[arg(long, default_value_t = DEFAULT_MAX_SESSIONS)]
    pub max_sessions: u64,
}

/// The daemon's runtime configuration after merging the CLI with the optional `--config` file.
///
/// Every field is fully resolved (no more precedence to apply): an explicit CLI flag beat the file,
/// the file beat the built-in default. [`run_with_datapath`] reads from here, never from the raw
/// [`EngineArgs`], so there is exactly one place the precedence rule is applied — [`Self::resolve`].
/// XDP-selection knobs are **not** here — they belong to the `siphon-rtp-xdp-daemon` binary, which
/// resolves them alongside this via the same [`FileConfig`] so the engine stays datapath-agnostic.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// JSON-over-TCP control listen address.
    pub control: SocketAddr,
    /// rtpengine NG/bencode control listen address (UDP); `None` = off.
    pub ng: Option<SocketAddr>,
    /// Bind relay/media sockets to this IP instead of loopback; `None` = loopback.
    pub relay_bind_ip: Option<IpAddr>,
    /// Public IP advertised in rewritten SDP instead of the bind IP; `None` = advertise the bind IP.
    /// Sugar for a lone `default` interface; ignored when [`Self::interfaces`] is non-empty.
    pub advertise_ip: Option<IpAddr>,
    /// Named media interfaces (config-file only). Empty ⇒ a single `default` interface synthesised
    /// from [`Self::relay_bind_ip`] + [`Self::advertise_ip`].
    pub interfaces: Vec<InterfaceConfig>,
    /// Interface used when a call carries no `direction`; `None` ⇒ the first defined interface.
    pub default_interface: Option<String>,
    /// Lowest media port the datapath may bind (paired with [`Self::port_max`]).
    pub port_min: Option<u16>,
    /// Highest media port the datapath may bind (paired with [`Self::port_min`]).
    pub port_max: Option<u16>,
    /// Prometheus metrics + health HTTP listen address; `None` = off.
    pub metrics_addr: Option<SocketAddr>,
    /// Per-connection control request cap (requests/second); `0` disables.
    pub max_control_rps: u64,
    /// Reap a call after this many seconds with no accepted media.
    pub media_timeout_secs: u64,
    /// Bounded SIGTERM/SIGINT drain grace period (seconds).
    pub shutdown_grace_secs: u64,
    /// STUN servers asked for a server-reflexive candidate when gathering; empty ⇒ host-only.
    pub stun_servers: Vec<SocketAddr>,
    /// Run a full RFC 8445 ICE agent on ICE legs (off ⇒ the ICE-lite responder posture).
    pub ice_full: bool,
    /// Actively run RFC 7675 consent freshness on ICE legs (off ⇒ the ICE-lite responder posture).
    pub ice_consent: bool,
    /// Seconds between consent checks on a validated pair.
    pub consent_interval_secs: u64,
    /// Seconds without a correlated consent response before the pair is declared dead.
    pub consent_timeout_secs: u64,
    /// TURN UDP listen address (`turn:`); `None` = off.
    pub turn_udp: Option<SocketAddr>,
    /// TURN TCP listen address (`turn:` over TCP); `None` = off.
    pub turn_tcp: Option<SocketAddr>,
    /// TURN TLS listen address (`turns:`); `None` = off.
    pub turn_tls: Option<SocketAddr>,
    /// PEM certificate-chain file for the `turns:` listener.
    pub turn_tls_cert: Option<PathBuf>,
    /// PEM private-key file for the `turns:` listener.
    pub turn_tls_key: Option<PathBuf>,
    /// Public IP advertised in XOR-RELAYED-ADDRESS when the bound IP differs.
    pub turn_relay_ip: Option<IpAddr>,
    /// Lawful-interception content delivery (ETSI TS 103 221-2 X3). `None` ⇒ this node is not
    /// provisioned for interception and `attach_x3` is refused.
    pub x3: Option<crate::x3::X3Config>,
    /// Bounds a `play_media` fetch from an http(s) URL runs under.
    pub media_fetch: MediaFetchLimits,
    /// Only carried through for the log filter: the file may set it, but the process environment
    /// (`RUST_LOG` / the default-env filter) always wins, so it is applied before anything is logged.
    pub log_filter: Option<String>,
    /// Cluster node id (`load` / `node_info`); `None` here means "fall back to `HOSTNAME`" at build.
    pub node_id: Option<String>,
    /// Advertised maximum concurrent sessions for cluster load reporting (`0` = unlimited).
    pub max_sessions: u64,
}

impl RunConfig {
    /// Merge parsed CLI `args` (plus clap's `matches`, to tell an explicit flag from a defaulted
    /// one) with the optional config `file`, applying the precedence rule documented on the
    /// [`crate::config`] module: explicit CLI > file > default.
    pub fn resolve(args: EngineArgs, matches: &ArgMatches, file: FileConfig) -> Self {
        // A flag counts as "explicit" only when clap sourced it from the command line — a value left
        // at its clap default must not mask a file setting.
        let explicit = |id: &str| matches.value_source(id) == Some(ValueSource::CommandLine);

        // Resolved before the struct literal because it reads several fields of both inputs, which
        // the field-by-field moves below would otherwise have partially consumed.
        let x3 = resolve_x3(&args, &file);

        Self {
            control: resolve_defaulted(
                args.control,
                explicit("control"),
                file.control,
                default_control(),
            ),
            ng: resolve_optional(args.ng, file.ng),
            relay_bind_ip: resolve_optional(args.relay_bind_ip, file.relay_bind_ip),
            advertise_ip: resolve_optional(args.advertise_ip, file.advertise_ip),
            interfaces: file.interface,
            default_interface: file.default_interface,
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
            // A repeated CLI flag has no "explicit" bit to test, so a non-empty list simply wins over
            // the file (the same precedence, expressed for a `Vec`).
            stun_servers: if args.stun_server.is_empty() {
                file.stun_server.unwrap_or_default()
            } else {
                args.stun_server
            },
            ice_full: resolve_defaulted(args.ice_full, explicit("ice_full"), file.ice_full, false),
            ice_consent: resolve_defaulted(
                args.ice_consent,
                explicit("ice_consent"),
                file.ice_consent,
                false,
            ),
            consent_interval_secs: resolve_defaulted(
                args.consent_interval_secs,
                explicit("consent_interval_secs"),
                file.consent_interval_secs,
                DEFAULT_CONSENT_INTERVAL_SECS,
            ),
            consent_timeout_secs: resolve_defaulted(
                args.consent_timeout_secs,
                explicit("consent_timeout_secs"),
                file.consent_timeout_secs,
                DEFAULT_CONSENT_TIMEOUT_SECS,
            ),
            turn_udp: resolve_optional(args.turn_udp, file.turn_udp),
            turn_tcp: resolve_optional(args.turn_tcp, file.turn_tcp),
            turn_tls: resolve_optional(args.turn_tls, file.turn_tls),
            turn_tls_cert: resolve_optional(args.turn_tls_cert, file.turn_tls_cert),
            turn_tls_key: resolve_optional(args.turn_tls_key, file.turn_tls_key),
            turn_relay_ip: resolve_optional(args.turn_relay_ip, file.turn_relay_ip),
            // Interception is provisioned only when all three PEM paths are present. Anything less
            // is treated as "not configured" rather than half-configured: a partially-provisioned
            // node would accept a warrant it cannot deliver on.
            x3,
            media_fetch: MediaFetchLimits {
                connect_timeout: Duration::from_millis(resolve_defaulted(
                    args.media_fetch_connect_timeout_ms,
                    explicit("media_fetch_connect_timeout_ms"),
                    file.media_fetch_connect_timeout_ms,
                    media_fetch::DEFAULT_CONNECT_TIMEOUT_MS,
                )),
                first_byte_timeout: Duration::from_millis(resolve_defaulted(
                    args.media_fetch_first_byte_timeout_ms,
                    explicit("media_fetch_first_byte_timeout_ms"),
                    file.media_fetch_first_byte_timeout_ms,
                    media_fetch::DEFAULT_FIRST_BYTE_TIMEOUT_MS,
                )),
                total_timeout: Duration::from_millis(resolve_defaulted(
                    args.media_fetch_timeout_ms,
                    explicit("media_fetch_timeout_ms"),
                    file.media_fetch_timeout_ms,
                    media_fetch::DEFAULT_TOTAL_TIMEOUT_MS,
                )),
                max_body_bytes: resolve_defaulted(
                    args.media_fetch_max_bytes,
                    explicit("media_fetch_max_bytes"),
                    file.media_fetch_max_bytes,
                    media_fetch::DEFAULT_MAX_BODY_BYTES,
                ),
                max_redirects: resolve_defaulted(
                    args.media_fetch_max_redirects,
                    explicit("media_fetch_max_redirects"),
                    file.media_fetch_max_redirects,
                    media_fetch::DEFAULT_MAX_REDIRECTS,
                ),
                // A repeated CLI flag has no "explicit" bit, so a non-empty list wins over the file.
                allow_hosts: Arc::new(if args.media_fetch_allow_host.is_empty() {
                    file.media_fetch_allow_host.unwrap_or_default()
                } else {
                    args.media_fetch_allow_host
                }),
            },
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

    /// Build the engine's [`InterfaceTable`] from the resolved config. When `[[interface]]` entries are
    /// present they define the named interfaces (and `advertise_ip` is ignored — a warning is logged
    /// if it was also set); otherwise a single `default` interface is synthesised from `relay_bind_ip`
    /// (loopback when unset) + `advertise_ip`. Both datapath binaries call this once at startup.
    ///
    /// # Errors
    /// Propagates [`InterfaceTable::from_entries`] validation failures (empty table, duplicate family
    /// on one name, unknown `default_interface`) as a human-readable startup error.
    pub fn interface_table(&self) -> Result<InterfaceTable, String> {
        if self.interfaces.is_empty() {
            let bind = self
                .relay_bind_ip
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
            return Ok(InterfaceTable::single(bind, self.advertise_ip));
        }
        if self.advertise_ip.is_some() {
            tracing::warn!(
                "--advertise-ip is ignored when [[interface]] entries are configured; \
                 set `advertised` on the interface instead"
            );
        }
        let entries = self
            .interfaces
            .iter()
            .map(|iface: &InterfaceConfig| {
                InterfaceEntry::new(iface.name.clone(), iface.address, iface.advertised)
            })
            .collect();
        InterfaceTable::from_entries(entries, self.default_interface.as_deref())
    }
}

/// Resolve the lawful-interception (ETSI TS 103 221-2 X3) delivery configuration from the CLI args
/// and the config file, CLI winning.
///
/// Returns `None` unless **all three** PEM paths are present. A node with, say, a client certificate
/// but no CA is treated as unprovisioned rather than half-provisioned, because the alternative is
/// accepting a warrant onto a delivery connection that can never complete a handshake — an
/// interception that looks wired and delivers nothing.
///
/// The two identity strings default to empty (the attributes are still emitted, carrying no value)
/// and the buffer depth and keepalive to [`crate::x3::X3Config::default`].
fn resolve_x3(args: &EngineArgs, file: &FileConfig) -> Option<crate::x3::X3Config> {
    let defaults = crate::x3::X3Config::default();
    let client_cert = resolve_optional(args.x3_client_cert.clone(), file.x3_client_cert.clone())?;
    let client_key = resolve_optional(args.x3_client_key.clone(), file.x3_client_key.clone())?;
    let ca = resolve_optional(args.x3_ca.clone(), file.x3_ca.clone())?;
    Some(crate::x3::X3Config {
        client_cert,
        client_key,
        ca,
        network_function_id: resolve_optional(
            args.x3_network_function_id.clone(),
            file.x3_network_function_id.clone(),
        )
        .unwrap_or_default(),
        interception_point_id: resolve_optional(
            args.x3_interception_point_id.clone(),
            file.x3_interception_point_id.clone(),
        )
        .unwrap_or_default(),
        buffer_packets: resolve_optional(args.x3_buffer_packets, file.x3_buffer_packets)
            .unwrap_or(defaults.buffer_packets),
        keepalive: resolve_optional(args.x3_keepalive_secs, file.x3_keepalive_secs)
            .map_or(defaults.keepalive, Duration::from_secs),
    })
}

/// Validate the optional media-port range: both `--port-min` and `--port-max` must be set together
/// and satisfy `min <= max`. Returns `Ok(None)` when neither is set (OS-ephemeral ports), `Ok(Some)`
/// for a valid range, and a human-readable `Err` for a half-set or inverted range (fatal at startup).
/// Pure and unit-tested; both datapath binaries call it once, up front.
pub fn resolve_port_range(
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

/// Build the always-available UDP-loopback datapath from the resolved config: a `--port-min`/
/// `--port-max` range (already validated by [`resolve_port_range`]) draws media ports from a bounded,
/// firewallable window (and enables same-port HA takeover); otherwise a `--relay-bind-ip` binds a
/// routable IP instead of loopback; neither set falls back to OS-ephemeral loopback ports (the
/// NIC-free default). This is the engine's default backend and the `siphon-rtp-xdp-daemon`'s
/// graceful fallback when the kernel fast path is unavailable.
#[must_use]
pub fn build_udp_datapath(
    config: &RunConfig,
    port_range: Option<(u16, u16)>,
) -> UdpLoopbackDatapath {
    let bind_ip = config
        .relay_bind_ip
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    match port_range {
        Some((min, max)) => UdpLoopbackDatapath::with_port_range(bind_ip, min, max),
        None => match config.relay_bind_ip {
            Some(ip) => UdpLoopbackDatapath::with_bind_ip(ip),
            None => UdpLoopbackDatapath::new(),
        },
    }
}

/// Install the global `tracing` subscriber, applying the log-filter precedence: the process
/// environment (`RUST_LOG` / the default-env filter) wins; the config file's `log_filter` is the
/// next fallback; then a built-in `info`. Call once per process, before anything is logged.
pub fn init_tracing(config: &RunConfig) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| match &config.log_filter {
            Some(directive) => {
                EnvFilter::try_new(directive).unwrap_or_else(|_| EnvFilter::new("info"))
            }
            None => EnvFilter::new("info"),
        });
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}

/// Built-in default for `--control` (kept in one place so the CLI default and the precedence
/// fallback can never drift). Parsing a compile-time-constant literal that is always valid.
fn default_control() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))
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
/// How often the full-ICE driver polls its agents. Below the RFC 8445 §14.2 `Ta` of 50 ms, so pacing
/// is decided by the agent rather than by the tick granularity.
const ICE_DRIVER_INTERVAL_MS: u64 = 20;
/// Built-in default for `--consent-interval-secs` (RFC 7675 §5.1 recommends ~5 s, randomised).
const DEFAULT_CONSENT_INTERVAL_SECS: u64 = 5;
/// Built-in default for `--consent-timeout-secs` (RFC 7675 §5.1: consent expires after 30 s).
const DEFAULT_CONSENT_TIMEOUT_SECS: u64 = 30;

/// Run every post-datapath subsystem over the selected `datapath`: the cluster/engine, control
/// server, built-in TURN server, the single redirect dispatcher, the media-timeout + TURN sweeper,
/// the optional metrics/HEP/NG front-ends, and the graceful-shutdown drain. Generic over the
/// datapath backend `D`, so the UDP-loopback and XDP/AF_XDP paths run through identical wiring — the
/// datapath *selection* (which binary built which backend) is the only place the two differ.
/// Behaviour-preserving for the UDP path (the engine integration tests exercise it unchanged).
///
/// The media-timeout sweep advances the backend's logical clock via [`Datapath::advance_clock`] — a
/// no-op on real-time backends (the XDP fast path derives `now_ticks` from a monotonic kernel clock),
/// which keeps this runner generic without a shim trait that would hit the orphan rule.
pub async fn run_with_datapath<D>(
    datapath: D,
    config: RunConfig,
) -> Result<(), Box<dyn std::error::Error>>
where
    D: Datapath + Clone + Send + Sync + 'static,
{
    // Named-interface table (rtpengine-style): the advertised/bind-IP policy the engine applies at
    // SDP-rewrite time. Built once here so both datapath binaries inherit it; a malformed table is a
    // fatal startup error (never a silent fallback).
    let interfaces = config.interface_table()?;

    // Cluster state for the `load` / `node_info` / `drain` control commands. The node id falls back to
    // the host's `HOSTNAME` (else `siphon-rtp`); the advertised media addresses are the interfaces'
    // advertised IPs (skipping a `0.0.0.0` wildcard, which is not a reachable address to hand a peer).
    let node_id = config.node_id.clone().unwrap_or_else(default_node_id);
    let media_addresses = interfaces.advertised_media_addresses();
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
    if config.media_fetch.allow_hosts.is_empty() {
        tracing::info!(
            target: "siphon_rtp::control",
            "play_media URL fetches are unrestricted — the engine will fetch any host it can route \
             to; set --media-fetch-allow-host (or an egress policy) if the control plane is not \
             fully trusted"
        );
    } else {
        tracing::info!(
            target: "siphon_rtp::control",
            hosts = ?config.media_fetch.allow_hosts,
            "play_media URL fetches restricted to these hosts"
        );
    }
    let mut engine = Engine::new(datapath.clone())
        .with_cluster(cluster.clone())
        .with_interfaces(interfaces)
        .with_media_fetch_limits(config.media_fetch.clone());
    if let Some(x3) = config.x3.clone() {
        // Logged at startup so an operator can see, without placing a call, that this node will
        // accept a warrant — and, just as importantly, so its absence is visible on a node that
        // will refuse one. The identifiers are node identity, not interception data.
        tracing::info!(
            target: "siphon_rtp::li",
            network_function_id = %x3.network_function_id,
            interception_point_id = %x3.interception_point_id,
            buffer_packets = x3.buffer_packets,
            "lawful-interception content delivery (ETSI TS 103 221-2 X3) is provisioned"
        );
        engine = engine.with_x3(x3);
    }
    if !config.stun_servers.is_empty() {
        tracing::info!(
            target: "siphon_rtp::control",
            servers = ?config.stun_servers,
            "ICE gathering will probe these STUN servers for a server-reflexive candidate"
        );
        engine = engine.with_stun_servers(config.stun_servers.clone());
    }
    if config.ice_full {
        tracing::info!(
            target: "siphon_rtp::media",
            "full RFC 8445 ICE enabled — ICE legs run checklists and connectivity checks; media waits for a selected pair"
        );
        engine = engine.with_full_ice();
    }
    if config.ice_consent {
        tracing::info!(
            target: "siphon_rtp::media",
            interval_secs = config.consent_interval_secs,
            timeout_secs = config.consent_timeout_secs,
            "RFC 7675 ICE consent freshness enabled — ICE legs are actively probed on their validated pair"
        );
        engine = engine.with_consent(crate::ice::driver::ConsentConfig {
            // One sweeper tick is one wall second, so seconds and ticks are the same unit here.
            interval_ticks: config.consent_interval_secs,
            timeout_ticks: config.consent_timeout_secs,
            ..Default::default()
        });
    }
    let engine = Arc::new(engine);

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
    tokio::spawn(run_redirect_dispatcher_with_text(
        datapath.rx(),
        engine.bridge(),
        engine.media(),
        engine.text(),
        engine.ws(),
        engine.conference(),
        turn_relay,
    ));

    // Full-ICE driver: the RFC's `Ta` pacing is 50 ms and its initial RTO 500 ms, so the agents need
    // a sub-second clock of their own — the 1 Hz media sweep below is far too coarse. Idle (one
    // no-op poll per tick) unless `--ice full` is set.
    if config.ice_full {
        let ice_engine = engine.clone();
        tokio::spawn(async move {
            let started = tokio::time::Instant::now();
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_millis(ICE_DRIVER_INTERVAL_MS));
            // Under load a missed tick must not produce a burst of catch-up polls; the agent's own
            // timers are elapsed-based, so skipping is correct and cheaper.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                for call_id in ice_engine
                    .drive_ice_agents(started.elapsed().as_millis() as u64)
                    .await
                {
                    tracing::warn!(target: "siphon_rtp::media", %call_id, "call torn down: ICE failed");
                }
            }
        });
    }

    // Media-timeout sweep: advance the logical clock ~1 tick/second, reap calls idle past the
    // timeout (docs/security-and-nat.md §4 layer 6), and reap expired TURN allocations on the same
    // clock (§11). `advance_clock` is the additive `Datapath` trait method — a no-op on a real-time
    // backend, which advances the deterministic loopback clock and leaves the kernel clock alone.
    let sweeper = engine.clone();
    let turn_sweeper = turn.clone();
    let timeout_ticks = config.media_timeout_secs;
    tracing::info!(
        target: "siphon_rtp::media",
        media_timeout_secs = timeout_ticks,
        "media-timeout sweeper enabled"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            ticker.tick().await;
            sweeper.datapath().advance_clock(1);
            // Propagate any kernel-learned peer source into the sibling leg's forward destination,
            // closing the in-kernel symmetric-RTP loop (docs/security-and-nat.md §4 layer 3); a no-op
            // on the loopback backend (which resolves the latch inline when forwarding).
            sweeper.refresh_latched_destinations().await;
            // RFC 7675 consent freshness on ICE legs: probe each validated pair and tear down a call
            // whose peer stopped answering. A no-op unless `--ice-consent` is set. Runs *before* the
            // idle reap so a call the peer just refreshed is not also evaluated as idle this tick.
            sweeper.drive_consent().await;
            for call_id in sweeper.reap_idle(timeout_ticks).await {
                tracing::warn!(target: "siphon_rtp::media", %call_id, idle_secs = timeout_ticks, "media timeout — call reaped");
            }
            let reaped = sweeper.reap_idle_conferences(timeout_ticks).await;
            if reaped > 0 {
                tracing::warn!(
                    target: "siphon_rtp::media",
                    participants = reaped,
                    idle_secs = timeout_ticks,
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
                ws_tees: gauge_engine.ws_tee_count() as u64,
                ws_bridges: gauge_engine.ws_bridge_count() as u64,
                ws_tee_frames_sent: gauge_engine.ws_tee_frames_sent(),
                ws_tee_frames_dropped: gauge_engine.ws_tee_frames_dropped(),
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
                    // Share the one connected exporter with both the live RTCP loop and the
                    // end-of-call RFC 4103 text-QoS export in `finish_call`.
                    engine.set_hep_export(exporter, agent_id);
                    tokio::spawn(engine.clone().run_rtcp_export());
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
    settings: &RunConfig,
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

#[cfg(test)]
mod tests {
    use super::{resolve_port_range, resolve_x3, EngineArgs, RunConfig};
    use crate::config::{FileConfig, InterfaceConfig};
    use crate::media_fetch::MediaFetchLimits;
    use siphon_rtp_datapath::AddressFamily;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    /// `EngineArgs` is a flattenable `clap::Args`, not a top-level `Parser`, so a test parses it the
    /// same way the real binaries do — through a wrapper that flattens it.
    #[derive(clap::Parser)]
    struct TestCommandLine {
        #[command(flatten)]
        engine: EngineArgs,
    }

    /// `EngineArgs` with every flag unset, so an X3 resolution test drives the file side alone.
    fn bare_args() -> EngineArgs {
        <TestCommandLine as clap::Parser>::parse_from(["siphon-rtp"]).engine
    }

    /// A `FileConfig` naming all three lawful-interception PEM paths.
    fn provisioned_file() -> FileConfig {
        FileConfig {
            x3_client_cert: Some(PathBuf::from("/etc/siphon-rtp/li/client.pem")),
            x3_client_key: Some(PathBuf::from("/etc/siphon-rtp/li/client.key")),
            x3_ca: Some(PathBuf::from("/etc/siphon-rtp/li/mdf-ca.pem")),
            ..FileConfig::default()
        }
    }

    #[test]
    fn interception_is_unconfigured_unless_all_three_pem_paths_are_present() {
        // Half-provisioned must count as unprovisioned. A node with a client certificate but no CA
        // could never complete the delivery handshake, so accepting a warrant on it would produce an
        // interception that looks wired and delivers nothing.
        assert!(
            resolve_x3(&bare_args(), &FileConfig::default()).is_none(),
            "nothing set means not provisioned"
        );

        for missing in ["x3_client_cert", "x3_client_key", "x3_ca"] {
            let mut file = provisioned_file();
            match missing {
                "x3_client_cert" => file.x3_client_cert = None,
                "x3_client_key" => file.x3_client_key = None,
                _ => file.x3_ca = None,
            }
            assert!(
                resolve_x3(&bare_args(), &file).is_none(),
                "missing {missing} must leave the node unprovisioned, not half-provisioned"
            );
        }

        assert!(
            resolve_x3(&bare_args(), &provisioned_file()).is_some(),
            "all three present provisions the node"
        );
    }

    #[test]
    fn interception_defaults_the_buffer_depth_and_keepalive() {
        let resolved = resolve_x3(&bare_args(), &provisioned_file()).expect("provisioned");
        let defaults = crate::x3::X3Config::default();
        assert_eq!(resolved.buffer_packets, defaults.buffer_packets);
        assert_eq!(resolved.keepalive, defaults.keepalive);
        // The identity attributes are optional; they are emitted carrying no value when unset.
        assert!(resolved.network_function_id.is_empty());
        assert!(resolved.interception_point_id.is_empty());
    }

    #[test]
    fn interception_reads_the_identity_and_bounds_from_the_file() {
        let mut file = provisioned_file();
        file.x3_network_function_id = Some("siphon-rtp-sbc-01".into());
        file.x3_interception_point_id = Some("media-relay-a".into());
        file.x3_buffer_packets = Some(40_000);
        file.x3_keepalive_secs = Some(15);

        let resolved = resolve_x3(&bare_args(), &file).expect("provisioned");
        assert_eq!(resolved.network_function_id, "siphon-rtp-sbc-01");
        assert_eq!(resolved.interception_point_id, "media-relay-a");
        assert_eq!(resolved.buffer_packets, 40_000);
        assert_eq!(resolved.keepalive, std::time::Duration::from_secs(15));
    }

    /// A `RunConfig` with everything at its off/default value, so a test overrides only the fields it
    /// cares about (the interface-table inputs).
    fn bare_run_config() -> RunConfig {
        RunConfig {
            control: "127.0.0.1:8080".parse().unwrap(),
            ng: None,
            relay_bind_ip: None,
            advertise_ip: None,
            interfaces: Vec::new(),
            default_interface: None,
            port_min: None,
            port_max: None,
            metrics_addr: None,
            max_control_rps: 0,
            media_timeout_secs: 30,
            shutdown_grace_secs: 25,
            stun_servers: Vec::new(),
            ice_full: false,
            ice_consent: false,
            consent_interval_secs: 5,
            consent_timeout_secs: 30,
            turn_udp: None,
            turn_tcp: None,
            turn_tls: None,
            turn_tls_cert: None,
            turn_tls_key: None,
            turn_relay_ip: None,
            x3: None,
            media_fetch: MediaFetchLimits::default(),
            log_filter: None,
            node_id: None,
            max_sessions: 0,
        }
    }

    #[test]
    fn interface_table_synthesises_default_from_bind_and_advertise_ip() {
        // No `[[interface]]`: a single `default` interface from relay_bind_ip + advertise_ip (sugar).
        let config = RunConfig {
            relay_bind_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            advertise_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
            ..bare_run_config()
        };
        let table = config.interface_table().expect("single interface");
        let address = table
            .default_interface()
            .exact_address_for(AddressFamily::V4)
            .expect("v4");
        assert_eq!(address.bind, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(
            address.advertised,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
        );
    }

    #[test]
    fn interface_table_with_no_config_is_loopback() {
        let table = bare_run_config()
            .interface_table()
            .expect("loopback default");
        let address = table
            .default_interface()
            .exact_address_for(AddressFamily::V4)
            .expect("v4");
        assert_eq!(address.bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(address.advertised, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn interface_table_builds_named_interfaces_from_config() {
        let config = RunConfig {
            interfaces: vec![
                InterfaceConfig {
                    name: "internal".into(),
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    advertised: None,
                },
                InterfaceConfig {
                    name: "external".into(),
                    address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    advertised: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
                },
            ],
            default_interface: Some("external".into()),
            ..bare_run_config()
        };
        let table = config.interface_table().expect("named interfaces");
        assert_eq!(table.default_interface().name, "external");
        let (near, far) =
            table.resolve_direction(&["external".to_string(), "internal".to_string()]);
        assert_eq!(
            near.exact_address_for(AddressFamily::V4)
                .unwrap()
                .advertised,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
        );
        assert_eq!(
            far.exact_address_for(AddressFamily::V4).unwrap().bind,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn interface_table_rejects_an_unknown_default() {
        let config = RunConfig {
            interfaces: vec![InterfaceConfig {
                name: "a".into(),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                advertised: None,
            }],
            default_interface: Some("missing".into()),
            ..bare_run_config()
        };
        assert!(config.interface_table().is_err());
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
}
