//! siphon-rtp-turn — the built-in TURN server (RFC 5766), a drop-in for coturn on the WebRTC
//! voice-AI legs.
//!
//! A standalone, always-listening relay: WebRTC clients behind restrictive NAT/firewalls `Allocate`
//! a relay address with a short-lived credential and the engine forwards their media. It is
//! independent of the JSON control plane — clients reach it directly — and draws its relay ports
//! from the **same bounded [`siphon_rtp_datapath::Datapath`] pool** the media plane uses, so the
//! port/FD-exhaustion guard and (later) the XDP/AF_XDP acceleration both apply for free.
//!
//! Design (per the project's concurrency rules):
//! - **Single-owner actor.** All allocation state lives in one task (the `manager` module) reached only
//!   through a bounded `flume` mailbox — no `Arc<Mutex<…>>` over allocation state, no lock held
//!   across an `.await`.
//! - **Pure Rust, zero C.** The STUN/TURN codec and the `MD5`/HMAC-SHA1 credential crypto are
//!   hand-rolled in [`siphon_rtp_stun`]; TLS (M-T6) will be rustls only.
//! - **Deterministic time.** Allocation/permission/channel/nonce lifetimes run on the datapath's
//!   injected logical clock (never `Instant::now()`); only the coturn REST credential's embedded
//!   wall-clock expiry uses a [`UnixClock`], itself injectable for tests.
//!
//! Credentials: the coturn REST profile (`static-auth-secret`) on the RFC 5766 long-term-credential
//! mechanism (MESSAGE-INTEGRITY = HMAC-SHA1, key = `MD5(username:realm:password)`). RFC 8656
//! MESSAGE-INTEGRITY-SHA256 is a deferred seam. The full threat model is `docs/security-and-nat.md`
//! §11.
#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use siphon_rtp_datapath::{Datapath, RxPacket};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;

mod credentials;
mod fastpath;
mod manager;
mod server;
pub mod tls;

pub use credentials::{CredentialVerifier, NonceFactory};
pub use fastpath::{ChannelRoute, NoFastPath, TurnFastPath};
pub use manager::AllocationManager;

use manager::Message;

/// The client→server transport an allocation was created over. Part of the allocation 5-tuple so a
/// client's UDP, TCP, and TLS allocations from the same address never collide (RFC 5766 §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    /// TURN over UDP (`turn:` on UDP).
    Udp,
    /// TURN over TCP (`turn:` on TCP, RFC 6062 client↔server framing).
    Tcp,
    /// TURN over TLS (`turns:`).
    Tls,
}

/// The allocation key (RFC 5766 §2.2): the client transport address, the server transport address it
/// reached, and the transport protocol between them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    /// The client's transport address.
    pub client: SocketAddr,
    /// The server transport address the client reached.
    pub server: SocketAddr,
    /// The client→server transport protocol.
    pub transport: TransportProtocol,
}

/// How the server writes back to a client — transport-agnostic so the allocation actor is unit-
/// testable on loopback (and over an in-memory channel) without caring which listener is underneath.
#[derive(Clone)]
pub enum ClientTransport {
    /// A datagram reply on a shared UDP listener socket to the client's address.
    Udp {
        /// The listener socket (shared by all UDP clients).
        socket: Arc<UdpSocket>,
        /// The client's transport address — the reply target.
        peer: SocketAddr,
    },
    /// A reply written to a per-connection stream (TCP/TLS) via its writer task's mailbox.
    Stream {
        /// The writer task's mailbox; each `Bytes` is one framed message to write.
        writer: flume::Sender<Bytes>,
    },
}

impl ClientTransport {
    /// Whether this is a stream transport (TCP/TLS) — ChannelData is 4-byte padded on a stream but
    /// not on UDP (RFC 5766 §11.5).
    #[must_use]
    pub(crate) fn is_stream(&self) -> bool {
        matches!(self, ClientTransport::Stream { .. })
    }

    /// Write one already-framed message back to the client. Best-effort: a failed UDP send or a
    /// closed stream writer is logged, not propagated (the reaper / connection teardown handles a
    /// dead client).
    pub(crate) async fn send(&self, message: &[u8]) {
        match self {
            ClientTransport::Udp { socket, peer } => {
                if let Err(error) = socket.send_to(message, *peer).await {
                    tracing::debug!(%peer, %error, "TURN UDP reply failed");
                }
            }
            ClientTransport::Stream { writer } => {
                if writer.send_async(Bytes::copy_from_slice(message)).await.is_err() {
                    tracing::debug!("TURN stream writer closed");
                }
            }
        }
    }
}

/// A wall-clock source for validating the coturn REST credential's embedded expiry timestamp
/// (`username = <unix-expiry>:<id>`). Injected so credential-expiry tests are deterministic — the
/// internal lifetimes use the datapath logical clock instead.
pub trait UnixClock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn now_unix(&self) -> u64;
}

/// The real wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemUnixClock;

impl UnixClock for SystemUnixClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A test clock whose Unix time is set explicitly.
#[derive(Debug, Default)]
pub struct FixedUnixClock(AtomicU64);

impl FixedUnixClock {
    /// A clock reading `seconds`.
    #[must_use]
    pub fn new(seconds: u64) -> Self {
        Self(AtomicU64::new(seconds))
    }

    /// Set the current Unix time.
    pub fn set(&self, seconds: u64) {
        self.0.store(seconds, Ordering::Relaxed);
    }
}

impl UnixClock for FixedUnixClock {
    fn now_unix(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Which peer addresses an allocation may relay to/from — the anti-SSRF / anti-reflection denylist
/// (coturn `denied-peer-ip`). A TURN server is an open-relay primitive; this stops a client steering
/// the relay at the server's own infrastructure or at private/loopback ranges
/// (docs/security-and-nat.md §11, R3).
#[derive(Clone, Debug)]
pub struct PeerIpPolicy {
    /// Deny loopback peers (`127.0.0.0/8`, `::1`).
    pub deny_loopback: bool,
    /// Deny RFC 1918 / unique-local private ranges.
    pub deny_private: bool,
    /// Deny link-local (`169.254.0.0/16`, `fe80::/10`).
    pub deny_link_local: bool,
    /// Deny multicast and the unspecified/broadcast addresses.
    pub deny_multicast: bool,
    /// Explicit denied addresses (e.g. the server's own listener / relay IPs).
    pub denied: Vec<IpAddr>,
}

impl Default for PeerIpPolicy {
    /// The secure production default: deny loopback, private, link-local, and multicast peers.
    fn default() -> Self {
        Self {
            deny_loopback: true,
            deny_private: true,
            deny_link_local: true,
            deny_multicast: true,
            denied: Vec::new(),
        }
    }
}

impl PeerIpPolicy {
    /// A fully permissive policy — required by the NIC-free loopback tests, whose peers are on
    /// `127.0.0.0/8`. Never a production default.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            deny_loopback: false,
            deny_private: false,
            deny_link_local: false,
            deny_multicast: false,
            denied: Vec::new(),
        }
    }

    /// Whether the relay may exchange traffic with `peer` (RFC 5766 §8/§9 permission target).
    #[must_use]
    pub fn permits(&self, peer: IpAddr) -> bool {
        if self.denied.contains(&peer) {
            return false;
        }
        // The unspecified address (0.0.0.0 / ::) is never a valid relay peer.
        if peer.is_unspecified() {
            return false;
        }
        match peer {
            IpAddr::V4(ip) => {
                if self.deny_loopback && ip.is_loopback() {
                    return false;
                }
                if self.deny_private && ip.is_private() {
                    return false;
                }
                if self.deny_link_local && ip.is_link_local() {
                    return false;
                }
                if self.deny_multicast && (ip.is_multicast() || ip.is_broadcast()) {
                    return false;
                }
                true
            }
            IpAddr::V6(ip) => {
                if self.deny_loopback && ip.is_loopback() {
                    return false;
                }
                // Unique-local fc00::/7 and link-local fe80::/10 by prefix (no stable std helpers).
                let first = ip.octets()[0];
                if self.deny_private && (first & 0xfe) == 0xfc {
                    return false;
                }
                let segs = ip.segments();
                if self.deny_link_local && (segs[0] & 0xffc0) == 0xfe80 {
                    return false;
                }
                if self.deny_multicast && ip.is_multicast() {
                    return false;
                }
                true
            }
        }
    }
}

/// Static configuration for the TURN server. Lifetimes are in seconds (the logical clock advances
/// ~1 tick/second in the daemon); the secret and realm come from deployment config and are never
/// logged.
#[derive(Clone)]
pub struct TurnConfig {
    /// The authentication realm advertised in the 401 challenge (RFC 5389 §15.7).
    pub realm: String,
    /// The coturn `static-auth-secret` — the REST credential HMAC key (RFC 5766 §4). Never logged.
    pub static_auth_secret: Vec<u8>,
    /// Optional SOFTWARE attribute value advertised in responses (RFC 5389 §15.10).
    pub software: Option<String>,
    /// The IP to advertise in XOR-RELAYED-ADDRESS, when the relay socket's bound IP is not the
    /// publicly reachable one (e.g. the loopback CI backend, or a NAT'd host). `None` advertises the
    /// datapath-assigned address verbatim.
    pub relay_address: Option<IpAddr>,
    /// Default allocation lifetime when the client requests none (RFC 5766 §6.2: 600 s).
    pub default_lifetime: u32,
    /// Maximum allocation lifetime the server will grant.
    pub max_lifetime: u32,
    /// Permission lifetime (RFC 5766 §8: 300 s).
    pub permission_lifetime: u32,
    /// Channel-binding lifetime (RFC 5766 §11: 600 s).
    pub channel_lifetime: u32,
    /// Nonce lifetime in logical ticks before a 438 Stale Nonce (RFC 5389 §10.2).
    pub nonce_lifetime: u64,
    /// Maximum concurrent allocations per credential username — the per-credential quota (→ 486).
    pub max_allocations_per_user: usize,
    /// Optional per-allocation relayed-byte cap; `None` is unlimited.
    pub max_bytes_per_allocation: Option<u64>,
    /// The peer-address denylist (anti-SSRF).
    pub denied_peers: PeerIpPolicy,
    /// Whether to append FINGERPRINT to responses (harmless; some clients expect it).
    pub include_fingerprint: bool,
}

impl TurnConfig {
    /// A config with the RFC-default lifetimes and the secure denylist, for `realm` + `secret`.
    #[must_use]
    pub fn new(realm: impl Into<String>, static_auth_secret: impl Into<Vec<u8>>) -> Self {
        Self {
            realm: realm.into(),
            static_auth_secret: static_auth_secret.into(),
            software: Some(concat!("siphon-rtp-turn ", env!("CARGO_PKG_VERSION")).to_string()),
            relay_address: None,
            default_lifetime: 600,
            max_lifetime: 3600,
            permission_lifetime: 300,
            channel_lifetime: 600,
            nonce_lifetime: 3600,
            max_allocations_per_user: 16,
            max_bytes_per_allocation: None,
            denied_peers: PeerIpPolicy::default(),
            include_fingerprint: true,
        }
    }
}

/// Errors from constructing or driving the TURN server.
#[derive(Debug, thiserror::Error)]
pub enum TurnError {
    /// The OS CSPRNG failed to seed the nonce secret.
    #[error("failed to gather entropy for the TURN nonce secret: {0}")]
    Entropy(String),
    /// Loading TLS material for the `turns:` listener failed.
    #[error("TURN TLS configuration error: {0}")]
    Tls(String),
}

/// A handle to a running TURN server: a cheap, cloneable sender into the allocation actor. The
/// datapath generic is erased at [`spawn`](Turn::spawn) — the manager task owns the `Arc<D>`.
#[derive(Clone)]
pub struct Turn {
    pub(crate) client_tx: flume::Sender<Message>,
}

impl Turn {
    /// Spawn the allocation actor + the relay-inbound dispatcher against `datapath`, returning a
    /// handle. Listeners (`serve_udp`, …) feed client datagrams into the returned handle.
    ///
    /// `unix_clock` validates the REST credential's embedded expiry; pass [`SystemUnixClock`] in
    /// production. The mailbox is bounded (backpressure on the control path; drop-newest for relay
    /// media, where late frames are worthless).
    pub fn spawn<D>(
        datapath: Arc<D>,
        config: TurnConfig,
        unix_clock: Arc<dyn UnixClock>,
    ) -> Result<Self, TurnError>
    where
        D: Datapath + 'static,
    {
        Self::spawn_with_fast_path(datapath, config, unix_clock, Box::new(NoFastPath))
    }

    /// As [`spawn`](Turn::spawn), but driving a kernel channel-relay [`TurnFastPath`] — the XDP
    /// datapath installs each bound channel's rewrite in-kernel so established channel data bypasses
    /// userspace (M-T8). The UDP-loopback backend uses [`NoFastPath`].
    pub fn spawn_with_fast_path<D>(
        datapath: Arc<D>,
        config: TurnConfig,
        unix_clock: Arc<dyn UnixClock>,
        fast_path: Box<dyn TurnFastPath>,
    ) -> Result<Self, TurnError>
    where
        D: Datapath + 'static,
    {
        // Standalone: TURN is the sole consumer of the datapath's shared Redirect stream.
        let relay_rx = datapath.rx();
        Self::spawn_with_relay_source(datapath, config, unix_clock, fast_path, relay_rx)
    }

    /// As [`spawn_with_fast_path`](Turn::spawn_with_fast_path), but draining `relay_rx` for relayed
    /// peer datagrams instead of `datapath.rx()` directly. Use this when a **central redirect
    /// dispatcher** owns the datapath's shared Redirect stream and routes only TURN's relay packets
    /// here — the posture when the engine runs the TURN server and the SRTP media bridge over one
    /// datapath (both use `FlowAction::Redirect`, so the dispatcher demuxes by `EndpointId`). The
    /// provided receiver should deliver only datagrams for TURN relay endpoints.
    pub fn spawn_with_relay_source<D>(
        datapath: Arc<D>,
        config: TurnConfig,
        unix_clock: Arc<dyn UnixClock>,
        fast_path: Box<dyn TurnFastPath>,
        relay_rx: flume::Receiver<RxPacket>,
    ) -> Result<Self, TurnError>
    where
        D: Datapath + 'static,
    {
        let mut nonce_secret = [0u8; 32];
        getrandom::getrandom(&mut nonce_secret).map_err(|e| TurnError::Entropy(e.to_string()))?;
        let nonce = NonceFactory::new(nonce_secret, config.nonce_lifetime);

        let (client_tx, client_rx) = flume::bounded::<Message>(2048);
        let manager =
            AllocationManager::new(datapath.clone(), config, unix_clock, nonce, fast_path);
        tokio::spawn(manager.run(client_rx));

        // Drain redirected peer datagrams into the allocation actor. Drop-newest on a full mailbox —
        // late media is worthless (docs/security-and-nat.md §11; CLAUDE.md concurrency rules).
        let relay_tx = client_tx.clone();
        tokio::spawn(async move {
            while let Ok(packet) = relay_rx.recv_async().await {
                let message = Message::RelayInbound {
                    endpoint: packet.endpoint,
                    peer: packet.source,
                    data: packet.data,
                };
                if let Err(flume::TrySendError::Full(_)) = relay_tx.try_send(message) {
                    tracing::trace!("TURN relay mailbox full; dropping inbound peer datagram");
                }
            }
        });

        Ok(Self { client_tx })
    }

    /// Serve TURN over UDP on `socket` (the `turn:` UDP front door) until the socket errors. All UDP
    /// clients share this one socket; per-client state is keyed by their source 5-tuple.
    pub async fn serve_udp(&self, socket: UdpSocket) -> std::io::Result<()> {
        server::serve_udp(self.client_tx.clone(), socket).await
    }

    /// Serve TURN over TCP (`turn:` on TCP, RFC 6062 client↔server framing) on `listener`.
    pub async fn serve_tcp(&self, listener: TcpListener) -> std::io::Result<()> {
        server::serve_tcp(self.client_tx.clone(), listener).await
    }

    /// Serve TURN over TLS (`turns:`) on `listener`, completing a rustls handshake per connection with
    /// `acceptor` before the TCP framing runs over the encrypted stream.
    pub async fn serve_tls(
        &self,
        listener: TcpListener,
        acceptor: TlsAcceptor,
    ) -> std::io::Result<()> {
        server::serve_tls(self.client_tx.clone(), listener, acceptor).await
    }

    /// Tick the allocation actor's reaper (frees expired allocations/permissions/channels against the
    /// datapath logical clock). The daemon calls this ~once/second; tests call it after advancing the
    /// clock for determinism.
    pub fn reap(&self) {
        let _ = self.client_tx.try_send(Message::Tick);
    }

    /// Stop the allocation actor (its relay endpoints are freed as the manager drops). Listeners
    /// still holding a handle observe the closed mailbox and exit on their next send.
    pub fn shutdown(&self) {
        let _ = self.client_tx.try_send(Message::Shutdown);
    }

    /// The number of live allocations — a metrics surface and the leak-soak's drain-to-zero check.
    pub async fn allocation_count(&self) -> usize {
        let (reply, response) = tokio::sync::oneshot::channel();
        if self.client_tx.send_async(Message::Count(reply)).await.is_err() {
            return 0;
        }
        response.await.unwrap_or(0)
    }
}
