//! Lawful-interception content delivery (ETSI TS 103 221-2 X3).
//!
//! The engine already holds every intercepted packet, so it frames and ships them itself rather
//! than routing warranted media back through the signalling process. This module owns the pieces
//! between the media path and the Mediation Function: the per-direction tap, the bounded buffer
//! between them, and the mutually-authenticated delivery connection.
//!
//! The framing itself lives in [`siphon_rtp_li`], which is validated against an independent decoder.
//!
//! # Where the taps sit, and why it matters
//!
//! An X3 tap is **not** the pcap recorder's tap, in two ways that are both disqualifying for
//! interception:
//!
//! - **After the decrypt.** The pcap recorder copies the verbatim wire bytes before
//!   `Direction::handle` runs, and `handle` decrypts SDES-SRTP at its top. On a secure leg that
//!   recording is ciphertext — fine for debugging, useless to an agency that has no key. Every X3
//!   tap runs on the same plaintext slice the relay and the tee see.
//! - **After the authentication decision.** `handle` drops a datagram whose SRTP `unprotect` fails
//!   (bad auth, replay, wrong key) and one that arrives before a DTLS leg is keyed. The recorder has
//!   already copied those. Delivering them would present forged or replayed packets to the agency as
//!   the target's media.
//!
//! There are three tap sites because there are three places the engine holds accepted plaintext:
//! the media pipeline's `Direction::handle`, and the SRTP and DTLS crypto bridges (which relay
//! without decoding, so a same-codec WebRTC call never reaches the pipeline at all).
//!
//! # Loss policy
//!
//! Deliberately not the recorder's "best-effort, drop on full". Silently discarding warranted
//! content is a reportable failure, so the buffer is deep, every drop is counted and surfaced, and
//! the delivered stream stays a **contiguous prefix**: when the buffer is full the engine discards
//! the *arriving* packet rather than evicting a buffered one, so the gap is one contiguous range
//! the controller can report as a single destination-level failure. The media path is never
//! blocked — protecting other calls' audio wins if the choice is forced — but the loss is loud.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use siphon_rtp_li::attributes::{AttributeWriter, IP_PROTOCOL_UDP};
use siphon_rtp_li::clock::WallClockAnchor;
use siphon_rtp_li::inbound::InboundHeader;
use siphon_rtp_li::{encode, PayloadDirection, PduHeader};
use siphon_rtp_proto::Xid;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// How long to wait before the first reconnect attempt after the delivery connection drops.
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_millis(250);
/// Ceiling on the reconnect backoff. A Mediation Function outage is measured in minutes, and the
/// buffer is what covers it; retrying faster than this only burns connections.
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// How often the delivery task checks whether the drop counter moved, to emit a loss report.
const LOSS_REPORT_INTERVAL: Duration = Duration::from_secs(5);

/// Operator configuration for X3 delivery. Node-level rather than per-call: the PKI material and
/// the network-element identity belong to the deployment, not to a warrant.
///
/// Its presence is what makes [`crate::engine::Engine`] able to accept an interception at all — an
/// `attach_x3` on a daemon without this configured is **refused**, never accepted and left inert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X3Config {
    /// PEM certificate chain the engine presents to the Mediation Function.
    pub client_cert: PathBuf,
    /// PEM private key for `client_cert`.
    pub client_key: PathBuf,
    /// PEM certificate(s) of the CA that signs the Mediation Function's certificate. The PKI is
    /// private, so the public Mozilla bundle the WebSocket client uses would never contain it.
    pub ca: PathBuf,
    /// Network Function ID (conditional attribute 6) — which network element produced the PDU.
    pub network_function_id: String,
    /// Interception Point ID (conditional attribute 7) — where in that element the tap sits.
    pub interception_point_id: String,
    /// How many intercepted packets to buffer per interception before dropping. At a 20 ms ptime,
    /// 20000 packets is roughly 400 seconds of one direction, or 200 of both.
    pub buffer_packets: usize,
    /// How long the delivery connection may sit idle before a keepalive PDU is sent.
    pub keepalive: Duration,
}

impl Default for X3Config {
    fn default() -> Self {
        Self {
            client_cert: PathBuf::new(),
            client_key: PathBuf::new(),
            ca: PathBuf::new(),
            network_function_id: String::new(),
            interception_point_id: String::new(),
            buffer_packets: 20_000,
            keepalive: Duration::from_secs(30),
        }
    }
}

/// What went wrong standing up or running X3 delivery.
#[derive(Debug, thiserror::Error)]
pub enum X3Error {
    /// The daemon has no `x3_*` configuration, so an interception cannot be accepted.
    #[error(
        "lawful interception is not configured on this node (x3_client_cert / x3_client_key / \
         x3_ca); refusing rather than accepting an intercept that would deliver nowhere"
    )]
    NotConfigured,
    /// A PEM file could not be read or contained nothing usable.
    #[error("{path}: {reason}")]
    Pem {
        /// The file that failed.
        path: PathBuf,
        /// What was wrong with it.
        reason: String,
    },
    /// rustls rejected the assembled client configuration (for example a key that does not match
    /// the certificate).
    #[error("X3 delivery TLS configuration: {0}")]
    Tls(String),
    /// The delivery address is not a resolvable `host:port`.
    #[error("X3 delivery address {address}: {reason}")]
    Address {
        /// The address as configured.
        address: String,
        /// Why it could not be used.
        reason: String,
    },
}

/// One intercepted packet on its way to the Mediation Function.
///
/// `payload` is an owned buffer rather than a `Bytes` because the delivery task hands it back to
/// the tap for reuse, so a steady interception allocates nothing per packet.
#[derive(Debug)]
pub struct X3Packet {
    /// The peer's observed source address, post source-gate.
    pub source: SocketAddr,
    /// The engine endpoint the packet arrived on.
    pub destination: SocketAddr,
    /// Datapath receive-clock reading, microseconds. Resolved to absolute time by the delivery
    /// task's [`WallClockAnchor`] — it is a relative timeline on its own.
    pub arrival_micros: u64,
    /// Target-relative direction, decided when the tap was installed.
    pub direction: PayloadDirection,
    /// The accepted, decrypted RTP packet.
    pub payload: Vec<u8>,
}

/// Delivery counters, shared between the media-path taps and the delivery task.
#[derive(Debug, Default)]
pub struct X3Counters {
    delivered: AtomicU64,
    dropped: AtomicU64,
}

impl X3Counters {
    /// Packets handed to the delivery transport.
    pub fn delivered(&self) -> u64 {
        self.delivered.load(Ordering::Relaxed)
    }

    /// Packets dropped because the buffer was full. Non-zero means warranted content did not reach
    /// the agency.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// The media-path handle: one per tapped direction, holding everything the tap needs so the hot
/// path neither looks anything up nor branches on policy.
///
/// Cheap to clone (three `Arc`-like handles and two `Copy` fields).
#[derive(Debug, Clone)]
pub struct X3Tap {
    packets: flume::Sender<X3Packet>,
    /// Buffers coming back from the delivery task, ready to be refilled.
    recycle_receiver: flume::Receiver<Vec<u8>>,
    /// The same pool's sending end, so a packet the buffer had to drop returns its allocation
    /// instead of freeing it — a sustained outage must not also churn the allocator.
    recycle_sender: flume::Sender<Vec<u8>>,
    destination: SocketAddr,
    direction: PayloadDirection,
    counters: Arc<X3Counters>,
}

impl X3Tap {
    /// Deliver one **accepted, decrypted** packet.
    ///
    /// Call sites are responsible for the two properties this cannot check: that `data` is
    /// plaintext, and that the engine has already accepted it (source gate passed, SRTP
    /// authenticated). Everything else is here.
    ///
    /// RTCP is skipped: a PDU declares payload format 8, "RTP packet", and the RFC 5761 demux byte
    /// is what separates the two on a muxed endpoint.
    ///
    /// Never blocks and never allocates on a steady interception — the buffer comes back from the
    /// delivery task through the recycle channel. On a full buffer the *arriving* packet is
    /// discarded, keeping what has been delivered a contiguous prefix, and the drop is counted.
    pub fn deliver(&self, source: SocketAddr, arrival_micros: u64, data: &[u8]) {
        if data.len() < 2 {
            return;
        }
        // RFC 5761 §4: payload type 64..=95 marks RTCP on a muxed endpoint.
        let packet_type = data[1] & 0x7f;
        if (64..=95).contains(&packet_type) {
            return;
        }
        let mut payload = self.recycle_receiver.try_recv().unwrap_or_default();
        payload.clear();
        payload.extend_from_slice(data);
        let packet = X3Packet {
            source,
            destination: self.destination,
            arrival_micros,
            direction: self.direction,
            payload,
        };
        if let Err(returned) = self.packets.try_send(packet) {
            // Put the buffer back so a sustained outage does not also churn the allocator. A full
            // pool simply frees it.
            let _ = self.recycle_sender.try_send(returned.into_inner().payload);
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The counters this tap feeds (test/observability helper).
    #[must_use]
    pub fn counters(&self) -> &Arc<X3Counters> {
        &self.counters
    }
}

/// Builds the per-direction [`X3Tap`]s for one interception. Each tap carries its own engine-local
/// address and its own target-relative direction, both fixed at install time so the media path does
/// no work to decide them.
#[derive(Debug, Clone)]
pub struct X3TapFactory {
    packets: flume::Sender<X3Packet>,
    recycle_receiver: flume::Receiver<Vec<u8>>,
    recycle_sender: flume::Sender<Vec<u8>>,
    counters: Arc<X3Counters>,
}

impl X3TapFactory {
    /// A tap for one direction: packets arriving on `destination` are delivered with `direction`.
    #[must_use]
    pub fn tap(&self, destination: SocketAddr, direction: PayloadDirection) -> X3Tap {
        X3Tap {
            packets: self.packets.clone(),
            recycle_receiver: self.recycle_receiver.clone(),
            recycle_sender: self.recycle_sender.clone(),
            destination,
            direction,
            counters: self.counters.clone(),
        }
    }

    /// The shared counters, so the engine can report delivery totals when the interception ends.
    #[must_use]
    pub fn counters(&self) -> &Arc<X3Counters> {
        &self.counters
    }
}

/// The delivery-task end of an interception: intercepted packets in, recycled buffers out.
#[derive(Debug)]
pub struct X3Delivery {
    /// Intercepted packets, in arrival order.
    pub packets: flume::Receiver<X3Packet>,
    /// Buffers returned to the taps after framing.
    pub recycle: flume::Sender<Vec<u8>>,
    /// Shared delivery counters.
    pub counters: Arc<X3Counters>,
}

/// Create the bounded channel pair for one interception.
///
/// `buffer_packets` bounds the packet queue. The recycle pool is bounded at the same size, so it
/// can never hold more buffers than were in flight.
#[must_use]
pub fn x3_channel(buffer_packets: usize) -> (X3TapFactory, X3Delivery) {
    let capacity = buffer_packets.max(1);
    let (packet_sender, packet_receiver) = flume::bounded(capacity);
    let (recycle_sender, recycle_receiver) = flume::bounded(capacity);
    let counters = Arc::new(X3Counters::default());
    (
        X3TapFactory {
            packets: packet_sender,
            recycle_receiver,
            recycle_sender: recycle_sender.clone(),
            counters: counters.clone(),
        },
        X3Delivery {
            packets: packet_receiver,
            recycle: recycle_sender,
            counters,
        },
    )
}

/// Which target-relative direction each leg's **ingress** carries, given the leg the warrant names.
///
/// The mapping is the whole reason `target_leg` is a required input (TS 103 221-2 §5.2.6). With the
/// target on leg A: A's ingress is what the target sent (3, from the target) and B's ingress is what
/// the far end sent (2, to the target). Both ingress taps together cover both directions, so no
/// egress tap is needed — a fact worth stating because it is not obvious from the pipeline shape.
///
/// Returns `(leg A ingress direction, leg B ingress direction)`.
#[must_use]
pub fn ingress_directions(target_is_caller: bool) -> (PayloadDirection, PayloadDirection) {
    if target_is_caller {
        (PayloadDirection::FromTarget, PayloadDirection::ToTarget)
    } else {
        (PayloadDirection::ToTarget, PayloadDirection::FromTarget)
    }
}

/// Build the ring-backed rustls client configuration for X3 delivery.
///
/// Deliberately *not* the WebSocket bridge's client config, which is `with_no_client_auth()` over
/// the Mozilla CA bundle and is wrong here on both counts: the Mediation Function authenticates the
/// network element by certificate, and its own certificate is signed by a private CA the public
/// bundle does not contain.
///
/// TLS 1.3 preferred, 1.2 accepted; ring only, per the project's zero-C rule.
///
/// # Errors
///
/// [`X3Error::Pem`] if a file is unreadable or empty of the object it should hold;
/// [`X3Error::Tls`] if rustls rejects the assembled configuration.
pub fn build_tls_client_config(config: &X3Config) -> Result<Arc<rustls::ClientConfig>, X3Error> {
    siphon_rtp_turn::tls::install_crypto_provider();

    let mut roots = rustls::RootCertStore::empty();
    let ca_certs = load_certs(&config.ca)?;
    if ca_certs.is_empty() {
        return Err(X3Error::Pem {
            path: config.ca.clone(),
            reason: "no CA certificates".to_string(),
        });
    }
    for certificate in ca_certs {
        roots.add(certificate).map_err(|error| X3Error::Pem {
            path: config.ca.clone(),
            reason: error.to_string(),
        })?;
    }

    let client_certs = load_certs(&config.client_cert)?;
    if client_certs.is_empty() {
        return Err(X3Error::Pem {
            path: config.client_cert.clone(),
            reason: "no certificates".to_string(),
        });
    }
    let key = load_key(&config.client_key)?;

    let client_config = rustls::ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_root_certificates(roots)
    .with_client_auth_cert(client_certs, key)
    .map_err(|error| X3Error::Tls(error.to_string()))?;
    Ok(Arc::new(client_config))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, X3Error> {
    let bytes = std::fs::read(path).map_err(|error| X3Error::Pem {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })?;
    CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| X3Error::Pem {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, X3Error> {
    let bytes = std::fs::read(path).map_err(|error| X3Error::Pem {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })?;
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|error| X3Error::Pem {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

/// Split a `host:port` delivery address into its parts, keeping the host as written so TLS verifies
/// the certificate against the configured name rather than against a resolved address.
///
/// # Errors
///
/// [`X3Error::Address`] if there is no port, or the host is not a valid DNS name or IP literal.
pub fn split_delivery_address(address: &str) -> Result<(ServerName<'static>, String), X3Error> {
    let (host, port) = address.rsplit_once(':').ok_or_else(|| X3Error::Address {
        address: address.to_string(),
        reason: "expected host:port".to_string(),
    })?;
    // An IPv6 literal is bracketed in a host:port string; the brackets are not part of the name.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if port.parse::<u16>().is_err() {
        return Err(X3Error::Address {
            address: address.to_string(),
            reason: "port is not a number".to_string(),
        });
    }
    let server_name = ServerName::try_from(host.to_string()).map_err(|error| X3Error::Address {
        address: address.to_string(),
        reason: error.to_string(),
    })?;
    Ok((server_name, address.to_string()))
}

/// Everything one interception's delivery task needs.
pub struct X3DeliveryTask {
    /// The buffered packet stream and its counters.
    pub delivery: X3Delivery,
    /// Where the Mediation Function listens, as `host:port`.
    pub address: String,
    /// The interception task identifier, copied into every PDU.
    pub xid: Xid,
    /// The session correlation, copied into every PDU.
    pub correlation_id: u64,
    /// Network Function ID (attribute 6).
    pub network_function_id: String,
    /// Interception Point ID (attribute 7).
    pub interception_point_id: String,
    /// Idle keepalive period.
    pub keepalive: Duration,
    /// The ring-backed mutual-TLS client configuration.
    pub tls: Arc<rustls::ClientConfig>,
}

/// Why a delivery task stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X3DeliveryEnd {
    /// The tap side went away — the interception was detached or the call ended.
    SourceClosed,
    /// The Mediation Function closed the connection and it could not be re-established.
    MediationClosed,
}

/// Run one interception's delivery connection until the tap side closes.
///
/// Reconnects with backoff, holding the buffer across an outage rather than discarding through it,
/// and sends a keepalive PDU (type 3) when the connection has been idle. `on_loss` is called with
/// `(dropped, delivered)` when the drop counter has moved since the last report, so the caller can
/// raise a destination-level report.
pub async fn run_x3_delivery<F>(task: X3DeliveryTask, mut on_loss: F) -> X3DeliveryEnd
where
    F: FnMut(u64, u64) + Send,
{
    let mut backoff = RECONNECT_BACKOFF_MIN;
    let mut reported_drops = 0u64;
    // The wall-clock anchor is taken once, on the first intercepted packet, and reused for the whole
    // interception — including across reconnects. Re-anchoring would let a wall-clock step reorder
    // delivered timestamps.
    let mut anchor: Option<WallClockAnchor> = None;
    // Held across a failed connection so a packet already taken off the queue is not lost.
    let mut pending: Option<X3Packet> = None;

    loop {
        if task.delivery.packets.is_disconnected() && task.delivery.packets.is_empty() {
            return X3DeliveryEnd::SourceClosed;
        }
        let stream = match connect(&task).await {
            Ok(stream) => {
                backoff = RECONNECT_BACKOFF_MIN;
                stream
            }
            Err(error) => {
                tracing::warn!(
                    target: "siphon_rtp::li",
                    address = %task.address,
                    %error,
                    backoff_ms = backoff.as_millis() as u64,
                    "X3 delivery connect failed; buffering"
                );
                // Report loss that accumulated while disconnected, then wait.
                report_loss(&task, &mut reported_drops, &mut on_loss);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
                continue;
            }
        };
        tracing::info!(
            target: "siphon_rtp::li",
            address = %task.address,
            "X3 delivery connected"
        );

        match serve_connection(
            &task,
            stream,
            &mut anchor,
            &mut pending,
            &mut reported_drops,
            &mut on_loss,
        )
        .await
        {
            ConnectionEnd::SourceClosed => return X3DeliveryEnd::SourceClosed,
            ConnectionEnd::Reconnect => {
                tracing::warn!(
                    target: "siphon_rtp::li",
                    address = %task.address,
                    "X3 delivery connection lost; buffering and reconnecting"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
            }
        }
    }
}

/// Why one connection attempt ended.
enum ConnectionEnd {
    /// The tap side closed — the whole task is done.
    SourceClosed,
    /// The connection failed; the buffer is intact and should be redelivered.
    Reconnect,
}

/// Dial the Mediation Function and complete the mutual-TLS handshake.
async fn connect(
    task: &X3DeliveryTask,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let (server_name, address) =
        split_delivery_address(&task.address).map_err(|error| error.to_string())?;
    let tcp = TcpStream::connect(&address)
        .await
        .map_err(|error| format!("connect {address}: {error}"))?;
    // Media delivery is a steady stream of small PDUs; Nagle would batch them into added latency.
    let _ = tcp.set_nodelay(true);
    let connector = TlsConnector::from(task.tls.clone());
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|error| format!("TLS handshake with {address}: {error}"))
}

/// Drain the buffer onto one live connection until it fails or the taps go away.
async fn serve_connection<F>(
    task: &X3DeliveryTask,
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    anchor: &mut Option<WallClockAnchor>,
    pending: &mut Option<X3Packet>,
    reported_drops: &mut u64,
    on_loss: &mut F,
) -> ConnectionEnd
where
    F: FnMut(u64, u64) + Send,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    // Read and discard whatever the peer sends (keepalive acknowledgements). The socket must be
    // drained or the peer's writes eventually block; the header parse is there so a malformed or
    // hostile length can be recognised rather than silently desynchronising a future reader.
    let mut inbound = [0u8; 1024];

    // Per-connection sequence number (TS 103 221-2 attribute 8), reset on every new connection and
    // allowed to wrap at 2^32.
    let mut sequence: u32 = 0;
    let mut attributes = Vec::with_capacity(256);
    let mut pdu = Vec::with_capacity(2048);

    let mut keepalive = tokio::time::interval(task.keepalive);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick completes immediately; consume it so a fresh connection does not open with a
    // keepalive.
    keepalive.tick().await;
    let mut loss_report = tokio::time::interval(LOSS_REPORT_INTERVAL);
    loss_report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loss_report.tick().await;

    loop {
        // A packet held from a previous failed connection is redelivered before anything new is
        // taken off the queue, so a reconnect does not reorder the stream.
        let packet = match pending.take() {
            Some(packet) => Some(packet),
            None => {
                // Deliberately **not** `biased`. Biased polling would take the packet arm first on
                // every iteration, and a backed-up buffer keeps that arm permanently ready — which
                // is precisely the condition that causes loss. The loss-report arm would then never
                // be polled and `x3_loss` would never fire exactly when it is needed, and the
                // inbound socket would never be drained. Random selection gives every ready arm a
                // fair turn, so a fired timer wins within a packet or two.
                tokio::select! {
                    received = task.delivery.packets.recv_async() => match received {
                        Ok(packet) => Some(packet),
                        // Every tap has been dropped and the buffer is drained.
                        Err(_) => return ConnectionEnd::SourceClosed,
                    },
                    _ = keepalive.tick() => None,
                    _ = loss_report.tick() => {
                        report_loss(task, reported_drops, on_loss);
                        continue;
                    }
                    read = reader.read(&mut inbound) => {
                        match read {
                            // The Mediation Function closed the connection.
                            Ok(0) => return ConnectionEnd::Reconnect,
                            Ok(length) => {
                                note_inbound(&inbound[..length]);
                                continue;
                            }
                            Err(_) => return ConnectionEnd::Reconnect,
                        }
                    }
                }
            }
        };

        let Some(packet) = packet else {
            // Keepalive tick with nothing to send.
            if encode(&PduHeader::keepalive(), &[], &[], &mut pdu).is_ok()
                && writer.write_all(&pdu).await.is_err()
            {
                return ConnectionEnd::Reconnect;
            }
            continue;
        };

        // Anchor the wall clock to the first intercepted packet, so every delivered timestamp is
        // absolute while the spacing between them comes from the datapath receive clock.
        let clock =
            *anchor.get_or_insert_with(|| WallClockAnchor::anchored_now(packet.arrival_micros));
        let (seconds, nanoseconds) = clock.timestamp(packet.arrival_micros);

        AttributeWriter::new(&mut attributes)
            .network_function_id(&task.network_function_id)
            .interception_point_id(&task.interception_point_id)
            .sequence_number(sequence)
            .timestamp(seconds, nanoseconds)
            .source(packet.source)
            .destination(packet.destination)
            .ip_protocol(IP_PROTOCOL_UDP);

        let header = PduHeader::x3_rtp(*task.xid.as_bytes(), task.correlation_id, packet.direction);
        if let Err(error) = encode(&header, &attributes, &packet.payload, &mut pdu) {
            // The only reachable case is a zero Correlation ID, which `attach_x3` refuses up front.
            // Log and drop this packet rather than spinning on it forever.
            tracing::error!(
                target: "siphon_rtp::li",
                %error,
                "X3 framing failed; dropping the packet"
            );
            let _ = task.delivery.recycle.try_send(packet.payload);
            continue;
        }

        if writer.write_all(&pdu).await.is_err() {
            // Keep the packet: it is redelivered on the next connection rather than lost.
            *pending = Some(packet);
            return ConnectionEnd::Reconnect;
        }
        sequence = sequence.wrapping_add(1);
        task.delivery
            .counters
            .delivered
            .fetch_add(1, Ordering::Relaxed);
        // Hand the buffer back for reuse. A full pool just drops it.
        let _ = task.delivery.recycle.try_send(packet.payload);
    }
}

/// Log what the Mediation Function sent back. Only keepalive acknowledgements are expected; anything
/// else is noted once rather than acted on, because the delivery direction is ours.
fn note_inbound(bytes: &[u8]) {
    match InboundHeader::parse(bytes) {
        Ok(header) if header.is_keepalive_acknowledgement() => {
            tracing::trace!(target: "siphon_rtp::li", "X3 keepalive acknowledged");
        }
        Ok(header) => {
            tracing::debug!(
                target: "siphon_rtp::li",
                pdu_type = header.pdu_type,
                "X3 delivery peer sent an unexpected PDU type"
            );
        }
        Err(error) => {
            tracing::debug!(
                target: "siphon_rtp::li",
                %error,
                "X3 delivery peer sent an unreadable PDU header"
            );
        }
    }
}

/// Emit a loss report if the drop counter moved since the last one.
fn report_loss<F>(task: &X3DeliveryTask, reported: &mut u64, on_loss: &mut F)
where
    F: FnMut(u64, u64),
{
    let dropped = task.delivery.counters.dropped();
    if dropped > *reported {
        let delivered = task.delivery.counters.delivered();
        tracing::warn!(
            target: "siphon_rtp::li",
            address = %task.address,
            dropped,
            delivered,
            "X3 delivery dropped warranted content — the buffer filled"
        );
        *reported = dropped;
        on_loss(dropped, delivered);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn address(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), port)
    }

    /// A minimal RTP packet: version 2, PT 0, then a payload.
    fn rtp(sequence: u16) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x40, 0xde, 0xad, 0xbe, 0xef]);
        packet.extend_from_slice(&[0xd5; 160]);
        packet
    }

    /// A minimal RTCP sender report: PT 200, which is inside the RFC 5761 demux range.
    fn rtcp() -> Vec<u8> {
        vec![0x80, 200, 0x00, 0x06, 0xde, 0xad, 0xbe, 0xef]
    }

    #[test]
    fn the_target_leg_decides_which_direction_each_leg_carries() {
        // §5.2.6 is target-relative. With the target on leg A, A's ingress is what the target sent.
        let (leg_a, leg_b) = ingress_directions(true);
        assert_eq!(leg_a, PayloadDirection::FromTarget);
        assert_eq!(leg_b, PayloadDirection::ToTarget);

        // Target on leg B inverts both.
        let (leg_a, leg_b) = ingress_directions(false);
        assert_eq!(leg_a, PayloadDirection::ToTarget);
        assert_eq!(leg_b, PayloadDirection::FromTarget);
    }

    #[test]
    fn a_tap_delivers_rtp_with_its_installed_direction_and_destination() {
        let (factory, delivery) = x3_channel(8);
        let local = address(20000);
        let tap = factory.tap(local, PayloadDirection::FromTarget);

        tap.deliver(address(16384), 1_000, &rtp(1));

        let packet = delivery.packets.try_recv().expect("a delivered packet");
        assert_eq!(packet.source, address(16384));
        assert_eq!(packet.destination, local);
        assert_eq!(packet.direction, PayloadDirection::FromTarget);
        assert_eq!(packet.arrival_micros, 1_000);
        assert_eq!(packet.payload, rtp(1));
    }

    #[test]
    fn a_tap_skips_rtcp() {
        // A PDU declares payload format 8 ("RTP packet"), so RTCP on a muxed endpoint must not be
        // delivered as one.
        let (factory, delivery) = x3_channel(8);
        let tap = factory.tap(address(20000), PayloadDirection::ToTarget);

        tap.deliver(address(16384), 0, &rtcp());
        assert!(
            delivery.packets.try_recv().is_err(),
            "RTCP must not be delivered"
        );

        tap.deliver(address(16384), 0, &rtp(1));
        assert!(
            delivery.packets.try_recv().is_ok(),
            "RTP must still be delivered"
        );
    }

    #[test]
    fn a_tap_ignores_a_runt_datagram() {
        let (factory, delivery) = x3_channel(8);
        let tap = factory.tap(address(20000), PayloadDirection::ToTarget);
        for runt in [vec![], vec![0x80]] {
            tap.deliver(address(16384), 0, &runt);
        }
        assert!(delivery.packets.try_recv().is_err());
    }

    #[test]
    fn two_taps_share_one_ordered_stream_and_one_set_of_counters() {
        // Both legs feed one delivery connection, and the Mediation Function sees them interleaved
        // in arrival order — which is what makes a single per-connection sequence number meaningful.
        let (factory, delivery) = x3_channel(8);
        let caller = factory.tap(address(20000), PayloadDirection::FromTarget);
        let callee = factory.tap(address(20002), PayloadDirection::ToTarget);

        caller.deliver(address(16384), 0, &rtp(1));
        callee.deliver(address(16386), 20_000, &rtp(100));
        caller.deliver(address(16384), 20_000, &rtp(2));

        let directions: Vec<_> = (0..3)
            .map(|_| delivery.packets.try_recv().expect("packet").direction)
            .collect();
        assert_eq!(
            directions,
            vec![
                PayloadDirection::FromTarget,
                PayloadDirection::ToTarget,
                PayloadDirection::FromTarget
            ]
        );
        assert!(Arc::ptr_eq(caller.counters(), callee.counters()));
    }

    #[test]
    fn a_full_buffer_drops_the_arriving_packet_and_keeps_a_contiguous_prefix() {
        // The loss policy, and the reason it is not the pcap recorder's: what has been buffered is
        // already-warranted content, so the newest packet is discarded rather than the oldest. The
        // delivered stream stays a contiguous prefix and the gap is one reportable range.
        let (factory, delivery) = x3_channel(3);
        let tap = factory.tap(address(20000), PayloadDirection::FromTarget);

        for sequence in 1..=3 {
            tap.deliver(address(16384), 0, &rtp(sequence));
        }
        assert_eq!(tap.counters().dropped(), 0);

        for sequence in 4..=6 {
            tap.deliver(address(16384), 0, &rtp(sequence));
        }
        assert_eq!(
            tap.counters().dropped(),
            3,
            "every over-cap packet is counted"
        );

        // What survived is the first three, in order — not the last three.
        let delivered: Vec<u16> = (0..3)
            .map(|_| {
                let packet = delivery.packets.try_recv().expect("packet");
                u16::from_be_bytes([packet.payload[2], packet.payload[3]])
            })
            .collect();
        assert_eq!(delivered, vec![1, 2, 3]);
    }

    #[test]
    fn the_media_path_never_blocks_on_a_stalled_mediation_function() {
        // Nothing drains the channel here. Every call must still return.
        let (factory, _delivery) = x3_channel(2);
        let tap = factory.tap(address(20000), PayloadDirection::FromTarget);
        for sequence in 0..1000 {
            tap.deliver(address(16384), 0, &rtp(sequence));
        }
        assert_eq!(tap.counters().dropped(), 998);
    }

    #[test]
    fn buffers_are_recycled_rather_than_reallocated() {
        let (factory, delivery) = x3_channel(4);
        let tap = factory.tap(address(20000), PayloadDirection::FromTarget);

        tap.deliver(address(16384), 0, &rtp(1));
        let packet = delivery.packets.try_recv().expect("packet");
        let capacity = packet.payload.capacity();
        let pointer = packet.payload.as_ptr();
        delivery.recycle.try_send(packet.payload).expect("recycle");

        tap.deliver(address(16384), 0, &rtp(2));
        let next = delivery.packets.try_recv().expect("packet");
        assert_eq!(next.payload.capacity(), capacity);
        assert_eq!(next.payload.as_ptr(), pointer, "the buffer must be reused");
    }

    #[test]
    fn counters_start_at_zero_and_only_move_on_delivery_or_loss() {
        let (factory, _delivery) = x3_channel(1);
        assert_eq!(factory.counters().delivered(), 0);
        assert_eq!(factory.counters().dropped(), 0);
    }

    #[test]
    fn splits_a_delivery_address_keeping_the_host_for_certificate_verification() {
        let (name, address) = split_delivery_address("mdf.example.net:8090").expect("host:port");
        assert_eq!(address, "mdf.example.net:8090");
        assert!(matches!(name, ServerName::DnsName(_)));

        let (name, _) = split_delivery_address("203.0.113.9:8090").expect("ip:port");
        assert!(matches!(name, ServerName::IpAddress(_)));

        let (name, _) = split_delivery_address("[2001:db8::1]:8090").expect("v6");
        assert!(matches!(name, ServerName::IpAddress(_)));
    }

    #[test]
    fn refuses_a_delivery_address_that_is_not_host_and_port() {
        for bad in [
            "mdf.example.net",
            "mdf.example.net:http",
            "mdf.example.net:99999",
        ] {
            assert!(
                split_delivery_address(bad).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn a_missing_pem_file_is_an_error_naming_the_path() {
        let config = X3Config {
            ca: PathBuf::from("/nonexistent/x3-ca.pem"),
            client_cert: PathBuf::from("/nonexistent/x3-client.pem"),
            client_key: PathBuf::from("/nonexistent/x3-client.key"),
            ..X3Config::default()
        };
        let error = build_tls_client_config(&config).expect_err("must fail");
        assert!(error.to_string().contains("x3-ca.pem"), "{error}");
    }

    #[test]
    fn the_not_configured_error_says_why_it_refuses() {
        // The failure mode this message exists to prevent: an intercept that looks accepted and
        // delivers nowhere.
        let message = X3Error::NotConfigured.to_string();
        assert!(message.contains("x3_client_cert"), "{message}");
        assert!(message.contains("refusing"), "{message}");
    }
}
