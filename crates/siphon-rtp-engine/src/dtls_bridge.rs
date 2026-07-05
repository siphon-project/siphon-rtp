//! The userspace DTLS-SRTP bridge — the `Redirect` slow path for a leg keyed by a DTLS handshake
//! (RFC 5764) rather than SDES. It bridges an insecure (`RTP/AVP`) leg to a DTLS-secured
//! (`UDP/TLS/RTP/SAVPF`) leg, e.g. a WebRTC browser bridged to a PSTN side.
//!
//! Structurally it is the [`crate::srtp_bridge::SrtpBridge`] with a handshake in front. On register,
//! a task drives the DTLS handshake ([`siphon_rtp_dtls::handshake`]) over the datapath's `Redirect`
//! path: inbound DTLS records (the ones the RFC 7983 demux classifies [`PacketClass::Dtls`]) are fed
//! to it and outbound records are sent via [`Datapath::send`]. Until the handshake completes there is
//! no [`SecureLeg`], so media is dropped; once it does, both directions relay exactly as the SDES
//! bridge — plain→secure `protect`s, secure→plain `unprotect`s. Because `Redirect` bypasses the
//! datapath's source gate, the bridge re-enforces it (RTPBleed defence) before any crypto.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use dashmap::DashMap;
use siphon_rtp_datapath::{classify, Datapath, EndpointId, PacketClass, RxPacket, SourceFilter};
use siphon_rtp_dtls::{handshake, DtlsCertificate, DtlsRole, DtlsTransport, Fingerprint};
use siphon_rtp_srtp::leg::SecureLeg;
use tokio::task::JoinHandle;

/// A shared secure leg that is `None` until the DTLS handshake installs it.
type SharedSecureLeg = Arc<Mutex<Option<SecureLeg>>>;

/// Which direction of the bridge a redirected endpoint carries.
#[derive(Clone)]
enum Direction {
    /// Plain ingress → encrypt (`SecureLeg::protect`) for the DTLS peer, once keyed.
    Encrypt,
    /// DTLS-peer ingress → feed DTLS records to the handshake, or `unprotect` SRTP media for the
    /// plain peer once keyed.
    Decrypt {
        /// Sends inbound DTLS records to the handshake task.
        dtls_in: flume::Sender<Bytes>,
    },
}

/// One redirected endpoint's flow: how to gate it, which crypto direction, and where to forward.
struct Flow {
    direction: Direction,
    accepted_source: SourceFilter,
    out_endpoint: EndpointId,
    out_dst: SocketAddr,
    /// Shared with the call's other direction; `None` until the handshake completes.
    secure: SharedSecureLeg,
}

/// A whole call's DTLS-SRTP bridge plan: the two endpoint flows plus the handshake parameters.
pub struct DtlsCallPlan {
    /// The insecure endpoint (plaintext RTP in, SRTP out to the DTLS peer).
    pub plain_endpoint: EndpointId,
    /// Signalled-source gate for the insecure endpoint.
    pub plain_source: SourceFilter,
    /// The plain peer's address (decrypted media is forwarded here).
    pub plain_dst: SocketAddr,
    /// The DTLS-secured endpoint (DTLS + SRTP in, plaintext RTP out to the plain peer).
    pub secure_endpoint: EndpointId,
    /// Signalled-source gate for the secure endpoint.
    pub secure_source: SourceFilter,
    /// The DTLS peer's address (encrypted media + DTLS records are sent here).
    pub secure_dst: SocketAddr,
    /// The secure endpoint's own local address (for the DTLS transport's `local_addr`).
    pub secure_local: SocketAddr,
    /// The engine's DTLS certificate (shared across calls).
    pub certificate: DtlsCertificate,
    /// The engine's DTLS role (from `a=setup`) — normally [`DtlsRole::Server`].
    pub role: DtlsRole,
    /// The DTLS peer's certificate fingerprint (from its SDP `a=fingerprint`), verified per RFC 5763 §5.
    pub peer_fingerprint: Fingerprint,
}

/// The DTLS bridge registry: redirected endpoint → its `Flow`, plus the per-call handshake/drain
/// tasks keyed by the secure endpoint (aborted on deregister). Shared (`Arc`) between the control path
/// and the redirect dispatcher.
pub struct DtlsBridge<D: Datapath> {
    datapath: D,
    flows: DashMap<EndpointId, Flow>,
    sessions: DashMap<EndpointId, Vec<JoinHandle<()>>>,
}

impl<D: Datapath + Clone + 'static> DtlsBridge<D> {
    /// Create an empty bridge over `datapath` (a clone of the engine's datapath, used to transmit).
    #[must_use]
    pub fn new(datapath: D) -> Self {
        Self {
            datapath,
            flows: DashMap::new(),
            sessions: DashMap::new(),
        }
    }

    /// Register a call's DTLS-SRTP bridge: install the two endpoint flows and spawn the handshake +
    /// outbound-record drain tasks. The caller installs `FlowAction::Redirect` on both endpoints and
    /// tears them down on delete via [`Self::deregister`].
    pub fn register(&self, plan: DtlsCallPlan) {
        let secure: SharedSecureLeg = Arc::new(Mutex::new(None));
        let (transport, channels) = DtlsTransport::new(plan.secure_local, plan.secure_dst);
        let dtls_in = channels.inbound;

        // Drain outbound DTLS records to the peer via the secure endpoint. Ends when the transport is
        // dropped (post-handshake) or the session is aborted.
        let drain = {
            let datapath = self.datapath.clone();
            let outbound = channels.outbound;
            let secure_endpoint = plan.secure_endpoint;
            let secure_dst = plan.secure_dst;
            tokio::spawn(async move {
                while let Ok(record) = outbound.recv_async().await {
                    if let Err(error) = datapath.send(secure_endpoint, secure_dst, &record).await {
                        tracing::debug!(%error, "DTLS record send failed");
                    }
                }
            })
        };

        // Drive the handshake; install the SecureLeg on success.
        let shake = {
            let secure = secure.clone();
            let certificate = plan.certificate;
            let role = plan.role;
            let peer_fingerprint = plan.peer_fingerprint;
            tokio::spawn(async move {
                match handshake(Arc::new(transport), &certificate, role, &peer_fingerprint).await {
                    Ok(leg) => {
                        if let Ok(mut guard) = secure.lock() {
                            *guard = Some(leg);
                        }
                        tracing::info!("DTLS-SRTP handshake complete; secure leg installed");
                    }
                    Err(error) => {
                        tracing::warn!(%error, "DTLS-SRTP handshake failed; media stays dropped");
                    }
                }
            })
        };

        self.flows.insert(
            plan.plain_endpoint,
            Flow {
                direction: Direction::Encrypt,
                accepted_source: plan.plain_source,
                out_endpoint: plan.secure_endpoint,
                out_dst: plan.secure_dst,
                secure: secure.clone(),
            },
        );
        self.flows.insert(
            plan.secure_endpoint,
            Flow {
                direction: Direction::Decrypt { dtls_in },
                accepted_source: plan.secure_source,
                out_endpoint: plan.plain_endpoint,
                out_dst: plan.plain_dst,
                secure,
            },
        );
        self.sessions
            .insert(plan.secure_endpoint, vec![drain, shake]);
    }

    /// Drop the flows for `endpoints` and abort their handshake/drain tasks — the bridge half of call
    /// teardown.
    pub fn deregister(&self, endpoints: impl IntoIterator<Item = EndpointId>) {
        for endpoint in endpoints {
            self.flows.remove(&endpoint);
            if let Some((_, tasks)) = self.sessions.remove(&endpoint) {
                for task in tasks {
                    task.abort();
                }
            }
        }
    }

    /// Whether this bridge owns `endpoint` — the dispatcher's routing predicate.
    #[must_use]
    pub fn owns(&self, endpoint: EndpointId) -> bool {
        self.flows.contains_key(&endpoint)
    }

    /// Handle one redirected datagram: gate the source, then either feed the DTLS handshake or apply
    /// the flow's SRTP crypto and forward it. Anything unkeyed, un-gated, or un-decryptable is dropped.
    pub async fn handle(&self, packet: RxPacket) {
        let Some((direction, accepted_source, out_endpoint, out_dst, secure)) =
            self.flows.get(&packet.endpoint).map(|flow| {
                (
                    flow.direction.clone(),
                    flow.accepted_source,
                    flow.out_endpoint,
                    flow.out_dst,
                    flow.secure.clone(),
                )
            })
        else {
            return; // not a DTLS-bridge endpoint
        };

        // RTPBleed gate: Redirect skips the datapath's source check, so re-enforce it here.
        if !accepted_source.accepts(packet.source.ip()) {
            tracing::debug!(source = %packet.source, "DTLS bridge dropped unsignalled source");
            return;
        }

        // On the secure endpoint a DTLS record drives the handshake, never SRTP crypto.
        if let Direction::Decrypt { dtls_in } = &direction {
            if classify(&packet.data) == PacketClass::Dtls {
                // Drop-newest on a full handshake mailbox → DTLS retransmits; never block the datapath.
                let _ = dtls_in.try_send(packet.data);
                return;
            }
        }

        // Media path: only relay RTP/RTCP, and only once the handshake has keyed the leg.
        if classify(&packet.data) != PacketClass::Media {
            return;
        }
        let mut out = Vec::new();
        let transformed = {
            let Ok(mut guard) = secure.lock() else {
                tracing::error!("DTLS secure-leg mutex poisoned; dropping packet");
                return;
            };
            let Some(leg) = guard.as_mut() else {
                return; // handshake not complete yet — no key, drop the media
            };
            match direction {
                Direction::Encrypt => leg.protect(&packet.data, &mut out),
                Direction::Decrypt { .. } => leg.unprotect(&packet.data, &mut out),
            }
        };
        if let Err(error) = transformed {
            tracing::debug!(?error, "DTLS bridge crypto failed; dropping packet");
            return;
        }
        if let Err(error) = self.datapath.send(out_endpoint, out_dst, &out).await {
            tracing::debug!(%error, "DTLS bridge forward send failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
    use siphon_rtp_datapath::FlowAction;
    use siphon_rtp_dtls::DtlsChannels;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
    const RECV_TIMEOUT: Duration = Duration::from_secs(2);

    fn rtp(seq: u16, ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(b"webrtc-media----");
        packet
    }

    /// Bridge B's socket to a DTLS transport: pump inbound datagrams in, outbound records out to
    /// `engine_secure`. Returns the transport plus the two pump tasks.
    fn pump(
        socket: Arc<UdpSocket>,
        channels: DtlsChannels,
        engine_secure: SocketAddr,
    ) -> (JoinHandle<()>, JoinHandle<()>) {
        let recv_socket = socket.clone();
        let inbound = channels.inbound;
        let reader = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            while let Ok((len, _)) = recv_socket.recv_from(&mut buffer).await {
                if inbound
                    .send_async(Bytes::copy_from_slice(&buffer[..len]))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let outbound = channels.outbound;
        let writer = tokio::spawn(async move {
            while let Ok(record) = outbound.recv_async().await {
                if socket.send_to(&record, engine_secure).await.is_err() {
                    break;
                }
            }
        });
        (reader, writer)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dtls_handshake_then_bidirectional_srtp_relay() {
        let datapath = UdpLoopbackDatapath::new();
        let plain = datapath.alloc_endpoint().await.expect("alloc plain");
        let secure = datapath.alloc_endpoint().await.expect("alloc secure");
        datapath
            .install_flow(plain.id, FlowAction::Redirect)
            .expect("redirect plain");
        datapath
            .install_flow(secure.id, FlowAction::Redirect)
            .expect("redirect secure");

        // Phone A (plain) and the WebRTC peer B (DTLS).
        let phone_a = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .expect("bind a");
        let addr_a = phone_a.local_addr().expect("addr a");
        let peer_b = Arc::new(
            UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
                .await
                .expect("bind b"),
        );
        let addr_b = peer_b.local_addr().expect("addr b");

        let engine_cert = DtlsCertificate::generate().expect("engine cert");
        let peer_cert = DtlsCertificate::generate().expect("peer cert");

        // Register the bridge: engine is the DTLS server; A↔B bridged through it.
        let bridge = Arc::new(DtlsBridge::new(datapath.clone()));
        bridge.register(DtlsCallPlan {
            plain_endpoint: plain.id,
            plain_source: SourceFilter::Exact(addr_a.ip()),
            plain_dst: addr_a,
            secure_endpoint: secure.id,
            secure_source: SourceFilter::Exact(addr_b.ip()),
            secure_dst: addr_b,
            secure_local: secure.local_addr,
            certificate: engine_cert.clone(),
            role: DtlsRole::Server,
            peer_fingerprint: peer_cert.fingerprint(),
        });

        // Dispatch the datapath's redirect stream into the bridge.
        let rx = datapath.rx();
        let dispatch = bridge.clone();
        tokio::spawn(async move {
            while let Ok(packet) = rx.recv_async().await {
                dispatch.handle(packet).await;
            }
        });

        // Drive B's side of the DTLS handshake (client) over its socket.
        let (b_transport, b_channels) = DtlsTransport::new(addr_b, secure.local_addr);
        let (b_reader, b_writer) = pump(peer_b.clone(), b_channels, secure.local_addr);
        let mut peer_leg = timeout(
            HANDSHAKE_TIMEOUT,
            handshake(
                Arc::new(b_transport),
                &peer_cert,
                DtlsRole::Client,
                &engine_cert.fingerprint(),
            ),
        )
        .await
        .expect("handshake did not time out")
        .expect("peer handshake");
        // The pump only carries the handshake; stop it so the test owns peer_b's socket for media.
        b_reader.abort();
        b_writer.abort();

        // B → engine: SRTP media, decrypted and relayed to phone A.
        // Retry to absorb the tiny window between B finishing and the engine installing its leg.
        let media = rtp(1000, 0x0B0B_0B0B);
        let mut sealed = Vec::new();
        let mut recovered_at_a = None;
        for _ in 0..25 {
            sealed.clear();
            peer_leg.protect(&media, &mut sealed).expect("peer protect");
            peer_b
                .send_to(&sealed, secure.local_addr)
                .await
                .expect("b send");
            let mut buffer = [0u8; 2048];
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
            {
                recovered_at_a = Some(buffer[..len].to_vec());
                break;
            }
        }
        assert_eq!(
            recovered_at_a.expect("phone A received the relayed media"),
            media,
            "B's SRTP is decrypted and relayed to A as plaintext"
        );

        // A → engine: plaintext RTP, encrypted and relayed to B as SRTP.
        let media_ab = rtp(2000, 0x0A0A_0A0A);
        phone_a
            .send_to(&media_ab, plain.local_addr)
            .await
            .expect("a send");
        let mut buffer = [0u8; 2048];
        let (len, _) = timeout(RECV_TIMEOUT, peer_b.recv_from(&mut buffer))
            .await
            .expect("b received something")
            .expect("b recv");
        let mut recovered = Vec::new();
        peer_leg
            .unprotect(&buffer[..len], &mut recovered)
            .expect("peer unprotect");
        assert_eq!(
            recovered, media_ab,
            "A's plaintext is encrypted and relayed to B as SRTP"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn media_is_dropped_before_the_handshake_completes() {
        let datapath = UdpLoopbackDatapath::new();
        let plain = datapath.alloc_endpoint().await.expect("alloc plain");
        let secure = datapath.alloc_endpoint().await.expect("alloc secure");
        let phone_a = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .expect("bind a");
        let addr_a = phone_a.local_addr().expect("addr a");
        let peer_b = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind b");
        let addr_b = peer_b.local_addr().expect("addr b");

        let bridge = DtlsBridge::new(datapath.clone());
        bridge.register(DtlsCallPlan {
            plain_endpoint: plain.id,
            plain_source: SourceFilter::Exact(addr_a.ip()),
            plain_dst: addr_a,
            secure_endpoint: secure.id,
            secure_source: SourceFilter::Exact(addr_b.ip()),
            secure_dst: addr_b,
            secure_local: secure.local_addr,
            certificate: DtlsCertificate::generate().expect("cert"),
            role: DtlsRole::Server,
            peer_fingerprint: DtlsCertificate::generate().expect("cert").fingerprint(),
        });

        // An SRTP-shaped packet from the signalled secure source, but no handshake has happened → the
        // leg is unkeyed → it must be dropped, never forwarded to A.
        let packet = RxPacket {
            endpoint: secure.id,
            source: addr_b,
            arrival: 0,
            data: Bytes::from(rtp(1, 0x1234)),
        };
        bridge.handle(packet).await;
        let mut buffer = [0u8; 2048];
        assert!(
            timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer))
                .await
                .is_err(),
            "media before the handshake must be dropped"
        );

        // owns() reflects registration; deregister aborts the tasks and stops owning.
        assert!(bridge.owns(secure.id) && bridge.owns(plain.id));
        bridge.deregister([plain.id, secure.id]);
        assert!(!bridge.owns(secure.id) && !bridge.owns(plain.id));
    }
}
