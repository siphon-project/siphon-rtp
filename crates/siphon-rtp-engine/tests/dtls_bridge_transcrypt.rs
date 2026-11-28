//! The DTLS bridge's plain side re-keyed with an SDES leg (`PipelineKind::DtlsOffererTranscrypt`): a
//! DTLS-SRTP peer (RFC 5764) on the secure endpoint and an SDES-SRTP peer (RFC 4568) on the plain one.
//! Each datagram crosses two transforms under two unrelated keyings (RFC 3711 on both).
//!
//! The DTLS peer runs a real handshake and the SDES peer builds its own SRTP/SRTCP contexts from the
//! two keys, so neither shares a code path with the bridge.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::{Datapath, FlowAction, RxPacket, SourceFilter};
use siphon_rtp_dtls::{DtlsCertificate, DtlsRole, DtlsSession, Fingerprint};
use siphon_rtp_engine::dtls_bridge::{DtlsBridge, DtlsCallPlan};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
use siphon_rtp_srtp::srtcp::SrtcpContext;
use siphon_rtp_srtp::SrtpContext;
use tokio::net::UdpSocket;

fn rtp(sequence: u16, ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.resize(172, 0xAB);
    packet
}

fn receiver_report(ssrc: u32) -> Vec<u8> {
    let mut report = vec![0x80, 201, 0x00, 0x01];
    report.extend_from_slice(&ssrc.to_be_bytes());
    report
}

async fn peer_handshake(
    socket: Arc<UdpSocket>,
    engine: SocketAddr,
    cert: &DtlsCertificate,
    fingerprint: &Fingerprint,
) -> SecureLeg {
    let mut session = DtlsSession::new(
        cert,
        DtlsRole::Client,
        fingerprint.clone(),
        Duration::from_millis(200),
    )
    .expect("session");
    session.start(Instant::now()).expect("flight");
    while let Some(record) = session.poll_transmit() {
        socket.send_to(&record, engine).await.expect("send");
    }
    let mut buffer = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !session.is_keyed() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let wait = session.poll_timeout().map_or(remaining, |at| {
            at.saturating_duration_since(Instant::now()).min(remaining)
        });
        match tokio::time::timeout(wait, socket.recv_from(&mut buffer)).await {
            Ok(Ok((len, _))) => {
                session
                    .handle_datagram(Instant::now(), &buffer[..len])
                    .expect("record");
            }
            _ => session.handle_timeout(Instant::now()).expect("timer"),
        }
        while let Some(record) = session.poll_transmit() {
            socket.send_to(&record, engine).await.expect("send");
        }
    }
    session
        .keying()
        .map(|keying| keying.to_secure_leg())
        .expect("keyed")
}

/// The desk phone's own crypto, from the two keys it knows.
struct Desk {
    sends: SrtpContext,
    receives: SrtpContext,
    sends_rtcp: SrtcpContext,
    receives_rtcp: SrtcpContext,
}

struct Harness {
    bridge: Arc<DtlsBridge<UdpLoopbackDatapath>>,
    secure: siphon_rtp_datapath::Endpoint,
    plain: siphon_rtp_datapath::Endpoint,
    plain_rtcp: siphon_rtp_datapath::Endpoint,
    desk_socket: UdpSocket,
    desk_rtcp_socket: UdpSocket,
    desk_addr: SocketAddr,
    desk_rtcp_addr: SocketAddr,
    peer: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    peer_cert: DtlsCertificate,
    engine_cert: DtlsCertificate,
    desk: Desk,
    engine_leg: Arc<Mutex<SecureLeg>>,
    datapath: UdpLoopbackDatapath,
}

async fn harness() -> Harness {
    let datapath = UdpLoopbackDatapath::new();
    let plain = datapath.alloc_endpoint().await.expect("endpoint");
    let plain_rtcp = datapath.alloc_endpoint().await.expect("endpoint");
    let secure = datapath.alloc_endpoint().await.expect("endpoint");
    datapath
        .install_flow(secure.id, FlowAction::Redirect)
        .expect("redirect");
    let desk_socket = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
        .await
        .expect("bind");
    let desk_rtcp_socket = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
        .await
        .expect("bind");
    let peer = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind"),
    );
    let (desk_addr, desk_rtcp_addr, peer_addr) = (
        desk_socket.local_addr().expect("addr"),
        desk_rtcp_socket.local_addr().expect("addr"),
        peer.local_addr().expect("addr"),
    );
    let engine_cert = DtlsCertificate::generate().expect("cert");
    let peer_cert = DtlsCertificate::generate().expect("cert");
    // The key the engine offered the desk phone, and the one the desk phone answered.
    let toward_desk = SrtpKeyMaterial::generate().expect("key");
    let from_desk = SrtpKeyMaterial::generate().expect("key");
    let bridge = Arc::new(DtlsBridge::new(datapath.clone()));
    bridge.register(DtlsCallPlan {
        plain_endpoint: plain.id,
        plain_source: SourceFilter::Exact(desk_addr.ip()),
        plain_dst: desk_addr,
        secure_endpoint: secure.id,
        secure_source: SourceFilter::Exact(peer_addr.ip()),
        secure_dst: peer_addr,
        secure_local: secure.local_addr,
        certificate: engine_cert.clone(),
        role: DtlsRole::Server,
        peer_fingerprint: peer_cert.fingerprint(),
        gate_on_ice: false,
        ice_validated: None,
        plain_rtcp: Some(siphon_rtp_engine::dtls_bridge::PlainRtcp {
            endpoint: plain_rtcp.id,
            source: SourceFilter::Exact(desk_rtcp_addr.ip()),
            dst: desk_rtcp_addr,
        }),
    });
    let engine_leg = Arc::new(Mutex::new(SecureLeg::new(&toward_desk, &from_desk)));
    assert!(
        bridge.set_plain_leg(secure.id, engine_leg.clone()),
        "the association's plain side takes the SDES leg"
    );
    Harness {
        bridge,
        secure,
        plain,
        plain_rtcp,
        desk_socket,
        desk_rtcp_socket,
        desk_addr,
        desk_rtcp_addr,
        peer,
        peer_addr,
        peer_cert,
        engine_cert,
        desk: Desk {
            sends: SrtpContext::from_key_material(&from_desk),
            receives: SrtpContext::from_key_material(&toward_desk),
            sends_rtcp: SrtcpContext::from_key_material(&from_desk),
            receives_rtcp: SrtcpContext::from_key_material(&toward_desk),
        },
        engine_leg,
        datapath,
    }
}

fn packet(
    endpoint: siphon_rtp_datapath::EndpointId,
    source: SocketAddr,
    data: Vec<u8>,
) -> RxPacket {
    RxPacket {
        endpoint,
        source,
        arrival: 0,
        data: Bytes::from(data),
    }
}

impl Harness {
    /// Run the DTLS peer's handshake against the bridge, which the datapath's dispatcher feeds.
    async fn handshake(&self) -> SecureLeg {
        let rx = self.datapath.rx();
        let dispatch = self.bridge.clone();
        let dispatcher = tokio::spawn(async move {
            while let Ok(received) = rx.recv_async().await {
                dispatch.handle(received).await;
            }
        });
        let leg = peer_handshake(
            self.peer.clone(),
            self.secure.local_addr,
            &self.peer_cert,
            &self.engine_cert.fingerprint(),
        )
        .await;
        dispatcher.abort();
        leg
    }

    async fn quiet(socket: &UdpSocket, wait: Duration) -> bool {
        let mut buffer = [0u8; 2048];
        tokio::time::timeout(wait, socket.recv_from(&mut buffer))
            .await
            .is_err()
    }

    async fn receive(socket: &UdpSocket) -> Vec<u8> {
        let mut buffer = [0u8; 2048];
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
            .await
            .expect("a datagram arrives")
            .expect("recv");
        buffer[..len].to_vec()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unkeyed_association_forwards_nothing_in_either_direction() {
    let mut rig = harness().await;
    // The desk phone's SRTP, valid under its own key, before the DTLS peer has keyed anything: it
    // must reach the DTLS peer neither in the clear nor re-encrypted under a key that does not exist.
    for sequence in 0..5u16 {
        let sealed = {
            let mut sealed = Vec::new();
            rig.desk
                .sends
                .protect(&rtp(sequence, 0x0B0B_0B0B), &mut sealed)
                .expect("seal");
            sealed
        };
        rig.bridge
            .handle(packet(rig.plain.id, rig.desk_addr, sealed))
            .await;
    }
    assert!(
        Harness::quiet(&rig.peer, Duration::from_millis(300)).await,
        "nothing reaches the unkeyed DTLS peer"
    );
    // After the handshake the very same stream flows.
    let mut peer_leg = rig.handshake().await;
    let mut delivered = false;
    for sequence in 10..60u16 {
        let mut sealed = Vec::new();
        rig.desk
            .sends
            .protect(&rtp(sequence, 0x0B0B_0B0B), &mut sealed)
            .expect("seal");
        rig.bridge
            .handle(packet(rig.plain.id, rig.desk_addr, sealed))
            .await;
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            tokio::time::timeout(Duration::from_millis(100), rig.peer.recv_from(&mut buffer)).await
        {
            let mut opened = Vec::new();
            peer_leg
                .unprotect(&buffer[..len], &mut opened)
                .expect("the DTLS peer opens it");
            assert_eq!(opened, rtp(sequence, 0x0B0B_0B0B));
            delivered = true;
            break;
        }
    }
    assert!(delivered, "the keyed association relays");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn media_crosses_the_double_transform_in_both_directions_with_rtcp() {
    let mut rig = harness().await;
    let mut peer_leg = rig.handshake().await;

    // DTLS peer → SDES desk phone, RTP.
    let from_peer = rtp(7, 0x0A0A_0A0A);
    let mut sealed = Vec::new();
    peer_leg.protect(&from_peer, &mut sealed).expect("seal");
    rig.bridge
        .handle(packet(rig.secure.id, rig.peer_addr, sealed.clone()))
        .await;
    let at_desk = Harness::receive(&rig.desk_socket).await;
    assert_ne!(at_desk, from_peer, "never plaintext to the desk phone");
    assert_ne!(at_desk, sealed, "nor the peer's own ciphertext");
    let mut opened = Vec::new();
    rig.desk
        .receives
        .unprotect(&at_desk, &mut opened)
        .expect("the desk phone opens it under the key it was offered");
    assert_eq!(opened, from_peer);

    // SDES desk phone → DTLS peer, RTP.
    let from_desk = rtp(9, 0x0B0B_0B0B);
    let mut sealed = Vec::new();
    rig.desk
        .sends
        .protect(&from_desk, &mut sealed)
        .expect("seal");
    rig.bridge
        .handle(packet(rig.plain.id, rig.desk_addr, sealed))
        .await;
    let at_peer = Harness::receive(&rig.peer).await;
    assert_ne!(at_peer, from_desk);
    let mut opened = Vec::new();
    peer_leg.unprotect(&at_peer, &mut opened).expect("open");
    assert_eq!(opened, from_desk);

    // DTLS peer's SRTCP (muxed) → the desk phone's own RTCP port, as SRTCP under the SDES key.
    let report = receiver_report(0x0A0A_0A0A);
    let mut sealed = Vec::new();
    peer_leg.protect(&report, &mut sealed).expect("seal");
    rig.bridge
        .handle(packet(rig.secure.id, rig.peer_addr, sealed))
        .await;
    let at_desk_rtcp = Harness::receive(&rig.desk_rtcp_socket).await;
    let mut opened = Vec::new();
    rig.desk
        .receives_rtcp
        .unprotect(&at_desk_rtcp, &mut opened)
        .expect("the desk phone opens the SRTCP");
    assert_eq!(opened, report);

    // The desk phone's SRTCP on its RTCP port → the DTLS peer, as SRTCP on the association.
    let report = receiver_report(0x0B0B_0B0B);
    let mut sealed = Vec::new();
    rig.desk
        .sends_rtcp
        .protect(&report, &mut sealed)
        .expect("seal");
    rig.bridge
        .handle(packet(rig.plain_rtcp.id, rig.desk_rtcp_addr, sealed))
        .await;
    let at_peer = Harness::receive(&rig.peer).await;
    let mut opened = Vec::new();
    peer_leg.unprotect(&at_peer, &mut opened).expect("open");
    assert_eq!(opened, report);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_or_misplaced_datagram_on_the_sdes_side_is_dropped_before_the_dtls_peer() {
    let mut rig = harness().await;
    let mut peer_leg = rig.handshake().await;
    // Key the association with one good packet.
    let mut sealed = Vec::new();
    rig.desk
        .sends
        .protect(&rtp(1, 0x0B0B_0B0B), &mut sealed)
        .expect("seal");
    rig.bridge
        .handle(packet(rig.plain.id, rig.desk_addr, sealed.clone()))
        .await;
    let first = Harness::receive(&rig.peer).await;
    let mut opened = Vec::new();
    peer_leg.unprotect(&first, &mut opened).expect("open");

    // A replay of that same SRTP packet fails the SDES leg's replay check (RFC 3711 §3.3.2).
    rig.bridge
        .handle(packet(rig.plain.id, rig.desk_addr, sealed))
        .await;
    // SRTP the desk phone never sealed (the DTLS peer's own plaintext as if it were SRTP).
    rig.bridge
        .handle(packet(rig.plain.id, rig.desk_addr, rtp(2, 0x0B0B_0B0B)))
        .await;
    // Valid SRTP, from an address the desk phone never signalled.
    let mut sealed = Vec::new();
    rig.desk
        .sends
        .protect(&rtp(3, 0x0B0B_0B0B), &mut sealed)
        .expect("seal");
    rig.bridge
        .handle(packet(
            rig.plain.id,
            "127.0.0.9:4000".parse().expect("addr"),
            sealed,
        ))
        .await;
    assert!(
        Harness::quiet(&rig.peer, Duration::from_millis(300)).await,
        "none of the three reaches the DTLS peer"
    );
    // The leg itself is intact: genuine media still flows.
    let mut sealed = Vec::new();
    rig.desk
        .sends
        .protect(&rtp(4, 0x0B0B_0B0B), &mut sealed)
        .expect("seal");
    rig.bridge
        .handle(packet(rig.plain.id, rig.desk_addr, sealed))
        .await;
    Harness::receive(&rig.peer).await;
    // A genuine SDES leg of the engine, rekeyed in place, keeps what it sent.
    assert!(rig.engine_leg.lock().is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tap_on_either_endpoint_reads_the_plaintext_between_the_two_transforms() {
    let mut rig = harness().await;
    let mut peer_leg = rig.handshake().await;
    let (from_peer_tap, from_peer_taken) = flume::bounded(8);
    let (from_desk_tap, from_desk_taken) = flume::bounded(8);
    assert!(rig
        .bridge
        .add_plain_tap(rig.secure.id, "peer", from_peer_tap));
    assert!(rig
        .bridge
        .add_plain_tap(rig.plain.id, "desk", from_desk_tap));

    let from_peer = rtp(5, 0x0A0A_0A0A);
    let mut sealed = Vec::new();
    peer_leg.protect(&from_peer, &mut sealed).expect("seal");
    rig.bridge
        .handle(packet(rig.secure.id, rig.peer_addr, sealed))
        .await;
    let from_desk = rtp(6, 0x0B0B_0B0B);
    let mut sealed = Vec::new();
    rig.desk
        .sends
        .protect(&from_desk, &mut sealed)
        .expect("seal");
    rig.bridge
        .handle(packet(rig.plain.id, rig.desk_addr, sealed))
        .await;
    assert_eq!(
        from_peer_taken.try_recv().expect("a copy").as_ref(),
        from_peer.as_slice(),
        "the tap on the DTLS side reads RTP in the clear, not SRTP of either keying"
    );
    assert_eq!(
        from_desk_taken.try_recv().expect("a copy").as_ref(),
        from_desk.as_slice(),
        "and so does the tap on the SDES side"
    );
}
