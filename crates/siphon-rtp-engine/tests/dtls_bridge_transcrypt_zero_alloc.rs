//! A DTLS association whose plain peer is keyed by SDES (`PipelineKind::DtlsOffererTranscrypt`) runs
//! two transforms per datagram (RFC 3711 under two keyings). The second must add **zero** per-packet
//! heap allocation over the single-transform relay of a plain peer: both write into the scratch
//! buffers the bridge keeps.
//!
//! A counting global allocator proves it. A steady-state loop of `handle` through a plain-peer bridge
//! is the baseline (it pays the datapath's own send cost), and the same loop through the transcrypt
//! must allocate no more often, in each direction.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::{Datapath, FlowAction, RxPacket, SourceFilter};
use siphon_rtp_dtls::{DtlsCertificate, DtlsRole, DtlsSession, Fingerprint};
use std::sync::Mutex;

use siphon_rtp_engine::dtls_bridge::{DtlsBridge, DtlsCallPlan};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
use siphon_rtp_srtp::SrtpContext;
use tokio::net::UdpSocket;

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

// SAFETY: delegates straight to the system allocator; only bumps a relaxed counter when armed.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

const FRAMES: usize = 1_000;

fn rtp(payload_type: u8, sequence: u16, ssrc: u32, length: usize) -> Vec<u8> {
    let mut packet = vec![0x80, payload_type];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.resize(length, 0xAB);
    packet
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

#[derive(Clone, Copy, PartialEq)]
enum Shape {
    SecureToPlain,
    PlainToSecure,
}

/// Allocations over `FRAMES` relayed packets of `shape`, with the plain peer keyed by SDES or not.
async fn allocations_over(shape: Shape, sdes_plain_peer: bool) -> usize {
    let datapath = UdpLoopbackDatapath::new();
    let plain = datapath.alloc_endpoint().await.expect("endpoint");
    let secure = datapath.alloc_endpoint().await.expect("endpoint");
    datapath
        .install_flow(secure.id, FlowAction::Redirect)
        .expect("redirect");
    let desk = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
        .await
        .expect("bind");
    let peer = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind"),
    );
    let (desk_addr, peer_addr) = (
        desk.local_addr().expect("addr"),
        peer.local_addr().expect("addr"),
    );
    let engine_cert = DtlsCertificate::generate().expect("cert");
    let peer_cert = DtlsCertificate::generate().expect("cert");
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
        plain_rtcp: None,
    });
    let toward_desk = SrtpKeyMaterial::generate().expect("key");
    let from_desk = SrtpKeyMaterial::generate().expect("key");
    if sdes_plain_peer {
        assert!(bridge.set_plain_leg(
            secure.id,
            Arc::new(Mutex::new(SecureLeg::new(&toward_desk, &from_desk)))
        ));
    }
    let rx = datapath.rx();
    let dispatch = bridge.clone();
    let dispatcher = tokio::spawn(async move {
        while let Ok(packet) = rx.recv_async().await {
            dispatch.handle(packet).await;
        }
    });
    let mut leg = peer_handshake(
        peer.clone(),
        secure.local_addr,
        &peer_cert,
        &engine_cert.fingerprint(),
    )
    .await;
    dispatcher.abort();
    let packet = |endpoint, source, data: Vec<u8>| RxPacket {
        endpoint,
        source,
        arrival: 0,
        data: Bytes::from(data),
    };
    let mut desk_out = SrtpContext::from_key_material(&from_desk);
    // The packet the desk phone sends: SRTP under its own key when it is keyed, plaintext otherwise.
    let mut from_the_desk = |sequence: u16| {
        let plain_packet = rtp(0, sequence, 0x0B0B_0B0B, 172);
        if sdes_plain_peer {
            let mut sealed = Vec::new();
            desk_out
                .protect(&plain_packet, &mut sealed)
                .expect("protect");
            sealed
        } else {
            plain_packet
        }
    };
    // Warm-up: the engine installs its leg a moment after the peer finishes, and the buffers grow
    // once to the largest datagram.
    let mut drain = [0u8; 2048];
    let mut keyed = false;
    for sequence in 0..50u16 {
        let mut sealed = Vec::new();
        leg.protect(&rtp(0, sequence, 0x0A0A_0A0A, 172), &mut sealed)
            .expect("protect");
        bridge.handle(packet(secure.id, peer_addr, sealed)).await;
        if tokio::time::timeout(Duration::from_millis(100), desk.recv_from(&mut drain))
            .await
            .is_ok()
        {
            keyed = true;
            break;
        }
    }
    assert!(keyed, "the bridge keyed its leg");
    let mut measured: Vec<RxPacket> = Vec::with_capacity(FRAMES + 64);
    for sequence in 100..(100 + FRAMES as u16 + 64) {
        measured.push(match shape {
            Shape::SecureToPlain => {
                let mut sealed = Vec::new();
                leg.protect(&rtp(0, sequence, 0x0A0A_0A0A, 172), &mut sealed)
                    .expect("protect");
                packet(secure.id, peer_addr, sealed)
            }
            Shape::PlainToSecure => packet(plain.id, desk_addr, from_the_desk(sequence)),
        });
    }
    let timed = measured.split_off(64);
    for warm in measured {
        bridge.handle(warm).await;
    }
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    for item in timed {
        bridge.handle(item).await;
    }
    ARMED.with(|armed| armed.set(false));
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

#[tokio::test(flavor = "current_thread")]
async fn the_second_transform_of_a_transcrypted_relay_allocates_no_more_than_a_plain_peers() {
    for (label, shape) in [
        ("DTLS peer to SDES peer", Shape::SecureToPlain),
        ("SDES peer to DTLS peer", Shape::PlainToSecure),
    ] {
        let single = allocations_over(shape, false).await;
        let double = allocations_over(shape, true).await;
        println!(
            "{label}: {double} allocations over {FRAMES} packets against {single} for a plain peer"
        );
        assert!(
            double <= single,
            "{label} allocates {double} times over {FRAMES} packets against {single} for a plain \
             peer through the same bridge"
        );
    }
}
