//! The userspace SDES-SRTP bridge a secure video stream rides must add **zero** per-packet heap
//! allocation over a plain relay through the same bridge: the crypto transforms write into buffers the
//! bridge keeps and reuses, never into a fresh `Vec` per datagram, and video is the stream where that
//! counts (hundreds of 1200 byte packets a second per direction).
//!
//! A counting global allocator proves it. A steady-state loop of `handle` over a flow with no keyed
//! side is the baseline (it pays the bridge's own, unavoidable cost), and each keyed shape (SDES to
//! plain, plain to SDES, and the SDES to SDES transcrypt) must allocate exactly as often.
//!
//! The first-IDR injector of an `answer_local` call's far video ([`VideoInjector`], RFC 6184 §8.1)
//! sits in a plain flow: once settled it must cost the plain flow nothing, and while it is armed
//! (dropping until the IDR, then writing the parameter sets into the bridge's buffer) it must not
//! allocate either.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::{Datapath, RxPacket, SourceFilter};
use siphon_rtp_engine::srtp_bridge::{BridgeCallPlan, BridgeFlowPlan, BridgeLeg, SrtpBridge};
use siphon_rtp_engine::video_injector::{Verdict, VideoInjector};
use siphon_rtp_media::h264::ParameterSets;
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
use tokio::net::UdpSocket;

/// A pass-through allocator that counts allocations on the armed thread only.
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
const SOURCE: [u8; 4] = [127, 0, 0, 2];

fn key(seed: u8) -> SrtpKeyMaterial {
    SrtpKeyMaterial::from_inline_bytes(&[seed; 30]).expect("30 bytes")
}

/// A 1200 byte H.264-sized RTP packet (PT 96) with `sequence`.
fn video_packet(sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 96];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 3000).to_be_bytes());
    packet.extend_from_slice(&0xCAFE_F00Du32.to_be_bytes());
    packet.resize(1200, 0xAB);
    packet
}

#[derive(Clone, Copy)]
enum Shape {
    Plain,
    SdesToPlain,
    PlainToSdes,
    Transcrypt,
    /// A plain flow with a first-IDR injector that has settled.
    SettledInjector,
}

/// The allocations `FRAMES` `handle` calls make on a flow of `shape`, after a warm-up.
async fn allocations_over(shape: Shape) -> usize {
    let datapath = UdpLoopbackDatapath::new();
    let ingress = datapath.alloc_endpoint().await.expect("endpoint").id;
    let egress = datapath.alloc_endpoint().await.expect("endpoint").id;
    let sink = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let out_dst = sink.local_addr().expect("addr");
    let bridge = SrtpBridge::new(datapath.clone());
    let leg = |seed: u8| SecureLeg::new(&key(seed), &key(seed.wrapping_add(1)));
    let (near_leg, far_leg, ingress_leg, egress_leg) = match shape {
        Shape::Plain | Shape::SettledInjector => (None, None, None, None),
        Shape::SdesToPlain => (Some(leg(1)), None, Some(BridgeLeg::Near), None),
        Shape::PlainToSdes => (None, Some(leg(3)), None, Some(BridgeLeg::Far)),
        Shape::Transcrypt => (
            Some(leg(1)),
            Some(leg(3)),
            Some(BridgeLeg::Near),
            Some(BridgeLeg::Far),
        ),
    };
    bridge.register(BridgeCallPlan {
        near_leg,
        far_leg,
        flows: vec![BridgeFlowPlan {
            endpoint: ingress,
            ingress_leg,
            egress_leg,
            accepted_source: SourceFilter::Exact(SOURCE.into()),
            latch: false,
            out_endpoint: egress,
            out_dst,
        }],
    });
    if matches!(shape, Shape::SettledInjector) {
        let mut sets = ParameterSets::new();
        sets.store(&[0x67, 0x42, 0xC0, 0x1E], true);
        sets.store(&[0x68, 0xCE, 0x3C, 0x80], false);
        let injector = std::sync::Arc::new(VideoInjector::new(sets));
        // Settle it: an IDR, then the stream advancing past the reordering window
        // (`SETTLE_PACKETS` beyond the IDR), after which every packet is forwarded untouched.
        let mut idr = video_packet(0);
        idr[1] |= 0x80;
        idr[12] = 0x65;
        let mut scratch = Vec::new();
        assert!(matches!(
            injector.admit(&idr, &mut scratch),
            Verdict::Forward(_)
        ));
        let settle =
            u16::try_from(siphon_rtp_engine::video_injector::SETTLE_PACKETS).expect("positive");
        for sequence in 1..=settle {
            let _ = injector.admit(&video_packet(sequence), &mut scratch);
        }
        assert!(injector.is_settled());
        assert!(bridge.attach_video_injector(ingress, injector));
    }
    // What the sender puts on the wire: protected under the key the bridge decrypts with (the peer's
    // own, the second of the leg's pair) when the ingress is secure.
    let mut sender = SecureLeg::new(&key(2), &key(1));
    let wire: Vec<Bytes> = (0..(FRAMES + 64) as u16)
        .map(|sequence| {
            let plain = video_packet(sequence);
            if matches!(shape, Shape::SdesToPlain | Shape::Transcrypt) {
                let mut sealed = Vec::new();
                sender.protect(&plain, &mut sealed).expect("protect");
                Bytes::from(sealed)
            } else {
                Bytes::from(plain)
            }
        })
        .collect();
    let source: SocketAddr = (SOURCE, 5000).into();
    // Built up front and moved in, so the counter sees the bridge and not the harness cloning bytes.
    let mut packets: Vec<RxPacket> = wire
        .into_iter()
        .map(|data| RxPacket {
            endpoint: ingress,
            source,
            arrival: 0,
            data,
        })
        .collect();
    let measured = packets.split_off(64);
    let mut drain = [0u8; 2048];
    for packet in packets {
        bridge.handle(packet).await;
        // The datagram must really cross the bridge: a flow that drops everything allocates
        // nothing and proves nothing.
        let (length, _) = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            sink.recv_from(&mut drain),
        )
        .await
        .expect("the bridge relayed the warm-up datagram")
        .expect("recv");
        let sealed_out = matches!(shape, Shape::PlainToSdes | Shape::Transcrypt);
        assert_eq!(
            length,
            if sealed_out { 1210 } else { 1200 },
            "relayed length"
        );
    }
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    for packet in measured {
        bridge.handle(packet).await;
    }
    ARMED.with(|armed| armed.set(false));
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

#[tokio::test(flavor = "current_thread")]
async fn a_secure_video_flow_allocates_no_more_than_a_plain_one_through_the_bridge() {
    let plain = allocations_over(Shape::Plain).await;
    for (label, shape) in [
        ("sdes to plain", Shape::SdesToPlain),
        ("plain to sdes", Shape::PlainToSdes),
        ("sdes to sdes transcrypt", Shape::Transcrypt),
        ("settled first-IDR injector", Shape::SettledInjector),
    ] {
        let keyed = allocations_over(shape).await;
        assert!(
            keyed <= plain,
            "{label} allocates {keyed} times over {FRAMES} packets against {plain} for a plain \
             relay through the same bridge"
        );
    }
}

/// An H.264 RTP packet of `payload` (PT 96) with `sequence`.
fn h264_packet(sequence: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x80, if marker { 0x80 | 96 } else { 96 }];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&90_000u32.to_be_bytes());
    packet.extend_from_slice(&0xCAFE_F00Du32.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

#[test]
fn an_armed_injector_drops_and_injects_without_allocating() {
    let mut sets = ParameterSets::new();
    sets.store(&[0x67, 0x42, 0xC0, 0x1E, 0xDA], true);
    sets.store(&[0x68, 0xCE, 0x3C, 0x80], false);
    // Built up front: creating an injector allocates, using one must not.
    let injectors: Vec<VideoInjector> =
        (0..100).map(|_| VideoInjector::new(sets.clone())).collect();
    let slice = h264_packet(10, false, &[0x41, 0x9A, 0x00, 0x33]);
    let idr = h264_packet(11, true, &[0x65, 0x88, 0x84, 0x00]);
    // The bridge's buffer, grown once by a first injection like the pooled one is.
    let mut buffer = Vec::new();
    VideoInjector::new(sets.clone()).admit(&idr, &mut buffer);
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    let mut injected = 0;
    for injector in &injectors {
        for _ in 0..10 {
            assert_eq!(injector.admit(&slice, &mut buffer), Verdict::Drop);
        }
        match injector.admit(&idr, &mut buffer) {
            Verdict::Forward(found) => injected += found.count(),
            Verdict::Drop => panic!("the IDR must go through"),
        }
    }
    ARMED.with(|armed| armed.set(false));
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) - before;
    assert_eq!(injected, 200, "SPS and PPS ahead of each IDR");
    assert_eq!(allocations, 0, "the armed injector allocated");
}
