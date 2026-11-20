//! Intercepting a WebSocket-takeover call (ETSI TS 103 221-2 X3) must not add a heap allocation to
//! the leg's per-packet paths. The ingress tap sits in `WsRegistry::dispatch` and the egress tap in
//! the bridge's drain step (`ws_x3::downlink_datagram`); both copy the packet into a buffer the
//! delivery task hands back through the tap's recycle pool, and both read the leg's tap set with one
//! watch borrow, so once the pool is warm a tapped leg allocates exactly what an untapped one does.
//!
//! A counting global allocator measures the same loop with no interception, one and two, and the
//! counts must be equal.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::ws_bridge::{WsCallPlan, WsEgress, WsRegistry, WsSecureLeg};
use siphon_rtp_engine::ws_x3::{downlink_datagram, WsTapSet};
use siphon_rtp_engine::x3::{x3_channel, X3Delivery, X3Taps};
use siphon_rtp_li::PayloadDirection;
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::SrtpKeyMaterial;

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

/// The counter is process-wide, so the measuring tests take turns.
static MEASURING: std::sync::Mutex<()> = std::sync::Mutex::new(());

const PEER: &str = "127.0.0.2:41000";
const ENGINE: &str = "198.51.100.1:20000";
const WARM_FRAMES: usize = 64;
const MEASURED_FRAMES: usize = 500;

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn rtp_packet(sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
    packet.extend_from_slice(&[0xFFu8; 160]);
    packet
}

/// Hand every delivered packet's buffer back to the taps, as the delivery task does after framing.
fn return_buffers(deliveries: &[X3Delivery]) -> usize {
    let mut delivered = 0;
    for delivery in deliveries {
        while let Ok(packet) = delivery.packets.try_recv() {
            delivered += 1;
            let _ = delivery.recycle.try_send(packet.payload);
        }
    }
    delivered
}

/// The tap set of `count` deliveries: ingress `FromTarget`, egress `ToTarget`.
fn tap_set(count: usize) -> (WsTapSet, Vec<X3Delivery>) {
    let channels: Vec<_> = (0..count).map(|_| x3_channel(4096)).collect();
    let set = WsTapSet {
        ingress: X3Taps::new(
            channels
                .iter()
                .map(|(factory, _)| factory.tap(addr(ENGINE), PayloadDirection::FromTarget))
                .collect(),
        ),
        egress: X3Taps::new(
            channels
                .iter()
                .map(|(factory, _)| factory.tap(addr(ENGINE), PayloadDirection::ToTarget))
                .collect(),
        ),
    };
    (
        set,
        channels.into_iter().map(|(_, delivery)| delivery).collect(),
    )
}

fn measure(body: impl FnOnce() -> usize) -> (usize, usize) {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    let delivered = body();
    ARMED.with(|armed| armed.set(false));
    (ALLOCATIONS.load(Ordering::Relaxed) - before, delivered)
}

/// Allocations of `dispatch` over a settled leg under `deliveries` interceptions, and how many
/// packets they delivered.
async fn ingress_allocations(deliveries: usize) -> (usize, usize) {
    let datapath = UdpLoopbackDatapath::new();
    let endpoint: EndpointId = datapath.alloc_endpoint().await.expect("endpoint").id;
    // Taken after the last await, so the guard is never held across one.
    let _turn = MEASURING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let registry = WsRegistry::default();
    let egress = Arc::new(WsEgress::new(addr(PEER), false));
    let (rtp_in, mailbox) = flume::bounded::<Bytes>(1024);
    registry.register(WsCallPlan {
        call_id: "ws-x3".to_string(),
        endpoint_a: endpoint,
        accepted_source: SourceFilter::Exact(addr(PEER).ip()),
        ice_pending: false,
        secure: None,
        egress: egress.clone(),
        activity: Arc::new(datapath.clone()),
        rtp_in,
        bridge_task: tokio::spawn(std::future::pending()),
        drain_task: tokio::spawn(std::future::pending()),
        rtcp_tap: None,
    });
    let (set, channels) = tap_set(deliveries);
    if deliveries > 0 {
        egress.taps().set(set);
    }
    let frame = Bytes::from(rtp_packet(1));
    let pump = |count: usize| -> usize {
        let mut delivered = 0;
        for _ in 0..count {
            registry.dispatch(RxPacket {
                endpoint,
                source: addr(PEER),
                arrival: 0,
                data: frame.clone(),
            });
            let _ = mailbox.try_recv();
            delivered += return_buffers(&channels);
        }
        delivered
    };
    pump(WARM_FRAMES);
    measure(|| pump(MEASURED_FRAMES))
}

/// Allocations of the drain step over `MEASURED_FRAMES` packets, plain or SRTP, under `deliveries`.
fn drain_allocations(deliveries: usize, secure: bool) -> (usize, usize) {
    let _turn = MEASURING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let egress = WsEgress::new(addr(PEER), false);
    let (set, channels) = tap_set(deliveries);
    if deliveries > 0 {
        egress.taps().set(set);
    }
    let taps = egress.taps().subscribe();
    let leg = secure.then(|| {
        let key = |seed: u8| SrtpKeyMaterial::from_inline_bytes(&[seed; 30]).expect("30 bytes");
        WsSecureLeg::keyed(SecureLeg::new(&key(0x11), &key(0x22)))
    });
    let packets: Vec<Vec<u8>> = (0..WARM_FRAMES + MEASURED_FRAMES)
        .map(|sequence| rtp_packet(sequence as u16))
        .collect();
    let mut sealed = Vec::new();
    let mut run = |range: std::ops::Range<usize>| -> usize {
        let mut delivered = 0;
        for packet in &packets[range] {
            let datagram = downlink_datagram(packet, leg.as_ref(), &mut sealed, &taps, addr(PEER));
            assert!(datagram.is_some(), "the packet is sent");
            delivered += return_buffers(&channels);
        }
        delivered
    };
    run(0..WARM_FRAMES);
    measure(|| run(WARM_FRAMES..WARM_FRAMES + MEASURED_FRAMES))
}

#[tokio::test(flavor = "current_thread")]
async fn a_tapped_ws_takeover_leg_adds_no_allocation_to_its_ingress_path() {
    let (untapped, untapped_delivered) = ingress_allocations(0).await;
    let (one, one_delivered) = ingress_allocations(1).await;
    let (two, two_delivered) = ingress_allocations(2).await;
    assert_eq!(untapped_delivered, 0, "nothing is delivered with no tap");
    assert_eq!(untapped, 0, "the ingress step itself allocates nothing");
    assert_eq!(
        one_delivered, MEASURED_FRAMES,
        "one delivery gets every packet"
    );
    assert_eq!(
        two_delivered,
        2 * MEASURED_FRAMES,
        "two deliveries each get it"
    );
    assert_eq!(
        one, untapped,
        "one interception allocates nothing on ingress"
    );
    assert_eq!(
        two, untapped,
        "two interceptions allocate nothing on ingress"
    );
}

#[test]
fn a_tapped_ws_takeover_leg_adds_no_allocation_to_its_drain_step() {
    for secure in [false, true] {
        let (untapped, untapped_delivered) = drain_allocations(0, secure);
        let (one, one_delivered) = drain_allocations(1, secure);
        let (two, two_delivered) = drain_allocations(2, secure);
        assert_eq!(untapped_delivered, 0, "nothing is delivered with no tap");
        assert_eq!(
            untapped, 0,
            "the drain step itself allocates nothing (secure={secure})"
        );
        assert_eq!(one_delivered, MEASURED_FRAMES, "secure={secure}");
        assert_eq!(two_delivered, 2 * MEASURED_FRAMES, "secure={secure}");
        assert_eq!(
            one, untapped,
            "one interception allocates nothing (secure={secure})"
        );
        assert_eq!(
            two, untapped,
            "two interceptions allocate nothing (secure={secure})"
        );
    }
}
