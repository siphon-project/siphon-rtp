//! The symmetric-RTP latch that aims a WebSocket-takeover leg's downlink sits on the per-packet
//! ingress path, so it must add **zero** heap allocation there.
//!
//! Nothing in it can allocate by construction — the SSRC read is a slice index, the latch is two
//! `Option`s behind a `Mutex`, and the destination is a `tokio::sync::watch` whose value is replaced
//! in place — but "by construction" is what every leak looked like beforehand. A counting global
//! allocator proves it directly: a steady-state `dispatch` loop on a latching leg allocates exactly
//! as many times as the same loop on a leg whose latch is switched off (an ICE-managed egress, where
//! the agent owns the transport and media never re-points it).
//!
//! The **delta** is the assertion rather than an absolute zero, because `dispatch` also hands the
//! datagram to the bridge's mailbox and that is not this change's to account for. The rebind case is
//! measured too: even when the latch takes its write path on every single packet — a peer that would
//! have to re-NAT every 20 ms — it must still not allocate.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::ws_bridge::{WsCallPlan, WsEgress, WsRegistry};

/// A pass-through allocator that counts allocations on the armed thread only.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting, so the libtest harness's background-thread churn during
    // the same window is not miscounted. `const`-initialised so `alloc` never itself allocates.
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

/// Run `body` with allocation counting armed on this thread, and report how many it made.
fn allocations(body: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    body();
    ARMED.with(|armed| armed.set(false));
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

const PEER_IP: [u8; 4] = [127, 0, 0, 2];

fn peer(port: u16) -> SocketAddr {
    (PEER_IP, port).into()
}

/// A µ-law RTP packet (PT 0): a 160-sample / 20 ms frame.
fn rtp_packet(sequence: u16, ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&[0xFFu8; 160]);
    packet
}

/// One registered takeover leg, plus its mailbox so the caller can drain what it feeds.
///
/// `endpoint` is a real endpoint on `datapath`: `dispatch` stamps the leg's liveness for the idle
/// sweep on every accepted packet, and that stamp must be exercised for real here — it is on the same
/// per-packet path and is exactly the kind of thing that could start allocating unnoticed.
fn leg(
    datapath: &UdpLoopbackDatapath,
    endpoint: EndpointId,
    ice_managed: bool,
) -> (WsRegistry, flume::Receiver<Bytes>) {
    let registry = WsRegistry::default();
    let (rtp_in, rtp_in_rx) = flume::bounded::<Bytes>(1024);
    registry.register(WsCallPlan {
        call_id: "zero-alloc".to_string(),
        endpoint_a: endpoint,
        accepted_source: SourceFilter::Exact(peer(0).ip()),
        ice_pending: false,
        secure: None,
        egress: Arc::new(WsEgress::new(peer(41000), ice_managed)),
        activity: Arc::new(datapath.clone()),
        rtp_in,
        bridge_task: tokio::spawn(std::future::pending()),
        drain_task: tokio::spawn(std::future::pending()),
    });
    (registry, rtp_in_rx)
}

fn packet(endpoint: EndpointId, source: SocketAddr, data: &Bytes) -> RxPacket {
    RxPacket {
        endpoint,
        source,
        arrival: 0,
        data: data.clone(),
    }
}

/// Feed `count` packets from `source_for(i)` and drain each one, so neither the mailbox filling nor
/// the datagram itself is what the counter sees.
fn pump(
    registry: &WsRegistry,
    endpoint: EndpointId,
    mailbox: &flume::Receiver<Bytes>,
    frame: &Bytes,
    count: usize,
    source_for: impl Fn(usize) -> SocketAddr,
) {
    for index in 0..count {
        registry.dispatch(packet(endpoint, source_for(index), frame));
        let _ = mailbox.try_recv();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_downlink_latch_allocates_nothing_on_the_ingress_path() {
    const FRAMES: usize = 2_000;
    let frame = Bytes::from(rtp_packet(1, 0x0A0A_0A0A));

    let datapath = UdpLoopbackDatapath::new();
    let one = datapath.alloc_endpoint().await.expect("endpoint").id;
    let two = datapath.alloc_endpoint().await.expect("endpoint").id;
    let three = datapath.alloc_endpoint().await.expect("endpoint").id;
    let (latching, latching_rx) = leg(&datapath, one, false);
    let (no_latch, no_latch_rx) = leg(&datapath, two, true);

    // Warm both: the first packet latches, and any one-off inside the mailbox happens now.
    pump(&latching, one, &latching_rx, &frame, 16, |_| peer(41000));
    pump(&no_latch, two, &no_latch_rx, &frame, 16, |_| peer(41000));

    let with_latch = allocations(|| {
        pump(&latching, one, &latching_rx, &frame, FRAMES, |_| peer(41000));
    });
    let without_latch = allocations(|| {
        pump(&no_latch, two, &no_latch_rx, &frame, FRAMES, |_| peer(41000));
    });
    assert_eq!(
        with_latch, without_latch,
        "the latch adds no per-packet allocation ({with_latch} vs {without_latch} over {FRAMES} \
         frames)"
    );

    // The write path, taken on every packet: a source that never settles must not allocate either.
    let (rebinding, rebinding_rx) = leg(&datapath, three, false);
    pump(&rebinding, three, &rebinding_rx, &frame, 16, |index| {
        peer(41000 + (index % 64) as u16)
    });
    let while_rebinding = allocations(|| {
        pump(&rebinding, three, &rebinding_rx, &frame, FRAMES, |index| {
            peer(41000 + (index % 64) as u16)
        });
    });
    assert_eq!(
        while_rebinding, without_latch,
        "re-pointing the downlink allocates nothing either ({while_rebinding} vs {without_latch})"
    );
}
