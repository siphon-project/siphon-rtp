//! Intercepting an engine-answered single-leg call (ETSI TS 103 221-2 X3) must not add a heap
//! allocation to the call's per-packet path. The ingress tap and the egress tap copy each packet
//! into a buffer the delivery task hands back through the tap's recycle pool, so once the pool is
//! warm a tapped call allocates exactly what an untapped one does.
//!
//! A counting global allocator measures the same process-and-tick loop (the caller's packet in, the
//! engine's comfort-noise frame out) with and without the interception, and the two counts must be
//! equal.

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
use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::media_pipeline::{DirectionConfig, EchoProfile, MediaCall};
use siphon_rtp_engine::x3::{x3_channel, X3Delivery, X3Taps};
use siphon_rtp_li::PayloadDirection;

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

/// The allocation counter is process-wide, so the measuring tests take turns.
static MEASURING: std::sync::Mutex<()> = std::sync::Mutex::new(());

const CALLER: &str = "192.0.2.10:5000";
const ENGINE: &str = "198.51.100.1:20000";
const WARM_FRAMES: u16 = 40;
const MEASURED_FRAMES: u16 = 200;

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn direction() -> DirectionConfig {
    let spec = CodecSpec::new(0, "PCMU", 8000, 1, 20);
    DirectionConfig {
        ingress_endpoint: EndpointId(1),
        accepted_source: SourceFilter::Exact(addr(CALLER).ip()),
        egress_endpoint: EndpointId(1),
        egress_dst: addr(CALLER),
        decoder: siphon_rtp_codec::factory::decoder_for(&spec).unwrap(),
        encoder: siphon_rtp_codec::factory::encoder_for(&spec).unwrap(),
        egress_ssrc: 0xE0E0_0001,
        egress_payload_type: 0,
        telephone_event_in: None,
        telephone_event_out: None,
        noise_suppression: false,
        echo: EchoProfile::default(),
        beep_detection: false,
        beep_cadence_guard_ms: None,
        produce_echo_reference: false,
        ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
    }
}

fn voice(sequence: u16) -> RxPacket {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
    packet.extend_from_slice(&[0x40; 160]);
    RxPacket {
        endpoint: EndpointId(1),
        source: addr(CALLER),
        arrival: u64::from(sequence) * 20_000,
        data: Bytes::from(packet),
    }
}

/// Hand every delivered packet's buffer back to the taps, as the delivery task does after framing.
fn return_buffers(delivery: &X3Delivery) -> usize {
    let mut delivered = 0;
    while let Ok(packet) = delivery.packets.try_recv() {
        delivered += 1;
        let _ = delivery.recycle.try_send(packet.payload);
    }
    delivered
}

/// Allocations over `MEASURED_FRAMES` frames of a single-leg call under `deliveries` interceptions
/// (none for the baseline), and how many packets they delivered in all.
fn allocations_of_the_call(deliveries: usize) -> (usize, usize) {
    let _turn = MEASURING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut call = MediaCall::new("single", "tag-a", None, direction(), direction(), true)
        .with_comfort_idle(None);
    let channels: Vec<_> = (0..deliveries).map(|_| x3_channel(4096)).collect();
    if deliveries > 0 {
        call.start_x3_single_leg((
            X3Taps::new(
                channels
                    .iter()
                    .map(|(factory, _)| factory.tap(addr(ENGINE), PayloadDirection::FromTarget))
                    .collect(),
            ),
            X3Taps::new(
                channels
                    .iter()
                    .map(|(factory, _)| factory.tap(addr(ENGINE), PayloadDirection::ToTarget))
                    .collect(),
            ),
        ));
    }
    // Built before arming: building a packet allocates, handling one must not.
    let packets: Vec<RxPacket> = (0..WARM_FRAMES + MEASURED_FRAMES).map(voice).collect();
    let mut out = Vec::with_capacity(8);
    let mut events = Vec::with_capacity(8);
    let mut run = |range: std::ops::Range<usize>, call: &mut MediaCall| -> usize {
        let mut delivered = 0;
        for packet in &packets[range] {
            out.clear();
            events.clear();
            call.process(packet, &mut out, &mut events);
            call.tick(&mut out, &mut events);
            delivered += channels
                .iter()
                .map(|(_, delivery)| return_buffers(delivery))
                .sum::<usize>();
        }
        delivered
    };
    run(0..WARM_FRAMES as usize, &mut call);

    ALLOCATIONS.store(0, Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    let delivered = run(
        WARM_FRAMES as usize..(WARM_FRAMES + MEASURED_FRAMES) as usize,
        &mut call,
    );
    ARMED.with(|armed| armed.set(false));
    (ALLOCATIONS.load(Ordering::Relaxed), delivered)
}

#[test]
fn an_intercepted_single_leg_call_adds_no_allocation_to_its_packet_path() {
    let (untapped, untapped_delivered) = allocations_of_the_call(0);
    let (tapped, tapped_delivered) = allocations_of_the_call(1);

    assert_eq!(untapped_delivered, 0, "nothing is delivered with no tap");
    assert!(
        tapped_delivered >= usize::from(MEASURED_FRAMES) * 2 - 8,
        "the loop really delivers both directions ({tapped_delivered} packets)"
    );
    assert!(untapped > 0, "the call allocates its outbound datagrams");
    assert_eq!(
        tapped, untapped,
        "the interception allocates nothing beyond what the call itself does"
    );
}

#[test]
fn two_interceptions_of_a_single_leg_call_stay_allocation_free_on_the_packet_path() {
    let (untapped, _) = allocations_of_the_call(0);
    let (tapped, delivered) = allocations_of_the_call(2);

    assert!(
        delivered >= usize::from(MEASURED_FRAMES) * 4 - 16,
        "both deliveries receive both directions ({delivered} packets)"
    );
    assert_eq!(
        tapped, untapped,
        "a set of two taps allocates nothing beyond what the call itself does"
    );
}
