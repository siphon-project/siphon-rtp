//! Intercepting a conference seat (ETSI TS 103 221-2 X3) must not add a heap allocation to the
//! room's per-packet path. The taps copy each accepted packet into a buffer the delivery task hands
//! back through the tap's recycle pool, so once the pool is warm a tapped room allocates exactly
//! what an untapped one does: the outbound `Bytes` per datagram and nothing for the interception.
//!
//! A counting global allocator measures the same ingest-and-tick loop over a three-seat room with and
//! without a tapped seat, and the two counts must be equal.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use siphon_rtp_codec::g711::G711;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::conference::{Conference, ParticipantConfig, SeatTelemetry, SeatX3Source};
use siphon_rtp_engine::x3::{x3_channel, X3Delivery};
use siphon_rtp_proto::ConferenceDtmf;

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

const SEATS: usize = 3;
const WARM_FRAMES: u16 = 40;
const MEASURED_FRAMES: u16 = 200;

fn seat(index: usize) -> ParticipantConfig {
    let octet = u8::try_from(index + 1).unwrap();
    ParticipantConfig {
        tag: format!("seat-{index}"),
        decoder: Box::new(G711::ulaw()),
        encoder: Box::new(G711::ulaw()),
        ingress_endpoint: EndpointId(index as u64 + 1),
        egress_endpoint: EndpointId(index as u64 + 1),
        egress_dst: format!("192.0.2.{octet}:4000").parse().unwrap(),
        accepted_source: SourceFilter::Exact(format!("192.0.2.{octet}").parse().unwrap()),
        latch: false,
        egress_ssrc: 0xC000_0000 + index as u32,
        egress_payload_type: 0,
        mos_codec: siphon_rtp_hep::mos::Codec::G711,
        telephone_event: None,
        dtmf: ConferenceDtmf::Events,
        secure: None,
        secure_pending: false,
        text: None,
        ice_pending: false,
        routing: Default::default(),
        telemetry: SeatTelemetry {
            local: Some("198.51.100.1:20000".parse().unwrap()),
            sip_call_id: None,
        },
        call: None,
    }
}

fn voice(index: usize, sequence: u16) -> RxPacket {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&(0x1000_0000 + index as u32).to_be_bytes());
    packet.extend_from_slice(&[0x40; 160]);
    RxPacket {
        endpoint: EndpointId(index as u64 + 1),
        source: format!("192.0.2.{}:5000", index + 1).parse().unwrap(),
        arrival: 0,
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

/// Allocations over `MEASURED_FRAMES` ingest-and-tick frames of a three-seat room whose seat 1 is
/// intercepted by `deliveries` interceptions (none for the baseline), and how many packets they
/// delivered in all.
fn allocations_of_the_room(deliveries: usize) -> (usize, usize) {
    let _turn = MEASURING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut room = Conference::new("x3-zero-alloc".into(), 0);
    for index in 0..SEATS {
        room.add_participant(seat(index)).unwrap();
    }
    let channels: Vec<_> = (0..deliveries).map(|_| x3_channel(4096)).collect();
    if deliveries > 0 {
        let factories: Vec<_> = channels
            .iter()
            .map(|(factory, _)| SeatX3Source::target(factory.clone()))
            .collect();
        assert!(room.set_seat_x3("seat-1", &factories));
    }
    // Built before arming: building a packet allocates, handling one must not.
    let frames: Vec<Vec<RxPacket>> = (0..WARM_FRAMES + MEASURED_FRAMES)
        .map(|sequence| (0..SEATS).map(|index| voice(index, sequence)).collect())
        .collect();
    let mut out = Vec::with_capacity(SEATS * 4);
    let mut run = |range: std::ops::Range<usize>, room: &mut Conference| -> usize {
        let mut delivered = 0;
        for frame in &frames[range] {
            for packet in frame {
                room.ingest(packet);
            }
            out.clear();
            room.tick(&mut out);
            delivered += channels
                .iter()
                .map(|(_, delivery)| return_buffers(delivery))
                .sum::<usize>();
        }
        delivered
    };
    run(0..WARM_FRAMES as usize, &mut room);

    ALLOCATIONS.store(0, Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    let delivered = run(
        WARM_FRAMES as usize..(WARM_FRAMES + MEASURED_FRAMES) as usize,
        &mut room,
    );
    ARMED.with(|armed| armed.set(false));
    (ALLOCATIONS.load(Ordering::Relaxed), delivered)
}

#[test]
fn an_intercepted_seat_adds_no_allocation_to_the_rooms_packet_path() {
    let (untapped, untapped_delivered) = allocations_of_the_room(0);
    let (tapped, tapped_delivered) = allocations_of_the_room(1);

    assert_eq!(untapped_delivered, 0, "nothing is delivered with no tap");
    assert!(
        tapped_delivered >= usize::from(MEASURED_FRAMES) * 2 - 8,
        "the loop really delivers both directions of the seat ({tapped_delivered} packets)"
    );
    assert!(untapped > 0, "the room allocates its outbound datagrams");
    assert_eq!(
        tapped, untapped,
        "the interception allocates nothing beyond what the room itself does"
    );
}

#[test]
fn two_interceptions_of_a_seat_stay_allocation_free_on_the_rooms_packet_path() {
    let (untapped, _) = allocations_of_the_room(0);
    let (tapped, delivered) = allocations_of_the_room(2);

    assert!(
        delivered >= usize::from(MEASURED_FRAMES) * 4 - 16,
        "both deliveries receive both directions of the seat ({delivered} packets)"
    );
    assert_eq!(
        tapped, untapped,
        "a set of two taps allocates nothing beyond what the room itself does"
    );
}
