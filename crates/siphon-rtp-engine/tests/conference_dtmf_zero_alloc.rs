//! Forwarding a telephone-event (`dtmf: forward`) is on the per-packet path of a conference, so
//! regenerating it must not allocate beyond the one `Bytes` per outbound datagram that the mix path
//! also makes. A counting global allocator proves a tight ingest -> regenerate loop over a 63-target
//! room allocates exactly one buffer per packet sent and nothing else: no scratch growth, no
//! per-event bookkeeping.

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
use siphon_rtp_engine::conference::{Conference, ParticipantConfig, SeatTelemetry};
use siphon_rtp_engine::sdp::TelephoneEvent;
use siphon_rtp_media::rtp::{write_packet, RtpHeader};
use siphon_rtp_proto::ConferenceDtmf;

/// A pass-through allocator that counts allocations on the armed thread only.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting, so the libtest harness's background-thread churn is
    // not miscounted. `const`-initialised so `alloc` never itself allocates.
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

const TARGETS: usize = 63;

fn seat(index: usize, forward: bool, clock_rate_hz: u32) -> ParticipantConfig {
    let octet = u8::try_from(index + 1).unwrap();
    ParticipantConfig {
        tag: format!("seat-{index}"),
        decoder: Box::new(G711::alaw()),
        encoder: Box::new(G711::alaw()),
        ingress_endpoint: EndpointId(index as u64 + 1),
        egress_endpoint: EndpointId(index as u64 + 1),
        egress_dst: format!("192.0.2.{octet}:4000").parse().unwrap(),
        accepted_source: SourceFilter::Exact(format!("192.0.2.{octet}").parse().unwrap()),
        latch: false,
        egress_ssrc: 0xC000_0000 + index as u32,
        egress_payload_type: 8,
        mos_codec: siphon_rtp_hep::mos::Codec::G711,
        telephone_event: Some(TelephoneEvent {
            payload_type: 101,
            clock_rate_hz,
        }),
        dtmf: if forward {
            ConferenceDtmf::Forward
        } else {
            ConferenceDtmf::Events
        },
        secure: None,
        secure_pending: false,
        text: None,
        ice_pending: false,
        routing: Default::default(),
        telemetry: SeatTelemetry::default(),
        call: None,
    }
}

fn event(sequence: u16, timestamp: u32, end: bool) -> RxPacket {
    let header = RtpHeader {
        marker: false,
        payload_type: 101,
        sequence,
        timestamp,
        ssrc: 0x2000_0000,
    };
    let mut datagram = vec![0u8; 16];
    write_packet(
        &header,
        &[5, (u8::from(end) << 7) | 10, 0x01, 0x40],
        &mut datagram,
    )
    .unwrap();
    RxPacket {
        endpoint: EndpointId(1),
        source: "192.0.2.1:5000".parse().unwrap(),
        arrival: 0,
        data: Bytes::from(datagram),
    }
}

#[test]
fn regenerating_an_event_allocates_only_the_outbound_buffers() {
    let mut conference = Conference::new("zero-alloc".into(), 0);
    // The owner's event clock is 8 kHz here: the rescale path is a straight copy, and the 48 kHz
    // rescale is the same loop over the same scratch.
    conference.add_participant(seat(0, true, 8000)).unwrap();
    for index in 1..=TARGETS {
        conference
            .add_participant(seat(index, false, 8000))
            .unwrap();
    }
    // Built before arming: building a packet allocates, forwarding one must not.
    let updates: Vec<RxPacket> = (0..64)
        .map(|index| event(index, 8000, index == 63))
        .collect();
    let mut out = Vec::with_capacity(TARGETS);

    // Warm up: the first packet of an event starts it on every target, and the first End raises the
    // `dtmf` event (a one-off per press, outside this loop's budget).
    for packet in &updates {
        conference.ingest(packet);
        out.clear();
        conference.drain_forwarded(&mut out);
    }
    let _ = conference.drain_events().count();

    ALLOCATIONS.store(0, Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    let mut sent = 0usize;
    for packet in &updates {
        conference.ingest(packet);
        out.clear();
        conference.drain_forwarded(&mut out);
        sent += out.len();
    }
    ARMED.with(|armed| armed.set(false));
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);

    assert_eq!(sent, 64 * TARGETS, "every target got every packet");
    assert_eq!(
        allocations, sent,
        "exactly one buffer per outbound datagram, nothing for the regeneration itself"
    );
}
