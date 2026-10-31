//! Transcoding in a forwarding room is on the per-packet hot path of a group call with seats in
//! several codecs, so it must do **zero heap allocation** once warm: the decode, the resample, the
//! encode per codec group and the per-seat packet all run in buffers the room sized when the first
//! cross-codec seat arrived. A counting global allocator proves a tight ingest -> fan-out loop over a
//! 100-seat room split over two codec groups allocates nothing, for a source in the room codec and
//! for a source in another codec. (A source *change* rebuilds the decoder, once per talk spurt, and
//! is outside the measured loop.)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::forward::{ForwardRoom, ForwardSeatConfig, RoomCodec};
use siphon_rtp_media::rtp::{write_packet, RtpHeader};

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

const SEATS: usize = 100;
/// Seat 0 is in the room codec (PCMU); 1..=50 are PCMA; 51..=99 are Opus.
const LAST_PCMA: usize = 50;

fn config(index: usize, audio_payload_type: u8) -> ForwardSeatConfig {
    ForwardSeatConfig {
        tag: format!("seat-{index}"),
        endpoint: EndpointId(index as u64 + 1),
        egress_destination: format!("192.0.2.{}:{}", 1 + index % 250, 4000 + index)
            .parse()
            .unwrap(),
        accepted_source: SourceFilter::Any,
        latch: true,
        audio_payload_type,
        telephone_event: None,
        secure: None,
        secure_pending: false,
        ice_pending: false,
        egress_ssrc: 0xE000_0000 + index as u32,
        initial_sequence: 0,
        initial_timestamp: 0,
        floor: None,
        app_events: None,
    }
}

fn room() -> ForwardRoom {
    let spec = CodecSpec::new(0, "PCMU", 8000, 1, 20);
    let (codec, _) = RoomCodec::from_offer(std::slice::from_ref(&spec)).unwrap();
    let mut room = ForwardRoom::new("transcode-zero-alloc".to_string(), codec);
    room.add_seat(config(0, 0), 0).unwrap();
    for index in 1..SEATS {
        let spec = if index <= LAST_PCMA {
            CodecSpec::new(8, "PCMA", 8000, 1, 20)
        } else {
            CodecSpec::new(111, "opus", 48_000, 2, 20)
        };
        room.add_cross_codec_seat(config(index, spec.payload_type), spec, 0)
            .unwrap();
    }
    room
}

/// 64 packets from `talker` in `spec`, a 440 Hz tone, built before arming.
fn packets(talker: usize, spec: &CodecSpec) -> Vec<RxPacket> {
    stream(talker, spec, 64)
}

/// `count` consecutive packets from `talker` in `spec`, a 440 Hz tone, built before arming.
fn stream(talker: usize, spec: &CodecSpec, count: usize) -> Vec<RxPacket> {
    let mut encoder = factory::encoder_for(spec).unwrap();
    let rate = encoder.params().sample_rate_hz as usize;
    let frame = rate / 50;
    let clock_step = (spec.clock_rate_hz / 50) as usize;
    (0..count)
        .map(|step| {
            let pcm: Vec<i16> = (0..frame)
                .map(|n| {
                    let t = (step * frame + n) as f64 / rate as f64;
                    ((t * 440.0 * std::f64::consts::TAU).sin() * 8000.0) as i16
                })
                .collect();
            let mut payload = vec![0u8; 1500];
            let length = encoder.encode(&pcm, &mut payload).unwrap();
            let header = RtpHeader {
                marker: false,
                payload_type: spec.payload_type,
                sequence: step as u16 + 1,
                timestamp: (step * clock_step) as u32,
                ssrc: 0xA000_0000 + talker as u32,
            };
            let mut datagram = vec![0u8; 12 + length];
            write_packet(&header, &payload[..length], &mut datagram).unwrap();
            RxPacket {
                endpoint: EndpointId(talker as u64 + 1),
                source: format!("192.0.2.{}:{}", 1 + talker % 250, 4000 + talker)
                    .parse()
                    .unwrap(),
                arrival: (step as u64 + 1) * 20_000,
                data: Bytes::from(datagram),
            }
        })
        .collect()
}

fn measure(room: &mut ForwardRoom, packets: &[RxPacket]) -> (usize, usize) {
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut forwarded = 0usize;
    for _ in 0..100 {
        for packet in packets {
            room.ingest(packet);
            while let Some((_, _, datagram)) = room.next_datagram(packet) {
                forwarded += std::hint::black_box(datagram).len();
            }
        }
    }
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    (allocations, forwarded)
}

#[test]
fn transcoding_a_room_codec_source_to_two_codec_groups_makes_no_heap_allocation() {
    let mut room = room();
    let from_source = packets(0, &CodecSpec::new(0, "PCMU", 8000, 1, 20));
    room.set_source(Some("seat-0")).unwrap();
    // Warm: the first packet starts the run (rebuilds the decoder), latches every seat's reply
    // address and announces the source.
    room.ingest(&from_source[0]);
    while room.next_datagram(&from_source[0]).is_some() {}
    room.drain_events().for_each(drop);

    let (allocations, forwarded) = measure(&mut room, &from_source);
    assert!(forwarded > 0, "the loop forwarded something");
    assert_eq!(
        allocations, 0,
        "transcode fan-out allocated {allocations} times across 6400 packets x 99 receivers"
    );
    let stats = room.transcode_stats();
    assert!(stats.decodes >= 6400, "decoded once per packet: {stats:?}");
    assert!(
        stats.encodes >= 2 * 6400,
        "encoded once per group: {stats:?}"
    );
    assert_eq!(stats.dropped, 0);
}

#[test]
fn transcoding_a_cross_codec_source_makes_no_heap_allocation() {
    let mut room = room();
    // seat-1 is PCMA; its group-mates get its packets as they came, seat 0 (PCMU) and the Opus group
    // get the decode and the encodes.
    let from_source = packets(1, &CodecSpec::new(8, "PCMA", 8000, 1, 20));
    room.set_source(Some("seat-1")).unwrap();
    room.ingest(&from_source[0]);
    while room.next_datagram(&from_source[0]).is_some() {}
    room.drain_events().for_each(drop);

    let (allocations, forwarded) = measure(&mut room, &from_source);
    assert!(forwarded > 0);
    assert_eq!(
        allocations, 0,
        "cross-codec source fan-out allocated {allocations} times across 6400 packets"
    );
    assert_eq!(room.transcode_stats().dropped, 0);
}

/// Every 8th packet of the stream is lost on the way, so the loop ingests the survivors and the room
/// conceals the missing frame for every transcoded receiver before each one that follows a gap.
fn survivors(talker: usize, spec: &CodecSpec, count: usize) -> Vec<RxPacket> {
    stream(talker, spec, count)
        .into_iter()
        .enumerate()
        .filter(|(index, _)| index % 8 != 5)
        .map(|(_, packet)| packet)
        .collect()
}

fn measure_once(room: &mut ForwardRoom, packets: &[RxPacket]) -> (usize, usize) {
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut forwarded = 0usize;
    for packet in packets {
        room.ingest(packet);
        while let Some((_, _, datagram)) = room.next_datagram(packet) {
            forwarded += std::hint::black_box(datagram).len();
        }
    }
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    (allocations, forwarded)
}

#[test]
fn concealing_lost_packets_for_a_room_codec_source_makes_no_heap_allocation() {
    let mut room = room();
    let from_source = survivors(0, &CodecSpec::new(0, "PCMU", 8000, 1, 20), 4000);
    room.set_source(Some("seat-0")).unwrap();
    for packet in &from_source[..8] {
        room.ingest(packet);
        while room.next_datagram(packet).is_some() {}
    }
    room.drain_events().for_each(drop);
    let (allocations, forwarded) = measure_once(&mut room, &from_source[8..]);
    assert!(forwarded > 0);
    let stats = room.transcode_stats();
    assert!(
        stats.concealed >= 400,
        "the loop concealed the lost frames: {stats:?}"
    );
    assert_eq!(stats.conceal_failed, 0);
    assert_eq!(
        allocations,
        0,
        "concealing allocated {allocations} times across {} packets with {} concealed frames",
        from_source.len(),
        stats.concealed
    );
}

#[test]
fn concealing_lost_packets_for_a_cross_codec_source_makes_no_heap_allocation() {
    let mut room = room();
    let from_source = survivors(1, &CodecSpec::new(8, "PCMA", 8000, 1, 20), 4000);
    room.set_source(Some("seat-1")).unwrap();
    for packet in &from_source[..8] {
        room.ingest(packet);
        while room.next_datagram(packet).is_some() {}
    }
    room.drain_events().for_each(drop);
    let (allocations, forwarded) = measure_once(&mut room, &from_source[8..]);
    assert!(forwarded > 0);
    let stats = room.transcode_stats();
    assert!(stats.concealed >= 400, "{stats:?}");
    assert_eq!(stats.conceal_failed, 0);
    assert_eq!(
        allocations, 0,
        "concealing a cross-codec source allocated {allocations} times"
    );
}
