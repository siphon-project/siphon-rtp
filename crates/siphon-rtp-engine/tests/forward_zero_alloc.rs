//! The forwarding room's fan-out is on the per-packet hot path of a group call, so it must do **zero
//! heap allocation** once warm: the scratch buffers belong to the room and every translator writes
//! into them. A counting global allocator proves a tight ingest → fan-out loop over a 100-seat room
//! allocates nothing, across a source change as well (the change is a flag per translator).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::forward::{
    AppRequest, AppTarget, FloorConfig, ForwardRoom, ForwardSeatConfig, RoomCodec, VideoConfig,
};
use siphon_rtp_engine::sdp;
use siphon_rtp_engine::sdp::video::RoomVideoFormat;
use siphon_rtp_engine::sdp::MediaDirection;
use siphon_rtp_media::rtcp;
use siphon_rtp_media::rtp::{write_packet, RtpHeader};
use siphon_rtp_srtp::srtcp_gcm::{FloorMasterKey, SrtcpGcmContext};

/// A pass-through allocator that counts allocations on the armed thread only.
struct CountingAllocator;

/// The armed thread's own count: tests run in parallel, and another test's deliberate allocations
/// (the event strings of a source change) must not land in this one's window.
struct ThreadCount;

static ALLOCATIONS: ThreadCount = ThreadCount;

impl ThreadCount {
    fn load(&self, _: Ordering) -> usize {
        COUNT.with(Cell::get)
    }
}

thread_local! {
    static COUNT: Cell<usize> = const { Cell::new(0) };
    // Only the measuring thread arms counting, so the libtest harness's background-thread churn during
    // the same window is not miscounted. `const`-initialised so `alloc` never itself allocates.
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

// SAFETY: delegates straight to the system allocator; only bumps a relaxed counter when armed.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            COUNT.with(|count| count.set(count.get() + 1));
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

fn room() -> ForwardRoom {
    room_with(siphon_rtp_proto::ForwardMedia::Translate)
}

fn room_with(media: siphon_rtp_proto::ForwardMedia) -> ForwardRoom {
    room_keyed(media, false)
}

/// Seat `index`'s media SRTCP key (3GPP TS 33.180 §9.4.1): the MKI is the seat number.
fn media_key(index: usize) -> FloorMasterKey {
    FloorMasterKey::from_salt_96(index as u32, [index as u8; 16], &[0x5A ^ index as u8; 12])
}

fn room_keyed(media: siphon_rtp_proto::ForwardMedia, keyed: bool) -> ForwardRoom {
    build_room(media, keyed, false)
}

/// The video stream of seat `index`: endpoint `10_000 + index`, port `5000 + index`.
fn video_of(index: usize) -> VideoConfig {
    VideoConfig {
        endpoint: EndpointId(10_000 + index as u64),
        destination: format!("192.0.2.{}:{}", 1 + index % 250, 5000 + index)
            .parse()
            .unwrap(),
        accepted_source: SourceFilter::Any,
        payload_type: 99,
        direction: MediaDirection::SendRecv,
        egress_ssrc: 0xF000_0000 + index as u32,
        initial_sequence: 0,
        initial_timestamp: 0,
        format: RoomVideoFormat {
            packetization_mode: 1,
            profile_level_id: Some("640c1f".to_string()),
            fmtp: None,
        },
    }
}

fn build_room(media: siphon_rtp_proto::ForwardMedia, keyed: bool, video: bool) -> ForwardRoom {
    let offer = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                 m=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n";
    let codecs = sdp::parse(offer).unwrap().audio_codecs();
    let (codec, _) = RoomCodec::from_offer(&codecs).unwrap();
    let mut room = ForwardRoom::new("zero-alloc".to_string(), codec.with_media(media));
    for index in 0..SEATS {
        room.add_seat(
            ForwardSeatConfig {
                tag: format!("seat-{index}"),
                endpoint: EndpointId(index as u64 + 1),
                egress_destination: format!("192.0.2.{}:{}", 1 + index % 250, 4000 + index)
                    .parse()
                    .unwrap(),
                accepted_source: SourceFilter::Any,
                latch: true,
                audio_payload_type: 96,
                telephone_event: None,
                secure: None,
                secure_pending: false,
                ice_pending: false,
                egress_ssrc: 0xE000_0000 + index as u32,
                initial_sequence: 0,
                initial_timestamp: 0,
                floor: None,
                app_events: None,
                media_srtcp: if keyed {
                    vec![media_key(index)]
                } else {
                    Vec::new()
                },
                video: video.then(|| video_of(index)),
            },
            0,
        )
        .unwrap();
    }
    room
}

fn packet(talker: usize, sequence: u16) -> RxPacket {
    let header = RtpHeader {
        marker: false,
        payload_type: 96,
        sequence,
        timestamp: u32::from(sequence) * 320,
        ssrc: 0xA000_0000 + talker as u32,
    };
    let mut datagram = vec![0u8; 12 + 62];
    write_packet(&header, &[0x5A; 62], &mut datagram).unwrap();
    RxPacket {
        endpoint: EndpointId(talker as u64 + 1),
        source: format!("192.0.2.{}:{}", 1 + talker % 250, 4000 + talker)
            .parse()
            .unwrap(),
        arrival: u64::from(sequence) * 20_000,
        data: Bytes::from(datagram),
    }
}

#[test]
fn ingest_and_fan_out_make_no_heap_allocation() {
    let mut room = room();
    // Packets are built before arming: building one allocates, forwarding one must not.
    let from_first: Vec<RxPacket> = (1..=64).map(|sequence| packet(0, sequence)).collect();
    let from_second: Vec<RxPacket> = (1..=64).map(|sequence| packet(1, sequence)).collect();

    // Warm up: both talkers have been the source once, so every latch, statistics block and
    // translator has seen its first packet (the first packet of a seat latches its reply address).
    for talker in [0usize, 1, 0] {
        room.set_source(Some(&format!("seat-{talker}"))).unwrap();
        let warm = packet(talker, 1);
        room.ingest(&warm);
        while room.next_datagram(&warm).is_some() {}
    }
    room.drain_events().for_each(drop);

    // Steady talker: no source change, so not one allocation.
    room.set_source(Some("seat-0")).unwrap();
    room.ingest(&from_first[0]);
    while room.next_datagram(&from_first[0]).is_some() {}
    room.drain_events().for_each(drop);
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut forwarded = 0usize;
    for _ in 0..200 {
        for packet in &from_first {
            room.ingest(packet);
            while let Some((_, _, datagram)) = room.next_datagram(packet) {
                forwarded += std::hint::black_box(datagram).len();
            }
        }
    }
    let steady = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert!(forwarded > 0, "the loop forwarded something");
    assert_eq!(
        steady, 0,
        "fan-out allocated {steady} times across 12800 packets x 99 receivers (must be zero)"
    );

    // A talker change every 64 packets: a flag per translator, and the one source-started event the
    // change announces (two strings), nothing per packet.
    room.drain_events().for_each(drop);
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for round in 0..200 {
        let (tag, packets) = if round % 2 == 0 {
            ("seat-1", &from_second)
        } else {
            ("seat-0", &from_first)
        };
        room.set_source(Some(tag)).unwrap();
        for packet in packets {
            room.ingest(packet);
            while let Some((_, _, datagram)) = room.next_datagram(packet) {
                forwarded += std::hint::black_box(datagram).len();
            }
        }
        room.drain_events().for_each(drop);
    }
    let switching = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert!(
        switching <= 2 * 200,
        "{switching} allocations across 200 source changes (the event's two strings each, at most)"
    );
    assert!(forwarded > 0);
}

#[test]
fn a_preserving_rooms_fan_out_makes_no_heap_allocation_and_forwards_the_same_buffer() {
    let mut room = room_with(siphon_rtp_proto::ForwardMedia::Preserve);
    let packets: Vec<RxPacket> = (1..=64).map(|sequence| packet(0, sequence)).collect();
    room.set_source(Some("seat-0")).unwrap();
    room.ingest(&packets[0]);
    while room.next_datagram(&packets[0]).is_some() {}
    room.drain_events().for_each(drop);
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut forwarded = 0usize;
    for _ in 0..200 {
        for packet in &packets {
            room.ingest(packet);
            while let Some((_, _, datagram)) = room.next_datagram(packet) {
                // The datagram lent out is the very buffer that arrived: nothing was copied.
                assert!(std::ptr::eq(datagram.as_ptr(), packet.data.as_ptr()));
                forwarded += std::hint::black_box(datagram).len();
            }
        }
    }
    let steady = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert!(forwarded > 0);
    assert_eq!(
        steady, 0,
        "preserve fan-out allocated {steady} times (must be zero)"
    );
}

#[test]
fn a_keyed_preserving_rooms_srtcp_reseal_makes_no_heap_allocation() {
    // The talker's SRTCP is opened once into the room's buffer and sealed per receiver into the
    // room's output buffer: 99 seals per inbound datagram, nothing allocated once warm.
    let mut room = room_keyed(siphon_rtp_proto::ForwardMedia::Preserve, true);
    room.set_source(Some("seat-0")).unwrap();
    let mut talker = SrtcpGcmContext::new(&[media_key(0)]).unwrap();
    let mut plain = [0u8; 128];
    let length = rtcp::write_sender_report(
        0xA000_0000,
        0x0000_0001_8000_0000,
        320,
        1,
        62,
        &[],
        &mut plain,
    )
    .unwrap();
    // No APP part: an APP packet becomes an event for the controller, which allocates by design.
    // Fresh indices only: a replayed datagram is refused, so each one is sealed in advance.
    let packets: Vec<RxPacket> = (0..400u64)
        .map(|sequence| {
            let mut wire = Vec::new();
            talker.protect(&plain[..length], true, &mut wire).unwrap();
            RxPacket {
                endpoint: EndpointId(1),
                source: "192.0.2.1:4000".parse().unwrap(),
                arrival: sequence * 20_000,
                data: Bytes::from(wire),
            }
        })
        .collect();
    room.ingest(&packets[0]);
    while room.next_datagram(&packets[0]).is_some() {}
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut sent = 0usize;
    for packet in &packets[1..] {
        room.ingest(packet);
        while let Some((_, _, datagram)) = room.next_datagram(packet) {
            sent += std::hint::black_box(datagram).len();
        }
    }
    let steady = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert!(sent > 0);
    assert_eq!(
        steady, 0,
        "SRTCP reseal allocated {steady} times across 399 datagrams (must be zero)"
    );
    assert_eq!(room.seat_stats("seat-1").unwrap().media_srtcp_refused, 0);
}

#[test]
fn a_room_wide_rtcp_app_send_makes_no_heap_allocation() {
    // The send path writes every seat's datagram into the room's own scratch and lends it out.
    let mut room = {
        let offer = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                     m=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n";
        let codecs = sdp::parse(offer).unwrap().audio_codecs();
        let (codec, _) = RoomCodec::from_offer(&codecs).unwrap();
        ForwardRoom::new("zero-alloc-app".to_string(), codec)
    };
    for index in 0..SEATS {
        room.add_seat(
            ForwardSeatConfig {
                tag: format!("seat-{index}"),
                endpoint: EndpointId(index as u64 + 1),
                egress_destination: format!("192.0.2.{}:{}", 1 + index % 250, 4000 + index)
                    .parse()
                    .unwrap(),
                accepted_source: SourceFilter::Any,
                latch: true,
                audio_payload_type: 96,
                telephone_event: None,
                secure: None,
                secure_pending: false,
                ice_pending: false,
                egress_ssrc: 0xE000_0000 + index as u32,
                initial_sequence: 0,
                initial_timestamp: 0,
                floor: Some(FloorConfig {
                    endpoint: EndpointId(10_000 + index as u64),
                    destination: format!("192.0.2.{}:{}", 1 + index % 250, 8000 + index)
                        .parse()
                        .unwrap(),
                    accepted_source: SourceFilter::Any,
                    ice_gated: false,
                    keys: Vec::new(),
                }),
                app_events: None,
                media_srtcp: Vec::new(),
                video: None,
            },
            0,
        )
        .unwrap();
    }
    let request = AppRequest {
        stream: siphon_rtp_proto::RtcpAppStream::Floor,
        ssrc: None,
        name: *b"MCPT",
        subtype: 17,
        payload: vec![0; 12],
    };
    let everyone = AppTarget::Room { except: Vec::new() };
    let mut sent = 0usize;
    room.send_app(&everyone, &request, |_, _, data| sent += data.len())
        .unwrap();
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..200 {
        room.send_app(&everyone, &request, |_, _, data| {
            sent += std::hint::black_box(data).len();
        })
        .unwrap();
    }
    let allocated = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert!(sent > 0);
    assert_eq!(
        allocated, 0,
        "send_rtcp_app allocated {allocated} times across 200 room-wide sends"
    );
}

fn video_packet(talker: usize, sequence: u16, marker: bool) -> RxPacket {
    let header = RtpHeader {
        marker,
        payload_type: 99,
        sequence,
        timestamp: u32::from(sequence / 3) * 3000,
        ssrc: 0xB000_0000 + talker as u32,
    };
    let mut datagram = vec![0u8; 12 + 1200];
    write_packet(&header, &[0x7C; 1200], &mut datagram).unwrap();
    RxPacket {
        endpoint: EndpointId(10_000 + talker as u64),
        source: format!("192.0.2.{}:{}", 1 + talker % 250, 5000 + talker)
            .parse()
            .unwrap(),
        arrival: u64::from(sequence) * 11_000,
        data: Bytes::from(datagram),
    }
}

#[test]
fn video_ingest_and_fan_out_make_no_heap_allocation() {
    // 100 seats with video: one inbound packet is one translate per receiver on the 90 kHz clock.
    let mut room = build_room(siphon_rtp_proto::ForwardMedia::Translate, false, true);
    let from_first: Vec<RxPacket> = (1..=63)
        .map(|sequence| video_packet(0, sequence, sequence % 3 == 0))
        .collect();
    let from_second: Vec<RxPacket> = (1..=63)
        .map(|sequence| video_packet(1, sequence, sequence % 3 == 0))
        .collect();
    // Warm up: both talkers have been the source, so every latch, statistics block and video
    // translator has seen its first packet.
    for talker in [0usize, 1, 0] {
        room.set_source(Some(&format!("seat-{talker}"))).unwrap();
        let warm = video_packet(talker, 1, false);
        room.ingest(&warm);
        while room.next_datagram(&warm).is_some() {}
    }
    room.drain_events().for_each(drop);
    room.set_source(Some("seat-0")).unwrap();
    room.ingest(&from_first[0]);
    while room.next_datagram(&from_first[0]).is_some() {}
    room.drain_events().for_each(drop);
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut forwarded = 0usize;
    for _ in 0..100 {
        for packet in &from_first {
            room.ingest(packet);
            while let Some((_, _, datagram)) = room.next_datagram(packet) {
                forwarded += std::hint::black_box(datagram).len();
            }
        }
    }
    let steady = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert!(forwarded > 0, "the loop forwarded something");
    assert_eq!(
        steady, 0,
        "video fan-out allocated {steady} times across 6300 packets x 99 receivers (must be zero)"
    );
    // A switch every 63 packets: a flag per video translator, and the one event the change
    // announces (two strings), nothing per packet.
    room.drain_events().for_each(drop);
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for round in 0..100 {
        let (tag, packets) = if round % 2 == 0 {
            ("seat-1", &from_second)
        } else {
            ("seat-0", &from_first)
        };
        room.set_source(Some(tag)).unwrap();
        for packet in packets {
            room.ingest(packet);
            while let Some((_, _, datagram)) = room.next_datagram(packet) {
                forwarded += std::hint::black_box(datagram).len();
            }
        }
        room.drain_events().for_each(drop);
    }
    let switching = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert!(
        switching <= 100 * 8,
        "{switching} allocations across 100 switches: only the announcement may allocate"
    );
    assert!(forwarded > 0);
}
