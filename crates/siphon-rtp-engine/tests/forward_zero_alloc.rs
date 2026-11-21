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
use std::sync::Arc;

use bytes::Bytes;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::forward::{
    AppRequest, AppTarget, FloorConfig, ForwardRoom, ForwardSeatConfig, RoomCodec, VideoConfig,
};
use siphon_rtp_engine::sdp;
use siphon_rtp_engine::sdp::video::{RoomVideoFormat, VideoFeedback};
use siphon_rtp_engine::sdp::MediaDirection;
use siphon_rtp_engine::srtcp_ledger::SrtcpLedger;
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
        feedback: VideoFeedback::SUPPORTED,
        cname: "cname".to_string(),
        bundled: false,
    }
}

fn build_room(media: siphon_rtp_proto::ForwardMedia, keyed: bool, video: bool) -> ForwardRoom {
    build_room_on(media, keyed, video, Arc::default())
}

fn build_room_on(
    media: siphon_rtp_proto::ForwardMedia,
    keyed: bool,
    video: bool,
    ledger: Arc<SrtcpLedger>,
) -> ForwardRoom {
    let offer = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                 m=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n";
    let codecs = sdp::parse(offer).unwrap().audio_codecs();
    let (codec, _) = RoomCodec::from_offer(&codecs).unwrap();
    let mut room =
        ForwardRoom::with_ledger("zero-alloc".to_string(), codec.with_media(media), ledger);
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
    // A source change gates every receiver until a picture begins (RFC 6184 §5.8: an FU-A start of
    // an IDR slice is `0x7C 0x85`), so a run opens with one and goes on with middle fragments.
    let mut payload = [0x7C; 1200];
    payload[1] = if sequence == 1 { 0x85 } else { 0x05 };
    video_rtp(
        talker,
        sequence,
        u32::from(sequence / 3) * 3000,
        marker,
        &payload,
    )
}

/// A video RTP packet of seat `talker` with `payload`.
fn video_rtp(
    talker: usize,
    sequence: u16,
    timestamp: u32,
    marker: bool,
    payload: &[u8],
) -> RxPacket {
    let header = RtpHeader {
        marker,
        payload_type: 99,
        sequence,
        timestamp,
        ssrc: 0xB000_0000 + talker as u32,
    };
    let mut datagram = vec![0u8; 12 + payload.len()];
    write_packet(&header, payload, &mut datagram).unwrap();
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

#[test]
fn the_reception_gate_and_switching_it_make_no_heap_allocation() {
    // 100 seats with video; half of them have audio and video switched off, so every packet is
    // checked against the gate for 99 receivers and dropped for about half.
    let mut room = build_room(siphon_rtp_proto::ForwardMedia::Translate, false, true);
    let tags: Vec<String> = (0..SEATS).map(|index| format!("seat-{index}")).collect();
    let audio: Vec<RxPacket> = (1..=64).map(|sequence| packet(0, sequence)).collect();
    let video: Vec<RxPacket> = (1..=63)
        .map(|sequence| video_packet(0, sequence, sequence % 3 == 0))
        .collect();
    room.set_source(Some("seat-0")).unwrap();
    for warm in [&audio[0], &video[0]] {
        room.ingest(warm);
        while room.next_datagram(warm).is_some() {}
    }
    room.drain_events().for_each(drop);
    for tag in &tags[1..=50] {
        room.set_reception(tag, false, false).unwrap();
    }
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut forwarded = 0usize;
    for _ in 0..100 {
        for packet in audio.iter().chain(&video) {
            room.ingest(packet);
            while let Some((_, _, datagram)) = room.next_datagram(packet) {
                forwarded += std::hint::black_box(datagram).len();
            }
        }
    }
    let gated = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert!(forwarded > 0, "the other half was still forwarded to");
    assert_eq!(
        gated, 0,
        "the gated fan-out allocated {gated} times (must be zero)"
    );
    let stats = room.seat_stats("seat-1").unwrap();
    assert!(stats.reception_off_dropped_audio > 0 && stats.reception_off_dropped_video > 0);

    // Switching it back on and off between runs: a flag, a rebase and a keyframe request, no heap.
    let mut resumed = 0usize;
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for round in 0..100 {
        let on = round % 2 == 0;
        for tag in &tags[1..=50] {
            room.set_reception(tag, on, on).unwrap();
        }
        for packet in audio.iter().chain(&video) {
            room.ingest(packet);
            while let Some((_, _, datagram)) = room.next_datagram(packet) {
                resumed += std::hint::black_box(datagram).len();
            }
        }
    }
    let switching = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert_eq!(
        switching, 0,
        "switching reception allocated {switching} times across 100 rounds (must be zero)"
    );
    assert!(resumed > 0);
}

/// An RTCP datagram a video seat sends the room (its video endpoint, its signalled address).
fn video_rtcp(seat: usize, data: Vec<u8>) -> RxPacket {
    RxPacket {
        endpoint: EndpointId(10_000 + seat as u64),
        source: format!("192.0.2.{}:{}", 1 + seat % 250, 5000 + seat)
            .parse()
            .unwrap(),
        arrival: 0,
        data: Bytes::from(data),
    }
}

#[test]
fn the_keyframe_gate_the_parameter_set_replay_and_the_nack_serve_make_no_heap_allocation() {
    let mut room = build_room(siphon_rtp_proto::ForwardMedia::Translate, false, true);
    let sps = [0x67u8, 0x64, 0x00, 0x1F];
    let pps = [0x68u8, 0xEE, 0x3C];
    let idr = [0x7C, 0x85, 0x88, 0x84, 0x00];
    let slice = [0x41u8, 0x9A, 0x00];
    // One run of a source: pictures that are held back, its parameter sets, the keyframe that opens
    // every receiver (which replays the parameter sets first), then two pictures.
    let run = |talker: usize| -> Vec<RxPacket> {
        vec![
            video_rtp(talker, 1, 3_000, false, &slice),
            video_rtp(talker, 2, 6_000, false, &sps),
            video_rtp(talker, 3, 6_000, false, &pps),
            video_rtp(talker, 4, 6_000, false, &idr),
            video_rtp(talker, 5, 9_000, true, &slice),
            video_rtp(talker, 6, 12_000, true, &slice),
        ]
    };
    let (first, second) = (run(0), run(1));
    let feed = |room: &mut ForwardRoom, packets: &[RxPacket]| -> usize {
        let mut octets = 0;
        for packet in packets {
            room.ingest(packet);
            while let Some((_, _, datagram)) = room.next_datagram(packet) {
                octets += std::hint::black_box(datagram).len();
            }
        }
        octets
    };
    // Warm up: each talker has been the source with its parameter sets cached (the cache is
    // allocated the first time a seat sends one) and every translator has seen a run.
    for (tag, packets) in [("seat-0", &first), ("seat-1", &second), ("seat-0", &first)] {
        room.set_source(Some(tag)).unwrap();
        feed(&mut room, packets);
        room.drain_events().for_each(drop);
    }
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut forwarded = 0usize;
    for round in 0..100 {
        let (tag, packets) = if round % 2 == 0 {
            ("seat-1", &second)
        } else {
            ("seat-0", &first)
        };
        room.set_source(Some(tag)).unwrap();
        forwarded += feed(&mut room, packets);
        room.drain_events().for_each(drop);
    }
    let switching = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert!(forwarded > 0);
    // Only the source-started announcement (two strings) may allocate, once per switch.
    assert!(
        switching <= 100 * 2,
        "{switching} allocations across 100 gated switches with replay: only the announcement may allocate"
    );

    // A receiver's NACK, served from the history: what the room sent seat 2 last is asked for again.
    let mut last_sent = None;
    let probe = video_rtp(0, 7, 15_000, true, &slice);
    room.set_source(Some("seat-0")).unwrap();
    feed(&mut room, &first);
    room.ingest(&probe);
    while let Some((endpoint, _, datagram)) = room.next_datagram(&probe) {
        if endpoint == EndpointId(10_002) {
            last_sent = siphon_rtp_media::rtp::RtpPacket::parse(datagram)
                .ok()
                .map(|parsed| parsed.sequence);
        }
    }
    let egress_sequence = last_sent.expect("seat 2 was sent the probe");
    let mut nack = vec![0u8; rtcp::NACK_LEN];
    rtcp::write_nack(0xA0A0_A0A0, 0xF000_0002, egress_sequence, 0, &mut nack).unwrap();
    let nack = video_rtcp(2, nack);
    room.ingest(&nack);
    assert!(
        room.next_datagram(&nack).is_some(),
        "the packet is in the history"
    );
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut served = 0usize;
    for _ in 0..1_000 {
        room.ingest(&nack);
        while let Some((_, _, datagram)) = room.next_datagram(&nack) {
            served += std::hint::black_box(datagram).len();
        }
    }
    let nacks = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert!(served > 0);
    assert_eq!(
        nacks, 0,
        "serving a NACK allocated {nacks} times across 1000 requests"
    );
}

/// What the room sends WebRTC seat `index` is protected under `key(10 + index)`; what the seat sends
/// is protected under `key(100 + index)`.
fn browser_key(seed: usize) -> siphon_rtp_srtp::sdes::SrtpKeyMaterial {
    siphon_rtp_srtp::sdes::SrtpKeyMaterial::from_inline_bytes(&[seed as u8 + 1; 30]).unwrap()
}

fn room_leg(index: usize) -> siphon_rtp_srtp::leg::SecureLeg {
    siphon_rtp_srtp::leg::SecureLeg::new(&browser_key(10 + index), &browser_key(100 + index))
}

/// Seat `index`'s mirror image: protects what the room unprotects.
fn browser_leg(index: usize) -> siphon_rtp_srtp::leg::SecureLeg {
    siphon_rtp_srtp::leg::SecureLeg::new(&browser_key(100 + index), &browser_key(10 + index))
}

/// A 100-seat video room whose seat 0 is a plain RTP seat (video endpoint of its own) and whose other
/// seats are browsers: keyed by DTLS-SRTP, video bundled on the audio endpoint (RFC 8843).
fn build_browser_room() -> ForwardRoom {
    let offer = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                 m=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n";
    let codecs = sdp::parse(offer).unwrap().audio_codecs();
    let (codec, _) = RoomCodec::from_offer(&codecs).unwrap();
    let mut room = ForwardRoom::new("zero-alloc".to_string(), codec);
    for index in 0..SEATS {
        let endpoint = EndpointId(index as u64 + 1);
        let destination = format!("192.0.2.{}:{}", 1 + index % 250, 4000 + index)
            .parse()
            .unwrap();
        let browser = index != 0;
        let mut video = video_of(index);
        if browser {
            video.endpoint = endpoint;
            video.destination = destination;
            video.bundled = true;
        }
        room.add_seat(
            ForwardSeatConfig {
                tag: format!("seat-{index}"),
                endpoint,
                egress_destination: destination,
                accepted_source: SourceFilter::Any,
                latch: true,
                audio_payload_type: 96,
                telephone_event: None,
                secure: browser.then(|| room_leg(index)),
                secure_pending: false,
                ice_pending: false,
                egress_ssrc: 0xE000_0000 + index as u32,
                initial_sequence: 0,
                initial_timestamp: 0,
                floor: None,
                app_events: None,
                media_srtcp: Vec::new(),
                video: Some(video),
            },
            0,
        )
        .unwrap();
    }
    room
}

/// A video RTP datagram of browser seat `talker`, protected by its own key, on its audio endpoint.
fn browser_video(
    leg: &mut siphon_rtp_srtp::leg::SecureLeg,
    talker: usize,
    sequence: u16,
    payload: &[u8],
) -> RxPacket {
    let clear = video_rtp(
        talker,
        sequence,
        u32::from(sequence / 3) * 3000,
        sequence.is_multiple_of(3),
        payload,
    );
    let mut wire = Vec::new();
    leg.protect(&clear.data, &mut wire).unwrap();
    RxPacket {
        endpoint: EndpointId(talker as u64 + 1),
        source: format!("192.0.2.{}:{}", 1 + talker % 250, 4000 + talker)
            .parse()
            .unwrap(),
        arrival: clear.arrival,
        data: Bytes::from(wire),
    }
}

#[test]
fn browser_video_egress_and_ingest_make_no_heap_allocation() {
    let mut room = build_browser_room();
    // Egress to 99 browsers: a plain source's packet is translated once per receiver and protected
    // under each receiver's own key, into the room's buffer.
    let from_plain: Vec<RxPacket> = (1..=63)
        .map(|sequence| video_packet(0, sequence, sequence % 3 == 0))
        .collect();
    room.set_source(Some("seat-0")).unwrap();
    // Warm up: every receiver's SRTP context has seen its stream (the per-SSRC state is created on
    // the first packet), and the history and statistics exist.
    for packet in &from_plain {
        room.ingest(packet);
        while room.next_datagram(packet).is_some() {}
    }
    room.drain_events().for_each(drop);
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut forwarded = 0usize;
    for _ in 0..20 {
        for packet in &from_plain {
            room.ingest(packet);
            while let Some((_, _, datagram)) = room.next_datagram(packet) {
                forwarded += std::hint::black_box(datagram).len();
            }
        }
    }
    let egress = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert!(forwarded > 0, "the loop forwarded something");
    assert_eq!(
        egress, 0,
        "SRTP video egress allocated {egress} times across 1260 packets x 99 receivers (must be zero)"
    );

    // Ingest from a browser: the datagram is unprotected into the room's buffer, told from the audio
    // by payload type, and fanned out to the plain seat and the other browsers.
    let mut talker = browser_leg(1);
    let mut payload = [0x7C; 1200];
    payload[1] = 0x85;
    let first = browser_video(&mut talker, 1, 1, &payload);
    payload[1] = 0x05;
    let rest: Vec<RxPacket> = (2..=1_000)
        .map(|sequence| browser_video(&mut talker, 1, sequence, &payload))
        .collect();
    room.set_source(Some("seat-1")).unwrap();
    room.ingest(&first);
    while room.next_datagram(&first).is_some() {}
    room.drain_events().for_each(drop);
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut forwarded = 0usize;
    for packet in &rest {
        room.ingest(packet);
        while let Some((_, _, datagram)) = room.next_datagram(packet) {
            forwarded += std::hint::black_box(datagram).len();
        }
    }
    let ingest = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert!(forwarded > 0, "the browser's video was forwarded");
    assert_eq!(
        ingest, 0,
        "SRTP video ingest and fan-out allocated {ingest} times across 999 packets x 99 receivers (must be zero)"
    );
}

#[test]
fn a_preserving_rooms_video_fan_out_makes_no_heap_allocation_and_forwards_the_same_buffer() {
    // 100 seats with video: the source's SRTP video is lent to 99 receivers as it arrived, with no
    // translate, no keyframe gate and no copy (the NACK history stores it in a fixed ring).
    let mut room = build_room(siphon_rtp_proto::ForwardMedia::Preserve, false, true);
    let packets: Vec<RxPacket> = (1..=63)
        .map(|sequence| video_packet(0, sequence, sequence % 3 == 0))
        .collect();
    room.set_source(Some("seat-0")).unwrap();
    room.ingest(&packets[0]);
    while room.next_datagram(&packets[0]).is_some() {}
    room.drain_events().for_each(drop);
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut forwarded = 0usize;
    for _ in 0..100 {
        for packet in &packets {
            room.ingest(packet);
            while let Some((_, _, datagram)) = room.next_datagram(packet) {
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
        "preserve video fan-out allocated {steady} times across 6300 packets x 99 receivers (must be zero)"
    );
    let stats = room.seat_stats("seat-1").unwrap();
    assert_eq!(stats.video_dropped_awaiting_keyframe, 0, "no keyframe gate");
}

/// A video SR sealed on `phone`, as a keyed seat sends it on its video endpoint.
fn sealed_video_report(phone: &mut SrtcpGcmContext, seat: usize, arrival: u64) -> RxPacket {
    let mut plain = [0u8; 128];
    let length = rtcp::write_sender_report(
        0xB000_0000 + seat as u32,
        0x0000_0001_8000_0000,
        90_000,
        1,
        1200,
        &[],
        &mut plain,
    )
    .unwrap();
    let mut wire = Vec::new();
    phone.protect(&plain[..length], true, &mut wire).unwrap();
    let mut packet = video_rtcp(seat, wire);
    packet.arrival = arrival;
    packet
}

#[test]
fn a_keyed_preserving_rooms_video_srtcp_reseal_makes_no_heap_allocation() {
    // The talker's video SRTCP is opened once on the video stream's own replay window into the room's
    // buffer and sealed per receiver on the seat's one outgoing index: nothing allocated once warm.
    let mut room = build_room(siphon_rtp_proto::ForwardMedia::Preserve, true, true);
    room.set_source(Some("seat-0")).unwrap();
    let mut talker = SrtcpGcmContext::new(&[media_key(0)]).unwrap();
    let packets: Vec<RxPacket> = (0..400u64)
        .map(|sequence| sealed_video_report(&mut talker, 0, sequence * 20_000))
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
        "video SRTCP reseal allocated {steady} times across 399 datagrams x 99 receivers (must be zero)"
    );
    assert_eq!(room.seat_stats("seat-1").unwrap().media_srtcp_refused, 0);
    assert_eq!(room.seat_stats("seat-0").unwrap().media_srtcp_refused, 0);
}

#[test]
fn a_preserving_rooms_nack_serve_from_the_stored_srtp_makes_no_heap_allocation() {
    let mut room = build_room(siphon_rtp_proto::ForwardMedia::Preserve, true, true);
    room.set_source(Some("seat-0")).unwrap();
    let media: Vec<RxPacket> = (1..=63)
        .map(|sequence| video_packet(0, sequence, false))
        .collect();
    for packet in &media {
        room.ingest(packet);
        while room.next_datagram(packet).is_some() {}
    }
    // Seat 2 lost sequence numbers 10 and 12 over and over; each NACK is sealed in advance, one
    // index each.
    let mut receiver = SrtcpGcmContext::new(&[media_key(2)]).unwrap();
    let nacks: Vec<RxPacket> = (0..300u64)
        .map(|_| {
            let mut plain = [0u8; 64];
            let mut length = rtcp::write_empty_receiver_report(0xB000_0002, &mut plain).unwrap();
            length +=
                rtcp::write_nack(0xB000_0002, 0xB000_0000, 10, 0b10, &mut plain[length..]).unwrap();
            let mut wire = Vec::new();
            receiver.protect(&plain[..length], true, &mut wire).unwrap();
            video_rtcp(2, wire)
        })
        .collect();
    room.ingest(&nacks[0]);
    while room.next_datagram(&nacks[0]).is_some() {}
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut resent = 0usize;
    for nack in &nacks[1..] {
        room.ingest(nack);
        while let Some((_, _, datagram)) = room.next_datagram(nack) {
            resent += std::hint::black_box(datagram).len();
        }
    }
    let steady = ALLOCATIONS.load(Ordering::Relaxed) - before;
    ARMED.with(|armed| armed.set(false));
    assert!(resent > 0, "the stored packets were sent again");
    assert_eq!(
        steady, 0,
        "NACK serve allocated {steady} times across 299 NACKs (must be zero)"
    );
    assert!(room.seat_stats("seat-2").unwrap().nack_answered >= 598);
}

#[test]
fn two_rooms_sealing_on_one_ledger_make_no_heap_allocation_and_never_repeat_an_index() {
    // Both rooms hold seat keys with the same material, so their reseals draw from one counter per
    // key: one compare-and-swap each, nothing allocated once warm.
    let ledger: Arc<SrtcpLedger> = Arc::default();
    let mut rooms = [
        build_room_on(
            siphon_rtp_proto::ForwardMedia::Preserve,
            true,
            true,
            ledger.clone(),
        ),
        build_room_on(
            siphon_rtp_proto::ForwardMedia::Preserve,
            true,
            true,
            ledger.clone(),
        ),
    ];
    let mut talker = SrtcpGcmContext::new(&[media_key(0)]).unwrap();
    let packets: Vec<RxPacket> = (0..200u64)
        .map(|sequence| sealed_video_report(&mut talker, 0, sequence * 20_000))
        .collect();
    for room in &mut rooms {
        room.set_source(Some("seat-0")).unwrap();
        room.ingest(&packets[0]);
        while room.next_datagram(&packets[0]).is_some() {}
    }
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut sent = 0usize;
    for (position, packet) in packets[1..].iter().enumerate() {
        let room = &mut rooms[position % 2];
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
        "ledger-backed reseal allocated {steady} times (must be zero)"
    );
    // Seat 1 is a receiver of both rooms under media_key(1): the two warm-up reports and the 199
    // measured ones each took one index of the one counter, none twice.
    assert_eq!(ledger.counter_for(&media_key(1)).next(), 2 + 199);
}

#[test]
fn a_leased_ledger_adds_no_heap_allocation_to_the_seal() {
    // Once a checkpoint exists every counter has a lease; the check on the seal is an atomic load.
    let ledger: Arc<SrtcpLedger> = Arc::default();
    let mut room = build_room_on(
        siphon_rtp_proto::ForwardMedia::Preserve,
        true,
        true,
        ledger.clone(),
    );
    let _ = ledger.checkpoint(1 << 20, Some(1));
    room.set_source(Some("seat-0")).unwrap();
    let mut talker = SrtcpGcmContext::new(&[media_key(0)]).unwrap();
    let packets: Vec<RxPacket> = (0..200u64)
        .map(|sequence| sealed_video_report(&mut talker, 0, sequence * 20_000))
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
        "leased reseal allocated {steady} times (must be zero)"
    );
    assert_eq!(ledger.lease_refused(), 0);
}
