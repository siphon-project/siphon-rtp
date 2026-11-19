//! Criterion perf gate for the **forwarding room fan-out**: what one inbound packet from the chosen
//! source costs the room, with no sockets.
//!
//! One iteration is `ForwardRoom::ingest` (source gate, constrained latch, RTP parse, reception
//! statistics) followed by `next_datagram` until the room is done: one translator rewrite per
//! receiving seat, written into the room's scratch. The sink is a `black_box` of the datagram, so the
//! number is the room's own cost; the per-datagram `send` syscall is the datapath's and is measured
//! with the integration measurement in `docs/cookbook/forwarding.md`.
//!
//! `video_per_inbound_packet` is the same for one video packet of a seat with a video stream: the
//! same translator rewrite per receiver, with a 1200-octet payload.
//!
//! `video_webrtc_receivers_per_inbound_packet` is that with every receiver a browser: the video is
//! bundled on the receiver's endpoint and protected under its DTLS-SRTP key (RFC 3711), so the
//! difference to `video_per_inbound_packet` is the SRTP `protect` per receiver.
//! `video_webrtc_source_per_inbound_packet` is one video packet of a browser source: unprotected under
//! its key, told from the audio by payload type, then fanned out to plain receivers.
//!
//! Throughput is set to the receiver count, so criterion reports the cost **per forwarded packet**
//! next to the cost per inbound packet, at 10, 100, 500 and 1000 (the cap) seats.
//!
//! `cargo bench -p siphon-rtp --bench forward_fanout_bench`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use std::net::SocketAddr;

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::forward::{ForwardRoom, ForwardSeatConfig, RoomCodec, VideoConfig};
use siphon_rtp_engine::sdp;
use siphon_rtp_engine::sdp::video::{RoomVideoFormat, VideoFeedback};
use siphon_rtp_engine::sdp::MediaDirection;
use siphon_rtp_media::rtcp;
use siphon_rtp_media::rtp::{write_packet, RtpHeader, RtpPacket};
use siphon_rtp_proto::ForwardMedia;
use siphon_rtp_srtp::srtcp_gcm::{FloorMasterKey, SrtcpGcmContext};

/// An AMR-WB octet-aligned 20 ms frame at mode 8 (23.85 kbit/s): 1 + 61 octets.
const PAYLOAD_BYTES: usize = 62;

/// A video fragment's payload: an FU-A of 1200 octets.
const VIDEO_PAYLOAD_BYTES: usize = 1200;

/// Seat `index`'s media SRTCP key (3GPP TS 33.180 §9.4.1): the MKI is the seat number.
fn media_key(index: usize) -> FloorMasterKey {
    FloorMasterKey::from_salt_96(index as u32, [index as u8; 16], &[0x5A ^ index as u8; 12])
}

fn room_of(seats: usize, media: ForwardMedia) -> ForwardRoom {
    room_keyed(seats, media, false)
}

fn room_keyed(seats: usize, media: ForwardMedia, keyed: bool) -> ForwardRoom {
    build_room(seats, media, keyed, false)
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

fn build_room(seats: usize, media: ForwardMedia, keyed: bool, video: bool) -> ForwardRoom {
    let offer = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                 m=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n";
    let codecs = sdp::parse(offer).unwrap().audio_codecs();
    let (codec, _) = RoomCodec::from_offer(&codecs).unwrap();
    let mut room = ForwardRoom::new("bench".to_string(), codec.with_media(media));
    for index in 0..seats {
        let address: SocketAddr = format!("192.0.2.{}:{}", 1 + index % 250, 4000 + index)
            .parse()
            .unwrap();
        room.add_seat(
            ForwardSeatConfig {
                tag: format!("seat-{index}"),
                endpoint: EndpointId(index as u64 + 1),
                egress_destination: address,
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
    room.set_source(Some("seat-0")).unwrap();
    room
}

fn inbound() -> RxPacket {
    let header = RtpHeader {
        marker: false,
        payload_type: 96,
        sequence: 1,
        timestamp: 320,
        ssrc: 0xA0A0_A0A0,
    };
    let mut datagram = vec![0u8; 12 + PAYLOAD_BYTES];
    write_packet(&header, &[0x5A; PAYLOAD_BYTES], &mut datagram).unwrap();
    RxPacket {
        endpoint: EndpointId(1),
        source: "192.0.2.1:4000".parse().unwrap(),
        arrival: 1_000_000,
        data: Bytes::from(datagram),
    }
}

/// A video RTP datagram of the chosen source: an FU-A fragment of 1200 payload octets (RFC 6184
/// §5.8), the size a video packet fills most of an Ethernet MTU with. `sequence` 1 is the start of an
/// IDR slice (`0x7C 0x85`), which opens the keyframe gate a source change closes; later ones are
/// middle fragments.
fn video_inbound(sequence: u16) -> RxPacket {
    let header = RtpHeader {
        marker: false,
        payload_type: 99,
        sequence,
        timestamp: 90_000,
        ssrc: 0xB0B0_B0B0,
    };
    let mut payload = [0x7C; VIDEO_PAYLOAD_BYTES];
    payload[1] = if sequence == 1 { 0x85 } else { 0x05 };
    let mut datagram = vec![0u8; 12 + VIDEO_PAYLOAD_BYTES];
    write_packet(&header, &payload, &mut datagram).unwrap();
    RxPacket {
        endpoint: EndpointId(10_000),
        source: "192.0.2.1:5000".parse().unwrap(),
        arrival: 1_000_000,
        data: Bytes::from(datagram),
    }
}

/// What one inbound video packet costs a translating room once the keyframe has opened every
/// receiver: the same gate and one translator rewrite per receiver as audio, on the video endpoint,
/// with a larger payload to copy, and the copy into the history a NACK is served from.
fn video_fan_out(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("forward_fan_out");
    for seats in [10usize, 100, 500, 1000] {
        let mut room = build_room(seats, ForwardMedia::Translate, false, true);
        // The keyframe opens every receiver; the packet measured is the one after it.
        let keyframe = video_inbound(1);
        room.ingest(&keyframe);
        while room.next_datagram(&keyframe).is_some() {}
        let packet = video_inbound(2);
        room.drain_events().for_each(drop);
        group.throughput(Throughput::Elements(seats as u64 - 1));
        group.bench_function(
            BenchmarkId::new("video_per_inbound_packet", seats),
            |bencher| {
                bencher.iter(|| {
                    room.ingest(black_box(&packet));
                    let mut forwarded = 0usize;
                    while let Some((_, _, datagram)) = room.next_datagram(&packet) {
                        forwarded += black_box(datagram).len();
                    }
                    black_box(forwarded)
                });
            },
        );
    }
    group.finish();
}

/// What the room sends browser seat `index` is protected under `browser_key(10 + index)`, what the
/// seat sends under `browser_key(100 + index)`.
fn browser_key(seed: usize) -> siphon_rtp_srtp::sdes::SrtpKeyMaterial {
    siphon_rtp_srtp::sdes::SrtpKeyMaterial::from_inline_bytes(&[seed as u8 + 1; 30]).unwrap()
}

/// A video room whose seat 0 is plain RTP (a video endpoint of its own) and whose other seats are
/// browsers: DTLS-SRTP keyed, video bundled on the audio endpoint (RFC 8843). With `browser_source`
/// the room's source is browser seat 1 instead.
fn browser_room(seats: usize, browser_source: bool) -> ForwardRoom {
    let offer = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                 m=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n";
    let codecs = sdp::parse(offer).unwrap().audio_codecs();
    let (codec, _) = RoomCodec::from_offer(&codecs).unwrap();
    let mut room = ForwardRoom::new("bench".to_string(), codec);
    for index in 0..seats {
        let address: SocketAddr = format!("192.0.2.{}:{}", 1 + index % 250, 4000 + index)
            .parse()
            .unwrap();
        let endpoint = EndpointId(index as u64 + 1);
        let browser = index != 0;
        let mut video = video_of(index);
        if browser {
            video.endpoint = endpoint;
            video.destination = address;
            video.bundled = true;
        }
        room.add_seat(
            ForwardSeatConfig {
                tag: format!("seat-{index}"),
                endpoint,
                egress_destination: address,
                accepted_source: SourceFilter::Any,
                latch: true,
                audio_payload_type: 96,
                telephone_event: None,
                secure: browser.then(|| {
                    siphon_rtp_srtp::leg::SecureLeg::new(
                        &browser_key(10 + index),
                        &browser_key(100 + index),
                    )
                }),
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
    room.set_source(Some(if browser_source { "seat-1" } else { "seat-0" }))
        .unwrap();
    room
}

/// What one inbound video packet of a plain source costs a room of browsers: one translator rewrite
/// and one SRTP protect per receiver, into the room's buffer.
fn video_webrtc_receivers(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("forward_fan_out");
    for seats in [10usize, 100, 500, 1000] {
        let mut room = browser_room(seats, false);
        let keyframe = video_inbound(1);
        room.ingest(&keyframe);
        while room.next_datagram(&keyframe).is_some() {}
        let packet = video_inbound(2);
        room.drain_events().for_each(drop);
        group.throughput(Throughput::Elements(seats as u64 - 1));
        group.bench_function(
            BenchmarkId::new("video_webrtc_receivers_per_inbound_packet", seats),
            |bencher| {
                bencher.iter(|| {
                    room.ingest(black_box(&packet));
                    let mut forwarded = 0usize;
                    while let Some((_, _, datagram)) = room.next_datagram(&packet) {
                        forwarded += black_box(datagram).len();
                    }
                    black_box(forwarded)
                });
            },
        );
    }
    group.finish();
}

/// What one inbound video packet of a browser source costs: the room unprotects it under the seat's
/// key, then fans it out to the plain seat and the other browsers. Each datagram needs a fresh SRTP
/// index, or the replay window refuses it, so a chunk of them is protected by the browser outside the
/// timed loop.
fn video_webrtc_source(criterion: &mut Criterion) {
    const CHUNK: usize = 1024;
    let mut group = criterion.benchmark_group("forward_fan_out");
    for seats in [10usize, 100] {
        let mut room = browser_room(seats, true);
        let mut browser = siphon_rtp_srtp::leg::SecureLeg::new(&browser_key(101), &browser_key(11));
        let mut sequence = 0u16;
        let mut next_packet = move || {
            sequence = sequence.wrapping_add(1);
            // The first packet is the IDR start that opens every receiver's gate.
            let clear = video_inbound(if sequence == 1 { 1 } else { 2 }).data;
            // The browser's video arrives on its audio endpoint (RFC 8843), from its own address.
            let mut clear = clear.to_vec();
            clear[2..4].copy_from_slice(&sequence.to_be_bytes());
            let mut wire = Vec::new();
            browser.protect(&clear, &mut wire).unwrap();
            RxPacket {
                endpoint: EndpointId(2),
                source: "192.0.2.2:4001".parse().unwrap(),
                arrival: 1_000_000,
                data: Bytes::from(wire),
            }
        };
        let warm = next_packet();
        room.ingest(&warm);
        while room.next_datagram(&warm).is_some() {}
        room.drain_events().for_each(drop);
        group.throughput(Throughput::Elements(seats as u64 - 1));
        group.bench_function(
            BenchmarkId::new("video_webrtc_source_per_inbound_packet", seats),
            |bencher| {
                bencher.iter_custom(|iterations| {
                    let mut elapsed = std::time::Duration::ZERO;
                    let mut remaining = iterations as usize;
                    while remaining > 0 {
                        let chunk: Vec<RxPacket> =
                            (0..remaining.min(CHUNK)).map(|_| next_packet()).collect();
                        remaining -= chunk.len();
                        let started = std::time::Instant::now();
                        for packet in &chunk {
                            room.ingest(black_box(packet));
                            let mut forwarded = 0usize;
                            while let Some((_, _, datagram)) = room.next_datagram(packet) {
                                forwarded += black_box(datagram).len();
                            }
                            black_box(forwarded);
                        }
                        elapsed += started.elapsed();
                    }
                    elapsed
                });
            },
        );
    }
    group.finish();
}

/// What one receiver's Generic NACK costs: the history lookup and one translator rewrite of the
/// packet it asks for (RFC 4585 §6.2.1).
fn video_nack_serve(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("forward_fan_out");
    let mut room = build_room(100, ForwardMedia::Translate, false, true);
    let keyframe = video_inbound(1);
    room.ingest(&keyframe);
    while room.next_datagram(&keyframe).is_some() {}
    let packet = video_inbound(2);
    room.ingest(&packet);
    let mut egress_sequence = None;
    while let Some((endpoint, _, datagram)) = room.next_datagram(&packet) {
        if endpoint == EndpointId(10_001) {
            egress_sequence = RtpPacket::parse(datagram)
                .ok()
                .map(|parsed| parsed.sequence);
        }
    }
    let mut nack = vec![0u8; rtcp::NACK_LEN];
    rtcp::write_nack(
        0xA0A0_A0A0,
        0xF000_0001,
        egress_sequence.unwrap_or_default(),
        0,
        &mut nack,
    )
    .unwrap();
    let nack = RxPacket {
        endpoint: EndpointId(10_001),
        source: "192.0.2.2:5001".parse().unwrap(),
        arrival: 1_000_000,
        data: Bytes::from(nack),
    };
    group.throughput(Throughput::Elements(1));
    group.bench_function("video_nack_serve", |bencher| {
        bencher.iter(|| {
            room.ingest(black_box(&nack));
            let mut served = 0usize;
            while let Some((_, _, datagram)) = room.next_datagram(&nack) {
                served += black_box(datagram).len();
            }
            black_box(served)
        });
    });
    group.finish();
}

fn fan_out(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("forward_fan_out");
    // `translate` rewrites the packet per receiver; `preserve` lends the arrived datagram out
    // unchanged, so the difference is the translator's cost.
    for (mode, media) in [
        ("per_inbound_packet", ForwardMedia::Translate),
        ("per_inbound_packet_preserve", ForwardMedia::Preserve),
    ] {
        for seats in [10usize, 100, 500, 1000] {
            bench_mode(&mut group, mode, media, seats);
        }
    }
    group.finish();
}

fn bench_mode(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    mode: &str,
    media: ForwardMedia,
    seats: usize,
) {
    {
        let mut room = room_of(seats, media);
        let packet = inbound();
        // Warm: the first packet starts the run and announces the source.
        room.ingest(&packet);
        while room.next_datagram(&packet).is_some() {}
        room.drain_events().for_each(drop);
        group.throughput(Throughput::Elements(seats as u64 - 1));
        group.bench_function(BenchmarkId::new(mode, seats), |bencher| {
            bencher.iter(|| {
                room.ingest(black_box(&packet));
                let mut forwarded = 0usize;
                while let Some((_, _, datagram)) = room.next_datagram(&packet) {
                    forwarded += black_box(datagram).len();
                }
                black_box(forwarded)
            });
        });
    }
}

/// What one inbound audio SRTCP datagram of a keyed talker costs a preserving room: one `open` under
/// the talker's key, then one `seal` per receiver under that receiver's own (3GPP TS 33.180
/// §9.4.1). Each datagram needs a fresh SRTCP index, or the replay window refuses it, so a chunk
/// of them is sealed by the talker's phone outside the timed loop.
fn srtcp_fan_out(criterion: &mut Criterion) {
    const CHUNK: usize = 1024;
    let mut group = criterion.benchmark_group("forward_fan_out");
    for seats in [10usize, 100, 500, 1000] {
        let mut room = room_keyed(seats, ForwardMedia::Preserve, true);
        let mut talker = SrtcpGcmContext::new(&[media_key(0)]).unwrap();
        let mut plain = [0u8; 128];
        let length =
            rtcp::write_sender_report(0xA0A0_A0A0, 0, 320, 1, 62, &[], &mut plain).unwrap();
        let mut next_packet = move || {
            let mut wire = Vec::new();
            talker.protect(&plain[..length], true, &mut wire).unwrap();
            RxPacket {
                endpoint: EndpointId(1),
                source: "192.0.2.1:4000".parse().unwrap(),
                arrival: 1_000_000,
                data: Bytes::from(wire),
            }
        };
        let warm = next_packet();
        room.ingest(&warm);
        while room.next_datagram(&warm).is_some() {}
        group.throughput(Throughput::Elements(seats as u64 - 1));
        group.bench_function(
            BenchmarkId::new("per_inbound_srtcp_preserve", seats),
            |bencher| {
                bencher.iter_custom(|iterations| {
                    let mut elapsed = std::time::Duration::ZERO;
                    let mut remaining = iterations as usize;
                    while remaining > 0 {
                        let chunk: Vec<RxPacket> =
                            (0..remaining.min(CHUNK)).map(|_| next_packet()).collect();
                        remaining -= chunk.len();
                        let started = std::time::Instant::now();
                        for packet in &chunk {
                            room.ingest(black_box(packet));
                            let mut forwarded = 0usize;
                            while let Some((_, _, datagram)) = room.next_datagram(packet) {
                                forwarded += black_box(datagram).len();
                            }
                            black_box(forwarded);
                        }
                        elapsed += started.elapsed();
                    }
                    elapsed
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    fan_out,
    video_fan_out,
    video_webrtc_receivers,
    video_webrtc_source,
    video_nack_serve,
    srtcp_fan_out
);
criterion_main!(benches);
