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
use siphon_rtp_engine::sdp::video::RoomVideoFormat;
use siphon_rtp_engine::sdp::MediaDirection;
use siphon_rtp_media::rtcp;
use siphon_rtp_media::rtp::{write_packet, RtpHeader};
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
/// §5.8), the size a video packet fills most of an Ethernet MTU with.
fn video_inbound() -> RxPacket {
    let header = RtpHeader {
        marker: false,
        payload_type: 99,
        sequence: 1,
        timestamp: 90_000,
        ssrc: 0xB0B0_B0B0,
    };
    let mut datagram = vec![0u8; 12 + VIDEO_PAYLOAD_BYTES];
    write_packet(&header, &[0x7C; VIDEO_PAYLOAD_BYTES], &mut datagram).unwrap();
    RxPacket {
        endpoint: EndpointId(10_000),
        source: "192.0.2.1:5000".parse().unwrap(),
        arrival: 1_000_000,
        data: Bytes::from(datagram),
    }
}

/// What one inbound video packet costs a translating room: the same gate and one translator rewrite
/// per receiver as audio, on the video endpoint, with a larger payload to copy.
fn video_fan_out(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("forward_fan_out");
    for seats in [10usize, 100, 500, 1000] {
        let mut room = build_room(seats, ForwardMedia::Translate, false, true);
        let packet = video_inbound();
        room.ingest(&packet);
        while room.next_datagram(&packet).is_some() {}
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

criterion_group!(benches, fan_out, video_fan_out, srtcp_fan_out);
criterion_main!(benches);
