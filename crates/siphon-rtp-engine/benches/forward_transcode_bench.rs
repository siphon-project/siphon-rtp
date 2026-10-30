//! Criterion perf gate for **cross-codec seats in a forwarding room**: what one inbound packet costs
//! when the room decodes it once, encodes it once per codec group and packetizes it per seat.
//!
//! The room is 100 seats: one PCMU seat (the room codec), 50 PCMA seats (one codec group) and 49
//! Opus seats (the other). One iteration is `ForwardRoom::ingest` followed by `next_datagram` until
//! the room is done, with the datagram sunk into `black_box` (no sockets). Throughput is the receiver
//! count, so criterion reports the cost per forwarded packet beside the cost per inbound packet.
//!
//! * `room_codec_source`: PCMU in; 1 decode, 2 encodes, 99 packets (50 PCMA + 49 Opus).
//! * `cross_codec_source`: a PCMA seat in; its 49 group mates get its packet as it came, 1 decode and
//!   1 PCMU encode for the room codec, 1 Opus encode, and 99 packets.
//!
//! `cargo bench -p siphon-rtp --bench forward_transcode_bench`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::forward::{ForwardRoom, ForwardSeatConfig, RoomCodec};
use siphon_rtp_media::rtp::{write_packet, RtpHeader};

const SEATS: usize = 100;
/// Seat 0 is PCMU (the room codec); 1..=50 are PCMA; 51..=99 are Opus.
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
    let mut room = ForwardRoom::new("bench".to_string(), codec);
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

/// One 20 ms 440 Hz frame from seat `talker`, encoded as `spec`.
fn inbound(talker: usize, spec: &CodecSpec) -> RxPacket {
    let mut encoder = factory::encoder_for(spec).unwrap();
    let rate = encoder.params().sample_rate_hz as usize;
    let pcm: Vec<i16> = (0..rate / 50)
        .map(|n| ((n as f64 / rate as f64 * 440.0 * std::f64::consts::TAU).sin() * 8000.0) as i16)
        .collect();
    let mut payload = vec![0u8; 1500];
    let length = encoder.encode(&pcm, &mut payload).unwrap();
    let header = RtpHeader {
        marker: false,
        payload_type: spec.payload_type,
        sequence: 1,
        timestamp: 160,
        ssrc: 0xA0A0_A0A0,
    };
    let mut datagram = vec![0u8; 12 + length];
    write_packet(&header, &payload[..length], &mut datagram).unwrap();
    RxPacket {
        endpoint: EndpointId(talker as u64 + 1),
        source: format!("192.0.2.{}:{}", 1 + talker % 250, 4000 + talker)
            .parse()
            .unwrap(),
        arrival: 1_000_000,
        data: Bytes::from(datagram),
    }
}

fn fan_out(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("forward_transcode");
    group.throughput(Throughput::Elements(SEATS as u64 - 1));
    for (name, talker, spec) in [
        (
            "room_codec_source",
            0usize,
            CodecSpec::new(0, "PCMU", 8000, 1, 20),
        ),
        (
            "cross_codec_source",
            1usize,
            CodecSpec::new(8, "PCMA", 8000, 1, 20),
        ),
    ] {
        let mut room = room();
        room.set_source(Some(&format!("seat-{talker}"))).unwrap();
        let packet = inbound(talker, &spec);
        // Warm: the first packet starts the run and announces the source.
        room.ingest(&packet);
        while room.next_datagram(&packet).is_some() {}
        room.drain_events().for_each(drop);
        group.bench_function(name, |bencher| {
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
    group.finish();
}

criterion_group!(benches, fan_out);
criterion_main!(benches);
