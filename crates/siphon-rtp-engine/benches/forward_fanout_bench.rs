//! Criterion perf gate for the **forwarding room fan-out**: what one inbound packet from the chosen
//! source costs the room, with no sockets.
//!
//! One iteration is `ForwardRoom::ingest` (source gate, constrained latch, RTP parse, reception
//! statistics) followed by `next_datagram` until the room is done: one translator rewrite per
//! receiving seat, written into the room's scratch. The sink is a `black_box` of the datagram, so the
//! number is the room's own cost; the per-datagram `send` syscall is the datapath's and is measured
//! with the integration measurement in `docs/cookbook/forwarding.md`.
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
use siphon_rtp_engine::forward::{ForwardRoom, ForwardSeatConfig, RoomCodec};
use siphon_rtp_engine::sdp;
use siphon_rtp_media::rtp::{write_packet, RtpHeader};

/// An AMR-WB octet-aligned 20 ms frame at mode 8 (23.85 kbit/s): 1 + 61 octets.
const PAYLOAD_BYTES: usize = 62;

fn room_of(seats: usize) -> ForwardRoom {
    let offer = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                 m=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n";
    let codecs = sdp::parse(offer).unwrap().audio_codecs();
    let (codec, _) = RoomCodec::from_offer(&codecs).unwrap();
    let mut room = ForwardRoom::new("bench".to_string(), codec);
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

fn fan_out(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("forward_fan_out");
    for seats in [10usize, 100, 500, 1000] {
        let mut room = room_of(seats);
        let packet = inbound();
        // Warm: the first packet starts the run and announces the source.
        room.ingest(&packet);
        while room.next_datagram(&packet).is_some() {}
        room.drain_events().for_each(drop);
        group.throughput(Throughput::Elements(seats as u64 - 1));
        group.bench_function(BenchmarkId::new("per_inbound_packet", seats), |bencher| {
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
