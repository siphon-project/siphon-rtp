#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

//! The cost of one 20 ms room frame, ingest of every seat's packet and the tick that mixes and
//! sends, for a room whose seats are not intercepted and for one whose seat 1 is (ETSI TS 103 221-2
//! X3). The untapped arm is the room's own cost and the gate for the interception hooks (it must
//! stay within 10 % of the same loop without them); the tapped arm adds both directions of one seat
//! plus the recycled-buffer hand-back the delivery task does, so it is an upper bound on what an
//! intercepted seat costs the room.

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_codec::g711::G711;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::conference::{Conference, ParticipantConfig, SeatTelemetry};
use siphon_rtp_engine::x3::x3_channel;
use siphon_rtp_proto::ConferenceDtmf;

const FRAMES: usize = 4000;

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

fn room_benches(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("conference_room_frame");
    for seats in [3usize, 8] {
        let frames: Vec<Vec<RxPacket>> = (0..FRAMES)
            .map(|sequence| {
                (0..seats)
                    .map(|index| voice(index, sequence as u16))
                    .collect()
            })
            .collect();
        for deliveries in [0usize, 1, 2] {
            let mut room = Conference::new("bench".into(), 0);
            for index in 0..seats {
                room.add_participant(seat(index)).unwrap();
            }
            let channels: Vec<_> = (0..deliveries).map(|_| x3_channel(4096)).collect();
            if deliveries > 0 {
                let factories: Vec<_> = channels
                    .iter()
                    .map(|(factory, _)| factory.clone())
                    .collect();
                assert!(room.set_seat_x3("seat-1", &factories));
            }
            let mut out = Vec::with_capacity(seats * 4);
            let mut next = 0usize;
            let name = format!(
                "{seats}_seats_{}",
                match deliveries {
                    0 => "untapped",
                    1 => "seat_1_tapped",
                    _ => "seat_1_tapped_two",
                }
            );
            group.bench_function(name, |bencher| {
                bencher.iter(|| {
                    for packet in &frames[next] {
                        black_box(room.ingest(black_box(packet)));
                    }
                    out.clear();
                    room.tick(&mut out);
                    next = (next + 1) % FRAMES;
                    // The delivery task's side: frame it, hand the buffer back.
                    for (_, delivery) in &channels {
                        while let Ok(packet) = delivery.packets.try_recv() {
                            let _ = delivery.recycle.try_send(packet.payload);
                        }
                    }
                    black_box(out.len())
                });
            });
        }
    }
    group.finish();
}

criterion_group!(benches, room_benches);
criterion_main!(benches);
