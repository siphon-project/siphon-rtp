#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

//! The per-packet cost of forwarding one RFC 4733 telephone-event packet from a conference seat to
//! every other seat (`dtmf: forward`): the ingest gate and detector, then one rescaled, repacketized
//! copy per target on the target's own stream, with no sockets. Two room sizes: a small merged call
//! (2 targets) and a full room (63 targets, the 64-seat cap minus the owner). The outbound `Bytes`
//! per target is part of the cost, as it is for the mix.

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_codec::factory::{decoder_for, encoder_for, CodecSpec};
use siphon_rtp_codec::g711::G711;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::conference::{Conference, ParticipantConfig, SeatTelemetry};
use siphon_rtp_engine::sdp::TelephoneEvent;
use siphon_rtp_media::rtp::{write_packet, RtpHeader};
use siphon_rtp_proto::ConferenceDtmf;

fn target(index: usize) -> ParticipantConfig {
    let octet = u8::try_from(index + 1).unwrap();
    ParticipantConfig {
        tag: format!("target-{index}"),
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
            clock_rate_hz: 8000,
        }),
        dtmf: ConferenceDtmf::Events,
        secure: None,
        secure_pending: false,
        text: None,
        ice_pending: false,
        routing: Default::default(),
        telemetry: SeatTelemetry::default(),
        call: None,
    }
}

/// A room of the Opus owner (endpoint 1) and `targets` G.711 seats.
fn room(targets: usize) -> Conference {
    let mut conference = Conference::new("bench".into(), 0);
    let spec = CodecSpec::new(111, "opus", 48_000, 2, 20);
    let owner = ParticipantConfig {
        tag: "owner".into(),
        decoder: decoder_for(&spec).unwrap(),
        encoder: encoder_for(&spec).unwrap(),
        egress_payload_type: 111,
        mos_codec: siphon_rtp_hep::mos::Codec::Opus,
        telephone_event: Some(TelephoneEvent {
            payload_type: 101,
            clock_rate_hz: 48_000,
        }),
        dtmf: ConferenceDtmf::Forward,
        ..target(0)
    };
    conference.add_participant(owner).unwrap();
    for index in 1..=targets {
        conference.add_participant(target(index)).unwrap();
    }
    conference
}

/// The owner's End packet for digit 5 (60 ms at the 48 kHz event clock).
fn end_packet() -> RxPacket {
    let header = RtpHeader {
        marker: false,
        payload_type: 101,
        sequence: 1,
        timestamp: 96_000,
        ssrc: 0x2000_0000,
    };
    let mut datagram = vec![0u8; 16];
    write_packet(&header, &[5, 0x80 | 10, 0x0B, 0x40], &mut datagram).unwrap();
    RxPacket {
        endpoint: EndpointId(1),
        source: "192.0.2.1:5000".parse().unwrap(),
        arrival: 0,
        data: Bytes::from(datagram),
    }
}

fn forward_benches(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("conference_dtmf_forward");
    for targets in [2usize, 63] {
        let mut conference = room(targets);
        let packet = end_packet();
        let mut out = Vec::with_capacity(targets);
        // The loop must really forward: a refused packet would bench the gate alone.
        conference.ingest(&packet);
        conference.drain_forwarded(&mut out);
        assert_eq!(out.len(), targets, "every target gets the packet");
        group.bench_function(format!("one_event_packet_to_{targets}_seats"), |bencher| {
            bencher.iter(|| {
                out.clear();
                black_box(conference.ingest(black_box(&packet)));
                conference.drain_forwarded(&mut out);
                black_box(out.len())
            });
        });
    }
    group.finish();
}

criterion_group!(benches, forward_benches);
criterion_main!(benches);
