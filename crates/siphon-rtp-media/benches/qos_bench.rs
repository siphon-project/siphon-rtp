//! Per-packet RTCP interarrival-jitter folding (RFC 3550 §6.4.1) on the conference ingest hot path —
//! it must be negligible next to decode/mix; this proves it. (MOS itself is a per-report cost in the
//! `siphon-rtp-hep` G.107 estimator, off the per-packet path.)

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_codec::g711::G711;
use siphon_rtp_media::jitter::JitterBuffer;
use siphon_rtp_media::leg::MediaLeg;

/// A minimal valid G.711 µ-law RTP packet (12-byte header + 160-byte payload), built by hand so the
/// bench needs no packet-writer internals.
fn ulaw_packet(sequence: u16, timestamp: u32) -> Vec<u8> {
    let mut packet = vec![0xFFu8; 12 + 160];
    packet[0] = 0x80; // V=2, P=0, no CSRC
    packet[1] = 0; // M=0, PT=0 (PCMU)
    packet[2..4].copy_from_slice(&sequence.to_be_bytes());
    packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
    packet[8..12].copy_from_slice(&0x1111_2222u32.to_be_bytes());
    packet
}

fn ulaw_leg() -> MediaLeg {
    MediaLeg::new(
        Box::new(G711::ulaw()),
        Box::new(G711::ulaw()),
        JitterBuffer::new(1, 16),
        0xABCD_1234,
        0,
    )
}

fn bench_observe_arrival(criterion: &mut Criterion) {
    let mut leg = ulaw_leg();
    leg.ingest_rtp(&ulaw_packet(0, 0)).expect("ingest"); // primes last_ingress_timestamp
    let mut arrival = 0u64;
    criterion.bench_function("jitter_observe_arrival", |bencher| {
        bencher.iter(|| {
            arrival += 20_000;
            leg.observe_arrival(black_box(arrival));
        });
    });
}

criterion_group!(benches, bench_observe_arrival);
criterion_main!(benches);
