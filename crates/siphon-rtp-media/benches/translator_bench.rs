//! Per-packet cost of the per-receiver RTP translator (RFC 3550 §7): one rewrite of an AMR-WB-sized
//! payload, and one inbound packet fanned out to 500 receivers. Caller-owned output, no allocation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_media::rtp::{write_packet, RtpHeader};
use siphon_rtp_media::translator::Translator;

fn inbound() -> Vec<u8> {
    let header = RtpHeader {
        marker: false,
        payload_type: 96,
        sequence: 0,
        timestamp: 0,
        ssrc: 0x1111_2222,
    };
    let mut buffer = vec![0u8; 12 + 160];
    write_packet(&header, &[0x5Au8; 160], &mut buffer).unwrap();
    buffer
}

fn bench_translate(criterion: &mut Criterion) {
    let mut translator = Translator::new(0xABCD_0001, 1000, 50_000);
    let mut out = [0u8; 256];
    let mut packet = inbound();
    let mut sequence = 0u16;
    let mut timestamp = 0u32;
    criterion.bench_function("translator_rewrite_160b", |bencher| {
        bencher.iter(|| {
            sequence = sequence.wrapping_add(1);
            timestamp = timestamp.wrapping_add(320);
            packet[2..4].copy_from_slice(&sequence.to_be_bytes());
            packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
            black_box(
                translator
                    .translate(black_box(&packet), timestamp, &mut out)
                    .unwrap(),
            );
        });
    });
}

fn bench_fanout(criterion: &mut Criterion) {
    let mut translators: Vec<Translator> = (0..500u32)
        .map(|index| Translator::new(0xC000_0000 + index, index as u16, index * 977))
        .collect();
    let mut out = [0u8; 256];
    let mut packet = inbound();
    let mut sequence = 0u16;
    let mut timestamp = 0u32;
    criterion.bench_function("translator_fanout_500_receivers", |bencher| {
        bencher.iter(|| {
            sequence = sequence.wrapping_add(1);
            timestamp = timestamp.wrapping_add(320);
            packet[2..4].copy_from_slice(&sequence.to_be_bytes());
            packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
            for translator in &mut translators {
                black_box(
                    translator
                        .translate(black_box(&packet), timestamp, &mut out)
                        .unwrap(),
                );
            }
        });
    });
}

criterion_group!(benches, bench_translate, bench_fanout);
criterion_main!(benches);
