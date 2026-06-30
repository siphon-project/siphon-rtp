//! Criterion perf gate for the userspace relay hot path. `cargo bench -p siphon-rtp-media`.
//!
//! Models the per-packet cost the relay pays when it cannot stay in the kernel: parse an incoming
//! RTP packet (RFC 3550 §5), rewrite its SSRC/sequence (re-origination / topology hiding), and
//! serialize it into a caller-owned buffer. No per-packet heap allocation — that is the whole point.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_media::rtp::{write_packet, RtpHeader, RtpPacket, FIXED_HEADER_LEN};

/// A G.711 µ-law RTP packet: 12-byte header + 160-byte (20 ms @ 8 kHz) payload.
fn sample_packet() -> Vec<u8> {
    let header = RtpHeader {
        marker: false,
        payload_type: 0,
        sequence: 0x1234,
        timestamp: 0xDEAD_BEEF,
        ssrc: 0x0102_0304,
    };
    let payload = [0xABu8; 160];
    let mut buffer = vec![0u8; FIXED_HEADER_LEN + payload.len()];
    let len = write_packet(&header, &payload, &mut buffer).expect("seed packet");
    buffer.truncate(len);
    buffer
}

fn bench_relay(criterion: &mut Criterion) {
    let input = sample_packet();
    let mut out = vec![0u8; 1500];

    criterion.bench_function("rtp_parse_160", |bencher| {
        bencher.iter(|| {
            let packet = RtpPacket::parse(black_box(&input)).expect("parse");
            black_box(packet.payload.len())
        });
    });

    criterion.bench_function("rtp_parse_rewrite_write_160", |bencher| {
        bencher.iter(|| {
            let packet = RtpPacket::parse(black_box(&input)).expect("parse");
            let header = RtpHeader {
                marker: packet.marker,
                payload_type: packet.payload_type,
                sequence: packet.sequence.wrapping_add(1),
                timestamp: packet.timestamp,
                ssrc: 0xCAFE_BABE, // re-originated SSRC
            };
            let len = write_packet(black_box(&header), packet.payload, black_box(&mut out))
                .expect("write");
            black_box(len)
        });
    });
}

criterion_group!(benches, bench_relay);
criterion_main!(benches);
