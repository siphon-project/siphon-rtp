//! Criterion perf gate for the RFC 2198 RED hot path (parse + build per packet). `cargo bench -p
//! siphon-rtp-media --bench t140_red_bench`.
//!
//! A T.140/RED packet on an `m=text` leg is tiny (a few characters plus two redundant generations,
//! RFC 4103 §4), so parse and build must be a handful of nanoseconds — negligible next to the media
//! path. The paired zero-per-packet-alloc proof lives in `tests/t140_zero_alloc.rs`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_media::t140::{RedBuilder, RedGeneration, RedPacket};

fn bench_t140_red(criterion: &mut Criterion) {
    // A representative RFC 4103 packet: primary "world" + two redundant generations (RFC 4103 §4),
    // all on the t140 dynamic PT 98, at a 1000 Hz clock (300 ms apart).
    let generations = [
        RedGeneration {
            payload_type: 98,
            rtp_timestamp: 8000 - 600,
            data: b"hel",
        },
        RedGeneration {
            payload_type: 98,
            rtp_timestamp: 8000 - 300,
            data: b"lo",
        },
    ];
    let builder = RedBuilder {
        primary_payload_type: 98,
        primary_rtp_timestamp: 8000,
        primary_data: b"world",
        redundant: &generations,
    };

    // Warm the reused output buffer once so the benched loop measures steady-state (no realloc).
    let mut buffer = Vec::with_capacity(64);
    builder.write_into(&mut buffer).expect("build");

    criterion.bench_function("t140_red_build", |bencher| {
        bencher.iter(|| {
            builder.write_into(black_box(&mut buffer)).expect("build");
            black_box(buffer.len());
        });
    });

    criterion.bench_function("t140_red_parse", |bencher| {
        bencher.iter(|| {
            let packet = RedPacket::parse(black_box(&buffer)).expect("parse");
            black_box(packet.primary().data.len());
        });
    });
}

criterion_group!(benches, bench_t140_red);
criterion_main!(benches);
