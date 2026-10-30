//! Per-packet cost of the RTCP APP reader and builder (RFC 3550 §6.7) that carry MCPTT floor
//! control (3GPP TS 24.380 §8): one read per received floor message, one write per message the
//! controller sends, and a write per seat when a floor message goes to a whole room.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_media::rtcp::{app_packets, write_app};

/// A Floor Granted (TS 24.380 §8.2.5) with Duration and Audio SSRC of Granted Participant fields.
const FLOOR_GRANTED_DATA: [u8; 12] = [
    0x01, 0x02, 0x00, 0x1E, 0x0E, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
];

fn bench_read(criterion: &mut Criterion) {
    let mut datagram = [0u8; 64];
    let len = write_app(
        17,
        0xAABB_CCDD,
        *b"MCPT",
        &FLOOR_GRANTED_DATA,
        &mut datagram,
    )
    .unwrap();
    let datagram = &datagram[..len];
    criterion.bench_function("rtcp_app_read_floor_granted", |bencher| {
        bencher.iter(|| {
            for app in app_packets(black_box(datagram)) {
                black_box(app.unwrap());
            }
        });
    });
}

fn bench_write(criterion: &mut Criterion) {
    let mut out = [0u8; 64];
    criterion.bench_function("rtcp_app_write_floor_granted", |bencher| {
        bencher.iter(|| {
            black_box(
                write_app(
                    black_box(17),
                    black_box(0xAABB_CCDD),
                    *b"MCPT",
                    black_box(&FLOOR_GRANTED_DATA),
                    &mut out,
                )
                .unwrap(),
            )
        });
    });
}

criterion_group!(benches, bench_read, bench_write);
criterion_main!(benches);
