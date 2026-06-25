//! Criterion perf gates for the codec hot paths. `cargo bench -p siphon-rtp-codec`.
//!
//! These lock per-frame cost so a regression fails CI (the AMR kernels are benched here once
//! their DSP lands).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_codec::amr::basic_ops;
use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::{Decoder, Encoder};

/// One 20 ms frame of 8 kHz audio.
const FRAME: usize = 160;

fn sample_pcm() -> Vec<i16> {
    // A deterministic sweep so the encoder exercises multiple segments.
    (0..FRAME)
        .map(|i| (((i as i32 * 401) % 65536) - 32768) as i16)
        .collect()
}

fn bench_g711(criterion: &mut Criterion) {
    let pcm = sample_pcm();
    let mut payload = vec![0u8; FRAME];
    let mut out_pcm = vec![0i16; FRAME];

    let mut ulaw = G711::ulaw();
    criterion.bench_function("g711_ulaw_encode_frame", |bencher| {
        bencher.iter(|| {
            ulaw.encode(black_box(&pcm), black_box(&mut payload))
                .expect("encode")
        });
    });
    ulaw.encode(&pcm, &mut payload).expect("seed payload");
    criterion.bench_function("g711_ulaw_decode_frame", |bencher| {
        bencher.iter(|| {
            ulaw.decode(black_box(&payload), black_box(&mut out_pcm))
                .expect("decode")
        });
    });

    let mut alaw = G711::alaw();
    criterion.bench_function("g711_alaw_encode_frame", |bencher| {
        bencher.iter(|| {
            alaw.encode(black_box(&pcm), black_box(&mut payload))
                .expect("encode")
        });
    });
}

fn bench_basic_ops(criterion: &mut Criterion) {
    // A correlation-style MAC loop — the shape of the AMR pitch/FIR hot kernels.
    let signal: Vec<i16> = sample_pcm();
    criterion.bench_function("basic_ops_mac_correlation_160", |bencher| {
        bencher.iter(|| {
            let mut acc: i32 = 0;
            for window in signal.windows(2) {
                acc = basic_ops::l_mac(acc, black_box(window[0]), black_box(window[1]));
            }
            black_box(acc)
        });
    });
}

criterion_group!(benches, bench_g711, bench_basic_ops);
criterion_main!(benches);
