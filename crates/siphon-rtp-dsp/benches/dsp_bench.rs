//! Criterion perf gates for the DSP hot paths. `cargo bench -p siphon-rtp-dsp`.
//!
//!   - `resample_8k_16k_20ms` — the telephony→voice-AI upsample of one 20 ms frame (160 → 320
//!     samples). The per-output-sample cost is a polyphase FIR dot (`siphon_rtp_simd::fir_dot_f32`).
//!   - `vad_energy_320` — the energy VAD's per-frame sum-of-squares (`fir`-free reduction via
//!     `siphon_rtp_simd::sum_sq_i16`).
//!
//! No per-frame heap on the steady-state path: the resampler reuses its history/branches and the
//! caller-owned output vector; the VAD reduces in place.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_dsp::{EnergyVad, Resampler};

fn bench_resampler(criterion: &mut Criterion) {
    // 8 kHz → 16 kHz, one 20 ms frame (160 samples) → ~320 out: the WS/voice-AI bridge upsample.
    let input: Vec<i16> = (0..160)
        .map(|n| ((n as f32 * 0.1).sin() * 8000.0) as i16)
        .collect();

    criterion.bench_function("resample_8k_16k_20ms", |bencher| {
        let mut resampler = Resampler::new(8000, 16000).expect("build");
        let mut output = Vec::with_capacity(400);
        bencher.iter(|| {
            output.clear();
            resampler.process(black_box(&input), &mut output);
            black_box(output.len())
        });
    });
}

fn bench_vad_energy(criterion: &mut Criterion) {
    // One 20 ms frame at 16 kHz (320 samples).
    let frame: Vec<i16> = (0..320).map(|n| (n as i16).wrapping_mul(101)).collect();

    criterion.bench_function("vad_energy_320", |bencher| {
        bencher.iter(|| black_box(EnergyVad::energy(black_box(&frame))));
    });
}

criterion_group!(benches, bench_resampler, bench_vad_energy);
criterion_main!(benches);
