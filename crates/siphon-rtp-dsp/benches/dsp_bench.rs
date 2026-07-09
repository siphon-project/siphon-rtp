//! Criterion perf gates for the DSP hot paths. `cargo bench -p siphon-rtp-dsp`.
//!
//!   - `resample_8k_16k_20ms` — the telephony→voice-AI upsample of one 20 ms frame (160 → 320
//!     samples). The per-output-sample cost is a polyphase FIR dot (`siphon_rtp_simd::fir_dot_f32`).
//!   - `vad_energy_320` — the energy VAD's per-frame sum-of-squares (`fir`-free reduction via
//!     `siphon_rtp_simd::sum_sq_i16`).
//!   - `ns_8k_20ms` / `ns_16k_20ms` — one 20 ms noise-suppression frame (√Hann WOLA STFT + a real
//!     FFT/IFFT hop + the decision-directed Wiener gain over `N/2+1` bins), reported as µs/frame.
//!   - `aec_8k_20ms` / `aec_16k_20ms` — one NLMS echo-cancel frame (L=256): per sample a SIMD
//!     estimate dot (`siphon_rtp_simd::fir_dot_f32`) + a scalar NLMS weight update.
//!
//! No per-frame heap on the steady-state path: the resampler reuses its history/branches and the
//! caller-owned output vector; the VAD reduces in place; the noise suppressor's FFT/WOLA/PSD scratch
//! and the canceller's weights/ring are all preallocated (a counting-allocator test asserts zero
//! per-frame allocation).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_dsp::{EchoCanceller, EnergyVad, NoiseSuppressor, Resampler};

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

fn bench_noise_suppression(criterion: &mut Criterion) {
    // A deterministic noisy 20 ms frame; the suppressor runs the STFT hops internally.
    let make_frame = |frame_len: usize, seed: u32| -> Vec<i16> {
        let mut lcg = seed;
        (0..frame_len)
            .map(|index| {
                lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let voiced = 3000.0 * (index as f32 * 0.16).sin();
                let noise = ((lcg >> 8) as i32 % 4000 - 2000) as f32;
                (voiced + noise) as i16
            })
            .collect()
    };

    let mut nb = NoiseSuppressor::new(8_000).expect("build");
    let nb_frame = make_frame(160, 0x1111);
    criterion.bench_function("ns_8k_20ms", |bencher| {
        let mut frame = nb_frame.clone();
        bencher.iter(|| {
            frame.copy_from_slice(&nb_frame);
            nb.process(black_box(&mut frame));
            black_box(frame[0])
        });
    });

    let mut wb = NoiseSuppressor::new(16_000).expect("build");
    let wb_frame = make_frame(320, 0x2222);
    criterion.bench_function("ns_16k_20ms", |bencher| {
        let mut frame = wb_frame.clone();
        bencher.iter(|| {
            frame.copy_from_slice(&wb_frame);
            wb.process(black_box(&mut frame));
            black_box(frame[0])
        });
    });
}

fn bench_aec(criterion: &mut Criterion) {
    const TAIL: usize = 256;

    // A far-end (reference) and a near-end microphone frame; near carries an echo-like copy of far.
    let far_8k: Vec<i16> = (0..160)
        .map(|n| ((n as f32 * 0.13).sin() * 8_000.0) as i16)
        .collect();
    let near_8k: Vec<i16> = (0..160)
        .map(|n| ((n as f32 * 0.13).sin() * 2_000.0 + (n as f32 * 0.05).sin() * 3_000.0) as i16)
        .collect();

    criterion.bench_function("aec_8k_20ms", |bencher| {
        let mut canceller = EchoCanceller::new(8_000, TAIL).expect("build");
        let mut near = near_8k.clone();
        bencher.iter(|| {
            near.copy_from_slice(&near_8k);
            canceller.cancel(black_box(&mut near), black_box(&far_8k));
            black_box(near[0])
        });
    });

    let far_16k: Vec<i16> = (0..320)
        .map(|n| ((n as f32 * 0.09).sin() * 8_000.0) as i16)
        .collect();
    let near_16k: Vec<i16> = (0..320)
        .map(|n| ((n as f32 * 0.09).sin() * 2_000.0 + (n as f32 * 0.04).sin() * 3_000.0) as i16)
        .collect();

    criterion.bench_function("aec_16k_20ms", |bencher| {
        let mut canceller = EchoCanceller::new(16_000, TAIL).expect("build");
        let mut near = near_16k.clone();
        bencher.iter(|| {
            near.copy_from_slice(&near_16k);
            canceller.cancel(black_box(&mut near), black_box(&far_16k));
            black_box(near[0])
        });
    });
}

criterion_group!(
    benches,
    bench_resampler,
    bench_vad_energy,
    bench_noise_suppression,
    bench_aec
);
criterion_main!(benches);
