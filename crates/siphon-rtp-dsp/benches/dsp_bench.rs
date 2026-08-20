//! Criterion perf gates for the DSP hot paths. `cargo bench -p siphon-rtp-dsp`.
//!
//!   - `resample_8k_16k_20ms` — the telephony→voice-AI upsample of one 20 ms frame (160 → 320
//!     samples). The per-output-sample cost is a polyphase FIR dot (`siphon_rtp_simd::fir_dot_f32`).
//!   - `vad_energy_320` — the energy VAD's per-frame sum-of-squares (`fir`-free reduction via
//!     `siphon_rtp_simd::sum_sq_i16`).
//!   - `neural_vad_16k_window` — one 32 ms (512-sample) window through the whole Silero v5 graph:
//!     the 256-point transform as a filter-bank convolution, four encoder convolutions + ReLU, the
//!     LSTM cell, the output convolution and the sigmoid. ~680 K multiply-accumulates, every dot
//!     through `siphon_rtp_simd::fir_dot_f32`. This is the cost per 32 ms per concurrent call.
//!   - `neural_vad_stream_16k_20ms` / `neural_vad_stream_8k_20ms` — what a leg pays per media tick
//!     once the window cost is amortised over the frame clock (a window completes every 1.6 frames
//!     at 20 ms), narrowband additionally paying the 8 → 16 kHz polyphase resample.
//!   - `ns_8k_20ms` / `ns_16k_20ms` — one 20 ms noise-suppression frame (√Hann WOLA STFT + a real
//!     FFT/IFFT hop + the decision-directed Wiener gain over `N/2+1` bins), reported as µs/frame.
//!   - `beep_8k_20ms` / `beep_16k_20ms` — one 20 ms frame through the record-tone ("voicemail
//!     beep") detector: the √Hann WOLA analysis FFT per 16 ms hop plus the per-hop concentration /
//!     second-tone / peak-interpolation scan over the 200…3400 Hz band. Measured on a steady in-band
//!     tone, the worst case (every rule runs to completion instead of returning early).
//!   - `aec_8k_20ms` / `aec_16k_20ms` — one NLMS echo-cancel frame (L=256): per sample a SIMD
//!     estimate dot (`siphon_rtp_simd::fir_dot_f32`) + a scalar NLMS weight update.
//!   - `aec_twopath_8k_20ms` — one two-path/NCC echo-cancel frame (L=256): two SIMD estimate dots per
//!     sample (foreground + background) + the background NLMS update + the per-frame NCC accumulators,
//!     i.e. the extra per-frame cost the double-talk-robust path pays over the single-filter one.
//!   - `aec_mdf_8k_20ms` / `aec_mdf_16k_20ms` — one 20 ms frame through the MDF / partitioned-block
//!     frequency-domain backend over a 256 ms tail (16 partitions): the overlap-save block FFTs plus the
//!     per-partition gradient-constraint IFFT/FFT pairs. The heaviest AEC path; the µs/frame informs the
//!     inline-vs-DSP-worker decision for the (later) engine integration.
//!
//! No per-frame heap on the steady-state path: the resampler reuses its history/branches and the
//! caller-owned output vector; the VAD reduces in place; the noise suppressor's FFT/WOLA/PSD scratch
//! and the canceller's weights/ring are all preallocated (a counting-allocator test asserts zero
//! per-frame allocation).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_dsp::{
    EchoCanceller, EnergyVad, NeuralVad, NeuralVadStream, NoiseSuppressor, RecordToneDetector,
    Resampler, NEURAL_VAD_WINDOW_SAMPLES,
};

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

fn bench_neural_vad(criterion: &mut Criterion) {
    // A deterministic voiced-ish window: harmonics under a slow envelope, so the network runs its
    // full path (a silent window takes the same instruction count — there is no data-dependent
    // branching in a convolution — but a realistic input keeps the numbers honest).
    let window: Vec<i16> = (0..NEURAL_VAD_WINDOW_SAMPLES)
        .map(|index| {
            let time = index as f32 / 16_000.0;
            let envelope = 0.6 + 0.4 * (2.0 * std::f32::consts::PI * 4.0 * time).sin();
            let voiced = (2.0 * std::f32::consts::PI * 140.0 * time).sin()
                + 0.5 * (2.0 * std::f32::consts::PI * 420.0 * time).sin()
                + 0.25 * (2.0 * std::f32::consts::PI * 1_100.0 * time).sin();
            (voiced * envelope * 6_000.0) as i16
        })
        .collect();

    // The headline number: one 32 ms window through the whole graph — the 256-point transform as a
    // filter-bank convolution, four encoder convolutions with ReLU, the LSTM cell, the output
    // convolution and the sigmoid. This is paid once per 32 ms per concurrent call.
    criterion.bench_function("neural_vad_16k_window", |bencher| {
        let mut detector = NeuralVad::new();
        bencher.iter(|| black_box(detector.speech_probability(black_box(&window))));
    });

    // What the WS bridge actually pays per media tick: most 20 ms frames only accumulate, and one
    // in every 1.6 frames completes a window and runs the network. Amortised, this is the per-frame
    // cost a leg carries.
    let frame_16k: Vec<i16> = (0..320).map(|index| window[index % window.len()]).collect();
    criterion.bench_function("neural_vad_stream_16k_20ms", |bencher| {
        let mut stream = NeuralVadStream::new(16_000).expect("build");
        bencher.iter(|| black_box(stream.is_speech(black_box(&frame_16k))));
    });

    // The narrowband leg additionally pays an 8 → 16 kHz polyphase resample of every frame.
    let frame_8k: Vec<i16> = (0..160)
        .map(|index| window[(index * 2) % window.len()])
        .collect();
    criterion.bench_function("neural_vad_stream_8k_20ms", |bencher| {
        let mut stream = NeuralVadStream::new(8_000).expect("build");
        bencher.iter(|| black_box(stream.is_speech(black_box(&frame_8k))));
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

fn bench_record_tone_detection(criterion: &mut Criterion) {
    // A steady in-band tone: the worst case for the detector, because every per-hop rule runs to
    // completion (a frame that fails the concentration test returns early and is cheaper).
    let make_tone = |frame_len: usize, rate: f32| -> Vec<i16> {
        (0..frame_len)
            .map(|index| {
                (8000.0 * (2.0 * std::f32::consts::PI * 1400.0 * index as f32 / rate).sin()) as i16
            })
            .collect()
    };

    let mut narrowband = RecordToneDetector::new(8_000).expect("build");
    let narrowband_frame = make_tone(160, 8_000.0);
    criterion.bench_function("beep_8k_20ms", |bencher| {
        bencher.iter(|| black_box(narrowband.process(black_box(&narrowband_frame))));
    });

    let mut wideband = RecordToneDetector::new(16_000).expect("build");
    let wideband_frame = make_tone(320, 16_000.0);
    criterion.bench_function("beep_16k_20ms", |bencher| {
        bencher.iter(|| black_box(wideband.process(black_box(&wideband_frame))));
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

    // The two-path/NCC double-talk detector: a second (foreground) estimate dot per sample plus the
    // per-frame NCC accumulators, on top of the single-filter cost above (~2× the per-sample MAC).
    criterion.bench_function("aec_twopath_8k_20ms", |bencher| {
        let mut canceller = EchoCanceller::new(8_000, TAIL)
            .expect("build")
            .with_two_path_dtd();
        let mut near = near_8k.clone();
        bencher.iter(|| {
            near.copy_from_slice(&near_8k);
            canceller.cancel(black_box(&mut near), black_box(&far_8k));
            black_box(near[0])
        });
    });

    // The amortized per-frame cost with GCC-PHAT delay estimation on: every frame buffers the raw
    // near/far into the estimation block and, once per `block_size` samples, pays two forward real
    // FFTs + a phase-transformed cross-power + an inverse FFT. Search range 512 → 1024-point blocks
    // (one GCC block every ~6.4 frames at 8 kHz).
    criterion.bench_function("aec_delayest_8k_20ms", |bencher| {
        let mut canceller = EchoCanceller::with_delay_estimation(8_000, TAIL, 512).expect("build");
        let mut near = near_8k.clone();
        bencher.iter(|| {
            near.copy_from_slice(&near_8k);
            canceller.cancel(black_box(&mut near), black_box(&far_8k));
            black_box(near[0])
        });
    });

    // The MDF / partitioned-block frequency-domain backend covering a 256 ms tail (2048 taps @ 8 kHz,
    // 16 partitions of 128; 4096 taps @ 16 kHz, 16 partitions of 256). Per 20 ms frame it processes one
    // or two 256-/512-point overlap-save blocks; each block is the filter FFT (an inverse), the error
    // FFT (a forward), and — per partition — the gradient-constraint IFFT/FFT pair (the canonical MDF
    // cost). This is the heaviest AEC path; the µs/frame here informs whether the engine runs it inline
    // or on a bounded DSP worker (that wiring is a later PR).
    // Loud far-end + a quiet echo-like near-end so the Geigel screen never trips and the *adapting*
    // MDF path (the per-partition gradient-constraint IFFT/FFT pairs — the dominant cost) is measured
    // every frame, not the cheap frozen-filter path.
    let far_loud_8k: Vec<i16> = (0..160)
        .map(|n| ((n as f32 * 0.13).sin() * 24_000.0) as i16)
        .collect();
    let near_quiet_8k: Vec<i16> = (0..160)
        .map(|n| ((n as f32 * 0.13).sin() * 1_500.0) as i16)
        .collect();
    const MDF_TAIL_8K: usize = 2048;
    criterion.bench_function("aec_mdf_8k_20ms", |bencher| {
        let mut canceller = EchoCanceller::with_mdf(8_000, MDF_TAIL_8K).expect("build");
        let mut near = near_quiet_8k.clone();
        bencher.iter(|| {
            near.copy_from_slice(&near_quiet_8k);
            canceller.cancel(black_box(&mut near), black_box(&far_loud_8k));
            black_box(near[0])
        });
    });

    let far_loud_16k: Vec<i16> = (0..320)
        .map(|n| ((n as f32 * 0.09).sin() * 24_000.0) as i16)
        .collect();
    let near_quiet_16k: Vec<i16> = (0..320)
        .map(|n| ((n as f32 * 0.09).sin() * 1_500.0) as i16)
        .collect();
    const MDF_TAIL_16K: usize = 4096;
    criterion.bench_function("aec_mdf_16k_20ms", |bencher| {
        let mut canceller = EchoCanceller::with_mdf(16_000, MDF_TAIL_16K).expect("build");
        let mut near = near_quiet_16k.clone();
        bencher.iter(|| {
            near.copy_from_slice(&near_quiet_16k);
            canceller.cancel(black_box(&mut near), black_box(&far_loud_16k));
            black_box(near[0])
        });
    });

    // The residual-echo suppressor chained after the time-domain NLMS: on top of the linear cancel it
    // pays, per 20 ms frame, a √Hann WOLA STFT over the residual (one or two 256-point forward+inverse
    // FFT hops + the per-bin decision-directed Wiener gain) and an analysis-only forward FFT of the
    // frame-synchronous echo estimate. The extra per-frame cost the residual post-filter adds — the
    // number that informs whether the engine runs it inline or on a DSP worker (that wiring is a later
    // PR). Loud far-end + quiet echo-like near-end so the Geigel screen never freezes the linear filter.
    criterion.bench_function("aec_res_8k_20ms", |bencher| {
        let mut canceller = EchoCanceller::new(8_000, TAIL)
            .expect("build")
            .with_residual_suppression()
            .expect("res");
        let mut near = near_quiet_8k.clone();
        bencher.iter(|| {
            near.copy_from_slice(&near_quiet_8k);
            canceller.cancel(black_box(&mut near), black_box(&far_loud_8k));
            black_box(near[0])
        });
    });
}

criterion_group!(
    benches,
    bench_resampler,
    bench_vad_energy,
    bench_neural_vad,
    bench_noise_suppression,
    bench_record_tone_detection,
    bench_aec
);
criterion_main!(benches);
