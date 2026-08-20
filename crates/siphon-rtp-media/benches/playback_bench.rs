//! Criterion perf gate for overlay playback — the per-tick cost a leg pays for audio mixed *under*
//! its live egress. `cargo bench -p siphon-rtp-media --bench playback_bench`.
//!
//! Three costs, each measured on one 20 ms frame:
//!
//! - **overlay mix** at 1, 2 and 4 slots (the [`MAX_OVERLAY_SLOTS`] cap), at each egress rate the
//!   transcode path selects, plus the rate-converted slot (the only one carrying a resampler);
//! - **tone generation**, single- and dual-frequency, per frame;
//! - **gain application**, per frame, against the unity fast path it must beat being skipped.
//!
//! The neighbour to hold these against is `mixer_bench`: the conference mix bus is 139 ns for a
//! 3-party 8 kHz tick. Overlay mixing is the same shape of work (N sources accumulated into one
//! `i32` bus and saturated once) with the source render folded in, so it should land in the same
//! order of magnitude — and, like the conference mix, at zero per-tick heap allocation.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use siphon_rtp_media::fanout::MediaSink;
use siphon_rtp_media::playback::{
    FinishedPlayback, Gain, OverlayBus, Playback, PlaybackSource, MAX_OVERLAY_SLOTS,
};
use siphon_rtp_media::player::{PcmPlayer, WavSource};
use siphon_rtp_media::tone::{ToneGenerator, ToneSpec};
use siphon_rtp_media::wav::WavRecorder;

/// The egress rates a transcoding leg selects, with the 20 ms frame each implies.
const EGRESS_RATES: [(&str, u32, usize); 3] = [
    ("8k", 8_000, 160),
    ("16k", 16_000, 320),
    ("48k", 48_000, 960),
];

/// A one-second constant-valued prompt looped effectively forever, so no slot can run dry inside a
/// criterion run — a drained slot would measure the empty-bus early return instead of the mix.
fn prompt_source(rate_hz: u32, value: i16) -> PlaybackSource {
    let mut recorder = WavRecorder::new(rate_hz, 1);
    recorder.write_pcm(&vec![value; rate_hz as usize]);
    let wav = recorder.into_wav();
    let parsed = WavSource::parse(&wav).expect("fixture parses");
    PlaybackSource::Pcm(Box::new(PcmPlayer::new(&parsed, u32::MAX, 0)))
}

fn overlay_bus(slots: usize, source_rate_hz: u32, egress_rate_hz: u32, frame: usize) -> OverlayBus {
    let mut bus = OverlayBus::new(frame);
    for play_id in 0..slots as u64 {
        let playback = Playback::new(
            prompt_source(source_rate_hz, 1_000 + play_id as i16),
            egress_rate_hz,
            20,
            Gain::from_decibels(-6),
            play_id,
            None,
        )
        .expect("playback builds");
        bus.start(playback).expect("slot is free");
    }
    bus
}

fn bench_overlay_mix(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("overlay_mix_20ms");
    for (rate_name, rate_hz, frame) in EGRESS_RATES {
        for slots in [1usize, 2, MAX_OVERLAY_SLOTS] {
            let mut bus = overlay_bus(slots, rate_hz, rate_hz, frame);
            let mut base = vec![250i16; frame];
            let mut finished: Vec<FinishedPlayback> = Vec::with_capacity(MAX_OVERLAY_SLOTS);
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{rate_name}/{slots}slot")),
                &slots,
                |bencher, _| {
                    bencher.iter(|| {
                        bus.mix_into(black_box(&mut base), &mut finished);
                        finished.clear();
                        black_box(&base);
                    });
                },
            );
            assert!(
                bus.is_active(),
                "the bench must measure a live mix, not a drained bus"
            );
        }
    }
    group.finish();
}

fn bench_overlay_mix_resampled(criterion: &mut Criterion) {
    // The one overlay shape that carries a resampler and a re-framer: a 16 kHz prompt under an
    // 8 kHz leg. Expected to be dominated by the resample, exactly as the WS tee is.
    let mut group = criterion.benchmark_group("overlay_mix_20ms_resampled");
    let mut bus = overlay_bus(1, 16_000, 8_000, 160);
    let mut base = vec![250i16; 160];
    let mut finished: Vec<FinishedPlayback> = Vec::with_capacity(MAX_OVERLAY_SLOTS);
    group.bench_function("16k_source/8k_egress/1slot", |bencher| {
        bencher.iter(|| {
            bus.mix_into(black_box(&mut base), &mut finished);
            finished.clear();
            black_box(&base);
        });
    });
    assert!(
        bus.is_active(),
        "the bench must measure a live mix, not a drained bus"
    );
    group.finish();
}

fn bench_tone_generation(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("tone_generate_20ms");
    for (rate_name, rate_hz, frame) in EGRESS_RATES {
        for (shape, spec) in [
            ("single", "425/1000*inf"),
            ("dual", "440+480/1000*inf"),
            ("cadenced", "425/1000,0/4000*inf"),
        ] {
            let resolved = ToneSpec::resolve(spec).expect("tone resolves");
            let mut generator = ToneGenerator::new(resolved, rate_hz);
            let mut out = vec![0i16; frame];
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{rate_name}/{shape}")),
                &shape,
                |bencher, _| {
                    bencher.iter(|| {
                        let written = generator.next_frame(black_box(&mut out));
                        black_box(written)
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_gain(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("gain_apply_20ms");
    for (rate_name, _rate_hz, frame) in EGRESS_RATES {
        let attenuating = Gain::from_decibels(-12);
        let mut pcm = vec![9_000i16; frame];
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{rate_name}/-12dB")),
            &frame,
            |bencher, _| {
                bencher.iter(|| {
                    attenuating.apply_in_place(black_box(&mut pcm));
                    black_box(&pcm);
                });
            },
        );
        let unity = Gain::unity();
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{rate_name}/unity")),
            &frame,
            |bencher, _| {
                bencher.iter(|| {
                    unity.apply_in_place(black_box(&mut pcm));
                    black_box(&pcm);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_overlay_mix,
    bench_overlay_mix_resampled,
    bench_tone_generation,
    bench_gain
);
criterion_main!(benches);
