//! Criterion perf gate for the conference mix bus ([`Mixer::mix`]). `cargo bench -p siphon-rtp-media`.
//!
//! Reports the per-tick mix cost (one 20 ms room frame) at each room rate the engine's conference
//! selects — 8 kHz (all-narrowband), 16 kHz (wideband/bridged), 48 kHz (all-full-band Opus) — across
//! room sizes up to the 64-participant cap, plus the webinar shape (a handful of active speakers
//! gated out of a large listener pool). A 48 kHz tick is exactly 3× the samples of a 16 kHz one, so
//! this is where the full-band room's O(N × frame) cost is held against the 20 ms budget.
//!
//! This is the O(N) shared cost of a conference; the per-participant decode/resample/encode is
//! benched elsewhere (codec/dsp benches). The mix itself does zero per-tick heap allocation — all
//! scratch lives on the [`Mixer`].

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use siphon_rtp_media::mixer::{MixInputs, Mixer, Role};

/// The room rates the conference actor selects, with the 20 ms frame each implies.
const ROOM_RATES: [(&str, usize); 3] = [("8k", 160), ("16k", 320), ("48k", 960)];

/// Room sizes to sweep: a small call, a team call, a large room, and the 64-participant cap.
const ROOM_SIZES: [usize; 4] = [3, 10, 32, 64];

/// Build `count` distinct constant-valued talker frames so the mix actually sums real data.
fn talker_frames(count: usize, frame: usize) -> Vec<Vec<i16>> {
    (0..count)
        .map(|index| vec![((index as i16) * 37).wrapping_add(11); frame])
        .collect()
}

fn columns(count: usize, speaking: usize) -> (Vec<Role>, Vec<i64>, Vec<bool>) {
    (
        vec![Role::Talker; count],
        (0..count).map(|index| (index as i64 + 1) * 1_000).collect(),
        (0..count).map(|index| index < speaking).collect(),
    )
}

fn bench_full_room(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("mixer_full_room_20ms");
    for (rate_name, frame) in ROOM_RATES {
        for participants in ROOM_SIZES {
            let pcm = talker_frames(participants, frame);
            let (roles, energy, speaking) = columns(participants, participants);
            let inputs = MixInputs {
                pcm: &pcm,
                roles: &roles,
                energy: &energy,
                speaking: &speaking,
                external: None,
                frame_len: frame,
            };
            let mut mixer = Mixer::new(participants, frame);
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{rate_name}/{participants}p")),
                &participants,
                |bencher, _| {
                    bencher.iter(|| {
                        let active = mixer.mix(black_box(&inputs), &[], &[], 0);
                        black_box(active)
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_webinar(criterion: &mut Criterion) {
    // 60 participants, only the 3 loudest active (top_m = 3) — the active-speaker gating path, at
    // each room rate (the gating itself is rate-independent; the mixing it feeds is not).
    let participants = 60usize;
    let mut group = criterion.benchmark_group("mixer_webinar_60p_top3_20ms");
    for (rate_name, frame) in ROOM_RATES {
        let pcm = talker_frames(participants, frame);
        let (roles, energy, speaking) = columns(participants, participants);
        let inputs = MixInputs {
            pcm: &pcm,
            roles: &roles,
            energy: &energy,
            speaking: &speaking,
            external: None,
            frame_len: frame,
        };
        let mut mixer = Mixer::new(participants, frame);
        group.bench_with_input(
            BenchmarkId::from_parameter(rate_name),
            &frame,
            |bencher, _| {
                bencher.iter(|| {
                    let active = mixer.mix(black_box(&inputs), &[], &[], 3);
                    black_box(active)
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_full_room, bench_webinar);
criterion_main!(benches);
