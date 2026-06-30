//! Criterion perf gate for the conference mix bus ([`Mixer::mix`]). `cargo bench -p siphon-rtp-media`.
//!
//! Reports the per-tick mix cost (one 20 ms room frame) at a few room sizes, plus the webinar shape
//! (a handful of active speakers gated out of a large listener pool). This is the O(N) shared cost of
//! a conference; the per-participant decode/resample/encode is benched elsewhere (codec/dsp benches).
//! The mix itself does zero per-tick heap allocation — all scratch lives on the [`Mixer`].

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use siphon_rtp_media::mixer::{MixInputs, Mixer, Role};

/// 16 kHz / 20 ms room frame.
const ROOM_FRAME: usize = 320;

/// Build `count` distinct constant-valued talker frames so the mix actually sums real data.
fn talker_frames(count: usize) -> Vec<Vec<i16>> {
    (0..count)
        .map(|index| vec![((index as i16) * 37).wrapping_add(11); ROOM_FRAME])
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
    for participants in [3usize, 10, 32] {
        let pcm = talker_frames(participants);
        let (roles, energy, speaking) = columns(participants, participants);
        let inputs = MixInputs {
            pcm: &pcm,
            roles: &roles,
            energy: &energy,
            speaking: &speaking,
            external: None,
            frame_len: ROOM_FRAME,
        };
        let mut mixer = Mixer::new(participants, ROOM_FRAME);
        group.bench_with_input(
            BenchmarkId::from_parameter(participants),
            &participants,
            |bencher, _| {
                bencher.iter(|| {
                    let active = mixer.mix(black_box(&inputs), &[], &[], 0);
                    black_box(active)
                });
            },
        );
    }
    group.finish();
}

fn bench_webinar(criterion: &mut Criterion) {
    // 60 participants, only the 3 loudest active (top_m = 3) — the active-speaker gating path.
    let participants = 60usize;
    let pcm = talker_frames(participants);
    let (roles, energy, speaking) = columns(participants, participants);
    let inputs = MixInputs {
        pcm: &pcm,
        roles: &roles,
        energy: &energy,
        speaking: &speaking,
        external: None,
        frame_len: ROOM_FRAME,
    };
    let mut mixer = Mixer::new(participants, ROOM_FRAME);
    criterion.bench_function("mixer_webinar_60p_top3_20ms", |bencher| {
        bencher.iter(|| {
            let active = mixer.mix(black_box(&inputs), &[], &[], 3);
            black_box(active)
        });
    });
}

criterion_group!(benches, bench_full_room, bench_webinar);
criterion_main!(benches);
