//! Criterion perf gate for the RFC 9071 conference text mix bus ([`TextMixer::flush`]). `cargo bench
//! -p siphon-rtp-media --bench text_mixer_bench`.
//!
//! Reports the per-flush cost of distributing every participant's pending T.140 text to every other
//! participant (mix-minus-self, one RFC 2198 RED packet per receiver-source pair) across room sizes up
//! to the 64-participant cap. Text flushes only every ~300 ms — three orders of magnitude rarer than
//! the 20 ms audio tick — so this is never a bottleneck; the bench exists to hold that and to prove no
//! regression. The paired zero-per-flush-alloc proof lives in `tests/text_mixer_zero_alloc.rs`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use siphon_rtp_media::text_mixer::{TextMixer, TextSourceConfig};

/// Room sizes to sweep: a small call, a team call, a large room, and the 64-participant cap.
const ROOM_SIZES: [usize; 4] = [3, 10, 32, 64];

fn red_source(source_id: u32) -> Option<TextSourceConfig> {
    Some(TextSourceConfig {
        source_id,
        t140_payload_type: 98,
        red_payload_type: Some(99),
    })
}

fn bench_text_flush(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("text_mixer_flush_300ms");
    for participants in ROOM_SIZES {
        let mut mixer = TextMixer::new(300);
        for index in 0..participants {
            mixer.add_participant(red_source(0xA000 + index as u32));
        }
        // Warm the redundancy ring + scratch to steady state (every participant typing each flush).
        let mut counter = 0u64;
        for _ in 0..8 {
            for index in 0..participants {
                mixer.push_text(index, "abc");
            }
            counter += 1;
            mixer.flush(counter);
        }
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{participants}p")),
            &participants,
            |bencher, &participants| {
                bencher.iter(|| {
                    for index in 0..participants {
                        mixer.push_text(index, "abc");
                    }
                    counter += 1;
                    let emitted = mixer.flush(black_box(counter));
                    black_box(emitted);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_text_flush);
criterion_main!(benches);
