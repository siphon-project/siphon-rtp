//! Criterion perf gate for the multi-source mixer (SIPREC: several calls into one recording or tee):
//! the cost of one clock tick that takes a 20 ms frame from each of 2 sources (stereo) and from 8
//! (mono mix), including the per-source `write_pcm` that queues each frame, so the number is the full
//! per-frame price of a source set. `cargo bench -p siphon-rtp-media --bench multi_source_bench`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_media::bridge::multi_source::plan_multi_source;
use siphon_rtp_media::bridge::protocol::{Encoding, Endianness, MediaFormat};
use siphon_rtp_media::fanout::MediaSink;

fn format(channels: u8) -> MediaFormat {
    MediaFormat {
        encoding: Encoding::L16,
        sample_rate: 8000,
        channels,
        bit_depth: 16,
        endianness: Endianness::Little,
        ptime: 20,
    }
}

fn bench_tick(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("multi_source_tick_20ms");
    for (name, channels, sources) in [("stereo_2_sources", 2u8, 2usize), ("mono_8_sources", 1, 8)] {
        let mut plan = plan_multi_source(format(channels), sources).unwrap();
        let mut sinks: Vec<_> = (0..sources)
            .map(|index| plan.control.sink(index, None, "rec").unwrap())
            .collect();
        let pcm = [1234i16; 160];
        group.bench_function(name, |bencher| {
            bencher.iter(|| {
                for sink in &mut sinks {
                    sink.write_pcm(black_box(&pcm));
                }
                black_box(plan.mixer.tick());
                while let Ok(frame) = plan.frames.try_recv() {
                    black_box(frame.len());
                    plan.recycle.send(frame).unwrap();
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_tick);
criterion_main!(benches);
