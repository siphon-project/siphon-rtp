//! Criterion perf gate for the transcode repacketizer. `cargo bench -p siphon-rtp-media`.
//!
//! Measures the per-ingress-frame cost the transcode datapath pays to re-frame decoded PCM to a
//! different egress `ptime`: append to the preallocated accumulator, then drain each full egress frame
//! in place. No per-frame heap allocation — the accumulator is sized once (see
//! `tests/repacketize_zero_alloc.rs`). Three ratios cover the shapes the datapath meets: 1:1 (20→20),
//! integer up-shift (20→40, buffers a frame), down-shift (20→10, emits two), and a fractional 30→20.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_media::repacketize::Repacketizer;

/// One push + full drain cycle, mirroring what `Direction::repacketize` does per ingress frame.
fn cycle(repacketizer: &mut Repacketizer, ingress: &[i16], frame: &mut [i16]) {
    repacketizer.push(black_box(ingress));
    while let Some(count) = repacketizer.next_frame(frame) {
        black_box(&frame[..count]);
    }
}

fn bench_repacketize(criterion: &mut Criterion) {
    let mut frame = [0i16; 1920];

    // Each case: (label, ingress samples/frame, egress samples/frame). 8 kHz telephony framing.
    for (label, ingress_len, egress_len) in [
        ("repacketize_20ms_to_20ms", 160usize, 160usize),
        ("repacketize_20ms_to_40ms", 160, 320),
        ("repacketize_20ms_to_10ms", 160, 80),
        ("repacketize_30ms_to_20ms", 240, 160),
    ] {
        let ingress = vec![0x2Ai16; ingress_len];
        let mut repacketizer = Repacketizer::new(egress_len, ingress_len);
        criterion.bench_function(label, |bencher| {
            bencher.iter(|| cycle(&mut repacketizer, &ingress, &mut frame));
        });
    }
}

criterion_group!(benches, bench_repacketize);
criterion_main!(benches);
