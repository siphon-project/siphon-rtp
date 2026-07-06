//! Deterministic instruction-count benchmarks (valgrind/callgrind) for the codec hot path.
//!
//! Wall-clock criterion benches (`codec_bench.rs`) are the human-facing µs/frame numbers, but they
//! are too noisy on a shared CI runner to gate on. Callgrind counts *instructions executed*, which is
//! deterministic run-to-run, so a `>N%` change is a real code change, not measurement noise. The CI
//! `perf-gate` job runs these against a committed baseline and fails on a regression.
//!
//! Setup (codec construction, buffer allocation) runs in a `setup` fn so it is excluded from the
//! measured instruction count; only the per-frame `decode`/`encode` call is counted.

use iai_callgrind::{
    library_benchmark, library_benchmark_group, main, Callgrind, EventKind, LibraryBenchmarkConfig,
};
use std::hint::black_box;

use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::{Decoder, Encoder};

/// One 20 ms G.711 frame at 8 kHz.
const FRAME: usize = 160;

fn ulaw_decode_setup() -> (G711, [u8; FRAME], [i16; FRAME]) {
    (G711::ulaw(), [0x7f; FRAME], [0i16; FRAME])
}

fn ulaw_encode_setup() -> (G711, [i16; FRAME], [u8; FRAME]) {
    let pcm = std::array::from_fn(|i| (((i as i32 * 401) % 65536) - 32768) as i16);
    (G711::ulaw(), pcm, [0u8; FRAME])
}

#[library_benchmark]
#[bench::ulaw(setup = ulaw_decode_setup)]
fn g711_decode(input: (G711, [u8; FRAME], [i16; FRAME])) {
    let (mut codec, payload, mut out) = input;
    let _ = black_box(codec.decode(black_box(&payload), &mut out));
}

#[library_benchmark]
#[bench::ulaw(setup = ulaw_encode_setup)]
fn g711_encode(input: (G711, [i16; FRAME], [u8; FRAME])) {
    let (mut codec, pcm, mut out) = input;
    let _ = black_box(codec.encode(black_box(&pcm), &mut out));
}

library_benchmark_group!(name = codec; benchmarks = g711_decode, g711_encode);

// Fail the run (non-zero exit) if any measured kernel executes >10% more instructions than the
// `--baseline`. Instruction counts are deterministic under callgrind, so this is a real regression,
// not runner noise. The CI `perf-gate` job saves `main`'s baseline, then re-runs with `--baseline=main`.
main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().soft_limits([(EventKind::Ir, 10.0)]));
    library_benchmark_groups = codec
);
