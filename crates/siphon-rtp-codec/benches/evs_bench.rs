//! EVS decoder cost per 20 ms frame, over TS 26.444 conformance sequences the decoder reproduces
//! bit-exactly: one sequence per core and extension layer, so a regression shows up in the path it
//! is in.
//!
//! `cargo bench -p siphon-rtp-codec --features evs --bench evs_bench`
//!
//! There is no EVS encoder yet, and the sequences are copyrighted and gitignored, so the bench reads
//! them from `reference/evs/testvec` (`sh reference/evs/fetch.sh`, or `$SIPHON_RTP_EVS_VECTORS`)
//! and skips a sequence that is absent. Each iteration decodes the whole sequence on a fresh decoder
//! (built outside the timed section); the throughput is in frames, so criterion reports the cost of
//! one frame.

#![allow(clippy::expect_used, reason = "bench harness: a panic reports failure")]

#[cfg(feature = "evs")]
use criterion::{black_box, BatchSize, Throughput};
use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "evs")]
use siphon_rtp_codec::evs::decoder::EvsDecoder;
#[cfg(feature = "evs")]
use siphon_rtp_codec::evs::g192::G192Reader;

/// (bench name, bitstream under `testv/bitstreams`, output rate in Hz).
#[cfg(feature = "evs")]
const SEQUENCES: &[(&str, &str, u32)] = &[
    // ACELP core, WB
    ("evs_decode_acelp_7k2_wb", "wb/stv16c_7200_16kHz.COD", 16000),
    // ACELP core with the SWB time-domain bandwidth extension
    (
        "evs_decode_acelp_13k2_swb_tbe",
        "swb/stv32n2_13200_32kHz.COD",
        32000,
    ),
    // HQ (MDCT) core, WB
    ("evs_decode_hq_64k_wb", "wb/stv16c_64000_16kHz.COD", 16000),
    // HQ core with the high-rate FB bandwidth extension
    (
        "evs_decode_hq_64k_fb_hr_bwe",
        "fb/stv48c_64000_48kHz.COD",
        48000,
    ),
    // MODE2 (LPD) at 9.6 kbit/s WB: ACELP and TCX
    ("evs_decode_lpd_9k6_wb", "wb/stv16c_9600_16kHz.COD", 16000),
    // MODE2 TCX with IGF, SWB
    (
        "evs_decode_tcx_24k4_swb_igf",
        "swb/stv32c_24400_32kHz.COD",
        32000,
    ),
    // MODE2 TCX at 128 kbit/s FB
    (
        "evs_decode_tcx_128k_fb",
        "fb/stv48c_128000_48kHz.COD",
        48000,
    ),
];

#[cfg(feature = "evs")]
fn vectors_dir() -> std::path::PathBuf {
    std::env::var_os("SIPHON_RTP_EVS_VECTORS").map_or_else(
        || std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/testvec"),
        std::path::PathBuf::from,
    )
}

#[cfg(feature = "evs")]
fn bench_evs_decode(criterion: &mut Criterion) {
    let root = vectors_dir().join("testv/bitstreams");
    for &(name, file, output_rate) in SEQUENCES {
        let Ok(bytes) = std::fs::read(root.join(file)) else {
            eprintln!("skipping {name}: {file} not installed (sh reference/evs/fetch.sh)");
            continue;
        };
        let frames: Vec<_> = G192Reader::new(&bytes)
            .map(|frame| frame.expect("well-formed G.192"))
            .collect();
        let mut out = vec![0i16; 960];
        let mut group = criterion.benchmark_group("evs");
        group.throughput(Throughput::Elements(frames.len() as u64));
        group.bench_function(name, |bencher| {
            bencher.iter_batched(
                || EvsDecoder::new(output_rate).expect("decoder"),
                |mut decoder| {
                    for frame in &frames {
                        decoder
                            .decode_frame(black_box(frame), black_box(&mut out))
                            .expect("decode");
                    }
                },
                BatchSize::LargeInput,
            );
        });
        group.finish();
    }
}

#[cfg(not(feature = "evs"))]
fn bench_evs_decode(_criterion: &mut Criterion) {}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_evs_decode
}
criterion_main!(benches);
