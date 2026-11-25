//! EVS decoder cost per 20 ms frame, over TS 26.444 conformance sequences the decoder reproduces
//! bit-exactly: one sequence per core and extension layer, so a regression shows up in the path it
//! is in.
//!
//! `cargo bench -p siphon-rtp-codec --features evs --bench evs_bench`
//!
//! There is no EVS encoder, and the sequences are copyrighted and gitignored, so the bench reads
//! them from `reference/evs/testvec` (`sh reference/evs/fetch.sh`, or `$SIPHON_RTP_EVS_VECTORS`)
//! and skips a sequence that is absent. Each iteration decodes the whole sequence on a fresh decoder
//! (built outside the timed section); the throughput is in frames, so criterion reports the cost of
//! one frame. `evs_rtp_*` time the RTP path (depacketize + decode) on the committed reference-encoder
//! frames, which need no download.

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
    // AMR-WB IO at 12.65 kbit/s with the 6 - 8 kHz band extension
    (
        "evs_decode_amr_wb_io_12k65",
        "amrwb/T03_12650_16kHz.COD",
        16000,
    ),
    // AMR-WB IO at 23.85 kbit/s (the HF gain index of that rate), DTX
    (
        "evs_decode_amr_wb_io_23k85_dtx",
        "amrwb/T03_dtx_23850_16kHz.COD",
        16000,
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

/// The reference encoder's frames of `tests/evs_rtp_kat/frames.txt` of one configuration, as the
/// header-full payloads of one frame they are (`name|index|good|bits|g192 hex|storage hex`).
#[cfg(feature = "evs")]
fn storage_frames(configuration: &str) -> Vec<Vec<u8>> {
    include_str!("../tests/evs_rtp_kat/frames.txt")
        .lines()
        .filter(|line| line.split('|').next() == Some(configuration))
        .map(|line| {
            let hex = line.split('|').nth(5).expect("storage frame");
            (0..hex.len() / 2)
                .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex"))
                .collect()
        })
        .collect()
}

/// Depacketize and decode one RTP payload through the factory's [`Decoder`], the path the engine
/// runs, against the same decoder fed the same frames as G.192 above: the difference is the
/// depacketizer. A header-full payload of one frame each, a table of contents octet then the bits.
#[cfg(feature = "evs")]
fn bench_evs_rtp(criterion: &mut Criterion) {
    use siphon_rtp_codec::evs::rtp::Packet;
    use siphon_rtp_codec::factory::{decoder_for, CodecSpec, EvsParams};

    // (name, configuration in the frame file, fmtp, how many of its frames to cycle)
    let cases: &[(&str, &str, &str)] = &[
        (
            "evs_rtp_decode_acelp_13k2_wb",
            "evs_13200",
            "bw=wb;hf-only=1",
        ),
        (
            "evs_rtp_decode_tcx_24k4_swb",
            "evs_24400",
            "bw=swb;hf-only=1",
        ),
        ("evs_rtp_decode_hq_64k_fb", "evs_64000", "bw=fb;hf-only=1"),
        (
            "evs_rtp_decode_amr_wb_io_12k65",
            "io_12650",
            "bw=wb;hf-only=1",
        ),
        (
            "evs_rtp_decode_amr_wb_io_23k85",
            "io_23850",
            "bw=wb;hf-only=1",
        ),
    ];
    for &(name, configuration, fmtp) in cases {
        let payloads = storage_frames(configuration);
        assert!(
            !payloads.is_empty(),
            "{configuration} is not in the frame file"
        );
        let spec = CodecSpec::new(96, "EVS", 16_000, 1, 20)
            .with_evs_params(Some(EvsParams::parse(fmtp).expect("fmtp")));
        let mut decoder = decoder_for(&spec).expect("EVS decoder");
        let mut out = vec![0i16; decoder.frame_samples()];
        let mut group = criterion.benchmark_group("evs_rtp");
        group.throughput(Throughput::Elements(payloads.len() as u64));
        group.bench_function(name, |bencher| {
            bencher.iter(|| {
                for payload in &payloads {
                    decoder
                        .decode(black_box(payload), black_box(&mut out))
                        .expect("decode");
                }
            });
        });
        group.finish();
    }

    // the depacketizer alone: parse, then read every frame's bits in the decoder's order
    let payloads: Vec<Vec<u8>> = ["evs_13200", "evs_64000", "io_12650", "io_23850"]
        .into_iter()
        .flat_map(storage_frames)
        .collect();
    let mut bits = [0u8; 2560];
    let mut group = criterion.benchmark_group("evs_rtp");
    group.throughput(Throughput::Elements(payloads.len() as u64));
    group.bench_function("evs_rtp_depacketize", |bencher| {
        bencher.iter(|| {
            for payload in &payloads {
                let packet = Packet::parse(black_box(payload), true).expect("parse");
                for frame in packet.frames() {
                    black_box(frame.decoder_bits(black_box(&mut bits)));
                }
            }
        });
    });
    group.finish();
}

#[cfg(not(feature = "evs"))]
fn bench_evs_rtp(_criterion: &mut Criterion) {}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_evs_decode, bench_evs_rtp
}
criterion_main!(benches);
