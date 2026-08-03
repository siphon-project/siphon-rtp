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
use siphon_rtp_codec::opus::celt::decoder::CeltDecoder;
use siphon_rtp_codec::opus::celt::encoder::{CeltEncoder, RateControl};
use siphon_rtp_codec::opus::celt::mdct::{clt_mdct_forward, MdctLookup};
use siphon_rtp_codec::opus::celt::tables::{OVERLAP, WINDOW120};
use siphon_rtp_codec::opus::celt::vq::op_pvq_search;
use siphon_rtp_codec::opus::decoder::{OpusDecoder, MAX_PACKET_SAMPLES};
use siphon_rtp_codec::{Decoder, Encoder};

/// One 20 ms G.711 frame at 8 kHz.
const FRAME: usize = 160;
/// One 20 ms CELT frame at 48 kHz.
const CELT_FRAME: usize = 960;

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

/// A deterministic 48 kHz signal in `[-1, 1)`: harmonics plus a little noise, so the CELT analysis
/// takes realistic branches instead of the degenerate ones a pure tone or silence would.
fn celt_signal(samples: usize) -> Vec<f32> {
    let mut state = 0x5EED_u32;
    (0..samples)
        .map(|i| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let noise = ((state >> 16) as f32 / 32768.0 - 1.0) * 0.02;
            let t = i as f32;
            0.35 * (t * 0.031).sin() + 0.18 * (t * 0.097).sin() + 0.07 * (t * 0.21).cos() + noise
        })
        .collect()
}

type CeltEncodeInput = (CeltEncoder, Vec<f32>, Vec<u8>);

fn celt_encode_setup() -> CeltEncodeInput {
    let mut encoder = CeltEncoder::new().expect("build CELT encoder");
    encoder.set_bitrate(64_000);
    encoder.set_rate_control(RateControl::ConstrainedVbr);
    // Prime the encoder so the measured frame runs with a warm prefilter / energy history rather
    // than the cheaper start-up state.
    let signal = celt_signal(2 * CELT_FRAME);
    let mut payload = vec![0u8; 1275];
    let _ = encoder.encode(&signal[..CELT_FRAME], CELT_FRAME, &mut payload);
    (encoder, signal[CELT_FRAME..].to_vec(), payload)
}

/// Interleave a mono signal with a decorrelated copy of itself, so the stereo band coder has a real
/// mid/side decision to make instead of the degenerate "both channels identical" one.
fn celt_stereo_signal(samples: usize) -> Vec<f32> {
    let left = celt_signal(samples);
    let right = celt_signal(samples + 7);
    (0..samples)
        .flat_map(|i| [left[i], 0.6 * left[i] + 0.4 * right[i + 7]])
        .collect()
}

fn celt_stereo_encode_setup() -> CeltEncodeInput {
    let mut encoder = CeltEncoder::with_channels(2).expect("build stereo CELT encoder");
    encoder.set_bitrate(96_000);
    encoder.set_rate_control(RateControl::ConstrainedVbr);
    let signal = celt_stereo_signal(2 * CELT_FRAME);
    let mut payload = vec![0u8; 1275];
    let _ = encoder.encode(&signal[..2 * CELT_FRAME], CELT_FRAME, &mut payload);
    (encoder, signal[2 * CELT_FRAME..].to_vec(), payload)
}

type CeltDecodeInput = (CeltDecoder, Vec<u8>, Vec<i16>);

/// Encode two frames at `channels`, hand back the decoder primed on the first and the second
/// packet: the measured call then decodes with a warm ring and energy history.
fn celt_decode_setup(channels: usize, bitrate: i32) -> CeltDecodeInput {
    let mut encoder = CeltEncoder::with_channels(channels).expect("build CELT encoder");
    encoder.set_bitrate(bitrate);
    encoder.set_rate_control(RateControl::ConstrainedVbr);
    let signal = if channels == 2 {
        celt_stereo_signal(2 * CELT_FRAME)
    } else {
        celt_signal(2 * CELT_FRAME)
    };
    let block = CELT_FRAME * channels;
    let mut payload = vec![0u8; 1275];
    let mut decoder = CeltDecoder::with_channels(channels).expect("build CELT decoder");
    let mut pcm = vec![0i16; block];
    let first = encoder
        .encode(&signal[..block], CELT_FRAME, &mut payload)
        .expect("encode");
    let first = payload[..first].to_vec();
    let _ = decoder.decode(&first, &mut pcm, CELT_FRAME);
    let second = encoder
        .encode(&signal[block..2 * block], CELT_FRAME, &mut payload)
        .expect("encode");
    (decoder, payload[..second].to_vec(), pcm)
}

fn celt_decode_mono_setup() -> CeltDecodeInput {
    celt_decode_setup(1, 64_000)
}

fn celt_decode_stereo_setup() -> CeltDecodeInput {
    celt_decode_setup(2, 96_000)
}

type MdctInput = (MdctLookup, Vec<f32>, Vec<f32>);

fn celt_mdct_setup() -> MdctInput {
    let lookup = MdctLookup::new(1920, 3).expect("build 48 kHz MDCT lookup");
    (
        lookup,
        celt_signal(CELT_FRAME + OVERLAP),
        vec![0f32; CELT_FRAME],
    )
}

type PvqInput = (Vec<f32>, Vec<i32>);

fn celt_pvq_setup() -> PvqInput {
    let shape: Vec<f32> = (0..16).map(|i| (i as f32 * 0.41).sin()).collect();
    (shape, vec![0i32; 16])
}

// One whole 20 ms CELT frame through the encoder — the per-frame cost the datapath pays.
#[library_benchmark]
#[bench::mono_20ms(setup = celt_encode_setup)]
fn celt_encode(input: CeltEncodeInput) {
    let (mut encoder, signal, mut payload) = input;
    let _ = black_box(encoder.encode(black_box(&signal[..CELT_FRAME]), CELT_FRAME, &mut payload));
}

// The same frame in stereo: mid/side plus intensity on top of two channels of analysis and MDCT.
#[library_benchmark]
#[bench::stereo_20ms(setup = celt_stereo_encode_setup)]
fn celt_encode_stereo(input: CeltEncodeInput) {
    let (mut encoder, signal, mut payload) = input;
    let _ = black_box(encoder.encode(
        black_box(&signal[..2 * CELT_FRAME]),
        CELT_FRAME,
        &mut payload,
    ));
}

// One 20 ms CELT frame through the decoder, mono and stereo — the relay/transcode ingress cost.
#[library_benchmark]
#[bench::mono_20ms(setup = celt_decode_mono_setup)]
#[bench::stereo_20ms(setup = celt_decode_stereo_setup)]
fn celt_decode(input: CeltDecodeInput) {
    let (mut decoder, packet, mut pcm) = input;
    let _ = black_box(decoder.decode(black_box(&packet), &mut pcm, CELT_FRAME));
}

// The forward MDCT alone (20 ms long block), so a transform regression is localised.
#[library_benchmark]
#[bench::long_20ms(setup = celt_mdct_setup)]
fn celt_mdct_forward(input: MdctInput) {
    let (lookup, signal, mut out) = input;
    clt_mdct_forward(
        &lookup,
        black_box(&signal),
        &mut out,
        &WINDOW120,
        OVERLAP,
        0,
        1,
    );
    black_box(out[0]);
}

// The PVQ nearest-neighbour search — the encoder's hottest inner loop, run once per band leaf.
#[library_benchmark]
#[bench::n16_k8(setup = celt_pvq_setup)]
fn celt_pvq_search(input: PvqInput) {
    let (mut x, mut iy) = input;
    let _ = black_box(op_pvq_search(black_box(&mut x), &mut iy, 8, 16));
}

type OpusDecodeInput = (OpusDecoder, Vec<u8>, Vec<i16>);

/// A deterministic 20 ms packet in the given mode, and a decoder already primed on an identical one
/// so the measured call runs with warm state (decode ring, energy history, SILK prediction) rather
/// than paying a first-frame cost the datapath never pays twice.
///
/// The payload is a fixed pseudo-random byte string rather than a real encode: there is no SILK
/// encoder yet, and the official vectors are gitignored, so a self-contained bench is the only one
/// that can run on a CI box. The range coder reads any byte string, so every stage still executes —
/// what it decodes to is not audio, but the instruction count is deterministic, which is the whole
/// point of this file.
fn opus_decode_setup(config: u8, channels: usize) -> OpusDecodeInput {
    let mut packet = Vec::with_capacity(61);
    packet.push(config << 3);
    for i in 0..60u32 {
        packet.push((i.wrapping_mul(2_654_435_761) >> 24) as u8);
    }
    packet[1] &= 0x7f; // bias away from the CELT silence flag so the full pipeline runs
    let mut decoder = OpusDecoder::new(48_000, channels).expect("build Opus decoder");
    let mut pcm = vec![0i16; MAX_PACKET_SAMPLES * channels];
    decoder
        .decode(Some(&packet), &mut pcm, MAX_PACKET_SAMPLES, false)
        .expect("prime the decoder");
    (decoder, packet, pcm)
}

/// SILK-only, wideband, 20 ms (config 9).
fn opus_decode_silk_setup() -> OpusDecodeInput {
    opus_decode_setup(9, 1)
}

/// Hybrid, fullband, 20 ms (config 15) — both layers on one payload, the expensive case.
fn opus_decode_hybrid_setup() -> OpusDecodeInput {
    opus_decode_setup(15, 1)
}

/// CELT-only, fullband, 20 ms (config 31).
fn opus_decode_celt_setup() -> OpusDecodeInput {
    opus_decode_setup(31, 1)
}

/// Hybrid in stereo: two SILK channels plus CELT mid/side on the same payload.
fn opus_decode_hybrid_stereo_setup() -> OpusDecodeInput {
    opus_decode_setup(15, 2)
}

// One whole 20 ms Opus *packet* through the top-level decoder, per mode: TOC dispatch, the layer(s)
// it selects, and the output conversion. This is the per-packet cost an Opus leg actually pays.
#[library_benchmark]
#[bench::silk_20ms(setup = opus_decode_silk_setup)]
#[bench::hybrid_20ms(setup = opus_decode_hybrid_setup)]
#[bench::celt_20ms(setup = opus_decode_celt_setup)]
#[bench::hybrid_20ms_stereo(setup = opus_decode_hybrid_stereo_setup)]
fn opus_decode(input: OpusDecodeInput) {
    let (mut decoder, packet, mut pcm) = input;
    let _ = black_box(decoder.decode(
        Some(black_box(&packet)),
        &mut pcm,
        MAX_PACKET_SAMPLES,
        false,
    ));
}

// Concealment in each mode: what a lossy leg pays for a packet that never arrived.
#[library_benchmark]
#[bench::silk_20ms(setup = opus_decode_silk_setup)]
#[bench::hybrid_20ms(setup = opus_decode_hybrid_setup)]
#[bench::celt_20ms(setup = opus_decode_celt_setup)]
fn opus_conceal(input: OpusDecodeInput) {
    let (mut decoder, _packet, mut pcm) = input;
    let _ = black_box(decoder.decode(None, &mut pcm, 960, false));
}

library_benchmark_group!(
    name = codec;
    benchmarks =
        g711_decode,
        g711_encode,
        celt_encode,
        celt_encode_stereo,
        celt_decode,
        celt_mdct_forward,
        celt_pvq_search,
        opus_decode,
        opus_conceal
);

// Fail the run (non-zero exit) if any measured kernel executes >10% more instructions than the
// `--baseline`. Instruction counts are deterministic under callgrind, so this is a real regression,
// not runner noise. The CI `perf-gate` job saves `main`'s baseline, then re-runs with `--baseline=main`.
main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().soft_limits([(EventKind::Ir, 10.0)]));
    library_benchmark_groups = codec
);
