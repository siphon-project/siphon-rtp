//! Criterion perf gates for the codec hot paths. `cargo bench -p siphon-rtp-codec`.
//!
//! These lock per-frame / per-subframe cost so a regression fails CI. The AMR-WB decoder kernels
//! are benched per-tier, plus the full mode-0 frame decode (`dec_main`) once it is wired.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use siphon_rtp_codec::amr::wb::dec_main::{decode_frame, DecoderState};
use siphon_rtp_codec::amr::wb::{codebook, constants, filters, lpc, pitch};
use siphon_rtp_codec::amr::basic_ops;
use siphon_rtp_codec::amr::AMRWB_SPEECH_BITS;
use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::{Decoder, Encoder};

use std::path::PathBuf;

/// One 20 ms frame of 8 kHz audio.
const FRAME: usize = 160;

fn sample_pcm() -> Vec<i16> {
    // A deterministic sweep so the encoder exercises multiple segments.
    (0..FRAME)
        .map(|i| (((i as i32 * 401) % 65536) - 32768) as i16)
        .collect()
}

fn bench_g711(criterion: &mut Criterion) {
    let pcm = sample_pcm();
    let mut payload = vec![0u8; FRAME];
    let mut out_pcm = vec![0i16; FRAME];

    let mut ulaw = G711::ulaw();
    criterion.bench_function("g711_ulaw_encode_frame", |bencher| {
        bencher.iter(|| {
            ulaw.encode(black_box(&pcm), black_box(&mut payload))
                .expect("encode")
        });
    });
    ulaw.encode(&pcm, &mut payload).expect("seed payload");
    criterion.bench_function("g711_ulaw_decode_frame", |bencher| {
        bencher.iter(|| {
            ulaw.decode(black_box(&payload), black_box(&mut out_pcm))
                .expect("decode")
        });
    });

    let mut alaw = G711::alaw();
    criterion.bench_function("g711_alaw_encode_frame", |bencher| {
        bencher.iter(|| {
            alaw.encode(black_box(&pcm), black_box(&mut payload))
                .expect("encode")
        });
    });
}

fn bench_basic_ops(criterion: &mut Criterion) {
    // A correlation-style MAC loop — the shape of the AMR pitch/FIR hot kernels.
    let signal: Vec<i16> = sample_pcm();
    criterion.bench_function("basic_ops_mac_correlation_160", |bencher| {
        bencher.iter(|| {
            let mut acc: i32 = 0;
            for window in signal.windows(2) {
                acc = basic_ops::l_mac(acc, black_box(window[0]), black_box(window[1]));
            }
            black_box(acc)
        });
    });
}

/// AMR-WB decode hot-path kernels (µs/frame and µs/subframe), the ported DSP tiers.
fn bench_amrwb_dsp(criterion: &mut Criterion) {
    const M: usize = constants::M;
    const SUBFR: usize = constants::L_SUBFR;

    // A realistic ISP from a dequantized ISF envelope.
    let isf: [i16; M] = [
        500, 1100, 1900, 2800, 3900, 5100, 6400, 7800, 9200, 10500, 11700, 12700, 13500, 14100,
        14600, 7000,
    ];
    let mut isp = [0i16; M];
    lpc::isf_isp(&isf, &mut isp, M);

    // ISP → 4 subframe LP coefficient sets (per 20 ms frame): the LPC reconstruction.
    let mut az = [0i16; 4 * (M + 1)];
    criterion.bench_function("amrwb_int_isp_frame", |bencher| {
        bencher.iter(|| {
            lpc::int_isp(
                black_box(&isp),
                black_box(&isp),
                black_box(&[8192, 16384, 24576]),
                black_box(&mut az),
            )
        });
    });

    // One ISP → LP-coefficient conversion (Chebyshev), called 4×/frame inside int_isp.
    let mut a = [0i16; M + 1];
    criterion.bench_function("amrwb_isp_az", |bencher| {
        bencher.iter(|| lpc::isp_az(black_box(&isp), black_box(&mut a), M, false));
    });

    // Order-16 LPC synthesis, one subframe.
    lpc::isp_az(&isp, &mut a, M, false);
    let exc: Vec<i16> = (0..SUBFR).map(|i| ((i * 131 % 512) as i16) - 256).collect();
    let mut sig_hi = vec![0i16; M + SUBFR];
    let mut sig_lo = vec![0i16; M + SUBFR];
    criterion.bench_function("amrwb_syn_filt_subfr", |bencher| {
        bencher.iter(|| {
            filters::syn_filt_32(
                black_box(&a),
                M,
                black_box(&exc),
                0,
                &mut sig_hi,
                &mut sig_lo,
                SUBFR,
            )
        });
    });

    // Adaptive-codebook (pitch) interpolation, one subframe.
    let history = constants::PIT_MAX + constants::L_INTERPOL;
    let mut pexc = vec![0i16; history + SUBFR];
    for (i, v) in pexc.iter_mut().enumerate() {
        *v = ((i * 97 % 400) as i16) - 200;
    }
    criterion.bench_function("amrwb_pred_lt4_subfr", |bencher| {
        bencher.iter(|| pitch::pred_lt4(black_box(&mut pexc), history, 100, 2, SUBFR));
    });

    // 12.8 → 16 kHz 5/4 oversampler, one subframe.
    let sig12k8: Vec<i16> = (0..SUBFR).map(|i| ((i * 211 % 2000) as i16) - 1000).collect();
    let mut sig16k = vec![0i16; SUBFR * 5 / 4];
    let mut mem = [0i16; 24]; // 2 * NB_COEF_UP
    criterion.bench_function("amrwb_oversamp_subfr", |bencher| {
        bencher.iter(|| {
            filters::oversamp_16k(black_box(&sig12k8), SUBFR, black_box(&mut sig16k), &mut mem)
        });
    });
}

/// The 4-track algebraic codebook decode (µs/subframe), the per-subframe innovative-code kernel for
/// the higher modes. Benches the 36-bit (mode-2 / 12.65k VoLTE) and 88-bit (mode 7/8) budgets.
fn bench_amrwb_codebook(criterion: &mut Criterion) {
    let mut code = [0i16; constants::L_SUBFR];
    let ind36 = [0x12i16, 0x55, 0x1AA, 0x0FF];
    criterion.bench_function("amrwb_dec_acelp_4t64_36bit", |bencher| {
        bencher.iter(|| codebook::dec_acelp_4t64(black_box(&ind36), 36, black_box(&mut code)));
    });
    let ind88 = [0x123i16, 0x456, 0x789, 0x2AB, 0x3CD, 0x1EF, 0x012, 0x345];
    criterion.bench_function("amrwb_dec_acelp_4t64_88bit", |bencher| {
        bencher.iter(|| codebook::dec_acelp_4t64(black_box(&ind88), 88, black_box(&mut code)));
    });
}

/// Full per-mode frame decode (µs/frame): the whole `dec_main` pipeline including the 16 kHz HF
/// synthesis, for every speech mode 0..=8. Reads a real warmed-up speech frame from the 3GPP
/// `tst_mN.cod` vectors; if a (gitignored) vector is absent that mode's bench is skipped so CI
/// without the vectors still builds.
fn bench_amrwb_decode(criterion: &mut Criterion) {
    for mode in 0u8..=8 {
        let nb_bits = AMRWB_SPEECH_BITS[mode as usize] as usize;
        let cod_frame_words = 3 + nb_bits;

        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(format!("../../reference/amr-wb/testv/tst_m{mode}.cod"));
        let Ok(cod) = std::fs::read(&path) else {
            continue; // vectors not present in this checkout
        };
        let cod_words: Vec<i16> = cod
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();

        // Pick frame 8 — the first frame with real (non-silence, post-homing) speech energy.
        let frame_index = 8usize;
        let base = frame_index * cod_frame_words;
        let bits: Vec<i16> = cod_words[base + 3..base + cod_frame_words].to_vec();

        // Warm the decoder state through the preceding frames so the bench sees realistic memory.
        let mut state = DecoderState::new();
        let mut out = vec![0i16; constants::L_FRAME16K];
        for f in 0..frame_index {
            let fb = &cod_words[f * cod_frame_words + 3..(f + 1) * cod_frame_words];
            decode_frame(&mut state, mode, fb, &mut out);
        }
        let warm = state.clone();

        criterion.bench_function(&format!("amrwb_decode_mode{mode}_frame"), |bencher| {
            // Clone the warmed state outside the timed section so only the decode is measured.
            bencher.iter_batched(
                || warm.clone(),
                |mut st| decode_frame(&mut st, mode, black_box(&bits), black_box(&mut out)),
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(
    benches,
    bench_g711,
    bench_basic_ops,
    bench_amrwb_dsp,
    bench_amrwb_codebook,
    bench_amrwb_decode
);
criterion_main!(benches);
