//! Criterion perf gates for the codec hot paths. `cargo bench -p siphon-rtp-codec`.
//!
//! These lock per-frame / per-subframe cost so a regression fails CI. The AMR-WB decoder kernels
//! are benched per-tier, plus the full mode-0 frame decode (`dec_main`) once it is wired.

#[cfg(feature = "amr")]
use criterion::BatchSize;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
#[cfg(feature = "amr")]
use siphon_rtp_codec::amr::basic_ops;
#[cfg(feature = "amr")]
use siphon_rtp_codec::amr::nb::dec_main::SpeechDecoder as NbSpeechDecoder;
#[cfg(feature = "amr")]
use siphon_rtp_codec::amr::wb::dec_main::{decode_frame, DecoderState};
#[cfg(feature = "amr")]
use siphon_rtp_codec::amr::wb::{codebook, constants, filters, lpc, pitch};
#[cfg(feature = "amr")]
use siphon_rtp_codec::amr::{AmrNb, AmrNbMode, AmrWb, AMRWB_SPEECH_BITS};
use siphon_rtp_codec::cn::Cn;
use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::g722::G722;
use siphon_rtp_codec::g726::{Rate, G726};
use siphon_rtp_codec::gsm_fr::GsmFr;
use siphon_rtp_codec::{Decoder, Encoder};

#[cfg(feature = "amr")]
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

/// G.722 sub-band ADPCM encode/decode cost per 20 ms frame (320 samples ↔ 160 bytes). Encode and
/// decode are stateful, so per-call cost is what the relay datapath pays per frame.
fn bench_g722(criterion: &mut Criterion) {
    const G722_FRAME: usize = 320; // 20 ms at 16 kHz
    let pcm: Vec<i16> = (0..G722_FRAME)
        .map(|i| (((i as i32 * 401) % 65536) - 32768) as i16)
        .collect();
    let mut payload = vec![0u8; G722_FRAME / 2];
    let mut out_pcm = vec![0i16; G722_FRAME];

    let mut encoder = G722::new(20);
    criterion.bench_function("g722_encode_frame", |bencher| {
        bencher.iter(|| {
            encoder
                .encode(black_box(&pcm), black_box(&mut payload))
                .expect("encode")
        });
    });

    // Seed a representative payload from a fresh encoder, then bench the stateful decode.
    G722::new(20)
        .encode(&pcm, &mut payload)
        .expect("seed payload");
    let mut decoder = G722::new(20);
    criterion.bench_function("g722_decode_frame", |bencher| {
        bencher.iter(|| {
            decoder
                .decode(black_box(&payload), black_box(&mut out_pcm))
                .expect("decode")
        });
    });
}

/// G.726 ADPCM encode/decode cost per 20 ms frame at 32 kbit/s (the common VoIP rate; 160 samples ↔
/// 80 bytes). The 16/24/40 kbit/s rates share the same per-sample cost.
fn bench_g726(criterion: &mut Criterion) {
    const G726_FRAME: usize = 160; // 20 ms at 8 kHz
    let pcm: Vec<i16> = (0..G726_FRAME)
        .map(|i| (((i as i32 * 401) % 65536) - 32768) as i16)
        .collect();
    let mut payload = vec![0u8; 80]; // 4 bits/sample × 160 / 8
    let mut out_pcm = vec![0i16; G726_FRAME];

    let mut encoder = G726::new(Rate::R32, 20);
    criterion.bench_function("g726_32_encode_frame", |bencher| {
        bencher.iter(|| {
            encoder
                .encode(black_box(&pcm), black_box(&mut payload))
                .expect("encode")
        });
    });

    G726::new(Rate::R32, 20)
        .encode(&pcm, &mut payload)
        .expect("seed payload");
    let mut decoder = G726::new(Rate::R32, 20);
    criterion.bench_function("g726_32_decode_frame", |bencher| {
        bencher.iter(|| {
            decoder
                .decode(black_box(&payload), black_box(&mut out_pcm))
                .expect("decode")
        });
    });
}

/// GSM 06.10 Full-Rate (RPE-LTP) encode/decode cost per 20 ms frame (160 samples ↔ 33 bytes).
fn bench_gsm_fr(criterion: &mut Criterion) {
    let pcm: Vec<i16> = (0..160usize)
        .map(|i| (((i as i32 * 401) % 65536) - 32768) as i16)
        .collect();
    let mut payload = vec![0u8; 33];
    let mut out_pcm = vec![0i16; 160];

    let mut encoder = GsmFr::new();
    criterion.bench_function("gsm_fr_encode_frame", |bencher| {
        bencher.iter(|| {
            encoder
                .encode(black_box(&pcm), black_box(&mut payload))
                .expect("encode")
        });
    });

    GsmFr::new()
        .encode(&pcm, &mut payload)
        .expect("seed payload");
    let mut decoder = GsmFr::new();
    criterion.bench_function("gsm_fr_decode_frame", |bencher| {
        bencher.iter(|| {
            decoder
                .decode(black_box(&payload), black_box(&mut out_pcm))
                .expect("decode")
        });
    });
}

/// RFC 3389 comfort-noise generation cost per 20 ms frame (a CN level byte → 160 noise samples).
fn bench_cn(criterion: &mut Criterion) {
    let mut codec = Cn::new(8000, 20);
    let mut out = vec![0i16; 160];
    criterion.bench_function("cn_generate_frame", |bencher| {
        bencher.iter(|| {
            codec
                .decode(black_box(&[40u8]), black_box(&mut out))
                .expect("cn")
        });
    });
}

#[cfg(feature = "amr")]
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
#[cfg(feature = "amr")]
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
    let sig12k8: Vec<i16> = (0..SUBFR)
        .map(|i| ((i * 211 % 2000) as i16) - 1000)
        .collect();
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
#[cfg(feature = "amr")]
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
#[cfg(feature = "amr")]
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

/// AMR-NB full per-frame decode (`dec_main`), one bench per speech mode (0..=7), over the official
/// `T_<mode>` vectors. The decoder is warmed through the preceding frames so the timed decode sees
/// realistic filter/predictor memory (not the post-reset transient).
#[cfg(feature = "amr")]
fn bench_amrnb_decode(criterion: &mut Criterion) {
    // (mode index, vector tag) for the 8 speech modes.
    const MODES: [(usize, &str); 8] = [
        (0, "475"),
        (1, "515"),
        (2, "59"),
        (3, "67"),
        (4, "74"),
        (5, "795"),
        (6, "102"),
        (7, "122"),
    ];
    const FRAME_WORDS: usize = 250; // 1 + 244 + 1 + 4

    for (mode, tag) in MODES {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(format!(
            "../../reference/amr-nb/testv/NODTX/T_{tag}/T01_{tag}.COD"
        ));
        let Ok(cod) = std::fs::read(&path) else {
            continue; // vectors not present in this checkout
        };
        let cod_words: Vec<i16> = cod
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();

        let frame_index = 12usize.min(cod_words.len() / FRAME_WORDS - 1);
        let base = frame_index * FRAME_WORDS;
        let bits: Vec<i16> = cod_words[base + 1..base + 1 + 244].to_vec();

        let mut dec = NbSpeechDecoder::new();
        let mut out = vec![0i16; FRAME];
        for f in 0..frame_index {
            let fb = &cod_words[f * FRAME_WORDS + 1..f * FRAME_WORDS + 1 + 244];
            dec.decode_frame(mode, fb, &mut out);
        }
        let warm = dec.clone();

        criterion.bench_function(&format!("amrnb_decode_mode{mode}_frame"), |bencher| {
            bencher.iter_batched(
                || warm.clone(),
                |mut st| st.decode_frame(mode, black_box(&bits), black_box(&mut out)),
                BatchSize::SmallInput,
            );
        });
    }
}

/// Full per-mode frame encode (µs/frame): the whole `coder()` analysis pipeline, for every speech
/// mode 0..=8. Mode 8 additionally pays for the high-band `synthesis()` + HF-gain quantization.
/// Reads a real warmed-up speech frame from the 3GPP `tst.inp` input; if the (gitignored) input is
/// absent the bench is skipped so CI without the vectors still builds.
#[cfg(feature = "amr")]
fn bench_amrwb_encode(criterion: &mut Criterion) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../reference/amr-wb/testv/tst.inp");
    let Ok(inp) = std::fs::read(&path) else {
        return; // input vector not present in this checkout
    };
    let pcm: Vec<i16> = inp
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();
    let n_frames = pcm.len() / constants::L_FRAME16K;
    // Pick frame 8 — the first frame with real (non-silence, post-homing) speech energy.
    let frame_index = 8usize;
    if n_frames <= frame_index {
        return;
    }

    for mode in 0u8..=8 {
        let nb_bits = AMRWB_SPEECH_BITS[mode as usize] as usize;
        let frame_pcm: Vec<i16> = pcm
            [frame_index * constants::L_FRAME16K..(frame_index + 1) * constants::L_FRAME16K]
            .to_vec();

        // Warm the encoder state through the preceding frames so the bench sees realistic memory.
        let mut warm = AmrWb::new();
        let mut out = vec![0i16; nb_bits];
        for f in 0..frame_index {
            let fp = &pcm[f * constants::L_FRAME16K..(f + 1) * constants::L_FRAME16K];
            warm.encode_mode_bits(mode, fp, &mut out)
                .expect("warm encode");
        }

        criterion.bench_function(&format!("amrwb_encode_mode{mode}_frame"), |bencher| {
            // Clone the warmed state outside the timed section so only the encode is measured.
            bencher.iter_batched(
                || warm.clone(),
                |mut st| {
                    st.encode_mode_bits(mode, black_box(&frame_pcm), black_box(&mut out))
                        .expect("encode")
                },
                BatchSize::SmallInput,
            );
        });
    }
}

/// Full per-frame AMR-NB encode (µs/frame): the whole `cod_amr()` analysis-by-synthesis pipeline for
/// all eight speech modes — MR475 (2-pulse codebook + joint 2-subframe gain), the 2/3/4-pulse medium
/// rates, MR795 (4-pulse codebook + adaptive two-index gain), MR102 (8-pulse 31-bit codebook) and
/// MR122 (10-pulse GSM-EFR codebook). Reads a real warmed-up speech frame from the 3GPP `T01.INP`
/// input; skipped if the (gitignored) input is absent so CI without the vectors still builds.
#[cfg(feature = "amr")]
fn bench_amrnb_encode(criterion: &mut Criterion) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../reference/amr-nb/testv/NODTX/T_INP/T01.INP");
    let Ok(inp) = std::fs::read(&path) else {
        return; // input vector not present in this checkout
    };
    let pcm: Vec<i16> = inp
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();
    let n_frames = pcm.len() / FRAME;
    // Frame 12 — real (non-silence, post-homing) speech energy, matching the decode bench.
    let frame_index = 12usize;
    if n_frames <= frame_index {
        return;
    }

    for mode in [
        AmrNbMode::Mr475,
        AmrNbMode::Mr515,
        AmrNbMode::Mr590,
        AmrNbMode::Mr670,
        AmrNbMode::Mr740,
        AmrNbMode::Mr795,
        AmrNbMode::Mr1020,
        AmrNbMode::Mr1220,
    ] {
        let nb_bits = mode.bits() as usize;
        let frame_pcm: Vec<i16> = pcm[frame_index * FRAME..(frame_index + 1) * FRAME].to_vec();

        // Warm the encoder state through the preceding frames so the bench sees realistic memory.
        let mut warm = AmrNb::new();
        let mut out = vec![0i16; nb_bits];
        for f in 0..frame_index {
            let fp = &pcm[f * FRAME..(f + 1) * FRAME];
            warm.encode_mode_bits(mode, fp, &mut out)
                .expect("warm encode");
        }

        criterion.bench_function(
            &format!("amrnb_encode_mode{}_frame", mode.frame_type()),
            |bencher| {
                // Clone the warmed state outside the timed section so only the encode is measured.
                bencher.iter_batched(
                    || warm.clone(),
                    |mut st| {
                        st.encode_mode_bits(mode, black_box(&frame_pcm), black_box(&mut out))
                            .expect("encode")
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

/// Full-frame [`siphon_rtp_codec::Encoder::encode`] (RTP payload = CMR | ToC | speech) with and
/// without a per-frame RFC 4867 Codec Mode Request (`request_mode`), proving the `mode-set` clamp
/// adds no measurable per-frame cost. Uses synthetic PCM so it runs without the reference vector.
#[cfg(feature = "amr")]
fn bench_amrwb_encode_cmr(criterion: &mut Criterion) {
    use siphon_rtp_codec::Encoder;

    // A deterministic 20 ms / 16 kHz frame (no reference input needed).
    let frame_pcm: Vec<i16> = (0..constants::L_FRAME16K)
        .map(|i| (((i as i32 * 137) % 8000) - 4000) as i16)
        .collect();
    let mut out = vec![0u8; 64];

    // Plain full-frame encode at the default mode.
    let warm = AmrWb::new();
    criterion.bench_function("amrwb_encode_frame", |bencher| {
        bencher.iter_batched(
            || warm.clone(),
            |mut st| {
                st.encode(black_box(&frame_pcm), black_box(&mut out))
                    .expect("encode")
            },
            BatchSize::SmallInput,
        );
    });

    // Same, but a per-frame CMR is applied first (clamped to a mode-set). The bitmask clamp is a
    // handful of bit ops with no allocation — this case must match `amrwb_encode_frame`.
    let warm_cmr = AmrWb::new().with_allowed_modes(&[0, 1, 2]);
    criterion.bench_function("amrwb_encode_frame_with_cmr", |bencher| {
        bencher.iter_batched(
            || warm_cmr.clone(),
            |mut st| {
                st.request_mode(black_box(2));
                st.encode(black_box(&frame_pcm), black_box(&mut out))
                    .expect("encode")
            },
            BatchSize::SmallInput,
        );
    });
}

// AMR-WB/NB kernel benches are compiled only when the patent-gated `amr` feature is enabled.
#[cfg(feature = "amr")]
criterion_group!(
    benches,
    bench_g711,
    bench_g722,
    bench_g726,
    bench_gsm_fr,
    bench_cn,
    bench_basic_ops,
    bench_amrwb_dsp,
    bench_amrwb_codebook,
    bench_amrwb_decode,
    bench_amrnb_decode,
    bench_amrwb_encode,
    bench_amrnb_encode,
    bench_amrwb_encode_cmr
);
#[cfg(not(feature = "amr"))]
criterion_group!(
    benches,
    bench_g711,
    bench_g722,
    bench_g726,
    bench_gsm_fr,
    bench_cn
);
criterion_main!(benches);
