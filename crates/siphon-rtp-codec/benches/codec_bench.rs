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
use siphon_rtp_codec::opus::celt::band_analysis::compute_band_energies;
use siphon_rtp_codec::opus::celt::encoder::{CeltEncoder, RateControl};
use siphon_rtp_codec::opus::celt::mdct::{clt_mdct_forward, MdctLookup};
use siphon_rtp_codec::opus::celt::tables::{NB_BANDS, OVERLAP, WINDOW120};
use siphon_rtp_codec::opus::celt::vq::op_pvq_search;
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

/// A deterministic 48 kHz test signal in `[-1, 1)` — a few harmonics plus a little noise, so the
/// encoder's analysis has real decisions to make (a pure tone would take unrealistically cheap paths).
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

/// The CELT **encoder** hot path, one frame per iteration — criterion's time-per-iteration is
/// therefore directly the µs/frame this repo gates on.
fn bench_celt_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("celt_encode");
    for &(label, frame_size) in &[
        ("2.5ms_120", 120usize),
        ("5ms_240", 240),
        ("10ms_480", 480),
        ("20ms_960", 960),
    ] {
        let signal = celt_signal(frame_size * 64);
        group.bench_function(label, |b| {
            let mut encoder = CeltEncoder::new().expect("build CELT encoder");
            encoder.set_bitrate(64_000);
            encoder.set_rate_control(RateControl::ConstrainedVbr);
            let mut payload = vec![0u8; 1275];
            let mut frame = 0usize;
            b.iter(|| {
                let lo = (frame % 64) * frame_size;
                frame += 1;
                black_box(
                    encoder
                        .encode(
                            black_box(&signal[lo..lo + frame_size]),
                            frame_size,
                            &mut payload,
                        )
                        .expect("encode"),
                )
            });
        });
    }
    // The rate-control extremes, at the frame size RTP actually uses.
    let signal = celt_signal(960 * 64);
    for &(label, bitrate, rate_control) in &[
        ("20ms_cbr_32k", 32_000i32, RateControl::ConstantBitrate),
        ("20ms_vbr_128k", 128_000, RateControl::Vbr),
    ] {
        group.bench_function(label, |b| {
            let mut encoder = CeltEncoder::new().expect("build");
            encoder.set_bitrate(bitrate);
            encoder.set_rate_control(rate_control);
            let mut payload = vec![0u8; 1275];
            let mut frame = 0usize;
            b.iter(|| {
                let lo = (frame % 64) * 960;
                frame += 1;
                black_box(
                    encoder
                        .encode(black_box(&signal[lo..lo + 960]), 960, &mut payload)
                        .expect("encode"),
                )
            });
        });
    }
    group.finish();
}

/// The CELT encoder's per-frame sub-kernels, so a regression can be localised.
fn bench_celt_kernels(c: &mut Criterion) {
    let mut group = c.benchmark_group("celt_kernels");
    let lookup = MdctLookup::new(1920, 3).expect("build 48 kHz MDCT lookup");

    // Forward MDCT: one long block per frame size (shift = maxLM - LM).
    for &(label, shift, n) in &[
        ("mdct_forward_2.5ms", 3usize, 120usize),
        ("mdct_forward_5ms", 2, 240),
        ("mdct_forward_10ms", 1, 480),
        ("mdct_forward_20ms", 0, 960),
    ] {
        let input = celt_signal(n + OVERLAP);
        group.bench_function(label, |b| {
            let mut out = vec![0f32; n];
            b.iter(|| {
                clt_mdct_forward(
                    &lookup,
                    black_box(&input),
                    &mut out,
                    &WINDOW120,
                    OVERLAP,
                    shift,
                    1,
                );
                black_box(out[0])
            });
        });
    }

    // Band energies over a full 20 ms spectrum.
    let spectrum: Vec<f32> = celt_signal(960).iter().map(|v| v * 4000.0).collect();
    group.bench_function("compute_band_energies_20ms", |b| {
        let mut band_e = vec![0f32; 2 * NB_BANDS];
        b.iter(|| {
            compute_band_energies(black_box(&spectrum), &mut band_e, NB_BANDS, 1, 3);
            black_box(band_e[0])
        });
    });

    // The PVQ search: the encoder's most expensive inner loop. Two representative band shapes.
    for &(label, n, k) in &[
        ("pvq_search_n16_k8", 16usize, 8usize),
        ("pvq_search_n48_k6", 48, 6),
    ] {
        let shape: Vec<f32> = (0..n).map(|i| (i as f32 * 0.41).sin()).collect();
        group.bench_function(label, |b| {
            let mut x = shape.clone();
            let mut iy = vec![0i32; n];
            b.iter(|| {
                x.copy_from_slice(&shape);
                black_box(op_pvq_search(&mut x, &mut iy, k, n))
            });
        });
    }
    group.finish();
}

/// SILK's synthesis-side per-frame costs: the §4.2.7.9 LTP + LPC filters, the §4.2.8 stereo
/// unmixing, the §4.2.9 resampler and the §4.4 concealment path.
///
/// None of these read a bitstream, so they bench anywhere with no reference data. Together with
/// [`bench_silk_frame`] (which needs a vector) they cover everything a SILK packet pays per 20 ms.
fn bench_silk_synthesis(c: &mut Criterion) {
    use siphon_rtp_codec::opus::silk::decoder::{ChannelState, StereoState};
    use siphon_rtp_codec::opus::silk::plc::{self, PlcScratch};
    use siphon_rtp_codec::opus::silk::resampler::Resampler;
    use siphon_rtp_codec::opus::silk::stereo_unmix::mid_side_to_left_right;
    use siphon_rtp_codec::opus::silk::synthesis::{decode_core, CoreScratch, DecoderControl};
    use siphon_rtp_codec::opus::silk::types::{
        InternalRate, SignalType, SubframeLayout, LTP_ORDER, MAX_FRAME_LENGTH, MAX_NB_SUBFR,
    };

    /// A channel primed with a plausible history and excitation, as a real decode would leave it.
    fn primed_channel(rate: InternalRate) -> ChannelState {
        let mut channel = ChannelState::new();
        let layout = SubframeLayout::from_duration_ms(20).expect("20 ms");
        channel.set_internal_rate(rate, layout);
        channel.first_frame_after_reset = false;
        for (index, slot) in channel.out_buf.iter_mut().enumerate() {
            *slot = (7000.0 * ((index as f64) * 0.06).sin()) as i16;
        }
        for (index, slot) in channel.excitation_q14.iter_mut().enumerate() {
            *slot = (((index * 7919) % 4001) as i32 - 2000) << 6;
        }
        channel
    }

    /// A voiced control block with a mid-range gain and a real pitch.
    fn voiced_control(rate: InternalRate) -> DecoderControl {
        let mut control = DecoderControl::new();
        control.gains_q16 = [1 << 18, 1 << 19, 1 << 18, 1 << 17];
        control.pitch_lags = [(6 * rate.khz()) as i32; MAX_NB_SUBFR];
        control.ltp_scale_q14 = 15_565;
        for subframe in 0..MAX_NB_SUBFR {
            for tap in 0..LTP_ORDER {
                control.ltp_coef_q14[subframe * LTP_ORDER + tap] = 1_600 + (tap as i16) * 200;
            }
        }
        for order in 0..rate.lpc_order() {
            let value = 1_800 - (order as i16) * 90;
            control.pred_coef_q12[0][order] = value;
            control.pred_coef_q12[1][order] = value;
        }
        control
    }

    let mut group = c.benchmark_group("silk_synthesis");

    for (label, rate) in [
        ("nb_8k", InternalRate::Narrow8k),
        ("wb_16k", InternalRate::Wide16k),
    ] {
        for (voiced, signal_type) in [
            ("voiced", SignalType::Voiced),
            ("unvoiced", SignalType::Unvoiced),
        ] {
            let mut channel = primed_channel(rate);
            let mut control = voiced_control(rate);
            let mut scratch = CoreScratch::new();
            let mut output = [0i16; MAX_FRAME_LENGTH];
            group.bench_function(format!("decode_core_20ms_{label}_{voiced}"), |b| {
                b.iter(|| {
                    decode_core(
                        &mut channel,
                        &mut control,
                        signal_type,
                        false,
                        black_box(&mut output),
                        &mut scratch,
                    )
                    .expect("synthesis");
                    black_box(output[0])
                });
            });
        }
    }

    // §4.2.8 stereo unmixing, 20 ms wideband.
    {
        let mut state = StereoState::new();
        let mut mid = vec![0i16; 322];
        let mut side = vec![0i16; 322];
        for index in 0..322 {
            mid[index] = (6000.0 * ((index as f64) * 0.04).sin()) as i16;
            side[index] = (1500.0 * ((index as f64) * 0.11).cos()) as i16;
        }
        group.bench_function("stereo_unmix_20ms_wb", |b| {
            b.iter(|| {
                mid_side_to_left_right(
                    &mut state,
                    black_box(&mut mid),
                    black_box(&mut side),
                    [4096, -2048],
                    InternalRate::Wide16k,
                    320,
                )
                .expect("unmix");
                black_box(mid[1])
            });
        });
    }

    // §4.2.9 resampling to the API rate, one 20 ms frame per call.
    for (label, input_hz, samples) in [
        ("8k_to_48k", 8_000u32, 160usize),
        ("12k_to_48k", 12_000, 240),
        ("16k_to_48k", 16_000, 320),
        ("16k_to_8k", 16_000, 320),
    ] {
        let output_hz = if label.ends_with("8k") && input_hz == 16_000 {
            8_000
        } else {
            48_000
        };
        let mut resampler = Resampler::new();
        resampler.configure(input_hz, output_hz).expect("configure");
        let input: Vec<i16> = (0..samples)
            .map(|n| (8000.0 * ((n as f64) * 0.07).sin()) as i16)
            .collect();
        let mut output = vec![0i16; resampler.output_length(samples)];
        group.bench_function(format!("resample_20ms_{label}"), |b| {
            b.iter(|| {
                resampler
                    .process(black_box(&mut output), black_box(&input))
                    .expect("resample");
                black_box(output[0])
            });
        });
    }

    // §4.4 concealment: one lost 20 ms wideband frame.
    {
        let mut channel = primed_channel(InternalRate::Wide16k);
        let mut control = voiced_control(InternalRate::Wide16k);
        let mut scratch = PlcScratch::new();
        let mut frame = [0i16; MAX_FRAME_LENGTH];
        // One good-frame update first, so the concealer has real parameters to work from.
        plc::run(
            &mut channel,
            &mut control,
            SignalType::Voiced,
            false,
            &mut frame,
            &mut scratch,
        )
        .expect("plc update");
        group.bench_function("plc_conceal_20ms_wb", |b| {
            b.iter(|| {
                plc::run(
                    &mut channel,
                    &mut control,
                    SignalType::Voiced,
                    true,
                    black_box(&mut frame),
                    &mut scratch,
                )
                .expect("conceal");
                black_box(frame[0])
            });
        });
    }

    group.finish();
}

/// Whole-frame SILK decode — one Opus frame of a real SILK-only stream, from the range decoder all
/// the way to interleaved 48 kHz stereo PCM.
///
/// This is the number that matters for a transcoding leg: everything else in `silk_*` is a component
/// of it. It needs a real bitstream, so it reads the first packet of a `reference/opus/silk_only`
/// stream and is skipped (with a notice) when the vectors are absent — the same skip-when-absent rule
/// the conformance harnesses follow.
fn bench_silk_frame(c: &mut Criterion) {
    use siphon_rtp_codec::opus::packet;
    use siphon_rtp_codec::opus::range_coder::RangeDecoder;
    use siphon_rtp_codec::opus::silk::decoder::SilkDecoder;
    use siphon_rtp_codec::opus::silk::frame::LossFlag;
    use siphon_rtp_codec::opus::silk::types::InternalRate;
    use std::path::Path;

    /// First packet payload of an `opus_demo` `.bit` file.
    fn first_packet(path: &Path) -> Option<Vec<u8>> {
        let bytes = std::fs::read(path).ok()?;
        if bytes.len() < 8 {
            return None;
        }
        let length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        // The first packet of a silence lead-in is tiny; take the first one with real content.
        let mut offset = 0usize;
        let mut best: Option<Vec<u8>> = None;
        let mut length = length;
        while offset + 8 + length <= bytes.len() {
            let payload = bytes[offset + 8..offset + 8 + length].to_vec();
            if payload.len() > 20 {
                best = Some(payload);
                break;
            }
            offset += 8 + length;
            if offset + 8 > bytes.len() {
                break;
            }
            length = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]) as usize;
        }
        best
    }

    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus/silk_only");
    let cases = [
        ("nb_20ms_mono", "s01_NB_20_10000.bit"),
        ("wb_20ms_mono", "s01_WB_20_18000.bit"),
        ("wb_20ms_stereo", "s01_WB_20_18000_st.bit"),
        ("wb_60ms_mono", "s01_WB_60_18000.bit"),
    ];

    let mut group = c.benchmark_group("silk_frame");
    let mut benched = 0usize;
    for (label, file) in cases {
        let Some(payload) = first_packet(&directory.join(file)) else {
            continue;
        };
        let Ok(parsed) = packet::parse(&payload) else {
            continue;
        };
        let frame = parsed.frames()[0].to_vec();
        let channels = usize::from(parsed.toc.channels());
        let rate = InternalRate::from_bandwidth(parsed.toc.bandwidth());
        let duration_ms = parsed.toc.samples_per_frame(48_000) / 48;
        let mut silk = SilkDecoder::new(48_000, 2).expect("decoder");
        let mut output = vec![0i16; 2880 * 2];
        group.bench_function(format!("decode_{label}"), |b| {
            b.iter(|| {
                silk.configure(channels, rate, duration_ms)
                    .expect("configure");
                let mut decoder = RangeDecoder::new(black_box(&frame));
                let produced = silk
                    .decode(Some(&mut decoder), LossFlag::Normal, black_box(&mut output))
                    .expect("decode");
                black_box(produced)
            });
        });
        benched += 1;
    }
    if benched == 0 {
        eprintln!(
            "silk_frame bench: no vectors in {} — run reference/opus/gen_silk_only.sh (see CONTRIBUTING.md)",
            directory.display()
        );
    }
    group.finish();
}

/// SILK's §4.2.7.6-8 side-info stages: the LTP indices, the shell coder and the §4.2.7.8.6
/// reconstruction. These are per-frame costs on every SILK and hybrid packet, so they are benched
/// separately from the whole-frame decode that sits on top of them.
///
/// The payloads are built with our own range *encoder* rather than read from a vector file, so the
/// bench runs anywhere (no reference data) and the symbol mix is fixed and reproducible.
fn bench_silk_excitation(c: &mut Criterion) {
    use siphon_rtp_codec::opus::range_coder::{RangeDecoder, RangeEncoder};
    use siphon_rtp_codec::opus::silk::excitation::{
        self, PULSES_PER_BLOCK_ICDF, PULSE_BUFFER_LENGTH, RATE_LEVELS_ICDF, SHELL_BLOCK_LENGTH,
        SHELL_CODE_TABLE0, SHELL_CODE_TABLE1, SHELL_CODE_TABLE2, SHELL_CODE_TABLE3,
        SHELL_CODE_TABLE_OFFSETS, SIGN_ICDF,
    };
    use siphon_rtp_codec::opus::silk::ltp;
    use siphon_rtp_codec::opus::silk::types::{
        CondCoding, InternalRate, QuantOffsetType, SignalType, SubframeLayout, MAX_FRAME_LENGTH,
    };

    const FTB: u32 = 8;
    /// The sub-table for `pulse_count` inside a shell-code table (RFC 6716 Tables 47-50).
    fn split(table: &[u8; 152], pulse_count: usize) -> &[u8] {
        let start = SHELL_CODE_TABLE_OFFSETS[pulse_count] as usize;
        &table[start..start + pulse_count + 1]
    }

    let mut group = c.benchmark_group("silk_excitation");

    // ── The excitation stage, at each frame length RFC 6716 Table 44 lists ─────────────────────
    for &(label, frame_length) in &[
        ("decode_nb_10ms", 80usize),
        ("decode_nb_20ms", 160),
        ("decode_wb_10ms", 160),
        ("decode_wb_20ms", 320),
    ] {
        let block_count = frame_length.div_ceil(SHELL_BLOCK_LENGTH);
        let rate_level = 5usize;
        let signal_type = SignalType::Voiced;
        let quant_offset_type = QuantOffsetType::High;

        // A realistic block mix: a few pulses spread over the block, one loud block per frame.
        let blocks: Vec<[u16; SHELL_BLOCK_LENGTH]> = (0..block_count)
            .map(|block| {
                let mut pulses = [0u16; SHELL_BLOCK_LENGTH];
                pulses[block % SHELL_BLOCK_LENGTH] = 3;
                pulses[(block * 5 + 1) % SHELL_BLOCK_LENGTH] += 2;
                pulses[(block * 11 + 7) % SHELL_BLOCK_LENGTH] += 1;
                pulses
            })
            .collect();

        let mut payload = vec![0u8; 2048];
        let written = {
            let mut encoder = RangeEncoder::new(&mut payload);
            encoder.enc_icdf(rate_level, &RATE_LEVELS_ICDF[1], FTB);
            for block in &blocks {
                let total: u16 = block.iter().sum();
                encoder.enc_icdf(usize::from(total), &PULSES_PER_BLOCK_ICDF[rate_level], FTB);
            }
            for block in &blocks {
                // libopus' `silk_shell_encoder` symbol order (shell_coder.c:78-115).
                let combine = |input: &[u16]| -> Vec<u16> {
                    input.chunks_exact(2).map(|p| p[0] + p[1]).collect()
                };
                let level0 = block.to_vec();
                let level1 = combine(&level0);
                let level2 = combine(&level1);
                let level3 = combine(&level2);
                let level4 = combine(&level3);
                let mut emit = |child: u16, parent: u16, table: &[u8; 152]| {
                    if parent > 0 {
                        encoder.enc_icdf(
                            usize::from(child),
                            split(table, usize::from(parent)),
                            FTB,
                        );
                    }
                };
                emit(level3[0], level4[0], &SHELL_CODE_TABLE3);
                emit(level2[0], level3[0], &SHELL_CODE_TABLE2);
                emit(level1[0], level2[0], &SHELL_CODE_TABLE1);
                emit(level0[0], level1[0], &SHELL_CODE_TABLE0);
                emit(level0[2], level1[1], &SHELL_CODE_TABLE0);
                emit(level1[2], level2[1], &SHELL_CODE_TABLE1);
                emit(level0[4], level1[2], &SHELL_CODE_TABLE0);
                emit(level0[6], level1[3], &SHELL_CODE_TABLE0);
                emit(level2[2], level3[1], &SHELL_CODE_TABLE2);
                emit(level1[4], level2[2], &SHELL_CODE_TABLE1);
                emit(level0[8], level1[4], &SHELL_CODE_TABLE0);
                emit(level0[10], level1[5], &SHELL_CODE_TABLE0);
                emit(level1[6], level2[3], &SHELL_CODE_TABLE1);
                emit(level0[12], level1[6], &SHELL_CODE_TABLE0);
                emit(level0[14], level1[7], &SHELL_CODE_TABLE0);
            }
            // Signs: voiced / high offset is row 5 of Table 52.
            for block in &blocks {
                let total: u16 = block.iter().sum();
                let icdf = [SIGN_ICDF[35 + usize::from(total).min(6)], 0];
                for (sample, &magnitude) in block.iter().enumerate() {
                    if magnitude > 0 {
                        encoder.enc_icdf(sample & 1, &icdf, FTB);
                    }
                }
            }
            encoder.done() as usize
        };
        payload.truncate(written.max(1));

        group.bench_function(label, |b| {
            let mut pulses = [0i16; PULSE_BUFFER_LENGTH];
            let mut excitation_q14 = [0i32; MAX_FRAME_LENGTH];
            b.iter(|| {
                let mut decoder = RangeDecoder::new(black_box(&payload));
                let summary = excitation::decode(
                    &mut decoder,
                    signal_type,
                    quant_offset_type,
                    frame_length,
                    2,
                    &mut pulses,
                    &mut excitation_q14[..frame_length],
                )
                .expect("decode");
                black_box(summary.total_pulses())
            });
        });
    }

    // ── The §4.2.7.8.6 reconstruction alone, so a regression can be localised to it ────────────
    {
        let mut pulses = [0i16; MAX_FRAME_LENGTH];
        for (index, slot) in pulses.iter_mut().enumerate() {
            *slot = match index % 7 {
                0 => 0,
                1 => 1,
                2 => -2,
                3 => 5,
                _ => 0,
            };
        }
        group.bench_function("reconstruct_20ms_wb", |b| {
            let mut excitation_q14 = [0i32; MAX_FRAME_LENGTH];
            b.iter(|| {
                excitation::reconstruct(
                    black_box(&pulses),
                    SignalType::Voiced,
                    QuantOffsetType::Low,
                    3,
                    &mut excitation_q14,
                )
                .expect("reconstruct");
                black_box(excitation_q14[0])
            });
        });
    }

    // ── The LTP side info: index decode plus the codebook lookups synthesis consumes ───────────
    {
        let layout = SubframeLayout::from_duration_ms(20).expect("20 ms");
        let rate = InternalRate::Wide16k;
        let contour = ltp::PitchContourCodebook::select(rate, layout.subframe_count);
        let filter = ltp::LtpFilterCodebook::select(2);
        let mut payload = vec![0u8; 64];
        let written = {
            let mut encoder = RangeEncoder::new(&mut payload);
            encoder.enc_icdf(17, &ltp::PITCH_LAG_ICDF, FTB);
            encoder.enc_icdf(5, ltp::lag_low_bits_icdf(rate), FTB);
            encoder.enc_icdf(20, contour.icdf(), FTB);
            encoder.enc_icdf(2, &ltp::LTP_PERIODICITY_ICDF, FTB);
            for index in 0..layout.subframe_count {
                encoder.enc_icdf(index * 3, filter.icdf(), FTB);
            }
            encoder.enc_icdf(1, &ltp::LTP_SCALE_ICDF, FTB);
            encoder.done() as usize
        };
        payload.truncate(written.max(1));

        group.bench_function("ltp_indices_20ms_wb", |b| {
            b.iter(|| {
                let mut decoder = RangeDecoder::new(black_box(&payload));
                let indices = ltp::decode_indices(
                    &mut decoder,
                    rate,
                    layout,
                    CondCoding::Independently,
                    SignalType::Unvoiced,
                    0,
                );
                black_box(ltp::dequantize(&indices, rate).pitch_lags[0])
            });
        });
    }

    group.finish();
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
    bench_celt_encode,
    bench_celt_kernels,
    bench_silk_excitation,
    bench_silk_synthesis,
    bench_silk_frame,
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
    bench_cn,
    bench_celt_encode,
    bench_celt_kernels,
    bench_silk_excitation,
    bench_silk_synthesis,
    bench_silk_frame
);
criterion_main!(benches);
