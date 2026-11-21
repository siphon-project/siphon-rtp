//! `lib_dec/FEC_HQ_phase_ecu_fx.c` (the HQ phase ECU) against `fn_fec_hq_phase_ecu`: every function
//! on random inputs, whole frame sequences on one decoder with the whole state compared after every
//! lost frame, and `hq_ecu_fx` exactly where the reference decoder calls it on conformance
//! bitstreams with frame loss.

use siphon_rtp_codec::evs::dec::fec_hq_phase_ecu::*;
use siphon_rtp_codec::evs::rom::{ASR_LP16_FX, ASR_LP32_FX, ASR_LP48_FX};

use crate::common::{corpus, corpus_sized, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn each(function: &str, mut body: impl FnMut(&Case)) {
    let Some(cases) = corpus("fec_hq_phase_ecu", function) else {
        return;
    };
    for case in &cases {
        body(case);
    }
}

fn lprot_of(output_frame: i16) -> usize {
    match output_frame {
        320 => 512,
        640 => 1024,
        _ => 1536,
    }
}

#[test]
fn rand_phase_matches_the_reference() {
    each("rand_phase", |case| {
        let (mut sin, mut cos) = (-7, -7);
        let seed = rand_phase(case.i16("seed"), &mut sin, &mut cos);
        check(case, "seed2", &seed, &case.out_i16("seed2"));
        check(case, "sin", &sin, &case.out_i16("sin"));
        check(case, "cos", &cos, &case.out_i16("cos"));
    });
}

#[test]
fn fft_spec2_matches_the_reference() {
    each("fft_spec2", |case| {
        let n = case.i16("n");
        let mut mag = vec![-7_i32; n as usize / 2 + 1];
        fft_spec2(&case.i16s("x"), &mut mag, n);
        check(case, "mag", &mag, &case.out_i32s("mag"));
    });
}

#[test]
fn sqrt2nd_order_matches_the_reference() {
    each("sqrt2nd_order", |case| {
        check(case, "y", &sqrt2nd_order(case.i16("x")), &case.out_i16("y"));
    });
}

#[test]
fn windowing_matches_the_reference() {
    each("windowing", |case| {
        let (rect, half) = (case.i16("rect"), case.i16("half"));
        let total = 2 * half as usize + rect as usize;
        let mut y = vec![-7_i16; total];
        windowing(&case.i16s("x"), &mut y, &case.i16s("win"), rect, half);
        check(case, "y", &y, &case.out_i16s("y"));
        let mut in_place = case.i16s("x");
        windowing_in_place(&mut in_place, &case.i16s("win"), rect, half);
        check(case, "y (in place)", &in_place, &case.out_i16s("y"));
    });
}

#[test]
fn windowing_rom_optimized_matches_the_reference() {
    each("windowing_rom_optimized", |case| {
        let mut x = case.i16s("x");
        windowing_rom_optimized(&mut x, case.i16("down"), case.i16("rect"), case.i16("half"));
        check(case, "y", &x, &case.out_i16s("y"));
    });
}

#[test]
fn trans_ana_matches_the_reference() {
    each("trans_ana", |case| {
        let mut mag_chg = [-7_i16; 9];
        let mut ph_dith = -7;
        let mut mag_chg_1st = case.i16s("mag_chg_1st");
        let mut alpha = [-7_i16; 9];
        let mut beta = [-7_i16; 9];
        let mut beta_mute = case.i16("beta_mute");
        let mut xavg = [-7_i16; 9];
        trans_ana(
            &case.i16s("xfp"),
            &TransAnaParams {
                output_frame: case.i16("output_frame"),
                time_offs: case.i16("time_offs"),
                est_mus_content: case.i16("est_mus_content"),
                last_fec: case.i16("last_fec"),
            },
            &mut TransAnaOut {
                mag_chg: &mut mag_chg,
                ph_dith: &mut ph_dith,
                mag_chg_1st: &mut mag_chg_1st,
                alpha: &mut alpha,
                beta: &mut beta,
                beta_mute: &mut beta_mute,
                xavg: &mut xavg,
            },
        );
        check(
            case,
            "mag_chg",
            &mag_chg.to_vec(),
            &case.out_i16s("mag_chg"),
        );
        check(case, "ph_dith", &ph_dith, &case.out_i16("ph_dith"));
        check(
            case,
            "mag_chg_1st",
            &mag_chg_1st,
            &case.out_i16s("mag_chg_1st"),
        );
        check(case, "alpha", &alpha.to_vec(), &case.out_i16s("alpha"));
        check(case, "beta", &beta.to_vec(), &case.out_i16s("beta"));
        check(case, "beta_mute", &beta_mute, &case.out_i16("beta_mute"));
        check(case, "xavg", &xavg.to_vec(), &case.out_i16s("xavg"));
    });
}

#[test]
fn peakfinder_matches_the_reference() {
    each("peakfinder", |case| {
        let mut plocs = vec![-7_i16; 400];
        let mut c_ind = -7;
        peakfinder(
            &case.i16s("x0"),
            case.i16s("x0").len() as i16,
            &mut plocs,
            &mut c_ind,
            case.i16("sel"),
        );
        check(case, "c_ind", &c_ind, &case.out_i16("c_ind"));
        let found = c_ind.max(0) as usize;
        check(
            case,
            "plocs",
            &plocs[..found].to_vec(),
            &case.out_i16s("plocs"),
        );
    });
}

#[test]
fn imax_matches_the_reference() {
    each("imax", |case| {
        check(
            case,
            "posi",
            &imax(&case.i16s("y"), case.i16("special")),
            &case.out_i16("posi"),
        );
    });
}

#[test]
fn spec_ana_matches_the_reference() {
    each("spec_ana", |case| {
        let mut plocs = vec![-7_i16; 400];
        let mut plocsi = vec![-7_i32; 400];
        let mut num_plocs = -7;
        let mut x_sav = vec![-7_i16; 1536];
        let mut q = -7;
        spec_ana(
            &case.i16s("prevsynth"),
            case.i16("output_frame"),
            case.i16("bwidth"),
            &mut SpecAnaOut {
                plocs: &mut plocs,
                plocsi: &mut plocsi,
                num_plocs: &mut num_plocs,
                x_sav: &mut x_sav,
                q: &mut q,
            },
        );
        check(case, "num_plocs", &num_plocs, &case.out_i16("num_plocs"));
        let found = num_plocs.max(0) as usize;
        check(
            case,
            "plocs",
            &plocs[..found].to_vec(),
            &case.out_i16s("plocs"),
        );
        check(
            case,
            "plocsi",
            &plocsi[..found].to_vec(),
            &case.out_i32s("plocsi"),
        );
        check(case, "x_sav", &x_sav, &case.out_i16s("x_sav"));
        check(case, "q", &q, &case.out_i16("q"));
    });
}

#[test]
fn subst_spec_matches_the_reference() {
    each("subst_spec", |case| {
        let mut num_plocs = case.i16("num_plocs");
        let mut x = case.i16s("x");
        let mut seed = case.i16("seed");
        subst_spec(
            &SubstSpecInput {
                plocs: &case.i16s("plocs"),
                plocsi: &case.i32s("plocsi"),
                time_offs: case.i16("time_offs"),
                mag_chg: &case.i16s("mag_chg"),
                ph_dith: case.i16("ph_dith"),
                is_trans: &case.i16s("is_trans"),
                output_frame: case.i16("output_frame"),
                alpha: &case.i16s("alpha"),
                beta: &case.i16s("beta"),
                beta_mute: case.i16("beta_mute"),
                xavg: &case.i16s("xavg"),
            },
            &mut num_plocs,
            &mut x,
            &mut seed,
        );
        check(case, "num_plocs", &num_plocs, &case.out_i16("num_plocs"));
        check(case, "x", &x, &case.out_i16s("x"));
        check(case, "seed", &seed, &case.out_i16("seed"));
    });
}

#[test]
fn rec_wtda_matches_the_reference() {
    each("rec_wtda", |case| {
        let output_frame = case.i16("output_frame");
        let x = case.i16s("x");
        let mut ecu_rec = vec![-7_i32; 960];
        rec_wtda(
            &x,
            &mut ecu_rec,
            output_frame,
            lprot_of(output_frame) as i16,
            i32::from(output_frame) * 50,
        );
        check(
            case,
            "ecu_rec",
            &ecu_rec[..output_frame as usize].to_vec(),
            &case.out_i32s("ecu_rec"),
        );
        check(case, "x", &x, &case.out_i16s("x"));
    });
}

#[test]
fn rec_frame_matches_the_reference() {
    each("rec_frame", |case| {
        let output_frame = case.i16("output_frame");
        let mut x = case.i16s("x");
        let mut ecu_rec = vec![-7_i32; 960];
        rec_frame(&mut x, &mut ecu_rec, output_frame, case.i16("q"));
        check(
            case,
            "ecu_rec",
            &ecu_rec[..output_frame as usize].to_vec(),
            &case.out_i32s("ecu_rec"),
        );
        check(case, "x", &x, &case.out_i16s("x"));
    });
}

#[test]
fn mult_32_32_q_matches_the_reference() {
    each("mult_32_32_q", |case| {
        let r = mult_32_32_q(case.i32("a"), case.i32("b"), case.i16("q"));
        check(case, "r", &r, &case.out_i32("r"));
    });
}

#[test]
fn fir_dwn_matches_the_reference() {
    each("fir_dwn", |case| {
        let (h, q, k, decim): (&[i16], i16, i16, i16) = match case.i16("which") {
            0 => (&ASR_LP48_FX, 17, 60, 6),
            1 => (&ASR_LP32_FX, 15, 40, 4),
            2 => (&ASR_LP16_FX, 15, 20, 2),
            _ => (&ASR_LP16_FX, 15, 40, 2),
        };
        let x = case.i16s("x");
        let mut y = vec![-7_i16; 400];
        fir_dwn(&x, h, q, &mut y, x.len() as i16, k, decim);
        check(case, "y", &y[..320].to_vec(), &case.out_i16s("y"));
    });
}

#[test]
fn fec_ecu_pitch_matches_the_reference() {
    each("fec_ecu_pitch", |case| {
        let mut lp = vec![-7_i16; 320];
        let (mut n, mut corr, mut decim) = (-7, -7, -7);
        fec_ecu_pitch(
            &case.i16s("prevsynth"),
            &mut lp,
            case.i16("l"),
            &mut n,
            &mut corr,
            &mut decim,
            case.i16("voicing"),
        );
        check(case, "lp", &lp, &case.out_i16s("lp"));
        check(case, "n", &n, &case.out_i16("n"));
        check(case, "corr", &corr, &case.out_i16("corr"));
        check(case, "decim", &decim, &case.out_i16("decim"));
    });
}

#[test]
fn sin_cos_est_matches_the_reference() {
    each("sin_cos_est", |case| {
        let (cos, sin) = sin_cos_est(case.i32("phi"));
        check(case, "cos", &cos, &case.out_i16("cos"));
        check(case, "sin", &sin, &case.out_i16("sin"));
    });
}

#[test]
fn abs_iter_matches_the_reference() {
    each("abs_iter", |case| {
        let a = abs_iter(case.i16("re"), case.i16("im"), case.i16("n"));
        check(case, "a", &a, &case.out_i16("a"));
    });
}

#[test]
fn fec_ecu_dft_matches_the_reference() {
    each("fec_ecu_dft", |case| {
        let mut tfr = vec![-7_i16; 512];
        let mut tfi = vec![-7_i16; 512];
        let mut tf_abs = vec![-7_i16; 256];
        let (mut sum, mut nfft, mut exp) = (-7, -7, -7);
        fec_ecu_dft(
            &case.i16s("lp"),
            case.i16("n"),
            &mut DftOut {
                tfr: &mut tfr,
                tfi: &mut tfi,
                sum_tf_abs: &mut sum,
                tf_abs: &mut tf_abs,
                nfft: &mut nfft,
                exp: &mut exp,
            },
        );
        let half = nfft as usize / 2;
        check(case, "nfft", &nfft, &case.out_i16("nfft"));
        check(case, "exp", &exp, &case.out_i16("exp"));
        check(case, "sum", &sum, &case.out_i32("sum"));
        check(case, "tfr", &tfr[..half].to_vec(), &case.out_i16s("tfr"));
        check(case, "tfi", &tfi[..half].to_vec(), &case.out_i16s("tfi"));
        check(
            case,
            "tf_abs",
            &tf_abs[..half].to_vec(),
            &case.out_i16s("tf_abs"),
        );
    });
}

#[test]
fn singenerator_matches_the_reference() {
    each("singenerator", |case| {
        let mut xx = case.i32s("xx");
        singenerator(
            case.i16("l"),
            case.i16("cos"),
            case.i16("sin"),
            case.i16("a_re"),
            case.i16("a_im"),
            &mut xx,
        );
        check(case, "xx", &xx, &case.out_i32s("xx"));
    });
}

#[test]
fn sinusoidal_synthesis_matches_the_reference() {
    each("sinusoidal_synthesis", |case| {
        let l = case.i16("l");
        let nfft = case.i16("nfft") as usize;
        let mut tf_abs = case.i16s("tf_abs");
        tf_abs.resize(256, 0);
        let mut tfr = case.i16s("tfr");
        tfr.resize(512, 0);
        let mut tfi = case.i16s("tfi");
        tfi.resize(512, 0);
        let mut synthesis = vec![-7_i16; 1920];
        sinusoidal_synthesis(
            &SynthesisInput {
                tfr: &tfr,
                tfi: &tfi,
                n: case.i16("n"),
                l,
                decimate_factor: case.i16("decim"),
                nfft: nfft as i16,
                sum_tf_abs: case.i32("sum"),
                hq_voicing: case.i16("voicing"),
                exp: case.i16("exp"),
            },
            &mut tf_abs,
            &mut synthesis,
        );
        check(
            case,
            "synthesis",
            &synthesis[..2 * l as usize].to_vec(),
            &case.out_i16s("synthesis"),
        );
        check(
            case,
            "tf_abs",
            &tf_abs[..nfft / 2].to_vec(),
            &case.out_i16s("tf_abs"),
        );
    });
}

#[test]
fn fec_noise_filling_matches_the_reference() {
    each("fec_noise_filling", |case| {
        let l = case.i16("l");
        let mut synthesis = case.i16s("synthesis");
        synthesis.resize(1920, 0);
        let mut seed = case.i16("seed");
        let mut gapsynth = vec![-7_i16; 960];
        fec_noise_filling(
            &case.i16s("prevsynth"),
            &mut synthesis,
            &mut seed,
            l,
            case.i16("n"),
            case.i16("voicing"),
            &mut gapsynth,
        );
        check(
            case,
            "synthesis",
            &synthesis[..2 * l as usize].to_vec(),
            &case.out_i16s("synthesis"),
        );
        check(case, "seed", &seed, &case.out_i16("seed"));
        check(
            case,
            "gapsynth",
            &gapsynth[..l as usize].to_vec(),
            &case.out_i16s("gapsynth"),
        );
    });
}

#[test]
fn fec_alg_matches_the_reference() {
    each("fec_alg", |case| {
        let l = case.i16("l");
        let mut seed = case.i16("seed");
        let mut ecu_rec = vec![-7_i32; 960];
        let mut gapsynth = vec![-7_i16; 960];
        fec_alg(
            &case.i16s("prevsynth"),
            &case.i16s("lp"),
            &mut seed,
            &mut ecu_rec,
            l,
            case.i16("n"),
            case.i16("decim"),
            case.i16("voicing"),
            &mut gapsynth,
        );
        check(
            case,
            "ecu_rec",
            &ecu_rec[..l as usize].to_vec(),
            &case.out_i32s("ecu_rec"),
        );
        check(case, "seed", &seed, &case.out_i16("seed"));
        check(
            case,
            "gapsynth",
            &gapsynth[..l as usize].to_vec(),
            &case.out_i16s("gapsynth"),
        );
    });
}

/// `hq_phase_ecu_fx` (`whole_ecu` false) or `hq_ecu_fx` over six frames of good and lost data, the
/// whole state compared after every lost frame.
fn sequences(function: &str, whole_ecu: bool) {
    use crate::hq_state::{check_state, decoder_with, keep_unloadable, overlay, reload};
    let Some(cases) = corpus_sized("fec_hq_phase_ecu", function, 60) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let initial = overlay(case, "\u{0}never");
        let mut st = decoder_with(case, &initial);
        let output_frame = case.i16("output_frame");
        for frame in 0..6 {
            if case.i16(&format!("f{frame}_bfi")) == 0 {
                continue;
            }
            let context = format!("case {index} frame {frame}");
            let before = overlay(case, &format!("f{frame}_pre."));
            reload(&mut st, &before);
            let mut expected = overlay(case, &format!("f{frame}."));
            keep_unloadable(&mut st, &before, &mut expected);
            let mut ecu_rec = vec![0_i32; 960];
            let mut gapsynth = vec![0_i16; 960];
            if whole_ecu {
                hq_ecu(&mut st, &mut ecu_rec, &mut gapsynth, output_frame);
            } else {
                hq_phase_ecu(&mut st, &mut ecu_rec, output_frame);
                gapsynth.fill(0);
            }
            check(
                case,
                &format!("{context} ecu_rec"),
                &ecu_rec[..output_frame as usize].to_vec(),
                &case.i32s(&format!("f{frame}_ecu_rec")),
            );
            check(
                case,
                &format!("{context} gapsynth"),
                &gapsynth[..output_frame as usize].to_vec(),
                &case.i16s(&format!("f{frame}_gapsynth")),
            );
            check_state(&mut st, &expected, &context);
        }
    }
}

#[test]
fn hq_phase_ecu_matches_the_reference_over_frame_sequences() {
    sequences("hq_phase_ecu_sequence", false);
}

#[test]
fn hq_ecu_matches_the_reference_over_frame_sequences() {
    sequences("hq_ecu_sequence", true);
}

/// `hq_ecu_fx` exactly where the reference decoder calls it on the TS 26.444 conformance
/// bitstreams with frame loss (WB, SWB and FB HQ): `fn_fec_hq_phase_ecu stream` runs the whole
/// reference decoder and prints, for each call, the whole state before it, the buffers and, after
/// the arrow, the outputs and the state fields it changed.
#[test]
fn hq_ecu_matches_the_reference_on_conformance_bitstreams() {
    use crate::hq_state::{
        check_state, decoder_with, each_stream_call, keep_unloadable, overlay, state_after,
    };
    let mut checked = 0;
    for (name, rate, every) in [
        ("wb/stv16c_13200_16kHz.b10.COD", 16000, 2),
        ("wb/stv16c_16400_16kHz.f06.COD", 16000, 1),
        ("wb/stv16c_32000_16kHz.f06.COD", 16000, 3),
        ("wb/stv16c_64000_16kHz.f06.COD", 16000, 3),
        ("swb/stv32c_13200_32kHz.b10.COD", 32000, 2),
        ("swb/stv32c_16400_32kHz.f06.COD", 32000, 1),
        ("swb/stv32c_24400_32kHz.f06.COD", 32000, 1),
        ("swb/stv32c_32000_32kHz.f06.COD", 32000, 2),
        ("swb/stv32c_64000_32kHz.f06.COD", 32000, 3),
        ("fb/stv48c_24400_48kHz.f06.COD", 48000, 1),
        ("fb/stv48c_32000_48kHz.f06.COD", 48000, 2),
        ("fb/stv48c_64000_48kHz.f06.COD", 48000, 3),
    ] {
        let calls = each_stream_call("fec_hq_phase_ecu", name, rate, every, |index, case| {
            let before = overlay(case, "\u{0}never");
            let mut expected = state_after(case);
            let mut st = decoder_with(case, &before);
            keep_unloadable(&mut st, &before, &mut expected);
            let context = format!("{name} line {index}");
            let mut ecu_rec = case.i32s("ecu_in");
            let mut gapsynth = case.i16s("gap_in");
            hq_ecu(
                &mut st,
                &mut ecu_rec,
                &mut gapsynth,
                case.i16("call_output_frame"),
            );
            check(
                case,
                &format!("{context} ecu_rec"),
                &ecu_rec,
                &case.out_i32s("ecu_rec"),
            );
            check(
                case,
                &format!("{context} gapsynth"),
                &gapsynth,
                &case.out_i16s("gapsynth"),
            );
            check_state(&mut st, &expected, &context);
        });
        checked += calls.unwrap_or(0);
    }
    eprintln!("hq_ecu checked on {checked} conformance calls");
}
