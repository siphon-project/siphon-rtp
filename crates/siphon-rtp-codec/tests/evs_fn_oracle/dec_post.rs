//! `lib_dec/dec_post.c` against `fn_dec_post`. `nb_post_filt` runs three consecutive frames per
//! case through one `PFSTAT` and so proves `Dec_postfilt`, `pst_ltp`, `search_del`,
//! `compute_ltp_l`, `select_ltp`, `filt_plt` and `calc_st_filt` with it.

use siphon_rtp_codec::evs::dec::dec_post::{
    blend_subfr2, filt_mu, formant_post_filt, init_post_filter, modify_pst_param, nb_post_filt,
    pst_ltp, scale_st, select_ltp,
};
use siphon_rtp_codec::evs::dec::state::Pfstat;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn nb_post_filt_matches_the_reference() {
    let Some(cases) = corpus("dec_post", "nb_post_filt") else {
        return;
    };
    for case in &cases {
        let mut pf = Pfstat::zeroed();
        init_post_filter(&mut pf);
        pf.reset = case.i16("reset");
        pf.mem_pf_in.copy_from_slice(&case.i16s("mem_pf_in"));
        pf.mem_stp.copy_from_slice(&case.i16s("mem_stp"));
        pf.mem_res2.copy_from_slice(&case.i16s("mem_res2"));
        pf.gain_prec = case.i16("gain_prec");
        let l_frame = case.i16("L_frame");
        let mut psf_lp_noise = case.i16("psf_lp_noise");
        for f in 0..3 {
            let mut synth = case.i16s(&format!("synth{f}"));
            pf.reset = case.i16(&format!("reset{f}"));
            nb_post_filt(
                l_frame,
                &mut pf,
                &mut psf_lp_noise,
                case.i16(&format!("tmp_noise{f}")),
                &mut synth,
                &case.i16s(&format!("Aq{f}")),
                &case.i16s(&format!("pitch{f}")),
                case.i16(&format!("coder_type{f}")),
                case.i16(&format!("ber{f}")),
                case.i16("disable_hpf"),
            );
            let name = format!("synth{f}");
            check(case, &name, &synth, &case.out_i16s(&name));
        }
        check(
            case,
            "psf_lp_noise",
            &psf_lp_noise,
            &case.out_i16("psf_lp_noise"),
        );
        check(case, "reset", &pf.reset, &case.out_i16("reset"));
        check(
            case,
            "mem_pf_in",
            &pf.mem_pf_in.to_vec(),
            &case.out_i16s("mem_pf_in"),
        );
        check(
            case,
            "mem_stp",
            &pf.mem_stp.to_vec(),
            &case.out_i16s("mem_stp"),
        );
        check(
            case,
            "mem_res2",
            &pf.mem_res2.to_vec(),
            &case.out_i16s("mem_res2"),
        );
        check(case, "gain_prec", &pf.gain_prec, &case.out_i16("gain_prec"));
    }
}

#[test]
fn pst_ltp_matches_the_reference() {
    let Some(cases) = corpus("dec_post", "pst_ltp") else {
        return;
    };
    for case in &cases {
        let res2 = case.i16s("res2");
        let mut out = vec![0i16; 64];
        pst_ltp(
            case.i16("t0"),
            &res2,
            299,
            &mut out,
            case.i16("gain_factor"),
        );
        check(case, "out", &out, &case.out_i16s("out"));
    }
}

#[test]
fn modify_pst_param_matches_the_reference() {
    let Some(cases) = corpus("dec_post", "modify_pst_param") else {
        return;
    };
    for case in &cases {
        let (mut g1, mut g2, mut gain_factor) = (-1, -1, -1);
        modify_pst_param(
            case.i16("lp_noise"),
            &mut g1,
            &mut g2,
            case.i16("coder_type"),
            &mut gain_factor,
        );
        check(case, "g1", &g1, &case.out_i16("g1"));
        check(case, "g2", &g2, &case.out_i16("g2"));
        check(
            case,
            "gain_factor",
            &gain_factor,
            &case.out_i16("gain_factor"),
        );
    }
}

#[test]
fn filt_mu_matches_the_reference() {
    let Some(cases) = corpus("dec_post", "filt_mu") else {
        return;
    };
    for case in &cases {
        let mut out = vec![0i16; 64];
        filt_mu(&case.i16s("in"), &mut out, case.i16("parcor0"), 64);
        check(case, "out", &out, &case.out_i16s("out"));
    }
}

#[test]
fn scale_st_matches_the_reference() {
    let Some(cases) = corpus("dec_post", "scale_st") else {
        return;
    };
    for case in &cases {
        let mut out = case.i16s("out");
        let mut gain_prec = case.i16("gain_prec");
        scale_st(&case.i16s("in"), &mut out, &mut gain_prec, 64);
        check(case, "out", &out, &case.out_i16s("out"));
        check(case, "gain_prec", &gain_prec, &case.out_i16("gain_prec"));
    }
}

#[test]
fn select_ltp_matches_the_reference() {
    let Some(cases) = corpus("dec_post", "select_ltp") else {
        return;
    };
    for case in &cases {
        let r = select_ltp(
            case.i16("num1"),
            case.i16("den1"),
            case.i16("sh_num1"),
            case.i16("sh_den1"),
            case.i16("num2"),
            case.i16("den2"),
            case.i16("sh_num2"),
            case.i16("sh_den2"),
        );
        check(case, "r", &r, &case.out_i16("r"));
    }
}

#[test]
fn blend_subfr2_matches_the_reference() {
    let Some(cases) = corpus("dec_post", "blend_subfr2") else {
        return;
    };
    for case in &cases {
        let mut out = [0i16; 32];
        blend_subfr2(&case.i16s("in1"), &case.i16s("in2"), &mut out);
        check(case, "out", &out.to_vec(), &case.out_i16s("out"));
    }
}

/// `formant_post_filt` over three consecutive frames on one `Pfstat` (and so
/// `Dec_formant_postfilt`): both frame lengths, every weighting branch, loud subframes, the off
/// flag and the reset; the overwritten input history is compared too.
#[test]
fn formant_post_filt_matches_the_reference() {
    let Some(cases) = corpus("dec_post", "formant_post_filt") else {
        return;
    };
    for case in &cases {
        let mut pf = Pfstat::zeroed();
        init_post_filter(&mut pf);
        pf.reset = case.i16("reset");
        pf.mem_pf_in.copy_from_slice(&case.i16s("mem_pf_in"));
        pf.mem_stp.copy_from_slice(&case.i16s("mem_stp"));
        pf.mem_res2.copy_from_slice(&case.i16s("mem_res2"));
        pf.gain_prec = case.i16("gain_prec");
        let l_frame = case.i16("L_frame");
        for f in 0..3 {
            let mut temp_buf = case.i16s(&format!("history{f}"));
            temp_buf.extend(case.i16s(&format!("synth{f}")));
            let mut out = vec![0i16; l_frame as usize];
            pf.reset = case.i16(&format!("reset{f}"));
            formant_post_filt(
                &mut pf,
                &mut temp_buf,
                60,
                &case.i16s(&format!("Aq{f}")),
                &mut out,
                l_frame,
                case.i32(&format!("lp_noise{f}")),
                case.i32(&format!("rate{f}")),
                case.i16(&format!("off_flag{f}")),
            );
            check(
                case,
                &format!("out{f}"),
                &out,
                &case.out_i16s(&format!("out{f}")),
            );
            check(
                case,
                &format!("history{f}"),
                &temp_buf[..60].to_vec(),
                &case.out_i16s(&format!("history{f}")),
            );
        }
        check(case, "reset", &pf.reset, &case.out_i16("reset"));
        check(
            case,
            "mem_pf_in",
            &pf.mem_pf_in.to_vec(),
            &case.out_i16s("mem_pf_in"),
        );
        check(
            case,
            "mem_stp",
            &pf.mem_stp.to_vec(),
            &case.out_i16s("mem_stp"),
        );
        check(
            case,
            "mem_res2",
            &pf.mem_res2.to_vec(),
            &case.out_i16s("mem_res2"),
        );
        check(case, "gain_prec", &pf.gain_prec, &case.out_i16("gain_prec"));
    }
}
