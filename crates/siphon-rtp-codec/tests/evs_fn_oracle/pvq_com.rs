//! `lib_com/pvq_com_fx.c` (the decoder's PVQ helpers) against `fn_pvq_com`. `dsDirac2Dirac` is
//! proven through `conservativeL1Norm`.

use siphon_rtp_codec::evs::com::pvq_com::{
    apply_gain, band_bits_adjustment, conservative_l1_norm, ds_dirac_per_quanta, int_lim_c_div_pos,
    int_lim_c_div_signed, shrt_c_div_signed_approx, srt_vec_ind16,
};
use siphon_rtp_codec::evs::rom::HBITSN;

use crate::common::{corpus, mismatch, Case};

fn compare(case: &Case, names: &[&str], rust: &[i32]) {
    let reference: Vec<i32> = names.iter().map(|name| case.out_i32(name)).collect();
    if let Some(message) = mismatch(case, &names.join("/"), &rust.to_vec(), &reference) {
        panic!("{message}");
    }
}

#[test]
fn int_lim_c_div_matches_the_reference() {
    let Some(cases) = corpus("pvq_com", "int_lim_c_div") else {
        return;
    };
    for case in &cases {
        let (num, den) = (case.i32("num"), case.i16("den"));
        compare(
            case,
            &["pos", "signed"],
            &[
                int_lim_c_div_pos(num.unsigned_abs(), den) as i32,
                int_lim_c_div_signed(num, den),
            ],
        );
    }
}

#[test]
fn shrt_c_div_signed_approx_matches_the_reference() {
    let Some(cases) = corpus("pvq_com", "shrt_c_div") else {
        return;
    };
    for case in &cases {
        let quotient = shrt_c_div_signed_approx(case.i16("num"), case.i16("den"));
        compare(case, &["quotient"], &[i32::from(quotient)]);
    }
}

#[test]
fn ds_dirac_per_quanta_matches_the_reference() {
    let Some(cases) = corpus("pvq_com", "ds_dirac_per_quanta") else {
        return;
    };
    for case in &cases {
        let index = ds_dirac_per_quanta(
            case.i16("td"),
            case.i16("t_quanta"),
            case.i16("dsm"),
            &HBITSN,
        );
        compare(case, &["ds_idx"], &[i32::from(index)]);
    }
}

#[test]
fn conservative_l1_norm_matches_the_reference() {
    let Some(cases) = corpus("pvq_com", "conservative_l1_norm") else {
        return;
    };
    for case in &cases {
        let out = conservative_l1_norm(
            case.i16("l"),
            case.i16("qvec"),
            case.i16("fcons"),
            case.i16("qavail"),
            case.i16("qreserv"),
            case.i16("dspec"),
        );
        compare(
            case,
            &["dvec", "qspare", "qreservplus", "dspecplus"],
            &[
                i32::from(out.dvec),
                i32::from(out.qspare),
                i32::from(out.qreservplus),
                i32::from(out.dspecplus),
            ],
        );
    }
}

#[test]
fn band_bits_adjustment_matches_the_reference() {
    let Some(cases) = corpus("pvq_com", "band_bits_adjustment") else {
        return;
    };
    for case in &cases {
        let out = band_bits_adjustment(
            case.i16("brc"),
            case.i32("int_rc") as u32,
            case.i16("bavail"),
            case.i16("nbands"),
            case.i16("d"),
            case.i16("l"),
            case.i16("bband"),
            case.i16("breserv"),
        );
        compare(
            case,
            &["bband_adj", "brem", "breservplus"],
            &[
                i32::from(out.bband_adj),
                i32::from(out.brem),
                i32::from(out.breservplus),
            ],
        );
    }
}

#[test]
fn apply_gain_matches_the_reference() {
    let Some(cases) = corpus("pvq_com", "apply_gain") else {
        return;
    };
    for case in &cases {
        let ord = case.i16s("ord");
        let mut xq = case.i16s("xq");
        apply_gain(
            &ord,
            &case.i16s("band_start"),
            &case.i16s("band_end"),
            ord.len() as i16,
            &case.i16s("gains"),
            &mut xq,
        );
        if let Some(message) = mismatch(case, "xq", &xq, &case.out_i16s("xq")) {
            panic!("{message}");
        }
    }
}

#[test]
fn srt_vec_ind16_matches_the_reference() {
    let Some(cases) = corpus("pvq_com", "srt_vec_ind16") else {
        return;
    };
    for case in &cases {
        let linear = case.i16s("linear");
        let mut srt = vec![0; linear.len()];
        let mut index = vec![0; linear.len()];
        srt_vec_ind16(&linear, &mut srt, &mut index, linear.len() as i16);
        let rust = [srt, index].concat();
        let reference = [case.out_i16s("srt"), case.out_i16s("index")].concat();
        if let Some(message) = mismatch(case, "srt/index", &rust, &reference) {
            panic!("{message}");
        }
    }
}

#[test]
fn split_energy_helpers_match_the_reference() {
    use siphon_rtp_codec::evs::com::pvq_com::{
        atan2, density_angle2_rms_proj_dec, near_opp_split_adjustment, near_proj_q15,
        obtain_energy_quantizer_density, quanta_per_ds_dirac, ratio_r_q3,
    };
    if let Some(cases) = corpus("pvq_com", "near_proj") {
        for case in &cases {
            compare(case, &["r"], &[i32::from(near_proj_q15(case.i16("x")))]);
        }
    }
    if let Some(cases) = corpus("pvq_com", "energy_density") {
        for case in &cases {
            let d = obtain_energy_quantizer_density(case.i16("l"), case.i16("r"));
            compare(case, &["d"], &[i32::from(d)]);
        }
    }
    if let Some(cases) = corpus("pvq_com", "quanta_per_ds_dirac") {
        for case in &cases {
            let q = quanta_per_ds_dirac(case.i16("td"), case.i16("idx"), &HBITSN);
            compare(case, &["q"], &[i32::from(q)]);
        }
    }
    if let Some(cases) = corpus("pvq_com", "ratio_rq3") {
        for case in &cases {
            let r = ratio_r_q3(case.i16("opp"), case.i16("near"));
            compare(case, &["r"], &[i32::from(r)]);
        }
    }
    if let Some(cases) = corpus("pvq_com", "density_angle") {
        for case in &cases {
            let p = density_angle2_rms_proj_dec(case.i16("d"), case.i16("idx"));
            compare(
                case,
                &["opp", "near", "ratio"],
                &[p.opp_q15.into(), p.near_q15.into(), p.opp_ratio_q3.into()],
            );
        }
    }
    if let Some(cases) = corpus("pvq_com", "near_opp_split") {
        for case in &cases {
            let s = near_opp_split_adjustment(
                case.i16("qband"),
                case.i16("qzero"),
                case.i16("qac"),
                case.inputs["intac"][0] as u32,
                case.i16("qglobal"),
                case.i16("cons"),
                case.i16("np"),
                case.i16("nhead"),
                case.i16("ntail"),
                case.i16("nnear"),
                case.i16("nopp"),
                case.i16("oppr"),
            );
            compare(
                case,
                &["qnear", "qopp", "qupd"],
                &[s.qnear.into(), s.qopp.into(), s.qglobalupd.into()],
            );
        }
    }
    if let Some(cases) = corpus("pvq_com", "atan2") {
        for case in &cases {
            compare(
                case,
                &["angle"],
                &[i32::from(atan2(case.i32("y"), case.i32("x")))],
            );
        }
    }
}
