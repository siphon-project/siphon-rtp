//! `lib_dec/waveadjust_fec_dec.c` against `fn_m2conceal_waveadjust`: the bookkeeping of the last
//! good frame, the pitch search and the helpers it is built from, the log energy, the waveform
//! adjustment of the first and of the following lost frames, and the top-level tuning.

use siphon_rtp_codec::evs::dec::state::TPLCInfo;
use siphon_rtp_codec::evs::dec::waveadjust_fec_dec::{
    con_log10, concealment_decode_fix, concealment_signal_tuning_fx, concealment_update2_x,
    concealment_update_x, ffr_get_sf_word16, get_conv_relation_x, get_max_conv_and_pitch_x,
    get_voicing_x, harmo_x, int_div_s_x, is_periodic_x, log10_of_energy_x, lp_filter2_x,
    pitch_modify_x, pitch_search_fx, sig_tilt_x, sqrt_x_fast, waveform_adj2_fix, waveform_adj_fix,
};

use crate::common::{corpus_sized, mismatch, Case};

const COUNT: usize = 500;
const PCM_LEN: usize = 1440;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn plc_info(case: &Case, prefix: &str) -> Box<TPLCInfo> {
    let key = |name: &str| format!("{prefix}{name}");
    let mut plc = Box::new(TPLCInfo::zeroed());
    plc.frame_size = case.i16(&key("FrameSize"));
    plc.pitch = case.i16(&key("Pitch_fx"));
    plc.t_bfi = case.i16(&key("T_bfi_fx")) as i8;
    plc.transient.copy_from_slice(&case.i16s(&key("Transient")));
    plc.tcx_tonality
        .copy_from_slice(&case.i16s(&key("TCX_Tonality")));
    plc.outx_new_n1 = case.i16(&key("outx_new_n1_fx"));
    plc.nsapp_gain = case.i16(&key("nsapp_gain_fx"));
    plc.nsapp_gain_n = case.i16(&key("nsapp_gain_n_fx"));
    plc.data_reci2
        .copy_from_slice(&case.i32s(&key("data_reci2_fx")));
    plc.data_reci2_scale = case.i16(&key("data_reci2_scale"));
    plc.data_noise
        .copy_from_slice(&case.i16s(&key("data_noise")));
    plc.ener_mean = case.i32(&key("ener_mean_fx"));
    plc.ener = case.i32(&key("ener_fx"));
    plc.zp = case.i16(&key("zp_fx"));
    plc.recovery_gain = case.i16(&key("recovery_gain"));
    plc.step_concealgain = case.i16(&key("step_concealgain_fx"));
    plc.concealment_method = case.i16(&key("concealment_method"));
    plc.subframe = case.i16(&key("subframe_fx"));
    plc.nb_lost_cmpt = case.i32(&key("nbLostCmpt"));
    plc.seed = case.i16(&key("seed"));
    plc
}

fn check_plc(case: &Case, prefix: &str, plc: &TPLCInfo) {
    let key = |name: &str| format!("{prefix}{name}");
    let got = |name: &str| format!("{prefix}{name}");
    check(
        case,
        &got("FrameSize"),
        &plc.frame_size,
        &case.out_i16(&key("FrameSize")),
    );
    check(
        case,
        &got("Pitch_fx"),
        &plc.pitch,
        &case.out_i16(&key("Pitch_fx")),
    );
    check(
        case,
        &got("T_bfi_fx"),
        &i16::from(plc.t_bfi),
        &case.out_i16(&key("T_bfi_fx")),
    );
    check(
        case,
        &got("Transient"),
        &plc.transient.to_vec(),
        &case.out_i16s(&key("Transient")),
    );
    check(
        case,
        &got("TCX_Tonality"),
        &plc.tcx_tonality.to_vec(),
        &case.out_i16s(&key("TCX_Tonality")),
    );
    check(
        case,
        &got("outx_new_n1_fx"),
        &plc.outx_new_n1,
        &case.out_i16(&key("outx_new_n1_fx")),
    );
    check(
        case,
        &got("nsapp_gain_fx"),
        &plc.nsapp_gain,
        &case.out_i16(&key("nsapp_gain_fx")),
    );
    check(
        case,
        &got("nsapp_gain_n_fx"),
        &plc.nsapp_gain_n,
        &case.out_i16(&key("nsapp_gain_n_fx")),
    );
    check(
        case,
        &got("data_reci2_fx"),
        &plc.data_reci2.to_vec(),
        &case.out_i32s(&key("data_reci2_fx")),
    );
    check(
        case,
        &got("data_reci2_scale"),
        &plc.data_reci2_scale,
        &case.out_i16(&key("data_reci2_scale")),
    );
    check(
        case,
        &got("data_noise"),
        &plc.data_noise.to_vec(),
        &case.out_i16s(&key("data_noise")),
    );
    check(
        case,
        &got("ener_mean_fx"),
        &plc.ener_mean,
        &case.out_i32(&key("ener_mean_fx")),
    );
    check(
        case,
        &got("ener_fx"),
        &plc.ener,
        &case.out_i32(&key("ener_fx")),
    );
    check(case, &got("zp_fx"), &plc.zp, &case.out_i16(&key("zp_fx")));
    check(
        case,
        &got("recovery_gain"),
        &plc.recovery_gain,
        &case.out_i16(&key("recovery_gain")),
    );
    check(
        case,
        &got("step_concealgain_fx"),
        &plc.step_concealgain,
        &case.out_i16(&key("step_concealgain_fx")),
    );
    check(
        case,
        &got("concealment_method"),
        &plc.concealment_method,
        &case.out_i16(&key("concealment_method")),
    );
    check(
        case,
        &got("subframe_fx"),
        &plc.subframe,
        &case.out_i16(&key("subframe_fx")),
    );
    check(
        case,
        &got("nbLostCmpt"),
        &plc.nb_lost_cmpt,
        &case.out_i32(&key("nbLostCmpt")),
    );
    check(case, &got("seed"), &plc.seed, &case.out_i16(&key("seed")));
}

#[test]
fn concealment_update_x_matches_the_reference() {
    let Some(cases) = corpus_sized("m2conceal_waveadjust", "update_x", COUNT) else {
        return;
    };
    for case in &cases {
        let mut plc = plc_info(case, "p.");
        concealment_update_x(
            case.i16("bfi"),
            case.i16("curr_mode"),
            case.i16("tonality"),
            &case.i32s("invkoef"),
            case.i16("scale"),
            &mut plc,
        );
        check_plc(case, "p.", &plc);
    }
}

#[test]
fn concealment_decode_fix_matches_the_reference() {
    let Some(cases) = corpus_sized("m2conceal_waveadjust", "decode_fix", COUNT) else {
        return;
    };
    for case in &cases {
        let mut plc = plc_info(case, "p.");
        let mut invkoef = vec![-7i32; 960];
        let mut scale = 77i16;
        concealment_decode_fix(case.i16("curr_mode"), &mut invkoef, &mut scale, &mut plc);
        check_plc(case, "p.", &plc);
        check(case, "invkoef", &invkoef, &case.out_i32s("invkoef"));
        check(case, "scale", &scale, &case.out_i16("scale"));
    }
}

#[test]
fn pitch_search_fx_matches_the_reference() {
    let Some(cases) = corpus_sized("m2conceal_waveadjust", "pitch_search", 2000) else {
        return;
    };
    let mut found = 0;
    for case in &cases {
        let mut voicing = -1i16;
        let pitch = pitch_search_fx(
            &case.i16s("s"),
            &case.i16s("outx_new"),
            case.i16("frame_size"),
            &mut voicing,
            case.i16("zp"),
            case.i32("ener"),
            case.i32("ener_mean"),
            &case.i32s("mdct"),
            case.i16("curr_mode"),
        );
        check(case, "pitch", &pitch, &case.out_i16("pitch"));
        check(case, "voicing", &voicing, &case.out_i16("voicing"));
        found += usize::from(pitch > 0);
    }
    assert!(
        found > 100,
        "the corpus must reach the periodic branch: {found}"
    );
}

#[test]
fn the_pitch_search_helpers_match_the_reference() {
    let Some(cases) = corpus_sized("m2conceal_waveadjust", "parts", 2000) else {
        return;
    };
    for case in &cases {
        let s = case.i16s("s");
        let mdct = case.i32s("mdct");
        let frame_size = case.i16("frame_size");
        let mut lp = vec![0i16; 960];
        lp_filter2_x(&s, &mut lp, frame_size);
        check(
            case,
            "lp",
            &lp[..frame_size as usize].to_vec(),
            &case.out_i16s("lp"),
        );
        let (mut enr1, mut enr2) = (0i32, 0i32);
        sig_tilt_x(&lp, frame_size, &mut enr1, &mut enr2);
        check(case, "enr1", &enr1, &case.out_i32("enr1"));
        check(case, "enr2", &enr2, &case.out_i32("enr2"));
        let half = if frame_size > 320 {
            frame_size / 2
        } else {
            frame_size
        };
        let start = (0x80 + 34 * half) >> 8;
        let end = (2 + 3 * half) >> 2;
        let (mut cov_max, mut cov_bits, mut found) = (0i32, 0i16, 0i16);
        get_max_conv_and_pitch_x(
            &lp,
            start,
            end,
            half,
            &mut cov_max,
            &mut cov_bits,
            &mut found,
        );
        check(case, "cov_max", &cov_max, &case.out_i32("cov_max"));
        check(case, "cov_bits", &cov_bits, &case.out_i16("cov_bits"));
        check(case, "found", &found, &case.out_i16("found"));
        let voicing = get_voicing_x(&lp, found, cov_max, cov_bits, half);
        check(case, "voicing", &voicing, &case.out_i16("voicing"));
        let (mut voicing_mod, mut pitch_mod) = (voicing, found);
        pitch_modify_x(&lp, &mut voicing_mod, &mut pitch_mod, half);
        check(case, "pitch_mod", &pitch_mod, &case.out_i16("pitch_mod"));
        check(
            case,
            "voicing_mod",
            &voicing_mod,
            &case.out_i16("voicing_mod"),
        );
        let relation = get_conv_relation_x(&lp, found, frame_size - found);
        check(case, "relation", &relation, &case.out_i16("relation"));
        let flag_pitch = case.i16("flag_pitch");
        let periodic = is_periodic_x(
            &mdct,
            case.i16("cov"),
            case.i16("zp"),
            case.i32("ener"),
            case.i32("ener_mean"),
            flag_pitch,
            frame_size,
        );
        check(case, "periodic", &periodic, &case.out_i16("periodic"));
        check(
            case,
            "harm",
            &harmo_x(&mdct, frame_size, flag_pitch),
            &case.out_i16("harm"),
        );
        check(
            case,
            "root",
            &sqrt_x_fast(case.i32("value")),
            &case.out_i16("root"),
        );
        check(
            case,
            "quotient",
            &int_div_s_x(case.i16("a"), case.i16("b")),
            &case.out_i16("quotient"),
        );
    }
}

#[test]
fn the_log_energy_and_its_update_match_the_reference() {
    let Some(cases) = corpus_sized("m2conceal_waveadjust", "log10", 1000) else {
        return;
    };
    for case in &cases {
        let x = case.i16s("x");
        let frame_size = case.i16("frame_size");
        check(
            case,
            "con",
            &con_log10(case.i32("value"), case.i16("q")),
            &case.out_i32("con"),
        );
        check(
            case,
            "sf",
            &ffr_get_sf_word16(&x, case.i16("len")),
            &case.out_i16("sf"),
        );
        let mut enerlog = 5i32;
        log10_of_energy_x(&x, &mut enerlog, frame_size);
        check(case, "enerlog", &enerlog, &case.out_i32("enerlog"));
        let mut plc = plc_info(case, "p.");
        concealment_update2_x(&x, &mut plc, frame_size);
        check_plc(case, "p.", &plc);
    }
}

fn overlap_and_outdata2_at(frame_size: i16) -> (usize, usize) {
    (
        PCM_LEN - 3 * frame_size as usize / 2,
        PCM_LEN - frame_size as usize,
    )
}

#[test]
fn waveform_adj_fix_matches_the_reference() {
    let Some(cases) = corpus_sized("m2conceal_waveadjust", "waveform_adj", COUNT) else {
        return;
    };
    let mut adjusted = 0;
    for case in &cases {
        let frame_size = case.i16("frame_size");
        let (overlap_at, outdata2_at) = overlap_and_outdata2_at(frame_size);
        let mut tdb = case.i16s("tdb");
        let mut outx_new = case.i16s("outx_new");
        let mut data_noise = case.i16s("data_noise");
        let mut outx_new_n1 = case.i16("outx_new_n1");
        let mut nsapp_gain = case.i16("nsapp_gain");
        let mut nsapp_gain_n = case.i16("nsapp_gain_n");
        let pitch = waveform_adj_fix(
            &mut tdb,
            overlap_at,
            outdata2_at,
            &mut outx_new,
            &mut data_noise,
            &mut outx_new_n1,
            &mut nsapp_gain,
            &mut nsapp_gain_n,
            frame_size,
            case.i16("t_bfi") as i8,
            case.i16("voicing"),
            case.i16("curr_mode"),
            case.i16("pitch"),
        );
        check(case, "pitch", &pitch, &case.out_i16("pitch"));
        check(case, "tdb", &tdb, &case.out_i16s("tdb"));
        check(case, "outx_new", &outx_new, &case.out_i16s("outx_new"));
        check(
            case,
            "data_noise",
            &data_noise,
            &case.out_i16s("data_noise"),
        );
        check(
            case,
            "outx_new_n1",
            &outx_new_n1,
            &case.out_i16("outx_new_n1"),
        );
        check(case, "nsapp_gain", &nsapp_gain, &case.out_i16("nsapp_gain"));
        check(
            case,
            "nsapp_gain_n",
            &nsapp_gain_n,
            &case.out_i16("nsapp_gain_n"),
        );
        adjusted += usize::from(pitch > 0);
    }
    assert!(
        adjusted > COUNT / 4,
        "the corpus must reach the adjustment: {adjusted}"
    );
}

#[test]
fn waveform_adj2_fix_matches_the_reference() {
    let Some(cases) = corpus_sized("m2conceal_waveadjust", "waveform_adj2", COUNT) else {
        return;
    };
    for case in &cases {
        let frame_size = case.i16("frame_size");
        let (overlap_at, _) = overlap_and_outdata2_at(frame_size);
        let mut tdb = case.i16s("tdb");
        let mut outx_new = case.i16s("outx_new");
        let mut data_noise = case.i16s("data_noise");
        let mut outx_new_n1 = case.i16("outx_new_n1");
        let mut nsapp_gain = case.i16("nsapp_gain");
        let mut nsapp_gain_n = case.i16("nsapp_gain_n");
        let mut recovery_gain = case.i16("recovery_gain");
        waveform_adj2_fix(
            &mut tdb[overlap_at..],
            &mut outx_new,
            &mut data_noise,
            &mut outx_new_n1,
            &mut nsapp_gain,
            &mut nsapp_gain_n,
            &mut recovery_gain,
            case.i16("step"),
            case.i16("pitch"),
            frame_size,
            0,
            case.i16("bfi_cnt"),
            case.i16("bfi"),
        );
        check(case, "tdb", &tdb, &case.out_i16s("tdb"));
        check(case, "outx_new", &outx_new, &case.out_i16s("outx_new"));
        check(
            case,
            "data_noise",
            &data_noise,
            &case.out_i16s("data_noise"),
        );
        check(
            case,
            "outx_new_n1",
            &outx_new_n1,
            &case.out_i16("outx_new_n1"),
        );
        check(case, "nsapp_gain", &nsapp_gain, &case.out_i16("nsapp_gain"));
        check(
            case,
            "recovery_gain",
            &recovery_gain,
            &case.out_i16("recovery_gain"),
        );
    }
}

#[test]
fn concealment_signal_tuning_fx_matches_the_reference() {
    let Some(cases) = corpus_sized("m2conceal_waveadjust", "signal_tuning", COUNT) else {
        return;
    };
    for case in &cases {
        let mut plc = plc_info(case, "p.");
        let frame_size = plc.frame_size;
        let (overlap_at, outdata2_at) = overlap_and_outdata2_at(frame_size);
        let mut tdb = case.i16s("tdb");
        let mut outx_new = case.i16s("outx_new");
        concealment_signal_tuning_fx(
            case.i16("bfi"),
            case.i16("curr_mode"),
            &mut outx_new,
            &mut plc,
            case.i16("nb_lost"),
            case.i16("pre_bfi"),
            &mut tdb,
            overlap_at,
            case.i16("past_core_mode"),
            outdata2_at,
            case.i16("enable"),
            case.i32("brate"),
            case.i16("codec_mode"),
        );
        check(case, "tdb", &tdb, &case.out_i16s("tdb"));
        check(case, "outx_new", &outx_new, &case.out_i16s("outx_new"));
        check_plc(case, "p.", &plc);
    }
}

#[test]
fn is_periodic_x_matches_the_reference_at_every_threshold() {
    let Some(cases) = corpus_sized("m2conceal_periodic", "is_periodic", 5000) else {
        return;
    };
    for case in &cases {
        let frame_size = case.i16("frame_size");
        let pitch = case.i16("pitch");
        let mdct = case.i32s("mdct");
        let periodic = is_periodic_x(
            &mdct,
            case.i32("cov") as i16,
            case.i16("zp"),
            case.i32("ener"),
            case.i32("ener_mean"),
            pitch,
            frame_size,
        );
        check(case, "periodic", &periodic, &case.out_i16("periodic"));
        check(
            case,
            "harm",
            &harmo_x(&mdct, frame_size, pitch),
            &case.out_i16("harm"),
        );
    }
}
