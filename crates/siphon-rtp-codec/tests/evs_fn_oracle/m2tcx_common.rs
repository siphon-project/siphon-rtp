//! `lib_com/codec_tcx_common.c` against `fn_m2tcx_common`.

use siphon_rtp_codec::evs::com::codec_tcx_common::{
    tcx_formant_enhancement, tcx_get_noise_filling_tilt, tcx_invert_window_grouping,
};
use siphon_rtp_codec::evs::dec::state::TcxConfig;
use siphon_rtp_codec::itu::stl2009::StlFlags;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn tcx_get_noise_filling_tilt_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_common", "tcxGetNoiseFillingTilt") else {
        return;
    };
    for case in &cases {
        let mut flags = StlFlags {
            overflow: false,
            carry: case.i16("carry_in") != 0,
        };
        let mut tilt = 0x1234;
        let first = tcx_get_noise_filling_tilt(
            &case.i16s("a"),
            16,
            case.i16("l_frame"),
            case.i16("mode"),
            &mut tilt,
            &mut flags,
        );
        check(case, "first", &first, &case.out_i16("first"));
        check(case, "tilt", &tilt, &case.out_i16("tilt"));
        check(
            case,
            "carry",
            &i16::from(flags.carry),
            &case.out_i16("carry"),
        );
    }
}

#[test]
fn tcx_formant_enhancement_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_common", "tcxFormantEnhancement") else {
        return;
    };
    for case in &cases {
        let mut spectrum = case.i32s("spectrum");
        let mut spectrum_e = case.i16("spectrum_e");
        let mut xn_buf = vec![0x5555i16; 1400];
        tcx_formant_enhancement(
            &mut xn_buf,
            &case.i16s("g"),
            &case.i16s("ge"),
            &mut spectrum,
            &mut spectrum_e,
            case.i16("l_frame"),
            case.i16("l_frame_tcx"),
        );
        check(case, "spectrum", &spectrum, &case.out_i32s("spectrum"));
        check(case, "spectrum_e", &spectrum_e, &case.out_i16("spectrum_e"));
        check(
            case,
            "xn_buf",
            &xn_buf[..64].to_vec(),
            &case.out_i16s("xn_buf"),
        );
    }
}

#[test]
fn tcx_invert_window_grouping_matches_the_reference() {
    let Some(cases) = corpus("m2tcx_common", "tcxInvertWindowGrouping") else {
        return;
    };
    for case in &cases {
        let mut config = TcxConfig::zeroed();
        config.tcx_last_overlap_mode = case.i16("last_mode");
        config.tcx_curr_overlap_mode = case.i16("curr_mode");
        config.f_is_tns_allowed = case.i16("tns_allowed") as i8;
        config.tns_config[0][0].i_filter_borders[0] = case.i16("l_spec");
        let mut spectrum = case.i32s("spectrum");
        spectrum.resize(700, 0);
        let mut xn_buf = vec![0x5555_5555i32; 700];
        tcx_invert_window_grouping(
            &mut config,
            &mut xn_buf,
            &mut spectrum,
            case.i16("l_frame"),
            case.i16("use_tns") as i8,
            case.i16("last_core"),
            case.i16("index"),
            case.i16("frame_cnt"),
            case.i16("bfi"),
        );
        let l_frame = case.i16("l_frame") as usize;
        check(
            case,
            "spectrum",
            &spectrum[..l_frame].to_vec(),
            &case.out_i32s("spectrum"),
        );
        check(
            case,
            "xn_buf",
            &xn_buf[..l_frame].to_vec(),
            &case.out_i32s("xn_buf"),
        );
        check(
            case,
            "last_mode",
            &config.tcx_last_overlap_mode,
            &case.out_i16("last_mode"),
        );
    }
}
