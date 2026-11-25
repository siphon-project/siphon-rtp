//! `WindowSignal` (`lib_com/tcx_utils.c`) against `fn_m2tcx_window`. `tcx_get_windows` and
//! `tcx_windowing_analysis` are proven through it, on every overlap mode pair.

use siphon_rtp_codec::evs::com::tcx_utils::{init_tcx_config, window_signal};
use siphon_rtp_codec::evs::dec::state::TcxConfig;

use crate::common::{corpus_sized, mismatch, Case};

/// `sr2fscale`: `(sr · FSCALE_DENOM) / 12800` (FSCALE_DENOM = 512), as the decoder sets it.
fn sr2fscale(sample_rate: i32) -> i16 {
    (sample_rate * 512 / 12800) as i16
}

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn window_signal_matches_the_reference() {
    let Some(cases) = corpus_sized("m2tcx_window", "WindowSignal", 600) else {
        return;
    };
    for case in &cases {
        let (sr, fs) = (case.i32("sr"), case.i32("fs"));
        let mut config = TcxConfig::zeroed();
        init_tcx_config(
            &mut config,
            (sr / 50) as i16,
            sr2fscale(sr),
            (fs / 50) as i16,
            sr2fscale(fs),
        );
        config.tcx_offset = config.tcx_mdct_window_delay >> 1;
        config.tcx_offset_fb = config.tcx_mdct_window_delay_fb >> 1;

        let signal = case.i16s("signal");
        let mut l_frame = case.i16("l_frame");
        let (mut left_overlap, mut right_overlap) = (0x1111, 0x2222);
        let mut out = vec![0x5a5ai16; signal.len()];
        window_signal(
            &config,
            case.i16("offset"),
            case.i16("left_mode"),
            case.i16("right_mode"),
            &mut left_overlap,
            &mut right_overlap,
            &signal,
            500,
            &mut l_frame,
            &mut out,
            case.i16("fullband") as i8,
        );
        check(
            case,
            "left_overlap",
            &left_overlap,
            &case.out_i16("left_overlap"),
        );
        check(
            case,
            "right_overlap",
            &right_overlap,
            &case.out_i16("right_overlap"),
        );
        check(case, "l_frame_io", &l_frame, &case.out_i16("l_frame_io"));
        let expected = case.out_i16s("out");
        out.truncate(expected.len());
        check(case, "out", &out, &expected);
    }
}
