//! `lib_com/tcx_utils.c` against `fn_tcx_utils` (`getInvFrameLen`, `init_TCX_config`,
//! `InitTnsConfigs`, the synthesis windowing on every branch with random window slopes).

use siphon_rtp_codec::evs::com::tcx_utils::{
    get_inv_frame_len, init_tcx_config, init_tns_configs, tcx_windowing_synthesis_current_frame,
    tcx_windowing_synthesis_past_frame, AcelpTransition,
};
use siphon_rtp_codec::evs::dec::state::{PWord16, PWord16V, STnsConfig, TcxConfig};

use crate::common::{corpus, corpus_sized, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

/// A window as the oracle prints it: `len / 2` interleaved (re, im) pairs, empty for NULL.
fn window(w: &[PWord16], len: i16) -> Vec<i16> {
    if w.is_empty() {
        return Vec::new();
    }
    w.iter()
        .take(len as usize / 2)
        .flat_map(|p| [p.v.re, p.v.im])
        .collect()
}

#[test]
fn get_inv_frame_len_matches_the_reference() {
    let Some(cases) = corpus_sized("tcx_utils", "inv_frame_len", 500) else {
        return;
    };
    for case in &cases {
        check(
            case,
            "r",
            &get_inv_frame_len(case.i16("l")),
            &case.out_i16("r"),
        );
    }
}

#[test]
fn init_tcx_config_matches_the_reference() {
    let Some(cases) = corpus_sized("tcx_utils", "init_tcx_config", 200) else {
        return;
    };
    for case in &cases {
        let mut c = TcxConfig::zeroed();
        init_tcx_config(
            &mut c,
            case.i16("l_frame"),
            case.i16("fscale"),
            case.i16("l_frame_tcx"),
            case.i16("fscale_fb"),
        );
        let lengths = vec![
            c.tcx_mdct_window_length,
            c.tcx_mdct_window_delay,
            c.tcx_mdct_window_half_length,
            c.tcx_mdct_window_min_length,
            c.tcx_mdct_window_trans_length,
            c.tcx5_size,
            c.tcx_mdct_window_length_fb,
            c.tcx_mdct_window_delay_fb,
            c.tcx_mdct_window_half_length_fb,
            c.tcx_mdct_window_min_length_fb,
            c.tcx_mdct_window_trans_length_fb,
            c.tcx5_size_fb,
        ];
        check(case, "lengths", &lengths, &case.out_i16s("lengths"));
        let windows: [(&str, &[PWord16], i16); 8] = [
            ("w", c.tcx_mdct_window, c.tcx_mdct_window_length),
            (
                "w_half",
                c.tcx_mdct_window_half,
                c.tcx_mdct_window_half_length,
            ),
            (
                "w_min",
                c.tcx_mdct_window_minimum,
                c.tcx_mdct_window_min_length,
            ),
            (
                "w_trans",
                c.tcx_mdct_window_trans,
                c.tcx_mdct_window_trans_length,
            ),
            ("w_fb", c.tcx_mdct_window_fb, c.tcx_mdct_window_length_fb),
            (
                "w_half_fb",
                c.tcx_mdct_window_half_fb,
                c.tcx_mdct_window_half_length_fb,
            ),
            (
                "w_min_fb",
                c.tcx_mdct_window_minimum_fb,
                c.tcx_mdct_window_min_length_fb,
            ),
            (
                "w_trans_fb",
                c.tcx_mdct_window_trans_fb,
                c.tcx_mdct_window_trans_length_fb,
            ),
        ];
        for (name, w, len) in windows {
            check(case, name, &window(w, len), &case.out_i16s(name));
        }
        check(
            case,
            "aldo1",
            &c.tcx_aldo_window_1.to_vec(),
            &case.out_i16s("aldo1"),
        );
        check(
            case,
            "aldo1_trunc",
            &window(&c.tcx_aldo_window_1_trunc, 280),
            &case.out_i16s("aldo1_trunc"),
        );
        check(
            case,
            "aldo2",
            &window(&c.tcx_aldo_window_2, 280),
            &case.out_i16s("aldo2"),
        );
        check(
            case,
            "aldo1_fb",
            &c.tcx_aldo_window_1_fb.to_vec(),
            &case.out_i16s("aldo1_fb"),
        );
        check(
            case,
            "aldo1_fb_trunc",
            &window(&c.tcx_aldo_window_1_fb_trunc, 420),
            &case.out_i16s("aldo1_fb_trunc"),
        );
        check(
            case,
            "aldo2_fb",
            &window(&c.tcx_aldo_window_2_fb, 420),
            &case.out_i16s("aldo2_fb"),
        );
    }
}

#[test]
fn init_tns_configs_matches_the_reference() {
    let Some(cases) = corpus_sized("tcx_utils", "init_tns_configs", 1000) else {
        return;
    };
    for case in &cases {
        let mut configs: [[STnsConfig; 2]; 2] =
            std::array::from_fn(|_| std::array::from_fn(|_| STnsConfig::zeroed()));
        for (i, row) in configs.iter_mut().enumerate() {
            for (j, config) in row.iter_mut().enumerate() {
                let v = case.i16s(&format!("in{i}{j}"));
                config.max_order = v[0];
                config.n_max_filters = v[1];
                config.i_filter_borders.copy_from_slice(&v[2..5]);
            }
        }
        init_tns_configs(
            case.i32("sr"),
            case.i16("l_frame"),
            &mut configs,
            case.i16("igf_stop_freq"),
            case.i32("bitrate"),
        );
        for (i, row) in configs.iter().enumerate() {
            for (j, config) in row.iter().enumerate() {
                let name = format!("out{i}{j}");
                let rust = vec![
                    config.max_order,
                    config.n_max_filters,
                    crate::tns_base::table_id(config.p_tns_parameters),
                    config.i_filter_borders[0],
                    config.i_filter_borders[1],
                    config.i_filter_borders[2],
                ];
                check(case, &name, &rust, &case.out_i16s(&name));
            }
        }
    }
}

fn slopes(case: &Case, name: &str) -> Vec<PWord16> {
    case.i16s(name)
        .chunks(2)
        .map(|pair| PWord16 {
            v: PWord16V {
                re: pair[0],
                im: pair[1],
            },
        })
        .collect()
}

fn check_out(case: &Case, name: &str, rust: &[i16]) {
    if let Some(message) = mismatch(case, name, &rust.to_vec(), &case.out_i16s(name)) {
        panic!("{message}");
    }
}

#[test]
fn tcx_windowing_synthesis_current_frame_matches_the_reference() {
    let Some(cases) = corpus("tcx_utils", "current_frame") else {
        return;
    };
    for case in &cases {
        let mut signal = case.i16s("signal");
        let mut acelp_zir = case.i16s("acelp_zir");
        let old_syn = case.i16s("old_syn");
        let syn_overl = case.i16s("syn_overl");
        let a_zir = case.i16s("a_zir");
        tcx_windowing_synthesis_current_frame(
            &mut signal,
            &slopes(case, "window"),
            &slopes(case, "window_half"),
            &slopes(case, "window_min"),
            case.i16("window_length"),
            case.i16("window_half_length"),
            case.i16("window_min_length"),
            case.i16("left_rect"),
            case.i16("left_mode"),
            Some(AcelpTransition {
                acelp_zir: &mut acelp_zir,
                old_syn: &old_syn,
                syn_overl: &syn_overl,
                a_zir: &a_zir,
            }),
            &slopes(case, "window_trans"),
            case.i16("acelp_zir_len"),
            case.i16("acelp_mem_len"),
            case.i16("last_core_bfi"),
            case.i16("last_is_cng") as i8,
            case.i16("fullband_scale"),
        );
        check_out(case, "signal", &signal);
        check_out(case, "acelp_zir", &acelp_zir);
    }
}

#[test]
fn tcx_windowing_synthesis_past_frame_matches_the_reference() {
    let Some(cases) = corpus("tcx_utils", "past_frame") else {
        return;
    };
    for case in &cases {
        let mut signal = case.i16s("signal");
        tcx_windowing_synthesis_past_frame(
            &mut signal,
            &slopes(case, "window"),
            &slopes(case, "window_half"),
            &slopes(case, "window_min"),
            case.i16("window_length"),
            case.i16("window_half_length"),
            case.i16("window_min_length"),
            case.i16("right_mode"),
        );
        check_out(case, "signal", &signal);
    }
}
