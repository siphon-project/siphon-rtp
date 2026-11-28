//! `lib_com/core_com_config_fx.c` against `fn_core_com_config`.

use siphon_rtp_codec::evs::com::core_com_config::{
    get_core_samplerate_mode2, get_ctx_hm, get_num_tcx_coded_lines, get_resq, get_tcx_bandwidth,
    get_tcx_lpc_shaped_ari, get_tcx_ltp, get_tcxonly, get_tns_allowed, init_pitch_lag_parameters,
    sr2fscale,
};

use crate::common::{corpus, mismatch};

#[test]
fn core_configuration_matches_the_reference() {
    let Some(cases) = corpus("core_com_config", "config") else {
        return;
    };
    for case in &cases {
        let bitrate = case.i32("bitrate");
        let bandwidth = case.i16("bandwidth");
        let rf = case.i16("rf");
        let sr = case.i32("sr");
        let pitch = init_pitch_lag_parameters(case.i32("pitch_sr"));
        let rust: Vec<i64> = vec![
            get_core_samplerate_mode2(bitrate, bandwidth, rf).into(),
            get_tcxonly(bitrate).into(),
            get_ctx_hm(bitrate, rf).into(),
            get_resq(bitrate).into(),
            get_tns_allowed(bitrate, case.i16("igf")).into(),
            sr2fscale(sr).into(),
            get_tcx_bandwidth(bandwidth).into(),
            get_tcx_ltp(sr).into(),
            get_num_tcx_coded_lines(bandwidth).into(),
            get_tcx_lpc_shaped_ari(bitrate, bandwidth, rf).into(),
            pitch.pit_min.into(),
            pitch.pit_fr1.into(),
            pitch.pit_fr1b.into(),
            pitch.pit_fr2.into(),
            pitch.pit_max.into(),
            pitch.pit_res_max.into(),
        ];
        let names = [
            "core_sr",
            "tcxonly",
            "ctx_hm",
            "resq",
            "tns",
            "fscale",
            "tcx_bw",
            "tcxltp",
            "lines",
            "lpc_ari",
            "pit_min",
            "pit_fr1",
            "pit_fr1b",
            "pit_fr2",
            "pit_max",
            "pit_res_max",
        ];
        let reference: Vec<i64> = names.iter().map(|name| case.outputs[*name][0]).collect();
        if let Some(message) = mismatch(case, &names.join("/"), &rust, &reference) {
            panic!("{message}");
        }
    }
}
