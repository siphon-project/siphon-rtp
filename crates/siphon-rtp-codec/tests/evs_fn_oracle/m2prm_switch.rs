//! `lib_dec/core_dec_switch.c` (`mode_switch_decoder_LPD`) and `lib_dec/core_dec_reconf.c`
//! (`reconfig_decoder_LPD`) against `fn_m2prm_switch`, on the whole decoder state.

use siphon_rtp_codec::evs::dec::core_dec_reconf::reconfig_decoder_lpd;
use siphon_rtp_codec::evs::dec::core_dec_switch::mode_switch_decoder_lpd;

use siphon_rtp_codec::evs::com::core_com_config::get_igf_present;
use siphon_rtp_codec::evs::com::igf_base::{igf_common_funcs_igf_get_cf_tables, IgfCfTables};
use siphon_rtp_codec::evs::com::rom_basop_util::get_sine_window_table;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::Case;
use crate::state_case::{decoder_before, state_after};
use crate::{common::corpus_sized, state_dump};

const MODULE: &str = "m2prm_switch";

/// Select the IGF SCF coder's ROM tables of the configuration the "before" state was set up in (a
/// state load does not restore them; `IGFDecSetMode` points them at the bit rate's rows).
fn select_igf_tables(st: &mut DecoderState, case: &Case) {
    let (rate, mode, rf) = (
        case.i32("first_rate"),
        case.i16("first_bw"),
        case.i16("first_rf"),
    );
    if get_igf_present(rate, mode, rf) == 0 {
        return;
    }
    let mut tables = IgfCfTables::empty();
    igf_common_funcs_igf_get_cf_tables(rate, mode, rf, &mut tables);
    let decoder = &mut st.h_igf_dec.igf_data.h_arith_sc_fdec;
    decoder.cf_se00 = tables.cf_se00;
    decoder.cf_se01 = tables.cf_se01;
    decoder.cf_off_se01 = tables.cf_off_se01;
    decoder.cf_se02 = tables.cf_se02;
    decoder.cf_off_se02 = tables.cf_off_se02;
    decoder.cf_se10 = tables.cf_se10;
    decoder.cf_off_se10 = tables.cf_off_se10;
    decoder.cf_se11 = tables.cf_se11;
    decoder.cf_off_se11 = tables.cf_off_se11;
}

/// A state load does not restore the ROM window tables `init_TCX_config` selects from the window
/// lengths; select them the way it does.
fn reselect_windows(st: &mut DecoderState) {
    let cfg = &mut st.tcx_cfg;
    let pick = |length: i16| get_sine_window_table(length).unwrap();
    cfg.tcx_mdct_window = pick(cfg.tcx_mdct_window_length);
    cfg.tcx_mdct_window_half = pick(cfg.tcx_mdct_window_half_length);
    cfg.tcx_mdct_window_minimum = pick(cfg.tcx_mdct_window_min_length);
    cfg.tcx_mdct_window_trans = pick(cfg.tcx_mdct_window_trans_length);
    cfg.tcx_mdct_window_fb = pick(cfg.tcx_mdct_window_length_fb);
    cfg.tcx_mdct_window_half_fb = pick(cfg.tcx_mdct_window_half_length_fb);
    cfg.tcx_mdct_window_minimum_fb = pick(cfg.tcx_mdct_window_min_length_fb);
    cfg.tcx_mdct_window_trans_fb = pick(cfg.tcx_mdct_window_trans_length_fb);
}

#[test]
fn mode_switch_decoder_lpd_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized(MODULE, "mode_switch_decoder_LPD", 400) else {
        return;
    };
    let (mut reopened, mut kept) = (0, 0);
    for (index, case) in cases.iter().enumerate() {
        let mut st = decoder_before(case);
        reselect_windows(&mut st);
        select_igf_tables(&mut st, case);
        let fscale_before = st.fscale;
        mode_switch_decoder_lpd(&mut st, case.i16("bw"), case.i32("rate"), case.i16("index"));
        if st.fscale == fscale_before && st.fscale_old == fscale_before {
            kept += 1;
        } else {
            reopened += 1;
        }
        let context = format!("mode_switch_decoder_LPD case {index}");
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
    assert!(
        reopened > 50 && kept > 50,
        "reopened {reopened}, kept {kept}"
    );
}

#[test]
fn reconfig_decoder_lpd_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized(MODULE, "reconfig_decoder_LPD", 400) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = decoder_before(case);
        reselect_windows(&mut st);
        select_igf_tables(&mut st, case);
        reconfig_decoder_lpd(
            &mut st,
            case.i16("bits_frame"),
            case.i16("bw"),
            case.i32("rate"),
            case.i16("l_frame_old"),
        );
        let context = format!("reconfig_decoder_LPD case {index}");
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
}
