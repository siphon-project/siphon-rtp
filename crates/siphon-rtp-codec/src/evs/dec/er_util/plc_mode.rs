//! `GetPLCModeDecision` of `lib_dec/er_util.c` (TS 26.447 §5.4.3.1): which concealment a lost
//! frame gets, ACELP-like or TCX-like, with or without the tonal MDCT concealment.

use crate::evs::cnst::{ACELP_CORE, RF_TCXTD1, RF_TCXTD2, TCX_20_CORE, UNVOICED_TRANSITION};
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::tonal_mdct_concealment::tonal_mdct_conceal_detect;
use crate::itu::basic_ops::{l_abs, l_add, l_deposit_h, l_sub, shr, sub};

/// `GetPLCModeDecision`: the core (`ACELP_CORE` or `TCX_20_CORE`) to conceal the lost frame with.
/// Updates the lag memories for a guided ACELP frame, `plc_use_future_lag`, `last_core` after
/// the first frame of a stream, and `tonal_mdct_plc_active`; for the first loss after two TCX
/// frames of stable pitch it runs the detection of the tonal components.
pub fn get_plc_mode_decision(st: &mut DecoderState) -> i16 {
    let mut num_indices: i16 = 0;

    if sub(st.flag_guided_acelp, 1) == 0 {
        let at = 2 * st.nb_subfr as usize;
        st.old_pitch_buf[at] = l_deposit_h(st.guided_t0);
        st.old_pitch_buf[at + 1] = l_deposit_h(st.guided_t0);
        st.mem_pitch_gain[0] = 16384; // 1.f Q14
        st.mem_pitch_gain[1] = 16384;
    }
    st.plc_use_future_lag = 0;
    if (st.last_core > ACELP_CORE && st.tcxltp_last_gain_unmodified != 0)
        || sub(st.flag_guided_acelp, 1) == 0
    {
        // no updates needed here, because already updated in last good frame
        st.plc_use_future_lag = 1;
    }

    let mut core: i16;
    if sub(st.last_core, -1) == 0 {
        core = TCX_20_CORE;
        st.last_core = ACELP_CORE;
        if st.opt_amr_wb != 0 {
            core = ACELP_CORE;
        }
        st.tonal_mdct_plc_active = 0;
    } else {
        core = ACELP_CORE;
        if sub(st.nb_lost_cmpt, 1) > 0 {
            core = st.last_core_bfi;
        }
        if sub(st.nb_lost_cmpt, 1) == 0 {
            st.tonal_mdct_plc_active = 0;
            if !(st.rf_flag != 0
                && st.use_partial_copy != 0
                && (sub(st.rf_frame_type, RF_TCXTD1) == 0 || sub(st.rf_frame_type, RF_TCXTD2) == 0))
            {
                if sub(st.last_core, TCX_20_CORE) == 0
                    && sub(st.second_last_core, TCX_20_CORE) == 0
                    && (l_sub(st.old_fpitch, l_deposit_h(shr(st.l_frame, 1))) <= 0
                        || sub(st.tcxltp_last_gain_unmodified, 13107) <= 0) // 0.4f Q15
                    // it is fine to call the detection even if no ltp information is available,
                    // meaning that old_fpitch == tcxltp_second_last_pitch == L_frame
                    && l_sub(st.old_fpitch, st.tcxltp_second_last_pitch) == 0
                    && st.last_tns_active == 0
                    && st.second_last_tns_active == 0
                {
                    let mut pitch = l_deposit_h(0);
                    if st.tcxltp_last_gain_unmodified > 0 {
                        pitch = l_add(st.old_fpitch, 0);
                    }
                    tonal_mdct_conceal_detect(
                        &mut st.tonal_mdc_tconceal,
                        &st.tcx_cfg,
                        pitch,
                        &mut num_indices,
                    );

                    let third_second_pitch_distance_small = l_sub(
                        l_abs(l_sub(
                            st.tcxltp_third_last_pitch,
                            st.tcxltp_second_last_pitch,
                        )),
                        32768, // 0.5f Q16
                    ) < 0;
                    if sub(num_indices, 10) > 0
                        || (sub(num_indices, 5) > 0 && third_second_pitch_distance_small)
                        || (num_indices > 0
                            && (sub(st.last_good, UNVOICED_TRANSITION) <= 0
                                || sub(st.tcxltp_last_gain_unmodified, 13107) <= 0)
                            && third_second_pitch_distance_small)
                    {
                        core = TCX_20_CORE;
                        st.tonal_mdct_plc_active = 1;
                    } else if sub(st.last_good, UNVOICED_TRANSITION) <= 0
                        || sub(st.tcxltp_last_gain_unmodified, 13107) <= 0
                    {
                        core = TCX_20_CORE;
                    }
                } else if st.last_core != ACELP_CORE
                    && (sub(st.last_good, UNVOICED_TRANSITION) <= 0
                        || sub(st.tcxltp_last_gain_unmodified, 13107) <= 0)
                {
                    core = st.last_core;
                }
            }
        }
    }
    core
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_frame_after_start_up_conceals_as_tcx_and_resets_the_core() {
        let mut st = Box::new(DecoderState::zeroed());
        st.last_core = -1;
        st.tonal_mdct_plc_active = 1;
        assert_eq!(get_plc_mode_decision(&mut st), TCX_20_CORE);
        assert_eq!(st.last_core, ACELP_CORE);
        assert_eq!(st.tonal_mdct_plc_active, 0);
        st.last_core = -1;
        st.opt_amr_wb = 1;
        assert_eq!(get_plc_mode_decision(&mut st), ACELP_CORE);
    }

    #[test]
    fn a_later_loss_keeps_the_core_of_the_first_one() {
        let mut st = Box::new(DecoderState::zeroed());
        st.last_core = TCX_20_CORE;
        st.nb_lost_cmpt = 3;
        st.last_core_bfi = TCX_20_CORE;
        assert_eq!(get_plc_mode_decision(&mut st), TCX_20_CORE);
    }

    #[test]
    fn a_guided_acelp_frame_seeds_the_lag_memory() {
        let mut st = Box::new(DecoderState::zeroed());
        st.last_core = ACELP_CORE;
        st.nb_subfr = 4;
        st.nb_lost_cmpt = 2;
        st.flag_guided_acelp = 1;
        st.guided_t0 = 77;
        assert_eq!(get_plc_mode_decision(&mut st), ACELP_CORE);
        assert_eq!(st.old_pitch_buf[8], 77 << 16);
        assert_eq!(st.old_pitch_buf[9], 77 << 16);
        assert_eq!(st.mem_pitch_gain[0], 16384);
        assert_eq!(st.plc_use_future_lag, 1);
    }
}
