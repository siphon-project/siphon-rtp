//! Switching the MODE2 decoder core to a new bit rate / bandwidth (TS 26.442
//! `lib_dec/core_dec_switch.c`; TS 26.445 §5.3 / §6.1).
//!
//! `Overflow` and `Carry`: nothing in this file reads them.

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    ACELP_16K40, ACELP_24K40, ACELP_32K, AMR_WB_CORE, FB, FB_TBE, FSCALE_DENOM, LPC_SHB_ORDER,
    L_FRAME16K, L_SHB_LAHEAD, M, MAX_TEC_SMOOTHING_DEG, MODE1, NB, SWB, SWB_TBE, WB, WB_TBE,
};
use crate::evs::com::core_com_config::{
    get_core_samplerate_mode2, get_ctx_hm, get_igf_present, get_num_tcx_coded_lines, get_resq,
    get_tcx_bandwidth, get_tcx_lpc_shaped_ari, get_tns_allowed, sr2fscale,
};
use crate::evs::com::lsf_tools::{e_lpc_lsp_lsf_conversion, lsp2lsf};
use crate::evs::com::tcx_utils::init_tns_configs;
use crate::evs::com::tools::set16;
use crate::evs::dec::core_dec_init::open_decoder_lpd;
use crate::evs::dec::core_dec_reconf::reconfig_decoder_lpd;
use crate::evs::dec::igf_dec::igf_dec_set_mode;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::swb_tbe_dec::tbe_reset_dec;
use crate::evs::rom::{BWMODE2FS, FRAMESIZECONFIG};
use crate::itu::basic_ops::{extract_l, l_sub, sub};

/// `mode_switch_decoder_LPD`: reconfigure the LPD core of `st` for `bitrate` and the coded
/// `bandwidth` of a frame of size `frame_size_index` (an index into `FrameSizeConfig`): the core
/// sampling rate and TCX configuration (a full `open_decoder_LPD` when the core rate changes, the
/// codec comes from MODE1 or AMR-WB IO, or a reset is forced), IGF, the TBE / TEC / TFA and PLC
/// switches, and the bit-stream reading flags (`enableGplc`, `dec_glr`).
// the reference is one function
#[allow(clippy::too_many_lines)]
pub fn mode_switch_decoder_lpd(
    st: &mut DecoderState,
    bandwidth: i16,
    bitrate: i32,
    frame_size_index: i16,
) {
    let mut switch_wb: i16 = 0;
    let mut b_switch_from_amrwb_io: i8 = 0;

    if sub(st.last_core, AMR_WB_CORE) == 0 {
        b_switch_from_amrwb_io = 1;
    }

    let sr_core = get_core_samplerate_mode2(bitrate, bandwidth, st.rf_flag);

    let fscale = sr2fscale(sr_core);

    // set number of coded lines
    st.tcx_cfg.tcx_coded_lines = get_num_tcx_coded_lines(bandwidth);

    if sub(bandwidth, WB) >= 0
        && sub(fscale, ((i32::from(FSCALE_DENOM) * 16000) / 12800) as i16) == 0
        && sub(fscale, st.fscale) == 0
        && ((l_sub(bitrate, 32000) > 0 && st.tcxonly == 0)
            || (l_sub(bitrate, 32000) <= 0 && st.tcxonly != 0))
    {
        switch_wb = 1;
    }

    if sub(st.last_l_frame, L_FRAME16K) > 0 && l_sub(st.total_brate, i32::from(ACELP_32K)) <= 0 {
        switch_wb = 1;
    }

    st.igf = i16::from(get_igf_present(bitrate, bandwidth, st.rf_flag));

    st.h_igf_dec.info_igf_stop_freq = -1;
    if st.igf != 0 {
        // switch IGF configuration
        igf_dec_set_mode(
            &mut st.h_igf_dec,
            st.total_brate,
            bandwidth,
            -1,
            -1,
            st.rf_flag,
        );
    }

    if sub(fscale, st.fscale) != 0
        || switch_wb != 0
        || b_switch_from_amrwb_io != 0
        || sub(st.last_codec_mode, MODE1) == 0
        || st.force_lpd_reset != 0
    {
        open_decoder_lpd(st, bitrate, bandwidth);
    } else {
        mode_switch_decoder_lpd_keep_core(st, fscale, bandwidth, bitrate);
    }

    let frame_size = FRAMESIZECONFIG[frame_size_index as usize].frame_net_bits;

    let last_l_frame = st.last_l_frame;
    reconfig_decoder_lpd(st, frame_size, bandwidth, bitrate, last_l_frame);

    if st.env_weighted != 0 && st.enable_tcx_lpc == 0 {
        st.lsp_old = st.lspold_uw;
        st.lsf_old = st.lsfold_uw;
        st.env_weighted = 0;
    }

    // update PLC LSF memories
    if st.tcxonly == 0 {
        lsp2lsf(
            &st.lsp_old,
            &mut st.lsfoldbfi1,
            M,
            i32::from(extract_l(st.sr_core)),
        );
    } else {
        e_lpc_lsp_lsf_conversion(&st.lsp_old, &mut st.lsfoldbfi1, M);
    }
    st.lsfoldbfi0 = st.lsfoldbfi1;
    st.lsf_adaptive_mean = st.lsfoldbfi1;

    if st.igf != 0 {
        if (sub(st.bwidth, WB) == 0 && sub(st.last_extl, WB_TBE) != 0)
            || (sub(st.bwidth, SWB) == 0 && sub(st.last_extl, SWB_TBE) != 0)
            || (sub(st.bwidth, FB) == 0 && sub(st.last_extl, FB_TBE) != 0)
        {
            let bwidth = st.bwidth;
            tbe_reset_dec(st, bwidth);
        } else {
            set16(&mut st.state_lpc_syn, 0, LPC_SHB_ORDER);
            set16(&mut st.state_syn_shbexc, 0, L_SHB_LAHEAD);
            set16(&mut st.mem_stp_swb, 0, LPC_SHB_ORDER);
            set16(&mut st.mem_zero_swb, 0, LPC_SHB_ORDER);
            // Q14 = 1
            st.gain_prec_swb = 16384;
        }
    }

    if sub(bandwidth, SWB) == 0
        && (l_sub(st.total_brate, i32::from(ACELP_16K40)) == 0
            || l_sub(st.total_brate, i32::from(ACELP_24K40)) == 0)
    {
        if st.tec_tfa == 0 {
            set16(&mut st.tec_dec.lo_buffer, 0, MAX_TEC_SMOOTHING_DEG);
        }
        st.tec_tfa = 1;
    } else {
        st.tec_tfa = 0;
    }

    st.tec_flag = 0;
    st.tfa_flag = 0;

    // needed in decoder to read the bitstream
    st.enable_gplc = 0;
    if (sub(bandwidth, WB) == 0 && l_sub(bitrate, 24400) == 0)
        || (sub(bandwidth, SWB) == 0 && l_sub(bitrate, 24400) == 0)
        || (sub(bandwidth, FB) == 0 && l_sub(bitrate, 24400) == 0)
    {
        st.enable_gplc = 1;
    }
    st.dec_glr = 0;
    if l_sub(st.total_brate, 9600) == 0
        || l_sub(st.total_brate, 16400) == 0
        || l_sub(st.total_brate, 24400) == 0
    {
        st.dec_glr = 1;
    }
    st.dec_glr_idx = 0;
}

/// The `else` branch of `mode_switch_decoder_LPD`'s core test: the core sampling rate class stays,
/// so the configuration that depends on the rate and bandwidth is updated in place.
fn mode_switch_decoder_lpd_keep_core(
    st: &mut DecoderState,
    fscale: i16,
    bandwidth: i16,
    bitrate: i32,
) {
    st.fscale_old = st.fscale;
    st.fscale = fscale;
    st.l_frame = extract_l(mult_32_16(st.sr_core, 0x0290));
    st.l_frame_tcx = extract_l(mult_32_16(st.output_fs, 0x0290));

    st.tcx_cfg.ctx_hm = get_ctx_hm(bitrate, st.rf_flag);
    st.tcx_cfg.resq = get_resq(bitrate);

    st.tcx_lpc_shaped_ari = get_tcx_lpc_shaped_ari(bitrate, bandwidth, st.rf_flag);

    st.narrow_band = 0;
    if sub(bandwidth, NB) == 0 {
        st.narrow_band = 1;
    }
    st.tcx_bandwidth = get_tcx_bandwidth(bandwidth);

    st.tcx_cfg.p_current_tns_config = None;
    st.tcx_cfg.f_is_tns_allowed = get_tns_allowed(bitrate, st.igf);

    if st.tcx_cfg.f_is_tns_allowed != 0 {
        init_tns_configs(
            BWMODE2FS[bandwidth as usize],
            st.tcx_cfg.tcx_coded_lines,
            &mut st.tcx_cfg.tns_config,
            st.h_igf_dec.info_igf_stop_freq,
            st.total_brate,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bit_stream_reading_flags_follow_the_bit_rate() {
        let mut st = DecoderState::zeroed();
        st.nb_subfr = 4;
        st.last_codec_mode = MODE1;
        st.total_brate = 24400;
        st.output_fs = 16000;
        mode_switch_decoder_lpd(&mut st, WB, 24400, 5);
        assert_eq!((st.enable_gplc, st.dec_glr, st.dec_glr_idx), (1, 1, 0));
        assert_eq!((st.tec_tfa, st.tec_flag, st.tfa_flag), (0, 0, 0));
    }
}
