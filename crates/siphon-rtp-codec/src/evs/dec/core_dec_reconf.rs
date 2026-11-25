//! Reconfiguration of the MODE2 decoder core for a new frame size / rate (TS 26.442
//! `lib_dec/core_dec_reconf.c`; TS 26.445 §5.3 / §6.1).
//!
//! `Overflow` and `Carry`: nothing in this file reads them.

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    ACELP_CORE, FORMANT_SHARPENING_G1, FORMANT_SHARPENING_G2, LOWRATE_TCXLPC_MAX_BR, L_FRAME16K,
    L_SYN_MEM_CLAS_ESTIM, MODE1, SWB,
};
use crate::evs::com::bits_alloc::bits_alloc_init_config_acelp;
use crate::evs::com::core_com_config::{get_cna_present, get_tcx_ltp};
use crate::evs::com::lerp::{lerp_in_place, lerp_within};
use crate::evs::com::tcx_utils::get_inv_frame_len;
use crate::evs::com::tools::set16;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::SCALETCXTABLE;
use crate::itu::basic_ops::{extract_l, l_shr, l_sub, shr, sub};
use crate::itu::stl2009::l_mult0;

/// `reconfig_decoder_LPD`: set the frame size `bits_frame`, the ACELP configuration (and the
/// partial-copy one), the CNA / TCX-LTP switches and the non-active TCX scale for `bitrate` and
/// `bandwidth_mode`, and, after the first frame, resample the overlap and classifier memories
/// from the previous frame length `l_frame_old` to the new one.
pub fn reconfig_decoder_lpd(
    st: &mut DecoderState,
    bits_frame: i16,
    bandwidth_mode: i16,
    bitrate: i32,
    l_frame_old: i16,
) {
    st.bits_frame = bits_frame;

    if bandwidth_mode == 0 {
        st.narrow_band = 1;
    } else if bandwidth_mode > 0 {
        st.narrow_band = 0;
    }

    bits_alloc_init_config_acelp(bitrate, st.narrow_band, st.nb_subfr, &mut st.acelp_cfg);

    // Configuration of partial copy
    st.acelp_cfg_rf.mode_index = 1;
    st.acelp_cfg_rf.mid_lpc = 0;
    st.acelp_cfg_rf.mid_lpc_enable = 0;
    st.acelp_cfg_rf.pre_emphasis = 0;
    st.acelp_cfg_rf.formant_enh = 1;
    st.acelp_cfg_rf.formant_tilt = 1;
    st.acelp_cfg_rf.voice_tilt = 1;
    st.acelp_cfg_rf.formant_enh_num = FORMANT_SHARPENING_G1;
    st.acelp_cfg_rf.formant_enh_den = FORMANT_SHARPENING_G2;

    st.flag_cna = get_cna_present(bitrate, bandwidth_mode);

    // TCX-LTP
    st.tcxltp = get_tcx_ltp(st.sr_core);

    reconfig_decoder_lpd_na_scale(st, bandwidth_mode, bitrate);

    // if its not the first frame resample overlap buffer to new sampling rate
    if st.ini_frame != 0 {
        reconfig_decoder_lpd_resample(st, l_frame_old);
    }

    st.enable_tcx_lpc = i8::from(
        st.numlpc == 1
            && st.lpc_quantization == 1
            && (bitrate <= i32::from(LOWRATE_TCXLPC_MAX_BR) || st.rf_flag != 0),
    );

    if st.ini_frame == 0 {
        st.env_weighted = 0;
    }
}

/// The non-active TCX scale of `reconfig_decoder_LPD`: unity, or `scaleTcxTable`'s entry of the
/// bandwidth and bit-rate range below SWB (the previous range under RF, whose rate starts a range).
fn reconfig_decoder_lpd_na_scale(st: &mut DecoderState, bandwidth_mode: i16, bitrate: i32) {
    // Scale TCX for non-active frames to adjust loudness with ACELP
    st.tcx_cfg.na_scale = 32767;

    if sub(bandwidth_mode, SWB) < 0 && st.tcxonly == 0 {
        for (index, entry) in SCALETCXTABLE.iter().enumerate() {
            if sub(bandwidth_mode, entry.bwmode) == 0
                && l_sub(bitrate, entry.bitrate_from) >= 0
                && l_sub(bitrate, entry.bitrate_to) < 0
            {
                // `i--` of the reference; RF runs only at 13.2 kbit/s, which no first entry starts,
                // so `index` is never 0 here
                let index = if st.rf_flag != 0 {
                    index.saturating_sub(1)
                } else {
                    index
                };
                st.tcx_cfg.na_scale = SCALETCXTABLE[index].scale;
                break;
            }
        }
    }
}

/// The resampling half of `reconfig_decoder_LPD` (frames after the first): the overlap buffers
/// (`old_syn_Overl`, `syn_Overl`, `syn_Overl_TDAC`) when the core rate changed, and the classifier
/// memory `mem_syn_clas_estim` when the frame length did.
fn reconfig_decoder_lpd_resample(st: &mut DecoderState, l_frame_old: i16) {
    // no resempling is needed here when recovering from mode 1 acelp plc, since the buffers are
    // already sampled with the correct sampling rate in open_decoder_LPD()
    if sub(st.fscale, st.fscale_old) != 0
        && !(st.last_codec_mode == MODE1 && st.last_core == ACELP_CORE && st.prev_bfi != 0)
    {
        let mut new_len = st.tcx_cfg.tcx_mdct_window_length;
        let mut old_len = st.tcx_cfg.tcx_mdct_window_length_old;

        if (st.prev_bfi != 0 && sub(st.last_core_bfi, ACELP_CORE) == 0)
            || sub(st.last_core, ACELP_CORE) == 0
        {
            new_len = shr(st.l_frame, 1);
            old_len = shr(l_frame_old, 1);
        }

        lerp_in_place(&mut st.old_syn_overl, new_len, old_len);
        lerp_in_place(&mut st.syn_overl, new_len, old_len);

        if st.prev_bfi != 0 && sub(st.last_core_bfi, ACELP_CORE) == 0 {
            lerp_in_place(&mut st.syn_overl_tdac, new_len, old_len);
        }
    }

    if sub(st.l_frame, L_FRAME16K) <= 0 {
        if sub(st.last_l_frame, L_FRAME16K) <= 0 {
            if sub(st.l_frame, st.last_l_frame) != 0 {
                let (old_len_clas_buff, new_len_clas_buff);
                if sub(st.l_frame, st.last_l_frame) > 0 {
                    // Q21 -> Q6 -> Q0
                    old_len_clas_buff = extract_l(l_shr(
                        mpy_32_16_1(
                            l_mult0(st.last_l_frame, get_inv_frame_len(st.l_frame)),
                            L_SYN_MEM_CLAS_ESTIM,
                        ),
                        6,
                    ));
                    new_len_clas_buff = L_SYN_MEM_CLAS_ESTIM;
                } else {
                    old_len_clas_buff = L_SYN_MEM_CLAS_ESTIM;
                    new_len_clas_buff = extract_l(l_shr(
                        mpy_32_16_1(
                            l_mult0(st.l_frame, get_inv_frame_len(st.last_l_frame)),
                            L_SYN_MEM_CLAS_ESTIM,
                        ),
                        6,
                    ));
                }
                lerp_within(
                    &mut st.mem_syn_clas_estim,
                    (L_SYN_MEM_CLAS_ESTIM - old_len_clas_buff) as usize,
                    (L_SYN_MEM_CLAS_ESTIM - new_len_clas_buff) as usize,
                    new_len_clas_buff,
                    old_len_clas_buff,
                );
            }
        } else {
            set16(&mut st.mem_syn_clas_estim, 0, L_SYN_MEM_CLAS_ESTIM);
            st.classifier_q_mem_syn = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_frame_clears_the_envelope_weighting_and_sets_the_frame_size() {
        let mut st = DecoderState::zeroed();
        st.env_weighted = 1;
        st.nb_subfr = 4;
        st.ini_frame = 0;
        reconfig_decoder_lpd(&mut st, 480, 2, 24400, 256);
        assert_eq!(
            (st.bits_frame, st.env_weighted, st.narrow_band),
            (480, 0, 0)
        );
        assert_eq!(st.tcx_cfg.na_scale, 32767);
    }

    #[test]
    fn narrowband_mode_selects_the_first_tcx_scale_of_its_range() {
        let mut st = DecoderState::zeroed();
        st.nb_subfr = 4;
        reconfig_decoder_lpd(&mut st, 192, 0, 9600, 256);
        assert_eq!(st.narrow_band, 1);
        assert_eq!(st.tcx_cfg.na_scale, 24904);
    }
}
