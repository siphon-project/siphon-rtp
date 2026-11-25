//! The MODE2 frame decoder's entry (TS 26.442 `lib_dec/dec_acelp_tcx_main.c`).
//!
//! `Overflow` and `Carry`: nothing in this file reads them.

use crate::evs::cnst::{
    ACELP_13K20, ACELP_16K40, ACELP_9K60, ACELP_CORE, ACTIVE_FRAME, FB, FD_CNG, FRAME_NO_DATA,
    FRAME_SIZE_NB, INACTIVE, L_FRAME, L_FRAME16K, L_FRAME32K, MODE1, MODE2, NB, NL_BUFF_OFFSET,
    PIT16K_MAX, RF_TCXFD, RF_TCXTD2, SID_2K40, SID_FRAME, SWB, ZERO_FRAME,
};
use crate::evs::com::bitstream::{get_next_indice, get_next_indice_tmp};
use crate::evs::com::cldfb::{cldfb_get_num_channels, resample_cldfb};
use crate::evs::com::core_com_config::get_num_tcx_coded_lines;
use crate::evs::com::lerp::lerp_in_place;
use crate::evs::com::swb_tbe_com::{get_tbe_bits, non_linearity};
use crate::evs::dec::core_dec_switch::mode_switch_decoder_lpd;
use crate::evs::dec::dec_lpd::{decoder_lpd, PARAM_LPC_AT};
use crate::evs::dec::fd_cng_dec::configure_fd_cng_dec;
use crate::evs::dec::fd_cng_dec::fd_cng_decode_sid;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::swb_tbe_dec::tbe_read_bitstream;
use crate::evs::rom::FRAMESIZECONFIG;
use crate::itu::basic_ops::{add, extract_l, l_shr, l_sub, mult_r, shl, sub};

/// `DEC_NO_FRAM_LOSS` of the `DEC_MODE` enum (`lib_dec/stat_dec_fx.h`).
pub const DEC_NO_FRAM_LOSS: i16 = 0;
/// `DEC_CONCEALMENT_EXT` of the `DEC_MODE` enum.
pub const DEC_CONCEALMENT_EXT: i16 = 1;

/// `DEC_NPRM_DIV * NB_DIV + NPRM_LPC_NEW`: the parameter words of a frame.
const PARAM_LEN: usize = PARAM_LPC_AT + 136;
/// `old_bwe_exc[(PIT16k_MAX + (L_FRAME16k + 1) + L_SUBFR16k) * 2]`.
const OLD_BWE_EXC_LEN: usize = 1380;
use crate::itu::stl2009::{i_mult, l_mult0, mpy_32_16_ss};

/// The first index of `FrameSizeConfig` whose `frame_bits` is `num_bits`.
fn frame_size_index_of(num_bits: i16) -> Option<i16> {
    (0..FRAME_SIZE_NB).find(|&n| sub(FRAMESIZECONFIG[n as usize].frame_bits, num_bits) == 0)
}

/// `total_brate / 50`, the frame size in bits (`Mpy_32_16_ss(.., 5243, ..)` then `>> 3`).
fn num_bits_of(total_brate: i32) -> i16 {
    // 5243 is 1/50 in Q18. (0+18-15=3)
    let (l_tmp, _lsb) = mpy_32_16_ss(total_brate, 5243);
    // Q0
    extract_l(l_shr(l_tmp, 3))
}

/// `decode_frame_type`: read the frame type of a MODE2 frame from the bit stream and the bit rate:
/// ZERO (no data), SID (comfort noise type, bandwidth and frame length from the SID header) or
/// ACTIVE (bandwidth and the reserved bit), set `bwidth`, `total_brate`, `L_frame`, `m_frame_type`
/// and `BER_detect` accordingly, and, on a bit rate / bandwidth / codec-mode / RF change (unless
/// the frame is corrupt), reconfigure the core (`mode_switch_decoder_LPD`), the CLDFB banks, the
/// synthesis bank's zeroed bands and the FD-CNG, and resample their memories.
// the reference is one function
#[allow(clippy::too_many_lines)]
pub fn decode_frame_type(st: &mut DecoderState) {
    let mut frame_size_index: i16 = 0;
    let total_brate = st.total_brate;
    let mut num_bits = num_bits_of(st.total_brate);

    // Get Frame Type (NULL,SID,ACTIVE) and Frame Mode (2kbps, 4kbps,...)

    if sub(st.mdct_sw, MODE1) == 0 {
        st.m_frame_type = ACTIVE_FRAME;

        frame_size_index = frame_size_index_of(num_bits).unwrap_or(frame_size_index);
    } else if l_sub(st.total_brate, i32::from(FRAME_NO_DATA)) == 0 {
        // ZERO Frame
        st.bwidth = st.last_bwidth;
        st.m_frame_type = ZERO_FRAME;
    } else if l_sub(st.total_brate, i32::from(SID_2K40)) == 0 {
        // SID frame
        st.cng_type = get_next_indice(st, 1) as i16;
        if sub(st.cng_type, FD_CNG) != 0 {
            st.ber_detect = 1;
        }
        st.m_frame_type = SID_FRAME;
        frame_size_index = 1;
        st.bwidth = get_next_indice(st, 2) as i16;

        let mut frame_len_indicator = get_next_indice(st, 1) as i16;
        if sub(st.bwidth, NB) == 0 {
            if frame_len_indicator != 0 {
                st.ber_detect = 1;
            }
            frame_len_indicator = 0;
        }
        if frame_len_indicator == 0 {
            st.l_frame = L_FRAME;
            st.total_brate = 9600;
        } else {
            st.l_frame = L_FRAME16K;
            if st.last_total_brate == 16400 || st.last_total_brate == 24400 {
                st.total_brate = st.last_total_brate;
            } else {
                st.total_brate = 16400;
            }
        }

        num_bits = num_bits_of(st.total_brate);
        frame_size_index = frame_size_index_of(num_bits).unwrap_or(frame_size_index);
    } else {
        // EVS MODES: Get Frame mode
        st.m_frame_type = ACTIVE_FRAME;

        frame_size_index = frame_size_index_of(num_bits).unwrap_or(frame_size_index);
        let config = &FRAMESIZECONFIG[frame_size_index as usize];

        if st.rf_flag == 0 {
            // Get bandwidth mode
            st.bwidth = get_next_indice(st, i16::from(config.bandwidth_bits)) as i16;

            st.bwidth = add(st.bwidth, i16::from(config.bandwidth_min));
        } else {
            st.bwidth = st.bwidth.wrapping_add(i16::from(config.bandwidth_min));
        }

        if sub(st.bwidth, FB) > 0 {
            st.bwidth = FB;
            st.ber_detect = 1;
        }

        if sub(st.bwidth, SWB) > 0 && l_sub(st.total_brate, i32::from(ACELP_16K40)) < 0 {
            st.bwidth = SWB;
            st.ber_detect = 1;
        }

        // Get reserved bits
        if config.reserved_bits != 0 && st.rf_flag == 0 {
            let dummy_bit = i16::from(get_next_indice(st, 1) as i8);
            if dummy_bit != 0 {
                st.ber_detect = 1;
            }
        }
    }

    st.rate_switching_init = 0;
    if st.last_codec_mode != MODE2 || st.ber_detect == 0 {
        // Mode or Rate Change
        if (sub(st.m_frame_type, ACTIVE_FRAME) == 0 || sub(st.m_frame_type, SID_FRAME) == 0)
            && (l_sub(st.total_brate, st.last_total_brate) != 0
                || sub(st.bwidth, st.last_bwidth) != 0
                || sub(st.last_codec_mode, MODE1) == 0
                || sub(st.rf_flag, st.rf_flag_last) != 0
                || st.force_lpd_reset != 0)
        {
            st.rate_switching_init = 1;

            decode_frame_type_reconfigure(st, frame_size_index);
        }
    }

    st.total_brate = total_brate;
}

/// The "Reconf Core" half of `decode_frame_type`: the core, the CLDFB banks (resampled when the
/// frame length changed), the zeroed bands of the synthesis bank, FD-CNG and its overlap buffers.
fn decode_frame_type_reconfigure(st: &mut DecoderState, frame_size_index: i16) {
    // Reconf Core
    let (bwidth, total_brate) = (st.bwidth, st.total_brate);
    mode_switch_decoder_lpd(st, bwidth, total_brate, frame_size_index);

    // Reconf CLDFB
    let l_frame = st.l_frame;
    let analysis_geometry = st
        .cldfb_ana
        .as_ref()
        .map(|bank| i_mult(bank.no_channels, bank.no_col));
    if analysis_geometry.is_some_and(|samples| sub(samples, l_frame) != 0) {
        let new_cldfb_bands = cldfb_get_num_channels(l_mult0(l_frame, 50));

        if let Some(bank) = st.cldfb_ana.as_deref_mut() {
            resample_cldfb(bank, new_cldfb_bands, l_frame, 0);
        }
        if sub(l_frame, L_FRAME16K) <= 0 {
            if let Some(bank) = st.cldfb_bpf.as_deref_mut() {
                resample_cldfb(bank, new_cldfb_bands, l_frame, 0);
            }
        }
    }
    if let Some(bank) = st.cldfb_syn.as_deref_mut() {
        if sub(st.bwidth, NB) == 0 {
            bank.bands_to_zero = sub(bank.no_channels, 10);
        } else {
            bank.bands_to_zero = 0;
        }
    }

    // Reconf FD-CNG
    let mut l_tmp = st.total_brate;
    if sub(st.rf_flag, 1) == 0 && l_sub(st.total_brate, i32::from(ACELP_13K20)) == 0 {
        l_tmp = i32::from(ACELP_9K60);
    }
    let (bwidth, last_l_frame, m_frame_type) = (st.bwidth, st.last_l_frame, st.m_frame_type);
    if let Some(dec) = st.h_fd_cng_dec.as_deref_mut() {
        configure_fd_cng_dec(dec, bwidth, l_tmp, l_frame);
        if sub(last_l_frame, l_frame) != 0 && sub(l_frame, 320) <= 0 && sub(last_l_frame, 320) <= 0
        {
            lerp_in_place(
                &mut dec.olap_buffer_synth2,
                l_frame.wrapping_mul(2),
                last_l_frame.wrapping_mul(2),
            );
            let previous_type = dec
                .h_fd_cng_com
                .as_deref()
                .map(|com| com.frame_type_previous);
            if sub(m_frame_type, SID_FRAME) == 0
                && previous_type.is_some_and(|previous| sub(previous, ACTIVE_FRAME) != 0)
            {
                if let Some(com) = dec.h_fd_cng_com.as_deref_mut() {
                    lerp_in_place(
                        &mut com.olap_buffer_synth,
                        l_frame.wrapping_mul(2),
                        last_l_frame.wrapping_mul(2),
                    );

                    let count = (i32::from(l_frame) * 2) as usize;
                    if sub(l_frame, L_FRAME) == 0 {
                        for sample in &mut com.olap_buffer_synth[..count] {
                            *sample = mult_r(*sample, 20480);
                        }
                    } else {
                        for sample in &mut com.olap_buffer_synth[..count] {
                            *sample = mult_r(shl(*sample, 1), 26214);
                        }
                    }
                }
            }
        }
    }
    if sub(st.bwidth, st.last_bwidth) != 0 {
        if let Some(com) = st
            .h_fd_cng_dec
            .as_deref_mut()
            .and_then(|dec| dec.h_fd_cng_com.as_deref_mut())
        {
            com.ms_fr_cnt_init_counter = 0;
            com.init_old = 32767;
        }
    }

    // Reconf BPF
    st.p_bpf_noise_buf = None;
    if st.tcxonly == 0 {
        st.p_bpf_noise_buf = Some(0);
    }
}

/// `dec_acelp_tcx_frame`: decode (or conceal, `conceal_whole_frame != 0`) one MODE2 frame: its
/// frame type, then, for an active frame, the LPD core (`decoder_LPD`) with the bandwidth
/// extension inputs of an ACELP frame, or, for a SID / no-data frame, the SID parameters.
///
/// `pcm_buf` receives the core-rate synthesis, `pcm_buf_fb` the output-rate one,
/// `bwe_exc_extended` the SHB excitation, `voice_factors` and `pitch_buf` the ACELP outputs.
// the reference's one function
#[allow(clippy::too_many_lines)]
pub fn dec_acelp_tcx_frame(
    st: &mut DecoderState,
    coder_type: &mut i16,
    conceal_whole_frame: &mut i16,
    pcm_buf: &mut [i16],
    pcm_buf_fb: &mut [i16],
    bwe_exc_extended: &mut [i32],
    voice_factors: &mut [i16],
    pitch_buf: &mut [i16],
) {
    let num_bits = num_bits_of(st.total_brate);
    let mut param = [0i16; PARAM_LEN];
    let mut old_bwe_exc = [0i16; OLD_BWE_EXC_LEN];

    // Set the bit-stream
    let mut start_bit_pos = st.next_bit_pos;
    if sub(st.rf_flag, 1) == 0 {
        start_bit_pos = sub(start_bit_pos, 2);
    }

    // IDENTIFY FRAME TYPE
    st.m_old_frame_type = st.m_frame_type;

    if *conceal_whole_frame == 0 {
        let m_frame_type = st.m_frame_type;
        let bwidth = st.bwidth;
        let cng_type = st.cng_type;
        let l_frame = st.l_frame;
        let total_brate = st.last_total_brate;

        decode_frame_type(st);

        st.force_lpd_reset = 0;

        if sub(st.last_codec_mode, MODE2) == 0
            && (st.ber_detect != 0
                || (st.prev_bfi != 0
                    && sub(st.m_frame_type, ZERO_FRAME) == 0
                    && sub(st.m_old_frame_type, ACTIVE_FRAME) == 0))
        {
            // Copy back parameters from previous frame, because there is a high risk they are
            // corrupt. Do concealment with the configuration used in the previous frame
            st.m_frame_type = m_frame_type;
            st.bwidth = bwidth;
            st.cng_type = cng_type;
            st.l_frame = l_frame;
            if st.ini_frame != 0 {
                st.total_brate = total_brate;
            }

            *conceal_whole_frame = 1;
            st.m_decode_mode = DEC_CONCEALMENT_EXT;
            st.ber_detect = 0;

            if sub(st.bwidth, st.last_bwidth) != 0
                || sub(st.rf_flag, st.rf_flag_last) != 0
                || l_sub(st.total_brate, st.last_total_brate) != 0
            {
                st.force_lpd_reset = 1;
            }

            st.core_brate = st.last_core_brate;
            st.bfi = 1;
            if st.ini_frame == 0 {
                st.tcx_cfg.tcx_coded_lines = get_num_tcx_coded_lines(SWB);
            }
        } else {
            st.core_brate = st.total_brate;
        }
    }

    if *conceal_whole_frame != 0 {
        // add two zero bytes for arithmetic coder flush
        st.bit_stream[..8 * 2].fill(0);
    }

    if sub(st.m_frame_type, SID_FRAME) != 0 && sub(st.m_frame_type, ZERO_FRAME) != 0 {
        // DECODE CORE
        let tmp = sub(num_bits, sub(st.next_bit_pos, start_bit_pos));
        let mut bits_read: i16 = 0;

        // `old_bwe_exc` is zero from `PIT16k_MAX * 2` on, and carries the past excitation before
        let bwe_exc_at = PIT16K_MAX as usize * 2;
        old_bwe_exc[..bwe_exc_at].copy_from_slice(&st.old_bwe_exc[..bwe_exc_at]);

        if sub(st.m_decode_mode, DEC_NO_FRAM_LOSS) == 0 {
            decoder_lpd(
                pcm_buf,
                pcm_buf_fb,
                tmp,
                st,
                0,
                &mut bits_read,
                coder_type,
                &mut param,
                pitch_buf,
                voice_factors,
                &mut old_bwe_exc,
                bwe_exc_at,
            );

            if st.rate_switching_init == 0
                && sub(st.last_codec_mode, MODE2) == 0
                && !(st.use_partial_copy != 0
                    && sub(st.rf_frame_type, RF_TCXFD) >= 0
                    && sub(st.rf_frame_type, RF_TCXTD2) <= 0)
                && sub(st.bfi, 1) == 0
            {
                *conceal_whole_frame = 1;
                st.m_decode_mode = DEC_CONCEALMENT_EXT;
                st.ber_detect = 0;
            }
        } else if sub(st.m_decode_mode, DEC_CONCEALMENT_EXT) == 0 {
            // Decode the LPD data
            decoder_lpd(
                pcm_buf,
                pcm_buf_fb,
                0,
                st,
                1,
                &mut bits_read,
                coder_type,
                &mut param,
                pitch_buf,
                voice_factors,
                &mut old_bwe_exc,
                bwe_exc_at,
            );
        }

        if (st.bfi == 0 && (sub(st.prev_bfi, 1) == 0 || sub(st.prev_use_partial_copy, 1) == 0))
            || (sub(st.last_vbr_hw_bwe_disable_dec, 1) == 0 && st.vbr_hw_bwe_disable_dec == 0)
        {
            st.bwe_non_lin_prev_scale = 0;
            st.old_bwe_exc_extended[..NL_BUFF_OFFSET as usize].fill(0);
        }

        if sub(st.core, ACELP_CORE) == 0 && st.igf != 0 && st.con_tcx == 0 {
            non_linearity(
                &old_bwe_exc[bwe_exc_at..],
                bwe_exc_extended,
                L_FRAME32K,
                &mut st.bwe_non_lin_prev_scale,
                st.q_exc,
                *coder_type,
                voice_factors,
                st.l_frame,
            );

            // update the old BWE exe memory
            st.old_bwe_exc[..bwe_exc_at].copy_from_slice(
                &old_bwe_exc[L_FRAME32K as usize..L_FRAME32K as usize + bwe_exc_at],
            );
        } else {
            st.old_bwe_exc_extended[..NL_BUFF_OFFSET as usize].fill(0);
            st.old_bwe_exc[..bwe_exc_at].fill(0);
            st.bwe_non_lin_prev_scale = 0;
        }

        // for ACELP mode, skip core data to read TD-BWE side info
        if st.bfi == 0 && sub(st.core, ACELP_CORE) == 0 && st.total_brate > 0 {
            // target bs-position "-3": -2 as earlier "start_bit_pos -= 2;" are included in
            // st->rf_target_bits, -1 as flag-bit not considered in rf_target_bits
            let tbe_bits = get_tbe_bits(st.total_brate, st.bwidth, st.rf_flag);
            let skip = if sub(st.rf_flag, 1) == 0 {
                start_bit_pos + num_bits - st.rf_target_bits - 3 - tbe_bits - st.next_bit_pos
            } else {
                start_bit_pos + num_bits - st.rf_target_bits - tbe_bits - st.next_bit_pos
            };
            get_next_indice_tmp(st, skip);
            tbe_read_bitstream(st);
        }

        // updates
        st.last_voice_factor = voice_factors[st.nb_subfr.max(1) as usize - 1];
        st.last_coder_type = *coder_type;
    } else {
        if sub(st.m_frame_type, SID_FRAME) == 0 {
            fd_cng_decode_sid(st);
        }

        // updates
        st.last_voice_factor = 0;
        st.last_coder_type = INACTIVE;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_parameter_buffer_holds_the_lpc_indices_after_the_core_ones() {
        assert_eq!(PARAM_LEN, 2 * 729 + 136);
        assert_eq!(OLD_BWE_EXC_LEN, (289 + 321 + 80) * 2);
    }

    #[test]
    fn a_frame_size_in_bits_is_the_bit_rate_over_fifty() {
        assert_eq!(num_bits_of(13200), 264);
        assert_eq!(num_bits_of(24400), 488);
        assert_eq!(num_bits_of(9600), 192);
    }
}
