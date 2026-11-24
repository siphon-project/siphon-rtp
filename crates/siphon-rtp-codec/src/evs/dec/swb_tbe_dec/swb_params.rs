//! SWB / FB TBE decoder, first half of `swb_tbe_dec_fx` (TS 26.442 `lib_dec/swb_tbe_dec_fx.c`):
//! the fractive-frame decision, the frame's LSFs / gains (decoded, partial-copy or concealed) and
//! the LPC derived from them.

use super::params::{dequantize_shb_params_9_1, gradient_gain_shape};
use crate::evs::basop::{l_extract_lc, mult_32_16};
use crate::evs::com::lsf_tools::{a2rc, e_lpc_f_lsp_a_conversion, e_lpc_lsf_lsp_conversion};
use crate::evs::com::math_op::pow2;
use crate::evs::com::swb_bwe_com::calc_tilt_bwe;
use crate::evs::com::tools::{root_a, scale_sig};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{INTERPOL_FRAC_SHB, LSF_TAB_FX};
use crate::itu::basic_ops::{
    add, div_s, extract_l, l_abs, l_add, l_mac, l_mult, l_shl, l_shr, l_sub, mult, mult_r,
    round_word, shl, shr, sub,
};
use crate::itu::stl2009::{i_mult, mac_r};

/// The SWB TBE parameters of one frame (`lsf_shb`, `GainShape`, `GainFrame`, `shb_ener_sf_32`,
/// `shb_res_gshape`, `mixFactors` of the reference).
pub(super) struct SwbParameters {
    pub lsf_shb: [i16; 10],
    pub gain_shape: [i16; 16],
    pub gain_frame: i32,
    pub shb_ener_sf_32: i32,
    pub shb_res_gshape: [i16; 5],
    pub mix_factors: i16,
}

/// The tilt of the 12.8 / 16 kHz synthesis and the fractive-frame decision: returns
/// `(is_fractive, tilt_swb_fec)`.
pub(super) fn swb_tbe_dec_fractive(st: &DecoderState, old_syn_12k8_16k: &[i16]) -> (i16, i16) {
    let mut is_fractive: i16 = 0;
    let l_tmp = calc_tilt_bwe(old_syn_12k8_16k, st.q_syn2, st.l_frame);
    let mut tilt_swb_fec = round_word(l_shl(l_tmp, 3));
    if st.bfi != 0 && sub(st.clas_dec, 0) != 0 {
        tilt_swb_fec = st.tilt_swb_fec;
    }

    if (sub(st.tilt_wb, 10240) > 0 && sub(st.clas_dec, 0) == 0) || sub(st.tilt_wb, 20480) > 0 {
        if (st.prev_fractive == 0
            && (l_sub(st.prev_ener_lh, l_shl(st.ener_lh, 1)) < 0
                && l_sub(st.prev_ener_lh, l_shr(st.ener_lh, 1)) > 0
                && l_sub(st.prev_ener_ll, l_shl(st.ener_ll, 1)) < 0
                && l_sub(st.prev_ener_ll, l_shr(st.ener_ll, 1)) > 0))
            || (sub(st.prev_fractive, 1) == 0
                && l_sub(l_shr(st.prev_ener_lh, 2), mult_32_16(st.ener_lh, 24576)) > 0)
            || (l_sub(l_shr(st.ener_ll, 1), mult_32_16(st.ener_lh, 24576)) > 0
                && sub(st.tilt_wb, 20480) < 0)
        {
            is_fractive = 0;
        } else {
            is_fractive = 1;
        }
    }
    (is_fractive, tilt_swb_fec)
}

/// The RF partial-copy frame gain of the SWB TBE.
fn swb_tbe_dec_partial_copy_gain(st: &mut DecoderState, gain_frame: &mut i32) {
    if sub(st.rf_frame_type, 4 + 3) == 0 {
        *gain_frame = l_mac(-262144, st.rf_indx_tbe_gain_fr, 19661);
        let l_tmp = mult_32_16(*gain_frame, 27213);
        let (exp, frac) = l_extract_lc(l_tmp);
        let l_tmp = pow2(30, frac);
        *gain_frame = l_shl(l_tmp, sub(exp, 12));
        if sub(st.core, 0) == 0
            && sub(st.last_core, 0) == 0
            && st.prev_use_partial_copy == 0
            && sub(st.prev_coder_type, 1) == 0
            && l_sub(*gain_frame, st.gain_frame_prevfrm) != 0
            && sub(st.next_coder_type, 3) != 0
            && sub(st.last_extl, 8) == 0
        {
            *gain_frame = l_add(
                mult_32_16(st.gain_frame_prevfrm, 26214),
                mult_32_16(*gain_frame, 6553),
            );
        }
    } else {
        let mut temp: i16 = 0;
        match st.rf_indx_tbe_gain_fr {
            0 => {
                *gain_frame = 131072;
                if l_sub(st.gain_frame_prevfrm, 327680) <= 0 {
                    temp = 26214;
                }
            }
            1 => {
                *gain_frame = 524288;
                if l_sub(st.gain_frame_prevfrm, 327680) > 0
                    && l_sub(st.gain_frame_prevfrm, 786432) <= 0
                {
                    temp = 26214;
                }
            }
            2 => {
                *gain_frame = 1048576;
                if l_sub(st.gain_frame_prevfrm, 786432) > 0
                    && l_sub(st.gain_frame_prevfrm, 1572864) <= 0
                {
                    temp = 26214;
                }
            }
            3 => {
                *gain_frame = 2097152;
                if l_sub(st.gain_frame_prevfrm, 1572864) > 0
                    && l_sub(st.gain_frame_prevfrm, 4194304) <= 0
                {
                    temp = 26214;
                }
            }
            // the reference prints "RF SWB-TBE gain bits not supported." and goes on
            _ => {}
        }
        if sub(st.last_extl, 8) == 0 {
            *gain_frame = l_add(
                mult_32_16(st.gain_frame_prevfrm, temp),
                mult_32_16(*gain_frame, sub(32767, temp)),
            );
        }
        if sub(st.core, 0) == 0
            && sub(st.last_core, 0) == 0
            && st.prev_use_partial_copy == 0
            && sub(st.last_coder_type, 2) == 0
            && sub(st.rf_frame_type, 4 + 2) == 0
            && l_sub(*gain_frame, 2097152) > 0
            && l_sub(*gain_frame, 3059606) < 0
        {
            *gain_frame = mult_32_16(*gain_frame, 9830);
        }
    }
}

/// The parameters of a lost SWB TBE frame (`bfi`): the previous LSFs, the concealed gain shape
/// and frame gain, and the concealed SHB energy / mix factor / residual gain shape.
fn swb_tbe_dec_lost_frame(
    st: &mut DecoderState,
    tilt_swb_fec: i16,
    parameters: &mut SwbParameters,
) {
    parameters.lsf_shb.copy_from_slice(&st.lsp_prevfrm);
    if sub(st.codec_mode, 1) == 0 {
        gradient_gain_shape(st, &mut parameters.gain_shape, &mut parameters.gain_frame);
    } else {
        for i in 0..16 / 4 {
            for j in 0..4 {
                parameters.gain_shape[i * 4 + j] =
                    mult_r(st.cummulative_damping, st.gain_shape_delay[4 + i]);
            }
        }
        if sub(tilt_swb_fec, 8 << 11) > 0 {
            if sub(st.nb_lost_cmpt, 1) == 0 {
                parameters.gain_frame = mult_32_16(st.gain_frame_prevfrm, 19661);
            } else if sub(st.nb_lost_cmpt, 2) == 0 {
                parameters.gain_frame = mult_32_16(st.gain_frame_prevfrm, 11469);
            } else {
                parameters.gain_frame = mult_32_16(st.gain_frame_prevfrm, 6554);
            }
            parameters.gain_frame = mult_32_16(parameters.gain_frame, st.cummulative_damping);
        } else {
            parameters.gain_frame = st.gain_frame_prevfrm;
        }
    }

    if l_sub(st.total_brate, 24400) == 0 || l_sub(st.total_brate, 32000) == 0 {
        if sub(st.codec_mode, 1) == 0 {
            let l_tmp = l_mult(
                extract_l(st.prev2_shb_ener_sf),
                extract_l(st.prev3_shb_ener_sf),
            );
            let mut exp: i16 = 0;
            let mut tmp = round_word(root_a(l_tmp, 1, &mut exp));
            let mut tmp1 = extract_l(st.prev1_shb_ener_sf);
            let i = sub(crate::itu::basic_ops::norm_s(tmp1), 1);
            tmp1 = shl(tmp1, i);
            if tmp == 0 {
                tmp = 32767;
            } else {
                let mut scale = div_s(tmp1, tmp);
                scale = scale.max(0);
                tmp = shl(scale, 15 - exp - i);
            }
            let mut scale = mult_r(st.prev_res_shb_gshape, tmp);
            if l_sub(l_shr(st.prev2_shb_ener_sf, 1), st.prev1_shb_ener_sf) > 0
                || l_sub(l_shr(st.prev3_shb_ener_sf, 1), st.prev2_shb_ener_sf) > 0
            {
                parameters.shb_ener_sf_32 = mult_32_16(st.prev1_shb_ener_sf, scale);
                if sub(st.nb_lost_cmpt, 1) > 0 {
                    parameters.shb_ener_sf_32 = l_shr(parameters.shb_ener_sf_32, 1);
                }
            } else {
                let l_tmp = l_mult(scale, scale);
                scale = round_word(l_tmp);
                parameters.shb_ener_sf_32 = l_shl(mult_32_16(st.prev1_shb_ener_sf, scale), 2);
            }
        } else if l_sub(l_shr(st.prev2_shb_ener_sf, 1), st.prev1_shb_ener_sf) > 0
            || l_sub(l_shr(st.prev3_shb_ener_sf, 1), st.prev2_shb_ener_sf) > 0
        {
            parameters.shb_ener_sf_32 =
                l_shr(mult_32_16(st.prev1_shb_ener_sf, st.cummulative_damping), 1);
        } else {
            parameters.shb_ener_sf_32 = mult_32_16(st.prev1_shb_ener_sf, st.cummulative_damping);
        }
    }
    parameters.shb_ener_sf_32 = parameters.shb_ener_sf_32.max(1);
    parameters.mix_factors = st.prev_mix_factors;
    let fill = if sub(st.codec_mode, 1) == 0 {
        3277
    } else {
        16384
    };
    parameters.shb_res_gshape.fill(fill);
}

/// The parameters of a normal (not blind-spot) frame: the previous-LSF reset after a core switch,
/// then the bitstream / partial-copy / concealed values.
fn swb_tbe_dec_normal_frame(
    st: &mut DecoderState,
    tilt_swb_fec: i16,
    parameters: &mut SwbParameters,
) {
    if sub(st.last_extl, 8) != 0 && sub(st.last_extl, 11) != 0 {
        let (mut f, inc): (i16, i16) = (1489, 1489);
        for value in &mut st.lsp_prevfrm[..10] {
            *value = f;
            f = add(f, inc);
        }
    }
    if st.bfi == 0 {
        if st.use_partial_copy != 0 {
            if sub(st.last_extl, 8) != 0 {
                st.gain_frame_prevfrm = 0;
                let (mut f, inc): (i16, i16) = (1489, 1489);
                for value in &mut st.lsp_prevfrm[..10] {
                    *value = f;
                    f = add(f, inc);
                }
            }
            parameters.lsf_shb.copy_from_slice(&st.lsp_prevfrm);
            parameters.gain_shape.fill(11585);
            swb_tbe_dec_partial_copy_gain(st, &mut parameters.gain_frame);
        } else {
            let (extl, extl_brate) = (st.extl, st.extl_brate);
            let mut stemp: i16 = 0;
            dequantize_shb_params_9_1(
                st,
                extl,
                extl_brate,
                &mut parameters.lsf_shb,
                &mut parameters.gain_shape,
                &mut parameters.gain_frame,
                &mut stemp,
                &mut parameters.shb_ener_sf_32,
                &mut parameters.shb_res_gshape,
                &mut parameters.mix_factors,
            );
        }
    } else {
        swb_tbe_dec_lost_frame(st, tilt_swb_fec, parameters);
    }
}

/// The frame parameters of `swb_tbe_dec_fx`: the blind-spot (`bws_cnt > 0`) values, or those of
/// [`swb_tbe_dec_normal_frame`].
pub(super) fn swb_tbe_dec_parameters(
    st: &mut DecoderState,
    is_fractive: i16,
    tilt_swb_fec: i16,
) -> SwbParameters {
    let mut parameters = SwbParameters {
        lsf_shb: [0; 10],
        gain_shape: [0; 16],
        gain_frame: 0,
        shb_ener_sf_32: 0,
        shb_res_gshape: [1638; 5],
        mix_factors: 0,
    };

    if st.bws_cnt > 0 {
        if sub(is_fractive, 1) == 0 {
            st.lsp_prevfrm.copy_from_slice(&LSF_TAB_FX);
        } else {
            let (mut f, inc): (i16, i16) = (1489, 1489);
            for value in &mut st.lsp_prevfrm[..10] {
                *value = f;
                f = add(f, inc);
            }
        }
        // `L_sub(prev_enerLH, L_shr(enerLH, 1) > 0)` in the reference compares first: its second
        // operand is the 0 / 1 result of `> 0`, and the product is then used as a truth value
        let second = l_sub(st.prev_ener_lh, i32::from(l_shr(st.ener_lh, 1) > 0));
        if (sub(st.last_extl, 8) != 0
            && sub(st.last_extl, 11) != 0
            && !(l_sub(l_shr(st.prev_ener_lh, 1), st.ener_lh) < 0 && second != 0))
            || sub(st.last_core, 0) != 0
            || (sub(st.last_core, 0) == 0
                && l_sub(l_abs(l_sub(st.last_core_brate, st.core_brate)), 3600) > 0)
            || sub(is_fractive ^ st.prev_fractive, 1) == 0
        {
            parameters.gain_shape.fill(11587);
        } else {
            if sub(st.prev_gain_shape, 11587) > 0 {
                st.prev_gain_shape = 11587;
            }
            parameters.gain_shape.fill(st.prev_gain_shape);
        }
        parameters.lsf_shb.copy_from_slice(&st.lsp_prevfrm);
        parameters.shb_res_gshape.fill(3277);
    } else {
        swb_tbe_dec_normal_frame(st, tilt_swb_fec, &mut parameters);
    }
    parameters
}

/// The LPC of the SWB TBE of one frame: `lpc_shb` (11 coefficients, scaled to Q12 headroom) and,
/// at 24.4 / 32 kbit/s, the four sub-frame LPCs `lpc_shb_sf`; also `lsp_shb_2` (the LSP of this
/// frame) for the next frame's interpolation. Updates the LSF-difference smoothing memories.
pub(super) fn swb_tbe_dec_lpc(
    st: &mut DecoderState,
    coder_type: i16,
    lsf_shb: &[i16; 10],
    lpc_shb: &mut [i16; 11],
    lpc_shb_sf: &mut [i16; 44],
    lsp_shb_2: &mut [i16; 10],
) {
    let mut lsp_shb_1 = [0i16; 10];
    let mut lsp_temp = [0i16; 10];
    let mut lsf_diff = [0i16; 10];
    let mut w = [0i16; 10];
    let mut refl = [0i16; 16];

    e_lpc_lsf_lsp_conversion(lsf_shb, lsp_shb_2, 10);
    if sub(st.last_extl, 8) == 0 || sub(st.last_extl, 11) == 0 {
        lsp_shb_1.copy_from_slice(&st.swb_lsp_prev_interp);
    } else {
        lsp_shb_1.copy_from_slice(lsp_shb_2);
    }

    if st.bws_cnt == 0
        && st.bws_cnt1 == 0
        && st.prev_use_partial_copy == 0
        && st.use_partial_copy == 0
    {
        lsf_diff[0] = 16384;
        lsf_diff[10 - 1] = 16384;
        for i in 1..10 - 1 {
            lsf_diff[i] = sub(lsf_shb[i], lsf_shb[i - 1]);
        }
        a2rc(&st.cur_sub_aq, 1, &mut refl, 16);
        let mut tmp = add(16384, shr(refl[0], 1));
        let mut tmp1 = mult(27425, tmp);
        tmp1 = mult(tmp1, tmp);
        let tmp2 = shr(mult(31715, tmp), 2);
        let tilt_para = add(sub(tmp1, tmp2), 1335);

        if sub(st.last_extl, 8) != 0 && sub(st.last_extl, 11) != 0 {
            for i in 1..10 - 1 {
                st.prev_lsf_diff[i - 1] = shr(lsf_diff[i], 1);
            }
        }

        if l_sub(st.total_brate, 16400) <= 0 {
            if !(sub(st.prev_tilt_para, 5120) > 0
                && (sub(coder_type, 4) == 0 || sub(tilt_para, 1024) < 0))
                && !((sub(st.prev_tilt_para, 3072) < 0 && sub(st.prev_coder_type, 2) >= 0)
                    && sub(tilt_para, 5120) > 0)
            {
                for i in 1..10 - 1 {
                    if sub(lsf_diff[i], st.prev_lsf_diff[i - 1]) < 0 {
                        tmp = mult(26214, lsf_diff[i]);
                        if st.prev_lsf_diff[i - 1] <= 0 || tmp < 0 {
                            st.ber_detect = 1;
                            tmp = 0;
                        } else {
                            tmp = div_s(tmp, st.prev_lsf_diff[i - 1]);
                        }
                        tmp = tmp.max(16384);
                        w[i] = tmp; // `s_min(tmp, 32767)` cannot bind an i16
                    } else {
                        tmp = mult(26214, st.prev_lsf_diff[i - 1]);
                        if lsf_diff[i] <= 0 || tmp < 0 {
                            st.ber_detect = 1;
                            tmp = 0;
                        } else {
                            tmp = div_s(tmp, lsf_diff[i]);
                        }
                        tmp = tmp.max(16384);
                        w[i] = tmp; // `s_min(tmp, 32767)` cannot bind an i16
                    }
                }
                w[0] = w[1];
                w[10 - 1] = w[10 - 2];
                for i in 0..10 {
                    tmp1 = mult(lsp_shb_1[i], sub(32767, w[i]));
                    let tmp2 = mult(lsp_shb_2[i], w[i]);
                    lsp_temp[i] = add(tmp1, tmp2);
                }
            } else {
                lsp_temp.copy_from_slice(lsp_shb_2);
            }
        }
        st.prev_lsf_diff.copy_from_slice(&lsf_diff[1..9]);
        st.prev_tilt_para = tilt_para;
    } else {
        lsp_temp.copy_from_slice(lsp_shb_2);
    }

    if l_sub(st.total_brate, 24400) == 0 || l_sub(st.total_brate, 32000) == 0 {
        for j in 0..4 {
            let coefficient = &INTERPOL_FRAC_SHB[2 * j..2 * j + 2];
            for i in 0..10 {
                let l_tmp = l_mult(lsp_shb_1[i], coefficient[0]);
                lsp_temp[i] = mac_r(l_tmp, lsp_shb_2[i], coefficient[1]);
            }
            let tmp = i_mult(j as i16, 10 + 1) as usize;
            e_lpc_f_lsp_a_conversion(&lsp_temp, &mut lpc_shb_sf[tmp..], 10);
            let shift = sub(crate::itu::basic_ops::norm_s(lpc_shb_sf[tmp]), 2);
            scale_sig(&mut lpc_shb_sf[tmp..tmp + 11], 10 + 1, shift);
        }
    }
    e_lpc_f_lsp_a_conversion(&lsp_temp, lpc_shb, 10);
    let shift = sub(crate::itu::basic_ops::norm_s(lpc_shb[0]), 2);
    scale_sig(lpc_shb, 10 + 1, shift);
}
