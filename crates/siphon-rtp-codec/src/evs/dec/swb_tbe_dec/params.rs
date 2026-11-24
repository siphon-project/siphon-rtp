//! TBE parameter decoding: LSF / gain dequantisation, the bitstream reader and the gain-shape
//! concealment (TS 26.442 `lib_dec/swb_tbe_dec_fx.c`; TS 26.445 §6.1.3.4 and §6.1.4).

use crate::evs::basop::{l_extract_lc, mult_32_16};
use crate::evs::cnst::WB_TBE;
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::lsf_tools::space_lsfs;
use crate::evs::com::math_op::pow2;
use crate::evs::com::tools::{copy, copy32, set16, usdequant};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    GRID_SMOOTHING_FX, HBCB_SUBGAIN5BIT_FX, LBR_WB_BWE_LSFVQ_CBOOK_2BIT_FX, LSF_GRID_FX,
    LSF_Q_CB_FX, LSF_Q_NUM_BITS, MIRROR_POINT_Q_CB_FX, SHBCB_FRAMEGAIN16_FX, SHBCB_FRAMEGAIN64_FX,
    SHBCB_SUBGAIN5BIT_FX, SWB_TBE_LSFVQ_CBOOK_8B, WB_BWE_LSFVQ_CBOOK_8BIT_FX,
};
use crate::itu::basic_ops::{
    add, div_s, extract_l, l_mac, l_mult, l_shl, l_shr, l_sub, mult_r, shl, shr, sub,
};

/// `table[index]`, 0 past the end. Every index here is a bounded bitstream field, so a valid frame
/// stays inside; a corrupted one is flagged by `get_next_indice` (`BER_detect`) and reads 0.
fn at(table: &[i16], index: i32) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|position| table.get(position))
        .copied()
        .unwrap_or(0)
}

/// `Dequant_lower_LSF_fx`: the five lower LSFs `lsf_q[0..5]` (Q14) of the 5-stage differential
/// codebook indices `lsf_idx`.
pub fn dequant_lower_lsf(lsf_idx: &[i16], lsf_q: &mut [i16]) {
    lsf_q[0] = at(LSF_Q_CB_FX[0], i32::from(lsf_idx[0]));
    for i in 1..5 {
        lsf_q[i] = add(at(LSF_Q_CB_FX[i], i32::from(lsf_idx[i])), lsf_q[i - 1]);
    }
}

/// `Map_higher_LSF_fx`: the five higher LSFs `lsf_q[5..10]`, mirrored about the point `m` from the
/// lower ones and smoothed towards the grid `grid_in`.
pub fn map_higher_lsf(lsf_q: &mut [i16], m: i16, grid_in: &[i16]) {
    let mut lsf_map = [0i16; 5];
    let mut grid = [0i16; 5];
    let mut lsf_smooth = [0i16; 5];

    for i in 0..5 {
        lsf_map[i] = sub(shl(m, 1), lsf_q[5 - 1 - i]);
    }
    if sub(m, 8192) > 0 {
        let offset = lsf_map[0];
        let scale = div_s(sub(16384, m), m);
        for value in &mut lsf_map {
            *value = add(mult_r(sub(*value, offset), scale), offset);
        }
    }

    let last_q_lsf = lsf_q[5 - 1];
    let scale = sub(16384, last_q_lsf);
    for i in 0..5 {
        grid[i] = add(mult_r(grid_in[i], scale), last_q_lsf);
    }
    for i in 0..5 {
        lsf_smooth[i] = sub(
            mult_r(GRID_SMOOTHING_FX[i], grid[i]),
            mult_r(lsf_map[i], add(GRID_SMOOTHING_FX[i], -32768)),
        );
    }
    lsf_q[5..10].copy_from_slice(&lsf_smooth);
}

/// `Dequant_mirror_point_fx`: the mirror point (Q14) from its 2-bit index and the last lower LSF.
pub fn dequant_mirror_point(lsf_q: &[i16], m_idx: i16) -> i16 {
    add(at(&MIRROR_POINT_Q_CB_FX, i32::from(m_idx)), lsf_q[5 - 1])
}

/// The gain in the exponential domain of `dequantizeSHBparams`: `2^(value · 27213 / 2^k)` as
/// the reference computes it, `Pow2(14, frac)` shifted by the integer part.
fn pow2_gain(l_tmp: i32, shift: i16) -> i16 {
    let l_tmp = l_shr(l_tmp, shift);
    let (exp, frac) = l_extract_lc(l_tmp);
    let tmp = extract_l(pow2(14, frac));
    shl(tmp, add(exp, 1))
}

/// `dequantizeSHBparams_fx_9_1`: the decoded TBE parameters. For the WB TBE (`extl` `WB_TBE`):
/// the LSFs `q_lsf[0..4 or 6]`, the sub-frame gains `q_subgain[0..8]` and frame gain `q_framegrain`
/// (and `uv_flag`); for the SWB / FB TBE: `q_lsf[0..10]`, the 16 sub-frame gains, the frame gain,
/// and at 24.4 / 32 kbit/s the SHB energy `q_shb_ener_sf`, residual gain shape
/// `q_shb_res_gshape[0..5]` and mix factor. The bits come from the bitstream (MODE1) or from the
/// indices already read into the state (MODE2).
pub fn dequantize_shb_params_9_1(
    st: &mut DecoderState,
    extl: i16,
    extl_brate: i32,
    q_lsf: &mut [i16],
    q_subgain: &mut [i16],
    q_framegrain: &mut i32,
    uv_flag: &mut i16,
    q_shb_ener_sf: &mut i32,
    q_shb_res_gshape: &mut [i16],
    q_mix_factors: &mut i16,
) {
    if sub(extl, WB_TBE) == 0 {
        if l_sub(extl_brate, 350) == 0 {
            let idx_frame_gain = st.g_frame_wb;
            let idx_lsf = st.lsf_wb;
            copy(
                &LBR_WB_BWE_LSFVQ_CBOOK_2BIT_FX[(idx_lsf.clamp(0, 3) * 4) as usize..],
                q_lsf,
                4,
            );
            set16(q_subgain, 11585, 16 / 2);
            copy32(
                &SHBCB_FRAMEGAIN16_FX[idx_frame_gain.clamp(0, 15) as usize..],
                std::slice::from_mut(q_framegrain),
                1,
            );
        } else {
            *uv_flag = get_next_indice(st, 1) as i16;
            let idx_sub_gain = get_next_indice(st, 5) as i16;
            let idx_frame_gain = get_next_indice(st, 6) as i16;
            let idx_lsf = get_next_indice(st, 8) as i16;

            copy(
                &WB_BWE_LSFVQ_CBOOK_8BIT_FX[(idx_lsf.clamp(0, 255) * 6) as usize..],
                q_lsf,
                6,
            );
            let mut q_combined_gains = [0i16; 16 / 4];
            copy(
                &HBCB_SUBGAIN5BIT_FX[(idx_sub_gain.clamp(0, 31) as usize) * 16 / 4..],
                &mut q_combined_gains,
                16 / 4,
            );
            for gain in &mut q_combined_gains {
                *gain = pow2_gain(l_mult(*gain, 21771), 10);
            }
            for i in (0..16 / 2).step_by(2) {
                q_subgain[i] = q_combined_gains[i / 2];
                q_subgain[i + 1] = q_combined_gains[i / 2];
            }
            copy32(
                &SHBCB_FRAMEGAIN64_FX[idx_frame_gain.clamp(0, 63) as usize..],
                std::slice::from_mut(q_framegrain),
                1,
            );
        }
        return;
    }

    let (idx_sub_gain, idx_frame_gain) = if sub(st.codec_mode, 2) == 0 {
        (st.idx_sub_gains, st.idx_frame_gain)
    } else {
        let idx_sub_gain = get_next_indice(st, 5) as i16;
        (idx_sub_gain, get_next_indice(st, 5) as i16)
    };

    if l_sub(st.total_brate, 24400) == 0 || l_sub(st.total_brate, 32000) == 0 {
        let idx_shb_fr_gain = if sub(st.codec_mode, 2) == 0 {
            st.idx_shb_fr_gain
        } else {
            get_next_indice(st, 6) as i16
        };
        let temp_shb_ener_sf = usdequant(idx_shb_fr_gain, 0, 86);
        let mut l_tmp = l_mult(temp_shb_ener_sf, 27213);
        l_tmp = l_shl(l_tmp, -10);
        let (exp, frac) = l_extract_lc(l_tmp);
        l_tmp = pow2(14, frac);
        *q_shb_ener_sf = l_shl(l_tmp, exp - 14);

        for i in 0..5 {
            let idx_res_gs = if sub(st.codec_mode, 2) == 0 {
                st.idx_res_gs[i]
            } else {
                get_next_indice(st, 3) as i16
            };
            q_shb_res_gshape[i] = usdequant(idx_res_gs, 2048, 1024);
        }
        let idx_mix_fac = if sub(st.codec_mode, 2) == 0 {
            st.idx_mix_fac
        } else {
            get_next_indice(st, 3) as i16
        };
        *q_mix_factors = usdequant(idx_mix_fac, 4096, 2048);
    } else {
        *q_shb_ener_sf = 0;
        *q_mix_factors = 0;
        set16(q_shb_res_gshape, 0, 5);
    }

    if st.rf_flag == 0
        && !(l_sub(st.total_brate, 9600) == 0
            || (st.total_brate == 0
                && (l_sub(st.last_total_brate, 9600) == 0
                    || (l_sub(st.last_total_brate, 13200) == 0 && sub(st.rf_flag_last, 1) == 0))))
    {
        let mut lsf_q = [0i16; 10];
        // the reference leaves `lsf_idx` unset (and then reads it) for an `extl_brate` outside
        // these four, which the MODE1 SWB / FB TBE never has
        let mut lsf_idx = [0i16; 5];
        if l_sub(extl_brate, 1600) == 0
            || l_sub(extl_brate, 1800) == 0
            || l_sub(extl_brate, 2800) == 0
            || l_sub(extl_brate, 3000) == 0
        {
            if sub(st.codec_mode, 2) == 0 {
                lsf_idx.copy_from_slice(&st.lsf_idx);
            } else {
                for (i, index) in lsf_idx.iter_mut().enumerate() {
                    *index = get_next_indice(st, LSF_Q_NUM_BITS[i]) as i16;
                }
            }
        }
        dequant_lower_lsf(&lsf_idx, &mut lsf_q);

        let m_idx = if sub(st.codec_mode, 2) == 0 {
            st.m_idx
        } else {
            get_next_indice(st, 2) as i16
        };
        let mut m = dequant_mirror_point(&lsf_q, m_idx);
        if sub(m, 16384) > 0 {
            st.ber_detect = 1;
            m = 16384 - 1;
        }

        let grid_idx = if sub(st.codec_mode, 2) == 0 {
            st.grid_idx
        } else {
            get_next_indice(st, 2) as i16
        };
        map_higher_lsf(&mut lsf_q, m, &LSF_GRID_FX[(grid_idx & 3) as usize]);

        for i in 0..10 {
            if sub(lsf_q[10 - 1 - i], 16384) > 0 {
                st.ber_detect = 1;
                lsf_q[10 - 1 - i] = 16384 - 1;
            }
            q_lsf[i] = sub(16384, lsf_q[10 - 1 - i]);
        }
    } else {
        let mut lsf_idx = [0i16; 5];
        lsf_idx.copy_from_slice(&st.lsf_idx);
        let start = (lsf_idx[0].clamp(0, 255) as usize) * 10;
        copy(&SWB_TBE_LSFVQ_CBOOK_8B[start..], q_lsf, 10);
    }
    space_lsfs(q_lsf, 10);

    let j = (idx_sub_gain.clamp(0, 31) as usize) * 4;
    for (gain, &table_gain) in q_subgain.iter_mut().zip(&SHBCB_SUBGAIN5BIT_FX[j..j + 4]) {
        *gain = pow2_gain(l_mult(table_gain, 27213), 12);
    }
    for i in (0..16).rev() {
        q_subgain[i] = q_subgain[i * 4 / 16];
    }

    *q_framegrain = l_mac(-262144, idx_frame_gain, 19661);
    let l_tmp = mult_32_16(*q_framegrain, 27213);
    let (exp, frac) = l_extract_lc(l_tmp);
    let l_tmp = pow2(30, frac);
    *q_framegrain = l_shl(l_tmp, sub(exp, 12));
}

/// `gradientGainShape`: the concealed gain shape for a lost SWB TBE frame, extrapolating the
/// gradient of the delayed gain shapes (`GainShape_Delay`), and the concealed frame gain; the gain
/// attenuation `GainAttn` is updated.
pub fn gradient_gain_shape(st: &mut DecoderState, gain_shape: &mut [i16], gain_frame: &mut i32) {
    let mut gain_shape_temp = [0i16; 16 / 4];
    let mut gain_grad0 = [0i16; 3];
    let mut gain_grad1 = [0i16; 3];
    let mut gain_grad_fec = [0i16; 4];

    for j in 0..3 {
        gain_grad0[j] = sub(
            shr(st.gain_shape_delay[j + 1], 1),
            shr(st.gain_shape_delay[j], 1),
        );
        gain_grad1[j] = sub(
            shr(st.gain_shape_delay[j + 5], 1),
            shr(st.gain_shape_delay[j + 4], 1),
        );
        gain_grad_fec[j + 1] = add(mult_r(gain_grad0[j], 13107), mult_r(gain_grad1[j], 19660));
    }

    if (sub(shr(gain_grad1[2], 1), gain_grad1[1]) > 0
        && sub(shr(gain_grad1[1], 1), gain_grad1[0]) > 0)
        || (sub(shr(gain_grad1[2], 1), gain_grad1[1]) < 0
            && sub(shr(gain_grad1[1], 1), gain_grad1[0]) < 0)
    {
        gain_grad_fec[0] = add(mult_r(gain_grad1[1], 3277), mult_r(gain_grad1[2], 29490));
    } else {
        gain_grad_fec[0] = add(mult_r(gain_grad1[0], 6553), mult_r(gain_grad1[1], 9830));
        gain_grad_fec[0] = add(gain_grad_fec[0], mult_r(gain_grad1[2], 16384));
    }

    if (st.prev_coder_type == 1 || st.last_good == 0) && gain_grad_fec[0] > 0 {
        gain_shape_temp[0] = add(shr(st.gain_shape_delay[7], 1), gain_grad_fec[0]);
    } else if gain_grad_fec[0] > 0 {
        gain_shape_temp[0] = add(
            shr(st.gain_shape_delay[7], 1),
            mult_r(gain_grad_fec[0], 16384),
        );
    } else {
        gain_shape_temp[0] = shr(st.gain_shape_delay[7], 1);
    }

    let mut tmp = shr(gain_grad1[2], 3);
    tmp = mult_r(tmp, 26214);
    if sub(tmp, gain_grad1[1]) > 0 && gain_grad1[1] > 0 {
        for i in 1..16 / 4 {
            gain_shape_temp[i] = add(gain_shape_temp[i - 1], mult_r(gain_grad_fec[i], 26214));
            gain_shape_temp[i] = gain_shape_temp[i].max(328);
        }
    } else if sub(tmp, gain_grad1[1]) > 0 && gain_grad1[1] < 0 {
        for i in 1..16 / 4 {
            gain_shape_temp[i] = add(gain_shape_temp[i - 1], mult_r(gain_grad_fec[i], 6553));
            gain_shape_temp[i] = gain_shape_temp[i].max(328);
        }
    } else {
        for i in 1..16 / 4 {
            gain_shape_temp[i] = add(gain_shape_temp[i - 1], gain_grad_fec[i]);
            gain_shape_temp[i] = gain_shape_temp[i].max(328);
        }
    }

    if (st.prev_coder_type == 1 || st.last_good == 0) && st.nb_lost_cmpt == 1 {
        for i in 0..16 / 4 {
            for j in 0..4 {
                let tmp = mult_r(gain_shape_temp[i], 19660);
                gain_shape[i * 4 + j] = if sub(8192, tmp) > 0 {
                    shl(tmp, 2)
                } else {
                    32767
                };
            }
        }
        st.gain_attn = mult_r(st.gain_attn, 31129);
    } else if st.prev_coder_type == 1 || st.last_good == 0 {
        for i in 0..16 / 4 {
            for j in 0..4 {
                gain_shape[i * 4 + j] = if sub(gain_shape_temp[i], 16384) < 0 {
                    shl(gain_shape_temp[i], 1)
                } else {
                    32767
                };
            }
        }
        st.gain_attn = mult_r(st.gain_attn, 31129);
    } else if st.nb_lost_cmpt > 1 {
        for i in 0..16 / 4 {
            for j in 0..4 {
                gain_shape[i * 4 + j] = gain_shape_temp[i];
            }
        }
        st.gain_attn = mult_r(st.gain_attn, 16384);
    } else {
        for i in 0..16 / 4 {
            for j in 0..4 {
                gain_shape[i * 4 + j] = if sub(gain_shape_temp[i], 16384) < 0 {
                    shl(gain_shape_temp[i], 1)
                } else {
                    32767
                };
            }
        }
        st.gain_attn = mult_r(st.gain_attn, 27852);
    }

    *gain_frame = mult_32_16(st.gain_frame_prevfrm, st.gain_attn);
}

/// `tbe_read_bitstream_fx`: reads the TBE indices of a MODE1 frame into the state (the MODE2
/// decoder's [`dequantize_shb_params_9_1`] reads them from there).
pub fn tbe_read_bitstream(st: &mut DecoderState) {
    if (sub(st.rf_flag, 1) == 0 || l_sub(st.total_brate, 9600) == 0) && sub(st.bwidth, 1) == 0 {
        st.lsf_wb = get_next_indice(st, 2) as i16;
        st.g_frame_wb = get_next_indice(st, 4) as i16;
    } else if l_sub(st.total_brate, 9600) >= 0
        && l_sub(st.total_brate, 32000) <= 0
        && (sub(st.bwidth, 2) == 0 || sub(st.bwidth, 3) == 0)
    {
        if st.rf_flag == 0 && l_sub(st.total_brate, 9600) > 0 {
            for i in 0..5 {
                st.lsf_idx[i] = get_next_indice(st, LSF_Q_NUM_BITS[i]) as i16;
            }
            st.m_idx = get_next_indice(st, 2) as i16;
            st.grid_idx = get_next_indice(st, 2) as i16;
        } else {
            st.lsf_idx[0] = get_next_indice(st, 8) as i16;
            st.m_idx = 0;
            st.grid_idx = 0;
        }
        st.idx_sub_gains = get_next_indice(st, 5) as i16;
        st.idx_frame_gain = get_next_indice(st, 5) as i16;

        if l_sub(st.total_brate, 24400) >= 0 {
            st.idx_shb_fr_gain = get_next_indice(st, 6) as i16;
            for i in 0..5 {
                st.idx_res_gs[i] = get_next_indice(st, 3) as i16;
            }
            st.idx_mix_fac = get_next_indice(st, 3) as i16;
        }

        if sub(st.tec_tfa, 1) == 0 {
            st.tec_flag = get_next_indice(st, 1) as i16;
            st.tfa_flag = get_next_indice(st, 1) as i16;
            if st.tfa_flag != 0 && st.tec_flag != 0 {
                st.tec_flag = 2;
                st.tfa_flag = 0;
            }
        } else {
            st.tec_flag = 0;
            st.tfa_flag = 0;
        }
    }

    if sub(st.bwidth, 3) == 0 {
        st.idx_gain = get_next_indice(st, 4) as i16;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_lsfs_accumulate_the_stage_values() {
        let mut lsf_q = [0i16; 10];
        dequant_lower_lsf(&[0, 0, 0, 0, 0], &mut lsf_q);
        assert_eq!(lsf_q[0], LSF_Q_CB_FX[0][0]);
        assert_eq!(lsf_q[1], add(LSF_Q_CB_FX[1][0], lsf_q[0]));
    }

    #[test]
    fn mirror_point_is_the_table_entry_over_the_last_lower_lsf() {
        let lsf_q = [0, 0, 0, 0, 1000, 0, 0, 0, 0, 0];
        assert_eq!(
            dequant_mirror_point(&lsf_q, 2),
            1000 + MIRROR_POINT_Q_CB_FX[2]
        );
    }

    #[test]
    fn map_higher_lsf_fills_only_the_upper_half() {
        let mut lsf_q = [100, 200, 300, 400, 500, 7, 7, 7, 7, 7];
        map_higher_lsf(&mut lsf_q, 4000, &LSF_GRID_FX[0]);
        assert_eq!(&lsf_q[..5], &[100, 200, 300, 400, 500]);
        assert!(lsf_q[5..].iter().any(|&value| value != 7));
    }

    #[test]
    fn gradient_gain_shape_attenuates_the_frame_gain() {
        let mut st = Box::new(DecoderState::zeroed());
        st.gain_attn = 32767;
        st.gain_frame_prevfrm = 1 << 20;
        st.nb_lost_cmpt = 2;
        st.prev_coder_type = 3;
        st.last_good = 2;
        let mut gain_shape = [0i16; 16];
        let mut gain_frame = 0;
        gradient_gain_shape(&mut st, &mut gain_shape, &mut gain_frame);
        assert_eq!(st.gain_attn, 16384);
        assert_eq!(gain_frame, mult_32_16(1 << 20, 16384));
    }
}
