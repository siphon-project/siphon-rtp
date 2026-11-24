//! SWB / FB TBE decoder, gain handling of `swb_tbe_dec_fx` (TS 26.442 `lib_dec/swb_tbe_dec_fx.c`):
//! the frame gain after a blind spot or a lost frame, the gain-shape smoothing between frames
//! and the frame-power recovery.

use super::swb_params::SwbParameters;
use crate::evs::basop::{mult_32_16, mult_32_32};
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::com::tools::{root_a, root_a_over_b};
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_add, l_deposit_h, l_mult, l_negate, l_shl, l_shr, l_sub, mult, mult_r,
    negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{i_mult, l_mac0, l_mult0};

/// The energy-ratio tracking of the blind-spot branch of the frame gain (`bws_cnt > 0`).
fn swb_tbe_dec_gain_frame_blind_spot(
    st: &mut DecoderState,
    parameters: &mut SwbParameters,
    mut ener: i16,
    is_fractive: i16,
) {
    ener = mult(ener, 11587);
    if sub(st.tilt_swb, 16384) > 0 {
        st.prev_fractive = 1;
    }
    if is_fractive == 0 {
        if sub(st.tilt_wb, 2048) > 0 {
            st.tilt_wb = 2048;
        } else if sub(st.tilt_wb, 1024) < 0 {
            st.tilt_wb = 1024;
        }
        if st.prev_fractive == 1 && sub(st.tilt_wb, 1024) > 0 {
            st.tilt_wb = 1024;
        }
    } else if sub(st.tilt_wb, 8192) > 0 {
        st.tilt_wb = if st.prev_fractive == 0 { 8192 } else { 16384 };
    } else {
        st.tilt_wb = shl(st.tilt_wb, 2);
    }

    let gain_frame_prevfrm: i32 = if ener != 0 {
        let l_tmp = l_shl(l_mult0(ener, st.tilt_wb), sub(st.q_syn2, 14));
        let exp_ener = norm_s(ener);
        let tmp = shl(ener, exp_ener);
        let inv_ener = div_s(16384, tmp);
        if l_sub(l_tmp, st.ener_lh) > 0 {
            st.tilt_wb = extract_h(l_shr(
                mult_32_16(st.ener_lh, inv_ener),
                sub(sub(st.q_syn2, exp_ener), 16),
            ));
        } else if l_sub(l_tmp, mult_32_16(st.ener_lh, 1638)) < 0 && sub(is_fractive, 1) == 0 {
            st.tilt_wb = extract_h(l_shr(
                mult_32_16(st.ener_lh, inv_ener),
                sub(sub(st.q_syn2, exp_ener), 15),
            ));
        }
        let l_tmp = l_mult0(st.prev_ener_shb, inv_ener);
        l_shr(l_tmp, sub(9, exp_ener))
    } else {
        0
    };

    if sub(is_fractive, 1) == 0 {
        parameters.gain_frame = l_shl(i32::from(st.tilt_wb), 10);
    } else {
        parameters.gain_frame = l_shl(i32::from(st.tilt_wb), 8);
    }

    let gain_frame = parameters.gain_frame;
    if sub(is_fractive & st.prev_fractive, 1) == 0 && l_sub(gain_frame, gain_frame_prevfrm) > 0 {
        parameters.gain_frame = l_add(
            mult_32_16(gain_frame_prevfrm, 26214),
            mult_32_16(gain_frame, 6554),
        );
    } else if (l_sub(l_shr(st.prev_ener_lh, 1), st.ener_lh) < 0
        && l_sub(st.prev_ener_lh, l_shr(st.ener_lh, 1)) > 0)
        && (l_sub(l_shr(st.prev_ener_ll, 1), st.ener_ll) < 0
            && l_sub(st.prev_ener_ll, l_shr(st.ener_ll, 1)) > 0)
        && (is_fractive ^ st.prev_fractive) == 0
    {
        parameters.gain_frame = l_add(l_shr(gain_frame, 1), l_shr(gain_frame_prevfrm, 1));
    } else if is_fractive == 0 && sub(st.prev_fractive, 1) == 0 {
        let l_tmp1 = l_shl(mult_32_16(gain_frame, 3277), 13);
        let l_tmp = l_sub(2147483647, l_tmp1);
        parameters.gain_frame = l_add(
            mult_32_32(gain_frame, l_tmp),
            mult_32_32(gain_frame_prevfrm, l_tmp1),
        );
    } else {
        parameters.gain_frame = l_add(
            l_shr(gain_frame, 1),
            l_shr(gain_frame_prevfrm.min(gain_frame), 1),
        );
    }
    parameters.gain_frame = mult_32_16(parameters.gain_frame, i_mult(sub(40, st.bws_cnt), 819));
}

/// The frame gain of the lost-frame concealment (`bws_cnt == 0`): the blend with the previous
/// frame's energy ratio, depending on how many frames were lost.
fn swb_tbe_dec_gain_frame_lost(
    st: &mut DecoderState,
    parameters: &mut SwbParameters,
    mut ener: i16,
    tilt_swb_fec: i16,
) {
    if st.bws_cnt1 > 0 {
        parameters.gain_frame = mult_32_16(parameters.gain_frame, i_mult(st.bws_cnt1, 819));
    }
    let mut prev_ener_ratio: i32 = 0;
    if sub(st.nb_lost_cmpt, 1) >= 0 {
        ener = ener.max(1);
        let exp_ener = norm_s(ener);
        let tmp = shl(ener, exp_ener);
        let inv_ener = div_s(16384, tmp);
        prev_ener_ratio = l_shr(l_mult0(st.prev_ener_shb, inv_ener), sub(9, exp_ener));
    }
    let gain_frame = parameters.gain_frame;

    if sub(st.nb_lost_cmpt, 1) == 0 {
        if sub(st.clas_dec, 0) != 0
            && sub(st.clas_dec, 1) != 0
            && sub(st.tilt_swb_fec, 16384) < 0
            && ((l_sub(st.ener_ll, l_shr(st.prev_ener_ll, 1)) > 0
                && l_sub(l_shr(st.ener_ll, 1), st.prev_ener_ll) < 0)
                || (l_sub(st.ener_lh, l_shr(st.prev_ener_lh, 1)) > 0
                    && l_sub(l_shr(st.ener_lh, 1), st.prev_ener_lh) < 0))
        {
            if l_sub(l_shr(prev_ener_ratio, 2), gain_frame) > 0 {
                parameters.gain_frame = l_add(
                    mult_32_16(prev_ener_ratio, 13107),
                    mult_32_16(gain_frame, 19661),
                );
            } else if l_sub(l_shr(prev_ener_ratio, 1), gain_frame) > 0 {
                parameters.gain_frame = l_add(
                    mult_32_16(prev_ener_ratio, 26214),
                    mult_32_16(gain_frame, 6554),
                );
            } else {
                parameters.gain_frame = l_add(
                    mult_32_16(prev_ener_ratio, 6554),
                    mult_32_16(gain_frame, 26214),
                );
            }
            if sub(tilt_swb_fec, st.tilt_swb_fec) > 0 && st.tilt_swb_fec > 0 {
                let exp = norm_s(st.tilt_swb_fec);
                let mut tmp = shl(st.tilt_swb_fec, exp);
                tmp = div_s(16384, tmp);
                tmp = extract_h(l_shl(l_mult0(tmp, st.tilt_wb), sub(exp, 1)));
                parameters.gain_frame = l_shl(mult_32_16(parameters.gain_frame, tmp.min(20480)), 3);
            }
        } else if (sub(st.clas_dec, 0) != 0 || sub(st.tilt_swb_fec, 16384) > 0)
            && l_sub(l_shr(prev_ener_ratio, 2), gain_frame) > 0
            && (l_sub(st.ener_ll, l_shr(st.prev_ener_ll, 1)) > 0
                || l_sub(st.ener_lh, l_shr(st.prev_ener_lh, 1)) > 0)
        {
            parameters.gain_frame = l_add(
                mult_32_16(prev_ener_ratio, 6554),
                mult_32_16(gain_frame, 26214),
            );
        }
    } else if sub(st.nb_lost_cmpt, 1) > 0 {
        let energy_rising = (sub(st.codec_mode, 1) == 0
            && l_sub(st.ener_ll, st.prev_ener_ll) > 0
            && l_sub(st.ener_lh, st.prev_ener_lh) > 0)
            || sub(st.codec_mode, 2) == 0;
        let both_high = sub(tilt_swb_fec, 20480) > 0 && sub(st.tilt_swb_fec, 20480) > 0;
        if l_sub(l_shr(prev_ener_ratio, 2), gain_frame) > 0 && energy_rising {
            let limit = l_shl(mult_32_16(gain_frame, 16384), 3);
            parameters.gain_frame = if both_high {
                l_add(
                    mult_32_16(prev_ener_ratio, 26214),
                    mult_32_16(gain_frame, 6554),
                )
                .min(limit)
            } else {
                l_add(
                    mult_32_16(prev_ener_ratio, 16384),
                    mult_32_16(gain_frame, 16384),
                )
                .min(limit)
            };
        } else if l_sub(prev_ener_ratio, gain_frame) > 0 && energy_rising {
            parameters.gain_frame = if both_high {
                l_add(
                    mult_32_16(prev_ener_ratio, 16384),
                    mult_32_16(gain_frame, 16384),
                )
            } else {
                l_add(
                    mult_32_16(prev_ener_ratio, 6554),
                    mult_32_16(gain_frame, 26214),
                )
            };
        }
    }
}

/// The frame gain of `swb_tbe_dec_fx` after the energy of the shaped excitation is known: the
/// blind-spot (`bws_cnt > 0`) or lost-frame adjustment. `ener` is the excitation energy (Q of the
/// synthesis) and `st.prev_fractive` is set to `is_fractive` at the end, as the reference does.
pub(super) fn swb_tbe_dec_gain_frame(
    st: &mut DecoderState,
    parameters: &mut SwbParameters,
    ener: i16,
    is_fractive: i16,
    tilt_swb_fec: i16,
) {
    if st.bws_cnt > 0 {
        swb_tbe_dec_gain_frame_blind_spot(st, parameters, ener, is_fractive);
    } else {
        swb_tbe_dec_gain_frame_lost(st, parameters, ener, tilt_swb_fec);
    }
    st.prev_fractive = is_fractive;
}

/// The gain-shape continuity at the start of a stationary segment: limits the gain shape of each
/// quarter frame against the previous frame's energy and gain shape when the coder type repeats
/// and the pitch is high. `ener_tmp` are the four quarter-frame energies (Q of `q_bwe_exc`).
pub(super) fn swb_tbe_dec_gain_shape_smoothing(
    st: &mut DecoderState,
    parameters: &mut SwbParameters,
    ener_tmp: &[i32; 4],
    q_bwe_exc: i16,
    coder_type: i16,
    pitch_buf: &[i16],
) {
    use crate::itu::basic_ops::{l_mac, round_word as round};
    let mut gain_shape_tmp = [0i16; 4];

    let pitch_fx: i16 = if sub(st.l_frame, 256) == 0 {
        let mut l_tmp = l_mult(pitch_buf[0], 8192);
        for &value in &pitch_buf[1..4] {
            l_tmp = l_mac(l_tmp, value, 8192);
        }
        round(l_tmp)
    } else {
        let mut l_tmp = l_mult(pitch_buf[0], 6554);
        for &value in &pitch_buf[1..5] {
            l_tmp = l_mac(l_tmp, value, 6554);
        }
        round(l_tmp)
    };

    if ((l_sub(st.total_brate, 24400) >= 0
        && sub(st.prev_coder_type, coder_type) == 0
        && sub(coder_type, 1) != 0)
        || (l_sub(st.total_brate, 16400) <= 0
            && (sub(st.prev_coder_type, coder_type) == 0
                || (sub(st.prev_coder_type, 2) == 0 && sub(coder_type, 3) == 0)
                || (sub(st.prev_coder_type, 3) == 0 && sub(coder_type, 2) == 0))))
        && sub(pitch_fx, 4480) > 0
        && sub(st.extl, 11) < 0
    {
        for i in 0..4 {
            gain_shape_tmp[i] = parameters.gain_shape[shl(i as i16, 2) as usize];
        }
        for i in 0..4 {
            let l_tmp1 = mult_32_16(ener_tmp[i], gain_shape_tmp[i]);
            let mut l_tmp2 = mult_32_16(st.prev_ener, st.prev_gain_shape);
            let tmp = sub(shl(q_bwe_exc, 1), shl(st.prev_ener_fx_q, 1));
            l_tmp2 = l_shl(l_tmp2, tmp);
            if l_sub(l_tmp1, l_tmp2) > 0 {
                let mut l_tmp = l_tmp2;
                if l_tmp2 < 0 {
                    l_tmp = l_negate(l_tmp2);
                }
                let mut expb = norm_l(l_tmp);
                let mut fracb = round_word(l_shl(l_tmp, expb));
                expb = 30 - expb;
                let mut expa = norm_l(ener_tmp[i]);
                let fraca = extract_h(l_shl(ener_tmp[i], expa));
                expa = 30 - expa;
                let scale = shr(sub(fraca, fracb), 15);
                fracb = shl(fracb, scale);
                expb = sub(expb, scale);
                let mut tmp = div_s(fracb, fraca);
                let exp = sub(sub(expb, expa), 1);
                tmp = shl(tmp, exp);
                gain_shape_tmp[i] = add(tmp, shr(gain_shape_tmp[i], 1));
            }
            st.prev_ener = ener_tmp[i];
            st.prev_gain_shape = gain_shape_tmp[i];
            st.prev_ener_fx_q = q_bwe_exc;
        }
        for i in 0..16 {
            parameters.gain_shape[i] = gain_shape_tmp[i * 4 / 16];
        }
    } else {
        st.prev_ener_fx_q = q_bwe_exc;
    }
}

/// `root_a` applied three times to the same value (the reference's repeated fourth-root chain):
/// the Q15 result `temp` after `exp - shift` is applied.
fn fourth_root_chain(mut l_tmp: i32, mut exp: i16, shift: i16) -> i16 {
    for _ in 0..3 {
        l_tmp = root_a(l_tmp, 31 - exp, &mut exp);
    }
    round_word(l_shl(l_tmp, sub(exp, shift)))
}

/// The frame-power tracking: the power of the scaled excitation, its alignment with the previous
/// frame's, and the gain / excitation compensation after a recovered or lost frame. Returns
/// `(curr_frame_pow, curr_frame_pow_exp)` for the next-frame bookkeeping.
pub(super) fn swb_tbe_dec_frame_power(
    st: &mut DecoderState,
    parameters: &mut SwbParameters,
    shaped_shb_excitation: &mut [i16; 340],
    q_bwe_exc: i16,
) -> (i32, i16) {
    let mut shaped_shb_excitation_frac = [0i16; 340];
    let mut max: i16 = 0;
    for &value in &shaped_shb_excitation[..320] {
        max = max.max(value);
    }
    let mut curr_frame_pow: i32;
    let n: i16;
    if max == 0 {
        curr_frame_pow = 0;
        n = 0;
    } else {
        n = norm_s(max);
        for i in 0..320 {
            shaped_shb_excitation_frac[i] = shl(shaped_shb_excitation[i], n);
        }
        curr_frame_pow = 0;
        for &value in &shaped_shb_excitation_frac[..320] {
            let l_tmp = l_mult0(value, value);
            curr_frame_pow = l_add(curr_frame_pow, l_shr(l_tmp, 9));
        }
    }

    let mut curr_frame_pow_exp = sub(shl(add(q_bwe_exc, n), 1), 9);
    let mut tmp = sub(st.prev_frame_pow_exp, curr_frame_pow_exp);
    if tmp > 0 {
        if sub(tmp, 32) > 0 {
            st.prev_frame_pow_exp = add(curr_frame_pow_exp, 32);
            tmp = 32;
        }
        st.prev_swb_bwe_frame_pow = l_shr(st.prev_swb_bwe_frame_pow, tmp);
        st.prev_frame_pow_exp = curr_frame_pow_exp;
    } else {
        if sub(tmp, -32) < 0 {
            // (the reference also sets `curr_frame_pow_exp` here, then overwrites it below)
            tmp = -32;
        }
        curr_frame_pow = l_shr(curr_frame_pow, negate(tmp));
        curr_frame_pow_exp = st.prev_frame_pow_exp;
    }

    if st.bfi == 0 && st.prev_bfi != 0 {
        let mut l_tmp = l_shr(curr_frame_pow, 4);
        l_tmp = mult_32_16(l_tmp, 17476);
        let (mut scale, temp): (i16, i16);
        if l_sub(l_shr(curr_frame_pow, 1), st.prev_swb_bwe_frame_pow) > 0
            && l_sub(st.prev_swb_bwe_frame_pow, l_tmp) > 0
            && sub(st.prev_coder_type, 1) == 0
        {
            let mut exp: i16 = 0;
            let l_root = root_a_over_b(
                st.prev_swb_bwe_frame_pow,
                curr_frame_pow_exp,
                curr_frame_pow,
                curr_frame_pow_exp,
                &mut exp,
            );
            scale = round_word(l_shl(l_root, exp));
            temp = fourth_root_chain(l_root, exp, 0);
        } else {
            scale = 32767;
            temp = 32767;
        }
        for j in 0..8 {
            parameters.gain_shape[2 * j] = mult_r(parameters.gain_shape[2 * j], scale);
            parameters.gain_shape[2 * j + 1] = mult_r(parameters.gain_shape[2 * j + 1], scale);
            for i in 0..320 / 8 {
                let index = i + j * 320 / 8;
                shaped_shb_excitation[index] = mult_r(shaped_shb_excitation[index], scale);
            }
            if temp > 0 {
                scale = if sub(scale, temp) < 0 {
                    div_s(scale, temp)
                } else {
                    32767
                };
            } else {
                scale = 0;
            }
        }
    }

    if st.bfi != 0 {
        swb_tbe_dec_frame_power_lost(
            st,
            parameters,
            shaped_shb_excitation,
            curr_frame_pow,
            curr_frame_pow_exp,
        );
    }
    (curr_frame_pow, curr_frame_pow_exp)
}

/// The lost-frame compensation of [`swb_tbe_dec_frame_power`]: the excitation and gain shape are
/// scaled (by up to 8) towards the previous frame's power.
fn swb_tbe_dec_frame_power_lost(
    st: &mut DecoderState,
    parameters: &mut SwbParameters,
    shaped_shb_excitation: &mut [i16; 340],
    curr_frame_pow: i32,
    curr_frame_pow_exp: i16,
) {
    let mut scale: i16 = 4096;
    let mut temp: i16 = 4096;
    let mut exp: i16 = 0;
    let root_ratio = |exp: &mut i16| {
        root_a_over_b(
            st.prev_swb_bwe_frame_pow,
            curr_frame_pow_exp,
            curr_frame_pow,
            curr_frame_pow_exp,
            exp,
        )
    };
    let energy_up = l_sub(st.ener_ll, l_shr(st.prev_ener_ll, 1)) > 0
        || l_sub(st.ener_lh, l_shr(st.prev_ener_lh, 1)) > 0;
    let low_power = l_sub(curr_frame_pow, l_shr(st.prev_swb_bwe_frame_pow, 1)) < 0;

    if sub(st.nb_lost_cmpt, 1) == 0 {
        // (the reference has two branches with this same body)
        if (l_sub(curr_frame_pow, st.prev_swb_bwe_frame_pow) > 0
            && sub(st.prev_coder_type, 1) != 0
            && sub(st.last_good, 0) != 0)
            || (low_power
                && energy_up
                && (sub(st.prev_coder_type, 1) == 0
                    || sub(st.last_good, 0) == 0
                    || sub(st.tilt_swb_fec, 10240) > 0))
        {
            let l_tmp = root_ratio(&mut exp);
            scale = round_word(l_shl(l_tmp, sub(exp, 3)));
            temp = fourth_root_chain(l_tmp, exp, 3);
        }
    } else if sub(st.nb_lost_cmpt, 1) > 0 {
        if l_sub(curr_frame_pow, st.prev_swb_bwe_frame_pow) > 0 {
            let l_tmp = root_ratio(&mut exp);
            scale = round_word(l_shl(l_tmp, sub(exp, 3)));
            temp = fourth_root_chain(l_tmp, exp, 3);
        } else if low_power
            && energy_up
            && (st.prev_coder_type == 1 || st.last_good == 0 || sub(st.tilt_swb_fec, 10240) > 0)
        {
            let mut l_tmp = root_ratio(&mut exp);
            l_tmp = l_tmp.min(l_shl(2, 31 - exp));
            scale = round_word(l_shl(l_tmp, sub(exp, 3)));
            temp = fourth_root_chain(l_tmp, exp, 3);
        }
    }

    for j in 0..8 {
        parameters.gain_shape[2 * j] = shl(mult_r(parameters.gain_shape[2 * j], scale), 3);
        parameters.gain_shape[2 * j + 1] = shl(mult_r(parameters.gain_shape[2 * j + 1], scale), 3);
        for i in 0..40 {
            let index = add(i, i_mult(j as i16, 40)) as usize;
            shaped_shb_excitation[index] = shl(mult_r(shaped_shb_excitation[index], scale), 3);
        }
        if temp > 0 {
            if sub(scale, temp) < 0 {
                scale = shr(div_s(scale, temp), 3);
            } else {
                let tmp1 = sub(norm_s(scale), 1);
                let tmp2 = norm_s(temp);
                scale = div_s(shl(scale, tmp1), shl(temp, tmp2));
                scale = shr(scale, add(sub(tmp1, tmp2), 3));
            }
        } else {
            scale = 0;
        }
    }
}

/// The energy of the post-processed excitation of the previous-frame bookkeeping:
/// `prev_ener_shb` (Q of `q_bwe_exc`) and the `prev_SWB_fenv` envelope levels.
pub(super) fn swb_tbe_dec_prev_energies(
    st: &mut DecoderState,
    shaped_shb_excitation: &[i16; 340],
    q_bwe_exc: i16,
    curr_frame_pow: i32,
    curr_frame_pow_exp: i16,
) {
    let mut l_prev_ener_shb: i32 = 0;
    for &value in &shaped_shb_excitation[..320] {
        l_prev_ener_shb = l_mac0(l_prev_ener_shb, value, value);
    }
    l_prev_ener_shb = mult_32_16(l_prev_ener_shb, 26214);
    st.prev_ener_shb = 0;
    if l_prev_ener_shb != 0 {
        let mut exp = norm_l(l_prev_ener_shb);
        let mut tmp = extract_h(l_shl(l_prev_ener_shb, exp));
        exp = sub(exp, 30 - (2 * q_bwe_exc + 8));
        tmp = div_s(16384, tmp);
        let l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp);
        st.prev_ener_shb = round_word(l_shl(l_tmp, sub(exp, 14)));
    }

    let l_tmp = mult_32_16(curr_frame_pow, 26214);
    let mut tmp: i16 = 0;
    if l_tmp != 0 {
        let mut exp = norm_l(l_tmp);
        tmp = extract_h(l_shl(l_tmp, exp));
        exp = sub(exp, 30 - (curr_frame_pow_exp + 8));
        tmp = div_s(16384, tmp);
        let l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp);
        tmp = round_word(l_shl(l_tmp, sub(exp, 14)));
    }
    st.prev_swb_fenv.fill(tmp);
}
