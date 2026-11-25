//! The LPC envelope and start band of the AMR-WB IO high-band extension (TS 26.442
//! `lib_dec/hf_synth_fx.c`: `envelope_fx`, `EnhanceClass_fx`, `AdaptiveStartBand_fx`; TS 26.445
//! §6.2.2.4 "high band", TS 26.190 §6.3 high-band gain).

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    ACELP_12K65, ACELP_15K85, ACELP_23K05, ACELP_6K60, ACELP_8K85, AUDIO_CLAS, M, VOICED_CLAS,
};
use crate::evs::com::math_op::isqrt;
use crate::evs::com::tools::{copy_scale_sig, scale_sig};
use crate::evs::com::weight_a::weight_a_lc;
use crate::evs::rom::{EXP_TAB_P_FX, EXP_TAB_Q_FX, GAMMA_19661_TBL_FX, GAMMA_29491_TBL};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_l, l_add, l_deposit_l, l_mac, l_msu, l_mult, l_shl, l_shr, l_sub,
    mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::l_mult0;

/// `EnhanceClass_fx`: decide (`unvoicing_flag`, with hysteresis) whether the frame is unvoiced
/// enough to allow the band extension enhancement when the original envelope level `qq_fx` is
/// above the extended one `pp_fx`. Updates the smoothed voicing and the unvoiced parameters.
fn enhance_class(
    qq_fx: i16,
    pp_fx: i16,
    tilt0_fx: i16,
    tilt_fx: i16,
    voice_factor_fx: i16,
    voice_fac_fx: &mut i16,
    unvoicing_fx: &mut i16,
    unvoicing_sm_fx: &mut i16,
    unvoicing_flag: &mut i16,
) -> bool {
    // Decide (*unvoicing_flag) to allow BWE enhancement when qq > pp
    *voice_fac_fx = round_word(l_mac(l_mult(*voice_fac_fx, 24576), voice_factor_fx, 8192)); // Q15

    let mut tmp = mult_r(sub(8192, tilt0_fx), 16384); // Q13

    let mut l_tmp = l_sub(32768, i32::from(*voice_fac_fx)); // Q15

    l_tmp = mult_32_16(l_tmp, tmp); // Q13
    tmp = extract_l(l_tmp); // Q13

    let mut tmp1 = mult_r(tilt_fx, 21845); // Q15->1/1.5 ->Q13+15-15->Q13
    tmp1 = tmp1.min(8192);

    l_tmp = l_mult(tmp, tmp1); // Q13+Q13+1
    let unvoicing_tmp_fx = extract_l(l_shr(l_tmp, 12)); // Q15

    *unvoicing_fx = round_word(l_mac(l_mult(16384, *unvoicing_fx), 16384, unvoicing_tmp_fx)); // Q15

    if sub(*unvoicing_sm_fx, *unvoicing_fx) > 0 {
        *unvoicing_sm_fx = round_word(l_mac(l_mult(29491, *unvoicing_sm_fx), 3277, *unvoicing_fx));
        // Q15
    } else {
        *unvoicing_sm_fx = round_word(l_mac(l_mult(32440, *unvoicing_sm_fx), 328, *unvoicing_fx));
        // Q15
    }

    if sub(sub(*unvoicing_fx, *unvoicing_sm_fx), 3277) > 0 {
        *unvoicing_flag = 1;
    }

    if sub(sub(*unvoicing_fx, *unvoicing_sm_fx), 1638) < 0 {
        *unvoicing_flag = 0;
    }
    *unvoicing_flag != 0 && sub(qq_fx, pp_fx) > 0
}

/// The level estimate of the envelope of `coefficients[0..count]` (the first `count` taps of
/// the `Ap` or `Aq` polynomial): the real and imaginary parts `x`, `y` of its response, taken
/// with the table `table` and its mirror image, at the common scale `q` (`Q(10+q)`).
fn envelope_response(coefficients: &[i16], table: &[i16], count: usize) -> (i16, i16, i16) {
    let mut l_tmp = l_deposit_l(0);
    for i in 0..count {
        l_tmp = l_mac(l_tmp, coefficients[i], table[i]);
    }
    let mut q1 = norm_l(l_tmp);
    l_tmp = l_shl(l_tmp, q1); // Q(27+q1)
    let mut x = round_word(l_shr(l_tmp, 1)); // Q(10+q1)

    l_tmp = l_deposit_l(0);
    for i in 0..count {
        l_tmp = l_mac(l_tmp, coefficients[i], table[33 - i]);
    }
    let q2 = norm_l(l_tmp);
    let shift = sub(q1, q2);
    if shift >= 0 {
        x = shr(x, shift);
        l_tmp = l_shl(l_tmp, q2); // Q(27+q2)
        q1 = q2;
    } else {
        l_tmp = l_shl(l_tmp, q1); // Q(27+q1)
    }
    let y = round_word(l_shr(l_tmp, 1)); // Q(10+q1)
    (x, y, q1)
}

/// The level `1/sqrt(x² + y²)`-style magnitude (Q10) of a response pair at scale `q`.
fn envelope_level(x: i16, y: i16, q: i16) -> i16 {
    let mut l_tmp = l_mult(x, x);
    l_tmp = l_mac(l_tmp, y, y); // Q(21+2*q)
    round_word(isqrt(l_shr(l_tmp, add(11, shl(q, 1))))) // Q10
}

/// The two-tap reduction of the quantised filter: the reflection coefficients `k1`, `k2` of
/// `As[0..3]` limited to ±4055 and ±2458, and the order-2 filter `As` built from them.
fn envelope_second_order(as_: &mut [i16; 3]) {
    let (k1, k2);
    if add(2048, shr(as_[2], 1)) == 0 {
        k2 = -2458;
        k1 = if as_[1] < 0 { -4055 } else { 4055 };
    } else {
        let mut k1_value = add(2048, shr(as_[2], 1)); // Q11
        let mut q1: i16 = 11;
        let q2 = norm_s(k1_value);
        k1_value = shl(k1_value, q2); // q1+q2
        let mut tmp = abs_s(k1_value);
        q1 = add(q1, q2);
        tmp = div_s(shl(1, 14), tmp); // Q(29-q1)
        if k1_value < 0 {
            tmp = negate(tmp);
        }

        let l_tmp = l_mult(as_[1], tmp); // Q(42-q1)
        q1 = sub(q1, 14);
        k1_value = round_word(l_shl(l_tmp, q1)); // Q12
        let mut k2_value = as_[2]; // Q12
        if sub(k2_value, 2458) > 0 {
            k2_value = 2458;
        }
        if add(k2_value, 2458) < 0 {
            k2_value = -2458;
        }
        if sub(k1_value, 4055) > 0 {
            k1_value = 4055;
        }
        if add(k1_value, 4055) < 0 {
            k1_value = -4055;
        }
        k1 = k1_value;
        k2 = k2_value;
    }
    as_[1] = add(4096, k2);
    let l_tmp = l_mult(as_[1], k1); // Q25
    as_[1] = round_word(l_shl(l_tmp, 3)); // Q12
    as_[2] = k2; // Q12
}

/// `envelope_fx`: the extended LPC `ap` (Q12, `M + 1` taps) of one subframe and its gain
/// `sub_gain` (Q12): the envelope of the weighted filter is compared with that of the
/// quantised filter and of its two-tap reduction, and the gain follows the (un)voicing class
/// (`tilt0` Q14, `tilt` Q13, `voice_factor` Q15).
pub fn envelope(
    core_brate: i32,
    aq_dyn_scal: &[i16],
    ap: &mut [i16],
    sub_gain: &mut i16,
    tilt0: i16,
    tilt: i16,
    voice_factor: i16,
    prev_r: &mut i16,
    voice_fac: &mut i16,
    unvoicing: &mut i16,
    unvoicing_sm: &mut i16,
    unvoicing_flag: &mut i16,
) {
    let mut aq = [0i16; M as usize + 1];

    // Aq has dynamic scaling: go back to Q12 to make sure there is no overflow while calculating
    // qx, qy
    let mut shift = sub(norm_s(aq_dyn_scal[0]), 2);
    copy_scale_sig(aq_dyn_scal, &mut aq, M + 1, shift);

    // LPC envelope weighting
    if l_sub(core_brate, i32::from(ACELP_6K60)) == 0 {
        weight_a_lc(&aq, ap, &GAMMA_29491_TBL, M);
    } else {
        weight_a_lc(&aq, ap, &GAMMA_19661_TBL_FX, M);
    }
    // Ap has dynamic scaling: go back to Q12 to make sure there is no overflow while calculating
    // px, py
    shift = sub(norm_s(ap[0]), 2);
    if shift != 0 {
        scale_sig(ap, M + 1, shift);
    }

    // LPC envelope level estimate
    let taps = M as usize + 1;
    let (px, py, q1) = envelope_response(ap, &EXP_TAB_P_FX, taps);
    let (rx, ry, q2) = envelope_response(&aq, &EXP_TAB_Q_FX, taps);
    let pp = envelope_level(px, py, q1); // Q10
    let mut rr = envelope_level(rx, ry, q2); // Q10

    let mut as_ = [aq[0], aq[1], aq[2]];
    envelope_second_order(&mut as_);
    let (qx, qy, q1) = envelope_response(&as_, &EXP_TAB_Q_FX, 3);
    let mut qq = envelope_level(qx, qy, q1); // Q10

    let unvoicing_class = enhance_class(
        rr,
        pp,
        tilt0,
        tilt,
        voice_factor,
        voice_fac,
        unvoicing,
        unvoicing_sm,
        unvoicing_flag,
    );

    if unvoicing_class {
        if sub(rr, *prev_r) > 0 {
            rr = shr(add(rr, *prev_r), 1);
        }

        *prev_r = rr;

        let mut l_tmp = l_mult(tilt, sub(26214, shr(voice_factor, 1))); // Q28

        l_tmp = l_tmp.min(268_435_456);

        l_tmp = mult_32_16(l_tmp, rr); // Q23
        rr = round_word(l_shl(l_tmp, 3)); // Q10
        l_tmp = l_mult(tilt, sub(26214, shr(voice_factor, 1))); // Q28
        l_tmp = l_tmp.max(268_435_456);
        l_tmp = mult_32_16(l_tmp, qq); // Q23
        qq = round_word(l_shl(l_tmp, 3)); // Q10
        rr = rr.min(qq);
        rr = rr.max(pp);
    } else {
        if sub(rr, 1024) < 0 && sub(*prev_r, 1024) < 0 {
            let mut l_tmp = l_mult(rr, rr); // Q21
            let tmp = round_word(l_shl(l_tmp, 9)); // Q14
            l_tmp = l_sub(2_097_152, l_tmp); // Q21
            let alpha = round_word(l_shl(l_tmp, 9)); // Q14
            l_tmp = l_mult(alpha, *prev_r); // Q25
            l_tmp = l_mac(l_tmp, tmp, rr); // Q25
            rr = round_word(l_shl(l_tmp, 1)); // Q10
        }

        *prev_r = rr;

        let mut l_tmp = l_mult(tilt, sub(26214, shr(voice_factor, 1))); // Q28

        l_tmp = l_tmp.min(268_435_456);
        l_tmp = mult_32_16(l_tmp, qq); // Q23
        let est_level1 = round_word(l_shl(l_tmp, 3)); // Q10

        let mut tmp = pp;
        tmp = tmp.min(qq);
        rr = tmp.min(rr);

        l_tmp = l_mult(abs_s(sub(tilt, 8192)), sub(26214, shr(voice_factor, 1))); // Q28
        l_tmp = l_add(l_tmp, 268_435_456);
        l_tmp = mult_32_16(l_tmp, rr); // Q23
        let est_level2 = round_word(l_shl(l_tmp, 3)); // Q10

        rr = est_level1.min(est_level2);
    }

    let q1 = norm_s(pp);
    let tmp = div_s(shl(1, sub(14, q1)), pp); // Q(29-q1-10)
    let l_tmp = l_mult(rr, tmp); // Q(30-q1-10+10)

    *sub_gain = 20480.min(round_word(l_shl(l_tmp, sub(q1, 2)))); // Q12
}

/// `AdaptiveStartBand_fx`: adaptively select the start band of the bandwidth extension (the
/// point in the 12.8 kHz excitation spectrum the high band is copied from) from the LSFs
/// (`lsf`, Q2), the voicing factor (Q14) and the signal class, with hysteresis
/// (`voicing_flag`, `start_band_old`, `opt_crit_old`).
pub fn adaptive_start_band(
    start_band: &mut i16,
    rate: i32,
    lsf: &[i16],
    voicing_fac: i16,
    clas: i16,
    voicing_flag: &mut i16,
    start_band_old: &mut i16,
    opt_crit_old: &mut i32,
) {
    let mut lsf_diff = [0i16; M as usize];

    // voicing switching flag: to avoid switching the start band frequently in VOICED or AUDIO
    // areas
    let voicing_flag_old = *voicing_flag;
    if sub(voicing_fac, 6554) > 0
        || (sub(voicing_fac, 4915) > 0 && sub(clas, VOICED_CLAS) >= 0)
        || sub(clas, AUDIO_CLAS) == 0
    {
        *voicing_flag = 1;
    }

    if sub(voicing_fac, 3277) < 0 && sub(clas, VOICED_CLAS) < 0 {
        *voicing_flag = 0;
    }

    // rate adaptive start band
    *start_band = 160;
    if l_sub(rate, i32::from(ACELP_23K05)) < 0 {
        for i in 1..(M as usize - 1) {
            lsf_diff[i] = sub(lsf[i], lsf[i - 1]); // Q2
        }
        let tmp1 = extract_l(mult_32_16(rate, 27046)); // Q14
        let l_tmp = l_shr(l_mult0(tmp1, 22370), 15); // Q27->1/6000 ->Q26
        let tmp2 = extract_l(l_tmp); // Q26
        let mut w_fx = mult_r(tmp1, tmp2); // Q25

        if sub(clas, AUDIO_CLAS) == 0 {
            w_fx = mult_r(w_fx, 24576); // Q25
        }

        let mut m2 = sub(M, 2);
        if sub(*voicing_flag, 1) == 0 {
            if l_sub(rate, i32::from(ACELP_8K85)) <= 0 {
                m2 = sub(M, 8);
            } else if l_sub(rate, i32::from(ACELP_12K65)) <= 0 {
                m2 = sub(M, 6);
            } else if l_sub(rate, i32::from(ACELP_15K85)) <= 0 {
                m2 = sub(M, 4);
            }
        }

        // do the procedure for i==2
        let l_tmp = l_msu(171_798_692, lsf[2], w_fx).max(171_799); // Q2.56+25+1
        let crit = mult_32_16(l_tmp, lsf_diff[2]); // Q2.56+25+1+2.56-15 = Q11+2.56+2.56

        let mut opt_crit = l_add(crit, 0);
        let mut pos: usize = 2;

        for i in 3..m2.max(0) as usize {
            let l_tmp = l_msu(171_798_692, lsf[i], w_fx).max(171_799); // Q2.56+25+1
            let crit = mult_32_16(l_tmp, lsf_diff[i]);
            if l_sub(crit, opt_crit) <= 0 {
                opt_crit = l_add(crit, 0); // Q11+2.56+2.56
                pos = i;
            }
        }

        let tmp1 = add(mult_r(lsf[pos - 1], 256), mult_r(lsf[pos], 256));
        *start_band = sub(tmp1, 40).clamp(40, 160);

        let l_tmp = mult_32_16(*opt_crit_old, 22938); // Q11+2.56+2.56
        if sub(voicing_flag_old, *voicing_flag) != 0
            || (*voicing_flag == 0 && l_sub(opt_crit, *opt_crit_old) < 0)
            || (l_sub(opt_crit, l_tmp) < 0 && l_sub(*opt_crit_old, 858_993) > 0)
        {
            *opt_crit_old = opt_crit;
            if sub(abs_s(sub(*start_band, *start_band_old)), 20) < 0
                && sub(*voicing_flag, 1) == 0
                && sub(voicing_flag_old, 1) == 0
            {
                *start_band = *start_band_old;
            }
        } else {
            if l_sub(opt_crit, *opt_crit_old) < 0 && sub(*voicing_flag, 1) == 0 {
                *opt_crit_old = opt_crit;
            }

            *start_band = *start_band_old;
        }

        if sub(clas, AUDIO_CLAS) == 0 {
            *start_band = (*start_band).min(120);
        }

        let flag = sub(*start_band & 0x0001, 1);
        if flag == 0 {
            *start_band = sub(*start_band, 1);
        }
    }

    *start_band_old = *start_band;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn above_the_adaptive_rates_the_start_band_is_fixed() {
        let lsf = [0i16; M as usize];
        let (mut start_band, mut voicing_flag, mut old, mut crit) = (0i16, 0i16, 7i16, 5i32);
        adaptive_start_band(
            &mut start_band,
            23_850,
            &lsf,
            0,
            0,
            &mut voicing_flag,
            &mut old,
            &mut crit,
        );
        assert_eq!((start_band, old, crit), (160, 160, 5));
    }

    #[test]
    fn the_start_band_is_odd_free_and_inside_its_limits() {
        let lsf: [i16; M as usize] = core::array::from_fn(|i| (800 * (i as i16 + 1)).min(6000));
        let (mut start_band, mut voicing_flag, mut old, mut crit) = (0i16, 0i16, 160i16, 32768i32);
        adaptive_start_band(
            &mut start_band,
            8_850,
            &lsf,
            2000,
            0,
            &mut voicing_flag,
            &mut old,
            &mut crit,
        );
        assert!((40..=160).contains(&start_band));
        assert_eq!(old, start_band);
    }

    #[test]
    fn an_unvoiced_decision_needs_the_level_of_the_original_envelope_above_the_extended_one() {
        let (mut voice_fac, mut unvoicing, mut unvoicing_sm, mut flag) =
            (0i16, 0i16, 32767i16, 1i16);
        let decision = enhance_class(
            100,
            200,
            0,
            0,
            0,
            &mut voice_fac,
            &mut unvoicing,
            &mut unvoicing_sm,
            &mut flag,
        );
        assert!(!decision);
    }
}
