//! Time-domain shaping of the SHB signal (TS 26.442 `lib_com/swb_bwe_com_fx.c`:
//! `time_envelop_shaping_fx`, `time_reduce_pre_echo_fx`; TS 26.445 §6.1.4.1).

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::SWB_TENV;
use crate::evs::com::math_op::isqrt_lc;
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_add, l_deposit_h, l_deposit_l, l_mult, l_shl, l_shr, l_sub, mult_r,
    norm_l, norm_s, round_word, shl, sub,
};
use crate::itu::stl2009::{i_mult, l_mac0};

/// `time_envelop_shaping_fx`: scale each of the `SWB_TENV` quarter-frames of the SHB synthesis
/// `werr` (Q`q_synth`) to the temporal envelope `swb_tenv` (Q15). A quarter-frame whose envelope is
/// below 1.0 and whose energy is below it is left alone and `q_synth` is raised by 3 instead.
pub fn time_envelop_shaping(werr: &mut [i16], swb_tenv: &[i32], l: i16, q_synth: &mut i16) {
    let mut pit: usize = 0;
    let quarter = (l / 4) as usize;
    let exp_l = norm_s(l);
    let inv_l = div_s(shl(1, sub(14, exp_l)), l); // Q(29-exp_L)
    for &tenv in &swb_tenv[..SWB_TENV as usize] {
        let mut energy = l_deposit_l(0);
        for _ in 0..quarter {
            energy = l_mac0(energy, werr[pit], werr[pit]); // (2*Q_synth)
            pit += 1;
        }
        // Q(29-exp_L-15) -> Q(-exp_L+14+2*Q_synth)
        energy = mult_32_16(energy, inv_l);
        let mut energy_16: i16 = 0;
        // exp = 31-(-exp_L+14 +(2*(*Q_synth)))
        let mut exp = sub(17, sub(shl(*q_synth, 1), exp_l));

        if energy != 0 {
            exp = norm_l(energy);
            let frac = extract_h(l_shl(energy, exp));
            // exp = sub(exp, 30-(-exp_L+14-2+(2*(*Q_synth))))
            exp = sub(exp, sub(30, add(sub(shl(*q_synth, 1), exp_l), 14 - 2)));

            let tmp = div_s(16384, frac);
            let l_tmp = l_deposit_h(tmp);
            energy = isqrt_lc(l_tmp, &mut exp); // Q(31-exp)
            energy_16 = round_word(l_shl(energy, sub(exp, 15))); // Q0
        }

        if l_sub(tenv, 65536) < 0 && l_sub(energy, l_shl(tenv, sub(16, exp))) < 0 {
            *q_synth = add(*q_synth, 3);
        } else {
            pit -= quarter;
            let mut tmp_ener: i16 = 0;
            let mut exp: i16 = 0;
            if energy_16 != 0 {
                exp = norm_s(energy_16);
                tmp_ener = div_s(shl(1, sub(14, exp)), energy_16); // Q(29-exp)
            }
            let l_tmp = mult_32_16(tenv, tmp_ener); // Q(29-exp)
            let tmp = round_word(l_tmp); // Q(13-exp)
            for _ in 0..quarter {
                // Q(13-exp+1)->Q(14-exp)->Qsyn-3
                werr[pit] = round_word(l_shl(l_mult(tmp, werr[pit]), sub(exp, 1)));
                pit += 1;
            }
        }
    }
}

/// `time_reduce_pre_echo_fx` part 1: the four sub-frame RMS values of the core synthesis (Q15).
fn time_reduce_pre_echo_rms(synth: &[i16], l: i16, q_syn: i16) -> [i32; 4] {
    let exp_l = norm_s(l);
    let inv_l = div_s(shl(1, sub(14, exp_l)), l); // Q(29-exp_L)
    let mut energy_l = [0_i32; 4];
    for (i, slot) in energy_l.iter_mut().enumerate() {
        let len = i_mult(l, i as i16) as usize;
        let mut l_tmp = l_deposit_l(0);
        for &value in &synth[len..len + l as usize] {
            l_tmp = l_mac0(l_tmp, value, value); // 2*Q_syn
        }
        // Q(2*Q_syn +29-exp_L-15 - (14-exp_L) ) -> Q(2*Q_syn)
        *slot = mult_32_16(l_shr(l_tmp, sub(14, exp_l)), inv_l);
        if *slot != 0 {
            let mut exp = norm_l(*slot);
            let frac = extract_h(l_shl(*slot, exp));
            exp = sub(exp, sub(30, shl(q_syn, 1)));
            let tmp = div_s(16384, frac);
            let l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp);
            *slot = l_shl(l_tmp, sub(exp, 16)); // Q15
        }
    }
    energy_l
}

/// Q0 RMS of `error[from..from + count]` (`2*Q_synth` energy scaled by `1/count`), the
/// `Energy_16` computation `time_reduce_pre_echo_fx` repeats for both windows.
fn time_reduce_pre_echo_energy_16(
    error: &[i16],
    from: usize,
    count: usize,
    inv_count: i16,
    exp_count: i16,
    q_synth: i16,
) -> i16 {
    let mut energy = l_deposit_l(0);
    for &value in &error[from..from + count] {
        energy = l_mac0(energy, value, value); // Q(2*Q_synth)
    }
    // Q(29-exp+1-16) -> Q(-exp+14 +2*Q_synth)
    energy = mult_32_16(energy, inv_count);
    let mut energy_16: i16 = 0;
    if energy != 0 {
        let mut exp = norm_l(energy);
        let frac = extract_h(l_shl(energy, exp));
        // exp = sub(exp, 30-(-exp+14 +2*Q_synth))
        exp = sub(exp, sub(14, sub(shl(q_synth, 1), exp_count)));
        let tmp = div_s(16384, frac);
        let l_tmp = l_deposit_h(tmp);
        energy = isqrt_lc(l_tmp, &mut exp); // Q(31-exp)
        energy_16 = round_word(l_shl(energy, sub(exp, 15))); // Q0
    }
    energy_16
}

/// `time_reduce_pre_echo_fx`: when the core synthesis `synth` (Q`q_syn`) shows an energy onset in
/// sub-frame `pos`, scale the SHB synthesis `error` (Q`q_synth`) before it down to the pre-onset
/// level and cross-fade over the next sub-frame. `prev_td_energy` is passed by value in the
/// reference, so the clamp applied to it is local.
pub fn time_reduce_pre_echo(
    synth: &[i16],
    error: &mut [i16],
    mut prev_td_energy: i16,
    l: i16,
    q_syn: i16,
    q_synth: i16,
) {
    let exp_l = norm_s(l);
    let inv_l = div_s(shl(1, sub(14, exp_l)), l); // Q(29-exp_L)
    let energy_l = time_reduce_pre_echo_rms(synth, l, q_syn);

    let mut pos: i16 = 0;
    for i in 0..3 {
        let l_tmp = mult_32_16(energy_l[i], 29491); // Q14
        if l_sub(l_shr(energy_l[i + 1], 1), l_tmp) > 0 && l_sub(energy_l[i + 1], 1_638_400) > 0 {
            pos = add(i as i16, 1);
            break;
        }
    }

    if pos > 0 {
        if sub(pos, 3) < 0 {
            pos = add(pos, 1);
        }
        let j = i_mult(l, pos);
        let exp_j = norm_s(j);
        let inv_j = div_s(shl(1, sub(14, exp_j)), j); // Q(29-exp_j)
        let energy_16 = time_reduce_pre_echo_energy_16(error, 0, j as usize, inv_j, exp_j, q_synth);

        let tmp = mult_r(energy_16, 6554); // Q0
        if sub(prev_td_energy, tmp) < 0 {
            prev_td_energy = tmp;
        }

        let mut tmp_ener: i16 = 0;
        let mut exp: i16 = 0;
        if energy_16 != 0 {
            exp = norm_s(energy_16);
            tmp_ener = div_s(shl(1, sub(14, exp)), energy_16); // Q(29-exp)
        }
        let l_tmp = l_mult(prev_td_energy, tmp_ener); // Q(30-exp)
        let tmp_exp = add(1, exp);
        for slot in &mut error[..j as usize] {
            // Q(30-exp+1-16)->Q(15-exp)->Q_synth
            *slot = round_word(l_shl(mult_32_16(l_tmp, *slot), tmp_exp));
        }

        let energy_16 =
            time_reduce_pre_echo_energy_16(error, j as usize, l as usize, inv_l, exp_l, q_synth);
        let mut tmp_ener: i16 = 0;
        let mut exp: i16 = 0;
        if energy_16 != 0 {
            exp = norm_s(energy_16);
            tmp_ener = div_s(shl(1, sub(14, exp)), energy_16); // Q(29-exp)
        }
        let l_tmp_ener = l_mult(prev_td_energy, tmp_ener); // Q(30-exp)
        let l_tmp1 = l_shl(1, sub(30, exp));

        for i in 0..l {
            // Q15
            let tmpi = round_word(l_shl(l_mult(i, inv_l), add(1, exp_l)));
            let l_tmp = l_sub(l_tmp1, l_tmp_ener); // Q(30-exp)
            let l_tmp = mult_32_16(l_tmp, tmpi); // Q(30-exp)
            let l_tmp = l_add(l_tmp_ener, l_tmp); // Q(30-exp)
            let slot = &mut error[j as usize + i as usize];
            *slot = round_word(l_shl(mult_32_16(l_tmp, *slot), add(1, exp))); // Q0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silent_input_is_left_untouched_by_pre_echo_reduction() {
        let synth = [0_i16; 320];
        let mut error = [123_i16; 320];
        time_reduce_pre_echo(&synth, &mut error, 10, 80, 12, 12);
        assert!(error.iter().all(|&value| value == 123));
    }

    #[test]
    fn low_energy_quarter_frames_only_raise_the_q_format() {
        let mut werr = [0_i16; 320];
        let tenv = [1000_i32; 4];
        let mut q_synth = 5;
        time_envelop_shaping(&mut werr, &tenv, 320, &mut q_synth);
        assert_eq!(q_synth, 5 + 3 * 4);
    }
}
