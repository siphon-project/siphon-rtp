//! Estimation of the voicing (mixing) factors at the higher SHB bit rates (TS 26.442
//! `lib_com/swb_tbe_com_fx.c`, `Estimate_mix_factors_fx`).

use crate::evs::basop::mult_32_16;
use crate::evs::com::tools::{dot_product, root_a_over_b, usquant};
use crate::itu::basic_ops::{
    div_s, extract_h, l_shl, l_sub, negate, norm_l, round_word, shl, shr, sub,
};

/// `Estimate_mix_factors_fx`: the voicing factor of the 320-sample SHB residual `shb_res` (Q`q_shb`)
/// against the whitened excitation `exc16k_whtnd` and the noise `white_exc16k_frac`, quantised
/// into `vf_ind` and written to the five entries of `vf_modified`.
pub fn estimate_mix_factors(
    shb_res: &[i16],
    q_shb: i16,
    exc16k_whtnd: &[i16],
    q_bwe_exc: i16,
    white_exc16k_frac: &[i16],
    q_frac: i16,
    pow1: i32,
    q_pow1: i16,
    pow22: i32,
    q_pow22: i16,
    vf_modified: &mut [i16],
    vf_ind: &mut i16,
) {
    let mut shb_res_local = [0i16; 320];
    let mut wn_exc_local = [0i16; 320];
    let mut temp_numer1 = [0i16; 320];
    let mut temp_numer2 = [0i16; 320];
    let mut exp1: i16 = 0;
    let mut exp2: i16 = 0;

    shb_res_local.copy_from_slice(&shb_res[..320]);
    wn_exc_local.copy_from_slice(&white_exc16k_frac[..320]);

    let mut pow3 = dot_product(&shb_res_local, &shb_res_local, 320);
    // a plain C `+=`: the sum wraps rather than saturates
    pow3 = pow3.wrapping_add(l_shl(21475, 2 * q_shb + 1 - 31));
    if pow3 == 0 {
        pow3 = 1;
    }

    let mut temp_p1_p2 = root_a_over_b(pow1, q_pow1, pow22, q_pow22, &mut exp1);
    let mut temp_p1_p3 = root_a_over_b(pow1, q_pow1, pow3, 2 * q_shb + 1, &mut exp2);

    let sc1 = q_bwe_exc - (q_frac - exp1);
    let sc2 = q_bwe_exc - (q_shb - exp2);

    for i in 0..320 {
        let l_tmp1 = mult_32_16(temp_p1_p2, wn_exc_local[i]);
        wn_exc_local[i] = round_word(l_tmp1);
        let l_tmp2 = mult_32_16(temp_p1_p3, shb_res_local[i]);
        shb_res_local[i] = round_word(l_tmp2);

        temp_numer1[i] = round_word(l_sub(l_shl(l_tmp2, sc2), l_shl(l_tmp1, sc1)));
        temp_numer2[i] = sub(exc16k_whtnd[i], round_word(l_shl(l_tmp1, sc1)));
    }

    let length: i16 = 320;
    temp_p1_p2 = dot_product(&temp_numer1, &temp_numer2, length);
    temp_p1_p3 = dot_product(&temp_numer2, &temp_numer2, length);

    let mut tmp: i16;
    if temp_p1_p3 > 0 {
        let mut expa = norm_l(temp_p1_p3);
        let mut fraca = extract_h(l_shl(temp_p1_p3, expa));
        expa = sub(30, expa);

        let mut expb = norm_l(temp_p1_p2);
        let mut fracb = round_word(l_shl(temp_p1_p2, expb));
        expb = sub(30, expb);

        let mut num_flag = 0;
        if fraca < 0 {
            num_flag = 1;
            fraca = negate(fraca);
        }
        let mut den_flag = 0;
        if fracb < 0 {
            den_flag = 1;
            fracb = negate(fracb);
        }

        let scale = shr(sub(fraca, fracb), 15);
        fracb = shl(fracb, scale);
        expb = sub(expb, scale);

        tmp = div_s(fracb, fraca);
        exp1 = sub(expb, expa);
        tmp = shl(tmp, exp1);
        if sub(num_flag, den_flag) != 0 {
            tmp = negate(tmp);
        }
    } else {
        tmp = 0;
    }

    vf_modified[0] = tmp.clamp(3277, 32440);
    let mut tmp1: i16 = 0;
    *vf_ind = usquant(vf_modified[0], &mut tmp1, 4096, 2048, shl(1, 3));
    for value in vf_modified.iter_mut().take(5) {
        *value = tmp1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silent_input_gives_the_lowest_voicing_class() {
        let zeros = [0i16; 320];
        let mut vf = [9i16; 5];
        let mut index = 0;
        estimate_mix_factors(
            &zeros, 10, &zeros, 8, &zeros, 8, 100, 20, 100, 20, &mut vf, &mut index,
        );
        assert!(vf.iter().all(|&value| value == vf[0]));
        assert!((0..8).contains(&index));
    }
}
