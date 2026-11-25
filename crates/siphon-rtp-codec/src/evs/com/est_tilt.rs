//! Excitation tilt and voicing factor (TS 26.442 `lib_com/est_tilt_fx.c`).

use crate::evs::basop::{mpy_32_16_1, mpy_32_32};
use crate::evs::cnst::L_SUBFR;
use crate::evs::com::basop_util::divide3232;
use crate::evs::com::math_op::dot_product12;
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, l_add, l_deposit_l, l_mult, l_shl, l_shr, l_sub, mult, mult_r,
    negate, norm_l, norm_s, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0, mac_r};

/// `est_tilt_fx`: the voicing factor `(E_pit - E_code) / (E_pit + E_code)` (Q15, written to
/// `voice_fac`) from the adaptive excitation `exc` (Q`Q_exc`) scaled by `gain_pit` (Q14) and the
/// innovation `code` (Q9) scaled by `gain_code` (Q16), over one `L_SUBFR` subframe; returns the
/// tilt `0.25·(1 + voice_fac)` (Q15).
#[must_use]
pub fn est_tilt(
    exc: &[i16],
    gain_pit: i16,
    code: &[i16],
    gain_code: i32,
    voice_fac: &mut i16,
    q_exc: i16,
) -> i16 {
    let mut exp1 = 0;
    let mut ener1 = extract_h(dot_product12(exc, exc, L_SUBFR, &mut exp1));
    exp1 = sub(exp1, add(q_exc, q_exc));
    let l_tmp = l_mult(gain_pit, gain_pit);
    let mut exp = norm_l(l_tmp);
    let mut tmp = extract_h(l_shl(l_tmp, exp));
    ener1 = mult(ener1, tmp);
    exp1 = sub(sub(exp1, exp), 10);

    let mut exp2 = 0;
    let mut ener2 = extract_h(dot_product12(code, code, L_SUBFR, &mut exp2));
    exp = norm_l(gain_code);
    tmp = extract_h(l_shl(gain_code, exp));
    tmp = mult(tmp, tmp);
    ener2 = mult(ener2, tmp);
    exp2 = sub(exp2, add(exp, exp));

    let i = sub(exp1, exp2);
    ener1 = shr(ener1, sub(1, i.min(0)));
    ener2 = shr(ener2, add(i.max(0), 1));
    tmp = sub(ener1, ener2);
    ener1 = add(add(ener1, ener2), 1);
    exp = div_s(abs_s(tmp), ener1);
    if tmp < 0 {
        exp = negate(exp);
    }
    *voice_fac = exp;
    mac_r(8192 * 65536 - 0x8000, *voice_fac, 8192)
}

/// `E_UTIL_voice_factor`: the voicing factor `voice_fac` (Q15, `(E_pit - E_code) / (E_pit +
/// E_code)`) of the subframe at `exc[i_subfr..]` (adaptive excitation, Q`Q_new`, optionally scaled
/// down by `shift`) and the innovation `code` (Q9), with their gains, and the tilt `tilt_code` of
/// the code for the next subframe: `flag_tilt` 0 spans 0 (unvoiced) to 0.5 (voiced), 1 spans 0.25
/// to 0.5 and anything else 0.28 to 0.56.
pub fn e_util_voice_factor(
    exc: &[i16],
    i_subfr: i16,
    code: &[i16],
    gain_pit: i16,
    gain_code: i32,
    voice_fac: &mut i16,
    tilt_code: &mut i16,
    l_subfr: i16,
    flag_tilt: i16,
    q_new: i16,
    shift: i16,
) {
    let start = i_subfr.max(0) as usize;
    let count = l_subfr.max(0) as usize;
    let frame = &exc[start..start + count];

    let mut ener: i32;
    if shift != 0 {
        let fac = shl(0x4000, add(1, shift));
        // energy of pitch excitation
        let mut stmp = mult_r(frame[0], fac); // remove fac bits
        ener = l_mac0(0, stmp, stmp);
        for &sample in &frame[1..] {
            stmp = mult_r(sample, fac); // remove fac bits
            ener = l_mac0(ener, stmp, stmp);
        }
    } else {
        ener = l_mult0(frame[0], frame[0]);
        for &sample in &frame[1..] {
            ener = l_mac0(ener, sample, sample); // Q_new -> exponent = (15-Q_new)*2+1
        }
    }

    // exponent of ener: (2*(15-Q_new+shift)+1+2-exp_ener-2*e2)
    let mut exp_ener = norm_l(ener);
    if ener == 0 {
        exp_ener = 31;
    }
    ener = l_shl(ener, exp_ener);
    let e2 = norm_s(gain_pit);
    let gain_pit = shl(gain_pit, e2);
    ener = mpy_32_16_1(ener, mult_r(gain_pit, gain_pit));

    // energy of innovative code excitation
    let mut tmp = l_deposit_l(1);

    for &value in &code[..count] {
        tmp = l_mac0(tmp, value, value); // 6Q9 -> 13Q18
    }
    // exponent of tmp: 2*(15-9)+1+2*(15-e))
    let e = norm_l(gain_code);
    let gain_code = l_shl(gain_code, e);
    tmp = mpy_32_32(tmp, mpy_32_32(gain_code, gain_code));

    // find voice factor (1=voiced, -1=unvoiced)
    // i = (2*(15-Q_new+shift)+1+2-exp_ener-2*e2) - (2*(15-9)+1 + 2*(15-e));
    let i = sub(
        sub(
            sub(sub(sub(33, add(shift, shift)), add(q_new, q_new)), exp_ener),
            add(e2, e2),
        ),
        sub(43, add(e, e)),
    );
    if i >= 0 {
        ener = l_shr(ener, 1);
        tmp = l_shr(tmp, add(1, i));
    } else {
        tmp = l_shr(tmp, 1);
        ener = l_shr(ener, sub(1, i));
    }

    *voice_fac = 0;
    let num = l_sub(ener, tmp);
    if num != 0 {
        // Allow saturating the voice factor because it has a limited range by definition.
        *voice_fac = divide3232(num, l_add(ener, tmp));
    }

    // find tilt of code for next subframe
    if flag_tilt == 0 {
        // Between 0 (=unvoiced) and 0.5 (=voiced)
        *tilt_code = add(8192, mult_r(8192, *voice_fac));
    } else if flag_tilt == 1 {
        // Between 0.25 (=unvoiced) and 0.5 (=voiced)
        *tilt_code = add(mult_r(4096, *voice_fac), 12288);
    } else {
        // Between 0.28 (=unvoiced) and 0.56 (=voiced)
        *tilt_code = add(mult_r(4588, *voice_fac), 13763);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silent_subframe_is_unvoiced_with_the_lowest_tilt() {
        let exc = [0i16; 64];
        let code = [0i16; 64];
        let (mut voice_fac, mut tilt_code) = (99, 99);
        e_util_voice_factor(
            &exc,
            0,
            &code,
            0,
            0,
            &mut voice_fac,
            &mut tilt_code,
            64,
            0,
            0,
            0,
        );
        // Both energies are zero, so the factor stays 0 and the tilt is 0.25.
        assert_eq!(voice_fac, 0);
        assert_eq!(tilt_code, 8192);
    }
}
