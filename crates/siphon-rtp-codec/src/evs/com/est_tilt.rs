//! Excitation tilt and voicing factor (TS 26.442 `lib_com/est_tilt_fx.c`).

use crate::evs::cnst::L_SUBFR;
use crate::evs::com::math_op::dot_product12;
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, l_mult, l_shl, mult, negate, norm_l, shr, sub,
};
use crate::itu::stl2009::mac_r;

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
