//! The TCX forward and inverse MDCT / MDST on windowed time signals, folded onto a DCT-IV / DST-IV
//! (TS 26.442 `lib_com/tcx_mdct.c`; TS 26.445 §5.3.3.2.3 and §6.2.4).

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{L_MDCT_OVLP_MAX, NORM_MDCT_FACTOR, N_MAX};
use crate::evs::com::basop_util::{isqrt16, sqrt16};
use crate::evs::com::edct::{edct, edct_in_place, edst_in_place};
use crate::itu::basic_ops::{
    add, l_mac, l_msu, l_mult, l_shl, mult_r, negate, round_word, shl, shr, sub,
};

/// `TCX_MDCT_GetScaleFactor`: the normalisation `sqrt(NORM_MDCT_FACTOR / L)` of the forward
/// transform of length `l`, as a mantissa and `*factor_e`.
fn tcx_mdct_get_scale_factor(l: i16, factor_e: &mut i16) -> i16 {
    if sub(l, NORM_MDCT_FACTOR) == 0 {
        *factor_e = 0;
        32767
    } else if sub(l, 2 * NORM_MDCT_FACTOR) == 0 {
        *factor_e = 0;
        23170
    } else if sub(l, 4 * NORM_MDCT_FACTOR) == 0 {
        *factor_e = 0;
        16384
    } else {
        let factor = mult_r(shl(l, 4), 26214 /* 128.f / NORM_MDCT_FACTOR */); // 4Q11
        *factor_e = 4;
        isqrt16(factor, factor_e)
    }
}

/// `TCX_MDCT_Inverse_GetScaleFactor`: the normalisation `sqrt(L / NORM_MDCT_FACTOR)` of the
/// inverse transform of length `l`, as a mantissa and `*factor_e`.
fn tcx_mdct_inverse_get_scale_factor(l: i16, factor_e: &mut i16) -> i16 {
    if sub(l, NORM_MDCT_FACTOR) == 0 {
        *factor_e = 0;
        32767
    } else if sub(l, 2 * NORM_MDCT_FACTOR) == 0 {
        *factor_e = 1;
        23170
    } else if sub(l, 4 * NORM_MDCT_FACTOR) == 0 {
        *factor_e = 1;
        32767
    } else {
        let factor = mult_r(shl(l, 4), 26214 /* 128.f / NORM_MDCT_FACTOR */); // 4Q11
        *factor_e = 4;
        sqrt16(factor, factor_e)
    }
}

/// `TCX_MDCT`: the MDCT of the `l + m + r` windowed samples `x` (left overlap `l`, flat part `m`,
/// right overlap `r`) into `y[0..l/2 + m + r/2]`; `*y_e` is the input's exponent on entry and the
/// output's on return.
pub fn tcx_mdct(x: &[i16], y: &mut [i32], y_e: &mut i16, l: i16, m: i16, r: i16) {
    let mut factor_e = 0;
    let factor = tcx_mdct_get_scale_factor(add(add(shr(l, 1), m), shr(r, 1)), &mut factor_e);
    *y_e = add(*y_e, factor_e);

    let neg_factor = negate(factor);
    let (l, m, r) = (l as usize, m as usize, r as usize);

    // Init
    for i in 0..m / 2 {
        y[m / 2 + r / 2 + i] = l_mult(x[l + m / 2 - 1 - i], neg_factor);
    }
    for i in 0..l / 2 {
        y[m / 2 + r / 2 + m / 2 + i] = l_msu(l_mult(x[i], factor), x[l - 1 - i], factor);
    }
    for i in 0..m / 2 {
        y[m / 2 + r / 2 - 1 - i] = l_mult(x[l + m / 2 + i], neg_factor);
    }
    for i in 0..r / 2 {
        y[m / 2 + r / 2 - 1 - m / 2 - i] = l_mac(
            l_mult(x[l + m + i], neg_factor),
            x[l + m + r - 1 - i],
            neg_factor,
        );
    }

    *y_e = sub(15, *y_e);
    edct_in_place(y, (l / 2 + m + r / 2) as i16, y_e);
    *y_e = sub(15 - 1, *y_e);
}

/// `TCX_MDST`: [`tcx_mdct`] with the sine transform (the MDST spectrum TCX uses for the
/// intensity-stereo-like and LTP side analysis).
pub fn tcx_mdst(x: &[i16], y: &mut [i32], y_e: &mut i16, l: i16, m: i16, r: i16) {
    let mut factor_e = 0;
    let factor = tcx_mdct_get_scale_factor(add(add(shr(l, 1), m), shr(r, 1)), &mut factor_e);
    *y_e = add(*y_e, factor_e);
    let neg_factor = negate(factor);
    let (l, m, r) = (l as usize, m as usize, r as usize);

    // Init
    for i in 0..m / 2 {
        y[m / 2 + r / 2 + i] = l_mult(x[l + m / 2 - 1 - i], neg_factor);
    }
    for i in 0..l / 2 {
        y[m / 2 + r / 2 + m / 2 + i] = l_msu(l_mult(x[i], neg_factor), x[l - 1 - i], factor);
    }
    for i in 0..m / 2 {
        y[m / 2 + r / 2 - 1 - i] = l_mult(x[l + m / 2 + i], neg_factor);
    }
    for i in 0..r / 2 {
        y[m / 2 + r / 2 - 1 - m / 2 - i] = l_mac(
            l_mult(x[l + m + i], neg_factor),
            x[l + m + r - 1 - i],
            factor,
        );
    }

    *y_e = sub(15, *y_e);
    edst_in_place(y, (l / 2 + m + r / 2) as i16, y_e);
    *y_e = sub(15 - 1, *y_e);
}

/// `TCX_MDCT_Inverse`: the inverse MDCT of `x[0..l/2 + m + r/2]` (exponent `x_e`) into the
/// `l + m + r` time samples `y`, unfolded. `x` is left as it was.
pub fn tcx_mdct_inverse(x: &[i32], x_e: i16, y: &mut [i16], l: i16, m: i16, r: i16) {
    let mut tmp_buf = [0i32; N_MAX as usize + L_MDCT_OVLP_MAX as usize / 2];

    let l2 = shr(l, 1);
    let r2 = shr(r, 1);

    let mut x_e = sub(15, x_e);
    edct(x, &mut tmp_buf[l2 as usize..], l / 2 + m + r / 2, &mut x_e);
    x_e = sub(15, x_e);

    let mut fac_e = 0;
    let fac = tcx_mdct_inverse_get_scale_factor(add(add(shr(l, 1), m), shr(r, 1)), &mut fac_e);
    x_e = add(x_e, fac_e);

    let negfac = negate(fac);

    let s = x_e;
    let (l, m, l2, r2) = (l as usize, m as usize, l2 as usize, r2 as usize);

    for i in 0..r2 {
        y[l + m + r2 + i] = round_word(l_shl(mpy_32_16_1(tmp_buf[l2 + i], negfac), s));
        // fold out right end of DCT
    }

    for i in 0..l2 {
        y[i] = round_word(l_shl(mpy_32_16_1(tmp_buf[l2 + m + r2 + i], fac), s));
        // negate, fold out left end of DCT
    }

    for i in 0..shr(add(l2 as i16, add(m as i16, r2 as i16)), 1) as usize {
        let f = round_word(l_shl(mpy_32_16_1(tmp_buf[l2 + i], negfac), s));

        y[l2 + i] = round_word(l_shl(mpy_32_16_1(tmp_buf[l + m + r2 - 1 - i], negfac), s)); // time-reverse mid of DCT

        y[l + m + r2 - 1 - i] = f;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_factors_of_the_tabulated_lengths() {
        let mut e = 9;
        assert_eq!(tcx_mdct_get_scale_factor(160, &mut e), 32767);
        assert_eq!(e, 0);
        assert_eq!(tcx_mdct_get_scale_factor(320, &mut e), 23170);
        assert_eq!(tcx_mdct_get_scale_factor(640, &mut e), 16384);
        assert_eq!(tcx_mdct_inverse_get_scale_factor(320, &mut e), 23170);
        assert_eq!(e, 1);
        assert_eq!(tcx_mdct_inverse_get_scale_factor(640, &mut e), 32767);
        assert_eq!(e, 1);
    }

    #[test]
    fn a_silent_frame_stays_silent() {
        let x = [0i16; 320];
        let mut y = [1i32; 320];
        let mut y_e = 0;
        tcx_mdct(&x, &mut y, &mut y_e, 0, 320, 0);
        assert!(y.iter().all(|&v| v == 0));
    }
}
