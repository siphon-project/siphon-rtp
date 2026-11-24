//! Mantissa/exponent arithmetic, logarithms, divisions and scaling helpers of the BASOP framework
//! (TS 26.442 `lib_com/basop_util.c`).
//!
//! Only the functions the decoder executes are ported. The reference `assert`s its preconditions;
//! where a violated one would index a table out of range the Rust clamps the index instead, which
//! changes nothing for an input the reference accepts.

use crate::evs::basop::{mpy_32_16_1, mpy_32_32, mult_32_16};
use crate::evs::cnst::LD_DATA_SCALE;
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::rom::{
    BASOP_UTIL_NORMRECIPROCAL, EXP2W_TAB_LONG, EXP2X_TAB_LONG, EXP2_TAB_LONG, INVDIFFTABLE,
    INVTABLE, ISQRTDIFFTABLE, ISQRTTABLE, LDCOEFF, SINETABLE512, SQRTDIFFTABLE, SQRTTABLE,
};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_l, l_mac, l_msu, l_mult,
    l_shl, l_shr, l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{
    div_l, l_add_c, l_lshl, l_lshr, l_mac0, l_mac_ns, l_msu0, l_msu_ns, l_mult0, mac_r, msu_r,
    StlFlags,
};

/// `LD`: log2 of the sine table's quarter-wave length (`SINETAB` = `SineTable512`).
const LD: i16 = 9;

/// `BASOP_Util_Log2`: `log2(x) / 64` in Q31 (`LD_DATA_SCALE` = 6) for `x >= 0` in Q31;
/// `MIN_32` for zero.
#[must_use]
pub fn basop_util_log2(x: i32) -> i32 {
    if x == 0 {
        return i32::MIN;
    }
    // normalize input, calculate integer part
    let exp_e = norm_l(x);
    let x = l_shl(x, exp_e);
    let mut exp = l_deposit_l(exp_e);

    // calculate (1-normalized_input)
    let n_in = extract_h(l_sub(i32::MAX, x));

    // approximate ln() for the fractional part (nIn*c0 + nIn^2*c1 + ... )
    let mut accu_res = l_mult(n_in, LDCOEFF[0]);
    let mut accu_sqr = mult(n_in, n_in);
    for &coefficient in &LDCOEFF[1..6] {
        accu_res = l_mac(accu_res, accu_sqr, coefficient);
        accu_sqr = mult(accu_sqr, n_in);
    }
    accu_res = l_mac(accu_res, accu_sqr, LDCOEFF[6]);

    // ld(fractional part) = ln(fractional part)/ln(2), 1/ln(2) = (1 + 0.44269504)
    accu_res = l_mac0(l_shr(accu_res, 1), extract_h(accu_res), 14506);

    accu_res = l_shr(accu_res, LD_DATA_SCALE - 1); // fractional part/LD_DATA_SCALE
    exp = l_shl(exp, 31 - LD_DATA_SCALE); // integer part/LD_DATA_SCALE
    l_sub(accu_res, exp)
}

/// `BASOP_Util_InvLog2`: `2^(64·x)` for `x` in Q31 (scaled by `LD_DATA_SCALE`), as an integer
/// mantissa; 0 below -31/64, `MAX_32` at or above 31/64 and for zero.
#[must_use]
pub fn basop_util_inv_log2(x: i32) -> i32 {
    if x < -1_040_187_392 {
        return 0;
    }
    if l_sub(x, 1_040_187_392) >= 0 || x == 0 {
        return 0x7FFF_FFFF;
    }

    let frac = extract_l(x & 0x3FF);

    let index3 = (l_shr(x, 10) & 0x1F) as usize;
    let index2 = (l_shr(x, 15) & 0x1F) as usize;
    let index1 = (l_shr(x, 20) & 0x1F) as usize;

    let mut exp = extract_l(l_shr(x, 25));
    if x > 0 {
        exp = sub(31, exp);
    }
    if x < 0 {
        exp = negate(exp);
    }

    // The tables are UWord32; the reference hands them to Word32 operators unchanged.
    let lookup3f = l_add(
        EXP2X_TAB_LONG[index3] as i32,
        l_shr(mpy_32_16_1(0x0016_302F, frac), 1),
    );
    let lookup12 = mpy_32_32(EXP2_TAB_LONG[index1] as i32, EXP2W_TAB_LONG[index2] as i32);
    let lookup = mpy_32_32(lookup12, lookup3f);

    l_shr(lookup, sub(exp, 3))
}

/// `BASOP_Util_Divide_MantExp`: `a / b` on 16-bit mantissa/exponent pairs (`b_m != 0`), by a
/// table-interpolated reciprocal of `b`.
pub fn basop_util_divide_mant_exp(
    a_m: i16,
    a_e: i16,
    b_m: i16,
    b_e: i16,
    ptr_result_m: &mut i16,
    ptr_result_e: &mut i16,
) {
    // normalize b
    let pre_shift = norm_s(b_m);
    let mut m = shl(b_m, pre_shift);

    // make b positive
    if m < 0 {
        m = negate(m);
    }

    // get table index (upper 6 bits minus 32): index = (m >> 9) - 32
    let index = mac_r(-32768 - (32 << 16), m, 1 << 6);
    // b_m == 0 (excluded by the reference's assert) would index -32
    let index = index.clamp(0, 31) as usize;

    // get fractional part for interpolation (lower 9 bits)
    let frac = shl(m & 0x1FF, 1); // Q10

    // interpolate 1/b
    m = msu_r(INVTABLE[index], INVDIFFTABLE[index], frac);

    // restore sign
    if b_m < 0 {
        m = negate(m);
    }

    // multiply with a
    let m32 = l_mult(a_m, m);

    // normalize result
    let post_shift = norm_l(m32);
    m = round_word(l_shl(m32, post_shift));

    *ptr_result_e = sub(add(add(a_e, sub(1, b_e)), pre_shift), post_shift);
    *ptr_result_m = m;
}

/// `Sqrt32_common`: the square-root mantissa of a normalised `m` (`m >= 2^30` or zero) with
/// exponent `e`, by table interpolation; an odd exponent multiplies by `sqrt(1/2)`.
#[must_use]
pub fn sqrt32_common(m: i32, e: i16) -> i32 {
    let mut m = m;
    let m16 = round_word(m);

    // get table index (upper 6 bits minus 32): index = (m16 >> 9) - 32
    let index = mac_r(-32768 - (32 << 16), m16, 1 << 6);

    // get fractional part for interpolation (lower 9 bits)
    let frac = m16 & 0x1FF; // Q9

    // interpolate (the table is not read for m == 0, whose index is -32)
    if m != 0 {
        let index = index.clamp(0, 31) as usize;
        m = l_mac(SQRTTABLE[index], SQRTDIFFTABLE[index], frac);
    }

    // handle odd exponents
    if e & 1 != 0 {
        m = mpy_32_16_1(m, 0x5a82);
    }
    m
}

/// `Sqrt32`: square root of `mantissa · 2^exponent` (`mantissa >= 0`); the result's exponent is
/// written back to `exponent`.
pub fn sqrt32(mantissa: i32, exponent: &mut i16) -> i32 {
    // normalize
    let pre_shift = norm_l(mantissa);
    let e = sub(*exponent, pre_shift);
    let mantissa = l_shl(mantissa, pre_shift);

    // calc mantissa
    let mantissa = sqrt32_common(mantissa, e);

    // e = (e + 1) >> 1
    *exponent = mult_r(e, 1 << 14);
    mantissa
}

/// `Sqrt16_common`: the 16-bit square-root mantissa of a normalised `m` (`m >= 2^14` or zero) with
/// exponent `e`, by table interpolation; an odd exponent multiplies by `sqrt(1/2)`.
#[must_use]
pub fn sqrt16_common(m: i16, e: i16) -> i16 {
    let mut m = m;

    // get table index (upper 6 bits minus 32): index = (m >> 9) - 32
    let index = mac_r(-32768 - (32 << 16), m, 1 << 6);

    // get fractional part for interpolation (lower 9 bits)
    let frac = m & 0x1FF; // Q9

    // interpolate (the table is not read for m == 0, whose index is -32)
    if m != 0 {
        let index = index.clamp(0, 31) as usize;
        m = mac_r(SQRTTABLE[index], SQRTDIFFTABLE[index], frac);
    }

    // handle odd exponents
    if e & 1 != 0 {
        m = mult_r(m, 0x5a82);
    }
    m
}

/// `Sqrt16`: square root of `mantissa · 2^exponent` (`mantissa >= 0`); the result's exponent is
/// written back to `exponent`.
pub fn sqrt16(mantissa: i16, exponent: &mut i16) -> i16 {
    // normalize
    let pre_shift = norm_s(mantissa);
    let e = sub(*exponent, pre_shift);
    let mantissa = shl(mantissa, pre_shift);

    // calc mantissa
    let mantissa = sqrt16_common(mantissa, e);

    // e = (e + 1) >> 1
    *exponent = mult_r(e, 1 << 14);
    mantissa
}

/// `getScaleFactor16`: headroom of `x[0..len_x]` in `[0, 15]`, 0 if all values are zero.
#[must_use]
pub fn get_scale_factor16(x: &[i16], len_x: i16) -> i16 {
    let mut x_max: i16 = 0;
    let mut x_min: i16 = 0;
    for &value in &x[..len_x.max(0) as usize] {
        if value >= 0 {
            x_max = x_max.max(value);
        }
        if value < 0 {
            x_min = x_min.min(value);
        }
    }
    let mut i_max = 0x10;
    let mut i_min = 0x10;
    if x_max != 0 {
        i_max = norm_s(x_max);
    }
    if x_min != 0 {
        i_min = norm_s(x_min);
    }
    i_max.min(i_min) & 0xF
}

/// `getScaleFactor32`: headroom of `x[0..len_x]` in `[0, 31]`, 0 if all values are zero.
#[must_use]
pub fn get_scale_factor32(x: &[i32], len_x: i16) -> i16 {
    let mut x_max: i32 = 0;
    let mut x_min: i32 = 0;
    for &value in &x[..len_x.max(0) as usize] {
        if value >= 0 {
            x_max = x_max.max(value);
        }
        if value < 0 {
            x_min = x_min.min(value);
        }
    }
    let mut i_max = 0x20;
    let mut i_min = 0x20;
    if x_max != 0 {
        i_max = norm_l(x_max);
    }
    if x_min != 0 {
        i_min = norm_l(x_min);
    }
    i_max.min(i_min) & 0x1F
}

/// `BASOP_Util_Divide3232_uu_1616_Scale`: `x / y` for `x >= 0`, `y > 0` on their 16 most
/// significant bits; the result is `z · 2^s`.
pub fn basop_util_divide3232_uu_1616_scale(x: i32, y: i32, s: &mut i16) -> i16 {
    if x == 0 {
        *s = 0;
        return 0;
    }
    let mut sx = norm_l(x);
    let sy = norm_l(y);

    let mut x16 = extract_h(l_shl(x, sx));
    let y16 = extract_h(l_shl(y, sy));

    if sub(x16, y16) > 0 {
        sx = sub(sx, 1);
    }
    if sub(y16, x16) < 0 {
        x16 = mult_r(x16, 0x4000);
    }

    let z = div_s(x16, y16);
    *s = sub(sy, sx);
    z
}

/// `divide3232`: signed `L_num / L_denom` in Q15 for `|L_num| < |L_denom|`, the denominator
/// rounded to 16 bits after both are normalised by the smaller headroom.
#[must_use]
pub fn divide3232(l_num: i32, l_denom: i32) -> i16 {
    let sign = (l_num ^ l_denom) as u32 & 0x8000_0000;

    let l_num = l_abs(l_num);
    let l_denom = l_abs(l_denom);

    // limit the range of denominator to Word16
    let z = norm_l(l_num).min(norm_l(l_denom));
    let l_num = l_shl(l_num, z);
    let l_denom = l_shl(l_denom, z);

    // round_fx instead of extract_h improves spectral distortion in E_UTIL_lev_dur (schur version).
    let mut z = div_l(l_num, round_word(l_denom));
    if sign != 0 {
        z = negate(z);
    }
    z
}

/// `BASOP_Util_Divide3232_Scale`: `x / y` with the denominator reduced to 16 bits; the result is
/// `z · 2^s`.
pub fn basop_util_divide3232_scale(x: i32, y: i32, s: &mut i16) -> i16 {
    let mut sy = norm_l(y);
    if sy > 0 {
        sy = sub(sy, 1);
    }
    let y = l_shl(y, sy);
    let z = basop_util_divide3216_scale(x, extract_h(y), s);
    *s = add(*s, sy);
    z
}

/// `BASOP_Util_Divide3216_Scale`: signed `x / y`, not normalised; the result is `z · 2^s`, and
/// `s = 0` for `x == 0`. `y` must be non-zero.
pub fn basop_util_divide3216_scale(x: i32, y: i16, s: &mut i16) -> i16 {
    // check, if numerator equals zero, return zero then
    if x == 0 {
        *s = 0;
        return 0;
    }
    let sign = extract_h(x) ^ y; // just to exor the sign bits
    let mut x = l_abs(x);
    let mut y = abs_s(y);
    let sx = sub(norm_l(x), 1);
    x = l_shl(x, sx);
    let sy = norm_s(y);
    y = shl(y, sy);
    *s = sub(sy, sx);

    let mut z = div_s(round_word(x), y);
    if sign < 0 {
        // if sign bits differ, negate the result
        z = negate(z);
    }
    z
}

/// `BASOP_Util_Divide1616_Scale`: signed `x / y` for 16-bit operands, not normalised; the result
/// is `z · 2^s`, and `s = 0` for `x == 0`. `y` must be non-zero.
pub fn basop_util_divide1616_scale(x: i16, y: i16, s: &mut i16) -> i16 {
    let (mut x, mut y) = (x, y);
    let mut sign: i16 = 0;
    if x < 0 {
        x = negate(x);
        sign ^= 1;
    }
    if y < 0 {
        y = negate(y);
        sign ^= 1;
    }
    if x == 0 {
        *s = 0;
        return 0;
    }
    let sx = norm_s(x);
    x = shl(x, sx);
    x = shr(x, 1);
    *s = sub(1, sx);

    let sy = norm_s(y);
    y = shl(y, sy);
    *s = add(*s, sy);

    // y == 0 is excluded by the reference's assert; div_s answers it saturated, never panics
    let mut z = div_s(x, y);
    if sign != 0 {
        z = negate(z);
    }
    z
}

/// `BASOP_Util_Add_MantExp`: `a_m·2^a_e + b_m·2^b_e` for 16-bit mantissas; the normalised sum's
/// mantissa into `ptr_sum_m`, its exponent returned. The exponent difference is limited to ±15.
pub fn basop_util_add_mant_exp(a_m: i16, a_e: i16, b_m: i16, b_e: i16, ptr_sum_m: &mut i16) -> i16 {
    let mut shift = sub(a_e, b_e);
    if shift >= 0 {
        shift = shift.min(15);
    }
    if shift < 0 {
        shift = shift.max(-15);
    }
    let mut a_e = a_e.max(b_e);
    // mantissa belonging to the higher exponent, and the one belonging to the lower exponent
    let mut l_hm = l_deposit_l(a_m);
    let mut l_lm = l_deposit_l(a_m);
    if shift >= 0 {
        l_lm = l_deposit_l(b_m);
    }
    if shift < 0 {
        l_hm = l_deposit_l(b_m);
    }
    if shift > 0 {
        shift = negate(shift);
    }
    l_hm = l_shr(l_hm, shift); // shift left due to negative shift parameter
    a_e = add(a_e, shift);
    l_hm = l_add(l_hm, l_lm);
    let shift = norm_l(l_hm);
    l_hm = l_shl(l_hm, shift);
    *ptr_sum_m = extract_h(l_hm);

    a_e = sub(a_e, shift);
    if l_hm != 0 {
        a_e = add(a_e, 16);
    }
    a_e
}

/// `Inv16`: `1 / (mantissa · 2^exponent)` by a table-interpolated reciprocal; the result's
/// mantissa returned (Q15), its exponent written back into `exponent`. `mantissa` must be
/// non-zero.
pub fn inv16(mantissa: i16, exponent: &mut i16) -> i16 {
    // absolute
    let mut m = abs_s(mantissa);

    // normalize
    let pre_shift = norm_s(m);
    let e = sub(*exponent, pre_shift);
    m = shl(m, pre_shift);

    // get table index (upper 6 bits minus 32): index = (m >> 9) - 32
    let index = mac_r(-32768 - (32 << 16), m, 1 << 6);
    // mantissa == 0 (excluded by the reference's assert) would index -32
    let index = index.clamp(0, 31) as usize;

    // get fractional part for interpolation (lower 9 bits)
    let frac = shl(m & 0x1FF, 1); // Q10

    // interpolate
    m = msu_r(INVTABLE[index], INVDIFFTABLE[index], frac);

    // restore sign
    if mantissa < 0 {
        m = negate(m);
    }

    // e = 1 - e
    *exponent = sub(1, e);
    m
}

/// `set_zero_Word8`: `x[0..n] = 0`.
pub fn set_zero_word8(x: &mut [i8], n: i32) {
    x[..n.max(0) as usize].fill(0);
}

/// `fixp_sin_cos_residual_16`: split the angle `x` (`flag_radix2 == 0`: radians, Q(15-2-scale)
/// scaled by 1/pi first; otherwise already in units of pi) into a sine-table point, written to
/// `sine` / `cosine`, and the residual angle it returns (Q15, radians).
pub fn fixp_sin_cos_residual_16(
    x: i16,
    scale: i16,
    sine: &mut i16,
    cosine: &mut i16,
    flag_radix2: i8,
) -> i16 {
    let shift = 15 - LD - 1 - scale;
    let mut x = x;
    if flag_radix2 == 0 {
        x = mult_r(x, 10430); // 1.0/EVS_PI Q15
    }
    let mut s = shr(x, shift);

    let mut residual = x & ((1 << shift) - 1);
    // We assume "2+scale" is a constant
    residual = shl(residual, 2 + scale);
    residual = mult_r(residual, 25736); // EVS_PI/4.0 Q15

    // Sine sign symmetry
    let ssign = s & ((1 << LD) << 1);
    // Cosine sign symmetry
    let csign = add(s, 1 << LD) & ((1 << LD) << 1);
    // Modulo PI
    s &= (2 << LD) - 1;
    // PI/2 symmetry
    s = s.min(sub(2 << LD, s));

    let tmp = sub(1 << LD, s).min(s);
    s = sub(tmp, s);
    let entry = SINETABLE512[tmp.clamp(0, 256) as usize].v;
    let (mut sl, mut cl) = if s == 0 {
        (entry.im, entry.re)
    } else {
        (entry.re, entry.im)
    };
    if ssign != 0 {
        sl = negate(sl);
    }
    if csign != 0 {
        cl = negate(cl);
    }
    *sine = sl;
    *cosine = cl;
    residual
}

/// `getCosWord16R2`: `cos(pi · theta)` for `theta` in Q15 units of pi, result Q15.
#[must_use]
pub fn get_cos_word16_r2(theta: i16) -> i16 {
    let (mut sine, mut cosine) = (0, 0);
    let residual = fixp_sin_cos_residual_16(theta, 1, &mut sine, &mut cosine, 1);
    // This negation prevents the subsequent addition from overflow
    sine = negate(sine);
    msu_r(l_mult(sine, residual), cosine, -32768)
}

/// `imult1616`: `x · y` as an integer, low 16 bits (the reference asserts it fits).
#[must_use]
pub fn imult1616(x: i16, y: i16) -> i16 {
    extract_l(l_mult0(x, y))
}

/// `idiv1616`: integer division `x / y` truncated toward zero, `y != 0`.
#[must_use]
pub fn idiv1616(x: i16, y: i16) -> i16 {
    let num = abs_s(x);
    let mut den = abs_s(y);
    let sign = (x ^ y) & i16::MIN;

    // make num > den
    let mut s = add(sub(norm_s(den), norm_s(num)), 1);
    s = s.max(0);
    den = shl(den, s);

    // divide and shift
    let mut y = shr(div_s(num, den), sub(15, s));
    if sign != 0 {
        y = negate(y);
    }
    y
}

/// `idiv1616U`: integer division `x / y` of non-negative `x`, positive `y`, truncated.
#[must_use]
pub fn idiv1616_u(x: i16, y: i16) -> i16 {
    // make y > x to meet the requirements for div_s parameters
    let mut sx = norm_s(x);
    let sy = norm_s(y);
    let mut x = shl(x, sx);
    let y = shl(y, sy);
    if x >= y {
        x = shr(x, 1);
        sx = sub(sx, 1);
    }
    // divide and shift
    shr(div_s(x, y), sub(15, sub(sy, sx)))
}

/// `norm_llQ31`: normalise the 64-bit accumulator `(l_c, l_sum)` (`l_c` the upper bits Q-1,
/// `l_sum` the lower bits, unsigned Q31) to a Q31 mantissa with exponent `exp` in `[-32, 31]`.
///
/// Clears `Carry` on entry and leaves it as its two `L_add_c` calls set it.
pub fn norm_ll_q31(l_c: i32, l_sum: i32, exp: &mut i16, flags: &mut StlFlags) -> i32 {
    // Move MSBit of L_sum into L_c
    flags.carry = false;
    let l_tmp = l_add_c(l_sum, l_sum, flags); // L_tmp = L_sum << 1
    let mut l_c = l_add_c(l_c, l_c, flags);
    let mut l_sum = l_sum;
    let i;
    if l_c != 0 && l_c != -1 {
        let shift = norm_l(l_c);
        l_c = l_shl(l_c, shift);
        i = sub(31, shift); // positive exponent
        l_sum = l_lshr(l_tmp, 1); // L_sum with MSBit=0
        l_sum = l_lshr(l_sum, i);
        l_sum = l_add(l_c, l_sum);
    } else {
        let mut exponent = -32; // default exponent, if total sum=0
        if l_sum != 0 {
            exponent = norm_l(l_sum);
            l_sum = l_shl(l_sum, exponent);
            exponent = negate(exponent); // negative or zero exponent
        }
        i = exponent;
    }
    *exp = i;
    l_sum
}

/// `Dot_productSq16HQ`: `L_off + Σ 2·x[i]²` accumulated to 64 bits through the carry operators,
/// normalised by [`norm_ll_q31`] to a Q31 mantissa with exponent `exp`.
pub fn dot_product_sq16_hq(
    l_off: i32,
    x: &[i16],
    lg: i16,
    exp: &mut i16,
    flags: &mut StlFlags,
) -> i32 {
    // Clear carry flag and init sum
    flags.carry = false;
    let mut l_c: i32 = 0;
    let mut l_sum = l_mac_ns(l_off, 0, 0, flags);
    if l_sum > 0 {
        l_c = l_mac_ns(l_c, 0, 0, flags);
    }
    if l_sum < 0 {
        l_c = l_msu_ns(l_c, 0, 0, flags);
    }
    for &value in &x[..lg.max(0) as usize] {
        flags.carry = false;
        l_sum = l_mac_ns(l_sum, value, value, flags);
        flags.overflow = false; // the reference clears the warning L_mult raises for -32768²
        l_c = l_mac_ns(l_c, 0, 0, flags);
    }
    norm_ll_q31(l_c, l_sum, exp, flags)
}

/// `limitScale32` (`basop_util.h`, a static inline there): clamp a shift computed just before to
/// a valid 32-bit shift, `[-31, 31]`.
#[must_use]
pub fn limit_scale32(s: i16) -> i16 {
    let mut s = s;
    if s >= 0 {
        s = s.min(31);
    }
    if s < 0 {
        s = s.max(1 - 32);
    }
    s
}

/// `Dot_product16HQ`: `L_off + Σ 2·x[i]·y[i]` accumulated to 64 bits through the carry
/// operators, normalised by [`norm_ll_q31`] to a Q31 mantissa with exponent `exp`.
pub fn dot_product16_hq(
    l_off: i32,
    x: &[i16],
    y: &[i16],
    lg: i16,
    exp: &mut i16,
    flags: &mut StlFlags,
) -> i32 {
    // Clear carry flag and init sum
    flags.carry = false;
    let mut l_c: i32 = 0;
    let mut l_sum = l_mac_ns(l_off, 0, 0, flags);
    if l_sum > 0 {
        l_c = l_mac_ns(l_c, 0, 0, flags);
    }
    if l_sum < 0 {
        l_c = l_msu_ns(l_c, 0, 0, flags);
    }
    for (&a, &b) in x.iter().zip(y).take(lg.max(0) as usize) {
        // the sign of the product decides the carry word's extension; -32768² saturates
        let l_test = l_mult(a, b);
        flags.carry = false;
        l_sum = l_mac_ns(l_sum, a, b, flags);
        flags.overflow = false; // the reference clears the warning L_mult raises
        if l_test >= 0 {
            l_c = l_mac_ns(l_c, 0, 0, flags);
        }
        if l_test < 0 {
            l_c = l_msu_ns(l_c, 0, 0, flags);
        }
    }
    norm_ll_q31(l_c, l_sum, exp, flags)
}

/// `dotp_s_fx`: `Σ x[i]·y[i]`, each pair of products shifted right by `s - 1` before it is
/// accumulated (saturating).
#[must_use]
pub fn dotp_s(x: &[i16], y: &[i16], n: i16, s: i16) -> i32 {
    let mut l_sum: i32 = 0;
    let n2 = shr(n, 1) as usize;
    let s = sub(s, 1);
    for i in 0..n2 {
        let mut l_tmp = l_mult0(x[2 * i], y[2 * i]);
        l_tmp = l_mac0(l_tmp, x[2 * i + 1], y[2 * i + 1]);
        l_sum = l_add(l_sum, l_shr(l_tmp, s));
    }
    if n & 1 != 0 {
        let last = n as usize - 1;
        let l_tmp = l_mult0(x[last], y[last]);
        l_sum = l_add(l_sum, l_shr(l_tmp, s));
    }
    l_sum
}

/// `getNormReciprocalWord16`: `1/x` in Q15 for `x` in `[1, 160]` (0 for `x == 0`).
#[must_use]
pub fn get_norm_reciprocal_word16(x: i16) -> i16 {
    // The reference asserts x is a table index.
    let index = (x.max(0) as usize).min(BASOP_UTIL_NORMRECIPROCAL.len() - 1);
    extract_h(BASOP_UTIL_NORMRECIPROCAL[index])
}

/// `BASOP_Util_Add_Mant32Exp`: `a_m·2^a_e + b_m·2^b_e` as a normalised 32-bit mantissa; the
/// exponent into `ptr_e` (0 for a zero result).
pub fn basop_util_add_mant32_exp(a_m: i32, a_e: i16, b_m: i32, b_e: i16, ptr_e: &mut i16) -> i32 {
    let (mut a_m, mut a_e, mut b_m, mut b_e) = (a_m, a_e, b_m, b_e);
    if a_m == 0 {
        a_e = b_e;
    }
    if b_m == 0 {
        b_e = a_e;
    }
    let mut shift = sub(a_e, b_e);
    shift = shift.max(-31);
    shift = shift.min(31);
    if shift < 0 {
        // exponent of b is greater than exponent of a, shr a_m
        a_m = l_shl(a_m, shift);
    }
    if shift > 0 {
        // exponent of a is greater than exponent of b
        b_m = l_shr(b_m, shift);
    }
    a_e = add(a_e.max(b_e), 1);
    let mut l_tmp = l_add(l_shr(a_m, 1), l_shr(b_m, 1));
    let shift = norm_l(l_tmp);
    if shift != 0 {
        l_tmp = l_shl(l_tmp, shift);
    }
    if l_tmp == 0 {
        a_e = 0;
    }
    if l_tmp != 0 {
        a_e = sub(a_e, shift);
    }
    *ptr_e = a_e;
    l_tmp
}

/// `dotWord32_16_Mant32Exp`: `Σ bufX32[i]·bufY16[i]` as a normalised mantissa; the exponent into
/// `exp` (0 for a zero result). `bufY16` must leave headroom for `len` accumulations.
pub fn dot_word32_16_mant32_exp(
    buf_x32: &[i32],
    buf_x32_exp: i16,
    buf_y16: &[i16],
    buf_y16_exp: i16,
    len: i16,
    exp: &mut i16,
) -> i32 {
    let mut shift = get_scale_factor32(buf_x32, len); // current available headroom
    shift = sub(shift, sub(14, norm_s(len))); // reduced required headroom
    let mut l_sum: i32 = 0;
    for i in 0..len.max(0) as usize {
        l_sum = l_mac0(l_sum, round_word(l_shl(buf_x32[i], shift)), buf_y16[i]);
    }
    let shift1 = norm_l(l_sum);
    l_sum = l_shl(l_sum, shift1); // return value

    shift = sub(add(buf_x32_exp, buf_y16_exp), add(shift, shift1));
    shift = add(shift, 1); // compensate for factor of 2 introduced by L_mac0
                           // In case of NULL result, we want to have a 0 exponent too
    if l_sum == 0 {
        shift = 0;
    }
    *exp = shift;
    l_sum
}

/// `getSqrtWord32`: `floor(sqrt(val))` for a non-negative `val`, as an integer.
///
/// An `Isqrt_lc` estimate of `1/sqrt(val)` times `val`, rounded, then walked down by up to seven and
/// up by one with exact integer comparisons, ported step for step.
#[must_use]
pub fn get_sqrt_word32(val: i32) -> i16 {
    let exp2 = norm_l(val);
    let l_temp2 = l_shl(val, exp2);
    let mut exp = sub(31 - 32, exp2);
    let l_temp = isqrt_lc(l_temp2, &mut exp);
    let mut temp = round_word(l_temp);
    let l_temp = l_shl(mult_32_16(l_temp2, temp), sub(exp, exp2));
    temp = round_word(l_temp);
    for step in [2, 2, 2, 1] {
        if l_msu0(val, temp, temp) < 0 {
            temp = sub(temp, step);
        }
    }
    let temp2 = add(temp, 1);
    if l_msu0(val, temp2, temp2) >= 0 {
        temp = temp2;
    }
    temp
}

/// `ISqrt32_common`: the inverse square-root mantissa of a normalised `m` (`m >= 2^30`) with
/// exponent `e`, by table interpolation; an even exponent multiplies by `sqrt(1/2)`.
fn isqrt32_common(m: i32, e: i16) -> i32 {
    let m16 = round_word(m);

    // get table index (upper 6 bits minus 32): index = (m16 >> 25) - 32
    let index = mac_r(-32768 - (32 << 16), m16, 1 << 6);

    // get fractional part for interpolation (lower 9 bits)
    let frac = m16 & 0x1FF; // Q9

    // interpolate (the reference asserts m > 0, which keeps the index in the table)
    let index = index.clamp(0, 31) as usize;
    let mut m = l_msu(ISQRTTABLE[index], ISQRTDIFFTABLE[index], frac);

    // handle even exponents
    if e & 1 == 0 {
        m = mpy_32_16_1(m, 0x5a82);
    }
    m
}

/// `ISqrt32`: `1 / sqrt(mantissa · 2^exponent)` for `mantissa > 0`; the result's exponent is
/// written back to `exponent`.
pub fn isqrt32(mantissa: i32, exponent: &mut i16) -> i32 {
    // normalize
    let pre_shift = norm_l(mantissa);
    let e = sub(*exponent, pre_shift);
    let mantissa = l_shl(mantissa, pre_shift);

    // calc mantissa
    let mantissa = isqrt32_common(mantissa, e);

    // e = (2 - e) >> 1
    *exponent = msu_r(1 << 15, e, 1 << 14);
    mantissa
}

/// `BASOP_util_norm_s_bands2shift`: the shift `15 - norm_s(-x)` that normalises a band count `x`
/// for `getNormReciprocalWord16`.
#[must_use]
pub fn basop_util_norm_s_bands2shift(x: i16) -> i16 {
    sub(16 - 1, norm_s(negate(x)))
}

/// `BASOP_util_Pow2`: `2^(exp_m · 2^exp_e)` (`exp_m` Q31) as a mantissa with the exponent written
/// to `result_e`, by a Taylor polynomial around the fractional part (brought into ±0.5).
pub fn basop_util_pow2(exp_m: i32, exp_e: i16, result_e: &mut i16) -> i32 {
    const POW2_COEFF: [i16; 8] = [
        22713, // ln(2)^1 /1!
        7872,  // ln(2)^2 /2!
        1819,  // ln(2)^3 /3!
        315,   // ln(2)^4 /4!
        44,    // ln(2)^5 /5!
        5,     // ln(2)^6 /6!
        0,     // ln(2)^7 /7!
        0,     // ln(2)^8 /8!
    ];

    let mut int_part: i16 = 0;
    let mut frac_part: i32 = 0;

    if exp_e > 0 {
        // "+ 1" compensates L_shr(,1) of the polynomial evaluation at the loop end.
        int_part = add(1, extract_l(l_shr(exp_m, sub(31, exp_e))));
        frac_part = l_lshl(exp_m, exp_e);
        frac_part &= 0x7FFF_FFFF;
    }
    if exp_e <= 0 {
        frac_part = l_shl(exp_m, exp_e);
        int_part = 1;
    }

    // Best accuracy is around 0, so try to get there with the fractional part.
    let tmp_frac = l_sub(frac_part, 1_073_741_824);
    if tmp_frac >= 0 {
        int_part = add(int_part, 1);
        frac_part = l_sub(tmp_frac, 1_073_741_824);
    } else {
        let tmp_frac = l_add(frac_part, 1_073_741_824);
        if tmp_frac < 0 {
            int_part = sub(int_part, 1);
            frac_part = l_add(tmp_frac, 1_073_741_824);
        }
    }

    // Evaluate taylor polynomial which approximates 2^x
    // First taylor series coefficient a_0 = 1.0, scaled by 0.5 due to L_shr(,1).
    let mut result_m = l_add(
        1_073_741_824,
        l_shr(mpy_32_16_1(frac_part, POW2_COEFF[0]), 1),
    );
    let mut p = mpy_32_32(frac_part, frac_part);
    for &coeff in &POW2_COEFF[1..7] {
        // next taylor series term: a_i * x^i, x=0
        result_m = l_add(result_m, l_shr(mpy_32_16_1(p, coeff), 1));
        p = mpy_32_32(p, frac_part);
    }
    result_m = l_add(result_m, l_shr(mpy_32_16_1(p, POW2_COEFF[7]), 1));

    *result_e = int_part;
    result_m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_zero_word8_clears_only_the_prefix() {
        let mut x = [3i8; 4];
        set_zero_word8(&mut x, 3);
        assert_eq!(x, [0, 0, 0, 3]);
    }

    #[test]
    fn idiv1616_truncates_toward_zero() {
        assert_eq!(idiv1616(7, 2), 3);
        assert_eq!(idiv1616(-7, 2), -3);
        assert_eq!(imult1616(-12, 11), -132);
    }
}
