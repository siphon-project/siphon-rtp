//! Vector and scalar utilities shared by the whole codec (TS 26.442 `lib_com/tools_fx.c`).
//!
//! Only the functions the decoder executes are ported here. They are hub utilities, so their
//! signatures stay as close to the C as Rust allows: a `const Word16 *` is a slice, an in/out or
//! output scalar is a `&mut`, and the return value is what the C returns. Where the C passes the
//! same buffer as input and output (`Copy_Scale_sig(x, x, ...)`), the in-place variant is the
//! matching `Scale_sig*` function or `slice::copy_within`, which is what `Copy` computes for
//! overlapping buffers (it picks the copy direction from the pointer order, i.e. a `memmove`).

use crate::evs::basop::{l_extract_lc, madd_32_16, msub_32_16, mult_32_16};
use crate::evs::cnst::{L_FILT_MAX, L_FRAME16K, L_FRAME32K, L_SUBFR};
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::rom::{A_HP400_FX, B_HP400_FX};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_msu,
    l_mult, l_shl, l_shr, l_shr_r, l_sub, mult_r, negate, norm_l, norm_s, round_word, shl, shr,
    shr_r, sub,
};
use crate::itu::oper_32b::{l_extract, mpy_32, mpy_32_16};
use crate::itu::stl2009::{
    l_lshl, l_mac0, l_msu0, l_mult0, lshr, mpy_32_32_uu, msu_r, norm_ul, ul_add_ns, ul_sub_ns,
};

/// `Sqrt_Ratio32`: `sqrt(val1 / val2)` of two mantissa/exponent pairs (an exponent > 0 means the
/// value was shifted left), as a Q31 mantissa with the number of `L_shl` still to apply in `exp`.
pub fn sqrt_ratio32(l_val1: i32, exp1: i16, l_val2: i32, exp2: i16, exp: &mut i16) -> i32 {
    // normalize Energy #1
    let temp = norm_l(l_val1);
    let l_val1 = l_shl(l_val1, temp);
    let exp1 = add(exp1, temp);
    // normalize Energy #2
    let temp = norm_l(l_val2);
    let l_val2 = l_shl(l_val2, temp);
    let exp2 = add(exp2, temp);
    // Prepare for Inverse
    let temp = round_word(l_val1);
    let temp = div_s(16384, temp);
    // Mult Now
    let l_val2 = mult_32_16(l_val2, temp);
    let exp1 = add(sub(exp2, exp1), 15 * 2);
    // Here Result of ('L_val2' * 0.5/('L_val1')) is known to be in range [0.5..1.0]
    let temp = norm_l(l_val2);
    let l_val2 = l_shl(l_val2, temp);
    let exp1 = add(temp, exp1);
    // Do Sqrt
    let mut temp = sub(31, exp1);
    let l_val1 = isqrt_lc(l_val2, &mut temp);
    *exp = temp;
    l_val1
}

/// `usdequant_fx`: uniform scalar de-quantiser, `idx · delta + qlow` (Qx; `delta` is Qx-1).
#[must_use]
pub fn usdequant(idx: i16, qlow: i16, delta: i16) -> i16 {
    let mut l_tmp = l_deposit_l(qlow);
    l_tmp = l_mac(l_tmp, idx, delta);
    round_word(l_shl(l_tmp, 16))
}

/// `Dot_product`: `1 + Σ 2·x[i]·y[i]` over `lg` samples, saturating (`lg >= 1`).
#[must_use]
pub fn dot_product(x: &[i16], y: &[i16], lg: i16) -> i32 {
    let mut l_sum = l_mac(1, x[0], y[0]);
    for i in 1..lg as usize {
        l_sum = l_mac(l_sum, x[i], y[i]);
    }
    l_sum
}

/// `sum2_fx`: `Σ 2·vec[i]²`, saturating.
#[must_use]
pub fn sum2(vec: &[i16], lvec: i16) -> i32 {
    let mut l_tmp = 0;
    for &value in &vec[..lvec.max(0) as usize] {
        l_tmp = l_mac(l_tmp, value, value);
    }
    l_tmp
}

/// `Copy`: `y[0..l] = x[0..l]`. For an overlapping copy within one buffer use
/// `slice::copy_within`, which matches the C's direction-aware loop.
pub fn copy(x: &[i16], y: &mut [i16], l: i16) {
    let l = l.max(0) as usize;
    y[..l].copy_from_slice(&x[..l]);
}

/// `Copy32`: [`copy`] for 32-bit vectors.
pub fn copy32(x: &[i32], y: &mut [i32], l: i16) {
    let l = l.max(0) as usize;
    y[..l].copy_from_slice(&x[..l]);
}

/// `set16_fx`: `y[0..n] = a`.
pub fn set16(y: &mut [i16], a: i16, n: i16) {
    y[..n.max(0) as usize].fill(a);
}

/// `set32_fx`: `y[0..n] = a`. (The C's two branches store the same value.)
pub fn set32(y: &mut [i32], a: i32, n: i16) {
    y[..n.max(0) as usize].fill(a);
}

/// `Copy_Scale_sig`: `y = round(x << exp0)`, saturating; a negative `exp0` rounds.
pub fn copy_scale_sig(x: &[i16], y: &mut [i16], lg: i16, exp0: i16) {
    let lg = lg.max(0) as usize;
    if exp0 == 0 {
        y[..lg].copy_from_slice(&x[..lg]);
        return;
    }
    if exp0 < 0 {
        // A negative factor so that 1.0 is representable.
        let tmp = shl(-32768, exp0);
        for i in 0..lg {
            y[i] = msu_r(0, x[i], tmp);
        }
        return;
    }
    for i in 0..lg {
        y[i] = shl(x[i], exp0);
    }
}

/// `Copy_Scale_sig_16_32`: `y = x << exp0` widened to 32 bits; the 16-bit shift saturates for a
/// negative `exp0` (a path the reference marks "should not happen"), the positive one multiplies
/// in 32 bits.
pub fn copy_scale_sig_16_32(x: &[i16], y: &mut [i32], lg: i16, exp0: i16) {
    let lg = lg.max(0) as usize;
    if exp0 == 0 {
        for i in 0..lg {
            y[i] = l_deposit_l(x[i]);
        }
        return;
    }
    if exp0 < 0 {
        // Should not happen
        for i in 0..lg {
            y[i] = l_deposit_l(shl(x[i], exp0));
        }
        return;
    }
    let tmp = shl(1, exp0);
    for i in 0..lg {
        y[i] = l_mult0(x[i], tmp); // saturation can occur here
    }
}

/// `Copy_Scale_sig_32_16`: `y = round(x << (16 + exp0))` into 16 bits.
pub fn copy_scale_sig_32_16(x: &[i32], y: &mut [i16], lg: i16, exp0: i16) {
    let lg = lg.max(0) as usize;
    let tmp = add(16, exp0);
    if tmp != 0 {
        for i in 0..lg {
            y[i] = round_word(l_shl(x[i], tmp));
        }
    } else {
        for i in 0..lg {
            y[i] = round_word(x[i]);
        }
    }
}

/// `Copy_Scale_sig32_16`: `dst = round(src << exp0)` into 16 bits.
pub fn copy_scale_sig32_16(src: &[i32], dst: &mut [i16], len: i16, exp0: i16) {
    let len = len.max(0) as usize;
    if exp0 == 0 {
        for i in 0..len {
            dst[i] = round_word(src[i]);
        }
        return;
    }
    for i in 0..len {
        dst[i] = round_word(l_shl(src[i], exp0));
    }
}

/// `Scale_sig32`: `x <<= exp0` in place, saturating.
pub fn scale_sig32(x: &mut [i32], lg: i16, exp0: i16) {
    for value in &mut x[..lg.max(0) as usize] {
        *value = l_shl(*value, exp0);
    }
}

/// `Random_Fill`: `n` values of the 16-bit LCG, each shifted right by `scaling`.
pub fn random_fill(seed: &mut i16, n: i16, y: &mut [i16], scaling: i16) {
    let mut local_seed = *seed;
    for value in &mut y[..n.max(0) as usize] {
        local_seed = extract_l(l_mac0(13849, local_seed, 31821));
        *value = shr(local_seed, scaling);
    }
    *seed = local_seed;
}

/// `Scale_sig`: `x = round(x << exp0)` in place; a negative `exp0` rounds, zero is a no-op.
pub fn scale_sig(x: &mut [i16], lg: i16, exp0: i16) {
    let lg = lg.max(0) as usize;
    if exp0 > 0 {
        for value in &mut x[..lg] {
            *value = shl(*value, exp0);
        }
        return;
    }
    if exp0 < 0 {
        let tmp = shl(-32768, exp0);
        for value in &mut x[..lg] {
            // msu instead of mac because the factor is negative
            *value = msu_r(0, *value, tmp);
        }
    }
}

/// `mean_fx`: `sum16 · (1/lvec)`, rounded.
#[must_use]
pub fn mean(vec: &[i16], lvec: i16) -> i16 {
    let tmp = sum16(vec, lvec);
    mult_r(tmp, div_s(1, lvec))
}

/// `Vr_add`: `out = in1 + in2`, saturating.
pub fn vr_add(in1: &[i16], in2: &[i16], out: &mut [i16], len: i16) {
    for i in 0..len.max(0) as usize {
        out[i] = add(in1[i], in2[i]);
    }
}

/// `sort_fx`: ascending insertion sort of `r[lo..=up]` in place.
pub fn sort(r: &mut [i16], lo: i16, up: i16) {
    let mut i = sub(up, 1);
    while i >= lo {
        let i1 = add(i, 1);
        let tempr = r[i as usize];
        let mut j = i1;
        while j <= up {
            if sub(tempr, r[j as usize]) <= 0 {
                break;
            }
            r[j as usize - 1] = r[j as usize];
            j += 1;
        }
        r[j as usize - 1] = tempr;
        i -= 1;
    }
}

/// `minimum_fx`: index of the first minimum of `vec[0..lvec]`, the minimum into `min_fx`.
pub fn minimum(vec: &[i16], lvec: i16, min_fx: &mut i16) -> i16 {
    let mut ind = 0;
    let mut tmp = vec[0];
    for j in 1..lvec.max(1) {
        let value = vec[j as usize];
        if sub(value, tmp) < 0 {
            ind = j;
        }
        tmp = tmp.min(value);
    }
    *min_fx = tmp;
    ind
}

/// `maximum_fx`: index of the first maximum of `vec[0..lvec]`, the maximum into `max_fx`.
pub fn maximum(vec: &[i16], lvec: i16, max_fx: &mut i16) -> i16 {
    let mut ind = 0;
    let mut tmp = vec[0];
    for j in 1..lvec.max(1) {
        let value = vec[j as usize];
        if sub(value, tmp) > 0 {
            ind = j;
        }
        tmp = tmp.max(value);
    }
    *max_fx = tmp;
    ind
}

/// `sum16_32_fx`: `Σ vec[i]` in 32 bits.
#[must_use]
pub fn sum16_32(vec: &[i16], lvec: i16) -> i32 {
    let mut tmp = 0;
    for &value in &vec[..lvec.max(0) as usize] {
        tmp = l_add(tmp, l_deposit_l(value));
    }
    tmp
}

/// `Vr_subt`: `y = x1 - x2`, saturating.
pub fn vr_subt(x1: &[i16], x2: &[i16], y: &mut [i16], n: i16) {
    for i in 0..n.max(0) as usize {
        y[i] = sub(x1[i], x2[i]);
    }
}

/// `emaximum_fx`: index of the first element of maximum energy, the energy (scaled down by
/// `2·Qvec`) into `ener_max`.
pub fn emaximum(qvec: i16, vec: &[i16], lvec: i16, ener_max: &mut i32) -> i16 {
    let mut emax = l_mult0(vec[0], vec[0]);
    let mut ind = 0;
    for j in 1..lvec.max(1) {
        let l_tmp = l_mult0(vec[j as usize], vec[j as usize]);
        if l_sub(l_tmp, emax) > 0 {
            ind = j;
        }
        emax = emax.max(l_tmp);
    }
    *ener_max = l_shr(emax, add(qvec, qvec));
    ind
}

/// `sum16_fx`: `Σ vec[i]` in 16 bits, saturating.
#[must_use]
pub fn sum16(vec: &[i16], lvec: i16) -> i16 {
    let mut tmp = 0;
    for &value in &vec[..lvec.max(0) as usize] {
        tmp = add(tmp, value);
    }
    tmp
}

/// `Random`: advance the 16-bit LCG `seed = seed·31821 + 13849` and return it.
pub fn random(seed: &mut i16) -> i16 {
    *seed = extract_l(l_mac0(13849, *seed, 31821));
    *seed
}

/// `own_random2_fx`: one step of the [`random`] LCG on a seed passed by value.
#[must_use]
pub fn own_random2(seed: i16) -> i16 {
    extract_l(l_mac0(13849, seed, 31821))
}

/// `add_vec_fx`: `y = x1·2^(Qy-Qx1) + x2·2^(Qy-Qx2)`, each term rounded.
pub fn add_vec(x1: &[i16], qx1: i16, x2: &[i16], qx2: i16, y: &mut [i16], qy: i16, n: i16) {
    let qyx1 = sub(qx1, qy);
    let qyx2 = sub(qx2, qy);
    let n = n.max(0) as usize;
    if qyx1 == 0 {
        for i in 0..n {
            y[i] = add(x1[i], shr_r(x2[i], qyx2));
        }
    } else {
        for i in 0..n {
            y[i] = add(shr_r(x1[i], qyx1), shr_r(x2[i], qyx2));
        }
    }
}

/// `L_mac0` that also reports whether it saturated (the STL raises `Overflow` exactly then).
fn l_mac0_overflowing(l_var3: i32, var1: i16, var2: i16) -> (i32, bool) {
    let wide = i64::from(l_var3) + i64::from(l_mult0(var1, var2));
    (
        l_mac0(l_var3, var1, var2),
        wide != i64::from(l_mac0(l_var3, var1, var2)),
    )
}

/// `Calc_Energy_Autoscaled`: the energy of `signal[0..len]`, halving the running sum whenever the
/// next eight-sample block would overflow it; the energy's exponent into `energy_exp`.
///
/// The C clears `Overflow` on entry and reads it once per block. Between two reads the operators
/// that can raise it are the block's `L_mac0` chain (eight samples of magnitude 16384 sum to 2^31)
/// and the trial `L_add`; `mult_r(·, 16384)`, `L_mult0` of two halved samples and the
/// non-negative `L_shr` cannot. The flag is reproduced from those two, and is cleared again in the
/// branch exactly as the C does.
pub fn calc_energy_autoscaled(
    signal: &[i16],
    signal_exp: i16,
    len: i16,
    energy_exp: &mut i16,
) -> i32 {
    let mut overflow = false;
    let mut temp2: i16 = 0;
    let mut l_energy = l_deposit_l(1);
    let mut position = 0usize;
    let head = 7 & len;
    for _ in 0..head {
        // divide by 2 so energy will be divided by 4
        let temp = mult_r(signal[position], 16384);
        position += 1;
        l_energy = l_mac0(l_energy, temp, temp);
    }
    let mut i = head;
    while i < len {
        let temp = mult_r(signal[position], 16384);
        position += 1;
        let mut l_temp = l_mult0(temp, temp);
        for _ in 1..8 {
            let temp = mult_r(signal[position], 16384);
            position += 1;
            let (sum, saturated) = l_mac0_overflowing(l_temp, temp, temp);
            l_temp = sum;
            overflow |= saturated;
        }
        l_temp = l_shr(l_temp, temp2);
        // Trial addition, result discarded: only its Overflow side effect matters.
        overflow |= i64::from(l_energy) + i64::from(l_temp) > i64::from(i32::MAX);
        if overflow {
            l_energy = l_shr(l_energy, 1);
            l_temp = l_shr(l_temp, 1);
            temp2 = add(temp2, 1);
            overflow = false;
        }
        l_energy = l_add(l_energy, l_temp);
        i += 8;
    }
    // sub 2 because of the mult_r by 16384 that already divides the energy by 4
    *energy_exp = sub(sub(shl(signal_exp, 1), temp2), 2);
    l_energy
}

/// `Find_Max_Norm16`: `norm_s` of the largest magnitude in `src[0..len]` (0 when all zero).
#[must_use]
pub fn find_max_norm16(src: &[i16], len: i16) -> i16 {
    let mut max16: i16 = 0;
    for &value in &src[..len.max(0) as usize] {
        max16 = max16.max(abs_s(value));
    }
    norm_s(max16)
}

/// `Find_Max_Norm32`: `norm_l` of the largest magnitude in `src[0..len]` (31 when all zero).
#[must_use]
pub fn find_max_norm32(src: &[i32], len: i16) -> i16 {
    let mut max32 = l_deposit_l(1);
    for &value in &src[..len.max(0) as usize] {
        max32 = max32.max(l_abs(value));
    }
    norm_l(max32)
}

/// `Acelp_dec_total_exc`: for one subframe at `i_subfr`, `exc2 = gain_pit·exc` and
/// `exc = gain_pit·exc + gain_code·code` (`gain_pit` Q14, `code` Q9).
pub fn acelp_dec_total_exc(
    exc: &mut [i16],
    exc2: &mut [i16],
    gain_code16: i16,
    gain_pit: i16,
    i_subfr: i16,
    code: &[i16],
) {
    let base = i_subfr.max(0) as usize;
    for i in 0..L_SUBFR as usize {
        let mut l_tmp = l_shl(l_mult(gain_pit, exc[i + base]), 1);
        exc2[i + base] = round_word(l_tmp);
        l_tmp = l_add(l_tmp, l_shl(l_mult(gain_code16, code[i]), 6));
        exc[i + base] = round_word(l_tmp);
    }
}

/// `UL_inverse`: `1 / ul_val` as a Q`exp` mantissa.
pub fn ul_inverse(ul_val: u32, exp: &mut i16) -> u32 {
    *exp = norm_ul(ul_val);
    let ul_tmp = l_lshl(ul_val as i32, *exp) as u32; // Q32
    *exp = add(32, sub(31, *exp));
    ul_div(0x8000_0000, ul_tmp)
}

/// `UL_div`: `ul_num / ul_den` by five Newton steps (`ul_num` Q31, `ul_den` Q32, result Q32).
#[must_use]
pub fn ul_div(ul_num: u32, ul_den: u32) -> u32 {
    let mut ul_e = ul_sub_ns(0xffff_ffff, ul_den).0;
    let mut ul_q = ul_num;
    for _ in 0..5 {
        let (ul_msb, _) = mpy_32_32_uu(ul_q, ul_e);
        ul_q = ul_add_ns(ul_q, ul_msb).0;
        ul_e = mpy_32_32_uu(ul_e, ul_e).0;
    }
    ul_q
}

/// `hp400_12k8_fx`: second-order 400 Hz high-pass at 12.8 kHz in place over `signal[0..lg]`
/// (the output is also divided by 16), with the filter memory `mem[0..6]`. `lg >= 2`.
pub fn hp400_12k8(signal: &mut [i16], lg: i16, mem: &mut [i16]) {
    let lg = lg as usize;
    let mut y1_hi = mem[2];
    let mut y1_lo = mem[3];

    let mut l_tmp3 = l_mac(16384, mem[1], A_HP400_FX[2]); // rounding to maximize precision
    l_tmp3 = l_mac(l_tmp3, y1_lo, A_HP400_FX[1]);
    l_tmp3 = l_shr(l_tmp3, 15);
    let mut l_tmp2 = l_mac(l_tmp3, mem[0], A_HP400_FX[2]);
    l_tmp2 = l_mac(l_tmp2, mem[5], B_HP400_FX[2]);
    l_tmp2 = l_mac(l_tmp2, mem[4], B_HP400_FX[1]);
    l_tmp3 = l_mult(mem[4], B_HP400_FX[2]);

    mem[5] = signal[lg - 2];

    let mut position = 0usize;
    for _ in 1..lg {
        // y[i] = b[0]*x[i] + b[1]*x[i-1] + b[2]*x[i-2] + a[1]*y[i-1] + a[2]*y[i-2]
        let x = signal[position];
        let mut l_tmp = l_mac(l_tmp2, y1_hi, A_HP400_FX[1]);
        l_tmp = l_mac(l_tmp, x, B_HP400_FX[0]);
        l_tmp = l_shl(l_tmp, 1); // coeff Q12 --> Q13

        l_tmp2 = l_mac(l_tmp3, y1_hi, A_HP400_FX[2]);
        l_tmp2 = l_mac(l_tmp2, x, B_HP400_FX[1]);
        l_tmp3 = l_mac(16384, y1_lo, A_HP400_FX[2]); // rounding to maximize precision

        (y1_hi, y1_lo) = l_extract_lc(l_tmp);

        l_tmp3 = l_mac(l_tmp3, y1_lo, A_HP400_FX[1]);
        l_tmp3 = l_shr(l_tmp3, 15);
        l_tmp2 = l_add(l_tmp3, l_tmp2);
        l_tmp3 = l_mult(x, B_HP400_FX[2]);

        // signal is divided by 16 to avoid overflow in energy computation
        signal[position] = round_word(l_tmp);
        position += 1;
    }

    let mut l_tmp = l_mac(l_tmp2, y1_hi, A_HP400_FX[1]);
    mem[4] = signal[position];
    l_tmp = l_mac(l_tmp, mem[4], B_HP400_FX[0]);
    l_tmp = l_shl(l_tmp, 1); // coeff Q12 --> Q13
    mem[0] = y1_hi;
    mem[1] = y1_lo;
    (mem[2], mem[3]) = l_extract(l_tmp);
    signal[position] = round_word(l_tmp);
}

/// `Div_32_optmz`: `L_num / denom_hi` (`denom_hi` normalised) by one Newton step on
/// `div_s(0x3fff, denom_hi)`; the result is in Q(num) - 2 relative to `Div_32`.
#[must_use]
pub fn div_32_optmz(l_num: i32, denom_hi: i16) -> i32 {
    // First approximation: 1 / L_denom = 1/denom_hi
    let approx = div_s(0x3fff, denom_hi);
    // 1/L_denom = approx * (2.0 - L_denom * approx)
    let mut l_32 = l_msu(0x7fff_ffff, denom_hi, approx);
    let (hi, lo) = l_extract_lc(l_32);
    l_32 = mpy_32_16(hi, lo, approx);
    // L_num * (1/L_denom)
    let (hi, lo) = l_extract_lc(l_32);
    let (n_hi, n_lo) = l_extract_lc(l_num);
    mpy_32(n_hi, n_lo, hi, lo)
}

/// `iDiv_and_mod_32`: integer quotient and remainder of the (non-negative) `numer` by `denom`,
/// with `denom` taken as `2·denom` when `rshift` is 1. The fractional division can come out one
/// short, which the trailing correction loop repairs.
pub fn idiv_and_mod_32(
    numer: i32,
    denom: i16,
    int_quotient: &mut i32,
    int_mod: &mut i32,
    rshift: i16,
) {
    // The reference aborts in div_s on a zero divisor (its tables never pass one); a non-positive
    // divisor would also never satisfy the correction loop, so refuse it here instead.
    if denom <= 0 {
        *int_quotient = 0;
        *int_mod = numer;
        return;
    }
    // Normalize 'Numer' & 'Denom'
    let mut exp_a = norm_l(numer);
    let mut n = l_shl(numer, exp_a);
    let exp_b = norm_s(denom);
    let d = shl(denom, exp_b);

    // Need to shift right 'Numer' by 1?
    if l_mac(n, d, -32768) >= 0 {
        exp_a = sub(exp_a, 1);
    }
    n = l_shl(numer, exp_a);

    let mut quotient = div_32_optmz(n, d);
    // Bring Back to Q0 (minus 2 because we removed the left shift by 2 in the Div32_optmz)
    quotient = if rshift != 0 {
        l_shr(quotient, add(15 - 2, sub(exp_a, sub(exp_b, 1))))
    } else {
        l_shr(quotient, add(15 - 2, sub(exp_a, exp_b)))
    };

    // Cross Check (do Quotient x Divisor): high and low 15-bit halves of the quotient
    let product = |quotient: i32| {
        let temp = l_shl(l_mult0(extract_h(l_shl(quotient, 1)), denom), 16 - 1);
        l_mac0(temp, extract_l(0x7fff & quotient), denom)
    };
    let mut temp = product(quotient);

    // The fractional division can leave the quotient one too small; step it up until the
    // remainder is below the divisor (one step for the divisors the codec uses).
    if rshift != 0 {
        temp = l_shl(temp, 1);
        while l_msu0(l_sub(numer, temp), 2, denom) >= 0 {
            quotient = l_add(quotient, 1);
            temp = l_shl(product(quotient), 1);
        }
    } else {
        while l_msu0(l_sub(numer, temp), 1, denom) >= 0 {
            quotient = l_add(quotient, 1);
            temp = product(quotient);
        }
    }
    *int_quotient = quotient;
    *int_mod = if l_msu0(l_sub(numer, temp), 1, denom) == 0 {
        0
    } else {
        l_sub(numer, temp)
    };
}

/// `maximum_32_fx` (`lib_com/tools_fx.c`): the index of the first maximum of `vec[0..lvec]` and
/// the maximum.
#[must_use]
pub fn maximum_32(vec: &[i32], lvec: i16, max: &mut i32) -> i16 {
    let mut ind: i16 = 0;
    let mut tmp = vec[0];
    for j in 1..lvec.max(1) {
        let value = vec[j as usize];
        if l_sub(value, tmp) > 0 {
            ind = j;
        }
        tmp = tmp.max(value);
    }
    *max = tmp;
    ind
}

/// `sum32_fx` (`lib_com/tools_fx.c`): `Σ vec[0..lvec]`, saturating.
#[must_use]
pub fn sum32(vec: &[i32], lvec: i16) -> i32 {
    let mut tmp: i32 = 0;
    for &value in &vec[..lvec.max(0) as usize] {
        tmp = l_add(tmp, value);
    }
    tmp
}

/// `ratio`: the mantissa (Q14) of `numer / denom`, with the exponent difference in `expo` (the
/// quotient is `result · 2^-(14 + expo)` in the numbers' own Q).
pub fn ratio(numer: i32, denom: i32, expo: &mut i16) -> i16 {
    let exp_denom = norm_l(denom);
    let man_denom = extract_h(l_shl(denom, exp_denom));
    let exp_numer = norm_l(numer);
    let mut man_numer = extract_h(l_shl(numer, exp_numer));
    man_numer = shr(man_numer, 1); // make sure the numerator is smaller than the denominator
    let quotient = div_s(man_numer, man_denom); // in Q14

    *expo = sub(exp_numer, exp_denom);

    quotient
}

/// `Exp16Array`: the `norm_s` of the largest magnitude in `sx[..n]`, the left shift that
/// normalises the whole array.
#[must_use]
pub fn exp16_array(n: i16, sx: &[i16]) -> i16 {
    let mut s_max = abs_s(sx[0]);
    for &value in sx.iter().take(n.max(1) as usize).skip(1) {
        s_max = s_max.max(abs_s(value));
    }
    norm_s(s_max)
}

/// `find_rem`: the integer quotient `n / m` (returned) and remainder (`r`) of two positive
/// 16-bit values by restoring division. A non-positive operand, or `n < m`, gives 0 and `r = n`.
pub fn find_rem(n: i16, m: i16, r: &mut i16) -> i16 {
    if n <= 0 || m <= 0 || n < m {
        *r = n;
        return 0;
    }
    let mut q1 = norm_s(n);
    q1 = sub(q1, 1);
    let mut l_acc = l_deposit_h(shl(n, q1));
    let mut qd = sub(q1, 1);
    let mut q2 = norm_s(m);
    q2 = sub(q2, 1);
    let mut l_temp2 = l_deposit_h(shl(m, q2));
    qd = sub(q2, qd);
    q2 = add(q2, 1);

    for _ in 0..qd.max(0) {
        l_acc = l_sub(l_acc, l_temp2);
        if l_acc >= 0 {
            l_acc = l_add(l_shl(l_acc, 1), 1);
        } else {
            l_acc = l_add(l_acc, l_temp2);
            l_acc = l_shl(l_acc, 1);
        }
    }
    q1 = extract_l(l_acc);
    l_temp2 = l_shr(l_acc, q2);
    *r = extract_h(l_temp2);
    q1
}

/// `find_remd`: the integer quotient `n / m` (returned) and remainder (`r`) of two positive
/// 32-bit values by restoring division. A non-positive operand, or `n < m`, gives 0 and `r = n`.
pub fn find_remd(n: i32, m: i32, r: &mut i32) -> i32 {
    if n <= 0 || m <= 0 || n < m {
        *r = n;
        return 0;
    }
    let mut q1 = norm_l(n);
    q1 = sub(q1, 1);
    let mut l_acc = l_shl(n, q1);
    let mut qd = sub(q1, 1);
    let mut q2 = norm_l(m);
    q2 = sub(q2, 1);
    let l_temp2 = l_shl(m, q2);
    qd = sub(q2, qd);
    q2 = add(q2, 1);
    let mut qo: i32 = 0;

    for _ in 0..qd.max(0) {
        l_acc = l_sub(l_acc, l_temp2);
        qo = l_shl(qo, 1);
        if l_acc >= 0 {
            l_acc = l_shl(l_acc, 1);
            qo = l_add(qo, 1);
        } else {
            l_acc = l_add(l_acc, l_temp2);
            l_acc = l_shl(l_acc, 1);
        }
    }
    *r = l_shr(l_acc, q2);
    qo
}

/// `rint_new_fx`: round a Q16 value to the nearest integer, ties to even.
#[must_use]
pub fn rint_new(x: i32) -> i16 {
    // middle value point test
    let frac = lshr(extract_l(x), 1); // Q15
    let tmp = sub(frac, 0x4000);
    if tmp == 0 {
        let a = add(extract_h(x), 1);
        if a & 1 == 0 {
            return a;
        }
        return extract_h(x);
    }
    let l_tmp = l_add(x, 32768); // Q16
    extract_h(l_tmp)
}

/// `fir_fx`: FIR filter `h` (`k + 1` taps, Q`15 - shift`) over `l` samples of `x` into `y`, with
/// the `k` previous input samples in `mem` (updated when `upd` is set). The reference copies `x`
/// into a local buffer before writing `y`, so a caller filtering in place copies the input first.
pub fn fir(
    x: &[i16],
    h: &[i16],
    y: &mut [i16],
    mem: &mut [i16],
    l: i16,
    k: i16,
    upd: i16,
    shift: i16,
) {
    let mut buf_in = [0i16; (L_FRAME32K + L_FILT_MAX) as usize];
    let lu = l.max(0) as usize;
    let ku = k.max(0) as usize;

    // prepare the input buffer (copy and update memory)
    copy(mem, &mut buf_in, k);
    copy(x, &mut buf_in[ku..], l);
    if upd != 0 {
        copy(&buf_in[lu..], mem, k);
    }

    // do the filtering
    for i in 0..lu {
        let mut s = l_mult(buf_in[ku + i], h[0]);
        for j in 1..=ku {
            s = l_mac(s, h[j], buf_in[ku + i - j]);
        }
        s = l_shl(s, shift);
        y[i] = round_word(s); // Qx
    }
}

/// `floating_point_add`: `x <- x + y` on (Q31 mantissa, exponent) pairs, the value being
/// `m * 2^-e`; the result is renormalised. As in the reference, a zero mantissa must come with
/// exponent 32.
pub fn floating_point_add(mx: &mut i32, ex: &mut i16, my: i32, ey: i16) {
    // Ensure 1 bit headroom before addition.
    let mut acc_x = l_shr(*mx, 1);
    let acc_y = l_shr(my, 1);
    // First, align the Q-points of the two operands. Then, add.
    let align = sub(*ex, ey);
    if align < 0 {
        acc_x = l_add(acc_x, l_shl(acc_y, align));
    } else {
        acc_x = l_add(acc_y, l_shr(acc_x, align));
        *ex = ey;
    }
    // Normalize the result and update the mantissa and exponent.
    let expo = norm_l(acc_x);
    *mx = l_shl(acc_x, expo);
    // Subtract 1 due to the 1-bit down-shift above ensuring 1 bit headroom before addition.
    *ex = sub(add(*ex, expo), 1);
}

/// `pz_filter_sp_fx`: pole-zero filter `b(z)/a(z)` (`PNR`/`PDR` taps beyond the first, Q`Qa`
/// coefficients) over `N` samples of `x` into `y`, single precision: the state `buf` holds the
/// past 16-bit outputs of the all-pole stage, newest first.
pub fn pz_filter_sp(
    b: &[i16],
    a: &[i16],
    x: &[i16],
    y: &mut [i16],
    buf: &mut [i16],
    pnr: i16,
    pdr: i16,
    n: i16,
    qa: i16,
) {
    let mut s = negate(qa);
    s = add(s, s); // s=-2Qa
    s = add(s, 1);
    let pdr_u = pdr.max(0) as usize;
    let pnr_u = pnr.max(0) as usize;
    let order = pdr.max(pnr).max(0) as usize;
    for i in 0..n.max(0) as usize {
        let mut l_acc = l_deposit_h(x[i]); // Lacc in Q(16+Qn)
        l_acc = l_shl(l_acc, s); // Lacc=x[i] in Q(16+Qn-2Qa+1)
        for j in (0..pdr_u).rev() {
            l_acc = l_msu(l_acc, buf[j], a[j + 1]); // Q(16+Qn-2Qa+1)
        }

        l_acc = l_shr(l_acc, 1);
        let l_temp1 = l_add(l_shl(l_acc, qa), 0x08000);
        let s_mem = extract_h(l_temp1);

        l_acc = l_deposit_l(0);
        for j in (0..pnr_u).rev() {
            l_acc = l_mac(l_acc, buf[j], b[j + 1]);
        }
        l_acc = l_mac(l_acc, s_mem, b[0]);
        // Lacc in Q(1+Qc+Qn-Qa)

        // Update filter memory
        for j in (1..order).rev() {
            buf[j] = buf[j - 1];
        }
        buf[0] = s_mem;

        let l_temp1 = l_add(l_shr(l_acc, s), 0x08000); // Ltemp1 in Qc+Qa+Qn=Q(Qn)
        y[i] = extract_h(l_temp1); // y[i] in Qn
    }
}

/// `pz_filter_dp_fx`: [`pz_filter_sp`] with a 32-bit state (the all-pole stage's outputs kept in
/// double precision, products through `Msub_32_16` / `Madd_32_16`).
pub fn pz_filter_dp(
    b: &[i16],
    a: &[i16],
    x: &[i16],
    y: &mut [i16],
    buf: &mut [i32],
    pnr: i16,
    pdr: i16,
    n: i16,
    qa: i16,
) {
    let mut s = negate(qa);
    s = add(s, s); // s=-2Qa
    s = add(s, 1);
    let pdr_u = pdr.max(0) as usize;
    let pnr_u = pnr.max(0) as usize;
    let order = pdr.max(pnr).max(0) as usize;
    for i in 0..n.max(0) as usize {
        let mut l_acc = l_deposit_h(x[i]); // Lacc in Q(16+Qn)
        l_acc = l_shl(l_acc, s); // Lacc=x[i] in Q(16+Qn-2Qa+1)
        for j in (0..pdr_u).rev() {
            l_acc = msub_32_16(l_acc, buf[j], a[j + 1]); // Q(16+Qn-2Qa+1)
        }

        let s_mem = l_shl(l_acc, sub(qa, 1)); // Qn-Qa+16=Qn+Qc

        l_acc = l_deposit_l(0);
        for j in (0..pnr_u).rev() {
            l_acc = madd_32_16(l_acc, buf[j], b[j + 1]);
        }
        l_acc = madd_32_16(l_acc, s_mem, b[0]);
        // Lacc in Q(1+Qc+Qn-Qa)

        // Update filter memory
        for j in (1..order).rev() {
            buf[j] = buf[j - 1];
        }
        buf[0] = s_mem;

        let l_temp1 = l_shr(l_acc, s); // Ltemp1 in Qc+Qa+Qn=Q(16+Qn)
        y[i] = extract_h(l_temp1); // y[i] in Qn
    }
}

/// `root_a_fx`: `sqrt(1 / a)` for a Q`q_a` value `a`, as a Q31 mantissa with its exponent in
/// `exp_out`. A non-positive `a` yields 0 with exponent 0.
pub fn root_a(a: i32, q_a: i16, exp_out: &mut i16) -> i32 {
    if a <= 0 {
        *exp_out = 0;
        return 0;
    }
    let mut exp = norm_l(a);
    let mut tmp = extract_h(l_shl(a, exp));
    exp = sub(exp, sub(30, q_a));
    tmp = div_s(16384, tmp);
    let l_tmp = l_deposit_h(tmp);
    let l_tmp = isqrt_lc(l_tmp, &mut exp);
    *exp_out = exp;
    l_tmp
}

/// `root_a_over_b_fx`: `sqrt(a / b)` for a Q`q_a` value `a` and a Q`q_b` value `b`, as a Q31
/// mantissa with its exponent in `exp_out`. A non-positive operand yields 0 with exponent 0.
pub fn root_a_over_b(a: i32, q_a: i16, b: i32, q_b: i16, exp_out: &mut i16) -> i32 {
    if a <= 0 || b <= 0 {
        *exp_out = 0;
        return 0;
    }
    let mut exp_num = norm_l(b);
    let mut num = round_word(l_shl(b, exp_num));
    exp_num = sub(sub(30, exp_num), q_b);

    let mut exp_den = norm_l(a);
    let den = round_word(l_shl(a, exp_den));
    exp_den = sub(sub(30, exp_den), q_a);

    let scale = shr(sub(den, num), 15);
    num = shl(num, scale);
    exp_num = sub(exp_num, scale);

    let tmp = div_s(num, den);
    let mut exp = sub(exp_num, exp_den);
    let l_tmp = l_deposit_h(tmp);
    let l_tmp = isqrt_lc(l_tmp, &mut exp);
    *exp_out = exp;
    l_tmp
}

/// `Add_flt32_flt32`: sum of two floating-point values (Q31 mantissa, exponent), renormalised.
pub fn add_flt32_flt32(a: i32, exp_a: i16, b: i32, exp_b: i16, exp_out: &mut i16) -> i32 {
    let temp = sub(exp_a.min(exp_b), 1);
    let exp_a = sub(exp_a, temp);
    let a = l_shr(a, exp_a);
    let exp_b = sub(exp_b, temp);
    let b = l_shr(b, exp_b);
    let l_temp = l_add(a, b);
    let temp2 = norm_l(l_temp);
    *exp_out = add(temp, temp2);
    l_shl(l_temp, temp2)
}

/// `Mul_flt32_Q15`: a floating-point value times a Q15 fraction, renormalised (`exp_v` in/out).
pub fn mul_flt32_q15(value: i32, exp_v: &mut i16, frac: i16) -> i32 {
    let l_temp = mult_32_16(value, frac);
    let temp = norm_l(l_temp);
    *exp_v = add(temp, *exp_v);
    l_shl(l_temp, temp)
}

/// `Div_flt32_flt32`: quotient of two floating-point values (Q31 mantissa, exponent), renormalised.
pub fn div_flt32_flt32(a: i32, exp_a: i16, b: i32, exp_b: i16, exp_out: &mut i16) -> i32 {
    let mut temp = div_s(16384, round_word(b));
    let l_temp = mult_32_16(a, temp);
    let mut temp2 = sub(31 - 1, exp_b);
    temp2 = add(temp2, exp_a);
    temp = norm_l(l_temp);
    *exp_out = add(temp, temp2);
    l_shl(l_temp, temp)
}

/// `sum2_fx_mod`: `Σ (2·vec[i]²) >> 9`, saturating.
#[must_use]
pub fn sum2_mod(vec: &[i16], lvec: i16) -> i32 {
    let mut l_tmp = 0;
    for &value in &vec[..lvec.max(0) as usize] {
        l_tmp = l_add(l_tmp, l_shr(l_mult(value, value), 9));
    }
    l_tmp
}

/// `usquant_fx`: uniform scalar quantiser of `x` with the lowest level `qlow`, the step `delta`
/// and `cbsize` levels; returns the index and writes the quantised value to `xq`.
pub fn usquant(x: i16, xq: &mut i16, qlow: i16, delta: i16, cbsize: i16) -> i16 {
    let exp = norm_s(delta);
    let tmp = div_s(shl(1, sub(14, exp)), delta);
    let mut l_tmp = l_mult(sub(x, qlow), tmp);
    let mut idx = extract_l(l_shr_r(
        l_add(l_tmp, i32::from(shl(1, sub(30, exp)))),
        sub(31, exp),
    ));
    idx = idx.min(sub(cbsize, 1));
    idx = idx.max(0);
    l_tmp = l_deposit_l(qlow);
    l_tmp = l_mac(l_tmp, idx, delta);
    *xq = round_word(l_shl(l_tmp, 16));
    idx
}

/// `Exp32Array`: the headroom (`norm_l` of the largest magnitude, 31 if all zero) of `sx[0..n]`.
#[must_use]
pub fn exp32_array(n: i16, sx: &[i32]) -> i16 {
    let mut l_max = l_abs(sx[0]);
    for &value in sx.iter().take(n.max(0) as usize).skip(1) {
        l_max = l_max.max(l_abs(value));
    }
    let mut exp = norm_l(l_max);
    if l_max == 0 {
        exp = 31;
    }
    exp
}

/// `Invert16`: `1/val` for `val >= 1` as a Q15 mantissa with the exponent `*exp` updated
/// (it is both input and output): the result is Q(15 + `*exp`).
pub fn invert16(val: i16, exp: &mut i16) -> i16 {
    // prevent 0 input
    let mut val = val.max(1);
    // Normalize Value
    let temp = norm_s(val);
    val = shl(val, temp);

    // -1 because of 0x4000 is 1.0 in Q14 (and not Q15)
    *exp = sub(sub(15 - 1, *exp), temp);

    div_s(0x4000, val)
}

/// `dot_prod_satcontr`: `Σ x[i]·y[i]` (inputs Q`qx`, Q`qy`) as a 16-bit mantissa, rescaling both
/// inputs by 2 bits (and the result's exponent by 4) until the 32-bit accumulation, started at a
/// rounding offset, no longer saturates; `qo` receives the Q format of the result.
///
/// The reference loops on the STL `Overflow` flag, reset at the top of each pass and raised by the
/// operators `L_shl` (the offset) and `L_mac0` (each product). Each is checked here against the
/// same arithmetic in 64 bits, which is exactly when the reference operator saturates.
pub fn dot_prod_satcontr(x: &[i16], y: &[i16], qx: i16, qy: i16, qo: &mut i16, len: i16) -> i16 {
    let mut tmp_tab_x = [0i16; L_FRAME16K as usize];
    let mut tmp_tab_y = [0i16; L_FRAME16K as usize];
    let count = (len.max(0) as usize).min(L_FRAME16K as usize);

    tmp_tab_x[..count].copy_from_slice(&x[..count]);
    tmp_tab_y[..count].copy_from_slice(&y[..count]);
    let mut shift: i16 = 0;
    let mut l_tmp;
    loop {
        // Overflow = 0
        let mut overflow = false;
        let offset_shift = sub(add(add(qx, qy), 7), shift).max(0);
        l_tmp = l_shl(1, offset_shift);
        if offset_shift >= 31 {
            overflow = true; // 1 << 31 saturates
        }
        for i in 0..count {
            let exact = i64::from(l_tmp) + i64::from(l_mult0(tmp_tab_x[i], tmp_tab_y[i]));
            l_tmp = l_mac0(l_tmp, tmp_tab_x[i], tmp_tab_y[i]); // Q(qx+qy-shift)
            if exact != i64::from(l_tmp) {
                overflow = true;
            }
        }

        if !overflow {
            break;
        }
        scale_sig(&mut tmp_tab_x, len, -2);
        scale_sig(&mut tmp_tab_y, len, -2);
        shift = add(shift, 4);
    }

    let mut q = norm_l(l_tmp);
    l_tmp = l_shl(l_tmp, q); // Q(qx+qy-shift+q)
    let ener = extract_h(l_tmp); // Q(qx+qy-shift+q-16)
    q = add(q, add(qx, qy));
    *qo = sub(q, add(shift, 16));

    ener
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_and_set_fill_exactly_the_requested_prefix() {
        let mut y = [9i16; 4];
        copy(&[1, 2, 3, 4], &mut y, 3);
        assert_eq!(y, [1, 2, 3, 9]);
        set16(&mut y, -5, 2);
        assert_eq!(y, [-5, -5, 3, 9]);
        let mut y32 = [7i32; 3];
        copy32(&[1, 2, 3], &mut y32, 2);
        assert_eq!(y32, [1, 2, 7]);
        set32(&mut y32, 0x12345, 3);
        assert_eq!(y32, [0x12345; 3]);
    }

    #[test]
    fn random_is_the_reference_lcg() {
        // 0·31821 + 13849, then 13849·31821 + 13849 mod 2^16 as a signed value.
        let mut seed = 0;
        assert_eq!(random(&mut seed), 13849);
        assert_eq!(random(&mut seed), (13849i32 * 31821 + 13849) as i16);
    }

    #[test]
    fn root_a_family_rejects_non_positive_operands() {
        let mut exp = 7;
        assert_eq!(root_a(0, 20, &mut exp), 0);
        assert_eq!(exp, 0);
        exp = 7;
        assert_eq!(root_a_over_b(5, 3, 0, 3, &mut exp), 0);
        assert_eq!(exp, 0);
    }

    #[test]
    fn flt32_helpers_renormalise() {
        let mut exp = 0;
        // 0.25 + 0.25 with equal exponents is 0.5 normalised to 0x4000_0000.
        let sum = add_flt32_flt32(0x2000_0000, 1, 0x2000_0000, 1, &mut exp);
        assert_eq!(sum, 0x4000_0000);
        let mut exp_v = 3;
        let product = mul_flt32_q15(0x4000_0000, &mut exp_v, 16384);
        assert_eq!(product, 0x4000_0000);
        assert_eq!(exp_v, 4);
    }

    #[test]
    fn usquant_clamps_the_index_to_the_codebook() {
        let mut xq = 0;
        let idx = usquant(32000, &mut xq, 4096, 2048, 8);
        assert!((0..8).contains(&idx));
        assert_eq!(idx, usquant(i16::MAX, &mut xq, 4096, 2048, 8));
        assert_eq!(usquant(i16::MIN, &mut xq, 4096, 2048, 8), 0);
        assert_eq!(xq, 4096);
    }

    #[test]
    fn sum2_mod_scales_the_energy_down_by_nine_bits() {
        assert_eq!(sum2_mod(&[512, 512], 2), 2 * ((2 * 512 * 512) >> 9));
    }
}
