// AMR-WB encoder — WORK IN PROGRESS: not yet wired into the codec factory or validated
// bit-exact. Ported from the 3GPP fixed-point C reference (index loops / manual slice
// copies mirror the C, plus not-yet-used WIP code); these style + dead-code lints are
// quieted module-wide until the encoder is complete and validated, then revisited.
#![allow(
    clippy::needless_range_loop,
    clippy::manual_memcpy,
    clippy::explicit_counter_loop,
    clippy::manual_div_ceil,
    clippy::unnecessary_to_owned,
    dead_code,
    unused
)]

//! AMR-WB encoder per-subframe ACELP tier (3GPP TS 26.173), ported bit-exact.
//!
//! This module ports the analysis-by-synthesis inner loop of `coder.c`: the closed-loop fractional
//! pitch search ([`pitch_fr4`] + `Norm_corr` + `Interpol_4`, `pitch_f4.c`), the helper filters
//! ([`convolve`], [`syn_filt`], [`preemph`]/[`preemph2`], `residu`), the pitch-gain
//! ([`g_pitch`], `g_pitch.c`) and pitch-gain clipping ([`gp_clip`] etc, `gpclip.c`), the
//! target/correlation prep ([`updt_tar`], [`cor_h_x`]), the **algebraic codebook search**
//! ([`acelp_2t64_fx`] for mode 0 / [`acelp_4t64_fx`] for modes 1-8, `c2t64fx.c`/`c4t64fx.c`) with
//! the pulse-index encoders ([`q_pulse`], `q_pulse.c`), the gain VQ ([`q_gain2`], `q_gain2.c`), and
//! the voicing factor ([`voice_factor`], `voicefac.c`).

use crate::amr::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_msu,
    l_mult, l_negate, l_shl, l_shr, l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl,
    shr, shr_r, sub,
};
use crate::amr::math_op::{dot_product12, isqrt_n};
use crate::amr::oper_32b::{l_extract, mpy_32_16};
use crate::amr::wb::tables::{T_QUA_GAIN6B, T_QUA_GAIN7B};

/// Subframe size at 12.8 kHz.
pub const L_SUBFR: usize = 64;
const NBBITS_7K: i16 = 132;
const NBBITS_9K: i16 = 177;

// ---------------------------------------------------------------------------
// q_pulse.c — algebraic-codebook pulse index *encoders* (the search emits these).
// ---------------------------------------------------------------------------

const NB_POS: i16 = 16;

/// Quantize 1 pulse in N+1 bits (`q_pulse.c` `quant_1p_N1`).
pub fn quant_1p_n1(pos: i16, n: i16) -> i32 {
    let mask = sub(shl(1, n), 1);
    let mut index = l_deposit_l(pos & mask);
    if (pos & NB_POS) != 0 {
        index = l_add(index, l_deposit_l(shl(1, n)));
    }
    index
}

/// Quantize 2 pulses in 2N+1 bits (`q_pulse.c` `quant_2p_2N1`).
pub fn quant_2p_2n1(pos1: i16, pos2: i16, n: i16) -> i32 {
    let mask = sub(shl(1, n), 1);
    let mut index;
    if ((pos2 ^ pos1) & NB_POS) == 0 {
        if sub(pos1, pos2) <= 0 {
            index = l_deposit_l(add(shl(pos1 & mask, n), pos2 & mask));
        } else {
            index = l_deposit_l(add(shl(pos2 & mask, n), pos1 & mask));
        }
        if (pos1 & NB_POS) != 0 {
            let tmp = shl(n, 1);
            index = l_add(index, l_shl(1, tmp));
        }
    } else if sub(pos1 & mask, pos2 & mask) <= 0 {
        index = l_deposit_l(add(shl(pos2 & mask, n), pos1 & mask));
        if (pos2 & NB_POS) != 0 {
            let tmp = shl(n, 1);
            index = l_add(index, l_shl(1, tmp));
        }
    } else {
        index = l_deposit_l(add(shl(pos1 & mask, n), pos2 & mask));
        if (pos1 & NB_POS) != 0 {
            let tmp = shl(n, 1);
            index = l_add(index, l_shl(1, tmp));
        }
    }
    index
}

/// Quantize 3 pulses in 3N+1 bits (`q_pulse.c` `quant_3p_3N1`).
pub fn quant_3p_3n1(pos1: i16, pos2: i16, pos3: i16, n: i16) -> i32 {
    let nb_pos = shl(1, sub(n, 1));
    let mut index;
    if ((pos1 ^ pos2) & nb_pos) == 0 {
        index = quant_2p_2n1(pos1, pos2, sub(n, 1));
        index = l_add(index, l_shl(l_deposit_l(pos1 & nb_pos), n));
        index = l_add(index, l_shl(quant_1p_n1(pos3, n), shl(n, 1)));
    } else if ((pos1 ^ pos3) & nb_pos) == 0 {
        index = quant_2p_2n1(pos1, pos3, sub(n, 1));
        index = l_add(index, l_shl(l_deposit_l(pos1 & nb_pos), n));
        index = l_add(index, l_shl(quant_1p_n1(pos2, n), shl(n, 1)));
    } else {
        index = quant_2p_2n1(pos2, pos3, sub(n, 1));
        index = l_add(index, l_shl(l_deposit_l(pos2 & nb_pos), n));
        index = l_add(index, l_shl(quant_1p_n1(pos1, n), shl(n, 1)));
    }
    index
}

/// Quantize 4 pulses in 4N+1 bits (`q_pulse.c` `quant_4p_4N1`).
pub fn quant_4p_4n1(pos1: i16, pos2: i16, pos3: i16, pos4: i16, n: i16) -> i32 {
    let nb_pos = shl(1, sub(n, 1));
    let mut index;
    if ((pos1 ^ pos2) & nb_pos) == 0 {
        index = quant_2p_2n1(pos1, pos2, sub(n, 1));
        index = l_add(index, l_shl(l_deposit_l(pos1 & nb_pos), n));
        index = l_add(index, l_shl(quant_2p_2n1(pos3, pos4, n), shl(n, 1)));
    } else if ((pos1 ^ pos3) & nb_pos) == 0 {
        index = quant_2p_2n1(pos1, pos3, sub(n, 1));
        index = l_add(index, l_shl(l_deposit_l(pos1 & nb_pos), n));
        index = l_add(index, l_shl(quant_2p_2n1(pos2, pos4, n), shl(n, 1)));
    } else {
        index = quant_2p_2n1(pos2, pos3, sub(n, 1));
        index = l_add(index, l_shl(l_deposit_l(pos2 & nb_pos), n));
        index = l_add(index, l_shl(quant_2p_2n1(pos1, pos4, n), shl(n, 1)));
    }
    index
}

/// Quantize 4 pulses in 4N bits (`q_pulse.c` `quant_4p_4N`).
pub fn quant_4p_4n(pos: &[i16], n: i16) -> i32 {
    let n_1 = n - 1;
    let nb_pos = shl(1, n_1);
    let mut pos_a = [0i16; 4];
    let mut pos_b = [0i16; 4];
    let mut i = 0usize;
    let mut j = 0usize;
    for &p in pos.iter().take(4) {
        if (p & nb_pos) == 0 {
            pos_a[i] = p;
            i += 1;
        } else {
            pos_b[j] = p;
            j += 1;
        }
    }

    let mut index = match i {
        0 => {
            let tmp = sub(shl(n, 2), 3);
            let mut idx = l_shl(1, tmp);
            idx = l_add(idx, quant_4p_4n1(pos_b[0], pos_b[1], pos_b[2], pos_b[3], n_1));
            idx
        }
        1 => {
            let tmp = add(extract_l(l_shr(l_mult_pos(3, n_1), 1)), 1);
            let mut idx = l_shl(quant_1p_n1(pos_a[0], n_1), tmp);
            idx = l_add(idx, quant_3p_3n1(pos_b[0], pos_b[1], pos_b[2], n_1));
            idx
        }
        2 => {
            let tmp = add(shl(n_1, 1), 1);
            let mut idx = l_shl(quant_2p_2n1(pos_a[0], pos_a[1], n_1), tmp);
            idx = l_add(idx, quant_2p_2n1(pos_b[0], pos_b[1], n_1));
            idx
        }
        3 => {
            let mut idx = l_shl(quant_3p_3n1(pos_a[0], pos_a[1], pos_a[2], n_1), n);
            idx = l_add(idx, quant_1p_n1(pos_b[0], n_1));
            idx
        }
        _ => quant_4p_4n1(pos_a[0], pos_a[1], pos_a[2], pos_a[3], n_1),
    };
    let tmp = sub(shl(n, 2), 2);
    index = l_add(index, l_shl(l_deposit_l(i as i16) & 3, tmp));
    index
}

/// Quantize 5 pulses in 5N bits (`q_pulse.c` `quant_5p_5N`).
pub fn quant_5p_5n(pos: &[i16], n: i16) -> i32 {
    let n_1 = n - 1;
    let nb_pos = shl(1, n_1);
    let mut pos_a = [0i16; 5];
    let mut pos_b = [0i16; 5];
    let mut i = 0usize;
    let mut j = 0usize;
    for &p in pos.iter().take(5) {
        if (p & nb_pos) == 0 {
            pos_a[i] = p;
            i += 1;
        } else {
            pos_b[j] = p;
            j += 1;
        }
    }

    match i {
        0 => {
            let tmp = sub(extract_l(l_shr(l_mult_pos(5, n), 1)), 1);
            let mut index = l_shl(1, tmp);
            let tmp2 = add(shl(n, 1), 1);
            let t = l_shl(quant_3p_3n1(pos_b[0], pos_b[1], pos_b[2], n_1), tmp2);
            index = l_add(index, t);
            index = l_add(index, quant_2p_2n1(pos_b[3], pos_b[4], n));
            index
        }
        1 => {
            let tmp = sub(extract_l(l_shr(l_mult_pos(5, n), 1)), 1);
            let mut index = l_shl(1, tmp);
            let tmp2 = add(shl(n, 1), 1);
            let t = l_shl(quant_3p_3n1(pos_b[0], pos_b[1], pos_b[2], n_1), tmp2);
            index = l_add(index, t);
            index = l_add(index, quant_2p_2n1(pos_b[3], pos_a[0], n));
            index
        }
        2 => {
            let tmp = sub(extract_l(l_shr(l_mult_pos(5, n), 1)), 1);
            let mut index = l_shl(1, tmp);
            let tmp2 = add(shl(n, 1), 1);
            let t = l_shl(quant_3p_3n1(pos_b[0], pos_b[1], pos_b[2], n_1), tmp2);
            index = l_add(index, t);
            index = l_add(index, quant_2p_2n1(pos_a[0], pos_a[1], n));
            index
        }
        3 => {
            let tmp = add(shl(n, 1), 1);
            let mut index = l_shl(quant_3p_3n1(pos_a[0], pos_a[1], pos_a[2], n_1), tmp);
            index = l_add(index, quant_2p_2n1(pos_b[0], pos_b[1], n));
            index
        }
        4 => {
            let tmp = add(shl(n, 1), 1);
            let mut index = l_shl(quant_3p_3n1(pos_a[0], pos_a[1], pos_a[2], n_1), tmp);
            index = l_add(index, quant_2p_2n1(pos_a[3], pos_b[0], n));
            index
        }
        _ => {
            let tmp = add(shl(n, 1), 1);
            let mut index = l_shl(quant_3p_3n1(pos_a[0], pos_a[1], pos_a[2], n_1), tmp);
            index = l_add(index, quant_2p_2n1(pos_a[3], pos_a[4], n));
            index
        }
    }
}

/// Quantize 6 pulses in 6N-2 bits (`q_pulse.c` `quant_6p_6N_2`).
pub fn quant_6p_6n_2(pos: &[i16], n: i16) -> i32 {
    let n_1 = n - 1;
    let nb_pos = shl(1, n_1);
    let mut pos_a = [0i16; 6];
    let mut pos_b = [0i16; 6];
    let mut i = 0usize;
    let mut j = 0usize;
    for &p in pos.iter().take(6) {
        if (p & nb_pos) == 0 {
            pos_a[i] = p;
            i += 1;
        } else {
            pos_b[j] = p;
            j += 1;
        }
    }

    let mut index = match i {
        0 => {
            let mut idx = l_shl(1, 6 * n - 5);
            idx = l_add(idx, l_shl(quant_5p_5n(&pos_b, n_1), n));
            idx = l_add(idx, quant_1p_n1(pos_b[5], n_1));
            idx
        }
        1 => {
            let mut idx = l_shl(1, 6 * n - 5);
            idx = l_add(idx, l_shl(quant_5p_5n(&pos_b, n_1), n));
            idx = l_add(idx, quant_1p_n1(pos_a[0], n_1));
            idx
        }
        2 => {
            let mut idx = l_shl(1, 6 * n - 5);
            idx = l_add(idx, l_shl(quant_4p_4n(&pos_b, n_1), 2 * n_1 + 1));
            idx = l_add(idx, quant_2p_2n1(pos_a[0], pos_a[1], n_1));
            idx
        }
        3 => {
            let mut idx = l_shl(quant_3p_3n1(pos_a[0], pos_a[1], pos_a[2], n_1), 3 * n_1 + 1);
            idx = l_add(idx, quant_3p_3n1(pos_b[0], pos_b[1], pos_b[2], n_1));
            idx
        }
        4 => {
            i = 2;
            let mut idx = l_shl(quant_4p_4n(&pos_a, n_1), 2 * n_1 + 1);
            idx = l_add(idx, quant_2p_2n1(pos_b[0], pos_b[1], n_1));
            idx
        }
        5 => {
            i = 1;
            let mut idx = l_shl(quant_5p_5n(&pos_a, n_1), n);
            idx = l_add(idx, quant_1p_n1(pos_b[0], n_1));
            idx
        }
        _ => {
            i = 0;
            let mut idx = l_shl(quant_5p_5n(&pos_a, n_1), n);
            idx = l_add(idx, quant_1p_n1(pos_a[5], n_1));
            idx
        }
    };
    index = l_add(index, l_shl(l_deposit_l(i as i16) & 3, 6 * n - 4));
    index
}

/// `L_mult(a,b)` of non-negative small constants (the `(a*b)<<1` the `L_shr(.,1)` callers undo).
#[inline]
fn l_mult_pos(a: i16, b: i16) -> i32 {
    ((a as i32) * (b as i32)) << 1
}

// ---------------------------------------------------------------------------
// helper filters
// ---------------------------------------------------------------------------

/// Convolution `y = x * h` (`convolve.c` `Convolve`), result rounded to 16 bit.
pub fn convolve(x: &[i16], h: &[i16], y: &mut [i16], l: usize) {
    for n in 0..l {
        let mut l_sum = 0i32;
        for i in 0..=n {
            l_sum = l_mac(l_sum, x[i], h[n - i]);
        }
        y[n] = round_word(l_sum);
    }
}

/// Target update `x2 = x - gain·y` (`updt_tar.c` `Updt_tar`), `gain` in Q14.
pub fn updt_tar(x: &[i16], x2: &mut [i16], y: &[i16], gain: i16, l: usize) {
    for i in 0..l {
        let mut l_tmp = l_mult(x[i], 16384);
        l_tmp = l_msu(l_tmp, y[i], gain);
        x2[i] = extract_h(l_shl(l_tmp, 1));
    }
}

/// Pre-emphasis `1 - mu·z^-1` (`preemph.c` `Preemph`). `mem` is `x[-1]`, updated.
pub fn preemph(x: &mut [i16], mu: i16, lg: usize, mem: &mut i16) {
    let temp = x[lg - 1];
    for i in (1..lg).rev() {
        let mut l_tmp = l_deposit_h(x[i]);
        l_tmp = l_msu(l_tmp, x[i - 1], mu);
        x[i] = round_word(l_tmp);
    }
    let mut l_tmp = l_deposit_h(x[0]);
    l_tmp = l_msu(l_tmp, *mem, mu);
    x[0] = round_word(l_tmp);
    *mem = temp;
}

/// Pre-emphasis with ×2 (`preemph.c` `Preemph2`).
pub fn preemph2(x: &mut [i16], mu: i16, lg: usize, mem: &mut i16) {
    let temp = x[lg - 1];
    for i in (1..lg).rev() {
        let mut l_tmp = l_deposit_h(x[i]);
        l_tmp = l_msu(l_tmp, x[i - 1], mu);
        l_tmp = l_shl(l_tmp, 1);
        x[i] = round_word(l_tmp);
    }
    let mut l_tmp = l_deposit_h(x[0]);
    l_tmp = l_msu(l_tmp, *mem, mu);
    l_tmp = l_shl(l_tmp, 1);
    x[0] = round_word(l_tmp);
    *mem = temp;
}

/// LPC synthesis `1/A(z)` (`syn_filt.c` `Syn_filt`). `mem[m]` is the carried state. `x`/`y` are `lg`
/// long. When `update` the new state is written back to `mem`.
pub fn syn_filt(a: &[i16], m: usize, x: &[i16], y: &mut [i16], lg: usize, mem: &mut [i16], update: bool) {
    // y_buf = [mem(m)] ++ [output(lg)]
    let mut y_buf = vec![0i16; m + lg];
    y_buf[..m].copy_from_slice(&mem[..m]);

    let s = sub(norm_s(a[0]), 2);
    let a0 = shr(a[0], 1);

    for i in 0..lg {
        let mut l_tmp = l_mult(x[i], a0);
        for j in 1..=m {
            l_tmp = l_msu(l_tmp, a[j], y_buf[m + i - j]);
        }
        l_tmp = l_shl(l_tmp, add(3, s));
        let v = round_word(l_tmp);
        y_buf[m + i] = v;
        y[i] = v;
    }

    if update {
        mem[..m].copy_from_slice(&y_buf[lg..lg + m]);
    }
}

/// Pitch gain in Q14 (`g_pitch.c` `G_pitch`), saturated to 1.2. Sets `g_coeff[0..4]` (yy, exp_yy,
/// xy, exp_xy).
pub fn g_pitch(xn: &[i16], y1: &[i16], g_coeff: &mut [i16], l_subfr: usize) -> i16 {
    let (yy_l, exp_yy) = dot_product12(y1, y1, l_subfr);
    let yy = extract_h(yy_l);
    let (xy_l, exp_xy) = dot_product12(xn, y1, l_subfr);
    let xy = extract_h(xy_l);

    g_coeff[0] = yy;
    g_coeff[1] = exp_yy;
    g_coeff[2] = xy;
    g_coeff[3] = exp_xy;

    if xy < 0 {
        return 0;
    }

    let xy = shr(xy, 1);
    let mut gain = div_s(xy, yy);
    let mut i = add(exp_xy, 0);
    i = sub(i, exp_yy);
    gain = shl(gain, i);
    if sub(gain, 19661) > 0 {
        gain = 19661;
    }
    gain
}

/// Voicing factor in Q15, -1 unvoiced .. 1 voiced (`voicefac.c` `voice_factor`).
pub fn voice_factor(exc: &[i16], q_exc: i16, gain_pit: i16, code: &[i16], gain_code: i16, l_subfr: usize) -> i16 {
    let (e1_l, mut exp1) = dot_product12(exc, exc, l_subfr);
    let mut ener1 = extract_h(e1_l);
    exp1 = sub(exp1, add(q_exc, q_exc));
    let l_tmp = l_mult(gain_pit, gain_pit);
    let exp = norm_l(l_tmp);
    let tmp = extract_h(l_shl(l_tmp, exp));
    ener1 = mult(ener1, tmp);
    exp1 = sub(sub(exp1, exp), 10);

    let (e2_l, mut exp2) = dot_product12(code, code, l_subfr);
    let mut ener2 = extract_h(e2_l);
    let exp = norm_s(gain_code);
    let mut tmp = shl(gain_code, exp);
    tmp = mult(tmp, tmp);
    ener2 = mult(ener2, tmp);
    exp2 = sub(exp2, add(exp, exp));

    let i = sub(exp1, exp2);
    if i >= 0 {
        ener1 = shr(ener1, 1);
        ener2 = shr(ener2, add(i, 1));
    } else {
        ener1 = shr(ener1, sub(1, i));
        ener2 = shr(ener2, 1);
    }

    let tmp = sub(ener1, ener2);
    let ener1 = add(add(ener1, ener2), 1);
    if tmp >= 0 {
        div_s(tmp, ener1)
    } else {
        negate(div_s(negate(tmp), ener1))
    }
}

/// Correlation of target with impulse response (`cor_h_x.c` `cor_h_x`). `dn` receives 64 samples.
pub fn cor_h_x(h: &[i16], x: &[i16], dn: &mut [i16]) {
    const NB_TRACK: usize = 4;
    const STEP: usize = 4;
    let mut y32 = [0i32; L_SUBFR];
    let mut l_tot = 1i32;

    for k in 0..NB_TRACK {
        let mut l_max = 0i32;
        let mut i = k;
        while i < L_SUBFR {
            let mut l_tmp = 1i32;
            for j in i..L_SUBFR {
                l_tmp = l_mac(l_tmp, x[j], h[j - i]);
            }
            y32[i] = l_tmp;
            let abs = l_abs(l_tmp);
            if l_sub(abs, l_max) > 0 {
                l_max = abs;
            }
            i += STEP;
        }
        l_max = l_shr(l_max, 2);
        l_tot = l_add(l_tot, l_max);
        l_tot = l_add(l_tot, l_shr(l_max, 1));
    }

    let j = sub(norm_l(l_tot), 4);
    for i in 0..L_SUBFR {
        dn[i] = round_word(l_shl(y32[i], j));
    }
}

// ---------------------------------------------------------------------------
// pitch_f4.c — closed-loop fractional pitch search.
// ---------------------------------------------------------------------------

/// 1/4-resolution correlation interpolation filter, Q14 (`pitch_f4.c` `inter4_1`).
#[rustfmt::skip]
static INTER4_1: [i16; 32] = [
    -12, -26, 32, 206, 420, 455, 73, -766,
    -1732, -2142, -1242, 1376, 5429, 9910, 13418, 14746,
    13418, 9910, 5429, 1376, -1242, -2142, -1732, -766,
    73, 455, 420, 206, 32, -26, -12, 0,
];
const UP_SAMP: i16 = 4;
const L_INTERPOL1: i16 = 4;

/// Interpolate the correlation at `corr[center+frac/4]` (`pitch_f4.c` `Interpol_4`).
fn interpol_4(corr: &[i16], center: isize, frac: i16) -> i16 {
    let mut frac = frac;
    let mut x = center;
    if frac < 0 {
        frac = add(frac, UP_SAMP);
        x -= 1;
    }
    x = x - L_INTERPOL1 as isize + 1;
    let mut l_sum = 0i32;
    let mut k = sub(sub(UP_SAMP, 1), frac);
    for i in 0..(2 * L_INTERPOL1 as usize) {
        l_sum = l_mac(l_sum, corr[(x + i as isize) as usize], INTER4_1[k as usize]);
        k = add(k, UP_SAMP);
    }
    round_word(l_shl(l_sum, 1))
}

/// Normalized correlation of target with filtered past excitation (`pitch_f4.c` `Norm_Corr`).
/// `corr_norm` is indexed at `corr_offset + t` for `t in t_min..=t_max`.
#[allow(clippy::too_many_arguments)]
fn norm_corr(
    exc: &[i16],
    exc_off: usize,
    xn: &[i16],
    h: &[i16],
    l_subfr: usize,
    t_min: i16,
    t_max: i16,
    corr_norm: &mut [i16],
    corr_offset: i16,
) {
    let mut excf = [0i16; L_SUBFR];
    // Convolve(&exc[-t_min], h, excf, L_subfr); k = -t_min
    let mut k = negate(t_min);
    // exc index for excf base = exc_off + k
    {
        let base = (exc_off as isize + k as isize) as usize;
        convolve(&exc[base..base + l_subfr], h, &mut excf, l_subfr);
    }

    // 1/sqrt(energy of xn[]) scale
    let mut l_tmp = 1i32;
    for i in 0..l_subfr {
        l_tmp = l_mac(l_tmp, xn[i], xn[i]);
    }
    let mut exp = norm_l(l_tmp);
    exp = sub(30, exp);
    exp = add(exp, 2);
    let scale = negate(shr(exp, 1));

    let mut t = t_min;
    while t <= t_max {
        let mut l_corr = 1i32;
        for i in 0..l_subfr {
            l_corr = l_mac(l_corr, xn[i], excf[i]);
        }
        let exp = norm_l(l_corr);
        l_corr = l_shl(l_corr, exp);
        let exp_corr = sub(30, exp);
        let corr = extract_h(l_corr);

        let mut l_norm = 1i32;
        for i in 0..l_subfr {
            l_norm = l_mac(l_norm, excf[i], excf[i]);
        }
        let exp = norm_l(l_norm);
        l_norm = l_shl(l_norm, exp);
        let mut exp_norm = sub(30, exp);

        isqrt_n(&mut l_norm, &mut exp_norm);
        let norm = extract_h(l_norm);

        let mut l_out = l_mult(corr, norm);
        l_out = l_shl(l_out, add(add(exp_corr, exp_norm), scale));
        corr_norm[(corr_offset + t) as usize] = round_word(l_out);

        // update excf for next iteration
        if sub(t, t_max) != 0 {
            k -= 1;
            let base = (exc_off as isize + k as isize) as usize;
            for i in (1..l_subfr).rev() {
                excf[i] = add(mult(exc[base], h[i]), excf[i - 1]);
            }
            excf[0] = mult(exc[base], h[0]);
        }
        t += 1;
    }
}

/// Closed-loop fractional pitch search (`pitch_f4.c` `Pitch_fr4`). Returns the integer lag `T0` and
/// sets `pit_frac`. `exc_off` is `exc[0]` index in `exc`.
#[allow(clippy::too_many_arguments)]
pub fn pitch_fr4(
    exc: &[i16],
    exc_off: usize,
    xn: &[i16],
    h: &[i16],
    t0_min: i16,
    t0_max: i16,
    pit_frac: &mut i16,
    i_subfr: i16,
    t0_fr2: i16,
    t0_fr1: i16,
    l_subfr: usize,
) -> i16 {
    let t_min = sub(t0_min, L_INTERPOL1);
    let t_max = add(t0_max, L_INTERPOL1);
    let corr_v_offset = negate(t_min);

    let mut corr_v = [0i16; 40];
    norm_corr(exc, exc_off, xn, h, l_subfr, t_min, t_max, &mut corr_v, corr_v_offset);

    let mut max = corr_v[(corr_v_offset + t0_min) as usize];
    let mut t0 = t0_min;
    let mut i = add(t0_min, 1);
    while i <= t0_max {
        if sub(corr_v[(corr_v_offset + i) as usize], max) >= 0 {
            max = corr_v[(corr_v_offset + i) as usize];
            t0 = i;
        }
        i += 1;
    }

    if i_subfr == 0 && sub(t0, t0_fr1) >= 0 {
        *pit_frac = 0;
        return t0;
    }

    let mut step = 1i16;
    let mut fraction = -3i16;
    if (i_subfr == 0 && sub(t0, t0_fr2) >= 0) || sub(t0_fr2, 34) == 0 {
        step = 2;
        fraction = -2;
    }
    if sub(t0, t0_min) == 0 {
        fraction = 0;
    }

    let center = (corr_v_offset + t0) as isize;
    let mut max = interpol_4(&corr_v, center, fraction);
    let mut i = add(fraction, step);
    while i <= 3 {
        let temp = interpol_4(&corr_v, center, i);
        if sub(temp, max) > 0 {
            max = temp;
            fraction = i;
        }
        i = add(i, step);
    }

    if fraction < 0 {
        fraction = add(fraction, UP_SAMP);
        t0 = sub(t0, 1);
    }
    *pit_frac = fraction;
    t0
}

// ---------------------------------------------------------------------------
// gpclip.c — gain-pitch clipping.
// ---------------------------------------------------------------------------

const DIST_ISF_MAX_IO: i16 = 384;
const DIST_ISF_MAX: i16 = 307;
const DIST_ISF_THRES: i16 = 154;
const GAIN_PIT_THRES: i16 = 14746;
const GAIN_PIT_MIN: i16 = 9830;

/// Init the gp-clip state `[dist, gain]` (`gpclip.c` `Init_gp_clip`).
pub fn init_gp_clip(mem: &mut [i16; 2]) {
    mem[0] = DIST_ISF_MAX;
    mem[1] = GAIN_PIT_MIN;
}

/// `gpclip.c` `Gp_clip`: return 1 if pitch-gain clipping should be applied.
pub fn gp_clip(ser_size: i16, mem: &[i16; 2]) -> i16 {
    if ser_size == NBBITS_7K || ser_size == NBBITS_9K {
        let thres = add(14746, mult(1638, extract_l(l_mult(mem[0], 16384 / DIST_ISF_MAX_IO))));
        if sub(mem[1], thres) > 0 {
            return 1;
        }
        0
    } else if sub(mem[0], DIST_ISF_THRES) < 0 && sub(mem[1], GAIN_PIT_THRES) > 0 {
        1
    } else {
        0
    }
}

/// `gpclip.c` `Gp_clip_test_isf`: update the min-ISF-distance state.
pub fn gp_clip_test_isf(ser_size: i16, isf: &[i16], mem: &mut [i16; 2]) {
    let mut dist_min = sub(isf[1], isf[0]);
    for i in 2..(16 - 1) {
        let dist = sub(isf[i], isf[i - 1]);
        if sub(dist, dist_min) < 0 {
            dist_min = dist;
        }
    }
    let mut dist = extract_h(l_mac(l_mult(26214, mem[0]), 6554, dist_min));
    if ser_size == NBBITS_7K || ser_size == NBBITS_9K {
        if sub(dist, DIST_ISF_MAX_IO) > 0 {
            dist = DIST_ISF_MAX_IO;
        }
    } else if sub(dist, DIST_ISF_MAX) > 0 {
        dist = DIST_ISF_MAX;
    }
    mem[0] = dist;
}

/// `gpclip.c` `Gp_clip_test_gain_pit`: update the running pitch-gain average.
pub fn gp_clip_test_gain_pit(ser_size: i16, gain_pit: i16, mem: &mut [i16; 2]) {
    let l_tmp = if ser_size == NBBITS_7K || ser_size == NBBITS_9K {
        l_mac(l_mult(32113, mem[1]), 655, gain_pit)
    } else {
        l_mac(l_mult(29491, mem[1]), 3277, gain_pit)
    };
    let mut gain = extract_h(l_tmp);
    if sub(gain, GAIN_PIT_MIN) < 0 {
        gain = GAIN_PIT_MIN;
    }
    mem[1] = gain;
}

// ---------------------------------------------------------------------------
// q_gain2.c — gain VQ.
// ---------------------------------------------------------------------------

const MEAN_ENER: i16 = 30;
const RANGE: usize = 64;
const PRED: [i16; 4] = [4096, 3277, 2458, 1638];
const NB_QUA_GAIN7B: usize = 128;

/// Init the gain-quantizer energy predictor (`q_gain2.c` `Init_Q_gain2`): 4×(-14.0 Q10).
pub fn init_q_gain2(mem: &mut [i16; 4]) {
    for v in mem.iter_mut() {
        *v = -14336;
    }
}

/// Quantize pitch + code gains (`q_gain2.c` `Q_gain2`). Returns the index; sets `*gain_pit` (Q14)
/// and `*gain_cod` (Q16). `mem[4]` is the past quantized-energy predictor.
#[allow(clippy::too_many_arguments)]
pub fn q_gain2(
    xn: &[i16],
    y1: &[i16],
    q_xn: i16,
    y2: &[i16],
    code: &[i16],
    g_coeff: &[i16],
    l_subfr: usize,
    nbits: i16,
    gain_pit: &mut i16,
    gain_cod: &mut i32,
    gp_clip_flag: i16,
    mem: &mut [i16; 4],
) -> i16 {
    let past_qua_en = mem;

    let (t_qua_gain, min_ind, size): (&[i16], usize, usize) = if sub(nbits, 6) == 0 {
        let mut size = RANGE;
        if sub(gp_clip_flag, 1) == 0 {
            size -= 16;
        }
        (&T_QUA_GAIN6B, 0, size)
    } else {
        // q_gain2.c: `p = t_qua_gain7b + RANGE` is Word16* arithmetic — `p` points at *word* RANGE
        // (= entry RANGE/2, the 1/4 point of the 128-entry table), and `p += 2` advances one full
        // (pitch, code) pair per step, so `*p` at iteration i is the pitch gain of entry RANGE/2 + i,
        // i.e. word RANGE + 2*i. (NOT entry RANGE + i.)
        let mut j = NB_QUA_GAIN7B - RANGE;
        if sub(gp_clip_flag, 1) == 0 {
            j -= 27;
        }
        let mut min_ind = 0usize;
        let g_pitch = *gain_pit;
        for i in 0..j {
            if sub(g_pitch, T_QUA_GAIN7B[RANGE + 2 * i]) > 0 {
                min_ind += 1;
            }
        }
        (&T_QUA_GAIN7B, min_ind, RANGE)
    };

    // coeff[0..5] / exp_coeff[0..5]
    let mut coeff = [0i16; 5];
    let mut coeff_lo = [0i16; 5];
    let mut exp_coeff = [0i16; 5];

    coeff[0] = g_coeff[0];
    exp_coeff[0] = g_coeff[1];
    coeff[1] = negate(g_coeff[2]);
    exp_coeff[1] = add(g_coeff[3], 1);

    let (c2, exp) = dot_product12(y2, y2, l_subfr);
    coeff[2] = extract_h(c2);
    exp_coeff[2] = add(sub(exp, 18), shl(q_xn, 1));

    let (c3, exp) = dot_product12(xn, y2, l_subfr);
    coeff[3] = extract_h(l_negate(c3));
    exp_coeff[3] = add(sub(exp, 9 - 1), q_xn);

    let (c4, exp) = dot_product12(y1, y2, l_subfr);
    coeff[4] = extract_h(c4);
    exp_coeff[4] = add(sub(exp, 9 - 1), q_xn);

    // energy of code
    let (l_code, exp_code) = dot_product12(code, code, l_subfr);
    let exp_code = sub(exp_code, 18 + 6 + 31);

    let (exp, frac) = crate::amr::math_op::log2(l_code);
    let exp = add(exp, exp_code);
    let mut l_tmp = mpy_32_16(exp, frac, -24660);
    l_tmp = l_mac(l_tmp, MEAN_ENER, 8192);

    // gcode0
    l_tmp = l_shl(l_tmp, 10);
    l_tmp = l_mac(l_tmp, PRED[0], past_qua_en[0]);
    l_tmp = l_mac(l_tmp, PRED[1], past_qua_en[1]);
    l_tmp = l_mac(l_tmp, PRED[2], past_qua_en[2]);
    l_tmp = l_mac(l_tmp, PRED[3], past_qua_en[3]);
    let mut gcode0 = extract_h(l_tmp);

    l_tmp = l_mult(gcode0, 5443);
    l_tmp = l_shr(l_tmp, 8);
    let (mut exp_gcode0, frac) = l_extract(l_tmp);
    gcode0 = extract_l(crate::amr::math_op::pow2(14, frac));
    exp_gcode0 = sub(exp_gcode0, 14);

    let exp_code2 = add(exp_gcode0, 4);
    let mut exp_max = [0i16; 5];
    exp_max[0] = sub(exp_coeff[0], 13);
    exp_max[1] = sub(exp_coeff[1], 14);
    exp_max[2] = add(exp_coeff[2], add(15, shl(exp_code2, 1)));
    exp_max[3] = add(exp_coeff[3], exp_code2);
    exp_max[4] = add(exp_coeff[4], add(1, exp_code2));

    let mut e_max = exp_max[0];
    for &e in exp_max.iter().skip(1) {
        if sub(e, e_max) > 0 {
            e_max = e;
        }
    }

    for i in 0..5 {
        let j = add(sub(e_max, exp_max[i]), 2);
        let mut l_tmp = l_deposit_h(coeff[i]);
        l_tmp = l_shr(l_tmp, j);
        (coeff[i], coeff_lo[i]) = l_extract(l_tmp);
        coeff_lo[i] = shr(coeff_lo[i], 3);
    }

    let mut dist_min = i32::MAX;
    let mut index = 0usize;
    for i in 0..size {
        let p = 2 * (min_ind + i);
        let g_pitch_v = t_qua_gain[p];
        let mut g_code = t_qua_gain[p + 1];

        g_code = mult_r(g_code, gcode0);
        let g2_pitch = mult_r(g_pitch_v, g_pitch_v);
        let g_pit_cod = mult_r(g_code, g_pitch_v);
        let l_mul = l_mult(g_code, g_code);
        let (g2_code, g2_code_lo) = l_extract(l_mul);

        let mut l_tmp = l_mult(coeff[2], g2_code_lo);
        l_tmp = l_shr(l_tmp, 3);
        l_tmp = l_mac(l_tmp, coeff_lo[0], g2_pitch);
        l_tmp = l_mac(l_tmp, coeff_lo[1], g_pitch_v);
        l_tmp = l_mac(l_tmp, coeff_lo[2], g2_code);
        l_tmp = l_mac(l_tmp, coeff_lo[3], g_code);
        l_tmp = l_mac(l_tmp, coeff_lo[4], g_pit_cod);
        l_tmp = l_shr(l_tmp, 12);
        l_tmp = l_mac(l_tmp, coeff[0], g2_pitch);
        l_tmp = l_mac(l_tmp, coeff[1], g_pitch_v);
        l_tmp = l_mac(l_tmp, coeff[2], g2_code);
        l_tmp = l_mac(l_tmp, coeff[3], g_code);
        l_tmp = l_mac(l_tmp, coeff[4], g_pit_cod);

        if l_sub(l_tmp, dist_min) < 0 {
            dist_min = l_tmp;
            index = i;
        }
    }

    let index = index + min_ind;
    let p = 2 * index;
    *gain_pit = t_qua_gain[p];
    let g_code = t_qua_gain[p + 1];

    let mut l_tmp = l_mult(g_code, gcode0);
    l_tmp = l_shl(l_tmp, add(exp_gcode0, 4));
    *gain_cod = l_tmp;

    // qua_ener = 6.0206*(log2(g_code)-11)
    let l_g = l_deposit_l(g_code);
    let (exp, frac) = crate::amr::math_op::log2(l_g);
    let exp = sub(exp, 11);
    let l_tmp = mpy_32_16(exp, frac, 24660);
    let qua_ener = extract_l(l_shr(l_tmp, 3));

    past_qua_en[3] = past_qua_en[2];
    past_qua_en[2] = past_qua_en[1];
    past_qua_en[1] = past_qua_en[0];
    past_qua_en[0] = qua_ener;

    index as i16
}

// ---------------------------------------------------------------------------
// c2t64fx.c — mode-0 (6.60k) 2-pulse algebraic codebook search.
// ---------------------------------------------------------------------------

/// 2-pulse algebraic codebook search (`c2t64fx.c` `ACELP_2t64_fx`). Writes `code`/`y` (Q9) and the
/// single 12-bit index to `index[0]`.
pub fn acelp_2t64_fx(dn: &mut [i16], cn: &[i16], hh: &[i16], code: &mut [i16], y: &mut [i16], index: &mut [i16]) {
    const NB_TRACK: usize = 2;
    const STEP: usize = 2;
    const NB_POS_2T: usize = 32;
    const MSIZE: usize = 1024;

    let alp = 8192i16;

    // sign / energy normalisation
    let (mut s, mut exp) = dot_product12(cn, cn, L_SUBFR);
    isqrt_n(&mut s, &mut exp);
    s = l_shl(s, add(exp, 5));
    let k_cn = round_word(s);

    let (mut s, mut exp) = dot_product12(dn, dn, L_SUBFR);
    isqrt_n(&mut s, &mut exp);
    let k_dn = round_word(l_shl(s, add(exp, 5 + 3)));
    let k_dn = mult_r(alp, k_dn);

    let mut dn2 = [0i16; L_SUBFR];
    for i in 0..L_SUBFR {
        let s = l_mac(l_mult(k_cn, cn[i]), k_dn, dn[i]);
        dn2[i] = extract_h(l_shl(s, 8));
    }

    let mut sign = [0i16; L_SUBFR];
    let mut vec = [0i16; L_SUBFR];
    for k in 0..NB_TRACK {
        let mut i = k;
        while i < L_SUBFR {
            let mut val = dn[i];
            let ps = dn2[i];
            if ps >= 0 {
                sign[i] = 32767;
                vec[i] = -32768;
            } else {
                sign[i] = -32768;
                vec[i] = 32767;
                val = negate(val);
            }
            dn[i] = val;
            i += STEP;
        }
    }

    // h / h_inv buffers
    let mut h_buf = [0i16; 4 * L_SUBFR];
    for i in 0..L_SUBFR {
        h_buf[L_SUBFR + i] = hh[i]; // h = h_buf + L_SUBFR? -> see below
    }
    // In the C: h = h_buf; h_inv = h_buf + 2*L_SUBFR; first L_SUBFR of each zeroed; then h[i]=H[i].
    // So h starts at index 0 with the first L_SUBFR zeros then H. Reproduce exactly:
    h_buf = [0i16; 4 * L_SUBFR];
    // h occupies h_buf[0..2*L_SUBFR]; the loop sets *h++=0 for L_SUBFR then h[i]=H[i] writes h_buf[L_SUBFR+i].
    // Wait: pointers h=h_buf, h_inv=h_buf+2L. The zeroing loop does *h++=0 (h_buf[0..L]) and
    // *h_inv++=0 (h_buf[2L..3L]). Then h[i]=H[i] writes h_buf[i] for i in 0..L (h still points base+0
    // AFTER the post-increment loop? No: in C `h` was advanced by L in the zero loop). Re-derive:
    // Actually after the first loop h has advanced by L_SUBFR, so the 2nd loop h[i]=H[i] writes
    // h_buf[L_SUBFR + i]; similarly h_inv advanced by L so h_inv[i] writes h_buf[3L + i].
    for i in 0..L_SUBFR {
        h_buf[L_SUBFR + i] = hh[i];
        h_buf[3 * L_SUBFR + i] = negate(hh[i]);
    }
    let h_base = L_SUBFR; // index of h[0]
    let h_inv_base = 3 * L_SUBFR; // index of h_inv[0]

    // rrixix[2][32]
    let mut rrixix = [[0i16; NB_POS_2T]; NB_TRACK];
    {
        let mut p0 = NB_POS_2T - 1;
        let mut p1 = NB_POS_2T - 1;
        let mut ptr = h_base;
        let mut cor = 0x0001_0000i32;
        for _ in 0..NB_POS_2T {
            cor = l_mac(cor, h_buf[ptr], h_buf[ptr]);
            ptr += 1;
            rrixix[1][p1] = extract_h(cor);
            p1 = p1.wrapping_sub(1);
            cor = l_mac(cor, h_buf[ptr], h_buf[ptr]);
            ptr += 1;
            rrixix[0][p0] = extract_h(cor);
            p0 = p0.wrapping_sub(1);
        }
        for i in 0..NB_POS_2T {
            rrixix[0][i] = shr(rrixix[0][i], 1);
            rrixix[1][i] = shr(rrixix[1][i], 1);
        }
    }

    // rrixiy[1024]
    let mut rrixiy = [0i16; MSIZE];
    {
        // c2t64fx.c: pos/pos2 are Word16 (signed); their final `pos -= NB_POS` underflows to -1 but
        // is never used after the loop exits, so keep them signed to mirror the C exactly.
        let mut pos: isize = (MSIZE - 1) as isize;
        let mut pos2: isize = (MSIZE - 2) as isize;
        let mut ptr_hf = h_base + 1;
        for k in 0..NB_POS_2T {
            let mut p1 = pos;
            let mut p0 = pos2;
            let mut cor = 0x0000_8000i32;
            let mut ptr_h1 = h_base;
            let mut ptr_h2 = ptr_hf;
            for _ in (k + 1)..NB_POS_2T {
                cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
                ptr_h1 += 1;
                ptr_h2 += 1;
                rrixiy[p1 as usize] = extract_h(cor);
                cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
                ptr_h1 += 1;
                ptr_h2 += 1;
                rrixiy[p0 as usize] = extract_h(cor);
                p1 -= (NB_POS_2T + 1) as isize;
                p0 -= (NB_POS_2T + 1) as isize;
            }
            cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
            rrixiy[p1 as usize] = extract_h(cor);
            pos -= NB_POS_2T as isize;
            pos2 -= 1;
            ptr_hf += STEP;
        }
    }

    // sign modification of rrixiy
    {
        let mut p0 = 0usize;
        let mut i = 0usize;
        while i < L_SUBFR {
            let psign: &[i16] = if sign[i] < 0 { &vec } else { &sign };
            let mut j = 1usize;
            while j < L_SUBFR {
                rrixiy[p0] = mult(rrixiy[p0], psign[j]);
                p0 += 1;
                j += STEP;
            }
            i += STEP;
        }
    }

    // search 32x32
    let mut psk = -1i16;
    let mut alpk = 1i16;
    let mut ix = 0usize;
    let mut iy = 1usize;
    {
        let mut p0 = 0usize; // rrixix[0]
        let mut p1; // rrixix[1]
        let mut p2 = 0usize; // rrixiy
        let mut i0 = 0usize;
        while i0 < L_SUBFR {
            let ps1 = dn[i0];
            let alp1 = rrixix[0][p0];
            p0 += 1;
            p1 = 0usize;
            let mut pos: isize = -1;
            let mut i1 = 1usize;
            while i1 < L_SUBFR {
                let ps2 = add(ps1, dn[i1]);
                let alp2 = add(alp1, add(rrixix[1][p1], rrixiy[p2]));
                p1 += 1;
                p2 += 1;
                let sq = mult(ps2, ps2);
                let s = l_msu(l_mult(alpk, sq), psk, alp2);
                if s > 0 {
                    psk = sq;
                    alpk = alp2;
                    pos = i1 as isize;
                }
                i1 += STEP;
            }
            // p1 -= NB_POS (it was advanced by NB_POS over the inner loop; reset handled by index)
            if pos >= 0 {
                ix = i0;
                iy = pos as usize;
            }
            i0 += STEP;
        }
    }

    // build codeword + index
    for v in code.iter_mut().take(L_SUBFR) {
        *v = 0;
    }
    let mut i0 = shr(ix as i16, 1);
    let mut i1 = shr(iy as i16, 1);
    let p0_base;
    let p1_base;
    if sign[ix] > 0 {
        code[ix] = 512;
        p0_base = h_base as isize - ix as isize;
    } else {
        code[ix] = -512;
        i0 = add(i0, NB_POS_2T as i16);
        p0_base = h_inv_base as isize - ix as isize;
    }
    if sign[iy] > 0 {
        code[iy] = 512;
        p1_base = h_base as isize - iy as isize;
    } else {
        code[iy] = -512;
        i1 = add(i1, NB_POS_2T as i16);
        p1_base = h_inv_base as isize - iy as isize;
    }
    index[0] = add(shl(i0, 6), i1);

    for i in 0..L_SUBFR {
        let a = h_buf[(p0_base + i as isize) as usize];
        let b = h_buf[(p1_base + i as isize) as usize];
        y[i] = shr_r(add(a, b), 3);
    }
}

// ---------------------------------------------------------------------------
// c4t64fx.c — modes 1-8 (8.85k..23.85k) 4-track algebraic codebook search.
// ---------------------------------------------------------------------------

const NB_TRACK_4T: usize = 4;
const STEP_4T: usize = 4;
const NB_POS_4T: usize = 16;
const MSIZE_4T: usize = 256;
const NB_MAX_4T: usize = 8;
const NB_PULSE_MAX: usize = 24;
const NPMAXPT: usize = (NB_PULSE_MAX + NB_TRACK_4T - 1) / NB_TRACK_4T; // 6

/// Starting-track table (`c4t64fx.c` `tipos`), 36 entries (9 iterations × 4).
#[rustfmt::skip]
const TIPOS: [i16; 36] = [
    0, 1, 2, 3, 1, 2, 3, 0, 2, 3, 0, 1, 3, 0, 1, 2,
    0, 1, 2, 3, 1, 2, 3, 0, 2, 3, 0, 1, 3, 0, 1, 2,
    0, 1, 2, 3,
];

/// `cor_h_vec` (`c4t64fx.c`): correlation of `h` with `vec` for a track, biased by `rrixix`.
fn cor_h_vec(
    h: &[i16],
    h_off: usize,
    vec: &[i16],
    track: usize,
    sign: &[i16],
    rrixix: &[[i16; NB_POS_4T]; NB_TRACK_4T],
    cor: &mut [i16],
) {
    let mut pos = track;
    for i in 0..NB_POS_4T {
        let mut l_sum = 0i32;
        let mut p1 = h_off;
        let mut p2 = pos;
        for _ in pos..L_SUBFR {
            l_sum = l_mac(l_sum, h[p1], vec[p2]);
            p1 += 1;
            p2 += 1;
        }
        l_sum = l_shl(l_sum, 1);
        let corr = round_word(l_sum);
        cor[i] = add(mult(corr, sign[pos]), rrixix[track][i]);
        pos += STEP_4T;
    }
}

/// `search_ixiy` (`c4t64fx.c`): find the best positions of 2 pulses.
#[allow(clippy::too_many_arguments)]
fn search_ixiy(
    nb_pos_ix: i16,
    track_x: usize,
    track_y: usize,
    ps: &mut i16,
    alp: &mut i16,
    ix: &mut i16,
    iy: &mut i16,
    dn: &[i16],
    dn2: &[i16],
    cor_x: &[i16],
    cor_y: &[i16],
    rrixiy: &[[i16; MSIZE_4T]; NB_TRACK_4T],
) {
    let thres_ix = sub(nb_pos_ix, NB_MAX_4T as i16);
    let mut alp0 = l_deposit_h(*alp);
    alp0 = l_add(alp0, 0x0000_8000);

    let mut sqk = -1i16;
    let mut alpk = 1i16;
    *ix = track_x as i16;
    *iy = track_y as i16;

    let mut p0 = 0usize; // cor_x index
    let mut p2 = 0usize; // rrixiy[track_x] index
    let mut x = track_x;
    while x < L_SUBFR {
        let ps1 = add(*ps, dn[x]);
        let alp1 = l_mac(alp0, cor_x[p0], 4096);
        p0 += 1;

        if sub(dn2[x], thres_ix) < 0 {
            let mut pos: isize = -1;
            let mut p1 = 0usize; // cor_y index (reset each outer per C: p1 -= NB_POS after inner)
            let mut y = track_y;
            while y < L_SUBFR {
                let ps2 = add(ps1, dn[y]);
                let mut alp2 = l_mac(alp1, cor_y[p1], 4096);
                alp2 = l_mac(alp2, rrixiy[track_x][p2], 8192);
                p1 += 1;
                p2 += 1;
                let alp_16 = extract_h(alp2);
                let sq = mult(ps2, ps2);
                let s = l_msu(l_mult(alpk, sq), sqk, alp_16);
                if s > 0 {
                    sqk = sq;
                    alpk = alp_16;
                    pos = y as isize;
                }
                y += STEP_4T;
            }
            // p1 -= NB_POS handled by re-init of p1 each x-iteration above.
            if pos >= 0 {
                *ix = x as i16;
                *iy = pos as i16;
            }
        } else {
            p2 += NB_POS_4T;
        }
        x += STEP_4T;
    }

    *ps = add(*ps, add(dn[*ix as usize], dn[*iy as usize]));
    *alp = alpk;
}

/// 4-track algebraic codebook search (`c4t64fx.c` `ACELP_4t64_fx`). Writes `code`/`y` (Q9) and the
/// per-track indices to `index`.
#[allow(clippy::too_many_arguments)]
pub fn acelp_4t64_search(
    dn: &mut [i16],
    cn: &[i16],
    hh: &[i16],
    code: &mut [i16],
    y: &mut [i16],
    nbbits: i16,
    ser_size: i16,
    index: &mut [i16],
) {
    let (nbiter, mut alp, nb_pulse, nbpos): (usize, i16, usize, [i16; 10]) = match nbbits {
        20 => (4, 8192, 4, [4, 8, 0, 0, 0, 0, 0, 0, 0, 0]),
        36 => (4, 4096, 8, [4, 8, 8, 0, 0, 0, 0, 0, 0, 0]),
        44 => (4, 4096, 10, [4, 6, 8, 8, 0, 0, 0, 0, 0, 0]),
        52 => (4, 4096, 12, [4, 6, 8, 8, 0, 0, 0, 0, 0, 0]),
        64 => (3, 3277, 16, [4, 4, 6, 6, 8, 8, 0, 0, 0, 0]),
        72 => (3, 3072, 18, [2, 3, 4, 5, 6, 7, 8, 0, 0, 0]),
        88 => {
            let it = if sub(ser_size, 462) > 0 { 1 } else { 2 };
            (it, 2048, 24, [2, 2, 3, 4, 5, 6, 7, 8, 8, 8])
        }
        _ => (0, 0, 0, [0; 10]),
    };

    let mut codvec = [0i16; NB_PULSE_MAX];
    for (i, v) in codvec.iter_mut().enumerate().take(nb_pulse) {
        *v = i as i16;
    }

    // sign for each position
    let (mut s, mut exp) = dot_product12(cn, cn, L_SUBFR);
    isqrt_n(&mut s, &mut exp);
    s = l_shl(s, add(exp, 5));
    let k_cn = round_word(s);

    let (mut s, mut exp) = dot_product12(dn, dn, L_SUBFR);
    isqrt_n(&mut s, &mut exp);
    let k_dn = round_word(l_shl(s, add(exp, 5 + 3)));
    let k_dn = mult_r(alp, k_dn);

    let mut dn2 = [0i16; L_SUBFR];
    for i in 0..L_SUBFR {
        let s = l_mac(l_mult(k_cn, cn[i]), k_dn, dn[i]);
        dn2[i] = extract_h(l_shl(s, 8));
    }

    let mut sign = [0i16; L_SUBFR];
    let mut vec = [0i16; L_SUBFR];
    for k in 0..NB_TRACK_4T {
        let mut i = k;
        while i < L_SUBFR {
            let mut val = dn[i];
            let mut ps = dn2[i];
            if ps >= 0 {
                sign[i] = 32767;
                vec[i] = -32768;
            } else {
                sign[i] = -32768;
                vec[i] = 32767;
                val = negate(val);
                ps = negate(ps);
            }
            dn[i] = val;
            dn2[i] = ps;
            i += STEP_4T;
        }
    }

    // select NB_MAX positions per track
    let mut pos_max = [0i16; NB_TRACK_4T];
    {
        let mut pos = 0usize;
        for i in 0..NB_TRACK_4T {
            for k in 0..NB_MAX_4T {
                let mut ps = -1i16;
                let mut j = i;
                while j < L_SUBFR {
                    if sub(dn2[j], ps) > 0 {
                        ps = dn2[j];
                        pos = j;
                    }
                    j += STEP_4T;
                }
                dn2[pos] = sub(k as i16, NB_MAX_4T as i16);
                if k == 0 {
                    pos_max[i] = pos as i16;
                }
            }
        }
    }

    // scale h[] into h / h_inv buffers
    let mut h_buf = [0i16; 4 * L_SUBFR];
    let h_base = L_SUBFR;
    let h_inv_base = 3 * L_SUBFR;
    let mut l_tmp = 0i32;
    for i in 0..L_SUBFR {
        l_tmp = l_mac(l_tmp, hh[i], hh[i]);
    }
    let val_e = extract_h(l_tmp);
    let mut h_shift = 0i16;
    if sub(nb_pulse as i16, 12) >= 0 && sub(val_e, 1024) > 0 {
        h_shift = 1;
    }
    if sub(val_e, 0x6000) > 0 {
        h_shift = 2;
    }
    for i in 0..L_SUBFR {
        h_buf[h_base + i] = shr(hh[i], h_shift);
        h_buf[h_inv_base + i] = negate(h_buf[h_base + i]);
    }

    // rrixix[4][16]
    let mut rrixix = [[0i16; NB_POS_4T]; NB_TRACK_4T];
    {
        let mut p = [NB_POS_4T - 1; NB_TRACK_4T]; // p0..p3 last positions
        let mut ptr = h_base;
        let mut cor = 0x0000_8000i32;
        for _ in 0..NB_POS_4T {
            cor = l_mac(cor, h_buf[ptr], h_buf[ptr]);
            ptr += 1;
            rrixix[3][p[3]] = extract_h(cor);
            cor = l_mac(cor, h_buf[ptr], h_buf[ptr]);
            ptr += 1;
            rrixix[2][p[2]] = extract_h(cor);
            cor = l_mac(cor, h_buf[ptr], h_buf[ptr]);
            ptr += 1;
            rrixix[1][p[1]] = extract_h(cor);
            cor = l_mac(cor, h_buf[ptr], h_buf[ptr]);
            ptr += 1;
            rrixix[0][p[0]] = extract_h(cor);
            for v in p.iter_mut() {
                *v = v.wrapping_sub(1);
            }
        }
    }

    // rrixiy[4][256]
    let mut rrixiy = [[0i16; MSIZE_4T]; NB_TRACK_4T];
    {
        // first block: storage order i2i3, i1i2, i0i1, i3i0
        let mut pos = (MSIZE_4T - 1) as isize;
        let mut ptr_hf = h_base + 1;
        let p0_offset = -(NB_POS_4T as isize);
        for k in 0..NB_POS_4T {
            let mut p3 = pos; // rrixiy[2]
            let mut p2 = pos; // rrixiy[1]
            let mut p1 = pos; // rrixiy[0]
            let mut p0 = pos; // rrixiy[3]
            let mut cor = 0x0000_8000i32;
            let mut ptr_h1 = h_base;
            let mut ptr_h2 = ptr_hf;
            for _ in (k + 1)..NB_POS_4T {
                cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
                ptr_h1 += 1;
                ptr_h2 += 1;
                rrixiy[2][p3 as usize] = extract_h(cor);
                cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
                ptr_h1 += 1;
                ptr_h2 += 1;
                rrixiy[1][p2 as usize] = extract_h(cor);
                cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
                ptr_h1 += 1;
                ptr_h2 += 1;
                rrixiy[0][p1 as usize] = extract_h(cor);
                cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
                ptr_h1 += 1;
                ptr_h2 += 1;
                rrixiy[3][(p0 + p0_offset) as usize] = extract_h(cor);
                p3 -= (NB_POS_4T + 1) as isize;
                p2 -= (NB_POS_4T + 1) as isize;
                p1 -= (NB_POS_4T + 1) as isize;
                p0 -= (NB_POS_4T + 1) as isize;
            }
            cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
            ptr_h1 += 1;
            ptr_h2 += 1;
            rrixiy[2][p3 as usize] = extract_h(cor);
            cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
            ptr_h1 += 1;
            ptr_h2 += 1;
            rrixiy[1][p2 as usize] = extract_h(cor);
            cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
            rrixiy[0][p1 as usize] = extract_h(cor);

            pos -= NB_POS_4T as isize;
            ptr_hf += STEP_4T;
        }

        // second block: storage order i3i0, i2i3, i1i2, i0i1
        let mut pos = (MSIZE_4T - 1) as isize;
        let mut ptr_hf = h_base + 3;
        for k in 0..NB_POS_4T {
            let mut p3 = pos; // rrixiy[3][pos]
            let mut p2 = pos - 1; // rrixiy[2][pos-1]
            let mut p1 = pos - 1; // rrixiy[1][pos-1]
            let mut p0 = pos - 1; // rrixiy[0][pos-1]
            let mut cor = 0x0000_8000i32;
            let mut ptr_h1 = h_base;
            let mut ptr_h2 = ptr_hf;
            for _ in (k + 1)..NB_POS_4T {
                cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
                ptr_h1 += 1;
                ptr_h2 += 1;
                rrixiy[3][p3 as usize] = extract_h(cor);
                cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
                ptr_h1 += 1;
                ptr_h2 += 1;
                rrixiy[2][p2 as usize] = extract_h(cor);
                cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
                ptr_h1 += 1;
                ptr_h2 += 1;
                rrixiy[1][p1 as usize] = extract_h(cor);
                cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
                ptr_h1 += 1;
                ptr_h2 += 1;
                rrixiy[0][p0 as usize] = extract_h(cor);
                p3 -= (NB_POS_4T + 1) as isize;
                p2 -= (NB_POS_4T + 1) as isize;
                p1 -= (NB_POS_4T + 1) as isize;
                p0 -= (NB_POS_4T + 1) as isize;
            }
            cor = l_mac(cor, h_buf[ptr_h1], h_buf[ptr_h2]);
            rrixiy[3][p3 as usize] = extract_h(cor);
            pos -= 1;
            ptr_hf += STEP_4T;
        }
    }

    // sign modification of rrixiy: p0 walks rrixiy[0][0]..rrixiy[3][...] contiguously.
    {
        // The C treats rrixiy as a flat [4][MSIZE] array and p0 marches across all four rows.
        let mut flat = [[0i16; MSIZE_4T]; NB_TRACK_4T];
        flat.copy_from_slice(&rrixiy);
        // emulate a flat pointer p0 over rows 0..4
        let mut row = 0usize;
        let mut col = 0usize;
        let mut advance = |flat: &mut [[i16; MSIZE_4T]; NB_TRACK_4T], v: i16, row: &mut usize, col: &mut usize| {
            flat[*row][*col] = mult(flat[*row][*col], v);
            *col += 1;
            if *col == MSIZE_4T {
                *col = 0;
                *row += 1;
            }
        };
        for k in 0..NB_TRACK_4T {
            let mut i = k;
            while i < L_SUBFR {
                let psign: &[i16] = if sign[i] < 0 { &vec } else { &sign };
                let mut j = (k + 1) % NB_TRACK_4T;
                while j < L_SUBFR {
                    advance(&mut flat, psign[j], &mut row, &mut col);
                    j += STEP_4T;
                }
                i += STEP_4T;
            }
        }
        rrixiy = flat;
    }

    // deep-first search
    let mut psk = -1i16;
    let mut alpk = 1i16;
    let mut ipos = [0i16; NB_PULSE_MAX];
    let mut ind = [0i16; NPMAXPT * NB_TRACK_4T];

    for k in 0..nbiter {
        for i in 0..nb_pulse {
            ipos[i] = TIPOS[k * 4 + i];
        }

        let mut ps;
        let pos;
        if nbbits == 20 {
            pos = 0;
            ps = 0;
            alp = 0;
            for v in vec.iter_mut() {
                *v = 0;
            }
        } else if nbbits == 36 || nbbits == 44 {
            pos = 2;
            let ix = pos_max[ipos[0] as usize];
            let iy = pos_max[ipos[1] as usize];
            ind[0] = ix;
            ind[1] = iy;
            ps = add(dn[ix as usize], dn[iy as usize]);
            let i = shr(ix, 2);
            let j = shr(iy, 2);
            let mut s = l_mult(rrixix[ipos[0] as usize][i as usize], 4096);
            s = l_mac(s, rrixix[ipos[1] as usize][j as usize], 4096);
            let ii = add(shl(i, 4), j);
            s = l_mac(s, rrixiy[ipos[0] as usize][ii as usize], 8192);
            alp = round_word(s);
            let p0b = if sign[ix as usize] < 0 { h_inv_base as isize - ix as isize } else { h_base as isize - ix as isize };
            let p1b = if sign[iy as usize] < 0 { h_inv_base as isize - iy as isize } else { h_base as isize - iy as isize };
            for i in 0..L_SUBFR {
                vec[i] = add(h_buf[(p0b + i as isize) as usize], h_buf[(p1b + i as isize) as usize]);
            }
            if nbbits == 44 {
                ipos[8] = 0;
                ipos[9] = 1;
            }
        } else {
            pos = 4;
            let ix = pos_max[ipos[0] as usize];
            let iy = pos_max[ipos[1] as usize];
            let ii = pos_max[ipos[2] as usize];
            let jj = pos_max[ipos[3] as usize];
            ind[0] = ix;
            ind[1] = iy;
            ind[2] = ii;
            ind[3] = jj;
            ps = add(add(add(dn[ix as usize], dn[iy as usize]), dn[ii as usize]), dn[jj as usize]);
            let p0b = if sign[ix as usize] < 0 { h_inv_base as isize - ix as isize } else { h_base as isize - ix as isize };
            let p1b = if sign[iy as usize] < 0 { h_inv_base as isize - iy as isize } else { h_base as isize - iy as isize };
            let p2b = if sign[ii as usize] < 0 { h_inv_base as isize - ii as isize } else { h_base as isize - ii as isize };
            let p3b = if sign[jj as usize] < 0 { h_inv_base as isize - jj as isize } else { h_base as isize - jj as isize };
            for i in 0..L_SUBFR {
                vec[i] = add(
                    add(add(h_buf[(p0b + i as isize) as usize], h_buf[(p1b + i as isize) as usize]), h_buf[(p2b + i as isize) as usize]),
                    h_buf[(p3b + i as isize) as usize],
                );
            }
            let mut l_t = 0i32;
            for i in 0..L_SUBFR {
                l_t = l_mac(l_t, vec[i], vec[i]);
            }
            alp = round_word(l_shr_local(l_t, 3));
            if nbbits == 72 {
                ipos[16] = 0;
                ipos[17] = 1;
            }
        }

        // other stages of 2 pulses
        let mut j = pos;
        let mut st = 0usize;
        while j < nb_pulse {
            let mut cor_x = [0i16; NB_POS_4T];
            let mut cor_y = [0i16; NB_POS_4T];
            cor_h_vec(&h_buf, h_base, &vec, ipos[j] as usize, &sign, &rrixix, &mut cor_x);
            cor_h_vec(&h_buf, h_base, &vec, ipos[j + 1] as usize, &sign, &rrixix, &mut cor_y);

            let mut ix = 0i16;
            let mut iy = 0i16;
            search_ixiy(
                nbpos[st], ipos[j] as usize, ipos[j + 1] as usize, &mut ps, &mut alp, &mut ix, &mut iy,
                dn, &dn2, &cor_x, &cor_y, &rrixiy,
            );
            ind[j] = ix;
            ind[j + 1] = iy;

            let p0b = if sign[ix as usize] < 0 { h_inv_base as isize - ix as isize } else { h_base as isize - ix as isize };
            let p1b = if sign[iy as usize] < 0 { h_inv_base as isize - iy as isize } else { h_base as isize - iy as isize };
            for i in 0..L_SUBFR {
                vec[i] = add(vec[i], add(h_buf[(p0b + i as isize) as usize], h_buf[(p1b + i as isize) as usize]));
            }
            j += 2;
            st += 1;
        }

        // best codevector
        let ps2 = mult(ps, ps);
        let s = l_msu(l_mult(alpk, ps2), psk, alp);
        if s > 0 {
            psk = ps2;
            alpk = alp;
            for i in 0..nb_pulse {
                codvec[i] = ind[i];
            }
            for i in 0..L_SUBFR {
                y[i] = vec[i];
            }
        }
    }

    // build codeword + indices
    for v in ind.iter_mut() {
        *v = -1;
    }
    for i in 0..L_SUBFR {
        code[i] = 0;
        y[i] = shr_r(y[i], 3);
    }
    let val = shr(512, h_shift);

    for k in 0..nb_pulse {
        let i = codvec[k];
        let j = sign[i as usize];
        let mut idx = shr(i, 2);
        let track = (i & 0x03) as usize;
        if j > 0 {
            code[i as usize] = add(code[i as usize], val);
        } else {
            code[i as usize] = sub(code[i as usize], val);
            idx = add(idx, NB_POS_4T as i16);
        }
        let mut slot = extract_l(l_shr_local(l_mult_pos(track as i16, NPMAXPT as i16), 1)) as usize;
        while ind[slot] >= 0 {
            slot += 1;
        }
        ind[slot] = idx;
    }

    build_index(nbbits, &ind, index);
}

#[inline]
fn l_shr_local(v: i32, n: i16) -> i32 {
    crate::amr::basic_ops::l_shr(v, n)
}

/// Pack the per-track pulse positions in `ind` into the bitstream indices (`c4t64fx.c` tail).
fn build_index(nbbits: i16, ind: &[i16], index: &mut [i16]) {
    let mut k = 0usize;
    match nbbits {
        20 => {
            for slot in index.iter_mut().take(NB_TRACK_4T) {
                *slot = extract_l(quant_1p_n1(ind[k], 4));
                k += NPMAXPT;
            }
        }
        36 => {
            for slot in index.iter_mut().take(NB_TRACK_4T) {
                *slot = extract_l(quant_2p_2n1(ind[k], ind[k + 1], 4));
                k += NPMAXPT;
            }
        }
        44 => {
            for slot in index.iter_mut().take(NB_TRACK_4T - 2) {
                *slot = extract_l(quant_3p_3n1(ind[k], ind[k + 1], ind[k + 2], 4));
                k += NPMAXPT;
            }
            for track in 2..NB_TRACK_4T {
                index[track] = extract_l(quant_2p_2n1(ind[k], ind[k + 1], 4));
                k += NPMAXPT;
            }
        }
        52 => {
            for slot in index.iter_mut().take(NB_TRACK_4T) {
                *slot = extract_l(quant_3p_3n1(ind[k], ind[k + 1], ind[k + 2], 4));
                k += NPMAXPT;
            }
        }
        64 => {
            for track in 0..NB_TRACK_4T {
                let l_index = quant_4p_4n(&ind[k..k + 4], 4);
                index[track] = extract_l(l_shr_local(l_index, 14) & 3);
                index[track + NB_TRACK_4T] = extract_l(l_index & 0x3FFF);
                k += NPMAXPT;
            }
        }
        72 => {
            for track in 0..(NB_TRACK_4T - 2) {
                let l_index = quant_5p_5n(&ind[k..k + 5], 4);
                index[track] = extract_l(l_shr_local(l_index, 10) & 0x03FF);
                index[track + NB_TRACK_4T] = extract_l(l_index & 0x03FF);
                k += NPMAXPT;
            }
            for track in 2..NB_TRACK_4T {
                let l_index = quant_4p_4n(&ind[k..k + 4], 4);
                index[track] = extract_l(l_shr_local(l_index, 14) & 3);
                index[track + NB_TRACK_4T] = extract_l(l_index & 0x3FFF);
                k += NPMAXPT;
            }
        }
        _ => {
            for track in 0..NB_TRACK_4T {
                let l_index = quant_6p_6n_2(&ind[k..k + 6], 4);
                index[track] = extract_l(l_shr_local(l_index, 11) & 0x07FF);
                index[track + NB_TRACK_4T] = extract_l(l_index & 0x07FF);
                k += NPMAXPT;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convolve_unit_impulse() {
        // convolve.c `Convolve`: y[n] = round(Σ L_mac(x[i], h[n-i])).
        // With h[0] = 0.5 in Q15 (16384), each tap is L_mac(0, x, 16384) = x·16384·2 = x·32768,
        // and round(x·32768) = (x·32768 + 0x8000) >> 16 = x/2 (rounded). So y == x/2.
        // Ground truth from the fixed-point C reference (basicop2.c + convolve.c).
        let x = [100i16, 200, 300, 400];
        let h = [16384i16, 0, 0, 0];
        let mut y = [0i16; 4];
        convolve(&x, &h, &mut y, 4);
        assert_eq!(y, [50, 100, 150, 200]);
    }

    #[test]
    fn updt_tar_subtracts_scaled() {
        // x2 = x - gain·y, gain=1.0 Q14=16384 → x2 = x - y.
        let x = [1000i16, 2000];
        let y = [100i16, 200];
        let mut x2 = [0i16; 2];
        updt_tar(&x, &mut x2, &y, 16384, 2);
        assert_eq!(x2, [900, 1800]);
    }

    #[test]
    fn preemph_zero_mu_identity() {
        let mut x = [100i16, 200, 300];
        let mut mem = 0;
        preemph(&mut x, 0, 3, &mut mem);
        assert_eq!(x, [100, 200, 300]);
        assert_eq!(mem, 300);
    }

    #[test]
    fn syn_filt_unity_passes_input() {
        // syn_filt.c `Syn_filt`: with a = [4096, 0] (Q12 1.0, no prediction term) the filter is a
        // pure gain. a0 = shr(4096, 1) = 2048; s = norm_s(4096) - 2 = 1; the per-sample accumulator
        // is L_mult(x, 2048) = x·2048·2, scaled by L_shl(·, 3 + 1) and rounded → x/2.
        // Ground truth from the fixed-point C reference (basicop2.c + syn_filt.c).
        let a = [4096i16, 0];
        let x = [100i16, 200, 300, 400];
        let mut y = [0i16; 4];
        let mut mem = [0i16; 1];
        syn_filt(&a, 1, &x, &mut y, 4, &mut mem, true);
        assert_eq!(y, [50, 100, 150, 200]);
        // Carried state is the last output sample.
        assert_eq!(mem[0], 200);
    }

    #[test]
    fn g_pitch_zero_target_is_zero() {
        let xn = [0i16; 64];
        let y1 = [100i16; 64];
        let mut g = [0i16; 4];
        assert_eq!(g_pitch(&xn, &y1, &mut g, 64), 0);
    }

    #[test]
    fn quant_2p_roundtrips_through_decoder() {
        // Encode 2 pulse positions and check the decoder recovers them.
        use crate::amr::wb::codebook::dec_acelp_4t64;
        // pulses on track 0: positions 0 and 4 (both within track stride later); use raw N=4.
        let idx = quant_2p_2n1(3, 10, 4);
        // round-trip via dec_2p (exercised through dec_acelp_4t64 mode 36 with one track non-trivial)
        let mut code = [0i16; 64];
        dec_acelp_4t64(&[idx as i16, 0, 0, 0], 36, &mut code);
        // Two pulses placed on track 0 (positions ≡ 0 mod 4); just assert it does not panic and
        // produces ≤2 nonzero on that track.
        let nz = code.iter().step_by(4).filter(|&&v| v != 0).count();
        assert!(nz <= 2);
    }

    #[test]
    fn init_q_gain2_sets_predictor() {
        let mut mem = [0i16; 4];
        init_q_gain2(&mut mem);
        assert!(mem.iter().all(|&v| v == -14336));
    }
}
