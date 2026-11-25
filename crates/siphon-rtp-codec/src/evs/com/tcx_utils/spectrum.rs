//! The spectral side of `lib_com/tcx_utils.c`: the LPC envelope in the MDCT domain (`lpc2mdct`),
//! its application to a spectrum (`mdct_shaping*`, `mdct_noiseShaping_interp`), the low-frequency
//! de-emphasis and the TCX noise filling (TS 26.445 §6.2.3 and §6.2.4).

use crate::evs::basop::{mpy_32_16_1, mpy_32_16_r};
use crate::evs::cnst::FDNS_NPTS;
use crate::evs::com::basop_util::{
    basop_util_divide3216_scale, basop_util_inv_log2, basop_util_log2,
    basop_util_sqrt_inv_sqrt_mant_exp, comp_mant_exp16_unorm, idiv1616_u, inv16, isqrt16,
};
use crate::evs::com::fft::{basop_cfft, Split, BASOP_CFFT_WORK_LENGTH};
use crate::evs::com::rom_basop_util::basop_get_tables;
use crate::evs::com::tcx_utils::get_inv_frame_len;
use crate::evs::com::tools::own_random2;
use crate::evs::rom::INVINTTABLE;
use crate::itu::basic_ops::{
    add, extract_h, l_abs, l_add, l_deposit_h, l_deposit_l, l_mult, l_negate, l_shl, l_shr, l_sub,
    mult, mult_r, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0, mac_r};

/// `FDNS_NPTS` as an index bound.
const NPTS: usize = FDNS_NPTS as usize;

/// One bin of `lpc2mdct`'s amplitude spectrum: the magnitude `sqrt(re² + im²)` and its inverse as
/// mantissa/exponent pairs `(g, g_e, ig, ig_e)`.
fn lpc2mdct_bin(real: i32, imag: i32, scale: i16) -> (i16, i16, i16, i16) {
    let mut s = sub(norm_l(l_abs(real).max(l_abs(imag))), 1);

    let mut tmp16 = extract_h(l_shl(real, s));
    let tmp32 = l_mult(tmp16, tmp16);

    tmp16 = extract_h(l_shl(imag, s));
    tmp16 = mac_r(tmp32, tmp16, tmp16);

    s = shl(sub(scale, s), 1);

    if tmp16 == 0 {
        s = -16;
    }
    if tmp16 == 0 {
        tmp16 = 1;
    }

    let (mut g, mut g_e, mut ig, mut ig_e) = (0, 0, 0, 0);
    basop_util_sqrt_inv_sqrt_mant_exp(tmp16, s, &mut g, &mut g_e, &mut ig, &mut ig_e);
    (g, g_e, ig, ig_e)
}

/// The four optional outputs of `lpc2mdct`, each `FDNS_NPTS` long when present.
#[derive(Debug, Default)]
pub struct Lpc2MdctOutputs<'a> {
    /// `mdct_gains`: the LPC magnitude gains (mantissas).
    pub mdct_gains: Option<&'a mut [i16]>,
    /// `mdct_gains_exp`: their exponents.
    pub mdct_gains_exp: Option<&'a mut [i16]>,
    /// `mdct_inv_gains`: the inverse gains (mantissas).
    pub mdct_inv_gains: Option<&'a mut [i16]>,
    /// `mdct_inv_gains_exp`: their exponents.
    pub mdct_inv_gains_exp: Option<&'a mut [i16]>,
}

impl Lpc2MdctOutputs<'_> {
    fn store(&mut self, k: usize, bin: (i16, i16, i16, i16)) {
        if let Some(out) = self.mdct_gains.as_deref_mut() {
            out[k] = bin.0;
        }
        if let Some(out) = self.mdct_gains_exp.as_deref_mut() {
            out[k] = bin.1;
        }
        if let Some(out) = self.mdct_inv_gains.as_deref_mut() {
            out[k] = bin.2;
        }
        if let Some(out) = self.mdct_inv_gains_exp.as_deref_mut() {
            out[k] = bin.3;
        }
    }
}

/// `lpc2mdct`: evaluate the LPC filter `lpc_coeffs[0..=lpc_order]` on the `FDNS_NPTS`-bin ODFT
/// grid of the MDCT and return its magnitude (and inverse magnitude) per bin through `outputs`.
/// The reference asserts `lpc_order < FDNS_NPTS`.
pub fn lpc2mdct(lpc_coeffs: &[i16], lpc_order: i16, outputs: &mut Lpc2MdctOutputs<'_>) {
    let mut real_data = [0i32; NPTS];
    let mut imag_data = [0i32; NPTS];
    let mut work_buffer = [0i32; BASOP_CFFT_WORK_LENGTH];

    let size_n = shl(FDNS_NPTS, 1);

    let tables = basop_get_tables(size_n);
    let step = tables.sin_step as usize;

    // ODFT: pre-twiddle
    let mut i = 0usize;
    while i <= lpc_order as usize {
        let twiddle = tables.sin_twiddle[i * step].v;
        real_data[i] = l_mult(lpc_coeffs[i], twiddle.re);
        imag_data[i] = l_negate(l_mult(lpc_coeffs[i], twiddle.im));
        i += 1;
    }

    // zero padding
    while i < NPTS {
        real_data[i] = l_deposit_l(0);
        imag_data[i] = l_deposit_l(0);
        i += 1;
    }

    // half length FFT
    let mut scale = add(norm_s(lpc_coeffs[0]), 1);

    basop_cfft(
        &mut Split {
            re: &mut real_data,
            im: &mut imag_data,
        },
        FDNS_NPTS,
        1,
        &mut scale,
        &mut work_buffer,
    );

    // Get amplitude
    let mut j = NPTS - 1;
    let mut k = 0usize;

    for i in 0..NPTS / 2 {
        let bin = lpc2mdct_bin(real_data[i], imag_data[i], scale);
        outputs.store(k, bin);
        k += 1;

        let bin = lpc2mdct_bin(real_data[j], imag_data[j], scale);
        outputs.store(k, bin);

        j -= 1;
        k += 1;
    }
}

/// `mdct_shaping`: apply the shaping gains `gains[]` (mantissas) / `gains_exp[]` to `x[0..lg]`.
/// (The floating-point software's `mdct_noiseShaping` and `mdct_preShaping` combined.) When `lg` is
/// not a multiple of `FDNS_NPTS` the gains are spread over groups of `lg / 64` and `lg / 64 + 1`
/// lines; otherwise gain `i` applies to the interleaved lines `l + i * k`.
pub fn mdct_shaping(x: &mut [i32], lg: i16, gains: &[i16], gains_exp: &[i16]) {
    // FDNS_NPTS = 64
    let mut k = shr(lg, 6);
    let m = lg & 0x3F;

    if m != 0 {
        let (n, k1, k2);
        if sub(m, FDNS_NPTS / 2) <= 0 {
            n = idiv1616_u(FDNS_NPTS, m);
            k1 = k;
            k2 = add(k, 1);
        } else {
            n = idiv1616_u(FDNS_NPTS, sub(FDNS_NPTS, m));
            k1 = add(k, 1);
            k2 = k;
        }

        let mut i: i16 = 0;
        let mut j: i16 = 0;
        let mut x_at = 0usize;
        let mut gains_at = 0usize;

        while sub(i, lg) < 0 {
            k = k2;
            if j != 0 {
                k = k1;
            }

            j = add(j, 1);
            if sub(j, n) == 0 {
                j = 0;
            }

            // Limit number of loops, if end is reached
            k = k.min(sub(lg, i));

            for _ in 0..k {
                x[x_at] = l_shl(mpy_32_16_r(x[x_at], gains[gains_at]), gains_exp[gains_at]);
                x_at += 1;
            }
            i = add(i, k);

            gains_at += 1;
        }
    } else {
        for l in 0..k as usize {
            let mut x_at = l;
            for i in 0..NPTS {
                x[x_at] = l_shl(mpy_32_16_r(x[x_at], gains[i]), gains_exp[i]);
                x_at += k as usize;
            }
        }
    }
}

/// `mdct_shaping_16`: [`mdct_shaping`] of the 16-bit spectrum `x[0..lg]` (`lg` a multiple of
/// `FDNS_NPTS`, asserted by the reference) into the 32-bit `y`, with the exponents taken relative
/// to `gains_max_exp`; the lines `lg..lg_total` use the last gain.
pub fn mdct_shaping_16(
    x: &[i16],
    lg: i16,
    lg_total: i16,
    gains: &[i16],
    gains_exp: &[i16],
    gains_max_exp: i16,
    y: &mut [i32],
) {
    let mut gains_exp_loc = [0i16; NPTS];

    // FDNS_NPTS = 64
    let k = shr(lg, 6) as usize;

    for i in 0..NPTS {
        gains_exp_loc[i] = sub(gains_exp[i], gains_max_exp);
    }
    for l in 0..k {
        let mut at = l;
        for i in 0..NPTS {
            y[at] = l_shl(l_mult(x[at], gains[i]), gains_exp_loc[i]);
            at += k;
        }
    }

    let gain_exp = sub(gains_exp[NPTS - 1], gains_max_exp);
    for i in lg..lg_total {
        y[i as usize] = l_shl(l_mult(x[i as usize], gains[NPTS - 1]), gain_exp);
    }
}

/// The interpolated gain `mac_r(L_mult(a, wa), b, wb)` of two neighbouring envelope gains brought
/// to their common exponent `e` (the larger of the two).
fn interp_gain(a: i16, a_exp: i16, b: i16, b_exp: i16, weight_a: i16, weight_b: i16) -> (i16, i16) {
    let (mut a, mut b) = (a, b);
    // the gain with the smaller exponent is shifted right to the larger one
    let tmp = sub(a_exp, b_exp);
    if tmp > 0 {
        b = shr(b, tmp);
    }
    if tmp < 0 {
        a = shl(a, tmp);
    }
    let e = b_exp.max(a_exp);
    (mac_r(l_mult(a, weight_a), b, weight_b), e)
}

/// `mdct_noiseShaping_interp`: apply the `FDNS_NPTS` envelope gains to `x[0..lg]` (`lg` a multiple
/// of 64), linearly interpolated between neighbouring gains for 4 or 5 lines per gain and stepped
/// for any other group size. Without `gains` the spectrum is left alone.
pub fn mdct_noise_shaping_interp(x: &mut [i32], lg: i16, gains: Option<&[i16]>, gains_exp: &[i16]) {
    let Some(gains) = gains else {
        return;
    };
    // The reference asserts lg % FDNS_NPTS == 0
    let k = shr(lg, 6);

    // Linear interpolation
    if sub(k, 4) == 0 {
        let mut jp = 0usize;
        let mut j = 0usize;
        let mut jn = 1usize;

        let mut i = 0usize;
        while i < lg as usize {
            // pg and g at their common exponent
            let (tmp, e) = interp_gain(
                gains[jp],
                gains_exp[jp],
                gains[j],
                gains_exp[j],
                12288, /* 0.375f Q15 */
                20480, /* 0.625f Q15 */
            );
            x[i] = l_shl(mpy_32_16_1(x[i], tmp), e);

            let (tmp, e) = interp_gain(
                gains[jp],
                gains_exp[jp],
                gains[j],
                gains_exp[j],
                4096,  /* 0.125f Q15 */
                28672, /* 0.875f Q15 */
            );
            x[i + 1] = l_shl(mpy_32_16_1(x[i + 1], tmp), e);

            // g and ng at their common exponent
            let (tmp, e) = interp_gain(
                gains[j],
                gains_exp[j],
                gains[jn],
                gains_exp[jn],
                28672, /* 0.875f Q15 */
                4096,  /* 0.125f Q15 */
            );
            x[i + 2] = l_shl(mpy_32_16_1(x[i + 2], tmp), e);

            let (tmp, e) = interp_gain(
                gains[j],
                gains_exp[j],
                gains[jn],
                gains_exp[jn],
                20480, /* 0.625f Q15 */
                12288, /* 0.375f Q15 */
            );
            x[i + 3] = l_shl(mpy_32_16_1(x[i + 3], tmp), e);

            jp = j;
            j = jn;
            jn = (jn + 1).min(NPTS - 1);
            i += 4;
        }
    } else if sub(k, 5) == 0 {
        let mut jp = 0usize;
        let mut j = 0usize;
        let mut jn = 1usize;

        let mut i = 0usize;
        while i < lg as usize {
            let (tmp, e) = interp_gain(
                gains[jp],
                gains_exp[jp],
                gains[j],
                gains_exp[j],
                13107, /* 0.40f Q15 */
                19661, /* 0.60f Q15 */
            );
            x[i] = l_shl(mpy_32_16_1(x[i], tmp), e);

            let (tmp, e) = interp_gain(
                gains[jp],
                gains_exp[jp],
                gains[j],
                gains_exp[j],
                6554,  /* 0.20f Q15 */
                26214, /* 0.80f Q15 */
            );
            x[i + 1] = l_shl(mpy_32_16_1(x[i + 1], tmp), e);

            x[i + 2] = l_shl(mpy_32_16_1(x[i + 2], gains[j]), gains_exp[j]);

            let (tmp, e) = interp_gain(
                gains[j],
                gains_exp[j],
                gains[jn],
                gains_exp[jn],
                26214, /* 0.80f Q15 */
                6554,  /* 0.20f Q15 */
            );
            x[i + 3] = l_shl(mpy_32_16_1(x[i + 3], tmp), e);

            let (tmp, e) = interp_gain(
                gains[j],
                gains_exp[j],
                gains[jn],
                gains_exp[jn],
                19661, /* 0.60f Q15 */
                13107, /* 0.40f Q15 */
            );
            x[i + 4] = l_shl(mpy_32_16_1(x[i + 4], tmp), e);

            jp = j;
            j = jn;
            jn = (jn + 1).min(NPTS - 1);
            i += 5;
        }
    } else {
        // no interpolation
        let mut x_at = 0usize;
        for i in 0..NPTS {
            for _ in 0..k {
                x[x_at] = l_shl(mpy_32_16_1(x[x_at], gains[i]), gains_exp[i]);
                x_at += 1;
            }
        }
    }
}

/// `PsychAdaptLowFreqDeemph`: lower the 32 lowest lines (and, when given, their de-emphasis
/// factors) gradually by `(max / min)^(1/128)` per line when the LPC gains of the low band differ
/// by less than a factor 32. The reference asserts `lpcGains[0] >= 0x4000`.
pub fn psych_adapt_low_freq_deemph(
    x: &mut [i32],
    lpc_gains: &[i16],
    lpc_gains_e: &[i16],
    mut lf_deemph_factors: Option<&mut [i16]>,
) {
    let mut max = lpc_gains[0];
    let mut max_e = lpc_gains_e[0];
    let mut min = lpc_gains[0];
    let mut min_e = lpc_gains_e[0];

    // find minimum (min) and maximum (max) of LPC gains in low frequencies
    for i in 1..9 {
        if comp_mant_exp16_unorm(lpc_gains[i], lpc_gains_e[i], min, min_e) < 0 {
            min = lpc_gains[i];
            min_e = lpc_gains_e[i];
        }

        if comp_mant_exp16_unorm(lpc_gains[i], lpc_gains_e[i], max, max_e) > 0 {
            max = lpc_gains[i];
            max_e = lpc_gains_e[i];
        }
    }

    min_e = add(min_e, 5); // min *= 32.0f;

    if comp_mant_exp16_unorm(max, max_e, min, min_e) < 0 && min > 0 {
        // fac = tmp = (float)pow(max / min, 0.0078125f);
        let mut tmp_e = min_e;
        let mut tmp = inv16(min, &mut tmp_e);
        let mut l_tmp = l_shl(l_mult(tmp, max), add(tmp_e, max_e)); // Q31
        l_tmp = basop_util_log2(l_tmp); // Q25
        l_tmp = l_shr(l_tmp, 7); // 0.0078125f = 1.f/(1<<7)
        l_tmp = basop_util_inv_log2(l_tmp); // Q31
        tmp = round_word(l_tmp); // Q15
        let mut fac = tmp; // Q15

        // gradual lowering of lowest 32 bins; DC is lowered by (max/tmp)^1/4
        for i in (0..32).rev() {
            x[i] = mpy_32_16_1(x[i], fac);
            if let Some(factors) = lf_deemph_factors.as_deref_mut() {
                factors[i] = mult_r(factors[i], fac);
            }
            fac = mult_r(fac, tmp);
        }
    }
}

/// One of the two "always expand two lines" steps of `AdaptLowFreqDeemph` (step 5): shrink the
/// line `x[i]` (and its de-emphasis factor) by half when it lies within `±4.0` of zero, else pull
/// it towards zero by `2.0`.
fn adapt_low_freq_deemph_expand_line(x: &mut [i32], i: usize, v2: i32, v4: i32, lf: &mut [i16]) {
    if x[i] < 0 {
        let tmp32 = l_sub(x[i], l_negate(v4));

        if tmp32 > 0 {
            lf[i] = shr(lf[i], 1);
        }
        if tmp32 <= 0 {
            x[i] = l_add(x[i], v2);
        }
        if tmp32 > 0 {
            x[i] = l_shr(x[i], 1);
        }
    } else {
        let tmp32 = l_sub(x[i], v4);

        if tmp32 < 0 {
            lf[i] = shr(lf[i], 1);
        }
        if tmp32 >= 0 {
            x[i] = l_sub(x[i], v2);
        }
        if tmp32 < 0 {
            x[i] = l_shr(x[i], 1);
        }
    }
}

/// `AdaptLowFreqDeemph`: expand the value range of the lowest lines of `x` (Q`x_e`) before the
/// arithmetic coder when the spectrum is not LPC-shaped, recording the expansion in
/// `lf_deemph_factors`; with `tcx_lpc_shaped_ari` set it defers to
/// [`psych_adapt_low_freq_deemph`]. The reference dereferences the factors in the first case, so
/// callers pass them whenever `tcx_lpc_shaped_ari == 0`.
// the line indices are the reference's, shared by the spectrum and the factors
#[allow(clippy::needless_range_loop)]
pub fn adapt_low_freq_deemph(
    x: &mut [i32],
    x_e: i16,
    tcx_lpc_shaped_ari: i16,
    lpc_gains: &[i16],
    lpc_gains_e: &[i16],
    lg: i16,
    lf_deemph_factors: Option<&mut [i16]>,
) {
    if tcx_lpc_shaped_ari != 0 {
        psych_adapt_low_freq_deemph(x, lpc_gains, lpc_gains_e, lf_deemph_factors);
        return;
    }
    let Some(lf) = lf_deemph_factors else {
        // NULL here is a crash in the reference; no decoder call passes it
        return;
    };

    let v2 = l_shl(2, sub(31, x_e)); // 2.0
    let v4 = l_shl(v2, 1); // 4.0
    let lg_4 = shr(lg, 2); // lg/4
    let mut tmp32: i32 = 0;

    // 1. find first magnitude maximum in lower quarter of spectrum
    let mut i_max: i16 = -1;

    for i in 0..lg_4 as usize {
        if l_sub(l_abs(x[i]), v4) >= 0 {
            tmp32 = 0;

            if x[i] < 0 {
                tmp32 = l_add(x[i], v2);
            }
            if x[i] > 0 {
                tmp32 = l_sub(x[i], v2);
            }

            x[i] = tmp32;
            i_max = i as i16;
            break;
        }
    }

    // 2. expand value range of all xi up to i_max: two extra steps
    for i in 0..i_max.max(0) as usize {
        x[i] = l_shr(x[i], 1);
        lf[i] = shr(lf[i], 1);
    }

    // 3. find first magnitude maximum in lower quarter of spectrum
    let i_max_old = i_max;

    if i_max_old >= 0 {
        i_max = -1;

        for i in 0..lg_4 as usize {
            if l_sub(l_abs(x[i]), v4) >= 0 {
                if x[i] < 0 {
                    tmp32 = l_add(x[i], v2);
                }
                if x[i] >= 0 {
                    tmp32 = l_sub(x[i], v2);
                }
                x[i] = tmp32;
                i_max = i as i16;
                break;
            }
        }
    }

    // 4. expand value range of all xi up to i_max: two extra steps
    for i in 0..i_max.max(0) as usize {
        x[i] = l_shr(x[i], 1);
        lf[i] = shr(lf[i], 1);
    }

    // 5. always expand two lines; lines could be at index 0 and 1!
    i_max = i_max.max(i_max_old);
    let i = add(i_max, 1) as usize;
    adapt_low_freq_deemph_expand_line(x, i, v2, v4, lf);
    adapt_low_freq_deemph_expand_line(x, i + 1, v2, v4, lf);
}

/// `tcx_noise_filling`: fill the zeroed lines of `q` between `i_first_line` and `lowpass_line`
/// with random noise of level `fac_ns` (tilted by `tilt_comp_factor` towards high frequencies),
/// fade-in/-out over `n_trans_width` lines at the borders of the filled segments, and
/// RMS-normalise every segment. The filled lines are flagged in `info_tcx_noise` (for IGF).
pub fn tcx_noise_filling(
    q: &mut [i32],
    q_e: i16,
    seed: i16,
    i_first_line: i16,
    lowpass_line: i16,
    n_trans_width: i16,
    l_frame: i16,
    tilt_comp_factor: i16,
    fac_ns: i16,
    mut info_tcx_noise: Option<&mut [i16]>,
) {
    let (mut seed, mut fac_ns) = (seed, fac_ns);

    // get inverse frame length
    let mut tmp1 = get_inv_frame_len(l_frame);

    // tilt_factor = (float)pow(max(0.375f, tiltCompFactor), 1.0f/(float)L_frame);
    let mut tmp32 = basop_util_log2(l_deposit_h(0x3000.max(tilt_comp_factor))); // 6Q25
    tmp32 = l_shr(mpy_32_16_1(tmp32, tmp1), 6);
    let tilt_factor = round_word(basop_util_inv_log2(tmp32));

    // find last nonzero line below iFirstLine, use it as start offset
    tmp1 = shr(i_first_line, 1);
    let mut i = i_first_line;
    while i > tmp1 {
        if q[i as usize] != 0 {
            break;
        }
        i -= 1;
    }
    // fac_ns *= (float)pow(tilt_factor, (float)i);
    for _ in 0..i.max(0) {
        fac_ns = mult_r(fac_ns, tilt_factor);
    }

    let mut nrg = l_deposit_l(1);
    let mut win: i16 = 0;
    i = add(i, 1);
    let mut segment_offset = i;
    let mut s: i16 = 0;

    while i < lowpass_line {
        fac_ns = mult_r(fac_ns, tilt_factor);

        if q[i as usize] != 0 {
            if win > 0 {
                // RMS-normalize current noise-filled segment
                tmp1 = basop_util_divide3216_scale(nrg, sub(i, segment_offset), &mut s); // mean
                s = add(s, 9 - 15); // scaling
                tmp1 = isqrt16(tmp1, &mut s); // 1/RMS
                tmp1 = mult_r(tmp1, INVINTTABLE[n_trans_width as usize]); // compensate win
                s = add(s, sub(16, q_e)); // scaling

                let tmp2 = sub(i, win);
                if sub(segment_offset, tmp2) < 0 {
                    for m in segment_offset..tmp2 {
                        q[m as usize] = l_shl(mpy_32_16_1(q[m as usize], tmp1), s);
                    }
                }

                let tmp2 = mult(tmp1, INVINTTABLE[n_trans_width as usize]);
                tmp1 = l_mult0(tmp2, win) as i16;
                for m in sub(i, win)..i {
                    q[m as usize] = l_shl(mpy_32_16_1(q[m as usize], tmp1), s);
                    win = sub(win, 1);
                    tmp1 = sub(tmp1, tmp2);
                }

                nrg = l_deposit_l(1); // start new segment: reset noise segment energy
            }
            segment_offset = add(i, 1);
        } else {
            // line is zero, so fill line and update window and energy
            if sub(win, n_trans_width) < 0 {
                win = add(win, 1);
            }

            seed = own_random2(seed);
            q[i as usize] = l_mult0(mult(seed, fac_ns), win);

            tmp1 = shr(seed, 4);
            nrg = l_mac0(nrg, tmp1, tmp1); // sum up energy of current noise segment

            if let Some(info) = info_tcx_noise.as_deref_mut() {
                // set noiseflags for IGF
                info[i as usize] = 1;
            }
        }
        i += 1;
    }

    if win > 0 {
        // RMS-normalize uppermost noise-filled segment
        tmp1 = basop_util_divide3216_scale(nrg, sub(lowpass_line, segment_offset), &mut s); // mean
        s = add(s, 9 - 15); // compensate energy scaling
        tmp1 = isqrt16(tmp1, &mut s); // 1/RMS
        tmp1 = mult_r(tmp1, INVINTTABLE[n_trans_width as usize]); // compensate win
        s = add(s, sub(16, q_e)); // compensate noise scaling

        for m in segment_offset..lowpass_line {
            q[m as usize] = l_shl(mpy_32_16_1(q[m as usize], tmp1), s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_gains_leave_the_spectrum_alone() {
        let mut x: Vec<i32> = (0..256).map(|i| (i - 128) * 1000).collect();
        let before = x.clone();
        let gains = [0x4000i16; NPTS];
        let exps = [1i16; NPTS];
        mdct_noise_shaping_interp(&mut x, 256, Some(&gains), &exps);
        // 0.5 in Q15 times 2^1: the gain of one, to the precision of the 32 by 16 product
        for (a, b) in x.iter().zip(&before) {
            assert!((a - b).abs() <= 2);
        }
    }

    #[test]
    fn noise_filling_fills_only_the_zero_lines_below_the_lowpass_line() {
        let mut q = vec![0i32; 256];
        q[10] = 1 << 20;
        tcx_noise_filling(&mut q, 4, 1234, 32, 128, 8, 256, 18432, 20000, None);
        assert_eq!(q[10], 1 << 20);
        assert!(q[128..].iter().all(|&v| v == 0));
        assert!(q[33..128].iter().any(|&v| v != 0));
    }
}
