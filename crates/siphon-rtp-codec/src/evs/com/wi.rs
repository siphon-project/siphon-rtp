//! Waveform interpolation over discrete-time Fourier series prototypes (TS 26.442
//! `lib_com/wi_fx.c`; TS 26.445 §6.1.1.3.4 / §7.11.1.2).
//!
//! Only what the MODE1 decoder reaches is ported: the FEC fast-recovery interpolation of
//! `decod_gen_voic_fx` (`DTFS_to_fs_fx`, `GetSinCosTab_fx`, `WIsyn_fx` and everything under it,
//! both of `WIsyn_fx`'s alignment branches included). The PPP / NELP coders' quantisers that live
//! in the same file are not ported.
//!
//! The reference allocates its `DTFS_STRUCTURE_FX`s with `calloc`; here they are plain values on
//! the stack ([`DtfsStructure`]), copied wherever the C passes one by value. The `S_fx` / `C_fx`
//! tables are indexed `(·) % (4·lag)`; `at` reads them, returning 0 for an index the reference
//! would take out of bounds (a lag of 0, which no caller passes).

use crate::evs::basop::{l_extract_lc, mult_32_16, mult_32_32};
use crate::evs::cnst::{INT_FS_FX, L_FRAME, M, MAXLAG_WI, MIN_32, WI_FX_PHASE_FX};
use crate::evs::com::math_op::{i_mult2, isqrt_lc, pow2};
use crate::evs::com::tools::{find_rem, rint_new};
use crate::evs::rom::{COS_DIFF_TABLE, COS_TABLE, INVERSE_TABLE, PWF_FX, SINC_FX};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_msu,
    l_mult, l_negate, l_shl, l_shr, l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl,
    shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_msu0, l_mult0, shl_r};

mod fft;
mod ppp;

pub use fft::r_fft_4;
pub use ppp::{
    copy_phase, dtfs_car2pol, dtfs_dequant_cw, dtfs_erb_inv, dtfs_set_engy_harm, dtfs_to_erb,
    erb_add, erb_slot, q2phase_shift, rshift_harm_band,
};

/// `LL`: the length of the oversampled prototype `DTFS_transform_fx` interpolates in.
const LL: i32 = 256;
/// `OSLENGTH`: the taps of the `sinc_fx` interpolator.
const OSLENGTH: i32 = 12;
/// `WI_SAMPLE_THLD`: below this many samples of slack the interpolation weight is linear.
const WI_SAMPLE_THLD: i16 = 20;

const LAG_MAX: usize = MAXLAG_WI as usize;

/// `DTFS_STRUCTURE_FX`: a pitch prototype as a discrete-time Fourier series, the harmonics'
/// cosine (`a`) and sine (`b`) amplitudes in Q`q` over one pitch period of `lag` samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DtfsStructure {
    /// `a_fx`: cosine amplitudes, Q`q`.
    pub a: [i16; LAG_MAX],
    /// `b_fx`: sine amplitudes, Q`q`.
    pub b: [i16; LAG_MAX],
    /// `lag_fx`: the pitch period in samples.
    pub lag: i16,
    /// `nH_fx`: the harmonics below `upper_cut_off_freq`.
    pub nh: i16,
    /// `nH_4kHz_fx`: the harmonics below 4 kHz.
    pub nh_4khz: i16,
    /// `upper_cut_off_freq_of_interest_fx`.
    pub upper_cut_off_freq_of_interest: i16,
    /// `upper_cut_off_freq_fx`.
    pub upper_cut_off_freq: i16,
    /// `Fs_fx`: the sampling rate.
    pub fs: i16,
    /// `Q`: the Q of `a` and `b`.
    pub q: i16,
}

/// `DTFS_new_fx`: an empty prototype (the reference's `calloc` plus its initialisation).
#[must_use]
pub fn dtfs_new() -> DtfsStructure {
    DtfsStructure {
        a: [0; LAG_MAX],
        b: [0; LAG_MAX],
        lag: 0,
        nh: 0,
        nh_4khz: 0,
        upper_cut_off_freq_of_interest: 3300,
        upper_cut_off_freq: 4000,
        fs: 0,
        q: 0,
    }
}

/// `DTFS_copy_fx`: copy every field of `xinp` into `xout` except `Fs_fx`, which the reference
/// leaves as it was.
pub fn dtfs_copy(xout: &mut DtfsStructure, xinp: &DtfsStructure) {
    xout.a = xinp.a;
    xout.b = xinp.b;
    xout.lag = xinp.lag;
    xout.nh = xinp.nh;
    xout.nh_4khz = xinp.nh_4khz;
    xout.upper_cut_off_freq_of_interest = xinp.upper_cut_off_freq_of_interest;
    xout.upper_cut_off_freq = xinp.upper_cut_off_freq;
    xout.q = xinp.q;
}

/// `table[value % modulus]` as the reference reads its `S_fx` / `C_fx` tables; 0 where that
/// index would be out of bounds or the modulus 0 (never on the decoder's paths).
#[inline]
fn at(table: &[i16], value: i32, modulus: i32) -> i16 {
    if modulus == 0 {
        return 0;
    }
    usize::try_from(value % modulus)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or(0)
}

/// `table[index]` for the fixed ROM tables, 0 out of bounds.
#[inline]
fn rom<T: Copy + Default>(table: &[T], index: i32) -> T {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or_default()
}

/// `min(lag / 2, nH)`, the highest harmonic most loops visit, clamped to the arrays.
#[inline]
fn half_lag(lag: i16, nh: i16) -> usize {
    (shr(lag, 1).min(nh).max(-1) + 1).min(MAXLAG_WI) as usize
}

/// `DTFS_fast_fs_inv_fx`: the time-domain waveform (`n_fx` samples, `n_fx = 2^log2n`) of the
/// prototype, by an inverse real FFT.
pub fn dtfs_fast_fs_inv(x_fx: &DtfsStructure, out_fx: &mut [i16], n_fx: i16, log2n: i16) {
    let mut dbuf_fx = [0_i16; 256 + 1];
    let m_2 = shr(x_fx.lag, 1).min(x_fx.nh);
    let n_2 = shr(n_fx, 1);
    let s = negate(x_fx.q);

    dbuf_fx[0] = x_fx.a[0];
    dbuf_fx[1] = 0;
    let mut i: i16 = 1;
    while i <= m_2 && (i as usize) < LAG_MAX && 2 * (i as usize) + 1 < dbuf_fx.len() {
        dbuf_fx[2 * i as usize] = shl_r(x_fx.a[i as usize], s);
        dbuf_fx[2 * i as usize + 1] = shl_r(x_fx.b[i as usize], s);
        i += 1;
    }
    while i < n_2 && 2 * (i as usize) + 1 < dbuf_fx.len() {
        dbuf_fx[2 * i as usize] = 0;
        dbuf_fx[2 * i as usize + 1] = 0;
        i += 1;
    }

    // do IFFT
    r_fft_4(&mut dbuf_fx, n_fx, sub(log2n, 1), -1);

    let n = (n_fx.max(0) as usize).min(256);
    out_fx[..n].copy_from_slice(&dbuf_fx[..n]);
}

/// `DTFS_alignment_weight_fx`: the shift (Q7) of the prototype `X2` that best aligns it with
/// `X_fx` in the perceptually weighted domain, searched around the expected shift `Eshift`.
pub fn dtfs_alignment_weight(
    x_fx: &DtfsStructure,
    mut x2: DtfsStructure,
    eshift: i16,
    lpc1: &[i16],
    lpc2: &[i16],
    s_fx: &[i16],
    c_fx: &[i16],
    pf_temp1: &mut [i16],
    pf_temp2: &mut [i16],
    pf_temp: &mut [i16],
    pf_n2: &mut [i16],
) -> i16 {
    // Eshift is w.r.t  X2
    let mut ab1 = [0_i16; LAG_MAX];
    let mut ab2 = [0_i16; LAG_MAX];
    let mut tmplpc_fx = [0_i16; M as usize + 1];
    let mut diff_fx: i16 = 0; // to avoid compilation warnings

    let mut x1 = *x_fx;
    dtfs_adjust_lag(&mut x1, x2.lag);

    // PORTING: Handling the functions with variable no. of arguments
    pole_filter_setup(
        lpc1,
        add(M, 1),
        &x1,
        s_fx,
        c_fx,
        pf_temp1,
        pf_temp2,
        pf_temp,
        pf_n2,
    );
    dtfs_pole_filter_9(&mut x1, pf_temp1, pf_temp2, pf_temp, pf_n2);
    for k in 0..=M as usize {
        tmplpc_fx[k] = mult_r(lpc1[k], PWF_FX[k]); // Q12
    }
    dtfs_zero_filter(&mut x1, &tmplpc_fx, M + 1, s_fx, c_fx);

    pole_filter_setup(
        lpc2,
        add(M, 1),
        &x2,
        s_fx,
        c_fx,
        pf_temp1,
        pf_temp2,
        pf_temp,
        pf_n2,
    );
    dtfs_pole_filter_9(&mut x2, pf_temp1, pf_temp2, pf_temp, pf_n2);
    for k in 0..=M as usize {
        tmplpc_fx[k] = mult_r(lpc2[k], PWF_FX[k]); // Q12
    }
    dtfs_zero_filter(&mut x2, &tmplpc_fx, M + 1, s_fx, c_fx);

    let mut maxcorr_fx = MIN_32;
    let mut qmaxcorr: i16 = 0;
    let mut fshift_fx = eshift;
    // Q7, 768=6*128, 4915 = 0.15*32768
    let adiff_fx = 768_i16.max(mult_r(4915, shl(x2.lag, 7)));

    if sub(x2.lag, 60) < 0 {
        diff_fx = 32; // Q7 of 0.25
    }
    if sub(x2.lag, 60) >= 0 {
        diff_fx = 64; // Q7 of 0.5
    }

    let half = half_lag(x2.lag, x2.nh_4khz);
    let exp = norm_s(x2.lag);
    let tmp = div_s(shl(1, sub(14, exp)), x2.lag);
    let l_tmp = l_shl(i32::from(tmp), exp.wrapping_add(6));
    let inv_lag = round_word(l_tmp);

    for k in 0..half {
        ab1[k] = round_word(l_mac0(l_mult0(x1.a[k], x2.a[k]), x1.b[k], x2.b[k])); // Q(-15)
        ab2[k] = round_word(l_msu0(l_mult0(x1.a[k], x2.b[k]), x1.b[k], x2.a[k]));
        // Q(-15)
    }

    let start = sub(eshift, adiff_fx);
    let end = add(eshift, adiff_fx);

    let mut n_fx = start;
    while n_fx <= end {
        // Q7
        let mut corr_fx: i32 = 0;
        let mut temp: i16 = 0;
        let mut temp1 = round_word(l_shr(l_mult(inv_lag, n_fx), 2)); // Q(19+7+1-2-16)=Q9 of n/X2.lag
        if temp1 < 0 {
            temp1 = add(temp1, 0x200); // avoid negative, 0x200 is Q9 of 1 ( 2*pi )
        }
        for k in 0..half {
            corr_fx = l_mac0(corr_fx, ab1[k], COS_TABLE[(temp & 511) as usize]);
            corr_fx = l_mac0(
                corr_fx,
                ab2[k],
                COS_TABLE[((i32::from(temp) + 128) & 511) as usize],
            );
            temp = add(temp, temp1);
        }
        let temp = sub(8192, mult_r(20972, abs_s(sub(n_fx, eshift)))); // Q13, 20972 = Q21 of 0.01.
        let mut qcorr = norm_l(corr_fx);
        if corr_fx == 0 {
            qcorr = 31;
        }
        let temp1 = round_word(l_shl(corr_fx, qcorr)); // Q(Qcorr-16)
        let wcorr_fx = l_mult(temp1, shl(temp, 2)); // Q(Qcorr-16+13+2+1)=Q(Qcorr)

        let diff_corr = if sub(qmaxcorr, qcorr) >= 0 {
            l_sub(wcorr_fx, l_shl(maxcorr_fx, sub(qcorr, qmaxcorr))) // Qcorr
        } else {
            l_sub(l_shl(wcorr_fx, sub(qmaxcorr, qcorr)), maxcorr_fx) // Qmaxcorr
        };
        if diff_corr > 0 {
            fshift_fx = n_fx;
            maxcorr_fx = wcorr_fx;
            qmaxcorr = qcorr;
        }
        n_fx = n_fx.wrapping_add(diff_fx);
        if diff_fx <= 0 {
            break;
        }
    }
    fshift_fx
}

/// `DTFS_alignment_full_fx`: the shift (Q1) of `X2` that best aligns it with `X1`, over the whole
/// period in the FR context (`FR_flag`) or around the expected shift otherwise.
pub fn dtfs_alignment_full(
    mut x1_dtfs_fx: DtfsStructure,
    x2_dtfs_fx: DtfsStructure,
    ph_offset_fx: i16,
    s_fx: &[i16],
    c_fx: &[i16],
    fr_flag: i16,
) -> i16 {
    let mut ab1 = [0_i16; LAG_MAX];
    let mut ab2 = [0_i16; LAG_MAX];
    let mut temp: i16 = 0;
    let mut eshift: i16 = 0;

    // Calculating the expected alignment shift
    let eshift0 = mult_r(ph_offset_fx, shl(x2_dtfs_fx.lag, 7)); // confirmed I<2 by smv12.org, Q7
    find_rem(
        L_FRAME,
        shr(add(x2_dtfs_fx.lag, x1_dtfs_fx.lag), 1),
        &mut temp,
    );
    temp = add(shl(temp, 7), eshift0); // Q7
    if temp < 0 {
        temp = add(temp, shl(x1_dtfs_fx.lag, 7)); // Q7
    }
    find_rem(temp, shl(x1_dtfs_fx.lag, 7), &mut eshift); // Q7
    eshift = shl(shr(eshift, 7), 1); // Q1 but integer

    let adiff_fx = if sub(x2_dtfs_fx.lag, 60) > 0 {
        shl(x2_dtfs_fx.lag, 1 - 3) // lag_fx/8 in Q1
    } else {
        shl(x2_dtfs_fx.lag, 1 - 2) // lag_fx/4 in Q1
    };

    if x1_dtfs_fx.lag < x2_dtfs_fx.lag {
        dtfs_zero_padd(x2_dtfs_fx.lag, &mut x1_dtfs_fx);
    }

    let mut maxcorr_fx = MIN_32;
    let half = half_lag(x2_dtfs_fx.lag, x2_dtfs_fx.nh_4khz);

    for k in 0..half {
        let x1 = &x1_dtfs_fx;
        let x2 = &x2_dtfs_fx;
        ab1[k] = round_word(l_mac(l_mult(x1.a[k], x2.a[k]), x1.b[k], x2.b[k])); // Q(-15)
        ab2[k] = round_word(l_msu(l_mult(x1.b[k], x2.a[k]), x1.a[k], x2.b[k])); // Q(-15)
    }
    let (start, end) = if fr_flag == 0 {
        (sub(eshift, adiff_fx), add(eshift, adiff_fx)) // Q1
    } else {
        // in FR mode, we cannot save and carry forward ph_offset as in VBR mode encoder
        // "ph_offset_E_fx", so we set ph_offset_fx = 0, as a result we cannot accurately
        // estimate the expected alignment shift Eshift to limit the search, so we search the
        // full range [0 to X2_DTFS_fx.lag_fx] similar to FL
        (0, shl(x2_dtfs_fx.lag, 1)) // Q1
    };

    let mut fshift_fx = start; // Q1
    let modulus = 4 * i32::from(x2_dtfs_fx.lag);
    let mut n = start;
    while n <= end {
        // n in Q1
        let mut corr_fx: i32 = 0;
        let mut temp: i16 = 0;
        let temp1 = add(n, shl(x2_dtfs_fx.lag, 1)); // add lag_fx in Q1 to make positive
        for k in 0..half {
            let index = 2 * i32::from(temp);
            corr_fx = l_mac(corr_fx, ab1[k], at(c_fx, index, modulus));
            corr_fx = l_mac(corr_fx, ab2[k], at(s_fx, index, modulus));
            temp = add(temp, temp1);
        }
        if l_sub(corr_fx, maxcorr_fx) > 0 {
            fshift_fx = n; // Q1
            maxcorr_fx = corr_fx;
        }
        if n == i16::MAX {
            break;
        }
        n += 1;
    }
    fshift_fx // Q1
}

/// `DTFS_phaseShift_fx`: shift the phase of every harmonic by `2pi·ph/Lag` (`ph` in Q7).
pub fn dtfs_phase_shift(x_fx: &mut DtfsStructure, ph: i16, lag: i16, s_fx: &[i16], c_fx: &[i16]) {
    let mut l_temp2: i32 = 0;
    let half = half_lag(x_fx.lag, x_fx.nh);
    let modulus = 4 * i32::from(lag);

    if ph > 0 {
        for k in 0..half {
            let temp = x_fx.a[k];
            let l_temp = l_shr(l_temp2, 5); // Q2
            let (c, s) = (at(c_fx, l_temp, modulus), at(s_fx, l_temp, modulus));
            x_fx.a[k] = round_word(l_msu(l_mult(temp, c), x_fx.b[k], s)); // X.Q
            x_fx.b[k] = round_word(l_mac(l_mult(x_fx.b[k], c), temp, s));
            l_temp2 = l_add(l_temp2, i32::from(ph));
        }
    }
    if ph < 0 {
        for k in 0..half {
            let temp = x_fx.a[k];
            let l_temp = l_shr(l_negate(l_temp2), 5); // Q2
            let (c, s) = (at(c_fx, l_temp, modulus), at(s_fx, l_temp, modulus));
            x_fx.a[k] = round_word(l_mac(l_mult(temp, c), x_fx.b[k], s)); // X.Q
            x_fx.b[k] = round_word(l_msu(l_mult(x_fx.b[k], c), temp, s));
            l_temp2 = l_add(l_temp2, i32::from(ph));
        }
    }
}

/// `DTFS_zeroPadd_fx`: extend the prototype to the period `n_fx` with zero harmonics and recount
/// the harmonics below the cut-off.
pub fn dtfs_zero_padd(n_fx: i16, x_fx: &mut DtfsStructure) {
    if sub(n_fx, x_fx.lag) == 0 {
        return;
    }
    let start = add(shr(x_fx.lag, 1), 1);
    let end = shr(n_fx, 1);
    let mut i = start.max(0);
    while i <= end && (i as usize) < LAG_MAX {
        x_fx.a[i as usize] = 0;
        x_fx.b[i as usize] = 0;
        i += 1;
    }
    x_fx.lag = n_fx;

    // recompute nH for new lag
    let mut rem_fx: i16 = 0;
    let diff_fx = find_rem(12800, x_fx.lag, &mut rem_fx);
    x_fx.nh = find_rem(x_fx.upper_cut_off_freq, diff_fx, &mut rem_fx);

    if sub(
        sub(
            x_fx.upper_cut_off_freq,
            shr(l_mult(diff_fx, x_fx.nh) as i16, 1),
        ),
        diff_fx,
    ) >= 0
    {
        x_fx.nh = add(x_fx.nh, 1);
    }
}

/// `DTFS_to_fs_fx`: the Fourier series of the `n`-sample period `x` (one pitch cycle), with the
/// harmonics above the cut-off of the sampling rate `fs` (or of the FR context, `fr_flag`)
/// zeroed. `s_fx` / `c_fx` are `GetSinCosTab_fx(n)`'s tables.
pub fn dtfs_to_fs(
    x: &[i16],
    n: i16,
    x_fx: &mut DtfsStructure,
    fs: i16,
    fr_flag: i16,
    s_fx: &[i16],
    c_fx: &[i16],
) {
    let mut la = [0_i32; LAG_MAX];
    let mut lb = [0_i32; LAG_MAX];

    if fr_flag == 0 {
        if sub(fs, 16000) == 0 {
            x_fx.upper_cut_off_freq_of_interest = 4000;
            x_fx.upper_cut_off_freq = 6400;
            x_fx.fs = INT_FS_FX;
        } else if sub(fs, 8000) == 0 {
            x_fx.upper_cut_off_freq_of_interest = 3300;
            x_fx.upper_cut_off_freq = 4000;
            x_fx.fs = INT_FS_FX;
        }
    } else {
        x_fx.upper_cut_off_freq_of_interest = 8000;
        x_fx.upper_cut_off_freq = 8000;
        x_fx.fs = 16000;
    }
    x_fx.lag = n;

    let mut exp = norm_s(x_fx.lag);
    let mut tmp = div_s(shl(1, sub(14, exp)), x_fx.lag); // Q29-exp
    let mut l_tmp1 = l_mult(12800, tmp); // Q(30-exp)
    let diff_fx = extract_h(l_shl(l_tmp1, sub(exp, 14))); // Q0

    exp = norm_s(diff_fx);
    tmp = div_s(shl(1, sub(14, exp)), diff_fx); // Q29-exp
    l_tmp1 = l_mult(x_fx.upper_cut_off_freq, tmp); // Q(30-exp)
    let mut nh_band = extract_h(l_shl(l_tmp1, sub(exp, 14))); // Q0

    let mut nh_4khz = mult(10240, x_fx.lag); // 4000/12800 in Q15

    if sub(
        sub(
            x_fx.upper_cut_off_freq,
            shr(l_mult(diff_fx, nh_band) as i16, 1),
        ),
        diff_fx,
    ) >= 0
    {
        nh_band = add(nh_band, 1);
    }
    if sub(sub(4000, shr(l_mult(diff_fx, nh_4khz) as i16, 1)), diff_fx) >= 0 {
        nh_4khz = add(nh_4khz, 1);
    }

    // Number of harmonics excluding the ones at 0 and at pi
    let nh = shr(sub(n, 1), 1);

    // The DC component
    x_fx.a[0] = 0;
    x_fx.b[0] = 0;

    exp = norm_s(n);
    tmp = div_s(shl(1, sub(14, exp)), n);
    let l_tmp = l_shl(i32::from(tmp), add(exp, 6));
    let inv_lag = round_word(l_tmp);

    let lx0 = l_deposit_h(x.first().copied().unwrap_or(0));
    let mut labmax: i32 = 0;
    let modulus = 4 * i32::from(n);
    let nu = n.max(0) as usize;
    let mut k: usize = 1;
    while (k as i16) <= nh && k < LAG_MAX {
        let mut l_a = l_shr(lx0, 1); // Q16
        let mut l_b: i32 = 0;
        let mut sum = k as i16;
        let temp = k as i16;
        for &sample in x.iter().take(nu).skip(1) {
            l_a = l_mac0(l_a, sample, at(c_fx, 4 * i32::from(sum), modulus)); // Q16 of x[n]*cos(sum)
            l_b = l_mac0(l_b, sample, at(s_fx, 4 * i32::from(sum), modulus)); // Q16 of x[n]*sin(sum)
            sum = add(sum, temp);
        }
        la[k] = l_shr(l_a, 6); // Q8 of a[k]*2.0
        lb[k] = l_shr(l_b, 6); // Q8 of b[k]*2.0

        let l_temp = l_abs(la[k]);
        if l_sub(l_temp, labmax) > 0 {
            labmax = l_temp;
        }
        let l_temp = l_abs(lb[k]);
        if l_sub(l_temp, labmax) > 0 {
            labmax = l_temp;
        }
        k += 1;
    }

    // The harmonic at 'pi'
    if n & 1 == 0 && k < LAG_MAX {
        let mut l_a: i32 = 0;
        let temp: i16 = 1;
        let temp_neg = negate(temp);
        let mut n_i: usize = 0;
        while (n_i as i32) < i32::from(n) - 1 {
            l_a = l_mac(l_a, x[n_i], temp); // Q1
            l_a = l_mac(l_a, x[n_i + 1], temp_neg);
            n_i += 2;
        }
        if n & 1 != 0 {
            // if N is odd we need to calculate last
            l_a = l_mac(l_a, x[n_i], temp); // Q1
        }
        la[k] = l_shl(l_a, 7); // Q8 of a[k]*1.0

        let l_temp = l_abs(la[k]);
        if l_sub(l_temp, labmax) > 0 {
            labmax = l_temp;
        }
        x_fx.b[k] = 0;
    }

    let mut temp = norm_l(labmax);
    if labmax == 0 {
        temp = 31;
    }

    let mut k: usize = 1;
    while (k as i16) <= nh && k < LAG_MAX {
        x_fx.a[k] = round_word(l_shl(la[k], temp)); // Q(8+temp-16)=Q(temp-8)
        x_fx.a[k] = mult_r(x_fx.a[k], inv_lag); // Q(temp-8+19+1-16)=Q(temp-4) of a[k]*2.0/N
        x_fx.b[k] = round_word(l_shl(lb[k], temp)); // Q(8+temp-16)=Q(temp-8)
        x_fx.b[k] = mult_r(x_fx.b[k], inv_lag); // Q(temp-8+19+1-16)=Q(temp-4) of b[k]*2.0/N
        k += 1;
    }

    if n & 1 == 0 && k < LAG_MAX {
        x_fx.a[k] = round_word(l_shl(la[k], temp)); // Q(8+temp-16)=Q(temp-8)
        x_fx.a[k] = mult_r(x_fx.a[k], inv_lag); // Q(temp-4) of a[k]*1.0/N
        x_fx.b[k] = 0;
    }

    x_fx.q = sub(temp, 4);

    let tmp = shr(x_fx.lag, 1).min(sub(MAXLAG_WI, 1));
    let mut k = add(nh_band, 1).max(0);
    while k <= tmp {
        x_fx.a[k as usize] = 0;
        x_fx.b[k as usize] = 0;
        k += 1;
    }
    x_fx.nh = nh_band;
    x_fx.nh_4khz = nh_4khz;
}

/// `DTFS_transform_fx`: `n` samples interpolated from prototype `x_fx` to prototype `x2_fx`
/// along the phase track `phase_fx` (Q27), the weight growing exponentially (or linearly in the
/// FR context, `fr_flag`) from the first to the second.
pub fn dtfs_transform(
    x_fx: &DtfsStructure,
    x2_fx: &DtfsStructure,
    phase_fx: &[i32],
    out_fx: &mut [i16],
    n: i16,
    fr_flag: i16,
) {
    let mut x2_256_fx = [0_i16; 256];
    let mut x1_256_fx = [0_i16; 256];
    let mut x_r_fx = [0_i32; 256];
    let nrg_flag: i16 = 0;

    let tmp1_dtfs_fx = *x_fx;
    let tmp2_dtfs_fx = *x2_fx;
    let mut tmp2: i16 = 0; // to avoid compilation warnings

    dtfs_fast_fs_inv(&tmp1_dtfs_fx, &mut x1_256_fx, 256, 8);
    dtfs_fast_fs_inv(&tmp2_dtfs_fx, &mut x2_256_fx, 256, 8);

    let mut exp1 = norm_s(n);
    let inv1_fx = div_s(shl(1, sub(14, exp1)), n); // 29-exp1
    let q1 = add(exp1, 1);

    let tmp1 = sub(x_fx.lag, n);
    let mut exp2 = norm_s(tmp1);
    if tmp1 < 0 {
        tmp2 = negate(tmp1);
    }
    let tmp = div_s(shl(1, 14_i16.wrapping_sub(exp2)), tmp2); // 29-exp2
    let mut l_tmp = l_shl(i32::from(tmp), 16);
    if tmp1 < 0 {
        l_tmp = l_negate(l_tmp);
    }
    let q2 = sub(exp2, 3);

    // L_temp=log(0.2)*log10(e)/(lag-M), Q(61-n)
    let l_temp_fx = mult_32_16(l_tmp, 22904);
    let inv2_fx = round_word(l_temp_fx); // log(0.2)*log10(e)/(lag-M), Q(45-n)

    let inv_fx = if sub(sub(n, WI_SAMPLE_THLD), x_fx.lag) > 0 {
        inv2_fx
    } else {
        exp2 = exp1;
        inv1_fx
    };

    let mut lw_fx = l_deposit_l(inv_fx);
    let nu = (n.max(0) as usize).min(out_fx.len()).min(phase_fx.len());
    for i in 0..nu {
        let w_fx: i16;
        if fr_flag == 0 {
            if sub(sub(n, WI_SAMPLE_THLD), x_fx.lag) > 0 {
                let mut l_tmp = l_shl(lw_fx, q2); // Q29-exp2+q2
                l_tmp = mult_32_16(l_tmp, 27213); // 3.321928 in Q13 -> 16+13+1, 27-exp2
                l_tmp = l_shl(l_tmp, sub(exp2, add(q2, 11)));
                let (exponent, frac) = l_extract_lc(l_tmp); // Extract exponent
                exp1 = exponent;
                let mut l_temp_fx = pow2(14, frac);
                exp1 = sub(exp1, 14);
                l_temp_fx = l_shl(l_temp_fx, add(exp1, 15)); // Q15
                                                             // w_fx in Q14 1- exp(- (i+1) * log(.2)/(lag-M))
                w_fx = sub(16384, extract_h(l_shl(l_temp_fx, 15)));
            } else {
                w_fx = round_word(l_shl(lw_fx, q1)); // Q14
            }
        } else if nrg_flag != 0 {
            w_fx = round_word(l_shl(lw_fx, q1)); // Q14
        } else {
            let n1 = sub(n, tmp2_dtfs_fx.lag);
            if sub(i as i16, n1) < 0 {
                // w =  (i+1)/N1;
                if n1 != 0 {
                    let mut expa = norm_s(n1);
                    let fraca = shl(n1, expa);
                    expa = sub(14, expa);

                    let tmp = add(i as i16, 1);
                    let mut expb = norm_s(tmp);
                    let mut fracb = shl(tmp, expb);
                    expb = sub(14, expb);

                    let scale = shr(sub(fraca, fracb), 15);
                    fracb = shl(fracb, scale);
                    expb = sub(expb, scale);

                    let w = div_s(fracb, fraca);
                    exp1 = sub(expb, expa);
                    w_fx = shl(w, exp1.wrapping_sub(1)); // Q14
                } else {
                    w_fx = 0;
                }
                lw_fx = l_deposit_h(w_fx);
            } else {
                w_fx = 16384;
            }
        }

        lw_fx = l_add(lw_fx, i32::from(inv_fx)); // (i+1)*inv
                                                 // mapping phase to 8x256 length signal
        let temp32_fx = phase_fx[i]; // Q(27-11)=Q16 due to multiplication by pow(2.0,11)
        let mut j = rint_new(temp32_fx);
        j &= 0x07ff;

        // k=j%8
        let k = (j & 7) as usize;
        let l1 = i32::from(shr(j, 3)); // reminder and quotient

        let temp_w = sub(16384, w_fx);
        for jj in 0..OSLENGTH {
            let m = ((1000 * LL + l1 - OSLENGTH / 2 + jj) % LL) as usize; // circular addressing
            x_r_fx[m] = l_mac(l_mult(x1_256_fx[m], temp_w), x2_256_fx[m], w_fx);
        }
        let mut tmptmp3_40_fx: i32 = 0;
        for jj in 0..OSLENGTH {
            let m = ((1000 * LL + l1 - OSLENGTH / 2 + jj) % LL) as usize; // circular addressing
            tmptmp3_40_fx = l_add(
                tmptmp3_40_fx,
                mult_32_16(x_r_fx[m], SINC_FX[k][jj as usize]),
            );
        }
        out_fx[i] = round_word(l_shl(tmptmp3_40_fx, 2));
    }
}

/// `DTFS_zeroFilter_fx`: filter the prototype by the FIR `LPC[0..N]` (Q12), harmonic by harmonic,
/// renormalising to a common Q.
#[allow(clippy::needless_range_loop)] // `k` indexes a, b and Qab in step, as the C does
pub fn dtfs_zero_filter(x_fx: &mut DtfsStructure, lpc: &[i16], n: i16, s_fx: &[i16], c_fx: &[i16]) {
    let mut qab = [0_i16; LAG_MAX];
    let mut qmin: i16 = 32767;
    let half = half_lag(x_fx.lag, x_fx.nh);
    let modulus = 4 * i32::from(x_fx.lag);
    let nu = n.max(0) as usize;

    for k in 0..half {
        let temp = k as i16;
        let mut temp2 = k as i16;

        // Calculate sum1 and sum2
        let mut sum1_fx = l_deposit_h(4096); // 1: Q(12+15+1)
        let mut sum2_fx: i32 = 0;
        for &coefficient in &lpc[..nu] {
            sum1_fx = l_mac(
                sum1_fx,
                coefficient,
                at(c_fx, 4 * i32::from(temp2), modulus),
            ); // Q(12+15+1)
            sum2_fx = l_mac(
                sum2_fx,
                coefficient,
                at(s_fx, 4 * i32::from(temp2), modulus),
            );
            temp2 = add(temp2, temp);
        }

        let temp1 = round_word(sum1_fx); // Q(12+15+1-16)=Q(12)
        let temp2 = round_word(sum2_fx); // Q(12)

        // Calculate the circular convolution
        let mut l_temp1 = l_mult(temp1, x_fx.a[k]);
        l_temp1 = l_msu(l_temp1, temp2, x_fx.b[k]); // Q(12+Q+1)
        let mut l_temp2 = l_mult(temp1, x_fx.b[k]);
        l_temp2 = l_mac(l_temp2, temp2, x_fx.a[k]); // Q(12+Q+1)

        // normalization
        let mut na = norm_l(l_temp1);
        if l_temp1 == 0 {
            na = 31;
        }
        let mut nb = norm_l(l_temp2);
        if l_temp2 == 0 {
            nb = 31;
        }
        if sub(na, nb) < 0 {
            nb = na;
        }
        x_fx.a[k] = round_word(l_shl(l_temp1, nb)); // Q(13+Q+nb-16)=Q(Q+nb-3)
        x_fx.b[k] = round_word(l_shl(l_temp2, nb)); // Q(Q+nb-3)

        qab[k] = sub(nb, 3);
        if sub(qab[k], qmin) < 0 {
            qmin = qab[k];
        }
    }
    // bring to the same Q
    for k in 0..half {
        x_fx.a[k] = shl(x_fx.a[k], sub(qmin, qab[k])); // Q(Q+Qmin)
        x_fx.b[k] = shl(x_fx.b[k], sub(qmin, qab[k])); // Q(Q+Qmin)
    }
    x_fx.q = add(x_fx.q, qmin);
}

/// `DTFS_poleFilter_fx_9`: filter the prototype by the all-pole filter whose per-harmonic
/// response `poleFilter_setup_fx` precomputed, renormalising to a common Q.
#[allow(clippy::needless_range_loop)] // `k` indexes a, b and Qab in step, as the C does
pub fn dtfs_pole_filter_9(
    x_fx: &mut DtfsStructure,
    pf_temp1: &[i16],
    pf_temp2: &[i16],
    pf_temp: &[i16],
    pf_n2_temp1: &[i16],
) {
    let mut qab = [0_i16; LAG_MAX];
    let mut qmin: i16 = 32767;
    let half = half_lag(x_fx.lag, x_fx.nh);

    for k in 0..half {
        let n2_temp1 = pf_n2_temp1[k];
        let temp1 = pf_temp1[k]; // Q(12+15+1+n2-16)=Q(12+n2)
        let temp2 = pf_temp2[k]; // Q(12+n2)

        // Calculate the circular convolution
        let l_temp1 = l_mac(l_mult(temp1, x_fx.a[k]), temp2, x_fx.b[k]); // Q(13+n2+Q)
        let l_temp2 = l_msu(l_mult(temp1, x_fx.b[k]), temp2, x_fx.a[k]); // Q(13+n2+Q)

        let temp = pf_temp[k]; // Q(20-2*n2-temp1)

        let sum1_fx = mult_32_16(l_temp1, temp); // Q(13+n2+Q+exp)
        let sum2_fx = mult_32_16(l_temp2, temp);
        // normalization
        let mut na = norm_l(sum1_fx);
        if sum1_fx == 0 {
            na = 31;
        }
        let mut nb = norm_l(sum2_fx);
        if sum2_fx == 0 {
            nb = 31;
        }
        if sub(na, nb) < 0 {
            nb = na;
        }
        nb = sub(nb, 1); // leave one more sign bit
        x_fx.a[k] = round_word(l_shl(sum1_fx, nb)); // Q(-3+n2+Q+exp+nb)
        x_fx.b[k] = round_word(l_shl(sum2_fx, nb));

        qab[k] = add(sub(nb, 3), n2_temp1);
        if sub(qab[k], qmin) < 0 {
            qmin = qab[k];
        }
    }
    // bring to the same Q
    for k in 0..half {
        x_fx.a[k] = shl(x_fx.a[k], sub(qmin, qab[k])); // Q(Q+Qmin)
        x_fx.b[k] = shl(x_fx.b[k], sub(qmin, qab[k])); // Q(Q+Qmin)
    }
    x_fx.q = add(x_fx.q, qmin);
}

/// `DTFS_adjustLag_fx`: change the prototype's period to `n_fx`, zero-padding a longer one and
/// truncating a shorter one at constant energy.
pub fn dtfs_adjust_lag(x_dtfs_fx: &mut DtfsStructure, n_fx: i16) {
    if sub(n_fx, x_dtfs_fx.lag) == 0 {
        return;
    }
    if sub(n_fx, x_dtfs_fx.lag) > 0 {
        dtfs_zero_padd(n_fx, x_dtfs_fx);
        return;
    }
    let en_fx = dtfs_get_engy(x_dtfs_fx); // Q = 2*(X_DTFS_FX->Q)

    let tmp = shr(x_dtfs_fx.lag, 1).min(x_dtfs_fx.nh);
    let mut k = add(shr(n_fx, 1), 1).max(0);
    while k <= tmp && (k as usize) < LAG_MAX {
        x_dtfs_fx.a[k as usize] = 0;
        x_dtfs_fx.b[k as usize] = 0;
        k += 1;
    }
    dtfs_set_engy(x_dtfs_fx, en_fx);
    x_dtfs_fx.lag = n_fx;

    // recompute nH for new lag
    let mut exp = norm_s(x_dtfs_fx.lag);
    let mut tmp = div_s(shl(1, sub(14, exp)), x_dtfs_fx.lag); // 29 - exp
    let mut l_tmp = l_mult0(12800, tmp);
    let temp32_fx = l_shl(l_tmp, sub(exp, 23));
    let diff_fx = l_shl(l_tmp, sub(exp, 29)) as i16;

    exp = norm_s(diff_fx);
    tmp = div_s(shl(1, sub(14, exp)), diff_fx); // 29 - exp
    l_tmp = l_mult0(x_dtfs_fx.upper_cut_off_freq, tmp);
    x_dtfs_fx.nh = l_shl(l_tmp, sub(exp, 29)) as i16;

    l_tmp = l_mult0(4000, tmp);
    x_dtfs_fx.nh_4khz = extract_l(l_shl(l_tmp, sub(exp, 29)));

    if sub(
        sub(
            x_dtfs_fx.upper_cut_off_freq,
            shr(l_mult(diff_fx, x_dtfs_fx.nh) as i16, 1),
        ),
        diff_fx,
    ) >= 0
    {
        x_dtfs_fx.nh = add(x_dtfs_fx.nh, 1);
    }

    let mul1_fx = l_shl(temp32_fx, 13); // Q19
    let mul2_fx = l_shl(i32::from(x_dtfs_fx.nh_4khz), 18); // Q18
    let mut tempnh_fx = mult_32_32(mul1_fx, mul2_fx); // Q6
    tempnh_fx = l_sub(256_000, tempnh_fx); // Q6

    if l_sub(tempnh_fx, temp32_fx) >= 0 {
        x_dtfs_fx.nh_4khz = add(x_dtfs_fx.nh_4khz, 1);
    }
}

/// `DTFS_getEngy_fx`: the prototype's energy, Q`2·q`.
#[must_use]
pub fn dtfs_get_engy(x_fx: &DtfsStructure) -> i32 {
    let mut en_fx: i32 = 0;
    let half = shr(sub(x_fx.lag, 1), 1).min(x_fx.nh);
    let mut k: usize = 1;
    while (k as i16) <= half && k < LAG_MAX {
        en_fx = l_mac0(en_fx, x_fx.a[k], x_fx.a[k]);
        en_fx = l_mac0(en_fx, x_fx.b[k], x_fx.b[k]);
        k += 1;
    }
    en_fx = l_shr(en_fx, 1);
    en_fx = l_mac0(en_fx, x_fx.a[0], x_fx.a[0]);

    // IF (X_fx->lag_fx%2 == 0)
    if x_fx.lag & 1 == 0 && k < LAG_MAX {
        en_fx = l_mac0(en_fx, x_fx.a[k], x_fx.a[k]);
        en_fx = l_mac0(en_fx, x_fx.b[k], x_fx.b[k]);
    }
    en_fx // 2*X1.Q+1=Q13
}

/// `DTFS_setEngy_fx`: scale the prototype to the energy `en2_fx`; returns its previous energy.
pub fn dtfs_set_engy(x_dtfs_fx: &mut DtfsStructure, en2_fx: i32) -> i32 {
    let half = half_lag(x_dtfs_fx.lag, x_dtfs_fx.nh);
    let en1_fx = dtfs_get_engy(x_dtfs_fx);

    if en1_fx == 0 {
        return 0;
    }

    let factor_fx = if en2_fx == 0 {
        0
    } else {
        let mut expa = norm_l(en2_fx);
        let fraca = extract_h(l_shl(en2_fx, expa));
        expa = sub(30, add(expa, shl(x_dtfs_fx.q, 1)));

        let mut expb = norm_l(en1_fx);
        let mut fracb = round_word(l_shl(en1_fx, expb));
        expb = sub(30, add(expb, shl(x_dtfs_fx.q, 1)));

        let scale = shr(sub(fraca, fracb), 15);
        fracb = shl(fracb, scale);
        expb = sub(expb, scale);

        let tmp = div_s(fracb, fraca);
        let mut exp = sub(expb, expa);

        let l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp); // Q(31-exp)
        l_shr(l_tmp, 1)
    };

    for k in 0..half {
        let l_temp_fx = mult_32_16(factor_fx, x_dtfs_fx.a[k]); // Q(temp+X1.Q-15)
        x_dtfs_fx.a[k] = round_word(l_temp_fx); // Q(temp+X1.Q-31)
        let l_temp_fx = mult_32_16(factor_fx, x_dtfs_fx.b[k]);
        x_dtfs_fx.b[k] = round_word(l_temp_fx);
    }
    en1_fx // 2*X1.Q+1 = Q13
}

/// `cubicPhase_fx`: the cubic phase track (Q27, `n` samples) from phase `ph1` at pitch `L1` to
/// phase `ph2` at pitch `L2`, continuing linearly over the last period.
pub fn cubic_phase(ph1_fx: i16, ph2_fx: i16, l1: i16, l2: i16, n: i16, ph_out_fx: &mut [i32]) {
    let mut num_flag: i16 = 0;
    let mut den_flag: i16 = 0;

    let n = sub(n, l2);

    let mut exp = norm_s(l1);
    let mut tmp = div_s(shl(1, sub(14, exp)), l1);
    let mut l_tmp = l_shl(i32::from(tmp), exp.wrapping_add(6));
    let f1 = round_word(l_tmp);

    exp = norm_s(l2);
    tmp = div_s(shl(1, sub(14, exp)), l2);
    l_tmp = l_shl(i32::from(tmp), exp.wrapping_add(6));
    let ltemp4 = rom(&INVERSE_TABLE, i32::from(l2));
    let f2 = round_word(l_tmp);

    let c3 = ph1_fx; // c3 in Q15
    let c2 = f1; // c2 in Q19

    let mut ltemp1 = l_sub(i32::from(ph1_fx), i32::from(ph2_fx)); // Q15
    let mut ltemp2 = l_add(i32::from(f1), i32::from(f2)); // Q20
    let temp = extract_l(ltemp2); // Q20

    if temp < 0 {
        let l_tmp1 = l_shl(l_add(65536, i32::from(temp)), 14); // Q30
        let l_tmp = mult_32_16(l_tmp1, n); // 30-15=15
        ltemp2 = l_shl(l_tmp, 1);
    } else {
        ltemp2 = l_mult0(n, temp); // Q20
    }

    ltemp1 = l_add(l_shl(ltemp1, 5), ltemp2); // Q20
    let factor = round_word(l_shr(ltemp1, 4)); // factor in Q0

    let mut c1 = sub(f2, f1); // c1=f2-f1, Q19
    ltemp1 = l_sub(i32::from(ph2_fx), i32::from(ph1_fx)); // Q15
    ltemp2 = l_mult(n, f1); // Q20
    ltemp2 = l_sub(l_shl(l_deposit_h(factor), 4), ltemp2); // Q20
    ltemp1 = l_add(ltemp2, l_shl(ltemp1, 5)); // Q20

    if sub(n, 180) > 0 {
        ltemp2 = l_shl(l_mult0(n, n), 14);
        ltemp2 = l_shl(mult_32_16(ltemp2, n), 1);
        if n & 1 == 1 {
            ltemp2 = l_add(ltemp2, 1);
        }
    } else {
        ltemp2 = l_shr(l_mult(n, n), 1);
        ltemp2 = l_mult0(n, extract_l(ltemp2)); // Ltemp2=N^3
    }
    let mut ltemp3 = l_mult(n, c1); // Q20
    ltemp3 = l_sub(ltemp3, l_shl(ltemp1, 1)); // N*c1-2*Ltemp1, Q20

    let c0 = if l_sub(l_abs(ltemp3), l_shl(ltemp2, 8)) >= 0 {
        let lacc = if ltemp3 > 0 { i32::MAX } else { MIN_32 };
        extract_h(lacc) // c0 in Q33
    } else {
        let mut expa = norm_l(ltemp3);
        let mut fraca = extract_h(l_shl(ltemp3, expa));
        expa = sub(30, add(expa, 20));
        if fraca < 0 {
            num_flag = 1;
        }
        let mut expb = norm_l(ltemp2);
        let mut fracb = extract_h(l_shl(ltemp2, expb));
        expb = sub(30, expb);
        if fracb < 0 {
            den_flag = 1;
        }
        if num_flag != 0 {
            fraca = negate(fraca);
        }
        if den_flag != 0 {
            fracb = negate(fracb);
        }
        let scale = shr(sub(fracb, fraca), 15);
        fraca = shl(fraca, scale);
        expa = sub(expa, scale);

        let mut tmp = div_s(fraca, fracb); // 15-exp
        let exp = sub(expa, expb);
        if num_flag != 0 && den_flag == 0 {
            tmp = negate(tmp);
        }
        if den_flag != 0 && num_flag == 0 {
            tmp = negate(tmp);
        }
        let mut lacc = l_shl(i32::from(tmp), add(exp, 34));
        lacc = l_add(lacc, 0x08000);
        extract_h(lacc) // c0 in Q33
    };

    ltemp1 = l_mult(n, n); // Ltemp1=2*N*N
    ltemp1 = l_add(ltemp1, l_shr(ltemp1, 1)); // Ltemp1=3*N*N, max is 3*140*140

    // patch added for time warping support, where N can be more than 140
    let dbgshft = norm_l(ltemp1);
    ltemp1 = l_shl(ltemp1, dbgshft);
    let temp = extract_h(ltemp1);
    ltemp1 = l_shl(l_mult0(c0, temp), sub(16, dbgshft)); // Ltemp1=3*N*N*c0, Q33
                                                         // Patch end

    num_flag = 0;
    den_flag = 0;
    ltemp1 = l_sub(l_shr(l_deposit_h(c1), 2), ltemp1); // Ltemp1=c1-3*N*N*c0, Q33

    let mut expa = norm_l(ltemp1);
    let mut fraca = extract_h(l_shl(ltemp1, expa));
    expa = sub(30, add(expa, 33));
    if fraca < 0 {
        num_flag = 1;
    }
    let mut expb = norm_l(i32::from(n));
    let mut fracb = extract_h(l_shl(i32::from(n), expb));
    expb = sub(30, expb);
    if fracb < 0 {
        den_flag = 1;
    }
    if num_flag != 0 {
        fraca = negate(fraca);
    }
    if den_flag != 0 {
        fracb = negate(fracb);
    }
    let scale = shr(sub(fracb, fraca), 15);
    fraca = shl(fraca, scale);
    expa = sub(expa, scale);

    let mut tmp = div_s(fraca, fracb); // 15-exp
    let exp = sub(expa, expb);
    if num_flag != 0 && den_flag == 0 {
        tmp = negate(tmp);
    }
    if den_flag != 0 && num_flag == 0 {
        tmp = negate(tmp);
    }
    let mut lacc = l_shl(i32::from(tmp), exp.wrapping_add(27));
    lacc = l_add(lacc, 0x08000);
    c1 = extract_h(lacc); // c1 in Q27

    // Computation of the phase value at each sample point
    // ph[n]=  c0*n^3+c1*n^2+c2*n+c3, Q15
    let len = ph_out_fx.len().min(WI_FX_PHASE_FX as usize);
    if len == 0 {
        return;
    }
    ph_out_fx[0] = l_shl(i32::from(ph1_fx), 11); // Q27

    let poly = |ltemp3: i32, ltemp2: i32, n_i: i16| -> i32 {
        let ltemp1 = l_shl(l_mult(c2, n_i), 7); // c2*n, Q27
        let mut ltemp = l_shl(i32::from(c3), 12); // Q27
        ltemp = l_add(ltemp1, ltemp); // Q27
        ltemp = l_add(ltemp2, ltemp); // Q27
        l_add(ltemp3, ltemp) // Q27
    };

    let mut n_i: i16 = 1;
    let low_end = if sub(n, 181) < 0 { n } else { 181 };
    while n_i < low_end && (n_i as usize) < len {
        let n2 = i_mult2(n_i, n_i); // n2=n^2
        let mut ltemp3 = l_mult0(n_i, n2); // n^3
        ltemp3 = l_shl(mult_32_16(l_shl(ltemp3, 7), c0), 2); // c0*n^3, Q27
        let ltemp2 = l_mult0(c1, n2); // c1*n^2, Q27
        ph_out_fx[n_i as usize] = poly(ltemp3, ltemp2, n_i);
        n_i += 1;
    }
    if sub(n, 181) >= 0 {
        while n_i < n && (n_i as usize) < len {
            let n2_32 = l_shl(l_mult0(n_i, n_i), 14);
            let mut ltemp3 = l_shl(mult_32_16(n2_32, n_i), 1);
            if n & 1 == 1 {
                ltemp3 = l_add(ltemp3, 1);
            }
            ltemp3 = l_shl(mult_32_16(l_shl(ltemp3, 7), c0), 2); // c0*n^3, Q27
            let ltemp2 = l_shl(mult_32_16(n2_32, c1), 1);
            ph_out_fx[n_i as usize] = poly(ltemp3, ltemp2, n_i);
            n_i += 1;
        }
    }

    let tmp = add(n, l2);
    while n_i < tmp && (n_i as usize) < len {
        ph_out_fx[n_i as usize] = l_add(ph_out_fx[n_i as usize - 1], ltemp4); // Q27
        n_i += 1;
    }
}

/// `WIsyn_fx`: synthesise `n` samples by waveform interpolation from the previous prototype
/// `prevcw_fx` to the current one `curr_cw_dtfs_fx` (which is aligned and phase-shifted in place),
/// carrying the phase offset `ph_offset_fx` (Q15). `curr_lpc_fx` weights the alignment search
/// outside the FR context (`fr_flag == 0`); the `pf_*` arrays are its scratch.
pub fn wi_syn(
    mut prevcw_fx: DtfsStructure,
    curr_cw_dtfs_fx: &mut DtfsStructure,
    curr_lpc_fx: &[i16],
    ph_offset_fx: &mut i16,
    out_fx: &mut [i16],
    n: i16,
    fr_flag: i16,
    s_fx: &[i16],
    c_fx: &[i16],
    pf_temp1: &mut [i16],
    pf_temp2: &mut [i16],
    pf_temp: &mut [i16],
    pf_n2: &mut [i16],
) {
    let big_i: u16 = 1;
    let flag: u16 = 0;
    let mut phase_fx = [0_i32; WI_FX_PHASE_FX as usize];
    let mut temp: i16 = 0;
    let mut tmp_fx: i16 = 0;

    if sub(prevcw_fx.q, curr_cw_dtfs_fx.q) < 0 {
        let temp = sub(curr_cw_dtfs_fx.q, prevcw_fx.q);
        let half = half_lag(curr_cw_dtfs_fx.lag, curr_cw_dtfs_fx.nh);
        for i in 0..half {
            curr_cw_dtfs_fx.a[i] = shr(curr_cw_dtfs_fx.a[i], temp);
            curr_cw_dtfs_fx.b[i] = shr(curr_cw_dtfs_fx.b[i], temp);
        }
        curr_cw_dtfs_fx.q = prevcw_fx.q;
    }

    if sub(curr_cw_dtfs_fx.q, prevcw_fx.q) < 0 {
        let temp = sub(prevcw_fx.q, curr_cw_dtfs_fx.q);
        let half = half_lag(prevcw_fx.lag, prevcw_fx.nh);
        for i in 0..half {
            prevcw_fx.a[i] = shr(prevcw_fx.a[i], temp);
            prevcw_fx.b[i] = shr(prevcw_fx.b[i], temp);
        }
        prevcw_fx.q = curr_cw_dtfs_fx.q;
    }

    let mut currcw_dtfs_fx = dtfs_new();
    dtfs_copy(&mut currcw_dtfs_fx, curr_cw_dtfs_fx);
    // Calculating the expected alignment shift
    let mut alignment_fx = mult_r(*ph_offset_fx, shl(prevcw_fx.lag, 7)); // confirmed I<2 by smv12.org, Q7

    if flag == 1 {
        alignment_fx = extract_l(l_shr(l_mult(alignment_fx, big_i as i16), 1)); // Q7
    }

    // Calculating the expected alignment shift
    find_rem(n, shr(add(prevcw_fx.lag, currcw_dtfs_fx.lag), 1), &mut temp);
    temp = add(shl(temp, 7), alignment_fx); // Q7

    if temp < 0 {
        temp = add(temp, shl(currcw_dtfs_fx.lag, 7)); // Q7
    }

    find_rem(temp, shl(currcw_dtfs_fx.lag, 7), &mut tmp_fx); // Q7
    if fr_flag == 0 {
        alignment_fx = dtfs_alignment_weight(
            &prevcw_fx,
            currcw_dtfs_fx,
            tmp_fx,
            curr_lpc_fx,
            curr_lpc_fx,
            s_fx,
            c_fx,
            pf_temp1,
            pf_temp2,
            pf_temp,
            pf_n2,
        ); // Q7
    } else {
        alignment_fx = dtfs_alignment_full(
            prevcw_fx,
            currcw_dtfs_fx,
            *ph_offset_fx,
            s_fx,
            c_fx,
            fr_flag,
        );
        // alignment_fx is in Q1, we make it Q7
        alignment_fx = shl(alignment_fx, 6);
    }

    let lag_q7 = shl(currcw_dtfs_fx.lag, 7);
    let fraction_of_lag = |temp: i16| -> i16 {
        let tmp = lag_q7;
        let exp = norm_s(tmp);
        let tmp = div_s(shl(1, sub(14, exp)), tmp); // 22-exp
        let l_tmp = l_shl(l_mult(temp, tmp), exp.wrapping_add(1));
        round_word(l_tmp)
    };
    if sub(alignment_fx, lag_q7) >= 0 {
        tmp_fx = fraction_of_lag(sub(alignment_fx, lag_q7));
    } else if alignment_fx < 0 {
        tmp_fx = negate(fraction_of_lag(negate(alignment_fx)));
    } else {
        tmp_fx = fraction_of_lag(alignment_fx);
    }

    let lag = currcw_dtfs_fx.lag;
    dtfs_phase_shift(&mut currcw_dtfs_fx, alignment_fx, lag, s_fx, c_fx); // Qmin
    let lag = curr_cw_dtfs_fx.lag;
    dtfs_phase_shift(curr_cw_dtfs_fx, alignment_fx, lag, s_fx, c_fx); // Qmin

    // Compute the cubic phase track and transform to 1-D signal
    cubic_phase(
        *ph_offset_fx,
        tmp_fx,
        prevcw_fx.lag,
        currcw_dtfs_fx.lag,
        n,
        &mut phase_fx,
    );

    if fr_flag == 0 {
        dtfs_transform(&prevcw_fx, &currcw_dtfs_fx, &phase_fx, out_fx, n, 0);
    } else {
        dtfs_transform(&prevcw_fx, &currcw_dtfs_fx, &phase_fx, out_fx, n, 1);
    }

    // Adjust the phase offset and wrap it between 0 and 2pi
    let mut l_temp = if flag == 2 {
        l_shr(l_mult(tmp_fx, big_i as i16), 1) // Q15
    } else {
        l_deposit_l(tmp_fx) // Q15
    };
    while l_temp < 0 {
        l_temp += 0x8000;
    }
    l_temp &= 0x7fff; // fraction part
    *ph_offset_fx = extract_l(l_temp);
}

/// `GetSinCosTab_fx`: `sin` / `cos` of `2pi·i/(4L)` for `i < 4L` (Q15), interpolated from the
/// 512-entry cosine table.
pub fn get_sin_cos_tab(l: i16, sin_tab: &mut [i16], cos_tab: &mut [i16]) {
    let inv_l = l_shr(rom(&INVERSE_TABLE, i32::from(l)), 4); // 1/4L in Q25
    let l4 = (shl(l, 2).max(0) as usize)
        .min(sin_tab.len())
        .min(cos_tab.len());
    let mut lw: i32 = 0;
    // `Ltemp = L_tmp * dt` is a plain C product in the reference (a 17-bit by 16-bit value, so it
    // never overflows 32 bits).
    let interpolate = |dl: i16, dt: i16| -> i32 {
        if dl < 0 {
            let l_tmp = l_add(65536, i32::from(dl));
            l_tmp.wrapping_mul(i32::from(dt))
        } else {
            l_mult0(dt, dl) // Ltemp in Q31
        }
    };
    for i in 0..l4 {
        let mut w = extract_h(lw); // w in Q9
        let dl = extract_l(lw); // dl has 16 bits left-over
        w &= 511;
        let t1 = COS_TABLE[w as usize];
        let dt = COS_DIFF_TABLE[w as usize];
        let l_temp = interpolate(dl, dt);
        cos_tab[i] = add(t1, l_shr(l_temp, 16) as i16); // interpolated cos(i*2pi/4L)

        // add 0.75 in Q25, which is 3pi/2 to convert sin to cos
        let l_temp = l_add(lw, 0x0180_0000);
        let mut w = extract_h(l_temp); // w is equivalent cos index
        w &= 511;
        let t1 = COS_TABLE[w as usize];
        let dt = COS_DIFF_TABLE[w as usize];
        // the reference interpolates with the cosine's left-over dl, not the shifted one's
        let l_temp = interpolate(dl, dt);
        sin_tab[i] = add(t1, l_shr(l_temp, 16) as i16); // t1 is interpolated cos(w)

        lw = l_add(lw, inv_l); // Lw=(i+1)/4L, Q25
    }
}

/// `poleFilter_setup_fx`: per harmonic of `X_fx`, the response of `1/A(z)` (`LPC[0..N]`, Q12)
/// that `DTFS_poleFilter_fx_9` applies: its real and imaginary part (`pf_temp1`, `pf_temp2`),
/// the inverse squared magnitude `pf_temp` and their exponents `pf_n2_temp1`.
pub fn pole_filter_setup(
    lpc: &[i16],
    n: i16,
    x_fx: &DtfsStructure,
    s_fx: &[i16],
    c_fx: &[i16],
    pf_temp1: &mut [i16],
    pf_temp2: &mut [i16],
    pf_temp: &mut [i16],
    pf_n2_temp1: &mut [i16],
) {
    let half = half_lag(x_fx.lag, x_fx.nh);
    let modulus = 4 * i32::from(x_fx.lag);
    let nu = n.max(0) as usize;

    for k in 0..half {
        let mut temp2 = k as i16;
        // Calculate sum1 and sum2
        let mut sum1_fx = l_deposit_h(4096); // 1: Q(12+15+1)
        let mut sum2_fx: i32 = 0;
        for &coefficient in &lpc[..nu] {
            sum1_fx = l_mac(
                sum1_fx,
                coefficient,
                at(c_fx, 4 * i32::from(temp2), modulus),
            ); // Q(12+15+1)
            sum2_fx = l_mac(
                sum2_fx,
                coefficient,
                at(s_fx, 4 * i32::from(temp2), modulus),
            ); // Q(12+15+1)
            temp2 = add(temp2, k as i16);
        }

        let n1 = if sum1_fx == 0 { 31 } else { norm_l(sum1_fx) };
        let mut n2 = if sum2_fx == 0 { 31 } else { norm_l(sum2_fx) };
        if sub(n1, n2) < 0 {
            n2 = n1;
        }
        n2 = sub(n2, 1);
        let temp1 = round_word(l_shl(sum1_fx, n2)); // Q(12+n2)
        pf_temp1[k] = temp1;
        let temp2 = round_word(l_shl(sum2_fx, n2)); // Q(12+n2)
        pf_temp2[k] = temp2;

        // Calculate the circular convolution
        let sum = l_mac(l_mult(temp1, temp1), temp2, temp2); // Q(25+2*n2)

        let mut exp = norm_l(sum);
        let tmp = extract_h(l_shl(sum, exp));
        exp = sub(sub(30, exp), add(25, shl(n2, 1)));
        let tmp = div_s(16384, tmp); // Q(15+exp)

        pf_n2_temp1[k] = add(n2, exp);
        pf_temp[k] = tmp; // Q15+exp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_prototype_is_empty_with_the_narrowband_cut_offs() {
        let x = dtfs_new();
        assert_eq!((x.lag, x.nh, x.nh_4khz, x.fs, x.q), (0, 0, 0, 0, 0));
        assert_eq!(
            (x.upper_cut_off_freq_of_interest, x.upper_cut_off_freq),
            (3300, 4000)
        );
        assert!(x.a.iter().chain(&x.b).all(|&v| v == 0));
    }

    #[test]
    fn a_zero_lag_never_indexes_out_of_bounds() {
        let (mut s, mut c) = ([0_i16; 925], [0_i16; 925]);
        get_sin_cos_tab(0, &mut s, &mut c);
        let mut x = dtfs_new();
        dtfs_to_fs(&[0; 4], 0, &mut x, 8000, 1, &s, &c);
        let y = x;
        assert_eq!(dtfs_alignment_full(x, y, 0, &s, &c, 1), 0);
    }
}
