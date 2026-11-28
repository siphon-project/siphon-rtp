//! Pitch-dependent concealment of the HQ phase ECU (TS 26.442 `lib_dec/FEC_HQ_phase_ecu_fx.c`):
//! `fir_dwn_fx`, `fec_ecu_pitch_fx`, `fec_ecu_dft_fx`, `sinusoidal_synthesis_fx`,
//! `fec_noise_filling_fx` and `fec_alg_fx`.

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    ALDO_WINDOW, L_FRAME16K, L_FRAME32K, L_FRAME48K, N16_CORE_SW, R1_16, R1_48, R2_16, R2_48,
};
use crate::evs::com::fft_fx::do_rtftn;
use crate::evs::com::math_op::{i_mult2, isqrt};
use crate::evs::com::tools::{
    copy_scale_sig_16_32, copy_scale_sig_32_16, exp16_array, find_max_norm16, random, scale_sig,
};
use crate::evs::com::window_ola::sinq;
use crate::evs::com::wtda::wtda;
use crate::evs::rom::{
    ASR_LP16_FX, ASR_LP32_FX, ASR_LP48_FX, SINCOS_T_RAD3_FX, SINQ_16K, SINQ_32K, SINQ_48K,
};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_deposit_l, l_msu, l_mult, l_shl,
    l_shr, l_sub, negate, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_lshr, l_mac0, l_msu0, mac_r, mpy_32_32_ss};

const FEC_MAX: usize = 512;
const FEC_NB_PULSE_MAX: usize = 20;
const FEC_FFT_MAX_SIZE: usize = 512;

/// `mult_32_32_q`: the 64-bit product of `a` and `b`, shifted right by `q + 1` bits into 32.
pub fn mult_32_32_q(a: i32, b: i32, q: i16) -> i32 {
    let (hi, lo) = mpy_32_32_ss(a, b);
    l_shl(hi, 32 - q - 1) | l_lshr(lo as i32, q + 1)
}

/// `fir_dwn_fx`: FIR filter `h` (`K+1` coefficients, Q`h_q`) and decimate `x` (`L` samples),
/// without delay (the filter is centred, the signal edges are zero extended).
pub fn fir_dwn(x: &[i16], h: &[i16], h_q: i16, y: &mut [i16], l: i16, k: i16, decimation: i16) {
    let centering = sub(16, h_q);
    let kdiv2 = shr(k, 1);
    let mut p_y = 0usize;

    // do the filtering
    let mut i = kdiv2;
    while i < k {
        let mut s = l_deposit_l(0);
        for j in 1..=i as usize {
            s = l_mac0(s, h[j], x[i as usize - j]);
        }
        y[p_y] = extract_h(l_shl(s, centering));
        p_y += 1;
        i += decimation;
    }
    while i < l {
        let mut s = l_deposit_l(0);
        for j in 1..=k as usize {
            s = l_mac0(s, h[j], x[i as usize - j]);
        }
        y[p_y] = extract_h(l_shl(s, centering));
        p_y += 1;
        i += decimation;
    }
    let tmp = add(l, kdiv2);
    while i < tmp {
        let mut s = l_deposit_l(0);
        let first = (i - l + 1) as usize; // ptr_h = h + i - L + 1
        for (offset, j) in (first..=k as usize).enumerate() {
            s = l_mac0(s, h[j], x[l as usize - 1 - offset]);
        }
        y[p_y] = extract_h(l_shl(s, centering));
        p_y += 1;
        i += decimation;
    }
}

/// `fec_ecu_pitch_fx`: the pitch lag `n` (at the input rate, in `n`) and its normalised
/// correlation `min_corr` (Q15) of the previous synthesis, found on the 8 kHz down-sampled
/// signal `prevsynth_lp` (320 samples).
pub fn fec_ecu_pitch(
    prevsynth: &[i16],
    prevsynth_lp: &mut [i16],
    l: i16,
    n: &mut i16,
    min_corr: &mut i16,
    decimatefaktor: &mut i16,
    hq_voicing: i16,
) {
    let (filt_size, asr_lp, q_asr, lmul2): (i16, &[i16], i16, i16) = match l {
        L_FRAME48K => {
            *decimatefaktor = 6;
            (60, &ASR_LP48_FX, 17, 1920)
        }
        L_FRAME32K => {
            *decimatefaktor = 4;
            (40, &ASR_LP32_FX, 15, 1280)
        }
        L_FRAME16K => {
            *decimatefaktor = 2;
            (20, &ASR_LP16_FX, 15, 640)
        }
        _ => {
            *decimatefaktor = 2;
            (40, &ASR_LP16_FX, 15, 320)
        }
    };
    let lon20mul6: i16 = 48;
    let lon20mul28: i16 = 224;
    let lon20mul33: i16 = 264;
    let lon20mul34: i16 = 272;

    // Resampling to work at 8Khz (without delay)
    fir_dwn(
        prevsynth,
        asr_lp,
        q_asr,
        prevsynth_lp,
        lmul2,
        filt_size,
        *decimatefaktor,
    );

    let tmp_qlp = find_max_norm16(prevsynth_lp, 320);
    scale_sig(prevsynth_lp, 320, sub(tmp_qlp, 3)); // to avoid over scaling

    // Correlation analysis
    *min_corr = 0;
    let mut acc_c = l_deposit_l(0);
    let c_start = lon20mul34 as usize;
    for k in 0..lon20mul6 as usize {
        acc_c = l_mac0(acc_c, prevsynth_lp[c_start + k], prevsynth_lp[c_start + k]);
    }

    let cb_start: i16 = 0;
    let cb_end = if hq_voicing == 1 {
        lon20mul33
    } else {
        lon20mul28
    };

    let mut acc_b: i32 = 0;
    let mut delay_ind = cb_start;
    for i in cb_start..cb_end {
        let mut acc_a: i32 = 0;
        let iu = i as usize;
        if i == cb_start {
            acc_b = 0;
            for k in 0..lon20mul6 as usize {
                acc_a = l_mac0(acc_a, prevsynth_lp[k], prevsynth_lp[c_start + k]);
                acc_b = l_mac0(acc_b, prevsynth_lp[k], prevsynth_lp[k]);
            }
        } else {
            let old = prevsynth_lp[iu - 1];
            let new = prevsynth_lp[iu + lon20mul6 as usize - 1];
            acc_b = l_mac0(l_msu0(acc_b, old, old), new, new);
            for k in 0..lon20mul6 as usize {
                acc_a = l_mac0(acc_a, prevsynth_lp[iu + k], prevsynth_lp[c_start + k]);
            }
        }

        // accA: Q(6 - 2 tmpQLP), accB / accC: energies
        let acc_b_isqrt = isqrt(acc_b); // Q31 - 3 + tmpQLP
        let acc_c_isqrt = isqrt(acc_c);

        let mut ryytmp = mult_32_32_q(acc_a, acc_c_isqrt, 16 + 3 - tmp_qlp);
        ryytmp = mult_32_32_q(ryytmp, acc_b_isqrt, 15 - 3 + tmp_qlp); // Q31
        let ryy = extract_h(ryytmp); // Q15

        if ryy > *min_corr {
            *min_corr = ryy;
            delay_ind = i;
        }

        if hq_voicing == 0 && *min_corr > 31130 {
            break;
        }
    }

    *n = sub(lon20mul34, delay_ind);

    scale_sig(prevsynth_lp, 320, negate(sub(tmp_qlp, 3)));
}

/// `sin_cos_est_fx`: cos and sin (Q15) of `phi`, a normalised frequency between 0 and Pi (Q30),
/// from the radix-3 sine table and a first order correction. Returns `(cosfreq, sinfreq)`.
pub fn sin_cos_est(phi: i32) -> (i16, i16) {
    let mut i: i16 = 0;
    let mut imin: i32 = 0;
    while imin < phi {
        i = add(i, 1);
        imin = imin.wrapping_add(4_392_264);
    }

    let delta = l_sub(phi, imin); // Q30
                                  // Q15. The callers keep `phi` at or below Pi/2 (`i <= 384`); an index the table does not
                                  // hold is a read past it in the reference and reads 0 here.
    let table = |index: i32| {
        usize::try_from(index)
            .ok()
            .and_then(|k| SINCOS_T_RAD3_FX.get(k))
            .copied()
            .unwrap_or(0)
    };
    let sinb = table(i32::from(i));
    let cosb = table(384 - i32::from(i));

    // sinv = sin(phi) = sinb*cos(delta)+cosb*sin(delta)
    // cosv = cos(phi) = cosb*cos(delta)-sinb*sin(delta)
    // sin(delta) is approximated by delta for very small delta; cos(delta) by 1
    let tmp = l_shl(mult_32_16(delta, cosb), 1); // Q31
    let sinv = l_add(l_deposit_h(sinb), tmp);
    let tmp = l_shl(mult_32_16(delta, sinb), 1); // Q31
    let cosv = l_sub(l_deposit_h(cosb), tmp);

    (round_word(cosv), round_word(sinv))
}

/// `abs_iter_fx`: |re + j im| by `n` CORDIC iterations (the gain correction is omitted in the
/// reference).
pub fn abs_iter(re: i16, im: i16, n: i16) -> i16 {
    let mut exp = norm_s(re);
    exp = exp.min(norm_s(im));
    exp = sub(exp, 2);

    let mut re = shl(re, exp);
    let mut im = shl(im, exp);

    if im < 0 {
        im = negate(im);
    } else {
        re = negate(re);
    }
    std::mem::swap(&mut re, &mut im);

    for i in 0..n {
        let mut l_tmp1 = shr(im, i);
        let mut l_tmp2 = shr(re, i);
        if im < 0 {
            l_tmp1 = negate(l_tmp1);
        } else {
            l_tmp2 = negate(l_tmp2);
        }
        re = add(re, l_tmp1);
        im = add(im, l_tmp2);
    }
    let tmp = abs_s(re);
    shr(tmp, exp)
}

/// The outputs of [`fec_ecu_dft`].
pub struct DftOut<'a> {
    pub tfr: &'a mut [i16],
    pub tfi: &'a mut [i16],
    pub sum_tf_abs: &'a mut i32,
    pub tf_abs: &'a mut [i16],
    pub nfft: &'a mut i16,
    pub exp: &'a mut i16,
}

/// `fec_ecu_dft_fx`: DFT of the last `n` samples of the down-sampled signal (interpolated to the
/// next power of two `nfft` above), with the CORDIC magnitudes `tf_abs` of the lower half.
pub fn fec_ecu_dft(prevsynth_lp: &[i16], n: i16, out: &mut DftOut<'_>) {
    let mut tfr32 = [0i32; 512];
    let mut tfi32 = [0i32; 512];
    let mut target = [0i16; 2 * L_FRAME48K as usize];
    let mut tfr16 = [0i16; FEC_FFT_MAX_SIZE];

    let tmp = sub(296, n);
    target[..n as usize].copy_from_slice(&prevsynth_lp[tmp as usize..(tmp + n) as usize]);

    // DFT
    let mut l_tmp = l_deposit_l(n);
    let mut tmp: i16 = 0;
    while l_tmp <= 16384 {
        l_tmp = l_shl(l_tmp, 1);
        tmp += 1;
    }
    *out.nfft = shl(1, sub(15, tmp));
    let nfft = *out.nfft;
    let nfft_us = nfft as usize;

    tfr16[0] = target[0];
    tfr16[nfft_us - 1] = target[n as usize - 1];

    if sub(nfft, n) == 0 {
        tfr16[1..nfft_us - 1].copy_from_slice(&target[1..nfft_us - 1]);
    } else {
        let tmp = div_s(sub(n, 1), sub(nfft, 1));
        let mut tmp_acc = l_deposit_l(tmp);
        let fac = l_add(tmp_acc, 0);
        let tmp_loop = sub(nfft, 1);
        for value in tfr16.iter_mut().take(tmp_loop as usize).skip(1) {
            // interpolation for FFT
            let tmp_short = extract_l(l_shr(tmp_acc, 15));
            let tmp = extract_l(l_msu(tmp_acc, tmp_short, 16384));
            let ts = tmp_short as usize;
            let l_tmp = l_mult(sub(target[ts + 1], target[ts]), tmp); // Qin+16
            *value = add(target[ts], round_word(l_tmp)); // Qin
            tmp_acc = l_add(tmp_acc, fac);
        }
    }

    // to avoid overflow in DoRTFTn_fx()
    let tmp = exp16_array(nfft, &tfr16);
    *out.exp = add(tmp, add(2, norm_s(nfft)));
    copy_scale_sig_16_32(&tfr16, &mut tfr32, nfft, *out.exp); // Qin+exp

    do_rtftn(&mut tfr32, &mut tfi32, nfft);
    let n_lp = shr(nfft, 1) as usize;

    let mut l_tmp = l_deposit_l(0);
    for i in 0..n_lp {
        out.tfr[i] = extract_h(tfr32[i]); // Qin+exp-16
        out.tfi[i] = extract_h(tfi32[i]);
        out.tf_abs[i] = abs_iter(out.tfr[i], out.tfi[i], 5);
        l_tmp = l_mac0(l_tmp, out.tf_abs[i], 1);
    }
    *out.sum_tf_abs = l_tmp;
    *out.exp = sub(*out.exp, 16);
}

/// `singenerator_fx`: add `L` samples of the sinusoid with the complex amplitude `a_re + j a_im`
/// and per-sample rotation `cosfreq + j sinfreq` to `xx` (Q(in)+16), by the recursive oscillator.
pub fn singenerator(l: i16, cosfreq: i16, sinfreq: i16, a_re: i16, a_im: i16, xx: &mut [i32]) {
    let mut l_s0 = l_deposit_l(0); // prevent warning
    let mut l_c0 = l_deposit_h(a_re); // Qin+16
    let mut s0 = a_im;

    let mut ptr = 0usize;
    xx[ptr] = l_add(xx[ptr], l_c0);
    ptr += 1;

    for _ in 0..(i32::from(l) / 2 - 1).max(0) {
        let c0 = extract_h(l_c0); // Qin
        let mut l_c1 = l_mult(c0, cosfreq); // Qin+16
        l_c1 = l_msu(l_c1, s0, sinfreq);
        let l_s1 = l_mult(c0, sinfreq);
        let s1 = mac_r(l_s1, s0, cosfreq);
        xx[ptr] = l_add(xx[ptr], l_c1);
        ptr += 1;

        let c1 = extract_h(l_c1);
        l_c0 = l_mult(c1, cosfreq);
        l_c0 = l_msu(l_c0, s1, sinfreq);
        l_s0 = l_mult(c1, sinfreq);
        s0 = mac_r(l_s0, s1, cosfreq);
        xx[ptr] = l_add(xx[ptr], l_c0);
        ptr += 1;
    }

    let c0 = extract_h(l_c0);
    let s0 = extract_h(l_s0);
    let mut l_c1 = l_mult(c0, cosfreq);
    l_c1 = l_msu(l_c1, s0, sinfreq);
    xx[ptr] = l_add(xx[ptr], l_c1);
}

/// The index of the largest `tf_abs` among the pulse candidates (the first of equals, the
/// previous pick if none exceeds zero), as the reference's selection loop; returns
/// `(mmax, indmax)` with `indmax` carried over between calls.
fn strongest_pulse(tf_abs: &[i16], pulses: &[i16], nb_pulses: i16, mut indmax: i16) -> (i16, i16) {
    let mut mmax: i16 = 0;
    for &tmp in &pulses[..nb_pulses.max(0) as usize] {
        if sub(tf_abs[tmp as usize], mmax) > 0 {
            indmax = tmp;
        }
        mmax = tf_abs[tmp as usize].max(mmax);
    }
    (mmax, indmax)
}

/// The spectrum and its dimensions for [`sinusoidal_synthesis`].
pub struct SynthesisInput<'a> {
    pub tfr: &'a [i16],
    pub tfi: &'a [i16],
    pub n: i16,
    pub l: i16,
    pub decimate_factor: i16,
    pub nfft: i16,
    pub sum_tf_abs: i32,
    pub hq_voicing: i16,
    pub exp: i16,
}

/// `sinusoidal_synthesis_fx`: pick the strongest spectral peaks of the (`tf_abs`) magnitude
/// spectrum, up to 20 or 70 % of its sum, and synthesise `2L` samples of their sinusoids into
/// `synthesis` (which marks the picked bins `-1` in `tf_abs`).
pub fn sinusoidal_synthesis(input: &SynthesisInput<'_>, tf_abs: &mut [i16], synthesis: &mut [i16]) {
    let (tfr, tfi, n, l) = (input.tfr, input.tfi, input.n, input.l);
    let mut pulses = [0i16; FEC_MAX / 2];
    let mut freqi = [0i16; FEC_NB_PULSE_MAX];
    let mut a_re = [0i16; FEC_NB_PULSE_MAX];
    let mut a_im = [0i16; FEC_NB_PULSE_MAX];
    let mut synthesis_fx = [0i32; 2 * L_FRAME48K as usize];
    let mut indmax: i16 = 0;
    let lon20_10: i16 = 80;

    let mut flag = input.hq_voicing;
    if sub(n, lon20_10) > 0 {
        flag = 1; // flag corresponds to condition sub(N, Lon20_10)>0 || HqVoicing
    }

    let mut nb_pulses: i16 = 0;
    let mut pl: i16 = 0;
    let mut cpt: i16 = 0;
    let mut old: i16 = 0;
    let mut new_s = tf_abs[1];
    if flag != 0 {
        pl = 1;
    }
    let tmp = sub(shr(n, 1), 3);
    while sub(cpt, tmp) <= 0 {
        if sub(tf_abs[cpt as usize], old) > 0 && sub(tf_abs[cpt as usize], new_s) > 0 {
            // `glued` is only ever assigned in the reference, never read
            let tmp2 = add(add(cpt, pl), 1);
            for i in cpt..tmp2 {
                pulses[nb_pulses as usize] = i;
                nb_pulses += 1;
            }
            old = tf_abs[add(cpt, pl) as usize];
            new_s = tf_abs[add(add(cpt, 2), pl) as usize];
            cpt = add(add(cpt, pl), 1);
        } else {
            old = tf_abs[cpt as usize];
            new_s = tf_abs[add(cpt, 2) as usize];
            cpt += 1;
        }
    }

    let s_n = sub(13, norm_s(input.nfft)); // for amplitude normalization by 2/nfft
    let mut cumsum = l_deposit_l(0);
    let l_tmp = mult_32_16(input.sum_tf_abs, 22938);

    let mut maxi = (FEC_NB_PULSE_MAX as i16).min(nb_pulses);
    let mut nb_pulses_final = maxi;
    let len = shl(l, 1);
    let mut picked = 0usize;
    if input.hq_voicing != 0 {
        for _ in 0..maxi {
            let (_, index) = strongest_pulse(tf_abs, &pulses, nb_pulses, indmax);
            indmax = index;
            a_re[picked] = tfr[indmax as usize]; // scaling of a_re is Qin+sN
            a_im[picked] = tfi[indmax as usize];
            freqi[picked] = indmax;
            picked += 1;
            tf_abs[indmax as usize] = -1;
        }
    } else {
        loop {
            let (mmax, index) = strongest_pulse(tf_abs, &pulses, nb_pulses, indmax);
            indmax = index;
            cumsum = l_mac0(cumsum, mmax, 1);

            a_re[picked] = tfr[indmax as usize];
            a_im[picked] = tfi[indmax as usize];
            freqi[picked] = indmax;
            picked += 1;
            tf_abs[indmax as usize] = -1;

            maxi = sub(maxi, 1);
            if !(maxi > 0 && l_sub(cumsum, l_tmp) < 0) {
                break;
            }
        }
        nb_pulses_final = sub(nb_pulses_final, maxi);
    }

    // sinusoidal synthesis (`q = ceil(N/4)` of the reference is never used)
    synthesis_fx[..len as usize].fill(0);
    let exp = add(input.exp, s_n);
    let inv_den = i_mult2(n, input.decimate_factor); // Q0

    for i in 0..nb_pulses_final.max(0) as usize {
        let tmp = div_s(shl(freqi[i], 1), inv_den); // Q15: ind*2/(N*decim)
                                                    // Q30: ind*2/(N*decim)*pi/4*4, never greater than PI/2
        let freq = l_shl(l_mult(tmp, 25736), 1);
        let (cosfreq, sinfreq) = sin_cos_est(freq);
        singenerator(len, cosfreq, sinfreq, a_re[i], a_im[i], &mut synthesis_fx);
    }
    copy_scale_sig_32_16(&synthesis_fx, synthesis, len, negate(add(exp, 16))); // Qin
}

/// `fec_noise_filling_fx`: add the shaped residual noise (the difference between the previous
/// synthesis and the sinusoidal one, replayed with random segment lengths) to `synthesis`, make
/// `gapsynth` of the second frame and overlap-add the start with the previous synthesis.
pub fn fec_noise_filling(
    prevsynth: &[i16],
    synthesis: &mut [i16],
    ni_seed_forfec: &mut i16,
    l: i16,
    n: i16,
    hq_voicing: i16,
    gapsynth: &mut [i16],
) {
    let mut noisevect = [0i16; 34 * L_FRAME48K as usize / 20];
    let mut ss = [0i16; L_FRAME48K as usize / 2];

    let sinq_tab: &[i16] = if sub(l, L_FRAME32K) == 0 {
        &SINQ_32K
    } else if sub(l, L_FRAME48K) == 0 {
        &SINQ_48K
    } else {
        &SINQ_16K
    };

    let l20 = extract_h(l_mult(1639, l)); // L/20

    // N = 47*L/20 - delay_ind*decimatefactor - 6*L/20
    let tmp_fx = sub(sub(shl(l, 1), i_mult2(3, l20)), n);
    noisevect[..n as usize].copy_from_slice(&prevsynth[tmp_fx as usize..(tmp_fx + n) as usize]);

    // Noise addition on full band: residual
    let tmp_fx = n.min(l);
    let n_noise = shr(tmp_fx, 1);
    let ind = sub(n, tmp_fx) as usize;
    for k in 0..tmp_fx.max(0) as usize {
        noisevect[k] = sub(noisevect[ind + k], synthesis[ind + k]);
    }

    if hq_voicing != 0 {
        scale_sig(&mut noisevect, n, -2);
    }

    let mut kk: i16 = 0;
    let mut flag = shl(l, 1);
    let mut p5 = 0usize;
    while flag > 0 {
        let tmp_fx = random(ni_seed_forfec);

        let mut l_tmp = crate::itu::basic_ops::l_mac(1_503_264_768, tmp_fx, 9830);
        if kk == 0 {
            l_tmp = crate::itu::basic_ops::l_mac(1_073_741_824, tmp_fx, 6554);
        }
        kk = sub(1, kk);
        let tmp_fx = round_word(l_tmp);
        let rnd_n_noise = extract_h(l_mult(n_noise, tmp_fx)); // Q0

        let tmp_fx = div_s(1, rnd_n_noise); // Q15
        let tmp_fx = round_word(l_shl(l_mult(tmp_fx, 25736), 2)); // Q15

        sinq(shr(tmp_fx, 1), shr(tmp_fx, 2), rnd_n_noise, &mut ss);

        let pt2 = n_noise as usize;
        let pt1 = pt2 - rnd_n_noise as usize;
        let tmp_fx = rnd_n_noise.min(flag);
        for i in 0..tmp_fx.max(0) as usize {
            let mut l_tmp = l_mult(noisevect[pt1 + i], ss[i]); // Qsynth+16
            l_tmp = crate::itu::basic_ops::l_mac(
                l_tmp,
                noisevect[pt2 + i],
                ss[rnd_n_noise as usize - 1 - i],
            );
            synthesis[p5] = add(synthesis[p5], round_word(l_tmp)); // Qsynth
            p5 += 1;
        }
        flag = sub(flag, tmp_fx);
    }

    let q1 = i_mult2(7, l20) as usize;
    let q2 = i_mult2(33, l20) as usize;

    synthesis.copy_within(0..q2, q1);
    gapsynth[..l as usize].copy_from_slice(&synthesis[l as usize..2 * l as usize]);
    let from = (i_mult2(37, l20) as usize) - q1;
    synthesis[..q1].copy_from_slice(&prevsynth[from..from + q1]);
    let pt1_start = q1;
    let pt6_start = i_mult2(37, l20) as usize;
    let tmp_fx = i_mult2(3, l20);

    // overlap-add with the ms of valid mdct of the last frame
    for (offset, &sinq_value) in sinq_tab[..tmp_fx as usize].iter().enumerate() {
        let (pt1, pt6) = (pt1_start + offset, pt6_start + offset);
        let l_tmp = l_mult(sinq_value, sinq_value); // Q30
        let q2 = round_word(l_sub(2_147_483_647, l_tmp)); // Q15
        let q1 = round_word(l_tmp); // Q15
        let mut l_tmp = l_mult(synthesis[pt1], q1); // Qsynth+16
        l_tmp = crate::itu::basic_ops::l_mac(l_tmp, prevsynth[pt6], q2);
        synthesis[pt1] = round_word(l_tmp); // Qsynth
    }
}

/// `fec_alg_fx`: the pitch-dependent concealment of a lost frame: a sinusoidal model of the
/// last pitch cycle plus noise filling, windowed into `ecu_rec`; `gapsynth` is the synthesis of
/// the following frame.
pub fn fec_alg(
    prevsynth: &[i16],
    prevsynth_lp: &[i16],
    ni_seed_forfec: &mut i16,
    ecu_rec: &mut [i32],
    output_frame: i16,
    n: i16,
    decimatefactor: i16,
    hq_voicing: i16,
    gapsynth: &mut [i16],
) {
    let mut tfr = [0i16; FEC_FFT_MAX_SIZE];
    let mut tfi = [0i16; FEC_FFT_MAX_SIZE];
    let mut tf_abs = [0i16; FEC_FFT_MAX_SIZE / 2];
    let mut synthesis = [0i16; 2 * L_FRAME48K as usize];
    let mut nfft: i16 = 0;
    let mut sum_tf_abs: i32 = 0;
    let mut exp: i16 = 0;

    fec_ecu_dft(
        prevsynth_lp,
        n,
        &mut DftOut {
            tfr: &mut tfr,
            tfi: &mut tfi,
            sum_tf_abs: &mut sum_tf_abs,
            tf_abs: &mut tf_abs,
            nfft: &mut nfft,
            exp: &mut exp,
        },
    );

    sinusoidal_synthesis(
        &SynthesisInput {
            tfr: &tfr,
            tfi: &tfi,
            n,
            l: output_frame,
            decimate_factor: decimatefactor,
            nfft,
            sum_tf_abs,
            hq_voicing,
            exp,
        },
        &mut tf_abs,
        &mut synthesis,
    );

    fec_noise_filling(
        prevsynth,
        &mut synthesis,
        ni_seed_forfec,
        output_frame,
        i_mult2(n, decimatefactor),
        hq_voicing,
        gapsynth,
    );

    let mut n = R1_48 - R2_48;
    if sub(output_frame, L_FRAME32K) == 0 || sub(output_frame, L_FRAME16K) == 0 {
        n = R1_16 - R2_16;
        if sub(output_frame, L_FRAME32K) == 0 {
            n = 2 * N16_CORE_SW;
        }
    }
    let mut q: i16 = 0;
    let mut q_old_wtda: i16 = 0;
    wtda(
        &mut synthesis,
        sub(output_frame, n) as usize,
        &mut q,
        ecu_rec,
        None,
        &mut q_old_wtda,
        ALDO_WINDOW,
        ALDO_WINDOW,
        output_frame,
    ); // returns Q15
}
