//! Spectral and transient analysis of the HQ phase ECU (TS 26.442 `lib_dec/FEC_HQ_phase_ecu_fx.c`):
//! `rand_phase_fx`, `fft_spec2_fx`, `trans_ana_fx`, `peakfinder_fx`, `imax_fx`, `spec_ana_fx` and
//! the windowing helpers.

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    BETA_MUTE_FAC_INI, LGW_MAX, LPROT32K, LPROT_HAMM_LEN2_16K, LPROT_HAMM_LEN2_32K,
    LPROT_HAMM_LEN2_48K, LTRANA48K, L_FRAME32K, L_FRAME48K, OFF_FRAMES_LIMIT, QUOT_LPR_LTR,
};
use crate::evs::com::fft_fx::fft3 as fft3_fx;
use crate::evs::com::fft_rel::r_fft_fx_lc_in_place;
use crate::evs::com::math_op::sqrt_l;
use crate::evs::com::tools::{
    copy_scale_sig, exp16_array, maximum, minimum, own_random2, ratio, set16, vr_subt,
};
use crate::evs::rom::{
    FFT_W128, FFT_W256, FFT_W512, FFT_W64, GR_POW_HEADROOM, GW_FX, GW_LEN_INV_FX,
    INNER_FRAME_TBL_FX, POW_ATT_TABLE0, POW_ATT_TABLE1, SINCOS_T_EXT_FX, SINCOS_T_RAD3_FX,
    W_HAMM16K_2_FX, W_HAMM32K_2_FX, W_HAMM48K_2_FX, W_HAMM_SANA48K_2_FX,
};
use crate::itu::basic_ops::{
    add, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_shl, l_shr, l_sub,
    mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0, mac_r, mpy_32_16_ss, msu_r};

/// `FEC_HQ_ECU_POINT5`: 0.5 in Q15.
const FEC_HQ_ECU_POINT5: i16 = 0x4000;
/// `FEC_HQ_ECU_ROOT2`: sqrt(2) in Q14.
pub const FEC_HQ_ECU_ROOT2: i16 = 0x5a83;
/// `FEC_HQ_HAMM_A0`: 0.54 in Q15.
const FEC_HQ_WIN_A0: i16 = 17695;
/// `FEC_HQ_HAMM_A1`: 0.46 in Q15.
const FEC_HQ_WIN_A1: i16 = 15073;
const THRESH_TR_LIN_BY2_FX: i16 = 10 / 2;
const BURST_PHDITH_THRESH: i16 = 4 - 1;
const BURST_ATT_THRESH: i16 = 3 - 1;
const ATT_PER_FRAME: i16 = 4;
const BURST_PHDITH_RAMPUP_LEN: i16 = 2;
const BETA_MUTE_THR: i16 = 10;
const LGW32K: i16 = 7;
const LGW16K: i16 = 6;
const LGW48K: i16 = LGW32K + 1;
const LTRANALOG32K: i16 = 8;
const LTRANALOG16K: i16 = 7;
/// `(1.0 - pfind_sen)` in Q15.
const CMPLMNT_PFIND_SENS_FX: i16 = 983;
/// `Lprot48k` = `Lprot32k * 3/2`.
pub const LPROT48K: usize = 1536;
const LPROT48K_2: usize = LPROT48K / 2;
/// `MAX_PLOCS` = `Lprot48k/4+1`.
pub const MAX_PLOCS: usize = LPROT48K / 4 + 1;
/// `T_SIN_PI_2` = `PH_ECU_SPEC_SIZE/4`.
const T_SIN_PI_2: i16 = 384;
const LTRANA48K_US: usize = LTRANA48K as usize;

/// `rand_phase_fx`: a randomised phase as sine and cosine components; returns the new seed.
pub fn rand_phase(seed: i16, sin_f: &mut i16, cos_f: &mut i16) -> i16 {
    let seed2 = own_random2(seed);
    let seed2_shift = shr(seed2, 8);
    // sincos = sincos_t_ext_fx + 128; the shift is in -128..=127, so both indices stay in the table
    let at = |offset: i16| SINCOS_T_EXT_FX[(128 + i32::from(offset)) as usize];

    *sin_f = negate(at(seed2_shift));
    if (seed2 & 0x40) != 0 {
        *sin_f = at(seed2_shift);
    }
    *cos_f = negate(at(negate(seed2_shift)));
    if (seed2 & 0x80) != 0 {
        *cos_f = at(negate(seed2_shift));
    }
    seed2
}

/// `fft_spec2_fx`: squared magnitude of the FFT spectrum `x` (real parts in `x[0..=n/2]`, the
/// imaginary parts mirrored in `x[n/2+1..n]`).
pub fn fft_spec2(x: &[i16], x_mag_sq: &mut [i32], n: i16) {
    // Magnitude at 0. Non-fractional multiply gives the subsequent group power accumulation a bit
    // of headroom.
    x_mag_sq[0] = l_mult0(x[0], x[0]);
    let mut p_re = 1usize;
    let mut p_im = n as usize - 1;
    let l = sub(shr(n, 1), 1);
    for i in 0..l.max(0) as usize {
        let acc = l_mult0(x[p_re], x[p_re]);
        p_re += 1;
        x_mag_sq[1 + i] = l_mac0(acc, x[p_im], x[p_im]);
        p_im = p_im.wrapping_sub(1);
    }
    // The magnitude square at N/2
    x_mag_sq[1 + l.max(0) as usize] = l_mult0(x[p_re], x[p_re]);
}

/// `sqrt2ndOrder`: sqrt(x) for a normalised `0.5 <= x < 1` (Q15), 2nd order least-squares
/// approximation.
pub fn sqrt2nd_order(x: i16) -> i16 {
    let acc = 1_890_205_600;
    let z = mac_r(acc, x, -6506);
    let acc = 682_030_261;
    mac_r(acc, z, x)
}

/// `windowing`: a symmetric Hamming (`rect_length == 0`) or Hamming-rectangular window; `x` and
/// `y` may be the same buffer (the reference calls it in place), so the input is copied first.
pub fn windowing(x: &[i16], y: &mut [i16], win: &[i16], rect_length: i16, half_length: i16) {
    let half = half_length.max(0) as usize;
    let rect = rect_length.max(0) as usize;
    for i in 0..half {
        y[i] = mult_r(x[i], win[i]);
    }
    y[half..half + rect].copy_from_slice(&x[half..half + rect]);
    for i in 0..half {
        y[half + rect + i] = mult_r(x[half + rect + i], win[half - 1 - i]);
    }
}

/// [`windowing`] in place (`x == y` in the reference).
pub fn windowing_in_place(x: &mut [i16], win: &[i16], rect_length: i16, half_length: i16) {
    let half = half_length.max(0) as usize;
    let rect = rect_length.max(0) as usize;
    for i in 0..half {
        x[i] = mult_r(x[i], win[i]);
    }
    for i in 0..half {
        x[half + rect + i] = mult_r(x[half + rect + i], win[half - 1 - i]);
    }
}

/// `windowing_ROM_optimized`: Hamming-rectangular window whose Hamming coefficients come from the
/// sine table shared with `fft3_fx`, in place.
pub fn windowing_rom_optimized(
    x: &mut [i16],
    down_samples: i16,
    rect_length: i16,
    half_length: i16,
) {
    let quarter_len = shr(half_length, 1);
    let init_offset = add(T_SIN_PI_2, shr(down_samples, 1));
    let step = i32::from(down_samples);
    let mut p_sine = i32::from(init_offset);
    let sine = |index: i32| SINCOS_T_RAD3_FX[index as usize];
    let mut p = 0usize;

    // 1st half of the left half of the Hamming window.
    for _ in 0..quarter_len.max(0) {
        p_sine -= step;
        let acc = l_deposit_h(FEC_HQ_WIN_A0);
        let hamm = msu_r(acc, sine(p_sine), FEC_HQ_WIN_A1);
        x[p] = mult_r(hamm, x[p]);
        p += 1;
    }
    // 2nd half of the left half of the Hamming window.
    for _ in 0..quarter_len.max(0) {
        let acc = l_deposit_h(FEC_HQ_WIN_A0);
        let hamm = mac_r(acc, sine(p_sine), FEC_HQ_WIN_A1);
        x[p] = mult_r(hamm, x[p]);
        p += 1;
        p_sine += step;
    }
    // The rectangular flat region
    p += rect_length.max(0) as usize;
    // 1st half of the right half of the Hamming window.
    for _ in 0..quarter_len.max(0) {
        p_sine -= step;
        let acc = l_deposit_h(FEC_HQ_WIN_A0);
        let hamm = mac_r(acc, sine(p_sine), FEC_HQ_WIN_A1);
        x[p] = mult_r(hamm, x[p]);
        p += 1;
    }
    // 2nd half of the right half of the Hamming window.
    for _ in 0..quarter_len.max(0) {
        let acc = l_deposit_h(FEC_HQ_WIN_A0);
        let hamm = msu_r(acc, sine(p_sine), FEC_HQ_WIN_A1);
        x[p] = mult_r(hamm, x[p]);
        p += 1;
        p_sine += step;
    }
}

/// `trans_ana_fx` inputs that are not per-band output vectors.
pub struct TransAnaParams {
    pub output_frame: i16,
    pub time_offs: i16,
    pub est_mus_content: i16,
    pub last_fec: i16,
}

/// The per-band outputs of [`trans_ana`].
pub struct TransAnaOut<'a> {
    pub mag_chg: &'a mut [i16],
    pub ph_dith: &'a mut i16,
    pub mag_chg_1st: &'a mut [i16],
    pub alpha: &'a mut [i16],
    pub beta: &'a mut [i16],
    pub beta_mute: &'a mut i16,
    pub xavg: &'a mut [i16],
}

/// `trans_ana_fx`: transient analysis of the signal around the loss, giving the per-band magnitude
/// modification, the phase dither and the fade-to-average factors.
pub fn trans_ana(xfp: &[i16], params: &TransAnaParams, out: &mut TransAnaOut<'_>) {
    let output_frame = params.output_frame;
    let est_mus_content = params.est_mus_content;
    let last_fec = params.last_fec;
    let mut xfp_left = [0i16; LTRANA48K_US];
    let mut xfp_right = [0i16; LTRANA48K_US];
    let mut mag_sq_left = [0i32; LTRANA48K_US / 2 + 1];
    let mut mag_sq_right = [0i32; LTRANA48K_US / 2 + 1];
    let mut gr_pow_left = [0i32; LGW_MAX as usize];
    let mut gr_pow_right = [0i32; LGW_MAX as usize];
    let mut tr_dec = [0i16; LGW_MAX as usize];
    let mut att_always: i16 = 0;
    let lgw: i16;
    let mut ltrana_log_minus1: i16 = 0;
    let mut p_fft_tbl: &[i16] = &[];

    let one_over_frame: i16;
    let w_hamm: &[i16];
    let lprot: i16;
    if sub(output_frame, L_FRAME48K) == 0 {
        one_over_frame = 34; // 1/960 in Q15
        w_hamm = &W_HAMM48K_2_FX;
        lgw = LGW48K;
        lprot = 1536; // (2*output_frame)*1024/1280
    } else if sub(output_frame, L_FRAME32K) == 0 {
        one_over_frame = 51; // 1/640 in Q15
        w_hamm = &W_HAMM32K_2_FX;
        lgw = LGW32K;
        lprot = 1024;
        p_fft_tbl = &FFT_W128; // Table for 256 real input radix-2 FFT
        ltrana_log_minus1 = LTRANALOG32K - 1;
    } else {
        one_over_frame = 102; // 1/320 in Q15
        w_hamm = &W_HAMM16K_2_FX;
        lgw = LGW16K;
        lprot = 512;
        p_fft_tbl = &FFT_W64; // Table for 128 real input radix-2 FFT
        ltrana_log_minus1 = LTRANALOG16K - 1;
    }
    let burst_len = add(mult_r(params.time_offs, one_over_frame), 1);

    *out.ph_dith = 0; // typical pattern is 2*pi*[0  0 .25 .50 .75 1.0 1.0 1.0 ..]

    let burst_phdith_thresh: i16;
    let burst_att_thresh: i16;
    let att_per_frame: i16;
    if sub(output_frame, L_FRAME32K) >= 0 {
        // currently est_mus_content only calculated for SWB and FB
        let mut round_est_mus_content = 0;
        if sub(est_mus_content, FEC_HQ_ECU_POINT5) >= 0 {
            round_est_mus_content = 1;
        }
        // softly shift attenuation just a bit later for estimated "stable" music_content
        burst_phdith_thresh = add(BURST_PHDITH_THRESH, round_est_mus_content);
        burst_att_thresh = add(BURST_ATT_THRESH, round_est_mus_content);
        att_per_frame = sub(ATT_PER_FRAME, round_est_mus_content);
    } else {
        // lock to music-like stable envelope setting for now
        burst_phdith_thresh = add(BURST_PHDITH_THRESH, 1);
        burst_att_thresh = add(BURST_ATT_THRESH, 1);
        att_per_frame = sub(ATT_PER_FRAME, 1);
    }

    if sub(burst_len, burst_phdith_thresh) > 0 {
        // increase degree of dither; phase_dith = min(1.0, (burst_len - thresh)/rampup_len) with
        // the ramp-up length fixed at 2
        *out.ph_dith = 32767; // 1.0 in Q15 (2*PI is not included)
        let tmp16 = sub(burst_len, burst_phdith_thresh);
        if sub(tmp16, BURST_PHDITH_RAMPUP_LEN) < 0 {
            *out.ph_dith = 16384;
        }
    }

    let mut att_degree_frames: i16 = 0;
    if sub(burst_len, burst_att_thresh) > 0 {
        att_always = 1;
        // (burst_len - burst_att_thresh) is NOT multiplied by att_per_frame so that the
        // 10^(-att_degree/20) lookup is a direct table access; hard limited to OFF_FRAMES_LIMIT
        att_degree_frames = sub(burst_len, burst_att_thresh);
        if sub(att_degree_frames, OFF_FRAMES_LIMIT) > 0 {
            att_degree_frames = OFF_FRAMES_LIMIT;
        }
    }

    let ltrana = shr(lprot, 2);
    let ltrana_2 = shr(ltrana, 1);

    let first_burst_frames = sub(burst_len, 1) <= 0 || (sub(burst_len, 2) == 0 && last_fec != 0);
    if first_burst_frames {
        set16(out.alpha, 32767, LGW_MAX);
        set16(out.beta, 0, LGW_MAX);
        *out.beta_mute = BETA_MUTE_FAC_INI;

        // Apply Hamming window
        windowing(xfp, &mut xfp_left, w_hamm, 0, ltrana_2); // 1st quarter
        let three4th_length = sub(lprot, ltrana) as usize;
        windowing(&xfp[three4th_length..], &mut xfp_right, w_hamm, 0, ltrana_2); // 4th quarter

        // spectrum
        if sub(output_frame, L_FRAME48K) == 0 {
            fft3_fx(&mut xfp_left, ltrana);
            fft3_fx(&mut xfp_right, ltrana);
        } else {
            r_fft_fx_lc_in_place(
                p_fft_tbl,
                ltrana,
                ltrana_2,
                ltrana_log_minus1,
                &mut xfp_left,
                1,
            );
            r_fft_fx_lc_in_place(
                p_fft_tbl,
                ltrana,
                ltrana_2,
                ltrana_log_minus1,
                &mut xfp_right,
                1,
            );
        }

        // square representation
        fft_spec2(&xfp_left, &mut mag_sq_left, ltrana);
        fft_spec2(&xfp_right, &mut mag_sq_right, ltrana);

        // band powers in frequency groups; exclude bin at PI from calculation
        mag_sq_left[ltrana_2 as usize] = l_deposit_l(0);
        mag_sq_right[ltrana_2 as usize] = l_deposit_l(0);
    }

    let mut p_gw = 0usize;
    for k in 0..lgw.max(0) as usize {
        if first_burst_frames {
            let lower_edge = GW_FX[p_gw];
            p_gw += 1;
            let l = sub(GW_FX[p_gw], lower_edge);
            let headroom = GR_POW_HEADROOM[k]; // bits to scale down to prevent saturation
            let lower = lower_edge as usize;
            gr_pow_left[k] = l_deposit_l(0);
            gr_pow_right[k] = l_deposit_l(0);
            for i in 0..l.max(0) as usize {
                let acc = l_shr(mag_sq_left[lower + i], headroom);
                gr_pow_left[k] = l_add(gr_pow_left[k], acc);
                let acc = l_shr(mag_sq_right[lower + i], headroom);
                gr_pow_right[k] = l_add(gr_pow_right[k], acc);
            }

            // Xavg[k] = sqrt(0.5f*(gr_pow_left[k]+gr_pow_right[k])/(float)(gw[k+1]-gw[k]));
            let mut acc = l_shr(l_add(gr_pow_left[k], gr_pow_right[k]), 1);
            acc = mult_32_16(acc, GW_LEN_INV_FX[k]); // -headroom

            let mut expo: i16 = 0;
            acc = sqrt_l(acc, &mut expo); // -headroom+31+expo

            expo = sub(add(expo, 31), headroom);
            if sub(expo & 1, 1) == 0 {
                acc = mult_32_16(acc, 23170); // 1/sqrt(2) in Q15
            }
            expo = shr(expo, 1);
            // Q0, additional right shift by 2 to account for that Xavg is calculated using length
            // N/4 fft but is applied on a fft of length N
            out.xavg[k] = round_word(l_shl(acc, sub(sub(16, expo), 2)));

            // dither phase in case of transient: separate transition detection and application of
            // forced burst dithering
            tr_dec[k] = 0;
            // to facilitate fixed-point implementation, the threshold is divided by 2
            let (hi, lsb) = mpy_32_16_ss(gr_pow_left[k], THRESH_TR_LIN_BY2_FX);
            let acc = l_shl(hi, 16) | (0xffff & i32::from(lsb));
            if l_sub(gr_pow_right[k], acc) > 0 {
                // gr_pow_right > thres_tr_lin*gr_pow_left
                tr_dec[k] = 1;
            }
            let (hi, lsb) = mpy_32_16_ss(gr_pow_right[k], THRESH_TR_LIN_BY2_FX);
            let acc = l_shl(hi, 16) | (0xffff & i32::from(lsb));
            if l_sub(gr_pow_left[k], acc) > 0 {
                // gr_pow_left > thres_tr_lin*gr_pow_right
                tr_dec[k] = 1;
            }

            // magnitude modification
            if add(tr_dec[k], att_always) != 0 {
                // MAX_INCREASE_GRPPOW_FX is 0: the power may not increase
                let mut att_val: i16 = 32767;
                if l_sub(gr_pow_right[k], 0) > 0 && l_sub(gr_pow_right[k], gr_pow_left[k]) < 0 {
                    // (gr_pow_right/gr_pow_left) < 1.0: sqrt(grp_pow_chg)
                    let mut expo: i16 = 0;
                    let tmp16 = ratio(gr_pow_right[k], gr_pow_left[k], &mut expo); // Q14
                    expo = sub(expo, 15 - 14); // now tmp16 is considered in Q15
                    let i = norm_s(tmp16);
                    let mut man = shl(tmp16, i); // mandatory normalisation before the root
                    expo = add(expo, i);
                    man = sqrt2nd_order(man);
                    if (expo & 1) != 0 {
                        man = mult_r(man, FEC_HQ_ECU_ROOT2);
                    }
                    expo = shr(expo, 1); // divided by 2: square root operation
                    att_val = shr(man, expo); // denormalise the mantissa back to Q15
                }
                // else (gr_pow_right/gr_pow_left) >= 1.0, i.e. max_increase_grppow_lin

                out.mag_chg_1st[k] = att_val;
                out.mag_chg[k] = att_val;
            } else {
                out.mag_chg_1st[k] = 32767;
                out.mag_chg[k] = 32767; // 1.0 in Q15
            }
        } else {
            // 10^(-att_degree/20) by direct table lookup; att_per_frame is ATT_PER_FRAME or
            // ATT_PER_FRAME-1, one table for each
            let att_val = if sub(att_per_frame, ATT_PER_FRAME) == 0 {
                POW_ATT_TABLE0[att_degree_frames as usize]
            } else {
                POW_ATT_TABLE1[att_degree_frames as usize]
            };
            out.mag_chg[k] = mult_r(out.mag_chg_1st[k], att_val); // Q15

            if sub(burst_len, BETA_MUTE_THR) > 0 {
                *out.beta_mute = shr(*out.beta_mute, 1);
            }
            out.alpha[k] = out.mag_chg[k];
            // beta[k] = sqrt(1.0f - SQR(alpha[k])) * *beta_mute;
            let mut acc = l_sub(1_073_741_824, l_mult0(out.alpha[k], out.alpha[k]));
            let mut expo: i16 = 0;
            acc = sqrt_l(acc, &mut expo);
            expo = add(30, add(31, expo));
            if sub(expo & 1, 1) == 0 {
                acc = mult_32_16(acc, 23170); // 1/sqrt(2) in Q15
            }
            expo = shr(expo, 1);
            out.beta[k] = mult_r(*out.beta_mute, round_word(l_shl(acc, sub(31, expo))));

            if sub(k as i16, LGW32K - 1) >= 0 {
                out.beta[k] = mult_r(out.beta[k], 3277); // 0.1 in Q15
            } else if sub(k as i16, LGW16K - 1) >= 0 {
                out.beta[k] = mult_r(out.beta[k], 16384); // 0.5 in Q15
            }
        }
    }
}

/// `peakfinder_fx`: peak-picking; the indices of the peaks of `x0[0..len0]` that rise at least
/// `sel` above their surroundings go to `plocs`, their number to `c_ind`.
pub fn peakfinder(x0: &[i16], len0: i16, plocs: &mut [i16], c_ind: &mut i16, sel: i16) {
    let mut dx0 = [0i16; LPROT48K_2];
    let mut x = [0i16; LPROT48K_2 + 1];
    let mut indarr = [0i16; LPROT48K_2 + 1];
    let mut peak_loc = [0i16; MAX_PLOCS];
    let mut temp_loc: i16 = 0;

    // Find derivative
    let len0_minus1 = sub(len0, 1);
    vr_subt(&x0[1..], x0, &mut dx0, len0_minus1);
    for value in dx0.iter_mut().take(len0_minus1.max(0) as usize) {
        if *value == 0 {
            *value = -1;
        }
    }

    // Find where the derivative changes sign; include endpoints in potential peaks and valleys
    let mut p_x = 0usize;
    let mut p_ind = 0usize;
    x[p_x] = x0[0];
    p_x += 1;
    indarr[p_ind] = 0;
    p_ind += 1;
    let mut len: i16 = 2;
    let len0_minus2 = sub(len0, 2);
    for i in 0..len0_minus2.max(0) {
        let iu = i as usize;
        if (dx0[iu] ^ dx0[iu + 1]) < 0 {
            // Detect sign change.
            indarr[p_ind] = add(i, 1);
            p_ind += 1;
            x[p_x] = x0[iu + 1];
            p_x += 1;
            len = add(len, 1);
        }
    }
    indarr[p_ind] = len0_minus1;
    x[p_x] = x0[len0_minus1.max(0) as usize];

    // x[] only has the peaks, valleys, and endpoints
    let mut min_mag: i16 = 0;
    let _ = minimum(&x, len, &mut min_mag);

    if sub(len, 2) > 0 {
        // Set initial parameters for loop
        let mut temp_mag = min_mag;
        let mut found_peak: i16 = 0;
        let mut left_min = min_mag;
        let mut threshold = add(left_min, sel);

        // Deal with the first point a little differently since it was tacked on: the sign of the
        // derivative does not necessarily alternate like the rest.
        let x_at0 = x[0];
        let x_at1 = x[1];
        let x_at2 = x[2];
        let mut ii: i16;
        // p_x tracks the reference's pointer, which may sit at x[-1] before the loop
        let mut p_x: isize = 1;
        if sub(x_at0, x_at1) >= 0 {
            // The first point is larger or equal to the second
            ii = -1;
            if sub(x_at1, x_at2) >= 0 {
                // x[1] is not an extremum -> overwrite with x[0]
                x[1] = x_at0;
                indarr[1] = indarr[0];
                len = sub(len, 1);
            }
            p_x -= 1; // x[0]
        } else {
            // First point is smaller than the second
            ii = 0;
            if sub(x_at1, x_at2) < 0 {
                // x[1] is not an extremum -> overwrite with x[0]
                x[1] = x_at0;
                indarr[1] = indarr[0];
                len = sub(len, 1);
            }
        }
        p_x -= 1; // x[-1] or x[0]

        *c_ind = 0;
        // Loop through extrema which should be peaks and then valleys
        let len_minus1 = sub(len, 1);
        loop {
            ii = add(ii, 1); // This is a peak

            // Make sure we don't iterate past the length of our vector
            if sub(ii, len_minus1) >= 0 {
                break;
            }

            // Reset peak finding if we had a peak and the next peak is bigger than the last or
            // the left min was small enough to reset.
            if sub(found_peak, 0) > 0 {
                temp_mag = min_mag;
                found_peak = 0;
            }

            // Found new peak that was larger than temp mag and selectivity larger than the
            // minimum to its left.
            p_x += 1;
            if sub(x[p_x as usize], temp_mag) > 0 && sub(x[p_x as usize], threshold) > 0 {
                // threshold = leftMin + sel
                temp_loc = ii;
                temp_mag = x[p_x as usize];
            }

            ii = add(ii, 1); // Move onto the valley
            p_x += 1;

            // Come down at least sel from peak
            if found_peak == 0 && sub(temp_mag, add(sel, x[p_x as usize])) > 0 {
                found_peak = 1; // We have found a peak
                left_min = x[p_x as usize];
                threshold = add(left_min, sel);
                let c = *c_ind as usize;
                if c < MAX_PLOCS {
                    peak_loc[c] = temp_loc; // Add peak to index
                }
                *c_ind = add(*c_ind, 1);
            }
            if found_peak == 0 && sub(x[p_x as usize], left_min) < 0 {
                // The above IF-block has not found the peak yet: new left minimum
                left_min = x[p_x as usize];
                threshold = add(left_min, sel);
            }
        }

        // Check end point
        let last = x[len_minus1.max(0) as usize];
        if sub(last, temp_mag) > 0 && sub(last, threshold) > 0 {
            // threshold = leftMin + sel
            let c = *c_ind as usize;
            if c < MAX_PLOCS {
                peak_loc[c] = len_minus1;
            }
            *c_ind = add(*c_ind, 1);
            found_peak = 1;
        }
        if found_peak == 0 && sub(temp_mag, min_mag) > 0 {
            // Check if we still need to add the last point
            let c = *c_ind as usize;
            if c < MAX_PLOCS {
                peak_loc[c] = temp_loc;
            }
            *c_ind = add(*c_ind, 1);
        }

        // Create output
        for i in 0..(*c_ind).max(0) as usize {
            plocs[i] = indarr[peak_loc[i] as usize];
        }
    } else {
        // This is a monotone function where an endpoint is the only peak
        let mut x_ind = 1usize;
        if sub(x[0], x[1]) > 0 {
            x_ind = 0;
        }
        // (peakMag[] is otherwise write-only in the reference)
        let peak_mag = x[x_ind];
        if sub(peak_mag, add(min_mag, sel)) > 0 {
            plocs[0] = indarr[x_ind];
            *c_ind = 1;
        } else {
            *c_ind = 0;
        }
    }
}

/// `imax_fx`: the interpolated position (Q15, relative to the middle of the 3 points `y`) of the
/// maximum of the parabola through them; `special` is -1 / 0 / +1 for the left edge / normal /
/// right edge case.
pub fn imax(y: &[i16], special: i16) -> i16 {
    let (y1, y2, y3) = (y[0], y[1], y[2]);

    // The extremum location: posi = (y3 - y1)/(4*y2 - 2*y1 - 2*y3), computed as follows (y2 is
    // multiplied by 2 only, y1 and y3 not at all, so the ratio is in Q15).
    let y3_y1 = l_sub(i32::from(y3), i32::from(y1));
    let mut acc = l_shl(i32::from(y2), 1);
    acc = l_sub(acc, i32::from(y1));
    let mut denom = l_sub(acc, i32::from(y3));
    let sign = y3_y1 ^ denom; // preserve the sign since div_s() only takes positive arguments
    let numer = l_abs(y3_y1);
    denom = l_abs(denom);
    if numer == 0 {
        return 0;
    }
    if denom == 0 {
        return 0;
    }
    let mut expo: i16 = 0;
    let man = ratio(numer, denom, &mut expo); // the mantissa is considered in Q15
    let mut posi = shr(man, expo); // in Q15, automatically bound inside [-1.0, 1.0]

    if sign < 0 {
        posi = negate(posi); // restore the sign
    }

    // For both edges the extremum found above may be a minimum, which must be rejected.
    if sub(special, 0) != 0 {
        let mut edge: i16 = 0x7fff; // 1 in Q15 for the right edge special case
        if sub(special, 0) < 0 {
            edge = 0; // left edge special case
        }
        // The slope of the interpolating parabola at y=0 is B = (y3 - y1)/2: it tells whether the
        // parabola is concave upward or downward.
        if sub(posi, 0) > 0 {
            // between the middle and the right given data points
            if sub(y3, y1) <= 0 {
                posi = edge; // minimum case
            } else {
                posi = sub(0x7fff, posi); // maximum case
            }
        } else if sub(y3, y1) >= 0 {
            // between the left and the middle given data points
            posi = edge; // minimum case
        } else {
            posi = add(0x7fff, posi); // maximum case
        }
    }
    posi
}

/// The outputs of [`spec_ana`].
pub struct SpecAnaOut<'a> {
    pub plocs: &'a mut [i16],
    pub plocsi: &'a mut [i32],
    pub num_plocs: &'a mut i16,
    pub x_sav: &'a mut [i16],
    pub q: &'a mut i16,
}

/// `spec_ana_fx`: spectral analysis of the previous synthesis: peaks of its magnitude spectrum
/// and their interpolated positions (Q16), and the stored spectrum.
pub fn spec_ana(prevsynth: &[i16], output_frame: i16, bwidth_fx: i16, out: &mut SpecAnaOut<'_>) {
    let mut xfp = [0i16; LPROT48K];
    let mut mag_sq = [0i32; LPROT48K / 2 + 1];
    let mut lprot_log2_minus1: i16 = 0;
    let hamm_len2: i16;
    let sin_tbl_offset: i16;
    let lprot: i16;
    let mut p_fft_tbl: &[i16] = &[];

    if sub(output_frame, L_FRAME48K) == 0 {
        lprot = LPROT48K as i16; // 1536 = (2*output_frame)*1024/1280
        sin_tbl_offset = 0;
        hamm_len2 = LPROT_HAMM_LEN2_48K as i16; // half Hamming window = 288
    } else if sub(output_frame, L_FRAME32K) == 0 {
        lprot = LPROT32K; // 1024
        sin_tbl_offset = 4;
        hamm_len2 = LPROT_HAMM_LEN2_32K as i16; // 192
        p_fft_tbl = &FFT_W512; // Table for 1024-point real input FFT
        lprot_log2_minus1 = 9; // FFT stages for complex input FFT
    } else {
        lprot = 512;
        sin_tbl_offset = 8;
        hamm_len2 = LPROT_HAMM_LEN2_16K as i16; // 96
        p_fft_tbl = &FFT_W256; // Table for 512-point real input FFT
        lprot_log2_minus1 = 8;
    }

    let lprot2 = shr(lprot, 1);
    let lprot2_1 = add(lprot2, 1);
    // The length of the rectangular portion of the Hamming-Rectangular window.
    let rect_length = sub(lprot, shl(hamm_len2, 1));

    *out.q = 0.max(sub(exp16_array(lprot, prevsynth), 1));
    copy_scale_sig(prevsynth, &mut xfp, lprot, *out.q);

    if sub(output_frame, L_FRAME48K) == 0 {
        // Apply hamming-rect window
        windowing_in_place(&mut xfp, &W_HAMM_SANA48K_2_FX, rect_length, hamm_len2);
        // Spectrum
        fft3_fx(&mut xfp, lprot);
    } else {
        windowing_rom_optimized(&mut xfp, sin_tbl_offset, rect_length, hamm_len2);
        r_fft_fx_lc_in_place(p_fft_tbl, lprot, lprot2, lprot_log2_minus1, &mut xfp, 1);
    }

    // Apply zeroing of non-coded FFT spectrum
    if sub(output_frame, INNER_FRAME_TBL_FX[bwidth_fx as usize]) > 0 {
        let stop_band_start = shl(128, bwidth_fx);
        let stop_band_length = sub(lprot, shl(stop_band_start, 1));
        let stop_band_start = add(stop_band_start, 1);
        set16(&mut xfp[stop_band_start as usize..], 0, stop_band_length);
    }

    out.x_sav[..lprot as usize].copy_from_slice(&xfp[..lprot as usize]);

    // Magnitude representation
    fft_spec2(&xfp, &mut mag_sq, lprot);

    // Compute xfp[m] = sqrt(magSq[m])
    for m in 0..lprot2_1 as usize {
        if mag_sq[m] == 0 {
            xfp[m] = extract_l(mag_sq[m]); // magSq[] is zero
        } else {
            let expo = norm_l(mag_sq[m]); // exponent
            let mut man = extract_h(l_shl(mag_sq[m], expo)); // mantissa
            man = sqrt2nd_order(man);
            let mut expo_by2 = shr(expo, 1); // divided by 2: square root operation
            if (expo & 1) == 0 {
                man = mult_r(man, FEC_HQ_ECU_ROOT2); // sqrt(2) in Q14
                expo_by2 = sub(expo_by2, 1);
            }
            xfp[m] = shr(man, expo_by2); // denormalise the mantissa back to Q0
        }
    }

    // Find maximum and minimum.
    let mut xmax: i16 = 0;
    let mut xmin: i16 = 0;
    let _ = maximum(&xfp, lprot2_1, &mut xmax);
    let _ = minimum(&xfp, lprot2_1, &mut xmin);
    let sel = mult_r(sub(xmax, xmin), CMPLMNT_PFIND_SENS_FX);
    peakfinder(&xfp, lprot2_1, out.plocs, out.num_plocs, sel);

    // Refine peaks
    let mut p_plocsi = 0usize;
    let mut p_plocs = 0usize;
    let mut n = sub(*out.num_plocs, 1); // -1 so as to exclude the very last peak.
                                        // Special case: the very 1st peak if it is at 0 index position
    if sub(out.plocs[p_plocs], 0) == 0 {
        // only the very 1st peak can be at 0 index position
        let fraction = imax(&xfp, -1); // -1 signifies the special left edge case
        let acc = l_deposit_h(out.plocs[p_plocs]);
        p_plocs += 1;
        out.plocsi[p_plocsi] = l_mac(acc, fraction, 1); // in Q16
        p_plocsi += 1;
        n = sub(n, 1); // this special case is taken care of, one less to go
    }
    // All peaks except the very last peak but including the very 1st one if it has not been
    // taken care of: imax looks at the bin before, the peak and the bin after.
    for _ in 0..n.max(0) {
        let start = out.plocs[p_plocs] as usize - 1;
        let fraction = imax(&xfp[start..], 0); // in Q15
        let acc = l_deposit_h(out.plocs[p_plocs]);
        p_plocs += 1;
        // in Q16: append the fractional part to the integral part
        out.plocsi[p_plocsi] = l_mac(acc, fraction, 1);
        p_plocsi += 1;
    }
    if n >= 0 {
        // Special case: the very last peak
        let mut start = out.plocs[p_plocs] as usize - 1;
        let special: i16 = if sub(out.plocs[p_plocs], lprot2) == 0 {
            // only the very last peak can be at Lprot2 index position
            start -= 1; // special case needs an extra decrement
            1 // signify the special right edge case
        } else {
            0
        };
        let fraction = imax(&xfp[start..], special); // in Q15
        let acc = l_deposit_h(out.plocs[p_plocs]);
        out.plocsi[p_plocsi] = l_mac(acc, fraction, 1); // in Q16
    }
}

const _: () = {
    assert!(QUOT_LPR_LTR == 4);
    assert!(LTRANA48K == 384);
};
