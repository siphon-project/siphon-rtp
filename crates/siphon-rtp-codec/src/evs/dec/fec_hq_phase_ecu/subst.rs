//! Substitution spectrum and frame reconstruction of the HQ phase ECU (TS 26.442
//! `lib_dec/FEC_HQ_phase_ecu_fx.c`): `subst_spec_fx`, `rec_wtda_fx`, `rec_frame_fx`.

use super::analysis::{rand_phase, LPROT48K, MAX_PLOCS};
use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    ALDO_WINDOW, LPROT32K, L_FRAME32K, L_FRAME48K, PH_ECU_ALDO_OLP2_NS, PH_ECU_LOOKAHEAD_NS,
};
use crate::evs::com::fft_fx::ifft3;
use crate::evs::com::fft_rel::r_fft_fx_lc_in_place;
use crate::evs::com::math_op::sqrt_l;
use crate::evs::com::tools::{own_random2, scale_sig, set16};
use crate::evs::com::wtda::wtda;
use crate::evs::macros::{ns2sa, ns2sa_fx2};
use crate::evs::rom::{FFT_W256, FFT_W512, GWLPR_FX, SINCOS_T_EXT_FX, SINCOS_T_FX};
use crate::itu::basic_ops::{
    add, extract_l, l_add, l_mult, l_shl, l_shr, l_sub, mult, mult_r, negate, round_word, shl, shr,
    sub,
};
use crate::itu::stl2009::{l_mult0, lshr, mpy_32_16_ss};

const DELTA_CORR: i16 = 6;
const PHASE_DITH_SCALE_SHIFT: i16 = 16;
const LGW32K: i16 = 7;
const LGW16K: i16 = 6;

/// The sine and cosine of `Xph_short / 1024 · 2π` (10 bit phase, from the extended sine table).
fn sin_cos_of_phase(xph_short: i16) -> (i16, i16) {
    let x = i32::from(xph_short);
    let at = |index: i32| SINCOS_T_EXT_FX[index as usize];
    if sub(xph_short, 512) >= 0 {
        let sin_f = negate(at(x - 512));
        let cos_f = if sub(xph_short, 768) < 0 {
            negate(at(x - (512 - 256)))
        } else {
            at(-x + (1024 + 256))
        };
        (sin_f, cos_f)
    } else {
        let sin_f = at(x);
        let cos_f = if sub(xph_short, 256) < 0 {
            at(x + 256)
        } else {
            negate(at(-x + (256 + 512)))
        };
        (sin_f, cos_f)
    }
}

/// The running position of `subst_spec_fx` through the spectrum: bin `i`, frequency group `k`, and
/// the real / imaginary indices (`pReX`, `pImX`).
struct Cursor {
    i: i16,
    k: usize,
    re_index: usize,
    im_index: usize,
}

impl Cursor {
    /// `i = add(i, 1); if (i >= gwlpr[k+1]) k++`, with the two spectrum pointers advanced.
    fn advance(&mut self) {
        self.re_index += 1;
        self.im_index = self.im_index.wrapping_sub(1);
        self.i = add(self.i, 1);
        if sub(self.i, GWLPR_FX[self.k + 1]) >= 0 {
            self.k += 1;
        }
    }
}

/// The per-band fade tables of `subst_spec_fx`.
struct Bands<'a> {
    mag_chg: &'a [i16],
    alpha: &'a [i16],
    beta: &'a [i16],
    xavg: &'a [i16],
}

/// `segmentLen` bins between the peaks (and after the last): random phase, then either the fade
/// to the group average (`alpha < 32766`) or the magnitude modification.
fn random_phase_bins(
    x: &mut [i16],
    cursor: &mut Cursor,
    segment_len: i16,
    seed: &mut i16,
    bands: &Bands<'_>,
) {
    for _ in 0..segment_len.max(0) {
        let k = cursor.k;
        let mut sin_f = 0;
        let mut cos_f = 0;
        *seed = rand_phase(*seed, &mut sin_f, &mut cos_f);

        let re = x[cursor.re_index];
        let im = x[cursor.im_index];
        let tmp = sub(mult_r(re, cos_f), mult_r(im, sin_f));
        let im = add(mult_r(re, sin_f), mult_r(im, cos_f));
        if sub(bands.alpha[k], 32766) < 0 {
            *seed = rand_phase(*seed, &mut sin_f, &mut cos_f);
            let tmp2 = mult_r(bands.beta[k], bands.xavg[k]);
            x[cursor.re_index] = add(mult_r(bands.alpha[k], tmp), mult_r(tmp2, cos_f));
            x[cursor.im_index] = add(mult_r(bands.alpha[k], im), mult_r(tmp2, sin_f));
        } else {
            x[cursor.re_index] = mult_r(bands.mag_chg[k], tmp);
            x[cursor.im_index] = mult_r(bands.mag_chg[k], im);
        }
        cursor.advance();
    }
}

/// The peak bins of `subst_spec_fx`: `segmentLen` bins rotated by the peak's corrected phase
/// (`corr_phase`), dithered when `ph_dith != 0`, with the fade of `alpha < 32766`.
fn peak_bins(
    x: &mut [i16],
    cursor: &mut Cursor,
    segment_len: i16,
    corr_phase: i32,
    ph_dith: i16,
    seed: &mut i16,
    beta_mute: i16,
    bands: &Bands<'_>,
) {
    let xph = corr_phase;
    let xph_short = extract_l(l_shr(xph, 16 - 10)) & 0x3ff; // 10 bits after radix point
    let (mut sin_f, mut cos_f) = sin_cos_of_phase(xph_short);

    for _ in 0..segment_len.max(0) {
        let k = cursor.k;
        let mut mag_chg_local = bands.mag_chg[k];
        if ph_dith != 0 {
            let mut xph = corr_phase; // in Q16, 2*PI is not included
            *seed = own_random2(*seed); // in Q0
            let mut acc = l_mult(*seed, ph_dith); // ph_dith is in Q15, between 0 and 1.0
            acc = l_shr(acc, PHASE_DITH_SCALE_SHIFT);
            xph = l_add(xph, acc); // in Q16

            if ph_dith > 0 {
                // up to 6 dB additional attenuation of peaks in non-transient longer bursts
                // (when the peak phase is randomised)
                mag_chg_local = mult_r(mag_chg_local, sub(32767, shr(ph_dith, 1)));
            }
            let xph_short = extract_l(l_shr(xph, 16 - 10)) & 0x3ff;
            (sin_f, cos_f) = sin_cos_of_phase(xph_short);
        }

        let re = x[cursor.re_index];
        let im = x[cursor.im_index];
        let tmp = sub(mult_r(re, cos_f), mult_r(im, sin_f));
        let im = add(mult_r(re, sin_f), mult_r(im, cos_f));
        if sub(bands.alpha[k], 32766) < 0 {
            let alpha_local = mag_chg_local;
            let mut acc = l_sub(1_073_741_824, l_mult0(alpha_local, alpha_local));
            let mut expo: i16 = 0;
            acc = sqrt_l(acc, &mut expo);
            expo = add(30, add(31, expo));
            if sub(expo & 1, 1) == 0 {
                acc = mult_32_16(acc, 23170); // 1/sqrt(2) in Q15
            }
            expo = shr(expo, 1);
            let mut beta_local = mult_r(beta_mute, round_word(l_shl(acc, sub(31, expo))));

            if sub(k as i16, LGW32K - 1) >= 0 {
                beta_local = mult_r(beta_local, 3277); // 0.1 in Q15
            } else if sub(k as i16, LGW16K - 1) >= 0 {
                beta_local = mult_r(beta_local, 16384); // 0.5 in Q15
            }

            *seed = rand_phase(*seed, &mut sin_f, &mut cos_f);
            let tmp2 = mult_r(beta_local, bands.xavg[k]);
            x[cursor.re_index] = add(mult_r(alpha_local, tmp), mult_r(tmp2, cos_f));
            x[cursor.im_index] = add(mult_r(alpha_local, im), mult_r(tmp2, sin_f));
        } else {
            x[cursor.re_index] = mult_r(mag_chg_local, tmp);
            x[cursor.im_index] = mult_r(mag_chg_local, im);
        }
        cursor.advance();
    }
}

/// The inputs of [`subst_spec`] that are plain values and read-only tables.
pub struct SubstSpecInput<'a> {
    pub plocs: &'a [i16],
    pub plocsi: &'a [i32],
    pub time_offs: i16,
    pub mag_chg: &'a [i16],
    pub ph_dith: i16,
    pub is_trans: &'a [i16],
    pub output_frame: i16,
    pub alpha: &'a [i16],
    pub beta: &'a [i16],
    pub beta_mute: i16,
    pub xavg: &'a [i16],
}

/// `subst_spec_fx`: the substitution spectrum `x` (real parts from bin 1 up, imaginary parts
/// mirrored from the end): the spectral peaks are phase-advanced to the concealed time, all other
/// bins get a random phase, and every bin is attenuated or faded to the group average.
pub fn subst_spec(input: &SubstSpecInput<'_>, num_plocs: &mut i16, x: &mut [i16], seed: &mut i16) {
    let output_frame = input.output_frame;
    let mut corr_phase = [0i32; MAX_PLOCS];
    let lecu = shl(output_frame, 1);

    let (lprot, lprot_inv): (i16, i16) = if sub(output_frame, L_FRAME48K) == 0 {
        (LPROT48K as i16, 2731) // 1536 = (2*output_frame)*1024/1280; Q22
    } else if sub(output_frame, L_FRAME32K) == 0 {
        (LPROT32K, 4096) // 1024; Q22
    } else {
        (512, 8192) // Q22
    };

    // Correction phase of the identified peaks
    if (input.is_trans[0] | input.is_trans[1]) != 0 {
        *num_plocs = 0;
    } else {
        let mut tmp = ns2sa(
            i32::from(output_frame) * 50,
            PH_ECU_ALDO_OLP2_NS - PH_ECU_LOOKAHEAD_NS,
        );
        tmp = add(tmp, sub(lecu, shr(sub(lecu, lprot), 1)));
        tmp = sub(tmp, shr(output_frame, 1));
        tmp = add(tmp, input.time_offs);
        tmp = round_word(l_shl(l_mult0(tmp, lprot_inv), 4)); // 0+22+4-16=10

        for (phase, &plocsi) in corr_phase
            .iter_mut()
            .zip(input.plocsi)
            .take((*num_plocs).max(0) as usize)
        {
            // plocsi[] in Q16, tmp in Q10 and tmp does not include 2*PI
            let (hi, lsb) = mpy_32_16_ss(plocsi, tmp);
            // in Q16, 2*PI is not included
            *phase = l_add(l_shl(hi, 5), i32::from(lshr(lsb as i16, 11)));
        }
    }

    let bands = Bands {
        mag_chg: input.mag_chg,
        alpha: input.alpha,
        beta: input.beta,
        xavg: input.xavg,
    };
    let lprot_by2_minus1 = sub(shr(lprot, 1), 1);
    let mut cursor = Cursor {
        i: 1,
        k: 0,
        re_index: 1,
        im_index: (lprot - 1) as usize,
    };
    // plocs[m + 1] for the last peak is the entry after the list: stale data in the reference,
    // and past the array when the list is full
    let ploc = |index: usize| input.plocs.get(index).copied().unwrap_or(0);
    let mut p_plocs = 0usize;
    let mut pk_location = ploc(p_plocs); // N.B. no post-increment
    let mut pk_location1 = ploc(p_plocs);
    p_plocs += 1;
    let last_peak = sub(*num_plocs, 1);
    for m in 0..(*num_plocs).max(0) {
        let mut delta_corr_dn = DELTA_CORR;
        let mut delta_corr_up = DELTA_CORR;

        let pk_location_1 = pk_location; // plocs[m - 1]
        pk_location = pk_location1; // plocs[m]
        pk_location1 = ploc(p_plocs); // plocs[m + 1]
        p_plocs += 1;
        if m > 0 {
            let delta_tmp = shr(sub(sub(pk_location, pk_location_1), 1), 1);
            if sub(delta_tmp, DELTA_CORR) < 0 {
                delta_corr_dn = delta_tmp;
            }
        }
        if sub(m, last_peak) < 0 {
            let delta_tmp = shr(sub(sub(pk_location1, pk_location), 1), 1);
            if sub(delta_tmp, DELTA_CORR) < 0 {
                delta_corr_up = delta_tmp;
            }
        }

        // Input Xph
        let segment_len = sub(sub(pk_location, delta_corr_dn), cursor.i);
        random_phase_bins(x, &mut cursor, segment_len, seed, &bands);

        let mut e = add(pk_location, delta_corr_up);
        if sub(e, lprot_by2_minus1) > 0 {
            e = lprot_by2_minus1;
        }

        let segment_len = add(sub(e, cursor.i), 1);
        peak_bins(
            x,
            &mut cursor,
            segment_len,
            corr_phase[m as usize],
            input.ph_dith,
            seed,
            input.beta_mute,
            &bands,
        );
    }

    let segment_len = sub(shr(lprot, 1), cursor.i);
    random_phase_bins(x, &mut cursor, segment_len, seed, &bands);
}

/// `rec_wtda_fx`: windowing and time-domain aliasing of the reconstructed frame `x` (`lprot`
/// samples) into `ecu_rec`.
pub fn rec_wtda(x: &[i16], ecu_rec: &mut [i32], output_frame: i16, lprot: i16, fs: i32) {
    let mut rec_buf = [0i16; 3 * L_FRAME48K as usize];
    let output_frame_us = output_frame as usize;
    let lprot2 = shr(lprot, 1);

    // Initialize to WB constants
    let (xf_len, tbl_delta): (i16, i16) = if sub(output_frame, L_FRAME48K) == 0 {
        (78, 3361) // Q12
    } else if sub(output_frame, L_FRAME32K) == 0 {
        (52, 5041) // Q12
    } else {
        (26, 10082) // Q12
    };

    // extract reconstructed frame with aldo window: xsubst_ = rec_buf + output_frame
    let xsubst = output_frame_us;
    let l = sub(output_frame, lprot2);
    set16(&mut rec_buf[xsubst..], 0, l);
    let lu = l.max(0) as usize;
    rec_buf[xsubst + lu..xsubst + lu + lprot as usize].copy_from_slice(&x[..lprot as usize]);
    set16(
        &mut rec_buf[xsubst + (output_frame + lprot2) as usize..],
        0,
        l,
    );

    // Smoothen onset of ECU frame
    let p_ecu = xsubst + (output_frame - lprot2) as usize;
    for i in 0..xf_len {
        let idx = extract_l(l_shr(l_mult0(i, tbl_delta), 12));
        let mut g = SINCOS_T_FX[idx as usize];
        g = mult(g, g);
        rec_buf[p_ecu + i as usize] = mult(g, rec_buf[p_ecu + i as usize]);
    }

    let timesh = ns2sa_fx2(fs, 10_000_000 - PH_ECU_ALDO_OLP2_NS);

    set16(&mut rec_buf, 0, output_frame);
    let mut q_in: i16 = 0;
    let out_ptr = (sub(shl(output_frame, 1), timesh)) as usize;
    let mut q_old_wtda: i16 = 0;
    wtda(
        &mut rec_buf,
        out_ptr,
        &mut q_in,
        ecu_rec,
        None,
        &mut q_old_wtda,
        ALDO_WINDOW,
        ALDO_WINDOW,
        output_frame,
    );
}

/// `rec_frame_fx`: the inverse FFT of the substitution spectrum `x` (scaled back by `q`) and its
/// windowing into `ecu_rec`.
pub fn rec_frame(x: &mut [i16], ecu_rec: &mut [i32], output_frame: i16, q: i16) {
    let fs = l_mult0(output_frame, 50);

    // Initialize to WB constants
    let mut lprot: i16 = 512;
    let mut lprot_log2_minus1: i16 = 9 - 1;
    let mut p_fft_tbl: &[i16] = &FFT_W256; // Table for 512-point real input FFT
    if sub(output_frame, L_FRAME48K) == 0 {
        lprot = LPROT48K as i16; // 1536 = (2*output_frame)*1024/1280
    } else if sub(output_frame, L_FRAME32K) == 0 {
        lprot = LPROT32K; // 1024
        lprot_log2_minus1 = 10 - 1;
        p_fft_tbl = &FFT_W512; // Table for 1024-point real input FFT
    }

    // extend spectrum and IDFT
    if sub(output_frame, L_FRAME48K) == 0 {
        ifft3(x, lprot);
    } else {
        r_fft_fx_lc_in_place(p_fft_tbl, lprot, shr(lprot, 1), lprot_log2_minus1, x, 0);
        // inverse
    }
    scale_sig(x, lprot, negate(q));

    rec_wtda(x, ecu_rec, output_frame, lprot, fs);
}
