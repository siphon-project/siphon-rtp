//! Comfort-noise parameter history (TS 26.442 `lib_com/cng_exc_fx.c`; TS 26.445 §6.7.2).
//!
//! Ported: `CNG_exc_fx`, the LP-CNG excitation of an inactive frame, and `cng_params_upd_fx`, which
//! every active ACELP frame runs to feed the DTX hangover averaging (`cng_params_postupd_fx` is
//! encoder-only).

use crate::evs::basop::{l_extract_lc, madd_32_16, mult_32_16};
use crate::evs::cnst::{
    ACELP_13K20, ACELP_7K20, ACELP_8K00, ACELP_9K60, ENC, FRAME_NO_DATA, HO_HIST_SIZE, LOG2_L_FFT,
    L_FFT, L_FRAME, L_FRAME16K, L_SUBFR, M, NUM_ENV_CNG, PIT16K_MAX, PIT_MAX, SID_1K75, SID_2K40,
};
use crate::evs::com::fft_rel_sas::{fft_rel, ifft_rel};
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::math_op::{dot_product12, isqrt_lc, pow2};
use crate::evs::com::modif_fs::modify_fs_in_place;
use crate::evs::com::swb_tbe_com::{interp_code_4over2, interp_code_5over2};
use crate::evs::com::tools::{calc_energy_autoscaled, random, random_fill};
use crate::evs::rom::ENR_ATT_FX;
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_deposit_l, l_mult, l_shl, l_shr,
    l_sub, mult, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::oper_32b::l_comp;
use crate::itu::stl2009::{l_mac0, l_mult0};

/// `cng_params_upd_fx`: advance the CNG hangover ring (`ho_circ_ptr`, `ho_circ_size`) and store the
/// frame's LSPs, its excitation energy (Q6) and, in the decoder, its attenuated excitation spectrum
/// envelope; the encoder instead keeps the excitation for later processing.
pub fn cng_params_upd(
    lsp_new: &[i16],
    exc2: &[i16],
    l_frame: i16,
    ho_circ_ptr: &mut i16,
    ho_ener_circ: &mut [i32],
    ho_circ_size: &mut i16,
    ho_lsp_circ: &mut [i16],
    q_exc: i16,
    enc_dec_flag: i16,
    ho_env_circ: &mut [i32],
    cng_buf_cnt: &mut i16,
    cng_exc2_buf: &mut [i16],
    cng_qexc_buf: &mut [i16],
    cng_brate_buf: &mut [i32],
    last_active_brate: i32,
) {
    // update the pointer to circular buffer of old LSP vectors
    *ho_circ_ptr = add(*ho_circ_ptr, 1);
    if sub(*ho_circ_ptr, HO_HIST_SIZE) == 0 {
        *ho_circ_ptr = 0;
    }
    let ptr = *ho_circ_ptr as usize;

    // update the circular buffer of old LSP vectors with the new LSP vector
    let m = M as usize;
    ho_lsp_circ[ptr * m..(ptr + 1) * m].copy_from_slice(&lsp_new[..m]);

    // calculate the residual signal energy
    let mut maxv: i16 = 0;
    for &value in &exc2[..l_frame.max(0) as usize] {
        maxv = maxv.max(abs_s(value));
    }
    let scale = norm_s(maxv);

    let mut l_ener: i32 = 0;
    let pairs = if sub(l_frame, L_FRAME) == 0 { 128 } else { 160 };
    for pair in exc2[..2 * pairs].as_chunks::<2>().0 {
        let tmpv = shl(pair[0], scale);
        let mut l_tmp = l_mult0(tmpv, tmpv); // 2*(Q_exc+scale)
        let tmpv = shl(pair[1], scale);
        l_tmp = l_mac0(l_tmp, tmpv, tmpv);
        if sub(l_frame, L_FRAME) == 0 {
            // division by L_frame done here
            l_ener = l_add(l_ener, l_shr(l_tmp, 7));
        } else {
            // L_FRAME16k: 256/320 in Q15
            l_ener = l_add(l_ener, l_shr(mult_32_16(l_tmp, 26214), 7));
        }
    }
    l_ener = l_shr(l_ener, sub(shl(add(q_exc, scale), 1), 5)); // Q6

    // update the circular buffer of old energies
    ho_ener_circ[ptr] = l_ener;

    if sub(enc_dec_flag, ENC) == 0 {
        // Store residual signal for postponed FFT-processing
        *cng_buf_cnt = add(*cng_buf_cnt, 1);
        if sub(*cng_buf_cnt, HO_HIST_SIZE) > 0 {
            *cng_buf_cnt = HO_HIST_SIZE;
        }
        let l_fft = L_FFT as usize;
        cng_exc2_buf[ptr * l_fft..(ptr + 1) * l_fft].copy_from_slice(&exc2[..l_fft]);
        cng_qexc_buf[ptr] = q_exc;
        cng_brate_buf[ptr] = last_active_brate;
    } else {
        cng_params_upd_envelope(exc2, l_frame, q_exc, ptr, ho_env_circ, last_active_brate);
    }
    *ho_circ_size = add(*ho_circ_size, 1);
    if sub(*ho_circ_size, HO_HIST_SIZE) > 0 {
        *ho_circ_size = HO_HIST_SIZE;
    }
}

/// The decoder half of `cng_params_upd_fx`: the excitation's power spectrum in its first
/// `NUM_ENV_CNG` bins, attenuated by the bit-rate dependent `ENR_ATT_fx`, into slot `ptr` of
/// `ho_env_circ`.
fn cng_params_upd_envelope(
    exc2: &[i16],
    l_frame: i16,
    q_exc: i16,
    ptr: usize,
    ho_env_circ: &mut [i32],
    last_active_brate: i32,
) {
    // calculate the spectrum of residual signal
    let mut fft_io = [0_i16; L_FRAME16K as usize];
    let frame = l_frame.max(0) as usize;
    fft_io[..frame].copy_from_slice(&exc2[..frame]);
    fft_rel(&mut fft_io, L_FFT, LOG2_L_FFT);

    let mut env = [0_i32; NUM_ENV_CNG as usize];
    for (i, slot) in env.iter_mut().enumerate() {
        // sp[i] = 2.0f*(*ptR * *ptR + *ptI * *ptI)/L_FFT;
        let real = fft_io[1 + i];
        let imaginary = fft_io[L_FFT as usize - 1 - i];
        let mut l_tmp = l_mult(real, real); // 2*Q_exc+1
        l_tmp = l_add(l_tmp, l_mult(imaginary, imaginary)); // 2*Q_exc+1
        l_tmp = l_add(l_tmp, l_tmp); // 2*Q_exc+1
        l_tmp = mult_32_16(l_tmp, 128); // 2*Q_exc+1
        let tmp = add(add(q_exc, q_exc), 1);
        *slot = l_shr(l_tmp, sub(tmp, 6)); // Q6
    }

    let cng_mode: usize = if l_sub(last_active_brate, i32::from(ACELP_13K20)) > 0 {
        4
    } else if l_sub(last_active_brate, i32::from(ACELP_9K60)) > 0 {
        3
    } else if l_sub(last_active_brate, i32::from(ACELP_8K00)) > 0 {
        2
    } else if l_sub(last_active_brate, i32::from(ACELP_7K20)) > 0 {
        1
    } else {
        0
    };

    // att = 1/pow(2,ENR_ATT_fx[CNG_mode]);
    let l_tmp = l_shl(l_deposit_l(ENR_ATT_FX[cng_mode]), 8); // 16
    let (temp_hi_fx, temp_lo_fx) = l_extract_lc(l_tmp);
    let exp_pow = sub(14, temp_hi_fx);
    let mut l_tmp = pow2(14, temp_lo_fx); // Qexp_pow
    l_tmp = l_shl(l_tmp, sub(13, exp_pow)); // Q13
    let mut tmp = extract_l(l_tmp); // Q13
    let exp1 = norm_s(tmp);
    tmp = shl(tmp, exp1); // Q(exp1+13)
    tmp = div_s(16384, tmp); // Q(15+14-exp1-13)
    tmp = shr(tmp, sub(1, exp1)); // Q15

    // update the circular buffer of old residual envelope
    let n = NUM_ENV_CNG as usize;
    for (slot, value) in ho_env_circ[ptr * n..(ptr + 1) * n].iter_mut().zip(env) {
        *slot = mult_32_16(value, tmp);
    }
}

/// `A2`: the weight of the new SID energy in the normal CNG energy update (Q15).
const A2: i16 = 6554;
/// `OmA2`: `32768 - A2`.
const OM_A2: i16 = 26214;
/// `GAIN_VAR`: the depth of the random energy variation (Q31 halved, i.e. Q30).
const GAIN_VAR: i16 = 11811;

/// `CNG_exc_fx`: the comfort-noise excitation of an inactive frame (TS 26.445 §6.7.3.1).
///
/// White noise scaled per subframe to the low-passed SID energy `lp_ener` (Q6, randomised by
/// `cng_ener_seed`); outside the AMR-WB IO mode (`opt_amr_wb` != 1) it is then spectrally shaped
/// towards the decoded/low-passed envelope (`q_env`, `lp_env`, `old_env`, Q6), the shaped noise
/// replacing `exc2` while the plain white noise goes to `exc` (via `exc3`). `bwe_exc` receives the
/// TBE excitation (`exc2` interpolated by 5/2 at 12.8 kHz, 2 at 16 kHz).
///
/// `exc[exc_at..]` is the frame; in the very first CNG frame when it is a NO_DATA frame the energy
/// is taken from the `pit_max` samples before it. `exc2` and `exc3` must hold `L_FRAME16k`
/// samples (the reference copies that many whatever the frame length); `exc_mem` / `exc_mem1` are
/// the 12.8 → 16 kHz and 16 → 12.8 kHz resampler memories. `first_cng` and `sid_bw` are read only.
pub fn cng_exc(
    core_brate: i32,
    l_frame: i16,
    enew: &mut i32,
    seed: &mut i16,
    exc: &mut [i16],
    exc_at: usize,
    exc2: &mut [i16],
    lp_ener: &mut i32,
    last_core_brate: i32,
    first_cng: i16,
    cng_ener_seed: &mut i16,
    bwe_exc: &mut [i16],
    allow_cn_step: i16,
    last_allow_cn_step: &mut i16,
    old_q_exc: i16,
    q_exc: i16,
    num_ho: i16,
    q_env: &[i32],
    lp_env: &mut [i32],
    old_env: &mut [i32],
    exc_mem: &mut [i16],
    exc_mem1: &mut [i16],
    sid_bw: i16,
    cng_ener_seed1: &mut i16,
    exc3: &mut [i16],
    opt_amr_wb: i16,
) {
    let pit_max = if l_frame == L_FRAME {
        PIT_MAX
    } else {
        PIT16K_MAX
    };
    let lf = usize::try_from(l_frame).unwrap_or(0);

    // initialization of the CNG energy for the first CNG frame
    if first_cng == 0 {
        if core_brate == i32::from(FRAME_NO_DATA) {
            // needed only in the decoder when the very first SID frame was erased and this frame is
            // a FRAME_NO_DATA frame: the energy of the last pit_max samples of excitation (every
            // caller keeps at least PIT16k_MAX samples of history before the frame)
            let from = exc_at.saturating_sub(pit_max as usize);
            let mut q_ener = 0i16;
            let mut l_tmp_ener =
                calc_energy_autoscaled(&exc[from..], old_q_exc, pit_max, &mut q_ener);
            l_tmp_ener = mult_32_16(l_tmp_ener, 9079); // divide by PIT_MAX (Q15 + Q6 -> Q6)
            l_tmp_ener = l_shr(l_tmp_ener, q_ener);
            if l_frame == L_FRAME16K {
                l_tmp_ener = mult_32_16(l_tmp_ener, 26214); // compensate for 16 kHz
            }
            *enew = l_tmp_ener;
        }
        *lp_ener = *enew;
    }

    cng_exc_energy_update(
        core_brate,
        *enew,
        lp_ener,
        last_core_brate,
        allow_cn_step,
        last_allow_cn_step,
        num_ho,
    );

    // white noise vector, with a random variation of the excitation energy per subframe
    random_fill(seed, l_frame, exc2, 4);
    let mut i_subfr = 0;
    while i_subfr < lf {
        let mut l_tmp = mult_32_16(*lp_ener, random(cng_ener_seed));
        l_tmp = mult_32_16(l_tmp, GAIN_VAR);
        l_tmp = l_add(l_tmp, *lp_ener);
        l_tmp = l_tmp.max(1);
        let sub_frame = &mut exc2[i_subfr..i_subfr + L_SUBFR as usize];
        let mut exp = 0i16;
        let tmp = extract_h(dot_product12(sub_frame, sub_frame, L_SUBFR, &mut exp));
        exp = add(exp, 8 - 6); // 8 from Q-4, -6 from L_SUBFR
        let (tmp, mut exp) = cng_exc_sqrt_ratio(tmp, exp, l_tmp);
        exp = add(exp, 4); // from Q15 to Q19
        exp = add(exp, q_exc); // Q_exc + Q19
        for v in sub_frame.iter_mut() {
            let l_tmp = l_mult(*v, tmp); // Q-4 * Q_exc+19 -> Q_exc+16
            *v = round_word(l_shl(l_tmp, exp));
        }
        i_subfr += L_SUBFR as usize;
    }

    if opt_amr_wb != 1 {
        exc3[..L_FRAME16K as usize].copy_from_slice(&exc2[..L_FRAME16K as usize]);
        let shaping = CngShaping {
            core_brate,
            l_frame,
            enew: *enew,
            lp_ener: *lp_ener,
            last_core_brate,
            first_cng,
            q_exc,
            sid_bw,
        };
        cng_exc_spectral(
            &shaping,
            exc2,
            q_env,
            lp_env,
            old_env,
            exc_mem,
            exc_mem1,
            cng_ener_seed1,
        );
        exc[exc_at..exc_at + lf].copy_from_slice(&exc3[..lf]);
    } else {
        exc[exc_at..exc_at + lf].copy_from_slice(&exc2[..lf]);
    }

    if l_frame == L_FRAME {
        interp_code_5over2(exc2, bwe_exc, L_FRAME);
    } else {
        interp_code_4over2(exc2, bwe_exc, l_frame);
    }
}

/// `CNG_exc_fx`'s update of the low-passed CNG energy `lp_ener` (Q6) from the SID energy `enew`:
/// a partial reset after an active period, the normal AR update otherwise, a step where allowed.
fn cng_exc_energy_update(
    core_brate: i32,
    enew: i32,
    lp_ener: &mut i32,
    last_core_brate: i32,
    allow_cn_step: i16,
    last_allow_cn_step: &mut i16,
    num_ho: i16,
) {
    let l_tmp_ener;
    if last_core_brate != i32::from(SID_1K75)
        && last_core_brate != i32::from(FRAME_NO_DATA)
        && last_core_brate != i32::from(SID_2K40)
    {
        // partially reset the CNG energy after an active speech period
        if allow_cn_step == 0 && *last_allow_cn_step == 0 {
            if num_ho < 3 || mult_32_16(enew, 21845) < *lp_ener {
                // lp_ener = 0.8 lp_ener + 0.2 Enew
                let t = mult_32_16(*lp_ener, 26214);
                l_tmp_ener = madd_32_16(t, enew, 6554);
            } else {
                // lp_ener = 0.95 lp_ener + 0.05 Enew
                let t = mult_32_16(*lp_ener, 31130);
                l_tmp_ener = madd_32_16(t, enew, 1638);
            }
        } else {
            l_tmp_ener = l_add(0, enew);
            *last_allow_cn_step = 0;
        }
    } else if *last_allow_cn_step == 0 {
        // normal CNG update: lp_ener = A2 Enew + (1-A2) lp_ener
        let t = mult_32_16(enew, A2);
        l_tmp_ener = madd_32_16(t, *lp_ener, OM_A2);
    } else {
        if core_brate == i32::from(SID_1K75) || core_brate == i32::from(SID_2K40) {
            *last_allow_cn_step = 0;
        }
        l_tmp_ener = enew;
    }
    *lp_ener = l_tmp_ener.max(1); // to avoid / per 0

    if allow_cn_step == 1 {
        *last_allow_cn_step = 1;
    }
}

/// `sqrt(energy / (tmp·2^exp))` the way `CNG_exc_fx` writes it per subframe: `energy` (Q6) is
/// normalised, the smaller mantissa divided by the larger, and `Isqrt_lc` applied. Returns the
/// square root's high half and its exponent.
fn cng_exc_sqrt_ratio(tmp: i16, exp: i16, energy: i32) -> (i16, i16) {
    let mut tmp = tmp;
    let exp2 = norm_l(energy);
    let tmp2 = extract_h(l_shl(energy, exp2));
    let exp2 = sub(31 - 6, exp2); // in Q15 (energy in Q6)
    let mut exp = sub(exp, exp2);
    if tmp > tmp2 {
        exp = add(exp, 1);
    }
    if tmp > tmp2 {
        tmp = shr(tmp, 1);
    }
    tmp = div_s(tmp, tmp2);
    let l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp);
    (extract_h(l_tmp), exp)
}

/// `sqrt(num / den)` of two Q6 energies the way `CNG_exc_fx` writes it for the spectral shaping:
/// returns `Isqrt_lc`'s 32-bit result (Q(31-exp)) and `exp`.
fn cng_exc_isqrt_of_ratio(num: i32, den: i32) -> (i32, i16) {
    let l_tmp = num.max(1); // Q6
    let exp = norm_l(l_tmp);
    let tmp = extract_h(l_shl(l_tmp, exp));
    let exp = sub(31 - 6, exp);
    let exp2 = norm_l(den);
    let mut tmp2 = extract_h(l_shl(den, exp2));
    let exp2 = sub(31 - 6, exp2);
    let mut exp = sub(exp2, exp); // denormalize and subtract
    if tmp2 > tmp {
        exp = add(exp, 1);
    }
    if tmp2 > tmp {
        tmp2 = shr(tmp2, 1);
    }
    let tmp = div_s(tmp2, tmp);
    let l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp);
    (l_tmp, exp)
}

/// The frame parameters [`cng_exc_spectral`] reads.
struct CngShaping {
    core_brate: i32,
    l_frame: i16,
    enew: i32,
    lp_ener: i32,
    last_core_brate: i32,
    first_cng: i16,
    q_exc: i16,
    sid_bw: i16,
}

/// `log2(Enew·L_frame)` in Q6, as `CNG_exc_fx` and `CNG_dec_fx` compute it (`enr1`).
pub(crate) fn cng_log2_frame_energy(enew: i32, l_frame: i16) -> i32 {
    let mut exp = norm_l(enew);
    let mut l_tmp = l_shl(enew, exp); // Q(exp+6)
    l_tmp = mult_32_16(l_tmp, shl(l_frame, 5)); // Q(exp+6+5-15 = exp-4)
    l_tmp = l_shr(l_tmp, sub(exp, 10)); // Q6
    exp = norm_l(l_tmp);
    let fra = log2_norm_lc(l_shl(l_tmp, exp));
    exp = sub(sub(30, exp), 6);
    let l_tmp = l_comp(exp, fra);
    l_shr(l_tmp, 10) // Q6
}

/// `pow(2, enr1 - q_env)` in Q6 (`enr1`, `q_env` in Q6), as `CNG_exc_fx` and `CNG_dec_fx` compute
/// the quantised envelope.
pub(crate) fn cng_envelope_band(enr1: i32, q_env: i32) -> i32 {
    let mut l_tmp = l_sub(enr1, q_env); // Q6
    l_tmp = l_shl(l_tmp, 10); // Q16
    let (temp_hi, temp_lo) = l_extract_lc(l_tmp);
    let exp_pow = sub(14, temp_hi);
    let l_tmp = pow2(14, temp_lo); // Q(exp_pow)
    l_shl(l_tmp, sub(6, exp_pow)) // Q6
}

/// `CNG_exc_fx`'s spectral shaping of the white noise in `exc2` (outside the AMR-WB IO mode): the
/// envelope update, the shaped random spectrum, its time-domain randomisation and the final mix
/// `0.75·shaped + white`, normalised to `lp_ener`, written back to `exc2`.
fn cng_exc_spectral(
    p: &CngShaping,
    exc2: &mut [i16],
    q_env: &[i32],
    lp_env: &mut [i32],
    old_env: &mut [i32],
    exc_mem: &mut [i16],
    exc_mem1: &mut [i16],
    cng_ener_seed1: &mut i16,
) {
    let n_env = NUM_ENV_CNG as usize;
    let lf = usize::try_from(p.l_frame).unwrap_or(0);
    let mut env = [0i32; NUM_ENV_CNG as usize];
    let enr1 = cng_log2_frame_energy(p.enew, p.l_frame);

    if p.core_brate == i32::from(SID_2K40) {
        if p.sid_bw == 0 {
            for i in 0..n_env {
                // the quantized envelope
                env[i] = cng_envelope_band(enr1, q_env[i]);
            }
        }
        // initialize the CNG envelope
        if p.first_cng == 0 && p.sid_bw == 0 {
            lp_env[..n_env].copy_from_slice(&env);
        }
        if p.sid_bw == 0 {
            old_env[..n_env].copy_from_slice(&env);
        }
    }
    for i in 0..n_env {
        // AR low-passed envelope: lp_env = 0.9 lp_env + 0.1 old_env
        let l_tmp = mult_32_16(lp_env[i], 29491);
        lp_env[i] = l_add(l_tmp, mult_32_16(old_env[i], 3277));
    }

    // the spectrum of the random excitation signal
    let mut fft_io = [0i16; L_FRAME16K as usize];
    fft_io[..lf].copy_from_slice(&exc2[..lf]);
    if p.l_frame == L_FRAME16K {
        modify_fs_in_place(&mut fft_io, L_FRAME16K, 16000, 12800, exc_mem1, 0);
    }
    fft_rel(&mut fft_io, L_FFT, LOG2_L_FFT);
    let l_fft = L_FFT as usize;
    for i in 0..n_env {
        // env = 2 (R^2 + I^2) / L_FFT
        let (r, im) = (fft_io[1 + i], fft_io[l_fft - 1 - i]);
        let mut l_tmp = l_mult0(r, r);
        l_tmp = l_mac0(l_tmp, im, im);
        l_tmp = l_shr(l_tmp, 1);
        let tmp = add(p.q_exc, p.q_exc);
        env[i] = l_shr(l_tmp, tmp); // Q6
    }
    let mut denv = [0i32; NUM_ENV_CNG as usize];
    for i in 0..n_env {
        // denv = lp_env + 2 lp_ener - env
        let l_tmp = l_add(p.lp_ener, p.lp_ener);
        denv[i] = l_sub(l_add(lp_env[i], l_tmp), env[i]);
        if denv[i] < 0 {
            denv[i] = l_deposit_l(0);
        }
    }

    cng_exc_random_spectrum(&mut fft_io, &denv, p.q_exc, cng_ener_seed1);
    ifft_rel(&mut fft_io, L_FFT, LOG2_L_FFT);
    if p.l_frame == L_FRAME16K {
        modify_fs_in_place(&mut fft_io, L_FFT, 12800, 16000, exc_mem, 0);
    }

    // enr1 = dotp(fft_io, fft_io, L_frame) / L_frame
    let enr1 = l_shr(
        cng_exc_mean_energy(&fft_io, p.l_frame),
        sub(add(p.q_exc, p.q_exc), 5),
    ); // Q6
    cng_exc_time_randomisation(p, &mut fft_io, enr1, cng_ener_seed1);

    for i in 0..lf {
        // fft_io = 0.75 fft_io + exc2
        let tmp = mult(fft_io[i], 24576);
        fft_io[i] = add(tmp, exc2[i]);
    }
    // enr = dotp(fft_io, fft_io, L_frame) / L_frame + 0.01
    let l_tmp2 = l_shr(
        cng_exc_mean_energy(&fft_io, p.l_frame),
        sub(add(p.q_exc, p.q_exc), 5),
    ); // Q6

    // ftmp = sqrt(lp_ener / enr)
    let (l_tmp, exp) = cng_exc_isqrt_of_ratio(p.lp_ener, l_tmp2);
    let ftmp = extract_h(l_shl(l_tmp, exp)); // Q15
    for v in &mut fft_io[..lf] {
        *v = mult(*v, ftmp);
    }
    exc2[..lf].copy_from_slice(&fft_io[..lf]);
}

/// `CNG_exc_fx`'s random spectrum: `NUM_ENV_CNG` random bins (from `cng_ener_seed1`), each scaled
/// to `sqrt(itmp / env)` where `itmp` is the randomised target envelope `denv`; the rest of
/// `fft_io[0..L_FFT]` is zero.
fn cng_exc_random_spectrum(fft_io: &mut [i16], denv: &[i32], q_exc: i16, cng_ener_seed1: &mut i16) {
    let n_env = NUM_ENV_CNG as usize;
    let l_fft = L_FFT as usize;
    let mut env = [0i32; NUM_ENV_CNG as usize];
    let mut itmp = [0i32; NUM_ENV_CNG as usize];
    fft_io[..l_fft].fill(0);
    for i in 0..n_env {
        fft_io[1 + i] = random(cng_ener_seed1);
        fft_io[l_fft - 1 - i] = random(cng_ener_seed1);
        let (r, im) = (fft_io[1 + i], fft_io[l_fft - 1 - i]);
        let mut l_tmp = l_mult0(r, r);
        l_tmp = l_mac0(l_tmp, im, im);
        env[i] = l_shr(l_tmp, 1);
    }
    for i in 0..n_env {
        // itmp += random * denv * 0.000011 + denv
        let mut l_tmp = mult_32_16(denv[i], random(cng_ener_seed1));
        l_tmp = mult_32_16(l_tmp, GAIN_VAR);
        l_tmp = l_add(l_tmp, denv[i]);
        itmp[i] = l_add(l_tmp, itmp[i]);
        if itmp[i] < 0 {
            itmp[i] = 0;
        }
    }
    for i in 0..n_env {
        // R *= sqrt(itmp / env), I *= sqrt(itmp / env)
        let (l_tmp, exp) = cng_exc_isqrt_of_ratio(itmp[i], env[i]);
        let l_tmp2 = mult_32_16(l_tmp, fft_io[1 + i]);
        fft_io[1 + i] = extract_h(l_shl(l_tmp2, add(exp, q_exc)));
        let l_tmp2 = mult_32_16(l_tmp, fft_io[l_fft - 1 - i]);
        fft_io[l_fft - 1 - i] = extract_h(l_shl(l_tmp2, add(exp, q_exc)));
    }
}

/// `1 + Σ x² / L_frame` over pairs of samples, as `CNG_exc_fx` accumulates it (Q(2·Q_exc+1)).
fn cng_exc_mean_energy(fft_io: &[i16], l_frame: i16) -> i32 {
    let mut enr = l_deposit_l(1);
    let pairs = if l_frame == L_FRAME { 128 } else { 160 };
    for j in 0..pairs {
        let mut l_tmp = l_mult0(fft_io[2 * j], fft_io[2 * j]);
        l_tmp = l_mac0(l_tmp, fft_io[2 * j + 1], fft_io[2 * j + 1]);
        if l_frame == L_FRAME {
            enr = l_add(enr, l_shr(l_tmp, 7)); // divide by L_frame done here
        } else {
            enr = l_add(enr, l_shr(mult_32_16(l_tmp, 26214), 7)); // 256/320
        }
    }
    enr
}

/// `CNG_exc_fx`'s time-domain randomisation of the shaped noise: each subframe scaled to a
/// randomised `enr1`, the gain capped at 1 in the first SID frame after active speech.
fn cng_exc_time_randomisation(
    p: &CngShaping,
    fft_io: &mut [i16],
    enr1: i32,
    cng_ener_seed1: &mut i16,
) {
    let lf = usize::try_from(p.l_frame).unwrap_or(0);
    let mut i_subfr = 0;
    while i_subfr < lf {
        let mut l_tmp = mult_32_16(enr1, random(cng_ener_seed1));
        l_tmp = mult_32_16(l_tmp, GAIN_VAR);
        l_tmp = l_add(l_tmp, enr1);
        l_tmp = l_tmp.max(1);
        let sub_frame = &mut fft_io[i_subfr..i_subfr + L_SUBFR as usize];
        let mut exp = 0i16;
        let mut tmp = extract_h(dot_product12(sub_frame, sub_frame, L_SUBFR, &mut exp));
        exp = add(exp, sub(-6, add(p.q_exc, p.q_exc))); // -2 Q_exc from fft_io, -6 from L_SUBFR

        // enr = sqrt(ener_lp L_SUBFR / enr)
        let exp2 = norm_l(l_tmp);
        let tmp2 = extract_h(l_shl(l_tmp, exp2));
        let exp2 = sub(31 - 6, exp2);
        exp = sub(exp, exp2);
        if tmp > tmp2 {
            exp = add(exp, 1);
        }
        if tmp > tmp2 {
            tmp = shr(tmp, 1);
        }
        tmp = div_s(tmp, tmp2);
        let mut l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp); // Q(31-exp)
        if p.last_core_brate != i32::from(SID_2K40)
            && p.last_core_brate != i32::from(SID_1K75)
            && p.last_core_brate != i32::from(FRAME_NO_DATA)
            && p.core_brate == i32::from(SID_2K40)
            && l_tmp > l_shl(1, sub(31, exp))
        {
            l_tmp = l_shl(1, sub(31, exp));
        }
        let tmp = extract_h(l_tmp);
        for v in sub_frame.iter_mut() {
            let l_tmp = l_mult(*v, tmp); // Q_exc + 16 - exp
            *v = round_word(l_shl(l_tmp, exp)); // Q_exc
        }
        i_subfr += L_SUBFR as usize;
    }
}
