//! The harmonic and HVQ bandwidth extensions of the HQ high-rate core (TS 26.442
//! `lib_com/hq_tools_fx.c`: `hq_swb_harmonic_calc_norm_envelop_fx`, `harm_bwe_fine_fx`,
//! `hvq_bwe_fine_fx`, `harm_bwe_fx`, `hvq_bwe_fx`, `noise_mix_fx`; TS 26.445 §6.2.2.3.8).

use crate::evs::basop::{div_32, l_extract_lc, madd_32_16, mult_32_16, mult_32_32};
use crate::evs::cnst::{
    EPSILLON_FX, HQ_24K40, HQ_CORE, HQ_GEN_SWB, HQ_HARMONIC, HQ_HVQ, HQ_NORMAL, L_HARMONIC_EXC,
    MAX_16, START_EXC,
};
use crate::evs::com::logqnorm::logqnorm;
use crate::evs::com::math_op::{isqrt, isqrt_lc};
use crate::evs::com::swb_bwe_com::calc_normal_length_32;
use crate::evs::com::tools::random;
use crate::evs::rom::{DICN_FX, HVQ_BWE_FAC_FX, INV_N_FX, INV_TBL_FX, SQAC_HEADROOM_FX};
use crate::itu::basic_ops::{
    abs_s, add, div_s, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult, l_negate, l_shl,
    l_shr, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{div_l, l_mac0, l_mult0, lshr, mpy_32_16_ss};

/// The harmonic excitation length `L_HARMONIC_EXC` as an array size.
const EXC: usize = L_HARMONIC_EXC as usize;

/// A band-table value or band index as a slice index (all non-negative by construction).
fn at(index: i16) -> usize {
    index.max(0) as usize
}

/// `dicn_fx[index]`. Norm indices are bounded to 0..=39 by the envelope decoder (out-of-range
/// deltas become 39 and flag a bit error); the clamp only keeps a corrupt index from reading
/// past the 40-entry table, which the reference would do.
fn dicn(index: i16) -> i32 {
    DICN_FX[index.clamp(0, 39) as usize]
}

/// `hq_swb_harmonic_calc_norm_envelop_fx`: the moving-average magnitude envelope (Q12) of the
/// first `swb_flength` coefficients of `l_swb_signal`, over a window of `l_swb_norm`
/// coefficients, shortened at both ends.
pub fn hq_swb_harmonic_calc_norm_envelop(
    l_swb_signal: &[i32],
    l_envelope: &mut [i32],
    l_swb_norm: i16,
    swb_flength: i16,
) {
    let lookback = shr(l_swb_norm, 1);
    let mut env_index = 0usize;
    let window = |from: usize, count: i16| -> i32 {
        let mut sum = i32::from(EPSILLON_FX);
        for &value in &l_swb_signal[from..from + at(count)] {
            sum = l_add(sum, l_abs(value));
        }
        sum
    };
    for n_freq in 0..lookback.max(0) {
        let n_lag_now = add(lookback, n_freq);
        l_envelope[env_index] = window(0, n_lag_now);
        env_index += 1;
    }

    let n_lag_now = l_swb_norm;
    for n_freq in 0..(i32::from(swb_flength) - i32::from(l_swb_norm)).max(0) {
        l_envelope[env_index] = window(n_freq as usize, n_lag_now);
        env_index += 1;
    }

    let mut i: i16 = 0;
    for n_freq in (swb_flength - l_swb_norm)..(swb_flength - lookback) {
        let n_lag_now = sub(l_swb_norm, i);
        l_envelope[env_index] = window(at(n_freq), n_lag_now);
        env_index += 1;
        i = add(i, 1);
    }
}

/// Divide `l_signal` by its envelope (`Div_32` on the normalised envelope, sign handled
/// outside) and round to Q15, as `harm_bwe_fine_fx` normalises the excitation.
fn harm_bwe_fine_normalise(l_signal: &[i32; EXC], envelope: &[i32; EXC], swb_signal: &mut [i16]) {
    for i in 0..EXC {
        let norm_signal = norm_l(envelope[i]);
        let (enve_hi, enve_lo) = l_extract_lc(l_shl(envelope[i], norm_signal));
        let quotient = if l_signal[i] > 0 {
            div_32(l_signal[i], enve_hi, enve_lo)
        } else {
            l_negate(div_32(l_negate(l_signal[i]), enve_hi, enve_lo))
        };
        swb_signal[i] = round_word(l_shl(quotient, norm_signal));
    }
}

/// `harm_bwe_fine_fx`: shape the coded bands `0..=last_sfm` (bands without bits stay zero) into
/// `coeff_out` (Q12), normalise the first `L_HARMONIC_EXC` coefficients by their envelope, and
/// replicate that excitation (forward, then mirrored) into `coeff_fine` above `last_sfm`.
pub fn harm_bwe_fine(
    r: &[i16],
    last_sfm: i16,
    high_sfm: i16,
    num_sfm: i16,
    norm: &[i16],
    sfm_start: &[i16],
    sfm_end: &[i16],
    prev_l_swb_norm: &mut i16,
    coeff: &[i16],
    coeff_out: &mut [i32],
    coeff_fine: &mut [i16],
) {
    let mut swb_signal = [0i16; EXC];
    let mut envelope = [0i32; EXC];
    let mut l_signal = [0i32; EXC];
    let mut norm_width: i16 = 64;

    // shape the spectrum
    for sfm in 0..=at(last_sfm) {
        let (start, end) = (at(sfm_start[sfm]), at(sfm_end[sfm]));
        if r[sfm] != 0 {
            let normq = l_add(0, dicn(norm[sfm]));
            for i in start..end {
                coeff_out[i] = l_shl(mult_32_16(normq, coeff[i]), 1); // Q12
            }
        } else {
            coeff_out[start..end.max(start)].fill(0);
        }
    }

    // excitation replication
    l_signal.copy_from_slice(&coeff_out[..EXC]);
    calc_normal_length_32(
        HQ_CORE,
        coeff_out,
        HQ_HARMONIC,
        -1,
        &mut norm_width,
        prev_l_swb_norm,
    );
    hq_swb_harmonic_calc_norm_envelop(&l_signal, &mut envelope, norm_width, L_HARMONIC_EXC);

    // normalise with the envelope
    harm_bwe_fine_normalise(&l_signal, &envelope, &mut swb_signal);

    let mut dst = at(sfm_end[at(last_sfm)]);
    let end = at(sfm_end[at(num_sfm - 1)]);
    let gap = sub(sfm_end[at(last_sfm)], sfm_end[at(high_sfm)]);
    // fill_spectrum_fx raises last_sfm to at least high_sfm, so the gap is never negative; the
    // clamp only keeps a direct caller from starting the copy before the excitation
    let mut src: isize = if gap <= L_HARMONIC_EXC - START_EXC {
        isize::from(START_EXC) + isize::from(gap.max(0))
    } else {
        isize::from(L_HARMONIC_EXC) - 1
    };
    let exc = isize::from(L_HARMONIC_EXC);
    let start_exc = isize::from(START_EXC);

    while dst < end {
        while dst < end && src < exc {
            coeff_fine[dst] = swb_signal[src as usize];
            dst += 1;
            src += 1;
        }
        src -= 1;
        while dst < end && src >= start_exc {
            coeff_fine[dst] = swb_signal[src as usize];
            dst += 1;
            src -= 1;
        }
        src += 1;
    }
}

/// `hvq_bwe_fine_fx`: normalise the first `L_HARMONIC_EXC` coefficients of `l_coeff` (Q12) by
/// their envelope to the HVQ fine structure (Q15), mark the decoded peaks in `peak_pos`, silence
/// the excitation above the last peak (but not below bin 181), and replicate excitation and peak
/// marks (forward, then mirrored) into `coeff_fine` (from 0) and `bwe_peaks` (from
/// `sfm_end[last_sfm]`).
pub fn hvq_bwe_fine(
    last_sfm: i16,
    num_sfm: i16,
    sfm_end: &[i16],
    peak_idx: &[i16],
    npeaks: i16,
    peak_pos: &mut [i16],
    prev_l_swb_norm: &mut i16,
    l_coeff: &[i32],
    bwe_peaks: &mut [i16],
    coeff_fine: &mut [i16],
) {
    let mut swb_signal = [0i16; EXC];
    let mut l_envelope = [0i32; EXC];
    let mut norm_width: i16 = 64;

    calc_normal_length_32(
        HQ_CORE,
        l_coeff,
        HQ_HVQ,
        -1,
        &mut norm_width,
        prev_l_swb_norm,
    );
    hq_swb_harmonic_calc_norm_envelop(l_coeff, &mut l_envelope, norm_width, L_HARMONIC_EXC);

    // normalise with the envelope
    for i in 0..EXC {
        let shift = norm_l(l_envelope[i]);
        let mut tmp = round_word(l_shl(l_envelope[i], shift)); // Q(-4+s)
                                                               // avoid division by zero
        if tmp == 0 {
            tmp = 1 << 14;
        }
        tmp = div_s(1 << 14, tmp); // Q(33-s)
        let (l_tmp, lsb) = mpy_32_16_ss(l_coeff[i], tmp); // Q(30-s)
        let shift2 = add(shift, 1);
        let tmp = round_word(l_shl(l_tmp, shift2)); // Q15
        swb_signal[i] = add(tmp, lshr(lsb as i16, sub(32, shift2)));
    }

    let mut dst = 0usize;
    let end = at(sub(sfm_end[at(num_sfm - 1)], sfm_end[at(last_sfm)]));

    for &index in &peak_idx[..at(npeaks)] {
        // hvq_dec_fx produces non-negative peak positions; a negative one would make the
        // reference write before peak_pos, so it is skipped
        if sub(index, L_HARMONIC_EXC) < 0 && index >= 0 {
            peak_pos[index as usize] = 1;
        }
    }

    // `while (i-- > 0)`: scan 200 down to 0 for the last peak, leaving i = -1 when none is found
    let mut i: i16 = sub(L_HARMONIC_EXC, 1);
    loop {
        let test = i > 0;
        i -= 1;
        if !test || sub(peak_pos[at(i)], 1) == 0 {
            break;
        }
    }
    if sub(i, 180) < 0 {
        i = 180;
    }
    let mut j = L_HARMONIC_EXC - 1;
    while j > i + 1 {
        swb_signal[at(j)] = 0;
        j -= 1;
    }

    let exc = isize::from(L_HARMONIC_EXC);
    let start_exc = isize::from(START_EXC);
    let mut src = start_exc;
    let mut peak_src = start_exc;
    let mut peak_dst = at(sfm_end[at(last_sfm)]);
    while dst < end {
        while dst < end && src < exc {
            coeff_fine[dst] = swb_signal[src as usize];
            dst += 1;
            src += 1;
            bwe_peaks[peak_dst] = peak_pos[peak_src as usize];
            peak_dst += 1;
            peak_src += 1;
        }
        peak_src -= 1;
        src -= 1;
        while dst < end && src >= start_exc {
            coeff_fine[dst] = swb_signal[src as usize];
            dst += 1;
            src -= 1;
            bwe_peaks[peak_dst] = peak_pos[peak_src as usize];
            peak_dst += 1;
            peak_src -= 1;
        }
        peak_src += 1;
        src += 1;
    }
}

/// The noise-level smoothing `harm_bwe_fx` and `hvq_bwe_fx` share: 0.9 of the previous frame's
/// level plus 0.1 of this frame's, raised by 4 when the previous frame was a normal or generic
/// HQ frame and the level is below 0.25.
fn smooth_noise_level(noise_level: &mut [i16], prev_noise_level: &[i16], prev_hq_mode: i16) {
    for k in 0..2 {
        let l_tmp = l_mult(29491, prev_noise_level[k]);
        noise_level[k] = round_word(l_mac(l_tmp, 3277, noise_level[k])); // Q15
    }
    if prev_hq_mode == HQ_NORMAL || sub(prev_hq_mode, HQ_GEN_SWB) == 0 {
        for level in noise_level.iter_mut().take(2) {
            if sub(*level, 8192) < 0 {
                *level = shl(*level, 2);
            }
        }
    }
}

/// The cross-fade over the 32 bins around `sfm_end[last_sfm] + L_HARMONIC_EXC - START_EXC`,
/// both directions weighted by `hvq_bwe_fac_fx`.
fn bwe_fade(coeff_out: &mut [i32], centre: usize) {
    for (i, &fac) in HVQ_BWE_FAC_FX.iter().enumerate() {
        coeff_out[centre + i] = mult_32_16(coeff_out[centre + i], fac);
        coeff_out[centre - 1 - i] = mult_32_16(coeff_out[centre - 1 - i], fac);
    }
}

/// `harm_bwe_fx`: the harmonic-mode BWE. Bands without bits up to `last_sfm` get the
/// noise-filled spectrum `coeff` scaled by their norm; every band above `last_sfm` gets the fine
/// structure `coeff_fine` normalised to unit energy, mixed with noise by the smoothed noise
/// levels and scaled by its norm. `coeff_out` is Q12; the FB layout (33 bands) clears 800..960.
pub fn harm_bwe(
    coeff_fine: &[i16],
    coeff: &[i16],
    num_sfm: i16,
    sfm_start: &[i16],
    sfm_end: &[i16],
    last_sfm: i16,
    r: &[i16],
    prev_hq_mode: i16,
    norm: &[i16],
    noise_level: &mut [i16],
    prev_noise_level: &mut [i16],
    bwe_seed: &mut i16,
    coeff_out: &mut [i32],
) {
    for sfm in 0..=at(last_sfm) {
        if r[sfm] == 0 {
            let normq = dicn(norm[sfm]); // Q14
            for i in at(sfm_start[sfm])..at(sfm_end[sfm]) {
                coeff_out[i] = l_shl(mult_32_16(normq, coeff[i]), 1); // Q12
            }
        }
    }
    noise_level[1] = noise_level[0];

    // shaping the BWE spectrum further by envelopes and noise factors
    smooth_noise_level(noise_level, prev_noise_level, prev_hq_mode);

    for i in at(add(last_sfm, 1))..at(num_sfm) {
        harm_bwe_band(
            coeff_fine,
            sfm_start[i],
            sfm_end[i],
            i,
            norm,
            noise_level,
            bwe_seed,
            coeff_out,
        );
    }

    prev_noise_level[0] = noise_level[0];
    prev_noise_level[1] = noise_level[1];

    bwe_fade(
        coeff_out,
        at(add(sfm_end[at(last_sfm)], L_HARMONIC_EXC - START_EXC)),
    );
    if sub(num_sfm, 33) == 0 {
        coeff_out[800..960].fill(0);
    }
}

/// One band `i` above `last_sfm` of `harm_bwe_fx`.
fn harm_bwe_band(
    coeff_fine: &[i16],
    band_start: i16,
    band_end: i16,
    i: usize,
    norm: &[i16],
    noise_level: &[i16],
    bwe_seed: &mut i16,
    coeff_out: &mut [i32],
) {
    let (start, end) = (at(band_start), at(band_end));
    let mut e_l: i32 = l_add(0, 1);
    for &fine in &coeff_fine[start..end.max(start)] {
        let l_tmp = l_mult0(fine, fine); // Q30
        e_l = l_add(e_l, l_shr(l_tmp, 6)); // Q24
    }

    let normq = l_add(0, dicn(norm[i]));

    let mut alfa = noise_level[0];
    if i > 27 {
        alfa = noise_level[1];
    }

    let band_width = sub(band_end, band_start);
    let mut exp1 = norm_l(e_l);
    if exp1 == 0 {
        e_l = mult_32_16(e_l, INV_TBL_FX[at(band_width)]); // Q24
        let tmp = div_l(e_l, sub(32767, alfa)).max(1); // Q8
        let l_tmp = l_deposit_h(tmp); // Q24
        e_l = isqrt(l_tmp); // Q19
    } else {
        exp1 = sub(exp1, 1);
        e_l = mult_32_16(l_shl(e_l, exp1), INV_TBL_FX[at(band_width)]); // Q24+exp1
        let tmp = div_l(e_l, sub(32767, alfa)).max(1); // Q8+exp1
        let l_tmp = l_shl(l_deposit_l(tmp), sub(16, exp1)); // Q24
        e_l = isqrt(l_tmp); // Q19
    }

    let mut exp1 = norm_s(alfa);
    let tmp1 = shl(alfa, exp1);
    exp1 = add(1, exp1);
    let tmp1 = div_s(16384, tmp1.max(16384));
    let l_tmp2 = isqrt_lc(l_deposit_h(tmp1), &mut exp1);
    let beta = shr(round_word(l_shl(l_tmp2, exp1)), 1); // Q15

    for sfm in start..end.max(start) {
        let mut l_tmp = mult_32_16(e_l, coeff_fine[sfm]); // Q19
        l_tmp = l_shl(l_tmp, 9); // Q28
        let tmp = random(bwe_seed); // Q15
        let l_tmp2 = l_shr(l_mult(beta, tmp), 3); // Q28
        l_tmp = l_add(l_tmp, l_tmp2); // Q28
        coeff_out[sfm] = l_shl(mult_32_32(l_tmp, normq), 1); // Q12
    }
}

/// `noise_mix_fx`: for `i` in `istart..iend`, `L_coeff_out[i] = ((1 - noise_level) ·
/// coeff_fine[i] · L_E + noise_level · random) · normq` in Q`qout`, with `coeff_fine` in Q`qin`
/// and `L_E` Q17. The reference passes `&coeff_fine[-offset]`; here `coeff_fine_at` is the
/// (possibly negative) index of that pointer in `coeff_fine`, so `coeff_fine[i]` is
/// `coeff_fine[coeff_fine_at + i]`.
pub fn noise_mix(
    coeff_fine: &[i16],
    coeff_fine_at: isize,
    l_e: i32,
    l_normq: i32,
    seed: &mut i16,
    istart: i16,
    iend: i16,
    noise_level: i16,
    l_coeff_out: &mut [i32],
    qin: i16,
    qout: i16,
) {
    let n_c = sub(MAX_16, noise_level); // Q15
    for i in istart..iend {
        let fine = coeff_fine[(coeff_fine_at + isize::from(i)) as usize];
        l_coeff_out[at(i)] = noise_mix_bin(l_e, fine, n_c, noise_level, l_normq, seed, qin, qout);
    }
}

/// One output bin of the noise mix (the body `noise_mix_fx` and the special 24.4 kbit/s
/// cross-fade of `hvq_bwe_fx` share, with the norm already chosen).
fn noise_mix_bin(
    l_e: i32,
    fine: i16,
    n_c: i16,
    noise_level: i16,
    l_normq: i32,
    seed: &mut i16,
    qin: i16,
    qout: i16,
) -> i32 {
    let (l_tmp0, _) = mpy_32_16_ss(l_e, fine); // Qin+2
    let (mut l_tmp0, lsb) = mpy_32_16_ss(l_tmp0, n_c); // Qin+2
    if l_tmp0 != 0 {
        // normalise with 1 bit headroom for the addition
        let mut tmp = 30 - (qin + 2); // assuming fixed Q values
        tmp = norm_l(l_tmp0).min(tmp);
        tmp = sub(tmp, 1);

        l_tmp0 = l_add(
            l_shl(l_tmp0, tmp),
            l_deposit_l(lshr(lsb as i16, sub(16, tmp))),
        ); // Qin+2+tmp
        l_tmp0 = l_add(
            l_tmp0,
            l_shr(l_mult0(noise_level, random(seed)), sub(30 - (qin + 2), tmp)),
        ); // Qin+2+tmp
        let tmp = round_word(l_shl(l_tmp0, 27 - (qin + 2) - tmp)); // Q11
        let (l_tmp0, lsb) = mpy_32_16_ss(l_normq, tmp); // Q10
        l_add(
            l_shl(l_tmp0, qout - 10),
            l_deposit_l(lshr(lsb as i16, 10 + 16 - qout)),
        ) // Qout
    } else {
        let l_tmp0 = l_mult0(noise_level, random(seed)); // Q30
        let tmp = round_word(l_tmp0); // Q14
        let (l_tmp0, _) = mpy_32_16_ss(l_normq, tmp); // Q13
        l_shr(l_tmp0, 13 - qout) // Qout
    }
}

/// `L_E` of `hvq_bwe_fx`: `sqrt(band_size / Σ coeff_fine²)` (Q17) over `istart..iend` of the fine
/// structure (Q`qin`, read at `i - offset`), with the headroom shift `sqac_headroom_fx` gives.
fn hvq_bwe_band_energy(coeff_fine: &[i16], offset: usize, istart: i16, iend: i16, qin: i16) -> i32 {
    let (start, end) = (at(istart), at(iend).max(at(istart)));
    let mut tmp: i16 = 1;
    for i in start..end {
        tmp = tmp.max(abs_s(coeff_fine[i - offset]));
    }
    let band_size = sub(iend, istart);
    // headroom for square and accumulate
    let shift = sub(norm_s(tmp), SQAC_HEADROOM_FX[at(band_size)]);
    let mut l_e: i32 = 1;
    for i in start..end {
        let coeff_s = shl(coeff_fine[i - offset], shift); // Q15 + shift
        l_e = l_mac0(l_e, coeff_s, coeff_s); // Q2*(qin + shift)
    }
    let power_shift = shl(shift, 1);
    l_e = l_shr(l_e, sub(power_shift, 28 - 2 * qin)); // Q28
    l_e = mult_32_16(l_e, INV_TBL_FX[at(band_size)]); // Q28
                                                      // to avoid overflow in Isqrt()
    if l_e == 0 {
        l_e = 1;
    }
    isqrt(l_e) // Q17
}

/// `hvq_bwe_fx`: the HVQ BWE above `last_sfm`. `l_coeff_out` (Q`qout`) is both the reference's
/// `L_coeff` input and its `L_coeff_out` output: its only caller (`fill_spectrum_fx`) passes the
/// same buffer for both, and the function reads `L_coeff[i]` only to copy it to
/// `L_coeff_out[i]` (bands with bits), so those bins keep their value here. `coeff_fine` (Q`qin`)
/// starts at bin `sfm_end[last_sfm]`. Updates `norm[last_sfm]` from the decoded spectrum, the
/// noise levels and the seed.
pub fn hvq_bwe(
    coeff_fine: &[i16],
    sfm_start: &[i16],
    sfm_end: &[i16],
    sfm_len: &[i16],
    last_sfm: i16,
    prev_hq_mode: i16,
    bwe_peaks: &[i16],
    bin_th: i16,
    num_sfm: i16,
    core_brate: i32,
    r: &[i16],
    norm: &mut [i16],
    noise_level: &mut [i16],
    prev_noise_level: &mut [i16],
    bwe_seed: &mut i16,
    l_coeff_out: &mut [i32],
    qin: i16,
    qout: i16,
) {
    let offset = sfm_end[at(last_sfm)];
    let bwe_noise_th = add(bin_th, shr(sub(sfm_end[at(sub(num_sfm, 1))], bin_th), 1));
    let ls = at(last_sfm);
    norm[ls] = logqnorm(&l_coeff_out[at(sfm_start[ls])..], qout, 40, sfm_len[ls], 0);

    // shaping the BWE spectrum further by envelopes and noise factors
    smooth_noise_level(noise_level, prev_noise_level, prev_hq_mode);

    let mut norm_ind = add(last_sfm, 1);
    if core_brate == i32::from(HQ_24K40) {
        hvq_bwe_24k4(
            coeff_fine,
            offset,
            sfm_start,
            sfm_end,
            norm_ind,
            norm,
            noise_level[0],
            bwe_seed,
            l_coeff_out,
            qin,
            qout,
        );
        norm_ind = add(norm_ind, 2);
    }

    while norm_ind < num_sfm {
        let b = at(norm_ind);
        if r[b] == 0 {
            hvq_bwe_band(
                coeff_fine,
                offset,
                sfm_start,
                sfm_end,
                sfm_len,
                last_sfm,
                bwe_peaks,
                bwe_noise_th,
                num_sfm,
                norm_ind,
                norm,
                noise_level,
                bwe_seed,
                l_coeff_out,
                qin,
                qout,
            );
        } else {
            // R[norm_ind] > 0: L_coeff_out[i] = L_coeff[i] for the band, scaling already applied;
            // the caller aliases L_coeff and L_coeff_out, so the bins are left as they are
        }
        norm_ind += 1;
    }

    prev_noise_level[0] = noise_level[0];
    prev_noise_level[1] = noise_level[1];
    bwe_fade(
        l_coeff_out,
        at(add(sfm_end[ls], L_HARMONIC_EXC - START_EXC)),
    );
}

/// The first two bands above `last_sfm` at 24.4 kbit/s in `hvq_bwe_fx`: one energy over both,
/// noise mix up to bin 240 with the first band's smoothed norm, a 32-bin linear cross-fade of the
/// two norms (240..272), then the second band's norm up to its end.
fn hvq_bwe_24k4(
    coeff_fine: &[i16],
    offset: i16,
    sfm_start: &[i16],
    sfm_end: &[i16],
    norm_ind: i16,
    norm: &[i16],
    noise_level: i16,
    bwe_seed: &mut i16,
    l_coeff_out: &mut [i32],
    qin: i16,
    qout: i16,
) {
    let n = at(norm_ind);
    let fine_at = -isize::from(offset);
    // the peak flag the reference computes over these bands is overwritten before it is read
    let l_e = hvq_bwe_band_energy(coeff_fine, at(offset), sfm_start[n], sfm_end[n + 1], qin);

    let l_tmp0 = l_add(dicn(norm[n]), 0);
    let l_tmp1 = l_add(dicn(norm[n + 1]), 0);
    let l_normq = madd_32_16(
        madd_32_16(mult_32_16(l_tmp0, 26214), dicn(norm[n - 1]), 3277),
        l_tmp1,
        3277,
    ); // Q14
    let l_tmp_norm = madd_32_16(
        madd_32_16(mult_32_16(l_tmp1, 26214), dicn(norm[n + 2]), 3277),
        l_tmp0,
        3277,
    ); // Q14

    let istart = sfm_start[n];
    // iend = istart + sfm_len[norm_ind]/2
    let iend: i16 = 240;
    noise_mix(
        coeff_fine,
        fine_at,
        l_e,
        l_normq,
        bwe_seed,
        istart,
        iend,
        noise_level,
        l_coeff_out,
        qin,
        qout,
    );

    // N = sfm_len[norm_ind]/2 + sfm_len[norm_ind+1]/2 - 1
    let mut j: i16 = 0;
    let mut j_n: i16 = 31;
    let istart = iend;
    // iend = sfm_start[norm_ind+1] + sfm_len[norm_ind+1]/2
    let iend: i16 = 272;

    // special case that is not handled by noise_mix_fx()
    let n_c = sub(MAX_16, noise_level); // Q15
    for i in istart..iend {
        let l_norm_mix = madd_32_16(
            mult_32_16(l_normq, INV_N_FX[at(j_n)]),
            l_tmp_norm,
            INV_N_FX[at(j)],
        ); // Q14
        j = add(j, 1);
        j_n = sub(j_n, 1);
        let fine = coeff_fine[(fine_at + isize::from(i)) as usize];
        l_coeff_out[at(i)] =
            noise_mix_bin(l_e, fine, n_c, noise_level, l_norm_mix, bwe_seed, qin, qout);
    }

    let istart = iend;
    let iend = sfm_end[n + 1];
    noise_mix(
        coeff_fine,
        fine_at,
        l_e,
        l_tmp_norm,
        bwe_seed,
        istart,
        iend,
        noise_level,
        l_coeff_out,
        qin,
        qout,
    );
}

/// One band without bits (`R[norm_ind] == 0`) of the generic band loop of `hvq_bwe_fx`.
fn hvq_bwe_band(
    coeff_fine: &[i16],
    offset: i16,
    sfm_start: &[i16],
    sfm_end: &[i16],
    sfm_len: &[i16],
    last_sfm: i16,
    bwe_peaks: &[i16],
    bwe_noise_th: i16,
    num_sfm: i16,
    norm_ind: i16,
    norm: &[i16],
    noise_level: &[i16],
    bwe_seed: &mut i16,
    l_coeff_out: &mut [i32],
    qin: i16,
    qout: i16,
) {
    let b = at(norm_ind);
    let fine_at = -isize::from(offset);
    let mut peak_band: i16 = 0;
    for &peak in &bwe_peaks[at(sfm_start[b])..at(sfm_end[b])] {
        if peak != 0 {
            peak_band = 1;
        }
    }

    let mut istart = sfm_start[b];
    let mut iend = sfm_end[b];
    let last_norm_ind = sub(num_sfm, 1);
    if sub(peak_band, 1) == 0
        && sub(norm_ind, add(last_sfm, 1)) > 0
        && sub(norm_ind, last_norm_ind) < 0
    {
        istart = sub(istart, shr(sfm_len[b - 1], 1));
        iend = add(iend, shr(sfm_len[b + 1], 1));
    }
    let l_e = hvq_bwe_band_energy(coeff_fine, at(offset), istart, iend, qin);

    let l_normq = if peak_band != 0 {
        if sub(add(norm_ind, 2), num_sfm) > 0 {
            madd_32_16(mult_32_16(dicn(norm[b]), 27853), dicn(norm[b - 1]), 4915)
        // Q14
        } else {
            madd_32_16(
                madd_32_16(mult_32_16(dicn(norm[b]), 26214), dicn(norm[b + 1]), 3277),
                dicn(norm[b - 1]),
                3277,
            ) // Q14
        }
    } else {
        let low = norm_ind;
        let high = add(norm_ind, 1).min(last_norm_ind);
        let mut sel_norm = norm[b - 1];
        for j in low..=high {
            if sub(norm[at(j)], sel_norm) > 0 {
                sel_norm = norm[at(j)];
            }
        }
        dicn(sel_norm)
    };

    let mut iend = sfm_end[b].min(bwe_noise_th);
    if sub(iend, sfm_start[b]) > 0 {
        noise_mix(
            coeff_fine,
            fine_at,
            l_e,
            l_normq,
            bwe_seed,
            sfm_start[b],
            iend,
            noise_level[0],
            l_coeff_out,
            qin,
            qout,
        );
    } else {
        iend = sfm_end[b];
        noise_mix(
            coeff_fine,
            fine_at,
            l_e,
            l_normq,
            bwe_seed,
            sfm_start[b],
            iend,
            noise_level[1],
            l_coeff_out,
            qin,
            qout,
        );
    }
    // noise mix up to the threshold done
    if sub(iend, bwe_noise_th) == 0 {
        noise_mix(
            coeff_fine,
            fine_at,
            l_e,
            l_normq,
            bwe_seed,
            iend,
            sfm_end[b],
            noise_level[1],
            l_coeff_out,
            qin,
            qout,
        );
    }
}
