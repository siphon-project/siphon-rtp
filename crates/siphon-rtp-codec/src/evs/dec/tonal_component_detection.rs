//! Tonal component detection for the TCX tonal concealment (TS 26.442
//! `lib_dec/TonalComponentDetection.c`; TS 26.445 §5.4.3.6).
//!
//! The last good spectrum is searched for peaks (`findCandidates`), the pitch refines the
//! thresholds the second-last power spectrum is then searched with (`RefineThresholdsUsingPitch`,
//! `findTonalComponents`).

use crate::evs::basop::{mpy_32_16_1, mpy_32_32};
use crate::evs::cnst::{
    ALLOWED_SIDE_LOBE_FLUCTUATION, ALLOWED_SIDE_LOBE_FLUCTUATION_EXP, BIG_THRESHOLD, GROUP_LENGTH,
    LAST_HARMONIC_POS_TO_CHECK, L_FRAME_MAX, MAX_NUMBER_OF_IDX, MAX_PEAKS_FROM_PITCH,
    SMALL_THRESHOLD, UNREACHABLE_THRESHOLD,
};
use crate::evs::com::basop_util::{basop_util_divide_mant_exp, imult1616};
use crate::evs::com::tcx_utils::mdct_shaping_16;
use crate::evs::com::tools::{set16, set32, sort};
use crate::evs::rom::INVINTTABLE;
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_l, l_mult, l_shl, l_shr,
    l_sub, mult, mult_r, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::lshr;

/// `LEVEL_EXP`.
const LEVEL_EXP: i16 = 3;

/// `calcPseudoSpec`: the power spectrum estimated from the MDCT spectrum alone, the MDST being
/// estimated from the two neighbouring MDCT lines.
fn calc_pseudo_spec(
    mdct_spec: &[i32],
    mdct_spec_exp: i16,
    n_samples: i16,
    floor_power_spectrum: i16,
    power_spec: &mut [i32],
    power_spec_exp: &mut i16,
) {
    *power_spec_exp = add(add(mdct_spec_exp, mdct_spec_exp), 5);

    let mut k = sub(31, *power_spec_exp);
    // If the signal is below the floor, special care is needed for *powerSpec_exp.
    // The 3 is the extra headroom for the MA filter in getEnvelope.
    if sub(add(16 - 3, norm_s(floor_power_spectrum)), k) < 0 {
        k = add(16 - 3, norm_s(floor_power_spectrum));
        let l_tmp_floor = l_shl(l_deposit_l(floor_power_spectrum), k);
        set32(power_spec, l_tmp_floor, n_samples);
        *power_spec_exp = sub(31, k);
    } else {
        let l_tmp_floor = l_shl(l_deposit_l(floor_power_spectrum), k);

        let tmp_loop = sub(n_samples, 2);
        k = 1;
        while k <= tmp_loop {
            let ku = k as usize;
            // An MDST estimate.
            let mut x = l_sub(l_shr(mdct_spec[ku + 1], 1), l_shr(mdct_spec[ku - 1], 1));

            x = l_shr(mpy_32_32(x, x), 3);

            let mut l_tmp = mpy_32_32(mdct_spec[ku], mdct_spec[ku]);
            l_tmp = l_shr(l_tmp, 5);

            power_spec[ku] = l_tmp_floor.max(l_add(l_tmp, x));
            k += 1;
        }
    }

    power_spec[0] = l_shr(power_spec[1], 1);
    let last = n_samples as usize - 1;
    power_spec[last] = l_shr(power_spec[last - 1], 1);
}

/// `getEnvelope`: moving-average envelope (`envelope`) and 3-tap smoothed spectrum of the power
/// spectrum, both in `powerSpec_exp + LEVEL_EXP`.
fn get_envelope(
    n_samples: i16,
    power_spec: &[i32],
    f0: i16,
    envelope: &mut [i32],
    smoothed_spectrum: &mut [i32],
) {
    let n_filter_length: i16 = if f0 == 0 {
        15
    } else if f0 <= 10240 {
        // 10.0 in Q10
        11
    } else if f0 >= 22528 {
        // 22.0 in Q10. For F0 >= 22 the peak is isolated well enough with the filter length of
        // 23. This case is not triggered due to the limit of pit_min, but is kept for security.
        23
    } else {
        // 1+2*(int)(F0/2); F0 is Q10
        shr(f0, 10) | 1
    };

    let n_half_filter_length = shr(n_filter_length, 1);
    let n1 = add(n_half_filter_length, 1);
    let n_second_half_filter_length = sub(n_filter_length, n_half_filter_length);
    let n2 = sub(n_second_half_filter_length, 1);

    let mut sum: i32 = 0;
    let level: i16 = 31089; // LEVEL_ABOVE_ENVELOPE, Q12

    for &line in &power_spec[..n2 as usize] {
        sum = l_add(sum, line);
    }
    // No need to re-init the pointer for powerSpec[i+n2]: continue from the previous loop.
    for i in 0..n1 {
        let iu = i as usize;
        sum = l_add(sum, power_spec[iu + n2 as usize]);
        let tmp = mpy_32_16_1(sum, level);
        envelope[iu] = mpy_32_16_1(tmp, INVINTTABLE[(i + n_second_half_filter_length) as usize]);
    }

    let inv_len = mult_r(level, INVINTTABLE[n_filter_length as usize]);
    let mut i = n1;
    while i < n_samples - n2 {
        let iu = i as usize;
        sum = l_add(
            sum,
            l_sub(power_spec[iu + n2 as usize], power_spec[iu - n1 as usize]),
        );
        envelope[iu] = mpy_32_16_1(sum, inv_len);
        i += 1;
    }

    i = n_samples - n2;
    while i < n_samples {
        let iu = i as usize;
        sum = l_sub(sum, power_spec[iu - n1 as usize]);
        let tmp = mpy_32_16_1(sum, level);
        envelope[iu] = mpy_32_16_1(
            tmp,
            INVINTTABLE[(n_samples - (i - n_half_filter_length)) as usize],
        );
        i += 1;
    }

    for i in 1..(n_samples as usize - 1) {
        smoothed_spectrum[i] = l_add(
            l_add(
                mpy_32_16_1(power_spec[i - 1], 3072), // 0.75 in Q12
                l_shr(power_spec[i], LEVEL_EXP),
            ),
            mpy_32_16_1(power_spec[i + 1], 3072),
        );
    }

    let last = n_samples as usize - 1;
    smoothed_spectrum[0] = l_add(
        mpy_32_16_1(power_spec[1], 3072),
        l_shr(power_spec[0], LEVEL_EXP),
    );
    smoothed_spectrum[last] = l_add(
        mpy_32_16_1(power_spec[last - 1], 3072),
        l_shr(power_spec[last], LEVEL_EXP),
    );
}

/// `findStrongestHarmonics`: the `MAX_PEAKS_FROM_PITCH` harmonics of `F0` with the largest power,
/// sorted by harmonic number into `p_harmonic_indexes`, their count into `pn_harmonics`.
fn find_strongest_harmonics(
    power_spectrum: &[i32],
    f0: i16,
    n_total_harmonics: i16,
    p_harmonic_indexes: &mut [i16],
    pn_harmonics: &mut i16,
) {
    let mut peaks = [0_i32; MAX_PEAKS_FROM_PITCH as usize];
    let mut n_peaks: i16 = 0;
    let mut i_smallest_peak: i16 = 0;
    let mut smallest_peak: i32 = 0x7fff_ffff;

    let n_peaks_to_check = n_total_harmonics.min(MAX_PEAKS_FROM_PITCH + 1);

    let mut i: i16 = 1;
    while i < n_peaks_to_check {
        // k = (int)(i*F0); the reference asserts 0 < k < 2*LAST_HARMONIC_POS_TO_CHECK and
        // k < nSamples.
        let k = extract_h(l_shl(l_mult(i, f0), 5));
        let new_peak = l_add(power_spectrum[k as usize], 0);

        peaks[n_peaks as usize] = new_peak;
        p_harmonic_indexes[n_peaks as usize] = i;

        if l_sub(new_peak, smallest_peak) <= 0 {
            i_smallest_peak = n_peaks;
            smallest_peak = l_add(new_peak, 0);
        }

        n_peaks = add(n_peaks, 1);
        i += 1;
    }

    while i < n_total_harmonics {
        let k = extract_h(l_shl(l_mult(i, f0), 5));
        let new_peak = l_add(power_spectrum[k as usize], 0);

        if l_sub(new_peak, smallest_peak) > 0 {
            peaks[i_smallest_peak as usize] = new_peak;
            p_harmonic_indexes[i_smallest_peak as usize] = i;
            smallest_peak = l_add(new_peak, 0);

            for l in 0..MAX_PEAKS_FROM_PITCH {
                if peaks[l as usize] <= smallest_peak {
                    i_smallest_peak = l;
                    smallest_peak = l_add(peaks[l as usize], 0);
                }
            }
        }
        i += 1;
    }

    sort(p_harmonic_indexes, 0, sub(n_peaks, 1));

    *pn_harmonics = n_peaks;
}

/// `CorrectF0`: use the new F0 for which the harmonics are most common in `pHarmonicIndexes`.
/// `p_f0` is Q10, range {0}, [4..18).
fn correct_f0(p_harmonic_indexes: &[i16], n_harmonics: i16, p_f0: &mut i16) {
    let mut f0 = *p_f0;

    if f0 > 0 && n_harmonics != 0 {
        // The reference leaves diff/sortedDiff uninitialised past nHarmonics-1 entries and, for
        // nHarmonics == 1, reads sortedDiff[0] uninitialised; the decoder never gets there
        // (nHarmonics >= 2 for every pitch it feeds), so zero-fill mirrors the in-domain run.
        let mut diff = [0_i16; MAX_PEAKS_FROM_PITCH as usize - 1];
        let mut sorted_diff = [0_i16; MAX_PEAKS_FROM_PITCH as usize - 1];

        let tmp = sub(n_harmonics, 1);
        for i in 0..tmp as usize {
            diff[i] = sub(p_harmonic_indexes[i + 1], p_harmonic_indexes[i]);
            sorted_diff[i] = diff[i];
        }
        sort(&mut sorted_diff, 0, sub(n_harmonics, 1 + 1));
        let mut i_most_common_diff = sorted_diff[0];
        let mut n_same_diff: i16 = 1;
        let mut i: i16 = 1;
        if sub(imult1616(sorted_diff[0], p_harmonic_indexes[0]), 1) == 0 {
            // Find how many distances between peaks have length 1
            while i < tmp {
                if sub(sorted_diff[i as usize], 1) == 0 {
                    n_same_diff = add(n_same_diff, 1);
                }
                i += 1;
            }
        }
        let mut n_most_common_diff = n_same_diff;

        // If there are at least 3 distances between peaks with length 1 and if the 1st harmonic is
        // in pHarmonicIndexes then keep the original F0. Otherwise find the most common distance
        // between peaks.
        if sub(n_same_diff, 3) < 0 {
            // Find the most common difference
            i = n_same_diff;
            while i < tmp {
                let iu = i as usize;
                if sub(sorted_diff[iu], sorted_diff[iu - 1]) == 0 {
                    n_same_diff = add(n_same_diff, 1);
                } else {
                    // A longer run wins; of two runs of the same length the one whose difference is
                    // closer to the first harmonic's index does.
                    if sub(n_same_diff, n_most_common_diff) > 0
                        || (sub(n_same_diff, n_most_common_diff) == 0
                            && abs_s(sub(i_most_common_diff, p_harmonic_indexes[0]))
                                > abs_s(sub(sorted_diff[iu - 1], p_harmonic_indexes[0])))
                    {
                        n_most_common_diff = n_same_diff;
                        i_most_common_diff = sorted_diff[iu - 1];
                    }
                    n_same_diff = 1;
                }
                i += 1;
            }
            if sub(n_same_diff, n_most_common_diff) > 0 {
                n_most_common_diff = n_same_diff;
                i_most_common_diff = sorted_diff[(n_harmonics - 2) as usize];
            }
        }

        // If there are enough peaks at the same distance
        if sub(n_most_common_diff, MAX_PEAKS_FROM_PITCH / 2) >= 0 {
            let mut i_mult: i16 = 1;
            i = 0;
            while i < tmp {
                let iu = i as usize;
                if sub(diff[iu], i_most_common_diff) == 0 {
                    i_mult = p_harmonic_indexes[iu];
                    break;
                }
                // for rare cases of octave mismatch or missing harmonics
                if sub(sub(n_harmonics, 2), i) > 0
                    && sub(diff[iu], diff[iu + 1]) == 0
                    && sub(add(diff[iu], diff[iu + 1]), i_most_common_diff) == 0
                {
                    i_mult = p_harmonic_indexes[iu];
                    break;
                }
                i += 1;
            }

            // If the real F0 is much higher than the original F0 from the pitch
            if sub(i_mult, 3) <= 0 {
                // Use iMostCommonDiff, because the lowest pHarmonicIndexes[i] (which is equal to
                // iMult) may not correspond to the new F0, but to its multiple.
                f0 = round_word(l_shl(l_mult(i_most_common_diff, f0), 15));
            } else {
                f0 = 0;
            }
        } else if sub(i_most_common_diff, 1) > 0 || sub(n_most_common_diff, 3) < 0 {
            // Otherwise, if there are at least 3 distances between peaks with length 1 and the 1st
            // harmonic is in pHarmonicIndexes keep the original F0; otherwise don't use F0.
            // Not enough peaks at the same distance => don't use the pitch.
            f0 = 0;
        }
        *p_f0 = f0;
    }
}

/// `GetF0`: the F0 (Q10) of the last pitch lag (Q16), before (`p_orig_f0`) and after (`p_f0`) the
/// correction from the strongest harmonics of the power spectrum.
fn get_f0(
    n_samples: i16,
    n_samples_core: i16,
    power_spectrum: &[i32],
    pitch_lag: i32,
    p_orig_f0: &mut i16,
    p_f0: &mut i16,
) {
    let mut rgi_strong_harmonics = [0_i16; MAX_PEAKS_FROM_PITCH as usize];
    let mut n_total_harmonics: i16 = 0;
    let mut n_strong_harmonics: i16 = 0;
    let mut tmp: i16 = 0;

    // Use only F0 >= 100 Hz
    if pitch_lag > 0 && sub(round_word(pitch_lag), shr(n_samples_core, 1)) <= 0 {
        // "halfPitchLag" in the float code: read as Q5 for comparison to halfpitchlag. No division
        // by 2 here, it is done in the following division; the left shift before rounding
        // preserves accuracy and is accommodated in the following division as well.
        let tmp_pitch_lag = round_word(l_shl(pitch_lag, 4));

        // pF0 = nSamplesCore/tmpPitchLag; pF0 is Q15
        basop_util_divide_mant_exp(
            n_samples_core,
            0,
            tmp_pitch_lag,
            -(1 + 4), // division by 2 + accuracy-preserving left shift
            p_f0,
            &mut tmp,
        );
        *p_f0 = shr(*p_f0, sub(5, tmp)); // Q10 without scaling factor
        *p_orig_f0 = *p_f0; // Q10
        tmp = 2 * LAST_HARMONIC_POS_TO_CHECK;
        if sub(n_samples, 2 * LAST_HARMONIC_POS_TO_CHECK) < 0 {
            tmp = n_samples;
        }
        let numerator = tmp;
        basop_util_divide_mant_exp(numerator, 15, *p_f0, 5, &mut n_total_harmonics, &mut tmp);
        n_total_harmonics = shl(n_total_harmonics, sub(tmp, 15));

        // Get in rgiStrongHarmonics all i for which i*F0 are the strongest harmonics
        find_strongest_harmonics(
            power_spectrum,
            *p_f0,
            n_total_harmonics,
            &mut rgi_strong_harmonics,
            &mut n_strong_harmonics,
        );

        correct_f0(&rgi_strong_harmonics, n_strong_harmonics, p_f0);
    } else {
        *p_f0 = 0;
        *p_orig_f0 = 0;
    }
}

/// `modifyThreshold`: threshold (Q10) for the bins around the `i`-th harmonic of `F0` (Q10).
fn modify_threshold(i: i16, f0: i16, threshold: i16, threshold_modification: &mut [i16]) {
    let harmonic = l_mult(shl(i, 5), f0); // Q0 * Q10 = 15Q16
    let k = extract_h(harmonic); // Q0
    let fractional = lshr(extract_l(harmonic), 1); // fractional part of i*F0, Q15
                                                   // threshold if the centre of the peak is between k-1 and k, threshold+2 if it is between k
                                                   // and k+1 (Q10)
    let two_times_fract = mult(2048, fractional);

    // k-1 >= 0 and k+1 < nSamples for every F0 the decoder produces ([4..18) in Q10 units of
    // bins, harmonics up to LAST_HARMONIC_POS_TO_CHECK); an index outside the array is left out
    // rather than written out of bounds.
    let mut store = |index: i16, value: i16| {
        if let Some(slot) = usize::try_from(index)
            .ok()
            .and_then(|index| threshold_modification.get_mut(index))
        {
            *slot = value;
        }
    };
    store(k, threshold);
    store(sub(k, 1), add(threshold, two_times_fract));
    store(add(k, 1), add(threshold, sub(2048, two_times_fract)));
}

/// `modifyThresholds`: lower the thresholds around the harmonics of `F0` (Q10) and of the pitch's
/// own `origF0` (Q10).
fn modify_thresholds(f0: i16, orig_f0: i16, threshold_modification: &mut [i16]) {
    if orig_f0 > 0 {
        if f0 == 0 {
            let n_harmonics =
                MAX_PEAKS_FROM_PITCH.min(shl(div_s(LAST_HARMONIC_POS_TO_CHECK, orig_f0), -5));

            for i in 1..=n_harmonics {
                modify_threshold(i, orig_f0, 717, threshold_modification); // 0.7 in Q10
            }
        }
        if f0 > 0 {
            let n_harmonics =
                MAX_PEAKS_FROM_PITCH.min(shl(div_s(LAST_HARMONIC_POS_TO_CHECK, f0), -5));

            // (int)(F0/origF0+0.5f)
            let mut tmp_m: i16 = 0;
            let mut tmp_e: i16 = 0;
            basop_util_divide_mant_exp(f0, 0, orig_f0, 0, &mut tmp_m, &mut tmp_e);
            let tmp = round_word(l_shl(l_deposit_l(tmp_m), add(tmp_e, 1)));

            let mut i = tmp;
            while i > 0 {
                modify_threshold(i, orig_f0, 358, threshold_modification); // 0.35 in Q10
                i -= 1;
            }
            for i in 1..=n_harmonics {
                modify_threshold(i, f0, 358, threshold_modification);
            }
        }
    }
}

/// The right foot of the peak at `k` (the `upperIdx` of `findCandidates` / `findTonalComponents`).
fn find_right_foot(power_spectrum: &[i32], k: i16, tmp_loop2: i16) -> i16 {
    let side_lobe = |bin: i32| {
        l_shl(
            mpy_32_16_1(bin, ALLOWED_SIDE_LOBE_FLUCTUATION),
            ALLOWED_SIDE_LOBE_FLUCTUATION_EXP,
        )
    };

    let mut upper_idx = add(k, 1);
    while sub(upper_idx, tmp_loop2) < 0 {
        let u = upper_idx as usize;
        if l_sub(power_spectrum[u], power_spectrum[u + 1]) < 0 {
            // Side lobes may increase for certain amount
            if l_sub(side_lobe(power_spectrum[u]), power_spectrum[u + 1]) < 0 {
                break;
            }
            // Check for further decrease after a side lobe increase
            let mut j = add(upper_idx, 1);
            while j < tmp_loop2 {
                if l_sub(
                    power_spectrum[j as usize],
                    side_lobe(power_spectrum[j as usize + 1]),
                ) < 0
                {
                    break;
                }
                j += 1;
            }
            // Side lobe increase must be 2 times smaller than the decrease to the foot.
            // Eq. to 2.0f*powerSpectrum[lowerIdx-1]/powerSpectrum[lowerIdx] >
            // powerSpectrum[lowerIdx]/powerSpectrum[j]
            if l_sub(
                mpy_32_32(l_shl(power_spectrum[u + 1], 1), power_spectrum[j as usize]),
                mpy_32_32(power_spectrum[u], power_spectrum[u]),
            ) > 0
            {
                break;
            }
            upper_idx = sub(j, 1);
        }
        upper_idx = add(upper_idx, 1);
    }
    upper_idx
}

/// The left foot of the peak at `k`, not going below `lower_bound` (the `lowerIdx` of
/// `findCandidates` / `findTonalComponents`).
fn find_left_foot(power_spectrum: &[i32], k: i16, lower_bound: i16) -> i16 {
    let side_lobe = |bin: i32| {
        l_shl(
            mpy_32_16_1(bin, ALLOWED_SIDE_LOBE_FLUCTUATION),
            ALLOWED_SIDE_LOBE_FLUCTUATION_EXP,
        )
    };

    let mut lower_idx = sub(k, 1);
    while sub(lower_idx, lower_bound) > 0 {
        let l = lower_idx as usize;
        if l_sub(power_spectrum[l], power_spectrum[l - 1]) < 0 {
            // Side lobes may increase for certain amount
            if l_sub(side_lobe(power_spectrum[l]), power_spectrum[l - 1]) < 0 {
                break;
            }
            // Check for further decrease after a side lobe increase
            let mut j = sub(lower_idx, 1);
            while j > 0 {
                if l_sub(
                    power_spectrum[j as usize],
                    side_lobe(power_spectrum[j as usize - 1]),
                ) < 0
                {
                    break;
                }
                j -= 1;
            }
            // Side lobe increase must be 2 times smaller than the decrease to the foot.
            if l_sub(
                mpy_32_32(l_shl(power_spectrum[l - 1], 1), power_spectrum[j as usize]),
                mpy_32_32(power_spectrum[l], power_spectrum[l]),
            ) > 0
            {
                break;
            }
            lower_idx = add(j, 1);
        }
        lower_idx = sub(lower_idx, 1);
    }
    lower_idx
}

/// `findCandidates`: the peaks of the last frame's spectrum, as the thresholds (Q10) the
/// second-last frame's peaks must beat.
fn find_candidates(
    n_samples: i16,
    mdct_spectrum: &[i32],
    mdct_spectrum_exp: i16,
    threshold_modification_new: &mut [i16],
    floor_power_spectrum: i16,
) {
    let mut power_spectrum = [0_i32; L_FRAME_MAX as usize];
    let mut power_spectrum_exp: i16 = 0;
    let mut envelope = [0_i32; L_FRAME_MAX as usize];
    let mut smoothed_spectrum = [0_i32; L_FRAME_MAX as usize];

    calc_pseudo_spec(
        mdct_spectrum,
        mdct_spectrum_exp,
        n_samples,
        floor_power_spectrum,
        &mut power_spectrum,
        &mut power_spectrum_exp,
    );

    get_envelope(
        n_samples,
        &power_spectrum,
        0,
        &mut envelope,
        &mut smoothed_spectrum,
    );

    set16(threshold_modification_new, UNREACHABLE_THRESHOLD, n_samples);

    let mut k = GROUP_LENGTH / 2;
    let tmp_loop1 = sub(n_samples, GROUP_LENGTH - GROUP_LENGTH / 2);
    let tmp_loop2 = sub(n_samples, 1);
    while sub(k, tmp_loop1) <= 0 {
        let ku = k as usize;
        if l_sub(smoothed_spectrum[ku], envelope[ku]) > 0 {
            // The check that the bin at k is bigger than the bins at k-1 and k+1 is needed to
            // avoid deadlocks when the thresholds are low. It removes some true peaks, especially
            // if a non weighted sum is used for the smoothed spectrum.
            let bigger_neighbor = power_spectrum[ku - 1].max(power_spectrum[ku + 1]);

            if l_sub(power_spectrum[ku], bigger_neighbor) >= 0 {
                let upper_idx = find_right_foot(&power_spectrum, k, tmp_loop2);
                let lower_idx = find_left_foot(&power_spectrum, k, 0);

                // Check if there is a bigger peak up to the next peak foot
                let mut tmp_loop3 = upper_idx.min(tmp_loop1);
                let mut j = (GROUP_LENGTH / 2).max(lower_idx);
                while j <= tmp_loop3 {
                    if l_sub(power_spectrum[j as usize], power_spectrum[k as usize]) > 0 {
                        k = j;
                    }
                    j += 1;
                }

                // Modify thresholds for the following frame
                tmp_loop3 = add(k, 2);
                j = sub(k, 1);
                while j < tmp_loop3 {
                    let ju = j as usize;
                    threshold_modification_new[ju] = BIG_THRESHOLD;

                    if l_sub(smoothed_spectrum[ju], envelope[ju]) > 0 {
                        threshold_modification_new[ju] = SMALL_THRESHOLD;
                    }
                    j += 1;
                }
                // Jump to the next foot of the peak.
                k = upper_idx;
            }
        }
        k = add(k, 1);
    }
}

/// `RefineThresholdsUsingPitch`: if the pitch is stable between the last and the current frame,
/// lower the thresholds at the harmonics of its F0 (Q10, into `p_f0`).
fn refine_thresholds_using_pitch(
    n_samples: i16,
    n_samples_core: i16,
    power_spectrum: &[i32],
    last_pitch_lag: i32,
    current_pitch_lag: i32,
    p_f0: &mut i16,
    threshold_modification: &mut [i16],
) {
    // pitchIsStable = (fabs(lastPitchLag-currentPitchLag) < 0.25f)
    let l_tmp = l_abs(l_sub(last_pitch_lag, current_pitch_lag));
    let pitch_is_stable = l_sub(l_tmp, 16384) < 0; // 0.25 in Q16

    if pitch_is_stable {
        let mut orig_f0: i16 = 0;
        get_f0(
            n_samples,
            n_samples_core,
            power_spectrum,
            last_pitch_lag,
            &mut orig_f0,
            p_f0,
        );

        modify_thresholds(*p_f0, orig_f0, threshold_modification);
    } else {
        *p_f0 = 0;
    }
}

/// `findTonalComponents`: the peaks of the second-last power spectrum that beat their threshold,
/// with the 7-bin groups around them.
fn find_tonal_components(
    index_of_tonal_peak: &mut [i16],
    lower_index: &mut [i16],
    upper_index: &mut [i16],
    num_indexes: &mut i16,
    n_samples: i16,
    power_spectrum: &[i32],
    f0: i16,
    threshold_modification: &[i16],
) {
    let mut envelope = [0_i32; L_FRAME_MAX as usize];
    let mut smoothed_spectrum = [0_i32; L_FRAME_MAX as usize];

    get_envelope(
        n_samples,
        power_spectrum,
        f0,
        &mut envelope,
        &mut smoothed_spectrum,
    );

    let mut nr_of_fis: i16 = 0;
    let mut lower_bound: i16 = 0;

    let mut k = GROUP_LENGTH / 2;
    let tmp_loop1 = sub(n_samples, GROUP_LENGTH - GROUP_LENGTH / 2);
    let tmp_loop2 = sub(n_samples, 1);
    while sub(k, tmp_loop1) <= 0 {
        let ku = k as usize;
        // There are 3 bits headroom in envelope and the max of thresholdModification is 16384, so
        // shifting left for 4 would produce overflow only when the result is anyhow close to 1.
        if l_sub(
            l_shr(smoothed_spectrum[ku], 1),
            l_shl(mpy_32_16_1(envelope[ku], threshold_modification[ku]), 4),
        ) > 0
        {
            // See findCandidates for why the neighbour check is needed.
            let bigger_neighbor = power_spectrum[ku - 1].max(power_spectrum[ku + 1]);

            if l_sub(power_spectrum[ku], bigger_neighbor) >= 0 {
                let upper_idx = find_right_foot(power_spectrum, k, tmp_loop2);
                let lower_idx = find_left_foot(power_spectrum, k, lower_bound);

                lower_bound = upper_idx;

                // Check if there is a bigger peak up to the next peak foot
                let tmp_loop3 = upper_idx.min(tmp_loop1);
                let mut j = (GROUP_LENGTH / 2).max(lower_idx);
                while j <= tmp_loop3 {
                    if l_sub(power_spectrum[j as usize], power_spectrum[k as usize]) > 0 {
                        k = j;
                    }
                    j += 1;
                }

                let n = nr_of_fis as usize;
                lower_index[n] = sub(k, GROUP_LENGTH / 2);
                upper_index[n] = add(k, GROUP_LENGTH - GROUP_LENGTH / 2 - 1);

                if nr_of_fis > 0 && sub(lower_index[n], upper_index[n - 1]) <= 0 {
                    let m = shr(add(k, index_of_tonal_peak[n - 1]), 1);
                    upper_index[n - 1] = m;
                    lower_index[n] = add(m, 1);
                }

                index_of_tonal_peak[n] = k;
                nr_of_fis += 1;

                if sub(nr_of_fis, MAX_NUMBER_OF_IDX) == 0 {
                    break;
                }
                // Jump to the next foot of the peak.
                k = upper_idx;
            }
        }
        k = add(k, 1);
    }

    *num_indexes = nr_of_fis;
}

/// `DetectTonalComponents`: detect the tonal components in the last MDCT spectrum, use the
/// second-last power spectrum for the precise location of the peaks and store them in
/// `index_of_tonal_peak`. Updates `lower_index`, `upper_index` and `p_num_indexes` accordingly.
pub fn detect_tonal_components(
    index_of_tonal_peak: &mut [i16],
    lower_index: &mut [i16],
    upper_index: &mut [i16],
    p_num_indexes: &mut i16,
    last_pitch_lag: i32,
    current_pitch_lag: i32,
    last_mdct_spectrum: &[i16],
    last_mdct_spectrum_exp: i16,
    scale_factors: &[i16],
    scale_factors_exp: &[i16],
    scale_factors_max_e: i16,
    second_last_power_spectrum: &[i32],
    n_samples: i16,
    n_samples_core: i16,
    floor_power_spectrum: i16,
) {
    let mut f0: i16 = 0;
    let mut threshold_modification = [0_i16; L_FRAME_MAX as usize];
    let mut p_scaled_mdct_spectrum = [0_i32; L_FRAME_MAX as usize];

    mdct_shaping_16(
        last_mdct_spectrum,
        n_samples_core,
        n_samples,
        scale_factors,
        scale_factors_exp,
        scale_factors_max_e,
        &mut p_scaled_mdct_spectrum,
    );
    let last_mdct_spectrum_exp = add(last_mdct_spectrum_exp, scale_factors_max_e);

    // Find peak candidates in the last frame.
    find_candidates(
        n_samples,
        &p_scaled_mdct_spectrum,
        last_mdct_spectrum_exp,
        &mut threshold_modification,
        floor_power_spectrum,
    );

    // Refine peak candidates using the pitch information
    refine_thresholds_using_pitch(
        n_samples,
        n_samples_core,
        second_last_power_spectrum,
        last_pitch_lag,
        current_pitch_lag,
        &mut f0,
        &mut threshold_modification,
    );

    // Find peaks in the second last frame
    find_tonal_components(
        index_of_tonal_peak,
        lower_index,
        upper_index,
        p_num_indexes,
        n_samples,
        second_last_power_spectrum,
        f0,
        &threshold_modification,
    );
}

/// `RefineTonalComponents`: when the tonal components are already stored in `index_of_tonal_peak`,
/// detect them again in the last MDCT spectrum and keep only those detected again. Updates
/// `index_of_tonal_peak`, `lower_index`, `upper_index`, `phase_diff`, `phases` and
/// `p_num_indexes`.
pub fn refine_tonal_components(
    index_of_tonal_peak: &mut [i16],
    lower_index: &mut [i16],
    upper_index: &mut [i16],
    phase_diff: &mut [i16],
    phases: &mut [i16],
    p_num_indexes: &mut i16,
    last_pitch_lag: i32,
    current_pitch_lag: i32,
    last_mdct_spectrum: &[i16],
    last_mdct_spectrum_exp: i16,
    scale_factors: &[i16],
    scale_factors_exp: &[i16],
    scale_factors_max_e: i16,
    second_last_power_spectrum: &[i32],
    n_samples: i16,
    n_samples_core: i16,
    floor_power_spectrum: i16,
) {
    let mut new_index_of_tonal_peak = [0_i16; MAX_NUMBER_OF_IDX as usize];
    let mut new_lower_index = [0_i16; MAX_NUMBER_OF_IDX as usize];
    let mut new_upper_index = [0_i16; MAX_NUMBER_OF_IDX as usize];
    let mut new_num_indexes: i16 = 0;

    detect_tonal_components(
        &mut new_index_of_tonal_peak,
        &mut new_lower_index,
        &mut new_upper_index,
        &mut new_num_indexes,
        last_pitch_lag,
        current_pitch_lag,
        last_mdct_spectrum,
        last_mdct_spectrum_exp,
        scale_factors,
        scale_factors_exp,
        scale_factors_max_e,
        second_last_power_spectrum,
        n_samples,
        n_samples_core,
        floor_power_spectrum,
    );

    let mut n_preserved_peaks: i16 = 0;
    let mut i_new: i16 = 0;
    // pOldPhase / pNewPhase walk `phases`. The pointer skip of the dropped peaks in the reference
    // (`upperIndex - (lowerIndex + 1)`, one short of the group length) is mirrored as is.
    let mut p_old_phase: isize = 0;
    let mut p_new_phase: usize = 0;

    for i_old in 0..*p_num_indexes as usize {
        // We don't want the old peak index to be at the border of the new peak region, that is
        // why >= newUpperIndex and > newLowerIndex.
        while sub(i_new, new_num_indexes) < 0
            && sub(index_of_tonal_peak[i_old], new_upper_index[i_new as usize]) >= 0
        {
            i_new = add(i_new, 1);
        }

        if sub(i_new, new_num_indexes) < 0
            && sub(index_of_tonal_peak[i_old], new_lower_index[i_new as usize]) > 0
        {
            let n = n_preserved_peaks as usize;
            new_index_of_tonal_peak[n] = index_of_tonal_peak[i_old];
            new_lower_index[n] = lower_index[i_old];
            new_upper_index[n] = upper_index[i_old];
            phase_diff[n] = phase_diff[i_old];

            let mut j = lower_index[i_old];
            while j <= upper_index[i_old] {
                // pOldPhase never trails the start of `phases` here: it only moves back by one
                // for a dropped one-bin group, after which a kept group copies from >= 0.
                let source = usize::try_from(p_old_phase).unwrap_or(0);
                phases[p_new_phase] = phases[source];
                p_new_phase += 1;
                p_old_phase += 1;
                j += 1;
            }
            n_preserved_peaks = add(n_preserved_peaks, 1);
        } else {
            p_old_phase += isize::from(sub(upper_index[i_old], add(lower_index[i_old], 1)));
        }
    }

    let preserved = n_preserved_peaks as usize;
    index_of_tonal_peak[..preserved].copy_from_slice(&new_index_of_tonal_peak[..preserved]);
    lower_index[..preserved].copy_from_slice(&new_lower_index[..preserved]);
    upper_index[..preserved].copy_from_slice(&new_upper_index[..preserved]);
    *p_num_indexes = n_preserved_peaks;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_of_a_flat_spectrum_is_flat_in_the_middle() {
        let power_spec = [1 << 20; 64];
        let mut envelope = [0_i32; 64];
        let mut smoothed = [0_i32; 64];
        get_envelope(64, &power_spec, 0, &mut envelope, &mut smoothed);
        assert!(envelope[20] > 0);
        assert_eq!(envelope[20], envelope[30]);
        assert_eq!(smoothed[20], smoothed[30]);
    }

    #[test]
    fn a_single_dominant_bin_is_found_as_a_tonal_component() {
        // One strong peak in a quiet spectrum, thresholds at the unreachable default lowered to
        // the small threshold so the peak must be found with its 7 bin group.
        let mut power_spectrum = [1_000_i32; 128];
        power_spectrum[40] = 1 << 28;
        let threshold = [SMALL_THRESHOLD; 128];
        let mut peaks = [0_i16; MAX_NUMBER_OF_IDX as usize];
        let mut lower = [0_i16; MAX_NUMBER_OF_IDX as usize];
        let mut upper = [0_i16; MAX_NUMBER_OF_IDX as usize];
        let mut count = 0_i16;
        find_tonal_components(
            &mut peaks,
            &mut lower,
            &mut upper,
            &mut count,
            128,
            &power_spectrum,
            0,
            &threshold,
        );
        assert_eq!(count, 1);
        assert_eq!((peaks[0], lower[0], upper[0]), (40, 37, 43));
    }

    #[test]
    fn no_pitch_means_no_f0() {
        let spectrum = [0_i32; 128];
        let (mut orig_f0, mut f0) = (1_i16, 1_i16);
        get_f0(128, 128, &spectrum, 0, &mut orig_f0, &mut f0);
        assert_eq!((orig_f0, f0), (0, 0));
    }

    #[test]
    fn an_unstable_pitch_leaves_the_thresholds_alone() {
        let spectrum = [0_i32; 128];
        let mut threshold = [UNREACHABLE_THRESHOLD; 128];
        let mut f0 = 5_i16;
        refine_thresholds_using_pitch(128, 128, &spectrum, 0, 1 << 16, &mut f0, &mut threshold);
        assert_eq!(f0, 0);
        assert!(threshold.iter().all(|&t| t == UNREACHABLE_THRESHOLD));
    }
}
