//! `FindPhases` and `FindPhaseDifferences` (TS 26.442 `lib_dec/tonalMDCTconcealment.c`): the phase
//! of each line of the tonal groups, and the phase advance per frame of each tonal peak.

use super::TciView;
use crate::evs::basop::mpy_32_16_1;
use crate::evs::com::basop_util::{
    basop_util_atan2, basop_util_divide3232_uu_1616_scale, basop_util_f_pow,
};
use crate::itu::basic_ops::{
    add, l_add, l_deposit_h, l_mult, l_shl, l_shr, l_sub, round_word, sub,
};

/// `FindPhases`: the phase (`[-pi;pi]`, 2Q13) of every line of every tonal group, from the MDST
/// and MDCT of the second last block, into `phase_currentFramePredicted`.
///
/// In contrast to the float code the MDST needs not to be negated, due to a different
/// implementation of the MDST.
pub(super) fn find_phases(
    tci: &mut TciView<'_>,
    second_last_mdct: &[i32],
    second_last_mdst: &[i32],
    diff_exp: i16,
) {
    let mut current_phase = 0_usize;
    // for each index/index group
    for i in 0..*tci.num_indexes as usize {
        for l in tci.lower_index[i]..=tci.upper_index[i] {
            let l = l as usize;
            tci.phase_current_frame_predicted[current_phase] =
                basop_util_atan2(second_last_mdst[l], second_last_mdct[l], diff_exp);
            current_phase += 1;
        }
    }
}

/// `1.0/(2*1.36)` in Q31.
const G: i32 = 789_516_047;
/// Maximum ratio |ODFT[k-1]|/|ODFT[k+1]| (44.8 in Q9) is 16.5 dB, that is the maximum ratio (for
/// fractional = 0) is `(cos(PI/bandwidth)/cos(3PI/bandwidth))^1.36`.
const MAXRATIO: i16 = 22938;
/// `FL2WORD32(cos(EVS_PI/BANDWIDTH))`, bandwidth 7.
const MM: i32 = 1_934_815_907;
/// `FL2WORD16(cos((3*EVS_PI)/BANDWIDTH)*4)`, Q17.
const SS: i16 = 29166;
/// `FL2WORD32(sin(EVS_PI/BANDWIDTH))`.
const N: i32 = 931_758_243;
/// `FL2WORD16(sin((3*EVS_PI)/BANDWIDTH))`.
const J: i16 = 31946;

/// `FindPhaseDifferences`: the phase difference (`[-pi;pi]`, 3Q12) per frame of every tonal peak
/// from the ratio of the power spectrum around it, into `phaseDiff`.
pub(super) fn find_phase_differences(tci: &mut TciView<'_>, power_spectrum: &[i32]) {
    let s = SS;
    let j = J;

    for i in 0..*tci.num_indexes as usize {
        let mut m = MM;
        let mut n = N;

        let k = tci.index_of_tonal_peak[i];
        let ku = k as usize;

        if l_sub(
            mpy_32_16_1(power_spectrum[ku - 1], 512), // 1.0 in Q9
            mpy_32_16_1(power_spectrum[ku + 1], MAXRATIO),
        ) >= 0
        {
            tci.phase_diff[i] = 0; // tan(0.0f*EVS_PI/bandwidth)
            if k & 1 != 0 {
                tci.phase_diff[i] = -12868; // -EVS_PI 3Q12
            }
        } else if l_sub(
            mpy_32_16_1(power_spectrum[ku + 1], 512),
            mpy_32_16_1(power_spectrum[ku - 1], MAXRATIO),
        ) >= 0
        {
            tci.phase_diff[i] = 12868; // EVS_PI 3Q12; tan(2.0f*PI/bandwidth)
            if k & 1 != 0 {
                tci.phase_diff[i] = 0; // 0 Q13, 2Q13
            }
        } else {
            // Q = (float)pow(odft_left/odft_right, G);
            // a = (m - Q * s) / (n + Q * j);
            // phaseDiff[i] = (float)atan(a) * (bandwidth/2.0f);
            // max divi=44.8 & sf=6
            let mut sf: i16 = 0;
            let divi = basop_util_divide3232_uu_1616_scale(
                power_spectrum[ku - 1],
                power_spectrum[ku + 1],
                &mut sf,
            );
            let base_exp = sf;
            let q = basop_util_f_pow(l_deposit_h(divi), base_exp, G, 0, &mut sf);
            let mut l_tmp = mpy_32_16_1(q, s);
            let mut sfn = sub(sf, 2);

            if sfn > 0 {
                m = l_shr(m, sfn);
            }

            if sfn < 0 {
                l_tmp = l_shl(l_tmp, sfn);
                sfn = 0;
            }

            let a = l_sub(m, l_tmp); // sf

            l_tmp = mpy_32_16_1(q, j);
            let sfd;
            if sf >= 0 {
                l_tmp = l_shr(l_tmp, 1);
                sfd = add(sf, 1);
                n = l_shr(n, sfd);
            } else {
                sfd = 0;
                l_tmp = l_shl(l_tmp, sf);
            }

            l_tmp = l_add(n, l_tmp);
            let fractional = basop_util_atan2(a, l_tmp, sub(sfn, sfd)); // 2Q13
                                                                        // BANDWIDTH/2.0f Q13; 2Q13*2Q13 = 4Q27
            l_tmp = l_mult(fractional, 28672);

            // fractional is in the range 0..+pi; we need to stay in the range -2pi..+2pi
            if (k & 3) == 1 {
                l_tmp = l_add(l_tmp, 421_657_440); // +1*EVS_PI Q27
            }
            if (k & 3) == 2 {
                l_tmp = l_sub(l_tmp, 843_314_880); // +2*EVS_PI = -2*EVS_PI Q27
            }
            if (k & 3) == 3 {
                l_tmp = l_sub(l_tmp, 421_657_440); // +3*EVS_PI = -1*EVS_PI Q27
            }
            tci.phase_diff[i] = round_word(l_shl(l_tmp, 1)); // 3Q12
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::dec::tonal_mdct_concealment::tci_view;

    #[test]
    fn a_pure_mdst_line_is_a_quarter_turn() {
        let mut buffer = [0_i16; 1440];
        let mut tci = tci_view(&mut buffer);
        *tci.num_indexes = 1;
        tci.lower_index[0] = 2;
        tci.upper_index[0] = 3;
        let mut mdst = [0_i32; 8];
        mdst[2] = 1 << 20;
        mdst[3] = 1 << 20;
        find_phases(&mut tci, &[0; 8], &mdst, 0);
        // pi/2 in Q13
        assert_eq!(tci.phase_current_frame_predicted[..2], [12868, 12868]);
    }

    #[test]
    fn a_peak_far_louder_on_its_left_has_no_phase_advance_on_even_lines() {
        let mut buffer = [0_i16; 1440];
        let mut tci = tci_view(&mut buffer);
        *tci.num_indexes = 2;
        tci.index_of_tonal_peak[0] = 4;
        tci.index_of_tonal_peak[1] = 5;
        let mut power = [1_i32 << 10; 8];
        power[3] = 1 << 28;
        power[4] = 1 << 28;
        power[5] = 1 << 28;
        power[6] = 1 << 10;
        find_phase_differences(&mut tci, &power);
        // Line 5 (odd): the left neighbour (4) is louder than the right one (6) by more than the
        // maximum ratio.
        assert_eq!(tci.phase_diff[1], -12868);
    }

    /// `(k, power[k-1], power[k+1], phaseDiff)` as the reference's `FindPhaseDifferences` returns
    /// them, across both ratio limits (44.8) and the four `k & 3` quadrants of the interpolation.
    const REFERENCE_PHASE_DIFFERENCES: [(i16, i32, i32, i16); 16] = [
        (4, 268_435_456, 5_990_000, 0),
        (4, 268_435_456, 6_000_000, 4),
        (5, 268_435_456, 5_990_000, -12868),
        (5, 268_435_456, 6_000_000, 12871),
        (6, 5_990_000, 268_435_456, 12868),
        (6, 6_000_000, 268_435_456, -12891),
        (7, 5_990_000, 268_435_456, 0),
        (7, 6_000_000, 268_435_456, -23),
        (4, 67_108_864, 67_108_864, 6454),
        (5, 67_108_864, 67_108_864, 19322),
        (6, 67_108_864, 33_554_432, -20733),
        (7, 16_777_216, 67_108_864, -3602),
        (8, 33_554_432, 67_108_864, 7889),
        (9, 3_145_728, 33_554_432, 23828),
        (10, 50_331_648, 33_554_432, -20134),
        (11, 1_048_576, 6_291_456, -2870),
    ];

    #[test]
    fn phase_differences_match_the_reference_values() {
        for (k, left, right, expected) in REFERENCE_PHASE_DIFFERENCES {
            let mut buffer = [0_i16; 1440];
            let mut tci = tci_view(&mut buffer);
            *tci.num_indexes = 1;
            tci.index_of_tonal_peak[0] = k;
            let mut power = [0_i32; 16];
            power[usize::try_from(k - 1).unwrap_or(0)] = left;
            power[usize::try_from(k + 1).unwrap_or(0)] = right;
            find_phase_differences(&mut tci, &power);
            assert_eq!(
                tci.phase_diff[0], expected,
                "k {k} left {left} right {right}"
            );
        }
    }
}
