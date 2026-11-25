//! The context-based harmonic model of the TCX arithmetic coder (TS 26.442 `lib_com/ari_hm.c`;
//! TS 26.445 §5.3.3.2.4.x, "TCX harmonic model" and the context-mapping of the arithmetic coder).
//!
//! The reference's `CONTEXT_HM_CONFIG` holds three pointers into one `indexBuffer`
//! (`peakIndices` at its start, `holeIndices` after the peaks); [`ContextHmConfig`] keeps the
//! buffer and the two offsets.
//!
//! `Overflow` and `Carry`: nothing in this file reads them.

pub mod envelope;
use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    KLTPHMFLAG, KLTPHMFRACTIONALRESOLUTION, KSMALLERLAGSTARGETBITSTHRESHOLD,
    KTCXHMPARABOLAHALFWIDTH,
};
use crate::evs::com::basop_util::basop_util_inv_log2;
use crate::evs::com::math_op::i_mult2;
use crate::evs::rom::{NUMRATIOBITS, RATIOS};
use crate::itu::basic_ops::{
    add, div_s, extract_l, l_add, l_deposit_l, l_shl, l_shr, l_shr_r, l_sub, mult_r, negate,
    round_word, shr, sub,
};
use crate::itu::stl2009::l_mult0;

/// `CONTEXT_HM_CONFIG`: the peak and hole indices of the harmonic model, both stored in
/// `index_buffer` (`peakIndices = indexBuffer`, `holeIndices = indexBuffer + numPeakIndices`).
#[derive(Debug)]
pub struct ContextHmConfig<'a> {
    /// `indexBuffer`: `N_MAX + 1` entries in the reference (`dec_prm.c`).
    pub index_buffer: &'a mut [i16],
    /// Offset of `peakIndices` in `index_buffer`.
    pub peak_indices_at: usize,
    /// Offset of `holeIndices` in `index_buffer`.
    pub hole_indices_at: usize,
    /// `numPeakIndices`
    pub num_peak_indices: i16,
    /// `numHoleIndices`
    pub num_hole_indices: i16,
}

impl<'a> ContextHmConfig<'a> {
    /// A configuration over `index_buffer` with every count and offset zero, as the reference's
    /// stack struct is before `ConfigureContextHm` runs.
    #[must_use]
    pub fn new(index_buffer: &'a mut [i16]) -> Self {
        Self {
            index_buffer,
            peak_indices_at: 0,
            hole_indices_at: 0,
            num_peak_indices: 0,
            num_hole_indices: 0,
        }
    }
}

/// `GET_ADJ2(T, L, F)`: `(L << F) - T`.
const fn get_adj2(t: i16, l: i16, f: i16) -> i16 {
    (l << f) - t
}

/// `UnmapIndex`: the lag (with `fractional_resolution` bits of fraction) a periodicity index
/// stands for. An index of an LTP-derived lag that the ratio table does not hold (a bit error
/// the reference does not guard, where it reads past the table) maps to a zero ratio.
pub fn unmap_index(
    periodicity_index: i16,
    bandwidth: i8,
    ltp_pitch_lag: i16,
    smaller_lags: i8,
    fractional_resolution: &mut i16,
    lag: &mut i32,
) {
    if ltp_pitch_lag > 0 && (periodicity_index & KLTPHMFLAG) != 0 {
        let ltp_pitch_index = shr(periodicity_index, 9);
        let multiplier = periodicity_index & 0xff;

        *fractional_resolution = KLTPHMFRACTIONALRESOLUTION;
        let ratio = usize::try_from(bandwidth)
            .ok()
            .and_then(|bandwidth| RATIOS.get(bandwidth))
            .zip(usize::try_from(ltp_pitch_index).ok())
            .and_then(|(row, index)| row.get(index))
            .zip(usize::try_from(sub(multiplier, 1)).ok())
            .and_then(|(ratios, index)| ratios.get(index))
            .copied()
            .unwrap_or(0);
        *lag = l_shr(l_mult0(ltp_pitch_lag, ratio), 8);
    } else {
        let lag16 = if sub(periodicity_index, 16) < 0 {
            *fractional_resolution = 3;
            add(periodicity_index, get_adj2(0, 6, 3))
        } else if sub(periodicity_index, 80) < 0 {
            *fractional_resolution = 4;
            add(periodicity_index, get_adj2(16, 8, 4))
        } else if sub(periodicity_index, 208) < 0 {
            *fractional_resolution = 3;
            add(periodicity_index, get_adj2(80, 12, 3))
        } else if sub(periodicity_index, 224) < 0 || smaller_lags != 0 {
            *fractional_resolution = 1;
            add(periodicity_index, get_adj2(208, 28, 1))
        } else {
            *fractional_resolution = 0;
            add(periodicity_index, get_adj2(224, 188, 0))
        };
        *lag = l_deposit_l(lag16);
    }
}

/// `ConfigureContextHm`: fill `hm_cfg`'s peak indices (three per harmonic: the line before, at
/// and after it) and hole indices (every other line), then the end marker `NumCoeffs`.
///
/// The reference writes through raw pointers into `indexBuffer` (`N_MAX + 1` entries). A
/// harmonic spacing under three lines (only a bit-errored lag gets there) or a lag of zero would
/// overrun it or never end; writes past the buffer are dropped and a non-positive lag stops the
/// peak loop.
pub fn configure_context_hm(
    num_coeffs: i16,
    target_bits: i16,
    periodicity_index: i16,
    ltp_pitch_lag: i16,
    hm_cfg: &mut ContextHmConfig<'_>,
) {
    let mut bandwidth: i8 = 0;
    if sub(num_coeffs, 256) >= 0 {
        bandwidth = 1;
    }

    let mut smaller_lags: i8 = 0;
    if sub(target_bits, KSMALLERLAGSTARGETBITSTHRESHOLD) <= 0 || bandwidth == 0 {
        smaller_lags = 1;
    }

    let mut fractional_resolution = 0;
    let mut lag = 0;
    unmap_index(
        periodicity_index,
        bandwidth,
        ltp_pitch_lag,
        smaller_lags,
        &mut fractional_resolution,
        &mut lag,
    );

    // Set up and fill peakIndices
    hm_cfg.peak_indices_at = 0;
    let mut tmp: usize = 0;
    let limit = l_shl(l_deposit_l(sub(num_coeffs, 1)), fractional_resolution);
    if l_sub(lag, limit) < 0 && lag > 0 {
        let mut i = lag;
        while i < limit {
            let index = extract_l(l_shr(i, fractional_resolution));
            for value in [sub(index, 1), index, add(index, 1)] {
                put_index(hm_cfg.index_buffer, tmp, value);
                tmp += 1;
            }
            i = i.wrapping_add(lag);
        }
    }
    hm_cfg.num_peak_indices = tmp as i16;

    // Set up and fill holeIndices
    hm_cfg.hole_indices_at = tmp;
    let mut index: i16 = 0;
    if hm_cfg.num_peak_indices > 0 {
        let mut j: i16 = 0;
        while j < hm_cfg.num_peak_indices {
            let peak = hm_cfg
                .index_buffer
                .get(hm_cfg.peak_indices_at + j as usize)
                .copied()
                .unwrap_or(i16::MAX);
            while index < peak {
                put_index(hm_cfg.index_buffer, tmp, index);
                tmp += 1;
                index += 1;
            }
            index = add(index, 3); // Skip the peak
            j += 3;
        }
    }
    if sub(index, num_coeffs) < 0 {
        while index < num_coeffs {
            put_index(hm_cfg.index_buffer, tmp, index);
            tmp += 1;
            index += 1;
        }
    }
    hm_cfg.num_hole_indices = (tmp - hm_cfg.hole_indices_at) as i16;
    // Add extremal element signaling the end of the buffer
    put_index(hm_cfg.index_buffer, tmp, num_coeffs);
}

/// `*tmp++ = value` into `indexBuffer`, dropped past its end (see [`configure_context_hm`]).
fn put_index(buffer: &mut [i16], at: usize, value: i16) {
    if let Some(slot) = buffer.get_mut(at) {
        *slot = value;
    }
}

/// `CountIndexBits`: the bits the periodicity index takes in the bitstream.
#[must_use]
pub fn count_index_bits(bandwidth: i16, periodicity_index: i16) -> i16 {
    let mut result = 8;
    let periodicity_index_s = shr(periodicity_index, 9);

    if (periodicity_index & KLTPHMFLAG) != 0 {
        // The reference indexes `NumRatioBits[Bandwidth][PeriodicityIndexS]` unchecked; its
        // callers keep both inside the table (a 0/1 bandwidth, an index of at most 16).
        result = usize::try_from(bandwidth)
            .ok()
            .and_then(|bandwidth| NUMRATIOBITS.get(bandwidth))
            .zip(usize::try_from(periodicity_index_s).ok())
            .and_then(|(row, index)| row.get(index))
            .copied()
            .unwrap_or(0);
    }

    result
}

/// `tcx_hm_render`: render the harmonic model's prototype peak `p` (nine values, Q13) for a
/// pitch `lag` of `fract_res` fractional bits. Returns `true` for a bit error (the reference
/// returns 1).
#[must_use]
pub fn tcx_hm_render(lag: i32, fract_res: i16, p: &mut [i16]) -> bool {
    let half_width = KTCXHMPARABOLAHALFWIDTH;
    let mid = half_width as usize;

    // Set up overall shape
    let f0 = l_shl(lag, sub(15, fract_res)); // Q31

    let mut tmp32 = mpy_32_16_1(f0, -26474);
    tmp32 = l_shr_r(basop_util_inv_log2(l_shl(tmp32, 7)), 2);
    tmp32 = l_sub(603_979_776, tmp32);
    tmp32 = l_add(l_add(tmp32, tmp32), mpy_32_16_1(tmp32, 26214));
    let height = round_word(tmp32); // Q13

    tmp32 = mpy_32_16_1(f0, -18910);
    tmp32 = l_shr_r(basop_util_inv_log2(l_shl(tmp32, 7)), 2);
    tmp32 = l_sub(1_395_864_371, tmp32);
    let peak_deviation = round_word(tmp32); // Q14

    if sub(13915, peak_deviation) > 0 {
        // A bit error was encountered
        return true;
    }
    // The reference evaluates this pair twice (before and after the check), to the same value.
    let mut tmp = div_s(13915, peak_deviation);
    tmp = mult_r(tmp, tmp); // Q15

    // Render the prototype peak
    p[mid] = height;

    for k in 1..=half_width {
        p[mid + k as usize] = round_word(mpy_32_16_1(
            basop_util_inv_log2(l_shl(l_mult0(i_mult2(negate(k), k), tmp), 10)),
            height,
        ));
    }
    // Mirror
    for k in -half_width..0 {
        p[(mid as i16 + k) as usize] = p[(mid as i16 - k) as usize];
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmap_index_covers_each_resolution_band() {
        let mut fractional_resolution = 0;
        let mut lag = 0;
        for (index, expected_resolution, expected_lag) in [
            (0, 3, 48),
            (15, 3, 63),
            (16, 4, 128),
            (79, 4, 191),
            (80, 3, 96),
            (207, 3, 223),
            (208, 1, 56),
            (223, 1, 71),
        ] {
            unmap_index(index, 1, 0, 0, &mut fractional_resolution, &mut lag);
            assert_eq!(
                (fractional_resolution, lag),
                (expected_resolution, expected_lag)
            );
        }
        // From 224 up the resolution is whole lines unless smaller lags are in use.
        unmap_index(224, 1, 0, 0, &mut fractional_resolution, &mut lag);
        assert_eq!((fractional_resolution, lag), (0, 188));
        unmap_index(224, 1, 0, 1, &mut fractional_resolution, &mut lag);
        assert_eq!((fractional_resolution, lag), (1, 72));
    }

    #[test]
    fn configure_context_hm_lists_peaks_then_holes() {
        let mut buffer = [0_i16; 1201];
        let mut hm_cfg = ContextHmConfig::new(&mut buffer);
        // Index 208 at 128 lines: lag 56 in 1/2 lines, i.e. a harmonic every 28 lines.
        configure_context_hm(128, 100, 208, -1, &mut hm_cfg);
        assert_eq!(hm_cfg.num_peak_indices, 12);
        assert_eq!(hm_cfg.hole_indices_at, 12);
        assert_eq!(hm_cfg.num_peak_indices + hm_cfg.num_hole_indices, 12 + 116);
        assert_eq!(&hm_cfg.index_buffer[..3], &[27, 28, 29]);
    }

    #[test]
    fn count_index_bits_is_eight_without_the_ltp_flag() {
        assert_eq!(count_index_bits(1, 100), 8);
        assert_eq!(count_index_bits(1, KLTPHMFLAG), NUMRATIOBITS[1][0]);
    }

    #[test]
    fn render_rejects_a_peak_that_is_too_wide() {
        let mut p = [0_i16; 9];
        // A zero lag has no harmonic: the deviation test fails.
        assert!(tcx_hm_render(0, 3, &mut p));
    }
}
