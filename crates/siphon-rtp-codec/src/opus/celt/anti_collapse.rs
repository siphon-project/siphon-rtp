//! CELT anti-collapse (RFC 6716 §4.3.5; libopus `anti_collapse`, `bands.c`, float path).
//!
//! **Phase 3d.** For transient frames with multiple short MDCTs, a band that received no pulses in a
//! given short block would synthesize to digital silence there (energy "collapse"). This fills each
//! collapsed short block with pseudo-random `±r` noise — `r` derived from how much the band's energy
//! dropped versus the previous two frames (`Ediff`) and its pulse depth — then renormalises the band
//! back to unit norm. Operates on the normalised band coefficients before denormalisation.

use crate::opus::celt::synthesis::{celt_exp2, celt_lcg_rand};
use crate::opus::celt::tables::{E_BANDS, NB_BANDS};
use crate::opus::celt::vq::renormalise_vector;

/// Inject anti-collapse noise into the collapsed short blocks of bands `start..end` (libopus
/// `anti_collapse`, decoder path). `x` is the `channels * size` normalised band buffer;
/// `collapse_masks[i*channels + c]` has one bit per short block (set = had pulses). `log_e` is this
/// frame's per-band log2 energy, `prev1/prev2_log_e` the previous two frames' (each `2*NB_BANDS`).
/// Returns the advanced PRNG `seed`.
#[allow(clippy::too_many_arguments)]
pub fn anti_collapse(
    x: &mut [f32],
    collapse_masks: &[u8],
    lm: usize,
    channels: usize,
    size: usize,
    start: usize,
    end: usize,
    log_e: &[f32],
    prev1_log_e: &[f32],
    prev2_log_e: &[f32],
    pulses: &[i32],
    mut seed: u32,
) -> u32 {
    for i in start..end {
        let n0 = (E_BANDS[i + 1] - E_BANDS[i]) as usize;
        // Pulse "depth" in 1/8 bits per sample, then per short block.
        let depth = ((1 + pulses[i] as usize) / n0) >> lm;
        let thresh = 0.5 * celt_exp2(-0.125 * depth as f32);
        let sqrt_1 = 1.0 / ((n0 << lm) as f32).sqrt();

        for c in 0..channels {
            let mut prev1 = prev1_log_e[c * NB_BANDS + i];
            let mut prev2 = prev2_log_e[c * NB_BANDS + i];
            if channels == 1 {
                // Mono: also consider the (duplicated) second channel's history.
                prev1 = prev1.max(prev1_log_e[NB_BANDS + i]);
                prev2 = prev2.max(prev2_log_e[NB_BANDS + i]);
            }
            let ediff = (log_e[c * NB_BANDS + i] - prev1.min(prev2)).max(0.0);
            // Short blocks carry less energy: ×2 (×2√2 for the longest frame).
            let mut r = 2.0 * celt_exp2(-ediff);
            if lm == 3 {
                r *= std::f32::consts::SQRT_2;
            }
            r = thresh.min(r) * sqrt_1;

            let band_off = c * size + ((E_BANDS[i] as usize) << lm);
            let mut renormalize = false;
            for k in 0..(1usize << lm) {
                if collapse_masks[i * channels + c] & (1 << k) == 0 {
                    for j in 0..n0 {
                        seed = celt_lcg_rand(seed);
                        x[band_off + (j << lm) + k] = if seed & 0x8000 != 0 { r } else { -r };
                    }
                    renormalize = true;
                }
            }
            if renormalize {
                renormalise_vector(&mut x[band_off..band_off + (n0 << lm)], n0 << lm, 1.0);
            }
        }
    }
    seed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::celt::tables::SHORT_MDCT_SIZE;

    #[test]
    fn collapsed_band_is_filled_and_renormalised() {
        let lm = 2usize; // 4 short blocks
        let channels = 1usize;
        let size = (1 << lm) * SHORT_MDCT_SIZE;
        let band = 12usize; // n0 = eBands[13]-eBands[12] = 20-16 = 4
        let n0 = (E_BANDS[band + 1] - E_BANDS[band]) as usize;
        let band_off = (E_BANDS[band] as usize) << lm;

        let mut x = vec![0.0f32; channels * size];
        let collapse_masks = vec![0u8; NB_BANDS]; // all blocks collapsed in every band
        let mut log_e = vec![0.0f32; 2 * NB_BANDS];
        let mut prev1 = vec![0.0f32; 2 * NB_BANDS];
        let mut prev2 = vec![0.0f32; 2 * NB_BANDS];
        // Make Ediff modest so r is a usable amplitude.
        log_e[band] = 2.0;
        prev1[band] = 1.0;
        prev2[band] = 1.0;
        let mut pulses = vec![0i32; NB_BANDS];
        pulses[band] = 8;

        let seed = anti_collapse(
            &mut x, &collapse_masks, lm, channels, size, band, band + 1, &log_e, &prev1, &prev2,
            &pulses, 0x1234_5678,
        );
        // The whole band (n0<<lm = 16 bins) was filled and renormalised to unit energy.
        let energy: f32 = x[band_off..band_off + (n0 << lm)].iter().map(|v| v * v).sum();
        assert!((energy - 1.0).abs() < 1e-4, "renormalised band energy = {energy}");
        assert!(x[band_off..band_off + (n0 << lm)].iter().all(|&v| v != 0.0));
        assert_ne!(seed, 0x1234_5678, "PRNG advanced");
    }

    #[test]
    fn fully_present_band_is_untouched() {
        let lm = 2usize;
        let channels = 1usize;
        let size = (1 << lm) * SHORT_MDCT_SIZE;
        let band = 12usize;
        let mut x = vec![0.5f32; channels * size];
        let original = x.clone();
        // All short blocks present (low 2^LM bits set).
        let mut collapse_masks = vec![0u8; NB_BANDS];
        collapse_masks[band] = 0xFF;
        let log_e = vec![1.0f32; 2 * NB_BANDS];
        let prev = vec![1.0f32; 2 * NB_BANDS];
        let pulses = vec![4i32; NB_BANDS];

        anti_collapse(
            &mut x, &collapse_masks, lm, channels, size, band, band + 1, &log_e, &prev, &prev,
            &pulses, 42,
        );
        assert_eq!(x, original, "no collapsed blocks → band untouched");
    }
}
