//! CELT synthesis-path leaf DSP (RFC 6716 §4.3; libopus `bands.c`/`celt_decoder.c`/`mathops.h`,
//! float build).
//!
//! **Phase 3d (leaves).** The small, self-contained float functions of the synthesis tail:
//! [`celt_exp2`] (the band gain), [`denormalise_bands`] (apply per-band energy to the unit-norm
//! shapes), [`deemphasis`] (the output 1-pole), and [`celt_lcg_rand`] (the anti-collapse PRNG). The
//! inverse MDCT / overlap-add, comb post-filter, and `anti_collapse` build on these.
//!
//! Float reductions per the libopus float `arch.h`: every shift/round/saturate macro is the
//! identity, every `MULT*_Qxx` is a plain `a*b`, and `celt_exp2_db == celt_exp2 == 2^x`.

use crate::opus::celt::tables::{E_BANDS, E_MEANS, SHORT_MDCT_SIZE};

/// `2^x` via libopus's degree-5 `FLOAT_APPROX` polynomial (`celt_exp2`, `mathops.h`). Bit-faithful
/// to the reference float build; `celt_exp2_db` is an alias of this.
#[must_use]
#[allow(clippy::excessive_precision)] // poly coeffs verbatim from libopus; round to the intended f32
pub fn celt_exp2(x: f32) -> f32 {
    let integer = x.floor() as i32;
    if integer < -50 {
        return 0.0;
    }
    let frac = x - integer as f32;
    // Lolremez degree-5 approximation of exp(x·ln2) on [0,1].
    let res = 0.999_999_940_395_355_224_609_375
        + frac
            * (0.693_153_083_324_432_373_046_875
                + frac
                    * (0.240_153_610_706_329_345_703_125
                        + frac
                            * (0.055_826_317_518_949_508_666_992_187_5
                                + frac
                                    * (0.008_989_339_694_380_760_192_871_093_75
                                        + frac * 0.001_877_576_694_823_801_517_486_572_265_625))));
    // Scale by 2^integer by adding `integer` to the IEEE-754 exponent field, then drop the sign bit.
    f32::from_bits((res.to_bits() as i32).wrapping_add(integer << 23) as u32 & 0x7fff_ffff)
}

/// De-normalise: scale each band's unit-norm shape `x` by its linear gain into `freq` (libopus
/// `denormalise_bands`, float path → `freq[bin] = x[bin] * 2^(bandLogE[i] + eMeans[i])`).
///
/// `x` and `freq` are indexed by absolute MDCT bin; `band_log_e[i]` is the band's decoded log2
/// energy. Bins below `M·eBands[start]` and from `bound` to `N` are zeroed.
pub fn denormalise_bands(
    x: &[f32],
    freq: &mut [f32],
    band_log_e: &[f32],
    mut start: usize,
    mut end: usize,
    m: usize,
    downsample: usize,
    silence: bool,
) {
    let n = m * SHORT_MDCT_SIZE;
    let mut bound = m * E_BANDS[end] as usize;
    if downsample != 1 {
        bound = bound.min(n / downsample);
    }
    if silence {
        bound = 0;
        start = 0;
        end = 0;
    }
    let lo = m * E_BANDS[start] as usize;
    freq[..lo].fill(0.0);
    for i in start..end {
        let j0 = m * E_BANDS[i] as usize;
        let j1 = m * E_BANDS[i + 1] as usize;
        let lg = (band_log_e[i] + E_MEANS[i]).min(32.0);
        let g = celt_exp2(lg);
        for j in j0..j1 {
            freq[j] = x[j] * g;
        }
    }
    freq[bound..n].fill(0.0);
}

/// Apply the output de-emphasis 1-pole to one channel, writing interleaved float PCM (libopus
/// `deemphasis`, the standard `coef[1] == 0` path): `tmp = sig + VERY_SMALL + mem;
/// mem = coef0·tmp; pcm = tmp / 32768`. `mem` persists across frames in the decoder state.
///
/// `downsample` is 48000 / the API rate (`celt_decoder.c:302`). The 1-pole always runs at the full
/// 48 kHz synthesis rate — only the *output* is decimated, keeping every `downsample`-th sample, so
/// `n / downsample` samples per channel are written. A lower API rate therefore changes which
/// samples come out, never the filter state.
#[allow(clippy::too_many_arguments)]
pub fn deemphasis(
    sig: &[f32],
    pcm: &mut [f32],
    n: usize,
    channels: usize,
    channel: usize,
    coef0: f32,
    downsample: usize,
    mem: &mut f32,
) {
    const VERY_SMALL: f32 = 1e-30;
    const CELT_SIG_SCALE: f32 = 32768.0;
    let mut m = *mem;
    if downsample == 1 {
        for j in 0..n {
            let tmp = sig[j] + VERY_SMALL + m;
            m = coef0 * tmp;
            pcm[j * channels + channel] = tmp / CELT_SIG_SCALE;
        }
        *mem = m;
        return;
    }
    // The C runs the filter into a scratch buffer and then decimates it; keeping the running index
    // instead writes the same samples without the scratch (and without a per-frame allocation).
    for j in 0..n {
        let tmp = sig[j] + VERY_SMALL + m;
        m = coef0 * tmp;
        if j % downsample == 0 {
            pcm[(j / downsample) * channels + channel] = tmp / CELT_SIG_SCALE;
        }
    }
    *mem = m;
}

/// Anti-collapse pseudo-random generator (libopus `celt_lcg_rand`): the Numerical-Recipes LCG.
#[must_use]
pub fn celt_lcg_rand(seed: u32) -> u32 {
    seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223)
}

/// Convert float PCM (±1 nominal) to interleaved little-endian 16-bit (libopus `FLOAT2INT16`:
/// `clamp(round(x·32768), -32768, 32767)`).
#[must_use]
pub fn float_to_i16(x: f32) -> i16 {
    let scaled = x * 32768.0;
    let rounded = (scaled + 0.5).floor();
    rounded.clamp(-32768.0, 32767.0) as i16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::celt::tables::NB_BANDS;

    #[test]
    fn celt_exp2_matches_powf_within_tolerance() {
        for &x in &[-8.0f32, -3.5, -1.0, 0.0, 0.5, 1.0, 3.0, 7.25, 15.0, 31.9] {
            let approx = celt_exp2(x);
            let exact = 2.0f32.powf(x);
            let rel = (approx - exact).abs() / exact.max(1e-9);
            assert!(
                rel < 1e-3,
                "celt_exp2({x}) = {approx}, 2^x = {exact}, rel {rel}"
            );
        }
        assert_eq!(celt_exp2(-60.0), 0.0); // integer < -50 clamps to 0
    }

    #[test]
    fn denormalise_applies_per_band_gain() {
        // M=1 (LM=0): bins map 1:1 to eBands. Unit shape, a couple of known band energies.
        let m = 1;
        let n = m * SHORT_MDCT_SIZE;
        let x = vec![1.0f32; n];
        let mut band_log_e = [0.0f32; 2 * NB_BANDS];
        band_log_e[0] = -2.0;
        band_log_e[5] = 1.5;
        let mut freq = vec![999.0f32; n];
        denormalise_bands(&x, &mut freq, &band_log_e, 0, NB_BANDS, m, 1, false);
        // Band 0 spans bins [eBands[0], eBands[1]) = [0,1); gain = 2^(-2 + eMeans[0]).
        let g0 = celt_exp2(-2.0 + E_MEANS[0]);
        assert!((freq[0] - g0).abs() < 1e-3 * g0);
        // Band 5 spans [eBands[5], eBands[6]) = [5,6); gain = 2^(1.5 + eMeans[5]).
        let g5 = celt_exp2(1.5 + E_MEANS[5]);
        let bin5 = E_BANDS[5] as usize;
        assert!((freq[bin5] - g5).abs() < 1e-3 * g5);
        // Tail above the last band is zeroed.
        assert_eq!(
            freq[E_BANDS[NB_BANDS] as usize..n]
                .iter()
                .copied()
                .sum::<f32>(),
            0.0
        );
    }

    #[test]
    fn denormalise_silence_zeros_everything() {
        let m = 1;
        let n = m * SHORT_MDCT_SIZE;
        let x = vec![1.0f32; n];
        let band_log_e = [3.0f32; 2 * NB_BANDS];
        let mut freq = vec![7.0f32; n];
        denormalise_bands(&x, &mut freq, &band_log_e, 0, NB_BANDS, m, 1, true);
        assert!(freq.iter().all(|&v| v == 0.0));
    }

    #[test]
    fn deemphasis_is_one_pole() {
        // y[n] = x[n] + 0.85*y_scaled_prev; mem holds 0.85*y[n]; pcm = tmp/32768.
        let coef0 = 0.85f32;
        let sig = [32768.0f32, 0.0, 0.0, 0.0];
        let mut pcm = [0.0f32; 4];
        let mut mem = 0.0f32;
        deemphasis(&sig, &mut pcm, 4, 1, 0, coef0, 1, &mut mem);
        // Independent reference recurrence.
        let mut m = 0.0f32;
        let mut expected = [0.0f32; 4];
        for j in 0..4 {
            let tmp = sig[j] + 1e-30 + m;
            m = coef0 * tmp;
            expected[j] = tmp / 32768.0;
        }
        assert_eq!(pcm, expected);
        assert!((mem - m).abs() < 1e-9);
        // Impulse decays geometrically by 0.85 in the SIG domain.
        assert!((pcm[1] / pcm[0] - 0.85).abs() < 1e-4);
        assert!((pcm[2] / pcm[1] - 0.85).abs() < 1e-4);
    }

    /// `celt_decoder.c:302` — a lower API rate decimates the *output* only: the 1-pole still runs at
    /// 48 kHz, so the kept samples and the carried filter memory are identical to the full-rate run.
    #[test]
    fn deemphasis_downsamples_the_output_without_changing_the_filter() {
        let coef0 = 0.85f32;
        let sig: Vec<f32> = (0..12).map(|j| (j as f32) * 100.0).collect();

        let mut full = [0.0f32; 12];
        let mut mem_full = 0.0f32;
        deemphasis(&sig, &mut full, 12, 1, 0, coef0, 1, &mut mem_full);

        let mut third = [0.0f32; 4];
        let mut mem_third = 0.0f32;
        deemphasis(&sig, &mut third, 12, 1, 0, coef0, 3, &mut mem_third);

        for j in 0..4 {
            assert_eq!(third[j], full[j * 3], "kept sample {j}");
        }
        assert_eq!(mem_third, mem_full, "filter memory is rate-independent");
    }

    #[test]
    fn lcg_rand_matches_formula() {
        let mut seed = 12345u32;
        seed = celt_lcg_rand(seed);
        assert_eq!(
            seed,
            12345u32.wrapping_mul(1_664_525).wrapping_add(1_013_904_223)
        );
        // Deterministic and full-period-ish (no immediate fixed point).
        assert_ne!(celt_lcg_rand(seed), seed);
    }

    #[test]
    fn float_to_i16_rounds_and_clamps() {
        assert_eq!(float_to_i16(0.0), 0);
        assert_eq!(float_to_i16(1.0), 32767); // 32768 clamps to i16::MAX
        assert_eq!(float_to_i16(-1.0), -32768);
        assert_eq!(float_to_i16(0.5), 16384);
        assert_eq!(float_to_i16(2.0), 32767); // over-range clamps
    }
}
