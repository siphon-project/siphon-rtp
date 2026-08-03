//! CELT encoder-side band analysis (RFC 6716 §4.3.2; libopus `bands.c` + `quant_bands.c`, float
//! build) — the exact inverse of the decoder's [`denormalise_bands`].
//!
//! Three steps turn the forward-MDCT spectrum into what the entropy coder needs:
//! [`compute_band_energies`] measures each band's L2 amplitude, [`amp2_log2`] converts that to the
//! log2 energy the coarse/fine quantisers code (mean-removed), and [`normalise_bands`] divides the
//! spectrum by the amplitude so every band carries a unit-norm shape for the PVQ.
//! [`celt_preemphasis`] is the input-side 1-pole that mirrors the decoder's
//! [`deemphasis`](crate::opus::celt::synthesis::deemphasis).
//!
//! [`denormalise_bands`]: crate::opus::celt::synthesis::denormalise_bands

use crate::opus::celt::mathops::{celt_inner_prod, celt_log2};
use crate::opus::celt::tables::{E_BANDS, E_MEANS, NB_BANDS, SHORT_MDCT_SIZE};

/// Energy floor added before the square root (libopus `1e-27f`, `bands.c:168`) so a silent band
/// never yields a zero amplitude (which would divide by zero in [`normalise_bands`]).
const ENERGY_EPSILON: f32 = 1e-27;

/// Log2 energy written for bands above `eff_end` (libopus `-QCONST16(14.f, DB_SHIFT)`,
/// `quant_bands.c:561`).
const UNCODED_BAND_LOG_ENERGY: f32 = -14.0;

/// Per-band L2 amplitude of the MDCT spectrum (libopus `compute_band_energies`, float path,
/// `bands.c:159`): `bandE[i] = sqrt(1e-27 + Σ X[j]²)` over band `i`'s bins.
///
/// `x` is the interleaved `C*N` signal MDCT buffer, `band_e` the `C*NB_BANDS` amplitude buffer.
pub fn compute_band_energies(
    x: &[f32],
    band_e: &mut [f32],
    end: usize,
    channels: usize,
    lm: usize,
) {
    let n = SHORT_MDCT_SIZE << lm;
    for c in 0..channels {
        for i in 0..end {
            let lo = c * n + ((E_BANDS[i] as usize) << lm);
            let width = ((E_BANDS[i + 1] - E_BANDS[i]) as usize) << lm;
            let sum = ENERGY_EPSILON + celt_inner_prod(&x[lo..], &x[lo..], width);
            band_e[i + c * NB_BANDS] = sum.sqrt();
        }
    }
}

/// Divide every band by its amplitude so each carries a unit-norm shape (libopus `normalise_bands`,
/// float path, `bands.c:177`): `X[j] = freq[j] / (1e-27 + bandE[i])`.
pub fn normalise_bands(
    freq: &[f32],
    x: &mut [f32],
    band_e: &[f32],
    end: usize,
    channels: usize,
    m: usize,
) {
    let n = m * SHORT_MDCT_SIZE;
    for c in 0..channels {
        for i in 0..end {
            let g = 1.0 / (ENERGY_EPSILON + band_e[i + c * NB_BANDS]);
            let lo = m * E_BANDS[i] as usize;
            let hi = m * E_BANDS[i + 1] as usize;
            for j in lo..hi {
                x[j + c * n] = freq[j + c * n] * g;
            }
        }
    }
}

/// Amplitude → mean-removed log2 energy (libopus `amp2Log2`, `quant_bands.c:544`):
/// `bandLogE[i] = log2(bandE[i]) - eMeans[i]`, with bands `eff_end..end` pinned to −14 dB.
pub fn amp2_log2(
    band_e: &[f32],
    band_log_e: &mut [f32],
    eff_end: usize,
    end: usize,
    channels: usize,
) {
    for c in 0..channels {
        for i in 0..eff_end {
            band_log_e[i + c * NB_BANDS] = celt_log2(band_e[i + c * NB_BANDS]) - E_MEANS[i];
        }
        for i in eff_end..end {
            band_log_e[i + c * NB_BANDS] = UNCODED_BAND_LOG_ENERGY;
        }
    }
}

/// Input pre-emphasis (libopus `celt_preemphasis`, `celt_encoder.c:507`, the `coef[1] == 0`,
/// `upsample == 1` fast path used by the 48 kHz mode): `in[i] = x[i]·32768 − mem`,
/// `mem = coef0·x[i]·32768`, reading channel `channel` out of `channels`-interleaved PCM.
///
/// `mem` persists across frames in the encoder state; it is the exact counterpart of the decoder's
/// de-emphasis memory. `clip` reproduces the reference's `[-65536, 65536]` SIG-domain clamp, which
/// libopus applies only when the input actually exceeds full scale.
pub fn celt_preemphasis(
    pcm: &[f32],
    inp: &mut [f32],
    n: usize,
    channels: usize,
    channel: usize,
    coef0: f32,
    mem: &mut f32,
    clip: bool,
) {
    // `SCALEIN` in the float build is `(x)*CELT_SIG_SCALE` = x*32768 (arch.h float path).
    const CELT_SIG_SCALE: f32 = 32768.0;
    let mut m = *mem;
    for i in 0..n {
        let mut x = pcm[channels * i + channel] * CELT_SIG_SCALE;
        if clip {
            x = x.clamp(-65536.0, 65536.0);
        }
        // SHL32(x, SIG_SHIFT) and SHR32(MULT16_16(coef0,x), 15-SIG_SHIFT) are both the identity
        // scaling in the float build (arch.h: SIG_SHIFT is fixed-point only).
        inp[i] = x - m;
        m = coef0 * x;
    }
    *mem = m;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::celt::synthesis::{celt_exp2, deemphasis, denormalise_bands};
    use crate::opus::celt::tables::PREEMPH;

    /// `compute_band_energies` must equal a straight per-band L2 norm of the spectrum.
    #[test]
    fn band_energies_are_the_l2_norm_per_band() {
        let lm = 3usize;
        let n = SHORT_MDCT_SIZE << lm;
        let x: Vec<f32> = (0..n)
            .map(|i| ((i as f32) * 0.013).sin() * 1000.0)
            .collect();
        let mut band_e = vec![0f32; NB_BANDS];
        compute_band_energies(&x, &mut band_e, NB_BANDS, 1, lm);
        for i in 0..NB_BANDS {
            let lo = (E_BANDS[i] as usize) << lm;
            let hi = (E_BANDS[i + 1] as usize) << lm;
            let want: f32 = (1e-27 + x[lo..hi].iter().map(|v| v * v).sum::<f32>()).sqrt();
            assert!(
                (band_e[i] - want).abs() < 1e-3 * want.max(1.0),
                "band {i}: {} vs {want}",
                band_e[i]
            );
        }
    }

    /// A silent band must not produce a zero (or NaN) amplitude — the epsilon floor.
    #[test]
    fn band_energies_floor_on_silence() {
        let lm = 0usize;
        let n = SHORT_MDCT_SIZE << lm;
        let x = vec![0f32; n];
        let mut band_e = vec![0f32; NB_BANDS];
        compute_band_energies(&x, &mut band_e, NB_BANDS, 1, lm);
        assert!(
            band_e.iter().all(|&e| e > 0.0 && e.is_finite()),
            "{band_e:?}"
        );
    }

    /// After `normalise_bands` every coded band has unit L2 norm.
    #[test]
    fn normalise_bands_produces_unit_norm_shapes() {
        let lm = 2usize;
        let m = 1usize << lm;
        let n = SHORT_MDCT_SIZE << lm;
        let freq: Vec<f32> = (0..n)
            .map(|i| ((i as f32) * 0.07 + 0.3).cos() * 250.0)
            .collect();
        let mut band_e = vec![0f32; NB_BANDS];
        compute_band_energies(&freq, &mut band_e, NB_BANDS, 1, lm);
        let mut x = vec![0f32; n];
        normalise_bands(&freq, &mut x, &band_e, NB_BANDS, 1, m);
        for i in 0..NB_BANDS {
            let lo = m * E_BANDS[i] as usize;
            let hi = m * E_BANDS[i + 1] as usize;
            let energy: f32 = x[lo..hi].iter().map(|v| v * v).sum();
            assert!(
                (energy - 1.0).abs() < 1e-3,
                "band {i}: norm² {energy} != 1 (width {})",
                hi - lo
            );
        }
    }

    /// The headline round trip: `normalise_bands` + `amp2_log2` on the analysis side must be
    /// inverted by the decoder's `denormalise_bands` (which applies `2^(bandLogE + eMeans)`).
    /// This validates both directions against each other through the *real* decoder function.
    #[test]
    fn analysis_then_denormalise_recovers_the_spectrum() {
        let lm = 3usize;
        let m = 1usize << lm;
        let n = SHORT_MDCT_SIZE << lm;
        let freq: Vec<f32> = (0..n)
            .map(|i| ((i as f32) * 0.021).sin() * 4000.0 + ((i as f32) * 0.005).cos() * 800.0)
            .collect();

        let mut band_e = vec![0f32; 2 * NB_BANDS];
        compute_band_energies(&freq, &mut band_e, NB_BANDS, 1, lm);
        let mut band_log_e = vec![0f32; 2 * NB_BANDS];
        amp2_log2(&band_e, &mut band_log_e, NB_BANDS, NB_BANDS, 1);
        let mut x = vec![0f32; n];
        normalise_bands(&freq, &mut x, &band_e, NB_BANDS, 1, m);

        let mut back = vec![0f32; n];
        denormalise_bands(&x, &mut back, &band_log_e, 0, NB_BANDS, m, 1, false);

        // The only loss is `celt_log2`/`celt_exp2` round-off, so allow a small relative error.
        let bound = m * E_BANDS[NB_BANDS] as usize;
        for j in 0..bound {
            let scale = freq[j].abs().max(1.0);
            assert!(
                (back[j] - freq[j]).abs() < 2e-3 * scale,
                "bin {j}: {} vs {}",
                back[j],
                freq[j]
            );
        }
    }

    /// `amp2_log2` must be `log2(amp) - eMeans`, and bands past `eff_end` pinned to −14.
    #[test]
    fn amp2_log2_removes_the_band_mean_and_pins_the_tail() {
        let band_e: Vec<f32> = (0..NB_BANDS).map(|i| 2.0f32.powi(i as i32 % 7)).collect();
        let mut band_log_e = vec![0f32; 2 * NB_BANDS];
        amp2_log2(&band_e, &mut band_log_e, 17, NB_BANDS, 1);
        for (i, (&got, &amp)) in band_log_e.iter().zip(band_e.iter()).take(17).enumerate() {
            let want = amp.log2() - E_MEANS[i];
            assert!((got - want).abs() < 1e-4, "band {i}");
        }
        for (i, &got) in band_log_e.iter().enumerate().take(NB_BANDS).skip(17) {
            assert_eq!(got, -14.0, "band {i} must be pinned");
        }
    }

    /// `celt_exp2(amp2_log2(e) + eMeans)` must recover the amplitude — the pair the codec relies on.
    #[test]
    fn amp2_log2_is_inverted_by_celt_exp2() {
        for &amp in &[1e-3f32, 0.5, 1.0, 17.0, 4096.0, 1.0e6] {
            let band_e = [amp; NB_BANDS];
            let mut band_log_e = [0f32; 2 * NB_BANDS];
            amp2_log2(&band_e, &mut band_log_e, NB_BANDS, NB_BANDS, 1);
            let back = celt_exp2(band_log_e[3] + E_MEANS[3]);
            assert!(
                (back - amp).abs() < 2e-3 * amp,
                "amp {amp} round-tripped to {back}"
            );
        }
    }

    /// Pre-emphasis then the decoder's de-emphasis is the identity (up to the 1-pole memory),
    /// which is what keeps the codec's overall gain at unity.
    #[test]
    fn preemphasis_is_inverted_by_deemphasis() {
        let coef0 = PREEMPH[0];
        let n = 240usize;
        let pcm: Vec<f32> = (0..n)
            .map(|i| ((i as f32) * 0.13).sin() * 0.4 + ((i as f32) * 0.02).cos() * 0.2)
            .collect();

        let mut sig = vec![0f32; n];
        let mut enc_mem = 0f32;
        celt_preemphasis(&pcm, &mut sig, n, 1, 0, coef0, &mut enc_mem, false);

        let mut back = vec![0f32; n];
        let mut dec_mem = 0f32;
        deemphasis(&sig, &mut back, n, 1, 0, coef0, 1, &mut dec_mem);

        for i in 0..n {
            assert!(
                (back[i] - pcm[i]).abs() < 1e-5,
                "sample {i}: {} vs {}",
                back[i],
                pcm[i]
            );
        }
    }

    /// The pre-emphasis memory must persist so a frame boundary is seamless.
    #[test]
    fn preemphasis_memory_carries_across_frames() {
        let coef0 = PREEMPH[0];
        let pcm: Vec<f32> = (0..200).map(|i| ((i as f32) * 0.09).sin() * 0.5).collect();

        // One 200-sample pass.
        let mut one = vec![0f32; 200];
        let mut mem = 0f32;
        celt_preemphasis(&pcm, &mut one, 200, 1, 0, coef0, &mut mem, false);

        // Two 100-sample passes sharing the memory.
        let mut two = vec![0f32; 200];
        let mut mem2 = 0f32;
        celt_preemphasis(
            &pcm[..100],
            &mut two[..100],
            100,
            1,
            0,
            coef0,
            &mut mem2,
            false,
        );
        let (_, second) = two.split_at_mut(100);
        celt_preemphasis(&pcm[100..], second, 100, 1, 0, coef0, &mut mem2, false);

        assert_eq!(one, two);
        assert!((mem - mem2).abs() < 1e-9);
    }

    /// Interleaved stereo PCM: each channel must be pre-emphasised independently.
    #[test]
    fn preemphasis_reads_the_requested_interleaved_channel() {
        let coef0 = PREEMPH[0];
        let n = 16usize;
        // Left ramps up, right ramps down.
        let mut pcm = vec![0f32; 2 * n];
        for i in 0..n {
            pcm[2 * i] = i as f32 * 0.01;
            pcm[2 * i + 1] = -(i as f32) * 0.02;
        }
        let mut left = vec![0f32; n];
        let mut right = vec![0f32; n];
        let mut ml = 0f32;
        let mut mr = 0f32;
        celt_preemphasis(&pcm, &mut left, n, 2, 0, coef0, &mut ml, false);
        celt_preemphasis(&pcm, &mut right, n, 2, 1, coef0, &mut mr, false);
        // First sample has no memory yet, so it is just the scaled input.
        assert!((left[0] - 0.0).abs() < 1e-6);
        assert!((right[1] - (-0.02 * 32768.0 - coef0 * 0.0)).abs() < 1e-2);
        assert!(right.iter().skip(1).all(|&v| v < 0.0), "{right:?}");
    }

    /// `clip` must clamp the SIG-domain sample, and must be a no-op inside full scale.
    #[test]
    fn preemphasis_clip_clamps_only_over_full_scale() {
        let coef0 = PREEMPH[0];
        let pcm = [3.0f32, -3.0, 0.5];
        let mut clipped = [0f32; 3];
        let mut mem = 0f32;
        celt_preemphasis(&pcm, &mut clipped, 3, 1, 0, coef0, &mut mem, true);
        // 3.0*32768 = 98304 clamps to 65536.
        assert!((clipped[0] - 65536.0).abs() < 1e-3, "{}", clipped[0]);

        let inside = [0.5f32, -0.25];
        let mut with_clip = [0f32; 2];
        let mut without_clip = [0f32; 2];
        let mut m1 = 0f32;
        let mut m2 = 0f32;
        celt_preemphasis(&inside, &mut with_clip, 2, 1, 0, coef0, &mut m1, true);
        celt_preemphasis(&inside, &mut without_clip, 2, 1, 0, coef0, &mut m2, false);
        assert_eq!(with_clip, without_clip);
    }
}
