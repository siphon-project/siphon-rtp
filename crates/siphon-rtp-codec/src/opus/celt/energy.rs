//! CELT band-energy decode (RFC 6716 §4.3.2; libopus `quant_bands.c`, float path).
//!
//! **Phase 3b.** Three stages fill the per-band log2 energy buffer `old_e` (consumed later by
//! `denormalise_bands`): coarse energy (Laplace-coded deltas + inter/intra log-domain prediction),
//! fine energy (raw refinement bits), and a leftover-bit finalisation. In the float build an energy
//! unit is one base-2 octave, so a coarse delta `qi` enters the predictor directly (`q = qi`).
//!
//! `old_e` is the `2*NB_BANDS` buffer; channel `c`'s band `i` lives at `i + c*NB_BANDS`. On entry to
//! [`unquant_coarse_energy`] it holds the previous frame's energy (the inter-frame predictor).

use crate::opus::celt::laplace::ec_laplace_decode;
use crate::opus::celt::tables::{
    BETA_COEF, BETA_INTRA, E_PROB_MODEL, NB_BANDS, PRED_COEF, SMALL_ENERGY_ICDF,
};
use crate::opus::range_coder::RangeDecoder;

/// Maximum fine-energy bits per band (libopus `MAX_FINE_BITS`).
pub const MAX_FINE_BITS: i32 = 8;

/// Decode coarse band energy (libopus `unquant_coarse_energy`).
pub fn unquant_coarse_energy(
    start: usize,
    end: usize,
    old_e: &mut [f32],
    intra: bool,
    dec: &mut RangeDecoder,
    channels: usize,
    lm: usize,
) {
    let prob_model = &E_PROB_MODEL[lm][usize::from(intra)];
    let mut prev = [0f32; 2];
    let (coef, beta) = if intra {
        (0.0, BETA_INTRA)
    } else {
        (PRED_COEF[lm], BETA_COEF[lm])
    };
    let budget = dec.storage_bits() as i32;
    for i in start..end {
        for (c, prev_c) in prev.iter_mut().enumerate().take(channels) {
            let tell = dec.tell();
            let qi = if budget - tell >= 15 {
                // Coarse resolution: Laplace-coded delta.
                let pi = 2 * i.min(20);
                ec_laplace_decode(
                    dec,
                    u32::from(prob_model[pi]) << 7,
                    u32::from(prob_model[pi + 1]) << 6,
                )
            } else if budget - tell >= 2 {
                // Tight budget: a 3-symbol ICDF, then un-zigzag.
                let qi = dec.dec_icdf(&SMALL_ENERGY_ICDF, 2) as i32;
                (qi >> 1) ^ -(qi & 1)
            } else if budget - tell >= 1 {
                -i32::from(dec.dec_bit_logp(1))
            } else {
                -1
            };
            let q = qi as f32;
            let idx = i + c * NB_BANDS;
            old_e[idx] = old_e[idx].max(-9.0);
            old_e[idx] = coef * old_e[idx] + *prev_c + q;
            *prev_c += q - beta * q;
        }
    }
}

/// Decode fine band-energy refinements (libopus `unquant_fine_energy`, decoder path — `prev_quant`
/// is `NULL`, so the prediction scaling is unity).
pub fn unquant_fine_energy(
    start: usize,
    end: usize,
    old_e: &mut [f32],
    fine_quant: &[i32],
    dec: &mut RangeDecoder,
    channels: usize,
) {
    for i in start..end {
        let extra = fine_quant[i];
        if extra <= 0 {
            continue;
        }
        if dec.tell() + channels as i32 * extra > dec.storage_bits() as i32 {
            continue;
        }
        for c in 0..channels {
            let q2 = dec.dec_bits(extra as u32) as i32;
            let offset = (q2 as f32 + 0.5) * (1 << (14 - extra)) as f32 * (1.0 / 16384.0) - 0.5;
            old_e[i + c * NB_BANDS] += offset;
        }
    }
}

/// Distribute leftover bits as a final 1-bit energy refinement (libopus `unquant_energy_finalise`).
pub fn unquant_energy_finalise(
    start: usize,
    end: usize,
    old_e: &mut [f32],
    fine_quant: &[i32],
    fine_priority: &[i32],
    mut bits_left: i32,
    dec: &mut RangeDecoder,
    channels: usize,
) {
    let c_bits = channels as i32;
    for prio in 0..2 {
        for i in start..end {
            if bits_left < c_bits {
                break;
            }
            if fine_quant[i] >= MAX_FINE_BITS || fine_priority[i] != prio {
                continue;
            }
            for c in 0..channels {
                let q2 = dec.dec_bits(1) as i32;
                let offset =
                    (q2 as f32 - 0.5) * (1 << (14 - fine_quant[i] - 1)) as f32 * (1.0 / 16384.0);
                old_e[i + c * NB_BANDS] += offset;
                bits_left -= 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::celt::laplace::ec_laplace_encode;
    use crate::opus::range_coder::RangeEncoder;

    /// Encode a chosen coarse-delta sequence (via the Laplace encoder, exactly as the decoder reads
    /// it), independently apply the inter-frame prediction recurrence, and require the decoder to
    /// reproduce the same per-band energies.
    #[test]
    fn coarse_energy_matches_encoded_prediction_recurrence() {
        let lm = 3usize;
        let channels = 1usize;
        let end = NB_BANDS;
        let prob_model = &E_PROB_MODEL[lm][0]; // inter
        let (coef, beta) = (PRED_COEF[lm], BETA_COEF[lm]);

        let qis: Vec<i32> = (0..end).map(|i| ((i as i32 * 7 + 3) % 9) - 4).collect();

        let mut buf = vec![0u8; 4096];
        let mut clamped = Vec::with_capacity(end);
        {
            let mut enc = RangeEncoder::new(&mut buf);
            for (i, &qi) in qis.iter().enumerate() {
                let pi = 2 * i.min(20);
                let mut v = qi;
                ec_laplace_encode(
                    &mut enc,
                    &mut v,
                    u32::from(prob_model[pi]) << 7,
                    u32::from(prob_model[pi + 1]) << 6,
                );
                clamped.push(v);
            }
            enc.done();
            assert!(!enc.error());
        }

        // Reference recurrence (initial energy 0), using the clamped deltas.
        let mut expected = [0f32; 2 * NB_BANDS];
        let mut prev = 0f32;
        for i in 0..end {
            let q = clamped[i] as f32;
            expected[i] = expected[i].max(-9.0);
            expected[i] = coef * expected[i] + prev + q;
            prev += q - beta * q;
        }

        let mut old_e = vec![0f32; 2 * NB_BANDS];
        let mut dec = RangeDecoder::new(&buf);
        unquant_coarse_energy(0, end, &mut old_e, false, &mut dec, channels, lm);
        for i in 0..end {
            assert!(
                (old_e[i] - expected[i]).abs() < 1e-3,
                "band {i}: {} vs {}",
                old_e[i],
                expected[i]
            );
        }
    }

    /// Encode chosen fine-refinement bits and require the decoded offsets to match the documented
    /// fine-energy formula.
    #[test]
    fn fine_energy_applies_expected_offsets() {
        let channels = 1usize;
        let end = NB_BANDS;
        let fine_quant: Vec<i32> = (0..end).map(|i| 1 + (i as i32 % 4)).collect(); // 1..=4 bits
        let q2s: Vec<i32> = (0..end)
            .map(|i| (i as i32 * 5 + 1) % (1 << fine_quant[i]))
            .collect();

        let mut buf = vec![0u8; 4096];
        {
            let mut enc = RangeEncoder::new(&mut buf);
            for i in 0..end {
                enc.enc_bits(q2s[i] as u32, fine_quant[i] as u32);
            }
            enc.done();
            assert!(!enc.error());
        }

        let mut old_e = vec![0f32; 2 * NB_BANDS];
        let mut dec = RangeDecoder::new(&buf);
        unquant_fine_energy(0, end, &mut old_e, &fine_quant, &mut dec, channels);
        for i in 0..end {
            let extra = fine_quant[i];
            let expected =
                (q2s[i] as f32 + 0.5) * (1 << (14 - extra)) as f32 * (1.0 / 16384.0) - 0.5;
            assert!((old_e[i] - expected).abs() < 1e-5, "band {i}");
        }
    }
}
