//! CELT band-energy decode (RFC 6716 §4.3.2; libopus `quant_bands.c`, float path).
//!
//! **Phase 3b.** Three stages fill the per-band log2 energy buffer `old_e` (consumed later by
//! `denormalise_bands`): coarse energy (Laplace-coded deltas + inter/intra log-domain prediction),
//! fine energy (raw refinement bits), and a leftover-bit finalisation. In the float build an energy
//! unit is one base-2 octave, so a coarse delta `qi` enters the predictor directly (`q = qi`).
//!
//! `old_e` is the `2*NB_BANDS` buffer; channel `c`'s band `i` lives at `i + c*NB_BANDS`. On entry to
//! [`unquant_coarse_energy`] it holds the previous frame's energy (the inter-frame predictor).

use crate::opus::celt::laplace::{ec_laplace_decode, ec_laplace_encode};
use crate::opus::celt::tables::{
    BETA_COEF, BETA_INTRA, E_PROB_MODEL, NB_BANDS, PRED_COEF, SMALL_ENERGY_ICDF,
};
use crate::opus::range_coder::{RangeDecoder, RangeEncoder};

/// Maximum fine-energy bits per band (libopus `MAX_FINE_BITS`).
pub const MAX_FINE_BITS: i32 = 8;

/// Largest Opus packet, and therefore the largest byte range the two-pass coarse-energy trial can
/// have to save (RFC 6716 §3.4: 1275 bytes per frame).
const MAX_PACKET_BYTES: usize = 1275;

/// Energy floor in the log2 domain (libopus `-QCONST16(28.f, DB_SHIFT)`).
const ENERGY_FLOOR_DB: f32 = -28.0;

/// Encode the coarse band energy for one prediction mode (libopus `quant_coarse_energy_impl`,
/// `quant_bands.c:156`, float path). Returns the *badness* — the total magnitude by which the
/// bit-budget guards had to pull the ideal `qi` back — which the two-pass trial minimises.
///
/// The predictor recurrence is bit-for-bit the decoder's ([`unquant_coarse_energy`]): the encoder
/// picks `qi` by rounding the prediction residual, and then advances `old_e`/`prev` with the
/// *quantised* value so both sides stay in lockstep.
#[allow(clippy::too_many_arguments)]
fn quant_coarse_energy_impl(
    start: usize,
    end: usize,
    band_log_e: &[f32],
    old_e: &mut [f32],
    budget: i32,
    tell: i32,
    prob_model: &[u8; 42],
    error: &mut [f32],
    enc: &mut RangeEncoder,
    channels: usize,
    lm: usize,
    intra: bool,
    max_decay: f32,
) -> i32 {
    let mut badness = 0i32;
    let mut prev = [0f32; 2];
    let (coef, beta) = if intra {
        (0.0, BETA_INTRA)
    } else {
        (PRED_COEF[lm], BETA_COEF[lm])
    };
    if tell + 3 <= budget {
        enc.enc_bit_logp(intra, 3);
    }
    for i in start..end {
        for (c, prev_c) in prev.iter_mut().enumerate().take(channels) {
            let idx = i + c * NB_BANDS;
            let x = band_log_e[idx];
            let old = old_e[idx].max(-9.0);
            let f = x - coef * old - *prev_c;
            // "Rounding to nearest integer here is really important!" (quant_bands.c:201)
            let mut qi = (0.5 + f).floor() as i32;
            // Prevent the energy from dropping too fast (e.g. a one-bin band).
            let decay_bound = old_e[idx].max(ENERGY_FLOOR_DB) - max_decay;
            if qi < 0 && x < decay_bound {
                qi += (decay_bound - x) as i32; // `SHR16(.., DB_SHIFT)` is the identity in float
                if qi > 0 {
                    qi = 0;
                }
            }
            let qi0 = qi;
            // If we don't have enough bits to encode all the energy, assume something safe.
            let tell = enc.tell();
            let bits_left = budget - tell - 3 * (channels as i32) * (end as i32 - i as i32);
            if i != start && bits_left < 30 {
                if bits_left < 24 {
                    qi = qi.min(1);
                }
                if bits_left < 16 {
                    qi = qi.max(-1);
                }
            }
            if budget - tell >= 15 {
                let pi = 2 * i.min(20);
                // `ec_laplace_encode` clamps an out-of-range magnitude in place, so `qi` below is
                // exactly what the decoder will return.
                ec_laplace_encode(
                    enc,
                    &mut qi,
                    u32::from(prob_model[pi]) << 7,
                    u32::from(prob_model[pi + 1]) << 6,
                );
            } else if budget - tell >= 2 {
                qi = qi.clamp(-1, 1);
                // Zig-zag: 0 -> 0, -1 -> 1, 1 -> 2 (the decoder un-zigzags with
                // `(qi>>1) ^ -(qi&1)`).
                let symbol = ((2 * qi) ^ -i32::from(qi < 0)) as usize;
                enc.enc_icdf(symbol, &SMALL_ENERGY_ICDF, 2);
            } else if budget - tell >= 1 {
                qi = qi.min(0);
                // libopus writes the *sign* as one bit and keeps the unclamped `qi` for the
                // predictor, so a `qi < -1` here leaves encoder and decoder on different energies
                // (`quant_bands.c:241` vs the decoder's `-(bit)`). Reproduced deliberately: this
                // path only triggers with under 2 bits left in the whole packet, and diverging
                // from the reference would be the worse bug.
                enc.enc_bit_logp(-qi != 0, 1);
            } else {
                qi = -1;
            }
            error[idx] = f - qi as f32;
            badness += (qi0 - qi).abs();
            let q = qi as f32;
            old_e[idx] = coef * old + *prev_c + q;
            *prev_c += q - beta * q;
        }
    }
    badness
}

/// Squared log-energy distance from the previous frame (libopus `loss_distortion`,
/// `quant_bands.c:142`), capped at 200. Drives the intra-refresh decision: the more the spectrum
/// moved, the more a lost frame would cost, so the more an intra frame is worth.
fn loss_distortion(
    band_log_e: &[f32],
    old_e: &[f32],
    start: usize,
    end: usize,
    channels: usize,
) -> f32 {
    let mut dist = 0f32;
    for c in 0..channels {
        for i in start..end {
            let d = band_log_e[i + c * NB_BANDS] - old_e[i + c * NB_BANDS];
            dist += d * d;
        }
    }
    dist.min(200.0)
}

/// Encode the coarse band energy, choosing between inter- and intra-frame prediction (libopus
/// `quant_coarse_energy`, `quant_bands.c:261`). Returns whether the *intra* model was used.
///
/// With `two_pass` set (libopus: `complexity >= 4`) both models are actually encoded and the
/// cheaper one kept — which needs a real rollback of the range encoder, hence
/// [`RangeEncoder::save_state`] plus a replay of the byte range the trial touched. `budget` is the
/// packet size in bits; `delayed_intra` is the running distortion accumulator held in the encoder
/// state.
#[allow(clippy::too_many_arguments)]
pub fn quant_coarse_energy(
    start: usize,
    end: usize,
    eff_end: usize,
    band_log_e: &[f32],
    old_e: &mut [f32],
    budget: i32,
    error: &mut [f32],
    enc: &mut RangeEncoder,
    channels: usize,
    lm: usize,
    nb_available_bytes: i32,
    force_intra: bool,
    delayed_intra: &mut f32,
    mut two_pass: bool,
    loss_rate: i32,
) -> bool {
    let span = (end - start) as i32;
    let mut intra = force_intra
        || (!two_pass
            && *delayed_intra > 2.0 * (channels as i32 * span) as f32
            && nb_available_bytes > span * channels as i32);
    let intra_bias =
        ((budget as f32) * *delayed_intra * loss_rate as f32 / (channels as f32 * 512.0)) as i32;
    let new_distortion = loss_distortion(band_log_e, old_e, start, eff_end, channels);

    let tell = enc.tell();
    if tell + 3 > budget {
        two_pass = false;
        intra = false;
    }

    let mut max_decay = 16.0f32;
    if end - start > 10 {
        max_decay = max_decay.min(0.125 * nb_available_bytes as f32);
    }

    let enc_start_state = enc.save_state();
    let nstart_bytes = enc.range_bytes() as usize;
    let coded = channels * NB_BANDS;
    let mut old_e_intra = [0f32; 2 * NB_BANDS];
    let mut error_intra = [0f32; 2 * NB_BANDS];
    old_e_intra[..coded].copy_from_slice(&old_e[..coded]);

    let mut badness1 = 0i32;
    if two_pass || intra {
        badness1 = quant_coarse_energy_impl(
            start,
            end,
            band_log_e,
            &mut old_e_intra,
            budget,
            tell,
            &E_PROB_MODEL[lm][1],
            &mut error_intra,
            enc,
            channels,
            lm,
            true,
            max_decay,
        );
    }

    if !intra {
        let tell_intra = enc.tell_frac() as i32;
        let enc_intra_state = enc.save_state();
        let nintra_bytes = enc.range_bytes() as usize;
        let save_bytes = nintra_bytes - nstart_bytes;
        let mut intra_bits = [0u8; MAX_PACKET_BYTES];
        intra_bits[..save_bytes].copy_from_slice(&enc.buffer()[nstart_bytes..nintra_bytes]);

        enc.restore_state(&enc_start_state);
        let badness2 = quant_coarse_energy_impl(
            start,
            end,
            band_log_e,
            old_e,
            budget,
            tell,
            &E_PROB_MODEL[lm][0],
            error,
            enc,
            channels,
            lm,
            false,
            max_decay,
        );
        if two_pass
            && (badness1 < badness2
                || (badness1 == badness2 && enc.tell_frac() as i32 + intra_bias > tell_intra))
        {
            enc.restore_state(&enc_intra_state);
            enc.buffer_mut()[nstart_bytes..nintra_bytes].copy_from_slice(&intra_bits[..save_bytes]);
            old_e[..coded].copy_from_slice(&old_e_intra[..coded]);
            error[..coded].copy_from_slice(&error_intra[..coded]);
            intra = true;
        }
    } else {
        old_e[..coded].copy_from_slice(&old_e_intra[..coded]);
        error[..coded].copy_from_slice(&error_intra[..coded]);
    }

    if intra {
        *delayed_intra = new_distortion;
    } else {
        *delayed_intra = PRED_COEF[lm] * PRED_COEF[lm] * *delayed_intra + new_distortion;
    }
    intra
}

/// Encode the fine band-energy refinements (libopus `quant_fine_energy`, `quant_bands.c:361`).
/// Consumes the residual left in `error` by the coarse pass and updates it with what was coded, so
/// [`quant_energy_finalise`] can spend leftover bits on the remainder.
pub fn quant_fine_energy(
    start: usize,
    end: usize,
    old_e: &mut [f32],
    error: &mut [f32],
    fine_quant: &[i32],
    enc: &mut RangeEncoder,
    channels: usize,
) {
    for (i, &extra) in fine_quant.iter().enumerate().take(end).skip(start) {
        if extra <= 0 {
            continue;
        }
        let frac = 1i32 << extra;
        for c in 0..channels {
            let idx = i + c * NB_BANDS;
            // Truncating (not rounding) division, per the C's `floor`.
            let q2 = (((error[idx] + 0.5) * frac as f32).floor() as i32).clamp(0, frac - 1);
            enc.enc_bits(q2 as u32, extra as u32);
            let offset = (q2 as f32 + 0.5) * (1 << (14 - extra)) as f32 * (1.0 / 16384.0) - 0.5;
            old_e[idx] += offset;
            error[idx] -= offset;
        }
    }
}

/// Spend any leftover bits on a final 1-bit energy refinement (libopus `quant_energy_finalise`,
/// `quant_bands.c:398`) — the exact mirror of [`unquant_energy_finalise`].
#[allow(clippy::too_many_arguments)]
pub fn quant_energy_finalise(
    start: usize,
    end: usize,
    old_e: &mut [f32],
    error: &mut [f32],
    fine_quant: &[i32],
    fine_priority: &[i32],
    mut bits_left: i32,
    enc: &mut RangeEncoder,
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
                let idx = i + c * NB_BANDS;
                let q2 = i32::from(error[idx] >= 0.0);
                enc.enc_bits(q2 as u32, 1);
                let offset =
                    (q2 as f32 - 0.5) * (1 << (14 - fine_quant[i] - 1)) as f32 * (1.0 / 16384.0);
                old_e[idx] += offset;
                error[idx] -= offset;
                bits_left -= 1;
            }
        }
    }
}

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

    // ── Encoder side ────────────────────────────────────────────────────────────────────────────
    //
    // The decode path above is validated bitstream-exact against libopus (96 CELT-only streams),
    // so it is the reference the encode path is checked against: whatever the encoder writes, the
    // decoder must reconstruct the *same* `old_e` — a shared bug is not possible here because only
    // one of the two directions is new.

    /// A plausible per-band log2 energy curve (falling with frequency, like real audio).
    fn synthetic_band_log_energy(seed: u32, channels: usize) -> Vec<f32> {
        let mut out = vec![0f32; 2 * NB_BANDS];
        for c in 0..channels {
            for i in 0..NB_BANDS {
                let jitter =
                    (((seed.wrapping_mul(2_654_435_761) >> (i % 16)) & 0xff) as f32 / 255.0 - 0.5)
                        * 3.0;
                out[i + c * NB_BANDS] = 6.0 - 0.35 * i as f32 + jitter + c as f32 * 0.5;
            }
        }
        out
    }

    /// Encode coarse energy, then decode it: the decoder's reconstructed `old_e` must equal the
    /// encoder's, band for band and channel for channel, for every frame size, both prediction
    /// modes, and mono/stereo.
    #[test]
    fn coarse_energy_encode_then_decode_agrees_on_every_band() {
        for lm in 0..4usize {
            for channels in 1..=2usize {
                for force_intra in [false, true] {
                    let end = NB_BANDS;
                    let band_log_e = synthetic_band_log_energy(0x1234 + lm as u32, channels);
                    let mut buf = vec![0u8; 400];
                    let budget = (buf.len() as i32) * 8;

                    let mut enc_old_e = vec![0f32; 2 * NB_BANDS];
                    let mut error = vec![0f32; 2 * NB_BANDS];
                    let mut delayed_intra = 0f32;
                    let used_intra;
                    {
                        let mut enc = RangeEncoder::new(&mut buf);
                        used_intra = quant_coarse_energy(
                            0,
                            end,
                            end,
                            &band_log_e,
                            &mut enc_old_e,
                            budget,
                            &mut error,
                            &mut enc,
                            channels,
                            lm,
                            400,
                            force_intra,
                            &mut delayed_intra,
                            true,
                            0,
                        );
                        enc.done();
                        assert!(!enc.error(), "lm={lm} c={channels}: encoder overflow");
                    }
                    if force_intra {
                        assert!(used_intra, "force_intra must select the intra model");
                    }

                    let mut dec_old_e = vec![0f32; 2 * NB_BANDS];
                    let mut dec = RangeDecoder::new(&buf);
                    // The intra flag is the first symbol the encoder wrote.
                    let intra = dec.dec_bit_logp(3);
                    assert_eq!(intra, used_intra, "lm={lm} c={channels}: intra flag");
                    unquant_coarse_energy(0, end, &mut dec_old_e, intra, &mut dec, channels, lm);
                    for c in 0..channels {
                        for i in 0..end {
                            let idx = i + c * NB_BANDS;
                            assert!(
                                (enc_old_e[idx] - dec_old_e[idx]).abs() < 1e-4,
                                "lm={lm} c={channels} intra={force_intra} band {i} ch {c}: \
                                 enc {} != dec {}",
                                enc_old_e[idx],
                                dec_old_e[idx]
                            );
                        }
                    }
                    // The residual the coarse pass leaves must be within half a coarse step.
                    for c in 0..channels {
                        for i in 0..end {
                            let e = error[i + c * NB_BANDS];
                            assert!(
                                e.abs() <= 0.5 + 1e-4,
                                "lm={lm} band {i}: coarse error {e} exceeds half a step"
                            );
                        }
                    }
                }
            }
        }
    }

    /// The two-pass trial must roll the encoder back cleanly: whichever model it keeps, the stream
    /// still decodes to the same energies. Driven with a spectrum that moves a lot frame to frame
    /// (which is what makes intra win) across several frames so the rollback path actually fires.
    #[test]
    fn coarse_energy_two_pass_rollback_produces_a_decodable_stream() {
        let lm = 3usize;
        let channels = 1usize;
        let end = NB_BANDS;
        let mut enc_old_e = vec![0f32; 2 * NB_BANDS];
        let mut dec_old_e = vec![0f32; 2 * NB_BANDS];
        let mut delayed_intra = 0f32;
        let mut intra_count = 0usize;

        for frame in 0..8u32 {
            // Alternate between two very different spectra so `loss_distortion` stays high.
            let band_log_e = if frame % 2 == 0 {
                synthetic_band_log_energy(0xAAAA, channels)
            } else {
                let mut e = synthetic_band_log_energy(0x5555, channels);
                for v in e.iter_mut() {
                    *v = -*v;
                }
                e
            };
            let mut buf = vec![0u8; 120];
            let budget = (buf.len() as i32) * 8;
            let mut error = vec![0f32; 2 * NB_BANDS];
            let used_intra;
            {
                let mut enc = RangeEncoder::new(&mut buf);
                used_intra = quant_coarse_energy(
                    0,
                    end,
                    end,
                    &band_log_e,
                    &mut enc_old_e,
                    budget,
                    &mut error,
                    &mut enc,
                    channels,
                    lm,
                    120,
                    false,
                    &mut delayed_intra,
                    true,
                    0,
                );
                enc.done();
                assert!(!enc.error(), "frame {frame}: encoder overflow");
            }
            if used_intra {
                intra_count += 1;
            }
            let mut dec = RangeDecoder::new(&buf);
            let intra = dec.dec_bit_logp(3);
            assert_eq!(intra, used_intra, "frame {frame}: intra flag");
            unquant_coarse_energy(0, end, &mut dec_old_e, intra, &mut dec, channels, lm);
            for i in 0..end {
                assert!(
                    (enc_old_e[i] - dec_old_e[i]).abs() < 1e-4,
                    "frame {frame} band {i}: enc {} != dec {}",
                    enc_old_e[i],
                    dec_old_e[i]
                );
            }
        }
        // With a spectrum that flips sign every frame the intra model must win at least once,
        // proving the rollback branch (restore state + replay bytes) actually executed.
        assert!(
            intra_count > 0,
            "two-pass never selected intra, so the rollback path was never exercised"
        );
    }

    /// Fine energy: encode then decode must apply the identical offsets, and the residual must
    /// shrink by roughly the quantiser step.
    #[test]
    fn fine_energy_encode_then_decode_agrees() {
        for channels in 1..=2usize {
            let end = NB_BANDS;
            let fine_quant: Vec<i32> = (0..end).map(|i| i as i32 % 5).collect();
            // A coarse residual in [-0.5, 0.5], which is what `quant_coarse_energy` leaves.
            let mut error = vec![0f32; 2 * NB_BANDS];
            for c in 0..channels {
                for i in 0..end {
                    error[i + c * NB_BANDS] = ((i as f32 * 0.37 + c as f32).sin()) * 0.5;
                }
            }
            let base: Vec<f32> = (0..2 * NB_BANDS).map(|i| i as f32 * 0.1).collect();

            let mut enc_old_e = base.clone();
            let mut enc_error = error.clone();
            let mut buf = vec![0u8; 200];
            {
                let mut enc = RangeEncoder::new(&mut buf);
                quant_fine_energy(
                    0,
                    end,
                    &mut enc_old_e,
                    &mut enc_error,
                    &fine_quant,
                    &mut enc,
                    channels,
                );
                enc.done();
                assert!(!enc.error());
            }
            let mut dec_old_e = base.clone();
            let mut dec = RangeDecoder::new(&buf);
            unquant_fine_energy(0, end, &mut dec_old_e, &fine_quant, &mut dec, channels);
            for c in 0..channels {
                for (i, &bits) in fine_quant.iter().enumerate().take(end) {
                    let idx = i + c * NB_BANDS;
                    assert!(
                        (enc_old_e[idx] - dec_old_e[idx]).abs() < 1e-6,
                        "c={channels} band {i} ch {c}: enc {} != dec {}",
                        enc_old_e[idx],
                        dec_old_e[idx]
                    );
                    // A band with k fine bits must cut the residual to about 2^-k.
                    if bits > 0 {
                        let step = (1 << bits) as f32;
                        assert!(
                            enc_error[idx].abs() <= 0.5 / step + 1e-4,
                            "band {i} ({bits} bits): residual {} not reduced",
                            enc_error[idx]
                        );
                    }
                }
            }
        }
    }

    /// The final leftover-bit pass must agree with the decoder and always move the energy toward
    /// the residual's sign.
    #[test]
    fn energy_finalise_encode_then_decode_agrees() {
        let end = NB_BANDS;
        let channels = 1usize;
        let fine_quant: Vec<i32> = (0..end).map(|i| i as i32 % 4).collect();
        let fine_priority: Vec<i32> = (0..end).map(|i| i as i32 % 2).collect();
        let mut error = vec![0f32; 2 * NB_BANDS];
        for (i, e) in error.iter_mut().enumerate().take(end) {
            *e = if i % 3 == 0 { 0.05 } else { -0.05 };
        }
        let base = vec![1.0f32; 2 * NB_BANDS];

        let mut enc_old_e = base.clone();
        let mut enc_error = error.clone();
        let mut buf = vec![0u8; 64];
        {
            let mut enc = RangeEncoder::new(&mut buf);
            quant_energy_finalise(
                0,
                end,
                &mut enc_old_e,
                &mut enc_error,
                &fine_quant,
                &fine_priority,
                100,
                &mut enc,
                channels,
            );
            enc.done();
            assert!(!enc.error());
        }
        let mut dec_old_e = base.clone();
        let mut dec = RangeDecoder::new(&buf);
        unquant_energy_finalise(
            0,
            end,
            &mut dec_old_e,
            &fine_quant,
            &fine_priority,
            100,
            &mut dec,
            channels,
        );
        for i in 0..end {
            assert!(
                (enc_old_e[i] - dec_old_e[i]).abs() < 1e-6,
                "band {i}: enc {} != dec {}",
                enc_old_e[i],
                dec_old_e[i]
            );
            // The refinement must push the energy the way the residual pointed.
            if fine_quant[i] < MAX_FINE_BITS {
                let delta = enc_old_e[i] - base[i];
                assert_eq!(
                    delta > 0.0,
                    error[i] >= 0.0,
                    "band {i}: refinement went the wrong way ({delta} for error {})",
                    error[i]
                );
            }
        }
    }

    /// A budget so tight that the coarse encoder has to fall back to the 3-symbol ICDF and then to
    /// the single sign bit must still produce a stream the decoder follows symbol for symbol.
    #[test]
    fn coarse_energy_tight_budget_stays_in_sync() {
        let lm = 0usize;
        let channels = 1usize;
        let end = NB_BANDS;
        let band_log_e = synthetic_band_log_energy(0x77, channels);
        // 6 bytes for 21 bands forces every tight-budget branch.
        let mut buf = vec![0u8; 6];
        let budget = (buf.len() as i32) * 8;
        let mut enc_old_e = vec![0f32; 2 * NB_BANDS];
        let mut error = vec![0f32; 2 * NB_BANDS];
        let mut delayed_intra = 0f32;
        let used_intra;
        {
            let mut enc = RangeEncoder::new(&mut buf);
            used_intra = quant_coarse_energy(
                0,
                end,
                end,
                &band_log_e,
                &mut enc_old_e,
                budget,
                &mut error,
                &mut enc,
                channels,
                lm,
                6,
                false,
                &mut delayed_intra,
                true,
                0,
            );
            enc.done();
        }
        let mut dec_old_e = vec![0f32; 2 * NB_BANDS];
        let mut dec = RangeDecoder::new(&buf);
        let intra = dec.dec_bit_logp(3);
        assert_eq!(intra, used_intra);
        unquant_coarse_energy(0, end, &mut dec_old_e, intra, &mut dec, channels, lm);
        // The low bands (coded while bits remained) must match exactly; the tail runs out of
        // budget, where libopus' own encoder/decoder pair diverges by design (see the
        // `budget-tell >= 1` note in `quant_coarse_energy_impl`).
        for i in 0..8 {
            assert!(
                (enc_old_e[i] - dec_old_e[i]).abs() < 1e-4,
                "band {i}: enc {} != dec {}",
                enc_old_e[i],
                dec_old_e[i]
            );
        }
    }
}
