//! CELT Laplace coder for coarse band energy (RFC 6716 §4.3.2.1; libopus `celt/laplace.c`).
//!
//! Coarse-energy deltas are coded as a two-sided geometric ("Laplace") distribution over the range
//! coder. **Phase 3b** piece. Ported with *both* encode and decode so it is validated by an
//! encode↔decode round-trip (the coder is exactly invertible, modulo the documented in-place
//! clamping of out-of-range magnitudes on encode). The `ec_laplace_*_p0` variants in libopus are
//! `ENABLE_QEXT`-only and omitted.

use crate::opus::range_coder::{RangeDecoder, RangeEncoder};

/// `log2` of the minimum delta probability (out of 32768) — libopus `LAPLACE_LOG_MINP`.
const LAPLACE_LOG_MINP: u32 = 0;
/// Minimum delta probability — libopus `LAPLACE_MINP` (`1 << LAPLACE_LOG_MINP`).
const LAPLACE_MINP: u32 = 1 << LAPLACE_LOG_MINP;
/// Minimum guaranteed-representable deltas in one direction — libopus `LAPLACE_NMIN`.
const LAPLACE_NMIN: u32 = 16;
/// Range-coder total for the binary Laplace symbol (`1 << 15`).
const LAPLACE_FT_BITS: u32 = 15;
const LAPLACE_FT: u32 = 1 << LAPLACE_FT_BITS;

/// libopus `ec_laplace_get_freq1`. `decay` is positive and at most 11456.
fn ec_laplace_get_freq1(fs0: u32, decay: u32) -> u32 {
    let ft = LAPLACE_FT - LAPLACE_MINP * (2 * LAPLACE_NMIN) - fs0;
    (ft * (16384 - decay)) >> 15
}

/// Encode a signed energy delta `value` (libopus `ec_laplace_encode`). On the geometric tail the
/// magnitude is clamped to the largest representable value, written back into `*value`; the decoder
/// returns exactly that clamped value.
pub fn ec_laplace_encode(enc: &mut RangeEncoder, value: &mut i32, mut fs: u32, decay: u32) {
    let mut fl: u32 = 0;
    let mut val = *value;
    if val != 0 {
        let s: i32 = -i32::from(val < 0);
        val = (val + s) ^ s; // |value|
        fl = fs;
        fs = ec_laplace_get_freq1(fs, decay);
        // Search the decaying part of the PDF.
        let mut i: i32 = 1;
        while fs > 0 && i < val {
            fs *= 2;
            fl += fs + 2 * LAPLACE_MINP;
            fs = (fs * decay) >> 15;
            i += 1;
        }
        // Everything beyond that has probability LAPLACE_MINP.
        if fs == 0 {
            let ndi_max = (LAPLACE_FT - fl + LAPLACE_MINP - 1) >> LAPLACE_LOG_MINP;
            let ndi_max = ndi_max.wrapping_sub(s as u32) >> 1;
            let di = (val - i).min(ndi_max as i32 - 1);
            fl += (2 * di + 1 + s) as u32 * LAPLACE_MINP;
            fs = LAPLACE_MINP.min(LAPLACE_FT - fl);
            *value = (i + di + s) ^ s;
        } else {
            fs += LAPLACE_MINP;
            fl += fs & !(s as u32);
        }
    }
    enc.encode_bin(fl, fl + fs, LAPLACE_FT_BITS);
}

/// Decode a signed energy delta (libopus `ec_laplace_decode`).
pub fn ec_laplace_decode(dec: &mut RangeDecoder, mut fs: u32, decay: u32) -> i32 {
    let mut val: i32 = 0;
    let fm = dec.decode_bin(LAPLACE_FT_BITS);
    let mut fl: u32 = 0;
    if fm >= fs {
        val += 1;
        fl = fs;
        fs = ec_laplace_get_freq1(fs, decay) + LAPLACE_MINP;
        // Search the decaying part of the PDF.
        while fs > LAPLACE_MINP && fm >= fl + 2 * fs {
            fs *= 2;
            fl += fs;
            fs = ((fs - 2 * LAPLACE_MINP) * decay) >> 15;
            fs += LAPLACE_MINP;
            val += 1;
        }
        // Everything beyond that has probability LAPLACE_MINP.
        if fs <= LAPLACE_MINP {
            let di = (fm - fl) >> (LAPLACE_LOG_MINP + 1);
            val += di as i32;
            fl += 2 * di * LAPLACE_MINP;
        }
        if fm < fl + fs {
            val = -val;
        } else {
            fl += fs;
        }
    }
    dec.dec_update(fl, (fl + fs).min(LAPLACE_FT), LAPLACE_FT);
    val
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::celt::tables::E_PROB_MODEL;

    /// Encode `values` with `(fs, decay)`, then decode and require each back exactly (against the
    /// possibly-clamped value the encoder wrote, mirroring libopus's own round-trip self-test).
    fn roundtrip_with(fs: u32, decay: u32, values: &[i32]) {
        let mut buf = vec![0u8; 8192];
        let mut encoded = Vec::with_capacity(values.len());
        {
            let mut enc = RangeEncoder::new(&mut buf);
            for &v in values {
                let mut ev = v;
                ec_laplace_encode(&mut enc, &mut ev, fs, decay);
                encoded.push(ev);
            }
            enc.done();
            assert!(!enc.error());
        }
        let mut dec = RangeDecoder::new(&buf);
        for &ev in &encoded {
            assert_eq!(
                ec_laplace_decode(&mut dec, fs, decay),
                ev,
                "fs={fs} decay={decay}"
            );
        }
    }

    #[test]
    fn roundtrips_over_real_model_params() {
        let values: Vec<i32> = (-20..=20).collect();
        // A spread of (P(0), decay) pairs drawn from the actual coarse-energy probability model.
        for lm_models in &E_PROB_MODEL {
            for model in lm_models {
                for band in [0usize, 5, 10, 20] {
                    let fs = u32::from(model[2 * band]) << 7;
                    let decay = u32::from(model[2 * band + 1]) << 6;
                    roundtrip_with(fs, decay, &values);
                }
            }
        }
    }

    #[test]
    fn zero_delta_roundtrips_to_zero() {
        roundtrip_with(72 << 7, 127 << 6, &[0, 0, 0, 0]);
    }

    #[test]
    fn large_magnitudes_clamp_and_roundtrip() {
        // Beyond the representable range the encoder clamps; the decoder must return the clamp.
        roundtrip_with(100 << 7, 30 << 6, &[50, -50, 300, -300, 1000]);
    }
}
