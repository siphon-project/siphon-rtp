//! The entropy-coder abstraction that lets the CELT band quantiser and bit allocator be written
//! **once** for both directions (RFC 6716 §4.3.3-4.3.4).
//!
//! libopus passes a single `ec_ctx` plus an `encode` flag through `quant_all_bands`,
//! `quant_band`, `quant_partition`, `compute_theta` and `interp_bits2pulses`, and branches on that
//! flag at each symbol (`bands.c:721`, `rate.c:346`). Rust has distinct
//! [`RangeEncoder`]/[`RangeDecoder`] types, so the shared code is generic over this trait instead —
//! same single implementation, no duplicated allocator or band recursion. `ENCODE` is an associated
//! constant so the encode-only decision code compiles out of the decoder entirely.
//!
//! Every method takes its value by `&mut`: on the encoder it *writes* what the caller decided, on
//! the decoder it *overwrites* the caller's placeholder with what was read. That is exactly the
//! `if (encode) ec_enc_x(ec, v, ..) else v = ec_dec_x(ec, ..)` shape of the C, expressed once.

use crate::opus::celt::bands::isqrt32;
use crate::opus::celt::vq::{alg_quant, alg_unquant};
use crate::opus::range_coder::{RangeDecoder, RangeEncoder};

/// One side of the CELT entropy layer, as seen by the shared band-coding and allocation code.
pub trait CeltCoder {
    /// `true` for the encoder, `false` for the decoder (libopus' `encode` flag).
    const ENCODE: bool;

    /// Bits consumed/produced so far, rounded up (libopus `ec_tell`).
    fn tell(&self) -> i32;
    /// Bits consumed/produced so far in 1/8-bit units (libopus `ec_tell_frac`).
    fn tell_frac(&self) -> u32;
    /// The buffer's total capacity in bits (libopus `ec->storage*8`).
    fn storage_bits(&self) -> u32;
    /// The current range register (libopus `ec->rng`) — the cross-frame fold/anti-collapse seed.
    fn rng(&self) -> u32;

    /// `bits` raw bits (libopus `ec_enc_bits` / `ec_dec_bits`).
    fn code_bits(&mut self, value: &mut u32, bits: u32);
    /// A single bit with probability `1/(1<<logp)` of being one (libopus `ec_{enc,dec}_bit_logp`).
    fn code_bit_logp(&mut self, value: &mut bool, logp: u32);
    /// A symbol from an inverse-CDF table (libopus `ec_{enc,dec}_icdf`).
    fn code_icdf(&mut self, value: &mut usize, icdf: &[u8], ftb: u32);
    /// A uniformly-distributed integer in `[0, ft)` (libopus `ec_{enc,dec}_uint`).
    fn code_uint(&mut self, value: &mut u32, ft: u32);

    /// The stereo split angle's **step** pdf, used when `stereo && N > 2` (`bands.c:777`):
    /// probability `p0 = 3` up to `itheta = qn/2`, then 1.
    fn code_theta_step(&mut self, itheta: &mut i32, qn: i32);
    /// The split angle's **uniform** pdf, used for a time split of more than one block or for
    /// stereo `N == 2` (`bands.c:797`).
    fn code_theta_uniform(&mut self, itheta: &mut i32, qn: i32);
    /// The split angle's **triangular** pdf, the default for a mono time split (`bands.c:803`).
    fn code_theta_triangular(&mut self, itheta: &mut i32, qn: i32);

    /// One band's PVQ shape: `alg_quant` on the encoder, `alg_unquant` on the decoder
    /// (`bands.c:1056`). Returns the anti-collapse mask. `resynth` is ignored by the decoder, which
    /// always reconstructs.
    #[allow(clippy::too_many_arguments)]
    fn code_band_shape(
        &mut self,
        x: &mut [f32],
        n: usize,
        k: usize,
        spread: u32,
        b: usize,
        gain: f32,
        resynth: bool,
    ) -> u32;
}

/// `[fl, fh)` for the step pdf at `x` (libopus `bands.c:786`, shared by both directions).
#[inline]
fn theta_step_range(x: i32, x0: i32, p0: i32) -> (i32, i32) {
    if x <= x0 {
        (p0 * x, p0 * (x + 1))
    } else {
        ((x - 1 - x0) + (x0 + 1) * p0, (x - x0) + (x0 + 1) * p0)
    }
}

impl CeltCoder for RangeEncoder<'_> {
    const ENCODE: bool = true;

    fn tell(&self) -> i32 {
        RangeEncoder::tell(self)
    }
    fn tell_frac(&self) -> u32 {
        RangeEncoder::tell_frac(self)
    }
    fn storage_bits(&self) -> u32 {
        RangeEncoder::storage_bits(self)
    }
    fn rng(&self) -> u32 {
        RangeEncoder::rng(self)
    }

    fn code_bits(&mut self, value: &mut u32, bits: u32) {
        self.enc_bits(*value, bits);
    }
    fn code_bit_logp(&mut self, value: &mut bool, logp: u32) {
        self.enc_bit_logp(*value, logp);
    }
    fn code_icdf(&mut self, value: &mut usize, icdf: &[u8], ftb: u32) {
        self.enc_icdf(*value, icdf, ftb);
    }
    fn code_uint(&mut self, value: &mut u32, ft: u32) {
        self.enc_uint(*value, ft);
    }

    fn code_theta_step(&mut self, itheta: &mut i32, qn: i32) {
        let p0 = 3i32;
        let x0 = qn / 2;
        let ft = p0 * (x0 + 1) + x0;
        let (fl, fh) = theta_step_range(*itheta, x0, p0);
        self.encode(fl as u32, fh as u32, ft as u32);
    }

    fn code_theta_uniform(&mut self, itheta: &mut i32, qn: i32) {
        self.enc_uint(*itheta as u32, (qn + 1) as u32);
    }

    fn code_theta_triangular(&mut self, itheta: &mut i32, qn: i32) {
        let ft = ((qn >> 1) + 1) * ((qn >> 1) + 1);
        let t = *itheta;
        let (fl, fs) = if t <= (qn >> 1) {
            ((t * (t + 1)) >> 1, t + 1)
        } else {
            (ft - (((qn + 1 - t) * (qn + 2 - t)) >> 1), qn + 1 - t)
        };
        self.encode(fl as u32, (fl + fs) as u32, ft as u32);
    }

    fn code_band_shape(
        &mut self,
        x: &mut [f32],
        n: usize,
        k: usize,
        spread: u32,
        b: usize,
        gain: f32,
        resynth: bool,
    ) -> u32 {
        alg_quant(x, n, k, spread, b, self, gain, resynth)
    }
}

impl CeltCoder for RangeDecoder<'_> {
    const ENCODE: bool = false;

    fn tell(&self) -> i32 {
        RangeDecoder::tell(self)
    }
    fn tell_frac(&self) -> u32 {
        RangeDecoder::tell_frac(self)
    }
    fn storage_bits(&self) -> u32 {
        RangeDecoder::storage_bits(self)
    }
    fn rng(&self) -> u32 {
        RangeDecoder::rng(self)
    }

    fn code_bits(&mut self, value: &mut u32, bits: u32) {
        *value = self.dec_bits(bits);
    }
    fn code_bit_logp(&mut self, value: &mut bool, logp: u32) {
        *value = self.dec_bit_logp(logp);
    }
    fn code_icdf(&mut self, value: &mut usize, icdf: &[u8], ftb: u32) {
        *value = self.dec_icdf(icdf, ftb);
    }
    fn code_uint(&mut self, value: &mut u32, ft: u32) {
        *value = self.dec_uint(ft);
    }

    fn code_theta_step(&mut self, itheta: &mut i32, qn: i32) {
        let p0 = 3i32;
        let x0 = qn / 2;
        let ft = p0 * (x0 + 1) + x0;
        let fs = self.decode(ft as u32) as i32;
        let x = if fs < (x0 + 1) * p0 {
            fs / p0
        } else {
            x0 + 1 + (fs - (x0 + 1) * p0)
        };
        let (fl, fh) = theta_step_range(x, x0, p0);
        self.dec_update(fl as u32, fh as u32, ft as u32);
        *itheta = x;
    }

    fn code_theta_uniform(&mut self, itheta: &mut i32, qn: i32) {
        *itheta = self.dec_uint((qn + 1) as u32) as i32;
    }

    fn code_theta_triangular(&mut self, itheta: &mut i32, qn: i32) {
        let ft = ((qn >> 1) + 1) * ((qn >> 1) + 1);
        let fm = self.decode(ft as u32) as i32;
        let (t, fl, fs);
        if fm < (((qn >> 1) * ((qn >> 1) + 1)) >> 1) {
            t = ((isqrt32((8 * fm + 1) as u32) as i32) - 1) >> 1;
            fs = t + 1;
            fl = (t * (t + 1)) >> 1;
        } else {
            t = (2 * (qn + 1) - (isqrt32((8 * (ft - fm - 1) + 1) as u32) as i32)) >> 1;
            fs = qn + 1 - t;
            fl = ft - (((qn + 1 - t) * (qn + 2 - t)) >> 1);
        }
        self.dec_update(fl as u32, (fl + fs) as u32, ft as u32);
        *itheta = t;
    }

    fn code_band_shape(
        &mut self,
        x: &mut [f32],
        n: usize,
        k: usize,
        spread: u32,
        b: usize,
        gain: f32,
        _resynth: bool,
    ) -> u32 {
        alg_unquant(x, n, k, spread, b, self, gain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every symbol form must round-trip through the pair of impls — that is precisely the property
    /// the shared band coder relies on for encoder/decoder agreement.
    #[test]
    fn every_symbol_form_roundtrips() {
        let mut buf = vec![0u8; 4096];
        let raw_bits: Vec<u32> = (0..20).map(|i| (i * 37) % 256).collect();
        let flags: Vec<bool> = (0..20).map(|i| i % 3 == 0).collect();
        let icdf = [25u8, 23, 2, 0];
        let symbols: Vec<usize> = (0..20).map(|i| i % 3).collect();
        let uints: Vec<u32> = (0..20).map(|i| (i * 13) % 97).collect();
        {
            let mut enc = RangeEncoder::new(&mut buf);
            for i in 0..20 {
                let mut v = raw_bits[i];
                enc.code_bits(&mut v, 8);
                let mut f = flags[i];
                enc.code_bit_logp(&mut f, 2);
                let mut s = symbols[i];
                enc.code_icdf(&mut s, &icdf, 5);
                let mut u = uints[i];
                enc.code_uint(&mut u, 97);
            }
            enc.done();
            assert!(!enc.error());
        }
        let mut dec = RangeDecoder::new(&buf);
        for i in 0..20 {
            let mut v = 0u32;
            dec.code_bits(&mut v, 8);
            assert_eq!(v, raw_bits[i], "raw bits {i}");
            let mut f = false;
            dec.code_bit_logp(&mut f, 2);
            assert_eq!(f, flags[i], "bit_logp {i}");
            let mut s = 0usize;
            dec.code_icdf(&mut s, &icdf, 5);
            assert_eq!(s, symbols[i], "icdf {i}");
            let mut u = 0u32;
            dec.code_uint(&mut u, 97);
            assert_eq!(u, uints[i], "uint {i}");
        }
    }

    /// All three `theta` pdfs must round-trip for every representable angle at several `qn` — a
    /// mis-derived `[fl, fh)` on either side desynchronises the range coder on the first split band.
    #[test]
    fn every_theta_pdf_roundtrips_over_its_whole_range() {
        for qn in [2i32, 4, 6, 8, 16, 32, 64, 128, 256] {
            for pdf in 0..3 {
                let angles: Vec<i32> = (0..=qn).collect();
                let mut buf = vec![0u8; 8192];
                {
                    let mut enc = RangeEncoder::new(&mut buf);
                    for &a in &angles {
                        let mut t = a;
                        match pdf {
                            0 => enc.code_theta_step(&mut t, qn),
                            1 => enc.code_theta_uniform(&mut t, qn),
                            _ => enc.code_theta_triangular(&mut t, qn),
                        }
                    }
                    enc.done();
                    assert!(!enc.error(), "qn={qn} pdf={pdf}: encoder overflow");
                }
                let mut dec = RangeDecoder::new(&buf);
                for &a in &angles {
                    let mut t = -1;
                    match pdf {
                        0 => dec.code_theta_step(&mut t, qn),
                        1 => dec.code_theta_uniform(&mut t, qn),
                        _ => dec.code_theta_triangular(&mut t, qn),
                    }
                    assert_eq!(t, a, "qn={qn} pdf={pdf}: angle {a} did not round-trip");
                }
            }
        }
    }

    /// The step pdf must actually be a step: angles at or below `qn/2` cost less than those above.
    #[test]
    fn theta_step_pdf_is_cheaper_below_the_midpoint() {
        let qn = 64i32;
        let cost = |angle: i32| -> u32 {
            let mut buf = vec![0u8; 256];
            let mut enc = RangeEncoder::new(&mut buf);
            let mut t = angle;
            enc.code_theta_step(&mut t, qn);
            enc.tell_frac()
        };
        assert!(
            cost(0) < cost(qn),
            "step pdf not cheaper at 0 ({}) than at {qn} ({})",
            cost(0),
            cost(qn)
        );
    }

    /// The triangular pdf must be cheapest in the middle (that is the point of it).
    #[test]
    fn theta_triangular_pdf_is_cheapest_at_the_midpoint() {
        let qn = 32i32;
        let cost = |angle: i32| -> u32 {
            let mut buf = vec![0u8; 256];
            let mut enc = RangeEncoder::new(&mut buf);
            let mut t = angle;
            enc.code_theta_triangular(&mut t, qn);
            enc.tell_frac()
        };
        assert!(cost(qn / 2) < cost(0), "midpoint not cheapest vs 0");
        assert!(cost(qn / 2) < cost(qn), "midpoint not cheapest vs qn");
    }

    /// The `ENCODE` flag is what the shared band coder and allocator branch on, so pin both values.
    #[test]
    fn encode_flag_distinguishes_the_two_impls() {
        const ENC: bool = <RangeEncoder as CeltCoder>::ENCODE;
        const DEC: bool = <RangeDecoder as CeltCoder>::ENCODE;
        assert_eq!((ENC, DEC), (true, false));
    }
}
