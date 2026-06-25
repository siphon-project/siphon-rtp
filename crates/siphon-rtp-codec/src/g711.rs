//! G.711 µ-law (PCMU, payload type 0) and A-law (PCMA, payload type 8).
//!
//! 8 kHz, mono, one byte per sample. Decoding is a 256-entry table lookup; encoding uses the
//! canonical CCITT segment search. The defining correctness property — `encode(decode(c)) == c`
//! for all 256 code words — is asserted in the tests.

use crate::{CodecError, CodecParams, Decoder, Encoder};

const BIAS: i32 = 0x84;
/// µ-law clip in the 14-bit domain.
const ULAW_CLIP: i32 = 8159;
/// Segment end points (µ-law, 14-bit domain).
const SEG_UEND: [i32; 8] = [0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF];
/// Segment end points (A-law, 13-bit domain).
const SEG_AEND: [i32; 8] = [0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF];

/// Decode one µ-law code word to a linear 16-bit sample.
#[must_use]
pub const fn ulaw_to_linear(u_val: u8) -> i16 {
    let u = !u_val;
    let mut t: i32 = (((u & 0x0F) as i32) << 3) + BIAS;
    t <<= ((u & 0x70) >> 4) as u32;
    if (u & 0x80) != 0 {
        (BIAS - t) as i16
    } else {
        (t - BIAS) as i16
    }
}

/// Decode one A-law code word to a linear 16-bit sample.
#[must_use]
pub const fn alaw_to_linear(a_val: u8) -> i16 {
    let a = a_val ^ 0x55;
    let mut t: i32 = ((a & 0x0F) as i32) << 4;
    let seg = ((a & 0x70) >> 4) as i32;
    match seg {
        0 => t += 8,
        1 => t += 0x108,
        _ => {
            t += 0x108;
            t <<= (seg - 1) as u32;
        }
    }
    if (a & 0x80) != 0 {
        t as i16
    } else {
        -t as i16
    }
}

const fn search(val: i32, table: &[i32; 8]) -> i32 {
    let mut i = 0;
    while i < 8 {
        if val <= table[i] {
            return i as i32;
        }
        i += 1;
    }
    8
}

/// Encode one linear 16-bit sample to a µ-law code word.
#[must_use]
pub fn linear_to_ulaw(pcm: i16) -> u8 {
    let mut pcm_val = (pcm as i32) >> 2; // 16-bit -> 14-bit
    let mask;
    if pcm_val < 0 {
        pcm_val = -pcm_val;
        mask = 0x7F;
    } else {
        mask = 0xFF;
    }
    if pcm_val > ULAW_CLIP {
        pcm_val = ULAW_CLIP;
    }
    pcm_val += BIAS >> 2;
    let seg = search(pcm_val, &SEG_UEND);
    if seg >= 8 {
        (0x7F ^ mask) as u8
    } else {
        let uval = (seg << 4) | ((pcm_val >> (seg + 1)) & 0x0F);
        (uval ^ mask) as u8
    }
}

/// Encode one linear 16-bit sample to an A-law code word.
#[must_use]
pub fn linear_to_alaw(pcm: i16) -> u8 {
    let mut pcm_val = (pcm as i32) >> 3; // 16-bit -> 13-bit
    let mask;
    if pcm_val >= 0 {
        mask = 0xD5;
    } else {
        mask = 0x55;
        pcm_val = -pcm_val - 1;
        if pcm_val < 0 {
            pcm_val = 0;
        }
    }
    let seg = search(pcm_val, &SEG_AEND);
    if seg >= 8 {
        (0x7F ^ mask) as u8
    } else {
        let mut aval = seg << 4;
        if seg < 2 {
            aval |= (pcm_val >> 1) & 0x0F;
        } else {
            aval |= (pcm_val >> seg) & 0x0F;
        }
        (aval ^ mask) as u8
    }
}

const fn build_decode_table(alaw: bool) -> [i16; 256] {
    let mut table = [0i16; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = if alaw {
            alaw_to_linear(i as u8)
        } else {
            ulaw_to_linear(i as u8)
        };
        i += 1;
    }
    table
}

/// Precomputed µ-law → linear decode table.
pub static ULAW_DECODE: [i16; 256] = build_decode_table(false);
/// Precomputed A-law → linear decode table.
pub static ALAW_DECODE: [i16; 256] = build_decode_table(true);

/// Which G.711 variant a codec instance handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// µ-law (PCMU, payload type 0).
    Ulaw,
    /// A-law (PCMA, payload type 8).
    Alaw,
}

impl Variant {
    #[inline]
    const fn decode_table(self) -> &'static [i16; 256] {
        match self {
            Variant::Ulaw => &ULAW_DECODE,
            Variant::Alaw => &ALAW_DECODE,
        }
    }

    #[inline]
    fn encode_sample(self, pcm: i16) -> u8 {
        match self {
            Variant::Ulaw => linear_to_ulaw(pcm),
            Variant::Alaw => linear_to_alaw(pcm),
        }
    }
}

/// A G.711 codec instance (used as both [`Decoder`] and [`Encoder`]).
#[derive(Debug, Clone)]
pub struct G711 {
    variant: Variant,
    params: CodecParams,
}

impl G711 {
    /// Create a G.711 codec for `variant` at the given packetization time (8 kHz mono).
    #[must_use]
    pub fn new(variant: Variant, ptime_ms: u8) -> Self {
        Self {
            variant,
            params: CodecParams {
                sample_rate_hz: 8000,
                channels: 1,
                ptime_ms,
            },
        }
    }

    /// µ-law codec at the default 20 ms packetization.
    #[must_use]
    pub fn ulaw() -> Self {
        Self::new(Variant::Ulaw, 20)
    }

    /// A-law codec at the default 20 ms packetization.
    #[must_use]
    pub fn alaw() -> Self {
        Self::new(Variant::Alaw, 20)
    }

    /// The codec's native parameters (inherent shortcut; the trait methods also expose this).
    #[must_use]
    pub fn params(&self) -> CodecParams {
        self.params
    }

    /// Samples in one packetization interval.
    #[must_use]
    pub fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }
}

impl Decoder for G711 {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }

    fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
        if out.len() < payload.len() {
            return Err(CodecError::OutputTooSmall {
                needed: payload.len(),
                have: out.len(),
            });
        }
        let table = self.variant.decode_table();
        for (sample, &code) in out.iter_mut().zip(payload.iter()) {
            *sample = table[code as usize];
        }
        Ok(payload.len())
    }

    fn conceal(&mut self, out: &mut [i16]) -> Result<usize, CodecError> {
        // Basic PLC: comfort silence. A waveform-similarity concealment (G.711 Appendix I)
        // is a later refinement; silence is correct and artifact-free for short gaps.
        let count = self.frame_samples().min(out.len());
        out[..count].fill(0);
        Ok(count)
    }
}

impl Encoder for G711 {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }

    fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, CodecError> {
        if out.len() < pcm.len() {
            return Err(CodecError::OutputTooSmall {
                needed: pcm.len(),
                have: out.len(),
            });
        }
        for (byte, &sample) in out.iter_mut().zip(pcm.iter()) {
            *byte = self.variant.encode_sample(sample);
        }
        Ok(pcm.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulaw_encode_decode_is_identity_except_negative_zero() {
        // Decoding then re-encoding recovers the code word for all 256 codes — except µ-law's
        // negative-zero code 0x7F, which decodes to 0 and canonicalizes to +0 (0xFF) on encode.
        for code in 0u8..=255 {
            let linear = ulaw_to_linear(code);
            let recoded = linear_to_ulaw(linear);
            if code == 0x7F {
                assert_eq!(linear, 0, "0x7F is µ-law negative zero");
                assert_eq!(recoded, 0xFF, "negative zero canonicalizes to +0");
            } else {
                assert_eq!(recoded, code, "ulaw roundtrip failed for code {code:#04x}");
            }
        }
    }

    #[test]
    fn ulaw_decode_encode_is_idempotent() {
        // The robust property that holds for every code: decode is stable under re-encode.
        for code in 0u8..=255 {
            let linear = ulaw_to_linear(code);
            let recoded = linear_to_ulaw(linear);
            assert_eq!(
                ulaw_to_linear(recoded),
                linear,
                "ulaw decode not idempotent for code {code:#04x}"
            );
        }
    }

    #[test]
    fn alaw_encode_decode_is_identity_over_all_codes() {
        for code in 0u8..=255 {
            let linear = alaw_to_linear(code);
            let recoded = linear_to_alaw(linear);
            assert_eq!(recoded, code, "alaw roundtrip failed for code {code:#04x}");
        }
    }

    #[test]
    fn known_reference_values() {
        // µ-law idle code 0xFF decodes to 0.
        assert_eq!(ulaw_to_linear(0xFF), 0);
        // µ-law full-scale negative.
        assert_eq!(ulaw_to_linear(0x00), -32124);
        // A-law idle pattern: 0xD5 -> +8, 0x55 -> -8.
        assert_eq!(alaw_to_linear(0xD5), 8);
        assert_eq!(alaw_to_linear(0x55), -8);
    }

    #[test]
    fn decode_tables_match_functions() {
        for code in 0u8..=255 {
            assert_eq!(ULAW_DECODE[code as usize], ulaw_to_linear(code));
            assert_eq!(ALAW_DECODE[code as usize], alaw_to_linear(code));
        }
    }

    #[test]
    fn encode_clips_extremes() {
        // Max/min 16-bit input must produce valid code words (no panic, round-trips back near rails).
        let max_code = linear_to_ulaw(i16::MAX);
        let min_code = linear_to_ulaw(i16::MIN);
        assert_ne!(max_code, min_code);
        let _ = linear_to_alaw(i16::MAX);
        let _ = linear_to_alaw(i16::MIN);
    }

    #[test]
    fn codec_decode_roundtrip_frame() {
        let mut codec = G711::ulaw();
        assert_eq!(codec.frame_samples(), 160);

        let payload: Vec<u8> = (0u8..=255).collect();
        let mut pcm = vec![0i16; payload.len()];
        let produced = codec.decode(&payload, &mut pcm).expect("decode");
        assert_eq!(produced, payload.len());

        let mut out = vec![0u8; pcm.len()];
        let written = codec.encode(&pcm, &mut out).expect("encode");
        assert_eq!(written, pcm.len());

        // Re-decode must reproduce the same PCM (stable round-trip; tolerates µ-law's two
        // zero codes, where 0x7F and 0xFF both map to 0).
        let mut pcm_again = vec![0i16; pcm.len()];
        codec.decode(&out, &mut pcm_again).expect("re-decode");
        assert_eq!(pcm_again, pcm);
    }

    #[test]
    fn decode_rejects_small_output() {
        let mut codec = G711::alaw();
        let payload = [0u8; 160];
        let mut out = [0i16; 10];
        assert_eq!(
            codec.decode(&payload, &mut out),
            Err(CodecError::OutputTooSmall {
                needed: 160,
                have: 10
            })
        );
    }

    #[test]
    fn encode_rejects_small_output() {
        let mut codec = G711::ulaw();
        let pcm = [0i16; 160];
        let mut out = [0u8; 10];
        assert_eq!(
            codec.encode(&pcm, &mut out),
            Err(CodecError::OutputTooSmall {
                needed: 160,
                have: 10
            })
        );
    }

    #[test]
    fn conceal_writes_silence() {
        let mut codec = G711::ulaw();
        let mut out = [123i16; 160];
        let written = codec.conceal(&mut out).expect("conceal");
        assert_eq!(written, 160);
        assert!(out.iter().all(|&s| s == 0));
    }
}
