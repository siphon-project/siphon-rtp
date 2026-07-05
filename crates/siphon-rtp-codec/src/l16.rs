//! L16 — linear 16-bit PCM, big-endian (RTP network byte order), mono.
//!
//! This is the "codec" used to carry raw PCM (e.g. to/from the WebSocket AI bridge). Decode
//! converts big-endian payload bytes to native `i16`; encode does the reverse. No compression.

use crate::{CodecError, CodecParams, Decoder, Encoder};

/// Linear 16-bit PCM (network byte order) codec.
#[derive(Debug, Clone)]
pub struct L16 {
    params: CodecParams,
}

impl L16 {
    /// Create an L16 codec at the given sample rate and packetization time (mono).
    #[must_use]
    pub fn new(sample_rate_hz: u32, ptime_ms: u8) -> Self {
        Self {
            params: CodecParams {
                sample_rate_hz,
                channels: 1,
                ptime_ms,
            },
        }
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

impl Decoder for L16 {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }

    fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
        if !payload.len().is_multiple_of(2) {
            return Err(CodecError::Malformed("L16 payload length must be even"));
        }
        let samples = payload.len() / 2;
        if out.len() < samples {
            return Err(CodecError::OutputTooSmall {
                needed: samples,
                have: out.len(),
            });
        }
        for (sample, chunk) in out.iter_mut().zip(payload.chunks_exact(2)) {
            *sample = i16::from_be_bytes([chunk[0], chunk[1]]);
        }
        Ok(samples)
    }

    fn conceal(&mut self, out: &mut [i16]) -> Result<usize, CodecError> {
        let count = self.frame_samples().min(out.len());
        out[..count].fill(0);
        Ok(count)
    }
}

impl Encoder for L16 {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }

    fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, CodecError> {
        let needed = pcm.len() * 2;
        if out.len() < needed {
            return Err(CodecError::OutputTooSmall {
                needed,
                have: out.len(),
            });
        }
        for (sample, chunk) in pcm.iter().zip(out.chunks_exact_mut(2)) {
            let bytes = sample.to_be_bytes();
            chunk[0] = bytes[0];
            chunk[1] = bytes[1];
        }
        Ok(needed)
    }

    fn is_stateless(&self) -> bool {
        true // raw big-endian PCM samples — no inter-frame state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_preserves_samples() {
        let mut codec = L16::new(16000, 20);
        assert_eq!(codec.frame_samples(), 320);

        let pcm: Vec<i16> = (-160..160).collect();
        let mut bytes = vec![0u8; pcm.len() * 2];
        let written = codec.encode(&pcm, &mut bytes).expect("encode");
        assert_eq!(written, pcm.len() * 2);

        let mut decoded = vec![0i16; pcm.len()];
        let produced = codec.decode(&bytes, &mut decoded).expect("decode");
        assert_eq!(produced, pcm.len());
        assert_eq!(decoded, pcm);
    }

    #[test]
    fn big_endian_byte_order() {
        let mut codec = L16::new(8000, 20);
        let pcm = [0x1234i16];
        let mut bytes = [0u8; 2];
        codec.encode(&pcm, &mut bytes).expect("encode");
        assert_eq!(bytes, [0x12, 0x34]);
    }

    #[test]
    fn decode_rejects_odd_length() {
        let mut codec = L16::new(8000, 20);
        let mut out = [0i16; 4];
        assert_eq!(
            codec.decode(&[0u8; 3], &mut out),
            Err(CodecError::Malformed("L16 payload length must be even"))
        );
    }
}
