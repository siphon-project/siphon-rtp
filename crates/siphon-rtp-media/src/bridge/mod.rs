//! Stream bridges: moving leg PCM to/from external transports (WebSocket voice-AI today).
//!
//! [`protocol`] is the raw-WS-PCM control protocol (text frames). This module also holds the
//! binary-audio framing helpers: the M1 wire order is **little-endian L16**, while RTP L16
//! payloads are big-endian — conversions live here so the byte-swap happens in exactly one place
//! (see the spec gotchas). Conversions write into caller-owned buffers (no per-frame heap alloc).

pub mod protocol;
pub mod session;

pub use protocol::{
    ControlMessage, Direction, Encoding, Endianness, MediaFormat, PlaySource, StartData,
};
pub use session::{BridgeSession, TickResult};

/// Encode i16 PCM samples to little-endian L16 bytes (the M1 binary-frame wire order).
///
/// Returns the number of bytes written. `out` must hold at least `2 * pcm.len()` bytes; excess
/// samples are skipped if it is shorter.
pub fn pcm_to_l16_le(pcm: &[i16], out: &mut [u8]) -> usize {
    let count = pcm.len().min(out.len() / 2);
    for (sample, chunk) in pcm.iter().zip(out.chunks_exact_mut(2)).take(count) {
        chunk.copy_from_slice(&sample.to_le_bytes());
    }
    count * 2
}

/// Decode little-endian L16 bytes to i16 PCM samples. Returns the number of samples written.
/// A trailing odd byte is ignored.
pub fn l16_le_to_pcm(bytes: &[u8], out: &mut [i16]) -> usize {
    let count = (bytes.len() / 2).min(out.len());
    for (chunk, sample) in bytes.chunks_exact(2).zip(out.iter_mut()).take(count) {
        *sample = i16::from_le_bytes([chunk[0], chunk[1]]);
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l16_little_endian_roundtrip() {
        let pcm = [0x1234i16, -2, 32767, -32768, 0];
        let mut bytes = [0u8; 10];
        let written = pcm_to_l16_le(&pcm, &mut bytes);
        assert_eq!(written, 10);
        // 0x1234 little-endian = [0x34, 0x12].
        assert_eq!(&bytes[0..2], &[0x34, 0x12]);

        let mut back = [0i16; 5];
        let samples = l16_le_to_pcm(&bytes, &mut back);
        assert_eq!(samples, 5);
        assert_eq!(back, pcm);
    }

    #[test]
    fn conversions_respect_buffer_bounds() {
        let pcm = [1i16, 2, 3, 4];
        let mut small = [0u8; 4]; // room for 2 samples
        assert_eq!(pcm_to_l16_le(&pcm, &mut small), 4);

        let bytes = [1u8, 0, 2, 0, 3]; // trailing odd byte
        let mut out = [0i16; 4];
        assert_eq!(l16_le_to_pcm(&bytes, &mut out), 2);
        assert_eq!(&out[..2], &[1, 2]);
    }
}
