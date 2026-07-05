//! RFC 4867 AMR / AMR-WB RTP payload framing — both **octet-aligned** (§4.4) and
//! **bandwidth-efficient** (§4.3) modes.
//!
//! [`parse_octet_aligned`](super::parse_octet_aligned) reads only the header; this module extracts
//! the *frames* (each speech/SID frame's bits) the codec decodes, and packs frames back into a
//! payload — the front-end the AMR-WB transcode needs before the ACELP DSP. Bandwidth-efficient is
//! the RFC default; octet-aligned is common in VoLTE (`a=fmtp ... octet-align=1`).
//!
//! A frame's bits are MSB-first, left-aligned in `ceil(bits/8)` bytes with the trailing bits of the
//! last byte zero — the same layout the codec's bit de-/serializer consumes.

use crate::CodecError;

use super::{Toc, AMRNB_SID_BITS, AMRNB_SPEECH_BITS, AMRWB_SID_BITS, AMRWB_SPEECH_BITS};

/// Speech bits for an AMR-WB frame type (RFC 4867 Table 1a): speech 0..=8, SID 9, speech-lost 14 /
/// no-data 15 carry no bits; 10..=13 are reserved (`None`).
#[must_use]
pub fn amrwb_frame_bits(frame_type: u8) -> Option<u16> {
    match frame_type {
        0..=8 => Some(AMRWB_SPEECH_BITS[frame_type as usize]),
        9 => Some(AMRWB_SID_BITS),
        14 | 15 => Some(0),
        _ => None,
    }
}

/// Speech bits for an AMR-NB frame type (RFC 4867 Table 1): speech 0..=7, SID 8, no-data 15 carry
/// the listed bits; 9..=14 (other-system SIDs / reserved) are not handled here (`None`).
#[must_use]
pub fn amrnb_frame_bits(frame_type: u8) -> Option<u16> {
    match frame_type {
        0..=7 => Some(AMRNB_SPEECH_BITS[frame_type as usize]),
        8 => Some(AMRNB_SID_BITS),
        15 => Some(0),
        _ => None,
    }
}

/// One speech/SID frame from a payload: its frame type, quality bit, and speech bits (MSB-first,
/// zero-padded to `ceil(bits/8)` bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmrFrame {
    /// RFC 4867 frame type (mode, SID, speech-lost, or no-data).
    pub frame_type: u8,
    /// Quality bit: the frame is not damaged.
    pub quality_ok: bool,
    /// The frame's speech bits, MSB-first in `ceil(bits/8)` bytes.
    pub data: Vec<u8>,
}

/// A decoded AMR/AMR-WB RTP payload: the Codec Mode Request plus the per-frame data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmrPayload {
    /// Codec Mode Request (4-bit), `0xF` for "no request".
    pub cmr: u8,
    /// The frames, in order (one ToC entry each).
    pub frames: Vec<AmrFrame>,
}

impl AmrPayload {
    /// Parse an AMR-WB payload (`octet_aligned` selects §4.4 vs §4.3).
    pub fn parse_amr_wb(payload: &[u8], octet_aligned: bool) -> Result<Self, CodecError> {
        Self::parse(payload, octet_aligned, amrwb_frame_bits)
    }

    /// Parse an AMR-NB payload (`octet_aligned` selects §4.4 vs §4.3).
    pub fn parse_amr_nb(payload: &[u8], octet_aligned: bool) -> Result<Self, CodecError> {
        Self::parse(payload, octet_aligned, amrnb_frame_bits)
    }

    /// Parse a payload, resolving each frame's bit count via `frame_bits`.
    pub fn parse(
        payload: &[u8],
        octet_aligned: bool,
        frame_bits: fn(u8) -> Option<u16>,
    ) -> Result<Self, CodecError> {
        if octet_aligned {
            Self::parse_octet(payload, frame_bits)
        } else {
            Self::parse_bandwidth_efficient(payload, frame_bits)
        }
    }

    fn parse_octet(payload: &[u8], frame_bits: fn(u8) -> Option<u16>) -> Result<Self, CodecError> {
        if payload.is_empty() {
            return Err(CodecError::Malformed("empty AMR payload"));
        }
        let cmr = payload[0] >> 4;
        let mut tocs = Vec::new();
        let mut index = 1;
        loop {
            let byte = *payload
                .get(index)
                .ok_or(CodecError::Malformed("truncated AMR ToC"))?;
            index += 1;
            let toc = Toc::from_octet(byte);
            let follow = toc.follow;
            tocs.push(toc);
            if !follow {
                break;
            }
        }
        let mut frames = Vec::with_capacity(tocs.len());
        for toc in tocs {
            let bits = frame_bits(toc.frame_type)
                .ok_or(CodecError::Malformed("reserved AMR frame type"))?;
            let bytes = (bits as usize).div_ceil(8);
            let data = payload
                .get(index..index + bytes)
                .ok_or(CodecError::Malformed("truncated AMR frame data"))?
                .to_vec();
            index += bytes;
            frames.push(AmrFrame {
                frame_type: toc.frame_type,
                quality_ok: toc.quality_ok,
                data,
            });
        }
        Ok(Self { cmr, frames })
    }

    fn parse_bandwidth_efficient(
        payload: &[u8],
        frame_bits: fn(u8) -> Option<u16>,
    ) -> Result<Self, CodecError> {
        let mut reader = BitReader::new(payload);
        let cmr = reader
            .read(4)
            .ok_or(CodecError::Malformed("truncated AMR CMR"))? as u8;
        let mut tocs = Vec::new();
        loop {
            let follow = reader
                .read(1)
                .ok_or(CodecError::Malformed("truncated AMR ToC"))?
                != 0;
            let frame_type = reader
                .read(4)
                .ok_or(CodecError::Malformed("truncated AMR ToC"))?
                as u8;
            let quality_ok = reader
                .read(1)
                .ok_or(CodecError::Malformed("truncated AMR ToC"))?
                != 0;
            tocs.push(Toc {
                follow,
                frame_type,
                quality_ok,
            });
            if !follow {
                break;
            }
        }
        let mut frames = Vec::with_capacity(tocs.len());
        for toc in tocs {
            let bits = frame_bits(toc.frame_type)
                .ok_or(CodecError::Malformed("reserved AMR frame type"))?;
            let data = reader
                .read_to_bytes(bits as usize)
                .ok_or(CodecError::Malformed("truncated AMR frame data"))?;
            frames.push(AmrFrame {
                frame_type: toc.frame_type,
                quality_ok: toc.quality_ok,
                data,
            });
        }
        Ok(Self { cmr, frames })
    }

    /// Serialize into an AMR-WB payload (`octet_aligned` selects §4.4 vs §4.3).
    pub fn serialize_amr_wb(&self, octet_aligned: bool) -> Result<Vec<u8>, CodecError> {
        self.serialize(octet_aligned, amrwb_frame_bits)
    }

    /// Serialize into an AMR-NB payload (`octet_aligned` selects §4.4 vs §4.3).
    pub fn serialize_amr_nb(&self, octet_aligned: bool) -> Result<Vec<u8>, CodecError> {
        self.serialize(octet_aligned, amrnb_frame_bits)
    }

    /// Serialize, resolving each frame's bit count via `frame_bits`.
    pub fn serialize(
        &self,
        octet_aligned: bool,
        frame_bits: fn(u8) -> Option<u16>,
    ) -> Result<Vec<u8>, CodecError> {
        if octet_aligned {
            let mut out = vec![(self.cmr & 0x0F) << 4];
            for (index, frame) in self.frames.iter().enumerate() {
                out.push(
                    Toc {
                        follow: index + 1 < self.frames.len(),
                        frame_type: frame.frame_type,
                        quality_ok: frame.quality_ok,
                    }
                    .to_octet(),
                );
            }
            for frame in &self.frames {
                let bytes = self.frame_data_len(frame, frame_bits)?;
                out.extend_from_slice(&frame.data[..bytes]);
            }
            Ok(out)
        } else {
            let mut writer = BitWriter::new();
            writer.write(u32::from(self.cmr & 0x0F), 4);
            for (index, frame) in self.frames.iter().enumerate() {
                writer.write(u32::from(index + 1 < self.frames.len()), 1);
                writer.write(u32::from(frame.frame_type & 0x0F), 4);
                writer.write(u32::from(frame.quality_ok), 1);
            }
            for frame in &self.frames {
                let bits = frame_bits(frame.frame_type)
                    .ok_or(CodecError::Malformed("reserved AMR frame type"))?
                    as usize;
                self.frame_data_len(frame, frame_bits)?; // length check
                writer.write_bits_from_bytes(&frame.data, bits);
            }
            Ok(writer.finish())
        }
    }

    /// The whole-byte length a frame's `data` must have, erroring if it is shorter.
    fn frame_data_len(
        &self,
        frame: &AmrFrame,
        frame_bits: fn(u8) -> Option<u16>,
    ) -> Result<usize, CodecError> {
        let bits =
            frame_bits(frame.frame_type).ok_or(CodecError::Malformed("reserved AMR frame type"))?;
        let bytes = (bits as usize).div_ceil(8);
        if frame.data.len() < bytes {
            return Err(CodecError::Malformed(
                "AMR frame data shorter than its mode",
            ));
        }
        Ok(bytes)
    }
}

/// MSB-first bit reader over a byte slice.
struct BitReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Read `count` (≤ 32) bits MSB-first into the low bits of a `u32`, or `None` if insufficient.
    fn read(&mut self, count: usize) -> Option<u32> {
        if self.position + count > self.bytes.len() * 8 {
            return None;
        }
        let mut value = 0u32;
        for _ in 0..count {
            let byte = self.bytes[self.position / 8];
            let bit = (byte >> (7 - self.position % 8)) & 1;
            value = (value << 1) | u32::from(bit);
            self.position += 1;
        }
        Some(value)
    }

    /// Read `count` bits into a left-aligned, zero-padded byte buffer (`ceil(count/8)` bytes).
    fn read_to_bytes(&mut self, count: usize) -> Option<Vec<u8>> {
        if self.position + count > self.bytes.len() * 8 {
            return None;
        }
        let mut out = vec![0u8; count.div_ceil(8)];
        for index in 0..count {
            let byte = self.bytes[self.position / 8];
            let bit = (byte >> (7 - self.position % 8)) & 1;
            if bit != 0 {
                out[index / 8] |= 1 << (7 - index % 8);
            }
            self.position += 1;
        }
        Some(out)
    }
}

/// MSB-first bit writer, padding the final byte with zero bits.
struct BitWriter {
    bytes: Vec<u8>,
    position: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            position: 0,
        }
    }

    fn write_bit(&mut self, bit: u8) {
        if self.position.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if bit != 0 {
            let index = self.position / 8;
            self.bytes[index] |= 1 << (7 - self.position % 8);
        }
        self.position += 1;
    }

    fn write(&mut self, value: u32, count: usize) {
        for shift in (0..count).rev() {
            self.write_bit(((value >> shift) & 1) as u8);
        }
    }

    /// Write the first `count` bits of `data` (MSB-first).
    fn write_bits_from_bytes(&mut self, data: &[u8], count: usize) {
        for index in 0..count {
            let bit = (data[index / 8] >> (7 - index % 8)) & 1;
            self.write_bit(bit);
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amr::AmrWbMode;

    fn frame(frame_type: u8, fill: u8) -> AmrFrame {
        let bits = amrwb_frame_bits(frame_type).expect("bits") as usize;
        let mut data = vec![fill; bits.div_ceil(8)];
        // Zero the trailing pad bits of the last byte — bandwidth-efficient preserves only the valid
        // `bits`, so a round-trip drops them; keep the fixture exactly representable.
        let valid_in_last = bits % 8;
        if valid_in_last != 0 {
            let last = data.len() - 1;
            data[last] &= 0xFFu8 << (8 - valid_in_last);
        }
        AmrFrame {
            frame_type,
            quality_ok: true,
            data,
        }
    }

    #[test]
    fn octet_aligned_round_trip_single_frame() {
        let payload = AmrPayload {
            cmr: 0xF,
            frames: vec![frame(AmrWbMode::Mr1265.frame_type(), 0xAB)],
        };
        let bytes = payload.serialize_amr_wb(true).expect("serialize");
        // CMR byte + 1 ToC byte + 253-bit frame (32 bytes).
        assert_eq!(bytes.len(), 1 + 1 + 32);
        let parsed = AmrPayload::parse_amr_wb(&bytes, true).expect("parse");
        assert_eq!(parsed, payload);
    }

    #[test]
    fn bandwidth_efficient_round_trip_single_frame() {
        // Mode 0 (6.60 kbit/s, 132 bits). The last data byte's low bits must be zero so the
        // left-aligned round-trip is exact (132 bits = 16 bytes + 4 bits).
        let mut data = vec![0x5Au8; 17];
        let last = data.len() - 1;
        data[last] &= 0xF0; // keep only the 4 valid bits of the 132nd-bit byte
        let payload = AmrPayload {
            cmr: 0x3,
            frames: vec![AmrFrame {
                frame_type: 0,
                quality_ok: true,
                data,
            }],
        };
        let bytes = payload.serialize_amr_wb(false).expect("serialize");
        // 4 (CMR) + 6 (ToC) + 132 (frame) = 142 bits → 18 bytes.
        assert_eq!(bytes.len(), 18);
        let parsed = AmrPayload::parse_amr_wb(&bytes, false).expect("parse");
        assert_eq!(parsed, payload);
    }

    #[test]
    fn multi_frame_round_trip_both_modes() {
        let payload = AmrPayload {
            cmr: 0x2,
            frames: vec![
                frame(AmrWbMode::Mr885.frame_type(), 0x11),
                frame(AmrWbMode::Mr885.frame_type(), 0x22),
            ],
        };
        for octet_aligned in [true, false] {
            let bytes = payload.serialize_amr_wb(octet_aligned).expect("serialize");
            let parsed = AmrPayload::parse_amr_wb(&bytes, octet_aligned).expect("parse");
            assert_eq!(parsed, payload, "octet_aligned={octet_aligned}");
        }
    }

    #[test]
    fn cmr_and_follow_bits_survive_round_trip() {
        let payload = AmrPayload {
            cmr: 0x5,
            frames: vec![
                frame(AmrWbMode::Mr660.frame_type(), 0x01),
                frame(AmrWbMode::Mr2385.frame_type(), 0x02),
            ],
        };
        let bytes = payload.serialize_amr_wb(false).expect("serialize");
        let parsed = AmrPayload::parse_amr_wb(&bytes, false).expect("parse");
        assert_eq!(parsed.cmr, 0x5);
        assert_eq!(parsed.frames.len(), 2);
        assert_eq!(parsed.frames[0].frame_type, 0);
        assert_eq!(parsed.frames[1].frame_type, 8);
    }

    #[test]
    fn rejects_truncated_and_reserved() {
        // Truncated bandwidth-efficient: CMR+ToC promise a frame, but no frame bits follow.
        assert!(matches!(
            AmrPayload::parse_amr_wb(&[0x00, 0x00], false),
            Err(CodecError::Malformed(_))
        ));
        // Octet-aligned reserved frame type (10), follow=0 → rejected at frame extraction.
        // ToC byte F=0 FT=1010(10) Q=1 pad=00 → 0x54.
        assert!(matches!(
            AmrPayload::parse_amr_wb(&[0xF0, 0x54], true),
            Err(CodecError::Malformed("reserved AMR frame type"))
        ));
        assert!(matches!(
            AmrPayload::parse_amr_wb(&[], true),
            Err(CodecError::Malformed("empty AMR payload"))
        ));
    }

    #[test]
    fn no_data_frame_carries_no_bits() {
        // Frame type 15 (no data): a valid ToC with zero frame bits.
        let payload = AmrPayload {
            cmr: 0xF,
            frames: vec![AmrFrame {
                frame_type: 15,
                quality_ok: true,
                data: Vec::new(),
            }],
        };
        for octet_aligned in [true, false] {
            let bytes = payload.serialize_amr_wb(octet_aligned).expect("serialize");
            let parsed = AmrPayload::parse_amr_wb(&bytes, octet_aligned).expect("parse");
            assert_eq!(parsed, payload);
        }
    }

    use proptest::prelude::*;

    proptest! {
        /// Arbitrary bytes off the network must decode-or-error, never panic (CLAUDE.md fuzz rule).
        #[test]
        fn parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = AmrPayload::parse_amr_wb(&bytes, true);
            let _ = AmrPayload::parse_amr_wb(&bytes, false);
            let _ = AmrPayload::parse_amr_nb(&bytes, true);
            let _ = AmrPayload::parse_amr_nb(&bytes, false);
        }
    }
}
