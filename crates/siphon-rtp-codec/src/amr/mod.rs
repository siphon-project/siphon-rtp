//! AMR-NB (3GPP TS 26.071, RTP RFC 4867) and AMR-WB (TS 26.171) — the VoLTE codecs.
//!
//! This module currently provides the **foundation**: the fixed-point [`basic_ops`], the mode
//! tables (bit/byte sizes, frame-type mapping), and RFC 4867 payload framing. The ACELP
//! encode/decode DSP is the multi-week bit-exact effort tracked separately; until it lands the
//! [`AmrNb`]/[`AmrWb`] codecs return [`CodecError::Unsupported`] rather than panicking.

pub mod basic_ops;
pub mod math_op;
pub mod payload;

use crate::{CodecError, CodecParams, Decoder, Encoder};

/// AMR-NB speech frame sizes in bits, indexed by frame type (0..=7). RFC 4867 Table 1.
pub const AMRNB_SPEECH_BITS: [u16; 8] = [95, 103, 118, 134, 148, 159, 204, 244];
/// AMR-NB SID (comfort-noise) frame size in bits (frame type 8).
pub const AMRNB_SID_BITS: u16 = 39;

/// AMR-WB speech frame sizes in bits, indexed by frame type (0..=8). RFC 4867 Table 1a.
pub const AMRWB_SPEECH_BITS: [u16; 9] = [132, 177, 253, 285, 317, 365, 397, 461, 477];
/// AMR-WB SID (comfort-noise) frame size in bits (frame type 9).
pub const AMRWB_SID_BITS: u16 = 40;

#[inline]
const fn bits_to_bytes(bits: u16) -> usize {
    (bits as usize).div_ceil(8)
}

/// AMR-NB bitrate modes. The discriminant is the RFC 4867 frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AmrNbMode {
    /// 4.75 kbit/s
    Mr475 = 0,
    /// 5.15 kbit/s
    Mr515 = 1,
    /// 5.90 kbit/s
    Mr590 = 2,
    /// 6.70 kbit/s
    Mr670 = 3,
    /// 7.40 kbit/s
    Mr740 = 4,
    /// 7.95 kbit/s
    Mr795 = 5,
    /// 10.2 kbit/s
    Mr1020 = 6,
    /// 12.2 kbit/s (GSM-EFR)
    Mr1220 = 7,
}

impl AmrNbMode {
    /// The RFC 4867 frame type (0..=7).
    #[must_use]
    pub const fn frame_type(self) -> u8 {
        self as u8
    }

    /// Speech frame size in bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        AMRNB_SPEECH_BITS[self as usize]
    }

    /// Speech frame size in bytes (octet-aligned).
    #[must_use]
    pub const fn bytes(self) -> usize {
        bits_to_bytes(self.bits())
    }

    /// Map an RFC 4867 frame type to a speech mode (None for SID/reserved/no-data).
    #[must_use]
    pub const fn from_frame_type(frame_type: u8) -> Option<Self> {
        match frame_type {
            0 => Some(Self::Mr475),
            1 => Some(Self::Mr515),
            2 => Some(Self::Mr590),
            3 => Some(Self::Mr670),
            4 => Some(Self::Mr740),
            5 => Some(Self::Mr795),
            6 => Some(Self::Mr1020),
            7 => Some(Self::Mr1220),
            _ => None,
        }
    }
}

/// AMR-WB bitrate modes. The discriminant is the RFC 4867 frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AmrWbMode {
    /// 6.60 kbit/s
    Mr660 = 0,
    /// 8.85 kbit/s
    Mr885 = 1,
    /// 12.65 kbit/s
    Mr1265 = 2,
    /// 14.25 kbit/s
    Mr1425 = 3,
    /// 15.85 kbit/s
    Mr1585 = 4,
    /// 18.25 kbit/s
    Mr1825 = 5,
    /// 19.85 kbit/s
    Mr1985 = 6,
    /// 23.05 kbit/s
    Mr2305 = 7,
    /// 23.85 kbit/s
    Mr2385 = 8,
}

impl AmrWbMode {
    /// The RFC 4867 frame type (0..=8).
    #[must_use]
    pub const fn frame_type(self) -> u8 {
        self as u8
    }

    /// Speech frame size in bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        AMRWB_SPEECH_BITS[self as usize]
    }

    /// Speech frame size in bytes (octet-aligned).
    #[must_use]
    pub const fn bytes(self) -> usize {
        bits_to_bytes(self.bits())
    }

    /// Map an RFC 4867 frame type to a speech mode (None for SID/reserved/no-data).
    #[must_use]
    pub const fn from_frame_type(frame_type: u8) -> Option<Self> {
        match frame_type {
            0 => Some(Self::Mr660),
            1 => Some(Self::Mr885),
            2 => Some(Self::Mr1265),
            3 => Some(Self::Mr1425),
            4 => Some(Self::Mr1585),
            5 => Some(Self::Mr1825),
            6 => Some(Self::Mr1985),
            7 => Some(Self::Mr2305),
            8 => Some(Self::Mr2385),
            _ => None,
        }
    }
}

/// One RFC 4867 Table-of-Contents entry (octet-aligned form).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Toc {
    /// Follow bit: another ToC entry follows this one.
    pub follow: bool,
    /// Frame type index (mode, SID, or no-data marker).
    pub frame_type: u8,
    /// Quality bit: frame is not damaged.
    pub quality_ok: bool,
}

impl Toc {
    /// Parse a ToC byte (octet-aligned): `F(1) | FT(4) | Q(1) | padding(2)`.
    #[must_use]
    pub const fn from_octet(byte: u8) -> Self {
        Self {
            follow: byte & 0x80 != 0,
            frame_type: (byte >> 3) & 0x0F,
            quality_ok: byte & 0x04 != 0,
        }
    }

    /// Serialize to a ToC byte (octet-aligned).
    #[must_use]
    pub const fn to_octet(self) -> u8 {
        ((self.follow as u8) << 7)
            | ((self.frame_type & 0x0F) << 3)
            | ((self.quality_ok as u8) << 2)
    }
}

/// A parsed RFC 4867 octet-aligned payload header: requested mode + ToC list + frame-data offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OctetAlignedHeader {
    /// Codec Mode Request (top nibble of the first byte).
    pub cmr: u8,
    /// Table-of-contents entries, one per speech frame in the payload.
    pub entries: Vec<Toc>,
    /// Byte offset at which speech-frame data begins.
    pub data_offset: usize,
}

/// Parse the header of an octet-aligned AMR (RFC 4867 §4.4.2) RTP payload.
///
/// Returns the CMR, the ToC list, and the offset to the first frame's data. The
/// bandwidth-efficient mode (bit-packed) is a separate parser, not yet implemented.
pub fn parse_octet_aligned(payload: &[u8]) -> Result<OctetAlignedHeader, CodecError> {
    if payload.is_empty() {
        return Err(CodecError::Malformed("empty AMR payload"));
    }
    let cmr = payload[0] >> 4;
    let mut entries = Vec::new();
    let mut index = 1;
    loop {
        let byte = *payload
            .get(index)
            .ok_or(CodecError::Malformed("truncated AMR ToC"))?;
        index += 1;
        let toc = Toc::from_octet(byte);
        let follow = toc.follow;
        entries.push(toc);
        if !follow {
            break;
        }
    }
    Ok(OctetAlignedHeader {
        cmr,
        entries,
        data_offset: index,
    })
}

/// AMR-NB codec (8 kHz, mono, 20 ms = 160 samples). DSP is WIP — see module docs.
#[derive(Debug, Clone)]
pub struct AmrNb {
    params: CodecParams,
}

impl Default for AmrNb {
    fn default() -> Self {
        Self::new()
    }
}

impl AmrNb {
    /// Create an AMR-NB codec at the canonical 8 kHz / 20 ms configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            params: CodecParams {
                sample_rate_hz: 8000,
                channels: 1,
                ptime_ms: 20,
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

impl Decoder for AmrNb {
    fn params(&self) -> CodecParams {
        self.params
    }
    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }
    fn decode(&mut self, _payload: &[u8], _out: &mut [i16]) -> Result<usize, CodecError> {
        Err(CodecError::Unsupported(
            "AMR-NB decode DSP not yet implemented",
        ))
    }
    fn conceal(&mut self, _out: &mut [i16]) -> Result<usize, CodecError> {
        Err(CodecError::Unsupported("AMR-NB PLC not yet implemented"))
    }
}

impl Encoder for AmrNb {
    fn params(&self) -> CodecParams {
        self.params
    }
    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }
    fn encode(&mut self, _pcm: &[i16], _out: &mut [u8]) -> Result<usize, CodecError> {
        Err(CodecError::Unsupported(
            "AMR-NB encode DSP not yet implemented",
        ))
    }
}

/// AMR-WB codec (16 kHz, mono, 20 ms = 320 samples). DSP is WIP — see module docs.
#[derive(Debug, Clone)]
pub struct AmrWb {
    params: CodecParams,
}

impl Default for AmrWb {
    fn default() -> Self {
        Self::new()
    }
}

impl AmrWb {
    /// Create an AMR-WB codec at the canonical 16 kHz / 20 ms configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            params: CodecParams {
                sample_rate_hz: 16000,
                channels: 1,
                ptime_ms: 20,
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

impl Decoder for AmrWb {
    fn params(&self) -> CodecParams {
        self.params
    }
    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }
    fn decode(&mut self, _payload: &[u8], _out: &mut [i16]) -> Result<usize, CodecError> {
        Err(CodecError::Unsupported(
            "AMR-WB decode DSP not yet implemented",
        ))
    }
    fn conceal(&mut self, _out: &mut [i16]) -> Result<usize, CodecError> {
        Err(CodecError::Unsupported("AMR-WB PLC not yet implemented"))
    }
}

impl Encoder for AmrWb {
    fn params(&self) -> CodecParams {
        self.params
    }
    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }
    fn encode(&mut self, _pcm: &[i16], _out: &mut [u8]) -> Result<usize, CodecError> {
        Err(CodecError::Unsupported(
            "AMR-WB encode DSP not yet implemented",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amrnb_mode_sizes() {
        assert_eq!(AmrNbMode::Mr475.bits(), 95);
        assert_eq!(AmrNbMode::Mr475.bytes(), 12);
        assert_eq!(AmrNbMode::Mr1220.bits(), 244);
        assert_eq!(AmrNbMode::Mr1220.bytes(), 31);
        assert_eq!(AmrNbMode::Mr1220.frame_type(), 7);
    }

    #[test]
    fn amrwb_mode_sizes() {
        assert_eq!(AmrWbMode::Mr660.bits(), 132);
        assert_eq!(AmrWbMode::Mr660.bytes(), 17);
        assert_eq!(AmrWbMode::Mr2385.bits(), 477);
        assert_eq!(AmrWbMode::Mr2385.bytes(), 60);
        assert_eq!(AmrWbMode::Mr1265.frame_type(), 2);
    }

    #[test]
    fn frame_type_roundtrip() {
        for ft in 0u8..=7 {
            let mode = AmrNbMode::from_frame_type(ft).expect("nb mode");
            assert_eq!(mode.frame_type(), ft);
        }
        for ft in 0u8..=8 {
            let mode = AmrWbMode::from_frame_type(ft).expect("wb mode");
            assert_eq!(mode.frame_type(), ft);
        }
        assert_eq!(AmrNbMode::from_frame_type(8), None); // SID
        assert_eq!(AmrWbMode::from_frame_type(9), None); // SID
        assert_eq!(AmrWbMode::from_frame_type(15), None); // no-data
    }

    #[test]
    fn toc_octet_roundtrip() {
        for follow in [false, true] {
            for quality_ok in [false, true] {
                for frame_type in 0u8..=15 {
                    let toc = Toc {
                        follow,
                        frame_type,
                        quality_ok,
                    };
                    assert_eq!(Toc::from_octet(toc.to_octet()), toc);
                }
            }
        }
    }

    #[test]
    fn toc_bit_layout() {
        // FT=7 (MR1220), follow=1, quality=1 -> bits 1_0111_1_00 = 0b1011_1100 = 0xBC.
        let toc = Toc {
            follow: true,
            frame_type: 7,
            quality_ok: true,
        };
        assert_eq!(toc.to_octet(), 0b1011_1100);
    }

    #[test]
    fn parse_single_frame_payload() {
        // CMR=0xF (no request), one ToC (FT=7, no follow, quality ok), then frame data.
        let toc = Toc {
            follow: false,
            frame_type: 7,
            quality_ok: true,
        };
        let mut payload = vec![0xF0, toc.to_octet()];
        payload.extend(std::iter::repeat(0u8).take(AmrNbMode::Mr1220.bytes()));

        let header = parse_octet_aligned(&payload).expect("parse");
        assert_eq!(header.cmr, 0xF);
        assert_eq!(header.entries.len(), 1);
        assert_eq!(header.entries[0].frame_type, 7);
        assert_eq!(header.data_offset, 2);
    }

    #[test]
    fn parse_multi_frame_payload() {
        let first = Toc {
            follow: true,
            frame_type: 2,
            quality_ok: true,
        };
        let second = Toc {
            follow: false,
            frame_type: 2,
            quality_ok: true,
        };
        let payload = vec![0x00, first.to_octet(), second.to_octet(), 0x11, 0x22];
        let header = parse_octet_aligned(&payload).expect("parse");
        assert_eq!(header.entries.len(), 2);
        assert!(header.entries[0].follow);
        assert!(!header.entries[1].follow);
        assert_eq!(header.data_offset, 3);
    }

    #[test]
    fn parse_rejects_empty_and_truncated() {
        assert_eq!(
            parse_octet_aligned(&[]),
            Err(CodecError::Malformed("empty AMR payload"))
        );
        // CMR byte with follow bit set but no ToC byte present.
        assert_eq!(
            parse_octet_aligned(&[0xF0]),
            Err(CodecError::Malformed("truncated AMR ToC"))
        );
    }

    #[test]
    fn amr_codecs_report_params_but_decode_is_wip() {
        let mut nb = AmrNb::new();
        assert_eq!(nb.frame_samples(), 160);
        assert_eq!(nb.params().sample_rate_hz, 8000);
        assert!(matches!(
            nb.decode(&[0u8; 32], &mut [0i16; 160]),
            Err(CodecError::Unsupported(_))
        ));

        let mut wb = AmrWb::new();
        assert_eq!(wb.frame_samples(), 320);
        assert_eq!(wb.params().sample_rate_hz, 16000);
        assert!(matches!(
            wb.encode(&[0i16; 320], &mut [0u8; 64]),
            Err(CodecError::Unsupported(_))
        ));
    }
}
