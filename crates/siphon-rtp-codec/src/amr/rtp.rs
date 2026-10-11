//! RFC 4867 payload framing for the RTP path: both payload formats, read and written in place.
//!
//! [`read_payload`] takes a received payload apart into its codec mode request and its frames;
//! [`write_payload`] assembles one. Neither allocates: a packet is framed once in each direction
//! for every 20 ms of audio, so this is per-packet hot path.
//!
//! The two formats carry the same fields and differ only in alignment (RFC 4867 §4.3, §4.4):
//!
//! | | bandwidth-efficient | octet-aligned |
//! |---|---|---|
//! | header | CMR (4 bits) | CMR (4 bits), 4 reserved bits |
//! | ToC entry | F, FT (4 bits), Q | F, FT (4 bits), Q, 2 padding bits |
//! | frame | its bits, packed | its bits, padded to the octet |
//! | end | 0 to 7 padding bits | nothing |
//!
//! Interleaving, robust sorting and frame CRCs (§4.4.1, §4.4.2) are not implemented; a stream that
//! negotiated one of them is refused when the codec is built, see [`super::RtpConfig`].

use crate::CodecError;

use super::payload::{amrnb_frame_bits, amrwb_frame_bits};

/// The payload format of a stream (RFC 4867 §8.1 `octet-align`: "If 1, octet-aligned operation
/// SHALL be used. If 0 or if not present, bandwidth-efficient operation is employed.").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PayloadFormat {
    /// RFC 4867 §4.3, the default.
    #[default]
    BandwidthEfficient,
    /// RFC 4867 §4.4.
    OctetAligned,
}

impl PayloadFormat {
    /// Bits of the payload header: the CMR, and in octet-aligned mode its four reserved bits.
    const fn header_bits(self) -> usize {
        match self {
            Self::BandwidthEfficient => 4,
            Self::OctetAligned => 8,
        }
    }

    /// Bits of one ToC entry: F, FT and Q, and in octet-aligned mode two padding bits.
    const fn toc_entry_bits(self) -> usize {
        match self {
            Self::BandwidthEfficient => 6,
            Self::OctetAligned => 8,
        }
    }

    /// Bits a frame of `bits` speech bits occupies in the payload.
    const fn frame_span(self, bits: usize) -> usize {
        match self {
            Self::BandwidthEfficient => bits,
            Self::OctetAligned => bits.div_ceil(8) * 8,
        }
    }
}

/// Which of the two codecs a payload belongs to. They share the payload format and differ in their
/// frame type tables (3GPP TS 26.101 Table 1a, TS 26.201 Table 1a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// AMR, 8 kHz: speech modes 0 to 7, SID frame type 8.
    Narrowband,
    /// AMR-WB, 16 kHz: speech modes 0 to 8, SID frame type 9, SPEECH_LOST frame type 14.
    Wideband,
}

impl Variant {
    /// The highest speech mode (frame type) of the codec.
    #[must_use]
    pub const fn highest_mode(self) -> u8 {
        match self {
            Self::Narrowband => 7,
            Self::Wideband => 8,
        }
    }

    /// Bits of a frame of `frame_type`, `None` for a type the payload format does not carry.
    #[must_use]
    pub fn frame_bits(self, frame_type: u8) -> Option<u16> {
        match self {
            Self::Narrowband => amrnb_frame_bits(frame_type),
            Self::Wideband => amrwb_frame_bits(frame_type),
        }
    }

    /// PCM samples of one 20 ms frame.
    #[must_use]
    pub const fn frame_samples(self) -> usize {
        match self {
            Self::Narrowband => 160,
            Self::Wideband => 320,
        }
    }
}

pub use crate::NO_MODE_REQUEST;
/// Frame type 15, NO_DATA: nothing was produced or is carried for this frame (RFC 4867 §4.3.2).
pub const NO_DATA: u8 = 15;
/// Frame type 14, SPEECH_LOST, AMR-WB only (RFC 4867 §4.3.2).
pub const SPEECH_LOST: u8 = 14;

/// The most frames one payload may carry. 3GPP TS 26.114 §7.5.2.1.2.3: a client "shall accept any
/// number of frames per RTP packet up to the maximum limit of 12 speech frames per RTP packet",
/// which is `a=maxptime:240`.
pub const MAX_FRAMES: usize = 12;
/// Octets of the largest frame: AMR-WB mode 8, 477 bits.
pub const MAX_FRAME_OCTETS: usize = 60;

/// One frame of a received payload: its ToC entry and where its bits are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameSlot {
    /// Frame type: a speech mode, the SID frame, SPEECH_LOST or NO_DATA.
    pub frame_type: u8,
    /// The Q bit. Clear means "the corresponding frame is severely damaged" (RFC 4867 §4.3.2).
    pub quality_ok: bool,
    /// Bits of the frame, 0 for NO_DATA and SPEECH_LOST.
    pub bits: u16,
    /// Where the frame's first bit is in the payload, in bits from its start.
    bit_offset: u32,
}

impl FrameSlot {
    /// Copy the frame's bits out of `payload`, left-aligned, into `out`; the bits past the frame in
    /// its last octet are zero. Returns the octets written, 0 when `out` is too short or `payload`
    /// is not the one this slot was read from.
    pub fn copy_bits(&self, payload: &[u8], out: &mut [u8]) -> usize {
        let bits = usize::from(self.bits);
        let octets = bits.div_ceil(8);
        let start = self.bit_offset as usize;
        if out.len() < octets || start + bits > payload.len() * 8 {
            return 0;
        }
        let shift = start % 8;
        let first = start / 8;
        for (index, slot) in out[..octets].iter_mut().enumerate() {
            let high = payload[first + index] << shift;
            let low = match payload.get(first + index + 1) {
                Some(next) if shift != 0 => next >> (8 - shift),
                _ => 0,
            };
            *slot = high | low;
        }
        if !bits.is_multiple_of(8) {
            out[octets - 1] &= 0xFF << (8 - bits % 8);
        }
        octets
    }
}

/// A received payload taken apart: the codec mode request and the frames, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadLayout {
    /// The 4-bit codec mode request; [`NO_MODE_REQUEST`] when the peer asks for nothing.
    pub cmr: u8,
    frames: [FrameSlot; MAX_FRAMES],
    count: usize,
}

impl PayloadLayout {
    /// The frames of the payload, oldest first.
    #[must_use]
    pub fn frames(&self) -> &[FrameSlot] {
        &self.frames[..self.count]
    }
}

/// One bit of `payload`, most significant bit of each octet first (RFC 4867 §4.3.4).
fn bit(payload: &[u8], index: usize) -> Option<bool> {
    payload
        .get(index / 8)
        .map(|octet| octet & (0x80 >> (index % 8)) != 0)
}

/// `width` (at most 8) bits of `payload` from `start`, as a number.
fn field(payload: &[u8], start: usize, width: usize) -> Option<u8> {
    let mut value = 0;
    for offset in 0..width {
        value = (value << 1) | u8::from(bit(payload, start + offset)?);
    }
    Some(value)
}

/// Take a received payload apart.
///
/// Refuses, as [`CodecError::Malformed`], a payload that is not exactly what its own table of
/// contents describes: RFC 4867 §4.5.1, "if the receiver finds that the calculated payload length
/// ... does not match the size of the received packet, the receiver SHOULD discard the packet",
/// and §4.3.2, a frame type the format does not define means "the whole packet SHOULD be
/// discarded". Reserved and padding bits are ignored, as §4.4.1 and §4.3.4 require.
pub fn read_payload(
    payload: &[u8],
    format: PayloadFormat,
    variant: Variant,
) -> Result<PayloadLayout, CodecError> {
    if payload.is_empty() {
        return Err(CodecError::Malformed("empty AMR payload"));
    }
    let total = payload.len() * 8;
    let cmr = field(payload, 0, 4).ok_or(CodecError::Malformed("truncated AMR CMR"))?;
    let mut position = format.header_bits();
    let mut frames = [FrameSlot::default(); MAX_FRAMES];
    let mut count = 0;
    loop {
        let entry =
            field(payload, position, 6).ok_or(CodecError::Malformed("truncated AMR ToC"))?;
        position += format.toc_entry_bits();
        if position > total {
            return Err(CodecError::Malformed("truncated AMR ToC"));
        }
        let frame_type = (entry >> 1) & 0x0F;
        let bits = variant
            .frame_bits(frame_type)
            .ok_or(CodecError::Malformed("reserved AMR frame type"))?;
        let slot = frames.get_mut(count).ok_or(CodecError::Malformed(
            "more AMR frames in one payload than the 12 a receiver accepts",
        ))?;
        *slot = FrameSlot {
            frame_type,
            quality_ok: entry & 0x01 != 0,
            bits,
            bit_offset: 0,
        };
        count += 1;
        if entry & 0x20 == 0 {
            break;
        }
    }
    for slot in &mut frames[..count] {
        slot.bit_offset = position as u32;
        position += format.frame_span(usize::from(slot.bits));
    }
    if position > total {
        return Err(CodecError::Malformed("truncated AMR frame data"));
    }
    // Bandwidth-efficient ends in 0 to 7 padding bits; octet-aligned ends on the last frame.
    if total - position > 7 {
        return Err(CodecError::Malformed(
            "AMR payload longer than its table of contents describes",
        ));
    }
    Ok(PayloadLayout { cmr, frames, count })
}

/// One frame to put in a payload: its ToC entry and its bits, left-aligned.
#[derive(Debug, Clone, Copy)]
pub struct FrameSource<'a> {
    /// Frame type: a speech mode, the SID frame, SPEECH_LOST or NO_DATA.
    pub frame_type: u8,
    /// The Q bit.
    pub quality_ok: bool,
    /// The frame's bits, most significant first; empty for NO_DATA and SPEECH_LOST.
    pub data: &'a [u8],
}

/// Octets of a payload that carries frames of these types, or `None` when one is not a frame type
/// of the codec.
#[must_use]
pub fn payload_len(
    format: PayloadFormat,
    variant: Variant,
    frame_types: impl IntoIterator<Item = u8>,
) -> Option<usize> {
    let mut bits = format.header_bits();
    for frame_type in frame_types {
        bits += format.toc_entry_bits()
            + format.frame_span(usize::from(variant.frame_bits(frame_type)?));
    }
    Some(bits.div_ceil(8))
}

/// OR the first `bits` bits of `source` into `out` from bit `start`. `out` is zero there already.
fn put_bits(out: &mut [u8], start: usize, source: &[u8], bits: usize) {
    let shift = start % 8;
    let first = start / 8;
    let octets = bits.div_ceil(8);
    for (index, &octet) in source[..octets].iter().enumerate() {
        // The bits of the last octet past the end of the frame are not part of it.
        let octet = if index + 1 == octets && !bits.is_multiple_of(8) {
            octet & (0xFF << (8 - bits % 8))
        } else {
            octet
        };
        out[first + index] |= octet >> shift;
        if shift != 0 {
            if let Some(next) = out.get_mut(first + index + 1) {
                *next |= octet << (8 - shift);
            }
        }
    }
}

/// Assemble a payload into `out`, returning its length in octets.
///
/// `cmr` is the codec mode request to the peer, [`NO_MODE_REQUEST`] for none. The reserved bits of
/// the octet-aligned header and every padding bit are zero (RFC 4867 §4.4.1, §4.3.4).
pub fn write_payload(
    format: PayloadFormat,
    variant: Variant,
    cmr: u8,
    frames: &[FrameSource<'_>],
    out: &mut [u8],
) -> Result<usize, CodecError> {
    if frames.is_empty() || frames.len() > MAX_FRAMES {
        return Err(CodecError::Malformed(
            "an AMR payload carries 1 to 12 frames",
        ));
    }
    let needed = payload_len(format, variant, frames.iter().map(|frame| frame.frame_type))
        .ok_or(CodecError::Malformed("reserved AMR frame type"))?;
    if out.len() < needed {
        return Err(CodecError::OutputTooSmall {
            needed,
            have: out.len(),
        });
    }
    let out = &mut out[..needed];
    out.fill(0);
    out[0] = (cmr & 0x0F) << 4;
    let mut position = format.header_bits();
    for (index, frame) in frames.iter().enumerate() {
        let follow = u8::from(index + 1 < frames.len());
        let entry = (follow << 5) | ((frame.frame_type & 0x0F) << 1) | u8::from(frame.quality_ok);
        // The 6-bit entry, left-aligned in an octet, is the octet-aligned ToC octet as it stands.
        put_bits(out, position, &[entry << 2], 6);
        position += format.toc_entry_bits();
    }
    for frame in frames {
        let bits = usize::from(
            variant
                .frame_bits(frame.frame_type)
                .ok_or(CodecError::Malformed("reserved AMR frame type"))?,
        );
        if frame.data.len() < bits.div_ceil(8) {
            return Err(CodecError::Malformed(
                "AMR frame data shorter than its mode",
            ));
        }
        put_bits(out, position, frame.data, bits);
        position += format.frame_span(bits);
    }
    Ok(needed)
}

#[cfg(test)]
mod tests;
