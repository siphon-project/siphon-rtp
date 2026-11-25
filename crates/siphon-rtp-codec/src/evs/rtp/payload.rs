//! Reading an EVS RTP payload, 3GPP TS 26.445 Annex A.2: the compact and the header-full format,
//! and the rule that tells them apart.
//!
//! # The two formats
//!
//! **Compact** (A.2.1) carries one frame and no header: the payload's size says what the frame is.
//! An EVS primary frame is the whole payload, bit for bit as the codec wrote it. An AMR-WB
//! interoperable (IO) frame starts with a 3-bit CMR, then its speech bits in the AMR-WB order with
//! the first bit `d(0)` moved to the end, then zero bits to the octet boundary.
//!
//! **Header-full** (A.2.2) is an optional CMR octet (`H` = 1), then one table-of-contents octet per
//! frame (`H` = 0, `F` "another follows", the EVS-mode bit `E`, `Q` for an IO frame, and a 4-bit
//! frame type), then the frames in the same order, each padded with zero bits to an octet. Any
//! number of frames may follow, which is how a packet carries more than 20 ms.
//!
//! # Telling them apart (A.2.3)
//!
//! With `hf-only=1` every payload is header-full (A.2.3.2). Otherwise (A.2.3.1) a payload whose
//! size in bits is one of the 22 compact sizes is compact, and any other is header-full. Two sizes
//! need a note:
//!
//! - 56 bits is both the EVS primary 2.8 kbit/s frame (compact) and an AMR-WB IO SID in the
//!   header-full format with a CMR octet. The IO SID has no compact format, and the primary frame's
//!   first bit is always 0, while the CMR octet's `H` bit is 1: the first bit decides (A.2.1.3).
//! - 48 bits is the EVS primary SID. An IO SID without a CMR octet would be 48 bits too, which is
//!   why an IO SID is always sent with one.
//!
//! This is the TS 26.442 reference's `evsPayload_unpackFrame` and `evsHeaderFullPayload_unpackFrame`
//! (`lib_dec/evs_rtp_payload.c`), checked against Wireshark's dissector and against the reference
//! encoder's own storage-format output (`tests/evs_rtp_conformance.rs`).
//!
//! What is read is not trusted: a packet that does not parse is refused with a [`PayloadError`] and
//! nothing about it reaches the decoder.

use super::cmr::Cmr;
use super::sort::SORT_TABLES;
use crate::evs::frame::{AmrWbIoMode, FrameKind, PrimaryRate};
use crate::CodecError;

/// The most frames one packet may carry here: 240 ms. The format itself sets no limit, but every
/// frame costs a decode, and a table of contents of `F` bits is one octet per frame, so a hostile
/// packet could otherwise ask for a thousand.
pub const MAX_FRAMES_PER_PACKET: usize = 12;

/// The payload sizes, in bits, that identify a compact-format payload (TS 26.445 A.2.1.3, the
/// reference's `evsPayloadProtectedSizes`).
const COMPACT_SIZES: [(usize, CompactFrame); 22] = [
    (48, CompactFrame::PrimarySid),
    (56, CompactFrame::Primary(PrimaryRate::Rate2800)),
    (136, CompactFrame::AmrWbIo(0)),
    (144, CompactFrame::Primary(PrimaryRate::Rate7200)),
    (160, CompactFrame::Primary(PrimaryRate::Rate8000)),
    (184, CompactFrame::AmrWbIo(1)),
    (192, CompactFrame::Primary(PrimaryRate::Rate9600)),
    (256, CompactFrame::AmrWbIo(2)),
    (264, CompactFrame::Primary(PrimaryRate::Rate13200)),
    (288, CompactFrame::AmrWbIo(3)),
    (320, CompactFrame::AmrWbIo(4)),
    (328, CompactFrame::Primary(PrimaryRate::Rate16400)),
    (368, CompactFrame::AmrWbIo(5)),
    (400, CompactFrame::AmrWbIo(6)),
    (464, CompactFrame::AmrWbIo(7)),
    (480, CompactFrame::AmrWbIo(8)),
    (488, CompactFrame::Primary(PrimaryRate::Rate24400)),
    (640, CompactFrame::Primary(PrimaryRate::Rate32000)),
    (960, CompactFrame::Primary(PrimaryRate::Rate48000)),
    (1280, CompactFrame::Primary(PrimaryRate::Rate64000)),
    (1920, CompactFrame::Primary(PrimaryRate::Rate96000)),
    (2560, CompactFrame::Primary(PrimaryRate::Rate128000)),
];

/// What a compact payload size means. An AMR-WB IO frame is the mode number: its speech bits and the
/// 3-bit CMR are in the payload and zero bits pad it to the size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompactFrame {
    PrimarySid,
    Primary(PrimaryRate),
    AmrWbIo(u8),
}

/// Why a payload is not an EVS payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// No octets at all.
    #[error("empty EVS payload")]
    Empty,
    /// The table of contents does not end before the payload does.
    #[error("EVS payload ends inside its table of contents")]
    TruncatedToc,
    /// A second CMR octet where a table-of-contents entry must be.
    #[error("EVS payload has a CMR octet where a table-of-contents entry must be")]
    CmrInsteadOfToc,
    /// A frame type the specification reserves (primary 13, AMR-WB IO 10 to 13).
    #[error("EVS payload has a reserved frame type")]
    ReservedFrameType,
    /// The frames the table of contents lists do not fit in the payload.
    #[error("EVS payload is shorter than its table of contents says")]
    TruncatedFrame,
    /// More frames than [`MAX_FRAMES_PER_PACKET`].
    #[error("EVS payload carries more frames than the engine accepts in one packet")]
    TooManyFrames,
}

impl PayloadError {
    /// A short fixed description, for the `&'static str` the codec error carries.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Empty => "empty EVS payload",
            Self::TruncatedToc => "EVS payload ends inside its table of contents",
            Self::CmrInsteadOfToc => "EVS payload has a CMR octet where a ToC entry must be",
            Self::ReservedFrameType => "EVS payload has a reserved frame type",
            Self::TruncatedFrame => "EVS payload is shorter than its table of contents says",
            Self::TooManyFrames => "EVS payload carries too many frames",
        }
    }
}

impl From<PayloadError> for CodecError {
    fn from(error: PayloadError) -> Self {
        Self::Malformed(error.reason())
    }
}

/// Which of the two formats a payload is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFormat {
    /// One frame, no header (A.2.1).
    Compact,
    /// An optional CMR, a table of contents and the frames (A.2.2).
    HeaderFull,
}

/// What one frame of a payload is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// An EVS primary speech frame.
    Primary(PrimaryRate),
    /// The EVS primary SID, 2.4 kbit/s.
    PrimarySid,
    /// An AMR-WB IO speech frame.
    AmrWbIo(AmrWbIoMode),
    /// The AMR-WB IO SID, 1.75 kbit/s, followed by the STI bit and the 4 CMI bits.
    AmrWbIoSid,
    /// The sender knows the frame was lost (`FT` 14), in the mode the table of contents named.
    SpeechLost {
        /// Whether the table of contents named the AMR-WB IO mode (`E` = 1).
        amr_wb_io: bool,
    },
    /// No frame was sent, or none arrived (`FT` 15).
    NoData {
        /// Whether the table of contents named the AMR-WB IO mode (`E` = 1).
        amr_wb_io: bool,
    },
}

impl FrameType {
    /// The frame's speech bits (the SID's 35 for an IO SID), 0 for a frame with none.
    #[must_use]
    pub fn speech_bits(self) -> usize {
        match self {
            Self::Primary(rate) => FrameKind::Primary(rate).bits(),
            Self::PrimarySid => FrameKind::PrimarySid.bits(),
            Self::AmrWbIo(mode) => FrameKind::AmrWbIo(mode).bits(),
            Self::AmrWbIoSid => FrameKind::AmrWbIoSid.bits(),
            Self::SpeechLost { .. } | Self::NoData { .. } => 0,
        }
    }

    /// Bits the frame occupies in a header-full payload before the padding: the speech bits, and
    /// for an IO SID the STI bit and the four CMI bits after them (A.2.2.1.3).
    #[must_use]
    pub fn stored_bits(self) -> usize {
        match self {
            Self::AmrWbIoSid => self.speech_bits() + 5,
            _ => self.speech_bits(),
        }
    }

    /// Whether the frame is in the AMR-WB IO mode: its speech bits are in the AMR-WB order, and
    /// the decoder's mode follows.
    #[must_use]
    pub fn is_amr_wb_io(self) -> bool {
        matches!(
            self,
            Self::AmrWbIo(_)
                | Self::AmrWbIoSid
                | Self::SpeechLost { amr_wb_io: true }
                | Self::NoData { amr_wb_io: true }
        )
    }

    /// The 4-bit frame type of the table of contents (`FT`), as the reference's `core_mode`.
    #[must_use]
    pub fn frame_type_index(self) -> u8 {
        match self {
            Self::Primary(rate) => PrimaryRate::ALL
                .iter()
                .position(|candidate| *candidate == rate)
                .map_or(0, |index| index as u8),
            Self::PrimarySid => 12,
            Self::AmrWbIo(mode) => mode.index(),
            Self::AmrWbIoSid => 9,
            Self::SpeechLost { .. } => 14,
            Self::NoData { .. } => 15,
        }
    }
}

/// One frame of a packet: its type, the quality bit, and where its bits are. The bits are read
/// into the decoder's order by [`Frame::decoder_bits`].
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    /// What the frame is.
    pub frame_type: FrameType,
    /// The `Q` bit of an AMR-WB IO table-of-contents entry: `false` marks a frame damaged in
    /// transit (the bits are still there). Always `true` for an EVS primary frame, which has no
    /// such bit, and for a compact frame.
    pub quality_ok: bool,
    payload: &'a [u8],
    /// The payload bit the frame's first stored bit is at.
    first_bit: usize,
    /// A compact AMR-WB IO frame: the first speech bit `d(0)` is the last bit of the frame, and
    /// the others follow the CMR (A.2.1.2).
    d0_last: bool,
}

impl Frame<'_> {
    /// The payload bit at `index` of the frame's stored bits, 0 past the end of the payload.
    fn stored_bit(&self, index: usize) -> u8 {
        let position = self.first_bit + index;
        self.payload
            .get(position / 8)
            .map_or(0, |octet| (octet >> (7 - position % 8)) & 1)
    }

    /// The `index`-th speech bit in payload order (AMR-WB order for an IO frame).
    fn speech_bit(&self, index: usize) -> u8 {
        if self.d0_last {
            // CMR (3 bits), d(1) .. d(n-1), then d(0): A.2.1.2
            let bits = self.frame_type.speech_bits();
            self.stored_bit(if index == 0 { bits + 2 } else { index + 2 })
        } else {
            self.stored_bit(index)
        }
    }

    /// The STI bit of an AMR-WB IO SID: `true` for a SID_UPDATE, `false` for SID_FIRST
    /// (A.2.2.1.3). `None` for any other frame.
    #[must_use]
    pub fn sid_update(&self) -> Option<bool> {
        (self.frame_type == FrameType::AmrWbIoSid).then(|| self.stored_bit(35) == 1)
    }

    /// The 4 CMI bits of an AMR-WB IO SID, the codec mode indication, or `None` for any other
    /// frame. The decoder does not use them.
    #[must_use]
    pub fn codec_mode_indication(&self) -> Option<u8> {
        (self.frame_type == FrameType::AmrWbIoSid).then(|| {
            (0..4).fold(0u8, |value, offset| {
                (value << 1) | self.stored_bit(36 + offset)
            })
        })
    }

    /// Write the frame's speech bits into `out`, one per element (0 or 1), in the order the
    /// decoder reads them, and return how many. An AMR-WB IO frame is un-sorted from the AMR-WB
    /// order (TS 26.445 A.2.1.2 / A.2.2.1.2); every other frame is as written.
    ///
    /// `out` must hold [`FrameType::speech_bits`]; a shorter one is filled as far as it goes.
    pub fn decoder_bits(&self, out: &mut [u8]) -> usize {
        let bits = self.frame_type.speech_bits().min(out.len());
        let table = match self.frame_type {
            FrameType::AmrWbIo(mode) => SORT_TABLES.get(usize::from(mode.index())),
            FrameType::AmrWbIoSid => SORT_TABLES.get(9),
            _ => None,
        };
        for index in 0..bits {
            let bit = self.speech_bit(index);
            let slot = table
                .and_then(|table| table.get(index))
                .map_or(index, |&target| usize::from(target));
            if let Some(slot) = out.get_mut(slot) {
                *slot = bit;
            }
        }
        bits
    }
}

/// A parsed EVS RTP payload: its format, its codec mode request and its frames.
#[derive(Debug, Clone, Copy)]
pub struct Packet<'a> {
    payload: &'a [u8],
    format: PayloadFormat,
    cmr: Option<Cmr>,
    /// Header-full: where the table of contents starts, how many entries it has, and where the
    /// first frame starts. Compact: the frame.
    layout: Layout,
}

#[derive(Debug, Clone, Copy)]
enum Layout {
    Compact(CompactFrame),
    HeaderFull {
        toc: usize,
        frames: usize,
        data: usize,
    },
}

/// One table-of-contents entry.
struct TocEntry {
    frame_type: FrameType,
    quality_ok: bool,
    last: bool,
}

fn parse_toc(octet: u8) -> Result<TocEntry, PayloadError> {
    if octet & 0x80 != 0 {
        return Err(PayloadError::CmrInsteadOfToc);
    }
    let amr_wb_io = octet & 0x20 != 0;
    let index = octet & 0x0F;
    let frame_type = if amr_wb_io {
        match index {
            0..=8 => AmrWbIoMode::from_index(index).map(FrameType::AmrWbIo),
            9 => Some(FrameType::AmrWbIoSid),
            14 => Some(FrameType::SpeechLost { amr_wb_io }),
            15 => Some(FrameType::NoData { amr_wb_io }),
            _ => None,
        }
    } else {
        match index {
            0..=11 => PrimaryRate::ALL
                .get(usize::from(index))
                .copied()
                .map(FrameType::Primary),
            12 => Some(FrameType::PrimarySid),
            14 => Some(FrameType::SpeechLost { amr_wb_io }),
            15 => Some(FrameType::NoData { amr_wb_io }),
            _ => None,
        }
    }
    .ok_or(PayloadError::ReservedFrameType)?;
    Ok(TocEntry {
        frame_type,
        // the `Q` bit is defined for the AMR-WB IO mode only
        quality_ok: !amr_wb_io || octet & 0x10 != 0,
        last: octet & 0x40 == 0,
    })
}

impl<'a> Packet<'a> {
    /// Read `payload`. `header_full_only` is the negotiated `hf-only=1`.
    ///
    /// # Errors
    /// [`PayloadError`] for a payload that is not EVS: empty, a table of contents or frame that
    /// does not fit, a reserved frame type, a CMR where a table-of-contents entry must be, or more
    /// than [`MAX_FRAMES_PER_PACKET`] frames.
    pub fn parse(payload: &'a [u8], header_full_only: bool) -> Result<Self, PayloadError> {
        let first = *payload.first().ok_or(PayloadError::Empty)?;
        // A.2.1.3: 56 bits with the first bit set is an IO SID behind a CMR octet, not the 2.8 kbit/s
        // frame, whose first bit is 0.
        let io_sid_behind_cmr = payload.len() == 7 && first & 0x80 != 0;
        if !header_full_only && !io_sid_behind_cmr {
            let bits = payload.len() * 8;
            if let Some(&(_, frame)) = COMPACT_SIZES.iter().find(|(size, _)| *size == bits) {
                let cmr = match frame {
                    // the 3-bit CMR is the first three bits (A.2.1.2)
                    CompactFrame::AmrWbIo(_) => Some(Cmr::AmrWbIoCompact(first >> 5)),
                    _ => None,
                };
                return Ok(Self {
                    payload,
                    format: PayloadFormat::Compact,
                    cmr,
                    layout: Layout::Compact(frame),
                });
            }
        }
        Self::parse_header_full(payload)
    }

    fn parse_header_full(payload: &'a [u8]) -> Result<Self, PayloadError> {
        let (cmr, toc) = match payload.first() {
            Some(&octet) if octet & 0x80 != 0 => (Some(Cmr::from_octet(octet)), 1),
            _ => (None, 0),
        };
        let mut frames = 0;
        let mut data_octets = 0;
        let mut position = toc;
        loop {
            let octet = *payload.get(position).ok_or(PayloadError::TruncatedToc)?;
            let entry = parse_toc(octet)?;
            frames += 1;
            if frames > MAX_FRAMES_PER_PACKET {
                return Err(PayloadError::TooManyFrames);
            }
            data_octets += entry.frame_type.stored_bits().div_ceil(8);
            position += 1;
            if entry.last {
                break;
            }
        }
        // Octets after the last frame are padding; a payload must not end before it (A.2.2).
        if payload.len() < position + data_octets {
            return Err(PayloadError::TruncatedFrame);
        }
        Ok(Self {
            payload,
            format: PayloadFormat::HeaderFull,
            cmr,
            layout: Layout::HeaderFull {
                toc,
                frames,
                data: position,
            },
        })
    }

    /// Which format the payload was in.
    #[must_use]
    pub fn format(&self) -> PayloadFormat {
        self.format
    }

    /// The codec mode request: the CMR octet of a header-full payload, the 3-bit field of a
    /// compact AMR-WB IO one, and `None` where the payload has none.
    #[must_use]
    pub fn cmr(&self) -> Option<Cmr> {
        self.cmr
    }

    /// How many frames the payload carries, each 20 ms.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        match self.layout {
            Layout::Compact(_) => 1,
            Layout::HeaderFull { frames, .. } => frames,
        }
    }

    /// The frames, in order.
    #[must_use]
    pub fn frames(&self) -> Frames<'a> {
        Frames {
            packet: *self,
            index: 0,
            data_bit: match self.layout {
                Layout::Compact(_) => 0,
                Layout::HeaderFull { data, .. } => data * 8,
            },
        }
    }
}

/// The frames of a [`Packet`].
#[derive(Debug, Clone)]
pub struct Frames<'a> {
    packet: Packet<'a>,
    index: usize,
    data_bit: usize,
}

impl<'a> Iterator for Frames<'a> {
    type Item = Frame<'a>;

    fn next(&mut self) -> Option<Frame<'a>> {
        let payload = self.packet.payload;
        let frame = match self.packet.layout {
            Layout::Compact(compact) => {
                if self.index > 0 {
                    return None;
                }
                match compact {
                    CompactFrame::PrimarySid => Frame {
                        frame_type: FrameType::PrimarySid,
                        quality_ok: true,
                        payload,
                        first_bit: 0,
                        d0_last: false,
                    },
                    CompactFrame::Primary(rate) => Frame {
                        frame_type: FrameType::Primary(rate),
                        quality_ok: true,
                        payload,
                        first_bit: 0,
                        d0_last: false,
                    },
                    CompactFrame::AmrWbIo(mode) => Frame {
                        frame_type: FrameType::AmrWbIo(AmrWbIoMode::from_index(mode)?),
                        quality_ok: true,
                        payload,
                        first_bit: 0,
                        d0_last: true,
                    },
                }
            }
            Layout::HeaderFull { toc, frames, .. } => {
                if self.index >= frames {
                    return None;
                }
                // `parse` accepted every entry, so this cannot fail; stopping is the safe answer
                let entry = parse_toc(*payload.get(toc + self.index)?).ok()?;
                let frame = Frame {
                    frame_type: entry.frame_type,
                    quality_ok: entry.quality_ok,
                    payload,
                    first_bit: self.data_bit,
                    d0_last: false,
                };
                self.data_bit += entry.frame_type.stored_bits().div_ceil(8) * 8;
                frame
            }
        };
        self.index += 1;
        Some(frame)
    }
}

#[cfg(test)]
mod tests;
