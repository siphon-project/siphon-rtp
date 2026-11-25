#![allow(clippy::expect_used, reason = "test harness: a panic reports failure")]
//! Wrapping G.192 frames into EVS RTP payloads (TS 26.445 Annex A), so the decoder's RTP path can
//! be held to the same reference outputs as its G.192 path.
//!
//! This is the *test's* packetizer: it writes the format from the specification's description and
//! shares nothing with the depacketizer under test but the AMR-WB IO sort table, whose independent
//! check is the reference encoder's own storage-format output (`evs_rtp_oracle`).

use siphon_rtp_codec::evs::frame::{FrameKind, PrimaryRate};
use siphon_rtp_codec::evs::g192::G192Frame;
use siphon_rtp_codec::evs::rtp::sort::SORT_TABLES;

/// The payload sizes in bits that mean "compact" to a receiver (A.2.1.3).
const COMPACT_SIZES: [usize; 22] = [
    48, 56, 136, 144, 160, 184, 192, 256, 264, 288, 320, 328, 368, 400, 464, 480, 488, 640, 960,
    1280, 1920, 2560,
];

/// Which payload format to write.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// Header-full for every frame (`hf-only=1`), with a CMR octet (0xFF, no request) on every
    /// other payload so both shapes are exercised.
    HeaderFull,
    /// Compact wherever the format has a compact form, header-full otherwise (NO_DATA, SPEECH_LOST,
    /// a damaged frame, an AMR-WB IO SID), padded where a header-full payload would be mistaken for
    /// a compact one.
    Compact,
}

/// The state a frame's packetization depends on: the G.192 file says SID_FIRST with a frame of no
/// bits that follows speech, which an RTP sender writes as an AMR-WB IO SID with STI = 0.
pub struct Packetizer {
    format: Format,
    previous_was_speech: bool,
    amr_wb_io: bool,
    count: usize,
}

fn pack_bits(bits: &[u8]) -> Vec<u8> {
    let mut octets = vec![0u8; bits.len().div_ceil(8)];
    for (index, &bit) in bits.iter().enumerate() {
        octets[index / 8] |= (bit & 1) << (7 - index % 8);
    }
    octets
}

impl Packetizer {
    pub fn new(format: Format) -> Self {
        Self {
            format,
            previous_was_speech: false,
            amr_wb_io: false,
            count: 0,
        }
    }

    /// The payload carrying `frame`.
    pub fn payload(&mut self, frame: &G192Frame<'_>) -> Vec<u8> {
        let mut bits = [0u8; FrameKind::MAX_BITS];
        let count = frame.unpack_bits(&mut bits).expect("bits");
        let bits = &bits[..count];
        self.count += 1;
        let (payload, compact) = match frame.kind {
            FrameKind::AmrWbIo(mode) => {
                self.amr_wb_io = true;
                self.speech(true, mode.index(), bits, frame.good)
            }
            FrameKind::AmrWbIoSid => {
                self.amr_wb_io = true;
                (self.io_sid(true, bits, frame.good), false)
            }
            FrameKind::Primary(rate) => {
                self.amr_wb_io = false;
                let index = PrimaryRate::ALL
                    .iter()
                    .position(|candidate| *candidate == rate)
                    .expect("rate") as u8;
                self.speech(false, index, bits, frame.good)
            }
            FrameKind::PrimarySid => {
                self.amr_wb_io = false;
                self.speech(false, 12, bits, frame.good)
            }
            FrameKind::NoData => {
                let payload = if !frame.good {
                    self.lost()
                } else if self.amr_wb_io && self.previous_was_speech {
                    // SID_FIRST: an IO SID with STI = 0 and nothing in the 35 bits that must be zero
                    self.io_sid(false, &[0u8; 35], true)
                } else {
                    vec![0x0F | if self.amr_wb_io { 0x20 } else { 0 }]
                };
                (payload, false)
            }
        };
        // speech is anything above the 2.4 kbit/s SID
        self.previous_was_speech = frame.kind.bits() > 2400 / 50;
        let mut payload = payload;
        if self.format == Format::Compact && !compact {
            // A.2.3.1: with `hf-only` 0 a header-full payload whose size is a compact size would
            // be read as compact (the 7-octet IO SID behind its CMR octet is told apart by its
            // first bit), so the sender pads it with zero octets until it is not.
            while COMPACT_SIZES.contains(&(payload.len() * 8))
                && !(payload.len() == 7 && payload[0] & 0x80 != 0)
            {
                payload.push(0);
            }
        }
        payload
    }

    fn lost(&self) -> Vec<u8> {
        vec![0x0E | if self.amr_wb_io { 0x20 } else { 0 }]
    }

    /// A speech frame or a primary SID: `index` is the frame type. The flag says the payload is
    /// compact.
    fn speech(&self, amr_wb_io: bool, index: u8, bits: &[u8], good: bool) -> (Vec<u8>, bool) {
        if !amr_wb_io && !good {
            // an EVS primary frame has no Q bit: a damaged one is a lost one
            return (self.lost(), false);
        }
        let mut sorted = bits.to_vec();
        if amr_wb_io {
            for (position, &slot) in SORT_TABLES[usize::from(index)].iter().enumerate() {
                sorted[position] = bits[usize::from(slot)];
            }
        }
        if self.format == Format::Compact && good {
            if let Some(payload) = compact(amr_wb_io, &sorted) {
                return (payload, true);
            }
        }
        let toc = if amr_wb_io {
            0x20 | if good { 0x10 } else { 0 } | index
        } else {
            index
        };
        let mut payload = Vec::new();
        if self.count % 2 == 1 {
            payload.push(0xFF);
        }
        payload.push(toc);
        payload.extend(pack_bits(&sorted));
        (payload, false)
    }

    /// An AMR-WB IO SID in the header-full format, always behind a CMR octet (A.2.1.3), followed
    /// by the STI bit and four CMI bits.
    fn io_sid(&self, update: bool, bits: &[u8], good: bool) -> Vec<u8> {
        let mut stored = bits.to_vec();
        stored.push(u8::from(update));
        stored.extend([0, 0, 0, 0]);
        let mut payload = vec![0xFF, 0x20 | if good { 0x10 } else { 0 } | 9];
        payload.extend(pack_bits(&stored));
        payload
    }
}

/// The compact payload of a good frame, or `None` where the format has none.
fn compact(amr_wb_io: bool, sorted: &[u8]) -> Option<Vec<u8>> {
    if !amr_wb_io {
        // the 2.8 kbit/s frame is only compact while its first bit is 0 (A.2.1.3)
        if sorted.len() == 56 && sorted[0] == 1 {
            return None;
        }
        return Some(pack_bits(sorted));
    }
    // CMR (3 bits, 7 = no request), d(1) .. d(n-1), d(0), then zeros to the compact size
    let mut stream = vec![1, 1, 1];
    stream.extend_from_slice(&sorted[1..]);
    stream.push(sorted[0]);
    let size = [136, 184, 256, 288, 320, 368, 400, 464, 480]
        .into_iter()
        .find(|&size| size >= stream.len() && size - stream.len() < 8)?;
    stream.resize(size, 0);
    Some(pack_bits(&stream))
}
