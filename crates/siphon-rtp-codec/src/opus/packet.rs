//! Opus packet framing — the TOC byte + frame packing (RFC 6716 §3).
//!
//! Splits a received Opus packet into its table-of-contents ([`Toc`]) and constituent Opus frames,
//! before the SILK/CELT layers decode each frame. A faithful port of libopus `src/opus.c`
//! `opus_packet_parse_impl` + `parse_size` and the `opus_packet_get_*` accessors — the parsing logic
//! and rejection points match the C exactly, so a hostile bitstream off the network errors rather
//! than mis-frames (it never panics, indexes out of bounds, or loops). Self-delimited framing
//! (Appendix B — repacketizer / multistream only) is not needed to decode an RTP payload and is
//! omitted.
//!
//! ## The TOC byte (§3.1)
//! ```text
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+
//! | config  |s| c |
//! +-+-+-+-+-+-+-+-+
//! ```
//! `config` (0..=31) selects mode / audio bandwidth / frame duration (Table 2); `s` is the stereo
//! flag; `c` is the frame-count code (0: 1 frame, 1: 2 CBR, 2: 2 VBR, 3: arbitrary, §3.2).

use crate::CodecError;

/// One Opus frame is at most 1275 bytes (RFC 6716 §3.2.1 — the size that fits the 2-byte length).
const MAX_FRAME_BYTES: i32 = 1275;
/// At most 48 frames per packet (RFC 6716 §3.2.5 — the 6-bit count, capped by the 120 ms total).
const MAX_FRAMES: usize = 48;
/// 120 ms at 48 kHz — the maximum audio a single packet may carry (libopus `5760`).
const MAX_PACKET_SAMPLES_48K: i32 = 5760;

/// The coding mode a TOC `config` selects (RFC 6716 §3.1, Table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// SILK-only (speech), `config` 0..=11.
    Silk,
    /// Hybrid SILK + CELT, `config` 12..=15.
    Hybrid,
    /// CELT-only (music / low-latency), `config` 16..=31.
    Celt,
}

/// Audio bandwidth a TOC `config` selects (RFC 6716 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bandwidth {
    /// 4 kHz (8 kHz sampled).
    Narrowband,
    /// 6 kHz (12 kHz sampled) — SILK only.
    Mediumband,
    /// 8 kHz (16 kHz sampled).
    Wideband,
    /// 12 kHz (24 kHz sampled).
    SuperWideband,
    /// 20 kHz (48 kHz sampled).
    Fullband,
}

/// The parsed table-of-contents byte (RFC 6716 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Toc {
    /// Configuration number, 0..=31 (Table 2).
    pub config: u8,
    /// Stereo flag (`s` bit): `true` = 2 channels.
    pub stereo: bool,
    /// Frame-count code (`c`), 0..=3 (§3.2).
    pub frame_code: u8,
}

impl Toc {
    /// Parse the TOC byte (RFC 6716 §3.1).
    #[must_use]
    pub fn parse(byte: u8) -> Self {
        Self {
            config: byte >> 3,
            stereo: byte & 0x04 != 0,
            frame_code: byte & 0x03,
        }
    }

    /// The coding mode (libopus: `config` ranges, §3.1).
    #[must_use]
    pub fn mode(&self) -> Mode {
        if self.config & 0x10 != 0 {
            Mode::Celt // config >= 16
        } else if self.config >= 12 {
            Mode::Hybrid // config 12..=15
        } else {
            Mode::Silk // config 0..=11
        }
    }

    /// Channel count (1 or 2) — the `s` bit (libopus `opus_packet_get_nb_channels`).
    #[must_use]
    pub fn channels(&self) -> u8 {
        if self.stereo {
            2
        } else {
            1
        }
    }

    /// The audio bandwidth (libopus `opus_packet_get_bandwidth`).
    #[must_use]
    pub fn bandwidth(&self) -> Bandwidth {
        let config = self.config;
        if config & 0x10 != 0 {
            // CELT: NB / WB / SWB / FB (no mediumband).
            match (config >> 2) & 0x3 {
                0 => Bandwidth::Narrowband,
                1 => Bandwidth::Wideband,
                2 => Bandwidth::SuperWideband,
                _ => Bandwidth::Fullband,
            }
        } else if config >= 12 {
            // Hybrid: SWB (config 12,13) or FB (config 14,15).
            if config & 0x2 != 0 {
                Bandwidth::Fullband
            } else {
                Bandwidth::SuperWideband
            }
        } else {
            // SILK: NB / MB / WB.
            match (config >> 2) & 0x3 {
                0 => Bandwidth::Narrowband,
                1 => Bandwidth::Mediumband,
                _ => Bandwidth::Wideband,
            }
        }
    }

    /// Samples per frame at `sample_rate` (libopus `opus_packet_get_samples_per_frame`). The frame
    /// duration is 2.5/5/10/20 ms (CELT), 10/20 ms (Hybrid), or 10/20/40/60 ms (SILK).
    #[must_use]
    pub fn samples_per_frame(&self, sample_rate: u32) -> usize {
        let fs = sample_rate as usize;
        let config = self.config as usize;
        if config & 0x10 != 0 {
            // CELT: 2.5 ms << index.
            (fs << (config & 0x3)) / 400
        } else if config >= 12 {
            // Hybrid: 10 ms or 20 ms.
            if config & 0x1 != 0 {
                fs / 50
            } else {
                fs / 100
            }
        } else {
            // SILK: 10/20/40 ms, or 60 ms for index 3.
            let index = config & 0x3;
            if index == 3 {
                fs * 60 / 1000
            } else {
                (fs << index) / 100
            }
        }
    }
}

/// A parsed Opus packet (RFC 6716 §3): the TOC plus the constituent frames (slices into the original
/// buffer; a zero-length frame is DTX / "no data"). At most [`MAX_FRAMES`]; no heap allocation.
#[derive(Debug)]
pub struct OpusPacket<'a> {
    /// The table-of-contents byte.
    pub toc: Toc,
    /// Frame byte-slices, valid for `0..count` ([`OpusPacket::frames`]).
    slots: [&'a [u8]; MAX_FRAMES],
    count: usize,
    /// Trailing padding bytes (RFC 6716 §3.2.5), ignored by the decoder.
    pub padding: usize,
}

impl<'a> OpusPacket<'a> {
    /// The constituent Opus frames (1..=48), each a slice into the source packet.
    #[must_use]
    pub fn frames(&self) -> &[&'a [u8]] {
        &self.slots[..self.count]
    }

    /// Number of frames in the packet.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.count
    }
}

/// Read a frame size (RFC 6716 §3.2.1, libopus `parse_size`): 0..=251 is a one-byte length;
/// 252..=255 needs a second byte for `4*second + first`. Returns `(size, bytes_consumed)`, or `None`
/// when the buffer is too short (the caller rejects the packet).
fn parse_size(data: &[u8]) -> Option<(i32, usize)> {
    match data.first().copied() {
        None => None,
        Some(byte) if byte < 252 => Some((i32::from(byte), 1)),
        Some(byte) => data
            .get(1)
            .map(|&second| (4 * i32::from(second) + i32::from(byte), 2)),
    }
}

/// Parse an Opus packet into its TOC and frames (RFC 6716 §3, libopus `opus_packet_parse_impl` with
/// `self_delimited = 0`). Errors — never panics — on any malformed/truncated input.
pub fn parse(data: &[u8]) -> Result<OpusPacket<'_>, CodecError> {
    let invalid = || CodecError::Malformed("opus: invalid packet framing");
    if data.is_empty() {
        return Err(invalid());
    }

    let toc = Toc::parse(data[0]);
    let framesize = toc.samples_per_frame(48_000) as i32;

    let mut sizes = [0i32; MAX_FRAMES];
    let mut offset = 1usize; // read cursor, just past the TOC
    let mut len = (data.len() - 1) as i32; // bytes remaining after the TOC
    let mut last_size = len;
    let mut padding = 0usize;
    let count: usize;

    match toc.frame_code {
        // One frame: the whole payload.
        0 => {
            count = 1;
        }
        // Two equal (CBR) frames.
        1 => {
            count = 2;
            if len & 0x1 != 0 {
                return Err(invalid()); // odd payload can't split in two.
            }
            last_size = len / 2;
            sizes[0] = last_size;
        }
        // Two VBR frames; the first length is prefixed.
        2 => {
            count = 2;
            let (size, bytes) = parse_size(data.get(offset..).ok_or_else(invalid)?).ok_or_else(invalid)?;
            len -= bytes as i32;
            if size > len {
                return Err(invalid());
            }
            offset += bytes;
            sizes[0] = size;
            last_size = len - size;
        }
        // Arbitrary frame count (0..120 ms), CBR or VBR, optional padding.
        _ => {
            if len < 1 || offset >= data.len() {
                return Err(invalid());
            }
            let frame_count_byte = data[offset];
            offset += 1;
            len -= 1;
            count = (frame_count_byte & 0x3F) as usize; // M = low 6 bits.
            if count == 0 || framesize * count as i32 > MAX_PACKET_SAMPLES_48K {
                return Err(invalid()); // M>0 and total ≤ 120 ms.
            }
            // Padding flag (bit 6): decode the padding length (255-continuation bytes).
            if frame_count_byte & 0x40 != 0 {
                loop {
                    if len <= 0 || offset >= data.len() {
                        return Err(invalid());
                    }
                    let p = data[offset];
                    offset += 1;
                    len -= 1;
                    let tmp = if p == 255 { 254 } else { i32::from(p) };
                    len -= tmp;
                    padding += tmp as usize;
                    if p != 255 {
                        break;
                    }
                }
            }
            if len < 0 {
                return Err(invalid());
            }
            // VBR flag is bit 7; CBR when clear.
            let cbr = frame_count_byte & 0x80 == 0;
            if cbr {
                // CBR: all frames equal; payload must divide evenly.
                last_size = len / count as i32;
                if last_size * count as i32 != len {
                    return Err(invalid());
                }
                for size in sizes.iter_mut().take(count - 1) {
                    *size = last_size;
                }
            } else {
                // VBR: M-1 explicit lengths, last frame = the rest.
                last_size = len;
                for size in sizes.iter_mut().take(count - 1) {
                    let (sz, bytes) =
                        parse_size(data.get(offset..).ok_or_else(invalid)?).ok_or_else(invalid)?;
                    len -= bytes as i32;
                    if sz > len {
                        return Err(invalid());
                    }
                    offset += bytes;
                    last_size -= bytes as i32 + sz;
                    *size = sz;
                }
                if last_size < 0 {
                    return Err(invalid());
                }
            }
        }
    }

    // Non-self-delimited tail: the implicit last (or CBR) frame may exceed 1275 — reject it here.
    if last_size > MAX_FRAME_BYTES {
        return Err(invalid());
    }
    sizes[count - 1] = last_size;

    // Lay out frame slices sequentially from the read cursor (bounds-checked — a hostile packet
    // must error, never read out of bounds).
    let mut slots: [&[u8]; MAX_FRAMES] = [&[]; MAX_FRAMES];
    for (slot, &size) in slots.iter_mut().zip(sizes.iter()).take(count) {
        let sz = size as usize;
        let end = offset.checked_add(sz).ok_or_else(invalid)?;
        if end > data.len() {
            return Err(invalid());
        }
        *slot = &data[offset..end];
        offset = end;
    }

    // Trailing padding must fit after all frames.
    let pad_end = offset.checked_add(padding).ok_or_else(invalid)?;
    if pad_end > data.len() {
        return Err(invalid());
    }

    Ok(OpusPacket {
        toc,
        slots,
        count,
        padding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── TOC decoding (RFC 6716 Table 2) ──────────────────────────────────────────────────────
    #[test]
    fn toc_silk_configs() {
        let toc = Toc::parse(0x00); // config 0: SILK / NB / 10 ms, mono, code 0
        assert_eq!(toc.config, 0);
        assert_eq!(toc.mode(), Mode::Silk);
        assert_eq!(toc.bandwidth(), Bandwidth::Narrowband);
        assert_eq!(toc.channels(), 1);
        assert_eq!(toc.frame_code, 0);
        assert_eq!(toc.samples_per_frame(48_000), 480); // 10 ms
        let toc = Toc::parse(5 << 3); // config 5: SILK / MB / 20 ms
        assert_eq!(toc.bandwidth(), Bandwidth::Mediumband);
        assert_eq!(toc.samples_per_frame(48_000), 960);
        let toc = Toc::parse(11 << 3); // config 11: SILK / WB / 60 ms
        assert_eq!(toc.bandwidth(), Bandwidth::Wideband);
        assert_eq!(toc.samples_per_frame(48_000), 2880);
    }

    #[test]
    fn toc_hybrid_and_celt_configs() {
        let toc = Toc::parse(12 << 3); // Hybrid / SWB / 10 ms
        assert_eq!(toc.mode(), Mode::Hybrid);
        assert_eq!(toc.bandwidth(), Bandwidth::SuperWideband);
        assert_eq!(toc.samples_per_frame(48_000), 480);
        let toc = Toc::parse(15 << 3); // Hybrid / FB / 20 ms
        assert_eq!(toc.bandwidth(), Bandwidth::Fullband);
        assert_eq!(toc.samples_per_frame(48_000), 960);
        let toc = Toc::parse(16 << 3); // CELT / NB / 2.5 ms
        assert_eq!(toc.mode(), Mode::Celt);
        assert_eq!(toc.bandwidth(), Bandwidth::Narrowband);
        assert_eq!(toc.samples_per_frame(48_000), 120);
        let toc = Toc::parse(31 << 3); // CELT / FB / 20 ms
        assert_eq!(toc.bandwidth(), Bandwidth::Fullband);
        assert_eq!(toc.samples_per_frame(48_000), 960);
    }

    #[test]
    fn toc_stereo_flag() {
        assert_eq!(Toc::parse(0x04).channels(), 2);
    }

    // ── Framing codes 0–3 ────────────────────────────────────────────────────────────────────
    #[test]
    fn code0_single_frame() {
        let data = [0x00u8, 0xDE, 0xAD, 0xBE, 0xEF];
        let pkt = parse(&data).expect("valid");
        assert_eq!(pkt.frame_count(), 1);
        assert_eq!(pkt.frames()[0], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn code0_toc_only_is_dtx() {
        let pkt = parse(&[0x00u8]).expect("valid DTX");
        assert_eq!(pkt.frame_count(), 1);
        assert!(pkt.frames()[0].is_empty());
    }

    #[test]
    fn empty_packet_rejected() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn code1_two_equal_frames() {
        let pkt = parse(&[0x01u8, 0xAA, 0xBB, 0xCC, 0xDD]).expect("valid");
        assert_eq!(pkt.frame_count(), 2);
        assert_eq!(pkt.frames()[0], &[0xAA, 0xBB]);
        assert_eq!(pkt.frames()[1], &[0xCC, 0xDD]);
    }

    #[test]
    fn code1_odd_payload_rejected() {
        assert!(parse(&[0x01u8, 0xAA, 0xBB, 0xCC]).is_err());
    }

    #[test]
    fn code2_two_vbr_frames() {
        let data = [0x02u8, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let pkt = parse(&data).expect("valid");
        assert_eq!(pkt.frames()[0], &[0x11, 0x22]);
        assert_eq!(pkt.frames()[1], &[0x33, 0x44, 0x55]);
    }

    #[test]
    fn code2_two_byte_length_prefix() {
        let mut data = vec![0x02u8, 252, 1]; // length = 4*1 + 252 = 256
        data.extend(std::iter::repeat_n(0x77u8, 256));
        data.push(0x99);
        let pkt = parse(&data).expect("valid");
        assert_eq!(pkt.frames()[0].len(), 256);
        assert_eq!(pkt.frames()[1], &[0x99]);
    }

    #[test]
    fn code2_truncated_or_overrun_rejected() {
        assert!(parse(&[0x02u8, 252]).is_err()); // 2-byte prefix, 2nd byte missing
        assert!(parse(&[0x02u8, 200, 0x01, 0x02]).is_err()); // first frame overruns
    }

    #[test]
    fn code3_cbr_frames() {
        let data = [0x03u8, 0x03, 0x10, 0x11, 0x20, 0x21, 0x30, 0x31];
        let pkt = parse(&data).expect("valid");
        assert_eq!(pkt.frame_count(), 3);
        assert_eq!(pkt.frames()[1], &[0x20, 0x21]);
    }

    #[test]
    fn code3_cbr_not_divisible_rejected() {
        assert!(parse(&[0x03u8, 0x03, 1, 2, 3, 4, 5, 6, 7]).is_err());
    }

    #[test]
    fn code3_zero_count_rejected() {
        assert!(parse(&[0x03u8, 0x00, 1, 2]).is_err());
    }

    #[test]
    fn code3_vbr_frames() {
        let data = [0x03u8, 0x83, 1, 2, 0xA0, 0xB0, 0xB1, 0xC0, 0xC1, 0xC2];
        let pkt = parse(&data).expect("valid");
        assert_eq!(pkt.frame_count(), 3);
        assert_eq!(pkt.frames()[0], &[0xA0]);
        assert_eq!(pkt.frames()[1], &[0xB0, 0xB1]);
        assert_eq!(pkt.frames()[2], &[0xC0, 0xC1, 0xC2]);
    }

    #[test]
    fn code3_padding() {
        let data = [0x03u8, 0x42, 0x03, 0x10, 0x11, 0x20, 0x21, 0xFF, 0xFF, 0xFF];
        let pkt = parse(&data).expect("valid");
        assert_eq!(pkt.frame_count(), 2);
        assert_eq!(pkt.padding, 3);
        assert_eq!(pkt.frames()[1], &[0x20, 0x21]);
    }

    #[test]
    fn code3_padding_255_continuation() {
        let mut data = vec![0x03u8, 0x42, 255, 1, 0x10, 0x11, 0x20, 0x21];
        data.extend(std::iter::repeat_n(0u8, 255));
        let pkt = parse(&data).expect("valid");
        assert_eq!(pkt.padding, 255);
    }

    #[test]
    fn code3_padding_overrun_rejected() {
        assert!(parse(&[0x03u8, 0x42, 200, 0x10, 0x11]).is_err());
    }

    #[test]
    fn frame_over_1275_rejected() {
        let data = vec![0u8; 1 + 1276];
        assert!(parse(&data).is_err());
    }

    // ── Fuzz-robustness ──────────────────────────────────────────────────────────────────────
    #[test]
    fn arbitrary_bytes_never_panic() {
        for seed in 0u32..6000 {
            let n = (seed % 40) as usize + 1;
            let buf: Vec<u8> = (0..n)
                .map(|k| (seed.wrapping_mul(2_654_435_761).wrapping_add(k as u32) >> 13) as u8)
                .collect();
            let _ = parse(&buf); // Ok or Err — never panic / OOB.
        }
    }
}
