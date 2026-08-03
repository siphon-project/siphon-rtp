//! Opus packet assembly (RFC 6716 §3.2; libopus `src/repacketizer.c`,
//! `opus_repacketizer_out_range_impl`).
//!
//! One or more encoded frames and a TOC byte go in; a packet comes out, in whichever of the four
//! framing codes is smallest for that set of frame lengths:
//!
//! | Frames | Lengths | Code | Overhead beyond the frames |
//! |---|---|---|---|
//! | 1 | — | 0 | 1 byte (the TOC) |
//! | 2 | equal | 1 | 1 byte |
//! | 2 | differ | 2 | 2-3 bytes (TOC + the first length) |
//! | 3+ | equal | 3 CBR | 2 bytes (TOC + count) |
//! | 3+ | differ | 3 VBR | 2 bytes + one length per frame but the last |
//!
//! The choice is not cosmetic. A 60 ms CBR packet of three equal frames pays two bytes in code 3;
//! coding it VBR would pay four, and at 16 kb/s that is a quarter of a percent of the whole budget
//! given away for nothing.
//!
//! **Padding** (§3.2.5) is the other half: in CBR the packet must come out at exactly the target
//! size whatever the frames cost, so code 3 gains a padding run. libopus writes it as `0xFF` bytes
//! for each full 255, one remainder byte, and then zeros — and sets bit 6 of the frame-count byte to
//! say so. A packet that needs padding is always promoted to code 3, even a single frame, because
//! codes 0-2 have nowhere to put a padding length.

use crate::CodecError;

/// Largest single Opus **frame** (RFC 6716 §3.4: the compressed data for one frame is at most 1275
/// bytes, which is what the length field can express).
///
/// A *packet* is larger: a code-0 packet is a TOC plus a frame, so 1276 bytes, and a multi-frame
/// packet is larger still. libopus caps its own output at 1276 (`opus_encoder.c:1090`).
pub const MAX_PACKET_BYTES: usize = 1275;

/// At most 48 frames per packet (§3.2.5): the 6-bit count, capped by the 120 ms total.
pub const MAX_FRAMES_PER_PACKET: usize = 48;

/// `encode_size` (`opus.c:140-151`) — a frame length as one or two bytes (§3.2.1).
///
/// Returns how many bytes were written.
fn encode_size(size: usize, output: &mut [u8]) -> Result<usize, CodecError> {
    if size < 252 {
        let have = output.len();
        *output
            .first_mut()
            .ok_or(CodecError::OutputTooSmall { needed: 1, have })? = size as u8;
        Ok(1)
    } else {
        if output.len() < 2 {
            return Err(CodecError::OutputTooSmall {
                needed: 2,
                have: output.len(),
            });
        }
        let first = 252 + (size & 0x3);
        output[0] = first as u8;
        output[1] = ((size - first) >> 2) as u8;
        Ok(2)
    }
}

/// How many bytes `encode_size` will write for `size`.
fn size_bytes(size: usize) -> usize {
    if size < 252 {
        1
    } else {
        2
    }
}

/// One frame's location inside the staging buffer.
#[derive(Debug, Clone, Copy, Default)]
struct FrameSlot {
    offset: usize,
    length: usize,
}

/// Assembles the frames of one Opus packet.
///
/// Owns its staging buffer, so building a packet allocates nothing: the caller encodes each frame
/// into [`PacketBuilder::next_frame_buffer`] and commits the length it used.
#[derive(Debug)]
pub struct PacketBuilder {
    /// The frames, back to back. Sized for the worst case a single packet may carry.
    staging: [u8; MAX_PACKET_BYTES * 2],
    slots: [FrameSlot; MAX_FRAMES_PER_PACKET],
    count: usize,
    used: usize,
}

impl Default for PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketBuilder {
    /// An empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            staging: [0; MAX_PACKET_BYTES * 2],
            slots: [FrameSlot::default(); MAX_FRAMES_PER_PACKET],
            count: 0,
            used: 0,
        }
    }

    /// Forget every staged frame, keeping the allocation.
    pub fn clear(&mut self) {
        self.count = 0;
        self.used = 0;
    }

    /// Frames staged so far.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.count
    }

    /// The buffer the next frame should be encoded into. Its length is whatever staging space is
    /// left, which is the real ceiling on one frame.
    pub fn next_frame_buffer(&mut self) -> &mut [u8] {
        &mut self.staging[self.used..]
    }

    /// Record that the frame just written into [`PacketBuilder::next_frame_buffer`] is `length`
    /// bytes long.
    pub fn commit_frame(&mut self, length: usize) -> Result<(), CodecError> {
        if self.count >= MAX_FRAMES_PER_PACKET {
            return Err(CodecError::Unsupported(
                "opus enc: more than 48 frames in one packet",
            ));
        }
        if self.used + length > self.staging.len() {
            return Err(CodecError::OutputTooSmall {
                needed: self.used + length,
                have: self.staging.len(),
            });
        }
        self.slots[self.count] = FrameSlot {
            offset: self.used,
            length,
        };
        self.count += 1;
        self.used += length;
        Ok(())
    }

    /// The bytes of a staged frame.
    #[must_use]
    pub fn frame(&self, index: usize) -> &[u8] {
        let slot = self.slots[index];
        &self.staging[slot.offset..slot.offset + slot.length]
    }

    /// Write the packet (`opus_repacketizer_out_range_impl` with `self_delimited = 0`).
    ///
    /// `toc` must already carry the config, stereo and (ignored) frame-count bits; the low two bits
    /// are replaced. `pad_to` asks for CBR padding: `Some(n)` writes a packet of exactly `n` bytes,
    /// `None` writes the shortest legal one. Returns the packet length.
    pub fn write(
        &self,
        toc: u8,
        output: &mut [u8],
        pad_to: Option<usize>,
    ) -> Result<usize, CodecError> {
        if self.count == 0 {
            return Err(CodecError::Unsupported("opus enc: no frames to pack"));
        }
        let lengths: [usize; MAX_FRAMES_PER_PACKET] = std::array::from_fn(|index| {
            if index < self.count {
                self.slots[index].length
            } else {
                0
            }
        });
        let lengths = &lengths[..self.count];
        if lengths.iter().any(|&length| length > MAX_PACKET_BYTES) {
            return Err(CodecError::Unsupported(
                "opus enc: a frame longer than 1275 bytes has no representable length",
            ));
        }
        let max_len = pad_to.unwrap_or(output.len());
        if max_len > output.len() {
            return Err(CodecError::OutputTooSmall {
                needed: max_len,
                have: output.len(),
            });
        }

        // Codes 0-2 first, exactly as the C tries them, then code 3 if the frame count or the
        // padding request forces it (`repacketizer.c:174-211`).
        let mut total = 0usize;
        let mut cursor = 0usize;
        if self.count == 1 {
            total = lengths[0] + 1;
            if total > max_len {
                return Err(CodecError::OutputTooSmall {
                    needed: total,
                    have: max_len,
                });
            }
            output[cursor] = toc & 0xFC;
            cursor += 1;
        } else if self.count == 2 {
            if lengths[1] == lengths[0] {
                total = 2 * lengths[0] + 1;
                if total > max_len {
                    return Err(CodecError::OutputTooSmall {
                        needed: total,
                        have: max_len,
                    });
                }
                output[cursor] = (toc & 0xFC) | 0x1;
                cursor += 1;
            } else {
                total = 1 + size_bytes(lengths[0]) + lengths[0] + lengths[1];
                if total > max_len {
                    return Err(CodecError::OutputTooSmall {
                        needed: total,
                        have: max_len,
                    });
                }
                output[cursor] = (toc & 0xFC) | 0x2;
                cursor += 1;
                cursor += encode_size(lengths[0], &mut output[cursor..])?;
            }
        }

        let padding_wanted = pad_to.is_some_and(|target| total < target);
        if self.count > 2 || padding_wanted {
            // "Restart the process for the padding case" (`repacketizer.c:217`): whatever codes
            // 0-2 wrote above is discarded and the packet is rebuilt from byte zero.
            let variable = lengths.iter().any(|&length| length != lengths[0]);
            if variable {
                total = 2
                    + lengths[..self.count - 1]
                        .iter()
                        .map(|&length| size_bytes(length) + length)
                        .sum::<usize>()
                    + lengths[self.count - 1];
            } else {
                total = self.count * lengths[0] + 2;
            }
            if total > max_len {
                return Err(CodecError::OutputTooSmall {
                    needed: total,
                    have: max_len,
                });
            }
            output[0] = (toc & 0xFC) | 0x3;
            output[1] = if variable {
                (self.count as u8) | 0x80
            } else {
                self.count as u8
            };
            cursor = 2;

            let pad_amount = pad_to.map_or(0, |target| target.saturating_sub(total));
            if pad_amount != 0 {
                // §3.2.5: bit 6 of the frame-count byte says a padding length follows.
                output[1] |= 0x40;
                let full_255s = (pad_amount - 1) / 255;
                if total + full_255s + 1 > max_len {
                    return Err(CodecError::OutputTooSmall {
                        needed: total + full_255s + 1,
                        have: max_len,
                    });
                }
                for _ in 0..full_255s {
                    output[cursor] = 255;
                    cursor += 1;
                }
                output[cursor] = (pad_amount - 255 * full_255s - 1) as u8;
                cursor += 1;
                total += pad_amount;
            }
            if variable {
                for &length in &lengths[..self.count - 1] {
                    cursor += encode_size(length, &mut output[cursor..])?;
                }
            }
        }

        for index in 0..self.count {
            let frame = self.frame(index);
            output[cursor..cursor + frame.len()].copy_from_slice(frame);
            cursor += frame.len();
        }
        // "Fill padding with zeros" (`repacketizer.c:311-315`).
        if pad_to.is_some() {
            output[cursor..total].fill(0);
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::packet;

    /// Build a packet from explicit frame bytes.
    fn pack(toc: u8, frames: &[&[u8]], pad_to: Option<usize>) -> Result<Vec<u8>, CodecError> {
        let mut builder = PacketBuilder::new();
        for frame in frames {
            builder.next_frame_buffer()[..frame.len()].copy_from_slice(frame);
            builder.commit_frame(frame.len())?;
        }
        let mut output = vec![0u8; MAX_PACKET_BYTES];
        let length = builder.write(toc, &mut output, pad_to)?;
        output.truncate(length);
        Ok(output)
    }

    /// Every framing code must survive a round trip through the decoder's own parser, frame for
    /// frame — the parser is the thing that will actually read these on the wire.
    #[test]
    fn every_framing_code_round_trips_through_the_parser() {
        // A wideband 20 ms SILK TOC; the low two bits are the builder's to set.
        const TOC: u8 = 0x48;
        let cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
            ("code 0", vec![vec![0xAA; 30]]),
            ("code 1 (equal pair)", vec![vec![0xAA; 30], vec![0xBB; 30]]),
            (
                "code 2 (unequal pair)",
                vec![vec![0xAA; 30], vec![0xBB; 41]],
            ),
            (
                "code 3 cbr",
                vec![vec![0xAA; 20], vec![0xBB; 20], vec![0xCC; 20]],
            ),
            (
                "code 3 vbr",
                vec![vec![0xAA; 20], vec![0xBB; 31], vec![0xCC; 17]],
            ),
            (
                "code 3 vbr with a two-byte length",
                vec![vec![0xAA; 300], vec![0xBB; 31]],
            ),
        ];
        for (label, frames) in cases {
            let borrowed: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
            let packet = pack(TOC, &borrowed, None).unwrap_or_else(|error| {
                panic!("{label}: {error:?}");
            });
            let parsed = packet::parse(&packet).unwrap_or_else(|error| {
                panic!("{label}: parse: {error:?}");
            });
            assert_eq!(parsed.frame_count(), frames.len(), "{label}: frame count");
            for (index, frame) in frames.iter().enumerate() {
                assert_eq!(parsed.frames()[index], &frame[..], "{label}: frame {index}");
            }
            assert_eq!(parsed.toc.config, TOC >> 3, "{label}: config preserved");
        }
    }

    /// The code choice is the point of the module: pick the *smallest* legal framing.
    #[test]
    fn the_smallest_framing_is_chosen() {
        const TOC: u8 = 0x48;
        assert_eq!(pack(TOC, &[&[0u8; 10]], None).expect("code 0")[0] & 0x3, 0);
        assert_eq!(
            pack(TOC, &[&[0u8; 10], &[0u8; 10]], None).expect("code 1")[0] & 0x3,
            1,
            "an equal pair is code 1, not code 2"
        );
        assert_eq!(
            pack(TOC, &[&[0u8; 10], &[0u8; 11]], None).expect("code 2")[0] & 0x3,
            2
        );
        assert_eq!(
            pack(TOC, &[&[0u8; 10], &[0u8; 10], &[0u8; 10]], None).expect("code 3")[0] & 0x3,
            3
        );

        // Code 1 must be one byte cheaper than code 2 would have been for the same pair.
        let equal = pack(TOC, &[&[0u8; 40], &[0u8; 40]], None).expect("code 1");
        let unequal = pack(TOC, &[&[0u8; 40], &[0u8; 41]], None).expect("code 2");
        assert_eq!(equal.len(), 81, "TOC + two 40-byte frames");
        assert_eq!(unequal.len(), 83, "TOC + a length byte + 40 + 41");

        // Code 3 CBR must be two bytes cheaper than code 3 VBR for three equal frames.
        let cbr = pack(TOC, &[&[0u8; 20], &[0u8; 20], &[0u8; 20]], None).expect("cbr");
        let vbr = pack(TOC, &[&[0u8; 20], &[0u8; 21], &[0u8; 20]], None).expect("vbr");
        assert_eq!(cbr.len(), 62, "TOC + count + 3 x 20");
        assert_eq!(vbr.len(), 65, "TOC + count + two lengths + 20 + 21 + 20");
        assert_eq!(cbr[1] & 0x80, 0, "the CBR flag");
        assert_eq!(vbr[1] & 0x80, 0x80, "the VBR flag");
    }

    /// Padding must hit the requested size exactly, and the parser must see through it to the same
    /// frames.
    #[test]
    fn padding_hits_the_requested_size_exactly() {
        const TOC: u8 = 0x48;
        // 41 bytes is the natural code-1 size of two 20-byte frames and 42 the code-3 one, so the
        // sweep starts at 42: a target *below* the natural size is an error, not a padding request,
        // and at exactly 42 the promotion to code 3 alone covers it with no padding run at all.
        const NATURAL_CODE_3: usize = 42;
        for target in [NATURAL_CODE_3, 100, 300, 600, 1275] {
            let packet =
                pack(TOC, &[&[0x5Au8; 20], &[0x5Au8; 20]], Some(target)).expect("padded packet");
            assert_eq!(packet.len(), target, "padded to {target}");
            assert_eq!(packet[0] & 0x3, 3, "padding forces code 3");
            assert_eq!(
                packet[1] & 0x40,
                if target > NATURAL_CODE_3 { 0x40 } else { 0 },
                "the padding flag must be set exactly when a padding run was written ({target})"
            );
            let parsed = packet::parse(&packet).expect("parse");
            assert_eq!(parsed.frame_count(), 2);
            assert_eq!(parsed.frames()[0], &[0x5Au8; 20][..]);
            assert_eq!(parsed.frames()[1], &[0x5Au8; 20][..]);
        }

        // A single frame padded is still legal and still parses to one frame.
        let single = pack(TOC, &[&[0x11u8; 10]], Some(64)).expect("padded single");
        assert_eq!(single.len(), 64);
        let parsed = packet::parse(&single).expect("parse");
        assert_eq!(parsed.frame_count(), 1);
        assert_eq!(parsed.frames()[0], &[0x11u8; 10][..]);

        // Asking for exactly the natural size must not add a padding run.
        let natural = pack(TOC, &[&[0x11u8; 10]], None).expect("natural");
        let exact = pack(TOC, &[&[0x11u8; 10]], Some(natural.len())).expect("exact");
        assert_eq!(exact, natural, "no padding was needed");
    }

    /// A packet that does not fit must be an error, never a truncated packet.
    #[test]
    fn an_oversized_packet_is_rejected() {
        const TOC: u8 = 0x48;
        let mut builder = PacketBuilder::new();
        builder.commit_frame(600).expect("first");
        builder.commit_frame(600).expect("second");
        let mut output = [0u8; 900];
        assert!(builder.write(TOC, &mut output, None).is_err());

        // And an empty builder is an error rather than a bare TOC.
        let empty = PacketBuilder::new();
        assert!(empty.write(TOC, &mut output, None).is_err());
    }

    /// More than 48 frames is not representable in the 6-bit count, so it must be refused at commit
    /// time rather than silently truncated at write time.
    #[test]
    fn more_than_forty_eight_frames_is_refused() {
        let mut builder = PacketBuilder::new();
        for index in 0..MAX_FRAMES_PER_PACKET {
            builder
                .commit_frame(1)
                .unwrap_or_else(|error| panic!("frame {index}: {error:?}"));
        }
        assert!(builder.commit_frame(1).is_err());
    }

    /// `encode_size` must reproduce §3.2.1 for both branches, including the boundary.
    #[test]
    fn frame_lengths_are_encoded_per_section_3_2_1() {
        let mut buffer = [0u8; 2];
        assert_eq!(encode_size(0, &mut buffer).expect("zero"), 1);
        assert_eq!(buffer[0], 0);
        assert_eq!(encode_size(251, &mut buffer).expect("251"), 1);
        assert_eq!(buffer[0], 251);
        assert_eq!(encode_size(252, &mut buffer).expect("252"), 2);
        assert_eq!((buffer[0], buffer[1]), (252, 0));
        assert_eq!(encode_size(1275, &mut buffer).expect("1275"), 2);
        assert_eq!(
            4 * u32::from(buffer[1]) + u32::from(buffer[0]),
            1275,
            "the parser's own reconstruction"
        );
        // Every length must survive the parser's `parse_size`.
        for size in [0usize, 1, 251, 252, 253, 254, 255, 500, 1275] {
            let written = encode_size(size, &mut buffer).expect("encode");
            let recovered = if written == 1 {
                usize::from(buffer[0])
            } else {
                4 * usize::from(buffer[1]) + usize::from(buffer[0])
            };
            assert_eq!(recovered, size, "size {size}");
        }
    }

    /// Building must not allocate: the staging buffer and the slot table are both owned.
    #[test]
    fn clearing_reuses_the_staging_buffer() {
        let mut builder = PacketBuilder::new();
        builder.next_frame_buffer()[..4].copy_from_slice(&[1, 2, 3, 4]);
        builder.commit_frame(4).expect("commit");
        assert_eq!(builder.frame(0), &[1, 2, 3, 4]);
        builder.clear();
        assert_eq!(builder.frame_count(), 0);
        builder.next_frame_buffer()[..2].copy_from_slice(&[9, 9]);
        builder.commit_frame(2).expect("commit");
        assert_eq!(builder.frame(0), &[9, 9], "the buffer was reused from zero");
    }
}
