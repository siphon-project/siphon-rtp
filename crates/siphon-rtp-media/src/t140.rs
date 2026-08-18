//! Real-Time Text over RTP: RFC 2198 redundant coding (RED) and RFC 4103 T.140 reassembly.
//!
//! This module is the parse/build/reassemble core for an `m=text` leg; it is deliberately pure,
//! synchronous, and NIC-free like [`crate::dtmf`], so the datapath/engine wire it to sockets in a
//! later change (it is not itself connected here).
//!
//! Two layers:
//!
//! * **RED (RFC 2198).** [`RedPacket::parse`] is a robust depacketizer over untrusted network bytes
//!   (decode-or-error, never panic / never out-of-bounds); [`RedBuilder`] produces the wire bytes
//!   into a caller-owned buffer (no per-call heap allocation). A RED payload is a run of 4-byte
//!   redundant-block headers, then the 1-byte primary header, then all data blocks in header order
//!   (RFC 2198 §3).
//! * **T.140 reassembly (RFC 4103).** [`T140Reassembler`] mirrors [`crate::dtmf::DtmfDetector`]'s
//!   minimal-state shape (highest RTP sequence / timestamp seen). It uses the RED redundant copies
//!   to recover lost generations (RFC 4103 §4.2 / §5), inserts a single missing-text marker (U+FFFD,
//!   RFC 4103 §5.3 → ITU-T T.140 Addendum 1) where redundancy cannot recover a gap, deduplicates so
//!   each generation's text is emitted exactly once, and buffers a UTF-8 character that a
//!   non-conformant sender split across a packet boundary rather than emit an invalid code unit
//!   (RFC 4103 §3.3 — T.140 text is UTF-8/ISO 10646). It is deterministic: sequence and timestamp
//!   are inputs, never `Instant::now()`.

/// Maximum redundant generations [`RedPacket::parse`] accepts before rejecting the payload.
///
/// RFC 4103 §4 recommends only two redundant generations, and RED headers are bounded by the
/// payload size, but a hostile packet could stack many tiny blocks. Capping keeps the parser
/// allocation-free (a fixed on-stack block table) and its output bounded (`Err(TooManyBlocks)`).
pub const MAX_RED_BLOCKS: usize = 32;

/// The largest value the RFC 2198 §3 14-bit timestamp-offset field can hold.
const MAX_TIMESTAMP_OFFSET: u32 = (1 << 14) - 1;

/// The largest value the RFC 2198 §3 10-bit block-length field can hold.
const MAX_BLOCK_LENGTH: usize = (1 << 10) - 1;

/// The Unicode REPLACEMENT CHARACTER (U+FFFD), used as the T.140 missing-text marker.
///
/// RFC 4103 §5.3 requires marking a lost T140block with a missing-text marker "as specified in
/// ITU-T T.140 Addendum 1"; the realized marker is U+FFFD (the convention across RTT stacks). It is
/// also the standard replacement for otherwise-undecodable bytes, so a single character covers both
/// "text lost on the wire" and "text arrived malformed".
pub const MISSING_TEXT_MARKER: char = '\u{FFFD}';

/// Initial reassembly-output capacity, reserved once at construction so steady-state delivery of
/// small text chunks never reallocates.
const DEFAULT_OUTPUT_CAPACITY: usize = 256;

/// Errors from RED depacketization ([`RedPacket::parse`]) and building ([`RedBuilder`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RedError {
    /// The payload ended in the middle of a block header (RFC 2198 §3): a redundant header needs 4
    /// bytes, and there must be a final primary header byte.
    #[error("RED payload truncated inside a block header")]
    Truncated,
    /// A redundant block's declared length runs past the end of the payload.
    #[error("RED block length {length} exceeds the {remaining} bytes remaining")]
    BlockLengthExceedsPayload {
        /// The declared block length.
        length: usize,
        /// The bytes actually left in the payload at that point.
        remaining: usize,
    },
    /// The payload declares more than [`MAX_RED_BLOCKS`] redundant blocks.
    #[error("RED payload declares more than {max} redundant blocks")]
    TooManyBlocks {
        /// The enforced ceiling ([`MAX_RED_BLOCKS`]).
        max: usize,
    },
    /// A redundant generation's timestamp offset does not fit the RFC 2198 §3 14-bit field (the
    /// generation is newer than the primary, or older than ~16.38 s at 1000 Hz).
    #[error("RED timestamp offset {offset} does not fit the 14-bit field")]
    TimestampOffsetTooLarge {
        /// The offset that overflowed.
        offset: u32,
    },
    /// A block's data does not fit the RFC 2198 §3 10-bit block-length field (> 1023 bytes).
    #[error("RED block length {length} does not fit the 10-bit field")]
    BlockLengthTooLarge {
        /// The data length that overflowed.
        length: usize,
    },
}

/// One block inside a RED payload: a payload type, the timestamp offset back to the generation this
/// block carries (0 for the primary), and a borrowed view of that generation's data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedBlock<'a> {
    /// The block's RTP payload type (RFC 2198 §3, 7-bit PT).
    pub payload_type: u8,
    /// RTP timestamp units to subtract from the primary timestamp to get this block's timestamp
    /// (RFC 2198 §3). Always 0 for the primary block.
    pub timestamp_offset: u32,
    /// The block's data (excluding header). Borrowed from the input payload.
    pub data: &'a [u8],
}

/// A parsed RED payload (RFC 2198 §3): zero or more redundant blocks (oldest-first) plus the
/// primary block. Blocks borrow the input payload — parsing allocates nothing.
#[derive(Debug)]
pub struct RedPacket<'a> {
    /// Redundant blocks in header order (RFC 4103 §4.2: oldest first, most-recent last).
    redundant: [RedBlock<'a>; MAX_RED_BLOCKS],
    /// How many entries of `redundant` are populated.
    redundant_count: usize,
    /// The primary (final) block — the newest generation.
    primary: RedBlock<'a>,
}

impl<'a> RedPacket<'a> {
    /// Depacketize a RED payload (RFC 2198 §3).
    ///
    /// Robust against arbitrary/hostile network bytes: every truncation, an inconsistent block
    /// length, or a run of more than [`MAX_RED_BLOCKS`] headers returns `Err` — never a panic and
    /// never an out-of-bounds read.
    ///
    /// # Errors
    /// Returns [`RedError::Truncated`] if the payload ends inside a header,
    /// [`RedError::BlockLengthExceedsPayload`] if a declared block length runs past the data, and
    /// [`RedError::TooManyBlocks`] beyond [`MAX_RED_BLOCKS`].
    pub fn parse(payload: &'a [u8]) -> Result<Self, RedError> {
        // On-stack, allocation-free block table. `data` is filled in the second pass.
        let mut redundant: [RedBlock<'a>; MAX_RED_BLOCKS] = [RedBlock {
            payload_type: 0,
            timestamp_offset: 0,
            data: &[],
        }; MAX_RED_BLOCKS];
        let mut lengths = [0usize; MAX_RED_BLOCKS];
        let mut redundant_count = 0usize;
        let mut cursor = 0usize;

        // Pass 1 — headers. Read 4-byte redundant headers (F=1) until the 1-byte primary header
        // (F=0), which is always last (RFC 2198 §3).
        let primary_payload_type = loop {
            let first = *payload.get(cursor).ok_or(RedError::Truncated)?;
            // F is the top bit of the first header byte.
            if first & 0x80 == 0 {
                // Final (primary) header: `0 | PT(7)`.
                cursor += 1;
                break first & 0x7F;
            }
            if redundant_count == MAX_RED_BLOCKS {
                return Err(RedError::TooManyBlocks {
                    max: MAX_RED_BLOCKS,
                });
            }
            // Redundant header: `F(1)=1 | PT(7) | timestamp-offset(14) | block-length(10)` = 4 bytes.
            let header = payload.get(cursor..cursor + 4).ok_or(RedError::Truncated)?;
            let payload_type = header[0] & 0x7F;
            // timestamp offset = 14 bits = all of byte 1 (high 8) + top 6 bits of byte 2.
            let timestamp_offset = (u32::from(header[1]) << 6) | (u32::from(header[2]) >> 2);
            // block length = 10 bits = low 2 bits of byte 2 + all of byte 3.
            let block_length = ((u32::from(header[2]) & 0x03) << 8) | u32::from(header[3]);
            redundant[redundant_count] = RedBlock {
                payload_type,
                timestamp_offset,
                data: &[],
            };
            lengths[redundant_count] = block_length as usize;
            redundant_count += 1;
            cursor += 4;
        };

        // Pass 2 — data blocks, in header order (RFC 2198 §3: no padding or delimiters).
        for index in 0..redundant_count {
            let length = lengths[index];
            let data = payload.get(cursor..cursor + length).ok_or(
                RedError::BlockLengthExceedsPayload {
                    length,
                    remaining: payload.len() - cursor,
                },
            )?;
            redundant[index].data = data;
            cursor += length;
        }
        // The primary block has no length field: its data is the remainder (RFC 2198 §3). `cursor`
        // is always <= payload.len() here, so the slice never panics.
        let primary = RedBlock {
            payload_type: primary_payload_type,
            timestamp_offset: 0,
            data: payload.get(cursor..).unwrap_or(&[]),
        };

        Ok(Self {
            redundant,
            redundant_count,
            primary,
        })
    }

    /// The redundant blocks, oldest generation first (RFC 4103 §4.2).
    #[must_use]
    pub fn redundant_blocks(&self) -> &[RedBlock<'a>] {
        &self.redundant[..self.redundant_count]
    }

    /// The primary (newest) block.
    #[must_use]
    pub fn primary(&self) -> &RedBlock<'a> {
        &self.primary
    }

    /// The number of redundant generations carried (0 for a bare primary-only RED payload).
    #[must_use]
    pub fn generation_count(&self) -> usize {
        self.redundant_count
    }
}

/// One prior generation fed to [`RedBuilder`]: its payload type, the RTP timestamp it was originally
/// sent with, and its data. The builder computes the RFC 2198 §3 timestamp offset from the primary.
#[derive(Debug, Clone, Copy)]
pub struct RedGeneration<'a> {
    /// The generation's RTP payload type.
    pub payload_type: u8,
    /// The RTP timestamp this generation was (or would be) sent with as a primary.
    pub rtp_timestamp: u32,
    /// The generation's data.
    pub data: &'a [u8],
}

/// Builds a RED payload (RFC 2198 §3) from the current primary plus prior generations.
///
/// `redundant` is ordered oldest-first (RFC 4103 §4.2: the most recent redundant generation is last
/// in the redundancy area, so a receiver can infer each generation's sequence number by counting
/// backwards from the RTP header). The timestamp offset of each generation is
/// `primary_rtp_timestamp - generation.rtp_timestamp` in RTP-clock units (1000 Hz for T.140).
#[derive(Debug, Clone, Copy)]
pub struct RedBuilder<'a> {
    /// The primary block's payload type.
    pub primary_payload_type: u8,
    /// The RTP timestamp of the primary block — the reference for every offset.
    pub primary_rtp_timestamp: u32,
    /// The primary (newest) generation's data.
    pub primary_data: &'a [u8],
    /// Prior generations, oldest first (RFC 4103 §4.2).
    pub redundant: &'a [RedGeneration<'a>],
}

impl RedBuilder<'_> {
    /// Serialize the RED payload into `out`, which is cleared first and reused across calls (no
    /// per-call heap allocation once its capacity is warm). Returns the number of bytes written.
    ///
    /// # Errors
    /// [`RedError::TooManyBlocks`] beyond [`MAX_RED_BLOCKS`]; [`RedError::TimestampOffsetTooLarge`]
    /// if a generation is not strictly older than the primary within the 14-bit offset field; and
    /// [`RedError::BlockLengthTooLarge`] if a block's data exceeds the 10-bit length field.
    pub fn write_into(&self, out: &mut Vec<u8>) -> Result<usize, RedError> {
        out.clear();
        if self.redundant.len() > MAX_RED_BLOCKS {
            return Err(RedError::TooManyBlocks {
                max: MAX_RED_BLOCKS,
            });
        }
        // Redundant block headers: `F(1)=1 | PT(7) | timestamp-offset(14) | block-length(10)`.
        for generation in self.redundant {
            let (offset, length) = self.validated_offset_length(generation)?;
            let header: u32 = (1u32 << 31)
                | (u32::from(generation.payload_type & 0x7F) << 24)
                | (offset << 10)
                | (length as u32);
            out.extend_from_slice(&header.to_be_bytes());
        }
        // Primary (final) block header: `F(1)=0 | PT(7)`.
        out.push(self.primary_payload_type & 0x7F);
        // Data blocks, in header order: redundant (oldest-first) then primary (RFC 2198 §3).
        for generation in self.redundant {
            out.extend_from_slice(generation.data);
        }
        out.extend_from_slice(self.primary_data);
        Ok(out.len())
    }

    /// The exact number of bytes [`Self::write_into`] would produce, so a caller can pre-size its
    /// buffer.
    ///
    /// # Errors
    /// Same validation as [`Self::write_into`].
    pub fn encoded_len(&self) -> Result<usize, RedError> {
        if self.redundant.len() > MAX_RED_BLOCKS {
            return Err(RedError::TooManyBlocks {
                max: MAX_RED_BLOCKS,
            });
        }
        // Primary header (1 byte) + primary data.
        let mut total = 1 + self.primary_data.len();
        for generation in self.redundant {
            let (_, length) = self.validated_offset_length(generation)?;
            // 4-byte header + data.
            total += 4 + length;
        }
        Ok(total)
    }

    /// Validate one generation against the RFC 2198 §3 field widths and return its `(offset,
    /// length)`. A redundant generation must be strictly older than the primary, so the unsigned
    /// offset stays inside the 14-bit field.
    fn validated_offset_length(
        &self,
        generation: &RedGeneration<'_>,
    ) -> Result<(u32, usize), RedError> {
        let offset = self
            .primary_rtp_timestamp
            .wrapping_sub(generation.rtp_timestamp);
        if offset > MAX_TIMESTAMP_OFFSET {
            return Err(RedError::TimestampOffsetTooLarge { offset });
        }
        let length = generation.data.len();
        if length > MAX_BLOCK_LENGTH {
            return Err(RedError::BlockLengthTooLarge { length });
        }
        Ok((offset, length))
    }
}

/// The text newly recovered from one [`T140Reassembler::on_packet`] call, plus loss counters for
/// the CDR/QoS surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T140Output<'a> {
    /// The newly-recovered, deduplicated UTF-8 text for this packet (may be empty — e.g. a
    /// duplicate/reordered packet, an idle keepalive, or a still-incomplete split character).
    pub text: &'a str,
    /// Missing-text markers (U+FFFD) inserted this call for unrecoverable gaps (RFC 4103 §5.3).
    pub missing_markers: usize,
    /// Generations recovered from RED redundancy this call (RFC 4103 §4.2 / §5).
    pub recovered_from_redundancy: usize,
}

/// Reassembles an RFC 4103 T.140 text stream, recovering losses from RED redundancy and marking the
/// gaps redundancy cannot cover.
///
/// Modeled on [`crate::dtmf::DtmfDetector`]: minimal state (the next sequence number owed and the
/// highest RTP timestamp seen), fed one packet at a time. Deterministic — sequence and timestamp are
/// inputs. Steady-state delivery allocates nothing (a reused output buffer plus a fixed 4-byte
/// partial-character buffer).
#[derive(Debug)]
pub struct T140Reassembler {
    /// The next RTP sequence number whose text we still owe the receiver. `None` until the first
    /// packet establishes the stream; thereafter it is (highest delivered sequence + 1).
    expected_sequence: Option<u16>,
    /// The highest RTP timestamp seen (RFC 3550 serial-number order) — informational stream state.
    highest_timestamp: Option<u32>,
    /// An incomplete trailing UTF-8 sequence carried to the next block (a valid multi-byte prefix is
    /// at most 3 bytes; the 4th slot is headroom). RFC 4103 §3.3 forbids splitting a character, so
    /// this only fires for a non-conformant sender — it exists to never emit an invalid code unit.
    partial: [u8; 4],
    /// How many bytes of `partial` are pending.
    partial_len: usize,
    /// Reused output buffer, cleared and refilled per packet so steady state never reallocates.
    output: String,
}

impl Default for T140Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl T140Reassembler {
    /// Create an idle reassembler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            expected_sequence: None,
            highest_timestamp: None,
            partial: [0; 4],
            partial_len: 0,
            output: String::with_capacity(DEFAULT_OUTPUT_CAPACITY),
        }
    }

    /// The next RTP sequence number the reassembler still owes, or `None` before the first packet.
    #[must_use]
    pub fn next_expected_sequence(&self) -> Option<u16> {
        self.expected_sequence
    }

    /// The highest RTP timestamp seen so far, or `None` before the first packet.
    #[must_use]
    pub fn highest_timestamp(&self) -> Option<u32> {
        self.highest_timestamp
    }

    /// Feed one RTP packet's `sequence`, `timestamp`, and payload, returning the newly-recovered
    /// text. `is_red` selects the RED (RFC 2198) depacketizer; `false` treats `payload` as bare
    /// T.140 data on the raw t140 payload type (a legal, redundancy-free packet, RFC 4103 §4).
    ///
    /// Recovery (RFC 4103 §4.2 / §5): a sequence gap that the packet's redundant generations cover
    /// is filled from those copies; a gap older than the available redundancy is marked once with
    /// [`MISSING_TEXT_MARKER`] (RFC 4103 §5.3). Text already delivered (by an earlier packet's
    /// primary, or a duplicate/reordered packet) is never re-emitted. A UTF-8 character a sender
    /// split across packets is completed on the next packet, never emitted partially.
    ///
    /// # Errors
    /// Propagates [`RedPacket::parse`] errors when `is_red` is set and the payload is malformed.
    pub fn on_packet(
        &mut self,
        sequence: u16,
        timestamp: u32,
        payload: &[u8],
        is_red: bool,
    ) -> Result<T140Output<'_>, RedError> {
        self.output.clear();
        let mut missing_markers = 0usize;
        let mut recovered_from_redundancy = 0usize;

        // Track the highest RTP timestamp (RFC 3550 serial-number arithmetic).
        self.highest_timestamp = Some(match self.highest_timestamp {
            Some(previous) if !timestamp_is_after(timestamp, previous) => previous,
            _ => timestamp,
        });

        // Depacketize. A bare packet is just primary data with zero redundancy.
        let parsed = if is_red {
            Some(RedPacket::parse(payload)?)
        } else {
            None
        };
        let (redundant, primary_data): (&[RedBlock<'_>], &[u8]) = match &parsed {
            Some(packet) => (packet.redundant_blocks(), packet.primary().data),
            None => (&[][..], payload),
        };
        let redundancy = redundant.len();

        let expected = match self.expected_sequence {
            None => {
                // First packet on the stream: deliver only its primary. Its redundant blocks are
                // pre-join history the receiver was never owed.
                self.push_text(primary_data);
                self.expected_sequence = Some(sequence.wrapping_add(1));
                return Ok(self.output_view(missing_markers, recovered_from_redundancy));
            }
            Some(expected) => expected,
        };

        // RFC 3550 serial-number arithmetic: how far this packet's sequence is ahead of the next one
        // owed. Negative ⇒ an already-delivered / duplicate / reordered packet.
        let ahead = sequence_distance(sequence, expected);
        if ahead < 0 {
            // Everything here is <= what we already delivered — dedupe, emit nothing, and do not
            // rewind the high-water mark (RFC 4103 §5: never re-emit delivered text).
            return Ok(self.output_view(missing_markers, recovered_from_redundancy));
        }
        let ahead = ahead as usize;

        // The gap [expected, sequence) splits into an unrecoverable older run and a
        // redundancy-covered tail. RED carries sequences [sequence-redundancy, sequence-1], with the
        // most-recent generation last (RFC 4103 §4.2).
        let recoverable = ahead.min(redundancy);
        let unrecoverable = ahead - recoverable;

        if unrecoverable > 0 {
            // Redundancy cannot reach this run. Insert ONE missing-text marker for the contiguous
            // loss (RFC 4103 §5.3 → ITU-T T.140 Addendum 1). Coalescing a run into a single marker
            // keeps output bounded — a large (possibly hostile) sequence gap cannot expand into
            // unbounded U+FFFD output — and matches T.140 marking the *location* of missing text.
            // Drop any half-built character: it cannot be completed across lost data.
            self.partial_len = 0;
            self.output.push(MISSING_TEXT_MARKER);
            missing_markers += 1;
        }

        // Recover the redundancy-covered, not-yet-delivered generations in ascending sequence order:
        // the last `recoverable` redundant blocks (they carry sequences [sequence-recoverable,
        // sequence-1], all >= expected).
        for block in &redundant[redundancy - recoverable..] {
            self.push_text(block.data);
            recovered_from_redundancy += 1;
        }

        // Finally this packet's own primary generation (sequence).
        self.push_text(primary_data);
        self.expected_sequence = Some(sequence.wrapping_add(1));

        Ok(self.output_view(missing_markers, recovered_from_redundancy))
    }

    /// Borrow the accumulated output together with this call's counters.
    fn output_view(
        &self,
        missing_markers: usize,
        recovered_from_redundancy: usize,
    ) -> T140Output<'_> {
        T140Output {
            text: &self.output,
            missing_markers,
            recovered_from_redundancy,
        }
    }

    /// Append one generation's bytes as UTF-8, completing any pending split character first and
    /// buffering a new trailing incomplete character rather than emitting an invalid code unit
    /// (RFC 4103 §3.3 — T.140 is UTF-8; a block SHOULD hold whole characters, but we tolerate a
    /// sender that splits one).
    fn push_text(&mut self, mut bytes: &[u8]) {
        // Complete a character split from a previous block.
        if self.partial_len > 0 {
            match utf8_lead_length(self.partial[0]) {
                Some(needed) => {
                    while self.partial_len < needed && !bytes.is_empty() {
                        self.partial[self.partial_len] = bytes[0];
                        self.partial_len += 1;
                        bytes = &bytes[1..];
                    }
                    if self.partial_len < needed {
                        // Still short — wait for more bytes on the next block.
                        return;
                    }
                    match std::str::from_utf8(&self.partial[..needed]) {
                        Ok(text) => self.output.push_str(text),
                        // A malformed continuation completed the buffer: one replacement char.
                        Err(_) => self.output.push(MISSING_TEXT_MARKER),
                    }
                    self.partial_len = 0;
                }
                None => {
                    // The buffered lead byte was never a valid UTF-8 start (defensive).
                    self.output.push(MISSING_TEXT_MARKER);
                    self.partial_len = 0;
                }
            }
        }

        // Decode the remainder, buffering only a trailing incomplete character.
        loop {
            match std::str::from_utf8(bytes) {
                Ok(text) => {
                    self.output.push_str(text);
                    return;
                }
                Err(error) => {
                    let valid_up_to = error.valid_up_to();
                    if let Ok(text) = std::str::from_utf8(&bytes[..valid_up_to]) {
                        self.output.push_str(text);
                    }
                    match error.error_len() {
                        Some(bad) => {
                            // Genuinely invalid bytes in the middle: replace, continue after them.
                            self.output.push(MISSING_TEXT_MARKER);
                            bytes = &bytes[valid_up_to + bad..];
                        }
                        None => {
                            // Incomplete trailing sequence (a valid prefix, <= 3 bytes): buffer it.
                            let tail = &bytes[valid_up_to..];
                            self.partial_len = tail.len().min(self.partial.len());
                            self.partial[..self.partial_len]
                                .copy_from_slice(&tail[..self.partial_len]);
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// The number of bytes in the UTF-8 character that starts with `byte`, or `None` if `byte` is not a
/// valid UTF-8 lead byte.
fn utf8_lead_length(byte: u8) -> Option<usize> {
    if byte & 0x80 == 0x00 {
        Some(1)
    } else if byte & 0xE0 == 0xC0 {
        Some(2)
    } else if byte & 0xF0 == 0xE0 {
        Some(3)
    } else if byte & 0xF8 == 0xF0 {
        Some(4)
    } else {
        None
    }
}

/// RFC 3550 serial-number arithmetic: the signed distance `a - b` in 16-bit sequence space. Positive
/// ⇒ `a` is ahead of `b`.
fn sequence_distance(a: u16, b: u16) -> i32 {
    i32::from(a.wrapping_sub(b) as i16)
}

/// RFC 3550 serial-number arithmetic: whether RTP timestamp `a` is strictly after `b`.
fn timestamp_is_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// An RFC-document dynamic payload type for T.140 (RFC 4103 uses a dynamic PT; 98 is in range).
    const T140_PAYLOAD_TYPE: u8 = 98;

    /// Build a RED payload for `primary` at `primary_ts` with `redundant` = oldest-first
    /// `(rtp_timestamp, data)` generations, all on the t140 PT. Test helper (allocation is fine in
    /// tests).
    fn build_red(primary_ts: u32, primary: &[u8], redundant: &[(u32, &[u8])]) -> Vec<u8> {
        let generations: Vec<RedGeneration> = redundant
            .iter()
            .map(|(rtp_timestamp, data)| RedGeneration {
                payload_type: T140_PAYLOAD_TYPE,
                rtp_timestamp: *rtp_timestamp,
                data,
            })
            .collect();
        let builder = RedBuilder {
            primary_payload_type: T140_PAYLOAD_TYPE,
            primary_rtp_timestamp: primary_ts,
            primary_data: primary,
            redundant: &generations,
        };
        let mut out = Vec::new();
        builder.write_into(&mut out).expect("build RED payload");
        out
    }

    // ----- RED parse: reference vectors (byte-exact against RFC 2198 §3 bit-layout) -----

    #[test]
    fn parses_rfc2198_section7_example() {
        // RFC 2198 §7 worked example: a DVI4 (PT 5) primary of 84 bytes with one LPC (PT 7)
        // redundant block of 14 bytes, both 20 ms @ 8 kHz — so the redundant generation is one 20 ms
        // frame (160 samples) older than the primary.
        //
        // Redundant header (RFC 2198 §3, 4 bytes): F=1 | PT=7 | ts-offset=160 | block-len=14
        //   0x87 = 1_0000111  -> F=1, PT=0000111=7
        //   0x02 0x80 0x0E    -> ts-offset(14)=00000010100000=160, block-len(10)=0000001110=14
        // Primary header (1 byte): F=0 | PT=5 -> 0x05 = 0_0000101
        let mut payload = vec![0x87, 0x02, 0x80, 0x0E, 0x05];
        let lpc = [0xA1u8; 14];
        let dvi4 = [0xB2u8; 84];
        payload.extend_from_slice(&lpc);
        payload.extend_from_slice(&dvi4);

        let packet = RedPacket::parse(&payload).expect("parse RFC 2198 §7 example");
        assert_eq!(packet.generation_count(), 1);
        let redundant = packet.redundant_blocks();
        assert_eq!(redundant[0].payload_type, 7);
        assert_eq!(redundant[0].timestamp_offset, 160);
        assert_eq!(redundant[0].data, &lpc[..]);
        assert_eq!(packet.primary().payload_type, 5);
        assert_eq!(packet.primary().timestamp_offset, 0);
        assert_eq!(packet.primary().data, &dvi4[..]);
    }

    #[test]
    fn builds_rfc2198_section7_example_byte_for_byte() {
        // The same logical packet built by RedBuilder must be byte-identical to the RFC 2198 §3
        // header layout above. Primary ts = 3000; the redundant generation is 160 units older.
        let lpc = [0xA1u8; 14];
        let dvi4 = [0xB2u8; 84];
        let generations = [RedGeneration {
            payload_type: 7,
            rtp_timestamp: 3000 - 160,
            data: &lpc,
        }];
        let builder = RedBuilder {
            primary_payload_type: 5,
            primary_rtp_timestamp: 3000,
            primary_data: &dvi4,
            redundant: &generations,
        };
        let mut out = Vec::new();
        let written = builder.write_into(&mut out).expect("build");

        let mut expected = vec![0x87, 0x02, 0x80, 0x0E, 0x05];
        expected.extend_from_slice(&lpc);
        expected.extend_from_slice(&dvi4);
        assert_eq!(out, expected);
        assert_eq!(written, expected.len());
        assert_eq!(builder.encoded_len().expect("len"), expected.len());
    }

    #[test]
    fn parses_two_redundant_generations_exact_triples() {
        // An RFC 4103-style T.140 packet: primary "C" plus two redundant generations "A" (oldest)
        // and "B" (newest), all on t140 PT 98, primary ts arbitrary; offsets 600 ms and 300 ms.
        //
        // redundant[0] header: F=1 | PT=98 | ts-offset=600 | block-len=1
        //   0xE2 = 1_1100010 -> F=1, PT=1100010=98
        //   0x09 0x60 0x01   -> ts-offset(14)=00001001011000=600, block-len(10)=0000000001=1
        // redundant[1] header: F=1 | PT=98 | ts-offset=300 | block-len=1
        //   0xE2 0x04 0xB0 0x01 -> ts-offset=00000100101100=300, block-len=1
        // primary header: F=0 | PT=98 -> 0x62
        // data blocks in header order: "A"(0x41) "B"(0x42) then primary "C"(0x43)
        let payload = [
            0xE2, 0x09, 0x60, 0x01, // redundant[0] header (offset 600, len 1)
            0xE2, 0x04, 0xB0, 0x01, // redundant[1] header (offset 300, len 1)
            0x62, // primary header, PT 98
            0x41, // redundant[0] data "A"
            0x42, // redundant[1] data "B"
            0x43, // primary data "C"
        ];
        let packet = RedPacket::parse(&payload).expect("parse two-redundant");
        let redundant = packet.redundant_blocks();
        assert_eq!(redundant.len(), 2);
        assert_eq!(
            (
                redundant[0].payload_type,
                redundant[0].timestamp_offset,
                redundant[0].data
            ),
            (98, 600, &b"A"[..])
        );
        assert_eq!(
            (
                redundant[1].payload_type,
                redundant[1].timestamp_offset,
                redundant[1].data
            ),
            (98, 300, &b"B"[..])
        );
        assert_eq!(
            (packet.primary().payload_type, packet.primary().data),
            (98, &b"C"[..])
        );
    }

    #[test]
    fn builds_two_redundant_generations_byte_for_byte() {
        // Byte-identical to the hand-decoded fixture above.
        let generations = [
            RedGeneration {
                payload_type: 98,
                rtp_timestamp: 1000 - 600,
                data: b"A",
            },
            RedGeneration {
                payload_type: 98,
                rtp_timestamp: 1000 - 300,
                data: b"B",
            },
        ];
        let builder = RedBuilder {
            primary_payload_type: 98,
            primary_rtp_timestamp: 1000,
            primary_data: b"C",
            redundant: &generations,
        };
        let mut out = Vec::new();
        builder.write_into(&mut out).expect("build");
        assert_eq!(
            out,
            [0xE2, 0x09, 0x60, 0x01, 0xE2, 0x04, 0xB0, 0x01, 0x62, 0x41, 0x42, 0x43]
        );
    }

    #[test]
    fn parses_primary_only_red_payload() {
        // A RED payload with no redundancy: just the 1-byte primary header + data.
        let payload = [0x62, 0x48, 0x69]; // PT 98, "Hi"
        let packet = RedPacket::parse(&payload).expect("parse primary-only");
        assert_eq!(packet.generation_count(), 0);
        assert!(packet.redundant_blocks().is_empty());
        assert_eq!(packet.primary().data, b"Hi");
    }

    #[test]
    fn parses_empty_primary_block() {
        // An idle keepalive (RFC 4103 §5.2): primary header with zero data.
        let payload = [0x62];
        let packet = RedPacket::parse(&payload).expect("parse empty primary");
        assert!(packet.primary().data.is_empty());
    }

    // ----- RED parse: error paths over untrusted bytes -----

    #[test]
    fn rejects_empty_payload() {
        assert!(matches!(RedPacket::parse(&[]), Err(RedError::Truncated)));
    }

    #[test]
    fn rejects_truncated_redundant_header() {
        // F=1 header needs 4 bytes; only 3 present.
        assert!(matches!(
            RedPacket::parse(&[0x87, 0x02, 0x80]),
            Err(RedError::Truncated)
        ));
    }

    #[test]
    fn rejects_missing_primary_header() {
        // A complete redundant header (F=1) with no following primary header byte.
        assert!(matches!(
            RedPacket::parse(&[0x87, 0x02, 0x80, 0x0E]),
            Err(RedError::Truncated)
        ));
    }

    #[test]
    fn rejects_block_length_exceeding_payload() {
        // Redundant header claims block-len=14 but only 5 data bytes follow the primary header.
        let payload = [0x87, 0x02, 0x80, 0x0E, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(matches!(
            RedPacket::parse(&payload),
            Err(RedError::BlockLengthExceedsPayload {
                length: 14,
                remaining: 5,
            })
        ));
    }

    #[test]
    fn rejects_more_than_max_redundant_blocks() {
        // MAX_RED_BLOCKS + 1 redundant headers (F=1) before any primary.
        let mut payload = Vec::new();
        for _ in 0..=MAX_RED_BLOCKS {
            // F=1, PT=0, offset=0, len=0
            payload.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        }
        payload.push(0x00); // primary header (never reached)
        assert!(matches!(
            RedPacket::parse(&payload),
            Err(RedError::TooManyBlocks {
                max: MAX_RED_BLOCKS
            })
        ));
    }

    #[test]
    fn parses_exactly_max_redundant_blocks() {
        // MAX_RED_BLOCKS redundant zero-length blocks + a primary must parse (boundary).
        let mut payload = Vec::new();
        for _ in 0..MAX_RED_BLOCKS {
            payload.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        }
        payload.push(0x62);
        payload.push(0x21); // primary "!"
        let packet = RedPacket::parse(&payload).expect("parse max blocks");
        assert_eq!(packet.generation_count(), MAX_RED_BLOCKS);
        assert_eq!(packet.primary().data, b"!");
    }

    // ----- RED build: error paths -----

    #[test]
    fn build_rejects_timestamp_offset_overflow() {
        // A generation newer than the primary yields a huge unsigned offset that overflows 14 bits.
        let generations = [RedGeneration {
            payload_type: 98,
            rtp_timestamp: 1000 + 1, // newer than primary
            data: b"x",
        }];
        let builder = RedBuilder {
            primary_payload_type: 98,
            primary_rtp_timestamp: 1000,
            primary_data: b"y",
            redundant: &generations,
        };
        let mut out = Vec::new();
        assert!(matches!(
            builder.write_into(&mut out),
            Err(RedError::TimestampOffsetTooLarge { .. })
        ));
    }

    #[test]
    fn build_rejects_block_length_overflow() {
        let big = vec![0u8; MAX_BLOCK_LENGTH + 1];
        let generations = [RedGeneration {
            payload_type: 98,
            rtp_timestamp: 1000 - 100,
            data: &big,
        }];
        let builder = RedBuilder {
            primary_payload_type: 98,
            primary_rtp_timestamp: 1000,
            primary_data: b"y",
            redundant: &generations,
        };
        let mut out = Vec::new();
        assert_eq!(
            builder.write_into(&mut out),
            Err(RedError::BlockLengthTooLarge {
                length: MAX_BLOCK_LENGTH + 1
            })
        );
    }

    #[test]
    fn build_rejects_too_many_generations() {
        let data = b"a";
        let generations: Vec<RedGeneration> = (0..=MAX_RED_BLOCKS)
            .map(|index| RedGeneration {
                payload_type: 98,
                rtp_timestamp: 10_000 - index as u32,
                data,
            })
            .collect();
        let builder = RedBuilder {
            primary_payload_type: 98,
            primary_rtp_timestamp: 10_000,
            primary_data: b"z",
            redundant: &generations,
        };
        let mut out = Vec::new();
        assert_eq!(
            builder.write_into(&mut out),
            Err(RedError::TooManyBlocks {
                max: MAX_RED_BLOCKS
            })
        );
    }

    // ----- RED build/parse roundtrip -----

    #[test]
    fn build_then_parse_roundtrips_offsets_and_data() {
        let payload = build_red(5000, b"world", &[(5000 - 400, b"hel"), (5000 - 200, b"lo")]);
        let packet = RedPacket::parse(&payload).expect("parse");
        let redundant = packet.redundant_blocks();
        assert_eq!(redundant.len(), 2);
        assert_eq!(
            (redundant[0].timestamp_offset, redundant[0].data),
            (400, &b"hel"[..])
        );
        assert_eq!(
            (redundant[1].timestamp_offset, redundant[1].data),
            (200, &b"lo"[..])
        );
        assert_eq!(packet.primary().data, b"world");
    }

    // ----- T.140 reassembly -----

    #[test]
    fn first_packet_delivers_primary_only() {
        let mut reassembler = T140Reassembler::new();
        // First packet carries redundant history that must NOT be replayed on join.
        let payload = build_red(1000, b"C", &[(400, b"A"), (700, b"B")]);
        let output = reassembler
            .on_packet(10, 1000, &payload, true)
            .expect("packet");
        assert_eq!(output.text, "C");
        assert_eq!(output.missing_markers, 0);
        assert_eq!(output.recovered_from_redundancy, 0);
        assert_eq!(reassembler.next_expected_sequence(), Some(11));
        assert_eq!(reassembler.highest_timestamp(), Some(1000));
    }

    #[test]
    fn bare_t140_packets_reassemble() {
        // is_red = false: the payload is raw T.140 text on the t140 PT.
        let mut reassembler = T140Reassembler::new();
        assert_eq!(
            reassembler
                .on_packet(1, 1000, b"Hel", false)
                .expect("p1")
                .text,
            "Hel"
        );
        assert_eq!(
            reassembler
                .on_packet(2, 1100, b"lo", false)
                .expect("p2")
                .text,
            "lo"
        );
    }

    #[test]
    fn in_order_stream_never_double_emits_redundancy() {
        // Each packet repeats the previous generation as redundancy; delivered-once dedup means only
        // the primary of each packet is emitted.
        let mut reassembler = T140Reassembler::new();
        let p1 = build_red(1000, b"H", &[]);
        let p2 = build_red(1100, b"e", &[(1000, b"H")]);
        let p3 = build_red(1200, b"y", &[(1000, b"H"), (1100, b"e")]);
        assert_eq!(
            reassembler.on_packet(1, 1000, &p1, true).expect("p1").text,
            "H"
        );
        assert_eq!(
            reassembler.on_packet(2, 1100, &p2, true).expect("p2").text,
            "e"
        );
        assert_eq!(
            reassembler.on_packet(3, 1200, &p3, true).expect("p3").text,
            "y"
        );
    }

    #[test]
    fn recovers_single_lost_packet_from_redundancy() {
        // Stream "Help": seq 1 H, 2 e, 3 l, 4 p, each packet carrying the prior two generations.
        // Packet 3 is lost; packet 4's redundancy recovers "l" (RFC 4103 §4.2 / §5).
        let mut reassembler = T140Reassembler::new();
        let p1 = build_red(1000, b"H", &[]);
        let p2 = build_red(1100, b"e", &[(1000, b"H")]);
        // p3 lost.
        let p4 = build_red(1300, b"p", &[(1100, b"e"), (1200, b"l")]);
        assert_eq!(
            reassembler.on_packet(1, 1000, &p1, true).expect("p1").text,
            "H"
        );
        assert_eq!(
            reassembler.on_packet(2, 1100, &p2, true).expect("p2").text,
            "e"
        );
        let recovered = reassembler.on_packet(4, 1300, &p4, true).expect("p4");
        assert_eq!(recovered.text, "lp");
        assert_eq!(recovered.recovered_from_redundancy, 1);
        assert_eq!(recovered.missing_markers, 0);
    }

    #[test]
    fn marks_unrecoverable_gap_once_with_replacement_character() {
        // seq 1 H, 2 e, then 3/4/5 lost; seq 6 carries only generations 4 and 5. Generation 3 is
        // beyond the redundancy window → one U+FFFD marker (RFC 4103 §5.3), then 4 and 5 recovered,
        // then primary 6.
        let mut reassembler = T140Reassembler::new();
        let p1 = build_red(1000, b"H", &[]);
        let p2 = build_red(1100, b"e", &[(1000, b"H")]);
        let p6 = build_red(1500, b"!", &[(1300, b"?"), (1400, b".")]);
        reassembler.on_packet(1, 1000, &p1, true).expect("p1");
        reassembler.on_packet(2, 1100, &p2, true).expect("p2");
        let output = reassembler.on_packet(6, 1500, &p6, true).expect("p6");
        assert_eq!(output.text, "\u{FFFD}?.!");
        assert_eq!(output.missing_markers, 1);
        assert_eq!(output.recovered_from_redundancy, 2);
    }

    #[test]
    fn bare_stream_marks_each_loss_once() {
        // No redundancy at all: a single lost packet becomes one marker before the next primary.
        let mut reassembler = T140Reassembler::new();
        assert_eq!(
            reassembler
                .on_packet(1, 1000, b"A", false)
                .expect("p1")
                .text,
            "A"
        );
        // seq 2 lost; seq 3 arrives bare → marker + "C".
        let output = reassembler.on_packet(3, 1200, b"C", false).expect("p3");
        assert_eq!(output.text, "\u{FFFD}C");
        assert_eq!(output.missing_markers, 1);
    }

    #[test]
    fn large_sequence_gap_stays_bounded() {
        // A big forward jump with no redundancy must coalesce to ONE marker, not thousands.
        let mut reassembler = T140Reassembler::new();
        reassembler.on_packet(1, 1000, b"A", false).expect("p1");
        let output = reassembler
            .on_packet(20_000, 2000, b"Z", false)
            .expect("jump");
        assert_eq!(output.text, "\u{FFFD}Z");
        assert_eq!(output.missing_markers, 1);
    }

    #[test]
    fn duplicate_and_reordered_packets_emit_nothing() {
        let mut reassembler = T140Reassembler::new();
        let p1 = build_red(1000, b"A", &[]);
        let p2 = build_red(1100, b"B", &[(1000, b"A")]);
        assert_eq!(
            reassembler.on_packet(1, 1000, &p1, true).expect("p1").text,
            "A"
        );
        assert_eq!(
            reassembler.on_packet(2, 1100, &p2, true).expect("p2").text,
            "B"
        );
        // Duplicate of seq 2.
        assert_eq!(
            reassembler.on_packet(2, 1100, &p2, true).expect("dup").text,
            ""
        );
        // Reordered old seq 1.
        assert_eq!(
            reassembler.on_packet(1, 1000, &p1, true).expect("old").text,
            ""
        );
    }

    #[test]
    fn completes_two_byte_utf8_split_across_packets() {
        // 'é' = U+00E9 = [0xC3, 0xA9] split across two bare packets (a sender violating §3.3; we
        // tolerate it rather than emit an invalid unit).
        let mut reassembler = T140Reassembler::new();
        assert_eq!(
            reassembler
                .on_packet(1, 1000, &[0xC3], false)
                .expect("lead")
                .text,
            ""
        );
        assert_eq!(
            reassembler
                .on_packet(2, 1100, &[0xA9], false)
                .expect("tail")
                .text,
            "é"
        );
    }

    #[test]
    fn completes_four_byte_utf8_split_across_packets() {
        // '😀' = U+1F600 = [0xF0, 0x9F, 0x98, 0x80] split 2 + 2.
        let mut reassembler = T140Reassembler::new();
        assert_eq!(
            reassembler
                .on_packet(1, 1000, &[0xF0, 0x9F], false)
                .expect("lead")
                .text,
            ""
        );
        assert_eq!(
            reassembler
                .on_packet(2, 1100, &[0x98, 0x80], false)
                .expect("tail")
                .text,
            "😀"
        );
    }

    #[test]
    fn invalid_byte_in_block_becomes_replacement_and_decoding_continues() {
        // 0xFF is never valid UTF-8: it is replaced and the surrounding ASCII still decodes.
        let mut reassembler = T140Reassembler::new();
        let output = reassembler
            .on_packet(1, 1000, &[b'a', 0xFF, b'b'], false)
            .expect("p");
        assert_eq!(output.text, "a\u{FFFD}b");
    }

    #[test]
    fn recovers_across_sequence_number_wraparound() {
        // Highest seq near u16::MAX, then wrap through 0 with the lost generation recovered.
        let mut reassembler = T140Reassembler::new();
        let p_first = build_red(1000, b"X", &[]);
        // seq 65534 establishes the stream; expected becomes 65535.
        assert_eq!(
            reassembler
                .on_packet(65534, 1000, &p_first, true)
                .expect("first")
                .text,
            "X"
        );
        // seq 65535 is lost; seq 0 (wrapped) recovers it from redundancy.
        let p_wrap = build_red(1200, b"Z", &[(1100, b"Y")]);
        let output = reassembler.on_packet(0, 1200, &p_wrap, true).expect("wrap");
        assert_eq!(output.text, "YZ");
        assert_eq!(output.recovered_from_redundancy, 1);
        assert_eq!(reassembler.next_expected_sequence(), Some(1));
    }

    #[test]
    fn full_lossy_stream_reconstructs_expected_text() {
        // "Hello": drop packet 3 ('l'), recover it from packet 4's redundancy (2 generations).
        let mut reassembler = T140Reassembler::new();
        let packets = [
            (1u16, 1000u32, build_red(1000, b"H", &[])),
            (2, 1100, build_red(1100, b"e", &[(1000, b"H")])),
            (
                3,
                1200,
                build_red(1200, b"l", &[(1000, b"H"), (1100, b"e")]),
            ),
            (
                4,
                1300,
                build_red(1300, b"l", &[(1100, b"e"), (1200, b"l")]),
            ),
            (
                5,
                1400,
                build_red(1400, b"o", &[(1200, b"l"), (1300, b"l")]),
            ),
        ];
        let mut assembled = String::new();
        for (index, (sequence, timestamp, payload)) in packets.iter().enumerate() {
            if index == 2 {
                continue; // packet 3 lost on the wire
            }
            let output = reassembler
                .on_packet(*sequence, *timestamp, payload, true)
                .expect("p");
            assembled.push_str(output.text);
        }
        assert_eq!(assembled, "Hello");
    }

    // ----- Property tests -----

    proptest! {
        /// RED build → parse round-trips every block's (PT, offset, data) exactly, over arbitrary
        /// valid block sets within the RFC 2198 §3 field widths.
        #[test]
        fn prop_red_build_parse_roundtrip(
            primary_pt in 0u8..=127,
            primary_ts in 0u32..=1_000_000,
            primary_data in proptest::collection::vec(any::<u8>(), 0..300),
            generations in proptest::collection::vec(
                (0u8..=127, 0u32..=MAX_TIMESTAMP_OFFSET, proptest::collection::vec(any::<u8>(), 0..MAX_BLOCK_LENGTH)),
                0..8,
            ),
        ) {
            let gens: Vec<RedGeneration> = generations
                .iter()
                .map(|(pt, offset, data)| RedGeneration {
                    payload_type: *pt,
                    // Offset is (primary_ts - gen_ts); pick gen_ts so the offset equals `offset`.
                    rtp_timestamp: primary_ts.wrapping_sub(*offset),
                    data,
                })
                .collect();
            let builder = RedBuilder {
                primary_payload_type: primary_pt,
                primary_rtp_timestamp: primary_ts,
                primary_data: &primary_data,
                redundant: &gens,
            };
            let mut out = Vec::new();
            builder.write_into(&mut out).expect("build");
            let packet = RedPacket::parse(&out).expect("parse");

            prop_assert_eq!(packet.generation_count(), gens.len());
            for (parsed, (pt, offset, data)) in packet.redundant_blocks().iter().zip(generations.iter()) {
                prop_assert_eq!(parsed.payload_type, pt & 0x7F);
                prop_assert_eq!(parsed.timestamp_offset, *offset);
                prop_assert_eq!(parsed.data, data.as_slice());
            }
            prop_assert_eq!(packet.primary().payload_type, primary_pt & 0x7F);
            prop_assert_eq!(packet.primary().data, primary_data.as_slice());
        }

        /// The parser never panics on arbitrary bytes (fuzz-adjacent invariant).
        #[test]
        fn prop_parse_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = RedPacket::parse(&data);
        }

        /// The reassembler survives arbitrary loss / duplicate / reorder schedules: it never panics,
        /// its per-packet output is bounded, and total emitted characters stay proportional to the
        /// input (no unbounded U+FFFD amplification from a hostile sequence jump).
        #[test]
        fn prop_reassembler_bounded_over_arbitrary_schedule(
            steps in proptest::collection::vec(
                (any::<u16>(), 0u32..=2_000_000, proptest::collection::vec(any::<u8>(), 0..8)),
                0..200,
            ),
        ) {
            let mut reassembler = T140Reassembler::new();
            let mut total_chars = 0usize;
            for (sequence, timestamp, text) in &steps {
                // Wrap each step as a bare T.140 packet (arbitrary bytes decode-or-mark).
                let output = reassembler.on_packet(*sequence, *timestamp, text, false).expect("bare never errors");
                let chars = output.text.chars().count();
                // Each packet emits at most: one marker + the primary's characters (<= its bytes).
                prop_assert!(chars <= text.len() + 1);
                total_chars += chars;
            }
            // Across the whole schedule, output is bounded by input bytes + one marker per packet.
            let input_bytes: usize = steps.iter().map(|(_, _, text)| text.len()).sum();
            prop_assert!(total_chars <= input_bytes + steps.len());
        }
    }
}
