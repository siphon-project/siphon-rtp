//! The ITU-T G.192 serial bitstream format the TS 26.444 vectors are stored in.
//!
//! Each frame is a little-endian 16-bit word stream: a synchronisation word that doubles as the
//! bad-frame indicator, a length word giving the number of bits, then one word per bit (`0x0081` for
//! a one, `0x007F` for a zero). This module is the container only. What the reference does *with* a
//! frame once it is read (the SID / NO_DATA / bad-frame reception handling in `read_indices_fx`) is
//! decoder state and lives with the decoder.

use super::frame::FrameKind;
use crate::CodecError;

/// Sync word of a frame received intact (`SYNC_GOOD_FRAME`).
pub const SYNC_GOOD: u16 = 0x6B21;
/// Sync word of a frame received damaged (`SYNC_BAD_FRAME`); its bits are still present.
pub const SYNC_BAD: u16 = 0x6B20;
/// A one bit (`G192_BIN1`). The reference reads every other value as a zero.
pub const BIT_ONE: u16 = 0x0081;
/// A zero bit (`G192_BIN0`).
pub const BIT_ZERO: u16 = 0x007F;

/// One frame of a G.192 stream, borrowing its bit words from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct G192Frame<'a> {
    /// `false` when the sync word marked the frame as damaged.
    pub good: bool,
    /// What the frame's size says it carries.
    pub kind: FrameKind,
    words: &'a [u8],
}

impl G192Frame<'_> {
    /// Number of bits in the frame.
    #[must_use]
    pub fn bit_count(&self) -> usize {
        self.words.len() / 2
    }

    /// Write the frame's bits, one per byte (0 or 1), into `out`; returns how many were written.
    ///
    /// # Errors
    /// [`CodecError::OutputTooSmall`] when `out` cannot hold [`Self::bit_count`] bits.
    pub fn unpack_bits(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let count = self.bit_count();
        let have = out.len();
        let slots = out.get_mut(..count).ok_or(CodecError::OutputTooSmall {
            needed: count,
            have,
        })?;
        let (words, _) = self.words.as_chunks::<2>();
        for (slot, word) in slots.iter_mut().zip(words) {
            *slot = u8::from(u16::from_le_bytes(*word) == BIT_ONE);
        }
        Ok(count)
    }
}

/// Iterator over the frames of a G.192 byte stream.
#[derive(Debug, Clone)]
pub struct G192Reader<'a> {
    rest: &'a [u8],
}

impl<'a> G192Reader<'a> {
    /// Read frames from `bytes`, a whole G.192 file.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], CodecError> {
        if self.rest.len() < count {
            self.rest = &[];
            return Err(CodecError::Malformed("G.192 stream truncated mid-frame"));
        }
        let (head, tail) = self.rest.split_at(count);
        self.rest = tail;
        Ok(head)
    }

    fn word(&mut self) -> Result<u16, CodecError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn frame(&mut self) -> Result<G192Frame<'a>, CodecError> {
        let good = match self.word()? {
            SYNC_GOOD => true,
            SYNC_BAD => false,
            _ => {
                self.rest = &[];
                return Err(CodecError::Malformed(
                    "G.192 frame does not start with a sync word",
                ));
            }
        };
        let bits = usize::from(self.word()?);
        let Some(kind) = FrameKind::from_bits(bits) else {
            self.rest = &[];
            return Err(CodecError::Malformed(
                "G.192 frame length is not an EVS frame size",
            ));
        };
        let words = self.take(bits * 2)?;
        Ok(G192Frame { good, kind, words })
    }
}

impl<'a> Iterator for G192Reader<'a> {
    type Item = Result<G192Frame<'a>, CodecError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        Some(self.frame())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::frame::PrimaryRate;

    fn frame_bytes(sync: u16, bits: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&sync.to_le_bytes());
        bytes.extend_from_slice(&(bits.len() as u16).to_le_bytes());
        for &bit in bits {
            bytes.extend_from_slice(&(if bit == 1 { BIT_ONE } else { BIT_ZERO }).to_le_bytes());
        }
        bytes
    }

    #[test]
    fn reads_good_bad_and_empty_frames_in_order() {
        let sid: Vec<u8> = (0..48).map(|index| (index % 3 == 0) as u8).collect();
        let speech: Vec<u8> = (0..264).map(|index| (index % 2) as u8).collect();
        let mut stream = frame_bytes(SYNC_GOOD, &speech);
        stream.extend(frame_bytes(SYNC_BAD, &sid));
        stream.extend(frame_bytes(SYNC_GOOD, &[]));

        let frames: Vec<_> = G192Reader::new(&stream)
            .collect::<Result<_, _>>()
            .expect("valid stream");
        assert_eq!(frames.len(), 3);
        assert!(frames[0].good);
        assert_eq!(frames[0].kind, FrameKind::Primary(PrimaryRate::Rate13200));
        assert!(!frames[1].good);
        assert_eq!(frames[1].kind, FrameKind::PrimarySid);
        assert_eq!(frames[2].kind, FrameKind::NoData);

        let mut bits = [0u8; FrameKind::MAX_BITS];
        assert_eq!(frames[0].unpack_bits(&mut bits), Ok(264));
        assert_eq!(&bits[..264], speech.as_slice());
        assert_eq!(frames[1].unpack_bits(&mut bits), Ok(48));
        assert_eq!(&bits[..48], sid.as_slice());
    }

    #[test]
    fn any_word_but_the_one_marker_reads_as_zero() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&SYNC_GOOD.to_le_bytes());
        stream.extend_from_slice(&35u16.to_le_bytes());
        for index in 0..35u16 {
            let word = if index == 0 { BIT_ONE } else { index };
            stream.extend_from_slice(&word.to_le_bytes());
        }
        let frame = G192Reader::new(&stream)
            .next()
            .expect("one frame")
            .expect("valid frame");
        let mut bits = [9u8; 35];
        assert_eq!(frame.unpack_bits(&mut bits), Ok(35));
        assert_eq!(bits[0], 1);
        assert!(bits[1..].iter().all(|&bit| bit == 0));
    }

    #[test]
    fn a_frame_size_no_evs_mode_has_is_refused() {
        let stream = frame_bytes(SYNC_GOOD, &[0; 100]);
        let error = G192Reader::new(&stream).next().expect("one item");
        assert_eq!(
            error,
            Err(CodecError::Malformed(
                "G.192 frame length is not an EVS frame size"
            ))
        );
    }

    #[test]
    fn an_unknown_sync_word_ends_the_stream_with_an_error() {
        let mut reader = G192Reader::new(&[0x34, 0x12, 0, 0]);
        assert!(matches!(reader.next(), Some(Err(CodecError::Malformed(_)))));
        assert_eq!(reader.next(), None);
    }

    #[test]
    fn a_truncated_frame_is_an_error_and_not_a_panic() {
        let stream = frame_bytes(SYNC_GOOD, &[1; 264]);
        for cut in 1..stream.len() {
            let results: Vec<_> = G192Reader::new(&stream[..cut]).collect();
            assert_eq!(results.len(), 1, "cut at {cut}");
            assert!(results[0].is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn unpack_refuses_a_buffer_too_small_for_the_frame() {
        let stream = frame_bytes(SYNC_GOOD, &[1; 264]);
        let frame = G192Reader::new(&stream)
            .next()
            .expect("one frame")
            .expect("valid frame");
        let mut small = [0u8; 100];
        assert_eq!(
            frame.unpack_bits(&mut small),
            Err(CodecError::OutputTooSmall {
                needed: 264,
                have: 100
            })
        );
    }
}
