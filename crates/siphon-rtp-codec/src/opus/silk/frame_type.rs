//! Frame type — the joint signal-type / quantization-offset-type symbol (RFC 6716 §4.2.7.3; libopus
//! `decode_indices.c:48-57`).
//!
//! One symbol per SILK frame, decoded with one of **two** PDFs picked by whether the frame is active.
//! The two PDFs cover disjoint symbol ranges (0..=1 inactive, 2..=5 active), so picking the wrong one
//! does not merely give a wrong answer — it reads a different number of bits and desynchronises the
//! rest of the frame.
//!
//! "Active" is *not* the same as "voiced": it means the frame's VAD flag was set, or the frame is an
//! LBRR frame (which carries no VAD flag of its own and is active by definition, RFC 6716 §4.2.5).

use crate::opus::range_coder::RangeDecoder;
use crate::opus::silk::tables::{TYPE_OFFSET_NO_VAD_ICDF, TYPE_OFFSET_VAD_ICDF};
use crate::opus::silk::types::FrameType;
use crate::CodecError;

/// `ftb` for every SILK ICDF symbol: total frequency 256.
const ICDF_FTB: u32 = 8;

/// Offset added to the active-frame symbol to reach RFC 6716 Table 10's numbering
/// (`decode_indices.c:52`). The inactive PDF needs no offset.
const ACTIVE_SYMBOL_OFFSET: usize = 2;

/// Decode the frame type (RFC 6716 §4.2.7.3).
///
/// `active` is the C's `decode_LBRR || psDec->VAD_flags[FrameIndex]` — see
/// [`super::header::ChannelFlags::is_active`].
///
/// Cannot fail on any input: both PDFs are total, so the decoded symbol is always in range for its
/// table. The `Result` is kept because [`FrameType`] owns the range invariant, and a table typo here
/// must surface as an error rather than a silently wrong signal type.
pub fn decode_frame_type(
    decoder: &mut RangeDecoder<'_>,
    active: bool,
) -> Result<FrameType, CodecError> {
    let symbol = if active {
        decoder.dec_icdf(&TYPE_OFFSET_VAD_ICDF, ICDF_FTB) + ACTIVE_SYMBOL_OFFSET
    } else {
        decoder.dec_icdf(&TYPE_OFFSET_NO_VAD_ICDF, ICDF_FTB)
    };
    let symbol = u8::try_from(symbol)
        .map_err(|_| CodecError::Malformed("silk: frame type symbol out of range"))?;
    FrameType::from_symbol(symbol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::RangeEncoder;
    use crate::opus::silk::types::{QuantOffsetType, SignalType};

    fn encode_frame_type(symbol: usize, active: bool, buffer: &mut [u8]) {
        let mut encoder = RangeEncoder::new(buffer);
        if active {
            encoder.enc_icdf(
                symbol - ACTIVE_SYMBOL_OFFSET,
                &TYPE_OFFSET_VAD_ICDF,
                ICDF_FTB,
            );
        } else {
            encoder.enc_icdf(symbol, &TYPE_OFFSET_NO_VAD_ICDF, ICDF_FTB);
        }
        encoder.done();
        assert!(!encoder.error());
    }

    /// An inactive frame can only be frame type 0 or 1 — inactive with a low or high quantization
    /// offset (RFC 6716 Table 9 "Inactive" row, Table 10).
    #[test]
    fn inactive_frames_decode_types_0_and_1() {
        for (symbol, offset) in [(0usize, QuantOffsetType::Low), (1, QuantOffsetType::High)] {
            let mut buffer = [0u8; 32];
            encode_frame_type(symbol, false, &mut buffer);
            let mut decoder = RangeDecoder::new(&buffer);
            let frame_type = decode_frame_type(&mut decoder, false).expect("valid");
            assert_eq!(frame_type.symbol() as usize, symbol);
            assert_eq!(frame_type.signal_type(), SignalType::Inactive);
            assert_eq!(frame_type.quant_offset_type(), offset);
        }
    }

    /// An active frame spans types 2..=5 — unvoiced/voiced × low/high offset.
    #[test]
    fn active_frames_decode_types_2_through_5() {
        for (symbol, signal, offset) in [
            (2usize, SignalType::Unvoiced, QuantOffsetType::Low),
            (3, SignalType::Unvoiced, QuantOffsetType::High),
            (4, SignalType::Voiced, QuantOffsetType::Low),
            (5, SignalType::Voiced, QuantOffsetType::High),
        ] {
            let mut buffer = [0u8; 32];
            encode_frame_type(symbol, true, &mut buffer);
            let mut decoder = RangeDecoder::new(&buffer);
            let frame_type = decode_frame_type(&mut decoder, true).expect("valid");
            assert_eq!(frame_type.symbol() as usize, symbol);
            assert_eq!(frame_type.signal_type(), signal);
            assert_eq!(frame_type.quant_offset_type(), offset);
        }
    }

    /// An inactive frame can never come out voiced, and an active frame can never come out inactive —
    /// the disjoint symbol ranges guarantee it whatever the payload says.
    #[test]
    fn the_two_pdfs_cover_disjoint_ranges() {
        for seed in 0u32..600 {
            let payload: Vec<u8> = (0..4)
                .map(|k| (seed.wrapping_mul(2_654_435_761).wrapping_add(k) >> 13) as u8)
                .collect();

            let mut decoder = RangeDecoder::new(&payload);
            let inactive = decode_frame_type(&mut decoder, false).expect("total pdf");
            assert!(inactive.symbol() <= 1);
            assert_eq!(inactive.signal_type(), SignalType::Inactive);

            let mut decoder = RangeDecoder::new(&payload);
            let active = decode_frame_type(&mut decoder, true).expect("total pdf");
            assert!((2..=5).contains(&active.symbol()));
            assert_ne!(active.signal_type(), SignalType::Inactive);
        }
    }

    /// Decoding an active frame with the inactive PDF (or vice versa) leaves the range decoder in a
    /// different state, so every later symbol in the frame shifts. This is why "active" must come from
    /// the VAD/LBRR flags and can never be guessed from the payload. Measured in 1/8-bit units
    /// (`tell_frac`), since the two symbols can round to the same whole bit count.
    #[test]
    fn choosing_the_wrong_pdf_desynchronises_the_decoder() {
        let mut buffer = [0u8; 32];
        encode_frame_type(4, true, &mut buffer);
        let mut correct = RangeDecoder::new(&buffer);
        let frame_type = decode_frame_type(&mut correct, true).expect("valid");
        assert_eq!(frame_type.symbol(), 4);
        let mut wrong = RangeDecoder::new(&buffer);
        let _ = decode_frame_type(&mut wrong, false).expect("total pdf");
        assert_ne!(
            correct.tell_frac(),
            wrong.tell_frac(),
            "the two PDFs are not interchangeable"
        );
    }

    #[test]
    fn arbitrary_payloads_never_panic() {
        for seed in 0u32..3000 {
            let length = seed % 4;
            let payload: Vec<u8> = (0..length)
                .map(|k| (seed.wrapping_mul(40_503).wrapping_add(k) >> 3) as u8)
                .collect();
            for active in [false, true] {
                let mut decoder = RangeDecoder::new(&payload);
                let frame_type = decode_frame_type(&mut decoder, active).expect("total pdf");
                assert!(frame_type.symbol() <= 5);
            }
        }
    }
}
