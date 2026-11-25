//! Decoding of the harmonic-model parameters of the TCX arithmetic coder
//! (TS 26.442 `lib_dec/ari_hm_dec.c`; TS 26.445 §6.2.2.2.4).
//!
//! `Overflow` and `Carry`: nothing in this file reads them.

pub mod decode;
use crate::evs::cnst::{KLTPHMFLAG, KLTPHMFRACTIONALRESOLUTION, KLTPHMGAINTHR, KTCXHMNUMGAINBITS};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{NUMRATIOBITS, QGAINS};
use crate::itu::basic_ops::{add, mult_r, shl, sub};

/// `NumRatioBits[bandwidth][ltp_pitch_index]`. The reference indexes unchecked; the pitch index
/// is at most 16 for any lag the decoder keeps, and a 0/1 bandwidth selects the row. Anything else
/// (unreachable) reads as 0 bits.
fn num_ratio_bits(bandwidth: i16, ltp_pitch_index: i16) -> i16 {
    usize::try_from(bandwidth)
        .ok()
        .and_then(|bandwidth| NUMRATIOBITS.get(bandwidth))
        .zip(usize::try_from(ltp_pitch_index).ok())
        .and_then(|(row, index)| row.get(index))
        .copied()
        .unwrap_or(0)
}

/// `DecodeIndex`: read the periodicity index of the harmonic model into `periodicity_index`;
/// returns the number of bits it took.
pub fn decode_index(st: &mut DecoderState, bandwidth: i16, periodicity_index: &mut i16) -> i16 {
    if st.tcx_hm_ltp_pitch_lag > 0 && sub(st.tcxltp_gain, KLTPHMGAINTHR) > 0 {
        let ltp_pitch_index = sub(
            mult_r(
                st.tcx_hm_ltp_pitch_lag,
                1 << (15 - KLTPHMFRACTIONALRESOLUTION),
            ),
            2,
        );
        let bits = num_ratio_bits(bandwidth, ltp_pitch_index);

        *periodicity_index = KLTPHMFLAG;
        *periodicity_index |= get_next_indice(st, bits) as i16;
        *periodicity_index = add(*periodicity_index, 1);
        *periodicity_index |= shl(ltp_pitch_index, 9);

        bits
    } else {
        *periodicity_index = get_next_indice(st, 8) as i16;
        8
    }
}

/// `tcx_hm_dequantize_gain`: the harmonic-model gain (Q11) of index `gain_idx` for the coder type
/// (0 generic, 1 voiced). Returns `true` for an index out of range (a bit error), with a zero
/// gain.
pub fn tcx_hm_dequantize_gain(coder_type: i16, gain_idx: i16, gain: &mut i16) -> bool {
    // safety check in case of bit errors
    if !(0 <= gain_idx && sub(gain_idx, 1 << KTCXHMNUMGAINBITS) < 0) {
        *gain = 0;
        return true;
    }

    // The reference asserts 0 <= coder_type <= 1.
    *gain = QGAINS[usize::from(coder_type != 0)][gain_idx as usize];

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gain_index_selects_the_row_by_coder_type() {
        let mut gain = 0;
        assert!(!tcx_hm_dequantize_gain(0, 0, &mut gain));
        assert_eq!(gain, 1536);
        assert!(!tcx_hm_dequantize_gain(1, 3, &mut gain));
        assert_eq!(gain, 20480);
    }

    #[test]
    fn gain_index_out_of_range_is_a_bit_error() {
        let mut gain = 77;
        assert!(tcx_hm_dequantize_gain(1, 4, &mut gain));
        assert_eq!(gain, 0);
        assert!(tcx_hm_dequantize_gain(1, -1, &mut gain));
    }

    #[test]
    fn decode_index_reads_eight_bits_without_a_ltp_lag() {
        let mut st = Box::new(DecoderState::zeroed());
        st.total_num_bits = 64;
        st.bit_stream[..8].copy_from_slice(&[1, 0, 1, 0, 0, 1, 1, 1]);
        let mut index = 0;
        assert_eq!(decode_index(&mut st, 1, &mut index), 8);
        assert_eq!(index, 0b1010_0111);
    }
}
