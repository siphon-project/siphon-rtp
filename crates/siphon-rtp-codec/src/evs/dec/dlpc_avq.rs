//! Variable bit-rate multiple LPC un-quantizer and the reading of its indices (TS 26.442
//! `lib_dec/dlpc_avq.c`; TS 26.445 §6.1.1.1).

use crate::evs::cnst::{M, NB_SPHERE};
use crate::evs::com::bitstream::{get_next_indice, get_next_indice_1};
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::vlpc_1st_dec::vlpc_1st_dec;
use crate::evs::dec::vlpc_2st_dec::vlpc_2st_dec;
use crate::itu::basic_ops::{add, shl, sub};

/// `M` as an index.
const MU: usize = M as usize;

/// `dlpc_avq`: dequantise `numlpc` (1 or 2) LPC vectors from the parameters `index` into
/// `lsf_q` (`M` values, or `2·M` with the intermediate LPC first and the last at `M`); returns
/// the number of parameters used. The last LPC is a first-stage absolute vector plus an
/// algebraic-VQ refinement; an intermediate one (512 framing) is either the same or a refinement
/// of the last.
pub fn dlpc_avq(index: &[i16], lsf_q: &mut [i16], numlpc: i16, sr_core: i32) -> i16 {
    // Last LPC index
    let last = if sub(numlpc, 1) != 0 { MU } else { 0 };

    let mut p: usize = 0;

    // Decode last LPC
    lsf_q[last..last + MU].fill(0);
    vlpc_1st_dec(index[p], &mut lsf_q[last..]);
    p += 1;
    vlpc_2st_dec(&mut lsf_q[last..], &index[p..], 0, sr_core);
    let nbi = add(2, add(index[p], index[p + 1]));
    p += nbi as usize;

    // Decode intermediate LPC (512 framing)
    if sub(numlpc, 2) == 0 {
        let q_type = index[p];
        p += 1;

        if q_type == 0 {
            lsf_q[..MU].fill(0);
            vlpc_1st_dec(index[p], &mut lsf_q[..MU]);
            p += 1;
            vlpc_2st_dec(&mut lsf_q[..MU], &index[p..], 0, sr_core);
        } else if sub(q_type, 1) == 0 {
            lsf_q.copy_within(MU..2 * MU, 0);
            vlpc_2st_dec(&mut lsf_q[..MU], &index[p..], 3, sr_core);
        }
        let nbi = add(2, add(index[p], index[p + 1]));
        p += nbi as usize;
    }

    p as i16
}

/// `unary_decode`: read a unary code (`0` ends it; the stop bit counts) into `ind`: the number of
/// ones, plus one if there were any. Returns the number of bits read.
fn unary_decode(st: &mut DecoderState, ind: &mut i16) -> i16 {
    let start_bit_pos = st.next_bit_pos;

    // Index bits
    *ind = 0;
    while get_next_indice_1(st) != 0 && st.ber_detect == 0 {
        *ind = add(*ind, 1);
    }

    if *ind != 0 {
        *ind = add(*ind, 1);
    }

    sub(st.next_bit_pos, start_bit_pos)
}

/// `pack4bits`: read `nbits` bits as 4-bit words into `prm`; returns the number of words.
fn pack4bits(nbits: i16, st: &mut DecoderState, prm: &mut [i16]) -> i16 {
    let mut nbits = nbits;
    let mut i: usize = 0;

    while nbits > 4 {
        prm[i] = get_next_indice(st, 4) as i16;
        i += 1;
        nbits -= 4;
    }
    prm[i] = get_next_indice(st, nbits) as i16;
    i += 1;

    i as i16
}

/// `decode_lpc_avq`: read the LPC parameters of `numlpc` vectors from the bitstream into
/// `param_lpc` (the quantiser type of every vector after the first, the 8-bit first-stage index of
/// an absolute one, the two codebook numbers and the 4-bit words of the algebraic VQ); returns
/// the number of bits read. `param_lpc` holds `NPRM_LPC_NEW` = 136 values, enough for any frame
/// (a codebook number past `NB_SPHERE` is a bit error and is zeroed).
pub fn decode_lpc_avq(st: &mut DecoderState, numlpc: i16, param_lpc: &mut [i16]) -> i16 {
    let start_bit_pos = st.next_bit_pos;
    let mut j: usize = 0;

    for k in 0..numlpc.max(0) {
        // Decode quantizer type
        let q_type: i16;
        if k == 0 {
            q_type = 0;
        } else {
            q_type = get_next_indice(st, 1) as i16;
            param_lpc[j] = q_type;
            j += 1;
        }

        // Decode quantization indices
        if q_type == 0 {
            // Absolute quantizer with 1st stage stochastic codebook
            param_lpc[j] = get_next_indice(st, 8) as i16;
            j += 1;
        }

        // 2 bits to specify Q2,Q3,Q4,ext
        let mut qn1 = add(2, get_next_indice(st, 2) as i16);
        let mut qn2 = add(2, get_next_indice(st, 2) as i16);

        // Unary code
        // Q5 = 0, Q6=10, Q0=110, Q7=1110, ...
        if sub(qn1, 4) > 0 {
            let nb = unary_decode(st, &mut qn1);

            if sub(nb, 1) == 0 {
                qn1 = add(qn1, 5);
            }
            if sub(nb, 2) == 0 {
                qn1 = add(qn1, 4);
            }
            if sub(nb, 3) == 0 {
                qn1 = 0;
            }
            if sub(nb, 3) > 0 {
                qn1 = add(qn1, 3);
            }
        }

        if sub(qn2, 4) > 0 {
            let nb = unary_decode(st, &mut qn2);

            if sub(nb, 1) == 0 {
                qn2 = add(qn2, 5);
            }
            if sub(nb, 2) == 0 {
                qn2 = add(qn2, 4);
            }
            if sub(nb, 3) == 0 {
                qn2 = 0;
            }
            if sub(nb, 3) > 0 {
                qn2 = add(qn2, 3);
            }
        }

        // check for potential bit errors
        if sub(qn1, NB_SPHERE) > 0 || sub(qn2, NB_SPHERE) > 0 {
            qn1 = 0;
            qn2 = 0;
            st.ber_detect = 1;
        }

        param_lpc[j] = qn1;
        j += 1;
        param_lpc[j] = qn2;
        j += 1;

        // Decode Split-by-2 algebraic VQ
        let avq_bits = shl(qn1, 2);

        pack4bits(avq_bits, st, &mut param_lpc[j..]);
        j += qn1.max(0) as usize;

        let avq_bits = shl(qn2, 2);
        pack4bits(avq_bits, st, &mut param_lpc[j..]);
        j += qn2.max(0) as usize;
    }

    sub(st.next_bit_pos, start_bit_pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(bits: &[u16]) -> Box<DecoderState> {
        let mut st = Box::new(DecoderState::zeroed());
        for (slot, &bit) in st.bit_stream.iter_mut().zip(bits) {
            *slot = bit;
        }
        st.total_num_bits = 400;
        st.codec_mode = 2;
        st
    }

    #[test]
    fn unary_code_counts_ones_before_the_stop_bit() {
        let mut st = stream(&[1, 1, 0]);
        let mut ind = 0;
        assert_eq!(unary_decode(&mut st, &mut ind), 3);
        assert_eq!(ind, 3);
        let mut st = stream(&[0]);
        assert_eq!(unary_decode(&mut st, &mut ind), 1);
        assert_eq!(ind, 0);
    }

    #[test]
    fn pack4bits_splits_into_nibbles() {
        let mut st = stream(&[1, 0, 1, 1, 0, 1, 1]);
        let mut prm = [0i16; 2];
        assert_eq!(pack4bits(7, &mut st, &mut prm), 2);
        assert_eq!(prm, [0b1011, 0b011]);
    }

    #[test]
    fn single_lpc_uses_the_first_slot_pair_and_reports_its_size() {
        // index: first stage 0, then the AVQ codebook numbers 0 and 0: 3 parameters.
        let index = [0i16, 0, 0];
        let mut lsf_q = [0i16; 16];
        assert_eq!(dlpc_avq(&index, &mut lsf_q, 1, 12800), 3);
    }
}
