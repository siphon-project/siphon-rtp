//! Context-based arithmetic decoding of the MDCT spectrum, 17-symbol low-complexity models
//! (TS 26.442 `lib_dec/ACcontextMapping_dec.c`; TS 26.445 §6.2.2.2.4).
//!
//! `Overflow` and `Carry`: nothing in this file reads them.

use crate::evs::cnst::{CBITSNEW, NBITS_CONTEXT, VAL_ESC};
use crate::evs::com::ac_context_mapping::{
    get_next_coeff_mapped, get_next_coeff_unmapped, update_mixed_context,
};
use crate::evs::com::ari_hm::ContextHmConfig;
use crate::evs::com::bitstream::{
    get_indice_1, get_next_indice, get_next_indice_1, get_next_indice_tmp,
};
use crate::evs::dec::ari_dec::{ari_decode_14bits_s17_ext, ari_start_decoding_14bits};
use crate::evs::dec::state::{DecoderState, TastatDec};
use crate::evs::rom::{ARI_LOOKUP_S17_LC, ARI_PK_S17_LC_EXT, POW2TAB, TAB_ESC_NB};
use crate::itu::basic_ops::{add, extract_l, negate, norm_s, shl, shr, sub};
use crate::itu::stl2009::l_mac0;

/// The pair of coefficient indices and the peak/hole flags `get_next_coeff` hands the main loop.
struct Tuple {
    a1_i: i16,
    b1_i: i16,
    p1: i16,
    p2: i16,
    idx1: i16,
    idx2: i16,
}

/// `ACcontextMapping_decode2_no_mem_s17_LC`: decode `nt` spectral lines into `x` (and the
/// residual-quantisation bits into `x[nt..]`) from a budget of `nbbits` bits. With a `hm_cfg` the
/// lines come in the harmonic model's order (peaks and holes), otherwise in natural order.
/// Returns the number of residual bits read (0 on a bit error, which also sets `BER_detect`).
///
/// `x` holds at least `nt + resQMaxBits` values.
pub fn ac_context_mapping_decode2_no_mem_s17_lc(
    st: &mut DecoderState,
    x: &mut [i16],
    nt: i16,
    nbbits: i16,
    res_q_max_bits: i16,
    mut hm_cfg: Option<&mut ContextHmConfig<'_>>,
) -> i16 {
    let mut as_ = TastatDec::zeroed();
    let mut r: i16 = 0;
    let mut esc_nb: i16 = 0;
    let mut lev: i16;
    let mut ii: [i16; 2] = [0; 2];
    let mut c: [i16; 2] = [0; 2];
    let (mut p1, mut p2): (i16, i16) = (0, 0);

    x[..nt.max(0) as usize].fill(0);

    // Rate flag
    let mut rate_flag: i16 = 0;
    if sub(nbbits, 400) > 0 {
        rate_flag = 2 << NBITS_CONTEXT;
    }

    // Decode number of ntuples
    let start_bit_pos = st.next_bit_pos;
    let mut lsbs_bit_pos = add(start_bit_pos, sub(nbbits, 1));

    let l = sub(14, norm_s(negate(nt)));
    let n = add(get_next_indice(st, l) as i16, 1);

    // Init
    let nt_half = shr(nt, 1);
    let mut t: i16;

    let lastnz = shl(n, 1);

    if sub(lastnz, nt) > 0 || st.ber_detect != 0 {
        st.ber_detect = 1;
        return 0;
    }

    let mapped = hm_cfg.is_some();
    if let Some(hm_cfg) = hm_cfg.as_deref_mut() {
        // mapped domain
        let num_peak_indices_orig = hm_cfg.num_peak_indices;
        hm_cfg.num_peak_indices = hm_cfg.num_peak_indices.min(lastnz);
        let num_hole_indices = sub(lastnz, hm_cfg.num_peak_indices);

        // Mark hole indices beyond lastnz as pruned
        let mut k = num_hole_indices;
        while k < hm_cfg.num_hole_indices {
            let at = hm_cfg.hole_indices_at + k as usize;
            if let Some(slot) = hm_cfg.index_buffer.get_mut(at) {
                *slot = add(*slot, nt);
            }
            k += 1;
        }

        ii[0] = num_peak_indices_orig;
        ii[1] = 0;
    } else {
        // unmapped domain
        ii[0] = 0;
    }

    // Start Decoding
    ari_start_decoding_14bits(st, &mut as_);

    let mut overflow_bit_pos = st.next_bit_pos;
    let nbbits_m2 = add(nbbits, CBITSNEW - 2);
    let mut rest_bits = negate(nbbits_m2);
    let mut rest_bits_overflow = rest_bits;

    // Main Loop through the 2-tuples
    let mut k: i16 = 0;
    while k < lastnz {
        // First and second coefficient
        let tuple = next_tuple(&mut ii, hm_cfg.as_deref(), p1, p2);
        let (a1_i, b1_i, idx1, idx2) = (tuple.a1_i, tuple.b1_i, tuple.idx1, tuple.idx2);
        p1 = tuple.p1;
        p2 = tuple.p2;

        let idx = idx1.min(idx2);

        // Get context
        let ctx = (p1 | p2) as usize;

        t = add(c[ctx], rate_flag);
        if sub(idx, nt_half) > 0 {
            t = add(t, 1 << NBITS_CONTEXT);
        }

        if t < 0 || lsbs_bit_pos <= 0 {
            st.ber_detect = 1;
            return 0;
        }

        let mut la: i32 = 0;
        let mut lb: i32 = 0;
        // MSBs decoding
        lev = 0;
        while lev < 15 && lsbs_bit_pos > 0 {
            esc_nb = lev.min(3);
            let tmp = add(t, TAB_ESC_NB[esc_nb as usize]);
            // The reference asserts 0 <= tmp < 4096; the context stays far below that.
            let Some(&pki) = ARI_LOOKUP_S17_LC.get(tmp as usize) else {
                st.ber_detect = 1;
                return 0;
            };
            let Some(model) = usize::try_from(pki)
                .ok()
                .and_then(|pki| ARI_PK_S17_LC_EXT.get(pki))
            else {
                st.ber_detect = 1;
                return 0;
            };
            r = ari_decode_14bits_s17_ext(st, &mut as_, model);

            if sub(r, VAL_ESC) < 0 {
                break;
            }

            // LSBs decoding
            la = l_mac0(
                la,
                POW2TAB[lev as usize],
                get_indice_1(st, lsbs_bit_pos) as i16,
            );
            lsbs_bit_pos = lsbs_bit_pos.wrapping_sub(1);
            lb = l_mac0(
                lb,
                POW2TAB[lev as usize],
                get_indice_1(st, lsbs_bit_pos) as i16,
            );
            lsbs_bit_pos = lsbs_bit_pos.wrapping_sub(1);
            lev += 1;
        }

        if (sub(lsbs_bit_pos, -1) < 0 && sub(r, VAL_ESC) >= 0) || sub(lev, 14) > 0 {
            store(x, a1_i, 0);
            store(x, b1_i, 0);
            st.ber_detect = 1;
            return 0;
        }

        // MSBs contributions
        let b1 = shr(r, 2);
        let a1 = r & 0x3;
        let a = extract_l(l_mac0(la, POW2TAB[lev as usize], a1));
        let b = extract_l(l_mac0(lb, POW2TAB[lev as usize], b1));

        // lsbs bits sign bits
        rest_bits = add(rest_bits, shl(lev, 1));

        if a > 0 {
            rest_bits = add(rest_bits, 1);
        }
        if b > 0 {
            rest_bits = add(rest_bits, 1);
        }

        // Dectect overflow
        if add(sub(st.next_bit_pos, start_bit_pos), rest_bits) > 0 {
            // Roll back bit-stream position to overflow_bit_pos
            get_next_indice_tmp(st, sub(overflow_bit_pos, st.next_bit_pos));
            rest_bits = rest_bits_overflow;
            store(x, a1_i, 0);
            store(x, b1_i, 0);
            break;
        }

        overflow_bit_pos = st.next_bit_pos;
        rest_bits_overflow = rest_bits;

        // Store decoded data
        store(x, a1_i, a);
        store(x, b1_i, b);

        // Update context for next 2-tuple
        if sub(p1, p2) == 0 {
            // peak-peak or hole-hole context
            lev = sub(esc_nb, 1);
            if lev > 0 {
                t = add(12, lev);
            }
            if lev <= 0 {
                t = add(a1, b1);
            }
            if lev == 0 {
                t = add(t, t);
            }

            c[ctx] = add(shl(c[ctx] & 0xf, 4), add(t, 1));
        } else {
            // mixed context
            if (idx1 & 1) != 0 {
                // update first context
                c[p1 as usize] = update_mixed_context(c[p1 as usize], a);
            }

            if (idx2 & 1) != 0 {
                // update second context
                c[p2 as usize] = update_mixed_context(c[p2 as usize], b);
            }
        }
        k += 2;
    }

    // Total number of decoded AC bits
    get_next_indice_tmp(st, -(CBITSNEW - 2));

    // detect overflow
    if sub(k, lastnz) != 0 {
        rest_bits = add(rest_bits, nbbits_m2);
        // Set bit-stream position to (start_bit_pos+nbbits-rest_bits)
        let delta = sub(sub(add(start_bit_pos, nbbits), rest_bits), st.next_bit_pos);
        get_next_indice_tmp(st, delta);
    }

    // Decode signs
    let sign_lines = if mapped { nt } else { lastnz };
    for line in &mut x[..sign_lines.max(0) as usize] {
        if *line > 0 && get_next_indice_1(st) != 0 {
            *line = negate(*line);
        }
    }

    // Decode Residual Q
    let res_q_bits = res_q_max_bits.min(sub(add(lsbs_bit_pos, 1), st.next_bit_pos));
    for k in 0..res_q_bits.max(0) {
        x[(nt + k) as usize] = get_indice_1(st, sub(lsbs_bit_pos, k)) as i16;
    }

    // Set bit-stream pointer to end of buffer
    let delta = sub(add(start_bit_pos, nbbits), st.next_bit_pos);
    get_next_indice_tmp(st, delta);

    res_q_bits
}

/// `x[index] = value`. The harmonic model's indices stay inside the spectrum for every lag the
/// encoder sends; a bit-errored lag can put a peak line at -1, where the reference writes outside
/// the array. That write is dropped.
fn store(x: &mut [i16], index: i16, value: i16) {
    if let Some(slot) = usize::try_from(index)
        .ok()
        .and_then(|index| x.get_mut(index))
    {
        *slot = value;
    }
}

/// Two calls of `get_next_coeff` (mapped with a harmonic model, unmapped without one). The
/// unmapped reader does not touch the peak/hole flags, which keep their previous values.
fn next_tuple(ii: &mut [i16; 2], hm_cfg: Option<&ContextHmConfig<'_>>, p1: i16, p2: i16) -> Tuple {
    let (mut idx1, mut idx2) = (0, 0);
    let (a1_i, b1_i);
    let (mut q1, mut q2) = (p1, p2);
    if let Some(hm_cfg) = hm_cfg {
        a1_i = get_next_coeff_mapped(ii, &mut q1, &mut idx1, hm_cfg);
        b1_i = get_next_coeff_mapped(ii, &mut q2, &mut idx2, hm_cfg);
    } else {
        a1_i = get_next_coeff_unmapped(ii, &mut idx1);
        b1_i = get_next_coeff_unmapped(ii, &mut idx2);
    }
    Tuple {
        a1_i,
        b1_i,
        p1: q1,
        p2: q2,
        idx1,
        idx2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::cnst::MODE2;

    fn state() -> Box<DecoderState> {
        let mut st = Box::new(DecoderState::zeroed());
        st.codec_mode = MODE2;
        st.total_num_bits = 200;
        st
    }

    #[test]
    fn a_tuple_count_beyond_the_spectrum_is_a_bit_error() {
        let mut st = state();
        // nt = 10 reads a 3-bit count: all ones gives n = 8, lastnz = 16 > nt.
        st.bit_stream[..16].fill(1);
        let mut x = [7_i16; 40];
        assert_eq!(
            ac_context_mapping_decode2_no_mem_s17_lc(&mut st, &mut x, 10, 100, 8, None),
            0
        );
        assert_eq!(st.ber_detect, 1);
        assert_eq!(&x[..10], &[0; 10]);
    }

    #[test]
    fn an_all_zero_payload_decodes_only_escapes_and_is_a_bit_error() {
        let mut st = state();
        // The zero bits select the escape symbol at every level: more than 14 of them is
        // corrupt, so the frame is rejected with the decoded lines cleared.
        let mut x = [0_i16; 40];
        let bits = ac_context_mapping_decode2_no_mem_s17_lc(&mut st, &mut x, 16, 40, 4, None);
        assert_eq!(bits, 0);
        assert_eq!(st.ber_detect, 1);
    }
}
