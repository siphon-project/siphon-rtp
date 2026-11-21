//! Huffman decoding of the HQ norm indices (TS 26.442 `lib_dec/hdecnrm_fx.c`; TS 26.445 §6.2.2.3).

use crate::evs::cnst::{HTH_NORM, LTH_NORM, OFFSET_NORM};
use crate::evs::com::bitstream::{get_next_indice, get_next_indice_1};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{HETABLE_FX, HNTABLE_FX};
use crate::itu::basic_ops::{add, l_add, negate, shl, shr, sub};
use crate::itu::stl2009::{lshl, lshr};

/// `decode_huff_context_fx`: walk the Huffman tree `hufftab` with bits from the stream; adds the
/// bits read to `rbits` and returns the decoded symbol.
///
/// Each internal node packs (offset to its children, bits to read); a leaf is stored negated.
/// The tables are complete trees, so the walk stays inside them for any bit pattern; a node
/// outside the table (a corrupted table, never a corrupted stream) ends the walk with symbol 0.
pub fn decode_huff_context(st: &mut DecoderState, hufftab: &[i16], rbits: &mut i16) -> i16 {
    let mut hufftab_idx: i32 = 0;
    loop {
        let Some(&node) = usize::try_from(hufftab_idx)
            .ok()
            .and_then(|index| hufftab.get(index))
        else {
            return 0;
        };
        if node <= 0 {
            return negate(node);
        }
        let tmp_h = shr(node, 4);
        let tmp_l = sub(node, shl(tmp_h, 4));
        *rbits = add(*rbits, tmp_l);
        hufftab_idx = l_add(
            hufftab_idx,
            l_add(i32::from(tmp_h), i32::from(get_next_indice(st, tmp_l))),
        );
    }
}

/// `hdecnrm_context_fx`: decode the norm indices `index[1..n]` with the context (above / below /
/// near the previous index) choosing the Huffman table; `index[0]` is already decoded. `n_length`
/// accumulates the bits read.
pub fn hdecnrm_context(st: &mut DecoderState, n: i16, index: &mut [i16], n_length: &mut i16) {
    let count = usize::try_from(n).unwrap_or(0).min(index.len());
    let Some(&first) = index.first() else {
        return;
    };
    let mut prevj = add(first, OFFSET_NORM);
    for slot in index.iter_mut().take(count).skip(1) {
        *slot = if sub(prevj, HTH_NORM) > 0 {
            // above
            let tmp = decode_huff_context(st, &HNTABLE_FX, n_length);
            sub(31, tmp)
        } else if sub(prevj, LTH_NORM) < 0 {
            // less
            decode_huff_context(st, &HNTABLE_FX, n_length)
        } else {
            // equal
            decode_huff_context(st, &HETABLE_FX, n_length)
        };
        prevj = *slot;
    }
}

/// `hdecnrm_resize_fx`: decode `n - 1` norm indices of the resized (unary-coded) scheme into
/// `index[0..n - 1]`.
pub fn hdecnrm_resize(st: &mut DecoderState, n: i16, index: &mut [i16]) {
    let m = usize::try_from(sub(n, 1)).unwrap_or(0).min(index.len());
    for slot in index.iter_mut().take(m) {
        let mut k: i16 = 0;
        for _ in 0..11 {
            if get_next_indice_1(st) != 0 {
                k = add(k, 1);
            } else {
                break;
            }
        }
        *slot = match k {
            11 => 25,
            10 => 5,
            9 => 6,
            _ => {
                if get_next_indice_1(st) != 0 {
                    add(16, k)
                } else {
                    sub(15, k)
                }
            }
        };
    }
}

/// `hdecnrm_fx`: Huffman decoding of `num_norms - 1` differential norm indices into `index` with
/// the fixed (non-context) code, 2 to 7 bits per index.
pub fn hdecnrm(st: &mut DecoderState, num_norms: i16, index: &mut [i16]) {
    let m = sub(num_norms, 1);
    for slot in index.iter_mut().take(m.max(0) as usize) {
        let mut j: i16 = 0;
        let mut k: i16 = 0;
        if get_next_indice_1(st) != 0 {
            j = 1;
        }
        if get_next_indice_1(st) != 0 {
            k = 1;
        }
        let n = add(shl(j, 1), k);
        j = shl(j, 2);
        let mut temp = sub(add(16, n), j);
        if get_next_indice_1(st) != 0 {
            temp = add(add(12, n), j);
            if get_next_indice_1(st) != 0 {
                j = 0;
                if get_next_indice_1(st) != 0 {
                    j = 1;
                }
                temp = add(8, n);
                if j != 0 {
                    temp = add(temp, 12);
                }
                if get_next_indice_1(st) != 0 {
                    temp = n;
                    if get_next_indice_1(st) != 0 {
                        temp = add(4, n);
                    }
                    if j != 0 {
                        temp = add(temp, 24);
                    }
                }
            }
        }
        *slot = temp;
    }
}

/// `hdecnrm_tran_fx`: Huffman decoding of `n - 1` differential norm indices of a transient frame
/// into `index`.
pub fn hdecnrm_tran(st: &mut DecoderState, n: i16, index: &mut [i16]) {
    let m = sub(n, 1);
    for slot in index.iter_mut().take(m.max(0) as usize) {
        let mut j: i16 = 0;
        let mut k: i16 = 0;
        if get_next_indice_1(st) != 0 {
            j = 1;
        }
        if get_next_indice_1(st) != 0 {
            k = 1;
        }

        // n = k * 2 + j;
        let n = add(shl(k, 1), j);
        // l = k * 4;
        let l = shl(k, 2);
        let temp = if (j == 0 && k == 0)
            || (sub(j, 1) == 0 && k == 0)
            || (sub(j, 1) == 0 && sub(k, 1) == 0)
        {
            sub(add(15, l), n)
        } else if get_next_indice_1(st) != 0 {
            sub(add(15, n), l)
        } else {
            let mut temp = sub(add(15, l), n);
            if get_next_indice_1(st) != 0 {
                // the reference reuses `k` as the run counter
                k = 0;
                while k < 3 {
                    if get_next_indice_1(st) != 0 {
                        k = add(k, 1);
                    } else {
                        break;
                    }
                }
                if k == 0 || sub(k, 3) == 0 {
                    temp = sub(temp, 5);
                    if sub(k, 3) == 0 {
                        temp = sub(temp, 1);
                    }
                } else if sub(k, 1) == 0 {
                    temp = add(temp, 1);
                } else {
                    temp = add(temp, 2);
                    if get_next_indice_1(st) != 0 {
                        temp = add(temp, 1);
                        if get_next_indice_1(st) != 0 {
                            temp = add(temp, 1);
                        }
                    }
                }
            }
            temp
        };
        *slot = temp;
    }
}

/// `huff_dec_fx`: decode `n` codewords of a canonical Huffman code into `index`, reading
/// `buffer_len` bits ahead and putting the unused ones back at the end.
///
/// `thres[j]` is the first codeword of length class `j` (left-aligned in `buffer_len` bits, with
/// `thres[0] == 0`), `offset[j]` its first entry in `huff_tab`. The walk and the table index stay
/// inside the tables for any bit pattern when they are consistent; an inconsistent table (never a
/// corrupted stream) yields symbol 0 instead of reading outside it.
pub fn huff_dec(
    st: &mut DecoderState,
    n: i16,
    buffer_len: i16,
    num_lengths: i16,
    thres: &[i16],
    offset: &[i16],
    huff_tab: &[i16],
    index: &mut [i16],
) {
    let mut val: i16 = 0;
    let mut j: i16 = 0;
    for slot in index.iter_mut().take(n.max(0) as usize) {
        let last_bits = sub(buffer_len, j);
        val = lshl(val, last_bits);
        val &= sub(lshl(1, buffer_len), 1);
        val |= get_next_indice(st, last_bits) as i16;

        // Find codeword length
        j = sub(num_lengths, 1);
        while j > 0 && sub(val, table_at(thres, j)) < 0 {
            j = sub(j, 1);
        }
        let k = lshr(sub(val, table_at(thres, j)), j);
        *slot = table_at(huff_tab, add(table_at(offset, j), k));
    }

    // Put back unused bits
    st.next_bit_pos = sub(st.next_bit_pos, j);
}

/// `table[index]`, or 0 outside the table (see [`huff_dec`]).
fn table_at(table: &[i16], index: i16) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or(0)
}
