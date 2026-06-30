//! AMR-NB algebraic (fixed) codebook decoders — 3GPP TS 26.073 `d2_9pf.c`, `d2_11pf.c`,
//! `d3_14pf.c`, `d4_17pf.c`, `d8_31pf.c`, `d1035pf.c`. Ported bit-exact.
//!
//! Each mode uses a different multi-pulse codebook; the decoder turns the received
//! position+sign index(es) into the 40-sample innovation vector `cod[]` (pulses at `±1.0`).
//!
//! | mode | function | pulses | bits |
//! |------|----------|--------|------|
//! | MR475/MR515/MR59 | [`decode_2i40_9bits`] | 2 | 9 |
//! | MR59 | [`decode_2i40_11bits`] | 2 | 11 |
//! | MR67 | [`decode_3i40_14bits`] | 3 | 14 |
//! | MR74/MR795 | [`decode_4i40_17bits`] | 4 | 17 |
//! | MR102 | [`dec_8i40_31bits`] | 8 | 31 |
//! | MR122 | [`dec_10i40_35bits`] | 10 | 35 |

use crate::amr::basic_ops::{add, extract_l, l_mult, l_shr, negate, shl, shr};
use crate::amr::nb::constants::{L_CODE, L_SUBFR, NB_TRACK, NB_TRACK_MR102};

/// Track start positions for the 9-bit 2-pulse codebook (`c2_9pf.tab` `startPos[2*4*2]`).
#[rustfmt::skip]
static START_POS: [i16; 16] = [
    0, 2, 0, 3,
    0, 2, 0, 3,
    1, 3, 2, 4,
    1, 4, 1, 4,
];

/// Gray-decode table (`gray.tab` `dgray[8]`).
static DGRAY: [i16; 8] = [0, 1, 3, 2, 5, 6, 4, 7];

/// Decode the 9-bit 2-pulse algebraic codebook (`d2_9pf.c` `decode_2i40_9bits`), for MR475/515/59.
/// `sub_nr` is the subframe number; `sign` the 2 pulse signs; `index` the packed positions.
pub fn decode_2i40_9bits(sub_nr: i16, sign: i16, index: i16, cod: &mut [i16]) {
    let mut pos = [0i16; 2];

    // table bit is the MSB
    let j = shr(index & 64, 6);

    let i = index & 7;
    let i = add(i, shl(i, 2)); // pos0 = i*5 + startPos[j*8 + subNr*2]
    let k = START_POS[add(shl(j, 3), shl(sub_nr, 1)) as usize];
    pos[0] = add(i, k);

    let index = shr(index, 3);
    let i = index & 7;
    let i = add(i, shl(i, 2)); // pos1 = i*5 + startPos[j*8 + subNr*2 + 1]
    let k = START_POS[add(add(shl(j, 3), shl(sub_nr, 1)), 1) as usize];
    pos[1] = add(i, k);

    build_codeword(sign, &pos, cod);
}

/// Decode the 11-bit 2-pulse algebraic codebook (`d2_11pf.c` `decode_2i40_11bits`), for MR59.
pub fn decode_2i40_11bits(sign: i16, index: i16, cod: &mut [i16]) {
    let mut pos = [0i16; 2];

    let j = index & 1;
    let index = shr(index, 1);
    let i = index & 7;
    let i = add(i, shl(i, 2)); // pos0 = i*5 + 1 + j*2
    let i = add(i, 1);
    let j2 = shl(j, 1);
    pos[0] = add(i, j2);

    let index = shr(index, 3);
    let j = index & 3;
    let index = shr(index, 2);
    let i = index & 7;
    if j == 3 {
        let i = add(i, shl(i, 2)); // pos1 = i*5 + 4
        pos[1] = add(i, 4);
    } else {
        let i = add(i, shl(i, 2)); // pos1 = i*5 + j
        pos[1] = add(i, j);
    }

    build_codeword(sign, &pos, cod);
}

/// Decode the 14-bit 3-pulse algebraic codebook (`d3_14pf.c` `decode_3i40_14bits`), for MR67.
pub fn decode_3i40_14bits(sign: i16, index: i16, cod: &mut [i16]) {
    let mut pos = [0i16; 3];

    let i = index & 7;
    pos[0] = add(i, shl(i, 2)); // pos0 = i*5

    let index = shr(index, 3);
    let j = index & 1;
    let index = shr(index, 1);
    let i = index & 7;
    let i = add(i, shl(i, 2)); // pos1 = i*5 + 1 + j*2
    let i = add(i, 1);
    let j2 = shl(j, 1);
    pos[1] = add(i, j2);

    let index = shr(index, 3);
    let j = index & 1;
    let index = shr(index, 1);
    let i = index & 7;
    let i = add(i, shl(i, 2)); // pos2 = i*5 + 2 + j*2
    let i = add(i, 2);
    let j2 = shl(j, 1);
    pos[2] = add(i, j2);

    // d3_14pf uses `i > 0` for the sign test (vs `i != 0`); same effect since `i` is sign&1 (0/1).
    build_codeword(sign, &pos, cod);
}

/// Decode the 17-bit 4-pulse algebraic codebook (`d4_17pf.c` `decode_4i40_17bits`), for MR74/MR795.
pub fn decode_4i40_17bits(sign: i16, index: i16, cod: &mut [i16]) {
    let mut pos = [0i16; 4];

    let i = DGRAY[(index & 7) as usize];
    pos[0] = add(i, shl(i, 2)); // pos0 = i*5

    let index = shr(index, 3);
    let i = DGRAY[(index & 7) as usize];
    let i = add(i, shl(i, 2)); // pos1 = i*5 + 1
    pos[1] = add(i, 1);

    let index = shr(index, 3);
    let i = DGRAY[(index & 7) as usize];
    let i = add(i, shl(i, 2)); // pos2 = i*5 + 2
    pos[2] = add(i, 2);

    let index = shr(index, 3);
    let j = index & 1;
    let index = shr(index, 1);
    let i = DGRAY[(index & 7) as usize];
    let i = add(i, shl(i, 2)); // pos3 = i*5 + 3 + j
    let i = add(i, 3);
    pos[3] = add(i, j);

    build_codeword(sign, &pos, cod);
}

/// Common pulse-placement: zero `cod[0..L_SUBFR]`, then for each pulse set `±8191`/`-8192` per its
/// sign bit (LSB-first). Shared by the 9/11/14/17-bit decoders (their `cod` build is identical).
fn build_codeword(mut sign: i16, pos: &[i16], cod: &mut [i16]) {
    for c in cod.iter_mut().take(L_SUBFR) {
        *c = 0;
    }
    for &p in pos {
        let bit = sign & 1;
        sign = shr(sign, 1);
        cod[p as usize] = if bit != 0 { 8191 } else { -8192 };
    }
}

/// Decompress one 10-bit linear codeword into 3 positions (`d8_31pf.c` `decompress10`).
fn decompress10(
    mut msbs: i16,
    lsbs: i16,
    index1: usize,
    index2: usize,
    index3: usize,
    pos_indx: &mut [i16],
) {
    if msbs > 124 {
        msbs = 124;
    }
    let ia = crate::amr::basic_ops::mult(msbs, 1311);
    let ia = crate::amr::basic_ops::sub(msbs, extract_l(l_shr(l_mult(ia, 25), 1)));
    let ib = shl(
        crate::amr::basic_ops::sub(
            ia,
            extract_l(l_shr(l_mult(crate::amr::basic_ops::mult(ia, 6554), 5), 1)),
        ),
        1,
    );

    let ic = shl(shr(lsbs, 2), 2);
    let ic = crate::amr::basic_ops::sub(lsbs, ic);
    pos_indx[index1] = add(ib, ic & 1);

    let ib = shl(crate::amr::basic_ops::mult(ia, 6554), 1);
    pos_indx[index2] = add(ib, shr(ic, 1));

    pos_indx[index3] = add(
        shl(crate::amr::basic_ops::mult(msbs, 1311), 1),
        shr(lsbs, 2),
    );
}

/// Decompress the 8-pulse linear codeword into 4 signs + 8 positions (`d8_31pf.c` `decompress_code`).
fn decompress_code(indx: &[i16], sign_indx: &mut [i16; 4], pos_indx: &mut [i16; 8]) {
    use crate::amr::basic_ops::{mult, sub};

    sign_indx[..NB_TRACK_MR102].copy_from_slice(&indx[..NB_TRACK_MR102]);

    // First index (7+3 bits)
    let msbs = shr(indx[NB_TRACK_MR102], 3);
    let lsbs = indx[NB_TRACK_MR102] & 7;
    decompress10(msbs, lsbs, 0, 4, 1, pos_indx);

    // Second index (7+3 bits)
    let msbs = shr(indx[NB_TRACK_MR102 + 1], 3);
    let lsbs = indx[NB_TRACK_MR102 + 1] & 7;
    decompress10(msbs, lsbs, 2, 6, 5, pos_indx);

    // Third index (5+2 bits)
    let msbs = shr(indx[NB_TRACK_MR102 + 2], 2);
    let lsbs = indx[NB_TRACK_MR102 + 2] & 3;

    let msbs0_24 = shr(add(extract_l(l_shr(l_mult(msbs, 25), 1)), 12), 5);

    let ia = mult(msbs0_24, 6554) & 1;
    let mut ib = sub(
        msbs0_24,
        extract_l(l_shr(l_mult(mult(msbs0_24, 6554), 5), 1)),
    );
    if ia == 1 {
        ib = sub(4, ib);
    }
    pos_indx[3] = add(shl(ib, 1), lsbs & 1);

    let ia = shl(mult(msbs0_24, 6554), 1);
    pos_indx[7] = add(ia, shr(lsbs, 1));
}

/// Decode the 31-bit 8-pulse algebraic codebook (`d8_31pf.c` `dec_8i40_31bits`), for MR102.
/// `index` holds the 7 received parameters (4 signs + 3 position indices).
pub fn dec_8i40_31bits(index: &[i16], cod: &mut [i16]) {
    use crate::amr::basic_ops::sub;
    const POS_CODE: i16 = 8191;
    const NEG_CODE: i16 = 8191;

    for c in cod.iter_mut().take(L_CODE) {
        *c = 0;
    }

    let mut linear_signs = [0i16; 4];
    let mut linear_codewords = [0i16; 8];
    decompress_code(index, &mut linear_signs, &mut linear_codewords);

    for j in 0..NB_TRACK_MR102 {
        // pulse "j"
        let i = linear_codewords[j];
        let i = extract_l(l_shr(l_mult(i, 4), 1));
        let pos1 = add(i, j as i16);
        let mut sign = if linear_signs[j] == 0 {
            POS_CODE
        } else {
            -NEG_CODE
        };
        cod[pos1 as usize] = sign;

        // pulse "j+4"
        let i = linear_codewords[j + 4];
        let i = extract_l(l_shr(l_mult(i, 4), 1));
        let pos2 = add(i, j as i16);
        if sub(pos2, pos1) < 0 {
            sign = negate(sign);
        }
        cod[pos2 as usize] = add(cod[pos2 as usize], sign);
    }
}

/// Decode the 35-bit 10-pulse algebraic codebook (`d1035pf.c` `dec_10i40_35bits`), for MR122.
/// `index` holds the 10 received pulse parameters.
pub fn dec_10i40_35bits(index: &[i16], cod: &mut [i16]) {
    use crate::amr::basic_ops::sub;

    for c in cod.iter_mut().take(L_CODE) {
        *c = 0;
    }

    for j in 0..NB_TRACK {
        // pulse "j"
        let tmp = index[j];
        let i = DGRAY[(tmp & 7) as usize];
        let i = extract_l(l_shr(l_mult(i, 5), 1));
        let pos1 = add(i, j as i16);

        let bit = shr(tmp, 3) & 1;
        let mut sign = if bit == 0 { 4096 } else { -4096 };
        cod[pos1 as usize] = sign;

        // pulse "j+5"
        let i = DGRAY[(index[j + 5] & 7) as usize];
        let i = extract_l(l_shr(l_mult(i, 5), 1));
        let pos2 = add(i, j as i16);
        if sub(pos2, pos1) < 0 {
            sign = negate(sign);
        }
        cod[pos2 as usize] = add(cod[pos2 as usize], sign);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonzero_positions(cod: &[i16]) -> Vec<(usize, i16)> {
        cod.iter()
            .enumerate()
            .filter(|(_, &v)| v != 0)
            .map(|(i, &v)| (i, v))
            .collect()
    }

    #[test]
    fn decode_2i40_9bits_places_two_pulses() {
        let mut cod = [0i16; L_SUBFR];
        // index=0, sign=0b11 -> both pulses positive (8191). Positions per startPos[subNr=0].
        decode_2i40_9bits(0, 0b11, 0, &mut cod);
        let nz = nonzero_positions(&cod);
        assert_eq!(nz.len(), 2);
        assert!(nz.iter().all(|&(_, v)| v == 8191));
    }

    #[test]
    fn decode_2i40_9bits_signs_are_lsb_first() {
        let mut cod = [0i16; L_SUBFR];
        decode_2i40_9bits(0, 0b01, 0, &mut cod); // pulse0 +, pulse1 -
        let nz = nonzero_positions(&cod);
        assert_eq!(nz.len(), 2);
        // first pulse positive, second negative (LSB-first sign decode)
        let mut sorted = nz.clone();
        sorted.sort_by_key(|&(p, _)| p);
        // pos0 = 0 here (index 0, startPos[0]=0); pos1 = 0 + startPos[1]=2.
        assert_eq!(cod[0], 8191);
        assert_eq!(cod[2], -8192);
    }

    #[test]
    fn decode_3i40_14bits_places_three_pulses() {
        let mut cod = [0i16; L_SUBFR];
        decode_3i40_14bits(0b111, 0, &mut cod);
        assert_eq!(nonzero_positions(&cod).len(), 3);
    }

    #[test]
    fn decode_4i40_17bits_places_four_pulses() {
        let mut cod = [0i16; L_SUBFR];
        decode_4i40_17bits(0b1111, 0, &mut cod);
        assert_eq!(nonzero_positions(&cod).len(), 4);
    }

    #[test]
    fn dec_8i40_31bits_runs_without_panic_and_places_pulses() {
        let mut cod = [0i16; L_CODE];
        let index = [0i16, 0, 0, 0, 0, 0, 0]; // 4 signs + 3 position indices
        dec_8i40_31bits(&index, &mut cod);
        // 8 pulses across 4 tracks; pairs may collide so count is <= 8, > 0.
        assert!(!nonzero_positions(&cod).is_empty());
    }

    #[test]
    fn dec_10i40_35bits_runs_without_panic_and_places_pulses() {
        let mut cod = [0i16; L_CODE];
        let index = [0i16; 10];
        dec_10i40_35bits(&index, &mut cod);
        assert!(!nonzero_positions(&cod).is_empty());
    }

    #[test]
    fn all_pulse_positions_within_subframe() {
        // Fuzz a range of indices/signs for every decoder; positions must stay in [0, L_SUBFR).
        let mut cod = [0i16; L_SUBFR];
        for idx in 0..512i16 {
            decode_2i40_9bits((idx & 3).min(3), idx & 3, idx, &mut cod);
            decode_2i40_11bits(idx & 3, idx, &mut cod);
            decode_3i40_14bits(idx & 7, idx, &mut cod);
            decode_4i40_17bits(idx & 15, idx, &mut cod);
        }
        // No panic == positions stayed in bounds.
    }
}
