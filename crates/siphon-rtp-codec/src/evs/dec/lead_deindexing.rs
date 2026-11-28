//! Base-codebook index decoding of the RE8 lattice vector quantiser (TS 26.442
//! `lib_dec/lead_deindexing_fx.c`; TS 26.445 §6.1.4.2.1, the absolute-leader / permutation /
//! sign decomposition of the codebooks Q0, Q2, Q3 and Q4).

use crate::evs::rom::{
    A3_FX, A4_FX, I3_FX, I4_FX, IS_FX, MULT_AVQ_TAB_FX, SELECT_TABLE22_FX, SHIFT_AVQ_TAB_FX,
    VALS_A_FX, VALS_Q_FX,
};
use crate::itu::basic_ops::{add, extract_l, l_shr, l_sub, shl, shr, sub};
use crate::itu::stl2009::l_mult0;

/// `re8_decode_base_index_fx`: decode the index `i` of a point of the base codebook `Q_n`
/// (`n` in {0, 2, 3, 4}) into the 8-dimensional integer vector `x`.
pub fn re8_decode_base_index(n: i16, mut i: u16, x: &mut [i16]) {
    let mut setor_8p_temp = [0_i16; 8];
    let mut setor_8p_temp_1 = [0_i16; 8];
    let mut setor_8p_temp_2 = [0_i16; 8];

    if sub(n, 2) < 0 {
        x[..8].fill(0);
        return;
    }
    if l_sub(i32::from(i), 65519) > 0 {
        i = 0;
    }

    // search for the identifier ka of the absolute leader (table-lookup):
    // Q2 is a subset of Q3 - the two cases are considered in the same branch
    let ka = if sub(n, 3) <= 0 {
        let mut k = 1;
        while k < 9 {
            if l_sub(i32::from(i), i32::from(I3_FX[k])) < 0 {
                break;
            }
            k += 1;
        }
        A3_FX[k - 1]
    } else {
        let mut k = 1;
        while k < 27 {
            if l_sub(i32::from(i), i32::from(I4_FX[k])) < 0 {
                break;
            }
            k += 1;
        }
        A4_FX[k - 1]
    } as usize;

    // reconstruct the absolute leader
    let a1 = &VALS_A_FX[ka];
    let a2 = &VALS_Q_FX[ka];
    let k1 = a2[0];
    let code_level = a2[1];
    let offset = IS_FX[ka];
    let mut code_index = extract_l(l_sub(i32::from(i), i32::from(offset)));
    let sign_8p = code_index & sub(shl(1, k1), 1);
    code_index = shr(code_index, k1);

    let mut m: i16 = 0;
    let mut m1: i16 = 0;
    let mut m2: i16 = 0;
    let element_a10 = a1[0];
    let mut element_a11: i16 = 0;
    let mut element_a12: i16 = 0;

    // The reference's switch falls through: level 4 decodes the third position set, then the
    // level-3 and level-2 work.
    if code_level == 4 {
        m2 = 1;
        let bit = code_index & 1;
        setor_8p_temp_2[0] = 0;
        if bit != 0 {
            setor_8p_temp_2[0] = 1;
        }
        code_index = shr(code_index, 1);
    }
    if code_level == 4 || code_level == 3 {
        m = a2[2];
        m1 = a2[3];
        let l = SELECT_TABLE22_FX[m1 as usize][m as usize];
        let j = extract_l(l_shr(
            l_mult0(code_index, MULT_AVQ_TAB_FX[l as usize]),
            SHIFT_AVQ_TAB_FX[l as usize],
        ));
        code_index = sub(code_index, extract_l(l_mult0(j, l)));
        fcb_decode_pos(code_index, &mut setor_8p_temp_1, m, m1);
        code_index = j;
        element_a12 = a1[2];
    }
    if (2..=4).contains(&code_level) {
        m = a2[2];
        fcb_decode_pos(code_index, &mut setor_8p_temp, 8, m);
        element_a11 = a1[1];
    }

    x[..8].fill(element_a10);
    for &pos in &setor_8p_temp[..m.max(0) as usize] {
        x[pos as usize & 7] = element_a11;
    }
    for &pos in &setor_8p_temp_1[..m1.max(0) as usize] {
        x[setor_8p_temp[pos as usize & 7] as usize & 7] = element_a12;
    }
    for _ in 0..m2 {
        let inner = setor_8p_temp_1[setor_8p_temp_2[0] as usize & 7] as usize & 7;
        x[setor_8p_temp[inner] as usize & 7] = 6;
    }

    // add the sign of all elements (except sometimes for the last one)
    m1 = sub(k1, 1);
    m2 = 8;
    let mut l: i16 = 1;
    if x[..8].contains(&0) {
        l = 0;
    }
    if k1 == 7 && l > 0 {
        m2 = 7;
    }
    for value in x.iter_mut().take(m2 as usize) {
        if *value != 0 {
            if (shr(sign_8p, m1) & 1) != 0 {
                *value = sub(0, *value);
            }
            m1 = sub(m1, 1);
        }
    }

    // recover the sign of the last element if needed
    if sub(k1, 7) == 0 {
        let mut sum: i16 = 0;
        for &value in &x[..8] {
            sum = add(sum, value);
        }
        if sum & 3 != 0 {
            x[7] = sub(0, x[7]);
        }
    }
}

/// `select_table22_fx` read as the reference's flat `[5][9]` array, so a pointer walked back
/// past the start of a row reads the end of the previous one as the C does. Outside the table
/// (which the reference's own index ranges never reach) it reads 0.
fn select_table22_flat(index: isize) -> i16 {
    if !(0..45).contains(&index) {
        return 0;
    }
    let index = index as usize;
    SELECT_TABLE22_FX[index / 9][index % 9]
}

/// `fcb_decode_pos_fx`: decode the combinatorial `index` of `pos_num` positions among
/// `pulse_num` into `pos_vector`.
fn fcb_decode_pos(index: i16, pos_vector: &mut [i16; 8], pulse_num: i16, pos_num: i16) {
    let mut k = index;
    let mut l: i16 = 0;
    let mut temp1 = pos_num;
    let temp2 = add(pulse_num, 1);
    let tmp_loop = sub(pos_num, 1);

    let mut i: usize = 0;
    while (i as i16) < tmp_loop {
        let row = isize::from(temp1) * 9;
        let mut select_table24 = row + isize::from(sub(pulse_num, l));
        k = sub(select_table22_flat(select_table24), k);
        while sub(k, select_table22_flat(select_table24)) <= 0 {
            l = add(l, 1);
            select_table24 -= 1;
            if select_table24 < -1 {
                // A hostile index cannot occur (the codebook offsets bound it); stop rather than
                // walk the pointer through memory the reference would read.
                break;
            }
        }
        k = sub(select_table22_flat(row + isize::from(sub(temp2, l))), k);
        pos_vector[i & 7] = sub(l, 1);
        temp1 = sub(temp1, 1);
        i += 1;
    }
    pos_vector[i & 7] = add(l, k);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_base_index_of_every_codebook_decodes_without_panicking() {
        let mut x = [0_i16; 8];
        for n in [0, 2, 3, 4] {
            for i in 0..=u16::MAX {
                re8_decode_base_index(n, i, &mut x);
            }
        }
    }

    #[test]
    fn codebook_zero_is_the_origin() {
        let mut x = [5_i16; 8];
        re8_decode_base_index(0, 1234, &mut x);
        assert_eq!(x, [0; 8]);
    }
}
