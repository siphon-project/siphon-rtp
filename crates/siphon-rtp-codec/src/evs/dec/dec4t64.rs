//! Algebraic codebook decoding of the 4-track, 64-position ACELP codebook (TS 26.442
//! `lib_dec/dec4t64_fx.c`; TS 26.445 §6.1.1.2.2).
//!
//! Every function of the file: `dec_acelp_4t64_fx` with its pulse-group decoders (`dec_1p_N1_fx`
//! ... `dec_6p_6N2_fx`), and `D_ACELP_decode_43bit` with the helpers it uses (`add_pulses_fx`,
//! `dec_2p_2N1_fx`, `fcb_decode_PI_fx`, `fcb_decode_class_all_p_fx`, `fcb_decode_position_fx`).

use crate::evs::cnst::{L_SUBFR, NB_POS_FCB_4T};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::tools::{idiv_and_mod_32, set16};
use crate::evs::dec::dec_acelp::d_acelp_indexing;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::types::PulseConfig;
use crate::evs::rom::{PI_OFFSET_FX, PI_SELECT_TABLE_FX};
use crate::itu::basic_ops::{
    add, extract_l, l_add, l_deposit_l, l_mult, l_shl, l_shr, l_sub, shl, shr, sub,
};
use crate::itu::stl2009::l_mult0;

/// `TRACKPOS_FIXED_FIRST` of `enum TRACKPOS` (`lib_com/cnst_fx.h`).
const TRACKPOS_FIXED_FIRST: i8 = 0;

/// `dec_acelp_4t64_fx`: read an `nbbits`-bit algebraic codebook index from the bitstream and decode
/// it into `code[0..L_SUBFR]` (Q9). EVS codebooks (20, 28, 36, 43, 50, 62, 87 bits) go through
/// `D_ACELP_indexing`; the AMR-WB IO ones (`opt_amr_wb`: 20, 36, 44, 52, 64, 72, 88 bits) through
/// the pulse-group decoders below.
pub fn dec_acelp_4t64(st: &mut DecoderState, nbbits: i16, code: &mut [i16], opt_amr_wb: i16) {
    let mut pos = [0i16; 7];
    let mut ind1 = [0i32; 4];

    if opt_amr_wb == 0 {
        let mut config = PulseConfig::zeroed();
        // nbbits comes from the bit-allocation tables, so another value never reaches here (the
        // reference would leave nb_pulse uninitialised)
        config.nb_pulse = match nbbits {
            20 => 4,
            28 => 6,
            36 => 8,
            43 => 10,
            50 => 12,
            62 => 16,
            87 => 26,
            _ => 0,
        };
        config.bits = nbbits;
        config.codetrackpos = TRACKPOS_FIXED_FIRST;

        let mut indexing_indices = [0i16; 6];
        // the largest codebook is 87 bits: five whole words and a remainder
        let wordcnt = shr(nbbits, 4).clamp(0, 5);
        let bitcnt = nbbits & 15;
        let mut i = 0usize;
        while i < wordcnt as usize {
            indexing_indices[i] = get_next_indice(st, 16) as i16;
            i += 1;
        }
        if bitcnt != 0 {
            indexing_indices[i] = get_next_indice(st, bitcnt) as i16;
        }
        d_acelp_indexing(code, config, 4, &indexing_indices, &mut st.ber_detect);
    } else {
        for sample in code.iter_mut().take(256 / 4) {
            *sample = 0;
        }
        match nbbits {
            20 => {
                for k in 0..4 {
                    let l_index = i32::from(get_next_indice(st, 5));
                    dec_1p_n1(l_index, 4, 0, &mut pos);
                    add_pulses(&pos, 1, k, code);
                }
            }
            36 => {
                for k in 0..4 {
                    let l_index = i32::from(get_next_indice(st, 9));
                    dec_2p_2n1(l_index, 4, 0, &mut pos);
                    add_pulses(&pos, 2, k, code);
                }
            }
            44 => {
                for k in 0..4 - 2 {
                    let l_index = i32::from(get_next_indice(st, 13));
                    dec_3p_3n1(l_index, 4, 0, &mut pos);
                    add_pulses(&pos, 3, k, code);
                }
                for k in 2..4 {
                    let l_index = i32::from(get_next_indice(st, 9));
                    dec_2p_2n1(l_index, 4, 0, &mut pos);
                    add_pulses(&pos, 2, k, code);
                }
            }
            52 => {
                for k in 0..4 {
                    let l_index = i32::from(get_next_indice(st, 13));
                    dec_3p_3n1(l_index, 4, 0, &mut pos);
                    add_pulses(&pos, 3, k, code);
                }
            }
            64 => {
                for slot in &mut ind1 {
                    *slot = i32::from(get_next_indice(st, 2));
                }
                for k in 0..4 {
                    let index2 = get_next_indice(st, 14) as i16;
                    let l_index = l_add(l_shl(ind1[k as usize], 14), i32::from(index2));
                    dec_4p_4n(l_index, 4, 0, &mut pos);
                    add_pulses(&pos, 4, k, code);
                }
            }
            72 => {
                for slot in &mut ind1[..2] {
                    *slot = i32::from(get_next_indice(st, 10));
                }
                for slot in &mut ind1[2..] {
                    *slot = i32::from(get_next_indice(st, 2));
                }
                for k in 0..4 - 2 {
                    let index2 = get_next_indice(st, 10) as i16;
                    let l_index = l_add(l_shl(ind1[k as usize], 10), i32::from(index2));
                    dec_5p_5n(l_index, 4, 0, &mut pos);
                    add_pulses(&pos, 5, k, code);
                }
                for k in 2..4 {
                    let index2 = get_next_indice(st, 14) as i16;
                    let l_index = l_add(l_shl(ind1[k as usize], 14), i32::from(index2));
                    dec_4p_4n(l_index, 4, 0, &mut pos);
                    add_pulses(&pos, 4, k, code);
                }
            }
            88 => {
                for slot in &mut ind1 {
                    *slot = i32::from(get_next_indice(st, 11));
                }
                for k in 0..4 {
                    let index2 = get_next_indice(st, 11) as i16;
                    let l_index = l_add(l_shl(ind1[k as usize], 11), i32::from(index2));
                    dec_6p_6n2(l_index, 4, 0, &mut pos);
                    add_pulses(&pos, 6, k, code);
                }
            }
            _ => {}
        }
    }
}

/// `dec_1p_N1_fx`: decode one pulse coded with `N + 1` bits into `pos[0]`.
pub fn dec_1p_n1(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let mask = l_deposit_l(sub(shl(1, n), 1));
    let mut pos1 = add(extract_l(index & mask), offset);
    let i = l_shr(index, n) & 1;
    if i != 0 {
        pos1 = add(pos1, 16);
    }
    pos[0] = pos1;
}

/// `dec_3p_3N1_fx`: decode three pulses coded with `3·N + 1` bits into `pos[0..3]`.
fn dec_3p_3n1(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let tmp = sub(shl(n, 1), 1);
    let mask = l_sub(l_shl(1, tmp), 1);
    let idx = index & mask;
    let mut j = offset;
    let tmp = sub(shl(n, 1), 1);
    if l_shr(index, tmp) & 1 != 0 {
        j = add(j, shl(1, sub(n, 1)));
    }
    dec_2p_2n1(idx, sub(n, 1), j, pos);
    let mask = i32::from(sub(shl(1, add(n, 1)), 1));
    let tmp = shl(n, 1);
    let idx = l_shr(index, tmp) & mask;
    dec_1p_n1(idx, n, offset, &mut pos[2..]);
}

/// `dec_4p_4N1_fx`: decode four pulses coded with `4·N + 1` bits into `pos[0..4]`.
fn dec_4p_4n1(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let tmp = sub(shl(n, 1), 1);
    let mask = l_sub(l_shl(1, tmp), 1);
    let idx = index & mask;
    let mut j = offset;
    let tmp = sub(shl(n, 1), 1);
    if l_shr(index, tmp) & 1 != 0 {
        j = add(j, shl(1, sub(n, 1)));
    }
    dec_2p_2n1(idx, sub(n, 1), j, pos);
    let tmp = add(shl(n, 1), 1);
    let mask = l_sub(l_shl(1, tmp), 1);
    let idx = l_shr(index, shl(n, 1)) & mask;
    dec_2p_2n1(idx, n, offset, &mut pos[2..]);
}

/// `dec_4p_4N_fx`: decode four pulses coded with `4·N` bits into `pos[0..4]`.
fn dec_4p_4n(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let n_1 = sub(n, 1);
    let j = add(offset, shl(1, n_1));
    let tmp = sub(shl(n, 2), 2);
    match l_shr(index, tmp) & 3 {
        0 => {
            let tmp = add(shl(n_1, 2), 1);
            if l_shr(index, tmp) & 1 == 0 {
                dec_4p_4n1(index, n_1, offset, pos);
            } else {
                dec_4p_4n1(index, n_1, j, pos);
            }
        }
        1 => {
            let tmp = add(extract_l(l_shr(l_mult(3, n_1), 1)), 1);
            dec_1p_n1(l_shr(index, tmp), n_1, offset, pos);
            dec_3p_3n1(index, n_1, j, &mut pos[1..]);
        }
        2 => {
            let tmp = add(shl(n_1, 1), 1);
            dec_2p_2n1(l_shr(index, tmp), n_1, offset, pos);
            dec_2p_2n1(index, n_1, j, &mut pos[2..]);
        }
        _ => {
            let tmp = add(n_1, 1);
            dec_3p_3n1(l_shr(index, tmp), n_1, offset, pos);
            dec_1p_n1(index, n_1, j, &mut pos[3..]);
        }
    }
}

/// `dec_5p_5N_fx`: decode five pulses coded with `5·N` bits into `pos[0..5]`.
fn dec_5p_5n(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let n_1 = sub(n, 1);
    let j = add(offset, shl(1, n_1));
    let tmp = add(shl(n, 1), 1);
    let idx = l_shr(index, tmp);
    let tmp = sub(extract_l(l_shr(l_mult(5, n), 1)), 1);
    if l_shr(index, tmp) & 1 == 0 {
        dec_3p_3n1(idx, n_1, offset, pos);
    } else {
        dec_3p_3n1(idx, n_1, j, pos);
    }
    dec_2p_2n1(index, n, offset, &mut pos[3..]);
}

/// `dec_6p_6N2_fx`: decode six pulses coded with `6·N - 2` bits into `pos[0..6]`.
fn dec_6p_6n2(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let n_1 = sub(n, 1);
    let j = add(offset, shl(1, n_1));
    let n_6 = extract_l(l_mult0(n, 6));
    let mut offset_a = j;
    let mut offset_b = j;
    if l_shr(index, sub(n_6, 5)) & 1 == 0 {
        offset_a = offset;
    } else {
        offset_b = offset;
    }
    match l_shr(index, sub(n_6, 4)) & 3 {
        0 => {
            dec_5p_5n(l_shr(index, n), n_1, offset_a, pos);
            dec_1p_n1(index, n_1, offset_a, &mut pos[5..]);
        }
        1 => {
            dec_5p_5n(l_shr(index, n), n_1, offset_a, pos);
            dec_1p_n1(index, n_1, offset_b, &mut pos[5..]);
        }
        2 => {
            dec_4p_4n(l_shr(index, add(shl(n_1, 1), 1)), n_1, offset_a, pos);
            dec_2p_2n1(index, n_1, offset_b, &mut pos[4..]);
        }
        _ => {
            dec_3p_3n1(
                l_shr(index, add(add(shl(n_1, 1), n_1), 1)),
                n_1,
                offset,
                pos,
            );
            dec_3p_3n1(index, n_1, j, &mut pos[3..]);
        }
    }
}

/// `PI_select_table_fx[row][column]`, or `None` outside the table (a corrupt index; the reference
/// would read out of bounds).
fn pi_select(row: i32, column: i32) -> Option<i32> {
    PI_SELECT_TABLE_FX
        .get(usize::try_from(row).ok()?)?
        .get(usize::try_from(column).ok()?)
        .copied()
}

/// `add_pulses_fx`: add `nb_pulse` signed unit pulses (±512, Q9) at positions `pos` of track
/// `track` to `code`.
pub fn add_pulses(pos: &[i16], nb_pulse: i16, track: i16, code: &mut [i16]) {
    let track = track.max(0) as usize;
    for &position in pos.iter().take(nb_pulse.max(0) as usize) {
        // i = ((pos[k] & (NB_POS-1))*NB_TRACK) + track
        let i = shl(position & (NB_POS_FCB_4T - 1), 2) as usize;
        let sample = &mut code[track + i];
        *sample = if position & NB_POS_FCB_4T == 0 {
            add(*sample, 512)
        } else {
            sub(*sample, 512)
        };
    }
}

/// `dec_2p_2N1_fx`: decode two pulses coded with `2·N + 1` bits into `pos[0..2]`.
pub fn dec_2p_2n1(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let mask = l_deposit_l(sub(shl(1, n), 1)); // mask = ((1<<N)-1)
    let mut pos1 = extract_l(l_add(l_shr(index, n) & mask, l_deposit_l(offset)));
    let tmp = shl(n, 1);
    let i = l_shr(index, tmp) & 1;
    let mut pos2 = add(extract_l(index & mask), offset);
    if sub(pos2, pos1) < 0 {
        if i != 0 {
            pos1 = add(pos1, NB_POS_FCB_4T);
        } else {
            pos2 = add(pos2, NB_POS_FCB_4T);
        }
    } else if i != 0 {
        pos1 = add(pos1, NB_POS_FCB_4T);
        pos2 = add(pos2, NB_POS_FCB_4T);
    }
    pos[0] = pos1;
    pos[1] = pos2;
}

/// `fcb_decode_class_all_p_fx`: split the track index into the number of distinct positions
/// (`pos_num`), the pulses at each (`sector_6p_num`) and the index of the position set (returned).
fn fcb_decode_class_all_p(
    code_index: &mut i32,
    sector_6p_num: &mut [i16; 7],
    pulse_num: i16,
    pos_num: &mut i16,
) -> i32 {
    let offsets = &PI_OFFSET_FX[(pulse_num.max(0) as usize).min(PI_OFFSET_FX.len() - 1)];
    let mut i: i16 = 1;
    while i <= pulse_num && (i as usize) < offsets.len() {
        if l_sub(*code_index, offsets[i as usize]) < 0 {
            break;
        }
        i += 1;
    }
    *code_index = l_sub(*code_index, offsets[(i - 1).max(0) as usize]);

    let pulse_pos_num = add(sub(pulse_num, i), 2);
    let j = l_shr(*code_index, pulse_pos_num);
    let select = pi_select(16, i32::from(pulse_pos_num)).unwrap_or(1).max(1);
    let (k, mn9) = if l_sub(j, select) < 0 {
        (0, j)
    } else {
        let mut l_tmp: i32 = 0;
        let mut l_tmp1 = j;
        while l_sub(l_tmp1, select) >= 0 {
            l_tmp = l_add(l_tmp, 1);
            l_tmp1 = l_sub(l_tmp1, select);
        }
        (l_tmp, l_tmp1)
    };

    if sub(pulse_pos_num, pulse_num) < 0 && sub(pulse_pos_num, 1) > 0 {
        for count in sector_6p_num.iter_mut().take(pulse_pos_num as usize) {
            *count = 1;
        }
        // k < pulse_pos_num for every valid index
        if let Some(count) = usize::try_from(k)
            .ok()
            .and_then(|k| sector_6p_num.get_mut(k))
        {
            *count += 1;
        }
    } else if sub(pulse_pos_num, 1) == 0 {
        sector_6p_num[0] = pulse_num;
    } else {
        for count in sector_6p_num.iter_mut().take(pulse_num.max(0) as usize) {
            *count = 1;
        }
    }
    *pos_num = pulse_pos_num;
    mn9
}

/// `fcb_decode_position_fx`: decode the combinatorial index of `pos_num` distinct positions into
/// `pos_vector`. Stops early on an index no encoder produces.
fn fcb_decode_position(index: i32, pos_vector: &mut [i16; 7], pos_num: i16) {
    let mut k = index;
    let mut l: i32 = 0;
    let mut temp = i32::from(pos_num);
    let mut i = 0usize;
    while (i as i32) < i32::from(pos_num) - 1 && i < pos_vector.len() {
        let Some(select) = pi_select(16 - l, temp) else {
            return;
        };
        k = l_sub(select, k);
        loop {
            let Some(select) = pi_select(16 - l, temp) else {
                return;
            };
            if select < k {
                break;
            }
            l += 2;
        }
        let Some(select) = pi_select(l_sub(17, l), temp) else {
            return;
        };
        if l_sub(k, select) > 0 {
            l = l_sub(l, 1);
        }
        let Some(select) = pi_select(l_sub(17, l), temp) else {
            return;
        };
        temp -= 1;
        k = l_sub(select, k);
        pos_vector[i] = extract_l(l_sub(l, 1));
        i += 1;
    }
    if let Some(position) = pos_vector.get_mut(i) {
        *position = extract_l(l_add(l, k));
    }
}

/// `fcb_decode_PI_fx`: decode the `pulse_num` pulse positions of one track (with repeats) from
/// `code_index` into `sector_6p`; returns the number of distinct positions.
fn fcb_decode_pi(code_index: i32, sector_6p: &mut [i16; 7], pulse_num: i16) -> i32 {
    let mut code_index = code_index;
    let mut sector_6p_temp = [0i16; 7];
    let mut sector_6p_num_temp = [0i16; 7];
    let mut pulse_pos_num: i16 = 0;

    // get the position number and the pulse number on every position
    let mn9 = fcb_decode_class_all_p(
        &mut code_index,
        &mut sector_6p_num_temp,
        pulse_num,
        &mut pulse_pos_num,
    );
    // decode the pulse position not same to the others
    fcb_decode_position(mn9, &mut sector_6p_temp, pulse_pos_num);
    let ppn = (pulse_pos_num.max(0) as usize).min(7);
    for i in (0..ppn).rev() {
        sector_6p_temp[i] = add(sector_6p_temp[i], extract_l(l_shl(code_index & 0x1, 4)));
        code_index = l_shr(code_index, 1);
    }
    // decode the pulse position maybe some pulse position same to other pulse
    let mut ptr0 = (pulse_num.max(0) as usize).min(7);
    let mut ptr1 = ppn;
    for i in 0..ppn {
        ptr1 -= 1;
        let j = ppn - 1 - i;
        for _ in 0..sector_6p_num_temp[j].max(0) {
            if ptr0 == 0 {
                break;
            }
            ptr0 -= 1;
            sector_6p[ptr0] = sector_6p_temp[ptr1];
        }
    }
    i32::from(pulse_pos_num)
}

/// `D_ACELP_decode_43bit`: decode the 43-bit 4-track codebook index `idxs[0..3]` (16-bit words,
/// least significant first) into `code[0..L_SUBFR]` with `pulsestrack[t]` pulses on track `t`.
pub fn d_acelp_decode_43bit(idxs: &[u16], code: &mut [i16], pulsestrack: &[i16]) {
    let mut ps = [0i32; 8];
    let mut pos = [0i16; 7];
    let joint_offset: i32 = 3_611_648; // offset for 3 pulses per track

    set16(code, 0, L_SUBFR);

    ps[3] = l_deposit_l((idxs[0] as i16) & 0x1ff);
    ps[2] = l_add(
        l_shl(i32::from((idxs[1] as i16) & 3), 7),
        l_shr(i32::from(idxs[0]), 9),
    );
    let mut joint_index = l_shr(l_add(l_shl(i32::from(idxs[2]), 16), i32::from(idxs[1])), 2);
    if l_sub(joint_index, joint_offset) >= 0 {
        joint_index = l_sub(joint_index, joint_offset);
    }

    let (mut quotient, mut remainder) = (0, 0);
    idiv_and_mod_32(joint_index, 5472, &mut quotient, &mut remainder, 0);
    ps[0] = quotient;
    ps[1] = remainder;
    fcb_decode_pi(ps[0], &mut pos, 3);
    add_pulses(&pos, pulsestrack[0].min(7), 0, code);
    fcb_decode_pi(ps[1], &mut pos, 3);
    add_pulses(&pos, pulsestrack[1].min(7), 1, code);

    dec_2p_2n1(ps[2], 4, 0, &mut pos);
    add_pulses(&pos, pulsestrack[2].min(7), 2, code);
    dec_2p_2n1(ps[3], 4, 0, &mut pos);
    add_pulses(&pos, pulsestrack[3].min(7), 3, code);
}
