//! AMR-WB algebraic (fixed) codebook decoders (3GPP TS 26.173), ported bit-exact.
//!
//! The fixed codebook places a small number of unit pulses (±1) on interleaved tracks of the
//! 64-sample subframe; the bitstream index encodes each pulse's position and sign. Mode 0 (6.60
//! kbit/s) uses the 2-pulse decoder [`dec_acelp_2t64`] (`d2t64fx.c`); the higher modes use the
//! 4-track decoder [`dec_acelp_4t64`] (`d4t64fx.c` + `q_pulse.c`). Output is Q9 (±512 = ±1.0).

use crate::amr::basic_ops::{add, extract_l, l_add, l_deposit_l, l_shl, l_shr, shl, shr, sub};

/// Codevector length (one subframe).
const L_CODE: usize = 64;
/// Positions per track (mode-0 2t64 sign-bit mask value, `0x20`).
const NB_POS_2T: i16 = 32;
/// Number of tracks in the 4-track codebook.
const NB_TRACK: usize = 4;
/// Positions per track in the 4-track codebook; also the sign-bit mask (`q_pulse.c` `NB_POS`).
const NB_POS_4T: i16 = 16;

/// Decode the 12-bit 2-pulse algebraic codebook index into a Q9 codevector (`DEC_ACELP_2t64_fx`):
/// two ±1 pulses, one on the even-position track and one on the odd-position track, 32 positions
/// each. `code` must be at least 64 samples; it is fully overwritten.
pub fn dec_acelp_2t64(index: i16, code: &mut [i16]) {
    for value in code.iter_mut().take(L_CODE) {
        *value = 0;
    }

    // Pulse 0 on the even track, pulse 1 on the odd track.
    let i0 = (shr(index, 5) & 0x003E) as usize;
    let i1 = add(shl(index & 0x001F, 1), 1) as usize;

    code[i0] = if (shr(index, 6) & NB_POS_2T) == 0 {
        512
    } else {
        -512
    };
    code[i1] = if (index & NB_POS_2T) == 0 { 512 } else { -512 };
}

/// Decode 1 pulse encoded with `N+1` bits (`q_pulse.c` `dec_1p_N1`), writing `pos[0]`.
fn dec_1p_n1(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let mask = l_deposit_l(sub(shl(1, n), 1)); // ((1<<N)-1)
    let mut pos1 = add(extract_l(index & mask), offset);
    let i = l_shr(index, n) & 1; // (index >> N) & 1
    if i == 1 {
        pos1 = add(pos1, NB_POS_4T);
    }
    pos[0] = pos1;
}

/// Decode 2 pulses encoded with `2*N+1` bits (`q_pulse.c` `dec_2p_2N1`), writing `pos[0..2]`.
fn dec_2p_2n1(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let mask = l_deposit_l(sub(shl(1, n), 1)); // ((1<<N)-1)
                                               // pos1 = (((index >> N) & mask) + offset)
    let mut pos1 = extract_l(l_add(l_shr(index, n) & mask, l_deposit_l(offset)));
    let tmp = shl(n, 1);
    let i = l_shr(index, tmp) & 1; // (index >> (2*N)) & 1
    let mut pos2 = add(extract_l(index & mask), offset); // (index & mask) + offset
    if sub(pos2, pos1) < 0 {
        if i == 1 {
            pos1 = add(pos1, NB_POS_4T);
        } else {
            pos2 = add(pos2, NB_POS_4T);
        }
    } else if i == 1 {
        pos1 = add(pos1, NB_POS_4T);
        pos2 = add(pos2, NB_POS_4T);
    }
    pos[0] = pos1;
    pos[1] = pos2;
}

/// Decode 3 pulses encoded with `3*N+1` bits (`q_pulse.c` `dec_3p_3N1`), writing `pos[0..3]`.
fn dec_3p_3n1(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let tmp = sub(shl(n, 1), 1); // (2*N)-1
    let mask = l_sub32(l_shl(1, tmp), 1); // ((1<<((2*N)-1))-1)
    let idx = index & mask;
    let mut j = offset;
    if (l_shr(index, tmp) & 1) != 0 {
        j = add(j, shl(1, sub(n, 1))); // j += (1<<(N-1))
    }
    dec_2p_2n1(idx, sub(n, 1), j, pos);

    let mask = sub(shl(1, add(n, 1)), 1); // ((1<<(N+1))-1)
    let tmp = shl(n, 1);
    let idx = l_shr(index, tmp) & l_deposit_l(mask); // (index >> (2*N)) & mask
    dec_1p_n1(idx, n, offset, &mut pos[2..]);
}

/// Decode 4 pulses encoded with `4*N+1` bits (`q_pulse.c` `dec_4p_4N1`), writing `pos[0..4]`.
fn dec_4p_4n1(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let tmp = sub(shl(n, 1), 1); // (2*N)-1
    let mask = l_sub32(l_shl(1, tmp), 1);
    let idx = index & mask;
    let mut j = offset;
    if (l_shr(index, tmp) & 1) != 0 {
        j = add(j, shl(1, sub(n, 1)));
    }
    dec_2p_2n1(idx, sub(n, 1), j, pos);

    let tmp = add(shl(n, 1), 1); // (2*N)+1
    let mask = l_sub32(l_shl(1, tmp), 1);
    let idx = l_shr(index, shl(n, 1)) & mask; // (index >> (2*N)) & mask
    dec_2p_2n1(idx, n, offset, &mut pos[2..]);
}

/// Decode 4 pulses encoded with `4*N` bits (`q_pulse.c` `dec_4p_4N`), writing `pos[0..4]`.
fn dec_4p_4n(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let n_1 = sub(n, 1);
    let j = add(offset, shl(1, n_1)); // offset + (1 << n_1)

    let tmp = sub(shl(n, 2), 2); // (4*N)-2
    match l_shr(index, tmp) & 3 {
        0 => {
            let tmp = add(shl(n_1, 2), 1); // (4*n_1)+1
            if (l_shr(index, tmp) & 1) == 0 {
                dec_4p_4n1(index, n_1, offset, pos);
            } else {
                dec_4p_4n1(index, n_1, j, pos);
            }
        }
        1 => {
            // tmp = (3*n_1)+1
            let tmp = add(extract_l(l_shr(l_mult_pos(3, n_1), 1)), 1);
            dec_1p_n1(l_shr(index, tmp), n_1, offset, pos);
            dec_3p_3n1(index, n_1, j, &mut pos[1..]);
        }
        2 => {
            let tmp = add(shl(n_1, 1), 1); // (2*n_1)+1
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

/// Decode 5 pulses encoded with `5*N` bits (`q_pulse.c` `dec_5p_5N`), writing `pos[0..5]`.
fn dec_5p_5n(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let n_1 = sub(n, 1);
    let j = add(offset, shl(1, n_1)); // offset + (1 << n_1)
    let tmp = add(shl(n, 1), 1); // (2*N)+1
    let idx = l_shr(index, tmp); // index >> ((2*N)+1)
    let tmp = sub(extract_l(l_shr(l_mult_pos(5, n), 1)), 1); // (5*N)-1

    if (l_shr(index, tmp) & 1) == 0 {
        dec_3p_3n1(idx, n_1, offset, pos);
        dec_2p_2n1(index, n, offset, &mut pos[3..]);
    } else {
        dec_3p_3n1(idx, n_1, j, pos);
        dec_2p_2n1(index, n, offset, &mut pos[3..]);
    }
}

/// Decode 6 pulses encoded with `6*N-2` bits (`q_pulse.c` `dec_6p_6N_2`), writing `pos[0..6]`.
fn dec_6p_6n_2(index: i32, n: i16, offset: i16, pos: &mut [i16]) {
    let n_1 = sub(n, 1);
    let j = add(offset, shl(1, n_1)); // offset + (1 << n_1)

    // N and n_1 are constants; the 6*N-… shift amounts fit i16.
    let mut offset_a = j;
    let mut offset_b = j;
    if (l_shr(index, 6 * n - 5) & 1) == 0 {
        offset_a = offset;
    } else {
        offset_b = offset;
    }

    match l_shr(index, 6 * n - 4) & 3 {
        0 => {
            dec_5p_5n(l_shr(index, n), n_1, offset_a, pos);
            dec_1p_n1(index, n_1, offset_a, &mut pos[5..]);
        }
        1 => {
            dec_5p_5n(l_shr(index, n), n_1, offset_a, pos);
            dec_1p_n1(index, n_1, offset_b, &mut pos[5..]);
        }
        2 => {
            dec_4p_4n(l_shr(index, 2 * n_1 + 1), n_1, offset_a, pos);
            dec_2p_2n1(index, n_1, offset_b, &mut pos[4..]);
        }
        _ => {
            dec_3p_3n1(l_shr(index, 3 * n_1 + 1), n_1, offset, pos);
            dec_3p_3n1(index, n_1, j, &mut pos[3..]);
        }
    }
}

/// Place `nb_pulse` ±1 pulses of a track into the interleaved codevector (`d4t64fx.c` `add_pulses`):
/// `i = (pos & (NB_POS-1))*NB_TRACK + track`; sign from the `NB_POS` bit, amplitude ±512 (Q9).
fn add_pulses(pos: &[i16], nb_pulse: usize, track: i16, code: &mut [i16]) {
    for &p in pos.iter().take(nb_pulse) {
        let i = add(shl(p & (NB_POS_4T - 1), 2), track) as usize;
        if (p & NB_POS_4T) == 0 {
            code[i] = add(code[i], 512);
        } else {
            code[i] = sub(code[i], 512);
        }
    }
}

/// Decode the 4-track algebraic codebook index set into a Q9 codevector (`DEC_ACELP_4t64_fx`).
///
/// `nbbits` selects the per-track pulse budget: 20 (1 pulse/track, modes 1), 36 (2/track, mode 2),
/// 44 (3+3+2+2, mode 3), 52 (3/track, mode 4), 64 (4/track, mode 5), 72 (5+5+4+4, mode 6) or
/// 88 (6/track, modes 7/8). `index` holds the per-track indices (4 or 8 entries) and `code` (≥64)
/// is fully overwritten. 4 tracks × 16 positions = 64 samples.
///
/// The per-track loops index `index[k]` and `index[k + NB_TRACK]` against the track number `k`, so
/// the `needless_range_loop` lint does not apply (two arrays at a fixed offset, plus the track id).
#[allow(clippy::needless_range_loop)]
pub fn dec_acelp_4t64(index: &[i16], nbbits: i16, code: &mut [i16]) {
    for value in code.iter_mut().take(L_CODE) {
        *value = 0;
    }
    let mut pos = [0i16; 6];

    match nbbits {
        20 => {
            for k in 0..NB_TRACK {
                let l_index = l_deposit_l(index[k]);
                dec_1p_n1(l_index, 4, 0, &mut pos);
                add_pulses(&pos, 1, k as i16, code);
            }
        }
        36 => {
            for k in 0..NB_TRACK {
                let l_index = l_deposit_l(index[k]);
                dec_2p_2n1(l_index, 4, 0, &mut pos);
                add_pulses(&pos, 2, k as i16, code);
            }
        }
        44 => {
            for k in 0..(NB_TRACK - 2) {
                let l_index = l_deposit_l(index[k]);
                dec_3p_3n1(l_index, 4, 0, &mut pos);
                add_pulses(&pos, 3, k as i16, code);
            }
            for k in 2..NB_TRACK {
                let l_index = l_deposit_l(index[k]);
                dec_2p_2n1(l_index, 4, 0, &mut pos);
                add_pulses(&pos, 2, k as i16, code);
            }
        }
        52 => {
            for k in 0..NB_TRACK {
                let l_index = l_deposit_l(index[k]);
                dec_3p_3n1(l_index, 4, 0, &mut pos);
                add_pulses(&pos, 3, k as i16, code);
            }
        }
        64 => {
            for k in 0..NB_TRACK {
                // L_index = (index[k] << 14) + index[k+NB_TRACK]
                let l_index = l_add(
                    l_shl(l_deposit_l(index[k]), 14),
                    l_deposit_l(index[k + NB_TRACK]),
                );
                dec_4p_4n(l_index, 4, 0, &mut pos);
                add_pulses(&pos, 4, k as i16, code);
            }
        }
        72 => {
            for k in 0..(NB_TRACK - 2) {
                let l_index = l_add(
                    l_shl(l_deposit_l(index[k]), 10),
                    l_deposit_l(index[k + NB_TRACK]),
                );
                dec_5p_5n(l_index, 4, 0, &mut pos);
                add_pulses(&pos, 5, k as i16, code);
            }
            for k in 2..NB_TRACK {
                let l_index = l_add(
                    l_shl(l_deposit_l(index[k]), 14),
                    l_deposit_l(index[k + NB_TRACK]),
                );
                dec_4p_4n(l_index, 4, 0, &mut pos);
                add_pulses(&pos, 4, k as i16, code);
            }
        }
        88 => {
            for k in 0..NB_TRACK {
                let l_index = l_add(
                    l_shl(l_deposit_l(index[k]), 11),
                    l_deposit_l(index[k + NB_TRACK]),
                );
                dec_6p_6n_2(l_index, 4, 0, &mut pos);
                add_pulses(&pos, 6, k as i16, code);
            }
        }
        _ => {}
    }
}

/// 32-bit subtract without saturation (the index math in `q_pulse.c` is plain `Word32`).
#[inline]
fn l_sub32(a: i32, b: i32) -> i32 {
    a - b
}

/// 16-bit multiply of two non-negative small constants into Q0 `Word32` (`L_mult(3,n)` style):
/// the reference's `L_mult` doubles the product; the callers always pass `L_shr(.,1)` to undo it,
/// so we reproduce `(a*b) << 1` here exactly.
#[inline]
fn l_mult_pos(a: i16, b: i16) -> i32 {
    ((a as i32) * (b as i32)) << 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pulses(code: &[i16]) -> Vec<(usize, i16)> {
        code.iter()
            .enumerate()
            .filter(|(_, &v)| v != 0)
            .map(|(i, &v)| (i, v))
            .collect()
    }

    #[test]
    fn index_zero_places_two_positive_pulses() {
        let mut code = [0i16; 64];
        dec_acelp_2t64(0, &mut code);
        assert_eq!(pulses(&code), vec![(0, 512), (1, 512)]);
    }

    #[test]
    fn sign_bits_flip_the_pulse_amplitudes() {
        // index 0x20: bit5 set → pulse 1 negative; pulse positions still 0 and 1.
        let mut code = [0i16; 64];
        dec_acelp_2t64(0x20, &mut code);
        assert_eq!(pulses(&code), vec![(0, 512), (1, -512)]);

        // index 0x800: bit11 set → pulse 0 negative.
        let mut code = [0i16; 64];
        dec_acelp_2t64(0x800, &mut code);
        assert_eq!(pulses(&code), vec![(0, -512), (1, 512)]);
    }

    #[test]
    fn position_bits_move_the_even_track_pulse() {
        // index 0x80: (0x80>>5)&0x3E = 4 → pulse 0 at position 4; pulse 1 stays at 1.
        let mut code = [0i16; 64];
        dec_acelp_2t64(0x80, &mut code);
        assert_eq!(pulses(&code), vec![(1, 512), (4, 512)]);
    }

    #[test]
    fn pulses_are_always_on_their_track_parity() {
        // Every index yields exactly one even-track and one odd-track pulse, both ±512.
        for index in 0..4096i16 {
            let mut code = [0i16; 64];
            dec_acelp_2t64(index, &mut code);
            let found = pulses(&code);
            assert_eq!(found.len(), 2, "two pulses for {index}");
            let positions: Vec<usize> = found.iter().map(|(p, _)| *p).collect();
            assert!(
                positions.iter().any(|p| p % 2 == 0),
                "even pulse for {index}"
            );
            assert!(
                positions.iter().any(|p| p % 2 == 1),
                "odd pulse for {index}"
            );
            assert!(found.iter().all(|(_, v)| v.abs() == 512));
        }
    }

    /// All pulses placed by `add_pulses` for track `k` land on positions `≡ k (mod 4)`.
    #[test]
    fn four_track_pulses_respect_track_interleave() {
        // 20-bit mode: 4 indices, one pulse per track. Pulse on track k sits at index%4 == k.
        let mut code = [0i16; 64];
        dec_acelp_4t64(&[0, 0, 0, 0], 20, &mut code);
        let found = pulses(&code);
        assert_eq!(found.len(), 4, "one pulse per track");
        for (track, &(p, v)) in found.iter().enumerate() {
            // With index 0, pos = 0 + offset 0, so each pulse lands at position == track.
            assert_eq!(p % 4, track, "track {track} pulse at {p}");
            assert_eq!(v, 512);
        }
    }

    /// The 36-bit (mode-2) path decodes 8 pulses (2 per track), all ±512 on the right tracks.
    #[test]
    fn thirty_six_bit_mode_decodes_eight_pulses() {
        // Use distinct per-track indices so we exercise the position/sign unpacking.
        let mut code = [0i16; 64];
        dec_acelp_4t64(&[0x12, 0x55, 0x1AA, 0x0FF], 36, &mut code);
        let found = pulses(&code);
        // Two pulses per track, but two pulses may coincide and sum to ±1024 or cancel to 0.
        let total: i32 = found.iter().map(|(_, v)| (v.abs() as i32) / 512).sum();
        assert!(
            total <= 8 && total > 0,
            "at most 8 unit pulses, got {total}"
        );
        // Every non-zero sample is a multiple of 512 in [-1024, 1024].
        assert!(found.iter().all(|(_, v)| v.abs() == 512 || v.abs() == 1024));
    }

    /// Every 4t64 budget decodes without panicking and stays within the codevector bounds.
    #[test]
    fn four_track_budgets_never_panic() {
        let budgets: [(i16, usize); 7] = [
            (20, 4),
            (36, 4),
            (44, 4),
            (52, 4),
            (64, 8),
            (72, 8),
            (88, 8),
        ];
        for (nbbits, nind) in budgets {
            for seed in 0..64i16 {
                let index: Vec<i16> = (0..nind)
                    .map(|i| (seed * 7 + i as i16 * 13) & 0x3FFF)
                    .collect();
                let mut code = [0i16; 64];
                dec_acelp_4t64(&index, nbbits, &mut code);
                assert!(code.iter().all(|&v| v.abs() <= 6 * 512), "nbbits {nbbits}");
            }
        }
    }
}
