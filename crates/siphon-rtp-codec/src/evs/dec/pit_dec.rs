//! Pitch lag decoding for the MODE1 ACELP core (TS 26.442 `lib_dec/pit_dec.c`; TS 26.445
//! §6.1.1.3.1, §7.1.2.1). The MODE2 functions of the same file (`Mode2_pit_decode`, ...) are not
//! ported here.

use crate::evs::cnst::{
    ACELP_13K20, ACELP_7K20, ACELP_8K85, AUDIO, GENERIC, L_FRAME, L_FRAME16K, L_SUBFR,
    PIT16K_FR1_EXTEND_9B, PIT16K_FR2_EXTEND_10B, PIT16K_FR2_EXTEND_9B, PIT16K_MAX,
    PIT16K_MIN_EXTEND, PIT_DECODE_1, PIT_DECODE_10, PIT_DECODE_2, PIT_DECODE_2XL_SUBFR,
    PIT_DECODE_3, PIT_DECODE_7, PIT_DECODE_8, PIT_DECODE_9,
    PIT_FR1_8B_MINUS_PIT_FR1_8B_MINUS_PIT_MIN_X2, PIT_FR1_8B_MINUS_PIT_MIN_X2,
    PIT_FR1_DEXT8B_MINUS_PIT_MIN_DEXT_X2, PIT_FR1_EXT8B_MINUS_PIT_MIN_EXT_X2,
    PIT_FR1_EXT9B_MINUS_PIT_FR2_EXT9B_X2, PIT_FR1_EXTEND_8B, PIT_FR2_9B,
    PIT_FR2_9B_MINUS_PIT_MIN_X4, PIT_FR2_DEXT9B_MINUS_PIT_MIN_DEXT_X4, PIT_FR2_DOUBLEEXTEND_9B,
    PIT_FR2_EXT9B_MINUS_PIT_MIN_EXT_X4, PIT_FR2_EXTEND_9B, PIT_MAX, PIT_MIN, PIT_MIN_16K,
    PIT_MIN_DOUBLEEXTEND, PIT_MIN_EXTEND, VOICED,
};
use crate::evs::com::bitstream::{bit_alloc_idx, bit_alloc_idx_16khz, get_next_indice};
use crate::evs::com::limit_t0::limit_t0;
use crate::evs::com::limit_t0::limit_t0_voiced;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{ACB_BITS_16KHZ_TBL, ACB_BITS_TBL, INVINTTABLE};
use crate::itu::basic_ops::{add, l_deposit_h, l_mac, mult, shl, shr, sub};
use crate::itu::stl2009::i_mult;

/// `ACB_bits_tbl[index]` / `ACB_bits_16kHz_tbl[index]`. The index comes from the bit rate and the
/// bitstream's coder type; a combination the codec never signals (a corrupted coder type) can lie
/// past the table, where the reference reads out of bounds. Reading no bits there is the safe
/// equivalent.
fn acb_bits(table: &[i16], index: i32) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or(0)
}

/// `T0 << 2` as the reference writes it: a C shift in `int`, truncated to `Word16` by the `add` it
/// feeds.
fn lag_q2(t0: i16) -> i16 {
    (i32::from(t0) << 2) as i16
}

/// `pit_decode_fx`: read and decode the pitch lag of one subframe; returns the pitch in Q6. Updates
/// `limit_flag` and the delta-search window `[T0_min, T0_max]` the next subframes decode against.
pub fn pit_decode(
    st: &mut DecoderState,
    core_brate: i32,
    opt_amr_wb: i16,
    l_frame: i16,
    i_subfr: i16,
    coder_type: i16,
    limit_flag: &mut i16,
    t0: &mut i16,
    t0_frac: &mut i16,
    t0_min: &mut i16,
    t0_max: &mut i16,
    l_subfr: i16,
) -> i16 {
    let mut pitch_index: i16 = 0;

    // Set pit_flag = 0 for every subframe with absolute pitch search
    let mut pit_flag = i_subfr;
    if i_subfr == PIT_DECODE_2XL_SUBFR {
        pit_flag = 0;
    }

    if opt_amr_wb == 0 {
        // pitch Q: limit_flag 0 for restrained limits, 1 for extended, 2 for double-extended
        if i_subfr == 0 {
            *limit_flag = 1;
            if coder_type == VOICED {
                *limit_flag = 2; // double-extended limits
            }
            if coder_type == GENERIC && core_brate == i32::from(ACELP_7K20) {
                *limit_flag = 0;
            }
        } else if i_subfr == 2 * L_SUBFR
            && coder_type == GENERIC
            && core_brate <= i32::from(ACELP_13K20)
            && sub(*t0, shr(add(PIT_FR1_EXTEND_8B, PIT_MIN), 1)) > 0
        {
            *limit_flag = 0;
        }

        // Retrieve the number of Q bits
        let mut n_bits: i16 = 0;
        if coder_type != AUDIO {
            n_bits = if l_frame == L_FRAME {
                acb_bits(
                    &ACB_BITS_TBL,
                    bit_alloc_idx(core_brate, coder_type, i_subfr, 0),
                )
            } else {
                acb_bits(
                    &ACB_BITS_16KHZ_TBL,
                    bit_alloc_idx_16khz(core_brate, coder_type, i_subfr, 0),
                )
            };
            pitch_index = get_next_indice(st, n_bits) as i16;
        }

        if coder_type == AUDIO {
            // Pitch decoding in AUDIO mode (both ACELP@12k8 and ACELP@16k cores)
            if l_subfr == L_FRAME / 2 && i_subfr != 0 {
                pit_flag = L_SUBFR;
            }
            n_bits = if pit_flag == 0 { 10 } else { 6 };
            pitch_index = get_next_indice(st, n_bits) as i16;
            if l_subfr == L_FRAME / 2 && i_subfr != 0 && pitch_index >= 32 {
                // safety check in case of bit errors
                pitch_index = shr(pitch_index, 1);
                st.ber_detect = 1;
            }
            pit_q_dec(
                0,
                pitch_index,
                n_bits,
                4,
                pit_flag,
                *limit_flag,
                t0,
                t0_frac,
                t0_min,
                t0_max,
                &mut st.ber_detect,
            );
        } else if coder_type == VOICED {
            // Pitch decoding in VOICED mode (ACELP@12k8 core only)
            if i_subfr == 2 * L_SUBFR {
                pit_flag = i_subfr;
            }
            pit_q_dec(
                0,
                pitch_index,
                n_bits,
                4,
                pit_flag,
                *limit_flag,
                t0,
                t0_frac,
                t0_min,
                t0_max,
                &mut st.ber_detect,
            );
        } else if l_frame == L_FRAME {
            // Pitch decoding in GENERIC mode (both ACELP@12k8 and ACELP@16k cores)
            pit_q_dec(
                0,
                pitch_index,
                n_bits,
                8,
                pit_flag,
                *limit_flag,
                t0,
                t0_frac,
                t0_min,
                t0_max,
                &mut st.ber_detect,
            );
        } else {
            pit16k_q_dec(
                pitch_index,
                n_bits,
                *limit_flag,
                t0,
                t0_frac,
                t0_min,
                t0_max,
                &mut st.ber_detect,
            );
        }
    } else {
        // Pitch decoding in AMR-WB IO mode
        *limit_flag = 0;
        let acelp_8k85 = i32::from(ACELP_8K85);
        let mut n_bits = if i_subfr == 0 || (i_subfr == 2 * L_SUBFR && core_brate == acelp_8k85) {
            8
        } else {
            5
        };
        if core_brate > acelp_8k85 {
            n_bits = 6;
            if i_subfr == 0 || i_subfr == 2 * L_SUBFR {
                n_bits = 9;
            }
        }
        pitch_index = get_next_indice(st, n_bits) as i16;
        pit_q_dec(
            1,
            pitch_index,
            n_bits,
            8,
            pit_flag,
            *limit_flag,
            t0,
            t0_frac,
            t0_min,
            t0_max,
            &mut st.ber_detect,
        );
    }

    // Compute floating pitch output: save subframe pitch values Q6
    shl(add(shl(*t0, 2), *t0_frac), 4)
}

/// `pit_Q_dec_fx`: decode a pitch index of `n_bits` bits (absolute at 10/9/8 bits, relative to
/// `T0_min` at 6/5/4) and update the delta-search window.
pub fn pit_q_dec(
    opt_amr_wb: i16,
    pitch_index: i16,
    n_bits: i16,
    delta: i16,
    pit_flag: i16,
    limit_flag: i16,
    t0: &mut i16,
    t0_frac: &mut i16,
    t0_min: &mut i16,
    t0_max: &mut i16,
    ber_detect: &mut i16,
) {
    match n_bits {
        10 => {
            // absolute decoding with 10 bits
            let base = match limit_flag {
                0 => PIT_MIN,
                1 => PIT_MIN_EXTEND,
                _ => PIT_MIN_DOUBLEEXTEND,
            };
            *t0 = add(base, shr(pitch_index, 2));
            *t0_frac = sub(pitch_index, shl(sub(*t0, base), 2));
        }
        9 | 8 => {
            // absolute decoding with 9 / 8 bits
            abs_pit_dec(
                if n_bits == 9 { 4 } else { 2 },
                pitch_index,
                limit_flag,
                t0,
                t0_frac,
            );
            // find T0_min and T0_max for delta search
            if opt_amr_wb != 0 {
                // T0_frac==0 to keep IO with AMR-WB
                (*t0_min, *t0_max) = limit_t0(L_FRAME, delta, pit_flag, 0, *t0, 0);
            }
        }
        // relative decoding with 6 bits
        6 => delta_pit_dec(4, pitch_index, t0, t0_frac, *t0_min),
        // relative decoding with 5 bits
        5 => delta_pit_dec(
            if delta == 8 { 2 } else { 4 },
            pitch_index,
            t0,
            t0_frac,
            *t0_min,
        ),
        // nBits == 4: relative decoding with 4 bits
        _ => delta_pit_dec(
            if delta == 8 { 0 } else { 2 },
            pitch_index,
            t0,
            t0_frac,
            *t0_min,
        ),
    }

    // biterror detection mechanism
    if sub(add(lag_q2(*t0), *t0_frac), add(PIT_MAX << 2, 2)) > 0 && pit_flag == 0 && opt_amr_wb == 0
    {
        *t0 = L_SUBFR;
        *t0_frac = 0;
        *ber_detect = 1;
    }

    if opt_amr_wb == 0 {
        // find T0_min and T0_max for delta search
        (*t0_min, *t0_max) = limit_t0(L_FRAME, delta, L_SUBFR, limit_flag, *t0, *t0_frac);
    }
}

/// `pit16k_Q_dec_fx`: pitch decoding for the 16 kHz core.
pub fn pit16k_q_dec(
    pitch_index: i16,
    n_bits: i16,
    limit_flag: i16,
    t0: &mut i16,
    t0_frac: &mut i16,
    t0_min: &mut i16,
    t0_max: &mut i16,
    ber_detect: &mut i16,
) {
    if n_bits == 10 {
        // absolute decoding with 10 bits
        let fr2_offset = (PIT16K_FR2_EXTEND_10B - PIT16K_MIN_EXTEND) << 2;
        if sub(pitch_index, fr2_offset) < 0 {
            *t0 = add(PIT16K_MIN_EXTEND, shr(pitch_index, 2));
            *t0_frac = sub(pitch_index, shl(sub(*t0, PIT16K_MIN_EXTEND), 2));
        } else {
            let index = sub(pitch_index, fr2_offset);
            *t0 = add(PIT16K_FR2_EXTEND_10B, shr(index, 1));
            *t0_frac = sub(index, shl(sub(*t0, PIT16K_FR2_EXTEND_10B), 1));
            *t0_frac = shl(*t0_frac, 1);
        }
    } else if n_bits == 9 {
        // absolute decoding with 9 bits
        let fr2_offset = (PIT16K_FR2_EXTEND_9B - PIT16K_MIN_EXTEND) * 4;
        let fr1_offset = fr2_offset + (PIT16K_FR1_EXTEND_9B - PIT16K_FR2_EXTEND_9B) * 2;
        if sub(pitch_index, fr2_offset) < 0 {
            *t0 = add(PIT16K_MIN_EXTEND, shr(pitch_index, 2));
            *t0_frac = sub(pitch_index, shl(sub(*t0, PIT16K_MIN_EXTEND), 2));
        } else if sub(pitch_index, fr1_offset) < 0 {
            let index = sub(pitch_index, fr2_offset);
            *t0 = add(PIT16K_FR2_EXTEND_9B, shr(index, 1));
            *t0_frac = sub(index, shl(sub(*t0, PIT16K_FR2_EXTEND_9B), 1));
            // The reference writes `(*T0_frac) *= shl((*T0_frac),1);`, a plain C multiply by the
            // shifted value (not a doubling): 0 stays 0 and 1 becomes 2.
            *t0_frac = t0_frac.wrapping_mul(shl(*t0_frac, 1));
        } else {
            *t0 = add(pitch_index, PIT16K_FR1_EXTEND_9B - fr1_offset);
            *t0_frac = 0;
        }
    } else {
        // nBits == 6: relative decoding with 6 bits
        delta_pit_dec(4, pitch_index, t0, t0_frac, *t0_min);
    }

    // biterror detection mechanism
    if sub(add(lag_q2(*t0), *t0_frac), PIT16K_MAX << 2) > 0 && n_bits >= 9 {
        *t0 = L_SUBFR;
        *t0_frac = 0;
        *ber_detect = 1;
    }

    // find T0_min and T0_max for delta search
    (*t0_min, *t0_max) = limit_t0(L_FRAME16K, 8, L_SUBFR, limit_flag, *t0, *t0_frac);
}

/// `abs_pit_dec_fx`: absolute pitch decoding at fractional resolution `fr_steps` (2 or 4; the
/// reference leaves the outputs untouched for 0, which the codec never uses).
pub fn abs_pit_dec(
    fr_steps: i16,
    mut pitch_index: i16,
    limit_flag: i16,
    t0: &mut i16,
    t0_frac: &mut i16,
) {
    if limit_flag == 0 {
        if fr_steps == 2 {
            if sub(pitch_index, PIT_FR1_8B_MINUS_PIT_MIN_X2) < 0 {
                *t0 = add(PIT_MIN, shr(pitch_index, 1));
                let temp = shl(sub(*t0, PIT_MIN), 1);
                *t0_frac = shl(sub(pitch_index, temp), 1);
            } else {
                *t0 = add(pitch_index, PIT_FR1_8B_MINUS_PIT_FR1_8B_MINUS_PIT_MIN_X2);
                *t0_frac = 0;
            }
        } else if fr_steps == 4 {
            if sub(pitch_index, PIT_FR2_9B_MINUS_PIT_MIN_X4) < 0 {
                *t0 = add(PIT_MIN, shr(pitch_index, 2));
                let temp = shl(sub(*t0, PIT_MIN), 2);
                *t0_frac = sub(pitch_index, temp);
            } else if sub(pitch_index, PIT_DECODE_1) < 0 {
                pitch_index = sub(pitch_index, PIT_DECODE_2);
                *t0 = add(PIT_FR2_9B, shr(pitch_index, 1));
                let temp = shl(sub(*t0, PIT_FR2_9B), 1);
                *t0_frac = shl(sub(pitch_index, temp), 1);
            } else {
                *t0 = add(pitch_index, PIT_DECODE_3);
                *t0_frac = 0;
            }
        }
    } else if limit_flag == 1 {
        // extended Q range
        if fr_steps == 2 {
            if sub(pitch_index, PIT_FR1_EXT8B_MINUS_PIT_MIN_EXT_X2) < 0 {
                *t0 = add(PIT_MIN_EXTEND, shr(pitch_index, 1));
                *t0_frac = sub(pitch_index, shl(sub(*t0, PIT_MIN_EXTEND), 1));
                *t0_frac = shl(*t0_frac, 1);
            } else {
                *t0 = add(
                    pitch_index,
                    sub(PIT_FR1_EXTEND_8B, PIT_FR1_EXT8B_MINUS_PIT_MIN_EXT_X2),
                );
                *t0_frac = 0;
            }
        } else if fr_steps == 4 {
            if sub(pitch_index, PIT_FR2_EXT9B_MINUS_PIT_MIN_EXT_X4) < 0 {
                *t0 = add(PIT_MIN_EXTEND, shr(pitch_index, 2));
                *t0_frac = sub(pitch_index, shl(sub(*t0, PIT_MIN_EXTEND), 2));
            } else if sub(
                pitch_index,
                add(
                    PIT_FR2_EXT9B_MINUS_PIT_MIN_EXT_X4,
                    PIT_FR1_EXT9B_MINUS_PIT_FR2_EXT9B_X2,
                ),
            ) < 0
            {
                pitch_index = sub(pitch_index, PIT_FR2_EXT9B_MINUS_PIT_MIN_EXT_X4);
                *t0 = add(PIT_FR2_EXTEND_9B, shr(pitch_index, 1));
                *t0_frac = sub(pitch_index, shl(sub(*t0, PIT_FR2_EXTEND_9B), 1));
                *t0_frac = shl(*t0_frac, 1);
            } else {
                *t0 = add(pitch_index, PIT_DECODE_7);
                *t0_frac = 0;
            }
        }
    } else if fr_steps == 2 {
        // limit_flag == 2
        if sub(pitch_index, PIT_FR1_DEXT8B_MINUS_PIT_MIN_DEXT_X2) < 0 {
            *t0 = add(PIT_MIN_DOUBLEEXTEND, shr(pitch_index, 1));
            *t0_frac = sub(pitch_index, shl(sub(*t0, PIT_MIN_DOUBLEEXTEND), 1));
            *t0_frac = shl(*t0_frac, 1);
        } else {
            *t0 = add(pitch_index, PIT_DECODE_8);
            *t0_frac = 0;
        }
    } else if fr_steps == 4 {
        if sub(pitch_index, PIT_FR2_DEXT9B_MINUS_PIT_MIN_DEXT_X4) < 0 {
            *t0 = add(PIT_MIN_DOUBLEEXTEND, shr(pitch_index, 2));
            *t0_frac = sub(pitch_index, shl(sub(*t0, PIT_MIN_DOUBLEEXTEND), 2));
        } else if sub(pitch_index, PIT_DECODE_9) < 0 {
            pitch_index = sub(pitch_index, PIT_FR2_DEXT9B_MINUS_PIT_MIN_DEXT_X4);
            *t0 = add(PIT_FR2_DOUBLEEXTEND_9B, shr(pitch_index, 1));
            *t0_frac = sub(pitch_index, shl(sub(*t0, PIT_FR2_DOUBLEEXTEND_9B), 1));
            *t0_frac = shl(*t0_frac, 1);
        } else {
            *t0 = add(pitch_index, PIT_DECODE_10);
            *t0_frac = 0;
        }
    }
}

/// `inv_T0_res[res]` (`InvIntTable`): `1/res` in Q15. `res` is a pitch resolution (at most 6); one
/// past the table (a corrupted frame) reads as 0.
fn inv_t0_res(res: i16) -> i16 {
    usize::try_from(res)
        .ok()
        .and_then(|index| INVINTTABLE.get(index))
        .copied()
        .unwrap_or(0)
}

/// `*(*pt_indice)++`: the next quantisation index of `pt_indice`, which is advanced past it. An
/// exhausted list reads 0 (the reference would run past the end of the parameter array).
fn next_pitch_index(pt_indice: &mut &[i16]) -> i16 {
    let index = pt_indice.first().copied().unwrap_or(0);
    *pt_indice = pt_indice.get(1..).unwrap_or(&[]);
    index
}

/// The relative-pitch step every MODE2 coding model shares: `limit_T0_voiced` around
/// `(t0_in, t0_frac_in, t0_res_in)` with `nbits` / `res`, then the resolution becomes `res` and
/// `Mode2_delta_pit_dec` reads the index.
fn mode2_relative_pit(
    nbits: i16,
    res: i16,
    around: (i16, i16, i16),
    limits: (i16, i16),
    outputs: (&mut i16, &mut i16, &mut i16),
    window: (&mut i16, &mut i16, &mut i16, &mut i16),
    pt_indice: &mut &[i16],
) {
    let (t0_in, t0_frac_in, t0_res_in) = around;
    let (pit_min, pit_max) = limits;
    let (t0, t0_frac, t0_res) = outputs;
    let (t0_min, t0_min_frac, t0_max, t0_max_frac) = window;

    (*t0_min, *t0_min_frac, *t0_max, *t0_max_frac) =
        limit_t0_voiced(nbits, res, t0_in, t0_frac_in, t0_res_in, pit_min, pit_max);
    *t0_res = res;
    mode2_delta_pit_dec(t0, t0_frac, *t0_res, *t0_min, *t0_min_frac, pt_indice);
}

/// `Mode2_pit_decode`: decode the pitch lag of one MODE2 ACELP subframe from `pt_indice` (the
/// remaining indices, advanced past what is read). Absolute decoding on the first subframe(s) of
/// each coding model, relative decoding in the window `[T0_min, T0_max]` after that; returns the
/// pitch `T0 + T0_frac/T0_res` (`T0` in the upper half of the `Word32`).
pub fn mode2_pit_decode(
    coder_type: i16,
    i_subfr: i16,
    l_subfr: i16,
    pt_indice: &mut &[i16],
    t0: &mut i16,
    t0_frac: &mut i16,
    t0_res: &mut i16,
    t0_min: &mut i16,
    t0_min_frac: &mut i16,
    t0_max: &mut i16,
    t0_max_frac: &mut i16,
    pit_min: i16,
    pit_fr1: i16,
    pit_fr1b: i16,
    pit_fr2: i16,
    pit_max: i16,
    pit_res_max: i16,
) -> i32 {
    let around = (*t0, *t0_frac, *t0_res);
    if coder_type == 0 {
        *t0 = l_subfr;
        *t0_frac = 0;
        *t0_res = 1;
    } else if sub(coder_type, 1) == 0 {
        // 8/4/4/4 (EVS)
        if i_subfr == 0 {
            mode2_abs_pit_dec(
                t0,
                t0_frac,
                t0_res,
                pt_indice,
                pit_min,
                pit_fr1b,
                pit_min,
                pit_res_max,
            );
        } else {
            let res = shr(pit_res_max, 1);
            mode2_relative_pit(
                4,
                res,
                around,
                (pit_min, pit_max),
                (t0, t0_frac, t0_res),
                (t0_min, t0_min_frac, t0_max, t0_max_frac),
                pt_indice,
            );
        }
    } else if sub(coder_type, 2) == 0 {
        // 8/5/8/5 (EVS)
        if i_subfr == 0 || sub(i_subfr, shl(l_subfr, 1)) == 0 {
            mode2_abs_pit_dec(
                t0,
                t0_frac,
                t0_res,
                pt_indice,
                pit_min,
                pit_fr1b,
                pit_min,
                pit_res_max,
            );
        } else {
            let res = shr(pit_res_max, 1);
            mode2_relative_pit(
                5,
                res,
                around,
                (pit_min, pit_max),
                (t0, t0_frac, t0_res),
                (t0_min, t0_min_frac, t0_max, t0_max_frac),
                pt_indice,
            );
        }
    } else if sub(coder_type, 3) == 0 {
        // 9/6/6/6 (HRs- VC)
        let mut pit_res_max2 = pit_res_max;
        if sub(pit_min, PIT_MIN_16K) == 0 {
            pit_res_max2 = shr(pit_res_max, 1);
        }

        if i_subfr == 0 {
            mode2_abs_pit_dec(
                t0,
                t0_frac,
                t0_res,
                pt_indice,
                pit_min,
                pit_fr1,
                pit_fr2,
                pit_res_max,
            );
        } else {
            mode2_relative_pit(
                6,
                pit_res_max2,
                (*t0, 0, 1),
                (pit_min, pit_max),
                (t0, t0_frac, t0_res),
                (t0_min, t0_min_frac, t0_max, t0_max_frac),
                pt_indice,
            );
        }
    } else if sub(coder_type, 4) == 0 {
        // 9/6/9/6 (AMRWB)
        let mut pit_res_max2 = pit_res_max;
        if sub(pit_min, PIT_MIN_16K) == 0 {
            pit_res_max2 = shr(pit_res_max, 1);
        }
        if i_subfr == 0 || sub(i_subfr, shl(l_subfr, 1)) == 0 {
            mode2_abs_pit_dec(
                t0,
                t0_frac,
                t0_res,
                pt_indice,
                pit_min,
                pit_fr1,
                pit_fr2,
                pit_res_max,
            );
        } else {
            mode2_relative_pit(
                6,
                pit_res_max2,
                (*t0, 0, 1),
                (pit_min, pit_max),
                (t0, t0_frac, t0_res),
                (t0_min, t0_min_frac, t0_max, t0_max_frac),
                pt_indice,
            );
        }
    } else if sub(coder_type, 8) == 0 {
        // 8/5/5/5 (RF all pred mode)
        if i_subfr == 0 {
            mode2_abs_pit_dec(
                t0,
                t0_frac,
                t0_res,
                pt_indice,
                pit_min,
                pit_fr1b,
                pit_min,
                pit_res_max,
            );
        } else {
            let res = shr(pit_res_max, 1);
            mode2_relative_pit(
                5,
                res,
                around,
                (pit_min, pit_max),
                (t0, t0_frac, t0_res),
                (t0_min, t0_min_frac, t0_max, t0_max_frac),
                pt_indice,
            );
        }
    } else if sub(coder_type, 9) == 0 {
        // 8/0/8/0 (RF gen pred mode)
        if i_subfr == 0 {
            mode2_abs_pit_dec(
                t0,
                t0_frac,
                t0_res,
                pt_indice,
                pit_min,
                pit_fr1b,
                pit_min,
                pit_res_max,
            );
        } else {
            let res = shr(pit_res_max, 1);
            mode2_relative_pit(
                4,
                res,
                around,
                (pit_min, pit_max),
                (t0, t0_frac, t0_res),
                (t0_min, t0_min_frac, t0_max, t0_max_frac),
                pt_indice,
            );
        }
    }
    // The reference asserts on any other coding model ("LTP mode not supported"); the decoder
    // only signals the ones above, so a corrupted value leaves the lag as it was.

    // Compute floating pitch output
    // pitch = (float)(*T0) + (float)(*T0_frac)/(float)(*T0_res);
    l_mac(l_deposit_h(*t0), *t0_frac, inv_t0_res(*t0_res))
}

/// `Mode2_abs_pit_dec`: decode an absolute pitch index into `T0`, `T0_frac` and the resolution
/// `T0_res`, in three regions: resolution `pit_res_max` below `pit_fr2`, half of it up to
/// `pit_fr1`, integer lags above.
pub fn mode2_abs_pit_dec(
    t0: &mut i16,
    t0_frac: &mut i16,
    t0_res: &mut i16,
    pt_indice: &mut &[i16],
    pit_min: i16,
    pit_fr1: i16,
    pit_fr2: i16,
    pit_res_max: i16,
) {
    let mut index = next_pitch_index(pt_indice);
    let pit_res_max_half = shr(pit_res_max, 1);

    let tmp1 = i_mult(sub(pit_fr2, pit_min), pit_res_max);
    let tmp2 = i_mult(sub(pit_fr1, pit_fr2), pit_res_max_half);
    if sub(index, tmp1) < 0 {
        // the reference asserts 1 < pit_res_max <= 6
        let mut res = pit_res_max;
        if sub(pit_res_max, 6) == 0 {
            res = shr(res, 1);
        }

        *t0 = mult(index, inv_t0_res(res));
        if sub(pit_res_max, 6) == 0 {
            *t0 = shr(*t0, 1);
        }

        *t0 = add(pit_min, *t0);

        *t0_frac = sub(index, i_mult(sub(*t0, pit_min), pit_res_max));
        *t0_res = pit_res_max;
    } else if index < add(tmp1, tmp2) {
        index = sub(index, tmp1);
        *t0 = add(pit_fr2, mult(index, inv_t0_res(pit_res_max_half)));
        *t0_frac = sub(index, i_mult(sub(*t0, pit_fr2), pit_res_max_half));
        *t0_res = pit_res_max_half;
    } else {
        *t0 = add(index, sub(pit_fr1, add(tmp1, tmp2)));
        *t0_frac = 0;
        *t0_res = 1;
    }
}

/// `Mode2_delta_pit_dec`: decode a relative pitch index against the window start
/// (`t0_min`, `t0_min_frac`) at resolution `t0_res` (2..=6). The reference takes `T0_min` and
/// `T0_min_frac` by pointer but only reads them.
pub fn mode2_delta_pit_dec(
    t0: &mut i16,
    t0_frac: &mut i16,
    t0_res: i16,
    t0_min: i16,
    t0_min_frac: i16,
    pt_indice: &mut &[i16],
) {
    // the reference asserts 1 < T0_res <= 6
    let mut res = t0_res;
    if sub(t0_res, 6) == 0 {
        res = shr(res, 1);
    }

    let index = next_pitch_index(pt_indice);

    *t0 = mult(add(index, t0_min_frac), inv_t0_res(res));
    if sub(t0_res, 6) == 0 {
        *t0 = shr(*t0, 1);
    }

    *t0 = add(t0_min, *t0);

    *t0_frac = add(index, sub(t0_min_frac, i_mult(sub(*t0, t0_min), t0_res)));
}

/// `delta_pit_dec_fx`: pitch decoding relative to `T0_min` at fractional resolution `fr_steps`
/// (0, 2 or 4; any other value leaves the outputs untouched, as the reference does).
pub fn delta_pit_dec(
    fr_steps: i16,
    pitch_index: i16,
    t0: &mut i16,
    t0_frac: &mut i16,
    t0_min: i16,
) {
    if fr_steps == 0 {
        *t0 = add(t0_min, pitch_index);
        *t0_frac = 0;
    } else if fr_steps == 2 {
        *t0 = add(t0_min, shr(pitch_index, 1));
        let temp = shl(sub(*t0, t0_min), 1);
        *t0_frac = shl(sub(pitch_index, temp), 1);
    } else if fr_steps == 4 {
        *t0 = add(t0_min, shr(pitch_index, 2));
        let temp = shl(sub(*t0, t0_min), 2);
        *t0_frac = sub(pitch_index, temp);
    }
}
