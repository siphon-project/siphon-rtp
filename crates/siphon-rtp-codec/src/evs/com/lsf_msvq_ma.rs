//! MODE2 mid-frame LSF decoding and the TCX LPC index activity test (TS 26.442
//! `lib_com/lsf_msvq_ma.c`; TS 26.445 §6.1.1.1.4).

use crate::evs::cnst::{LSF_GAP_MID_FX, M, UNVOICED};
use crate::evs::rom::{MIN_DISTANCE_THR, TBL_MID_GEN_WB_5B_FX, TBL_MID_UNV_WB_5B_FX};
use crate::itu::basic_ops::{add, l_mac, l_mult, l_shl, mult_r, round_word, sub};

/// `ratio[index]` of a mid-frame interpolation table; 0 past it. The index is `idx * M + j` for a
/// 5-bit codebook index, inside the table for any valid frame.
fn at(table: &[i16], index: usize) -> i16 {
    table.get(index).copied().unwrap_or(0)
}

/// `midlsf_dec`: the mid-frame LSFs `qlsf[0..M]` (Q(x2.56)) as the codebook-weighted mix of the
/// previous (`qlsf0`) and current (`qlsf1`) end-frame LSFs. With `mid_lsf_int` (the decoder) the
/// mix falls back to a fixed 0.4 / 0.6 interpolation after a lost frame (`prev_bfi`) or an
/// incorrect LSF ordering, and `mid_lsf_int` is updated; without it (the encoder) the regular
/// spacing is enforced.
pub fn midlsf_dec(
    qlsf0: &[i16],
    qlsf1: &[i16],
    idx: i16,
    qlsf: &mut [i16],
    coder_type: i16,
    mid_lsf_int: Option<&mut i16>,
    prev_bfi: i16,
    safety_net: i16,
) {
    let mut bad_spacing = false;

    // Select codebook
    let ratio: &[i16] = if sub(coder_type, UNVOICED) == 0 {
        &TBL_MID_UNV_WB_5B_FX
    } else {
        &TBL_MID_GEN_WB_5B_FX
    };
    let base = usize::try_from(idx).unwrap_or(0) * M as usize;
    for j in 0..M as usize {
        let weight = at(ratio, base + j);
        let mut l_tmp = l_mult(sub(0x2000, weight), qlsf0[j]); // Q(x2.56+13+1)->Q(x2.56+14)
        l_tmp = l_mac(l_tmp, weight, qlsf1[j]); // Q(x2.56+14)
        qlsf[j] = round_word(l_shl(l_tmp, 2)); // Q(x2.56)
    }

    if let Some(mid_lsf_int) = mid_lsf_int {
        // at the decoder: check for incorrect LSF ordering
        if sub(*mid_lsf_int, 1) == 0 {
            for j in 1..M as usize {
                if sub(qlsf[j], qlsf[j - 1]) < 0 {
                    bad_spacing = true;
                    break;
                }
            }
        }
        // Redo mid-LSF interpolation with 0.4 in case of LSF instability
        if prev_bfi != 0 || (sub(*mid_lsf_int, 1) == 0 && bad_spacing) {
            for j in 0..M as usize {
                // redo mid-LSF interpolation with 0.4
                // 13107 = 0.4 (Q15), 19661 = 0.6 (Q15)
                qlsf[j] = add(mult_r(13107, qlsf0[j]), mult_r(19661, qlsf1[j]));

                // ensure correct ordering of LSF indices
                if j > 0 && sub(qlsf[j], add(qlsf[j - 1], LSF_GAP_MID_FX)) < 0 {
                    qlsf[j] = add(qlsf[j - 1], LSF_GAP_MID_FX);
                }
            }
        } else {
            // otherwise, use regular LSF spacing and ordering as in the encoder
            for j in 0..M as usize {
                if j > 0 && sub(qlsf[j], add(qlsf[j - 1], LSF_GAP_MID_FX)) < 0 {
                    qlsf[j] = add(qlsf[j - 1], LSF_GAP_MID_FX);
                }
            }
        }
        if prev_bfi != 0 {
            // continue redoing mid-LSF interpolation with 0.4 in order not to propagate the error
            *mid_lsf_int = 1;
        }
        if safety_net != 0 {
            // safety-net encountered -> stop redoing mid-LSF interpolation with 0.4
            *mid_lsf_int = 0;
        }
    } else {
        // use regular LSF spacing
        for j in 0..M as usize {
            if j > 0 && sub(qlsf[j], add(qlsf[j - 1], LSF_GAP_MID_FX)) < 0 {
                qlsf[j] = add(qlsf[j - 1], LSF_GAP_MID_FX);
            }
        }
    }
}

/// `lsf_ind_is_active`: whether the independent-LSF refinement stage is used, i.e. whether the
/// first LSF (`lsf_q_ind[0] + means[0]`) or the gap to the second (`lsf_q_ind[1] + means[1]`)
/// falls below the threshold of the (`narrowband`, `cdk`) codebook; returns 0 or 1.
#[must_use]
pub fn lsf_ind_is_active(lsf_q_ind: &[i16], means: &[i16], narrowband: i16, cdk: i16) -> i16 {
    let lsf = [add(lsf_q_ind[0], means[0]), add(lsf_q_ind[1], means[1])];

    let mut min_distance = lsf[0];
    min_distance = min_distance.min(sub(lsf[1], lsf[0]));

    // the reference asserts narrowband and cdk are 0 or 1
    let threshold = MIN_DISTANCE_THR
        .get(usize::try_from(narrowband).unwrap_or(0))
        .and_then(|row| row.get(usize::try_from(cdk).unwrap_or(0)))
        .copied()
        .unwrap_or(0);
    i16::from(sub(min_distance, threshold) < 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsf_ind_is_active_compares_the_tighter_distance_with_the_threshold() {
        // WB, cdk 0: threshold 580; lsf[0] = 100 is below it.
        assert_eq!(lsf_ind_is_active(&[100, 0], &[0, 5000], 0, 0), 1);
        // Both the first LSF and the gap are far above it.
        assert_eq!(lsf_ind_is_active(&[2000, 4000], &[0, 0], 0, 0), 0);
        // NB cdk 0 raises the threshold to 1000.
        assert_eq!(lsf_ind_is_active(&[800, 4000], &[0, 0], 1, 0), 1);
    }

    #[test]
    fn encoder_midlsf_enforces_the_regular_spacing() {
        let qlsf0 = [0i16; 16];
        let qlsf1 = [0i16; 16];
        let mut qlsf = [0i16; 16];
        midlsf_dec(&qlsf0, &qlsf1, 0, &mut qlsf, 0, None, 0, 0);
        for j in 1..16 {
            assert_eq!(qlsf[j], qlsf[j - 1] + LSF_GAP_MID_FX);
        }
    }
}
