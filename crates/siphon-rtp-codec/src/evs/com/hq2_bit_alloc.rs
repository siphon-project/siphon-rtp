//! Bit allocation of the low-rate HQ (HQ2) core (TS 26.442 `lib_com/hq2_bit_alloc_fx.c`).
//!
//! `hq2_bit_alloc_fx` for every class but `HQ_HARMONIC`, whose allocation is
//! [`hq2_bit_alloc_har`] over the per-group [`bits2indvsb`].

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    BANDS_MAX, G1G2_RANGE, G1_RANGE, GRP_SB, HQ_16K40, HQ_NORMAL, NB_SWB_SUBBANDS,
    NB_SWB_SUBBANDS_HAR, SWB, SWB_BWE_LR_QBE, SWB_BWE_LR_QRK, THR1, THR2, THR3,
};
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::reordvct::reordvct;
use crate::evs::com::swb_bwe_com_lr::div_s_ss;
use crate::evs::com::tools::{set16, set32};
use crate::evs::rom::BITS_LAGINDICES_MODENORMAL_FX;
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, l_abs, l_add, l_deposit_h, l_deposit_l, l_mult, l_shl, l_shr,
    l_sub, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::oper_32b::l_comp;
use crate::itu::stl2009::div_l;

/// `MIN_BITS_FIX` (QRk = 18).
const MIN_BITS_FIX: i32 = 0;
/// `HQ_16k40_BIT`: 16400/50 = 328 bits.
const HQ_16K40_BIT: i16 = HQ_16K40 / 50;
/// `C1_QRk`: 1 in Q`SWB_BWE_LR_QRk`.
const C1_QRK: i32 = 1 << SWB_BWE_LR_QRK;

/// `hq2_bit_alloc_fx`: iteratively allocate the bit budget across `bands` sub-bands in
/// proportion to their energies (`l_band_energy`, Q`SWB_BWE_LR_Qbe`), pruning bands that fall
/// under their minimum, into `l_rk` (Q`SWB_BWE_LR_QRk`). Returns the total allocated (same Q).
/// May lower `bit_budget` (and clear `p2a_flags`) in the SWB normal mode; a negative budget from a
/// corrupt frame is left for the caller to flag, as in the reference.
pub fn hq2_bit_alloc(
    l_band_energy: &[i32],
    bands: i16,
    l_rk: &mut [i32],
    bit_budget: &mut i16,
    p2a_flags: &mut [i16],
    weight: i16,
    band_width: &[i16],
    num_bits: i16,
    hqswb_clas: i16,
    bwidth: i16,
    is_transient: i16,
) -> i32 {
    let nb = bands.max(0) as usize;
    let l_thr1 = l_shl(l_deposit_l(THR1), SWB_BWE_LR_QRK);
    let l_thr2 = l_shl(l_deposit_l(THR2), SWB_BWE_LR_QRK);
    let l_thr3 = l_shl(l_deposit_l(THR3), SWB_BWE_LR_QRK);

    // Init Rk to non-zero values for bands to be allocated bits
    if sub(num_bits, HQ_16K40_BIT) <= 0 {
        set32(l_rk, C1_QRK, bands);
        if is_transient != 0 && sub(bands, 32) == 0 {
            for k in [6, 7, 14, 15, 22, 23, 30, 31] {
                l_rk[k] = 0;
            }
        }
    } else {
        for k in 0..nb {
            l_rk[k] = l_shl(l_deposit_l(p2a_flags[k]), SWB_BWE_LR_QRK);
        }
    }

    let mut l_rcalc: i32 = 0;
    let mut l_rcalc1: i32 = 0;

    for _ in 0..nb {
        let mut rcnt: i16 = 0;
        let mut l_ravg: i32 = 0;
        for k in 0..nb {
            if l_rk[k] > 0 {
                l_ravg = l_add(
                    l_ravg,
                    l_shl(l_band_energy[k], sub(SWB_BWE_LR_QRK, SWB_BWE_LR_QBE)),
                );
                rcnt = add(rcnt, 1);
            }
        }

        // L_Ravg /= Rcnt
        let mut exp_normd = norm_l(l_ravg);
        exp_normd = sub(exp_normd, 1);
        let exp_normn = norm_s(rcnt);
        let mut tmp = shl(rcnt, exp_normn);
        tmp = tmp.max(1);
        let mut div_fx = if l_ravg > 0 {
            div_l(l_shl(l_ravg, exp_normd), tmp) // Qdiv = 14+exp_normd-(exp_normn)-1
        } else {
            negate(div_l(l_shl(l_abs(l_ravg), exp_normd), tmp))
        };
        let mut qdiv = sub(sub(add(SWB_BWE_LR_QRK, exp_normd), exp_normn), 1);
        l_ravg = l_shr(l_deposit_l(div_fx), sub(qdiv, SWB_BWE_LR_QRK));

        exp_normd = norm_s(*bit_budget);
        exp_normd = sub(exp_normd, 1);
        let bit_budget_norm = shl(*bit_budget, exp_normd);
        div_fx = 0;
        if bit_budget_norm > 0 && sub(bit_budget_norm, tmp) < 0 {
            div_fx = div_s(bit_budget_norm, tmp);
        }
        qdiv = add(sub(exp_normd, exp_normn), 15);
        for k in 0..nb {
            if l_rk[k] > 0 {
                // Rk[k] = bit_budget / Rcnt + weight * (band_energy[k] - Ravg)
                let mut l_tmp = mult_32_16(
                    l_sub(
                        l_shl(l_band_energy[k], sub(SWB_BWE_LR_QRK, SWB_BWE_LR_QBE)),
                        l_ravg,
                    ),
                    weight,
                ); // SWB_BWE_LR_QRk + Q13 - 15
                l_tmp = l_shl(l_tmp, 2); // -> SWB_BWE_LR_QRk
                l_rk[k] = l_add(l_shr(l_deposit_l(div_fx), sub(qdiv, SWB_BWE_LR_QRK)), l_tmp);
            }
        }

        let mut negflag = false;
        l_rcalc = 0;
        for rk in &mut l_rk[..nb] {
            if l_sub(*rk, MIN_BITS_FIX) < 0 {
                *rk = 0;
                negflag = true;
            }
            l_rcalc = l_add(l_rcalc, *rk);
        }

        // prune noiselike bands with low allocation
        if sub(num_bits, HQ_16K40_BIT) <= 0 && !negflag {
            let mut l_maxxy: i32 = 0;
            let mut maxdex: i16 = -1;
            l_rcalc = 0;
            // find worst under-allocation
            for k in (0..nb).rev() {
                let tmp_fx = band_width[k].min(12.max(shr(band_width[k], 2)));
                let l_dummy = l_sub(l_shl(l_deposit_l(tmp_fx), SWB_BWE_LR_QRK), l_rk[k]);
                if p2a_flags[k] == 0 && l_sub(l_dummy, l_maxxy) > 0 && l_rk[k] > 0 {
                    maxdex = k as i16;
                    l_maxxy = l_dummy;
                }
            }
            // prune worst allocation and recalculate total allocation
            if sub(maxdex, -1) > 0 {
                l_rk[maxdex as usize] = 0;
            }
            for &rk in &l_rk[..nb] {
                l_rcalc = l_add(l_rcalc, rk);
            }
        }

        if l_sub(l_rcalc, l_rcalc1) == 0 && sub(bwidth, SWB) == 0 {
            // Reallocate bits to individual subbands for HQ_NORMAL mode
            // if bits allocated to subbands are less than predefined threshold
            if sub(hqswb_clas, HQ_NORMAL) == 0 && sub(num_bits, HQ_16K40_BIT) < 0 {
                let mut l_dummy: i32 = 0;
                for (k, rk) in l_rk[..nb].iter_mut().enumerate() {
                    // below 11: THR1, 11..16: THR2, from 16: THR3
                    let threshold = if k < 11 {
                        l_thr1
                    } else if k < 16 {
                        l_thr2
                    } else {
                        l_thr3
                    };
                    if l_sub(*rk, threshold) < 0 {
                        *rk = 0;
                    }
                    l_dummy = l_add(l_dummy, *rk);
                }

                if l_sub(l_dummy, l_rcalc) == 0 {
                    // (the reference re-tests the same HQ_NORMAL condition here; it holds)
                    let mut bit_budget_temp = *bit_budget;
                    // the SWB band layouts always have more than NB_SWB_SUBBANDS bands
                    let first = nb.saturating_sub(NB_SWB_SUBBANDS as usize);
                    for (k, &lag_bits) in BITS_LAGINDICES_MODENORMAL_FX
                        .iter()
                        .enumerate()
                        .take(NB_SWB_SUBBANDS as usize)
                    {
                        let band = first + k;
                        if band < nb && p2a_flags[band] == 1 && l_rk[band] == 0 {
                            p2a_flags[band] = 0;
                            bit_budget_temp = sub(bit_budget_temp, lag_bits);
                        }
                    }
                    if sub(bit_budget_temp, *bit_budget) < 0 {
                        *bit_budget = bit_budget_temp;
                    } else if sub(bit_budget_temp, *bit_budget) == 0 {
                        break;
                    }
                }
            } else {
                break;
            }
        } else if l_sub(l_rcalc, l_rcalc1) == 0 && sub(bwidth, SWB) != 0 {
            break;
        }

        l_rcalc1 = l_rcalc;
    }

    l_rcalc
}

/// `BITS_FACT_1p10` = 1.10 in Q`Qbf` (Q14); the reference's initial `C1_Qbf` is overwritten on
/// every path.
const BITS_FACT_1P10: i16 = 18022;
/// `BITS_FACT_1p05` = 1.05 in Q`Qbf`.
const BITS_FACT_1P05: i16 = 17203;
/// `BITS_FACT_1p00` = 1.00 in Q`Qbf`.
const BITS_FACT_1P00: i16 = 16384;
/// `BITS_FACT_0p97` = 0.97 in Q`Qbf`.
const BITS_FACT_0P97: i16 = 15892;
/// `BITS_FACT_0p92` = 0.92 in Q`Qbf`.
const BITS_FACT_0P92: i16 = 15073;

/// The reference sizes `Bits2indvsb_fx`'s scratch at 14 bands, the widest group its callers
/// form; sized here at `BANDS_MAX` so a corrupt grouping cannot index past it. The extra entries
/// are never read for a group of 14 bands or fewer.
const GROUP_MAX: usize = BANDS_MAX as usize;

/// `Bits2indvsb_fx`: share the `bits` of the group `start_band..end_band` among its bands in
/// proportion to their energies `l_be` (Qbe) into `l_rsubband` (QRk), dropping (and clearing the
/// `p2aflags` of) the weakest bands while they get less than `l_bits_needed`.
// Index loops mirror the reference's pointer walks so the two can be diffed.
#[allow(clippy::needless_range_loop)]
pub fn bits2indvsb(
    l_be: &[i32],
    start_band: i16,
    end_band: i16,
    bits: i16,
    l_bits_needed: i32,
    l_rsubband: &mut [i32],
    p2aflags: &mut [i16],
) {
    let mut l_r_temp = [0i32; GROUP_MAX]; // QRk = QL_Rsubband
    let mut index = [0i16; GROUP_MAX];
    let mut y_index = [0i16; GROUP_MAX];

    let band_num = sub(end_band, start_band);
    let start = start_band as usize;
    let nb = (band_num.max(0) as usize).min(GROUP_MAX);
    for i in 0..nb {
        y_index[i] = extract_h(l_shr(l_be[start + i], sub(SWB_BWE_LR_QBE, 16)));
        index[i] = i as i16;
    }

    // Rearrange norm vector in decreasing order
    reordvct(&mut y_index, nb as i16, &mut index);

    let mut be_sum: i16 = 0;
    let mut be_cnt: i16 = 0;
    for j in 0..nb {
        if y_index[j] <= 0 || p2aflags[start + index[j] as usize] == 0 {
            y_index[j] = 0;
            l_r_temp[j] = 0;
        } else {
            l_r_temp[j] = C1_QRK; // filled not zero value
            be_cnt = add(be_cnt, 1);
        }
    }

    let mut i = sub(be_cnt, 1);
    for k in 0..=i.max(-1) {
        if l_r_temp[k as usize] > 0 {
            be_sum = add(be_sum, y_index[k as usize]);
        }
    }

    // Ravg = (float) be_sum/be_cnt;
    let mut ravg: i16 = 0;
    let mut qravg: i16 = 0;
    if be_cnt != 0 {
        let mut exp_normn = norm_s(be_sum);
        exp_normn = sub(exp_normn, 1);
        let exp_normd = norm_s(be_cnt);
        ravg = div_s(shl(be_sum, exp_normn), shl(be_cnt, exp_normd));
        ravg = shr(ravg, 2); // safe shift
        qravg = add(sub(exp_normn, exp_normd), 15 - 2);
    }

    let mut enr_diffcnt: i16 = 0;
    let th_5 = shl(5, qravg);
    for j in 0..be_cnt.max(0) as usize {
        if sub(abs_s(sub(ravg, shl(y_index[j], qravg))), th_5) > 0 {
            enr_diffcnt = add(enr_diffcnt, 1);
        }
    }

    let mut scale_fact: i16 = 19661; // 0.60f 19660.8(Q15)
    if enr_diffcnt > 0 {
        scale_fact = 11468; // 0.35f 11468.8(Q15)
    }

    // Bits allocation to individual SB's in a group based on Band Energies
    for _ in 0..be_cnt.max(0) {
        let rcnt = add(i, 1);

        // Ravg = (float) be_sum/Rcnt;
        let mut exp_normn = norm_s(be_sum);
        exp_normn = sub(exp_normn, 1);
        let exp_normd = norm_s(rcnt);
        ravg = div_s(shl(be_sum, exp_normn), shl(rcnt, exp_normd));
        ravg = shr(ravg, 2); // safe shift
        qravg = add(sub(exp_normn, exp_normd), 15 - 2);

        if be_sum <= 0 {
            be_sum = 1;
        }

        // Bits_avg = (float) Bits/(be_sum+EPSILON);
        let mut bits_avg: i16 = 0;
        let mut qbavg: i16 = 0;
        if bits != 0 {
            let mut exp_normn = norm_s(bits);
            exp_normn = sub(exp_normn, 1);
            let exp_normd = norm_s(be_sum);
            bits_avg = div_s(shl(bits, exp_normn), shl(be_sum, exp_normd));
            bits_avg = shr(bits_avg, 2); // safe_shift
            qbavg = add(sub(exp_normn, exp_normd), 15 - 2);
        }
        for k in 0..=i as usize {
            if l_r_temp[k] > 0 {
                // Allocate more bits to SB, if SB bandenergy is higher than average energy
                // R_temp[k] = Bits_avg * y_index[k] + scale_fact * (y_index[k] - Ravg)
                let l_temp1 = l_mult(bits_avg, y_index[k]); // QBavg+1
                let l_temp2 = l_mult(scale_fact, sub(shl(y_index[k], qravg), ravg)); // 15+QRavg+1
                l_r_temp[k] = l_add(
                    l_shr(l_temp1, sub(add(qbavg, 1), SWB_BWE_LR_QRK)),
                    l_shr(l_temp2, sub(add(qravg, 16), SWB_BWE_LR_QRK)),
                );
            }
        }
        let iu = i as usize;
        if l_sub(l_r_temp[iu], l_bits_needed) < 0 {
            l_r_temp[iu] = 0;
            p2aflags[start + index[iu] as usize] = 0;
            // be_sum -= y_index[i];
            be_sum = sub(be_sum, y_index[iu]);
            i = sub(i, 1);
        } else {
            break;
        }
    }

    // Rearrange the bit allocation to align with original
    for k in 0..nb {
        let j = index[k] as usize;
        l_rsubband[start + j] = l_r_temp[k];
    }
}

/// `hq2_bit_alloc_har_fx`: bit allocation of the `HQ_HARMONIC` SWB mode. The `n` bands are cut
/// into `GRP_SB` groups (two low-band groups bounded by energy drops, the rest of the harmonic
/// low band, and the `p2a_bands` high bands); the budget `b` is shared between the groups by
/// energy and then within each group by [`bits2indvsb`], into `l_rsubband` (QRk).
// Index loops mirror the reference's walks so the two can be diffed.
#[allow(clippy::needless_range_loop)]
pub fn hq2_bit_alloc_har(
    l_y: &[i32],
    b: i16,
    n: i16,
    l_rsubband: &mut [i32],
    p2a_bands: i16,
    l_core_brate: i32,
    p2a_flags: &mut [i16],
    band_width: &[i16],
) {
    let mut b = b;
    let mut l_temp_band_energy = [0i32; BANDS_MAX as usize]; // Qbe
    let mut bits_grp = [0i16; GRP_SB as usize];

    let l_thr1 = l_shl(l_deposit_l(THR1), SWB_BWE_LR_QRK);
    let l_thr2 = l_shl(l_deposit_l(THR2), SWB_BWE_LR_QRK);
    let l_thr3 = l_shl(l_deposit_l(THR3), SWB_BWE_LR_QRK);

    // Initialize subbands bits allocation vector based on harmonic bands
    let harmonic_band = add(sub(n, p2a_bands), 1);
    let nb = n.max(0) as usize;
    for k in 0..nb {
        l_rsubband[k] = C1_QRK; // Constant Value
        l_temp_band_energy[k] = l_y[k]; // SWB_BWE_LR_Qbe
    }

    let gmax_range = hq2_bit_alloc_har_ranges(&l_temp_band_energy, l_core_brate);

    let mut grp_bound = [0i16; GRP_SB as usize + 1];
    grp_bound[0] = 0;
    grp_bound[1..GRP_SB as usize - 1].copy_from_slice(&gmax_range);
    grp_bound[GRP_SB as usize - 1] = harmonic_band;
    grp_bound[GRP_SB as usize] = n;

    let mut l_ravg_sub = [0i32; GRP_SB as usize]; // Qbe
    for i in 0..GRP_SB as usize {
        for j in grp_bound[i]..grp_bound[i + 1] {
            let j = j as usize;
            if l_temp_band_energy[j] > 0 {
                l_ravg_sub[i] = l_add(l_ravg_sub[i], l_temp_band_energy[j]);
            }
        }
    }

    let mut l_temp_band_energydiff = [0i32; BANDS_MAX as usize];
    l_temp_band_energydiff[0] = l_temp_band_energy[0];
    for j in 1..harmonic_band.max(1) as usize {
        l_temp_band_energydiff[j] = l_abs(l_sub(l_temp_band_energy[j], l_temp_band_energy[j - 1]));
    }

    let mut g1_be_diff_pos: i16 = 0;
    let mut l_g1_be_diff_val: i32 = 0;
    for j in 1..harmonic_band.max(1) as usize {
        if l_sub(l_temp_band_energydiff[j], l_g1_be_diff_val) > 0 {
            g1_be_diff_pos = j as i16;
            l_g1_be_diff_val = l_add(0, l_temp_band_energydiff[j]);
        }
    }

    let final_gr_fact_pos: i16 = if sub(g1_be_diff_pos, gmax_range[0]) < 0 && g1_be_diff_pos > 0 {
        0
    } else if sub(g1_be_diff_pos, gmax_range[0]) >= 0 && sub(g1_be_diff_pos, gmax_range[1]) < 0 {
        1
    } else {
        2
    };

    let (bits_fact, bits_fact1) = if final_gr_fact_pos == 0 || sub(final_gr_fact_pos, 1) == 0 {
        if l_sub(l_core_brate, i32::from(HQ_16K40)) == 0 {
            (BITS_FACT_1P10, BITS_FACT_0P92) // G1, G3
        } else {
            (BITS_FACT_1P05, BITS_FACT_0P97)
        }
    } else if l_sub(l_core_brate, i32::from(HQ_16K40)) == 0 {
        (BITS_FACT_0P97, BITS_FACT_1P00)
    } else {
        (BITS_FACT_0P92, BITS_FACT_1P00)
    };

    let mut index = [0i16; NB_SWB_SUBBANDS_HAR as usize];
    let mut y_index = [0i16; NB_SWB_SUBBANDS_HAR as usize];
    let j = sub(n, harmonic_band);
    for i in 0..(j.max(0) as usize).min(NB_SWB_SUBBANDS_HAR as usize) {
        y_index[i] = extract_h(l_shl(
            l_temp_band_energy[harmonic_band as usize + i],
            sub(16, SWB_BWE_LR_QBE),
        ));
        index[i] = add(harmonic_band, i as i16);
    }
    // the high bands are p2a_bands - 1 <= NB_SWB_SUBBANDS_HAR for every harmonic configuration
    let high = sub(n, harmonic_band).min(NB_SWB_SUBBANDS_HAR);
    reordvct(&mut y_index, high, &mut index);

    // Log2
    let mut l_temp = l_deposit_l(band_width[index[0] as usize]);
    let mut exp = norm_l(l_temp);
    let frac = log2_norm_lc(l_shl(l_temp, exp));
    exp = sub(30, exp);
    l_temp = l_comp(exp, frac);
    // ceil
    if (0x0000_ffff & l_temp) > 0 {
        l_temp = l_add(l_temp, 0x0001_0000);
    }
    let esthf_bits = extract_h(l_temp);

    let l_grp_thr = [
        l_thr1,
        l_thr2,
        l_thr3,
        l_shl(l_deposit_l(esthf_bits), SWB_BWE_LR_QRK),
    ];

    let mut l_norm_sum = l_deposit_l(1);
    for value in l_ravg_sub.iter().take(3) {
        l_norm_sum = l_add(l_norm_sum, *value);
    }

    let shares = HarShares {
        l_ravg_sub,
        l_norm_sum,
        harmonic_band,
        index0: index[0],
        esthf_bits,
        final_gr_fact_pos,
        bits_fact,
        bits_fact1,
    };
    hq2_bit_alloc_har_groups(
        &shares,
        &l_temp_band_energy,
        &mut b,
        n,
        p2a_bands,
        &mut bits_grp,
    );

    for i in 0..GRP_SB as usize {
        if bits_grp[i] > 0 {
            bits2indvsb(
                &l_temp_band_energy,
                grp_bound[i],
                grp_bound[i + 1],
                bits_grp[i],
                l_grp_thr[i],
                l_rsubband,
                p2a_flags,
            );
        } else {
            let from = grp_bound[i].max(0) as usize;
            let len = sub(grp_bound[i + 1], grp_bound[i]);
            set32(&mut l_rsubband[from..], 0, len);
            if sub(i as i16, GRP_SB - 1) == 0 {
                set16(&mut p2a_flags[from..], 0, len);
            }
        }
    }
}

/// The two low-band group ends of [`hq2_bit_alloc_har`] (`gmax_range_fx`): from `G1_RANGE` /
/// `G1G2_RANGE`, extended over the run of non-increasing energies that follows (at most to
/// band 7 / 16), then pulled back to the first rise inside that run.
fn hq2_bit_alloc_har_ranges(l_temp_band_energy: &[i32], l_core_brate: i32) -> [i16; 2] {
    let mut gmax_range = [G1_RANGE, G1G2_RANGE];
    if l_sub(l_core_brate, i32::from(HQ_16K40)) == 0 {
        gmax_range[1] = add(gmax_range[1], 2);
    }

    // decide each group range, for grouping spectral coefficients
    let grp_rngmax: [i16; 2] = [7, 16];
    let energy = |i: i16| l_temp_band_energy[i as usize];
    for i in 0..2 {
        let mut j = gmax_range[i];
        let mut k: i16 = 0;
        while l_sub(energy(gmax_range[i] - 1), energy(j)) >= 0 && sub(j, grp_rngmax[i]) < 0 {
            k = add(k, 1);
            j = add(j, 1);
        }
        let mut temp = k;
        if sub(temp, 1) > 0 {
            temp = 2;
            while temp <= k {
                let at = gmax_range[i] + temp;
                if l_sub(energy(at - 1), energy(at)) < 0 {
                    break;
                }
                // the reference's ELSE IF (>= 0) is the complement of the test above
                temp = add(temp, 1);
                if sub(temp, k) > 0 {
                    temp = sub(temp, 1);
                    break;
                }
            }
            gmax_range[i] = add(gmax_range[i], temp);
        } else {
            gmax_range[i] = add(gmax_range[i], temp);
        }
    }
    gmax_range
}

/// What [`hq2_bit_alloc_har_groups`] needs from the analysis in [`hq2_bit_alloc_har`].
struct HarShares {
    l_ravg_sub: [i32; GRP_SB as usize],
    l_norm_sum: i32,
    harmonic_band: i16,
    index0: i16,
    esthf_bits: i16,
    final_gr_fact_pos: i16,
    bits_fact: i16,
    bits_fact1: i16,
}

/// The split of the budget `b` between the four groups of [`hq2_bit_alloc_har`] (`Bits_grp_fx`):
/// first a reservation for the high-band group when it is loud enough, then the low-band groups
/// by energy share.
fn hq2_bit_alloc_har_groups(
    s: &HarShares,
    l_temp_band_energy: &[i32],
    b: &mut i16,
    n: i16,
    p2a_bands: i16,
    bits_grp: &mut [i16; GRP_SB as usize],
) {
    let last = GRP_SB as usize - 1;

    // reserve bits for HF coding
    let l_temp = l_add(s.l_norm_sum, s.l_ravg_sub[last]);
    let mut exp_normn = norm_l(l_temp);
    exp_normn = sub(exp_normn, 1);
    let exp_normd = norm_s(n);
    // (Qbe+exp_normn)-(0+exp_normd)-1)
    let div = div_l(l_shl(l_temp, exp_normn), shl(n, exp_normd));
    let l_norm_sum_avg = l_shr(l_deposit_h(div), add(sub(exp_normn, exp_normd), 15)); // -> Qbe

    let exp_norm = norm_l(s.l_norm_sum);
    let norm_sum = extract_h(l_shl(s.l_norm_sum, exp_norm)); // SWB_BWE_LR_Qbe+exp_norm-16
    let qns = sub(add(SWB_BWE_LR_QBE, exp_norm), 16);
    let inv_norm_sum = div_s(0x4000 /* Q15 */, norm_sum);
    let qins = sub(31, exp_norm); // 14 - (14+exp_norm-16) + 15

    let grp_bit_avg = div_s_ss(*b, GRP_SB); // Q0

    let exp_normd = norm_s(p2a_bands);
    let inv_p2a_bands = div_s(0x3fff, shl(p2a_bands, exp_normd)); // 14-exp_normd+15
    let qipb = sub(29, exp_normd);

    let l_temp = l_shl(
        mult_32_16(s.l_ravg_sub[last], inv_p2a_bands),
        sub(SWB_BWE_LR_QBE, sub(qipb, 1)),
    );
    let l_norm_diff = l_sub(l_temp, l_norm_sum_avg); // Qbe

    let l_temp = mult_32_16(s.l_ravg_sub[last], sub(GRP_SB, 1)); // Qbe+0+1
    let l_temp = mult_32_16(l_temp, inv_norm_sum); // Qbe+1+QIpb+1
    let lf_hf_ge_r = round_word(l_shl(
        l_temp,
        sub(15 + 16, sub(add(SWB_BWE_LR_QBE, qins), 30)),
    ));

    let mut exp_normn = norm_s(norm_sum);
    exp_normn = sub(exp_normn, 1);
    let exp_normd = norm_s(s.harmonic_band);
    let div = div_s(shl(norm_sum, exp_normn), shl(s.harmonic_band, exp_normd));
    // Qbe - (Qns+exp_normn-(exp_normd)+15) -16
    let l_avg_enhf_en_diff = l_sub(
        l_temp_band_energy[s.index0 as usize],
        l_shl(
            l_deposit_h(div),
            sub(sub(SWB_BWE_LR_QBE, add(qns, sub(exp_normn, exp_normd))), 31),
        ),
    );

    // 0.8=26214.4(Q15) 8.0f=131072(Qbe)
    if sub(lf_hf_ge_r, 26214) > 0 && l_sub(l_avg_enhf_en_diff, 8 << SWB_BWE_LR_QBE) > 0 {
        let mut bits_allocweigh: i16 = 6554; // 0.2 6553.6(Q15)
        if l_norm_diff < 0 {
            bits_allocweigh = 13107; // 0.4 13107.2(Q15)
        }
        // Bits_grp[GRP_SB-1] = min((grp_bit_avg/p2a_bands + bits_allocweigh*norm_diff), 10)
        let mut l_temp = l_mult(grp_bit_avg, inv_p2a_bands); // Q0+QIpb+1
        let l_temp2 = mult_32_16(l_norm_diff, bits_allocweigh); // Qbe+Q15-15
        l_temp = l_shr(l_temp, add(qipb, 1));
        l_temp = l_add(l_shl(l_temp, SWB_BWE_LR_QBE), l_temp2);
        bits_grp[last] = extract_h(l_shl(l_temp, sub(16, SWB_BWE_LR_QBE)));
        bits_grp[last] = bits_grp[last].min(10);
        if sub(bits_grp[last], s.esthf_bits) < 0 {
            bits_grp[last] = 0;
        }
        *b = sub(*b, bits_grp[last]);
    }

    let mut exp_shift = sub(add(SWB_BWE_LR_QBE, qins), 47); // (SWB_BWE_LR_Qbe+14+1+QIns-15-16)
    let exp_norm = norm_s(*b);
    let b_norm = shl(*b, exp_norm);
    exp_shift = add(exp_shift, exp_norm);

    let share = |ravg: i32, fact: i16| {
        let l_temp = mult_32_16(ravg, extract_h(l_mult(fact, b_norm)));
        let l_temp = mult_32_16(l_temp, inv_norm_sum);
        extract_h(l_shr(l_temp, exp_shift))
    };
    if sub(s.final_gr_fact_pos, 1) == 0 {
        bits_grp[1] = share(s.l_ravg_sub[1], s.bits_fact);
        bits_grp[2] = share(s.l_ravg_sub[2], s.bits_fact1);
        bits_grp[0] = sub(sub(*b, bits_grp[1]), bits_grp[2]);
    } else {
        bits_grp[0] = share(s.l_ravg_sub[0], s.bits_fact);
        bits_grp[2] = share(s.l_ravg_sub[2], s.bits_fact1);
        bits_grp[1] = sub(sub(*b, bits_grp[0]), bits_grp[2]);
    }

    if sub(bits_grp[2], THR2) < 0 {
        bits_grp[1] = add(bits_grp[1], bits_grp[2]);
        bits_grp[2] = 0;
    }
}
