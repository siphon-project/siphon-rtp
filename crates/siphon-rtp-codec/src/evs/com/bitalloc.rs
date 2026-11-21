//! HQ high-rate bit allocation (TS 26.442 `lib_com/bitalloc_fx.c`; TS 26.445 §6.2.2.3.3): the
//! integer greedy allocation `bitalloc_fx`, the fractional allocation `BitAllocF_fx` used by the
//! SWB generic and transient modes, and the grouped WB allocation `BitAllocWB_fx` of the 32 kbit/s
//! WB mode.

use crate::evs::basop::{mult_32_16, mult_32_32};
use crate::evs::cnst::{
    HQ_GEN_FB, HQ_GEN_SWB, HQ_HARMONIC, NB_SFM, SFM_G1, SFM_G1G2, SFM_N, WID_G1, WID_G2,
};
use crate::evs::com::reordvct::reordvct;
use crate::evs::rom::{Nb, BAND_END_HQ, LNB};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_deposit_l, l_msu, l_mult, l_shl,
    l_shr, l_sub, mult, negate, norm_l, norm_s, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_msu0, l_mult0};

/// `bitalloc_fx`: the greedy integer allocation. `y` holds the norms sorted in decreasing order
/// and `idx` the band each came from; each step gives one bit per coefficient to the band with
/// the largest remaining norm (lowering that norm by `fac` = 3) until `sum` bits are spent or no
/// band can take more than `K - 2` bits; what is left goes to bands without bits, one or two bits
/// at a time (`WID_G2`-wide bands of the second group first, then the `WID_G1` ones).
pub fn bitalloc(
    y: &mut [i16],
    idx: &[i16],
    mut sum: i16,
    n: i16,
    k_max: i16,
    r: &mut [i16],
    sfmsize: &[i16],
    hqswb_clas: i16,
) {
    let n = sub(n, 1);
    let mut sfm_thr = SFM_G1G2;
    if sub(hqswb_clas, HQ_HARMONIC) == 0 {
        sfm_thr = 22;
    }

    let fac: i16 = 3;
    let k_max = sub(k_max, 2);
    let mut im: i16 = 1;
    let mut diff = sum;
    let steps = shr(sum, 3);
    for _ in 0..steps.max(0) {
        let mut k: i16 = 0;
        let mut temp = y[0];
        let mut m: i16 = 1;
        while m < im {
            let v = sub(temp, y[m as usize]);
            temp = temp.max(y[m as usize]);
            if v < 0 {
                k = m;
            }
            m += 1;
        }

        if sub(temp, y[m as usize]) < 0 {
            k = m;
            if sub(im, n) < 0 {
                im = add(im, 1);
            }
        }

        let j = idx[k as usize] as usize;

        if sub(sum, sfmsize[j]) >= 0 && sub(r[j], k_max) < 0 {
            y[k as usize] = sub(y[k as usize], fac);
            r[j] = add(r[j], 1);
            if sub(r[j], k_max) >= 0 {
                y[k as usize] = -32768;
            }
            sum = sub(sum, sfmsize[j]);
        } else {
            y[k as usize] = -32768;
            k = add(k, 1);
            if sub(k, im) == 0 && sub(im, n) < 0 {
                im = add(im, 1);
            }
        }

        if sub(sum, WID_G1) < 0 || sub(diff, sum) == 0 {
            break;
        }

        diff = sum;
        let v = sub(n, 1);

        if sub(k, v) > 0 {
            for ii in 0..=n {
                if sub(y[ii as usize], -32768) > 0 {
                    if sub(ii, n) < 0 {
                        im = add(ii, 1);
                    }
                    break;
                }
            }
        }
    }

    bitalloc_fill(&mut sum, idx, n, r, WID_G2, 0, 1, SFM_G1, sfm_thr, true);
    bitalloc_fill(&mut sum, idx, n, r, WID_G2, 1, 2, SFM_G1, sfm_thr, true);
    bitalloc_fill(&mut sum, idx, n, r, WID_G1, 0, 1, 0, SFM_G1, false);
    bitalloc_fill(&mut sum, idx, n, r, WID_G1, 1, 2, 0, SFM_G1, false);
}

/// One of `bitalloc_fx`'s four tail passes: while at least `width` bits remain, raise the bands
/// `j` (in `idx` order) holding `from` bits to `to`, for `j` in `[low, high)` (`high_only` for the
/// second group, whose lower limit is `low`; the first group's test is `j < high` alone).
fn bitalloc_fill(
    sum: &mut i16,
    idx: &[i16],
    n: i16,
    r: &mut [i16],
    width: i16,
    from: i16,
    to: i16,
    low: i16,
    high: i16,
    second_group: bool,
) {
    if sub(*sum, width) < 0 {
        return;
    }
    for i in 0..=n.max(-1) {
        let j = idx[i as usize];
        let in_group = if second_group {
            sub(j, low) >= 0 && sub(j, high) < 0
        } else {
            sub(j, high) < 0
        };
        if in_group && r[j as usize] == from {
            r[j as usize] = to;
            *sum = sub(*sum, width);
            if sub(*sum, width) < 0 {
                break;
            }
        }
    }
}

/// `BitAllocF_fx`: the fractional allocation. Bits are first spread over the `N` bands in
/// proportion to how far each norm `y` lies above the mean (Q15 per band), redistributed until
/// they sum to `B`, bands below `bs + LNb` bits dropped and bands below one bit per coefficient
/// raised to it, and the rest redistributed again; `Rsubband` (Q3) and `R` (whole bits per band)
/// are the result, the return value the bits used.
pub fn bit_alloc_f(
    y: &[i16],
    bit_rate: i32,
    mut b: i16,
    n: i16,
    r: &mut [i16],
    rsubband: &mut [i16],
    hqswb_clas: i16,
    num_env_bands: i16,
) -> i16 {
    let mut rsubband_w32 = [0i32; NB_SFM as usize]; // Q15
    let count = n.max(0) as usize;

    let bs: i16 = if l_sub(bit_rate, 32000) < 0 { 2 } else { 3 };
    let low_rate: i16 = 1;

    // initial bits distribution: the generic modes weigh the norms over the envelope bands only
    let weighted = if sub(hqswb_clas, HQ_GEN_SWB) == 0 || sub(hqswb_clas, HQ_GEN_FB) == 0 {
        num_env_bands
    } else {
        n
    };
    let (mut t, mut nb) = bit_alloc_f_initial(y, b, count, weighted, &mut rsubband_w32);

    // distribute the remaining bits to subbands with non-zero bits
    let b_fx = l_shl(i32::from(b), 15);
    while l_sub(l_shr(l_add(t, 16384), 15), i32::from(b)) != 0 {
        let l_tmp1 = l_sub(t, b_fx);
        let exp1 = sub(norm_l(l_tmp1), 1);
        let exp2 = norm_s(nb);
        let tmp = div_s(extract_h(l_shl(l_tmp1, exp1)), shl(nb, exp2));
        let m = shl(tmp, sub(exp2, exp1)); // Q14

        t = 0;
        nb = 0;
        for i in 0..count {
            if rsubband_w32[i] > 0 {
                rsubband_w32[i] = l_msu(rsubband_w32[i], m, Nb[i]);
                if rsubband_w32[i] > 0 {
                    nb = add(nb, Nb[i]);
                    t = l_add(t, rsubband_w32[i]);
                } else {
                    rsubband_w32[i] = 0;
                }
            }
        }
    }
    let bits = b;

    // impose bit constraints on subbands with less than the minimum bits
    t = 0;
    nb = 0;
    for i in 0..count {
        if rsubband_w32[i] > 0 {
            if l_sub(rsubband_w32[i], l_shl(i32::from(add(bs, LNB[i])), 15)) < 0
                && sub(low_rate, 1) == 0
            {
                rsubband_w32[i] = 0;
            } else if l_sub(rsubband_w32[i], l_shl(i32::from(Nb[i]), 15)) <= 0 {
                b = sub(b, Nb[i]);
                rsubband_w32[i] = l_shl(i32::from(Nb[i]), 15);
            } else {
                nb = add(nb, Nb[i]);
                t = l_add(t, rsubband_w32[i]);
            }
        }
    }

    bit_alloc_f_above_one_bit(&mut rsubband_w32, count, &mut b, t, nb);
    bit_alloc_f_finish(&rsubband_w32, count, bits, r, rsubband)
}

/// `BitAllocF_fx`'s initial distribution: `Rsubband_w32[i]` (Q15) proportional to
/// `y[i] · band_end - (Σ Nb·y over the first `weighted` bands - 3·B)` for the positive ones;
/// returns their total and the number of coefficients they cover.
fn bit_alloc_f_initial(
    y: &[i16],
    b: i16,
    count: usize,
    weighted: i16,
    rsubband_w32: &mut [i32],
) -> (i32, i16) {
    let fac: i16 = 3;
    let mut l_tmp1: i32 = 0;
    for i in 0..weighted.max(0) as usize {
        l_tmp1 = l_mac0(l_tmp1, Nb[i], y[i]);
    }
    l_tmp1 = l_msu0(l_tmp1, fac, b);

    let mut t: i32 = 0;
    let mut nb: i16 = 0;
    // band_end_HQ[weighted - 1]: weighted is a band count from hq_configure_fx, at least 1
    let band_end = BAND_END_HQ[(weighted - 1).max(0) as usize];
    let mut tmp = add(band_end, shl(band_end, 1));
    let mut exp1 = norm_s(tmp);
    tmp = div_s(16384, shl(tmp, exp1)); // 15 + 14 - exp1
    let exp2 = norm_s(tmp);
    tmp = shl(tmp, exp2);
    exp1 = add(29, sub(exp2, exp1));

    for i in 0..count {
        let l_tmp2 = l_sub(l_mult0(y[i], band_end), l_tmp1);
        rsubband_w32[i] = l_mult0(extract_l(l_tmp2), Nb[i]); // Q0
        if rsubband_w32[i] > 0 {
            nb = add(nb, Nb[i]);
            let l_tmp3 = mult_32_16(rsubband_w32[i], tmp); // exp1 - 15
            rsubband_w32[i] = l_shl(l_tmp3, sub(30, exp1)); // Q15
            t = l_add(t, rsubband_w32[i]);
        } else {
            rsubband_w32[i] = 0;
        }
    }
    (t, nb)
}

/// `BitAllocF_fx`'s second redistribution: move the difference between the total `t` and `B`
/// over the bands with more than one bit per coefficient; bands that fall to one bit per
/// coefficient are pinned there. If no band is left above that, bits are taken back from the
/// highest bands with bits until the budget is no longer overdrawn.
fn bit_alloc_f_above_one_bit(
    rsubband_w32: &mut [i32],
    count: usize,
    b: &mut i16,
    mut t: i32,
    mut nb: i16,
) {
    while l_sub(l_shr(l_add(t, 16384), 15), i32::from(*b)) != 0 {
        let l_tmp1 = l_sub(t, l_shl(i32::from(*b), 15));
        let l_tmp2 = l_abs(l_tmp1);

        if nb > 0 {
            let exp1 = sub(norm_l(l_tmp2), 1);
            let exp2 = norm_s(nb);
            let tmp = div_s(extract_h(l_shl(l_tmp2, exp1)), shl(nb, exp2));
            let mut m = shl(tmp, sub(exp2, exp1)); // Q14
            if l_tmp1 < 0 {
                m = negate(m);
            }

            t = 0;
            nb = 0;
            for i in 0..count {
                if l_sub(rsubband_w32[i], l_shl(i32::from(Nb[i]), 15)) > 0 {
                    rsubband_w32[i] = l_msu(rsubband_w32[i], m, Nb[i]);
                    if l_sub(rsubband_w32[i], l_shl(i32::from(Nb[i]), 15)) > 0 {
                        nb = add(nb, Nb[i]);
                        t = l_add(t, rsubband_w32[i]);
                    } else {
                        *b = sub(*b, Nb[i]);
                        rsubband_w32[i] = l_shl(i32::from(Nb[i]), 15);
                    }
                }
            }
        }
        // in case no subband has more than one bit per sample, take bits off the higher subbands
        if t == 0 {
            for i in (0..count).rev() {
                if rsubband_w32[i] > 0 {
                    *b = add(*b, Nb[i]);
                    rsubband_w32[i] = 0;
                    if *b >= 0 {
                        break;
                    }
                }
            }
            break;
        }
    }
}

/// `BitAllocF_fx`'s tail: `Rsubband` (Q3) from the Q15 allocation, the rounding error against
/// `bits` taken off (or added to) the first band that can absorb it, then `R` and the total.
fn bit_alloc_f_finish(
    rsubband_w32: &[i32],
    count: usize,
    bits: i16,
    r: &mut [i16],
    rsubband: &mut [i16],
) -> i16 {
    let mut tmp: i16 = 0;
    for i in 0..count {
        rsubband[i] = extract_l(l_shr(rsubband_w32[i], 12));
        tmp = add(tmp, rsubband[i]);
    }

    let b_w16 = shl(bits, 3);
    if sub(tmp, b_w16) > 0 {
        tmp = sub(tmp, b_w16);
        for i in 0..count {
            if sub(rsubband[i], add(shl(Nb[i], 3), tmp)) >= 0 {
                rsubband[i] = sub(rsubband[i], tmp);
                break;
            }
        }
    } else {
        tmp = sub(tmp, b_w16);
        for value in rsubband.iter_mut().take(count) {
            if *value > 0 {
                *value = sub(*value, tmp);
                break;
            }
        }
    }

    // total used bits, and R for the noise filling
    tmp = 0;
    for i in 0..count {
        tmp = add(tmp, rsubband[i]);
        r[i] = shr(rsubband[i], 3);
    }
    shr(tmp, 3)
}

/// `Bit_group_fx`: allocate `Bits` over bands `[start_band, end_band)` (at most 16): the norms,
/// sorted and tilted down by `fac` (Q13, `fac[1]` for groups with `thr > 5`), share the bits in
/// proportion, bands below `thr` bits dropped from the top until the rest all reach it; when the
/// group cannot give every band 0.75 of a bit, only the `bit_band` largest are considered.
/// Writes `Rsubband` (Q21) of the group's bands.
fn bit_group(
    y: &[i16],
    start_band: i16,
    end_band: i16,
    bits: i16,
    thr: i16,
    rsubband: &mut [i32],
    fac: &[i16; 2],
) {
    let mut y_index = [0i16; 16];
    let mut index = [0i16; 16];
    let mut r_temp = [0i32; 16];

    // initialisation for the bit allocation in one group
    let mut tmp: i16 = 6554; // 1/5, Q15
    if sub(thr, 5) == 0 {
        tmp = 6554;
    }
    if sub(thr, 6) == 0 {
        tmp = 5462; // 1/6
    }
    if sub(thr, 7) == 0 {
        tmp = 4682; // 1/7
    }
    let bit_band = mult(tmp, bits);
    let band_num = sub(end_band, start_band);
    let count = band_num.max(0) as usize;

    for i in 0..count {
        y_index[i] = y[add(i as i16, start_band) as usize];
        index[i] = i as i16;
    }

    // rearrange the norm vector in decreasing order
    reordvct(&mut y_index, band_num, &mut index);

    // norm vector modification
    let factor = div_s(1, band_num); // Q15
    let tilt = if sub(thr, 5) > 0 { fac[1] } else { fac[0] };
    for (i, value) in y_index.iter_mut().enumerate().take(count) {
        let l_tmp = l_mult(i as i16, factor); // Q16
        let mut t = extract_h(l_shl(l_tmp, 13)); // Q13
        t = sub(tilt, t);
        let l_tmp = l_mult(*value, t); // Q14
        *value = extract_h(l_shl(l_tmp, 2)); // Q0
    }

    // bit allocation based on the modified norm
    let l_tmp = l_mult(band_num, 24576); // Q16
    let limit = extract_h(l_shl(l_tmp, 7)); // Q7
    if sub(shl(bit_band, 7), limit) >= 0 {
        bit_group_all(&mut y_index, &mut r_temp, count, bits, thr);
    } else {
        bit_group_largest(&mut y_index, &mut r_temp, count, bit_band, bits, thr);
    }

    // index comeback
    for k in 0..count {
        let j = index[k];
        rsubband[add(j, start_band) as usize] = r_temp[k];
    }
}

/// `R_temp[k]` (Q21) of the first `i` bands: `Bits · y_index[k] / norm_sum`, or 0 when the
/// norms sum to zero.
fn bit_group_share(y_index: &[i16], r_temp: &mut [i32], i: usize, norm_sum: i16, bits: i16) {
    if norm_sum == 0 {
        r_temp[..i].fill(0);
    } else {
        let exp = norm_s(norm_sum);
        let mut tmp = shl(norm_sum, exp); // Q(exp)
        tmp = div_s(16384, tmp); // Q(15+14-exp)
        let bits_avg = l_mult(tmp, bits); // Q(30-exp)
        for k in 0..i {
            let mut l_tmp = l_shl(l_deposit_l(y_index[k]), 24);
            l_tmp = mult_32_32(bits_avg, l_tmp); // Q(23-exp)
            r_temp[k] = l_shl(l_tmp, sub(exp, 2)); // Q21
        }
    }
}

/// `Bit_group_fx` when every band of the group is a candidate: drop the smallest band while it
/// gets fewer than `thr` bits.
fn bit_group_all(y_index: &mut [i16], r_temp: &mut [i32], count: usize, bits: i16, thr: i16) {
    for j in 0..count {
        if y_index[j] < 0 {
            y_index[j] = 0;
        }
        r_temp[j] = 2_097_152; // 1, Q21
    }

    let mut i = count as isize - 1;
    let mut norm_sum: i16 = 0;
    for &value in &y_index[..count] {
        norm_sum = add(norm_sum, value);
    }

    for _ in 0..count {
        // i >= 0: it starts at count - 1 and drops by one per pass of this count-pass loop
        let top = i.max(0) as usize;
        bit_group_share(y_index, r_temp, top + 1, norm_sum, bits);

        let l_tmp = l_shl(l_deposit_l(thr), 21); // Q21
        if l_sub(r_temp[top], l_tmp) < 0 {
            r_temp[top] = l_deposit_h(0);
            norm_sum = sub(norm_sum, y_index[top]);
            i -= 1;
        } else {
            break;
        }
    }
}

/// `Bit_group_fx` when only the `bit_band` largest bands are candidates: share among them,
/// cutting the list at the first band below `thr` bits, until the shared total stops changing.
fn bit_group_largest(
    y_index: &mut [i16],
    r_temp: &mut [i32],
    count: usize,
    bit_band: i16,
    bits: i16,
    thr: i16,
) {
    // bit_band < 0.75 · band_num here, so the candidates are inside the group
    let candidates = (bit_band.max(0) as usize).min(count);
    for j in 0..candidates {
        if y_index[j] < 0 {
            y_index[j] = 0;
        }
        r_temp[j] = 2_097_152; // 1, Q21
    }
    r_temp[candidates..count].fill(0);

    let mut norm_sum: i16 = 0;
    for &value in &y_index[..candidates] {
        norm_sum = add(norm_sum, value);
    }

    let mut r_sum_org: i32 = 0;
    let mut i = candidates;
    for _ in 0..candidates {
        bit_group_share(y_index, r_temp, i, norm_sum, bits);
        let mut r_sum: i32 = 0;
        let l_tmp = l_shl(l_deposit_l(thr), 21); // Q21
        for k in 0..i {
            if l_sub(r_temp[k], l_tmp) < 0 {
                for m in k..i {
                    norm_sum = sub(norm_sum, y_index[m]);
                    r_temp[m] = 0;
                }
                i = k;
                break;
            }
            r_sum = l_add(r_sum, r_temp[k]);
        }
        if l_sub(r_sum, r_sum_org) == 0 {
            break;
        }
        r_sum_org = r_sum;
    }
}

/// Sum of the positive norms `y[from..to]` (`BitAllocWB_fx`'s group sums).
fn positive_sum(y: &[i16], from: usize, to: usize) -> i16 {
    let mut sum: i16 = 0;
    for &value in &y[from..to] {
        if value > 0 {
            sum = add(sum, value);
        }
    }
    sum
}

/// `B · Rsum_sub / Rsum`, rounded up when the remainder allows (`BitAllocWB_fx`'s group share);
/// `tmp` and `exp` are the normalised reciprocal of `Rsum`.
fn bit_alloc_wb_share(b: i16, rsum_sub: i16, rsum: i16, tmp: i16, exp: i16) -> i16 {
    let l_tmp1 = l_mult(b, rsum_sub); // Q1
    let l_tmp = mult_32_16(l_tmp1, tmp); // Q(15-exp)
    let mut share = extract_h(l_shl(l_tmp, add(exp, 1))); // Q0
    if l_sub(l_tmp1, l_mult(share, rsum)) > 0 && l_sub(l_tmp1, l_mult(add(share, 1), rsum)) >= 0 {
        share = add(share, 1);
    }
    share
}

/// `BitAllocWB_fx`: the 32 kbit/s WB allocation. The `B` bits are split over three groups of
/// bands (`[0, SFM_G1)`, `[SFM_G1, SFM_G1G2)`, the rest) by their norm sums, with caps when the
/// spectrum is flat, then allocated inside each group by `Bit_group_fx`. Writes `Rsubband` (Q3)
/// and `R` (whole bits) and returns the bits used.
pub fn bit_alloc_wb(y: &[i16], b: i16, n: i16, r: &mut [i16], rsubband: &mut [i16]) -> i16 {
    let mut rsubband_buf = [0i32; NB_SFM as usize];
    let bands = n.min(SFM_N);
    let band_count = bands.max(0) as usize;
    // init Rsubband to non-zero values for bands to be allocated bits
    rsubband_buf[..band_count].fill(2_097_152); // Q21

    // norm sum and average of each group
    let g1 = SFM_G1 as usize;
    let g1g2 = SFM_G1G2 as usize;
    let rsum_sub = [
        positive_sum(y, 0, g1),
        positive_sum(y, g1, g1g2),
        positive_sum(y, g1g2, band_count.max(g1g2)),
    ];
    let ravg_sub = [
        l_mult(rsum_sub[0], 2048), // Q16, 1/16
        l_mult(rsum_sub[1], 4096), // Q16, 1/8
        l_mult(rsum_sub[2], div_s(1, bands - SFM_G1G2)),
    ];

    // bit allocation for every group
    let rsum = add(add(rsum_sub[0], rsum_sub[1]), rsum_sub[2]);
    let mut factor: [i16; 2] = [16384, 24576]; // Q13
    let r_diff = [
        l_sub(ravg_sub[0], ravg_sub[1]),
        l_sub(ravg_sub[1], ravg_sub[2]),
    ];

    let (b1, mut b2, mut b3);
    if l_sub(r_diff[0], 393_216) < 0 && l_sub(r_diff[1], 245_760) < 0 {
        let (mut s1, mut s2, mut s3) = (0, 0, 0);
        if rsum != 0 {
            let exp = norm_s(rsum);
            let tmp = div_s(16384, shl(rsum, exp)); // Q(15+14-exp)
            s1 = bit_alloc_wb_share(b, rsum_sub[0], rsum, tmp, exp);
            s2 = bit_alloc_wb_share(b, rsum_sub[1], rsum, tmp, exp);
            s3 = bit_alloc_wb_share(b, rsum_sub[2], rsum, tmp, exp);
        }
        if l_sub(ravg_sub[2], 786_432) > 0 {
            bit_alloc_wb_cap(b, &mut s1, &mut s2, &mut s3);
        }
        (b1, b2, b3) = (s1, s2, s3);
        factor = [16384, 12288];
    } else if rsum == 0 {
        (b1, b2, b3) = (0, 0, b);
    } else {
        let exp = norm_s(rsum);
        let tmp = div_s(16384, shl(rsum, exp)); // Q(15+14-exp)
        b1 = bit_alloc_wb_share(b, rsum_sub[0], rsum, tmp, exp);
        let mut l_tmp1 = mult_32_16(1_975_684_956, shl(b, 5)); // Q21
        l_tmp1 = mult_32_16(l_tmp1, shl(rsum_sub[1], 7)); // Q13
        let l_tmp = mult_32_16(l_tmp1, tmp); // Q(27-exp)
        b2 = extract_h(l_shl(l_tmp, sub(exp, 11))); // Q0
        if l_sub(l_tmp1, l_shl(l_mult(b2, rsum), 12)) > 0
            && l_sub(l_add(l_tmp1, 2), l_shl(l_mult(add(b2, 1), rsum), 12)) >= 0
        {
            b2 = add(b2, 1);
        }
        b3 = sub(sub(b, b1), b2);
    }

    if sub(rsum_sub[2], 3) < 0 {
        b2 = add(b2, b3);
        b3 = 0;
    }

    // bit allocation in each group
    bit_group(y, 0, SFM_G1, b1, 5, &mut rsubband_buf, &factor);
    bit_group(y, SFM_G1, SFM_G1G2, b2, 6, &mut rsubband_buf, &factor);
    bit_group(y, SFM_G1G2, bands, b3, 7, &mut rsubband_buf, &factor);
    for i in 0..band_count {
        rsubband[i] = extract_l(l_shr(rsubband_buf[i], 18));
    }

    // total used bits, and R for the noise filling
    let mut l_tmp: i32 = 0;
    for i in 0..n.max(0) as usize {
        l_tmp = l_add(l_tmp, rsubband_buf[i]); // Q21
        r[i] = extract_h(l_shr(rsubband_buf[i], 5)); // Q0
    }
    extract_h(l_shr(l_tmp, 5))
}

/// `BitAllocWB_fx`'s caps for a loud third group: at most 288 / 256 / 96 bits per group, the
/// excess handed to the uncapped groups.
fn bit_alloc_wb_cap(b: i16, b1: &mut i16, b2: &mut i16, b3: &mut i16) {
    let mut b_saved: i16 = 0;
    if sub(*b1, 288) > 0 {
        b_saved = sub(*b1, 288);
        *b1 = 288;
    }
    if sub(*b2, 256) > 0 {
        b_saved = add(b_saved, sub(*b2, 256));
        *b2 = 256;
    }
    if sub(*b3, 96) > 0 {
        b_saved = add(b_saved, sub(*b3, 96));
        *b3 = 96;
    }

    if b_saved > 0 {
        if sub(*b1, 288) == 0 {
            *b2 = add(*b2, shr(b_saved, 1));
            *b3 = sub(sub(b, *b1), *b2);
        } else {
            *b1 = add(*b1, shr(b_saved, 1));
            if sub(*b2, 256) == 0 {
                *b3 = sub(sub(b, *b1), *b2);
            } else {
                *b2 = sub(sub(b, *b1), *b3);
            }
        }
    }
}
