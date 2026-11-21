//! The QPPP prototype dequantiser and its spectral helpers (TS 26.442 `lib_com/wi_fx.c`;
//! TS 26.445 §6.1.2.3): the ERB-domain amplitude codebooks (`erb_add_fx`, `erb_slot_fx`,
//! `DTFS_erb_inv_fx`, `DTFS_to_erb_fx`), the band energy control (`DTFS_setEngyHarm_fx`,
//! `rshiftHarmBand_fx`), the polar conversion and phase copy (`DTFS_car2pol_fx`, `copy_phase_fx`),
//! the quarter-sample phase shift (`Q2phaseShift_fx`) and `DTFS_dequant_cw_fx` above them.
//!
//! Harmonic indices are bounded by `lag / 2 <= MAX_LAG_PIT / 2 < MAXLAG_WI` on every decoder
//! path; the loops still stop at the array end ([`band`]), where the reference would read past
//! `a_fx` on a prototype no caller builds.

use super::{at, half_lag, DtfsStructure, LAG_MAX};
use crate::evs::basop::{l_extract_lc, mult_32_16};
use crate::evs::cnst::{EVS_SW_MAX, MAX_32, NUM_ERB_NB, NUM_ERB_WB};
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::math_op::{isqrt_lc, pow2};
use crate::evs::rom::{
    AMPCB1_NB_FX, AMPCB1_WB_FX, AMPCB2_NB_FX, AMPCB2_WB_FX, ERB_NB_FX, ERB_WB_FX, POWERCB_NB_FX,
    POWERCB_WB_FX,
};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_mac, l_msu, l_mult, l_negate, l_shl,
    l_shr, l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::oper_32b::mpy_32_16;
use crate::itu::stl2009::{l_mac0, l_mult0, shl_r};

const NUM_ERB_MAX: usize = NUM_ERB_WB as usize;

/// The harmonic indices `low + 1 ..= high` the band loops visit, clipped to the arrays.
#[inline]
fn band(low: i16, high: i16) -> std::ops::Range<usize> {
    let start = (i32::from(low) + 1).max(0) as usize;
    let end = (i32::from(high) + 1).clamp(0, LAG_MAX as i32) as usize;
    start..end.max(start)
}

/// `table[index]`, 0 outside it (the codebooks are indexed by bitstream fields the reference
/// bounds by their bit widths, and by ERB counts it only ever sets to `NUM_ERB_NB` / `_WB`).
#[inline]
fn entry(table: &[i16], index: i32) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|i| table.get(i))
        .copied()
        .unwrap_or(0)
}

/// `Q2phaseShift_fx`: rotate the harmonics of `x_fx` by `ph` quarter samples of the period `lag`
/// (`S_fx` / `C_fx` the sin / cos tables of `4·lag` entries).
pub fn q2phase_shift(x_fx: &mut DtfsStructure, ph: i16, lag: i16, s_fx: &[i16], c_fx: &[i16]) {
    let mut temp2: i32 = 0;
    let modulus = 4 * i32::from(lag);
    let half = half_lag(x_fx.lag, x_fx.nh);

    if ph > 0 {
        for k in 0..half {
            let temp = x_fx.a[k];
            let c = at(c_fx, temp2, modulus);
            let s = at(s_fx, temp2, modulus);
            x_fx.a[k] = round_word(l_msu(l_mult(temp, c), x_fx.b[k], s)); // X.Q
            x_fx.b[k] = round_word(l_mac(l_mult(x_fx.b[k], c), temp, s));
            temp2 = l_add(temp2, i32::from(ph));
        }
    }

    if ph < 0 {
        for k in 0..half {
            let temp = x_fx.a[k];
            let c = at(c_fx, temp2, modulus);
            let s = at(s_fx, temp2, modulus);
            x_fx.a[k] = round_word(l_mac(l_mult(temp, c), x_fx.b[k], s)); // X.Q
            x_fx.b[k] = round_word(l_msu(l_mult(x_fx.b[k], c), temp, s));
            // the reference adds in 16 bits: `add((Word16)temp2, negate(ph))`
            temp2 = i32::from(add(temp2 as i16, negate(ph)));
        }
    }
}

/// `1 / sqrt(lacc)` scaled back to Q`q`, as `DTFS_car2pol_fx` computes a harmonic magnitude from
/// its squared value `lacc` (Q`2q`, already known to be non-zero).
fn car2pol_magnitude(lacc: i32, q: i16) -> i16 {
    let mut exp = norm_l(lacc);
    let frac = extract_h(l_shl(lacc, exp)); // Q14
    exp = sub(exp, sub(30, shl(q, 1)));

    let tmp = div_s(16384, frac); // Q15
    let ltemp = isqrt_lc(l_deposit_h(tmp), &mut exp); // Q(31-exp)

    extract_h(l_shl(ltemp, sub(add(q, exp), 15))) // Q
}

/// `DTFS_car2pol_fx`: replace each harmonic's cosine amplitude by the magnitude `sqrt(a² + b²)`
/// and clear the sine part (the phase is not kept: QPPP copies it with [`copy_phase`]).
pub fn dtfs_car2pol(x_fx: &mut DtfsStructure) {
    let half_lag = shr(sub(x_fx.lag, 1), 1).min(x_fx.nh);
    let mut k: i16 = 1;
    while k <= half_lag && (k as usize) < LAG_MAX {
        let ku = k as usize;
        let mut lacc = l_mult(x_fx.a[ku], x_fx.a[ku]); // a[k]^2, 2Q+1
        lacc = l_mac(lacc, x_fx.b[ku], x_fx.b[ku]); // a[k]^2+b[k]^2, 2Q+1
        lacc = l_shr(lacc, 3); // Lacc=(a[k]^2+b[k]^2)/4, 2Q

        if lacc != 0 {
            // the reference writes `30 - 2*X_fx->Q` as `sub(30, (2*X_fx->Q))`, i.e. without
            // the saturating `shl`; equal for every prototype Q
            let mut exp = norm_l(lacc);
            let frac = extract_h(l_shl(lacc, exp)); // Q14
            exp = sub(exp, sub(30, x_fx.q.wrapping_mul(2)));
            let tmp = div_s(16384, frac); // Q15
            let ltemp = isqrt_lc(l_deposit_h(tmp), &mut exp); // Q(31-exp)
            x_fx.a[ku] = extract_h(l_shl(ltemp, sub(add(x_fx.q, exp), 15))); // Q
        } else {
            x_fx.a[ku] = 0;
        }
        x_fx.b[ku] = 0; // clear b[k]
        k += 1;
    }

    // `k` is the harmonic after the loop's last one (at least 1)
    if x_fx.lag & 1 == 0 && (k as usize) < LAG_MAX {
        let ku = k as usize;
        if x_fx.a[ku] != 0 {
            let mut lacc = l_mult0(x_fx.a[ku], x_fx.a[ku]); // a[k]^2, 2Q+1
            lacc = l_mac0(lacc, x_fx.b[ku], x_fx.b[ku]); // a[k]^2+b[k]^2, 2Q+1
            x_fx.a[ku] = car2pol_magnitude(lacc, x_fx.q);
        } else {
            x_fx.a[ku] = 0;
        }
        x_fx.b[ku] = 0; // clear b[k]
    }
}

/// `DTFS_setEngyHarm_fx`: scale the harmonics of `x_fx` in the band `(g1, g2]` so that the
/// band `(f1, f2]` (frequencies normalised by 12800, Q15) has the mean energy `en2_fx`
/// (Q`qen2_fx`; 0 leaves the band zeroed). Returns the band's energy before (Q`2·X.Q`), and in
/// `qa_fx` the Q the scaled harmonics are in.
pub fn dtfs_set_engy_harm(
    f1_fx: i16,
    f2_fx: i16,
    g1_fx: i16,
    g2_fx: i16,
    en2_fx: i32,
    qen2_fx: i16,
    qa_fx: &mut i16,
    x_fx: &mut DtfsStructure,
) -> i32 {
    let mut count: i16 = 0;
    let mut lacc_max: i32 = 0;
    let mut expp: i16 = 0;

    let f_low_fx = mult(f1_fx, x_fx.lag); // Q0
    let f_high_fx = mult(f2_fx, x_fx.lag); // Q0
    let g_low_fx = mult(g1_fx, x_fx.lag); // Q0
    let g_high_fx = mult(g2_fx, x_fx.lag); // Q0
    let mut half_lag_fx = f_high_fx.min(shl(x_fx.nh, 1));

    let mut lacc: i32 = 0;
    for k in band(f_low_fx, half_lag_fx) {
        lacc = l_mac0(lacc, x_fx.a[k], x_fx.a[k]); // 2*X1.Q
        lacc_max = lacc_max.max(lacc);
        count = add(count, 1);
    }

    // a saturated sum: redo it with each square scaled down by the band width
    let saturated = l_sub(lacc_max, MAX_32) >= 0;
    if saturated {
        let tmp = sub(half_lag_fx, f_low_fx);
        let exp = norm_s(tmp);
        expp = sub(15, exp);

        lacc = 0;
        for k in band(f_low_fx, half_lag_fx) {
            let l_tmp = l_mult(x_fx.a[k], x_fx.a[k]);
            lacc = l_add(lacc, l_shr(l_tmp, expp)); // 2*X1.Q-expp
            count = add(count, 1);
        }
    }

    if count <= 0 {
        count = 1;
    }

    let mut exp = norm_s(count);
    let tmp = div_s(shl(1, sub(14, exp)), count); // 29 - exp
    let en1_fx = l_shl(mult_32_16(lacc, tmp), sub(exp, 14));

    let factor_fx = if en1_fx > 0 && en2_fx > 0 {
        let mut expa = norm_l(en2_fx);
        let fraca = extract_h(l_shl(en2_fx, expa));
        expa = sub(30, add(expa, qen2_fx));

        let mut expb = norm_l(en1_fx);
        let mut fracb = round_word(l_shl(en1_fx, expb));

        if saturated {
            expb = sub(30, add(expb, sub(shl(x_fx.q, 1), expp)));
        } else {
            expb = sub(30, add(expb, shl(x_fx.q, 1)));
        }

        let scale = shr(sub(fraca, fracb), 15);
        fracb = shl(fracb, scale);
        expb = sub(expb, scale);

        let tmp = div_s(fracb, fraca);
        exp = sub(expb, expa);

        let l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp); // Q(31-exp)

        if saturated {
            l_shr(l_tmp, add(1, expp.min(2)))
        } else {
            l_shr(l_tmp, 1)
        }
    } else {
        0
    };

    half_lag_fx = g_high_fx.min(shl(x_fx.nh, 1));
    for k in band(g_low_fx, half_lag_fx) {
        let l_temp_fx = mult_32_16(factor_fx, x_fx.a[k]); // Q(temp+X1.Q-15)
        x_fx.a[k] = round_word(l_temp_fx); // Q(temp+X1.Q-31)
    }

    if saturated {
        *qa_fx = sub(sub(x_fx.q, add(1, expp.min(2))), exp);
    } else {
        *qa_fx = sub(sub(x_fx.q, 1), exp);
    }

    en1_fx // Q(2*X1.Q)
}

/// `count`'s mean of a sum `value` in Q`q` as `DTFS_to_erb_fx` / `erb_slot_fx` divide it: the
/// magnitude's mantissa over the count's, with the exponent difference shifted by `shift`.
fn mean_of(value: i32, q: i16, count: i16, shift: i16) -> i16 {
    let mut expb = norm_l(value);
    let mut fracb = round_word(l_shl(value, expb));
    expb = sub(30, add(expb, q));

    let mut expa = norm_l(i32::from(count));
    let fraca = extract_h(l_shl(i32::from(count), expa));
    expa = sub(30, expa);

    let scale = shr(sub(fraca, fracb), 15);
    fracb = shl(fracb, scale);
    expb = sub(expb, scale);

    let tmp = div_s(fracb, fraca);
    let exp = sub(expb, expa);
    round_word(l_shl(i32::from(tmp), add(exp, shift)))
}

/// The ERB band edges for a cut-off, as `DTFS_to_erb_fx` picks them; `None` for a cut-off the
/// reference has no table for (it would dereference a null pointer; no decoder path does).
fn erb_table_for_cut_off(cut_off: i16) -> (i16, Option<&'static [i16]>) {
    if sub(cut_off, 0x02800) == 0 || sub(cut_off, 4000) == 0 {
        // 0x2800=0.3125 in Q15 (4000Hz)
        (NUM_ERB_NB, Some(&ERB_NB_FX[..]))
    } else if sub(cut_off, 0x04000) == 0 || sub(cut_off, 6400) == 0 {
        // 0x4000=0.5 in Q15 (6400Hz)
        (NUM_ERB_WB, Some(&ERB_WB_FX[..]))
    } else {
        (NUM_ERB_NB, None)
    }
}

/// The ERB band edges for a band count, as `erb_slot_fx` picks them (and its cut-off in Hz).
fn erb_table_for_count(num_erb_fx: i16) -> (i16, Option<&'static [i16]>) {
    if sub(num_erb_fx, NUM_ERB_NB) == 0 {
        (4000, Some(&ERB_NB_FX[..]))
    } else if sub(num_erb_fx, NUM_ERB_WB) == 0 {
        (6400, Some(&ERB_WB_FX[..]))
    } else {
        (4000, None)
    }
}

/// `1 / lag` in Q19 rounded to 16 bits (`diff_fx` of the ERB mappings).
fn inverse_lag(lag: i16) -> i16 {
    let exp = norm_s(lag);
    let tmp = div_s(shl(1, sub(14, exp)), lag); // 29-exp
    round_word(l_shl(i32::from(tmp), add(exp, 6)))
}

/// `DTFS_to_erb_fx`: the mean harmonic amplitude of `x_fx` in each ERB band (Q13) into `out_fx`
/// (22 bands below 4 kHz, 24 below 6.4 kHz, by the prototype's cut-off).
pub fn dtfs_to_erb(x_fx: &DtfsStructure, out_fx: &mut [i16]) {
    let mut count = [0_i16; NUM_ERB_MAX];
    let mut sum_a_fx = [0_i32; NUM_ERB_MAX];

    let (num_erb_fx, erb_fx) = erb_table_for_cut_off(x_fx.upper_cut_off_freq);
    let num = num_erb_fx as usize;

    let diff_fx = inverse_lag(x_fx.lag);
    let n = shr(x_fx.lag, 1).min(x_fx.nh);

    if let Some(erb_fx) = erb_fx {
        let mut j = 0;
        for i in 0..=n.clamp(-1, LAG_MAX as i16 - 1) {
            let ltemp_fx = l_mult(diff_fx, i); // Ltemp=i*diff, Q20
            while j < num {
                if l_sub(ltemp_fx, l_shl(i32::from(erb_fx[j + 1]), 5)) < 0 {
                    sum_a_fx[j] = l_add(sum_a_fx[j], i32::from(x_fx.a[i as usize])); // X_fx.Q
                    count[j] = add(count[j], 1);
                    break;
                }
                j += 1;
            }
        }
    }

    // Make output in Q13
    let n = sub(29, x_fx.q);
    for i in 0..num {
        out_fx[i] = round_word(l_shl(sum_a_fx[i], n)); // Q13

        if sub(count[i], 1) > 0 {
            let l_temp = if sum_a_fx[i] < 0 {
                l_negate(sum_a_fx[i])
            } else {
                l_add(sum_a_fx[i], 0)
            };
            out_fx[i] = mean_of(l_temp, x_fx.q, count[i], 14);
        }
    }
}

/// `erb_slot_fx`: how many harmonics of the period `lag_fx` fall in each of the `num_erb_fx` ERB
/// bands (`out_fx`) and the bands' mean harmonic frequency (`mfreq_fx`, normalised by 12800,
/// Q15).
pub fn erb_slot(lag_fx: i16, out_fx: &mut [i16], mfreq_fx: &mut [i16], num_erb_fx: i16) {
    let mut mf_fx = [0_i32; NUM_ERB_MAX];
    let (upper_cut_off_freq_fx, erb_fx) = erb_table_for_count(num_erb_fx);
    let num = (num_erb_fx.max(0) as usize).min(NUM_ERB_MAX);

    let mut exp = norm_s(lag_fx);
    let mut tmp = div_s(shl(1, sub(14, exp)), lag_fx); // Q29-exp
    let mut l_tmp1 = l_mult(12800, tmp); // Q(30-exp)
    let diff_fx = extract_h(l_shl(l_tmp1, sub(exp, 14))); // Q0

    exp = norm_s(diff_fx);
    tmp = div_s(shl(1, sub(14, exp)), diff_fx); // Q29-exp
    l_tmp1 = l_mult(upper_cut_off_freq_fx, tmp); // Q(30-exp)
    let mut nh_band_fx = round_word(l_shl(l_tmp1, sub(exp, 14))); // Q0

    out_fx[..num].fill(0);

    let l_tmp = l_mult0(diff_fx, nh_band_fx); // Q0
    if l_sub(i32::from(upper_cut_off_freq_fx), l_tmp) >= i32::from(diff_fx) {
        nh_band_fx = add(nh_band_fx, 1); // Q0
    }

    let n = shr(lag_fx, 1).min(nh_band_fx);
    let diff_fx = inverse_lag(lag_fx);

    if let Some(erb_fx) = erb_fx {
        let mut j = 0;
        for i in 0..=n.max(-1) {
            let mut ltemp_fx = l_mult(diff_fx, i); // Ltemp=i*diff, Q20
            if sub(num_erb_fx, NUM_ERB_NB) == 0 {
                ltemp_fx = ltemp_fx.min(0x050000); // 0x50000=0.3125 in Q20 (4000Hz)
            } else if sub(num_erb_fx, NUM_ERB_WB) == 0 {
                ltemp_fx = ltemp_fx.min(0x080000); // 0x80000=0.5 in Q20 (6400Hz)
            }
            while j < num {
                if l_sub(ltemp_fx, l_shl(i32::from(erb_fx[j + 1]), 5)) < 0 {
                    mf_fx[j] = l_add(mf_fx[j], ltemp_fx);
                    out_fx[j] = add(out_fx[j], 1);
                    break;
                }
                j += 1;
            }
        }
    }

    for j in 0..num {
        mfreq_fx[j] = round_word(l_shl(mf_fx[j], 11)); // Q15
        if sub(out_fx[j], 1) > 0 {
            mfreq_fx[j] = mean_of(mf_fx[j], 20, out_fx[j], 16);
        }
    }
}

/// One harmonic of `DTFS_erb_inv_fx`: the amplitude linearly interpolated at `freq` between the
/// ERB points `(f_lo, amp_lo)` and `(f_hi, amp_hi)` (with `d1 = f_hi - freq`), normalised, and
/// its Q.
fn erb_inv_interpolate(f_lo: i16, f_hi: i16, amp_lo: i16, amp_hi: i16, freq: i16) -> (i16, i16) {
    let d1 = sub(f_hi, freq);
    let mut d2 = sub(freq, f_lo);
    let mut ltemp_fx = l_mac(l_mult(amp_hi, d2), amp_lo, d1); // Q29
    d2 = sub(f_hi, f_lo); // Q15
    let exp = norm_s(d2);
    let tmp = div_s(shl(1, sub(14, exp)), d2); // 29-exp
    let ltemp2_fx = l_shl(i32::from(tmp), 16);
    let n = add(exp, 16);

    let d1h = extract_h(ltemp_fx);
    let d1l = extract_l(ltemp_fx);
    let mut d2h = extract_h(ltemp2_fx);
    let d2l = extract_l(ltemp2_fx);
    ltemp_fx = l_mult0(d1h, d2l);
    let lacc_fx = l_mac0(ltemp_fx, d2h, d1l);
    ltemp_fx = l_add(l_shr(lacc_fx, 15), l_mult(d1h, d2h)); // 46-n+29-31
    d2h = norm_l(ltemp_fx); // d2h is 0 IF Ltemp=0
    if ltemp_fx == 0 {
        d2h = 31;
    }
    let a = round_word(l_shl(ltemp_fx, d2h)); // Q(28-n+d2h)
    (a, add(sub(28, n), d2h))
}

/// `DTFS_erb_inv_fx`: the harmonic amplitudes of `x_fx` (polar, block-normalised to `X.Q`) by
/// linear interpolation of the ERB amplitudes `in_fx` at the occupied bands' mean frequencies
/// (`slot_fx` / `mfreq_fx` from [`erb_slot`]).
pub fn dtfs_erb_inv(
    in_fx: &[i16],
    slot_fx: &[i16],
    mfreq_fx: &[i16],
    x_fx: &mut DtfsStructure,
    num_erb_fx: i16,
) {
    let mut q = [0_i16; LAG_MAX];
    let mut f_fx = [0_i16; NUM_ERB_MAX + 2];
    let mut amp_fx = [0_i16; NUM_ERB_MAX + 2];
    let num = (num_erb_fx.max(0) as usize).min(NUM_ERB_MAX);

    let upper_cut_off_freq_fx: i16 = if sub(num_erb_fx, NUM_ERB_NB) == 0 {
        0x02800 // 0x2800=0.3125 in Q15 (4000Hz)
    } else if sub(num_erb_fx, NUM_ERB_WB) == 0 {
        0x04000 // 0x4000=0.5 in Q15 (6400Hz)
    } else {
        0
    };

    let mut m_fx = 0;
    f_fx[m_fx] = 0;
    amp_fx[m_fx] = 0;
    m_fx += 1;

    for i in 0..num {
        if slot_fx[i] != 0 {
            f_fx[m_fx] = mfreq_fx[i];
            amp_fx[m_fx] = in_fx[i];
            m_fx += 1;
        }
    }
    f_fx[m_fx] = upper_cut_off_freq_fx;
    amp_fx[m_fx] = 0;
    m_fx += 1;

    let exp = norm_s(x_fx.lag);
    let tmp = div_s(shl(1, sub(14, exp)), x_fx.lag); // 29-exp
    let diff_fx = shl(tmp, exp - 10); // Q19

    let mut min_q = EVS_SW_MAX;
    x_fx.a[0] = 0;

    let half = half_lag(x_fx.lag, x_fx.nh);
    let mut j = 1;
    #[allow(clippy::needless_range_loop)] // `i` indexes `a` and `q` in step, as the C does
    for i in 1..half {
        let ltemp_fx = l_mult(diff_fx, i as i16); // Ltemp=i*diff, Q20
        let mut freq_fx = round_word(l_shl(ltemp_fx, 11)); // Q15
        freq_fx = freq_fx.min(upper_cut_off_freq_fx); // 0x4000 is 0.5 in Q15

        while j < m_fx {
            if sub(f_fx[j], freq_fx) >= 0 {
                let (a, qi) =
                    erb_inv_interpolate(f_fx[j - 1], f_fx[j], amp_fx[j - 1], amp_fx[j], freq_fx);
                x_fx.a[i] = a;
                q[i] = qi;
                min_q = min_q.min(qi);
                break;
            }
            j += 1;
        }
    }
    // block normalize a[i]
    #[allow(clippy::needless_range_loop)] // `i` indexes `a` and `q` in step, as the C does
    for i in 1..half {
        x_fx.a[i] = shl(x_fx.a[i], sub(min_q, q[i]));
    }

    x_fx.q = min_q;
}

/// `erb_add_fx`: the current ERB amplitudes (Q13) from the two codebook indices `index_fx` and
/// the previous frame's ERB vector `prev_erb_fx` (lag `pl_fx`), mapped onto the current lag
/// `l_fx`'s occupied bands (empty bands are filled from the nearest occupied neighbour).
pub fn erb_add(
    curr_erb_fx: &mut [i16],
    l_fx: i16,
    prev_erb_fx: &[i16],
    pl_fx: i16,
    index_fx: &[i16],
    num_erb_fx: i16,
) {
    let mut pslot_fx = [0_i16; NUM_ERB_MAX];
    let mut cslot_fx = [0_i16; NUM_ERB_MAX];
    let mut t_prev_erb_fx = [0_i16; NUM_ERB_MAX];
    let num = (num_erb_fx.max(0) as usize).min(NUM_ERB_MAX);

    let amp_cb1_fx: &[i16] = if sub(num_erb_fx, NUM_ERB_NB) == 0 {
        &AMPCB1_NB_FX
    } else if sub(num_erb_fx, NUM_ERB_WB) == 0 {
        &AMPCB1_WB_FX
    } else {
        &[]
    };

    // the second call overwrites the first's mean frequencies, which are not used
    erb_slot(l_fx, &mut cslot_fx, &mut t_prev_erb_fx, num_erb_fx);
    erb_slot(pl_fx, &mut pslot_fx, &mut t_prev_erb_fx, num_erb_fx);

    t_prev_erb_fx[..num].copy_from_slice(&prev_erb_fx[..num]); // Q13

    if sub(pl_fx, l_fx) > 0 {
        let mut tmp_fx = t_prev_erb_fx[0]; // Q13
        for i in 0..num {
            if pslot_fx[i] != 0 {
                tmp_fx = t_prev_erb_fx[i]; // Q13
            } else {
                t_prev_erb_fx[i] = tmp_fx; // Q13
            }
        }
    } else if sub(l_fx, pl_fx) > 0 && num > 0 {
        let mut tmp_fx = t_prev_erb_fx[num - 1]; // Q13
        for i in (0..num).rev() {
            if pslot_fx[i] != 0 {
                tmp_fx = t_prev_erb_fx[i]; // Q13
            } else {
                t_prev_erb_fx[i] = tmp_fx; // Q13
            }
        }
    }

    let tmp_fx = add(shl(index_fx[0], 3), shl(index_fx[0], 1)); // tmp_fx=10*index_fx[0]
    for i in 1..11 {
        if cslot_fx[i] != 0 {
            let cb = entry(amp_cb1_fx, i32::from(sub(add(tmp_fx, i as i16), 1)));
            curr_erb_fx[i] = add(cb, t_prev_erb_fx[i]); // Q13+Q13=Q13
            curr_erb_fx[i] = curr_erb_fx[i].max(0);
        } else {
            curr_erb_fx[i] = 0;
        }
    }

    let tmp_fx = add(shl(index_fx[1], 3), index_fx[1]); // tmp=9*index[1]
    let tmp2_fx = mult(shl(index_fx[1], 6), 5632); // temp=11*index_fx[1]
    let tmp_loop = sub(num_erb_fx, 2);
    for i in 11..tmp_loop.max(11) {
        let iu = i as usize;
        if cslot_fx[iu] != 0 {
            if sub(num_erb_fx, NUM_ERB_NB) == 0 {
                let cb = entry(&AMPCB2_NB_FX, i32::from(sub(add(tmp_fx, i), 11)));
                curr_erb_fx[iu] = add(cb, t_prev_erb_fx[iu]); // Q13+Q13=Q13
                curr_erb_fx[iu] = curr_erb_fx[iu].max(0);
            } else if sub(num_erb_fx, NUM_ERB_WB) == 0 {
                let cb = entry(&AMPCB2_WB_FX, i32::from(sub(add(tmp2_fx, i), 11)));
                curr_erb_fx[iu] = add(cb, t_prev_erb_fx[iu]); // Q13
                curr_erb_fx[iu] = curr_erb_fx[iu].max(0);
            }
        } else {
            curr_erb_fx[iu] = 0;
        }
    }
}

/// `rshiftHarmBand_fx`: shift the harmonics of `x_fx` in the band `(lband, hband]` (normalised
/// frequencies, Q15) right by `-shift_fx` with rounding (`shl_r`).
pub fn rshift_harm_band(x_fx: &mut DtfsStructure, lband_fx: i16, hband_fx: i16, shift_fx: i16) {
    let low_fx = mult(lband_fx, x_fx.lag); // low=lband*lag, Q0
    let high_fx = mult(hband_fx, x_fx.lag); // high=hband*lag, Q0
    let half_lag_fx = high_fx.min(shl(x_fx.nh, 1));

    for k in band(low_fx, half_lag_fx) {
        x_fx.a[k] = shl_r(x_fx.a[k], shift_fx); // right shift and round
    }
}

/// Bring both bands of a prototype to one Q after their energies were set (the lower of the two
/// band Qs `ql` / `qh`), as `ppp_voiced_decoder_fx` and `DTFS_dequant_cw_fx` do.
pub(crate) fn unify_band_q(x_fx: &mut DtfsStructure, ql: i16, qh: i16) {
    x_fx.q = ql.min(qh); // set Q factor to be the smaller one
    let n = sub(ql, qh); // compare band Q factors

    // This logic adjusts difference between Q formats of both bands
    if n < 0 {
        let cut_off = x_fx.upper_cut_off_freq;
        rshift_harm_band(x_fx, 2828, cut_off, n);
    } else if n > 0 {
        rshift_harm_band(x_fx, 0, 2828, sub(qh, ql));
    }
}

/// `10^(gain - log10(lag))` of a Q11 band gain as `DTFS_dequant_cw_fx` feeds it to
/// [`dtfs_set_engy_harm`]: the target energy and its Q.
fn dequant_band_energy(gain: i16, log_lag_fx: i32) -> (i32, i16) {
    let ltemp_fx = l_sub(l_shr(l_deposit_h(gain), 1), log_lag_fx); // Ltemp=gain-log10(lag), Q26

    // Lacc_fx=dsp_pow10(Ltemp_fx) : Lacc=10^gain/lag, Q15
    let mut l_tmp = mult_32_16(ltemp_fx, 27213); // 3.321928 in Q13
    l_tmp = l_shr(l_tmp, 8); // Q16
    let (mut exp1, frac) = l_extract_lc(l_tmp); // Extract exponent
    l_tmp = pow2(14, frac);
    exp1 = sub(exp1, 14);
    let mut l_temp = l_shl(l_tmp, add(exp1, 15)); // Q15

    let l_tmp2 = l_temp;
    if l_sub(l_temp, MAX_32) >= 0 {
        l_temp = l_shl(l_tmp, 15); // Q(15-exp1)
    }

    let n = norm_l(l_temp);
    let ltemp_fx = l_shl(l_temp, n); // Ltemp in Q(15+n) or Q(15 - exp1 +n)

    if l_sub(l_tmp2, MAX_32) >= 0 {
        (ltemp_fx, add(15, sub(n, exp1)))
    } else {
        (ltemp_fx, add(15, n))
    }
}

/// `DTFS_dequant_cw_fx`: dequantise the QPPP prototype amplitudes of `x_fx` (lag already set)
/// from the power index and the two amplitude-shape indices, differentially against the previous
/// prototype (lag `pl_fx`, ERB vector `lasterb_d_fx`, band gains `last_lgain_d_fx` /
/// `last_hgain_d_fx`, all updated). The cut-offs of `x_fx` are normalised by 12800 here.
pub fn dtfs_dequant_cw(
    pl_fx: i16,
    power_idx_fx: i16,
    amp_idx_fx: &[i16],
    last_lgain_d_fx: &mut i16,
    last_hgain_d_fx: &mut i16,
    lasterb_d_fx: &mut [i16],
    x_fx: &mut DtfsStructure,
    num_erb_fx: i16,
) {
    let mut mfreq_fx = [0_i16; NUM_ERB_MAX];
    let mut curr_erb_fx = [0_i16; NUM_ERB_MAX];
    let mut slot_fx = [0_i16; NUM_ERB_MAX];
    let mut ql: i16 = 0;
    let mut qh: i16 = 0;

    let power_cb_fx: &[i16] = if num_erb_fx == NUM_ERB_NB {
        &POWERCB_NB_FX
    } else if num_erb_fx == NUM_ERB_WB {
        &POWERCB_WB_FX
    } else {
        &[]
    };

    // Amplitude Dequantization
    erb_add(
        &mut curr_erb_fx,
        x_fx.lag,
        lasterb_d_fx,
        pl_fx,
        amp_idx_fx,
        num_erb_fx,
    );

    // only NUM_ERB_NB / NUM_ERB_WB reach here (the quarter decoder sets one of the two)
    let last = (num_erb_fx.clamp(3, NUM_ERB_WB)) as usize;
    curr_erb_fx[0] = mult_r(curr_erb_fx[1], 9830); // 0.3 inQ15 leaves curr_erb in Q13
    curr_erb_fx[last - 2] = mult_r(curr_erb_fx[last - 3], 9830); // Q13
    curr_erb_fx[last - 1] = 0;

    erb_slot(x_fx.lag, &mut slot_fx, &mut mfreq_fx, num_erb_fx);

    // mfreq normalized (2.56) in Q15
    dtfs_erb_inv(&curr_erb_fx, &slot_fx, &mfreq_fx, x_fx, num_erb_fx);

    // Back up the lasterbD memory after power normalization
    dtfs_set_engy_harm(236, 2828, 0, 2828, 1, 0, &mut ql, x_fx);
    let (of_interest, cut_off) = (x_fx.upper_cut_off_freq_of_interest, x_fx.upper_cut_off_freq);
    dtfs_set_engy_harm(2828, of_interest, 2828, cut_off, 1, 0, &mut qh, x_fx);
    unify_band_q(x_fx, ql, qh);

    dtfs_to_erb(x_fx, lasterb_d_fx);

    // Power Dequantization
    let tmp_fx = i32::from(shl(power_idx_fx, 1)); // tmp=2*POWER_IDX
    *last_lgain_d_fx = add(*last_lgain_d_fx, entry(power_cb_fx, tmp_fx)); // Q11
    *last_hgain_d_fx = add(*last_hgain_d_fx, entry(power_cb_fx, tmp_fx + 1)); // Q11

    let mut l_tmp = l_deposit_h(x_fx.lag); // Q16
    let mut exp = norm_l(l_tmp);
    l_tmp = l_shl(l_tmp, exp);
    let frac = log2_norm_lc(l_tmp);
    exp = sub(30, add(exp, 16));
    l_tmp = mpy_32_16(exp, frac, 12330); // Q13; 10*log10(2) in Q12
    let ltemp_fx = l_shl(l_tmp, 10); // Q23

    let log_lag_fx = mult_32_16(ltemp_fx, 0x6666); // logLag=log10(lag), Q26

    let (en, q_en) = dequant_band_energy(*last_lgain_d_fx, log_lag_fx);
    dtfs_set_engy_harm(236, 2828, 0, 2828, en, q_en, &mut ql, x_fx);

    let (en, q_en) = dequant_band_energy(*last_hgain_d_fx, log_lag_fx);
    let (of_interest, cut_off) = (x_fx.upper_cut_off_freq_of_interest, x_fx.upper_cut_off_freq);
    dtfs_set_engy_harm(2828, of_interest, 2828, cut_off, en, q_en, &mut qh, x_fx);

    // Need to unify the Q factors of both bands
    unify_band_q(x_fx, ql, qh);
}

/// The two terms of `copy_phase_fx`'s per-harmonic normalisation: `1 / |X1[k]|` as a Q(`q`+16)
/// value (with `q` returned), from the squared magnitude `lacc_fx` (Q`2·x1_q + 1`).
fn copy_phase_inverse_magnitude(lacc_fx: i32, x1_q: i16) -> (i32, i16) {
    let mut exp = norm_l(lacc_fx);
    let mut tmp = extract_h(l_shl(lacc_fx, exp));
    // plain C arithmetic in the reference (`2*X1_fx->Q+1`, `15+exp1+16-1`)
    let exp1 = sub(sub(30, exp), x1_q.wrapping_mul(2).wrapping_add(1));

    tmp = if tmp != 0 { div_s(16384, tmp) } else { 0 }; // 15+exp1
    tmp = shr(tmp, 1);
    let mut q: i16 = 15_i16.wrapping_add(exp1).wrapping_add(16 - 1);

    let mut ltemp_fx = if tmp != 0 {
        exp = norm_s(tmp);
        tmp = shl(tmp, exp);
        tmp = div_s(16384, tmp);
        isqrt_lc(l_deposit_h(tmp), &mut exp) // Q(31-exp)
    } else {
        0
    };

    if q & 1 != 0 {
        ltemp_fx = mult_32_16(ltemp_fx, 23170); // 23170 is 1/sqrt(2) in Q15
    }
    q = shr(q, 1); // Ltemp_fx in Q(q+16)
    (ltemp_fx, q)
}

/// `copy_phase_fx`: `ret_x_fx` gets the lag of `x1_fx`, the amplitudes of `x2_fx` and the phases
/// of `x1_fx` (Cartesian, Q`X2.Q - 1`). The reference takes `X2` by value, so a caller passing
/// the output's own prototype passes a copy.
pub fn copy_phase(x1_fx: &DtfsStructure, x2_fx: DtfsStructure, ret_x_fx: &mut DtfsStructure) {
    ret_x_fx.lag = x1_fx.lag;
    ret_x_fx.q = sub(x2_fx.q, 1); // equivalent to 2x MIN_FX(shr(sub(X_fx->lag_fx,1),1),X_fx->nH_fx)
    let half_lag = shr(x1_fx.lag, 1).min(x1_fx.nh);
    let mut k: i16 = 1;
    while k <= half_lag && (k as usize) < LAG_MAX {
        let ku = k as usize;
        let mut lacc_fx = l_mult(x1_fx.a[ku], x1_fx.a[ku]);
        lacc_fx = l_mac(lacc_fx, x1_fx.b[ku], x1_fx.b[ku]); // 2*Q+1

        let (ltemp_fx, q) = copy_phase_inverse_magnitude(lacc_fx, x1_fx.q);

        let d1h = extract_h(ltemp_fx);
        let d1l = extract_l(ltemp_fx);
        let mut ltemp_fx = l_mult0(x1_fx.b[ku], d1l);
        ltemp_fx = l_add(l_shr(ltemp_fx, 15), l_mult(x1_fx.b[ku], d1h)); // sin(w) in Q(q+16+Q-15)
        let sn = round_word(l_shl(ltemp_fx, sub(30, add(q, x1_fx.q)))); // Q15
        ret_x_fx.b[ku] = mult_r(x2_fx.a[ku], sn); // X2_fx.Q

        ltemp_fx = l_mult0(x1_fx.a[ku], d1l);
        ltemp_fx = l_add(l_shr(ltemp_fx, 15), l_mult(x1_fx.a[ku], d1h)); // cos(w) in Q(q+Q+1)
        let cn = round_word(l_shl(ltemp_fx, sub(30, add(q, x1_fx.q)))); // Q15
        ret_x_fx.a[ku] = mult_r(x2_fx.a[ku], cn); // X2_fx.Q
        k += 1;
    }
    let k = sub(k, 1) as usize;

    if x1_fx.lag & 1 == 0 && k < LAG_MAX {
        ret_x_fx.a[k] = shr(ret_x_fx.a[k], 1);
        ret_x_fx.b[k] = shr(ret_x_fx.b[k], 1);
    }
}
