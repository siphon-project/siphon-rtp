//! PVQ helpers shared by the encoder and decoder (TS 26.442 `lib_com/pvq_com_fx.c`; TS 26.445
//! §5.3.4.2.7). Only the functions the decoder runs are ported.

use crate::evs::cnst::QUANTAQ3OFFSET;
use crate::evs::com::range_com::range_coder_finalization_f_bits;
use crate::evs::com::tools::{copy, ratio};
use crate::evs::rom::{
    DSDIRACSTAB, HBITSN, INTLIMCDIVINVDQ31, LIM_NEG_INV_TBL_FX, OBTAINENERGYQUANTIZERDENSITY_F,
};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_l, l_mac, l_mult, l_negate,
    l_shl, l_shr, l_sub, mult_r, negate, norm_l, norm_s, shl, shr, sub,
};
use crate::itu::stl2009::{l_lshl, l_mac0, l_mult0, lshr, mac_r, mpy_32_16_ss, mpy_32_32_uu};

/// `sv[index]` widened; 0 past the table. Every index the decoder forms is inside its row of
/// `hBitsN`; the fallback only keeps an inconsistent call from panicking.
fn table_at(table: &[u8], index: i16) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .map_or(0, |&value| i16::from(value))
}

/// `intLimCDivPos_fx`: `NUM / DEN` for a small positive denominator, by the reciprocal table.
/// A denominator past `intLimCDivInvDQ31` divides by nothing and returns 0.
pub fn int_lim_c_div_pos(num: u32, den: i16) -> u32 {
    let inverse = usize::try_from(den)
        .ok()
        .and_then(|den| INTLIMCDIVINVDQ31.get(den))
        .copied()
        .unwrap_or(0);
    mpy_32_32_uu(l_lshl(num as i32, 1) as u32, inverse).0
}

/// `intLimCDivSigned_fx`: `NUM / DEN` rounded towards zero, by the reciprocal table.
pub fn int_lim_c_div_signed(num: i32, den: i16) -> i32 {
    let mut l_tmp = int_lim_c_div_pos(l_abs(num) as u32, den) as i32;
    if num < 0 {
        l_tmp = l_negate(l_tmp); // one op
    }
    l_tmp
}

/// `shrtCDivSignedApprox`: `num / den` for `den` in 1..=10, approximately.
pub fn shrt_c_div_signed_approx(num: i16, den: i16) -> i16 {
    let inverse = usize::try_from(den)
        .ok()
        .and_then(|den| LIM_NEG_INV_TBL_FX.get(den))
        .copied()
        .unwrap_or(0);
    let mut pool_part = extract_h(l_mult(negate(abs_s(num)), inverse));
    // neg_in always, positive out always, so that positive truncation (rounding) is used
    if num < 0 {
        pool_part = negate(pool_part); // make negative, one op
    }
    pool_part
}

/// `dsDirac2Dirac_fx`: the pulse count of a down-sampled pulse-count index.
pub fn ds_dirac2_dirac(ds_dirac_index: i16) -> i16 {
    usize::try_from(ds_dirac_index)
        .ok()
        .and_then(|index| DSDIRACSTAB.get(index))
        .copied()
        .unwrap_or(0)
}

/// `dsDiracPerQuanta_fx`: the down-sampled pulse-count index a band of dimension `td` can afford
/// with `t_quanta` (Q3) quanta; `dsm > 0` rounds down, otherwise to the nearest. `fr_quanta` is
/// `hBitsN`: row 0 holds each dimension's search depth, row `td` that dimension's cost table.
pub fn ds_dirac_per_quanta(td: i16, t_quanta: i16, dsm: i16, fr_quanta: &[&[u8]]) -> i16 {
    let sv: &[u8] = usize::try_from(td)
        .ok()
        .and_then(|td| fr_quanta.get(td))
        .copied()
        .unwrap_or(&[]);
    let depth = fr_quanta.first().map_or(0, |row| table_at(row, td));

    let nsv = table_at(sv, 0);
    let t_quanta_o = sub(t_quanta, QUANTAQ3OFFSET);

    if sub(t_quanta_o, table_at(sv, nsv)) >= 0 {
        return nsv;
    }
    if sub(t_quanta_o, table_at(sv, 1)) <= 0 {
        return 1;
    }

    let mut ds_index = shl(1, depth);
    if sub(t_quanta_o, table_at(sv, shr(nsv, 1))) > 0 {
        ds_index = sub(nsv, ds_index);
    }
    let mut i = sub(depth, 1);
    while i >= 0 {
        ds_index = add(
            ds_index,
            shl(
                sub(shl(lshr(sub(table_at(sv, ds_index), t_quanta_o), 15), 1), 1),
                i,
            ),
        );
        i -= 1;
    }

    ds_index = add(ds_index, lshr(sub(table_at(sv, ds_index), t_quanta_o), 15));
    ds_index = sub(ds_index, lshr(sub(1, ds_index), 15));

    if dsm > 0 {
        return ds_index;
    }
    add(
        ds_index,
        lshr(
            sub(
                add(table_at(sv, add(ds_index, 1)), table_at(sv, ds_index)),
                shl(t_quanta_o, 1),
            ),
            15,
        ),
    )
}

/// The outputs of [`conservative_l1_norm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConservativeL1Norm {
    /// `*Dvec`: pulses the band gets.
    pub dvec: i16,
    /// `*Qspare`: quanta left unspent.
    pub qspare: i16,
    /// `*Qreservplus`
    pub qreservplus: i16,
    /// `*Dspecplus`
    pub dspecplus: i16,
}

/// `conservativeL1Norm_fx`: the pulse count of a band of dimension `l` with budget `qvec`, backed
/// off until it fits in `qavail`.
pub fn conservative_l1_norm(
    l: i16,
    qvec: i16,
    fcons: i16,
    qavail: i16,
    qreserv: i16,
    dspec: i16,
) -> ConservativeL1Norm {
    let fr_quanta_l: &[u8] = usize::try_from(l)
        .ok()
        .and_then(|l| HBITSN.get(l))
        .copied()
        .unwrap_or(&[]);

    let mut qreservplus = add(qreserv, sub(qvec, QUANTAQ3OFFSET));

    let minit = ds_dirac_per_quanta(l, qvec, fcons, &HBITSN);
    let mut mprime = minit;

    let mut qspare;
    loop {
        let qtestminus = table_at(fr_quanta_l, mprime);
        qspare = sub(qavail, qtestminus);
        mprime = sub(mprime, 1);
        if !(mprime >= 0 && sub(qspare, QUANTAQ3OFFSET) < 0) {
            break;
        }
    }

    if mprime < 0 {
        qspare = add(qavail, QUANTAQ3OFFSET); // single op
    }
    let dvec = ds_dirac2_dirac(add(mprime, 1));

    let dspecplus = add(dspec, dvec);
    qreservplus = sub(qreservplus, table_at(fr_quanta_l, minit));
    qspare = sub(qspare, QUANTAQ3OFFSET);

    ConservativeL1Norm {
        dvec,
        qspare,
        qreservplus,
        dspecplus,
    }
}

/// The outputs of [`band_bits_adjustment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandBitsAdjustment {
    /// `*Bband_adj`
    pub bband_adj: i16,
    /// `*Brem`
    pub brem: i16,
    /// `*Breservplus`
    pub breservplus: i16,
}

/// `bandBitsAdjustment_fx`: the bits band `L` may spend, given what the range coder has used.
pub fn band_bits_adjustment(
    brc: i16,
    int_rc: u32,
    bavail: i16,
    nbands: i16,
    d: i16,
    l: i16,
    bband: i16,
    breserv: i16,
) -> BandBitsAdjustment {
    let bff = range_coder_finalization_f_bits(brc, int_rc);

    let (btemp, breservplus) = if sub(d, nbands) < 0 {
        let l_tmp = i32::from(sub(breserv, bff));
        // result always fits in Word16
        (
            extract_l(int_lim_c_div_signed(l_tmp, d.min(3))),
            add(bband, breserv),
        )
    } else {
        (0, add(bband, bff))
    };
    let mut bband_adj = extract_l(l_mult(l, 40)).min(bband);
    let brem = sub(bavail, bff);
    bband_adj = brem.min(add(bband_adj, btemp));
    bband_adj = bband_adj.max(0);

    BandBitsAdjustment {
        bband_adj,
        brem,
        breservplus,
    }
}

/// `apply_gain_fx`: scale each band of `xq` by its gain `gains[ord[band]]` (Q12).
pub fn apply_gain(
    ord: &[i16],
    band_start: &[i16],
    band_end: &[i16],
    num_sfm: i16,
    gains: &[i16],
    xq: &mut [i16],
) {
    for band in 0..num_sfm as usize {
        let g = gains[ord[band] as usize];
        for i in band_start[band]..band_end[band] {
            xq[i as usize] = mult_r(g, xq[i as usize]);
        }
    }
}

/// `srt_vec_ind16_fx`: sort `linear[0..length]` ascending into `srt` (a stable exchange sort),
/// with the original indices in `i`.
pub fn srt_vec_ind16(linear: &[i16], srt: &mut [i16], i: &mut [i16], length: i16) {
    let length = length.max(0) as usize;
    for (pos, index) in i.iter_mut().enumerate().take(length) {
        *index = pos as i16;
    }
    copy(linear, srt, length as i16);

    // now iterate
    for pos in 0..length.saturating_sub(1) {
        for npos in pos + 1..length {
            if sub(srt[npos], srt[pos]) < 0 {
                i.swap(pos, npos);
                srt.swap(pos, npos);
            }
        }
    }
}

/// `nearProjQ15_fx`: the cubic approximation (Q15) of the near-side projection of a split angle
/// `x` (Q15).
pub fn near_proj_q15(x: i16) -> i16 {
    const A: [i16; 4] = [14967, -25518, 3415, 32351];

    let mut b = i32::from(A[0]);
    b = l_shl(i32::from(add(A[1], extract_h(l_mult0(b as i16, x)))), 1);
    b = mpy_32_16_ss(b, x).0;
    b = l_add(i32::from(A[2]), b);
    b = mpy_32_16_ss(b, x).0;
    b = l_add(i32::from(A[3]), b);
    extract_l(b)
}

/// `obtainEnergyQuantizerDensity_fx`: the density of the split-energy quantiser for a band of
/// dimension `l` with `r` quanta (Q3).
pub fn obtain_energy_quantizer_density(l: i16, r: i16) -> i16 {
    let den = sub(shl(l, 1), 1);
    let mut rnrg = if den <= 67 {
        extract_l(int_lim_c_div_pos(l_deposit_l(r) as u32, den) as i32)
    } else {
        let n = norm_s(den);
        shr(div_s(r, shl(den, n)), sub(15, n))
    };
    rnrg = add(rnrg, 28);

    rnrg = rnrg.min(56);
    rnrg = rnrg.min(sub(r, 96));

    rnrg = rnrg.max(3);
    // rnrg is clamped to 3..=56, inside the 57-entry table
    i16::from(OBTAINENERGYQUANTIZERDENSITY_F[rnrg as usize])
}

/// `QuantaPerDsDirac_fx`: the quanta (Q3) a band of dimension `td` spends on the down-sampled
/// pulse-count index `ds_dirac_index`, from `dim_fr_quanta` (`hBitsN`).
pub fn quanta_per_ds_dirac(td: i16, ds_dirac_index: i16, dim_fr_quanta: &[&[u8]]) -> i16 {
    let mut quanta = usize::try_from(td)
        .ok()
        .and_then(|td| dim_fr_quanta.get(td))
        .map_or(0, |row| table_at(row, ds_dirac_index));
    if ds_dirac_index == 0 {
        quanta = -1; // single op
    }
    add(quanta, 1)
}

/// `Ratio_base2Q11_fx`: `log2(opp / near)` in Q11, by a quadratic approximation on the
/// normalised mantissas.
fn ratio_base2_q11(opp: i16, near: i16) -> i16 {
    let ns = norm_s(opp); // exponent
    let nc = norm_s(near); // exponent

    let ms = shl(opp, ns); // mantissa
    let mc = shl(near, nc); // mantissa

    let acc = l_mac(538_500_224, mc, -2776); // a0*mc + a1, acc(Q27), a0(Q11), a1(Q27)
    let mut z = mac_r(acc, ms, -2776); // z in Q11, a0 in Q11
    let d = sub(ms, mc); // d in Q15
    z = mult_r(z, d); // z in Q11

    add(z, shl(sub(nc, ns), 11))
}

/// `Ratio_rQ3_fx`: `log2(opp / near)` rounded to Q3.
pub fn ratio_r_q3(opp: i16, near: i16) -> i16 {
    let tmp = add(1 << 7, ratio_base2_q11(opp, near));
    shr(tmp, 8)
}

/// The outputs of [`density_angle2_rms_proj_dec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DensityAngle2RmsProj {
    /// `*oppQ15`
    pub opp_q15: i16,
    /// `*nearQ15`
    pub near_q15: i16,
    /// `*oppRatioQ3`
    pub opp_ratio_q3: i16,
}

/// `densityAngle2RmsProjDec_fx`: the RMS projections (Q15) onto the opposite and near halves of a
/// split for angle index `indexphi` of an energy quantiser of density `d` (`indexphi < 0`: no
/// angle coded, an even split), and their log2 ratio (Q3).
pub fn density_angle2_rms_proj_dec(d: i16, indexphi: i16) -> DensityAngle2RmsProj {
    let mut phi_q14q = int_lim_c_div_pos(l_shl(l_deposit_l(indexphi), 13) as u32, shr(d, 1)) as i16;
    if indexphi < 0 {
        phi_q14q = 1 << 13; // one op
    }

    let opp_tail = shr(sub(16320, phi_q14q), 15);
    let near_tail = shr(sub(phi_q14q, 64), 15);

    if (opp_tail | near_tail) < 0 {
        DensityAngle2RmsProj {
            opp_q15: opp_tail & 0x7fff,
            near_q15: near_tail & 0x7fff,
            opp_ratio_q3: shl(add(1, shl(near_tail, 1)), 14),
        }
    } else {
        let opp_q15 = near_proj_q15(shl(sub(1 << 14, phi_q14q), 1));
        let near_q15 = near_proj_q15(shl(phi_q14q, 1));
        DensityAngle2RmsProj {
            opp_q15,
            near_q15,
            opp_ratio_q3: ratio_r_q3(opp_q15, near_q15),
        }
    }
}

/// The outputs of [`near_opp_split_adjustment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NearOppSplit {
    /// `*qnear`: quanta of the near half.
    pub qnear: i16,
    /// `*qopp`: quanta of the opposite half.
    pub qopp: i16,
    /// `*qglobalupd`: the updated global quanta.
    pub qglobalupd: i16,
}

/// `NearOppSplitAdjustment_fx`: split the `qband` quanta of a band between its near (`nnear`
/// coefficients) and opposite (`nopp`) halves, given what the range coder used since `qzero`.
pub fn near_opp_split_adjustment(
    qband: i16,
    qzero: i16,
    qac: i16,
    int_ac: u32,
    qglobal: i16,
    flag_cons: i16,
    np: i16,
    nhead: i16,
    ntail: i16,
    nnear: i16,
    nopp: i16,
    opp_r_q3: i16,
) -> NearOppSplit {
    let qac = range_coder_finalization_f_bits(qac, int_ac);
    let qboth = sub(qband, sub(qac, qzero));
    // skew calc code
    let mut qskew: i16 = 0;
    if sub(nhead, 1) > 0 {
        let qavg = extract_h(l_shl(int_lim_c_div_signed(i32::from(qboth), np), 16)); // qboth may be negative
        let midx = ds_dirac_per_quanta(ntail, qavg, flag_cons, &HBITSN);
        let qmin = quanta_per_ds_dirac(nhead, midx, &HBITSN);
        qskew = sub(qavg, qmin);
        qskew = qskew.max(0);
    } // skew calc code

    let qia = add(
        extract_l(int_lim_c_div_pos(l_deposit_l(nopp) as u32, nnear) as i32),
        1,
    ); // always positive, Word16
    let l_qnum = l_sub(
        l_deposit_l(sub(sub(add(qband, qzero), qac), qskew)),
        l_mult0(nopp, opp_r_q3),
    );

    let mut l_qib: i32 = 0;
    if l_qnum > 0 {
        l_qib = int_lim_c_div_pos(l_qnum as u32, qia) as i32;
    }
    let mut qnear = qboth;
    let qib = extract_h(l_shl(l_qib, 16)); // may saturate
    if sub(qib, qboth) <= 0 {
        qnear = qib;
    }
    NearOppSplit {
        qnear,
        qopp: sub(qboth, qnear),
        qglobalupd: sub(qglobal, sub(qac, qzero)),
    }
}

/// `atan2_fx`: `atan(y / x)` for non-negative `y`, `x`, between 0 and pi/2 (Q14); pi/2 for
/// `x == 0`. Piecewise polynomial approximations over the ranges of the ratio.
pub fn atan2(y: i32, x: i32) -> i16 {
    // Q14 pi/2
    const PI_BY_2_Q14: i16 = 25736;

    if x == 0 {
        return PI_BY_2_Q14;
    }
    let mut expo: i16 = 0;
    let mut man = ratio(y, x, &mut expo); // man in Q14
    expo = sub(expo, 15 - 14); // Now, man is considered in Q15
    let arg = l_shr(i32::from(man), expo);

    if l_shr(arg, 3 + 15) != 0 {
        // atan(x) = pi/2 - 1/x for x >= 8 (approximately)
        expo = norm_l(arg);
        man = extract_h(l_shl(arg, expo));
        let mut reciprocal = div_s(0x3fff, man);
        expo = sub(15 + 1, expo);
        reciprocal = shr(reciprocal, expo); // Q14
        let mut angle = sub(PI_BY_2_Q14, reciprocal); // Q14 (pi/2 - 1/x)

        // for 8 <= x < 10: the error is larger, so correct it
        if l_sub(l_shr(arg, 15), 10) < 0 {
            angle = add(angle, 8); // Q14
        }
        angle
    } else if l_shr(arg, 2 + 15) != 0 {
        // 4 <= x < 8
        let w = extract_l(l_shr(arg, 3)); // Q12
        let mut z = mac_r(533_625_337, w, -2161);
        z = mac_r(-797_517_542, w, z);
        z = mac_r(592_675_551, w, z);
        let acc = l_mac(201_114_012, w, z);
        extract_l(l_shr(acc, 28 - 14))
    } else if l_shr(arg, 1 + 15) != 0 {
        // 2 <= x < 4
        let w = extract_l(l_shr(arg, 2)); // Q13
        let mut z = mac_r(702_602_883, w, -2751);
        z = mac_r(-1_100_849_465, w, z);
        z = mac_r(877_095_185, w, z);
        let acc = l_mac(57_332_634, w, z);
        extract_l(l_shr(acc, 28 - 14))
    } else if l_shr(arg, 15) != 0 {
        // 1 <= x < 2
        let w = extract_l(l_shr(arg, 1)); // Q14
        let mut z = mac_r(655_887_249, w, -2106);
        z = mac_r(-1_314_948_992, w, z);
        z = mac_r(1_428_924_557, w, z);
        let acc = l_mac(-37_424_701, w, z);
        extract_l(l_shr(acc, 29 - 14))
    } else {
        // 0 <= x < 1
        let w = extract_l(arg); // Q15
        let mut z = mac_r(1_188_376_431, w, -3547);
        z = extract_h(l_mac0(-995_054_571, w, z));
        z = mac_r(61_673_254, w, z);
        z = mac_r(2_141_982_059, w, z);
        let acc = l_mac(115_139, w, z);
        extract_l(l_shr(acc, 31 - 14))
    }
}
