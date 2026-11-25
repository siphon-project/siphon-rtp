//! LSF / LSP conversions, ordering and the LSF quantiser's bit allocation (TS 26.442
//! `lib_com/lsf_tools_fx.c`; TS 26.445 §5.2.2.1, §6.1.1.1). Only the functions the 7.2/8.0 kbit/s
//! decoder runs are ported.

use crate::evs::basop::{madd_32_16, mpy_32_16_1, msub_32_16};
use crate::evs::cnst::{
    GENERIC, GENERIC_MA_LIMIT, GRID100_POINTS, GUESS_TBL_SZ, INT_FS_16K, INT_FS_16K_FX, L_FRAME16K,
    M, NO_CODING_MODES, PH_ECU_SPEC_SIZE,
};
use crate::evs::com::basop_util::get_cos_word16_r2;
use crate::evs::com::math_op::i_mult2;
use crate::evs::com::mslvq_com::deindex_lvq;
use crate::evs::com::tools::{set16, vr_add};
use crate::evs::rom::{
    ACOS_SLOPE, AR_INTRACOEFF_FX, AR_SVQ_CB1_FX, AR_SVQ_CB2_FX, AR_TCVQ_CB_SUB1_FX,
    AR_TCVQ_CB_SUB2_FX, AR_TCVQ_CB_SUB3_FX, BITSVQ_FX, BITSVQ_P_FX, CBBITS_FX, CBBITS_P_FX,
    CBSIZES_FX, CB_LSF_FX, CB_P_LSF_FX, COS_TABLE_129, GRID, IND_GUESS, NTRANS2, PREDMODE_TAB,
    QUANTIZERS_FX, QUANTIZERS_P_FX, SCALE_ARSN_FX, SINCOS_T_RAD3_FX, SN_INTRACOEFF_FX,
    SN_TCVQ_CB_SUB1_FX, SN_TCVQ_CB_SUB2_FX, SN_TCVQ_CB_SUB3_FX,
};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_mac, l_msu, l_mult,
    l_shl, l_shr, l_sub, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_msu0, l_mult0, mac_r, msu_r};

/// `NC_MAX` (file-local in the reference): the largest half order.
const NC_MAX: usize = 8;

/// `T_SIN_PI_2` = `PH_ECU_SPEC_SIZE/4`.
const T_SIN_PI_2: i16 = PH_ECU_SPEC_SIZE / 4;

/// `table[index]`, 0 past either end. Used where an index comes from the bitstream or from a
/// value the reference does not range-check; every index a valid frame produces is inside.
fn at(table: &[i16], index: i32) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or(0)
}

/// The STL `Overflow` flag over the operators of [`e_lpc_f_lsp_pol_get`]. Each wrapper returns
/// the shared operator's result and raises the flag when it differs from the exact arithmetic,
/// which is exactly when the reference operator sets `Overflow` (every STL operator raises it at
/// the moment it clamps).
#[derive(Default)]
struct OverflowFlag(bool);

impl OverflowFlag {
    fn observe32(&mut self, exact: i128, result: i32) -> i32 {
        if exact != i128::from(result) {
            self.0 = true;
        }
        result
    }

    fn observe16(&mut self, exact: i128, result: i16) -> i16 {
        if exact != i128::from(result) {
            self.0 = true;
        }
        result
    }

    fn l_add(&mut self, a: i32, b: i32) -> i32 {
        self.observe32(
            i128::from(a) + i128::from(b),
            crate::itu::basic_ops::l_add(a, b),
        )
    }

    fn l_sub(&mut self, a: i32, b: i32) -> i32 {
        self.observe32(i128::from(a) - i128::from(b), l_sub(a, b))
    }

    fn l_mult(&mut self, a: i16, b: i16) -> i32 {
        self.observe32(2 * i128::from(a) * i128::from(b), l_mult(a, b))
    }

    /// `L_shl`: a right shift (negative count) never saturates.
    fn l_shl(&mut self, x: i32, n: i16) -> i32 {
        let result = l_shl(x, n);
        if n <= 0 {
            return result;
        }
        let exact = if n >= 64 {
            if x == 0 {
                0
            } else {
                i128::MAX
            }
        } else {
            i128::from(x) << n
        };
        self.observe32(exact, result)
    }

    /// `shl`: a right shift (negative count) never saturates.
    fn shl(&mut self, x: i16, n: i16) -> i16 {
        let result = shl(x, n);
        if n <= 0 {
            return result;
        }
        let exact = if n >= 64 {
            if x == 0 {
                0
            } else {
                i128::MAX
            }
        } else {
            i128::from(x) << n
        };
        self.observe16(exact, result)
    }
}

/// `E_LPC_f_lsp_pol_get`: the coefficients `f[0..=n]` (Q23, or less on a MODE1 overflow) of
/// `F(z) = prod (1 - 2 lsp[2i] z^-1 + z^-2)` over every other LSP of `lsp` (which starts at the
/// first LSP of this polynomial). Returns the number of bits of headroom given up.
///
/// The reference clears `Overflow` on entry and reads it after the recursion: the operators that
/// can raise it in between are the `L_shl` / `shl` building `f[0]` and the multiplier, `L_mult`,
/// `L_sub`, `L_add` and the doubling `L_shl` (`Mpy_32_16_1` cannot: `Mpy_32_16_ss` special-cases
/// its one saturating input without touching the flag). In MODE1 an overflow redoes the whole
/// computation one bit lower, which the reference does by recursing and this does by looping.
pub fn e_lpc_f_lsp_pol_get(
    lsp: &[i16],
    f: &mut [i32],
    n: i16,
    past_ovf: i16,
    is_mode1: i16,
) -> i16 {
    let mut ovf_in = past_ovf;
    loop {
        // All computation in Q23
        let mut q_out: i16 = 31 - 23;
        let ovf = ovf_in;

        // In some NB cases, overflow where detectected in f1 or f2 polynomial computation when it
        // happen we reduce the precision of the computing to limit the risk of saturation
        if ovf_in != 0 && is_mode1 != 0 {
            // Currently this feature is implemented only in MODE1
            q_out = add(q_out, ovf_in);
        }
        let mut overflow = OverflowFlag::default();

        f[0] = overflow.l_shl(1, sub(31, q_out));
        // b = -2.0f * *plsp;
        let mut b = lsp[0];
        let m2 = overflow.shl(-2, sub(15, q_out));
        f[1] = overflow.l_mult(b, m2);

        for i in 2..=n.max(0) as usize {
            // b = 2.0f * *plsp;
            b = lsp[2 * (i - 1)];
            let b32 = overflow.l_mult(b, m2);

            // f[i] = -b*f[i-1] + 2.0f*f[i-2];
            let difference = overflow.l_sub(f[i - 2], mpy_32_16_1(f[i - 1], b));
            f[i] = overflow.l_shl(difference, 1);

            for j in (2..i).rev() {
                // f[j] += b*f[j-1] + f[j-2];
                let doubled = overflow.l_shl(mpy_32_16_1(f[j - 1], b), 1);
                let difference = overflow.l_sub(f[j - 2], doubled);
                f[j] = overflow.l_add(f[j], difference);
            }
            f[1] = overflow.l_add(f[1], b32);
        }

        if overflow.0 && is_mode1 != 0 {
            // If an overflow is detected, redo the computation with 1 bit less
            ovf_in = add(ovf, 1);
            continue;
        }
        return ovf;
    }
}

/// `chebyshev`: the Chebyshev polynomial series `f[0..=n]` (`n` 5 or 8; Q23, or Q22 for the last
/// term as `E_LPC_a_lsp_conversion` builds it) evaluated at the cosine `x` (Q15), scaled by
/// `2^shift` and rounded to Q14. For `|x| < 0.5` the recursion runs on `2x` and halves instead.
fn chebyshev(mut x: i16, f: &[i32], n: i16, shift: i16) -> i16 {
    let mut k = 0usize;
    let mut next = || {
        let value = f[k];
        k += 1;
        value
    };

    let mut cheb = norm_s(x);
    if cheb != 0 {
        x = shl(x, 1);
    }
    let mut t0 = mpy_32_16_1(next(), x); // t0 = x*b2
    if cheb == 0 {
        t0 = l_shl(t0, 1); // t0 = 2*x*b2
    }
    let mut b1 = l_add(t0, next()); // b1 = 2*x*b2 + f[1]

    // i = 2
    t0 = mpy_32_16_1(b1, x); // t0 = x*b1
    if cheb == 0 {
        t0 = l_shl(t0, 1); // t0 = 2*x*b1
    }
    let mut b2 = l_add(t0, next()); // b0 = 2*x*b1 - b2 + f[i]

    // i = 3
    t0 = mpy_32_16_1(b2, x);
    if cheb == 0 {
        t0 = l_shl(t0, 1);
    }
    t0 = l_sub(t0, b1);
    b1 = l_add(t0, next());

    // i = 4
    t0 = mpy_32_16_1(b1, x);
    if cheb == 0 {
        t0 = l_shl(t0, 1);
    }
    t0 = l_sub(t0, b2);

    // If the LP order is greater than 10
    if sub(n, 5) > 0 {
        b2 = l_add(t0, next());
        // i = 5
        t0 = mpy_32_16_1(b2, x);
        if cheb == 0 {
            t0 = l_shl(t0, 1);
        }
        t0 = l_sub(t0, b1);
        b1 = l_add(t0, next());

        // i = 6
        t0 = mpy_32_16_1(b1, x);
        if cheb == 0 {
            t0 = l_shl(t0, 1);
        }
        t0 = l_sub(t0, b2);
    }
    if n == 8 {
        b2 = l_add(t0, next());
        // i = 7
        t0 = mpy_32_16_1(b2, x);
        if cheb == 0 {
            t0 = l_shl(t0, 1);
        }
        t0 = l_sub(t0, b1);
        // (b2 keeps the i = 7 value; the reference leaves `b1 = b2` commented out)
    } else {
        b2 = b1;
    }

    t0 = l_add(t0, next()); // b0 = 2*x*b1 - b2 + f[i]

    t0 = mpy_32_16_1(t0, x); // t0 = x*b1
    if cheb != 0 {
        t0 = l_shr(t0, 1);
    }
    t0 = l_sub(t0, b2); // t0 = x*b1 - b2
    t0 = l_add(t0, next()); // t0 = x*b1 - b2 + 0.5*f[n]

    t0 = l_shl(t0, shift); // Qx to Q30 with saturation
    cheb = round_word(t0); // Result in Q14
    cheb.max(-32767) // to avoid saturation
}

/// `E_LPC_a_lsp_conversion`: the LSPs `lsp[0..m]` (cosine domain, Q15) of the LP filter
/// `a[0..=m]` (any Q, `a[0]` giving it), found as the alternating roots of the sum and difference
/// polynomials on the 100-point grid, each refined by two bisections and a linear interpolation.
/// If fewer than `m` roots are found, `old_lsp` is returned instead.
pub fn e_lpc_a_lsp_conversion(a: &[i16], lsp: &mut [i16], old_lsp: &[i16], m: i16) {
    let mut f = [[0i32; NC_MAX + 1]; 2];

    let nc = shr(m, 1);
    let nc_len = (nc.max(0) as usize).min(NC_MAX);
    let m_len = m.max(0) as usize;

    let scale = shl(128, norm_s(a[0]));

    // find the sum and diff polynomials F1(z) and F2(z)
    //      F1(z) = [A(z) + z^11 A(z^-1)]/(1+z^-1)
    //      F2(z) = [A(z) - z^11 A(z^-1)]/(1-z^-1)
    f[0][0] = l_mult(a[0], scale); // 1.0f in Q23
    f[1][0] = l_mult(a[0], scale); // 1.0f in Q23
    for i in 1..nc_len {
        let t0 = l_mult(a[i], scale); // Q23
        let sum = l_mac(t0, a[m_len + 1 - i], scale);
        let diff = l_msu(t0, a[m_len + 1 - i], scale);
        f[0][i] = l_sub(sum, f[0][i - 1]); // Q23
        f[1][i] = l_add(diff, f[1][i - 1]); // Q23
    }
    let i = nc_len;
    let t1 = l_mult0(a[i], scale); // Q23-1
    let sum = l_mac0(t1, a[m_len + 1 - i], scale);
    let diff = l_msu0(t1, a[m_len + 1 - i], scale);
    f[0][nc_len] = l_sub(sum, l_shr(f[0][i - 1], 1)); // Q23-1
    f[1][nc_len] = l_add(diff, l_shr(f[1][i - 1], 1)); // Q23-1

    // Precalculate difference to index 0 for index 2
    f[0][2] = l_sub(f[0][2], f[0][0]);
    f[1][2] = l_sub(f[1][2], f[1][0]);

    // Find the LSPs (roots of F1(z) and F2(z)) using the Chebyshev polynomial evaluation. The
    // roots of F1(z) and F2(z) are alternatively searched.
    let mut nf: usize = 0; // number of found frequencies
    let mut ip: usize = 0; // indicator for f1 or f2

    let mut xlow = GRID[0];
    let mut ylow = chebyshev(xlow, &f[ip], nc, 8);

    for &grid_point in &GRID[1..=GRID100_POINTS as usize] {
        let mut xhigh = xlow;
        let mut yhigh = ylow;
        xlow = grid_point;
        ylow = chebyshev(xlow, &f[ip], nc, 8);

        if l_mult(ylow, yhigh) <= 0 {
            let mut t0 = l_mult(xhigh, 0x4000);
            // divide 2 times the interval
            let mut x = mac_r(t0, xlow, 0x4000); // xmid = (xlow + xhigh)/2
            let mut y = chebyshev(x, &f[ip], nc, 8);

            if l_mult(ylow, y) <= 0 {
                yhigh = y;
                xhigh = x;
                y = ylow;
                x = xlow;
                // 'xhigh' has changed, update 't0'
                t0 = l_mult(xhigh, 0x4000);
            }
            xlow = mac_r(t0, x, 0x4000); // xmid = (xlow + xhigh)/2
            ylow = chebyshev(xlow, &f[ip], nc, 8);

            if l_mult(y, ylow) <= 0 {
                yhigh = ylow;
                xhigh = xlow;
                ylow = y;
                xlow = x;
            }

            // Linear interpolation
            // xint = xlow - ylow*(xhigh-xlow)/(yhigh-ylow)
            y = msu_r(l_mult(yhigh, 0x4000), ylow, 0x4000);

            if y != 0 {
                x = sub(xhigh, xlow);
                let mut tmp = abs_s(y);
                let exp = norm_s(tmp);
                if exp != 0 {
                    tmp = shl(tmp, exp);
                }
                tmp = div_s(16383 / 2, tmp);
                t0 = l_mult(x, tmp);
                t0 = l_shr(t0, sub(20, exp));
                tmp = extract_l(t0); // y = (xhigh-xlow)/(yhigh-ylow) in Q11

                // Restore Sign
                if y < 0 {
                    tmp = negate(tmp);
                }

                t0 = l_mult(ylow, tmp); // result in Q26
                t0 = l_shr(t0, 11); // result in Q15
                xlow = sub(xlow, extract_l(t0)); // xint = xlow - ylow*y
            }
            lsp[nf] = xlow;
            nf += 1;

            if nf >= m_len {
                break;
            }

            ip ^= 1;
            ylow = chebyshev(xlow, &f[ip], nc, 8);
        }
    }

    // Check if m roots found
    // if not use the LSPs from previous frame
    if nf < m_len {
        lsp[..m_len].copy_from_slice(&old_lsp[..m_len]);
    }
}

/// `E_LPC_f_isp_a_conversion`: the LP coefficients `a[0..=m]` (Q12, adaptively down-scaled when the
/// middle coefficient would saturate; `a[0]` gives the scaling) of the ISPs `isp[0..m]` (Q15).
pub fn e_lpc_f_isp_a_conversion(isp: &[i16], a: &mut [i16], m: i16) {
    let mut f1 = [0i32; NC_MAX + 1]; // Q23
    let mut f2 = [0i32; NC_MAX + 1]; // Q23

    let m_len = m.max(1) as usize;
    let isp_last = isp[m_len - 1];

    // Find the polynomials F1(z) and F2(z)
    let nc = shr(m, 1);
    let nc_len = (nc.max(0) as usize).min(NC_MAX);

    e_lpc_f_lsp_pol_get(isp, &mut f1, nc, 0, 0);
    e_lpc_f_lsp_pol_get(&isp[1..], &mut f2, sub(nc, 1), 0, 0);

    // Multiply F2(z) by (1 - z^-2)
    for i in (2..nc_len).rev() {
        // f2[i] -= f2[i-2];
        f2[i] = l_sub(f2[i], f2[i - 2]);
    }

    // Scale F1(z) by (1+isp[m-1])  and  F2(z) by (1-isp[m-1])
    for i in 0..nc_len {
        // f1[i] *= (1.0 + isp[m-1]);
        f1[i] = madd_32_16(f1[i], f1[i], isp_last);
        // f2[i] *= (1.0 - isp[m-1]);
        f2[i] = msub_32_16(f2[i], f2[i], isp_last);
    }

    // A(z) = (F1(z)+F2(z))/2
    // F1(z) is symmetric and F2(z) is antisymmetric

    // Maximum LPC
    let mut tmax: i32 = 1;
    for i in 1..nc_len {
        let t0 = l_add(f1[i], f2[i]);
        tmax = tmax.max(l_abs(t0));
        let t0 = l_sub(f1[i], f2[i]);
        tmax = tmax.max(l_abs(t0));
    }
    let mut q = norm_l(tmax).min(6);

    let mut t0;
    loop {
        // a[0] = 1.0
        a[0] = shl(256, q);
        let mut j = m_len - 1;
        for i in 1..nc_len {
            // a[i] = 0.5*(f1[i] + f2[i])
            let t = l_shl(l_add(f1[i], f2[i]), q);
            a[i] = round_word(t); // from Q23 to Q12 and * 0.5

            // a[j] = 0.5*(f1[i] - f2[i])
            let t = l_shl(l_sub(f1[i], f2[i]), q);
            a[j] = round_word(t); // from Q23 to Q12 and * 0.5

            j -= 1;
        }

        // a[NC] = 0.5*f1[NC]*(1.0 + isp[m-1])
        t0 = madd_32_16(f1[nc_len], f1[nc_len], isp_last);

        // overflow handling in loop expression
        t0 = l_shl(t0, q);
        let t0n = l_sub(t0, 0x7FFF_FFFF); // check for positive overflow
        let t0p = l_sub(t0, i32::MIN); // check for negative overflow

        q = sub(q, 1); // decrease q in case of overflow
        if !(t0n == 0 || t0p == 0) {
            break; // in case of overflow, recalculate coefficients
        }
    }

    a[nc_len] = round_word(t0); // from Q23 to Q12 and * 0.5

    // a[m] = isp[m-1]
    let t = l_mult(a[0], isp_last); // from Q15 to Q12
    a[m_len] = round_word(t);
}

/// `E_LPC_f_lsp_a_conversion`: the LP coefficients `a[0..=m]` of the LSPs `lsp[0..m]` (Q15),
/// `m` 10 or 16; `a[0]` carries the scaling (Q12 nominally).
pub fn e_lpc_f_lsp_a_conversion(lsp: &[i16], a: &mut [i16], m: i16) {
    let mut f1 = [0i32; NC_MAX + 1];
    let mut f2 = [0i32; NC_MAX + 1];

    // Find the polynomials F1(z) and F2(z)
    let nc = shr(m, 1);

    let ovf = e_lpc_f_lsp_pol_get(lsp, &mut f1, nc, 0, 1);
    let ovf2 = e_lpc_f_lsp_pol_get(&lsp[1..], &mut f2, nc, ovf, 1);
    if sub(ovf2, ovf) != 0 {
        // to ensure similar scaling for f1 and f2 in case an overflow would be detected only in
        // f2, but this case never happen on my dtb
        e_lpc_f_lsp_pol_get(lsp, &mut f1, nc, ovf2.max(ovf), 1);
    }

    // Multiply F1(z) by (1+z^-1) and F2(z) by (1-z^-1)
    let nc = nc as usize;
    for i in 0..nc {
        f1[nc - i] = crate::itu::basic_ops::l_add(f1[nc - i], f1[nc - i - 1]);
        f2[nc - i] = l_sub(f2[nc - i], f2[nc - i - 1]);
    }

    // A(z) = (F1(z)+F2(z))/2; F1(z) is symmetric and F2(z) is antisymmetric
    let mut t0: i32 = 0;
    for i in 1..=nc {
        t0 = t0.max(l_abs(crate::itu::basic_ops::l_add(f1[i], f2[i])));
        t0 = t0.max(l_abs(l_sub(f1[i], f2[i])));
    }
    let k = norm_l(t0).min(6);
    a[0] = shl(256, k);
    if ovf != 0 || ovf2 != 0 {
        a[0] = shl(256, sub(k, ovf));
    }
    let mut j = m as usize;
    for i in 1..=nc {
        // a[i] = 0.5*(f1[i] + f2[i])
        let mut t0 = crate::itu::basic_ops::l_add(f1[i], f2[i]);
        t0 = l_shl(t0, k);
        a[i] = round_word(t0); // from Q23 to Qx and * 0.5

        // a[j] = 0.5*(f1[i] - f2[i])
        let mut t0 = l_sub(f1[i], f2[i]);
        t0 = l_shl(t0, k);
        a[j] = round_word(t0); // from Q23 to Qx and * 0.5
        j -= 1;
    }
}

/// `reorder_lsf_fx`: enforce ascending order with a minimum gap `min_dist` over `lsf[0..n]`
/// (Q(x2.56)), then, if the top LSF is too close to `fs/2`, again downwards from there.
pub fn reorder_lsf(lsf: &mut [i16], min_dist: i16, n: i16, fs: i32) {
    let mut lsf_min = min_dist;

    // Verify the LSF ordering and minimum GAP
    for value in lsf.iter_mut().take(n.max(0) as usize) {
        if sub(*value, lsf_min) < 0 {
            *value = lsf_min;
        }
        lsf_min = add(*value, min_dist);
    }

    // Reverify the LSF ordering and minimum GAP in the reverse order (security)
    // Q0 + Q9 , 1311 is 2.56 in Q9
    let mut lsf_max = round_word(l_sub(
        l_shr(l_mult0(extract_l(l_shr(fs, 1)), 1311), 9 - 16),
        l_deposit_h(min_dist),
    ));
    let n_m_1 = sub(n, 1);
    if n_m_1 >= 0 && sub(lsf[n_m_1 as usize], lsf_max) > 0 {
        // If danger of unstable filter in case of resonance in HF: reverify the minimum LSF gap
        // in the reverse direction
        for i in (0..=n_m_1 as usize).rev() {
            if sub(lsf[i], lsf_max) > 0 {
                lsf[i] = lsf_max;
            }
            lsf_max = sub(lsf[i], min_dist);
        }
    }
}

/// `reorder_isf_fx`: enforce ascending order with a minimum gap `min_dist` over the first
/// `n - 1` ISFs (the last one, the order-`n` reflection, is left alone), then, if `isf[n-2]` is
/// too close to `fs` (already the half sampling rate), again downwards from there.
pub fn reorder_isf(isf: &mut [i16], min_dist: i16, n: i16, fs: i16) {
    let mut isf_min = min_dist;

    // Verify the ISF ordering and minimum GAP
    for value in isf.iter_mut().take(sub(n, 1).max(0) as usize) {
        if sub(*value, isf_min) < 0 {
            *value = isf_min;
        }
        isf_min = add(*value, min_dist);
    }

    // Reverify the ISF ordering and minimum GAP in the reverse order (security)
    let mut isf_max = sub(fs, min_dist); // Fs already divide per 2
    let n_m_2 = sub(n, 2);
    if n_m_2 >= 0 && sub(isf[n_m_2 as usize], isf_max) > 0 {
        // If danger of unstable filter in case of resonance in HF: reverify the minimum ISF gap
        // in the reverse direction
        for i in (0..=n_m_2 as usize).rev() {
            if sub(isf[i], isf_max) > 0 {
                isf[i] = isf_max;
            }
            isf_max = sub(isf[i], min_dist);
        }
    }
}

/// The codebooks and lattice tables of one LSF quantiser (safety net or predictive): stage
/// codebooks, their first row per mode, offsets of the two 8-dim lattice halves, scale counts.
type LvqTables<'a> = (&'a [&'a [i16]], &'a [i16], &'a [i32], &'a [i32], &'a [i16]);

/// `vq_dec_lvq_fx`: the LSF residual `x[0..n]` (Q(x2.56)) as the sum of the multi-stage VQ
/// codevectors `indices[0..stages-1]` and the lattice VQ of `indices[stages-1..]`, from the
/// safety-net (`sf_flag == 1`) or predictive codebooks of `mode`. Returns the lattice decoder's
/// bit-error flag.
pub fn vq_dec_lvq(
    sf_flag: i16,
    x: &mut [i16],
    indices: &mut [i16],
    stages: i16,
    n: i16,
    mode: i16,
    no_bits: i16,
    p_offset_scale1: &[i32],
    p_offset_scale2: &[i32],
    p_offset_scale1_p: &[i32],
    p_offset_scale2_p: &[i32],
    p_no_scales: &[i16],
    p_no_scales_p: &[i16],
) -> i16 {
    static ZERO: [i16; M as usize] = [0; M as usize];
    let mut x_lvq = [0i16; M as usize];
    let mut previous = [0i16; M as usize];

    // clear vector
    set16(x, 0, n);

    // add contribution of each stage
    let stagesm1 = sub(stages, 1);
    let (quantizers, cb, offset_scale1, offset_scale2, no_scales): LvqTables<'_> =
        if sub(sf_flag, 1) == 0 {
            (
                &QUANTIZERS_FX,
                &CB_LSF_FX,
                p_offset_scale1,
                p_offset_scale2,
                p_no_scales,
            )
        } else {
            (
                &QUANTIZERS_P_FX,
                &CB_P_LSF_FX,
                p_offset_scale1_p,
                p_offset_scale2_p,
                p_no_scales_p,
            )
        };

    for i in 0..stagesm1.max(0) {
        let pt = i_mult2(indices[i as usize], n);
        // The stage codebook and the codevector inside it come from the mode and the bitstream;
        // both are inside the tables for every mode the decoder selects. A row or codevector past
        // them contributes nothing rather than reading out of bounds.
        let codevector: &[i16] = usize::try_from(i32::from(at(cb, i32::from(mode))) + i32::from(i))
            .ok()
            .and_then(|row| quantizers.get(row))
            .and_then(|row| usize::try_from(pt).ok().and_then(|pt| row.get(pt..)))
            .filter(|codevector| codevector.len() >= n as usize)
            .unwrap_or(&ZERO);
        previous[..n as usize].copy_from_slice(&x[..n as usize]);
        vr_add(&previous, codevector, x, n);
    }
    let ber_flag = deindex_lvq(
        &mut indices[stagesm1.max(0) as usize..],
        &mut x_lvq,
        mode,
        sf_flag,
        no_bits,
        offset_scale1,
        offset_scale2,
        no_scales,
    );

    previous[..n as usize].copy_from_slice(&x[..n as usize]);
    vr_add(&previous, &x_lvq, x, n);

    ber_flag
}

/// `lsf_allocate_fx`: the stage structure (stage counts, codebook sizes, bits per stage) of the
/// safety-net and predictive LSF quantisers for `n_bits` bits in modes `framemode` /
/// `framemode_p`. As in the reference, an output is left untouched where its branch is skipped
/// (`framemode == 14`, `framemode_p == -1`, ...).
pub fn lsf_allocate(
    n_bits: i16,
    framemode: i16,
    framemode_p: i16,
    stages0: &mut i16,
    stages1: &mut i16,
    levels0: &mut [i16],
    levels1: &mut [i16],
    bits0: &mut [i16],
    bits1: &mut [i16],
) {
    // VOICED@16kHz
    if sub(framemode, 14) == 0 {
        return;
    }

    // Calculate bit allocation for safety-net quantizer
    let mut cumleft = at(&BITSVQ_FX, i32::from(framemode));
    let mut bits_lvq = sub(n_bits, cumleft);
    let mut nbits0 = at(&CBBITS_FX, i32::from(framemode));
    if sub(nbits0, -1) > 0 {
        let n_stages: i16 = if nbits0 > 0 {
            let mut stages: i16 = 2;
            levels0[0] = at(&CBSIZES_FX, i32::from(nbits0));
            bits0[0] = nbits0;
            bits0[1] = sub(cumleft, nbits0);

            if bits0[1] == 0 {
                stages = sub(stages, 1);
            } else {
                levels0[1] = at(&CBSIZES_FX, i32::from(sub(cumleft, nbits0)));
            }
            stages
        } else {
            // no bits for VQ stage
            0
        };

        *stages0 = n_stages;
        if bits_lvq > 0 {
            bits0[n_stages as usize] = bits_lvq;
            levels0[n_stages as usize] = bits_lvq;
            *stages0 = add(n_stages, 1);
        }
    } else {
        *stages0 = 0;
    }

    // Calculate bit allocation for predictive quantizer
    if sub(framemode_p, -1) > 0 {
        cumleft = at(&BITSVQ_P_FX, i32::from(framemode_p));
        bits_lvq = sub(n_bits, cumleft);
        nbits0 = at(&CBBITS_P_FX, i32::from(framemode_p));

        if sub(nbits0, -1) > 0 {
            if nbits0 > 0 {
                if sub(framemode_p, 7) == 0 {
                    // for UNVOICED_WB only
                    let n_stages: usize = 3;
                    for i in 0..n_stages {
                        levels1[i] = at(&CBSIZES_FX, i32::from(nbits0));
                        bits1[i] = nbits0;
                    }
                    bits1[n_stages] = bits_lvq;
                    levels1[n_stages] = bits_lvq;
                    *stages1 = add(n_stages as i16, 1);
                } else {
                    let mut n_stages: i16 = 1;
                    levels1[0] = at(&CBSIZES_FX, i32::from(nbits0));
                    bits1[0] = nbits0;
                    nbits0 = sub(cumleft, nbits0);
                    if nbits0 > 0 {
                        levels1[1] = at(&CBSIZES_FX, i32::from(nbits0));
                        bits1[1] = nbits0;
                        n_stages = 2;
                    }

                    levels1[n_stages as usize] = bits_lvq;
                    bits1[n_stages as usize] = bits_lvq;
                    *stages1 = add(n_stages, 1);
                }
            } else {
                *stages1 = 1;
                bits1[0] = bits_lvq;
                levels1[0] = bits_lvq;
            }
        }
    }
}

/// `find_pred_mode`: the LSF codebook modes (`p_mode_lvq` safety net, `p_mode_lvq_p`
/// predictive or -1) for a coder type, bandwidth and internal rate; returns the prediction mode
/// (0 safety net only, 1 MA, 2 AR / switched).
pub fn find_pred_mode(
    coder_type: i16,
    bwidth: i16,
    int_fs: i32,
    p_mode_lvq: &mut i16,
    p_mode_lvq_p: &mut i16,
    core_brate: i32,
) -> i16 {
    // bwidth = 0(NB), 1 (WB), 2(WB2); line index in predmode_tab[][]
    let mut idx = bwidth;
    if sub(idx, 1) > 0 {
        idx = 1;
    }
    if l_sub(int_fs, i32::from(INT_FS_16K)) == 0 {
        // WB2 is actually used if sampling frequency is 16kHz
        idx = 2;
    } else if l_sub(core_brate, i32::from(GENERIC_MA_LIMIT)) >= 0
        && sub(coder_type, GENERIC) == 0
        && sub(idx, 1) == 0
    {
        idx = 3;
    }

    // A coder type past the table (only a corrupted frame signals one) reads as "no prediction".
    let predmode = usize::try_from(idx)
        .ok()
        .and_then(|row| PREDMODE_TAB.get(row))
        .and_then(|row| {
            usize::try_from(coder_type)
                .ok()
                .and_then(|col| row.get(col))
        })
        .copied()
        .unwrap_or(0);

    if sub(idx, 2) <= 0 {
        *p_mode_lvq = add(i_mult2(NO_CODING_MODES, idx), coder_type);
        *p_mode_lvq_p = if predmode > 0 { *p_mode_lvq } else { -1 };
    } else {
        // WB 12.8 with MA pred in GENERIC
        *p_mode_lvq = add(NO_CODING_MODES, coder_type);
        if sub(coder_type, GENERIC) == 0 {
            *p_mode_lvq_p = 18;
        } else {
            *p_mode_lvq_p = if predmode > 0 { *p_mode_lvq } else { -1 };
        }
    }

    predmode
}

/// `lsf_stab_fx`: the stability factor (Q15) of the LP filter from the distance between `lsf`
/// and the previous frame's `lsfold` (Q(x2.56)).
pub fn lsf_stab(lsf: &[i16], lsfold: &[i16], opt_amr_wb: i16, l_frame: i16) -> i16 {
    // Check stability on lsf: distance between old lsf and current lsf
    let mut l_tmp: i32;
    if opt_amr_wb != 0 {
        let m = M - 1;
        let tmp = sub(lsf[0], lsfold[0]);
        l_tmp = l_mult(tmp, tmp); // Q1
        for i in 1..m as usize {
            let tmp = sub(lsf[i], lsfold[i]);
            l_tmp = l_mac(l_tmp, tmp, tmp); // Q1
        }
    } else {
        l_tmp = 0;
        for i in 0..M as usize {
            let tmp = sub(lsf[i], lsfold[i]);
            l_tmp = l_mac(l_tmp, tmp, tmp); // Q1
        }
    }

    let mut e = norm_l(l_tmp);
    l_tmp = l_shl(l_tmp, e); // Q(1+e)

    if l_frame == L_FRAME16K {
        // stab_fac = (float)(1.25f - (tmp/625000.0f));
        l_tmp = mpy_32_16_1(l_tmp, 16777); // 30-eQ(1+e)*-21Q36 = 30-21-eQ31-9+e
    } else {
        // stab_fac = (float)(1.25f - (tmp1/400000.0f*2.56=1024000))
        l_tmp = mpy_32_16_1(l_tmp, 26214); // 30-eQ(1+e)*-21Q36 = 30-21-eQ31-9+e
    }
    e = sub(30 - 21 - 1, e);
    let mut tmp = round_word(l_shl(l_tmp, e)); // Q14

    tmp = sub(20480, tmp); // 1.25 - tmp in Q14
    tmp = shl(tmp, 1); // Q14 -> Q15 with saturation
    tmp.max(0)
}

/// `lsp2lsf_fx`: LSPs (Q15 cosines) to LSFs (Q(x2.56)) over `m` coefficients, for internal
/// rate `int_fs`.
pub fn lsp2lsf(lsp: &[i16], lsf: &mut [i16], m: i16, int_fs: i32) {
    for i in 0..m.max(0) as usize {
        // find value in table that is just greater than lsp[i]
        let mut l_tmp = sub_lsp2lsf(lsp[i]);
        if l_sub(int_fs, i32::from(INT_FS_16K_FX)) == 0 {
            l_tmp = l_shr(l_mult0(extract_l(l_tmp), 5), 2);
        }
        lsf[i] = extract_l(l_tmp);
    }
}

/// `lsf2lsp_fx`: LSFs (Q(x2.56)) to LSPs (Q15 cosines) over `m` coefficients by interpolating
/// the sine table, for internal rate `int_fs`.
pub fn lsf2lsp(lsf: &[i16], lsp: &mut [i16], m: i16, int_fs: i32) {
    const ADD_PREC: i16 = 4;

    // 0.75 = (1<<add_prec)*T_SIN_PI_2/(2.56f*3200.0f)
    let mut c: i16 = 24576; // 0.75f Q15
    if l_sub(int_fs, i32::from(INT_FS_16K_FX)) == 0 {
        // 0.6 = (1<<add_prec)*T_SIN_PI_2/(2.56f*4000.0f)
        c = 19661; // 0.6f Q15
    }

    for i in 0..m.max(0) as usize {
        // lsp[i] = cos(lsf[i] * EVS_PI / (int_fs/2));
        let mut l_tmp = l_shr(l_mult(lsf[i], c), ADD_PREC);
        let ind = extract_h(l_tmp);

        // interpolate cosine table at indexes ind and ind+1. An LSF inside [0, fs/2] keeps both
        // indices within the quarter-wave table; one past it reads 0.
        let mut ind2 = sub(T_SIN_PI_2, ind);
        let mut lsf_tmp = at(&SINCOS_T_RAD3_FX, i32::from(ind2.max(negate(ind2))));
        if ind2 < 0 {
            lsf_tmp = negate(lsf_tmp);
        }
        ind2 = sub(T_SIN_PI_2 - 1, ind);
        let mut offset = at(&SINCOS_T_RAD3_FX, i32::from(ind2.max(negate(ind2))));
        if ind2 < 0 {
            offset = negate(offset);
        }

        l_tmp = l_mult(sub(offset, lsf_tmp), round_word(l_shl(l_tmp & 0xFFFF, 15)));
        l_tmp = l_msu(l_tmp, lsf_tmp, -32768);
        lsp[i] = round_word(l_tmp);
    }
}

/// `E_LPC_lsf_lsp_conversion`: LSFs (Q(x2.56) of 6400 Hz) to LSPs (Q15) by `xsf_to_xsp`, over
/// `m` coefficients.
pub fn e_lpc_lsf_lsp_conversion(lsf: &[i16], lsp: &mut [i16], m: i16) {
    // convert ISFs to the cosine domain
    for i in 0..m.max(0) as usize {
        lsp[i] = xsf_to_xsp(lsf[i]);
    }
}

/// `E_LPC_lsp_lsf_conversion`: LSPs (Q15) to LSFs (Q(x2.56) of 6400 Hz) by `xsp_to_xsf`, over
/// `m` coefficients.
pub fn e_lpc_lsp_lsf_conversion(lsp: &[i16], lsf: &mut [i16], m: i16) {
    for i in 0..m.max(0) as usize {
        lsf[i] = xsp_to_xsf(lsp[i]);
    }
}

/// `xsp_to_xsf`: `acos(lsp) · 6400 / π` through the 129-point cosine table. The reference's body
/// is `sub_lsp2lsf_fx`'s, operator for operator, truncated to 16 bits by its final `extract_l`.
#[must_use]
pub fn xsp_to_xsf(lsp: i16) -> i16 {
    extract_l(sub_lsp2lsf(lsp))
}

/// `xsf_to_xsp`: `cos(lsf · π / 6400)`.
pub fn xsf_to_xsp(lsf: i16) -> i16 {
    get_cos_word16_r2(lsf)
}

/// `E_LPC_isf_isp_conversion`: ISFs (Q(x2.56), 0..6400) to ISPs (Q15); the last ISF is the
/// order-`m` reflection at half the scale, so it is doubled first.
pub fn e_lpc_isf_isp_conversion(isf: &[i16], isp: &mut [i16], m: i16) {
    let m = m.max(1) as usize;
    for i in 0..m - 1 {
        isp[i] = xsf_to_xsp(isf[i]);
    }
    isp[m - 1] = xsf_to_xsp(shl(isf[m - 1], 1));
}

/// `sub_lsp2lsf_fx`: one LSP (Q15) to its LSF (Q(x2.56)) through the 129-point cosine table and
/// its arc-cosine slopes.
pub fn sub_lsp2lsf(lsp_i: i16) -> i32 {
    // find value in table that is just greater than lsp[i]; Retrieve Index Guess Based on lsp[i]
    let mut ind = mac_r(
        i32::from(GUESS_TBL_SZ) / 2 * 65536 - 0x8000,
        lsp_i,
        GUESS_TBL_SZ / 2,
    );
    ind = i16::from(IND_GUESS[ind as u8 as usize]);

    // Correct Index so that table[ind] > lsp[i]
    let cos_at = |index: i16| at(&COS_TABLE_129, i32::from(index));
    let mut tmp = sub(lsp_i, cos_at(ind));
    // 69%: (Final Index - Index Guess) is <= 1
    // 28%: (Final Index - Index Guess) is 2
    //  2%: (Final Index - Index Guess) is >= 3
    // <1%: ...
    if tmp > 0 {
        // possible range 0 to -5 (-1-2-2)
        ind = sub(ind, 1);
        tmp = sub(lsp_i, cos_at(ind));
        if tmp > 0 {
            ind = sub(ind, 2);
            tmp = sub(lsp_i, cos_at(ind));
            if tmp > 0 {
                ind = sub(ind, 2);
            }
            tmp = sub(lsp_i, cos_at(ind + 1));
            if tmp <= 0 {
                ind = add(ind, 1);
            }
            tmp = sub(lsp_i, cos_at(ind));
        }
    }

    // acos(lsp[i])= ind*128 + (lsp[i]-table[ind]) * acos_slope[ind] / 2048
    let mut l_tmp = l_mac(1 << 11, tmp, at(&ACOS_SLOPE, i32::from(ind)));
    l_tmp = l_shr(l_tmp, 12); // (lsp[i]-table[ind]) * acos_slope[ind]) >> 11
    l_mac0(l_tmp, ind, 128)
}

/// `NTRANS2[row][state]`, 0 outside the table (a corrupt TCVQ index; valid indices stay inside).
fn tcvq_ntrans(row: i16, state: i16) -> i16 {
    usize::try_from(row)
        .ok()
        .and_then(|row| NTRANS2.get(row))
        .map_or(0, |row| at(row, i32::from(state)))
}

/// `codebook[iwd]`, zero outside the codebook (a corrupt TCVQ index; valid indices stay inside).
fn tcvq_codeword(codebook: &[[i16; 2]], iwd: i16) -> [i16; 2] {
    usize::try_from(iwd)
        .ok()
        .and_then(|iwd| codebook.get(iwd))
        .copied()
        .unwrap_or([0, 0])
}

/// The intra-frame prediction of one TCVQ stage from the previous stage's decoded pair.
fn tcvq_pred(coeff: &[[i16; 2]; 2], d: &[i16; 2]) -> [i16; 2] {
    [
        add(mult_r(coeff[0][0], d[0]), mult_r(coeff[0][1], d[1])),
        add(mult_r(coeff[1][0], d[0]), mult_r(coeff[1][1], d[1])),
    ]
}

/// `tcvq_Dec_fx`: decode the block-constrained trellis-coded VQ of the 16 kHz VOICED LSF residual
/// (eight 2-dim stages) from the nine indices `ind[0..9]` into `d_out[0..16]`, with the safety-net
/// or the AR codebooks.
pub fn tcvq_dec(ind: &[i16], d_out: &mut [i16], safety_net: i16) {
    let mut index = [0i16; 9];
    index.copy_from_slice(&ind[..9]);

    let (cb_sub1, cb_sub2, cb_sub3, intra_coeff) = if safety_net != 0 {
        (
            &SN_TCVQ_CB_SUB1_FX,
            &SN_TCVQ_CB_SUB2_FX,
            &SN_TCVQ_CB_SUB3_FX,
            &SN_INTRACOEFF_FX,
        )
    } else {
        (
            &AR_TCVQ_CB_SUB1_FX,
            &AR_TCVQ_CB_SUB2_FX,
            &AR_TCVQ_CB_SUB3_FX,
            &AR_INTRACOEFF_FX,
        )
    };

    let mut branch = [0i16; 8];
    let mut codeword = [0i16; 8];
    let mut d = [[0i16; 2]; 8];

    // Decode the final state.
    let fins = index[0] & 15;

    // Decode the branches.
    branch[0] = shr(index[1], 4);
    branch[1] = shr(index[2], 4);
    for stage in 2..4 {
        branch[stage] = shr(index[stage + 1], 3);
    }
    branch[4] = fins & 0x1;
    branch[5] = shr(fins, 1) & 0x1;
    branch[6] = shr(fins, 2) & 0x1;
    branch[7] = shr(fins, 3) & 0x1;

    // Decode the codewords.
    for stage in 0..2 {
        codeword[stage] = shl(index[stage + 1] & 15, 3);
    }
    for stage in 2..4 {
        codeword[stage] = shl(index[stage + 1] & 7, 3);
    }
    for stage in 4..8 {
        codeword[stage] = shl(index[stage + 1] & 3, 3);
    }

    let mut state = shl(shr(fins, 2), 2);

    // Stage 1.
    let mut iwd = add(tcvq_ntrans(branch[0] + 2, state), codeword[0]);
    d[0] = tcvq_codeword(&cb_sub1[0], iwd);
    state = tcvq_ntrans(branch[0], state);

    // Stage 2.
    let mut pred = tcvq_pred(&intra_coeff[0], &d[0]);
    iwd = add(tcvq_ntrans(branch[1] + 2, state), codeword[1]);
    let cw = tcvq_codeword(&cb_sub1[1], iwd);
    d[1] = [add(cw[0], pred[0]), add(cw[1], pred[1])];
    state = tcvq_ntrans(branch[1], state);

    // Stages 3 and 4.
    for stage in 2..4 {
        pred = tcvq_pred(&intra_coeff[stage - 1], &d[stage - 1]);
        iwd = add(tcvq_ntrans(branch[stage] + 2, state), codeword[stage]);
        let cw = tcvq_codeword(&cb_sub2[stage - 2], iwd);
        d[stage] = [add(cw[0], pred[0]), add(cw[1], pred[1])];
        state = tcvq_ntrans(branch[stage], state);
    }

    // Stages 5 to 8.
    for stage in 4..8 {
        pred = tcvq_pred(&intra_coeff[stage - 1], &d[stage - 1]);
        iwd = add(tcvq_ntrans(branch[stage] + 2, state), codeword[stage]);
        let cw = tcvq_codeword(&cb_sub3[stage - 4], iwd);
        d[stage] = [add(cw[0], pred[0]), add(cw[1], pred[1])];
        state = tcvq_ntrans(branch[stage], state);
    }

    for stage in 0..8 {
        d_out[2 * stage] = d[stage][0];
        d_out[2 * stage + 1] = d[stage][1];
    }
}

/// `qlsf_ARSN_tcvq_Dec_16k_fx`: decode the 16 kHz VOICED LSF residual `y` (Q(x2.56)) from
/// `indice` (`indice[0]` the safety-net flag, `[1..10]` the TCVQ indices, `[10..12]` the SVQ
/// refinement when `n_bits > 30`). Returns the safety-net flag.
pub fn qlsf_arsn_tcvq_dec_16k(y: &mut [i16], indice: &[i16], n_bits: i16) -> i16 {
    let mut error_svq_q = [0i16; M as usize];

    let safety_net = indice[0];

    // The SVQ indices are 5 and 4 bits; past the codebooks they add nothing.
    let svq = |error_svq_q: &mut [i16; M as usize]| {
        let cb1 = usize::try_from(indice[10])
            .ok()
            .and_then(|i| AR_SVQ_CB1_FX.get(i));
        let cb2 = usize::try_from(indice[11])
            .ok()
            .and_then(|i| AR_SVQ_CB2_FX.get(i));
        for i in 0..8 {
            error_svq_q[i] = cb1.map_or(0, |row| row[i]);
            error_svq_q[i + 8] = cb2.map_or(0, |row| row[i]);
        }
    };

    if sub(safety_net, 1) == 0 {
        tcvq_dec(&indice[1..], y, safety_net);

        if sub(n_bits, 30) > 0 {
            svq(&mut error_svq_q);
            for i in 0..M as usize {
                y[i] = add(
                    y[i],
                    extract_h(l_shl(l_mult0(error_svq_q[i], SCALE_ARSN_FX[i]), 2)),
                );
            }
        }
    } else {
        tcvq_dec(&indice[1..], y, safety_net);

        if sub(n_bits, 30) > 0 {
            svq(&mut error_svq_q);
            for i in 0..M as usize {
                y[i] = add(y[i], error_svq_q[i]);
            }
        }
    }

    safety_net
}

mod lpc_conv;
pub use lpc_conv::{a2rc, compute_poly_product, lsp2lpc, lsp_convolve, poscos, space_lsfs};
mod isp_conv;
pub use isp_conv::{
    e_lpc_a_isp_conversion, e_lpc_isp_isf_conversion, isf2lsf, isp2lsp, lsf2isf, lsf_update_memory,
    lsp2isp, msvq_dec, tcxlpc_get_cdk,
};
