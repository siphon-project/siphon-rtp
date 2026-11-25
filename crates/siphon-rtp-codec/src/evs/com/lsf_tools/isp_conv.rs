//! ISP / ISF conversions, the multi-stage LSF vector dequantiser and the MA memory update of the
//! MODE2 LPC path (TS 26.442 `lib_com/lsf_tools_fx.c`).

use super::{at, e_lpc_a_lsp_conversion};
use super::{
    chebyshev, e_lpc_f_isp_a_conversion, e_lpc_f_lsp_a_conversion, e_lpc_isf_isp_conversion,
    e_lpc_lsf_lsp_conversion, e_lpc_lsp_lsf_conversion, xsp_to_xsf, NC_MAX,
};
use crate::evs::cnst::{GRID100_POINTS, M, MU_MA_FX, VOICED};
use crate::evs::rom::{GRID, LSF_MEANS};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_l, l_mult, l_shr, mult, mult_r, negate, norm_s, shl, shr, sub,
};
use crate::itu::stl2009::{i_mult, lshl, lshr, mac_r};

use crate::evs::com::math_op::i_mult2;

/// `E_LPC_a_isp_conversion`: the ISPs `isp[0..m]` (Q15 cosines) of the LP filter `a[0..=m]`
/// (any Q, `a[0]` giving it), as the alternating roots of the sum and difference polynomials on
/// the 100-point grid, each refined by two bisections and a linear interpolation; the last ISP is
/// the last reflection coefficient. If fewer than `m - 1` roots are found and the last
/// coefficient is small, `old_isp` is returned instead.
pub fn e_lpc_a_isp_conversion(a: &[i16], isp: &mut [i16], old_isp: &[i16], m: i16) {
    let mut f = [[0i32; NC_MAX + 1]; 2];

    // find the sum and diff polynomials F1(z) and F2(z)
    //      F1(z) = [A(z) + z^M A(z^-1)]
    //      F2(z) = [A(z) - z^M A(z^-1)]/(1-z^-2)
    let nc = shr(m, 1);
    let nc_len = (nc.max(0) as usize).min(NC_MAX);
    let m_len = m.max(0) as usize;

    let scale = shl(256, norm_s(a[0]));

    for i in 0..nc_len {
        let t0 = l_mult(a[i], scale); // Q23
        let t1 = l_mult(a[m_len - i], scale); // Q23
        f[0][i] = crate::itu::basic_ops::l_add(t0, t1); // Q23
        f[1][i] = crate::itu::basic_ops::l_sub(t0, t1); // Q23
    }
    f[0][nc_len] = l_mult(a[nc_len], scale); // Q23-1

    for i in 2..nc_len {
        f[1][i] = crate::itu::basic_ops::l_add(f[1][i], f[1][i - 2]);
    }
    f[1][nc_len - 1] = l_shr(f[1][nc_len - 1], 1);

    f[0][2] = crate::itu::basic_ops::l_sub(f[0][2], f[0][0]);
    f[1][2] = crate::itu::basic_ops::l_sub(f[1][2], f[1][0]);

    // Find the ISPs (roots of F1(z) and F2(z)) using the Chebyshev polynomial evaluation. The
    // roots of F1(z) and F2(z) are alternatively searched. We start by finding the first root of
    // F1(z) then we switch to F2(z) then back to F1(z) and so on until all roots are found.
    //
    //  - Evaluate Chebyshev pol. at grid points and check for sign change.
    //  - If sign change track the root by subdividing the interval 2 times and checking sign
    //    change.
    let mut nf: usize = 0; // number of found frequencies
    let mut ip: usize = 0; // indicator for f1 or f2

    let mut order = nc;

    let mut xlow = GRID[0];
    let mut ylow = chebyshev(xlow, &f[ip], order, 7);

    for &grid_point in &GRID[1..=GRID100_POINTS as usize] {
        let mut xhigh = xlow;
        let mut yhigh = ylow;
        xlow = grid_point;
        ylow = chebyshev(xlow, &f[ip], order, 7);

        if l_mult(ylow, yhigh) <= 0 {
            let mut t0 = l_mult(xhigh, 0x4000);
            // divide 2 times the interval
            let mut x = mac_r(t0, xlow, 0x4000); // xmid = (xlow + xhigh)/2
            let mut y = chebyshev(x, &f[ip], order, 7);

            if l_mult(ylow, y) <= 0 {
                yhigh = y;
                xhigh = x;
                y = ylow;
                x = xlow;
                // 'xhigh' has changed, update 't0'
                t0 = l_mult(xhigh, 0x4000);
            }
            xlow = mac_r(t0, x, 0x4000); // xlow = (x + xhigh)/2
            ylow = chebyshev(xlow, &f[ip], order, 7);

            if l_mult(y, ylow) <= 0 {
                yhigh = ylow;
                xhigh = xlow;
                ylow = y;
                xlow = x;
            }

            // Linear interpolation
            // xint = xlow - ylow*(xhigh-xlow)/(yhigh-ylow)
            y = sub(yhigh, ylow);

            if y != 0 {
                x = sub(xhigh, xlow);

                let mut tmp = abs_s(y);
                let exp = norm_s(tmp);
                if exp != 0 {
                    tmp = shl(tmp, exp);
                }
                tmp = div_s(16383, tmp);
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

            isp[nf] = xlow;
            nf += 1;

            if sub(nf as i16, m - 1) >= 0 {
                break;
            }

            ip ^= 1;
            order = sub(nc, ip as i16);
            ylow = chebyshev(xlow, &f[ip], order, 7);
        }
    }

    // Check if m-1 roots found, if not use the ISPs from previous frame
    isp[m_len - 1] = shl(a[m_len], add(norm_s(a[0]), 1)); // From Qx to Q15 with saturation

    if sub(nf as i16, m - 1).min(sub(8192, abs_s(a[m_len]))) < 0 {
        isp[..m_len].copy_from_slice(&old_isp[..m_len]);
    }
}

/// `E_LPC_isp_isf_conversion`: ISPs (Q15 cosines) to ISFs (Q(x2.56), 0..6400): the cosine to
/// frequency map, the last ISF (the reflection coefficient) at half the scale.
pub fn e_lpc_isp_isf_conversion(isp: &[i16], isf: &mut [i16], m: i16) {
    let m_len = m.max(1) as usize;
    for i in 0..m_len {
        isf[i] = xsp_to_xsf(isp[i]);
    }

    isf[m_len - 1] = shr(isf[m_len - 1], 1);
}

/// `lsp2isp_fx`: LSPs to ISPs through the predictor coefficients; `stable_isp` supplies the ISPs
/// to fall back on and is updated to the latest result. Works on the full `M` = 16 vector.
pub fn lsp2isp(lsp: &[i16], isp: &mut [i16], stable_isp: &mut [i16], m: i16) {
    let mut a = [0i16; M as usize + 1];

    // LSP --> A
    e_lpc_f_lsp_a_conversion(lsp, &mut a, m);

    // A --> ISP
    e_lpc_a_isp_conversion(&a, isp, stable_isp, m);

    // Update to latest stable ISP
    stable_isp[..M as usize].copy_from_slice(&isp[..M as usize]);
}

/// `isp2lsp_fx`: ISPs to LSPs through the predictor coefficients; `stable_lsp` supplies the LSPs
/// to fall back on and is updated to the latest result. Works on the full `M` = 16 vector.
pub fn isp2lsp(isp: &[i16], lsp: &mut [i16], stable_lsp: &mut [i16], m: i16) {
    let mut a = [0i16; M as usize + 1];

    // ISP --> A
    e_lpc_f_isp_a_conversion(isp, &mut a, m);
    // A --> LSP
    e_lpc_a_lsp_conversion(&a, lsp, stable_lsp, m);
    // Update to latest stable LSP
    stable_lsp[..M as usize].copy_from_slice(&lsp[..M as usize]);
}

/// `lsf2isf_fx`: LSFs to ISFs (via LSPs and ISPs); `stable_isp` as in [`lsp2isp`].
pub fn lsf2isf(lsf: &[i16], isf: &mut [i16], stable_isp: &mut [i16], m: i16) {
    let mut tmp_lsp = [0i16; M as usize];
    let mut tmp_isp = [0i16; M as usize];

    // LSF --> LSP
    e_lpc_lsf_lsp_conversion(lsf, &mut tmp_lsp, m);

    // LSP --> ISP
    lsp2isp(&tmp_lsp, &mut tmp_isp, stable_isp, m);

    // ISP --> ISF
    e_lpc_isp_isf_conversion(&tmp_isp, isf, m);
}

/// `isf2lsf_fx`: ISFs to LSFs (via ISPs and LSPs) over the full `M` coefficients; `stable_lsp` as
/// in [`isp2lsp`].
pub fn isf2lsf(isf: &[i16], lsf: &mut [i16], stable_lsp: &mut [i16]) {
    let mut tmp_isp = [0i16; M as usize];
    let mut tmp_lsp = [0i16; M as usize];

    // ISF --> ISP
    e_lpc_isf_isp_conversion(isf, &mut tmp_isp, M);
    // ISP --> LSP
    isp2lsp(&tmp_isp, &mut tmp_lsp, stable_lsp, M);

    // LSP --> LSF
    e_lpc_lsp_lsf_conversion(&tmp_lsp, lsf, M);
}

/// `lsf_update_memory`: the moving-average memory `mem_ma = qlsf - mean - mu · old_mem_ma` of
/// the (wide- or narrow-band) quantised LSFs `qlsf` over `lpcorder` coefficients.
pub fn lsf_update_memory(
    narrowband: i16,
    qlsf: &[i16],
    old_mem_ma: &[i16],
    mem_ma: &mut [i16],
    lpcorder: i16,
) {
    let means = LSF_MEANS[usize::from(narrowband != 0)];
    for i in 0..lpcorder.max(0) as usize {
        mem_ma[i] = sub(sub(qlsf[i], means[i]), mult_r(MU_MA_FX, old_mem_ma[i]));
    }
}

/// `tcxlpc_get_cdk`: the TCX LPC codebook set, 1 for voiced ACELP extension mode, else 0.
#[must_use]
pub fn tcxlpc_get_cdk(acelp_ext_mode: i16) -> i16 {
    let mut cdk = 0;
    if sub(acelp_ext_mode, VOICED) == 0 {
        cdk = 1;
    }
    cdk
}

/// `msvq_dec`: the multi-stage LSF vector `uq[0..N]` (Q(x2.56)) as the sum over `stages` of the
/// codebook vectors `cb[i]` selected by `idx[i]`. A stage covers `dims[i]` elements from `offs[i]`
/// of the vector (the whole vector, from 0, without `dims` / `offs`); its codebook rows are packed
/// four values to three words, which `depack_4_values` unpacks.
pub fn msvq_dec(
    cb: &[&[i16]],
    dims: Option<&[i16]>,
    offs: Option<&[i16]>,
    stages: i16,
    n: i16,
    max_n: i16,
    idx: &[i16],
    uq: &mut [i16],
) {
    uq[..n.max(0) as usize].fill(0);

    for i in 0..stages.max(0) as usize {
        let mut cur_n = n;
        let mut maxn = max_n;
        if let Some(dims) = dims {
            cur_n = dims[i];
        }
        if dims.is_some() {
            maxn = cur_n;
        }

        // the reference asserts maxn % 4 == 0
        let n34 = mult(maxn, 24576); // 0.75 Q15

        let mut start: i16 = 0;
        if let Some(offs) = offs {
            start = offs[i];
        }

        // vr_add( uq+start, cb[i]+Idx[i]*maxn, uq+start, n ); where uq = a zero vector
        let offset = i_mult2(idx[i], n34);

        let mut j: i16 = 0;
        while j < cur_n {
            // depack_4_values(cb[i]+offset+i_mult(3,(shr(j,2))), val0, val1, val2, val3)
            let base = i32::from(offset) + i32::from(i_mult(3, shr(j, 2)));
            let word = |k: i32| at(cb[i], base + k);
            let val0 = shr(word(0), 4);
            let val1 = shr(word(1), 4);
            let val2 = shr(word(2), 4);
            let val3 = add(
                add(shr(lshl(word(2), 12), 4), lshr(lshl(word(1), 12), 8)),
                word(0) & 0xF,
            );

            let at_start = start as usize + j as usize;
            uq[at_start] = add(uq[at_start], val0); // 14Q1*1.28
            uq[at_start + 1] = add(uq[at_start + 1], val1);
            uq[at_start + 2] = add(uq[at_start + 2], val2);
            uq[at_start + 3] = add(uq[at_start + 3], val3);
            j += 4;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcxlpc_cdk_is_one_only_for_voiced() {
        assert_eq!(tcxlpc_get_cdk(VOICED), 1);
        assert_eq!(tcxlpc_get_cdk(0), 0);
        assert_eq!(tcxlpc_get_cdk(VOICED + 1), 0);
    }

    #[test]
    fn msvq_dec_sums_the_unpacked_stage_vectors() {
        // One stage of four values packed in three words: (0x1234, 0x5678, 0x9abc) unpacks with
        // val0 = w0 >> 4, val1 = w1 >> 4, val2 = w2 >> 4 and val3 from the three low nibbles.
        let words: [i16; 3] = [0x1234, 0x5678, 0x9abc_u16 as i16];
        let stage: &[i16] = &words;
        let mut uq = [0i16; 4];
        msvq_dec(&[stage], None, None, 1, 4, 4, &[0], &mut uq);
        assert_eq!(uq[0], 0x123);
        assert_eq!(uq[1], 0x567);
        assert_eq!(uq[2], (0x9abc_u16 as i16) >> 4);
        // val3 = (w2 << 12 >> 4) + (w1 << 12 >>> 8) + (w0 & 0xF) = -1024 + 128 + 4
        assert_eq!(uq[3], -892);
    }

    #[test]
    fn lsf_update_memory_subtracts_the_mean_and_the_scaled_old_memory() {
        let qlsf = [LSF_MEANS[0][0]; 1];
        let mut mem = [0i16; 1];
        lsf_update_memory(0, &qlsf, &[0], &mut mem, 1);
        assert_eq!(mem[0], 0);
    }
}
