//! LSP to LPC conversion for the TBE LPC (`lsp2lpc_fx`) and its helpers, the LSF spacing, and the
//! LPC to reflection-coefficient conversion (TS 26.442 `lib_com/lsf_tools_fx.c`).

use super::OverflowFlag;
use crate::evs::rom::{COS_COEF_NEW, PWALPHA};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_mac, l_msu, l_mult, l_negate, l_shl,
    l_shr, l_sub, mult_r, negate, norm_l, norm_s, round_word, shl, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0};

/// `poscos_fx`: the polynomial (Taylor) evaluation of the LSP cosine term for `w` (Q15), as a Q31
/// value; `0xc0000004` for `w == 0`.
#[must_use]
pub fn poscos(w: i16) -> i32 {
    if w == 0 {
        return 0xc000_0004u32 as i32;
    }
    let mut z: i16 = 0x2000;
    z = shl(sub(z, w), 2);
    let a: i16 = 0x6488;
    z = mult_r(z, a);
    let z2 = mult_r(z, z);
    let z3 = round_word(l_shl(l_mult0(z, z2), 0));
    let z5 = mult_r(z2, z3);
    let z7 = round_word(l_shl(l_mult0(z2, z5), 0));
    let z9 = round_word(l_shl(l_mult0(z2, z7), 0));

    let mut lacc = l_mult(z9, COS_COEF_NEW[0]);
    lacc = l_mac0(lacc, z7, COS_COEF_NEW[1]);
    let ltemp = l_shl(l_mult(z3, COS_COEF_NEW[3]), 1);
    lacc = l_add(l_shr(lacc, 1), ltemp);
    lacc = l_add(lacc, l_deposit_h(z));
    let ltemp = l_mult(z5, COS_COEF_NEW[2]);
    lacc = l_sub(lacc, l_shl(ltemp, 1));
    l_negate(lacc)
}

/// `lsp_convolve_fx`: multiplies the polynomial `p1[0..=len]` by the quadratic factor of the LSP
/// term `x` (Q31), into `p2[0..=len + 1]`.
pub fn lsp_convolve(x: i32, p1: &[i32], p2: &mut [i32], len: i16) {
    let len = len.max(0) as usize;
    let d1h = extract_h(x);
    let d1l = extract_l(x);

    let mut ltemp = l_add(x, p1[0]);
    p2[0] = ltemp;
    ltemp = l_deposit_h(0x100);
    for i in 0..len {
        ltemp = l_add(ltemp, p1[i + 1]);
        let d2h = extract_h(p1[i]);
        let d2l = extract_l(p1[i]);
        // `(UWord16) d2l` converts back to the operator's `Word16` parameter: the same bits.
        let mut lacc = l_mult0(d1h, d2l);
        lacc = l_mac0(lacc, d2h, d1l);
        lacc = l_add(l_shr(lacc, 16), l_shr(l_mult(d1h, d2h), 1));
        lacc = l_add(l_shl(lacc, 8), ltemp);
        p2[i + 1] = lacc;
        ltemp = l_add(0, p1[i]);
    }
    p2[len + 1] = p2[len.wrapping_sub(1)];
}

/// `compute_poly_product_fx`: the polynomial `p[0..=order/2]` whose roots are the `order/2` LSPs
/// `coef[0], coef[2], ...` (every second LSP of `coef`), built by repeated [`lsp_convolve`].
pub fn compute_poly_product(coef: &[i16], p: &mut [i32], order: i16) {
    let half = (order / 2) as usize;
    let mut lspcos = [0i32; 10];
    let mut p2 = [0i32; 10];

    for i in 0..half {
        lspcos[i] = poscos(coef[i * 2]);
    }
    p[0] = l_deposit_h(0x100);
    p[2] = l_deposit_h(0x100);
    p[1] = l_shr(lspcos[half - 1], 5);
    p2[0] = l_deposit_h(0x100);

    let mut len: i16 = 1;
    // `p_in` / `p_out` alternate between `p + 1` and `p2 + 1`
    let mut in_is_p = true;
    for lsp in lspcos.iter().take(half - 1) {
        if in_is_p {
            lsp_convolve(l_shr(*lsp, 5), &p[1..], &mut p2[1..], len);
        } else {
            lsp_convolve(l_shr(*lsp, 5), &p2[1..], &mut p[1..], len);
        }
        in_is_p = !in_is_p;
        len = add(len, 1);
    }
    if (half - 1) & 1 != 0 {
        // the product ended up in `p2 + 1`
        p[1..=half].copy_from_slice(&p2[1..=half]);
    }
}

/// `lsp2lpc_fx`: the LPC `a[0..order]` (Q12) of the LSP set `freq` (Q15), falling back to the
/// bandwidth-expanded previous LPC `prev_a` when a polynomial overflows (the reference reads its
/// `Overflow` flag after clearing it before each stage).
pub fn lsp2lpc(a: &mut [i16], freq: &[i16], prev_a: &[i16], order: i16) {
    let order_u = order.max(0) as usize;
    let half = order_u / 2;
    let mut pq = [0i32; 10];
    let mut p = [0i32; 10];
    let mut q = [0i32; 10];
    let mut tmp_pci = [0i16; 17];
    tmp_pci[..order_u].copy_from_slice(&prev_a[..order_u]);

    compute_poly_product(freq, &mut pq, order);
    // `Overflow = 0` before the loop; a saturated sum sets it and ends the loop
    let mut overflowed = false;
    for i in 0..half {
        let mut flag = OverflowFlag::default();
        let ltemp = flag.l_add(pq[i], pq[i + 1]);
        if flag.0 {
            overflowed = true;
            break;
        }
        p[i] = ltemp;
    }
    if overflowed {
        for i in 0..order_u {
            a[i] = mult_r(prev_a[i], PWALPHA[i]);
        }
        return;
    }

    compute_poly_product(&freq[1..], &mut pq, order);
    for i in 0..half {
        let mut flag = OverflowFlag::default();
        let ltemp = flag.l_sub(pq[i + 1], pq[i]);
        if flag.0 {
            overflowed = true;
            break;
        }
        q[i] = ltemp;
    }
    if overflowed {
        for i in 0..order_u {
            a[i] = mult_r(prev_a[i], PWALPHA[i]);
        }
    } else {
        for i in 0..half {
            let mut flag = OverflowFlag::default();
            let mut lacc = flag.l_add(p[i], q[i]);
            if flag.0 {
                overflowed = true;
            }
            lacc = l_negate(lacc);
            let mut flag = OverflowFlag::default();
            let shifted = flag.l_shl(lacc, 3);
            lacc = flag.l_add(shifted, 0x08000);
            if flag.0 {
                overflowed = true;
            }
            a[i] = extract_h(lacc);
            if overflowed {
                break;
            }
        }
        for i in 0..half {
            let mut flag = OverflowFlag::default();
            let mut lacc = flag.l_sub(q[i], p[i]);
            if flag.0 {
                overflowed = true;
            }
            let mut flag = OverflowFlag::default();
            let shifted = flag.l_shl(lacc, 3);
            lacc = flag.l_add(shifted, 0x08000);
            if flag.0 {
                overflowed = true;
            }
            a[order_u - 1 - i] = extract_h(lacc);
            if overflowed {
                break;
            }
        }
    }
    if overflowed {
        for i in 0..order_u {
            a[i] = mult_r(tmp_pci[i], PWALPHA[i]);
        }
    }
}

/// `space_lsfs_fx`: moves LSFs (Q14, `0..16384`) apart until every gap, the first and last
/// included, is at least 770.
pub fn space_lsfs(lsfs: &mut [i16], order: i16) {
    let order_u = order.max(0) as usize;
    let mut flag = true;
    while flag {
        flag = false;
        for i in 0..=order_u {
            let mut delta = if i == 0 {
                lsfs[0]
            } else if i == order_u {
                sub(16384, lsfs[i - 1])
            } else {
                sub(lsfs[i], lsfs[i - 1])
            };
            if sub(delta, 770) < 0 {
                flag = true;
                delta = sub(delta, 771);
                if i == order_u {
                    lsfs[i - 1] = add(lsfs[i - 1], delta);
                } else if i == 0 {
                    lsfs[i] = sub(lsfs[i], delta);
                } else {
                    delta = mult_r(delta, 16384);
                    lsfs[i - 1] = add(lsfs[i - 1], delta);
                    lsfs[i] = sub(lsfs[i], delta);
                }
            }
        }
    }
}

/// `a2rc_fx`: the reflection coefficients `refl[0..lpcorder]` of the LP filter whose coefficients
/// `a[a_at..a_at + lpcorder]` follow the leading coefficient `a[a_at - 1]` (which sets the Q
/// format). An unstable filter gives all-zero reflection coefficients.
pub fn a2rc(a: &[i16], a_at: usize, refl: &mut [i16], lpcorder: i16) {
    let order = lpcorder.max(0) as usize;
    let mut f_fx = [0i16; 16];

    let q = add(norm_s(a[a_at - 1]), 1);
    let q_a = sub(15, q);
    let q_a2 = add(shl(q_a, 1), 1);

    for m in 0..order {
        f_fx[m] = negate(a[a_at + m]);
    }
    let one_qx = shl(1, q_a);
    let one_qx2 = l_shl(1, q_a2);

    for m in (0..order).rev() {
        let km_fx = f_fx[m];
        if sub(km_fx, negate(one_qx)) <= 0 || sub(km_fx, one_qx) >= 0 {
            refl[..order].fill(0);
            return;
        }
        refl[m] = negate(km_fx);

        let mut l_tmp1 = l_add(0, one_qx2);
        l_tmp1 = l_msu(l_tmp1, km_fx, km_fx);
        let mut exp = norm_l(l_tmp1);
        let mut tmp = extract_h(l_shl(l_tmp1, exp));
        exp = sub(sub(30, exp), q_a2);
        tmp = if tmp != 0 { div_s(16384, tmp) } else { 0 };
        let new_mant = l_deposit_h(tmp);
        let denom_mant = round_word(l_shl(new_mant, 0));

        l_tmp1 = l_mult(km_fx, denom_mant);
        l_tmp1 = l_shl(l_tmp1, q);
        let tmp = round_word(l_tmp1);

        let mut j = 0usize;
        while j < m / 2 {
            let n = m - 1 - j;
            let mut l_tmp1 = l_mult(denom_mant, f_fx[j]);
            l_tmp1 = l_mac(l_tmp1, tmp, f_fx[n]);
            let mut l_tmp2 = l_mult(denom_mant, f_fx[n]);
            l_tmp2 = l_mac(l_tmp2, tmp, f_fx[j]);
            l_tmp1 = l_shr(l_tmp1, exp);
            l_tmp2 = l_shr(l_tmp2, exp);
            f_fx[j] = round_word(l_tmp1);
            f_fx[n] = round_word(l_tmp2);
            j += 1;
        }
        if m & 1 != 0 {
            let mut l_tmp1 = l_mult(denom_mant, f_fx[j]);
            l_tmp1 = l_mac(l_tmp1, tmp, f_fx[j]);
            l_tmp1 = l_shr(l_tmp1, exp);
            f_fx[j] = round_word(l_tmp1);
        }
    }
    for value in refl.iter_mut().take(order) {
        *value = shl(*value, q);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poscos_of_zero_is_the_reference_constant() {
        assert_eq!(poscos(0), 0xc000_0004u32 as i32);
    }

    #[test]
    fn space_lsfs_enforces_the_minimum_gap() {
        let mut lsfs = [100i16, 120, 130, 4000, 4100, 9000, 9100, 9200, 14000, 16300];
        space_lsfs(&mut lsfs, 10);
        let mut previous = 0i16;
        for &value in &lsfs {
            assert!(value - previous >= 770 - 2, "{lsfs:?}");
            previous = value;
        }
        assert!(16384 - previous >= 770 - 2);
    }

    #[test]
    fn a2rc_of_a_flat_filter_is_zero() {
        // leading coefficient 1.0 (Q12) and all-zero predictor: every reflection coefficient is 0
        let mut a = [0i16; 11];
        a[0] = 4096;
        let mut refl = [1i16; 10];
        a2rc(&a, 1, &mut refl, 10);
        assert_eq!(refl, [0; 10]);
    }

    #[test]
    fn lsp2lpc_falls_back_to_the_expanded_previous_lpc_on_overflow() {
        // freq of 0 everywhere drives the polynomial products into saturation territory; whatever
        // happens, the result must be a finite LPC of the requested order
        let freq = [0i16; 7];
        let prev = [100i16; 6];
        let mut a = [7i16; 6];
        lsp2lpc(&mut a, &freq, &prev, 6);
        assert!(a.iter().all(|&value| value != 7));
    }
}
