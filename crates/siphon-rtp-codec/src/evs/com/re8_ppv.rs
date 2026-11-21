//! Nearest-neighbour search in the infinite RE8 lattice (TS 26.442 `lib_com/re8_ppv_fx.c`;
//! TS 26.445 §6.1.4.2.1): RE8 = 2D8 ∪ (2D8 + [1,...,1]), decoded by cosets after Conway and
//! Sloane.

use crate::evs::cnst::QR;
use crate::itu::basic_ops::{
    add, extract_h, extract_l, l_abs, l_add, l_mac, l_msu, l_mult, l_shl, l_sub, mult, round_word,
    shl, sub,
};
use crate::itu::stl2009::l_mac0;

/// `re8_PPV_fx`: the point `y` of RE8 nearest to `x` (Q15).
pub fn re8_ppv(x: &[i32; 8], y: &mut [i16]) {
    // find the nearest neighbor y0 of x in 2D8
    let mut y0 = [0_i16; 8];
    nearest_neighbor_2d8(x, &mut y0);

    // find the nearest neighbor y1 of x in 2D8+(1,...,1) (by coset decoding)
    let mut x1 = [0_i32; 8];
    for i in 0..8 {
        x1[i] = l_sub(x[i], QR);
    }
    let mut y1 = [0_i16; 8];
    nearest_neighbor_2d8(&x1, &mut y1);
    for value in &mut y1 {
        *value = add(*value, 1);
    }

    // compute e0=||x-y0||^2 and e1=||x-y1||^2
    let e0 = compute_error_2d8(x, &y0);
    let e1 = compute_error_2d8(x, &y1);

    // select best candidate y0 or y1 to minimize distortion
    if l_sub(e0, e1) < 0 {
        y[..8].copy_from_slice(&y0);
    } else {
        y[..8].copy_from_slice(&y1);
    }
}

/// `nearest_neighbor_2D8_fx`: the point `y` of 2D8 nearest to `x`, by rounding to 2Z^8 and the
/// Wagner rule.
fn nearest_neighbor_2d8(x: &[i32; 8], y: &mut [i16; 8]) {
    // round x into 2Z^8 i.e. compute y=(y1,...,y8) such that yi = 2[xi/2]
    //   where [.] is the nearest integer operator
    //   in the mean time, compute sum = y1+...+y8
    let mut sum: i16 = 0;
    for i in 0..8 {
        // round to ..., -2, 0, 2, ... ([-1..1[ --> 0)
        let tmp16 = round_word(l_add(x[i], x[i] >> 31));
        y[i] = shl(tmp16, 1);
        sum = add(sum, y[i]);
    }

    // check if y1+...+y8 is a multiple of 4; if not, round xj in the wrong way where
    // j = arg max_i | xi -yi| (this is called the Wagner rule)
    if sum & 2 != 0 {
        let mut em: i32 = 0;
        let mut j = 0;
        for i in 0..8 {
            // e[i]=x[i]-y[i]
            let e = l_msu(x[i], y[i], (QR / 2) as i16);
            let s = l_abs(e);
            if l_sub(em, s) < 0 {
                j = i;
            }
            em = s.max(em);
        }
        // round xj in the "wrong way"
        let e = l_msu(x[j], y[j], (QR / 2) as i16);
        let tmp16 = extract_h(e);
        let mut tmp16b = add(y[j], 2);
        if tmp16 < 0 {
            tmp16b = sub(tmp16b, 2 + 2);
        }
        y[j] = tmp16b;
    }
}

/// `compute_error_2D8_fx`: the squared error between `x` (Q15) and the integer point `y`.
fn compute_error_2d8(x: &[i32; 8], y: &[i16; 8]) -> i32 {
    let mut err: i32 = 0;
    for i in 0..8 {
        // tmp = x[i]-y[i]
        let mut l_tmp = l_msu(x[i], y[i], 16384);
        let hi = extract_h(l_shl(l_tmp, 1));
        let lo = extract_l(l_msu(l_tmp, hi, 16384));

        l_tmp = l_mult(hi, hi);
        l_tmp = l_shl(l_tmp, 14);
        l_tmp = l_mac(l_tmp, hi, lo);
        l_tmp = l_mac0(l_tmp, mult(lo, lo), 1);

        // err+=tmp*tmp
        err = l_add(l_tmp, err);
    }
    err
}
