//! Energy of the impulse response of `1/A(z)` (TS 26.442 `lib_com/enr_1_az_fx.c`).

use crate::evs::cnst::L_SUBFR;
use crate::itu::basic_ops::{l_add, l_mult, l_shl, l_sub, norm_s, round_word, shr, sub};

/// `L_mult`, raising the STL `Overflow` flag when the operator saturates (`-32768 * -32768`).
fn l_mult_flagged(a: i16, b: i16, overflow: &mut bool) -> i32 {
    if a == i16::MIN && b == i16::MIN {
        *overflow = true;
    }
    l_mult(a, b)
}

/// `L_mac(acc, a, b)`, raising `Overflow` where the multiply or the accumulate saturates.
fn l_mac_flagged(acc: i32, a: i16, b: i16, overflow: &mut bool) -> i32 {
    let product = l_mult_flagged(a, b, overflow);
    let result = l_add(acc, product);
    if i64::from(acc) + i64::from(product) != i64::from(result) {
        *overflow = true;
    }
    result
}

/// `L_msu(acc, a, b)`, raising `Overflow` where the multiply or the subtraction saturates.
fn l_msu_flagged(acc: i32, a: i16, b: i16, overflow: &mut bool) -> i32 {
    let product = l_mult_flagged(a, b, overflow);
    let result = l_sub(acc, product);
    if i64::from(acc) - i64::from(product) != i64::from(result) {
        *overflow = true;
    }
    result
}

/// `L_shl(x, n)` for `n >= 0`, raising `Overflow` where the shift saturates (it clamps, and
/// raises the flag, as soon as the value no longer fits in 32 bits).
fn l_shl_flagged(x: i32, n: i16, overflow: &mut bool) -> i32 {
    let result = l_shl(x, n);
    if n > 0 {
        let exact = if n >= 64 {
            if x == 0 {
                0
            } else {
                i128::MAX
            }
        } else {
            i128::from(x) << n
        };
        if exact != i128::from(result) {
            *overflow = true;
        }
    }
    result
}

/// `round_fx(x)`: `L_add(x, 0x8000)` saturates for `x > 0x7FFF7FFF`.
fn round_flagged(x: i32, overflow: &mut bool) -> i16 {
    if x > 0x7FFF_7FFF {
        *overflow = true;
    }
    round_word(x)
}

/// `Enr_1_Az_fx`: energy of the first `len` samples (at most `2·L_SUBFR`) of the impulse response
/// of the order-16 synthesis filter `1/Aq(z)` (`Aq` Q12), rounded to 16 bits. A `len` below 16
/// still sums the first 16 samples, as the reference does.
#[must_use]
pub fn enr_1_az(aq: &[i16], len: i16) -> i16 {
    enr_1_az_flagged(aq, len).0
}

/// [`enr_1_az`] together with the STL `Overflow` flag as the reference leaves it: whether any
/// operator of the filter recursion or of the energy sum saturated (`L_mult`, `L_mac`, `L_msu`,
/// `L_shl` and the `round_fx` additions). Callers that read `Overflow` after the call
/// (`improv_amr_wb_gs_fx` clears it first) take it from here.
#[must_use]
pub fn enr_1_az_flagged(aq: &[i16], len: i16) -> (i16, bool) {
    const H1_LEN: usize = 2 * L_SUBFR as usize;
    let mut overflow = false;
    let mut h1 = [0_i16; H1_LEN];
    // The first 16 samples are computed whatever `len` is (the reference's first loop is fixed).
    let len = (len.max(16) as usize).min(H1_LEN);
    let mut q = sub(3, norm_s(aq[0]));
    let a0 = shr(aq[0], q);
    q = sub(4, q);

    let first = l_mult_flagged(a0, 1 << 13, &mut overflow);
    h1[0] = round_flagged(first, &mut overflow);
    let mut l_tmp2 = l_mult_flagged(h1[0], h1[0], &mut overflow);

    let mut l_tmp = l_msu_flagged(0, aq[1], h1[0], &mut overflow);
    let shifted = l_shl_flagged(l_tmp, q, &mut overflow);
    h1[1] = round_flagged(shifted, &mut overflow);
    l_tmp2 = l_mac_flagged(l_tmp2, h1[1], h1[1], &mut overflow);

    for i in 2..len {
        l_tmp = l_msu_flagged(0, aq[1], h1[i - 1], &mut overflow);
        for j in 2..=i.min(16) {
            l_tmp = l_msu_flagged(l_tmp, aq[j], h1[i - j], &mut overflow);
        }
        let shifted = l_shl_flagged(l_tmp, q, &mut overflow);
        h1[i] = round_flagged(shifted, &mut overflow);
        l_tmp2 = l_mac_flagged(l_tmp2, h1[i], h1[i], &mut overflow);
    }
    (round_flagged(l_tmp2, &mut overflow), overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `a(z) = 1` has the impulse response `1, 0, 0, ...`: the energy is the first sample's.
    #[test]
    fn the_unit_filter_has_the_energy_of_its_first_sample() {
        let mut aq = [0i16; 17];
        aq[0] = 4096;
        let (energy, overflow) = enr_1_az_flagged(&aq, 64);
        assert_eq!(energy, enr_1_az(&aq, 64));
        assert!(!overflow);
        assert!(energy > 0);
    }

    #[test]
    fn a_resonant_filter_raises_the_overflow_flag() {
        let mut aq = [0i16; 17];
        aq[0] = 4096;
        aq[1] = -32768;
        aq[2] = 32767;
        let (_, overflow) = enr_1_az_flagged(&aq, 128);
        assert!(overflow);
    }
}
