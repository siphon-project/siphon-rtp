//! Energy of the impulse response of `1/A(z)` (TS 26.442 `lib_com/enr_1_az_fx.c`).

use crate::evs::cnst::L_SUBFR;
use crate::itu::basic_ops::{l_mac, l_msu, l_mult, l_shl, norm_s, round_word, shr, sub};

/// `Enr_1_Az_fx`: energy of the first `len` samples (at most `2·L_SUBFR`) of the impulse response
/// of the order-16 synthesis filter `1/Aq(z)` (`Aq` Q12), rounded to 16 bits. A `len` below 16
/// still sums the first 16 samples, as the reference does.
#[must_use]
pub fn enr_1_az(aq: &[i16], len: i16) -> i16 {
    const H1_LEN: usize = 2 * L_SUBFR as usize;
    let mut h1 = [0_i16; H1_LEN];
    // The first 16 samples are computed whatever `len` is (the reference's first loop is fixed).
    let len = (len.max(16) as usize).min(H1_LEN);
    let mut q = sub(3, norm_s(aq[0]));
    let a0 = shr(aq[0], q);
    q = sub(4, q);

    h1[0] = round_word(l_mult(a0, 1 << 13));
    let mut l_tmp2 = l_mult(h1[0], h1[0]);

    let mut l_tmp = l_msu(0, aq[1], h1[0]);
    h1[1] = round_word(l_shl(l_tmp, q));
    l_tmp2 = l_mac(l_tmp2, h1[1], h1[1]);

    for i in 2..len {
        l_tmp = l_msu(0, aq[1], h1[i - 1]);
        for j in 2..=i.min(16) {
            l_tmp = l_msu(l_tmp, aq[j], h1[i - j]);
        }
        h1[i] = round_word(l_shl(l_tmp, q));
        l_tmp2 = l_mac(l_tmp2, h1[i], h1[i]);
    }
    round_word(l_tmp2)
}
