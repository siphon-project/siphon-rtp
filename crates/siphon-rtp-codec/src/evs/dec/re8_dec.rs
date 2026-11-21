//! Multi-rate RE8 lattice index decoding (TS 26.442 `lib_dec/re8_dec_fx.c`; TS 26.445
//! §6.1.4.2.1).

use crate::evs::com::re8_util::re8_k2y;
use crate::evs::dec::lead_deindexing::re8_decode_base_index;
use crate::itu::basic_ops::{add, shl, sub};

/// `re8_dec_fx`: decode the point `y` of RE8 from its codebook number `n` (0, 2, 3, 4, ...), its
/// base-codebook index `i` and, for `n > 4`, its Voronoi index `k` (8 values).
pub fn re8_dec(mut n: i16, i: u16, k: &[i16], y: &mut [i16]) {
    // decode the sub-indices I and kv[] according to the codebook number n:
    //  if n=0,2,3,4, decode I (no Voronoi extension)
    //  if n>4, Voronoi extension is used, decode I and kv[]
    if sub(n, 4) <= 0 {
        re8_decode_base_index(n, i, y);
        return;
    }
    // compute the Voronoi modulo m = 2^r where r is extension order
    let mut m: i16 = 0;
    while n > 4 {
        m = add(m, 1);
        n -= 2;
    }
    // decode base codebook index I into c (c is an element of Q3 or Q4)
    // [here c is stored in y to save memory]
    re8_decode_base_index(n, i, y);
    // decode Voronoi index k[] into v
    let mut v = [0_i16; 8];
    re8_k2y(k, m, &mut v);
    // reconstruct y as y = m c + v (with m=2^r, r integer >=1)
    for (yi, &vi) in y.iter_mut().zip(&v) {
        *yi = add(shl(*yi, m), vi);
    }
}
