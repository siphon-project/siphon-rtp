//! RE8 lattice utilities (TS 26.442 `lib_com/re8_util_fx.c`; TS 26.445 §6.1.4.2.1). Only the
//! decoder's `re8_k2y_fx` is ported; the rest is the encoder's.

use crate::evs::com::re8_ppv::re8_ppv;
use crate::itu::basic_ops::{extract_l, l_add, l_deposit_l, l_msu, l_shl, l_sub, shl, shr, sub};

/// `re8_k2y_fx`: the point `y` of RE8 of Voronoi index `k` (8 values) for the Voronoi modulo
/// `2^m`.
pub fn re8_k2y(k: &[i16], m: i16, y: &mut [i16]) {
    let mut ytp = [0_i32; 8];
    let mut z = [0_i32; 8];

    // compute y = k M and z=(y-a)/m, where
    //   M = [4        ]
    //       [2 2      ]
    //       [|   \    ]
    //       [2     2  ]
    //       [1 1 _ 1 1]
    //   a=(2,0,...,0)
    let m_tmp = sub(15, m);

    let mut l_sum = l_deposit_l(k[7]);
    ytp[7] = l_sum;
    z[7] = l_shl(l_sum, m_tmp); // (int)(floor(y[7]*QR+0.5))>>m

    for i in (1..=6).rev() {
        let l_tmp = l_deposit_l(shl(k[i], 1));
        l_sum = l_add(l_sum, l_tmp);
        ytp[i] = l_add(ytp[7], l_tmp);
        z[i] = l_shl(ytp[i], m_tmp);
    }

    l_sum = l_add(l_sum, l_deposit_l(shl(k[0], 2)));
    ytp[0] = l_sum;
    z[0] = l_shl(l_sub(l_sum, 2), m_tmp);

    // find nearest neighbor v of z in infinite RE8
    let mut v = [0_i16; 8];
    re8_ppv(&z, &mut v);

    // compute y -= m v
    let mm = shr(shl(1, m), 1); // shr to remove effect of L_mult in L_msu
    for i in 0..8 {
        let l_tmp = l_msu(ytp[i], v[i], mm);
        y[i] = extract_l(l_tmp);
    }
}
