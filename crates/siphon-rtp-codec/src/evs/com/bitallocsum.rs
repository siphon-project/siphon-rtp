//! Total of an HQ bit allocation (TS 26.442 `lib_com/bitallocsum_fx.c`).

use crate::evs::cnst::L_FRAME32K;
use crate::itu::basic_ops::{add, extract_l, shl, sub};
use crate::itu::stl2009::l_mult0;

/// `bitallocsum_fx`: the bits `R[i] · sfmsize[i]` the integer allocation `R` takes (`sum`) and the
/// per-band rate `Rsubband` (Q3); up to 32 kHz the `v - sum` bits left over are handed out one at
/// a time, round-robin, to the bands that have bits.
pub fn bitallocsum(
    r: &[i16],
    nb_sfm: i16,
    sum: &mut i16,
    rsubband: &mut [i16],
    v: i16,
    length: i16,
    sfmsize: &[i16],
) {
    let bands = nb_sfm.max(0) as usize;
    let mut total: i16 = 0;
    for i in 0..bands {
        let tmp = extract_l(l_mult0(r[i], sfmsize[i]));
        rsubband[i] = shl(tmp, 3);
        total = add(total, tmp);
    }
    *sum = total;

    if sub(length, L_FRAME32K) <= 0 {
        let mut diff = sub(v, *sum);
        // The reference spins forever when bits are left over but no band has any (it only
        // hands bits to bands with R > 0); stop instead. The allocators never leave that state.
        if diff > 0 && !r[..bands].iter().any(|&bits| bits > 0) {
            return;
        }
        let mut i: i16 = 0;
        while diff > 0 {
            if r[i as usize] > 0 {
                rsubband[i as usize] = add(rsubband[i as usize], 8);
                diff = sub(diff, 1);
                *sum = add(*sum, 1);
            }
            i = add(i, 1);
            if sub(i, nb_sfm) >= 0 {
                i = 0;
            }
        }
    }
}
