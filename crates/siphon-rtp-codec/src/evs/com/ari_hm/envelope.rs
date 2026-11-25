//! `tcx_hm_modify_envelope` of TS 26.442 `lib_com/ari_hm.c`: the harmonic model's shaping of the
//! arithmetic coder's envelope (TS 26.445 §6.2.2.2.4).
//!
//! `Overflow` and `Carry`: nothing here reads them.

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::KTCXHMPARABOLAHALFWIDTH;
use crate::evs::com::basop_util::imult3216;
use crate::itu::basic_ops::{add, div_s, extract_l, l_shr, mult_r, sub};

/// `tcx_hm_modify_envelope`: attenuate `env` (Q16, `l_frame` lines) around each harmonic of the
/// pitch `lag` (`fract_res` fractional bits) by the prototype peak `p` scaled with `gain` (Q11).
pub fn tcx_hm_modify_envelope(
    gain: i16,
    lag: i32,
    fract_res: i16,
    p: &[i16],
    env: &mut [i32],
    l_frame: i16,
) {
    const HALF_WIDTH: i16 = KTCXHMPARABOLAHALFWIDTH;
    if gain == 0 {
        return;
    }

    let mut inv_shape = [0_i16; 2 * HALF_WIDTH as usize + 1];
    for (inv, &peak) in inv_shape.iter_mut().zip(p) {
        // Q24 = Q11 * Q13; 512 = 1.0 in Q24 format
        *inv = div_s(512, add(512, mult_r(gain, peak)));
    }

    let mut h: i16 = 1;
    let mut k = extract_l(l_shr(lag, fract_res));

    let l_frame_m1 = sub(l_frame, 1);
    let l_frame_for_loop = add(l_frame, HALF_WIDTH - 1);

    while sub(k, l_frame_for_loop) <= 0 {
        let l1 = 0.max(sub(k, HALF_WIDTH));
        let l2 = add(k, HALF_WIDTH).min(l_frame_m1);
        for x in l1..=l2 {
            let at = (x - k + HALF_WIDTH) as usize;
            env[x as usize] = mpy_32_16_1(env[x as usize], inv_shape[at]);
        }

        if h == i16::MAX {
            // `h` saturates and `k` stops advancing: the reference would loop forever. A lag
            // that small is rejected by `tcx_hm_render` before this runs.
            break;
        }
        h = add(h, 1);
        k = extract_l(l_shr(imult3216(lag, h), fract_res));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_gain_leaves_the_envelope_alone() {
        let mut env = [65536_i32; 32];
        tcx_hm_modify_envelope(0, 10 << 3, 3, &[0; 9], &mut env, 32);
        assert_eq!(env, [65536; 32]);
    }

    #[test]
    fn a_harmonic_peak_attenuates_the_lines_around_it() {
        let mut env = [65536_i32; 32];
        let p = [0, 0, 0, 0, 8192, 0, 0, 0, 0];
        tcx_hm_modify_envelope(2048, 10 << 3, 3, &p, &mut env, 32);
        assert!(env[10] < 65536);
        assert_eq!(env[0], 65536);
        // The next harmonic sits at line 20.
        assert!(env[20] < 65536);
    }
}
