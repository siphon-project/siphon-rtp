//! Innovation gain (TS 26.442 `lib_com/gain_inov.c`).

use crate::evs::basop::mpy_32_32;
use crate::evs::com::basop_util::{dot_product12_offs, isqrt32norm};
use crate::itu::basic_ops::{l_shl, norm_l, norm_s, sub};

/// `calc_gain_inov`: `1 / sqrt((Σ code[i]² + 0.01) / lcode)` for the Q9 innovation `code` of
/// `lcode` (32, 40, 64 or 80) samples, as 15Q16. `dotp` (Q31-`dotp_e`) and `dotp_e` receive the
/// normalised intermediate energy when asked for.
pub fn calc_gain_inov(
    code: &[i16],
    lcode: i16,
    dotp: Option<&mut i32>,
    dotp_e: Option<&mut i16>,
) -> i32 {
    // L_tmp = dot_product(code, code, lcode) + 0.01
    let mut exp_l_tmp: i16 = 0;
    let mut l_tmp = dot_product12_offs(code, code, lcode, Some(&mut exp_l_tmp), 2621); // 0.01f/2.0f Q19
    exp_l_tmp = sub(exp_l_tmp, 18);

    // gain_inov = 1.0f / sqrt((dot_product(code, code, lcode) + 0.01) / lcode)
    // Note: lcode is in range: 32,40,64,80
    if (lcode & sub(lcode, 1)) != 0 {
        l_tmp = mpy_32_32(l_tmp, 1_717_986_918); // 64.0/80.0 Q31
    }
    exp_l_tmp = sub(exp_l_tmp, sub(14, norm_s(lcode)));

    let i = norm_l(l_tmp);
    l_tmp = l_shl(l_tmp, i);
    exp_l_tmp = sub(exp_l_tmp, i);

    if let Some(dotp) = dotp {
        *dotp = l_tmp;
    }
    if let Some(dotp_e) = dotp_e {
        *dotp_e = exp_l_tmp;
    }

    l_tmp = isqrt32norm(l_tmp, &mut exp_l_tmp);

    l_shl(l_tmp, sub(exp_l_tmp, 15)) // 15Q16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_energy_pulse_gives_the_expected_gain_and_intermediates() {
        // One pulse of 1.0 (Q9 = 512) in 64 samples: energy 512², mean 512²/64 = 64² · 64.
        let mut code = [0i16; 64];
        code[10] = 512;
        let (mut dotp, mut dotp_e) = (0, 0);
        let gain = calc_gain_inov(&code, 64, Some(&mut dotp), Some(&mut dotp_e));
        assert!(dotp >= 0x4000_0000);
        // 1/sqrt((1 + 0.01) / 64) = 7.9605, in Q16.
        assert!((gain - 521_700).abs() < 200, "gain {gain}");
    }
}
