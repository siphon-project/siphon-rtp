//! The damping factor of the MODE2 frame loss concealment (TS 26.442 `lib_dec/er_scale_syn.c`;
//! TS 26.447 §5.4.2.5 / §5.4.3.1).

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    _ALPHA_UT_FX, _ALPHA_UU_FX, _ALPHA_U_FX, _ALPHA_VT_FX, _ALPHA_V_FX, ACELP_CORE, GENERIC, ONSET,
    UNVOICED, UNVOICED_CLAS, UNVOICED_TRANSITION, VOICED_CLAS,
};
use crate::evs::com::basop_util::sqrt32;
use crate::itu::basic_ops::{add, l_shl, mult_r, round_word, sub};
use crate::itu::stl2009::mac_r;

/// `Damping_fact`: the damping factor (Q14) of the concealed excitation gain. `lp_gainp` is the
/// damped pitch gain (2Q29), updated for a voiced last good frame in ACELP; `core` selects the
/// ACELP (`ACELP_CORE`) or the TCX estimate.
pub fn damping_fact(
    coder_type: i16,
    nb_lost_cmpt: i16,
    last_good: i16,
    stab_fac: i16,
    lp_gainp: &mut i32,
    core: i16,
) -> i16 {
    let mut alpha: i16;

    if core == ACELP_CORE {
        alpha = mult_r(_ALPHA_VT_FX, 16384); // rapid convergence to 0
        if sub(coder_type, UNVOICED) == 0 && sub(nb_lost_cmpt, 3) <= 0 {
            // Clear unvoiced last good frame
            alpha = mult_r(_ALPHA_UU_FX, 16384);
        } else if sub(last_good, UNVOICED_CLAS) == 0 {
            if sub(nb_lost_cmpt, 1) == 0 {
                // If stable, do not decrease the energy, pitch gain = 0
                alpha = add(mult_r(stab_fac, sub(16384, _ALPHA_U_FX)), _ALPHA_U_FX);
            } else if sub(nb_lost_cmpt, 2) == 0 {
                alpha = mult_r(_ALPHA_U_FX, 24576); // 1.5f Q14
            } else {
                alpha = mult_r(_ALPHA_U_FX, 16384); // go rapidly to CNG gain, pitch gain = 0
            }
        } else if sub(last_good, UNVOICED_TRANSITION) == 0 {
            alpha = mult_r(_ALPHA_UT_FX, 16384);
        } else if sub(last_good, ONSET) == 0
            && sub(nb_lost_cmpt, 3) <= 0
            && sub(coder_type, GENERIC) == 0
        {
            alpha = 13107; // 0.8f Q14
        } else if (sub(last_good, VOICED_CLAS) == 0 || sub(last_good, ONSET) == 0)
            && sub(nb_lost_cmpt, 3) <= 0
        {
            alpha = mult_r(_ALPHA_V_FX, 16384); // constant for the first 3 erased frames
        }

        if sub(last_good, VOICED_CLAS) >= 0 {
            let mut lp_tmp = *lp_gainp;

            if sub(nb_lost_cmpt, 1) == 0 {
                // if first erased frame in a block, reset harmonic gain: move the pitch gain
                // towards 1 for voiced to remove energy fluctuations
                let mut s_gainp: i16 = 31 - 29;
                let gain32 = sqrt32(lp_tmp, &mut s_gainp);

                let mut gain = round_word(l_shl(gain32, s_gainp)); // Q15
                gain = gain.min(32113); // 0.98f Q15
                gain = gain.max(27853); // 0.85f Q15
                alpha = mult_r(alpha, gain);
            } else if sub(nb_lost_cmpt, 2) == 0 {
                // 0.6 + 0.35*stab_fac
                alpha = mult_r(
                    mac_r(1_288_490_240, 11469, stab_fac),
                    round_word(l_shl(lp_tmp, 1)),
                );
            } else {
                // 0.7 + 0.2*stab_fac
                lp_tmp = mpy_32_16_1(lp_tmp, mac_r(1_503_238_528, 6554, stab_fac)); // 2Q29
                alpha = round_word(l_shl(lp_tmp, 1)); // 1Q14
            }
            *lp_gainp = lp_tmp; // store
        }
    } else {
        alpha = mac_r(375_809_632, 6554, stab_fac); // 0.35f Q30 + 0.4f Q14 * stab_fac
        if sub(nb_lost_cmpt, 2) < 0 {
            alpha = mac_r(751_619_264, 4915, stab_fac);
        }
        if sub(nb_lost_cmpt, 2) == 0 {
            alpha = mac_r(483_183_808, 6554, stab_fac);
        }
    }
    alpha
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::cnst::TCX_20_CORE;

    #[test]
    fn tcx_estimate_is_the_stability_ramp() {
        let mut gainp = 0;
        // first and second loss use the same base point at stab_fac 0
        assert_eq!(
            damping_fact(0, 1, 0, 0, &mut gainp, TCX_20_CORE),
            mac_r(751_619_264, 4915, 0)
        );
        assert_eq!(
            damping_fact(0, 2, 0, 0, &mut gainp, TCX_20_CORE),
            mac_r(483_183_808, 6554, 0)
        );
        assert_eq!(
            damping_fact(0, 5, 0, 32767, &mut gainp, TCX_20_CORE),
            mac_r(375_809_632, 6554, 32767)
        );
    }

    #[test]
    fn acelp_unvoiced_keeps_the_pitch_gain_untouched() {
        let mut gainp = 12345;
        let alpha = damping_fact(UNVOICED, 1, VOICED_CLAS - 3, 0, &mut gainp, ACELP_CORE);
        assert_eq!(alpha, mult_r(_ALPHA_UU_FX, 16384));
        assert_eq!(gainp, 12345);
    }

    #[test]
    fn acelp_voiced_first_loss_clamps_the_gain() {
        let mut gainp = 0;
        let alpha = damping_fact(GENERIC, 1, VOICED_CLAS, 0, &mut gainp, ACELP_CORE);
        // sqrt(0) rounds to 0, clamped up to 0.85
        assert_eq!(alpha, mult_r(mult_r(_ALPHA_V_FX, 16384), 27853));
    }
}
