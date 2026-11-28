//! Envelope stability measure of the HQ core and its speech / music state smoothing (TS 26.442
//! `lib_com/env_stab_fx.c`; TS 26.445 §6.2.2.3 and the HQ frame-loss concealment, §6.2.4).

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    D_STAB_TBL_FX, HALF_D_STAB_TBL_FX, INV_STAB_TRANS_FX, L_STAB_TBL, M_STAB_TBL_FX,
    NUM_ENV_STAB_PLC_STATES,
};
use crate::evs::com::math_op::sqrt_l;
use crate::evs::com::tools::{dot_product, maximum};
use crate::evs::rom::{ENV_STAB_TP_FX, STAB_TRANS_FX};
use crate::itu::basic_ops::{
    abs_s, add, div_s, l_mac, l_mult, l_shl, mult_r, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0};

/// `ENV_STAB_SMO_HO`: number of hangover frames when switching from music to speech state.
const ENV_STAB_SMO_HO: i16 = 10;

/// `stab_trans_fx[index]`; `index` is a loop counter bounded by `L_STAB_TBL - 1`.
fn stab_trans(index: i16) -> i16 {
    STAB_TRANS_FX[usize::try_from(index)
        .unwrap_or(0)
        .min(STAB_TRANS_FX.len() - 1)]
}

/// `env_stability_fx`: envelope stability (Q15) of the norms `ynrm[0..nb_sfm]` against the
/// previous frame's `mem_norm`, which is updated; `mem_env_delta` (Q12) smooths the distance over
/// time.
pub fn env_stability(
    ynrm: &[i16],
    nb_sfm: i16,
    mem_norm: &mut [i16],
    mem_env_delta: &mut i16,
) -> i16 {
    // Calculate envelope stability parameter
    let mut l_env_delta: i32 = 0;
    for i in 0..nb_sfm.max(0) as usize {
        let tmp = sub(mem_norm[i], ynrm[i]);
        l_env_delta = l_mac0(l_env_delta, tmp, tmp);
        mem_norm[i] = ynrm[i];
    }

    let mut inv_nb_sfm: i16 = 19418; // Q19
    if nb_sfm == 26 {
        inv_nb_sfm = 20165; // Q19
    }
    let mut exp = norm_l(l_env_delta);
    l_env_delta = mult_32_16(l_shl(l_env_delta, exp), inv_nb_sfm); // 0+exp+19-15
    let mut exp2: i16 = 0;
    let mut l_tmp = sqrt_l(l_env_delta, &mut exp2); // exp+4+31+exp2
    exp = add(35, add(exp, exp2));
    if sub(exp & 1, 1) == 0 {
        l_tmp = mult_32_16(l_tmp, 23170); // 1/sqrt(2) in Q15
    }
    exp = shr(exp, 1);
    let env_delta_q10 = round_word(l_shl(l_tmp, sub(26, exp))); // Q10
    let mut l_tmp = l_mult0(26214, env_delta_q10); // 26214 is 0.1 in Q18. Q28
    l_tmp = l_mac(l_tmp, 29491, *mem_env_delta); // 29491 is 0.9 in Q15. Q28
    *mem_env_delta = round_word(l_tmp); // Q12

    // `Overflow = 0; env_delta = round_fx(L_shl(L_tmp, 1)); if (Overflow != 0)`: the flag is set
    // by L_shl saturating or by the rounding L_add(.., 0x8000) saturating.
    let doubled = i64::from(l_tmp) << 1;
    let overflow = doubled + 0x8000 > i64::from(i32::MAX) || doubled < i64::from(i32::MIN);
    let env_delta = round_word(l_shl(l_tmp, 1)); // Q13
    if overflow {
        // Saturated due to the above up-shifting operation.
        return stab_trans(sub(L_STAB_TBL, 1)); // The highest quantized index.
    }

    // If tmp_stab > (D_STAB_TBL*L_STAB_TBL + M_STAB_TBL), i.e., 0.103138*10+2.51757=3.603137,
    // the quantized index is equal to 9. Hence, we only need to worry about any tmpStab < 4.
    // In this case, Q13 is good enough.
    let mut tmp_stab = sub(env_delta, M_STAB_TBL_FX); // in Q13
    tmp_stab = abs_s(tmp_stab);

    // Table lookup for smooth transitions. First, find the quantization level, i, of tmpStab.
    tmp_stab = sub(tmp_stab, HALF_D_STAB_TBL_FX); // in Q13
    let mut i: i16 = 0;
    while i < L_STAB_TBL - 1 {
        if tmp_stab < 0 {
            break;
        }
        tmp_stab = sub(tmp_stab, D_STAB_TBL_FX); // in Q13
        i += 1;
    }

    let mut env_stab = stab_trans(i);
    if sub(env_delta, M_STAB_TBL_FX) < 0 {
        env_stab = sub(0x7FFF, stab_trans(i));
    }
    env_stab
}

/// `env_stab_smo_fx`: smooth the stability `env_stab` (Q15) into a speech (0) / music (1) state
/// with the two-state probabilities `env_stab_state_p` (Q15, updated) and a hangover counter
/// `ho_cnt` for the speech state. Returns the state.
pub fn env_stab_smo(env_stab: i16, env_stab_state_p: &mut [i16], ho_cnt: &mut i16) -> i16 {
    let states = NUM_ENV_STAB_PLC_STATES as usize;
    let mut maxval: i16 = 0;
    let mut pp = [0i16; NUM_ENV_STAB_PLC_STATES as usize];
    let mut pa = [0i16; NUM_ENV_STAB_PLC_STATES as usize];

    // get previous state
    let prev_state = maximum(env_stab_state_p, NUM_ENV_STAB_PLC_STATES, &mut maxval);

    // assume two states: speech(0), music(1)
    // set a posteriori likelihoods for the two states according to env_stab
    // re-scale. Unclear if needed
    let mut tmp = sub(env_stab, stab_trans(sub(L_STAB_TBL, 1)));
    tmp = round_word(l_shl(l_mult(tmp, INV_STAB_TRANS_FX), 1)); // Q15
    pp[0] = sub(32767, tmp); // 1 in Q15
    pp[1] = tmp;

    // calculate a priori likelihoods
    pa[0] = round_word(dot_product(
        &ENV_STAB_TP_FX[0],
        env_stab_state_p,
        NUM_ENV_STAB_PLC_STATES,
    )); // Q15
    pa[1] = round_word(dot_product(
        &ENV_STAB_TP_FX[1],
        env_stab_state_p,
        NUM_ENV_STAB_PLC_STATES,
    ));

    // multiply elementwise with a posteriori likelihoods
    let mut sum: i16 = 0;
    for i in 0..states {
        env_stab_state_p[i] = mult_r(pa[i], pp[i]); // Q15
        sum = add(sum, env_stab_state_p[i]);
    }

    // renormalize state probabilities
    let exp = norm_s(sum);
    let tmp = div_s(16384, shl(sum, exp)); // Q(14-exp)
    for slot in env_stab_state_p.iter_mut().take(states) {
        *slot = round_word(l_shl(l_mult(*slot, tmp), add(exp, 1))); // Q15
    }

    // find maximum index as return value
    let state = maximum(env_stab_state_p, NUM_ENV_STAB_PLC_STATES, &mut maxval);

    // apply some hangover for speech
    if state == 0 && sub(prev_state, 1) == 0 {
        *ho_cnt = ENV_STAB_SMO_HO;
    }
    if *ho_cnt > 0 {
        *ho_cnt = sub(*ho_cnt, 1);
    }
    state
}
