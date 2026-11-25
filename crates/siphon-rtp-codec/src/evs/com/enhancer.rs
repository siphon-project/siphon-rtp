//! Excitation enhancer: phase dispersion and noise enhancement of the fixed-codebook contribution
//! (TS 26.442 `lib_com/enhancer_fx.c`; TS 26.445 §6.1.1.3).
//!
//! `enhancer_fx` is the MODE1 / AMR-WB IO path, `E_UTIL_enhancer` MODE2's.

use crate::evs::basop::{madd_32_16, mpy_32_16_1, mpy_32_32, mult_32_16};
use crate::evs::cnst::{L_FRAME16K, L_SUBFR, UNVOICED, VOICED};
use crate::evs::com::fft_rel::r_fft_fx_lc;
use crate::evs::com::math_op::isqrt;
use crate::evs::com::phase_dispersion::phase_dispersion as e_util_phase_dispersion;
use crate::evs::dec::state::DispMem;
use crate::evs::rom::{LOW_H_PHASEDISP, MID_H_PHASEDISP, PHS_TBL_DEC};
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_add, l_deposit_h, l_mac, l_msu, l_mult, l_shl, l_shr, l_sub, mult,
    mult_r, norm_l, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_msu0, l_mult0, mac_r, msu_r};

const SUBFR: usize = L_SUBFR as usize;

/// `enhancer_fx`: enhances the excitation `exc2[i_subfr..i_subfr + L_SUBFR]` with the
/// fixed-codebook vector `code` (Q12): phase dispersion of `code` (modified in place, the
/// dispersion memory in `dm_fx`), then a gain-smoothed, tilt-filtered code added into `exc2`.
/// `gc_threshold` carries the gain smoothing threshold between subframes.
pub fn enhancer(
    core_brate: i32,
    opt_amr_wb: i16,
    coder_type: i16,
    i_subfr: i16,
    l_frame: i16,
    voice_fac: i16,
    stab_fac: i16,
    mut norm_gain_code: i32,
    gain_inov: i16,
    gc_threshold: &mut i32,
    code: &mut [i16],
    exc2: &mut [i16],
    gain_pit: i16,
    dm_fx: &mut DispMem,
    q_exc: i16,
) {
    let mut excp = [0i16; SUBFR];
    let mut pit_sharp = gain_pit;
    let at = i_subfr.max(0) as usize;
    let pt_exc2 = &mut exc2[at..at + SUBFR];

    // Phase dispersion mode: 0 at the lowest rates, 1 at the next ones, 2 (none) otherwise.
    let mut i: i16 = 2;
    if opt_amr_wb != 0 {
        if l_sub(core_brate, 6600) <= 0 {
            i = 0;
        } else if l_sub(core_brate, 8850) <= 0 {
            i = 1;
        }
    } else if sub(coder_type, 1) != 0 {
        if l_sub(core_brate, 7200) <= 0 {
            i = 0;
        } else if (sub(coder_type, 3) == 0
            || sub(coder_type, 4) == 0
            || sub(coder_type, 5) == 0
            || sub(coder_type, 0) == 0)
            && l_sub(core_brate, 9600) <= 0
        {
            i = 1;
        }
    }
    phase_dispersion(norm_gain_code, gain_pit, code, i, dm_fx);

    // Noise enhancer: fac = 0.5·stab_fac·(1 - voice_fac), Q15
    let tmp = msu_r(0x4000_0000, voice_fac, 16384);
    let fac = mult(stab_fac, tmp);
    let mut l_tmp;
    if l_sub(norm_gain_code, *gc_threshold) < 0 {
        l_tmp = madd_32_16(norm_gain_code, norm_gain_code, 6226);
        l_tmp = l_tmp.min(*gc_threshold);
    } else {
        l_tmp = mult_32_16(norm_gain_code, 27536);
        l_tmp = l_tmp.max(*gc_threshold);
    }
    *gc_threshold = l_tmp;
    l_tmp = l_sub(l_tmp, norm_gain_code);
    norm_gain_code = madd_32_16(norm_gain_code, l_tmp, fac);

    l_tmp = mult_32_16(norm_gain_code, gain_inov);
    let sc: i16 = 6;
    let gain_code_hi = round_word(l_shl(l_tmp, add(q_exc, 3)));

    if opt_amr_wb == 0 && sub(coder_type, 1) == 0 {
        // Unvoiced: no tilt filtering.
        for i in 0..SUBFR {
            pt_exc2[i] = round_word(l_shl(l_mult(gain_code_hi, code[i]), sc));
        }
        return;
    }

    let amr_wb_low =
        opt_amr_wb != 0 && (l_sub(core_brate, 8850) == 0 || l_sub(core_brate, 6600) == 0);
    if amr_wb_low {
        pit_sharp = shl(gain_pit, 1);
        if sub(pit_sharp, 16384) > 0 {
            let tmp16 = mult(pit_sharp, 8192);
            for i in 0..SUBFR {
                excp[i] = mult_r(pt_exc2[i], tmp16);
            }
        }
    }

    let tmp = if sub(l_frame, 320) == 0 {
        mac_r(0x1000_0000, voice_fac, 4915)
    } else {
        mac_r(0x1000_0000, voice_fac, 4096)
    };

    // code_tilt = code - tmp·(code[-1] + code[+1]), added with the gain into exc2
    l_tmp = l_deposit_h(code[0]);
    l_tmp = l_msu(l_tmp, code[1], tmp);
    l_tmp = l_shl(l_mult(gain_code_hi, extract_h(l_tmp)), sc);
    pt_exc2[0] = msu_r(l_tmp, -32768, pt_exc2[0]);
    for i in 1..SUBFR - 1 {
        l_tmp = l_msu(-32768, code[i], -32768);
        l_tmp = l_msu(l_tmp, code[i + 1], tmp);
        let tmp16 = msu_r(l_tmp, code[i - 1], tmp);
        l_tmp = l_shl(l_mult(gain_code_hi, tmp16), sc);
        pt_exc2[i] = msu_r(l_tmp, -32768, pt_exc2[i]);
    }
    l_tmp = l_deposit_h(code[SUBFR - 1]);
    l_tmp = l_msu(l_tmp, code[SUBFR - 2], tmp);
    l_tmp = l_shl(l_mult(gain_code_hi, extract_h(l_tmp)), sc);
    pt_exc2[SUBFR - 1] = msu_r(l_tmp, -32768, pt_exc2[SUBFR - 1]);

    if amr_wb_low && sub(pit_sharp, 16384) > 0 {
        for i in 0..SUBFR {
            excp[i] = add(excp[i], pt_exc2[i]);
        }
        agc2(pt_exc2, &mut excp, L_SUBFR);
        pt_exc2.copy_from_slice(&excp);
    }
}

/// `phase_dispersion_fx`: post-processing that spreads the energy of a sparse code vector by a
/// circular convolution (in the frequency domain) with a low- or mid-dispersion impulse response,
/// chosen from the pitch gain history in `dm_fx` and the bit-rate dependent `mode`.
pub fn phase_dispersion(
    gain_code: i32,
    gain_pit: i16,
    code: &mut [i16],
    mode: i16,
    dm_fx: &mut DispMem,
) {
    let mut code2 = [0i16; 2 * SUBFR];

    let mut state: i16 = 2;
    if sub(gain_pit, 14746) < 0 {
        state = 1;
    }
    if sub(gain_pit, 9830) < 0 {
        state = 0;
    }
    for i in (1..6).rev() {
        dm_fx.prev_gain_pit[i] = dm_fx.prev_gain_pit[i - 1];
    }
    dm_fx.prev_gain_pit[0] = gain_pit;

    if l_sub(
        l_sub(gain_code, dm_fx.prev_gain_code),
        l_shl(dm_fx.prev_gain_code, 1),
    ) > 0
    {
        // onset
        state = add(state, 1).min(2);
    } else {
        let mut j: i16 = 0;
        for &gain in &dm_fx.prev_gain_pit[..6] {
            j = sub(j, shr(sub(gain, 9830), 15));
        }
        if sub(j, 2) > 0 {
            state = 0;
        }
        if sub(sub(state, dm_fx.prev_state), 1) > 0 {
            state = sub(state, 1);
        }
    }
    dm_fx.prev_gain_code = gain_code;
    dm_fx.prev_state = state;

    state = add(state, mode);
    if sub(state, 2) >= 0 {
        return;
    }
    r_fft_fx_lc(&PHS_TBL_DEC, 64, 32, 5, code, &mut code2, 1);
    let h: &[i16] = if state == 0 {
        &LOW_H_PHASEDISP
    } else {
        &MID_H_PHASEDISP
    };
    code[0] = mult(code2[0], h[0]);
    for i in 1..SUBFR / 2 {
        let im = SUBFR - i;
        code[i] = msu_r(l_mult(code2[i], h[i]), code2[im], h[im]);
        code[im] = mac_r(l_mult(code2[i], h[im]), code2[im], h[i]);
    }
    code[SUBFR / 2] = mult(code2[SUBFR / 2], h[SUBFR / 2]);
    r_fft_fx_lc(&PHS_TBL_DEC, 64, 32, 5, code, &mut code2, 0);
    for i in 0..SUBFR {
        code[i] = shl(code2[i], 1);
    }
}

/// `agc2_fx`: scales `sig_out` to the energy of `sig_in` (AMR-WB IO 6.6/8.85 kbit/s only).
// Index loops mirror the reference's pointer walks so the two can be diffed.
#[allow(clippy::needless_range_loop)]
fn agc2(sig_in: &[i16], sig_out: &mut [i16], l_trm: i16) {
    let l_trm = l_trm.max(1) as usize;
    let mut temp = shr(sig_out[0], 2);
    let mut s = l_mult0(temp, temp);
    for i in 1..l_trm {
        temp = shr(sig_out[i], 2);
        s = l_mac0(s, temp, temp);
    }
    if s == 0 {
        return;
    }
    let mut exp = sub(norm_l(s), 1);
    let gain_out = round_word(l_shl(s, exp));

    temp = shr(sig_in[0], 2);
    s = l_mult0(temp, temp);
    for i in 1..l_trm {
        temp = shr(sig_in[i], 2);
        s = l_mac0(s, temp, temp);
    }
    let mut g0: i16 = 0;
    if s != 0 {
        let i = norm_l(s);
        let gain_in = round_word(l_shl(s, i));
        exp = sub(exp, i);
        s = l_mult0(128, div_s(gain_out, gain_in));
        s = l_shr(s, exp);
        s = isqrt(s);
        g0 = round_word(l_shl(s, 9));
    }
    for i in 0..l_trm {
        sig_out[i] = round_word(l_shl(l_mac(-8192, sig_out[i], g0), 2));
    }
}

/// `E_UTIL_enhancer`: MODE2's enhancement of the excitation before synthesis. Phase dispersion of
/// the innovation `code` (Q9, exponent returned), the noise enhancer that moves its gain 1.5 dB
/// toward the threshold `gc_threshold` when the signal is noisy and the LP filter stable, and the
/// pitch enhancer (a smooth HP filtering of the code) added into `exc2`. Returns the exponent of
/// `code`. `prev_gain_code`, `prev_gain_pit` (6 values) and `prev_state` are the phase-dispersion
/// memory.
pub fn e_util_enhancer(
    voice_fac: i16,
    stab_fac: i16,
    gain_code: i32,
    gain_inov: i16,
    gc_threshold: &mut i32,
    code: &mut [i16],
    exc2: &mut [i16],
    gain_pit: i16,
    prev_gain_code: &mut i32,
    prev_gain_pit: &mut [i16],
    prev_state: &mut i16,
    coder_type: i16,
    cdk_index: i16,
    l_subfr: i16,
    l_frame: i16,
    q_new: i16,
) -> i16 {
    let mut code_exp: i16 = 15 - 9;
    let exc2_exp: i16 = 15 - q_new;
    let gain_inov = shr(gain_inov, 1);

    // Phase dispersion to enhance noise at low bit rates
    let mut max_cdk_index_uv: i16 = 10;
    if sub(l_frame, L_FRAME16K) == 0 {
        max_cdk_index_uv = 14;
    }
    let mut disp_mode: i16 = 2; // any=off
    if (sub(coder_type, VOICED) != 0 && sub(cdk_index, 2) <= 0)
        || (sub(coder_type, UNVOICED) == 0 && sub(cdk_index, max_cdk_index_uv) <= 0)
    {
        disp_mode = 0; // high
    } else if sub(coder_type, VOICED) != 0 && sub(cdk_index, 7) <= 0 {
        disp_mode = 1; // low
    }

    e_util_phase_dispersion(
        gain_code,
        gain_pit,
        code,
        &mut code_exp,
        disp_mode,
        prev_gain_code,
        prev_gain_pit,
        prev_state,
        l_subfr,
    );

    // noise enhancer: enhance excitation on noise (modify gain of code). If signal is noisy and
    // LPC filter is stable, move gain of code 1.5 dB toward gain of code threshold. This
    // decrease by 3 dB noise energy variation.
    let mut tmp = msu_r(1_073_741_824, 16384, voice_fac); // 1=unvoiced, 0=voiced
    let fac = mult_r(stab_fac, tmp); // fac in Q15

    let mut l_tmp = l_add(0, gain_code); // L_tmp in 15Q16

    if l_sub(l_tmp, *gc_threshold) < 0 {
        l_tmp = l_shl(mpy_32_32(l_tmp, 1_277_752_832), 1);
        l_tmp = l_tmp.min(*gc_threshold);
    } else {
        l_tmp = mpy_32_32(l_tmp, 1_804_608_000);
        l_tmp = l_tmp.max(*gc_threshold);
    }
    *gc_threshold = l_tmp; // in 15Q16

    // gain = ( (fac * L_tmp) + (gain_code - fac*gain_code) ) * gain_inov
    // exponent of L_tmp: 31-16 + 15-11
    l_tmp = mpy_32_16_1(
        l_add(
            mpy_32_16_1(l_tmp, fac),
            l_sub(gain_code, mpy_32_16_1(gain_code, fac)),
        ),
        gain_inov,
    );

    // exponent gain: 31-16 + 15-11 - tmp
    tmp = norm_l(l_tmp);

    // exponent of code: 31-16 + 15-11 - tmp + code_exp
    code_exp = sub(add(31 - 16 + 15 - 11, code_exp), tmp);

    l_tmp = l_shl(l_tmp, tmp);
    let mut gain = round_word(l_tmp);

    for value in code.iter_mut().take(l_subfr.max(0) as usize) {
        *value = mult_r(*value, gain);
    }

    // pitch enhancer: enhance excitation on voice (HP filtering of code). On voiced signal,
    // filtering of code by a smooth fir HP filter to decrease energy of code in low frequency.

    // exponent difference of code and exc2. +1 accounts for headroom required below.
    gain = add(sub(code_exp, exc2_exp), 1);

    tmp = mac_r(268_435_456, 4096, voice_fac); // 0.25=voiced, 0=unvoiced
    if sub(l_frame, L_FRAME16K) == 0 {
        tmp = mac_r(322_122_560, 4915, voice_fac); // 0.30=voiced, 0=unvoiced
    }

    // exc2[0] = exc2[0] + code[0] - tmp*code[1];
    l_tmp = l_mult(code[0], 16384);
    l_tmp = l_msu0(l_tmp, tmp, code[1]);
    if gain != 0 {
        l_tmp = l_shl(l_tmp, gain);
    }
    exc2[0] = msu_r(l_tmp, -32768, exc2[0]);

    let last = (l_subfr.max(1) - 1) as usize;
    for i in 1..last {
        // exc2[i] = exc2[i] + code[i] - tmp*(code[i+1]+code[i-1]);
        l_tmp = l_mult(code[i], 16384);
        l_tmp = l_msu0(l_tmp, tmp, code[i - 1]);
        l_tmp = l_msu0(l_tmp, tmp, code[i + 1]);
        if gain != 0 {
            l_tmp = l_shl(l_tmp, gain);
        }
        exc2[i] = msu_r(l_tmp, -32768, exc2[i]);
    }
    // exc2[L_subfr-1] = exc2[L_subfr-1] + code[L_subfr-1] - tmp*code[L_subfr-2];
    l_tmp = l_mult(code[last], 16384);
    l_tmp = l_msu0(l_tmp, tmp, code[last - 1]);
    if gain != 0 {
        l_tmp = l_shl(l_tmp, gain);
    }
    exc2[last] = msu_r(l_tmp, -32768, exc2[last]);

    code_exp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_code_leaves_the_excitation_and_reports_a_finite_exponent() {
        let mut code = [0i16; 64];
        let mut exc2 = [100i16; 64];
        let mut gc_threshold = 0;
        let mut prev_gain_code = 0;
        let mut prev_gain_pit = [0i16; 6];
        let mut prev_state = 0;
        let code_exp = e_util_enhancer(
            0,
            0,
            0,
            2048,
            &mut gc_threshold,
            &mut code,
            &mut exc2,
            0,
            &mut prev_gain_code,
            &mut prev_gain_pit,
            &mut prev_state,
            VOICED,
            9,
            64,
            256,
            5,
        );
        assert!(exc2.iter().all(|&value| value == 100));
        assert!(code_exp > -64 && code_exp < 64);
    }
}
