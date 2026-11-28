//! Excitation enhancer: phase dispersion and noise enhancement of the fixed-codebook contribution
//! (TS 26.442 `lib_com/enhancer_fx.c`; TS 26.445 §6.1.1.3).
//!
//! Only the MODE1 / AMR-WB IO path (`enhancer_fx`) is ported; `E_UTIL_enhancer` is MODE2's.

use crate::evs::basop::{madd_32_16, mult_32_16};
use crate::evs::cnst::L_SUBFR;
use crate::evs::com::fft_rel::r_fft_fx_lc;
use crate::evs::com::math_op::isqrt;
use crate::evs::dec::state::DispMem;
use crate::evs::rom::{LOW_H_PHASEDISP, MID_H_PHASEDISP, PHS_TBL_DEC};
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_deposit_h, l_mac, l_msu, l_mult, l_shl, l_shr, l_sub, mult, mult_r,
    norm_l, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0, mac_r, msu_r};

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
