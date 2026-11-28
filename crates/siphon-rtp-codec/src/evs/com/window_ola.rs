//! MDCT windowing and overlap-add for the HQ core, and the ACELP→HQ core-switching overlap
//! (TS 26.442 `lib_com/window_ola_fx.c`; TS 26.445 §6.2.4, §6.6.2).
//!
//! The reference walks its buffers with pointers that run backwards past the start of a window
//! once a loop has finished (`p3 -= decimate` after the last use); here every walking pointer is a
//! signed index into its buffer, converted only where it is read.

use crate::evs::basop::{mult_32_16, mult_32_32};
use crate::evs::cnst::{
    DELAY_CLDFB_NS, L_FRAME, L_FRAME16K, L_FRAME32K, L_FRAME48K, L_FRAME8K, N16_CORE_SW, NB, R1_16,
    R1_25, R1_48, R2_16, R2_25, R2_48, SWITCH_GAP_LENGTH_8K, SWITCH_MAX_GAP, SWITCH_OVERLAP_8K,
    WINDECAY16, WINDECAY48, WINDECAY48_256,
};
use crate::evs::com::basop_util::get_norm_reciprocal_word16;
use crate::evs::com::math_op::i_mult2;
use crate::evs::com::modif_fs::modify_fs_intcub3m_sup;
use crate::evs::com::tools::{find_max_norm16, find_max_norm32, scale_sig, scale_sig32};
use crate::evs::com::wtda::tcx_get_windows_mode1;
use crate::evs::macros::ns2sa;
use crate::evs::rom::{
    ONE_ON_WIN_48K_FX, ONE_ON_WIN_8K_16K_48K_FX, SIN_SWITCH_16, SIN_SWITCH_32, SIN_SWITCH_48,
    SIN_SWITCH_8,
};
use crate::itu::basic_ops::{
    abs_s, add, div_s, l_add, l_deposit_h, l_deposit_l, l_mult, l_negate, l_shl, l_sub, mult,
    mult_r, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mult0, mac_r};

/// `L_FRAME48k - NS2SA(48000, N_ZERO_MDCT_NS)`: the size of the BFI window buffers.
const BFI_WIN_LEN: usize = L_FRAME48K as usize - 270;
/// `HQ_DELAY_COMP * HQ_DELTA_MAX + 2`: the resampled-memory buffer of the core-switching overlap.
const SWITCH_BUF2_LEN: usize = 10 * 6 + 2;

/// A walking index converted for a read; the reference's tables keep it inside the buffer.
#[inline]
fn at(index: i32) -> usize {
    index as usize
}

/// `sinq_fx`: `x[i] = sin(tmp·i + phi)` for `i < n` (Q15), the first three samples from the
/// truncated Taylor series, the rest by the Chebyshev recursion `x[i] = 2cos(tmp)·x[i-1] - x[i-2]`.
pub fn sinq(tmp: i16, phi: i16, n: i16, x: &mut [i16]) {
    x[0] = phi; // sin(x) approximated by x; Q15
    let mut tmp1 = add(tmp, phi);
    let mut l_tmp = l_mult(tmp1, tmp1);
    l_tmp = mult_32_16(l_tmp, tmp1);
    l_tmp = mult_32_16(l_tmp, 5461); // division by 6
    let mut tmp2 = round_word(l_tmp);
    x[1] = sub(tmp1, tmp2); // sin(x) approximated by (x-x^3/3!); Q15
    tmp1 = add(shl(tmp, 1), phi);
    l_tmp = l_mult(tmp1, tmp1);
    l_tmp = mult_32_16(l_tmp, tmp1);
    l_tmp = mult_32_16(l_tmp, 5461);
    tmp2 = round_word(l_tmp);
    x[2] = sub(tmp1, tmp2);

    let a32 = if sub(abs_s(tmp), 3) > 0 {
        // A = (x[2]+x[0])/x[1] = 2*cos(tmp); here approximated by 2*(1-tmp^2/2!)
        let a32 = l_mult0(tmp, tmp); // Q30
        l_add(l_sub(1_073_741_824, a32), 1_073_741_824)
    } else {
        l_deposit_l(0)
    };

    let mut tmp_old = l_deposit_h(x[2]);
    let mut tmp_old_old = l_deposit_h(x[1]);
    for value in x.iter_mut().take(n.max(0) as usize).skip(3) {
        let mut l_tmp = mult_32_32(a32, tmp_old); // Q30
        l_tmp = l_sub(l_tmp, crate::itu::basic_ops::l_shr(tmp_old_old, 1));
        tmp_old_old = l_add(tmp_old, 0);
        tmp_old = l_shl(l_tmp, 1);
        *value = round_word(tmp_old);
    }
}

/// `window_ola_fx`: window the IMDCT output `wtda_audio[0..L]` (Q `q_sig`) and overlap-add it with
/// the previous frame's `old_au_out` (Q `q_old`) into `au_out[0..L]`, then keep the new aliased
/// half in `old_au_out`. The windows come from the overlap modes (`tcx_get_windows_mode1`).
/// `use_bfi_win` replaces the left half by the concealment's sine crossfade with the old output,
/// or (`old_hq_voicing`) with `oldgapsynth`. On return `q_sig` is the Q of `au_out` and equals
/// `q_old`.
pub fn window_ola(
    wtda_audio: &[i32],
    au_out: &mut [i16],
    q_sig: &mut i16,
    old_au_out: &mut [i16],
    q_old: &mut i16,
    l: i16,
    right_mode: i16,
    left_mode: i16,
    use_bfi_win: i16,
    old_hq_voicing: i16,
    oldgapsynth: Option<&mut [i16]>,
) {
    let mut win_right = [0i16; R2_48 as usize];
    let mut win_int_left = [0i16; R1_16 as usize];
    let mut win_left = [0i16; R1_48 as usize];
    let mut win_int_right = [0i16; R2_16 as usize];
    // for not to overwrite wtda_audio (ImdctOut) by the rescaling
    let mut imdct_out = [0i32; 2 * L_FRAME48K as usize];
    let mut ss2 = [0i16; BFI_WIN_LEN];
    let mut wret2 = [0i16; BFI_WIN_LEN];
    let lu = l.clamp(0, L_FRAME48K) as usize;

    // Windows loading
    tcx_get_windows_mode1(
        left_mode,
        right_mode,
        &mut win_left,
        &mut win_right,
        &mut win_int_left,
        &mut win_int_right,
        l,
    );

    let mut temp = find_max_norm16(old_au_out, l);
    scale_sig(old_au_out, l, temp); // Copy_Scale_sig in place
    *q_old = add(*q_old, temp);

    // need to rescale input (because ImdctOut not full scaled and cause issue in 16 bit
    // conversion); rescale to temp-1 because left shift after
    temp = sub(find_max_norm32(wtda_audio, l), 2);
    for i in 0..lu {
        imdct_out[i] = l_shl(wtda_audio[i], temp);
    }
    *q_sig = add(*q_sig, temp);

    // rescaling for overlapp add
    if sub(add(*q_old, 15), *q_sig) > 0 {
        scale_sig(old_au_out, l, sub(*q_sig, add(*q_old, 15)));
        *q_old = sub(*q_sig, 15);
    } else if sub(add(*q_old, 15), *q_sig) < 0 {
        scale_sig32(&mut imdct_out, l, sub(add(*q_old, 15), *q_sig));
        *q_sig = add(*q_old, 15);
    }

    *q_sig = *q_old; // fixing output to new Q_old

    let mut decimate: i16 = 1; // L_FRAME 48k
    let mut decay: i16 = 0;
    let mut windecay48 = WINDECAY48;
    let mut n: i16 = R1_48 - R2_48;

    if sub(l, L_FRAME32K) == 0 || sub(l, L_FRAME16K) == 0 {
        decimate = 3;
        decay = 1;
        n = R1_16 - R2_16;
        if sub(l, L_FRAME32K) == 0 {
            n = 2 * N16_CORE_SW;
        }
    } else if sub(l, L_FRAME8K) == 0 {
        decimate = 6;
        decay = 2;
        n = (R1_16 - R2_16) / 2;
    } else if sub(l, 512) == 0 {
        windecay48 = WINDECAY48_256;
        decimate = 1;
        decay = 0;
        n = R1_25 - R2_25;
    } else if sub(l, 256) == 0 {
        windecay48 = WINDECAY48_256;
        decimate = 2;
        decay = 0;
        n = (R1_25 - R2_25) / 2;
    }
    let (l32, n32, dec32) = (i32::from(l), i32::from(n), i32::from(decimate));
    let half = shr(l, 1);
    let half32 = i32::from(half);
    // paout = auOut - n: paout[k] is au_out[k - n]

    if sub(use_bfi_win, 1) == 0 {
        temp = sub(l, n);

        let mut tmp2 = div_s(1, temp); // Q15
        tmp2 = round_word(l_shl(l_mult(tmp2, 25736), 2)); // Q15

        sinq(shr(tmp2, 1), shr(tmp2, 2), temp, &mut ss2);
        let temp32 = i32::from(temp);

        if sub(l, L_FRAME32K) == 0 {
            let mut p4 = half32 - 1;
            let mut p1 = i32::from(sub(half, n));
            let mut p2 = i32::from(L_FRAME16K / 2 - 1);
            let mut p3 = i32::from((L_FRAME16K / 2 - 1) * 3 + 1);
            let mut i = 0;
            while i < half {
                wret2[at(p1)] = div_s(shr(ss2[at(p4)], 5), add(win_int_left[at(p2)], 10));
                p1 += 1;
                p4 -= 1;
                p2 -= 1;
                wret2[at(p1)] = div_s(shr(ss2[at(p4)], 5), add(win_left[at(p3)], 10)); // Wret2 Q10
                p1 += 1;
                p4 -= 1;
                p3 -= dec32;
                i += 2;
            }
            p4 = temp32 - 1;
            p1 = 0;
            let mut p2 = i32::from((L_FRAME16K - N16_CORE_SW) * 3 - 1 - 1);
            let mut p3 = i32::from(L_FRAME16K - N16_CORE_SW - 1);
            let temp_len = sub(half, n);
            let mut i = 0;
            while i < temp_len {
                wret2[at(p1)] = div_s(shr(ss2[at(p4)], 5), win_left[at(p2)]);
                p1 += 1;
                p4 -= 1;
                wret2[at(p1)] = div_s(shr(ss2[at(p4)], 5), win_int_left[at(p3)]);
                p1 += 1;
                p4 -= 1;
                p3 -= 1;
                p2 -= dec32;
                i += 2;
            }
        } else {
            let mut p2 = i32::from(add(i_mult2(sub(half, 1), decimate), decay));
            let mut p1 = i32::from(sub(half, n));
            let mut p4 = half32 - 1;
            for _ in 0..half {
                wret2[at(p1)] = div_s(shr(ss2[at(p4)], 5), add(win_left[at(p2)], 10)); // Wret2 Q10
                p1 += 1;
                p4 -= 1;
                p2 -= dec32;
            }

            p1 = 0;
            p4 = temp32 - 1;
            p2 = i32::from(sub(sub(i_mult2(sub(l, n), decimate), decay), 1));
            for _ in 0..sub(half, n) {
                wret2[at(p1)] = div_s(shr(ss2[at(p4)], 5), win_left[at(p2)]);
                p1 += 1;
                p4 -= 1;
                p2 -= dec32;
            }
        }

        // p1 = paout + n, i.e. au_out[0]
        let mut p1: usize = 0;
        let mut pa = half32 + n32;
        for _ in 0..sub(half, n) {
            au_out[p1] = round_word(l_shl(imdct_out[at(pa)], 1));
            p1 += 1;
            pa += 1;
        }

        pa = l32 - 1;
        for _ in 0..half {
            au_out[p1] = round_word(l_negate(l_shl(imdct_out[at(pa)], 1)));
            p1 += 1;
            pa -= 1;
        }

        let tempu = temp.max(0) as usize;
        let nu = n.max(0) as usize;
        match oldgapsynth {
            Some(oldgapsynth) if old_hq_voicing != 0 => {
                // rescale oldgapsynth
                scale_sig(oldgapsynth, l, *q_sig);
                for i in 0..tempu {
                    // auOut[i]*SS2[i] + oldgapsynth[i+n]*(SS2[L-n-i-1])
                    au_out[i] = add(
                        mult(au_out[i], ss2[i]),
                        mult(oldgapsynth[nu + i], ss2[tempu - 1 - i]),
                    );
                }
            }
            _ => {
                // a voiced concealment always passes oldgapsynth; without it the C would
                // dereference a null pointer, here the old output is used as without voicing
                for i in 0..tempu {
                    // auOut[i]*SS2[i] + OldauOut[i+n]*(SS2[L-n-i-1])/(wret2[i]+0.01f)
                    au_out[i] = add(
                        mult(au_out[i], ss2[i]),
                        shl(mult(old_au_out[nu + i], wret2[i]), 5),
                    );
                }
            }
        }
    }

    if sub(l, L_FRAME32K) == 0 {
        window_ola_32k(
            &imdct_out,
            au_out,
            old_au_out,
            l,
            n,
            decimate,
            use_bfi_win,
            &win_left,
            &win_right,
            &win_int_left,
            &win_int_right,
        );
    } else {
        if use_bfi_win == 0 {
            let mut p1: usize = 0; // paout + n
            let mut pa = half32 + n32;
            let mut p3 = i32::from(sub(
                sub(sub(i_mult2(sub(shl(l, 1), n), decimate), 1), decay),
                windecay48,
            ));
            let mut p4 = n.max(0) as usize;

            for _ in 0..sub(half, n) {
                au_out[p1] = round_word(l_add(
                    l_shl(mult_32_16(imdct_out[at(pa)], win_right[at(p3)]), 1),
                    l_deposit_h(old_au_out[p4]),
                ));
                p1 += 1;
                pa += 1;
                p4 += 1;
                p3 -= dec32;
            }

            pa = l32 - 1;
            p3 = i32::from(sub(
                add(i_mult2(sub(i_mult2(half, 3), 1), decimate), decay),
                windecay48,
            ));
            for _ in 0..sub(half, n) {
                au_out[p1] = round_word(l_sub(
                    l_deposit_h(old_au_out[p4]),
                    l_shl(mult_32_16(imdct_out[at(pa)], win_right[at(p3)]), 1),
                ));
                p1 += 1;
                p4 += 1;
                pa -= 1;
                p3 -= dec32;
            }
            for _ in 0..n {
                au_out[p1] = round_word(l_sub(
                    l_deposit_h(old_au_out[p4]),
                    l_shl(imdct_out[at(pa)], 1),
                ));
                p1 += 1;
                p4 += 1;
                pa -= 1;
            }
        }

        let mut p1 = half.max(0) as usize;
        let mut pa: i32 = 0;
        let mut p2 = i32::from(add(i_mult2(sub(half, 1), decimate), decay));
        for _ in 0..half {
            old_au_out[p1] = round_word(l_negate(l_shl(
                mult_32_16(imdct_out[at(pa)], win_left[at(p2)]),
                1,
            )));
            p1 += 1;
            pa += 1;
            p2 -= dec32;
        }

        p1 = n.max(0) as usize;
        pa = half32 - 1 - n32;
        p2 = i32::from(sub(sub(i_mult2(sub(l, n), decimate), decay), 1));
        for _ in 0..sub(half, n) {
            old_au_out[p1] = round_word(l_negate(l_shl(
                mult_32_16(imdct_out[at(pa)], win_left[at(p2)]),
                1,
            )));
            p1 += 1;
            pa -= 1;
            p2 -= dec32;
        }
    }

    let mut pa = half32 - 1;
    let tail = at(l32 - n32); // paout + L
    for i in 0..n.max(0) as usize {
        old_au_out[i] = round_word(l_negate(l_shl(imdct_out[at(pa)], 1)));
        au_out[tail + i] = old_au_out[i];
        pa -= 1;
    }
}

/// The 32 kHz overlap-add of [`window_ola`]: the 48 kHz window (decimated by 3) and the 16 kHz
/// "int" window interleaved sample by sample.
fn window_ola_32k(
    imdct_out: &[i32],
    au_out: &mut [i16],
    old_au_out: &mut [i16],
    l: i16,
    n: i16,
    decimate: i16,
    use_bfi_win: i16,
    win_left: &[i16],
    win_right: &[i16],
    win_int_left: &[i16],
    win_int_right: &[i16],
) {
    let dec32 = i32::from(decimate);
    let half = shr(l, 1);
    let half32 = i32::from(half);
    let n32 = i32::from(n);
    if use_bfi_win == 0 {
        // decimate=3, decay=1
        let mut p1: usize = 0; // paout + n
        let mut pa = half32 + n32;
        let mut p3 = i32::from((2 * L_FRAME16K - N16_CORE_SW) * 3 - 1 - 1 - WINDECAY48);
        let mut p5 = i32::from((2 * L_FRAME16K - N16_CORE_SW) - 1 - WINDECAY16);
        let mut p4 = n.max(0) as usize;

        let temp_len = sub(half, n);
        let mut i = 0;
        while i < temp_len {
            au_out[p1] = round_word(l_add(
                l_shl(mult_32_16(imdct_out[at(pa)], win_right[at(p3)]), 1),
                l_deposit_h(old_au_out[p4]),
            ));
            p1 += 1;
            pa += 1;
            p4 += 1;
            p3 -= dec32;
            au_out[p1] = round_word(l_add(
                l_shl(mult_32_16(imdct_out[at(pa)], win_int_right[at(p5)]), 1),
                l_deposit_h(old_au_out[p4]),
            ));
            p1 += 1;
            pa += 1;
            p4 += 1;
            p5 -= 1;
            i += 2;
        }

        pa = i32::from(l) - 1;
        p3 = i32::from((3 * L_FRAME16K / 2 - 1) * 3 + 1 - WINDECAY48);
        p5 = i32::from((3 * L_FRAME16K / 2) - 1 - WINDECAY16);

        let mut i = 0;
        while i < temp_len {
            au_out[p1] = round_word(l_sub(
                l_deposit_h(old_au_out[p4]),
                l_shl(mult_32_16(imdct_out[at(pa)], win_int_right[at(p5)]), 1),
            ));
            p1 += 1;
            p4 += 1;
            pa -= 1;
            p5 -= 1;
            au_out[p1] = round_word(l_sub(
                l_deposit_h(old_au_out[p4]),
                l_shl(mult_32_16(imdct_out[at(pa)], win_right[at(p3)]), 1),
            ));
            p1 += 1;
            p4 += 1;
            pa -= 1;
            p3 -= dec32;
            i += 2;
        }
        let mut i = 0;
        while i < n {
            for _ in 0..2 {
                au_out[p1] = round_word(l_sub(
                    l_deposit_h(old_au_out[p4]),
                    l_shl(imdct_out[at(pa)], 1),
                ));
                p1 += 1;
                p4 += 1;
                pa -= 1;
            }
            i += 2;
        }
    }

    let mut p1 = half.max(0) as usize;
    let mut pa: i32 = 0;
    let mut p2 = i32::from(L_FRAME16K / 2 - 1);
    let mut p3 = i32::from((L_FRAME16K / 2 - 1) * 3 + 1);

    let mut i = 0;
    while i < half {
        old_au_out[p1] = round_word(l_negate(l_shl(
            mult_32_16(imdct_out[at(pa)], win_int_left[at(p2)]),
            1,
        )));
        p1 += 1;
        pa += 1;
        p2 -= 1;
        old_au_out[p1] = round_word(l_negate(l_shl(
            mult_32_16(imdct_out[at(pa)], win_left[at(p3)]),
            1,
        )));
        p1 += 1;
        pa += 1;
        p3 -= dec32;
        i += 2;
    }

    p1 = n.max(0) as usize;
    pa = half32 - 1 - n32;
    p2 = i32::from((L_FRAME16K - N16_CORE_SW) * 3 - 1 - 1);
    p3 = i32::from(L_FRAME16K - N16_CORE_SW - 1);
    let temp_len = sub(half, n);
    let mut i = 0;
    while i < temp_len {
        old_au_out[p1] = round_word(l_negate(l_shl(
            mult_32_16(imdct_out[at(pa)], win_left[at(p2)]),
            1,
        )));
        p1 += 1;
        pa -= 1;
        old_au_out[p1] = round_word(l_negate(l_shl(
            mult_32_16(imdct_out[at(pa)], win_int_left[at(p3)]),
            1,
        )));
        p1 += 1;
        pa -= 1;
        p3 -= 1;
        p2 -= dec32;
        i += 2;
    }
}

/// `core_switching_OLA_fx`: after an ACELP→HQ switch, cross-fade the HQ synthesis `synth`
/// (Q `qsynth`) with the ACELP subframe `synth_subfr_out` (Q `qsubfr`, `SWITCH_MAX_GAP` samples) and
/// its BWE `synth_subfr_bwe`, the CLDFB-delay part of the ACELP side resampled from the
/// upsampling memory `mem_over_hp` (`NS2SA(16000, DELAY_CLDFB_NS) + 2` samples) when the output
/// rate differs. Both signals are first brought to the lower of the two Qs.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
pub fn core_switching_ola(
    mem_over_hp: &mut [i16],
    last_l_frame: i16,
    output_fs: i32,
    synth: &mut [i16],
    synth_subfr_out: &mut [i16],
    synth_subfr_bwe: &mut [i16],
    output_frame: i16,
    bwidth: i16,
    qsynth: &mut i16,
    qsubfr: &mut i16,
) {
    let mut tmp_buf_switch = [0i16; SWITCH_MAX_GAP as usize];
    let mut tmp_buf_switch2 = [0i16; SWITCH_BUF2_LEN];

    // Scaling (if needed)
    let mut tmp = (*qsynth).min(*qsubfr);
    scale_sig(synth, output_frame, sub(tmp, *qsynth));
    *qsynth = tmp;
    scale_sig(synth_subfr_out, SWITCH_MAX_GAP, sub(tmp, *qsubfr));
    // reScale mem over HP at Qsynth
    scale_sig(
        mem_over_hp,
        ns2sa(16000, DELAY_CLDFB_NS) + 2,
        sub(tmp, *qsubfr),
    );
    *qsubfr = tmp;

    let on_win: &[i16] = &ONE_ON_WIN_48K_FX;
    let on_win_int: &[i16] = &ONE_ON_WIN_8K_16K_48K_FX;

    let (decimate, delta, pt_sin): (i16, i16, &[i16]) = match output_frame {
        L_FRAME8K => (6, 1, &SIN_SWITCH_8),
        L_FRAME16K => (3, 2, &SIN_SWITCH_16),
        L_FRAME32K => (3, 4, &SIN_SWITCH_32),
        L_FRAME48K => (1, 6, &SIN_SWITCH_48),
        // the C leaves pt_sin NULL and crashes on it below; no output rate takes this
        _ => return,
    };

    let loverlapp = i_mult2(delta, SWITCH_OVERLAP_8K);
    let gap = i_mult2(SWITCH_GAP_LENGTH_8K, delta);
    let gap_us = gap.max(0) as usize;

    // copy 6.25 ms subframe
    tmp_buf_switch[..gap_us].copy_from_slice(&synth_subfr_out[..gap_us]);

    // conversion from 12.8kHz to output_Fs
    if sub(last_l_frame, L_FRAME) == 0 {
        // resample filter memory
        if sub(output_frame, L_FRAME8K) == 0 {
            core_switching_ola_copy_8k(synth_subfr_out, &mut tmp_buf_switch, output_fs);
        } else {
            core_switching_ola_resample(
                mem_over_hp,
                12800,
                output_fs,
                bwidth,
                gap_us,
                synth_subfr_out,
                &mut tmp_buf_switch,
                &mut tmp_buf_switch2,
            );
        }
    } else if (output_frame - L_FRAME16K) == 0 {
        // no resampling
        let len = ns2sa(output_fs, DELAY_CLDFB_NS).max(0) as usize;
        tmp_buf_switch[gap_us..gap_us + len].copy_from_slice(&mem_over_hp[2..2 + len]);
    } else if (output_frame - L_FRAME8K) == 0 {
        // not done yet
        core_switching_ola_copy_8k(synth_subfr_out, &mut tmp_buf_switch, output_fs);
    } else {
        core_switching_ola_resample(
            mem_over_hp,
            16000,
            output_fs,
            bwidth,
            gap_us,
            synth_subfr_out,
            &mut tmp_buf_switch,
            &mut tmp_buf_switch2,
        );
    }

    // compensate aldo; 6.25 ms gap + 1.25 ms resamp
    let l = i_mult2(delta, SWITCH_GAP_LENGTH_8K + ns2sa(8000, DELAY_CLDFB_NS));
    tmp = sub(l, loverlapp);
    let tmp_us = tmp.max(0) as usize;

    synth[..tmp_us].fill(0);

    if sub(output_frame, L_FRAME32K) == 0 {
        let mut pt = tmp_us;
        let mut pt5: i32 = 210 - 1;
        let mut pt4: i32 = 70 - 1;
        let temp_len = i_mult2(shr(R2_16, 2), delta);
        let mut i = 0;
        while i < temp_len {
            // Q14 * Q15 + shl ==> Q15
            synth[pt] = shl(mult_r(synth[pt], on_win[at(pt5)]), 1);
            synth[pt + 1] = shl(mult_r(synth[pt + 1], on_win_int[at(pt4)]), 1);
            pt += 2;
            pt5 -= 3;
            pt4 -= 1;
            i += 2;
        }
    } else {
        let mut pt = tmp_us;
        let mut pt5: i32 = 210 - 1;
        let temp_len = i_mult2(shr(R2_16, 2), delta);
        for _ in 0..temp_len {
            synth[pt] = shl(mult_r(synth[pt], on_win[at(pt5)]), 1);
            pt += 1;
            pt5 -= i32::from(decimate);
        }
    }

    let delay = ns2sa(output_fs, DELAY_CLDFB_NS);
    let mut pt = tmp_us;
    let mut pt2 = at(i32::from(tmp) - i32::from(delay));
    let mut pt3 = tmp_us;
    let mut pt_cos = at(i32::from(loverlapp) - 1);
    // Windowing for overlapadd
    for &sin in pt_sin.iter().take(loverlapp.max(0) as usize) {
        synth[pt] = mult_r(synth[pt], sin);
        let tmp2 = mult_r(pt_sin[pt_cos], pt_sin[pt_cos]);
        pt_cos = pt_cos.wrapping_sub(1);
        synth_subfr_bwe[pt2] = mult_r(synth_subfr_bwe[pt2], tmp2);
        tmp_buf_switch[pt3] = mult_r(tmp_buf_switch[pt3], tmp2);
        pt += 1;
        pt2 += 1;
        pt3 += 1;
    }

    // overlapadd ACELP (tmp_buf_switch) + HQ (synth)
    let delay_us = delay.max(0) as usize;
    for i in 0..delay_us {
        synth[i] = add(synth[i], tmp_buf_switch[i]);
    }
    for i in 0..sub(l, delay).max(0) as usize {
        synth[delay_us + i] = add(
            add(synth[delay_us + i], tmp_buf_switch[delay_us + i]),
            synth_subfr_bwe[i],
        );
    }
}

/// At 8 kHz output the CLDFB-delay part of the ACELP side comes straight from the subframe.
fn core_switching_ola_copy_8k(synth_subfr_out: &[i16], tmp_buf_switch: &mut [i16], output_fs: i32) {
    let from = SWITCH_GAP_LENGTH_8K as usize;
    let len = ns2sa(output_fs, DELAY_CLDFB_NS).max(0) as usize;
    tmp_buf_switch[from..from + len].copy_from_slice(&synth_subfr_out[from..from + len]);
}

/// Above 8 kHz the CLDFB-delay part is the upsampling memory resampled by cubic interpolation
/// from `fin`, cross-faded into the CLDFB-resampled subframe when the output is wider band.
fn core_switching_ola_resample(
    mem_over_hp: &[i16],
    fin: i32,
    output_fs: i32,
    bwidth: i16,
    buf_offset: usize,
    synth_subfr_out: &[i16],
    tmp_buf_switch: &mut [i16],
    tmp_buf_switch2: &mut [i16],
) {
    let mut filt_delay: i16 = 0;
    let out_filt_length = modify_fs_intcub3m_sup(
        mem_over_hp,
        2,
        ns2sa(fin, DELAY_CLDFB_NS),
        fin,
        tmp_buf_switch2,
        output_fs,
        &mut filt_delay,
    );
    let pt = at(i32::from(sub(out_filt_length, filt_delay)));
    let fill = tmp_buf_switch2[pt.wrapping_sub(1)];
    for value in tmp_buf_switch2
        .iter_mut()
        .skip(pt)
        .take(filt_delay.max(0) as usize)
    {
        *value = fill;
    }

    let ofl = out_filt_length.max(0) as usize;
    if (sub(bwidth, NB) == 0 && output_fs >= 16000) || (sub(bwidth, NB) > 0 && output_fs > 16000) {
        // mix cubic and CLDFB resampled buffers in case of resampling to higher frequency rates
        let divisor = get_norm_reciprocal_word16(out_filt_length);
        for i in 0..ofl {
            let a = i_mult2(i as i16, divisor);
            let b = sub(32767, a);

            let l_tmp = l_mult(a, tmp_buf_switch2[i]);
            tmp_buf_switch[buf_offset + i] = mac_r(l_tmp, b, synth_subfr_out[buf_offset + i]);
        }
    } else {
        // copy cubic resampled buffer (memory)
        tmp_buf_switch[buf_offset..buf_offset + ofl].copy_from_slice(&tmp_buf_switch2[..ofl]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sinq_starts_at_the_phase() {
        let mut x = [0i16; 16];
        sinq(1000, 500, 16, &mut x);
        assert_eq!(x[0], 500);
        assert!(x[1] > x[0] && x[2] > x[1]);
    }
}
