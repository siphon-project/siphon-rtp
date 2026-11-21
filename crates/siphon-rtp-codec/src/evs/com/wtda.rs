//! Windowing and time-domain aliasing (the MDCT's TDA) for the HQ / MDCT path
//! (TS 26.442 `lib_com/wtda_fx.c`; TS 26.445 §5.3.2.2).

use crate::evs::com::tools::scale_sig;
use crate::evs::rom::{
    HALF_OVERLAP_25, HALF_OVERLAP_48, HALF_OVERLAP_INT, SMALL_OVERLAP_25, SMALL_OVERLAP_48,
    SMALL_OVERLAP_INT, WINDOW_256KHZ, WINDOW_48KHZ_FX, WINDOW_8_16_32KHZ_FX,
};
use crate::itu::basic_ops::{add, l_deposit_h, l_mult, l_negate, l_shr, negate, shr, sub};
use crate::itu::stl2009::{l_mac0, l_msu0, l_mult0};

/// `N_ZERO_MDCT_NS` at 32 kHz (`NS2SA(32000, N_ZERO_MDCT_NS)`).
const N_ZERO_MDCT_NS_32K: i16 = 90;
/// `L_MDCT_OVLP_MAX`.
const L_MDCT_OVLP_MAX: usize = 690;
/// `L_ALDO_WIN1_FB_MAX`, `L_ALDO_WIN2_FB_MAX` (the ALDO window halves at 48 kHz).
const ALDO_WIN1_48K: usize = 690;
const ALDO_WIN2_48K: usize = 420;
/// The same at 25.6 kHz and at the 16 kHz "int" rate.
const ALDO_WIN1_25K: usize = 368;
const ALDO_WIN2_25K: usize = 224;
const ALDO_WIN1_INT: usize = 230;
const ALDO_WIN2_INT: usize = 140;

/// `mvs2s_inv`: copy `l` samples of `input`, decimated by `decimate` from the middle of each
/// group, into `out` in reverse order.
fn mvs2s_inv(input: &[i16], out: &mut [i16], l: usize, decimate: i16) {
    let mut at = shr(sub(decimate, 1), 1) as usize;
    let step = decimate as usize;
    for i in 0..l {
        out[l - 1 - i] = input[at];
        at += step;
    }
}

/// `mvs2s_dec`: copy `l` samples of `input`, decimated by `decimate`, into `out` in order.
fn mvs2s_dec(input: &[i16], out: &mut [i16], l: usize, decimate: i16) {
    let mut at = shr(sub(decimate, 1), 1) as usize;
    let step = decimate as usize;
    for item in out.iter_mut().take(l) {
        *item = input[at];
        at += step;
    }
}

/// `copy_win`: builds a window of `nb_zero` zeros, `win_lenght` samples of `in_win` and
/// `nb_one` ones; a negative `decimate` builds it mirrored (ones, reversed slope, zeros).
fn copy_win(
    out_win: &mut [i16],
    nb_zero: usize,
    in_win: &[i16],
    win_lenght: usize,
    nb_one: usize,
    decimate: i16,
) {
    if decimate < 0 {
        out_win[..nb_one].fill(32767);
        mvs2s_inv(in_win, &mut out_win[nb_one..], win_lenght, negate(decimate));
        out_win[win_lenght + nb_one..win_lenght + nb_one + nb_zero].fill(0);
    } else {
        out_win[..nb_zero].fill(0);
        mvs2s_dec(in_win, &mut out_win[nb_zero..], win_lenght, decimate);
        out_win[nb_zero + win_lenght..nb_zero + win_lenght + nb_one].fill(32767);
    }
}

/// `tcx_get_windows_mode1`: the left and right MDCT windows for overlap modes `left_mode` /
/// `right_mode` (2 = small, 3 = half, 4 = full ALDO; others leave the window untouched), at the
/// frame length `L`. For `L` of 256 or 512 (the 25.6 kHz rates) only `left_win` / `right_win` are
/// written; otherwise the 48 kHz window and the 16 kHz-rate "int" window both are.
///
/// Sizes: `left_win` 690, `right_win` 420, `left_win_int` 230, `right_win_int` 140.
pub fn tcx_get_windows_mode1(
    left_mode: i16,
    right_mode: i16,
    left_win: &mut [i16],
    right_win: &mut [i16],
    left_win_int: &mut [i16],
    right_win_int: &mut [i16],
    l: i16,
) {
    let r25 = sub(l, 256) == 0 || sub(l, 512) == 0;
    // Left part
    if sub(left_mode, 2) == 0 {
        if r25 {
            copy_win(
                left_win,
                ALDO_WIN1_25K - 4 * ALDO_WIN2_25K / 7,
                &SMALL_OVERLAP_25,
                ALDO_WIN2_25K / 7,
                3 * ALDO_WIN2_25K / 7,
                1,
            );
        } else {
            copy_win(
                left_win,
                ALDO_WIN1_48K - 4 * ALDO_WIN2_48K / 7,
                &SMALL_OVERLAP_48,
                ALDO_WIN2_48K / 7,
                3 * ALDO_WIN2_48K / 7,
                1,
            );
            copy_win(
                left_win_int,
                ALDO_WIN1_INT - 4 * ALDO_WIN2_INT / 7,
                &SMALL_OVERLAP_INT,
                ALDO_WIN2_INT / 7,
                3 * ALDO_WIN2_INT / 7,
                1,
            );
        }
    } else if sub(left_mode, 3) == 0 {
        if r25 {
            copy_win(
                left_win,
                ALDO_WIN1_25K - 5 * ALDO_WIN2_25K / 7,
                &HALF_OVERLAP_25,
                3 * ALDO_WIN2_25K / 7,
                2 * ALDO_WIN2_25K / 7,
                1,
            );
        } else {
            copy_win(
                left_win,
                ALDO_WIN1_48K - 5 * ALDO_WIN2_48K / 7,
                &HALF_OVERLAP_48,
                3 * ALDO_WIN2_48K / 7,
                2 * ALDO_WIN2_48K / 7,
                1,
            );
            copy_win(
                left_win_int,
                ALDO_WIN1_INT - 5 * ALDO_WIN2_INT / 7,
                &HALF_OVERLAP_INT,
                3 * ALDO_WIN2_INT / 7,
                2 * ALDO_WIN2_INT / 7,
                1,
            );
        }
    } else if sub(left_mode, 4) == 0 {
        if r25 {
            left_win[..ALDO_WIN1_25K].copy_from_slice(&WINDOW_256KHZ[..ALDO_WIN1_25K]);
        } else {
            left_win[..ALDO_WIN1_48K].copy_from_slice(&WINDOW_48KHZ_FX[..ALDO_WIN1_48K]);
            left_win_int[..ALDO_WIN1_INT].copy_from_slice(&WINDOW_8_16_32KHZ_FX[..ALDO_WIN1_INT]);
        }
    }
    // Right part
    if sub(right_mode, 2) == 0 || sub(right_mode, -2) == 0 {
        if r25 {
            copy_win(
                right_win,
                3 * ALDO_WIN2_25K / 7,
                &SMALL_OVERLAP_25,
                ALDO_WIN2_25K / 7,
                3 * ALDO_WIN2_25K / 7,
                -1,
            );
        } else {
            copy_win(
                right_win,
                3 * ALDO_WIN2_48K / 7,
                &SMALL_OVERLAP_48,
                ALDO_WIN2_48K / 7,
                3 * ALDO_WIN2_48K / 7,
                -1,
            );
            copy_win(
                right_win_int,
                3 * ALDO_WIN2_INT / 7,
                &SMALL_OVERLAP_INT,
                ALDO_WIN2_INT / 7,
                3 * ALDO_WIN2_INT / 7,
                -1,
            );
        }
    } else if sub(right_mode, 3) == 0 {
        if r25 {
            copy_win(
                right_win,
                2 * ALDO_WIN2_25K / 7,
                &HALF_OVERLAP_25,
                3 * ALDO_WIN2_25K / 7,
                2 * ALDO_WIN2_25K / 7,
                -1,
            );
        } else {
            copy_win(
                right_win,
                2 * ALDO_WIN2_48K / 7,
                &HALF_OVERLAP_48,
                3 * ALDO_WIN2_48K / 7,
                2 * ALDO_WIN2_48K / 7,
                -1,
            );
            copy_win(
                right_win_int,
                2 * ALDO_WIN2_INT / 7,
                &HALF_OVERLAP_INT,
                3 * ALDO_WIN2_INT / 7,
                2 * ALDO_WIN2_INT / 7,
                -1,
            );
        }
    } else if sub(right_mode, 4) == 0 {
        if r25 {
            right_win[..ALDO_WIN2_25K]
                .copy_from_slice(&WINDOW_256KHZ[ALDO_WIN1_25K..ALDO_WIN1_25K + ALDO_WIN2_25K]);
        } else {
            right_win[..ALDO_WIN2_48K]
                .copy_from_slice(&WINDOW_48KHZ_FX[ALDO_WIN1_48K..ALDO_WIN1_48K + ALDO_WIN2_48K]);
            right_win_int[..ALDO_WIN2_INT].copy_from_slice(
                &WINDOW_8_16_32KHZ_FX[ALDO_WIN1_INT..ALDO_WIN1_INT + ALDO_WIN2_INT],
            );
        }
    }
}

/// `wtda_fx`: windowing and time-domain aliasing of one frame of `L` samples into `L` MDCT input
/// values `wtda_audio` (Q of `new_audio` + 15, written back to `q`).
///
/// `new_audio` is the whole buffer and `new_audio_at` the index the C pointer points at: without
/// an `old_wtda` the reference reads `L - n` samples *before* that pointer (`n` = 270, 90, 180 or
/// 45 by rate). `old_wtda`, when given, holds the previous frame (`q_old_wtda` its Q; unused
/// without `old_wtda`, as in the reference); the lower Q of the two is applied to both, then the
/// current frame is saved into it.
///
/// `L` is one of 160, 320, 640 or 960, the output frame lengths the decoder calls it with; the
/// reference's pointer arithmetic is undefined for any other, and this returns without writing.
pub fn wtda(
    new_audio: &mut [i16],
    new_audio_at: usize,
    q: &mut i16,
    wtda_audio: &mut [i32],
    old_wtda: Option<&mut [i16]>,
    q_old_wtda: &mut i16,
    left_mode: i16,
    right_mode: i16,
    l: i16,
) {
    let mut win_right = [0i16; ALDO_WIN2_48K];
    let mut win_int_left = [0i16; ALDO_WIN1_INT];
    let mut win_left = [0i16; ALDO_WIN1_48K];
    let mut win_int_right = [0i16; ALDO_WIN2_INT];

    if !matches!(l, 160 | 320 | 640 | 960) {
        return;
    }
    tcx_get_windows_mode1(
        left_mode,
        right_mode,
        &mut win_left,
        &mut win_right,
        &mut win_int_left,
        &mut win_int_right,
        l,
    );

    let mut decimate: i16 = 1;
    let mut decay: i16 = 0;
    let mut n: i16 = (L_MDCT_OVLP_MAX - ALDO_WIN2_48K) as i16;
    if sub(l, 640) == 0 || sub(l, 320) == 0 {
        decimate = 3;
        decay = 1;
        n = (ALDO_WIN1_INT - ALDO_WIN2_INT) as i16;
        if sub(l, 640) == 0 {
            n = 2 * N_ZERO_MDCT_NS_32K;
        }
    } else if sub(l, 160) == 0 {
        decimate = 6;
        decay = 2;
        n = ((ALDO_WIN1_INT - ALDO_WIN2_INT) / 2) as i16;
    }
    let windows = Windows {
        left: &win_left,
        right: &win_right,
        int_left: &win_int_left,
        int_right: &win_int_right,
    };
    let lu = l as usize;
    let nu = n as usize;

    match old_wtda {
        None => {
            // allsig_l = new_audio + n - L
            let Some(lb) = (new_audio_at + nu).checked_sub(lu) else {
                return;
            };
            let new: &[i16] = new_audio;
            wtda_window(
                new,
                new_audio_at,
                new,
                lb,
                &windows,
                wtda_audio,
                decimate,
                decay,
                n,
                l,
            );
        }
        Some(old_wtda) => {
            if sub(*q_old_wtda, *q) > 0 {
                scale_sig(old_wtda, l, sub(*q, *q_old_wtda));
                *q_old_wtda = *q;
            } else if sub(*q_old_wtda, *q) < 0 {
                scale_sig(&mut new_audio[new_audio_at..], l, sub(*q_old_wtda, *q));
                *q = *q_old_wtda;
            }
            // allsig_l = old_wtda + n
            wtda_window(
                new_audio,
                new_audio_at,
                old_wtda,
                nu,
                &windows,
                wtda_audio,
                decimate,
                decay,
                n,
                l,
            );
            old_wtda[..lu].copy_from_slice(&new_audio[new_audio_at..new_audio_at + lu]);
        }
    }
    *q = add(*q, 15);
}

/// The four windows `tcx_get_windows_mode1` built for one frame.
struct Windows<'a> {
    left: &'a [i16],
    right: &'a [i16],
    int_left: &'a [i16],
    int_right: &'a [i16],
}

/// The windowing and folding of `wtda_fx`. `new` / `at` is `new_audio`, `left` / `lb` is
/// `allsig_l`; `allsig_r` is `new_audio + n`.
// Index loops mirror the reference's pointer walks so the two can be diffed.
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
fn wtda_window(
    new: &[i16],
    at: usize,
    left: &[i16],
    lb: usize,
    win: &Windows<'_>,
    out: &mut [i32],
    decimate: i16,
    decay: i16,
    n: i16,
    l: i16,
) {
    let r = at + n as usize;
    let nu = n as usize;
    let lu = l as usize;
    let dec = decimate as usize;
    let mut pa = 0;
    if lu == 640 {
        // 32 kHz: the 48 kHz window decimated by 3, interleaved with the 16 kHz-rate window.
        let mut p1 = r + 320 - 1;
        let mut p2 = 3 * 320 / 2 - 1 - 410;
        let mut p3 = p1 + 1;
        let mut p4 = p2 + 1;
        let mut p5 = (3 * 320 / 2 - 1) * 3 + 1 - 1230;
        let mut p6 = (3 * 320 / 2 + 1) * 3 - 1 - 1 - 1230;
        for _ in (0..320 - 2 * 90).step_by(2) {
            out[pa] = l_negate(l_mac0(
                l_mult0(new[p1], win.int_right[p2]),
                new[p3],
                win.int_right[p4],
            ));
            pa += 1;
            p1 = p1.wrapping_sub(1);
            p2 = p2.wrapping_sub(1);
            p3 += 1;
            p4 += 1;
            out[pa] = l_negate(l_mac0(
                l_mult0(new[p1], win.right[p5]),
                new[p3],
                win.right[p6],
            ));
            pa += 1;
            p1 = p1.wrapping_sub(1);
            p3 += 1;
            p5 = p5.wrapping_sub(dec);
            p6 += dec;
        }
        for _ in (0..nu).step_by(2) {
            out[pa] = l_mult(new[p1], -16384);
            out[pa + 1] = l_mult(new[p1 - 1], -16384);
            pa += 2;
            p1 = p1.wrapping_sub(2);
        }

        pa = 320;
        let mut p1 = lb;
        let mut p2 = 1;
        let mut p3 = at + 2 * 90 - 1;
        let mut p4 = 0;
        for _ in (0..nu).step_by(2) {
            out[pa] = l_mac0(l_mult0(left[p1], win.left[p2]), new[p3], -32768);
            out[pa + 1] = l_mac0(l_mult0(left[p1 + 1], win.int_left[p4]), new[p3 - 1], -32768);
            pa += 2;
            p1 += 2;
            p3 = p3.wrapping_sub(2);
            p4 += 1;
            p2 += dec;
        }
        let mut p5 = lb + 640 - 1 - 90 * 2;
        let mut p6 = (320 - 90) * 3 - 1 - 1;
        let mut p3 = 320 - 90 - 1;
        let tmp = sub(shr(l, 1), n).max(0) as usize;
        for _ in (0..tmp).step_by(2) {
            out[pa] = l_msu0(l_mult0(left[p1], win.left[p2]), left[p5], win.left[p6]);
            out[pa + 1] = l_msu0(
                l_mult0(left[p1 + 1], win.int_left[p4]),
                left[p5 - 1],
                win.int_left[p3],
            );
            pa += 2;
            p1 += 2;
            p5 = p5.wrapping_sub(2);
            p4 += 1;
            p3 = p3.wrapping_sub(1);
            p2 += dec;
            p6 = p6.wrapping_sub(dec);
        }
        return;
    }

    // 8, 16 and 48 kHz
    let half = (l / 2) as i32;
    let d = i32::from(decimate);
    let dc = i32::from(decay);
    let mut p1 = r + half as usize - 1;
    let mut p2 = (3 * half * d - d + dc - 1230) as usize;
    let mut p3 = p1 + 1;
    let mut p4 = (3 * half * d + d - dc - 1230 - 1) as usize;
    let tmp = sub(shr(l, 1), n).max(0) as usize;
    for _ in 0..tmp {
        out[pa] = l_msu0(l_msu0(0, new[p1], win.right[p2]), new[p3], win.right[p4]);
        pa += 1;
        p1 = p1.wrapping_sub(1);
        p3 += 1;
        p2 = p2.wrapping_sub(dec);
        p4 += dec;
    }
    for _ in 0..nu {
        out[pa] = l_negate(l_shr(l_deposit_h(new[p1]), 1));
        pa += 1;
        p1 = p1.wrapping_sub(1);
    }

    pa = half as usize;
    let mut p1 = lb;
    let mut p2 = decay as usize;
    let mut p3 = (at + nu).wrapping_sub(1);
    for _ in 0..nu {
        out[pa] = l_mac0(l_mult0(left[p1], win.left[p2]), new[p3], -32768);
        pa += 1;
        p1 += 1;
        p3 = p3.wrapping_sub(1);
        p2 += dec;
    }
    let mut p3 = lb + lu - 1 - nu;
    let mut p4 = ((lu - nu) * dec - 1 - decay as usize) as isize;
    for _ in 0..tmp {
        out[pa] = l_msu0(
            l_mult0(left[p1], win.left[p2]),
            left[p3],
            win.left[p4 as usize],
        );
        pa += 1;
        p1 += 1;
        p3 = p3.wrapping_sub(1);
        p2 += dec;
        p4 -= dec as isize;
    }
}
