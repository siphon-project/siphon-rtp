//! TCX long-term (harmonic) post-filter (TS 26.442 `lib_com/tcx_ltp.c`; TS 26.445 §6.9.2).
//!
//! In MODE1 the post-filter runs on the ACELP / HQ output with a zero gain, so it only fades out
//! whatever filtering the previous (MODE2) frame left on and delays the signal by the TCX
//! look-ahead.

use crate::evs::basop::{l_extract_lc, mpy_32_16_1};
use crate::evs::com::basop_util::{idiv1616_u, imult1616};
use crate::evs::com::lpc_tools::e_lpc_lev_dur;
use crate::evs::com::syn_filt::e_util_synthesis;
use crate::evs::rom::types::TcxLtpFilter;
use crate::evs::rom::TCXLTPFILTERS;
use crate::itu::basic_ops::{
    add, div_s, l_mac, l_shl, l_shr, l_sub, mult_r, norm_l, norm_s, round_word, shl, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0, lshl};

/// `L_FRAME_MAX`.
const L_FRAME_MAX: usize = 960;
/// `TCXLTP_MAX_DELAY` = `NS2SA(48000, TCXLTP_DELAY_NS)`.
const TCXLTP_MAX_DELAY: usize = 12;
/// `TCXLTP_LTP_ORDER`.
const TCXLTP_LTP_ORDER: usize = 24;

/// One filtered sample: the interpolated pitch-delayed output minus 0.85 times the interpolated
/// input (the two-sided `tcxLtpFilters` interpolation), as the reference's inner loop computes
/// it. `x` / `x_at` is the output history at `-pitch_int`, `y` / `y_at` the input.
fn ltp_sample(
    filter: &TcxLtpFilter,
    pitch_fr: usize,
    pitch_res: usize,
    x: &[i16],
    x_at: usize,
    y: &[i16],
    y_at: usize,
) -> i16 {
    let filt = filter.filt;
    let w1_at = pitch_res - pitch_fr;
    let mut s: i32 = 0;
    let mut s2: i32 = 0;
    let mut k = 0usize;
    for i in 0..filter.length.max(0) as usize {
        // x0[i], x1[-i] = x0[-1 - i]; y0[i], y1[-i] = y0[-1 - i]
        s = l_mac(
            l_mac(s, filt[pitch_fr + k], x[x_at + i]),
            filt[w1_at + k],
            x[x_at - 1 - i],
        );
        s2 = l_mac(
            l_mac(s2, filt[k], y[y_at + i]),
            filt[pitch_res + k],
            y[y_at - 1 - i],
        );
        k += pitch_res;
    }
    sub(round_word(s), mult_r(round_word(s2), 27853 /* 0.85 */))
}

/// The filter `filt_idx` and whether the reads `ltp_sample` makes for `length` samples stay
/// inside both buffers; `None` where the reference would read out of bounds (a negative filter
/// index, which it asserts against, or a pitch beyond the history it keeps).
fn checked_filter(
    filt_idx: i16,
    pitch_int: i16,
    pitch_fr: i16,
    pitch_res: i16,
    length: usize,
    x_len: usize,
    x_at: usize,
    y_len: usize,
    y_at: usize,
) -> Option<&'static TcxLtpFilter> {
    let filter = TCXLTPFILTERS.get(usize::try_from(filt_idx).ok()?)?;
    let taps = filter.length.max(0) as usize;
    let pitch_int = usize::try_from(pitch_int).ok()?;
    let pitch_fr = usize::try_from(pitch_fr).ok()?;
    let pitch_res = usize::try_from(pitch_res).ok()?;
    if pitch_fr > pitch_res
        || pitch_res * taps >= filter.filt.len()
        || x_at < pitch_int + taps
        || y_at < taps
        || x_at - pitch_int + length + taps > x_len + 1
        || y_at + length + taps > y_len + 1
    {
        return None;
    }
    Some(filter)
}

/// `tcx_ltp_synth_filter`: `length` samples of `synth` (at `synth_at`) post-filtered into
/// `synth_ltp` (at `synth_ltp_at`, whose preceding samples are the output history the pitch lag
/// reads). `fade` 0 holds the gain, 1 fades it in, -1 fades it out over `length`; `zir`, when
/// given, is subtracted. A non-positive gain copies the input.
pub fn tcx_ltp_synth_filter(
    synth_ltp: &mut [i16],
    synth_ltp_at: usize,
    synth: &[i16],
    synth_at: usize,
    length: i16,
    pitch_int: i16,
    pitch_fr: i16,
    gain: i16,
    pitch_res: i16,
    zir: Option<&[i16]>,
    fade: i16,
    filt_idx: i16,
) {
    let len = length.max(0) as usize;
    if gain <= 0 {
        synth_ltp[synth_ltp_at..synth_ltp_at + len]
            .copy_from_slice(&synth[synth_at..synth_at + len]);
        return;
    }
    let Some(filter) = checked_filter(
        filt_idx,
        pitch_int,
        pitch_fr,
        pitch_res,
        len,
        synth_ltp.len(),
        synth_ltp_at,
        synth.len(),
        synth_at,
    ) else {
        return;
    };
    let pitch_fr = pitch_fr as usize;
    let res = pitch_res as usize;

    let mut alpha: i16 = 0;
    let mut step: i16 = 0;
    if fade != 0 {
        if fade < 0 {
            alpha = 0x7FFF;
        }
        // step = 1.f/(float)(length)
        step = shl(2, norm_s(length));
        if (length & sub(length, 1)) != 0 {
            step = mult_r(step, 26214 /* 64.f/80.f Q15 */);
        }
        if sub(length, 240) == 0 {
            step = 137; // 1.f/240.f Q15
        }
        if fade < 0 {
            step = crate::itu::basic_ops::negate(step);
        }
    }

    let x_base = synth_ltp_at - pitch_int as usize;
    for j in 0..len {
        let i = ltp_sample(
            filter,
            pitch_fr,
            res,
            synth_ltp,
            x_base + j,
            synth,
            synth_at + j,
        );
        let mut k = mult_r(gain, i);
        if fade != 0 {
            k = mult_r(k, alpha);
        }
        k = add(synth[synth_at + j], k);
        if let Some(zir) = zir {
            k = sub(k, zir[j]);
        }
        synth_ltp[synth_ltp_at + j] = k;
        if fade != 0 {
            alpha = add(alpha, step);
        }
    }
}

/// `tcx_ltp_get_lpc`: an order-`order` LP filter `a` (Levinson-Durbin, lag window-free) of the
/// `L` samples of `x`, scaled down first where their energy would overflow.
pub fn tcx_ltp_get_lpc(x: &[i16], l: i16, a: &mut [i16], order: i16) {
    let mut tmpbuf = [0i16; L_FRAME_MAX];
    let mut r_l = [0i16; TCXLTP_LTP_ORDER + 1];
    let mut r_h = [0i16; TCXLTP_LTP_ORDER + 1];
    let lu = (l.max(0) as usize).min(L_FRAME_MAX).min(x.len());
    let order = (order.max(0) as usize).min(TCXLTP_LTP_ORDER);

    let mut s: i16 = 0;
    let mut r: i32 = 0;
    for &v in &x[..lu] {
        let l_tmp = l_sub(r, 0x4000_0000);
        if l_tmp > 0 {
            s = sub(s, 1);
        }
        if l_tmp > 0 {
            r = l_shr(r, 2);
        }
        let tmp = shl(v, s);
        r = l_mac0(r, tmp, tmp);
    }
    r = r.max(l_shl(100, shl(s, 1)));
    r = mpy_32_16_1(r, 16386); // 1.0001f Q14
    let mut s2 = norm_l(r);
    r = l_shl(r, s2);
    s2 = sub(s2, 1);
    (r_h[0], r_l[0]) = l_extract_lc(r);

    let p: &[i16] = if s < 0 {
        r = 0;
        let tmp = lshl(i16::MIN, s);
        for j in 0..lu {
            tmpbuf[j] = mult_r(x[j], tmp);
            r = l_mac0(r, tmpbuf[j], tmpbuf[j]);
        }
        r = r.max(l_shl(100, shl(s, 1)));
        r = mpy_32_16_1(r, 16386);
        s2 = norm_l(r);
        r = l_shl(r, s2);
        s2 = sub(s2, 1);
        (r_h[0], r_l[0]) = l_extract_lc(r);
        &tmpbuf[..lu]
    } else {
        &x[..lu]
    };

    for i in 1..=order {
        r = 0;
        for j in 0..lu.saturating_sub(i) {
            r = l_mac0(r, p[j], p[j + i]);
        }
        r = l_shl(r, s2);
        (r_h[i], r_l[i]) = l_extract_lc(r);
    }
    e_lpc_lev_dur(&r_h, &r_l, a, None, order as i16, None);
}

/// `tcx_ltp_get_zir`: the zero-input response that smooths a change of the post-filter's
/// parameters: the post-filter error over the `lpcorder` samples before the transition is run
/// through `1/A(z)` and faded out over the second half of `length`. `synth_ltp` / `synth` are
/// indexed from `lpcorder` samples before the transition, as the reference passes them.
pub fn tcx_ltp_get_zir(
    zir: &mut [i16],
    length: i16,
    synth_ltp: &[i16],
    synth_ltp_at: usize,
    synth: &[i16],
    synth_at: usize,
    a: &[i16],
    lpcorder: i16,
    gain: i16,
    pitch_int: i16,
    pitch_fr: i16,
    pitres: i16,
    filt_idx: i16,
) {
    let mut buf = [0i16; TCXLTP_LTP_ORDER];
    let order = (lpcorder.max(0) as usize).min(TCXLTP_LTP_ORDER);
    let len = length.max(0) as usize;
    let Some(filter) = checked_filter(
        filt_idx,
        pitch_int,
        pitch_fr,
        pitres,
        order,
        synth_ltp.len(),
        synth_ltp_at,
        synth.len(),
        synth_at,
    ) else {
        return;
    };
    let x_base = synth_ltp_at - pitch_int as usize;
    for j in 0..order {
        let i = ltp_sample(
            filter,
            pitch_fr as usize,
            pitres as usize,
            synth_ltp,
            x_base + j,
            synth,
            synth_at + j,
        );
        buf[j] = add(
            sub(synth[synth_at + j], synth_ltp[synth_ltp_at + j]),
            mult_r(gain, i),
        );
    }

    zir[..len].fill(0);
    let mut zero = [0i16; L_FRAME_MAX / 4];
    zero[..len].copy_from_slice(&zir[..len]);
    e_util_synthesis(0, a, &zero, zir, length, &mut buf, 0, lpcorder);

    let mut alpha: i16 = 0x7FFF;
    // step = 2.f/(float)(length)
    let mut step = shl(4, norm_s(length));
    if (length & sub(length, 1)) != 0 {
        step = mult_r(step, 26214 /* 64.f/80.f Q15 */);
    }
    if sub(length, 240) == 0 {
        step = 273; // 2.f/240.f Q15
    }
    for z in zir.iter_mut().take(len).skip(len / 2) {
        *z = mult_r(*z, alpha);
        alpha = sub(alpha, step);
    }
}

/// The `tcxLtpFilters` index for an output frame length and a core frame length, or -1 for a core
/// rate without filters (the reference asserts on an output length it has no filter for).
fn filter_index(l_frame_core: i16, l_frame: i16) -> i16 {
    let base = match l_frame_core {
        256 => 0,
        320 => 4,
        512 => 8,
        _ => return -1,
    };
    match l_frame {
        160 => base,
        320 => base + 1,
        640 => base + 2,
        960 => base + 3,
        // assert(0) in the reference; keep the previous assignment's value (0).
        _ => 0,
    }
}

/// `tcx_ltp_post`: the TCX LTP post-filter of one output frame `sig` (in place, delayed by
/// `tcx_buf_len` samples kept in `mem_in`), with `mem_out` the previous output frame. The
/// post-filter parameters of the previous frame are carried in the `*_past` references.
///
/// `tcx_buf` (the TCX look-ahead, `tcx_buf_len` samples) is read only when `core > 0`.
///
/// A change of non-zero parameters is smoothed with the zero-input response of an LPC of the
/// previous output ([`tcx_ltp_get_lpc`], [`tcx_ltp_get_zir`]).
pub fn tcx_ltp_post(
    tcxltp_on: i8,
    core: i16,
    l_frame: i16,
    l_frame_core: i16,
    delay: i16,
    sig: &mut [i16],
    tcx_buf: Option<&[i16]>,
    tcx_buf_len: i16,
    bfi: i16,
    mut pitch_int: i16,
    mut pitch_fr: i16,
    mut gain: i16,
    pitch_int_past: &mut i16,
    pitch_fr_past: &mut i16,
    gain_past: &mut i16,
    filt_idx_past: &mut i16,
    pitres: i16,
    pitres_past: &mut i16,
    damping: i16,
    side_info_only: i16,
    mem_in: &mut [i16],
    mem_out: &mut [i16],
    bitrate: i32,
) {
    let mut buf_in = [0i16; TCXLTP_MAX_DELAY + L_FRAME_MAX + TCXLTP_MAX_DELAY];
    let mut buf_out = [0i16; 2 * L_FRAME_MAX];
    let lf = l_frame.max(0) as usize;
    let tbl = tcx_buf_len.max(0) as usize;
    let dl = delay.max(0) as usize;
    if lf > L_FRAME_MAX || tbl > TCXLTP_MAX_DELAY || lf < tbl || dl > lf {
        return;
    }

    let l_transition = (l_frame >> 2) as usize;
    let lpcorder = TCXLTP_LTP_ORDER as i16;

    // Input buffer
    let sig_in = tbl;
    buf_in[..tbl].copy_from_slice(&mem_in[..tbl]);
    buf_in[tbl..tbl + lf].copy_from_slice(&sig[..lf]);
    if core > 0 {
        if let Some(tcx_buf) = tcx_buf {
            buf_in[sig_in + lf..sig_in + lf + tbl].copy_from_slice(&tcx_buf[..tbl]);
        }
    }
    mem_in[..tbl].copy_from_slice(&sig[lf - tbl..lf]);

    // Output buffer
    let sig_out = lf;
    buf_out[..lf].copy_from_slice(&mem_out[..lf]);

    // LTP parameters: integer pitch, fractional pitch, gain
    if !(side_info_only != 0 || tcxltp_on != 0) || sub(core, 0) == 0 {
        // No LTP on ACELP frames
        pitch_int = 0;
        pitch_fr = 0;
        gain = 0;
    } else if bfi == 0 {
        // LTP and good frame
        if sub(l_frame, l_frame_core) != 0 {
            // rescale the pitch from the core rate to the output rate
            let tmp = div_s(l_frame, shl(l_frame_core, 2));
            let tmp32 = l_mult0(add(imult1616(pitch_int, pitres), pitch_fr), tmp);
            let tmp = round_word(l_shl(tmp32, 3));
            pitch_int = idiv1616_u(tmp, pitres);
            pitch_fr = sub(tmp, imult1616(pitch_int, pitres));
        }
        if bitrate == 48000 && sub(l_frame_core, 320) == 0 {
            gain = mult_r(gain, 10486); // 0.32f Q15
        } else if bitrate == 48000 && sub(l_frame_core, 512) == 0 {
            gain = mult_r(gain, 13107); // 0.40f Q15
        } else {
            gain = mult_r(gain, 20972); // 0.64f Q15
        }
    } else if pitres == *pitres_past {
        // PLC: repeat the old LTP parameters, damped
        pitch_int = *pitch_int_past;
        pitch_fr = *pitch_fr_past;
        gain = shl(mult_r(*gain_past, damping), 1);
    } else {
        gain = 0;
    }
    if side_info_only != 0 {
        gain = 0;
        if bfi != 0 {
            *gain_past = 0;
        }
    }
    let gain2 = gain;
    let filt_idx = filter_index(l_frame_core, l_frame);

    // Previous frame's parameters over the delay
    tcx_ltp_synth_filter(
        &mut buf_out,
        sig_out,
        &buf_in,
        sig_in,
        delay,
        *pitch_int_past,
        *pitch_fr_past,
        *gain_past,
        *pitres_past,
        None,
        0,
        *filt_idx_past,
    );

    // Transition
    let tr = l_transition as i16;
    if gain == 0 && *gain_past == 0 {
        buf_out[sig_out + dl..sig_out + dl + l_transition]
            .copy_from_slice(&buf_in[sig_in + dl..sig_in + dl + l_transition]);
    } else if *gain_past == 0 {
        tcx_ltp_synth_filter(
            &mut buf_out,
            sig_out + dl,
            &buf_in,
            sig_in + dl,
            tr,
            pitch_int,
            pitch_fr,
            gain,
            pitres,
            None,
            1,
            filt_idx,
        );
    } else if gain == 0 {
        tcx_ltp_synth_filter(
            &mut buf_out,
            sig_out + dl,
            &buf_in,
            sig_in + dl,
            tr,
            *pitch_int_past,
            *pitch_fr_past,
            *gain_past,
            *pitres_past,
            None,
            -1,
            *filt_idx_past,
        );
    } else if sub(gain, *gain_past) == 0
        && sub(pitch_int, *pitch_int_past) == 0
        && sub(pitch_fr, *pitch_fr_past) == 0
    {
        tcx_ltp_synth_filter(
            &mut buf_out,
            sig_out + dl,
            &buf_in,
            sig_in + dl,
            tr,
            pitch_int,
            pitch_fr,
            gain,
            pitres,
            None,
            0,
            filt_idx,
        );
    } else {
        // Parameter change: smooth it with the zero-input response of an LPC of the previous
        // output. The reference reads lpcorder samples before the transition; a delay shorter
        // than that (no caller has one) would read before its buffers.
        let mut a = [0i16; TCXLTP_LTP_ORDER + 1];
        let mut zir = [0i16; L_FRAME_MAX / 4];
        let order = TCXLTP_LTP_ORDER;
        if let (Some(out_at), Some(in_at)) = (
            (sig_out + dl).checked_sub(order),
            (sig_in + dl).checked_sub(order),
        ) {
            tcx_ltp_get_lpc(&buf_out[dl..dl + lf], l_frame, &mut a, lpcorder);
            tcx_ltp_get_zir(
                &mut zir, tr, &buf_out, out_at, &buf_in, in_at, &a, lpcorder, gain, pitch_int,
                pitch_fr, pitres, filt_idx,
            );
            tcx_ltp_synth_filter(
                &mut buf_out,
                sig_out + dl,
                &buf_in,
                sig_in + dl,
                tr,
                pitch_int,
                pitch_fr,
                gain,
                pitres,
                Some(&zir[..l_transition]),
                0,
                filt_idx,
            );
        }
    }

    // Current frame's parameters after the transition
    let rest = sub(l_frame, add(delay, tr));
    tcx_ltp_synth_filter(
        &mut buf_out,
        sig_out + dl + l_transition,
        &buf_in,
        sig_in + dl + l_transition,
        rest,
        pitch_int,
        pitch_fr,
        gain,
        pitres,
        None,
        0,
        filt_idx,
    );

    // Output
    sig[..lf].copy_from_slice(&buf_out[sig_out..sig_out + lf]);
    *pitch_int_past = pitch_int;
    *pitch_fr_past = pitch_fr;
    *gain_past = gain2;
    *filt_idx_past = filt_idx;
    *pitres_past = pitres;
    mem_out[..lf].copy_from_slice(&buf_out[sig_out..sig_out + lf]);
}
