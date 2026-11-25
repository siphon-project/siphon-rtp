//! TCX helpers shared by the encoder and decoder (TS 26.442 `lib_com/codec_tcx_common.c`;
//! TS 26.445 §6.2.3.1 formant enhancement and noise filling, §6.2.5 window grouping).

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{ACELP_CORE, FDNS_NPTS, FULL_OVERLAP, M};
use crate::evs::com::basop_util::{idiv1616_u, inv16, sqrt16};
use crate::evs::com::get_gain::get_gain;
use crate::evs::com::tools::copy_scale_sig;
use crate::evs::dec::state::TcxConfig;
use crate::evs::rom::INVINTTABLE;
use crate::itu::basic_ops::{
    add, extract_l, l_shl, l_shr, mult, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mult0, StlFlags};

/// `FDNS_NPTS` as an index bound.
const NPTS: usize = FDNS_NPTS as usize;

/// `tcxGetNoiseFillingTilt`: the first line to noise-fill (`L_frame / 6` or `L_frame / 8`) and the
/// noise tilt factor (Q15) of a frame, from the LPC filter `a` (`mode == 0`) or a fixed tilt
/// (`mode != 0`).
pub fn tcx_get_noise_filling_tilt(
    a: &[i16],
    lpcorder: i16,
    l_frame: i16,
    mode: i16,
    noise_tilt_factor: &mut i16,
    flags: &mut StlFlags,
) -> i16 {
    let first_line;

    if mode != 0 {
        first_line = idiv1616_u(l_frame, 6);
        *noise_tilt_factor = 18432 /* 0.5625f Q15 */;
    } else {
        let mut as_ = [0i16; M as usize + 1];
        first_line = shr(l_frame, 3);

        copy_scale_sig(a, &mut as_, add(lpcorder, 1), sub(norm_s(a[0]), 2));
        let tmp = get_gain(&as_[1..], &as_, lpcorder, flags);
        *noise_tilt_factor = add(round_word(l_shl(tmp, 15)), 3072 /* 0.09375f Q15 */);
    }

    first_line
}

/// The linear interpolation of the formant-enhancement factor between two peaks of the LPC
/// envelope (the loop body that `tcxFormantEnhancement` runs at every peak and once more at the
/// end): the lines `l..l + n` of `xn_buf` are scaled by factors running from `fac0` to `fac1`
/// (`d` apart over `n` steps) at exponent `fac_e`, limited to `xn_one`.
fn formant_enhancement_interpolate(
    xn_buf: &mut [i16],
    l: usize,
    n: i16,
    fac0: i16,
    d: i16,
    fac_e: i16,
    xn_one: i16,
) {
    xn_buf[l] = xn_one;
    for j in 1..n {
        let fac = add(
            fac0,
            mult(d, extract_l(l_mult0(j, INVINTTABLE[n as usize]))),
        );
        let at = l + j as usize;
        xn_buf[at] = xn_one.min(shl(mult(xn_buf[at], fac), fac_e));
    }
}

/// `tcxFormantEnhancement`: derive a per-band spectral gain from the square root of the LPC gains
/// (`gainlpc` / `gainlpc_e`, `FDNS_NPTS` bands), flatten the valleys between its peaks, scale the
/// MDCT lines `spectrum[0..L_frame]` with it and shift the remaining `L_frameTCX - L_frame` lines
/// down by the gain exponent. `xn_buf` (at least `FDNS_NPTS` long) is the work buffer.
pub fn tcx_formant_enhancement(
    xn_buf: &mut [i16],
    gainlpc: &[i16],
    gainlpc_e: &[i16],
    spectrum: &mut [i32],
    spectrum_e: &mut i16,
    l_frame: i16,
    l_frame_tcx: i16,
) {
    let k = shr(l_frame, 6); // FDNS_NPTS = 64
    let mut l: usize = 0;

    // get exponent
    let mut xn_buf_e: i16 = 0;
    for &exponent in &gainlpc_e[..NPTS] {
        xn_buf_e = xn_buf_e.max(exponent);
    }
    xn_buf_e = shr(add(xn_buf_e, 1), 1); // max exponent after sqrt
    let xn_one = shr(0x4000, sub(xn_buf_e, 1)); // 1.0 scaled to xn_buf_e

    // Formant enhancement via square root of the LPC gains
    let mut e = gainlpc_e[0];
    let mut m = sqrt16(gainlpc[0], &mut e);
    xn_buf[0] = shl(m, sub(e, xn_buf_e));

    e = gainlpc_e[1];
    m = sqrt16(gainlpc[1], &mut e);
    xn_buf[1] = shl(m, sub(e, xn_buf_e));

    let mut fac0 = xn_buf[0].min(xn_buf[1]);
    let mut fac_e = xn_buf_e;
    fac0 = inv16(fac0, &mut fac_e);

    let mut i = 1usize;
    while i < NPTS - 1 {
        e = gainlpc_e[i + 1];
        m = sqrt16(gainlpc[i + 1], &mut e);
        xn_buf[i + 1] = shl(m, sub(e, xn_buf_e));

        if sub(xn_buf[i - 1], xn_buf[i]) <= 0 && sub(xn_buf[i + 1], xn_buf[i]) <= 0 {
            m = xn_buf[i - 1].max(xn_buf[i + 1]);
            e = xn_buf_e;
            m = inv16(m, &mut e);

            let mut fac1 = m;
            let tmp = sub(e, fac_e);

            if tmp > 0 {
                fac0 = shr(fac0, tmp);
            }
            if tmp < 0 {
                fac1 = shl(fac1, tmp);
            }

            if tmp > 0 {
                fac_e = e;
            }

            let d = sub(fac1, fac0);
            let n = sub(i as i16, l as i16);

            formant_enhancement_interpolate(xn_buf, l, n, fac0, d, fac_e, xn_one);

            l = i;

            fac0 = m;
            fac_e = e;
        }
        i += 1;
    }
    // i = FDNS_NPTS - 1; Completing changes to gains
    m = xn_buf[i - 1].min(xn_buf[i]);
    e = xn_buf_e;
    m = inv16(m, &mut e);

    let mut fac1 = m;
    let tmp = sub(e, fac_e);

    if tmp > 0 {
        fac0 = shr(fac0, tmp);
    }
    if tmp < 0 {
        fac1 = shl(fac1, tmp);
    }

    if tmp > 0 {
        fac_e = e;
    }

    let d = sub(fac1, fac0);
    let n = sub(i as i16, l as i16);

    formant_enhancement_interpolate(xn_buf, l, n, fac0, d, fac_e, xn_one);

    xn_buf[i] = xn_one;

    // Application of changed gains onto decoded MDCT lines
    let mut at = 0usize;
    let mut band = 0usize;
    let mut i: i16 = 0;
    while i < l_frame {
        for _ in 0..k {
            spectrum[at] = mpy_32_16_1(spectrum[at], xn_buf[band]);
            at += 1;
        }
        band += 1;
        i = add(i, k);
    }

    let tmp = sub(l_frame_tcx, l_frame);
    for i in 0..tmp.max(0) as usize {
        spectrum[at + i] = l_shr(spectrum[at + i], xn_buf_e);
    }
    *spectrum_e = add(*spectrum_e, xn_buf_e);
}

/// `tcxInvertWindowGrouping`: undo the interleaving of the lines of the short-window TCX
/// sub-frames (`spectrum` is `L_frame` lines of interleaved sub-windows; `xn_buf` is scratch) and,
/// with TNS in use, rearrange the lowest lines of the sub-windows for the TNS synthesis filter.
/// The overlap mode of the previous frame is first refreshed for sub-frames after the first.
pub fn tcx_invert_window_grouping(
    tcx_cfg: &mut TcxConfig,
    xn_buf: &mut [i32],
    spectrum: &mut [i32],
    l_frame: i16,
    f_use_tns: i8,
    last_core: i16,
    index: i16,
    frame_cnt: i16,
    bfi: i16,
) {
    let l_win = shr(l_frame, 1);
    let l_spec = tcx_cfg.tns_config[0][0].i_filter_borders[0];

    if frame_cnt != 0 && bfi == 0 && last_core != ACELP_CORE {
        // fix sub-window overlap
        tcx_cfg.tcx_last_overlap_mode = tcx_cfg.tcx_curr_overlap_mode;
    }
    if (bfi == 0
        && (tcx_cfg.tcx_last_overlap_mode != FULL_OVERLAP
            || (tcx_cfg.tcx_curr_overlap_mode == FULL_OVERLAP && frame_cnt == 0 && index == 0)))
        || (bfi != 0
            && (tcx_cfg.tcx_last_overlap_mode != FULL_OVERLAP
                && tcx_cfg.tcx_curr_overlap_mode != FULL_OVERLAP))
    {
        let (l_frame_u, l_win_u) = (l_frame as usize, l_win as usize);

        // ungroup sub-windows: deinterleave MDCT bins into separate windows
        let mut p = 0usize;
        let mut i = 1usize;
        while i < l_win_u {
            xn_buf[p] = spectrum[i];
            p += 1;
            i += 2;
        }

        p = 0;
        i = 0;
        while i < l_frame_u {
            spectrum[p] = spectrum[i];
            p += 1;
            i += 2;
        }

        let mut p = l_frame_u - 1;
        let mut i = l_frame_u - 1;
        while i > l_win_u {
            spectrum[p] = spectrum[i];
            p -= 1;
            i = i.wrapping_sub(2);
        }
        let quarter = shr(l_win, 1) as usize;
        spectrum[l_win_u..l_win_u + quarter].copy_from_slice(&xn_buf[..quarter]);

        if tcx_cfg.f_is_tns_allowed != 0 && bfi == 0 && f_use_tns != 0 {
            // rearrange LF sub-window lines prior to TNS synthesis filtering
            if sub(l_spec, l_frame) < 0 {
                let half_spec = shr(l_spec, 1) as usize;
                spectrum.copy_within(8..half_spec, 16);
                spectrum.copy_within(l_frame_u / 2..l_frame_u / 2 + 8, 8);
                spectrum.copy_within(
                    l_frame_u / 2 + 8..l_frame_u / 2 + half_spec,
                    l_spec as usize / 2 + 8,
                );
            } else {
                xn_buf[..8].copy_from_slice(&spectrum[l_win_u..l_win_u + 8]);
                spectrum.copy_within(8..l_win_u, 16);
                spectrum[8..16].copy_from_slice(&xn_buf[..8]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fixed_tilt_mode_splits_at_a_sixth_of_the_frame() {
        let mut tilt = 0;
        let mut flags = StlFlags::default();
        let first_line = tcx_get_noise_filling_tilt(&[0; 17], 16, 320, 1, &mut tilt, &mut flags);
        assert_eq!((first_line, tilt), (53, 18432));
    }

    #[test]
    fn a_flat_envelope_leaves_the_spectrum_unchanged_up_to_scaling() {
        let mut xn_buf = [0i16; 64];
        let gains = [0x4000i16; 64];
        let exps = [0i16; 64];
        let mut spectrum = [1 << 20; 256];
        let mut spectrum_e = 0;
        tcx_formant_enhancement(
            &mut xn_buf,
            &gains,
            &exps,
            &mut spectrum,
            &mut spectrum_e,
            256,
            256,
        );
        assert!(spectrum.iter().all(|&v| v == spectrum[0]));
    }
}
