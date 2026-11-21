//! TCX helpers shared by the encoder and decoder (TS 26.442 `lib_com/tcx_utils.c`).
//!
//! Ported so far: `getInvFrameLen` and `init_TCX_config`, the two the decoder's ACELP (MODE1)
//! path reaches, `InitTnsConfigs`, and the two synthesis-windowing functions the FD-CNG decoder's
//! transition from an active TCX frame (`generate_comfort_noise_dec`) reaches.

use crate::evs::cnst::{ACELP_32K, ACELP_CORE, LD_FSCALE_DENOM, L_FRAME_MAX, L_LOOK_12K8, M};
use crate::evs::com::basop_util::idiv1616_u;
use crate::evs::com::lerp::lerp;
use crate::evs::com::syn_filt::e_util_synthesis_in_place;
use crate::evs::com::tcx_mdct_window::{mdct_window_aldo, mdct_window_sine};
use crate::evs::com::tns_base::init_tns_configuration;
use crate::evs::dec::state::{STnsConfig, TcxConfig};
use crate::evs::rom::types::PWord16;
use crate::evs::rom::L_FRAME_INV;
use crate::itu::basic_ops::{
    add, div_s, extract_l, l_mac, l_mult, l_shr, l_sub, mult_r, norm_s, shl, shr, sub,
};
use crate::itu::stl2009::{l_mult0, mac_r};

/// `NS2SA(12800, 5000000L)`: 5 ms at 12.8 kHz.
const LOOK_5MS_12K8: i16 = 64;

/// `getInvFrameLen`: `1 / l_frame` in Q21, for the frame lengths the codec uses (a power of two
/// times 64, 75, 80, 90, 96, 100 or 120; the reference asserts that).
#[must_use]
pub fn get_inv_frame_len(l_frame: i16) -> i16 {
    let s = norm_s(l_frame);
    let mut idx = shl(l_frame, s);
    idx = mult_r(idx, 0x10); // idx = shr(add(idx, 0x0400), 11)
    idx &= 7;
    shl(L_FRAME_INV[idx as usize], sub(s, 7))
}

/// `init_TCX_config`: the TCX MDCT window lengths and slopes for a core frame of `l_frame` samples
/// (`fscale` the core rate in `FSCALE_DENOM` units) and a TCX frame of `l_frame_tcx` samples at the
/// output rate (`fscale_fb`).
pub fn init_tcx_config(
    tcx_cfg: &mut TcxConfig,
    l_frame: i16,
    fscale: i16,
    l_frame_tcx: i16,
    fscale_fb: i16,
) {
    // Initialize the TCX MDCT windows
    tcx_cfg.tcx_mdct_window_length =
        extract_l(l_shr(l_mult0(L_LOOK_12K8, fscale), LD_FSCALE_DENOM));
    tcx_cfg.tcx_mdct_window_delay = tcx_cfg.tcx_mdct_window_length;
    tcx_cfg.tcx_mdct_window_half_length = extract_l(l_shr(
        l_mult0(L_LOOK_12K8 - LOOK_5MS_12K8, fscale),
        LD_FSCALE_DENOM,
    ));
    tcx_cfg.tcx_mdct_window_min_length = shr(l_frame, 4); // 1.25 ms
    tcx_cfg.tcx_mdct_window_trans_length = shr(l_frame, 4); // 1.25 ms
    tcx_cfg.tcx5_size = shr(l_frame, 2); // 5 ms

    tcx_cfg.tcx_mdct_window_length_fb =
        extract_l(l_shr(l_mult0(L_LOOK_12K8, fscale_fb), LD_FSCALE_DENOM));
    tcx_cfg.tcx_mdct_window_delay_fb = tcx_cfg.tcx_mdct_window_length_fb;
    tcx_cfg.tcx_mdct_window_half_length_fb = extract_l(l_shr(
        l_mult0(L_LOOK_12K8 - LOOK_5MS_12K8, fscale_fb),
        LD_FSCALE_DENOM,
    ));
    tcx_cfg.tcx_mdct_window_min_length_fb = shr(l_frame_tcx, 4); // 1.25 ms
    tcx_cfg.tcx_mdct_window_trans_length_fb = shr(l_frame_tcx, 4); // 1.25 ms
    tcx_cfg.tcx5_size_fb = shr(l_frame_tcx, 2); // 5 ms

    mdct_window_sine(&mut tcx_cfg.tcx_mdct_window, tcx_cfg.tcx_mdct_window_length);
    mdct_window_sine(
        &mut tcx_cfg.tcx_mdct_window_half,
        tcx_cfg.tcx_mdct_window_half_length,
    );
    mdct_window_sine(
        &mut tcx_cfg.tcx_mdct_window_minimum,
        tcx_cfg.tcx_mdct_window_min_length,
    );
    mdct_window_sine(
        &mut tcx_cfg.tcx_mdct_window_trans,
        tcx_cfg.tcx_mdct_window_trans_length,
    );

    mdct_window_sine(
        &mut tcx_cfg.tcx_mdct_window_fb,
        tcx_cfg.tcx_mdct_window_length_fb,
    );
    mdct_window_sine(
        &mut tcx_cfg.tcx_mdct_window_half_fb,
        tcx_cfg.tcx_mdct_window_half_length_fb,
    );
    mdct_window_sine(
        &mut tcx_cfg.tcx_mdct_window_minimum_fb,
        tcx_cfg.tcx_mdct_window_min_length_fb,
    );
    mdct_window_sine(
        &mut tcx_cfg.tcx_mdct_window_trans_fb,
        tcx_cfg.tcx_mdct_window_trans_length_fb,
    );

    // ALDO windows for MODE2
    mdct_window_aldo(
        &mut tcx_cfg.tcx_aldo_window_1,
        &mut tcx_cfg.tcx_aldo_window_1_trunc,
        &mut tcx_cfg.tcx_aldo_window_2,
        l_frame,
    );
    mdct_window_aldo(
        &mut tcx_cfg.tcx_aldo_window_1_fb,
        &mut tcx_cfg.tcx_aldo_window_1_fb_trunc,
        &mut tcx_cfg.tcx_aldo_window_2_fb,
        l_frame_tcx,
    );
}

/// `InitTnsConfigs`: the TNS configurations of a TCX core at `n_sample_rate` and `l_frame` lines:
/// `tnsConfig[1][0]` for TCX20 and `[1][1]` for TCX20 after ACELP (1.25 frames), and above
/// 32 kbit/s `[0][0]` for TCX10. The reference ignores `InitTnsConfiguration`'s status, and so
/// does this (it only fails for a non-positive rate or length, which no core configuration has).
pub fn init_tns_configs(
    n_sample_rate: i32,
    l_frame: i16,
    tns_config: &mut [[STnsConfig; 2]; 2],
    igf_stop_freq: i16,
    bitrate: i32,
) {
    if l_sub(bitrate, i32::from(ACELP_32K)) > 0 {
        let _ = init_tns_configuration(
            n_sample_rate,
            shr(l_frame, 1),
            &mut tns_config[0][0],
            igf_stop_freq,
            bitrate,
        );
    }
    let _ = init_tns_configuration(
        n_sample_rate,
        l_frame,
        &mut tns_config[1][0],
        igf_stop_freq,
        bitrate,
    );
    let _ = init_tns_configuration(
        n_sample_rate,
        add(l_frame, shr(l_frame, 2)),
        &mut tns_config[1][1],
        igf_stop_freq,
        bitrate,
    );
}

/// The ACELP side of a TCX frame's left window: the zero-input response of the past ACELP frame
/// and its synthesis, as `tcx_windowing_synthesis_current_frame` takes them.
pub struct AcelpTransition<'a> {
    /// `acelp_zir`: the ACELP zero-input response (computed here when not fullband-scaled).
    pub acelp_zir: &'a mut [i16],
    /// `old_syn`: the past ACELP synthesis.
    pub old_syn: &'a [i16],
    /// `syn_overl`: the overlap of the past synthesis.
    pub syn_overl: &'a [i16],
    /// `A_zir`: the LP filter of the ZIR.
    pub a_zir: &'a [i16],
}

/// `tcx_windowing_synthesis_current_frame`: window the left part of a decoded TCX frame `signal`
/// for its overlap-add with the past frame: a fade-in from the ACELP ZIR after a CNG frame, the
/// rectangular transition window (after ACELP: time-domain aliasing cancellation with `old_syn`,
/// ZIR replacement; after TCX: plain), or the normal sine / half / minimum overlap.
///
/// `transition` carries the ACELP buffers (the C's `acelp_zir`, `old_syn`, `syn_overl`, `A_zir`);
/// the branches that read them are not taken without them (the C would dereference null). With a
/// nonzero `fullband_scale` the ZIR is resampled from the core rate by `lerp`.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
pub fn tcx_windowing_synthesis_current_frame(
    signal: &mut [i16],
    window: &[PWord16],
    window_half: &[PWord16],
    window_min: &[PWord16],
    window_length: i16,
    window_half_length: i16,
    window_min_length: i16,
    left_rect: i16,
    left_mode: i16,
    transition: Option<AcelpTransition<'_>>,
    window_trans: &[PWord16],
    acelp_zir_len: i16,
    acelp_mem_len: i16,
    last_core_bfi: i16,
    last_is_cng: i8,
    fullband_scale: i16,
) {
    // Init
    let overlap = shr(window_length, 1);

    // Past-frame is TCX concealed as CNG and current-frame is TCX
    if sub(i16::from(last_is_cng), 1) == 0 && left_rect == 0 {
        if let Some(transition) = transition {
            current_frame_after_cng(
                signal,
                transition,
                overlap,
                acelp_zir_len,
                acelp_mem_len,
                fullband_scale,
            );
        }
    }
    // Rectangular window (past-frame is ACELP)
    else if sub(left_rect, 1) == 0 && last_core_bfi == ACELP_CORE {
        if let Some(transition) = transition {
            current_frame_after_acelp(
                signal,
                transition,
                window_trans,
                overlap,
                acelp_zir_len,
                acelp_mem_len,
                fullband_scale,
            );
        }
    }
    // Rectangular window (past-frame is TCX)
    else if left_rect == 1 && last_core_bfi != ACELP_CORE {
        let n = add(overlap, acelp_mem_len).max(0) as usize;
        signal[..n].fill(0);

        let at = n;
        let half = shr(window_length, 1).max(0) as usize;
        let wl = window_length.max(0) as usize;
        for i in 0..half {
            signal[i + at] = mult_r(signal[i + at], window[i].v.im);
        }
        for i in half..wl {
            signal[i + at] = mult_r(signal[i + at], window[wl - 1 - i].v.re);
        }
    }
    // Normal window (past-frame is ACELP)
    else if left_rect != 1 && last_core_bfi == ACELP_CORE {
        let half = shr(window_length, 1).max(0) as usize;
        let wl = window_length.max(0) as usize;
        for i in 0..half {
            signal[i] = mult_r(signal[i], window[i].v.im);
        }
        for i in half..wl {
            signal[i] = mult_r(signal[i], window[wl - 1 - i].v.re);
        }
        if let Some(transition) = transition {
            for i in 0..wl {
                signal[i] = add(signal[i], transition.syn_overl[i]);
            }
        }
    }
    // Normal window (past-frame is TCX)
    else if sub(left_mode, 2) == 0 {
        // min. overlap
        let n = shr(sub(window_length, window_min_length), 1).max(0) as usize;
        signal[..n].fill(0);
        let mut at = n;
        let n = shr(window_min_length, 1).max(0) as usize;
        for i in 0..n {
            signal[at] = mult_r(signal[at], window_min[i].v.im);
            at += 1;
        }
        for i in 0..n {
            signal[at] = mult_r(signal[at], window_min[n - 1 - i].v.re);
            at += 1;
        }
    } else if sub(left_mode, 3) == 0 {
        // half OL
        let n = shr(sub(window_length, window_half_length), 1).max(0) as usize;
        signal[..n].fill(0);
        let mut i = n;
        let n = shr(window_half_length, 1).max(0) as usize;
        let half = (window_half_length / 2).max(0) as usize;
        for w in 0..n {
            signal[i] = mult_r(signal[i], window_half[w].v.im);
            i += 1;
        }
        for w in 0..n {
            signal[i] = mult_r(signal[i], window_half[half - 1 - w].v.re);
            i += 1;
        }
    } else {
        // normal full/maximum overlap
        let half = shr(window_length, 1).max(0) as usize;
        let wl = window_length.max(0) as usize;
        for i in 0..half {
            signal[i] = mult_r(signal[i], window[i].v.im);
        }
        for i in half..wl {
            signal[i] = mult_r(signal[i], window[wl - 1 - i].v.re);
        }
    }

    // Right part asymmetric window : with ALDO do nothing->can be skipped
}

/// The ZIR of the ACELP synthesis filter `a_zir` from the filter state that ends at
/// `signal[at - M..at]` (the C passes that pointer as the memory, without update).
fn acelp_zir_from(signal: &[i16], at: usize, a_zir: &[i16], zir: &mut [i16], len: i16) {
    let m = M as usize;
    let mut mem = [0i16; M as usize];
    mem.copy_from_slice(&signal[at - m..at]);
    zir[..len.max(0) as usize].fill(0);
    e_util_synthesis_in_place(0, a_zir, zir, len, &mut mem, 0, M);
}

/// After a CNG frame: cross-fade from the ACELP ZIR into the TCX frame over `acelp_zir_len`.
fn current_frame_after_cng(
    signal: &mut [i16],
    transition: AcelpTransition<'_>,
    overlap: i16,
    acelp_zir_len: i16,
    acelp_mem_len: i16,
    fullband_scale: i16,
) {
    let mut tmp_buf = [0i16; L_FRAME_MAX as usize / 2];
    let zir: &[i16] = if fullband_scale == 0 {
        let at = add(overlap, acelp_mem_len).max(0) as usize;
        acelp_zir_from(
            signal,
            at,
            transition.a_zir,
            transition.acelp_zir,
            acelp_zir_len,
        );
        transition.acelp_zir
    } else {
        lerp(
            transition.acelp_zir,
            &mut tmp_buf,
            acelp_zir_len,
            idiv1616_u(shl(acelp_zir_len, LD_FSCALE_DENOM), fullband_scale),
        );
        &tmp_buf
    };

    for i in 0..acelp_zir_len.max(0) {
        let iu = i as usize;
        signal[iu] = add(
            mult_r(signal[iu], div_s(i, acelp_zir_len)),
            mult_r(zir[iu], div_s(sub(acelp_zir_len, i), acelp_zir_len)),
        );
    }
}

/// After an ACELP frame: time-domain aliasing cancellation with the past synthesis over the
/// transition window, then the TCX frame's own ZIR replaced by the ACELP one.
fn current_frame_after_acelp(
    signal: &mut [i16],
    transition: AcelpTransition<'_>,
    window_trans: &[PWord16],
    overlap: i16,
    acelp_zir_len: i16,
    acelp_mem_len: i16,
    fullband_scale: i16,
) {
    let old_syn = transition.old_syn;
    let tmp = sub(overlap, acelp_mem_len).max(0) as usize;
    signal[..tmp].fill(0);

    let start = sub(overlap, acelp_mem_len).max(0) as usize;
    let zl = acelp_zir_len.max(0) as usize;
    if fullband_scale == 0 {
        let tmp = shl(acelp_mem_len, 1).max(0) as usize;
        let mem_len = acelp_mem_len.max(0) as usize;

        // OLA with ACELP
        for i in 0..mem_len {
            let w = window_trans[i].v;
            // window decoded TCX with aliasing
            let mut tmp2 = mult_r(signal[i + start], w.im);
            // Time TDAC: 1)forward part of ACELP
            tmp2 = add(tmp2, mult_r(old_syn[zl + i - tmp], mult_r(w.re, w.re)));
            // Time TDAC: 1)reward part of ACELP
            tmp2 = add(tmp2, mult_r(old_syn[zl - i - 1], mult_r(w.im, w.re)));
            signal[i + start] = tmp2;
        }
        for i in mem_len..tmp {
            let w = window_trans[tmp - 1 - i].v;
            let mut tmp2 = mult_r(signal[i + start], w.re);
            tmp2 = add(tmp2, mult_r(old_syn[zl + i - tmp], mult_r(w.im, w.im)));
            tmp2 = add(tmp2, mult_r(old_syn[zl - i - 1], mult_r(w.re, w.im)));
            signal[i + start] = tmp2;
        }

        let m = M as usize;
        let at = (overlap + acelp_mem_len).max(0) as usize - m;
        for i in 0..m {
            signal[at + i] = sub(signal[at + i], old_syn[zl - m + i]);
        }
    }
    // ZIR at the end of the ACELP frame
    let mut acelp_zir_len: i16 = 64;
    let at = add(overlap, acelp_mem_len).max(0) as usize;

    let mut tmp_buf = [0i16; L_FRAME_MAX as usize / 2];
    let zir: &mut [i16] = if fullband_scale == 0 {
        acelp_zir_from(
            signal,
            at,
            transition.a_zir,
            transition.acelp_zir,
            acelp_zir_len,
        );
        transition.acelp_zir
    } else {
        let tmp = extract_l(l_shr(
            l_mult0(acelp_zir_len, fullband_scale),
            LD_FSCALE_DENOM,
        ));
        lerp(transition.acelp_zir, &mut tmp_buf, tmp, acelp_zir_len);
        acelp_zir_len = tmp;
        let zir = &mut tmp_buf[..];

        if sub(acelp_zir_len, 2 * 64) >= 0 {
            // apply a simple low-pass to the ZIR, to avoid potentially unmasked HF content
            let n = acelp_zir_len as usize;
            for i in 2..n {
                let mut l_tmp = l_mult(zir[i - 2], 8192);
                l_tmp = l_mac(l_tmp, zir[i - 1], 11469);
                zir[i] = mac_r(l_tmp, zir[i], 13107);
            }

            let mut l_tmp = l_mult(zir[n - 1], 13107);
            l_tmp = l_mac(l_tmp, zir[n - 1], 11469);
            zir[n - 1] = mac_r(l_tmp, zir[n - 2], 8192);
            l_tmp = l_mult(zir[n - 2], 13107);
            l_tmp = l_mac(l_tmp, zir[n - 1], 11469);
            zir[n - 2] = mac_r(l_tmp, zir[n - 1], 8192);
            for i in (0..n - 2).rev() {
                let mut l_tmp = l_mult(zir[i], 13107);
                l_tmp = l_mac(l_tmp, zir[i + 1], 11469);
                zir[i] = mac_r(l_tmp, zir[i + 2], 8192);
            }
        }
        zir
    };

    for i in 0..acelp_zir_len.max(0) {
        let iu = i as usize;
        // remove reconstructed ZIR and add ACELP ZIR
        signal[iu + at] = sub(
            signal[iu + at],
            mult_r(zir[iu], div_s(sub(acelp_zir_len, i), acelp_zir_len)),
        );
    }
}

/// `tcx_windowing_synthesis_past_frame`: window the right part of the past frame's overlap
/// `signal` for `right_mode` (the current frame's left mode): minimum (2), half (3) or full
/// overlap.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
pub fn tcx_windowing_synthesis_past_frame(
    signal: &mut [i16],
    window: &[PWord16],
    window_half: &[PWord16],
    window_min: &[PWord16],
    window_length: i16,
    window_half_length: i16,
    window_min_length: i16,
    right_mode: i16,
) {
    if sub(right_mode, 2) == 0 {
        // min. overlap
        let mut at = shr(sub(window_length, window_min_length), 1).max(0) as usize;
        let n = shr(window_min_length, 1).max(0) as usize;
        for i in 0..n {
            signal[at] = mult_r(signal[at], window_min[i].v.re);
            at += 1;
        }
        for i in 0..n {
            signal[at] = mult_r(signal[at], window_min[n - 1 - i].v.im);
            at += 1;
        }
        let n = shr(sub(window_length, window_min_length), 1).max(0) as usize;
        signal[at..at + n].fill(0);
    } else if sub(right_mode, 3) == 0 {
        // half OL
        let mut i = shr(sub(window_length, window_half_length), 1).max(0) as usize;
        let n = shr(window_half_length, 1).max(0) as usize;
        let half = (window_half_length / 2).max(0) as usize;
        for w in 0..n {
            signal[i] = mult_r(signal[i], window_half[w].v.re);
            i += 1;
        }
        for w in 0..n {
            signal[i] = mult_r(signal[i], window_half[half - 1 - w].v.im);
            i += 1;
        }
        let wl = window_length.max(0) as usize;
        if i < wl {
            signal[i..wl].fill(0);
        }
    } else {
        // normal full/maximum overlap
        let n = shr(window_length, 1).max(0) as usize;
        let wl = window_length.max(0) as usize;
        for i in 0..n {
            signal[i] = mult_r(signal[i], window[i].v.re);
            signal[wl - 1 - i] = mult_r(signal[wl - 1 - i], window[i].v.im);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_inverse_frame_length_is_q21() {
        // 1/256 in Q21 is 8192, 1/320 is 6553.6 (truncated by the table and the final shift)
        assert_eq!(get_inv_frame_len(256), 8192);
        assert_eq!(get_inv_frame_len(320), 6553);
    }
}
