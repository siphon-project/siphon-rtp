//! `IMDCT` of TS 26.442 `lib_dec/dec_tcx.c` (TS 26.445 §6.2.2.3.11 inverse MDCT, §6.2.2.3.12
//! windowing and overlap-add): the inverse transform of a TCX frame or of its two TCX-10
//! sub-frames, the windowing with the past frame and the update of the ALDO window memories, at
//! the core rate (`fullband == false`) or at the output rate.

use super::at;
use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    ACELP_CORE, FULL_OVERLAP, L_FRAME_PLUS, MIN_OVERLAP, N_MAX, N_ZERO_MDCT_NS, TCX_IMDCT_HEADROOM,
    TCX_IMDCT_SCALE, TRANSITION_OVERLAP,
};
use crate::evs::com::basop_util::{imult1616, sqrt16};
use crate::evs::com::edct::edct;
use crate::evs::com::tcx_mdct::tcx_mdct_inverse;
use crate::evs::com::tcx_utils::{
    tcx_windowing_synthesis_current_frame, tcx_windowing_synthesis_past_frame, AcelpTransition,
};
use crate::evs::com::tools::set16;
use crate::evs::com::window_ola::window_ola;
use crate::evs::dec::state::DecoderState;
use crate::evs::macros::ns2sa_fx2;
use crate::evs::rom::types::PWord16;
use crate::itu::basic_ops::{add, mult_r, negate, shl, shr, sub};

/// The scalars `decoder_tcx` hands to `IMDCT`.
pub(super) struct ImdctArgs {
    pub x_e: i16,
    pub index: i16,
    pub left_rect: i16,
    pub tcx_offset: i16,
    pub overlap: i16,
    pub l_frame: i16,
    pub l_frame_tcx: i16,
    pub l_spec_tcx5: i16,
    pub l_frame_glob: i16,
    pub frame_cnt: i16,
    pub bfi: i16,
    pub fullband_scale: i16,
}

/// The windows and window lengths of the rate being synthesised.
struct Windows<'a> {
    aldo_window_1: &'a [i16],
    aldo_window_1_trunc: &'a [PWord16],
    aldo_window_2: &'a [PWord16],
    half: &'a [PWord16],
    minimum: &'a [PWord16],
    trans: &'a [PWord16],
    half_length: i16,
    min_length: i16,
}

/// What `IMDCT` reads of the decoder besides the windows and the memories it updates.
struct Context<'a> {
    w: Windows<'a>,
    a: &'a ImdctArgs,
    /// `st->old_syn_Overl`: the past ACELP synthesis.
    old_syn_overl: &'a [i16],
    /// `st->old_Aq_12_8_fx`: the LP filter of the ACELP zero-input response.
    a_zir: &'a [i16],
    last_core_bfi: i16,
    last_is_cng: i8,
    last_core: i16,
    prev_bfi: i16,
    last_overlap_mode: i16,
    curr_overlap_mode: i16,
    last_aldo: i16,
    /// `shr(st->L_frameTCX, 1) == L_frameTCX && st->tcxonly`: a TCX-10 frame.
    short: bool,
    nz: i16,
    tmp_offset: i16,
    /// The spectrum is the 32-bit view of the memory `xn_buf` is the 16-bit view of.
    overlaid: bool,
}

/// The spectrum as the reference's `Word32 *x` sees it: `x`, or, when the spectrum shares its
/// memory with `xn_buf` (the core-rate call), the 32-bit words of the memory `xn_buf` is right now
/// (little endian), so every write to `xn_buf` since the spectrum was copied in shows in it, as
/// the first TCX-5 transform of a grouped TCX-10 frame sees its lowest lines zeroed by the
/// reference's own `set16(xn_buf, 0, ...)`.
fn spectrum_view<'a>(
    ctx: &Context<'_>,
    x: &'a [i32],
    xn_buf: &[i16],
    image: &'a mut [i32; N_MAX as usize],
) -> &'a [i32] {
    if !ctx.overlaid {
        return x;
    }
    for (word, pair) in image.iter_mut().zip(xn_buf.as_chunks::<2>().0) {
        *word = i32::from(pair[0] as u16) | (i32::from(pair[1]) << 16);
    }
    image
}

/// `IMDCT`: transform the spectrum `x` (exponent `args.x_e`) to the time signal `xn_buf`
/// (`overlap` samples of overlap with the previous frame, `L_frame + overlap` in all), overlap
/// and add the past frame, and keep what the next frame needs: `syn_Overl` (the overlap),
/// `old_out` / `Q_old_wtda` (the windowed synthesis for an ALDO window) and `last_aldo`.
pub(super) fn imdct(
    x: &[i32],
    xn_buf: &mut [i16],
    acelp_zir: &mut [i16],
    st: &mut DecoderState,
    fullband: bool,
    args: &ImdctArgs,
) {
    let DecoderState {
        tcx_cfg,
        syn_overl,
        syn_overl_tdac,
        syn_overl_fb,
        syn_overl_tdacfb,
        old_out,
        q_old_wtda,
        old_out_lb,
        q_old_wtda_lb,
        old_syn_overl,
        old_aq_12_8,
        last_core_bfi,
        last_is_cng,
        sr_core,
        output_fs,
        l_frame_tcx,
        tcxonly,
        last_core,
        prev_bfi,
        ..
    } = st;

    // the memories of the rate being synthesised
    let (syn_overlap, syn_overl_tdac, old_out, q_old_wtda): (
        &mut [i16],
        &[i16],
        &mut [i16],
        &mut i16,
    ) = if fullband {
        (syn_overl_fb, syn_overl_tdacfb, old_out, q_old_wtda)
    } else {
        (syn_overl, syn_overl_tdac, old_out_lb, q_old_wtda_lb)
    };

    let windows = if fullband {
        Windows {
            aldo_window_1: &tcx_cfg.tcx_aldo_window_1_fb,
            aldo_window_1_trunc: &tcx_cfg.tcx_aldo_window_1_fb_trunc,
            aldo_window_2: &tcx_cfg.tcx_aldo_window_2_fb,
            half: tcx_cfg.tcx_mdct_window_half_fb,
            minimum: tcx_cfg.tcx_mdct_window_minimum_fb,
            trans: tcx_cfg.tcx_mdct_window_trans_fb,
            half_length: tcx_cfg.tcx_mdct_window_half_length_fb,
            min_length: tcx_cfg.tcx_mdct_window_min_length_fb,
        }
    } else {
        Windows {
            aldo_window_1: &tcx_cfg.tcx_aldo_window_1,
            aldo_window_1_trunc: &tcx_cfg.tcx_aldo_window_1_trunc,
            aldo_window_2: &tcx_cfg.tcx_aldo_window_2,
            half: tcx_cfg.tcx_mdct_window_half,
            minimum: tcx_cfg.tcx_mdct_window_minimum,
            trans: tcx_cfg.tcx_mdct_window_trans,
            half_length: tcx_cfg.tcx_mdct_window_half_length,
            min_length: tcx_cfg.tcx_mdct_window_min_length,
        }
    };

    // number of zero for ALDO windows
    let nz = ns2sa_fx2(
        if args.fullband_scale != 0 {
            *output_fs
        } else {
            *sr_core
        },
        N_ZERO_MDCT_NS,
    );

    let mut tmp_offset = 0;
    if args.tcx_offset < 0 {
        tmp_offset = negate(args.tcx_offset);
    }

    let ctx = Context {
        w: windows,
        a: args,
        old_syn_overl,
        a_zir: old_aq_12_8,
        last_core_bfi: *last_core_bfi,
        last_is_cng: *last_is_cng,
        last_core: *last_core,
        prev_bfi: *prev_bfi,
        last_overlap_mode: tcx_cfg.tcx_last_overlap_mode,
        curr_overlap_mode: tcx_cfg.tcx_curr_overlap_mode,
        last_aldo: tcx_cfg.last_aldo,
        short: sub(args.l_frame_tcx, shr(*l_frame_tcx, 1)) == 0 && *tcxonly != 0,
        nz,
        tmp_offset,
        overlaid: !fullband,
    };

    let mut aldo: i16 = 0;
    if ctx.short {
        imdct_tcx10(&ctx, x, xn_buf, acelp_zir, syn_overl_tdac);
    } else {
        aldo = imdct_tcx20(
            &ctx,
            x,
            xn_buf,
            acelp_zir,
            syn_overl_tdac,
            old_out,
            q_old_wtda,
        );
    }

    aldo = imdct_overlap_add_past(
        &ctx,
        xn_buf,
        syn_overlap,
        old_out,
        q_old_wtda,
        aldo,
        *l_frame_tcx,
    );

    if args.fullband_scale != 0 {
        tcx_cfg.last_aldo = aldo;
    }

    imdct_smooth_after_acelp_plc(&ctx, xn_buf, syn_overlap);
}

/// The TCX-10 sub-frame(s): two TCX-5 transforms grouped into one window, or one TCX-10
/// transform.
fn imdct_tcx10(
    ctx: &Context<'_>,
    x: &[i32],
    xn_buf: &mut [i16],
    acelp_zir: &mut [i16],
    syn_overl_tdac: &[i16],
) {
    let a = ctx.a;
    // Mode decision in PLC (last overlap / current overlap -> left and right TCX-10 sub-window)
    if (a.bfi == 0 && ctx.last_overlap_mode != FULL_OVERLAP)
        || (a.bfi != 0
            && ctx.last_overlap_mode != FULL_OVERLAP
            && ctx.curr_overlap_mode != FULL_OVERLAP)
    {
        imdct_tcx10_grouped(ctx, x, xn_buf, acelp_zir, syn_overl_tdac);
    } else if a.bfi == 0 && a.frame_cnt == 0 && ctx.curr_overlap_mode == FULL_OVERLAP {
        imdct_tcx10_special_overlap(ctx, x, xn_buf, acelp_zir, syn_overl_tdac);
    } else {
        // default i.e. maximum overlap, single transform, no grouping
        let mut image = [0i32; N_MAX as usize];
        tcx_mdct_inverse(
            spectrum_view(ctx, x, xn_buf, &mut image),
            sub(a.x_e, TCX_IMDCT_SCALE + TCX_IMDCT_HEADROOM),
            xn_buf,
            a.overlap,
            sub(a.l_frame, a.overlap),
            a.overlap,
        );

        let mut tmp1 = a.index;
        if a.bfi == 0 && a.frame_cnt > 0 && a.index == 0 && ctx.last_core != ACELP_CORE {
            tmp1 = MIN_OVERLAP;
        }

        let mut tmp3 = ctx.last_core_bfi;
        if a.frame_cnt > 0 {
            tmp3 = 1;
        }

        let mut tmp8 = ctx.last_is_cng;
        if a.frame_cnt > 0 {
            tmp8 = 0;
        }

        tcx_windowing_synthesis_current_frame(
            xn_buf,
            ctx.w.aldo_window_2,
            ctx.w.half,
            ctx.w.minimum,
            a.overlap,
            ctx.w.half_length,
            ctx.w.min_length,
            a.left_rect,
            tmp1,
            Some(AcelpTransition {
                acelp_zir,
                old_syn: ctx.old_syn_overl,
                syn_overl: syn_overl_tdac,
                a_zir: ctx.a_zir,
            }),
            ctx.w.trans,
            shr(a.l_frame_glob, 1),
            ctx.tmp_offset,
            tmp3,
            tmp8,
            a.fullband_scale,
        );
    }
}

/// Minimum or half overlap: two TCX-5 transforms, grouped into one window.
fn imdct_tcx10_grouped(
    ctx: &Context<'_>,
    x: &[i32],
    xn_buf: &mut [i16],
    acelp_zir: &mut [i16],
    syn_overl_tdac: &[i16],
) {
    let a = ctx.a;
    let mut win = [0i16; (L_FRAME_PLUS as usize + 420) / 2]; // (L_FRAME_PLUS+L_MDCT_OVLP_MAX)/2

    let l_win = shr(a.l_frame, 1);
    let mut l_ola = ctx.w.half_length;
    if sub(ctx.last_overlap_mode, MIN_OVERLAP) == 0 {
        l_ola = ctx.w.min_length;
    }

    set16(xn_buf, 0, add(a.tcx_offset, shr(l_ola, 1))); // zero left end of buffer

    for w in 0..2i16 {
        let mut image = [0i32; N_MAX as usize];
        tcx_mdct_inverse(
            &spectrum_view(ctx, x, xn_buf, &mut image)
                [at(i32::from(w) * i32::from(a.l_spec_tcx5))..],
            sub(a.x_e, TCX_IMDCT_SCALE + TCX_IMDCT_HEADROOM),
            &mut win,
            l_ola,
            sub(l_win, l_ola),
            l_ola,
        );

        let mut tmp1 = a.left_rect;
        let mut tmp2 = ctx.last_overlap_mode;
        let mut tmp3 = ctx.last_core_bfi;
        let mut tmp8 = ctx.last_is_cng;
        if w > 0 {
            tmp1 = 0;
            tmp2 = MIN_OVERLAP;
            tmp3 = 1;
            tmp8 = 0;
        }
        if w == 0 && sub(a.index, 2) == 0 {
            tmp2 = MIN_OVERLAP;
        }
        if a.frame_cnt > 0 {
            tmp3 = 1;
            tmp8 = 0;
        }

        tcx_windowing_synthesis_current_frame(
            &mut win,
            ctx.w.aldo_window_2,
            ctx.w.half,
            ctx.w.minimum,
            l_ola,
            ctx.w.half_length,
            ctx.w.min_length,
            tmp1,
            tmp2,
            Some(AcelpTransition {
                acelp_zir,
                old_syn: ctx.old_syn_overl,
                syn_overl: syn_overl_tdac,
                a_zir: ctx.a_zir,
            }),
            ctx.w.trans,
            l_win,
            ctx.tmp_offset,
            tmp3,
            tmp8,
            a.fullband_scale,
        );

        let start =
            i32::from(a.tcx_offset) - i32::from(shr(l_ola, 1)) + i32::from(imult1616(w, l_win));
        if w > 0 {
            tcx_windowing_synthesis_past_frame(
                &mut xn_buf[at(start)..],
                ctx.w.aldo_window_1_trunc,
                ctx.w.half,
                ctx.w.minimum,
                l_ola,
                ctx.w.half_length,
                ctx.w.min_length,
                MIN_OVERLAP,
            );
        }
        // add part of current sub-window overlapping with previous window
        let start =
            at(i32::from(a.tcx_offset) - i32::from(shr(l_ola, 1))
                + i32::from(w) * i32::from(l_win));
        for i in 0..at(i32::from(l_ola)) {
            xn_buf[start + i] = add(win[i], xn_buf[start + i]);
        }
        // copy new sub-window region not overlapping with previous window
        let to = at(i32::from(a.tcx_offset)
            + i32::from(shr(l_ola, 1))
            + i32::from(w) * i32::from(l_win));
        let (l_ola_u, l_win_u) = (at(i32::from(l_ola)), at(i32::from(l_win)));
        xn_buf[to..to + l_win_u].copy_from_slice(&win[l_ola_u..l_ola_u + l_win_u]);
    }

    // To assure that no garbage values are passed to overlap
    let from = at(i32::from(a.l_frame) + i32::from(a.tcx_offset) + i32::from(shr(l_ola, 1)));
    set16(
        &mut xn_buf[from..],
        0,
        sub(sub(a.overlap, a.tcx_offset), shr(l_ola, 1)),
    );
}

/// Two TCX-5 transforms with the minimum overlap between them and the maximum overlap on the
/// left (the special overlap of a TCX-10 frame after a full overlap TCX frame).
fn imdct_tcx10_special_overlap(
    ctx: &Context<'_>,
    x: &[i32],
    xn_buf: &mut [i16],
    acelp_zir: &mut [i16],
    syn_overl_tdac: &[i16],
) {
    let a = ctx.a;
    let mut win = [0i16; (L_FRAME_PLUS as usize + 420) / 2];

    // special overlap attempt, two transforms, grouping into one window
    let l_win = shr(a.l_frame, 1);
    let l_ola = ctx.w.min_length;
    let (l_win_u, l_ola_u) = (at(i32::from(l_win)), at(i32::from(l_ola)));
    let half_overlap = at(i32::from(shr(a.overlap, 1)));

    // 1st TCX-5 window, special MDCT with minimum overlap on right side
    let mut image = [0i32; N_MAX as usize];
    tcx_mdct_inverse(
        spectrum_view(ctx, x, xn_buf, &mut image),
        sub(a.x_e, TCX_IMDCT_SCALE + TCX_IMDCT_HEADROOM),
        &mut win[l_win_u..],
        0,
        sub(l_win, shr(l_ola, 1)),
        l_ola,
    );

    set16(xn_buf, 0, shr(a.overlap, 1));
    // copy new sub-window region not overlapping with previous window
    let n = at(i32::from(add(l_win, shr(l_ola, 1))));
    xn_buf[half_overlap..half_overlap + n].copy_from_slice(&win[l_win_u..l_win_u + n]);

    // 2nd TCX-5 window, regular MDCT with minimum overlap on both sides
    let mut image = [0i32; N_MAX as usize];
    tcx_mdct_inverse(
        &spectrum_view(ctx, x, xn_buf, &mut image)[at(i32::from(a.l_spec_tcx5))..],
        sub(a.x_e, TCX_IMDCT_SCALE + TCX_IMDCT_HEADROOM),
        &mut win,
        l_ola,
        sub(l_win, l_ola),
        l_ola,
    );

    tcx_windowing_synthesis_current_frame(
        &mut win,
        ctx.w.aldo_window_2,
        ctx.w.half,
        ctx.w.minimum,
        l_ola,
        ctx.w.half_length,
        ctx.w.min_length,
        0,           // left_rect
        MIN_OVERLAP, // left_mode
        Some(AcelpTransition {
            acelp_zir,
            old_syn: ctx.old_syn_overl,
            syn_overl: syn_overl_tdac,
            a_zir: ctx.a_zir,
        }),
        ctx.w.trans,
        l_win,
        ctx.tmp_offset,
        1, // st->last_core_bfi
        0, // st->last_is_cng
        a.fullband_scale,
    );

    let past = at(i32::from(sub(l_win, shr(l_ola, 1))) + i32::from(shr(a.overlap, 1)));
    tcx_windowing_synthesis_past_frame(
        &mut xn_buf[past..],
        ctx.w.aldo_window_1_trunc,
        ctx.w.half,
        ctx.w.minimum,
        l_ola,
        ctx.w.half_length,
        ctx.w.min_length,
        MIN_OVERLAP,
    );

    // add part of current sub-window overlapping with previous window
    for i in 0..l_ola_u {
        xn_buf[past + i] = add(xn_buf[past + i], win[i]);
    }

    // copy new sub-window region not overlapping with previous window
    let to = half_overlap + at(i32::from(shr(l_ola, 1))) + l_win_u;
    xn_buf[to..to + l_win_u].copy_from_slice(&win[l_ola_u..l_ola_u + l_win_u]);

    // extra folding-out on left side of win, for perfect reconstruction
    for w in shr(a.overlap, 1)..a.overlap {
        xn_buf[at(i32::from(a.overlap) - 1 - i32::from(w))] = negate(xn_buf[at(i32::from(w))]);
    }

    tcx_windowing_synthesis_current_frame(
        xn_buf,
        ctx.w.aldo_window_2,
        ctx.w.half,
        ctx.w.minimum,
        a.overlap,
        ctx.w.half_length,
        ctx.w.min_length,
        a.left_rect,
        0, // left_mode
        Some(AcelpTransition {
            acelp_zir,
            old_syn: ctx.old_syn_overl,
            syn_overl: syn_overl_tdac,
            a_zir: ctx.a_zir,
        }),
        ctx.w.trans,
        shl(l_win, 1),
        ctx.tmp_offset,
        ctx.last_core_bfi,
        ctx.last_is_cng,
        a.fullband_scale,
    );
}

/// A TCX-20 frame (or a TCX-10 frame of a codec that is not TCX-only): the ALDO window with the
/// transform of the whole frame, or, right after an ACELP frame, the sine window with the
/// transition window. Returns whether the ALDO window was used.
fn imdct_tcx20(
    ctx: &Context<'_>,
    x: &[i32],
    xn_buf: &mut [i16],
    acelp_zir: &mut [i16],
    syn_overl_tdac: &[i16],
    old_out: &mut [i16],
    q_old_wtda: &mut i16,
) -> i16 {
    let a = ctx.a;
    if sub(ctx.last_overlap_mode, TRANSITION_OVERLAP) != 0 {
        let mut tmp_buf = [0i32; L_FRAME_PLUS as usize];

        // DCT
        let mut q = sub(31, a.x_e);
        let mut image = [0i32; N_MAX as usize];
        edct(
            spectrum_view(ctx, x, xn_buf, &mut image),
            &mut tmp_buf,
            a.l_frame,
            &mut q,
        );

        // scale by sqrt(L / NORM_MDCT_FACTOR)
        let mut tmp1 = mult_r(
            shl(a.l_frame, 4),
            26214, /* 128.f / NORM_MDCT_FACTOR Q15 */
        ); // 4Q11
        let mut tmp2: i16 = 4;
        tmp1 = sqrt16(tmp1, &mut tmp2);

        for value in &mut tmp_buf[..at(i32::from(a.l_frame))] {
            *value = mpy_32_16_1(*value, tmp1);
        }
        q = sub(q, tmp2);

        window_ola(
            &tmp_buf,
            xn_buf,
            &mut q,
            old_out,
            q_old_wtda,
            a.l_frame,
            ctx.last_overlap_mode,
            ctx.curr_overlap_mode,
            0,
            0,
            None,
        );

        // scale output
        let l_frame = at(i32::from(a.l_frame));
        if q <= 0 {
            for value in &mut xn_buf[..l_frame] {
                *value = shr(*value, q);
            }
        } else {
            let tmp1 = shr(0x4000, sub(q, 1));
            for value in &mut xn_buf[..l_frame] {
                *value = mult_r(*value, tmp1);
            }
        }

        1
    } else {
        let mut image = [0i32; N_MAX as usize];
        tcx_mdct_inverse(
            spectrum_view(ctx, x, xn_buf, &mut image),
            sub(a.x_e, TCX_IMDCT_SCALE + TCX_IMDCT_HEADROOM),
            xn_buf,
            a.overlap,
            sub(a.l_frame, a.overlap),
            a.overlap,
        );

        // Windowing, overlap and add: window current frame
        tcx_windowing_synthesis_current_frame(
            xn_buf,
            ctx.w.aldo_window_2,
            ctx.w.half,
            ctx.w.minimum,
            a.overlap,
            ctx.w.half_length,
            ctx.w.min_length,
            a.left_rect,
            ctx.last_overlap_mode,
            Some(AcelpTransition {
                acelp_zir,
                old_syn: ctx.old_syn_overl,
                syn_overl: syn_overl_tdac,
                a_zir: ctx.a_zir,
            }),
            ctx.w.trans,
            shr(a.l_frame_glob, 1),
            ctx.tmp_offset,
            ctx.last_core_bfi,
            ctx.last_is_cng,
            a.fullband_scale,
        );
        0
    }
}

/// Window and overlap-add the past frame when it was TCX, apply the output headroom, and keep the
/// windowed synthesis for an ALDO window in the next frame. Returns the updated `aldo`.
fn imdct_overlap_add_past(
    ctx: &Context<'_>,
    xn_buf: &mut [i16],
    syn_overlap: &mut [i16],
    old_out: &mut [i16],
    q_old_wtda: &mut i16,
    mut aldo: i16,
    st_l_frame_tcx: i16,
) -> i16 {
    let a = ctx.a;
    let mut index = a.index;
    let l_frame = at(i32::from(a.l_frame));

    // Window and overlap-add past frame if past frame is TCX
    if a.frame_cnt != 0 || ctx.last_core_bfi > ACELP_CORE {
        if ctx.short || sub(ctx.last_overlap_mode, TRANSITION_OVERLAP) == 0 {
            if a.bfi == 0
                && a.frame_cnt > 0
                && index == 0
                && ctx.curr_overlap_mode == FULL_OVERLAP
                && ctx.last_core != ACELP_CORE
            {
                index = MIN_OVERLAP; // use minimum overlap between the two TCX-10 windows
            }

            if ctx.last_aldo != 0 {
                overlap_add_past_after_aldo(ctx, xn_buf, old_out, *q_old_wtda);
            } else {
                overlap_add_past_after_sine(ctx, xn_buf, syn_overlap, index);
            }
        }
    } else if aldo == 0 {
        for value in &mut xn_buf[..l_frame] {
            *value = shl(*value, TCX_IMDCT_HEADROOM);
        }
    }

    if aldo == 0
        && ((sub(a.l_frame_tcx, shr(st_l_frame_tcx, 1)) == 0 && a.frame_cnt > 0)
            || sub(a.l_frame_tcx, shr(st_l_frame_tcx, 1)) != 0)
    {
        // Compute windowed synthesis in case of switching to ALDO windows in next frame
        let nz = at(i32::from(ctx.nz));
        let overlap = at(i32::from(a.overlap));
        for i in 0..nz {
            old_out[i] = shr(xn_buf[l_frame - nz + i], TCX_IMDCT_HEADROOM);
        }
        old_out[nz..nz + overlap].copy_from_slice(&xn_buf[l_frame..l_frame + overlap]);
        old_out[nz + overlap..nz + overlap + nz].fill(0);

        tcx_windowing_synthesis_past_frame(
            &mut old_out[nz..],
            ctx.w.aldo_window_1_trunc,
            ctx.w.half,
            ctx.w.minimum,
            a.overlap,
            ctx.w.half_length,
            ctx.w.min_length,
            ctx.curr_overlap_mode,
        );

        // If current overlap mode = FULL_OVERLAP -> ALDO_WINDOW
        if sub(ctx.curr_overlap_mode, FULL_OVERLAP) == 0 {
            for i in 0..nz {
                old_out[nz + overlap + i] = shr(
                    mult_r(xn_buf[l_frame - 1 - i], ctx.w.aldo_window_1[nz - 1 - i]),
                    TCX_IMDCT_HEADROOM,
                );
            }
            aldo = 1;
        }

        *q_old_wtda = -TCX_IMDCT_HEADROOM;
    }
    aldo
}

/// The past frame was ALDO windowed: add its stored tail (`old_out`) over the overlap, fading the
/// truncated window.
fn overlap_add_past_after_aldo(
    ctx: &Context<'_>,
    xn_buf: &mut [i16],
    old_out: &[i16],
    q_old_wtda: i16,
) {
    let a = ctx.a;
    let nz = i32::from(ctx.nz);
    let tmp2 = add(q_old_wtda, TCX_IMDCT_HEADROOM);
    let tmp4 = sub(shr(a.overlap, 1), a.tcx_offset);
    let old = |i: i16| old_out[at(i32::from(i) + nz)];

    for i in 0..tmp4 {
        xn_buf[at(i32::from(i))] = shl(xn_buf[at(i32::from(i))], TCX_IMDCT_HEADROOM);
    }

    let mut i: i16 = 0;
    let tmp1 = sub(a.overlap, ctx.w.min_length);
    while i < tmp1 {
        let k = at(i32::from(i) + i32::from(tmp4));
        xn_buf[k] = shl(add(xn_buf[k], shr(old(i), tmp2)), TCX_IMDCT_HEADROOM);
        i += 1;
    }

    // fade truncated ALDO window
    let tmp1 = sub(a.overlap, shr(ctx.w.min_length, 1));
    while i < tmp1 {
        let k = at(i32::from(i) + i32::from(tmp4));
        let window =
            ctx.w.minimum[at(i32::from(i) - i32::from(a.overlap) + i32::from(ctx.w.min_length))];
        let tmp3 = mult_r(shr(old(i), tmp2), window.v.re);
        xn_buf[k] = shl(add(xn_buf[k], tmp3), TCX_IMDCT_HEADROOM);
        i += 1;
    }
    while i < a.overlap {
        let k = at(i32::from(i) + i32::from(tmp4));
        let window = ctx.w.minimum[at(i32::from(a.overlap) - 1 - i32::from(i))];
        let tmp3 = mult_r(shr(old(i), tmp2), window.v.im);
        xn_buf[k] = shl(add(xn_buf[k], tmp3), TCX_IMDCT_HEADROOM);
        i += 1;
    }

    let mut i = add(i, tmp4);
    while i < a.l_frame {
        xn_buf[at(i32::from(i))] = shl(xn_buf[at(i32::from(i))], TCX_IMDCT_HEADROOM);
        i += 1;
    }
}

/// The past frame was sine windowed: window its overlap (`syn_overlap`, in place) and add it to
/// the start of the frame, applying the output headroom.
fn overlap_add_past_after_sine(
    ctx: &Context<'_>,
    xn_buf: &mut [i16],
    syn_overlap: &mut [i16],
    index: i16,
) {
    let a = ctx.a;
    let mut tmp1 = index;
    if index == 0 || sub(ctx.last_overlap_mode, MIN_OVERLAP) == 0 {
        tmp1 = ctx.last_overlap_mode;
    }

    tcx_windowing_synthesis_past_frame(
        syn_overlap,
        ctx.w.aldo_window_1_trunc,
        ctx.w.half,
        ctx.w.minimum,
        a.overlap,
        ctx.w.half_length,
        ctx.w.min_length,
        tmp1,
    );

    // BASOP_SATURATE_WARNING_OFF
    let ix = |i: i16, offset: i16| at(i32::from(i) + i32::from(offset));
    if a.bfi != 0 {
        let tmp1 = sub(shr(a.overlap, 1), a.tcx_offset);
        let tmp3 = shr(ctx.w.half_length, 1);
        for i in 0..tmp1 {
            xn_buf[ix(i, 0)] = shl(xn_buf[ix(i, 0)], TCX_IMDCT_HEADROOM);
        }
        let mut i: i16 = 0;
        while i < tmp3 {
            let tmp2 = add(
                xn_buf[ix(i, tmp1)],
                mult_r(syn_overlap[ix(i, 0)], ctx.w.half[ix(i, 0)].v.re),
            );
            xn_buf[ix(i, tmp1)] = shl(tmp2, TCX_IMDCT_HEADROOM);
            i += 1;
        }
        while i < ctx.w.half_length {
            let window = ctx.w.half[at(i32::from(ctx.w.half_length) - 1 - i32::from(i))];
            let tmp2 = add(
                xn_buf[ix(i, tmp1)],
                mult_r(syn_overlap[ix(i, 0)], window.v.im),
            );
            xn_buf[ix(i, tmp1)] = shl(tmp2, TCX_IMDCT_HEADROOM);
            i += 1;
        }
        if sub(add(i, tmp1), a.l_frame) < 0 {
            let mut i = add(i, tmp1);
            while i < a.l_frame {
                xn_buf[ix(i, 0)] = shl(xn_buf[ix(i, 0)], TCX_IMDCT_HEADROOM);
                i += 1;
            }
        }
    } else if a.left_rect == 0 {
        let mut i: i16 = 0;
        while i < a.overlap {
            xn_buf[ix(i, 0)] = shl(
                add(xn_buf[ix(i, 0)], syn_overlap[ix(i, 0)]),
                TCX_IMDCT_HEADROOM,
            );
            i += 1;
        }

        if sub(i, a.l_frame) < 0 {
            while i < a.l_frame {
                xn_buf[ix(i, 0)] = shl(xn_buf[ix(i, 0)], TCX_IMDCT_HEADROOM);
                i += 1;
            }
        }
    } else {
        let tmp1 = shr(a.overlap, 1);
        for i in 0..tmp1 {
            xn_buf[ix(i, 0)] = shl(xn_buf[ix(i, 0)], TCX_IMDCT_HEADROOM);
        }

        let mut i: i16 = 0;
        while i < a.overlap {
            xn_buf[ix(i, tmp1)] = shl(
                add(xn_buf[ix(i, tmp1)], syn_overlap[ix(i, 0)]),
                TCX_IMDCT_HEADROOM,
            );
            i += 1;
        }

        if sub(add(i, tmp1), a.l_frame) < 0 {
            let mut i = add(i, tmp1);
            while i < a.l_frame {
                xn_buf[ix(i, 0)] = shl(xn_buf[ix(i, 0)], TCX_IMDCT_HEADROOM);
                i += 1;
            }
        }
    }
}

/// Smoothing between the ACELP PLC and the TCX transition frame, with the shape of the half
/// overlap window for the crossfade.
fn imdct_smooth_after_acelp_plc(ctx: &Context<'_>, xn_buf: &mut [i16], syn_overlap: &[i16]) {
    let a = ctx.a;
    if !(a.left_rect != 0
        && a.frame_cnt == 0
        && sub(ctx.last_core_bfi, ACELP_CORE) == 0
        && ctx.prev_bfi != 0)
    {
        return;
    }
    // both the full-band and the core rate use the same formula on their own memory
    let tmp1 = sub(shr(a.overlap, 1), a.tcx_offset);
    let tmp3 = shr(ctx.w.half_length, 1);
    let half = |i: i16| ctx.w.half[at(i32::from(i))].v;
    let mut i: i16 = 0;
    while i < tmp3 {
        let k = at(i32::from(i) + i32::from(tmp1));
        xn_buf[k] = mult_r(xn_buf[k], half(i).im);
        xn_buf[k] = add(
            xn_buf[k],
            mult_r(
                syn_overlap[at(i32::from(i))],
                mult_r(half(i).re, half(i).re),
            ),
        );
        i += 1;
    }
    while i < ctx.w.half_length {
        let k = at(i32::from(i) + i32::from(tmp1));
        let mirrored = half(sub(sub(ctx.w.half_length, 1), i));
        xn_buf[k] = mult_r(xn_buf[k], mirrored.re);
        xn_buf[k] = add(
            xn_buf[k],
            mult_r(
                syn_overlap[at(i32::from(i))],
                mult_r(mirrored.im, mirrored.im),
            ),
        );
        i += 1;
    }
}
