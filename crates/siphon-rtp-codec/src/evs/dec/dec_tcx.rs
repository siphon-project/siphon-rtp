//! The TCX frame decoder of the MODE2 (LPD) decoder (TS 26.442 `lib_dec/dec_tcx.c`; TS 26.445
//! §6.2.2 TCX decoding, §6.2.4 frame loss concealment): [`decoder_tcx`] decodes one TCX-20 frame
//! or one TCX-10 sub-frame, [`decoder_tcx_post`] finishes the frame (fade-out, memory update).
//!
//! The reference passes the decoder's own `tcx_cfg` into `decoder_tcx` (`&st->tcx_cfg` at both call
//! sites), so the port takes only `st` and reads `st.tcx_cfg`.
//!
//! `xn_buf` and `xn_buf32` overlay the same memory in the reference (`xn_buf = (Word16 *)
//! xn_buf32`), and the core-rate inverse transform reads its spectrum from the 32-bit view while it
//! writes its output through the 16-bit view, so the reference's own writes to the output reach the
//! spectrum (a grouped TCX-10 frame zeroes the lowest lines of its first transform before it reads
//! them). The port keeps the memory as the 16-bit array: the spectrum is copied into it as
//! little-endian halves (`Buffers::sync_overlay`) and the inverse transform reads the 32-bit
//! words back from it (`spectrum_view` in `imdct.rs`), so every write shows, as in the reference.
//! The full-band inverse transform has its own buffer, as in the reference.
//!
//! The reference's `xn_bufFB` is uninitialised; one path (a TCX-10 frame with the special overlap)
//! leaves its tail unwritten and the reference copies that stack residue into `syn_OverlFB`, where
//! it never reaches an output. The port's buffer is zeroed.

mod imdct;
mod itf;
mod post;

pub use post::decoder_tcx_post;

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    ACELP_13K20, ACELP_CORE, FDNS_NPTS, FSCALE_DENOM, FULL_OVERLAP, IGF_GRID_LB_NORM,
    IGF_GRID_LB_SHORT, IGF_GRID_LB_TRAN, LTPSIZE, L_FRAME_PLUS, L_MDCT_OVLP_MAX, L_SUBFR, M,
    MIN_NOISE_FILLING_HOLE, NBITS_NOISE_FILL_LEVEL, NOISE_FILL_RANGES, NPRM_CTX_HM, N_MAX,
    RF_TCXFD, SPEC_EXP_DEC, TCX_10_CORE, TCX_20_CORE, TCX_NONTONAL, TCX_TONAL,
};
use crate::evs::com::basop_util::get_scale_factor32;
use crate::evs::com::basop_util::{
    basop_util_add_mant_exp, basop_util_divide_mant_exp, basop_util_inv_log2, dot_product_sq16_hq,
    isqrt16, norm_ll_q31, sqrt32,
};
use crate::evs::com::codec_tcx_common::{
    tcx_formant_enhancement, tcx_get_noise_filling_tilt, tcx_invert_window_grouping,
};
use crate::evs::com::deemph::deemph;
use crate::evs::com::syn_filt::e_util_synthesis_in_place;
use crate::evs::com::tcx_utils::{
    adapt_low_freq_deemph, get_inv_frame_len, lpc2mdct, mdct_shaping, psych_adapt_low_freq_deemph,
    set_tns_config, tcx_noise_filling, Lpc2MdctOutputs,
};
use crate::evs::com::tns_base::{apply_tns_filter, STnsData};
use crate::evs::com::tools::{copy32, scale_sig32, set16, set32};
use crate::evs::com::weight_a::weight_a;
use crate::evs::dec::arith_coder_dec::envelope::tcx_arith_decode_envelope;
use crate::evs::dec::er_scale_syn::damping_fact;
use crate::evs::dec::fd_cng_dec::generate_masking_noise_mdct;
use crate::evs::dec::igf_dec::{
    igf_dec_apply_mono, igf_dec_copy_lpc_flat_spectrum, igf_dec_update_info,
};
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::tcx_utils_dec::{
    tcx_ari_res_inv_q_spec, tcx_res_inv_q_gain, tcx_res_inv_q_spec,
};
use crate::evs::dec::tns_base_dec::decode_tns_data;
use crate::evs::dec::tonal_mdct_concealment::{
    tonal_mdct_conceal_apply, tonal_mdct_conceal_insert_noise, tonal_mdct_conceal_save_freq_signal,
    tonal_mdct_conceal_update_state,
};
use crate::evs::dec::waveadjust_fec_dec::{concealment_decode_fix, concealment_update_x};
use crate::evs::rom::T_DIV_L_FRAME;
use crate::itu::basic_ops::l_mac;
use crate::itu::basic_ops::{
    abs_s, add, extract_h, extract_l, l_add, l_deposit_h, l_mult, l_shl, l_shr, l_sub, mult,
    mult_r, negate, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{div_l, l_mac0, l_mac_ns, l_msu_ns, l_mult0};

use imdct::{imdct, ImdctArgs};
use itf::igf_flattening;

/// Samples of the 16-bit view of the overlaid buffer: `xn_buf` is `N_MAX` 32-bit words wide.
const XN_BUF_LEN: usize = 2 * N_MAX as usize;
/// `L_MDCT_OVLP_MAX + L_FRAME_PLUS + L_MDCT_OVLP_MAX`: the full-band output buffer.
const XN_BUF_FB_LEN: usize = (L_MDCT_OVLP_MAX + L_FRAME_PLUS + L_MDCT_OVLP_MAX) as usize;

/// A buffer index from a sample count or offset that the reference's range checks keep
/// non-negative (a negative one would read before the buffer in the reference).
pub(crate) fn at(value: i32) -> usize {
    usize::try_from(value).unwrap_or(0)
}

/// The frame-sized work buffers of `decoder_tcx`.
struct Buffers {
    /// `x`: the MDCT spectrum.
    x: [i32; N_MAX as usize],
    /// `xn_buf`: the time signal / the 16-bit view of `xn_buf32`.
    xn_buf: [i16; XN_BUF_LEN],
    /// `xn_buf32`: the 32-bit view of the overlaid buffer, as the spectrum is copied into it and as
    /// `tcx_invert_window_grouping` uses it for scratch; `xn_buf` is the memory itself.
    xn_buf32: [i32; N_MAX as usize],
}

impl Buffers {
    /// The reference zeroes `xn_buf32[0..(L_MDCT_OVLP_MAX+L_FRAME_PLUS+L_MDCT_OVLP_MAX)/2]`, which
    /// is the same memory as `xn_buf[0..L_MDCT_OVLP_MAX+L_FRAME_PLUS+L_MDCT_OVLP_MAX]`; the rest of
    /// it is not read before it is written.
    fn new() -> Self {
        Self {
            x: [0; N_MAX as usize],
            xn_buf: [0; XN_BUF_LEN],
            xn_buf32: [0; N_MAX as usize],
        }
    }

    /// After a write of `xn_buf32[0..words]`, the 16-bit view of the same memory (little endian,
    /// the reference's platform) shows its image.
    fn sync_overlay(&mut self, words: usize) {
        for (word, pair) in self.xn_buf32[..words]
            .iter()
            .zip(self.xn_buf.as_chunks_mut::<2>().0)
        {
            pair[0] = *word as i16;
            pair[1] = (*word >> 16) as i16;
        }
    }
}

/// The scalars `decoder_tcx` carries from one section of the frame to the next.
struct Frame {
    l_frame: i16,
    l_frame_tcx: i16,
    tcx_offset: i16,
    tcx_offset_fb: i16,
    left_rect: i16,
    l_spec: i16,
    l_spec_con: i16,
    gamma1: i16,
    overlap: i16,
    overlap_fb: i16,
    info_igf_start_line: i16,
    noise_filling_size: i16,
    index: i16,
    fac_ns: i16,
    f_use_tns: i8,
    tns_size: i16,
    tns_data: STnsData,
    /// Offsets into `prm`: the TNS data, the harmonic model parameters, the spectrum.
    prm_tns: usize,
    prm_hm: usize,
    prm_sq_q: usize,
    /// Offset of the target bit count in `prm` (`prm_target`), set by the LPC-shaped coder.
    prm_target: usize,
    gain_tcx: i16,
    gain_tcx_e: i16,
    x_e: i16,
    nf_seed: i16,
    gainlpc2: [i16; FDNS_NPTS as usize],
    gainlpc2_e: [i16; FDNS_NPTS as usize],
    ap: [i16; M as usize + 2],
    temp_concealment_method: i16,
}

/// `decoder_tcx`: decode one TCX frame (`frame_cnt` 0 of a TCX-20 frame, 0 or 1 of a TCX-10
/// frame) from the parameters `prm` into `synth` (core rate) and `synth_fb` (output rate), with
/// the LPC filter `a` and the frame independent one `a_ind`. `bfi != 0` conceals a lost frame.
/// The configuration is `st.tcx_cfg`.
pub fn decoder_tcx(
    prm: &mut [i16],
    a: &[i16],
    a_ind: &[i16],
    l_frame_glob: i16,
    l_frame_tcx_glob: i16,
    l_spec: i16,
    synth: &mut [i16],
    synth_fb: &mut [i16],
    st: &mut DecoderState,
    coder_type: i16,
    bfi: i16,
    frame_cnt: i16,
    stab_fac: i16,
) {
    let mut b = Buffers::new();
    let mut f = Frame {
        l_frame: 0,
        l_frame_tcx: 0,
        tcx_offset: st.tcx_cfg.tcx_offset,
        tcx_offset_fb: st.tcx_cfg.tcx_offset_fb,
        left_rect: 0,
        l_spec,
        l_spec_con: l_spec,
        gamma1: st.gamma,
        overlap: st.tcx_cfg.tcx_mdct_window_length,
        overlap_fb: st.tcx_cfg.tcx_mdct_window_length_fb,
        info_igf_start_line: 0,
        noise_filling_size: 0,
        index: 0,
        fac_ns: 0,
        f_use_tns: 0,
        tns_size: 0,
        tns_data: STnsData::zeroed(),
        prm_tns: 0,
        prm_hm: 0,
        prm_sq_q: 0,
        prm_target: 0,
        gain_tcx: 0,
        gain_tcx_e: 0,
        x_e: 0,
        nf_seed: 0,
        gainlpc2: [0; FDNS_NPTS as usize],
        gainlpc2_e: [0; FDNS_NPTS as usize],
        ap: [0; M as usize + 2],
        temp_concealment_method: 0,
    };
    let mut acelp_zir = [0i16; 480];

    tcx_frame_lengths(st, &mut f, l_frame_glob, l_frame_tcx_glob, bfi, frame_cnt);
    tcx_igf_setup(st, &mut f);
    tcx_read_parameters(st, &mut f, prm, bfi);
    tcx_decode_spectrum(st, &mut f, &mut b, prm, a, a_ind, bfi, frame_cnt);
    tcx_global_gain(st, &mut f, coder_type, bfi, stab_fac);
    tcx_synthesis_gain_compensation(st, &mut f, a, bfi, frame_cnt);
    tcx_residual_and_formant(st, &mut f, &mut b, prm, bfi, frame_cnt);
    tcx_gain_and_noise_filling(st, &mut f, &mut b, prm, a, bfi, frame_cnt);
    tcx_plc_method(st, &mut f, bfi, frame_cnt, l_frame_tcx_glob);
    tcx_conceal_or_save(st, &mut f, &mut b, a, bfi, frame_cnt);
    tcx_shape_spectrum(st, &mut f, &mut b, bfi, frame_cnt);
    tcx_concealment_update(st, &mut f, &mut b, bfi);
    tcx_igf_apply(st, &mut f, &mut b, bfi);
    tcx_tns_and_grouping(st, &mut f, &mut b, l_frame_glob, bfi, frame_cnt);

    // Compute inverse MDCT of x[].
    let words = at(i32::from(f.l_frame.max(f.l_frame_tcx).max(f.l_spec)));
    copy32(&b.x, &mut b.xn_buf32, words as i16);
    if st.igf != 0 {
        let start = at(i32::from(st.h_igf_dec.info_igf_start_line));
        set32(
            &mut b.xn_buf32[start..],
            0,
            sub(f.l_frame_tcx, st.h_igf_dec.info_igf_start_line),
        );
    }
    b.sync_overlay(words.max(at(i32::from(f.l_frame_tcx))));

    let l_spec_tcx5 = shr(f.l_frame_tcx.max(f.l_spec), 1);
    imdct(
        &[], // the spectrum is the 32-bit view of xn_buf
        &mut b.xn_buf,
        &mut acelp_zir,
        st,
        false,
        &ImdctArgs {
            x_e: f.x_e,
            index: f.index,
            left_rect: f.left_rect,
            tcx_offset: f.tcx_offset,
            overlap: f.overlap,
            l_frame: f.l_frame,
            l_frame_tcx: f.l_frame_tcx,
            l_spec_tcx5,
            l_frame_glob,
            frame_cnt,
            bfi,
            fullband_scale: 0,
        },
    );

    // Generate additional comfort noise to mask potential coding artefacts
    if st.flag_cna != 0 {
        // the reference dereferences the FD-CNG instance, which exists whenever flag_cna is set
        if let Some(com) = st
            .h_fd_cng_dec
            .as_mut()
            .and_then(|fd_cng| fd_cng.h_fd_cng_com.as_mut())
        {
            generate_masking_noise_mdct(
                &mut b.x,
                &mut f.x_e,
                com,
                f.l_frame.max(f.l_frame_tcx).max(f.l_spec),
            );
        }
    }

    let mut xn_buf_fb = [0i16; XN_BUF_FB_LEN];
    let fullband_scale = div_l(l_mult(FSCALE_DENOM, l_frame_tcx_glob), l_frame_glob);
    imdct(
        &b.x,
        &mut xn_buf_fb,
        &mut acelp_zir,
        st,
        true,
        &ImdctArgs {
            x_e: f.x_e,
            index: f.index,
            left_rect: f.left_rect,
            tcx_offset: f.tcx_offset_fb,
            overlap: f.overlap_fb,
            l_frame: f.l_frame_tcx,
            l_frame_tcx: f.l_frame_tcx,
            l_spec_tcx5,
            l_frame_glob: l_frame_tcx_glob,
            frame_cnt,
            bfi,
            fullband_scale,
        },
    );

    tcx_update_pitch_history(st, &f, bfi);

    // Update old_syn_overl
    if st.tcx_cfg.last_aldo == 0 {
        let overlap = at(i32::from(f.overlap));
        let l_frame = at(i32::from(f.l_frame));
        st.syn_overl[..overlap].copy_from_slice(&b.xn_buf[l_frame..l_frame + overlap]);
        let overlap_fb = at(i32::from(f.overlap_fb));
        let l_frame_tcx = at(i32::from(f.l_frame_tcx));
        st.syn_overl_fb[..overlap_fb]
            .copy_from_slice(&xn_buf_fb[l_frame_tcx..l_frame_tcx + overlap_fb]);
    }

    // Output
    let from = at(i32::from(shr(f.overlap, 1)) - i32::from(f.tcx_offset));
    let frame = at(i32::from(l_frame_glob));
    synth[..frame].copy_from_slice(&b.xn_buf[from..from + frame]);
    let from_fb = at(i32::from(shr(f.overlap_fb, 1)) - i32::from(f.tcx_offset_fb));
    let frame_fb = at(i32::from(l_frame_tcx_glob));
    synth_fb[..frame_fb].copy_from_slice(&xn_buf_fb[from_fb..from_fb + frame_fb]);
}

/// The frame lengths and the left window of the frame (`decoder_tcx` up to the IGF update).
fn tcx_frame_lengths(
    st: &mut DecoderState,
    f: &mut Frame,
    l_frame_glob: i16,
    l_frame_tcx_glob: i16,
    bfi: i16,
    frame_cnt: i16,
) {
    if st.enable_tcx_lpc != 0 {
        f.gamma1 = 0x7FFF;
    }

    if bfi != 0 {
        // PLC: [TCX: Memory update]; PLC: Init buffers
        f.l_frame = st.l_frame_past;
        f.l_frame_tcx = st.l_frame_tcx_past;
        f.left_rect = st.prev_widow_left_rect;
        if f.left_rect != 0 {
            f.tcx_offset = st.tcx_cfg.lfac_next;
            f.tcx_offset_fb = st.tcx_cfg.lfac_next_fb;
            f.l_spec = add(f.l_spec, shr(st.tcx_cfg.tcx_coded_lines, 2));
            f.l_spec_con = add(f.l_spec_con, shr(st.tcx_cfg.tcx_coded_lines, 2));
        }
    } else {
        if frame_cnt == 0 && st.last_core == ACELP_CORE {
            if st.prev_bfi == 0 {
                st.tcx_cfg.last_aldo = 0;
            }

            // if past frame is ACELP
            f.l_frame = add(l_frame_glob, f.tcx_offset);
            f.l_frame_tcx = add(l_frame_tcx_glob, f.tcx_offset_fb);
            f.l_spec_con = add(f.l_spec_con, shr(st.tcx_cfg.tcx_coded_lines, 2));
            f.l_frame = sub(f.l_frame, st.tcx_cfg.lfac_next);
            f.l_frame_tcx = sub(f.l_frame_tcx, st.tcx_cfg.lfac_next_fb);
            f.tcx_offset = st.tcx_cfg.lfac_next;
            f.tcx_offset_fb = st.tcx_cfg.lfac_next_fb;
            f.left_rect = 1;
            st.prev_widow_left_rect = 1;
        } else {
            f.l_frame = l_frame_glob;
            f.l_frame_tcx = l_frame_tcx_glob;
            f.left_rect = 0;
            st.prev_widow_left_rect = 0;
        }

        if frame_cnt == 0 && sub(st.last_core_bs, ACELP_CORE) == 0 {
            // int arithmetic, stored to a Word16
            f.l_spec = f.l_spec.wrapping_add(st.tcx_cfg.tcx_coded_lines >> 2);
        }

        st.l_frame_past = f.l_frame;
        st.l_frame_tcx_past = f.l_frame_tcx;
    }
}

/// The IGF grid of the frame, the highest line the core codes and the noise filling limit.
fn tcx_igf_setup(st: &mut DecoderState, f: &mut Frame) {
    if sub(f.l_frame, shr(st.l_frame, 1)) == 0 && st.tcxonly != 0 {
        igf_dec_update_info(&mut st.h_igf_dec, IGF_GRID_LB_SHORT);
    } else if sub(st.last_core, ACELP_CORE) == 0 || (f.left_rect != 0 && st.bfi != 0) {
        igf_dec_update_info(&mut st.h_igf_dec, IGF_GRID_LB_TRAN);
    } else {
        igf_dec_update_info(&mut st.h_igf_dec, IGF_GRID_LB_NORM);
    }

    if st.igf == 0 {
        if st.narrow_band == 0 {
            // minimum needed for output with sampling rates lower then the nominal sampling rate
            f.info_igf_start_line = f.l_frame_tcx.min(f.l_frame);
        } else {
            f.info_igf_start_line = f.l_frame_tcx;
        }
    } else {
        f.info_igf_start_line = st.h_igf_dec.info_igf_start_line.min(f.l_frame_tcx);
    }

    f.noise_filling_size = f.l_spec;
    if st.igf != 0 {
        f.noise_filling_size = st.h_igf_dec.info_igf_start_line;
    }
}

/// Read the TCX parameters: the global gain index, the noise level and the TNS data.
fn tcx_read_parameters(st: &mut DecoderState, f: &mut Frame, prm: &[i16], bfi: i16) {
    // prm_ltp = &prm[1+NOISE_FILL_RANGES]; prm_tns = prm_ltp + LTPSIZE
    f.prm_tns = at(i32::from(add(add(1, NOISE_FILL_RANGES), LTPSIZE)));

    f.index = 0;
    if bfi == 0 {
        f.index = prm[0];

        // read noise level (fac_ns)
        let noise_filling_index = prm[1];
        f.fac_ns = extract_l(l_shr(
            l_mult0(noise_filling_index, 0x6000),
            NBITS_NOISE_FILL_LEVEL,
        ));
    } else {
        f.fac_ns = 0;
    }

    // read TNS data. The reference reads `pCurrentTnsConfig`, which the frame's parameter
    // decoding has selected; without one it would dereference NULL.
    f.f_use_tns = 0;
    if bfi == 0 && st.tcx_cfg.f_is_tns_allowed != 0 {
        if let Some((i, j)) = st.tcx_cfg.p_current_tns_config {
            f.f_use_tns = decode_tns_data(
                &st.tcx_cfg.tns_config[i][j],
                &prm[f.prm_tns..],
                &mut f.tns_size,
                &mut f.tns_data,
            ) as i8;
        }
    }

    f.prm_hm = f.prm_tns + at(i32::from(f.tns_size));
    f.prm_sq_q = f.prm_hm + at(i32::from(NPRM_CTX_HM));
}

/// The spectrum data, and the adaptive low frequency de-emphasis (`bfi == 0` only).
fn tcx_decode_spectrum(
    st: &mut DecoderState,
    f: &mut Frame,
    b: &mut Buffers,
    prm: &mut [i16],
    a: &[i16],
    a_ind: &[i16],
    bfi: i16,
    frame_cnt: i16,
) {
    if bfi != 0 {
        return;
    }
    let l_spec = at(i32::from(f.l_spec));

    // Context HM
    if st.tcx_cfg.ctx_hm != 0 && (sub(st.last_core_bs, ACELP_CORE) != 0 || frame_cnt > 0) {
        st.last_ctx_hm_enabled = prm[f.prm_hm];
        // no context harmonic model, copy MDCT coefficients to x
        for i in 0..l_spec {
            b.x[i] = l_mult(prm[f.prm_sq_q + i], 1 << (30 - SPEC_EXP_DEC));
        }
        f.x_e = SPEC_EXP_DEC;
    } else if st.tcx_lpc_shaped_ari != 0 {
        // low rates: new arithmetic coder
        f.prm_target = f.prm_sq_q;
        f.prm_sq_q = f.prm_target + 1;

        let use_hm: i8 = i8::from(sub(st.last_core_bs, ACELP_CORE) != 0);
        let target_bits = prm[f.prm_target];
        let pitch = st.tcx_hm_ltp_pitch_lag;
        let low_complexity = shr(st.bwidth, 1);
        let (head, tail) = prm.split_at_mut(f.prm_sq_q);
        let (mut arith_bits, mut signaling_bits) = (0i16, 0i16);
        tcx_arith_decode_envelope(
            &mut b.x,
            &mut f.x_e,
            f.l_frame,
            f.l_spec,
            st,
            a_ind,
            target_bits,
            tail,
            use_hm,
            &mut head[f.prm_hm..],
            pitch,
            &mut arith_bits,
            &mut signaling_bits,
            &mut f.nf_seed,
            low_complexity,
        );

        st.res_q_bits[at(i32::from(frame_cnt))] = sub(target_bits, arith_bits);
    } else {
        // TCX-only: old arithmetic coder
        for i in 0..l_spec {
            b.x[i] = l_mult(prm[f.prm_sq_q + i], 1 << (30 - SPEC_EXP_DEC));
        }
        set32(&mut b.x[l_spec..], 0, sub(f.l_frame_tcx, f.l_spec));
        f.x_e = SPEC_EXP_DEC;
    }
    let tmp1 = f.l_frame.max(f.l_frame_tcx).max(f.l_spec_con);
    set32(&mut b.x[l_spec..], 0, sub(tmp1, f.l_spec));

    // adaptive low frequency deemphasis.
    weight_a(a, &mut f.ap, f.gamma1, M);
    lpc2mdct(
        &f.ap,
        M,
        &mut Lpc2MdctOutputs {
            mdct_gains: None,
            mdct_gains_exp: None,
            mdct_inv_gains: Some(&mut f.gainlpc2),
            mdct_inv_gains_exp: Some(&mut f.gainlpc2_e),
        },
    );

    // initialize LF deemphasis factors in xn_buf
    let tmp1 = f.l_spec.max(f.l_frame_tcx);
    set16(&mut b.xn_buf, 0x4000, tmp1);

    if st.tcxonly == 0 {
        adapt_low_freq_deemph(
            &mut b.x,
            f.x_e,
            st.tcx_lpc_shaped_ari,
            &f.gainlpc2,
            &f.gainlpc2_e,
            f.l_frame,
            Some(&mut b.xn_buf),
        );
    }
}

/// The global gain, or, when concealing, the damping of the fade-out.
fn tcx_global_gain(st: &mut DecoderState, f: &mut Frame, coder_type: i16, bfi: i16, stab_fac: i16) {
    st.damping = 0;

    if bfi == 0 {
        // Compute global gain
        let tmp32 = l_shl(l_mult0(f.index, 0x797D), 7); // 6Q25; 0x797D -> log2(10)/28 (Q18)
        f.gain_tcx_e = add(extract_l(l_shr(tmp32, 25)), 1); // get exponent
        f.gain_tcx = round_word(basop_util_inv_log2(tmp32 | 0xFE00_0000_u32 as i32));

        let mut tmp1 = mult_r(
            shl(f.l_spec, 5),
            26214, /* 128.f/NORM_MDCT_FACTOR Q15 */
        );
        let mut s: i16 = 15 - 5 - 7;
        if f.l_spec >= 1024 {
            // reduce precision for avoiding overflow
            tmp1 = mult_r(shl(f.l_spec, 4), 26214);
            s = 15 - 4 - 7;
        }
        tmp1 = isqrt16(tmp1, &mut s);

        f.gain_tcx = mult(f.gain_tcx, tmp1);
        f.gain_tcx_e = add(f.gain_tcx_e, s);

        st.old_gaintcx_bfi = f.gain_tcx;
        st.old_gaintcx_bfi_e = f.gain_tcx_e;

        st.cummulative_damping_tcx = 32767; // 1.0f Q15
    } else {
        // PLC: [TCX: Fade-out]; derivation of damping factor
        if st.use_partial_copy != 0 {
            if sub(st.rf_frame_type, RF_TCXFD) == 0 {
                let tmp32 = l_shl(l_mult0(st.old_gaintcx_bfi, 0x797D), 7);
                f.gain_tcx_e = add(extract_l(l_shr(tmp32, 25)), 1);
                f.gain_tcx = round_word(basop_util_inv_log2(tmp32 | 0xFE00_0000_u32 as i32));

                let mut tmp1 = mult_r(shl(f.l_spec, 5), 26214);
                let mut s: i16 = 15 - 5 - 7;
                tmp1 = isqrt16(tmp1, &mut s);

                f.gain_tcx = mult(f.gain_tcx, tmp1);
                f.gain_tcx_e = add(f.gain_tcx_e, s);

                st.old_gaintcx_bfi = f.gain_tcx;
                st.old_gaintcx_bfi_e = f.gain_tcx_e;
            } else {
                f.gain_tcx = st.old_gaintcx_bfi;
                f.gain_tcx_e = st.old_gaintcx_bfi_e;
            }

            st.damping = 16384; // 1.f Q14
        } else {
            st.damping = damping_fact(
                coder_type,
                st.nb_lost_cmpt,
                st.last_good,
                stab_fac,
                &mut st.mode2_lp_gainp,
                st.last_core,
            );
            f.gain_tcx = st.old_gaintcx_bfi;
            f.gain_tcx_e = st.old_gaintcx_bfi_e;
        }

        // shl(Q15*Q14, 1) = shl(Q14, 1) = Q15
        st.cummulative_damping_tcx = shl(mult(st.cummulative_damping_tcx, st.damping), 1);
    }
}

/// The LPC weighting of a concealed frame and the level of the synthesis filter's impulse
/// response, which the gain compensation of the concealed frames follows.
fn tcx_synthesis_gain_compensation(
    st: &mut DecoderState,
    f: &mut Frame,
    a: &[i16],
    bfi: i16,
    frame_cnt: i16,
) {
    if bfi != 0 {
        // PLC: [TCX: Fade-out]; PLC: invert LPC weighting in case of PLC (the reference first
        // sets gamma to gamma1, or to st->gamma with envWeighted, and overwrites it here)
        let gamma = if st.enable_tcx_lpc != 0 {
            add(
                mult_r(st.cummulative_damping_tcx, sub(st.gamma, 32767)),
                32767,
            )
        } else {
            add(
                mult_r(st.cummulative_damping_tcx, sub(f.gamma1, 32767)),
                32767,
            )
        };
        weight_a(a, &mut f.ap, gamma, M);

        lpc2mdct(
            &f.ap,
            M,
            &mut Lpc2MdctOutputs {
                mdct_gains: None,
                mdct_gains_exp: None,
                mdct_inv_gains: Some(&mut f.gainlpc2),
                mdct_inv_gains_exp: Some(&mut f.gainlpc2_e),
            },
        );
    }
    let mut tmp2: i16 = 0;
    let mut h1 = [0i16; 241]; // L_FRAME_MAX/4+1
    let mut mem = [0i16; M as usize];
    h1[0] = 1024; // 32768/32
    e_util_synthesis_in_place(0, &f.ap, &mut h1, L_SUBFR, &mut mem, 0, M);
    deemph(&mut h1, st.preemph_fac, L_SUBFR, &mut tmp2);
    // impulse response level = gain introduced by synthesis+deemphasis
    if bfi == 0 {
        let tmp32 =
            dot_product_sq16_hq(0, &h1, L_SUBFR, &mut st.last_gain_syn_deemph_e, &mut st.stl); // Q15, st->last_gain_syn_deemph_e
                                                                                               // scaling of h1[0] and E_UTIL_synthesis * 2
        st.last_gain_syn_deemph_e = add(st.last_gain_syn_deemph_e, 10);
        let tmp32 = sqrt32(tmp32, &mut st.last_gain_syn_deemph_e);
        st.last_gain_syn_deemph = round_word(tmp32);
        // for avoiding compiler warnings
        st.gain_helper = 16384; // 32768/2
        st.gain_helper_e = 1;
        st.step_compensate = 0;
        st.step_compensate_e = 0;
    } else if sub(TCX_20_CORE, st.core) == 0 || sub(frame_cnt, 1) == 0 {
        // gainCompensate = st->last_gain_syn_deemph/(float)sqrt(dot_product( h1, h1, L_SUBFR));
        let mut gain_compensate_e: i16 = 0;
        let tmp32 = dot_product_sq16_hq(0, &h1, L_SUBFR, &mut gain_compensate_e, &mut st.stl);
        // scaling of h1[0] and E_UTIL:synthesis
        gain_compensate_e = add(gain_compensate_e, 10);
        let mut gain_compensate = round_word(sqrt32(tmp32, &mut gain_compensate_e));
        let (numerator, numerator_e) = (st.last_gain_syn_deemph, st.last_gain_syn_deemph_e);
        let (denominator, denominator_e) = (gain_compensate, gain_compensate_e);
        basop_util_divide_mant_exp(
            numerator,
            numerator_e,
            denominator,
            denominator_e,
            &mut gain_compensate,
            &mut gain_compensate_e,
        );

        // The reference indexes T_DIV_L_Frame with the frame length; a core length without an
        // entry (none the decoder runs) reads 0 here instead of out of bounds.
        let tmp1 = T_DIV_L_FRAME
            .get(at(l_shl(l_mac(-28000, st.l_frame, 95), 1 - 15)))
            .copied()
            .unwrap_or(0);

        if sub(st.nb_lost_cmpt, 1) == 0 {
            // stepCompensate = (1.f - gainCompensate)/st->L_frame_fx;
            st.step_compensate_e = basop_util_add_mant_exp(
                tmp1,
                -7,
                negate(mult(gain_compensate, tmp1)),
                add(-7, gain_compensate_e),
                &mut st.step_compensate,
            );

            st.gain_helper = 16384; // 32768/2
            st.gain_helper_e = 1;
        } else {
            // stepCompensate = (st->last_concealed_gain_syn_deemph - gainCompensate)/st->L_frame_fx;
            st.step_compensate_e = basop_util_add_mant_exp(
                mult(tmp1, st.last_concealed_gain_syn_deemph),
                add(-7, st.last_concealed_gain_syn_deemph_e),
                negate(mult(tmp1, gain_compensate)),
                add(-7, gain_compensate_e),
                &mut st.step_compensate,
            );
            st.gain_helper = st.last_concealed_gain_syn_deemph;
            st.gain_helper_e = st.last_concealed_gain_syn_deemph_e;
        }
        st.last_concealed_gain_syn_deemph = gain_compensate;
        st.last_concealed_gain_syn_deemph_e = gain_compensate_e;
    }
}

/// The residual inverse quantisation, the TCX-only psychoacoustic de-emphasis and the formant
/// enhancement of the low rates.
fn tcx_residual_and_formant(
    st: &mut DecoderState,
    f: &mut Frame,
    b: &mut Buffers,
    prm: &[i16],
    bfi: i16,
    frame_cnt: i16,
) {
    let res_q_bits = st.res_q_bits[at(i32::from(frame_cnt))];
    if bfi == 0 && st.tcx_cfg.resq != 0 {
        if st.tcx_lpc_shaped_ari != 0 {
            // new arithmetic coder
            let target_bits = prm[f.prm_target];
            let prm_resq = f.prm_sq_q + at(i32::from(target_bits) - i32::from(res_q_bits));

            tcx_ari_res_inv_q_spec(
                &mut b.x,
                f.x_e,
                f.l_spec,
                &prm[prm_resq..],
                res_q_bits,
                0,
                st.tcx_cfg.sq_rounding,
                &b.xn_buf, // LF deemphasis factors
            );
        } else {
            // old arithmetic coder
            let l_spec = at(i32::from(f.l_spec));
            let i = tcx_res_inv_q_gain(
                &mut f.gain_tcx,
                &mut f.gain_tcx_e,
                &prm[f.prm_sq_q + l_spec..],
                res_q_bits,
            );

            let factors: Option<&[i16]> = if st.tcxonly != 0 {
                None
            } else {
                Some(&b.xn_buf)
            };
            tcx_res_inv_q_spec(
                &mut b.x,
                f.x_e,
                f.l_spec,
                &prm[f.prm_sq_q + l_spec..],
                res_q_bits,
                i,
                st.tcx_cfg.sq_rounding,
                factors, // LF deemphasis factors
            );
        }
    }
    if bfi == 0 && st.tcxonly != 0 && st.tcxltp != 0 && st.tcxltp_gain > 0 && f.f_use_tns == 0 {
        psych_adapt_low_freq_deemph(&mut b.x, &f.gainlpc2, &f.gainlpc2_e, None);
    }

    // for FAC
    if bfi == 0
        && st.tcxonly == 0
        && (l_sub(st.total_brate, i32::from(ACELP_13K20)) < 0 || st.rf_flag != 0)
    {
        // Replication of ACELP formant enhancement for low rates
        tcx_formant_enhancement(
            &mut b.xn_buf,
            &f.gainlpc2,
            &f.gainlpc2_e,
            &mut b.x,
            &mut f.x_e,
            f.l_frame,
            f.l_frame_tcx,
        );
    }
}

/// Add the gain to the LPC gains, and the noise filling.
fn tcx_gain_and_noise_filling(
    st: &mut DecoderState,
    f: &mut Frame,
    b: &mut Buffers,
    prm: &[i16],
    a: &[i16],
    bfi: i16,
    _frame_cnt: i16,
) {
    // Add gain to the lpc gains
    if st.vad == 0 {
        f.gain_tcx = mult_r(f.gain_tcx, st.tcx_cfg.na_scale);
    }

    let i = norm_s(f.gain_tcx);
    f.gain_tcx = shl(f.gain_tcx, i);
    f.gain_tcx_e = sub(f.gain_tcx_e, i);
    for gain in &mut f.gainlpc2 {
        *gain = mult_r(*gain, f.gain_tcx);
    }

    // Noise filling.
    if bfi == 0 && f.fac_ns > 0 {
        let mut mode: i16 = 0;
        if sub(st.bits_frame, 256) >= 0 && st.rf_flag == 0 {
            mode = 1;
        }

        let mut noise_tilt_factor: i16 = 0;
        let first_line =
            tcx_get_noise_filling_tilt(a, M, f.l_frame, mode, &mut noise_tilt_factor, &mut st.stl);

        let mut noise_trans_width = MIN_NOISE_FILLING_HOLE;
        if st.tcxonly != 0 {
            let mut tmp1: i16 = 0;
            if st.tcx_cfg.ctx_hm != 0
                && sub(st.last_core, ACELP_CORE) != 0
                && st.last_ctx_hm_enabled != 0
            {
                tmp1 = 10240; // 0.3125f Q15
            }
            // HOLE_SIZE_FROM_LTP(s_max(st->tcxltp_gain, tmp1))
            noise_trans_width = add(
                4,
                extract_h(l_shr(l_mult0(st.tcxltp_gain.max(tmp1), 0x6666), 10)),
            );

            if sub(f.l_frame, shr(st.l_frame, 1)) == 0 {
                noise_trans_width = 3; // minimum transition fading for noise filling in TCX-10
            }
        }

        if st.tcx_lpc_shaped_ari == 0 {
            // old arithmetic coder: noise filling seed
            let mut tmp32 = 0i32;
            for i in 0..f.l_spec {
                tmp32 = l_mac_ns(
                    tmp32,
                    abs_s(prm[f.prm_sq_q + at(i32::from(i))]),
                    i,
                    &mut st.stl,
                );
            }
            f.nf_seed = extract_l(tmp32);
        }

        let seed = f.nf_seed;
        let info_tcx_noise: Option<&mut [i16]> = if st.igf != 0 {
            Some(&mut st.h_igf_dec.info_tcx_noise)
        } else {
            None
        };
        tcx_noise_filling(
            &mut b.x,
            f.x_e,
            seed,
            first_line,
            f.noise_filling_size,
            noise_trans_width,
            f.l_frame,
            noise_tilt_factor,
            f.fac_ns,
            info_tcx_noise,
        );
        st.seed_tcx_plc = seed;
    }
}

/// The concealment method of a lost frame (tonal or waveform adjustment) and the sub-frame
/// position of a TCX-10 frame.
fn tcx_plc_method(
    st: &mut DecoderState,
    f: &mut Frame,
    bfi: i16,
    frame_cnt: i16,
    l_frame_tcx_glob: i16,
) {
    if st.enable_plc_waveadjust == 0 {
        return;
    }
    if bfi != 0 {
        if sub(st.nb_lost_cmpt, 1) == 0 {
            st.plc_info.concealment_method = TCX_NONTONAL;
            // tonal/non-tonal decision
            if sub(st.plc_info.transient[0], 1) == 0
                && sub(st.plc_info.transient[1], 1) == 0
                && sub(st.plc_info.transient[2], 1) == 0
            {
                let mut sum: i16 = 0;
                for i in (0..10).rev() {
                    sum = add(sum, st.plc_info.tcx_tonality[i]);
                }

                if sub(sum, 6) >= 0 {
                    st.plc_info.concealment_method = TCX_TONAL;
                }
            }

            if st.tonal_mdct_plc_active != 0 {
                st.plc_info.concealment_method = TCX_TONAL;
            }
        }

        if sub(f.l_frame_tcx, st.l_frame_tcx) > 0 {
            st.plc_info.concealment_method = TCX_TONAL;
        }

        f.temp_concealment_method = st.plc_info.concealment_method;

        if sub(st.core, TCX_10_CORE) == 0 {
            f.temp_concealment_method = TCX_TONAL;
        }
    }
    // get the starting location of the subframe in the frame
    if sub(st.core, TCX_10_CORE) == 0 {
        st.plc_info.subframe = extract_l(l_mult0(frame_cnt, l_frame_tcx_glob));
    }
}

/// The tonal concealment: save the spectrum of a good frame, insert the fade-out noise into a
/// lost one.
fn tcx_conceal_or_save(
    st: &mut DecoderState,
    f: &mut Frame,
    b: &mut Buffers,
    a: &[i16],
    bfi: i16,
    frame_cnt: i16,
) {
    if bfi == 0 {
        tonal_mdct_conceal_save_freq_signal(
            &mut st.tonal_mdc_tconceal,
            &b.x,
            f.x_e,
            f.l_frame_tcx,
            f.l_frame,
            &f.gainlpc2,
            &f.gainlpc2_e,
            f.gain_tcx_e,
        );
    } else if st.enable_plc_waveadjust == 0 || sub(f.temp_concealment_method, TCX_TONAL) == 0 {
        // set f to 1 to not fade out, to 0 to immediately switch to white noise
        let mut fade = st.cummulative_damping_tcx;
        if st.tcxonly != 0 {
            fade = 32767; // 1.0f Q15
        }

        if frame_cnt == 0
            && sub(f.l_frame_tcx, shr(st.l_frame_tcx, 1)) == 0
            && st.tcxonly != 0
            && st.tonal_mdct_plc_active == 0
            && sub(st.nb_lost_cmpt, 1) == 0
            && st.tcx_cfg.tcx_last_overlap_mode != FULL_OVERLAP
            && st.tcx_cfg.tcx_curr_overlap_mode != FULL_OVERLAP
        {
            tcx_replace_louder_tcx5_block(st, f);
        }

        let mut noise_tilt_factor: i16 = 32767; // 1.0f Q15

        let mut mode: i16 = 0;
        if sub(st.bits_frame, 256) >= 0 && st.rf_flag == 0 {
            mode = 1;
        }

        tcx_get_noise_filling_tilt(a, M, f.l_frame, mode, &mut noise_tilt_factor, &mut st.stl);

        tonal_mdct_conceal_insert_noise(
            &mut st.tonal_mdc_tconceal,
            &mut b.x,
            &mut f.x_e,
            st.tonal_mdct_plc_active,
            &mut st.seed_tcx_plc,
            noise_tilt_factor,
            fade,
            f.info_igf_start_line,
        );
    }
}

/// `CalculateAbsEnergy`: the energy of every second line of `x[0..lg]` as a Q31 mantissa with
/// the exponent `exp`, summed to 64 bits through the carry operators, starting from `l_off`.
fn calculate_abs_energy(
    l_off: i32,
    x: &[i16],
    lg: i16,
    exp: &mut i16,
    flags: &mut crate::itu::stl2009::StlFlags,
) -> i32 {
    // Clear carry flag and init sum
    flags.carry = false;
    let mut l_c = l_add(0, 0);
    let mut l_sum = l_mac_ns(l_off, 0, 0, flags);
    if l_sum > 0 {
        l_c = l_mac_ns(l_c, 0, 0, flags);
    }
    if l_sum < 0 {
        l_c = l_msu_ns(l_c, 0, 0, flags);
    }

    let mut i: i16 = 0;
    while i < lg {
        flags.carry = false;
        // multiplication of -32768 * -32768 throws an overflow, but is not critical
        l_sum = l_mac_ns(l_sum, x[at(i32::from(i))], x[at(i32::from(i))], flags);
        flags.overflow = false; // to avoid useless warning in L_macNs calling L_mult
        l_c = l_mac_ns(l_c, 0, 0, flags);
        i = add(i, 2);
    }
    norm_ll_q31(l_c, l_sum, exp, flags)
}

/// Replace the higher energy TCX-5 block of the last good frame by the lower one, to avoid an
/// energy fluctuation in the first concealed TCX-10 frame.
fn tcx_replace_louder_tcx5_block(st: &mut DecoderState, f: &Frame) {
    let row = st
        .tonal_mdc_tconceal
        .last_block_data
        .spectral_data
        .unwrap_or(0);
    let (mut exp1, mut exp2) = (0i16, 0i16);
    let data = &st.tonal_mdc_tconceal.spectral_data_buffers[row];
    let e_2nd_last =
        calculate_abs_energy(1, &data[0..], f.info_igf_start_line, &mut exp2, &mut st.stl);
    let e_last = calculate_abs_energy(1, &data[1..], f.info_igf_start_line, &mut exp1, &mut st.stl);

    let (mut tmp1, mut tmp2) = (0i16, 0i16);
    basop_util_divide_mant_exp(
        extract_h(e_2nd_last),
        exp2,
        extract_h(e_last),
        exp1,
        &mut tmp1,
        &mut tmp2,
    );

    tmp1 = shr(tmp1, 2); // Q13
    tmp1 = shl(tmp1, tmp2);
    let data = &mut st.tonal_mdc_tconceal.spectral_data_buffers[row];
    if sub(tmp1, 16384 /* 2 in Q13 */) > 0 {
        let mut i = 0usize;
        while i < at(i32::from(f.info_igf_start_line)) {
            data[i] = data[i + 1];
            i += 2;
        }
    } else if sub(tmp1, 4096 /* 0.5 in Q13 */) < 0 {
        let mut i = 0usize;
        while i < at(i32::from(f.info_igf_start_line)) {
            data[i + 1] = data[i];
            i += 2;
        }
    }
}

/// The IGF flat spectrum and the noise shaping in the frequency domain (1/Wz).
fn tcx_shape_spectrum(
    st: &mut DecoderState,
    f: &mut Frame,
    b: &mut Buffers,
    bfi: i16,
    frame_cnt: i16,
) {
    let l_spec = at(i32::from(f.l_spec));
    let l_frame = at(i32::from(f.l_frame));

    if sub(f.l_spec, f.l_frame) < 0 {
        set32(&mut b.x[l_spec..], 0, sub(f.l_frame, f.l_spec));
    } else if sub(f.l_spec, f.l_frame_tcx) > 0 {
        set32(
            &mut b.x[at(i32::from(f.l_frame_tcx))..],
            0,
            sub(f.l_spec, f.l_frame_tcx),
        );
    }

    if bfi != 0
        && (st.enable_plc_waveadjust == 0 || sub(f.temp_concealment_method, TCX_TONAL) == 0)
        && st.igf != 0
        && frame_cnt == 0
        && sub(f.l_frame_tcx, shr(st.l_frame_tcx, 1)) == 0
        && st.tcxonly != 0
        && st.tonal_mdct_plc_active == 0
        && sub(st.nb_lost_cmpt, 1) == 0
        && st.tcx_cfg.tcx_last_overlap_mode != FULL_OVERLAP
        && st.tcx_cfg.tcx_curr_overlap_mode != FULL_OVERLAP
    {
        igf_dec_copy_lpc_flat_spectrum(&mut st.h_igf_dec, &b.x, f.x_e, IGF_GRID_LB_SHORT);
        let current = st.h_igf_dec.igf_data.igf_curr_subframe[0][0];
        st.h_igf_dec.igf_data.igf_curr_subframe[1][0] = current;
    }

    // Noise shaping in frequency domain (1/Wz)
    if st.igf != 0 && bfi == 0 {
        if sub(f.l_frame, shr(st.l_frame, 1)) == 0 && st.tcxonly != 0 {
            igf_dec_copy_lpc_flat_spectrum(&mut st.h_igf_dec, &b.x, f.x_e, IGF_GRID_LB_SHORT);
        } else if sub(st.last_core, ACELP_CORE) == 0 {
            igf_dec_copy_lpc_flat_spectrum(&mut st.h_igf_dec, &b.x, f.x_e, IGF_GRID_LB_TRAN);
        } else {
            igf_dec_copy_lpc_flat_spectrum(&mut st.h_igf_dec, &b.x, f.x_e, IGF_GRID_LB_NORM);
        }
    }

    // LPC gains already available
    if st.enable_plc_waveadjust == 0 || bfi == 0 || sub(f.temp_concealment_method, TCX_TONAL) == 0 {
        f.x_e = add(f.x_e, f.gain_tcx_e);
        mdct_shaping(&mut b.x, f.l_frame, &f.gainlpc2, &f.gainlpc2_e);
        if bfi == 0 {
            for line in b.x[..l_spec].iter_mut().skip(l_frame) {
                *line = l_shl(
                    mpy_32_16_1(*line, f.gainlpc2[FDNS_NPTS as usize - 1]),
                    f.gainlpc2_e[FDNS_NPTS as usize - 1],
                );
            }
        }

        set32(&mut b.x[l_spec..], 0, sub(f.l_frame_tcx, f.l_spec));
        if bfi != 0
            && (st.enable_plc_waveadjust == 0 || sub(f.temp_concealment_method, TCX_TONAL) == 0)
        {
            let start = at(i32::from(f.info_igf_start_line));
            scale_sig32(
                &mut b.x[start..],
                sub(f.l_spec, f.info_igf_start_line),
                negate(f.gain_tcx_e),
            );
        }
    }
}

/// The tonal concealment of a lost frame, the tonal state update, and the waveform adjustment
/// concealment.
fn tcx_concealment_update(st: &mut DecoderState, f: &mut Frame, b: &mut Buffers, bfi: i16) {
    // PLC: [TCX: Tonal Concealment]
    if bfi != 0 && st.tonal_mdct_plc_active != 0 {
        tonal_mdct_conceal_apply(&mut st.tonal_mdc_tconceal, &mut b.x, f.x_e);
    }

    let mut pitch = l_deposit_h(0);
    if st.tcxltp_last_gain_unmodified > 0 {
        pitch = l_add(st.old_fpitch, 0);
    }
    let mut active: i8 = 0;
    if bfi != 0 && st.tonal_mdct_plc_active != 0 {
        active = 1;
    }
    tonal_mdct_conceal_update_state(
        &mut st.tonal_mdc_tconceal,
        f.l_frame_tcx,
        pitch,
        bfi,
        active,
    );

    if st.enable_plc_waveadjust != 0 {
        let core = st.core;
        // spectrum concealment
        if bfi != 0 && sub(f.temp_concealment_method, TCX_NONTONAL) == 0 {
            // x_e = 31-x_scale;
            concealment_decode_fix(core, &mut b.x, &mut f.x_e, &mut st.plc_info);
        }
        // update spectrum buffer, tonality flag, etc.
        concealment_update_x(bfi, core, st.tonality_flag, &b.x, f.x_e, &mut st.plc_info);
    }
}

/// The IGF gap filling of the frame (and of the TCX-10 sub-frame).
fn tcx_igf_apply(st: &mut DecoderState, f: &mut Frame, b: &mut Buffers, bfi: i16) {
    let short = sub(f.l_frame, shr(st.l_frame, 1)) == 0 && st.tcxonly != 0;
    if st.igf != 0 && !short {
        // packet loss after first TCX must be handled like transition frame
        let grid = if sub(st.last_core, ACELP_CORE) == 0 || (f.left_rect != 0 && bfi != 0) {
            IGF_GRID_LB_TRAN
        } else {
            IGF_GRID_LB_NORM
        };

        st.h_igf_dec.igf_data.igf_info.nf_seed = extract_l(l_mac0(13849, f.nf_seed, 31821));

        igf_dec_apply_mono(&mut st.h_igf_dec, &mut b.x, &mut f.x_e, grid, bfi);
    }
    if st.igf != 0 && short {
        st.h_igf_dec.igf_data.igf_info.nf_seed = extract_l(l_mac0(13849, f.nf_seed, 31821));
        igf_dec_apply_mono(
            &mut st.h_igf_dec,
            &mut b.x,
            &mut f.x_e,
            IGF_GRID_LB_SHORT,
            bfi,
        );
    }
}

/// The normalisation of the spectrum, the IGF temporal flattening, the TCX-10 window grouping
/// and the TNS synthesis.
fn tcx_tns_and_grouping(
    st: &mut DecoderState,
    f: &mut Frame,
    b: &mut Buffers,
    l_frame_glob: i16,
    bfi: i16,
    frame_cnt: i16,
) {
    f.index = st.tcx_cfg.tcx_last_overlap_mode; // backup last TCX overlap mode

    // normalize spectrum to minimize IMDCT noise
    let tmp1 = f.l_frame.max(f.l_frame_tcx).max(f.l_spec);
    // Keep 4 bits headroom for TNS
    let s = 0.max(sub(get_scale_factor32(&b.x, tmp1), 4));
    crate::evs::com::tools::scale_sig32(&mut b.x, tmp1, s);
    f.x_e = sub(f.x_e, s);

    if st.igf != 0 && st.h_igf_dec.flattening_trigger != 0 && f.f_use_tns == 0 {
        igf_flattening(st, f.x_e, &mut b.x);
    }

    let short = sub(f.l_frame, shr(st.l_frame, 1)) == 0 && st.tcxonly != 0;
    if short {
        let mut l = f.l_frame_tcx;
        if (st.tcx_cfg.f_is_tns_allowed != 0 && f.f_use_tns != 0 && bfi == 0)
            || sub(f.l_spec, f.l_frame_tcx) > 0
        {
            l = f.l_spec;
        }

        tcx_invert_window_grouping(
            &mut st.tcx_cfg,
            &mut b.xn_buf32,
            &mut b.x,
            l,
            f.f_use_tns,
            st.last_core,
            f.index,
            frame_cnt,
            bfi,
        );
    }

    // Temporal Noise Shaping Synthesis
    if st.tcx_cfg.f_is_tns_allowed != 0 && f.f_use_tns != 0 && bfi == 0 {
        // Apply TNS to get the reconstructed signal
        set_tns_config(
            &mut st.tcx_cfg,
            i8::from(l_frame_glob == st.l_frame),
            i8::from(st.last_core == ACELP_CORE && frame_cnt == 0),
        );

        if let Some((i, j)) = st.tcx_cfg.p_current_tns_config {
            apply_tns_filter(&st.tcx_cfg.tns_config[i][j], &f.tns_data, &mut b.x, 0);
        }

        if short
            && (st.tcx_cfg.tcx_last_overlap_mode != FULL_OVERLAP
                || (st.tcx_cfg.tcx_curr_overlap_mode == FULL_OVERLAP
                    && frame_cnt == 0
                    && f.index == 0))
        {
            let border = st.tcx_cfg.tns_config[0][0].i_filter_borders[0];
            let tmp1 = at(i32::from(shr(border, 1)));
            // a border below 8 lines leaves the reference's counts (tmp1 - 8) negative: no copy
            let n = tmp1.saturating_sub(8);
            // undo rearrangement of LF sub-window lines for TNS synthesis filtering
            let limit = f.l_frame_tcx.max(f.l_spec);
            if limit > border {
                let tmp2 = at(i32::from(shr(limit, 1)));
                b.x.copy_within(tmp1 + 8..tmp1 + 8 + n, tmp2 + 8);
                b.x.copy_within(8..16, tmp2);
                b.x.copy_within(16..16 + n, 8);
                b.x[tmp1..tmp2].fill(0);
                b.x[tmp2 + tmp1..tmp2 + tmp2].fill(0);
            } else {
                let scratch: [i32; 8] = core::array::from_fn(|k| b.x[8 + k]);
                b.x.copy_within(16..16 + n, 8);
                b.x[tmp1..tmp1 + 8].copy_from_slice(&scratch);
            }
        }
    }
}

/// The pitch history of a good frame.
fn tcx_update_pitch_history(st: &mut DecoderState, f: &Frame, bfi: i16) {
    // PLC: [TCX: Tonal Concealment]
    if bfi == 0 {
        st.second_last_tns_active = st.last_tns_active;
        st.last_tns_active = 0;
        if st.tcx_cfg.f_is_tns_allowed != 0 && f.f_use_tns != 0 {
            st.last_tns_active = 1;
        }

        st.tcxltp_third_last_pitch = st.tcxltp_second_last_pitch;
        st.tcxltp_second_last_pitch = st.old_fpitch;
        st.old_fpitch = l_add(
            l_deposit_h(st.tcxltp_pitch_int),
            l_mult(
                st.tcxltp_pitch_fr,
                crate::itu::basic_ops::div_s(1, st.pit_res_max),
            ), // Q16
        );
        st.old_fpitch_fb = mpy_32_16_1(
            st.old_fpitch,                                       // Q16
            mult_r(f.l_frame_tcx, get_inv_frame_len(f.l_frame)), // Q21 -> Q6
        ); // Q7
        st.old_fpitch_fb = l_shr(st.old_fpitch_fb, 7 - 16); // -> Q16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::itu::basic_ops::norm_l;
    use crate::itu::stl2009::StlFlags;

    #[test]
    fn at_clamps_a_negative_count_to_zero() {
        assert_eq!(at(-3), 0);
        assert_eq!(at(0), 0);
        assert_eq!(at(7), 7);
    }

    #[test]
    fn sync_overlay_shows_each_word_as_little_endian_halves() {
        let mut b = Buffers::new();
        b.xn_buf32[0] = 0x1234_5678;
        b.xn_buf32[1] = -2;
        b.sync_overlay(2);
        assert_eq!(b.xn_buf[..5], [0x5678, 0x1234, -2, -1, 0]);
    }

    #[test]
    fn calculate_abs_energy_sums_the_even_lines_from_the_offset() {
        // 1 + 2 * (3 * 3 + 4 * 4) = 51, normalised to Q31 with its exponent
        let (mut exp, mut flags) = (0i16, StlFlags::default());
        let mantissa = calculate_abs_energy(1, &[3, 100, 4, 100], 4, &mut exp, &mut flags);
        assert_eq!(mantissa, 51 << norm_l(51));
        assert_eq!(exp, -norm_l(51));
    }

    #[test]
    fn calculate_abs_energy_of_nothing_is_the_default_exponent() {
        let (mut exp, mut flags) = (0i16, StlFlags::default());
        assert_eq!(calculate_abs_energy(0, &[], 0, &mut exp, &mut flags), 0);
        assert_eq!(exp, -32);
    }
}
