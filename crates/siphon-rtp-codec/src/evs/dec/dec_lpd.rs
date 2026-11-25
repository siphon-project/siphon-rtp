//! The MODE2 core decoder (TS 26.442 `lib_dec/dec_LPD.c`): `decoder_LPD` decodes one frame of the
//! LPD core, ACELP, TCX-20 or TCX-10 (or conceals it), from the bit stream parameters into the
//! core-rate synthesis `signal_out` and the output-rate synthesis `signal_out_fb`, and carries the
//! memories to the next frame.
//!
//! The reference's long function is split along its own sections: `lpc` (the LPC parameters and
//! their concealment), `acelp`, `tcx` and `tail` (classification, memory updates, the CNG
//! parameters and the post-filter).
//!
//! `Overflow` and `Carry`: nothing in this file reads them.

mod acelp;
mod lpc;
mod tail;
mod tcx;

use crate::evs::cnst::{
    DEC_NPRM_DIV, L_FRAME_PLUS, M, MODE2, NB_DIV, NB_SUBFR16K, OLD_SYNTH_SIZE_DEC, RF_TCXFD,
    RF_TCXTD2,
};
use crate::evs::dec::dec_prm::dec_prm;
use crate::evs::dec::er_util::get_plc_mode_decision;
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{add, sub};

/// `synth_buf[OLD_SYNTH_SIZE_DEC + L_FRAME_PLUS + M]`.
pub(super) const SYNTH_BUF_LEN: usize = (OLD_SYNTH_SIZE_DEC + L_FRAME_PLUS + M) as usize;
/// `lsf[(NB_DIV + 1) * M]`.
pub(super) const LSF_LEN: usize = ((NB_DIV + 1) * M) as usize;
/// `xspnew_uw[NB_DIV * M]`.
pub(super) const XSP_LEN: usize = (NB_DIV * M) as usize;
/// `Aq[(NB_SUBFR16k + 1) * (M + 1)]`.
pub(super) const AQ_LEN: usize = ((NB_SUBFR16K + 1) * (M + 1)) as usize;
/// Where the LPC parameters start in the parameter buffer (`param + DEC_NPRM_DIV * NB_DIV`).
pub const PARAM_LPC_AT: usize = (DEC_NPRM_DIV * NB_DIV) as usize;
/// `RF_GENPRED` = `ACELP_MODE_MAX + 2`.
pub(super) const RF_GENPRED: i16 = crate::evs::cnst::ACELP_MODE_MAX + 2;

/// The locals of `decoder_LPD` its sections share.
pub(super) struct Lpd {
    /// `bfi`: the frame is concealed (it is changed by the partial copy and by a bit error).
    pub bfi: i16,
    pub synth_buf: [i16; SYNTH_BUF_LEN],
    pub synth_buf_fb: [i16; SYNTH_BUF_LEN],
    /// Where `synth` / `synthFB` start in their buffers (`old_synth_len` / `old_synth_lenFB`).
    pub synth_at: usize,
    pub synth_fb_at: usize,
    pub lsf: [i16; LSF_LEN],
    pub lsp: [i16; LSF_LEN],
    pub lspmid: [i16; M as usize],
    pub lsfmid: [i16; M as usize],
    pub aq: [i16; AQ_LEN],
    pub pitch: [i16; NB_SUBFR16K as usize],
    pub pit_gain: [i16; NB_SUBFR16K as usize],
    pub aind: [i16; M as usize + 1],
    pub lspind: [i16; M as usize],
    pub enr_old: i16,
    pub enr_new: i16,
    pub xspnew_uw: [i16; XSP_LEN],
    pub xsfnew_uw: [i16; XSP_LEN],
    pub lsf_q_prediction: i16,
    pub past_core_mode: i16,
}

/// `decoder_LPD`: decode (`bfi == 0`) or conceal (`bfi != 0`) one MODE2 core frame.
///
/// `signal_out` receives the `L_frame` core-rate samples (post-filtered), `signal_out_fb` the
/// `L_frameTCX` output-rate samples; `param` holds the decoded parameters (`PARAM_LPC_AT` of the
/// frame's, then the LPC indices; zeros when concealing), `total_nbbits` the bits of the frame
/// and `bits_read` the bits read before the core (in and out). `pitch_buf`, `voice_factors` and
/// `old_bwe_exc[bwe_exc_at..]` are the ACELP outputs the bandwidth extension uses.
pub fn decoder_lpd(
    signal_out: &mut [i16],
    signal_out_fb: &mut [i16],
    total_nbbits: i16,
    st: &mut DecoderState,
    bfi: i16,
    bits_read: &mut i16,
    coder_type: &mut i16,
    param: &mut [i16],
    pitch_buf: &mut [i16],
    voice_factors: &mut [i16],
    old_bwe_exc: &mut [i16],
    bwe_exc_at: usize,
) {
    let mut w = Lpd {
        bfi,
        synth_buf: [0; SYNTH_BUF_LEN],
        synth_buf_fb: [0; SYNTH_BUF_LEN],
        synth_at: 0,
        synth_fb_at: 0,
        lsf: [0; LSF_LEN],
        lsp: [0; LSF_LEN],
        lspmid: [0; M as usize],
        lsfmid: [0; M as usize],
        aq: [0; AQ_LEN],
        pitch: [0; NB_SUBFR16K as usize],
        pit_gain: [0; NB_SUBFR16K as usize],
        aind: [0; M as usize + 1],
        lspind: [0; M as usize],
        enr_old: 0,
        enr_new: 0,
        xspnew_uw: [0; XSP_LEN],
        xsfnew_uw: [0; XSP_LEN],
        lsf_q_prediction: -1,
        past_core_mode: st.last_core_bfi,
    };

    // to avoid compilation warnings, the reference clears the core here
    st.core = 0;

    if st.use_partial_copy != 0
        && sub(st.rf_frame_type, RF_TCXFD) >= 0
        && sub(st.rf_frame_type, RF_TCXTD2) <= 0
    {
        w.bfi = st.bfi;
    }

    // Adjust bit per frame
    if w.bfi == 0 {
        st.bits_frame_core = sub(st.bits_frame, *bits_read);
    }

    // Initialize the synthesis buffers: the past synthesis then zeros
    w.synth_at = st.old_synth_len.max(0) as usize;
    w.synth_buf[..w.synth_at].copy_from_slice(&st.old_synth[..w.synth_at]);
    w.synth_fb_at = st.old_synth_len_fb.max(0) as usize;
    let fb = st.old_synth_fb;
    w.synth_buf_fb[..w.synth_fb_at].copy_from_slice(&st.synth_history[fb..fb + w.synth_fb_at]);

    // For post-processing (post-filtering + blind BWE)
    if st.tcxonly == 0 {
        // for bass postfilter
        let nb_subfr = st.nb_subfr.max(0) as usize;
        w.pitch[..nb_subfr].fill(crate::evs::cnst::L_SUBFR);
        w.pit_gain[..nb_subfr].fill(0);
    }

    // PLC: [Common: Memory update]; update the number of lost frames
    if w.bfi != 0 {
        st.nb_lost_cmpt = add(st.nb_lost_cmpt, 1);
    }

    // BITSTREAM DECODING
    decoder_lpd_read_parameters(st, &mut w, total_nbbits, bits_read, coder_type, param);

    // PLC: [Common: mode decision]; decide which concealment to use
    if w.bfi != 0 {
        st.core = get_plc_mode_decision(st);
    }

    if w.bfi == 0 {
        if sub(st.prev_bfi, 1) == 0 {
            st.prev_nb_lost_cmpt = st.nb_lost_cmpt;
        } else {
            st.prev_nb_lost_cmpt = 0;
        }
        st.nb_lost_cmpt = 0;
    }

    // LPC PARAMETERS
    lpc::decode_lpc(st, &mut w, *coder_type, param);

    acelp::decode_acelp(
        st,
        &mut w,
        *coder_type,
        param,
        pitch_buf,
        voice_factors,
        old_bwe_exc,
        bwe_exc_at,
    );
    tcx::decode_tcx(st, &mut w, *coder_type, param);

    tail::finish(st, &mut w, *coder_type, signal_out, signal_out_fb);
}

/// The bit stream part of `decoder_LPD`: `dec_prm` of a good frame (and the bit-error fallback to
/// concealment), or of the RF TCX partial copy of a lost one.
fn decoder_lpd_read_parameters(
    st: &mut DecoderState,
    w: &mut Lpd,
    total_nbbits: i16,
    bits_read: &mut i16,
    coder_type: &mut i16,
    param: &mut [i16],
) {
    let l_frame = st.l_frame;
    let (param_main, param_lpc) = param.split_at_mut(PARAM_LPC_AT);
    if w.bfi == 0 {
        // PLC: [TCX: Tonal Concealment]
        st.second_last_core = st.last_core;
        let tcx_last_overlap_mode = st.tcx_cfg.tcx_last_overlap_mode;
        let tcx_current_overlap_mode = st.tcx_cfg.tcx_curr_overlap_mode;
        dec_prm(
            coder_type,
            param_main,
            param_lpc,
            total_nbbits,
            st,
            l_frame,
            bits_read,
        );
        if st.rate_switching_init == 0 && sub(st.last_codec_mode, MODE2) == 0 && st.ber_detect != 0
        {
            // the bit stream is corrupt: conceal the frame instead
            *coder_type = st.last_coder_type;
            st.last_core = st.second_last_core;
            st.tcx_cfg.tcx_last_overlap_mode = tcx_last_overlap_mode;
            st.tcx_cfg.tcx_curr_overlap_mode = tcx_current_overlap_mode;
            st.bfi = 1;
            w.bfi = 1;
            st.flag_guided_acelp = 0;
            st.nb_lost_cmpt = add(st.nb_lost_cmpt, 1);
            st.core_brate = st.last_core_brate;
            st.core = get_plc_mode_decision(st);
        }
    } else {
        if st.use_partial_copy != 0
            && sub(st.rf_frame_type, RF_TCXFD) >= 0
            && sub(st.rf_frame_type, RF_TCXTD2) <= 0
        {
            dec_prm(
                coder_type,
                param_main,
                param_lpc,
                total_nbbits,
                st,
                l_frame,
                bits_read,
            );
        }

        if sub(st.nb_lost_cmpt, 1) > 0 {
            st.flag_guided_acelp = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zeroed set of locals.
    pub(super) fn work() -> Box<Lpd> {
        Box::new(Lpd {
            bfi: 0,
            synth_buf: [0; SYNTH_BUF_LEN],
            synth_buf_fb: [0; SYNTH_BUF_LEN],
            synth_at: 0,
            synth_fb_at: 0,
            lsf: [0; LSF_LEN],
            lsp: [0; LSF_LEN],
            lspmid: [0; M as usize],
            lsfmid: [0; M as usize],
            aq: [0; AQ_LEN],
            pitch: [0; NB_SUBFR16K as usize],
            pit_gain: [0; NB_SUBFR16K as usize],
            aind: [0; M as usize + 1],
            lspind: [0; M as usize],
            enr_old: 0,
            enr_new: 0,
            xspnew_uw: [0; XSP_LEN],
            xsfnew_uw: [0; XSP_LEN],
            lsf_q_prediction: -1,
            past_core_mode: 0,
        })
    }

    #[test]
    fn buffer_sizes_follow_the_reference_declarations() {
        assert_eq!(SYNTH_BUF_LEN, 1920 + 1200 + 16);
        assert_eq!(LSF_LEN, 48);
        assert_eq!(XSP_LEN, 32);
        assert_eq!(AQ_LEN, 6 * 17);
        assert_eq!(PARAM_LPC_AT, 2 * 729);
    }
}
