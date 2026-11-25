//! The MODE2 part of `evs_dec_fx` (the `ELSE /* MODE2 PART */` block of
//! `lib_dec/evs_dec_fx.c`): concealment selection, the MODE2 core (`dec_acelp_tcx_frame`), the
//! TBE interface of an IGF frame, and the post-processing in the CLDFB domain (FD-CNG, bass
//! post-filter, TEC / TFA, the synthesis), the delay alignment of the ACELP, TCX and TD-BWE
//! components and the TCX-LTP post-filter. The frame ends in `output_sp` (and `w.synth`).
//!
//! `Overflow` and `Carry`: nothing in this file reads them.

mod postproc;
mod transitions;

use super::FrameWork;
use crate::evs::cnst::{
    ACELP_CORE, ACTIVE_FRAME, FB, FB_TBE, FB_TBE_1K8, IGF_BWE, L_FRAME16K, L_FRAME48K, L_FRAME_MAX,
    MODE1, RF_TCXFD, RF_TCXTD2, SWB, SWB_TBE, SWB_TBE_1K6, WB, WB_TBE, WB_TBE_0K35,
};
use crate::evs::com::bitstream::{FRAMEMODE_MISSING, FRAMEMODE_NORMAL};
use crate::evs::dec::dec_acelp_tcx_main::{
    dec_acelp_tcx_frame, DEC_CONCEALMENT_EXT, DEC_NO_FRAM_LOSS,
};
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::swb_tbe_dec::{fb_tbe_dec, swb_tbe_dec, tbe_reset_dec, wb_tbe_dec};
use crate::evs::error::EvsError;
use crate::itu::basic_ops::{l_deposit_l, l_sub, sub};

/// The MODE2 decode of one frame into `output_sp` (`output_frame` samples at the output rate, Q0).
/// `frame_mode` is `FRAMEMODE_NORMAL` or `FRAMEMODE_MISSING` and becomes missing when the core
/// concealed the frame. Returns whether the whole frame was concealed (`concealWholeFrameTmp`).
///
/// # Errors
/// [`EvsError::Malformed`] when the decoder was not initialised for MODE2 (no CLDFB banks).
pub(super) fn evs_dec_mode2(
    st: &mut DecoderState,
    w: &mut FrameWork,
    output_sp: &mut [i16],
    frame_mode: &mut i16,
) -> Result<bool, EvsError> {
    let mut pcm_buf_fb = [0i16; L_FRAME_MAX as usize];

    // CONCEALMENT
    let mut conceal_whole_frame: i16 = 0;

    if sub(*frame_mode, FRAMEMODE_NORMAL) == 0 {
        st.m_decode_mode = DEC_NO_FRAM_LOSS;
    }

    if sub(*frame_mode, FRAMEMODE_MISSING) == 0 {
        if st.use_partial_copy != 0
            && sub(st.rf_frame_type, RF_TCXFD) >= 0
            && sub(st.rf_frame_type, RF_TCXTD2) <= 0
        {
            st.m_decode_mode = DEC_NO_FRAM_LOSS;
        } else {
            st.m_decode_mode = DEC_CONCEALMENT_EXT;
        }
    }

    if sub(st.m_decode_mode, DEC_CONCEALMENT_EXT) == 0 {
        conceal_whole_frame = 1;
    }

    // DECODE CORE
    dec_acelp_tcx_frame(
        st,
        &mut w.coder_type,
        &mut conceal_whole_frame,
        output_sp,
        &mut pcm_buf_fb,
        &mut w.bwe_exc_extended,
        &mut w.voice_factors,
        &mut w.pitch_buf,
    );

    let conceal_whole_frame_tmp = conceal_whole_frame;
    if st.bfi != 0 {
        *frame_mode = FRAMEMODE_MISSING;
    }
    if st.igf != 0 {
        igf_tbe_interface(st, w);
    }

    if sub(st.m_frame_type, ACTIVE_FRAME) != 0 {
        st.extl = -1;
        st.extl_brate = l_deposit_l(0);
    }

    // APPLY POSTPROC
    let time_in_e = postproc::postproc(st, w, output_sp, &mut pcm_buf_fb, conceal_whole_frame)?;
    transitions::transitions(st, w, output_sp, &pcm_buf_fb, time_in_e);

    let frame = w.output_frame.max(0) as usize;
    w.synth[..frame].copy_from_slice(&output_sp[..frame]);
    Ok(conceal_whole_frame_tmp != 0)
}

/// The TBE interface of an IGF frame: the extension layer, the TBE decoders of an ACELP frame
/// and the transitions out of / into the TBE.
fn igf_tbe_interface(st: &mut DecoderState, w: &mut FrameWork) {
    let output = w.output_frame.max(0) as usize;

    if (st.bfi == 0 || sub(st.last_core, ACELP_CORE) == 0) && sub(st.core, ACELP_CORE) == 0 {
        match st.bwidth {
            WB => {
                st.extl = WB_TBE;
                st.extl_brate = i32::from(WB_TBE_0K35);
            }
            SWB => {
                st.extl = SWB_TBE;
                st.extl_brate = i32::from(SWB_TBE_1K6);
            }
            FB => {
                st.extl = FB_TBE;
                st.extl_brate = i32::from(FB_TBE_1K8);
            }
            _ => {}
        }
    } else {
        st.extl = IGF_BWE;
        st.extl_brate = l_deposit_l(0);
    }

    if l_sub(st.output_fs, 8000) == 0
        || (l_sub(st.output_fs, 16000) == 0 && sub(st.l_frame, L_FRAME16K) == 0)
    {
        st.extl = -1;
    }

    st.core_brate = l_sub(st.total_brate, st.extl_brate);

    st.bws_cnt = 0;
    st.bws_cnt1 = 0;
    st.tilt_wb = 0;

    if sub(st.m_frame_type, ACTIVE_FRAME) == 0 {
        if (st.bfi == 0 || sub(st.last_core, ACELP_CORE) == 0) && sub(st.core, ACELP_CORE) == 0 {
            if sub(st.extl, WB_TBE) == 0 {
                let q_exc = st.q_exc;
                wb_tbe_dec(
                    st,
                    w.coder_type,
                    &w.bwe_exc_extended,
                    q_exc,
                    &w.voice_factors,
                    &mut w.hb_synth,
                    &mut w.hb_synth_exp,
                );
            } else if sub(st.extl, SWB_TBE) == 0 || sub(st.extl, FB_TBE) == 0 {
                // SWB TBE decoder
                let q_exc = st.q_exc;
                let old_core_synth = st.old_core_synth;
                swb_tbe_dec(
                    st,
                    w.coder_type,
                    &w.bwe_exc_extended,
                    q_exc,
                    &w.voice_factors,
                    &old_core_synth,
                    &mut w.fb_exc,
                    &mut w.q_fb_exc,
                    &mut w.hb_synth,
                    &mut w.hb_synth_exp,
                    &w.pitch_buf,
                );

                if sub(st.extl, FB_TBE) == 0 && sub(w.output_frame, L_FRAME48K) == 0 {
                    fb_tbe_dec(st, &w.fb_exc, w.q_fb_exc, &mut w.hb_synth, w.hb_synth_exp);
                }
            }
            st.old_hb_synth[..output].copy_from_slice(&w.hb_synth[..output]);
        } else if sub(st.last_core, ACELP_CORE) == 0 {
            transitions::tbe_transition(st, w);
            let bwidth = st.bwidth;
            tbe_reset_dec(st, bwidth);
        } else if sub(st.last_codec_mode, MODE1) == 0 {
            transitions::tbe_reset_after_mode1(st);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode2_decode_modes_match_the_reference_enum() {
        assert_eq!(DEC_NO_FRAM_LOSS, 0);
        assert_eq!(DEC_CONCEALMENT_EXT, 1);
    }
}
