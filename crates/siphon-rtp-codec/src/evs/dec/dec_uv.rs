//! Decoding of an unvoiced (UNVOICED, Gaussian-codebook) frame of the MODE1 ACELP core (TS 26.442
//! `lib_dec/dec_uv.c`; TS 26.445 §6.1.1.2.7).

use crate::evs::cnst::{L_FRAME, L_SUBFR, NB_SUBFR};
use crate::evs::com::enhancer::enhancer;
use crate::evs::com::swb_tbe_com::interp_code_5over2;
use crate::evs::com::tools::set16;
use crate::evs::dec::gaus_dec::gaus_dec;
use crate::evs::dec::rst_dec::cng_reset_dec;
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{extract_h, sub};

const SUBFR: usize = L_SUBFR as usize;

/// `decod_unvoiced_fx`: decode the four Gaussian-excitation subframes of an unvoiced 12.8 kHz
/// frame into `exc` (from `exc[exc_at]`, with the past excitation in front), `exc2` (the frame
/// itself) and the BWE excitation `bwe_exc` (from `bwe_exc[bwe_exc_at]`); `pitch_buf` and
/// `voice_factors` receive the per-subframe pitch (floating) and voicing, `tmp_noise` the last
/// subframe's normalised gain (for the noise-shaping post-processing), `gain_buf` zeros.
///
/// `aq` (the quantised LP filters) is only stepped through by the reference, never read.
pub fn decod_unvoiced(
    st: &mut DecoderState,
    aq: &[i16],
    coder_type: i16,
    tmp_noise: &mut i16,
    pitch_buf: &mut [i16],
    voice_factors: &mut [i16],
    exc: &mut [i16],
    exc_at: usize,
    exc2: &mut [i16],
    bwe_exc: &mut [i16],
    bwe_exc_at: usize,
    gain_buf: &mut [i16],
) {
    let _ = aq;
    let mut gain_pit: i16 = 0;
    let mut gain_code: i32 = 0;
    let mut gain_inov: i16 = 0;
    let mut norm_gain_code: i32 = 0;
    let mut voice_fac: i16 = 0;
    let mut code = [0i16; SUBFR];

    if sub(st.last_ppp_mode_dec, 1) == 0 || sub(st.last_nelp_mode_dec, 1) == 0 {
        // SC-VBR - reset the decoder, to avoid memory not updated issue for this unrealistic case
        cng_reset_dec(st, pitch_buf, voice_factors);
    }

    for (subframe, i_subfr) in (0..L_FRAME).step_by(SUBFR).enumerate() {
        // Gaussian codebook: the gain, the pitch and the excitation of the subframe
        gaus_dec(
            st,
            st.core_brate,
            i_subfr,
            &mut code,
            &mut norm_gain_code,
            &mut gain_inov,
            &mut voice_fac,
            &mut gain_pit,
            &mut pitch_buf[subframe],
            exc,
            exc_at,
            &mut gain_code,
            exc2,
            bwe_exc,
            bwe_exc_at,
        );

        *tmp_noise = extract_h(norm_gain_code);

        // Excitation enhancer
        enhancer(
            st.core_brate,
            0,
            coder_type,
            i_subfr,
            L_FRAME,
            voice_fac,
            st.stab_fac,
            norm_gain_code,
            gain_inov,
            &mut st.gc_threshold,
            &mut code,
            exc2,
            gain_pit,
            &mut st.dm,
            st.q_exc,
        );

        voice_factors[subframe] = 0;

        let at = i_subfr as usize;
        interp_code_5over2(
            &exc[exc_at + at..exc_at + at + SUBFR],
            &mut bwe_exc[bwe_exc_at + at * 5 / 2..],
            L_SUBFR,
        );

        st.tilt_code_dec[subframe] = st.tilt_code;
    }

    // SC-VBR
    st.prev_gain_pit_dec = gain_pit;

    set16(gain_buf, 0, NB_SUBFR);
}
