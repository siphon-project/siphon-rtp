//! Excitation decoding of an unvoiced NELP frame (TS 26.442 `lib_dec/dec_nelp_fx.c`; TS 26.445
//! §6.1.2.4): the NELP excitation becomes both the adaptive and the total excitation, the pitch
//! and voicing are reset to "purely unvoiced", and the SWB TBE excitation is upsampled from it.

use crate::evs::cnst::{L_FRAME, L_SUBFR_Q6, NB_SUBFR, NB_SUBFR16K};
use crate::evs::com::swb_tbe_com::interp_code_5over2;
use crate::evs::com::tools::{copy, set16};
use crate::evs::dec::nelp_dec::nelp_decoder;
use crate::evs::dec::state::DecoderState;

/// `decod_nelp_fx`: decode the NELP excitation into `exc[exc_at..]` (whose `L_SUBFR` samples
/// before `exc_at` a lost frame reads) and `exc2`, reset the code tilt and the noise enhancer's
/// pitch-gain memory, set the four subframe pitches to `L_SUBFR` (Q6) and the voicing factors to
/// 0, and upsample the excitation into `bwe_exc` (`L_FRAME · 5/2` samples). `q_exc` is the
/// excitation's Q in and out (see [`nelp_decoder`]).
pub fn decod_nelp(
    st: &mut DecoderState,
    coder_type: i16,
    tmp_noise: &mut i16,
    pitch_buf: &mut [i16],
    exc: &mut [i16],
    exc_at: usize,
    exc2: &mut [i16],
    voice_factors: &mut [i16],
    bwe_exc: &mut [i16],
    q_exc: &mut i16,
    bfi: i16,
    gain_buf: &mut [i16],
) {
    let mut exc_nelp = [0i16; L_FRAME as usize];

    *tmp_noise = 0;

    nelp_decoder(
        st,
        &mut exc_nelp,
        exc,
        exc_at,
        q_exc,
        bfi,
        coder_type,
        gain_buf,
    );

    copy(&exc_nelp, &mut exc[exc_at..], L_FRAME);
    copy(&exc_nelp, exc2, L_FRAME);

    st.tilt_code = 0; // purely unvoiced, Q15
    set16(&mut st.tilt_code_dec, 0, NB_SUBFR16K);

    st.dm.prev_state = 0; // Q0
    st.prev_gain_pit_dec = 0; // Q14
    st.dm.prev_gain_pit[0] = st.prev_gain_pit_dec;

    for i in 1..5 {
        st.dm.prev_gain_pit[i] = st.dm.prev_gain_pit[i - 1]; // Q14
    }

    set16(pitch_buf, L_SUBFR_Q6, NB_SUBFR); // L_SUBFR = 64, Q6
    set16(voice_factors, 0, NB_SUBFR16K);
    interp_code_5over2(exc2, bwe_exc, L_FRAME);
}
