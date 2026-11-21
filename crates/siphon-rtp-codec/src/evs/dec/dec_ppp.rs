//! SC-VBR quarter-rate PPP frame decoding (TS 26.442 `lib_dec/dec_ppp_fx.c`; TS 26.445 §6.1.2.3).

use crate::evs::cnst::{L_FRAME, M, NB_SUBFR, NB_SUBFR16K};
use crate::evs::com::ppp::deemph_lpc;
use crate::evs::com::swb_tbe_com::interp_code_5over2;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::voiced_dec::ppp_voiced_decoder;

/// `decod_ppp_fx`: decodes a PPP frame into the excitation `exc` / `exc2` (at `exc_at` /
/// `exc2_at` in their history buffers), the per-subframe pitch `pitch_buf` (Q6), the BWE excitation
/// `bwe_exc` and clears `voice_factors` and `gain_buf`; updates the display memory (`dm`) and the
/// tilt of the code. The LP filter used is the last subframe's of `aq` with de-emphasis folded in.
pub fn decod_ppp(
    st: &mut DecoderState,
    aq: &[i16],
    pitch_buf: &mut [i16],
    exc: &mut [i16],
    exc_at: usize,
    exc2: &mut [i16],
    exc2_at: usize,
    bfi: i16,
    gain_buf: &mut [i16],
    voice_factors: &mut [i16],
    bwe_exc: &mut [i16],
) {
    const ORDER: usize = M as usize;
    let mut lpc_de_curr = [0i16; ORDER + 1];
    let mut lpc_de_old = [0i16; ORDER + 1];
    let mut p_aq_curr = [0i16; ORDER];
    let p_aq_old = [0i16; ORDER + 1];
    let mut exc_q_ppp = [0i16; L_FRAME as usize];
    let mut pitch = [0i16; NB_SUBFR as usize];

    // call the voiced decoder at this point
    for k in 0..ORDER {
        p_aq_curr[k] = aq[k + 3 * (ORDER + 1) + 1]; // Q12
    }

    deemph_lpc(&p_aq_curr, &p_aq_old, &mut lpc_de_curr, &mut lpc_de_old, 0); // LPC in Q12

    ppp_voiced_decoder(
        st,
        &mut exc_q_ppp,
        &lpc_de_curr,
        &*exc,
        exc_at,
        &mut pitch,
        bfi,
    );

    st.tilt_code = st.tilt_code_dec[3];

    exc[exc_at..exc_at + L_FRAME as usize].copy_from_slice(&exc_q_ppp);
    let frame: [i16; L_FRAME as usize] = exc[exc_at..exc_at + L_FRAME as usize]
        .try_into()
        .unwrap_or([0; L_FRAME as usize]);
    exc2[exc2_at..exc2_at + L_FRAME as usize].copy_from_slice(&frame);

    st.dm.prev_state = 2;

    st.dm.prev_gain_pit[0] = st.prev_gain_pit_dec; // Q14

    for k in 3..7 {
        st.dm.prev_gain_pit[k - 2] = st.dm.prev_gain_pit[k - 3]; // Q14
    }

    pitch_buf[..NB_SUBFR as usize].copy_from_slice(&pitch); // Q6

    interp_code_5over2(&exc2[exc2_at..], bwe_exc, L_FRAME);
    voice_factors[..NB_SUBFR16K as usize].fill(0);

    gain_buf[..NB_SUBFR16K as usize].fill(0);
}
