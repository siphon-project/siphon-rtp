//! Decoding of the excitation signal in AMR-WB IO mode (TS 26.442 `lib_dec/dec_amr_wb_fx.c`;
//! TS 26.445 §6.2.2 "AMR-WB IO mode decoding", TS 26.190 §6).

use crate::evs::cnst::{
    ACELP_23K85, L_FRAME, L_INTERPOL2, L_SUBFR, M, MODE1, PIT_UP_SAMP, VF_0TH_PARAM_FX,
    VF_1ST_PARAM_FX, VF_2ND_PARAM_FX,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::enhancer::enhancer;
use crate::evs::com::est_tilt::est_tilt;
use crate::evs::com::pred_lt4::pred_lt4;
use crate::evs::com::scale_mem::rescale_exc;
use crate::evs::com::tools::acelp_dec_total_exc;
use crate::evs::dec::gain_dec::{gain_dec_amr_wb, lp_gain_updt};
use crate::evs::dec::inov_dec::inov_decode;
use crate::evs::dec::lp_exc_d::lp_filt_exc_dec;
use crate::evs::dec::pit_dec::pit_decode;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::PITCH_INTER4_2;
use crate::itu::basic_ops::{l_mac, l_mult, l_shl, l_sub, mult_r, round_word, shr};
use crate::itu::stl2009::mac_r;

/// `decod_amr_wb_fx`: decode the excitation of one AMR-WB IO frame, subframe by subframe: pitch
/// lag, adaptive codebook with its low-pass filter, innovation, gains, rescaling, the total
/// excitation and its enhancement, and the HF gain index of 23.85 kbit/s.
///
/// `exc[exc_at..]` is where the reference's `exc_fx` points (the frame, with the excitation
/// history before it); `exc2` starts at the frame. Outputs: `pitch_buf` (Q6, per subframe),
/// `hf_gain` (the 23.85 kbit/s HF gain index per subframe), `voice_factors` (Q15) and `gain_buf`
/// (the pitch gain of each subframe, Q14).
pub fn decod_amr_wb(
    st: &mut DecoderState,
    aq: &[i16],
    pitch_buf: &mut [i16],
    exc: &mut [i16],
    exc_at: usize,
    exc2: &mut [i16],
    hf_gain: &mut [i16],
    voice_factors: &mut [i16],
    gain_buf: &mut [i16],
) {
    let mut code = [0i16; L_SUBFR as usize]; // algebraic codevector
    let mut p_aq_at = 0usize; // pointer to the interpolated LPC parameters
    let mut pt_pitch_at = 0usize; // pointer to the floating pitch
    let mut l_voice_fac_ave: i32 = 0;
    // always restrained pitch Q range in IO mode
    let mut pitch_limit_flag: i16 = 0;
    let core_brate = st.core_brate;

    // ACELP subframe loop
    // the search window of the pitch lag is carried from subframe to subframe
    let mut t0: i16 = 0;
    let mut t0_frac: i16 = 0;
    let mut t0_min: i16 = 0;
    let mut t0_max: i16 = 0;
    let mut i_subfr: i16 = 0;
    while i_subfr < L_FRAME {
        let subframe = i_subfr as usize;

        // Decode the pitch lag
        pitch_buf[pt_pitch_at] = pit_decode(
            st,
            core_brate,
            1,
            L_FRAME,
            i_subfr,
            -1,
            &mut pitch_limit_flag,
            &mut t0,
            &mut t0_frac,
            &mut t0_min,
            &mut t0_max,
            L_SUBFR,
        );

        // Find the adaptive codebook vector
        pred_lt4(
            exc,
            exc_at + subframe,
            t0,
            t0_frac,
            L_SUBFR + 1,
            &PITCH_INTER4_2,
            L_INTERPOL2,
            PIT_UP_SAMP,
        );

        // LP filtering of the adaptive excitation
        lp_filt_exc_dec(
            st, MODE1, core_brate, 1, -1, i_subfr, L_SUBFR, L_FRAME, 0, exc, exc_at,
        );

        // Innovation decoding
        let tilt_code = st.tilt_code;
        inov_decode(
            st,
            core_brate,
            1,
            L_FRAME,
            -1,
            0,
            i_subfr,
            -1,
            &aq[p_aq_at..],
            tilt_code,
            pitch_buf[pt_pitch_at],
            &mut code,
        );

        // Gain decoding; estimate the spectrum tilt and the voicing
        let mut gain_pit: i16 = 0;
        let mut l_gain_code: i32 = 0;
        let mut gain_inov: i16 = 0;
        let mut l_norm_gain_code: i32 = 0;
        gain_dec_amr_wb(
            st,
            core_brate,
            &mut gain_pit,
            &mut l_gain_code,
            &mut gain_inov,
            &code,
            &mut l_norm_gain_code,
        );

        // update the LP filtered gains for the case of frame erasures
        lp_gain_updt(
            i_subfr,
            gain_pit,
            l_norm_gain_code,
            &mut st.lp_gainp,
            &mut st.lp_gainc,
            L_FRAME,
        );

        let mut voice_fac: i16 = 0;
        st.tilt_code = est_tilt(
            &exc[exc_at + subframe..],
            gain_pit,
            &code,
            l_gain_code,
            &mut voice_fac,
            st.q_exc,
        );

        rescale_exc(
            Some(&mut st.dct_post_old_exc),
            exc,
            exc_at + subframe,
            None,
            Some(&mut st.last_exc_dct_in),
            L_SUBFR,
            0,
            l_gain_code,
            &mut st.q_exc,
            &mut st.q_subfr,
            Some(exc2),
            i_subfr,
            -1,
        );

        let gain_code16 = round_word(l_shl(l_gain_code, st.q_exc)); // Q_exc

        // Find the total excitation
        acelp_dec_total_exc(
            &mut exc[exc_at..],
            exc2,
            gain_code16,
            gain_pit,
            i_subfr,
            &code,
        );

        // Excitation enhancements
        enhancer(
            core_brate,
            1,
            -1,
            i_subfr,
            L_FRAME,
            voice_fac,
            st.stab_fac,
            l_norm_gain_code,
            gain_inov,
            &mut st.gc_threshold,
            &mut code,
            exc2,
            gain_pit,
            &mut st.dm,
            st.q_exc,
        );

        // HF gain modification factors at 23.85 kbps
        if l_sub(core_brate, i32::from(ACELP_23K85)) == 0 {
            hf_gain[shr(i_subfr, 6) as usize] = get_next_indice(st, 4) as i16;
        }

        // voice_fac = VF_0th_PARAM + VF_1st_PARAM * voice_fac + VF_2nd_PARAM * voice_fac * voice_fac
        let mut l_tmp = l_mult(VF_2ND_PARAM_FX, mult_r(voice_fac, voice_fac));
        l_tmp = l_mac(l_tmp, VF_1ST_PARAM_FX, voice_fac);
        voice_fac = mac_r(l_tmp, VF_0TH_PARAM_FX, 32767);

        // voice_factors[i_subfr/L_SUBFR] = min( max(0.0f, voice_fac), 1.0f)
        // s_min( s_max(0, voice_fac), 32767 ): the upper limit is the largest Word16
        voice_factors[subframe / L_SUBFR as usize] = voice_fac.max(0);
        p_aq_at += M as usize + 1;
        pt_pitch_at += 1;

        l_voice_fac_ave = l_mac(l_voice_fac_ave, 8192, voice_fac);
        gain_buf[subframe / L_SUBFR as usize] = gain_pit;
        i_subfr += L_SUBFR;
    }

    st.lt_voice_fac = round_word(l_voice_fac_ave);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::cnst::{ACELP_6K60, L_EXC_MEM_DEC};

    #[test]
    fn a_zero_bitstream_frame_decodes_without_touching_the_history() {
        let mut st = Box::new(DecoderState::zeroed());
        st.core_brate = i32::from(ACELP_6K60);
        st.opt_amr_wb = 1;
        let aq = [0i16; 4 * (M as usize + 1)];
        let mut pitch_buf = [0i16; 4];
        let mut exc = [0i16; L_EXC_MEM_DEC as usize + L_FRAME as usize + 1];
        let mut exc2 = [0i16; L_FRAME as usize];
        let mut hf_gain = [0i16; 4];
        let mut voice_factors = [0i16; 4];
        let mut gain_buf = [0i16; 4];
        decod_amr_wb(
            &mut st,
            &aq,
            &mut pitch_buf,
            &mut exc,
            L_EXC_MEM_DEC as usize,
            &mut exc2,
            &mut hf_gain,
            &mut voice_factors,
            &mut gain_buf,
        );
        assert!(voice_factors.iter().all(|&factor| factor >= 0));
        assert_eq!(hf_gain, [0; 4]);
    }
}
