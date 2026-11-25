//! `tcx_arith_decode_envelope` of TS 26.442 `lib_dec/arith_coder_dec.c` (TS 26.445 §6.2.2.2.4):
//! the arithmetic decoding of the TCX spectrum against the envelope the LPC shape and the
//! harmonic model give.
//!
//! `Overflow` and `Carry`: nothing here reads them (`tcx_arith_decode` takes the decoder's
//! carry from `st.stl`).

use crate::evs::cnst::{ACELP_13K20, N_MAX_ARI};
use crate::evs::com::arith_coder::env_half;
use crate::evs::com::arith_coder::envelope::{tcx_arith_render_envelope, tcx_arith_scale_envelope};
use crate::evs::com::tools::set32;
use crate::evs::dec::ari_hm_dec::decode::tcx_hm_decode;
use crate::evs::dec::arith_coder_dec::tcx_arith_decode;
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{add, sub};

/// `tcx_arith_decode_envelope`: decode `l_spec` lines of the spectrum into `q_spectrum` (`l_frame`
/// values, the rest cleared) from the parameter bits `prm` within `target_bits`, with the
/// harmonic model when `use_hm` (its parameters in `prm_hm`). `signaling_bits` receives the bits
/// the model's side information took and `arith_bits` those of the arithmetic code. A frame
/// outside the coder's limits or with an unusable model sets `BER_detect` and clears the
/// spectrum.
pub fn tcx_arith_decode_envelope(
    q_spectrum: &mut [i32],
    q_spectrum_e: &mut i16,
    l_frame: i16,
    l_spec: i16,
    st: &mut DecoderState,
    a_ind: &[i16],
    target_bits: i16,
    prm: &[i16],
    use_hm: i8,
    prm_hm: &mut [i16],
    tcxltp_pitch: i16,
    arith_bits: &mut i16,
    signaling_bits: &mut i16,
    nf_seed: &mut i16,
    low_complexity: i16,
) {
    let mut env = [0_i32; N_MAX_ARI as usize];
    let mut envelope_e: i16 = 0;
    let mut hm_bits: i16 = 0;

    if sub(l_spec, N_MAX_ARI) > 0 || sub(target_bits, ACELP_13K20 / 50) > 0 || target_bits <= 0 {
        // this could happen in case of bit errors
        st.ber_detect = 1;
        *signaling_bits = 0;
        *arith_bits = 0;
        set32(q_spectrum, 0, l_frame);

        return;
    }

    *signaling_bits = 0;
    // The reference asserts st->enableTcxLpc.
    let gamma_w: i16 = 32767; // 1.0f Q15
    let gamma_uw = st.inv_gamma;

    tcx_arith_render_envelope(
        a_ind,
        l_frame,
        l_spec,
        st.tcx_cfg.preemph_fac,
        gamma_w,
        gamma_uw,
        &mut env,
    );

    if use_hm != 0 {
        if prm_hm[0] != 0 {
            tcx_hm_decode(
                l_spec,
                &mut env,
                target_bits,
                st.tcx_cfg.coder_type,
                prm_hm,
                tcxltp_pitch,
                &mut hm_bits,
            );

            if hm_bits < 0 {
                st.ber_detect = 1;
                *signaling_bits = 0;
                *arith_bits = 0;
                set32(q_spectrum, 0, l_frame);
                return;
            }
        } else {
            hm_bits = 1;
        }
        *signaling_bits = add(*signaling_bits, hm_bits);
    } else {
        prm_hm[0] = 0; // just to be sure
    }

    let mut l_spec_core = l_spec;
    if st.igf != 0 {
        l_spec_core = l_spec_core.min(st.h_igf_dec.info_igf_start_line);
    }

    tcx_arith_scale_envelope(
        l_spec,
        l_spec_core,
        &mut env,
        target_bits,
        low_complexity,
        &mut envelope_e,
    );

    // `envelope = (Word16*)env`: the scaled envelope the call above left in the half-words.
    let mut envelope = [0_i16; N_MAX_ARI as usize];
    for (k, value) in envelope.iter_mut().enumerate().take(l_spec.max(0) as usize) {
        *value = env_half(&env, k);
    }

    *arith_bits = tcx_arith_decode(
        l_spec,
        &envelope,
        envelope_e,
        target_bits,
        prm,
        q_spectrum,
        q_spectrum_e,
        nf_seed,
        &mut st.stl,
    );

    // safety check in case of bit errors
    if *arith_bits < 0 {
        st.ber_detect = 1;
        set32(q_spectrum, 0, l_frame);
    }

    set32(
        &mut q_spectrum[l_spec.max(0) as usize..],
        0,
        sub(l_frame, l_spec),
    );
}
