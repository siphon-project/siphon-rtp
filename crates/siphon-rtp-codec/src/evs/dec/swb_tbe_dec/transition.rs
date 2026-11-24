//! Cross-fades of the TBE output at a core switch, and the FB TBE decoder (TS 26.442
//! `lib_dec/swb_tbe_dec_fx.c`: `GenTransition_fx`, `GenTransition_WB_fx`, `fb_tbe_dec_fx`).

use crate::evs::cnst::L_SHB_TRANSITION_LENGTH;
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::modif_fs::{
    decimate_allpass_steep_in_place, interpolate_3_over_1_allpass,
    interpolate_3_over_2_allpass_in_place, interpolate_allpass_steep,
};
use crate::evs::com::swb_tbe_com::{flip_and_downmix_generic, synthesise_fb_high_band};
use crate::evs::com::tools::{copy_scale_sig, sum2_mod};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{ALLPASS_POLES_3_OV_2, WINDOW_SHB_32K_FX, WINDOW_SHB_FX};
use crate::itu::basic_ops::{add, l_mult, l_sub, mult_r, negate, shl, sub};
use crate::itu::stl2009::mac_r;

const TRANSITION: usize = L_SHB_TRANSITION_LENGTH as usize;

/// `GenTransition_fx`: the SWB TBE output over a core switch: the tail `old_hb_synth` of the
/// previous HB synthesis (read backwards) cross-faded over 40 samples with the first
/// `(320 - 20) / (16 - 1) = 20` samples of the new HB signal `input` at 32 kHz (after the
/// all-pass interpolation and flipping), then the tail alone up to `length`; resampled to the
/// output rate `target_fs`.
pub fn gen_transition(
    input: &[i16],
    old_hb_synth: &[i16],
    length: i16,
    output: &mut [i16],
    hilbert_mem: &mut [i32],
    state_lsyn_filt_shb_local: &mut [i16],
    mem_resamp_hb_32k: &mut [i16],
    syn_dm_phase: &mut i16,
    target_fs: i32,
    up_mem: &mut [i16],
    rf_flag: i16,
    bitrate: i32,
) {
    const OL_LEN: usize = 2 * (320 - 20) / (16 - 1);
    let mut syn_overlap_32k = [0i16; 640];
    let length_u = length.max(0) as usize;

    interpolate_allpass_steep(
        input,
        state_lsyn_filt_shb_local,
        (320 - 20) / (16 - 1),
        &mut syn_overlap_32k,
    );

    if rf_flag != 0 || l_sub(bitrate, 9600) == 0 {
        // the reference passes the buffer as input and output; the output is written last, over
        // all `OL_LEN` samples, so a separate output buffer then a copy is the same
        let mut flipped = [0i16; OL_LEN];
        let (mem1, rest) = hilbert_mem.split_at_mut(5);
        let (mem2, mem3) = rest.split_at_mut(2 * 4);
        flip_and_downmix_generic(
            &mut syn_overlap_32k,
            &mut flipped,
            OL_LEN as i16,
            mem1,
            mem2,
            mem3,
            syn_dm_phase,
        );
        syn_overlap_32k[..OL_LEN].copy_from_slice(&flipped);
    } else {
        for i in (0..OL_LEN).step_by(2) {
            syn_overlap_32k[i] = negate(syn_overlap_32k[i]);
        }
    }

    for i in 0..OL_LEN {
        let l_tmp = l_mult(WINDOW_SHB_32K_FX[i], old_hb_synth[TRANSITION - 1 - i]);
        output[i] = mac_r(l_tmp, WINDOW_SHB_32K_FX[2 * 20 - 1 - i], syn_overlap_32k[i]);
    }
    for i in OL_LEN..length_u {
        output[i] = old_hb_synth[TRANSITION - 1 - i];
    }

    if l_sub(target_fs, 48000) == 0 {
        interpolate_3_over_2_allpass_in_place(output, length, up_mem, &ALLPASS_POLES_3_OV_2);
    } else if l_sub(target_fs, 16000) == 0 {
        decimate_allpass_steep_in_place(output, mem_resamp_hb_32k, 640);
    }
}

/// `GenTransition_WB_fx`: [`gen_transition`] for the WB TBE: the first 10 samples of the new WB
/// high band `input` (scaled by `prev_qx`), interpolated to 20 at 16 kHz and flipped, cross-faded
/// with the previous tail `old_hb_synth`, scaled by 21299 (Q15), and upsampled to `output_fs`.
pub fn gen_transition_wb(
    input: &[i16],
    old_hb_synth: &[i16],
    prev_qx: i16,
    length: i16,
    output: &mut [i16],
    state_lsyn_filt_shb1: &mut [i16],
    state_lsyn_filt_shb2: &mut [i16],
    output_fs: i32,
    up_mem: &mut [i16],
) {
    let mut speech_buf_16k1 = [0i16; 320];
    let mut speech_buf_16k2 = [0i16; 320];
    let mut upsampled_synth = [0i16; 960];
    let mut input_scaled = [0i16; (320 - 20) / (16 - 1) / 2];
    let length_u = length.max(0) as usize;

    copy_scale_sig(input, &mut input_scaled, (320 - 20) / (16 - 1) / 2, prev_qx);
    interpolate_allpass_steep(
        &input_scaled,
        state_lsyn_filt_shb1,
        (320 - 20) / (16 - 1) / 2,
        &mut speech_buf_16k1,
    );
    interpolate_allpass_steep(
        &speech_buf_16k1,
        state_lsyn_filt_shb2,
        (320 - 20) / (16 - 1),
        &mut speech_buf_16k2,
    );
    for i in (0..(320 - 20) / (16 - 1)).step_by(2) {
        speech_buf_16k2[i] = negate(speech_buf_16k2[i]);
    }

    for i in 0..20 {
        let l_tmp = l_mult(WINDOW_SHB_FX[i], old_hb_synth[TRANSITION - 1 - i]);
        output[i] = mac_r(l_tmp, WINDOW_SHB_FX[20 - 1 - i], speech_buf_16k2[i]);
        output[i] = mult_r(output[i], 21299);
    }
    for i in 20..length_u {
        output[i] = mult_r(old_hb_synth[TRANSITION - 1 - i], 21299);
    }

    if l_sub(output_fs, 32000) == 0 {
        interpolate_allpass_steep(output, up_mem, 320, &mut upsampled_synth);
        output[..640].copy_from_slice(&upsampled_synth[..640]);
    } else if l_sub(output_fs, 48000) == 0 {
        interpolate_3_over_1_allpass(
            output,
            320,
            &mut upsampled_synth,
            up_mem,
            &ALLPASS_POLES_3_OV_2,
        );
        output[..960].copy_from_slice(&upsampled_synth[..960]);
    }
}

/// `fb_tbe_dec_fx`: adds the FB TBE high band (14 to 20 kHz) to the 48 kHz HB synthesis
/// `hb_synth` (960 samples, Q`hb_synth_exp`) from the FB excitation `fb_exc` (320 samples,
/// Q`q_fb_exc`); the band's gain comes from the bitstream (MODE1) or the state (MODE2), and the
/// previous one is repeated after a lost frame.
pub fn fb_tbe_dec(
    st: &mut DecoderState,
    fb_exc: &[i16],
    q_fb_exc: i16,
    hb_synth: &mut [i16],
    hb_synth_exp: i16,
) {
    let mut fb_synth = [0i16; 960];
    let mut ratio: i16 = 0;

    if sub(st.extl, 11) == 0 && st.bfi == 0 {
        let i = if sub(st.codec_mode, 2) == 0 {
            st.idx_gain
        } else {
            get_next_indice(st, 4) as i16
        };
        ratio = shl(1, i);
    } else if sub(st.extl, 11) == 0 && st.bfi != 0 {
        ratio = st.prev_fbbwe_ratio;
    }

    let fb_exc_energy = sum2_mod(fb_exc, 320);
    synthesise_fb_high_band(
        fb_exc,
        q_fb_exc,
        &mut fb_synth,
        fb_exc_energy,
        ratio,
        st.l_frame,
        st.bfi,
        &mut st.prev_fbbwe_ratio,
        &mut st.fbbwe_hpf_mem,
        &mut st.fbbwe_hpf_mem_fx_q,
        hb_synth_exp,
    );
    for i in 0..960 {
        hb_synth[i] = add(hb_synth[i], fb_synth[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lost_fb_frame_repeats_the_previous_ratio_and_adds_silence_for_a_silent_excitation() {
        let mut st = Box::new(DecoderState::zeroed());
        st.extl = 11;
        st.bfi = 1;
        st.l_frame = 320;
        st.prev_fbbwe_ratio = 1000;
        let mut hb_synth = [5i16; 960];
        fb_tbe_dec(&mut st, &[0; 320], 10, &mut hb_synth, 4);
        assert_eq!(hb_synth, [5; 960]);
        assert_eq!(st.prev_fbbwe_ratio, 500);
    }

    #[test]
    fn the_transition_tail_is_copied_after_the_cross_fade() {
        let input = [0i16; 20];
        let mut old_hb_synth = [0i16; TRANSITION];
        old_hb_synth[TRANSITION - 1 - 45] = 321;
        let mut output = [0i16; 640];
        let mut hilbert = [0i32; 21];
        let mut local = [0i16; 6];
        let mut resamp = [0i16; 7];
        let mut phase = 0;
        let mut up_mem = [0i16; 15];
        gen_transition(
            &input,
            &old_hb_synth,
            100,
            &mut output,
            &mut hilbert,
            &mut local,
            &mut resamp,
            &mut phase,
            32000,
            &mut up_mem,
            0,
            13200,
        );
        assert_eq!(output[45], 321);
        assert_eq!(output[46], 0);
    }
}
