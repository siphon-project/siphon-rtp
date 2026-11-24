//! SWB / FB TBE decoder (TS 26.442 `lib_dec/swb_tbe_dec_fx.c`, `swb_tbe_dec_fx`; TS 26.445 §6.1.3).

use super::memory::{find_max_mem_dec, rescale_gen_shb_mem_dec};
use super::swb_gain::{
    swb_tbe_dec_frame_power, swb_tbe_dec_gain_frame, swb_tbe_dec_gain_shape_smoothing,
    swb_tbe_dec_prev_energies,
};
use super::swb_params::{
    swb_tbe_dec_fractive, swb_tbe_dec_lpc, swb_tbe_dec_parameters, SwbParameters,
};
use crate::evs::basop::mult_32_16;
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::com::modif_fs::{decimate_allpass_steep, interpolate_3_over_2_allpass};
use crate::evs::com::swb_tbe_com::{
    gen_shaped_shb_excitation, gen_shb_synth, post_short_term, scale_shaped_shb, swb_formant_fac,
};
use crate::evs::com::tools::{root_a_over_b, scale_sig};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{ALLPASS_POLES_3_OV_2, SUBWIN_SHB_FX, WINDOW_SHB_FX};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, l_abs, l_add, l_deposit_h, l_mac, l_mult, l_shl, l_shr, l_sub,
    mult_r, norm_l, norm_s, round_word, shl, sub,
};
use crate::itu::stl2009::{i_mult, l_mac0};

/// `L_SHB_TRANSITION_LENGTH`: the length of the HB synthesis tail kept for a core switch.
const TRANSITION: usize = 222;

/// The Q of the extended excitation, its 16-bit form with the previous frame's 12 samples in front
/// (`bwe_exc_extended_16`, 652 samples) and the memories rescaled to it. Returns `Q_bwe_exc`
/// (before the `- 16` the excitation generator wants) and the memory headroom `n_mem3`.
fn swb_tbe_dec_excitation_q(
    st: &mut DecoderState,
    bwe_exc_extended: &[i32],
    q_exc: i16,
    bwe_exc_extended_16: &mut [i16; 640 + 12],
) -> (i16, i16, i16) {
    let mut l_max: i32 = 0;
    for &value in &bwe_exc_extended[..640] {
        l_max = l_max.max(l_abs(value));
    }
    let mut q_bwe_exc = norm_l(l_max);
    if l_max == 0 {
        q_bwe_exc = 31;
    }
    q_bwe_exc = add(q_bwe_exc, add(q_exc, q_exc));

    let (mut n_mem, mut n_mem2, mut n_mem3) = (0, 0, 0);
    find_max_mem_dec(st, &mut n_mem, &mut n_mem2, &mut n_mem3);
    let tmp = add(st.prev_q_bwe_exc, n_mem);
    if sub(q_bwe_exc, tmp) > 0 {
        q_bwe_exc = tmp;
    }
    let mut sc = sub(q_bwe_exc, st.prev_q_bwe_exc);
    if sc != 0 {
        rescale_gen_shb_mem_dec(st, sc);
    }
    bwe_exc_extended_16[..12].copy_from_slice(&st.old_bwe_exc_extended);
    sc = sub(q_bwe_exc, add(q_exc, q_exc));
    for cnt in 0..640 {
        bwe_exc_extended_16[cnt + 12] = round_word(l_shl(bwe_exc_extended[cnt], sc));
    }
    st.old_bwe_exc_extended
        .copy_from_slice(&bwe_exc_extended_16[640..652]);
    (q_bwe_exc, n_mem2, n_mem3)
}

/// The scaling of the first 30 samples of the shaped excitation so that its level follows the
/// previous frame's tail (the cross-fade `prev_pow` / `curr_pow` of the reference).
fn swb_tbe_dec_excitation_continuity(
    shaped_shb_excitation: &mut [i16; 340],
    q_bwe_exc: i16,
    voice_factors: &[i16],
) {
    let tmp = sub(shl(q_bwe_exc, 1), 31 + 16);
    let mut prev_pow = l_shl(1407374848, tmp);
    let mut curr_pow = l_shl(1407374848, tmp);
    for i in 0..20 + 10 {
        prev_pow = l_mac0(prev_pow, shaped_shb_excitation[i], shaped_shb_excitation[i]);
        curr_pow = l_mac0(
            curr_pow,
            shaped_shb_excitation[i + 20 + 10],
            shaped_shb_excitation[i + 20 + 10],
        );
    }
    if sub(voice_factors[0], 24576) > 0 {
        curr_pow = l_shr(curr_pow, 2);
    }
    let mut exp: i16 = 0;
    let mut l_scale = root_a_over_b(
        curr_pow,
        shl(q_bwe_exc, 1),
        prev_pow,
        shl(q_bwe_exc, 1),
        &mut exp,
    );
    for sample in &mut shaped_shb_excitation[..20] {
        let l_tmp = mult_32_16(l_scale, *sample);
        *sample = round_word(l_shl(l_tmp, exp));
    }
    if exp < 0 {
        l_scale = l_shl(l_scale, exp);
        exp = 0;
    }
    for (i, sample) in shaped_shb_excitation
        .iter_mut()
        .enumerate()
        .take(20 + 10)
        .skip(20)
    {
        let mut temp = i_mult(sub(i as i16, 19), 3277);
        let l_tmp1 = mult_32_16(l_shl(1, sub(31, exp)), temp);
        temp = sub(32767, temp);
        l_scale = l_add(mult_32_16(l_scale, temp), l_tmp1);
        let l_tmp = mult_32_16(l_scale, *sample);
        *sample = round_word(l_shl(l_tmp, exp));
    }
}

/// The energies of the four quarter frames of the excitation: `ener_tmp[i]` (Q of `q_bwe_exc`,
/// 1/4 of their sum below) and the frame energy `ener` (Q of the synthesis).
fn swb_tbe_dec_quarter_energies(
    shaped_shb_excitation: &[i16; 340],
    q_bwe_exc: i16,
) -> ([i32; 4], i16) {
    let mut ener_tmp = [0i32; 4];
    let mut l_ener: i32 = 0;
    let l_subframe = 320 / 4;
    for i in 0..4 {
        let mut l_tmp: i32 = 0;
        for j in 0..l_subframe {
            let value = shaped_shb_excitation[i * l_subframe + j];
            l_tmp = l_mac0(l_tmp, value, value);
        }
        l_tmp = mult_32_16(l_tmp, 410);
        if l_tmp != 0 {
            let mut exp = norm_l(l_tmp);
            let mut tmp = extract_h(l_shl(l_tmp, exp));
            exp = sub(exp, 30 - (2 * q_bwe_exc));
            tmp = div_s(16384, tmp);
            let l_root = isqrt_lc(l_deposit_h(tmp), &mut exp);
            ener_tmp[i] = l_shl(l_root, sub(add(exp, shl(q_bwe_exc, 1)), 31));
            l_ener = l_add(l_ener, l_shr(ener_tmp[i], 2));
        }
    }
    let ener = round_word(l_shl(l_ener, sub(19, shl(q_bwe_exc, 1)))).max(1);
    (ener_tmp, ener)
}

/// The upsampling of the 32 kHz SWB TBE synthesis to the output rate (with the `29491` Q15 gain
/// at MODE1) and the FB excitation level for 48 kHz output.
fn swb_tbe_dec_output(
    st: &mut DecoderState,
    gain_frame: i32,
    gain_shape: &[i16; 16],
    error: &mut [i16; 640],
    synth: &mut [i16],
    white_exc16k: &mut [i16],
    q_white_exc: &mut i16,
) {
    let synth_scale: i16 = if sub(st.codec_mode, 1) == 0 {
        29491
    } else {
        32767
    };
    if l_sub(st.output_fs, 48000) == 0 {
        if l_sub(i32::from(st.extl), 11) == 0 {
            let mut tmp = norm_l(gain_frame);
            if gain_frame == 0 {
                tmp = 31;
            }
            let l_tmp = l_shl(gain_frame, tmp);
            let mut tmp1: i16 = 0;
            for i in 0..320 {
                let l_tmp1 = mult_32_16(l_tmp, gain_shape[16 * i / 320]);
                white_exc16k[i] = round_word(mult_32_16(l_tmp1, white_exc16k[i]));
                tmp1 = tmp1.max(abs_s(white_exc16k[i]));
            }
            *q_white_exc = sub(add(*q_white_exc, tmp), 13);
            tmp = norm_s(tmp1);
            if tmp1 == 0 {
                tmp = 15;
            }
            for sample in white_exc16k[..320].iter_mut() {
                *sample = shl(*sample, sub(tmp, 1));
            }
            *q_white_exc = sub(add(*q_white_exc, tmp), 1);
        }
        if sub(synth_scale, 32767) != 0 {
            for sample in error.iter_mut() {
                *sample = mult_r(*sample, synth_scale);
            }
        }
        interpolate_3_over_2_allpass(
            error,
            640,
            synth,
            &mut st.int_3_over_2_tbemem_dec,
            &ALLPASS_POLES_3_OV_2,
        );
    } else if l_sub(st.output_fs, 32000) == 0 {
        if sub(synth_scale, 32767) != 0 {
            for i in 0..640 {
                synth[i] = mult_r(synth_scale, error[i]);
            }
        } else {
            synth[..640].copy_from_slice(&error[..]);
        }
    } else if l_sub(st.output_fs, 16000) == 0 {
        if sub(synth_scale, 32767) != 0 {
            for sample in error.iter_mut() {
                *sample = mult_r(*sample, synth_scale);
            }
        }
        decimate_allpass_steep(error, &mut st.mem_resamp_hb_32k, 640, synth);
    }
}

/// `swb_tbe_dec_fx`: decodes the SWB / FB time-domain bandwidth extension of one frame into
/// `synth` (640 samples at 32 kHz, 320 at 16 kHz, 960 at 48 kHz; Q`q_synth`). `bwe_exc_extended`
/// is the 32 kHz extended excitation (Q`q_exc` squared), `old_syn_12k8_16k` the core synthesis
/// for the tilt estimate and `pitch_buf` the sub-frame pitches. For the FB TBE `white_exc16k`
/// receives the FB excitation (Q`q_white_exc`).
pub fn swb_tbe_dec(
    st: &mut DecoderState,
    coder_type: i16,
    bwe_exc_extended: &[i32],
    q_exc: i16,
    voice_factors: &[i16],
    old_syn_12k8_16k: &[i16],
    white_exc16k: &mut [i16],
    q_white_exc: &mut i16,
    synth: &mut [i16],
    q_synth: &mut i16,
    pitch_buf: &[i16],
) {
    let mut shaped_shb_excitation = [0i16; 320 + 20];
    let mut shaped_shb_excitation_temp = [0i16; 320];
    let mut bwe_exc_extended_16 = [0i16; 640 + 12];
    let mut lpc_shb = [0i16; 10 + 1];
    let mut lpc_shb_sf = [0i16; 4 * (10 + 1)];
    let mut lsp_shb_2 = [0i16; 10];
    let mut vf_modified = [0i16; 5];
    let mut error = [0i16; 640];
    let shb_res_dummy = [0i16; 320];

    st.shb_dtx_count = 0;
    let q_shb: i16 = 0;
    let (is_fractive, tilt_swb_fec) = swb_tbe_dec_fractive(st, old_syn_12k8_16k);
    let mut parameters: SwbParameters = swb_tbe_dec_parameters(st, is_fractive, tilt_swb_fec);

    st.gain_shape_delay.copy_within(4..8, 0);
    if st.rf_flag != 0 || l_sub(st.total_brate, 9600) == 0 {
        for i in 0..16 / 4 {
            st.gain_shape_delay[i + 4] = parameters.gain_shape[i * 4].clamp(3277, 16384);
        }
    } else {
        for i in 0..16 / 4 {
            st.gain_shape_delay[i + 4] = parameters.gain_shape[i * 4];
        }
    }

    let mut l_tmp = l_mult(voice_factors[0], 8192);
    l_tmp = l_mac(l_tmp, voice_factors[1], 8192);
    l_tmp = l_mac(l_tmp, voice_factors[2], 8192);
    let mean_vf = crate::itu::stl2009::mac_r(l_tmp, voice_factors[3], 8192);
    vf_modified.copy_from_slice(&voice_factors[..5]);
    if sub(coder_type, 2) == 0 || sub(mean_vf, 13107) > 0 {
        for i in 1..4 {
            let l_tmp = l_mult(voice_factors[i], 26214);
            vf_modified[i] = crate::itu::stl2009::mac_r(l_tmp, voice_factors[i - 1], 6554);
        }
        if sub(st.l_frame, 256) != 0 {
            let l_tmp = l_mult(voice_factors[4], 26214);
            vf_modified[4] = crate::itu::stl2009::mac_r(l_tmp, voice_factors[3], 6554);
        }
    }

    swb_tbe_dec_lpc(
        st,
        coder_type,
        &parameters.lsf_shb,
        &mut lpc_shb,
        &mut lpc_shb_sf,
        &mut lsp_shb_2,
    );

    st.swb_lsp_prev_interp.copy_from_slice(&lsp_shb_2);
    st.prev3_shb_ener_sf = st.prev2_shb_ener_sf;
    st.prev2_shb_ener_sf = st.prev1_shb_ener_sf;
    st.prev1_shb_ener_sf = parameters.shb_ener_sf_32;
    st.prev_res_shb_gshape = parameters.shb_res_gshape[4];
    st.prev_mix_factors = parameters.mix_factors;
    st.lsp_shb_prev_prev.copy_from_slice(&st.lsp_shb_prev);
    st.lsp_shb_prev.copy_from_slice(&parameters.lsf_shb);
    let mut vind = shl(parameters.mix_factors, 3 - 15);
    let formant_fac = swb_formant_fac(lpc_shb[1], &mut st.tilt_mem);

    let (mut q_bwe_exc, n_mem2, n_mem3) =
        swb_tbe_dec_excitation_q(st, bwe_exc_extended, q_exc, &mut bwe_exc_extended_16);

    shaped_shb_excitation[..20].copy_from_slice(&st.state_syn_shbexc);
    st.prev_q_bwe_exc = q_bwe_exc;
    q_bwe_exc = sub(q_bwe_exc, 16);
    let mut q_bwe_exc_fb = st.prev_q_bwe_exc_fb;
    if l_sub(st.total_brate, 32000) > 0 {
        for j in 0..4 {
            lpc_shb_sf[j * (10 + 1)..(j + 1) * (10 + 1)].copy_from_slice(&lpc_shb);
        }
    }
    gen_shaped_shb_excitation(
        &mut shaped_shb_excitation,
        20,
        &lpc_shb,
        white_exc16k,
        &mut st.mem_csfilt,
        &mut st.mem_gen_sh_bexc_filt_down_shb,
        &mut st.state_lpc_syn,
        coder_type,
        &bwe_exc_extended_16,
        &mut st.bwe_seed,
        &mut vf_modified,
        st.extl,
        &mut st.tbe_demph,
        &mut st.tbe_premph,
        &lpc_shb_sf,
        parameters.shb_ener_sf_32,
        &parameters.shb_res_gshape,
        &shb_res_dummy,
        &mut vind,
        formant_fac,
        &mut st.fb_state_lpc_syn,
        &mut st.fb_tbe_demph,
        &mut q_bwe_exc,
        &mut q_bwe_exc_fb,
        q_shb,
        n_mem2,
        st.prev_q_bwe_syn,
        st.total_brate,
        st.prev_bfi,
    );
    *q_white_exc = q_bwe_exc_fb;
    st.prev_q_bwe_exc_fb = if sub(st.extl, 11) == 0 {
        q_bwe_exc_fb
    } else {
        51
    };

    for value in &mut st.mem_stp_swb[..10] {
        // `Q_bwe_exc - prev_Q_bwe_syn` is a C `int`, converted to the operator's `Word16`
        *value = shl(
            *value,
            (i32::from(q_bwe_exc) - i32::from(st.prev_q_bwe_syn)) as i16,
        );
    }
    for i in (0..320).step_by(320 / 4) {
        post_short_term(
            &shaped_shb_excitation,
            20 + i,
            &lpc_shb,
            &mut shaped_shb_excitation_temp[i..],
            &mut st.mem_stp_swb,
            st.ptr_mem_stp_swb,
            &mut st.gain_prec_swb,
            &mut st.mem_zero_swb,
            formant_fac,
        );
    }
    shaped_shb_excitation[20..340].copy_from_slice(&shaped_shb_excitation_temp);

    swb_tbe_dec_excitation_continuity(&mut shaped_shb_excitation, q_bwe_exc, voice_factors);
    st.state_syn_shbexc
        .copy_from_slice(&shaped_shb_excitation[320..340]);

    let (ener_tmp, ener) = swb_tbe_dec_quarter_energies(&shaped_shb_excitation, q_bwe_exc);
    swb_tbe_dec_gain_frame(st, &mut parameters, ener, is_fractive, tilt_swb_fec);
    swb_tbe_dec_gain_shape_smoothing(
        st,
        &mut parameters,
        &ener_tmp,
        q_bwe_exc,
        coder_type,
        pitch_buf,
    );

    st.prev_q_bwe_syn = q_bwe_exc;
    let mut qx: i16 = 0;
    scale_shaped_shb(
        (320 - 20) / (16 - 1),
        &mut shaped_shb_excitation,
        &mut st.syn_overlap,
        &parameters.gain_shape,
        parameters.gain_frame,
        &WINDOW_SHB_FX,
        &SUBWIN_SHB_FX,
        &mut q_bwe_exc,
        &mut qx,
        n_mem3,
        st.prev_q_bwe_syn2,
    );

    let (curr_frame_pow, curr_frame_pow_exp) =
        swb_tbe_dec_frame_power(st, &mut parameters, &mut shaped_shb_excitation, q_bwe_exc);
    st.prev_swb_bwe_frame_pow = curr_frame_pow;
    st.prev_frame_pow_exp = curr_frame_pow_exp;
    swb_tbe_dec_prev_energies(
        st,
        &shaped_shb_excitation,
        q_bwe_exc,
        curr_frame_pow,
        curr_frame_pow_exp,
    );

    let sc = sub(q_bwe_exc, st.prev_q_bwe_syn2);
    if sc != 0 {
        for value in &mut st.gen_sh_bsynth_state_lsyn_filt_shb_local[..2 * 3] {
            *value = shl(*value, sc);
        }
        if sub(st.l_frame, 256) == 0 {
            for value in &mut st.gen_sh_bsynth_hilbert_mem[..5 + 2 * 4 + 2 * 4] {
                *value = l_shl(*value, sc);
            }
        }
        if st.output_fs == 48000 {
            scale_sig(&mut st.int_3_over_2_tbemem_dec, 15, sc);
        }
        if st.output_fs == 16000 {
            scale_sig(&mut st.mem_resamp_hb_32k, 2 * 3 + 1, sc);
        }
    }
    let l_frame = st.l_frame;
    gen_shb_synth(
        &shaped_shb_excitation,
        &mut error,
        &mut st.gen_sh_bsynth_hilbert_mem,
        &mut st.gen_sh_bsynth_state_lsyn_filt_shb_local,
        l_frame,
        &mut st.syn_dm_phase,
    );
    st.old_tbe_synth[..TRANSITION].copy_from_slice(&error[640 - TRANSITION..640]);

    swb_tbe_dec_output(
        st,
        parameters.gain_frame,
        &parameters.gain_shape,
        &mut error,
        synth,
        white_exc16k,
        q_white_exc,
    );

    st.lsp_prevfrm.copy_from_slice(&parameters.lsf_shb);
    if sub(st.codec_mode, 1) == 0 {
        st.gain_frame_prevfrm = parameters.gain_frame;
        st.tilt_swb_fec = tilt_swb_fec;
        if st.bfi == 0 {
            st.gain_attn = 32767;
        }
    } else if st.bfi == 0 {
        st.gain_frame_prevfrm = parameters.gain_frame;
        st.tilt_swb_fec = tilt_swb_fec;
        st.gain_attn = 32767;
    }

    st.prev_ener = ener_tmp[4 - 1];
    st.prev_gain_shape = parameters.gain_shape[16 - 1];
    *q_synth = q_bwe_exc;
    st.prev_q_bwe_syn2 = q_bwe_exc;
    st.prev_qx = q_bwe_exc;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_silent_mode1_frame_decodes_to_silence() {
        let mut st = Box::new(DecoderState::zeroed());
        st.codec_mode = 1;
        st.l_frame = 320;
        st.output_fs = 32000;
        st.extl = 8;
        st.extl_brate = 1600;
        st.total_brate = 13200;
        st.bws_cnt = 1;
        st.prev_frame_pow_exp = 0;
        st.ptr_mem_stp_swb = 9;
        let excitation = [0i32; 640];
        let mut white = [0i16; 320];
        let mut q_white = 0;
        let mut synth = [3i16; 960];
        let mut q_synth = 0;
        swb_tbe_dec(
            &mut st,
            0,
            &excitation,
            0,
            &[0; 5],
            &[0; 320],
            &mut white,
            &mut q_white,
            &mut synth,
            &mut q_synth,
            &[0; 5],
        );
        assert!(synth[..640].iter().all(|&sample| sample == 0));
        assert_eq!(st.prev_q_bwe_syn2, q_synth);
    }
}
