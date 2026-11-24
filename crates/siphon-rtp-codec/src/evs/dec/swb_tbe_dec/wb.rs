//! WB TBE decoder (TS 26.442 `lib_dec/swb_tbe_dec_fx.c`, `wb_tbe_dec_fx`; TS 26.445 §6.1.3).

use super::memory::{find_max_mem_wb, rescale_gen_wb_mem};
use super::params::dequantize_shb_params_9_1;
use crate::evs::basop::mult_32_16;
use crate::evs::com::lsf_tools::lsp2lpc;
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::com::modif_fs::{interpolate_3_over_1_allpass, interpolate_allpass_steep};
use crate::evs::com::swb_tbe_com::{gen_shaped_wb_excitation, gen_wb_synth, scale_shaped_wb};
use crate::evs::com::tools::{root_a, root_a_over_b, scale_sig};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{ALLPASS_POLES_3_OV_2, SHBCB_FRAMEGAIN16_FX, SUBWIN_WB_FX, WINDOW_WB_FX};
use crate::itu::basic_ops::{
    abs_s, add, div_s, l_abs, l_add, l_deposit_h, l_mult, l_shl, l_shr, l_sub, mult_r, negate,
    norm_l, norm_s, round_word, shl, sub,
};
use crate::itu::stl2009::{l_mac0, shl_r};

/// `L_SHB_TRANSITION_LENGTH`: the length of the HB synthesis tail kept for a core switch.
const TRANSITION: usize = 222;

/// The WB TBE's decoded parameters of one frame.
struct WbParameters {
    lsf_wb: [i16; 6],
    gain_shape: [i16; 16],
    gain_frame: i32,
    uv_flag: i16,
}

/// The RF partial-copy frame gain of the WB TBE (`rf_frame_type == 4 + 3`: the 4-bit index into
/// the 16 frame gains; otherwise one of four fixed gains, smoothed against the previous one).
fn wb_tbe_dec_partial_copy_gain(st: &mut DecoderState, gain_frame: &mut i32) {
    if sub(st.rf_frame_type, 4 + 3) == 0 {
        st.rf_indx_tbe_gain_fr &= 0xF;
        *gain_frame = SHBCB_FRAMEGAIN16_FX[st.rf_indx_tbe_gain_fr as usize];
        if sub(st.core, 0) == 0
            && sub(st.last_core, 0) == 0
            && st.prev_use_partial_copy == 0
            && sub(st.prev_coder_type, 1) == 0
            && l_sub(*gain_frame, st.gain_frame_prevfrm) != 0
            && sub(st.last_extl, 5) == 0
        {
            *gain_frame = l_add(
                mult_32_16(st.gain_frame_prevfrm, 26214),
                mult_32_16(*gain_frame, 6553),
            );
        }
    } else {
        let mut temp: i16 = 0;
        match st.rf_indx_tbe_gain_fr {
            0 => {
                *gain_frame = 131072;
                if l_sub(st.gain_frame_prevfrm, 327680) <= 0 {
                    temp = 26214;
                }
            }
            1 => {
                *gain_frame = 524288;
                if l_sub(st.gain_frame_prevfrm, 327680) > 0
                    && l_sub(st.gain_frame_prevfrm, 786432) <= 0
                {
                    temp = 26214;
                }
            }
            2 => {
                *gain_frame = 1048576;
                if l_sub(st.gain_frame_prevfrm, 786432) > 0
                    && l_sub(st.gain_frame_prevfrm, 1572864) <= 0
                {
                    temp = 26214;
                }
            }
            3 => {
                *gain_frame = 2097152;
                if l_sub(st.gain_frame_prevfrm, 1572864) > 0
                    && l_sub(st.gain_frame_prevfrm, 4194304) <= 0
                {
                    temp = 26214;
                }
            }
            // the reference prints "RF SWB-TBE gain bits not supported." and goes on
            _ => {}
        }
        if sub(st.last_extl, 5) == 0 {
            *gain_frame = l_add(
                mult_32_16(st.gain_frame_prevfrm, temp),
                mult_32_16(*gain_frame, sub(32767, temp)),
            );
        }
        if sub(st.core, 0) == 0
            && sub(st.last_core, 0) == 0
            && st.prev_use_partial_copy == 0
            && sub(st.last_coder_type, 2) == 0
            && sub(st.rf_frame_type, 4 + 2) == 0
            && sub(st.prev_tilt_code_dec, 1497) < 0
            && sub(st.prev_tilt_code_dec, 200) > 0
        {
            *gain_frame = mult_32_16(*gain_frame, 9830);
        }
    }
}

/// The first part of `wb_tbe_dec_fx`: the LSFs, gain shape and frame gain of this frame, decoded
/// from the bitstream, taken from the RF partial copy, or concealed after a lost frame.
fn wb_tbe_dec_parameters(st: &mut DecoderState) -> WbParameters {
    let mut parameters = WbParameters {
        lsf_wb: [0; 6],
        gain_shape: [11469; 16],
        gain_frame: 1,
        uv_flag: 0,
    };

    if st.bfi == 0 {
        if sub(st.use_partial_copy, 1) == 0 {
            if sub(st.last_extl, 5) != 0 {
                st.gain_frame_prevfrm = 0;
                st.lsp_prevfrm[0] = 3277;
                for i in 1..4 {
                    // the reference indexes `lsp_prevfrm_fx[i - i]`
                    st.lsp_prevfrm[i] = add(st.lsp_prevfrm[0], 3277);
                }
            }
            // only the four LSFs of the 0.35 kbit/s RF WB TBE are set; the reference leaves
            // `lsf_wb[4..6]` uninitialised and reads them only for a 6-LSF `extl_brate`, which a
            // partial copy never carries
            parameters.lsf_wb[..4].copy_from_slice(&st.lsp_prevfrm[..4]);
            parameters.gain_shape[..16 / 2].fill(11585);
            wb_tbe_dec_partial_copy_gain(st, &mut parameters.gain_frame);
        } else {
            let (extl, extl_brate) = (st.extl, st.extl_brate);
            // the energy / residual / mix outputs of the SWB TBE are not produced for the WB TBE
            let mut unused_energy = 0;
            let mut unused_gains = [0i16; 5];
            let mut unused_mix = 0;
            dequantize_shb_params_9_1(
                st,
                extl,
                extl_brate,
                &mut parameters.lsf_wb,
                &mut parameters.gain_shape,
                &mut parameters.gain_frame,
                &mut parameters.uv_flag,
                &mut unused_energy,
                &mut unused_gains,
                &mut unused_mix,
            );
        }
    } else {
        if l_sub(st.extl_brate, 350) == 0 {
            parameters.lsf_wb[..4].copy_from_slice(&st.lsp_prevfrm[..4]);
        } else {
            parameters.lsf_wb.copy_from_slice(&st.lsp_prevfrm[..6]);
        }
        parameters.gain_shape[..16 / 2].fill(11585);
        st.gain_attn = mult_r(st.gain_attn, 27853);
        if sub(st.codec_mode, 1) == 0 {
            parameters.gain_frame = mult_32_16(st.gain_frame_prevfrm, st.gain_attn);
        } else {
            parameters.gain_frame = st.gain_frame_prevfrm;
        }
    }
    parameters
}

/// The LPC `lpc_wb` (Q12, `lpc_wb[0] = 1`) of the WB TBE from the LSPs `lsf_wb`, with the
/// previous-frame fallback kept in `prev_lpc_wb`.
fn wb_tbe_dec_lpc(st: &mut DecoderState, lsf_wb: &[i16], lpc_wb: &mut [i16; 7]) {
    let order: i16 = if st.extl_brate == 350 { 4 } else { 6 };
    lsp2lpc(&mut lpc_wb[1..], lsf_wb, &st.prev_lpc_wb, order);
    if st.extl_brate == 350 {
        lpc_wb[4 + 1..].fill(0);
    }
    st.prev_lpc_wb.copy_from_slice(&lpc_wb[1..6 + 1]);
    for value in &mut lpc_wb[1..=order as usize] {
        *value = negate(*value);
    }
    lpc_wb[0] = 4096;
}

/// The WB TBE excitation of one frame: its Q, the voice-factor smoothing, the extended excitation
/// in 16 bits, the shaped high-band excitation `shaped_wb_excitation` (85 samples: the 5 of the
/// previous frame and 80 new) rescaled to continue the previous frame's energy, and its gains
/// applied by [`scale_shaped_wb`]. Returns the excitation Q and the extended-excitation Q.
fn wb_tbe_dec_excitation(
    st: &mut DecoderState,
    parameters: &mut WbParameters,
    lpc_wb: &[i16; 7],
    coder_type: i16,
    bwe_exc_extended: &[i32],
    q_exc: i16,
    voice_factors: &[i16],
    shaped_wb_excitation: &mut [i16; (320 + 20) / 4],
) -> (i16, i16) {
    let mut bwe_exc_extended_16 = [0i16; 640 + 40];
    let mut exc4k_whtnd = [0i16; 320 / 4];
    let mut vf_modified = [0i16; 5];

    vf_modified.copy_from_slice(&voice_factors[..5]);
    if coder_type == 2 {
        for i in 1..4 {
            vf_modified[i] = add(
                mult_r(26214, voice_factors[i]),
                mult_r(6554, voice_factors[i - 1]),
            );
        }
        if st.l_frame != 256 {
            vf_modified[4] = add(
                mult_r(26214, voice_factors[4]),
                mult_r(6554, voice_factors[3]),
            );
        }
    }

    let mut l_max: i32 = 0;
    for &value in &bwe_exc_extended[..640] {
        l_max = l_max.max(l_abs(value));
    }
    let mut q_bwe_exc = if l_max == 0 { 31 } else { norm_l(l_max) };
    q_bwe_exc = sub(q_bwe_exc, 1);
    q_bwe_exc = add(q_bwe_exc, add(q_exc, q_exc));

    let mut n_mem = 0;
    find_max_mem_wb(st, &mut n_mem);
    if sub(q_bwe_exc, st.prev_q_bwe_exc) > n_mem {
        q_bwe_exc = add(st.prev_q_bwe_exc, n_mem);
    }
    if parameters.uv_flag != 0 && sub(q_bwe_exc, 20) > 0 {
        q_bwe_exc = 20;
    }

    let mut prev_pow: i32 = 0;
    for &value in &st.state_syn_shbexc[..20 / 4] {
        prev_pow = l_mac0(prev_pow, value, value);
    }

    rescale_gen_wb_mem(st, sub(q_bwe_exc, st.prev_q_bwe_exc));

    bwe_exc_extended_16[..12].copy_from_slice(&st.old_bwe_exc_extended);
    let sc = sub(q_bwe_exc, add(q_exc, q_exc));
    for cnt in 0..640 {
        bwe_exc_extended_16[cnt + 12] = round_word(l_shl(bwe_exc_extended[cnt], sc));
    }
    st.old_bwe_exc_extended
        .copy_from_slice(&bwe_exc_extended_16[640..652]);

    shaped_wb_excitation[..20 / 4].copy_from_slice(&st.state_syn_shbexc[..20 / 4]);

    let q_bwe_exc_ext = sub(q_bwe_exc, 16);
    gen_shaped_wb_excitation(
        &mut shaped_wb_excitation[20 / 4..],
        lpc_wb,
        &mut exc4k_whtnd,
        &mut st.mem_csfilt,
        &mut st.mem_gen_sh_bexc_filt_down_shb,
        &mut st.mem_gen_sh_bexc_filt_down_wb2,
        &mut st.mem_gen_sh_bexc_filt_down_wb3,
        &mut st.state_lpc_syn,
        coder_type,
        &bwe_exc_extended_16,
        q_bwe_exc_ext,
        &mut st.bwe_seed,
        &vf_modified,
        parameters.uv_flag,
        st.igf,
    );

    let mut curr_pow: i32 = 0;
    for i in 0..20 / 4 {
        curr_pow = l_mac0(
            curr_pow,
            shaped_wb_excitation[i + 20 / 4],
            shaped_wb_excitation[i + 20 / 4],
        );
    }
    if sub(voice_factors[0], 24576) > 0 {
        curr_pow = l_shr(curr_pow, 2);
    }

    let mut exp: i16 = 0;
    let mut l_scale = root_a_over_b(
        curr_pow,
        shl_r(q_bwe_exc_ext, 1),
        prev_pow,
        shl_r(sub(st.prev_q_bwe_exc, 16), 1),
        &mut exp,
    );
    for sample in &mut shaped_wb_excitation[..20 / 4 - 1] {
        let l_tmp = mult_32_16(l_scale, *sample);
        *sample = round_word(l_shl(l_tmp, exp));
    }
    l_scale = root_a(l_scale, 31 - exp, &mut exp);
    let l_tmp = mult_32_16(l_scale, shaped_wb_excitation[20 / 4 - 1]);
    shaped_wb_excitation[20 / 4 - 1] = round_word(l_shl(l_tmp, exp));

    st.state_syn_shbexc[..20 / 4].copy_from_slice(&shaped_wb_excitation[320 / 4..320 / 4 + 20 / 4]);

    // `dynQ == 0`: the output Q and the previous one are the reference's `dummy`s
    let mut dummy_qx: i16 = 0;
    let dummy_prev_qx: i16 = 0;
    let dummy2 = [0i32; 5 + 2 * 4 + 2 * 4];
    scale_shaped_wb(
        (320 - 20) / (16 - 1) / 2,
        shaped_wb_excitation,
        &mut st.syn_overlap,
        &parameters.gain_shape,
        parameters.gain_frame,
        &WINDOW_WB_FX,
        &SUBWIN_WB_FX,
        q_bwe_exc_ext,
        st.l_frame,
        0,
        &mut dummy_qx,
        dummy_prev_qx,
        &dummy2,
    );
    (q_bwe_exc, q_bwe_exc_ext)
}

/// The frame-energy tracking of `wb_tbe_dec_fx`: the energy of the shaped excitation, and after a
/// lost frame the smoothing of the gains back towards the energy of the frame before it.
fn wb_tbe_dec_frame_energy(
    st: &mut DecoderState,
    parameters: &mut WbParameters,
    shaped_wb_excitation: &mut [i16; (320 + 20) / 4],
) {
    let mut shaped_wb_excitation_frac = [0i16; 320 / 4];

    let mut max: i16 = 0;
    for &value in &shaped_wb_excitation[..320 / 4] {
        max = max.max(value);
    }
    let mut curr_frame_pow: i32;
    let mut n: i16;
    if max == 0 {
        curr_frame_pow = 1;
        n = 0;
    } else {
        n = norm_s(max);
        for i in 0..320 / 4 {
            shaped_wb_excitation_frac[i] = shl(shaped_wb_excitation[i], n);
        }
        n = sub(14, n);
        curr_frame_pow = 1;
        for &value in &shaped_wb_excitation_frac {
            let l_tmp = l_mult(value, value);
            curr_frame_pow = l_add(curr_frame_pow, l_shr(l_tmp, 7));
        }
    }

    let mut curr_frame_pow_exp = add(n, n);
    if sub(st.prev_frame_pow_exp, curr_frame_pow_exp) > 0 {
        curr_frame_pow = l_shr(
            curr_frame_pow,
            sub(st.prev_frame_pow_exp, curr_frame_pow_exp),
        );
        curr_frame_pow_exp = st.prev_frame_pow_exp;
    } else {
        st.prev_wb_bwe_frame_pow = l_shr(
            st.prev_wb_bwe_frame_pow,
            sub(curr_frame_pow_exp, st.prev_frame_pow_exp),
        );
    }

    if st.bfi == 0 && st.prev_bfi != 0 {
        let mut scale: i16;
        let temp: i16;
        if l_sub(l_shr(curr_frame_pow, 1), st.prev_wb_bwe_frame_pow) > 0 {
            let mut exp: i16 = 0;
            let mut l_tmp =
                root_a_over_b(st.prev_wb_bwe_frame_pow, 22, curr_frame_pow, 22, &mut exp);
            scale = round_word(l_shl(l_tmp, exp));
            l_tmp = root_a(l_tmp, 31 - exp, &mut exp);
            l_tmp = root_a(l_tmp, 31 - exp, &mut exp);
            l_tmp = root_a(l_tmp, 31 - exp, &mut exp);
            temp = round_word(l_shl(l_tmp, exp));
        } else {
            scale = 32767;
            temp = 32767;
        }
        for j in 0..8 {
            parameters.gain_shape[2 * j] = mult_r(parameters.gain_shape[2 * j], scale);
            parameters.gain_shape[2 * j + 1] = mult_r(parameters.gain_shape[2 * j + 1], scale);
            for i in 0..320 / (4 * 8) {
                let index = i + j * 320 / (4 * 8);
                shaped_wb_excitation[index] = mult_r(shaped_wb_excitation[index], scale);
            }
            if temp > 0 {
                scale = if sub(scale, temp) < 0 {
                    div_s(scale, temp)
                } else {
                    32767
                };
            } else {
                scale = 0;
            }
        }
    }
    st.prev_wb_bwe_frame_pow = curr_frame_pow;
    st.prev_frame_pow_exp = curr_frame_pow_exp;
}

/// The synthesis half of `wb_tbe_dec_fx`: scales the shaped excitation to the synthesis Q `Qx`,
/// upsamples it to the 16 kHz high band (and on to the output rate), keeps the tail for a core
/// switch and the band energy for the next frame. Returns `Qx`.
fn wb_tbe_dec_synthesis(
    st: &mut DecoderState,
    shaped_wb_excitation: &mut [i16; (320 + 20) / 4],
    synth: &mut [i16],
) -> i16 {
    let mut error = [0i16; 320];
    let mut synth_frac = [0i16; 320];
    let mut upsampled_synth = [0i16; 960];

    let mut max: i16 = 0;
    for &value in shaped_wb_excitation.iter() {
        if abs_s(value) > max {
            max = abs_s(value);
        }
    }
    let mut qx = norm_s(max);
    if max == 0 {
        qx = 15;
    }
    qx = sub(qx, 1);

    max = 0;
    for &value in &st.state_lsyn_filt_shb[..2 * 3] {
        if abs_s(value) > max {
            max = abs_s(value);
        }
    }
    for &value in &st.state_lsyn_filt_dwn_shb[..2 * 3] {
        if abs_s(value) > max {
            max = abs_s(value);
        }
    }
    if l_sub(st.output_fs, 32000) == 0 {
        for &value in &st.state_32and48k_wb_upsample[..2 * 3] {
            max = max.max(abs_s(value));
        }
    }
    if l_sub(st.output_fs, 48000) == 0 {
        for &value in &st.mem_resamp_hb[..13] {
            max = max.max(abs_s(value));
        }
    }
    let mut n_mem: i16 = 15;
    if max != 0 {
        n_mem = norm_s(max);
    }
    n_mem = n_mem.max(0);
    if sub(qx, st.prev_qx) > n_mem {
        qx = add(st.prev_qx, n_mem);
    }

    for value in shaped_wb_excitation.iter_mut() {
        *value = shl(*value, qx);
    }
    for value in &mut st.state_lsyn_filt_shb[..2 * 3] {
        *value = shl(*value, sub(qx, st.prev_qx));
    }
    for value in &mut st.state_lsyn_filt_dwn_shb[..2 * 3] {
        *value = shl(*value, sub(qx, st.prev_qx));
    }

    gen_wb_synth(
        shaped_wb_excitation,
        &mut error,
        &mut st.state_lsyn_filt_shb,
        &mut st.state_lsyn_filt_dwn_shb,
    );
    st.old_tbe_synth[..TRANSITION].copy_from_slice(&error[320 - TRANSITION..320]);

    for i in 0..320 {
        synth[i] = mult_r(error[i], 21299);
    }

    max = 0;
    for &value in &synth[..320] {
        max = max.max(abs_s(value));
    }
    if max == 0 {
        st.last_wb_bwe_ener = 0;
    } else {
        let mut n = norm_s(max);
        for cnt in 0..320 {
            synth_frac[cnt] = shl(synth[cnt], n);
        }
        n = sub(sub(14, n), qx);
        let mut l_acc: i32 = 0;
        for &value in &synth_frac {
            let l_tmp = l_mult(value, value);
            l_acc = l_add(l_acc, l_shr(l_tmp, 7));
        }
        let mut l_tmp = mult_32_16(l_acc, 102);
        let mut exp = norm_l(l_tmp);
        let mut tmp = round_word(l_shl(l_tmp, exp));
        exp = sub(add(exp, 22), 30);
        tmp = div_s(16384, tmp);
        l_tmp = isqrt_lc(l_deposit_h(tmp), &mut exp);
        st.last_wb_bwe_ener = round_word(l_shl(l_tmp, add(exp, n - 12)));
    }

    if l_sub(st.output_fs, 32000) == 0 {
        scale_sig(
            &mut st.state_32and48k_wb_upsample,
            2 * 3,
            sub(qx, st.prev_qx),
        );
        interpolate_allpass_steep(
            synth,
            &mut st.state_32and48k_wb_upsample,
            320,
            &mut upsampled_synth,
        );
        synth[..640].copy_from_slice(&upsampled_synth[..640]);
    } else if l_sub(st.output_fs, 48000) == 0 {
        scale_sig(&mut st.mem_resamp_hb, 13, sub(qx, st.prev_qx));
        interpolate_3_over_1_allpass(
            synth,
            320,
            &mut upsampled_synth,
            &mut st.mem_resamp_hb,
            &ALLPASS_POLES_3_OV_2,
        );
        synth[..960].copy_from_slice(&upsampled_synth[..960]);
    }
    qx
}

/// `wb_tbe_dec_fx`: decodes the WB time-domain bandwidth extension of one frame into `synth`
/// (320 samples at 16 kHz, or 640 / 960 at the 32 / 48 kHz output rate; Q`q_synth`), from the
/// extended excitation `bwe_exc_extended` (Q`q_exc` squared) and the voice factors.
pub fn wb_tbe_dec(
    st: &mut DecoderState,
    coder_type: i16,
    bwe_exc_extended: &[i32],
    q_exc: i16,
    voice_factors: &[i16],
    synth: &mut [i16],
    q_synth: &mut i16,
) {
    let mut shaped_wb_excitation = [0i16; (320 + 20) / 4];
    let gain_frame;
    let lsf_wb;
    let qx;
    let q_bwe_exc;

    if st.bws_cnt == 0 {
        let mut parameters = wb_tbe_dec_parameters(st);
        let mut lpc_wb = [0i16; 6 + 1];
        wb_tbe_dec_lpc(st, &parameters.lsf_wb, &mut lpc_wb);

        let (q_bwe_exc_value, _q_bwe_exc_ext) = wb_tbe_dec_excitation(
            st,
            &mut parameters,
            &lpc_wb,
            coder_type,
            bwe_exc_extended,
            q_exc,
            voice_factors,
            &mut shaped_wb_excitation,
        );
        wb_tbe_dec_frame_energy(st, &mut parameters, &mut shaped_wb_excitation);
        qx = wb_tbe_dec_synthesis(st, &mut shaped_wb_excitation, synth);
        q_bwe_exc = q_bwe_exc_value;
        gain_frame = parameters.gain_frame;
        lsf_wb = parameters.lsf_wb;
    } else {
        let mut f: i16 = 5461;
        let inc: i16 = 5461;
        let mut lsf = [0i16; 6];
        for value in &mut lsf {
            *value = f;
            f = add(f, inc);
        }
        lsf_wb = lsf;
        gain_frame = 0;
        qx = 0;
        q_bwe_exc = 31;
        st.prev_wb_bwe_frame_pow = 4194;
        st.prev_frame_pow_exp = 0;
    }

    if l_sub(st.extl_brate, 350) == 0 {
        st.lsp_prevfrm[..4].copy_from_slice(&lsf_wb[..4]);
    } else {
        st.lsp_prevfrm[..6].copy_from_slice(&lsf_wb);
    }
    st.gain_frame_prevfrm = gain_frame;
    if st.bfi == 0 {
        st.gain_attn = 32767;
    }

    *q_synth = qx;
    st.prev_q_bwe_exc = q_bwe_exc;
    st.prev_qx = qx;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blind_spot_frame_resets_the_wb_tbe_state_and_reports_q0() {
        let mut st = Box::new(DecoderState::zeroed());
        st.bws_cnt = 1;
        st.extl_brate = 350;
        let excitation = [0i32; 640];
        let mut synth = [7i16; 960];
        let mut q_synth = 5;
        wb_tbe_dec(
            &mut st,
            0,
            &excitation,
            0,
            &[0; 5],
            &mut synth,
            &mut q_synth,
        );
        assert_eq!(q_synth, 0);
        assert_eq!(st.prev_q_bwe_exc, 31);
        assert_eq!(st.prev_wb_bwe_frame_pow, 4194);
        assert_eq!(&st.lsp_prevfrm[..4], &[5461, 10922, 16383, 21844]);
        assert_eq!(st.gain_attn, 32767);
        assert_eq!(synth, [7; 960]);
    }

    #[test]
    fn the_lost_frame_gain_follows_the_attenuation() {
        let mut st = Box::new(DecoderState::zeroed());
        st.bfi = 1;
        st.codec_mode = 1;
        st.extl_brate = 350;
        st.gain_attn = 32767;
        st.gain_frame_prevfrm = 1 << 20;
        let parameters = wb_tbe_dec_parameters(&mut st);
        assert_eq!(st.gain_attn, mult_r(32767, 27853));
        assert_eq!(parameters.gain_frame, mult_32_16(1 << 20, st.gain_attn));
        assert_eq!(parameters.gain_shape[0], 11585);
        assert_eq!(parameters.gain_shape[8], 11469);
    }

    #[test]
    fn the_wb_lpc_is_negated_with_a_unit_leading_coefficient() {
        let mut st = Box::new(DecoderState::zeroed());
        st.extl_brate = 350;
        let mut lpc_wb = [9i16; 7];
        wb_tbe_dec_lpc(&mut st, &[0, 0, 0, 0, 0], &mut lpc_wb);
        assert_eq!(lpc_wb[0], 4096);
        assert_eq!(&lpc_wb[5..], &[0, 0]);
    }
}
