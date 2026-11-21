//! Signal classification for frame-erasure concealment when the class is not in the bitstream,
//! and the decoding of the FEC side information when it is (TS 26.442
//! `lib_dec/FEC_clas_estim_fx.c`; TS 26.445 §6.1.1.3 and §6.3.1.2.1).

use crate::evs::basop::{l_extract_lc, mpy_32_16_1, mult_32_16};
use crate::evs::cnst::{
    ACELP_11K60, ACELP_12K65, ACELP_14K25, ACELP_15K85, ACELP_18K25, ACELP_19K85, ACELP_23K05,
    ACELP_23K85, ACELP_6K60, ACELP_8K85, AUDIO, AUDIO_CLAS, GENERIC, INACTIVE, INACTIVE_CLAS,
    LT_UV_THR_FX, L_FRAME, L_FRAME16K, L_SUBFR, L_SYN_MEM_CLAS_ESTIM, MAX_LT, MODE1, MODE2, ONSET,
    SID_1K75, SIN_ONSET, TRANSITION, UNVOICED, UNVOICED_CLAS, UNVOICED_TRANSITION, VOICED,
    VOICED_CLAS, VOICED_TRANSITION,
};
use crate::evs::com::bitstream::{bit_alloc_idx_16khz, get_indice, get_next_indice};
use crate::evs::com::frame_ener::frame_energy;
use crate::evs::com::lerp::lerp_within;
use crate::evs::com::math_op::{dot_product12, i_mult2, isqrt_lc, pow2};
use crate::evs::com::preemph::preemph_copy_in_place;
use crate::evs::com::tcx_utils::get_inv_frame_len;
use crate::evs::com::tools::{copy_scale_sig, scale_sig, sqrt_ratio32};
use crate::evs::dec::pit_dec::pit16k_q_dec;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::ACB_BITS_16KHZ_TBL;
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_l, l_mac, l_mult, l_shl,
    l_shr, l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_msu0, l_mult0, mac_r};

/// `UNS6`: 1/6 in Q15, halved (`10923/2`, a macro, so `2*UNS6` is written out at its use).
const UNS6: i16 = 10923 / 2;

/// `K_COR_FX` (Q14, 0.8547) and `C_COR_FX` (Q14+16, 0.2479): the voicing's affine map to [0, 1].
const K_COR_FX: i16 = 14004;
const C_COR_FX: i32 = 266_180_599;
/// `K_TILT_FX` (Q14, 0.8333) and `C_TILT_FX` (Q14+16, 0.2917).
const K_TILT_FX: i16 = 13653;
const C_TILT_FX: i32 = 313_210_491;
/// `K_ZC_FX` (Q15, -0.04) and `C_ZC_FX` (11Q20, 2.52).
const K_ZC_FX: i16 = -1310;
const C_ZC_FX: i32 = 2_642_416;
/// `K_ENR_FX` (Q15, 0.04) and `C_ENR_FX` (Q8+16, 0.56).
const K_ENR_FX: i16 = 1311;
const C_ENR_FX: i32 = 9_395_241;
/// `K_PC_FX` (Q15, -0.0357) and `C_PC_FX` (Q0+16, 1.6071).
const K_PC_FX: i16 = -1169;
const C_PC_FX: i32 = 105_323;

/// `INV_MAX_LT_FX`, `(Word16)((1.0f/MAX_LT)*32768)` = 819 (lib_com/cnst_fx.h).
const INV_MAX_LT_FX: i16 = 819;

/// `CLASSIFIER_TCX` of the reference's `SIGNAL_CLASSIFIER_MODE` (lib_com/cnst_fx.h).
const CLASSIFIER_TCX: i16 = 1;

/// The length of the local synthesis buffer, `L_SYN_MEM_CLAS_ESTIM + L_FRAME16k`.
const OLD_SYNTH_LEN: usize = (L_SYN_MEM_CLAS_ESTIM + L_FRAME16K) as usize;

/// `buffer[at..at + len]`, or `None` when the window leaves the buffer. Only a pitch outside the
/// pitch decoder's range moves a correlation window off the local synthesis buffer (where the
/// reference reads off its stack).
fn window(buffer: &[i16], at: i32, len: i16) -> Option<&[i16]> {
    let at = usize::try_from(at).ok()?;
    let end = at.checked_add(usize::try_from(len).ok()?)?;
    buffer.get(at..end)
}

/// `Corre`: the normalised correlation `<x, y> / sqrt(<x, x> <y, y>)` of two `l`-sample vectors,
/// returned in Q15.
#[must_use]
pub fn corre(x: &[i16], y: &[i16], l: i16) -> i16 {
    let mut cor_exp = 0i16;
    let mut den_exp = 0i16;
    let mut den2_exp = 0i16;

    // keep Q15 normalized result
    let cor = extract_h(dot_product12(x, y, l, &mut cor_exp));
    let den = add(extract_h(dot_product12(y, y, l, &mut den_exp)), 1);
    let den2 = extract_h(dot_product12(x, x, l, &mut den2_exp));

    // den *= den2
    let mut tmp = l_mult(den, den2);
    let mut tmp_exp = norm_l(tmp);
    tmp = l_shl(tmp, tmp_exp);
    tmp_exp = sub(add(den_exp, den2_exp), tmp_exp);

    // den = 1 / sqrt(den)
    tmp = isqrt_lc(tmp, &mut tmp_exp);

    // cor *= den
    shl(mult_r(cor, extract_h(tmp)), add(cor_exp, tmp_exp))
}

/// [`corre`] of the `t0` samples of `synth` at `pos` against those `t0` earlier, both relative to
/// the start of the current frame in the local buffer `old_synth`; 0 when a window leaves it
/// (see [`window`]).
fn corre_at(old_synth: &[i16], pos: i16, t0: i16) -> i16 {
    let base = i32::from(L_SYN_MEM_CLAS_ESTIM);
    match (
        window(old_synth, base + i32::from(pos), t0),
        window(old_synth, base + i32::from(pos) - i32::from(t0), t0),
    ) {
        (Some(x), Some(y)) => corre(x, y, t0),
        _ => 0,
    }
}

/// `FEC_clas_estim_fx`: estimates the signal class (`st.clas_dec`) of a frame whose class is not
/// transmitted, from the zero-crossing rate, pitch-synchronous normalised correlation, pitch
/// coherence, spectral tilt and end-of-frame energy of the synthesis, and updates the
/// classifier's synthesis memory.
///
/// `syn` holds the frame's synthesis (Q`q_syn`) from `syn[syn_at]`; the TCX classifier mode of
/// MODE2 also reads `syn[syn_at - 1]`, which `syn_at` must then be at least 1 for.
///
/// Every caller in the reference passes the decoder's own fields for `clas`, `lp_speech`,
/// `decision_hyst`, `UV_cnt`, `LT_UV_cnt`, `Last_ener`, `lt_diff_etot`, `mem_syn_clas_estim` and
/// `Q_mem_syn` (or NULL where the function does not touch them), so they are read and written
/// here as `st.clas_dec`, `st.lp_ener_fer`, `st.decision_hyst`, `st.uv_cnt`, `st.lt_uv_cnt`,
/// `st.last_ener`, `st.lt_diff_etot`, `st.mem_syn_clas_estim` and `st.classifier_q_mem_syn`.
/// `locattack`, `amr_io_class` (AMR-WB IO only) and `class_para` (MODE1 only) are the callers'
/// locals; `None` stands for the reference's NULL, which no caller passes where it is written.
pub fn fec_clas_estim(
    st: &mut DecoderState,
    opt_amr_wb: i16,
    l_frame: i16,
    coder_type: i16,
    pitch: &[i16],
    syn: &[i16],
    syn_at: usize,
    locattack: Option<&mut i16>,
    amr_io_class: Option<&mut i16>,
    bitrate: i32,
    q_syn: i16,
    class_para: Option<&mut i16>,
    ltp_gain: i16,
    mode: i16,
    bfi: i16,
    last_core_brate: i32,
) {
    let mut old_synth = [0i16; OLD_SYNTH_LEN];
    let synth_at = L_SYN_MEM_CLAS_ESTIM as usize;
    let l_frame_len = l_frame.clamp(0, L_FRAME16K) as usize;

    let codec_mode = st.codec_mode;
    let tcxonly = st.tcxonly;
    let narrow_band = st.narrow_band;
    let preemph_fac = st.preemph_fac;

    let mut tmp_scale_syn: i16 = 0;
    let mut frame_ener: i16 = 1;
    let mut ener: i16 = 0;

    // Copy synthesized into local buffer
    // After Rate Switching st->last_core is reset to 0. Check for last_core_brate is needed
    let last_was_amr_wb = [
        SID_1K75,
        ACELP_6K60,
        ACELP_8K85,
        ACELP_12K65,
        ACELP_14K25,
        ACELP_15K85,
        ACELP_18K25,
        ACELP_19K85,
        ACELP_23K05,
        ACELP_23K85,
    ]
    .iter()
    .any(|&rate| l_sub(last_core_brate, i32::from(rate)) == 0);
    if last_was_amr_wb
        && opt_amr_wb == 0
        && sub(codec_mode, MODE2) == 0
        && sub(l_frame, L_FRAME) > 0
    {
        let old_len_clas_buff = extract_l(l_shr(
            mpy_32_16_1(
                l_mult0(st.last_l_frame, get_inv_frame_len(st.l_frame)), // Q21
                L_SYN_MEM_CLAS_ESTIM,
            ), // Q6
            6,
        ));
        let new_len_clas_buff = L_SYN_MEM_CLAS_ESTIM;
        // `last_L_frame` is a core frame length, so the old length never exceeds the buffer.
        let old_at = sub(L_SYN_MEM_CLAS_ESTIM, old_len_clas_buff).max(0) as usize;
        lerp_within(
            &mut st.mem_syn_clas_estim,
            old_at,
            0,
            new_len_clas_buff,
            old_len_clas_buff,
        );
    }

    fec_clas_estim_rescale_memory(st, q_syn, mode, &mut tmp_scale_syn);

    let tmp_scale: i16 = -1;
    copy_scale_sig(
        &st.mem_syn_clas_estim,
        &mut old_synth,
        L_SYN_MEM_CLAS_ESTIM,
        tmp_scale,
    );
    copy_scale_sig(
        &syn[syn_at..],
        &mut old_synth[synth_at..],
        l_frame,
        add(tmp_scale_syn, tmp_scale),
    );
    // Tell MODE2 decoder the scaling of the buffer
    st.classifier_q_mem_syn = add(add(q_syn, tmp_scale_syn), tmp_scale);

    if sub(codec_mode, MODE2) == 0 && sub(mode, CLASSIFIER_TCX) == 0 {
        // TCX outputs non-pe-speech
        // `syn[-1]`: the caller's synthesis keeps its memory sample before the frame.
        let previous = syn_at
            .checked_sub(1)
            .and_then(|at| syn.get(at))
            .copied()
            .unwrap_or(0);
        let mut tmp16 = shl(previous, tmp_scale); // dont forget to scale the mem
        preemph_copy_in_place(&mut old_synth[synth_at..], preemph_fac, l_frame, &mut tmp16);
    }

    // Do the classification only
    // - MODE1: when the class is not transmitted in the bitstream
    // - MODE2: on good frames (classifier is also called for bfi=1)
    if !((sub(codec_mode, MODE1) == 0
        && (l_sub(bitrate, i32::from(ACELP_11K60)) < 0
            || sub(coder_type, UNVOICED) <= 0
            || opt_amr_wb != 0))
        || (sub(codec_mode, MODE2) == 0 && sub(bfi, 1) != 0 && tcxonly == 0))
    {
        fec_clas_estim_update_memory(st, &old_synth, l_frame_len, q_syn, tmp_scale_syn, tmp_scale);
        return;
    }

    // Overwrite classification decision using coder_type information
    if sub(coder_type, VOICED) == 0 {
        st.clas_dec = VOICED_CLAS;
    } else if sub(coder_type, UNVOICED) == 0 {
        st.clas_dec = UNVOICED_CLAS;
    } else if sub(coder_type, INACTIVE) == 0 && opt_amr_wb == 0 {
        st.clas_dec = INACTIVE_CLAS;
    } else {
        let fmerit1 = fec_clas_estim_merit(
            st,
            &old_synth,
            l_frame,
            pitch,
            ltp_gain,
            mode,
            narrow_band,
            &mut ener,
            &mut frame_ener,
            class_para,
        );

        // frame classification
        if (sub(coder_type, VOICED) != 0 && l_sub(bitrate, i32::from(ACELP_11K60)) < 0)
            || opt_amr_wb != 0
        {
            let mut result = UNVOICED_CLAS;
            match st.clas_dec {
                VOICED_CLAS | ONSET | SIN_ONSET | VOICED_TRANSITION => {
                    if sub(fmerit1, 12780 /* 0.39f Q15 */) < 0 {
                        result = UNVOICED_CLAS;
                    } else if sub(fmerit1, 20644 /* 0.63f Q15 */) < 0
                        && (add(ener, 3840) < 0 || sub(codec_mode, MODE2) == 0)
                    {
                        result = VOICED_TRANSITION;
                    } else {
                        result = VOICED_CLAS;
                    }
                }
                UNVOICED_CLAS | UNVOICED_TRANSITION | INACTIVE_CLAS => {
                    if sub(fmerit1, 18350 /* 0.56f Q15 */) > 0 {
                        result = ONSET;
                    } else if sub(fmerit1, 14746 /* 0.45f Q15 */) > 0 {
                        result = UNVOICED_TRANSITION;
                    } else {
                        result = UNVOICED_CLAS;
                    }
                }
                _ => {}
            }
            st.clas_dec = result;
        }
    }

    if sub(codec_mode, MODE1) == 0 {
        // Overwrite classification decision in case of music
        if sub(coder_type, AUDIO) == 0 {
            st.decision_hyst = add(st.decision_hyst, 4);
        } else {
            st.decision_hyst = sub(st.decision_hyst, 1);
        }
        if sub(coder_type, INACTIVE) == 0 {
            st.decision_hyst = sub(st.decision_hyst, 10);
        }
        if sub(st.decision_hyst, 200) > 0 {
            st.decision_hyst = 200;
        } else if st.decision_hyst < 0 {
            st.decision_hyst = 0;
        }
        if sub(st.decision_hyst, 16) > 0
            && sub(st.clas_dec, VOICED_CLAS) < 0
            && sub(coder_type, AUDIO) == 0
        {
            st.clas_dec = VOICED_CLAS;
        }
    }

    // Measure energy on active voice frames (to improve FEC performance)
    if sub(st.clas_dec, VOICED_CLAS) == 0 {
        if (sub(codec_mode, MODE2) == 0 && sub(coder_type, VOICED) == 0)
            || (sub(codec_mode, MODE1) == 0
                && (opt_amr_wb != 0
                    || (sub(coder_type, GENERIC) != 0 && sub(coder_type, TRANSITION) != 0)))
        {
            // pitch-synchronous energy at the frame end
            let lp_speech = st.lp_ener_fer;
            let q_mem_syn = st.classifier_q_mem_syn;
            frame_energy(
                l_frame,
                pitch,
                &old_synth[synth_at..],
                lp_speech,
                &mut frame_ener,
                q_mem_syn,
                &mut st.stl,
            );
        }
        // update of long-term active speech energy
        let ltmp = l_mult0(655, frame_ener); // 0.01
        st.lp_ener_fer = mac_r(ltmp, 32440, st.lp_ener_fer);
    }

    if sub(codec_mode, MODE1) == 0 {
        // Overwrite classification decision to UNVOICED_CLAS in case of INACTIVE frame
        if sub(coder_type, INACTIVE) == 0 && sub(st.clas_dec, INACTIVE_CLAS) != 0 {
            st.clas_dec = UNVOICED_CLAS;
        }

        // Classification refinement to improve noise coding (only in AMR-WB IO mode)
        if opt_amr_wb != 0 {
            if let (Some(locattack), Some(amr_io_class)) = (locattack, amr_io_class) {
                fec_clas_estim_amr_wb_io(st, coder_type, ener, locattack, amr_io_class);
            }
        }
    }

    fec_clas_estim_update_memory(st, &old_synth, l_frame_len, q_syn, tmp_scale_syn, tmp_scale);
}

/// The scaling half of `FEC_clas_estim_fx`'s prologue: in MODE2 the synthesis memory and the
/// incoming synthesis are aligned to one scaling (switching MODE2 -> MODE1).
fn fec_clas_estim_rescale_memory(
    st: &mut DecoderState,
    q_syn: i16,
    mode: i16,
    tmp_scale_syn: &mut i16,
) {
    // Rescale synthesis mem buffer or synthesis buffer, if necessary -
    // allign them to the same scaling in case of switching MODE2->MODE1
    if sub(st.codec_mode, MODE2) != 0 {
        return;
    }
    // find maximum of mem syn
    let mut memmax: i16 = 1;
    for &value in &st.mem_syn_clas_estim {
        memmax = memmax.max(value);
    }

    let tmp_scale = sub(st.classifier_q_mem_syn, q_syn);
    if tmp_scale > 0 {
        // mem syn is bigger, scale it down
        let tmp_scale_mem = negate(tmp_scale);
        scale_sig(
            &mut st.mem_syn_clas_estim,
            L_SYN_MEM_CLAS_ESTIM,
            tmp_scale_mem,
        );
    } else {
        // synthesis is bigger, scale it down
        // check for upscaling mem syn, first
        let mut tmp_scale_mem = norm_s(sub(memmax, 1));
        if sub(memmax, 1) == 0 {
            tmp_scale_mem = 14;
        }
        // if this is negative, syn can be scaled down
        *tmp_scale_syn = sub(add(st.classifier_q_mem_syn, tmp_scale_mem), q_syn);
        if *tmp_scale_syn > 0 || sub(mode, CLASSIFIER_TCX) == 0 {
            // dont scale up syn, but scale mem_syn, adequately
            tmp_scale_mem = sub(tmp_scale_mem, *tmp_scale_syn);
            *tmp_scale_syn = 0;
        }
        scale_sig(
            &mut st.mem_syn_clas_estim,
            L_SYN_MEM_CLAS_ESTIM,
            tmp_scale_mem,
        );
        st.classifier_q_mem_syn = add(st.classifier_q_mem_syn, tmp_scale_mem);
    }
}

/// The merit function of `FEC_clas_estim_fx` (zero crossings, pitch-synchronous correlation,
/// pitch coherence, tilt and energy), returned as `fmerit1` (Q15); writes `ener` and `frame_ener`
/// as the reference's locals, and `class_para` in MODE1.
fn fec_clas_estim_merit(
    st: &mut DecoderState,
    old_synth: &[i16; OLD_SYNTH_LEN],
    l_frame: i16,
    pitch: &[i16],
    ltp_gain: i16,
    mode: i16,
    narrow_band: i8,
    ener: &mut i16,
    frame_ener: &mut i16,
    class_para: Option<&mut i16>,
) -> i16 {
    let codec_mode = st.codec_mode;
    let synth_at = L_SYN_MEM_CLAS_ESTIM as usize;
    let nb_subfr = shr(l_frame, 6);

    // Compute the zero crossing rate for all subframes
    let mut tmp_s = shr(old_synth[synth_at - 1], 15); // sets 'tmpS to -1 if *pt1 < 0
    let mut ltmp = l_deposit_l(0);
    let n = (L_SUBFR * nb_subfr).clamp(0, L_FRAME16K) as usize;
    for &sample in &old_synth[synth_at..synth_at + n] {
        let tmp16 = add(1, tmp_s);
        if sample != 0 {
            // Do only count zero crossing, no zero touchings
            tmp_s = shr(sample, 15); // 1Clk: >=0 ---> 0 OTHERWISE -1
        }
        ltmp = l_msu0(ltmp, tmp_s, tmp16);
    }
    let mut zc_frame = shl(extract_l(ltmp), 4); // Q4
    if sub(l_frame, L_FRAME16K) == 0 {
        // zc_frame *= 0.8f; Renormalization for 12.8kHz core
        zc_frame = mult_r(zc_frame, 26214);
    }

    let voicing = fec_clas_estim_voicing(old_synth, l_frame, pitch);

    // Compute pitch coherence
    let mut pc: i16 = 0;
    if sub(codec_mode, MODE1) == 0
        || !(sub(ltp_gain, -32768 /* -1.f Q15 */) != 0 && sub(mode, CLASSIFIER_TCX) == 0)
    {
        pc = shr(
            abs_s(sub(add(pitch[3], sub(pitch[2], pitch[1])), pitch[0])),
            6,
        );
        if sub(l_frame, L_FRAME16K) == 0 {
            pc = mult_r(pc, 26214); // Renormalization for 12.8kHz core
        }
    }

    let tilt = fec_clas_estim_tilt(old_synth, nb_subfr);

    // Compute pitch-synchronous energy at the frame end
    let lp_speech = st.lp_ener_fer;
    let q_mem_syn = st.classifier_q_mem_syn;
    *ener = frame_energy(
        l_frame,
        pitch,
        &old_synth[synth_at..],
        lp_speech,
        frame_ener,
        q_mem_syn,
        &mut st.stl,
    );

    // transform parameters between 0 & 1
    // find unique merit function
    let enern = mac_r(C_ENR_FX, K_ENR_FX, *ener); // Q8
    let tiltn = extract_h(l_shr(l_mac(C_TILT_FX, K_TILT_FX, tilt), 6)); // Q14 -> Q8
    let corn = extract_h(l_shr(l_mac(C_COR_FX, K_COR_FX, voicing), 6)); // Q14 -> Q8
    let zcn = extract_h(l_shl(l_mac(C_ZC_FX, K_ZC_FX, zc_frame), 4)); // Q4 -> Q8

    let tmp16 = sub(ltp_gain, -32768 /* -1.f Q15 */);
    let mut pcn = if sub(codec_mode, MODE2) == 0 && tmp16 != 0 && sub(mode, CLASSIFIER_TCX) == 0 {
        round_word(l_shl(mpy_32_16_1(C_PC_FX /* Q16 */, ltp_gain /* Q15 */), 8))
    // Q16
    } else {
        extract_h(l_shl(l_mac(C_PC_FX, K_PC_FX, pc), 8)) // Q0 -> Q8
    };
    pcn = pcn.min(256);
    pcn = pcn.max(0);

    // fmerit1 = (1.0f/6.0f) * (tiltn + 2.0f*corn + zcn + pcn + enern)
    ltmp = l_mult(tiltn, UNS6);
    // `2*UNS6` expands textually to `2*10923/2` = 10923, not twice `UNS6` (5461).
    ltmp = l_mac(ltmp, corn, 2 * 10923 / 2);
    ltmp = l_mac(ltmp, zcn, UNS6);
    ltmp = l_mac(ltmp, pcn, UNS6);
    ltmp = l_mac(ltmp, enern, UNS6);
    let mut fmerit1 = round_word(l_shl(ltmp, 15 - 8)); // Q15 can saturate to 1.0
    if sub(codec_mode, MODE2) == 0 && narrow_band != 0 {
        fmerit1 = mult_r(fmerit1, 29491 /* 0.9f Q15 */); // 0.90
    }
    if sub(codec_mode, MODE1) == 0 {
        if let Some(class_para) = class_para {
            // Q14 - cannot be saturated, degrades HF synthesis
            *class_para = round_word(l_shl(ltmp, 14 - 8));
        }
    }
    fmerit1
}

/// The normalised correlation, pitch-synchronous at the end of the frame, of
/// `FEC_clas_estim_fx` (`voicing`, Q15).
fn fec_clas_estim_voicing(old_synth: &[i16; OLD_SYNTH_LEN], l_frame: i16, pitch: &[i16]) -> i16 {
    let mut cor_max = [0i16; 4];

    let mut t0 = shr(pitch[3], 6);
    let ltmp1 = l_mult(pitch[3], 256);
    if sub(t0, L_SUBFR * 3 / 2) > 0 {
        t0 = mac_r(ltmp1, pitch[2], 256);
    }
    let mut pos = sub(l_frame, t0); // T0 [34 231]
    cor_max[0] = corre_at(old_synth, pos, t0);

    let t0 = mult_r(add(pitch[2], pitch[3]), 256);
    let pos_limit = sub(l_frame, L_SUBFR);
    let mut j = 1.min(0.max(sub(pos, pos_limit)));
    let mut ltmp = l_deposit_l(cor_max[0]);
    if j > 0 {
        j = 16384;
        pos = sub(pos, t0); // T0 [34 231]
        cor_max[1] = corre_at(old_synth, pos, t0);
        ltmp = l_add(ltmp, i32::from(cor_max[1]));
        if sub(pos, pos_limit) > 0 {
            j = 10923;
            pos = sub(pos, t0); // T0 [34 231]
            cor_max[2] = corre_at(old_synth, pos, t0);
            ltmp = l_add(ltmp, i32::from(cor_max[2]));
        }
        if sub(pos, pos_limit) > 0 {
            j = 8192;
            pos = sub(pos, t0); // T0 [34 231]
            cor_max[3] = corre_at(old_synth, pos, t0);
            ltmp = l_add(ltmp, i32::from(cor_max[3]));
        }
    }
    let mut voicing = cor_max[0];
    if j > 0 {
        voicing = extract_l(mult_32_16(ltmp, j));
    }
    voicing
}

/// The spectral tilt (first normalised autocorrelation of the synthesis past its first
/// subframe) of `FEC_clas_estim_fx`, Q15 saturating to 1.0.
fn fec_clas_estim_tilt(old_synth: &[i16; OLD_SYNTH_LEN], nb_subfr: i16) -> i16 {
    let synth_at = L_SYN_MEM_CLAS_ESTIM as usize;
    let first = synth_at + L_SUBFR as usize;
    let mut ltmp = l_mult0(old_synth[first], old_synth[first]);
    let mut ltmp1 = l_mult0(old_synth[first], old_synth[first - 1]);
    let n = (L_SUBFR * sub(nb_subfr, 1)).clamp(0, L_FRAME16K - L_SUBFR) as usize;
    for k in first + 1..first + n.max(1) {
        ltmp = l_mac0(ltmp, old_synth[k], old_synth[k]);
        ltmp1 = l_mac0(ltmp1, old_synth[k], old_synth[k - 1]);
    }

    let mut tilt: i16 = 0;
    if ltmp != 0 {
        // sets a flag -1 or 1 for sign of Ltmp1
        let tmp16 = extract_l(l_shr(ltmp1, 32) | 1);
        ltmp1 = l_abs(ltmp1);
        let mut exp1 = norm_l(ltmp1);
        let mut tmp_y = extract_h(l_shl(ltmp1, exp1));
        exp1 = sub(31 - 1 + 3, exp1);
        let mut exp2 = norm_l(ltmp);
        let tmp_x = extract_h(l_shl(ltmp, exp2));
        exp2 = sub(31 - 1 + 3, exp2);
        let tmp_s = shr(sub(tmp_x, tmp_y), 16); // if tmp_x >= tmp_y tmpS = 0, -1 otherwise
        tmp_y = shl(tmp_y, tmp_s);
        exp1 = sub(exp1, tmp_s);
        tilt = div_s(tmp_y, tmp_x);
        tilt = shl(tilt, sub(exp1, exp2)); // saturate to 1.0
        tilt = i_mult2(tilt, tmp16);
    }
    tilt
}

/// The AMR-WB IO classification refinement of `FEC_clas_estim_fx` (noise coding: unvoiced
/// counters, attack detection, the `AUDIO_CLAS` override from the energy-variation history).
fn fec_clas_estim_amr_wb_io(
    st: &mut DecoderState,
    coder_type: i16,
    ener: i16,
    locattack: &mut i16,
    amr_io_class: &mut i16,
) {
    *locattack = 0;

    // Unvoiced signal but not silence
    if sub(st.clas_dec, UNVOICED_CLAS) == 0 && sub(coder_type, INACTIVE) != 0 {
        if sub(st.lp_ener_fer, 40 * 256 /* Q8 */) <= 0 {
            st.uv_cnt = 16;
        } else {
            st.uv_cnt = sub(st.uv_cnt, 8);
        }
    }
    // Neither unvoiced nor clean silence
    // Number of frames between UV is increased
    else if sub(coder_type, INACTIVE) != 0 {
        st.uv_cnt = add(st.uv_cnt, 1);
    }

    // Maximum/minimum number of frames between UV reached
    // Range 0..300
    st.uv_cnt = 300.min(st.uv_cnt).max(0);

    // IF VAD = 0 (no voice activity)
    //   long-term average updated towards to speech
    //   maximum number of frames between UV is limited to 125
    // Else
    //   update long-term average
    if sub(coder_type, INACTIVE) == 0 {
        st.lt_uv_cnt = mult_r(31130 /* 0.95f */, st.lt_uv_cnt); // tend to speech if no activity
        st.uv_cnt = 125.min(st.uv_cnt);
    } else {
        // *LT_UV_cnt = 0.9f * *LT_UV_cnt + 0.1f * *UV_cnt
        let mut ltmp = l_mult(3277 /* 0.1f */, st.uv_cnt);
        // Bring to Q22
        ltmp = l_shl(ltmp, 6);
        // Add to 0.9 x *LT_UV_cnt (Already in Q6)
        ltmp = l_mac(ltmp, 29491 /* 0.9f */, st.lt_uv_cnt); // Q22
        st.lt_uv_cnt = round_word(ltmp);
    }

    // Compute frame energy difference
    // IF long-term average is high and energy difference is relatively low
    //   classification is overwritten to AUDIO
    // IF energy difference > 6.0dB
    //   consider an attack
    let diff_ener = sub(ener, st.last_ener);
    st.last_ener = ener;
    *amr_io_class = st.clas_dec;
    if sub(st.lt_uv_cnt, LT_UV_THR_FX) > 0 && sub(diff_ener, 12 * 256 /* Q8 */) < 0 {
        *amr_io_class = AUDIO_CLAS;
    }
    if (sub(diff_ener, 6 * 256 /* Q8 */) > 0 && sub(st.clas_dec, AUDIO_CLAS) == 0)
        || sub(diff_ener, 9 * 256 /* Q8 */) > 0
    {
        *locattack = 1;
    }

    // Find mean of the past 40 frames energy variation
    if sub(coder_type, INACTIVE) != 0 {
        let max_lt = MAX_LT as usize;
        let lt_diff_etot = &mut st.lt_diff_etot;
        let mut ltmp = l_deposit_l(0);
        for i in 1..max_lt {
            ltmp = l_mac(ltmp, INV_MAX_LT_FX, lt_diff_etot[i - 1]); // divide by MAX_LT
            lt_diff_etot[i - 1] = lt_diff_etot[i];
        }
        ltmp = l_mac(ltmp, INV_MAX_LT_FX, lt_diff_etot[max_lt - 1]); // divide by MAX_LT
                                                                     // Ltmp is in Q24 (Q16+Q8)

        // Find statistical deviation of the energy variation history
        // against the last 15 frames
        let mut ltmp1 = l_deposit_l(1);
        for &value in &lt_diff_etot[max_lt - 15..max_lt] {
            // ftmp_c = lt_diff_etot[i] - mean_diff
            let tmp16 = mac_r(ltmp, value, -32768);
            // fcorr += ftmp_c*ftmp_c
            ltmp1 = l_mac0(ltmp1, tmp16, tmp16); // in Q16 (Q8xQ8)
        }
        lt_diff_etot[max_lt - 1] = diff_ener;

        // Compute statistical deviation
        // Overwrite classification, if needed
        // dev = (float)sqrt(fcorr / (MAX_LT-15))
        let mut tmp16 = 0i16;
        ltmp = sqrt_ratio32(
            ltmp1,
            16, /* Q16 */
            i32::from(MAX_LT - 15),
            0, /* Q0 */
            &mut tmp16,
        );
        // Put in Q8 (Don't care about Possible Saturation)
        tmp16 = round_word(l_shr(ltmp, sub(15 - 8, tmp16)));
        if sub(*amr_io_class, AUDIO_CLAS) == 0 && sub(tmp16, 5 * 256 /* Q8 */) > 0 {
            *amr_io_class = st.clas_dec;
            // *UV_cnt =  (short)(80 + *UV_cnt*0.2f)
            st.uv_cnt = add(80, mult(st.uv_cnt, 6554));
        }
    }
}

/// The epilogue of `FEC_clas_estim_fx`: the synthesis memory for frame class estimation keeps the
/// last `L_SYN_MEM_CLAS_ESTIM` samples of the local buffer.
fn fec_clas_estim_update_memory(
    st: &mut DecoderState,
    old_synth: &[i16; OLD_SYNTH_LEN],
    l_frame: usize,
    q_syn: i16,
    tmp_scale_syn: i16,
    tmp_scale: i16,
) {
    let len = L_SYN_MEM_CLAS_ESTIM as usize;
    if sub(st.codec_mode, 2) == 0 {
        st.mem_syn_clas_estim
            .copy_from_slice(&old_synth[l_frame..l_frame + len]);
    } else {
        copy_scale_sig(
            &old_synth[l_frame..],
            &mut st.mem_syn_clas_estim,
            L_SYN_MEM_CLAS_ESTIM,
            negate(tmp_scale),
        );
        st.classifier_q_mem_syn = sub(add(q_syn, tmp_scale_syn), tmp_scale);
    }
}

/// `FEC_dec_class_fx`: reads the signal class (and, at 14.8 kbit/s and above for a non-transition
/// frame, the quantised frame energy `enr_q`) the encoder sent for concealment.
fn fec_dec_class(
    st: &mut DecoderState,
    bitrate: i32,
    coder_type: i16,
    enr_q: &mut i32,
    last_good: i16,
) -> i16 {
    let mut clas = ONSET;

    if sub(coder_type, VOICED) != 0 {
        // decode the class
        let tmp_s = get_next_indice(st, 2) as i16;

        if tmp_s == 0 {
            clas = UNVOICED_CLAS;
        } else if sub(tmp_s, 1) == 0 {
            if sub(last_good, VOICED_TRANSITION) >= 0 {
                clas = VOICED_TRANSITION;
            } else {
                clas = UNVOICED_TRANSITION;
            }
        } else if sub(tmp_s, 2) == 0 {
            clas = VOICED_CLAS;
        }
    } else {
        clas = VOICED_CLAS;
    }

    // decode the energy
    if l_sub(bitrate, 14800 /* ACELP_14k80 */) >= 0
        && sub(coder_type, TRANSITION) != 0
        && sub(coder_type, AUDIO) < 0
    {
        let mut tmp_s = get_next_indice(st, 5) as i16;

        // convert from logarithmic to linear domain (the energy is quantized in the logarithmic domain with step of 3.1 dB)
        tmp_s = mult_r(shl(tmp_s, 10), 24576); // Q8
        let mut l_tmp = l_mult(tmp_s, 10885); // 0.3321928 in Q15 -> Q24
        l_tmp = l_shr(l_tmp, 8); // From Q24 to Q16
        let (exponent, sfrac) = l_extract_lc(l_tmp);
        *enr_q = pow2(exponent, sfrac);
    }
    clas
}

/// `FEC_pos_dec_fx`: decodes the FEC side information of a MODE1 ACELP frame (class and energy
/// through `FEC_dec_class_fx`, and above 24.4 kbit/s for a generic frame the last glottal pulse
/// position); returns the decoded pitch `T0` of the pulse, 0 if none.
pub fn fec_pos_dec(
    st: &mut DecoderState,
    coder_type: i16,
    last_good: i16,
    last_pulse_pos: &mut i16,
    clas: &mut i16,
    enr_q: &mut i32,
    core_brate: i32,
) -> i16 {
    let mut t0: i16 = 0;
    let mut t0_frac: i16 = 0;

    if sub(coder_type, UNVOICED) > 0 {
        // decode the clas and energy information
        if sub(coder_type, AUDIO) < 0 {
            *clas = fec_dec_class(st, core_brate, coder_type, enr_q, last_good);

            if sub(coder_type, GENERIC) == 0
                && sub(*clas, VOICED_CLAS) == 0
                && (sub(last_good, UNVOICED_CLAS) <= 0 || sub(last_good, INACTIVE_CLAS) == 0)
            {
                *clas = SIN_ONSET;
            }
        }

        if sub(coder_type, GENERIC) == 0 && l_sub(core_brate, 24400 /* ACELP_24k40 */) > 0 {
            let mut n_bits: i16 = 0;
            if sub(coder_type, AUDIO) != 0 {
                // find the number of bits
                let index = bit_alloc_idx_16khz(core_brate, coder_type, 0, 0);
                n_bits = usize::try_from(index)
                    .ok()
                    .and_then(|index| ACB_BITS_16KHZ_TBL.get(index))
                    .copied()
                    .unwrap_or(0);
            }

            // use the absolute position of pitch index in the bitstream (this value is hard coded and must be udpated when it changes in the encoder)
            let mut bit_pos_pitch_index: i16 = 71; // 64.0 <= core_brate < 96.0 kbit/s
            if l_sub(core_brate, 32000 /* ACELP_32k */) <= 0 {
                bit_pos_pitch_index = 72; // 32.0 kbit/s
                if sub(st.bwidth, 1 /* WB */) > 0 {
                    bit_pos_pitch_index = 73; // SWB and FB
                }
            }

            // retrieve the pitch index
            let pitch_index = get_indice(st, bit_pos_pitch_index, n_bits) as i16;

            // decode pitch period
            let mut t0_min: i16 = 34; // PIT_MIN
            let mut t0_max: i16 = 231; // PIT_MAX
            pit16k_q_dec(
                pitch_index,
                10,
                1,
                &mut t0,
                &mut t0_frac,
                &mut t0_min,
                &mut t0_max,
                &mut st.ber_detect,
            );

            // decode last pulse position
            *last_pulse_pos = get_next_indice(st, 8) as i16;

            // respect the sign
            if sub(*last_pulse_pos, 128) >= 0 {
                *last_pulse_pos = negate(*last_pulse_pos & 0x7F);
            }
            if sub(t0, 128) >= 0 {
                *last_pulse_pos = add(*last_pulse_pos, *last_pulse_pos);
            }

            if st.ber_detect != 0 {
                *last_pulse_pos = 0;
            }
        }
    }
    t0
}
