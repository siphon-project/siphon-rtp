//! The 6 kHz to 8 kHz band extension of AMR-WB IO mode (TS 26.442 `lib_dec/hf_synth_fx.c`:
//! `hf_synth_amr_wb_fx`, `hf_synth_amr_wb_reset_fx`, `hf_synthesis_amr_wb_fx`; TS 26.445 §6.2.2.4,
//! TS 26.190 §6.3): the 6-7 kHz part of the excitation spectrum is rebuilt from a part of the
//! 12.8 kHz excitation, shaped, transformed to 16 kHz, gain-adjusted per subframe, filtered with
//! the extended LPC and added to the output at its sampling rate.

use super::amr_wb_envelope::{adaptive_start_band, envelope};
use super::{DELAY_CLDFB_16K, INTERP_3_1_MEM_LEN, L_SUBFR32K, L_SUBFR48K};
use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    ACELP_23K85, ACELP_6K60, ACELP_8K85, ALLPASSSECTIONS_STEEP, FRAME_COUNT, L_FRAME, L_FRAME16K,
    L_SUBFR, L_SUBFR16K, M, NB_SUBFR, UNVOICED_CLAS,
};
use crate::evs::com::edct::edct;
use crate::evs::com::math_op::isqrt;
use crate::evs::com::modif_fs::{interpolate_3_over_1_allpass, interpolate_allpass_steep};
use crate::evs::com::syn_filt::syn_filt_s;
use crate::evs::com::tools::{
    copy, copy_scale_sig_16_32, copy_scale_sig_32_16, dot_prod_satcontr, dot_product, exp16_array,
    exp32_array, find_max_norm16, random, scale_sig, set16, vr_add,
};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{ALLPASS_POLES_3_OV_2, DEEM_TAB_FX, FILT_HP_FX, HP_GAIN_FX};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_mac, l_mult, l_shl, l_shr, mult, mult_r, negate,
    norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0};

/// The HF synthesis memories of the decoder state that `hf_synth_amr_wb_fx` and
/// `hf_synth_amr_wb_reset_fx` read and update (the reference passes each as its own argument).
pub struct HfSynthAmrWbState<'a> {
    /// `mem_syn_hf`: HF LPC synthesis filter memory (`M`).
    pub mem_syn_hf: &'a mut [i16],
    /// `delay_syn_hf`: HF synthesis delay line (`NS2SA(16000, DELAY_CLDFB_NS)`).
    pub delay_syn_hf: &'a mut [i16],
    /// `prev_r`: previous subframe gain (Q10).
    pub prev_r: &'a mut i16,
    /// `fmerit_w_sm`: smoothed `fmerit_w` (Q14).
    pub fmerit_w_sm: &'a mut i16,
    /// `mem_hp_interp`: interpolation memory.
    pub mem_hp_interp: &'a mut [i16],
    /// `frame_count`.
    pub frame_count: &'a mut i16,
    /// `ne_min`: minimum noise gate short-term energy (Q8).
    pub ne_min: &'a mut i16,
    /// `fmerit_m_sm`: smoothed `fmerit_m` (Q14).
    pub fmerit_m_sm: &'a mut i16,
    /// `voice_fac_amr_wb_hf`: voice factor memory (Q15).
    pub voice_fac: &'a mut i16,
    /// `unvoicing`: unvoiced parameter (Q15).
    pub unvoicing: &'a mut i16,
    /// `unvoicing_sm`: smoothed unvoiced parameter (Q15).
    pub unvoicing_sm: &'a mut i16,
    /// `unvoicing_flag`.
    pub unvoicing_flag: &'a mut i16,
    /// `voicing_flag`.
    pub voicing_flag: &'a mut i16,
    /// `start_band_old`: previous start point for copying the frequency band.
    pub start_band_old: &'a mut i16,
    /// `OptCrit_old`: previous criterion value for deciding the start point (Q15).
    pub opt_crit_old: &'a mut i32,
}

impl<'a> HfSynthAmrWbState<'a> {
    /// The decoder's own HF memories, the way every reference call passes them, and the seed of
    /// the HF noise (`seed2`) that goes with them.
    pub fn of(st: &'a mut DecoderState) -> (&'a mut i16, Self) {
        (
            &mut st.seed2,
            Self {
                mem_syn_hf: &mut st.mem_syn_hf,
                delay_syn_hf: &mut st.delay_syn_hf,
                prev_r: &mut st.prev_r,
                fmerit_w_sm: &mut st.fmerit_w_sm,
                mem_hp_interp: &mut st.mem_hp_interp,
                frame_count: &mut st.frame_count,
                ne_min: &mut st.ne_min,
                fmerit_m_sm: &mut st.fmerit_m_sm,
                voice_fac: &mut st.voice_fac_amr_wb_hf,
                unvoicing: &mut st.unvoicing,
                unvoicing_sm: &mut st.unvoicing_sm,
                unvoicing_flag: &mut st.unvoicing_flag,
                voicing_flag: &mut st.voicing_flag,
                start_band_old: &mut st.start_band_old,
                opt_crit_old: &mut st.opt_crit_old,
            },
        )
    }
}

/// `hf_synth_amr_wb_reset_fx`: reset the HF synthesis filters (needed in switching scenarios):
/// advance the noise seed by one 16 kHz frame, clear the memories and set the initial values.
pub fn hf_synth_amr_wb_reset(seed2: &mut i16, state: &mut HfSynthAmrWbState<'_>) {
    for _ in 0..L_FRAME16K {
        let _ = random(seed2);
    }

    set16(state.mem_syn_hf, 0, M);
    set16(state.delay_syn_hf, 0, DELAY_CLDFB_16K as i16);
    set16(state.mem_hp_interp, 0, INTERP_3_1_MEM_LEN);

    *state.prev_r = 0;
    *state.fmerit_w_sm = 0;
    *state.frame_count = 0;
    *state.ne_min = -7680; // Q8
    *state.fmerit_m_sm = 0;
    *state.voice_fac = 0;
    *state.unvoicing = 0;
    *state.unvoicing_sm = 32767; // Q15
    *state.unvoicing_flag = 0;
    *state.voicing_flag = 0;
    *state.start_band_old = 160;
    *state.opt_crit_old = 32768; // Q15
}

/// The scalars `hf_synth_amr_wb_fx` derives before the spectral processing.
struct Smoothed {
    /// `voice_fac` (Q14): the mean of the four voicing factors.
    voice_fac: i16,
    /// `fmerit_w`: the smoothed weighting merit (Q14).
    fmerit_w: i16,
}

/// The first-order correlation `til` (Q13) of every 64-sample subframe of the synthesis.
fn subframe_tilt(synth: &[i16], til: &mut [i16], til0: &mut [i16]) {
    for i in 0..NB_SUBFR as usize {
        let at = i * L_SUBFR as usize;
        let enr1 = dot_product(&synth[at..], &synth[at..], L_SUBFR); // 2*(Q_syn-3)+1
        let enr2 = dot_product(&synth[at + 1..], &synth[at..], L_SUBFR - 1); // 2*(Q_syn-3)+1

        let mut tmp1 = extract_h(enr1);
        tmp1 = tmp1.max(1);
        let tmp2 = extract_h(enr2);

        let exp = norm_s(tmp1);
        tmp1 = div_s(shl(1, sub(14, exp)), tmp1); // Q(29-exp-2*(Q_syn-3)-1)
        let l_tmp = l_mult(tmp2, tmp1); // 30-exp-2*(Q_syn-3)-1+2*(Q_syn-3)+1 -> 30-exp
        til[i] = round_word(l_shl(l_tmp, sub(exp, 1))); // 13
        til0[i] = til[i];
    }
}

/// The smoothing of the LF parameters used for the excitation weighting and the subframe gains:
/// the frame counter and minimum noise energy, the voicing factor, `fmerit_w` / `fmerit_m` and
/// the per-subframe tilt `til` (Q13).
fn smooth_parameters(
    state: &mut HfSynthAmrWbState<'_>,
    amr_io_class: i16,
    core_type: i16,
    fmerit: i16,
    voice_factors: &[i16],
    pitch_buf: &[i16],
    ng_ener_st: i16,
    til: &mut [i16],
) -> Smoothed {
    // modify the LF parameters for the excitation weighting or the sub-frame gains calculation
    let mut pitch_var_cur: i16 = 0;
    for i in 0..3 {
        let tmp1 = abs_s(sub(pitch_buf[i], pitch_buf[i + 1])); // Q5
        pitch_var_cur = add(pitch_var_cur, shr(tmp1, 1)); // Q6 -> Q5
    }
    if sub(*state.frame_count, FRAME_COUNT) > 0 && amr_io_class == UNVOICED_CLAS {
        *state.frame_count = 0;
        *state.ne_min = -7680; // Q8
    } else {
        let tmp1 = *state.frame_count;
        *state.frame_count = add(*state.frame_count, 1);
        if sub(tmp1, 2 * FRAME_COUNT) > 0 {
            *state.frame_count = 2 * FRAME_COUNT;
        }
        if sub(ng_ener_st, *state.ne_min) < 0 {
            *state.ne_min = ng_ener_st; // Q8
        }
    }

    let mut l_tmp = l_mult(voice_factors[0], 4096);
    for &factor in &voice_factors[1..4] {
        l_tmp = l_mac(l_tmp, factor, 4096);
    }
    let voice_fac = round_word(l_tmp);

    // fmerit_w = fmerit > 5734 ? 5734 : (fmerit < 2458 ? 2458 : fmerit); // Q14
    let mut fmerit_w = fmerit.min(5734);
    fmerit_w = fmerit_w.max(2458);

    if sub(core_type, 1) == 0 {
        fmerit_w = shr(fmerit_w, 1); // Q14
    }

    l_tmp = l_mult(fmerit_w, add(16384, voice_fac));
    fmerit_w = extract_l(l_shr(l_tmp, 15)); // Q14
    *state.fmerit_w_sm = round_word(l_mac(l_mult(*state.fmerit_w_sm, 29491), fmerit_w, 3277)); // Q14
    fmerit_w = *state.fmerit_w_sm;

    let mut tmp1 = fmerit;
    if sub(fmerit, 8192) < 0 {
        tmp1 = 16384;
    }
    let fmerit_m = negate(add(-32768, tmp1));
    *state.fmerit_m_sm = add(shr(*state.fmerit_m_sm, 1), shr(fmerit_m, 1)); // Q14
    let fmerit_m = *state.fmerit_m_sm;

    for value in til.iter_mut().take(NB_SUBFR as usize) {
        let mut tmp = sub(pitch_var_cur, 320);
        tmp &= *value;
        if tmp < 0 {
            *value = 1638;
        }

        let tmp1 = sub(8192, *value);
        *value = 6554.max(tmp1);
        let tmp1 = add(*state.ne_min, 7680); // Q8
        let tmp1 = mult_r(tmp1, 7340); // Q20 -> 0.007 // Q13
        *value = add(*value, tmp1); // Q13

        l_tmp = l_mult0(*value, fmerit_m); // Q13+14
        *value = extract_l(l_shr(l_tmp, 14)); // Q13
    }
    Smoothed {
        voice_fac,
        fmerit_w,
    }
}

/// The 6 kHz - 8 kHz part of the DCT of the excitation, and the energy of its copied band.
struct HighBand {
    /// `dct_hb`: the high band of the DCT spectrum at 16 kHz (`L_FRAME16k`), at `qdct`.
    dct_hb: [i16; L_FRAME16K as usize],
    /// `signum`: the signs of the copied band.
    signum: [i16; L_SUBFR16K as usize],
    /// `qdct`: the Q of `dct_hb`.
    qdct: i16,
    /// `hb_ener`: the energy of the copied band at `q1`.
    hb_ener: i16,
    /// `q1`: the Q of `hb_ener`.
    q1: i16,
}

/// The DCT of the excitation and the copy of its band from `start_band` as the high band
/// (200..240 as is, 240..320 as magnitudes with their signs kept aside).
fn high_band_spectrum(exc: &[i16], q_exc: i16, start_band: i16) -> HighBand {
    let mut exc32 = [0i32; L_FRAME as usize];
    let mut dct_exc32 = [0i32; L_FRAME as usize];
    let mut dct_exc = [0i16; L_FRAME as usize];

    let q_tmp = exp16_array(L_FRAME, exc);
    let mut qdct = sub(q_tmp, 1);
    copy_scale_sig_16_32(exc, &mut exc32, L_FRAME, qdct);

    qdct = add(qdct, q_exc);
    edct(&exc32, &mut dct_exc32, L_FRAME, &mut qdct);
    let mut q_tmp = exp32_array(L_FRAME, &dct_exc32);

    q_tmp = sub(q_tmp, 16);
    copy_scale_sig_32_16(&dct_exc32, &mut dct_exc, L_FRAME, q_tmp);
    qdct = add(qdct, q_tmp);

    let mut dct_hb = [0i16; L_FRAME16K as usize];
    dct_hb[200..240].copy_from_slice(&dct_exc[200..240]); // qdct
    let mut signum = [1i16; L_SUBFR16K as usize];
    let start = start_band.max(0) as usize;
    for i in 0..(L_FRAME16K as usize - 240) {
        let value = dct_exc[start + i];
        if value < 0 {
            signum[i] = -1;
        }
        dct_hb[240 + i] = abs_s(value); // qdct
    }
    let mut q1: i16 = 0;
    let hb_ener = dot_prod_satcontr(
        &dct_hb[240..],
        &dct_hb[240..],
        qdct,
        qdct,
        &mut q1,
        L_SUBFR16K,
    );
    HighBand {
        dct_hb,
        signum,
        qdct,
        hb_ener,
        q1,
    }
}

/// The tonal / ambient split of the copied band: the band is smoothed over a sliding window
/// (`hb_amb`), what stands above it is the tonal part, the tonal part is attenuated by `g`
/// (from the energy ratio and `beta`) and the ambient part amplified by `1/g`; the signs are put
/// back. Returns the output scale `scale` (Q15).
fn tonal_ambient_split(hb: &mut HighBand, beta: i16, gamma: i16) -> i16 {
    let sub16 = L_SUBFR16K as usize;
    let qdct = hb.qdct;
    let q1 = hb.q1;
    let mut hb_amb = [0i16; L_SUBFR16K as usize];
    let mut hb_tonal = [0i16; L_SUBFR16K as usize];

    let mut l_tmp: i32 = 1; // variable for the tonal energy

    for i in 0..8usize {
        let fn_ = add(i as i16, 8);
        let tmp1 = div_s(1, fn_); // Q15
        let mut tmp: i16 = 0;
        for j in 0..fn_ as usize {
            tmp = add(tmp, shr(hb.dct_hb[240 + j], 2)); // qdct-2
        }
        hb_amb[i] = round_word(l_shl(l_mult(tmp, tmp1), 2)); // qdct
        hb_tonal[i] = sub(hb.dct_hb[240 + i], hb_amb[i]);
        if hb_tonal[i] > 0 {
            l_tmp = l_mac0(l_tmp, shr(hb_tonal[i], 1), shr(hb_tonal[i], 1));
        }
    }
    for i in 8..sub16 - 8 {
        let fb = sub(i as i16, 7) as usize;
        let fn_ = fb + 15;
        let mut tmp: i16 = 0;
        for j in fb..fn_ {
            tmp = add(tmp, shr(hb.dct_hb[240 + j], 2)); // qdct-2
        }
        hb_amb[i] = mult_r(tmp, 8738); // 8738 = 1/15 in Q17 qdct
        hb_tonal[i] = sub(hb.dct_hb[240 + i], hb_amb[i]);
        if hb_tonal[i] > 0 {
            l_tmp = l_mac0(l_tmp, shr(hb_tonal[i], 1), shr(hb_tonal[i], 1));
        }
    }
    for i in sub16 - 8..sub16 {
        let fb = sub(i as i16, 7) as usize;
        let mut tmp: i16 = 0;
        let fn_ = sub(L_SUBFR16K, fb as i16);
        let tmp1 = div_s(1, fn_); // Q15
        for j in fb..sub16 {
            tmp = add(tmp, shr(hb.dct_hb[240 + j], 2)); // qdct-2
        }
        hb_amb[i] = round_word(l_shl(l_mult(tmp, tmp1), 2)); // qdct
        hb_tonal[i] = sub(hb.dct_hb[240 + i], hb_amb[i]);
        if hb_tonal[i] > 0 {
            l_tmp = l_mac0(l_tmp, shr(hb_tonal[i], 1), shr(hb_tonal[i], 1)); // 2*qdct-2
        }
    }

    // scaling of hb_ener is q1; tonal_ener < hb_ener, so the scaling of tonal_ener can be q1 too
    let tonal_ener = round_word(l_shr(l_tmp, sub(shl(qdct, 1), add(q1, 18))));
    let mut tmp = sub(hb.hb_ener, tonal_ener); // q1
    let mut tmp1 = round_word(l_shl(l_mult(beta, tonal_ener), 1)); // q1
    tmp1 = sub(hb.hb_ener, tmp1); // q1
    tmp = div_s(tmp, tmp1.max(1)); // Q15
    let g = shl(mult(beta, tmp), 1); // Q15
    let q2 = norm_s(g);
    let mut inv_g = div_s(shl(1, sub(14, q2)), g); // Q(29-q2-15)
    inv_g = shl(inv_g, sub(q2, 2)); // Q12
    for i in 0..sub16 {
        if hb_tonal[i] > 0 {
            hb_tonal[i] = mult_r(hb_tonal[i], g); // qdct
        }
        hb_amb[i] = round_word(l_shl(l_mult(hb_amb[i], inv_g), 3)); // qdct
        hb.dct_hb[240 + i] = add(hb_tonal[i], hb_amb[i]);
        hb.dct_hb[240 + i] = extract_l(l_mult0(hb.dct_hb[240 + i], hb.signum[i]));
        // qdct
    }

    let mut q2: i16 = 0;
    let ener = dot_prod_satcontr(
        &hb.dct_hb[240..],
        &hb.dct_hb[240..],
        qdct,
        qdct,
        &mut q2,
        L_SUBFR16K,
    );
    let mut scale = div_s(shl(1, 14), hb.hb_ener); // Q(29-q1)
    let l_tmp = l_mult(ener, scale); // 30-q1+q2
    let q2 = sub(q1, q2); // 30-q2
    scale = round_word(isqrt(l_shl(l_tmp, sub(q2, 24)))); // Q12
    round_word(l_shl(l_mult(scale, gamma), 4)) // Q15
}

/// The weights (Q14) of the end of the band: `filt_weight_coeff` values falling from 1 towards
/// 0.5, and the number of them, by bit rate.
fn filter_weights(core_brate: i32, filt_weight: &mut [i16]) -> i16 {
    let (filt_weight_coeff, rev_filt_weight_coeff): (i16, i16) =
        if core_brate == i32::from(ACELP_6K60) {
            (60, 555) // 1/(filt_weight_coeff-1) Q15
        } else if core_brate == i32::from(ACELP_8K85) {
            (40, 840)
        } else {
            (20, 1725)
        };

    for i in 0..filt_weight_coeff {
        let mut l_tmp = l_mult(-32735, rev_filt_weight_coeff); // Q31
        l_tmp = l_shl(mult_32_16(l_tmp, i), 14); // Q16+14
        filt_weight[i as usize] = add(round_word(l_tmp), 16384); // Q14
    }
    filt_weight_coeff
}

/// The shaping of the high-band spectrum: the output scale, the band-end weights, the high-pass
/// and, below 23.85 kbit/s, the de-emphasis; at 23.85 kbit/s the HF gain index selects the
/// per-subframe correction gain instead.
fn shape_high_band(
    core_brate: i32,
    hb: &mut HighBand,
    scale: i16,
    hf_gain: &[i16],
    hf_corr_gain: &mut [i16],
) {
    let mut filt_weight = [0i16; L_SUBFR16K as usize];
    let filt_weight_coeff = filter_weights(core_brate, &mut filt_weight);
    let first_weighted = 320 - filt_weight_coeff as usize;

    if core_brate == i32::from(ACELP_23K85) {
        for i in 240..L_FRAME16K as usize {
            hb.dct_hb[i] = mult_r(hb.dct_hb[i], scale); // qdct
            if i >= first_weighted {
                let weight = filt_weight[i - first_weighted];
                hb.dct_hb[i] = round_word(l_shl(l_mult(weight, hb.dct_hb[i]), 1));
                // qdct
            }
        }
        for i in 200..256usize {
            hb.dct_hb[i] = mult_r(FILT_HP_FX[i - 200], hb.dct_hb[i]); // qdct
        }
        for i in 0..NB_SUBFR as usize {
            let index = hf_gain[i];
            hf_corr_gain[i] = HP_GAIN_FX.get(index.max(0) as usize).copied().unwrap_or(0);
            // Q14
        }
    } else {
        for i in 240..L_FRAME16K as usize {
            hb.dct_hb[i] = mult_r(hb.dct_hb[i], scale); // qdct
            if i > 255 {
                hb.dct_hb[i] = mult_r(19505, hb.dct_hb[i]);
            }

            if i >= first_weighted {
                let weight = filt_weight[i - first_weighted];
                hb.dct_hb[i] = round_word(l_shl(l_mult(weight, hb.dct_hb[i]), 1));
                // qdct
            }
        }

        for i in 200..256usize {
            hb.dct_hb[i] = mult_r(FILT_HP_FX[i - 200], hb.dct_hb[i]); // qdct
            hb.dct_hb[i] = mult_r(DEEM_TAB_FX[i - 200], hb.dct_hb[i]);
        }
    }
}

/// The inverse DCT of the shaped high band to the 16 kHz excitation `exc16k` (at the returned
/// `qhf`), and its per-subframe energy normalisation to the energy of the 12.8 kHz excitation
/// `exc` of the same subframe. Returns `qhf - 1`, the Q of the normalised `exc16k`.
fn excitation_16k(hb: &HighBand, exc: &[i16], q_exc: i16, exc16k: &mut [i16]) -> i16 {
    let mut dct_hb32 = [0i32; L_FRAME16K as usize];
    let mut exc16k32 = [0i32; L_FRAME16K as usize];

    let q_tmp = exp16_array(L_FRAME16K, &hb.dct_hb);
    let mut qhf = sub(q_tmp, 1);
    copy_scale_sig_16_32(&hb.dct_hb, &mut dct_hb32, L_FRAME16K, qhf);
    qhf = add(qhf, hb.qdct);
    edct(&dct_hb32, &mut exc16k32, L_FRAME16K, &mut qhf);
    let mut q_tmp = exp32_array(L_FRAME16K, &exc16k32);
    q_tmp = sub(q_tmp, 16);
    copy_scale_sig_32_16(&exc16k32, exc16k, L_FRAME16K, q_tmp);
    qhf = add(qhf, q_tmp);

    let (mut q1, mut q2, mut q3, mut q4) = (0i16, 0i16, 0i16, 0i16);
    let ener = dot_prod_satcontr(exc, exc, q_exc, q_exc, &mut q1, L_FRAME);
    let tmp = dot_prod_satcontr(exc16k, exc16k, qhf, qhf, &mut q2, L_FRAME16K);

    for i in 0..NB_SUBFR as usize {
        let at12k8 = i * L_SUBFR as usize;
        let at16k = i * L_SUBFR16K as usize;
        let e_subfr1 = dot_prod_satcontr(
            &exc[at12k8..],
            &exc[at12k8..],
            q_exc,
            q_exc,
            &mut q3,
            L_SUBFR,
        );
        let e_subfr2 = dot_prod_satcontr(
            &exc16k[at16k..],
            &exc16k[at16k..],
            qhf,
            qhf,
            &mut q4,
            L_SUBFR16K,
        );

        let mut l_tmp = l_mult(e_subfr1, tmp); // Q(q2+q3+1)
        q3 = add(add(q2, q3), 1);
        let mut shift = norm_l(l_tmp);
        l_tmp = l_shl(l_tmp, shift); // Q(q3+shift)
        q3 = add(q3, shift);
        let mut scale = round_word(l_tmp); // Q(q3-16)
        q3 = sub(q3, 16);
        scale = div_s(shl(1, 14), scale); // Q(29-q3)
        l_tmp = l_mult(scale, ener); // Q(29-q3+q1+1)
        shift = norm_l(l_tmp);
        l_tmp = l_shl(l_tmp, shift); // Q(29-q3+q1+1+shift)
        scale = round_word(l_tmp); // Q(29-q3+q1+1+shift-16)
        l_tmp = l_mult(scale, e_subfr2); // Q(15+q1-q3+q4+shift)
        q3 = sub(15, q3);
        q3 = add(q3, q1);
        q3 = add(q3, shift);
        q3 = add(q3, q4);
        scale = round_word(isqrt(l_shl(l_tmp, sub(6, q3)))); // Q12

        for value in &mut exc16k[at16k..at16k + L_SUBFR16K as usize] {
            *value = round_word(l_shl(l_mult(*value, scale), 2)); // qhf-1
        }
    }
    sub(qhf, 1)
}

/// `hf_synth_amr_wb_fx`: the 6 - 8 kHz band extension of AMR-WB IO; adds the synthesised high
/// band to `synth_out` (`output_frame` samples at the output rate, Q`q_out`).
///
/// `exc` is the total excitation at 12.8 kHz (Q`q_exc`), `synth` the 12.8 kHz synthesis (Q`q_syn`,
/// scaled down by 3 bits here, as in the reference), `aq` the four LP filters, `fmerit` the
/// classification parameter of the FEC (Q14), `hf_gain` the 23.85 kbit/s HF gain indices,
/// `voice_factors` (Q15), `pitch_buf` (Q5), `ng_ener_st` the noise gate energy (Q8) and `lsf_new`
/// the ISFs (Q2). `amr_io_class` is the FEC signal class.
pub fn hf_synth_amr_wb(
    core_brate: i32,
    output_frame: i16,
    aq: &[i16],
    exc: &[i16],
    synth: &mut [i16],
    state: &mut HfSynthAmrWbState<'_>,
    amr_io_class: i16,
    synth_out: &mut [i16],
    fmerit: i16,
    hf_gain: &[i16],
    voice_factors: &[i16],
    pitch_buf: &[i16],
    ng_ener_st: i16,
    lsf_new: &[i16],
    q_exc: i16,
    q_out: i16,
) {
    let mut til = [0i16; NB_SUBFR as usize];
    let mut til0 = [0i16; NB_SUBFR as usize];
    let mut hf_corr_gain = [0i16; NB_SUBFR as usize];
    let mut sub_gain = [0i16; NB_SUBFR as usize];
    let mut ap = [0i16; (M as usize + 1) * NB_SUBFR as usize];
    let mut exc16k = [0i16; L_FRAME16K as usize];

    scale_sig(synth, L_FRAME, -3);
    subframe_tilt(synth, &mut til, &mut til0);

    let output_subfr = shr(output_frame, 2);

    let mut core_type: i16 = 1;
    if sub(amr_io_class, 7) != 0 {
        core_type = 0;
    }

    let Smoothed {
        voice_fac,
        fmerit_w,
    } = smooth_parameters(
        state,
        amr_io_class,
        core_type,
        fmerit,
        voice_factors,
        pitch_buf,
        ng_ener_st,
        &mut til,
    );

    // predict the LPC coefficients and calculate the sub-frame gains
    for i in 0..NB_SUBFR as usize {
        let at = i * (M as usize + 1);
        envelope(
            core_brate,
            &aq[at..],
            &mut ap[at..],
            &mut sub_gain[i],
            til0[i],
            til[i],
            voice_factors[i],
            state.prev_r,
            state.voice_fac,
            state.unvoicing,
            state.unvoicing_sm,
            state.unvoicing_flag,
        );
    }

    let mut start_band: i16 = 0;
    adaptive_start_band(
        &mut start_band,
        core_brate,
        lsf_new,
        voice_fac,
        amr_io_class,
        state.voicing_flag,
        state.start_band_old,
        state.opt_crit_old,
    );

    let mut hb = high_band_spectrum(exc, q_exc, start_band);

    let mut l_tmp = l_shl(l_mult(start_band, 205), 14); // Q30
    let mut tmp = round_word(l_tmp); // Q14
    tmp = sub(18022, tmp); // Q14
    let fmerit_w = round_word(l_shl(l_mult(fmerit_w, tmp), 1)); // Q: 14+14+1+1-16 = 14

    l_tmp = i32::from(fmerit_w); // Q14
    l_tmp = isqrt(l_tmp); // Q(31-7)
    tmp = round_word(l_tmp); // Q8
    let q2 = norm_s(tmp);
    let mut alpha = div_s(shl(1, sub(14, q2)), tmp); // Q(29-q2-8)
    alpha = shl(alpha, sub(q2, 7)); // Q14

    let beta = sub(16384, fmerit_w); // Q14

    l_tmp = l_mult(alpha, 31130); // Q30
    let mut gamma = round_word(l_tmp); // Q14
    gamma = sub(17203, gamma); // Q14
    gamma = gamma.min(16384);
    gamma = gamma.max(4915);

    let scale = if sub(beta, 16384) < 0 {
        tonal_ambient_split(&mut hb, beta, gamma)
    } else {
        32767 // ~1 in Q15
    };

    shape_high_band(core_brate, &mut hb, scale, hf_gain, &mut hf_corr_gain);
    let qhf = excitation_16k(&hb, exc, q_exc, &mut exc16k);

    for i in 0..NB_SUBFR as usize {
        hf_synthesis_amr_wb(
            core_brate,
            output_subfr,
            &ap[i * (M as usize + 1)..],
            &mut exc16k[i * L_SUBFR16K as usize..],
            &mut synth_out[i * output_subfr as usize..],
            state.mem_syn_hf,
            state.delay_syn_hf,
            state.mem_hp_interp,
            sub_gain[i],
            hf_corr_gain[i],
            til0[i],
            voice_factors[i],
            &exc[i * L_SUBFR as usize..],
            q_exc,
            q_out,
            qhf,
        );
    }
}

/// `hf_synthesis_amr_wb_fx`: one subframe of the high band: the gain of the 16 kHz excitation,
/// at 23.85 kbit/s the correction against the HF gain index, the LPC synthesis, the CLDFB delay
/// compensation, the interpolation to the output rate and the addition to `synth_out`.
fn hf_synthesis_amr_wb(
    core_brate: i32,
    output_subfr: i16,
    ap: &[i16],
    exc16k: &mut [i16],
    synth_out: &mut [i16],
    mem_syn_hf: &mut [i16],
    delay_syn_hf: &mut [i16],
    mem_hp_interp: &mut [i16],
    p_r: i16,
    hf_corr_gain: i16,
    til: i16,
    voice_factors: i16,
    exc: &[i16],
    q_exc: i16,
    q_out: i16,
    mut qhf: i16,
) {
    const SUB16: usize = L_SUBFR16K as usize;
    let mut hf_syn = [0i16; SUB16];
    let mut upsampled_hf_syn = [0i16; L_SUBFR48K as usize];
    let mut temp_buffer = [0i16; DELAY_CLDFB_16K];
    let mut exc2385 = [0i16; SUB16];

    if core_brate == i32::from(ACELP_23K85) {
        let (mut q1, mut q2) = (0i16, 0i16);
        let mut ener = dot_prod_satcontr(exc, exc, q_exc, q_exc, &mut q1, L_SUBFR);
        let mut tmp = dot_prod_satcontr(exc16k, exc16k, qhf, qhf, &mut q2, L_SUBFR16K);

        let mut l_tmp = l_mult(ener, 6554); // Q(q1+16)
        let mut q3 = norm_l(l_tmp);
        l_tmp = l_shl(l_tmp, q3); // Q(q1+q3+16)
        ener = extract_h(l_tmp); // Q(q1+q3)
        q1 = add(q1, q3);

        let mut scale = div_s(shl(1, 14), ener); // Q(29-q1)
        l_tmp = l_mult(tmp, scale); // 30-q1+q2
        q2 = sub(q1, q2); // 30-q2
        scale = round_word(isqrt(l_shl(l_tmp, sub(q2, 24)))); // Q12

        for i in 0..SUB16 {
            l_tmp = l_mult(exc16k[i], hf_corr_gain); // qhf+15
            l_tmp = mult_32_16(l_tmp, scale); // qhf-1+12+1
            exc2385[i] = round_word(l_shl(l_tmp, 1)); // qhf-3
        }

        for value in exc16k[..SUB16].iter_mut() {
            *value = mult_r(*value, p_r); // qhf-3
        }

        qhf = sub(qhf, 3);

        ener = dot_prod_satcontr(exc16k, exc16k, qhf, qhf, &mut q1, L_SUBFR16K);
        tmp = dot_prod_satcontr(&exc2385, &exc2385, qhf, qhf, &mut q2, L_SUBFR16K);
        l_tmp = l_mult(ener, 9830); // Q(q1+16)
        q3 = norm_l(l_tmp);
        l_tmp = l_shl(l_tmp, q3); // Q(q1+q3+16)
        ener = extract_h(l_tmp); // Q(q1+q3)
        q1 = add(q1, q3);

        scale = div_s(shl(1, 14), ener); // Q(29-q1)
        l_tmp = l_mult(tmp, scale); // 30-q1+q2
        q2 = sub(q1, q2); // 30-q2
        scale = round_word(isqrt(l_shl(l_tmp, sub(q2, 24)))); // Q12

        let mut flag = negate(til & -0x8000_i32 as i16);
        if sub(scale, 4096) > 0 {
            flag = 1;
        }
        if flag != 0 {
            copy(&exc2385, exc16k, L_SUBFR16K);
        } else {
            for i in 0..SUB16 {
                // `16348` (not 16384) is the reference's constant
                tmp = sub(16348, shl(til, 1)); // Q14
                l_tmp = l_mult(tmp, sub(26214, shr(voice_factors, 1))); // Q29
                tmp = round_word(l_shr(l_tmp, 1)); // Q12
                tmp = tmp.min(4096);
                tmp = tmp.max(scale);
                exc16k[i] = round_word(l_shl(l_mult(exc2385[i], tmp), 3)); // qhf
            }
        }
    } else {
        for value in exc16k[..SUB16].iter_mut() {
            *value = mult_r(*value, p_r); // qhf-3
        }

        qhf = sub(qhf, 3);
    }

    let shift = sub(qhf, q_out);
    syn_filt_s(shift, ap, M, exc16k, &mut hf_syn, L_SUBFR16K, mem_syn_hf, 1); // Q_out = qhf-shift

    // Resample to the output sampling rate; synchronize the LB and HB components (delay
    // compensation); add the synthesised high band to the speech synthesis

    // compensate the CLDFB resampling delay
    let delay = DELAY_CLDFB_16K;
    temp_buffer.copy_from_slice(&hf_syn[SUB16 - delay..]);
    hf_syn.copy_within(0..SUB16 - delay, delay);
    hf_syn[..delay].copy_from_slice(&delay_syn_hf[..delay]);
    delay_syn_hf[..delay].copy_from_slice(&temp_buffer);

    let mem_len = INTERP_3_1_MEM_LEN as usize;
    if sub(output_subfr, L_SUBFR48K) == 0 {
        // 48 kHz sampled output
        let s = sub(
            find_max_norm16(&hf_syn, L_SUBFR16K)
                .min(find_max_norm16(mem_hp_interp, INTERP_3_1_MEM_LEN - 3)),
            3,
        )
        .min(sub(find_max_norm16(&mem_hp_interp[mem_len - 3..], 3), 1))
        .max(0);
        scale_sig(&mut hf_syn, L_SUBFR16K, s);
        scale_sig(mem_hp_interp, INTERP_3_1_MEM_LEN, s);

        interpolate_3_over_1_allpass(
            &hf_syn,
            L_SUBFR16K,
            &mut upsampled_hf_syn,
            mem_hp_interp,
            &ALLPASS_POLES_3_OV_2,
        );

        scale_sig(&mut upsampled_hf_syn, L_SUBFR48K, add(-s, -1));
        scale_sig(mem_hp_interp, INTERP_3_1_MEM_LEN, -s);
        scale_sig(&mut hf_syn, L_SUBFR16K, -s);
    } else if sub(output_subfr, L_SUBFR32K) == 0 {
        // 32 kHz sampled output
        let s = sub(
            find_max_norm16(&hf_syn, L_SUBFR16K)
                .min(find_max_norm16(mem_hp_interp, 2 * ALLPASSSECTIONS_STEEP)),
            2,
        )
        .max(0);
        scale_sig(&mut hf_syn, L_SUBFR16K, s);
        scale_sig(mem_hp_interp, 2 * ALLPASSSECTIONS_STEEP, s);

        interpolate_allpass_steep(&hf_syn, mem_hp_interp, L_SUBFR16K, &mut upsampled_hf_syn);

        scale_sig(&mut upsampled_hf_syn, 2 * L_SUBFR16K, -s);
        scale_sig(mem_hp_interp, 2 * ALLPASSSECTIONS_STEEP, -s);
        scale_sig(&mut hf_syn, L_SUBFR16K, -s);
    } else {
        // 16 kHz sampled output
        copy(&hf_syn, &mut upsampled_hf_syn, L_SUBFR16K);
    }

    // Vr_add(synth_out, upsampled_HF_syn, synth_out, output_subfr): element-wise, so the output
    // is also the first input
    let out_len = (output_subfr.max(0) as usize).min(L_SUBFR48K as usize);
    let mut current = [0i16; L_SUBFR48K as usize];
    current[..out_len].copy_from_slice(&synth_out[..out_len]);
    vr_add(&current, &upsampled_hf_syn, synth_out, out_len as i16);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_clears_the_memories_and_advances_the_seed() {
        let mut seed2: i16 = 1;
        let mut mem_syn_hf = [3i16; M as usize];
        let mut delay_syn_hf = [3i16; DELAY_CLDFB_16K];
        let mut mem_hp_interp = [3i16; INTERP_3_1_MEM_LEN as usize];
        let (mut prev_r, mut fmerit_w_sm, mut frame_count, mut ne_min) = (9i16, 9i16, 9i16, 9i16);
        let (mut fmerit_m_sm, mut voice_fac, mut unvoicing, mut unvoicing_sm) =
            (9i16, 9i16, 9i16, 9i16);
        let (mut unvoicing_flag, mut voicing_flag, mut start_band_old) = (9i16, 9i16, 9i16);
        let mut opt_crit_old = 9i32;
        let mut state = HfSynthAmrWbState {
            mem_syn_hf: &mut mem_syn_hf,
            delay_syn_hf: &mut delay_syn_hf,
            prev_r: &mut prev_r,
            fmerit_w_sm: &mut fmerit_w_sm,
            mem_hp_interp: &mut mem_hp_interp,
            frame_count: &mut frame_count,
            ne_min: &mut ne_min,
            fmerit_m_sm: &mut fmerit_m_sm,
            voice_fac: &mut voice_fac,
            unvoicing: &mut unvoicing,
            unvoicing_sm: &mut unvoicing_sm,
            unvoicing_flag: &mut unvoicing_flag,
            voicing_flag: &mut voicing_flag,
            start_band_old: &mut start_band_old,
            opt_crit_old: &mut opt_crit_old,
        };
        hf_synth_amr_wb_reset(&mut seed2, &mut state);
        assert!(state.mem_syn_hf.iter().all(|&value| value == 0));
        assert!(state.delay_syn_hf.iter().all(|&value| value == 0));
        assert_eq!(*state.ne_min, -7680);
        assert_eq!(*state.unvoicing_sm, 32767);
        assert_eq!(*state.start_band_old, 160);
        assert_eq!(*state.opt_crit_old, 32768);
        assert_ne!(seed2, 1);
    }
}
