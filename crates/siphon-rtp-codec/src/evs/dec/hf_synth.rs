//! 6-7 kHz high-band synthesis of the 12.8 kHz ACELP core (TS 26.442 `lib_dec/hf_synth_fx.c`;
//! TS 26.445 §6.1.4.2).
//!
//! Ported: the 12.8 kHz core's 6-7 kHz noise synthesis (`hf_synth_fx`) with its filters and
//! initialisations, and the AMR-WB IO high band (`hf_synth_amr_wb_fx` with `envelope_fx`,
//! `AdaptiveStartBand_fx`; in the submodules `amr_wb` and `amr_wb_envelope`).

mod amr_wb;
mod amr_wb_envelope;

pub use amr_wb::{hf_synth_amr_wb, hf_synth_amr_wb_reset, HfSynthAmrWbState};
pub use amr_wb_envelope::{adaptive_start_band, envelope};

use crate::evs::cnst::{
    ALLPASSSECTIONS_STEEP, DELAY_CLDFB_NS, FRAME_NO_DATA, L_FILT16K, L_FIR, L_FRAME, L_FRAME16K,
    L_FRAME48K, L_SUBFR, L_SUBFR16K, M, M16K, NB_SUBFR, SID_2K40,
};
use crate::evs::com::math_op::{dot_product12, isqrt_lc};
use crate::evs::com::modif_fs::{interpolate_3_over_1_allpass, interpolate_allpass_steep};
use crate::evs::com::syn_filt::syn_filt_s;
use crate::evs::com::tools::{
    copy, copy_scale_sig, find_max_norm16, hp400_12k8, random, random_fill, scale_sig, set16,
    vr_add,
};
use crate::evs::com::weight_a::weight_a_lc;
use crate::evs::rom::{ALLPASS_POLES_3_OV_2, FIR_6K_7K_FX, GAMMA_19661_TBL_FX};
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_deposit_h, l_mac, l_mult, l_shl, l_sub, mult, mult_r, norm_l,
    round_word, shl, shr, sub,
};

/// `L_SUBFR48k`: one subframe at 48 kHz.
const L_SUBFR48K: i16 = 240;
/// `L_SUBFR32k`: one subframe at 32 kHz.
const L_SUBFR32K: i16 = 160;

/// `NS2SA(16000, DELAY_CLDFB_NS)`: the CLDFB delay in samples at 16 kHz.
const DELAY_CLDFB_16K: usize = (16000 / 100 * (DELAY_CLDFB_NS / 100) / 100_000) as usize;
/// `INTERP_3_1_MEM_LEN`.
const INTERP_3_1_MEM_LEN: i16 = crate::evs::cnst::INTERP_3_1_MEM_LEN;

/// `hf_synth_init_fx`: clear the 400 Hz high-pass memory (6) and the 6-7 kHz band-pass memory
/// (`2·L_FILT16k`).
pub fn hf_synth_init(mem_hp400: &mut [i16], mem_hf: &mut [i16]) {
    mem_hp400[..6].fill(0);
    mem_hf[..2 * L_FILT16K as usize].fill(0);
}

/// `hf_synth_reset_fx`: advance the noise seed by one 16 kHz frame and clear the HF synthesis
/// memories (needed in switching scenarios).
pub fn hf_synth_reset(
    seed2: &mut i16,
    mem_hf: &mut [i16],
    mem_syn_hf: &mut [i16],
    mem_hp400: &mut [i16],
    mem_hp_interp: &mut [i16],
    delay_syn_hf: &mut [i16],
) {
    for _ in 0..L_FRAME16K {
        let _ = random(seed2);
    }
    set16(mem_hf, 0, 2 * L_FILT16K);
    set16(mem_syn_hf, 0, M);
    set16(mem_hp400, 0, 4);
    set16(delay_syn_hf, 0, DELAY_CLDFB_16K as i16);
    set16(mem_hp_interp, 0, INTERP_3_1_MEM_LEN);
}

/// `hf_synth_fx`: add the 6-7 kHz noise band to the output-rate synthesis `synth16k` for each of
/// the four 12.8 kHz subframes of `exc` / `synth` (`aq` holds the four quantised LP filters).
/// `synth` is high-passed in place, as in the reference.
pub fn hf_synth(
    core_brate: i32,
    output_frame: i16,
    aq: &[i16],
    exc: &[i16],
    synth: &mut [i16],
    synth16k: &mut [i16],
    seed2: &mut i16,
    mem_hp400: &mut [i16],
    mem_syn_hf: &mut [i16],
    mem_hf: &mut [i16],
    q_exc: i16,
    q_syn2: i16,
    delay_syn_hf: &mut [i16],
    mem_exp1: &mut i16,
    mem_hp_interp: &mut [i16],
    extl: i16,
    cng_mode: i16,
) {
    // plain C division
    let output_subfr = output_frame / NB_SUBFR;
    let mut p_aq = 0usize;
    for i_subfr in (0..L_FRAME as usize).step_by(L_SUBFR as usize) {
        let out_at = i_subfr * output_subfr.max(0) as usize / L_SUBFR as usize;
        hf_synthesis(
            core_brate,
            output_subfr,
            &aq[p_aq..],
            &exc[i_subfr..],
            q_exc,
            &mut synth[i_subfr..],
            &mut synth16k[out_at..],
            seed2,
            mem_hp400,
            mem_syn_hf,
            mem_hf,
            q_syn2,
            delay_syn_hf,
            mem_exp1,
            mem_hp_interp,
            extl,
            cng_mode,
        );
        p_aq += M as usize + 1;
    }
}

/// `hf_synthesis_fx`: one subframe of HF noise between 6 and 7 kHz, scaled to the energy of the
/// 12.8 kHz excitation and by the synthesis tilt (tilt > 0.8: -14 dB, voiced; 0.5: -6 dB;
/// < 0: 0 dB, noise), filtered through the weighted LP filter, delayed to match the CLDFB path,
/// interpolated to the output rate and added to `synth16k[0..output_subfr]`.
pub fn hf_synthesis(
    core_brate: i32,
    output_subfr: i16,
    aq: &[i16],
    exc: &[i16],
    q_exc: i16,
    synth: &mut [i16],
    synth16k: &mut [i16],
    seed2: &mut i16,
    mem_hp400: &mut [i16],
    mem_syn_hf: &mut [i16],
    mem_hf: &mut [i16],
    q_syn: i16,
    delay_syn_hf: &mut [i16],
    mem_exp1: &mut i16,
    mem_hp_interp: &mut [i16],
    _extl: i16,
    _cng_mode: i16,
) {
    const SUB16: usize = L_SUBFR16K as usize;
    const MAX_OUT: usize = L_FRAME48K as usize / NB_SUBFR as usize;
    let mut hf_syn = [0i16; SUB16];
    let mut upsampled_hf_syn = [0i16; MAX_OUT];
    let mut hf_exc = [0i16; SUB16];
    let mut temp_buffer = [0i16; DELAY_CLDFB_16K - L_FILT16K as usize];
    let mut ap = [0i16; M16K as usize + 1];
    let mut exp1: i16 = 0;
    let mut exp2: i16 = 0;

    // generate white noise vector
    random_fill(seed2, L_SUBFR16K, &mut hf_exc, 3); // HF_exc in Q-3

    // energy scaling factor so that white noise would have the same energy as exc12k8
    let mut ener = extract_h(dot_product12(exc, exc, L_SUBFR, &mut exp2));
    exp2 = sub(exp2, add(q_exc, q_exc));

    let mut l_tmp = dot_product12(&hf_exc, &hf_exc, L_SUBFR16K, &mut exp1);
    let mut tmp = round_word(l_tmp);
    // tmp = sqrt(ener/tmp); scale is -1 if tmp > ener
    let mut scale = shr(sub(ener, tmp), 15);
    tmp = shl(tmp, scale);
    exp1 = sub(exp1, scale);
    tmp = div_s(tmp, ener);
    exp1 = sub(exp1, exp2);
    l_tmp = l_deposit_h(tmp);
    l_tmp = isqrt_lc(l_tmp, &mut exp1);
    scale = round_word(l_tmp); // Q18 when Q_exc=-1, HF_exc in Q-3

    exp2 = sub(*mem_exp1, exp1);
    *mem_exp1 = exp1;

    // energy scaling factor to respect tilt of synth12k8 (tilt: 1=voiced, -1=unvoiced)
    hp400_12k8(synth, L_SUBFR, mem_hp400); // synth: Q_syn -> Q_syn-3

    let sub_len = L_SUBFR as usize;
    l_tmp = l_mac(1, synth[0], synth[0]);
    for &value in &synth[1..sub_len] {
        l_tmp = l_mac(l_tmp, value, value);
    }
    tmp = norm_l(l_tmp);
    ener = extract_h(l_shl(l_tmp, tmp)); // ener = r[0]

    l_tmp = l_mac(1, synth[1], synth[0]);
    for i in 2..sub_len {
        l_tmp = l_mac(l_tmp, synth[i], synth[i - 1]);
    }
    // same normalisation as r[0]: r[1] can saturate, which the thresholds below absorb
    tmp = extract_h(l_shl(l_tmp, tmp)); // tmp = r[1]

    tmp = tmp.max(0);
    if tmp > 0 {
        tmp = div_s(tmp, ener);
    }

    // modify energy of white noise according to synthesis tilt: tmp = 1.0 - fac
    tmp = add(1, sub(32767, tmp));
    if l_sub(core_brate, i32::from(FRAME_NO_DATA)) == 0
        || l_sub(core_brate, i32::from(SID_2K40)) == 0
    {
        // emphasize HF noise in CNG
        tmp = add(tmp, tmp);
    }
    tmp = tmp.max(3277); // 0.1 in Q15
    tmp = mult_r(scale, tmp);

    // modify HF excitation according to both scaling factors; high pass filtering (0.94 ms delay)
    filt_6k_7k_scale(&mut hf_exc, L_SUBFR16K, mem_hf, tmp, exp2); // HF_exc in Q0

    // synthesis of noise: 4.8kHz..5.6kHz --> 6kHz..7kHz
    weight_a_lc(aq, &mut ap, &GAMMA_19661_TBL_FX, M); // Ap in Q14
    syn_filt_s(0, &ap, M, &hf_exc, &mut hf_syn, L_SUBFR16K, mem_syn_hf, 1);
    scale_sig(&mut hf_syn, L_SUBFR16K, add(q_syn, exp1)); // to (Q_syn+exp1)

    // delay by 5 samples @16kHz to compensate CLDFB resampling delay (20 samples) and HP
    // filtering delay (roughly 15 samples)
    let delay = DELAY_CLDFB_16K - 15;
    temp_buffer[..delay].copy_from_slice(&hf_syn[SUB16 - delay..]);
    hf_syn.copy_within(0..SUB16 - delay, delay);
    hf_syn[..delay].copy_from_slice(&delay_syn_hf[..delay]);
    delay_syn_hf[..delay].copy_from_slice(&temp_buffer[..delay]);

    // interpolate the HF synthesis
    let mem_len = INTERP_3_1_MEM_LEN as usize;
    if sub(output_subfr, L_SUBFR48K) == 0 {
        // 48kHz sampled output
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
        scale_sig(&mut upsampled_hf_syn, 3 * L_SUBFR16K, -s);
        scale_sig(mem_hp_interp, INTERP_3_1_MEM_LEN, -s);
        scale_sig(&mut hf_syn, L_SUBFR16K, -s);
        scale_sig(&mut upsampled_hf_syn, L_SUBFR48K, -1);
    } else if sub(output_subfr, L_SUBFR32K) == 0 {
        // 32kHz sampled output
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
        // 16kHz sampled output
        copy(&hf_syn, &mut upsampled_hf_syn, L_SUBFR16K);
    }

    // Vr_add(synth16k, upsampled_HF_syn, synth16k, ...): element-wise, so in place is exact
    let out_len = (output_subfr.max(0) as usize).min(MAX_OUT);
    let mut current = [0i16; MAX_OUT];
    current[..out_len].copy_from_slice(&synth16k[..out_len]);
    vr_add(&current, &upsampled_hf_syn, synth16k, out_len as i16);
}

/// `filt_6k_7k_scale_fx`: 15th order band pass 6 kHz to 7 kHz FIR filter (gain 4) in place over
/// `signal[0..lg]`, the input first multiplied by `fact` (Q15) and the memory `mem[0..30]`
/// rescaled by `exp`.
///
/// frequency: 4kHz 5kHz 5.5kHz 6kHz 6.5kHz 7kHz 7.5kHz 8kHz,
/// dB loss: -60dB -45dB -13dB -3dB 0dB -3dB -13dB -45dB.
pub fn filt_6k_7k_scale(signal: &mut [i16], lg: i16, mem: &mut [i16], fact: i16, exp: i16) {
    const FIR_MEM: usize = L_FIR as usize - 1;
    let mut x = [0i16; L_FRAME48K as usize / NB_SUBFR as usize + FIR_MEM];
    let lg = (lg.max(0) as usize).min(x.len() - FIR_MEM);

    copy_scale_sig(mem, &mut x, L_FIR - 1, exp);
    for i in 0..lg {
        x[i + FIR_MEM] = shr(mult(signal[i], fact), 2); // gain of filter = 4
    }
    for i in 0..lg {
        let mut l_tmp = l_mult(x[i], FIR_6K_7K_FX[0]);
        for j in 1..L_FIR as usize {
            // taps 7 and 23 are zero and skipped by the reference; a zero L_mac changes nothing
            if j == 7 || j == 23 {
                continue;
            }
            l_tmp = l_mac(l_tmp, x[i + j], FIR_6K_7K_FX[j]);
        }
        signal[i] = round_word(l_tmp);
    }
    copy(&x[lg..], mem, L_FIR - 1);
}

/// `hf_synth_amr_wb_init_fx`: initial values of the AMR-WB IO high-band memories.
pub fn hf_synth_amr_wb_init(
    prev_r: &mut i16,
    fmerit_w_sm: &mut i16,
    mem_syn_hf: &mut [i16],
    frame_count: &mut i16,
    ne_min: &mut i16,
    fmerit_m_sm: &mut i16,
    voice_fac: &mut i16,
    unvoicing: &mut i16,
    unvoicing_sm: &mut i16,
    unvoicing_flag: &mut i16,
    voicing_flag: &mut i16,
    start_band_old: &mut i16,
    opt_crit_old: &mut i32,
) {
    *prev_r = 0;
    set16(mem_syn_hf, 0, M);
    *fmerit_w_sm = 0;
    *frame_count = 0;
    *ne_min = -7680; // Q8
    *fmerit_m_sm = 0;
    *voice_fac = 0;
    *unvoicing = 0;
    *unvoicing_sm = 32767; // Q15
    *unvoicing_flag = 0;
    *voicing_flag = 0;
    *start_band_old = 160;
    *opt_crit_old = 32768; // Q15
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cldfb_delay_is_twenty_samples_at_16k() {
        assert_eq!(DELAY_CLDFB_16K, 20);
    }

    #[test]
    fn init_clears_both_memories() {
        let (mut hp400, mut hf) = ([3i16; 6], [4i16; 30]);
        hf_synth_init(&mut hp400, &mut hf);
        assert_eq!((hp400, hf), ([0; 6], [0; 30]));
    }

    #[test]
    fn amr_wb_init_sets_the_reference_start_values() {
        let mut v = [9i16; 11];
        let mut syn = [5i16; 16];
        let mut crit = 0i32;
        let [a, b, c, d, e, f, g, h, i, j, k] = &mut v;
        hf_synth_amr_wb_init(a, b, &mut syn, c, d, e, f, g, h, i, j, k, &mut crit);
        assert_eq!(v, [0, 0, 0, -7680, 0, 0, 0, 32767, 0, 0, 160]);
        assert_eq!((syn, crit), ([0; 16], 32768));
    }
}
