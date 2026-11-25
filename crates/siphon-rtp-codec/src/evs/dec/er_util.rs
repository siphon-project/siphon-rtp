//! Helpers of the MODE2 frame loss concealment (TS 26.442 `lib_dec/er_util.c`; TS 26.447 §5.4):
//! the background level tracker, the level of the LPC synthesis and de-emphasis, the bandwidth
//! adaptive low-pass and high-pass filters of the concealed excitation, and the high-pass
//! filtering of the noise.

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    L_FRAME_PLUS, M, PLC_MIN_CNG_LEV, PLC_MIN_STAT_BUFF_SIZE, UNVOICED_TRANSITION,
};
use crate::evs::com::basop_util::{
    basop_util_add_mant_exp, basop_util_divide1616_scale, dot_product12_offs, inv16, sqrt32,
};
use crate::evs::com::deemph::deemph;
use crate::evs::com::syn_filt::e_util_synthesis_in_place;
use crate::evs::com::tools::{dot_product, set16};
use crate::itu::basic_ops::{
    add, div_s, l_add, l_mult, l_shl, l_sub, mult_r, negate, norm_l, norm_s, round_word, shl, shr,
    sub,
};

mod plc_mode;

pub use plc_mode::get_plc_mode_decision;

/// `setnoiseLevelMemory`: store the minimum `f` and its exponent at the current position of the
/// circular buffer of [`minimum_statistics`].
fn set_noise_level_memory(
    f: i16,
    new_noise_estimate_e: i16,
    noise_level_memory_e: &mut [i16],
    noise_level_memory: &mut [i16],
    curr_level_index: i16,
) {
    noise_level_memory[curr_level_index as usize] = f;
    noise_level_memory_e[curr_level_index as usize] = new_noise_estimate_e;
}

/// `minimumStatistics`: track the minimum of the smoothed frame levels over the last
/// `PLC_MIN_STAT_BUFF_SIZE` frames as the background noise estimate (PLC fade-out). Levels are
/// mantissa/exponent pairs; `noise_level_memory` and `noise_level_memory_e` are the circular
/// buffer of minima, `noise_level_index` the position of the current minimum and
/// `curr_level_index` the write position.
pub fn minimum_statistics(
    noise_level_memory: &mut [i16],
    noise_level_index: &mut i16,
    curr_level_index: &mut i16,
    noise_estimate: &mut i16,
    last_frame_level: &mut i16,
    mut current_frame_level: i16,
    noise_level_memory_e: &mut [i16],
    noise_estimate_e: i16,
    new_noise_estimate_e: &mut i16,
    last_frame_level_e: &mut i16,
    mut current_frame_level_e: i16,
) {
    let mut a_opt: i16;
    let mut a_opt_e: i16 = 0;
    let mut f: i16 = 0;
    let mut tmp: i16 = 0;

    if sub(
        shl(current_frame_level, current_frame_level_e),
        PLC_MIN_CNG_LEV,
    ) < 0
    {
        current_frame_level = PLC_MIN_CNG_LEV;
        current_frame_level_e = 0;
    }

    // compute optimal factor aOpt for recursive smoothing of frame minima
    let _ = basop_util_add_mant_exp(
        *last_frame_level,
        *last_frame_level_e,
        negate(*noise_estimate),
        noise_estimate_e,
        &mut tmp,
    );
    if tmp >= 0 {
        // aOpt = *noiseEstimate / *lastFrameLevel;
        a_opt = basop_util_divide1616_scale(*noise_estimate, *last_frame_level, &mut a_opt_e);
        a_opt_e = add(a_opt_e, sub(noise_estimate_e, *last_frame_level_e));
    } else {
        // aOpt = *lastFrameLevel / *noiseEstimate;
        a_opt = basop_util_divide1616_scale(*last_frame_level, *noise_estimate, &mut a_opt_e);
        a_opt_e = add(a_opt_e, sub(*last_frame_level_e, noise_estimate_e));
    }
    a_opt = mult_r(a_opt, a_opt); // Q15
    a_opt_e = shl(a_opt_e, 1);
    if a_opt == 0 {
        a_opt_e = 0;
    }

    *last_frame_level = current_frame_level;
    *last_frame_level_e = current_frame_level_e;

    // recursively compute smoothed frame minima using optimal factor aOpt
    tmp = *curr_level_index;
    if tmp == 0 {
        tmp = PLC_MIN_STAT_BUFF_SIZE;
    }
    // f = (aOpt * noiseLevelMemory[tmp-1]) - (currentFrameLevel * (aOpt-1))
    let tmp32 = l_mult(a_opt, noise_level_memory[(tmp - 1) as usize]); // exponent aOpt_e + noiseLevelMemory_e[tmp - 1]
    let tmp_e = tmp;

    let mut tmp2 = basop_util_add_mant_exp(a_opt, a_opt_e, negate(16384), 1, &mut tmp);
    tmp = mult_r(tmp, current_frame_level); // exponent tmp2 + currentFrameLevel_e
    tmp2 = add(tmp2, current_frame_level_e);

    *new_noise_estimate_e = basop_util_add_mant_exp(
        round_word(tmp32),
        add(a_opt_e, noise_level_memory_e[(tmp_e - 1) as usize]),
        negate(tmp.max(-32767)), // to avoid negate(-32768)
        tmp2,
        &mut f,
    );

    // if current frame min is a new local min, set index to current index
    let mut p = *noise_level_index;
    let _ = basop_util_add_mant_exp(
        noise_level_memory[p as usize],
        noise_level_memory_e[p as usize],
        negate(f),
        *new_noise_estimate_e,
        &mut tmp,
    );
    if tmp >= 0 {
        set_noise_level_memory(
            f,
            *new_noise_estimate_e,
            noise_level_memory_e,
            noise_level_memory,
            *curr_level_index,
        );
        p = *curr_level_index;
    } else {
        set_noise_level_memory(
            f,
            *new_noise_estimate_e,
            noise_level_memory_e,
            noise_level_memory,
            *curr_level_index,
        );

        // current min is not a new min, so check if min must be re-searched
        if sub(p, *curr_level_index) != 0 {
            f = noise_level_memory[p as usize]; // min is still in memory, so return it
            *new_noise_estimate_e = noise_level_memory_e[p as usize];
        } else {
            // p == currLevelIndex; min was removed from memory, re-search min
            for i in 0..PLC_MIN_STAT_BUFF_SIZE {
                let _ = basop_util_add_mant_exp(
                    noise_level_memory[p as usize],
                    noise_level_memory_e[p as usize],
                    negate(noise_level_memory[i as usize]),
                    noise_level_memory_e[i as usize],
                    &mut tmp,
                );
                if tmp > 0 {
                    p = i;
                }
            }
            f = noise_level_memory[p as usize];
            *new_noise_estimate_e = noise_level_memory_e[p as usize];
        }
    }

    // update local-minimum-value index and current circular-buffer index
    *noise_level_index = p;
    *curr_level_index = add(*curr_level_index, 1);
    if sub(*curr_level_index, PLC_MIN_STAT_BUFF_SIZE) == 0 {
        *curr_level_index = 0;
    }

    *noise_estimate = f;
}

/// `getLevelSynDeemph`: the level (mantissa returned in Q15, exponent in `exp`) of the impulse
/// response of the LPC synthesis followed by the de-emphasis, averaged over `num_loops` sets of
/// LPC coefficients of `A` (`M + 1` each). `h1_init[0]` is the impulse amplitude (Q15) and is
/// rescaled in place.
pub fn get_level_syn_deemph(
    h1_init: &mut [i16],
    a: &[i16],
    lpcorder: i16,
    len_lpc_exc: i16,
    preemph_fac: i16,
    num_loops: i16,
    exp: &mut i16,
) -> i16 {
    let mut level_syn_deemph: i32 = 0;
    let mut h1 = [0i16; (L_FRAME_PLUS / 4) as usize];
    let mut mem = [0i16; M as usize];
    let mut tmp: i16 = 0;
    let mut q_h1: i16 = 9; // synthesis scaling

    // calculate headroom for dotproduct
    let hr16 = sub(15, norm_s(len_lpc_exc));

    // compensate synthesis scaling with headroom as much as possible to retain precision
    q_h1 = sub(q_h1, hr16).max(0);

    // factor to be multiplied in order to calculate dotproduct with headroom
    let mut tmp16 = shr(16384, sub(hr16, 1));

    h1_init[0] = mult_r(h1_init[0], tmp16);

    let mut a_at = 0usize;
    for _loop in 0..num_loops.max(0) {
        set16(&mut h1, 0, len_lpc_exc);
        set16(&mut mem, 0, lpcorder);

        h1[0] = h1_init[0];
        // h1 will be scaled down, Q_h1
        e_util_synthesis_in_place(
            q_h1,
            &a[a_at..],
            &mut h1,
            len_lpc_exc,
            &mut mem,
            0,
            lpcorder,
        );
        deemph(&mut h1, preemph_fac, len_lpc_exc, &mut tmp);
        a_at += (M + 1) as usize;

        // gain introduced by synthesis+deemphasis
        let mut s16: i16 = 0;
        let level_syn_deemph_sub_raw = dot_product12_offs(&h1, &h1, len_lpc_exc, Some(&mut s16), 0);
        s16 = sub(shl(add(q_h1, hr16), 1), sub(30, s16));

        let level_syn_deemph_sub = sqrt32(level_syn_deemph_sub_raw, &mut s16); // Q31

        // mean of the above across all subframes
        tmp16 = 32767; // 1.0f Q15
        if sub(num_loops, 1) > 0 {
            tmp16 = div_s(1, num_loops);
        }

        level_syn_deemph = l_add(
            level_syn_deemph,
            l_shl(mpy_32_16_1(level_syn_deemph_sub, tmp16), sub(s16, 10)),
        ); // 10Q21
    }
    let s16 = norm_l(level_syn_deemph);
    level_syn_deemph = l_shl(level_syn_deemph, s16);
    *exp = sub(10, s16); // exponent that transforms the return value to Q15

    round_word(level_syn_deemph)
}

/// `genPlcFiltBWAdap`: the three coefficients of the symmetric low-pass (`type_` 0) or its
/// damped, adaptive variant (`type_` 1, from `alpha`, Q15) applied to the concealed excitation,
/// for 16 kHz or any other core sampling rate.
pub fn gen_plc_filt_bw_adap(sr_core: i32, lp_filt_adapt: &mut [i16], type_: i16, alpha: i16) {
    let wideband = l_sub(sr_core, 16000) == 0;
    if type_ == 0 {
        let (a, b) = if wideband {
            (7282, 18204) // 0.4000f/(2.f*0.4000f+1.f), 1.f/(2.f*0.4000f+1.f) Q15
        } else {
            (5899, 20970) // 0.2813f/(2.f*0.2813f+1.f), 1.f/(2.f*0.2813f+1.f) Q15
        };
        lp_filt_adapt[0] = a;
        lp_filt_adapt[1] = b;
        lp_filt_adapt[2] = a;
    } else {
        let coefficient = if wideband { 13107 } else { 9218 }; // 0.4000f / 0.2813f Q15
        let mut a = mult_r(coefficient, alpha);
        let mut exp: i16 = 0;
        let mut b = inv16(add(a, 16384 /* 0.5f Q15 */), &mut exp);
        b = shr(b, sub(1, exp));
        a = negate(mult_r(a, b));
        lp_filt_adapt[0] = a;
        lp_filt_adapt[1] = b;
        lp_filt_adapt[2] = a;
    }
}

/// `highPassFiltering`: for a voiced last good frame, high-pass filter the unvoiced excitation
/// `exc2[0..L_buffer]` in place with the `l_fir_fer` taps `hp_filt` (reading `l_fir_fer - 1`
/// samples beyond `L_buffer`).
pub fn high_pass_filtering(
    last_good: i16,
    l_buffer: i16,
    exc2: &mut [i16],
    hp_filt: &[i16],
    l_fir_fer: i16,
) {
    if sub(last_good, UNVOICED_TRANSITION) > 0 {
        for i in 0..l_buffer.max(0) as usize {
            exc2[i] = round_word(l_sub(dot_product(&exc2[i..], hp_filt, l_fir_fer), 1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plc_filter_type0_is_symmetric_and_sums_to_unity() {
        let mut taps = [0i16; 3];
        gen_plc_filt_bw_adap(16000, &mut taps, 0, 0);
        assert_eq!(taps, [7282, 18204, 7282]);
        assert!(i32::from(taps[1]) + 2 * i32::from(taps[0]) >= 32766);
        gen_plc_filt_bw_adap(12800, &mut taps, 0, 0);
        assert_eq!(taps, [5899, 20970, 5899]);
    }

    #[test]
    fn plc_filter_type1_without_damping_is_a_pass_through() {
        let mut taps = [1i16; 3];
        gen_plc_filt_bw_adap(16000, &mut taps, 1, 0);
        assert_eq!(taps[0], 0);
        assert_eq!(taps[0], taps[2]);
        assert!(taps[1] > 32000);
    }

    #[test]
    fn high_pass_filtering_leaves_an_unvoiced_frame_alone() {
        let mut exc = [5i16; 20];
        let taps = [1000i16; 3];
        high_pass_filtering(UNVOICED_TRANSITION, 10, &mut exc, &taps, 3);
        assert_eq!(exc, [5i16; 20]);
    }

    #[test]
    fn high_pass_filtering_runs_in_place_over_a_voiced_frame() {
        let mut exc = [1000i16; 12];
        let taps = [16384i16, 0, 0];
        high_pass_filtering(UNVOICED_TRANSITION + 1, 8, &mut exc, &taps, 3);
        assert_eq!(&exc[..8], &[500i16; 8]);
        assert_eq!(&exc[8..], &[1000i16; 4]);
    }

    #[test]
    fn minimum_statistics_follows_a_decaying_level() {
        let mut memory = [0i16; PLC_MIN_STAT_BUFF_SIZE as usize];
        let mut memory_e = [0i16; PLC_MIN_STAT_BUFF_SIZE as usize];
        memory.fill(16384);
        let (mut noise_index, mut curr_index) = (0i16, 1i16);
        let (mut estimate, mut last_level, mut last_e) = (16384i16, 16384i16, 2i16);
        let mut new_e = 0i16;
        minimum_statistics(
            &mut memory,
            &mut noise_index,
            &mut curr_index,
            &mut estimate,
            &mut last_level,
            8192,
            &mut memory_e,
            2,
            &mut new_e,
            &mut last_e,
            2,
        );
        assert_eq!(curr_index, 2);
        assert_eq!(last_level, 8192);
        assert!(estimate > 0);
    }
}
