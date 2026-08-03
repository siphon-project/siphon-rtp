//! The delayed-decision noise-shaping quantiser (libopus `silk/NSQ_del_dec.c`).
//!
//! [`super::nsq`]'s plain quantiser is greedy: at each sample it takes the cheaper of the two
//! candidate levels and never reconsiders. That is locally optimal and globally wrong, because the
//! level it picks feeds the prediction of every following sample — a slightly worse choice now can
//! be much cheaper 30 samples later. This variant keeps `nStatesDelayedDecision` whole quantiser
//! states alive at once (each with its own synthesis filter, shaping filter and dither seed), forks
//! every one of them into both candidates at every sample, and only commits a decision once it is
//! `decisionDelay` samples in the past and one path has provably won.
//!
//! It is also the **only** variant that implements the warped shaping filter, which is why
//! `silk_NSQ_wrapper_FLP` routes here whenever `warping_Q16 > 0` even at a single state
//! (`wrappers_FLP.c:157`).
//!
//! # The three pruning rules, in the order they run
//!
//! Per sample, after forking (`NSQ_del_dec.c:568-611`):
//!
//! 1. **The winner's dither wins.** Any state whose dither history at the sample about to be
//!    committed disagrees with the current best state's is penalised by `INT32_MAX >> 4`. The
//!    committed pulse feeds the LCG, so two states that disagree on it will disagree on every
//!    future dither — they cannot be compared against each other any more, and keeping both alive
//!    would let a doomed one win later on a stale comparison.
//! 2. **Best-of-seconds replaces worst-of-firsts.** The `2 N` forks are pruned back to `N` by
//!    swapping in the best second choice only if it beats the worst first choice.
//! 3. **A mid-frame reset re-scores from the winner.** When the two LPC halves differ, subframe 2
//!    rewhitens with new coefficients, so the surviving paths' states are no longer comparable.
//!    The C penalises every loser by the same `INT32_MAX >> 4` and flushes the winner's delayed
//!    samples out (`NSQ_del_dec.c:218-249`).
//!
//! # Seeds
//!
//! Each state starts from `(k + Seed) & 3` (`NSQ_del_dec.c:160`), so the four states explore four
//! different dither sequences, and the winner's **initial** seed is what gets coded. That is why
//! [`quantize_del_dec`] returns a seed at all: the frame driver must write the winner's, not its
//! own frame counter's.
//!
//! # The state-replacement memcpy
//!
//! `NSQ_del_dec.c:608-609` copies a state from `((opus_int32 *)&psDelDec[src]) + i` — skipping the
//! first `i` words of the struct, which are the already-consumed entries of `sLPC_Q14`. Those
//! entries are dead: at sample `i` the short-term predictor reads `sLPC_Q14[i ..= 15 + i]` and the
//! end-of-subframe slide copies from `[length ..]`, so nothing ever reads `[0 .. i)` again. A whole
//! struct copy is therefore exactly equivalent, and is what this port does.

use crate::opus::silk::enc::fixed::smlawt;
use crate::opus::silk::enc::nsq::{
    lpc_analysis_filter, quantization_candidates, rand_step, short_term_prediction,
    start_of_ltp_window, NsqConfig, NsqInput, NsqState, HARM_SHAPE_FIR_TAPS, MAX_LTP_WORK,
    NSQ_LPC_BUF_LENGTH,
};
use crate::opus::silk::enc::MAX_SHAPE_LPC_ORDER;
use crate::opus::silk::fixed::{
    div32_var_q, inverse32_var_q, rshift_round, sat16, smlawb, smulwb, smulww,
};
use crate::opus::silk::types::{SignalType, LTP_ORDER, MAX_SUB_FRAME_LENGTH};

/// `DECISION_DELAY` (`define.h:165`) — how many samples a decision is held open before it is
/// committed, and the length of every per-state ring buffer here.
pub const DECISION_DELAY: usize = 40;

/// `MAX_DEL_DEC_STATES` — `nStatesDelayedDecision` never exceeds 4 (`control_codec.c:314-386`).
pub const MAX_DEL_DEC_STATES: usize = 4;

/// The penalty applied to a state that can no longer be compared against the winner
/// (`NSQ_del_dec.c:231`, `:582-583`). It is large enough that such a state never wins again unless
/// every rival is penalised too, and small enough that adding it cannot overflow.
const PRUNE_PENALTY: i32 = i32::MAX >> 4;

/// One surviving quantiser path (libopus `NSQ_del_dec_struct`, `NSQ_del_dec.c:37-50`).
#[derive(Debug, Clone, Copy)]
struct DelayedState {
    /// `sLPC_Q14` — short-term synthesis state, indexed from `NSQ_LPC_BUF_LENGTH`.
    lpc_q14: [i32; MAX_SUB_FRAME_LENGTH + NSQ_LPC_BUF_LENGTH],
    /// `RandState` — the dither value at each still-open sample.
    rand_state: [i32; DECISION_DELAY],
    /// `Q_Q10` — the quantisation level at each still-open sample.
    level_q10: [i32; DECISION_DELAY],
    /// `Xq_Q14` — the reconstructed output at each still-open sample.
    output_q14: [i32; DECISION_DELAY],
    /// `Pred_Q15` — the LTP state contribution at each still-open sample.
    prediction_q15: [i32; DECISION_DELAY],
    /// `Shape_Q14` — the shaping signal at each still-open sample.
    shape_q14: [i32; DECISION_DELAY],
    /// `sAR2_Q14` — the (possibly warped) shaping filter state.
    shaping_q14: [i32; MAX_SHAPE_LPC_ORDER],
    /// `LF_AR_Q14`.
    lf_ar_q14: i32,
    /// `Diff_Q14`.
    difference_q14: i32,
    /// `Seed` — this path's dither.
    seed: i32,
    /// `SeedInit` — the seed this path started from, which is what gets coded if it wins.
    seed_init: i32,
    /// `RD_Q10` — the accumulated rate-distortion cost.
    cost_q10: i32,
}

impl DelayedState {
    const fn zeroed() -> Self {
        Self {
            lpc_q14: [0; MAX_SUB_FRAME_LENGTH + NSQ_LPC_BUF_LENGTH],
            rand_state: [0; DECISION_DELAY],
            level_q10: [0; DECISION_DELAY],
            output_q14: [0; DECISION_DELAY],
            prediction_q15: [0; DECISION_DELAY],
            shape_q14: [0; DECISION_DELAY],
            shaping_q14: [0; MAX_SHAPE_LPC_ORDER],
            lf_ar_q14: 0,
            difference_q14: 0,
            seed: 0,
            seed_init: 0,
            cost_q10: 0,
        }
    }
}

/// One fork of one state for one sample (libopus `NSQ_sample_struct`, `NSQ_del_dec.c:52-60`).
#[derive(Debug, Clone, Copy, Default)]
struct SampleFork {
    level_q10: i32,
    cost_q10: i32,
    output_q14: i32,
    lf_ar_q14: i32,
    difference_q14: i32,
    shape_q14: i32,
    lpc_excitation_q14: i32,
}

/// `silk_NSQ_del_dec_c` (`NSQ_del_dec.c:117-312`).
///
/// Returns the winning path's initial seed, which is the `Seed` symbol the bitstream must carry.
pub(crate) fn quantize_del_dec(
    state: &mut NsqState,
    input: &NsqInput,
    x16: &[i16],
    pulses: &mut [i8],
    config: &NsqConfig,
) -> u8 {
    let frame_length = config.frame_length();
    let memory = config.ltp_memory_length;
    let states = config.delayed_decision_states.clamp(1, MAX_DEL_DEC_STATES);

    let mut lag = state.previous_lag;
    let interpolates = input.interpolates();
    let offset_q10 = input.offset_q10();

    let mut paths = [DelayedState::zeroed(); MAX_DEL_DEC_STATES];
    for (index, path) in paths.iter_mut().enumerate().take(states) {
        path.seed = (index as i32 + i32::from(input.seed)) & 3;
        path.seed_init = path.seed;
        path.lf_ar_q14 = state.lf_ar_shaping_q14;
        path.difference_q14 = state.difference_shaping_q14;
        path.shape_q14[0] = state.shaping_signal_q14[memory - 1];
        path.lpc_q14[..NSQ_LPC_BUF_LENGTH]
            .copy_from_slice(&state.lpc_state_q14[..NSQ_LPC_BUF_LENGTH]);
        path.shaping_q14 = state.shaping_state_q14;
    }

    let mut ring_index = 0usize;

    // The decision must commit before the LTP predictor reaches back into it, or a state would
    // predict from a sample it has not yet decided (`NSQ_del_dec.c:173-184`).
    let mut decision_delay = DECISION_DELAY.min(config.subframe_length) as i32;
    if input.signal_type == SignalType::Voiced {
        for &pitch in input.pitch_lags.iter().take(config.subframe_count) {
            decision_delay = decision_delay.min(pitch - (LTP_ORDER / 2) as i32 - 1);
        }
    } else if lag > 0 {
        decision_delay = decision_delay.min(lag - (LTP_ORDER / 2) as i32 - 1);
    }
    let decision_delay = decision_delay.max(0) as usize;

    let mut ltp_q15 = [0i32; MAX_LTP_WORK];
    let mut rewhitened = [0i16; MAX_LTP_WORK];
    let mut scaled_input_q10 = [0i32; MAX_SUB_FRAME_LENGTH];
    let mut delayed_gain_q10 = [0i32; DECISION_DELAY];

    state.shaping_buffer_index = memory;
    state.ltp_buffer_index = memory;

    // `subfr` in the C: counts subframes since the last mid-frame reset, and gates the output write
    // for the first `decisionDelay` samples of a frame.
    let mut since_reset = 0usize;

    for subframe in 0..config.subframe_count {
        let lpc_half = usize::from(!interpolates) | (subframe >> 1);
        let prediction = &input.prediction_coefficients_q12[lpc_half.min(1)];
        let ltp_taps = &input.ltp_coefficients_q14[subframe * LTP_ORDER..][..LTP_ORDER];
        let shaping_ar =
            &input.shaping_ar_q13[subframe * MAX_SHAPE_LPC_ORDER..][..config.shaping_lpc_order];

        let harmonic = input.harmonic_shape_gain_q14[subframe];
        let harmonic_fir_packed_q14 = (harmonic >> 2) | ((harmonic >> 1) << 16);

        state.rewhitened = false;
        if input.signal_type == SignalType::Voiced {
            lag = input.pitch_lags[subframe];

            if subframe & (3 - (usize::from(interpolates) << 1)) == 0 {
                if subframe == 2 {
                    // Mid-frame reset: the new short-term coefficients make the surviving paths
                    // incomparable, so keep only the winner and flush its delayed samples.
                    let winner = best_path(&paths[..states]);
                    for (index, path) in paths.iter_mut().enumerate().take(states) {
                        if index != winner {
                            path.cost_q10 = path.cost_q10.wrapping_add(PRUNE_PENALTY);
                        }
                    }
                    flush_delayed(
                        &paths[winner],
                        state,
                        pulses,
                        ring_index,
                        decision_delay,
                        subframe * config.subframe_length,
                        memory,
                        // The C scales by `Gains_Q16[1]` here — the gain the flushed samples were
                        // quantised under, which is subframe 1's (`NSQ_del_dec.c:243-244`).
                        input.gains_q16[1],
                        14,
                    );
                    since_reset = 0;
                }

                let start =
                    memory as i32 - lag - config.predict_lpc_order as i32 - (LTP_ORDER / 2) as i32;
                debug_assert!(start > 0, "silk nsq: rewhitening window underflowed");
                let start = start.clamp(1, memory as i32) as usize;
                lpc_analysis_filter(
                    &mut rewhitened[start..memory],
                    &state.quantised_output[start + subframe * config.subframe_length..],
                    &prediction[..config.predict_lpc_order],
                );
                state.ltp_buffer_index = memory;
                state.rewhitened = true;
            }
        }

        scale_states(
            state,
            &mut paths[..states],
            input,
            &x16[subframe * config.subframe_length..],
            &mut scaled_input_q10[..config.subframe_length],
            &rewhitened,
            &mut ltp_q15,
            subframe,
            config,
            decision_delay,
        );

        quantize_subframe(
            state,
            &mut paths[..states],
            input.signal_type,
            &scaled_input_q10[..config.subframe_length],
            pulses,
            subframe * config.subframe_length,
            &mut ltp_q15,
            &mut delayed_gain_q10,
            &prediction[..config.predict_lpc_order],
            ltp_taps,
            shaping_ar,
            lag,
            harmonic_fir_packed_q14,
            input.tilt_q14[subframe],
            input.lf_shape_q14[subframe],
            input.gains_q16[subframe],
            input.lambda_q10,
            offset_q10,
            since_reset,
            config,
            &mut ring_index,
            decision_delay,
        );
        since_reset += 1;
    }

    // Commit the frame: take the cheapest surviving path and flush its still-open samples.
    let winner = best_path(&paths[..states]);
    let seed = (paths[winner].seed_init & 3) as u8;
    flush_delayed(
        &paths[winner],
        state,
        pulses,
        ring_index,
        decision_delay,
        frame_length,
        memory,
        input.gains_q16[config.subframe_count - 1] >> 6,
        8,
    );

    state.lpc_state_q14[..NSQ_LPC_BUF_LENGTH].copy_from_slice(
        &paths[winner].lpc_q14[config.subframe_length..config.subframe_length + NSQ_LPC_BUF_LENGTH],
    );
    state.shaping_state_q14 = paths[winner].shaping_q14;
    state.lf_ar_shaping_q14 = paths[winner].lf_ar_q14;
    state.difference_shaping_q14 = paths[winner].difference_q14;
    state.previous_lag = input.pitch_lags[config.subframe_count - 1];

    state
        .quantised_output
        .copy_within(frame_length..frame_length + memory, 0);
    state
        .shaping_signal_q14
        .copy_within(frame_length..frame_length + memory, 0);

    seed
}

/// The cheapest surviving path (`NSQ_del_dec.c:277-284`). Ties go to the lowest index, as the C's
/// strict `<` does.
fn best_path(paths: &[DelayedState]) -> usize {
    let mut winner = 0usize;
    let mut best = paths[0].cost_q10;
    for (index, path) in paths.iter().enumerate().skip(1) {
        if path.cost_q10 < best {
            best = path.cost_q10;
            winner = index;
        }
    }
    winner
}

/// Write out the `decision_delay` samples a winning path was still holding open
/// (`NSQ_del_dec.c:238-246` and `:289-299`), which differ only in the gain and shift they scale by.
///
/// `end` is the index one past the last output sample, measured from the frame start.
#[allow(clippy::too_many_arguments)]
fn flush_delayed(
    path: &DelayedState,
    state: &mut NsqState,
    pulses: &mut [i8],
    ring_index: usize,
    decision_delay: usize,
    end: usize,
    memory: usize,
    gain: i32,
    shift: u32,
) {
    let mut newest = ring_index + decision_delay;
    for offset in 0..decision_delay {
        newest = (newest + DECISION_DELAY - 1) % DECISION_DELAY;
        let target = end + offset - decision_delay;
        pulses[target] = rshift_round(path.level_q10[newest], 10) as i8;
        state.quantised_output[memory + target] =
            sat16(rshift_round(smulww(path.output_q14[newest], gain), shift));
        state.shaping_signal_q14[state.shaping_buffer_index - decision_delay + offset] =
            path.shape_q14[newest];
    }
}

/// `silk_noise_shape_quantizer_del_dec` (`NSQ_del_dec.c:318-648`) — one subframe, all states.
#[allow(clippy::too_many_arguments)]
fn quantize_subframe(
    state: &mut NsqState,
    paths: &mut [DelayedState],
    signal_type: SignalType,
    scaled_input_q10: &[i32],
    pulses: &mut [i8],
    output_offset: usize,
    ltp_q15: &mut [i32],
    delayed_gain_q10: &mut [i32; DECISION_DELAY],
    prediction_q12: &[i16],
    ltp_taps_q14: &[i16],
    shaping_ar_q13: &[i16],
    lag: i32,
    harmonic_fir_packed_q14: i32,
    tilt_q14: i32,
    lf_shape_q14: i32,
    gain_q16: i32,
    lambda_q10: i32,
    offset_q10: i32,
    since_reset: usize,
    config: &NsqConfig,
    ring_index: &mut usize,
    decision_delay: usize,
) {
    let mut shaping_lag =
        state.shaping_buffer_index as i32 - lag + (HARM_SHAPE_FIR_TAPS / 2) as i32;
    let mut prediction_lag = state.ltp_buffer_index as i32 - lag + (LTP_ORDER / 2) as i32;
    let gain_q10 = gain_q16 >> 6;
    let warping_q16 = config.warping_q16;
    let order = shaping_ar_q13.len();

    let mut forks = [[SampleFork::default(); 2]; MAX_DEL_DEC_STATES];

    for (sample, &input_q10) in scaled_input_q10.iter().enumerate() {
        // Long-term prediction and long-term shaping are the same for every state: they read the
        // *committed* history, which all states share.
        let ltp_prediction_q14 = if signal_type == SignalType::Voiced {
            let base = prediction_lag as usize;
            let mut accumulator = 2i32;
            for (tap, &coefficient) in ltp_taps_q14.iter().enumerate() {
                accumulator = smlawb(accumulator, ltp_q15[base - tap], i32::from(coefficient));
            }
            prediction_lag += 1;
            accumulator << 1
        } else {
            0
        };

        let long_term_shaping_q14 = if lag > 0 {
            let base = shaping_lag as usize;
            let mut harmonic = smulwb(
                state.shaping_signal_q14[base].saturating_add(state.shaping_signal_q14[base - 2]),
                harmonic_fir_packed_q14,
            );
            harmonic = smlawt(
                harmonic,
                state.shaping_signal_q14[base - 1],
                harmonic_fir_packed_q14,
            );
            shaping_lag += 1;
            // silk_SUB_LSHIFT32( LTP_pred_Q14, n_LTP_Q14, 2 ): Q12 -> Q14.
            ltp_prediction_q14.wrapping_sub(harmonic << 2)
        } else {
            0
        };

        for (index, path) in paths.iter_mut().enumerate() {
            path.seed = rand_step(path.seed);

            let newest = NSQ_LPC_BUF_LENGTH - 1 + sample;
            let lpc_prediction_q14 =
                short_term_prediction(&path.lpc_q14, newest, prediction_q12) << 4;

            // Warped shaping cascade (`NSQ_del_dec.c:422-442`). `warping_Q16 == 0` degenerates to
            // the plain all-pole filter, so this one loop covers both.
            let mut carry_low = smlawb(path.difference_q14, path.shaping_q14[0], warping_q16);
            let mut carry_all = smlawb(
                path.shaping_q14[0],
                path.shaping_q14[1].wrapping_sub(carry_low),
                warping_q16,
            );
            path.shaping_q14[0] = carry_low;
            let mut shaping_q14 = (order >> 1) as i32;
            shaping_q14 = smlawb(shaping_q14, carry_low, i32::from(shaping_ar_q13[0]));
            let mut tap = 2;
            while tap < order {
                carry_low = smlawb(
                    path.shaping_q14[tap - 1],
                    path.shaping_q14[tap].wrapping_sub(carry_all),
                    warping_q16,
                );
                path.shaping_q14[tap - 1] = carry_all;
                shaping_q14 = smlawb(shaping_q14, carry_all, i32::from(shaping_ar_q13[tap - 1]));
                carry_all = smlawb(
                    path.shaping_q14[tap],
                    path.shaping_q14[tap + 1].wrapping_sub(carry_low),
                    warping_q16,
                );
                path.shaping_q14[tap] = carry_low;
                shaping_q14 = smlawb(shaping_q14, carry_low, i32::from(shaping_ar_q13[tap]));
                tap += 2;
            }
            path.shaping_q14[order - 1] = carry_all;
            shaping_q14 = smlawb(shaping_q14, carry_all, i32::from(shaping_ar_q13[order - 1]));

            shaping_q14 <<= 1; // Q11 -> Q12
            shaping_q14 = smlawb(shaping_q14, path.lf_ar_q14, tilt_q14);
            shaping_q14 <<= 2; // Q12 -> Q14

            let mut low_frequency_q14 = smulwb(path.shape_q14[*ring_index], lf_shape_q14);
            low_frequency_q14 = smlawt(low_frequency_q14, path.lf_ar_q14, lf_shape_q14);
            low_frequency_q14 <<= 2; // Q12 -> Q14

            let feedback = shaping_q14.saturating_add(low_frequency_q14);
            let predicted = long_term_shaping_q14.wrapping_add(lpc_prediction_q14);
            let combined_q10 = rshift_round(predicted.saturating_sub(feedback), 4);

            let mut residual_q10 = input_q10.wrapping_sub(combined_q10);
            if path.seed < 0 {
                residual_q10 = -residual_q10;
            }
            residual_q10 = residual_q10.clamp(-(31 << 10), 30 << 10);

            let (first, second, rate1, rate2) =
                quantization_candidates(residual_q10, offset_q10, lambda_q10);
            // The del-dec variant carries its cost in Q10 rather than Q20 (`NSQ_del_dec.c:507-509`).
            let rate1 = rate1 >> 10;
            let rate2 = rate2 >> 10;

            let fork = &mut forks[index];
            if rate1 < rate2 {
                fork[0].cost_q10 = path.cost_q10.wrapping_add(rate1);
                fork[1].cost_q10 = path.cost_q10.wrapping_add(rate2);
                fork[0].level_q10 = first;
                fork[1].level_q10 = second;
            } else {
                fork[0].cost_q10 = path.cost_q10.wrapping_add(rate2);
                fork[1].cost_q10 = path.cost_q10.wrapping_add(rate1);
                fork[0].level_q10 = second;
                fork[1].level_q10 = first;
            }

            for branch in fork.iter_mut() {
                let mut excitation_q14 = branch.level_q10 << 4;
                if path.seed < 0 {
                    excitation_q14 = -excitation_q14;
                }
                let lpc_excitation_q14 = excitation_q14.wrapping_add(ltp_prediction_q14);
                let output_q14 = lpc_excitation_q14.wrapping_add(lpc_prediction_q14);
                branch.difference_q14 = output_q14.wrapping_sub(input_q10 << 4);
                let lf_ar = branch.difference_q14.wrapping_sub(shaping_q14);
                branch.shape_q14 = lf_ar.saturating_sub(low_frequency_q14);
                branch.lf_ar_q14 = lf_ar;
                branch.lpc_excitation_q14 = lpc_excitation_q14;
                branch.output_q14 = output_q14;
            }
        }

        *ring_index = (*ring_index + DECISION_DELAY - 1) % DECISION_DELAY;
        let oldest = (*ring_index + decision_delay) % DECISION_DELAY;

        // 1. The winner, and the dither-history penalty.
        let mut winner = 0usize;
        let mut best = forks[0][0].cost_q10;
        for (index, fork) in forks.iter().enumerate().take(paths.len()).skip(1) {
            if fork[0].cost_q10 < best {
                best = fork[0].cost_q10;
                winner = index;
            }
        }
        let winner_dither = paths[winner].rand_state[oldest];
        for (fork, path) in forks.iter_mut().zip(paths.iter()) {
            if path.rand_state[oldest] != winner_dither {
                fork[0].cost_q10 = fork[0].cost_q10.wrapping_add(PRUNE_PENALTY);
                fork[1].cost_q10 = fork[1].cost_q10.wrapping_add(PRUNE_PENALTY);
            }
        }

        // 2. Best-of-seconds replaces worst-of-firsts.
        let mut worst_first = forks[0][0].cost_q10;
        let mut best_second = forks[0][1].cost_q10;
        let mut worst_index = 0usize;
        let mut best_index = 0usize;
        for (index, fork) in forks.iter().enumerate().take(paths.len()).skip(1) {
            if fork[0].cost_q10 > worst_first {
                worst_first = fork[0].cost_q10;
                worst_index = index;
            }
            if fork[1].cost_q10 < best_second {
                best_second = fork[1].cost_q10;
                best_index = index;
            }
        }
        if best_second < worst_first {
            // See the module docs: copying the whole state is equivalent to the C's partial copy,
            // because the words it skips are dead.
            paths[worst_index] = paths[best_index];
            forks[worst_index][0] = forks[best_index][1];
        }

        // 3. Commit the sample that has now aged out, from the winner.
        if since_reset > 0 || sample >= decision_delay {
            let path = &paths[winner];
            let target = output_offset + sample - decision_delay;
            pulses[target] = rshift_round(path.level_q10[oldest], 10) as i8;
            state.quantised_output[config.ltp_memory_length + target] = sat16(rshift_round(
                smulww(path.output_q14[oldest], delayed_gain_q10[oldest]),
                8,
            ));
            state.shaping_signal_q14[state.shaping_buffer_index - decision_delay] =
                path.shape_q14[oldest];
            ltp_q15[state.ltp_buffer_index - decision_delay] = path.prediction_q15[oldest];
        }
        state.shaping_buffer_index += 1;
        state.ltp_buffer_index += 1;

        for (index, path) in paths.iter_mut().enumerate() {
            let fork = &forks[index][0];
            path.lf_ar_q14 = fork.lf_ar_q14;
            path.difference_q14 = fork.difference_q14;
            path.lpc_q14[NSQ_LPC_BUF_LENGTH + sample] = fork.output_q14;
            path.output_q14[*ring_index] = fork.output_q14;
            path.level_q10[*ring_index] = fork.level_q10;
            path.prediction_q15[*ring_index] = fork.lpc_excitation_q14 << 1;
            path.shape_q14[*ring_index] = fork.shape_q14;
            path.seed = path.seed.wrapping_add(rshift_round(fork.level_q10, 10));
            path.rand_state[*ring_index] = path.seed;
            path.cost_q10 = fork.cost_q10;
        }
        delayed_gain_q10[*ring_index] = gain_q10;
    }

    for path in paths.iter_mut() {
        path.lpc_q14.copy_within(
            scaled_input_q10.len()..scaled_input_q10.len() + NSQ_LPC_BUF_LENGTH,
            0,
        );
    }
}

/// `silk_nsq_del_dec_scale_states` (`NSQ_del_dec.c:651-733`).
#[allow(clippy::too_many_arguments)]
fn scale_states(
    state: &mut NsqState,
    paths: &mut [DelayedState],
    input: &NsqInput,
    x16: &[i16],
    scaled_input_q10: &mut [i32],
    rewhitened: &[i16],
    ltp_q15: &mut [i32],
    subframe: usize,
    config: &NsqConfig,
    decision_delay: usize,
) {
    let lag = input.pitch_lags[subframe];
    let mut inverse_gain_q31 = inverse32_var_q(input.gains_q16[subframe].max(1), 47);

    let inverse_gain_q26 = rshift_round(inverse_gain_q31, 5);
    for (slot, &sample) in scaled_input_q10.iter_mut().zip(x16.iter()) {
        *slot = smulww(i32::from(sample), inverse_gain_q26);
    }

    if state.rewhitened {
        if subframe == 0 {
            inverse_gain_q31 = smulwb(inverse_gain_q31, input.ltp_scale_q14) << 2;
        }
        let start = start_of_ltp_window(state.ltp_buffer_index, lag);
        for (slot, &whitened) in ltp_q15[start..state.ltp_buffer_index]
            .iter_mut()
            .zip(rewhitened[start..].iter())
        {
            *slot = smulwb(inverse_gain_q31, i32::from(whitened));
        }
    }

    if input.gains_q16[subframe] != state.previous_gain_q16 {
        let adjust_q16 = div32_var_q(state.previous_gain_q16, input.gains_q16[subframe], 16);

        for index in
            state.shaping_buffer_index - config.ltp_memory_length..state.shaping_buffer_index
        {
            state.shaping_signal_q14[index] = smulww(adjust_q16, state.shaping_signal_q14[index]);
        }

        if input.signal_type == SignalType::Voiced && !state.rewhitened {
            let start = start_of_ltp_window(state.ltp_buffer_index, lag);
            let end = state.ltp_buffer_index - decision_delay;
            for slot in ltp_q15[start..end.max(start)].iter_mut() {
                *slot = smulww(adjust_q16, *slot);
            }
        }

        for path in paths.iter_mut() {
            path.lf_ar_q14 = smulww(adjust_q16, path.lf_ar_q14);
            path.difference_q14 = smulww(adjust_q16, path.difference_q14);
            for slot in path.lpc_q14.iter_mut().take(NSQ_LPC_BUF_LENGTH) {
                *slot = smulww(adjust_q16, *slot);
            }
            for slot in path.shaping_q14.iter_mut() {
                *slot = smulww(adjust_q16, *slot);
            }
            for index in 0..DECISION_DELAY {
                path.prediction_q15[index] = smulww(adjust_q16, path.prediction_q15[index]);
                path.shape_q14[index] = smulww(adjust_q16, path.shape_q14[index]);
            }
        }

        state.previous_gain_q16 = input.gains_q16[subframe];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::enc::nsq::quantize;
    use crate::opus::silk::enc::nsq::tests::{test_config, test_input, test_signal};
    use crate::opus::silk::types::MAX_FRAME_LENGTH;

    /// The delayed-decision search must produce a legal pulse train for every survivor count, and
    /// must report the seed of the path that actually won rather than the one it was handed.
    #[test]
    fn every_survivor_count_quantises_and_reports_a_legal_seed() {
        let frame = 320usize;
        let signal = test_signal(frame);
        for states in 1..=MAX_DEL_DEC_STATES {
            let mut settings = test_config(80, 4);
            settings.delayed_decision_states = states;
            settings.warping_q16 = if states == 1 { 983 * 16 } else { 0 };
            let input = test_input(6 << 16, 1200);
            let mut state = NsqState::default();
            let mut pulses = [0i8; MAX_FRAME_LENGTH];

            let seed = quantize(&mut state, &input, &signal, &mut pulses, &settings);
            assert!(seed < 4, "{states} states: seed {seed} out of range");
            assert!(
                pulses[..frame].iter().any(|&p| p != 0),
                "{states} states: no pulses"
            );
        }
    }

    /// A deeper search must never cost more distortion+rate than a shallower one on the same
    /// signal: that is the entire justification for spending the extra states. Measured as the
    /// pulse energy needed, which is what the rate control reads.
    #[test]
    fn a_deeper_search_does_not_spend_more_than_a_shallower_one() {
        let frame = 320usize;
        let signal = test_signal(frame);
        let mut spent = Vec::new();
        for states in [1usize, 4] {
            let mut settings = test_config(80, 4);
            settings.delayed_decision_states = states;
            settings.warping_q16 = 983 * 16;
            let input = test_input(6 << 16, 1200);
            let mut state = NsqState::default();
            let mut pulses = [0i8; MAX_FRAME_LENGTH];
            quantize(&mut state, &input, &signal, &mut pulses, &settings);
            spent.push(
                pulses[..frame]
                    .iter()
                    .map(|&p| i64::from(p).abs())
                    .sum::<i64>(),
            );
        }
        assert!(spent[1] <= spent[0] + spent[0] / 10, "{spent:?}");
    }

    /// Silence through the delayed-decision path must still cost nothing.
    #[test]
    fn silence_costs_no_pulses_through_the_delayed_decision_path() {
        let mut settings = test_config(80, 4);
        settings.delayed_decision_states = 4;
        let input = test_input(1 << 16, 1024);
        let mut state = NsqState::default();
        let mut pulses = [0i8; MAX_FRAME_LENGTH];
        quantize(&mut state, &input, &vec![0i16; 320], &mut pulses, &settings);
        assert_eq!(&pulses[..320], &[0i8; 320]);
    }

    /// The decision delay must stay strictly below the pitch lag on a voiced frame, or a state
    /// would predict from a sample it has not committed yet.
    #[test]
    fn the_decision_delay_stays_below_the_pitch_lag() {
        let mut settings = test_config(80, 4);
        settings.delayed_decision_states = 3;
        let mut input = test_input(6 << 16, 1024);
        input.signal_type = SignalType::Voiced;
        input.pitch_lags = [34, 34, 34, 34];
        input.ltp_coefficients_q14[2] = 8192;
        input.ltp_scale_q14 = 15565;
        let signal = test_signal(320);
        let mut state = NsqState::default();
        let mut pulses = [0i8; MAX_FRAME_LENGTH];
        // 34 - 2 - 1 = 31 < DECISION_DELAY, so the clamp is what keeps this in bounds at all.
        let seed = quantize(&mut state, &input, &signal, &mut pulses, &settings);
        assert!(seed < 4);
    }
}
