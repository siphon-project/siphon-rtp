//! The encoder's algebraic (fixed) codebook search — ITU-T G.729 §3.8, reference `acelp_co.c`.
//!
//! Four pulses in forty samples, seventeen bits: thirteen for the positions and four for the signs.
//! Each pulse is confined to its own track — one residue class modulo five — except the fourth,
//! which may sit on either of two, and that confinement is what makes the address fit.
//!
//! An exhaustive search would be 8·8·8·16 = 8192 candidates per subframe. The reference does not run
//! one. It fixes each pulse's sign in advance from the sign of the target correlation at that
//! position, which removes the sign dimension entirely; it skips the innermost loop whenever the
//! first three pulses do not clear a threshold derived from the frame's own correlation statistics;
//! and it caps the number of times that innermost loop may run, carrying whatever budget the first
//! subframe did not spend into the second. The result is a search whose worst case is bounded, which
//! is the property a fixed-point codec running on a DSP needed.
//!
//! The objective is `(x·y)² / (y·Hᵀ H y)`, compared as a cross-product so that no division is
//! needed: a candidate wins when `ps3² · alpha_best − psc_best · alpha > 0`.

use super::bitstream::SUBFRAME_SAMPLES;
use super::excitation::sharpen;
use crate::itu::basic_ops::{
    add, extract_h, extract_l, l_abs, l_mac, l_msu, l_mult, l_shr, l_sub, mult, negate, norm_l,
    shl, shr, sub,
};

/// Positions available to each of the five tracks.
const TRACK_POSITIONS: usize = 8;
/// Entries in a cross-track correlation block: one per pair of positions.
const BLOCK: usize = TRACK_POSITIONS * TRACK_POSITIONS;
/// Spacing between consecutive positions on one track.
const STEP: usize = 5;
/// Size of the correlation matrix: five same-track blocks plus nine cross-track ones.
const CORRELATIONS: usize = 5 * TRACK_POSITIONS + 9 * BLOCK;

/// Where each block of the correlation matrix begins. The five same-track runs come first, then the
/// cross-track blocks in the order the search walks them.
const RR00: usize = 0;
const RR11: usize = RR00 + TRACK_POSITIONS;
const RR22: usize = RR11 + TRACK_POSITIONS;
const RR33: usize = RR22 + TRACK_POSITIONS;
const RR44: usize = RR33 + TRACK_POSITIONS;
const RR01: usize = RR44 + TRACK_POSITIONS;
const RR02: usize = RR01 + BLOCK;
const RR03: usize = RR02 + BLOCK;
const RR04: usize = RR03 + BLOCK;
const RR12: usize = RR04 + BLOCK;
const RR13: usize = RR12 + BLOCK;
const RR14: usize = RR13 + BLOCK;
const RR23: usize = RR14 + BLOCK;
const RR24: usize = RR23 + BLOCK;

/// Fraction of the way from the average to the best three-pulse correlation at which the fourth
/// pulse loop is worth entering: 0.4 in Q15 (`THRESHFCB`).
const THRESHOLD_FRACTION: i16 = 13_107;
/// Iterations of the innermost loop one subframe may spend (`MAX_TIME`).
const MAX_ITERATIONS: i16 = 75;
/// Extra iterations the first subframe of a frame starts with. Whatever it leaves unspent is carried
/// into the second, so a frame has one budget rather than two.
const STARTING_SURPLUS: i16 = 30;

/// The result of one subframe's codebook search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Codeword {
    /// The 13-bit pulse-position index, as transmitted.
    pub positions: u16,
    /// The 4-bit sign index, as transmitted.
    pub signs: u16,
    /// The codeword itself, Q13.
    pub code: [i16; SUBFRAME_SAMPLES],
    /// The codeword seen through the weighted synthesis filter, Q12 — the gain quantiser needs it,
    /// and the search has already computed it.
    pub filtered: [i16; SUBFRAME_SAMPLES],
}

/// The algebraic codebook search, holding the one piece of state that outlives a subframe.
#[derive(Debug, Clone, Default)]
pub struct CodebookSearch {
    /// Iterations left over from the first subframe of the current frame.
    surplus: i16,
}

impl CodebookSearch {
    /// A search in its reset state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            surplus: STARTING_SURPLUS,
        }
    }

    /// Search one subframe.
    ///
    /// `impulse` is the Q12 impulse response of the weighted synthesis filter and is **modified**:
    /// the previous subframe's quantised pitch gain is folded into it as a fixed-gain pitch
    /// contribution, so that the search sees the periodicity the adaptive codebook will add rather
    /// than choosing pulses that fight it. The same sharpening is then applied to the chosen
    /// codeword. `target` is the residual target after the adaptive contribution has been removed.
    pub fn search(
        &mut self,
        target: &[i16; SUBFRAME_SAMPLES],
        impulse: &mut [i16; SUBFRAME_SAMPLES],
        lag: i16,
        pitch_sharpening: i16,
        first_subframe: bool,
    ) -> Codeword {
        // The same sharpening the decoder applies to the codeword is applied to the impulse
        // response first, so the search chooses pulses against the response the codeword will
        // actually be filtered through.
        sharpen(impulse, lag, pitch_sharpening);

        let correlations = impulse_correlations(impulse);
        let mut projections = target_correlations(impulse, target);

        if first_subframe {
            self.surplus = STARTING_SURPLUS;
        }
        let mut codeword =
            search_pulses(&mut projections, correlations, impulse, &mut self.surplus);

        sharpen(&mut codeword.code, lag, pitch_sharpening);
        codeword
    }
}

/// Correlations of the impulse response with itself, for every pair of pulse positions (`Cor_h`).
///
/// Each entry is `Σ h[n − i]·h[n − j]` for one pair of positions, which is the energy term the
/// search needs when it adds a pulse. They are accumulated down the diagonals — every longer
/// correlation extends the one before it by two more products — so the whole matrix costs one pass
/// over the impulse response per diagonal rather than a dot product per entry.
fn impulse_correlations(response: &[i16; SUBFRAME_SAMPLES]) -> [i16; CORRELATIONS] {
    // Scale the response for maximum precision, or down by one bit if it is already large enough
    // that the accumulation below could saturate.
    let mut energy = 0_i32;
    for &sample in response.iter() {
        energy = l_mac(energy, sample, sample);
    }
    let mut h = [0_i16; SUBFRAME_SAMPLES];
    if l_sub(i32::from(extract_h(energy)), 32_000) > 0 {
        for (out, &sample) in h.iter_mut().zip(response.iter()) {
            *out = shr(sample, 1);
        }
    } else {
        // Half the normalisation, because the products below square the response.
        let headroom = shr(norm_l(energy), 1);
        for (out, &sample) in h.iter_mut().zip(response.iter()) {
            *out = shl(sample, headroom);
        }
    }

    let mut rr = [0_i16; CORRELATIONS];

    // The five same-track runs, written from the longest correlation backwards.
    let mut p = [
        (RR00 + TRACK_POSITIONS - 1) as isize,
        (RR11 + TRACK_POSITIONS - 1) as isize,
        (RR22 + TRACK_POSITIONS - 1) as isize,
        (RR33 + TRACK_POSITIONS - 1) as isize,
        (RR44 + TRACK_POSITIONS - 1) as isize,
    ];
    let mut index = 0;
    let mut cor = 0_i32;
    for _ in 0..TRACK_POSITIONS {
        for track in (0..5).rev() {
            cor = l_mac(cor, h[index], h[index]);
            index += 1;
            rr[p[track] as usize] = extract_h(cor);
            p[track] -= 1;
        }
    }

    // The cross-track blocks. Each pass fixes the separation between the two tracks — one, two,
    // three or four samples — and walks the diagonals of the blocks that separation feeds. `slots`
    // names those blocks in the order the accumulation reaches them, each with the number of
    // products that separate its entry from the previous one and whether its diagonal starts at the
    // block's last entry or the one before; `tail` says how many of them the final, shortest
    // diagonal still reaches.
    struct Pass {
        slots: &'static [(usize, usize, bool)],
        tail: usize,
    }
    const PASSES: [Pass; 4] = [
        Pass {
            slots: &[
                (RR23, 2, true),
                (RR12, 1, true),
                (RR01, 1, true),
                (RR04, 1, false),
            ],
            tail: 3,
        },
        Pass {
            slots: &[
                (RR24, 1, true),
                (RR13, 1, true),
                (RR02, 1, true),
                (RR14, 1, false),
                (RR03, 1, false),
            ],
            tail: 3,
        },
        Pass {
            slots: &[
                (RR14, 1, true),
                (RR03, 1, true),
                (RR24, 1, false),
                (RR13, 1, false),
                (RR02, 1, false),
            ],
            tail: 2,
        },
        Pass {
            slots: &[
                (RR04, 1, true),
                (RR23, 2, false),
                (RR12, 1, false),
                (RR01, 1, false),
            ],
            tail: 1,
        },
    ];

    let stride = (TRACK_POSITIONS + 1) as isize;
    for (index, pass) in PASSES.iter().enumerate() {
        let separation = index + 1;
        let mut top = (BLOCK - 1) as isize;
        let mut bottom = top - 1;
        let mut second = separation;

        for k in 0..TRACK_POSITIONS {
            let mut positions = [0_isize; 5];
            for (slot, &(_, _, from_top)) in pass.slots.iter().enumerate() {
                positions[slot] = if from_top { top } else { bottom };
            }

            let mut first = 0_usize;
            let mut offset = second;
            let mut cor = 0_i32;
            let accumulate =
                |cor: &mut i32, first: &mut usize, offset: &mut usize, products: usize| {
                    for _ in 0..products {
                        *cor = l_mac(*cor, h[*first], h[*offset]);
                        *first += 1;
                        *offset += 1;
                    }
                };

            for _ in k + 1..TRACK_POSITIONS {
                for (slot, &(base, products, _)) in pass.slots.iter().enumerate() {
                    accumulate(&mut cor, &mut first, &mut offset, products);
                    rr[(base as isize + positions[slot]) as usize] = extract_h(cor);
                }
                for position in positions.iter_mut() {
                    *position -= stride;
                }
            }
            for (slot, &(base, products, _)) in pass.slots.iter().take(pass.tail).enumerate() {
                accumulate(&mut cor, &mut first, &mut offset, products);
                rr[(base as isize + positions[slot]) as usize] = extract_h(cor);
            }

            top -= TRACK_POSITIONS as isize;
            bottom -= 1;
            second += STEP;
        }
    }

    rr
}

/// Correlations of the impulse response with the target vector (`Cor_h_X`).
///
/// One backward-running dot product per position, renormalised together so the largest occupies
/// thirteen bits — a common scale, because the search adds them across positions.
fn target_correlations(
    response: &[i16; SUBFRAME_SAMPLES],
    target: &[i16; SUBFRAME_SAMPLES],
) -> [i16; SUBFRAME_SAMPLES] {
    let mut wide = [0_i32; SUBFRAME_SAMPLES];
    let mut largest = 0_i32;
    for i in 0..SUBFRAME_SAMPLES {
        let mut sum = 0_i32;
        for j in i..SUBFRAME_SAMPLES {
            sum = l_mac(sum, target[j], response[j - i]);
        }
        wide[i] = sum;
        let magnitude = l_abs(sum);
        if l_sub(magnitude, largest) > 0 {
            largest = magnitude;
        }
    }

    let mut headroom = norm_l(largest);
    if sub(headroom, 16) > 0 {
        headroom = 16;
    }
    let shift = sub(18, headroom);

    let mut narrow = [0_i16; SUBFRAME_SAMPLES];
    for (out, &value) in narrow.iter_mut().zip(wide.iter()) {
        *out = extract_l(l_shr(value, shift));
    }
    narrow
}

/// Search the four pulse positions that maximise `(x·y)²/(y·y)` (`D4i40_17`).
fn search_pulses(
    projections: &mut [i16; SUBFRAME_SAMPLES],
    mut rr: [i16; CORRELATIONS],
    response: &[i16; SUBFRAME_SAMPLES],
    surplus: &mut i16,
) -> Codeword {
    // Each pulse's sign is decided here rather than searched: the best sign for a pulse at a given
    // position is the sign of the target correlation there, whatever the other three pulses do.
    // Taking the magnitudes now turns the objective into a maximisation over positions alone.
    let mut signs = [0_i16; SUBFRAME_SAMPLES];
    for (sign, projection) in signs.iter_mut().zip(projections.iter_mut()) {
        if *projection >= 0 {
            *sign = i16::MAX;
        } else {
            *sign = i16::MIN;
            *projection = negate(*projection);
        }
    }

    // The threshold the first three pulses must clear for the fourth loop to run, placed 40 % of the
    // way from the average three-pulse correlation to the best one.
    let mut best_of = [projections[0], projections[1], projections[2]];
    for position in (STEP..SUBFRAME_SAMPLES).step_by(STEP) {
        for (track, best) in best_of.iter_mut().enumerate() {
            if sub(projections[position + track], *best) > 0 {
                *best = projections[position + track];
            }
        }
    }
    let peak = add(add(best_of[0], best_of[1]), best_of[2]);

    let mut total = 0_i32;
    for position in (0..SUBFRAME_SAMPLES).step_by(STEP) {
        for track in 0..3 {
            total = l_mac(total, projections[position + track], 1);
        }
    }
    let average = extract_l(l_shr(total, 4));
    let threshold = add(mult(sub(peak, average), THRESHOLD_FRACTION), average);

    // Fold the signs into the cross-track correlations, so the search itself never consults them.
    let mut write = [RR01, RR02, RR03, RR04];
    for first in (0..SUBFRAME_SAMPLES).step_by(STEP) {
        for second in (1..SUBFRAME_SAMPLES).step_by(STEP) {
            for (offset, slot) in write.iter_mut().enumerate() {
                rr[*slot] = mult(rr[*slot], mult(signs[first], signs[second + offset]));
                *slot += 1;
            }
        }
    }
    let mut write = [RR12, RR13, RR14];
    for first in (1..SUBFRAME_SAMPLES).step_by(STEP) {
        for second in (2..SUBFRAME_SAMPLES).step_by(STEP) {
            for (offset, slot) in write.iter_mut().enumerate() {
                rr[*slot] = mult(rr[*slot], mult(signs[first], signs[second + offset]));
                *slot += 1;
            }
        }
    }
    let mut write = [RR23, RR24];
    for first in (2..SUBFRAME_SAMPLES).step_by(STEP) {
        for second in (3..SUBFRAME_SAMPLES).step_by(STEP) {
            for (offset, slot) in write.iter_mut().enumerate() {
                rr[*slot] = mult(rr[*slot], mult(signs[first], signs[second + offset]));
                *slot += 1;
            }
        }
    }

    let mut chosen = [0_usize, 1, 2, 3];
    let mut best_correlation = 0_i16;
    let mut best_energy = i16::MAX;
    let mut iterations = add(MAX_ITERATIONS, *surplus);

    let mut r01 = RR01;
    let mut r02 = RR02;
    let mut r03 = RR03;
    let mut r04 = RR04;

    'search: for i0 in (0..SUBFRAME_SAMPLES).step_by(STEP) {
        let correlation0 = projections[i0];
        // The same-track terms are addressed straight from the loop position: one entry per
        // position on the track, in the order the loop visits them.
        let energy0 = rr[RR00 + i0 / STEP];

        let mut r12 = RR12;
        let mut r13 = RR13;
        let mut r14 = RR14;

        for i1 in (1..SUBFRAME_SAMPLES).step_by(STEP) {
            let correlation1 = add(correlation0, projections[i1]);
            let mut energy1 = l_mult(energy0, 1);
            energy1 = l_mac(energy1, rr[RR11 + (i1 - 1) / STEP], 1);
            energy1 = l_mac(energy1, rr[r01], 2);
            r01 += 1;

            let mut r23 = RR23;
            let mut r24 = RR24;

            for i2 in (2..SUBFRAME_SAMPLES).step_by(STEP) {
                let correlation2 = add(correlation1, projections[i2]);
                let mut energy2 = l_mac(energy1, rr[RR22 + (i2 - 2) / STEP], 1);
                energy2 = l_mac(energy2, rr[r02], 2);
                r02 += 1;
                energy2 = l_mac(energy2, rr[r12], 2);
                r12 += 1;

                if sub(correlation2, threshold) <= 0 {
                    r23 += TRACK_POSITIONS;
                    r24 += TRACK_POSITIONS;
                    continue;
                }

                for i3 in (3..SUBFRAME_SAMPLES).step_by(STEP) {
                    let correlation3 = add(correlation2, projections[i3]);
                    let mut energy3 = l_mac(energy2, rr[RR33 + (i3 - 3) / STEP], 1);
                    energy3 = l_mac(energy3, rr[r03], 2);
                    r03 += 1;
                    energy3 = l_mac(energy3, rr[r13], 2);
                    r13 += 1;
                    energy3 = l_mac(energy3, rr[r23], 2);
                    r23 += 1;
                    let energy = extract_l(l_shr(energy3, 5));

                    let squared = mult(correlation3, correlation3);
                    let comparison = l_msu(l_mult(squared, best_energy), best_correlation, energy);
                    if comparison > 0 {
                        best_correlation = squared;
                        best_energy = energy;
                        chosen = [i0, i1, i2, i3];
                    }
                }
                r03 -= TRACK_POSITIONS;
                r13 -= TRACK_POSITIONS;

                for i3 in (4..SUBFRAME_SAMPLES).step_by(STEP) {
                    let correlation3 = add(correlation2, projections[i3]);
                    let mut energy3 = l_mac(energy2, rr[RR44 + (i3 - 4) / STEP], 1);
                    energy3 = l_mac(energy3, rr[r04], 2);
                    r04 += 1;
                    energy3 = l_mac(energy3, rr[r14], 2);
                    r14 += 1;
                    energy3 = l_mac(energy3, rr[r24], 2);
                    r24 += 1;
                    let energy = extract_l(l_shr(energy3, 5));

                    let squared = mult(correlation3, correlation3);
                    let comparison = l_msu(l_mult(squared, best_energy), best_correlation, energy);
                    if comparison > 0 {
                        best_correlation = squared;
                        best_energy = energy;
                        chosen = [i0, i1, i2, i3];
                    }
                }
                r04 -= TRACK_POSITIONS;
                r14 -= TRACK_POSITIONS;

                iterations = sub(iterations, 1);
                if iterations <= 0 {
                    break 'search;
                }
            }

            r02 -= TRACK_POSITIONS;
            r13 += TRACK_POSITIONS;
            r14 += TRACK_POSITIONS;
        }

        r02 += TRACK_POSITIONS;
        r03 += TRACK_POSITIONS;
        r04 += TRACK_POSITIONS;
    }

    *surplus = iterations;

    let pulse_signs: [i16; 4] = [
        signs[chosen[0]],
        signs[chosen[1]],
        signs[chosen[2]],
        signs[chosen[3]],
    ];

    let mut code = [0_i16; SUBFRAME_SAMPLES];
    for (&position, &sign) in chosen.iter().zip(pulse_signs.iter()) {
        // Q15 to Q13, which is the scale the decoder's codebook is defined in.
        code[position] = shr(sign, 2);
    }

    // The filtered codeword: four shifted copies of the impulse response, added or subtracted.
    let mut filtered = [0_i16; SUBFRAME_SAMPLES];
    for (&position, &sign) in chosen.iter().zip(pulse_signs.iter()) {
        for (offset, index) in (position..SUBFRAME_SAMPLES).enumerate() {
            filtered[index] = if sign > 0 {
                add(filtered[index], response[offset])
            } else {
                sub(filtered[index], response[offset])
            };
        }
    }

    let mut sign_index = 0_u16;
    for (bit, &sign) in pulse_signs.iter().enumerate() {
        if sign > 0 {
            sign_index |= 1 << bit;
        }
    }

    // Three bits each for the first three pulses, four for the fourth: its low bit says which of the
    // two tracks it sits on.
    // The fourth pulse's track is 3 or 4 modulo five, and which of the two is its low bit.
    let fourth = chosen[3] / STEP;
    let fourth_track = (chosen[3] % STEP).saturating_sub(3);
    let positions = (chosen[0] / STEP)
        | ((chosen[1] / STEP) << 3)
        | ((chosen[2] / STEP) << 6)
        | ((2 * fourth + fourth_track) << 9);

    Codeword {
        positions: positions as u16,
        signs: sign_index,
        code,
        filtered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::g729::excitation::{fixed_codebook, SHARP_MIN};

    /// A plausible weighted-synthesis impulse response: decaying, Q12.
    fn impulse_response() -> [i16; SUBFRAME_SAMPLES] {
        std::array::from_fn(|i| {
            let decay = (-(i as f32) / 9.0).exp();
            ((i as f32 * 0.7).cos() * decay * 4096.0) as i16
        })
    }

    fn target() -> [i16; SUBFRAME_SAMPLES] {
        std::array::from_fn(|i| ((i as f32 * 0.31).sin() * 3500.0) as i16)
    }

    /// A lag at least the subframe length, so no pitch sharpening is folded in and the codeword the
    /// search returns is the one it chose.
    const NO_SHARPENING: i16 = SUBFRAME_SAMPLES as i16;

    #[test]
    fn the_transmitted_indices_rebuild_the_codeword_the_search_chose() {
        // The contract across the two halves of the codec. `fixed_codebook` is pinned bit-exact by
        // the conformance vectors, so agreeing with it is evidence about the encoder rather than
        // about two functions that share a misreading.
        let mut impulse = impulse_response();
        let mut search = CodebookSearch::new();
        let codeword = search.search(&target(), &mut impulse, NO_SHARPENING, SHARP_MIN, true);

        assert_eq!(
            fixed_codebook(codeword.signs, codeword.positions),
            codeword.code
        );
    }

    #[test]
    fn the_four_pulses_each_sit_on_their_own_track() {
        let mut impulse = impulse_response();
        let mut search = CodebookSearch::new();
        let codeword = search.search(&target(), &mut impulse, NO_SHARPENING, SHARP_MIN, true);

        let placed: Vec<usize> = codeword
            .code
            .iter()
            .enumerate()
            .filter(|(_, &sample)| sample != 0)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(placed.len(), 4, "four pulses, at {placed:?}");

        // The pulses are not in position order — the first pulse's track runs to 35 while the
        // second's starts at 1 — so it is the set of tracks that is fixed, not the sequence.
        let mut tracks: Vec<usize> = placed.iter().map(|position| position % STEP).collect();
        tracks.sort_unstable();
        assert_eq!(&tracks[..3], &[0, 1, 2], "placed at {placed:?}");
        assert!(
            tracks[3] == 3 || tracks[3] == 4,
            "the fourth pulse has two tracks, found {tracks:?}"
        );
    }

    #[test]
    fn every_pulse_is_a_full_scale_unit_of_either_sign() {
        // The codebook carries no amplitude: a pulse is ±1 in Q13 and the gain quantiser supplies
        // the scale. A pulse of any other magnitude would mean the decoder rebuilds a different
        // vector from the same index.
        let mut impulse = impulse_response();
        let mut search = CodebookSearch::new();
        let codeword = search.search(&target(), &mut impulse, NO_SHARPENING, SHARP_MIN, true);

        for (index, &sample) in codeword.code.iter().enumerate() {
            assert!(
                sample == 0 || sample == 8191 || sample == -8192,
                "sample {index} is {sample}"
            );
        }
    }

    #[test]
    fn the_indices_fit_the_bits_the_bitstream_allots_them() {
        let mut impulse = impulse_response();
        let mut search = CodebookSearch::new();
        let codeword = search.search(&target(), &mut impulse, NO_SHARPENING, SHARP_MIN, true);
        assert!(codeword.positions < 1 << 13, "{}", codeword.positions);
        assert!(codeword.signs < 1 << 4, "{}", codeword.signs);
    }

    #[test]
    fn each_pulse_takes_the_sign_of_the_correlation_at_its_position() {
        // The search never tries both signs. The best sign for a pulse at a position is the sign of
        // the target's correlation with the impulse response placed there, whatever the other three
        // pulses do, so it is fixed before the position search begins. This checks that claim
        // against the correlation computed directly, in wide arithmetic.
        let response = impulse_response();
        let signal = target();
        let mut impulse = response;
        let mut search = CodebookSearch::new();
        let codeword = search.search(&signal, &mut impulse, NO_SHARPENING, SHARP_MIN, true);

        for (position, &sample) in codeword.code.iter().enumerate() {
            if sample == 0 {
                continue;
            }
            let correlation: i64 = (position..SUBFRAME_SAMPLES)
                .map(|j| i64::from(signal[j]) * i64::from(response[j - position]))
                .sum();
            assert_eq!(
                sample > 0,
                correlation >= 0,
                "position {position}: correlation {correlation}"
            );
        }
    }

    #[test]
    fn the_filtered_codeword_is_causal_from_the_first_pulse() {
        // Nothing precedes the earliest pulse, and the sample at it is the impulse response's own
        // first tap with that pulse's sign — the property the gain quantiser's energy term assumes.
        let mut impulse = impulse_response();
        let first_tap = impulse[0];
        let mut search = CodebookSearch::new();
        let codeword = search.search(&target(), &mut impulse, NO_SHARPENING, SHARP_MIN, true);

        let first_pulse = codeword
            .code
            .iter()
            .position(|&sample| sample != 0)
            .expect("a pulse");
        assert!(codeword.filtered[..first_pulse].iter().all(|&s| s == 0));
        let sign = if codeword.code[first_pulse] > 0 {
            1
        } else {
            -1
        };
        assert_eq!(codeword.filtered[first_pulse], sign * first_tap);
    }

    #[test]
    fn the_search_budget_is_reset_at_the_start_of_every_frame() {
        // The iteration budget carries from a frame's first subframe into its second and is reset
        // for the next frame. Were it not reset, a frame's result would depend on how much work the
        // frame before it happened to do, and a decoder resynchronising mid-stream would diverge.
        let mut search = CodebookSearch::new();
        let mut impulse = impulse_response();
        let first = search.search(&target(), &mut impulse, NO_SHARPENING, SHARP_MIN, true);

        let mut impulse = impulse_response();
        let again = search.search(&target(), &mut impulse, NO_SHARPENING, SHARP_MIN, true);
        assert_eq!(first, again);
    }

    #[test]
    fn pitch_sharpening_reaches_the_codeword_only_when_the_lag_is_short() {
        // A lag at or past the subframe length has no sample inside the subframe to fold back, so
        // the codeword is the bare pulse train. A short lag repeats every pulse one period later.
        let mut long = impulse_response();
        let mut search = CodebookSearch::new();
        let bare = search.search(&target(), &mut long, NO_SHARPENING, SHARP_MIN, true);
        assert_eq!(bare.code.iter().filter(|&&s| s != 0).count(), 4);

        let mut short = impulse_response();
        let mut search = CodebookSearch::new();
        let sharpened = search.search(&target(), &mut short, 20, SHARP_MIN, true);
        assert!(
            sharpened.code.iter().filter(|&&s| s != 0).count() > 4,
            "a 20-sample lag must repeat pulses within the subframe"
        );
    }

    #[test]
    fn a_silent_target_still_produces_a_transmittable_codeword() {
        // Nothing correlates, so the search never clears its threshold and keeps its defaults. It
        // must still hand back an index the decoder can read.
        let mut impulse = [0_i16; SUBFRAME_SAMPLES];
        let mut search = CodebookSearch::new();
        let codeword = search.search(
            &[0; SUBFRAME_SAMPLES],
            &mut impulse,
            NO_SHARPENING,
            SHARP_MIN,
            true,
        );
        assert!(codeword.positions < 1 << 13);
        assert!(codeword.signs < 1 << 4);
        assert_eq!(
            fixed_codebook(codeword.signs, codeword.positions),
            codeword.code
        );
    }
}
