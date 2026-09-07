//! LSP decoding: turning the two transmitted LSP indices back into the ten line spectral pairs the
//! synthesis filter is built from (ITU-T G.729 Release 3 `lspdec.c` and `lspgetq.c`).
//!
//! The quantiser is two-stage and *predictive*: what the indices address is not the LSF vector
//! itself but a residual, from which the vector is recovered by adding back a moving average of the
//! four previous frames' residuals. That is why this carries state, and why a lost frame cannot
//! simply be skipped — the predictor has to be advanced anyway or every subsequent frame decodes
//! against the wrong history.
//!
//! Two MA predictor coefficient sets exist and one bit per frame chooses between them, so the state
//! also remembers which set was last used, for the erasure path to keep predicting with.

use super::tables::{FG, FG_SUM, FG_SUM_INV, LSPCB1, LSPCB2, SLOPE_COS, TABLE2};
use crate::itu::basic_ops::{
    add, extract_h, extract_l, l_deposit_h, l_mac, l_msu, l_mult, l_shl, l_shr, mult, shr, sub,
};

/// LP order: ten line spectral pairs per frame.
pub const ORDER: usize = 10;

/// Split point of the two-stage codebook: the second stage codes the lower and upper halves of the
/// vector with separate indices.
const SPLIT: usize = 5;

/// Order of the moving-average prediction over previous frames' LSF residuals.
const MA_ORDER: usize = 4;

/// Minimum spacing enforced between adjacent LSFs in the first expansion pass. Q13.
const GAP1: i16 = 10;
/// Minimum spacing enforced in the second expansion pass. Q13.
const GAP2: i16 = 5;
/// Minimum spacing the stability check enforces after prediction. Q13.
const GAP3: i16 = 321;
/// Lowest LSF the stability check permits, 0.005 in Q13.
const LOW_LIMIT: i16 = 40;
/// Highest LSF the stability check permits, 3.135 in Q13.
const HIGH_LIMIT: i16 = 25_681;

/// The predictor's reset state: LSFs evenly spaced across the band, `PI*(j+1)/(M+1)` in Q13.
const RESET: [i16; ORDER] = [
    2339, 4679, 7018, 9358, 11_698, 14_037, 16_377, 18_717, 21_056, 23_396,
];

/// The LSP decoder's state: the predictor history, and what to fall back on when a frame is lost.
#[derive(Debug, Clone)]
pub struct LspDecoder {
    /// The four previous frames' LSF residuals, most recent first. Q13.
    history: [[i16; ORDER]; MA_ORDER],
    /// The last successfully decoded LSF vector, repeated when a frame is erased. Q13.
    previous: [i16; ORDER],
    /// Which MA coefficient set the last good frame selected, so an erased frame predicts with the
    /// same one rather than defaulting.
    previous_mode: usize,
}

impl Default for LspDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl LspDecoder {
    /// A decoder at its reset state (the reference's `Lsp_decw_reset`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            history: [RESET; MA_ORDER],
            previous: RESET,
            previous_mode: 0,
        }
    }

    /// Decode one frame's LSPs from its two transmitted indices.
    ///
    /// `stage1` is the 8-bit parameter carrying the MA-set bit and the first-stage index; `stage2`
    /// the 10-bit parameter carrying the two second-stage indices. `erased` says the frame was lost,
    /// in which case the indices are ignored and the previous vector is repeated — while still
    /// advancing the predictor, which is the part that matters for the frames after it.
    ///
    /// Returns the ten LSPs in Q15.
    pub fn decode(&mut self, stage1: u16, stage2: u16, erased: bool) -> [i16; ORDER] {
        let lsf = self.decode_lsf(stage1, stage2, erased);
        lsf_to_lsp(&lsf)
    }

    /// The quantiser proper (`Lsp_iqua_cs`), returning LSFs in Q13.
    fn decode_lsf(&mut self, stage1: u16, stage2: u16, erased: bool) -> [i16; ORDER] {
        if erased {
            // Repeat the last vector, but still run the predictor over it: `Lsp_prev_extract`
            // recovers the residual that vector would have had, and pushing it into the history
            // keeps the next good frame predicting from a sane place.
            let previous = self.previous;
            let mode = self.previous_mode;
            let residual = self.extract_residual(&previous, mode);
            self.push_history(&residual);
            return previous;
        }

        let mode = usize::from((stage1 >> 7) & 1);
        let code0 = usize::from(stage1) & (LSPCB1.len() - 1);
        let code1 = usize::from(stage2 >> 5) & (LSPCB2.len() - 1);
        let code2 = usize::from(stage2) & (LSPCB2.len() - 1);

        // Two-stage sum: the lower half of the vector uses one second-stage index, the upper half
        // the other.
        let mut residual = [0_i16; ORDER];
        for j in 0..SPLIT {
            residual[j] = add(LSPCB1[code0][j], LSPCB2[code1][j]);
        }
        for j in SPLIT..ORDER {
            residual[j] = add(LSPCB1[code0][j], LSPCB2[code2][j]);
        }

        // Two passes of minimum-distance expansion on the residual, before prediction.
        expand(&mut residual, GAP1);
        expand(&mut residual, GAP2);

        let mut lsf = self.compose(&residual, mode);
        self.push_history(&residual);
        stabilise(&mut lsf);

        self.previous = lsf;
        self.previous_mode = mode;
        lsf
    }

    /// Add the moving-average prediction back onto a residual (`Lsp_prev_compose`).
    fn compose(&self, residual: &[i16; ORDER], mode: usize) -> [i16; ORDER] {
        let mut lsf = [0_i16; ORDER];
        for j in 0..ORDER {
            let mut accumulator = l_mult(residual[j], FG_SUM[mode][j]);
            for (previous, coefficients) in self.history.iter().zip(&FG[mode]) {
                accumulator = l_mac(accumulator, previous[j], coefficients[j]);
            }
            lsf[j] = extract_h(accumulator);
        }
        lsf
    }

    /// Recover the residual a given LSF vector would have had (`Lsp_prev_extract`) — the inverse of
    /// [`Self::compose`], needed only on the erasure path.
    fn extract_residual(&self, lsf: &[i16; ORDER], mode: usize) -> [i16; ORDER] {
        let mut residual = [0_i16; ORDER];
        for j in 0..ORDER {
            let mut accumulator = l_deposit_h(lsf[j]);
            for (previous, coefficients) in self.history.iter().zip(&FG[mode]) {
                accumulator = l_msu(accumulator, previous[j], coefficients[j]);
            }
            let temp = extract_h(accumulator);
            let scaled = l_mult(temp, FG_SUM_INV[mode][j]);
            residual[j] = extract_h(l_shl(scaled, 3));
        }
        residual
    }

    /// Push a residual onto the predictor history, dropping the oldest (`Lsp_prev_update`).
    fn push_history(&mut self, residual: &[i16; ORDER]) {
        for k in (1..MA_ORDER).rev() {
            self.history[k] = self.history[k - 1];
        }
        self.history[0] = *residual;
    }
}

/// Force a minimum spacing between adjacent entries by pushing each colliding pair apart evenly
/// (`Lsp_expand_1_2`). LSFs that cross would give an unstable synthesis filter.
fn expand(buffer: &mut [i16; ORDER], gap: i16) {
    for j in 1..ORDER {
        let difference = sub(buffer[j - 1], buffer[j]);
        let correction = shr(add(difference, gap), 1);
        if correction > 0 {
            buffer[j - 1] = sub(buffer[j - 1], correction);
            buffer[j] = add(buffer[j], correction);
        }
    }
}

/// Sort, clamp and space the predicted LSFs (`Lsp_stability`).
///
/// The reference prints a warning when it has to clamp an endpoint. Nothing is logged here: this is
/// a defined step of the algorithm reached by ordinary bitstreams, not a fault, and a per-frame log
/// line on a media path would be worse than useless.
fn stabilise(buffer: &mut [i16; ORDER]) {
    // One bubble pass, which is what the reference does — enough because prediction can only
    // disorder neighbours.
    for j in 0..ORDER - 1 {
        if buffer[j + 1] < buffer[j] {
            buffer.swap(j, j + 1);
        }
    }
    if buffer[0] < LOW_LIMIT {
        buffer[0] = LOW_LIMIT;
    }
    for j in 0..ORDER - 1 {
        if sub(buffer[j + 1], buffer[j]) < GAP3 {
            buffer[j + 1] = add(buffer[j], GAP3);
        }
    }
    if buffer[ORDER - 1] > HIGH_LIMIT {
        buffer[ORDER - 1] = HIGH_LIMIT;
    }
}

/// Convert LSFs (Q13, 0..PI) to LSPs (Q15, -1..1) by table lookup and linear interpolation
/// (`Lsf_lsp2`).
#[must_use]
pub fn lsf_to_lsp(lsf: &[i16; ORDER]) -> [i16; ORDER] {
    let mut lsp = [0_i16; ORDER];
    for (index, &frequency) in lsf.iter().enumerate() {
        // 20861 is 1/(2*PI) in Q17, so this normalises the frequency to a Q15 fraction of a turn;
        // its top eight bits address the table and its bottom eight position within the interval.
        let normalised = mult(frequency, 20_861);
        let mut point = shr(normalised, 8) as usize;
        let offset = normalised & 0x00ff;
        point = point.min(TABLE2.len() - 1);

        let interpolated = l_mult(SLOPE_COS[point], offset);
        lsp[index] = add(TABLE2[point], extract_l(l_shr(interpolated, 13)));
    }
    lsp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_decoder_starts_from_evenly_spaced_line_frequencies() {
        let decoder = LspDecoder::new();
        assert_eq!(decoder.previous, RESET);
        assert!(decoder.history.iter().all(|row| *row == RESET));
        assert!(
            RESET.windows(2).all(|w| w[0] < w[1]),
            "the reset vector is ordered, or the first frame decodes against nonsense"
        );
    }

    #[test]
    fn decoded_line_frequencies_stay_ordered_and_inside_the_band() {
        // Whatever indices arrive — including ones no encoder would emit — the vector handed to the
        // synthesis filter must be ordered and bounded, because an unordered LSP set is an unstable
        // filter and the decoder has no way to reject a frame.
        let mut decoder = LspDecoder::new();
        for stage1 in (0..256_u16).step_by(7) {
            for stage2 in (0..1024_u16).step_by(37) {
                let lsf = decoder.decode_lsf(stage1, stage2, false);
                assert!(lsf[0] >= LOW_LIMIT, "{stage1}/{stage2}: {lsf:?}");
                assert!(lsf[ORDER - 1] <= HIGH_LIMIT, "{stage1}/{stage2}: {lsf:?}");
                for pair in lsf.windows(2) {
                    assert!(pair[0] < pair[1], "{stage1}/{stage2} unordered: {lsf:?}");
                }
            }
        }
    }

    #[test]
    fn expansion_separates_colliding_frequencies_and_leaves_spaced_ones_alone() {
        let mut spaced = [
            1000, 3000, 5000, 7000, 9000, 11_000, 13_000, 15_000, 17_000, 19_000,
        ];
        let untouched = spaced;
        expand(&mut spaced, GAP1);
        assert_eq!(spaced, untouched, "already further apart than the gap");

        let mut collided = [
            5000, 5000, 5000, 7000, 9000, 11_000, 13_000, 15_000, 17_000, 19_000,
        ];
        expand(&mut collided, GAP1);
        assert!(
            collided.windows(2).all(|w| w[1] > w[0]),
            "collisions pushed apart: {collided:?}"
        );
    }

    #[test]
    fn stability_sorts_clamps_and_spaces() {
        let mut crossed = [
            9000, 8000, 12_000, 13_000, 14_000, 15_000, 16_000, 17_000, 18_000, 19_000,
        ];
        stabilise(&mut crossed);
        assert!(crossed[0] < crossed[1], "a crossed pair is swapped back");

        let mut low = [1, 400, 800, 1200, 1600, 2000, 2400, 2800, 3200, 3600];
        stabilise(&mut low);
        assert_eq!(low[0], LOW_LIMIT, "the bottom is clamped up");

        let mut high = [
            40, 4000, 8000, 12_000, 16_000, 20_000, 24_000, 26_000, 27_000, 32_000,
        ];
        stabilise(&mut high);
        assert_eq!(high[ORDER - 1], HIGH_LIMIT, "the top is clamped down");
        for pair in high.windows(2) {
            assert!(
                pair[1] - pair[0] >= GAP3 || pair[1] == HIGH_LIMIT,
                "{high:?}"
            );
        }
    }

    #[test]
    fn an_erased_frame_repeats_the_previous_vector_and_still_advances_the_predictor() {
        // The repeat is the audible part; advancing the predictor is the part that decides whether
        // the *next* good frame is right. A decoder that skipped the update would drift silently.
        let mut decoder = LspDecoder::new();
        let good = decoder.decode_lsf(0x2a, 0x155, false);
        let history_before = decoder.history;

        let repeated = decoder.decode_lsf(0, 0, true);
        assert_eq!(repeated, good, "the previous vector is repeated verbatim");
        assert_ne!(
            decoder.history, history_before,
            "the predictor history advanced through the erasure"
        );
    }

    #[test]
    fn composing_a_residual_and_extracting_it_again_round_trips_closely() {
        // `Lsp_prev_extract` is the inverse `Lsp_prev_compose`, used only on the erasure path. They
        // are fixed-point inverses, so agreement is close rather than exact; a sign or scaling error
        // in either would show up here as a gross mismatch.
        let decoder = LspDecoder::new();
        let residual = [
            500_i16, 1200, 2400, 3600, 4800, 6000, 7200, 8400, 9600, 10_800,
        ];
        for mode in 0..2 {
            let composed = decoder.compose(&residual, mode);
            let extracted = decoder.extract_residual(&composed, mode);
            for (index, (&back, &original)) in extracted.iter().zip(&residual).enumerate() {
                let error = (i32::from(back) - i32::from(original)).abs();
                assert!(
                    error < 64,
                    "mode {mode} coefficient {index}: {back} vs {original}"
                );
            }
        }
    }

    #[test]
    fn line_frequencies_map_to_line_pairs_monotonically_downwards() {
        // The conversion is a cosine, so a rising LSF gives a falling LSP across the band.
        let lsf: [i16; ORDER] = [
            40, 2600, 5200, 7800, 10_400, 13_000, 15_600, 18_200, 20_800, 25_681,
        ];
        let lsp = lsf_to_lsp(&lsf);
        assert!(lsp.windows(2).all(|w| w[0] > w[1]), "{lsp:?}");
        assert!(lsp[0] > 30_000, "an LSF near zero maps to an LSP near +1");
        assert!(
            lsp[ORDER - 1] < -30_000,
            "an LSF near PI maps to an LSP near -1"
        );
    }
}
