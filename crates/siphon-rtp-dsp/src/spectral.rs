//! Shared per-bin **decision-directed Wiener** spectral gain (Ephraim & Malah 1984).
//!
//! Both spectral post-filters in this crate reduce one interference against one observed spectrum
//! with the identical gain law — only the interference PSD differs:
//!
//! - the noise suppressor ([`crate::ns`]) uses the tracked **noise** PSD, and
//! - the AEC residual-echo suppressor ([`crate::res`]) uses the estimated **residual-echo** PSD.
//!
//! Factoring the gain here keeps the two from drifting apart (no duplicate logic) and guarantees the
//! residual-echo suppressor computes the *same* gain the noise suppressor's committed golden output
//! was pinned against. The arithmetic below is a byte-for-byte extract of the noise suppressor's
//! original inline gain — the operation order is preserved exactly, so the refactor is numerically
//! identical (its golden vector test is the regression guard).

/// The decision-directed Wiener gain law and its three fixed coefficients.
///
/// Per bin, given the observed power `|Y|²`, the interference PSD `N̂` (noise **or** residual echo),
/// and the previous frame's clean-amplitude-squared estimate `Â_prev²`:
///
/// ```text
///   γ  = |Y|² / N̂                                  (posterior SNR)
///   ξ  = α·Â_prev²/N̂ + (1-α)·max(γ-1, 0)           (decision-directed a priori SNR)
///   G  = max( ξ / (1 + ξ), G_floor )               (Wiener gain, spectral-floored)
/// ```
///
/// The decision-directed `ξ` (Ephraim & Malah, *Speech enhancement using a MMSE short-time spectral
/// amplitude estimator*, IEEE TASSP 32(6) 1984) is the standard defence against musical noise; the
/// spectral floor keeps the output from ever fully gating so the residual stays natural.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DecisionDirectedWiener {
    /// Decision-directed a priori SNR smoothing `α` (the canonical 0.98..0.99 range).
    pub decision_directed: f32,
    /// Small a priori SNR floor so `ξ` stays positive before the gain floor applies.
    pub a_priori_floor: f32,
    /// Spectral gain floor (e.g. ≈ −16 dB); the output never fully gates.
    pub gain_floor: f32,
}

impl DecisionDirectedWiener {
    /// The per-bin gain for observed power `power`, interference PSD `interference` (assumed `> 0`),
    /// and the previous frame's clean-amplitude-squared estimate `previous_clean_power`.
    ///
    /// The caller multiplies the complex bin by this gain and stores `G²·|Y|²` as the next frame's
    /// `previous_clean_power` (the decision-directed recursion's clean-amplitude estimate).
    #[inline]
    pub(crate) fn gain(&self, power: f32, interference: f32, previous_clean_power: f32) -> f32 {
        let posterior_snr = power / interference;
        let decision_directed = previous_clean_power / interference;
        let maximum_likelihood = (posterior_snr - 1.0).max(0.0);
        let a_priori_snr = (self.decision_directed * decision_directed
            + (1.0 - self.decision_directed) * maximum_likelihood)
            .max(self.a_priori_floor);
        let mut gain = a_priori_snr / (1.0 + a_priori_snr);
        if gain < self.gain_floor {
            gain = self.gain_floor;
        }
        gain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gain() -> DecisionDirectedWiener {
        DecisionDirectedWiener {
            decision_directed: 0.99,
            a_priori_floor: 0.003,
            gain_floor: 0.158_489_32,
        }
    }

    #[test]
    fn floors_at_the_spectral_floor_when_interference_dominates() {
        // Interference equal to the observed power and no prior clean estimate → the a priori SNR sits
        // at its floor, so the gain collapses to the spectral floor (never below).
        let gain = gain().gain(1.0, 1.0, 0.0);
        assert!(
            (gain - 0.158_489_32).abs() < 1e-6,
            "gain {gain} should sit at the spectral floor"
        );
    }

    #[test]
    fn approaches_unity_when_signal_dominates() {
        // A large posterior SNR *and* a confident prior clean estimate (steady speech ≫ interference)
        // drive the decision-directed a priori SNR high, so the gain approaches 1.
        let gain = gain().gain(1_000.0, 1.0, 900.0);
        assert!(gain > 0.99, "gain {gain} should approach unity");
        assert!(gain <= 1.0, "gain {gain} must not exceed unity");
    }

    #[test]
    fn is_monotonic_in_the_a_priori_estimate() {
        // A larger previous clean estimate (more confidence in signal presence) never lowers the gain.
        let gain = gain();
        let low = gain.gain(4.0, 1.0, 0.5);
        let high = gain.gain(4.0, 1.0, 5.0);
        assert!(
            high >= low,
            "gain must be non-decreasing in Â_prev² ({low} → {high})"
        );
    }
}
