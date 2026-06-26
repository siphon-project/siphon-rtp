//! Voice-quality estimation: an ITU-T G.107 **E-model** R-factor and its MOS mapping, computed from
//! the loss / delay / jitter an RTCP receiver report exposes. This is the QoS metric the engine
//! ships to Homer (as the JSON payload of a HEP3 report capture — see the crate root).
//!
//! Narrowband E-model (R0 = 93.2). Codec equipment-impairment factors `Ie` and packet-loss
//! robustness `Bpl` are per ITU-T G.113 Appendix I for the narrowband codecs; wideband codecs
//! (G.722, AMR-WB, Opus) are placed on the same scale as a pragmatic approximation — a wideband
//! E-model (G.107.1) is a later refinement. Pure `f64` math, deterministic and unit-testable.

/// Codecs the estimator knows equipment-impairment / loss-robustness factors for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// G.711 (PCMU/PCMA).
    G711,
    /// G.722 (wideband; approximated on the narrowband scale).
    G722,
    /// G.729 / G.729A.
    G729,
    /// G.723.1 (6.3 kbit/s).
    G723_1,
    /// AMR narrowband (~12.2 kbit/s).
    AmrNb,
    /// AMR wideband (approximated on the narrowband scale).
    AmrWb,
    /// Opus (approximated on the narrowband scale).
    Opus,
}

impl Codec {
    /// A short codec name for QoS reports.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Codec::G711 => "G711",
            Codec::G722 => "G722",
            Codec::G729 => "G729",
            Codec::G723_1 => "G723.1",
            Codec::AmrNb => "AMR-NB",
            Codec::AmrWb => "AMR-WB",
            Codec::Opus => "Opus",
        }
    }

    /// `(Ie, Bpl)` — equipment impairment factor and packet-loss robustness factor.
    /// Narrowband values are ITU-T G.113 Appendix I; wideband codecs are approximations.
    fn impairment_factors(self) -> (f64, f64) {
        match self {
            Codec::G711 => (0.0, 25.1),
            Codec::G722 => (0.0, 25.1),
            Codec::G729 => (11.0, 19.0),
            Codec::G723_1 => (15.0, 16.1),
            Codec::AmrNb => (7.0, 10.0),
            Codec::AmrWb => (2.0, 18.0),
            Codec::Opus => (1.0, 20.0),
        }
    }
}

/// The transmission impairments observed for a stream over a reporting interval.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Impairments {
    /// Packet loss over the interval, as a percentage (0–100).
    pub loss_percent: f64,
    /// One-way mouth-to-ear delay in milliseconds (≈ RTT/2 + fixed processing).
    pub one_way_delay_ms: f64,
    /// Interarrival jitter in milliseconds (RFC 3550); a de-jitter buffer adds ≈ 2× this to delay.
    pub jitter_ms: f64,
}

impl Impairments {
    /// Derive impairments from an RTCP receiver-report block (RFC 3550 §6.4.1) plus a round-trip
    /// time. `fraction_lost` is the 8-bit field (lost/256 over the interval); `jitter` is in RTP
    /// timestamp units at `clock_rate_hz`; one-way delay is taken as half the RTT.
    #[must_use]
    pub fn from_rtcp(fraction_lost: u8, jitter: u32, clock_rate_hz: u32, rtt_ms: f64) -> Self {
        let loss_percent = f64::from(fraction_lost) / 256.0 * 100.0;
        let jitter_ms = if clock_rate_hz > 0 {
            f64::from(jitter) / f64::from(clock_rate_hz) * 1000.0
        } else {
            0.0
        };
        Self {
            loss_percent,
            one_way_delay_ms: rtt_ms / 2.0,
            jitter_ms,
        }
    }
}

/// The base E-model R-factor for an ideal narrowband connection (ITU-T G.107 default).
const R0: f64 = 93.2;

/// The E-model R-factor (0–100; higher is better) for `codec` under `impairments` (ITU-T G.107,
/// with the default advantage factor `A = 0` and simultaneous-impairment `Is = 0`).
#[must_use]
pub fn r_factor(codec: Codec, impairments: Impairments) -> f64 {
    // Effective delay: the de-jitter buffer holds back ≈ 2× the jitter on top of the network delay.
    let delay = impairments.one_way_delay_ms + 2.0 * impairments.jitter_ms;
    // Delay impairment Id (G.107 §7.4 approximation): a linear term plus a steeper penalty past the
    // ~177 ms "knee" where interactivity degrades.
    let delay_impairment = 0.024 * delay + 0.11 * (delay - 177.3).max(0.0);

    // Effective equipment impairment Ie_eff (G.107 §7.5): the codec's base impairment grows toward
    // 95 as loss rises, tempered by the codec's packet-loss robustness Bpl.
    let (ie, bpl) = codec.impairment_factors();
    let loss = impairments.loss_percent.max(0.0);
    let ie_eff = ie + (95.0 - ie) * (loss / (loss + bpl));

    (R0 - delay_impairment - ie_eff).clamp(0.0, 100.0)
}

/// Map an E-model R-factor to a Mean Opinion Score (ITU-T G.107 Annex B), clamped to `[1.0, 4.5]`.
#[must_use]
pub fn mos(r_factor: f64) -> f64 {
    if r_factor <= 0.0 {
        return 1.0;
    }
    if r_factor >= 100.0 {
        return 4.5;
    }
    let mos = 1.0 + 0.035 * r_factor + r_factor * (r_factor - 60.0) * (100.0 - r_factor) * 7.0e-6;
    mos.clamp(1.0, 4.5)
}

/// Convenience: the estimated MOS for `codec` under `impairments`.
#[must_use]
pub fn estimate_mos(codec: Codec, impairments: Impairments) -> f64 {
    mos(r_factor(codec, impairments))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean() -> Impairments {
        Impairments {
            loss_percent: 0.0,
            one_way_delay_ms: 0.0,
            jitter_ms: 0.0,
        }
    }

    #[test]
    fn pristine_g711_is_near_toll_quality() {
        let mos = estimate_mos(Codec::G711, clean());
        assert!((4.3..=4.5).contains(&mos), "G.711 clean MOS ~4.4, got {mos}");
    }

    #[test]
    fn loss_degrades_mos_monotonically() {
        let none = estimate_mos(Codec::G711, clean());
        let some = estimate_mos(
            Codec::G711,
            Impairments {
                loss_percent: 5.0,
                ..clean()
            },
        );
        let lots = estimate_mos(
            Codec::G711,
            Impairments {
                loss_percent: 20.0,
                ..clean()
            },
        );
        assert!(none > some, "5% loss lowers MOS ({none} -> {some})");
        assert!(some > lots, "20% loss lowers it further ({some} -> {lots})");
        assert!(lots >= 1.0, "MOS never drops below 1.0");
    }

    #[test]
    fn excessive_delay_crosses_the_interactivity_knee() {
        // Below the ~177 ms knee, delay barely hurts; well above it, the steeper term bites.
        let low = r_factor(
            Codec::G711,
            Impairments {
                one_way_delay_ms: 100.0,
                ..clean()
            },
        );
        let high = r_factor(
            Codec::G711,
            Impairments {
                one_way_delay_ms: 400.0,
                ..clean()
            },
        );
        assert!(low - high > 20.0, "delay past the knee costs R sharply ({low} -> {high})");
    }

    #[test]
    fn jitter_adds_to_effective_delay() {
        let no_jitter = r_factor(Codec::G711, clean());
        let jittery = r_factor(
            Codec::G711,
            Impairments {
                jitter_ms: 50.0,
                ..clean()
            },
        );
        assert!(no_jitter > jittery, "jitter inflates buffering delay and lowers R");
    }

    #[test]
    fn lower_bitrate_codec_scores_below_g711_at_equal_conditions() {
        let g711 = estimate_mos(Codec::G711, clean());
        let g729 = estimate_mos(Codec::G729, clean());
        assert!(g711 > g729, "G.729 (Ie=11) < G.711 (Ie=0): {g711} vs {g729}");
    }

    #[test]
    fn mos_is_clamped_to_the_valid_range() {
        assert_eq!(mos(-10.0), 1.0);
        assert_eq!(mos(150.0), 4.5);
    }

    #[test]
    fn impairments_from_rtcp_fields() {
        // fraction_lost 128/256 = 50%; jitter 160 units @ 8 kHz = 20 ms; RTT 100 ms → 50 ms one-way.
        let impairments = Impairments::from_rtcp(128, 160, 8000, 100.0);
        assert!((impairments.loss_percent - 50.0).abs() < 1e-9);
        assert!((impairments.jitter_ms - 20.0).abs() < 1e-9);
        assert!((impairments.one_way_delay_ms - 50.0).abs() < 1e-9);
        // A zero clock rate is tolerated (no divide-by-zero).
        assert_eq!(Impairments::from_rtcp(0, 99, 0, 0.0).jitter_ms, 0.0);
    }
}
