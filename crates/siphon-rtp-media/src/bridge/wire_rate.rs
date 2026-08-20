//! The **WebSocket wire sample rate**: validating a requested rate and building the conversion into
//! it, shared by the send-only tee ([`super::tee`]) and the takeover bridge ([`super::session`]).
//!
//! The wire rate is the rate of the L16 the WS server actually exchanges, and it is **independent of
//! the leg's codec rate**: an 8 kHz G.711 call can stream at 16 kHz, and a server may render downlink
//! audio at 24 kHz into that same 8 kHz call. The rate a leg's codec happens to decode at is only the
//! *default*, never a constraint.
//!
//! Both shells validate through here **before** anything is attached, so an unserviceable rate is a
//! clean control-plane rejection rather than a half-built stream: the wire frame length, the ring and
//! scratch sizing, the noise-suppressor/echo-canceller construction and the resampler all derive from
//! this one number, and each of them fails differently (or silently) if it is nonsense.

use siphon_rtp_dsp::resample::{ResampleError, Resampler};

use super::audio::MAX_SAMPLE_RATE_HZ;

/// Lowest wire sample rate the bridge accepts, in Hz — the narrowband telephony rate every codec on
/// this path can be converted from (G.711 samples at 8000 Hz, RFC 3551 §4.5.14). Nothing below it is
/// a rate a voice consumer asks for, and a very low rate would make the per-frame sample count a
/// rounding artefact rather than audio.
pub const MIN_WIRE_SAMPLE_RATE_HZ: u32 = 8_000;

/// Highest wire sample rate the bridge accepts, in Hz. Single-sourced from
/// [`MAX_SAMPLE_RATE_HZ`] — the ceiling every buffer on this path is already sized against
/// ([`super::audio::MAX_FRAME_SAMPLES`]), and the highest rate any codec here runs at (RFC 7587 §4.1
/// pins Opus at 48 kHz). Accepting more would announce a frame the staging buffers cannot hold.
pub const MAX_WIRE_SAMPLE_RATE_HZ: u32 = MAX_SAMPLE_RATE_HZ as u32;

/// Samples per millisecond are computed as `sample_rate / 1000` throughout the bridge (the wire frame
/// length, the ring capacity, the resample scratch), so a rate that is not a whole number of samples
/// per millisecond would silently truncate — 11025 Hz would frame as if it were 11000 Hz, drifting
/// against the server's clock by 25 samples a second with nothing anywhere reporting an error.
pub const WIRE_SAMPLE_RATE_GRANULARITY_HZ: u32 = 1_000;

/// Why a requested WebSocket wire sample rate cannot be served.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireRateError {
    /// The requested rate was zero — no frame length, no resampler, no stream.
    #[error("websocket wire sample rate must not be zero")]
    Zero,
    /// The requested rate is outside the supported band.
    #[error(
        "websocket wire sample rate {requested} Hz is outside the supported \
         {MIN_WIRE_SAMPLE_RATE_HZ}–{MAX_WIRE_SAMPLE_RATE_HZ} Hz range"
    )]
    OutOfRange {
        /// The rate that was asked for, in Hz.
        requested: u32,
    },
    /// The requested rate is not a whole number of samples per millisecond.
    #[error(
        "websocket wire sample rate {requested} Hz is not a whole number of samples per \
         millisecond (it must be a multiple of {WIRE_SAMPLE_RATE_GRANULARITY_HZ} Hz)"
    )]
    NotWholeSamplesPerMillisecond {
        /// The rate that was asked for, in Hz.
        requested: u32,
    },
    /// The resampler into (or out of) the requested rate could not be built.
    #[error("no resampler from {from} Hz to {to} Hz: {source}")]
    Resampler {
        /// Input rate of the conversion, in Hz.
        from: u32,
        /// Output rate of the conversion, in Hz.
        to: u32,
        /// The DSP crate's reason.
        source: ResampleError,
    },
}

/// Validate a controller-requested wire sample rate, returning it unchanged when it is serviceable.
///
/// Rejects rather than clamps: a caller that asked for 44100 Hz and silently got 44000 would hear a
/// slow drift with nothing to point at, and a caller that asked for 96000 and silently got 48000
/// would frame every buffer at half the length it expects.
pub fn validate_wire_sample_rate(requested: u32) -> Result<u32, WireRateError> {
    if requested == 0 {
        return Err(WireRateError::Zero);
    }
    if !(MIN_WIRE_SAMPLE_RATE_HZ..=MAX_WIRE_SAMPLE_RATE_HZ).contains(&requested) {
        return Err(WireRateError::OutOfRange { requested });
    }
    if !requested.is_multiple_of(WIRE_SAMPLE_RATE_GRANULARITY_HZ) {
        return Err(WireRateError::NotWholeSamplesPerMillisecond { requested });
    }
    Ok(requested)
}

/// The conversion from `from` Hz to `to` Hz, or `None` when the two rates are already equal.
///
/// `None` is the whole point of the "ask for what you already have" case: a tee or bridge whose wire
/// rate matches its leg pays **nothing** — no resampler is built, no scratch is reserved, and the
/// per-frame path is byte-for-byte the one that shipped before wire rates were selectable.
pub fn wire_resampler(from: u32, to: u32) -> Result<Option<Resampler>, WireRateError> {
    if from == to {
        return Ok(None);
    }
    Resampler::new(from, to)
        .map(Some)
        .map_err(|source| WireRateError::Resampler { from, to, source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_rates_the_bridge_can_frame() {
        for rate in [8_000u32, 16_000, 24_000, 32_000, 44_000, 48_000] {
            assert_eq!(
                validate_wire_sample_rate(rate),
                Ok(rate),
                "{rate} Hz must be serviceable"
            );
        }
    }

    #[test]
    fn rejects_a_zero_rate_with_its_own_reason() {
        assert_eq!(validate_wire_sample_rate(0), Err(WireRateError::Zero));
    }

    #[test]
    fn rejects_a_rate_below_the_narrowband_floor() {
        assert_eq!(
            validate_wire_sample_rate(4_000),
            Err(WireRateError::OutOfRange { requested: 4_000 })
        );
    }

    #[test]
    fn rejects_a_rate_above_the_buffer_ceiling() {
        // 96 kHz would announce a frame longer than `MAX_FRAME_SAMPLES` can stage at the ptime cap.
        assert_eq!(
            validate_wire_sample_rate(96_000),
            Err(WireRateError::OutOfRange { requested: 96_000 })
        );
    }

    #[test]
    fn rejects_a_rate_that_is_not_a_whole_number_of_samples_per_millisecond() {
        // 44100 Hz is a real audio rate, and exactly the trap: `44100 / 1000 * 20` frames 880 samples,
        // 2 short of the 882 one 20 ms period actually holds.
        assert_eq!(
            validate_wire_sample_rate(44_100),
            Err(WireRateError::NotWholeSamplesPerMillisecond { requested: 44_100 })
        );
    }

    #[test]
    fn the_ceiling_tracks_the_buffers_it_protects() {
        // The band must stay inside what the staging buffers were sized for, or a legal rate could
        // announce a frame the core silently truncates.
        assert_eq!(MAX_WIRE_SAMPLE_RATE_HZ, MAX_SAMPLE_RATE_HZ as u32);
        // Both endpoints of the band are themselves serviceable — an off-by-one in the range check
        // would make the documented floor or ceiling unusable.
        assert_eq!(
            validate_wire_sample_rate(MIN_WIRE_SAMPLE_RATE_HZ),
            Ok(MIN_WIRE_SAMPLE_RATE_HZ)
        );
        assert_eq!(
            validate_wire_sample_rate(MAX_WIRE_SAMPLE_RATE_HZ),
            Ok(MAX_WIRE_SAMPLE_RATE_HZ)
        );
    }

    #[test]
    fn asking_for_the_rate_you_already_have_builds_no_resampler() {
        assert!(
            wire_resampler(8_000, 8_000)
                .expect("identity is serviceable")
                .is_none(),
            "a matching rate must cost nothing at all"
        );
    }

    #[test]
    fn a_differing_rate_builds_the_conversion_in_that_direction() {
        let up = wire_resampler(8_000, 16_000)
            .expect("serviceable")
            .expect("a conversion");
        assert_eq!(up.input_rate(), 8_000);
        assert_eq!(up.output_rate(), 16_000);
        assert!(!up.is_identity());

        let down = wire_resampler(24_000, 8_000)
            .expect("serviceable")
            .expect("a conversion");
        assert_eq!(down.input_rate(), 24_000);
        assert_eq!(down.output_rate(), 8_000);
    }

    #[test]
    fn a_zero_rate_conversion_surfaces_the_dsp_error_rather_than_panicking() {
        let error = wire_resampler(0, 8_000).expect_err("zero input rate");
        assert_eq!(
            error,
            WireRateError::Resampler {
                from: 0,
                to: 8_000,
                source: ResampleError::ZeroRate,
            }
        );
        // And it renders with both rates, so an operator can see which direction failed.
        assert!(error.to_string().contains("0 Hz to 8000 Hz"), "{error}");
    }

    #[test]
    fn every_rejection_names_the_rate_that_was_asked_for() {
        for rate in [0u32, 4_000, 96_000, 44_100] {
            let Err(error) = validate_wire_sample_rate(rate) else {
                continue;
            };
            let rendered = error.to_string();
            assert!(
                rendered.contains("websocket wire sample rate"),
                "{rate}: {rendered}"
            );
        }
    }
}
