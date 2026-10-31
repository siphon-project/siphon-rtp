//! The Codec Mode Request a stream's sender puts in its own RTP (RFC 4867 §4.3.1), tracked without
//! decoding the audio.
//!
//! A decoder only sees the CMR of the payloads it decodes. A forwarding room decodes one talker at a
//! time, but every seat keeps sending its own RTP (and its CMR) while it listens, so the request has
//! to be read off the packets themselves. This reuses the payload parser and the mode decision the
//! AMR codec acts on ([`crate::amr::rtp::read_payload`], [`crate::amr::mode_control::ModeControl`]),
//! so a request means here exactly what it means to an encoder: a cap on the mode sent back, ignored
//! when it names a mode outside the negotiated `mode-set` (RFC 4867 §4.3.1, "MUST be ignored"),
//! withdrawn by CMR 15.
//!
//! Without the `amr` feature there is no AMR codec and nothing to track: [`ModeRequestTracker::for_spec`]
//! is `None` for every spec.

use crate::factory::CodecSpec;

/// The Codec Mode Request of one AMR or AMR-WB stream, as the sender asks for the media sent back to
/// it.
#[derive(Debug, Clone)]
pub struct ModeRequestTracker {
    #[cfg(feature = "amr")]
    inner: tracker::Tracker,
}

impl ModeRequestTracker {
    /// A tracker for a stream negotiated as `spec`, or `None` when `spec` is not an AMR format this
    /// build carries (no `amr` feature, not AMR, or a configuration the codec refuses).
    #[must_use]
    pub fn for_spec(spec: &CodecSpec) -> Option<Self> {
        #[cfg(feature = "amr")]
        {
            tracker::Tracker::for_spec(spec).map(|inner| Self { inner })
        }
        #[cfg(not(feature = "amr"))]
        {
            let _ = spec;
            None
        }
    }

    /// Take the request in an RTP `payload` of the stream. A payload the AMR decoder would discard
    /// (malformed, or an undefined frame type) carries no request. Returns whether the
    /// [`Self::ceiling`] changed.
    pub fn observe(&mut self, payload: &[u8]) -> bool {
        #[cfg(feature = "amr")]
        {
            self.inner.observe(payload)
        }
        #[cfg(not(feature = "amr"))]
        {
            let _ = payload;
            false
        }
    }

    /// The highest speech mode the sender asked to receive, `None` while that leaves the encoder
    /// where it is by default: no request, a request for the default mode or above it, or one the
    /// mode-set does not allow. Always a mode of the negotiated `mode-set`.
    #[must_use]
    pub fn ceiling(&self) -> Option<u8> {
        #[cfg(feature = "amr")]
        {
            self.inner.ceiling()
        }
        #[cfg(not(feature = "amr"))]
        {
            None
        }
    }
}

#[cfg(feature = "amr")]
mod tracker {
    use crate::amr::mode_control::ModeControl;
    use crate::amr::rtp::{read_payload, PayloadFormat, Variant};
    use crate::factory::{amr_rtp_config, CodecSpec};

    #[derive(Debug, Clone)]
    pub(super) struct Tracker {
        format: PayloadFormat,
        variant: Variant,
        modes: ModeControl,
        /// The mode sent when nothing is requested.
        default_mode: u8,
    }

    impl Tracker {
        pub(super) fn for_spec(spec: &CodecSpec) -> Option<Self> {
            if !spec.is_amr() {
                return None;
            }
            let config = amr_rtp_config(spec).ok()?;
            let variant = if spec.encoding_name == "AMR" {
                Variant::Narrowband
            } else {
                Variant::Wideband
            };
            let modes = ModeControl::new(
                variant.highest_mode(),
                config.mode_set,
                config.preferred_mode,
            )?;
            Some(Self {
                format: config.format,
                variant,
                default_mode: modes.target(),
                modes,
            })
        }

        pub(super) fn observe(&mut self, payload: &[u8]) -> bool {
            let Ok(layout) = read_payload(payload, self.format, self.variant) else {
                return false;
            };
            let before = self.modes.target();
            self.modes.request(layout.cmr);
            self.modes.target() != before
        }

        pub(super) fn ceiling(&self) -> Option<u8> {
            let target = self.modes.target();
            (target != self.default_mode).then_some(target)
        }
    }
}

#[cfg(all(test, feature = "amr"))]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::amr::rtp::{write_payload, FrameSource, PayloadFormat, Variant};

    fn wideband(allowed: &[u8]) -> CodecSpec {
        CodecSpec::new(96, "AMR-WB", 16000, 1, 20).with_allowed_modes(allowed.to_vec())
    }

    /// An octet-aligned AMR-WB payload of one NO_DATA frame carrying `cmr` (RFC 4867 §4.4.1: the CMR
    /// is the first four bits; a NO_DATA frame has no speech bits).
    fn payload_with(cmr: u8) -> Vec<u8> {
        let frame = FrameSource {
            frame_type: 15,
            quality_ok: true,
            data: &[],
        };
        let mut out = [0u8; 8];
        let length = write_payload(
            PayloadFormat::OctetAligned,
            Variant::Wideband,
            cmr,
            &[frame],
            &mut out,
        )
        .unwrap();
        out[..length].to_vec()
    }

    fn octet_aligned(spec: CodecSpec) -> CodecSpec {
        let mut spec = spec;
        spec.amr = Some(crate::factory::AmrParams {
            octet_align: Some(true),
            ..Default::default()
        });
        spec
    }

    #[test]
    fn a_request_below_the_default_mode_is_a_ceiling_and_cmr_15_withdraws_it() {
        let mut tracker = ModeRequestTracker::for_spec(&octet_aligned(wideband(&[]))).unwrap();
        assert_eq!(tracker.ceiling(), None, "no request: the default mode");
        assert!(tracker.observe(&payload_with(2)));
        assert_eq!(tracker.ceiling(), Some(2));
        assert!(
            !tracker.observe(&payload_with(2)),
            "the same request changes nothing"
        );
        assert!(tracker.observe(&payload_with(15)), "CMR 15 withdraws it");
        assert_eq!(tracker.ceiling(), None);
    }

    #[test]
    fn a_request_for_the_default_mode_or_above_changes_nothing() {
        let mut tracker =
            ModeRequestTracker::for_spec(&octet_aligned(wideband(&[0, 2, 4]))).unwrap();
        assert!(
            !tracker.observe(&payload_with(4)),
            "4 is the default of the set"
        );
        assert_eq!(tracker.ceiling(), None);
    }

    #[test]
    fn a_request_outside_the_mode_set_is_ignored_and_a_request_inside_it_holds() {
        let mut tracker =
            ModeRequestTracker::for_spec(&octet_aligned(wideband(&[0, 2, 5]))).unwrap();
        assert!(tracker.observe(&payload_with(2)));
        assert_eq!(tracker.ceiling(), Some(2));
        assert!(
            !tracker.observe(&payload_with(3)),
            "3 is not in the mode-set: ignored"
        );
        assert_eq!(
            tracker.ceiling(),
            Some(2),
            "the earlier request stays in force"
        );
        assert!(
            !tracker.observe(&payload_with(7)),
            "7 is not in the mode-set either"
        );
        assert_eq!(tracker.ceiling(), Some(2));
    }

    #[test]
    fn a_reserved_cmr_value_is_ignored() {
        let mut tracker = ModeRequestTracker::for_spec(&octet_aligned(wideband(&[]))).unwrap();
        assert!(tracker.observe(&payload_with(3)));
        assert!(
            !tracker.observe(&payload_with(12)),
            "reserved values MUST be ignored"
        );
        assert_eq!(tracker.ceiling(), Some(3));
    }

    #[test]
    fn a_payload_the_codec_would_discard_carries_no_request() {
        let mut tracker = ModeRequestTracker::for_spec(&octet_aligned(wideband(&[]))).unwrap();
        assert!(!tracker.observe(&[]), "empty");
        assert!(
            !tracker.observe(&[0x20]),
            "a table of contents entry with nothing behind it"
        );
        assert_eq!(tracker.ceiling(), None);
    }

    #[test]
    fn narrowband_and_the_bandwidth_efficient_format_are_read_too() {
        let spec = CodecSpec::new(97, "AMR", 8000, 1, 20);
        let mut tracker = ModeRequestTracker::for_spec(&spec).unwrap();
        let mut out = [0u8; 8];
        let frame = FrameSource {
            frame_type: 15,
            quality_ok: true,
            data: &[],
        };
        let length = write_payload(
            PayloadFormat::BandwidthEfficient,
            Variant::Narrowband,
            1,
            &[frame],
            &mut out,
        )
        .unwrap();
        assert!(tracker.observe(&out[..length]));
        assert_eq!(tracker.ceiling(), Some(1));
    }

    #[test]
    fn a_spec_that_is_not_amr_has_no_tracker() {
        assert!(ModeRequestTracker::for_spec(&CodecSpec::new(0, "PCMU", 8000, 1, 20)).is_none());
        let refused = CodecSpec::new(96, "AMR-WB", 16000, 1, 20).with_allowed_modes(vec![9]);
        assert!(ModeRequestTracker::for_spec(&refused).is_none());
    }
}

#[cfg(all(test, not(feature = "amr")))]
mod tests {
    use super::*;

    #[test]
    fn without_the_amr_feature_nothing_is_tracked() {
        assert!(
            ModeRequestTracker::for_spec(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20)).is_none()
        );
    }
}
