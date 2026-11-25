//! The `audio/EVS` `a=fmtp` parameters of an SDP stream (3GPP TS 26.445 A.3), on their way to the
//! codec spec the decoder is built from.
//!
//! Every fmtp line is read this way, because the codec of a payload type is not known until the
//! rtpmaps are, and the parameters are only used for one that turns out to be EVS. A parameter the
//! registration defines with a value it does not permit gives [`EvsParams::malformed`] rather than a
//! default, so the payload type is relayed as it always was and never decoded on a guess.

use siphon_rtp_codec::factory::{CodecSpec, EvsParams};

/// Parse an `a=fmtp:<pt> ...` attribute value as the EVS parameters of that payload type. A line with
/// no EVS parameter in it records nothing, so a payload type that declared none keeps the
/// registration's defaults.
pub(super) fn parse_fmtp(value: &str) -> Option<(u8, EvsParams)> {
    let (payload_type, params) = super::split_fmtp(value)?;
    let parsed = EvsParams::parse(params).unwrap_or_else(|error| {
        tracing::debug!(
            target: "siphon_rtp::sdp",
            payload_type,
            %error,
            "an a=fmtp line is not valid audio/EVS parameters"
        );
        EvsParams {
            malformed: true,
            ..EvsParams::default()
        }
    });
    (parsed != EvsParams::default()).then_some((payload_type, parsed))
}

/// The spec of an EVS payload type with the parameters its peer declared: `hf-only` decides how every
/// payload is read, and the widest `bw` the peer sends decides the decoder's output rate.
pub(super) fn negotiated(
    spec: CodecSpec,
    declared: &[(u8, EvsParams)],
    payload_type: u8,
) -> CodecSpec {
    let params = declared
        .iter()
        .find(|(declared_type, _)| *declared_type == payload_type)
        .map(|(_, params)| *params);
    spec.with_evs_params(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_with_evs_parameters_is_recorded_under_its_payload_type() {
        let (payload_type, params) = parse_fmtp("fmtp:110 hf-only=1;bw=nb-wb").expect("recorded");
        assert_eq!(payload_type, 110);
        assert!(params.header_full_only());
        assert!(!params.malformed);
    }

    #[test]
    fn a_line_without_any_is_not_a_declaration() {
        assert_eq!(parse_fmtp("fmtp:110 some-future-parameter=1"), None);
        assert_eq!(parse_fmtp("fmtp:110 annexb=no"), None);
        assert_eq!(parse_fmtp("rtpmap:110 EVS/16000"), None);
    }

    #[test]
    fn a_parameter_the_registration_does_not_permit_is_malformed_not_dropped() {
        let (_, params) = parse_fmtp("fmtp:110 hf-only=maybe").expect("recorded");
        assert!(params.malformed);
    }

    #[test]
    fn only_the_declaring_payload_type_gets_the_parameters() {
        let declared = [(
            110,
            EvsParams {
                hf_only: Some(true),
                ..EvsParams::default()
            },
        )];
        let evs = |payload_type| CodecSpec::new(payload_type, "EVS", 16_000, 1, 20);
        assert!(negotiated(evs(110), &declared, 110).evs.is_some());
        assert_eq!(negotiated(evs(111), &declared, 111).evs, None);
    }
}
