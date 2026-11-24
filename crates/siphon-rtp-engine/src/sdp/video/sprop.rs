//! The out-of-band parameter sets of an H.264 stream: `sprop-parameter-sets` (RFC 6184 §8.1), a
//! comma-separated list of base64-encoded (RFC 4648 §4) SPS and PPS NAL units that a sender puts in
//! its SDP so a receiver can start decoding without waiting for them in-band.
//!
//! An `answer_local` caller's own answer is frozen (RFC 3264 §8), so it can never be told the far
//! party's. The engine reads them here and hands them over in-band ahead of the first IDR
//! ([`crate::video_injector`]).

use siphon_rtp_media::h264::{ParameterSets, MAX_PARAMETER_SET, NAL_PPS, NAL_SPS};
use siphon_rtp_stun::turn::base64_decode;

use super::{packetization_mode, parameter};

/// The parameter sets named by the `sprop-parameter-sets` of an `a=fmtp` line (`parameters` is the
/// text after the payload type), or `None` when the line names none, carries a malformed one, or
/// is packetization mode 2.
///
/// - A list with any entry that is not base64, is empty, is larger than
///   [`MAX_PARAMETER_SET`] octets, sets the forbidden bit (RFC 6184 §1.3) or is not an SPS (type 7)
///   or a PPS (type 8) is refused whole: half a list may pair a PPS with the wrong SPS.
/// - At most one SPS and one PPS are kept, the first of each.
/// - Packetization mode 2 (interleaved, RFC 6184 §5.4) forbids the single NAL unit packets the
///   injector sends and its packets cannot be classified, so the sets are not used there. The mode
///   is 0 when the line names none (RFC 6184 §8.1).
#[must_use]
pub fn sprop_parameter_sets(parameters: &str) -> Option<Box<ParameterSets>> {
    let value = parameter(parameters, "sprop-parameter-sets")?;
    if packetization_mode(parameters) > 1 {
        return None;
    }
    let mut sets = ParameterSets::new();
    let (mut have_sps, mut have_pps) = (false, false);
    for entry in value.split(',') {
        let unit = decode_entry(entry.trim())?;
        let header = *unit.first()?;
        if header & 0x80 != 0 || unit.len() > MAX_PARAMETER_SET {
            return None;
        }
        match header & 0x1F {
            NAL_SPS if !have_sps => have_sps = sets.store(&unit, true),
            NAL_PPS if !have_pps => have_pps = sets.store(&unit, false),
            NAL_SPS | NAL_PPS => {}
            _ => return None,
        }
    }
    (have_sps || have_pps).then_some(sets)
}

/// One base64 entry, padded when a sender left the `=` off (RFC 4648 §3.2 allows a profile to omit
/// it, and real SDP does).
fn decode_entry(entry: &str) -> Option<Vec<u8>> {
    if entry.is_empty() {
        return None;
    }
    let decoded = if entry.len().is_multiple_of(4) {
        base64_decode(entry)?
    } else {
        let mut padded = entry.to_string();
        while !padded.len().is_multiple_of(4) {
            padded.push('=');
        }
        base64_decode(&padded)?
    };
    (!decoded.is_empty()).then_some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPS: [u8; 9] = [0x67, 0x42, 0xE0, 0x1F, 0xDA, 0x01, 0x40, 0x16, 0xE8];
    const PPS: [u8; 4] = [0x68, 0xCE, 0x3C, 0x80];
    const BOTH: &str = "packetization-mode=1;sprop-parameter-sets=Z0LgH9oBQBbo,aM48gA==";

    #[test]
    fn an_sps_and_a_pps_are_decoded_and_kept() {
        let sets = sprop_parameter_sets(BOTH).expect("valid");
        assert_eq!((sets.sps(), sets.pps()), (Some(&SPS[..]), Some(&PPS[..])));
    }

    #[test]
    fn the_parameter_name_is_matched_without_case_and_around_other_parameters() {
        let sets = sprop_parameter_sets(
            "profile-level-id=42e01f; Sprop-Parameter-Sets = Z0LgH9oBQBbo,aM48gA== ;packetization-mode=0",
        )
        .expect("valid");
        assert_eq!(sets.sps(), Some(&SPS[..]));
    }

    #[test]
    fn a_pps_alone_and_an_sps_alone_are_kept() {
        let pps = sprop_parameter_sets("sprop-parameter-sets=aM48gA==").expect("valid");
        assert_eq!((pps.sps(), pps.pps()), (None, Some(&PPS[..])));
        let sps = sprop_parameter_sets("sprop-parameter-sets=Z0LgH9oBQBbo").expect("valid");
        assert_eq!((sps.sps(), sps.pps()), (Some(&SPS[..]), None));
    }

    #[test]
    fn only_the_first_sps_and_the_first_pps_are_kept() {
        // A second SPS (0x67 0x4D ...) and a second PPS (0x68 0xEB ...), "Z00AH9k=" and "aOvjyyA=".
        let sets =
            sprop_parameter_sets("sprop-parameter-sets=Z0LgH9oBQBbo,aM48gA==,Z00AH9k=,aOvjyyA=")
                .expect("valid");
        assert_eq!((sets.sps(), sets.pps()), (Some(&SPS[..]), Some(&PPS[..])));
    }

    #[test]
    fn padding_a_sender_left_off_is_tolerated() {
        let sets = sprop_parameter_sets("sprop-parameter-sets=Z0LgH9oBQBbo,aM48gA").expect("valid");
        assert_eq!(sets.pps(), Some(&PPS[..]));
    }

    #[test]
    fn a_line_without_the_parameter_names_nothing() {
        assert!(sprop_parameter_sets("packetization-mode=1;profile-level-id=42e01f").is_none());
        assert!(sprop_parameter_sets("").is_none());
    }

    #[test]
    fn malformed_lists_are_refused_whole() {
        for bad in [
            "sprop-parameter-sets=",
            "sprop-parameter-sets=!!notbase64!!",
            "sprop-parameter-sets=Z0LgH9oBQBbo,",
            "sprop-parameter-sets=,aM48gA==",
            "sprop-parameter-sets=Z0LgH9oBQBbo,@@@@",
            // Forbidden zero bit set (0xE7 ...): "5wAA".
            "sprop-parameter-sets=5wAA",
        ] {
            assert!(sprop_parameter_sets(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_unit_that_is_neither_an_sps_nor_a_pps_refuses_the_list() {
        // An IDR slice (0x65 ...) and an SEI (0x06 ...): "ZYiEAA==", "BgEB".
        for bad in [
            "sprop-parameter-sets=Z0LgH9oBQBbo,ZYiEAA==",
            "sprop-parameter-sets=BgEB",
        ] {
            assert!(sprop_parameter_sets(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn an_oversize_unit_refuses_the_list() {
        let mut unit = vec![0x67];
        unit.resize(MAX_PARAMETER_SET + 1, 0x11);
        let encoded = encode(&unit);
        assert!(sprop_parameter_sets(&format!("sprop-parameter-sets={encoded}")).is_none());
        unit.truncate(MAX_PARAMETER_SET);
        let encoded = encode(&unit);
        assert!(sprop_parameter_sets(&format!("sprop-parameter-sets={encoded}")).is_some());
    }

    #[test]
    fn packetization_mode_two_names_no_sets_and_the_default_mode_is_zero() {
        let line = "sprop-parameter-sets=Z0LgH9oBQBbo,aM48gA==";
        assert!(sprop_parameter_sets(&format!("packetization-mode=2;{line}")).is_none());
        assert!(sprop_parameter_sets(&format!("packetization-mode=0;{line}")).is_some());
        assert!(sprop_parameter_sets(line).is_some(), "mode 0 when absent");
    }

    /// Base64 (RFC 4648 §4) for building test input; independent of the decoder under test.
    fn encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let word = chunk.iter().enumerate().fold(0u32, |word, (index, byte)| {
                word | u32::from(*byte) << (16 - 8 * index)
            });
            for index in 0..4 {
                if index <= chunk.len() {
                    out.push(char::from(
                        ALPHABET[(word >> (18 - 6 * index) & 0x3F) as usize],
                    ));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    proptest::proptest! {
        /// Whatever an SDP line says, parsing it never panics, and what it keeps fits the buffers.
        #[test]
        fn arbitrary_fmtp_text_never_panics(parameters in ".{0,300}") {
            let _ = sprop_parameter_sets(&parameters);
            let _ = sprop_parameter_sets(&format!("sprop-parameter-sets={parameters}"));
        }
    }
}
