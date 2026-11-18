//! What a room needs to know about an H.264 RTP payload to start a receiver on a keyframe
//! (RFC 6184 §5): whether the packet begins an IDR picture, and the SPS and PPS it carries.
//!
//! Video stays opaque to the room, so nothing here decodes: the NAL unit header (RFC 6184 §1.3) and,
//! for the aggregation and fragmentation packet types, the framing around it are read, and no more.
//! Only the packetization modes the room carries are understood: single NAL unit packets (§5.6),
//! STAP-A (§5.7.1) and FU-A (§5.8). Interleaved packets (STAP-B, MTAP, FU-B) are not classified.

/// NAL unit type of a coded slice of an IDR picture (ITU-T H.264 Table 7-1).
pub const NAL_IDR_SLICE: u8 = 5;
/// NAL unit type of a sequence parameter set.
pub const NAL_SPS: u8 = 7;
/// NAL unit type of a picture parameter set.
pub const NAL_PPS: u8 = 8;
/// RFC 6184 §5.4: single-time aggregation packet A.
const NAL_STAP_A: u8 = 24;
/// RFC 6184 §5.4: fragmentation unit A.
const NAL_FU_A: u8 = 28;

/// What [`scan`] found in one RTP payload, borrowing from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Scan<'a> {
    /// The packet begins an IDR slice: a single NAL unit of type 5, an aggregated one inside a
    /// STAP-A, or an FU-A whose start bit is set on a type 5 (RFC 6184 §5.6-§5.8).
    pub keyframe_start: bool,
    /// A sequence parameter set NAL unit, header included, when the packet carries one whole.
    pub sps: Option<&'a [u8]>,
    /// A picture parameter set NAL unit, header included, when the packet carries one whole.
    pub pps: Option<&'a [u8]>,
}

/// Classify one H.264 RTP payload (RFC 6184 §5.2: the first octet is the NAL unit header, whose type
/// says whether it is a single NAL unit, an aggregation or a fragment).
///
/// Never panics and never reads past `payload`: a truncated STAP-A is read as far as it is whole, and
/// a payload that sets the forbidden zero bit (RFC 6184 §1.3) or is empty classifies as nothing.
#[must_use]
pub fn scan(payload: &[u8]) -> Scan<'_> {
    let Some(&header) = payload.first() else {
        return Scan::default();
    };
    if header & 0x80 != 0 {
        return Scan::default(); // forbidden_zero_bit
    }
    let mut found = Scan::default();
    match header & 0x1F {
        NAL_STAP_A => {
            let mut rest = &payload[1..];
            // RFC 6184 §5.7.1: each aggregated unit is a 16-bit size and then the NAL unit.
            while let Some(size) = rest.get(..2) {
                let size = usize::from(u16::from_be_bytes([size[0], size[1]]));
                let Some(unit) = rest.get(2..2 + size) else {
                    break;
                };
                classify_single(unit, &mut found);
                rest = &rest[2 + size..];
            }
        }
        NAL_FU_A => {
            // RFC 6184 §5.8: FU header S, E, R and the type of the fragmented NAL unit.
            if let Some(&fragment) = payload.get(1) {
                found.keyframe_start = fragment & 0x80 != 0 && fragment & 0x1F == NAL_IDR_SLICE;
            }
        }
        _ => classify_single(payload, &mut found),
    }
    found
}

/// Classify a whole NAL unit: a single NAL unit packet's payload, or one unit of a STAP-A.
fn classify_single<'a>(unit: &'a [u8], found: &mut Scan<'a>) {
    let Some(&header) = unit.first() else {
        return;
    };
    if header & 0x80 != 0 {
        return;
    }
    match header & 0x1F {
        NAL_IDR_SLICE => found.keyframe_start = true,
        NAL_SPS => found.sps = Some(unit),
        NAL_PPS => found.pps = Some(unit),
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    const IDR: [u8; 3] = [0x65, 0x88, 0x84];
    const SPS: [u8; 4] = [0x67, 0x64, 0x00, 0x1F];
    const PPS: [u8; 3] = [0x68, 0xEE, 0x3C];
    const NON_IDR: [u8; 3] = [0x41, 0x9A, 0x00];

    /// A STAP-A (RFC 6184 §5.7.1) of `units`: header 0x78 (NRI 3, type 24), then size and unit each.
    fn stap_a(units: &[&[u8]]) -> Vec<u8> {
        let mut payload = vec![0x78];
        for unit in units {
            payload.extend_from_slice(&(unit.len() as u16).to_be_bytes());
            payload.extend_from_slice(unit);
        }
        payload
    }

    #[test]
    fn a_single_idr_slice_begins_a_keyframe() {
        let found = scan(&IDR);
        assert!(found.keyframe_start);
        assert_eq!((found.sps, found.pps), (None, None));
    }

    #[test]
    fn a_non_idr_slice_does_not() {
        assert_eq!(scan(&NON_IDR), Scan::default());
    }

    #[test]
    fn a_single_sps_and_pps_are_returned_whole_with_their_header() {
        let sps = scan(&SPS);
        assert_eq!(sps.sps, Some(&SPS[..]));
        assert!(!sps.keyframe_start);
        assert_eq!(scan(&PPS).pps, Some(&PPS[..]));
    }

    #[test]
    fn a_stap_a_with_parameter_sets_and_an_idr_reports_all_three() {
        let payload = stap_a(&[&SPS, &PPS, &IDR]);
        let found = scan(&payload);
        assert!(found.keyframe_start);
        assert_eq!(found.sps, Some(&SPS[..]));
        assert_eq!(found.pps, Some(&PPS[..]));
    }

    #[test]
    fn a_stap_a_of_non_idr_slices_is_not_a_keyframe() {
        let payload = stap_a(&[&NON_IDR, &NON_IDR]);
        assert_eq!(scan(&payload), Scan::default());
    }

    #[test]
    fn a_truncated_stap_a_is_read_as_far_as_it_is_whole() {
        let mut payload = stap_a(&[&SPS, &IDR]);
        payload.truncate(payload.len() - 1); // the IDR unit lost its last octet
        let found = scan(&payload);
        assert_eq!(found.sps, Some(&SPS[..]));
        assert!(!found.keyframe_start);
        // A size field with one octet.
        assert_eq!(scan(&[0x78, 0x00]), Scan::default());
        // A size that overruns.
        assert_eq!(scan(&[0x78, 0xFF, 0xFF, 0x65]), Scan::default());
    }

    #[test]
    fn an_fu_a_start_of_an_idr_is_a_keyframe_start_and_its_middle_and_end_are_not() {
        // RFC 6184 §5.8: indicator 0x7C (NRI 3, type 28), then S|E|R|type.
        assert!(scan(&[0x7C, 0x85, 0x88]).keyframe_start, "start, type 5");
        assert!(!scan(&[0x7C, 0x05, 0x88]).keyframe_start, "middle");
        assert!(!scan(&[0x7C, 0x45, 0x88]).keyframe_start, "end");
        assert!(
            !scan(&[0x7C, 0x81, 0x88]).keyframe_start,
            "start of a non-IDR"
        );
        assert!(
            scan(&[0x7C, 0x85]).keyframe_start,
            "no fragment data needed"
        );
        assert!(!scan(&[0x7C]).keyframe_start, "no FU header");
    }

    #[test]
    fn empty_input_and_a_set_forbidden_bit_classify_as_nothing() {
        assert_eq!(scan(&[]), Scan::default());
        assert_eq!(scan(&[0xE5, 0x88]), Scan::default());
        let payload = stap_a(&[&[0xE5, 0x88]]);
        assert_eq!(scan(&payload), Scan::default());
    }

    #[test]
    fn interleaved_types_are_not_classified() {
        // STAP-B (25), MTAP16 (26), MTAP24 (27) and FU-B (29) are packetization mode 2.
        for header in [0x79u8, 0x7A, 0x7B, 0x7D] {
            assert_eq!(scan(&[header, 0x85, 0x88, 0x84]), Scan::default());
        }
    }

    use proptest::prelude::*;

    proptest! {
        /// Arbitrary bytes classify without a panic, and what is returned lies inside the input.
        #[test]
        fn scan_never_panics_and_borrows_from_the_input(
            bytes in prop::collection::vec(any::<u8>(), 0..512)
        ) {
            let found = scan(&bytes);
            for part in [found.sps, found.pps].into_iter().flatten() {
                let start = part.as_ptr() as usize - bytes.as_ptr() as usize;
                prop_assert!(start + part.len() <= bytes.len());
            }
        }
    }
}
