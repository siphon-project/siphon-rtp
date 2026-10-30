//! The one codec a forwarding room carries, and which offered codecs a seat may use to join it.
//!
//! A forwarding room never decodes: it copies the source's RTP payload to every other seat
//! (RFC 3550 §7.1, a translator does not touch the encoding). So the room needs no encoder or
//! decoder for its codec, and a codec this build cannot transcode (AMR-WB without the `amr` feature)
//! forwards fine. What it does need is that every seat reads the payload the same way, which is a
//! matter of the payload format, not of the codec's name alone:
//!
//! * the encoding name, the clock rate and the channel count (RFC 3264 §6.1: the same format);
//! * for AMR and AMR-WB, `octet-align` (RFC 4867 §4.4: bandwidth-efficient and octet-aligned
//!   payloads put the same frames in different bits, so copying one to a seat expecting the other
//!   delivers garbage);
//! * for G.729, `annexb` (RFC 3555 §4.1.13: with `annexb=no` there are no SID frames).
//!
//! The AMR `mode-set` is not part of the payload format but it bounds what the source may send
//! (RFC 4867 §8.1: only modes of the set are sent). The room's set is the first seat's; a later seat
//! is answered with the room's set (RFC 4867 §8.3.1: the answer's mode-set is a subset of the
//! offer's), so it is refused if its own offer excludes a mode the room may send.

use siphon_rtp_codec::factory::CodecSpec;

/// The codec of a forwarding room, fixed by its first seat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomCodec {
    /// The first seat's spec for the codec. Its payload type is that seat's own; every other seat
    /// answers with its own number (RFC 3264 §6.1, payload types are per-direction names).
    reference: CodecSpec,
}

/// Whether the room can carry a codec at all.
///
/// Comfort noise and telephone-event are companions of an audio codec, not codecs of their own, and
/// an AMR configuration the engine does not implement (CRC, robust sorting, interleaving) is a
/// payload layout a forwarder could copy but never validate, so it is declined as everywhere else.
fn forwardable(spec: &CodecSpec) -> Result<(), String> {
    if spec.is_telephone_event() || spec.encoding_name == "CN" {
        return Err("a companion payload, not an audio codec".to_string());
    }
    if let Some(reason) = spec.amr_unsupported() {
        return Err(reason.to_string());
    }
    Ok(())
}

impl RoomCodec {
    /// Fix the room's codec from the first seat's choice among its `offered` codecs (RFC 3264 §6.1
    /// order: the offerer's preference). `Err` names why each offered codec was passed over.
    ///
    /// # Errors
    /// A reason listing every offered codec and why the room cannot carry it.
    pub fn from_offer(offered: &[CodecSpec]) -> Result<(Self, CodecSpec), String> {
        let mut reasons = Vec::new();
        for spec in offered {
            match forwardable(spec) {
                Ok(()) => {
                    return Ok((
                        Self {
                            reference: spec.clone(),
                        },
                        spec.clone(),
                    ));
                }
                Err(reason) => reasons.push(format!(
                    "{}/{} payload type {}: {reason}",
                    spec.encoding_name, spec.clock_rate_hz, spec.payload_type
                )),
            }
        }
        if reasons.is_empty() {
            return Err("offer has no audio codec".to_string());
        }
        Err(format!(
            "no offered codec can be forwarded: {}",
            reasons.join("; ")
        ))
    }

    /// The room's codec as its first seat offered it.
    #[must_use]
    pub fn spec(&self) -> &CodecSpec {
        &self.reference
    }

    /// The RTP clock rate the room's timestamps run at (RFC 3550 §5.1).
    #[must_use]
    pub fn clock_rate_hz(&self) -> u32 {
        self.reference.clock_rate_hz
    }

    /// The codec as a refusal names it, e.g. `AMR-WB/16000 (bandwidth-efficient)`.
    #[must_use]
    pub fn describe(&self) -> String {
        let spec = &self.reference;
        let mut text = format!("{}/{}", spec.encoding_name, spec.clock_rate_hz);
        if spec.channels > 1 {
            text.push_str(&format!("/{}", spec.channels));
        }
        if spec.is_amr() {
            text.push_str(if octet_aligned(spec) {
                " (octet-aligned)"
            } else {
                " (bandwidth-efficient)"
            });
        }
        if spec.encoding_name == "G729" && !spec.annex_b {
            text.push_str(" (annexb=no)");
        }
        text
    }

    /// Why `offered` is not the room's codec, or `None` when it is.
    fn mismatch(&self, offered: &CodecSpec) -> Option<String> {
        let room = &self.reference;
        if offered.encoding_name != room.encoding_name
            || offered.clock_rate_hz != room.clock_rate_hz
            || offered.channels != room.channels
        {
            return Some("a different codec".to_string());
        }
        if room.is_amr() {
            // RFC 4867 §4.4: the two payload layouts are not interchangeable.
            if octet_aligned(offered) != octet_aligned(room) {
                return Some(if octet_aligned(room) {
                    "bandwidth-efficient where the room is octet-aligned (RFC 4867 §4.4)"
                        .to_string()
                } else {
                    "octet-aligned where the room is bandwidth-efficient (RFC 4867 §4.4)"
                        .to_string()
                });
            }
            // RFC 4867 §8.1 / §8.3.1: an empty set is every mode. The seat is answered with the
            // room's set, which must therefore be inside what the seat offered.
            let covers = |mode: u8| offered.allowed_modes.contains(&mode);
            let seat_allows_every_mode = offered.allowed_modes.is_empty();
            let room_modes_covered = if room.allowed_modes.is_empty() {
                seat_allows_every_mode
            } else {
                seat_allows_every_mode || room.allowed_modes.iter().all(|&mode| covers(mode))
            };
            if !room_modes_covered {
                return Some("a mode-set that excludes modes the room may send".to_string());
            }
        }
        if room.encoding_name == "G729" && offered.annex_b != room.annex_b {
            return Some("a different annexb setting (RFC 3555 §4.1.13)".to_string());
        }
        None
    }

    /// The seat's spec for the room codec: the first of its `offered` codecs (offer order) that
    /// reads the room's payload, carrying the seat's own payload type and the room's mode-set, which
    /// is what the answer presents (RFC 3264 §6.1, RFC 4867 §8.3.1).
    ///
    /// # Errors
    /// A reason naming the room's codec and why each offered codec is not it.
    pub fn admit(&self, offered: &[CodecSpec]) -> Result<CodecSpec, String> {
        let mut reasons = Vec::new();
        for spec in offered {
            match self.mismatch(spec) {
                None => {
                    let mut answer = spec.clone();
                    answer
                        .allowed_modes
                        .clone_from(&self.reference.allowed_modes);
                    return Ok(answer);
                }
                Some(reason) => reasons.push(format!(
                    "{}/{} payload type {}: {reason}",
                    spec.encoding_name, spec.clock_rate_hz, spec.payload_type
                )),
            }
        }
        let offer = if reasons.is_empty() {
            "the offer has no audio codec".to_string()
        } else {
            reasons.join("; ")
        };
        Err(format!(
            "the room carries {} and the seat does not offer it: {offer}",
            self.describe()
        ))
    }
}

impl RoomCodec {
    /// The first of the `offered` codecs (offer order) a seat could be transcoded in: the engine has
    /// a decoder and an encoder for both it and the room's codec, and its packetization interval is
    /// the room's. The spec carries the seat's own payload type and parameters, which is what its
    /// answer presents. Used for a seat that [`Self::admit`] refused: the room then decodes the
    /// source once per packet and encodes once per codec group (see the transcode module).
    ///
    /// # Errors
    /// A reason naming each offered codec and why it cannot be transcoded (a build without the `amr`
    /// feature says so).
    pub fn admit_cross(&self, offered: &[CodecSpec]) -> Result<CodecSpec, String> {
        let mut reasons = Vec::new();
        for spec in offered {
            match super::transcode::check_pair(&self.reference, spec) {
                Ok(()) => return Ok(spec.clone()),
                Err(reason) => reasons.push(format!(
                    "{}/{} payload type {}: {reason}",
                    spec.encoding_name, spec.clock_rate_hz, spec.payload_type
                )),
            }
        }
        if reasons.is_empty() {
            return Err("the offer has no audio codec".to_string());
        }
        Err(reasons.join("; "))
    }
}

/// `octet-align=1` (RFC 4867 §8.1); absent reads as bandwidth-efficient.
fn octet_aligned(spec: &CodecSpec) -> bool {
    spec.amr.is_some_and(|params| params.octet_aligned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::sdp;

    /// An offer line set for one AMR-WB payload type with the given fmtp.
    fn amr_wb_offer(payload_type: u8, fmtp: &str) -> Vec<CodecSpec> {
        let text = format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
             m=audio 4000 RTP/AVP {payload_type}\r\na=rtpmap:{payload_type} AMR-WB/16000\r\n\
             a=fmtp:{payload_type} {fmtp}\r\n"
        );
        sdp::parse(&text).unwrap().audio_codecs()
    }

    fn g711_offer() -> Vec<CodecSpec> {
        let text = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                    m=audio 4000 RTP/AVP 0 8 101\r\na=rtpmap:101 telephone-event/8000\r\n";
        sdp::parse(text).unwrap().audio_codecs()
    }

    #[test]
    fn the_first_seat_fixes_the_codec_in_offer_order() {
        let (room, chosen) = RoomCodec::from_offer(&g711_offer()).unwrap();
        assert_eq!(chosen.encoding_name, "PCMU");
        assert_eq!(room.clock_rate_hz(), 8000);
        assert_eq!(room.describe(), "PCMU/8000");
    }

    #[test]
    fn a_codec_this_build_cannot_transcode_is_still_forwarded() {
        // AMR-WB has no encoder or decoder without the `amr` feature; forwarding needs neither.
        let (room, chosen) = RoomCodec::from_offer(&amr_wb_offer(96, "octet-align=1")).unwrap();
        assert_eq!(chosen.encoding_name, "AMR-WB");
        assert_eq!(room.describe(), "AMR-WB/16000 (octet-aligned)");
    }

    #[test]
    fn comfort_noise_and_unsupported_amr_layouts_are_passed_over_with_a_reason() {
        let text = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                    m=audio 4000 RTP/AVP 13\r\n";
        let offered = sdp::parse(text).unwrap().audio_codecs();
        let reason = RoomCodec::from_offer(&offered).unwrap_err();
        assert!(reason.contains("CN/8000"), "{reason}");
        assert!(RoomCodec::from_offer(&amr_wb_offer(96, "crc=1"))
            .unwrap_err()
            .contains("crc=1"));
        assert_eq!(
            RoomCodec::from_offer(&[]).unwrap_err(),
            "offer has no audio codec"
        );
    }

    #[test]
    fn a_later_seat_answers_with_its_own_payload_type() {
        let (room, _) = RoomCodec::from_offer(&amr_wb_offer(96, "octet-align=1")).unwrap();
        let answer = room.admit(&amr_wb_offer(111, "octet-align=1")).unwrap();
        assert_eq!(answer.payload_type, 111);
    }

    #[test]
    fn an_octet_align_mismatch_is_refused_both_ways_naming_the_room_codec() {
        let (octet, _) = RoomCodec::from_offer(&amr_wb_offer(96, "octet-align=1")).unwrap();
        let reason = octet.admit(&amr_wb_offer(96, "octet-align=0")).unwrap_err();
        assert!(reason.contains("AMR-WB/16000 (octet-aligned)"), "{reason}");
        assert!(reason.contains("bandwidth-efficient"), "{reason}");
        let (efficient, _) = RoomCodec::from_offer(&amr_wb_offer(96, "mode-set=2")).unwrap();
        // An absent octet-align is bandwidth-efficient (RFC 4867 §8.1), so it matches `=0`.
        assert!(efficient.admit(&amr_wb_offer(97, "octet-align=0")).is_ok());
        let reason = efficient
            .admit(&amr_wb_offer(97, "octet-align=1"))
            .unwrap_err();
        assert!(
            reason.contains("AMR-WB/16000 (bandwidth-efficient)"),
            "{reason}"
        );
    }

    #[test]
    fn the_seat_is_answered_with_the_rooms_mode_set() {
        let (room, _) = RoomCodec::from_offer(&amr_wb_offer(96, "mode-set=0,1,2")).unwrap();
        // A seat that allows every mode, or a superset, is answered with the room's set.
        let answer = room.admit(&amr_wb_offer(97, "octet-align=0")).unwrap();
        assert_eq!(answer.allowed_modes, vec![0, 1, 2]);
        let answer = room.admit(&amr_wb_offer(97, "mode-set=0,1,2,3")).unwrap();
        assert_eq!(answer.allowed_modes, vec![0, 1, 2]);
        // A seat whose own set leaves a room mode out cannot be sent that mode.
        let reason = room.admit(&amr_wb_offer(97, "mode-set=0,1")).unwrap_err();
        assert!(reason.contains("mode-set"), "{reason}");
    }

    #[test]
    fn a_room_that_allows_every_mode_needs_a_seat_that_allows_every_mode() {
        let (room, _) = RoomCodec::from_offer(&amr_wb_offer(96, "octet-align=0")).unwrap();
        assert!(room.admit(&amr_wb_offer(97, "octet-align=0")).is_ok());
        assert!(room.admit(&amr_wb_offer(97, "mode-set=2")).is_err());
    }

    #[test]
    fn a_different_codec_or_clock_rate_is_refused() {
        let (room, _) = RoomCodec::from_offer(&amr_wb_offer(96, "octet-align=0")).unwrap();
        let reason = room.admit(&g711_offer()).unwrap_err();
        assert!(
            reason.starts_with("the room carries AMR-WB/16000"),
            "{reason}"
        );
        assert!(reason.contains("PCMU/8000 payload type 0"), "{reason}");
        assert!(reason.contains("PCMA/8000 payload type 8"), "{reason}");
        assert_eq!(
            room.admit(&[]).unwrap_err(),
            "the room carries AMR-WB/16000 (bandwidth-efficient) and the seat does not offer it: \
             the offer has no audio codec"
        );
    }

    #[test]
    fn the_seat_may_offer_the_room_codec_after_others() {
        let (room, _) = RoomCodec::from_offer(&g711_offer()).unwrap();
        let text = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                    m=audio 4000 RTP/AVP 8 0\r\n";
        let offered = sdp::parse(text).unwrap().audio_codecs();
        assert_eq!(room.admit(&offered).unwrap().payload_type, 0);
    }
}
