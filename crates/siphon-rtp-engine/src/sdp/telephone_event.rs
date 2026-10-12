//! The RFC 4733 telephone-event payload types of an audio stream, and which of them goes with the
//! codec a leg ends up on.
//!
//! An offer may declare the event payload more than once, at different clock rates: a wideband
//! terminal lists `telephone-event/16000` for its 16 kHz codecs and `telephone-event/8000` for its
//! narrowband ones. RFC 4733 §2.1 ties the event stream to the clock of the audio it accompanies,
//! so the payload type a leg uses follows the codec that was selected for it, and RFC 3264 §6.1
//! has the answer describe that payload type exactly as the offer did.

use siphon_rtp_codec::factory::CodecSpec;

use super::MediaInfo;

/// One telephone-event payload type, as the SDP that declared it mapped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelephoneEvent {
    /// The RTP payload type.
    pub payload_type: u8,
    /// The RTP clock rate of its `a=rtpmap`.
    pub clock_rate_hz: u32,
}

impl TelephoneEvent {
    /// The clock rate of an event payload type whose rate was not recorded: the 8 kHz every
    /// telephone-event implementation has (RFC 4733 §2.1), and what the engine presented for all
    /// of them before it kept the rate.
    pub const DEFAULT_CLOCK_RATE_HZ: u32 = 8000;

    /// The payload type of `declared` that accompanies `codec`: the first at the codec's RTP
    /// clock rate, else the first declared. The fallback keeps events working for a party that
    /// offers a wideband codec with only `telephone-event/8000`, which RFC 4733 does not describe
    /// and endpoints do anyway; it is still presented at the rate that party gave it.
    #[must_use]
    pub fn accompanying(declared: &[Self], codec: Option<&CodecSpec>) -> Option<Self> {
        codec
            .and_then(|codec| {
                declared
                    .iter()
                    .find(|event| event.clock_rate_hz == codec.clock_rate_hz)
            })
            .or(declared.first())
            .copied()
    }

    /// The `a=rtpmap` line of this payload type (RFC 4733 §7.1.1).
    pub(super) fn rtpmap_line(self) -> String {
        format!(
            "a=rtpmap:{} telephone-event/{}",
            self.payload_type, self.clock_rate_hz
        )
    }
}

impl MediaInfo {
    /// Every telephone-event payload type the stream declares, in `a=rtpmap` order.
    #[must_use]
    pub fn telephone_events(&self) -> Vec<TelephoneEvent> {
        self.rtpmaps
            .iter()
            .filter(|map| map.encoding_name.eq_ignore_ascii_case("telephone-event"))
            .map(|map| TelephoneEvent {
                payload_type: map.payload_type,
                clock_rate_hz: map.clock_rate_hz,
            })
            .collect()
    }

    /// The first RFC 4733 telephone-event payload type declared on this stream, if any, whatever
    /// its clock rate.
    #[must_use]
    pub fn telephone_event_payload_type(&self) -> Option<u8> {
        self.telephone_events()
            .first()
            .map(|event| event.payload_type)
    }

    /// The telephone-event payload type that accompanies this stream's primary codec.
    #[must_use]
    pub fn primary_telephone_event(&self) -> Option<TelephoneEvent> {
        TelephoneEvent::accompanying(&self.telephone_events(), self.primary_codec().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{force_answer_codec, parse};
    use super::*;

    /// An offer of AMR-WB and AMR with telephone-event at both clock rates, 16 kHz listed first.
    const BOTH_RATES: &str = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\n\
         t=0 0\r\nm=audio 49152 RTP/AVP 104 102 105 100\r\na=rtpmap:104 AMR-WB/16000\r\n\
         a=rtpmap:102 AMR/8000\r\na=rtpmap:105 telephone-event/16000\r\na=fmtp:105 0-15\r\n\
         a=rtpmap:100 telephone-event/8000\r\na=fmtp:100 0-15\r\n";

    const WIDEBAND: TelephoneEvent = TelephoneEvent {
        payload_type: 105,
        clock_rate_hz: 16_000,
    };
    const NARROWBAND: TelephoneEvent = TelephoneEvent {
        payload_type: 100,
        clock_rate_hz: 8000,
    };

    #[test]
    fn every_declared_event_payload_type_is_read_with_its_clock_rate() {
        let info = parse(BOTH_RATES).expect("parse");
        assert_eq!(info.telephone_events(), [WIDEBAND, NARROWBAND]);
        assert_eq!(info.primary_telephone_event(), Some(WIDEBAND));
    }

    #[test]
    fn the_event_payload_type_follows_the_clock_rate_of_the_codec() {
        let declared = [WIDEBAND, NARROWBAND];
        let at = |name: &str, clock_rate_hz: u32| {
            let codec = CodecSpec::new(96, name, clock_rate_hz, 1, 20);
            TelephoneEvent::accompanying(&declared, Some(&codec))
        };
        assert_eq!(at("AMR-WB", 16_000), Some(WIDEBAND));
        assert_eq!(at("AMR", 8000), Some(NARROWBAND));
        // G.722 samples at 16 kHz on an 8 kHz RTP clock (RFC 3551 §4.5.2): the clock decides.
        assert_eq!(at("G722", 8000), Some(NARROWBAND));
        // No event payload at the codec's rate: the first one declared, at its own rate.
        assert_eq!(at("opus", 48_000), Some(WIDEBAND));
        assert_eq!(
            TelephoneEvent::accompanying(&declared, None),
            Some(WIDEBAND)
        );
        // A party that declares only the 8 kHz event next to a wideband codec keeps it.
        let wideband = CodecSpec::new(104, "AMR-WB", 16_000, 1, 20);
        assert_eq!(
            TelephoneEvent::accompanying(&[NARROWBAND], Some(&wideband)),
            Some(NARROWBAND)
        );
        assert_eq!(TelephoneEvent::accompanying(&[], Some(&wideband)), None);
    }

    #[test]
    fn an_answer_maps_the_event_payload_type_at_the_rate_it_was_offered() {
        let far = "v=0\r\no=- 2 2 IN IP4 192.0.2.20\r\ns=-\r\nc=IN IP4 192.0.2.20\r\nt=0 0\r\n\
                   m=audio 40000 RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\n\
                   a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\n";
        let amr_wb = CodecSpec::new(104, "AMR-WB", 16_000, 1, 20);
        let answer = force_answer_codec(far, &amr_wb, Some(WIDEBAND));
        let lines: Vec<&str> = answer.lines().collect();
        assert!(lines.contains(&"m=audio 40000 RTP/AVP 104 105"), "{answer}");
        assert!(
            lines.contains(&"a=rtpmap:105 telephone-event/16000"),
            "{answer}"
        );
        assert!(!answer.contains("telephone-event/8000"), "{answer}");
    }
}
