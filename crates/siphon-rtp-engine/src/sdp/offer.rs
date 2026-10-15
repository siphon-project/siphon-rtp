//! The SDP offer the engine writes for a conference seat it calls out to.
//!
//! Every other SDP the engine emits is a rewrite of one a peer wrote. A room that dials a participant
//! (RFC 4579 §5.5) has no peer SDP to start from: the room is the offerer (RFC 3264 §5), so the offer
//! is written whole here, from the codecs the room can mix.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};

use siphon_rtp_codec::factory::{CodecSpec, OPUS_MAX_PTIME_MS};

use super::{egress_fmtp_line, rtpmap_line, TelephoneEvent, CRLF};

/// The RFC 4733 §3 events a room acts on: the sixteen DTMF events, which it reports as `dtmf`.
const DTMF_EVENTS: &str = "0-15";

/// Write a conference seat's offer: one `RTP/AVP` audio stream at `rtp` advertised as `advertised`,
/// listing `codecs` in preference order followed by `events`, sendrecv and RTCP-multiplexed.
///
/// - RFC 4566 §5: the mandatory lines in order. `o=` carries `session_id`, version 1.
/// - RFC 3264 §5.1: the `m=` format list is the offerer's preference order, and every format the
///   offerer lists is one it is willing to receive.
/// - RFC 4733 §2.1: one telephone-event per clock rate the codecs use, since an event stream is
///   clocked like the audio it accompanies.
/// - RFC 4566 §6 `a=maxptime`: the room's packetization ceiling, which is what it can receive in
///   any of the listed codecs (the RFC 7587 §6.1 maximum, the bound `seat::fit` enforces).
/// - RFC 5761 §5.1.1: `a=rtcp-mux`, because a seat is one muxed endpoint; the room sends its RTCP on
///   that endpoint whatever the answer says.
#[must_use]
pub fn conference_seat_offer(
    rtp: SocketAddr,
    advertised: IpAddr,
    session_id: u32,
    codecs: &[CodecSpec],
    events: &[TelephoneEvent],
) -> String {
    let addrtype = if advertised.is_ipv6() { "IP6" } else { "IP4" };
    let formats: Vec<String> = codecs
        .iter()
        .map(|codec| codec.payload_type)
        .chain(events.iter().map(|event| event.payload_type))
        .map(|payload_type| payload_type.to_string())
        .collect();
    let mut sdp = String::with_capacity(512);
    let _ = write!(
        sdp,
        "v=0{CRLF}o=- {session_id} 1 IN {addrtype} {advertised}{CRLF}s=-{CRLF}\
         c=IN {addrtype} {advertised}{CRLF}t=0 0{CRLF}m=audio {port} RTP/AVP {formats}{CRLF}",
        port = rtp.port(),
        formats = formats.join(" "),
    );
    for codec in codecs {
        let _ = write!(sdp, "{}{CRLF}", rtpmap_line(codec));
        if let Some(fmtp) = egress_fmtp_line(codec) {
            let _ = write!(sdp, "{fmtp}{CRLF}");
        }
    }
    for event in events {
        let _ = write!(
            sdp,
            "{}{CRLF}a=fmtp:{} {DTMF_EVENTS}{CRLF}",
            event.rtpmap_line(),
            event.payload_type
        );
    }
    let _ = write!(
        sdp,
        "a=ptime:20{CRLF}a=maxptime:{OPUS_MAX_PTIME_MS}{CRLF}a=sendrecv{CRLF}a=rtcp-mux{CRLF}"
    );
    sdp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> String {
        let codecs = [
            CodecSpec::new(111, "opus", 48_000, 2, 20),
            CodecSpec::new(9, "G722", 8000, 1, 20),
            CodecSpec::new(0, "PCMU", 8000, 1, 20),
        ];
        let events = [
            TelephoneEvent {
                payload_type: 110,
                clock_rate_hz: 48_000,
            },
            TelephoneEvent {
                payload_type: 101,
                clock_rate_hz: 8000,
            },
        ];
        conference_seat_offer(
            "127.0.0.1:30000".parse().expect("address"),
            "203.0.113.7".parse().expect("ip"),
            42,
            &codecs,
            &events,
        )
    }

    #[test]
    fn the_offer_is_written_line_by_line_in_rfc_4566_order() {
        assert_eq!(
            offer(),
            concat!(
                "v=0\r\n",
                "o=- 42 1 IN IP4 203.0.113.7\r\n",
                "s=-\r\n",
                "c=IN IP4 203.0.113.7\r\n",
                "t=0 0\r\n",
                "m=audio 30000 RTP/AVP 111 9 0 110 101\r\n",
                "a=rtpmap:111 OPUS/48000/2\r\n",
                "a=fmtp:111 stereo=0;sprop-stereo=0\r\n",
                "a=rtpmap:9 G722/8000\r\n",
                "a=rtpmap:0 PCMU/8000\r\n",
                "a=rtpmap:110 telephone-event/48000\r\n",
                "a=fmtp:110 0-15\r\n",
                "a=rtpmap:101 telephone-event/8000\r\n",
                "a=fmtp:101 0-15\r\n",
                "a=ptime:20\r\n",
                "a=maxptime:120\r\n",
                "a=sendrecv\r\n",
                "a=rtcp-mux\r\n",
            )
        );
    }

    #[test]
    fn the_engines_own_parser_reads_the_offer_back() {
        let info = super::super::parse(&offer()).expect("parse");
        assert_eq!(
            info.remote_rtp,
            "203.0.113.7:30000".parse::<SocketAddr>().expect("address")
        );
        assert!(info.rtcp_mux);
        assert!(!info.secure);
        assert_eq!(info.direction, super::super::MediaDirection::SendRecv);
        let names: Vec<(u8, String, u32)> = info
            .audio_codecs()
            .into_iter()
            .map(|codec| (codec.payload_type, codec.encoding_name, codec.clock_rate_hz))
            .collect();
        assert_eq!(
            names,
            [
                (111, "OPUS".to_string(), 48_000),
                (9, "G722".to_string(), 8000),
                (0, "PCMU".to_string(), 8000),
            ]
        );
        assert_eq!(info.telephone_events().len(), 2);
    }

    #[test]
    fn an_ipv6_seat_is_offered_in_ip6() {
        let sdp = conference_seat_offer(
            "[::1]:30000".parse().expect("address"),
            "2001:db8::7".parse().expect("ip"),
            1,
            &[CodecSpec::new(8, "PCMA", 8000, 1, 20)],
            &[],
        );
        assert!(sdp.contains("o=- 1 1 IN IP6 2001:db8::7\r\n"), "{sdp}");
        assert!(sdp.contains("c=IN IP6 2001:db8::7\r\n"), "{sdp}");
        assert!(sdp.contains("m=audio 30000 RTP/AVP 8\r\n"), "{sdp}");
    }
}
