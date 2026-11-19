//! The SDP offer the engine writes for a conference seat it calls out to.
//!
//! Every other SDP the engine emits is a rewrite of one a peer wrote. A room that dials a participant
//! (RFC 4579 §5.5) has no peer SDP to start from: the room is the offerer (RFC 3264 §5), so the offer
//! is written whole here, from the codecs the room can mix.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};

use siphon_rtp_codec::factory::{CodecSpec, OPUS_MAX_PTIME_MS};

use siphon_rtp_ice::{Candidate, END_OF_CANDIDATES_ATTRIBUTE};

use super::data_channel::{DATA_CHANNEL_SCTP_PORT, MAX_MESSAGE_SIZE};
use super::{egress_fmtp_line, rtpmap_line, Fingerprint, Setup, TelephoneEvent, CRLF};

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
    write_audio_attributes(&mut sdp, codecs, events);
    sdp
}

/// The audio section's format attributes, shared by the plain and the WebRTC offer: `a=rtpmap` /
/// `a=fmtp` per codec, the telephone-events, the packetization and `a=sendrecv` / `a=rtcp-mux`.
fn write_audio_attributes(sdp: &mut String, codecs: &[CodecSpec], events: &[TelephoneEvent]) {
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
}

/// What turns a seat's offer into a WebRTC one (RFC 8829 / RFC 8839 / RFC 5763): the ICE identity the
/// engine mints for the seat, its DTLS certificate fingerprint, and whether the MCPTT floor control
/// rides a data channel section.
#[derive(Debug, Clone, Copy)]
pub struct WebrtcOffer<'a> {
    /// The engine's ICE username fragment for the seat.
    pub ufrag: &'a str,
    /// The engine's ICE password for the seat.
    pub pwd: &'a str,
    /// The candidates gathered for the seat (RFC 8445 §5.1.1), written as `a=candidate` lines.
    pub candidates: &'a [Candidate],
    /// The engine's DTLS certificate fingerprint (RFC 8122 §5, RFC 5763 §5).
    pub fingerprint: &'a Fingerprint,
    /// Offer `m=application ... UDP/DTLS/SCTP webrtc-datachannel` (RFC 8841) bundled with the audio.
    pub data_channel: bool,
    /// Offer an `m=video` section bundled with the audio (RFC 8843).
    pub video: Option<WebrtcVideoOffer<'a>>,
}

/// What a bundled video section of a [`webrtc_seat_offer`] says.
#[derive(Debug, Clone, Copy)]
pub struct WebrtcVideoOffer<'a> {
    /// The `a=fmtp` parameters of the room's H.264 format (RFC 6184 §8.1), when it has one.
    pub fmtp: Option<&'a str>,
    /// `b=AS` in kilobits per second.
    pub bandwidth_kbps: Option<u32>,
}

/// The `a=mid` of the audio section of a [`webrtc_seat_offer`] (RFC 5888 §4).
pub const WEBRTC_AUDIO_MID: &str = "0";
/// The `a=mid` of the data channel section of a [`webrtc_seat_offer`].
pub const WEBRTC_DATA_CHANNEL_MID: &str = "1";
/// The `a=mid` of the video section of a [`webrtc_seat_offer`].
pub const WEBRTC_VIDEO_MID: &str = "2";

/// Write a WebRTC seat's offer: [`conference_seat_offer`]'s audio over `UDP/TLS/RTP/SAVPF` on a
/// transport the engine terminates (a browser member of a forwarding room).
///
/// - RFC 8829 §5.2.1 / RFC 5764 §4.1.2: `UDP/TLS/RTP/SAVPF`, keyed by the DTLS handshake, so no
///   `a=crypto`.
/// - RFC 5763 §5 / RFC 8842 §5.1: `a=fingerprint` of the engine's certificate and `a=setup:actpass`,
///   leaving the answerer to pick the DTLS role.
/// - RFC 8839 §5.1 / RFC 8445 §2.5: `a=ice-lite` (session level) with the seat's `a=ice-ufrag` /
///   `a=ice-pwd` and gathered candidates, closed by `a=end-of-candidates` (RFC 8838 §14) because
///   gathering ran to completion before the offer was written. The engine is a lite agent, so the
///   answerer controls (RFC 8445 §6.1.1).
/// - RFC 8843 §7.2: the offerer puts every section in one `a=group:BUNDLE`, each with an `a=mid`,
///   and repeats the transport attributes in each so the answerer can read either.
/// - RFC 8841 §5: the data channel section is `m=application <audio port> UDP/DTLS/SCTP
///   webrtc-datachannel` with `a=sctp-port` and `a=max-message-size`, on the audio's own port (the
///   engine runs one transport per seat).
#[must_use]
pub fn webrtc_seat_offer(
    rtp: SocketAddr,
    advertised: IpAddr,
    session_id: u32,
    codecs: &[CodecSpec],
    events: &[TelephoneEvent],
    webrtc: &WebrtcOffer<'_>,
) -> String {
    let addrtype = if advertised.is_ipv6() { "IP6" } else { "IP4" };
    let formats: Vec<String> = codecs
        .iter()
        .map(|codec| codec.payload_type)
        .chain(events.iter().map(|event| event.payload_type))
        .map(|payload_type| payload_type.to_string())
        .collect();
    let mut sdp = String::with_capacity(1024);
    let _ = write!(
        sdp,
        "v=0{CRLF}o=- {session_id} 1 IN {addrtype} {advertised}{CRLF}s=-{CRLF}t=0 0{CRLF}a=ice-lite{CRLF}"
    );
    let _ = write!(sdp, "a=group:BUNDLE {WEBRTC_AUDIO_MID}");
    if webrtc.data_channel {
        let _ = write!(sdp, " {WEBRTC_DATA_CHANNEL_MID}");
    }
    if webrtc.video.is_some() {
        let _ = write!(sdp, " {WEBRTC_VIDEO_MID}");
    }
    sdp.push_str(CRLF);
    let mut transport = String::new();
    let _ = write!(
        transport,
        "a=ice-ufrag:{}{CRLF}a=ice-pwd:{}{CRLF}a=ice-options:trickle ice2{CRLF}",
        webrtc.ufrag, webrtc.pwd
    );
    for candidate in webrtc.candidates {
        let _ = write!(transport, "{}{CRLF}", candidate.to_attribute_line());
    }
    let _ = write!(
        transport,
        "{END_OF_CANDIDATES_ATTRIBUTE}{CRLF}a={}{CRLF}a=setup:{}{CRLF}",
        webrtc.fingerprint.to_attribute_value(),
        Setup::Actpass.token()
    );
    let _ = write!(
        sdp,
        "m=audio {port} UDP/TLS/RTP/SAVPF {formats}{CRLF}c=IN {addrtype} {advertised}{CRLF}",
        port = rtp.port(),
        formats = formats.join(" "),
    );
    write_audio_attributes(&mut sdp, codecs, events);
    let _ = write!(sdp, "a=mid:{WEBRTC_AUDIO_MID}{CRLF}{transport}");
    if webrtc.data_channel {
        let _ = write!(
            sdp,
            "m=application {port} UDP/DTLS/SCTP webrtc-datachannel{CRLF}c=IN {addrtype} {advertised}{CRLF}\
             a=mid:{WEBRTC_DATA_CHANNEL_MID}{CRLF}{transport}\
             a=sctp-port:{DATA_CHANNEL_SCTP_PORT}{CRLF}a=max-message-size:{MAX_MESSAGE_SIZE}{CRLF}",
            port = rtp.port(),
        );
    }
    if let Some(video) = &webrtc.video {
        // RFC 8843 §7.2: on the audio's own port and connection, with the transport attributes
        // repeated, like the data channel; one payload type, the room's format, with the feedback the
        // room serves.
        let _ = write!(
            sdp,
            "m=video {port} UDP/TLS/RTP/SAVPF {payload_type}{CRLF}c=IN {addrtype} {advertised}{CRLF}",
            port = rtp.port(),
            payload_type = super::video::OFFER_PAYLOAD_TYPE,
        );
        if let Some(kbps) = video.bandwidth_kbps {
            let _ = write!(sdp, "b=AS:{kbps}{CRLF}");
        }
        let _ = write!(sdp, "a=mid:{WEBRTC_VIDEO_MID}{CRLF}{transport}");
        super::video::write_offered_format(&mut sdp, video.fmtp);
        sdp.push_str("a=sendrecv\r\na=rtcp-mux\r\n");
    }
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

    fn webrtc_offer(data_channel: bool) -> String {
        webrtc_offer_with(data_channel, None)
    }

    fn webrtc_offer_with(data_channel: bool, video: Option<WebrtcVideoOffer<'_>>) -> String {
        let address: SocketAddr = "127.0.0.1:30000".parse().expect("address");
        let mut gatherer =
            siphon_rtp_ice::Gatherer::new(siphon_rtp_ice::GatherConfig::host_only(address), 0);
        let _ = gatherer.poll(0);
        let candidates = gatherer.candidates().to_vec();
        let fingerprint = Fingerprint {
            hash_function: "sha-256".to_string(),
            bytes: (0u8..32).collect(),
        };
        webrtc_seat_offer(
            address,
            "203.0.113.7".parse().expect("ip"),
            42,
            &[CodecSpec::new(0, "PCMU", 8000, 1, 20)],
            &[],
            &WebrtcOffer {
                ufrag: "ENGUF",
                pwd: "engpassword01234567",
                candidates: &candidates,
                fingerprint: &fingerprint,
                data_channel,
                video,
            },
        )
    }

    #[test]
    fn the_webrtc_offer_carries_dtls_ice_lite_and_a_bundle() {
        let sdp = webrtc_offer(true);
        let lines: Vec<&str> = sdp.split("\r\n").collect();
        for expected in [
            "a=ice-lite",
            "a=group:BUNDLE 0 1",
            "m=audio 30000 UDP/TLS/RTP/SAVPF 0",
            "m=application 30000 UDP/DTLS/SCTP webrtc-datachannel",
            "a=mid:0",
            "a=mid:1",
            "a=rtcp-mux",
            "a=setup:actpass",
            "a=sctp-port:5000",
            "a=max-message-size:65536",
            "a=ice-ufrag:ENGUF",
            "a=ice-pwd:engpassword01234567",
            "a=end-of-candidates",
        ] {
            assert!(lines.contains(&expected), "{expected} in {sdp}");
        }
        // a=ice-lite and the group are session level: before the first m= line.
        let first_media = lines
            .iter()
            .position(|line| line.starts_with("m="))
            .expect("m=");
        assert!(lines[..first_media].contains(&"a=ice-lite"), "{sdp}");
        assert!(
            lines[..first_media].contains(&"a=group:BUNDLE 0 1"),
            "{sdp}"
        );
        assert!(!sdp.contains("a=crypto"), "{sdp}");
        // One association: the same fingerprint, credentials and role on both sections.
        assert_eq!(
            sdp.matches("a=fingerprint:sha-256 00:01:02:").count(),
            2,
            "{sdp}"
        );
        assert_eq!(sdp.matches("a=setup:actpass").count(), 2, "{sdp}");
        assert_eq!(sdp.matches("a=ice-ufrag:ENGUF").count(), 2, "{sdp}");
        assert!(sdp.contains("a=candidate:"), "{sdp}");
    }

    #[test]
    fn the_engines_own_parser_reads_the_webrtc_offer_back() {
        let sdp = webrtc_offer(true);
        let info = super::super::parse(&sdp).expect("parse");
        assert!(info.secure && info.dtls, "{info:?}");
        assert_eq!(info.setup, Some(Setup::Actpass));
        assert_eq!(
            info.fingerprint.as_ref().expect("fingerprint").bytes.len(),
            32
        );
        assert!(info.is_ice() && info.ice_lite);
        assert!(!info.candidates.is_empty());
        assert!(info.rtcp_mux);
        let channel = super::super::parse_data_channel(&sdp).expect("a bundled data channel");
        assert_eq!(
            (channel.audio_mid.as_str(), channel.mid.as_str()),
            ("0", "1")
        );
    }

    #[test]
    fn an_audio_only_webrtc_offer_has_no_data_channel_section() {
        let sdp = webrtc_offer(false);
        assert!(!sdp.contains("m=application"), "{sdp}");
        assert!(sdp.contains("a=group:BUNDLE 0\r\n"), "{sdp}");
        assert!(super::super::parse_data_channel(&sdp).is_none());
    }

    #[test]
    fn a_webrtc_offer_with_video_bundles_the_video_on_the_audios_transport() {
        let sdp = webrtc_offer_with(
            true,
            Some(WebrtcVideoOffer {
                fmtp: Some("profile-level-id=42e01f;packetization-mode=1"),
                bandwidth_kbps: Some(1200),
            }),
        );
        let lines: Vec<&str> = sdp.split("\r\n").collect();
        assert!(lines.contains(&"a=group:BUNDLE 0 1 2"), "{sdp}");
        let video_at = lines
            .iter()
            .position(|line| line.starts_with("m=video"))
            .expect("a video section");
        assert_eq!(
            lines[video_at], "m=video 30000 UDP/TLS/RTP/SAVPF 126",
            "the audio's port"
        );
        let video = &lines[video_at..];
        for expected in [
            "c=IN IP4 203.0.113.7",
            "b=AS:1200",
            "a=mid:2",
            "a=ice-ufrag:ENGUF",
            "a=setup:actpass",
            "a=rtpmap:126 H264/90000",
            "a=fmtp:126 profile-level-id=42e01f;packetization-mode=1",
            "a=rtcp-fb:126 nack",
            "a=rtcp-fb:126 nack pli",
            "a=rtcp-fb:126 ccm fir",
            "a=sendrecv",
            "a=rtcp-mux",
        ] {
            assert!(video.contains(&expected), "{expected}: {sdp}");
        }
        assert!(
            !sdp.contains("transport-cc") && !sdp.contains("goog-remb"),
            "{sdp}"
        );
        // The engine's own parser reads the section.
        let parsed = crate::sdp::video::parse_video(&sdp).expect("video");
        assert!(parsed.bundled);
        assert_eq!(parsed.mid.as_deref(), Some("2"));
        assert_eq!(parsed.transport, "UDP/TLS/RTP/SAVPF");
    }

    #[test]
    fn a_webrtc_offer_without_video_has_none_and_keeps_its_group() {
        let sdp = webrtc_offer(true);
        assert!(!sdp.contains("m=video"), "{sdp}");
        assert!(sdp.contains("a=group:BUNDLE 0 1\r\n"), "{sdp}");
    }
}
