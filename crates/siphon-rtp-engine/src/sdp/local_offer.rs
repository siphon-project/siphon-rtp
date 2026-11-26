//! The SDP offer of a single-leg call the engine makes itself (`offer_local`).
//!
//! A carrier INVITE without SDP asks the answerer to offer first (RFC 3261 §13.2.1), so the engine
//! is the offerer (RFC 3264 §5) of a call with one party and writes the whole offer: one audio
//! stream on the engine's media address, the codecs it can run both ways, and the keying and ICE
//! posture the controller asked for.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_ice::{Candidate, END_OF_CANDIDATES_ATTRIBUTE};
use siphon_rtp_srtp::sdes::CryptoAttribute;

use super::offer::write_format_attributes;
use super::{Fingerprint, Setup, TelephoneEvent, CRLF};

/// How the offered audio stream is secured.
#[derive(Debug, Clone, Copy)]
pub enum LocalOfferKeying<'a> {
    /// Plain `RTP/AVP`.
    Plain,
    /// SDES-SRTP (RFC 4568): `RTP/SAVP` with the engine's own `a=crypto` line.
    Sdes(&'a CryptoAttribute),
    /// DTLS-SRTP (RFC 5764): `UDP/TLS/RTP/SAVPF` with the engine's certificate fingerprint and the
    /// `a=setup` role it offers.
    Dtls {
        /// The fingerprint of the engine's certificate (RFC 8122 §5).
        fingerprint: &'a Fingerprint,
        /// The role offered: `actpass` unless the controller pinned one (RFC 5763 §5).
        setup: Setup,
        /// The `a=tls-id` naming the association (RFC 8842 §5.1).
        tls_id: &'a str,
    },
}

/// The engine's ICE identity for the offered stream (RFC 8839).
#[derive(Debug, Clone, Copy)]
pub struct LocalOfferIce<'a> {
    /// The engine's username fragment.
    pub ufrag: &'a str,
    /// The engine's password.
    pub pwd: &'a str,
    /// The gathered candidates (RFC 8445 §5.1.1), written in order.
    pub candidates: &'a [Candidate],
}

/// What [`local_audio_offer`] writes.
#[derive(Debug, Clone, Copy)]
pub struct LocalOffer<'a> {
    /// The engine's RTP endpoint (its port is the `m=` port).
    pub rtp: SocketAddr,
    /// The engine's separate RTCP port (RFC 3605 `a=rtcp`), when it has one: the RTCP port of an
    /// unmultiplexed offer, or the fallback of one that offers multiplexing (RFC 5761 §5.1.1).
    pub rtcp_port: Option<u16>,
    /// Offer `a=rtcp-mux` (RFC 5761 §5.1.1).
    pub rtcp_mux: bool,
    /// Also say multiplexing is the only RTCP transport on offer, `a=rtcp-mux-only` (RFC 8858 §3).
    pub rtcp_mux_only: bool,
    /// The address advertised in `o=` and `c=`.
    pub advertised: IpAddr,
    /// The `o=` session id.
    pub session_id: u32,
    /// The audio codecs, in preference order.
    pub codecs: &'a [CodecSpec],
    /// The telephone-event formats, after the codecs.
    pub events: &'a [TelephoneEvent],
    /// How the stream is secured.
    pub keying: LocalOfferKeying<'a>,
    /// The ICE identity, when the leg runs ICE.
    pub ice: Option<LocalOfferIce<'a>>,
}

/// Write the offer of a single-leg call.
///
/// - RFC 4566 §5: the mandatory lines in order, with the session-level connection line.
/// - RFC 3264 §5.1: the format list is the offerer's preference order, every format one the engine
///   will receive; telephone-event follows the codecs (RFC 4733 §2.1).
/// - RFC 4568 §6.1 / RFC 5764 §4.1.2 / RFC 5763 §5 / RFC 8842 §5.1: the transport profile and the
///   keying attributes of the chosen security.
/// - RFC 8839 §5.1 / RFC 8445 §2.5: a full agent, so no `a=ice-lite`; the candidates are complete
///   (gathering ran to the end before the offer was written, RFC 8838 §14).
/// - RFC 5761 §5.1.1 / RFC 3605 / RFC 8858: `a=rtcp-mux`, `a=rtcp` naming the separate RTCP port
///   (the fallback when multiplexing is only offered), and `a=rtcp-mux-only` when it is required.
#[must_use]
pub fn local_audio_offer(offer: &LocalOffer<'_>) -> String {
    let addrtype = if offer.advertised.is_ipv6() {
        "IP6"
    } else {
        "IP4"
    };
    let profile = match offer.keying {
        LocalOfferKeying::Plain => "RTP/AVP",
        LocalOfferKeying::Sdes(_) => "RTP/SAVP",
        LocalOfferKeying::Dtls { .. } => "UDP/TLS/RTP/SAVPF",
    };
    let formats: Vec<String> = offer
        .codecs
        .iter()
        .map(|codec| codec.payload_type)
        .chain(offer.events.iter().map(|event| event.payload_type))
        .map(|payload_type| payload_type.to_string())
        .collect();
    let advertised = offer.advertised;
    let mut sdp = String::with_capacity(1024);
    let _ = write!(
        sdp,
        "v=0{CRLF}o=- {session_id} 1 IN {addrtype} {advertised}{CRLF}s=-{CRLF}\
         c=IN {addrtype} {advertised}{CRLF}t=0 0{CRLF}m=audio {port} {profile} {formats}{CRLF}",
        session_id = offer.session_id,
        port = offer.rtp.port(),
        formats = formats.join(" "),
    );
    write_format_attributes(&mut sdp, offer.codecs, offer.events);
    let _ = write!(sdp, "a=ptime:20{CRLF}a=sendrecv{CRLF}");
    if let Some(port) = offer.rtcp_port {
        let _ = write!(sdp, "a=rtcp:{port}{CRLF}");
    }
    if offer.rtcp_mux {
        let _ = write!(sdp, "a=rtcp-mux{CRLF}");
    }
    if offer.rtcp_mux_only {
        let _ = write!(sdp, "a=rtcp-mux-only{CRLF}");
    }
    match offer.keying {
        LocalOfferKeying::Plain => {}
        LocalOfferKeying::Sdes(crypto) => {
            let _ = write!(sdp, "a={}{CRLF}", crypto.to_attribute_value());
        }
        LocalOfferKeying::Dtls {
            fingerprint,
            setup,
            tls_id,
        } => {
            let _ = write!(
                sdp,
                "a={}{CRLF}a=setup:{}{CRLF}a=tls-id:{tls_id}{CRLF}",
                fingerprint.to_attribute_value(),
                setup.token(),
            );
        }
    }
    if let Some(ice) = offer.ice {
        let _ = write!(
            sdp,
            "a=ice-ufrag:{}{CRLF}a=ice-pwd:{}{CRLF}a=ice-options:ice2{CRLF}",
            ice.ufrag, ice.pwd
        );
        for candidate in ice.candidates {
            let _ = write!(sdp, "{}{CRLF}", candidate.to_attribute_line());
        }
        let _ = write!(sdp, "{END_OF_CANDIDATES_ATTRIBUTE}{CRLF}");
    }
    sdp
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_srtp::sdes::CryptoSuite;

    fn codecs() -> Vec<CodecSpec> {
        vec![
            CodecSpec::new(8, "PCMA", 8000, 1, 20),
            CodecSpec::new(0, "PCMU", 8000, 1, 20),
        ]
    }

    fn events() -> Vec<TelephoneEvent> {
        vec![TelephoneEvent {
            payload_type: 101,
            clock_rate_hz: 8000,
        }]
    }

    fn offer<'a>(
        codecs: &'a [CodecSpec],
        events: &'a [TelephoneEvent],
        keying: LocalOfferKeying<'a>,
        rtcp_port: Option<u16>,
        ice: Option<LocalOfferIce<'a>>,
    ) -> LocalOffer<'a> {
        LocalOffer {
            rtp: "127.0.0.1:30000".parse().expect("address"),
            rtcp_port,
            rtcp_mux: rtcp_port.is_none(),
            rtcp_mux_only: false,
            advertised: "203.0.113.7".parse().expect("ip"),
            session_id: 42,
            codecs,
            events,
            keying,
            ice,
        }
    }

    #[test]
    fn a_plain_offer_is_written_line_by_line_in_rfc_4566_order() {
        let (codecs, events) = (codecs(), events());
        let text = local_audio_offer(&offer(
            &codecs,
            &events,
            LocalOfferKeying::Plain,
            Some(30001),
            None,
        ));
        assert_eq!(
            text,
            concat!(
                "v=0\r\n",
                "o=- 42 1 IN IP4 203.0.113.7\r\n",
                "s=-\r\n",
                "c=IN IP4 203.0.113.7\r\n",
                "t=0 0\r\n",
                "m=audio 30000 RTP/AVP 8 0 101\r\n",
                "a=rtpmap:8 PCMA/8000\r\n",
                "a=rtpmap:0 PCMU/8000\r\n",
                "a=rtpmap:101 telephone-event/8000\r\n",
                "a=fmtp:101 0-15\r\n",
                "a=ptime:20\r\n",
                "a=sendrecv\r\n",
                "a=rtcp:30001\r\n",
            )
        );
    }

    #[test]
    fn a_muxed_offer_says_rtcp_mux_and_no_rtcp_port() {
        let (codecs, events) = (codecs(), events());
        let text = local_audio_offer(&offer(
            &codecs,
            &events,
            LocalOfferKeying::Plain,
            None,
            None,
        ));
        assert!(text.contains("a=rtcp-mux\r\n"), "{text}");
        assert!(!text.contains("a=rtcp:"), "{text}");
    }

    #[test]
    fn an_offered_mux_keeps_the_fallback_port_and_a_required_one_says_mux_only() {
        let (codecs, events) = (codecs(), events());
        let mut local = offer(&codecs, &events, LocalOfferKeying::Plain, Some(30001), None);
        local.rtcp_mux = true;
        let text = local_audio_offer(&local);
        assert!(
            text.contains("a=rtcp:30001\r\na=rtcp-mux\r\n") && !text.contains("mux-only"),
            "{text}"
        );
        local.rtcp_port = None;
        local.rtcp_mux_only = true;
        let text = local_audio_offer(&local);
        assert!(text.contains("a=rtcp-mux\r\na=rtcp-mux-only\r\n"), "{text}");
        assert!(!text.contains("a=rtcp:"), "{text}");
    }

    #[test]
    fn an_sdes_offer_is_rtp_savp_with_one_crypto_line_the_parser_reads_back() {
        let (codecs, events) = (codecs(), events());
        let crypto = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
        let text = local_audio_offer(&offer(
            &codecs,
            &events,
            LocalOfferKeying::Sdes(&crypto),
            None,
            None,
        ));
        assert!(
            text.contains("m=audio 30000 RTP/SAVP 8 0 101\r\n"),
            "{text}"
        );
        let info = super::super::parse(&text).expect("parse");
        assert!(info.secure && !info.dtls);
        assert_eq!(info.crypto, vec![crypto]);
    }

    #[test]
    fn a_dtls_offer_carries_the_fingerprint_the_setup_and_the_tls_id() {
        let (codecs, events) = (codecs(), events());
        let fingerprint = Fingerprint {
            hash_function: "sha-256".to_string(),
            bytes: (0u8..32).collect(),
        };
        let text = local_audio_offer(&offer(
            &codecs,
            &events,
            LocalOfferKeying::Dtls {
                fingerprint: &fingerprint,
                setup: Setup::Actpass,
                tls_id: "0123456789abcdef0123",
            },
            None,
            None,
        ));
        assert!(
            text.contains("m=audio 30000 UDP/TLS/RTP/SAVPF 8 0 101\r\n"),
            "{text}"
        );
        assert!(text.contains("a=setup:actpass\r\n"), "{text}");
        assert!(text.contains("a=tls-id:0123456789abcdef0123\r\n"), "{text}");
        let info = super::super::parse(&text).expect("parse");
        assert!(info.dtls);
        assert_eq!(info.fingerprint, Some(fingerprint));
        assert_eq!(info.setup, Some(Setup::Actpass));
    }

    #[test]
    fn an_ice_offer_carries_credentials_candidates_and_is_not_lite() {
        let (codecs, events) = (codecs(), events());
        let address: SocketAddr = "127.0.0.1:30000".parse().expect("address");
        let mut gatherer =
            siphon_rtp_ice::Gatherer::new(siphon_rtp_ice::GatherConfig::host_only(address), 0);
        let _ = gatherer.poll(0);
        let candidates = gatherer.candidates().to_vec();
        let text = local_audio_offer(&offer(
            &codecs,
            &events,
            LocalOfferKeying::Plain,
            None,
            Some(LocalOfferIce {
                ufrag: "engu",
                pwd: "engineicepasswordengine1",
                candidates: &candidates,
            }),
        ));
        assert!(!text.contains("a=ice-lite"), "{text}");
        let info = super::super::parse(&text).expect("parse");
        assert_eq!(info.ice_ufrag.as_deref(), Some("engu"));
        assert_eq!(info.ice_pwd.as_deref(), Some("engineicepasswordengine1"));
        assert!(!info.ice_lite);
        assert_eq!(info.candidates.len(), candidates.len());
        assert!(info.end_of_candidates);
    }

    #[test]
    fn an_ipv6_offer_is_written_in_ip6() {
        let (codecs, events) = (codecs(), events());
        let mut local = offer(&codecs, &events, LocalOfferKeying::Plain, None, None);
        local.advertised = "2001:db8::7".parse().expect("ip");
        local.rtp = "[::1]:30000".parse().expect("address");
        let text = local_audio_offer(&local);
        assert!(text.contains("o=- 42 1 IN IP6 2001:db8::7\r\n"), "{text}");
        assert!(text.contains("c=IN IP6 2001:db8::7\r\n"), "{text}");
    }
}
