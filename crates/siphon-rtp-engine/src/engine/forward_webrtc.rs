//! A browser as a pre-arranged member of a forwarding room: `forward_offer` with a WebRTC profile
//! (`transport_protocol: "UDP/TLS/RTP/SAVPF"`) and the `forward_answer` that seats it.
//!
//! `forward_join` answers a browser that called the room. A group call also fans out the other way
//! (3GPP TS 24.379): the controller invites each member, a browser among them, so the engine is the
//! offerer (RFC 3264 §5) and writes a WebRTC offer ([`sdp::webrtc_seat_offer`]):
//!
//! * `UDP/TLS/RTP/SAVPF` with the engine's certificate fingerprint and `a=setup:actpass` (RFC 5763 §5);
//! * `a=ice-lite` with credentials and candidates minted for the seat (RFC 8445 §2.5): the engine is
//!   the lite agent, so the browser controls and nominates (RFC 8445 §6.1.1);
//! * when the room carries floor control, a bundled `m=application ... webrtc-datachannel` section
//!   (RFC 8841) in place of the UDP floor section, because a browser cannot send RTCP APP.
//!
//! What the offer fixed (certificate, ICE identity, candidates, the data channel intent) is kept in
//! the pending seat as [`OfferedWebrtc`]; [`OfferedWebrtc::read_answer`] checks the answer against it
//! and takes the DTLS role from the answer's `a=setup`. The seat is then taken `secure_pending`
//! (and `ice_pending` under a full agent), exactly as a joined browser seat is, and the browser opens
//! the `mcptt-floor` channel itself.

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{AddressFamily, Datapath, Endpoint, IceConfig, SourceFilter};
use siphon_rtp_dtls::{DtlsCertificate, DtlsRole};
use siphon_rtp_ice::Candidate;
use siphon_rtp_proto::{ForwardMedia, ProfileFlags};
use std::net::{IpAddr, SocketAddr};

use crate::dtls_bridge::PipelineTarget;
use crate::floor_channel::{floor_channel, FloorScope, FloorSink};
use crate::ice::{self, IceCredentials};
use crate::sdp::{self, TelephoneEvent};

use super::dial_out::refuse_unsupported_profile;
use super::negotiate::{dtls_directive, ice_directive, random_ssrc, DtlsDirective, IceDirective};
use super::seat_transport::{offerer_dtls_role, SeatTransport, PRESERVE_DTLS_REFUSAL};
use super::{ClientId, Engine, Leg};

/// The transport profile that asks for a WebRTC offer (RFC 8829 §5.2.1, RFC 5764 §4.1.2).
const WEBRTC_TRANSPORT: &str = "UDP/TLS/RTP/SAVPF";

/// Whether a `forward_offer` profile asks for a WebRTC offer, refusing a profile the engine cannot
/// offer. A profile without a transport (or `RTP/AVP`) is the plain offer, held to
/// [`refuse_unsupported_profile`]; `conference_offer` stays on that rule.
///
/// # Errors
/// A WebRTC profile on a preserve room (the engine would have to terminate SRTP the room forwards
/// end to end, 3GPP TS 33.180 §7.5.2 NOTE 3), `ice: remove` (WebRTC needs ICE) or a `dtls` other
/// than `actpass` (the offer's `a=setup` is `actpass`, RFC 5763 §5), and any unsupported plain profile.
pub(super) fn requested(profile: &ProfileFlags, media: ForwardMedia) -> Result<bool, String> {
    let webrtc = profile
        .transport_protocol
        .as_deref()
        .is_some_and(|protocol| protocol.trim().eq_ignore_ascii_case(WEBRTC_TRANSPORT));
    if !webrtc {
        return refuse_unsupported_profile(profile).map(|()| false);
    }
    if media == ForwardMedia::Preserve {
        return Err(PRESERVE_DTLS_REFUSAL.to_string());
    }
    if ice_directive(profile) == Some(IceDirective::Remove) {
        return Err(
            "ice remove contradicts a WebRTC offer: UDP/TLS/RTP/SAVPF is offered with ICE"
                .to_string(),
        );
    }
    match dtls_directive(profile) {
        None | Some(DtlsDirective::Role(sdp::Setup::Actpass)) => Ok(true),
        Some(_) => Err(
            "a WebRTC offer is a=setup:actpass (RFC 5763 §5): the member's answer picks the DTLS role; \
             dtls must be unset or actpass"
                .to_string(),
        ),
    }
}

/// What a WebRTC `forward_offer` fixed, kept until the member answers.
pub(super) struct OfferedWebrtc {
    /// The engine's certificate, whose fingerprint the offer carried.
    pub(super) certificate: DtlsCertificate,
    /// The seat's ICE identity as advertised.
    pub(super) credentials: IceCredentials,
    /// The candidates the offer advertised.
    pub(super) candidates: Vec<Candidate>,
    /// The offer carried a data channel section for the MCPTT floor control.
    pub(super) data_channel: bool,
    /// The address the offer advertised.
    pub(super) advertised: IpAddr,
}

/// What the member's answer settled for a WebRTC seat.
#[derive(Debug)]
pub(super) struct AnsweredWebrtc {
    /// The answer, parsed (the ICE agent reads the member's credentials and candidates from it).
    pub(super) info: sdp::MediaInfo,
    /// The engine's DTLS role, the complement of the answer's `a=setup`.
    pub(super) role: DtlsRole,
    /// The fingerprint the handshake must present (RFC 5763 §5).
    pub(super) peer_fingerprint: sdp::Fingerprint,
    /// The answer kept the data channel section: floor control rides it.
    pub(super) data_channel: bool,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Write the WebRTC offer for a seat whose audio endpoint is `endpoint`: mint its ICE identity,
    /// gather its candidates (RFC 8445 §5.1.1; a relayed candidate comes along when a TURN client is
    /// configured) and describe the engine's certificate. `data_channel` adds the floor-control
    /// section. Returns the offer and what it fixed.
    ///
    /// # Errors
    /// The engine has no DTLS certificate, or the OS random source cannot mint ICE credentials.
    pub(super) async fn write_webrtc_offer(
        &self,
        endpoint: Endpoint,
        advertised: IpAddr,
        codecs: &[CodecSpec],
        events: &[TelephoneEvent],
        data_channel: bool,
    ) -> Result<(String, OfferedWebrtc), String> {
        let Some(certificate) = self.dtls_certificate.clone() else {
            return Err("engine has no DTLS certificate".to_string());
        };
        let Some(credentials) = ice::generate_credentials() else {
            return Err("could not mint ICE credentials (OS RNG unavailable)".to_string());
        };
        let config = IceConfig {
            local_ufrag: credentials.ufrag.clone(),
            local_pwd: credentials.pwd.clone(),
        };
        // A room leg is one muxed endpoint, so one component (RFC 8445 §4.1.1.1).
        let leg = Leg {
            rtp: endpoint,
            rtcp: None,
            remote_rtp: None,
            remote_rtcp: None,
            advertised_ip: advertised,
            text: None,
            text_remote_rtp: None,
            image: None,
            image_remote: None,
            floor: None,
            floor_remote: None,
        };
        let candidates = self.gather_leg_candidates(&leg, &config).await;
        let fingerprint = sdp::Fingerprint {
            hash_function: certificate.fingerprint().hash_function,
            bytes: certificate.fingerprint().bytes,
        };
        let offer = sdp::webrtc_seat_offer(
            endpoint.local_addr,
            advertised,
            random_ssrc(),
            codecs,
            events,
            &sdp::WebrtcOffer {
                ufrag: &credentials.ufrag,
                pwd: &credentials.pwd,
                candidates: &candidates,
                fingerprint: &fingerprint,
                data_channel,
            },
        );
        Ok((
            offer,
            OfferedWebrtc {
                certificate,
                credentials,
                candidates,
                data_channel,
                advertised,
            },
        ))
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Finish seating an answered WebRTC member (the room already holds the seat `secure_pending`):
    /// carry its floor control on the data channel when the answer kept the section, then put the
    /// DTLS handshake in front of the endpoint in the role the answer's `a=setup` left the engine.
    ///
    /// The floor channel is attached **before** the handshake plan is registered, so the SCTP
    /// association has its sink when the first record arrives (as for `forward_join`). A failure
    /// takes the seat back out of the room and frees its endpoint.
    ///
    /// # Errors
    /// The datapath's refusal to install the handshake redirect.
    #[allow(
        clippy::too_many_arguments,
        reason = "the answered seat's already-decided parts"
    )]
    pub(super) async fn start_webrtc_seat(
        &self,
        client: ClientId,
        room_id: &str,
        from_tag: &str,
        endpoint: Endpoint,
        seat_remote: SocketAddr,
        accepted_source: SourceFilter,
        ice_pending: bool,
        offered: OfferedWebrtc,
        answered: AnsweredWebrtc,
    ) -> Result<(), String> {
        let forward = self.conference.forward();
        if answered.data_channel {
            let (handle, plan) = floor_channel(FloorSink {
                scope: FloorScope::Room(room_id.to_string()),
                tag: from_tag.to_string(),
                events: self.app_event_queue(client),
            });
            self.dtls_bridge().attach_floor_channel(endpoint.id, plan);
            if !forward.attach_floor_channel(room_id, from_tag, handle) {
                tracing::warn!(room_id, tag = %from_tag, "floor data channel for a seat that already left");
            }
        }
        // A forward seat opens one muxed endpoint and no second one, so the bind address a text or
        // floor endpoint would need is unused.
        let transport = SeatTransport::answered_dtls(
            endpoint,
            AddressFamily::of(endpoint.local_addr.ip()),
            None,
            offered.advertised,
            seat_remote,
            accepted_source,
            ice_pending,
            offered.certificate,
            answered.peer_fingerprint,
        );
        let target = PipelineTarget::Forward {
            forward: forward.clone(),
            room_id: room_id.to_string(),
            tag: from_tag.to_string(),
        };
        if let Err(error) = self.start_seat_dtls(&transport, answered.role, target) {
            self.release_forward_seat(room_id, from_tag).await;
            return Err(format!("install DTLS redirect: {error}"));
        }
        Ok(())
    }
}

impl OfferedWebrtc {
    /// The ICE configuration of the seat's endpoint.
    pub(super) fn ice_config(&self) -> IceConfig {
        IceConfig {
            local_ufrag: self.credentials.ufrag.clone(),
            local_pwd: self.credentials.pwd.clone(),
        }
    }

    /// Check the member's answer against the offer (RFC 3264 §6: the answer keeps the offer's
    /// transport) and read what the seat needs from it.
    ///
    /// # Errors
    /// An answer that is not `UDP/TLS/RTP/SAVPF` keyed by DTLS, has no `a=fingerprint` (RFC 5763 §5:
    /// the handshake is trusted only against it), carries SDES keys, or has no `active`/`passive`
    /// `a=setup`.
    pub(super) fn read_answer(
        &self,
        info: sdp::MediaInfo,
        answer: &str,
    ) -> Result<AnsweredWebrtc, String> {
        if !info.dtls || !info.secure {
            return Err(
                "the answer must be UDP/TLS/RTP/SAVPF, as the offer was: a WebRTC offer is keyed by DTLS-SRTP"
                    .to_string(),
            );
        }
        if !info.crypto.is_empty() {
            return Err(
                "the answer carries a=crypto, but the offer was keyed by DTLS-SRTP".to_string(),
            );
        }
        let Some(peer_fingerprint) = info.fingerprint.clone() else {
            return Err("UDP/TLS/RTP/SAVPF answer without an a=fingerprint".to_string());
        };
        let role = offerer_dtls_role(info.setup)?;
        // RFC 8841 §5: the answer keeps the section (a port, bundled) or declines it with port 0.
        let data_channel = self.data_channel && sdp::parse_data_channel(answer).is_some();
        Ok(AnsweredWebrtc {
            info,
            role,
            peer_fingerprint,
            data_channel,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn profile(transport: Option<&str>) -> ProfileFlags {
        ProfileFlags {
            transport_protocol: transport.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn a_webrtc_transport_is_a_webrtc_offer_and_a_plain_one_is_not() {
        assert_eq!(
            requested(&profile(Some("UDP/TLS/RTP/SAVPF")), ForwardMedia::Translate),
            Ok(true)
        );
        assert_eq!(
            requested(
                &profile(Some(" udp/tls/rtp/savpf ")),
                ForwardMedia::Translate
            ),
            Ok(true)
        );
        assert_eq!(
            requested(&profile(None), ForwardMedia::Translate),
            Ok(false)
        );
        assert_eq!(
            requested(&profile(Some("RTP/AVP")), ForwardMedia::Translate),
            Ok(false)
        );
    }

    #[test]
    fn other_transports_stay_refused() {
        for transport in ["RTP/SAVP", "RTP/SAVPF", "UDP/TLS/RTP/SAVP"] {
            let reason = requested(&profile(Some(transport)), ForwardMedia::Translate).unwrap_err();
            assert!(reason.contains(transport), "{reason}");
        }
    }

    #[test]
    fn a_webrtc_offer_is_refused_on_a_preserve_room() {
        let reason =
            requested(&profile(Some("UDP/TLS/RTP/SAVPF")), ForwardMedia::Preserve).unwrap_err();
        assert!(reason.contains("preserve room"), "{reason}");
    }

    #[test]
    fn a_webrtc_offer_refuses_ice_remove_and_a_pinned_dtls_role() {
        let mut flags = profile(Some("UDP/TLS/RTP/SAVPF"));
        flags.ice = Some("remove".to_string());
        assert!(requested(&flags, ForwardMedia::Translate)
            .unwrap_err()
            .contains("ice remove"));
        let mut flags = profile(Some("UDP/TLS/RTP/SAVPF"));
        for dtls in ["off", "active", "passive"] {
            flags.dtls = Some(dtls.to_string());
            assert!(
                requested(&flags, ForwardMedia::Translate)
                    .unwrap_err()
                    .contains("actpass"),
                "{dtls}"
            );
        }
        flags.dtls = Some("actpass".to_string());
        assert_eq!(requested(&flags, ForwardMedia::Translate), Ok(true));
        flags.ice = Some("force".to_string());
        assert_eq!(requested(&flags, ForwardMedia::Translate), Ok(true));
    }

    fn offered() -> OfferedWebrtc {
        OfferedWebrtc {
            certificate: DtlsCertificate::generate().unwrap(),
            credentials: IceCredentials {
                ufrag: "ENGUF".to_string(),
                pwd: "engpassword01234567".to_string(),
            },
            candidates: Vec::new(),
            data_channel: true,
            advertised: "127.0.0.1".parse().unwrap(),
        }
    }

    fn answer_text(setup: &str, fingerprint: bool, channel: bool) -> String {
        let mut text = format!(
            "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0 1\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 0\r\nc=IN IP4 0.0.0.0\r\na=rtpmap:0 PCMU/8000\r\n\
             a=mid:0\r\na=rtcp-mux\r\na=ice-ufrag:BR\r\na=ice-pwd:browserpassword0123456\r\na=setup:{setup}\r\n"
        );
        if fingerprint {
            text.push_str("a=fingerprint:sha-256 00:01:02:03\r\n");
        }
        text.push_str(&format!(
            "m=application {} UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:1\r\n\
             a=sctp-port:5000\r\na=setup:{setup}\r\n",
            if channel { 9 } else { 0 }
        ));
        text
    }

    fn read(setup: &str, fingerprint: bool, channel: bool) -> Result<AnsweredWebrtc, String> {
        let text = answer_text(setup, fingerprint, channel);
        offered().read_answer(sdp::parse(&text).unwrap(), &text)
    }

    #[test]
    fn the_answers_setup_picks_the_engines_dtls_role() {
        assert_eq!(read("active", true, true).unwrap().role, DtlsRole::Server);
        assert_eq!(read("passive", true, true).unwrap().role, DtlsRole::Client);
    }

    #[test]
    fn an_answer_that_picks_no_role_or_has_no_fingerprint_is_refused() {
        for setup in ["actpass", "holdconn"] {
            assert!(
                read(setup, true, true).unwrap_err().contains("a=setup"),
                "{setup}"
            );
        }
        assert!(read("active", false, true)
            .unwrap_err()
            .contains("a=fingerprint"));
    }

    #[test]
    fn a_plain_answer_is_refused() {
        let text = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
                    m=audio 4000 RTP/AVP 0\r\n";
        let reason = offered()
            .read_answer(sdp::parse(text).unwrap(), text)
            .unwrap_err();
        assert!(reason.contains("UDP/TLS/RTP/SAVPF"), "{reason}");
    }

    #[test]
    fn the_data_channel_is_kept_only_when_the_answer_accepts_it() {
        assert!(read("active", true, true).unwrap().data_channel);
        assert!(!read("active", true, false).unwrap().data_channel);
        let mut audio_only = offered();
        audio_only.data_channel = false;
        let text = answer_text("active", true, true);
        assert!(
            !audio_only
                .read_answer(sdp::parse(&text).unwrap(), &text)
                .unwrap()
                .data_channel
        );
    }
}
