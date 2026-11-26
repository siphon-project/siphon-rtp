//! The `offer_local` verb: the engine makes its own SDP offer for a one-legged call, and the caller's
//! answer completes it.
//!
//! The shape it serves is an INVITE that carries no SDP (a delayed offer, RFC 3261 §13.2.1) which a
//! controller answers itself: a voice bot, a prompt, a menu, voicemail, a recording. The answerer
//! offers (RFC 3264 §5), so the engine binds the one leg toward the caller and writes the offer, the
//! controller puts it in the 2xx, and the caller's answer comes back in the ACK, where the controller
//! hands it to `answer`. From then on the call is an `answer_local` call: the same pipeline, keying,
//! ICE agent and WebSocket takeover ([`super::answer_local`]).
//!
//! Until the answer arrives the call is **pending**: it holds its endpoints and nothing else. No
//! pipeline, bridge or agent exists, so nothing is sent toward the caller and nothing received is
//! forwarded or latched. There is no signalled peer yet to gate on, and the relay never forwards into
//! the void (docs/security-and-nat.md, layer 2). The latch is drawn only when the answer names the
//! address the caller will send from, exactly as for every other leg.

use std::net::SocketAddr;

use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_datapath::{AddressFamily, Datapath, Endpoint, FlowAction};
use siphon_rtp_proto::{CmdResult, Command, ProfileFlags, VideoRelay};
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};

use crate::ice::{self, IceCredentials};
use crate::sdp::{self, LocalOfferKeying, TelephoneEvent};

use super::answer_local::{
    order_codec_candidates, IceArming, LocalCallSpec, LocalEngage, LocalPeer, LocalTakeover,
    WsTakeoverSecurity,
};
use super::dial_out::{candidate_codecs, offered_events};
use super::negotiate::{
    dtls_directive, generate_tls_id, ice_directive, offered_dtls_setup, parse_codec_flags,
    random_ssrc, same_codec, DtlsDirective, IceDirective, SourcePosture,
};
use super::offer::far_address_family;
use super::{
    dispatch::{command_call_id, command_name},
    error_result, ok_sdp, unknown_call, Call, ClientId, Engine,
};

/// How the engine secured the stream it offered.
#[derive(Debug, Clone)]
pub(super) enum OfferedKeying {
    /// Plain `RTP/AVP`.
    Plain,
    /// SDES-SRTP: the key the engine offered, which the answer's `a=crypto` must name by tag and suite
    /// (RFC 4568 §5.1.2).
    Sdes(CryptoAttribute),
    /// DTLS-SRTP with the `a=setup` the offer carried.
    Dtls { setup: sdp::Setup },
}

/// The ICE identity the engine offered.
#[derive(Debug, Clone)]
pub(super) struct OfferedIce {
    credentials: IceCredentials,
    candidates: Vec<siphon_rtp_ice::Candidate>,
}

/// What an `offer_local` call keeps until the caller's answer completes it.
#[derive(Debug, Clone)]
pub(super) struct PendingLocalOffer {
    /// The offer the controller put in its 2xx, returned unchanged by the completing `answer`.
    offer_sdp: String,
    /// The profile the offer was made under: the codec policy, security, `ws_uri` and the rest.
    profile: ProfileFlags,
    /// The audio formats the offer listed, in its order.
    offered: Vec<CodecSpec>,
    /// The telephone-event formats the offer listed.
    events: Vec<TelephoneEvent>,
    keying: OfferedKeying,
    ice: Option<OfferedIce>,
    /// How the offer treated RTCP multiplexing (RFC 5761 §5.1.1, RFC 8858).
    mux: MuxPosture,
    /// Which offer this is: the call-id can be deleted and offered again between the validation of
    /// an answer and its consumption, and only the offer the answer was validated against may
    /// consume it.
    generation: u64,
}

/// The refusal of an answer whose offer is gone.
const SUPERSEDED: &str =
    "offer-local-superseded: the offer this answer was checked against is gone \
    (the call was deleted or offered again meanwhile); the answer completes nothing";

/// The one completion of an `offer_local` call that every step of the engagement belongs to: the
/// call-id and the exact offer (client, caller tag and generation) the answer consumed.
#[derive(Clone, Copy)]
pub(super) struct Completion<'a> {
    pub(super) client: ClientId,
    pub(super) call_id: &'a str,
    pub(super) from_tag: &'a str,
    pub(super) generation: u64,
}

impl Completion<'_> {
    /// Whether `call` is still the call this completion consumed the offer of.
    fn is_current(&self, call: &Call) -> bool {
        call.admits(self.client, self.call_id)
            && call.from_tag == self.from_tag
            && matches!(
                call.local_offer,
                Some(LocalOfferState::Answered { generation, .. }) if generation == self.generation
            )
    }
}

/// How an offer treats RTCP multiplexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MuxPosture {
    /// Separate RTCP on its own port (RFC 3605 `a=rtcp`).
    Separate,
    /// `a=rtcp-mux` with the separate port still advertised (RFC 5761 §5.1.1): an answer that
    /// declines multiplexing is accepted and RTCP runs on that port.
    Offered,
    /// `a=rtcp-mux` and `a=rtcp-mux-only` (RFC 8858): one port, and an answer that declines is
    /// refused.
    Required,
}

/// The next offer's [`PendingLocalOffer::generation`].
static OFFER_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// What the engine receives on an answered `offer_local` call, as it offered it: the caller sends
/// to the payload types of the **offer**, and the engine sends to the payload types of the
/// **answer** (RFC 3264 §5.1, §6.1: each side's format numbers are its own).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LocalIngress {
    /// The payload type of the one audio codec the engine decodes. The pipeline holds one decoder,
    /// so a packet on any other payload type is refused rather than fed to the wrong decoder (RFC
    /// 3264 §6.1 lets the caller send any answered format).
    pub(super) audio_payload_type: u8,
    /// The offered telephone-event payload type at the codec's clock rate (RFC 4733), which the
    /// caller sends events on.
    pub(super) event_payload_type: Option<u8>,
    /// The clock rate of that telephone-event stream, which times its durations (RFC 4733 §2.5).
    pub(super) event_clock_rate_hz: Option<u32>,
    /// The answer listed other formats than the one the call runs on.
    pub(super) other_formats_answered: bool,
}

/// Where an `offer_local` call stands.
#[derive(Debug, Clone)]
pub(super) enum LocalOfferState {
    /// Offered, not yet answered.
    Pending(Box<PendingLocalOffer>),
    /// Answered. The `to_tag` the controller put in its 2xx is recorded; it names no leg, the call
    /// stays a one-legged one.
    Answered {
        to_tag: String,
        ingress: LocalIngress,
        /// The generation of the offer this answered, so every step that completes it can tell it
        /// is still working on that call and not on a replacement.
        generation: u64,
    },
}

impl Call {
    /// Whether this is an `offer_local` call still waiting for its answer. An interception attached
    /// now is stood up at once and delivers from the answer on, as on an offered call.
    pub(super) fn local_offer_pending(&self) -> bool {
        self.pending_local_offer().is_some()
    }

    /// The offer this call is still waiting to have answered.
    fn pending_local_offer(&self) -> Option<&PendingLocalOffer> {
        match self.local_offer.as_ref()? {
            LocalOfferState::Pending(pending) => Some(pending),
            LocalOfferState::Answered { .. } => None,
        }
    }

    /// The generation of the offer this call is still waiting to have answered.
    #[cfg(test)]
    pub(super) fn pending_generation(&self) -> Option<u64> {
        self.pending_local_offer().map(|pending| pending.generation)
    }

    /// What an answered `offer_local` call receives on (see [`LocalIngress`]); `None` on every other
    /// call.
    pub(super) fn local_ingress(&self) -> Option<LocalIngress> {
        match self.local_offer.as_ref()? {
            LocalOfferState::Answered { ingress, .. } => Some(*ingress),
            LocalOfferState::Pending(_) => None,
        }
    }
}

/// The security, ICE and RTCP posture a profile asks an offer to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OfferShape {
    keying: ShapeKeying,
    ice: bool,
    mux: MuxPosture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShapeKeying {
    Plain,
    Sdes,
    Dtls(sdp::Setup),
}

/// Read the security shape of an offer off `profile`, the way `offer` reads the far leg's: a
/// `UDP/TLS` transport is DTLS-SRTP unless `dtls: off` downgrades it to plain, any other transport
/// naming `SAVP` is SDES, and `ice: force` runs ICE. RTCP multiplexing (RFC 5761 §5.1.1): `offer`
/// offers it with a separate port as the fallback, `require` offers it exclusively (RFC 8858) and
/// refuses an answer that declines. A DTLS or ICE leg requires it by default (RFC 8829 §5.1.1, whose
/// transports are multiplexed); a plain or SDES leg offers separate RTCP unless asked.
fn resolve_offer_shape(profile: &ProfileFlags) -> Result<OfferShape, String> {
    let transport = profile.transport_protocol.as_deref().unwrap_or_default();
    let directive = dtls_directive(profile);
    let dtls_transport = transport.contains("UDP/TLS");
    let keying = if dtls_transport && !matches!(directive, Some(DtlsDirective::Off)) {
        ShapeKeying::Dtls(offered_dtls_setup(directive))
    } else if !dtls_transport && transport.contains("SAVP") {
        ShapeKeying::Sdes
    } else {
        ShapeKeying::Plain
    };
    let ice = ice_directive(profile) == Some(IceDirective::Force);
    let explicit_mux = profile
        .rtcp_mux
        .iter()
        .find_map(|directive| match directive.as_str() {
            "require" => Some(MuxPosture::Required),
            "offer" => Some(MuxPosture::Offered),
            "demux" | "reject" | "remove" => Some(MuxPosture::Separate),
            _ => None,
        });
    if ice && explicit_mux == Some(MuxPosture::Separate) {
        return Err(
            "offer_local: ice-needs-rtcp-mux: an ICE leg runs one component, so RTCP is \
             multiplexed (RFC 8445 §4.1.1.1); drop the rtcp-mux directive that refuses it"
                .to_string(),
        );
    }
    // An ICE leg runs one component, so it has no fallback port to fall back to.
    let default = if ice || matches!(keying, ShapeKeying::Dtls(_)) {
        MuxPosture::Required
    } else {
        MuxPosture::Separate
    };
    let mux = match explicit_mux {
        Some(_) if ice => MuxPosture::Required,
        Some(explicit) => explicit,
        None => default,
    };
    Ok(OfferShape { keying, ice, mux })
}

/// Every codec this build can both encode and decode for a single-leg pipeline, widest band first,
/// edited by the profile's codec policy with the rules `answer_local` applies to an offer's codecs.
///
/// Which codecs this build can run depends only on the build, so it is decided once per process:
/// building every codec (an Opus and an AMR-WB encoder among them) on each offer would cost call
/// setup far more than the offer itself.
fn offerable_local_codecs(profile: &ProfileFlags) -> Vec<CodecSpec> {
    static RUNNABLE: std::sync::OnceLock<Vec<bool>> = std::sync::OnceLock::new();
    let candidates = candidate_codecs();
    let runnable = RUNNABLE.get_or_init(|| {
        candidates
            .iter()
            .map(|spec| factory::decoder_for(spec).is_ok() && factory::encoder_for(spec).is_ok())
            .collect()
    });
    let offered = candidates
        .into_iter()
        .zip(runnable.iter())
        .filter_map(|(spec, runnable)| runnable.then_some(spec))
        .collect();
    order_codec_candidates(offered, &parse_codec_flags(&profile.flags))
}

/// RFC 5763 §5 / RFC 4145 §4.1: whether `answered` is an `a=setup` an answer to an offer of `offered`
/// may carry. An `actpass` offer takes `active` or `passive`; an offer that pinned a role takes the
/// complementary one.
fn setup_answers(offered: sdp::Setup, answered: sdp::Setup) -> bool {
    use sdp::Setup::{Active, Actpass, Holdconn, Passive};
    match (offered, answered) {
        (Actpass, Active | Passive) | (Active, Passive) | (Passive, Active) => true,
        (Actpass | Active | Passive | Holdconn, _) => false,
    }
}

/// What a valid answer settled.
#[derive(Debug)]
struct AnsweredOffer {
    chosen: CodecSpec,
    /// The telephone-event the engine sends on: the answer's own payload type (RFC 3264 §6.1).
    telephone_event: Option<sdp::TelephoneEvent>,
    /// What the caller sends to, in the offer's numbering.
    ingress: LocalIngress,
    security: WsTakeoverSecurity,
    /// The peer's credentials, when the leg runs ICE.
    peer_ice: Option<IceCredentials>,
}

/// The offered format an answered one selects, and the payload type the engine receives it on.
///
/// RFC 3264 §5.1, §6.1: the answer may renumber a dynamic payload type, so a format is matched by
/// its encoding name, clock rate and channels and never by its number; for AMR the `octet-align`
/// payload format parameter must agree too (RFC 4867 §8.3.1). The answered spec, with the answer's
/// number and parameters, is what the engine sends; the offered number is what it receives.
fn match_offered_format(answered: CodecSpec, offered: &[CodecSpec]) -> Option<(CodecSpec, u8)> {
    let listed = offered
        .iter()
        .find(|listed| same_codec(listed, &answered))?;
    let octet_aligned = |spec: &CodecSpec| spec.amr.and_then(|amr| amr.octet_align) == Some(true);
    if answered.is_amr() && octet_aligned(&answered) != octet_aligned(listed) {
        return None;
    }
    let ingress = listed.payload_type;
    Some((answered, ingress))
}

/// A refusal of an answer: a stable token a controller can branch on, then the reason.
fn answer_refusal(token: &str, reason: &str) -> String {
    format!("answer: {token}: {reason}")
}

/// Check the caller's `info` answer against what `pending` offered (RFC 3264 §6, §6.1), and settle
/// the codec, the keying and whether ICE runs. The refusal is the whole reason, led by a stable
/// token; the call is left as it was, because an ACK cannot be answered with a 488 and the
/// controller ends the call itself.
fn validate_local_answer(
    pending: &PendingLocalOffer,
    local: SocketAddr,
    info: &sdp::MediaInfo,
) -> Result<AnsweredOffer, String> {
    // RFC 3264 §6: an answerer declines a stream with port 0.
    if info.remote_rtp.port() == 0 {
        return Err(answer_refusal(
            "answer-rejected",
            "the answer declined the audio stream (port 0, RFC 3264 §6)",
        ));
    }
    if AddressFamily::of(info.remote_rtp.ip()) != AddressFamily::of(local.ip()) {
        return Err(answer_refusal(
            "address-family-mismatch",
            &format!(
                "the answer's address {} is not in the family of the offered {local}",
                info.remote_rtp.ip()
            ),
        ));
    }
    // RFC 3264 §6.1: the answer selects from the formats the offer listed. The first answered format
    // that was offered is the one the call runs on.
    let answered_format_count = info.audio_codecs().len();
    let Some((chosen, ingress_payload_type)) = info
        .audio_codecs()
        .into_iter()
        .find_map(|answered| match_offered_format(answered, &pending.offered))
    else {
        return Err(answer_refusal(
            "codec-not-offered",
            "no format of the answer is one the offer listed (RFC 3264 §6.1)",
        ));
    };
    // RFC 5761 §5.1.1: multiplexing is the answerer's to accept, never to add.
    if pending.mux == MuxPosture::Required && !info.rtcp_mux {
        return Err(answer_refusal(
            "rtcp-mux-not-accepted",
            "the offer required multiplexed RTCP and the answer did not accept it (RFC 8858)",
        ));
    }
    if pending.mux == MuxPosture::Separate && info.rtcp_mux {
        return Err(answer_refusal(
            "rtcp-mux-not-offered",
            "the answer multiplexes RTCP, which the offer did not (RFC 5761 §5.1.1)",
        ));
    }
    let security = match &pending.keying {
        OfferedKeying::Plain => {
            if info.secure {
                return Err(answer_refusal(
                    "security-mismatch",
                    "the answer is secure and the offer was RTP/AVP (RFC 3264 §6)",
                ));
            }
            WsTakeoverSecurity::Plain
        }
        OfferedKeying::Sdes(offered) => {
            if !info.secure || info.dtls {
                return Err(answer_refusal(
                    "security-mismatch",
                    "the offer was RTP/SAVP and the answer is not (RFC 4568 §6.1)",
                ));
            }
            // RFC 4568 §5.1.2: the answer's tag names the offered line it accepted, in its suite.
            let Some(peer_key) = info
                .crypto
                .iter()
                .find(|crypto| crypto.tag == offered.tag && crypto.suite == offered.suite)
                .copied()
            else {
                return Err(answer_refusal(
                    "sdes-no-acceptable-crypto",
                    "the answer carries no usable a=crypto naming the offered line (RFC 4568 §5.1.2)",
                ));
            };
            WsTakeoverSecurity::Sdes { peer_key }
        }
        OfferedKeying::Dtls { setup } => {
            if !info.dtls {
                return Err(answer_refusal(
                    "security-mismatch",
                    "the offer was UDP/TLS/RTP/SAVPF and the answer is not (RFC 5764 §4.1.2)",
                ));
            }
            // RFC 5763 §5: without the peer's fingerprint the handshake is not bound to signalling.
            let Some(peer_fingerprint) = info.fingerprint.clone() else {
                return Err(answer_refusal(
                    "dtls-fingerprint-missing",
                    "the DTLS answer carries no a=fingerprint (RFC 5763 §5)",
                ));
            };
            // RFC 5763 §5: the answer is `active` or `passive`, and decides the roles: `active`
            // makes the engine the DTLS server. A missing or `actpass` setup decides nothing.
            let Some(peer_setup) = info
                .setup
                .filter(|answered| setup_answers(*setup, *answered))
            else {
                return Err(answer_refusal(
                    "dtls-setup-invalid",
                    "the answer's a=setup is missing or does not answer the offered role (RFC 5763 §5)",
                ));
            };
            WsTakeoverSecurity::Dtls {
                peer_fingerprint,
                peer_setup: Some(peer_setup),
            }
        }
    };
    // ICE (RFC 8839): an answer with credentials and candidates is checked against; an answer
    // without ICE means ICE is not used (§5.1), and one whose default destination matches none of
    // its candidates was altered in transit (§5.3); both run on the signalled address.
    let peer_ice = if pending.ice.is_some()
        && !info.ice_mismatch
        && !siphon_rtp_ice::is_ice_mismatch(info.remote_rtp, &info.candidates)
    {
        match super::negotiate::peer_ice_credentials(info) {
            Some(_) if info.candidates.is_empty() => {
                return Err(answer_refusal(
                    "ice-no-candidates",
                    "the ICE answer carries no candidates for the agent to check (RFC 8839 §5.1)",
                ));
            }
            other => other,
        }
    } else {
        None
    };
    // RFC 4733 §2.1: one event stream per clock rate. The caller sends events on the number the offer
    // gave that rate; the engine sends them on the number the answer gave it (RFC 3264 §6.1).
    let offered_event = pending
        .events
        .iter()
        .find(|event| event.clock_rate_hz == chosen.clock_rate_hz)
        .copied();
    let telephone_event =
        sdp::TelephoneEvent::accompanying(&info.telephone_events(), Some(&chosen))
            .filter(|_| offered_event.is_some());
    Ok(AnsweredOffer {
        chosen,
        telephone_event,
        ingress: LocalIngress {
            audio_payload_type: ingress_payload_type,
            event_payload_type: offered_event.map(|event| event.payload_type),
            event_clock_rate_hz: offered_event.map(|event| event.clock_rate_hz),
            other_formats_answered: answered_format_count > 1,
        },
        security,
        peer_ice,
    })
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// [`Command::OfferLocal`]: bind the one leg toward the caller and return the engine's SDP offer
    /// for it.
    pub(super) async fn offer_local(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: String,
        profile: &ProfileFlags,
    ) -> CmdResult {
        // A call-id already registered is never replaced: the call it names may be live media, and a
        // delayed-offer re-INVITE on it is not served (delete the call, then offer again).
        match self.calls.get(call_id) {
            Some(existing) if !existing.admits(client, call_id) => return unknown_call(call_id),
            Some(_) => return error_result(
                "offer_local",
                &"call-exists: the call-id already names a call; offer_local never replaces one \
                      (delete it first)",
            ),
            None => {}
        }
        if self.client_call_count(client) >= self.max_calls_per_client {
            return CmdResult::Error {
                reason: "per-client call quota exceeded".to_string(),
            };
        }
        if let Err(reason) = self.validate_and_reserve(profile) {
            return error_result("offer_local", &reason);
        }
        if profile.fax_passthrough {
            return error_result(
                "offer_local",
                &"fax-passthrough-needs-a-peer-leg: fax_passthrough forwards the payload verbatim, \
                  and offer_local terminates the call on the engine, so there is no peer to forward to",
            );
        }
        if profile.video_relay == VideoRelay::Anchor {
            return error_result(
                "offer_local",
                &"video-not-supported: offer_local offers one audio stream and anchors no video",
            );
        }
        let shape = match resolve_offer_shape(profile) {
            Ok(shape) => shape,
            Err(reason) => return CmdResult::Error { reason },
        };
        // The agent is the full RFC 8445 one, as for an answered ICE leg (`arm_single_leg_ice`): the
        // datapath's lite responder adopts a source into a `Forward` gate that a one-legged
        // `Redirect` leg never runs, so there is no lite posture for this leg.
        if shape.ice && self.ice_agents.is_none() {
            return error_result(
                "offer_local",
                &"ice-unsupported: ICE on a one-legged call needs the full RFC 8445 agent (start \
                  the engine with --ice-full)",
            );
        }
        let offered = offerable_local_codecs(profile);
        if offered.is_empty() {
            return error_result(
                "offer_local",
                &"no-offerable-codec: no codec this build runs both ways is left after the \
                  profile's codec flags",
            );
        }
        let events = offered_events(&offered);

        // The leg toward the caller: `direction[0]`'s interface, and IPv4 unless `address_family`
        // asks for IPv6, since there is no signalled address yet to take the family from.
        let family = far_address_family(profile).unwrap_or(AddressFamily::V4);
        let (interface, _) = self.interfaces.resolve_direction(&profile.direction);
        let (bind, advertised_override) = Self::leg_binding(interface, family);
        let endpoints = match self
            .alloc_endpoints(
                if shape.mux == MuxPosture::Required {
                    1
                } else {
                    2
                },
                family,
                bind,
            )
            .await
        {
            Ok(endpoints) => endpoints,
            Err(reason) => return CmdResult::Error { reason },
        };
        let rtp = endpoints[0];
        let rtcp = (shape.mux != MuxPosture::Required).then(|| endpoints[1]);
        let advertised = advertised_override.unwrap_or_else(|| rtp.local_addr.ip());

        let (keying, local_crypto, tls_id) = match self.local_offer_keying(shape, &endpoints).await
        {
            Ok(keying) => keying,
            Err(result) => return *result,
        };
        let ice = if shape.ice {
            let Some(credentials) = ice::generate_credentials() else {
                self.free(&endpoints).await;
                return error_result(
                    "offer_local",
                    &"could not mint ICE credentials (OS RNG unavailable)",
                );
            };
            let (candidates, _) = self
                .gather_local_ice(Some(&credentials), (rtp, rtcp, advertised))
                .await;
            // Gathering against a STUN server leaves the datapath's ICE-lite responder on the
            // endpoint, which answers an authenticated check by latching its source and stamping the
            // call alive. Before the answer there is no peer to latch to (docs/security-and-nat.md,
            // layer 2), so nothing may latch or stamp: the ICE state goes, and the agent arms from
            // the answer's credentials.
            self.datapath.set_ice(rtp.id, None);
            Some(OfferedIce {
                credentials,
                candidates,
            })
        } else {
            None
        };
        let fingerprint = self.engine_fingerprint();
        let wire_keying = match (&keying, local_crypto.as_ref(), fingerprint.as_ref()) {
            (OfferedKeying::Plain, ..) => LocalOfferKeying::Plain,
            (OfferedKeying::Sdes(_), Some(crypto), _) => LocalOfferKeying::Sdes(crypto),
            (OfferedKeying::Dtls { setup }, _, Some(fingerprint)) => LocalOfferKeying::Dtls {
                fingerprint,
                setup: *setup,
                tls_id: tls_id.as_deref().unwrap_or_default(),
            },
            // `local_offer_keying` produced the key, the certificate and the id these arms read.
            _ => {
                self.free(&endpoints).await;
                return error_result("offer_local", &"keying lost between its steps (internal)");
            }
        };
        let offer_text = sdp::local_audio_offer(&sdp::LocalOffer {
            rtp: rtp.local_addr,
            rtcp_port: rtcp.map(|endpoint| endpoint.local_addr.port()),
            rtcp_mux: shape.mux != MuxPosture::Separate,
            rtcp_mux_only: shape.mux == MuxPosture::Required,
            advertised,
            session_id: random_ssrc(),
            codecs: &offered,
            events: &events,
            keying: wire_keying,
            ice: ice.as_ref().map(|ice| sdp::LocalOfferIce {
                ufrag: &ice.credentials.ufrag,
                pwd: &ice.credentials.pwd,
                candidates: &ice.candidates,
            }),
        });
        // The controller's `a=key-mgmt` (RFC 4567), written once, here: the answer returns this text.
        let offer_text = match super::key_mgmt::keyed_sdp(&offer_text, profile) {
            Ok(keyed) => keyed,
            Err(reason) => {
                self.free(&endpoints).await;
                return error_result("offer_local: key_mgmt", &reason);
            }
        };

        let mut call = self.new_local_call(LocalCallSpec {
            client,
            call_id,
            from_tag,
            near_rtp: rtp,
            near_rtcp: rtcp,
            near_advertised: advertised,
            peer: LocalPeer::unsignalled(),
            profile,
            // The caller sends nothing before it has answered: silence until then is setup, not a
            // dead path (see `Call::anchored_before_answer`).
            anchored_before_answer: true,
        });
        call.local_offer = Some(LocalOfferState::Pending(Box::new(PendingLocalOffer {
            offer_sdp: offer_text.clone(),
            profile: profile.clone(),
            offered,
            events,
            keying,
            ice,
            mux: shape.mux,
            generation: OFFER_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        })));
        // Registered only if no other command took the call-id while the leg was being bound.
        let inserted = match self.calls.entry(call_id.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(_) => false,
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(call);
                true
            }
        };
        if !inserted {
            self.free(&endpoints).await;
            return error_result(
                "offer_local",
                &"call-exists: another command registered this call-id first",
            );
        }
        self.index_new_call(call_id, client);
        // Nothing the caller or anyone else sends is delivered anywhere until the answer installs a
        // flow behind a source gate: a datagram on these endpoints is dropped.
        for endpoint in &endpoints {
            if let Err(error) = self.datapath.install_flow(endpoint.id, FlowAction::Drop) {
                tracing::warn!(target: "siphon_rtp::media", call_id = %call_id, %error, "could not park the offered endpoint");
            }
        }
        tracing::info!(
            target: "siphon_rtp::media",
            call_id = %call_id,
            local = %rtp.local_addr,
            role = "uas_local_offer",
            "call created, offer made"
        );
        ok_sdp(offer_text, None)
    }

    /// The engine's own keying for an offer: its SDES key (RFC 4568 §6.1) or its certificate and a
    /// fresh `a=tls-id` (RFC 8842 §5.1). On an error the call's `endpoints` are freed.
    async fn local_offer_keying(
        &self,
        shape: OfferShape,
        endpoints: &[Endpoint],
    ) -> Result<(OfferedKeying, Option<CryptoAttribute>, Option<String>), Box<CmdResult>> {
        match shape.keying {
            ShapeKeying::Plain => Ok((OfferedKeying::Plain, None, None)),
            ShapeKeying::Sdes => {
                match CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80) {
                    Ok(crypto) => Ok((OfferedKeying::Sdes(crypto), Some(crypto), None)),
                    Err(error) => {
                        self.free(endpoints).await;
                        Err(Box::new(error_result(
                            "offer_local: generate SDES key",
                            &error,
                        )))
                    }
                }
            }
            ShapeKeying::Dtls(setup) => {
                if self.dtls_certificate.is_none() {
                    self.free(endpoints).await;
                    return Err(Box::new(error_result(
                        "offer_local",
                        &"dtls-unavailable: engine has no DTLS certificate",
                    )));
                }
                let Some(tls_id) = generate_tls_id() else {
                    self.free(endpoints).await;
                    return Err(Box::new(error_result(
                        "offer_local",
                        &"could not mint a tls-id (OS RNG unavailable)",
                    )));
                };
                Ok((OfferedKeying::Dtls { setup }, None, Some(tls_id)))
            }
        }
    }

    /// [`Command::Answer`]: the caller's answer to the engine's own offer (`offer_local`) completes
    /// that call, and any other answer goes to the far party it answers for. The profile's `ws_tee`
    /// is applied to the result either way.
    pub(super) async fn answer_command(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        to_tag: String,
        sdp: &str,
        profile: &ProfileFlags,
    ) -> CmdResult {
        let result = match self
            .complete_local_offer(client, call_id, from_tag, to_tag.clone(), sdp, profile)
            .await
        {
            Some(result) => result,
            None => {
                self.answer_or_complete_far(client, call_id, from_tag, to_tag, sdp, profile)
                    .await
            }
        };
        // The answer to a re-offer states the caller's own direction (a hold it accepts or declines).
        self.sync_ws_peer_receives(call_id);
        self.apply_profile_ws_tee(call_id, profile, result).await
    }

    /// [`Command::Answer`] on an `offer_local` call: the caller's answer completes the offer.
    ///
    /// `None` when `call_id` is no such call, and the answer then goes to [`Self::answer`] as ever.
    /// `from_tag` is the caller's, the tag `offer_local` was called with; `to_tag` is the one the
    /// controller put in its 2xx, recorded, and selecting nothing, since the call has one leg.
    ///
    /// A refused answer leaves the call pending and allocated: the controller deletes it, since an
    /// ACK cannot be answered with a 488. A valid one engages the call exactly as `answer_local`
    /// does, including the `ws_uri` takeover of the offer's profile, which is dialled **now** and not
    /// at the offer: the bridge's wire format is the codec the answer chose (RFC 3264 §6.1), which
    /// nobody knows before the answer arrives. The result is the engine's own offer, unchanged.
    pub(super) async fn complete_local_offer(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        to_tag: String,
        answer: &str,
        answer_profile: &ProfileFlags,
    ) -> Option<CmdResult> {
        let (pending, local) = {
            let call = self.calls.get(call_id)?;
            if !call.admits(client, call_id) {
                return None;
            }
            let state = call.local_offer.as_ref()?;
            if call.from_tag != from_tag {
                return Some(error_result("answer", &"from_tag mismatch"));
            }
            match state {
                LocalOfferState::Pending(pending) => {
                    ((**pending).clone(), call.near.rtp.local_addr)
                }
                // The far party `offer_far` offered a leg to answering is not this offer's answer.
                LocalOfferState::Answered { .. } if call.far_offer_pending() => return None,
                LocalOfferState::Answered {
                    to_tag: recorded, ..
                } => {
                    return Some(error_result(
                        "answer",
                        &format!(
                            "offer-local-already-answered: the offer was answered with to_tag \
                             {recorded}; the call is a one-legged one now"
                        ),
                    ));
                }
            }
        };
        let info = match sdp::parse(answer) {
            Ok(info) => info,
            Err(error) => {
                return Some(CmdResult::Error {
                    reason: answer_refusal(
                        "answer-sdp-invalid",
                        &format!("the answer's SDP does not parse: {error}"),
                    ),
                })
            }
        };
        let answered = match validate_local_answer(&pending, local, &info) {
            Ok(answered) => answered,
            Err(reason) => return Some(CmdResult::Error { reason }),
        };
        // Marked answered before anything is engaged, so a second answer racing this one finds
        // nothing left to complete.
        let pending = match self.consume_pending_offer(
            client,
            call_id,
            from_tag,
            pending.generation,
            &to_tag,
            answered.ingress,
        ) {
            Ok(pending) => pending,
            Err(reason) => return Some(error_result("answer", &reason)),
        };
        Some(
            self.engage_answered_offer(
                Completion {
                    client,
                    call_id,
                    from_tag,
                    generation: pending.generation,
                },
                &to_tag,
                (answer, &info),
                answered,
                *pending,
                answer_profile,
            )
            .await,
        )
    }

    /// Take the pending offer of `call_id` for the answer that was validated against `generation`.
    ///
    /// The validation of an answer reads a copy of the pending offer and releases the registry guard,
    /// so the call-id can be deleted (another connection, the reaper) and offered again before the
    /// answer is consumed. Consumption is therefore conditional on the exact offer validated: under
    /// the guard it is re-checked that the call is still the same client's pending offer, for the
    /// same caller tag, of the same generation. Anything else is refused with
    /// `offer-local-superseded`, and the replacement is left pending.
    pub(super) fn consume_pending_offer(
        &self,
        client: ClientId,
        call_id: &str,
        from_tag: &str,
        generation: u64,
        to_tag: &str,
        ingress: LocalIngress,
    ) -> Result<Box<PendingLocalOffer>, String> {
        let superseded = || SUPERSEDED.to_string();
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return Err(superseded());
        };
        let same_offer = call.admits(client, call_id)
            && call.from_tag == from_tag
            && call
                .pending_local_offer()
                .is_some_and(|pending| pending.generation == generation);
        if !same_offer {
            return Err(superseded());
        }
        match call.local_offer.replace(LocalOfferState::Answered {
            to_tag: to_tag.to_string(),
            ingress,
            generation,
        }) {
            Some(LocalOfferState::Pending(pending)) => Ok(pending),
            _ => Err(superseded()),
        }
    }

    /// Engage the call whose offer `answered` completes: record the caller's signalling, then run
    /// the same local pipeline, or WebSocket takeover, `answer_local` runs.
    async fn engage_answered_offer(
        &self,
        completion: Completion<'_>,
        to_tag: &str,
        (answer, info): (&str, &sdp::MediaInfo),
        answered: AnsweredOffer,
        pending: PendingLocalOffer,
        answer_profile: &ProfileFlags,
    ) -> CmdResult {
        let call_id = completion.call_id;
        let AnsweredOffer {
            chosen,
            telephone_event,
            security,
            peer_ice,
            ..
        } = answered;
        // The offer's profile, with what only the answer's moment knows: the caller's public
        // address, when the controller has it by now. `key_mgmt` was written into the offer.
        let mut profile = pending.profile.clone();
        profile.received_from = answer_profile.received_from.or(profile.received_from);
        profile.key_mgmt = None;
        let ice_credentials = pending.ice.as_ref().map(|ice| ice.credentials.clone());
        let ice_candidates = pending
            .ice
            .as_ref()
            .map(|ice| ice.candidates.clone())
            .unwrap_or_default();
        // The agent runs when the answer brought credentials and candidates to check against.
        let ice_config = ice_credentials
            .filter(|_| peer_ice.is_some())
            .map(|credentials| siphon_rtp_datapath::IceConfig {
                local_ufrag: credentials.ufrag,
                local_pwd: credentials.pwd,
            });
        let near_local_crypto = match &pending.keying {
            OfferedKeying::Sdes(local) => Some(*local),
            OfferedKeying::Plain | OfferedKeying::Dtls { .. } => None,
        };
        let peer = LocalPeer::signalled(info);
        let (near_rtp, unused_rtcp, instance) = {
            let Some(mut call) = self.calls.get_mut(call_id) else {
                return error_result("answer", &SUPERSEDED);
            };
            // The call-id may have been deleted and offered again since this answer consumed its
            // offer. Nothing below may touch a replacement: its signalling, its RTCP endpoint, its
            // keying. Nothing has been created by this completion yet, so there is nothing to free.
            if !completion.is_current(&call) {
                return error_result("answer", &SUPERSEDED);
            }
            // The call is answered now: its silence is judged like an `answer_local` call's from
            // here, against the media timeout from this moment and not the setup ceiling that ran
            // from the offer.
            call.anchored_before_answer = false;
            call.created_tick = self.datapath.now_ticks();
            // RFC 5761 §5.1.1: an answer that accepts multiplexing leaves the fallback RTCP port the
            // offer advertised unused.
            let unused_rtcp = if info.rtcp_mux {
                call.near.rtcp.take()
            } else {
                None
            };
            call.near.remote_rtp = peer.remote_rtp;
            call.near.remote_rtcp = peer.remote_rtcp;
            call.near_secure = peer.secure;
            call.near_direction = peer.direction;
            call.near_offered_telephone_events = peer.telephone_events;
            call.near_telephone_event = telephone_event;
            call.offer_received_from = profile.received_from;
            call.caller_source_posture = SourcePosture::from_profile(&profile);
            (call.near.rtp, unused_rtcp, call.instance)
        };
        if let Some(endpoint) = unused_rtcp {
            self.endpoint_calls.remove(&endpoint.id);
            self.free(&[endpoint]).await;
        }
        // Re-checked after the awaits above and before the engagement, which looks the call up by its
        // id: a replacement must not be engaged with this answer's codec, keying and ICE. (Commands
        // for one call-id are served in order on a connection; this closes the other connections and
        // the reaper.)
        if !self
            .calls
            .get(call_id)
            .is_some_and(|call| completion.is_current(&call))
        {
            return error_result("answer", &SUPERSEDED);
        }
        // RFC 8839 §5.1: an answer without ICE means ICE is not used, and the leg runs on the
        // signalled address. No datapath ICE state may be left to gate it.
        if pending.ice.is_some() && ice_config.is_none() {
            self.datapath.set_ice(near_rtp.id, None);
        }
        tracing::info!(
            target: "siphon_rtp::media",
            call_id = %call_id,
            %to_tag,
            answerer = %info.remote_rtp,
            codec = %chosen.encoding_name,
            role = "uas_local_offer",
            "offer answered"
        );
        let result = if let Some(ws_uri) = profile.ws_uri.clone() {
            // A takeover leg's media goes to the WebSocket server, so a lawful interception attached
            // at the offer is tapped onto the bridge, as it is onto a pipeline.
            let result = self
                .answer_local_takeover(LocalTakeover {
                    call_id,
                    ws_uri,
                    chosen,
                    offerer_security: &security,
                    near_local_crypto,
                    ice_config,
                    info,
                    profile: &profile,
                    near_rtp,
                    peer_ice: &peer_ice,
                    ice_candidates: &ice_candidates,
                    answer_sdp: pending.offer_sdp.clone(),
                    // RFC 8445 §6.1.1: the offerer controls.
                    controlling: true,
                    instance,
                })
                .await;
            if matches!(result, CmdResult::Ok { .. }) {
                self.carry_x3_across_answer(call_id).await;
            }
            result
        } else {
            let refusal = self
                .engage_local_pipeline(
                    call_id,
                    LocalEngage {
                        chosen,
                        // The offer carries no comfort noise format.
                        comfort_noise_payload_type: None,
                        offerer_security: &security,
                        near_local_crypto,
                        ice: ice_config.map(|config| IceArming {
                            config,
                            peer: peer_ice.as_ref(),
                            remote_candidates: &info.candidates,
                            local_candidates: &ice_candidates,
                            // RFC 8445 §6.1.1: the offerer controls.
                            controlling: true,
                        }),
                        info,
                        profile: &profile,
                        near_rtp,
                        // What `offer_far` grows the call from: the caller's signalling, and the
                        // offer the caller holds.
                        kept_offer: answer,
                        kept_answer: &pending.offer_sdp,
                    },
                )
                .await;
            match refusal {
                Some(refusal) => refusal,
                None => {
                    self.carry_x3_across_answer(call_id).await;
                    ok_sdp(pending.offer_sdp.clone(), None)
                }
            }
        };
        let result = match result {
            CmdResult::Ok { sdp, .. } => ok_sdp(sdp.unwrap_or_default(), Some(to_tag.to_string())),
            refusal => refusal,
        };
        // The offer's own `ws_tee`, applied now that there is media to stream. One on the answer's
        // profile is applied by the dispatcher.
        if answer_profile.ws_tee.is_none() {
            return self.apply_profile_ws_tee(call_id, &profile, result).await;
        }
        result
    }

    /// Whether `command` completes an `offer_local` call whose profile dials a WebSocket server, so
    /// the control connection runs it as a task of its own (see [`Self::command_dials`]).
    pub fn command_completes_a_dial(&self, call_key: &str, command: &Command) -> bool {
        matches!(command, Command::Answer { .. })
            && self.calls.get(call_key).is_some_and(|call| {
                call.pending_local_offer().is_some_and(|pending| {
                    pending.profile.ws_uri.is_some() || pending.profile.ws_tee.is_some()
                })
            })
    }

    /// The refusal of a verb that has nothing to act on yet: a call whose offer is still waiting for
    /// its answer has no pipeline, so it answers only the verbs that mean something for it. `None`
    /// for every other call, and for the verbs that are served.
    ///
    /// Served: `answer` (which completes it), `delete`, `query`, `attach_x3` and `detach_x3` (an
    /// interception attached at the offer delivers from the first answer on), and `offer_local`
    /// itself, which refuses a call-id that exists.
    pub(super) fn pending_offer_refusal(
        &self,
        client: ClientId,
        command: &Command,
    ) -> Option<CmdResult> {
        let call_id = command_call_id(command)?;
        if command.is_conference() {
            return None;
        }
        self.owned_call(client, call_id, |call| call.pending_local_offer().is_some())
            .filter(|pending| *pending)?;
        let verb = command_name(command);
        match command {
            Command::Answer { .. }
            | Command::Delete { .. }
            | Command::Query { .. }
            | Command::AttachX3 { .. }
            | Command::DetachX3 { .. }
            | Command::OfferLocal { .. } => None,
            Command::Checkpoint { .. } => Some(error_result(
                "checkpoint",
                &"checkpoint is unsupported for an offer_local call awaiting its answer: nothing is \
                  negotiated yet to replicate, and a standby resumes by being offered the call again",
            )),
            _ => Some(error_result(
                verb,
                &"offer-local-pending: the engine's offer is not answered yet; answer it, or delete \
                  the call",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(transport: Option<&str>, ice: Option<&str>) -> ProfileFlags {
        ProfileFlags {
            transport_protocol: transport.map(str::to_string),
            ice: ice.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn a_default_profile_offers_plain_rtp_with_separate_rtcp() {
        let shape = resolve_offer_shape(&ProfileFlags::default()).expect("shape");
        assert_eq!(
            shape,
            OfferShape {
                keying: ShapeKeying::Plain,
                ice: false,
                mux: MuxPosture::Separate
            }
        );
    }

    #[test]
    fn the_transport_protocol_picks_sdes_or_dtls_and_a_dtls_leg_multiplexes_by_default() {
        let sdes = resolve_offer_shape(&profile(Some("RTP/SAVP"), None)).expect("sdes");
        assert_eq!(sdes.keying, ShapeKeying::Sdes);
        assert_eq!(sdes.mux, MuxPosture::Separate);
        let dtls = resolve_offer_shape(&profile(Some("UDP/TLS/RTP/SAVPF"), None)).expect("dtls");
        assert_eq!(dtls.keying, ShapeKeying::Dtls(sdp::Setup::Actpass));
        assert_eq!(dtls.mux, MuxPosture::Required);
    }

    #[test]
    fn dtls_off_downgrades_a_udp_tls_transport_to_plain_and_a_role_directive_pins_the_setup() {
        let mut downgraded = profile(Some("UDP/TLS/RTP/SAVPF"), None);
        downgraded.dtls = Some("off".to_string());
        assert_eq!(
            resolve_offer_shape(&downgraded).expect("shape").keying,
            ShapeKeying::Plain
        );
        let mut pinned = profile(Some("UDP/TLS/RTP/SAVPF"), None);
        pinned.dtls = Some("passive".to_string());
        assert_eq!(
            resolve_offer_shape(&pinned).expect("shape").keying,
            ShapeKeying::Dtls(sdp::Setup::Passive)
        );
    }

    #[test]
    fn ice_force_runs_ice_on_a_multiplexed_leg_and_refuses_a_demuxed_one() {
        let shape = resolve_offer_shape(&profile(None, Some("force"))).expect("shape");
        assert!(shape.ice && shape.mux == MuxPosture::Required);
        let mut demuxed = profile(None, Some("force"));
        demuxed.rtcp_mux = vec!["demux".to_string()];
        let reason = resolve_offer_shape(&demuxed).expect_err("refused");
        assert!(reason.contains("ice-needs-rtcp-mux"), "{reason}");
        assert!(
            !resolve_offer_shape(&profile(None, Some("remove")))
                .expect("shape")
                .ice
        );
    }

    #[test]
    fn an_rtcp_mux_directive_decides_multiplexing_either_way() {
        let offer = ProfileFlags {
            rtcp_mux: vec!["offer".to_string()],
            ..Default::default()
        };
        assert_eq!(
            resolve_offer_shape(&offer).expect("shape").mux,
            MuxPosture::Offered
        );
        let require = ProfileFlags {
            rtcp_mux: vec!["require".to_string()],
            ..Default::default()
        };
        assert_eq!(
            resolve_offer_shape(&require).expect("shape").mux,
            MuxPosture::Required
        );
        let mut reject = profile(Some("UDP/TLS/RTP/SAVPF"), None);
        reject.rtcp_mux = vec!["reject".to_string()];
        assert_eq!(
            resolve_offer_shape(&reject).expect("shape").mux,
            MuxPosture::Separate
        );
    }

    #[test]
    fn the_codecs_offered_are_ordered_and_filtered_by_the_codec_flags() {
        let all = offerable_local_codecs(&ProfileFlags::default());
        assert!(all.iter().any(|codec| codec.encoding_name == "PCMU"));
        let flags = ProfileFlags {
            flags: vec![
                "codec-except-PCMA".to_string(),
                "codec-strip-all".to_string(),
            ],
            ..Default::default()
        };
        let kept = offerable_local_codecs(&flags);
        assert_eq!(
            kept.iter()
                .map(|codec| codec.encoding_name.as_str())
                .collect::<Vec<_>>(),
            ["PCMA"]
        );
        let first = ProfileFlags {
            flags: vec!["codec-offer-PCMA".to_string()],
            ..Default::default()
        };
        assert_eq!(
            offerable_local_codecs(&first)
                .first()
                .map(|codec| codec.encoding_name.as_str()),
            Some("PCMA")
        );
    }

    #[test]
    fn every_offered_codec_runs_both_ways() {
        for spec in offerable_local_codecs(&ProfileFlags::default()) {
            assert!(factory::decoder_for(&spec).is_ok(), "{spec:?}");
            assert!(factory::encoder_for(&spec).is_ok(), "{spec:?}");
        }
    }

    #[test]
    fn setup_answers_follow_rfc_5763() {
        use sdp::Setup::{Active, Actpass, Holdconn, Passive};
        assert!(setup_answers(Actpass, Active));
        assert!(setup_answers(Actpass, Passive));
        assert!(!setup_answers(Actpass, Actpass));
        assert!(!setup_answers(Actpass, Holdconn));
        assert!(setup_answers(Active, Passive));
        assert!(!setup_answers(Active, Active));
        assert!(setup_answers(Passive, Active));
        assert!(!setup_answers(Passive, Passive));
    }

    fn pending(keying: OfferedKeying, muxed: bool) -> PendingLocalOffer {
        PendingLocalOffer {
            offer_sdp: String::new(),
            profile: ProfileFlags::default(),
            offered: vec![
                CodecSpec::new(8, "PCMA", 8000, 1, 20),
                CodecSpec::new(0, "PCMU", 8000, 1, 20),
            ],
            events: vec![TelephoneEvent {
                payload_type: 101,
                clock_rate_hz: 8000,
            }],
            keying,
            ice: None,
            mux: if muxed {
                MuxPosture::Required
            } else {
                MuxPosture::Separate
            },
            generation: 0,
        }
    }

    fn answer(lines: &str) -> sdp::MediaInfo {
        sdp::parse(&format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n{lines}"
        ))
        .expect("answer parses")
    }

    const LOCAL: &str = "192.0.2.1:30000";

    fn local() -> SocketAddr {
        LOCAL.parse().expect("address")
    }

    fn token(result: Result<AnsweredOffer, String>) -> String {
        match result {
            Ok(_) => panic!("the answer was accepted"),
            Err(reason) => reason,
        }
    }

    #[test]
    fn the_first_answered_format_that_was_offered_is_the_codec() {
        let info = answer(
            "m=audio 4000 RTP/AVP 18 0 8\r\na=rtpmap:18 G729/8000\r\na=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:8 PCMA/8000\r\n",
        );
        let settled = validate_local_answer(&pending(OfferedKeying::Plain, false), local(), &info)
            .expect("accepted");
        assert_eq!(settled.chosen.encoding_name, "PCMU");
    }

    #[test]
    fn an_answer_with_no_offered_codec_is_refused_with_a_token() {
        let info = answer("m=audio 4000 RTP/AVP 18\r\na=rtpmap:18 G729/8000\r\n");
        let reason = token(validate_local_answer(
            &pending(OfferedKeying::Plain, false),
            local(),
            &info,
        ));
        assert!(reason.starts_with("answer: codec-not-offered:"), "{reason}");
    }

    #[test]
    fn a_declined_stream_is_refused_with_a_token() {
        let info = answer("m=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n");
        let reason = token(validate_local_answer(
            &pending(OfferedKeying::Plain, false),
            local(),
            &info,
        ));
        assert!(reason.starts_with("answer: answer-rejected:"), "{reason}");
    }

    #[test]
    fn a_secure_answer_to_a_plain_offer_and_the_reverse_are_a_security_mismatch() {
        let secure = answer("m=audio 4000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n");
        assert!(token(validate_local_answer(
            &pending(OfferedKeying::Plain, false),
            local(),
            &secure,
        ))
        .starts_with("answer: security-mismatch:"));
        let plain = answer("m=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n");
        let key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
        assert!(token(validate_local_answer(
            &pending(OfferedKeying::Sdes(key), false),
            local(),
            &plain,
        ))
        .starts_with("answer: security-mismatch:"));
    }

    #[test]
    fn an_sdes_answer_must_name_the_offered_line() {
        let offered = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
        let other = CryptoAttribute::generate(2, CryptoSuite::AesCm128HmacSha1_80).expect("key");
        let wrong_tag = answer(&format!(
            "m=audio 4000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\na={}\r\n",
            other.to_attribute_value()
        ));
        let pending_sdes = pending(OfferedKeying::Sdes(offered), false);
        assert!(
            token(validate_local_answer(&pending_sdes, local(), &wrong_tag))
                .starts_with("answer: sdes-no-acceptable-crypto:")
        );
        let none = answer("m=audio 4000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n");
        assert!(token(validate_local_answer(&pending_sdes, local(), &none))
            .starts_with("answer: sdes-no-acceptable-crypto:"));
        let accepted = answer(&format!(
            "m=audio 4000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\na={}\r\n",
            CryptoAttribute::answer_to(&offered)
                .expect("answer key")
                .to_attribute_value()
        ));
        assert!(validate_local_answer(&pending_sdes, local(), &accepted).is_ok());
    }

    #[test]
    fn a_dtls_answer_needs_a_fingerprint_and_an_active_or_passive_setup() {
        let pending_dtls = pending(
            OfferedKeying::Dtls {
                setup: sdp::Setup::Actpass,
            },
            true,
        );
        let base = "m=audio 4000 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n";
        let fingerprint = format!(
            "a={}\r\n",
            sdp::Fingerprint {
                hash_function: "sha-256".to_string(),
                bytes: vec![0xAB; 32]
            }
            .to_attribute_value()
        );
        let without = answer(&format!("{base}a=setup:active\r\n"));
        assert!(
            token(validate_local_answer(&pending_dtls, local(), &without))
                .starts_with("answer: dtls-fingerprint-missing:")
        );
        let no_setup = answer(&format!("{base}{fingerprint}"));
        assert!(
            token(validate_local_answer(&pending_dtls, local(), &no_setup))
                .starts_with("answer: dtls-setup-invalid:")
        );
        let actpass = answer(&format!("{base}{fingerprint}a=setup:actpass\r\n"));
        assert!(
            token(validate_local_answer(&pending_dtls, local(), &actpass))
                .starts_with("answer: dtls-setup-invalid:")
        );
        let active = answer(&format!("{base}{fingerprint}a=setup:active\r\n"));
        let settled = validate_local_answer(&pending_dtls, local(), &active).expect("accepted");
        assert!(matches!(
            settled.security,
            WsTakeoverSecurity::Dtls {
                peer_setup: Some(sdp::Setup::Active),
                ..
            }
        ));
    }

    #[test]
    fn rtcp_multiplexing_is_the_answerers_to_accept_and_never_to_add() {
        let muxed = answer("m=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n");
        let separate = answer("m=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n");
        assert!(token(validate_local_answer(
            &pending(OfferedKeying::Plain, true),
            local(),
            &separate,
        ))
        .starts_with("answer: rtcp-mux-not-accepted:"));
        assert!(token(validate_local_answer(
            &pending(OfferedKeying::Plain, false),
            local(),
            &muxed,
        ))
        .starts_with("answer: rtcp-mux-not-offered:"));
    }

    #[test]
    fn an_answer_in_another_address_family_is_refused() {
        let info = sdp::parse(
            "v=0\r\no=- 1 1 IN IP6 2001:db8::10\r\ns=-\r\nc=IN IP6 2001:db8::10\r\nt=0 0\r\n\
             m=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        )
        .expect("parse");
        let reason = token(validate_local_answer(
            &pending(OfferedKeying::Plain, false),
            local(),
            &info,
        ));
        assert!(
            reason.starts_with("answer: address-family-mismatch:"),
            "{reason}"
        );
    }
}

#[cfg(test)]
mod interleaving_tests {
    use super::*;
    use siphon_rtp_datapath::udp::UdpLoopbackDatapath;

    const CALL: &str = "interleaved";
    const CLIENT: ClientId = ClientId(1);

    fn muxed_offer_profile() -> ProfileFlags {
        ProfileFlags {
            flags: vec!["codec-strip-all".into(), "codec-except-PCMU".into()],
            rtcp_mux: vec!["offer".into()],
            ..Default::default()
        }
    }

    async fn offer(engine: &Engine<UdpLoopbackDatapath>) {
        let result = engine
            .handle(
                CLIENT,
                Command::OfferLocal {
                    call_id: CALL.into(),
                    from_tag: "tag-a".into(),
                    profile: muxed_offer_profile(),
                },
            )
            .await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    }

    /// The deterministic interleaving: an answer consumes its offer, the call-id is deleted and
    /// offered again, and only then does the engagement run. It must refuse, and leave the
    /// replacement exactly as it was: pending, unsignalled, with its RTCP endpoint intact.
    #[tokio::test]
    async fn an_engagement_of_a_consumed_offer_never_touches_the_replacement() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        offer(&engine).await;
        let (pending, local, generation) = {
            let call = engine.calls.get(CALL).expect("call");
            let pending = call.pending_local_offer().expect("pending").clone();
            let generation = pending.generation;
            (pending, call.near.rtp.local_addr, generation)
        };
        let answer = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                      m=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n";
        let info = sdp::parse(answer).expect("answer");
        let answered = validate_local_answer(&pending, local, &info).expect("valid");
        let consumed = engine
            .consume_pending_offer(CLIENT, CALL, "tag-a", generation, "tag-b", answered.ingress)
            .expect("consumed");
        // Deleted and offered again before the engagement runs.
        engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: CALL.into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        offer(&engine).await;
        let before = engine.endpoint_calls.len();

        let result = engine
            .engage_answered_offer(
                Completion {
                    client: CLIENT,
                    call_id: CALL,
                    from_tag: "tag-a",
                    generation,
                },
                "tag-b",
                (answer, &info),
                answered,
                *consumed,
                &ProfileFlags::default(),
            )
            .await;
        assert!(
            matches!(&result, CmdResult::Error { reason } if reason.contains("offer-local-superseded")),
            "{result:?}"
        );
        let call = engine.calls.get(CALL).expect("the replacement");
        assert!(call.local_offer_pending(), "still pending");
        assert_eq!(call.near.remote_rtp, None, "its peer was not overwritten");
        assert!(call.near.rtcp.is_some(), "its RTCP endpoint was not taken");
        assert!(call.anchored_before_answer, "its setup clock was not reset");
        drop(call);
        assert_eq!(
            engine.endpoint_calls.len(),
            before,
            "nothing of it was freed"
        );
    }
}
