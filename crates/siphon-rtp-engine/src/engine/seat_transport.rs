//! The transport of a room seat, opened the same way for every room that terminates its members'
//! media: a mixing conference seat and a forwarding room seat.
//!
//! [`Engine::open_seat_transport`] takes the seat's parsed offer and does everything between "the
//! offer was understood" and "the room is told about the seat": the ICE decision (RFC 8445, with the
//! RFC 8839 §5.3 mismatch fallback), one redirected engine endpoint, the RTPBleed source gate
//! (docs/security-and-nat.md §4 layers 2 to 4), candidate gathering and the ICE agent, and the keying
//! posture (SDES-SRTP key minted now, DTLS-SRTP keyed after the handshake). The caller then seats the
//! member, [`Engine::start_seat_dtls`] puts the handshake in front of a DTLS seat, and
//! [`Engine::answer_seat_sdp`] writes the answer.

use siphon_rtp_datapath::{AddressFamily, Datapath, Endpoint, FlowAction, IceConfig, SourceFilter};
use siphon_rtp_dtls::{DtlsCertificate, Fingerprint as DtlsFingerprint};
use siphon_rtp_proto::{CmdResult, ProfileFlags};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::CryptoAttribute;
use std::net::{IpAddr, SocketAddr};

use crate::dtls_bridge::{DtlsCallPlan, PipelineTarget};
use crate::ice::{self, IceCredentials};
use crate::sdp::{self, EngineMedia, IceRewrite, ImageRewrite, SecurityAdvertisement, TextRewrite};

use super::negotiate::{ice_directive, peer_media_address, IceDirective};
use super::{boxed_error_result, Engine, Leg};

/// A DTLS seat's handshake inputs, bound once and used by [`Engine::start_seat_dtls`].
pub(super) struct SeatDtls {
    certificate: DtlsCertificate,
    peer_fingerprint: sdp::Fingerprint,
}

/// An opened seat transport.
pub(super) struct SeatTransport {
    /// The seat's one redirected engine endpoint (RTP and RTCP muxed).
    pub(super) endpoint: Endpoint,
    pub(super) family: AddressFamily,
    /// The bind address the endpoint was allocated on (for a second endpoint such as text).
    pub(super) bind: Option<IpAddr>,
    /// The address the answer advertises.
    pub(super) advertised: IpAddr,
    /// Where the room sends to the seat until a gated source latches: the signalled address, or
    /// the post-NAT source the proxy saw (`received_from`).
    pub(super) seat_remote: SocketAddr,
    /// Layer 2: the sources the seat may send from.
    pub(super) accepted_source: SourceFilter,
    /// A full ICE agent runs and has not selected a pair: hold the seat shut.
    pub(super) ice_pending: bool,
    ice_credentials: Option<IceCredentials>,
    ice_candidates: Vec<siphon_rtp_ice::Candidate>,
    ice_mismatch: bool,
    dtls: Option<SeatDtls>,
    /// The SDES leg of a secure seat; `None` for a plain seat and for a DTLS seat (keyed later).
    pub(super) secure: Option<SecureLeg>,
    security: Option<SecurityAdvertisement>,
}

impl SeatTransport {
    /// Whether the seat is a DTLS-SRTP leg whose handshake is still to run.
    pub(super) fn dtls_pending(&self) -> bool {
        self.dtls.is_some()
    }

    /// How the answer presents the offer's ICE (RFC 8839 §5).
    fn ice_rewrite(&self, profile: &ProfileFlags) -> IceRewrite<'_> {
        match (self.ice_credentials.as_ref(), ice_directive(profile)) {
            (Some(credentials), _) => IceRewrite::Reoriginate(sdp::IceAdvertisement {
                ufrag: credentials.ufrag.as_str(),
                pwd: credentials.pwd.as_str(),
                candidates: &self.ice_candidates,
            }),
            (None, _) if self.ice_mismatch => IceRewrite::Mismatch,
            (None, Some(IceDirective::Remove)) => IceRewrite::Strip,
            (None, _) => IceRewrite::Keep,
        }
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Open a seat's transport from its parsed offer. `verb` names the command in refusals. On an
    /// error nothing stays allocated.
    pub(super) async fn open_seat_transport(
        &self,
        verb: &'static str,
        room_id: &str,
        info: &sdp::MediaInfo,
        profile: &ProfileFlags,
    ) -> Result<SeatTransport, Box<CmdResult>> {
        // ICE on a room leg (RFC 8445). The room, not a datapath forward rule, owns the seat's
        // egress, so a selection has to reach the room actor as well as the datapath
        // (`drive_ice_agents`).
        //
        // RFC 8839 §5.3: an offer whose default destination matches none of its own candidates was
        // rewritten in transit, so ICE describes a topology media no longer follows. Fall back to the
        // signalled address rather than negotiate ICE we cannot trust.
        let ice_mismatch = siphon_rtp_ice::is_ice_mismatch(info.remote_rtp, &info.candidates)
            && ice_directive(profile) != Some(IceDirective::Force);
        let want_ice = match ice_directive(profile) {
            _ if ice_mismatch => false,
            Some(IceDirective::Force) => true,
            Some(IceDirective::Remove) => false,
            None => info.is_ice(),
        };
        let ice_credentials = if want_ice {
            ice::generate_credentials()
        } else {
            None
        };
        if want_ice && ice_credentials.is_none() {
            return Err(boxed_error_result(
                verb,
                &"could not mint ICE credentials (OS RNG unavailable)",
            ));
        }
        // One engine endpoint in the offer's address family, redirected to the room actor. A seat is
        // a single leg, so it uses the near (`direction[0]`) interface: its bind IP and advertised
        // (public) address, defaulting when the request carries no `direction`.
        let family = AddressFamily::of(info.remote_rtp.ip());
        let (interface, _) = self.interfaces.resolve_direction(&profile.direction);
        let (bind, advertised_override) = Self::leg_binding(interface, family);
        let endpoint = match self.alloc_endpoints(1, family, bind).await {
            Ok(mut endpoints) => endpoints.remove(0),
            Err(reason) => return Err(boxed_error_result(verb, &reason)),
        };
        let advertised = advertised_override.unwrap_or_else(|| endpoint.local_addr.ip());
        if let Err(error) = self
            .datapath
            .install_flow(endpoint.id, FlowAction::Redirect)
        {
            self.free(&[endpoint]).await;
            return Err(boxed_error_result(
                &format!("{verb}: install redirect"),
                &error,
            ));
        }
        // RTPBleed gate: exact signalled-source by default; accept-any only for an explicit symmetric
        // leg. The constrained latch then learns the reply address from the gated source.
        //
        // An ICE seat runs this gate open (`Any`), because the signalled address is not the
        // discriminator on an ICE leg: a connectivity check legitimately arrives from a
        // peer-reflexive transport the SDP never carried (RFC 8445 §7.3.1.3). What holds the seat
        // shut is the datapath's layer-4 ICE gate, which redirects media to the room only from the
        // source a check authenticated with our own password; for a full-agent seat the room's
        // `ice_pending` additionally drops everything until the agent selects, and `ice_selected`
        // then narrows the filter to the selected pair (docs/security-and-nat.md §4 layer 4; RFC 8445
        // §7).
        //
        // A NATed member advertises a private `c=` and sends from its NAT's public address, which
        // the SIP proxy saw its request arrive from (`profile.received_from`). The gate and the
        // opening destination follow that hint exactly as a two-party answer's do
        // ([`peer_media_address`]); an ICE seat keeps the signalled address, since ICE decides its
        // transport.
        let seat_remote = if want_ice {
            info.remote_rtp
        } else {
            peer_media_address(info.remote_rtp, profile.received_from)
        };
        let accepted_source = if want_ice || profile.flags.iter().any(|flag| flag == "symmetric") {
            SourceFilter::Any
        } else {
            SourceFilter::Exact(seat_remote.ip())
        };

        // Gather the seat's candidates before the answer is written: the answer *is* the candidate
        // list. A room leg is always RTP/RTCP-muxed onto one endpoint, so it has exactly one
        // component (RFC 8445 §4.1.1.1).
        let (ice_candidates, ice_config) = match ice_credentials.as_ref() {
            Some(credentials) => {
                let config = IceConfig {
                    local_ufrag: credentials.ufrag.clone(),
                    local_pwd: credentials.pwd.clone(),
                };
                let leg = Leg {
                    rtp: endpoint,
                    rtcp: None,
                    remote_rtp: None,
                    remote_rtcp: None,
                    advertised_ip: advertised,
                    // A room seat anchors audio here; a conference seat's RFC 9071 text endpoint is
                    // anchored by the caller, so it has no component to gather candidates for.
                    text: None,
                    text_remote_rtp: None,
                    // Neither a single-leg local answer nor a room seat relays fax.
                    image: None,
                    image_remote: None,
                    floor: None,
                    floor_remote: None,
                };
                let candidates = self.gather_leg_candidates(&leg, &config).await;
                (candidates, Some(config))
            }
            None => (Vec::new(), None),
        };
        let ice_pending = self.arm_seat_ice(
            room_id,
            endpoint,
            info,
            ice_config.as_ref(),
            &ice_candidates,
        );

        // SDES-SRTP (RTP/SAVP): mint our own key, build the secure leg (decrypt inbound with theirs,
        // encrypt outbound with ours), and answer RTP/SAVP + a=crypto. DTLS-SRTP
        // (`UDP/TLS/RTP/SAVPF`): there is no key to build here, since the RFC 5764 handshake produces
        // it after this command returns, so the seat is taken **pending** and keyed later over the
        // room's control. Until then the room drops its ingress and sends it nothing, so an unkeyed
        // seat can neither inject noise nor receive the room in the clear.
        let dtls = if info.dtls {
            // The handshake needs the engine's certificate and the offer's fingerprint. Both are
            // bound here, once, and carried to the answer and to the handshake plan.
            let Some(certificate) = self.dtls_certificate.clone() else {
                self.free(&[endpoint]).await;
                return Err(boxed_error_result(verb, &"engine has no DTLS certificate"));
            };
            let Some(peer_fingerprint) = info.fingerprint.clone() else {
                self.free(&[endpoint]).await;
                return Err(boxed_error_result(
                    verb,
                    &"UDP/TLS/RTP/SAVPF offer without an a=fingerprint",
                ));
            };
            Some(SeatDtls {
                certificate,
                peer_fingerprint,
            })
        } else {
            None
        };
        let (secure, security) = if let Some(dtls) = dtls.as_ref() {
            // The answer advertises the engine's fingerprint and the answerer's DTLS role for the
            // offerer's `a=setup` (RFC 4145 §4.1, RFC 5763 §5).
            let (setup, _) = super::negotiate::answerer_dtls_setup(info.setup, None);
            (
                None,
                Some(SecurityAdvertisement::Dtls {
                    fingerprint: sdp::Fingerprint {
                        hash_function: dtls.certificate.fingerprint().hash_function,
                        bytes: dtls.certificate.fingerprint().bytes,
                    },
                    setup,
                    // A seat is a new association each time it joins; the offer's `a=tls-id` is not
                    // yet answered here.
                    tls_id: None,
                }),
            )
        } else if info.secure {
            let Some(remote) = info.crypto.first().copied() else {
                self.free(&[endpoint]).await;
                return Err(boxed_error_result(
                    verb,
                    &"RTP/SAVP offer without a usable a=crypto",
                ));
            };
            // Under the accepted line's tag and suite (RFC 4568 §5.1.2).
            let local = match CryptoAttribute::answer_to(&remote) {
                Ok(local) => local,
                Err(error) => {
                    self.free(&[endpoint]).await;
                    return Err(boxed_error_result(
                        &format!("{verb}: generate SDES key"),
                        &error,
                    ));
                }
            };
            (
                Some(SecureLeg::new(&local.key, &remote.key)),
                Some(SecurityAdvertisement::Secure(local)),
            )
        } else {
            (None, None)
        };
        Ok(SeatTransport {
            endpoint,
            family,
            bind,
            advertised,
            seat_remote,
            accepted_source,
            ice_pending,
            ice_credentials,
            ice_candidates,
            ice_mismatch,
            dtls,
            secure,
            security,
        })
    }

    /// Put the DTLS-SRTP handshake in front of a DTLS seat's endpoint. The bridge keeps the RFC 7983
    /// demux (DTLS records drive the handshake) and forwards accepted media to the room still
    /// encrypted, which decrypts it on the seat's own `SecureLeg` once keyed (`target`). A no-op for
    /// a seat that is not DTLS. The seat must already be taken `secure_pending`.
    ///
    /// # Errors
    /// The datapath's refusal to (re-)install the redirect.
    pub(super) fn start_seat_dtls(
        &self,
        transport: &SeatTransport,
        info: &sdp::MediaInfo,
        target: PipelineTarget,
    ) -> Result<(), siphon_rtp_datapath::DatapathError> {
        let Some(dtls) = transport.dtls.as_ref() else {
            return Ok(());
        };
        let endpoint = transport.endpoint;
        // The role matching the `a=setup` advertised in the answer (RFC 4145 §4.1, RFC 5763 §5).
        let (_, role) = super::negotiate::answerer_dtls_setup(info.setup, None);
        self.datapath
            .install_flow(endpoint.id, FlowAction::Redirect)?;
        // The seat's validated source as the datapath publishes it: a full agent's selection, or the
        // source of the check the ice-lite responder authenticated. `None` without ICE.
        let ice_validated = self.datapath.watch_ice_validated(endpoint.id);
        self.dtls_bridge().register_for_pipeline(
            DtlsCallPlan {
                // A room seat is one muxed endpoint; the "plain" side is unused in pipeline mode
                // (the room owns egress), so it mirrors the secure one.
                plain_endpoint: endpoint.id,
                plain_source: transport.accepted_source,
                plain_dst: transport.seat_remote,
                secure_endpoint: endpoint.id,
                secure_source: transport.accepted_source,
                secure_dst: transport.seat_remote,
                secure_local: endpoint.local_addr,
                certificate: dtls.certificate.clone(),
                role,
                peer_fingerprint: DtlsFingerprint::new(
                    dtls.peer_fingerprint.hash_function.clone(),
                    dtls.peer_fingerprint.bytes.clone(),
                ),
                // RFC 8445 §12, §12.1.1: a DTLS-SRTP seat keys the transport ICE chose. A full
                // agent's selection and an ice-lite responder's validated check both arrive through
                // `ice_validated`, so the handshake waits for either and its records follow it; a
                // seat without ICE starts at once, since nothing would release it.
                gate_on_ice: transport.ice_pending || ice_validated.is_some(),
                ice_validated,
                plain_rtcp: None,
            },
            target,
        );
        Ok(())
    }

    /// Write the answer to a seat's offer: the engine's endpoint, ICE (re-originated with the
    /// credentials and candidates minted for it, `a=ice-mismatch` when the offer's ICE was altered in
    /// transit so the peer stops waiting for checks that will never come, stripped on `ICE=remove`),
    /// and the keying the seat negotiated. A room leg is always RTP/RTCP-muxed onto the one endpoint,
    /// so the mux presentation mirrors the offer (the `rtcp-mux` directive is an offer/answer relay
    /// concern, not a room one).
    ///
    /// # Errors
    /// The SDP rewrite's refusal.
    pub(super) fn answer_seat_sdp(
        &self,
        offer: &str,
        transport: &mut SeatTransport,
        profile: &ProfileFlags,
        text: TextRewrite,
    ) -> Result<String, sdp::SdpError> {
        let engine = EngineMedia {
            rtp: transport.endpoint.local_addr,
            rtcp: None,
            advertised_ip: transport.advertised,
        };
        let security = transport.security.take();
        let ice = transport.ice_rewrite(profile);
        sdp::rewrite(offer, engine, ice, security, None, text, ImageRewrite::None)
            .map(|rewritten| rewritten.sdp)
    }
}
