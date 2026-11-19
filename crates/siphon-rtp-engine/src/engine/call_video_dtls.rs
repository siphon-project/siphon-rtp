//! DTLS-SRTP on a two-party call's anchored video stream (RFC 5764, RFC 5763, RFC 8843).
//!
//! The engine terminates the DTLS of one party, and the other is plain RTP. Two shapes:
//!
//! * **bundled** (`a=group:BUNDLE` names the video mid and the audio's, RFC 8843 §7.2): the video rides
//!   the audio's 5-tuple and its one association. The leg's [`crate::dtls_bridge::DtlsBridge`] tells
//!   the video from the audio after unprotect, by payload type (unique across a bundle, RFC 8843 §9.2)
//!   and, for RTCP, by SSRC, and relays it out of the other party's video endpoint. The bundled
//!   party's [`VideoLeg`](super::call_video::VideoLeg) shares the audio endpoint and owns none.
//! * **unbundled, no ICE**: a second association on the video endpoint, with its own handshake, the
//!   engine's one certificate and the `a=setup` of its own section.
//!
//! Anything else is declined with the reason, never relayed unkeyed: unbundled with ICE (ICE would run
//! per `m=` line), video without `a=rtcp-mux` (an association protects one port pair, RFC 5764 §5.1.2),
//! DTLS toward SDES (a transcrypt between two keying mechanisms), a DTLS leg whose DTLS the engine does
//! not terminate, and a bundled leg whose audio the media pipeline owns.

use siphon_rtp_datapath::{Datapath, EndpointId, FlowAction};
use siphon_rtp_dtls::{DtlsRole, Fingerprint as DtlsFingerprint};
use siphon_rtp_proto::ProfileFlags;
use std::net::SocketAddr;

use super::negotiate::{answerer_dtls_setup, bridge_source_filter, setup_for_role};
use super::{Engine, Party, PipelineKind};
use crate::dtls_bridge::{DtlsCallPlan, DtlsVideoPlan};
use crate::sdp::{self, VideoKeying, VideoStream};

/// How one party's video is keyed by DTLS.
#[derive(Debug, Clone, Default)]
pub(super) struct DtlsSide {
    /// The audio and video `a=mid` the party offered, when the video rides its audio association.
    pub(super) bundle: Option<(String, String)>,
    /// The video payload types, which tell a bundled stream's RTP from the audio's.
    pub(super) payload_types: Vec<u8>,
    /// The peer's certificate fingerprint of an association of the video's own (RFC 5763 §5).
    pub(super) peer_fingerprint: Option<sdp::Fingerprint>,
    /// The engine's role on that association, once settled.
    pub(super) role: Option<DtlsRole>,
}

/// Each party's DTLS video keying; a party with none is plain RTP (or SDES, see `VideoKeys`).
#[derive(Debug, Clone, Default)]
pub(super) struct VideoDtls {
    pub(super) near: Option<DtlsSide>,
    pub(super) far: Option<DtlsSide>,
}

impl VideoDtls {
    fn side(&self, party: Party) -> Option<&DtlsSide> {
        match party {
            Party::Near => self.near.as_ref(),
            Party::Far => self.far.as_ref(),
        }
    }

    fn slot(&mut self, party: Party) -> &mut Option<DtlsSide> {
        match party {
            Party::Near => &mut self.near,
            Party::Far => &mut self.far,
        }
    }
}

/// The role the engine takes against an answerer's `a=setup` (RFC 5763 §5, RFC 4145 §4.1): the
/// complement of the answer.
fn role_against(setup: Option<sdp::Setup>) -> DtlsRole {
    match setup {
        Some(sdp::Setup::Passive) => DtlsRole::Client,
        _ => DtlsRole::Server,
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// What the video section presented **to** `toward` says about keying, when that party's video is
    /// DTLS: the audio's bundle, or the engine's own fingerprint and role for the section.
    pub(super) fn dtls_keying_toward(&self, call_id: &str, toward: Party) -> Option<VideoKeying> {
        let side = self
            .calls
            .get(call_id)
            .and_then(|call| call.video.dtls.side(toward).cloned())?;
        if let Some((audio_mid, video_mid)) = side.bundle {
            return Some(VideoKeying::Bundled {
                audio_mid,
                video_mid,
            });
        }
        Some(VideoKeying::Dtls {
            fingerprint: self.engine_fingerprint()?,
            setup: side.role.map_or(sdp::Setup::Actpass, setup_for_role),
        })
    }

    /// Settle the DTLS keying of `party`'s video `stream` (an offer, a re-offer or an answer), or the
    /// reason it cannot be carried. A plain stream leaves a DTLS party alone only on the first offer
    /// of a call whose far leg is DTLS-SRTP: the engine then offers the far party DTLS video.
    pub(super) fn settle_dtls_video(
        &self,
        call_id: &str,
        party: Party,
        stream: &VideoStream,
        first_offer: bool,
        profile: &ProfileFlags,
    ) -> Result<(), String> {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return Ok(());
        };
        let (near_terminated, far_dtls, pipeline) =
            (call.near_dtls.is_some(), call.far_dtls, call.pipeline);
        let engine_ready = self.dtls_certificate.is_some();
        if !stream.is_dtls() {
            if call.video.dtls.side(party).is_some() {
                return Err(
                    "DTLS-SRTP video cannot be answered in the clear or moved to another transport \
                     by a re-offer"
                        .to_string(),
                );
            }
            // The far leg's audio is DTLS-SRTP: its video is offered DTLS-SRTP on an association of
            // its own, which needs the multiplexed RTCP an association protects (RFC 5764 §5.1.2).
            if party == Party::Near && first_offer && far_dtls {
                if !stream.rtcp_mux {
                    return Err(
                        "DTLS-SRTP video needs a=rtcp-mux: an association protects one port pair \
                         (RFC 5764 §5.1.2)"
                            .to_string(),
                    );
                }
                call.video.dtls.far = Some(DtlsSide::default());
            }
            return Ok(());
        }
        let valid = if !engine_ready {
            Err("DTLS-SRTP video needs the engine's DTLS certificate, which it has none of")
        } else if party == Party::Near && !near_terminated {
            Err(
                "DTLS-SRTP video is carried where the engine terminates the leg's DTLS, and this \
                 leg's DTLS passes through to the other party (ask for a plain far leg)",
            )
        } else if party == Party::Far && !far_dtls {
            Err("DTLS-SRTP video was answered where the engine offered none")
        } else if call.video.keys.is_secure() {
            Err(
                "DTLS-SRTP video toward an SDES-SRTP leg needs a transcrypt between two keying \
                 mechanisms, which is not carried",
            )
        } else if !stream.rtcp_mux {
            Err(
                "DTLS-SRTP video needs a=rtcp-mux: an association protects one port pair \
                 (RFC 5764 §5.1.2)",
            )
        } else if stream.bundled && stream.payload_collision {
            Err("a bundled video section shares a payload type with the audio, which RFC 8843 §9.2 \
                 forbids")
        } else if stream.bundled && party == Party::Far {
            Err("the answerer bundled video the engine offered on a transport of its own")
        } else if stream.bundled
            && matches!(
                pipeline,
                PipelineKind::DtlsOffererMedia | PipelineKind::DtlsMedia
            )
        {
            Err(
                "bundled DTLS-SRTP video is not carried on a leg whose audio the media pipeline \
                 transcodes or records",
            )
        } else if !stream.bundled && stream.ice {
            Err("DTLS-SRTP video that is not bundled with the audio and carries ICE would need a \
                 separate ICE session per m-line, which is not carried (bundle it with a=group:BUNDLE)")
        } else if !stream.bundled && stream.fingerprint.is_none() {
            Err("the DTLS-SRTP video section carries no a=fingerprint (RFC 5763 §5)")
        } else if stream.bundled && (stream.mid.is_none() || stream.audio_mid.is_none()) {
            Err("a bundled video section needs an a=mid on it and on the audio (RFC 8843 §7.2)")
        } else {
            Ok(())
        };
        valid.map_err(str::to_string)?;
        let previous = call.video.dtls.slot(party).take();
        let mut side = DtlsSide {
            payload_types: stream.payload_types.clone(),
            ..DtlsSide::default()
        };
        if stream.bundled {
            side.bundle = stream.audio_mid.clone().zip(stream.mid.clone());
        } else {
            // RFC 8842 §3.1: the same peer certificate keeps the association, and with it the role.
            let kept = previous
                .filter(|previous| previous.peer_fingerprint == stream.fingerprint)
                .and_then(|previous| previous.role);
            side.role = kept.or_else(|| {
                Some(match party {
                    Party::Near => {
                        answerer_dtls_setup(stream.setup, super::negotiate::dtls_directive(profile))
                            .1
                    }
                    Party::Far => role_against(stream.setup),
                })
            });
            side.peer_fingerprint.clone_from(&stream.fingerprint);
        }
        *call.video.dtls.slot(party) = Some(side);
        Ok(())
    }

    /// Detach a bundled video from the near leg's association and forget the DTLS state.
    pub(super) fn drop_dtls_video(&self, call_id: &str) {
        let mut detach: Option<EndpointId> = None;
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if call
                .video
                .dtls
                .near
                .as_ref()
                .is_some_and(|side| side.bundle.is_some())
            {
                detach = Some(call.near.rtp.id);
            }
            call.video.dtls = VideoDtls::default();
        }
        if let Some(endpoint) = detach {
            self.dtls_bridge().detach_video(endpoint);
        }
    }

    /// Install the DTLS video relay: a route on the bundled leg's association, or an association of
    /// the video's own, with the negotiated directions. `to_secure` is the plain party's video
    /// toward the DTLS one, `to_plain` the reverse.
    pub(super) fn install_dtls_video(
        &self,
        call_id: &str,
        profile: &ProfileFlags,
        legs: DtlsVideoLegs,
    ) -> Result<(), String> {
        let Some(side) = self
            .calls
            .get(call_id)
            .and_then(|call| call.video.dtls.side(legs.secure_party).cloned())
        else {
            return Ok(());
        };
        let bridge = self.dtls_bridge();
        let (secure, plain) = (legs.secure, legs.plain);
        let mut flows: Vec<(EndpointId, FlowAction)> = Vec::new();
        let any = legs.to_secure || legs.to_plain;
        if !any {
            // Nothing may flow, RTCP included: no association is worth keeping for the stream.
            let own = side.bundle.is_none();
            if own {
                bridge.deregister([secure, plain]);
            } else {
                bridge.detach_video(legs.audio_endpoint);
            }
            let closed: &[EndpointId] = if own { &[secure, plain] } else { &[plain] };
            for endpoint in closed {
                self.datapath
                    .install_flow(*endpoint, FlowAction::Drop)
                    .map_err(|error| format!("install video drop: {error}"))?;
                flows.push((*endpoint, FlowAction::Drop));
            }
        } else if side.bundle.is_some() {
            self.redirect_endpoints([plain], "install DTLS video redirect")
                .map_err(|_| "install DTLS video redirect".to_string())?;
            let attached = bridge.attach_video(&DtlsVideoPlan {
                secure_endpoint: legs.audio_endpoint,
                plain_endpoint: plain,
                plain_source: bridge_source_filter(profile, legs.plain_address),
                plain_dst: legs.plain_address,
                payload_types: side.payload_types.clone(),
                to_secure: legs.to_secure,
                to_plain: legs.to_plain,
            });
            if !attached {
                return Err("the leg's audio is not on the userspace DTLS bridge".to_string());
            }
            flows.push((plain, FlowAction::Redirect));
        } else {
            let (Some(certificate), Some(fingerprint), Some(role)) = (
                self.dtls_certificate.clone(),
                side.peer_fingerprint.clone(),
                side.role,
            ) else {
                return Err("the DTLS video association is not settled".to_string());
            };
            let plan = DtlsCallPlan {
                plain_endpoint: plain,
                plain_source: bridge_source_filter(profile, legs.plain_address),
                plain_dst: legs.plain_address,
                secure_endpoint: secure,
                secure_source: bridge_source_filter(profile, legs.secure_address),
                secure_dst: legs.secure_address,
                secure_local: legs.secure_local,
                certificate,
                role,
                peer_fingerprint: DtlsFingerprint::new(
                    fingerprint.hash_function,
                    fingerprint.bytes,
                ),
                gate_on_ice: false,
                ice_validated: None,
                plain_rtcp: None,
            };
            self.redirect_endpoints([plain, secure], "install DTLS video redirect")
                .map_err(|_| "install DTLS video redirect".to_string())?;
            if !bridge.renegotiate(&plan) {
                bridge.register(plan);
            }
            bridge.set_rtp_directions(secure, plain, (legs.to_secure, legs.to_plain));
            flows.push((plain, FlowAction::Redirect));
            flows.push((secure, FlowAction::Redirect));
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.video.flows = flows;
            call.video.bridged.clear();
        }
        Ok(())
    }
}

/// The two video legs of a DTLS stream, which one the engine terminates, where each is and which
/// directions are open.
pub(super) struct DtlsVideoLegs {
    pub(super) secure_party: Party,
    /// The secure party's video endpoint (its audio endpoint when bundled) and the plain party's.
    pub(super) secure: EndpointId,
    pub(super) plain: EndpointId,
    /// The endpoint the leg's audio association runs on (the secure party's audio endpoint).
    pub(super) audio_endpoint: EndpointId,
    pub(super) secure_local: SocketAddr,
    pub(super) secure_address: SocketAddr,
    pub(super) plain_address: SocketAddr,
    pub(super) to_secure: bool,
    pub(super) to_plain: bool,
}
