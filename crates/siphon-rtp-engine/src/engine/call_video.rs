//! Anchored video on a two-party relayed call (`ProfileFlags::video_relay`).
//!
//! The engine relays an offered `m=video` stream like its audio one: an endpoint pair per leg
//! (one when RTCP is muxed), the gated latch per stream (the same [`ingress_rule`] audio uses), the
//! direction attributes respected, and no transcoding (codecs and payload numbers are the two
//! parties' own). Plain RTP and SDES-SRTP per leg ([`super::call_video_secure`]); anything else is
//! declined with the reason in `video_declined`, never relayed unkeyed. See
//! docs/security-and-nat.md, "Video on a two-party call".

use siphon_rtp_datapath::{AddressFamily, Datapath, Endpoint, EndpointId, FlowAction};
use siphon_rtp_proto::{ProfileFlags, VideoRelay, VideoStats};
use std::net::{IpAddr, SocketAddr};

use super::answer::ingress_rule;
use super::call_video_secure::{Exchange, VideoFlowRule, VideoKeys};
use super::negotiate::{apply_received_from, far_received_from_hint, peer_media_address};
use super::{Engine, Leg, Party};
use crate::sdp::{self, EngineMedia, MediaDirection, VideoRewrite, VideoStream};

/// One side's video endpoints and what that side signalled.
#[derive(Debug, Clone, Copy)]
pub(super) struct VideoLeg {
    pub(super) rtp: Endpoint,
    /// The companion RTCP endpoint; `None` under `a=rtcp-mux` (RFC 5761).
    pub(super) rtcp: Option<Endpoint>,
    /// Where this side receives video RTP, from its SDP. `None` until known (B's, before its answer).
    pub(super) remote_rtp: Option<SocketAddr>,
    pub(super) remote_rtcp: Option<SocketAddr>,
    /// The stream rides the leg's audio endpoint and its DTLS association (RFC 8843): `rtp` is the
    /// audio's, which this stream does not own.
    pub(super) bundled: bool,
}

impl VideoLeg {
    /// Every datapath endpoint the stream owns: none when it is bundled with the audio.
    pub(super) fn endpoint_ids(&self) -> impl Iterator<Item = EndpointId> {
        let bundled = self.bundled;
        std::iter::once(self.rtp.id)
            .filter(move |_| !bundled)
            .chain(self.rtcp.map(|endpoint| endpoint.id))
    }

    /// The endpoints this leg presents in SDP, at the leg's advertised address.
    pub(super) fn engine_media(&self, advertised_ip: IpAddr) -> EngineMedia {
        EngineMedia {
            rtp: self.rtp.local_addr,
            rtcp: self.rtcp.map(|endpoint| endpoint.local_addr),
            advertised_ip,
        }
    }
}

/// The video state of a call that is not on a leg.
#[derive(Debug, Clone, Default)]
pub(super) struct CallVideo {
    /// The mode in force, from the profile of the offer (or a later verb that restated it).
    pub(super) mode: VideoRelay,
    /// Each party's own stated video direction (RFC 3264 §6.1).
    pub(super) near_direction: MediaDirection,
    pub(super) far_direction: MediaDirection,
    /// The in-datapath video flows installed at the last answer, kept so the latch refresh sweep
    /// can reprogram their destinations and a snapshot can name them.
    pub(super) flows: Vec<(EndpointId, FlowAction)>,
    /// Why the last offered or answered video stream was declined, when anchoring was asked.
    pub(super) declined: Option<String>,
    /// Each party's SDES keys for the stream; a party with none is on plain RTP.
    pub(super) keys: VideoKeys,
    /// The flows the SRTP bridge carries when either party is secure: their source gates, latches
    /// and destinations, kept for the snapshot and for the rollover read on a renegotiation.
    pub(super) bridged: Vec<VideoFlowRule>,
    /// Each party's DTLS-SRTP keying of the stream, see [`super::call_video_dtls`].
    pub(super) dtls: super::call_video_dtls::VideoDtls,
    /// Each party's video section accepts Picture Loss Indication (RFC 4585 §4.2).
    pub(super) near_picture_loss: bool,
    pub(super) far_picture_loss: bool,
    /// The SSRC each party declared for its video stream with `a=ssrc` (RFC 5576 §4.1), which names the
    /// stream a keyframe request is about when the relay has latched none.
    pub(super) near_ssrc: Option<u32>,
    pub(super) far_ssrc: Option<u32>,
    /// The keyframe requests still to send once the relay went live.
    pub(super) keyframe: super::call_video_local::KeyframeRequests,
    /// The far party's `sprop-parameter-sets` (RFC 6184 §8.1) of an `answer_local` call, which its
    /// caller's frozen answer cannot carry: the injector hands them over in-band
    /// ([`crate::video_injector`]). Only set for packetization modes 0 and 1.
    pub(super) far_sprop: Option<Box<siphon_rtp_media::h264::ParameterSets>>,
    /// The injector now carrying the far party's video toward the caller, while it is armed.
    pub(super) injector: Option<std::sync::Arc<crate::video_injector::VideoInjector>>,
    /// The injector has delivered the sets (or given up): a renegotiation does not arm another,
    /// the caller's decoder already has them.
    pub(super) sprop_spent: bool,
}

/// The leg's video stream rebuilt from its snapshot and the endpoints bound for it.
pub(super) fn video_leg(
    snapshot: Option<&crate::ha::VideoSnapshot>,
    rtp: Option<Endpoint>,
    rtcp: Option<Endpoint>,
) -> Option<VideoLeg> {
    let (snapshot, rtp) = (snapshot?, rtp?);
    Some(VideoLeg {
        rtp,
        rtcp,
        remote_rtp: snapshot.remote_rtp,
        remote_rtcp: snapshot.remote_rtcp,
        bundled: false,
    })
}

/// The call-level video state of a restored call: its mode, each party's own direction and its keys.
///
/// # Errors
/// A recorded key that cannot be rebuilt: the call is refused rather than restored as plain RTP
/// on a leg that negotiated SRTP.
pub(super) fn restored_call_video(
    snapshot: &crate::ha::CallSnapshot,
    near: &Leg,
) -> Result<CallVideo, Box<siphon_rtp_proto::CmdResult>> {
    let direction = |token: &str| MediaDirection::parse(token).unwrap_or_default();
    // A call whose far party declined the video keeps the caller's answered stream alone.
    let Some(video) = snapshot.video.as_ref().filter(|_| near.video.is_some()) else {
        return Ok(CallVideo::default());
    };
    let keys = VideoKeys::restored(video.secure.as_ref()).map_err(|reason| {
        Box::new(siphon_rtp_proto::CmdResult::Error {
            reason: format!("restore: video keys: {reason}"),
        })
    })?;
    Ok(CallVideo {
        mode: video.mode,
        near_direction: direction(&video.near_direction),
        far_direction: direction(&video.far_direction),
        flows: Vec::new(),
        declined: None,
        keys,
        bridged: Vec::new(),
        dtls: super::call_video_dtls::VideoDtls::default(),
        near_picture_loss: false,
        far_picture_loss: false,
        near_ssrc: None,
        far_ssrc: None,
        keyframe: super::call_video_local::KeyframeRequests::default(),
        far_sprop: None,
        injector: None,
        sprop_spent: false,
    })
}

/// The video flows of a restored call: the datapath rules or drops installed, and the flows the SRTP
/// bridge carries when the stream is secure.
#[derive(Default)]
pub(super) struct RestoredVideoFlows {
    pub(super) flows: Vec<(EndpointId, FlowAction)>,
    pub(super) bridged: Vec<VideoFlowRule>,
}

/// What negotiating a video stream decides for the SDP presented to the other party.
pub(super) struct VideoOutcome {
    pub(super) rewrite: VideoRewrite,
    pub(super) declined: Option<String>,
}

impl VideoOutcome {
    pub(super) fn passthrough() -> Self {
        Self {
            rewrite: VideoRewrite::Passthrough,
            declined: None,
        }
    }

    fn declined(reason: impl Into<String>) -> Self {
        Self {
            rewrite: VideoRewrite::Decline,
            declined: Some(reason.into()),
        }
    }
}

/// `result` with the reason a requested video stream was declined, when there is one.
pub(super) fn with_video_declined(
    mut result: siphon_rtp_proto::CmdResult,
    reason: Option<String>,
) -> siphon_rtp_proto::CmdResult {
    if let siphon_rtp_proto::CmdResult::Ok { video_declined, .. } = &mut result {
        if reason.is_some() {
            *video_declined = reason;
        }
    }
    result
}

/// The refusal of a verb that does not relay a two-party call's video: a mixing room decodes its
/// seats' audio, a forwarding room carries video by its own `video` profile, and a subscription and a
/// WebSocket bridge have no video stream to anchor, so a `video_relay` choice there would silently do
/// nothing. `answer_local` and `offer_far` take it ([`super::call_video_local`]).
pub(super) fn video_relay_refusal(
    command: &siphon_rtp_proto::Command,
) -> Option<siphon_rtp_proto::CmdResult> {
    use siphon_rtp_proto::Command;
    let (verb, profile) = match command {
        Command::ConferenceJoin { profile, .. } => ("conference_join", profile),
        Command::ConferenceOffer { profile, .. } => ("conference_offer", profile),
        Command::ForwardJoin { profile, .. } => ("forward_join", profile),
        Command::ForwardOffer { profile, .. } => ("forward_offer", profile),
        Command::SubscribeRequest { profile, .. } => ("subscribe_request", profile),
        Command::SubscribeAnswer { profile, .. } => ("subscribe_answer", profile),
        Command::AttachWsBridge {
            profile: Some(profile),
            ..
        } => ("attach_ws_bridge", profile),
        _ => return None,
    };
    (profile.video_relay != VideoRelay::Passthrough).then(|| {
        super::error_result(
            verb,
            &"video_relay applies to a two-party offer, answer and reoffer only: this verb does not \
              relay a call's video stream",
        )
    })
}

/// The forward rule of one video ingress endpoint, or a drop: media from a party that said it does
/// not send, or toward one that does not receive, is never relayed (RFC 3264 §6.1, §8.4).
fn video_action(allowed: bool, rule: siphon_rtp_datapath::ForwardRule) -> FlowAction {
    if allowed {
        FlowAction::Forward(rule)
    } else {
        FlowAction::Drop
    }
}

impl super::Call {
    /// The role of one of this call's video endpoints, for the snapshot of its flows.
    pub(super) fn video_endpoint_role(&self, id: EndpointId) -> Option<crate::ha::EndpointRole> {
        use crate::ha::EndpointRole;
        let is = |video: Option<VideoLeg>, rtcp: bool| {
            video
                .and_then(|video| if rtcp { video.rtcp } else { Some(video.rtp) })
                .is_some_and(|endpoint| endpoint.id == id)
        };
        let far = self.far.as_ref().and_then(|far| far.video);
        if is(self.near.video, false) {
            Some(EndpointRole::NearVideo)
        } else if is(self.near.video, true) {
            Some(EndpointRole::NearVideoRtcp)
        } else if is(far, false) {
            Some(EndpointRole::FarVideo)
        } else if is(far, true) {
            Some(EndpointRole::FarVideoRtcp)
        } else {
            None
        }
    }

    /// The call's anchored video stream as an HA snapshot, `None` when it carries none.
    pub(super) fn video_snapshot(&self) -> Option<crate::ha::CallVideoSnapshot> {
        // The caller's answered stream alone (a far party that declined it) is snapshotted too.
        self.near.video?;
        // The in-kernel rules, or, on a secure stream, the rules its bridge flows carry.
        let forwards = self
            .video
            .flows
            .iter()
            .filter_map(|(endpoint, action)| match action {
                FlowAction::Forward(rule) => Some((*endpoint, *rule)),
                _ => None,
            })
            .chain(
                self.video
                    .bridged
                    .iter()
                    .map(|flow| (flow.endpoint, flow.rule)),
            );
        let flows = forwards
            .filter_map(|(endpoint, rule)| {
                Some(crate::ha::FlowSnapshot {
                    installed_on: self.video_endpoint_role(endpoint)?,
                    out: self.video_endpoint_role(rule.out_endpoint)?,
                    out_dst: rule.out_dst,
                    accepted_source: super::snapshot::source_filter_snapshot(rule.accepted_source),
                    latch: super::snapshot::latch_snapshot(rule.latch),
                    rtcp_to_userspace: rule.rtcp_to_userspace,
                })
            })
            .collect();
        Some(crate::ha::CallVideoSnapshot {
            mode: self.video.mode,
            near_direction: self.video.near_direction.token().to_string(),
            far_direction: self.video.far_direction.token().to_string(),
            flows,
            secure: self.video.keys.snapshot(),
        })
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Reinstall a restored call's video flows: each snapshotted forward rule on its freshly bound
    /// endpoints, and a drop on every other video endpoint (a direction the parties did not allow).
    /// The source gate and latch come back exactly as the primary held them, so a restore never
    /// opens a window the primary had closed.
    pub(super) fn restore_video_flows(
        &self,
        snapshot: &crate::ha::CallSnapshot,
        bound: &[(crate::ha::EndpointRole, Endpoint)],
    ) -> Result<RestoredVideoFlows, Box<siphon_rtp_proto::CmdResult>> {
        use crate::ha::EndpointRole;
        let Some(video) = snapshot.video.as_ref() else {
            return Ok(RestoredVideoFlows::default());
        };
        let find = |role: EndpointRole| {
            bound
                .iter()
                .find(|(bound_role, _)| *bound_role == role)
                .map(|(_, endpoint)| *endpoint)
        };
        let refuse = |reason: String| {
            Box::new(siphon_rtp_proto::CmdResult::Error {
                reason: format!("restore: {reason}"),
            })
        };
        let keys = VideoKeys::restored(video.secure.as_ref())
            .map_err(|reason| refuse(format!("video keys: {reason}")))?;
        let mut installed: Vec<(EndpointId, FlowAction)> = Vec::new();
        let mut bridged: Vec<VideoFlowRule> = Vec::new();
        for flow in &video.flows {
            let (Some(on), Some(out)) = (find(flow.installed_on), find(flow.out)) else {
                return Err(refuse(
                    "a video flow references an unknown endpoint role".to_string(),
                ));
            };
            let rule = siphon_rtp_datapath::ForwardRule {
                out_endpoint: out.id,
                out_dst: flow.out_dst,
                accepted_source: super::snapshot::restore_source_filter(flow.accepted_source),
                latch: super::snapshot::restore_latch(flow.latch),
                rtcp_to_userspace: flow.rtcp_to_userspace,
            };
            if keys.is_secure() {
                let ingress = match flow.installed_on {
                    EndpointRole::NearVideo | EndpointRole::NearVideoRtcp => Party::Near,
                    _ => Party::Far,
                };
                bridged.push(VideoFlowRule {
                    endpoint: on.id,
                    ingress,
                    rule,
                });
                continue;
            }
            let action = FlowAction::Forward(rule);
            self.datapath
                .install_flow(on.id, action)
                .map_err(|error| refuse(format!("install video flow: {error}")))?;
            installed.push((on.id, action));
        }
        let roles = [
            EndpointRole::NearVideo,
            EndpointRole::FarVideo,
            EndpointRole::NearVideoRtcp,
            EndpointRole::FarVideoRtcp,
        ];
        if keys.is_secure() {
            // The stream is carried by the SRTP bridge, each secure leg seeded with the rollover the
            // primary had (RFC 3711 §3.3.1), and the flows reinstalled on their gates and latches.
            let endpoints: Vec<EndpointId> = roles
                .iter()
                .filter_map(|role| find(*role))
                .map(|endpoint| endpoint.id)
                .collect();
            let seeds = video.secure.as_ref();
            let previous = (
                seeds
                    .and_then(|secure| secure.near_rollover.as_ref())
                    .map(super::snapshot::restore_rollover),
                seeds
                    .and_then(|secure| secure.far_rollover.as_ref())
                    .map(super::snapshot::restore_rollover),
            );
            let flows = self
                .install_video_bridge(&keys, &bridged, &endpoints, (None, None), previous)
                .map_err(|reason| refuse(format!("video bridge: {reason}")))?;
            return Ok(RestoredVideoFlows { flows, bridged });
        }
        for role in roles {
            let Some(endpoint) = find(role) else {
                continue;
            };
            if !installed.iter().any(|(id, _)| *id == endpoint.id) {
                self.datapath
                    .install_flow(endpoint.id, FlowAction::Drop)
                    .map_err(|error| refuse(format!("install video drop: {error}")))?;
                installed.push((endpoint.id, FlowAction::Drop));
            }
        }
        Ok(RestoredVideoFlows {
            flows: installed,
            bridged,
        })
    }

    /// Allocate a video endpoint set (one RTP, plus RTCP unless muxed) on `leg`'s interface.
    pub(super) async fn alloc_video_leg(&self, leg: &Leg, muxed: bool) -> Result<VideoLeg, String> {
        let bind = leg.rtp.local_addr.ip();
        self.alloc_video_endpoints(AddressFamily::of(bind), bind, muxed)
            .await
    }

    /// Allocate a video endpoint set bound to `bind`.
    pub(super) async fn alloc_video_endpoints(
        &self,
        family: AddressFamily,
        bind: IpAddr,
        muxed: bool,
    ) -> Result<VideoLeg, String> {
        let mut endpoints = self
            .alloc_endpoints(if muxed { 1 } else { 2 }, family, Some(bind))
            .await?;
        let rtcp = (!muxed).then(|| endpoints.remove(1));
        Ok(VideoLeg {
            rtp: endpoints.remove(0),
            rtcp,
            remote_rtp: None,
            remote_rtcp: None,
            bundled: false,
        })
    }

    /// Free the call's video endpoints and flows (the stream was declined, dropped, or the call
    /// never carried one).
    pub(super) async fn free_call_video(&self, call_id: &str) {
        self.drop_dtls_video(call_id);
        let mut freed = Vec::new();
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(video) = call.near.video.take() {
                freed.extend(video.endpoint_ids());
            }
            if let Some(video) = call.far.as_mut().and_then(|far| far.video.take()) {
                freed.extend(video.endpoint_ids());
            }
            call.video.flows.clear();
            call.video.bridged.clear();
            call.video.keys = VideoKeys::default();
        }
        // A secure stream leaves the SRTP bridge with its endpoints, so no flow outlives them.
        self.bridge.deregister(freed.iter().copied());
        for endpoint in freed {
            self.endpoint_calls.remove(&endpoint);
            self.awaiting_media.remove(&endpoint);
            self.release_endpoint(endpoint).await;
        }
    }

    /// Negotiate the video stream of `sdp`, the SDP of `party` (an offer, a re-offer or an answer):
    /// record its address and direction, allocate or free endpoints, and say how the SDP presented
    /// to the other party carries the stream.
    ///
    /// `answering` is set for an answer, which cannot add a stream the offer did not carry
    /// (RFC 3264 §6): B's video in an answer to an offer with none is declined.
    pub(super) async fn negotiate_call_video(
        &self,
        call_id: &str,
        party: Party,
        sdp: &str,
        profile: &ProfileFlags,
        answering: bool,
    ) -> VideoOutcome {
        let Some((stored_mode, near, far)) = self
            .calls
            .get(call_id)
            .map(|call| (call.video.mode, call.near, call.far))
        else {
            return VideoOutcome::passthrough();
        };
        let mode = if profile.video_relay == VideoRelay::Passthrough {
            stored_mode
        } else {
            profile.video_relay
        };
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.video.mode = mode;
            call.video.declined = None;
        }
        match mode {
            VideoRelay::Passthrough => return VideoOutcome::passthrough(),
            VideoRelay::Decline => {
                self.release_declined_video(call_id).await;
                return VideoOutcome {
                    rewrite: VideoRewrite::Decline,
                    declined: None,
                };
            }
            VideoRelay::Anchor => {}
        }
        // A call the engine answered itself has no far leg to relay video to.
        let Some(far) = far else {
            return VideoOutcome::passthrough();
        };
        let Some(stream) = sdp::parse_video_stream(sdp) else {
            // No live stream from this party: whatever the call anchored is over.
            self.release_declined_video(call_id).await;
            return VideoOutcome::passthrough();
        };
        let outcome = self
            .anchor_video_stream(call_id, party, &stream, (near, far), (answering, profile))
            .await;
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.video.declined.clone_from(&outcome.declined);
        }
        outcome
    }

    /// Whether the engine offers a first-offered video stream's far party SDES-SRTP, as the audio
    /// leg's far transport says (`RTP/SAVP`). A DTLS-SRTP far leg is keyed by its own association
    /// instead ([`super::call_video_dtls`]).
    fn far_offers_srtp(&self, call_id: &str, profile: &ProfileFlags) -> bool {
        let transport = profile.transport_protocol.as_deref().unwrap_or_default();
        let (audio_dtls, audio_sdes) = self
            .calls
            .get(call_id)
            .map(|call| (call.far_dtls, call.far_local_crypto.is_some()))
            .unwrap_or_default();
        !audio_dtls && (transport.contains("SAVP") || audio_sdes)
    }

    async fn anchor_video_stream(
        &self,
        call_id: &str,
        party: Party,
        stream: &VideoStream,
        (near, far): (Leg, Leg),
        (answering, profile): (bool, &ProfileFlags),
    ) -> VideoOutcome {
        let allocated = near.video.zip(far.video);
        // Settle each party's keys first: a stream that cannot be keyed is declined before anything
        // is allocated or relayed (RFC 4568 §7.1: never in the clear).
        let mut keys = self
            .calls
            .get(call_id)
            .map(|call| call.video.keys)
            .unwrap_or_default();
        let exchange = if answering {
            Exchange::Answer
        } else if allocated.is_some() {
            Exchange::Offer
        } else {
            Exchange::FirstOffer {
                far_secure: self.far_offers_srtp(call_id, profile),
            }
        };
        if let Err(reason) = self.settle_dtls_video(
            call_id,
            party,
            stream,
            matches!(exchange, Exchange::FirstOffer { .. }),
            profile,
        ) {
            self.release_declined_video(call_id).await;
            return VideoOutcome::declined(reason);
        }
        // A DTLS stream is keyed by its handshake, not by SDES keys.
        if !stream.is_dtls() {
            if let Err(reason) = keys.settle(party, stream, exchange) {
                self.release_declined_video(call_id).await;
                return VideoOutcome::declined(reason);
            }
        }
        let bundled_near = party == Party::Near && stream.is_dtls() && stream.bundled;
        if let Some(near_video) = near.video {
            if party == Party::Near && near_video.bundled != bundled_near {
                self.release_declined_video(call_id).await;
                return VideoOutcome::declined(
                    "a re-offer cannot move the video stream in or out of the audio's bundle",
                );
            }
        }
        // The caller's stream may already own endpoints without a far one (a local answer whose far
        // party declined its video): the muxing it was answered with stays.
        let muxed = match near.video {
            Some(near_video) => near_video.rtcp.is_none(),
            None => stream.rtcp_mux,
        };
        if near.video.is_some() && stream.rtcp_mux != muxed {
            // RFC 5761 §5.1.1: the answer chooses; a party that answers the other way would put its
            // RTCP where no endpoint listens, so the stream is declined rather than half carried.
            self.release_declined_video(call_id).await;
            return VideoOutcome::declined(
                "the party did not keep the rtcp-mux choice the video endpoints were bound for",
            );
        }
        if allocated.is_none() {
            if answering {
                self.release_declined_video(call_id).await;
                return VideoOutcome::declined("the offer carried no video stream to answer");
            }
            let near_video = if let Some(existing) = near.video {
                existing
            } else if bundled_near {
                // RFC 8843: the video shares the audio's transport, so it owns no endpoint.
                VideoLeg {
                    rtp: near.rtp,
                    rtcp: None,
                    remote_rtp: None,
                    remote_rtcp: None,
                    bundled: true,
                }
            } else {
                match self.alloc_video_leg(&near, muxed).await {
                    Ok(video) => video,
                    Err(reason) => {
                        return VideoOutcome::declined(format!("video endpoints: {reason}"))
                    }
                }
            };
            let far_video = match self.alloc_video_leg(&far, muxed).await {
                Ok(video) => video,
                Err(reason) => {
                    // Endpoints the caller's frozen answer already names are not this call's to free.
                    if near.video.is_none() {
                        for endpoint in near_video.endpoint_ids() {
                            self.release_endpoint(endpoint).await;
                        }
                    }
                    return VideoOutcome::declined(format!("video endpoints: {reason}"));
                }
            };
            if let Some(mut call) = self.calls.get_mut(call_id) {
                call.near.video = Some(near_video);
                if let Some(stored) = call.far.as_mut() {
                    stored.video = Some(far_video);
                }
            }
            for endpoint in near_video.endpoint_ids().chain(far_video.endpoint_ids()) {
                self.endpoint_calls.insert(endpoint, call_id.to_string());
            }
        }
        // Record the party's own address and direction, and present the other party's leg.
        let mut presented = None;
        if let Some(mut call) = self.calls.get_mut(call_id) {
            let (own, own_direction) = match party {
                Party::Near => (Some(&mut call.near), true),
                Party::Far => (call.far.as_mut(), false),
            };
            if let Some(video) = own.and_then(|leg| leg.video.as_mut()) {
                video.remote_rtp = Some(stream.remote_rtp);
                video.remote_rtcp = Some(stream.remote_rtcp);
            }
            if own_direction {
                call.video.near_direction = stream.direction;
                call.video.near_picture_loss = stream.picture_loss;
                call.video.near_ssrc = stream.ssrc;
            } else {
                call.video.far_direction = stream.direction;
                call.video.far_picture_loss = stream.picture_loss;
                call.video.far_ssrc = stream.ssrc;
            }
            call.video.keys = keys;
            let other = match party {
                Party::Near => call.far.as_ref(),
                Party::Far => Some(&call.near),
            };
            presented =
                other.and_then(|leg| leg.video.map(|video| video.engine_media(leg.advertised_ip)));
        }
        let toward = match party {
            Party::Near => Party::Far,
            Party::Far => Party::Near,
        };
        match presented {
            Some(engine) => VideoOutcome {
                rewrite: VideoRewrite::Anchor {
                    engine,
                    keying: self
                        .dtls_keying_toward(call_id, toward)
                        .unwrap_or_else(|| keys.keying_toward(toward)),
                },
                declined: None,
            },
            None => VideoOutcome::declined("video endpoints are not available"),
        }
    }

    /// The reply to an offer: the presented SDP with the video stream anchored on its own endpoints
    /// when the profile asks for it, and the reason a requested stream was declined. A WebSocket
    /// takeover has no far party to relay video to, so it anchors none.
    pub(super) async fn offer_video_reply(
        &self,
        call_id: &str,
        sdp: &str,
        profile: &ProfileFlags,
        presented: String,
    ) -> siphon_rtp_proto::CmdResult {
        let video = if profile.ws_uri.is_none() {
            self.negotiate_call_video(call_id, Party::Near, sdp, profile, false)
                .await
        } else {
            VideoOutcome::passthrough()
        };
        let presented = video.rewrite.apply(&presented);
        with_video_declined(
            self.ok_sdp_keyed(call_id, presented, None, profile).await,
            video.declined,
        )
    }

    /// The reply to an answer: the video stream settled from the answering party's SDP, its relay
    /// installed, and `presented` carrying it for the other party.
    pub(super) async fn video_reply(
        &self,
        call_id: &str,
        (sdp, profile, reversed): (&str, &ProfileFlags, bool),
        (presented, to_tag): (String, String),
    ) -> siphon_rtp_proto::CmdResult {
        match self
            .settle_answered_video(call_id, sdp, profile, reversed, &presented)
            .await
        {
            Ok((presented, declined)) => with_video_declined(
                self.ok_sdp_keyed(call_id, presented, Some(to_tag), profile)
                    .await,
                declined,
            ),
            Err(result) => *result,
        }
    }

    /// The reply to a re-offer: the video stream follows it. A moved address or direction is
    /// recorded (the answer that completes the exchange re-gates the relay on it), a stream added
    /// mid-call gets endpoints, one dropped frees them, and the other party is shown the engine's own.
    pub(super) async fn reoffer_video_reply(
        &self,
        call_id: &str,
        party: Party,
        sdp: &str,
        profile: &ProfileFlags,
        presentation: super::negotiate::LegPresentation<'_>,
    ) -> siphon_rtp_proto::CmdResult {
        let video = self
            .negotiate_call_video(call_id, party, sdp, profile, false)
            .await;
        match super::negotiate::present_leg(sdp, presentation, &profile.replace, call_id) {
            Ok(presented) => with_video_declined(
                super::key_mgmt::ok_sdp_keyed_in_place(&video.rewrite.apply(&presented), profile),
                video.declined,
            ),
            Err(error) => super::error_result("re-offer rewrite", &error),
        }
    }

    /// The datapath counters of `leg`'s video endpoints, or `None` when the leg carries no video.
    pub(super) fn video_stats(&self, leg: &Leg) -> Option<VideoStats> {
        let video = leg.video?;
        let mut total = VideoStats::default();
        for endpoint in video.endpoint_ids() {
            let stats = self.datapath.stats(endpoint).unwrap_or_default();
            total.packets_in += stats.packets_in;
            total.packets_out += stats.packets_out;
            total.bytes_in += stats.bytes_in;
            total.bytes_out += stats.bytes_out;
        }
        Some(total)
    }

    /// Settle an answer's video stream: negotiate it from the answering party's SDP, install the
    /// relay, and return `presented` with the stream anchored (or declined) for the other party,
    /// plus the reason a requested stream was declined.
    pub(super) async fn settle_answered_video(
        &self,
        call_id: &str,
        sdp: &str,
        profile: &ProfileFlags,
        reversed: bool,
        presented: &str,
    ) -> Result<(String, Option<String>), Box<siphon_rtp_proto::CmdResult>> {
        let answering = if reversed { Party::Near } else { Party::Far };
        let video = self
            .negotiate_call_video(call_id, answering, sdp, profile, true)
            .await;
        if let Err(reason) = self.install_video_relay(call_id, profile, reversed) {
            return Err(Box::new(siphon_rtp_proto::CmdResult::Error {
                reason: format!("answer: {reason}"),
            }));
        }
        Ok((video.rewrite.apply(presented), video.declined))
    }

    /// Install the in-datapath video relay for an answered call: the ingress rule of each video
    /// endpoint, gated on the SDP-signalled address exactly as audio is (a `received-from` hint, the
    /// `subnet-source` and `symmetric` flags apply the same way), and a drop for every direction the
    /// negotiated directions do not allow. Returns an error reason when the datapath refuses a flow.
    pub(super) fn install_video_relay(
        &self,
        call_id: &str,
        profile: &ProfileFlags,
        reversed: bool,
    ) -> Result<(), String> {
        let Some((near, far, near_direction, far_direction, offer_hint, stored_far_hint, keys)) =
            self.calls.get(call_id).and_then(|call| {
                Some((
                    call.near.video?,
                    call.far.as_ref()?.video?,
                    call.video.near_direction,
                    call.video.far_direction,
                    call.offer_received_from,
                    call.far_received_from,
                    call.video.keys,
                ))
            })
        else {
            return Ok(());
        };
        let (Some(near_rtp), Some(far_rtp)) = (near.remote_rtp, far.remote_rtp) else {
            return Ok(());
        };
        let far_hint = far_received_from_hint(reversed, profile, stored_far_hint);
        let near_gate = apply_received_from(Some(near_rtp), offer_hint);
        let far_gate = peer_media_address(far_rtp, far_hint);
        let (near_to_far, far_to_near) = sdp::flow_directions(near_direction, far_direction);
        // RTCP carries receiver feedback (reports, picture loss) against the media's direction, so
        // it flows both ways whenever the stream flows at all. Muxed RTCP shares the RTP endpoint
        // (RFC 5761), where a kernel rule cannot tell the two apart: the RTP direction rule then
        // yields to the RTCP one, see docs/security-and-nat.md.
        let any = near_to_far || far_to_near;
        let dtls_party = self.calls.get(call_id).and_then(|call| {
            call.video
                .dtls
                .near
                .as_ref()
                .map(|_| Party::Near)
                .or_else(|| call.video.dtls.far.as_ref().map(|_| Party::Far))
        });
        if let Some(secure_party) = dtls_party {
            let near_address = near_gate.unwrap_or(near_rtp);
            let (secure, plain, secure_address, plain_address, to_secure, to_plain) =
                match secure_party {
                    Party::Near => (near, far, near_address, far_gate, far_to_near, near_to_far),
                    Party::Far => (far, near, far_gate, near_address, near_to_far, far_to_near),
                };
            let audio_endpoint = self
                .calls
                .get(call_id)
                .map(|call| match secure_party {
                    Party::Near => call.near.rtp.id,
                    Party::Far => call.far.as_ref().map_or(secure.rtp.id, |far| far.rtp.id),
                })
                .unwrap_or(secure.rtp.id);
            return self.install_dtls_video(
                call_id,
                profile,
                super::call_video_dtls::DtlsVideoLegs {
                    secure_party,
                    secure: secure.rtp.id,
                    plain: plain.rtp.id,
                    audio_endpoint,
                    secure_local: secure.rtp.local_addr,
                    secure_address,
                    plain_address,
                    to_secure,
                    to_plain,
                },
            );
        }
        // A negotiation that replaces the flows cancels the injector of the previous one; a plain
        // relay re-arms it below while the caller still lacks the sets.
        self.disarm_video_injector(call_id);
        let near_rule = ingress_rule(far.rtp.id, Some(far_gate), near_gate, profile, false);
        let far_rule = ingress_rule(near.rtp.id, near_gate, Some(far_gate), profile, false);
        let muxed = near.rtcp.is_none() || far.rtcp.is_none();
        // Every video endpoint with the rule it would forward by, and whether its direction is open.
        let mut planned: Vec<(VideoFlowRule, bool)> = vec![
            (
                VideoFlowRule {
                    endpoint: near.rtp.id,
                    ingress: Party::Near,
                    rule: near_rule,
                },
                near_to_far || (muxed && any),
            ),
            (
                VideoFlowRule {
                    endpoint: far.rtp.id,
                    ingress: Party::Far,
                    rule: far_rule,
                },
                far_to_near || (muxed && any),
            ),
        ];
        if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
            let near_rtcp_gate = apply_received_from(near.remote_rtcp, offer_hint);
            let far_rtcp_gate = far
                .remote_rtcp
                .map(|addr| peer_media_address(addr, far_hint));
            let near_rtcp_rule =
                ingress_rule(far_rtcp.id, far_rtcp_gate, near_rtcp_gate, profile, false);
            let far_rtcp_rule =
                ingress_rule(near_rtcp.id, near_rtcp_gate, far_rtcp_gate, profile, false);
            planned.push((
                VideoFlowRule {
                    endpoint: near_rtcp.id,
                    ingress: Party::Near,
                    rule: near_rtcp_rule,
                },
                any,
            ));
            planned.push((
                VideoFlowRule {
                    endpoint: far_rtcp.id,
                    ingress: Party::Far,
                    rule: far_rtcp_rule,
                },
                any,
            ));
        }
        let endpoints: Vec<EndpointId> = near.endpoint_ids().chain(far.endpoint_ids()).collect();
        if keys.is_secure() {
            // SDES-SRTP: the SRTP bridge carries the stream, seeded with the rollover the previous
            // negotiation had (RFC 3711 §3.3.1), so a re-offer does not restart either counter.
            let open: Vec<VideoFlowRule> = planned
                .iter()
                .filter(|(_, allowed)| *allowed)
                .map(|(flow, _)| *flow)
                .collect();
            let every: Vec<VideoFlowRule> = planned.iter().map(|(flow, _)| *flow).collect();
            let live = self.live_video_legs(&every);
            let previous = self.live_video_rollover(&every);
            let flows = self.install_video_bridge(&keys, &open, &endpoints, live, previous)?;
            if let Some(mut call) = self.calls.get_mut(call_id) {
                call.video.flows = flows;
                call.video.bridged = open;
            }
            return Ok(());
        }
        // RFC 6184 §8.1: the far party's out-of-band parameter sets reach the caller in-band, ahead
        // of the first IDR (`crate::video_injector`). Decided now, so the far endpoint is never given
        // a `Forward` rule it would relay the first IDR by: it goes to the bridge flow directly, below.
        let injector = self.plan_video_injector(call_id, &far_rule, far_to_near);
        let injected = |endpoint: EndpointId| injector.is_some() && endpoint == far.rtp.id;
        // A stream that was secure and is plain now leaves the bridge before the kernel takes it; the
        // injected endpoint's flow is replaced in one step below instead.
        self.bridge.deregister(
            endpoints
                .into_iter()
                .filter(|endpoint| !injected(*endpoint)),
        );
        let mut flows: Vec<(EndpointId, FlowAction)> = Vec::new();
        for (flow, allowed) in planned {
            let action = video_action(allowed, flow.rule);
            if !injected(flow.endpoint) {
                self.datapath
                    .install_flow(flow.endpoint, action)
                    .map_err(|error| format!("install video flow: {error}"))?;
            }
            flows.push((flow.endpoint, action));
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.video.flows = flows;
            call.video.bridged.clear();
        }
        if let Some(injector) = injector {
            self.activate_video_injector(call_id, far.rtp.id, far_rule, injector);
        }
        // A call grown from a local answer starts each sending decoder on a keyframe.
        self.arm_keyframe_requests(call_id, near_to_far, far_to_near);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_datapath::ForwardRule;

    #[test]
    fn a_disallowed_direction_is_a_drop_and_an_allowed_one_forwards() {
        let rule = ForwardRule::symmetric(EndpointId(1), None);
        assert_eq!(video_action(false, rule), FlowAction::Drop);
        assert_eq!(video_action(true, rule), FlowAction::Forward(rule));
    }

    #[test]
    fn the_default_call_video_is_passthrough_with_no_flows() {
        let video = CallVideo::default();
        assert_eq!(video.mode, VideoRelay::Passthrough);
        assert!(video.flows.is_empty() && video.declined.is_none());
    }
}
