//! Anchored video on a two-party relayed call (`ProfileFlags::video_relay`).
//!
//! The engine relays an offered `m=video` stream like its audio one: an endpoint pair per leg
//! (one when RTCP is muxed), the gated latch per stream (the same [`ingress_rule`] audio uses), the
//! direction attributes respected, and no transcoding (codecs and payload numbers are the two
//! parties' own). Plain RTP only here; a secure profile is declined with the reason in
//! `video_declined`, never relayed unkeyed. See docs/security-and-nat.md, "Video on a two-party call".

use siphon_rtp_datapath::{AddressFamily, Datapath, Endpoint, EndpointId, FlowAction};
use siphon_rtp_proto::{ProfileFlags, VideoRelay, VideoStats};
use std::net::{IpAddr, SocketAddr};

use super::answer::ingress_rule;
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
}

impl VideoLeg {
    /// Every datapath endpoint of the stream.
    pub(super) fn endpoint_ids(&self) -> impl Iterator<Item = EndpointId> {
        std::iter::once(self.rtp.id).chain(self.rtcp.map(|endpoint| endpoint.id))
    }

    /// The endpoints this leg presents in SDP, at the leg's advertised address.
    fn engine_media(&self, advertised_ip: IpAddr) -> EngineMedia {
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
    })
}

/// The call-level video state of a restored call: its mode and each party's own direction.
pub(super) fn restored_call_video(
    snapshot: &crate::ha::CallSnapshot,
    near: &Leg,
    far: &Leg,
) -> CallVideo {
    let direction = |token: &str| MediaDirection::parse(token).unwrap_or_default();
    match snapshot
        .video
        .as_ref()
        .filter(|_| near.video.is_some() && far.video.is_some())
    {
        Some(video) => CallVideo {
            mode: video.mode,
            near_direction: direction(&video.near_direction),
            far_direction: direction(&video.far_direction),
            flows: Vec::new(),
            declined: None,
        },
        None => CallVideo::default(),
    }
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

/// The refusal of a verb that has no two-party video to configure: a mixing room decodes its
/// seats' audio and a forwarding room carries video by its own `video` profile, so a
/// `video_relay` choice there would silently do nothing.
pub(super) fn video_relay_refusal(
    command: &siphon_rtp_proto::Command,
) -> Option<siphon_rtp_proto::CmdResult> {
    use siphon_rtp_proto::Command;
    let (verb, profile) = match command {
        Command::ConferenceJoin { profile, .. } => ("conference_join", profile),
        Command::ConferenceOffer { profile, .. } => ("conference_offer", profile),
        Command::ForwardJoin { profile, .. } => ("forward_join", profile),
        Command::ForwardOffer { profile, .. } => ("forward_offer", profile),
        _ => return None,
    };
    (profile.video_relay != VideoRelay::Passthrough).then(|| {
        super::error_result(
            verb,
            &"video_relay applies to a two-party offer, answer and reoffer only: a room does not relay \
              a call's video stream",
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
        self.near.video.zip(self.far.as_ref()?.video)?;
        let flows = self
            .video
            .flows
            .iter()
            .filter_map(|(endpoint, action)| {
                let FlowAction::Forward(rule) = action else {
                    return None;
                };
                Some(crate::ha::FlowSnapshot {
                    installed_on: self.video_endpoint_role(*endpoint)?,
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
    ) -> Result<Vec<(EndpointId, FlowAction)>, Box<siphon_rtp_proto::CmdResult>> {
        use crate::ha::EndpointRole;
        let Some(video) = snapshot.video.as_ref() else {
            return Ok(Vec::new());
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
        let mut installed: Vec<(EndpointId, FlowAction)> = Vec::new();
        for flow in &video.flows {
            let (Some(on), Some(out)) = (find(flow.installed_on), find(flow.out)) else {
                return Err(refuse(
                    "a video flow references an unknown endpoint role".to_string(),
                ));
            };
            let action = FlowAction::Forward(siphon_rtp_datapath::ForwardRule {
                out_endpoint: out.id,
                out_dst: flow.out_dst,
                accepted_source: super::snapshot::restore_source_filter(flow.accepted_source),
                latch: super::snapshot::restore_latch(flow.latch),
                rtcp_to_userspace: flow.rtcp_to_userspace,
            });
            self.datapath
                .install_flow(on.id, action)
                .map_err(|error| refuse(format!("install video flow: {error}")))?;
            installed.push((on.id, action));
        }
        for role in [
            EndpointRole::NearVideo,
            EndpointRole::FarVideo,
            EndpointRole::NearVideoRtcp,
            EndpointRole::FarVideoRtcp,
        ] {
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
        Ok(installed)
    }

    /// Allocate a video endpoint set (one RTP, plus RTCP unless muxed) on `leg`'s interface.
    async fn alloc_video_leg(&self, leg: &Leg, muxed: bool) -> Result<VideoLeg, String> {
        let family = AddressFamily::of(leg.rtp.local_addr.ip());
        let bind = Some(leg.rtp.local_addr.ip());
        let mut endpoints = self
            .alloc_endpoints(if muxed { 1 } else { 2 }, family, bind)
            .await?;
        let rtcp = (!muxed).then(|| endpoints.remove(1));
        Ok(VideoLeg {
            rtp: endpoints.remove(0),
            rtcp,
            remote_rtp: None,
            remote_rtcp: None,
        })
    }

    /// Free the call's video endpoints and flows (the stream was declined, dropped, or the call
    /// never carried one).
    async fn free_call_video(&self, call_id: &str) {
        let mut freed = Vec::new();
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(video) = call.near.video.take() {
                freed.extend(video.endpoint_ids());
            }
            if let Some(video) = call.far.as_mut().and_then(|far| far.video.take()) {
                freed.extend(video.endpoint_ids());
            }
            call.video.flows.clear();
        }
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
                self.free_call_video(call_id).await;
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
            self.free_call_video(call_id).await;
            return VideoOutcome::passthrough();
        };
        let outcome = self
            .anchor_video_stream(call_id, party, &stream, near, far, answering)
            .await;
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.video.declined.clone_from(&outcome.declined);
        }
        outcome
    }

    async fn anchor_video_stream(
        &self,
        call_id: &str,
        party: Party,
        stream: &VideoStream,
        near: Leg,
        far: Leg,
        answering: bool,
    ) -> VideoOutcome {
        if !stream.is_plain() {
            self.free_call_video(call_id).await;
            return VideoOutcome::declined(format!(
                "video transport {} is not carried: the engine anchors plain RTP video only",
                stream.transport
            ));
        }
        let allocated = near.video.zip(far.video);
        let muxed = match allocated {
            Some((near_video, _)) => near_video.rtcp.is_none(),
            None => stream.rtcp_mux,
        };
        if allocated.is_some() && stream.rtcp_mux != muxed {
            // RFC 5761 §5.1.1: the answer chooses; a party that answers the other way would put its
            // RTCP where no endpoint listens, so the stream is declined rather than half carried.
            self.free_call_video(call_id).await;
            return VideoOutcome::declined(
                "the party did not keep the rtcp-mux choice the video endpoints were bound for",
            );
        }
        if allocated.is_none() {
            if answering {
                self.free_call_video(call_id).await;
                return VideoOutcome::declined("the offer carried no video stream to answer");
            }
            let near_video = match self.alloc_video_leg(&near, muxed).await {
                Ok(video) => video,
                Err(reason) => return VideoOutcome::declined(format!("video endpoints: {reason}")),
            };
            let far_video = match self.alloc_video_leg(&far, muxed).await {
                Ok(video) => video,
                Err(reason) => {
                    for endpoint in near_video.endpoint_ids() {
                        self.release_endpoint(endpoint).await;
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
            } else {
                call.video.far_direction = stream.direction;
            }
            let other = match party {
                Party::Near => call.far.as_ref(),
                Party::Far => Some(&call.near),
            };
            presented =
                other.and_then(|leg| leg.video.map(|video| video.engine_media(leg.advertised_ip)));
        }
        match presented {
            Some(engine) => VideoOutcome {
                rewrite: VideoRewrite::Anchor(engine),
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
        let Some((near, far, near_direction, far_direction, offer_hint, stored_far_hint)) =
            self.calls.get(call_id).and_then(|call| {
                Some((
                    call.near.video?,
                    call.far.as_ref()?.video?,
                    call.video.near_direction,
                    call.video.far_direction,
                    call.offer_received_from,
                    call.far_received_from,
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
        let mut flows: Vec<(EndpointId, FlowAction)> = Vec::new();
        let mut install = |endpoint: EndpointId, action: FlowAction| {
            self.datapath
                .install_flow(endpoint, action)
                .map(|()| flows.push((endpoint, action)))
                .map_err(|error| format!("install video flow: {error}"))
        };
        // RTCP carries receiver feedback (reports, picture loss) against the media's direction, so
        // it flows both ways whenever the stream flows at all. Muxed RTCP shares the RTP endpoint
        // (RFC 5761), where a kernel rule cannot tell the two apart: the RTP direction rule then
        // yields to the RTCP one, see docs/security-and-nat.md.
        let any = near_to_far || far_to_near;
        let near_rule = ingress_rule(far.rtp.id, Some(far_gate), near_gate, profile, false);
        let far_rule = ingress_rule(near.rtp.id, near_gate, Some(far_gate), profile, false);
        let muxed = near.rtcp.is_none() || far.rtcp.is_none();
        install(
            near.rtp.id,
            video_action(near_to_far || (muxed && any), near_rule),
        )?;
        install(
            far.rtp.id,
            video_action(far_to_near || (muxed && any), far_rule),
        )?;
        if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
            let near_rtcp_gate = apply_received_from(near.remote_rtcp, offer_hint);
            let far_rtcp_gate = far
                .remote_rtcp
                .map(|addr| peer_media_address(addr, far_hint));
            let near_rtcp_rule =
                ingress_rule(far_rtcp.id, far_rtcp_gate, near_rtcp_gate, profile, false);
            let far_rtcp_rule =
                ingress_rule(near_rtcp.id, near_rtcp_gate, far_rtcp_gate, profile, false);
            install(near_rtcp.id, video_action(any, near_rtcp_rule))?;
            install(far_rtcp.id, video_action(any, far_rtcp_rule))?;
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.video.flows = flows;
        }
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
