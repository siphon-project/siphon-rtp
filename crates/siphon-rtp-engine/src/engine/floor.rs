//! The MCPTT floor-control stream of a two-party call (3GPP TS 24.380; SDP per TS 24.379).
//!
//! Where audio is relayed between the parties, the floor stream is **terminated** on the engine, one
//! endpoint per party: what a party sends on it reaches the controller as `rtcp_app`, and what the
//! controller sends goes to that party. Nothing is relayed from one party's floor stream to the
//! other's. The legs live in [`crate::call_floor`]; this is the offer/answer-time wiring.
//!
//! The endpoints are `Redirect` ones, so the stream works whether the call's audio rides the
//! in-kernel relay, the SRTP bridge or the userspace pipeline. They are part of the leg's endpoint
//! set ([`super::Leg::all_endpoint_ids`]), which is what frees them with the call, keeps them in the
//! media-timeout sweep's liveness reading, and carries them through a re-offer unchanged.

use std::net::{IpAddr, SocketAddr};

use siphon_rtp_datapath::{AddressFamily, Datapath, Endpoint, FlowAction};
use siphon_rtp_proto::ProfileFlags;

use crate::call_floor::CallFloorLeg;
use crate::floor_channel::{
    floor_channel, FloorChannelHandle, FloorChannelPlan, FloorScope, FloorSink,
};
use crate::sdp::{self, EngineMedia};

use super::install::AnswerWiring;
use super::negotiate::{apply_received_from, bridge_source_filter, random_ssrc};
use super::{ClientId, Engine};

/// The floor data channel of one DTLS leg of a two-party call, and the SSRC the engine's floor
/// messages to it carry when the controller names none (minted once per leg, RFC 3550 §8.1).
#[derive(Clone)]
pub(super) struct CallFloorChannel {
    pub(super) handle: FloorChannelHandle,
    pub(super) ssrc: u32,
}

/// What anchoring an offer's floor stream leaves for the call.
#[derive(Default)]
pub(super) struct OfferFloor {
    /// The A-facing endpoint, when the offer carried a floor stream the engine anchored.
    pub(super) near: Option<Endpoint>,
    /// The B-facing endpoint.
    pub(super) far: Option<Endpoint>,
    /// A's signalled floor address.
    pub(super) near_remote: Option<SocketAddr>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// The `rtcp_app` queue of the controller that owns `call_id`, for a pipeline that reads APP
    /// packets out of the call's audio RTCP.
    pub(super) fn call_app_queue(&self, call_id: &str) -> Option<crate::app_events::AppEventQueue> {
        let owner = self.owned_call_internal(call_id, |call| call.owner)?;
        self.app_event_queue(owner)
    }

    /// Create the floor data channel of leg `tag` of `call_id` (a DTLS leg that offered a WebRTC data
    /// channel, RFC 8841): the handle is kept for `send_rtcp_app`, the plan goes to the DTLS driver of
    /// the leg's endpoint ([`crate::dtls_bridge::DtlsBridge::attach_floor_channel`]) before it is
    /// registered. Events go to the controller that owns the call.
    pub(super) fn new_call_floor_channel(
        &self,
        call_id: &str,
        tag: &str,
        owner: ClientId,
    ) -> FloorChannelPlan {
        let (handle, plan) = floor_channel(FloorSink {
            scope: FloorScope::Call(call_id.to_string()),
            tag: tag.to_string(),
            events: self.app_event_queue(owner),
        });
        self.call_floor_channels.insert(
            (call_id.to_string(), tag.to_string()),
            CallFloorChannel {
                handle,
                ssrc: random_ssrc(),
            },
        );
        plan
    }

    /// Anchor the floor stream an offer carries: one `Redirect`-bound endpoint per leg, in the
    /// leg's family and on its interface, like the text and fax streams. A WebSocket-bridged call
    /// has no B leg and anchors nothing. A floor stream in another address family than the leg's
    /// audio is not anchored, and the legs without one decline it in what they present.
    ///
    /// Never fails the call: the floor is a stream of its own, and one that cannot be brought up is
    /// declined (as the fax stream's is) rather than costing the call its audio.
    pub(super) async fn anchor_offer_floor(
        &self,
        profile: &ProfileFlags,
        offer: &str,
        families: (
            (AddressFamily, Option<IpAddr>),
            (AddressFamily, Option<IpAddr>),
        ),
        endpoints: &mut Vec<Endpoint>,
    ) -> OfferFloor {
        let ((near_family, near_bind), (far_family, far_bind)) = families;
        let Some(offered) = sdp::parse_floor(offer).filter(|_| profile.ws_uri.is_none()) else {
            return OfferFloor::default();
        };
        if AddressFamily::of(offered.remote.ip()) != near_family {
            tracing::debug!(
                "the floor stream is in another address family than the call; declined"
            );
            return OfferFloor::default();
        }
        let near = self.alloc_floor_endpoint(near_family, near_bind).await;
        let far = self.alloc_floor_endpoint(far_family, far_bind).await;
        let (Some(near), Some(far)) = (near, far) else {
            self.free(&[near, far].into_iter().flatten().collect::<Vec<_>>())
                .await;
            return OfferFloor::default();
        };
        endpoints.extend([near, far]);
        OfferFloor {
            near: Some(near),
            far: Some(far),
            near_remote: Some(offered.remote),
        }
    }

    /// One redirected floor endpoint, or `None` (logged) when the datapath cannot give one.
    async fn alloc_floor_endpoint(
        &self,
        family: AddressFamily,
        bind: Option<IpAddr>,
    ) -> Option<Endpoint> {
        let endpoint = match self.alloc_endpoints(1, family, bind).await {
            Ok(mut allocated) => allocated.remove(0),
            Err(reason) => {
                tracing::warn!(%reason, "no endpoint for the floor stream; it is declined");
                return None;
            }
        };
        if let Err(error) = self
            .datapath
            .install_flow(endpoint.id, FlowAction::Redirect)
        {
            tracing::warn!(%error, "could not redirect the floor endpoint; the stream is declined");
            self.free(&[endpoint]).await;
            return None;
        }
        Some(endpoint)
    }

    /// Anchor the floor stream of a single-leg local answer (the engine is the far side): one
    /// endpoint, on the caller-facing leg. `None` when the offer carries none, or it cannot be
    /// brought up (then declined).
    pub(super) async fn anchor_local_floor(
        &self,
        offer: &str,
        family: AddressFamily,
        bind: Option<IpAddr>,
        endpoints: &mut Vec<Endpoint>,
    ) -> Option<(Endpoint, SocketAddr)> {
        let offered = sdp::parse_floor(offer)?;
        if AddressFamily::of(offered.remote.ip()) != family {
            tracing::debug!(
                "the floor stream is in another address family than the call; declined"
            );
            return None;
        }
        let endpoint = self.alloc_floor_endpoint(family, bind).await?;
        endpoints.push(endpoint);
        Some((endpoint, offered.remote))
    }

    /// The single-leg answer with its floor section answered on the engine's endpoint (TS 24.380
    /// §14.3.1) and every other stream declined.
    pub(super) fn present_local_floor(
        &self,
        answer: String,
        floor: Option<(Endpoint, SocketAddr)>,
        advertised: IpAddr,
        profile: &ProfileFlags,
        data_channel: bool,
    ) -> String {
        let anchored = match floor {
            Some((endpoint, _)) => sdp::anchor_floor(
                &answer,
                EngineMedia {
                    rtp: endpoint.local_addr,
                    rtcp: None,
                    advertised_ip: advertised,
                },
                profile.floor_fmtp.as_deref(),
            ),
            None => answer,
        };
        // RFC 8841: a DTLS caller's data channel is answered on the audio's own transport (BUNDLE).
        let anchored = if data_channel {
            sdp::anchor_data_channel(&anchored)
        } else {
            anchored
        };
        sdp::decline_unanswered_with_data_channel(anchored, false, floor.is_some(), data_channel)
    }

    /// Record a single-leg call's floor endpoint on its leg and start serving the stream, for the
    /// controller that owns the call and under the caller's leg tag.
    pub(super) fn install_local_floor(
        &self,
        call_id: &str,
        profile: &ProfileFlags,
        (endpoint, signalled): (Endpoint, SocketAddr),
    ) {
        let Some((tag, owner)) = self.calls.get_mut(call_id).map(|mut call| {
            call.near.floor = Some(endpoint);
            call.near.floor_remote = Some(signalled);
            (call.from_tag.clone(), call.owner)
        }) else {
            return;
        };
        let gate = apply_received_from(Some(signalled), profile.received_from).unwrap_or(signalled);
        self.conference.floors().register(
            &self.datapath,
            CallFloorLeg {
                call_id: call_id.to_string(),
                tag,
                endpoint: endpoint.id,
                destination: gate,
                accepted_source: bridge_source_filter(profile, gate),
                ssrc: random_ssrc(),
                events: self.app_event_queue(owner),
            },
        );
    }

    /// Install the floor legs of an answered call: terminated on both parties' endpoints, so what
    /// each sends reaches the controller. The SDP written for the party that offered carries the
    /// engine's endpoint and the controller's `a=fmtp:MCPTT` (TS 24.380 §14.3.1) through the
    /// presentation's [`sdp::FloorRewrite`].
    ///
    /// If the answerer declined the stream (no live `m=application … MCPTT` in its answer) nothing is
    /// registered and the offerer's section is answered declined with the rest of the answer. The
    /// endpoints stay allocated to the call until it ends, like any other stream's. `reversed` is A
    /// answering a re-offer from B: the legs were registered by the first answer and do not move.
    pub(super) fn install_answer_floor(
        &self,
        wiring: &AnswerWiring<'_>,
        answer: &str,
        reversed: bool,
    ) {
        let (near, far) = (&wiring.near, &wiring.far);
        let (Some(near_endpoint), Some(far_endpoint)) = (near.floor, far.floor) else {
            return;
        };
        if reversed {
            return;
        }
        let call_id = wiring.call_id;
        let Some((owner, offer_received_from)) = self
            .calls
            .get(call_id)
            .map(|call| (call.owner, call.offer_received_from))
        else {
            return;
        };
        let Some(answered) = sdp::parse_floor(answer) else {
            tracing::debug!(
                target: "siphon_rtp::media", call_id,
                "the answerer declined the floor stream; it is not served"
            );
            return;
        };
        let Some(near_signalled) = near.floor_remote else {
            tracing::warn!(
                target: "siphon_rtp::media", call_id,
                "the offerer's floor address is unknown; the floor stream is not served"
            );
            return;
        };
        let near_gate = apply_received_from(Some(near_signalled), offer_received_from)
            .unwrap_or(near_signalled);
        let far_gate = apply_received_from(Some(answered.remote), wiring.profile.received_from)
            .unwrap_or(answered.remote);
        let events = self.app_event_queue(owner);
        let floors = self.conference.floors();
        for (endpoint, tag, gate) in [
            (near_endpoint, wiring.from_tag, near_gate),
            (far_endpoint, wiring.to_tag, far_gate),
        ] {
            floors.register(
                &self.datapath,
                CallFloorLeg {
                    call_id: call_id.to_string(),
                    tag: tag.to_string(),
                    endpoint: endpoint.id,
                    destination: gate,
                    accepted_source: bridge_source_filter(wiring.profile, gate),
                    ssrc: random_ssrc(),
                    events: events.clone(),
                },
            );
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(stored) = call.far.as_mut() {
                stored.floor_remote = Some(answered.remote);
            }
        }
        tracing::info!(
            target: "siphon_rtp::media", call_id,
            "serving the MCPTT floor stream of both parties"
        );
    }
}
