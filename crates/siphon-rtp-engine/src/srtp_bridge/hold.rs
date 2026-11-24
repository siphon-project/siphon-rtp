//! Handing a bridged call's flows to the decoding media actor and taking them back.
//!
//! The bridge relays ciphertext it never decodes. To hold the call in userspace the engine reads what
//! the actor must be built from ([`SrtpBridge::hold_view`]), registers the actor, and only then lets
//! go of the flows ([`SrtpBridge::hold`]), which seals each one: the position of the stream it last
//! forwarded is final, and it forwards nothing more. Coming back, [`SrtpBridge::register_shared`]
//! rebuilds the flows over the very same shared [`SecureLeg`]s, each carrying on from where the actor
//! left its stream and with the taps the actor held.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use siphon_rtp_datapath::EndpointId;
use siphon_rtp_srtp::leg::SecureLeg;

use crate::egress_track::{LastForwarded, StreamPosition};
use crate::media_pipeline::HeldTaps;

use super::{BridgeFlowPlan, BridgeLeg, SrtpBridge};

/// A call's bridge plan over legs that already exist as shared handles.
pub(crate) struct SharedBridgePlan {
    pub(crate) near_leg: Option<Arc<Mutex<SecureLeg>>>,
    pub(crate) far_leg: Option<Arc<Mutex<SecureLeg>>>,
    pub(crate) flows: Vec<BridgeFlowPlan>,
    /// What each rebuilt flow takes over from the actor that held it.
    pub(crate) carried: Vec<CarriedFlow>,
}

/// What one rebuilt flow carries on from the actor that held its stream.
pub(crate) struct CarriedFlow {
    pub(crate) endpoint: EndpointId,
    /// The position the actor's next packet toward the flow's peer would have had.
    pub(crate) resume: Option<StreamPosition>,
    /// The flow is registered before the actor that owns the stream has stopped: it forwards nothing
    /// until [`SrtpBridge::finish_release`] says where the stream stands, so the endpoint has an
    /// owner throughout.
    pub(crate) awaiting: bool,
    pub(crate) taps: HeldTaps,
}

/// What a flow registered awaiting its stream is told once the actor has stopped.
pub(crate) struct FinishedFlow {
    pub(crate) endpoint: EndpointId,
    /// The gate and destination the actor had in force, where it reports them.
    pub(crate) gate: Option<siphon_rtp_datapath::SourceFilter>,
    pub(crate) destination: Option<SocketAddr>,
    /// The position the actor's next packet would have had; `None` when it could not say.
    pub(crate) next: Option<StreamPosition>,
    /// The actor could not report at all, so even `next: None` does not mean "nothing was sent":
    /// the flow sends under a fresh SSRC ([`EgressTrack::resolve_lost`](crate::egress_track)).
    pub(crate) lost: bool,
    pub(crate) taps: Option<HeldTaps>,
}

/// What a bridged call looks like from outside, read without changing it.
pub(crate) struct BridgeView {
    /// Each flow's plan: its gate, where it forwards and which party's leg is on each side.
    pub(crate) plans: Vec<BridgeFlowPlan>,
    pub(crate) near_leg: Option<Arc<Mutex<SecureLeg>>>,
    pub(crate) far_leg: Option<Arc<Mutex<SecureLeg>>>,
    /// The source each endpoint's peer is observed to send from, where the latch has adopted one.
    pub(crate) latched: Vec<(EndpointId, SocketAddr)>,
}

/// One flow the bridge let go of.
pub(crate) struct HeldFlow {
    pub(crate) endpoint: EndpointId,
    /// The last packet the flow forwarded toward its peer.
    pub(crate) last: Option<LastForwarded>,
    pub(crate) taps: HeldTaps,
}

impl<D: siphon_rtp_datapath::Datapath + Clone + 'static> SrtpBridge<D> {
    /// What the actor that takes over `endpoints` (a call's RTP endpoint first, A's, then the rest)
    /// must be built from, or `None` when the bridge does not own all of them.
    pub(crate) fn hold_view(&self, endpoints: &[EndpointId]) -> Option<BridgeView> {
        let first = *endpoints.first()?;
        if !endpoints
            .iter()
            .all(|endpoint| self.flows.contains_key(endpoint))
        {
            return None;
        }
        Some(BridgeView {
            plans: self.flow_plans(endpoints),
            near_leg: self.party_leg(first, BridgeLeg::Near),
            far_leg: self.party_leg(first, BridgeLeg::Far),
            latched: endpoints
                .iter()
                .filter_map(|endpoint| Some((*endpoint, self.latched_source(*endpoint)?)))
                .collect(),
        })
    }

    /// Complete a flow registered awaiting its stream: adopt what the actor had in force, take its
    /// taps, and start forwarding from the position it left. Returns whether the flow exists.
    pub(crate) fn finish_release(&self, finished: FinishedFlow) -> bool {
        let Some(mut flow) = self.flows.get_mut(&finished.endpoint) else {
            return false;
        };
        if let Some(gate) = finished.gate {
            flow.accepted_source = gate;
        }
        if let Some(destination) = finished.destination {
            flow.out_dst = destination;
        }
        if let Some(taps) = finished.taps {
            flow.x3 = taps.x3;
            flow.plain_taps = taps.plain;
            // The latch the actor had established, so a stranger who sends first now meets it.
            if let Some(latch) = &flow.latch {
                if let Ok(mut latch) = latch.lock() {
                    *latch = taps.latch;
                }
            }
        }
        if finished.lost {
            flow.track.resolve_lost();
        } else {
            flow.track.resolve(finished.next);
        }
        true
    }

    /// Let go of `endpoints`' flows: each is sealed (see [`EgressTrack::seal`](crate::egress_track))
    /// and removed, so the dispatcher no longer routes them here and the actor registered for them
    /// owns the endpoints. The legs are not touched: the actor holds the same handles.
    pub(crate) fn hold(&self, endpoints: &[EndpointId]) -> Vec<HeldFlow> {
        endpoints
            .iter()
            .filter_map(|endpoint| {
                let (_, flow) = self.flows.remove(endpoint)?;
                // The learned source goes with the flow; the actor latches for itself while it holds.
                self.latched.remove(endpoint);
                Some(HeldFlow {
                    endpoint: *endpoint,
                    last: flow.track.seal(),
                    taps: HeldTaps {
                        x3: flow.x3.clone(),
                        plain: flow.plain_taps.clone(),
                        latch: flow
                            .latch
                            .as_ref()
                            .and_then(|latch| latch.lock().ok().map(|latch| latch.clone()))
                            .unwrap_or_default(),
                    },
                })
            })
            .collect()
    }
}
