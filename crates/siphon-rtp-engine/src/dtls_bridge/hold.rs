//! Holding a relaying DTLS leg in the decoding media actor, and handing it back.
//!
//! The association never moves: the handshake driver, its retransmission answers and the ICE
//! destination stay where they are, so the peer sees no new handshake (RFC 8842 §5.5) and the key it
//! produced keeps working. What changes owner is the *media*. The leg's flow turns into a pipeline
//! flow, which does the RFC 7983 demux and hands the still-encrypted media to the actor, and the
//! `SecureLeg` moves out of the flow into the actor's hands. [`DtlsBridge::release`] is the reverse
//! and puts that same leg back.

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use siphon_rtp_datapath::{Datapath, EndpointId, SourceFilter};
use siphon_rtp_srtp::leg::SecureLeg;

use crate::egress_track::{EgressTrack, LastForwarded, StreamPosition};
use crate::media_pipeline::HeldTaps;
use crate::x3::X3Taps;

use super::{Direction, DtlsBridge, Flow, PipelineTarget, PlainRtcp};

/// What a DTLS leg looks like from outside, read without changing it.
pub(crate) struct DtlsView {
    /// The gate on the DTLS-facing endpoint (open on an ICE leg, whose gate the datapath owns).
    pub(crate) secure_gate: SourceFilter,
    /// The plain peer's gate and the address decrypted media goes to.
    pub(crate) plain_gate: SourceFilter,
    pub(crate) plain_dst: SocketAddr,
    /// Where the DTLS peer is now: the signalled address, or what ICE selected. `None` while a gated
    /// leg has no pair yet.
    pub(crate) secure_destination: Option<SocketAddr>,
    /// The plain peer's separate RTCP port, when it has one: its endpoint, its gate and the address
    /// the peer's RTCP goes to.
    pub(crate) plain_rtcp: Option<PlainRtcp>,
}

/// A leg the bridge let go of.
pub(crate) struct DtlsHeld {
    /// The key the handshake produced, now shared with the actor.
    pub(crate) leg: Arc<Mutex<SecureLeg>>,
    /// The last packet forwarded toward the plain peer (what the DTLS peer sent).
    pub(crate) toward_plain: Option<LastForwarded>,
    /// The last packet forwarded toward the DTLS peer (what the plain peer sent).
    pub(crate) toward_secure: Option<LastForwarded>,
    pub(crate) secure_taps: HeldTaps,
    pub(crate) plain_taps: HeldTaps,
}

/// What the bridge takes back from the actor that held a leg.
pub(crate) struct DtlsGiveBack {
    pub(crate) leg: SecureLeg,
    pub(crate) plain_endpoint: EndpointId,
    pub(crate) plain_gate: SourceFilter,
    pub(crate) plain_dst: SocketAddr,
    /// The plain peer's separate RTCP port, when it has one.
    pub(crate) plain_rtcp: Option<PlainRtcp>,
    /// The next position toward the plain peer and toward the DTLS peer, from the actor.
    pub(crate) next_toward_plain: Option<StreamPosition>,
    pub(crate) next_toward_secure: Option<StreamPosition>,
    /// The actor could not report, so both flows send under fresh SSRCs
    /// ([`EgressTrack::resolve_lost`]) instead of guessing a numbering.
    pub(crate) positions_lost: bool,
    pub(crate) secure_taps: HeldTaps,
    pub(crate) plain_taps: HeldTaps,
}

impl<D: Datapath + Clone + 'static> DtlsBridge<D> {
    fn track_after(next: Option<StreamPosition>, lost: bool) -> EgressTrack {
        if lost {
            let track = EgressTrack::default();
            track.resolve_lost();
            track
        } else {
            EgressTrack::continuing(next)
        }
    }

    /// The retained handle of the key a held leg's actor was given, kept for a renegotiation.
    pub(crate) fn retained(&self, secure_endpoint: EndpointId) -> Option<Arc<Mutex<SecureLeg>>> {
        self.pipeline_keys
            .get(&secure_endpoint)
            .map(|leg| leg.clone())
    }

    /// Whether the association running on `secure_endpoint` authenticated a peer certificate other than
    /// `fingerprint`: RFC 8842 §3.1 makes that a *new* association, which a call held in the actor
    /// cannot keep. `false` when there is no association to differ from.
    pub(crate) fn fingerprint_differs(
        &self,
        secure_endpoint: EndpointId,
        hash_function: &str,
        bytes: &[u8],
    ) -> bool {
        self.associations
            .get(&secure_endpoint)
            .is_some_and(|association| {
                association.peer_fingerprint.hash_function != hash_function
                    || association.peer_fingerprint.bytes != bytes
            })
    }

    /// What the actor that takes over this leg must be built from, or the reason it cannot be held:
    /// the leg is not relaying (it already belongs to a pipeline), its handshake has not keyed it, or
    /// it carries bundled video, which the actor does not (RFC 8843).
    pub(crate) fn hold_view(
        &self,
        secure_endpoint: EndpointId,
        plain_endpoint: EndpointId,
    ) -> Result<DtlsView, &'static str> {
        let secure = self
            .flows
            .get(&secure_endpoint)
            .ok_or("no DTLS flow on the endpoint")?;
        if !matches!(secure.direction, Direction::Decrypt { .. }) {
            return Err("the DTLS leg is not relaying");
        }
        if secure.video.is_some() {
            return Err("the DTLS leg carries bundled video");
        }
        let keyed = secure.secure.lock().is_ok_and(|leg| leg.is_some());
        if !keyed {
            return Err("the DTLS handshake has not completed");
        }
        let plain_gate = self
            .flows
            .get(&plain_endpoint)
            .map(|flow| flow.accepted_source)
            .ok_or("no flow on the plain endpoint")?;
        let plain_rtcp = secure.rtcp_out.and_then(|(endpoint, dst)| {
            let source = self.flows.get(&endpoint)?.accepted_source;
            Some(PlainRtcp {
                endpoint,
                source,
                dst,
            })
        });
        Ok(DtlsView {
            plain_rtcp,
            secure_gate: secure.accepted_source,
            plain_gate,
            plain_dst: secure
                .out_dst
                .ok_or("the DTLS leg has no plain destination")?,
            secure_destination: self
                .destinations
                .get(&secure_endpoint)
                .and_then(|destination| *destination.borrow()),
        })
    }

    /// Let go of a keyed relaying leg: its `SecureLeg` moves out of the flow into the returned handle,
    /// the flow becomes a pipeline flow feeding `target` still encrypted, and the plain side's flows
    /// are removed, so the actor registered for the plain endpoint owns it. Both relaying flows are
    /// sealed first-hand: the positions returned are final.
    ///
    /// Re-checks what [`Self::hold_view`] checked, atomically with the move, and changes nothing when
    /// it fails.
    pub(crate) fn hold(
        &self,
        secure_endpoint: EndpointId,
        plain_endpoint: EndpointId,
        target: PipelineTarget,
    ) -> Result<DtlsHeld, &'static str> {
        let destination = self
            .destinations
            .get(&secure_endpoint)
            .map(|destination| destination.clone());
        let (leg, toward_plain, secure_taps, rtcp_endpoint) = {
            let mut flow = self
                .flows
                .get_mut(&secure_endpoint)
                .ok_or("no DTLS flow on the endpoint")?;
            let Direction::Decrypt { dtls_in } = &flow.direction else {
                return Err("the DTLS leg is not relaying");
            };
            if flow.video.is_some() {
                return Err("the DTLS leg carries bundled video");
            }
            let dtls_in = dtls_in.clone();
            let leg = flow
                .secure
                .lock()
                .map_err(|_| "the DTLS leg's key is poisoned")?
                .take()
                .ok_or("the DTLS handshake has not completed")?;
            let rtcp_endpoint = flow.rtcp_out.map(|(endpoint, _)| endpoint);
            let toward_plain = flow.track.seal();
            let secure_taps = HeldTaps {
                x3: std::mem::take(&mut flow.x3),
                plain: std::mem::take(&mut flow.plain_taps),
                // The DTLS bridge keeps no reply latch; its gate is the datapath's.
                latch: Default::default(),
            };
            flow.direction = Direction::Pipeline {
                dtls_in,
                target,
                keyed: Arc::new(AtomicBool::new(true)),
            };
            flow.out_dst = None;
            flow.secure_dst = destination;
            flow.rtcp_out = None;
            flow.rtcp_only = false;
            (leg, toward_plain, secure_taps, rtcp_endpoint)
        };
        let (toward_secure, plain_taps) = match self.flows.remove(&plain_endpoint) {
            Some((_, flow)) => (
                flow.track.seal(),
                HeldTaps {
                    x3: flow.x3.clone(),
                    plain: flow.plain_taps.clone(),
                    latch: Default::default(),
                },
            ),
            None => (None, HeldTaps::default()),
        };
        // The plain peer's separate RTCP port: the actor relays RTCP on its own account.
        if let Some(endpoint) = rtcp_endpoint {
            self.flows.remove(&endpoint);
        }
        // Kept for a renegotiation, which rebuilds the actor and re-keys it from this copy.
        let leg = Arc::new(Mutex::new(leg));
        self.pipeline_keys.insert(secure_endpoint, leg.clone());
        Ok(DtlsHeld {
            leg,
            toward_plain,
            toward_secure,
            secure_taps,
            plain_taps,
        })
    }

    /// The first half of taking a held leg back: register the plain side's flows **before** the actor
    /// that owns them stops, so the plain endpoint is never ownerless. They forward nothing yet (no
    /// key, and a stream position still to come); [`Self::release`] completes them.
    pub(crate) fn release_begin(
        &self,
        secure_endpoint: EndpointId,
        plain_endpoint: EndpointId,
        plain_gate: SourceFilter,
        plain_rtcp: Option<PlainRtcp>,
    ) -> Result<(), &'static str> {
        let destination = self
            .destinations
            .get(&secure_endpoint)
            .map(|destination| destination.clone())
            .ok_or("no DTLS association on the endpoint")?;
        let shared: super::SharedSecureLeg = Arc::new(Mutex::new(None));
        self.flows.insert(
            plain_endpoint,
            Flow {
                direction: Direction::Encrypt,
                accepted_source: plain_gate,
                out_endpoint: secure_endpoint,
                out_dst: None,
                secure_dst: Some(destination.clone()),
                secure: shared.clone(),
                x3: X3Taps::default(),
                plain_taps: crate::plain_tap::PlainTaps::default(),
                rtcp_only: false,
                refusals: Arc::new(crate::ingress::RefusalLog::default()),
                video: None,
                rtp_closed: false,
                rtcp_out: None,
                track: Arc::new(EgressTrack::awaiting()),
            },
        );
        if let Some(flow) = self.flows.get(&plain_endpoint) {
            flow.track.guard();
        }
        if let Some(rtcp) = plain_rtcp {
            self.flows.insert(
                rtcp.endpoint,
                Self::plain_rtcp_flow(rtcp, secure_endpoint, destination, shared),
            );
        }
        Ok(())
    }

    /// Take a held leg back: the actor has stopped and returned the key, so the pipeline flow turns
    /// back into the relaying flow it was, around the same `SecureLeg`, and the plain side's flows
    /// are rebuilt, each carrying on from where the actor left its stream. Fails, changing nothing,
    /// when the leg is not held.
    pub(crate) fn release(
        &self,
        secure_endpoint: EndpointId,
        give: DtlsGiveBack,
    ) -> Result<(), &'static str> {
        let destination = self
            .destinations
            .get(&secure_endpoint)
            .map(|destination| destination.clone())
            .ok_or("no DTLS association on the endpoint")?;
        // The plain side's flows share one slot for the key, registered by `release_begin` or here.
        let shared: super::SharedSecureLeg = self
            .flows
            .get(&give.plain_endpoint)
            .map(|flow| flow.secure.clone())
            .unwrap_or_else(|| Arc::new(Mutex::new(None)));
        {
            let mut flow = self
                .flows
                .get_mut(&secure_endpoint)
                .ok_or("no DTLS flow on the endpoint")?;
            let Direction::Pipeline { dtls_in, .. } = &flow.direction else {
                return Err("the DTLS leg is not held");
            };
            let dtls_in = dtls_in.clone();
            // The key goes in before the flow relays, under the one lock both flows read it through.
            *shared
                .lock()
                .map_err(|_| "the DTLS leg's key is poisoned")? = Some(give.leg);
            flow.direction = Direction::Decrypt { dtls_in };
            flow.out_endpoint = give.plain_endpoint;
            flow.out_dst = Some(give.plain_dst);
            flow.secure_dst = None;
            flow.secure = shared.clone();
            flow.rtcp_out = give.plain_rtcp.map(|rtcp| (rtcp.endpoint, rtcp.dst));
            flow.x3 = give.secure_taps.x3;
            flow.plain_taps = give.secure_taps.plain;
            flow.track = Arc::new(Self::track_after(
                give.next_toward_plain,
                give.positions_lost,
            ));
        }
        self.pipeline_keys.remove(&secure_endpoint);
        let track = Arc::new(Self::track_after(
            give.next_toward_secure,
            give.positions_lost,
        ));
        match self.flows.get_mut(&give.plain_endpoint) {
            Some(mut flow) => {
                flow.accepted_source = give.plain_gate;
                flow.x3 = give.plain_taps.x3;
                flow.plain_taps = give.plain_taps.plain;
                // Resolved last: from here the plain side forwards, numbered after the actor.
                flow.track.guard();
                if give.positions_lost {
                    flow.track.resolve_lost();
                } else {
                    flow.track.resolve(give.next_toward_secure);
                }
            }
            None => {
                self.flows.insert(
                    give.plain_endpoint,
                    Flow {
                        direction: Direction::Encrypt,
                        accepted_source: give.plain_gate,
                        out_endpoint: secure_endpoint,
                        out_dst: None,
                        secure_dst: Some(destination.clone()),
                        secure: shared.clone(),
                        x3: give.plain_taps.x3,
                        plain_taps: give.plain_taps.plain,
                        rtcp_only: false,
                        refusals: Arc::new(crate::ingress::RefusalLog::default()),
                        video: None,
                        rtp_closed: false,
                        rtcp_out: None,
                        track: {
                            track.guard();
                            track
                        },
                    },
                );
            }
        }
        if let Some(rtcp) = give.plain_rtcp {
            if !self.flows.contains_key(&rtcp.endpoint) {
                self.flows.insert(
                    rtcp.endpoint,
                    Self::plain_rtcp_flow(rtcp, secure_endpoint, destination, shared),
                );
            }
        }
        Ok(())
    }
}
