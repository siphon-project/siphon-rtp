//! The datapath thread's STUN demux on an ICE endpoint: forward to the engine's agent, answer and adopt
//! as the ice-lite responder, and publish what was adopted to the userspace consumers that follow it.
//! Shared with the control plane by `Arc`, so a `set_ice` / `set_ice_agent` between bursts is visible
//! on the very next packet.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use siphon_rtp_datapath::{EndpointId, IceAgentMode, IceConfig, IceDatapathEvent};

use crate::IceAgentRegistration;

/// The ICE state the datapath thread needs to demux STUN out of the redirected stream: the
/// per-endpoint credentials (to answer a check) and the full-agent registrations (where to forward
/// it).
#[derive(Clone)]
pub(crate) struct IceDemux {
    pub(crate) ice: Arc<DashMap<EndpointId, IceConfig>>,
    pub(crate) ice_agents: Arc<DashMap<EndpointId, IceAgentRegistration>>,
    /// The source ICE has adopted per endpoint — the userspace record behind
    /// `Datapath::ice_validated_source`. Written by the ice-lite responder on this thread and by
    /// `Datapath::adopt_source` on the control plane; the kernel flow's latch fields are the
    /// enforcement copy of the same decision.
    pub(crate) adopted: Arc<DashMap<EndpointId, SocketAddr>>,
    /// Tick of the last validated check per endpoint — see `Inner::ice_last_check`.
    pub(crate) last_check: Arc<DashMap<EndpointId, u64>>,
    /// Subscribers to `adopted` — see `Inner::ice_validated`.
    pub(crate) validated: Arc<DashMap<EndpointId, tokio::sync::watch::Sender<Option<SocketAddr>>>>,
}

/// Publish `endpoint`'s adopted source to its `Datapath::watch_ice_validated` subscribers, if it has
/// any. The source is read inside the publisher's own lock, so a check adopted while a subscription is
/// being set up can never be overwritten by an older reading.
pub(crate) fn publish_adopted(
    adopted: &DashMap<EndpointId, SocketAddr>,
    validated: &DashMap<EndpointId, tokio::sync::watch::Sender<Option<SocketAddr>>>,
    endpoint: EndpointId,
) {
    if let Some(publisher) = validated.get(&endpoint) {
        publisher.send_if_modified(|published| {
            let current = adopted.get(&endpoint).map(|entry| *entry);
            if *published == current {
                return false;
            }
            *published = current;
            true
        });
    }
}

/// One STUN datagram's disposition on the datapath thread, decided by [`IceDemux::classify`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StunDisposition {
    /// Not an ICE endpoint — leave the datagram on the normal redirect path (a TURN allocation actor
    /// on a `Redirect` flow legitimately receives STUN-shaped bytes).
    NotIce,
    /// Consumed by ICE. It has already been forwarded to the agent; the two remaining side-effects
    /// are the caller's, so the decision itself stays I/O-free and testable without a NIC:
    /// transmit `respond` back to the source, and write `adopt` into the kernel's layer-4 gate.
    Consumed {
        /// The ice-lite responder's Binding success response, when the check authenticated.
        respond: Option<Vec<u8>>,
        /// A newly adopted media source — `None` when nothing changed, so the kernel map is written
        /// once per adoption rather than once per check.
        adopt: Option<SocketAddr>,
    },
}

impl IceDemux {
    /// Decide what happens to a STUN datagram that arrived on `endpoint` from `source`, performing
    /// the forward-to-agent side-effect. Mirrors the loopback backend's `recv_loop` demux exactly:
    /// forward to the agent first (so it sees Binding responses too), then let the responder answer
    /// unless the endpoint is [`IceAgentMode::ForwardOnly`] — where answering behind a full agent's
    /// back would adopt a source the checklist never selected.
    pub(crate) fn classify(
        &self,
        endpoint: EndpointId,
        source: SocketAddr,
        datagram: &[u8],
        tick: u64,
    ) -> StunDisposition {
        let registration = self.ice_agents.get(&endpoint).map(|entry| entry.clone());
        if let Some(registration) = registration.as_ref() {
            // Bounded sink, drop-on-full — never stall the datapath thread on a slow consumer.
            let _ = registration.events.try_send(IceDatapathEvent {
                endpoint,
                source,
                arrival_tick: tick,
                datagram: Bytes::copy_from_slice(datagram),
            });
            if registration.mode == IceAgentMode::ForwardOnly {
                return StunDisposition::Consumed {
                    respond: None,
                    adopt: None,
                };
            }
        }
        let Some(config) = self.ice.get(&endpoint).map(|entry| entry.clone()) else {
            // No ICE credentials at all. If a full agent is registered the datagram is still ICE's
            // (it was forwarded above); otherwise this is not an ICE endpoint and the datagram
            // belongs on the redirect path.
            return match registration {
                Some(_) => StunDisposition::Consumed {
                    respond: None,
                    adopt: None,
                },
                None => StunDisposition::NotIce,
            };
        };
        match siphon_rtp_datapath::respond_to_stun_check(datagram, &config, source) {
            siphon_rtp_datapath::StunCheckOutcome::Respond(response) => {
                // An authenticated check proves the path is alive, so it counts as activity for the
                // media-timeout sweep exactly as it does on the loopback backend — otherwise a leg
                // still establishing (or held, exchanging only consent checks) would be reaped.
                self.last_check.insert(endpoint, tick);
                // A check that authenticated: ICE supersedes blind latching, so this source becomes
                // the media path (RFC 8445 §7.3). Report the adoption only when it *changes*, so the
                // kernel map is written once per path rather than on every repeated check.
                let changed = self.adopted.get(&endpoint).map(|entry| *entry) != Some(source);
                if changed {
                    self.adopted.insert(endpoint, source);
                }
                StunDisposition::Consumed {
                    respond: Some(response),
                    adopt: changed.then_some(source),
                }
            }
            siphon_rtp_datapath::StunCheckOutcome::Drop => StunDisposition::Consumed {
                respond: None,
                adopt: None,
            },
        }
    }
}
