//! The receive loop's cached view of the shared per-endpoint maps.
//!
//! A relayed packet needs its endpoint's flow, whether the endpoint is an ICE or TURN leg, its own
//! latch, and the out leg's socket, counters, latch and TURN state. Read from the backend's
//! `DashMap`s that is six lookups per packet, each a shard read lock taken and released on a
//! cache line every receive task shares, for state that changes a handful of times per call.
//!
//! Instead each receive task resolves a [`Route`] once and reuses it while both endpoints'
//! generations stand still. Every control write that changes what a route reads bumps the
//! generation of the endpoint it wrote (`Inner::touch`), so the next packet on either side sees a
//! moved generation and resolves again. The window is the same one the uncached path had: a packet
//! already past its lookups when a write lands is handled under the old state; the next one is not.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use tokio::net::UdpSocket;

use super::{Inner, StatsAtomic};
use crate::{EndpointId, FlowAction, SourceLatch};

/// What a forwarded packet needs from the leg it leaves through.
pub(super) struct OutLeg {
    /// The out leg's socket, held weakly: `remove_endpoint` promises the OS socket is closed when it
    /// returns, so a route cached on another leg must never keep it open. Upgraded per packet; only
    /// this receive task upgrades it, so the count it touches is not shared with other workers.
    pub(super) socket: Weak<UdpSocket>,
    pub(super) stats: Arc<StatsAtomic>,
    /// The out leg's generation when this was resolved.
    generation: u64,
    /// The out leg's latched source: symmetric RTP replies to wherever the peer actually sends from.
    pub(super) latched: Option<SocketAddr>,
    /// Whether the out leg relays through a TURN allocation (its egress is then framed).
    pub(super) turn: bool,
}

/// One endpoint's resolved per-packet state. See the module docs for when it is resolved again.
pub(super) struct Route {
    /// This endpoint's generation when this was resolved.
    generation: u64,
    pub(super) flow: Option<FlowAction>,
    /// Whether the endpoint carries ICE credentials (the layer-4 gate applies).
    pub(super) ice: bool,
    /// Whether the endpoint relays through a TURN allocation (its ingress may need unwrapping).
    pub(super) turn: bool,
    /// The endpoint's own latch: the ICE-validated source, or the symmetric-RTP latch.
    pub(super) latch: Option<SourceLatch<SocketAddr>>,
    /// The out leg of a `Forward` flow, when it exists.
    pub(super) out: Option<OutLeg>,
}

impl Route {
    /// Read `endpoint`'s state from the shared maps. Each generation is loaded **before** the maps it
    /// guards, so a write that lands mid-resolve leaves a generation newer than the one stored here
    /// and the next packet resolves again rather than keeping a half-old view.
    pub(super) fn resolve(inner: &Inner, endpoint: EndpointId, stats: &StatsAtomic) -> Self {
        let generation = stats.generation.load(Ordering::Acquire);
        let flow = inner.flows.get(&endpoint).map(|flow| *flow);
        let out = match flow {
            Some(FlowAction::Forward(rule)) => OutLeg::resolve(inner, rule.out_endpoint),
            _ => None,
        };
        Self {
            generation,
            flow,
            ice: inner.ice.contains_key(&endpoint),
            turn: has_turn_relay(inner, endpoint),
            latch: inner.latched.get(&endpoint).map(|latch| *latch),
            out,
        }
    }

    /// Whether neither endpoint has been written since this was resolved.
    pub(super) fn is_current(&self, stats: &StatsAtomic) -> bool {
        stats.generation.load(Ordering::Acquire) == self.generation
            && self
                .out
                .as_ref()
                .is_none_or(|out| out.stats.generation.load(Ordering::Acquire) == out.generation)
    }

    /// The route in `slot`, resolved again first when it is missing or stale.
    pub(super) fn current<'slot>(
        slot: &'slot mut Option<Route>,
        inner: &Inner,
        endpoint: EndpointId,
        stats: &StatsAtomic,
    ) -> &'slot Route {
        if slot.as_ref().is_some_and(|route| route.is_current(stats)) {
            if let Some(route) = slot {
                return route;
            }
        }
        slot.insert(Self::resolve(inner, endpoint, stats))
    }
}

impl OutLeg {
    fn resolve(inner: &Inner, endpoint: EndpointId) -> Option<Self> {
        // Copy what the entry holds and release its guard before reading the other maps.
        let (socket, stats) = {
            let entry = inner.endpoints.get(&endpoint)?;
            (Arc::downgrade(&entry.socket), entry.stats.clone())
        };
        let generation = stats.generation.load(Ordering::Acquire);
        Some(Self {
            socket,
            stats,
            generation,
            latched: inner.latched.get(&endpoint).map(|latch| latch.source),
            turn: has_turn_relay(inner, endpoint),
        })
    }
}

/// Whether `endpoint` relays through a TURN allocation; free on a node with none installed.
fn has_turn_relay(inner: &Inner, endpoint: EndpointId) -> bool {
    inner.turn_relay_count.load(Ordering::Relaxed) != 0 && inner.turn_relay.contains_key(&endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp::UdpLoopbackDatapath;
    use crate::{Datapath, ForwardRule};

    #[tokio::test]
    async fn a_route_goes_stale_when_either_endpoint_is_written() {
        let datapath = UdpLoopbackDatapath::new();
        let near = datapath.alloc_endpoint().await.expect("alloc near");
        let far = datapath.alloc_endpoint().await.expect("alloc far");
        let peer: SocketAddr = "192.0.2.10:4000".parse().expect("addr");
        datapath
            .install_flow(
                near.id,
                FlowAction::Forward(ForwardRule::symmetric(far.id, Some(peer))),
            )
            .expect("flow");
        let inner = &datapath.inner;
        let near_stats = inner.endpoints.get(&near.id).expect("near").stats.clone();

        let route = Route::resolve(inner, near.id, &near_stats);
        assert!(route.is_current(&near_stats));
        assert!(route.out.is_some(), "the out leg resolved");

        // A write on the far leg (its latch moving) stales the near leg's route too.
        inner.touch(far.id);
        assert!(!route.is_current(&near_stats));

        let route = Route::resolve(inner, near.id, &near_stats);
        inner.touch(near.id);
        assert!(!route.is_current(&near_stats));
    }

    #[tokio::test]
    async fn current_reuses_a_fresh_route_and_replaces_a_stale_one() {
        let datapath = UdpLoopbackDatapath::new();
        let near = datapath.alloc_endpoint().await.expect("alloc near");
        let inner = &datapath.inner;
        let stats = inner.endpoints.get(&near.id).expect("near").stats.clone();
        let mut slot = None;

        assert!(Route::current(&mut slot, inner, near.id, &stats)
            .flow
            .is_none());
        datapath
            .install_flow(near.id, FlowAction::Drop)
            .expect("flow");
        // `install_flow` touched the endpoint, so the cached "no flow" is not reused.
        assert!(matches!(
            Route::current(&mut slot, inner, near.id, &stats).flow,
            Some(FlowAction::Drop)
        ));
    }

    #[tokio::test]
    async fn an_out_leg_that_does_not_exist_resolves_to_none() {
        let datapath = UdpLoopbackDatapath::new();
        let near = datapath.alloc_endpoint().await.expect("alloc near");
        let far = datapath.alloc_endpoint().await.expect("alloc far");
        datapath
            .install_flow(
                near.id,
                FlowAction::Forward(ForwardRule::symmetric(far.id, None)),
            )
            .expect("flow");
        datapath.remove_endpoint(far.id).await;
        let inner = &datapath.inner;
        let stats = inner.endpoints.get(&near.id).expect("near").stats.clone();
        assert!(Route::resolve(inner, near.id, &stats).out.is_none());
    }
}
