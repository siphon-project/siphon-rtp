//! The WebSocket-bridge slow path: attach a call leg's audio to an external WebSocket media server
//! (the mod_audio_stream / voice-AI integration).
//!
//! Where the datapath `Forward` fast path relays an opaque datagram untouched, the
//! [`crate::srtp_bridge`] terminates SRTP, and the [`crate::media_pipeline`] transcodes between two
//! legs, a **WebSocket-bridged** call sets leg A's RTP endpoint to
//! [`FlowAction::Redirect`](siphon_rtp_datapath::FlowAction::Redirect) and the redirect dispatcher
//! routes each of A's datagrams to this registry. The engine dials the WS server as a *client*
//! ([`tokio_tungstenite::connect_async`]) and runs [`siphon_rtp_media::bridge::run_bridge`], which:
//!
//! - decodes A's RTP to L16 and sends it uplink (call → server) as a WS binary frame, and
//! - encodes inbound WS binary frames (server → call) to RTP toward A.
//!
//! The WS server is leg A's far side, so the A↔B transcode/relay path is **not** wired in this mode
//! (B may still be allocated by offer/answer; its media is simply not bridged here).
//!
//! Like the SRTP bridge and media pipeline, this registry re-enforces the signalled-source gate
//! before feeding a datagram to the bridge — `Redirect` bypasses the datapath's Forward-path gate, so
//! the RTPBleed defence (docs/security-and-nat.md §4 layer 2) is applied here.

use bytes::Bytes;
use dashmap::DashMap;

use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};

/// One WS-bridged call's datapath route: the bridge's RTP-in mailbox plus the source gate to apply
/// before feeding it (the `Redirect` path skips the datapath's gate — RTPBleed defence).
struct WsRoute {
    /// Signalled-source gate — only this source may drive the bridge.
    accepted_source: SourceFilter,
    /// Leg A's RTP, forwarded (raw datagram bytes) into the bridge for decode → WS uplink.
    rtp_in: flume::Sender<Bytes>,
}

/// A handle to a running WS-bridge call: its endpoint(s) and the two tasks to abort on teardown.
struct WsCallHandle {
    /// Leg A's RTP endpoint — the redirected endpoint this call owns.
    endpoint_a: EndpointId,
    /// The bridge task ([`run_bridge`] over the dialed WS connection).
    bridge_task: tokio::task::JoinHandle<()>,
    /// The drain task pumping the bridge's `rtp_out` to the datapath toward A.
    drain_task: tokio::task::JoinHandle<()>,
}

/// The registry of WebSocket-bridged calls: routes leg A's redirected datagrams to the owning
/// bridge's RTP-in mailbox and holds each call's task handles for teardown. Mirrors the
/// [`crate::media_pipeline::MediaRegistry`] / [`crate::srtp_bridge::SrtpBridge`] "registry +
/// dispatcher" shape so the single redirect dispatcher can route by [`EndpointId`].
#[derive(Default)]
pub struct WsRegistry {
    /// Endpoint → the owning bridge's RTP-in route (the dispatcher's routing table).
    routes: DashMap<EndpointId, WsRoute>,
    /// Call-id → the running bridge's task handles + endpoint, for teardown.
    calls: DashMap<String, WsCallHandle>,
}

impl WsRegistry {
    /// Register a running WS bridge for `call_id`: route `endpoint_a`'s redirected datagrams to
    /// `rtp_in` (gated by `accepted_source`), and keep the bridge + drain tasks so teardown can abort
    /// them. The caller installs `FlowAction::Redirect` on `endpoint_a` and tears down via
    /// [`Self::deregister`].
    pub fn register(
        &self,
        call_id: impl Into<String>,
        endpoint_a: EndpointId,
        accepted_source: SourceFilter,
        rtp_in: flume::Sender<Bytes>,
        bridge_task: tokio::task::JoinHandle<()>,
        drain_task: tokio::task::JoinHandle<()>,
    ) {
        self.routes.insert(
            endpoint_a,
            WsRoute {
                accepted_source,
                rtp_in,
            },
        );
        self.calls.insert(
            call_id.into(),
            WsCallHandle {
                endpoint_a,
                bridge_task,
                drain_task,
            },
        );
    }

    /// Whether this registry routes datagrams for `endpoint` (the dispatcher's predicate).
    #[must_use]
    pub fn owns(&self, endpoint: EndpointId) -> bool {
        self.routes.contains_key(&endpoint)
    }

    /// Whether `call_id` is a WS-bridged call.
    #[must_use]
    pub fn is_ws_call(&self, call_id: &str) -> bool {
        self.calls.contains_key(call_id)
    }

    /// Route a redirected datagram (leg A's RTP) to its owning bridge's RTP-in mailbox. The source is
    /// re-gated here (RTPBleed defence — `Redirect` bypasses the datapath gate); an off-source or
    /// unowned datagram is dropped (never fed into the bridge / forwarded into the void).
    pub fn dispatch(&self, packet: RxPacket) {
        let Some(route) = self.routes.get(&packet.endpoint) else {
            return; // not a WS endpoint (the dispatcher should have routed it elsewhere)
        };
        if !route.accepted_source.accepts(packet.source.ip()) {
            tracing::debug!(
                endpoint = ?packet.endpoint,
                source = %packet.source,
                "ws-bridge dropped packet from unsignalled source"
            );
            return;
        }
        // Drop on a full or closed mailbox — late audio is worthless, and a closed channel means the
        // bridge task has already exited.
        if route.rtp_in.try_send(packet.data).is_err() {
            tracing::trace!(
                "ws-bridge rtp-in mailbox full or closed; dropping redirected datagram"
            );
        }
    }

    /// Tear a WS-bridge call down: drop its route and abort the bridge + drain tasks (closing the WS
    /// connection and the RTP-out drain). The WS half of call teardown.
    pub fn deregister(&self, call_id: &str) {
        if let Some((_, handle)) = self.calls.remove(call_id) {
            self.routes.remove(&handle.endpoint_a);
            handle.bridge_task.abort();
            handle.drain_task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn endpoint(id: u64) -> EndpointId {
        EndpointId(id)
    }

    fn rx(endpoint_id: u64, source: &str, data: &[u8]) -> RxPacket {
        RxPacket {
            endpoint: endpoint(endpoint_id),
            source: source.parse().expect("addr"),
            arrival: 0,
            data: Bytes::copy_from_slice(data),
        }
    }

    /// Spawn two no-op tasks to stand in for the bridge + drain tasks the registry owns.
    fn idle_tasks() -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        (
            tokio::spawn(std::future::pending()),
            tokio::spawn(std::future::pending()),
        )
    }

    #[tokio::test]
    async fn dispatch_forwards_accepted_source_to_the_bridge() {
        let registry = WsRegistry::default();
        let (rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        let (bridge, drain) = idle_tasks();
        registry.register(
            "call-1",
            endpoint(1),
            SourceFilter::Exact(Ipv4Addr::new(127, 0, 0, 2).into()),
            rtp_in_tx,
            bridge,
            drain,
        );

        assert!(registry.owns(endpoint(1)));
        assert!(registry.is_ws_call("call-1"));

        registry.dispatch(rx(1, "127.0.0.2:5000", b"rtp-frame"));
        let received = rtp_in_rx.try_recv().expect("forwarded to the bridge");
        assert_eq!(&received[..], b"rtp-frame");

        registry.deregister("call-1");
    }

    #[tokio::test]
    async fn dispatch_gates_out_an_off_source_packet() {
        let registry = WsRegistry::default();
        let (rtp_in_tx, rtp_in_rx) = flume::unbounded::<Bytes>();
        let (bridge, drain) = idle_tasks();
        registry.register(
            "call-1",
            endpoint(1),
            SourceFilter::Exact(Ipv4Addr::new(127, 0, 0, 2).into()),
            rtp_in_tx,
            bridge,
            drain,
        );

        // An attacker on a different IP sprays the endpoint — gated out before any bridge feed.
        registry.dispatch(rx(1, "127.0.0.9:5000", b"attacker"));
        assert!(
            rtp_in_rx.try_recv().is_err(),
            "off-source packet must not reach the bridge"
        );

        registry.deregister("call-1");
    }

    #[tokio::test]
    async fn dispatch_for_an_unowned_endpoint_is_a_noop() {
        let registry = WsRegistry::default();
        // No panic, no route — a datagram for an unknown endpoint is simply dropped.
        registry.dispatch(rx(999, "127.0.0.2:5000", b"orphan"));
        assert!(!registry.owns(endpoint(999)));
    }

    #[tokio::test]
    async fn deregister_stops_owning_and_aborts_the_tasks() {
        let registry = WsRegistry::default();
        let (rtp_in_tx, _rtp_in_rx) = flume::unbounded::<Bytes>();
        let (bridge, drain) = idle_tasks();
        let bridge_abort = bridge.abort_handle();
        let drain_abort = drain.abort_handle();
        registry.register(
            "call-1",
            endpoint(1),
            SourceFilter::Any,
            rtp_in_tx,
            bridge,
            drain,
        );
        assert!(registry.owns(endpoint(1)));

        registry.deregister("call-1");
        assert!(!registry.owns(endpoint(1)), "route dropped");
        assert!(!registry.is_ws_call("call-1"), "call dropped");
        // The tasks were aborted (pending() never completes otherwise). `abort()` schedules
        // cancellation asynchronously, so yield until the runtime finalizes both handles.
        for _ in 0..100 {
            if bridge_abort.is_finished() && drain_abort.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(bridge_abort.is_finished(), "bridge task aborted");
        assert!(drain_abort.is_finished(), "drain task aborted");
    }

    #[tokio::test]
    async fn deregister_unknown_call_is_a_noop() {
        let registry = WsRegistry::default();
        registry.deregister("nope"); // must not panic
    }
}
