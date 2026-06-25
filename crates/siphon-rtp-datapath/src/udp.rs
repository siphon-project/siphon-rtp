//! The UDP-loopback datapath backend.
//!
//! Every endpoint is a real `tokio` UDP socket bound on loopback; a per-endpoint receive task
//! applies the installed [`FlowAction`]. [`FlowAction::Forward`] re-emits the datagram out the
//! peer endpoint's socket — modelling the XDP_TX rewrite, including symmetric-RTP **latching**
//! (reply to wherever the peer's packets actually arrive from). This backend needs no privileges
//! or NIC, so it is the CI datapath and the behavioural reference the XDP backend must match.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use bytes::Bytes;
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::{
    Datapath, DatapathError, Endpoint, EndpointId, EndpointStats, FlowAction, RxPacket,
};

/// Receive buffer size. RTP/RTCP/STUN/DTLS media datagrams sit well under a 1500-byte MTU; this
/// leaves headroom without paying for jumbo frames the media plane never sees.
const MAX_DATAGRAM: usize = 2048;

/// Lock-free per-endpoint counters, mutated from receive tasks and snapshotted by `stats`.
#[derive(Default)]
struct StatsAtomic {
    packets_in: AtomicU64,
    packets_out: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    packets_dropped: AtomicU64,
}

impl StatsAtomic {
    fn snapshot(&self) -> EndpointStats {
        EndpointStats {
            packets_in: self.packets_in.load(Ordering::Relaxed),
            packets_out: self.packets_out.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
        }
    }
}

/// One allocated endpoint: its socket, counters, and receive task.
struct EndpointEntry {
    socket: Arc<UdpSocket>,
    stats: Arc<StatsAtomic>,
    task: JoinHandle<()>,
}

/// Shared backend state. Held by the public handle (strong) and by receive tasks (weak), so the
/// strong count reaches zero on teardown and [`Drop`] can abort the parked receive tasks.
struct Inner {
    next_id: AtomicU64,
    endpoints: DashMap<EndpointId, EndpointEntry>,
    flows: DashMap<EndpointId, FlowAction>,
    /// First observed source per endpoint (latch-once). Forward rules with `allow_latch` reply
    /// to the latched source of their `out_endpoint` instead of the SDP-advertised address.
    latched: DashMap<EndpointId, SocketAddr>,
    redirect_tx: flume::Sender<RxPacket>,
    redirect_rx: flume::Receiver<RxPacket>,
}

impl Inner {
    /// Apply the installed flow to one received datagram. Holds no map guard across an `.await`.
    async fn dispatch(
        &self,
        endpoint: EndpointId,
        source: SocketAddr,
        payload: &[u8],
        in_stats: &StatsAtomic,
    ) {
        let action = match self.flows.get(&endpoint) {
            Some(action) => *action,
            None => {
                in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        match action {
            FlowAction::Forward(rule) => {
                let destination = if rule.allow_latch {
                    self.latched
                        .get(&rule.out_endpoint)
                        .map(|latched| *latched)
                        .or(rule.out_dst)
                } else {
                    rule.out_dst
                };
                let Some(destination) = destination else {
                    // No negotiated address yet and nothing latched — nowhere to send.
                    in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                let out = match self.endpoints.get(&rule.out_endpoint) {
                    Some(entry) => (entry.socket.clone(), entry.stats.clone()),
                    None => {
                        in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
                match out.0.send_to(payload, destination).await {
                    Ok(sent) => {
                        out.1.packets_out.fetch_add(1, Ordering::Relaxed);
                        out.1.bytes_out.fetch_add(sent as u64, Ordering::Relaxed);
                    }
                    Err(error) => {
                        tracing::warn!(?endpoint, %error, "forward send failed");
                        in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            FlowAction::Redirect => {
                let packet = RxPacket {
                    endpoint,
                    source,
                    data: Bytes::copy_from_slice(payload),
                };
                if self.redirect_tx.send(packet).is_err() {
                    tracing::debug!(?endpoint, "redirect stream has no receiver");
                }
            }
            FlowAction::Drop => {
                in_stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // The receive tasks hold only a `Weak<Inner>`, so they are parked on `recv_from` with no
        // way to notice teardown — abort them explicitly.
        for entry in self.endpoints.iter() {
            entry.value().task.abort();
        }
    }
}

/// The always-available, NIC-free datapath backend. Cheaply cloned (shares one `Arc<Inner>`).
#[derive(Clone)]
pub struct UdpLoopbackDatapath {
    inner: Arc<Inner>,
}

impl Default for UdpLoopbackDatapath {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpLoopbackDatapath {
    /// Create an empty backend with no endpoints.
    #[must_use]
    pub fn new() -> Self {
        let (redirect_tx, redirect_rx) = flume::unbounded();
        Self {
            inner: Arc::new(Inner {
                next_id: AtomicU64::new(0),
                endpoints: DashMap::new(),
                flows: DashMap::new(),
                latched: DashMap::new(),
                redirect_tx,
                redirect_rx,
            }),
        }
    }

    /// A receiver for datagrams delivered by [`FlowAction::Redirect`] flows. Clone-per-consumer;
    /// all redirected endpoints share this single stream.
    #[must_use]
    pub fn rx(&self) -> flume::Receiver<RxPacket> {
        self.inner.redirect_rx.clone()
    }
}

/// Per-endpoint receive loop: drain the socket, latch the source, apply the flow.
async fn recv_loop(
    inner: Weak<Inner>,
    endpoint: EndpointId,
    socket: Arc<UdpSocket>,
    stats: Arc<StatsAtomic>,
) {
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    loop {
        let (len, source) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(error) => {
                tracing::debug!(?endpoint, %error, "endpoint receive loop ending");
                return;
            }
        };
        stats.packets_in.fetch_add(1, Ordering::Relaxed);
        stats.bytes_in.fetch_add(len as u64, Ordering::Relaxed);

        let Some(inner) = inner.upgrade() else {
            return;
        };
        inner.latched.entry(endpoint).or_insert(source);
        inner.dispatch(endpoint, source, &buffer[..len], &stats).await;
    }
}

impl Datapath for UdpLoopbackDatapath {
    async fn alloc_endpoint(&self) -> Result<Endpoint, DatapathError> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(DatapathError::Bind)?;
        let local_addr = socket.local_addr().map_err(DatapathError::Bind)?;
        let socket = Arc::new(socket);
        let id = EndpointId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        let stats = Arc::new(StatsAtomic::default());
        let task = tokio::spawn(recv_loop(
            Arc::downgrade(&self.inner),
            id,
            socket.clone(),
            stats.clone(),
        ));
        self.inner
            .endpoints
            .insert(id, EndpointEntry { socket, stats, task });
        Ok(Endpoint { id, local_addr })
    }

    fn install_flow(&self, endpoint: EndpointId, action: FlowAction) -> Result<(), DatapathError> {
        if !self.inner.endpoints.contains_key(&endpoint) {
            return Err(DatapathError::UnknownEndpoint(endpoint));
        }
        self.inner.flows.insert(endpoint, action);
        Ok(())
    }

    fn remove_flow(&self, endpoint: EndpointId) {
        self.inner.flows.remove(&endpoint);
    }

    async fn remove_endpoint(&self, endpoint: EndpointId) {
        if let Some((_, entry)) = self.inner.endpoints.remove(&endpoint) {
            entry.task.abort();
        }
        self.inner.flows.remove(&endpoint);
        self.inner.latched.remove(&endpoint);
    }

    async fn send(
        &self,
        endpoint: EndpointId,
        dst: SocketAddr,
        data: &[u8],
    ) -> Result<usize, DatapathError> {
        let (socket, stats) = match self.inner.endpoints.get(&endpoint) {
            Some(entry) => (entry.socket.clone(), entry.stats.clone()),
            None => return Err(DatapathError::UnknownEndpoint(endpoint)),
        };
        let sent = socket.send_to(data, dst).await.map_err(DatapathError::Send)?;
        stats.packets_out.fetch_add(1, Ordering::Relaxed);
        stats.bytes_out.fetch_add(sent as u64, Ordering::Relaxed);
        Ok(sent)
    }

    fn stats(&self, endpoint: EndpointId) -> Option<EndpointStats> {
        self.inner.endpoints.get(&endpoint).map(|e| e.stats.snapshot())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ForwardRule;
    use std::time::Duration;
    use tokio::time::timeout;

    const SHORT: Duration = Duration::from_secs(1);
    const NEGATIVE: Duration = Duration::from_millis(150);

    /// A test "phone": a loopback UDP socket standing in for a SIP endpoint.
    async fn phone() -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind phone");
        let addr = socket.local_addr().expect("phone addr");
        (socket, addr)
    }

    async fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buffer = [0u8; MAX_DATAGRAM];
        let (len, from) = timeout(SHORT, socket.recv_from(&mut buffer))
            .await
            .expect("recv did not time out")
            .expect("recv ok");
        (buffer[..len].to_vec(), from)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relays_in_both_directions() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: leg_b.id,
                    out_dst: Some(addr_b),
                    allow_latch: false,
                }),
            )
            .expect("flow a");
        datapath
            .install_flow(
                leg_b.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: leg_a.id,
                    out_dst: Some(addr_a),
                    allow_latch: false,
                }),
            )
            .expect("flow b");

        // A -> engine(leg_a) -> phone_b, leaving from the engine's B-facing port.
        phone_a
            .send_to(b"from-a", leg_a.local_addr)
            .await
            .expect("send a");
        let (data, from) = recv(&phone_b).await;
        assert_eq!(data, b"from-a");
        assert_eq!(from, leg_b.local_addr);

        // B -> engine(leg_b) -> phone_a, leaving from the engine's A-facing port.
        phone_b
            .send_to(b"from-b", leg_b.local_addr)
            .await
            .expect("send b");
        let (data, from) = recv(&phone_a).await;
        assert_eq!(data, b"from-b");
        assert_eq!(from, leg_a.local_addr);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn latching_resolves_unknown_destination() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        // Toward B we know the address; toward A we do not yet — only latching can resolve it.
        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule::latching(leg_b.id, Some(addr_b))),
            )
            .expect("flow a");
        datapath
            .install_flow(
                leg_b.id,
                FlowAction::Forward(ForwardRule::latching(leg_a.id, None)),
            )
            .expect("flow b");

        // Before A has spoken, B->A has no destination and must be dropped (not delivered).
        phone_b
            .send_to(b"early", leg_b.local_addr)
            .await
            .expect("send early");
        let mut scratch = [0u8; MAX_DATAGRAM];
        assert!(
            timeout(NEGATIVE, phone_a.recv_from(&mut scratch)).await.is_err(),
            "B->A must not be delivered before A is latched"
        );

        // A speaks: this latches leg_a's source to phone_a, and is forwarded to B.
        phone_a
            .send_to(b"a-first", leg_a.local_addr)
            .await
            .expect("send a");
        let (data, _) = recv(&phone_b).await;
        assert_eq!(data, b"a-first");

        // Now B->A resolves via the latched address even though out_dst was None.
        phone_b
            .send_to(b"b-reply", leg_b.local_addr)
            .await
            .expect("send b");
        let (data, from) = recv(&phone_a).await;
        assert_eq!(data, b"b-reply");
        assert_eq!(from, leg_a.local_addr);
        let _ = addr_a;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn redirect_delivers_to_rx_stream() {
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (phone, addr) = phone().await;
        datapath
            .install_flow(leg.id, FlowAction::Redirect)
            .expect("redirect flow");
        let rx = datapath.rx();

        phone
            .send_to(b"media-frame", leg.local_addr)
            .await
            .expect("send");
        let packet = timeout(SHORT, rx.recv_async())
            .await
            .expect("no timeout")
            .expect("packet");
        assert_eq!(packet.endpoint, leg.id);
        assert_eq!(packet.source, addr);
        assert_eq!(&packet.data[..], b"media-frame");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_action_and_stats_counters() {
        let datapath = UdpLoopbackDatapath::new();
        let leg_a = datapath.alloc_endpoint().await.expect("alloc a");
        let leg_b = datapath.alloc_endpoint().await.expect("alloc b");
        let (phone_a, _addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;

        datapath
            .install_flow(
                leg_a.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: leg_b.id,
                    out_dst: Some(addr_b),
                    allow_latch: false,
                }),
            )
            .expect("flow a");
        datapath
            .install_flow(leg_b.id, FlowAction::Drop)
            .expect("drop flow");

        phone_a
            .send_to(b"counted", leg_a.local_addr)
            .await
            .expect("send a");
        let _ = recv(&phone_b).await;
        // B's datagram is dropped by the Drop flow.
        phone_b
            .send_to(b"dropped", leg_b.local_addr)
            .await
            .expect("send b");

        // Poll until the dropped counter lands (the receive task runs asynchronously).
        let mut dropped = 0;
        for _ in 0..50 {
            dropped = datapath.stats(leg_b.id).expect("stats b").packets_dropped;
            if dropped >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(dropped, 1, "B's datagram should be counted as dropped");

        let stats_a = datapath.stats(leg_a.id).expect("stats a");
        assert_eq!(stats_a.packets_in, 1);
        let stats_b = datapath.stats(leg_b.id).expect("stats b");
        assert_eq!(stats_b.packets_out, 1, "one datagram forwarded out of B");
        assert_eq!(stats_b.bytes_out, b"counted".len() as u64);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_injects_from_endpoint() {
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        let (phone, addr) = phone().await;

        let sent = datapath.send(leg.id, addr, b"injected").await.expect("send");
        assert_eq!(sent, b"injected".len());
        let (data, from) = recv(&phone).await;
        assert_eq!(data, b"injected");
        assert_eq!(from, leg.local_addr);
        assert_eq!(datapath.stats(leg.id).expect("stats").packets_out, 1);
    }

    #[tokio::test]
    async fn install_flow_rejects_unknown_endpoint() {
        let datapath = UdpLoopbackDatapath::new();
        let result = datapath.install_flow(EndpointId(999), FlowAction::Drop);
        assert!(matches!(result, Err(DatapathError::UnknownEndpoint(_))));
        let result = datapath.send(EndpointId(999), "127.0.0.1:5000".parse().expect("addr"), b"x").await;
        assert!(matches!(result, Err(DatapathError::UnknownEndpoint(_))));
    }

    #[tokio::test]
    async fn remove_endpoint_frees_state() {
        let datapath = UdpLoopbackDatapath::new();
        let leg = datapath.alloc_endpoint().await.expect("alloc");
        assert!(datapath.stats(leg.id).is_some());
        datapath.remove_endpoint(leg.id).await;
        assert!(datapath.stats(leg.id).is_none());
        // Installing a flow on the removed endpoint now fails.
        assert!(matches!(
            datapath.install_flow(leg.id, FlowAction::Drop),
            Err(DatapathError::UnknownEndpoint(_))
        ));
    }
}
