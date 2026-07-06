//! The XDP/AF_XDP datapath backend.
//!
//! This crate is the kernel-acceleration counterpart of `siphon-rtp-datapath`'s UDP-loopback
//! backend, kept separate so the always-available backend never depends on aya/eBPF. It loads the
//! embedded XDP classifier ([`siphon-rtp-ebpf`]), attaches it to an interface, drives the `FLOWS` /
//! `STATS` / `XSKS` maps with the shared [`siphon_rtp_ebpf_common`] ABI, and binds an in-house
//! AF_XDP socket ([`xsk`]) that the classifier `XDP_REDIRECT`s media onto.
//!
//! Two layers:
//! - **control** ([`Loader`]): load + attach the program, manage the `FLOWS`/`STATS`/`XSKS` maps,
//!   and the capability probe [`xdp_supported`].
//! - **data** ([`XdpDatapath`]): the [`siphon_rtp_datapath::Datapath`] impl. It assigns media ports
//!   (one [`EndpointId`] = one engine-local UDP transport), programs the kernel `FLOWS` entry per
//!   flow so the classifier gates the source in-kernel (RTPBleed defence) and redirects matched
//!   media to the AF_XDP RX ring, runs a dedicated busy-poll thread that drains RX → the redirect
//!   [`flume`] stream and serialises TX through the same single-owner socket, and reports stats.
//!
//! ## What is wired vs. what needs a NIC
//!
//! The control plane (map programming, endpoint/flow registry, the port pool, the clock, the
//! redirect/observe streams, the FlowKey/FlowAction encoding, header build/parse + checksums, and
//! the UMEM frame book-keeping) is exercised NIC-free and unit-tested. Actually *binding* the AF_XDP
//! socket and moving packets needs a real driver queue + `CAP_NET_RAW`: [`XdpDatapath::new`] binds
//! the socket eagerly and returns [`XdpError::Xsk`] if that fails, so the engine selects this
//! backend only after [`xdp_supported`] and the AF_XDP bind both succeed, else it falls back to
//! UDP-loopback.
//!
//! ## Remaining for a full hardware data plane (documented gaps, not yet wired)
//!
//! - **Next-hop MAC resolution** for TX: [`build_and_push`] emits a zeroed destination MAC; ARP /
//!   `rtnetlink` neighbour-table lookup is the missing piece before TX frames egress a real NIC.
//! - **In-kernel `XDP_TX` passthrough**: the eBPF side currently `XDP_REDIRECT`s every matched flow
//!   to the AF_XDP RX ring (where SRTP/transcode/relay already live). The zero-copy `XDP_TX` rewrite
//!   fast path (and the TURN channel fast path) lands with the eBPF L2/L3/L4 rewrite work.
//! - **Per-endpoint stats**: the kernel `STATS` map is a single program-wide per-CPU counter, so
//!   [`XdpDatapath::stats`] reports the aggregate. A per-flow stats value is a planned ABI widening.
//! - **`last_activity`** is registry-stamped at `0`; the kernel does not yet feed back per-flow
//!   activity ticks for the media-timeout sweep.
//! - **RTCP observation** is wired for the userspace-redirected path only; the `XDP_TX` fast path
//!   needs an explicit RTCP copy-to-userspace, tracked with the `XDP_TX` work.
//!
//! ## ABI POD wrappers
//!
//! The ABI POD types live in the aya-free, no_std `siphon-rtp-ebpf-common`; here they are wrapped in
//! `#[repr(transparent)]` newtypes that impl [`aya::Pod`] (the orphan rule forbids impl'ing a
//! foreign trait on a foreign type, and keeping aya out of the shared crate keeps it off the
//! workspace's dependency graph).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use aya::maps::{HashMap as AyaHashMap, MapData, PerCpuArray, XskMap};
use aya::programs::{Xdp, XdpFlags};
use aya::{Ebpf, Pod};
use bytes::Bytes;
use dashmap::DashMap;

use siphon_rtp_datapath::{
    Datapath, DatapathError, Endpoint, EndpointId, EndpointStats, FlowAction as DpFlowAction,
    ForwardRule, IceConfig, ObservedRtcp, RxPacket, SourceFilter,
};
use siphon_rtp_ebpf_common::{action, latch, source, FlowAction, FlowKey, FlowStats};

pub mod headers;
pub mod xsk;

/// `#[repr(transparent)]` POD wrappers so the shared ABI types can key/value aya maps.
/// Safety: each wraps a `#[repr(C)]` all-integer POD, so every bit pattern is valid.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodKey(FlowKey);
unsafe impl Pod for PodKey {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodAction(FlowAction);
unsafe impl Pod for PodAction {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodStats(FlowStats);
unsafe impl Pod for PodStats {}

/// Errors from loading or driving the XDP backend.
#[derive(Debug, thiserror::Error)]
pub enum XdpError {
    /// Loading the embedded program failed.
    #[error("load XDP program: {0}")]
    Load(String),
    /// Attaching to the interface failed (missing caps, kernel too old, no driver support).
    // The field is `detail` (not `source`): thiserror treats a `source` field as a `#[source]`
    // error, but this carries the upstream error's rendered text, not an `Error` value.
    #[error("attach XDP to {interface}: {detail}")]
    Attach {
        /// The interface attach was attempted on.
        interface: String,
        /// The underlying error text.
        detail: String,
    },
    /// A map operation failed.
    #[error("map {map}: {detail}")]
    Map {
        /// The map name.
        map: &'static str,
        /// The underlying error text.
        detail: String,
    },
    /// Setting up the AF_XDP socket failed.
    #[error("AF_XDP socket: {0}")]
    Xsk(#[from] xsk::XskError),
}

/// How the XDP program attaches: native (driver) or generic SKB mode (any kernel, no driver ZC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
    /// Native/driver-offloaded XDP (lowest overhead; needs driver support).
    Native,
    /// Generic SKB-mode XDP (works on any kernel ≥ 5.10, incl. veth — the dev/CI path).
    Skb,
}

impl AttachMode {
    fn flags(self) -> XdpFlags {
        match self {
            AttachMode::Native => XdpFlags::default(),
            AttachMode::Skb => XdpFlags::SKB_MODE,
        }
    }
}

/// A loaded XDP classifier attached to one interface, owning its maps — the control half.
pub struct Loader {
    ebpf: Ebpf,
    interface: String,
}

impl Loader {
    /// Load the embedded XDP program and attach it to `interface` in `mode`.
    pub fn load(interface: &str, mode: AttachMode) -> Result<Self, XdpError> {
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/siphon-rtp-ebpf"
        )))
        .map_err(|error| XdpError::Load(error.to_string()))?;

        let program: &mut Xdp = ebpf
            .program_mut("siphon_rtp_xdp")
            .ok_or_else(|| XdpError::Load("program `siphon_rtp_xdp` not found".to_string()))?
            .try_into()
            .map_err(|error: aya::programs::ProgramError| XdpError::Load(error.to_string()))?;
        program
            .load()
            .map_err(|error| XdpError::Load(error.to_string()))?;
        program
            .attach(interface, mode.flags())
            .map_err(|error| XdpError::Attach {
                interface: interface.to_string(),
                detail: error.to_string(),
            })?;

        Ok(Self {
            ebpf,
            interface: interface.to_string(),
        })
    }

    /// The interface the program is attached to.
    #[must_use]
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Register an AF_XDP socket fd into the `XSKS` map at `queue` so the classifier's
    /// `XDP_REDIRECT(queue)` lands packets on it. The socket must be bound to the same queue.
    pub fn register_xsk(&mut self, queue: u32, socket_fd: std::os::fd::RawFd) -> Result<(), XdpError> {
        let mut xsks: XskMap<&mut MapData> =
            XskMap::try_from(self.ebpf.map_mut("XSKS").ok_or_else(|| XdpError::Map {
                map: "XSKS",
                detail: "missing".to_string(),
            })?)
            .map_err(|error| XdpError::Map {
                map: "XSKS",
                detail: error.to_string(),
            })?;
        xsks.set(queue, socket_fd, 0).map_err(|error| XdpError::Map {
            map: "XSKS",
            detail: error.to_string(),
        })
    }

    /// Install (or replace) the flow rule for `key`.
    pub fn set_flow(&mut self, key: FlowKey, action: FlowAction) -> Result<(), XdpError> {
        self.flows()?
            .insert(PodKey(key), PodAction(action), 0)
            .map_err(|error| XdpError::Map {
                map: "FLOWS",
                detail: error.to_string(),
            })
    }

    /// Remove the flow rule for `key` (subsequent matching packets `XDP_PASS`).
    pub fn remove_flow(&mut self, key: FlowKey) -> Result<(), XdpError> {
        self.flows()?
            .remove(&PodKey(key))
            .map_err(|error| XdpError::Map {
                map: "FLOWS",
                detail: error.to_string(),
            })
    }

    /// Sum the per-CPU counters across all CPUs.
    pub fn stats(&self) -> Result<FlowStats, XdpError> {
        let stats: PerCpuArray<_, PodStats> = PerCpuArray::try_from(
            self.ebpf.map("STATS").ok_or_else(|| XdpError::Map {
                map: "STATS",
                detail: "missing".to_string(),
            })?,
        )
        .map_err(|error| XdpError::Map {
            map: "STATS",
            detail: error.to_string(),
        })?;

        let per_cpu = stats.get(&0, 0).map_err(|error| XdpError::Map {
            map: "STATS",
            detail: error.to_string(),
        })?;
        let mut total = FlowStats::default();
        for value in per_cpu.iter() {
            total.packets_in += value.0.packets_in;
            total.packets_out += value.0.packets_out;
            total.bytes_in += value.0.bytes_in;
            total.bytes_out += value.0.bytes_out;
            total.packets_dropped += value.0.packets_dropped;
        }
        Ok(total)
    }

    fn flows(&mut self) -> Result<AyaHashMap<&mut MapData, PodKey, PodAction>, XdpError> {
        AyaHashMap::try_from(self.ebpf.map_mut("FLOWS").ok_or_else(|| XdpError::Map {
            map: "FLOWS",
            detail: "missing".to_string(),
        })?)
        .map_err(|error| XdpError::Map {
            map: "FLOWS",
            detail: error.to_string(),
        })
    }
}

/// The first ephemeral media port the XDP backend hands out (the IANA dynamic range floor minus the
/// odd-port reservations; rtpengine's default media range starts here). Ports are assigned in pairs-
/// agnostic single-port units; the session manager pairs RTP/RTCP at the call layer.
const MEDIA_PORT_BASE: u16 = 30000;
/// Upper bound of the media-port pool.
const MEDIA_PORT_TOP: u16 = 40000;

/// Per-endpoint record: the engine-local transport and the FLOWS key the kernel matches on.
#[derive(Clone, Copy)]
struct EndpointRecord {
    local_addr: SocketAddr,
    flow_key: FlowKey,
    /// Logical-clock tick of the last accepted packet (mirrors the loopback backend's `last_seen`).
    last_seen: u64,
}

/// A TX request sent to the datapath thread (the single owner of the AF_XDP socket): build an
/// L2/L3/L4 frame for `data` and push it onto the TX ring, replying through `done`.
struct TxRequest {
    source: SocketAddr,
    destination: SocketAddr,
    data: Vec<u8>,
    done: tokio::sync::oneshot::Sender<Result<usize, DatapathError>>,
}

/// Shared backend state behind the [`XdpDatapath`] handle.
struct Inner {
    /// The eBPF loader (maps), behind a short-lived control-plane lock — never held across `.await`.
    loader: Mutex<Loader>,
    /// Endpoint registry: id → transport + flow key. Lock-free reads on the relay path. `Arc`-shared
    /// (not `DashMap::clone`, which deep-copies) so the datapath thread sees live insertions.
    endpoints: Arc<DashMap<EndpointId, EndpointRecord>>,
    /// Allocated media ports, so the pool never double-assigns.
    used_ports: DashMap<u16, EndpointId>,
    /// Per-endpoint ICE-lite credentials (control-plane; STUN is handled in userspace on redirect).
    ice: DashMap<EndpointId, IceConfig>,
    next_id: AtomicU64,
    next_port: AtomicU64,
    /// Logical monotonic clock (ticks), advanced by the engine's sweep — never `Instant::now()`.
    clock: AtomicU64,
    /// Real-time monotonic origin for **arrival** timestamps and `now_micros` (RTCP interarrival
    /// jitter / DLSR, RFC 3550 §6.4.1). Distinct from the logical sweep `clock` above: this is
    /// wall-clock-rate elapsed time, shared with the datapath thread so a packet's arrival and a
    /// report's "now" read one clock. Production only — XDP runs on a real NIC, not in CI.
    start: std::time::Instant,
    /// The engine-local relay IPv4 every endpoint advertises and the kernel keys flows on.
    local_ip: Ipv4Addr,
    /// Receiver end of the redirect stream; the sole sender lives on the datapath thread.
    redirect_rx: flume::Receiver<RxPacket>,
    /// Kept so the observe channel never closes; the in-kernel RTCP tap is wired with the XDP_TX work.
    observe_tx: flume::Sender<ObservedRtcp>,
    observe_rx: flume::Receiver<ObservedRtcp>,
    /// TX command channel to the datapath thread (the single owner of the AF_XDP socket).
    tx_commands: flume::Sender<TxRequest>,
    /// Handle to the AF_XDP busy-poll thread, joined on teardown (see [`Inner::drop`]).
    datapath_thread: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Structured teardown: the only TX sender lives here, so dropping it (the field is dropped
        // after this body) leaves the channel about to close; explicitly take the receiver's twin by
        // closing now via a sentinel is unnecessary — instead we close by dropping `tx_commands`
        // first, then join. We swap the sender for a fresh disconnected one to force the thread's
        // `recv_timeout` to observe `Disconnected`, then join the handle so no orphan thread leaks.
        let (dead_tx, _) = flume::bounded::<TxRequest>(0);
        let _ = std::mem::replace(&mut self.tx_commands, dead_tx);
        if let Ok(mut guard) = self.datapath_thread.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

/// The XDP/AF_XDP datapath backend. Cheaply cloned (shares one `Arc<Inner>`); implements the same
/// [`Datapath`] trait as the UDP-loopback backend so the engine uses it interchangeably.
#[derive(Clone)]
pub struct XdpDatapath {
    inner: Arc<Inner>,
}

impl XdpDatapath {
    /// Build the XDP backend over an already-loaded [`Loader`], binding an AF_XDP socket on
    /// `interface`/`queue` and registering it into the `XSKS` map. `local_ip` is the engine-local
    /// relay IPv4 endpoints advertise and the kernel keys flows on.
    ///
    /// Spawns the dedicated busy-poll datapath thread (RX drain → redirect stream; TX serialisation).
    pub fn new(
        mut loader: Loader,
        interface: &str,
        queue: u32,
        local_ip: Ipv4Addr,
        config: xsk::XskConfig,
    ) -> Result<Self, XdpError> {
        let ifindex = xsk::ifindex(interface);
        let socket = xsk::XskSocket::new(ifindex, queue, &config)?;
        loader.register_xsk(queue, socket.as_raw_fd())?;

        let (redirect_tx, redirect_rx) = flume::unbounded();
        let (observe_tx, observe_rx) = flume::bounded(256);
        let (tx_commands, tx_rx) = flume::unbounded::<TxRequest>();
        let endpoints: Arc<DashMap<EndpointId, EndpointRecord>> = Arc::new(DashMap::new());
        let start = std::time::Instant::now();

        let inner = Arc::new(Inner {
            loader: Mutex::new(loader),
            endpoints: endpoints.clone(),
            used_ports: DashMap::new(),
            ice: DashMap::new(),
            next_id: AtomicU64::new(0),
            next_port: AtomicU64::new(0),
            clock: AtomicU64::new(0),
            start,
            local_ip,
            redirect_rx,
            observe_tx,
            observe_rx,
            tx_commands,
            datapath_thread: Mutex::new(None),
        });

        // The busy-poll thread is the single owner of the AF_XDP socket (actor model): it drains RX
        // into the redirect stream and serialises TX requests, so the ring is never touched
        // concurrently. It shares the live endpoint registry via the `Arc` (not a snapshot).
        let thread_redirect = redirect_tx;
        let thread_endpoints = endpoints;
        let local_ip_copy = local_ip;
        let handle = std::thread::Builder::new()
            .name("siphon-xdp-datapath".to_string())
            .spawn(move || {
                datapath_loop(
                    socket,
                    tx_rx,
                    thread_redirect,
                    thread_endpoints,
                    local_ip_copy,
                    start,
                );
            })
            .map_err(|error| XdpError::Xsk(xsk::XskError::Socket(error)))?;
        // A poisoned lock only means a prior holder panicked; the stored `JoinHandle` is still
        // structurally valid, so recover the guard rather than panic (house rule: no `.expect()`).
        *inner
            .datapath_thread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);

        Ok(Self { inner })
    }

    /// Advance the logical clock by `ticks` (mirrors the loopback backend; tests advance explicitly).
    pub fn advance_clock(&self, ticks: u64) {
        self.inner.clock.fetch_add(ticks, Ordering::Relaxed);
    }

    /// Assign the next free media port from the pool, or `None` when exhausted. Uses the `entry` API
    /// so a probe never clobbers a port already owned by another endpoint (check-and-claim is atomic
    /// per shard).
    fn alloc_port(&self, id: EndpointId) -> Option<u16> {
        use dashmap::mapref::entry::Entry;
        let span = (MEDIA_PORT_TOP - MEDIA_PORT_BASE) as u64;
        for _ in 0..span {
            let offset = self.inner.next_port.fetch_add(1, Ordering::Relaxed) % span;
            let port = MEDIA_PORT_BASE + offset as u16;
            if let Entry::Vacant(slot) = self.inner.used_ports.entry(port) {
                slot.insert(id);
                return Some(port);
            }
        }
        None
    }
}

/// Translate a userspace [`DpFlowAction`] into the kernel ABI [`FlowAction`], resolving the peer
/// endpoint's transport for the forward destination. The kernel only stores IPv4 transports, so a
/// destination that is not IPv4 (or an unresolved peer) yields the safe `DROP` until it resolves.
fn to_kernel_action(
    action: DpFlowAction,
    endpoints: &DashMap<EndpointId, EndpointRecord>,
    local_ip: Ipv4Addr,
    redirect_queue: u32,
) -> FlowAction {
    let mut kernel = FlowAction {
        kind: action::DROP,
        latch_policy: latch::OFF,
        source_kind: source::ANY,
        source_prefix: 0,
        source_ipv4: 0,
        out_ipv4: 0,
        out_local_ipv4: 0,
        out_port: 0,
        out_src_port: 0,
        latched_ipv4: 0,
        latched_ssrc: 0,
        latched_port: 0,
        latch_valid: 0,
        _pad: 0,
        redirect_queue,
    };
    match action {
        DpFlowAction::Drop => kernel,
        DpFlowAction::Redirect => {
            kernel.kind = action::REDIRECT;
            kernel
        }
        DpFlowAction::Forward(rule) => {
            kernel.kind = action::FORWARD;
            apply_source_filter(&mut kernel, rule.accepted_source);
            kernel.latch_policy = match rule.latch {
                siphon_rtp_datapath::LatchPolicy::Off => latch::OFF,
                siphon_rtp_datapath::LatchPolicy::SignalledOnly => latch::SIGNALLED,
                siphon_rtp_datapath::LatchPolicy::Symmetric => latch::SYMMETRIC,
            };
            apply_forward_target(&mut kernel, &rule, endpoints, local_ip);
            kernel
        }
    }
}

/// Encode a [`SourceFilter`] into the kernel action's source-gate fields (IPv4 only; a v6 filter is
/// represented as `ANY` until the v6 ABI lands, matching the IPv4-first datapath).
fn apply_source_filter(kernel: &mut FlowAction, filter: SourceFilter) {
    match filter {
        SourceFilter::Any => kernel.source_kind = source::ANY,
        SourceFilter::Exact(IpAddr::V4(ip)) => {
            kernel.source_kind = source::EXACT;
            kernel.source_ipv4 = u32::from_be_bytes(ip.octets());
        }
        SourceFilter::Subnet(IpAddr::V4(ip), prefix) => {
            kernel.source_kind = source::SUBNET;
            kernel.source_ipv4 = u32::from_be_bytes(ip.octets());
            kernel.source_prefix = prefix;
        }
        // A v6 gate cannot be expressed in the IPv4 ABI; fall back to ANY (the userspace path still
        // re-checks on redirect). Tracked with the v6 widening of the ABI.
        SourceFilter::Exact(IpAddr::V6(_)) | SourceFilter::Subnet(IpAddr::V6(_), _) => {
            kernel.source_kind = source::ANY;
        }
    }
}

/// Fill the kernel action's forward-target fields from the rule's resolved destination + the peer
/// endpoint's local transport (the XDP_TX source). Leaves them zero when unresolved — the kernel
/// then has no destination and drops (never forwards into the void).
fn apply_forward_target(
    kernel: &mut FlowAction,
    rule: &ForwardRule,
    endpoints: &DashMap<EndpointId, EndpointRecord>,
    local_ip: Ipv4Addr,
) {
    if let Some(SocketAddr::V4(dst)) = rule.out_dst {
        kernel.out_ipv4 = u32::from_be_bytes(dst.ip().octets());
        kernel.out_port = dst.port().to_be();
    }
    // The XDP_TX source transport is the peer endpoint's local media port on the engine.
    if let Some(peer) = endpoints.get(&rule.out_endpoint) {
        if let SocketAddr::V4(local) = peer.local_addr {
            kernel.out_local_ipv4 = u32::from_be_bytes(local.ip().octets());
            kernel.out_src_port = local.port().to_be();
        }
    } else {
        kernel.out_local_ipv4 = u32::from_be_bytes(local_ip.octets());
    }
}

/// The dedicated AF_XDP datapath thread: the single owner of the socket. It busy-polls the RX ring
/// (draining received frames → the redirect stream, keyed by destination transport → endpoint) and
/// serves TX requests from the command channel, completing TX frames between bursts.
fn datapath_loop(
    mut socket: xsk::XskSocket,
    tx_rx: flume::Receiver<TxRequest>,
    redirect: flume::Sender<RxPacket>,
    endpoints: Arc<DashMap<EndpointId, EndpointRecord>>,
    _local_ip: Ipv4Addr,
    start: std::time::Instant,
) {
    loop {
        // Drain RX: parse each frame, map its destination transport to an endpoint, push the payload
        // onto the redirect stream. The in-kernel classifier already gated the source.
        let received = socket.rx_burst(64);
        // One arrival stamp per burst: frames in a burst arrived together off the NIC, so reading the
        // real-time clock once (not per packet) keeps the RX hot loop cheap (RFC 3550 §6.4.1 jitter).
        let arrival = start.elapsed().as_micros() as u64;
        for packet in &received {
            let Some(parsed) = headers::parse_udp_frame(&packet.frame) else {
                continue;
            };
            let dst = SocketAddr::new(IpAddr::V4(parsed.dst_ip), parsed.dst_port);
            let Some(endpoint) = endpoint_for(&endpoints, dst) else {
                continue;
            };
            let payload = &packet.frame
                [parsed.payload_offset..parsed.payload_offset + parsed.payload_len];
            let rx_packet = RxPacket {
                endpoint,
                source: SocketAddr::new(IpAddr::V4(parsed.src_ip), parsed.src_port),
                arrival,
                data: Bytes::copy_from_slice(payload),
            };
            if redirect.send(rx_packet).is_err() {
                // No consumer; the whole datapath is being torn down.
                return;
            }
        }

        // Serve any pending TX requests (build the frame, push, kick).
        let mut transmitted = false;
        while let Ok(request) = tx_rx.try_recv() {
            let result = build_and_push(&mut socket, &request);
            transmitted = transmitted || result.as_ref().map(|n| *n > 0).unwrap_or(false);
            let _ = request.done.send(result);
        }
        if transmitted {
            if let Err(error) = socket.tx_kick() {
                tracing::warn!(%error, "AF_XDP TX kick failed");
            }
        }
        socket.complete_tx(64);

        // If there was no work this turn, block briefly on the TX channel so we are not a hot spin
        // when idle (the RX side is still drained each wake; production would integrate a poll() on
        // the socket fd alongside this for RX wake-ups).
        if received.is_empty() && !transmitted {
            match tx_rx.recv_timeout(std::time::Duration::from_millis(1)) {
                Ok(request) => {
                    let result = build_and_push(&mut socket, &request);
                    let _ = request.done.send(result);
                    let _ = socket.tx_kick();
                }
                Err(flume::RecvTimeoutError::Disconnected) => return,
                Err(flume::RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

/// Build an Ethernet+IPv4+UDP frame for one TX request and push it onto the ring. The next-hop MAC
/// is not yet resolved here (ARP / `rtnetlink` neighbour lookup is the remaining piece), so this
/// returns the frame length on a successful push and surfaces a clear error otherwise.
fn build_and_push(
    socket: &mut xsk::XskSocket,
    request: &TxRequest,
) -> Result<usize, DatapathError> {
    let (SocketAddr::V4(src), SocketAddr::V4(dst)) = (request.source, request.destination) else {
        // IPv4-only datapath; a v6 transport cannot be framed by the current ABI.
        return Err(DatapathError::Send(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "XDP datapath is IPv4-only",
        )));
    };
    let addrs = headers::FrameAddrs {
        // The next-hop MAC must come from the kernel neighbour table; a zeroed MAC is a placeholder
        // until ARP/rtnetlink resolution lands (the documented remaining gap).
        src_mac: [0u8; 6],
        dst_mac: [0u8; 6],
        src_ip: *src.ip(),
        dst_ip: *dst.ip(),
        src_port: src.port(),
        dst_port: dst.port(),
    };
    let mut frame = vec![0u8; headers::TOTAL_HDR_LEN + request.data.len()];
    let len = headers::build_udp_frame(&addrs, &request.data, &mut frame).ok_or_else(|| {
        DatapathError::Send(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "datagram too large to frame",
        ))
    })?;
    if socket.tx_push(&frame[..len]) {
        Ok(request.data.len())
    } else {
        Err(DatapathError::Send(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "AF_XDP TX ring full",
        )))
    }
}

/// The endpoint whose local transport matches `addr`, or `None`. Used by the datapath thread to map
/// an inbound destination transport back to the owning [`EndpointId`]. A linear scan is fine at the
/// per-session endpoint counts the relay runs; a reverse index can replace it if it ever shows up
/// in a profile.
fn endpoint_for(
    endpoints: &DashMap<EndpointId, EndpointRecord>,
    addr: SocketAddr,
) -> Option<EndpointId> {
    endpoints
        .iter()
        .find(|entry| entry.value().local_addr == addr)
        .map(|entry| *entry.key())
}

impl Datapath for XdpDatapath {
    async fn alloc_endpoint(&self) -> Result<Endpoint, DatapathError> {
        let id = EndpointId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        let port = self
            .alloc_port(id)
            .ok_or(DatapathError::PoolExhausted { limit: (MEDIA_PORT_TOP - MEDIA_PORT_BASE) as usize })?;
        let local_addr = SocketAddr::new(IpAddr::V4(self.inner.local_ip), port);
        let flow_key = FlowKey {
            local_ipv4: u32::from_be_bytes(self.inner.local_ip.octets()),
            local_port: port.to_be(),
            _pad: 0,
        };
        self.inner.endpoints.insert(
            id,
            EndpointRecord {
                local_addr,
                flow_key,
                last_seen: 0,
            },
        );
        Ok(Endpoint { id, local_addr })
    }

    fn install_flow(&self, endpoint: EndpointId, action: DpFlowAction) -> Result<(), DatapathError> {
        let record = match self.inner.endpoints.get(&endpoint) {
            Some(record) => *record,
            None => return Err(DatapathError::UnknownEndpoint(endpoint)),
        };
        // queue 0: single media RX queue for the first cut (the eBPF program redirects to the
        // socket bound on queue 0). Multi-queue spreads across redirect_queue per endpoint later.
        let kernel_action = to_kernel_action(action, &self.inner.endpoints, self.inner.local_ip, 0);
        // Recover from a poisoned lock (a prior holder panicked); the loader is still usable, and
        // `install_flow` returns a `Result`, so we must not panic here (house rule: no `.expect()`).
        let mut loader = self
            .inner
            .loader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loader
            .set_flow(record.flow_key, kernel_action)
            .map_err(|error| DatapathError::Send(std::io::Error::other(error.to_string())))
    }

    fn remove_flow(&self, endpoint: EndpointId) {
        if let Some(record) = self.inner.endpoints.get(&endpoint) {
            let key = record.flow_key;
            drop(record);
            if let Ok(mut loader) = self.inner.loader.lock() {
                let _ = loader.remove_flow(key);
            }
        }
    }

    async fn remove_endpoint(&self, endpoint: EndpointId) {
        if let Some((_, record)) = self.inner.endpoints.remove(&endpoint) {
            if let SocketAddr::V4(addr) = record.local_addr {
                self.inner.used_ports.remove(&addr.port());
            }
            if let Ok(mut loader) = self.inner.loader.lock() {
                let _ = loader.remove_flow(record.flow_key);
            }
        }
        self.inner.ice.remove(&endpoint);
    }

    async fn send(
        &self,
        endpoint: EndpointId,
        dst: SocketAddr,
        data: &[u8],
    ) -> Result<usize, DatapathError> {
        let source = match self.inner.endpoints.get(&endpoint) {
            Some(record) => record.local_addr,
            None => return Err(DatapathError::UnknownEndpoint(endpoint)),
        };
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let request = TxRequest {
            source,
            destination: dst,
            data: data.to_vec(),
            done: done_tx,
        };
        self.inner
            .tx_commands
            .send(request)
            .map_err(|_| DatapathError::Send(std::io::Error::other("datapath thread stopped")))?;
        done_rx
            .await
            .map_err(|_| DatapathError::Send(std::io::Error::other("datapath thread dropped reply")))?
    }

    fn stats(&self, endpoint: EndpointId) -> Option<EndpointStats> {
        // The kernel STATS map is a single global per-CPU counter (not yet per-endpoint), so an
        // endpoint that exists reports the program-wide totals. Per-endpoint counters are a planned
        // ABI widening (a per-flow stats value); until then this is the program aggregate, scoped to
        // "does this endpoint exist".
        self.inner.endpoints.get(&endpoint)?;
        let loader = self.inner.loader.lock().ok()?;
        let totals = loader.stats().ok()?;
        Some(EndpointStats {
            packets_in: totals.packets_in,
            packets_out: totals.packets_out,
            bytes_in: totals.bytes_in,
            bytes_out: totals.bytes_out,
            packets_dropped: totals.packets_dropped,
        })
    }

    fn now_ticks(&self) -> u64 {
        self.inner.clock.load(Ordering::Relaxed)
    }

    fn now_micros(&self) -> u64 {
        // The same real-time clock the RX thread stamps arrival from, so a participant's packet
        // arrival and its reception report's "now" (for DLSR) are read on one clock (RFC 3550 §6.4.1).
        self.inner.start.elapsed().as_micros() as u64
    }

    fn last_activity(&self, endpoint: EndpointId) -> Option<u64> {
        self.inner.endpoints.get(&endpoint).map(|r| r.last_seen)
    }

    fn set_ice(&self, endpoint: EndpointId, config: Option<IceConfig>) {
        match config {
            Some(config) => {
                self.inner.ice.insert(endpoint, config);
            }
            None => {
                self.inner.ice.remove(&endpoint);
            }
        }
    }

    fn rx(&self) -> flume::Receiver<RxPacket> {
        self.inner.redirect_rx.clone()
    }

    fn observe_rtcp(&self) -> flume::Receiver<ObservedRtcp> {
        // The observe tap is wired for the userspace-redirected path; the in-kernel XDP_TX fast path
        // would need an explicit RTCP copy-to-userspace, tracked with the XDP_TX work. The sender is
        // kept live so the receiver never sees a closed channel.
        let _ = &self.inner.observe_tx;
        self.inner.observe_rx.clone()
    }
}

/// Whether this host can load + attach XDP — else the engine selects the UDP-loopback backend.
///
/// Definitive probe: try to load and SKB-attach the program to the loopback interface. A lighter
/// probe (CAP_BPF/CAP_NET_ADMIN + kernel ≥ 5.10) can replace this once the loader is hot-pathed.
#[must_use]
pub fn xdp_supported() -> bool {
    Loader::load("lo", AttachMode::Skb).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_datapath::LatchPolicy;

    fn empty_endpoints() -> DashMap<EndpointId, EndpointRecord> {
        DashMap::new()
    }

    #[test]
    fn drop_action_maps_to_kernel_drop() {
        let kernel = to_kernel_action(DpFlowAction::Drop, &empty_endpoints(), Ipv4Addr::LOCALHOST, 0);
        assert_eq!(kernel.kind, action::DROP);
    }

    #[test]
    fn redirect_action_maps_to_kernel_redirect_with_queue() {
        let kernel =
            to_kernel_action(DpFlowAction::Redirect, &empty_endpoints(), Ipv4Addr::LOCALHOST, 3);
        assert_eq!(kernel.kind, action::REDIRECT);
        assert_eq!(kernel.redirect_queue, 3);
    }

    #[test]
    fn forward_action_encodes_source_gate_and_latch() {
        let endpoints = empty_endpoints();
        // A signalled rule: exact-source gate, signalled latch, IPv4 destination.
        let expected = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let dst: SocketAddr = "203.0.113.5:6000".parse().expect("addr");
        let rule = ForwardRule::signalled(EndpointId(1), Some(dst), expected);
        let kernel = to_kernel_action(
            DpFlowAction::Forward(rule),
            &endpoints,
            Ipv4Addr::new(198, 51, 100, 1),
            0,
        );
        assert_eq!(kernel.kind, action::FORWARD);
        assert_eq!(kernel.source_kind, source::EXACT);
        assert_eq!(kernel.source_ipv4, u32::from_be_bytes([198, 51, 100, 7]));
        assert_eq!(kernel.latch_policy, latch::SIGNALLED);
        assert_eq!(kernel.out_ipv4, u32::from_be_bytes([203, 0, 113, 5]));
        assert_eq!(kernel.out_port, 6000u16.to_be());
    }

    #[test]
    fn forward_subnet_gate_encodes_prefix() {
        let rule = ForwardRule {
            out_endpoint: EndpointId(2),
            out_dst: None,
            accepted_source: SourceFilter::Subnet(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
            latch: LatchPolicy::SignalledOnly,
        };
        let kernel = to_kernel_action(
            DpFlowAction::Forward(rule),
            &empty_endpoints(),
            Ipv4Addr::LOCALHOST,
            0,
        );
        assert_eq!(kernel.source_kind, source::SUBNET);
        assert_eq!(kernel.source_prefix, 8);
        assert_eq!(kernel.source_ipv4, u32::from_be_bytes([10, 0, 0, 0]));
    }

    #[test]
    fn forward_resolves_peer_local_transport_as_tx_source() {
        let endpoints = empty_endpoints();
        let peer = EndpointId(9);
        endpoints.insert(
            peer,
            EndpointRecord {
                local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 31000),
                flow_key: FlowKey {
                    local_ipv4: 0,
                    local_port: 0,
                    _pad: 0,
                },
                last_seen: 0,
            },
        );
        let rule = ForwardRule::symmetric(peer, Some("203.0.113.9:7000".parse().expect("addr")));
        let kernel = to_kernel_action(
            DpFlowAction::Forward(rule),
            &endpoints,
            Ipv4Addr::new(198, 51, 100, 1),
            0,
        );
        // The XDP_TX source transport is the peer endpoint's local media port.
        assert_eq!(kernel.out_local_ipv4, u32::from_be_bytes([198, 51, 100, 1]));
        assert_eq!(kernel.out_src_port, 31000u16.to_be());
        assert_eq!(kernel.latch_policy, latch::SYMMETRIC);
    }

    #[test]
    fn v6_source_filter_falls_back_to_any() {
        let rule = ForwardRule {
            out_endpoint: EndpointId(1),
            out_dst: None,
            accepted_source: SourceFilter::Exact(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            latch: LatchPolicy::Off,
        };
        let kernel = to_kernel_action(
            DpFlowAction::Forward(rule),
            &empty_endpoints(),
            Ipv4Addr::LOCALHOST,
            0,
        );
        assert_eq!(kernel.source_kind, source::ANY);
    }
}
