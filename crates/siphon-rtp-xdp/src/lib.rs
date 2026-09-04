//! The XDP/AF_XDP datapath backend.
//!
//! This crate is the kernel-acceleration counterpart of `siphon-rtp-datapath`'s UDP-loopback
//! backend, kept separate so the always-available backend never depends on aya/eBPF. It loads the
//! embedded XDP classifier (the `siphon-rtp-ebpf` crate), attaches it to an interface, drives the `FLOWS` /
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
//! The control plane (map programming, endpoint/flow registry, the port pool, the real-time clock,
//! the redirect/observe streams, the FlowKey/FlowAction encoding, header build/parse + checksums, and
//! the UMEM frame book-keeping) is exercised NIC-free and unit-tested. Actually *binding* the AF_XDP
//! socket and moving packets needs a real driver queue + `CAP_NET_RAW`: [`XdpDatapath::new`] binds
//! the socket eagerly and returns [`XdpError::Xsk`] if that fails, so the engine selects this
//! backend only after [`xdp_supported`] and the AF_XDP bind both succeed, else it falls back to
//! UDP-loopback.
//!
//! ## Next-hop MAC resolution (wired — Stage 1)
//!
//! `build_and_push` resolves the egress interface's source MAC and the next hop's destination MAC
//! before it frames a TX packet (see [`neighbor`]): the kernel route to the destination gives the
//! next hop (on-link → the destination itself, else the gateway — RFC 1122 §3.3.1) and egress
//! interface, and the kernel neighbour table (ARP, RFC 826) gives its MAC. The busy-poll thread only
//! reads a synchronous cache; on a miss it drops the packet and an off-thread rtnetlink worker
//! resolves it, so no frame ever egresses with a zeroed MAC and the datapath never blocks on netlink.
//!
//! ## Per-flow state feedback (wired — Stage 3a)
//!
//! The classifier feeds three per-flow facts back to userspace through the shared ABI:
//! - **Per-endpoint stats**: a per-flow `FLOW_STATS` (`PerCpuHashMap<FlowKey, FlowStats>`), alongside
//!   the program-wide `STATS` aggregate, lets [`XdpDatapath::stats`] report one endpoint's real
//!   `packets_*` / `bytes_*` / `packets_dropped`, summed across CPUs. Bytes count the UDP payload, to
//!   match the loopback backend's accounting.
//! - **`last_activity`**: the kernel stamps `FlowStats::last_seen_ns` with `bpf_ktime_get_ns()`
//!   (`CLOCK_MONOTONIC`) on every **accepted** packet — the in-kernel Forward relay *and* the Redirect
//!   path — so [`XdpDatapath::last_activity`] returns a real value (via `kernel_ns_to_tick`, mapped to
//!   the elapsed-tick domain against the construction origin, the same real-time clock domain as
//!   [`XdpDatapath::now_ticks`] / `now_micros`) for the media-timeout / dead-path sweep. `now_ticks`
//!   is real-time too — `monotonic_ns()` against the same origin, NOT a logical sweep clock — so the
//!   sweep's `now_ticks() - last_activity()` is a coherent elapsed-tick count and
//!   `Datapath::advance_clock` is a no-op here (docs/security-and-nat.md §4 layer 6).
//! - **Learned-latch readback**: [`XdpDatapath::learned_latch`] reads a flow's in-kernel-learned peer
//!   source (`latched_*` in the `FLOWS` value) when the latch is valid, and [`XdpDatapath::learned_source`]
//!   (the [`Datapath`] trait override) exposes it as a [`SocketAddr`]. The engine consumes it on its
//!   1 Hz sweep (`Engine::refresh_latched_destinations`): it propagates a learned NAT source to the
//!   **sibling** leg's `out_dst`, so a NATed peer's real post-latch source drives the in-kernel relay
//!   (the in-kernel symmetric-RTP loop is now closed; docs/security-and-nat.md §4 layer 3).
//!
//! ## RTCP copy-to-userspace tap (wired)
//!
//! The in-kernel `XDP_TX` Forward relay mirrors every **forwarded** RTCP datagram into the `RTCP_TAP`
//! ring buffer (a fixed [`siphon_rtp_ebpf_common::RtcpTapRecord`] per packet) as a pure side-effect —
//! the RTCP still `XDP_TX`-forwards exactly as before, and any tap failure is swallowed. The datapath
//! thread drains the ring (`observed_rtcp_from_record`) into the bounded observe stream, so a
//! kernelized relay's RTCP reaches the HEP QoS export (loss / jitter / RTT for VoIPmonitor / Homer)
//! exactly like the userspace-redirected path. [`XdpDatapath::observe_rtcp`] returns that fed stream.
//!
//! ## ABI POD wrappers
//!
//! The ABI POD types live in the aya-free, no_std `siphon-rtp-ebpf-common`; here they are wrapped in
//! `#[repr(transparent)]` newtypes that impl [`aya::Pod`] (the orphan rule forbids impl'ing a
//! foreign trait on a foreign type, and keeping aya out of the shared crate keeps it off the
//! workspace's dependency graph).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use aya::maps::{
    HashMap as AyaHashMap, MapData, MapError, PerCpuArray, PerCpuHashMap, RingBuf, XskMap,
};
use aya::programs::{Xdp, XdpFlags};
use aya::{Ebpf, Pod};
use bytes::Bytes;
use dashmap::DashMap;

use siphon_rtp_datapath::{
    classify, Datapath, DatapathError, Dscp, Endpoint, EndpointId, EndpointStats,
    FlowAction as DpFlowAction, ForwardRule, IceAgentMode, IceConfig, IceDatapathEvent,
    ObservedRtcp, PacketClass, RxPacket, SourceFilter,
};
use siphon_rtp_ebpf_common::{
    action, latch, source, FlowAction, FlowKey, FlowStats, RtcpTapRecord, RTCP_TAP_MAX_PAYLOAD,
};

pub mod headers;
pub mod neighbor;
pub mod xsk;

use neighbor::{NeighborResolver, Resolution, ResolverConfig};

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
    dscp: Dscp,
}

impl Loader {
    /// Load the embedded XDP program and attach it to `interface` in `mode`, marking every packet
    /// the in-kernel fast path forwards with `dscp` (RFC 2474).
    ///
    /// The marking is a **load-time constant**, not a per-flow map field: it is node policy, so it
    /// is stamped into the program's `.rodata` via `MEDIA_TOS` before the verifier sees it. The
    /// kernel then folds the DSCP write into the rewrite it already does, and a
    /// [`Dscp::BE`] configuration compiles down to a byte the program compares equal and skips.
    pub fn load(interface: &str, mode: AttachMode, dscp: Dscp) -> Result<Self, XdpError> {
        let mut ebpf = aya::EbpfLoader::new()
            // `must_exist = false`: a program object built before this global existed still loads,
            // it simply forwards unmarked — the same posture the datapath had before marking.
            .set_global("MEDIA_TOS", &dscp.to_tos_byte(), false)
            .load(aya::include_bytes_aligned!(concat!(
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
            dscp,
        })
    }

    /// The interface the program is attached to.
    #[must_use]
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// The DSCP the loaded program marks forwarded media with. [`XdpDatapath`] reads it back from
    /// here so the in-kernel XDP_TX path and the userspace AF_XDP TX path cannot drift apart.
    #[must_use]
    pub fn dscp(&self) -> Dscp {
        self.dscp
    }

    /// Register an AF_XDP socket fd into the `XSKS` map at `queue` so the classifier's
    /// `XDP_REDIRECT(queue)` lands packets on it. The socket must be bound to the same queue.
    pub fn register_xsk(
        &mut self,
        queue: u32,
        socket_fd: std::os::fd::RawFd,
    ) -> Result<(), XdpError> {
        let mut xsks: XskMap<&mut MapData> =
            XskMap::try_from(self.ebpf.map_mut("XSKS").ok_or_else(|| XdpError::Map {
                map: "XSKS",
                detail: "missing".to_string(),
            })?)
            .map_err(|error| XdpError::Map {
                map: "XSKS",
                detail: error.to_string(),
            })?;
        xsks.set(queue, socket_fd, 0)
            .map_err(|error| XdpError::Map {
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

    /// The program-wide aggregate: sum the per-CPU `STATS` counters across all CPUs (the totals over
    /// every flow). Per-endpoint counters come from [`Loader::flow_stats`]; this stays the global
    /// health metric.
    pub fn stats(&self) -> Result<FlowStats, XdpError> {
        let stats: PerCpuArray<_, PodStats> =
            PerCpuArray::try_from(self.ebpf.map("STATS").ok_or_else(|| XdpError::Map {
                map: "STATS",
                detail: "missing".to_string(),
            })?)
            .map_err(|error| XdpError::Map {
                map: "STATS",
                detail: error.to_string(),
            })?;

        let per_cpu = stats.get(&0, 0).map_err(|error| XdpError::Map {
            map: "STATS",
            detail: error.to_string(),
        })?;
        Ok(sum_flow_stats(per_cpu.iter().map(|value| value.0)))
    }

    /// Read one flow's per-CPU stats, summed across CPUs (counters) with `last_seen_ns` **maxed** (the
    /// most recent accepted-packet time on any CPU). `Ok(None)` when the flow has no entry yet (no
    /// packet has arrived on it), so an idle-but-existing endpoint reports zeros, never an error.
    pub fn flow_stats(&self, key: FlowKey) -> Result<Option<FlowStats>, XdpError> {
        let stats: PerCpuHashMap<_, PodKey, PodStats> =
            PerCpuHashMap::try_from(self.ebpf.map("FLOW_STATS").ok_or_else(|| XdpError::Map {
                map: "FLOW_STATS",
                detail: "missing".to_string(),
            })?)
            .map_err(|error| XdpError::Map {
                map: "FLOW_STATS",
                detail: error.to_string(),
            })?;
        match stats.get(&PodKey(key), 0) {
            Ok(per_cpu) => Ok(Some(sum_flow_stats(per_cpu.iter().map(|value| value.0)))),
            // A flow with no traffic yet simply has no per-CPU entry — not an error.
            Err(MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(XdpError::Map {
                map: "FLOW_STATS",
                detail: error.to_string(),
            }),
        }
    }

    /// Read a flow's current action value (the configured rule plus its in-kernel latch state), or
    /// `Ok(None)` when no flow is installed for `key`. The read primitive behind
    /// [`XdpDatapath::learned_latch`].
    pub fn flow(&self, key: FlowKey) -> Result<Option<FlowAction>, XdpError> {
        let flows: AyaHashMap<_, PodKey, PodAction> =
            AyaHashMap::try_from(self.ebpf.map("FLOWS").ok_or_else(|| XdpError::Map {
                map: "FLOWS",
                detail: "missing".to_string(),
            })?)
            .map_err(|error| XdpError::Map {
                map: "FLOWS",
                detail: error.to_string(),
            })?;
        match flows.get(&PodKey(key), 0) {
            Ok(action) => Ok(Some(action.0)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(XdpError::Map {
                map: "FLOWS",
                detail: error.to_string(),
            }),
        }
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

    /// Take ownership of the `RTCP_TAP` ring buffer (the in-kernel RTCP copy-to-userspace tap) out of
    /// the loaded program, so the datapath thread can drain it as its single owner without holding the
    /// loader lock across the (blocking-capable) ring reads. `None` if the program has no such map
    /// (older bytecode) or it is not a ring buffer — the caller then simply runs without the tap, and
    /// [`XdpDatapath::observe_rtcp`] yields no in-kernel observations (never an error). The map's fd
    /// stays alive in the returned handle, so the still-attached program keeps writing to it.
    pub fn take_rtcp_tap_ring(&mut self) -> Option<RingBuf<MapData>> {
        let map = self.ebpf.take_map("RTCP_TAP")?;
        RingBuf::try_from(map).ok()
    }
}

/// The first ephemeral media port the XDP backend hands out (the IANA dynamic range floor minus the
/// odd-port reservations; rtpengine's default media range starts here). Ports are assigned in pairs-
/// agnostic single-port units; the session manager pairs RTP/RTCP at the call layer.
const MEDIA_PORT_BASE: u16 = 30000;
/// Upper bound of the media-port pool.
const MEDIA_PORT_TOP: u16 = 40000;

/// Per-endpoint record: the engine-local transport and the FLOWS key the kernel matches on.
///
/// It carries no `last_seen` tick: unlike the loopback backend, the XDP datapath's per-flow activity
/// is fed back **from the kernel** (the classifier stamps `FlowStats::last_seen_ns` on every accepted
/// packet), so [`XdpDatapath::last_activity`] reads the kernel map, not a userspace-stamped field.
#[derive(Clone, Copy)]
struct EndpointRecord {
    local_addr: SocketAddr,
    flow_key: FlowKey,
}

/// A full-agent ICE registration for one endpoint (see [`Datapath::set_ice_agent`]): who answers
/// inbound connectivity checks, and the sink the raw STUN is forwarded to.
#[derive(Clone)]
struct IceAgentRegistration {
    /// Whether the datapath still answers checks itself, or only forwards them to the agent.
    mode: IceAgentMode,
    /// Where every STUN datagram seen on the endpoint goes — including the Binding *responses* the
    /// responder would otherwise drop, which is what RFC 7675 consent needs to correlate.
    events: flume::Sender<IceDatapathEvent>,
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
    /// `Arc`-shared with the datapath thread, which needs it to write an ice-lite responder's adopted
    /// source into the kernel flow (the enforcement copy of the layer-4 gate).
    loader: Arc<Mutex<Loader>>,
    /// Endpoint registry: id → transport + flow key. Lock-free reads on the relay path. `Arc`-shared
    /// (not `DashMap::clone`, which deep-copies) so the datapath thread sees live insertions.
    endpoints: Arc<DashMap<EndpointId, EndpointRecord>>,
    /// Allocated media ports, so the pool never double-assigns.
    used_ports: DashMap<u16, EndpointId>,
    /// Per-endpoint ICE credentials. Set on an endpoint, these flip the kernel flow's `ice` byte, so
    /// the classifier redirects STUN here (rather than dropping it at the layer-1 demux) and gates
    /// media on the adopted source alone. `Arc`-shared with the datapath thread, which answers checks
    /// on a [`IceAgentMode::RespondAndForward`] endpoint.
    ice: Arc<DashMap<EndpointId, IceConfig>>,
    /// Per-endpoint **full-agent** ICE registration: who answers inbound checks, and where the raw
    /// STUN goes. Present only for endpoints promoted via [`Datapath::set_ice_agent`]; the datapath
    /// thread reads it on every STUN datagram.
    ice_agents: Arc<DashMap<EndpointId, IceAgentRegistration>>,
    /// The source ICE adopted per endpoint (see [`Datapath::ice_validated_source`]). Shared with the
    /// datapath thread, which writes it when the ice-lite responder validates a check.
    ice_adopted: Arc<DashMap<EndpointId, SocketAddr>>,
    /// Tick of the last **validated** connectivity check per ICE endpoint, folded into
    /// [`Datapath::last_activity`]. The kernel stamps `last_seen_ns` only on accepted *media*, so
    /// without this an ICE leg that is exchanging checks but has not started media yet — the whole
    /// establishment window, and a held leg kept alive by consent — would look idle to the
    /// media-timeout sweep and be reaped. The loopback backend gets this for free (its responder
    /// stamps the same counter media does); this is what keeps the two backends agreeing.
    ice_last_check: Arc<DashMap<EndpointId, u64>>,
    next_id: AtomicU64,
    next_port: AtomicU64,
    /// Real-time monotonic origin for **arrival** timestamps and `now_micros` (RTCP interarrival
    /// jitter / DLSR, RFC 3550 §6.4.1): wall-clock-rate elapsed time, shared with the datapath thread
    /// so a packet's arrival and a report's "now" read one clock. XDP has **no** logical sweep clock —
    /// it runs on a real NIC (not the deterministic CI loopback datapath), so `now_ticks` is real-time
    /// too (`monotonic_ns` against `start_ktime_ns`), and `Datapath::advance_clock` is a no-op for it.
    /// Production only — XDP runs on a real NIC, not in CI.
    start: std::time::Instant,
    /// `CLOCK_MONOTONIC` ns reading captured at construction, in the **same** clock domain as the
    /// kernel's `bpf_ktime_get_ns()` (and as `start` above). It is the origin the kernel's per-flow
    /// `last_seen_ns` stamps are measured against, so [`XdpDatapath::last_activity`] converts a kernel
    /// ns stamp into the elapsed-tick domain (`kernel_ns_to_tick`) — and [`XdpDatapath::now_ticks`]
    /// maps `monotonic_ns()` against this same origin, so both share one real-time tick domain.
    start_ktime_ns: u64,
    /// The engine-local relay IPv4 every endpoint advertises and the kernel keys flows on.
    local_ip: Ipv4Addr,
    /// Receiver end of the redirect stream; the sole sender lives on the datapath thread.
    redirect_rx: flume::Receiver<RxPacket>,
    /// Receiver end of the RTCP observe stream ([`XdpDatapath::observe_rtcp`]). The sole sender lives on
    /// the datapath thread, which drains the in-kernel `RTCP_TAP` ring into it — so the channel stays
    /// open for the datapath's whole life (the thread is joined on teardown) and closes when it exits.
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
        // The marking the loader stamped into the kernel program, so the AF_XDP TX frames this
        // backend builds in userspace carry the identical TOS byte (RFC 2474) — one call must not
        // be marked differently depending on whether it took the in-kernel or the slow path.
        let tos = loader.dscp().to_tos_byte();
        let ifindex = xsk::ifindex(interface);
        let socket = xsk::XskSocket::new(ifindex, queue, &config)?;
        loader.register_xsk(queue, socket.as_raw_fd())?;
        // Take the in-kernel RTCP tap ring out of the program so the datapath thread owns it (drains it
        // without touching the loader lock). `None` if the program predates the tap — the datapath then
        // runs with no in-kernel RTCP observations, exactly as before this feature.
        let tap_ring = loader.take_rtcp_tap_ring();

        let (redirect_tx, redirect_rx) = flume::unbounded();
        let (observe_tx, observe_rx) = flume::bounded(256);
        let (tx_commands, tx_rx) = flume::unbounded::<TxRequest>();
        let endpoints: Arc<DashMap<EndpointId, EndpointRecord>> = Arc::new(DashMap::new());
        let ice: Arc<DashMap<EndpointId, IceConfig>> = Arc::new(DashMap::new());
        let ice_agents: Arc<DashMap<EndpointId, IceAgentRegistration>> = Arc::new(DashMap::new());
        let ice_adopted: Arc<DashMap<EndpointId, SocketAddr>> = Arc::new(DashMap::new());
        let ice_last_check: Arc<DashMap<EndpointId, u64>> = Arc::new(DashMap::new());
        let shared_loader = Arc::new(Mutex::new(loader));
        let start = std::time::Instant::now();
        // Same-instant CLOCK_MONOTONIC reading (the domain of the kernel's bpf_ktime_get_ns per-flow
        // stamps) — the origin `last_activity` maps those stamps against.
        let start_ktime_ns = monotonic_ns();
        // The next-hop MAC resolver spawns its own off-reactor rtnetlink worker; the busy-poll thread
        // owns it and reads its resolved-MAC cache synchronously on the TX path. Owned solely by that
        // thread, so it (and its worker) tear down when the datapath thread exits.
        let resolver = NeighborResolver::new(ResolverConfig::default());

        let inner = Arc::new(Inner {
            loader: shared_loader.clone(),
            endpoints: endpoints.clone(),
            used_ports: DashMap::new(),
            ice: ice.clone(),
            ice_agents: ice_agents.clone(),
            ice_adopted: ice_adopted.clone(),
            ice_last_check: ice_last_check.clone(),
            next_id: AtomicU64::new(0),
            next_port: AtomicU64::new(0),
            start,
            start_ktime_ns,
            local_ip,
            redirect_rx,
            observe_rx,
            tx_commands,
            datapath_thread: Mutex::new(None),
        });

        // The busy-poll thread is the single owner of the AF_XDP socket (actor model): it drains RX
        // into the redirect stream and serialises TX requests, so the ring is never touched
        // concurrently. It also owns and drains the in-kernel RTCP tap ring (the sole `observe_tx`
        // sender lives here, feeding the observe stream), so it is the single owner of every kernel-fed
        // stream. It shares the live endpoint registry via the `Arc` (not a snapshot).
        let thread_redirect = redirect_tx;
        let thread_loader = shared_loader.clone();
        let thread_endpoints = endpoints;
        let local_ip_copy = local_ip;
        let thread_resolver = resolver;
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
                    thread_resolver,
                    tap_ring,
                    observe_tx,
                    IceDemux {
                        ice,
                        ice_agents,
                        adopted: ice_adopted,
                        last_check: ice_last_check,
                    },
                    thread_loader,
                    tos,
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

    /// Push `endpoint`'s current ICE posture into its kernel flow: set (or clear) the `ice` byte the
    /// classifier reads, and carry the adopted source with it. Called whenever the credentials change,
    /// so an endpoint that gains ICE *after* its flow was installed still gets gated.
    ///
    /// No flow installed yet is not an error — `install_flow` reads the same state and stamps it on.
    fn set_kernel_ice_flag(&self, endpoint: EndpointId) {
        let Some(key) = self
            .inner
            .endpoints
            .get(&endpoint)
            .map(|record| record.flow_key)
        else {
            return;
        };
        let is_ice = self.inner.ice.contains_key(&endpoint);
        let adopted = self.inner.ice_adopted.get(&endpoint).map(|entry| *entry);
        let mut loader = self
            .inner
            .loader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let existing = match loader.flow(key) {
            Ok(Some(action)) => action,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(target: "siphon_rtp::datapath", ?endpoint, %error, "reading the flow to set the ICE flag failed");
                return;
            }
        };
        let mut updated = existing;
        apply_ice_posture(&mut updated, is_ice, adopted);
        if let Err(error) = loader.set_flow(key, updated) {
            tracing::warn!(target: "siphon_rtp::datapath", ?endpoint, %error, "writing the ICE flag into the kernel flow failed");
        }
    }

    /// Read back the peer source the kernel's in-kernel latch has learned for `endpoint` (symmetric
    /// RTP, RFC 3550 §8), or `None` when the endpoint is unknown, has no flow installed, or has not
    /// latched a source yet. The [`Datapath::learned_source`] override exposes this over the trait, and
    /// the engine consumes it on its 1 Hz sweep (`Engine::refresh_latched_destinations`) to propagate a
    /// learned NAT source to the sibling leg's `out_dst` — the in-kernel symmetric-RTP loop is now
    /// closed (docs/security-and-nat.md §4 layer 3). Kept an inherent method (with the trait override
    /// delegating to it) so the SSRC-bearing [`LearnedLatch`] detail stays inside the XDP backend.
    #[must_use]
    pub fn learned_latch(&self, endpoint: EndpointId) -> Option<LearnedLatch> {
        let key = self.inner.endpoints.get(&endpoint)?.flow_key;
        let loader = self
            .inner
            .loader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let action = loader.flow(key).ok()??;
        learned_latch_from_action(&action)
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

    /// Allocate an endpoint that binds/emits from a **specific** local IPv4 — the shared core of
    /// [`Datapath::alloc_endpoint`] (which uses the configured `local_ip`) and
    /// [`Datapath::alloc_endpoint_on`] (a named-interface source IP). The per-flow source is carried
    /// end-to-end without any eBPF change: the kernel `FlowAction.out_local_ipv4` is filled from the
    /// egress peer's `local_addr` (`apply_forward_target`) and the userspace TX frame builder sources
    /// from `record.local_addr`, so a different `bind_ip` here means a different egress source IP.
    /// Valid only for a source IP on the one attached NIC (the same-NIC scope; a second NIC needs a
    /// second AF_XDP socket).
    fn alloc_endpoint_on_ipv4(&self, bind_ip: Ipv4Addr) -> Result<Endpoint, DatapathError> {
        let id = EndpointId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        let port = self.alloc_port(id).ok_or(DatapathError::PoolExhausted {
            limit: (MEDIA_PORT_TOP - MEDIA_PORT_BASE) as usize,
        })?;
        let local_addr = SocketAddr::new(IpAddr::V4(bind_ip), port);
        let flow_key = FlowKey {
            local_ipv4: u32::from_be_bytes(bind_ip.octets()),
            local_port: port.to_be(),
            _pad: 0,
        };
        self.inner.endpoints.insert(
            id,
            EndpointRecord {
                local_addr,
                flow_key,
            },
        );
        Ok(Endpoint { id, local_addr })
    }
}

/// Nanoseconds per logical media tick: 20 ms — the RTP media frame period and the engine's sweep
/// cadence (the same 20 ms/tick the [`Datapath::now_micros`] default uses).
const NS_PER_TICK: u64 = 20_000_000;

/// Read `CLOCK_MONOTONIC` in nanoseconds — the same clock domain the kernel's `bpf_ktime_get_ns()`
/// stamps in and that `std::time::Instant` reads on Linux. Captured once at construction as the origin
/// the kernel's per-flow `last_seen_ns` is measured against. Returns 0 on the (essentially impossible)
/// syscall failure, which only means `last_activity` maps kernel stamps from tick 0.
fn monotonic_ns() -> u64 {
    let mut timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `timespec` is a valid, writable `timespec`; CLOCK_MONOTONIC is always available on Linux.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timespec) } != 0 {
        return 0;
    }
    (timespec.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(timespec.tv_nsec as u64)
}

/// Map an in-kernel `bpf_ktime_get_ns()` stamp (`CLOCK_MONOTONIC` ns since boot) into the datapath's
/// logical tick domain, relative to the backend's monotonic origin captured at construction. Both the
/// kernel helper and `start_ktime_ns` read `CLOCK_MONOTONIC` (the same clock `Instant` uses on Linux),
/// so the subtraction is well-defined and suspend-consistent. A zero stamp (no packet accepted yet)
/// maps to tick 0; a stamp before the origin saturates to 0. Pure — unit-tested with injected values
/// and criterion-benched (the per-`last_activity`-query conversion cost).
#[must_use]
pub fn kernel_ns_to_tick(last_seen_ns: u64, start_ktime_ns: u64) -> u64 {
    if last_seen_ns == 0 {
        return 0;
    }
    last_seen_ns.saturating_sub(start_ktime_ns) / NS_PER_TICK
}

/// Reduce a flow value's per-CPU slices to one [`FlowStats`]: **sum** the counter fields and take the
/// **max** of `last_seen_ns` (a monotonic timestamp, not a count — the most recent accepted packet on
/// any CPU). Pure and allocation-free (accumulates into one stack [`FlowStats`]) — unit-tested with
/// injected per-CPU vectors and criterion-benched (the per-endpoint stats-read reduction cost across
/// CPUs), no map / NIC needed.
#[must_use]
pub fn sum_flow_stats(per_cpu: impl IntoIterator<Item = FlowStats>) -> FlowStats {
    let mut total = FlowStats::default();
    for value in per_cpu {
        total.packets_in += value.packets_in;
        total.packets_out += value.packets_out;
        total.bytes_in += value.bytes_in;
        total.bytes_out += value.bytes_out;
        total.packets_dropped += value.packets_dropped;
        total.last_seen_ns = total.last_seen_ns.max(value.last_seen_ns);
        total.packets_lost += value.packets_lost;
        // `last_rtp_seq` is per-CPU internal loss-estimator state (the last observed RTP sequence),
        // not a summable counter — no meaningful cross-CPU reduction, so it is left 0 in the aggregate.
    }
    total
}

/// The peer source a Forward flow's in-kernel latch has learned (symmetric RTP, RFC 3550 §8),
/// read back from the `FLOWS` map value. Exposed over the trait as [`Datapath::learned_source`]
/// (dropping the SSRC) and consumed by the engine's 1 Hz sweep, which propagates the learned NAT
/// source to the sibling leg's `out_dst` (docs/security-and-nat.md §4 layer 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LearnedLatch {
    /// The learned peer transport (source IPv4 + port).
    pub source: SocketAddrV4,
    /// The RTP SSRC that pinned the latch (host order) — the re-latch consistency key.
    pub ssrc: u32,
}

/// Extract the learned latch from a flow action, or `None` when the kernel has not latched a source
/// (`latch_valid == 0`). The kernel stores `latched_ipv4` / `latched_port` in host order (a
/// `from_be_bytes` of the wire bytes; see `siphon-rtp-ebpf::forward_in_kernel`), so `Ipv4Addr::from`
/// and the raw port reconstruct the peer transport directly. Pure — unit-tested with a synthetic
/// action, no map / NIC needed.
fn learned_latch_from_action(action: &FlowAction) -> Option<LearnedLatch> {
    if action.latch_valid == 0 {
        return None;
    }
    Some(LearnedLatch {
        source: SocketAddrV4::new(Ipv4Addr::from(action.latched_ipv4), action.latched_port),
        ssrc: action.latched_ssrc,
    })
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
        ice: 0,
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

/// Stamp an endpoint's ICE posture onto a kernel action: the `ice` byte the classifier gates on, and
/// the adopted source in the latch fields it compares media against.
///
/// A **non**-ICE endpoint clears the flag and leaves the latch alone — that is the plain relay's
/// symmetric-RTP latch, which the kernel owns and must not be stamped over. An ICE endpoint with no
/// adoption yet is deliberately left `latch_valid = 0`, which the layer-4 gate reads as "forward
/// nothing": media waits for ICE rather than racing it.
fn apply_ice_posture(kernel: &mut FlowAction, is_ice: bool, adopted: Option<SocketAddr>) {
    if !is_ice {
        kernel.ice = 0;
        return;
    }
    kernel.ice = 1;
    match adopted {
        Some(SocketAddr::V4(source)) => {
            kernel.latched_ipv4 = u32::from_be_bytes(source.ip().octets());
            kernel.latched_port = source.port();
            kernel.latched_ssrc = 0;
            kernel.latch_valid = 1;
        }
        // Nothing adopted (or a v6 source the IPv4 ABI cannot express): keep the gate closed.
        _ => {
            kernel.latched_ipv4 = 0;
            kernel.latched_port = 0;
            kernel.latched_ssrc = 0;
            kernel.latch_valid = 0;
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

/// The ICE state the datapath thread needs to demux STUN out of the redirected stream: the
/// per-endpoint credentials (to answer a check) and the full-agent registrations (where to forward
/// it). Shared with the control plane by `Arc`, so a `set_ice` / `set_ice_agent` between bursts is
/// visible on the very next packet.
#[derive(Clone)]
struct IceDemux {
    ice: Arc<DashMap<EndpointId, IceConfig>>,
    ice_agents: Arc<DashMap<EndpointId, IceAgentRegistration>>,
    /// The source ICE has adopted per endpoint — the userspace record behind
    /// [`Datapath::ice_validated_source`]. Written by the ice-lite responder on this thread and by
    /// [`Datapath::adopt_source`] on the control plane; the kernel flow's latch fields are the
    /// enforcement copy of the same decision.
    adopted: Arc<DashMap<EndpointId, SocketAddr>>,
    /// Tick of the last validated check per endpoint — see `Inner::ice_last_check`.
    last_check: Arc<DashMap<EndpointId, u64>>,
}

/// One STUN datagram's disposition on the datapath thread, decided by [`IceDemux::classify`].
#[derive(Debug, PartialEq, Eq)]
enum StunDisposition {
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
    fn classify(
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

/// Write an ICE-adopted source into `endpoint`'s kernel flow, which is what the classifier's layer-4
/// gate compares every media datagram against (`rewrite::ice_media_allowed`). Until this lands, an
/// ICE flow forwards nothing at all — that is the intended posture: media follows ICE's decision, not
/// the first packet to arrive.
///
/// Best-effort by design: an endpoint with no flow installed yet simply has nothing to write to, and
/// the adoption is re-applied when the flow is installed (`install_flow` carries the adopted latch
/// forward). Never panics — a poisoned lock is recovered, a map error is logged.
fn adopt_source_in_kernel(
    loader: &Mutex<Loader>,
    endpoints: &DashMap<EndpointId, EndpointRecord>,
    endpoint: EndpointId,
    source: SocketAddr,
) {
    let SocketAddr::V4(source) = source else {
        // The kernel ABI is IPv4-only; a v6 ICE leg cannot be gated in-kernel, so leave the flow
        // ungated-but-empty rather than adopt something the classifier cannot represent.
        tracing::debug!(
            target: "siphon_rtp::datapath",
            ?endpoint,
            "ICE adopted an IPv6 source; the IPv4 kernel flow ABI cannot express it"
        );
        return;
    };
    let Some(key) = endpoints.get(&endpoint).map(|record| record.flow_key) else {
        return;
    };
    let mut loader = loader
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let existing = match loader.flow(key) {
        Ok(Some(action)) => action,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(target: "siphon_rtp::datapath", ?endpoint, %error, "reading the flow to adopt an ICE source failed");
            return;
        }
    };
    let mut updated = existing;
    // Host order, matching what the kernel's latch state machine reads and compares (see
    // `siphon-rtp-ebpf::forward_in_kernel`).
    updated.latched_ipv4 = u32::from_be_bytes(source.ip().octets());
    updated.latched_port = source.port();
    updated.latched_ssrc = 0; // Unused on an ICE flow: authentication, not SSRC continuity, gates it.
    updated.latch_valid = 1;
    if let Err(error) = loader.set_flow(key, updated) {
        tracing::warn!(target: "siphon_rtp::datapath", ?endpoint, %error, "writing the ICE-adopted source into the kernel flow failed");
    }
}

/// The dedicated AF_XDP datapath thread: the single owner of the socket. It busy-polls the RX ring
/// (draining received frames → the redirect stream, keyed by destination transport → endpoint) and
/// serves TX requests from the command channel, completing TX frames between bursts.
///
/// It also owns the **ICE demux**: on an ICE endpoint the kernel redirects STUN here instead of
/// dropping it, and this thread routes it to the engine's agent (and answers it, for an ice-lite
/// endpoint) rather than letting it reach the media consumer as if it were RTP.
#[allow(clippy::too_many_arguments)]
fn datapath_loop(
    mut socket: xsk::XskSocket,
    tx_rx: flume::Receiver<TxRequest>,
    redirect: flume::Sender<RxPacket>,
    endpoints: Arc<DashMap<EndpointId, EndpointRecord>>,
    _local_ip: Ipv4Addr,
    start: std::time::Instant,
    resolver: NeighborResolver,
    mut tap_ring: Option<RingBuf<MapData>>,
    observe: flume::Sender<ObservedRtcp>,
    ice: IceDemux,
    loader: Arc<Mutex<Loader>>,
    // TOS byte (DSCP << 2, RFC 2474) stamped on every frame this thread builds — see
    // `headers::FrameAddrs::tos`.
    tos: u8,
) {
    // Reused across bursts so answering a check allocates nothing per packet (the responses
    // themselves are built by the STUN encoder).
    let mut stun_responses: Vec<(EndpointId, SocketAddr, Vec<u8>)> = Vec::new();
    loop {
        // Stamp the resolver's freshness clock from the same monotonic origin the RX path uses
        // (seconds granularity is ample for neighbour/route TTLs). Production path only — never a
        // test-driven clock, so cache-expiry stays deterministic under test.
        resolver.set_now(start.elapsed().as_secs());

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
            let payload =
                &packet.frame[parsed.payload_offset..parsed.payload_offset + parsed.payload_len];
            let source = SocketAddr::new(IpAddr::V4(parsed.src_ip), parsed.src_port);

            // RFC 7983 demux: on an ICE endpoint the classifier redirects STUN up here (it does not
            // reach the kernel relay), and it belongs to the agent — never to the media consumer,
            // which would see a connectivity check as if it were a media frame.
            if classify(payload) == PacketClass::Stun {
                match ice.classify(endpoint, source, payload, arrival) {
                    StunDisposition::Consumed { respond, adopt } => {
                        if let Some(response) = respond {
                            stun_responses.push((endpoint, source, response));
                        }
                        if let Some(adopted) = adopt {
                            adopt_source_in_kernel(&loader, &endpoints, endpoint, adopted);
                        }
                        continue;
                    }
                    // Not an ICE endpoint: fall through. A TURN allocation actor on a `Redirect`
                    // flow legitimately receives STUN-shaped bytes and must still get them.
                    StunDisposition::NotIce => {}
                }
            }

            let rx_packet = RxPacket {
                endpoint,
                source,
                arrival,
                data: Bytes::copy_from_slice(payload),
            };
            if redirect.send(rx_packet).is_err() {
                // No consumer; the whole datapath is being torn down.
                return;
            }
        }

        // Answer the connectivity checks the ice-lite responder validated. Deferred out of the RX
        // drain above because transmitting needs `&mut socket` while the burst borrows it.
        let answered = !stun_responses.is_empty();
        for (endpoint, destination, response) in stun_responses.drain(..) {
            let Some(local) = endpoints.get(&endpoint).map(|record| record.local_addr) else {
                continue;
            };
            let (done, _discard) = tokio::sync::oneshot::channel();
            let request = TxRequest {
                source: local,
                destination,
                data: response,
                done,
            };
            if let Err(error) = build_and_push(&mut socket, &request, &resolver, tos) {
                tracing::debug!(target: "siphon_rtp::datapath", ?endpoint, %error, "sending the STUN response failed");
            }
        }
        if answered {
            if let Err(error) = socket.tx_kick() {
                tracing::warn!(%error, "AF_XDP TX kick failed after a STUN response");
            }
        }

        // Drain the in-kernel RTCP tap ring (low-rate; a full drain each poll turn is timely — the
        // idle path below still wakes at least every 1 ms). Each record is a forwarded RTCP datagram
        // the `XDP_TX` fast path mirrored; turn it into an `ObservedRtcp` for the HEP QoS export.
        // Bounded try_send — drop on backpressure / no consumer, never block the datapath thread.
        if let Some(ring) = tap_ring.as_mut() {
            while let Some(item) = ring.next() {
                if let Some(record) = parse_tap_record(&item) {
                    if let Some(observed) = observed_rtcp_from_record(&record, &endpoints) {
                        let _ = observe.try_send(observed);
                    }
                }
            }
        }

        // Serve any pending TX requests (build the frame, push, kick).
        let mut transmitted = false;
        while let Ok(request) = tx_rx.try_recv() {
            let result = build_and_push(&mut socket, &request, &resolver, tos);
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
            // Idle: sweep stale next-hop MAC cache entries so the maps drain under churn-then-idle.
            resolver.reap();
            match tx_rx.recv_timeout(std::time::Duration::from_millis(1)) {
                Ok(request) => {
                    let result = build_and_push(&mut socket, &request, &resolver, tos);
                    let _ = request.done.send(result);
                    let _ = socket.tx_kick();
                }
                Err(flume::RecvTimeoutError::Disconnected) => return,
                Err(flume::RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

/// Build an Ethernet+IPv4+UDP frame for one TX request and push it onto the ring. Resolves the egress
/// source MAC and the next-hop destination MAC from the kernel via the [`NeighborResolver`] (a
/// synchronous cache read); on an unresolved next hop it **drops** the packet (returns `WouldBlock`)
/// and the resolver kicks off an off-thread lookup, so subsequent frames flow once ARP completes and
/// no frame ever egresses with a zeroed destination MAC.
fn build_and_push(
    socket: &mut xsk::XskSocket,
    request: &TxRequest,
    resolver: &NeighborResolver,
    tos: u8,
) -> Result<usize, DatapathError> {
    let (SocketAddr::V4(src), SocketAddr::V4(dst)) = (request.source, request.destination) else {
        // IPv4-only datapath; a v6 transport cannot be framed by the current ABI.
        return Err(DatapathError::Send(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "XDP datapath is IPv4-only",
        )));
    };
    // Resolve source + next-hop MACs (RFC 1122 §3.3.1 next hop, RFC 826 ARP). A miss drops this
    // packet — never forward into the void — while the resolver resolves it off-thread.
    let (src_mac, dst_mac) = match resolver.resolve(*dst.ip()) {
        Resolution::Resolved { src_mac, dst_mac } => (src_mac, dst_mac),
        Resolution::Pending => {
            return Err(DatapathError::Send(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "next-hop MAC unresolved; resolution requested",
            )));
        }
    };
    let addrs = headers::FrameAddrs {
        src_mac,
        dst_mac,
        src_ip: *src.ip(),
        dst_ip: *dst.ip(),
        src_port: src.port(),
        dst_port: dst.port(),
        tos,
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

/// Reinterpret one `RTCP_TAP` ring-buffer entry's bytes as the [`RtcpTapRecord`] the kernel wrote.
/// `None` if the slot is shorter than the record (never expected — the kernel reserves exactly one
/// record per submit). Pure and NIC-free: unit-tested by round-tripping a byte image of a record.
///
/// Safety: [`RtcpTapRecord`] is a `#[repr(C)]` POD of integers + a byte array, so every bit pattern is
/// a valid value; the length check guarantees the read stays in-bounds. `read_unaligned` because a
/// ring slot carries no alignment guarantee for our type.
fn parse_tap_record(bytes: &[u8]) -> Option<RtcpTapRecord> {
    if bytes.len() < std::mem::size_of::<RtcpTapRecord>() {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const RtcpTapRecord) })
}

/// Turn one kernel-tapped RTCP record into an [`ObservedRtcp`] for the telemetry export, resolving the
/// owning [`EndpointId`] from the record's engine-local (ingress) transport. `None` when the endpoint
/// is unknown (torn down between tap and drain) or the record's `payload_len` is out of range. All
/// record transport fields are host order (the [`RtcpTapRecord`] ABI), so `Ipv4Addr::from` and the raw
/// port reconstruct each [`SocketAddr`] directly. Pure — unit-tested with a synthetic record + a
/// populated endpoint registry, no NIC needed.
fn observed_rtcp_from_record(
    record: &RtcpTapRecord,
    endpoints: &DashMap<EndpointId, EndpointRecord>,
) -> Option<ObservedRtcp> {
    let payload_len = record.payload_len as usize;
    if payload_len == 0 || payload_len > RTCP_TAP_MAX_PAYLOAD {
        return None;
    }
    let local = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(record.local_ipv4)),
        record.local_port,
    );
    let endpoint = endpoint_for(endpoints, local)?;
    let source = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(record.source_ipv4)),
        record.source_port,
    );
    let destination = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(record.dest_ipv4)),
        record.dest_port,
    );
    Some(ObservedRtcp {
        endpoint,
        source,
        destination,
        payload: Bytes::copy_from_slice(&record.payload[..payload_len]),
    })
}

impl Datapath for XdpDatapath {
    async fn alloc_endpoint(&self) -> Result<Endpoint, DatapathError> {
        self.alloc_endpoint_on_ipv4(self.inner.local_ip)
    }

    async fn alloc_endpoint_on(&self, bind_ip: IpAddr) -> Result<Endpoint, DatapathError> {
        match bind_ip {
            // A named-interface source IP on the attached NIC: bind/emit the leg from it.
            IpAddr::V4(ipv4) => self.alloc_endpoint_on_ipv4(ipv4),
            // The XDP fast path is IPv4-only (one attached NIC); a v6 interface address cannot be
            // sourced here, so fall back to the configured default rather than the wrong family.
            IpAddr::V6(_) => self.alloc_endpoint_on_ipv4(self.inner.local_ip),
        }
    }

    fn install_flow(
        &self,
        endpoint: EndpointId,
        action: DpFlowAction,
    ) -> Result<(), DatapathError> {
        let record = match self.inner.endpoints.get(&endpoint) {
            Some(record) => *record,
            None => return Err(DatapathError::UnknownEndpoint(endpoint)),
        };
        // queue 0: single media RX queue for the first cut (the eBPF program redirects to the
        // socket bound on queue 0). Multi-queue spreads across redirect_queue per endpoint later.
        let mut kernel_action =
            to_kernel_action(action, &self.inner.endpoints, self.inner.local_ip, 0);
        // Re-stamp the ICE posture: a flow is reinstalled whenever the answer or destination changes
        // (and on an RFC 8445 §9 restart), and a rebuilt action would otherwise drop the flag and the
        // adopted source — silently reverting an ICE leg to the signalled-source gate mid-call.
        apply_ice_posture(
            &mut kernel_action,
            self.inner.ice.contains_key(&endpoint),
            self.inner.ice_adopted.get(&endpoint).map(|entry| *entry),
        );
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
        self.inner.ice_agents.remove(&endpoint);
        self.inner.ice_adopted.remove(&endpoint);
        self.inner.ice_last_check.remove(&endpoint);
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
        done_rx.await.map_err(|_| {
            DatapathError::Send(std::io::Error::other("datapath thread dropped reply"))
        })?
    }

    fn stats(&self, endpoint: EndpointId) -> Option<EndpointStats> {
        // Per-endpoint counters from the kernel's per-flow FLOW_STATS map (Stage 3a). The flow_key
        // copies out before the loader lock so no DashMap guard is held across it. An endpoint with no
        // traffic yet has no map entry → report zeros (it exists, just idle), never `None`.
        let key = self.inner.endpoints.get(&endpoint)?.flow_key;
        let loader = self
            .inner
            .loader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let totals = loader.flow_stats(key).ok()?.unwrap_or_default();
        Some(EndpointStats {
            packets_in: totals.packets_in,
            packets_out: totals.packets_out,
            bytes_in: totals.bytes_in,
            bytes_out: totals.bytes_out,
            packets_dropped: totals.packets_dropped,
            packets_lost: totals.packets_lost,
        })
    }

    fn now_ticks(&self) -> u64 {
        // XDP runs on a real NIC (not the deterministic CI loopback datapath), so its clock is
        // wall-clock elapsed, NOT the logical sweep clock. Reporting real-time ticks since the
        // construction origin puts now_ticks() in the SAME domain as last_activity()
        // (kernel_ns_to_tick against start_ktime_ns), so the media-timeout sweep's
        // now_ticks() - last_activity() is a real elapsed-tick count (docs/security-and-nat.md §4
        // layer 6). The `Datapath::advance_clock` default is a no-op for this backend — the sweep
        // does not drive a real-time clock (RFC 3550 §6.4.1 monotonic clock).
        kernel_ns_to_tick(monotonic_ns(), self.inner.start_ktime_ns)
    }

    fn now_micros(&self) -> u64 {
        // The same real-time clock the RX thread stamps arrival from, so a participant's packet
        // arrival and its reception report's "now" (for DLSR) are read on one clock (RFC 3550 §6.4.1).
        self.inner.start.elapsed().as_micros() as u64
    }

    fn last_activity(&self, endpoint: EndpointId) -> Option<u64> {
        // Kernel-fed activity (Stage 3a): the classifier stamps FlowStats::last_seen_ns
        // (bpf_ktime_get_ns) on every accepted packet — for the in-kernel Forward relay *and* the
        // Redirect path, so this works even for flows userspace never sees. Map that CLOCK_MONOTONIC
        // ns into the logical tick domain relative to the construction origin. Endpoint unknown →
        // `None`; known but no packet yet → tick 0. `note_activity` stays the default no-op: the
        // kernel is the single source of truth for XDP activity (no userspace double-stamp).
        let key = self.inner.endpoints.get(&endpoint)?.flow_key;
        let loader = self
            .inner
            .loader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let last_seen_ns = loader
            .flow_stats(key)
            .ok()
            .flatten()
            .map_or(0, |stats| stats.last_seen_ns);
        let media_tick = kernel_ns_to_tick(last_seen_ns, self.inner.start_ktime_ns);
        // Fold in the last validated ICE check. The kernel stamps only accepted *media*, so on an ICE
        // leg that has not started media yet — the whole establishment window, and a held leg kept
        // alive by consent checks — the kernel stamp alone would read as idle and the sweep would reap
        // a live path. The loopback backend's responder stamps the same counter media does, so taking
        // the later of the two is what keeps the two backends agreeing.
        let check_tick = self
            .inner
            .ice_last_check
            .get(&endpoint)
            .map_or(0, |entry| *entry);
        Some(media_tick.max(check_tick))
    }

    fn learned_source(&self, endpoint: EndpointId) -> Option<std::net::SocketAddr> {
        // Mirror the kernel's own validated latch (symmetric RTP, RFC 3550 §8) into the trait so the
        // engine can propagate it to the sibling leg's `out_dst` (docs/security-and-nat.md §4 layer 3).
        // Only a source the kernel already latched (source-gate + SSRC re-latch passed) is exposed, so
        // no unvalidated source ever reaches the engine — the RTPBleed invariant holds.
        self.learned_latch(endpoint)
            .map(|latch| std::net::SocketAddr::V4(latch.source))
    }

    fn set_ice(&self, endpoint: EndpointId, config: Option<IceConfig>) {
        match config {
            Some(config) => {
                self.inner.ice.insert(endpoint, config);
            }
            None => {
                self.inner.ice.remove(&endpoint);
                self.inner.ice_agents.remove(&endpoint);
                self.inner.ice_adopted.remove(&endpoint);
                self.inner.ice_last_check.remove(&endpoint);
            }
        }
        // Flip the kernel flow's ICE byte. That is what makes the classifier redirect STUN here
        // instead of dropping it, and gate media on the adopted source instead of the signalled one —
        // without it the credentials would be a userspace map nothing enforces.
        self.set_kernel_ice_flag(endpoint);
    }

    fn set_ice_agent(
        &self,
        endpoint: EndpointId,
        config: IceConfig,
        mode: IceAgentMode,
        events: flume::Sender<IceDatapathEvent>,
    ) {
        self.inner
            .ice_agents
            .insert(endpoint, IceAgentRegistration { mode, events });
        // Installs the credentials and flips the kernel flag; a `ForwardOnly` endpoint keeps the
        // credentials because the *engine's* agent verifies with them — the datapath just stops
        // answering (see `IceDemux::classify`).
        self.set_ice(endpoint, Some(config));
    }

    fn ice_validated_source(&self, endpoint: EndpointId) -> Option<SocketAddr> {
        // The userspace record of what ICE adopted — deliberately not `learned_latch`, which reports
        // the *media* latch and on a non-ICE flow would hand back a blind-latched source as though a
        // check had authenticated it.
        self.inner.ice_adopted.get(&endpoint).map(|entry| *entry)
    }

    fn adopt_source(&self, endpoint: EndpointId, source: SocketAddr) {
        self.inner.ice_adopted.insert(endpoint, source);
        adopt_source_in_kernel(&self.inner.loader, &self.inner.endpoints, endpoint, source);
    }

    fn rx(&self) -> flume::Receiver<RxPacket> {
        self.inner.redirect_rx.clone()
    }

    fn observe_rtcp(&self) -> flume::Receiver<ObservedRtcp> {
        // Fed by the in-kernel RTCP copy-to-userspace tap: the `XDP_TX` Forward fast path mirrors every
        // forwarded RTCP datagram into the `RTCP_TAP` ring, and the datapath thread drains it into this
        // bounded stream (`observed_rtcp_from_record`), so a kernelized relay's RTCP reaches the HEP QoS
        // export exactly like the userspace-redirected path.
        self.inner.observe_rx.clone()
    }
}

/// Whether this host can load + attach XDP — else the engine selects the UDP-loopback backend.
///
/// Definitive probe: try to load and SKB-attach the program to the loopback interface. A lighter
/// probe (CAP_BPF/CAP_NET_ADMIN + kernel ≥ 5.10) can replace this once the loader is hot-pathed.
#[must_use]
pub fn xdp_supported() -> bool {
    Loader::load("lo", AttachMode::Skb, Dscp::DEFAULT).is_ok()
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
        let kernel = to_kernel_action(
            DpFlowAction::Drop,
            &empty_endpoints(),
            Ipv4Addr::LOCALHOST,
            0,
        );
        assert_eq!(kernel.kind, action::DROP);
    }

    #[test]
    fn redirect_action_maps_to_kernel_redirect_with_queue() {
        let kernel = to_kernel_action(
            DpFlowAction::Redirect,
            &empty_endpoints(),
            Ipv4Addr::LOCALHOST,
            3,
        );
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
    fn forward_tx_source_is_the_peer_per_leg_bind_ip_not_the_datapath_default() {
        // Named-interface per-leg source IP: the egress peer was allocated (via `alloc_endpoint_on`)
        // on the `external` interface IP 203.0.113.5, which differs from the datapath's default
        // `local_ip` 198.51.100.1. The kernel `FlowAction` must transmit from the peer's *per-leg*
        // source IP, so a two-interface XDP relay sources each leg from its own interface address —
        // with no eBPF change (the field was already carried; only the bound IP became per-leg).
        let endpoints = empty_endpoints();
        let peer = EndpointId(7);
        endpoints.insert(
            peer,
            EndpointRecord {
                local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 30500),
                flow_key: FlowKey {
                    local_ipv4: u32::from_be_bytes([203, 0, 113, 5]),
                    local_port: 30500u16.to_be(),
                    _pad: 0,
                },
            },
        );
        let rule = ForwardRule::signalled(
            peer,
            Some("198.51.100.9:8000".parse().expect("addr")),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        );
        let kernel = to_kernel_action(
            DpFlowAction::Forward(rule),
            &endpoints,
            Ipv4Addr::new(198, 51, 100, 1), // datapath default — must NOT be used for this leg
            0,
        );
        assert_eq!(
            kernel.out_local_ipv4,
            u32::from_be_bytes([203, 0, 113, 5]),
            "TX sources from the peer's per-leg interface IP, not the datapath default"
        );
        assert_eq!(kernel.out_src_port, 30500u16.to_be());
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

    // --- Stage 3a pure helpers: NIC-free, deterministic (injected values, never `Instant::now()`). ---

    #[test]
    fn kernel_ns_to_tick_maps_relative_to_origin() {
        let origin = 5_000_000_000; // 5 s since boot (CLOCK_MONOTONIC)
                                    // 60 ms after the origin = 3 ticks of 20 ms.
        assert_eq!(kernel_ns_to_tick(origin + 60_000_000, origin), 3);
        // Exactly one tick.
        assert_eq!(kernel_ns_to_tick(origin + NS_PER_TICK, origin), 1);
        // Sub-tick rounds down (floor division): 19.999 ms is still tick 0.
        assert_eq!(kernel_ns_to_tick(origin + NS_PER_TICK - 1, origin), 0);
    }

    #[test]
    fn kernel_ns_to_tick_zero_stamp_is_tick_zero() {
        // No packet accepted yet (never stamped) → tick 0, regardless of the origin.
        assert_eq!(kernel_ns_to_tick(0, 12_345), 0);
    }

    #[test]
    fn kernel_ns_to_tick_before_origin_saturates() {
        // A stamp earlier than the origin (must not underflow) → tick 0.
        assert_eq!(kernel_ns_to_tick(100, 5_000_000_000), 0);
    }

    #[allow(clippy::too_many_arguments)]
    fn flow_stats(
        packets_in: u64,
        packets_out: u64,
        bytes_in: u64,
        bytes_out: u64,
        packets_dropped: u64,
        last_seen_ns: u64,
        packets_lost: u64,
        last_rtp_seq: u64,
    ) -> FlowStats {
        FlowStats {
            packets_in,
            packets_out,
            bytes_in,
            bytes_out,
            packets_dropped,
            last_seen_ns,
            packets_lost,
            last_rtp_seq,
        }
    }

    #[test]
    fn sum_flow_stats_sums_counters_and_maxes_last_seen() {
        let per_cpu = [
            flow_stats(3, 2, 300, 200, 1, 10, 4, 100),
            flow_stats(4, 5, 400, 500, 0, 99, 5, 200),
            flow_stats(0, 0, 0, 0, 2, 50, 6, 300),
        ];
        let total = sum_flow_stats(per_cpu);
        assert_eq!(total.packets_in, 7);
        assert_eq!(total.packets_out, 7);
        assert_eq!(total.bytes_in, 700);
        assert_eq!(total.bytes_out, 700);
        assert_eq!(total.packets_dropped, 3);
        // last_seen_ns is a timestamp → max across CPUs, not a sum.
        assert_eq!(total.last_seen_ns, 99);
        // packets_lost is a summable counter → summed across CPUs.
        assert_eq!(total.packets_lost, 15);
        // last_rtp_seq is per-CPU internal loss-estimator state → left 0 in the aggregate.
        assert_eq!(total.last_rtp_seq, 0);
    }

    #[test]
    fn sum_flow_stats_of_empty_is_zero() {
        assert_eq!(sum_flow_stats(std::iter::empty()), FlowStats::default());
    }

    /// A `FORWARD` action carrying a latched peer (host-order fields, as the kernel writes them).
    fn latched_action(latch_valid: u8) -> FlowAction {
        FlowAction {
            kind: action::FORWARD,
            latch_policy: latch::SYMMETRIC,
            source_kind: source::ANY,
            source_prefix: 0,
            source_ipv4: 0,
            out_ipv4: 0,
            out_local_ipv4: 0,
            out_port: 0,
            out_src_port: 0,
            // Host order: from_be_bytes of the wire address/port (198.51.100.10:5000).
            latched_ipv4: u32::from_be_bytes([198, 51, 100, 10]),
            latched_ssrc: 0xDEAD_BEEF,
            latched_port: 5000,
            latch_valid,
            ice: 0,
            redirect_queue: 0,
        }
    }

    #[test]
    fn learned_latch_extracts_host_order_transport_when_valid() {
        let extracted = learned_latch_from_action(&latched_action(1)).expect("valid latch");
        assert_eq!(
            extracted.source,
            "198.51.100.10:5000".parse::<SocketAddrV4>().expect("addr")
        );
        assert_eq!(extracted.ssrc, 0xDEAD_BEEF);
    }

    #[test]
    fn learned_latch_is_none_when_not_valid() {
        // latch_valid == 0 means nothing learned yet, even with stale latched_* bytes present.
        assert_eq!(learned_latch_from_action(&latched_action(0)), None);
    }

    #[test]
    fn learned_source_maps_a_valid_latch_to_a_socket_addr_v4() {
        // `Datapath::learned_source` is `learned_latch(..).map(|l| SocketAddr::V4(l.source))`. A real
        // `XdpDatapath` needs a NIC + kernel, so exercise that exact mapping over the shared fixture:
        // a valid latch maps to the V4 socket address; an invalid one maps to `None`.
        let mapped =
            learned_latch_from_action(&latched_action(1)).map(|l| SocketAddr::V4(l.source));
        assert_eq!(
            mapped,
            Some("198.51.100.10:5000".parse::<SocketAddr>().expect("addr"))
        );
        assert_eq!(
            learned_latch_from_action(&latched_action(0)).map(|l| SocketAddr::V4(l.source)),
            None
        );
    }

    // --- ICE parity (RFC 8445 on the kernel datapath) --------------------------------------------

    const ICE_ENDPOINT: EndpointId = EndpointId(7);
    const PEER: &str = "198.51.100.10:5000";

    fn ice_config() -> IceConfig {
        IceConfig {
            local_ufrag: "engineUfrag".to_string(),
            local_pwd: "enginePasswordThatIsLongEnough".to_string(),
        }
    }

    /// A real MESSAGE-INTEGRITY-signed Binding request addressed to `ice_config()` — built by the
    /// STUN encoder, not hand-rolled, so the responder is exercised against a genuine check.
    fn signed_check(config: &IceConfig) -> Vec<u8> {
        siphon_rtp_stun::binding_request(
            &[1u8; 12],
            &format!("{}:peerUfrag", config.local_ufrag),
            config.local_pwd.as_bytes(),
        )
    }

    fn demux() -> IceDemux {
        IceDemux {
            ice: Arc::new(DashMap::new()),
            ice_agents: Arc::new(DashMap::new()),
            adopted: Arc::new(DashMap::new()),
            last_check: Arc::new(DashMap::new()),
        }
    }

    fn peer() -> SocketAddr {
        PEER.parse().expect("addr")
    }

    #[test]
    fn stun_on_a_non_ice_endpoint_stays_on_the_redirect_path() {
        // A TURN allocation actor sits on a `Redirect` flow and legitimately receives STUN-shaped
        // bytes; the ICE demux must not swallow them.
        let demux = demux();
        let disposition = demux.classify(ICE_ENDPOINT, peer(), &signed_check(&ice_config()), 0);
        assert_eq!(disposition, StunDisposition::NotIce);
    }

    #[test]
    fn ice_lite_endpoint_answers_a_valid_check_and_adopts_its_source() {
        let demux = demux();
        let config = ice_config();
        demux.ice.insert(ICE_ENDPOINT, config.clone());

        let StunDisposition::Consumed { respond, adopt } =
            demux.classify(ICE_ENDPOINT, peer(), &signed_check(&config), 0)
        else {
            panic!("an ICE endpoint must consume STUN");
        };
        let response = respond.expect("a valid check is answered");
        assert!(siphon_rtp_stun::verify_message_integrity(
            &response,
            config.local_pwd.as_bytes()
        ));
        assert_eq!(adopt, Some(peer()));
        assert_eq!(demux.adopted.get(&ICE_ENDPOINT).map(|e| *e), Some(peer()));
    }

    #[test]
    fn a_repeated_check_from_the_same_source_reports_no_new_adoption() {
        // Checks repeat for the life of the call (RFC 7675 consent). Re-reporting the adoption every
        // time would rewrite the kernel map on every check for no change.
        let demux = demux();
        let config = ice_config();
        demux.ice.insert(ICE_ENDPOINT, config.clone());
        let check = signed_check(&config);

        let first = demux.classify(ICE_ENDPOINT, peer(), &check, 0);
        assert!(matches!(
            first,
            StunDisposition::Consumed { adopt: Some(_), .. }
        ));
        let second = demux.classify(ICE_ENDPOINT, peer(), &check, 1);
        assert!(matches!(
            second,
            StunDisposition::Consumed { adopt: None, .. }
        ));
    }

    #[test]
    fn an_unauthenticated_check_is_dropped_and_adopts_nothing() {
        // The RTPbleed-class case: an off-path sender who never saw the SDP cannot move the path.
        let demux = demux();
        let config = ice_config();
        demux.ice.insert(ICE_ENDPOINT, config.clone());
        let forged = siphon_rtp_stun::binding_request(
            &[2u8; 12],
            &format!("{}:peerUfrag", config.local_ufrag),
            b"the-wrong-password",
        );

        let disposition = demux.classify(ICE_ENDPOINT, peer(), &forged, 0);
        assert_eq!(
            disposition,
            StunDisposition::Consumed {
                respond: None,
                adopt: None
            }
        );
        assert!(demux.adopted.get(&ICE_ENDPOINT).is_none());
    }

    #[test]
    fn a_full_agent_endpoint_forwards_the_check_and_answers_nothing_itself() {
        // RFC 8445: answering needs the role, the checklist and the nomination state, none of which
        // the datapath has. It must forward and stay out of the way — including not adopting, or it
        // would pin the media path behind the agent's back.
        let demux = demux();
        let config = ice_config();
        let (events, received) = flume::unbounded();
        demux.ice.insert(ICE_ENDPOINT, config.clone());
        demux.ice_agents.insert(
            ICE_ENDPOINT,
            IceAgentRegistration {
                mode: IceAgentMode::ForwardOnly,
                events,
            },
        );
        let check = signed_check(&config);

        let disposition = demux.classify(ICE_ENDPOINT, peer(), &check, 42);
        assert_eq!(
            disposition,
            StunDisposition::Consumed {
                respond: None,
                adopt: None
            }
        );
        assert!(demux.adopted.get(&ICE_ENDPOINT).is_none());

        let event = received.try_recv().expect("the agent is handed the check");
        assert_eq!(event.endpoint, ICE_ENDPOINT);
        assert_eq!(event.source, peer());
        assert_eq!(event.arrival_tick, 42);
        assert_eq!(event.datagram.as_ref(), check.as_slice());
    }

    #[test]
    fn a_respond_and_forward_endpoint_both_forwards_and_answers() {
        // The ice-lite + RFC 7675 consent posture: the datapath still answers, and the agent still
        // sees every datagram so it can correlate the Binding *responses* to its own checks.
        let demux = demux();
        let config = ice_config();
        let (events, received) = flume::unbounded();
        demux.ice.insert(ICE_ENDPOINT, config.clone());
        demux.ice_agents.insert(
            ICE_ENDPOINT,
            IceAgentRegistration {
                mode: IceAgentMode::RespondAndForward,
                events,
            },
        );

        let StunDisposition::Consumed { respond, adopt } =
            demux.classify(ICE_ENDPOINT, peer(), &signed_check(&config), 0)
        else {
            panic!("an ICE endpoint must consume STUN");
        };
        assert!(respond.is_some());
        assert_eq!(adopt, Some(peer()));
        assert!(received.try_recv().is_ok());
    }

    #[test]
    fn a_validated_check_counts_as_activity_for_the_media_timeout_sweep() {
        // The kernel stamps `last_seen_ns` only on accepted media, so without this an ICE leg still
        // establishing — or held, exchanging only consent checks — would look idle and be reaped.
        let demux = demux();
        let config = ice_config();
        demux.ice.insert(ICE_ENDPOINT, config.clone());

        demux.classify(ICE_ENDPOINT, peer(), &signed_check(&config), 4_200);
        assert_eq!(
            demux.last_check.get(&ICE_ENDPOINT).map(|e| *e),
            Some(4_200),
            "an authenticated check stamps activity, as the loopback responder does"
        );
    }

    #[test]
    fn an_unauthenticated_check_does_not_count_as_activity() {
        // Otherwise anyone able to send STUN-shaped bytes could hold a dead path open forever.
        let demux = demux();
        let config = ice_config();
        demux.ice.insert(ICE_ENDPOINT, config.clone());
        let forged = siphon_rtp_stun::binding_request(
            &[3u8; 12],
            &format!("{}:peerUfrag", config.local_ufrag),
            b"the-wrong-password",
        );

        demux.classify(ICE_ENDPOINT, peer(), &forged, 4_200);
        assert!(demux.last_check.get(&ICE_ENDPOINT).is_none());
    }

    #[test]
    fn ice_posture_gates_media_closed_until_a_source_is_adopted() {
        // The whole point of the layer-4 gate: an ICE flow with nothing adopted forwards nothing,
        // rather than blind-latching the first RTP sender to arrive.
        let mut action = latched_action(0);
        apply_ice_posture(&mut action, true, None);
        assert_eq!(action.ice, 1);
        assert_eq!(action.latch_valid, 0);
        assert!(!siphon_rtp_ebpf_common::rewrite::ice_media_allowed(
            learned_latch_from_action(&action).map(|l| siphon_rtp_ebpf_common::rewrite::Latched {
                ipv4: u32::from_be_bytes(l.source.ip().octets()),
                port: l.source.port(),
                ssrc: l.ssrc,
            }),
            u32::from_be_bytes([198, 51, 100, 10]),
            5000,
        ));
    }

    #[test]
    fn ice_posture_writes_the_adopted_source_into_the_kernel_gate() {
        let mut action = latched_action(0);
        apply_ice_posture(&mut action, true, Some(peer()));
        assert_eq!(action.ice, 1);
        assert_eq!(action.latch_valid, 1);
        assert_eq!(action.latched_ipv4, u32::from_be_bytes([198, 51, 100, 10]));
        assert_eq!(action.latched_port, 5000);
        // The classifier's gate now admits exactly that transport and nothing else.
        let latched = siphon_rtp_ebpf_common::rewrite::Latched {
            ipv4: action.latched_ipv4,
            port: action.latched_port,
            ssrc: action.latched_ssrc,
        };
        assert!(siphon_rtp_ebpf_common::rewrite::ice_media_allowed(
            Some(latched),
            u32::from_be_bytes([198, 51, 100, 10]),
            5000
        ));
        assert!(!siphon_rtp_ebpf_common::rewrite::ice_media_allowed(
            Some(latched),
            u32::from_be_bytes([198, 51, 100, 11]),
            5000
        ));
    }

    #[test]
    fn a_redirect_flow_carries_the_ice_posture_the_classifier_gates_on() {
        // The classifier's REDIRECT arm applies the same layer-4 gate as its FORWARD arm
        // (docs/security-and-nat.md §4 layer 4), so a redirected ICE endpoint — a conference seat, a
        // promoted call, an SRTP/DTLS bridge leg — must reach the kernel carrying the flag *and* the
        // adopted source. `to_kernel_action` builds no gate fields for a Redirect action, so this is
        // entirely `apply_ice_posture`'s job on the install path; without it the arm would have
        // nothing to compare against and would hand userspace every source.
        let mut action = to_kernel_action(
            DpFlowAction::Redirect,
            &empty_endpoints(),
            Ipv4Addr::LOCALHOST,
            0,
        );
        assert_eq!(action.ice, 0, "a plain redirect leg is not ICE-gated");
        assert_eq!(action.latch_valid, 0);

        apply_ice_posture(&mut action, true, Some(peer()));
        assert_eq!(action.kind, action::REDIRECT, "still a redirect flow");
        assert_eq!(action.ice, 1);
        let latched = siphon_rtp_ebpf_common::rewrite::Latched {
            ipv4: action.latched_ipv4,
            port: action.latched_port,
            ssrc: action.latched_ssrc,
        };
        assert!(siphon_rtp_ebpf_common::rewrite::ice_media_allowed(
            Some(latched),
            u32::from_be_bytes([198, 51, 100, 10]),
            5000
        ));
        assert!(
            !siphon_rtp_ebpf_common::rewrite::ice_media_allowed(
                Some(latched),
                u32::from_be_bytes([198, 51, 100, 11]),
                5000
            ),
            "an unvalidated source is gated out of the redirect path too"
        );
    }

    #[test]
    fn a_non_ice_flow_keeps_its_kernel_owned_media_latch() {
        // `apply_ice_posture` runs on every flow install, so it must leave a plain relay's
        // symmetric-RTP latch — which the kernel owns and updates — completely alone.
        let mut action = latched_action(1);
        let before = action;
        apply_ice_posture(&mut action, false, None);
        assert_eq!(action.ice, 0);
        assert_eq!(action.latched_ipv4, before.latched_ipv4);
        assert_eq!(action.latched_port, before.latched_port);
        assert_eq!(action.latched_ssrc, before.latched_ssrc);
        assert_eq!(action.latch_valid, 1);
    }

    #[test]
    fn an_ipv6_adoption_leaves_the_ipv4_gate_closed_rather_than_half_written() {
        // The kernel ABI is IPv4-only. Writing a truncated v6 address would open the gate to a
        // transport nobody adopted, so the flag goes on and the gate stays shut.
        let mut action = latched_action(1);
        apply_ice_posture(
            &mut action,
            true,
            Some("[2001:db8::1]:5000".parse().expect("addr")),
        );
        assert_eq!(action.ice, 1);
        assert_eq!(action.latch_valid, 0);
        assert_eq!(action.latched_ipv4, 0);
    }

    #[test]
    fn monotonic_ns_is_available_and_nondecreasing() {
        // A sanity check of the CLOCK_MONOTONIC wrapper (not a timing-driven logic path): the clock is
        // available (nonzero) and never runs backwards between two consecutive reads.
        let first = monotonic_ns();
        let second = monotonic_ns();
        assert!(first > 0, "CLOCK_MONOTONIC should be available");
        assert!(second >= first, "monotonic clock must not go backwards");
    }

    #[test]
    fn now_ticks_is_real_time_monotonic_and_coherent_with_last_activity() {
        // `XdpDatapath::now_ticks` is `kernel_ns_to_tick(monotonic_ns(), start_ktime_ns)` and
        // `last_activity` is `kernel_ns_to_tick(last_seen_ns, start_ktime_ns)` — both map a
        // CLOCK_MONOTONIC ns reading through the SAME conversion against the SAME construction origin.
        // This reproduces that exact arithmetic NIC-free (building an `XdpDatapath` needs an AF_XDP
        // bind), asserting the two properties the media-timeout sweep relies on, WITHOUT a sleep:
        //   1. now_ticks is monotonic non-decreasing across reads (CLOCK_MONOTONIC, RFC 3550 §6.4.1);
        //   2. now_ticks never precedes a flow stamped "just now", so `now_ticks - last_activity`
        //      (docs/security-and-nat.md §4 layer 6) is a real, non-underflowing elapsed-tick count.
        let origin = monotonic_ns();
        // A flow whose kernel `last_seen_ns` was stamped at (approximately) now.
        let last_seen_ns = monotonic_ns();
        let last_activity = kernel_ns_to_tick(last_seen_ns, origin);
        // now_ticks() sampled after the stamp: same domain, same origin.
        let now_first = kernel_ns_to_tick(monotonic_ns(), origin);
        let now_second = kernel_ns_to_tick(monotonic_ns(), origin);
        assert!(
            now_second >= now_first,
            "now_ticks must be monotonic non-decreasing"
        );
        assert!(
            now_first >= last_activity,
            "now_ticks must not precede a just-stamped last_activity (no sweep underflow)"
        );
    }

    // --- RTCP copy-to-userspace tap: the pure record -> ObservedRtcp reconstruction (NIC-free). -----

    /// A synthetic tap record with host-order transports (as the kernel writes them) and `payload_len`
    /// bytes of `payload`.
    fn tap_record(
        local: SocketAddrV4,
        source: SocketAddrV4,
        destination: SocketAddrV4,
        payload_bytes: &[u8],
    ) -> RtcpTapRecord {
        let mut record = RtcpTapRecord::zeroed();
        record.local_ipv4 = u32::from(*local.ip());
        record.local_port = local.port();
        record.source_ipv4 = u32::from(*source.ip());
        record.source_port = source.port();
        record.dest_ipv4 = u32::from(*destination.ip());
        record.dest_port = destination.port();
        record.payload[..payload_bytes.len()].copy_from_slice(payload_bytes);
        record.payload_len = payload_bytes.len() as u16;
        record
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
    }

    #[test]
    fn parse_tap_record_roundtrips_a_record_image() {
        // A ring slot is a verbatim byte image of the `#[repr(C)]` record; `parse_tap_record` reads it
        // back field-for-field, so the kernel emit and userspace read agree.
        let record = tap_record(
            v4(198, 51, 100, 1, 30000),
            v4(203, 0, 113, 9, 7000),
            v4(198, 51, 100, 9, 8000),
            &[0x80, 0xC8, 0x00, 0x06],
        );
        let bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(&record).cast::<u8>(),
                std::mem::size_of::<RtcpTapRecord>(),
            )
        };
        let parsed = parse_tap_record(bytes).expect("full-length slot parses");
        assert_eq!(parsed.local_ipv4, record.local_ipv4);
        assert_eq!(parsed.local_port, record.local_port);
        assert_eq!(parsed.source_ipv4, record.source_ipv4);
        assert_eq!(parsed.source_port, record.source_port);
        assert_eq!(parsed.dest_ipv4, record.dest_ipv4);
        assert_eq!(parsed.dest_port, record.dest_port);
        assert_eq!(parsed.payload_len, 4);
        assert_eq!(&parsed.payload[..4], &[0x80, 0xC8, 0x00, 0x06]);
    }

    #[test]
    fn parse_tap_record_rejects_a_short_slice() {
        // A slot shorter than the record (never expected — the kernel reserves exactly one) is refused
        // rather than reading out of bounds.
        assert!(parse_tap_record(&[0u8; 8]).is_none());
        assert!(parse_tap_record(&[]).is_none());
    }

    #[test]
    fn observed_rtcp_from_record_resolves_endpoint_and_transports() {
        // The engine-local transport resolves the owning endpoint; source/destination and the RTCP
        // payload reconstruct directly from the host-order record fields.
        let endpoints = empty_endpoints();
        let owner = EndpointId(5);
        let local = v4(198, 51, 100, 1, 30000);
        endpoints.insert(
            owner,
            EndpointRecord {
                local_addr: SocketAddr::V4(local),
                flow_key: FlowKey {
                    local_ipv4: u32::from_be_bytes([198, 51, 100, 1]),
                    local_port: 30000u16.to_be(),
                    _pad: 0,
                },
            },
        );
        // A minimal RTCP sender report prefix (V=2, PT=200) — the bytes are opaque to the tap.
        let payload = [0x80, 0xC8, 0x00, 0x06, 0xDE, 0xAD, 0xBE, 0xEF];
        let record = tap_record(
            local,
            v4(203, 0, 113, 9, 7000),
            v4(198, 51, 100, 9, 8000),
            &payload,
        );

        let observed = observed_rtcp_from_record(&record, &endpoints).expect("resolves");
        assert_eq!(observed.endpoint, owner);
        assert_eq!(
            observed.source,
            "203.0.113.9:7000".parse::<SocketAddr>().expect("addr")
        );
        assert_eq!(
            observed.destination,
            "198.51.100.9:8000".parse::<SocketAddr>().expect("addr")
        );
        assert_eq!(&observed.payload[..], &payload[..]);
    }

    #[test]
    fn observed_rtcp_from_record_unknown_endpoint_is_none() {
        // The endpoint was torn down between the kernel tap and the userspace drain: no observation.
        let endpoints = empty_endpoints();
        let record = tap_record(
            v4(198, 51, 100, 1, 30000),
            v4(203, 0, 113, 9, 7000),
            v4(198, 51, 100, 9, 8000),
            &[0x80, 0xC8, 0x00, 0x06],
        );
        assert!(observed_rtcp_from_record(&record, &endpoints).is_none());
    }

    #[test]
    fn observed_rtcp_from_record_rejects_out_of_range_payload_len() {
        // A record with an implausible length is dropped, never indexing past the payload buffer.
        let endpoints = empty_endpoints();
        let local = v4(198, 51, 100, 1, 30000);
        endpoints.insert(
            EndpointId(1),
            EndpointRecord {
                local_addr: SocketAddr::V4(local),
                flow_key: FlowKey {
                    local_ipv4: 0,
                    local_port: 0,
                    _pad: 0,
                },
            },
        );
        let mut record = tap_record(
            local,
            v4(203, 0, 113, 9, 7000),
            v4(198, 51, 100, 9, 8000),
            &[0x80, 0xC8, 0x00, 0x06],
        );
        record.payload_len = 0;
        assert!(observed_rtcp_from_record(&record, &endpoints).is_none());
        record.payload_len = (RTCP_TAP_MAX_PAYLOAD + 1) as u16;
        assert!(observed_rtcp_from_record(&record, &endpoints).is_none());
    }
}
