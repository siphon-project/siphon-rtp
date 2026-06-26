//! The XDP/AF_XDP datapath backend (userspace loader).
//!
//! This crate is the kernel-acceleration counterpart of `siphon-rtp-datapath`'s UDP-loopback
//! backend, kept separate so the always-available backend never depends on aya/eBPF. It loads the
//! embedded XDP classifier ([`siphon-rtp-ebpf`]), attaches it to an interface, and drives the
//! `FLOWS` / `STATS` maps with the shared [`siphon_rtp_ebpf_common`] ABI.
//!
//! This first cut is the **control half**: load + attach + map management + capability detection.
//! The data half — AF_XDP sockets (the in-house `xsk.rs` ring/UMEM mechanics) and the full
//! [`siphon_rtp_datapath::Datapath`] trait impl (alloc_endpoint / take_rx / send, plus the
//! EndpointId↔transport mapping the kernel needs) — is the next layer.
//!
//! The ABI POD types live in the aya-free, no_std `siphon-rtp-ebpf-common`; here they are wrapped in
//! `#[repr(transparent)]` newtypes that impl [`aya::Pod`] (the orphan rule forbids impl'ing a
//! foreign trait on a foreign type, and keeping aya out of the shared crate keeps it off the
//! workspace's dependency graph).

use aya::maps::{HashMap as AyaHashMap, MapData, PerCpuArray};
use aya::programs::{Xdp, XdpFlags};
use aya::{Ebpf, Pod};

use siphon_rtp_ebpf_common::{FlowAction, FlowKey, FlowStats};

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
    #[error("attach XDP to {interface}: {source}")]
    Attach {
        /// The interface attach was attempted on.
        interface: String,
        /// The underlying error text.
        source: String,
    },
    /// A map operation failed.
    #[error("map {map}: {source}")]
    Map {
        /// The map name.
        map: &'static str,
        /// The underlying error text.
        source: String,
    },
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

/// A loaded XDP classifier attached to one interface, owning its maps.
pub struct XdpDatapath {
    ebpf: Ebpf,
    interface: String,
}

impl XdpDatapath {
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
                source: error.to_string(),
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

    /// Install (or replace) the flow rule for `key`.
    pub fn set_flow(&mut self, key: FlowKey, action: FlowAction) -> Result<(), XdpError> {
        self.flows()?
            .insert(PodKey(key), PodAction(action), 0)
            .map_err(|error| XdpError::Map {
                map: "FLOWS",
                source: error.to_string(),
            })
    }

    /// Remove the flow rule for `key` (subsequent matching packets `XDP_PASS`).
    pub fn remove_flow(&mut self, key: FlowKey) -> Result<(), XdpError> {
        self.flows()?
            .remove(&PodKey(key))
            .map_err(|error| XdpError::Map {
                map: "FLOWS",
                source: error.to_string(),
            })
    }

    /// Sum the per-CPU counters across all CPUs.
    pub fn stats(&self) -> Result<FlowStats, XdpError> {
        let stats: PerCpuArray<_, PodStats> = PerCpuArray::try_from(
            self.ebpf.map("STATS").ok_or_else(|| XdpError::Map {
                map: "STATS",
                source: "missing".to_string(),
            })?,
        )
        .map_err(|error| XdpError::Map {
            map: "STATS",
            source: error.to_string(),
        })?;

        let per_cpu = stats.get(&0, 0).map_err(|error| XdpError::Map {
            map: "STATS",
            source: error.to_string(),
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
            source: "missing".to_string(),
        })?)
        .map_err(|error| XdpError::Map {
            map: "FLOWS",
            source: error.to_string(),
        })
    }
}

/// Whether this host can load + attach XDP — else the engine selects the UDP-loopback backend.
///
/// Definitive probe: try to load and SKB-attach the program to the loopback interface. A lighter
/// probe (CAP_BPF/CAP_NET_ADMIN + kernel ≥ 5.10) can replace this once the loader is hot-pathed.
#[must_use]
pub fn xdp_supported() -> bool {
    XdpDatapath::load("lo", AttachMode::Skb).is_ok()
}
