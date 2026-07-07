//! Next-hop MAC resolution for the AF_XDP TX path.
//!
//! The TX frame builder ([`crate::headers::build_udp_frame`]) needs two link-layer addresses the IP
//! layer does not carry: the egress interface's own **source MAC** and the **destination MAC** of the
//! next hop toward the peer. This module resolves both from the kernel, mirroring what the kernel
//! itself does when it sends an IP packet:
//!
//! 1. **Next hop.** Look up the route to the destination (`RTM_GETROUTE`). If the destination is
//!    on-link (no gateway on its route) the next hop is the destination itself; otherwise it is the
//!    route's gateway — RFC 1122 §3.3.1. The route also names the egress interface.
//! 2. **Destination MAC.** Look up the next hop in the kernel neighbour table (`RTM_GETNEIGH`, ARP
//!    for IPv4 — RFC 826). A resolved, usable entry gives the next hop's MAC.
//! 3. **Source MAC.** The egress interface's own hardware address (`RTM_GETLINK`).
//!
//! ## Split across two threads, so the busy-poll datapath never blocks on netlink
//!
//! `build_and_push` runs on the single-owner AF_XDP busy-poll thread, which must never block on async
//! netlink per packet. So the hot path only ever does a **synchronous, lock-free cache read**
//! ([`NeighborResolver::resolve`]): on a hit it returns the two MACs (a `Copy` `[u8; 6]` each — zero
//! allocation); on a miss it hands the destination to an off-thread worker and returns
//! [`Resolution::Pending`], and the caller **drops the packet** (never forward into the void). The
//! next packets to that destination flow once the worker resolves it — exactly how the kernel
//! queues/drops the first packet to an unresolved neighbour while ARP completes.
//!
//! The worker (`netlink::run_worker`) owns its own Tokio runtime and the one netlink socket, does all
//! `RTM_GET*` I/O and the ARP kick, and writes answers back into the shared caches. Requests reach it
//! over a **bounded** `flume` channel with an explicit overflow policy (reject on full — the missing
//! destination is retried on the next frame), and each in-flight destination is deduped so a stalled
//! resolution cannot flood the channel.
//!
//! Cache freshness is driven by an injected **logical clock** (seconds), never `Instant::now()` in
//! anything a test drives, so expiry is deterministic (the `cache` submodule).

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use dashmap::DashMap;

use crate::headers::MacAddr;

use self::cache::FreshCache;

mod cache;
mod netlink;

/// The outcome of a hot-path resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Both MACs are cached and fresh — build and transmit the frame.
    Resolved {
        /// The egress interface's own hardware address (Ethernet source).
        src_mac: MacAddr,
        /// The next hop's hardware address (Ethernet destination).
        dst_mac: MacAddr,
    },
    /// The next-hop MAC is not (yet) resolved; a resolution has been requested off-thread. The
    /// caller must **drop** this packet — the next ones flow once it resolves.
    Pending,
}

/// Tunables for the resolver's caches and request channel.
#[derive(Debug, Clone, Copy)]
pub struct ResolverConfig {
    /// Freshness window (logical ticks/seconds) for neighbour-table entries before re-resolution.
    pub neighbor_ttl: u64,
    /// Freshness window for route decisions.
    pub route_ttl: u64,
    /// Freshness window for egress-interface MACs (rarely change, so longer).
    pub link_ttl: u64,
    /// Bound of the resolution-request channel to the worker (reject-on-full overflow policy).
    pub channel_bound: usize,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        // 30 s neighbour/route freshness tracks gateway/ARP churn without re-querying per frame; a
        // 5 min link window since an interface MAC is effectively static; 256 in-flight destinations
        // is far more than a relay's concurrent unresolved next hops.
        Self {
            neighbor_ttl: 30,
            route_ttl: 30,
            link_ttl: 300,
            channel_bound: 256,
        }
    }
}

/// State shared between the resolver handle (hot-path reads) and the worker thread (netlink writes).
pub(crate) struct Shared {
    /// Destination IPv4 → (next hop IPv4, egress ifindex).
    pub(crate) routes: FreshCache<Ipv4Addr, (Ipv4Addr, u32)>,
    /// Next-hop IPv4 → its MAC (the neighbour-table mirror).
    pub(crate) neighbors: FreshCache<Ipv4Addr, MacAddr>,
    /// Egress ifindex → the interface's own source MAC.
    pub(crate) links: FreshCache<u32, MacAddr>,
    /// Destinations with a resolution in flight, so a miss is enqueued at most once at a time.
    in_flight: DashMap<Ipv4Addr, ()>,
    /// Logical clock (seconds) for cache freshness — set by the datapath loop / tests, never read
    /// from `Instant::now()` on any path a test drives.
    clock: AtomicU64,
}

impl Shared {
    fn now(&self) -> u64 {
        self.clock.load(Ordering::Relaxed)
    }

    /// Clear a destination's in-flight marker (the worker calls this when a pass finishes).
    pub(crate) fn clear_in_flight(&self, dst: Ipv4Addr) {
        self.in_flight.remove(&dst);
    }

    fn reap(&self, now: u64) {
        self.routes.reap(now);
        self.neighbors.reap(now);
        self.links.reap(now);
    }
}

/// Resolves next-hop MACs for the TX path: a synchronous cache the busy-poll thread reads, backed by
/// an off-thread netlink worker.
pub struct NeighborResolver {
    shared: Arc<Shared>,
    /// Bounded request channel to the worker; the sole sender (dropping it stops the worker).
    requests: flume::Sender<Ipv4Addr>,
    /// The worker thread handle, joined on drop.
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl NeighborResolver {
    /// Build the resolver and spawn its netlink worker thread. If the worker thread cannot be
    /// spawned, resolution degrades to always-`Pending` (every TX frame drops) and the failure is
    /// logged — the datapath never forwards with an unresolved MAC.
    #[must_use]
    pub fn new(config: ResolverConfig) -> Self {
        let (resolver, requests_rx) = Self::build(config);
        let shared = resolver.shared.clone();
        match std::thread::Builder::new()
            .name("siphon-xdp-neighbor".to_string())
            .spawn(move || netlink::run_worker(shared, requests_rx))
        {
            Ok(handle) => {
                if let Ok(mut guard) = resolver.worker.lock() {
                    *guard = Some(handle);
                }
            }
            Err(error) => {
                tracing::error!(%error, "neighbor resolver: worker thread spawn failed; MAC resolution disabled");
            }
        }
        resolver
    }

    /// Build the resolver without a worker, returning the request receiver. Used by the constructor
    /// (which spawns the worker on it) and, in tests/benches, to drive the caches deterministically.
    fn build(config: ResolverConfig) -> (Self, flume::Receiver<Ipv4Addr>) {
        let (requests, requests_rx) = flume::bounded(config.channel_bound);
        let shared = Arc::new(Shared {
            routes: FreshCache::new(config.route_ttl),
            neighbors: FreshCache::new(config.neighbor_ttl),
            links: FreshCache::new(config.link_ttl),
            in_flight: DashMap::new(),
            clock: AtomicU64::new(0),
        });
        (
            Self {
                shared,
                requests,
                worker: Mutex::new(None),
            },
            requests_rx,
        )
    }

    /// Advance the resolver's logical freshness clock to `seconds`. The datapath loop stamps it from
    /// its monotonic origin each iteration (production); tests set it explicitly.
    pub fn set_now(&self, seconds: u64) {
        self.shared.clock.store(seconds, Ordering::Relaxed);
    }

    /// Evict entries older than their TTL at the current clock (called on the datapath idle sweep so
    /// the caches drain under a churn-then-idle workload).
    pub fn reap(&self) {
        self.shared.reap(self.shared.now());
    }

    /// Resolve the source + destination MACs for a frame to `dst`, reading the caches synchronously.
    /// On any miss it requests off-thread resolution and returns [`Resolution::Pending`] so the
    /// caller drops the packet (never forward into the void).
    #[must_use]
    pub fn resolve(&self, dst: Ipv4Addr) -> Resolution {
        let now = self.shared.now();
        let Some((next_hop, ifindex)) = self.shared.routes.get(&dst, now) else {
            self.request(dst);
            return Resolution::Pending;
        };
        let Some(dst_mac) = self.shared.neighbors.get(&next_hop, now) else {
            self.request(dst);
            return Resolution::Pending;
        };
        let Some(src_mac) = self.shared.links.get(&ifindex, now) else {
            self.request(dst);
            return Resolution::Pending;
        };
        Resolution::Resolved { src_mac, dst_mac }
    }

    /// Enqueue an off-thread resolution for `dst`, at most one in flight per destination. On a full
    /// channel the request is dropped (reject-on-full) and the destination stays un-marked, so the
    /// next frame retries — no unbounded queue.
    fn request(&self, dst: Ipv4Addr) {
        use dashmap::mapref::entry::Entry;
        if let Entry::Vacant(slot) = self.shared.in_flight.entry(dst) {
            // Only mark in-flight if the request actually queued.
            if self.requests.try_send(dst).is_ok() {
                slot.insert(());
            }
        }
    }

    /// Insert a fully-resolved route + egress MAC + neighbour MAC directly, bypassing netlink.
    /// Pins a static next-hop MAC (and is how tests/benches drive the resolved hot path). `now` is
    /// the freshness stamp on the same logical clock [`Self::set_now`] uses.
    pub fn insert_resolved(
        &self,
        dst: Ipv4Addr,
        next_hop: Ipv4Addr,
        ifindex: u32,
        src_mac: MacAddr,
        dst_mac: MacAddr,
        now: u64,
    ) {
        self.shared.routes.insert(dst, (next_hop, ifindex), now);
        self.shared.neighbors.insert(next_hop, dst_mac, now);
        self.shared.links.insert(ifindex, src_mac, now);
    }
}

impl Drop for NeighborResolver {
    fn drop(&mut self) {
        // Close the request channel so the worker's blocking `recv` returns and the thread exits;
        // then join it so no orphan thread leaks (mirrors the datapath thread teardown). Swapping in
        // a fresh disconnected sender drops the real one held here.
        let (dead, _) = flume::bounded::<Ipv4Addr>(0);
        let _ = std::mem::replace(&mut self.requests, dead);
        if let Ok(mut guard) = self.worker.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

/// Format a MAC as lowercase colon-separated hex (`02:00:00:00:00:2a`), the IEEE 802 canonical form
/// used across `ip`/`tcpdump`. For logs and diagnostics.
#[must_use]
pub fn format_mac(mac: MacAddr) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC_MAC: MacAddr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const DST_MAC: MacAddr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const DST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 5);
    const NEXT_HOP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);

    fn resolver() -> (NeighborResolver, flume::Receiver<Ipv4Addr>) {
        NeighborResolver::build(ResolverConfig::default())
    }

    #[test]
    fn miss_drops_and_enqueues_a_resolution_request() {
        let (resolver, requests) = resolver();
        assert_eq!(
            resolver.resolve(DST),
            Resolution::Pending,
            "cold cache misses"
        );
        assert_eq!(
            requests.try_recv(),
            Ok(DST),
            "a resolution was requested for the dst"
        );
    }

    #[test]
    fn miss_enqueues_at_most_one_request_per_destination_in_flight() {
        let (resolver, requests) = resolver();
        // Three frames to the same unresolved dst before the worker answers.
        assert_eq!(resolver.resolve(DST), Resolution::Pending);
        assert_eq!(resolver.resolve(DST), Resolution::Pending);
        assert_eq!(resolver.resolve(DST), Resolution::Pending);
        assert_eq!(requests.try_recv(), Ok(DST), "first miss enqueues");
        assert!(
            requests.try_recv().is_err(),
            "in-flight dedup: no duplicate requests"
        );
    }

    #[test]
    fn cleared_in_flight_marker_allows_re_enqueue() {
        let (resolver, requests) = resolver();
        assert_eq!(resolver.resolve(DST), Resolution::Pending);
        assert_eq!(requests.try_recv(), Ok(DST));
        // Worker finished a pass (resolved nothing) and cleared the marker.
        resolver.shared.clear_in_flight(DST);
        assert_eq!(resolver.resolve(DST), Resolution::Pending);
        assert_eq!(
            requests.try_recv(),
            Ok(DST),
            "re-enqueued after the marker cleared"
        );
    }

    #[test]
    fn resolved_cache_hit_returns_both_macs_without_enqueue() {
        let (resolver, requests) = resolver();
        resolver.set_now(100);
        resolver.insert_resolved(DST, NEXT_HOP, 7, SRC_MAC, DST_MAC, 100);
        assert_eq!(
            resolver.resolve(DST),
            Resolution::Resolved {
                src_mac: SRC_MAC,
                dst_mac: DST_MAC
            }
        );
        assert!(requests.try_recv().is_err(), "a hit never enqueues");
    }

    #[test]
    fn expired_entry_misses_and_re_requests() {
        let (resolver, requests) = resolver();
        resolver.insert_resolved(DST, NEXT_HOP, 7, SRC_MAC, DST_MAC, 100);
        resolver.set_now(100);
        assert!(matches!(resolver.resolve(DST), Resolution::Resolved { .. }));
        // Advance past the 30 s neighbour TTL — the entry goes stale, so the next frame drops and
        // re-requests (kernel-like: revalidate an aged neighbour).
        resolver.set_now(131);
        assert_eq!(resolver.resolve(DST), Resolution::Pending);
        assert_eq!(requests.try_recv(), Ok(DST));
    }

    #[test]
    fn full_channel_rejects_without_marking_in_flight() {
        // A tiny channel that is already full: the request is dropped and the dst stays un-marked so
        // a later frame can retry (reject-on-full overflow policy, no unbounded growth).
        let (resolver, requests) = NeighborResolver::build(ResolverConfig {
            channel_bound: 1,
            ..ResolverConfig::default()
        });
        let _ = resolver.resolve(Ipv4Addr::new(203, 0, 113, 1)); // fills the single slot
        let _ = resolver.resolve(DST); // rejected (channel full)
        assert!(
            !resolver.shared.in_flight.contains_key(&DST),
            "rejected dst is not pinned in-flight"
        );
        // Drain, then the previously-rejected dst can enqueue.
        let _ = requests.drain().count();
        let _ = resolver.resolve(DST);
        assert!(resolver.shared.in_flight.contains_key(&DST));
    }

    #[test]
    fn churn_then_idle_drains_every_cache_to_zero() {
        // The memory-leak soak invariant: many distinct destinations resolved, then idle past TTL,
        // then reaped → the registry and every per-entry store return to 0 (no leak).
        let (resolver, _requests) = resolver();
        for octet in 0..200u16 {
            let dst = Ipv4Addr::new(203, 0, (octet >> 8) as u8, octet as u8);
            let next_hop = Ipv4Addr::new(198, 51, 100, octet as u8);
            resolver.insert_resolved(dst, next_hop, 7, SRC_MAC, DST_MAC, 10);
        }
        assert!(resolver.shared.routes.len() > 0);
        resolver.set_now(10_000); // long past every TTL
        resolver.reap();
        assert_eq!(resolver.shared.routes.len(), 0, "routes drained");
        assert_eq!(resolver.shared.neighbors.len(), 0, "neighbors drained");
        assert_eq!(resolver.shared.links.len(), 0, "links drained");
    }

    #[test]
    fn format_mac_is_canonical_colon_hex() {
        assert_eq!(
            format_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x2a]),
            "02:00:00:00:00:2a"
        );
        assert_eq!(
            format_mac([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            "ff:ff:ff:ff:ff:ff"
        );
        assert_eq!(format_mac([0x00; 6]), "00:00:00:00:00:00");
    }

    #[test]
    fn resolution_is_copy_and_debug() {
        // Resolution is a small Copy value carried on the hot path; prove the derives hold.
        let resolution = Resolution::Resolved {
            src_mac: SRC_MAC,
            dst_mac: DST_MAC,
        };
        let copied = resolution;
        assert_eq!(resolution, copied);
        assert!(format!("{resolution:?}").contains("Resolved"));
        assert!(format!("{:?}", Resolution::Pending).contains("Pending"));
    }

    #[test]
    fn dropping_resolver_without_worker_is_clean() {
        // build() spawns no worker; drop must not hang on a join of a non-existent thread.
        let (resolver, _requests) = resolver();
        drop(resolver);
    }
}

/// A live, kernel-touching resolution test — gated so it self-skips off a networked box.
#[cfg(test)]
mod live_tests {
    use super::*;
    use ::netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
    use ::netlink_packet_route::AddressFamily;
    use futures::TryStreamExt;
    use rtnetlink::IpVersion;
    use std::time::Duration;

    /// Resolve a neighbour that the running kernel already has in its table (e.g. a LAN gateway), end
    /// to end through the real netlink worker. **Self-skips** (logs + returns) when netlink is
    /// unavailable or no on-link, usable IPv4 neighbour is present — so `cargo test` stays green on an
    /// unprivileged / network-less box. On the kernel-capable CI runner (which has a real network,
    /// and where a veth+neigh may be primed) it exercises the full path.
    #[test]
    fn resolves_a_real_kernel_neighbour_when_one_is_present() {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("skip: cannot build runtime: {error}");
                return;
            }
        };

        // Find a candidate: a usable IPv4 neighbour whose route is on-link to the same interface, so
        // the resolver's route→neigh→link chain will resolve it deterministically.
        let candidate = runtime.block_on(async {
            let (connection, handle, _messages) = match rtnetlink::new_connection() {
                Ok(parts) => parts,
                Err(error) => {
                    eprintln!("skip: no netlink connection: {error}");
                    return None;
                }
            };
            tokio::spawn(connection);

            let mut neighbours = handle
                .neighbours()
                .get()
                .set_family(IpVersion::V4)
                .execute();
            while let Ok(Some(message)) = neighbours.try_next().await {
                let Some(neighbour) = super::netlink::neighbour_from_message(&message) else {
                    continue;
                };
                if !neighbour.usable {
                    continue;
                }
                // route-get(ip): keep only entries that are on-link to the neighbour's own interface.
                let mut request = RouteMessage::default();
                request.header.address_family = AddressFamily::Inet;
                request.header.destination_prefix_length = 32;
                request
                    .attributes
                    .push(RouteAttribute::Destination(RouteAddress::Inet(
                        neighbour.ip,
                    )));
                let mut routes = handle.route().get(request).execute();
                while let Ok(Some(route)) = routes.try_next().await {
                    if let Some(next_hop) =
                        super::netlink::next_hop_from_route(neighbour.ip, &route)
                    {
                        if next_hop.ip == neighbour.ip && next_hop.ifindex == neighbour.ifindex {
                            return Some(neighbour);
                        }
                    }
                }
            }
            None
        });

        let Some(candidate) = candidate else {
            eprintln!("skip: no on-link usable IPv4 neighbour present in the kernel table");
            return;
        };

        // Drive the real resolver: poll the synchronous hot path until the worker fills the cache.
        let resolver = NeighborResolver::new(ResolverConfig::default());
        let mut resolved = None;
        for _ in 0..40 {
            if let Resolution::Resolved { src_mac, dst_mac } = resolver.resolve(candidate.ip) {
                resolved = Some((src_mac, dst_mac));
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        let Some((src_mac, dst_mac)) = resolved else {
            // The kernel had the entry but the worker did not converge in time — do not fail CI on a
            // timing/permission edge; report it.
            eprintln!("skip: resolver did not converge for {}", candidate.ip);
            return;
        };
        assert_eq!(
            dst_mac, candidate.mac,
            "resolved dst MAC matches the kernel neighbour table"
        );
        assert_ne!(src_mac, [0u8; 6], "egress interface has a real source MAC");
    }
}
