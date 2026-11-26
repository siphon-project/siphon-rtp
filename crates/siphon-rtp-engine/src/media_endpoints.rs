//! The engine's live media endpoints, by bound address: the one list the built-in TURN server asks
//! before it relays to a loopback or private peer (RFC 8656 §21, docs/security-and-nat.md §11 R3).
//!
//! A TURN-only client on the engine's own network reaches the engine's media port through a relayed
//! candidate, and that port is on an address the TURN peer denylist refuses. The registry is what
//! lets the server accept exactly those ports and nothing else on the host: an endpoint is entered
//! when [`Engine`](crate::Engine) allocates it (`alloc_endpoints`, or the snapshot restore that
//! re-binds it) and leaves on the single release funnel (`release_endpoint`), so an address is live
//! for as long as a call holds its socket and not a moment longer.
//!
//! The per-packet read, [`OwnMediaEndpoints::is_live_media_endpoint`], is one sharded-map lookup. It is
//! not lock-free: `DashSet::contains` takes a shard read lock, held for the lookup alone and never
//! across an `.await`, which is the registry pattern used throughout the engine. It allocates
//! nothing.
//!
//! An endpoint bound to a wildcard address is not entered: its address is not one a peer could name,
//! and matching it by port alone would let a client aim the relay at that port on any private host.

use std::net::{IpAddr, SocketAddr};

use dashmap::{DashMap, DashSet};
use siphon_rtp_datapath::{Endpoint, EndpointId};
use siphon_rtp_turn::OwnMediaEndpoints;

/// The live media endpoints of one engine.
#[derive(Debug, Default)]
pub struct MediaEndpointRegistry {
    /// Where each live endpoint is bound, so a release (which only has the id) can find its address.
    bound: DashMap<EndpointId, SocketAddr>,
    /// The bound addresses, for the per-packet lookup.
    addresses: DashSet<SocketAddr>,
    /// How many live endpoints sit on each IP, for [`OwnMediaEndpoints::hosts_media_on`].
    per_ip: DashMap<IpAddr, usize>,
}

impl MediaEndpointRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enter a freshly bound endpoint. A wildcard-bound endpoint is ignored (see the module doc).
    pub fn register(&self, endpoint: Endpoint) {
        if endpoint.local_addr.ip().is_unspecified() {
            return;
        }
        if self
            .bound
            .insert(endpoint.id, endpoint.local_addr)
            .is_some()
        {
            // Registered twice: the first entry already counts toward its IP.
            return;
        }
        self.addresses.insert(endpoint.local_addr);
        *self.per_ip.entry(endpoint.local_addr.ip()).or_insert(0) += 1;
    }

    /// Remove an endpoint on its release. Idempotent: an unknown id is ignored.
    pub fn release(&self, id: EndpointId) {
        let Some((_, address)) = self.bound.remove(&id) else {
            return;
        };
        self.addresses.remove(&address);
        let ip = address.ip();
        if let Some(mut count) = self.per_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
        }
        self.per_ip.remove_if(&ip, |_, count| *count == 0);
    }

    /// How many endpoints are live.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bound.len()
    }

    /// Whether no endpoint is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bound.is_empty()
    }
}

impl OwnMediaEndpoints for MediaEndpointRegistry {
    fn hosts_media_on(&self, ip: IpAddr) -> bool {
        self.per_ip.contains_key(&ip)
    }

    fn is_live_media_endpoint(&self, endpoint: SocketAddr) -> bool {
        self.addresses.contains(&endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn endpoint(id: u64, ip: [u8; 4], port: u16) -> Endpoint {
        Endpoint {
            id: EndpointId(id),
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port),
        }
    }

    #[test]
    fn a_registered_endpoint_is_live_until_it_is_released() {
        let registry = MediaEndpointRegistry::new();
        let media = endpoint(1, [127, 0, 0, 1], 30_000);
        assert!(!registry.is_live_media_endpoint(media.local_addr));
        registry.register(media);
        assert!(registry.is_live_media_endpoint(media.local_addr));
        assert_eq!(registry.len(), 1);
        registry.release(media.id);
        assert!(!registry.is_live_media_endpoint(media.local_addr));
        assert!(registry.is_empty());
    }

    #[test]
    fn only_the_exact_ip_and_port_pair_is_live() {
        let registry = MediaEndpointRegistry::new();
        registry.register(endpoint(1, [127, 0, 0, 1], 30_000));
        let same_ip_other_port = SocketAddr::from(([127, 0, 0, 1], 30_001));
        let other_ip_same_port = SocketAddr::from(([127, 0, 0, 2], 30_000));
        assert!(!registry.is_live_media_endpoint(same_ip_other_port));
        assert!(!registry.is_live_media_endpoint(other_ip_same_port));
    }

    #[test]
    fn an_ip_hosts_media_while_any_endpoint_on_it_is_live() {
        let registry = MediaEndpointRegistry::new();
        let first = endpoint(1, [192, 0, 2, 10], 30_000);
        let second = endpoint(2, [192, 0, 2, 10], 30_002);
        registry.register(first);
        registry.register(second);
        assert!(registry.hosts_media_on(first.local_addr.ip()));
        registry.release(first.id);
        assert!(
            registry.hosts_media_on(second.local_addr.ip()),
            "one still there"
        );
        registry.release(second.id);
        assert!(!registry.hosts_media_on(second.local_addr.ip()));
    }

    #[test]
    fn releasing_twice_or_an_unknown_id_changes_nothing() {
        let registry = MediaEndpointRegistry::new();
        let kept = endpoint(1, [192, 0, 2, 10], 30_000);
        let freed = endpoint(2, [192, 0, 2, 10], 30_002);
        registry.register(kept);
        registry.register(freed);
        registry.release(freed.id);
        registry.release(freed.id);
        registry.release(EndpointId(99));
        assert!(registry.is_live_media_endpoint(kept.local_addr));
        assert!(registry.hosts_media_on(kept.local_addr.ip()));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registering_the_same_endpoint_twice_counts_it_once() {
        let registry = MediaEndpointRegistry::new();
        let media = endpoint(1, [192, 0, 2, 10], 30_000);
        registry.register(media);
        registry.register(media);
        registry.release(media.id);
        assert!(!registry.hosts_media_on(media.local_addr.ip()));
    }

    #[test]
    fn a_wildcard_bound_endpoint_is_never_live() {
        let registry = MediaEndpointRegistry::new();
        let wildcard = endpoint(1, [0, 0, 0, 0], 30_000);
        registry.register(wildcard);
        assert!(registry.is_empty());
        assert!(!registry.is_live_media_endpoint(SocketAddr::from(([10, 0, 0, 5], 30_000))));
        assert!(!registry.is_live_media_endpoint(wildcard.local_addr));
    }

    #[test]
    fn concurrent_register_and_release_drain_to_empty() {
        let registry = std::sync::Arc::new(MediaEndpointRegistry::new());
        let threads: Vec<_> = (0..8u64)
            .map(|thread| {
                let registry = registry.clone();
                std::thread::spawn(move || {
                    for round in 0..500u64 {
                        let id = thread * 1_000 + round;
                        let media = Endpoint {
                            id: EndpointId(id),
                            local_addr: SocketAddr::from((
                                [192, 0, 2, 10],
                                20_000 + (id % 9_000) as u16,
                            )),
                        };
                        registry.register(media);
                        registry.release(media.id);
                    }
                })
            })
            .collect();
        for handle in threads {
            handle.join().expect("thread");
        }
        // Ports collide across threads (same address, different ids), so the address set may have
        // lost an entry another id still held; what must hold is that nothing is left once every id
        // has been released.
        assert!(registry.is_empty());
        assert!(!registry.hosts_media_on(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))));
    }
}
