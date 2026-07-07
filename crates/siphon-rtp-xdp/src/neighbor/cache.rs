//! Freshness-gated in-memory caches for the [`super::NeighborResolver`].
//!
//! Each cache mirrors one kernel table the TX path needs to build an L2 frame:
//! - the **route** decision for a destination (next hop + egress interface),
//! - the **neighbour** entry for a next hop (its MAC — the ARP/RFC 826 answer),
//! - the egress interface's own **link** MAC (the frame's source MAC).
//!
//! All three share one shape: a [`DashMap`] of key → `(value, resolved_at_tick)`, read lock-free on
//! the hot path and evicted by a **logical clock** — never `Instant::now()`. The caller supplies
//! `now` on every read and write so expiry is deterministic under test (a logical sample-clock, the
//! repo's #1 flake-avoidance rule). A read past the freshness window is a miss, so the resolver
//! re-queries the kernel and the datapath drops the packet until the fresh answer lands.

use std::hash::Hash;

use dashmap::DashMap;

/// A `DashMap`-backed cache whose entries expire after `ttl` ticks of the injected logical clock.
///
/// `K: Copy` (IPv4 address or ifindex) and `V: Copy` (a `[u8; 6]` MAC or a `(next_hop, ifindex)`
/// tuple), so a hit copies the value out with zero heap allocation — the property the TX hot path
/// and its zero-alloc bench rely on.
pub(crate) struct FreshCache<K: Eq + Hash + Copy, V: Copy> {
    entries: DashMap<K, (V, u64)>,
    ttl: u64,
}

impl<K: Eq + Hash + Copy, V: Copy> FreshCache<K, V> {
    /// A cache whose entries are considered fresh for `ttl` logical ticks after they are written.
    pub(crate) fn new(ttl: u64) -> Self {
        Self {
            entries: DashMap::new(),
            ttl,
        }
    }

    /// Insert or replace `key`'s value, stamping it resolved at tick `now`.
    pub(crate) fn insert(&self, key: K, value: V, now: u64) {
        self.entries.insert(key, (value, now));
    }

    /// The fresh value for `key`, or `None` on a miss **or** if the entry is older than `ttl` at
    /// tick `now`. Stale entries are left in place (a later [`Self::reap`] removes them); a caller
    /// treating a stale read as a miss re-triggers resolution, which overwrites the entry.
    pub(crate) fn get(&self, key: &K, now: u64) -> Option<V> {
        let entry = self.entries.get(key)?;
        let (value, resolved_at) = *entry;
        // `saturating_sub` guards a clock that has not advanced past `resolved_at` (e.g. an entry
        // written by the worker one tick "ahead" of a reader that has not re-read the clock yet).
        if now.saturating_sub(resolved_at) < self.ttl {
            Some(value)
        } else {
            None
        }
    }

    /// Drop every entry older than `ttl` at tick `now`. Called on the resolver's idle sweep so the
    /// maps drain back toward zero under a churning-then-idle workload (the memory-leak soak).
    pub(crate) fn reap(&self, now: u64) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, (_, resolved_at)| now.saturating_sub(*resolved_at) < ttl);
    }

    /// Number of entries currently held (fresh or stale). For the leak soak and tests.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x2a];

    #[test]
    fn hit_within_ttl_returns_the_value() {
        let cache: FreshCache<Ipv4Addr, [u8; 6]> = FreshCache::new(30);
        let ip = Ipv4Addr::new(198, 51, 100, 2);
        cache.insert(ip, MAC, 100);
        assert_eq!(cache.get(&ip, 100), Some(MAC), "same-tick read is a hit");
        assert_eq!(
            cache.get(&ip, 129),
            Some(MAC),
            "one tick before ttl is a hit"
        );
    }

    #[test]
    fn read_at_or_past_ttl_is_a_miss() {
        let cache: FreshCache<Ipv4Addr, [u8; 6]> = FreshCache::new(30);
        let ip = Ipv4Addr::new(198, 51, 100, 2);
        cache.insert(ip, MAC, 100);
        assert_eq!(cache.get(&ip, 130), None, "exactly ttl later is expired");
        assert_eq!(cache.get(&ip, 200), None, "well past ttl is expired");
    }

    #[test]
    fn absent_key_is_a_miss() {
        let cache: FreshCache<Ipv4Addr, [u8; 6]> = FreshCache::new(30);
        assert_eq!(cache.get(&Ipv4Addr::new(203, 0, 113, 9), 0), None);
    }

    #[test]
    fn reinsert_refreshes_the_freshness_stamp() {
        let cache: FreshCache<Ipv4Addr, [u8; 6]> = FreshCache::new(30);
        let ip = Ipv4Addr::new(198, 51, 100, 2);
        cache.insert(ip, MAC, 100);
        // Would be stale at 140, but a re-resolution at 135 refreshes the stamp.
        cache.insert(ip, MAC, 135);
        assert_eq!(cache.get(&ip, 140), Some(MAC));
    }

    #[test]
    fn clock_before_stamp_does_not_underflow() {
        // A reader one tick behind the writer must not panic on `now - resolved_at`.
        let cache: FreshCache<Ipv4Addr, [u8; 6]> = FreshCache::new(30);
        let ip = Ipv4Addr::new(198, 51, 100, 2);
        cache.insert(ip, MAC, 100);
        assert_eq!(cache.get(&ip, 99), Some(MAC));
    }

    #[test]
    fn reap_removes_only_stale_entries_and_drains_to_zero() {
        let cache: FreshCache<Ipv4Addr, [u8; 6]> = FreshCache::new(30);
        for octet in 0..50u8 {
            cache.insert(Ipv4Addr::new(198, 51, 100, octet), MAC, 100);
        }
        assert_eq!(cache.len(), 50);
        // Nothing stale yet at 120.
        cache.reap(120);
        assert_eq!(cache.len(), 50, "fresh entries survive the sweep");
        // All stale at 200 → maps drain back to zero (the leak-soak invariant).
        cache.reap(200);
        assert_eq!(
            cache.len(),
            0,
            "stale entries are reaped, registry drains to 0"
        );
    }

    #[test]
    fn tuple_values_round_trip() {
        // The route cache stores (next_hop, ifindex); prove a Copy tuple works as V.
        let cache: FreshCache<Ipv4Addr, (Ipv4Addr, u32)> = FreshCache::new(30);
        let dst = Ipv4Addr::new(203, 0, 113, 5);
        let next_hop = Ipv4Addr::new(198, 51, 100, 1);
        cache.insert(dst, (next_hop, 7), 10);
        assert_eq!(cache.get(&dst, 10), Some((next_hop, 7)));
    }
}
