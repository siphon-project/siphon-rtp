//! The per-packet check the built-in TURN server runs for a peer in the denied loopback or private
//! range, [`OwnMediaEndpoints::is_live_media_endpoint`], allocates nothing: a live address, a dead
//! one on the same IP and an unknown IP are all a sharded-map read. A counting global allocator
//! proves it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_datapath::{Endpoint, EndpointId};
use siphon_rtp_engine::media_endpoints::MediaEndpointRegistry;
use siphon_rtp_turn::OwnMediaEndpoints;

/// A pass-through allocator that counts allocations on the armed thread only.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

// SAFETY: delegates straight to the system allocator; only bumps a relaxed counter when armed.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

#[test]
fn the_per_packet_liveness_check_allocates_nothing() {
    let registry = MediaEndpointRegistry::new();
    let live: SocketAddr = "192.0.2.10:30000".parse().expect("address");
    registry.register(Endpoint {
        id: EndpointId(1),
        local_addr: live,
    });
    let dead_port: SocketAddr = "192.0.2.10:30002".parse().expect("address");
    let other_ip: SocketAddr = "192.0.2.11:30000".parse().expect("address");

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    let mut hits = 0u32;
    for _ in 0..10_000 {
        hits += u32::from(registry.is_live_media_endpoint(live));
        hits += u32::from(registry.is_live_media_endpoint(dead_port));
        hits += u32::from(registry.is_live_media_endpoint(other_ip));
        hits += u32::from(registry.hosts_media_on(live.ip()));
    }
    ARMED.with(|armed| armed.set(false));
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) - before;

    assert_eq!(hits, 20_000, "the live address and its IP, every round");
    assert_eq!(allocations, 0, "the per-packet check must not allocate");
}
