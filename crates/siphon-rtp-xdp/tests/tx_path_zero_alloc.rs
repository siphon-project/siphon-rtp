//! The resolved next-hop-MAC hot path must not allocate per TX frame.
//!
//! `build_and_push` pays one [`NeighborResolver::resolve`] per outbound frame; on a cache hit it is a
//! synchronous read that returns two `Copy` `[u8; 6]` MACs into a caller-owned frame buffer, so it
//! must allocate nothing. A thread-local counting allocator makes that a hard assertion (the repo's
//! zero-per-frame-heap-alloc invariant), isolated to the measuring thread so the resolver's idle
//! background worker cannot perturb the count.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::net::Ipv4Addr;

use siphon_rtp_xdp::neighbor::{NeighborResolver, Resolution, ResolverConfig};

thread_local! {
    /// Allocation count for the current thread (const-init so reading it never itself allocates).
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

/// A `System` allocator that tallies allocations per thread.
struct CountingAllocator;

// SAFETY: every method forwards to the `System` allocator unchanged; the only added work is bumping
// a const-initialised thread-local `Cell<u64>`, which performs no allocation of its own.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn resolved_hot_path_allocates_nothing_per_frame() {
    let resolver = NeighborResolver::new(ResolverConfig::default());
    let destination = Ipv4Addr::new(203, 0, 113, 5);
    let next_hop = Ipv4Addr::new(198, 51, 100, 1);
    resolver.set_now(100);
    resolver.insert_resolved(
        destination,
        next_hop,
        7,
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        100,
    );

    // Warm up (and prove the hit path is actually taken) outside the measured window.
    assert!(matches!(
        resolver.resolve(destination),
        Resolution::Resolved { .. }
    ));

    let before = ALLOCATIONS.with(std::cell::Cell::get);
    for _ in 0..100_000 {
        black_box(resolver.resolve(black_box(destination)));
    }
    let after = ALLOCATIONS.with(std::cell::Cell::get);

    assert_eq!(
        after - before,
        0,
        "the resolved TX hot path must not allocate (allocated {} times over 100k frames)",
        after - before
    );
}
