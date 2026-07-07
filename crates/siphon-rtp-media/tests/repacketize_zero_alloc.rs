//! The repacketizer is on the per-frame transcode hot path, so it must do **zero heap allocation**
//! once its accumulator is warmed (sized at construction). A counting global allocator proves a tight
//! push → drain loop allocates nothing — the accumulator is preallocated and drained in place.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_media::repacketize::Repacketizer;

/// A pass-through allocator that counts allocations on the armed thread only.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting, so the libtest harness's background-thread churn during
    // the same window is not miscounted. `const`-initialised so `alloc` never itself allocates.
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
fn push_and_drain_make_no_heap_allocation() {
    // 8 kHz: 30 ms ingress (240 samples) → 20 ms egress (160 samples), a fractional 3:2 ratio that
    // buffers across packets — the worst case for the in-place tail shift.
    const INGRESS: usize = 240;
    const EGRESS: usize = 160;

    let ingress = [123i16; INGRESS];
    let mut frame = [0i16; EGRESS];
    let mut repacketizer = Repacketizer::new(EGRESS, INGRESS);

    // Warm up: run enough push/drain cycles that the accumulator reaches its steady-state length before
    // we arm counting (its capacity was reserved once at construction — this touches every page).
    for _ in 0..64 {
        repacketizer.push(&ingress);
        while repacketizer.next_frame(&mut frame).is_some() {}
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..10_000 {
        repacketizer.push(&ingress);
        while let Some(count) = repacketizer.next_frame(&mut frame) {
            std::hint::black_box(&frame[..count]);
        }
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "repacketize loop allocated {} times across 10000 cycles (must be zero)",
        after - before
    );
}
