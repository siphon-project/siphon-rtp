//! The echo canceller must do **zero per-frame heap allocation** on the hot path (a performance
//! invariant): the adaptive filter and its reference delay line are sized once in
//! [`EchoCanceller::new`], and [`EchoCanceller::cancel`] only mutates them in place (a bounded
//! `copy_within` slide + a SIMD dot + an O(tail) update). A counting global allocator proves a tight
//! `cancel` loop allocates nothing after warm-up.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_dsp::EchoCanceller;

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting, so the libtest harness's background-thread churn
    // during the same window is not miscounted. `const`-initialised so accessing it in `alloc` never
    // itself allocates, keeping the allocator re-entrancy-safe.
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

// SAFETY: every call delegates straight to the system allocator; we only bump a relaxed counter, and
// only when the current thread has armed counting.
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
fn cancel_frame_makes_no_heap_allocation() {
    const FRAME: usize = 160; // 20 ms @ 8 kHz
    const TAIL: usize = 128;

    // Setup (allocates freely): the frames and the canceller's buffers.
    let reference: Vec<i16> = (0..FRAME)
        .map(|n| ((n as i16).wrapping_mul(211)).wrapping_add(13))
        .collect();
    let near_source: Vec<i16> = (0..FRAME)
        .map(|n| ((n as i16).wrapping_mul(97)).wrapping_sub(5))
        .collect();
    let mut near = near_source.clone();
    let mut canceller = EchoCanceller::new(8000, TAIL).expect("build");

    // Warm up so any one-time lazy init is paid before we sample.
    canceller.cancel(&mut near, &reference);

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..1_000 {
        near.copy_from_slice(&near_source); // same length — not an allocation
        canceller.cancel(&mut near, &reference);
        std::hint::black_box(near[0]);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "cancel allocated {} times across 1000 frames (must be zero)",
        after - before
    );
}
