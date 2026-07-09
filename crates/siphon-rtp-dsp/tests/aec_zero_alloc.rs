//! The echo canceller must do **zero per-frame heap allocation** on the hot path (a performance
//! invariant): the adaptive filter weights, the far-end delay ring, and all scratch live on the
//! [`EchoCanceller`], sized once in `new`. A counting global allocator proves a tight `cancel` loop
//! allocates nothing after warm-up.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_dsp::EchoCanceller;

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting. A *global* counter would also catch the libtest
    // harness's background-thread allocations that land inside the wall-clock loop window — spurious
    // on a slow (CI) runner. `const`-initialised so accessing it in `alloc` never itself allocates
    // (no lazy Key / destructor registration), keeping the allocator re-entrancy-safe.
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
    const TAIL: usize = 256;
    const FRAME: usize = 160; // 8 kHz / 20 ms

    // Setup (allocates freely) — the canceller's state and the reusable frame buffers.
    let mut canceller = EchoCanceller::new(8_000, TAIL).expect("build");
    let reference: Vec<i16> = (0..FRAME)
        .map(|index| ((index as i16).wrapping_mul(211)).wrapping_sub(3_000))
        .collect();
    let source: Vec<i16> = (0..FRAME)
        .map(|index| ((index as i16).wrapping_mul(97)).wrapping_add(500))
        .collect();
    let mut near = source.clone();

    // Warm up one frame so any one-time lazy init is paid before we sample.
    canceller.cancel(&mut near, &reference);

    // Arm counting on *this* thread only, so the sample is the cancel loop's own allocations — not
    // the libtest harness's background-thread churn during the same window.
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..2_000 {
        // Refresh the near-end in place (no allocation) so cancel operates on a fresh frame.
        near.copy_from_slice(&source);
        canceller.cancel(&mut near, &reference);
        std::hint::black_box(near[0]);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "cancel allocated {} times across 2000 frames (must be zero)",
        after - before
    );
}
