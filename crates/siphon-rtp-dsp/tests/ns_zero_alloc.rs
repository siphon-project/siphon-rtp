//! The noise suppressor must do **zero per-frame heap allocation** on the hot path (a performance
//! invariant): every buffer — FFT work, WOLA rings, per-bin PSD/gain state, `i16`↔`f32` scratch — is
//! preallocated in `NoiseSuppressor::new`. A counting global allocator proves a tight `process` loop
//! allocates nothing after warm-up. Mirrors the media crate's `mixer_zero_alloc` pattern.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_dsp::NoiseSuppressor;

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting. A *global* counter would also catch the libtest
    // harness's background-thread allocations that land inside the loop window — spurious on a slow
    // CI runner. `const`-initialised so accessing it in `alloc` never itself allocates.
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

fn assert_zero_alloc_process(rate: u32, frame_len: usize) {
    let mut suppressor = NoiseSuppressor::new(rate).expect("build");
    let mut frame = vec![0i16; frame_len];

    // Deterministic non-silent input (fixed-seed LCG); never `rand`, never a clock.
    let mut lcg: u32 = 0x1234_5678 ^ rate;
    let mut next = || {
        lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        ((lcg >> 8) as i32 % 6000 - 3000) as i16
    };
    for slot in frame.iter_mut() {
        *slot = next();
    }

    // Warm up so any one-time lazy init is paid before we sample.
    for _ in 0..8 {
        let mut warm = frame.clone();
        suppressor.process(&mut warm);
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..2_000 {
        suppressor.process(&mut frame);
        std::hint::black_box(&frame);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "{rate} Hz: process allocated {} times across 2000 frames (must be zero)",
        after - before
    );
}

#[test]
fn narrowband_process_makes_no_heap_allocation() {
    assert_zero_alloc_process(8_000, 160);
}

#[test]
fn wideband_process_makes_no_heap_allocation() {
    assert_zero_alloc_process(16_000, 320);
}
