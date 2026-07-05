//! Zero-per-frame-allocation gate for the AMR encode hot path (CLAUDE.md performance invariant).
//!
//! `cargo test -p siphon-rtp-codec --features amr --test amr_zero_alloc`
//!
//! Unlike a jemalloc `stats.allocated` byte-delta (which moves in coarse arena-sized steps and so
//! is too noisy to gate a hot loop on a shared CI runner), a **counting** global allocator measures
//! exactly what the invariant is about: the number of calls into the allocator. A correct codec core
//! writes into caller-owned buffers and keeps its analysis-by-synthesis scratch on the encoder state,
//! so a warmed-up encode loop must make **zero** allocations. Allocate-then-free churn (invisible to a
//! live-bytes delta) still shows up here, so this gate is strictly stronger.
#![cfg(feature = "amr")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_codec::amr::{AmrNb, AmrNbMode, AmrWb};

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting, so the libtest harness's background-thread churn
    // during the same wall-clock window is not miscounted. `const`-initialised so touching it inside
    // `alloc` never itself allocates (no lazy Key / destructor registration) — re-entrancy-safe.
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

/// Run `body` `iterations` times with allocation counting armed on this thread, returning the number
/// of allocator calls it made.
fn count_allocations(iterations: usize, mut body: impl FnMut()) -> usize {
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..iterations {
        body();
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));
    after - before
}

#[test]
fn amr_nb_encode_core_makes_no_heap_allocation() {
    let pcm: Vec<i16> = (0..160_i32)
        .map(|i| (((i * 137) % 8000) - 4000) as i16)
        .collect();
    let mut nb = AmrNb::new();
    let mut bits = [0i16; 244]; // max AMR-NB serial size (MR122)

    // Warm up so any one-time lazy init (thread cache, first-call homing) is paid before we sample.
    for _ in 0..2_000 {
        nb.encode_mode_bits(AmrNbMode::Mr1220, &pcm, &mut bits)
            .expect("encode");
    }

    let allocations = count_allocations(50_000, || {
        nb.encode_mode_bits(AmrNbMode::Mr1220, &pcm, &mut bits)
            .expect("encode");
    });

    assert_eq!(
        allocations, 0,
        "AMR-NB encode core allocated {allocations} times across 50k frames (must be zero)"
    );
}

#[test]
fn amr_wb_encode_core_makes_no_heap_allocation() {
    let pcm: Vec<i16> = (0..320_i32)
        .map(|i| (((i * 137) % 8000) - 4000) as i16)
        .collect();
    let mut wb = AmrWb::new();
    let mut bits = [0i16; 477]; // max AMR-WB serial size (mode 8, 23.85 kbit/s)
    const MODE_1265: u8 = 2; // 12.65 kbit/s, the VoLTE workhorse mode

    for _ in 0..2_000 {
        wb.encode_mode_bits(MODE_1265, &pcm, &mut bits)
            .expect("encode");
    }

    let allocations = count_allocations(50_000, || {
        wb.encode_mode_bits(MODE_1265, &pcm, &mut bits)
            .expect("encode");
    });

    assert_eq!(
        allocations, 0,
        "AMR-WB encode core allocated {allocations} times across 50k frames (must be zero)"
    );
}
