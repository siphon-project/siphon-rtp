//! The conference mix bus must do **zero per-frame heap allocation** on the hot path (a
//! performance invariant): all scratch lives on the [`Mixer`], sized once at construction. A counting
//! global allocator proves a tight `mix` loop allocates nothing after warm-up.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_media::mixer::{MixInputs, Mixer, Role};

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
fn mix_tick_makes_no_heap_allocation() {
    const PARTICIPANTS: usize = 32;
    const FRAME: usize = 320; // 16 kHz / 20 ms

    // Setup (allocates freely) — frames, parallel columns, the mixer's scratch.
    let pcm: Vec<Vec<i16>> = (0..PARTICIPANTS)
        .map(|index| vec![((index as i16) * 41).wrapping_add(7); FRAME])
        .collect();
    let roles = vec![Role::Talker; PARTICIPANTS];
    let energy: Vec<i64> = (0..PARTICIPANTS)
        .map(|index| (index as i64 + 1) * 1_000)
        .collect();
    let speaking = vec![true; PARTICIPANTS];
    let inputs = MixInputs {
        pcm: &pcm,
        roles: &roles,
        energy: &energy,
        speaking: &speaking,
        external: None,
        frame_len: FRAME,
    };
    let mut mixer = Mixer::new(PARTICIPANTS, FRAME);

    // Warm up one tick so any one-time lazy init is paid before we sample.
    let _ = mixer.mix(&inputs, &[], &[], 0);

    // Arm counting on *this* thread only, so the sample is the mix loop's own allocations — not the
    // libtest harness's background-thread churn during the same window.
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..1_000 {
        let active = mixer.mix(&inputs, &[], &[], 0);
        std::hint::black_box(active);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "mix tick allocated {} times across 1000 ticks (must be zero)",
        after - before
    );
}
