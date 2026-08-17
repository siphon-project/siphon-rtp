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

/// Drive 1000 mix ticks at `frame` samples with `participants` talkers and return the allocation
/// count the loop made (must be zero).
fn allocations_over_1000_ticks(participants: usize, frame: usize, top_m: usize) -> usize {
    // Setup (allocates freely) — frames, parallel columns, the mixer's scratch.
    let pcm: Vec<Vec<i16>> = (0..participants)
        .map(|index| vec![((index as i16) * 41).wrapping_add(7); frame])
        .collect();
    let roles = vec![Role::Talker; participants];
    let energy: Vec<i64> = (0..participants)
        .map(|index| (index as i64 + 1) * 1_000)
        .collect();
    let speaking = vec![true; participants];
    let inputs = MixInputs {
        pcm: &pcm,
        roles: &roles,
        energy: &energy,
        speaking: &speaking,
        external: None,
        frame_len: frame,
    };
    let mut mixer = Mixer::new(participants, frame);

    // Warm up one tick so any one-time lazy init is paid before we sample.
    let _ = mixer.mix(&inputs, &[], &[], top_m);

    // Arm counting on *this* thread only, so the sample is the mix loop's own allocations — not the
    // libtest harness's background-thread churn during the same window.
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..1_000 {
        let active = mixer.mix(&inputs, &[], &[], top_m);
        std::hint::black_box(active);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));
    after - before
}

#[test]
fn mix_tick_makes_no_heap_allocation() {
    // Every room rate the conference actor selects — 8 kHz (all-narrowband), 16 kHz (wideband or
    // bridged), 48 kHz (all-full-band Opus) — at the 64-participant cap as well as a mid-size room.
    // A 48 kHz tick is 3× the samples of a 16 kHz one, which is exactly the size at which a scratch
    // buffer that was sized for the old ceiling would start reallocating mid-tick.
    for (rate, frame) in [(8_000, 160usize), (16_000, 320), (48_000, 960)] {
        for participants in [32usize, 64] {
            let allocations = allocations_over_1000_ticks(participants, frame, 0);
            assert_eq!(
                allocations, 0,
                "{rate} Hz / {participants}-party mix allocated {allocations} times across 1000 \
                 ticks (must be zero)"
            );
        }
    }
}

#[test]
fn top_m_gated_mix_tick_makes_no_heap_allocation() {
    // The webinar shape at the full-band rate: 60 talkers, top-3 active. The active-speaker
    // selection is a fixed-size insertion into a stack array, so it must not allocate either.
    let allocations = allocations_over_1000_ticks(60, 960, 3);
    assert_eq!(
        allocations, 0,
        "48 kHz top-3 webinar mix allocated {allocations} times across 1000 ticks (must be zero)"
    );
}
