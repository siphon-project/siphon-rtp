//! The RFC 9071 conference text mix bus must do **zero heap allocation** on the flush hot path — all
//! scratch (the emit list, the payload arena, the RED build buffer, each participant's queue +
//! redundancy ring) lives on the [`TextMixer`], sized once. A counting global allocator proves a tight
//! push+flush loop allocates nothing once the buffers are warm.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_media::text_mixer::{TextMixer, TextSourceConfig};

/// A pass-through allocator that counts allocations while armed on the current thread only (so the
/// libtest harness's background allocations do not spuriously land in the sample window).
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

// SAFETY: every call delegates to the system allocator; we only bump a relaxed counter, and only when
// the current thread has armed counting.
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

/// A RED-capable text participant with a stable source id and dynamic t140/red payload types.
fn red_source(source_id: u32) -> Option<TextSourceConfig> {
    Some(TextSourceConfig {
        source_id,
        t140_payload_type: 98,
        red_payload_type: Some(99),
    })
}

/// Drive `cycles` push+flush cycles over `participants` text talkers and return the allocations the
/// measured loop made. Every participant types a fixed increment each cycle, so once the redundancy
/// ring and every scratch buffer are warm the sizes are constant — a warm flush must allocate nothing.
fn allocations_over_cycles(participants: usize, cycles: u64) -> usize {
    let mut mixer = TextMixer::new(300);
    for index in 0..participants {
        assert!(mixer.add_participant(red_source(0xA000 + index as u32)));
    }

    // Each cycle every participant types the same 3-byte increment; the mixer distributes it to the
    // other participants (RFC 9071 mix-minus-self).
    let increment = "abc";
    let mut counter = 0u64;
    let cycle = |mixer: &mut TextMixer, counter: &mut u64| {
        for index in 0..participants {
            mixer.push_text(index, increment);
        }
        *counter += 1;
        mixer.flush(*counter);
    };

    // Warm up: the redundancy ring fills over the first MAX_TEXT_REDUNDANCY + 1 flushes, growing the
    // arena / RED buffer to their steady-state size — pay all of that before arming.
    for _ in 0..8 {
        cycle(&mut mixer, &mut counter);
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..cycles {
        cycle(&mut mixer, &mut counter);
        std::hint::black_box(mixer.emits().len());
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));
    after - before
}

#[test]
fn flush_tick_makes_no_heap_allocation() {
    // A small room and a large one (near the 64-participant cap): the per-flush emit count is
    // N × (N − 1), so the 64-party case is exactly where an emit/arena buffer sized for a small room
    // would start reallocating.
    for participants in [3usize, 16, 64] {
        let allocations = allocations_over_cycles(participants, 500);
        assert_eq!(
            allocations, 0,
            "{participants}-party text flush allocated {allocations} times across 500 cycles \
             (must be zero)"
        );
    }
}
