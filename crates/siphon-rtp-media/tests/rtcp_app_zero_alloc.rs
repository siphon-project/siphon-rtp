//! The RTCP APP reader and builder run once per MCPTT floor message, and once per seat when a floor
//! message goes to a whole room, so they must do **zero heap allocation**: the reader borrows from
//! the datagram and the builder writes into a caller-owned buffer. A counting global allocator
//! proves a tight write → read loop allocates nothing.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_media::rtcp::{app_packets, write_app};

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
fn write_and_read_make_no_heap_allocation() {
    // Floor Granted fields (3GPP TS 24.380 §8.2.5): Duration, Audio SSRC of Granted Participant.
    let data = [
        0x01, 0x02, 0x00, 0x1E, 0x0E, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
    ];
    // Two messages back to back in one datagram (TS 24.380 §8.1.1).
    let mut datagram = [0u8; 48];

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for ssrc in 0..10_000u32 {
        let first = write_app(17, ssrc, *b"MCPT", &data, &mut datagram).expect("write");
        let second = write_app(0, ssrc, *b"MCPT", &data, &mut datagram[first..]).expect("write");
        for app in app_packets(&datagram[..first + second]) {
            std::hint::black_box(app.expect("valid"));
        }
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "RTCP APP loop allocated {} times across 10000 cycles (must be zero)",
        after - before
    );
}
