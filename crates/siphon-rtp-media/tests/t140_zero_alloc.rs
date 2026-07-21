//! RED build/parse and T.140 reassembly are per-packet hot paths on an `m=text` leg, so the
//! steady-state loop must do **zero heap allocation** (the repo perf+leak gate). A counting global
//! allocator proves a tight build → parse → reassemble loop allocates nothing once the reused
//! buffers are warm: `RedBuilder::write_into` refills a caller-owned `Vec`, `RedPacket::parse` works
//! on the stack, and `T140Reassembler::on_packet` clears and refills its reused output string.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_media::t140::{RedBuilder, RedGeneration, RedPacket, T140Reassembler};

/// A pass-through allocator that counts allocations on the armed thread only.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting, so the libtest harness's background-thread churn
    // during the same window is not miscounted. `const`-initialised so `alloc` never itself
    // allocates.
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
fn red_build_parse_reassemble_make_no_heap_allocation() {
    // A representative RFC 4103 packet: primary "world" + two redundant generations.
    let generations = [
        RedGeneration {
            payload_type: 98,
            rtp_timestamp: 8000 - 600,
            data: b"hel",
        },
        RedGeneration {
            payload_type: 98,
            rtp_timestamp: 8000 - 300,
            data: b"lo",
        },
    ];
    let builder = RedBuilder {
        primary_payload_type: 98,
        primary_rtp_timestamp: 8000,
        primary_data: b"world",
        redundant: &generations,
    };

    let mut buffer = Vec::with_capacity(64);
    let mut reassembler = T140Reassembler::new();

    // Warm up: grow the reused output buffers to their steady-state capacity before arming, and
    // advance the reassembler past its first-packet path. Sequences are chosen in-order so each
    // packet delivers its primary text (exercising the push path), never wrapping over the window.
    for index in 0..256u32 {
        builder.write_into(&mut buffer).expect("build");
        let _ = RedPacket::parse(&buffer).expect("parse");
        let sequence = index as u16;
        let _ = reassembler
            .on_packet(sequence, index, &buffer, true)
            .expect("reassemble");
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for index in 256..10_256u32 {
        builder.write_into(&mut buffer).expect("build");
        let _ = RedPacket::parse(&buffer).expect("parse");
        let sequence = index as u16;
        let output = reassembler
            .on_packet(sequence, index, &buffer, true)
            .expect("reassemble");
        std::hint::black_box(output.text.len());
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "RED build/parse/reassemble loop allocated {} times across 10000 cycles (must be zero)",
        after - before
    );
}
