//! Zero-per-frame-allocation gate for the G.729 hot paths, in both directions (a performance
//! invariant).
//!
//! `cargo test -p siphon-rtp-codec --features g729 --test g729_zero_alloc`
//!
//! Unlike a jemalloc `stats.allocated` byte-delta (which moves in coarse arena-sized steps and so
//! is too noisy to gate a hot loop on a shared CI runner), a **counting** global allocator measures
//! exactly what the invariant is about: the number of calls into the allocator. A correct codec core
//! writes into caller-owned buffers and keeps its analysis-by-synthesis scratch on the encoder state,
//! so a warmed-up encode loop must make **zero** allocations. Allocate-then-free churn (invisible to a
//! live-bytes delta) still shows up here, so this gate is strictly stronger.
#![cfg(feature = "g729")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_codec::g729::{G729Decoder, G729Encoder};

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

/// A 10 ms frame of something the voice-activity decision calls speech, varying with `index` so a
/// long loop is not one frame repeated.
fn speech_frame(index: usize) -> [i16; 80] {
    std::array::from_fn(|i| {
        let t = (index * 80 + i) as f32;
        let voiced = (t * 0.21).sin() + 0.6 * (t * 0.63).sin();
        (voiced * 9000.0) as i16
    })
}

#[test]
fn g729_encode_makes_no_heap_allocation() {
    let mut encoder = G729Encoder::new();
    let mut index = 0_usize;

    // Warm up so any one-time lazy init is paid before the sample window.
    for _ in 0..2_000 {
        encoder.encode(&speech_frame(index));
        index += 1;
    }

    let allocations = count_allocations(30_000, || {
        encoder.encode(&speech_frame(index));
        index += 1;
    });

    assert_eq!(
        allocations, 0,
        "G.729 encode allocated {allocations} times across 30k frames (must be zero)"
    );
}

#[test]
fn g729_decode_makes_no_heap_allocation() {
    // Encode first so the decoder is fed real frames rather than a constant pattern, which would
    // exercise only the quietest path through the excitation.
    let mut encoder = G729Encoder::new();
    let frames: Vec<[u8; 10]> = (0..1_000)
        .map(|i| encoder.encode(&speech_frame(i)))
        .collect();

    let mut decoder = G729Decoder::new();
    let mut index = 0_usize;
    for _ in 0..2_000 {
        decoder
            .decode(&frames[index % frames.len()])
            .expect("decode");
        index += 1;
    }

    let allocations = count_allocations(30_000, || {
        decoder
            .decode(&frames[index % frames.len()])
            .expect("decode");
        index += 1;
    });

    assert_eq!(
        allocations, 0,
        "G.729 decode allocated {allocations} times across 30k frames (must be zero)"
    );
}

#[test]
fn g729_concealment_makes_no_heap_allocation() {
    // The path a lossy call spends real time on, and the one least likely to be measured.
    let mut decoder = G729Decoder::new();
    for _ in 0..2_000 {
        decoder.conceal();
    }
    let allocations = count_allocations(30_000, || {
        decoder.conceal();
    });
    assert_eq!(
        allocations, 0,
        "G.729 concealment allocated {allocations} times across 30k frames (must be zero)"
    );
}

#[test]
fn g729_annex_b_makes_no_heap_allocation_in_either_direction() {
    // Discontinuous transmission runs for as long as a call is on hold, so the comfort-noise path is
    // the one a quiet call spends nearly all its time in — and it is a different path through the
    // encoder and the decoder both.
    let mut encoder = G729Encoder::new();
    encoder.set_discontinuous_transmission(true);
    let mut decoder = G729Decoder::new();

    let silence = [0_i16; 80];
    for _ in 0..2_000 {
        let _ = encoder.encode_frame(&silence);
        let _ = decoder.decode_untransmitted();
    }

    let allocations = count_allocations(30_000, || {
        let _ = encoder.encode_frame(&silence);
        let _ = decoder.decode_untransmitted();
    });

    assert_eq!(
        allocations, 0,
        "the Annex B path allocated {allocations} times across 30k frames (must be zero)"
    );
}
