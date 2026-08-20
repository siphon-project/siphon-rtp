//! The record-tone detector runs on the media path, so it must do **zero per-frame heap allocation**
//! (a performance invariant): the STFT work buffers, the √Hann WOLA ring and the `i16`→`f32` scratch
//! are all preallocated in `RecordToneDetector::new`, and an oversized caller frame is fed to the
//! STFT in `frame_len` blocks rather than growing the scratch. A counting global allocator proves a
//! tight `process` loop allocates nothing after warm-up. Mirrors `ns_zero_alloc` / the media crate's
//! `mixer_zero_alloc` pattern.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_dsp::RecordToneDetector;

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

/// A tone burst / silence alternation, so the run and cadence state machines are both exercised
/// inside the measured loop (a detection that allocated only on the firing frame would slip past a
/// silence-only probe).
fn tone_and_silence(rate: u32, frame_len: usize) -> Vec<Vec<i16>> {
    let mut frames = Vec::new();
    let mut phase = 0.0f32;
    let step = 2.0 * std::f32::consts::PI * 1000.0 / rate as f32;
    // 20 frames of tone (400 ms), then 20 of silence — repeated by the caller's loop.
    for index in 0..40 {
        let mut frame = vec![0i16; frame_len];
        if index < 20 {
            for slot in frame.iter_mut() {
                *slot = (8000.0 * phase.sin()) as i16;
                phase += step;
            }
        }
        frames.push(frame);
    }
    frames
}

fn assert_zero_alloc_process(rate: u32, frame_len: usize) {
    let mut detector = RecordToneDetector::new(rate).expect("build");
    let frames = tone_and_silence(rate, frame_len);

    // Warm up so any one-time lazy init is paid before we sample.
    for frame in &frames {
        detector.process(frame);
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..50 {
        for frame in &frames {
            std::hint::black_box(detector.process(std::hint::black_box(frame)));
        }
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

#[test]
fn an_oversized_frame_makes_no_heap_allocation_either() {
    // A caller handing in a 100 ms block must still not reallocate the scratch — `process` chunks it.
    let mut detector = RecordToneDetector::new(8_000).expect("build");
    let block: Vec<i16> = (0..800)
        .map(|index| {
            (8000.0 * (2.0 * std::f32::consts::PI * 1000.0 * index as f32 / 8000.0).sin()) as i16
        })
        .collect();
    for _ in 0..8 {
        detector.process(&block);
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..500 {
        std::hint::black_box(detector.process(std::hint::black_box(&block)));
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "an oversized frame allocated {} times (must be zero)",
        after - before
    );
}
