//! The Ogg Opus writer allocates nothing per frame once it is running: the staging frame, the
//! packet buffer and the page body are all preallocated, and the caller's output buffer keeps its
//! capacity across pages. It runs in a recording's writer task rather than on the media path, but a
//! recording lasts as long as a call, so a per-frame allocation would be one per 20 ms for hours.
//!
//! A counting global allocator proves a tight push loop — paging included — allocates nothing after
//! warm-up, for mono and stereo.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_media::ogg_opus::{OggOpusConfig, OggOpusWriter};

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting, so the harness's own threads never land in a window.
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

// SAFETY: every call delegates straight to the system allocator; we only bump a relaxed counter,
// and only when the current thread has armed counting.
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

fn assert_no_allocation_per_frame(rate: u32, channels: u8) {
    let mut writer = OggOpusWriter::new(OggOpusConfig {
        sample_rate_hz: rate,
        channels,
        bitrate_bps: 16_000 * u32::from(channels),
        serial: 7,
        vendor: "zero-alloc",
    })
    .expect("writer");
    let frame = (rate / 50) as usize * usize::from(channels);
    let pcm: Vec<i16> = (0..frame)
        .map(|index| ((index * 37) % 4000) as i16)
        .collect();
    let mut out = Vec::with_capacity(256 * 1024);
    writer.write_headers(&mut out).expect("headers");
    // Warm up past the first few pages.
    for _ in 0..200 {
        out.clear();
        writer.push(&pcm, &mut out).expect("push");
    }

    ALLOCATIONS.store(0, Ordering::Relaxed);
    ARMED.with(|armed| armed.set(true));
    for _ in 0..1_000 {
        out.clear();
        writer.push(&pcm, &mut out).expect("push");
    }
    ARMED.with(|armed| armed.set(false));
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "{rate} Hz × {channels}: 1000 frames, 20 pages, no allocation"
    );
}

#[test]
fn a_mono_ogg_opus_stream_makes_no_heap_allocation_per_frame() {
    assert_no_allocation_per_frame(8_000, 1);
}

#[test]
fn a_stereo_ogg_opus_stream_makes_no_heap_allocation_per_frame() {
    assert_no_allocation_per_frame(16_000, 2);
}
