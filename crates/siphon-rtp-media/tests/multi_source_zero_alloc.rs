//! The multi-source mixer must do **zero per-frame heap allocation** in steady state: a source
//! sink's `write_pcm` (the media actor's per-packet path) copies into a pooled buffer, and the mixer's
//! tick reads preallocated rings into preallocated scratch and a pooled wire buffer. A counting global
//! allocator proves a tight write, tick, drain and recycle loop allocates nothing after warm-up, for
//! a stereo pair, an eight-source mono mix, and a resampling source.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_media::bridge::multi_source::{plan_multi_source, MultiSourceSink};
use siphon_rtp_media::bridge::protocol::{Encoding, Endianness, MediaFormat};
use siphon_rtp_media::fanout::MediaSink;

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting. A *global* counter would also catch the libtest
    // harness's background-thread allocations that land inside the measured window — spurious on a
    // slow (CI) runner. `const`-initialised so accessing it in `alloc` never itself allocates.
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

fn format(sample_rate: u32, channels: u8) -> MediaFormat {
    MediaFormat {
        encoding: Encoding::L16,
        sample_rate,
        channels,
        bit_depth: 16,
        endianness: Endianness::Little,
        ptime: 20,
    }
}

fn measure(sample_rate: u32, channels: u8, sources: usize, resample_first: bool, in_len: usize) {
    const FRAMES: usize = 2_000;
    let mut plan = plan_multi_source(format(sample_rate, channels), sources).expect("plan");
    let mut sinks: Vec<MultiSourceSink> = (0..sources)
        .map(|index| {
            let resampler = (resample_first && index == 0).then(|| {
                siphon_rtp_dsp::resample::Resampler::new(8_000, sample_rate).expect("resampler")
            });
            plan.control.sink(index, resampler, "rec-1").expect("sink")
        })
        .collect();
    let pcm_native = vec![1234i16; sample_rate as usize / 50];
    let pcm_first = vec![1234i16; in_len];
    let cycle = |plan: &mut siphon_rtp_media::bridge::multi_source::MultiSourcePlan,
                 sinks: &mut Vec<MultiSourceSink>| {
        for (index, sink) in sinks.iter_mut().enumerate() {
            if resample_first && index == 0 {
                sink.write_pcm(&pcm_first);
            } else {
                sink.write_pcm(&pcm_native);
            }
        }
        assert!(plan.mixer.tick());
        while let Ok(frame) = plan.frames.try_recv() {
            std::hint::black_box(frame.len());
            plan.recycle.send(frame).expect("recycle");
        }
    };
    for _ in 0..200 {
        cycle(&mut plan, &mut sinks);
    }
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..FRAMES {
        cycle(&mut plan, &mut sinks);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));
    assert!(plan.stats.forwarded() > FRAMES as u64);
    assert_eq!(
        after,
        before,
        "{sources} sources at {sample_rate} Hz allocated {} times across {FRAMES} frames (must be zero)",
        after - before
    );
}

#[test]
fn a_stereo_pair_makes_no_heap_allocation_per_frame() {
    measure(8000, 2, 2, false, 160);
}

#[test]
fn an_eight_source_mono_mix_makes_no_heap_allocation_per_frame() {
    measure(8000, 1, 8, false, 160);
}

#[test]
fn a_resampling_source_makes_no_heap_allocation_per_frame() {
    // An 8 kHz leg into a 16 kHz recording.
    measure(16_000, 2, 2, true, 160);
}
