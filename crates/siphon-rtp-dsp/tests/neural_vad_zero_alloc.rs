//! The neural VAD must do **zero heap allocation per window** and per fed frame.
//!
//! It runs once per 32 ms per concurrent call, so an allocation here is an allocation per call per
//! 32 ms — the exact shape of churn that makes a media plane jitter under load. Every tensor, every
//! ping-pong activation buffer, the resampler scratch and the window accumulator are all
//! preallocated in the constructors; the ~1.2 MB of parameters is decoded once for the whole
//! process and shared by reference, so a second detector allocates only its own scratch.
//!
//! Same counting-allocator pattern as `ns_zero_alloc` and the media crate's `mixer_zero_alloc`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_dsp::{NeuralVad, NeuralVadStream, VoiceDetector, NEURAL_VAD_WINDOW_SAMPLES};

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting; a global counter would also catch the libtest
    // harness's background-thread allocations. `const`-initialised so reading it never allocates.
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

/// Deterministic non-silent PCM from a fixed-seed LCG — never `rand`, never a clock.
fn deterministic_pcm(length: usize, seed: u32) -> Vec<i16> {
    let mut lcg = seed;
    (0..length)
        .map(|_| {
            lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            ((lcg >> 8) as i32 % 12_000 - 6_000) as i16
        })
        .collect()
}

fn measure(mut body: impl FnMut()) -> usize {
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    body();
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));
    after - before
}

#[test]
fn a_window_through_the_network_allocates_nothing() {
    let mut detector = NeuralVad::new();
    let window = deterministic_pcm(NEURAL_VAD_WINDOW_SAMPLES, 0x0BAD_F00D);

    // Warm up: the first call decodes the process-wide parameters.
    for _ in 0..4 {
        detector.speech_probability(&window).expect("window");
    }

    let allocations = measure(|| {
        for _ in 0..500 {
            let probability = detector.speech_probability(&window).expect("window");
            std::hint::black_box(probability);
        }
    });
    assert_eq!(
        allocations, 0,
        "the forward pass allocated {allocations} times across 500 windows (must be zero)"
    );
}

#[test]
fn the_wideband_stream_adapter_allocates_nothing_per_frame() {
    let mut stream = NeuralVadStream::new(16_000).expect("build");
    let frame = deterministic_pcm(320, 0x1234_ABCD);
    for _ in 0..8 {
        stream.is_speech(&frame);
    }

    let allocations = measure(|| {
        for _ in 0..1_000 {
            std::hint::black_box(stream.is_speech(&frame));
        }
    });
    assert_eq!(
        allocations, 0,
        "the 16 kHz stream adapter allocated {allocations} times across 1000 frames"
    );
}

#[test]
fn the_narrowband_stream_adapter_allocates_nothing_per_frame() {
    // The resampling path: `Resampler::process` appends into a reused, pre-reserved vector, so the
    // 8 → 16 kHz conversion must not grow it after warm-up either.
    let mut stream = NeuralVadStream::new(8_000).expect("build");
    let frame = deterministic_pcm(160, 0x5555_AAAA);
    for _ in 0..8 {
        stream.is_speech(&frame);
    }

    let allocations = measure(|| {
        for _ in 0..1_000 {
            std::hint::black_box(stream.is_speech(&frame));
        }
    });
    assert_eq!(
        allocations, 0,
        "the 8 kHz stream adapter allocated {allocations} times across 1000 frames"
    );
}

#[test]
fn a_long_ptime_frame_does_not_grow_the_accumulator() {
    // 120 ms is the bridge's ptime ceiling; the accumulator must swallow it whole without growing.
    let mut stream = NeuralVadStream::new(16_000).expect("build");
    let frame = deterministic_pcm(1_920, 0x7777_3333);
    for _ in 0..4 {
        stream.is_speech(&frame);
    }

    let allocations = measure(|| {
        for _ in 0..200 {
            std::hint::black_box(stream.is_speech(&frame));
        }
    });
    assert_eq!(
        allocations, 0,
        "a 120 ms frame allocated {allocations} times across 200 frames"
    );
}

#[test]
fn the_detector_enum_allocates_nothing_per_frame_on_either_variant() {
    let frame = deterministic_pcm(320, 0x9999_1111);
    for mut detector in [
        VoiceDetector::energy(1_000_000, 5),
        VoiceDetector::neural(16_000).expect("build"),
    ] {
        for _ in 0..8 {
            detector.is_speech(&frame);
        }
        let allocations = measure(|| {
            for _ in 0..500 {
                std::hint::black_box(detector.is_speech(&frame));
            }
        });
        assert_eq!(
            allocations,
            0,
            "VoiceDetector (neural: {}) allocated {allocations} times across 500 frames",
            detector.is_neural()
        );
    }
}

#[test]
fn a_second_detector_does_not_re_decode_the_shared_parameters() {
    // Construction is not a hot path, but the parameter blob must be process-wide: a per-leg copy
    // would be 1.2 MB per concurrent call. Building a detector after warm-up must allocate only its
    // own scratch — a handful of vectors, nowhere near the ~1500 allocations a fresh decode makes.
    let warm = NeuralVad::new();
    std::hint::black_box(&warm);

    let allocations = measure(|| {
        let detector = NeuralVad::new();
        std::hint::black_box(&detector);
    });
    assert!(
        allocations <= 16,
        "constructing a second detector made {allocations} allocations — the parameters are \
         probably being decoded per instance instead of once per process"
    );
}
