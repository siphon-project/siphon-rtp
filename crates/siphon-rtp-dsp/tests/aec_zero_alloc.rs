//! The echo canceller must do **zero per-frame heap allocation** on the hot path (a performance
//! invariant): the adaptive filter weights, the far-end delay ring, and all scratch live on the
//! [`EchoCanceller`], sized once in `new`. A counting global allocator proves a tight `cancel` loop
//! allocates nothing after warm-up.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_dsp::EchoCanceller;

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
fn cancel_frame_makes_no_heap_allocation() {
    const TAIL: usize = 256;
    const FRAME: usize = 160; // 8 kHz / 20 ms

    // Setup (allocates freely) — the canceller's state and the reusable frame buffers.
    let mut canceller = EchoCanceller::new(8_000, TAIL).expect("build");
    let reference: Vec<i16> = (0..FRAME)
        .map(|index| ((index as i16).wrapping_mul(211)).wrapping_sub(3_000))
        .collect();
    let source: Vec<i16> = (0..FRAME)
        .map(|index| ((index as i16).wrapping_mul(97)).wrapping_add(500))
        .collect();
    let mut near = source.clone();

    // Warm up one frame so any one-time lazy init is paid before we sample.
    canceller.cancel(&mut near, &reference);

    // Arm counting on *this* thread only, so the sample is the cancel loop's own allocations — not
    // the libtest harness's background-thread churn during the same window.
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..2_000 {
        // Refresh the near-end in place (no allocation) so cancel operates on a fresh frame.
        near.copy_from_slice(&source);
        canceller.cancel(&mut near, &reference);
        std::hint::black_box(near[0]);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "cancel allocated {} times across 2000 frames (must be zero)",
        after - before
    );
}

/// The two-path (foreground/background) + NCC path is also zero per-frame heap: the second (foreground)
/// filter and the copy are `copy_from_slice` into a buffer preallocated in `new`, and the NCC
/// accumulators are stack scalars — no allocation anywhere on the hot path, on either a single-talk
/// (copy-firing) or a double-talk (frozen) frame. This drives both regimes inside the measured window.
#[test]
fn cancel_two_path_makes_no_heap_allocation() {
    const TAIL: usize = 256;
    const FRAME: usize = 160; // 8 kHz / 20 ms

    let mut canceller = EchoCanceller::new(8_000, TAIL)
        .expect("build")
        .with_two_path_dtd();
    // An echo-like reference (single-talk → copies fire) and a loud near-end (double-talk → frozen).
    let reference: Vec<i16> = (0..FRAME)
        .map(|index| ((index as i16).wrapping_mul(211)).wrapping_sub(3_000))
        .collect();
    let echo_only: Vec<i16> = reference.iter().map(|&sample| sample / 4).collect();
    let near_end_talk: Vec<i16> = (0..FRAME)
        .map(|index| ((index as i16).wrapping_mul(157)).wrapping_add(9_000))
        .collect();
    let mut near = echo_only.clone();

    // Warm up (lets the foreground copy in, so both the copy and no-copy branches run under measurement).
    for _ in 0..8 {
        near.copy_from_slice(&echo_only);
        canceller.cancel(&mut near, &reference);
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for cycle in 0..2_000 {
        // Alternate single-talk and double-talk frames so both decision branches are measured.
        if cycle % 2 == 0 {
            near.copy_from_slice(&echo_only);
        } else {
            near.copy_from_slice(&near_end_talk);
        }
        canceller.cancel(&mut near, &reference);
        std::hint::black_box(near[0]);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "two-path cancel allocated {} times across 2000 frames (must be zero)",
        after - before
    );
}

/// The GCC-PHAT delay-estimation path is also zero per-frame heap: the estimation block, spectra,
/// cross-power, correlation, and accumulator are all preallocated in `with_delay_estimation`, and the
/// real FFT/IFFT are allocation-free — so even the frames on which a full GCC block fires allocate
/// nothing. The measured window spans many blocks so the FFT path is exercised inside it.
#[test]
fn cancel_with_delay_estimation_makes_no_heap_allocation() {
    const TAIL: usize = 160;
    const FRAME: usize = 160; // 8 kHz / 20 ms
    const SEARCH_RANGE: usize = 512; // → 1024-point GCC blocks, one every ~6.4 frames

    let mut canceller =
        siphon_rtp_dsp::EchoCanceller::with_delay_estimation(8_000, TAIL, SEARCH_RANGE)
            .expect("build");
    let reference: Vec<i16> = (0..FRAME)
        .map(|index| ((index as i16).wrapping_mul(211)).wrapping_sub(3_000))
        .collect();
    let source: Vec<i16> = (0..FRAME)
        .map(|index| ((index as i16).wrapping_mul(97)).wrapping_add(500))
        .collect();
    let mut near = source.clone();

    // Warm up enough frames to fill and process several estimation blocks (so the estimator has
    // locked and any one-time init is paid) before we sample.
    for _ in 0..64 {
        near.copy_from_slice(&source);
        canceller.cancel(&mut near, &reference);
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..2_000 {
        near.copy_from_slice(&source);
        canceller.cancel(&mut near, &reference);
        std::hint::black_box(near[0]);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "cancel-with-estimation allocated {} times across 2000 frames (must be zero)",
        after - before
    );
}

/// The MDF / partitioned-block frequency-domain backend is also zero per-frame heap: the `K` partition
/// weight spectra, the reference-spectrum delay line, the per-bin delay-line power, all FFT scratch, and
/// the block-assembly / output rings are preallocated in `with_mdf`, and the real FFT/IFFT are
/// allocation-free — so even the frames on which one or two overlap-save blocks fire (each running the
/// filter FFT + `K` per-partition gradient-constraint IFFT/FFT pairs) allocate nothing. Runs the
/// two-path variant so the per-block NCC path is measured too.
#[test]
fn cancel_mdf_makes_no_heap_allocation() {
    const TAIL: usize = 1024; // 8 partitions of 128 @ 8 kHz
    const FRAME: usize = 160; // 8 kHz / 20 ms

    let mut canceller = EchoCanceller::with_mdf(8_000, TAIL)
        .expect("build")
        .with_two_path_dtd();
    let reference: Vec<i16> = (0..FRAME)
        .map(|index| ((index as i16).wrapping_mul(211)).wrapping_sub(3_000))
        .collect();
    let echo_only: Vec<i16> = reference.iter().map(|&sample| sample / 4).collect();
    let mut near = echo_only.clone();

    // Warm up enough frames that the block/output rings and the two-path bootstrap have settled and any
    // one-time init is paid before we sample.
    for _ in 0..32 {
        near.copy_from_slice(&echo_only);
        canceller.cancel(&mut near, &reference);
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..2_000 {
        near.copy_from_slice(&echo_only);
        canceller.cancel(&mut near, &reference);
        std::hint::black_box(near[0]);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "MDF cancel allocated {} times across 2000 frames (must be zero)",
        after - before
    );
}

/// The MDF + GCC-PHAT delay-estimation path is zero per-frame heap too: on top of the MDF state, the
/// estimation block/spectra/correlation are preallocated in `with_mdf_delay_estimation`, so the frames
/// on which a GCC block fires (and a committed re-align re-slices the alignment ring) still allocate
/// nothing.
#[test]
fn cancel_mdf_with_delay_estimation_makes_no_heap_allocation() {
    const TAIL: usize = 512;
    const FRAME: usize = 160;
    const SEARCH_RANGE: usize = 512;

    let mut canceller =
        EchoCanceller::with_mdf_delay_estimation(8_000, TAIL, SEARCH_RANGE).expect("build");
    let reference: Vec<i16> = (0..FRAME)
        .map(|index| ((index as i16).wrapping_mul(211)).wrapping_sub(3_000))
        .collect();
    let source: Vec<i16> = (0..FRAME)
        .map(|index| ((index as i16).wrapping_mul(97)).wrapping_add(500))
        .collect();
    let mut near = source.clone();

    for _ in 0..64 {
        near.copy_from_slice(&source);
        canceller.cancel(&mut near, &reference);
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..2_000 {
        near.copy_from_slice(&source);
        canceller.cancel(&mut near, &reference);
        std::hint::black_box(near[0]);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "MDF cancel-with-estimation allocated {} times across 2000 frames (must be zero)",
        after - before
    );
}

/// The chained residual-echo suppressor is zero per-frame heap too: both WOLA rings, the FFT scratch,
/// the per-bin leakage / smoothing / gain state, the per-hop echo-power queue, and the near-snapshot /
/// echo-estimate scratch on the canceller are all preallocated in `with_residual_suppression` /
/// `new`, and the real FFT/IFFT hops the post-filter runs are allocation-free — so a tight cancel loop
/// with the RES on allocates nothing after warm-up. Driven with an echo-like near-end so the RES's
/// suppression path (leakage update + per-bin gain) is exercised inside the measured window.
#[test]
fn cancel_with_residual_suppression_makes_no_heap_allocation() {
    const TAIL: usize = 256;
    const FRAME: usize = 160; // 8 kHz / 20 ms

    let mut canceller = EchoCanceller::new(8_000, TAIL)
        .expect("build")
        .with_residual_suppression()
        .expect("res");
    let reference: Vec<i16> = (0..FRAME)
        .map(|index| ((index as i16).wrapping_mul(211)).wrapping_sub(3_000))
        .collect();
    // An echo-like near-end (a scaled copy of the reference) so the residual carries residual echo the
    // RES suppresses — driving the leakage-update and gain branches under measurement.
    let echo_like: Vec<i16> = reference.iter().map(|&sample| sample / 4).collect();
    let mut near = echo_like.clone();

    // Warm up so the RES seeds its state and any one-time lazy init is paid before we sample.
    for _ in 0..16 {
        near.copy_from_slice(&echo_like);
        canceller.cancel(&mut near, &reference);
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..2_000 {
        near.copy_from_slice(&echo_like);
        canceller.cancel(&mut near, &reference);
        std::hint::black_box(near[0]);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "cancel-with-residual-suppression allocated {} times across 2000 frames (must be zero)",
        after - before
    );
}
