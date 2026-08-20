//! The WebSocket tee's sink must do **zero per-frame heap allocation** on the media hot path
//! (`MediaSink::write_pcm` runs on the pipeline actor's per-packet path): the channel rings, the
//! interleave/mix scratch, and the wire buffers are all preallocated, and the wire buffers are
//! recycled back from the transport task rather than freshly allocated. A counting global allocator
//! proves a tight drain-and-recycle loop allocates nothing after warm-up.
//!
//! Both shapes are measured: a single-leg monologue and a stereo (both-legs) tee, whose emit path also
//! runs the interleave.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_media::bridge::protocol::{Encoding, Endianness, MediaFormat};
use siphon_rtp_media::bridge::tee::{plan_ws_tee, TeeChannel, WsTeeSink};
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
    format_at(sample_rate, channels, 20)
}

fn format_at(sample_rate: u32, channels: u8, ptime: u8) -> MediaFormat {
    MediaFormat {
        encoding: Encoding::L16,
        sample_rate,
        channels,
        bit_depth: 16,
        endianness: Endianness::Little,
        ptime,
    }
}

#[test]
fn a_monologue_tee_write_pcm_makes_no_heap_allocation() {
    const FRAMES: usize = 2_000;
    let plan = plan_ws_tee(format(8000, 1), false, false);
    let mut sink = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee-1", None);
    let pcm = [4321i16; 160]; // 8 kHz / 20 ms

    // Warm up past the primed pool so every later frame reuses a recycled buffer.
    for _ in 0..64 {
        sink.write_pcm(&pcm);
        let frame = plan.frames.try_recv().expect("drained");
        plan.recycle.send(frame).expect("recycle");
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..FRAMES {
        sink.write_pcm(&pcm);
        // Drain + recycle exactly as the transport task does, inside the measured window.
        let frame = plan.frames.try_recv().expect("drained");
        std::hint::black_box(frame.len());
        plan.recycle.send(frame).expect("recycle");
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "monologue tee allocated {} times across {FRAMES} frames (must be zero)",
        after - before
    );
}

#[test]
fn a_stereo_tee_write_pcm_makes_no_heap_allocation() {
    const FRAMES: usize = 2_000;
    let plan = plan_ws_tee(format(8000, 2), true, false);
    let mut caller = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee-1", None);
    let mut callee = WsTeeSink::new(TeeChannel::Callee, plan.mixer.clone(), "tee-1", None);
    let near = [1000i16; 160];
    let far = [-1000i16; 160];

    for _ in 0..64 {
        caller.write_pcm(&near);
        callee.write_pcm(&far);
        let frame = plan.frames.try_recv().expect("drained");
        plan.recycle.send(frame).expect("recycle");
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..FRAMES {
        caller.write_pcm(&near);
        callee.write_pcm(&far);
        let frame = plan.frames.try_recv().expect("drained");
        std::hint::black_box(frame.len());
        plan.recycle.send(frame).expect("recycle");
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "stereo tee allocated {} times across {FRAMES} frames (must be zero)",
        after - before
    );
}

/// The same invariant on a **long-ptime** tee: 48 kHz at `a=ptime:60` (2880 samples per frame), the
/// shape a WebRTC/Opus peer produces. The rings and scratch are sized from the negotiated frame, not
/// from a 20 ms assumption, so a longer frame is still assembled without touching the heap.
#[test]
fn a_long_ptime_tee_write_pcm_makes_no_heap_allocation() {
    const FRAMES: usize = 500;
    const FRAME_SAMPLES: usize = 2880; // 48 kHz × 60 ms
    let plan = plan_ws_tee(format_at(48_000, 1, 60), false, false);
    let mut sink = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "tee-1", None);
    let pcm = [4321i16; FRAME_SAMPLES];

    for _ in 0..64 {
        sink.write_pcm(&pcm);
        let frame = plan.frames.try_recv().expect("drained");
        assert_eq!(frame.len(), 2 * FRAME_SAMPLES, "the whole 60 ms frame");
        plan.recycle.send(frame).expect("recycle");
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..FRAMES {
        sink.write_pcm(&pcm);
        let frame = plan.frames.try_recv().expect("drained");
        std::hint::black_box(frame.len());
        plan.recycle.send(frame).expect("recycle");
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "long-ptime tee allocated {} times across {FRAMES} frames (must be zero)",
        after - before
    );
}

/// A **resampling** long-ptime sink: a 48 kHz leg feeding a 16 kHz tee at 60 ms. The resample scratch
/// is sized from the tee's output rate and the ptime ceiling, so the conversion never grows it on the
/// hot path.
#[test]
fn a_resampling_long_ptime_tee_write_pcm_makes_no_heap_allocation() {
    const FRAMES: usize = 500;
    let plan = plan_ws_tee(format_at(16_000, 1, 60), false, false);
    let resampler = siphon_rtp_dsp::resample::Resampler::new(48_000, 16_000).expect("resampler");
    let mut sink = WsTeeSink::new(
        TeeChannel::Caller,
        plan.mixer.clone(),
        "tee-1",
        Some(resampler),
    );
    let pcm = [4321i16; 2880]; // 48 kHz × 60 ms in, 960 samples out

    for _ in 0..64 {
        sink.write_pcm(&pcm);
        while let Ok(frame) = plan.frames.try_recv() {
            plan.recycle.send(frame).expect("recycle");
        }
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..FRAMES {
        sink.write_pcm(&pcm);
        while let Ok(frame) = plan.frames.try_recv() {
            std::hint::black_box(frame.len());
            plan.recycle.send(frame).expect("recycle");
        }
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "resampling long-ptime tee allocated {} times across {FRAMES} frames (must be zero)",
        after - before
    );
}

/// The **upsampling** sink: an 8 kHz leg teed at 16 kHz, the shape a controller asks for when it
/// wants wideband audio out of a narrowband call. The resample scratch is sized from the tee's output
/// rate, so producing *more* samples than came in still never grows a buffer on the media path.
#[test]
fn an_upsampling_tee_write_pcm_makes_no_heap_allocation() {
    const FRAMES: usize = 2_000;
    let plan = plan_ws_tee(format(16_000, 1), false, false);
    let resampler = siphon_rtp_dsp::resample::Resampler::new(8_000, 16_000).expect("resampler");
    let mut sink = WsTeeSink::new(
        TeeChannel::Caller,
        plan.mixer.clone(),
        "tee-1",
        Some(resampler),
    );
    let pcm = [4321i16; 160]; // 8 kHz x 20 ms in, 320 samples out

    for _ in 0..64 {
        sink.write_pcm(&pcm);
        while let Ok(frame) = plan.frames.try_recv() {
            assert_eq!(frame.len(), 640, "16 kHz x 20 ms mono L16");
            plan.recycle.send(frame).expect("recycle");
        }
    }

    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..FRAMES {
        sink.write_pcm(&pcm);
        while let Ok(frame) = plan.frames.try_recv() {
            std::hint::black_box(frame.len());
            plan.recycle.send(frame).expect("recycle");
        }
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));

    assert_eq!(
        after,
        before,
        "upsampling tee allocated {} times across {FRAMES} frames (must be zero)",
        after - before
    );
}
