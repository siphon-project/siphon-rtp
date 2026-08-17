//! Zero-per-frame-allocation gate for the CELT encode hot path (a performance invariant).
//!
//! `cargo test -p siphon-rtp-codec --test celt_zero_alloc`
//!
//! Its own test binary because a process may have only one `#[global_allocator]`.
//!
//! Unlike a jemalloc `stats.allocated` byte-delta (which moves in coarse arena-sized steps and so is
//! too noisy to gate a hot loop on a shared CI runner), a **counting** global allocator measures
//! exactly what the invariant is about: the number of calls into the allocator. The CELT encoder
//! writes into a caller-owned payload buffer and keeps every scratch buffer — the pre-emphasised
//! input, the prefilter history, the MDCT spectrum, the normalised bands, the per-band allocation
//! arrays — on its own state or on the stack, so a warmed-up encode loop must make **zero**
//! allocations. Allocate-then-free churn (invisible to a live-bytes delta) still shows up here, so
//! this gate is strictly stronger.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use siphon_rtp_codec::opus::celt::decoder::CeltDecoder;
use siphon_rtp_codec::opus::celt::encoder::{CeltEncoder, RateControl};

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

thread_local! {
    // Both the arm flag *and* the counter are thread-local: libtest runs the tests in this binary
    // concurrently, and a global counter would let one test's allocations be charged to another's
    // measurement window. `const`-initialised so touching them inside `alloc` never itself allocates
    // (no lazy Key / destructor registration) — re-entrancy-safe.
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call delegates straight to the system allocator; we only bump a thread-local
// counter, and only when the current thread has armed counting.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            ALLOCATIONS.with(|c| c.set(c.get() + 1));
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
    let before = ALLOCATIONS.with(Cell::get);
    for _ in 0..iterations {
        body();
    }
    let after = ALLOCATIONS.with(Cell::get);
    ARMED.with(|armed| armed.set(false));
    after - before
}

/// A deterministic 48 kHz signal in `[-1, 1)` — harmonics plus a little noise, so the encoder's
/// analysis takes realistic branches rather than the degenerate silence path.
fn celt_signal(samples: usize) -> Vec<f32> {
    let mut state = 0x5EED_u32;
    (0..samples)
        .map(|i| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let noise = ((state >> 16) as f32 / 32768.0 - 1.0) * 0.02;
            let t = i as f32;
            0.35 * (t * 0.031).sin() + 0.18 * (t * 0.097).sin() + 0.07 * (t * 0.21).cos() + noise
        })
        .collect()
}

/// Every CELT frame size, both rate-control modes with a rate target, and both the transient and the
/// steady path (the signal contains both) — a frame that allocated on any of those branches would
/// show up here.
#[test]
fn celt_encode_makes_no_heap_allocation_per_frame() {
    for &frame_size in &[120usize, 240, 480, 960] {
        for &rate_control in &[
            RateControl::ConstantBitrate,
            RateControl::ConstrainedVbr,
            RateControl::Vbr,
        ] {
            let signal = celt_signal(frame_size * 16);
            let mut encoder = CeltEncoder::new().expect("build CELT encoder");
            encoder.set_bitrate(64_000);
            encoder.set_rate_control(rate_control);
            // The caller owns the payload buffer.
            let mut payload = vec![0u8; 1275];

            // Warm up so any one-time lazy init is paid before we sample.
            let mut frame = 0usize;
            let encode_one = |encoder: &mut CeltEncoder, payload: &mut [u8], frame: &mut usize| {
                let lo = (*frame % 16) * frame_size;
                *frame += 1;
                encoder
                    .encode(&signal[lo..lo + frame_size], frame_size, payload)
                    .expect("encode");
            };
            for _ in 0..64 {
                encode_one(&mut encoder, &mut payload, &mut frame);
            }

            let allocations = count_allocations(2_000, || {
                encode_one(&mut encoder, &mut payload, &mut frame);
            });
            assert_eq!(
                allocations, 0,
                "CELT encode ({frame_size} samples, {rate_control:?}) allocated {allocations} \
                 times across 2000 frames (must be zero)"
            );
        }
    }
}

/// Silence takes a different (much shorter) path through the encoder; it must not allocate either.
#[test]
fn celt_encode_of_silence_makes_no_heap_allocation() {
    let frame_size = 960usize;
    let silence = vec![0f32; frame_size];
    let mut encoder = CeltEncoder::new().expect("build");
    encoder.set_bitrate(32_000);
    encoder.set_rate_control(RateControl::Vbr);
    let mut payload = vec![0u8; 1275];
    for _ in 0..64 {
        encoder
            .encode(&silence, frame_size, &mut payload)
            .expect("encode");
    }
    let allocations = count_allocations(2_000, || {
        encoder
            .encode(&silence, frame_size, &mut payload)
            .expect("encode");
    });
    assert_eq!(
        allocations, 0,
        "CELT encode of silence allocated {allocations} times across 2000 frames (must be zero)"
    );
}

/// Interleave a mono signal with a decorrelated copy of itself, so the stereo band coder faces a
/// real mid/side decision rather than the degenerate "both channels identical" one.
fn celt_stereo_signal(samples: usize) -> Vec<f32> {
    let left = celt_signal(samples);
    let right = celt_signal(samples + 7);
    (0..samples)
        .flat_map(|i| [left[i], 0.6 * left[i] + 0.4 * right[i + 7]])
        .collect()
}

/// The same invariant for **stereo**, which adds the mid/side band path, `intensity_stereo`, the
/// second channel's analysis and MDCT, and — at complexity 10 — the theta rate-distortion trial with
/// its coder rollback. The trial's scratch lives on the encoder state precisely so this stays zero.
#[test]
fn celt_stereo_encode_makes_no_heap_allocation_per_frame() {
    for &frame_size in &[120usize, 240, 480, 960] {
        for &complexity in &[5i32, 10] {
            for &rate_control in &[RateControl::ConstantBitrate, RateControl::ConstrainedVbr] {
                let signal = celt_stereo_signal(frame_size * 16);
                let mut encoder = CeltEncoder::with_channels(2).expect("build stereo encoder");
                encoder.set_bitrate(96_000);
                encoder.set_rate_control(rate_control);
                encoder.set_complexity(complexity).expect("complexity");
                let mut payload = vec![0u8; 1275];

                let mut frame = 0usize;
                let encode_one =
                    |encoder: &mut CeltEncoder, payload: &mut [u8], frame: &mut usize| {
                        let lo = (*frame % 16) * frame_size * 2;
                        *frame += 1;
                        encoder
                            .encode(&signal[lo..lo + 2 * frame_size], frame_size, payload)
                            .expect("encode");
                    };
                for _ in 0..64 {
                    encode_one(&mut encoder, &mut payload, &mut frame);
                }

                let allocations = count_allocations(1_000, || {
                    encode_one(&mut encoder, &mut payload, &mut frame);
                });
                assert_eq!(
                    allocations, 0,
                    "stereo CELT encode ({frame_size} samples, complexity {complexity}, \
                     {rate_control:?}) allocated {allocations} times across 1000 frames"
                );
            }
        }
    }
}

/// A warmed-up **stereo** encode + decode round trip, the shape a stereo transcode leg runs at
/// steady state, must not touch the allocator on either side.
#[test]
fn celt_stereo_round_trip_makes_no_heap_allocation_per_frame() {
    for &frame_size in &[120usize, 480, 960] {
        let signal = celt_stereo_signal(frame_size * 8);
        let mut encoder = CeltEncoder::with_channels(2).expect("build");
        encoder.set_bitrate(96_000);
        encoder.set_rate_control(RateControl::ConstrainedVbr);
        let mut decoder = CeltDecoder::with_channels(2).expect("build");
        let mut payload = vec![0u8; 1275];
        let mut pcm = vec![0i16; 2 * frame_size];
        let mut frame = 0usize;
        let round_trip = |encoder: &mut CeltEncoder,
                          decoder: &mut CeltDecoder,
                          payload: &mut Vec<u8>,
                          pcm: &mut Vec<i16>,
                          frame: &mut usize| {
            let lo = (*frame % 8) * frame_size * 2;
            *frame += 1;
            let written = encoder
                .encode(&signal[lo..lo + 2 * frame_size], frame_size, payload)
                .expect("encode");
            decoder
                .decode(&payload[..written], pcm, frame_size)
                .expect("decode");
        };
        for _ in 0..32 {
            round_trip(
                &mut encoder,
                &mut decoder,
                &mut payload,
                &mut pcm,
                &mut frame,
            );
        }
        let allocations = count_allocations(500, || {
            round_trip(
                &mut encoder,
                &mut decoder,
                &mut payload,
                &mut pcm,
                &mut frame,
            );
        });
        assert_eq!(
            allocations, 0,
            "a warmed-up stereo round trip ({frame_size} samples) allocated {allocations} times \
             across 500 frames"
        );
    }
}

/// Constructing an encoder *is* allowed to allocate (the MDCT/FFT twiddle tables), but only once —
/// this pins that it happens at construction and not per frame, which is the whole reason the
/// per-frame loop above can be allocation-free.
#[test]
fn encoder_construction_is_where_the_tables_are_allocated() {
    let build = count_allocations(1, || {
        let _ = CeltEncoder::new().expect("build");
    });
    assert!(
        build > 0,
        "expected construction to allocate the MDCT tables; got {build}"
    );
    // And the decoder pairs with it, so a transcode leg's steady state is allocation-free on both
    // sides of the pipe.
    let mut encoder = CeltEncoder::new().expect("build");
    encoder.set_bitrate(64_000);
    let mut decoder = CeltDecoder::new().expect("build");
    let signal = celt_signal(960 * 8);
    let mut payload = vec![0u8; 1275];
    let mut pcm = vec![0i16; 960];
    let mut frame = 0usize;
    for _ in 0..32 {
        let lo = (frame % 8) * 960;
        frame += 1;
        let written = encoder
            .encode(&signal[lo..lo + 960], 960, &mut payload)
            .expect("encode");
        decoder
            .decode(&payload[..written], &mut pcm, 960)
            .expect("decode");
    }
    let allocations = count_allocations(500, || {
        let lo = (frame % 8) * 960;
        frame += 1;
        let written = encoder
            .encode(&signal[lo..lo + 960], 960, &mut payload)
            .expect("encode");
        decoder
            .decode(&payload[..written], &mut pcm, 960)
            .expect("decode");
    });
    assert_eq!(
        allocations, 0,
        "a warmed-up encode+decode round trip allocated {allocations} times across 500 frames"
    );
}
