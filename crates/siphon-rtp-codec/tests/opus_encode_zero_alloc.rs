//! Zero-per-frame-allocation gate for the **top-level Opus encoder** (a performance invariant).
//!
//! `cargo test -p siphon-rtp-codec --test opus_encode_zero_alloc`
//!
//! Its own test binary because a process may have only one `#[global_allocator]`.
//!
//! This is the widest hot path in the crate: one call runs the decisions, the input high-pass, the
//! API-rate resampler, the SILK encoder, the CELT encoder and the packet assembly. Every one of them
//! owns its scratch — the staging PCM, the delay buffer, the resampler's filter memory, the packet
//! builder's frame staging — so a warmed-up encode loop must make **zero** allocations, at every
//! mode and both channel counts.
//!
//! A **counting** allocator rather than a jemalloc live-bytes delta: allocate-then-free churn is
//! invisible to a byte delta and is exactly the kind of per-frame cost this invariant exists to
//! forbid.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use siphon_rtp_codec::opus::enc::decision::Application;
use siphon_rtp_codec::opus::enc::encoder::{OpusEncoder, RateControl};
use siphon_rtp_codec::opus::packet::Mode;

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

thread_local! {
    // Both the arm flag and the counter are thread-local: libtest runs the tests in this binary
    // concurrently, and a global counter would charge one test's allocations to another's window.
    // `const`-initialised so touching them inside `alloc` never itself allocates.
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call delegates straight to the system allocator; we only bump a thread-local
// counter, and only when the current thread has armed counting.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            ALLOCATIONS.with(|counter| counter.set(counter.get() + 1));
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout);
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Run `body` `iterations` times with counting armed on this thread; returns the allocator calls.
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

/// Speech-like 16-bit input, so the analysis takes realistic branches rather than the silence path.
fn speech(samples: usize, channels: usize) -> Vec<i16> {
    let mut state = 0x1357_u32;
    let mut history = [0.0f32; 2];
    let mut out = Vec::with_capacity(samples * channels);
    for index in 0..samples {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let noise = ((state >> 20) as i32 - 2048) as f32 * 1.5;
        let pulse = if index % 240 == 0 { 6000.0 } else { 0.0 };
        let value = pulse + noise + 1.5 * history[0] - 0.85 * history[1];
        history[1] = history[0];
        history[0] = value;
        let sample = value.clamp(-24_000.0, 24_000.0) as i16;
        out.push(sample);
        if channels == 2 {
            out.push((i32::from(sample) * 2 / 3) as i16);
        }
    }
    out
}

/// One steady-state encode loop must allocate nothing, in every mode and at both channel counts.
#[test]
fn a_warmed_up_encode_loop_allocates_nothing() {
    const FRAME: usize = 960;
    const FRAMES: usize = 64;

    for &(label, channels, bitrate, application, expected) in &[
        (
            "silk mono",
            1usize,
            11_000i32,
            Application::Voip,
            Mode::Silk,
        ),
        ("hybrid mono", 1, 32_000, Application::Voip, Mode::Hybrid),
        (
            "celt mono",
            1,
            64_000,
            Application::RestrictedLowdelay,
            Mode::Celt,
        ),
        ("hybrid stereo", 2, 40_000, Application::Voip, Mode::Hybrid),
        ("celt stereo", 2, 160_000, Application::Audio, Mode::Celt),
    ] {
        let signal = speech(FRAME * FRAMES, channels);
        let mut encoder = OpusEncoder::new(48_000, channels, application).expect("encoder");
        encoder.set_bitrate(Some(bitrate)).expect("bitrate");
        encoder.set_rate_control(RateControl::ConstrainedVariable);
        encoder.set_complexity(9).expect("complexity");
        let mut payload = vec![0u8; 1500];

        // Warm-up, outside the measured window: the first frames settle the mode, bandwidth and
        // channel hysteresis and let every lazily built table exist.
        let mut mode = None;
        for frame in 0..8 {
            let lo = frame * FRAME * channels;
            mode = Some(
                encoder
                    .encode(&signal[lo..lo + FRAME * channels], FRAME, &mut payload)
                    .expect("warm-up encode")
                    .mode,
            );
        }
        assert_eq!(
            mode,
            Some(expected),
            "{label}: the configuration did not settle in the intended mode"
        );

        let mut frame = 8usize;
        let allocations = count_allocations(FRAMES - 8, || {
            let lo = (frame % FRAMES) * FRAME * channels;
            frame += 1;
            let _ = encoder
                .encode(&signal[lo..lo + FRAME * channels], FRAME, &mut payload)
                .expect("encode");
        });
        assert_eq!(
            allocations, 0,
            "{label}: the encode loop allocated {allocations} times"
        );
    }
}

/// The multi-frame path — 40, 60 and 120 ms — packs several Opus frames into one packet, and the
/// staging that needs must be owned too.
#[test]
fn multi_frame_packets_allocate_nothing() {
    for &frame_size in &[1920usize, 2880, 5760] {
        let frames = 8usize;
        let signal = speech(frame_size * frames, 1);
        let mut encoder = OpusEncoder::new(48_000, 1, Application::Voip).expect("encoder");
        encoder.set_bitrate(Some(32_000)).expect("bitrate");
        encoder.set_rate_control(RateControl::ConstrainedVariable);
        let mut payload = vec![0u8; 1500];
        for frame in 0..3 {
            encoder
                .encode(
                    &signal[frame * frame_size..(frame + 1) * frame_size],
                    frame_size,
                    &mut payload,
                )
                .expect("warm-up encode");
        }
        let mut frame = 3usize;
        let allocations = count_allocations(frames - 3, || {
            let lo = (frame % frames) * frame_size;
            frame += 1;
            let _ = encoder
                .encode(&signal[lo..lo + frame_size], frame_size, &mut payload)
                .expect("encode");
        });
        assert_eq!(
            allocations, 0,
            "{frame_size}-sample frames allocated {allocations} times"
        );
    }
}

/// The DTX and FEC paths take different branches through the SILK layer; neither may allocate.
#[test]
fn the_dtx_and_fec_paths_allocate_nothing() {
    const FRAME: usize = 960;
    const FRAMES: usize = 48;
    let speech_source = speech(FRAME * FRAMES, 1);
    let silence = vec![0i16; FRAME * FRAMES];

    for &(label, fec, dtx, source) in &[
        ("fec", true, false, &speech_source),
        ("dtx on speech", false, true, &speech_source),
        ("dtx on silence", false, true, &silence),
    ] {
        let mut encoder = OpusEncoder::new(48_000, 1, Application::Voip).expect("encoder");
        encoder.set_bitrate(Some(24_000)).expect("bitrate");
        encoder.set_rate_control(RateControl::ConstrainedVariable);
        encoder.set_in_band_fec(fec);
        encoder.set_dtx(dtx);
        encoder
            .set_packet_loss_percent(if fec { 20 } else { 0 })
            .expect("loss");
        let mut payload = vec![0u8; 1500];
        for frame in 0..8 {
            encoder
                .encode(
                    &source[frame * FRAME..(frame + 1) * FRAME],
                    FRAME,
                    &mut payload,
                )
                .expect("warm-up encode");
        }
        let mut frame = 8usize;
        let allocations = count_allocations(FRAMES - 8, || {
            let lo = (frame % FRAMES) * FRAME;
            frame += 1;
            let _ = encoder
                .encode(&source[lo..lo + FRAME], FRAME, &mut payload)
                .expect("encode");
        });
        assert_eq!(allocations, 0, "{label}: allocated {allocations} times");
    }
}

/// The gate must be *live*: a loop that does allocate has to be counted, or a zero above proves
/// nothing about the encoder.
#[test]
fn the_counter_sees_a_real_allocation() {
    let allocations = count_allocations(4, || {
        let buffer: Vec<u8> = Vec::with_capacity(4096);
        std::hint::black_box(&buffer);
    });
    assert!(
        allocations >= 4,
        "the counting allocator missed a deliberate allocation ({allocations})"
    );
}
