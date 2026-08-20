//! Overlay mixing and tone generation must do **zero per-frame heap allocation** (a performance
//! invariant, the same one [`siphon_rtp_media::mixer::Mixer`] holds): every buffer — the source
//! frame, the resampler output, the re-framer, the mix accumulator and the per-slot render
//! scratch — is sized once when the playback is built. A counting global allocator proves a tight
//! mix loop allocates nothing after warm-up.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use siphon_rtp_media::fanout::MediaSink;
use siphon_rtp_media::playback::{
    FinishedPlayback, Gain, OverlayBus, Playback, PlaybackSource, MAX_OVERLAY_SLOTS,
};
use siphon_rtp_media::player::{PcmPlayer, WavSource};
use siphon_rtp_media::tone::{ToneGenerator, ToneSpec};
use siphon_rtp_media::wav::WavRecorder;

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the measuring thread arms counting, so the libtest harness's background-thread churn
    // inside the same window cannot be mistaken for the loop's own allocations. `const`-initialised
    // so touching it inside `alloc` never itself allocates.
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

/// Run `body` with allocation counting armed on this thread, returning how many allocations it
/// made.
fn allocations_during(body: impl FnOnce()) -> usize {
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    body();
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    ARMED.with(|armed| armed.set(false));
    after - before
}

/// A long constant-valued prompt at `rate_hz`, so a slot never runs dry inside the measured loop.
fn prompt_source(rate_hz: u32, value: i16, seconds: usize) -> PlaybackSource {
    let mut recorder = WavRecorder::new(rate_hz, 1);
    recorder.write_pcm(&vec![value; rate_hz as usize * seconds]);
    let wav = recorder.into_wav();
    let parsed = WavSource::parse(&wav).expect("fixture parses");
    PlaybackSource::Pcm(Box::new(PcmPlayer::new(&parsed, 0, 0)))
}

fn tone_source(spec: &str, rate_hz: u32) -> PlaybackSource {
    let spec = ToneSpec::resolve(spec).expect("tone resolves");
    PlaybackSource::Tone(Box::new(ToneGenerator::new(spec, rate_hz)))
}

/// Drive `slots` overlays for 1000 mix ticks and return the allocation count (must be zero).
fn allocations_over_1000_overlay_ticks(slots: usize, frame: usize, rate_hz: u32) -> usize {
    let mut bus = OverlayBus::new(frame);
    for play_id in 0..slots as u64 {
        let playback = Playback::new(
            prompt_source(rate_hz, 1_000 + play_id as i16, 60),
            rate_hz,
            20,
            Gain::from_decibels(-6),
            play_id,
            None,
        )
        .expect("playback builds");
        bus.start(playback).expect("slot is free");
    }
    let mut base = vec![250i16; frame];
    // The caller owns the completion buffer; reserved once, exactly as the engine's direction does.
    let mut finished: Vec<FinishedPlayback> = Vec::with_capacity(MAX_OVERLAY_SLOTS);

    // Warm up: the first tick pays any one-time lazy init inside the sources.
    bus.mix_into(&mut base, &mut finished);
    finished.clear();

    allocations_during(|| {
        for _ in 0..1_000 {
            bus.mix_into(&mut base, &mut finished);
            finished.clear();
            std::hint::black_box(&base);
        }
    })
}

#[test]
fn overlay_mixing_makes_no_heap_allocation() {
    // Every egress rate the transcode path selects, at one slot and at the four-slot cap.
    for (rate, frame) in [(8_000u32, 160usize), (16_000, 320), (48_000, 960)] {
        for slots in [1usize, 2, MAX_OVERLAY_SLOTS] {
            let allocations = allocations_over_1000_overlay_ticks(slots, frame, rate);
            assert_eq!(
                allocations, 0,
                "{rate} Hz / {slots}-slot overlay mix allocated {allocations} times across 1000 \
                 ticks (must be zero)"
            );
        }
    }
}

#[test]
fn a_resampled_overlay_slot_makes_no_heap_allocation_after_warm_up() {
    // The rate-converted path is the one with a resampler and a re-framer in it — the buffers most
    // likely to grow mid-stream if they were not reserved up front.
    let mut bus = OverlayBus::new(160);
    bus.start(
        Playback::new(
            prompt_source(16_000, 900, 60),
            8_000,
            20,
            Gain::unity(),
            1,
            None,
        )
        .expect("playback builds"),
    )
    .expect("slot is free");
    let mut base = [100i16; 160];
    let mut finished: Vec<FinishedPlayback> = Vec::with_capacity(MAX_OVERLAY_SLOTS);
    for _ in 0..8 {
        bus.mix_into(&mut base, &mut finished);
        finished.clear();
    }
    let allocations = allocations_during(|| {
        for _ in 0..1_000 {
            bus.mix_into(&mut base, &mut finished);
            finished.clear();
            std::hint::black_box(&base);
        }
    });
    assert_eq!(
        allocations, 0,
        "a 16 kHz → 8 kHz overlay slot allocated {allocations} times across 1000 ticks"
    );
}

#[test]
fn tone_generation_makes_no_heap_allocation() {
    // The tone is a phase accumulator, not a rendered buffer: no table, no per-frame Vec.
    for (rate, frame) in [(8_000u32, 160usize), (16_000, 320), (48_000, 960)] {
        for spec in ["425/1000,0/4000*inf", "440+480/2000,0/4000*inf", "dial_uk"] {
            let resolved = ToneSpec::resolve(spec).expect("tone resolves");
            let mut generator = ToneGenerator::new(resolved, rate);
            let mut out = vec![0i16; frame];
            let _ = generator.next_frame(&mut out);
            let allocations = allocations_during(|| {
                for _ in 0..1_000 {
                    let written = generator.next_frame(&mut out);
                    std::hint::black_box(written);
                }
            });
            assert_eq!(
                allocations, 0,
                "{spec} at {rate} Hz allocated {allocations} times across 1000 frames"
            );
        }
    }
}

#[test]
fn a_takeover_playback_makes_no_heap_allocation() {
    // The superseding (non-overlay) path renders straight into the caller's buffer.
    let mut play = Playback::new(
        tone_source("425/1000*inf", 8_000),
        8_000,
        20,
        Gain::from_decibels(-3),
        1,
        None,
    )
    .expect("playback builds");
    let mut frame = [0i16; 160];
    let _ = play.next_frame(&mut frame);
    let allocations = allocations_during(|| {
        for _ in 0..1_000 {
            let written = play.next_frame(&mut frame);
            std::hint::black_box(written);
        }
    });
    assert_eq!(
        allocations, 0,
        "takeover playback allocated {allocations} times across 1000 frames"
    );
}
