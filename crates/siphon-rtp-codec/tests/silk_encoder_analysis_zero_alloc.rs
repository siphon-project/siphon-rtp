//! Zero-per-frame-allocation gate for the SILK encoder's analysis front end (a performance
//! invariant).
//!
//! `cargo test -p siphon-rtp-codec --test silk_encoder_analysis_zero_alloc`
//!
//! Its own test binary because a process may have only one `#[global_allocator]`.
//!
//! A **counting** allocator, not a jemalloc byte delta: the invariant is about the number of calls
//! into the allocator, and allocate-then-free churn (invisible to a live-bytes delta) is exactly
//! the kind of regression a `Vec` slipped into the Burg recursion or the pitch search would cause.
//!
//! The analysis front end holds a lot of scratch — a 640-sample whitening residual, two decimated
//! copies of the frame, a 4x34x5 stage-3 correlation cube, a 384-sample stacked LPC input, a 25-slot
//! LTP correlation matrix per subframe — and every one of those is a fixed-size array on the stack
//! sized by the codec's own constants. A warmed-up per-frame loop must therefore allocate nothing at
//! all, at any complexity, on any of the three internal rates.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use siphon_rtp_codec::opus::silk::enc::frame::{
    analyze_frame, AnalysisConfig, AnalysisState, ComplexitySettings,
};
use siphon_rtp_codec::opus::silk::enc::SignalMeasures;
use siphon_rtp_codec::opus::silk::types::{CondCoding, InternalRate, SignalType, SubframeLayout};

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

thread_local! {
    // Both the arm flag *and* the counter are thread-local: libtest runs the tests in this binary
    // concurrently, and a global counter would let one test's allocations be charged to another's
    // measurement window. `const`-initialised so touching them inside `alloc` never itself allocates.
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

/// Run `body` with allocation counting armed, and return how many allocations it made.
fn count_allocations(body: impl FnOnce()) -> usize {
    ALLOCATIONS.with(|counter| counter.set(0));
    ARMED.with(|armed| armed.set(true));
    body();
    ARMED.with(|armed| armed.set(false));
    ALLOCATIONS.with(Cell::get)
}

/// A deterministic voiced-like input: a pulse train through a two-formant filter plus a repeatable
/// pseudo-noise floor. Logical sample clock only — no `Instant::now()`, no `rand`.
fn voiced_signal(length: usize, period: usize) -> Vec<f32> {
    let mut state = 24_680u32;
    let mut signal = vec![0.0f32; length];
    let mut history = [0.0f32; 2];
    for (index, slot) in signal.iter_mut().enumerate() {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let noise = ((state >> 20) as i32 - 2048) as f32 * 0.5;
        let pulse = if index % period == 0 { 4000.0 } else { 0.0 };
        let value = pulse + noise + 1.5 * history[0] - 0.85 * history[1];
        history[1] = history[0];
        history[0] = value;
        *slot = value.clamp(-30_000.0, 30_000.0);
    }
    signal
}

fn measures() -> SignalMeasures {
    SignalMeasures {
        speech_activity_q8: 220,
        input_quality_bands_q15: [22_000; 4],
        input_tilt_q15: 1000,
        previous_signal_type: SignalType::Voiced,
    }
}

/// The whole front end, over every rate, both frame durations and the complexity extremes: not one
/// allocation per frame.
#[test]
fn analyze_frame_allocates_nothing_per_frame() {
    for rate in [
        InternalRate::Narrow8k,
        InternalRate::Medium12k,
        InternalRate::Wide16k,
    ] {
        for duration_ms in [10usize, 20] {
            // Complexity 0 (no warping, no NLSF interpolation, 2 survivors) and 10 (warping, the
            // interpolation search, 16 survivors) take genuinely different code paths.
            for complexity in [0u8, 10] {
                let config = AnalysisConfig {
                    internal_rate: rate,
                    layout: SubframeLayout::from_duration_ms(duration_ms).expect("legal duration"),
                    settings: ComplexitySettings::for_complexity(complexity),
                    snr_db_q7: 2600,
                    use_cbr: false,
                    packet_loss_percent: 10,
                    frames_per_packet: 1,
                    lbrr_enabled: false,
                };
                let history = config.required_history();
                let total = history + config.frame_length() + config.required_lookahead();
                let signal = voiced_signal(total, 5 * rate.khz());
                let mut state = AnalysisState {
                    first_frame_after_reset: false,
                    ..AnalysisState::default()
                };
                let measures = measures();

                // Warm up outside the measurement window, so a first-call lazy initialisation
                // anywhere in the chain would be charged to the warm-up rather than hidden.
                let _ = analyze_frame(
                    &mut state,
                    &signal,
                    history,
                    SignalType::Unvoiced,
                    CondCoding::Independently,
                    &measures,
                    &config,
                );

                let allocations = count_allocations(|| {
                    for frame in 0..32 {
                        let conditional = if frame % 2 == 0 {
                            CondCoding::Independently
                        } else {
                            CondCoding::Conditionally
                        };
                        let result = analyze_frame(
                            &mut state,
                            &signal,
                            history,
                            SignalType::Unvoiced,
                            conditional,
                            &measures,
                            &config,
                        );
                        assert!(result.is_ok(), "{rate:?} {duration_ms} ms c{complexity}");
                    }
                });

                assert_eq!(
                    allocations, 0,
                    "{rate:?} {duration_ms} ms complexity {complexity}: \
                     {allocations} allocations over 32 frames"
                );
            }
        }
    }
}

/// The same for an inactive frame, which takes the short-circuit path through the pitch search and
/// the unvoiced branch of the prediction search — a different set of buffers.
#[test]
fn an_inactive_frame_allocates_nothing_either() {
    let config = AnalysisConfig {
        internal_rate: InternalRate::Wide16k,
        layout: SubframeLayout::from_duration_ms(20).expect("legal duration"),
        settings: ComplexitySettings::for_complexity(5),
        snr_db_q7: 2600,
        use_cbr: true,
        packet_loss_percent: 0,
        frames_per_packet: 3,
        lbrr_enabled: true,
    };
    let history = config.required_history();
    let total = history + config.frame_length() + config.required_lookahead();
    let signal = voiced_signal(total, 80);
    let mut state = AnalysisState {
        first_frame_after_reset: false,
        ..AnalysisState::default()
    };
    let measures = SignalMeasures::default();

    let _ = analyze_frame(
        &mut state,
        &signal,
        history,
        SignalType::Inactive,
        CondCoding::Independently,
        &measures,
        &config,
    );

    let allocations = count_allocations(|| {
        for _ in 0..32 {
            let result = analyze_frame(
                &mut state,
                &signal,
                history,
                SignalType::Inactive,
                CondCoding::Independently,
                &measures,
                &config,
            );
            assert!(result.is_ok());
        }
    });
    assert_eq!(allocations, 0, "{allocations} allocations over 32 frames");
}

/// The counting allocator itself: it must see an allocation that really happens, and see none when
/// nothing allocates. Without this a broken counter would make every assertion above vacuous.
#[test]
fn the_counting_allocator_actually_counts() {
    let observed = count_allocations(|| {
        let buffer: Vec<u8> = Vec::with_capacity(4096);
        std::hint::black_box(&buffer);
    });
    assert!(observed >= 1, "the counter never fired");

    let quiet = count_allocations(|| {
        let value = std::hint::black_box(7u64) * 3;
        std::hint::black_box(value);
    });
    assert_eq!(quiet, 0, "arithmetic allocated {quiet} times");
}
