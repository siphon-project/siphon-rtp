//! Zero-per-packet-allocation gate for the SILK **encoder**'s coding half — the noise-shaping
//! quantiser, the bitstream writer, the rate loop and the packet driver (a performance invariant).
//!
//! `cargo test -p siphon-rtp-codec --test silk_encode_zero_alloc`
//!
//! Its own test binary because a process may have only one `#[global_allocator]`. It counts
//! **calls** into the allocator rather than live bytes, because allocate-then-free churn — a `Vec`
//! slipped into the quantiser's per-subframe scratch, say — is invisible to a byte delta and is
//! exactly the regression this guards against.
//!
//! Everything on this path is a fixed-size array sized by the codec's own constants, and several of
//! them are large: the delayed-decision search keeps four whole quantiser states alive (each with a
//! 96-word synthesis history, five 40-slot decision rings and a 24-word shaping filter), the rate
//! loop snapshots up to 1275 bytes of range-coder output so it can roll a trial back, and the
//! encoder's own input history is `2 * MAX_FRAME_LENGTH + LA_SHAPE_MAX` floats per channel. None of
//! that may reach the heap on a warmed-up loop.
//!
//! The rate loop is the interesting case and is covered deliberately: a CBR frame runs the
//! quantiser and the writer up to seven times, so if any of them allocated, this would catch it
//! seven times over.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use siphon_rtp_codec::opus::range_coder::RangeEncoder;
use siphon_rtp_codec::opus::silk::enc::bitstream::{encode_indices, encode_pulses, EntropyContext};
use siphon_rtp_codec::opus::silk::enc::encoder::{EncoderConfig, RateMode, SilkEncoder};
use siphon_rtp_codec::opus::silk::enc::frame::{
    analyze_frame, AnalysisConfig, AnalysisState, ComplexitySettings,
};
use siphon_rtp_codec::opus::silk::enc::nsq::{quantize, NsqConfig, NsqInput, NsqState};
use siphon_rtp_codec::opus::silk::enc::vad::{analyse, VadState};
use siphon_rtp_codec::opus::silk::enc::SignalMeasures;
use siphon_rtp_codec::opus::silk::types::{
    CondCoding, InternalRate, SignalType, SubframeLayout, MAX_FRAME_LENGTH,
};

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

thread_local! {
    // Both the arm flag *and* the counter are thread-local: libtest runs the tests in this binary
    // concurrently, and a global counter would let one test's allocations be charged to another's
    // measurement window.
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

/// A deterministic voiced-like input. Logical sample clock only — no `Instant::now()`, no `rand`.
fn voiced(length: usize, period: usize) -> Vec<f32> {
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

/// The noise-shaping quantiser must allocate nothing, at any survivor depth and either variant.
#[test]
fn the_noise_shaping_quantiser_allocates_nothing_per_frame() {
    for rate in [
        InternalRate::Narrow8k,
        InternalRate::Medium12k,
        InternalRate::Wide16k,
    ] {
        for (states, warping) in [(1usize, 0i32), (1, 983), (2, 0), (4, 983)] {
            let settings = ComplexitySettings::for_complexity(10);
            let layout = SubframeLayout::from_duration_ms(20).expect("20 ms");
            let configuration = AnalysisConfig {
                internal_rate: rate,
                layout,
                settings,
                snr_db_q7: 2600,
                use_cbr: false,
                packet_loss_percent: 0,
                frames_per_packet: 1,
                lbrr_enabled: false,
            };
            let history = configuration.required_history();
            let frame_length = configuration.frame_length();
            let signal = voiced(
                history + frame_length + configuration.required_lookahead(),
                5 * rate.khz(),
            );
            let mut analysis_state = AnalysisState {
                first_frame_after_reset: false,
                ..AnalysisState::default()
            };
            let analysis = analyze_frame(
                &mut analysis_state,
                &signal,
                history,
                SignalType::Unvoiced,
                CondCoding::Independently,
                &measures(),
                &configuration,
            )
            .expect("analysis");

            let nsq_config = NsqConfig {
                subframe_length: configuration.subframe_length(),
                subframe_count: layout.subframe_count,
                ltp_memory_length: configuration.ltp_memory_length(),
                predict_lpc_order: rate.lpc_order(),
                shaping_lpc_order: settings.shaping_lpc_order,
                warping_q16: warping * rate.khz() as i32,
                delayed_decision_states: states,
            };
            let input =
                NsqInput::from_analysis(&analysis.control, &analysis.indices, 1, &nsq_config);
            let mut x16 = [0i16; MAX_FRAME_LENGTH];
            for (slot, &sample) in x16.iter_mut().zip(signal[history..].iter()) {
                *slot = sample as i16;
            }

            let mut nsq = NsqState::default();
            let mut pulses = [0i8; MAX_FRAME_LENGTH];
            // Warm up outside the measurement window.
            quantize(&mut nsq, &input, &x16, &mut pulses, &nsq_config);

            let allocations = count_allocations(|| {
                for _ in 0..64 {
                    std::hint::black_box(quantize(
                        &mut nsq,
                        &input,
                        &x16,
                        &mut pulses,
                        &nsq_config,
                    ));
                }
            });
            assert_eq!(
                allocations, 0,
                "{rate:?} {states} states warping {warping}: {allocations} allocations"
            );
        }
    }
}

/// The bitstream writer must allocate nothing — it is pure table lookup over caller-owned buffers.
#[test]
fn the_bitstream_writer_allocates_nothing_per_frame() {
    let rate = InternalRate::Wide16k;
    let settings = ComplexitySettings::for_complexity(10);
    let layout = SubframeLayout::from_duration_ms(20).expect("20 ms");
    let configuration = AnalysisConfig {
        internal_rate: rate,
        layout,
        settings,
        snr_db_q7: 2600,
        use_cbr: false,
        packet_loss_percent: 0,
        frames_per_packet: 1,
        lbrr_enabled: false,
    };
    let history = configuration.required_history();
    let frame_length = configuration.frame_length();
    let signal = voiced(
        history + frame_length + configuration.required_lookahead(),
        80,
    );
    let mut analysis_state = AnalysisState {
        first_frame_after_reset: false,
        ..AnalysisState::default()
    };
    let analysis = analyze_frame(
        &mut analysis_state,
        &signal,
        history,
        SignalType::Unvoiced,
        CondCoding::Independently,
        &measures(),
        &configuration,
    )
    .expect("analysis");

    let nsq_config = NsqConfig {
        subframe_length: configuration.subframe_length(),
        subframe_count: layout.subframe_count,
        ltp_memory_length: configuration.ltp_memory_length(),
        predict_lpc_order: rate.lpc_order(),
        shaping_lpc_order: settings.shaping_lpc_order,
        warping_q16: configuration.warping_q16(),
        delayed_decision_states: 4,
    };
    let input = NsqInput::from_analysis(&analysis.control, &analysis.indices, 1, &nsq_config);
    let mut x16 = [0i16; MAX_FRAME_LENGTH];
    for (slot, &sample) in x16.iter_mut().zip(signal[history..].iter()) {
        *slot = sample as i16;
    }
    let mut nsq = NsqState::default();
    let mut pulses = [0i8; MAX_FRAME_LENGTH];
    let seed = quantize(&mut nsq, &input, &x16, &mut pulses, &nsq_config);

    // The output buffer is caller-owned and allocated once, outside the window.
    let mut buffer = vec![0u8; 1275];

    let allocations = count_allocations(|| {
        for _ in 0..64 {
            let mut range = RangeEncoder::new(&mut buffer);
            let mut context = EntropyContext::default();
            let mut scratch = pulses;
            encode_indices(
                &mut range,
                &analysis.indices,
                seed,
                rate,
                layout.subframe_count,
                CondCoding::Independently,
                false,
                &mut context,
            );
            encode_pulses(
                &mut range,
                analysis.indices.signal_type,
                analysis.indices.quant_offset_type,
                &mut scratch,
                frame_length,
            );
            std::hint::black_box(range.tell());
        }
    });
    assert_eq!(allocations, 0, "{allocations} allocations in the writer");
}

/// The VAD must allocate nothing: its whole filter bank fits in one fixed scratch array.
#[test]
fn the_vad_allocates_nothing_per_frame() {
    for rate in [
        InternalRate::Narrow8k,
        InternalRate::Medium12k,
        InternalRate::Wide16k,
    ] {
        for duration_ms in [10usize, 20] {
            let frame_length = duration_ms * rate.khz();
            let signal: Vec<i16> = voiced(frame_length, 5 * rate.khz())
                .iter()
                .map(|&value| value as i16)
                .collect();
            let mut state = VadState::default();
            analyse(&mut state, &signal, rate, SignalType::Unvoiced);

            let allocations = count_allocations(|| {
                for _ in 0..64 {
                    std::hint::black_box(analyse(&mut state, &signal, rate, SignalType::Unvoiced));
                }
            });
            assert_eq!(
                allocations, 0,
                "{rate:?} {duration_ms} ms: {allocations} allocations in the VAD"
            );
        }
    }
}

/// The whole packet path — VAD, stereo, analysis, the rate loop, the writer and LBRR — must
/// allocate nothing per packet once the encoder exists.
#[test]
fn the_whole_encoder_allocates_nothing_per_packet() {
    for (rate, duration_ms, channels, bitrate, mode, fec) in [
        (
            InternalRate::Narrow8k,
            20usize,
            1usize,
            10_000i32,
            RateMode::Variable,
            false,
        ),
        (
            InternalRate::Medium12k,
            10,
            1,
            14_000,
            RateMode::ConstrainedVariable,
            false,
        ),
        (
            InternalRate::Wide16k,
            20,
            1,
            24_000,
            RateMode::Constant,
            false,
        ),
        (
            InternalRate::Wide16k,
            60,
            1,
            24_000,
            RateMode::Variable,
            true,
        ),
        (
            InternalRate::Wide16k,
            20,
            2,
            48_000,
            RateMode::Variable,
            false,
        ),
    ] {
        let mut config = EncoderConfig::new(rate, duration_ms, bitrate);
        config.channels = channels;
        config.rate_mode = mode;
        config.use_in_band_fec = fec;
        config.packet_loss_percent = if fec { 20 } else { 0 };
        config.max_bytes = 250;

        let mut encoder = SilkEncoder::new(config).expect("encoder");
        let per_packet = encoder.samples_per_packet() * channels;
        let signal: Vec<i16> = voiced(per_packet * 8, 5 * rate.khz())
            .iter()
            .map(|&value| value as i16)
            .collect();
        // The output buffer belongs to the caller and is allocated once.
        let mut buffer = vec![0u8; 1275];

        // Warm up: the first packet takes the first-frame-after-reset path.
        {
            let mut range = RangeEncoder::new(&mut buffer);
            encoder
                .encode(&signal[..per_packet], &mut range)
                .expect("warm-up encode");
        }

        let allocations = count_allocations(|| {
            for packet in 1..7 {
                let start = packet * per_packet;
                let mut range = RangeEncoder::new(&mut buffer);
                std::hint::black_box(
                    encoder
                        .encode(&signal[start..start + per_packet], &mut range)
                        .expect("encode"),
                );
            }
        });
        assert_eq!(
            allocations, 0,
            "{rate:?} {duration_ms} ms {channels}ch {mode:?} fec={fec}: \
             {allocations} allocations per packet path"
        );
    }
}
