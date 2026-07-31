//! Zero-per-frame-allocation gate for the SILK synthesis, concealment, resampling and whole-frame
//! decode paths (a performance invariant).
//!
//! `cargo test -p siphon-rtp-codec --test silk_frame_zero_alloc`
//!
//! Its own test binary because a process may have only one `#[global_allocator]`.
//!
//! A **counting** allocator, not a jemalloc byte delta: the invariant is about the number of calls
//! into the allocator, and allocate-then-free churn (invisible to a live-bytes delta) is exactly the
//! kind of regression a `Vec` slipped into the subframe loop would cause. Every buffer these stages
//! touch is either caller-owned or a fixed-size array on `SilkDecoder` / `ChannelState`, so a
//! warmed-up decode loop must make zero allocations — including the resampler's batch scratch, which
//! is the one place the C uses `VARDECL` on a size that varies with the rate pair.
//!
//! The whole-frame case needs a real bitstream, so it reads one from `reference/opus/silk_only` and
//! skips (loudly) when the vectors are absent; every other case is synthetic and always runs.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::path::Path;

use siphon_rtp_codec::opus::packet;
use siphon_rtp_codec::opus::range_coder::RangeDecoder;
use siphon_rtp_codec::opus::silk::cng::{self, CngScratch};
use siphon_rtp_codec::opus::silk::decoder::{ChannelState, SilkDecoder, StereoState};
use siphon_rtp_codec::opus::silk::frame::LossFlag;
use siphon_rtp_codec::opus::silk::plc::{self, PlcScratch};
use siphon_rtp_codec::opus::silk::resampler::Resampler;
use siphon_rtp_codec::opus::silk::stereo_unmix::mid_side_to_left_right;
use siphon_rtp_codec::opus::silk::synthesis::{decode_core, CoreScratch, DecoderControl};
use siphon_rtp_codec::opus::silk::types::{
    InternalRate, SignalType, SubframeLayout, LTP_ORDER, MAX_FRAME_LENGTH, MAX_NB_SUBFR,
};

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

/// Run `body` `iterations` times with allocation counting armed, returning the allocator-call count.
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

/// A channel primed with a plausible history and excitation, as a real decode would leave it.
fn primed_channel(rate: InternalRate, duration_ms: usize) -> ChannelState {
    let mut channel = ChannelState::new();
    let layout = SubframeLayout::from_duration_ms(duration_ms).expect("duration");
    channel.set_internal_rate(rate, layout);
    channel.first_frame_after_reset = false;
    for (index, slot) in channel.out_buf.iter_mut().enumerate() {
        *slot = (7000.0 * ((index as f64) * 0.06).sin()) as i16;
    }
    for (index, slot) in channel.excitation_q14.iter_mut().enumerate() {
        *slot = (((index * 7919) % 4001) as i32 - 2000) << 6;
    }
    channel
}

/// A voiced control block with real gains, pitch lags and both filter halves.
fn voiced_control(rate: InternalRate) -> DecoderControl {
    let mut control = DecoderControl::new();
    control.gains_q16 = [1 << 18, 1 << 19, 1 << 18, 1 << 17];
    control.pitch_lags = [(6 * rate.khz()) as i32; MAX_NB_SUBFR];
    control.ltp_scale_q14 = 15_565;
    for subframe in 0..MAX_NB_SUBFR {
        for tap in 0..LTP_ORDER {
            control.ltp_coef_q14[subframe * LTP_ORDER + tap] = 1_600 + (tap as i16) * 200;
        }
    }
    for order in 0..rate.lpc_order() {
        let value = 1_800 - (order as i16) * 90;
        control.pred_coef_q12[0][order] = value;
        control.pred_coef_q12[1][order] = value;
    }
    control
}

/// The §4.2.7.9 synthesis filters, voiced and unvoiced, at every internal rate and both frame sizes.
#[test]
fn silk_synthesis_makes_no_heap_allocation_per_frame() {
    for rate in [
        InternalRate::Narrow8k,
        InternalRate::Medium12k,
        InternalRate::Wide16k,
    ] {
        for duration_ms in [10usize, 20] {
            for signal_type in [SignalType::Voiced, SignalType::Unvoiced] {
                let mut channel = primed_channel(rate, duration_ms);
                let mut control = voiced_control(rate);
                let mut scratch = CoreScratch::new();
                let mut output = [0i16; MAX_FRAME_LENGTH];

                let mut synthesise = || {
                    decode_core(
                        &mut channel,
                        &mut control,
                        signal_type,
                        // Both filter halves, so the subframe-2 re-whitening branch runs too.
                        true,
                        &mut output,
                        &mut scratch,
                    )
                    .expect("synthesis");
                };
                for _ in 0..32 {
                    synthesise();
                }
                let allocations = count_allocations(2_000, &mut synthesise);
                assert_eq!(
                    allocations, 0,
                    "SILK synthesis ({rate:?}, {duration_ms} ms, {signal_type:?}) allocated \
                     {allocations} times across 2000 frames (must be zero)"
                );
            }
        }
    }
}

/// §4.2.8 unmixing and the mono buffering path.
#[test]
fn silk_stereo_unmixing_makes_no_heap_allocation_per_frame() {
    let mut state = StereoState::new();
    let mut mid = [0i16; MAX_FRAME_LENGTH + 2];
    let mut side = [0i16; MAX_FRAME_LENGTH + 2];
    for index in 0..MAX_FRAME_LENGTH + 2 {
        mid[index] = (6000.0 * ((index as f64) * 0.04).sin()) as i16;
        side[index] = (1500.0 * ((index as f64) * 0.11).cos()) as i16;
    }
    let mut unmix = || {
        mid_side_to_left_right(
            &mut state,
            &mut mid,
            &mut side,
            [4096, -2048],
            InternalRate::Wide16k,
            MAX_FRAME_LENGTH,
        )
        .expect("unmix");
    };
    for _ in 0..32 {
        unmix();
    }
    assert_eq!(count_allocations(2_000, &mut unmix), 0);
}

/// §4.2.9 resampling, at every decoder rate pair — the C's `VARDECL` batch buffers are the whole
/// reason this needs its own case.
#[test]
fn silk_resampling_makes_no_heap_allocation_per_frame() {
    for input_hz in [8_000u32, 12_000, 16_000] {
        for output_hz in [8_000u32, 12_000, 16_000, 24_000, 48_000] {
            let mut resampler = Resampler::new();
            resampler.configure(input_hz, output_hz).expect("configure");
            let samples = (input_hz / 1000) as usize * 20;
            let input: Vec<i16> = (0..samples)
                .map(|n| (8000.0 * ((n as f64) * 0.07).sin()) as i16)
                .collect();
            let mut output = vec![0i16; resampler.output_length(samples)];

            let mut resample = || {
                resampler.process(&mut output, &input).expect("resample");
            };
            for _ in 0..32 {
                resample();
            }
            let allocations = count_allocations(2_000, &mut resample);
            assert_eq!(
                allocations, 0,
                "SILK resampling ({input_hz} -> {output_hz}) allocated {allocations} times \
                 across 2000 frames (must be zero)"
            );
        }
    }
}

/// §4.4 concealment and comfort noise, on the path a real outage takes: one PLC update, then
/// concealed frames with comfort noise added.
#[test]
fn silk_concealment_makes_no_heap_allocation_per_frame() {
    for rate in [
        InternalRate::Narrow8k,
        InternalRate::Medium12k,
        InternalRate::Wide16k,
    ] {
        let mut channel = primed_channel(rate, 20);
        let mut control = voiced_control(rate);
        let mut plc_scratch = PlcScratch::new();
        let mut cng_scratch = CngScratch::new();
        let mut frame = [0i16; MAX_FRAME_LENGTH];

        // Teach the concealer and the comfort-noise estimate from good frames first.
        for _ in 0..8 {
            channel.prev_signal_type = SignalType::Inactive;
            plc::run(
                &mut channel,
                &mut control,
                SignalType::Inactive,
                false,
                &mut frame,
                &mut plc_scratch,
            )
            .expect("plc update");
            channel.loss_count = 0;
            cng::run(&mut channel, &control, &mut frame, &mut cng_scratch).expect("cng");
        }

        let mut conceal = || {
            plc::run(
                &mut channel,
                &mut control,
                SignalType::Voiced,
                true,
                &mut frame,
                &mut plc_scratch,
            )
            .expect("conceal");
            cng::run(&mut channel, &control, &mut frame, &mut cng_scratch).expect("cng");
            plc::glue_frames(&mut channel, &mut frame);
        };
        for _ in 0..32 {
            conceal();
        }
        let allocations = count_allocations(2_000, &mut conceal);
        assert_eq!(
            allocations, 0,
            "SILK concealment ({rate:?}) allocated {allocations} times across 2000 frames \
             (must be zero)"
        );
    }
}

/// First packet payload with real content from an `opus_demo` `.bit` file.
fn first_packet(path: &Path) -> Option<Vec<u8>> {
    let bytes = std::fs::read(path).ok()?;
    let mut offset = 0usize;
    while offset + 8 <= bytes.len() {
        let length = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        if offset + 8 + length > bytes.len() {
            return None;
        }
        let payload = &bytes[offset + 8..offset + 8 + length];
        if payload.len() > 20 {
            return Some(payload.to_vec());
        }
        offset += 8 + length;
    }
    None
}

/// The whole decode, from the range decoder to interleaved 48 kHz stereo PCM. Everything above is a
/// component of this; the point of benching it separately is that the integrator itself — the
/// per-frame [`DecoderControl`], the channel PCM staging buffers, the resampler interleave — must not
/// allocate either.
#[test]
fn silk_whole_frame_decode_makes_no_heap_allocation_per_frame() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus/silk_only");
    let cases = [
        "s01_NB_20_10000.bit",
        "s01_WB_20_18000.bit",
        "s01_WB_20_18000_st.bit",
        "s01_WB_60_18000.bit",
    ];
    let mut scored = 0usize;
    for file in cases {
        let Some(payload) = first_packet(&directory.join(file)) else {
            continue;
        };
        let Ok(parsed) = packet::parse(&payload) else {
            continue;
        };
        let frame = parsed.frames()[0].to_vec();
        let channels = usize::from(parsed.toc.channels());
        let rate = InternalRate::from_bandwidth(parsed.toc.bandwidth());
        let duration_ms = parsed.toc.samples_per_frame(48_000) / 48;
        let mut silk = SilkDecoder::new(48_000, 2).expect("decoder");
        let mut output = vec![0i16; 2880 * 2];

        let mut decode_one = || {
            silk.configure(channels, rate, duration_ms)
                .expect("configure");
            let mut decoder = RangeDecoder::new(&frame);
            silk.decode(Some(&mut decoder), LossFlag::Normal, &mut output)
                .expect("decode");
        };
        for _ in 0..32 {
            decode_one();
        }
        let allocations = count_allocations(1_000, &mut decode_one);
        assert_eq!(
            allocations, 0,
            "whole-frame SILK decode ({file}) allocated {allocations} times across 1000 frames \
             (must be zero)"
        );
        scored += 1;
    }
    if scored == 0 {
        eprintln!(
            "silk whole-frame zero-alloc: no vectors in {} — run reference/opus/gen_silk_only.sh \
             (see CONTRIBUTING.md); the synthetic cases in this file still ran",
            directory.display()
        );
    }
}
