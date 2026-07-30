//! Zero-per-frame-allocation gate for the SILK LTP + excitation decode (a performance invariant).
//!
//! `cargo test -p siphon-rtp-codec --test silk_excitation_zero_alloc`
//!
//! Its own test binary because a process may have only one `#[global_allocator]`.
//!
//! A **counting** allocator, not a jemalloc byte delta: the invariant is about the number of calls
//! into the allocator, and allocate-then-free churn (invisible to a live-bytes delta) is exactly the
//! kind of regression a `Vec` slipped into the shell decoder would cause. RFC 6716 §4.2.7.8 decodes
//! up to 20 shell blocks and up to 320 excitation samples per frame; every one of those buffers is
//! either caller-owned ([`excitation::decode`]'s `pulses` / `excitation_q14`) or a fixed-size array
//! on the stack, so a warmed-up decode loop must make zero allocations.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use siphon_rtp_codec::opus::range_coder::{RangeDecoder, RangeEncoder};
use siphon_rtp_codec::opus::silk::excitation::{
    self, PULSES_PER_BLOCK_ICDF, PULSE_BUFFER_LENGTH, RATE_LEVELS_ICDF, SHELL_BLOCK_LENGTH,
    SHELL_CODE_TABLE0, SHELL_CODE_TABLE1, SHELL_CODE_TABLE2, SHELL_CODE_TABLE3,
    SHELL_CODE_TABLE_OFFSETS, SIGN_ICDF,
};
use siphon_rtp_codec::opus::silk::ltp;
use siphon_rtp_codec::opus::silk::types::{
    CondCoding, InternalRate, QuantOffsetType, SignalType, SubframeLayout, MAX_FRAME_LENGTH,
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

const FTB: u32 = 8;

/// The split sub-table for `pulse_count` (RFC 6716 Tables 47-50).
fn split(table: &[u8; 152], pulse_count: usize) -> &[u8] {
    let start = SHELL_CODE_TABLE_OFFSETS[pulse_count] as usize;
    &table[start..start + pulse_count + 1]
}

/// Encode one frame's worth of §4.2.7.8 symbols, in libopus' order, so the decode under test walks
/// the real code path (shell splits, signs) rather than the all-zero shortcut.
fn encode_frame(frame_length: usize, lsb_shifts: u8) -> Vec<u8> {
    let block_count = frame_length.div_ceil(SHELL_BLOCK_LENGTH);
    let rate_level = 5usize;
    let blocks: Vec<[u16; SHELL_BLOCK_LENGTH]> = (0..block_count)
        .map(|block| {
            let mut pulses = [0u16; SHELL_BLOCK_LENGTH];
            pulses[block % SHELL_BLOCK_LENGTH] = 4;
            pulses[(block * 5 + 1) % SHELL_BLOCK_LENGTH] += 2;
            pulses[(block * 11 + 7) % SHELL_BLOCK_LENGTH] += 1;
            pulses
        })
        .collect();

    let mut payload = vec![0u8; 4096];
    let written = {
        let mut encoder = RangeEncoder::new(&mut payload);
        encoder.enc_icdf(rate_level, &RATE_LEVELS_ICDF[1], FTB);
        for block in &blocks {
            let total: u16 = block.iter().sum();
            for shift in 0..lsb_shifts {
                let table = if shift == 0 {
                    &PULSES_PER_BLOCK_ICDF[rate_level]
                } else {
                    &PULSES_PER_BLOCK_ICDF[9]
                };
                encoder.enc_icdf(17, table, FTB);
            }
            let table = if lsb_shifts == 0 {
                &PULSES_PER_BLOCK_ICDF[rate_level]
            } else {
                &PULSES_PER_BLOCK_ICDF[9]
            };
            encoder.enc_icdf(usize::from(total), table, FTB);
        }
        for block in &blocks {
            let combine = |input: &[u16]| -> Vec<u16> {
                input.chunks_exact(2).map(|p| p[0] + p[1]).collect()
            };
            let level0 = block.to_vec();
            let level1 = combine(&level0);
            let level2 = combine(&level1);
            let level3 = combine(&level2);
            let level4 = combine(&level3);
            let mut emit = |child: u16, parent: u16, table: &[u8; 152]| {
                if parent > 0 {
                    encoder.enc_icdf(usize::from(child), split(table, usize::from(parent)), FTB);
                }
            };
            emit(level3[0], level4[0], &SHELL_CODE_TABLE3);
            emit(level2[0], level3[0], &SHELL_CODE_TABLE2);
            emit(level1[0], level2[0], &SHELL_CODE_TABLE1);
            emit(level0[0], level1[0], &SHELL_CODE_TABLE0);
            emit(level0[2], level1[1], &SHELL_CODE_TABLE0);
            emit(level1[2], level2[1], &SHELL_CODE_TABLE1);
            emit(level0[4], level1[2], &SHELL_CODE_TABLE0);
            emit(level0[6], level1[3], &SHELL_CODE_TABLE0);
            emit(level2[2], level3[1], &SHELL_CODE_TABLE2);
            emit(level1[4], level2[2], &SHELL_CODE_TABLE1);
            emit(level0[8], level1[4], &SHELL_CODE_TABLE0);
            emit(level0[10], level1[5], &SHELL_CODE_TABLE0);
            emit(level1[6], level2[3], &SHELL_CODE_TABLE1);
            emit(level0[12], level1[6], &SHELL_CODE_TABLE0);
            emit(level0[14], level1[7], &SHELL_CODE_TABLE0);
        }
        // LSBs, most significant first, for every sample of every block that asked for them.
        for _ in &blocks {
            for _sample in 0..SHELL_BLOCK_LENGTH {
                for _ in 0..lsb_shifts {
                    encoder.enc_icdf(1, &excitation::LSB_ICDF, FTB);
                }
            }
        }
        // Signs: voiced / high quantization offset is row 5 of RFC 6716 Table 52.
        for block in &blocks {
            let total: u16 = block.iter().sum();
            let icdf = [SIGN_ICDF[35 + usize::from(total).min(6)], 0];
            for (sample, &magnitude) in block.iter().enumerate() {
                let coded = if lsb_shifts == 0 { magnitude } else { 1 };
                if coded > 0 {
                    encoder.enc_icdf(sample & 1, &icdf, FTB);
                }
            }
        }
        encoder.done() as usize
    };
    payload.truncate(written.max(1));
    payload
}

/// Every frame length RFC 6716 Table 44 lists, plus the LSB-escape path, must decode with no heap
/// traffic at all.
#[test]
fn silk_excitation_decode_makes_no_heap_allocation_per_frame() {
    for &frame_length in &[80usize, 120, 160, 240, 320] {
        for &lsb_shifts in &[0u8, 3] {
            let payload = encode_frame(frame_length, lsb_shifts);
            let mut pulses = [0i16; PULSE_BUFFER_LENGTH];
            let mut excitation_q14 = [0i32; MAX_FRAME_LENGTH];

            let mut decode_one = || {
                let mut decoder = RangeDecoder::new(&payload);
                excitation::decode(
                    &mut decoder,
                    SignalType::Voiced,
                    QuantOffsetType::High,
                    frame_length,
                    2,
                    &mut pulses,
                    &mut excitation_q14[..frame_length],
                )
                .expect("decode");
            };
            for _ in 0..32 {
                decode_one();
            }
            let allocations = count_allocations(2_000, &mut decode_one);
            assert_eq!(
                allocations, 0,
                "SILK excitation decode ({frame_length} samples, {lsb_shifts} LSB shifts) \
                 allocated {allocations} times across 2000 frames (must be zero)"
            );
        }
    }
}

/// The §4.2.7.6 LTP stage — index decode plus the codebook lookups that produce the per-subframe
/// pitch lags and Q14 taps — is allocation-free too, at every internal rate and both frame sizes.
#[test]
fn silk_ltp_decode_makes_no_heap_allocation_per_frame() {
    for rate in [
        InternalRate::Narrow8k,
        InternalRate::Medium12k,
        InternalRate::Wide16k,
    ] {
        for duration_ms in [10usize, 20] {
            let layout = SubframeLayout::from_duration_ms(duration_ms).expect("duration");
            let contour = ltp::PitchContourCodebook::select(rate, layout.subframe_count);
            let filter = ltp::LtpFilterCodebook::select(2);
            let mut payload = vec![0u8; 128];
            let written = {
                let mut encoder = RangeEncoder::new(&mut payload);
                encoder.enc_icdf(17, &ltp::PITCH_LAG_ICDF, FTB);
                encoder.enc_icdf(1, ltp::lag_low_bits_icdf(rate), FTB);
                encoder.enc_icdf(contour.len() - 1, contour.icdf(), FTB);
                encoder.enc_icdf(2, &ltp::LTP_PERIODICITY_ICDF, FTB);
                for index in 0..layout.subframe_count {
                    encoder.enc_icdf(index * 3, filter.icdf(), FTB);
                }
                encoder.enc_icdf(1, &ltp::LTP_SCALE_ICDF, FTB);
                encoder.done() as usize
            };
            payload.truncate(written.max(1));

            let mut decode_one = || {
                let mut decoder = RangeDecoder::new(&payload);
                let indices = ltp::decode_indices(
                    &mut decoder,
                    rate,
                    layout,
                    CondCoding::Independently,
                    SignalType::Unvoiced,
                    0,
                );
                let parameters = ltp::dequantize(&indices, rate);
                assert!(parameters.pitch_lags[0] >= ltp::min_lag(rate));
            };
            for _ in 0..32 {
                decode_one();
            }
            let allocations = count_allocations(2_000, &mut decode_one);
            assert_eq!(
                allocations, 0,
                "SILK LTP decode ({rate:?}, {duration_ms} ms) allocated {allocations} times \
                 across 2000 frames (must be zero)"
            );
        }
    }
}
