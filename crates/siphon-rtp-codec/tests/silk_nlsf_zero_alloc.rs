//! The SILK NLSF stage must make **zero heap allocations per frame**.
//!
//! It runs once per 20 ms SILK frame per channel on every transcoded Opus leg, so it sits squarely on
//! the datapath, where the repo's no-per-frame-allocation invariant applies. Everything the stage
//! touches is a fixed-size array sized by `MAX_LPC_ORDER`, and this test is what keeps it that way: a
//! `Vec` slipped into the residual dequantiser or the polynomial construction would not change a
//! single decoded sample, so nothing else would catch it.
//!
//! Own test binary because there can only be one `#[global_allocator]` per binary — the same reason
//! `celt_zero_alloc.rs` is separate.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use siphon_rtp_codec::opus::range_coder::{RangeDecoder, RangeEncoder};
use siphon_rtp_codec::opus::silk::decoder::{SilkDecoder, MID_CHANNEL};
use siphon_rtp_codec::opus::silk::lpc::{inverse_prediction_gain_q12, nlsf_to_lpc_q12};
use siphon_rtp_codec::opus::silk::nlsf::{
    decode as decode_nlsf, decode_indices, interpolate, nlsf_indices_to_lpc, stabilize, unpack,
    NlsfIndices, MAX_NLSF_INDICES, NO_INTERPOLATION_Q2,
};
use siphon_rtp_codec::opus::silk::nlsf_tables::{NlsfCodebook, NB_MB, WB};
use siphon_rtp_codec::opus::silk::types::{InternalRate, SignalType, MAX_LPC_ORDER, MAX_NB_SUBFR};

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

thread_local! {
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

/// A plausible decoded index vector, with residuals that reach both saturation extremes.
fn sample_indices(order: usize) -> NlsfIndices {
    let mut indices = [0i8; MAX_NLSF_INDICES];
    indices[0] = 23;
    for coefficient in 0..order {
        indices[coefficient + 1] = match coefficient % 6 {
            0 => 0,
            1 => 3,
            2 => -4,
            3 => 7,
            4 => -1,
            _ => 1,
        };
    }
    NlsfIndices {
        indices,
        order,
        interpolation_factor_q2: 2,
    }
}

fn codebook_vector(codebook: &NlsfCodebook, index: usize) -> [i16; MAX_LPC_ORDER] {
    let mut vector = [0i16; MAX_LPC_ORDER];
    for (slot, &entry) in vector.iter_mut().zip(codebook.cb1_vector_q8(index)) {
        *slot = i16::from(entry) << 7;
    }
    vector
}

#[test]
fn nlsf_stage_makes_no_heap_allocation_per_frame() {
    for (rate, codebook) in [
        (InternalRate::Narrow8k, &NB_MB),
        (InternalRate::Medium12k, &NB_MB),
        (InternalRate::Wide16k, &WB),
    ] {
        let indices = sample_indices(codebook.order);
        let mut anchor = codebook_vector(codebook, 6);
        // Warm up outside the counted window, so any one-off lazy initialisation is not charged here.
        let _ = nlsf_indices_to_lpc(&indices, rate, &mut anchor.clone(), false, false);

        let allocations = count_allocations(64, || {
            let _ = nlsf_indices_to_lpc(&indices, rate, &mut anchor, false, false);
        });
        assert_eq!(
            allocations, 0,
            "{rate:?}: the per-frame NLSF -> LPC path allocated {allocations} times"
        );

        // And after a concealed frame, which takes the extra bandwidth-expansion branch.
        let allocations = count_allocations(64, || {
            let _ = nlsf_indices_to_lpc(&indices, rate, &mut anchor, false, true);
        });
        assert_eq!(allocations, 0, "{rate:?}: the post-loss path allocated");
    }
}

#[test]
fn the_individual_nlsf_steps_allocate_nothing() {
    for codebook in [&NB_MB, &WB] {
        let order = codebook.order;
        let indices = sample_indices(order);
        let mut nlsf = [0i16; MAX_LPC_ORDER];
        let mut coefficients = [0i16; MAX_LPC_ORDER];
        let previous = codebook_vector(codebook, 2);
        let mut interpolated = [0i16; MAX_LPC_ORDER];
        // Warm up.
        decode_nlsf(&mut nlsf, codebook, &indices);
        nlsf_to_lpc_q12(&mut coefficients, &nlsf[..order]);

        let allocations = count_allocations(64, || {
            let _ = unpack(codebook, indices.stage1_index());
            decode_nlsf(&mut nlsf, codebook, &indices);
            interpolate(
                &mut interpolated[..order],
                &previous[..order],
                &nlsf[..order],
                2,
            );
            nlsf_to_lpc_q12(&mut coefficients, &interpolated[..order]);
            let _ = inverse_prediction_gain_q12(&coefficients[..order]);
        });
        assert_eq!(
            allocations, 0,
            "order {order}: allocated {allocations} times"
        );
    }
}

/// The stabiliser's fallback path sorts in place; a reversed vector is what drives it there, and it
/// must not reach for a scratch `Vec` to do it.
#[test]
fn stabilisation_allocates_nothing_even_on_its_worst_case() {
    for codebook in [&NB_MB, &WB] {
        let mut worst_case = [0i16; MAX_LPC_ORDER];
        for (index, slot) in worst_case.iter_mut().enumerate().take(codebook.order) {
            *slot = 30_000 - 1_800 * index as i16;
        }
        // Warm up (on a copy — `stabilize` is in place).
        let mut warm_up = worst_case;
        stabilize(&mut warm_up[..codebook.order], codebook.delta_min_q15);

        let allocations = count_allocations(64, || {
            let mut vector = worst_case;
            stabilize(&mut vector[..codebook.order], codebook.delta_min_q15);
        });
        assert_eq!(allocations, 0, "order {}: allocated", codebook.order);
    }
}

/// The bitstream half too: reading the NLSF symbols out of a real range-coded payload must not
/// allocate. Encoding the fixture does allocate, so it happens outside the counted window.
#[test]
fn index_decode_allocates_nothing() {
    let codebook = &WB;
    let unpacked = unpack(codebook, 12);
    let mut buffer = vec![0u8; 256];
    let length = {
        let mut encoder = RangeEncoder::new(&mut buffer);
        encoder.enc_icdf(12, codebook.stage1_icdf(SignalType::Voiced.index()), 8);
        for coefficient in 0..codebook.order {
            encoder.enc_icdf(6, codebook.stage2_icdf(unpacked.pdf_index[coefficient]), 8);
        }
        encoder.enc_icdf(
            1,
            &siphon_rtp_codec::opus::silk::nlsf_tables::NLSF_INTERPOLATION_FACTOR_ICDF,
            8,
        );
        encoder.done() as usize
    };
    buffer.truncate(length);

    // Warm up.
    let mut decoder = RangeDecoder::new(&buffer);
    let _ = decode_indices(
        &mut decoder,
        InternalRate::Wide16k,
        SignalType::Voiced,
        MAX_NB_SUBFR,
    );

    let allocations = count_allocations(64, || {
        let mut decoder = RangeDecoder::new(&buffer);
        let _ = decode_indices(
            &mut decoder,
            InternalRate::Wide16k,
            SignalType::Voiced,
            MAX_NB_SUBFR,
        );
    });
    assert_eq!(allocations, 0, "index decode allocated {allocations} times");
}

/// The decoder-state entry point the synthesis phase calls: a `SilkDecoder` allocates once at
/// construction and never per frame.
#[test]
fn the_decoder_entry_point_allocates_nothing_per_frame() {
    let mut silk = SilkDecoder::new(16_000, 1).expect("decoder");
    silk.configure(1, InternalRate::Wide16k, 20)
        .expect("configure");

    let codebook = &WB;
    let unpacked = unpack(codebook, 8);
    let mut buffer = vec![0u8; 256];
    let length = {
        let mut encoder = RangeEncoder::new(&mut buffer);
        encoder.enc_icdf(8, codebook.stage1_icdf(SignalType::Unvoiced.index()), 8);
        for coefficient in 0..codebook.order {
            encoder.enc_icdf(4, codebook.stage2_icdf(unpacked.pdf_index[coefficient]), 8);
        }
        encoder.enc_icdf(
            0,
            &siphon_rtp_codec::opus::silk::nlsf_tables::NLSF_INTERPOLATION_FACTOR_ICDF,
            8,
        );
        encoder.done() as usize
    };
    buffer.truncate(length);

    // Warm up.
    let mut decoder = RangeDecoder::new(&buffer);
    let _ = silk.decode_nlsf(&mut decoder, MID_CHANNEL, SignalType::Unvoiced);

    let allocations = count_allocations(64, || {
        let mut decoder = RangeDecoder::new(&buffer);
        let _ = silk.decode_nlsf(&mut decoder, MID_CHANNEL, SignalType::Unvoiced);
    });
    assert_eq!(
        allocations, 0,
        "SilkDecoder::decode_nlsf allocated {allocations} times"
    );
}

/// The `LpcCoefficients` a frame returns really is a plain fixed-size value — no boxed tail hiding
/// behind the public API. Sanity check on the invariant above, not a replacement for it.
#[test]
fn lpc_coefficients_are_a_fixed_size_value() {
    use siphon_rtp_codec::opus::silk::nlsf::LpcCoefficients;
    // Three MAX_LPC_ORDER i16 arrays, plus the order and the interpolation factor.
    assert!(
        std::mem::size_of::<LpcCoefficients>() >= 3 * MAX_LPC_ORDER * 2,
        "LpcCoefficients is smaller than its own arrays; is something boxed?"
    );
    assert!(std::mem::size_of::<LpcCoefficients>() <= 3 * MAX_LPC_ORDER * 2 + 32);
    assert_eq!(NO_INTERPOLATION_Q2, 4);
}
