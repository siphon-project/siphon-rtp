//! Criterion benches for the SILK NLSF stage (RFC 6716 §4.2.7.5) — the per-frame cost of turning a
//! decoded NLSF index vector into the two Q12 LPC filters a SILK frame is synthesised with.
//!
//! This is a real datapath cost: it runs once per 20 ms SILK frame per channel, so 50 times a second
//! on every transcoded Opus leg, and it does two `silk_NLSF2A` conversions whenever the frame
//! interpolates. Reported as µs (ns here) per frame, which is directly comparable to the codec
//! benches next door.
//!
//! The bitstream half (`decode_indices`) is deliberately *not* benched against a synthetic payload:
//! the range decoder's cost is dominated by the packet it is reading, and a fabricated payload would
//! measure the fabrication. It gets its number from the whole-frame bench once the SILK layer
//! decodes end to end.
//!
//! For scale, on one modern x86-64 core the whole per-frame stage costs 244 ns (order 10, no
//! interpolation) to 797 ns (order 16, interpolated) — about 0.004 % of the 20 ms frame budget, with
//! the two `silk_NLSF2A` conversions dominating and the stabiliser essentially free except on its
//! sort-based fallback.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_codec::opus::silk::lpc::{inverse_prediction_gain_q12, nlsf_to_lpc_q12};
use siphon_rtp_codec::opus::silk::nlsf::{
    decode as decode_nlsf, nlsf_indices_to_lpc, stabilize, NlsfIndices, MAX_NLSF_INDICES,
    NO_INTERPOLATION_Q2,
};
use siphon_rtp_codec::opus::silk::nlsf_tables::{NlsfCodebook, NB_MB, WB};
use siphon_rtp_codec::opus::silk::types::{InternalRate, MAX_LPC_ORDER};

/// A plausible decoded index vector: a mid-range stage-1 entry with a spread of stage-2 residuals,
/// including both saturation extremes so the dequantiser's dead-zone branches are taken.
fn sample_indices(order: usize) -> NlsfIndices {
    let mut indices = [0i8; MAX_NLSF_INDICES];
    indices[0] = 17;
    for coefficient in 0..order {
        indices[coefficient + 1] = match coefficient % 5 {
            0 => 0,
            1 => 1,
            2 => -2,
            3 => 4,
            _ => -1,
        };
    }
    NlsfIndices {
        indices,
        order,
        interpolation_factor_q2: NO_INTERPOLATION_Q2,
    }
}

/// The previous frame's vector, as the interpolation anchor.
fn sample_previous(codebook: &NlsfCodebook) -> [i16; MAX_LPC_ORDER] {
    let mut previous = [0i16; MAX_LPC_ORDER];
    for (slot, &entry) in previous.iter_mut().zip(codebook.cb1_vector_q8(9)) {
        *slot = i16::from(entry) << 7;
    }
    previous
}

fn bench_nlsf_decode(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("silk_nlsf");
    for (name, rate, codebook) in [
        ("nb_mb_order10", InternalRate::Narrow8k, &NB_MB),
        ("wb_order16", InternalRate::Wide16k, &WB),
    ] {
        let indices = sample_indices(codebook.order);
        let previous = sample_previous(codebook);

        // Index vector -> stabilised NLSFs (dequantise + reconstruct + stabilise).
        group.bench_function(format!("{name}/nlsf_decode"), |bencher| {
            let mut nlsf = [0i16; MAX_LPC_ORDER];
            bencher.iter(|| {
                decode_nlsf(&mut nlsf, black_box(codebook), black_box(&indices));
                black_box(nlsf[0])
            });
        });

        // The stabiliser on its own, on a vector that actually needs repairing — the worst case is
        // the sort-based fallback, which is what a hostile or badly conditioned frame reaches.
        group.bench_function(format!("{name}/stabilize_worst_case"), |bencher| {
            let reversed: Vec<i16> = (0..codebook.order)
                .map(|k| 30_000 - 1_800 * k as i16)
                .collect();
            bencher.iter(|| {
                let mut vector = reversed.clone();
                stabilize(black_box(&mut vector), codebook.delta_min_q15);
                black_box(vector[0])
            });
        });

        // One NLSF -> Q12 LPC conversion, including the stability check and any bandwidth-expansion
        // retries it triggers.
        group.bench_function(format!("{name}/nlsf_to_lpc"), |bencher| {
            let mut nlsf = [0i16; MAX_LPC_ORDER];
            decode_nlsf(&mut nlsf, codebook, &indices);
            let mut coefficients = [0i16; MAX_LPC_ORDER];
            bencher.iter(|| {
                nlsf_to_lpc_q12(&mut coefficients, black_box(&nlsf[..codebook.order]));
                black_box(coefficients[0])
            });
        });

        // The stability test alone: `silk_NLSF2A` calls it at least once per conversion.
        group.bench_function(format!("{name}/inverse_prediction_gain"), |bencher| {
            let mut nlsf = [0i16; MAX_LPC_ORDER];
            decode_nlsf(&mut nlsf, codebook, &indices);
            let mut coefficients = [0i16; MAX_LPC_ORDER];
            nlsf_to_lpc_q12(&mut coefficients, &nlsf[..codebook.order]);
            bencher.iter(|| {
                black_box(inverse_prediction_gain_q12(black_box(
                    &coefficients[..codebook.order],
                )))
            });
        });

        // The whole per-frame stage the synthesis phase calls, in both shapes: no interpolation
        // (one NLSF2A) and interpolated (two).
        for (label, factor) in [
            ("no_interpolation", NO_INTERPOLATION_Q2),
            ("interpolated", 2),
        ] {
            let mut frame_indices = indices;
            frame_indices.interpolation_factor_q2 = factor;
            group.bench_function(format!("{name}/frame_{label}"), |bencher| {
                let mut anchor = previous;
                bencher.iter(|| {
                    black_box(nlsf_indices_to_lpc(
                        black_box(&frame_indices),
                        rate,
                        &mut anchor,
                        false,
                        false,
                    ))
                });
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_nlsf_decode);
criterion_main!(benches);
