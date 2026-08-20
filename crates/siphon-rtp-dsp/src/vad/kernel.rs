//! The tensor primitives the neural VAD's forward pass is built from.
//!
//! The whole network is four operators — a strided 1-D convolution, ReLU, one LSTM cell, and a
//! logistic sigmoid — so there is no graph engine here and no need for one. Each kernel is a plain
//! function over `f32` slices with an explicit layout contract, unit-tested against a hand-computed
//! case, and every inner product goes through [`siphon_rtp_simd::fir_dot_f32`] (AVX+FMA with a
//! scalar fallback and runtime detection), exactly as the polyphase resampler does.
//!
//! ## Layout contract
//!
//! Activations are **time-major**: `activation[t * channels + c]`. That is deliberate and it is
//! what makes the SIMD useful. A 1-D convolution's natural contiguous axis is the kernel tap (3
//! elements — far too short to vectorise), but with time-major activations and weights stored
//! `[out_channel][tap][in_channel]` each tap contributes one contiguous dot of length
//! `in_channels` (129, 128, 64), which is exactly the shape `fir_dot_f32` wants.

use siphon_rtp_simd::fir_dot_f32;

/// The kernel width of every encoder convolution in the network (all four are `k = 3`, `pad = 1`).
pub(crate) const ENCODER_KERNEL: usize = 3;

/// Logistic sigmoid `1 / (1 + e^-x)`.
///
/// Saturates rather than producing a NaN at the extremes: `exp(-x)` overflows to `+inf` for very
/// negative `x`, and `1 / inf` is `0`.
#[inline]
pub(crate) fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// Rectified linear unit, in place.
#[inline]
pub(crate) fn relu_in_place(values: &mut [f32]) {
    for value in values.iter_mut() {
        *value = value.max(0.0);
    }
}

/// A strided, unpadded 1-D convolution of a **single-channel** signal against a bank of filters.
///
/// This is the STFT front end: `weight` is `[filters][kernel]` row-major (a fixed Fourier basis,
/// not a learned parameter) and every output is one contiguous dot of length `kernel` against the
/// signal. `output` is time-major, `[frames][filters]`.
///
/// Returns the number of frames written. Frames are `(signal.len() - kernel) / stride + 1`.
pub(crate) fn conv1d_filter_bank(
    signal: &[f32],
    weight: &[f32],
    filters: usize,
    kernel: usize,
    stride: usize,
    output: &mut [f32],
) -> usize {
    debug_assert_eq!(weight.len(), filters * kernel);
    debug_assert!(stride > 0);
    if signal.len() < kernel {
        return 0;
    }
    let frames = (signal.len() - kernel) / stride + 1;
    debug_assert!(output.len() >= frames * filters);
    for frame in 0..frames {
        let start = frame * stride;
        let window = &signal[start..start + kernel];
        let row = &mut output[frame * filters..(frame + 1) * filters];
        for (filter, slot) in row.iter_mut().enumerate() {
            *slot = fir_dot_f32(&weight[filter * kernel..(filter + 1) * kernel], window);
        }
    }
    frames
}

/// Output length of a `k = 3`, `pad = 1` convolution — the shape every encoder stage has.
///
/// PyTorch/ONNX convention: `floor((in_len + 2 * pad - kernel) / stride) + 1`.
#[inline]
pub(crate) const fn encoder_output_length(input_length: usize, stride: usize) -> usize {
    if input_length + 2 < ENCODER_KERNEL {
        return 0;
    }
    (input_length + 2 - ENCODER_KERNEL) / stride + 1
}

/// A strided 1-D convolution with kernel 3 and symmetric zero padding 1, over time-major
/// activations.
///
/// * `input` is `[input_length][in_channels]`, time-major.
/// * `weight` is `[out_channels][3][in_channels]` — the ONNX `[out][in][k]` tensor transposed on
///   its last two axes so each tap is contiguous over the input channels (see the module contract).
/// * `bias` is `[out_channels]`, and its length *is* the output channel count.
/// * `output` is `[encoder_output_length(input_length, stride)][out_channels]`, time-major.
///
/// The padding is not materialised: a tap whose source index falls outside the input contributes
/// nothing, which is what zero padding means.
pub(crate) fn conv1d_k3_pad1(
    input: &[f32],
    input_length: usize,
    in_channels: usize,
    weight: &[f32],
    bias: &[f32],
    stride: usize,
    output: &mut [f32],
) {
    let out_channels = bias.len();
    debug_assert_eq!(input.len(), input_length * in_channels);
    debug_assert_eq!(weight.len(), out_channels * ENCODER_KERNEL * in_channels);
    debug_assert!(stride > 0);
    let frames = encoder_output_length(input_length, stride);
    debug_assert!(output.len() >= frames * out_channels);

    for frame in 0..frames {
        let row = &mut output[frame * out_channels..(frame + 1) * out_channels];
        for (out_channel, slot) in row.iter_mut().enumerate() {
            let weight_base = out_channel * ENCODER_KERNEL * in_channels;
            let mut accumulator = bias[out_channel];
            for tap in 0..ENCODER_KERNEL {
                // pad = 1, so tap `t` of output frame `f` reads input sample `f*stride + t - 1`.
                let padded_index = frame * stride + tap;
                if padded_index == 0 {
                    continue; // left pad
                }
                let source = padded_index - 1;
                if source >= input_length {
                    continue; // right pad
                }
                accumulator += fir_dot_f32(
                    &weight[weight_base + tap * in_channels..weight_base + (tap + 1) * in_channels],
                    &input[source * in_channels..(source + 1) * in_channels],
                );
            }
            *slot = accumulator;
        }
    }
}

/// One step of a single-layer unidirectional LSTM cell.
///
/// Gate order is PyTorch's `[input, forget, cell, output]` — the order the upstream checkpoint
/// stores, so the weights are used exactly as they come off disk with no re-permutation. (The ONNX
/// export re-slices them into ONNX's `[input, output, forget, cell]` at graph-build time; we skip
/// that round trip entirely.)
///
/// * `weight_ih` / `weight_hh` are `[4 * hidden][input_size]` and `[4 * hidden][hidden]` row-major.
/// * `bias_ih` / `bias_hh` are `[4 * hidden]`. PyTorch keeps both and adds them; so do we.
/// * `gates` is `[4 * hidden]` caller-owned scratch.
/// * `hidden` and `cell` are the carried state, updated in place.
pub(crate) fn lstm_cell_step(
    input: &[f32],
    weight_ih: &[f32],
    weight_hh: &[f32],
    bias_ih: &[f32],
    bias_hh: &[f32],
    gates: &mut [f32],
    hidden: &mut [f32],
    cell: &mut [f32],
) {
    let hidden_size = hidden.len();
    debug_assert_eq!(cell.len(), hidden_size);
    debug_assert_eq!(gates.len(), 4 * hidden_size);
    debug_assert_eq!(weight_ih.len(), 4 * hidden_size * input.len());
    debug_assert_eq!(weight_hh.len(), 4 * hidden_size * hidden_size);
    debug_assert_eq!(bias_ih.len(), 4 * hidden_size);
    debug_assert_eq!(bias_hh.len(), 4 * hidden_size);

    let input_size = input.len();
    for (row, slot) in gates.iter_mut().enumerate() {
        *slot = bias_ih[row]
            + bias_hh[row]
            + fir_dot_f32(&weight_ih[row * input_size..(row + 1) * input_size], input)
            + fir_dot_f32(
                &weight_hh[row * hidden_size..(row + 1) * hidden_size],
                hidden,
            );
    }

    for index in 0..hidden_size {
        let input_gate = sigmoid(gates[index]);
        let forget_gate = sigmoid(gates[hidden_size + index]);
        let cell_candidate = gates[2 * hidden_size + index].tanh();
        let output_gate = sigmoid(gates[3 * hidden_size + index]);
        let new_cell = forget_gate * cell[index] + input_gate * cell_candidate;
        cell[index] = new_cell;
        hidden[index] = output_gate * new_cell.tanh();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigmoid_matches_hand_computed_values() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-7);
        // 1 / (1 + e^-1) = 0.7310585786…
        assert!((sigmoid(1.0) - 0.731_058_6).abs() < 1e-6);
        assert!((sigmoid(-1.0) - 0.268_941_4).abs() < 1e-6);
    }

    #[test]
    fn sigmoid_saturates_without_producing_nan() {
        assert_eq!(sigmoid(1.0e30), 1.0);
        assert_eq!(sigmoid(-1.0e30), 0.0);
        assert!(sigmoid(f32::NEG_INFINITY).is_finite());
    }

    #[test]
    fn relu_clamps_negatives_to_zero() {
        let mut values = [-2.0f32, -0.0, 0.0, 3.5];
        relu_in_place(&mut values);
        assert_eq!(values, [0.0, 0.0, 0.0, 3.5]);
    }

    #[test]
    fn filter_bank_convolution_matches_hand_computed_case() {
        // Two filters of width 2 over a 5-sample signal at stride 2 → 2 frames.
        //   frame 0 = [1, 2], frame 1 = [3, 4]
        //   filter 0 = [1, 0]  → 1, 3
        //   filter 1 = [1, 1]  → 3, 7
        let signal = [1.0f32, 2.0, 3.0, 4.0, 5.0];
        let weight = [1.0f32, 0.0, 1.0, 1.0];
        let mut output = [0.0f32; 4];
        let frames = conv1d_filter_bank(&signal, &weight, 2, 2, 2, &mut output);
        assert_eq!(frames, 2);
        // Time-major: [frame0_filter0, frame0_filter1, frame1_filter0, frame1_filter1]
        assert_eq!(output, [1.0, 3.0, 3.0, 7.0]);
    }

    #[test]
    fn filter_bank_convolution_yields_no_frames_for_a_short_signal() {
        let mut output = [0.0f32; 4];
        assert_eq!(
            conv1d_filter_bank(&[1.0, 2.0], &[1.0; 4], 1, 4, 1, &mut output),
            0
        );
    }

    #[test]
    fn encoder_output_length_matches_the_onnx_shape_rule() {
        // The exact chain the network walks: 4 → 4 → 2 → 1 → 1.
        assert_eq!(encoder_output_length(4, 1), 4);
        assert_eq!(encoder_output_length(4, 2), 2);
        assert_eq!(encoder_output_length(2, 2), 1);
        assert_eq!(encoder_output_length(1, 1), 1);
    }

    #[test]
    fn padded_convolution_matches_hand_computed_case() {
        // 1 input channel, 1 output channel, weight [1, 2, 3] (taps t-1, t, t+1), bias 10, stride 1.
        // input = [1, 2, 3]
        //   t=0: pad*1 + 1*2 + 2*3 + 10 = 18
        //   t=1: 1*1  + 2*2 + 3*3 + 10 = 24
        //   t=2: 2*1  + 3*2 + pad*3 + 10 = 18
        let input = [1.0f32, 2.0, 3.0];
        let weight = [1.0f32, 2.0, 3.0];
        let bias = [10.0f32];
        let mut output = [0.0f32; 3];
        conv1d_k3_pad1(&input, 3, 1, &weight, &bias, 1, &mut output);
        assert_eq!(output, [18.0, 24.0, 18.0]);
    }

    #[test]
    fn padded_convolution_handles_stride_and_multiple_channels() {
        // 2 input channels, 2 output channels, stride 2, input length 4 → output length 2.
        // input (time-major) = [[1,2], [3,4], [5,6], [7,8]]
        // out_channel 0 weight [tap][in_ch] = [[1,0],[0,1],[1,1]], bias 0
        //   t=0 (frame 0 reads input -1,0,1): pad + (1*3+0*4)?? -- see the arithmetic below.
        let input = [1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let weight = [
            // out_channel 0: tap0 [1,0], tap1 [0,1], tap2 [1,1]
            1.0, 0.0, 0.0, 1.0, 1.0, 1.0, //
            // out_channel 1: tap0 [0,0], tap1 [1,0], tap2 [0,0]
            0.0, 0.0, 1.0, 0.0, 0.0, 0.0,
        ];
        let bias = [0.0f32, 100.0];
        let mut output = [0.0f32; 4];
        conv1d_k3_pad1(&input, 4, 2, &weight, &bias, 2, &mut output);
        // frame 0 reads sources -1 (pad), 0 = [1,2], 1 = [3,4]
        //   channel 0 = 0 + (0*1 + 1*2) + (1*3 + 1*4) = 9
        //   channel 1 = 100 + (1*1 + 0*2) + 0 = 101
        // frame 1 reads sources 1 = [3,4], 2 = [5,6], 3 = [7,8]
        //   channel 0 = (1*3 + 0*4) + (0*5 + 1*6) + (1*7 + 1*8) = 3 + 6 + 15 = 24
        //   channel 1 = 100 + (1*5 + 0*6) = 105
        assert_eq!(output, [9.0, 101.0, 24.0, 105.0]);
    }

    #[test]
    fn lstm_cell_step_matches_hand_computed_case() {
        // hidden_size 1, input_size 1. All weights 1, all biases 0, input 1, state zero.
        //   gate pre-activation = 1*1 + 1*0 = 1 for every gate
        //   i = f = o = sigmoid(1) = 0.7310586, g = tanh(1) = 0.7615942
        //   c = 0 * 0 + 0.7310586 * 0.7615942 = 0.5567
        //   h = 0.7310586 * tanh(0.5567) = 0.7310586 * 0.505... = 0.3694
        let input = [1.0f32];
        let weight_ih = [1.0f32; 4];
        let weight_hh = [1.0f32; 4];
        let bias_ih = [0.0f32; 4];
        let bias_hh = [0.0f32; 4];
        let mut gates = [0.0f32; 4];
        let mut hidden = [0.0f32; 1];
        let mut cell = [0.0f32; 1];
        lstm_cell_step(
            &input,
            &weight_ih,
            &weight_hh,
            &bias_ih,
            &bias_hh,
            &mut gates,
            &mut hidden,
            &mut cell,
        );
        let expected_cell = 1.0f32.tanh() * sigmoid(1.0);
        let expected_hidden = sigmoid(1.0) * expected_cell.tanh();
        assert!((cell[0] - expected_cell).abs() < 1e-6, "cell {}", cell[0]);
        assert!(
            (hidden[0] - expected_hidden).abs() < 1e-6,
            "hidden {}",
            hidden[0]
        );
    }

    #[test]
    fn lstm_forget_gate_carries_the_cell_state() {
        // Force i = 0 (bias -inf-ish), f = 1, o = 1: the cell must be carried unchanged.
        let input = [0.0f32];
        let weight_ih = [0.0f32; 4];
        let weight_hh = [0.0f32; 4];
        // Gate order [input, forget, cell, output].
        let bias_ih = [-40.0f32, 40.0, 0.0, 40.0];
        let bias_hh = [0.0f32; 4];
        let mut gates = [0.0f32; 4];
        let mut hidden = [0.0f32; 1];
        let mut cell = [7.0f32];
        lstm_cell_step(
            &input,
            &weight_ih,
            &weight_hh,
            &bias_ih,
            &bias_hh,
            &mut gates,
            &mut hidden,
            &mut cell,
        );
        assert!((cell[0] - 7.0).abs() < 1e-4, "cell carried: {}", cell[0]);
        assert!(
            (hidden[0] - 7.0f32.tanh()).abs() < 1e-4,
            "hidden {}",
            hidden[0]
        );
    }
}
