//! The neural VAD's 309 633 parameters, embedded in the binary.
//!
//! ## What is embedded, and where it came from
//!
//! [`SILERO_VAD_V5_16K`] is the 16 kHz branch of **Silero VAD v5** (MIT), taken from the upstream
//! release `snakers4/silero-vad` tag `v5.1.2`, file `src/silero_vad/data/silero_vad.onnx`
//! (sha256 `2623a295…d788f`). The tensors were lifted out of that graph once, out of tree, by
//! `reference/silero-vad/extract_weights.py`, and written back as a flat little-endian `f32` blob
//! in the fixed order of [`LAYOUT`]. Nothing in the build or the runtime reads ONNX, safetensors,
//! or any other container format — `include_bytes!` and `f32::from_le_bytes` are the whole reader.
//!
//! The published ONNX carries **two** parameter sets behind an `If` on the `sr` input: a 16 kHz
//! branch (512-sample window, 256-point STFT) and an 8 kHz one (256-sample window, 128-point
//! STFT). Only the 16 kHz branch is embedded — see [`super::neural`] for what an 8 kHz leg does.
//!
//! ## Why the blob is stored in the upstream tensor order rather than the kernel's
//!
//! Keeping the on-disk order identical to the ONNX tensor order means anyone can re-run the
//! extractor against the upstream release and byte-compare the result, which is the whole point of
//! a provenance record. The one re-layout the kernels need — transposing each encoder convolution
//! from `[out][in][tap]` to `[out][tap][in]` so a tap is contiguous over the input channels — is
//! done once per process in [`weights`], not per window and not per leg.

use std::sync::OnceLock;

/// The 16 kHz Silero VAD v5 parameters as a flat little-endian `f32` blob.
///
/// 309 633 values / 1 238 532 bytes, sha256 `b8df2e6e32753b7aa47ab59571b0d9d0b490a223f8dc9118bb388efeaec6f8e3`.
static SILERO_VAD_V5_16K: &[u8] = include_bytes!("silero_vad_v5_16k.f32");

/// Total number of `f32` values in the blob.
pub(crate) const PARAMETER_COUNT: usize = 309_633;

/// Filters in the STFT front end: 129 real and 129 imaginary rows of the Fourier basis.
pub(crate) const STFT_FILTERS: usize = 258;
/// Width of each STFT filter (the transform length).
pub(crate) const STFT_KERNEL: usize = 256;
/// Hop between STFT frames.
pub(crate) const STFT_HOP: usize = 128;
/// Magnitude bins per STFT frame: `STFT_FILTERS / 2`, i.e. `STFT_KERNEL / 2 + 1`.
pub(crate) const SPECTRUM_BINS: usize = STFT_FILTERS / 2;

/// Channel counts of the four encoder convolutions, as `(in, out, stride)`.
pub(crate) const ENCODER_STAGES: [(usize, usize, usize); 4] = [
    (SPECTRUM_BINS, 128, 1),
    (128, 64, 2),
    (64, 64, 2),
    (64, 128, 1),
];

/// LSTM hidden width (and, since the last encoder stage emits 128 channels, its input width).
pub(crate) const HIDDEN_SIZE: usize = 128;

/// The blob's tensor order: `(name, element count)`. Mirrors `LAYOUT` in the extractor.
const LAYOUT: [(&str, usize); 15] = [
    ("stft.forward_basis_buffer", STFT_FILTERS * STFT_KERNEL), // [258, 1, 256]
    ("encoder.0.reparam_conv.weight", 128 * SPECTRUM_BINS * 3),
    ("encoder.0.reparam_conv.bias", 128),
    ("encoder.1.reparam_conv.weight", 64 * 128 * 3),
    ("encoder.1.reparam_conv.bias", 64),
    ("encoder.2.reparam_conv.weight", 64 * 64 * 3),
    ("encoder.2.reparam_conv.bias", 64),
    ("encoder.3.reparam_conv.weight", 128 * 64 * 3),
    ("encoder.3.reparam_conv.bias", 128),
    ("decoder.rnn.weight_ih", 4 * HIDDEN_SIZE * HIDDEN_SIZE),
    ("decoder.rnn.weight_hh", 4 * HIDDEN_SIZE * HIDDEN_SIZE),
    ("decoder.rnn.bias_ih", 4 * HIDDEN_SIZE),
    ("decoder.rnn.bias_hh", 4 * HIDDEN_SIZE),
    ("decoder.decoder.2.weight", HIDDEN_SIZE), // [1, 128, 1]
    ("decoder.decoder.2.bias", 1),
];

/// One encoder convolution's parameters, already in the kernel's `[out][tap][in]` layout.
#[derive(Debug)]
pub(crate) struct EncoderStage {
    /// `[out_channels][3][in_channels]`, row-major.
    pub(crate) weight: Vec<f32>,
    /// `[out_channels]`.
    pub(crate) bias: Vec<f32>,
    /// Input channels this stage consumes.
    pub(crate) in_channels: usize,
    /// Convolution stride.
    pub(crate) stride: usize,
}

/// Every parameter of the network, laid out the way the kernels read it.
#[derive(Debug)]
pub(crate) struct NeuralWeights {
    /// The fixed Fourier basis, `[258][256]` row-major: rows 0..129 real, rows 129..258 imaginary.
    pub(crate) stft_basis: Vec<f32>,
    /// The four encoder convolutions, in order.
    pub(crate) encoder: Vec<EncoderStage>,
    /// `[4 * 128][128]` row-major, PyTorch gate order `[input, forget, cell, output]`.
    pub(crate) lstm_weight_ih: Vec<f32>,
    /// `[4 * 128][128]` row-major, same gate order.
    pub(crate) lstm_weight_hh: Vec<f32>,
    /// `[4 * 128]`.
    pub(crate) lstm_bias_ih: Vec<f32>,
    /// `[4 * 128]`.
    pub(crate) lstm_bias_hh: Vec<f32>,
    /// The `k = 1` output convolution's kernel, `[128]`.
    pub(crate) output_weight: Vec<f32>,
    /// The output convolution's single bias.
    pub(crate) output_bias: f32,
}

/// The process-wide parameter set, decoded and re-laid-out on first use.
///
/// Every detector instance borrows this, so the ~1.2 MB is paid once for the process rather than
/// once per leg, and constructing a detector for a new call allocates only its own scratch.
pub(crate) fn weights() -> &'static NeuralWeights {
    static WEIGHTS: OnceLock<NeuralWeights> = OnceLock::new();
    WEIGHTS.get_or_init(decode)
}

/// Decode the little-endian blob into owned `f32` tensors in kernel layout.
///
/// Infallible by construction: the blob is embedded at compile time and [`LAYOUT`] describes it
/// exactly, which the `blob_length_matches_the_layout` test enforces. A short blob would mean the
/// binary itself was corrupted, so the slice indices below are the right level of checking.
fn decode() -> NeuralWeights {
    let mut cursor = Cursor::new(SILERO_VAD_V5_16K);

    let stft_basis = cursor.take(LAYOUT[0].1);

    let mut encoder = Vec::with_capacity(ENCODER_STAGES.len());
    for &(in_channels, out_channels, stride) in &ENCODER_STAGES {
        // Upstream stores [out][in][tap]; the kernel wants [out][tap][in].
        let flat = cursor.take(out_channels * in_channels * super::kernel::ENCODER_KERNEL);
        let mut weight = vec![0.0f32; flat.len()];
        for out_channel in 0..out_channels {
            for in_channel in 0..in_channels {
                for tap in 0..super::kernel::ENCODER_KERNEL {
                    let source = (out_channel * in_channels + in_channel)
                        * super::kernel::ENCODER_KERNEL
                        + tap;
                    let destination = (out_channel * super::kernel::ENCODER_KERNEL + tap)
                        * in_channels
                        + in_channel;
                    weight[destination] = flat[source];
                }
            }
        }
        let bias = cursor.take(out_channels);
        encoder.push(EncoderStage {
            weight,
            bias,
            in_channels,
            stride,
        });
    }

    let lstm_weight_ih = cursor.take(4 * HIDDEN_SIZE * HIDDEN_SIZE);
    let lstm_weight_hh = cursor.take(4 * HIDDEN_SIZE * HIDDEN_SIZE);
    let lstm_bias_ih = cursor.take(4 * HIDDEN_SIZE);
    let lstm_bias_hh = cursor.take(4 * HIDDEN_SIZE);
    let output_weight = cursor.take(HIDDEN_SIZE);
    let output_bias = cursor.take(1).first().copied().unwrap_or(0.0);

    NeuralWeights {
        stft_basis,
        encoder,
        lstm_weight_ih,
        lstm_weight_hh,
        lstm_bias_ih,
        lstm_bias_hh,
        output_weight,
        output_bias,
    }
}

/// A forward-only reader over the little-endian `f32` blob.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Read `count` little-endian `f32` values. Values past the end of the blob read as zero
    /// rather than panicking; the layout test proves that never happens for the embedded blob.
    fn take(&mut self, count: usize) -> Vec<f32> {
        let mut out = Vec::with_capacity(count);
        for index in 0..count {
            let start = self.offset + index * 4;
            let value = self
                .bytes
                .get(start..start + 4)
                .and_then(|chunk| <[u8; 4]>::try_from(chunk).ok())
                .map_or(0.0, f32::from_le_bytes);
            out.push(value);
        }
        self.offset += count * 4;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_length_matches_the_layout() {
        let declared: usize = LAYOUT.iter().map(|(_, count)| count).sum();
        assert_eq!(
            declared, PARAMETER_COUNT,
            "LAYOUT must sum to the model size"
        );
        assert_eq!(
            SILERO_VAD_V5_16K.len(),
            PARAMETER_COUNT * 4,
            "embedded blob is not {PARAMETER_COUNT} little-endian f32 values"
        );
    }

    #[test]
    fn decoded_tensors_have_the_declared_shapes() {
        let weights = weights();
        assert_eq!(weights.stft_basis.len(), STFT_FILTERS * STFT_KERNEL);
        assert_eq!(weights.encoder.len(), 4);
        for (stage, &(in_channels, out_channels, stride)) in
            weights.encoder.iter().zip(ENCODER_STAGES.iter())
        {
            assert_eq!(stage.in_channels, in_channels);
            assert_eq!(stage.stride, stride);
            assert_eq!(stage.bias.len(), out_channels);
            assert_eq!(stage.weight.len(), out_channels * in_channels * 3);
        }
        assert_eq!(weights.lstm_weight_ih.len(), 4 * HIDDEN_SIZE * HIDDEN_SIZE);
        assert_eq!(weights.lstm_weight_hh.len(), 4 * HIDDEN_SIZE * HIDDEN_SIZE);
        assert_eq!(weights.lstm_bias_ih.len(), 4 * HIDDEN_SIZE);
        assert_eq!(weights.lstm_bias_hh.len(), 4 * HIDDEN_SIZE);
        assert_eq!(weights.output_weight.len(), HIDDEN_SIZE);
    }

    #[test]
    fn every_parameter_is_finite() {
        // A truncated or byte-swapped blob shows up here long before it shows up as a bad decision.
        let weights = weights();
        assert!(weights.stft_basis.iter().all(|v| v.is_finite()));
        assert!(weights.encoder.iter().all(|stage| stage
            .weight
            .iter()
            .chain(stage.bias.iter())
            .all(|v| v.is_finite())));
        assert!(weights.lstm_weight_ih.iter().all(|v| v.is_finite()));
        assert!(weights.lstm_weight_hh.iter().all(|v| v.is_finite()));
        assert!(weights.output_weight.iter().all(|v| v.is_finite()));
        assert!(weights.output_bias.is_finite());
    }

    #[test]
    fn stft_basis_row_zero_is_the_dc_analysis_window() {
        // Row 0 of the real half is the DC bin: the analysis window itself, so every tap is
        // non-negative and the row sums to the window's area. A transposed or mis-ordered read
        // would not have that shape.
        let weights = weights();
        let row = &weights.stft_basis[..STFT_KERNEL];
        assert!(row.iter().all(|&v| v >= 0.0), "DC row must be non-negative");
        let sum: f32 = row.iter().sum();
        assert!(sum > 1.0, "DC row should integrate the window, got {sum}");
    }

    #[test]
    fn encoder_transpose_preserves_every_coefficient() {
        // The re-layout is a permutation: the multiset of coefficients must be unchanged. Compare
        // sorted bit patterns of stage 0 against the raw blob slice it came from.
        let weights = weights();
        let stage = &weights.encoder[0];
        let start = LAYOUT[0].1 * 4;
        let count = stage.weight.len();
        let mut raw: Vec<u32> = (0..count)
            .map(|index| {
                let offset = start + index * 4;
                u32::from_le_bytes([
                    SILERO_VAD_V5_16K[offset],
                    SILERO_VAD_V5_16K[offset + 1],
                    SILERO_VAD_V5_16K[offset + 2],
                    SILERO_VAD_V5_16K[offset + 3],
                ])
            })
            .collect();
        let mut transposed: Vec<u32> = stage.weight.iter().map(|v| v.to_bits()).collect();
        raw.sort_unstable();
        transposed.sort_unstable();
        assert_eq!(raw, transposed);
    }

    #[test]
    fn encoder_transpose_places_each_coefficient_at_the_kernel_index() {
        // Spot-check the index arithmetic itself on stage 1 ([64][128][3] → [64][3][128]).
        let weights = weights();
        let stage = &weights.encoder[1];
        let in_channels = stage.in_channels;
        let blob_offset: usize = LAYOUT[..3].iter().map(|(_, count)| count).sum();
        let read = |index: usize| -> f32 {
            let offset = (blob_offset + index) * 4;
            f32::from_le_bytes([
                SILERO_VAD_V5_16K[offset],
                SILERO_VAD_V5_16K[offset + 1],
                SILERO_VAD_V5_16K[offset + 2],
                SILERO_VAD_V5_16K[offset + 3],
            ])
        };
        for &(out_channel, in_channel, tap) in &[(0usize, 0usize, 0usize), (3, 17, 2), (63, 127, 1)]
        {
            let source = (out_channel * in_channels + in_channel) * 3 + tap;
            let destination = (out_channel * 3 + tap) * in_channels + in_channel;
            assert_eq!(stage.weight[destination], read(source));
        }
    }
}
