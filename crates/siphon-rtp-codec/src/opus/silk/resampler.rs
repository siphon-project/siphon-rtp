//! SILK's own sample-rate converter (RFC 6716 §4.2.9; libopus `silk/resampler*.c`).
//!
//! SILK never decodes at the Opus API rate. It reconstructs at 8, 12 or 16 kHz and this stage lifts
//! the result to whatever the caller asked for (8/12/16/24/48 kHz). RFC 6716 §4.2.9 is explicit that
//! the resampler is **not normative** — a decoder may use any resampler it likes — but it is equally
//! explicit that the reference one is what the conformance vectors were produced with, and the whole
//! point of this port is to match libopus sample for sample. So this is libopus' resampler, with its
//! coefficients, its per-rate delay compensation and its fixed-point arithmetic, not a generic
//! polyphase filter borrowed from elsewhere.
//!
//! Three kernels cover every decoder rate pair (`resampler.c:32-48`):
//!
//! ```text
//!                          Fs_out (kHz)
//!                   8      12     16     24     48
//!            8      C      UF     U      UF     UF
//! Fs_in     12      AF     C      UF     U      UF
//!           16      D      AF     C      UF     UF
//!
//!   C  copy            U   allpass 2x upsample
//!   UF 2x upsample then 8-tap fractional FIR interpolation
//!   AF/D 2nd-order AR filter then a polyphase decimating FIR
//! ```
//!
//! The **input delay** table is the subtle part: each rate pair compensates a different number of
//! input samples so that every configuration presents the same total codec delay. It is applied by
//! holding back `input_delay` samples in the resampler's own delay buffer and processing the first
//! millisecond out of that buffer, which is why [`Resampler::process`] needs at least 1 ms of input
//! per call.

use crate::opus::silk::fixed::{
    add_lshift32, rshift_round, sat16, smlabb, smlawb, smulbb, smulwb, smulww,
};
use crate::CodecError;

/// `RESAMPLER_DOWN_ORDER_FIR0` (`resampler_rom.h:39`) — the fractional decimators' FIR order.
const DOWN_ORDER_FIR0: usize = 18;
/// `RESAMPLER_DOWN_ORDER_FIR1` — the 1:2 decimator's FIR order.
const DOWN_ORDER_FIR1: usize = 24;
/// `RESAMPLER_DOWN_ORDER_FIR2` — the 1:3, 1:4 and 1:6 decimators' FIR order.
const DOWN_ORDER_FIR2: usize = 36;
/// `RESAMPLER_ORDER_FIR_12` (`resampler_rom.h:42`) — the upsampling interpolator's FIR order.
const ORDER_FIR_12: usize = 8;
/// `SILK_RESAMPLER_MAX_FIR_ORDER` (`resampler_structs.h:35`).
const MAX_FIR_ORDER: usize = 36;
/// `SILK_RESAMPLER_MAX_IIR_ORDER` (`resampler_structs.h:36`).
const MAX_IIR_ORDER: usize = 6;
/// `RESAMPLER_MAX_BATCH_SIZE_MS` (`resampler_private.h:40`).
const MAX_BATCH_SIZE_MS: usize = 10;
/// Highest input rate in kHz that reaches an *upsampling* kernel. Upsampling only ever runs from a
/// SILK internal rate — 8→12/16/24/48 on the decoder side, 8→12 and 12→16 on the encoder side — so
/// the interpolator's scratch never needs more than 16 kHz of input per batch.
const MAX_UPSAMPLE_INPUT_KHZ: usize = 16;
/// Highest input rate in kHz that reaches a *decimating* kernel. `silk_resampler_init(forEnc = 1)`
/// accepts 48 kHz in (`resampler.c:92-93`), which is what bounds the decimator's scratch.
const MAX_DOWNSAMPLE_INPUT_KHZ: usize = 48;
/// Largest batch of input samples one upsampling kernel iteration consumes.
const MAX_BATCH_SIZE_UP: usize = MAX_BATCH_SIZE_MS * MAX_UPSAMPLE_INPUT_KHZ;
/// Largest batch of input samples one decimating kernel iteration consumes.
const MAX_BATCH_SIZE_DOWN: usize = MAX_BATCH_SIZE_MS * MAX_DOWNSAMPLE_INPUT_KHZ;
/// `delayBuf[48]` (`resampler_structs.h:44`). Exactly one millisecond at the highest encoder-side
/// input rate, which is what `silk_resampler` folds through it.
const DELAY_BUFFER_LENGTH: usize = 48;

/// `silk_resampler_down2_0` / `_1` — the plain 2x downsampler's allpass coefficients. Unused by the
/// decoder path (it always goes through the AR2 + FIR decimator) but kept with the rest of the ROM.
#[allow(dead_code)]
const DOWN2_COEFFICIENTS: [i16; 2] = [9872, 39809u16 as i16];

/// `silk_resampler_up2_hq_0` — even-phase allpass coefficients of the 2x upsampler
/// (`resampler_rom.h:49`).
const UP2_HQ_EVEN: [i16; 3] = [1746, 14986, (39083i32 - 65536) as i16];
/// `silk_resampler_up2_hq_1` — odd-phase allpass coefficients (`resampler_rom.h:50`).
const UP2_HQ_ODD: [i16; 3] = [6854, 25769, (55542i32 - 65536) as i16];

/// `silk_Resampler_3_4_COEFS` — AR2 pair followed by three polyphase FIR half-branches.
const COEFS_3_4: [i16; 2 + 3 * DOWN_ORDER_FIR0 / 2] = [
    -20694, -13867, //
    -49, 64, 17, -157, 353, -496, 163, 11047, 22205, //
    -39, 6, 91, -170, 186, 23, -896, 6336, 19928, //
    -19, -36, 102, -89, -24, 328, -951, 2568, 15909,
];

/// `silk_Resampler_2_3_COEFS`.
const COEFS_2_3: [i16; 2 + 2 * DOWN_ORDER_FIR0 / 2] = [
    -14457, -14019, //
    64, 128, -122, 36, 310, -768, 584, 9267, 17733, //
    12, 128, 18, -142, 288, -117, -865, 4123, 14459,
];

/// `silk_Resampler_1_2_COEFS`.
const COEFS_1_2: [i16; 2 + DOWN_ORDER_FIR1 / 2] = [
    616, -14323, //
    -10, 39, 58, -46, -84, 120, 184, -315, -541, 1284, 5380, 9024,
];

/// `silk_Resampler_1_3_COEFS`.
const COEFS_1_3: [i16; 2 + DOWN_ORDER_FIR2 / 2] = [
    16102, -15162, //
    -13, 0, 20, 26, 5, -31, -43, -4, 65, 90, 7, -157, -248, -44, 593, 1583, 2612, 3271,
];

/// `silk_Resampler_1_4_COEFS`.
const COEFS_1_4: [i16; 2 + DOWN_ORDER_FIR2 / 2] = [
    22500, -15099, //
    3, -14, -20, -15, 2, 25, 37, 25, -16, -71, -107, -79, 50, 292, 623, 982, 1288, 1464,
];

/// `silk_Resampler_1_6_COEFS`.
const COEFS_1_6: [i16; 2 + DOWN_ORDER_FIR2 / 2] = [
    27540, -15257, //
    17, 12, 8, 1, -10, -22, -30, -32, -22, 3, 44, 100, 168, 243, 317, 381, 429, 455,
];

/// `silk_resampler_frac_FIR_12` — interpolation fractions 1/24, 3/24, … 23/24, half of each
/// symmetric 8-tap branch (`resampler_rom.c:83-96`).
const FRAC_FIR_12: [[i16; ORDER_FIR_12 / 2]; 12] = [
    [189, -600, 617, 30567],
    [117, -159, -1070, 29704],
    [52, 221, -2392, 28276],
    [-4, 529, -3350, 26341],
    [-48, 758, -3956, 23973],
    [-80, 905, -4235, 21254],
    [-99, 972, -4222, 18278],
    [-107, 967, -3957, 15143],
    [-103, 896, -3487, 11950],
    [-91, 773, -2865, 8798],
    [-71, 611, -2143, 5784],
    [-46, 425, -1375, 2996],
];

/// `delay_matrix_dec[3][5]` (`resampler.c:62-67`) — input samples of delay compensation, indexed
/// `[input rate][output rate]` over 8/12/16 kHz in and 8/12/16/24/48 kHz out.
const DELAY_MATRIX_DEC: [[i8; 5]; 3] = [
    // in \ out   8  12  16  24  48
    /*  8 */ [4, 0, 2, 0, 0],
    /* 12 */ [0, 9, 4, 7, 4],
    /* 16 */ [0, 3, 12, 7, 7],
];

/// `delay_matrix_enc[5][3]` (`resampler.c:53-60`) — the same compensation for the *encode*
/// direction, indexed `[input rate][output rate]` over 8/12/16/24/48 kHz in and 8/12/16 kHz out.
///
/// The two matrices are not transposes of each other and must not be conflated: they exist to make
/// the *total* codec delay identical across configurations, and the encode and decode halves of a
/// given rate pair contribute different amounts of it.
const DELAY_MATRIX_ENC: [[i8; 3]; 5] = [
    // in \ out    8  12  16
    /*  8 */ [6, 0, 3],
    /* 12 */ [0, 7, 3],
    /* 16 */ [0, 1, 10],
    /* 24 */ [0, 2, 6],
    /* 48 */ [18, 10, 12],
];

/// Which half of the codec a [`Resampler`] serves — libopus' `forEnc` argument
/// (`silk_resampler_init`, `resampler.c:82`).
///
/// It decides two things and nothing else: which rate range is legal on each side, and which delay
/// matrix supplies the compensation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// `forEnc = 1` — API rate (8/12/16/24/48 kHz) down to a SILK internal rate (8/12/16 kHz).
    Encode,
    /// `forEnc = 0` — a SILK internal rate up to the API rate.
    Decode,
}

/// `rateID(R)` (`resampler.c:70`) — 8/12/16/24/48 kHz to 0..=4.
fn rate_id(rate_hz: u32) -> Option<usize> {
    match rate_hz {
        8_000 => Some(0),
        12_000 => Some(1),
        16_000 => Some(2),
        24_000 => Some(3),
        48_000 => Some(4),
        _ => None,
    }
}

/// Which kernel a rate pair selects (`resampler.c:113-160`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kernel {
    /// Rates are equal: pass through.
    Copy,
    /// Exactly 2:1 up: the allpass upsampler alone.
    Up2Hq,
    /// Any other upsampling ratio: 2x allpass then fractional FIR interpolation.
    IirFir,
    /// Downsampling: a 2nd-order AR filter then a polyphase decimating FIR.
    DownFir {
        /// `FIR_Fracs` — polyphase branches (3 for 3:4, 2 for 2:3, 1 for the integer ratios).
        fractions: usize,
        /// `FIR_Order`.
        order: usize,
        /// `Coefs` — the AR2 pair followed by the FIR half-branches.
        coefficients: &'static [i16],
    },
}

/// SILK's sample-rate converter (libopus `silk_resampler_state_struct`,
/// `resampler_structs.h:38-54`).
///
/// Everything is fixed-size, so a decoder allocates its resamplers once. [`Resampler::configure`] is
/// a no-op when the rate pair has not changed — calling it per packet the way
/// `silk_decoder_set_fs` does must not clear the filter memory, or every packet boundary would
/// click.
#[derive(Debug, Clone)]
pub struct Resampler {
    /// `sIIR[6]` — allpass state (upsampling) or AR2 state (downsampling).
    iir_state: [i32; MAX_IIR_ORDER],
    /// `sFIR.i32[36]` — the decimator's filter memory, in the AR2's Q8 output domain.
    fir_state_i32: [i32; MAX_FIR_ORDER],
    /// `sFIR.i16[8]` — the interpolator's filter memory. The C overlays this on `sFIR.i32` in a
    /// union; the two kernels are mutually exclusive, so keeping them apart costs a few bytes and
    /// removes the aliasing.
    fir_state_i16: [i16; ORDER_FIR_12],
    /// `delayBuf[48]` — the held-back input samples that implement the delay compensation.
    delay_buffer: [i16; DELAY_BUFFER_LENGTH],
    /// Scratch for the upsampling kernel — `2 * batchSize + RESAMPLER_ORDER_FIR_12`.
    upsample_scratch: [i16; 2 * MAX_BATCH_SIZE_UP + ORDER_FIR_12],
    /// Scratch for the decimating kernel — `batchSize + FIR_Order`.
    downsample_scratch: [i32; MAX_BATCH_SIZE_DOWN + MAX_FIR_ORDER],
    kernel: Kernel,
    /// `batchSize` — input samples per kernel iteration.
    batch_size: usize,
    /// `invRatio_Q16` — input samples advanced per output sample, in Q16 (against the 2x-upsampled
    /// signal for the [`Kernel::IirFir`] path).
    inverse_ratio_q16: i32,
    /// `Fs_in_kHz`.
    input_khz: usize,
    /// `Fs_out_kHz`.
    output_khz: usize,
    /// `inputDelay`.
    input_delay: usize,
    /// The configured pair, so a repeat [`Resampler::configure`] can keep the state.
    configured: Option<(u32, u32)>,
    /// Which delay matrix the configured pair drew from. Part of the identity of a configuration: a
    /// rate pair legal in both directions (8→8, 8→12, …) gets a *different* `inputDelay` in each, so
    /// switching direction must re-initialise even though the rates match.
    direction: Direction,
}

impl Resampler {
    /// An unconfigured resampler. It cannot run until [`Resampler::configure`] has picked a rate
    /// pair.
    #[must_use]
    pub fn new() -> Self {
        Self {
            iir_state: [0; MAX_IIR_ORDER],
            fir_state_i32: [0; MAX_FIR_ORDER],
            fir_state_i16: [0; ORDER_FIR_12],
            delay_buffer: [0; DELAY_BUFFER_LENGTH],
            upsample_scratch: [0; 2 * MAX_BATCH_SIZE_UP + ORDER_FIR_12],
            downsample_scratch: [0; MAX_BATCH_SIZE_DOWN + MAX_FIR_ORDER],
            kernel: Kernel::Copy,
            batch_size: 0,
            inverse_ratio_q16: 0,
            input_khz: 0,
            output_khz: 0,
            input_delay: 0,
            configured: None,
            direction: Direction::Decode,
        }
    }

    /// Select the kernel for a rate pair on the **decode** side (libopus `silk_resampler_init`,
    /// `resampler.c:78-170`, with `forEnc = 0`).
    ///
    /// **Clears the filter state**, exactly as the C's opening `silk_memset` does — but only when
    /// the pair actually changes. `silk_decoder_set_fs` guards the call the same way
    /// (`decoder_set_fs.c:51-56`); re-initialising every packet would restart the filters mid-stream.
    pub fn configure(&mut self, input_hz: u32, output_hz: u32) -> Result<(), CodecError> {
        self.configure_direction(input_hz, output_hz, Direction::Decode)
    }

    /// Select the kernel for a rate pair on the **encode** side (`forEnc = 1`): the API rate down to
    /// a SILK internal rate.
    ///
    /// Same guard as [`Resampler::configure`] — a repeat call with the same pair keeps the filter
    /// state, which is what lets `silk_Encode` call it every packet without clicking.
    pub fn configure_for_encoder(
        &mut self,
        input_hz: u32,
        output_hz: u32,
    ) -> Result<(), CodecError> {
        self.configure_direction(input_hz, output_hz, Direction::Encode)
    }

    /// The shared body of both `configure*` entry points.
    fn configure_direction(
        &mut self,
        input_hz: u32,
        output_hz: u32,
        direction: Direction,
    ) -> Result<(), CodecError> {
        if self.configured == Some((input_hz, output_hz)) && self.direction == direction {
            return Ok(());
        }
        // The legal rate ranges swap with the direction (`resampler.c:91-105`).
        let (input_id, output_id) = match direction {
            Direction::Decode => (
                rate_id(input_hz)
                    .filter(|&id| id <= 2)
                    .ok_or(CodecError::Unsupported(
                        "silk: resampler input rate must be 8, 12 or 16 kHz",
                    ))?,
                rate_id(output_hz).ok_or(CodecError::Unsupported(
                    "silk: resampler output rate must be 8, 12, 16, 24 or 48 kHz",
                ))?,
            ),
            Direction::Encode => (
                rate_id(input_hz).ok_or(CodecError::Unsupported(
                    "silk: resampler input rate must be 8, 12, 16, 24 or 48 kHz",
                ))?,
                rate_id(output_hz)
                    .filter(|&id| id <= 2)
                    .ok_or(CodecError::Unsupported(
                        "silk: resampler output rate must be 8, 12 or 16 kHz",
                    ))?,
            ),
        };

        // Clear state (resampler.c:88).
        self.iir_state = [0; MAX_IIR_ORDER];
        self.fir_state_i32 = [0; MAX_FIR_ORDER];
        self.fir_state_i16 = [0; ORDER_FIR_12];
        self.delay_buffer = [0; DELAY_BUFFER_LENGTH];

        self.input_delay = match direction {
            Direction::Decode => DELAY_MATRIX_DEC[input_id][output_id],
            Direction::Encode => DELAY_MATRIX_ENC[input_id][output_id],
        } as usize;
        self.direction = direction;
        self.input_khz = (input_hz / 1000) as usize;
        self.output_khz = (output_hz / 1000) as usize;
        self.batch_size = self.input_khz * MAX_BATCH_SIZE_MS;

        let mut upsampled = 0u32;
        self.kernel = if output_hz > input_hz {
            if output_hz == input_hz * 2 {
                Kernel::Up2Hq
            } else {
                upsampled = 1;
                Kernel::IirFir
            }
        } else if output_hz < input_hz {
            // Every decoder-side downsampling ratio, in the C's order.
            if output_hz * 4 == input_hz * 3 {
                Kernel::DownFir {
                    fractions: 3,
                    order: DOWN_ORDER_FIR0,
                    coefficients: &COEFS_3_4,
                }
            } else if output_hz * 3 == input_hz * 2 {
                Kernel::DownFir {
                    fractions: 2,
                    order: DOWN_ORDER_FIR0,
                    coefficients: &COEFS_2_3,
                }
            } else if output_hz * 2 == input_hz {
                Kernel::DownFir {
                    fractions: 1,
                    order: DOWN_ORDER_FIR1,
                    coefficients: &COEFS_1_2,
                }
            } else if output_hz * 3 == input_hz {
                Kernel::DownFir {
                    fractions: 1,
                    order: DOWN_ORDER_FIR2,
                    coefficients: &COEFS_1_3,
                }
            } else if output_hz * 4 == input_hz {
                Kernel::DownFir {
                    fractions: 1,
                    order: DOWN_ORDER_FIR2,
                    coefficients: &COEFS_1_4,
                }
            } else if output_hz * 6 == input_hz {
                Kernel::DownFir {
                    fractions: 1,
                    order: DOWN_ORDER_FIR2,
                    coefficients: &COEFS_1_6,
                }
            } else {
                return Err(CodecError::Unsupported(
                    "silk: no resampler for this rate ratio",
                ));
            }
        } else {
            Kernel::Copy
        };

        // Input samples per output sample, rounded *up* so the interpolator never walks past the
        // end of a batch (resampler.c:162-167).
        let mut ratio = (((input_hz << (14 + upsampled)) / output_hz) << 2) as i32;
        while smulww(ratio, output_hz as i32) < ((input_hz << upsampled) as i32) {
            ratio += 1;
        }
        self.inverse_ratio_q16 = ratio;
        self.configured = Some((input_hz, output_hz));
        Ok(())
    }

    /// Output samples one call produces for `input_length` input samples.
    #[must_use]
    pub fn output_length(&self, input_length: usize) -> usize {
        if self.input_khz == 0 {
            return 0;
        }
        input_length * self.output_khz / self.input_khz
    }

    /// Resample one block (libopus `silk_resampler`, `resampler.c:174-215`).
    ///
    /// `input` must hold at least 1 ms of samples — the C asserts it, because the first millisecond
    /// is what gets folded through the delay buffer. `out` must have room for
    /// [`Resampler::output_length`] samples. Returns the number written.
    pub fn process(&mut self, out: &mut [i16], input: &[i16]) -> Result<usize, CodecError> {
        if self.configured.is_none() {
            return Err(CodecError::Unsupported("silk: resampler not configured"));
        }
        let input_length = input.len();
        if input_length < self.input_khz {
            return Err(CodecError::Unsupported(
                "silk: resampler needs at least 1 ms of input",
            ));
        }
        let produced = self.output_length(input_length);
        if out.len() < produced {
            return Err(CodecError::Unsupported(
                "silk: resampler output buffer too short",
            ));
        }

        // Fold the held-back samples and the first millisecond of new input together, then run the
        // kernel twice: once over that millisecond, once over the rest of the input
        // (`resampler.c:188-209`). Both calls share the filter state, so the seam is invisible.
        let fresh = self.input_khz - self.input_delay;
        self.delay_buffer[self.input_delay..self.input_khz].copy_from_slice(&input[..fresh]);

        let head_length = self.output_khz;
        let (head_out, tail_out) = out[..produced].split_at_mut(head_length);
        let tail_in = &input[fresh..fresh + (input_length - self.input_khz)];

        let Self {
            iir_state,
            fir_state_i32,
            fir_state_i16,
            delay_buffer,
            upsample_scratch,
            downsample_scratch,
            kernel,
            batch_size,
            inverse_ratio_q16,
            input_khz,
            ..
        } = self;
        let head_in = &delay_buffer[..*input_khz];

        match *kernel {
            Kernel::Copy => {
                head_out.copy_from_slice(head_in);
                tail_out.copy_from_slice(tail_in);
            }
            Kernel::Up2Hq => {
                up2_hq(iir_state, head_out, head_in);
                up2_hq(iir_state, tail_out, tail_in);
            }
            Kernel::IirFir => {
                iir_fir(
                    iir_state,
                    fir_state_i16,
                    upsample_scratch,
                    *batch_size,
                    *inverse_ratio_q16,
                    head_out,
                    head_in,
                );
                iir_fir(
                    iir_state,
                    fir_state_i16,
                    upsample_scratch,
                    *batch_size,
                    *inverse_ratio_q16,
                    tail_out,
                    tail_in,
                );
            }
            Kernel::DownFir {
                fractions,
                order,
                coefficients,
            } => {
                down_fir(
                    iir_state,
                    fir_state_i32,
                    downsample_scratch,
                    *batch_size,
                    *inverse_ratio_q16,
                    fractions,
                    order,
                    coefficients,
                    head_out,
                    head_in,
                );
                down_fir(
                    iir_state,
                    fir_state_i32,
                    downsample_scratch,
                    *batch_size,
                    *inverse_ratio_q16,
                    fractions,
                    order,
                    coefficients,
                    tail_out,
                    tail_in,
                );
            }
        }

        // Hold back the tail for the next call.
        self.delay_buffer[..self.input_delay]
            .copy_from_slice(&input[input_length - self.input_delay..]);
        Ok(produced)
    }
}

impl Default for Resampler {
    fn default() -> Self {
        Self::new()
    }
}

/// `silk_resampler_private_up2_HQ` (`resampler_private_up2_HQ.c:38-102`) — 2x upsampling through
/// two three-section allpass chains, one per output phase. State and arithmetic are Q10.
fn up2_hq(state: &mut [i32; MAX_IIR_ORDER], out: &mut [i16], input: &[i16]) {
    for (index, &sample) in input.iter().enumerate() {
        let in32 = i32::from(sample) << 10;

        // Even output sample: three allpass sections.
        let mut y = in32 - state[0];
        let mut x = smulwb(y, i32::from(UP2_HQ_EVEN[0]));
        let mut out32_1 = state[0] + x;
        state[0] = in32 + x;

        y = out32_1 - state[1];
        x = smulwb(y, i32::from(UP2_HQ_EVEN[1]));
        let mut out32_2 = state[1] + x;
        state[1] = out32_1 + x;

        y = out32_2 - state[2];
        x = smlawb(y, y, i32::from(UP2_HQ_EVEN[2]));
        out32_1 = state[2] + x;
        state[2] = out32_2 + x;

        out[2 * index] = sat16(rshift_round(out32_1, 10));

        // Odd output sample.
        y = in32 - state[3];
        x = smulwb(y, i32::from(UP2_HQ_ODD[0]));
        out32_1 = state[3] + x;
        state[3] = in32 + x;

        y = out32_1 - state[4];
        x = smulwb(y, i32::from(UP2_HQ_ODD[1]));
        out32_2 = state[4] + x;
        state[4] = out32_1 + x;

        y = out32_2 - state[5];
        x = smlawb(y, y, i32::from(UP2_HQ_ODD[2]));
        out32_1 = state[5] + x;
        state[5] = out32_2 + x;

        out[2 * index + 1] = sat16(rshift_round(out32_1, 10));
    }
}

/// `silk_resampler_private_IIR_FIR` (`resampler_private_IIR_FIR.c:65-107`) — 2x upsample, then walk
/// the upsampled signal at `inverse_ratio_q16` picking an 8-tap symmetric interpolation branch per
/// fractional position.
#[allow(clippy::too_many_arguments)]
fn iir_fir(
    iir_state: &mut [i32; MAX_IIR_ORDER],
    fir_state: &mut [i16; ORDER_FIR_12],
    scratch: &mut [i16],
    batch_size: usize,
    inverse_ratio_q16: i32,
    out: &mut [i16],
    input: &[i16],
) {
    scratch[..ORDER_FIR_12].copy_from_slice(fir_state);
    let mut input = input;
    let mut written = 0usize;
    // The last batch's size — what the C's closing `memcpy` indexes by. Every path out of the loop
    // assigns it first.
    let mut consumed;
    loop {
        let batch = input.len().min(batch_size);
        up2_hq(
            iir_state,
            &mut scratch[ORDER_FIR_12..ORDER_FIR_12 + 2 * batch],
            &input[..batch],
        );
        // "+ 1 because 2x upsampling".
        let max_index_q16 = (batch as i32) << 17;
        let mut index_q16 = 0i32;
        while index_q16 < max_index_q16 {
            let table_index = smulwb(index_q16 & 0xFFFF, 12) as usize;
            let base = (index_q16 >> 16) as usize;
            let taps = &scratch[base..base + ORDER_FIR_12];
            let near = &FRAC_FIR_12[table_index];
            let far = &FRAC_FIR_12[11 - table_index];
            let mut result_q15 = smulbb(i32::from(taps[0]), i32::from(near[0]));
            result_q15 = smlabb(result_q15, i32::from(taps[1]), i32::from(near[1]));
            result_q15 = smlabb(result_q15, i32::from(taps[2]), i32::from(near[2]));
            result_q15 = smlabb(result_q15, i32::from(taps[3]), i32::from(near[3]));
            result_q15 = smlabb(result_q15, i32::from(taps[4]), i32::from(far[3]));
            result_q15 = smlabb(result_q15, i32::from(taps[5]), i32::from(far[2]));
            result_q15 = smlabb(result_q15, i32::from(taps[6]), i32::from(far[1]));
            result_q15 = smlabb(result_q15, i32::from(taps[7]), i32::from(far[0]));
            out[written] = sat16(rshift_round(result_q15, 15));
            written += 1;
            index_q16 += inverse_ratio_q16;
        }
        input = &input[batch..];
        consumed = batch;
        if input.is_empty() {
            break;
        }
        scratch.copy_within(batch * 2..batch * 2 + ORDER_FIR_12, 0);
    }
    fir_state.copy_from_slice(&scratch[consumed * 2..consumed * 2 + ORDER_FIR_12]);
}

/// `silk_resampler_private_AR2` (`resampler_private_AR2.c:36-54`) — a 2nd-order AR filter with
/// single delay elements, output in Q8.
fn ar2(
    state: &mut [i32; MAX_IIR_ORDER],
    out_q8: &mut [i32],
    input: &[i16],
    coefficients_q14: &[i16],
) {
    for (slot, &sample) in out_q8.iter_mut().zip(input.iter()) {
        let mut out32 = add_lshift32(state[0], i32::from(sample), 8);
        *slot = out32;
        out32 = ((out32 as u32) << 2) as i32;
        state[0] = smlawb(state[1], out32, i32::from(coefficients_q14[0]));
        state[1] = smulwb(out32, i32::from(coefficients_q14[1]));
    }
}

/// `silk_resampler_private_down_FIR` (`resampler_private_down_FIR.c:145-194`) — AR2 pre-filter then
/// a polyphase decimating FIR. The three FIR orders have distinct inner products in the C
/// (`FIR0` is polyphase and asymmetric per branch; `FIR1`/`FIR2` are single-branch and symmetric),
/// and that distinction is reproduced here.
#[allow(clippy::too_many_arguments)]
fn down_fir(
    iir_state: &mut [i32; MAX_IIR_ORDER],
    fir_state: &mut [i32; MAX_FIR_ORDER],
    scratch: &mut [i32],
    batch_size: usize,
    inverse_ratio_q16: i32,
    fractions: usize,
    order: usize,
    coefficients: &[i16],
    out: &mut [i16],
    input: &[i16],
) {
    scratch[..order].copy_from_slice(&fir_state[..order]);
    let fir_coefficients = &coefficients[2..];
    let mut input = input;
    let mut written = 0usize;
    // The last batch's size — what the C's closing `memcpy` indexes by. Every path out of the loop
    // assigns it first.
    let mut consumed;
    loop {
        let batch = input.len().min(batch_size);
        ar2(
            iir_state,
            &mut scratch[order..order + batch],
            &input[..batch],
            coefficients,
        );
        let max_index_q16 = (batch as i32) << 16;
        let mut index_q16 = 0i32;
        while index_q16 < max_index_q16 {
            let base = (index_q16 >> 16) as usize;
            let taps = &scratch[base..base + order];
            let result_q6 = if order == DOWN_ORDER_FIR0 {
                let branch = smulwb(index_q16 & 0xFFFF, fractions as i32) as usize;
                let near = &fir_coefficients[DOWN_ORDER_FIR0 / 2 * branch..];
                let far = &fir_coefficients[DOWN_ORDER_FIR0 / 2 * (fractions - 1 - branch)..];
                let mut accumulator = smulwb(taps[0], i32::from(near[0]));
                for tap in 1..DOWN_ORDER_FIR0 / 2 {
                    accumulator = smlawb(accumulator, taps[tap], i32::from(near[tap]));
                }
                for tap in 0..DOWN_ORDER_FIR0 / 2 {
                    accumulator = smlawb(
                        accumulator,
                        taps[DOWN_ORDER_FIR0 - 1 - tap],
                        i32::from(far[tap]),
                    );
                }
                accumulator
            } else {
                // Symmetric single-branch FIR: fold the two halves before the multiply.
                let half = order / 2;
                let mut accumulator = smulwb(
                    taps[0].wrapping_add(taps[order - 1]),
                    i32::from(fir_coefficients[0]),
                );
                for tap in 1..half {
                    accumulator = smlawb(
                        accumulator,
                        taps[tap].wrapping_add(taps[order - 1 - tap]),
                        i32::from(fir_coefficients[tap]),
                    );
                }
                accumulator
            };
            out[written] = sat16(rshift_round(result_q6, 6));
            written += 1;
            index_q16 += inverse_ratio_q16;
        }
        input = &input[batch..];
        consumed = batch;
        // The C breaks on `inLen > 1` rather than `> 0`: a single trailing sample cannot produce an
        // output at any supported ratio, so it is folded into the state instead.
        if input.len() <= 1 {
            break;
        }
        scratch.copy_within(batch..batch + order, 0);
    }
    fir_state[..order].copy_from_slice(&scratch[consumed..consumed + order]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_ids_match_the_c_macro() {
        // rateID(R) = ((((R>>12) - (R>16000)) >> (R>24000)) - 1).
        for rate in [8_000u32, 12_000, 16_000, 24_000, 48_000] {
            let expected =
                (((rate >> 12) as i32 - i32::from(rate > 16_000)) >> u32::from(rate > 24_000)) - 1;
            assert_eq!(rate_id(rate), Some(expected as usize), "rateID({rate})");
        }
        assert_eq!(rate_id(44_100), None);
    }

    #[test]
    fn configure_rejects_rates_outside_the_decoder_matrix() {
        let mut resampler = Resampler::new();
        assert!(resampler.configure(44_100, 48_000).is_err());
        assert!(
            resampler.configure(24_000, 48_000).is_err(),
            "decode side is 8/12/16 kHz in"
        );
        assert!(resampler.configure(8_000, 44_100).is_err());
        for input in [8_000u32, 12_000, 16_000] {
            for output in [8_000u32, 12_000, 16_000, 24_000, 48_000] {
                assert!(
                    resampler.configure(input, output).is_ok(),
                    "{input} -> {output} must be supported"
                );
            }
        }
    }

    /// Every decimator ROM, diffed against `silk/resampler_rom.c` element by element.
    ///
    /// Three of these tables — 1:3, 1:4 and 1:6 — are only ever selected by a 24 or 48 kHz *encoder*
    /// input, so until the encode direction existed nothing in the suite touched them and a
    /// transcription slip would have sat there unnoticed. The check re-parses the C rather than
    /// trusting a hand comparison, and skips when the reference tree is absent.
    #[test]
    fn decimator_coefficients_match_libopus() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../reference/opus/opus-1.5.2/silk/resampler_rom.c");
        let Ok(source) = std::fs::read_to_string(&path) else {
            eprintln!("skipping: {} is absent", path.display());
            return;
        };

        // `silk_<name>[ ... ] = { <i16 list> };`
        let parse = |name: &str| -> Vec<i16> {
            let start = source
                .find(&format!("silk_{name}["))
                .unwrap_or_else(|| panic!("{name} not found in resampler_rom.c"));
            let open = start + source[start..].find('{').expect("opening brace");
            let close = open + source[open..].find("};").expect("closing brace");
            source[open + 1..close]
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(|token| token.parse::<i16>().expect("i16 literal"))
                .collect()
        };

        for (name, ours) in [
            ("Resampler_3_4_COEFS", &COEFS_3_4[..]),
            ("Resampler_2_3_COEFS", &COEFS_2_3[..]),
            ("Resampler_1_2_COEFS", &COEFS_1_2[..]),
            ("Resampler_1_3_COEFS", &COEFS_1_3[..]),
            ("Resampler_1_4_COEFS", &COEFS_1_4[..]),
            ("Resampler_1_6_COEFS", &COEFS_1_6[..]),
        ] {
            assert_eq!(parse(name), ours, "silk_{name}");
        }

        let fractional = parse("resampler_frac_FIR_12");
        let flattened: Vec<i16> = FRAC_FIR_12.iter().flatten().copied().collect();
        assert_eq!(fractional, flattened, "silk_resampler_frac_FIR_12");

        let up2: Vec<i16> = UP2_HQ_EVEN
            .iter()
            .chain(UP2_HQ_ODD.iter())
            .copied()
            .collect();
        assert_eq!(
            up2.len(),
            6,
            "the 2x upsampler has two three-section chains"
        );
    }

    /// The encode direction accepts 24 and 48 kHz *in* and only SILK internal rates *out* — the
    /// mirror image of the decode direction's range (`resampler.c:91-105`).
    #[test]
    fn encoder_configure_accepts_the_api_rates_and_rejects_the_decoder_range() {
        let mut resampler = Resampler::new();
        for input in [8_000u32, 12_000, 16_000, 24_000, 48_000] {
            for output in [8_000u32, 12_000, 16_000] {
                assert!(
                    resampler.configure_for_encoder(input, output).is_ok(),
                    "{input} -> {output} must be supported on the encode side"
                );
            }
        }
        assert!(
            resampler.configure_for_encoder(16_000, 48_000).is_err(),
            "encode side is 8/12/16 kHz out"
        );
        assert!(resampler.configure_for_encoder(44_100, 16_000).is_err());
        assert!(resampler.configure_for_encoder(16_000, 44_100).is_err());
    }

    /// `delay_matrix_enc` (`resampler.c:53-60`), value for value. This is not cosmetic: the delay is
    /// what makes every configuration present the same total codec delay, so a transposed or
    /// mis-copied entry shifts the encoder's output against the decoder's by a few samples and shows
    /// up as a quality loss nothing else in the suite would name.
    #[test]
    fn encoder_delay_matrix_matches_the_c_table() {
        let expected: [[usize; 3]; 5] = [[6, 0, 3], [0, 7, 3], [0, 1, 10], [0, 2, 6], [18, 10, 12]];
        let mut resampler = Resampler::new();
        for (input_index, input) in [8_000u32, 12_000, 16_000, 24_000, 48_000]
            .into_iter()
            .enumerate()
        {
            for (output_index, output) in [8_000u32, 12_000, 16_000].into_iter().enumerate() {
                resampler
                    .configure_for_encoder(input, output)
                    .expect("configure");
                assert_eq!(
                    resampler.input_delay, expected[input_index][output_index],
                    "delay_matrix_enc[{input}][{output}]"
                );
                assert!(
                    resampler.input_delay <= resampler.input_khz,
                    "the delay must fit in the one millisecond `silk_resampler` folds through it"
                );
            }
        }
    }

    /// A rate pair legal in both directions carries a *different* delay in each, so re-configuring
    /// the same pair the other way round must re-initialise rather than short-circuit.
    #[test]
    fn switching_direction_reinitialises_a_shared_rate_pair() {
        let mut resampler = Resampler::new();
        resampler.configure(8_000, 8_000).expect("decode");
        assert_eq!(resampler.input_delay, 4, "delay_matrix_dec[8][8]");
        resampler
            .configure_for_encoder(8_000, 8_000)
            .expect("encode");
        assert_eq!(resampler.input_delay, 6, "delay_matrix_enc[8][8]");
        resampler.configure(8_000, 8_000).expect("decode again");
        assert_eq!(resampler.input_delay, 4);
    }

    /// The three decimating kernels the decode side never reaches — 1:3, 1:4 and 1:6 — are exactly
    /// the ones a 24/48 kHz API rate needs.
    #[test]
    fn encoder_kernel_selection_follows_the_resampler_matrix() {
        let mut resampler = Resampler::new();
        let cases = [
            (48_000u32, 16_000u32, 1usize, DOWN_ORDER_FIR2),
            (48_000, 12_000, 1, DOWN_ORDER_FIR2),
            (48_000, 8_000, 1, DOWN_ORDER_FIR2),
            (24_000, 8_000, 1, DOWN_ORDER_FIR2),
            (24_000, 12_000, 1, DOWN_ORDER_FIR1),
            (24_000, 16_000, 2, DOWN_ORDER_FIR0),
            (16_000, 12_000, 3, DOWN_ORDER_FIR0),
            (16_000, 8_000, 1, DOWN_ORDER_FIR1),
            (12_000, 8_000, 2, DOWN_ORDER_FIR0),
        ];
        for (input, output, fractions, order) in cases {
            resampler
                .configure_for_encoder(input, output)
                .expect("configure");
            match resampler.kernel {
                Kernel::DownFir {
                    fractions: got_fractions,
                    order: got_order,
                    ..
                } => {
                    assert_eq!(got_fractions, fractions, "{input} -> {output} fractions");
                    assert_eq!(got_order, order, "{input} -> {output} order");
                }
                other => panic!("{input} -> {output} selected {other:?}"),
            }
        }
        // The three non-decimating encode pairs.
        resampler.configure_for_encoder(8_000, 16_000).expect("up2");
        assert_eq!(resampler.kernel, Kernel::Up2Hq);
        resampler.configure_for_encoder(8_000, 12_000).expect("uf");
        assert_eq!(resampler.kernel, Kernel::IirFir);
        resampler
            .configure_for_encoder(16_000, 16_000)
            .expect("copy");
        assert_eq!(resampler.kernel, Kernel::Copy);
    }

    /// Every encode-side pair must consume a 20 ms API frame and emit exactly 20 ms at the internal
    /// rate, without walking off either buffer. The 48 kHz input is the case the decode-side
    /// buffers were never sized for.
    #[test]
    fn encoder_resampling_produces_one_frame_per_frame() {
        for input in [8_000u32, 12_000, 16_000, 24_000, 48_000] {
            for output in [8_000u32, 12_000, 16_000] {
                let mut resampler = Resampler::new();
                resampler
                    .configure_for_encoder(input, output)
                    .expect("configure");
                let input_frame = input as usize / 50;
                let output_frame = output as usize / 50;
                // A 300 Hz tone, well inside every target band, so nothing is filtered away.
                let samples: Vec<i16> = (0..input_frame * 5)
                    .map(|index| {
                        let phase =
                            2.0 * std::f64::consts::PI * 300.0 * index as f64 / f64::from(input);
                        (8000.0 * phase.sin()) as i16
                    })
                    .collect();
                let mut out = vec![0i16; output_frame];
                let mut peak = 0i32;
                for block in 0..5 {
                    let produced = resampler
                        .process(
                            &mut out,
                            &samples[block * input_frame..(block + 1) * input_frame],
                        )
                        .expect("process");
                    assert_eq!(produced, output_frame, "{input} -> {output}");
                    if block > 0 {
                        peak = peak.max(out.iter().map(|&s| i32::from(s).abs()).max().unwrap_or(0));
                    }
                }
                // The tone survives: a broken kernel selection or a mis-sized scratch buffer either
                // panics above or leaves silence here.
                assert!(
                    peak > 4_000,
                    "{input} -> {output} lost the tone (peak {peak})"
                );
            }
        }
    }

    #[test]
    fn kernel_selection_follows_the_resampler_matrix() {
        let cases = [
            (8_000u32, 8_000u32, Kernel::Copy),
            (12_000, 12_000, Kernel::Copy),
            (16_000, 16_000, Kernel::Copy),
            (8_000, 16_000, Kernel::Up2Hq),
            (12_000, 24_000, Kernel::Up2Hq),
            (8_000, 12_000, Kernel::IirFir),
            (8_000, 24_000, Kernel::IirFir),
            (8_000, 48_000, Kernel::IirFir),
            (12_000, 16_000, Kernel::IirFir),
            (12_000, 48_000, Kernel::IirFir),
            (16_000, 24_000, Kernel::IirFir),
            (16_000, 48_000, Kernel::IirFir),
        ];
        let mut resampler = Resampler::new();
        for (input, output, expected) in cases {
            resampler.configure(input, output).expect("configure");
            assert_eq!(resampler.kernel, expected, "{input} -> {output}");
        }
        // The three decimating pairs.
        resampler.configure(16_000, 12_000).expect("configure");
        assert!(matches!(
            resampler.kernel,
            Kernel::DownFir { fractions: 3, .. }
        ));
        resampler.configure(12_000, 8_000).expect("configure");
        assert!(matches!(
            resampler.kernel,
            Kernel::DownFir { fractions: 2, .. }
        ));
        resampler.configure(16_000, 8_000).expect("configure");
        assert!(matches!(
            resampler.kernel,
            Kernel::DownFir {
                fractions: 1,
                order: DOWN_ORDER_FIR1,
                ..
            }
        ));
    }

    /// The delay compensation is what equalises total codec delay across configurations; a wrong
    /// entry shifts the whole output by a sample or two, which `opus_compare` notices.
    #[test]
    fn input_delays_match_the_decoder_matrix() {
        let mut resampler = Resampler::new();
        for (input, output, expected) in [
            (8_000u32, 8_000u32, 4usize),
            (8_000, 16_000, 2),
            (8_000, 48_000, 0),
            (12_000, 12_000, 9),
            (12_000, 16_000, 4),
            (12_000, 24_000, 7),
            (12_000, 48_000, 4),
            (16_000, 12_000, 3),
            (16_000, 16_000, 12),
            (16_000, 24_000, 7),
            (16_000, 48_000, 7),
        ] {
            resampler.configure(input, output).expect("configure");
            assert_eq!(resampler.input_delay, expected, "{input} -> {output}");
        }
    }

    /// `invRatio_Q16` is rounded *up* until `SMULWW(ratio, Fs_out) >= Fs_in << up2x`, which is what
    /// keeps the interpolator inside its batch. Recomputing the postcondition here catches a wrong
    /// `up2x` as much as a wrong divide.
    #[test]
    fn inverse_ratio_is_rounded_up_past_the_exact_value() {
        let mut resampler = Resampler::new();
        for (input, output) in [
            (8_000u32, 12_000u32),
            (8_000, 24_000),
            (8_000, 48_000),
            (12_000, 16_000),
            (12_000, 48_000),
            (16_000, 24_000),
            (16_000, 48_000),
            (16_000, 8_000),
            (16_000, 12_000),
            (12_000, 8_000),
        ] {
            resampler.configure(input, output).expect("configure");
            let upsampled = u32::from(matches!(resampler.kernel, Kernel::IirFir));
            assert!(
                smulww(resampler.inverse_ratio_q16, output as i32) >= ((input << upsampled) as i32),
                "{input} -> {output}: ratio {} too small",
                resampler.inverse_ratio_q16
            );
            // One less must fail the same test — i.e. it really is the smallest such value.
            assert!(
                smulww(resampler.inverse_ratio_q16 - 1, output as i32)
                    < ((input << upsampled) as i32),
                "{input} -> {output}: ratio {} is not minimal",
                resampler.inverse_ratio_q16
            );
        }
    }

    /// 16 kHz to 48 kHz is the pair every wideband SILK stream uses at the conformance rate.
    #[test]
    fn sixteen_to_fortyeight_is_the_wideband_conformance_pair() {
        let mut resampler = Resampler::new();
        resampler.configure(16_000, 48_000).expect("configure");
        assert_eq!(
            resampler.inverse_ratio_q16, 43_691,
            "2/3 in Q16, rounded up"
        );
        assert_eq!(resampler.output_length(320), 960);
    }

    /// Equal rates copy verbatim, but still through the delay buffer — so the output is the input
    /// delayed by `input_delay` samples, and the first call emits that many zeros.
    #[test]
    fn equal_rates_copy_through_the_delay_buffer() {
        let mut resampler = Resampler::new();
        resampler.configure(16_000, 16_000).expect("configure");
        let input: Vec<i16> = (1..=320).collect();
        let mut out = vec![0i16; 320];
        assert_eq!(resampler.process(&mut out, &input).expect("resample"), 320);
        // 16 -> 16 kHz has a 12-sample delay.
        assert!(out[..12].iter().all(|&value| value == 0));
        assert_eq!(&out[12..], &input[..308]);

        // The held-back samples come out at the start of the next call.
        let mut second = vec![0i16; 320];
        let more: Vec<i16> = (321..=640).collect();
        resampler.process(&mut second, &more).expect("resample");
        assert_eq!(&second[..12], &input[308..]);
    }

    /// A resampler is a linear time-invariant filter: silence in must be silence out, at every
    /// supported pair. This is the cheap catch for an uninitialised state or a stray offset.
    #[test]
    fn silence_stays_silent_at_every_rate_pair() {
        for input_hz in [8_000u32, 12_000, 16_000] {
            for output_hz in [8_000u32, 12_000, 16_000, 24_000, 48_000] {
                let mut resampler = Resampler::new();
                resampler.configure(input_hz, output_hz).expect("configure");
                let input_length = (input_hz / 1000) as usize * 20;
                let input = vec![0i16; input_length];
                let mut out = vec![1234i16; resampler.output_length(input_length)];
                let produced = resampler.process(&mut out, &input).expect("resample");
                assert_eq!(produced, out.len());
                assert!(
                    out.iter().all(|&value| value == 0),
                    "{input_hz} -> {output_hz} must pass silence"
                );
            }
        }
    }

    /// A steady DC level must come out as the same steady level (up to the filters' settling), at
    /// every pair — the direct check that the FIR branches sum to unity gain.
    #[test]
    fn direct_current_gain_is_unity_at_every_rate_pair() {
        for input_hz in [8_000u32, 12_000, 16_000] {
            for output_hz in [8_000u32, 12_000, 16_000, 24_000, 48_000] {
                let mut resampler = Resampler::new();
                resampler.configure(input_hz, output_hz).expect("configure");
                let input_length = (input_hz / 1000) as usize * 20;
                let input = vec![4000i16; input_length];
                let mut out = vec![0i16; resampler.output_length(input_length)];
                // Run several frames so every filter has settled.
                for _ in 0..8 {
                    resampler.process(&mut out, &input).expect("resample");
                }
                let tail = &out[out.len() / 2..];
                for &sample in tail {
                    assert!(
                        (i32::from(sample) - 4000).abs() <= 40,
                        "{input_hz} -> {output_hz}: settled output {sample}, want ~4000"
                    );
                }
            }
        }
    }

    #[test]
    fn process_rejects_short_input_and_short_output() {
        let mut resampler = Resampler::new();
        assert!(resampler.process(&mut [0i16; 48], &[0i16; 16]).is_err());
        resampler.configure(16_000, 48_000).expect("configure");
        // Less than 1 ms of input.
        assert!(resampler.process(&mut [0i16; 48], &[0i16; 8]).is_err());
        // Output buffer too short.
        assert!(resampler.process(&mut [0i16; 47], &[0i16; 16]).is_err());
        assert!(resampler.process(&mut [0i16; 48], &[0i16; 16]).is_ok());
    }

    /// Re-configuring with the same pair must not disturb the filter memory, or every packet
    /// boundary would restart the filters.
    #[test]
    fn reconfiguring_the_same_pair_keeps_the_state() {
        let mut resampler = Resampler::new();
        resampler.configure(16_000, 48_000).expect("configure");
        let input: Vec<i16> = (0..320).map(|n| ((n * 311) % 2000) as i16 - 1000).collect();
        let mut out = vec![0i16; 960];
        resampler.process(&mut out, &input).expect("resample");
        let state = resampler.iir_state;
        let delay = resampler.delay_buffer;
        resampler.configure(16_000, 48_000).expect("reconfigure");
        assert_eq!(resampler.iir_state, state);
        assert_eq!(resampler.delay_buffer, delay);
        // A genuine change does clear it.
        resampler.configure(8_000, 48_000).expect("reconfigure");
        assert_eq!(resampler.iir_state, [0; MAX_IIR_ORDER]);
    }

    /// The upsampler's allpass sections are pure delay-and-add: an impulse must spread energy
    /// forward, never backward, and the total must stay bounded.
    #[test]
    fn up2_hq_impulse_response_is_causal_and_bounded() {
        let mut state = [0i32; MAX_IIR_ORDER];
        let mut input = [0i16; 64];
        input[0] = 10_000;
        let mut out = [0i16; 128];
        up2_hq(&mut state, &mut out, &input);
        assert!(out[..2].iter().any(|&value| value != 0), "must respond");
        let energy: i64 = out.iter().map(|&v| i64::from(v) * i64::from(v)).sum();
        let reference = 2 * i64::from(input[0]) * i64::from(input[0]);
        assert!(
            energy < 4 * reference,
            "allpass energy {energy} should stay near {reference}"
        );
    }

    /// **The** resampler gate: bit-exactness against libopus itself.
    ///
    /// Everything above tests properties; this runs the same deterministic pseudo-random signal
    /// through both implementations, eight 20 ms blocks per rate pair so the filter state carries
    /// across calls, and compares a rolling checksum of every output sample. The expected values
    /// come from `silk_resampler` built out of the unpacked libopus source. A single wrong
    /// coefficient, a wrong delay-matrix entry, or an off-by-one in the batch seam moves the
    /// checksum.
    #[test]
    fn matches_libopus_sample_for_sample() {
        for (input_hz, output_hz, expected) in [
            (8_000u32, 8_000u32, -8_076_406_635_430_183_502i64),
            (8_000, 12_000, 7_855_052_904_552_741_562),
            (8_000, 16_000, -4_963_888_612_156_231_691),
            (8_000, 24_000, -3_533_604_803_321_499_006),
            (8_000, 48_000, -604_529_034_392_234_925),
            (12_000, 8_000, 7_807_978_523_737_016_995),
            (12_000, 12_000, -8_020_975_465_137_177_212),
            (12_000, 16_000, 5_100_970_597_061_236_221),
            (12_000, 24_000, 4_648_099_795_756_605_246),
            (12_000, 48_000, 7_674_040_553_452_925_299),
            (16_000, 8_000, 1_550_413_241_243_624_922),
            (16_000, 12_000, -2_770_176_305_398_124_454),
            (16_000, 16_000, 6_989_329_816_212_925_360),
            (16_000, 24_000, 4_229_203_421_240_013_267),
            (16_000, 48_000, 7_047_290_820_016_192_231),
        ] {
            let mut resampler = Resampler::new();
            resampler.configure(input_hz, output_hz).expect("configure");
            let frame = (input_hz / 1000) as usize * 20;
            let produced = resampler.output_length(frame);
            let mut input = vec![0i16; frame];
            let mut out = vec![0i16; produced];
            let mut seed: u32 = 987_654_321;
            let mut checksum: i64 = 0;
            for _ in 0..8 {
                for slot in input.iter_mut() {
                    seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    *slot = (((seed >> 16) % 8001) as i32 - 4000) as i16;
                }
                resampler.process(&mut out, &input).expect("resample");
                for &sample in &out {
                    checksum = checksum.wrapping_mul(31).wrapping_add(i64::from(sample));
                }
            }
            assert_eq!(
                checksum, expected,
                "{input_hz} -> {output_hz} diverges from libopus"
            );
        }
    }

    /// The FIR interpolation branches are the 24-phase half-table; each pair must sum to a
    /// near-unity Q15 gain, which is what makes the DC test above pass at every fraction.
    #[test]
    fn interpolation_branches_have_unit_gain() {
        for branch in 0..12usize {
            let near = FRAC_FIR_12[branch];
            let far = FRAC_FIR_12[11 - branch];
            let sum: i32 = near.iter().map(|&v| i32::from(v)).sum::<i32>()
                + far.iter().map(|&v| i32::from(v)).sum::<i32>();
            assert!(
                (sum - 32_768).abs() < 40,
                "branch {branch}: taps sum to {sum}, want ~32768"
            );
        }
    }
}
