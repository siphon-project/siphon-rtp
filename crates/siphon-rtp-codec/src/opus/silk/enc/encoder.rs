//! The SILK encoder's packet driver (libopus `silk/enc_API.c:110-590`) — the entry point that ties
//! the VAD, the stereo conversion, the analysis, the noise-shaping quantiser and the bitstream
//! writer into one Opus frame's SILK layer.
//!
//! # What one call does
//!
//! ```text
//!   per 20 ms (or 10 ms) SILK frame interval, up to three per packet:
//!     stereo_LR_to_MS              -> mid/side + predictor indices + the mid/side rate split
//!     VAD (both channels)          -> signal type, DTX eligibility, the analysis' measures
//!     control_SNR                  -> the quality target from this frame's share of the budget
//!     encode_frame (per channel)   -> analysis -> NSQ -> encode_indices + encode_pulses
//!   once, at the head of the packet:
//!     the LBRR flags and the previous packet's LBRR frames
//!   once, at the end:
//!     patch the VAD/LBRR flag bits back into the first bytes
//! ```
//!
//! # Three things about this layer that are easy to get wrong
//!
//! * **The flags are written twice.** The LP-layer header's VAD and LBRR bits sit at the very start
//!   of the packet, but they are not known until every frame has been encoded. libopus reserves the
//!   space up front by coding a zero with a tailored ICDF and then rewrites those bits in place with
//!   `ec_enc_patch_initial_bits` (`enc_API.c:345-349`, `:535-537`). Anything else would either cost
//!   a whole extra pass or put the flags at the wrong end of the packet.
//! * **LBRR is a packet late.** The redundant copy of frame *n* is carried in packet *n + 1*, which
//!   is the entire point — a receiver that lost packet *n* still has it. So this driver writes the
//!   LBRR frames it generated **last** call, then generates this call's, and the two never appear
//!   in the same packet.
//! * **DTX is decided per packet, not per frame.** A frame being inactive is not enough; every
//!   channel of every frame in the packet has to be in DTX before the payload is dropped
//!   (`enc_API.c:540-542`). Otherwise a 60 ms packet with one active frame would lose the other two.
//!
//! # The seam above this
//!
//! [`SilkEncoder::encode`] takes PCM **at the SILK internal rate** (8, 12 or 16 kHz) and produces the
//! SILK layer of one Opus frame into a caller-supplied [`RangeEncoder`]. The API-rate resampler is
//! the *Opus* layer's (`silk_resampler` driven from `enc_API.c:292-329`), and so is the adaptive
//! high-pass **filter** (`opus_encoder.c:1799-1809`); the mode/bandwidth decision that chooses the
//! internal rate is the same layer's business.
//!
//! The high-pass's *tracker* is the one part of that split that lives here, because libopus puts it
//! here too: `silk_HP_variable_cutoff` (`enc_API.c:398`) drives `variable_HP_smth1_Q15` from SILK's
//! own pitch lag, signal type, speech activity and input quality, none of which the Opus layer can
//! see. [`SilkEncoder::high_pass_smth1_q15`] is what the Opus layer reads out of it, exactly as
//! `opus_encoder.c:1799` reaches into `state_Fxx[0].sCmn`.

use crate::opus::range_coder::RangeEncoder;
use crate::opus::silk::enc::bitstream::{encode_indices, encode_pulses};
use crate::opus::silk::enc::fixed::lin2log;
use crate::opus::silk::enc::frame::{AnalysisConfig, ComplexitySettings};
use crate::opus::silk::enc::rate_control::{
    control_snr, encode_frame, FrameEncodeRequest, FrameEncoderState, LbrrFrame,
};
use crate::opus::silk::enc::stereo::{
    encode_mid_only, encode_predictors, left_right_to_mid_side, StereoEncoderState, StereoIndices,
};
use crate::opus::silk::enc::vad::{
    analyse, classify, DtxState, VadState, LBRR_SPEECH_ACTIVITY_THRESHOLD_Q8,
};
use crate::opus::silk::enc::{SignalMeasures, LA_SHAPE_MS};
use crate::opus::silk::fixed::{smlawb, smulbb, smulwb};
use crate::opus::silk::tables::{LBRR_FLAGS_2_ICDF, LBRR_FLAGS_3_ICDF};
use crate::opus::silk::types::{
    CondCoding, InternalRate, SignalType, SubframeLayout, MAX_FRAMES_PER_PACKET, MAX_FRAME_LENGTH,
};
use crate::CodecError;

/// `ftb` for every SILK ICDF symbol.
const ICDF_FTB: u32 = 8;

/// The float input buffer each channel keeps: `2 * MAX_FRAME_LENGTH + LA_SHAPE_MAX`, as libopus'
/// `x_buf` (`structs_FLP.h:57`).
const INPUT_BUFFER: usize = 2 * MAX_FRAME_LENGTH + LA_SHAPE_MS * 16;

/// `BITRESERVOIR_DECAY_TIME_MS` (`tuning_parameters.h:44`) — how fast the bit reservoir forgives an
/// overspend.
const BIT_RESERVOIR_DECAY_MS: i32 = 500;

/// `VARIABLE_HP_MIN_CUTOFF_HZ` (`tuning_parameters.h:72`).
pub const MIN_CUTOFF_HZ: i32 = 60;
/// `VARIABLE_HP_MAX_CUTOFF_HZ` (`tuning_parameters.h:73`).
pub const MAX_CUTOFF_HZ: i32 = 100;

/// How the encoder should spend its bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateMode {
    /// Variable bitrate: a frame that fits its share of the budget is kept whatever it cost.
    Variable,
    /// Constrained VBR: still variable, but no packet may exceed `max_bytes`.
    ConstrainedVariable,
    /// Constant bitrate: every packet is driven up to the target.
    Constant,
}

/// What the encoder is configured to produce.
#[derive(Debug, Clone, Copy)]
pub struct EncoderConfig {
    /// The SILK internal rate the input is supplied at.
    pub internal_rate: InternalRate,
    /// Opus frame duration in ms — 10, 20, 40 or 60.
    pub duration_ms: usize,
    /// Internal channels: 1 (mono) or 2 (mid/side).
    pub channels: usize,
    /// Target bitrate in bits per second.
    pub bitrate_bps: i32,
    /// Complexity, 0..=10. Genuinely wired: it selects the search depths in
    /// [`ComplexitySettings`], including how many noise-shaping quantiser paths stay alive.
    pub complexity: u8,
    /// How to spend the budget.
    pub rate_mode: RateMode,
    /// Hard cap on the payload, in bytes. Ignored by [`RateMode::Variable`] except as a safety
    /// ceiling.
    pub max_bytes: usize,
    /// Whether in-band FEC (LBRR) may be generated.
    pub use_in_band_fec: bool,
    /// Whether DTX may drop a silent packet.
    pub use_dtx: bool,
    /// The far end's reported packet loss, 0..=100. Moves the LBRR gain increase and the LTP
    /// scaling decision.
    pub packet_loss_percent: i32,
}

impl EncoderConfig {
    /// A sane mono configuration at one rate and duration.
    #[must_use]
    pub fn new(internal_rate: InternalRate, duration_ms: usize, bitrate_bps: i32) -> Self {
        Self {
            internal_rate,
            duration_ms,
            channels: 1,
            bitrate_bps,
            complexity: 10,
            rate_mode: RateMode::Variable,
            max_bytes: 1275,
            use_in_band_fec: false,
            use_dtx: false,
            packet_loss_percent: 0,
        }
    }

    /// `nFramesPerPacket` and `nb_subfr` for this duration.
    fn layout(&self) -> Result<SubframeLayout, CodecError> {
        SubframeLayout::from_duration_ms(self.duration_ms)
    }

    /// Samples per SILK frame at the internal rate.
    fn frame_length(&self) -> Result<usize, CodecError> {
        Ok(self.layout()?.subframe_count * 5 * self.internal_rate.khz())
    }
}

/// One internal channel's whole encoder state.
#[derive(Debug, Clone, Copy)]
struct ChannelState {
    /// The analysis, quantiser and entropy state.
    frame: FrameEncoderState,
    /// The VAD's own state.
    vad: VadState,
    /// DTX bookkeeping.
    dtx: DtxState,
    /// `x_buf` — the float input history, lookahead included.
    input: [f32; INPUT_BUFFER],
    /// `VAD_flags` for this packet.
    vad_flags: [bool; MAX_FRAMES_PER_PACKET],
    /// `LBRR_flags` — set while generating, cleared once written into the *next* packet.
    lbrr_flags: [bool; MAX_FRAMES_PER_PACKET],
    /// `pulses_LBRR` / `indices_LBRR` — the redundant frames awaiting the next packet.
    lbrr: [LbrrFrame; MAX_FRAMES_PER_PACKET],
    /// `LBRR_GainIncreases`.
    lbrr_gain_increase: i32,
    /// Whether LBRR was enabled for the previous packet, which decides the gain increase.
    lbrr_was_enabled: bool,
    /// The VAD's verdict on the frame just analysed. Kept whole rather than reduced to
    /// `speech_activity_Q8`: the stereo smoother reads the activity, the analysis front end reads
    /// all four fields (see [`SignalMeasures`]), and `silk_HP_variable_cutoff` reads the activity
    /// and the lowest input-quality band.
    measures: SignalMeasures,
}

impl Default for ChannelState {
    fn default() -> Self {
        let mut frame = FrameEncoderState::default();
        // `silk_control_encoder`'s reset (`control_codec.c:246-258`).
        frame.analysis.shape.last_gain_index = 10;
        frame.analysis.previous_lag = 100;
        Self {
            frame,
            vad: VadState::default(),
            dtx: DtxState::default(),
            input: [0.0; INPUT_BUFFER],
            vad_flags: [false; MAX_FRAMES_PER_PACKET],
            lbrr_flags: [false; MAX_FRAMES_PER_PACKET],
            lbrr: [LbrrFrame::default(); MAX_FRAMES_PER_PACKET],
            lbrr_gain_increase: 7,
            lbrr_was_enabled: false,
            measures: SignalMeasures::default(),
        }
    }
}

/// What one `encode` call produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeResult {
    /// Payload size in bytes. **Zero means DTX**: every channel of every frame was inactive and the
    /// packet should not be sent at all (`enc_API.c:540-542`).
    pub payload_bytes: usize,
    /// Whether any frame of the packet was voice-active.
    pub active: bool,
    /// Whether this packet carries LBRR data for the *previous* one.
    pub carries_redundancy: bool,
}

/// The SILK encoder.
///
/// Stateful and single-owner by construction: the analysis, quantiser, VAD, stereo and bit
/// reservoir all carry state across packets, so one instance encodes exactly one stream.
#[derive(Debug, Clone)]
pub struct SilkEncoder {
    config: EncoderConfig,
    channels: [ChannelState; 2],
    stereo: StereoEncoderState,
    /// `predIx` / `mid_only_flags` for the packet being built.
    stereo_indices: [StereoIndices; MAX_FRAMES_PER_PACKET],
    /// `prev_decode_only_middle`.
    previous_mid_only: bool,
    /// `nBitsExceeded` — the bit reservoir, in bits, 0..=10000.
    bits_exceeded: i32,
    /// `nBitsUsedLBRR` — an exponential moving average of what LBRR costs.
    lbrr_bits_used: i32,
    /// `state_Fxx[0].sCmn.variable_HP_smth1_Q15` — the SILK-side half of the adaptive high-pass
    /// (`silk_HP_variable_cutoff`). The filter itself is the Opus layer's; only the tracking state
    /// belongs here, because it is driven by SILK's own pitch and quality measures.
    high_pass_smth1_q15: i32,
}

impl SilkEncoder {
    /// Create an encoder for one stream.
    ///
    /// Returns an error only for a configuration SILK does not define — a frame duration outside
    /// 10/20/40/60 ms, or a channel count outside 1..=2.
    pub fn new(config: EncoderConfig) -> Result<Self, CodecError> {
        if config.channels == 0 || config.channels > 2 {
            return Err(CodecError::Unsupported(
                "silk enc: internal channels must be 1 or 2",
            ));
        }
        config.layout()?;
        Ok(Self {
            config,
            channels: [ChannelState::default(); 2],
            stereo: StereoEncoderState::default(),
            stereo_indices: [StereoIndices::default(); MAX_FRAMES_PER_PACKET],
            previous_mid_only: false,
            bits_exceeded: 0,
            lbrr_bits_used: 0,
            // `silk_init_encoder` (`init_encoder.c:58`): start at the minimum cutoff. The C reaches
            // it through the Q16 form and the `-(16<<7)` correction rather than `lin2log(60)`
            // directly, and the two are not quite identical — keep its arithmetic.
            high_pass_smth1_q15: (lin2log(MIN_CUTOFF_HZ << 16) - (16 << 7)) << 8,
        })
    }

    /// The configuration this encoder was built with.
    #[must_use]
    pub fn config(&self) -> &EncoderConfig {
        &self.config
    }

    /// Samples per channel one [`SilkEncoder::encode`] call consumes.
    #[must_use]
    pub fn samples_per_packet(&self) -> usize {
        self.config.duration_ms * self.config.internal_rate.khz()
    }

    /// Encode one Opus frame's worth of SILK.
    ///
    /// `input` is interleaved PCM at the internal rate, `samples_per_packet()` frames of
    /// `config.channels` samples each. `encoder` is written in place; the caller owns the buffer and
    /// is responsible for calling [`RangeEncoder::done`] once the Opus layers above this one have
    /// had their turn.
    pub fn encode(
        &mut self,
        input: &[i16],
        encoder: &mut RangeEncoder<'_>,
    ) -> Result<EncodeResult, CodecError> {
        let layout = self.config.layout()?;
        let frame_length = self.config.frame_length()?;
        let channels = self.config.channels;
        let rate_khz = self.config.internal_rate.khz();
        let required = self.samples_per_packet() * channels;
        if input.len() < required {
            return Err(CodecError::Unsupported(
                "silk enc: input is shorter than one packet",
            ));
        }

        // ── The previous packet's LBRR, and the space the flags will be patched into ───────────
        let carries_redundancy = self.write_packet_header(encoder, layout, channels)?;
        let lbrr_bits = encoder.tell();

        let mut any_active = false;
        for interval in 0..layout.frames_per_packet {
            self.encode_interval(
                encoder,
                input,
                interval,
                layout,
                frame_length,
                rate_khz,
                channels,
                lbrr_bits,
                &mut any_active,
            )?;
        }

        // ── Patch the VAD and LBRR flags back into the head of the packet ─────────────────────
        // Bit order: per channel, one VAD flag per frame (MSB first), then the channel's LBRR flag.
        let mut flags = 0u32;
        for channel in self.channels.iter().take(channels) {
            for frame in 0..layout.frames_per_packet {
                flags = (flags << 1) | u32::from(channel.vad_flags[frame]);
            }
            flags = (flags << 1) | u32::from(channel.lbrr_flags.iter().any(|&flag| flag));
        }
        let flag_bits = (layout.frames_per_packet as u32 + 1) * channels as u32;
        encoder.patch_initial_bits(flags, flag_bits);

        let payload_bytes = (encoder.tell() as usize).div_ceil(8);

        // ── DTX is a whole-packet decision ────────────────────────────────────────────────────
        let all_silent = self.channels[..channels]
            .iter()
            .all(|channel| channel.dtx.in_dtx);
        let payload_bytes = if all_silent { 0 } else { payload_bytes };

        // ── The bit reservoir ─────────────────────────────────────────────────────────────────
        self.bits_exceeded += payload_bytes as i32 * 8;
        self.bits_exceeded -= self.config.bitrate_bps * self.config.duration_ms as i32 / 1000;
        self.bits_exceeded = self.bits_exceeded.clamp(0, 10_000);

        self.previous_mid_only = self.stereo_indices[layout.frames_per_packet - 1].mid_only;
        self.update_lbrr_gain_increase();

        Ok(EncodeResult {
            payload_bytes,
            active: any_active,
            carries_redundancy,
        })
    }

    /// Reserve the flag bits and write the previous packet's LBRR frames (`enc_API.c:345-395`).
    ///
    /// Returns whether any LBRR data was written.
    fn write_packet_header(
        &mut self,
        encoder: &mut RangeEncoder<'_>,
        layout: SubframeLayout,
        channels: usize,
    ) -> Result<bool, CodecError> {
        // Reserve `(frames + 1) * channels` bits by coding a zero from a table sized to exactly
        // that many symbols; `patch_initial_bits` rewrites them at the end.
        let flag_bits = (layout.frames_per_packet + 1) * channels;
        let reserve = [(256 - (256 >> flag_bits)) as u8, 0];
        encoder.enc_icdf(0, &reserve, ICDF_FTB);

        // The per-channel LBRR bit patterns. The global flag itself is patched in at the end, so
        // only the multi-frame pattern symbol is coded here.
        let mut any = false;
        for channel in self.channels.iter().take(channels) {
            let mut symbol = 0usize;
            for frame in 0..layout.frames_per_packet {
                symbol |= usize::from(channel.lbrr_flags[frame]) << frame;
            }
            if symbol > 0 {
                any = true;
                if layout.frames_per_packet > 1 {
                    let icdf: &[u8] = if layout.frames_per_packet == 2 {
                        &LBRR_FLAGS_2_ICDF
                    } else {
                        &LBRR_FLAGS_3_ICDF
                    };
                    encoder.enc_icdf(symbol - 1, icdf, ICDF_FTB);
                }
            }
        }

        // The LBRR frames themselves, in frame-then-channel order.
        for frame in 0..layout.frames_per_packet {
            for channel_index in 0..channels {
                if !self.channels[channel_index].lbrr_flags[frame] {
                    continue;
                }
                if channels == 2 && channel_index == 0 {
                    encode_predictors(encoder, &self.stereo_indices[frame].indices);
                    // With the side channel's own LBRR flag set there is nothing to disambiguate,
                    // so the mid-only flag is not coded (`enc_API.c:373-376`).
                    if !self.channels[1].lbrr_flags[frame] {
                        encode_mid_only(encoder, self.stereo_indices[frame].mid_only);
                    }
                }
                let cond_coding = if frame > 0 && self.channels[channel_index].lbrr_flags[frame - 1]
                {
                    CondCoding::Conditionally
                } else {
                    CondCoding::Independently
                };
                let channel = &mut self.channels[channel_index];
                let redundant = channel.lbrr[frame];
                encode_indices(
                    encoder,
                    &redundant.indices,
                    redundant.seed,
                    self.config.internal_rate,
                    layout.subframe_count,
                    cond_coding,
                    true,
                    &mut channel.frame.entropy,
                );
                let mut pulses = redundant.pulses;
                encode_pulses(
                    encoder,
                    redundant.indices.signal_type,
                    redundant.indices.quant_offset_type,
                    &mut pulses[..],
                    self.config.frame_length()?,
                );
            }
        }

        // The flags belong to the packet just written; clear them so this packet's own LBRR
        // generation starts from zero (`enc_API.c:391-394`).
        for channel in self.channels.iter_mut().take(channels) {
            channel.lbrr_flags = [false; MAX_FRAMES_PER_PACKET];
        }
        Ok(any)
    }

    /// Encode one 10/20 ms interval of the packet, both channels.
    #[allow(clippy::too_many_arguments)]
    fn encode_interval(
        &mut self,
        encoder: &mut RangeEncoder<'_>,
        input: &[i16],
        interval: usize,
        layout: SubframeLayout,
        frame_length: usize,
        rate_khz: usize,
        channels: usize,
        lbrr_bits: i32,
        any_active: &mut bool,
    ) -> Result<(), CodecError> {
        // ── The adaptive high-pass tracker (`enc_API.c:398`) ──────────────────────────────────
        // Runs before this interval's VAD and analysis, so it sees the previous interval's pitch,
        // activity and quality — which is exactly what the C does.
        self.update_high_pass_smoother();

        // ── This interval's share of the packet budget ────────────────────────────────────────
        let mut frame_bits =
            self.config.bitrate_bps * self.config.duration_ms as i32 / 1000 - self.lbrr_bits_used;
        frame_bits /= layout.frames_per_packet as i32;
        let mut target_bps = if self.config.duration_ms == 10 {
            frame_bits * 100
        } else {
            frame_bits * 50
        };
        // The reservoir: an overspend is repaid gradually rather than all at once.
        target_bps -= self.bits_exceeded * 1000 / BIT_RESERVOIR_DECAY_MS;
        if interval > 0 {
            let balance = encoder.tell() - lbrr_bits - frame_bits * interval as i32;
            target_bps -= balance * 1000 / BIT_RESERVOIR_DECAY_MS;
        }
        target_bps = target_bps.clamp(5_000, self.config.bitrate_bps.max(5_000));

        // ── Stereo conversion, or the mono pass-through ───────────────────────────────────────
        let mut mid = [0i16; MAX_FRAME_LENGTH + 2];
        let mut side = [0i16; MAX_FRAME_LENGTH + 2];
        let (mid_bps, side_bps) = self.prepare_interval(
            input,
            interval,
            frame_length,
            rate_khz,
            channels,
            target_bps,
            &mut mid,
            &mut side,
        );

        // ── The VAD, per channel ──────────────────────────────────────────────────────────────
        // Order matters: the side channel is analysed first when it is coded at all, because the
        // stereo decision for the *next* interval reads the mid's activity from this one.
        let mid_only = self.stereo_indices[interval].mid_only;
        if channels == 2 {
            if mid_only {
                self.channels[1].vad_flags[interval] = false;
            } else {
                self.run_vad(1, &side[..frame_length], interval);
            }
        }
        self.run_vad(0, &mid[..frame_length], interval);

        if channels == 2 {
            encode_predictors(encoder, &self.stereo_indices[interval].indices);
            if !self.channels[1].vad_flags[interval] {
                encode_mid_only(encoder, mid_only);
            }
        }

        // ── Encode each channel ───────────────────────────────────────────────────────────────
        for channel_index in 0..channels {
            let channel_bps = if channels == 1 {
                target_bps
            } else if channel_index == 0 {
                mid_bps
            } else {
                side_bps
            };
            if channel_bps <= 0 {
                continue;
            }

            // Independent coding when there is no previous frame of this channel in the packet; the
            // no-LTP-scaling variant when the side channel skipped one earlier in this same packet.
            let cond_coding = if interval as i32 - channel_index as i32 <= 0 {
                CondCoding::Independently
            } else if channel_index > 0 && self.previous_mid_only {
                CondCoding::IndependentlyNoLtpScaling
            } else {
                CondCoding::Conditionally
            };

            let samples = if channel_index == 0 { &mid } else { &side };
            self.encode_channel_frame(
                encoder,
                channel_index,
                interval,
                &samples[..frame_length],
                layout,
                frame_length,
                channel_bps,
                cond_coding,
            )?;
            if self.channels[channel_index].vad_flags[interval] {
                *any_active = true;
            }
        }
        Ok(())
    }

    /// De-interleave (and, in stereo, mid/side-convert) one interval's input.
    ///
    /// Returns the mid and side bitrates. In mono both are the caller's target.
    #[allow(clippy::too_many_arguments)]
    fn prepare_interval(
        &mut self,
        input: &[i16],
        interval: usize,
        frame_length: usize,
        rate_khz: usize,
        channels: usize,
        target_bps: i32,
        mid: &mut [i16; MAX_FRAME_LENGTH + 2],
        side: &mut [i16; MAX_FRAME_LENGTH + 2],
    ) -> (i32, i32) {
        let start = interval * frame_length;
        if channels == 1 {
            for (slot, &sample) in mid[2..frame_length + 2]
                .iter_mut()
                .zip(input[start..].iter())
            {
                *slot = sample;
            }
            self.stereo_indices[interval] = StereoIndices::default();
            return (target_bps, 0);
        }

        for index in 0..frame_length {
            mid[index + 2] = input[2 * (start + index)];
            side[index + 2] = input[2 * (start + index) + 1];
        }
        let previous_activity = self.channels[0].measures.speech_activity_q8;
        let (indices, rates) = left_right_to_mid_side(
            &mut self.stereo,
            &mut mid[..frame_length + 2],
            &mut side[..frame_length + 2],
            target_bps,
            previous_activity,
            false,
            rate_khz,
            frame_length,
        );
        self.stereo_indices[interval] = indices;
        // `silk_stereo_LR_to_MS` leaves the side residual at `x2[n - 1]`, i.e. starting at index 0
        // of the buffer it was handed; shift it up so both channels index alike from 2.
        side.copy_within(0..frame_length, 2);
        (rates.mid_bps, rates.side_bps)
    }

    /// Run the VAD for one channel and record its verdict.
    fn run_vad(&mut self, channel_index: usize, frame: &[i16], interval: usize) {
        let rate = self.config.internal_rate;
        let use_dtx = self.config.use_dtx;
        let channel = &mut self.channels[channel_index];
        let previous_type = channel.frame.analysis.previous_signal_type;
        let mut measures = analyse(&mut channel.vad, frame, rate, previous_type);
        // The Opus layer's own VAD is not modelled here; SILK's own verdict stands.
        let verdict = classify(&mut measures, &mut channel.dtx, use_dtx, true);
        channel.vad_flags[interval] = verdict.active;
        channel.measures = verdict.measures;
    }

    /// `silk_HP_variable_cutoff` (`HP_variable_cutoff.c:39-77`) — track the low end of the pitch
    /// frequency range and move the high-pass cutoff towards it.
    ///
    /// Only the state lives here; the filter itself is the Opus layer's, which is where libopus puts
    /// it too (`opus_encoder.c:1799-1809`). Reading it out is [`SilkEncoder::high_pass_smth1_q15`].
    /// Everything is the *previous* interval's: libopus calls this at the head of an interval,
    /// before the VAD and the analysis have run on the new one (`enc_API.c:398`).
    fn update_high_pass_smoother(&mut self) {
        let channel = &self.channels[0];
        if channel.frame.analysis.previous_signal_type != SignalType::Voiced {
            return;
        }
        let previous_lag = channel.frame.analysis.previous_lag.max(1);
        // Estimate the low end of the pitch frequency range, in the log domain.
        let pitch_freq_hz_q16 =
            ((self.config.internal_rate.khz() as i32 * 1000) << 16) / previous_lag;
        let mut pitch_freq_log_q7 = lin2log(pitch_freq_hz_q16) - (16 << 7);

        // Adjustment based on quality: a noisy input pulls the estimate back down towards the
        // minimum cutoff rather than trusting its pitch track.
        let quality_q15 = channel.measures.input_quality_bands_q15[0];
        pitch_freq_log_q7 = smlawb(
            pitch_freq_log_q7,
            smulwb(-quality_q15 << 2, quality_q15),
            pitch_freq_log_q7 - (lin2log(MIN_CUTOFF_HZ << 16) - (16 << 7)),
        );

        let mut delta_freq_q7 = pitch_freq_log_q7 - (self.high_pass_smth1_q15 >> 8);
        if delta_freq_q7 < 0 {
            // "less smoothing for decreasing pitch frequency, to track something close to the
            // minimum" (`HP_variable_cutoff.c:61`).
            delta_freq_q7 *= 3;
        }
        // SILK_FIX_CONST( VARIABLE_HP_MAX_DELTA_FREQ, 7 ) with VARIABLE_HP_MAX_DELTA_FREQ = 0.4.
        const MAX_DELTA_FREQ_Q7: i32 = 51;
        delta_freq_q7 = delta_freq_q7.clamp(-MAX_DELTA_FREQ_Q7, MAX_DELTA_FREQ_Q7);

        // SILK_FIX_CONST( VARIABLE_HP_SMTH_COEF1, 16 ) with VARIABLE_HP_SMTH_COEF1 = 0.1.
        const SMTH_COEF1_Q16: i32 = 6554;
        self.high_pass_smth1_q15 = smlawb(
            self.high_pass_smth1_q15,
            smulbb(channel.measures.speech_activity_q8, delta_freq_q7),
            SMTH_COEF1_Q16,
        );
        self.high_pass_smth1_q15 = self
            .high_pass_smth1_q15
            .clamp(lin2log(MIN_CUTOFF_HZ) << 8, lin2log(MAX_CUTOFF_HZ) << 8);
    }

    /// `variable_HP_smth1_Q15` — the SILK-side smoother the Opus layer's high-pass reads
    /// (`opus_encoder.c:1799`). Q15 log2 of the cutoff in Hz.
    #[must_use]
    pub fn high_pass_smth1_q15(&self) -> i32 {
        self.high_pass_smth1_q15
    }

    /// Slide one channel's float input buffer along and encode its frame.
    #[allow(clippy::too_many_arguments)]
    fn encode_channel_frame(
        &mut self,
        encoder: &mut RangeEncoder<'_>,
        channel_index: usize,
        interval: usize,
        samples: &[i16],
        layout: SubframeLayout,
        frame_length: usize,
        channel_bps: i32,
        cond_coding: CondCoding,
    ) -> Result<(), CodecError> {
        let settings = ComplexitySettings::for_complexity(self.config.complexity);
        let la_shape = settings.la_shape_ms * self.config.internal_rate.khz();
        let memory = self.config.internal_rate.ltp_memory_length();
        let history = memory.max(la_shape);

        let config = AnalysisConfig {
            internal_rate: self.config.internal_rate,
            layout,
            settings,
            snr_db_q7: control_snr(
                channel_bps,
                self.config.internal_rate,
                layout.subframe_count,
            ),
            use_cbr: self.config.rate_mode == RateMode::Constant,
            packet_loss_percent: self.config.packet_loss_percent,
            frames_per_packet: layout.frames_per_packet as i32,
            lbrr_enabled: self.config.use_in_band_fec,
        };

        // The encoder codes a frame that ends `la_shape` samples before the newest input, which is
        // how the noise-shaping analysis gets its lookahead (`encode_frame_FLP.c:123-134`).
        {
            let channel = &mut self.channels[channel_index];
            channel
                .input
                .copy_within(frame_length..frame_length + history + la_shape, 0);
            for (slot, &sample) in channel.input[history + la_shape..]
                .iter_mut()
                .zip(samples.iter())
                .take(frame_length)
            {
                *slot = f32::from(sample);
            }
            // "Add tiny signal to avoid high CPU load from denormalized floating point numbers"
            // (`encode_frame_FLP.c:136-139`).
            for step in 0..8 {
                channel.input[history + la_shape + step * (frame_length >> 3)] +=
                    (1 - (step as i32 & 2)) as f32 * 1e-6;
            }
        }

        // The frame's own budget. Constrained VBR and CBR both clamp against the packet cap; plain
        // VBR gets the packet cap as a ceiling only, so a frame it wants to spend on is not
        // truncated by an arbitrary per-frame share.
        let packet_cap_bits = (self.config.max_bytes as i32) * 8 - encoder.tell();
        let share = packet_cap_bits.max(0) / (layout.frames_per_packet - interval).max(1) as i32;
        let target_bits =
            channel_bps * self.config.duration_ms as i32 / (1000 * layout.frames_per_packet as i32);
        let max_bits = match self.config.rate_mode {
            RateMode::Variable => packet_cap_bits.max(0),
            RateMode::ConstrainedVariable => share,
            RateMode::Constant => target_bits.min(share),
        }
        .max(64);

        let use_cbr = self.config.rate_mode == RateMode::Constant;

        // LBRR: only for a frame active enough to be worth a redundant copy.
        let lbrr_wanted = self.config.use_in_band_fec
            && self.channels[channel_index].measures.speech_activity_q8
                > LBRR_SPEECH_ACTIVITY_THRESHOLD_Q8;
        let lbrr_continues = interval > 0 && self.channels[channel_index].lbrr_flags[interval - 1];
        let gain_increase = self.channels[channel_index].lbrr_gain_increase;

        let mut pulses = [0i8; MAX_FRAME_LENGTH];
        let channel = &mut self.channels[channel_index];
        let signal_type = if channel.vad_flags[interval] {
            SignalType::Unvoiced
        } else {
            SignalType::Inactive
        };
        // The VAD's whole verdict, not just its activity: `input_quality_bands_Q15` sets the shaping
        // and the lambda, `input_tilt_Q15` moves the pitch threshold and the voiced quantisation
        // offset, and `previous_signal_type` biases the pitch search — see [`SignalMeasures`].
        let measures = channel.measures;

        let request = FrameEncodeRequest {
            signal: &channel.input,
            frame_start: history,
            signal_type,
            cond_coding,
            measures: &measures,
            config: &config,
            max_bits,
            use_cbr,
            lbrr_gain_increase: lbrr_wanted.then_some(gain_increase),
            lbrr_continues,
        };
        // `request` borrows `channel.input`, so the frame encoder gets its own borrow of the rest.
        let mut frame_state = channel.frame;
        let result = encode_frame(&mut frame_state, encoder, &request, &mut pulses)?;
        channel.frame = frame_state;

        if let Some(redundant) = result.lbrr {
            channel.lbrr[interval] = redundant;
            channel.lbrr_flags[interval] = true;
        }
        Ok(())
    }

    /// Recompute the LBRR gain increase for the next packet (`control_codec.c:403-422`).
    ///
    /// It is 7 whenever the previous packet carried no LBRR (that packet was coded at a higher rate,
    /// so the redundant copy has more headroom to give up), and tapers towards 3 as the reported
    /// loss rises — a lossy line needs the redundancy to be *good*, not merely present.
    fn update_lbrr_gain_increase(&mut self) {
        let enabled = self.config.use_in_band_fec;
        for channel in self.channels.iter_mut() {
            channel.lbrr_gain_increase = if !channel.lbrr_was_enabled {
                7
            } else {
                // SILK_FIX_CONST( 0.2, 16 ) = 13107.
                (7 - smulwb(self.config.packet_loss_percent, 13107)).max(3)
            };
            channel.lbrr_was_enabled = enabled;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic voiced-ish mono signal at a known pitch.
    fn voiced(samples: usize, period: usize) -> Vec<i16> {
        let mut state = 24_680u32;
        let mut history = [0.0f32; 2];
        (0..samples)
            .map(|index| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let noise = ((state >> 20) as i32 - 2048) as f32 * 1.5;
                let pulse = if index % period == 0 { 6000.0 } else { 0.0 };
                let value = pulse + noise + 1.5 * history[0] - 0.85 * history[1];
                history[1] = history[0];
                history[0] = value;
                value.clamp(-24_000.0, 24_000.0) as i16
            })
            .collect()
    }

    fn encode_stream(config: EncoderConfig, packets: usize) -> (Vec<Vec<u8>>, Vec<EncodeResult>) {
        let mut encoder = SilkEncoder::new(config).expect("config");
        let per_packet = encoder.samples_per_packet();
        let source = voiced(per_packet * (packets + 1), 5 * config.internal_rate.khz());
        let mut payloads = Vec::new();
        let mut results = Vec::new();
        for packet in 0..packets {
            let mut buffer = vec![0u8; config.max_bytes];
            let mut range = RangeEncoder::new(&mut buffer);
            let start = packet * per_packet * config.channels;
            let result = encoder
                .encode(
                    &source[start..start + per_packet * config.channels],
                    &mut range,
                )
                .expect("encode");
            let used = (range.tell() as usize).div_ceil(8);
            range.done();
            payloads.push(buffer[..used.max(1)].to_vec());
            results.push(result);
        }
        (payloads, results)
    }

    /// Every bandwidth and duration must encode a plausible payload without erroring.
    #[test]
    fn every_bandwidth_and_duration_encodes() {
        for internal_rate in [
            InternalRate::Narrow8k,
            InternalRate::Medium12k,
            InternalRate::Wide16k,
        ] {
            for duration_ms in [10usize, 20, 40, 60] {
                let bitrate = 8_000 + 1_000 * internal_rate.khz() as i32;
                let config = EncoderConfig::new(internal_rate, duration_ms, bitrate);
                let (payloads, results) = encode_stream(config, 6);
                for (index, result) in results.iter().enumerate() {
                    assert!(
                        result.payload_bytes > 0,
                        "{internal_rate:?} {duration_ms} ms packet {index} was empty"
                    );
                    assert!(
                        result.payload_bytes <= config.max_bytes,
                        "{internal_rate:?} {duration_ms} ms packet {index} overflowed"
                    );
                }
                assert!(payloads.iter().all(|payload| !payload.is_empty()));
            }
        }
    }

    /// Stereo must produce a payload and must exercise the side channel at a rate that can afford
    /// one.
    #[test]
    fn stereo_encodes_both_channels() {
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 48_000);
        config.channels = 2;
        let mut encoder = SilkEncoder::new(config).expect("config");
        let per_packet = encoder.samples_per_packet();
        let mono = voiced(per_packet * 8, 80);
        // Decorrelate the two channels so the image is genuinely wide.
        let mut interleaved = vec![0i16; mono.len() * 2];
        for (index, &sample) in mono.iter().enumerate() {
            interleaved[2 * index] = sample;
            interleaved[2 * index + 1] = mono[mono.len() - 1 - index];
        }

        for packet in 0..6 {
            let mut buffer = vec![0u8; config.max_bytes];
            let mut range = RangeEncoder::new(&mut buffer);
            let start = packet * per_packet * 2;
            let result = encoder
                .encode(&interleaved[start..start + per_packet * 2], &mut range)
                .expect("encode");
            range.done();
            assert!(result.payload_bytes > 0, "packet {packet} was empty");
        }
        // A wide image at 48 kb/s must not have collapsed to mid-only.
        assert!(!encoder.stereo_indices[0].mid_only);
    }

    /// CBR must hold every packet at its per-packet target; VBR must not be bound by that target.
    ///
    /// "Hold", not "hit exactly": at this layer CBR is the gain loop driving the frame to within a
    /// few bits of its budget, and the gain multiplier is floored at 64 in Q8, so a frame the
    /// analysis aimed well below the budget cannot always be inflated all the way to it. Exact
    /// constant packet sizes are the *Opus* layer's job, which pads the packet — that is why
    /// `opus_encoder.c` still tracks a padding length after SILK has finished.
    ///
    /// The distinguishing property is the **ceiling**, not the total. VBR's per-frame `max_bits` is
    /// the whole remaining packet cap, so a frame worth spending on is allowed straight past the
    /// nominal per-packet target; CBR's is `min(target, share)` and cannot be. Comparing the two
    /// totals instead would be reading a rate-distortion outcome as if it were a rule, and which way
    /// it falls depends on the content.
    #[test]
    fn cbr_holds_the_target_where_vbr_is_free_to_pass_it() {
        let target_bytes = (24_000 * 20 / 1000 / 8) as usize;
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 24_000);
        // A cap well above the target, so the two modes differ by their own decision rather than by
        // running into the same ceiling.
        config.max_bytes = 100;

        config.rate_mode = RateMode::Variable;
        let (_, vbr) = encode_stream(config, 8);
        config.rate_mode = RateMode::Constant;
        let (_, cbr) = encode_stream(config, 8);

        let cbr_sizes: Vec<usize> = cbr.iter().map(|result| result.payload_bytes).collect();
        let vbr_sizes: Vec<usize> = vbr.iter().map(|result| result.payload_bytes).collect();

        for (index, &size) in cbr_sizes.iter().enumerate() {
            assert!(
                size <= target_bytes + 1,
                "cbr packet {index} overshot its target: {size} of {target_bytes}"
            );
            assert!(
                size * 4 >= target_bytes * 3,
                "cbr packet {index} under-filled badly: {size} of {target_bytes}"
            );
        }
        assert!(
            vbr_sizes.iter().any(|&size| size > target_bytes),
            "vbr {vbr_sizes:?} never passed the per-packet target, so the cap it does not have was \
             never demonstrated (cbr was {cbr_sizes:?})"
        );
    }

    /// Constrained VBR must never exceed the cap, whatever the signal does.
    #[test]
    fn constrained_vbr_respects_the_cap() {
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 64_000);
        config.rate_mode = RateMode::ConstrainedVariable;
        config.max_bytes = 40;
        let (payloads, results) = encode_stream(config, 8);
        for (index, result) in results.iter().enumerate() {
            assert!(
                result.payload_bytes <= 40,
                "packet {index} was {} bytes",
                result.payload_bytes
            );
        }
        assert!(payloads.iter().all(|payload| payload.len() <= 40));
    }

    /// DTX must eventually drop a silent stream to a zero-byte payload, and must not do so while
    /// there is speech.
    #[test]
    fn dtx_drops_a_silent_stream_and_not_a_live_one() {
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 16_000);
        config.use_dtx = true;
        let mut encoder = SilkEncoder::new(config).expect("config");
        let per_packet = encoder.samples_per_packet();

        let mut dropped = 0usize;
        for _ in 0..40 {
            let mut buffer = vec![0u8; config.max_bytes];
            let mut range = RangeEncoder::new(&mut buffer);
            let result = encoder
                .encode(&vec![0i16; per_packet], &mut range)
                .expect("encode");
            range.done();
            if result.payload_bytes == 0 {
                dropped += 1;
            }
        }
        assert!(dropped > 20, "silence produced only {dropped} DTX packets");

        // Speech must bring it straight back.
        let speech = voiced(per_packet * 4, 80);
        let mut buffer = vec![0u8; config.max_bytes];
        let mut range = RangeEncoder::new(&mut buffer);
        let result = encoder
            .encode(&speech[..per_packet], &mut range)
            .expect("encode");
        range.done();
        assert!(result.payload_bytes > 0, "speech was dropped by DTX");
    }

    /// With DTX off, silence must still be coded — the knob has to be wired both ways.
    #[test]
    fn dtx_disabled_always_emits_a_payload() {
        let config = EncoderConfig::new(InternalRate::Wide16k, 20, 16_000);
        let mut encoder = SilkEncoder::new(config).expect("config");
        let per_packet = encoder.samples_per_packet();
        for packet in 0..30 {
            let mut buffer = vec![0u8; config.max_bytes];
            let mut range = RangeEncoder::new(&mut buffer);
            let result = encoder
                .encode(&vec![0i16; per_packet], &mut range)
                .expect("encode");
            range.done();
            assert!(result.payload_bytes > 0, "packet {packet} was dropped");
        }
    }

    /// LBRR must appear one packet *after* the frame it protects, and must cost real bits.
    #[test]
    fn in_band_fec_carries_the_previous_packet() {
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 32_000);
        config.use_in_band_fec = true;
        config.packet_loss_percent = 20;
        let (_, with_fec) = encode_stream(config, 8);

        config.use_in_band_fec = false;
        let (_, without_fec) = encode_stream(config, 8);

        assert!(
            !with_fec[0].carries_redundancy,
            "the first packet cannot carry redundancy for a packet that does not exist"
        );
        assert!(
            with_fec[2..].iter().any(|result| result.carries_redundancy),
            "no packet carried redundancy"
        );
        let with: usize = with_fec.iter().map(|r| r.payload_bytes).sum();
        let without: usize = without_fec.iter().map(|r| r.payload_bytes).sum();
        assert!(with > without, "fec cost nothing: {with} vs {without}");
    }

    /// The adaptive high-pass tracker must start at the minimum cutoff, stay inside
    /// `[VARIABLE_HP_MIN_CUTOFF_HZ, VARIABLE_HP_MAX_CUTOFF_HZ]` forever, and actually *move* on
    /// voiced speech — a tracker pinned at its initial value would read as working.
    #[test]
    fn the_high_pass_tracker_starts_at_the_minimum_and_tracks_voiced_pitch() {
        let config = EncoderConfig::new(InternalRate::Wide16k, 20, 24_000);
        let mut encoder = SilkEncoder::new(config).expect("config");
        let initial = encoder.high_pass_smth1_q15();
        assert_eq!(
            initial,
            (lin2log(MIN_CUTOFF_HZ << 16) - (16 << 7)) << 8,
            "init_encoder.c:58"
        );

        let lower = lin2log(MIN_CUTOFF_HZ) << 8;
        let upper = lin2log(MAX_CUTOFF_HZ) << 8;

        // Nothing but a *voiced* previous frame moves it (`HP_variable_cutoff.c:48`), so drive the
        // state directly rather than hoping a synthetic signal trips the pitch search: an inactive
        // stream would make a broken tracker look correct.
        encoder.channels[0].frame.analysis.previous_signal_type = SignalType::Unvoiced;
        encoder.channels[0].frame.analysis.previous_lag = 80;
        encoder.channels[0].measures.speech_activity_q8 = 256;
        encoder.channels[0].measures.input_quality_bands_q15 = [22_000; 4];
        encoder.update_high_pass_smoother();
        assert_eq!(
            encoder.high_pass_smth1_q15(),
            initial,
            "an unvoiced previous frame must leave the tracker alone"
        );

        // A 200 Hz pitch at 16 kHz — a lag of 80 samples — is well above the 60 Hz floor, so the
        // smoother must climb towards it and then settle inside the legal band.
        encoder.channels[0].frame.analysis.previous_signal_type = SignalType::Voiced;
        let mut previous = initial;
        for step in 0..200 {
            encoder.update_high_pass_smoother();
            let smoothed = encoder.high_pass_smth1_q15();
            assert!(
                (lower..=upper).contains(&smoothed),
                "step {step}: {smoothed} left [{lower}, {upper}]"
            );
            assert!(
                smoothed >= previous,
                "step {step}: the smoother went backwards on a constant pitch"
            );
            previous = smoothed;
        }
        assert!(
            previous > initial,
            "the tracker never left its initial value on voiced speech"
        );

        // Silence has no speech activity, so the update is multiplied by zero and holds.
        encoder.channels[0].measures.speech_activity_q8 = 0;
        let held = encoder.high_pass_smth1_q15();
        for _ in 0..10 {
            encoder.update_high_pass_smoother();
        }
        assert_eq!(
            encoder.high_pass_smth1_q15(),
            held,
            "with no speech activity the smoother's step is zero"
        );

        // And the whole thing must survive a real stream without leaving the band.
        let per_packet = encoder.samples_per_packet();
        let speech = voiced(per_packet * 12, 80);
        for packet in 0..10 {
            let mut buffer = vec![0u8; config.max_bytes];
            let mut range = RangeEncoder::new(&mut buffer);
            let start = packet * per_packet;
            encoder
                .encode(&speech[start..start + per_packet], &mut range)
                .expect("encode");
            range.done();
            let smoothed = encoder.high_pass_smth1_q15();
            assert!(
                (lower..=upper).contains(&smoothed),
                "packet {packet}: {smoothed} left [{lower}, {upper}]"
            );
        }
    }

    /// A configuration SILK does not define must be rejected rather than silently coerced.
    #[test]
    fn illegal_configurations_are_rejected() {
        for duration in [0usize, 5, 15, 30, 80] {
            assert!(
                SilkEncoder::new(EncoderConfig::new(InternalRate::Wide16k, duration, 16_000))
                    .is_err(),
                "{duration} ms must be rejected"
            );
        }
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 16_000);
        config.channels = 3;
        assert!(SilkEncoder::new(config).is_err());
        config.channels = 0;
        assert!(SilkEncoder::new(config).is_err());
    }

    /// Too little input must be an error, not an out-of-bounds read.
    #[test]
    fn a_short_input_is_rejected() {
        let config = EncoderConfig::new(InternalRate::Wide16k, 20, 16_000);
        let mut encoder = SilkEncoder::new(config).expect("config");
        let mut buffer = [0u8; 256];
        let mut range = RangeEncoder::new(&mut buffer);
        assert!(encoder.encode(&[0i16; 100], &mut range).is_err());
    }
}
