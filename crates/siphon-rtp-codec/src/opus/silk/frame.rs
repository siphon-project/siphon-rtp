//! The SILK frame integrator — every stage of RFC 6716 §4.2, in Table 5 order, for one Opus frame
//! (libopus `silk_Decode` in `dec_API.c` plus `silk_decode_frame` in `decode_frame.c`).
//!
//! Everything else in this module tree decodes or synthesises one *thing*. This is the file that
//! knows the order they happen in, which channel each belongs to, and which of them are skipped for
//! a given packet shape. Getting the order wrong does not produce slightly wrong audio: the range
//! decoder desynchronises and the rest of the packet is noise.
//!
//! # One call per 20 ms
//!
//! [`SilkDecoder::decode_silk_frame`] is `silk_Decode`: it handles **one 20 ms interval** of an Opus
//! frame, for both channels. A 40 or 60 ms packet calls it two or three times, with `new_packet`
//! true only on the first — the LP-layer header and all the LBRR data are read on that first call.
//! [`SilkDecoder::decode`] is the wrapper that runs a whole Opus frame.
//!
//! # The order, and why each conditional is there
//!
//! ```text
//!   first interval only:  VAD + LBRR flags, both channels          §4.2.3-4
//!                         every LBRR frame, parsed and discarded    §4.2.5   (normal decode only)
//!   every interval:       stereo weights + mid-only flag            §4.2.7.1-2 (stereo only)
//!                         mid channel:   one SILK frame             §4.2.7, §4.2.7.9, §4.4
//!                         side channel:  one SILK frame             §4.2.7   (unless mid-only)
//!                         mid/side -> left/right                    §4.2.8   (stereo in and out)
//!                         resample to the API rate                  §4.2.9
//! ```
//!
//! The LBRR frames are *parsed* on a normal decode even though their audio is thrown away: they sit
//! in the bitstream ahead of the regular frames, so skipping them without decoding their symbols
//! would leave the range decoder pointing at the wrong bit. Only their index and pulse stages run —
//! `silk_decode_parameters` is deliberately not called for them, so the running log-gain and the
//! NLSF interpolation anchor must not move (`dec_API.c:272-274`).

use crate::opus::range_coder::RangeDecoder;
use crate::opus::silk::cng;
use crate::opus::silk::decoder::{ChannelState, SilkDecoder, MID_CHANNEL, SIDE_CHANNEL};
use crate::opus::silk::excitation;
use crate::opus::silk::frame_type::decode_frame_type;
use crate::opus::silk::gains::decode_gain_indices;
use crate::opus::silk::ltp;
use crate::opus::silk::nlsf;
use crate::opus::silk::plc;
use crate::opus::silk::stereo_pred::{
    decode_mid_only, decode_stereo_weights, mid_only_flag_is_coded,
};
use crate::opus::silk::stereo_unmix::{buffer_mono, mid_side_to_left_right, STEREO_HISTORY};
use crate::opus::silk::synthesis::{decode_core, update_output_history, DecoderControl};
use crate::opus::silk::types::{CondCoding, SignalType};
use crate::CodecError;

/// Longest one SILK frame can be at the API rate — 20 ms at 48 kHz.
pub const MAX_API_FRAME_LENGTH: usize = 960;

/// libopus' `lostFlag` (`define.h:170-172`) — what this call is being asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossFlag {
    /// `FLAG_DECODE_NORMAL` — decode the regular frames, skipping past any LBRR data.
    Normal,
    /// `FLAG_PACKET_LOST` — no bitstream; conceal.
    PacketLost,
    /// `FLAG_DECODE_LBRR` — decode the *redundant* copy of this interval carried by a later packet
    /// (RFC 6716 §4.2.5, in-band FEC). Falls back to concealment for any interval that has no LBRR
    /// frame.
    DecodeLbrr,
}

impl LossFlag {
    /// Whether the range decoder is read at all.
    #[must_use]
    fn reads_bitstream(self) -> bool {
        !matches!(self, Self::PacketLost)
    }
}

impl SilkDecoder {
    /// Decode every 20 ms interval of one Opus frame (RFC 6716 §4.2), writing interleaved PCM at the
    /// API rate.
    ///
    /// This is the loop `opus_decode_frame` runs around `silk_Decode` (`opus_decoder.c:427-448`).
    /// [`SilkDecoder::configure`] must have been called for this packet first — it is what fixes the
    /// internal rate, the channel count and the frame geometry, all of which come from the Opus TOC
    /// rather than from the SILK payload.
    ///
    /// `output` must hold `frames_per_packet * samples_per_interval * api_channels` samples.
    /// Returns the number of samples written **per channel**.
    pub fn decode(
        &mut self,
        range: Option<&mut RangeDecoder<'_>>,
        loss: LossFlag,
        output: &mut [i16],
    ) -> Result<usize, CodecError> {
        let intervals = self.channel(MID_CHANNEL)?.frames_per_packet();
        let api_channels = self.api_channel_count;
        let mut range = range;
        let mut written = 0usize;
        for interval in 0..intervals {
            let produced = self.decode_silk_frame(
                range.as_deref_mut(),
                loss,
                interval == 0,
                &mut output[written * api_channels..],
            )?;
            written += produced;
        }
        Ok(written)
    }

    /// Decode one 20 ms interval, both channels (libopus `silk_Decode`, `dec_API.c:132-452`).
    ///
    /// `new_packet` is the C's `newPacketFlag`: true only for the first interval of an Opus frame,
    /// which is when the LP-layer header and the LBRR data are read.
    ///
    /// Returns the number of samples written per channel, at the API rate.
    pub fn decode_silk_frame(
        &mut self,
        range: Option<&mut RangeDecoder<'_>>,
        loss: LossFlag,
        new_packet: bool,
        output: &mut [i16],
    ) -> Result<usize, CodecError> {
        let channel_count = self.channel_count;
        let api_channels = self.api_channel_count;
        let rate = self.channels[MID_CHANNEL].internal_rate()?;
        let frame_length = self.channels[MID_CHANNEL].frame_length()?;
        let intervals = self.channels[MID_CHANNEL].frames_per_packet();
        let mut range = range;

        if new_packet {
            for channel in self.channels.iter_mut().take(channel_count) {
                channel.frames_decoded = 0;
            }
        }

        // ── LP-layer header and LBRR data, once per Opus frame (§4.2.3-5) ──────────────────────
        if loss.reads_bitstream() && self.channels[MID_CHANNEL].frames_decoded == 0 {
            let decoder = range
                .as_deref_mut()
                .ok_or(CodecError::Unsupported("silk: no bitstream to decode"))?;
            self.decode_lp_layer_header(decoder)?;
            if loss == LossFlag::Normal {
                self.skip_lbrr_frames(decoder, intervals, channel_count)?;
            }
        }

        // ── Stereo prediction weights and the mid-only flag (§4.2.7.1-2) ───────────────────────
        let interval = self.channels[MID_CHANNEL].frames_decoded;
        let mut decode_only_middle = false;
        // On a lost packet the previous frame's weights are reused verbatim (`dec_API.c:295-299`),
        // which is what this is seeded with.
        let mut weights_q13 = [
            i32::from(self.stereo.pred_prev_q13[0]),
            i32::from(self.stereo.pred_prev_q13[1]),
        ];
        if channel_count == 2 {
            let this_interval_coded = match loss {
                LossFlag::Normal => true,
                LossFlag::DecodeLbrr => self.channels[MID_CHANNEL].lbrr_flags[interval],
                LossFlag::PacketLost => false,
            };
            if this_interval_coded {
                let side_coded = match loss {
                    LossFlag::Normal => self.channels[SIDE_CHANNEL].vad_flags[interval],
                    _ => self.channels[SIDE_CHANNEL].lbrr_flags[interval],
                };
                let decoder = range
                    .as_deref_mut()
                    .ok_or(CodecError::Unsupported("silk: no bitstream to decode"))?;
                let weights = decode_stereo_weights(decoder);
                weights_q13 = [weights.w0_q13, weights.w1_q13];
                if mid_only_flag_is_coded(side_coded) {
                    decode_only_middle = decode_mid_only(decoder);
                }
            }
        }

        // The side channel is coming back after being skipped: the LTP history it would reach into
        // belongs to a different time interval, so it has to go (`dec_API.c:302-310`). This runs
        // *before* the frames are decoded, while `prev_decode_only_middle` still holds the old value
        // that the conditional-coding decision below also depends on.
        if channel_count == 2 && !decode_only_middle && self.prev_decode_only_middle {
            self.reset_side_channel_prediction();
        }

        // `has_side` (`dec_API.c:329-334`).
        let has_side = match loss {
            LossFlag::Normal => !decode_only_middle,
            _ => {
                !self.prev_decode_only_middle
                    || (channel_count == 2
                        && loss == LossFlag::DecodeLbrr
                        && self.channels[SIDE_CHANNEL].lbrr_flags
                            [self.channels[SIDE_CHANNEL].frames_decoded])
            }
        };

        // ── One SILK frame per coded channel (§4.2.7, §4.2.7.9, §4.4) ──────────────────────────
        for index in 0..channel_count {
            if index == MID_CHANNEL || has_side {
                let cond_coding = self.conditional_coding(index, loss)?;
                self.decode_one_channel(range.as_deref_mut(), index, loss, cond_coding)?;
            } else {
                self.channel_pcm[index][STEREO_HISTORY..STEREO_HISTORY + frame_length].fill(0);
            }
            self.channels[index].frames_decoded += 1;
        }

        // ── Mid/side to left/right, or the mono one-sample delay (§4.2.8) ──────────────────────
        {
            let Self {
                stereo,
                channel_pcm,
                ..
            } = self;
            let (mid, side) = channel_pcm.split_at_mut(1);
            if api_channels == 2 && channel_count == 2 {
                mid_side_to_left_right(
                    stereo,
                    &mut mid[0],
                    &mut side[0],
                    weights_q13,
                    rate,
                    frame_length,
                )?;
            } else {
                buffer_mono(stereo, &mut mid[0], frame_length)?;
            }
        }

        // ── Resample to the API rate (§4.2.9) ──────────────────────────────────────────────────
        let produced = frame_length * self.api_rate_hz as usize / (rate.khz() * 1000);
        if output.len() < produced * api_channels {
            return Err(CodecError::Unsupported(
                "silk: output buffer shorter than the decoded frame",
            ));
        }
        for index in 0..api_channels.min(channel_count) {
            let Self {
                channels,
                channel_pcm,
                resample_scratch,
                ..
            } = self;
            // The resampler is fed from index 1, not 0 — the §4.2.8 stage leaves its output shifted
            // by the one-sample prediction delay (`dec_API.c:407`).
            let input = &channel_pcm[index][1..1 + frame_length];
            if api_channels == 2 {
                channels[index]
                    .resampler
                    .process(&mut resample_scratch[..produced], input)?;
                for (sample, &value) in resample_scratch[..produced].iter().enumerate() {
                    output[index + 2 * sample] = value;
                }
            } else {
                channels[index].resampler.process(output, input)?;
            }
        }

        // A mono stream feeding a stereo API duplicates the channel — except right after a stereo
        // stream collapses to mono, where the C runs the *side* channel's resampler over the same
        // input so its filter memory does not produce a discontinuity (`dec_API.c:417-432`).
        if api_channels == 2 && channel_count == 1 {
            if self.stereo_to_mono {
                let Self {
                    channels,
                    channel_pcm,
                    resample_scratch,
                    ..
                } = self;
                let input = &channel_pcm[MID_CHANNEL][1..1 + frame_length];
                channels[SIDE_CHANNEL]
                    .resampler
                    .process(&mut resample_scratch[..produced], input)?;
                for (sample, &value) in resample_scratch[..produced].iter().enumerate() {
                    output[1 + 2 * sample] = value;
                }
            } else {
                for sample in 0..produced {
                    output[1 + 2 * sample] = output[2 * sample];
                }
            }
        }

        // `dec_API.c:442-449`: a lost packet drops the gain clamping so the energy cannot bounce
        // back when the talker was fading out; otherwise the mid-only decision carries forward.
        if loss == LossFlag::PacketLost {
            for channel in self.channels.iter_mut().take(channel_count) {
                channel.last_gain_index = 10;
            }
        } else {
            self.prev_decode_only_middle = decode_only_middle;
        }
        Ok(produced)
    }

    /// The conditional-coding regime for `index`'s frame in the current interval
    /// (`dec_API.c:339-354`).
    ///
    /// `FrameIndex = channel_state[0].nFramesDecoded - n`: the side channel's frame index is one
    /// *behind* the mid channel's, so the second SILK frame of a 40 ms packet is still independently
    /// coded for it.
    fn conditional_coding(&self, index: usize, loss: LossFlag) -> Result<CondCoding, CodecError> {
        let frame_index = self.channels[MID_CHANNEL].frames_decoded;
        if frame_index <= index {
            return Ok(CondCoding::Independently);
        }
        let relative = frame_index - index;
        if loss == LossFlag::DecodeLbrr {
            return Ok(if self.channels[index].lbrr_flags[relative - 1] {
                CondCoding::Conditionally
            } else {
                CondCoding::Independently
            });
        }
        Ok(ChannelState::cond_coding(
            relative,
            true,
            index > MID_CHANNEL && self.prev_decode_only_middle,
        ))
    }

    /// Parse and discard every LBRR frame in this packet (`dec_API.c:252-278`).
    fn skip_lbrr_frames(
        &mut self,
        decoder: &mut RangeDecoder<'_>,
        intervals: usize,
        channel_count: usize,
    ) -> Result<(), CodecError> {
        let rate = self.channels[MID_CHANNEL].internal_rate()?;
        let layout = self.channels[MID_CHANNEL].layout();
        let frame_length = layout.frame_length(rate);
        for interval in 0..intervals {
            for index in 0..channel_count {
                if !self.channels[index].lbrr_flags[interval] {
                    continue;
                }
                if channel_count == 2 && index == MID_CHANNEL {
                    let _ = decode_stereo_weights(decoder);
                    if !self.channels[SIDE_CHANNEL].lbrr_flags[interval] {
                        let _ = decode_mid_only(decoder);
                    }
                }
                let cond_coding = if interval > 0 && self.channels[index].lbrr_flags[interval - 1] {
                    CondCoding::Conditionally
                } else {
                    CondCoding::Independently
                };
                // An LBRR frame is always active (`decode_indices.c:51`).
                let frame_type = decode_frame_type(decoder, true)?;
                let signal_type = frame_type.signal_type();
                decode_gain_indices(decoder, signal_type, cond_coding, layout.subframe_count)?;
                nlsf::decode_indices(decoder, rate, signal_type, layout.subframe_count)?;
                let indices = if signal_type == SignalType::Voiced {
                    let channel = &self.channels[index];
                    ltp::decode_indices(
                        decoder,
                        rate,
                        layout,
                        cond_coding,
                        channel.ec_prev_signal_type,
                        channel.ec_prev_lag_index,
                    )
                } else {
                    ltp::LtpIndices::unvoiced(layout.subframe_count)
                };
                {
                    let channel = &mut self.channels[index];
                    if signal_type == SignalType::Voiced {
                        channel.ec_prev_lag_index = indices.lag_index;
                    }
                    channel.ec_prev_signal_type = signal_type;
                }
                let seed = excitation::decode_seed(decoder);
                let Self {
                    pulses,
                    excitation_scratch,
                    ..
                } = self;
                excitation::decode(
                    decoder,
                    signal_type,
                    frame_type.quant_offset_type(),
                    frame_length,
                    seed,
                    pulses,
                    &mut excitation_scratch[..frame_length],
                )?;
            }
        }
        Ok(())
    }

    /// One channel's SILK frame (libopus `silk_decode_frame`, `decode_frame.c:43-169`).
    ///
    /// Writes `frame_length` samples of internal-rate PCM into `self.channel_pcm[index][2..]`,
    /// leaving room for the two history samples the §4.2.8 stage prepends.
    fn decode_one_channel(
        &mut self,
        range: Option<&mut RangeDecoder<'_>>,
        index: usize,
        loss: LossFlag,
        cond_coding: CondCoding,
    ) -> Result<(), CodecError> {
        let rate = self.channels[index].internal_rate()?;
        let layout = self.channels[index].layout();
        let frame_length = layout.frame_length(rate);
        let interval = self.channels[index].frames_decoded;
        let mut control = DecoderControl::new();

        let decode_this_frame = match loss {
            LossFlag::Normal => true,
            LossFlag::DecodeLbrr => self.channels[index].lbrr_flags[interval],
            LossFlag::PacketLost => false,
        };

        let mut signal_type = SignalType::Inactive;
        if decode_this_frame {
            let decoder = range.ok_or(CodecError::Unsupported("silk: no bitstream to decode"))?;
            // §4.2.7.3 frame type. An LBRR frame is always active; a regular frame follows its VAD
            // flag (`decode_indices.c:44-51`).
            let active = match loss {
                LossFlag::DecodeLbrr => true,
                _ => self.channels[index].vad_flags[interval],
            };
            let frame_type = decode_frame_type(decoder, active)?;
            signal_type = frame_type.signal_type();
            let quant_offset_type = frame_type.quant_offset_type();

            // §4.2.7.4 subframe gains, decoded and dequantized in one call.
            let gains = self.decode_subframe_gains(decoder, index, signal_type, cond_coding)?;
            control.gains_q16 = gains.gains_q16;

            // §4.2.7.5 NLSFs, and both halves' Q12 LPC filters.
            let coefficients = self.decode_nlsf(decoder, index, signal_type)?;
            control.pred_coef_q12[0] = coefficients.first_half_q12;
            control.pred_coef_q12[1] = coefficients.second_half_q12;
            // `NLSF_interpolation_flag` (`decode_core.c:65-69`), on the *effective* factor.
            let interpolated_nlsf = coefficients.interpolation_factor_q2 < 4;

            // §4.2.7.6 pitch lags, LTP filter and scaling.
            let ltp_indices = if signal_type == SignalType::Voiced {
                let channel = &self.channels[index];
                ltp::decode_indices(
                    decoder,
                    rate,
                    layout,
                    cond_coding,
                    channel.ec_prev_signal_type,
                    channel.ec_prev_lag_index,
                )
            } else {
                ltp::LtpIndices::unvoiced(layout.subframe_count)
            };
            {
                let channel = &mut self.channels[index];
                if signal_type == SignalType::Voiced {
                    channel.ec_prev_lag_index = ltp_indices.lag_index;
                }
                channel.ec_prev_signal_type = signal_type;
            }
            let parameters = ltp::dequantize(&ltp_indices, rate);
            control.pitch_lags = parameters.pitch_lags;
            control.ltp_coef_q14 = parameters.filter_taps_q14;
            control.ltp_scale_q14 = i32::from(parameters.scale_q14);

            // §4.2.7.7-8 seed and excitation, then §4.2.7.9 synthesis.
            let seed = excitation::decode_seed(decoder);
            let Self {
                channels,
                channel_pcm,
                pulses,
                excitation_scratch,
                core_scratch,
                ..
            } = self;
            excitation::decode(
                decoder,
                signal_type,
                quant_offset_type,
                frame_length,
                seed,
                pulses,
                &mut excitation_scratch[..frame_length],
            )?;
            channels[index].excitation_q14[..frame_length]
                .copy_from_slice(&excitation_scratch[..frame_length]);
            decode_core(
                &mut channels[index],
                &mut control,
                signal_type,
                interpolated_nlsf,
                &mut channel_pcm[index][STEREO_HISTORY..STEREO_HISTORY + frame_length],
                core_scratch,
            )?;
            update_output_history(
                &mut channels[index],
                &channel_pcm[index][STEREO_HISTORY..STEREO_HISTORY + frame_length],
            )?;
        }

        // PLC: state update on a good frame, concealment on a lost one — both through the same entry
        // point, exactly as `silk_decode_frame` does (`decode_frame.c:119-148`).
        {
            let Self {
                channels,
                channel_pcm,
                plc_scratch,
                ..
            } = self;
            plc::run(
                &mut channels[index],
                &mut control,
                signal_type,
                !decode_this_frame,
                &mut channel_pcm[index][STEREO_HISTORY..STEREO_HISTORY + frame_length],
                plc_scratch,
            )?;
        }

        if decode_this_frame {
            let channel = &mut self.channels[index];
            channel.loss_count = 0;
            channel.prev_signal_type = signal_type;
            // "A frame has been decoded without errors" (`decode_frame.c:130`).
            channel.first_frame_after_reset = false;
        } else {
            // The concealed frame goes into the output history too, so the next good frame's
            // long-term predictor has something continuous to reach back into.
            let Self {
                channels,
                channel_pcm,
                ..
            } = self;
            update_output_history(
                &mut channels[index],
                &channel_pcm[index][STEREO_HISTORY..STEREO_HISTORY + frame_length],
            )?;
        }

        // Comfort noise: estimate on a good inactive frame, add on a concealed one.
        {
            let Self {
                channels,
                channel_pcm,
                cng_scratch,
                ..
            } = self;
            cng::run(
                &mut channels[index],
                &control,
                &mut channel_pcm[index][STEREO_HISTORY..STEREO_HISTORY + frame_length],
                cng_scratch,
            )?;
        }

        // Smooth the seam between a concealed frame and the good frame that follows it.
        {
            let Self {
                channels,
                channel_pcm,
                ..
            } = self;
            plc::glue_frames(
                &mut channels[index],
                &mut channel_pcm[index][STEREO_HISTORY..STEREO_HISTORY + frame_length],
            );
        }

        self.channels[index].lag_prev = control.pitch_lags[layout.subframe_count - 1];
        Ok(())
    }
}
