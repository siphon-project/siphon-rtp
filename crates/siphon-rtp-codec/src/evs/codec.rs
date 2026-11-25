//! One negotiated EVS stream as the engine's [`Decoder`]: an RTP payload in, PCM out.
//!
//! **Decode only.** There is no EVS encoder, so [`crate::factory::encoder_for`] refuses EVS and the
//! engine never offers it as a transcode target. A leg that carries EVS can still be relayed
//! (nothing here runs), recorded, streamed to a WebSocket, forked and intercepted, all of which
//! need the audio and no encoder.
//!
//! # What a received frame becomes
//!
//! Every frame of a payload yields 20 ms of PCM, and the decoder is told what the sender said:
//!
//! - A speech frame is decoded, whatever its bit rate or mode, and a switch between the EVS primary
//!   and the AMR-WB interoperable modes needs nothing from the caller.
//! - An AMR-WB IO frame with its `Q` bit clear is damaged in transit, and concealed.
//! - SPEECH_LOST and NO_DATA are concealed, or, inside a silence period, comfort noise goes on
//!   (TS 26.445 A.2.2, TS 26.442 `read_indices_mime`).
//! - A SID frame starts or updates comfort noise.
//!
//! A payload that is not EVS (see [`super::rtp::PayloadError`]) is an error and no audio, and does not disturb
//! the decoder.

use super::com::bitstream_rtp::ReceivedFrame;
use super::decoder::EvsDecoder;
use super::error::EvsError;
use super::rtp::{Cmr, FrameType, Packet};
use crate::evs_fmtp::EvsParams;
use crate::{CodecError, CodecParams, Decoder};

/// Samples of one 20 ms EVS frame at 8, 16, 32 and 48 kHz are 160, 320, 640 and 960.
const FRAME_MS: u8 = 20;

/// The most speech bits one frame has, 128 kbit/s for 20 ms.
const MAX_FRAME_BITS: usize = 2560;

/// An EVS decoder for one negotiated stream.
pub struct EvsRtpDecoder {
    decoder: EvsDecoder,
    params: CodecParams,
    header_full_only: bool,
    last_cmr: Option<Cmr>,
}

impl EvsRtpDecoder {
    /// A decoder for a stream negotiated with `params` (the peer's `a=fmtp`) and `ptime_ms`.
    ///
    /// The output rate is the one that carries the widest bandwidth the peer may send
    /// ([`EvsParams::send_bandwidth_ceiling`]): 48 kHz with no `bw` at all, because the
    /// registration's default is every bandwidth. A narrower stream is decoded at a lower rate,
    /// which is cheaper downstream and loses nothing.
    ///
    /// # Errors
    /// [`CodecError::Unsupported`] for a configuration the engine does not carry
    /// ([`EvsParams::unsupported`]).
    pub fn negotiated(params: &EvsParams, ptime_ms: u8) -> Result<Self, CodecError> {
        if let Some(reason) = params.unsupported() {
            return Err(CodecError::Unsupported(reason));
        }
        let rate = params.send_bandwidth_ceiling().sample_rate_hz();
        let decoder = EvsDecoder::new_streaming(rate).map_err(codec_error)?;
        // frames are 20 ms: a ptime that is not a multiple of that is the nearest below, at least one
        let frames = (ptime_ms / FRAME_MS).max(1);
        Ok(Self {
            decoder,
            params: CodecParams {
                sample_rate_hz: rate,
                channels: 1,
                ptime_ms: frames * FRAME_MS,
            },
            header_full_only: params.header_full_only(),
            last_cmr: None,
        })
    }

    /// The codec mode request in the last payload decoded, `None` if it had none. Nothing acts on
    /// it yet: it is addressed to an encoder, and EVS has none.
    #[must_use]
    pub fn last_cmr(&self) -> Option<Cmr> {
        self.last_cmr
    }

    /// Samples of one 20 ms frame at the stream's output rate.
    fn frame_len(&self) -> usize {
        self.decoder.frame_samples()
    }

    /// Replace a decoder that failed: after an error the reference decoder must be discarded, and
    /// the next packet then starts a fresh stream rather than running on corrupt state.
    fn reset(&mut self) {
        if let Ok(decoder) = EvsDecoder::new_streaming(self.params.sample_rate_hz) {
            self.decoder = decoder;
        }
    }
}

fn codec_error(error: EvsError) -> CodecError {
    match error {
        EvsError::Malformed(reason) => CodecError::Malformed(reason),
        EvsError::OutputTooSmall { needed, have } => CodecError::OutputTooSmall { needed, have },
    }
}

impl Decoder for EvsRtpDecoder {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }

    /// 16000 Hz whatever the output rate: the RTP clock of `EVS/16000` (TS 26.445 A.3) does not
    /// follow the bandwidth the decoder is run at.
    fn rtp_clock_rate_hz(&self) -> u32 {
        crate::factory::EVS_CLOCK_RATE_HZ
    }

    /// Decode one EVS RTP payload in either format, every frame it carries.
    fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
        let packet = Packet::parse(payload, self.header_full_only).map_err(CodecError::from)?;
        let frame_len = self.frame_len();
        let needed = packet.frame_count() * frame_len;
        let have = out.len();
        let out = out
            .get_mut(..needed)
            .ok_or(CodecError::OutputTooSmall { needed, have })?;
        self.last_cmr = packet.cmr();
        let mut bits = [0u8; MAX_FRAME_BITS];
        for (frame, pcm) in packet.frames().zip(out.chunks_mut(frame_len)) {
            let count = frame.decoder_bits(&mut bits);
            let received = ReceivedFrame {
                amr_wb_io: frame.frame_type.is_amr_wb_io(),
                frame_type_index: frame.frame_type.frame_type_index(),
                quality_ok: frame.quality_ok,
                speech_lost: matches!(frame.frame_type, FrameType::SpeechLost { .. }),
                no_data: matches!(frame.frame_type, FrameType::NoData { .. }),
                sid_update: frame.sid_update(),
                bits: &bits[..count],
            };
            if let Err(error) = self.decoder.decode_received(&received, pcm) {
                self.reset();
                return Err(codec_error(error));
            }
        }
        Ok(needed)
    }

    /// Conceal one lost packet: one SPEECH_LOST frame per 20 ms of the packetization interval.
    /// In a silence period the decoder keeps producing comfort noise instead.
    fn conceal(&mut self, out: &mut [i16]) -> Result<usize, CodecError> {
        let frame_len = self.frame_len();
        let needed = self.params.frame_samples();
        let have = out.len();
        let out = out
            .get_mut(..needed)
            .ok_or(CodecError::OutputTooSmall { needed, have })?;
        for pcm in out.chunks_mut(frame_len) {
            let lost = ReceivedFrame {
                amr_wb_io: self.decoder.is_amr_wb_io(),
                frame_type_index: 14,
                quality_ok: true,
                speech_lost: true,
                no_data: false,
                sid_update: None,
                bits: &[],
            };
            if let Err(error) = self.decoder.decode_received(&lost, pcm) {
                self.reset();
                return Err(codec_error(error));
            }
        }
        Ok(needed)
    }
}

#[cfg(test)]
mod tests;
