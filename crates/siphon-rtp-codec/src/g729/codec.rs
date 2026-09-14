//! The [`Decoder`] and [`Encoder`] adapters that put G.729 on the engine's media path.
//!
//! The codec's own frame is 10 ms — 80 samples in ten octets — while a leg negotiates a packet time
//! that is usually 20 ms and may be anything a multiple of 10. An RTP payload is therefore a whole
//! number of codec frames concatenated, with no header of any kind (RFC 3551 §4.5.6 assigns static
//! payload type 18 and defines the payload as exactly that).

use super::{G729Decoder, G729Encoder, FRAME_BYTES, FRAME_SAMPLES};
use crate::{CodecError, CodecParams, Decoder, Encoder};

/// A G.729 codec instance, usable as either a [`Decoder`] or an [`Encoder`].
///
/// Both directions are bit-exact against the ITU-T reference vectors: encoding each `*.in` produces
/// its `*.bit` and decoding each `*.bit` produces its `*.pst`, byte for byte.
#[derive(Debug, Clone)]
pub struct G729 {
    params: CodecParams,
    decoder: G729Decoder,
    encoder: G729Encoder,
}

impl G729 {
    /// A codec for a leg with the given packet time, which must be a multiple of the codec's 10 ms
    /// frame; anything else is rounded down to one, and zero to a single frame.
    #[must_use]
    pub fn new(ptime_ms: u8) -> Self {
        let frames = (ptime_ms / 10).max(1);
        Self {
            params: CodecParams {
                sample_rate_hz: 8_000,
                channels: 1,
                ptime_ms: frames * 10,
            },
            decoder: G729Decoder::new(),
            encoder: G729Encoder::new(),
        }
    }

    /// The codec's parameters (8 kHz, mono).
    #[must_use]
    pub fn params(&self) -> CodecParams {
        self.params
    }

    /// Samples one packet carries: one per frame of the negotiated packet time.
    fn nominal_samples(&self) -> usize {
        self.params.ptime_ms as usize / 10 * FRAME_SAMPLES
    }
}

impl Decoder for G729 {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        self.nominal_samples()
    }

    fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
        // A two-octet payload is an Annex B silence-insertion descriptor. Annex B is not implemented,
        // and decoding it as a truncated speech frame would emit noise at full level, so it is
        // refused rather than guessed at.
        if !payload.len().is_multiple_of(FRAME_BYTES) {
            return Err(CodecError::Malformed(
                "G.729 payload is not a whole number of 10-octet frames",
            ));
        }
        let frames = payload.len() / FRAME_BYTES;
        let samples = frames * FRAME_SAMPLES;
        if out.len() < samples {
            return Err(CodecError::OutputTooSmall {
                needed: samples,
                have: out.len(),
            });
        }
        for (index, frame) in payload.as_chunks::<FRAME_BYTES>().0.iter().enumerate() {
            let decoded = self.decoder.decode(frame)?;
            out[index * FRAME_SAMPLES..(index + 1) * FRAME_SAMPLES].copy_from_slice(&decoded);
        }
        Ok(samples)
    }

    fn conceal(&mut self, out: &mut [i16]) -> Result<usize, CodecError> {
        // G.729 conceals from its own decoder state — §4.4 repeats the line spectral pairs, walks
        // the pitch lag forward and fades the gains — so a lost packet is filled by the codec rather
        // than by silence, and the state it leaves behind is the one the next good frame needs.
        let frames = (out.len() / FRAME_SAMPLES).min(self.params.ptime_ms as usize / 10);
        for index in 0..frames {
            let concealed = self.decoder.conceal();
            out[index * FRAME_SAMPLES..(index + 1) * FRAME_SAMPLES].copy_from_slice(&concealed);
        }
        Ok(frames * FRAME_SAMPLES)
    }
}

impl Encoder for G729 {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        self.nominal_samples()
    }

    fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, CodecError> {
        if !pcm.len().is_multiple_of(FRAME_SAMPLES) {
            return Err(CodecError::Malformed(
                "G.729 input is not a whole number of 80-sample frames",
            ));
        }
        let frames = pcm.len() / FRAME_SAMPLES;
        let bytes = frames * FRAME_BYTES;
        if out.len() < bytes {
            return Err(CodecError::OutputTooSmall {
                needed: bytes,
                have: out.len(),
            });
        }
        for (index, frame) in pcm.as_chunks::<FRAME_SAMPLES>().0.iter().enumerate() {
            let encoded = self.encoder.encode(frame);
            out[index * FRAME_BYTES..(index + 1) * FRAME_BYTES].copy_from_slice(&encoded);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_packet_time_decides_how_many_frames_a_packet_carries() {
        assert_eq!(Decoder::frame_samples(&G729::new(10)), 80);
        assert_eq!(Decoder::frame_samples(&G729::new(20)), 160);
        assert_eq!(Decoder::frame_samples(&G729::new(60)), 480);
        // A packet time the codec's frame does not divide is rounded down to one that it does, and
        // zero still yields one frame rather than a codec that carries nothing.
        assert_eq!(Decoder::frame_samples(&G729::new(25)), 160);
        assert_eq!(Decoder::frame_samples(&G729::new(0)), 80);
    }

    #[test]
    fn a_payload_that_is_not_whole_frames_is_refused() {
        let mut codec = G729::new(20);
        let mut out = [0_i16; 160];
        // Two octets is an Annex B silence descriptor, which this build does not implement. Reading
        // it as a truncated speech frame would put full-level noise on the call.
        assert!(Decoder::decode(&mut codec, &[0; 2], &mut out).is_err());
        assert!(Decoder::decode(&mut codec, &[0; 15], &mut out).is_err());
        assert!(Decoder::decode(&mut codec, &[0; 10], &mut out).is_ok());
        assert!(Decoder::decode(&mut codec, &[0; 20], &mut out).is_ok());
    }

    #[test]
    fn a_short_output_buffer_errors_rather_than_truncating() {
        let mut codec = G729::new(20);
        let mut out = [0_i16; 79];
        assert!(Decoder::decode(&mut codec, &[0; 10], &mut out).is_err());
        let mut bytes = [0_u8; 9];
        assert!(Encoder::encode(&mut codec, &[0; 80], &mut bytes).is_err());
    }

    #[test]
    fn a_packets_worth_of_speech_encodes_to_a_packets_worth_of_octets() {
        let mut codec = G729::new(20);
        let pcm: Vec<i16> = (0..160)
            .map(|i| ((i as f32 * 0.21).sin() * 6000.0) as i16)
            .collect();
        let mut out = [0_u8; 20];
        assert_eq!(
            Encoder::encode(&mut codec, &pcm, &mut out).expect("encode"),
            20
        );
    }

    #[test]
    fn concealment_fills_the_packet_from_the_codecs_own_state() {
        // Not silence: §4.4 repeats the spectrum, walks the lag forward and fades the gains, and the
        // state it leaves is what the next good frame decodes against.
        let mut codec = G729::new(20);
        let mut decoded = [0_i16; 160];
        let pcm: Vec<i16> = (0..160)
            .map(|i| ((i as f32 * 0.21).sin() * 8000.0) as i16)
            .collect();
        let mut payload = [0_u8; 20];
        Encoder::encode(&mut codec, &pcm, &mut payload).expect("encode");

        let mut decoder = G729::new(20);
        Decoder::decode(&mut decoder, &payload, &mut decoded).expect("decode");

        let mut concealed = [0_i16; 160];
        assert_eq!(
            Decoder::conceal(&mut decoder, &mut concealed).expect("conceal"),
            160
        );
        assert!(
            concealed.iter().any(|&sample| sample != 0),
            "concealment after voiced audio must not be silence"
        );
    }

    #[test]
    fn the_rtp_clock_is_the_sample_rate() {
        // RFC 3551 §4.5.6: G.729 samples and clocks at 8 kHz, unlike G.722.
        let codec = G729::new(20);
        assert_eq!(Decoder::rtp_clock_rate_hz(&codec), 8_000);
        assert_eq!(Encoder::rtp_clock_rate_hz(&codec), 8_000);
    }

    #[test]
    fn the_encoder_is_not_stateless() {
        // Every stage carries state across frames — the LSP predictor, the excitation history, the
        // gain predictor — so the conference mixer must never share one leg's payload with another.
        assert!(!Encoder::is_stateless(&G729::new(20)));
    }
}
