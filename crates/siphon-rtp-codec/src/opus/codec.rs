//! [`Decoder`] for Opus — the bridge between [`OpusDecoder`] and the engine's codec trait.
//!
//! [`OpusDecoder`] is the RFC 6716 decoder proper: it takes a whole packet, decides how many samples
//! that packet carries, and hands them back. The [`Decoder`] trait is the *media path's* view of a
//! codec: a fixed nominal frame, a caller-owned output buffer, an RTP clock, and concealment as a
//! first-class operation. This type is what makes the first answer the second.
//!
//! Three things it is responsible for, none of which the decoder underneath can know:
//!
//! * **The nominal frame.** A leg negotiates one `a=ptime` (RFC 7587 §6.1), and the media path sizes
//!   buffers and steps RTP timestamps from it. Opus, though, may legally send *any* frame duration
//!   from 2.5 ms to a 120 ms multi-frame packet whatever the negotiated ptime (RFC 6716 §3.1/§3.2),
//!   so [`Decoder::frame_samples`] is the *nominal* frame while [`OpusCodec::decode`] offers the
//!   whole output buffer as capacity. A 60 ms packet on a 20 ms leg therefore decodes in full
//!   instead of being rejected — the media path's decode scratch is sized for the 120 ms ceiling
//!   precisely so this works.
//! * **The RTP clock.** RFC 7587 §4.1: "the RTP timestamp is incremented with a 48000 Hz clock rate
//!   for all modes of Opus and all sampling rates". It is therefore fixed at 48 kHz and is *not*
//!   derived from the decoder's output rate — the one thing the trait's default implementation would
//!   get wrong for an Opus leg decoding at anything other than 48 kHz.
//! * **The interleaved value count.** The crate channel contract (see the crate docs) makes
//!   [`Decoder::frame_samples`] and the [`Decoder::decode`] return value **interleaved `i16`
//!   counts**, while [`OpusDecoder::decode`] returns samples *per channel*. The conversion happens
//!   here, once, so nothing downstream has to know Opus can be stereo.
//!
//! There is deliberately no `Encoder` impl here yet: the Opus encoder is still being built, and
//! [`crate::factory::encoder_for`] says so rather than pretending.

use crate::factory::OPUS_CLOCK_RATE_HZ;
use crate::opus::decoder::{OpusDecoder, MAX_PACKET_SAMPLES};
use crate::{CodecError, CodecParams, Decoder};

/// Divisor of the sample rate that yields the 2.5 ms quantum — the shortest frame RFC 6716 §3.1
/// defines, and the granularity `OpusDecoder`'s concealment path accepts (libopus
/// `opus_decoder.c:684`, `frame_size` must be a multiple of `Fs/400`).
const QUANTUM_DIVISOR: usize = 400;

/// An Opus leg's decode side, as the media path sees it (RFC 6716 / RFC 7587).
///
/// Built by [`crate::factory::decoder_for`] from the negotiated [`crate::factory::CodecSpec`]: the
/// output sample rate from the (RFC 7587 §4.1-pinned) clock rate, the channel count from the peer's
/// `sprop-stereo`, and the nominal frame from the negotiated `ptime`.
pub struct OpusCodec {
    decoder: OpusDecoder,
    params: CodecParams,
    /// `sample_rate / 400` — 2.5 ms, cached because [`OpusCodec::conceal`] needs it per frame.
    quantum: usize,
}

impl OpusCodec {
    /// Build an Opus decode side for `sample_rate_hz` (8/12/16/24/48 kHz — RFC 6716 §2 output
    /// rates), `channels` (1 or 2; RFC 7587 defines Opus over RTP as mono or stereo), and the
    /// negotiated `ptime_ms`.
    ///
    /// `ptime_ms` sets only the *nominal* frame: a packet carrying more is still decoded in full
    /// when the caller's buffer allows it (see the module docs). Errors — never panics — on a rate
    /// or channel count Opus does not define.
    pub fn new(sample_rate_hz: u32, channels: u8, ptime_ms: u8) -> Result<Self, CodecError> {
        let channels = channels.max(1);
        let decoder = OpusDecoder::new(sample_rate_hz, usize::from(channels))?;
        Ok(Self {
            decoder,
            params: CodecParams {
                sample_rate_hz,
                channels,
                ptime_ms: ptime_ms.max(1),
            },
            quantum: sample_rate_hz as usize / QUANTUM_DIVISOR,
        })
    }

    /// Channels the decoder interleaves into the output buffer, as a `usize` (always ≥ 1).
    fn channels(&self) -> usize {
        usize::from(self.params.channels.max(1))
    }

    /// Per-channel capacity `out` offers, capped at the longest packet RFC 6716 §3.2 allows (120 ms
    /// at 48 kHz). Offering the whole buffer rather than the nominal frame is what lets a packet
    /// longer than the negotiated `ptime` decode in full.
    fn capacity(&self, out: &[i16]) -> usize {
        (out.len() / self.channels()).min(MAX_PACKET_SAMPLES)
    }

    /// Conceal `out.len()`-bounded audio through the Opus PLC (RFC 6716 §4.4), rounded **down** to
    /// the 2.5 ms quantum the decoder's concealment path requires. Returns interleaved values.
    fn conceal_into(&mut self, out: &mut [i16]) -> Result<usize, CodecError> {
        let channels = self.channels();
        // One nominal frame, or as much of it as the caller's buffer holds.
        let requested = self.capacity(out).min(self.params.frame_samples());
        // libopus only conceals in whole 2.5 ms units; a ptime that is not a multiple of one (an
        // out-of-spec `a=ptime:3`, say) conceals the largest whole number of them that fits.
        let quantised = (requested / self.quantum) * self.quantum;
        if quantised == 0 {
            return Err(CodecError::OutputTooSmall {
                needed: self.quantum * channels,
                have: out.len(),
            });
        }
        let samples = self.decoder.decode(None, out, quantised, false)?;
        Ok(samples * channels)
    }
}

impl Decoder for OpusCodec {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        // The crate channel contract: this is the **interleaved** value count, i.e. a buffer size.
        self.params.frame_values()
    }

    fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
        let channels = self.channels();
        let needed = self.params.frame_values();
        if out.len() < needed {
            return Err(CodecError::OutputTooSmall {
                needed,
                have: out.len(),
            });
        }
        // A zero-length payload is Opus DTX / "no data" on the wire, not a malformed packet: there
        // is no TOC to parse, so the only correct output is concealment (libopus `opus_decode`
        // treats `len <= 0` as the PLC entry, `opus_decoder.c:715`).
        if payload.is_empty() {
            return self.conceal_into(out);
        }
        let capacity = self.capacity(out);
        let samples = self.decoder.decode(Some(payload), out, capacity, false)?;
        Ok(samples * channels)
    }

    fn conceal(&mut self, out: &mut [i16]) -> Result<usize, CodecError> {
        self.conceal_into(out)
    }

    fn rtp_clock_rate_hz(&self) -> u32 {
        // RFC 7587 §4.1: "the RTP timestamp is incremented with a 48000 Hz clock rate for all modes
        // of Opus and all sampling rates" — so it is *not* the decoder's output rate, which is why
        // the trait default (`params().sample_rate_hz`) would be wrong for a non-48 kHz Opus leg.
        OPUS_CLOCK_RATE_HZ
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::celt::encoder::{CeltEncoder, RateControl};

    /// TOC byte for config 31 (CELT-only, fullband, 20 ms), mono (`s` = 0), framing code 0 — RFC
    /// 6716 §3.1 Table 2 and §3.2.2. One CELT payload behind it is a complete, legal Opus packet.
    const TOC_CELT_FB_20MS_MONO: u8 = 31 << 3;
    /// Same, config 30 (CELT-only, fullband, 10 ms) — configs 28..=31 are fullband CELT at
    /// 2.5 / 5 / 10 / 20 ms respectively.
    const TOC_CELT_FB_10MS_MONO: u8 = 30 << 3;

    /// A deterministic 48 kHz signal in `[-1, 1)`: two harmonics plus a little noise, so the CELT
    /// analysis takes realistic branches instead of the degenerate ones silence would.
    fn signal(samples: usize) -> Vec<f32> {
        let mut state = 0x5EED_u32;
        (0..samples)
            .map(|index| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let noise = ((state >> 16) as f32 / 32768.0 - 1.0) * 0.02;
                let time = index as f32;
                0.35 * (time * 0.031).sin() + 0.18 * (time * 0.097).sin() + noise
            })
            .collect()
    }

    /// Encode `frames` consecutive 20 ms (or 10 ms) CELT frames of [`signal`] and wrap each in an
    /// RFC 6716 §3 code-0 packet behind `toc`.
    ///
    /// Real audio without needing the (gitignored) official vectors or an Opus *encoder*: the CELT
    /// encoder in this crate is complete and vector-gated, and a CELT-only Opus packet is exactly a
    /// TOC byte followed by one CELT frame.
    fn celt_packets(toc: u8, frame: usize, frames: usize) -> Vec<Vec<u8>> {
        let mut encoder = CeltEncoder::new().expect("build CELT encoder");
        encoder.set_bitrate(64_000);
        encoder.set_rate_control(RateControl::ConstrainedVbr);
        let pcm = signal(frame * frames);
        let mut payload = vec![0u8; 1275];
        (0..frames)
            .map(|index| {
                let written = encoder
                    .encode(
                        &pcm[index * frame..(index + 1) * frame],
                        frame,
                        &mut payload,
                    )
                    .expect("encode a CELT frame");
                let mut packet = Vec::with_capacity(1 + written);
                packet.push(toc);
                packet.extend_from_slice(&payload[..written]);
                packet
            })
            .collect()
    }

    /// Sum of squares — "is this actually audio, or is it zeros?".
    fn energy(pcm: &[i16]) -> i64 {
        pcm.iter().map(|&s| i64::from(s) * i64::from(s)).sum()
    }

    #[test]
    fn params_follow_the_constructor_and_the_channel_contract() {
        let mono = OpusCodec::new(48_000, 1, 20).expect("mono codec");
        assert_eq!(mono.params().sample_rate_hz, 48_000);
        assert_eq!(mono.params().channels, 1);
        assert_eq!(mono.params().ptime_ms, 20);
        // Mono: per-channel and interleaved counts coincide.
        assert_eq!(mono.params().frame_samples(), 960);
        assert_eq!(mono.frame_samples(), 960);

        // Stereo: `frame_samples` on the *trait* is the interleaved buffer size, twice the
        // per-channel count (the crate channel contract).
        let stereo = OpusCodec::new(48_000, 2, 20).expect("stereo codec");
        assert_eq!(stereo.params().frame_samples(), 960);
        assert_eq!(stereo.frame_samples(), 1920);

        // A non-48 kHz output rate is legal (RFC 6716 §2) and must not move the RTP clock.
        let narrow = OpusCodec::new(8_000, 1, 20).expect("8 kHz codec");
        assert_eq!(narrow.params().sample_rate_hz, 8_000);
        assert_eq!(narrow.frame_samples(), 160);
        assert_eq!(
            narrow.rtp_clock_rate_hz(),
            48_000,
            "RFC 7587 §4.1 pins the RTP clock at 48 kHz whatever the output rate"
        );
    }

    #[test]
    fn rejects_rates_and_channel_counts_opus_does_not_define() {
        // RFC 6716 §2 output rates are 8/12/16/24/48 kHz; RFC 7587 makes RTP Opus mono or stereo.
        assert!(matches!(
            OpusCodec::new(44_100, 1, 20),
            Err(CodecError::Unsupported(_))
        ));
        assert!(matches!(
            OpusCodec::new(48_000, 3, 20),
            Err(CodecError::Unsupported(_))
        ));
        // A degenerate ptime is clamped, not rejected (mirrors `CodecSpec::new`).
        assert_eq!(
            OpusCodec::new(48_000, 1, 0)
                .expect("clamped")
                .params()
                .ptime_ms,
            1
        );
    }

    #[test]
    fn decodes_a_celt_packet_to_real_audio() {
        let packets = celt_packets(TOC_CELT_FB_20MS_MONO, 960, 4);
        let mut codec = OpusCodec::new(48_000, 1, 20).expect("codec");
        let mut pcm = vec![0i16; codec.frame_samples()];
        // The first frame starts from a cold MDCT overlap, so score the later ones.
        let mut last = 0usize;
        for packet in &packets {
            last = codec.decode(packet, &mut pcm).expect("decode");
            assert_eq!(last, 960, "one 20 ms frame at 48 kHz");
        }
        assert!(
            energy(&pcm[..last]) > 1_000_000,
            "decoded Opus must be audio, not silence (energy {})",
            energy(&pcm[..last])
        );
    }

    #[test]
    fn decodes_a_frame_shorter_than_the_negotiated_ptime() {
        // RFC 6716 §3.1: the frame duration is the packet's business, not the negotiated ptime. A
        // 10 ms packet on a 20 ms leg yields 10 ms of PCM and says so in the return value.
        let packets = celt_packets(TOC_CELT_FB_10MS_MONO, 480, 2);
        let mut codec = OpusCodec::new(48_000, 1, 20).expect("codec");
        let mut pcm = vec![0i16; codec.frame_samples()];
        for packet in &packets {
            assert_eq!(codec.decode(packet, &mut pcm).expect("decode"), 480);
        }
    }

    #[test]
    fn decodes_a_multi_frame_packet_longer_than_the_negotiated_ptime() {
        // RFC 6716 §3.2.4: a code-2 packet carries two frames. On a 20 ms leg that is 40 ms of
        // audio — more than `frame_samples()` — and it must decode in full when the caller's buffer
        // holds it, rather than being dropped (a 60/120 ms Opus sender is entirely legal).
        let frames = celt_packets(TOC_CELT_FB_20MS_MONO, 960, 2);
        let first = &frames[0][1..];
        let second = &frames[1][1..];
        let mut packet = Vec::new();
        // Code 2 = two frames, first length coded in 1–2 bytes (§3.2.4). Keep it under 252 bytes so
        // the length is a single byte.
        assert!(first.len() < 252, "single-byte length prefix");
        packet.push(TOC_CELT_FB_20MS_MONO | 0b010);
        packet.push(first.len() as u8);
        packet.extend_from_slice(first);
        packet.extend_from_slice(second);

        let mut codec = OpusCodec::new(48_000, 1, 20).expect("codec");
        // The media path's decode scratch is sized for the 120 ms ceiling, not for `ptime`.
        let mut pcm = vec![0i16; MAX_PACKET_SAMPLES];
        assert_eq!(
            codec.decode(&packet, &mut pcm).expect("decode"),
            1920,
            "two 20 ms frames = 40 ms at 48 kHz"
        );
        assert!(energy(&pcm[..1920]) > 1_000_000, "both frames carry audio");
    }

    #[test]
    fn conceal_after_audio_is_real_opus_plc_not_silence() {
        // The jitter buffer calls `conceal` on a lost packet. It must synthesize from the decoder's
        // own state (RFC 6716 §4.4 packet-loss concealment), not hand back zeros — a zero frame is
        // an audible dropout and would make the PLC decorative.
        let packets = celt_packets(TOC_CELT_FB_20MS_MONO, 960, 3);
        let mut codec = OpusCodec::new(48_000, 1, 20).expect("codec");
        let mut pcm = vec![0i16; codec.frame_samples()];
        for packet in &packets {
            codec.decode(packet, &mut pcm).expect("decode");
        }
        let mut concealed = vec![0i16; codec.frame_samples()];
        let written = codec.conceal(&mut concealed).expect("conceal");
        assert_eq!(written, 960);
        assert!(
            energy(&concealed) > 1_000_000,
            "concealment must carry the signal forward, not fall silent (energy {})",
            energy(&concealed)
        );

        // And it is exactly the underlying decoder's PLC: drive a second, independent `OpusDecoder`
        // over the same packets and the same loss, and the two frames must be identical sample for
        // sample. That is what proves `conceal` is wired to Opus PLC rather than to anything of its
        // own invention.
        let mut reference = OpusDecoder::new(48_000, 1).expect("reference decoder");
        let mut scratch = vec![0i16; MAX_PACKET_SAMPLES];
        for packet in &packets {
            reference
                .decode(Some(packet), &mut scratch, MAX_PACKET_SAMPLES, false)
                .expect("reference decode");
        }
        let reference_written = reference
            .decode(None, &mut scratch, 960, false)
            .expect("reference conceal");
        assert_eq!(reference_written, 960);
        assert_eq!(
            concealed,
            scratch[..960],
            "conceal() must be the Opus PLC, sample for sample"
        );
    }

    #[test]
    fn conceal_before_any_packet_is_silence_and_not_an_error() {
        // Nothing has been decoded, so there is no signal to extrapolate (libopus
        // `opus_decoder.c:302` returns zeros). It must still succeed — a jitter buffer that starts
        // on a gap must not see a decode error.
        let mut codec = OpusCodec::new(48_000, 1, 20).expect("codec");
        let mut pcm = vec![0i16; codec.frame_samples()];
        assert_eq!(codec.conceal(&mut pcm).expect("conceal"), 960);
        assert_eq!(energy(&pcm), 0);
    }

    #[test]
    fn an_empty_payload_conceals_rather_than_erroring() {
        // A zero-length Opus payload is DTX / "no data" on the wire (RFC 6716 §3 has no TOC to
        // parse), so the right answer is concealment, not a decode error that drops the frame.
        let packets = celt_packets(TOC_CELT_FB_20MS_MONO, 960, 2);
        let mut codec = OpusCodec::new(48_000, 1, 20).expect("codec");
        let mut pcm = vec![0i16; codec.frame_samples()];
        for packet in &packets {
            codec.decode(packet, &mut pcm).expect("decode");
        }
        let mut empty_out = vec![0i16; codec.frame_samples()];
        assert_eq!(codec.decode(&[], &mut empty_out).expect("dtx"), 960);
        assert!(energy(&empty_out) > 0, "DTX runs the PLC, not a mute");
    }

    #[test]
    fn a_too_small_output_buffer_errors_instead_of_panicking() {
        let mut codec = OpusCodec::new(48_000, 1, 20).expect("codec");
        let packet = celt_packets(TOC_CELT_FB_20MS_MONO, 960, 1).remove(0);
        let mut pcm = vec![0i16; 959];
        assert!(matches!(
            codec.decode(&packet, &mut pcm),
            Err(CodecError::OutputTooSmall { .. })
        ));
        // Concealment below the 2.5 ms quantum has nothing legal to produce, and says so.
        let mut tiny = [0i16; 8];
        assert!(matches!(
            codec.conceal(&mut tiny),
            Err(CodecError::OutputTooSmall { .. })
        ));
    }

    #[test]
    fn a_malformed_payload_errors_instead_of_panicking() {
        let mut codec = OpusCodec::new(48_000, 1, 20).expect("codec");
        let mut pcm = vec![0i16; codec.frame_samples()];
        // Code 1 (two equal-length frames) with an odd byte count is illegal — RFC 6716 §3.2.3.
        assert!(codec.decode(&[0xF9, 0x00, 0x00], &mut pcm).is_err());
        // A lone TOC byte with framing code 3 and no frame-count byte is truncated (§3.2.5).
        assert!(codec.decode(&[0xFB], &mut pcm).is_err());
    }

    #[test]
    fn a_stereo_stream_decodes_interleaved_to_the_channel_count() {
        // RFC 7587 §6.1 `sprop-stereo=1`: the peer sends stereo, so the decoder is built for two
        // channels and the return value is the **interleaved** count (crate channel contract).
        let packets = celt_packets(TOC_CELT_FB_20MS_MONO, 960, 2);
        let mut codec = OpusCodec::new(48_000, 2, 20).expect("stereo codec");
        let mut pcm = vec![0i16; codec.frame_samples()];
        let mut written = 0;
        for packet in &packets {
            written = codec.decode(packet, &mut pcm).expect("decode");
        }
        assert_eq!(written, 1920, "960 samples × 2 channels, interleaved");
        // A mono bitstream decoded to a stereo API duplicates the channel (libopus upmix), so the
        // pairs are equal — which is exactly what proves the layout is interleaved, not planar.
        assert!(
            pcm.chunks_exact(2).all(|pair| pair[0] == pair[1]),
            "a mono stream upmixed to stereo must be equal L/R at each instant"
        );
        assert!(energy(&pcm) > 1_000_000);
    }
}
