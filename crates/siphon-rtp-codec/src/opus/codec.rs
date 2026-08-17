//! [`Decoder`] and [`Encoder`] for Opus — the bridge between [`OpusDecoder`] / [`OpusEncoder`] and
//! the engine's codec traits.
//!
//! [`OpusDecoder`] and [`OpusEncoder`] are the RFC 6716 codec proper: hand one a whole packet and it
//! decides how many samples it carries, hand the other a frame and it decides mode, bandwidth and
//! rate for itself. The [`Decoder`] / [`Encoder`] traits are the *media path's* view of a codec: a
//! fixed nominal frame, a caller-owned buffer, an RTP clock, and concealment as a first-class
//! operation. This type is what makes the first answer the second.
//!
//! Four things it is responsible for, none of which the codec underneath can know:
//!
//! * **The nominal frame.** A leg negotiates one `a=ptime` (RFC 7587 §6.1), and the media path sizes
//!   buffers and steps RTP timestamps from it. Opus, though, may legally send *any* frame duration
//!   from 2.5 ms to a 120 ms multi-frame packet whatever the negotiated ptime (RFC 6716 §3.1/§3.2),
//!   so on the decode side [`Decoder::frame_samples`] is the *nominal* frame while
//!   [`OpusCodec::decode`] offers the whole output buffer as capacity. A 60 ms packet on a 20 ms leg
//!   therefore decodes in full instead of being rejected — the media path's decode scratch is sized
//!   for the 120 ms ceiling precisely so this works. The encode side has no such freedom: it emits
//!   exactly the frame it was built for, so the negotiated ptime is **snapped** to a duration Opus
//!   can actually produce ([`snap_ptime_ms`]).
//! * **The RTP clock.** RFC 7587 §4.1: "the RTP timestamp is incremented with a 48000 Hz clock rate
//!   for all modes of Opus and all sampling rates". It is therefore fixed at 48 kHz in **both**
//!   directions and is *not* derived from the codec's PCM rate — the one thing the traits' default
//!   implementations would get wrong for an Opus leg running at anything other than 48 kHz.
//! * **The interleaved value count.** The crate channel contract (see the crate docs) makes
//!   [`Decoder::frame_samples`] / [`Encoder::frame_samples`] and the [`Decoder::decode`] return
//!   value **interleaved `i16` counts**, while [`OpusDecoder::decode`] and [`OpusEncoder::encode`]
//!   count samples *per channel*. The conversion happens here, once, so nothing downstream has to
//!   know Opus can be stereo.
//! * **The peer's `a=fmtp`.** [`OpusParams`] carries what the peer declared (RFC 7587 §6.1) and
//!   [`OpusCodec::new_encoder`] turns it into real encoder settings — target bitrate, maximum
//!   bandwidth, rate-control mode, in-band FEC and DTX. Every one of them changes the bitstream on
//!   the wire; see [`OpusCodec::new_encoder`] for the per-parameter mapping.
//!
//! # One half per object
//!
//! An [`OpusCodec`] is *either* the decode side or the encode side, never both — the two halves are
//! 46 KB and 86 KB of codec state respectively, and a transcoding call already builds one object per
//! direction, so carrying the unused half would double the per-leg footprint of every Opus call for
//! nothing. [`crate::factory::decoder_for`] builds the decode side, [`crate::factory::encoder_for`]
//! the encode side, and asking an object for the half it does not have is a clean
//! [`CodecError::Unsupported`], never a panic.

use crate::factory::{OpusParams, OPUS_CLOCK_RATE_HZ};
use crate::opus::decoder::{OpusDecoder, MAX_PACKET_SAMPLES};
use crate::opus::enc::decision::Application;
use crate::opus::enc::encoder::{OpusEncoder, RateControl};
use crate::opus::packet::Bandwidth;
use crate::{CodecError, CodecParams, Decoder, Encoder};

/// Divisor of the sample rate that yields the 2.5 ms quantum — the shortest frame RFC 6716 §3.1
/// defines, and the granularity `OpusDecoder`'s concealment path accepts (libopus
/// `opus_decoder.c:684`, `frame_size` must be a multiple of `Fs/400`).
const QUANTUM_DIVISOR: usize = 400;

/// Frame durations an Opus **packet** can carry, in whole milliseconds, ascending.
///
/// RFC 6716 §2 (Table 1) gives the frame durations of a single Opus frame — 2.5, 5, 10, 20, 40 and
/// 60 ms — and §3.2 lets a code-3 packet carry several of them, which `opus_encode` exposes as the
/// further 80 / 100 / 120 ms sizes (`frame_size_select`, libopus `opus_encoder.c:704`). 2.5 ms is
/// not a whole number of milliseconds so it can never be signalled by an SDP `a=ptime` (RFC 4566
/// §6, an integer attribute) and is deliberately absent.
const FRAME_DURATIONS_MS: [u8; 8] = [5, 10, 20, 40, 60, 80, 100, 120];

/// Round a negotiated `a=ptime` **down** to a duration Opus can actually emit ([`FRAME_DURATIONS_MS`]).
///
/// The encode side has to produce exactly one frame per call, so a ptime Opus has no frame for —
/// `a=ptime:30`, common on G.711 trunks and perfectly legal SDP — would otherwise fail every encode
/// with `BadFrameSize` and mute the leg. RFC 4566 §6 makes `ptime` "the recommended length", not a
/// constraint, so the nearest shorter length Opus *can* produce honours the recommendation as far as
/// the codec allows; rounding **up** could not, since it would exceed a peer's `a=maxptime`.
/// A ptime below the shortest whole-millisecond Opus frame yields that shortest frame (5 ms): there
/// is nothing smaller to fall back to.
#[must_use]
fn snap_ptime_ms(ptime_ms: u8) -> u8 {
    FRAME_DURATIONS_MS
        .iter()
        .rev()
        .copied()
        .find(|&duration| duration <= ptime_ms)
        .unwrap_or(FRAME_DURATIONS_MS[0])
}

/// The widest Opus audio bandwidth a receiver sampling at `rate_hz` can render, for the RFC 7587
/// §6.1 `maxplaybackrate` parameter ("a hint about the maximum output sampling rate the receiver is
/// capable of rendering").
///
/// RFC 7587 §3.1.1, Table 1 pairs each bandwidth with the sample rate it needs: NB 8000, MB 12000,
/// WB 16000, SWB 24000, FB 48000, and §6.1 only ever signals one of those five. An off-ladder value
/// (an out-of-spec peer) resolves to the lowest rung that is not below it, so the peer never ends up
/// with less bandwidth than the rate it named would suggest.
#[must_use]
fn max_bandwidth_for_playback_rate(rate_hz: u32) -> Bandwidth {
    match rate_hz {
        rate if rate <= 8_000 => Bandwidth::Narrowband,
        rate if rate <= 12_000 => Bandwidth::Mediumband,
        rate if rate <= 16_000 => Bandwidth::Wideband,
        rate if rate <= 24_000 => Bandwidth::SuperWideband,
        _ => Bandwidth::Fullband,
    }
}

/// Packet loss the Opus encoder is told to assume once the peer declared `useinbandfec=1`
/// (RFC 7587 §6.1), as a percentage.
///
/// In-band FEC is not free — an LBRR copy of the previous frame costs bits that would otherwise buy
/// quality — so libopus only generates one when it has a loss figure that justifies it: `decide_fec`
/// returns "no FEC" outright while `packet_loss_percent == 0` (`opus_encoder.c:811`). Honouring the
/// peer's declaration therefore means handing the encoder a figure, and 5 % is the largest one that
/// stays in libopus' *cheap* regime: at or below 5 % `decide_fec` will not trade audio bandwidth
/// away to afford FEC (`opus_encoder.c:832`), so the peer gets the redundancy it asked for without
/// silently losing the bandwidth its `maxplaybackrate` bought it.
///
/// It is a fixed assumption rather than a measurement because the engine has no per-leg loss
/// feedback wired into the encoder yet (RFC 3550 §6.4.1 reception reports are consumed for CDR/MOS,
/// not for encoder control); when that lands this becomes the reported figure.
const ASSUMED_PACKET_LOSS_PERCENT: i32 = 5;

/// The half of the codec this object carries. Exactly one, never both — see the module docs.
enum Half {
    /// The RFC 6716 decoder, built by [`crate::factory::decoder_for`].
    Decode(Box<OpusDecoder>),
    /// The RFC 6716 encoder, built by [`crate::factory::encoder_for`].
    Encode(Box<OpusEncoder>),
}

/// One direction of an Opus leg, as the media path sees it (RFC 6716 / RFC 7587).
///
/// Built by [`crate::factory::decoder_for`] / [`crate::factory::encoder_for`] from the negotiated
/// [`crate::factory::CodecSpec`]: the PCM sample rate from the (RFC 7587 §4.1-pinned) clock rate,
/// the channel count from `sprop-stereo` (ingress) or the engine's mono egress, the nominal frame
/// from the negotiated `ptime`, and — on the encode side — the peer's `a=fmtp` limits.
pub struct OpusCodec {
    half: Half,
    params: CodecParams,
    /// `sample_rate / 400` — 2.5 ms, cached because [`OpusCodec::conceal`] needs it per frame.
    quantum: usize,
}

impl OpusCodec {
    /// Build an Opus **decode** side for `sample_rate_hz` (8/12/16/24/48 kHz — RFC 6716 §2 output
    /// rates), `channels` (1 or 2; RFC 7587 defines Opus over RTP as mono or stereo), and the
    /// negotiated `ptime_ms`.
    ///
    /// `ptime_ms` sets only the *nominal* frame: a packet carrying more is still decoded in full
    /// when the caller's buffer allows it (see the module docs). Errors — never panics — on a rate
    /// or channel count Opus does not define.
    pub fn new_decoder(
        sample_rate_hz: u32,
        channels: u8,
        ptime_ms: u8,
    ) -> Result<Self, CodecError> {
        let channels = channels.max(1);
        let decoder = OpusDecoder::new(sample_rate_hz, usize::from(channels))?;
        Ok(Self {
            half: Half::Decode(Box::new(decoder)),
            params: CodecParams {
                sample_rate_hz,
                channels,
                ptime_ms: ptime_ms.max(1),
            },
            quantum: sample_rate_hz as usize / QUANTUM_DIVISOR,
        })
    }

    /// Build an Opus **encode** side for `sample_rate_hz`, `channels` and `ptime_ms`, configured by
    /// the peer's RFC 7587 §6.1 `a=fmtp` declaration.
    ///
    /// `ptime_ms` is snapped to a duration Opus can emit ([`snap_ptime_ms`]) and becomes this
    /// codec's frame for good: [`Encoder::frame_samples`] reports it and the media path repacketizes
    /// to it, so the datapath and the codec can never disagree about a frame length.
    ///
    /// The application is `VoIP` (libopus `OPUS_APPLICATION_VOIP`) — every Opus leg the engine
    /// encodes toward is a telephony leg, which is what RFC 7587 registers Opus over RTP for.
    ///
    /// Each of the peer's declarations maps to one encoder control, and each of them changes the
    /// bytes on the wire:
    ///
    /// | RFC 7587 §6.1 parameter | Encoder control | Effect on the bitstream |
    /// |---|---|---|
    /// | `maxaveragebitrate` | `set_bitrate` (`OPUS_SET_BITRATE`) | packet size, and through the rate-driven decisions the mode and bandwidth in the TOC |
    /// | `maxplaybackrate` | `set_max_bandwidth` (`OPUS_SET_MAX_BANDWIDTH`) | the bandwidth coded in the TOC (RFC 6716 §3.1, Table 2) |
    /// | `cbr` | `set_rate_control` (`OPUS_SET_VBR`) | every packet padded to one constant length |
    /// | `useinbandfec` | `set_in_band_fec` + [`ASSUMED_PACKET_LOSS_PERCENT`] | an LBRR copy of the previous frame inside each SILK/hybrid packet (RFC 6716 §2.1.7) |
    /// | `usedtx` | `set_dtx` (`OPUS_SET_DTX`) | a silent run collapses to bare one-byte TOC packets |
    ///
    /// `stereo` and `sprop-stereo` are not consumed here: the engine's media path is mono end to end
    /// so [`crate::factory::CodecSpec::encode_channels`] is always 1 (RFC 7587 §7.1 makes `stereo` a
    /// ceiling, never an obligation), and `sprop-stereo` describes the *peer's* sending direction,
    /// which is the decode side's business. `maxptime` is consumed before this point — it clamps the
    /// spec's `ptime_ms` in [`crate::factory::CodecSpec::with_opus_params`].
    ///
    /// Errors — never panics — on a rate or channel count Opus does not define.
    pub fn new_encoder(
        sample_rate_hz: u32,
        channels: u8,
        ptime_ms: u8,
        fmtp: OpusParams,
    ) -> Result<Self, CodecError> {
        let channels = channels.max(1);
        let mut encoder =
            OpusEncoder::new(sample_rate_hz, usize::from(channels), Application::Voip)?;

        // `maxaveragebitrate`: "the maximum average receive bitrate of a session in bits per
        // second". It is a ceiling on what we may send, so it *is* the target rate — an encoder
        // aiming below it would waste the headroom the peer offered. Unstated ⇒ `None`, i.e. the
        // encoder's own rate-derived default (`60 * Fs / frame_size + Fs * channels`).
        encoder.set_bitrate(
            fmtp.max_average_bitrate
                .map(|bitrate| OpusParams::clamp_average_bitrate(bitrate) as i32),
        )?;

        // `maxplaybackrate`: a receiver that cannot render above 8 kHz gains nothing from a
        // fullband packet, so cap the coded bandwidth rather than force it — the rate-driven
        // decision may still choose narrower on its own.
        encoder.set_max_bandwidth(max_bandwidth_for_playback_rate(
            OpusParams::clamp_playback_rate_hz(fmtp.max_playback_rate_hz),
        ));

        // `cbr`: "the decoder prefers the use of ... constant bitrate". Default 0 ⇒ VBR, and the
        // constrained flavour specifically, which is libopus' own default and the one real-time
        // transport wants (a reservoir holds the running average at the target instead of letting a
        // loud frame spike the packet size past the network's budget).
        encoder.set_rate_control(if fmtp.cbr {
            RateControl::Constant
        } else {
            RateControl::ConstrainedVariable
        });

        // `useinbandfec`: "the decoder has the capability to take advantage of the Opus in-band
        // FEC". Turning the generator on is not enough — see `ASSUMED_PACKET_LOSS_PERCENT`.
        encoder.set_in_band_fec(fmtp.use_inband_fec);
        encoder.set_packet_loss_percent(if fmtp.use_inband_fec {
            ASSUMED_PACKET_LOSS_PERCENT
        } else {
            0
        })?;

        // `usedtx`: "the decoder prefers the use of DTX".
        encoder.set_dtx(fmtp.use_dtx);

        Ok(Self {
            half: Half::Encode(Box::new(encoder)),
            params: CodecParams {
                sample_rate_hz,
                channels,
                ptime_ms: snap_ptime_ms(ptime_ms),
            },
            quantum: sample_rate_hz as usize / QUANTUM_DIVISOR,
        })
    }

    /// The codec's native parameters (inherent shortcut; both trait impls expose the same value).
    ///
    /// Inherent rather than only on the traits because [`OpusCodec`] implements both [`Decoder`] and
    /// [`Encoder`], which would otherwise make a bare `codec.params()` ambiguous at every call site
    /// that holds the concrete type — the same shortcut [`crate::g711::G711`] carries for the same
    /// reason.
    #[must_use]
    pub fn params(&self) -> CodecParams {
        self.params
    }

    /// `i16` values in one nominal frame — the **interleaved** count (inherent shortcut, as
    /// [`OpusCodec::params`]).
    #[must_use]
    pub fn frame_samples(&self) -> usize {
        self.params.frame_values()
    }

    /// The RTP timestamp clock, in Hz: 48 kHz whatever the PCM rate (RFC 7587 §4.1). Inherent
    /// shortcut, as [`OpusCodec::params`].
    #[must_use]
    pub fn rtp_clock_rate_hz(&self) -> u32 {
        OPUS_CLOCK_RATE_HZ
    }

    /// Channels the codec interleaves through the caller's buffer, as a `usize` (always ≥ 1).
    fn channels(&self) -> usize {
        usize::from(self.params.channels.max(1))
    }

    /// Per-channel capacity `out` offers, capped at the longest packet RFC 6716 §3.2 allows (120 ms
    /// at 48 kHz). Offering the whole buffer rather than the nominal frame is what lets a packet
    /// longer than the negotiated `ptime` decode in full.
    fn capacity(&self, out: &[i16]) -> usize {
        (out.len() / self.channels()).min(MAX_PACKET_SAMPLES)
    }

    /// The decode half, or [`CodecError::Unsupported`] on an encode-side object (see the module docs
    /// — the factory never builds one that way, so this only guards a misuse of the public API).
    fn decoder(&mut self) -> Result<&mut OpusDecoder, CodecError> {
        match &mut self.half {
            Half::Decode(decoder) => Ok(decoder),
            Half::Encode(_) => Err(CodecError::Unsupported(
                "this Opus codec is the encode side; build a decode side with `OpusCodec::new_decoder`",
            )),
        }
    }

    /// The encode half, or [`CodecError::Unsupported`] on a decode-side object.
    fn encoder(&mut self) -> Result<&mut OpusEncoder, CodecError> {
        match &mut self.half {
            Half::Encode(encoder) => Ok(encoder),
            Half::Decode(_) => Err(CodecError::Unsupported(
                "this Opus codec is the decode side; build an encode side with `OpusCodec::new_encoder`",
            )),
        }
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
        let samples = self.decoder()?.decode(None, out, quantised, false)?;
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
        let samples = self
            .decoder()?
            .decode(Some(payload), out, capacity, false)?;
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

impl Encoder for OpusCodec {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        // The crate channel contract: the **interleaved** value count `encode` consumes.
        self.params.frame_values()
    }

    fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, CodecError> {
        let needed = self.params.frame_values();
        if pcm.len() < needed {
            return Err(CodecError::BadFrameSize {
                expected: needed,
                got: pcm.len(),
            });
        }
        // Per-channel sample count, which is what `OpusEncoder` counts a frame in; `needed` above is
        // the interleaved length of the same frame (crate channel contract).
        let frame_samples = self.params.frame_samples();
        let result = self.encoder()?.encode(&pcm[..needed], frame_samples, out)?;
        // A one-byte result is a bare TOC — the packet Opus DTX emits for a silent frame (RFC 6716
        // §3.1: a packet with no compressed data). It is returned, not swallowed: it is a legal Opus
        // payload the peer's decoder reads as "no data, run the PLC/CNG", and sending it keeps the
        // RTP sequence and timestamp running so the peer's jitter buffer does not see a gap.
        Ok(result.bytes)
    }

    fn rtp_clock_rate_hz(&self) -> u32 {
        // RFC 7587 §4.1, exactly as on the decode side: 48 kHz for every mode and every sample rate,
        // so an Opus leg encoding from 48 kHz PCM still clocks RTP at 48 kHz — and one encoding at a
        // lower PCM rate would too, which the trait default would get wrong.
        OPUS_CLOCK_RATE_HZ
    }

    // `is_stateless` deliberately keeps the trait default, `false`. Opus is stateful across packets
    // in every layer (SILK's LPC/LTP predictors and gain history, CELT's MDCT overlap and band
    // energy, the range coder's own carry, and every hysteresis decision in `opus_encoder.c`), so
    // the conference mixer's shared-encode fan-out — one encode of the common listener mix, the
    // payload copied to every listener on that codec — would feed one encoder's output to legs whose
    // decoders hold different histories and corrupt all of them. Asserted by
    // `an_opus_encoder_is_never_stateless` below, because getting it wrong is silent.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::celt::encoder::{CeltEncoder, RateControl};
    use crate::opus::packet::Toc;

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
        let mono = OpusCodec::new_decoder(48_000, 1, 20).expect("mono codec");
        assert_eq!(mono.params().sample_rate_hz, 48_000);
        assert_eq!(mono.params().channels, 1);
        assert_eq!(mono.params().ptime_ms, 20);
        // Mono: per-channel and interleaved counts coincide.
        assert_eq!(mono.params().frame_samples(), 960);
        assert_eq!(mono.frame_samples(), 960);

        // Stereo: `frame_samples` on the *trait* is the interleaved buffer size, twice the
        // per-channel count (the crate channel contract).
        let stereo = OpusCodec::new_decoder(48_000, 2, 20).expect("stereo codec");
        assert_eq!(stereo.params().frame_samples(), 960);
        assert_eq!(stereo.frame_samples(), 1920);

        // A non-48 kHz output rate is legal (RFC 6716 §2) and must not move the RTP clock.
        let narrow = OpusCodec::new_decoder(8_000, 1, 20).expect("8 kHz codec");
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
            OpusCodec::new_decoder(44_100, 1, 20),
            Err(CodecError::Unsupported(_))
        ));
        assert!(matches!(
            OpusCodec::new_decoder(48_000, 3, 20),
            Err(CodecError::Unsupported(_))
        ));
        // A degenerate ptime is clamped, not rejected (mirrors `CodecSpec::new`).
        assert_eq!(
            OpusCodec::new_decoder(48_000, 1, 0)
                .expect("clamped")
                .params()
                .ptime_ms,
            1
        );
    }

    #[test]
    fn decodes_a_celt_packet_to_real_audio() {
        let packets = celt_packets(TOC_CELT_FB_20MS_MONO, 960, 4);
        let mut codec = OpusCodec::new_decoder(48_000, 1, 20).expect("codec");
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
        let mut codec = OpusCodec::new_decoder(48_000, 1, 20).expect("codec");
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

        let mut codec = OpusCodec::new_decoder(48_000, 1, 20).expect("codec");
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
        let mut codec = OpusCodec::new_decoder(48_000, 1, 20).expect("codec");
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
        let mut codec = OpusCodec::new_decoder(48_000, 1, 20).expect("codec");
        let mut pcm = vec![0i16; codec.frame_samples()];
        assert_eq!(codec.conceal(&mut pcm).expect("conceal"), 960);
        assert_eq!(energy(&pcm), 0);
    }

    #[test]
    fn an_empty_payload_conceals_rather_than_erroring() {
        // A zero-length Opus payload is DTX / "no data" on the wire (RFC 6716 §3 has no TOC to
        // parse), so the right answer is concealment, not a decode error that drops the frame.
        let packets = celt_packets(TOC_CELT_FB_20MS_MONO, 960, 2);
        let mut codec = OpusCodec::new_decoder(48_000, 1, 20).expect("codec");
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
        let mut codec = OpusCodec::new_decoder(48_000, 1, 20).expect("codec");
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
        let mut codec = OpusCodec::new_decoder(48_000, 1, 20).expect("codec");
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
        let mut codec = OpusCodec::new_decoder(48_000, 2, 20).expect("stereo codec");
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

    // ── The encode side ─────────────────────────────────────────────────────────────────────────

    /// Deterministic speech-like 16-bit PCM at 48 kHz: a pitch pulse train through a resonance plus
    /// noise, so the encoder's mode/bandwidth/VAD decisions take realistic branches rather than the
    /// degenerate ones a tone or silence would.
    fn speech(samples: usize) -> Vec<i16> {
        let mut state = 24_680u32;
        let mut history = [0.0f32; 2];
        (0..samples)
            .map(|index| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let noise = ((state >> 20) as i32 - 2048) as f32 * 1.5;
                let pulse = if index % 240 == 0 { 6000.0 } else { 0.0 };
                let value = pulse + noise + 1.5 * history[0] - 0.85 * history[1];
                history[1] = history[0];
                history[0] = value;
                value.clamp(-24_000.0, 24_000.0) as i16
            })
            .collect()
    }

    #[test]
    fn an_opus_encoder_is_never_stateless() {
        // Load-bearing, and silent when wrong: the conference mixer encodes the shared listener mix
        // **once** and copies the payload to every listener whose encoder reports `is_stateless`
        // (`conference.rs`, the shared-encode fan-out). Opus carries state across packets in every
        // layer — SILK's LPC/LTP predictors and gain history, CELT's MDCT overlap and band energy,
        // the range coder — so one encoder's bytes handed to legs with different histories would
        // desynchronise all of them, with no error anywhere.
        let encoder =
            OpusCodec::new_encoder(48_000, 1, 20, OpusParams::default()).expect("encoder");
        assert!(
            !Encoder::is_stateless(&encoder),
            "Opus is stateful; the conference shared-encode fan-out would corrupt it"
        );
    }

    #[test]
    fn encoder_params_follow_the_constructor_and_the_channel_contract() {
        let mono = OpusCodec::new_encoder(48_000, 1, 20, OpusParams::default()).expect("encoder");
        assert_eq!(Encoder::params(&mono).sample_rate_hz, 48_000);
        assert_eq!(Encoder::params(&mono).channels, 1);
        assert_eq!(Encoder::params(&mono).ptime_ms, 20);
        assert_eq!(Encoder::frame_samples(&mono), 960, "48 kHz × 20 ms, mono");
        assert_eq!(
            Encoder::rtp_clock_rate_hz(&mono),
            48_000,
            "RFC 7587 §4.1 pins the RTP clock at 48 kHz"
        );

        // Stereo: `frame_samples` on the trait is the **interleaved** input length (crate channel
        // contract), twice the per-channel count. The engine never builds one (its media path is
        // mono — `CodecSpec::encode_channels`), but the contract holds regardless.
        let stereo = OpusCodec::new_encoder(48_000, 2, 20, OpusParams::default()).expect("encoder");
        assert_eq!(Encoder::params(&stereo).frame_samples(), 960);
        assert_eq!(Encoder::frame_samples(&stereo), 1920);

        // A non-48 kHz PCM rate is legal (RFC 6716 §2) and must not move the RTP clock.
        let narrow = OpusCodec::new_encoder(16_000, 1, 20, OpusParams::default()).expect("encoder");
        assert_eq!(Encoder::frame_samples(&narrow), 320);
        assert_eq!(Encoder::rtp_clock_rate_hz(&narrow), 48_000);
    }

    #[test]
    fn rejects_encode_rates_and_channel_counts_opus_does_not_define() {
        assert!(matches!(
            OpusCodec::new_encoder(44_100, 1, 20, OpusParams::default()),
            Err(CodecError::Unsupported(_))
        ));
        assert!(matches!(
            OpusCodec::new_encoder(48_000, 3, 20, OpusParams::default()),
            Err(CodecError::Unsupported(_))
        ));
    }

    #[test]
    fn a_negotiated_ptime_opus_cannot_emit_is_snapped_down_to_one_it_can() {
        // RFC 6716 §2 Table 1 / §3.2: Opus frames are 2.5/5/10/20/40/60 ms, and a multi-frame packet
        // extends that to 80/100/120. `a=ptime:30` is legal SDP (RFC 4566 §6 — a *recommendation*)
        // and common on G.711 trunks, but Opus has no 30 ms frame, so an unsnapped encoder would
        // fail every `encode` with `BadFrameSize` and mute the leg.
        for (negotiated, expected) in [
            (5u8, 5u8),
            (10, 10),
            (20, 20),
            (30, 20),
            (40, 40),
            (50, 40),
            (60, 60),
            (75, 60),
            (120, 120),
            // Below the shortest whole-millisecond frame there is nothing to round down to.
            (1, 5),
            (0, 5),
        ] {
            let codec = OpusCodec::new_encoder(48_000, 1, negotiated, OpusParams::default())
                .expect("codec");
            assert_eq!(
                Encoder::params(&codec).ptime_ms,
                expected,
                "a=ptime:{negotiated} must encode as {expected} ms"
            );
        }
        // …and the snapped frame really is what `encode` consumes and produces: a 30 ms leg emits a
        // 20 ms packet, not an error.
        let mut codec =
            OpusCodec::new_encoder(48_000, 1, 30, OpusParams::default()).expect("30 ms codec");
        let pcm = speech(Encoder::frame_samples(&codec));
        let mut packet = [0u8; 1500];
        let written = codec.encode(&pcm, &mut packet).expect("encode");
        assert!(written > 1);
        assert_eq!(
            Toc::parse(packet[0]).frame_code,
            0,
            "one 20 ms frame in a code-0 packet (RFC 6716 §3.2.2)"
        );
    }

    #[test]
    fn encodes_pcm_into_a_packet_this_crate_decodes_back_to_the_same_audio() {
        // The round trip is not the proof (a shared encode/decode bug would pass it) — the encoder
        // is gated bit-for-bit against libopus elsewhere. What this proves is the *trait bridge*:
        // that `Encoder::encode` hands `OpusEncoder` a well-formed frame and returns a length that
        // describes a complete, legal RFC 6716 packet.
        let mut encoder =
            OpusCodec::new_encoder(48_000, 1, 20, OpusParams::default()).expect("encoder");
        let mut decoder = OpusCodec::new_decoder(48_000, 1, 20).expect("decoder");
        let frame = Encoder::frame_samples(&encoder);
        let pcm = speech(frame * 8);
        let mut packet = [0u8; 1500];
        let mut decoded = vec![0i16; MAX_PACKET_SAMPLES];

        let mut last = 0usize;
        for index in 0..8 {
            let written = encoder
                .encode(&pcm[index * frame..(index + 1) * frame], &mut packet)
                .expect("encode");
            assert!(
                written > 1,
                "a speech frame is a real packet, not a bare DTX TOC"
            );
            // The TOC must describe what we asked for: 20 ms, mono, one frame (RFC 6716 §3.1).
            let toc = Toc::parse(packet[0]);
            assert_eq!(toc.channels(), 1, "mono egress (RFC 7587 §7.1)");
            assert_eq!(toc.frame_code, 0, "one frame per packet at 20 ms");
            last = decoder
                .decode(&packet[..written], &mut decoded)
                .expect("decode");
            assert_eq!(last, 960, "one 20 ms frame at 48 kHz");
        }
        assert!(
            energy(&decoded[..last]) > 1_000_000,
            "the decoded packet must carry the encoded speech, not silence (energy {})",
            energy(&decoded[..last])
        );
    }

    #[test]
    fn a_short_pcm_frame_or_an_empty_output_errors_instead_of_panicking() {
        let mut codec =
            OpusCodec::new_encoder(48_000, 1, 20, OpusParams::default()).expect("encoder");
        let frame = Encoder::frame_samples(&codec);
        let pcm = speech(frame);
        let mut packet = [0u8; 1500];

        // One sample short of a frame: the encoder has nothing legal to code.
        assert!(matches!(
            codec.encode(&pcm[..frame - 1], &mut packet),
            Err(CodecError::BadFrameSize { .. })
        ));
        // No room at all for a packet.
        assert!(matches!(
            codec.encode(&pcm, &mut []),
            Err(CodecError::OutputTooSmall { .. })
        ));
        // A tiny-but-non-empty buffer is not an error: RFC 6716 lets the encoder fall back to a
        // near-empty packet the far decoder conceals, which is better than dropping the frame.
        assert!(codec.encode(&pcm, &mut packet[..2]).is_ok());
    }

    #[test]
    fn asking_a_codec_for_the_half_it_does_not_have_errors_instead_of_panicking() {
        // The factory only ever hands out the matching half, so this guards a misuse of the public
        // API — and it must be a clean error naming the missing direction, never a panic.
        let mut decode_side = OpusCodec::new_decoder(48_000, 1, 20).expect("decoder");
        let pcm = speech(960);
        let mut packet = [0u8; 1500];
        let Err(CodecError::Unsupported(reason)) = decode_side.encode(&pcm, &mut packet) else {
            panic!("a decode-side Opus codec cannot encode");
        };
        assert!(reason.contains("decode side"), "{reason}");

        let mut encode_side =
            OpusCodec::new_encoder(48_000, 1, 20, OpusParams::default()).expect("encoder");
        let mut decoded = vec![0i16; MAX_PACKET_SAMPLES];
        let real_packet = celt_packets(TOC_CELT_FB_20MS_MONO, 960, 1).remove(0);
        let Err(CodecError::Unsupported(reason)) = encode_side.decode(&real_packet, &mut decoded)
        else {
            panic!("an encode-side Opus codec cannot decode");
        };
        assert!(reason.contains("encode side"), "{reason}");
        // Concealment is the decoder's too.
        assert!(matches!(
            encode_side.conceal(&mut decoded),
            Err(CodecError::Unsupported(_))
        ));
    }

    #[test]
    fn maxplaybackrate_maps_to_the_rfc_7587_bandwidth_ladder() {
        // RFC 7587 §3.1.1, Table 1: each Opus bandwidth needs a particular receiver sample rate.
        for (rate_hz, expected) in [
            (8_000u32, Bandwidth::Narrowband),
            (12_000, Bandwidth::Mediumband),
            (16_000, Bandwidth::Wideband),
            (24_000, Bandwidth::SuperWideband),
            (48_000, Bandwidth::Fullband),
            // §6.1 signals only the five rates above; an off-ladder one resolves to the lowest rung
            // that is not below it.
            (11_000, Bandwidth::Mediumband),
            (44_100, Bandwidth::Fullband),
        ] {
            assert_eq!(
                max_bandwidth_for_playback_rate(rate_hz),
                expected,
                "{rate_hz} Hz"
            );
        }
    }
}
