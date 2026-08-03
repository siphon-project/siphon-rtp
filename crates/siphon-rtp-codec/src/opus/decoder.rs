//! The top-level Opus decoder (RFC 6716 §4, §4.5; libopus `src/opus_decoder.c`).
//!
//! [`super::silk`] decodes speech, [`super::celt`] decodes the transform layer, [`super::packet`]
//! splits a packet into frames. This module is what turns those three into *an Opus decoder*: it
//! reads the TOC, routes each frame to the right layer, and owns everything that lives **between**
//! the layers — the parts neither can see on its own.
//!
//! # What only this layer can do
//!
//! * **Hybrid (configs 12–15).** SILK decodes the 0–8 kHz band and CELT decodes bands 17..21 from
//!   the *same* range decoder over the *same* payload, in that order, and the two are summed. Get
//!   the order or the band split wrong and the entropy stream desynchronises.
//! * **Redundancy (RFC 6716 §4.5.1).** A packet switching between SILK and CELT carries an extra
//!   5 ms CELT frame at the **end** of the payload, cross-faded over the boundary so the switch is
//!   inaudible. libopus folds its range value into the one it reports —
//!   `rangeFinal = dec.rng ^ redundant_rng` (`opus_decoder.c:654`) — which is why whole-packet
//!   `final_range` is only checkable here.
//! * **Mode transitions.** A CELT↔SILK switch with no redundancy frame is smoothed by concealing
//!   5 ms in the *previous* mode and cross-fading that in (`opus_decoder.c:346-363, 493-497,
//!   618-637`). A Hybrid→SILK switch instead lets the CELT MDCT fade itself out by decoding a
//!   2-byte silence frame (`opus_decoder.c:570-574`).
//! * **In-band FEC (§4.4).** `decode_fec` re-decodes the *previous* frame from the LBRR copy this
//!   packet carries, concealing whatever the requested duration does not cover.
//! * **Output rate and channel count.** SILK resamples its own output; CELT decimates its 48 kHz
//!   synthesis. Mono/stereo mismatches between the stream and the caller are resolved here too — a
//!   change of the TOC stereo flag re-points [`CeltDecoder::set_stream_channels`] and SILK's
//!   internal channel count, which is what makes `celt_synthesis`'s up/downmix arms reachable.
//!
//! # Conformance
//!
//! `tests/opus_conformance.rs` decodes all 12 official RFC 6716 test vectors, mono and stereo, and
//! requires the §6 `opus_compare` pass, exact per-packet `final_range` equality with the encoder
//! value stored in the `.bit` file, and agreement with libopus' own decode to within one LSB. The
//! second is the strict one: it is bitstream-exactness, and it is what proves every symbol was read
//! in the right order — including the redundancy frame, which is why it is only checkable here.
//! `tests/opus_redundancy_conformance.rs` re-decodes the SILK oracle streams through this layer so
//! the redundancy-bearing packets the SILK harness has to exclude are covered at full strength.
//!
//! # Deliberately not here
//!
//! Opus multistream / surround (RFC 7845), `OPUS_SET_GAIN`, DRED and the deep-PLC extensions: none
//! are RFC 6716 decoder behaviour, and this crate does not expose knobs it does not implement.

use crate::opus::celt::decoder::CeltDecoder;
use crate::opus::celt::tables::WINDOW120;
use crate::opus::packet::{self, Bandwidth, Mode};
use crate::opus::range_coder::RangeDecoder;
use crate::opus::silk::decoder::SilkDecoder;
use crate::opus::silk::frame::LossFlag;
use crate::opus::silk::types::InternalRate;
use crate::CodecError;

/// Longest audio one Opus packet may carry — 120 ms at 48 kHz (RFC 6716 §3.2.5).
pub const MAX_PACKET_SAMPLES: usize = 5760;
/// Mono or stereo; Opus multistream is out of scope (see the module docs).
const MAX_CHANNELS: usize = 2;
/// Longest single Opus frame — 60 ms at 48 kHz (RFC 6716 §3.1, Table 2).
const MAX_FRAME_SAMPLES: usize = 2880;
/// 5 ms at 48 kHz — the redundancy frame and the transition cross-fade both work at this size.
const MAX_F5: usize = 240;
/// Spare bits a frame must have left for libopus to even look for a redundancy flag
/// (`opus_decoder.c:454`).
const REDUNDANCY_SPARE_BITS: i32 = 17;
/// Extra spare bits a **Hybrid** frame must have, on top of [`REDUNDANCY_SPARE_BITS`], before the
/// redundancy flag is coded at all (`opus_decoder.c:454`).
const HYBRID_REDUNDANCY_EXTRA_BITS: i32 = 20;
/// The two bytes libopus feeds CELT to fade the MDCT out on a Hybrid→SILK switch
/// (`opus_decoder.c:562`). `0xFF 0xFF` decodes to a silent CELT frame.
const CELT_FADE_OUT_SILENCE: [u8; 2] = [0xFF, 0xFF];

/// A complete Opus decoder (libopus `struct OpusDecoder`, `opus_decoder.c:64`).
///
/// Construct it for the output rate and channel count you want; every packet is then decoded to
/// that shape regardless of what the bitstream itself carries. See the module docs for what this
/// layer owns that the SILK and CELT decoders cannot.
pub struct OpusDecoder {
    silk: SilkDecoder,
    celt: CeltDecoder,
    /// `st->channels` — the caller's channel count, 1 or 2.
    channels: usize,
    /// `st->Fs` — the API sample rate: 8/12/16/24/48 kHz.
    sample_rate: u32,

    // ── Everything below is cleared by `reset` (the C's `OPUS_DECODER_RESET_START`) ─────────────
    /// `st->stream_channels` — channels the current packet's TOC codes.
    stream_channels: usize,
    /// `st->bandwidth` — the current packet's audio bandwidth. `None` is the C's 0 ("not from a
    /// packet"), which suppresses the `CELT_SET_END_BAND` update on a concealed frame.
    bandwidth: Option<Bandwidth>,
    /// `st->mode` — the current packet's coding mode.
    mode: Option<Mode>,
    /// `st->prev_mode` — the mode of the last frame actually decoded or concealed. `None` until the
    /// first packet, which is what makes concealment before any packet return silence.
    prev_mode: Option<Mode>,
    /// `st->frame_size` — samples per frame of the current packet, at the API rate.
    frame_size: usize,
    /// `st->prev_redundancy` — the previous frame ended on a SILK→CELT redundancy frame, so the
    /// CELT state is *not* stale even though the previous mode was not CELT.
    prev_redundancy: bool,
    /// Whether the frame just decoded carried a redundancy frame at all, in either direction — see
    /// [`OpusDecoder::last_frame_had_redundancy`]. Distinct from `prev_redundancy`, which is only
    /// the SILK→CELT half of it.
    last_frame_redundancy: bool,
    /// `st->last_packet_duration` — samples the last call produced, per channel.
    last_packet_duration: usize,
    /// `st->softclip_mem` — the declipping non-linearity's per-channel carry-over.
    softclip_mem: [f32; MAX_CHANNELS],
    /// `st->rangeFinal` — see [`OpusDecoder::final_range`].
    range_final: u32,

    /// `DecControl.nChannelsInternal` — the channel count SILK is configured for. Updated only from
    /// a real packet, so a concealed frame keeps decoding at the previous packet's shape
    /// (`opus_decoder.c:395-413`).
    silk_channels: usize,
    /// `DecControl.internalSampleRate` — likewise for SILK's internal rate.
    silk_rate: InternalRate,

    /// Whole-packet float scratch for the 16-bit entry point (`opus_decode`'s `VARDECL(float, out)`,
    /// `opus_decoder.c:864`), allocated **once** at construction so decoding never touches the
    /// allocator. A `Vec` rather than an inline array so [`OpusDecoder::decode`] can move it out of
    /// `self` for the duration of the call in O(1), instead of copying 45 KiB per packet.
    float_scratch: Vec<f32>,
}

impl OpusDecoder {
    /// Build a decoder for `sample_rate` (8/12/16/24/48 kHz) and `channels` (1 or 2) — libopus
    /// `opus_decoder_init`, `opus_decoder.c:129`.
    ///
    /// Neither has to match the bitstream: a stereo packet decoded by a mono decoder is downmixed
    /// and vice versa, and every internal rate is resampled to `sample_rate`.
    pub fn new(sample_rate: u32, channels: usize) -> Result<Self, CodecError> {
        if !matches!(sample_rate, 8_000 | 12_000 | 16_000 | 24_000 | 48_000) {
            return Err(CodecError::Unsupported(
                "opus: sample rate must be 8/12/16/24/48 kHz",
            ));
        }
        if channels != 1 && channels != 2 {
            return Err(CodecError::Unsupported("opus: channels must be 1 or 2"));
        }
        Ok(Self {
            silk: SilkDecoder::new(sample_rate, channels)?,
            celt: CeltDecoder::with_rate_and_channels(sample_rate, channels)?,
            channels,
            sample_rate,
            stream_channels: channels,
            bandwidth: None,
            mode: None,
            prev_mode: None,
            // `st->frame_size = Fs/400` (`opus_decoder.c:168`) — 2.5 ms, the shortest frame there is.
            frame_size: sample_rate as usize / 400,
            prev_redundancy: false,
            last_frame_redundancy: false,
            last_packet_duration: 0,
            softclip_mem: [0.0; MAX_CHANNELS],
            range_final: 0,
            silk_channels: channels,
            silk_rate: InternalRate::Wide16k,
            float_scratch: vec![0.0; MAX_PACKET_SAMPLES * MAX_CHANNELS],
        })
    }

    /// Full decoder reset (libopus `OPUS_RESET_STATE`): both layers and every field from
    /// `OPUS_DECODER_RESET_START` on. The API rate and channel count survive.
    pub fn reset(&mut self) {
        self.silk.reset();
        self.celt.reset_state();
        self.stream_channels = self.channels;
        self.bandwidth = None;
        self.mode = None;
        self.prev_mode = None;
        self.frame_size = self.sample_rate as usize / 400;
        self.prev_redundancy = false;
        self.last_frame_redundancy = false;
        self.last_packet_duration = 0;
        self.softclip_mem = [0.0; MAX_CHANNELS];
        self.range_final = 0;
        self.silk_channels = self.channels;
        self.silk_rate = InternalRate::Wide16k;
    }

    /// The API sample rate in Hz.
    #[must_use]
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// The API channel count (1 or 2). Decoded PCM is interleaved to this width.
    #[must_use]
    pub fn channels(&self) -> usize {
        self.channels
    }

    /// The range coder's final value after the last packet (libopus `OPUS_GET_FINAL_RANGE`).
    ///
    /// Every packet in the official `.bit` vectors carries the **encoder's** value; a conformant
    /// decoder must end the packet on exactly the same one, and `opus_demo` treats a mismatch as a
    /// hard error. It is an exact check, unlike the `opus_compare` tolerance metric, and it includes
    /// any redundancy frame's contribution (`rangeFinal = dec.rng ^ redundant_rng`,
    /// `opus_decoder.c:654`). A concealed or 1-byte frame reports 0.
    #[must_use]
    pub fn final_range(&self) -> u32 {
        self.range_final
    }

    /// Samples per channel the last [`OpusDecoder::decode`] produced
    /// (libopus `OPUS_GET_LAST_PACKET_DURATION`).
    #[must_use]
    pub fn last_packet_duration(&self) -> usize {
        self.last_packet_duration
    }

    /// Whether the frame just decoded carried an RFC 6716 §4.5.1 redundancy frame.
    ///
    /// An encoder emits one on a SILK↔CELT switch: an extra 5 ms CELT frame at the end of the
    /// payload, cross-faded over the boundary. Exposed because it is otherwise invisible from
    /// outside — the audio is already blended in and the extra bytes never reach the caller — while
    /// being exactly what a conformance harness needs to prove it decoded some, and what a live leg
    /// would report as mode-switch churn.
    #[must_use]
    pub fn last_frame_had_redundancy(&self) -> bool {
        self.last_frame_redundancy
    }

    /// Samples per channel `packet` decodes to at `sample_rate` (libopus
    /// `opus_packet_get_nb_samples`, `opus.c:307`). Errors on a packet longer than 120 ms.
    pub fn packet_samples(packet: &[u8], sample_rate: u32) -> Result<usize, CodecError> {
        let parsed = packet::parse(packet)?;
        let samples = parsed.frame_count() * parsed.toc.samples_per_frame(sample_rate);
        // Can't have more than 120 ms (`opus.c:314`).
        if samples * 25 > sample_rate as usize * 3 {
            return Err(CodecError::Malformed("opus: packet longer than 120 ms"));
        }
        Ok(samples)
    }

    /// Decode one Opus packet into interleaved 16-bit PCM, returning the samples **per channel**
    /// (libopus `opus_decode`, `opus_decoder.c:861` — the float build's soft-clipping path).
    ///
    /// * `packet` — `None` (or an empty slice) runs packet-loss concealment for `frame_size`
    ///   samples.
    /// * `frame_size` — the caller's per-channel capacity; `pcm` must hold `frame_size * channels`
    ///   values. For a real packet the decoder produces exactly what the packet carries, never more.
    /// * `decode_fec` — reconstruct the *previous* frame from this packet's in-band FEC (RFC 6716
    ///   §4.4) instead of decoding this one. `frame_size` must then be a multiple of 2.5 ms.
    pub fn decode(
        &mut self,
        packet: Option<&[u8]>,
        pcm: &mut [i16],
        frame_size: usize,
        decode_fec: bool,
    ) -> Result<usize, CodecError> {
        let channels = self.channels;
        // `opus_decode` clamps the request to what the packet actually holds before decoding
        // (`opus_decoder.c:875-882`), so a caller may always pass its buffer capacity.
        let mut frame_size = frame_size;
        if let Some(bytes) = packet {
            if !bytes.is_empty() && !decode_fec {
                frame_size = frame_size.min(Self::packet_samples(bytes, self.sample_rate)?);
            }
        }
        if frame_size > MAX_PACKET_SAMPLES {
            return Err(CodecError::BadFrameSize {
                expected: MAX_PACKET_SAMPLES,
                got: frame_size,
            });
        }
        if pcm.len() < frame_size * channels {
            return Err(CodecError::OutputTooSmall {
                needed: frame_size * channels,
                have: pcm.len(),
            });
        }
        // `float_scratch` is a field so a decode never allocates; move it out for the call (an
        // O(1) pointer swap — `Vec::default()` allocates nothing) and put it back after.
        let mut scratch = std::mem::take(&mut self.float_scratch);
        let result = self.decode_native(packet, &mut scratch, frame_size, decode_fec, true);
        if let Ok(written) = result {
            for (destination, &sample) in
                pcm.iter_mut().zip(scratch.iter()).take(written * channels)
            {
                *destination = float_to_i16(sample);
            }
        }
        self.float_scratch = scratch;
        result
    }

    /// Decode one Opus packet into interleaved **float** PCM, returning the samples per channel
    /// (libopus `opus_decode_float`, `opus_decoder.c:896`).
    ///
    /// Same contract as [`OpusDecoder::decode`], minus the soft-clipping: the float API hands back
    /// the decoder's own output, which may briefly exceed ±1 on a loud passage.
    pub fn decode_float(
        &mut self,
        packet: Option<&[u8]>,
        pcm: &mut [f32],
        frame_size: usize,
        decode_fec: bool,
    ) -> Result<usize, CodecError> {
        let mut frame_size = frame_size;
        if let Some(bytes) = packet {
            if !bytes.is_empty() && !decode_fec {
                frame_size = frame_size.min(Self::packet_samples(bytes, self.sample_rate)?);
            }
        }
        self.decode_native(packet, pcm, frame_size, decode_fec, false)
    }

    /// libopus `opus_decode_native` (`opus_decoder.c:670`): packet framing, the FEC entry, and the
    /// loop over the packet's frames.
    fn decode_native(
        &mut self,
        packet: Option<&[u8]>,
        pcm: &mut [f32],
        frame_size: usize,
        decode_fec: bool,
        soft_clip: bool,
    ) -> Result<usize, CodecError> {
        let channels = self.channels;
        let two_point_five_ms = self.sample_rate as usize / 400;
        // For FEC/PLC, frame_size has to be a multiple of 2.5 ms (`opus_decoder.c:684`).
        let is_concealment = decode_fec || packet.is_none_or(<[u8]>::is_empty);
        if is_concealment && (frame_size == 0 || !frame_size.is_multiple_of(two_point_five_ms)) {
            return Err(CodecError::BadFrameSize {
                expected: two_point_five_ms,
                got: frame_size,
            });
        }
        if pcm.len() < frame_size * channels {
            return Err(CodecError::OutputTooSmall {
                needed: frame_size * channels,
                have: pcm.len(),
            });
        }

        // ── No packet at all: conceal `frame_size` samples (`opus_decoder.c:715`) ────────────────
        let Some(data) = packet.filter(|bytes| !bytes.is_empty()) else {
            let mut produced = 0usize;
            while produced < frame_size {
                let written = self.decode_frame(
                    None,
                    &mut pcm[produced * channels..],
                    frame_size - produced,
                    false,
                )?;
                produced += written;
            }
            self.last_packet_duration = produced;
            return Ok(produced);
        };

        let parsed = packet::parse(data)?;
        let toc = parsed.toc;
        let packet_mode = toc.mode();
        let packet_bandwidth = toc.bandwidth();
        let packet_frame_size = toc.samples_per_frame(self.sample_rate);
        let packet_stream_channels = usize::from(toc.channels());

        // ── In-band FEC: conceal everything except the span the LBRR covers ──────────────────────
        if decode_fec {
            // If no FEC can be present, run the PLC instead (`opus_decoder.c:750`).
            if frame_size < packet_frame_size
                || packet_mode == Mode::Celt
                || self.mode == Some(Mode::Celt)
            {
                return self.decode_native(None, pcm, frame_size, false, soft_clip);
            }
            let conceal = frame_size - packet_frame_size;
            if conceal != 0 {
                let duration_copy = self.last_packet_duration;
                let result = self.decode_native(None, pcm, conceal, false, soft_clip);
                if result.is_err() {
                    self.last_packet_duration = duration_copy;
                }
                result?;
            }
            self.mode = Some(packet_mode);
            self.bandwidth = Some(packet_bandwidth);
            self.frame_size = packet_frame_size;
            self.stream_channels = packet_stream_channels;
            let first = parsed.frames().first().copied().unwrap_or(&[]);
            self.decode_frame(
                Some(first),
                &mut pcm[conceal * channels..],
                packet_frame_size,
                true,
            )?;
            self.last_packet_duration = frame_size;
            return Ok(frame_size);
        }

        if parsed.frame_count() * packet_frame_size > frame_size {
            return Err(CodecError::OutputTooSmall {
                needed: parsed.frame_count() * packet_frame_size * channels,
                have: pcm.len(),
            });
        }

        // Update the state as the last step, so an invalid packet leaves it alone
        // (`opus_decoder.c:784`).
        self.mode = Some(packet_mode);
        self.bandwidth = Some(packet_bandwidth);
        self.frame_size = packet_frame_size;
        self.stream_channels = packet_stream_channels;

        let mut produced = 0usize;
        for frame in parsed.frames() {
            let written = self.decode_frame(
                Some(frame),
                &mut pcm[produced * channels..],
                frame_size - produced,
                false,
            )?;
            produced += written;
        }
        self.last_packet_duration = produced;
        if soft_clip {
            soft_clip_pcm(
                &mut pcm[..produced * channels],
                produced,
                channels,
                &mut self.softclip_mem,
            );
        } else {
            self.softclip_mem = [0.0; MAX_CHANNELS];
        }
        Ok(produced)
    }

    /// Decode (or conceal) **one** Opus frame — libopus `opus_decode_frame`
    /// (`opus_decoder.c:237-668`). This is where the layers meet; see the module docs.
    #[allow(clippy::too_many_lines)]
    fn decode_frame(
        &mut self,
        data: Option<&[u8]>,
        pcm: &mut [f32],
        frame_size: usize,
        decode_fec: bool,
    ) -> Result<usize, CodecError> {
        let sample_rate = self.sample_rate as usize;
        let channels = self.channels;
        let f20 = sample_rate / 50;
        let f10 = f20 >> 1;
        let f5 = f10 >> 1;
        let f2_5 = f5 >> 1;

        if frame_size < f2_5 {
            return Err(CodecError::OutputTooSmall {
                needed: f2_5 * channels,
                have: pcm.len(),
            });
        }
        // Limit frame_size to avoid excessive stack allocations (`opus_decoder.c:282`).
        let mut frame_size = frame_size.min(sample_rate / 25 * 3);

        // Payloads of 1 (2 including the TOC) or 0 trigger the PLC/DTX (`opus_decoder.c:284`).
        let mut data = data;
        if data.is_some_and(|bytes| bytes.len() <= 1) {
            data = None;
            // Don't conceal more than what the TOC says.
            frame_size = frame_size.min(self.frame_size);
        }

        let mut audiosize;
        let mode;
        let bandwidth;
        match data {
            Some(_) => {
                audiosize = self.frame_size;
                mode = self.mode;
                bandwidth = self.bandwidth;
            }
            None => {
                audiosize = frame_size;
                // Run the PLC in the last used mode — CELT if we ended on CELT redundancy.
                mode = if self.prev_redundancy {
                    Some(Mode::Celt)
                } else {
                    self.prev_mode
                };
                bandwidth = None;
            }
        }
        let Some(mode) = mode else {
            // No packet has ever arrived: all we can do is return zeros (`opus_decoder.c:302`).
            if pcm.len() < audiosize * channels {
                return Err(CodecError::OutputTooSmall {
                    needed: audiosize * channels,
                    have: pcm.len(),
                });
            }
            pcm[..audiosize * channels].fill(0.0);
            return Ok(audiosize);
        };

        if data.is_none() {
            // Avoid running the PLC on sizes other than 2.5 (CELT), 5 (CELT), 10 or 20 ms
            // (`opus_decoder.c:311`).
            if audiosize > f20 {
                let mut remaining = audiosize;
                let mut offset = 0usize;
                while remaining > 0 {
                    let written = self.decode_frame(
                        None,
                        &mut pcm[offset * channels..],
                        remaining.min(f20),
                        false,
                    )?;
                    offset += written;
                    remaining -= written;
                }
                return Ok(frame_size);
            } else if audiosize < f20 {
                if audiosize > f10 {
                    audiosize = f10;
                } else if mode != Mode::Silk && audiosize > f5 && audiosize < f10 {
                    audiosize = f5;
                }
            }
        }

        // ── Is this a mode switch that needs a cross-fade? (`opus_decoder.c:346`) ────────────────
        // Only when there is no redundancy frame to do the job properly — that is decided below,
        // after the redundancy flag is read.
        let mut transition = data.is_some()
            && self.prev_mode.is_some()
            && ((mode == Mode::Celt
                && self.prev_mode != Some(Mode::Celt)
                && !self.prev_redundancy)
                || (mode != Mode::Celt && self.prev_mode == Some(Mode::Celt)));

        let mut pcm_transition = [0.0f32; MAX_F5 * MAX_CHANNELS];
        if transition && mode == Mode::Celt {
            // Conceal 5 ms in the *previous* (SILK or Hybrid) mode to fade out of.
            self.decode_frame(None, &mut pcm_transition, f5.min(audiosize), false)?;
        }

        if audiosize > frame_size {
            return Err(CodecError::OutputTooSmall {
                needed: audiosize * channels,
                have: pcm.len(),
            });
        }
        frame_size = audiosize;
        if pcm.len() < frame_size * channels {
            return Err(CodecError::OutputTooSmall {
                needed: frame_size * channels,
                have: pcm.len(),
            });
        }

        let mut range = data.map(RangeDecoder::new);

        // ── SILK layer (`opus_decoder.c:377-450`) ────────────────────────────────────────────────
        // `pcm_silk` is sized `IMAX(F10, frame_size)` per channel: the SILK PLC cannot produce less
        // than 10 ms, so a shorter request still comes back as a 10 ms frame.
        let mut pcm_silk = [0i16; MAX_FRAME_SAMPLES * MAX_CHANNELS];
        if mode != Mode::Celt {
            if self.prev_mode == Some(Mode::Celt) {
                // The SILK state is stale after a stretch of CELT-only frames.
                self.silk.reset();
            }
            // The SILK PLC cannot produce frames of less than 10 ms (`opus_decoder.c:393`).
            let payload_ms = 10.max(1000 * audiosize / sample_rate);
            if data.is_some() {
                self.silk_channels = self.stream_channels;
                self.silk_rate = if mode == Mode::Silk {
                    InternalRate::from_bandwidth(bandwidth.unwrap_or(Bandwidth::Wideband))
                } else {
                    // Hybrid: SILK always runs at 16 kHz (`opus_decoder.c:409-412`).
                    InternalRate::Wide16k
                };
            }
            self.silk
                .configure(self.silk_channels, self.silk_rate, payload_ms)?;
            let loss = match (data.is_some(), decode_fec) {
                (false, _) => LossFlag::PacketLost,
                (true, true) => LossFlag::DecodeLbrr,
                (true, false) => LossFlag::Normal,
            };
            let silk_written = match self.silk.decode(range.as_mut(), loss, &mut pcm_silk) {
                Ok(written) => written,
                // A PLC failure must not be fatal (`opus_decoder.c:436-446`).
                Err(_) if loss != LossFlag::Normal => {
                    pcm_silk[..frame_size * channels].fill(0);
                    frame_size
                }
                Err(error) => return Err(error),
            };
            if silk_written < frame_size {
                // The layer produced less than the frame needs: pad rather than leave stale samples.
                pcm_silk[silk_written * channels..frame_size * channels].fill(0);
            }
        }

        // ── Redundancy flag and the split of the payload (`opus_decoder.c:452-481`) ──────────────
        let mut frame_len = data.map_or(0, <[u8]>::len);
        let mut redundancy = false;
        let mut celt_to_silk = false;
        let mut redundancy_bytes = 0usize;
        if !decode_fec && mode != Mode::Celt && data.is_some() {
            let hybrid_extra = if mode == Mode::Hybrid {
                HYBRID_REDUNDANCY_EXTRA_BITS
            } else {
                0
            };
            let decoder = range
                .as_mut()
                .ok_or(CodecError::Malformed("opus: no bitstream to decode"))?;
            if decoder.tell() + REDUNDANCY_SPARE_BITS + hybrid_extra <= 8 * frame_len as i32 {
                redundancy = if mode == Mode::Hybrid {
                    decoder.dec_bit_logp(12)
                } else {
                    true
                };
                if redundancy {
                    celt_to_silk = decoder.dec_bit_logp(1);
                    // At least two bytes in the non-hybrid case, by the `ec_tell` check above.
                    let bytes = if mode == Mode::Hybrid {
                        decoder.dec_uint(256) as i32 + 2
                    } else {
                        frame_len as i32 - ((decoder.tell() + 7) >> 3)
                    };
                    let remaining = frame_len as i32 - bytes;
                    // A sanity check: it never happens for a valid packet, so the exact behaviour is
                    // not normative (`opus_decoder.c:470`).
                    if remaining * 8 < decoder.tell() {
                        frame_len = 0;
                        redundancy_bytes = 0;
                        redundancy = false;
                    } else {
                        frame_len = remaining as usize;
                        redundancy_bytes = bytes as usize;
                        // Shrink the decoder, because the raw bits are read from the far end.
                        decoder.shrink_storage(redundancy_bytes as u32);
                    }
                }
            }
        }
        // SILK owns everything below band 17 in every non-CELT mode (RFC 6716 §4.3).
        let start_band = if mode == Mode::Celt { 0 } else { 17 };

        if redundancy {
            // The redundancy frame does the cross-fade properly; no need for the concealed one.
            transition = false;
        }
        if transition && mode != Mode::Celt {
            // Conceal 5 ms of CELT to fade out of. Runs here, not earlier, because the redundancy
            // flag decides whether it is needed at all (`opus_decoder.c:493`).
            self.decode_frame(None, &mut pcm_transition, f5.min(audiosize), false)?;
        }

        if let Some(bandwidth) = bandwidth {
            let end = CeltDecoder::end_band_for_bandwidth(bandwidth);
            self.celt.set_band_range(self.celt_start_band(), end)?;
        }
        self.celt.set_stream_channels(self.stream_channels)?;

        // ── The CELT→SILK redundancy frame, decoded before the main frame ────────────────────────
        let mut redundant_audio = [0.0f32; MAX_F5 * MAX_CHANNELS];
        let mut redundant_range = 0u32;
        let frame_bytes = data.unwrap_or(&[]);
        if redundancy && celt_to_silk {
            // If the previous frame did not use CELT the decoder is stale here and the redundancy
            // audio is not useful — but the final range still is (for testing), so it is always
            // decoded and only the audio may be discarded (`opus_decoder.c:534-538`).
            let end = self.celt_end_band();
            self.celt.set_band_range(0, end)?;
            self.celt.decode_float(
                Some(&frame_bytes[frame_len..frame_len + redundancy_bytes]),
                &mut redundant_audio,
                f5,
                None,
            )?;
            redundant_range = self.celt.final_range();
        }

        // MUST be after the redundancy PLC (`opus_decoder.c:546`).
        let end = self.celt_end_band();
        self.celt.set_band_range(start_band, end)?;

        // ── CELT layer, or the Hybrid→SILK MDCT fade-out ─────────────────────────────────────────
        if mode != Mode::Silk {
            let celt_frame_size = f20.min(frame_size);
            // Discard any previous CELT state on a mode change into CELT. The reset only clears
            // from `DECODER_RESET_START` on, so the band range and stream channels just configured
            // survive it (`celt_decoder.c:1522`).
            if Some(mode) != self.prev_mode && self.prev_mode.is_some() && !self.prev_redundancy {
                self.celt.reset_state();
            }
            let celt_data = if decode_fec {
                None
            } else {
                Some(&frame_bytes[..frame_len])
            };
            self.celt
                .decode_float(celt_data, pcm, celt_frame_size, range.as_mut())?;
        } else {
            pcm[..frame_size * channels].fill(0.0);
            // For Hybrid→SILK transitions, let the CELT MDCT fade out by decoding a silence frame.
            if self.prev_mode == Some(Mode::Hybrid)
                && !(redundancy && celt_to_silk && self.prev_redundancy)
            {
                let end = self.celt_end_band();
                self.celt.set_band_range(0, end)?;
                self.celt
                    .decode_float(Some(&CELT_FADE_OUT_SILENCE), pcm, f2_5, None)?;
            }
        }

        // ── Sum the SILK low band onto the CELT high band (`opus_decoder.c:577`) ─────────────────
        if mode != Mode::Celt {
            for (sample, &silk) in pcm
                .iter_mut()
                .zip(pcm_silk.iter())
                .take(frame_size * channels)
            {
                *sample += (1.0 / 32768.0) * f32::from(silk);
            }
        }

        // ── The SILK→CELT redundancy frame, cross-faded onto the tail ────────────────────────────
        let fade_step = 48_000 / sample_rate;
        if redundancy && !celt_to_silk {
            self.celt.reset_state();
            let end = self.celt_end_band();
            self.celt.set_band_range(0, end)?;
            self.celt.decode_float(
                Some(&frame_bytes[frame_len..frame_len + redundancy_bytes]),
                &mut redundant_audio,
                f5,
                None,
            )?;
            redundant_range = self.celt.final_range();
            smooth_fade_into_second(
                &mut pcm[channels * (frame_size - f2_5)..],
                &redundant_audio[channels * f2_5..],
                f2_5,
                channels,
                fade_step,
            );
        }
        // The CELT→SILK redundancy frame replaces the first 2.5 ms and fades into the next 2.5 ms —
        // ignored if the previous frame did not use CELT, since the first redundancy frame of a
        // transition from SILK may have been lost (`opus_decoder.c:605`).
        if redundancy
            && celt_to_silk
            && (self.prev_mode != Some(Mode::Silk) || self.prev_redundancy)
        {
            pcm[..channels * f2_5].copy_from_slice(&redundant_audio[..channels * f2_5]);
            smooth_fade_into_first(
                &redundant_audio[channels * f2_5..],
                &mut pcm[channels * f2_5..],
                f2_5,
                channels,
                fade_step,
            );
        }
        if transition {
            if audiosize >= f5 {
                pcm[..channels * f2_5].copy_from_slice(&pcm_transition[..channels * f2_5]);
                smooth_fade_into_first(
                    &pcm_transition[channels * f2_5..],
                    &mut pcm[channels * f2_5..],
                    f2_5,
                    channels,
                    fade_step,
                );
            } else {
                // Not enough time to do a clean transition, but we do it anyway: amplitude is not
                // perfectly preserved and a little temporal aliasing creeps in, which is the best
                // available (`opus_decoder.c:627`).
                smooth_fade_into_first(&pcm_transition, pcm, f2_5, channels, fade_step);
            }
        }

        self.range_final = if frame_len <= 1 {
            0
        } else {
            range.map_or(0, |decoder| decoder.rng()) ^ redundant_range
        };
        self.prev_mode = Some(mode);
        self.prev_redundancy = redundancy && !celt_to_silk;
        self.last_frame_redundancy = redundancy;
        Ok(audiosize)
    }

    /// The CELT `end` band currently configured, so a temporary `start` change can restore it.
    fn celt_end_band(&self) -> usize {
        self.celt.end_band()
    }

    /// The CELT `start` band currently configured.
    fn celt_start_band(&self) -> usize {
        self.celt.start_band()
    }
}

impl std::fmt::Debug for OpusDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpusDecoder")
            .field("sample_rate", &self.sample_rate)
            .field("channels", &self.channels)
            .field("stream_channels", &self.stream_channels)
            .field("mode", &self.mode)
            .field("prev_mode", &self.prev_mode)
            .field("bandwidth", &self.bandwidth)
            .field("prev_redundancy", &self.prev_redundancy)
            .finish_non_exhaustive()
    }
}

/// Convert float PCM (±1 nominal) to 16-bit (libopus `FLOAT2INT16`).
fn float_to_i16(x: f32) -> i16 {
    crate::opus::celt::synthesis::float_to_i16(x)
}

/// `out = (1-w)·in1 + w·in2` over `overlap` samples, where **`in1` is the buffer written back**
/// (libopus `smooth_fade`, `opus_decoder.c:205`, called with `out == in1`).
///
/// `w` is `window[i·step]²` — the same MDCT window CELT uses, sampled every `48000/Fs`-th tap so a
/// lower API rate fades over the same 2.5 ms of wall time.
fn smooth_fade_into_second(
    out_in1: &mut [f32],
    in2: &[f32],
    overlap: usize,
    channels: usize,
    step: usize,
) {
    for c in 0..channels {
        for i in 0..overlap {
            let w = WINDOW120[i * step] * WINDOW120[i * step];
            let index = i * channels + c;
            out_in1[index] = w * in2[index] + (1.0 - w) * out_in1[index];
        }
    }
}

/// `out = (1-w)·in1 + w·in2` over `overlap` samples, where **`in2` is the buffer written back**
/// (libopus `smooth_fade` called with `out == in2`). See [`smooth_fade_into_second`].
fn smooth_fade_into_first(
    in1: &[f32],
    out_in2: &mut [f32],
    overlap: usize,
    channels: usize,
    step: usize,
) {
    for c in 0..channels {
        for i in 0..overlap {
            let w = WINDOW120[i * step] * WINDOW120[i * step];
            let index = i * channels + c;
            out_in2[index] = w * out_in2[index] + (1.0 - w) * in1[index];
        }
    }
}

/// Soft-clip interleaved float PCM into ±1 (libopus `opus_pcm_soft_clip`, `opus.c:36`).
///
/// A hard clip to ±1 would fold a loud passage's overshoot into audible harmonics; instead each
/// clipped excursion gets a quadratic non-linearity `x + a·x²` fitted so its own peak lands exactly
/// on 1, applied between the surrounding zero crossings. `mem` carries `a` across calls so the
/// non-linearity continues smoothly over a frame boundary.
fn soft_clip_pcm(pcm: &mut [f32], samples: usize, channels: usize, mem: &mut [f32; MAX_CHANNELS]) {
    if channels < 1 || samples < 1 {
        return;
    }
    // Saturate to ±2 first: that is the highest level the non-linearity can handle, and its
    // derivative is zero there, so this introduces no discontinuity in the derivative.
    for sample in pcm.iter_mut().take(samples * channels) {
        *sample = sample.clamp(-2.0, 2.0);
    }
    for (c, carry) in mem.iter_mut().enumerate().take(channels) {
        let at = |i: usize| i * channels + c;
        let mut a = *carry;
        // Continue applying the previous frame's non-linearity to avoid a discontinuity.
        for i in 0..samples {
            if pcm[at(i)] * a >= 0.0 {
                break;
            }
            pcm[at(i)] += a * pcm[at(i)] * pcm[at(i)];
        }

        let mut current = 0usize;
        let first = pcm[at(0)];
        loop {
            // Find the next sample that clips.
            let mut i = current;
            while i < samples && pcm[at(i)].abs() <= 1.0 {
                i += 1;
            }
            if i == samples {
                a = 0.0;
                break;
            }
            let clip = pcm[at(i)];
            let mut peak_position = i;
            let mut maxval = clip.abs();
            // The first zero crossing before the clipping, and the first one after it — the whole
            // half-cycle the non-linearity is applied over.
            let mut start = i;
            while start > 0 && clip * pcm[at(start - 1)] >= 0.0 {
                start -= 1;
            }
            let mut end = i;
            while end < samples && clip * pcm[at(end)] >= 0.0 {
                // Look for other peaks until the next zero crossing.
                if pcm[at(end)].abs() > maxval {
                    maxval = pcm[at(end)].abs();
                    peak_position = end;
                }
                end += 1;
            }
            // The special case where we clip before the first zero crossing.
            let special = start == 0 && clip * first >= 0.0;

            // Compute `a` such that maxval + a·maxval² == 1, boosted by 2^-22 so an aggressively
            // optimised build still cannot produce a value past ±1.
            a = (maxval - 1.0) / (maxval * maxval);
            a += a * 2.4e-7;
            if clip > 0.0 {
                a = -a;
            }
            for i in start..end {
                pcm[at(i)] += a * pcm[at(i)] * pcm[at(i)];
            }

            if special && peak_position >= 2 {
                // Add a linear ramp from the first sample to the signal peak, so the frame does not
                // begin on a discontinuity.
                let mut offset = first - pcm[at(0)];
                let delta = offset / peak_position as f32;
                for i in current..peak_position {
                    offset -= delta;
                    pcm[at(i)] = (pcm[at(i)] + offset).clamp(-1.0, 1.0);
                }
            }
            current = end;
            if current == samples {
                break;
            }
        }
        *carry = a;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic pseudo-random payload behind a TOC byte. Any byte string is a decodable (if
    /// musically meaningless) Opus frame — the range coder reads whatever is there — so this is how
    /// the structural tests reach every mode without needing an encoder.
    fn packet(config: u8, stereo: bool, frame_code: u8, bytes: usize) -> Vec<u8> {
        let mut payload = Vec::with_capacity(bytes + 1);
        payload.push((config << 3) | (u8::from(stereo) << 2) | frame_code);
        for i in 0..bytes {
            payload.push(((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8);
        }
        // Bias the first payload byte away from the CELT silence flag so the full pipeline runs.
        if let Some(first) = payload.get_mut(1) {
            *first &= 0x7f;
        }
        payload
    }

    /// Config numbers for the three modes at 20 ms (RFC 6716 §3.1, Table 2): SILK wideband
    /// (8..=11, `config & 3` picks 10/20/40/60 ms), Hybrid fullband (14/15, `config & 1` picks
    /// 10/20 ms), CELT fullband (28..=31, `config & 3` picks 2.5/5/10/20 ms).
    const SILK_WB_20MS: u8 = 9;
    const HYBRID_FB_20MS: u8 = 15;
    const CELT_FB_20MS: u8 = 31;

    #[test]
    fn rejects_rates_and_channel_counts_outside_rfc_6716() {
        assert!(OpusDecoder::new(44_100, 1).is_err());
        assert!(OpusDecoder::new(0, 1).is_err());
        assert!(OpusDecoder::new(48_000, 0).is_err());
        assert!(OpusDecoder::new(48_000, 3).is_err());
        for rate in [8_000u32, 12_000, 16_000, 24_000, 48_000] {
            for channels in [1usize, 2] {
                let decoder = OpusDecoder::new(rate, channels).expect("valid configuration");
                assert_eq!(decoder.sample_rate(), rate);
                assert_eq!(decoder.channels(), channels);
            }
        }
    }

    /// Every mode, every output rate, both channel counts, both stream channel counts: the packet
    /// must decode to exactly the duration its TOC declares.
    #[test]
    fn every_mode_decodes_to_the_duration_its_toc_declares() {
        for config in [SILK_WB_20MS, HYBRID_FB_20MS, CELT_FB_20MS] {
            for stereo in [false, true] {
                for rate in [8_000u32, 12_000, 16_000, 24_000, 48_000] {
                    for channels in [1usize, 2] {
                        let mut decoder = OpusDecoder::new(rate, channels).expect("decoder");
                        let data = packet(config, stereo, 0, 60);
                        let expected = rate as usize / 50; // 20 ms
                        let mut pcm = vec![0i16; expected * channels];
                        let written = decoder
                            .decode(Some(&data), &mut pcm, expected, false)
                            .unwrap_or_else(|error| {
                                panic!(
                                    "config {config} stereo={stereo} {rate} Hz {channels}ch: {error}"
                                )
                            });
                        assert_eq!(
                            written, expected,
                            "config {config} stereo={stereo} {rate} Hz {channels}ch"
                        );
                    }
                }
            }
        }
    }

    /// A multi-frame packet (code 1/3) must produce every frame's audio, not just the first.
    #[test]
    fn multi_frame_packets_produce_every_frame() {
        // Code 1: two equal CELT frames, so an even payload.
        let mut decoder = OpusDecoder::new(48_000, 1).expect("decoder");
        let data = packet(CELT_FB_20MS, false, 1, 80);
        let mut pcm = vec![0i16; 3 * 960];
        let written = decoder
            .decode(Some(&data), &mut pcm, 2 * 960, false)
            .expect("code 1 decodes");
        assert_eq!(written, 2 * 960, "two 20 ms frames");

        // Code 3 VBR: three frames with explicit lengths.
        let mut data = vec![(CELT_FB_20MS << 3) | 3, 0x83, 20, 30];
        for i in 0..90u32 {
            data.push((i.wrapping_mul(2_654_435_761) >> 24) as u8);
        }
        let mut decoder = OpusDecoder::new(48_000, 1).expect("decoder");
        let written = decoder
            .decode(Some(&data), &mut pcm, 3 * 960, false)
            .expect("code 3 decodes");
        assert_eq!(written, 3 * 960, "three 20 ms frames");
    }

    /// Concealment before any packet has arrived returns silence, not comfort noise
    /// (`opus_decoder.c:302-309`) — there is no mode to conceal in yet.
    #[test]
    fn concealment_before_the_first_packet_is_silence() {
        for channels in [1usize, 2] {
            let mut decoder = OpusDecoder::new(48_000, channels).expect("decoder");
            let mut pcm = vec![123i16; 960 * channels];
            let written = decoder.decode(None, &mut pcm, 960, false).expect("conceal");
            assert_eq!(written, 960);
            assert!(
                pcm[..960 * channels].iter().all(|&sample| sample == 0),
                "{channels}ch: concealment with no prior packet must be silent"
            );
            // And it reports no range, since nothing was decoded.
            assert_eq!(decoder.final_range(), 0);
        }
    }

    /// After a real packet, concealment runs the previous mode's PLC and must stay finite and
    /// bounded for every mode — including across a gap longer than one frame.
    #[test]
    fn concealment_after_a_packet_stays_bounded_in_every_mode() {
        for config in [SILK_WB_20MS, HYBRID_FB_20MS, CELT_FB_20MS] {
            let mut decoder = OpusDecoder::new(48_000, 2).expect("decoder");
            let data = packet(config, true, 0, 60);
            let mut pcm = vec![0i16; 2880 * 2];
            decoder
                .decode(Some(&data), &mut pcm, 960, false)
                .expect("good packet");
            for gap in 0..6 {
                let written = decoder
                    .decode(None, &mut pcm, 960, false)
                    .unwrap_or_else(|error| panic!("config {config} gap {gap}: {error}"));
                assert_eq!(written, 960, "config {config} gap {gap}");
            }
            // A gap longer than 20 ms recurses through the F20 splitter.
            let written = decoder
                .decode(None, &mut pcm, 2880, false)
                .expect("60 ms of concealment");
            assert_eq!(written, 2880);
        }
    }

    /// In-band FEC re-decodes the *previous* frame, so it produces the requested duration, and it
    /// falls back to plain concealment when the packet cannot carry FEC (CELT-only).
    #[test]
    fn fec_decode_produces_the_requested_duration() {
        let mut decoder = OpusDecoder::new(48_000, 1).expect("decoder");
        let silk = packet(SILK_WB_20MS, false, 0, 60);
        let mut pcm = vec![0i16; 1920];
        decoder
            .decode(Some(&silk), &mut pcm, 960, false)
            .expect("prime the decoder");
        // 20 ms of FEC: exactly the packet's own frame size.
        let written = decoder
            .decode(Some(&silk), &mut pcm, 960, true)
            .expect("fec decode");
        assert_eq!(written, 960);
        // 40 ms requested: 20 ms concealed, then 20 ms from the LBRR copy.
        let written = decoder
            .decode(Some(&silk), &mut pcm, 1920, true)
            .expect("fec decode with a concealed head");
        assert_eq!(written, 1920);
        // A CELT-only packet carries no FEC: the call degrades to plain concealment.
        let celt = packet(CELT_FB_20MS, false, 0, 60);
        let written = decoder
            .decode(Some(&celt), &mut pcm, 960, true)
            .expect("fec falls back to plc");
        assert_eq!(written, 960);
        // FEC needs a 2.5 ms multiple.
        assert!(decoder.decode(Some(&silk), &mut pcm, 961, true).is_err());
    }

    /// Switching mode packet to packet must keep decoding — every transition arm in both directions,
    /// including the ones that conceal 5 ms of the previous mode to cross-fade from.
    #[test]
    fn mode_switching_in_both_directions_keeps_decoding() {
        let order = [
            CELT_FB_20MS,
            SILK_WB_20MS,
            CELT_FB_20MS,
            HYBRID_FB_20MS,
            SILK_WB_20MS,
            HYBRID_FB_20MS,
            CELT_FB_20MS,
        ];
        for channels in [1usize, 2] {
            let mut decoder = OpusDecoder::new(48_000, channels).expect("decoder");
            let mut pcm = vec![0i16; 960 * channels];
            for (step, &config) in order.iter().enumerate() {
                let data = packet(config, step % 2 == 0, 0, 60);
                let written = decoder
                    .decode(Some(&data), &mut pcm, 960, false)
                    .unwrap_or_else(|error| panic!("{channels}ch step {step}: {error}"));
                assert_eq!(written, 960, "{channels}ch step {step}");
            }
        }
    }

    /// The float and 16-bit entry points must agree, modulo the soft clipping the 16-bit one adds.
    #[test]
    fn float_and_integer_entry_points_agree() {
        let data = packet(CELT_FB_20MS, false, 0, 60);
        let mut integer_decoder = OpusDecoder::new(48_000, 1).expect("decoder");
        let mut float_decoder = OpusDecoder::new(48_000, 1).expect("decoder");
        let mut integer_pcm = vec![0i16; 960];
        let mut float_pcm = vec![0f32; 960];
        let a = integer_decoder
            .decode(Some(&data), &mut integer_pcm, 960, false)
            .expect("i16");
        let b = float_decoder
            .decode_float(Some(&data), &mut float_pcm, 960, false)
            .expect("f32");
        assert_eq!(a, b);
        assert_eq!(integer_decoder.final_range(), float_decoder.final_range());
        for (index, (&integer, &float)) in integer_pcm.iter().zip(float_pcm.iter()).enumerate() {
            // Soft clipping only moves samples that would have exceeded ±1.
            if float.abs() < 0.9 {
                assert_eq!(
                    integer,
                    crate::opus::celt::synthesis::float_to_i16(float),
                    "sample {index}"
                );
            }
        }
    }

    /// A malformed or hostile packet must error, never panic and never read out of bounds.
    #[test]
    fn malformed_packets_error_rather_than_panic() {
        let mut decoder = OpusDecoder::new(48_000, 2).expect("decoder");
        let mut pcm = vec![0i16; MAX_PACKET_SAMPLES * 2];
        // An empty packet is a legal DTX gap: it conceals rather than erroring.
        assert!(decoder.decode(Some(&[]), &mut pcm, 960, false).is_ok());
        // Framing the parser rejects outright.
        assert!(decoder
            .decode(Some(&[0x01, 0xAA, 0xBB, 0xCC]), &mut pcm, 960, false)
            .is_err()); // code 1 with an odd payload
        assert!(decoder
            .decode(Some(&[0x03, 0x00, 1, 2]), &mut pcm, 960, false)
            .is_err()); // code 3 with zero frames
                        // An undersized output buffer is an error, not a truncated write.
        let data = packet(CELT_FB_20MS, true, 0, 60);
        let mut small = vec![0i16; 100];
        assert!(decoder.decode(Some(&data), &mut small, 960, false).is_err());

        // Arbitrary byte soup across every config: decode-or-error, never panic.
        for seed in 0u32..400 {
            let length = (seed % 60) as usize + 2;
            let mut bytes: Vec<u8> = (0..length)
                .map(|k| (seed.wrapping_mul(2_654_435_761).wrapping_add(k as u32) >> 11) as u8)
                .collect();
            bytes[0] = (((seed % 32) as u8) << 3) | ((seed >> 5) & 0x7) as u8;
            let _ = decoder.decode(Some(&bytes), &mut pcm, MAX_PACKET_SAMPLES, false);
        }
    }

    /// `packet_samples` is `opus_packet_get_nb_samples`: frame count times frame duration.
    #[test]
    fn packet_samples_matches_the_toc() {
        // One 20 ms CELT frame.
        let data = packet(CELT_FB_20MS, false, 0, 10);
        assert_eq!(
            OpusDecoder::packet_samples(&data, 48_000).expect("samples"),
            960
        );
        assert_eq!(
            OpusDecoder::packet_samples(&data, 16_000).expect("samples"),
            320
        );
        // Two frames.
        let data = packet(CELT_FB_20MS, false, 1, 10);
        assert_eq!(
            OpusDecoder::packet_samples(&data, 48_000).expect("samples"),
            1920
        );
        // An empty buffer has no TOC at all.
        assert!(OpusDecoder::packet_samples(&[], 48_000).is_err());
    }

    /// A reset must return the decoder to its fresh state — in particular concealment goes back to
    /// returning silence, which is only true when `prev_mode` was cleared.
    #[test]
    fn reset_returns_the_decoder_to_the_fresh_state() {
        let mut decoder = OpusDecoder::new(48_000, 1).expect("decoder");
        let data = packet(CELT_FB_20MS, false, 0, 60);
        let mut pcm = vec![0i16; 960];
        decoder
            .decode(Some(&data), &mut pcm, 960, false)
            .expect("decode");
        assert_ne!(decoder.final_range(), 0);
        assert_eq!(decoder.last_packet_duration(), 960);

        decoder.reset();
        assert_eq!(decoder.final_range(), 0);
        assert_eq!(decoder.last_packet_duration(), 0);
        assert!(!decoder.last_frame_had_redundancy());
        let mut pcm = vec![7i16; 960];
        decoder.decode(None, &mut pcm, 960, false).expect("conceal");
        assert!(
            pcm.iter().all(|&sample| sample == 0),
            "after a reset there is no mode to conceal in"
        );
        // Configuration survives.
        assert_eq!(decoder.sample_rate(), 48_000);
        assert_eq!(decoder.channels(), 1);
    }

    /// The two `smooth_fade` orientations must produce the same cross-fade — they differ only in
    /// which buffer is written back.
    #[test]
    fn the_two_smooth_fade_orientations_agree() {
        // The real 48 kHz shape: 2.5 ms of overlap over the full 120-tap window, step 1.
        let overlap = 120usize;
        let channels = 2usize;
        let first: Vec<f32> = (0..overlap * channels).map(|i| i as f32).collect();
        let second: Vec<f32> = (0..overlap * channels).map(|i| 100.0 - i as f32).collect();

        let mut over_first = first.clone();
        smooth_fade_into_second(&mut over_first, &second, overlap, channels, 1);
        let mut over_second = second.clone();
        smooth_fade_into_first(&first, &mut over_second, overlap, channels, 1);
        for index in 0..overlap * channels {
            assert!(
                (over_first[index] - over_second[index]).abs() < 1e-6,
                "sample {index}: {} vs {}",
                over_first[index],
                over_second[index]
            );
        }
        // The fade really is a fade: it starts near `first` and ends near `second`.
        assert!((over_first[0] - first[0]).abs() < (over_first[0] - second[0]).abs());
        let last = (overlap - 1) * channels;
        assert!((over_first[last] - second[last]).abs() < (over_first[last] - first[last]).abs());
    }

    /// Soft clipping must bring an over-range signal inside ±1 without touching a signal already in
    /// range (`opus.c:36`).
    #[test]
    fn soft_clip_bounds_the_signal_without_touching_a_quiet_one() {
        let mut memory = [0.0f32; MAX_CHANNELS];
        // Already in range: untouched.
        let quiet: Vec<f32> = (0..64).map(|i| 0.4 * ((i as f32) * 0.3).sin()).collect();
        let mut pcm = quiet.clone();
        soft_clip_pcm(&mut pcm, 64, 1, &mut memory);
        assert_eq!(pcm, quiet);

        // Over range: pulled inside ±1, and still recognisably the same waveform.
        let mut memory = [0.0f32; MAX_CHANNELS];
        let loud: Vec<f32> = (0..256).map(|i| 1.7 * ((i as f32) * 0.1).sin()).collect();
        let mut pcm = loud.clone();
        soft_clip_pcm(&mut pcm, 256, 1, &mut memory);
        assert!(
            pcm.iter().all(|&sample| sample.abs() <= 1.0),
            "soft clip must bound the output"
        );
        for (index, (&clipped, &original)) in pcm.iter().zip(loud.iter()).enumerate() {
            assert!(
                clipped * original >= 0.0,
                "sample {index} changed sign: {clipped} vs {original}"
            );
        }
        // Anything past ±2 saturates first, so it cannot escape either.
        let mut memory = [0.0f32; MAX_CHANNELS];
        let mut pcm = vec![9.0f32; 32];
        soft_clip_pcm(&mut pcm, 32, 1, &mut memory);
        assert!(pcm.iter().all(|&sample| sample.abs() <= 1.0));
    }
}
