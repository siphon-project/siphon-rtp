//! CELT **float** decode orchestration, mono or stereo (RFC 6716 §4.3; libopus
//! `celt/celt_decoder.c` `celt_decode_with_ec_dred` + `celt_synthesis`, `#ifndef FIXED_POINT`).
//!
//! Every sub-component — range coder, band-energy decode, tf-resolution, bit allocation, recursive
//! band/PVQ decode, anti-collapse, inverse MDCT, comb post-filter, de-emphasis — lives in its own
//! module and is validated against the libopus float build. This module is the glue: a
//! [`CeltDecoder`] state struct holding the persistent decoder fields (`CELTDecoder` in
//! `celt_decoder.c:80`) and a decode entry point that drives those pieces in the exact order libopus
//! does, with the exact 1/8-bit (`BITRES`) bit-budget arguments.
//!
//! # Two channel counts, not one
//!
//! `CC` ([`CeltDecoder::channels`]) is what the **caller** wants out; `C`
//! ([`CeltDecoder::stream_channels`]) is what the **bitstream** carries. They differ whenever an
//! Opus stream changes its stereo flag mid-call, so `celt_synthesis` has a mono→stereo copy arm and
//! a stereo→mono downmix arm alongside the `C == CC` normal case. All three are here; the Opus
//! layer only has to set [`CeltDecoder::set_stream_channels`] from the TOC.
//!
//! # Two entry points
//!
//! [`CeltDecoder::decode`] is the standalone CELT-only form: it owns its range decoder and writes
//! 16-bit PCM. [`CeltDecoder::decode_float`] is what the Opus layer drives — it takes an *external*
//! range decoder (Hybrid shares one with SILK over the same payload), writes float PCM so the SILK
//! low band can be summed onto it, and conceals when handed no data.
//!
//! All `ENABLE_QEXT` (quality-extension) and `ENABLE_DEEP_PLC` (neural PLC) branches of the C are
//! stripped — they are vendor extensions, not RFC 6716. The float decoder conforms via the
//! `opus_compare` tolerance metric, not bit-exact PCM (RFC 6716 §6), so this is a faithful float
//! port.
//!
//! Line references below cite `celt/celt_decoder.c` from the libopus tree the port was made against.

use crate::opus::celt::anti_collapse::anti_collapse;
use crate::opus::celt::band_coder::{quant_all_bands, StereoBands};
use crate::opus::celt::energy::{
    unquant_coarse_energy, unquant_energy_finalise, unquant_fine_energy,
};
use crate::opus::celt::mdct::{clt_mdct_backward, MdctLookup};
use crate::opus::celt::postfilter::{comb_filter, COMBFILTER_MINPERIOD};
use crate::opus::celt::rate::{clt_compute_allocation, init_caps};
use crate::opus::celt::synthesis::{deemphasis, denormalise_bands, float_to_i16};
use crate::opus::celt::tables::{
    BITRES, E_BANDS, MAX_LM, NB_BANDS, OVERLAP, PREEMPH, SHORT_MDCT_SIZE, SPREAD_ICDF,
    SPREAD_NORMAL, TAPSET_ICDF, TRIM_ICDF, WINDOW120,
};
use crate::opus::celt::tf::tf_decode;
use crate::opus::packet::Bandwidth;
use crate::opus::range_coder::RangeDecoder;
use crate::CodecError;

/// Decode ring length per channel (libopus `DECODE_BUFFER_SIZE`, `celt_decoder.c:72` →
/// `DEC_PITCH_BUF_SIZE` = 2048). The per-channel buffer is `DECODE_BUFFER_SIZE + overlap` long.
pub(super) const DECODE_BUFFER_SIZE: usize = 2048;

/// Total per-channel decode-ring length (`DECODE_BUFFER_SIZE + mode->overlap`).
pub(super) const DECODE_MEM_LEN: usize = DECODE_BUFFER_SIZE + OVERLAP;

/// Largest channel count (RFC 6716 is mono or stereo; Opus multistream is out of scope).
pub(super) const MAX_CHANNELS: usize = 2;

/// Order of the LPC filter the pitch-based PLC runs in (libopus `CELT_LPC_ORDER`, `celt_lpc.h:38`).
pub(super) const CELT_LPC_ORDER: usize = 24;

/// Base inverse-MDCT length for the 48 kHz mode (libopus `mode->mdct.n`). This is `2 *
/// shortMdctSize * nbShortMdcts = 2 * 120 * 8` — twice the long-frame sample count, because the MDCT
/// is a 50 %-overlapping transform (an N-sample frame is reconstructed by an MDCT of length 2N). The
/// `mdct.rs` docs require `MdctLookup::new(1920, 3)`.
const MDCT_BASE_LEN: usize = 1920;

/// Largest CELT frame in samples: `shortMdctSize << MAX_LM` = 960 (20 ms at 48 kHz).
pub(super) const MAX_FRAME_SAMPLES: usize = SHORT_MDCT_SIZE << MAX_LM;

/// `-28 dB` in the log2 energy domain (libopus `-GCONST(28.f)`), the reset value for the energy
/// history (`celt_decoder.c:1526`).
pub(super) const ENERGY_RESET_DB: f32 = -28.0;

/// Persistent CELT decoder state (libopus `struct OpusCustomDecoder`, `celt_decoder.c:80`, float —
/// the `DECODER_RESET_START` block plus the MDCT lookup and the cleared decode ring). QEXT and
/// deep-PLC fields are omitted (vendor extensions, out of RFC 6716 scope).
pub struct CeltDecoder {
    /// `st->channels` (`CC`) — the caller's channel count. `decode`'s PCM output is interleaved to
    /// this width and the decode ring holds this many channels.
    pub(super) channels: usize,
    /// `st->stream_channels` (`C`) — channels the *bitstream* codes. Equal to `channels` unless the
    /// Opus layer points them apart with [`CeltDecoder::set_stream_channels`].
    pub(super) stream_channels: usize,
    /// `st->downsample` — 48000 / API rate (`resampling_factor`, `celt_decoder.c:201`). CELT always
    /// synthesizes at 48 kHz; the output rate is reached by keeping every `downsample`-th sample.
    pub(super) downsample: usize,
    /// `st->disable_inv` — the mono decoder disables the PVQ's sign inversion
    /// (`celt_decoder.c:227`). Fixed at construction from the *API* channel count.
    pub(super) disable_inv: bool,
    /// Inverse-MDCT / FFT lookup for the 48 kHz mode (`mode->mdct`, base length 1920, shifts 0..=3).
    pub(super) mdct: MdctLookup,
    /// Previous frame's per-band log2 energy, `2*NB_BANDS` (`oldBandE`). Channel `c`'s band `i` is
    /// at `i + c*NB_BANDS`; the inter-frame coarse-energy predictor reads/writes it.
    pub(super) old_band_energy: [f32; 2 * NB_BANDS],
    /// Energy one frame back (`oldLogE`); reset to `-28 dB`.
    pub(super) old_log_energy: [f32; 2 * NB_BANDS],
    /// Energy two frames back (`oldLogE2`); reset to `-28 dB`. Feeds anti-collapse `Ediff`.
    pub(super) old_log_energy2: [f32; 2 * NB_BANDS],
    /// Tracked noise floor (`backgroundLogE`), allowed to rise by at most 2.4 dB/s. The noise-based
    /// concealment decays the band energies down to it rather than to silence
    /// (`celt_decoder.c:674, 1341-1343`).
    pub(super) background_log_energy: [f32; 2 * NB_BANDS],
    /// The decode ring (`_decode_mem`), **one per channel**, each `DECODE_BUFFER_SIZE + overlap`
    /// long. Holds the synthesized SIG-domain time signal + the overlap tail across frames; the comb
    /// post-filter reaches back into it for pitch history.
    pub(super) decode_mem: [[f32; DECODE_MEM_LEN]; MAX_CHANNELS],
    /// Per-channel LPC coefficients the pitch-based PLC fits to the last good frame (`lpc`).
    pub(super) lpc: [[f32; CELT_LPC_ORDER]; MAX_CHANNELS],
    /// De-emphasis 1-pole memory (`preemph_memD`), per channel, persists across frames.
    pub(super) preemph_mem: [f32; MAX_CHANNELS],
    /// Range-coder state carried across frames (`st->rng`) — the anti-collapse / fold PRNG seed.
    pub(super) rng: u32,
    /// `st->loss_duration` — samples concealed since the last good frame, saturating at 10000. Drives
    /// the energy-safety clamp, the concealment decay rate, and the noise-vs-pitch PLC choice.
    pub(super) loss_duration: i32,
    /// `st->skip_plc` — force noise-based concealment until two consecutive packets have arrived
    /// (`celt_decoder.c:699,1106`). Set by a reset, because the pitch history is meaningless then.
    pub(super) skip_plc: bool,
    /// `st->prefilter_and_fold` — the previous frame was concealed by the pitch-based PLC, which
    /// leaves the ring holding un-folded time-domain audio; the next frame must pre-filter and fold
    /// it before synthesising (`celt_decoder.c:1296`).
    pub(super) prefilter_and_fold: bool,
    /// `st->last_pitch_index` — the pitch period the first lost frame searched for, reused for as
    /// long as the loss lasts.
    pub(super) last_pitch_index: usize,
    /// Comb post-filter pitch period for the *current* frame (`postfilter_period`).
    pub(super) postfilter_period: usize,
    /// Comb post-filter pitch period for the *previous* frame (`postfilter_period_old`).
    pub(super) postfilter_period_old: usize,
    /// Comb post-filter gain, current frame (`postfilter_gain`).
    pub(super) postfilter_gain: f32,
    /// Comb post-filter gain, previous frame (`postfilter_gain_old`).
    pub(super) postfilter_gain_old: f32,
    /// Comb post-filter tapset, current frame (`postfilter_tapset`).
    pub(super) postfilter_tapset: usize,
    /// Comb post-filter tapset, previous frame (`postfilter_tapset_old`).
    pub(super) postfilter_tapset_old: usize,
    /// First coded band (`st->start`). 0 for CELT-only; 17 for Hybrid, where SILK carries everything
    /// below (RFC 6716 §4.3, `opus_decoder.c:546` `CELT_SET_START_BAND`).
    pub(super) start_band: usize,
    /// One past the last coded band (`st->end`), set from the packet bandwidth — **not** always 21.
    /// See [`CeltDecoder::set_band_range`].
    pub(super) end_band: usize,
}

impl CeltDecoder {
    /// Construct a fresh **mono** 48 kHz CELT decoder in the reset state.
    pub fn new() -> Result<Self, CodecError> {
        Self::with_channels(1)
    }

    /// Construct a fresh 48 kHz CELT decoder for 1 or 2 channels, in the reset state.
    pub fn with_channels(channels: usize) -> Result<Self, CodecError> {
        Self::with_rate_and_channels(48_000, channels)
    }

    /// Construct a fresh CELT decoder for an API rate and channel count, in the reset state (libopus
    /// `celt_decoder_init` + `opus_custom_decoder_init` + `OPUS_RESET_STATE`,
    /// `celt_decoder.c:195,208,1514`): cleared ring/energy, `oldLogE/oldLogE2 = -28 dB`, `rng = 0`,
    /// post-filter params 0, `skip_plc = 1`.
    ///
    /// `sample_rate` must divide 48000 into an integer 1/2/3/4/6 (`resampling_factor`,
    /// `celt.c:87`) — i.e. one of 8/12/16/24/48 kHz, the rates RFC 6716 §2 defines.
    pub fn with_rate_and_channels(sample_rate: u32, channels: usize) -> Result<Self, CodecError> {
        if channels == 0 || channels > MAX_CHANNELS {
            return Err(CodecError::Unsupported(
                "celt: channel count must be 1 or 2",
            ));
        }
        let downsample = match sample_rate {
            48_000 => 1,
            24_000 => 2,
            16_000 => 3,
            12_000 => 4,
            8_000 => 6,
            _ => {
                return Err(CodecError::Unsupported(
                    "celt: sample rate must be 8/12/16/24/48 kHz",
                ))
            }
        };
        // Base MDCT length 1920, shifts 0..=MAX_LM (=3) for the 48 kHz mode (`mdct.rs` docs).
        let mdct = MdctLookup::new(MDCT_BASE_LEN, MAX_LM)
            .map_err(|_| CodecError::Unsupported("celt: failed to build 48 kHz MDCT lookup"))?;
        let mut decoder = Self {
            channels,
            stream_channels: channels,
            downsample,
            // `st->disable_inv = channels == 1` (`celt_decoder.c:227`) — set once at init from the
            // API channel count, so a mono decoder keeps it even while decoding a stereo stream.
            disable_inv: channels == 1,
            mdct,
            old_band_energy: [0.0; 2 * NB_BANDS],
            old_log_energy: [ENERGY_RESET_DB; 2 * NB_BANDS],
            old_log_energy2: [ENERGY_RESET_DB; 2 * NB_BANDS],
            background_log_energy: [0.0; 2 * NB_BANDS],
            decode_mem: [[0.0; DECODE_MEM_LEN]; MAX_CHANNELS],
            lpc: [[0.0; CELT_LPC_ORDER]; MAX_CHANNELS],
            preemph_mem: [0.0; MAX_CHANNELS],
            rng: 0,
            loss_duration: 0,
            skip_plc: true,
            prefilter_and_fold: false,
            last_pitch_index: 0,
            postfilter_period: 0,
            postfilter_period_old: 0,
            postfilter_gain: 0.0,
            postfilter_gain_old: 0.0,
            postfilter_tapset: 0,
            postfilter_tapset_old: 0,
            start_band: 0,
            end_band: NB_BANDS,
        };
        decoder.reset_state();
        Ok(decoder)
    }

    /// Clear every field from `DECODER_RESET_START` on (libopus `OPUS_RESET_STATE`,
    /// `celt_decoder.c:1514-1529`): the decode ring, the LPC memory, the de-emphasis memory, the
    /// post-filter parameters, `rng` and the loss bookkeeping. `oldLogE`/`oldLogE2` become `-28 dB`
    /// and `skip_plc` is *set*, because the pitch history a reset just discarded cannot be
    /// extrapolated from.
    ///
    /// The Opus layer calls this on a mode change into CELT and before a SILK→CELT redundancy frame
    /// (`opus_decoder.c:553,597`), which is what stops the previous mode's ring from leaking through.
    pub fn reset_state(&mut self) {
        self.old_band_energy = [0.0; 2 * NB_BANDS];
        self.old_log_energy = [ENERGY_RESET_DB; 2 * NB_BANDS];
        self.old_log_energy2 = [ENERGY_RESET_DB; 2 * NB_BANDS];
        self.background_log_energy = [0.0; 2 * NB_BANDS];
        self.decode_mem = [[0.0; DECODE_MEM_LEN]; MAX_CHANNELS];
        self.lpc = [[0.0; CELT_LPC_ORDER]; MAX_CHANNELS];
        self.preemph_mem = [0.0; MAX_CHANNELS];
        self.rng = 0;
        self.loss_duration = 0;
        self.skip_plc = true;
        self.prefilter_and_fold = false;
        self.last_pitch_index = 0;
        self.postfilter_period = 0;
        self.postfilter_period_old = 0;
        self.postfilter_gain = 0.0;
        self.postfilter_gain_old = 0.0;
        self.postfilter_tapset = 0;
        self.postfilter_tapset_old = 0;
    }

    /// Set the coded band range (libopus `CELT_SET_START_BAND` / `CELT_SET_END_BAND`,
    /// `opus_decoder.c:523,546`).
    ///
    /// `end` is **derived from the packet bandwidth**, not fixed at 21 — a narrower bandwidth codes
    /// fewer bands, and decoding it as fullband desynchronises the range decoder
    /// (`opus_decoder.c:500-524`):
    ///
    /// | Bandwidth | `end` |
    /// |---|---|
    /// | Narrowband | 13 |
    /// | Medium / Wideband | 17 |
    /// | Super-wideband | 19 |
    /// | Fullband | 21 |
    ///
    /// `start` is 0 for CELT-only and 17 for Hybrid (SILK owns the bands below).
    ///
    /// The two are validated **independently** (`0 <= start < 21`, `1 <= end <= 21`), exactly as
    /// libopus' two separate ctls are. `start > end` is therefore accepted, and it is not
    /// hypothetical: a SILK-only narrowband packet sets `start = 17` from the mode and `end = 13`
    /// from the bandwidth. That configuration codes no CELT band at all, and the Opus layer never
    /// runs a CELT decode while it holds — [`CeltDecoder::decode_float`] rejects it rather than
    /// letting an empty range fall through the allocator's `end - start` arithmetic.
    pub fn set_band_range(&mut self, start: usize, end: usize) -> Result<(), CodecError> {
        if start >= NB_BANDS || end == 0 || end > NB_BANDS {
            return Err(CodecError::Unsupported(
                "celt: band range must satisfy 0 <= start < 21 and 1 <= end <= 21",
            ));
        }
        self.start_band = start;
        self.end_band = end;
        Ok(())
    }

    /// Set the number of channels the *bitstream* codes (libopus `CELT_SET_CHANNELS`,
    /// `celt_decoder.c:1489`). Independent of [`CeltDecoder::channels`]; see the module docs.
    pub fn set_stream_channels(&mut self, channels: usize) -> Result<(), CodecError> {
        if channels == 0 || channels > MAX_CHANNELS {
            return Err(CodecError::Unsupported(
                "celt: stream channel count must be 1 or 2",
            ));
        }
        self.stream_channels = channels;
        Ok(())
    }

    /// The range coder's final range after the last decoded frame (libopus `OPUS_GET_FINAL_RANGE`).
    ///
    /// `opus_demo` stores the *encoder's* final range alongside every packet it writes, and treats a
    /// decoder that ends a packet on a different value as a hard error ("Range coder state mismatch").
    /// It is therefore an exact, per-packet conformance oracle — far stricter than the `opus_compare`
    /// tolerance metric, and it localises a desync to the packet that caused it.
    #[must_use]
    pub fn final_range(&self) -> u32 {
        self.rng
    }

    /// `st->channels` (`CC`) — the caller's channel count.
    #[must_use]
    pub fn channels(&self) -> usize {
        self.channels
    }

    /// `st->stream_channels` (`C`) — channels the bitstream codes.
    #[must_use]
    pub fn stream_channels(&self) -> usize {
        self.stream_channels
    }

    /// `st->start` — the first coded band. See [`CeltDecoder::set_band_range`].
    #[must_use]
    pub fn start_band(&self) -> usize {
        self.start_band
    }

    /// `st->end` — one past the last coded band. See [`CeltDecoder::set_band_range`].
    #[must_use]
    pub fn end_band(&self) -> usize {
        self.end_band
    }

    /// The CELT `end` band for an Opus packet bandwidth (`opus_decoder.c:500-524`).
    #[must_use]
    pub fn end_band_for_bandwidth(bandwidth: Bandwidth) -> usize {
        match bandwidth {
            Bandwidth::Narrowband => 13,
            Bandwidth::Mediumband | Bandwidth::Wideband => 17,
            Bandwidth::SuperWideband => 19,
            Bandwidth::Fullband => NB_BANDS,
        }
    }

    /// Decode one CELT-only frame from `frame` into `pcm` as **interleaved** 16-bit samples,
    /// returning the number of samples **per channel** written (`pcm` must therefore hold
    /// `frame_size * channels` values — the crate's channel contract).
    ///
    /// The standalone CELT-only form: it owns its range decoder over `frame` and rounds the float
    /// synthesis to 16 bits itself. `frame_size` is the requested per-channel PCM sample count
    /// (which selects `LM`); it must be one of 120/240/480/960 (2.5/5/10/20 ms at 48 kHz), scaled by
    /// the decoder's output rate.
    pub fn decode(
        &mut self,
        frame: &[u8],
        pcm: &mut [i16],
        frame_size: usize,
    ) -> Result<usize, CodecError> {
        if frame.len() <= 1 {
            return Err(CodecError::Malformed(
                "celt: data packet must be >1 byte (PLC/DTX handled by the caller)",
            ));
        }
        let mut float_pcm = [0f32; MAX_CHANNELS * MAX_FRAME_SAMPLES];
        let written = self.decode_float(Some(frame), &mut float_pcm, frame_size, None)?;
        let channels = self.channels;
        if pcm.len() < written * channels {
            return Err(CodecError::OutputTooSmall {
                needed: written * channels,
                have: pcm.len(),
            });
        }
        for (destination, &sample) in pcm
            .iter_mut()
            .zip(float_pcm.iter())
            .take(written * channels)
        {
            *destination = float_to_i16(sample);
        }
        Ok(written)
    }

    /// Decode one CELT frame into **interleaved float** PCM, returning the samples per channel
    /// written. A faithful float port of `celt_decode_with_ec_dred` (`celt_decoder.c:970`).
    ///
    /// * `data` — the frame's bytes, or `None` for "no bitstream, conceal". A `data` of 0 or 1 byte
    ///   is also concealment (`celt_decoder.c:1086`): those are DTX / padding-only frames.
    /// * `frame_size` — samples per channel at the **API** rate; internally multiplied by
    ///   [`CeltDecoder::downsample`] to reach the 48 kHz `N` that selects `LM`.
    /// * `range` — an external range decoder to continue from. Hybrid passes the same decoder SILK
    ///   just read its layer from, so both layers share one entropy stream over one payload
    ///   (RFC 6716 §4.5). `None` starts a fresh decoder over `data`.
    ///
    /// `pcm` must hold `frame_size * channels` samples. Unlike [`CeltDecoder::decode`] the output is
    /// *overwritten*, never accumulated: the fixed-point build's `celt_accum` shortcut does not
    /// exist in the float build (`opus_decoder.c:341`), so the Opus layer sums the SILK band itself.
    #[allow(clippy::too_many_lines)]
    pub fn decode_float<'a>(
        &mut self,
        data: Option<&'a [u8]>,
        pcm: &mut [f32],
        frame_size: usize,
        range: Option<&mut RangeDecoder<'a>>,
    ) -> Result<usize, CodecError> {
        // frame_size *= st->downsample (celt_decoder.c:1031): LM is chosen at 48 kHz.
        let frame_size_48k =
            frame_size
                .checked_mul(self.downsample)
                .ok_or(CodecError::BadFrameSize {
                    expected: MAX_FRAME_SAMPLES,
                    got: frame_size,
                })?;
        // ── Frame size → LM (celt_decoder.c:1065) ────────────────────────────────────────────────
        // shortMdctSize<<LM == frame_size for some LM in 0..=maxLM.
        let lm = (0..=MAX_LM)
            .find(|&candidate| (SHORT_MDCT_SIZE << candidate) == frame_size_48k)
            .ok_or(CodecError::BadFrameSize {
                expected: SHORT_MDCT_SIZE << MAX_LM,
                got: frame_size_48k,
            })?;

        let m = 1usize << lm; // M = 1<<LM (celt_decoder.c:1071)
        let n = m * SHORT_MDCT_SIZE; // N = M*shortMdctSize (celt_decoder.c:1076)
        let channels = self.channels; // CC = st->channels
        let stream_channels = self.stream_channels; // C = st->stream_channels
        let start = self.start_band; // st->start
        let end = self.end_band; // st->end, from the packet bandwidth (see `set_band_range`)
        if start > end {
            // No CELT band is coded at all (see `set_band_range`). libopus never reaches its decoder
            // in this state; error out rather than run the bit allocator's `end - start` arithmetic
            // backwards.
            return Err(CodecError::Unsupported(
                "celt: decode called with an empty band range (start > end)",
            ));
        }
        let eff_end = end.min(NB_BANDS); // effEnd = IMIN(end, effEBands) (celt_decoder.c:1082)
        let output_samples = n / self.downsample;

        if pcm.len() < output_samples * channels {
            return Err(CodecError::OutputTooSmall {
                needed: output_samples * channels,
                have: pcm.len(),
            });
        }

        // len<0 || len>1275 (celt_decoder.c:1073).
        let frame = match data {
            Some(bytes) if bytes.len() > 1275 => {
                return Err(CodecError::Malformed("celt: frame longer than 1275 bytes"))
            }
            // `data == NULL || len <= 1` is the concealment path (celt_decoder.c:1086).
            Some(bytes) if bytes.len() > 1 => bytes,
            _ => {
                self.decode_lost(n, lm);
                self.write_output(pcm, n, output_samples);
                return Ok(output_samples);
            }
        };

        // "Check if there are at least two packets received consecutively before turning on the
        // pitch-based PLC" (celt_decoder.c:1106).
        if self.loss_duration == 0 {
            self.skip_plc = false;
        }

        // ── ec_dec_init, or continue the caller's decoder (celt_decoder.c:1108) ──────────────────
        let mut owned_decoder;
        let dec: &mut RangeDecoder<'_> = match range {
            Some(external) => external,
            None => {
                owned_decoder = RangeDecoder::new(frame);
                &mut owned_decoder
            }
        };

        // C==1: fold the (duplicated) second channel's energy into the first (celt_decoder.c:1114).
        // On the mono path band E[NB_BANDS..] mirrors band E[..NB_BANDS] (kept in sync at frame end),
        // so this is the max of a value with itself; preserved for exactness. A stereo stream keeps
        // the two halves genuinely separate, so the fold must not run.
        if stream_channels == 1 {
            for i in 0..NB_BANDS {
                self.old_band_energy[i] =
                    self.old_band_energy[i].max(self.old_band_energy[NB_BANDS + i]);
            }
        }

        let total_bits_i = (frame.len() as i32) * 8; // total_bits = len*8 (celt_decoder.c:1120)

        // ── Silence flag (celt_decoder.c:1123) ───────────────────────────────────────────────────
        let tell = dec.tell();
        let silence = if tell >= total_bits_i {
            true
        } else if tell == 1 {
            dec.dec_bit_logp(15)
        } else {
            false
        };
        // "Pretend we've read all the remaining bits" (celt_decoder.c:1131): advance `nbits_total`
        // to `len*8` so every `tell+X <= total_bits` guard below fails and no further symbol is
        // read — which is exactly what the encoder does on a silent frame, so both sides end the
        // packet on the same range value. `silence` additionally pins the energies and
        // `denormalise_bands(silence=true)` zeroes the spectrum.
        if silence {
            dec.declare_bits_used(total_bits_i);
        }

        // ── Post-filter params (start==0, celt_decoder.c:1139) ───────────────────────────────────
        let mut postfilter_gain = 0.0f32;
        let mut postfilter_pitch = 0usize;
        let mut postfilter_tapset = 0usize;
        let tell = dec.tell();
        // libopus nests the post-filter-present flag inside the bit-budget gate; `&&` short-circuit
        // keeps `dec_bit_logp` from being read unless the gate passes (identical bitstream order).
        if start == 0 && tell + 16 <= total_bits_i && dec.dec_bit_logp(1) {
            let octave = dec.dec_uint(6); // ec_dec_uint(dec, 6)
                                          // postfilter_pitch = (16<<octave) + ec_dec_bits(4+octave) - 1
            let period = dec.dec_bits(4 + octave);
            postfilter_pitch = ((16u32 << octave) + period - 1) as usize;
            let qg = dec.dec_bits(3); // ec_dec_bits(dec, 3)
            if dec.tell() + 2 <= total_bits_i {
                postfilter_tapset = dec.dec_icdf(&TAPSET_ICDF, 2);
            }
            // postfilter_gain = QCONST16(.09375f,15)*(qg+1) (float build: 0.09375*(qg+1)).
            postfilter_gain = 0.093_75 * (qg + 1) as f32;
        }

        // ── Transient flag (LM>0, celt_decoder.c:1154) ───────────────────────────────────────────
        let tell = dec.tell();
        let is_transient = if lm > 0 && tell + 3 <= total_bits_i {
            dec.dec_bit_logp(3)
        } else {
            false
        };
        let short_blocks = is_transient; // shortBlocks = isTransient ? M : 0; band decode takes a bool

        // ── Intra-energy flag (celt_decoder.c:1168) ──────────────────────────────────────────────
        let tell = dec.tell();
        let intra_ener = tell + 3 <= total_bits_i && dec.dec_bit_logp(3);

        // ── Post-loss energy safety (celt_decoder.c:1171-1198) ───────────────────────────────────
        // Coming out of concealment the inter-frame energy predictor is anchored on invented
        // energies, so a loud artefact is one bad prediction away. Continue a downward trend, else
        // take the minimum of the last frames; both channel slots, whatever C is.
        if !intra_ener && self.loss_duration != 0 {
            let missing = 10.min(self.loss_duration >> lm) as f32;
            let safety = match lm {
                0 => 1.5,
                1 => 0.5,
                _ => 0.0,
            };
            for channel in 0..2 {
                let base = channel * NB_BANDS;
                for i in start..end {
                    let e0 = self.old_band_energy[base + i];
                    let e1 = self.old_log_energy[base + i];
                    let e2 = self.old_log_energy2[base + i];
                    self.old_band_energy[base + i] = if e0 < e1.max(e2) {
                        let slope = (e1 - e0).max(0.5 * (e2 - e0));
                        (e0 - (0.0f32).max((1.0 + missing) * slope)).max(-20.0)
                    } else {
                        e0.min(e1).min(e2)
                    } - safety;
                }
            }
        }

        // ── Coarse band energy (celt_decoder.c:1200) ─────────────────────────────────────────────
        unquant_coarse_energy(
            start,
            end,
            &mut self.old_band_energy,
            intra_ener,
            dec,
            stream_channels,
            lm,
        );

        // ── tf-resolution (celt_decoder.c:1204) ──────────────────────────────────────────────────
        let mut tf_res = [0i32; NB_BANDS];
        tf_decode(start, end, is_transient, &mut tf_res, lm, dec);

        // ── Spread (celt_decoder.c:1206) ─────────────────────────────────────────────────────────
        let tell = dec.tell();
        let spread = if tell + 4 <= total_bits_i {
            dec.dec_icdf(&SPREAD_ICDF, 5) as u32
        } else {
            SPREAD_NORMAL
        };

        // ── Caps + dynalloc boost loop (celt_decoder.c:1211-1246) ────────────────────────────────
        let mut cap = [0i32; NB_BANDS];
        init_caps(&mut cap, lm, stream_channels);

        let mut offsets = [0i32; NB_BANDS];
        let mut dynalloc_logp = 6i32;
        // total_bits <<= BITRES  → from here on the budget is in 1/8 bits (celt_decoder.c:1218).
        let mut total_bits_frac = total_bits_i << BITRES;
        let mut tell_frac = dec.tell_frac() as i32;
        for i in start..end {
            // width = C*(eBands[i+1]-eBands[i])<<LM
            let width = ((stream_channels as i32) * i32::from(E_BANDS[i + 1] - E_BANDS[i])) << lm;
            // quanta = IMIN(width<<BITRES, IMAX(6<<BITRES, width))
            let quanta = (width << BITRES).min((6 << BITRES).max(width));
            let mut dynalloc_loop_logp = dynalloc_logp;
            let mut boost = 0i32;
            while tell_frac + (dynalloc_loop_logp << BITRES) < total_bits_frac && boost < cap[i] {
                let flag = dec.dec_bit_logp(dynalloc_loop_logp as u32);
                tell_frac = dec.tell_frac() as i32;
                if !flag {
                    break;
                }
                boost += quanta;
                total_bits_frac -= quanta;
                dynalloc_loop_logp = 1;
            }
            offsets[i] = boost;
            if boost > 0 {
                dynalloc_logp = 2.max(dynalloc_logp - 1);
            }
        }

        // ── Allocation trim (celt_decoder.c:1249) ────────────────────────────────────────────────
        let alloc_trim = if tell_frac + (6 << BITRES) <= total_bits_frac {
            dec.dec_icdf(&TRIM_ICDF, 7) as i32
        } else {
            5
        };

        // ── Bit budget for allocation + anti-collapse reservation (celt_decoder.c:1252) ──────────
        // bits = (len*8 << BITRES) - ec_tell_frac(dec) - 1   (1/8-bit units)
        let mut bits = (((frame.len() as i32) * 8) << BITRES) - dec.tell_frac() as i32 - 1;
        // anti_collapse_rsv = isTransient && LM>=2 && bits >= ((LM+2)<<BITRES) ? (1<<BITRES) : 0
        let anti_collapse_rsv = if is_transient && lm >= 2 && bits >= ((lm as i32 + 2) << BITRES) {
            1 << BITRES
        } else {
            0
        };
        bits -= anti_collapse_rsv;

        // ── Bit allocation (celt_decoder.c:1259) ─────────────────────────────────────────────────
        let mut intensity = 0usize;
        let mut dual_stereo = false;
        let mut pulses = [0i32; NB_BANDS];
        let mut fine_quant = [0i32; NB_BANDS];
        let mut fine_priority = [0i32; NB_BANDS];
        let mut balance = 0i32;
        let coded_bands = clt_compute_allocation(
            start,
            end,
            &offsets,
            &cap,
            alloc_trim,
            &mut intensity,
            &mut dual_stereo,
            bits,
            &mut balance,
            &mut pulses,
            &mut fine_quant,
            &mut fine_priority,
            stream_channels,
            lm,
            // `prev` / `signal_bandwidth` drive the *encoder's* band-skip choice only; a decoder
            // reads the flags (`rate.c:346`), so these are unread here.
            0,
            0,
            dec,
        );

        // ── Fine band energy (celt_decoder.c:1263) ───────────────────────────────────────────────
        unquant_fine_energy(
            start,
            end,
            &mut self.old_band_energy,
            &fine_quant,
            dec,
            stream_channels,
        );

        // ── Shift the decode ring left by N (celt_decoder.c:1265) ────────────────────────────────
        // OPUS_MOVE(decode_mem, decode_mem+N, decode_buffer_size-N+overlap): drop the oldest N
        // samples, sliding the rest down so the IMDCT overlap-add + the comb post-filter's pitch
        // history line up for this frame. The moved count is exactly `DECODE_MEM_LEN - N`, i.e. the
        // whole tail `[N..]` → `[0..]`. Over **CC** channels — the ring is the caller's width.
        for c in 0..channels {
            self.decode_mem[c].copy_within(n.., 0);
        }

        // ── Band / PVQ decode (celt_decoder.c:1274) ──────────────────────────────────────────────
        // X is the C*N normalised MDCT coefficient buffer, channel-major (`Y_ = X_ + N` in the C).
        // Fixed stack scratch, not a per-frame `Vec`: the hot path must not touch the allocator.
        let mut x_buf = [0f32; MAX_CHANNELS * MAX_FRAME_SAMPLES];
        let x = &mut x_buf[..stream_channels * n];
        let mut collapse_masks = [0u8; MAX_CHANNELS * NB_BANDS];
        // total_bits arg = len*(8<<BITRES) - anti_collapse_rsv  (1/8 bits).
        let band_total_bits = (frame.len() as i32) * (8 << BITRES) - anti_collapse_rsv;
        // `bandE`/`complexity`/`rdo` are encode-only inputs (`intensity_stereo`'s weights and the
        // theta trial), so a decoder passes none of them (`celt_decoder.c:1275` passes `NULL`/`0`).
        let mut stereo = StereoBands {
            band_energy: &[],
            intensity,
            dual_stereo,
            complexity: 0,
            rdo: None,
        };
        quant_all_bands(
            start,
            end,
            x,
            n,
            (stream_channels == 2).then_some(&mut stereo),
            &mut collapse_masks[..stream_channels * NB_BANDS],
            &pulses,
            short_blocks,
            spread,
            &tf_res,
            band_total_bits,
            balance,
            lm as i32,
            coded_bands,
            &mut self.rng,
            self.disable_inv,
            dec,
        );

        // ── Anti-collapse (celt_decoder.c:1279) ──────────────────────────────────────────────────
        let anti_collapse_on = if anti_collapse_rsv > 0 {
            dec.dec_bits(1) != 0
        } else {
            false
        };

        // ── Energy finalise (celt_decoder.c:1284) ────────────────────────────────────────────────
        // bits_left = len*8 - ec_tell(dec)
        unquant_energy_finalise(
            start,
            end,
            &mut self.old_band_energy,
            &fine_quant,
            &fine_priority,
            (frame.len() as i32) * 8 - dec.tell(),
            dec,
            stream_channels,
        );

        if anti_collapse_on {
            self.rng = anti_collapse(
                x,
                &collapse_masks[..stream_channels * NB_BANDS],
                lm,
                stream_channels,
                n,
                start,
                end,
                &self.old_band_energy,
                &self.old_log_energy,
                &self.old_log_energy2,
                &pulses,
                self.rng,
            );
        }

        // On silence the energies are pinned to -28 dB (celt_decoder.c:1291).
        if silence {
            self.old_band_energy.fill(ENERGY_RESET_DB);
        }

        // The previous frame was concealed by the pitch-based PLC, which left raw time-domain audio
        // in the ring: pre-filter and fold it so this frame's MDCT overlap-add lands on a TDAC-shaped
        // tail rather than a discontinuity (celt_decoder.c:1296).
        if self.prefilter_and_fold {
            self.prefilter_and_fold(n);
        }

        // ── Synthesis: denormalise + IMDCT + overlap-add into the decode ring (celt_decoder.c:1299)
        // `old_band_energy` is `Copy` (a fixed array), so pass it by value — this both reads the
        // final per-band energy and sidesteps borrowing `self` immutably across the `&mut self` call.
        let band_energy = self.old_band_energy;
        self.celt_synthesis(
            x,
            &band_energy,
            start,
            eff_end,
            stream_channels,
            is_transient,
            lm,
            n,
            silence,
        );

        // ── Comb post-filter on out_syn (celt_decoder.c:1302-1325) ───────────────────────────────
        // out_syn[c] = decode_mem[c] + DECODE_BUFFER_SIZE - N; comb_filter is in place on the ring,
        // reaching back into the (preserved) history before out_syn for the pitch taps. The
        // post-filter parameters are per *frame*, not per channel, so both channels use the same.
        let out_syn = DECODE_BUFFER_SIZE - n;
        self.postfilter_period = self.postfilter_period.max(COMBFILTER_MINPERIOD);
        self.postfilter_period_old = self.postfilter_period_old.max(COMBFILTER_MINPERIOD);
        for c in 0..channels {
            // First comb_filter: out_syn[0..shortMdctSize], old→current params.
            comb_filter(
                &mut self.decode_mem[c],
                out_syn,
                SHORT_MDCT_SIZE,
                self.postfilter_period_old,
                self.postfilter_period,
                self.postfilter_gain_old,
                self.postfilter_gain,
                self.postfilter_tapset_old,
                self.postfilter_tapset,
                &WINDOW120,
                OVERLAP,
            );
            if lm != 0 {
                // Second comb_filter: out_syn[shortMdctSize .. N], current→new (next frame) params.
                // `postfilter_pitch` is passed raw (unclamped) exactly as libopus does —
                // `comb_filter` clamps `t1` to COMBFILTER_MINPERIOD internally (postfilter.rs).
                comb_filter(
                    &mut self.decode_mem[c],
                    out_syn + SHORT_MDCT_SIZE,
                    n - SHORT_MDCT_SIZE,
                    self.postfilter_period,
                    postfilter_pitch,
                    self.postfilter_gain,
                    postfilter_gain,
                    self.postfilter_tapset,
                    postfilter_tapset,
                    &WINDOW120,
                    OVERLAP,
                );
            }
        }
        // Roll the post-filter params old<-current<-new (celt_decoder.c:1314).
        self.postfilter_period_old = self.postfilter_period;
        self.postfilter_gain_old = self.postfilter_gain;
        self.postfilter_tapset_old = self.postfilter_tapset;
        self.postfilter_period = postfilter_pitch;
        self.postfilter_gain = postfilter_gain;
        self.postfilter_tapset = postfilter_tapset;
        if lm != 0 {
            self.postfilter_period_old = self.postfilter_period;
            self.postfilter_gain_old = self.postfilter_gain;
            self.postfilter_tapset_old = self.postfilter_tapset;
        }

        // ── Energy history update (celt_decoder.c:1327-1357) ─────────────────────────────────────
        // C==1: mirror band energy into the (duplicated) second channel slots, which is what makes
        // the fold at the top of the next frame a no-op. A stereo stream has real energy in both
        // halves, so the mirror must not run.
        if stream_channels == 1 {
            for i in 0..NB_BANDS {
                self.old_band_energy[NB_BANDS + i] = self.old_band_energy[i];
            }
        }
        if !is_transient {
            // oldLogE2 <- oldLogE <- oldBandE
            self.old_log_energy2 = self.old_log_energy;
            self.old_log_energy = self.old_band_energy;
        } else {
            // Transient: oldLogE = min(oldLogE, oldBandE).
            for (log_e, &band_e) in self
                .old_log_energy
                .iter_mut()
                .zip(self.old_band_energy.iter())
            {
                *log_e = log_e.min(band_e);
            }
        }
        // The noise floor may rise by at most 2.4 dB/s in normal running, but a DTX gap hands the
        // update packet the weight of every packet it stood in for (celt_decoder.c:1341-1343).
        let max_background_increase = 160.min(self.loss_duration + m as i32) as f32 * 0.001;
        for (background, &band_e) in self
            .background_log_energy
            .iter_mut()
            .zip(self.old_band_energy.iter())
        {
            *background = (*background + max_background_increase).min(band_e);
        }
        // "In case start or end were to change" (celt_decoder.c:1344-1357): bands outside the coded
        // range are reset, for both channel slots, so a later frame that widens the range does not
        // predict from stale energy. Not a no-op once `end` tracks the packet bandwidth.
        for channel in 0..2 {
            let base = channel * NB_BANDS;
            for i in (0..start).chain(end..NB_BANDS) {
                self.old_band_energy[base + i] = 0.0;
                self.old_log_energy[base + i] = ENERGY_RESET_DB;
                self.old_log_energy2[base + i] = ENERGY_RESET_DB;
            }
        }

        // Resync the cross-frame fold/anti-collapse PRNG seed to the range-coder register, so the
        // next frame's noise fold is seeded from the entropy state (celt_decoder.c:1358
        // `st->rng = dec->rng`). The in-frame fold/anti-collapse already consumed `self.rng` via
        // `quant_all_bands`/`anti_collapse`; this overwrite is what carries forward.
        self.rng = dec.rng();

        // ── De-emphasis → interleaved float PCM (celt_decoder.c:1360) ────────────────────────────
        self.write_output(pcm, n, output_samples);
        self.loss_duration = 0;
        self.prefilter_and_fold = false;
        Ok(output_samples)
    }

    /// De-emphasise the freshly synthesized ring tail into interleaved float PCM (libopus
    /// `deemphasis(out_syn, pcm, N, CC, st->downsample, mode->preemph, st->preemph_memD, accum)`).
    fn write_output(&mut self, pcm: &mut [f32], n: usize, output_samples: usize) {
        let out_syn = DECODE_BUFFER_SIZE - n;
        let channels = self.channels;
        let downsample = self.downsample;
        for c in 0..channels {
            deemphasis(
                &self.decode_mem[c][out_syn..out_syn + n],
                &mut pcm[..output_samples * channels],
                n,
                channels,
                c,
                PREEMPH[0],
                downsample,
                &mut self.preemph_mem[c],
            );
        }
    }

    /// CELT synthesis (libopus `celt_synthesis`, `celt_decoder.c:382`, float): per channel,
    /// denormalise the band coefficients into the frequency buffer, then run the inverse MDCT of
    /// each short block straight into that channel's decode ring at `out_syn`, where it overlap-adds
    /// with the preserved tail.
    ///
    /// Three arms, exactly as the C has them: the `C == CC` normal case, a **mono stream into a
    /// stereo output** (the same spectrum inverse-transformed into both rings) and a **stereo stream
    /// into a mono output** (the two spectra averaged before one inverse transform). The Opus layer
    /// reaches the latter two whenever a stream's TOC stereo flag disagrees with the caller's
    /// channel count.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn celt_synthesis(
        &mut self,
        x: &[f32],
        old_band_energy: &[f32],
        start: usize,
        eff_end: usize,
        stream_channels: usize,
        is_transient: bool,
        lm: usize,
        n: usize,
        silence: bool,
    ) {
        let m = 1usize << lm;
        // B / NB / shift (celt_decoder.c:404): transient → M short blocks of shortMdctSize at maxLM
        // shift; else one long block of N at (maxLM-LM).
        let (blocks, nb, shift) = if is_transient {
            (m, SHORT_MDCT_SIZE, MAX_LM)
        } else {
            (1usize, n, MAX_LM - lm)
        };

        // freq: one channel's signal MDCTs (celt_decoder.c:401), length N. Fixed stack scratch,
        // not a per-frame `Vec` — the hot path must not touch the allocator.
        let mut freq_buf = [0f32; MAX_FRAME_SAMPLES];
        let mut freq2_buf = [0f32; MAX_FRAME_SAMPLES];
        // out_syn[c] = decode_mem[c] + DECODE_BUFFER_SIZE - N (celt_decoder.c:1079).
        let out_syn = DECODE_BUFFER_SIZE - n;
        let channels = self.channels;

        if channels == 2 && stream_channels == 1 {
            // Copying a mono stream to two channels (celt_decoder.c:415). The C stashes a copy in
            // out_syn[1] only because its `clt_mdct_backward` destroys its input; ours takes `&[f32]`
            // and cannot, so the same spectrum feeds both inverse transforms directly.
            denormalise_bands(
                x,
                &mut freq_buf[..n],
                old_band_energy,
                start,
                eff_end,
                m,
                self.downsample,
                silence,
            );
            for c in 0..2 {
                for b in 0..blocks {
                    let dst = out_syn + nb * b;
                    clt_mdct_backward(
                        &self.mdct,
                        &freq_buf[b..],
                        &mut self.decode_mem[c][dst..],
                        &WINDOW120,
                        OVERLAP,
                        shift,
                        blocks,
                    );
                }
            }
        } else if channels == 1 && stream_channels == 2 {
            // Downmixing a stereo stream to mono (celt_decoder.c:428): average the two denormalised
            // spectra, then one inverse transform.
            denormalise_bands(
                x,
                &mut freq_buf[..n],
                old_band_energy,
                start,
                eff_end,
                m,
                self.downsample,
                silence,
            );
            denormalise_bands(
                &x[n..],
                &mut freq2_buf[..n],
                &old_band_energy[NB_BANDS..],
                start,
                eff_end,
                m,
                self.downsample,
                silence,
            );
            for i in 0..n {
                freq_buf[i] = 0.5 * freq_buf[i] + 0.5 * freq2_buf[i];
            }
            for b in 0..blocks {
                let dst = out_syn + nb * b;
                clt_mdct_backward(
                    &self.mdct,
                    &freq_buf[b..],
                    &mut self.decode_mem[0][dst..],
                    &WINDOW120,
                    OVERLAP,
                    shift,
                    blocks,
                );
            }
        } else {
            // Normal case, mono or stereo (celt_decoder.c:442).
            for c in 0..channels {
                denormalise_bands(
                    &x[c * n..],
                    &mut freq_buf[..n],
                    &old_band_energy[c * NB_BANDS..],
                    start,
                    eff_end,
                    m,
                    self.downsample,
                    silence,
                );
                // For each short block b (celt_decoder.c:447): clt_mdct_backward reads `freq` with
                // stride B starting at offset b, and writes its block at `out_syn + NB*b`. Each
                // backward MDCT writes `overlap/2 + (mode->mdct.n>>shift)/2` samples — i.e. its
                // `N/2` core PLUS the front overlap half — so its destination must extend
                // `overlap/2` past `out_syn + N`. We hand it the whole remaining ring tail
                // (`decode_mem[c][dst..]`, which has +overlap headroom by construction) and it
                // writes only the prefix it needs; the front `overlap/2` samples it touches are the
                // previous frame's preserved tail, giving the cross-frame overlap-add (mdct.c:371
                // mirror fold reads the existing `out[..overlap/2]`).
                for b in 0..blocks {
                    let dst = out_syn + nb * b;
                    clt_mdct_backward(
                        &self.mdct,
                        &freq_buf[b..],
                        &mut self.decode_mem[c][dst..],
                        &WINDOW120,
                        OVERLAP,
                        shift,
                        blocks,
                    );
                }
            }
        }
        // (libopus SATURATEs out_syn to SIG_SAT here; in the float build SATURATE is the identity
        //  outside the optional hardening guards, so we leave the samples untouched.)
    }
}

impl std::fmt::Debug for CeltDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CeltDecoder")
            .field("channels", &self.channels)
            .field("stream_channels", &self.stream_channels)
            .field("downsample", &self.downsample)
            .field("rng", &self.rng)
            .field("loss_duration", &self.loss_duration)
            .field("postfilter_period", &self.postfilter_period)
            .field("postfilter_gain", &self.postfilter_gain)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::RangeEncoder;

    /// Construct a CELT decoder and decode a synthetic, in-range CELT bitstream. Full `opus_compare`
    /// validation needs SILK too (the RFC 6716 vectors are full-Opus packets), so this is a
    /// **structural smoke test**: the orchestration must drive every sub-component in order without
    /// panicking / indexing out of bounds, and must produce finite, in-range i16 PCM.
    #[test]
    fn decodes_synthetic_celt_frame_without_panic() {
        let mut decoder = CeltDecoder::new().expect("build mono CELT decoder");

        // A deterministic, plausible "random" payload. quant_* read it as range-coded symbols + raw
        // bits; any byte stream is a valid (if musically meaningless) bitstream — the decoder must
        // decode-or-stay-finite, never panic. >1 byte so we hit the data path (not PLC).
        let mut frame = vec![0u8; 80];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8;
        }
        // Bias toward the non-silence path (the silence bit is `val < rng>>15`) so we exercise the
        // full pipeline; either way the decode must stay finite and produce `frame_size` samples.
        frame[0] &= 0x7f;

        for &frame_size in &[120usize, 240, 480, 960] {
            let mut decoder = CeltDecoder::new().expect("build");
            let mut pcm = vec![0i16; frame_size];
            let written = decoder
                .decode(&frame, &mut pcm, frame_size)
                .expect("synthetic frame decodes");
            assert_eq!(written, frame_size, "frame_size={frame_size}");
            // i16 is inherently in range; the real assertion is "no panic + we got samples".
            assert_eq!(pcm.len(), frame_size);
        }

        // Decode a couple of consecutive frames to exercise the cross-frame ring / energy history.
        let mut pcm = vec![0i16; 960];
        for _ in 0..3 {
            decoder
                .decode(&frame, &mut pcm, 960)
                .expect("consecutive frames decode");
        }
    }

    /// A genuinely silent frame (tell==1 then the 1/15 silence bit set) must short-circuit to all-zero
    /// energies and produce (near-)silent PCM without touching the rest of the pipeline unsafely.
    #[test]
    fn silent_frame_decodes_to_low_energy() {
        // Encode: first symbol is the silence bit (logp=15, value=true). The range coder's first
        // tell() is 1, so the decoder takes the `tell==1` branch and reads this bit.
        let mut buf = vec![0u8; 64];
        {
            let mut enc = RangeEncoder::new(&mut buf);
            enc.enc_bit_logp(true, 15); // silence = 1
            enc.done();
            assert!(!enc.error());
        }

        let mut decoder = CeltDecoder::new().expect("build");
        let mut pcm = vec![0i16; 960];
        let written = decoder
            .decode(&buf, &mut pcm, 960)
            .expect("silent frame decodes");
        assert_eq!(written, 960);
        // De-emphasis of an all-zero SIG frame is ~silent; allow a small transient from the 1-pole
        // memory but assert it doesn't blow up.
        assert!(
            pcm.iter().all(|&s| s.abs() < 4000),
            "silent frame should be quiet"
        );
    }

    /// RFC 6716 §4.3 / `opus_decoder.c:500-524`: the CELT `end` band is derived from the packet
    /// bandwidth. Decoding a narrower bandwidth as fullband reads bands the encoder never coded and
    /// desynchronises the range decoder.
    #[test]
    fn end_band_follows_packet_bandwidth() {
        assert_eq!(
            CeltDecoder::end_band_for_bandwidth(Bandwidth::Narrowband),
            13
        );
        assert_eq!(
            CeltDecoder::end_band_for_bandwidth(Bandwidth::Mediumband),
            17
        );
        assert_eq!(CeltDecoder::end_band_for_bandwidth(Bandwidth::Wideband), 17);
        assert_eq!(
            CeltDecoder::end_band_for_bandwidth(Bandwidth::SuperWideband),
            19
        );
        assert_eq!(
            CeltDecoder::end_band_for_bandwidth(Bandwidth::Fullband),
            NB_BANDS
        );
    }

    #[test]
    fn defaults_to_the_fullband_celt_only_range() {
        let decoder = CeltDecoder::new().expect("build");
        assert_eq!(decoder.start_band, 0);
        assert_eq!(decoder.end_band, NB_BANDS);
        assert_eq!(decoder.stream_channels(), 1);
        assert_eq!(decoder.downsample, 1);
    }

    #[test]
    fn set_band_range_accepts_every_real_configuration() {
        let mut decoder = CeltDecoder::new().expect("build");
        // Every CELT-only bandwidth, plus the Hybrid start band (SILK owns 0..17).
        for end in [13usize, 17, 19, NB_BANDS] {
            decoder.set_band_range(0, end).expect("celt-only range");
            assert_eq!(decoder.end_band, end);
        }
        decoder.set_band_range(17, NB_BANDS).expect("hybrid range");
        assert_eq!(decoder.start_band, 17);
        // Degenerate but legal: an empty range (start == end).
        decoder.set_band_range(5, 5).expect("empty range");
        // A SILK-only narrowband packet really does configure `start = 17, end = 13`: the mode
        // decides `start`, the bandwidth decides `end`, and libopus validates them independently.
        decoder
            .set_band_range(17, 13)
            .expect("silk narrowband range");
    }

    #[test]
    fn set_band_range_rejects_out_of_range() {
        let mut decoder = CeltDecoder::new().expect("build");
        assert!(decoder.set_band_range(0, NB_BANDS + 1).is_err());
        assert!(decoder.set_band_range(NB_BANDS, NB_BANDS).is_err());
        assert!(decoder.set_band_range(0, 0).is_err());
        // A rejected call must not have mutated the state.
        assert_eq!(decoder.start_band, 0);
        assert_eq!(decoder.end_band, NB_BANDS);
    }

    /// `start > end` codes no band; a decode in that state must error, not run the allocator's
    /// `end - start` arithmetic backwards.
    #[test]
    fn decode_rejects_an_empty_band_range() {
        let mut decoder = CeltDecoder::new().expect("build");
        decoder
            .set_band_range(17, 13)
            .expect("silk narrowband range");
        let frame = vec![0x5au8; 40];
        let mut pcm = vec![0f32; 960];
        assert!(decoder
            .decode_float(Some(&frame), &mut pcm, 960, None)
            .is_err());
    }

    /// The bitstream's channel count is settable independently of the caller's — that is what makes
    /// the up/downmix synthesis arms reachable (`celt_decoder.c:1489`).
    #[test]
    fn stream_channels_are_independent_of_the_api_channels() {
        let mut decoder = CeltDecoder::with_channels(2).expect("build stereo");
        assert_eq!(decoder.channels(), 2);
        assert_eq!(decoder.stream_channels(), 2);
        decoder.set_stream_channels(1).expect("mono stream");
        assert_eq!(decoder.channels(), 2, "API width is unchanged");
        assert_eq!(decoder.stream_channels(), 1);
        assert!(decoder.set_stream_channels(0).is_err());
        assert!(decoder.set_stream_channels(3).is_err());
        // `disable_inv` follows the API channel count, not the stream's (`celt_decoder.c:227`).
        assert!(!decoder.disable_inv);
        assert!(CeltDecoder::new().expect("mono").disable_inv);
    }

    /// A mono stream decoded into a stereo output must fill both channels identically, and a stereo
    /// stream decoded into a mono output must produce a single channel — the two `celt_synthesis`
    /// arms the CELT-only path never reaches.
    #[test]
    fn mono_stream_into_a_stereo_output_duplicates_the_channel() {
        let mut frame = vec![0u8; 80];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8;
        }
        frame[0] &= 0x7f;

        let mut decoder = CeltDecoder::with_channels(2).expect("build stereo");
        decoder.set_stream_channels(1).expect("mono stream");
        let mut pcm = vec![0f32; 960 * 2];
        let written = decoder
            .decode_float(Some(&frame), &mut pcm, 960, None)
            .expect("decode");
        assert_eq!(written, 960);
        for i in 0..960 {
            assert_eq!(
                pcm[2 * i],
                pcm[2 * i + 1],
                "sample {i}: both channels come from the same spectrum"
            );
        }

        // Stereo stream, mono output: one channel out, and it must not be all zeros.
        let mut decoder = CeltDecoder::new().expect("build mono");
        decoder.set_stream_channels(2).expect("stereo stream");
        let mut pcm = vec![0f32; 960];
        let written = decoder
            .decode_float(Some(&frame), &mut pcm, 960, None)
            .expect("decode");
        assert_eq!(written, 960);
        assert!(pcm.iter().any(|&s| s != 0.0), "downmix produced silence");
    }

    /// Bands outside the coded range must be reset after each frame (`celt_decoder.c:1344-1357`), in
    /// both channel slots, so widening the range later cannot predict from stale energy.
    #[test]
    fn decode_resets_energy_outside_the_coded_range() {
        let mut decoder = CeltDecoder::new().expect("build");
        // Seed every band with a value that is neither 0 nor the reset floor.
        decoder.old_band_energy = [7.0; 2 * NB_BANDS];
        decoder.old_log_energy = [7.0; 2 * NB_BANDS];
        decoder.old_log_energy2 = [7.0; 2 * NB_BANDS];
        decoder.set_band_range(0, 13).expect("narrowband range");

        let mut frame = vec![0u8; 60];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8;
        }
        frame[0] &= 0x7f; // bias away from the silence bit
        let mut pcm = vec![0i16; 960];
        decoder.decode(&frame, &mut pcm, 960).expect("decode");

        for channel in 0..2 {
            for band in 13..NB_BANDS {
                let i = channel * NB_BANDS + band;
                assert_eq!(
                    decoder.old_band_energy[i], 0.0,
                    "band {band} (channel {channel}) above end must be zeroed"
                );
                assert_eq!(decoder.old_log_energy[i], ENERGY_RESET_DB);
                assert_eq!(decoder.old_log_energy2[i], ENERGY_RESET_DB);
            }
        }
    }

    /// A decoder built for a lower API rate keeps every 48 kHz `LM` but returns `N/downsample`
    /// samples (`celt_decoder.c:1031,1368`).
    #[test]
    fn a_downsampling_decoder_returns_fewer_samples() {
        let mut frame = vec![0u8; 60];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8;
        }
        frame[0] &= 0x7f;
        for (rate, factor) in [(48_000u32, 1usize), (24_000, 2), (16_000, 3), (8_000, 6)] {
            let mut decoder = CeltDecoder::with_rate_and_channels(rate, 1).expect("build");
            assert_eq!(decoder.downsample, factor);
            let requested = 960 / factor;
            let mut pcm = vec![0f32; requested];
            let written = decoder
                .decode_float(Some(&frame), &mut pcm, requested, None)
                .expect("decode");
            assert_eq!(written, requested, "rate {rate}");
        }
        assert!(CeltDecoder::with_rate_and_channels(44_100, 1).is_err());
    }

    #[test]
    fn rejects_bad_frame_size() {
        let mut decoder = CeltDecoder::new().expect("build");
        let frame = vec![0x12u8; 40];
        let mut pcm = vec![0i16; 200];
        // 200 samples is not 120/240/480/960.
        let err = decoder.decode(&frame, &mut pcm, 200).unwrap_err();
        assert!(matches!(err, CodecError::BadFrameSize { .. }));
    }

    #[test]
    fn rejects_too_short_packet() {
        let mut decoder = CeltDecoder::new().expect("build");
        let mut pcm = vec![0i16; 960];
        // <=1 byte is the PLC/DTX path, which `decode_float` owns — `decode` rejects it.
        assert!(decoder.decode(&[0x00], &mut pcm, 960).is_err());
        assert!(decoder.decode(&[], &mut pcm, 960).is_err());
    }

    #[test]
    fn rejects_undersized_output() {
        let mut decoder = CeltDecoder::new().expect("build");
        let frame = vec![0x34u8; 40];
        let mut pcm = vec![0i16; 100]; // < 960
        let err = decoder.decode(&frame, &mut pcm, 960).unwrap_err();
        assert!(matches!(err, CodecError::OutputTooSmall { .. }));
    }

    /// `OPUS_RESET_STATE` (`celt_decoder.c:1514`) must return every carried-over field to the fresh
    /// state, including the `-28 dB` energy floors and `skip_plc`.
    #[test]
    fn reset_state_returns_the_decoder_to_the_fresh_state() {
        let mut decoder = CeltDecoder::with_channels(2).expect("build");
        let mut frame = vec![0u8; 60];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8;
        }
        frame[0] &= 0x7f;
        let mut pcm = vec![0i16; 960 * 2];
        decoder.decode(&frame, &mut pcm, 960).expect("decode");
        assert_ne!(decoder.rng, 0);

        decoder.reset_state();
        assert_eq!(decoder.rng, 0);
        assert_eq!(decoder.loss_duration, 0);
        assert!(decoder.skip_plc);
        assert!(!decoder.prefilter_and_fold);
        assert!(decoder.decode_mem[0].iter().all(|&s| s == 0.0));
        assert!(decoder.decode_mem[1].iter().all(|&s| s == 0.0));
        assert!(decoder.old_band_energy.iter().all(|&e| e == 0.0));
        assert!(decoder.old_log_energy.iter().all(|&e| e == ENERGY_RESET_DB));
        assert!(decoder
            .old_log_energy2
            .iter()
            .all(|&e| e == ENERGY_RESET_DB));
        assert_eq!(decoder.preemph_mem, [0.0, 0.0]);
        // Configuration survives a state reset (the C keeps everything before DECODER_RESET_START).
        assert_eq!(decoder.channels(), 2);
    }
}
