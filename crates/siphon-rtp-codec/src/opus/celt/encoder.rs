//! CELT-only **mono float** encode orchestration (RFC 6716 §4.3; libopus `celt_encoder.c`
//! `celt_encode_with_ec`, `#ifndef FIXED_POINT`).
//!
//! The mirror of [`CeltDecoder`](crate::opus::celt::decoder::CeltDecoder): every sub-component —
//! pre-emphasis, prefilter/pitch, transient analysis, forward MDCT, band energy, coarse/fine energy
//! quantisation, tf and spreading decisions, dynalloc, the shared bit allocator, the shared band/PVQ
//! quantiser — lives in its own module, and this one drives them in the exact order libopus does
//! with the exact 1/8-bit (`BITRES`) budget arguments, so the symbol sequence is what a decoder
//! reads.
//!
//! Scope, stated plainly: **CELT-only, mono or stereo, no `ENABLE_QEXT`, no surround energy mask,
//! no `AnalysisInfo` tonality estimator, no LFE mode.** Those are separate libopus features (the
//! last two live above CELT, in `opus_encoder.c`/`analysis.c`) and are absent rather than
//! half-wired. Stereo is complete: the `stereo_analysis` L/R-vs-mid/side decision, the rate-driven
//! intensity threshold, dual stereo, and the theta rate-distortion trial at complexity ≥ 8.
//!
//! Line references cite `celt/celt_encoder.c` from the libopus tree this was ported against.

use crate::opus::celt::analysis::{
    alloc_trim_analysis, dynalloc_analysis, patch_transient_decision, spreading_decision,
    stereo_analysis, tf_analysis, transient_analysis,
};
use crate::opus::celt::band_analysis::{
    amp2_log2, celt_preemphasis, compute_band_energies, normalise_bands,
};
use crate::opus::celt::band_coder::{quant_all_bands, StereoBands, ThetaRdo};
use crate::opus::celt::energy::{quant_coarse_energy, quant_energy_finalise, quant_fine_energy};
use crate::opus::celt::mdct::{clt_mdct_forward, MdctLookup};
use crate::opus::celt::pitch::{pitch_downsample, pitch_search, remove_doubling};
use crate::opus::celt::postfilter::{
    comb_filter_out_of_place, COMBFILTER_MAXPERIOD, COMBFILTER_MINPERIOD,
};
use crate::opus::celt::rate::{clt_compute_allocation, init_caps};
use crate::opus::celt::tables::{
    BITRES, E_BANDS, MAX_LM, NB_BANDS, NB_SHORT_MDCTS, OVERLAP, PREEMPH, SHORT_MDCT_SIZE,
    SPREAD_AGGRESSIVE, SPREAD_ICDF, SPREAD_NONE, SPREAD_NORMAL, TAPSET_ICDF, TRIM_ICDF, WINDOW120,
};
use crate::opus::celt::tf::tf_encode;
use crate::opus::packet::Bandwidth;
use crate::opus::range_coder::RangeEncoder;
use crate::CodecError;

/// Largest channel count (RFC 6716 is mono or stereo).
const MAX_CHANNELS: usize = 2;
/// Base MDCT length for the 48 kHz mode (`mode->mdct.n`); see [`MdctLookup`].
const MDCT_BASE_LEN: usize = 1920;
/// Largest CELT frame in samples: `shortMdctSize << MAX_LM` = 960 (20 ms at 48 kHz).
const MAX_FRAME_SAMPLES: usize = SHORT_MDCT_SIZE << MAX_LM;
/// Pre-emphasis input buffer length: `N + overlap` at the largest frame.
const MAX_IN_LEN: usize = MAX_FRAME_SAMPLES + OVERLAP;
/// `-28 dB` in the log2 energy domain, the silent-frame / out-of-range reset value.
const ENERGY_RESET_DB: f32 = -28.0;
/// Largest Opus frame payload (RFC 6716 §3.4).
const MAX_PACKET_BYTES: usize = 1275;
/// Sample rate of the CELT mode (`mode->Fs`).
const SAMPLE_RATE: i32 = 48_000;

/// What the SILK layer decided for this frame, which the hybrid branches of the CELT encoder read
/// (libopus `SILKInfo`, `celt/celt.h`; set through `CELT_SET_SILK_INFO`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SilkInfo {
    /// `silk_mode.signalType` — 0 inactive, 1 unvoiced, 2 voiced. The low-rate hybrid tf override
    /// deliberately does *not* fire on voiced frames (`celt_encoder.c:1932`).
    pub signal_type: i32,
    /// `silk_mode.offset` — the quantisation offset SILK used. Below 100 the frame is tonal and the
    /// high band is given more bits; above 100 it is noisy and given fewer
    /// (`celt_encoder.c:2117-2119`).
    pub offset: i32,
}

/// Rate-control mode for the CELT encoder (libopus `st->vbr` / `st->constrained_vbr`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RateControl {
    /// Constant bitrate: every frame is padded to exactly the target size.
    #[default]
    ConstantBitrate,
    /// Constrained VBR: frames vary but a reservoir keeps the running average at the target.
    ConstrainedVbr,
    /// Unconstrained VBR: the frame size follows what the content needs.
    Vbr,
}

/// Persistent CELT encoder state (libopus `struct OpusCustomEncoder`, `celt_encoder.c:58`, mono
/// float — the `ENCODER_RESET_START` block plus the config fields we support).
pub struct CeltEncoder {
    /// Allocated channels, 1 or 2 (`st->channels`, the C's `CC`) — the width of the PCM handed to
    /// [`CeltEncoder::encode`] and of every per-channel buffer below.
    channels: usize,
    /// **Coded** channels, 1 or 2 (`st->stream_channels`, the C's `C`). Normally equal to
    /// [`CeltEncoder::channels`]; the Opus layer drops it to 1 mid-stream when the rate no longer
    /// justifies two, and then the two MDCTs are averaged into one rather than the right channel
    /// being thrown away (`compute_mdcts`, `celt_encoder.c:489-493`).
    stream_channels: usize,
    /// `st->silk_info` — the SILK layer's signal type and quantisation offset for this frame, set by
    /// the Opus layer in hybrid mode (`CELT_SET_SILK_INFO`). Genuinely wired: both move the
    /// hybrid-only tf and VBR-target branches.
    silk_info: SilkInfo,
    /// `st->disable_pf` — set by `CELT_SET_PREDICTION(0..1)`; the Opus layer turns the prefilter off
    /// for a redundancy frame, which must be decodable without the previous frame's comb state.
    disable_pf: bool,
    /// `st->upsample` = `48000 / Fs` (`resampling_factor`, `celt/modes.c`). CELT has exactly one
    /// mode, at 48 kHz; a lower API rate is carried by zero-stuffing the input and clearing the
    /// spectrum above the original Nyquist, not by a second MDCT size.
    upsample: usize,
    /// Forward-MDCT / FFT lookup for the 48 kHz mode (`mode->mdct`, base length 1920, shifts 0..=3).
    mdct: MdctLookup,
    /// Target bitrate in bit/s (`st->bitrate`).
    bitrate: i32,
    /// Rate-control mode (`st->vbr` + `st->constrained_vbr`).
    rate_control: RateControl,
    /// Analysis depth, 0..=10 (`st->complexity`). Genuinely wired: `>= 1` enables transient
    /// analysis, `>= 2` the tf Viterbi, `>= 3` the spreading estimator, `>= 4` the two-pass
    /// coarse-energy trial, `>= 5` the prefilter and the transient patch, `>= 8` the second MDCT.
    complexity: i32,
    /// Assumed packet-loss rate in percent (`st->loss_rate`); biases toward intra energy and away
    /// from the prefilter, both of which make a lost frame cheaper.
    loss_rate: i32,
    /// Effective input bit depth (`st->lsb_depth`), which sets the dynalloc noise floor.
    lsb_depth: i32,
    /// Force intra-frame energy coding on the next frame (`st->force_intra`).
    force_intra: bool,
    /// Clamp the input to full scale before pre-emphasis (`st->clip`).
    clip: bool,

    // ── Reset-on-state-reset fields (`ENCODER_RESET_START`) ─────────────────────────────────────
    /// Range-coder state carried across frames (`st->rng`) — also the fold PRNG seed.
    rng: u32,
    /// Last frame's spreading decision (`st->spread_decision`), the hysteresis input.
    spread_decision: u32,
    /// Running intra-refresh distortion accumulator (`st->delayedIntra`).
    delayed_intra: f32,
    /// Running tonality average for the spreading hysteresis (`st->tonal_average`).
    tonal_average: i32,
    /// Coded-band count of the previous frame (`st->lastCodedBands`), the allocator's `prev`.
    last_coded_bands: usize,
    /// Running high-frequency average for the tapset decision (`st->hf_average`).
    hf_average: i32,
    /// Post-filter tapset decision (`st->tapset_decision`).
    tapset_decision: usize,
    /// Prefilter pitch period, gain and tapset of the previous frame.
    prefilter_period: usize,
    prefilter_gain: f32,
    prefilter_tapset: usize,
    /// Consecutive transient count (`st->consec_transient`); gates anti-collapse.
    consec_transient: i32,
    /// Pre-emphasis 1-pole memory (`st->preemph_memE`), per channel, persists across frames.
    preemph_mem: [f32; MAX_CHANNELS],
    /// Constrained-VBR reservoir / drift / offset and frame count (`st->vbr_*`).
    vbr_reservoir: i32,
    vbr_drift: i32,
    vbr_offset: i32,
    vbr_count: i32,
    /// Peak sample of the previous frame's overlap region (`st->overlap_max`).
    overlap_max: f32,
    /// Running estimate of how many bits a correlated stereo pair saves (`st->stereo_saving`),
    /// produced by [`alloc_trim_analysis`] and consumed by the VBR target. Mono never writes it.
    stereo_saving: f32,
    /// First band coded with intensity stereo (`st->intensity`), chosen by rate with hysteresis.
    intensity: usize,
    /// Running spectral average for the temporal-VBR term (`st->spec_avg`).
    spec_avg: f32,
    /// Previous frame's per-band log2 energy (`oldBandE`), `2*NB_BANDS`.
    old_band_energy: [f32; 2 * NB_BANDS],
    /// Energy one and two frames back (`oldLogE`, `oldLogE2`); reset to `-28 dB`.
    old_log_energy: [f32; 2 * NB_BANDS],
    old_log_energy2: [f32; 2 * NB_BANDS],
    /// Residual coarse-energy error per band (`energyError`), used to bias the next frame.
    energy_error: [f32; 2 * NB_BANDS],
    /// The overlap tail of the pre-emphasised input (`st->in_mem`), per channel.
    in_mem: [[f32; OVERLAP]; MAX_CHANNELS],
    /// Prefilter history (`prefilter_mem`), `COMBFILTER_MAXPERIOD` samples per channel.
    prefilter_mem: [[f32; COMBFILTER_MAXPERIOD]; MAX_CHANNELS],
    /// Caller-owned scratch for the stereo theta rate-distortion trial (`bands.c:1409`), kept here
    /// so the mono and decode paths never pay for it.
    theta_rdo: ThetaRdo,
    /// First coded band (`st->start`) — 0 for CELT-only.
    start_band: usize,
    /// One past the last coded band (`st->end`), from the target bandwidth.
    end_band: usize,
}

impl CeltEncoder {
    /// Construct a fresh **mono** CELT encoder in the reset state.
    pub fn new() -> Result<Self, CodecError> {
        Self::with_channels(1)
    }

    /// Construct a fresh CELT encoder for 1 or 2 channels, in the reset state (libopus
    /// `opus_custom_encoder_init_arch` + `OPUS_RESET_STATE`, `celt_encoder.c:166`).
    pub fn with_channels(channels: usize) -> Result<Self, CodecError> {
        if channels == 0 || channels > MAX_CHANNELS {
            return Err(CodecError::Unsupported(
                "celt: channel count must be 1 or 2",
            ));
        }
        let mdct = MdctLookup::new(MDCT_BASE_LEN, MAX_LM)
            .map_err(|_| CodecError::Unsupported("celt: failed to build 48 kHz MDCT lookup"))?;
        Ok(Self {
            channels,
            stream_channels: channels,
            silk_info: SilkInfo::default(),
            disable_pf: false,
            upsample: 1,
            mdct,
            // `OPUS_BITRATE_MAX` in libopus; the caller normally sets a real target.
            bitrate: -1,
            rate_control: RateControl::ConstantBitrate,
            complexity: 5,
            loss_rate: 0,
            lsb_depth: 24,
            force_intra: false,
            clip: true,
            rng: 0,
            spread_decision: SPREAD_NORMAL,
            delayed_intra: 1.0,
            tonal_average: 256,
            last_coded_bands: 0,
            hf_average: 0,
            tapset_decision: 0,
            prefilter_period: 0,
            prefilter_gain: 0.0,
            prefilter_tapset: 0,
            consec_transient: 0,
            preemph_mem: [0.0; MAX_CHANNELS],
            vbr_reservoir: 0,
            vbr_drift: 0,
            vbr_offset: 0,
            vbr_count: 0,
            overlap_max: 0.0,
            stereo_saving: 0.0,
            intensity: 0,
            spec_avg: 0.0,
            old_band_energy: [0.0; 2 * NB_BANDS],
            old_log_energy: [ENERGY_RESET_DB; 2 * NB_BANDS],
            old_log_energy2: [ENERGY_RESET_DB; 2 * NB_BANDS],
            energy_error: [0.0; 2 * NB_BANDS],
            in_mem: [[0.0; OVERLAP]; MAX_CHANNELS],
            prefilter_mem: [[0.0; COMBFILTER_MAXPERIOD]; MAX_CHANNELS],
            theta_rdo: ThetaRdo::new(),
            start_band: 0,
            end_band: NB_BANDS,
        })
    }

    /// Set the target bitrate in bit/s. A negative value means "unlimited" (libopus
    /// `OPUS_BITRATE_MAX`), i.e. fill whatever the caller's buffer allows.
    pub fn set_bitrate(&mut self, bitrate: i32) {
        self.bitrate = bitrate;
    }

    /// Select CBR, constrained VBR or unconstrained VBR (`OPUS_SET_VBR` +
    /// `OPUS_SET_VBR_CONSTRAINT`).
    pub fn set_rate_control(&mut self, rate_control: RateControl) {
        self.rate_control = rate_control;
    }

    /// Set the analysis depth, 0..=10 (`OPUS_SET_COMPLEXITY`). See the field docs for exactly which
    /// stages each threshold turns on.
    pub fn set_complexity(&mut self, complexity: i32) -> Result<(), CodecError> {
        if !(0..=10).contains(&complexity) {
            return Err(CodecError::Unsupported("celt: complexity must be 0..=10"));
        }
        self.complexity = complexity;
        Ok(())
    }

    /// Set the expected packet-loss rate in percent (`OPUS_SET_PACKET_LOSS_PERC`): it biases the
    /// coarse-energy coder toward intra frames and scales the prefilter gain down (a prefiltered
    /// frame is harder to conceal).
    pub fn set_loss_rate(&mut self, percent: i32) -> Result<(), CodecError> {
        if !(0..=100).contains(&percent) {
            return Err(CodecError::Unsupported("celt: loss rate must be 0..=100"));
        }
        self.loss_rate = percent;
        Ok(())
    }

    /// Set the input's effective bit depth, 8..=24 (`OPUS_SET_LSB_DEPTH`); it raises the dynalloc
    /// noise floor so bits are not spent below the input's own noise.
    pub fn set_lsb_depth(&mut self, depth: i32) -> Result<(), CodecError> {
        if !(8..=24).contains(&depth) {
            return Err(CodecError::Unsupported("celt: lsb depth must be 8..=24"));
        }
        self.lsb_depth = depth;
        Ok(())
    }

    /// Always code band energy without inter-frame prediction (libopus `st->force_intra`), so every
    /// frame is decodable on its own. Persistent, like the reference field — call it again with
    /// `false` to go back to predicted energy.
    pub fn set_force_intra(&mut self, force: bool) {
        self.force_intra = force;
    }

    /// Set the coded band range (libopus `CELT_SET_START_BAND` / `CELT_SET_END_BAND`). `end` must
    /// come from [`Self::end_band_for_bandwidth`]; a decoder derives it from the packet's TOC, so an
    /// encoder that codes a different count desynchronises it.
    pub fn set_band_range(&mut self, start: usize, end: usize) -> Result<(), CodecError> {
        if start > end || end > NB_BANDS {
            return Err(CodecError::Unsupported(
                "celt: band range must satisfy start <= end <= 21",
            ));
        }
        self.start_band = start;
        self.end_band = end;
        Ok(())
    }

    /// The CELT `end` band for a target bandwidth (`opus_decoder.c:498-523`) — 13/17/19/21 for
    /// NB/MB-WB/SWB/FB. The same mapping the decoder uses.
    #[must_use]
    pub fn end_band_for_bandwidth(bandwidth: Bandwidth) -> usize {
        match bandwidth {
            Bandwidth::Narrowband => 13,
            Bandwidth::Mediumband | Bandwidth::Wideband => 17,
            Bandwidth::SuperWideband => 19,
            Bandwidth::Fullband => NB_BANDS,
        }
    }

    /// The range coder's final range after the last encoded frame (libopus `OPUS_GET_FINAL_RANGE`).
    /// A conforming decoder must end the same packet on exactly this value.
    #[must_use]
    pub fn final_range(&self) -> u32 {
        self.rng
    }

    /// Allocated channels, 1 or 2. `encode`'s PCM is interleaved to this width.
    #[must_use]
    pub fn channels(&self) -> usize {
        self.channels
    }

    /// Set the **coded** channel count (libopus `CELT_SET_CHANNELS`), 1 or 2 and never more than
    /// [`CeltEncoder::channels`].
    ///
    /// Dropping a stereo encoder to one coded channel does not discard the right channel: both are
    /// still pre-emphasised, prefiltered and transformed, and the two spectra are averaged
    /// (`compute_mdcts`, `celt_encoder.c:489-493`). That is why the state stays two channels wide
    /// and the switch is free of a reset.
    pub fn set_stream_channels(&mut self, channels: usize) -> Result<(), CodecError> {
        if channels == 0 || channels > self.channels {
            return Err(CodecError::Unsupported(
                "celt: coded channels must be 1..=channels",
            ));
        }
        self.stream_channels = channels;
        Ok(())
    }

    /// Coded channels, 1 or 2 (`st->stream_channels`).
    #[must_use]
    pub fn stream_channels(&self) -> usize {
        self.stream_channels
    }

    /// `CELT_SET_PREDICTION` (`celt_encoder.c`, `CELT_SET_PREDICTION_REQUEST`), 0..=2.
    ///
    /// 0 disables both the prefilter and inter-frame energy prediction, so the frame stands alone —
    /// which is what a redundancy frame bridging a mode switch has to do. 1 keeps intra prediction
    /// but drops the prefilter; 2 is the default, everything on.
    pub fn set_prediction(&mut self, prediction: i32) -> Result<(), CodecError> {
        if !(0..=2).contains(&prediction) {
            return Err(CodecError::Unsupported("celt: prediction must be 0..=2"));
        }
        self.disable_pf = prediction <= 1;
        self.force_intra = prediction == 0;
        Ok(())
    }

    /// Set the API sample rate, 8/12/16/24/48 kHz (`celt_encoder_init`'s `Fs`).
    ///
    /// It selects `upsample = 48000 / Fs`, which is the *only* thing a lower rate changes: the MDCT,
    /// the band layout and the bitstream all stay the 48 kHz mode's, and the input is zero-stuffed
    /// with the images cleared. `frame_size` in [`CeltEncoder::encode`] stays the count at the API
    /// rate.
    pub fn set_sample_rate(&mut self, sample_rate_hz: u32) -> Result<(), CodecError> {
        self.upsample = match sample_rate_hz {
            48_000 => 1,
            24_000 => 2,
            16_000 => 3,
            12_000 => 4,
            8_000 => 6,
            _ => {
                return Err(CodecError::Unsupported(
                    "celt: sample rate must be 8, 12, 16, 24 or 48 kHz",
                ))
            }
        };
        Ok(())
    }

    /// `CELT_SET_SILK_INFO` — what the SILK layer decided for this frame. Only read in hybrid mode
    /// (`start != 0`), where it moves the tf resolution and the VBR target.
    pub fn set_silk_info(&mut self, info: SilkInfo) {
        self.silk_info = info;
    }

    /// Reset every field `OPUS_RESET_STATE` resets, keeping the configuration
    /// (`celt_encoder.c:166`, the `ENCODER_RESET_START` block).
    ///
    /// The Opus layer needs this on a mode switch: a CELT frame that follows a stretch of SILK has
    /// no valid energy history, prefilter memory or overlap tail to predict from.
    pub fn reset_state(&mut self) {
        self.rng = 0;
        self.spread_decision = SPREAD_NORMAL;
        self.delayed_intra = 1.0;
        self.tonal_average = 256;
        self.last_coded_bands = 0;
        self.hf_average = 0;
        self.tapset_decision = 0;
        self.prefilter_period = 0;
        self.prefilter_gain = 0.0;
        self.prefilter_tapset = 0;
        self.consec_transient = 0;
        self.preemph_mem = [0.0; MAX_CHANNELS];
        self.vbr_reservoir = 0;
        self.vbr_drift = 0;
        self.vbr_offset = 0;
        self.vbr_count = 0;
        self.overlap_max = 0.0;
        self.stereo_saving = 0.0;
        self.intensity = 0;
        self.spec_avg = 0.0;
        self.old_band_energy = [0.0; 2 * NB_BANDS];
        self.old_log_energy = [ENERGY_RESET_DB; 2 * NB_BANDS];
        self.old_log_energy2 = [ENERGY_RESET_DB; 2 * NB_BANDS];
        self.energy_error = [0.0; 2 * NB_BANDS];
        self.in_mem = [[0.0; OVERLAP]; MAX_CHANNELS];
        self.prefilter_mem = [[0.0; COMBFILTER_MAXPERIOD]; MAX_CHANNELS];
    }

    /// Encode one **CELT-only** frame, mono or stereo, into its own packet.
    ///
    /// `pcm` holds `frame_size * channels` **interleaved** samples nominally in `[-1, 1)` — the
    /// crate's channel contract; `frame_size` is the per-channel count and must be 120/240/480/960
    /// (2.5/5/10/20 ms at 48 kHz). `output` is the caller-owned payload buffer — its length is the
    /// hard ceiling on the packet (`max_payload`), clamped to 1275 bytes. Returns the number of
    /// bytes written.
    ///
    /// For the hybrid case, where SILK has already written the low band into a shared range coder,
    /// use [`CeltEncoder::encode_with_range_encoder`] instead.
    pub fn encode(
        &mut self,
        pcm: &[f32],
        frame_size: usize,
        output: &mut [u8],
    ) -> Result<usize, CodecError> {
        // libopus rejects a target under 2 bytes outright (celt_encoder.c:1513).
        if output.len() < 2 {
            return Err(CodecError::OutputTooSmall {
                needed: 2,
                have: output.len(),
            });
        }
        // "Can't produce more than 1275 output bytes" (celt_encoder.c:1574).
        let capacity = output.len().min(MAX_PACKET_BYTES);
        let mut encoder_buffer = [0u8; MAX_PACKET_BYTES];
        let mut enc = RangeEncoder::new(&mut encoder_buffer[..capacity]);
        // The C initialises the range encoder *after* the CBR clamp and shrinks it before that
        // (`celt_encoder.c:1596` on a still-null `enc`); initialising at the full capacity and
        // letting the body shrink is equivalent — shrinking a coder that has emitted nothing only
        // moves its storage bound — and it is the only form that works for the shared-coder case.
        let written = self.encode_into(pcm, frame_size, &mut enc, capacity as i32)?;
        enc.done();
        if enc.error() {
            return Err(CodecError::Unsupported(
                "celt: range encoder overflowed the output buffer",
            ));
        }
        output[..written].copy_from_slice(&encoder_buffer[..written]);
        Ok(written)
    }

    /// Encode one frame into a range coder the caller owns — the **hybrid** entry point
    /// (`celt_encode_with_ec` with a non-null `enc`, `celt_encoder.c:1431`).
    ///
    /// The Opus layer calls this after `SilkEncoder::encode` has written the low band into the same
    /// coder, with [`CeltEncoder::set_band_range`]`(17, …)` so CELT codes only the high band. Two
    /// things follow from the coder being shared and neither is optional:
    ///
    /// * The silence flag is **not** written (`celt_encoder.c:1656`) — it is the first symbol of a
    ///   CELT-only frame and a decoder in hybrid mode does not read one.
    /// * The budget is `nb_compressed_bytes` *total*, of which SILK has already spent
    ///   `(tell + 4) / 8`; every rate decision below works from the difference.
    ///
    /// The caller is responsible for [`RangeEncoder::done`]. Returns the packet size CELT settled
    /// on, which VBR may have shrunk below `nb_compressed_bytes`.
    pub fn encode_with_range_encoder(
        &mut self,
        pcm: &[f32],
        frame_size: usize,
        enc: &mut RangeEncoder<'_>,
        nb_compressed_bytes: i32,
    ) -> Result<usize, CodecError> {
        if nb_compressed_bytes < 2 {
            return Err(CodecError::OutputTooSmall {
                needed: 2,
                have: nb_compressed_bytes.max(0) as usize,
            });
        }
        self.encode_into(pcm, frame_size, enc, nb_compressed_bytes)
    }

    /// The body both entry points share (`celt_encode_with_ec`).
    #[allow(clippy::too_many_lines)]
    // The per-band loops index parallel per-band arrays with the reference's own `i`; rewriting each
    // as an iterator would obscure which `celt_encoder.c` loop it corresponds to.
    #[allow(clippy::needless_range_loop)]
    fn encode_into(
        &mut self,
        pcm: &[f32],
        frame_size: usize,
        enc: &mut RangeEncoder<'_>,
        packet_bytes: i32,
    ) -> Result<usize, CodecError> {
        // ── Frame size → LM (celt_encoder.c:1519-1527) ───────────────────────────────────────────
        // `frame_size` is the count at the API rate; the MDCT always runs at 48 kHz.
        let api_frame_size = frame_size;
        let frame_size = frame_size * self.upsample;
        let lm = (0..=MAX_LM)
            .find(|&candidate| (SHORT_MDCT_SIZE << candidate) == frame_size)
            .ok_or(CodecError::BadFrameSize {
                expected: MAX_FRAME_SAMPLES,
                got: frame_size,
            })?;
        let m = 1usize << lm;
        let n = m * SHORT_MDCT_SIZE;
        // `CC` — allocated channels, the width of `pcm` and of every per-channel buffer.
        let cc = self.channels;
        // `C` — coded channels, which the entropy coding and the band analysis work in.
        let channels = self.stream_channels;
        if pcm.len() < api_frame_size * cc {
            return Err(CodecError::OutputTooSmall {
                needed: api_frame_size * cc,
                have: pcm.len(),
            });
        }

        let start = self.start_band;
        let end = self.end_band;
        let eff_end = end.min(NB_BANDS);
        // `hybrid` (celt_encoder.c:1511): SILK owns everything below band 17.
        let hybrid = start != 0;

        // What the caller's range coder has already spent (celt_encoder.c:1537-1545). For a fresh
        // coder `tell` is 1 and `nb_filled_bytes` is 0, which is exactly the C's `enc == NULL` arm.
        let tell0_frac = enc.tell_frac() as i32;
        let tell_at_entry = enc.tell();
        let nb_filled_bytes = (tell_at_entry + 4) >> 3;

        let mut nb_compressed_bytes = packet_bytes.min(MAX_PACKET_BYTES as i32);
        let mut nb_available_bytes = nb_compressed_bytes - nb_filled_bytes;

        // ── Rate control: target size and the VBR budget (celt_encoder.c:1577) ───────────────────
        let vbr = self.rate_control != RateControl::ConstantBitrate;
        let constrained_vbr = self.rate_control == RateControl::ConstrainedVbr;
        let mut vbr_rate = 0i32;
        let mut effective_bytes;
        if vbr && self.bitrate > 0 {
            let den = SAMPLE_RATE >> BITRES;
            vbr_rate = (self.bitrate * frame_size as i32 + (den >> 1)) / den;
            effective_bytes = vbr_rate >> (3 + BITRES);
        } else {
            if self.bitrate > 0 {
                // CBR: the packet is exactly the target size for this frame duration, plus whatever
                // the shared coder has already spent (celt_encoder.c:1589-1591).
                let mut tmp = self.bitrate * frame_size as i32;
                if tell_at_entry > 1 {
                    tmp += tell_at_entry * SAMPLE_RATE;
                }
                nb_compressed_bytes = nb_compressed_bytes
                    .min((tmp + 4 * SAMPLE_RATE) / (8 * SAMPLE_RATE))
                    .max(2);
                enc.shrink(nb_compressed_bytes as u32);
                // The C leaves `nbAvailableBytes` at its pre-clamp value here, which would let the
                // prefilter and the spreading decision spend against a buffer the packet no longer
                // has. That is unreachable from `opus_encode_native` — it hands CELT
                // `OPUS_BITRATE_MAX` in CBR and lets the *Opus* layer size the packet, so this whole
                // branch never runs there — but it is reachable through this crate's standalone
                // CELT-only entry point, where it desynchronises a 2-byte packet outright. Recompute
                // it, which is the value every reachable path in the reference already has.
                nb_available_bytes = nb_compressed_bytes - nb_filled_bytes;
            }
            effective_bytes = nb_compressed_bytes - nb_filled_bytes;
        }
        // "equiv_rate" — the rate a 20 ms frame would need for the same quality
        // (celt_encoder.c:1600).
        let mut equiv_rate = ((nb_compressed_bytes * 8 * 50) << (3 - lm))
            - (40 * channels as i32 + 20) * ((400 >> lm) - 50);
        if self.bitrate > 0 {
            equiv_rate =
                equiv_rate.min(self.bitrate - (40 * channels as i32 + 20) * ((400 >> lm) - 50));
        }

        if vbr_rate > 0 && constrained_vbr {
            // "Computes the max bit-rate allowed in VBR mode to avoid violating the target rate and
            // buffering. We must do this up front so that bust-prevention logic triggers correctly
            // if we don't have enough bits." (celt_encoder.c:1612)
            //
            // The floor is 2 bytes for a coder that was empty on entry "but to allow 0 in hybrid
            // mode", where SILK has already guaranteed a non-empty packet.
            let vbr_bound = vbr_rate;
            let floor = if tell_at_entry == 1 { 2 } else { 0 };
            let max_allowed = floor
                .max((vbr_rate + vbr_bound - self.vbr_reservoir) >> (BITRES + 3))
                .min(nb_available_bytes);
            if max_allowed < nb_available_bytes {
                nb_compressed_bytes = nb_filled_bytes + max_allowed;
                nb_available_bytes = max_allowed;
                enc.shrink(nb_compressed_bytes as u32);
            }
        }
        let mut total_bits = nb_compressed_bytes * 8;

        // ── Silence detection + flag (celt_encoder.c:1644) ───────────────────────────────────────
        // The peak is taken over `C*(N-overlap)` interleaved samples and then over the `C*overlap`
        // tail, which is carried into the next frame.
        let head = channels * n.saturating_sub(OVERLAP) / self.upsample;
        let tail_end = channels * n / self.upsample;
        let sample_max = self
            .overlap_max
            .max(peak_abs(&pcm[..head]))
            .max(peak_abs(&pcm[head..tail_end]));
        self.overlap_max = peak_abs(&pcm[head..tail_end]);
        // The flag is the first symbol of a CELT-only frame; in hybrid the decoder does not read one
        // and the frame is never silent as far as CELT is concerned (celt_encoder.c:1656-1659).
        let silence = if tell_at_entry == 1 {
            let silence = sample_max <= 1.0 / (1 << self.lsb_depth) as f32;
            enc.enc_bit_logp(silence, 15);
            silence
        } else {
            false
        };
        if silence {
            // "In VBR mode there is no need to send more than the minimum."
            if vbr_rate > 0 {
                nb_compressed_bytes = nb_compressed_bytes.min(nb_filled_bytes + 2);
                effective_bytes = nb_compressed_bytes;
                total_bits = nb_compressed_bytes * 8;
                nb_available_bytes = 2;
                enc.shrink(nb_compressed_bytes as u32);
            }
            // "Pretend we've filled all the remaining bits with zeros."
            enc.declare_bits_used(total_bits);
        }

        // ── Pre-emphasis (celt_encoder.c:1675) ───────────────────────────────────────────────────
        // `in` layout, per channel and channel-major with stride `N + overlap`:
        // [overlap tail of the previous frame][this frame's N samples]. Every *allocated* channel is
        // pre-emphasised, even when only one is coded — the second one still feeds the downmix.
        let mut input = [0f32; MAX_CHANNELS * MAX_IN_LEN];
        let need_clip = self.clip && sample_max > 2.0;
        let stride = n + OVERLAP;
        for c in 0..cc {
            let base = c * stride + OVERLAP;
            celt_preemphasis(
                pcm,
                &mut input[base..base + n],
                n,
                cc,
                c,
                self.upsample,
                PREEMPH[0],
                &mut self.preemph_mem[c],
                need_clip,
            );
        }

        // ── Prefilter: pitch period + gain, and the comb applied to the input (celt_encoder.c:1686)
        // Never in hybrid: the low band is SILK's and the comb would fight its own LTP.
        let prefilter_enabled = nb_available_bytes > 12 * channels as i32
            && !silence
            && !self.disable_pf
            && self.complexity >= 5
            && !hybrid;
        let prefilter_tapset = self.tapset_decision;
        let (pf_on, pitch_index, gain1, qg) = self.run_prefilter(
            &mut input,
            n,
            prefilter_tapset,
            prefilter_enabled,
            nb_available_bytes,
        );
        if pf_on {
            enc.enc_bit_logp(true, 1);
            // `octave = EC_ILOG(pitch_index+1) - 5`, where `EC_ILOG(x) = 1 + floor(log2(x))`
            // (celt_encoder.c:1707). With `pitch_index` in `15..=1022` that lands in `0..=5`, which
            // is what `ec_enc_uint(octave, 6)` can carry.
            let coded = pitch_index + 1;
            let octave = (32 - (coded as u32).leading_zeros()) as i32 - 5;
            debug_assert!((0..6).contains(&octave), "octave {octave} out of range");
            enc.enc_uint(octave as u32, 6);
            enc.enc_bits((coded as u32) - (16u32 << octave), 4 + octave as u32);
            enc.enc_bits(qg, 3);
            enc.enc_icdf(prefilter_tapset, &TAPSET_ICDF, 2);
        } else if !hybrid && enc.tell() + 16 <= total_bits {
            enc.enc_bit_logp(false, 1);
        }

        // ── Transient analysis (celt_encoder.c:1717) ─────────────────────────────────────────────
        // "Reduces the likelihood of energy instability on fricatives at low bitrate in hybrid mode.
        // It seems like we still want to have real transients on vowels though (small SILK
        // quantization offset value)."
        let allow_weak_transients =
            hybrid && effective_bytes < 15 && self.silk_info.signal_type != 2;
        let mut transient = if self.complexity >= 1 {
            transient_analysis(&input, n + OVERLAP, cc, allow_weak_transients)
        } else {
            Default::default()
        };
        let mut transient_got_disabled = false;
        if !(lm > 0 && enc.tell() + 3 <= total_bits) {
            transient.is_transient = false;
            transient_got_disabled = true;
        }
        let mut short_blocks = transient.is_transient;

        // ── Forward MDCT + band energies (celt_encoder.c:1741) ───────────────────────────────────
        let mut freq = [0f32; MAX_CHANNELS * MAX_FRAME_SAMPLES];
        let mut band_e = [0f32; 2 * NB_BANDS];
        let mut band_log_e = [0f32; 2 * NB_BANDS];
        let mut band_log_e2 = [0f32; 2 * NB_BANDS];

        // "secondMdct": at high complexity, measure the long-block energy too so dynalloc sees the
        // pre-transient spectrum (celt_encoder.c:1741).
        let second_mdct = short_blocks && self.complexity >= 8;
        if second_mdct {
            self.compute_mdcts(false, &input, &mut freq, lm, n);
            compute_band_energies(&freq, &mut band_e, eff_end, channels, lm);
            amp2_log2(&band_e, &mut band_log_e2, eff_end, end, channels);
            for c in 0..channels {
                for i in 0..end {
                    band_log_e2[c * NB_BANDS + i] += 0.5 * lm as f32;
                }
            }
        }

        self.compute_mdcts(short_blocks, &input, &mut freq, lm, n);
        // With two channels allocated but one coded, the downmix has already happened in the
        // frequency domain, so the tf analysis has only one channel to choose from
        // (celt_encoder.c:1759-1760).
        if cc == 2 && channels == 1 {
            transient.tf_chan = 0;
        }
        compute_band_energies(&freq, &mut band_e, eff_end, channels, lm);
        amp2_log2(&band_e, &mut band_log_e, eff_end, end, channels);

        // Temporal VBR: how loud this frame is versus the running average (celt_encoder.c:1850).
        let temporal_vbr;
        {
            let mut follow = -10.0f32;
            let mut frame_avg = 0f32;
            let offset = if short_blocks { 0.5 * lm as f32 } else { 0.0 };
            for i in start..end {
                follow = (follow - 1.0).max(band_log_e[i] - offset);
                if channels == 2 {
                    follow = follow.max(band_log_e[i + NB_BANDS] - offset);
                }
                frame_avg += follow;
            }
            if end > start {
                frame_avg /= (end - start) as f32;
            }
            temporal_vbr = (frame_avg - self.spec_avg).clamp(-1.5, 3.0);
            self.spec_avg += 0.02 * temporal_vbr;
        }

        if !second_mdct {
            band_log_e2[..channels * NB_BANDS].copy_from_slice(&band_log_e[..channels * NB_BANDS]);
        }

        // "Last chance to catch any transient we might have missed in the time-domain analysis"
        // (celt_encoder.c:1876).
        if lm > 0
            && enc.tell() + 3 <= total_bits
            && !transient.is_transient
            && self.complexity >= 5
            && !hybrid
            && patch_transient_decision(&band_log_e, &self.old_band_energy, start, end, channels)
        {
            transient.is_transient = true;
            short_blocks = true;
            self.compute_mdcts(true, &input, &mut freq, lm, n);
            compute_band_energies(&freq, &mut band_e, eff_end, channels, lm);
            amp2_log2(&band_e, &mut band_log_e, eff_end, end, channels);
            // Compensate for the scaling of short vs long MDCTs.
            for c in 0..channels {
                for i in 0..end {
                    band_log_e2[c * NB_BANDS + i] += 0.5 * lm as f32;
                }
            }
            transient.tf_estimate = 0.2;
        }
        if lm > 0 && enc.tell() + 3 <= total_bits {
            enc.enc_bit_logp(transient.is_transient, 3);
        }

        // ── Band normalisation (celt_encoder.c:1903) ─────────────────────────────────────────────
        let mut x = [0f32; MAX_CHANNELS * MAX_FRAME_SAMPLES];
        normalise_bands(&freq, &mut x, &band_e, eff_end, channels, m);

        // ── Dynalloc + importance/spread weights (celt_encoder.c:1911) ───────────────────────────
        let mut offsets = [0i32; NB_BANDS];
        let mut importance = [13i32; NB_BANDS];
        let mut spread_weight = [32i32; NB_BANDS];
        let dynalloc = dynalloc_analysis(
            &band_log_e,
            &band_log_e2,
            &self.old_band_energy,
            start,
            end,
            channels,
            &mut offsets,
            self.lsb_depth,
            transient.is_transient,
            vbr,
            constrained_vbr,
            lm,
            effective_bytes,
            &mut importance,
            &mut spread_weight,
        );

        // ── tf resolution (celt_encoder.c:1915) ──────────────────────────────────────────────────
        let mut tf_res = [0i32; NB_BANDS];
        // "Disable variable tf resolution for hybrid and at very low bitrate" — the Viterbi search
        // costs bits the high band cannot spare, and the two hybrid fallbacks below are chosen from
        // what SILK reported rather than measured (celt_encoder.c:1905-1942).
        let enable_tf_analysis =
            effective_bytes >= 15 * channels as i32 && !hybrid && self.complexity >= 2;
        let tf_select = if enable_tf_analysis {
            let lambda = (80i32).max(20480 / effective_bytes.max(1) + 2);
            let sel = tf_analysis(
                eff_end,
                transient.is_transient,
                &mut tf_res,
                lambda,
                &x,
                n,
                lm,
                transient.tf_estimate,
                transient.tf_chan,
                &importance,
            );
            for i in eff_end..end {
                tf_res[i] = tf_res[eff_end - 1];
            }
            sel
        } else if hybrid && transient.weak_transient {
            // "For weak transients, we rely on the fact that improving time resolution using TF on a
            // long window is imperfect and will not result in an energy collapse at low bitrate."
            for i in 0..end {
                tf_res[i] = 1;
            }
            0usize
        } else if hybrid && effective_bytes < 15 && self.silk_info.signal_type != 2 {
            // "For low bitrate hybrid, we force temporal resolution to 5 ms rather than 2.5 ms."
            for i in 0..end {
                tf_res[i] = 0;
            }
            usize::from(transient.is_transient)
        } else {
            for i in 0..end {
                tf_res[i] = i32::from(transient.is_transient);
            }
            0
        };

        // ── Coarse energy (celt_encoder.c:1944) ──────────────────────────────────────────────────
        let mut error = [0f32; 2 * NB_BANDS];
        for c in 0..channels {
            for i in start + c * NB_BANDS..end + c * NB_BANDS {
                // "When the energy is stable, slightly bias energy quantization towards the previous
                // error to make the gain more stable (a constant offset is better than
                // fluctuations)."
                if (band_log_e[i] - self.old_band_energy[i]).abs() < 2.0 {
                    band_log_e[i] -= 0.25 * self.energy_error[i];
                }
            }
        }
        quant_coarse_energy(
            start,
            end,
            eff_end,
            &band_log_e,
            &mut self.old_band_energy,
            total_bits,
            &mut error,
            enc,
            channels,
            lm,
            nb_available_bytes,
            self.force_intra,
            &mut self.delayed_intra,
            self.complexity >= 4,
            self.loss_rate,
        );

        tf_encode(
            start,
            end,
            transient.is_transient,
            &mut tf_res,
            lm,
            tf_select,
            enc,
        );

        // ── Spreading decision (celt_encoder.c:1965) ─────────────────────────────────────────────
        if enc.tell() + 4 <= total_bits {
            self.spread_decision = if hybrid {
                // The high band of a hybrid frame is mostly noise-like, so it is spread
                // aggressively unless the frame is a transient (celt_encoder.c:1971-1978).
                if self.complexity == 0 {
                    SPREAD_NONE
                } else if transient.is_transient {
                    SPREAD_NORMAL
                } else {
                    SPREAD_AGGRESSIVE
                }
            } else if short_blocks
                || self.complexity < 3
                || nb_available_bytes < 10 * channels as i32
            {
                if self.complexity == 0 {
                    SPREAD_NONE
                } else {
                    SPREAD_NORMAL
                }
            } else {
                spreading_decision(
                    &x,
                    &mut self.tonal_average,
                    self.spread_decision,
                    &mut self.hf_average,
                    &mut self.tapset_decision,
                    pf_on && !short_blocks,
                    eff_end,
                    channels,
                    m,
                    &spread_weight,
                )
            };
            enc.enc_icdf(self.spread_decision as usize, &SPREAD_ICDF, 5);
        }

        // ── Caps + dynalloc boost coding (celt_encoder.c:2014) ───────────────────────────────────
        let mut cap = [0i32; NB_BANDS];
        init_caps(&mut cap, lm, channels);
        let mut dynalloc_logp = 6i32;
        let total_bits_frac = total_bits << BITRES;
        let mut total_boost = 0i32;
        let mut tell = enc.tell_frac() as i32;
        for i in start..end {
            let width = ((channels as i32) * i32::from(E_BANDS[i + 1] - E_BANDS[i])) << lm;
            // "quanta is 6 bits, but no more than 1 bit/sample and no less than 1/8 bit/sample"
            let quanta = (width << BITRES).min((6 << BITRES).max(width));
            let mut dynalloc_loop_logp = dynalloc_logp;
            let mut boost = 0i32;
            let mut j = 0i32;
            while tell + (dynalloc_loop_logp << BITRES) < total_bits_frac - total_boost
                && boost < cap[i]
            {
                let flag = j < offsets[i];
                enc.enc_bit_logp(flag, dynalloc_loop_logp as u32);
                tell = enc.tell_frac() as i32;
                if !flag {
                    break;
                }
                boost += quanta;
                total_boost += quanta;
                dynalloc_loop_logp = 1;
                j += 1;
            }
            // Making dynalloc more likely.
            if j != 0 {
                dynalloc_logp = 2.max(dynalloc_logp - 1);
            }
            offsets[i] = boost;
        }

        // ── Stereo mode: intensity threshold + dual stereo (celt_encoder.c:2052) ─────────────────
        let mut dual_stereo = false;
        if channels == 2 {
            // "Always use MS for 2.5 ms frames until we can do a better analysis."
            if lm != 0 {
                dual_stereo = stereo_analysis(&x, lm, n);
            }
            self.intensity = hysteresis_decision(
                (equiv_rate / 1000) as f32,
                &INTENSITY_THRESHOLDS,
                &INTENSITY_HYSTERESIS,
                self.intensity,
            );
            self.intensity = self.intensity.clamp(start, end);
        }

        // ── Allocation trim (celt_encoder.c:2069) ────────────────────────────────────────────────
        let mut alloc_trim = 5i32;
        if tell + (6 << BITRES) <= total_bits_frac - total_boost {
            if start > 0 {
                self.stereo_saving = 0.0;
                alloc_trim = 5;
            } else {
                alloc_trim = alloc_trim_analysis(
                    &x,
                    &band_log_e,
                    end,
                    lm,
                    channels,
                    n,
                    &mut self.stereo_saving,
                    transient.tf_estimate,
                    self.intensity,
                    equiv_rate,
                );
            }
            enc.enc_icdf(alloc_trim as usize, &TRIM_ICDF, 7);
            tell = enc.tell_frac() as i32;
        }

        // ── Variable bitrate: pick the actual frame size (celt_encoder.c:2086) ───────────────────
        if vbr_rate > 0 {
            let lm_diff = MAX_LM as i32 - lm as i32;
            // "Don't attempt to use more than 510 kb/s, even for frames smaller than 20 ms."
            nb_compressed_bytes = nb_compressed_bytes.min(1275 >> (3 - lm));
            let mut base_target = if hybrid {
                // The high band's own overhead is much smaller than a whole CELT frame's, because
                // SILK already paid for the frame (celt_encoder.c:2102).
                (vbr_rate - ((9 * channels as i32 + 4) << BITRES)).max(0)
            } else {
                vbr_rate - ((40 * channels as i32 + 20) << BITRES)
            };
            if constrained_vbr {
                base_target += self.vbr_offset >> lm_diff;
            }
            let mut target = if hybrid {
                // The hybrid target is a handful of adjustments on the base rather than the full
                // `compute_vbr`, which is calibrated for a frame that carries the whole spectrum
                // (celt_encoder.c:2115-2127).
                let mut target = base_target;
                // "Tonal frames (offset<100) need more bits than noisy (offset>100) ones."
                if self.silk_info.offset < 100 {
                    target += (12 << BITRES) >> (3 - lm);
                }
                if self.silk_info.offset > 100 {
                    target -= (18 << BITRES) >> (3 - lm);
                }
                // "Boosting bitrate on transients and vowels with significant temporal spikes."
                target += ((transient.tf_estimate - 0.25) * (50 << BITRES) as f32) as i32;
                // "If we have a strong transient, let's make sure it has enough bits to code the
                // first two bands, so that it can use folding rather than noise."
                if transient.tf_estimate > 0.7 {
                    target = target.max(50 << BITRES);
                }
                target
            } else {
                compute_vbr(
                    base_target,
                    lm,
                    equiv_rate,
                    self.last_coded_bands,
                    channels,
                    self.intensity,
                    constrained_vbr,
                    self.stereo_saving,
                    dynalloc.tot_boost,
                    transient.tf_estimate,
                    dynalloc.max_depth,
                    temporal_vbr,
                )
            };
            // "The current offset is removed from the target and the space used so far is added."
            target += tell;
            // "In VBR mode the frame size must not be reduced so much that it would result in the
            // encoder running out of bits. The margin of 2 bytes ensures that none of the
            // bust-prevention logic in the decoder will have triggered so far."
            let mut min_allowed =
                ((tell + total_boost + (1 << (BITRES + 3)) - 1) >> (BITRES + 3)) + 2;
            if hybrid {
                // "Take into account the 37 bits we need to have left in the packet to signal a
                // redundant frame in hybrid mode. Creating a shorter packet would create an entropy
                // coder desync." (celt_encoder.c:2136-2140)
                min_allowed = min_allowed.max(
                    (tell0_frac + (37 << BITRES) + total_boost + (1 << (BITRES + 3)) - 1)
                        >> (BITRES + 3),
                );
            }
            nb_available_bytes = (target + (1 << (BITRES + 2))) >> (BITRES + 3);
            nb_available_bytes = nb_available_bytes.max(min_allowed).min(nb_compressed_bytes);
            let mut delta = target - vbr_rate;
            target = nb_available_bytes << (BITRES + 3);
            // "If the frame is silent we don't adjust our drift, otherwise the encoder will shoot to
            // very high rates after hitting a span of silence."
            if silence {
                nb_available_bytes = 2;
                target = (2 * 8) << BITRES;
                delta = 0;
            }
            let alpha = if self.vbr_count < 970 {
                self.vbr_count += 1;
                1.0 / (self.vbr_count + 20) as f32
            } else {
                0.001
            };
            if constrained_vbr {
                self.vbr_reservoir += target - vbr_rate;
                self.vbr_drift += (alpha
                    * ((delta * (1 << lm_diff)) - self.vbr_offset - self.vbr_drift) as f32)
                    as i32;
                self.vbr_offset = -self.vbr_drift;
                if self.vbr_reservoir < 0 {
                    // "We're under the min value -- increase rate."
                    let adjust = (-self.vbr_reservoir) / (8 << BITRES);
                    if !silence {
                        nb_available_bytes += adjust;
                    }
                    self.vbr_reservoir = 0;
                }
            }
            nb_compressed_bytes = nb_compressed_bytes.min(nb_available_bytes).max(2);
            // This moves the raw bits to take into account the new compressed size.
            enc.shrink(nb_compressed_bytes as u32);
        }

        // ── Bit allocation (celt_encoder.c:2197) ─────────────────────────────────────────────────
        let mut fine_quant = [0i32; NB_BANDS];
        let mut pulses = [0i32; NB_BANDS];
        let mut fine_priority = [0i32; NB_BANDS];
        // bits = packet size - where we are - safety
        let mut bits = ((nb_compressed_bytes * 8) << BITRES) - enc.tell_frac() as i32 - 1;
        let anti_collapse_rsv =
            if transient.is_transient && lm >= 2 && bits >= ((lm as i32 + 2) << BITRES) {
                1 << BITRES
            } else {
                0
            };
        bits -= anti_collapse_rsv;
        let signal_bandwidth = end - 1;
        let mut balance = 0i32;
        let coded_bands = clt_compute_allocation(
            start,
            end,
            &offsets,
            &cap,
            alloc_trim,
            // In/out, exactly as `&st->intensity` is in the C (`celt_encoder.c:2227`).
            &mut self.intensity,
            &mut dual_stereo,
            bits,
            &mut balance,
            &mut pulses,
            &mut fine_quant,
            &mut fine_priority,
            channels,
            lm,
            self.last_coded_bands,
            signal_bandwidth,
            enc,
        );
        self.last_coded_bands = if self.last_coded_bands != 0 {
            (self.last_coded_bands + 1).min((self.last_coded_bands - 1).max(coded_bands))
        } else {
            coded_bands
        };

        // ── Fine energy (celt_encoder.c:2234) ────────────────────────────────────────────────────
        quant_fine_energy(
            start,
            end,
            &mut self.old_band_energy,
            &mut error,
            &fine_quant,
            enc,
            channels,
        );

        // ── Residual (band/PVQ) quantisation (celt_encoder.c:2238) ───────────────────────────────
        let mut collapse_masks = [0u8; MAX_CHANNELS * NB_BANDS];
        let band_total_bits = nb_compressed_bytes * (8 << BITRES) - anti_collapse_rsv;
        let mut stereo = StereoBands {
            band_energy: &band_e,
            intensity: self.intensity,
            dual_stereo,
            complexity: self.complexity,
            rdo: Some(&mut self.theta_rdo),
        };
        quant_all_bands(
            start,
            end,
            &mut x,
            n,
            (channels == 2).then_some(&mut stereo),
            &mut collapse_masks[..channels * NB_BANDS],
            &pulses,
            short_blocks,
            self.spread_decision,
            &tf_res,
            band_total_bits,
            balance,
            lm as i32,
            coded_bands,
            &mut self.rng,
            // `st->disable_inv` is 0 for an encoder unless the caller turns phase inversion off; the
            // mono path has no side channel to invert, so the flag is moot there.
            channels == 1,
            enc,
        );

        // ── Anti-collapse flag (celt_encoder.c:2243) ─────────────────────────────────────────────
        if anti_collapse_rsv > 0 {
            enc.enc_bits(u32::from(self.consec_transient < 2), 1);
        }

        // ── Leftover-bit energy refinement (celt_encoder.c:2251) ─────────────────────────────────
        quant_energy_finalise(
            start,
            end,
            &mut self.old_band_energy,
            &mut error,
            &fine_quant,
            &fine_priority,
            nb_compressed_bytes * 8 - enc.tell(),
            enc,
            channels,
        );
        self.energy_error.fill(0.0);
        for c in 0..channels {
            for i in start + c * NB_BANDS..end + c * NB_BANDS {
                self.energy_error[i] = error[i].clamp(-0.5, 0.5);
            }
        }

        if silence {
            self.old_band_energy.fill(ENERGY_RESET_DB);
        }

        // ── Roll the prefilter + energy history (celt_encoder.c:2309) ────────────────────────────
        self.prefilter_period = pitch_index;
        self.prefilter_gain = gain1;
        self.prefilter_tapset = prefilter_tapset;
        // One coded channel: mirror its energy into the second half so the next frame's `max` fold
        // over both halves is a no-op whichever channel count that frame uses. The C only does this
        // for `CC == 2 && C == 1` (celt_encoder.c:2321-2323); doing it for a permanently mono
        // encoder as well is unobservable, because nothing there ever reads the second half.
        if channels == 1 {
            for i in 0..NB_BANDS {
                self.old_band_energy[NB_BANDS + i] = self.old_band_energy[i];
            }
        }
        if !transient.is_transient {
            self.old_log_energy2 = self.old_log_energy;
            self.old_log_energy = self.old_band_energy;
        } else {
            for (log_e, &band) in self
                .old_log_energy
                .iter_mut()
                .zip(self.old_band_energy.iter())
            {
                *log_e = log_e.min(band);
            }
        }
        // "In case start or end were to change" (celt_encoder.c:2333).
        for channel in 0..2 {
            let base = channel * NB_BANDS;
            for i in (0..start).chain(end..NB_BANDS) {
                self.old_band_energy[base + i] = 0.0;
                self.old_log_energy[base + i] = ENERGY_RESET_DB;
                self.old_log_energy2[base + i] = ENERGY_RESET_DB;
            }
        }
        if transient.is_transient || transient_got_disabled {
            self.consec_transient += 1;
        } else {
            self.consec_transient = 0;
        }
        self.rng = enc.rng();
        Ok(nb_compressed_bytes as usize)
    }

    /// Window and forward-MDCT the pre-emphasised input into the spectrum (libopus `compute_mdcts`,
    /// `celt_encoder.c:461`): per channel, one long block or `M` short blocks interleaved with
    /// stride `M`. `input` is channel-major with stride `N + overlap`, `out` with stride `N`.
    ///
    /// Every *allocated* channel is transformed. When only one is coded the two spectra are then
    /// averaged in place (`celt_encoder.c:489-493`) — a frequency-domain downmix, not a discard, so
    /// dropping a stereo stream to one coded channel keeps both channels' content.
    fn compute_mdcts(
        &self,
        short_blocks: bool,
        input: &[f32],
        out: &mut [f32],
        lm: usize,
        n: usize,
    ) {
        let (blocks, block_n, shift) = if short_blocks {
            (1usize << lm, SHORT_MDCT_SIZE, MAX_LM)
        } else {
            (1usize, n, MAX_LM - lm)
        };
        for c in 0..self.channels {
            let in_base = c * (n + OVERLAP);
            let out_base = c * n;
            for b in 0..blocks {
                clt_mdct_forward(
                    &self.mdct,
                    &input[in_base + b * block_n..],
                    &mut out[out_base + b..],
                    &WINDOW120,
                    OVERLAP,
                    shift,
                    blocks,
                );
            }
        }
        if self.channels == 2 && self.stream_channels == 1 {
            for i in 0..n {
                out[i] = 0.5 * out[i] + 0.5 * out[n + i];
            }
        }
        if self.upsample != 1 {
            // The zero-stuffed input has `upsample` copies of the spectrum; keep the first and clear
            // the images, scaling to undo the interpolation's loss (`celt_encoder.c:494-503`).
            let bound = n / self.upsample;
            for c in 0..self.stream_channels {
                let base = c * n;
                for i in 0..bound {
                    out[base + i] *= self.upsample as f32;
                }
                out[base + bound..base + n].fill(0.0);
            }
        }
    }

    /// Pitch search + the prefilter comb applied to `input` (libopus `run_prefilter`,
    /// `celt_encoder.c:1188`). Returns `(pf_on, pitch_index, gain, quantised_gain)`.
    ///
    /// Each channel's `input[c*(n+OVERLAP)..][..OVERLAP]` is filled with the previous frame's tail on
    /// entry and the rest holds this frame's pre-emphasised samples; on exit the whole `OVERLAP + n`
    /// region of every channel is prefiltered and the tails are saved for the next frame. The pitch
    /// search runs once, on the channel-summed downmix, so both channels share one comb.
    // The channel loops index four parallel per-channel arrays (`pre`, `input`, `in_mem`,
    // `prefilter_mem`) with the reference's own `c`; zipping them would obscure the correspondence.
    #[allow(clippy::needless_range_loop)]
    fn run_prefilter(
        &mut self,
        input: &mut [f32],
        n: usize,
        prefilter_tapset: usize,
        enabled: bool,
        nb_available_bytes: i32,
    ) -> (bool, usize, f32, u32) {
        let channels = self.channels;
        let stride = n + OVERLAP;
        // `pre[c]` = [COMBFILTER_MAXPERIOD of history][this frame's N samples].
        let mut pre = [[0f32; COMBFILTER_MAXPERIOD + MAX_FRAME_SAMPLES]; MAX_CHANNELS];
        for c in 0..channels {
            pre[c][..COMBFILTER_MAXPERIOD].copy_from_slice(&self.prefilter_mem[c]);
            let base = c * stride + OVERLAP;
            pre[c][COMBFILTER_MAXPERIOD..COMBFILTER_MAXPERIOD + n]
                .copy_from_slice(&input[base..base + n]);
        }

        let mut pitch_index = COMBFILTER_MINPERIOD;
        let mut gain1 = 0f32;
        if enabled {
            let mut pitch_buf = [0f32; (COMBFILTER_MAXPERIOD + MAX_FRAME_SAMPLES) / 2];
            let len = COMBFILTER_MAXPERIOD + n;
            let channel_views: [&[f32]; MAX_CHANNELS] = [&pre[0][..len], &pre[1][..len]];
            pitch_downsample(&channel_views[..channels], &mut pitch_buf, len, channels);
            // "Don't search the last 1.5 octave of the range because there's too many
            // false-positives due to short-term correlation" (celt_encoder.c:1222).
            let index = pitch_search(
                &pitch_buf[COMBFILTER_MAXPERIOD >> 1..],
                &pitch_buf,
                n,
                COMBFILTER_MAXPERIOD - 3 * COMBFILTER_MINPERIOD,
            );
            pitch_index = COMBFILTER_MAXPERIOD - index;
            gain1 = remove_doubling(
                &pitch_buf,
                COMBFILTER_MAXPERIOD,
                COMBFILTER_MINPERIOD,
                n,
                &mut pitch_index,
                self.prefilter_period,
                self.prefilter_gain,
            );
            pitch_index = pitch_index.min(COMBFILTER_MAXPERIOD - 2);
            gain1 *= 0.7;
            // A prefiltered frame is harder to conceal, so back off as loss rises.
            if self.loss_rate > 2 {
                gain1 *= 0.5;
            }
            if self.loss_rate > 4 {
                gain1 *= 0.5;
            }
            if self.loss_rate > 8 {
                gain1 = 0.0;
            }
        }

        // Gain threshold for enabling the prefilter/postfilter, adjusted by rate and continuity
        // (celt_encoder.c:1251).
        let mut pf_threshold = 0.2f32;
        if (pitch_index as i32 - self.prefilter_period as i32).abs() * 10 > pitch_index as i32 {
            pf_threshold += 0.2;
        }
        if nb_available_bytes < 25 {
            pf_threshold += 0.1;
        }
        if nb_available_bytes < 35 {
            pf_threshold += 0.1;
        }
        if self.prefilter_gain > 0.4 {
            pf_threshold -= 0.1;
        }
        if self.prefilter_gain > 0.55 {
            pf_threshold -= 0.1;
        }
        pf_threshold = pf_threshold.max(0.2);

        let (pf_on, qg);
        if gain1 < pf_threshold {
            gain1 = 0.0;
            pf_on = false;
            qg = 0;
        } else {
            if (gain1 - self.prefilter_gain).abs() < 0.1 {
                gain1 = self.prefilter_gain;
            }
            qg = (((0.5 + gain1 * 32.0 / 3.0).floor() as i32) - 1).clamp(0, 7) as u32;
            gain1 = 0.093_75 * (qg + 1) as f32;
            pf_on = true;
        }

        // Apply the comb to the input, crossfading from the previous frame's parameters
        // (celt_encoder.c:1290). The first `shortMdctSize - overlap` samples use the old parameters
        // throughout; the rest crossfades to the new ones.
        let offset = SHORT_MDCT_SIZE - OVERLAP;
        self.prefilter_period = self.prefilter_period.max(COMBFILTER_MINPERIOD);
        let mut filtered = [0f32; MAX_FRAME_SAMPLES];
        for c in 0..channels {
            let base = c * stride;
            input[base..base + OVERLAP].copy_from_slice(&self.in_mem[c]);
            if offset != 0 {
                comb_filter_out_of_place(
                    &mut filtered[..offset],
                    &pre[c],
                    COMBFILTER_MAXPERIOD,
                    offset,
                    self.prefilter_period,
                    self.prefilter_period,
                    -self.prefilter_gain,
                    -self.prefilter_gain,
                    self.prefilter_tapset,
                    self.prefilter_tapset,
                    &WINDOW120,
                    0,
                );
            }
            comb_filter_out_of_place(
                &mut filtered[offset..n],
                &pre[c],
                COMBFILTER_MAXPERIOD + offset,
                n - offset,
                self.prefilter_period,
                pitch_index,
                -self.prefilter_gain,
                -gain1,
                self.prefilter_tapset,
                prefilter_tapset,
                &WINDOW120,
                OVERLAP,
            );
            input[base + OVERLAP..base + OVERLAP + n].copy_from_slice(&filtered[..n]);
            self.in_mem[c].copy_from_slice(&input[base + n..base + n + OVERLAP]);

            // Roll the prefilter history.
            if n > COMBFILTER_MAXPERIOD {
                self.prefilter_mem[c].copy_from_slice(&pre[c][n..n + COMBFILTER_MAXPERIOD]);
            } else {
                self.prefilter_mem[c].copy_within(n.., 0);
                self.prefilter_mem[c][COMBFILTER_MAXPERIOD - n..]
                    .copy_from_slice(&pre[c][COMBFILTER_MAXPERIOD..COMBFILTER_MAXPERIOD + n]);
            }
        }
        (pf_on, pitch_index, gain1, qg)
    }
}

/// Bitrate (kb/s) at which each band starts being coded with intensity stereo (libopus
/// `intensity_thresholds`, `celt_encoder.c:2054`). The chosen index is the first band coded with
/// intensity stereo, so a higher rate keeps more bands in true stereo.
const INTENSITY_THRESHOLDS: [f32; NB_BANDS] = [
    1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 16.0, 24.0, 36.0, 44.0, 50.0, 56.0, 62.0, 67.0, 72.0,
    79.0, 88.0, 106.0, 134.0,
];
/// Hysteresis around those thresholds, so the intensity band cannot oscillate frame to frame
/// (libopus `intensity_histeresis`).
const INTENSITY_HYSTERESIS: [f32; NB_BANDS] = [
    1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 3.0, 3.0, 4.0, 5.0, 6.0,
    8.0, 8.0,
];

/// Pick the first threshold `val` falls below, refusing to move off `prev` until `val` clears the
/// neighbouring hysteresis band (libopus `hysteresis_decision`, `bands.c:46`).
fn hysteresis_decision(
    val: f32,
    thresholds: &[f32; NB_BANDS],
    hysteresis: &[f32; NB_BANDS],
    prev: usize,
) -> usize {
    let mut index = thresholds.len();
    for (i, &threshold) in thresholds.iter().enumerate() {
        if val < threshold {
            index = i;
            break;
        }
    }
    if index > prev && val < thresholds[prev] + hysteresis[prev] {
        index = prev;
    }
    if index < prev && val > thresholds[prev - 1] - hysteresis[prev - 1] {
        index = prev;
    }
    index
}

/// Peak absolute value in the SIG domain (libopus `celt_maxabs16` on the caller's PCM, scaled by
/// `CELT_SIG_SCALE` the way `sample_max` is compared at `celt_encoder.c:1650`).
fn peak_abs(pcm: &[f32]) -> f32 {
    let mut peak = 0f32;
    for &v in pcm {
        peak = peak.max(v.abs());
    }
    peak
}

/// The VBR target in 1/8 bits per frame (libopus `compute_vbr`, `celt_encoder.c:1320`; no surround
/// mask and no tonality analysis, both of which live above CELT).
#[allow(clippy::too_many_arguments)]
fn compute_vbr(
    base_target: i32,
    lm: usize,
    bitrate: i32,
    last_coded_bands: usize,
    channels: usize,
    intensity: usize,
    constrained_vbr: bool,
    stereo_saving: f32,
    tot_boost: i32,
    tf_estimate: f32,
    max_depth: f32,
    temporal_vbr: f32,
) -> i32 {
    let coded_bands = if last_coded_bands != 0 {
        last_coded_bands
    } else {
        NB_BANDS
    };
    let mut coded_bins = (E_BANDS[coded_bands] as i32) << lm;
    if channels == 2 {
        coded_bins += (E_BANDS[intensity.min(coded_bands)] as i32) << lm;
    }
    let mut target = base_target;

    // "Stereo savings" (celt_encoder.c:1351): the more correlated the two channels are, the less the
    // side costs, so the target comes down — capped both by a fraction of the target and by the
    // degrees of freedom actually coded in stereo.
    if channels == 2 {
        let coded_stereo_bands = intensity.min(coded_bands);
        let coded_stereo_dof =
            ((E_BANDS[coded_stereo_bands] as i32) << lm) - coded_stereo_bands as i32;
        // "Maximum fraction of the bits we can save if the signal is mono."
        let max_frac = 0.8 * coded_stereo_dof as f32 / coded_bins as f32;
        let stereo_saving = stereo_saving.min(1.0);
        let saving = (max_frac * target as f32)
            .min((stereo_saving - 0.1) * ((coded_stereo_dof << BITRES) as f32));
        target -= saving as i32;
    }

    // "Boost the rate according to dynalloc (minus the dynalloc average for calibration)."
    target += tot_boost - (19 << lm);
    // "Apply transient boost, compensating for average boost."
    let tf_calibration = 0.044f32;
    target += (2.0 * (tf_estimate - tf_calibration) * target as f32) as i32;

    {
        // Never spend more bits than the signal has depth above the noise floor.
        let bins = (E_BANDS[NB_BANDS - 2] as i32) << lm;
        let mut floor_depth = (((channels as i32 * bins) << BITRES) as f32 * max_depth) as i32;
        floor_depth = floor_depth.max(target >> 2);
        target = target.min(floor_depth);
    }

    // "Make VBR less aggressive for constrained VBR because we can't keep a higher bitrate for
    // long."
    if constrained_vbr {
        target = base_target + (0.67 * (target - base_target) as f32) as i32;
    }

    if tf_estimate < 0.2 {
        let amount = 0.0000031 * (0i32.max(32000.min(96000 - bitrate))) as f32;
        let tvbr_factor = temporal_vbr * amount;
        target += (tvbr_factor * target as f32) as i32;
    }

    // "Don't allow more than doubling the rate."
    (2 * base_target).min(target)
}

impl std::fmt::Debug for CeltEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CeltEncoder")
            .field("channels", &self.channels)
            .field("bitrate", &self.bitrate)
            .field("rate_control", &self.rate_control)
            .field("complexity", &self.complexity)
            .field("rng", &self.rng)
            .finish_non_exhaustive()
    }
}

/// `NB_SHORT_MDCTS` is the short-block count the module's MDCT sizing assumes; assert the tables
/// agree rather than hard-coding 8 twice.
const _: () = assert!(NB_SHORT_MDCTS == 1 << MAX_LM);
/// The spreading decision's aggressive value must be the largest, which the hysteresis relies on.
const _: () = assert!(SPREAD_AGGRESSIVE > SPREAD_NORMAL);

#[cfg(test)]
mod hybrid_tests {
    use super::*;
    use crate::opus::celt::decoder::CeltDecoder;
    use crate::opus::range_coder::RangeEncoder;

    /// A deterministic wideband-ish signal.
    fn signal(samples: usize, seed: u32) -> Vec<f32> {
        let mut state = seed | 1;
        (0..samples)
            .map(|index| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let noise = ((state >> 16) as f32 / 32768.0 - 1.0) * 0.05;
                let t = index as f32;
                0.3 * (t * 0.041).sin() + 0.15 * (t * 0.17).sin() + noise
            })
            .collect()
    }

    /// Stand in for the SILK layer: write `bits` worth of symbols into the coder, so the CELT layer
    /// sees a coder that is already part-full, exactly as it does in hybrid mode.
    fn fill_prefix(encoder: &mut RangeEncoder<'_>, bits: usize) {
        for index in 0..bits {
            encoder.enc_bit_logp(index % 3 == 0, 1);
        }
    }

    /// The hybrid entry point must code only the high band into a coder somebody else started, stay
    /// inside the budget, and leave the coder in a usable state.
    #[test]
    fn the_hybrid_entry_point_codes_the_high_band_into_a_shared_coder() {
        const FRAME: usize = 960;
        const BUDGET: usize = 120;
        let source = signal(FRAME * 6, 0xBEEF);
        for start in [17usize] {
            for end in [19usize, NB_BANDS] {
                let mut encoder = CeltEncoder::new().expect("encoder");
                encoder.set_bitrate(24_000);
                encoder.set_rate_control(RateControl::Vbr);
                encoder.set_band_range(start, end).expect("band range");
                for frame in 0..6 {
                    let mut buffer = [0u8; BUDGET];
                    let mut enc = RangeEncoder::new(&mut buffer);
                    fill_prefix(&mut enc, 200);
                    let before = enc.tell();
                    let written = encoder
                        .encode_with_range_encoder(
                            &source[frame * FRAME..(frame + 1) * FRAME],
                            FRAME,
                            &mut enc,
                            BUDGET as i32,
                        )
                        .expect("hybrid encode");
                    let after = enc.tell();
                    enc.done();
                    assert!(
                        !enc.error(),
                        "start={start} end={end} frame={frame}: overflow"
                    );
                    assert!(
                        after > before,
                        "start={start} end={end} frame={frame}: CELT coded nothing"
                    );
                    assert!(
                        (2..=BUDGET).contains(&written),
                        "start={start} end={end} frame={frame}: {written} bytes of {BUDGET}"
                    );
                }
            }
        }
    }

    /// A hybrid frame must **not** carry the silence flag: it is the first symbol of a CELT-only
    /// frame and a decoder in hybrid mode never reads one. A digitally silent input is the case that
    /// would write it, so encode exactly that and require the two paths to differ.
    #[test]
    fn a_hybrid_frame_never_writes_the_silence_flag() {
        const FRAME: usize = 960;
        let silence = vec![0.0f32; FRAME];

        // CELT-only: the flag is written and the encoder short-circuits to a 2-byte packet.
        let mut celt_only = CeltEncoder::new().expect("encoder");
        celt_only.set_bitrate(24_000);
        celt_only.set_rate_control(RateControl::Vbr);
        let mut buffer = [0u8; 200];
        let written = celt_only
            .encode(&silence, FRAME, &mut buffer)
            .expect("encode");
        assert_eq!(written, 2, "a silent CELT-only frame is the minimum packet");

        // Hybrid: no flag, so the same silent input costs the whole high-band machinery instead.
        let mut hybrid = CeltEncoder::new().expect("encoder");
        hybrid.set_bitrate(24_000);
        hybrid.set_rate_control(RateControl::Vbr);
        hybrid.set_band_range(17, NB_BANDS).expect("band range");
        let mut buffer = [0u8; 200];
        let mut enc = RangeEncoder::new(&mut buffer);
        fill_prefix(&mut enc, 200);
        let before = enc.tell();
        hybrid
            .encode_with_range_encoder(&silence, FRAME, &mut enc, 200)
            .expect("hybrid encode");
        assert!(
            enc.tell() > before,
            "the hybrid path took the silence short-circuit"
        );
    }

    /// `set_silk_info` must move the bitstream, or it is a knob that does nothing. The tonal and the
    /// noisy offsets pull the hybrid VBR target in opposite directions, so the two must not produce
    /// the same packet size across a stream.
    #[test]
    fn the_silk_info_offset_moves_the_hybrid_rate() {
        const FRAME: usize = 960;
        let source = signal(FRAME * 12, 0x51_1C);
        let encode_with = |offset: i32| -> usize {
            let mut encoder = CeltEncoder::new().expect("encoder");
            encoder.set_bitrate(20_000);
            encoder.set_rate_control(RateControl::Vbr);
            encoder.set_band_range(17, NB_BANDS).expect("band range");
            encoder.set_silk_info(SilkInfo {
                signal_type: 1,
                offset,
            });
            let mut total = 0usize;
            for frame in 0..12 {
                let mut buffer = [0u8; 200];
                let mut enc = RangeEncoder::new(&mut buffer);
                fill_prefix(&mut enc, 300);
                total += encoder
                    .encode_with_range_encoder(
                        &source[frame * FRAME..(frame + 1) * FRAME],
                        FRAME,
                        &mut enc,
                        200,
                    )
                    .expect("hybrid encode");
                enc.done();
            }
            total
        };
        let tonal = encode_with(50);
        let noisy = encode_with(150);
        assert!(
            tonal > noisy,
            "a tonal frame must be given more bits than a noisy one: {tonal} vs {noisy}"
        );
    }

    /// Dropping to one coded channel must *downmix*, not discard the right channel: a pair that
    /// cancels must come out near silent, and an identical pair must come out at full level. And the
    /// result must still be decodable by a mono decoder on the same entropy state.
    #[test]
    fn one_coded_channel_downmixes_rather_than_discarding() {
        const FRAME: usize = 960;
        let mono = signal(FRAME * 4, 0xD0FF);

        let energy_of = |right_sign: f32| -> f64 {
            let mut encoder = CeltEncoder::with_channels(2).expect("encoder");
            encoder.set_bitrate(64_000);
            encoder.set_rate_control(RateControl::Vbr);
            encoder.set_stream_channels(1).expect("one coded channel");
            let mut decoder = CeltDecoder::new().expect("decoder");
            let mut energy = 0f64;
            for frame in 0..4 {
                let mut interleaved = vec![0f32; FRAME * 2];
                for index in 0..FRAME {
                    let sample = mono[frame * FRAME + index];
                    interleaved[2 * index] = sample;
                    interleaved[2 * index + 1] = right_sign * sample;
                }
                let mut buffer = [0u8; 400];
                let written = encoder
                    .encode(&interleaved, FRAME, &mut buffer)
                    .expect("encode");
                let mut pcm = vec![0i16; FRAME];
                decoder
                    .decode(&buffer[..written], &mut pcm, FRAME)
                    .expect("decode");
                assert_eq!(
                    decoder.final_range(),
                    encoder.final_range(),
                    "frame {frame}: a downmixed stereo encoder desynchronised a mono decoder"
                );
                if frame > 0 {
                    energy += pcm
                        .iter()
                        .map(|&s| f64::from(s) * f64::from(s))
                        .sum::<f64>();
                }
            }
            energy
        };

        let in_phase = energy_of(1.0);
        let out_of_phase = energy_of(-1.0);
        assert!(in_phase > 0.0, "the in-phase pair decoded to silence");
        assert!(
            out_of_phase * 100.0 < in_phase,
            "an anti-phase pair must cancel in the downmix: {out_of_phase} vs {in_phase}"
        );
    }

    /// `set_prediction(0)` must make every frame stand alone — no prefilter, energy coded intra —
    /// which is what a redundancy frame bridging a mode switch needs. The bitstream must change and
    /// must still decode.
    #[test]
    fn disabling_prediction_changes_the_bitstream_and_still_decodes() {
        const FRAME: usize = 960;
        let source = signal(FRAME * 6, 0x9911);
        let run = |prediction: i32| -> Vec<Vec<u8>> {
            let mut encoder = CeltEncoder::new().expect("encoder");
            encoder.set_bitrate(48_000);
            encoder.set_rate_control(RateControl::Vbr);
            encoder.set_complexity(10).expect("complexity");
            encoder.set_prediction(prediction).expect("prediction");
            let mut decoder = CeltDecoder::new().expect("decoder");
            let mut packets = Vec::new();
            for frame in 0..6 {
                let mut buffer = [0u8; 400];
                let written = encoder
                    .encode(
                        &source[frame * FRAME..(frame + 1) * FRAME],
                        FRAME,
                        &mut buffer,
                    )
                    .expect("encode");
                let mut pcm = vec![0i16; FRAME];
                decoder
                    .decode(&buffer[..written], &mut pcm, FRAME)
                    .expect("decode");
                assert_eq!(
                    decoder.final_range(),
                    encoder.final_range(),
                    "frame {frame}"
                );
                packets.push(buffer[..written].to_vec());
            }
            packets
        };
        assert_ne!(run(2), run(0), "the prediction knob changed nothing");
        assert!(CeltEncoder::new()
            .expect("encoder")
            .set_prediction(3)
            .is_err());
        assert!(CeltEncoder::new()
            .expect("encoder")
            .set_prediction(-1)
            .is_err());
    }

    /// `reset_state` must leave the encoder exactly where a fresh one starts, or a mode switch
    /// inherits the previous mode's energy history and prefilter memory.
    #[test]
    fn resetting_state_matches_a_fresh_encoder() {
        const FRAME: usize = 960;
        let source = signal(FRAME * 8, 0x2468);
        let configure = |encoder: &mut CeltEncoder| {
            encoder.set_bitrate(48_000);
            encoder.set_rate_control(RateControl::Vbr);
        };

        let mut fresh = CeltEncoder::new().expect("encoder");
        configure(&mut fresh);

        let mut used = CeltEncoder::new().expect("encoder");
        configure(&mut used);
        for frame in 0..4 {
            let mut buffer = [0u8; 400];
            used.encode(
                &source[frame * FRAME..(frame + 1) * FRAME],
                FRAME,
                &mut buffer,
            )
            .expect("warm-up encode");
        }
        used.reset_state();

        for frame in 4..8 {
            let block = &source[frame * FRAME..(frame + 1) * FRAME];
            let mut a = [0u8; 400];
            let mut b = [0u8; 400];
            let written_a = fresh.encode(block, FRAME, &mut a).expect("fresh");
            let written_b = used.encode(block, FRAME, &mut b).expect("reset");
            assert_eq!(written_a, written_b, "frame {frame}: sizes diverged");
            assert_eq!(
                a[..written_a],
                b[..written_b],
                "frame {frame}: bytes diverged"
            );
        }
    }

    /// Band `start + 1` of a hybrid frame is **wider** than band `start`, so its fold source runs
    /// past the current band's own start in the norm buffer — which is exactly what
    /// `special_hybrid_folding` sets up. Every stereo path has to survive that, including the theta
    /// rate-distortion trials at complexity 10, which re-derive the fold source per trial.
    ///
    /// A regression here is an out-of-bounds index, not a quality loss, so the assertion is simply
    /// that a full sweep encodes.
    #[test]
    fn the_hybrid_fold_source_survives_every_stereo_path() {
        const FRAME: usize = 960;
        let mono = signal(FRAME * 6, 0xF01D);
        let mut interleaved = vec![0f32; FRAME * 6 * 2];
        for (index, &sample) in mono.iter().enumerate() {
            interleaved[2 * index] = sample;
            interleaved[2 * index + 1] = 0.6 * sample + 0.4 * mono[mono.len() - 1 - index];
        }

        for complexity in [5i32, 8, 10] {
            for &(bitrate, rate_control) in &[
                (24_000i32, RateControl::Vbr),
                (48_000, RateControl::ConstrainedVbr),
                (96_000, RateControl::ConstantBitrate),
            ] {
                for end in [19usize, NB_BANDS] {
                    let mut encoder = CeltEncoder::with_channels(2).expect("encoder");
                    encoder.set_bitrate(bitrate);
                    encoder.set_rate_control(rate_control);
                    encoder.set_complexity(complexity).expect("complexity");
                    encoder.set_band_range(17, end).expect("band range");
                    for frame in 0..6 {
                        let mut buffer = [0u8; 300];
                        let mut enc = RangeEncoder::new(&mut buffer);
                        fill_prefix(&mut enc, 400);
                        encoder
                            .encode_with_range_encoder(
                                &interleaved[frame * FRAME * 2..(frame + 1) * FRAME * 2],
                                FRAME,
                                &mut enc,
                                300,
                            )
                            .unwrap_or_else(|error| {
                                panic!(
                                    "complexity {complexity}, {bitrate} bit/s, end {end}, \
                                     frame {frame}: {error:?}"
                                )
                            });
                        enc.done();
                    }
                }
            }
        }
    }

    /// Illegal coded-channel counts must be rejected rather than silently coerced.
    #[test]
    fn illegal_coded_channel_counts_are_rejected() {
        let mut mono = CeltEncoder::new().expect("encoder");
        assert!(
            mono.set_stream_channels(2).is_err(),
            "mono has no second channel"
        );
        assert!(mono.set_stream_channels(0).is_err());
        assert_eq!(mono.stream_channels(), 1);

        let mut stereo = CeltEncoder::with_channels(2).expect("encoder");
        assert!(stereo.set_stream_channels(1).is_ok());
        assert_eq!(stereo.stream_channels(), 1);
        assert!(stereo.set_stream_channels(2).is_ok());
        assert!(stereo.set_stream_channels(3).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::celt::decoder::CeltDecoder;

    /// A deterministic test signal: a few harmonics plus a little noise, so the analysis has
    /// something real to decide about. No `Instant::now()`, no `rand`.
    fn test_signal(samples: usize, seed: u32) -> Vec<f32> {
        let mut state = seed | 1;
        (0..samples)
            .map(|i| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let noise = ((state >> 16) as f32 / 32768.0 - 1.0) * 0.02;
                let t = i as f32;
                0.35 * (t * 0.031).sin()
                    + 0.18 * (t * 0.097).sin()
                    + 0.07 * (t * 0.21).cos()
                    + noise
            })
            .collect()
    }

    /// A signal with a hard onset partway through, to force the transient path.
    fn transient_signal(samples: usize) -> Vec<f32> {
        (0..samples)
            .map(|i| {
                let amp = if i < samples / 2 { 0.005 } else { 0.7 };
                (i as f32 * 0.13).sin() * amp
            })
            .collect()
    }

    /// **The self-consistency gate.** Our decoder must end every encoded packet on exactly the
    /// `final_range` our encoder produced. Encoder and decoder disagreeing on the entropy state is a
    /// bug in one of them, and this localises it to the packet that caused it. Swept over every frame
    /// size, every bandwidth (which changes the coded band count), a wide bitrate spread, and all
    /// three rate-control modes.
    #[test]
    fn encoder_and_decoder_agree_on_final_range() {
        let bandwidths = [
            Bandwidth::Narrowband,
            Bandwidth::Wideband,
            Bandwidth::SuperWideband,
            Bandwidth::Fullband,
        ];
        for &frame_size in &[120usize, 240, 480, 960] {
            for &bandwidth in &bandwidths {
                for &bitrate in &[6_000i32, 24_000, 64_000, 128_000, 400_000] {
                    for &rate_control in &[
                        RateControl::ConstantBitrate,
                        RateControl::ConstrainedVbr,
                        RateControl::Vbr,
                    ] {
                        let end = CeltEncoder::end_band_for_bandwidth(bandwidth);
                        let mut encoder = CeltEncoder::new().expect("build encoder");
                        encoder.set_bitrate(bitrate);
                        encoder.set_rate_control(rate_control);
                        encoder.set_band_range(0, end).expect("band range");
                        let mut decoder = CeltDecoder::new().expect("build decoder");
                        decoder.set_band_range(0, end).expect("band range");

                        let frames = 6usize;
                        let signal = test_signal(frames * frame_size, 0xF00D + frame_size as u32);
                        let mut payload = vec![0u8; MAX_PACKET_BYTES];
                        let mut pcm = vec![0i16; frame_size];

                        for frame in 0..frames {
                            let lo = frame * frame_size;
                            let written = encoder
                                .encode(&signal[lo..lo + frame_size], frame_size, &mut payload)
                                .expect("encode");
                            assert!(
                                (2..=MAX_PACKET_BYTES).contains(&written),
                                "frame={frame}: wrote {written} bytes"
                            );
                            let decoded = decoder
                                .decode(&payload[..written], &mut pcm, frame_size)
                                .expect("decode our own packet");
                            assert_eq!(decoded, frame_size);
                            assert_eq!(
                                decoder.final_range(),
                                encoder.final_range(),
                                "frame_size={frame_size} bw={bandwidth:?} rate={bitrate} \
                                 rc={rate_control:?} frame={frame}: final_range diverged \
                                 (packet was {written} bytes)"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Interleave two mono signals into one stereo buffer.
    fn interleave(left: &[f32], right: &[f32]) -> Vec<f32> {
        left.iter().zip(right).flat_map(|(&l, &r)| [l, r]).collect()
    }

    /// The same entropy-state gate for **stereo**, over the whole matrix: 4 bandwidths × 4 frame
    /// sizes × a bitrate spread from "intensity stereo everywhere" to "true stereo everywhere" ×
    /// all three rate-control modes × complexity 5 and 10 (the latter turning on the theta
    /// rate-distortion trial and the second MDCT), on both a correlated and an uncorrelated pair.
    /// A stereo desync — a missed `theta`, a wrong inversion flag, a mis-restored trial — cannot
    /// survive this.
    #[test]
    fn stereo_encoder_and_decoder_agree_on_final_range() {
        let bandwidths = [
            Bandwidth::Narrowband,
            Bandwidth::Wideband,
            Bandwidth::SuperWideband,
            Bandwidth::Fullband,
        ];
        for &frame_size in &[120usize, 240, 480, 960] {
            for &bandwidth in &bandwidths {
                for &bitrate in &[6_000i32, 24_000, 64_000, 128_000, 400_000] {
                    for &rate_control in &[
                        RateControl::ConstantBitrate,
                        RateControl::ConstrainedVbr,
                        RateControl::Vbr,
                    ] {
                        for &complexity in &[5i32, 10] {
                            for &correlated in &[true, false] {
                                let end = CeltEncoder::end_band_for_bandwidth(bandwidth);
                                let mut encoder =
                                    CeltEncoder::with_channels(2).expect("build encoder");
                                encoder.set_bitrate(bitrate);
                                encoder.set_rate_control(rate_control);
                                encoder.set_complexity(complexity).expect("complexity");
                                encoder.set_band_range(0, end).expect("band range");
                                let mut decoder =
                                    CeltDecoder::with_channels(2).expect("build decoder");
                                decoder.set_band_range(0, end).expect("band range");

                                let frames = 6usize;
                                let samples = frames * frame_size;
                                let left = test_signal(samples, 0xF00D + frame_size as u32);
                                let right = if correlated {
                                    // A slightly delayed, attenuated copy: strongly mid-dominant.
                                    let mut r = vec![0f32; samples];
                                    r[3..].copy_from_slice(&left[..samples - 3]);
                                    r.iter().map(|v| v * 0.8).collect()
                                } else {
                                    test_signal(samples, 0x5A5A + frame_size as u32)
                                };
                                let signal = interleave(&left, &right);
                                let mut payload = vec![0u8; MAX_PACKET_BYTES];
                                let mut pcm = vec![0i16; 2 * frame_size];

                                for frame in 0..frames {
                                    let lo = 2 * frame * frame_size;
                                    let written = encoder
                                        .encode(
                                            &signal[lo..lo + 2 * frame_size],
                                            frame_size,
                                            &mut payload,
                                        )
                                        .expect("encode");
                                    assert!(
                                        (2..=MAX_PACKET_BYTES).contains(&written),
                                        "frame={frame}: wrote {written} bytes"
                                    );
                                    let decoded = decoder
                                        .decode(&payload[..written], &mut pcm, frame_size)
                                        .expect("decode our own packet");
                                    assert_eq!(decoded, frame_size);
                                    assert_eq!(
                                        decoder.final_range(),
                                        encoder.final_range(),
                                        "frame_size={frame_size} bw={bandwidth:?} rate={bitrate} \
                                         rc={rate_control:?} complexity={complexity} \
                                         correlated={correlated} frame={frame}: final_range \
                                         diverged (packet was {written} bytes)"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// A stereo encode must actually carry both channels: at a rate high enough to keep the bands in
    /// true stereo, two *uncorrelated* inputs must come back as two distinguishable outputs, each
    /// correlating with its own source. A mid-only coder (or a swapped channel) fails this.
    #[test]
    fn stereo_round_trip_keeps_the_channels_apart() {
        let frame_size = 960usize;
        let frames = 12usize;
        let samples = frames * frame_size;
        let mut encoder = CeltEncoder::with_channels(2).expect("build");
        encoder.set_bitrate(160_000);
        let mut decoder = CeltDecoder::with_channels(2).expect("build");
        let left = test_signal(samples, 0x1357);
        // A different harmonic set, so the two channels are genuinely independent.
        let right: Vec<f32> = (0..samples)
            .map(|i| {
                let t = i as f32;
                0.3 * (t * 0.017).sin() + 0.2 * (t * 0.143).cos()
            })
            .collect();
        let signal = interleave(&left, &right);
        let mut payload = vec![0u8; MAX_PACKET_BYTES];
        let mut pcm = vec![0i16; 2 * frame_size];
        let mut out_left = Vec::with_capacity(samples);
        let mut out_right = Vec::with_capacity(samples);
        for frame in 0..frames {
            let lo = 2 * frame * frame_size;
            let written = encoder
                .encode(&signal[lo..lo + 2 * frame_size], frame_size, &mut payload)
                .expect("encode");
            decoder
                .decode(&payload[..written], &mut pcm, frame_size)
                .expect("decode");
            for pair in pcm.chunks_exact(2) {
                out_left.push(f32::from(pair[0]) / 32768.0);
                out_right.push(f32::from(pair[1]) / 32768.0);
            }
        }
        // Skip the start-up frames, then align on the best lag within one overlap.
        let skip = 2 * frame_size;
        let best_correlation = |reference: &[f32], decoded: &[f32]| -> f32 {
            (0..=OVERLAP)
                .map(|lag| {
                    let a = &reference[skip..reference.len() - OVERLAP];
                    let b = &decoded[skip + lag..skip + lag + a.len()];
                    let dot: f32 = a.iter().zip(b).map(|(p, q)| p * q).sum();
                    let na = a.iter().map(|v| v * v).sum::<f32>().sqrt();
                    let nb = b.iter().map(|v| v * v).sum::<f32>().sqrt();
                    if na * nb > 0.0 {
                        dot / (na * nb)
                    } else {
                        0.0
                    }
                })
                .fold(f32::MIN, f32::max)
        };
        let left_own = best_correlation(&left, &out_left);
        let right_own = best_correlation(&right, &out_right);
        let left_cross = best_correlation(&right, &out_left);
        let right_cross = best_correlation(&left, &out_right);
        assert!(left_own > 0.8, "left channel correlates only {left_own}");
        assert!(right_own > 0.8, "right channel correlates only {right_own}");
        assert!(
            left_own > left_cross + 0.3 && right_own > right_cross + 0.3,
            "channels are not separated: own {left_own}/{right_own} vs cross \
             {left_cross}/{right_cross}"
        );
    }

    /// Mono and stereo are separate constructions, and the channel count must be validated.
    #[test]
    fn channel_count_is_validated() {
        assert_eq!(CeltEncoder::new().expect("mono").channels(), 1);
        assert_eq!(CeltEncoder::with_channels(2).expect("stereo").channels(), 2);
        assert!(CeltEncoder::with_channels(0).is_err());
        assert!(CeltEncoder::with_channels(3).is_err());
        assert_eq!(CeltDecoder::new().expect("mono").channels(), 1);
        assert_eq!(CeltDecoder::with_channels(2).expect("stereo").channels(), 2);
        assert!(CeltDecoder::with_channels(0).is_err());
        assert!(CeltDecoder::with_channels(3).is_err());
        // A stereo encode needs interleaved input of `2 * frame_size`.
        let mut encoder = CeltEncoder::with_channels(2).expect("stereo");
        let mut out = vec![0u8; 200];
        assert!(matches!(
            encoder.encode(&vec![0f32; 960], 960, &mut out),
            Err(CodecError::OutputTooSmall { .. })
        ));
    }

    /// The same gate on a transient input, which takes the short-block path (and therefore the
    /// anti-collapse reservation, the Haar recombination and the uniform theta pdf).
    #[test]
    fn transient_frames_also_agree_on_final_range() {
        for &frame_size in &[240usize, 480, 960] {
            let mut encoder = CeltEncoder::new().expect("build");
            encoder.set_bitrate(48_000);
            let mut decoder = CeltDecoder::new().expect("build");
            let frames = 8usize;
            let mut payload = vec![0u8; MAX_PACKET_BYTES];
            let mut pcm = vec![0i16; frame_size];
            for frame in 0..frames {
                // Alternate quiet and loud so every frame has an onset or an offset.
                let signal = if frame % 2 == 0 {
                    transient_signal(frame_size)
                } else {
                    let mut s = transient_signal(frame_size);
                    s.reverse();
                    s
                };
                let written = encoder
                    .encode(&signal, frame_size, &mut payload)
                    .expect("encode");
                decoder
                    .decode(&payload[..written], &mut pcm, frame_size)
                    .expect("decode");
                assert_eq!(
                    decoder.final_range(),
                    encoder.final_range(),
                    "frame_size={frame_size} frame={frame}: final_range diverged"
                );
            }
        }
    }

    /// Silence must produce the minimum packet and still round-trip the entropy state.
    #[test]
    fn silence_encodes_to_a_minimal_packet() {
        for &rate_control in &[RateControl::ConstantBitrate, RateControl::Vbr] {
            let frame_size = 960usize;
            let mut encoder = CeltEncoder::new().expect("build");
            encoder.set_bitrate(32_000);
            encoder.set_rate_control(rate_control);
            let mut decoder = CeltDecoder::new().expect("build");
            let silence = vec![0f32; frame_size];
            let mut payload = vec![0u8; MAX_PACKET_BYTES];
            let mut pcm = vec![0i16; frame_size];
            let written = encoder
                .encode(&silence, frame_size, &mut payload)
                .expect("encode silence");
            if rate_control != RateControl::ConstantBitrate {
                assert_eq!(written, 2, "VBR silence must be 2 bytes, got {written}");
            }
            decoder
                .decode(&payload[..written], &mut pcm, frame_size)
                .expect("decode silence");
            assert_eq!(decoder.final_range(), encoder.final_range());
            assert!(
                pcm.iter().all(|&s| s.abs() < 64),
                "silence decoded loud: max {}",
                pcm.iter().map(|s| s.abs()).max().unwrap_or(0)
            );
        }
    }

    /// The decoded audio must actually resemble the input — bit agreement alone would also hold for
    /// an encoder that coded the wrong spectrum. Measured as segmental correlation, which tolerates
    /// the codec's own delay-free but lossy reconstruction.
    #[test]
    fn decoded_audio_correlates_with_the_input_at_a_useful_rate() {
        let frame_size = 960usize;
        let frames = 12usize;
        let mut encoder = CeltEncoder::new().expect("build");
        encoder.set_bitrate(96_000);
        let mut decoder = CeltDecoder::new().expect("build");
        let signal = test_signal(frames * frame_size, 0x1357);
        let mut payload = vec![0u8; MAX_PACKET_BYTES];
        let mut decoded = Vec::with_capacity(frames * frame_size);
        let mut pcm = vec![0i16; frame_size];
        for frame in 0..frames {
            let lo = frame * frame_size;
            let written = encoder
                .encode(&signal[lo..lo + frame_size], frame_size, &mut payload)
                .expect("encode");
            decoder
                .decode(&payload[..written], &mut pcm, frame_size)
                .expect("decode");
            decoded.extend(pcm.iter().map(|&s| f32::from(s) / 32768.0));
        }
        // CELT's total delay is the MDCT overlap; skip the first two frames (start-up) and align on
        // the best lag within one overlap.
        let skip = 2 * frame_size;
        let reference = &signal[skip..];
        let best = (0..=OVERLAP)
            .map(|lag| {
                let a = &reference[..reference.len() - OVERLAP];
                let b = &decoded[skip + lag..skip + lag + a.len()];
                let dot: f32 = a.iter().zip(b).map(|(p, q)| p * q).sum();
                let na = a.iter().map(|v| v * v).sum::<f32>().sqrt();
                let nb = b.iter().map(|v| v * v).sum::<f32>().sqrt();
                if na * nb > 0.0 {
                    dot / (na * nb)
                } else {
                    0.0
                }
            })
            .fold(f32::MIN, f32::max);
        assert!(
            best > 0.8,
            "decoded audio only correlates {best} with the input at 96 kb/s"
        );
    }

    /// Rate control must actually control the rate: a higher target must produce bigger packets, CBR
    /// must produce exactly the target size, and `max_payload` must be respected.
    #[test]
    fn rate_control_hits_its_target() {
        let frame_size = 960usize; // 20 ms → 50 frames/s
        let frames = 20usize;
        let signal = test_signal(frames * frame_size, 0x2468);

        let mut sizes = Vec::new();
        for &bitrate in &[16_000i32, 32_000, 64_000, 128_000] {
            let mut encoder = CeltEncoder::new().expect("build");
            encoder.set_bitrate(bitrate);
            let mut payload = vec![0u8; MAX_PACKET_BYTES];
            let mut total = 0usize;
            for frame in 0..frames {
                let lo = frame * frame_size;
                let written = encoder
                    .encode(&signal[lo..lo + frame_size], frame_size, &mut payload)
                    .expect("encode");
                // CBR: exactly bitrate/8/50 bytes per frame.
                assert_eq!(
                    written,
                    (bitrate / 8 / 50) as usize,
                    "CBR at {bitrate}: frame {frame} was {written} bytes"
                );
                total += written;
            }
            sizes.push(total);
        }
        for w in sizes.windows(2) {
            assert!(
                w[1] > w[0],
                "packet size did not grow with the target: {sizes:?}"
            );
        }

        // Constrained VBR must average near the target over a run of frames.
        let target = 48_000i32;
        let mut encoder = CeltEncoder::new().expect("build");
        encoder.set_bitrate(target);
        encoder.set_rate_control(RateControl::ConstrainedVbr);
        let mut payload = vec![0u8; MAX_PACKET_BYTES];
        let mut total = 0usize;
        for frame in 0..frames {
            let lo = frame * frame_size;
            total += encoder
                .encode(&signal[lo..lo + frame_size], frame_size, &mut payload)
                .expect("encode");
        }
        let achieved = (total * 8 * 50 / frames) as i32;
        assert!(
            (achieved - target).abs() < target / 2,
            "constrained VBR achieved {achieved} bit/s for a {target} target"
        );

        // `max_payload` is the hard ceiling: a tiny output buffer must never be overrun.
        let mut encoder = CeltEncoder::new().expect("build");
        encoder.set_bitrate(400_000);
        let mut small = [0u8; 20];
        let written = encoder
            .encode(&signal[..frame_size], frame_size, &mut small)
            .expect("encode into a small buffer");
        assert!(written <= 20, "wrote {written} into a 20-byte buffer");
    }

    /// Every knob must change the bitstream (no decorative options).
    #[test]
    fn every_knob_changes_the_bitstream() {
        let frame_size = 480usize;
        let signal = test_signal(frame_size * 4, 0x99);
        let encode_all = |configure: &dyn Fn(&mut CeltEncoder)| -> Vec<u8> {
            let mut encoder = CeltEncoder::new().expect("build");
            encoder.set_bitrate(48_000);
            configure(&mut encoder);
            let mut out = Vec::new();
            let mut payload = vec![0u8; MAX_PACKET_BYTES];
            for frame in 0..4 {
                let lo = frame * frame_size;
                let written = encoder
                    .encode(&signal[lo..lo + frame_size], frame_size, &mut payload)
                    .expect("encode");
                out.extend_from_slice(&payload[..written]);
            }
            out
        };
        let baseline = encode_all(&|_| {});
        assert_ne!(
            baseline,
            encode_all(&|e| {
                e.set_complexity(0).expect("complexity");
            }),
            "complexity had no effect on the bitstream"
        );
        assert_ne!(
            baseline,
            encode_all(&|e| e.set_bitrate(96_000)),
            "bitrate had no effect"
        );
        assert_ne!(
            baseline,
            encode_all(&|e| e.set_rate_control(RateControl::Vbr)),
            "rate control had no effect"
        );
        assert_ne!(
            baseline,
            encode_all(&|e| e.set_force_intra(true)),
            "force_intra had no effect"
        );
        // `lsb_depth` raises the dynalloc noise floor, so it only binds when band energies are near
        // that floor — i.e. on a *quiet* input. Encode one at both depths.
        let quiet: Vec<f32> = test_signal(frame_size * 4, 0x99)
            .iter()
            .map(|v| v * 0.0008)
            .collect();
        let encode_quiet = |depth: i32| -> Vec<u8> {
            let mut encoder = CeltEncoder::new().expect("build");
            encoder.set_bitrate(48_000);
            encoder.set_rate_control(RateControl::Vbr);
            encoder.set_lsb_depth(depth).expect("lsb depth");
            let mut out = Vec::new();
            let mut payload = vec![0u8; MAX_PACKET_BYTES];
            for frame in 0..4 {
                let lo = frame * frame_size;
                let written = encoder
                    .encode(&quiet[lo..lo + frame_size], frame_size, &mut payload)
                    .expect("encode");
                out.extend_from_slice(&payload[..written]);
            }
            out
        };
        assert_ne!(
            encode_quiet(24),
            encode_quiet(8),
            "lsb_depth had no effect on the bitstream"
        );
        assert_ne!(
            baseline,
            encode_all(&|e| {
                e.set_loss_rate(20).expect("loss rate");
            }),
            "loss_rate had no effect"
        );
        assert_ne!(
            baseline,
            encode_all(&|e| {
                e.set_band_range(0, 13).expect("band range");
            }),
            "band range had no effect"
        );
    }

    /// `force_intra` must make the *first* frame decodable on its own: an intra frame carries no
    /// inter-frame energy prediction, so a decoder starting there reconstructs the same energies.
    #[test]
    fn force_intra_makes_a_frame_self_contained() {
        let frame_size = 960usize;
        let signal = test_signal(frame_size * 4, 0x7777);
        let mut encoder = CeltEncoder::new().expect("build");
        encoder.set_bitrate(64_000);
        let mut payload = vec![0u8; MAX_PACKET_BYTES];
        let mut packets = Vec::new();
        for frame in 0..4 {
            if frame == 2 {
                encoder.set_force_intra(true);
            }
            let lo = frame * frame_size;
            let written = encoder
                .encode(&signal[lo..lo + frame_size], frame_size, &mut payload)
                .expect("encode");
            packets.push(payload[..written].to_vec());
        }
        // Decode from the intra frame onward with a *fresh* decoder; the entropy state must match
        // what the encoder had for those packets (the intra frame does not predict from frame 1).
        let mut decoder = CeltDecoder::new().expect("build");
        let mut pcm = vec![0i16; frame_size];
        decoder
            .decode(&packets[2], &mut pcm, frame_size)
            .expect("decode the intra frame standalone");
        assert!(
            pcm.iter().any(|&s| s != 0),
            "the intra frame decoded to silence"
        );
    }

    #[test]
    fn rejects_bad_arguments() {
        let mut encoder = CeltEncoder::new().expect("build");
        let mut out = vec![0u8; 100];
        let pcm = vec![0f32; 960];
        // 200 samples is not 120/240/480/960.
        assert!(matches!(
            encoder.encode(&pcm, 200, &mut out),
            Err(CodecError::BadFrameSize { .. })
        ));
        // A PCM slice shorter than the frame.
        assert!(matches!(
            encoder.encode(&pcm[..100], 960, &mut out),
            Err(CodecError::OutputTooSmall { .. })
        ));
        // A payload buffer under 2 bytes.
        let mut tiny = [0u8; 1];
        assert!(matches!(
            encoder.encode(&pcm, 960, &mut tiny),
            Err(CodecError::OutputTooSmall { .. })
        ));
        assert!(encoder.set_complexity(11).is_err());
        assert!(encoder.set_complexity(-1).is_err());
        assert!(encoder.set_loss_rate(101).is_err());
        assert!(encoder.set_lsb_depth(4).is_err());
        assert!(encoder.set_band_range(0, NB_BANDS + 1).is_err());
        assert!(encoder.set_band_range(10, 4).is_err());
    }

    #[test]
    fn end_band_matches_the_decoder() {
        for bandwidth in [
            Bandwidth::Narrowband,
            Bandwidth::Mediumband,
            Bandwidth::Wideband,
            Bandwidth::SuperWideband,
            Bandwidth::Fullband,
        ] {
            assert_eq!(
                CeltEncoder::end_band_for_bandwidth(bandwidth),
                CeltDecoder::end_band_for_bandwidth(bandwidth),
                "{bandwidth:?}: encoder and decoder disagree on the band count"
            );
        }
    }
}
