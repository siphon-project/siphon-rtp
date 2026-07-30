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
//! Scope, stated plainly: **mono, CELT-only, no `ENABLE_QEXT`, no surround energy mask, no
//! `AnalysisInfo` tonality estimator, no LFE mode.** Those are separate libopus features (the last
//! two live above CELT, in `opus_encoder.c`/`analysis.c`) and are absent rather than half-wired. The
//! `C == 2` paths (stereo analysis, dual stereo, intensity, the theta rate-distortion trial) are
//! absent for the same reason the decoder is mono — see the scope note on
//! [`band_coder`](crate::opus::celt::band_coder).
//!
//! Line references cite `celt/celt_encoder.c` from the libopus tree this was ported against.

use crate::opus::celt::analysis::{
    alloc_trim_analysis, dynalloc_analysis, patch_transient_decision, spreading_decision,
    tf_analysis, transient_analysis,
};
use crate::opus::celt::band_analysis::{
    amp2_log2, celt_preemphasis, compute_band_energies, normalise_bands,
};
use crate::opus::celt::band_coder::quant_all_bands;
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

/// The 48 kHz CELT mode is always mono here (`C = CC = 1`).
const CHANNELS: usize = 1;
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
    /// Pre-emphasis 1-pole memory (`st->preemph_memE`), persists across frames.
    preemph_mem: f32,
    /// Constrained-VBR reservoir / drift / offset and frame count (`st->vbr_*`).
    vbr_reservoir: i32,
    vbr_drift: i32,
    vbr_offset: i32,
    vbr_count: i32,
    /// Peak sample of the previous frame's overlap region (`st->overlap_max`).
    overlap_max: f32,
    /// Running spectral average for the temporal-VBR term (`st->spec_avg`).
    spec_avg: f32,
    /// Previous frame's per-band log2 energy (`oldBandE`), `2*NB_BANDS`.
    old_band_energy: [f32; 2 * NB_BANDS],
    /// Energy one and two frames back (`oldLogE`, `oldLogE2`); reset to `-28 dB`.
    old_log_energy: [f32; 2 * NB_BANDS],
    old_log_energy2: [f32; 2 * NB_BANDS],
    /// Residual coarse-energy error per band (`energyError`), used to bias the next frame.
    energy_error: [f32; 2 * NB_BANDS],
    /// The overlap tail of the pre-emphasised input (`st->in_mem`).
    in_mem: [f32; OVERLAP],
    /// Prefilter history (`prefilter_mem`), `COMBFILTER_MAXPERIOD` samples.
    prefilter_mem: [f32; COMBFILTER_MAXPERIOD],
    /// First coded band (`st->start`) — 0 for CELT-only.
    start_band: usize,
    /// One past the last coded band (`st->end`), from the target bandwidth.
    end_band: usize,
}

impl CeltEncoder {
    /// Construct a fresh mono CELT encoder in the reset state (libopus
    /// `opus_custom_encoder_init_arch` + `OPUS_RESET_STATE`, `celt_encoder.c:166`).
    pub fn new() -> Result<Self, CodecError> {
        let mdct = MdctLookup::new(MDCT_BASE_LEN, MAX_LM)
            .map_err(|_| CodecError::Unsupported("celt: failed to build 48 kHz MDCT lookup"))?;
        Ok(Self {
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
            preemph_mem: 0.0,
            vbr_reservoir: 0,
            vbr_drift: 0,
            vbr_offset: 0,
            vbr_count: 0,
            overlap_max: 0.0,
            spec_avg: 0.0,
            old_band_energy: [0.0; 2 * NB_BANDS],
            old_log_energy: [ENERGY_RESET_DB; 2 * NB_BANDS],
            old_log_energy2: [ENERGY_RESET_DB; 2 * NB_BANDS],
            energy_error: [0.0; 2 * NB_BANDS],
            in_mem: [0.0; OVERLAP],
            prefilter_mem: [0.0; COMBFILTER_MAXPERIOD],
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

    /// Encode one mono CELT-only frame.
    ///
    /// `pcm` holds `frame_size` samples nominally in `[-1, 1)`; `frame_size` must be 120/240/480/960
    /// (2.5/5/10/20 ms at 48 kHz). `output` is the caller-owned payload buffer — its length is the
    /// hard ceiling on the packet (`max_payload`), clamped to 1275 bytes. Returns the number of
    /// bytes written.
    #[allow(clippy::too_many_lines)]
    // The per-band loops index parallel per-band arrays with the reference's own `i`; rewriting each
    // as an iterator would obscure which `celt_encoder.c` loop it corresponds to.
    #[allow(clippy::needless_range_loop)]
    pub fn encode(
        &mut self,
        pcm: &[f32],
        frame_size: usize,
        output: &mut [u8],
    ) -> Result<usize, CodecError> {
        // ── Frame size → LM (celt_encoder.c:1520) ────────────────────────────────────────────────
        let lm = (0..=MAX_LM)
            .find(|&candidate| (SHORT_MDCT_SIZE << candidate) == frame_size)
            .ok_or(CodecError::BadFrameSize {
                expected: MAX_FRAME_SAMPLES,
                got: frame_size,
            })?;
        let m = 1usize << lm;
        let n = m * SHORT_MDCT_SIZE;
        if pcm.len() < n {
            return Err(CodecError::OutputTooSmall {
                needed: n,
                have: pcm.len(),
            });
        }
        // libopus rejects a target under 2 bytes outright (celt_encoder.c:1513).
        if output.len() < 2 {
            return Err(CodecError::OutputTooSmall {
                needed: 2,
                have: output.len(),
            });
        }

        let start = self.start_band;
        let end = self.end_band;
        let eff_end = end.min(NB_BANDS);

        // "Can't produce more than 1275 output bytes" (celt_encoder.c:1574).
        let max_payload = output.len().min(MAX_PACKET_BYTES);
        let mut nb_compressed_bytes = max_payload as i32;

        // ── Rate control: target size and the VBR budget (celt_encoder.c:1577) ───────────────────
        let vbr = self.rate_control != RateControl::ConstantBitrate;
        let constrained_vbr = self.rate_control == RateControl::ConstrainedVbr;
        let mut vbr_rate = 0i32;
        let effective_bytes;
        if vbr && self.bitrate > 0 {
            let den = SAMPLE_RATE >> BITRES;
            vbr_rate = (self.bitrate * frame_size as i32 + (den >> 1)) / den;
            effective_bytes = vbr_rate >> (3 + BITRES);
        } else {
            if self.bitrate > 0 {
                // CBR: the packet is exactly the target size for this frame duration.
                let tmp = self.bitrate * frame_size as i32;
                nb_compressed_bytes = nb_compressed_bytes
                    .min((tmp + 4 * SAMPLE_RATE) / (8 * SAMPLE_RATE))
                    .max(2);
            }
            effective_bytes = nb_compressed_bytes;
        }
        // "equiv_rate" — the rate a 20 ms frame would need for the same quality
        // (celt_encoder.c:1600).
        let mut equiv_rate = ((nb_compressed_bytes * 8 * 50) << (3 - lm))
            - (40 * CHANNELS as i32 + 20) * ((400 >> lm) - 50);
        if self.bitrate > 0 {
            equiv_rate =
                equiv_rate.min(self.bitrate - (40 * CHANNELS as i32 + 20) * ((400 >> lm) - 50));
        }

        let mut encoder_buffer = [0u8; MAX_PACKET_BYTES];
        let mut enc = RangeEncoder::new(&mut encoder_buffer[..nb_compressed_bytes as usize]);

        if vbr_rate > 0 && constrained_vbr {
            // "Computes the max bit-rate allowed in VBR mode to avoid violating the target rate and
            // buffering. We must do this up front so that bust-prevention logic triggers correctly
            // if we don't have enough bits." (celt_encoder.c:1612)
            let vbr_bound = vbr_rate;
            let max_allowed = (2i32)
                .max((vbr_rate + vbr_bound - self.vbr_reservoir) >> (BITRES + 3))
                .min(nb_compressed_bytes);
            if max_allowed < nb_compressed_bytes {
                nb_compressed_bytes = max_allowed;
                enc.shrink(nb_compressed_bytes as u32);
            }
        }
        let mut total_bits = nb_compressed_bytes * 8;

        // ── Silence detection + flag (celt_encoder.c:1644) ───────────────────────────────────────
        let head = n.saturating_sub(OVERLAP);
        let sample_max = self
            .overlap_max
            .max(peak_abs(&pcm[..head]))
            .max(peak_abs(&pcm[head..n]));
        self.overlap_max = peak_abs(&pcm[head..n]);
        let silence = sample_max <= 1.0 / (1 << self.lsb_depth) as f32;
        enc.enc_bit_logp(silence, 15);
        if silence {
            // "In VBR mode there is no need to send more than the minimum."
            if vbr_rate > 0 {
                nb_compressed_bytes = nb_compressed_bytes.min(2);
                total_bits = nb_compressed_bytes * 8;
                enc.shrink(nb_compressed_bytes as u32);
            }
            // "Pretend we've filled all the remaining bits with zeros."
            enc.declare_bits_used(total_bits);
        }

        // ── Pre-emphasis (celt_encoder.c:1675) ───────────────────────────────────────────────────
        // `in` layout: [overlap tail of the previous frame][this frame's N samples].
        let mut input = [0f32; MAX_IN_LEN];
        let need_clip = self.clip && sample_max > 2.0;
        celt_preemphasis(
            pcm,
            &mut input[OVERLAP..OVERLAP + n],
            n,
            CHANNELS,
            0,
            PREEMPH[0],
            &mut self.preemph_mem,
            need_clip,
        );

        // ── Prefilter: pitch period + gain, and the comb applied to the input (celt_encoder.c:1686)
        let prefilter_enabled = nb_compressed_bytes > 12 * CHANNELS as i32
            && !silence
            && self.complexity >= 5
            && start == 0;
        let prefilter_tapset = self.tapset_decision;
        let (pf_on, pitch_index, gain1, qg) = self.run_prefilter(
            &mut input,
            n,
            prefilter_tapset,
            prefilter_enabled,
            nb_compressed_bytes,
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
        } else if start == 0 && enc.tell() + 16 <= total_bits {
            enc.enc_bit_logp(false, 1);
        }

        // ── Transient analysis (celt_encoder.c:1717) ─────────────────────────────────────────────
        let mut transient = if self.complexity >= 1 {
            transient_analysis(&input, n + OVERLAP, CHANNELS, false)
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
        let mut freq = [0f32; MAX_FRAME_SAMPLES];
        let mut band_e = [0f32; 2 * NB_BANDS];
        let mut band_log_e = [0f32; 2 * NB_BANDS];
        let mut band_log_e2 = [0f32; 2 * NB_BANDS];

        // "secondMdct": at high complexity, measure the long-block energy too so dynalloc sees the
        // pre-transient spectrum (celt_encoder.c:1741).
        let second_mdct = short_blocks && self.complexity >= 8;
        if second_mdct {
            self.compute_mdcts(false, &input, &mut freq, lm, n);
            compute_band_energies(&freq, &mut band_e, eff_end, CHANNELS, lm);
            amp2_log2(&band_e, &mut band_log_e2, eff_end, end, CHANNELS);
            for i in 0..end {
                band_log_e2[i] += 0.5 * lm as f32;
            }
        }

        self.compute_mdcts(short_blocks, &input, &mut freq, lm, n);
        compute_band_energies(&freq, &mut band_e, eff_end, CHANNELS, lm);
        amp2_log2(&band_e, &mut band_log_e, eff_end, end, CHANNELS);

        // Temporal VBR: how loud this frame is versus the running average (celt_encoder.c:1850).
        let temporal_vbr;
        {
            let mut follow = -10.0f32;
            let mut frame_avg = 0f32;
            let offset = if short_blocks { 0.5 * lm as f32 } else { 0.0 };
            for i in start..end {
                follow = (follow - 1.0).max(band_log_e[i] - offset);
                frame_avg += follow;
            }
            if end > start {
                frame_avg /= (end - start) as f32;
            }
            temporal_vbr = (frame_avg - self.spec_avg).clamp(-1.5, 3.0);
            self.spec_avg += 0.02 * temporal_vbr;
        }

        if !second_mdct {
            band_log_e2[..CHANNELS * NB_BANDS].copy_from_slice(&band_log_e[..CHANNELS * NB_BANDS]);
        }

        // "Last chance to catch any transient we might have missed in the time-domain analysis"
        // (celt_encoder.c:1876).
        if lm > 0
            && enc.tell() + 3 <= total_bits
            && !transient.is_transient
            && self.complexity >= 5
            && patch_transient_decision(&band_log_e, &self.old_band_energy, start, end)
        {
            transient.is_transient = true;
            short_blocks = true;
            self.compute_mdcts(true, &input, &mut freq, lm, n);
            compute_band_energies(&freq, &mut band_e, eff_end, CHANNELS, lm);
            amp2_log2(&band_e, &mut band_log_e, eff_end, end, CHANNELS);
            // Compensate for the scaling of short vs long MDCTs.
            for i in 0..end {
                band_log_e2[i] += 0.5 * lm as f32;
            }
            transient.tf_estimate = 0.2;
        }
        if lm > 0 && enc.tell() + 3 <= total_bits {
            enc.enc_bit_logp(transient.is_transient, 3);
        }

        // ── Band normalisation (celt_encoder.c:1903) ─────────────────────────────────────────────
        let mut x = [0f32; MAX_FRAME_SAMPLES];
        normalise_bands(&freq, &mut x, &band_e, eff_end, CHANNELS, m);

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
        let enable_tf_analysis = effective_bytes >= 15 * CHANNELS as i32 && self.complexity >= 2;
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
        } else {
            for i in 0..end {
                tf_res[i] = i32::from(transient.is_transient);
            }
            0
        };

        // ── Coarse energy (celt_encoder.c:1944) ──────────────────────────────────────────────────
        let mut error = [0f32; 2 * NB_BANDS];
        for i in start..end {
            // "When the energy is stable, slightly bias energy quantization towards the previous
            // error to make the gain more stable (a constant offset is better than fluctuations)."
            if (band_log_e[i] - self.old_band_energy[i]).abs() < 2.0 {
                band_log_e[i] -= 0.25 * self.energy_error[i];
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
            &mut enc,
            CHANNELS,
            lm,
            nb_compressed_bytes,
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
            &mut enc,
        );

        // ── Spreading decision (celt_encoder.c:1965) ─────────────────────────────────────────────
        if enc.tell() + 4 <= total_bits {
            self.spread_decision = if short_blocks
                || self.complexity < 3
                || nb_compressed_bytes < 10 * CHANNELS as i32
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
                    m,
                    &spread_weight,
                )
            };
            enc.enc_icdf(self.spread_decision as usize, &SPREAD_ICDF, 5);
        }

        // ── Caps + dynalloc boost coding (celt_encoder.c:2014) ───────────────────────────────────
        let mut cap = [0i32; NB_BANDS];
        init_caps(&mut cap, lm, CHANNELS);
        let mut dynalloc_logp = 6i32;
        let total_bits_frac = total_bits << BITRES;
        let mut total_boost = 0i32;
        let mut tell = enc.tell_frac() as i32;
        for i in start..end {
            let width = ((CHANNELS as i32) * i32::from(E_BANDS[i + 1] - E_BANDS[i])) << lm;
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

        // ── Allocation trim (celt_encoder.c:2069) ────────────────────────────────────────────────
        let mut alloc_trim = 5i32;
        if tell + (6 << BITRES) <= total_bits_frac - total_boost {
            if start > 0 {
                alloc_trim = 5;
            } else {
                alloc_trim =
                    alloc_trim_analysis(&band_log_e, end, lm, transient.tf_estimate, equiv_rate);
            }
            enc.enc_icdf(alloc_trim as usize, &TRIM_ICDF, 7);
            tell = enc.tell_frac() as i32;
        }

        // ── Variable bitrate: pick the actual frame size (celt_encoder.c:2086) ───────────────────
        if vbr_rate > 0 {
            let lm_diff = MAX_LM as i32 - lm as i32;
            // "Don't attempt to use more than 510 kb/s, even for frames smaller than 20 ms."
            nb_compressed_bytes = nb_compressed_bytes.min(1275 >> (3 - lm));
            let mut base_target = vbr_rate - ((40 * CHANNELS as i32 + 20) << BITRES);
            if constrained_vbr {
                base_target += self.vbr_offset >> lm_diff;
            }
            let mut target = compute_vbr(
                base_target,
                lm,
                equiv_rate,
                self.last_coded_bands,
                constrained_vbr,
                dynalloc.tot_boost,
                transient.tf_estimate,
                dynalloc.max_depth,
                temporal_vbr,
            );
            // "The current offset is removed from the target and the space used so far is added."
            target += tell;
            // "In VBR mode the frame size must not be reduced so much that it would result in the
            // encoder running out of bits. The margin of 2 bytes ensures that none of the
            // bust-prevention logic in the decoder will have triggered so far."
            let min_allowed = ((tell + total_boost + (1 << (BITRES + 3)) - 1) >> (BITRES + 3)) + 2;
            let mut nb_available_bytes = (target + (1 << (BITRES + 2))) >> (BITRES + 3);
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
        let mut intensity = 0usize;
        let mut dual_stereo = false;
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
            CHANNELS,
            lm,
            self.last_coded_bands,
            signal_bandwidth,
            &mut enc,
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
            &mut enc,
            CHANNELS,
        );

        // ── Residual (band/PVQ) quantisation (celt_encoder.c:2238) ───────────────────────────────
        let mut collapse_masks = [0u8; CHANNELS * NB_BANDS];
        let band_total_bits = nb_compressed_bytes * (8 << BITRES) - anti_collapse_rsv;
        quant_all_bands(
            start,
            end,
            &mut x,
            &mut collapse_masks,
            &pulses,
            short_blocks,
            self.spread_decision,
            intensity,
            &tf_res,
            band_total_bits,
            balance,
            lm as i32,
            coded_bands,
            &mut self.rng,
            true, // disable_inv = (channels == 1)
            &mut enc,
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
            &mut enc,
            CHANNELS,
        );
        self.energy_error.fill(0.0);
        for i in start..end {
            self.energy_error[i] = error[i].clamp(-0.5, 0.5);
        }

        if silence {
            self.old_band_energy.fill(ENERGY_RESET_DB);
        }

        // ── Roll the prefilter + energy history (celt_encoder.c:2309) ────────────────────────────
        self.prefilter_period = pitch_index;
        self.prefilter_gain = gain1;
        self.prefilter_tapset = prefilter_tapset;
        // C==1: mirror band energy into the (duplicated) second channel slots.
        for i in 0..NB_BANDS {
            self.old_band_energy[NB_BANDS + i] = self.old_band_energy[i];
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

        // "If there's any room left (can only happen for very high rates), it's already filled with
        // zeros" (celt_encoder.c:2354).
        enc.done();
        if enc.error() {
            return Err(CodecError::Unsupported(
                "celt: range encoder overflowed the output buffer",
            ));
        }
        let written = nb_compressed_bytes as usize;
        output[..written].copy_from_slice(&encoder_buffer[..written]);
        Ok(written)
    }

    /// Window and forward-MDCT the pre-emphasised input into the interleaved spectrum (libopus
    /// `compute_mdcts`, `celt_encoder.c:461`): one long block, or `M` short blocks interleaved with
    /// stride `M`.
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
        for b in 0..blocks {
            clt_mdct_forward(
                &self.mdct,
                &input[b * block_n..],
                &mut out[b..],
                &WINDOW120,
                OVERLAP,
                shift,
                blocks,
            );
        }
    }

    /// Pitch search + the prefilter comb applied to `input` (libopus `run_prefilter`,
    /// `celt_encoder.c:1188`). Returns `(pf_on, pitch_index, gain, quantised_gain)`.
    ///
    /// `input[..OVERLAP]` is filled with the previous frame's tail on entry and `input[OVERLAP..]`
    /// holds this frame's pre-emphasised samples; on exit the whole `OVERLAP + n` region is
    /// prefiltered and the tail is saved for the next frame.
    fn run_prefilter(
        &mut self,
        input: &mut [f32],
        n: usize,
        prefilter_tapset: usize,
        enabled: bool,
        nb_available_bytes: i32,
    ) -> (bool, usize, f32, u32) {
        // `pre` = [COMBFILTER_MAXPERIOD of history][this frame's N samples].
        let mut pre = [0f32; COMBFILTER_MAXPERIOD + MAX_FRAME_SAMPLES];
        pre[..COMBFILTER_MAXPERIOD].copy_from_slice(&self.prefilter_mem);
        pre[COMBFILTER_MAXPERIOD..COMBFILTER_MAXPERIOD + n]
            .copy_from_slice(&input[OVERLAP..OVERLAP + n]);

        let mut pitch_index = COMBFILTER_MINPERIOD;
        let mut gain1 = 0f32;
        if enabled {
            let mut pitch_buf = [0f32; (COMBFILTER_MAXPERIOD + MAX_FRAME_SAMPLES) / 2];
            let len = COMBFILTER_MAXPERIOD + n;
            pitch_downsample(&[&pre[..len]], &mut pitch_buf, len, 1);
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
        input[..OVERLAP].copy_from_slice(&self.in_mem);
        let mut filtered = [0f32; MAX_FRAME_SAMPLES];
        if offset != 0 {
            comb_filter_out_of_place(
                &mut filtered[..offset],
                &pre,
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
            &pre,
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
        input[OVERLAP..OVERLAP + n].copy_from_slice(&filtered[..n]);
        self.in_mem.copy_from_slice(&input[n..n + OVERLAP]);

        // Roll the prefilter history.
        if n > COMBFILTER_MAXPERIOD {
            self.prefilter_mem
                .copy_from_slice(&pre[n..n + COMBFILTER_MAXPERIOD]);
        } else {
            self.prefilter_mem.copy_within(n.., 0);
            self.prefilter_mem[COMBFILTER_MAXPERIOD - n..]
                .copy_from_slice(&pre[COMBFILTER_MAXPERIOD..COMBFILTER_MAXPERIOD + n]);
        }
        (pf_on, pitch_index, gain1, qg)
    }
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

/// The VBR target in 1/8 bits per frame (libopus `compute_vbr`, `celt_encoder.c:1320`, mono, no
/// surround mask and no tonality analysis).
#[allow(clippy::too_many_arguments)]
fn compute_vbr(
    base_target: i32,
    lm: usize,
    bitrate: i32,
    last_coded_bands: usize,
    constrained_vbr: bool,
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
    let coded_bins = (E_BANDS[coded_bands] as i32) << lm;
    let mut target = base_target;

    // "Boost the rate according to dynalloc (minus the dynalloc average for calibration)."
    target += tot_boost - (19 << lm);
    // "Apply transient boost, compensating for average boost."
    let tf_calibration = 0.044f32;
    target += (2.0 * (tf_estimate - tf_calibration) * target as f32) as i32;

    {
        // Never spend more bits than the signal has depth above the noise floor.
        let bins = (E_BANDS[NB_BANDS - 2] as i32) << lm;
        let mut floor_depth = (((CHANNELS as i32 * bins) << BITRES) as f32 * max_depth) as i32;
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
    let _ = coded_bins; // (only the surround/tonality terms use it, which are absent here)
    (2 * base_target).min(target)
}

impl std::fmt::Debug for CeltEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CeltEncoder")
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
