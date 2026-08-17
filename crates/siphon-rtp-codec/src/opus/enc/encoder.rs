//! The top-level Opus encoder (libopus `opus_encode_native` / `opus_encode_frame_native`,
//! `src/opus_encoder.c:1057-2459`).
//!
//! # What one `encode` call does
//!
//! ```text
//!   decisions once per call (opus_encode_native)
//!     bitrate -> equivalent 20 ms rate -> stream channels -> mode -> bandwidth -> FEC
//!   then, per Opus frame in the packet (opus_encode_frame_native)
//!     high-pass                 pitch-tracking (VoIP) or 3 Hz DC block
//!     SILK, if the mode has it  resample to 8/12/16 kHz, encode into the range coder
//!     redundancy signalling     the hybrid flag, and a 5 ms CELT frame across a mode switch
//!     CELT, if the mode has it  band 0 (CELT-only) or band 17 up (hybrid), same range coder
//!     TOC                       gen_toc(mode, frame rate, bandwidth, stream channels)
//!   finally
//!     packing                   framing code 0-3, plus CBR padding
//! ```
//!
//! # Why the two layers share one range coder
//!
//! A hybrid frame is not two payloads glued together. SILK writes the low band into the range coder,
//! CELT continues in the *same* coder from band 17, and the decoder reads straight through. There is
//! no length field between them: the split is implicit in the symbol sequence, which is why the two
//! encoders have to agree on the entropy state to the bit. That is also what makes the packet
//! checkable — libopus' decoder must end it on exactly the range value ours did.
//!
//! # What this layer deliberately does not do
//!
//! * **The tonality analysis** (`src/analysis.c`). Absent, not stubbed; see
//!   [`decision`](super::decision) for what that changes and why it is a supported libopus
//!   configuration rather than a gap invented here.
//! * **The SILK prefill** (`opus_encoder.c:2013-2036`). Entering SILK from CELT-only, libopus feeds
//!   SILK 10 ms of gain-faded history so its analysis starts warm. Here the SILK encoder is
//!   reconfigured instead, which re-seeds it exactly as `silk_setup_fs` does and leaves the first
//!   frame after the switch with `first_frame_after_reset` set — the constraint that keeps a cold
//!   predictor stable. The redundancy frame below covers the seam. This is a quality refinement that
//!   is not implemented, and no knob claims otherwise.

use crate::opus::celt::encoder::{CeltEncoder, RateControl as CeltRateControl, SilkInfo};
use crate::opus::celt::tables::{OVERLAP, WINDOW120};
use crate::opus::enc::decision::{
    automatic_bitrate, bandwidth_index, choose_bandwidth, choose_mode, compute_equiv_rate,
    compute_redundancy_bytes, compute_silk_rate_for_hybrid, compute_stereo_width, decide_dtx_mode,
    decide_fec, generate_toc, is_digital_silence, stream_channels, Application, ModeInputs,
    SignalHint, StereoWidthState,
};
use crate::opus::enc::highpass::VariableHighPass;
use crate::opus::enc::packer::{PacketBuilder, MAX_PACKET_BYTES};
use crate::opus::packet::{Bandwidth, Mode};
use crate::opus::range_coder::RangeEncoder;
use crate::opus::silk::enc::encoder::{
    EncoderConfig as SilkConfig, RateMode as SilkRateMode, SilkEncoder,
};
use crate::opus::silk::resampler::Resampler;
use crate::opus::silk::types::InternalRate;
use crate::CodecError;

/// `MAX_ENCODER_BUFFER` (`opus_encoder.c:62`) — 10 ms at 48 kHz, the delay buffer's length per
/// channel.
const MAX_ENCODER_BUFFER: usize = 480;

/// The longest Opus frame this layer encodes in one piece: 60 ms at 48 kHz. Anything longer is split
/// into several frames and repacketized (`opus_encode_native:1552`).
const MAX_FRAME_SAMPLES: usize = 2880;

/// Delay compensation at 48 kHz (`st->delay_compensation = Fs/250`, 4 ms).
const MAX_DELAY_COMPENSATION: usize = 192;

/// The staging buffer for one frame plus its delay compensation, both channels.
const MAX_PCM_BUFFER: usize = (MAX_FRAME_SAMPLES + MAX_DELAY_COMPENSATION) * 2;

/// The longest SILK frame at the internal rate: 60 ms at 16 kHz, both channels.
const MAX_SILK_SAMPLES: usize = 960 * 2;

/// Largest number of Opus frames one packet may carry here: 120 ms of 2.5 ms frames.
const MAX_SUB_FRAMES: usize = 48;

/// How the encoder spends its bits, at the Opus layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RateControl {
    /// `OPUS_SET_VBR(1)` + `OPUS_SET_VBR_CONSTRAINT(0)` — the packet is whatever the content needs.
    Variable,
    /// `OPUS_SET_VBR(1)` + `OPUS_SET_VBR_CONSTRAINT(1)` — variable, but a reservoir holds the
    /// running average at the target. libopus' default, and the safe one for real-time.
    #[default]
    ConstrainedVariable,
    /// `OPUS_SET_VBR(0)` — every packet is padded to exactly the target size.
    Constant,
}

/// What one [`OpusEncoder::encode`] call produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeResult {
    /// Packet length in bytes. **One byte means DTX**: the packet is a bare TOC and RFC 6716 §3.1
    /// lets the receiver treat it as "no data" for the frame.
    pub bytes: usize,
    /// The mode the packet was coded in.
    pub mode: Mode,
    /// The bandwidth signalled in the TOC.
    pub bandwidth: Bandwidth,
    /// Coded channels, 1 or 2 — not necessarily the input channel count.
    pub stream_channels: usize,
    /// The range coder's final value, `enc.rng ^ redundant_rng` (`OPUS_GET_FINAL_RANGE`). A
    /// conforming decoder must end this packet on exactly this value; zero means the packet carries
    /// no range-coded data (DTX).
    pub final_range: u32,
}

/// A complete Opus encoder: one SILK encoder, one CELT encoder, and the decisions that pick between
/// them.
///
/// Stateful and single-owner, like every other codec in this crate: the two layers, the high-pass,
/// the resamplers and every hysteresis decision carry state across packets, so one instance encodes
/// exactly one stream.
pub struct OpusEncoder {
    // ── Configuration ────────────────────────────────────────────────────────────────────────────
    sample_rate_hz: i32,
    channels: usize,
    application: Application,
    /// `st->user_bitrate_bps`; `None` is `OPUS_AUTO`.
    bitrate_bps: Option<i32>,
    rate_control: RateControl,
    complexity: i32,
    packet_loss_percent: i32,
    use_in_band_fec: bool,
    use_dtx: bool,
    signal_hint: SignalHint,
    forced_mode: Option<Mode>,
    forced_channels: Option<usize>,
    user_bandwidth: Option<Bandwidth>,
    max_bandwidth: Bandwidth,
    lsb_depth: i32,

    // ── The two codec layers ─────────────────────────────────────────────────────────────────────
    silk: SilkEncoder,
    celt: CeltEncoder,
    /// Whether `silk` has ever been driven since the last mode entry, so a mode switch can tell a
    /// cold encoder from a warm one.
    silk_configured: Option<SilkConfig>,
    /// One API-rate resampler per API channel (`state_Fxx[n].sCmn.resampler_state`).
    resamplers: [Resampler; 2],
    high_pass: VariableHighPass,

    // ── Cross-packet decision state (`OPUS_ENCODER_RESET_START`) ─────────────────────────────────
    stream_channels: usize,
    previous_channels: usize,
    mode: Mode,
    previous_mode: Option<Mode>,
    bandwidth: Bandwidth,
    auto_bandwidth: Bandwidth,
    first: bool,
    lbrr_coded: bool,
    /// `silk_mode.toMono` — set for the one packet that bridges a stereo-to-mono switch. Without the
    /// latch the transition never completes: the rule that holds the second channel for one more
    /// packet would re-arm every packet and the stream would stay stereo forever.
    to_mono: bool,
    silk_bandwidth_switch: bool,
    width_state: StereoWidthState,
    previous_hb_gain: f32,
    hybrid_stereo_width_q14: i32,
    stereo_width_q14: i32,
    no_activity_ms_q1: i32,
    final_range: u32,
    /// `st->delay_buffer` — the last 10 ms of *filtered* input, which the CELT layer needs as its
    /// look-behind after a mode switch.
    delay_buffer: [f32; MAX_ENCODER_BUFFER * 2],

    // ── Scratch, owned so the hot path never allocates ───────────────────────────────────────────
    pcm_buffer: [f32; MAX_PCM_BUFFER],
    silk_pcm: [i16; MAX_SILK_SAMPLES],
    resample_in: [i16; MAX_FRAME_SAMPLES],
    resample_out: [i16; MAX_SILK_SAMPLES],
    packer: PacketBuilder,
}

impl OpusEncoder {
    /// Create an encoder for an input rate, a channel count and an application.
    ///
    /// `sample_rate_hz` is 8/12/16/24/48 kHz and `channels` is 1 or 2 (RFC 6716 defines no more; see
    /// the plan's non-goals on multistream).
    pub fn new(
        sample_rate_hz: u32,
        channels: usize,
        application: Application,
    ) -> Result<Self, CodecError> {
        if !matches!(sample_rate_hz, 8_000 | 12_000 | 16_000 | 24_000 | 48_000) {
            return Err(CodecError::Unsupported(
                "opus enc: input rate must be 8, 12, 16, 24 or 48 kHz",
            ));
        }
        if channels == 0 || channels > 2 {
            return Err(CodecError::Unsupported("opus enc: channels must be 1 or 2"));
        }
        let silk = SilkEncoder::new(SilkConfig::new(InternalRate::Wide16k, 20, 25_000))?;
        let mut celt = CeltEncoder::with_channels(channels)?;
        // CELT has one mode, at 48 kHz; a lower API rate rides it zero-stuffed.
        celt.set_sample_rate(sample_rate_hz)?;
        Ok(Self {
            sample_rate_hz: sample_rate_hz as i32,
            channels,
            application,
            bitrate_bps: None,
            rate_control: RateControl::default(),
            // `st->silk_mode.complexity = 9` (`opus_encoder.c:244`).
            complexity: 9,
            packet_loss_percent: 0,
            use_in_band_fec: false,
            use_dtx: false,
            signal_hint: SignalHint::Auto,
            forced_mode: None,
            forced_channels: None,
            user_bandwidth: None,
            max_bandwidth: Bandwidth::Fullband,
            lsb_depth: 24,
            silk,
            celt,
            silk_configured: None,
            resamplers: [Resampler::new(), Resampler::new()],
            high_pass: VariableHighPass::new(),
            stream_channels: channels,
            previous_channels: channels,
            mode: Mode::Hybrid,
            previous_mode: None,
            bandwidth: Bandwidth::Fullband,
            auto_bandwidth: Bandwidth::Fullband,
            first: true,
            lbrr_coded: false,
            to_mono: false,
            silk_bandwidth_switch: false,
            width_state: StereoWidthState::default(),
            previous_hb_gain: 1.0,
            hybrid_stereo_width_q14: 1 << 14,
            stereo_width_q14: 1 << 14,
            no_activity_ms_q1: 0,
            final_range: 0,
            delay_buffer: [0.0; MAX_ENCODER_BUFFER * 2],
            pcm_buffer: [0.0; MAX_PCM_BUFFER],
            silk_pcm: [0; MAX_SILK_SAMPLES],
            resample_in: [0; MAX_FRAME_SAMPLES],
            resample_out: [0; MAX_SILK_SAMPLES],
            packer: PacketBuilder::new(),
        })
    }

    /// The input sample rate this encoder was built for.
    #[must_use]
    pub fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz as u32
    }

    /// Input channels, 1 or 2. Not the same as the coded channel count, which the rate decides.
    #[must_use]
    pub fn channels(&self) -> usize {
        self.channels
    }

    /// Set the target bitrate in bit/s, or `None` for the rate-derived default
    /// (`60 * Fs / frame_size + Fs * channels`, `opus_encoder.c:643`).
    pub fn set_bitrate(&mut self, bitrate_bps: Option<i32>) -> Result<(), CodecError> {
        if let Some(bitrate) = bitrate_bps {
            if !(500..=512_000 * self.channels as i32).contains(&bitrate) {
                return Err(CodecError::Unsupported(
                    "opus enc: bitrate must be 500..=512000 per channel",
                ));
            }
        }
        self.bitrate_bps = bitrate_bps;
        Ok(())
    }

    /// Select VBR, constrained VBR or CBR.
    pub fn set_rate_control(&mut self, rate_control: RateControl) {
        self.rate_control = rate_control;
    }

    /// Set the analysis depth, 0..=10 (`OPUS_SET_COMPLEXITY`). Genuinely wired all the way down: it
    /// picks the SILK search depths, the CELT analysis stages, and the equivalent-rate penalty every
    /// decision above is measured against.
    pub fn set_complexity(&mut self, complexity: i32) -> Result<(), CodecError> {
        if !(0..=10).contains(&complexity) {
            return Err(CodecError::Unsupported(
                "opus enc: complexity must be 0..=10",
            ));
        }
        self.complexity = complexity;
        self.celt.set_complexity(complexity)
    }

    /// Set the far end's reported packet loss, 0..=100 (`OPUS_SET_PACKET_LOSS_PERC`).
    pub fn set_packet_loss_percent(&mut self, percent: i32) -> Result<(), CodecError> {
        if !(0..=100).contains(&percent) {
            return Err(CodecError::Unsupported("opus enc: loss must be 0..=100"));
        }
        self.packet_loss_percent = percent;
        self.celt.set_loss_rate(percent)
    }

    /// Enable in-band FEC (`OPUS_SET_INBAND_FEC`). Only SILK carries it, so enabling it with real
    /// loss also biases the mode decision towards SILK.
    pub fn set_in_band_fec(&mut self, enabled: bool) {
        self.use_in_band_fec = enabled;
    }

    /// Enable discontinuous transmission (`OPUS_SET_DTX`).
    pub fn set_dtx(&mut self, enabled: bool) {
        self.use_dtx = enabled;
    }

    /// Tell the encoder what the content is (`OPUS_SET_SIGNAL`). This is what replaces the tonality
    /// estimator on a build without it — see [`decision`](super::decision).
    pub fn set_signal_hint(&mut self, hint: SignalHint) {
        self.signal_hint = hint;
    }

    /// Force a coding mode (`OPUS_SET_FORCE_MODE`), or `None` to let the rate decide.
    pub fn set_forced_mode(&mut self, mode: Option<Mode>) {
        self.forced_mode = mode;
    }

    /// Force the coded channel count (`OPUS_SET_FORCE_CHANNELS`), or `None` to let the rate decide.
    pub fn set_forced_channels(&mut self, channels: Option<usize>) -> Result<(), CodecError> {
        if let Some(forced) = channels {
            if forced == 0 || forced > self.channels {
                return Err(CodecError::Unsupported(
                    "opus enc: forced channels must be 1..=channels",
                ));
            }
        }
        self.forced_channels = channels;
        Ok(())
    }

    /// Force the coded bandwidth (`OPUS_SET_BANDWIDTH`), or `None` for the rate-driven choice.
    pub fn set_bandwidth(&mut self, bandwidth: Option<Bandwidth>) {
        self.user_bandwidth = bandwidth;
    }

    /// Cap the coded bandwidth (`OPUS_SET_MAX_BANDWIDTH`) without forcing it.
    pub fn set_max_bandwidth(&mut self, bandwidth: Bandwidth) {
        self.max_bandwidth = bandwidth;
    }

    /// Set the input's effective bit depth, 8..=24 (`OPUS_SET_LSB_DEPTH`). It sets the digital
    /// silence threshold and CELT's dynalloc noise floor.
    pub fn set_lsb_depth(&mut self, depth: i32) -> Result<(), CodecError> {
        if !(8..=24).contains(&depth) {
            return Err(CodecError::Unsupported(
                "opus enc: lsb depth must be 8..=24",
            ));
        }
        self.lsb_depth = depth;
        Ok(())
    }

    /// The range coder's final value for the last encoded packet (`OPUS_GET_FINAL_RANGE`).
    #[must_use]
    pub fn final_range(&self) -> u32 {
        self.final_range
    }

    /// Whether the frame size is one Opus can carry: 2.5/5/10/20/40/60/80/100/120 ms
    /// (`frame_size_select`, `opus_encoder.c:704-727`).
    #[must_use]
    pub fn is_valid_frame_size(&self, frame_size: usize) -> bool {
        let fs = self.sample_rate_hz as usize;
        let size = frame_size;
        400 * size == fs
            || 200 * size == fs
            || 100 * size == fs
            || 50 * size == fs
            || 25 * size == fs
            || 50 * size == 3 * fs
            || 50 * size == 4 * fs
            || 50 * size == 5 * fs
            || 50 * size == 6 * fs
    }

    /// Encode `frame_size` samples per channel of 16-bit PCM.
    ///
    /// `pcm` is interleaved to [`OpusEncoder::channels`]; `output` is the caller-owned packet buffer
    /// and its length is the hard ceiling on the packet. Returns what was produced — see
    /// [`EncodeResult`], and note that a one-byte result is DTX rather than an error.
    pub fn encode(
        &mut self,
        pcm: &[i16],
        frame_size: usize,
        output: &mut [u8],
    ) -> Result<EncodeResult, CodecError> {
        if pcm.len() < frame_size * self.channels {
            return Err(CodecError::OutputTooSmall {
                needed: frame_size * self.channels,
                have: pcm.len(),
            });
        }
        // `opus_encode`'s int16 entry point scales into the float domain the whole encoder works in
        // (`opus_encoder.c:2514-2515`) and declares a 16-bit input depth.
        let mut scaled = [0f32; MAX_PCM_BUFFER];
        let count = frame_size * self.channels;
        if count > scaled.len() {
            return Err(CodecError::BadFrameSize {
                expected: MAX_FRAME_SAMPLES,
                got: frame_size,
            });
        }
        for (slot, &sample) in scaled[..count].iter_mut().zip(pcm.iter()) {
            *slot = f32::from(sample) * (1.0 / 32768.0);
        }
        let depth = self.lsb_depth.min(16);
        self.encode_native(&scaled[..count], frame_size, output, depth)
    }

    /// Encode `frame_size` samples per channel of float PCM nominally in `[-1, 1)`.
    ///
    /// The crate's channel contract: interleaved to [`OpusEncoder::channels`].
    pub fn encode_float(
        &mut self,
        pcm: &[f32],
        frame_size: usize,
        output: &mut [u8],
    ) -> Result<EncodeResult, CodecError> {
        if pcm.len() < frame_size * self.channels {
            return Err(CodecError::OutputTooSmall {
                needed: frame_size * self.channels,
                have: pcm.len(),
            });
        }
        let depth = self.lsb_depth;
        self.encode_native(pcm, frame_size, output, depth)
    }

    /// `opus_encode_native` (`opus_encoder.c:1057`) — the decisions, then one or more frames.
    fn encode_native(
        &mut self,
        pcm: &[f32],
        frame_size: usize,
        output: &mut [u8],
        lsb_depth: i32,
    ) -> Result<EncodeResult, CodecError> {
        if frame_size == 0 || !self.is_valid_frame_size(frame_size) {
            return Err(CodecError::BadFrameSize {
                expected: self.sample_rate_hz as usize / 50,
                got: frame_size,
            });
        }
        if output.is_empty() {
            return Err(CodecError::OutputTooSmall { needed: 1, have: 0 });
        }
        self.final_range = 0;

        // `max_data_bytes = IMIN(1276, out_data_bytes)` (`opus_encoder.c:1090`).
        let mut max_data_bytes = (output.len() as i32).min(MAX_PACKET_BYTES as i32 + 1);
        let frame_rate = self.sample_rate_hz / frame_size as i32;

        // ── Bitrate, and the CBR packet size it implies (`opus_encoder.c:1185-1197`) ─────────────
        let mut bitrate_bps = self.bitrate_bps.unwrap_or_else(|| {
            automatic_bitrate(self.sample_rate_hz, self.channels, frame_size as i32)
        });
        let vbr = self.rate_control != RateControl::Constant;
        let mut cbr_bytes = -1i32;
        if !vbr {
            // "Multiply by 12 to make sure the division is exact."
            let frame_rate12 = 12 * self.sample_rate_hz / frame_size as i32;
            cbr_bytes =
                ((12 * bitrate_bps / 8 + frame_rate12 / 2) / frame_rate12).min(max_data_bytes);
            bitrate_bps = cbr_bytes * frame_rate12 * 8 / 12;
            max_data_bytes = cbr_bytes.max(1);
        }

        // ── Too little space to do anything useful: emit a PLC packet ───────────────────────────
        if max_data_bytes < 3
            || bitrate_bps < 3 * frame_rate * 8
            || (frame_rate < 50 && (max_data_bytes * frame_rate < 300 || bitrate_bps < 2400))
        {
            return self.emit_plc_packet(frame_rate, output, max_data_bytes, vbr);
        }

        let max_rate = frame_rate * max_data_bytes * 8;
        let voice_estimate =
            crate::opus::enc::decision::voice_estimate(self.signal_hint, self.application);

        // ── Stereo width, then the channel decision (`opus_encoder.c:1181-1319`) ────────────────
        let stereo_width = if self.channels == 2 && self.forced_channels != Some(1) {
            compute_stereo_width(pcm, frame_size, self.sample_rate_hz, &mut self.width_state)
        } else {
            0.0
        };
        let equiv_rate = compute_equiv_rate(
            bitrate_bps,
            self.channels,
            frame_rate,
            vbr,
            None,
            self.complexity,
            self.packet_loss_percent,
        );
        self.stream_channels = stream_channels(
            self.channels,
            self.forced_channels,
            self.stream_channels,
            equiv_rate,
            voice_estimate,
        );
        let equiv_rate = compute_equiv_rate(
            bitrate_bps,
            self.stream_channels,
            frame_rate,
            vbr,
            None,
            self.complexity,
            self.packet_loss_percent,
        );

        // Digital silence turns SILK's own DTX off so the generalised one can take the frame whole
        // (`opus_encoder.c:1324`).
        let is_silence = self.analysis_is_enabled(lsb_depth) && is_digital_silence(pcm, lsb_depth);
        let silk_dtx = self.use_dtx && !is_silence;

        // ── Mode (`opus_encoder.c:1330-1394`) ───────────────────────────────────────────────────
        let inputs = ModeInputs {
            application: self.application,
            voice_estimate,
            stereo_width,
            previous_mode: self.previous_mode,
            use_in_band_fec: self.use_in_band_fec,
            packet_loss_percent: self.packet_loss_percent,
            silk_dtx,
            max_data_bytes,
            frame_size: frame_size as i32,
            sample_rate_hz: self.sample_rate_hz,
            frame_rate,
        };
        self.mode = choose_mode(equiv_rate, self.forced_mode, &inputs);

        // ── Redundancy across a mode switch (`opus_encoder.c:1398-1415`) ────────────────────────
        let mut redundancy = false;
        let mut celt_to_silk = false;
        let mut to_celt = false;
        if let Some(previous) = self.previous_mode {
            let crossing = (self.mode != Mode::Celt && previous == Mode::Celt)
                || (self.mode == Mode::Celt && previous != Mode::Celt);
            if crossing {
                redundancy = true;
                celt_to_silk = self.mode != Mode::Celt;
                if !celt_to_silk {
                    // "Switch to SILK/hybrid if frame size is 10 ms or more": stay in the old mode
                    // for this frame and let the redundant CELT frame carry the crossfade.
                    if frame_size >= self.sample_rate_hz as usize / 100 {
                        self.mode = previous;
                        to_celt = true;
                    } else {
                        redundancy = false;
                    }
                }
            }
        }

        // "Delay stereo->mono transition by two frames so that SILK can do a smooth downmix"
        // (`opus_encoder.c:1419-1427`). The `!self.to_mono` guard is what ends the delay.
        if self.stream_channels == 1
            && self.previous_channels == 2
            && !self.to_mono
            && self.mode != Mode::Celt
            && self.previous_mode != Some(Mode::Celt)
        {
            self.to_mono = true;
            self.stream_channels = 2;
        } else {
            self.to_mono = false;
        }

        let equiv_rate = compute_equiv_rate(
            bitrate_bps,
            self.stream_channels,
            frame_rate,
            vbr,
            Some(self.mode),
            self.complexity,
            self.packet_loss_percent,
        );

        // ── Bandwidth (`opus_encoder.c:1440-1550`) ──────────────────────────────────────────────
        if self.mode == Mode::Celt || self.first {
            let chosen = choose_bandwidth(
                equiv_rate,
                voice_estimate,
                self.channels == 2 && self.forced_channels != Some(1),
                self.first,
                self.auto_bandwidth,
            );
            self.auto_bandwidth = chosen;
            self.bandwidth = chosen;
        }
        if bandwidth_index(self.bandwidth) > bandwidth_index(self.max_bandwidth) {
            self.bandwidth = self.max_bandwidth;
        }
        if let Some(forced) = self.user_bandwidth {
            self.bandwidth = forced;
        }
        // "This prevents us from using hybrid at unsafe CBR/max rates."
        if self.mode != Mode::Celt && max_rate < 15_000 {
            self.bandwidth = cap_bandwidth(self.bandwidth, Bandwidth::Wideband);
        }
        // "Prevents Opus from wasting bits on frequencies that are above the Nyquist rate of the
        // input signal."
        self.bandwidth = match self.sample_rate_hz {
            rate if rate <= 8_000 => cap_bandwidth(self.bandwidth, Bandwidth::Narrowband),
            rate if rate <= 12_000 => cap_bandwidth(self.bandwidth, Bandwidth::Mediumband),
            rate if rate <= 16_000 => cap_bandwidth(self.bandwidth, Bandwidth::Wideband),
            rate if rate <= 24_000 => cap_bandwidth(self.bandwidth, Bandwidth::SuperWideband),
            _ => self.bandwidth,
        };

        // ── FEC, which may narrow the bandwidth further (`opus_encoder.c:1532`) ─────────────────
        let mut bandwidth = self.bandwidth;
        self.lbrr_coded = decide_fec(
            self.use_in_band_fec,
            self.packet_loss_percent,
            self.lbrr_coded,
            self.mode,
            &mut bandwidth,
            equiv_rate,
        );
        self.bandwidth = bandwidth;
        self.celt.set_lsb_depth(lsb_depth)?;

        // "CELT mode doesn't support mediumband, use wideband instead."
        if self.mode == Mode::Celt && self.bandwidth == Bandwidth::Mediumband {
            self.bandwidth = Bandwidth::Wideband;
        }

        // "Chooses the appropriate mode for speech. *NEVER* switch to/from CELT-only mode here as
        // this will invalidate some assumptions." (`opus_encoder.c:1544-1549`)
        if self.mode == Mode::Silk
            && bandwidth_index(self.bandwidth) > bandwidth_index(Bandwidth::Wideband)
        {
            self.mode = Mode::Hybrid;
        }
        if self.mode == Mode::Hybrid
            && bandwidth_index(self.bandwidth) <= bandwidth_index(Bandwidth::Wideband)
        {
            self.mode = Mode::Silk;
        }

        // ── One frame, or several repacketized (`opus_encoder.c:1551-1695`) ─────────────────────
        let twenty_ms = self.sample_rate_hz as usize / 50;
        let sixty_ms = 3 * twenty_ms;
        let needs_split =
            (frame_size > twenty_ms && self.mode != Mode::Silk) || frame_size > sixty_ms;
        if needs_split {
            let sub_frame = if self.mode == Mode::Silk {
                if frame_size == 2 * self.sample_rate_hz as usize / 25 {
                    // 80 ms -> 2 x 40 ms.
                    self.sample_rate_hz as usize / 25
                } else if frame_size == 3 * self.sample_rate_hz as usize / 25 {
                    // 120 ms -> 2 x 60 ms.
                    sixty_ms
                } else {
                    // 100 ms -> 5 x 20 ms.
                    twenty_ms
                }
            } else {
                twenty_ms
            };
            let count = frame_size / sub_frame;
            if count > MAX_SUB_FRAMES {
                return Err(CodecError::BadFrameSize {
                    expected: sixty_ms,
                    got: frame_size,
                });
            }
            // "Worst cases: 2 frames: Code 2 with different compressed sizes; >2 frames: Code 3 VBR."
            let header_bytes = if count == 2 { 3 } else { 2 + (count - 1) * 2 };
            let repacketize_len = if vbr {
                output.len() as i32
            } else {
                cbr_bytes.min(output.len() as i32)
            };
            let budget_sum = count as i32 + repacketize_len - header_bytes as i32;

            self.packer.clear();
            let mut toc = None;
            let mut total = 0i32;
            let mut dtx_count = 0usize;
            for index in 0..count {
                let frame_to_celt = to_celt && index == count - 1;
                let frame_redundancy = redundancy && (frame_to_celt || (!to_celt && index == 0));
                let per_frame = (3 * bitrate_bps
                    / (3 * 8 * self.sample_rate_hz / sub_frame as i32))
                    .min(budget_sum / count as i32)
                    .min(budget_sum - total);
                let block = &pcm
                    [index * sub_frame * self.channels..(index + 1) * sub_frame * self.channels];
                let frame = self.encode_one_frame(
                    block,
                    sub_frame,
                    per_frame.clamp(1, MAX_PACKET_BYTES as i32 + 1),
                    lsb_depth,
                    bitrate_bps,
                    equiv_rate,
                    frame_redundancy,
                    celt_to_silk,
                    is_silence,
                )?;
                match toc {
                    None => toc = Some(frame.toc),
                    Some(first) if first != frame.toc => {
                        return Err(CodecError::Unsupported(
                            "opus enc: a multi-frame packet cannot change configuration mid-packet",
                        ))
                    }
                    Some(_) => {}
                }
                if frame.length == 0 {
                    dtx_count += 1;
                }
                total += frame.length as i32 + 1;
                self.packer.commit_frame(frame.length)?;
            }
            let toc = toc.ok_or(CodecError::Unsupported("opus enc: no frames encoded"))?;
            let pad_to =
                (!vbr && dtx_count != count).then(|| (repacketize_len as usize).min(output.len()));
            let bytes = self.packer.write(toc, output, pad_to)?;
            self.finish_frame(to_celt);
            return Ok(EncodeResult {
                bytes,
                mode: self.mode,
                bandwidth: self.bandwidth,
                stream_channels: self.stream_channels,
                final_range: self.final_range,
            });
        }

        self.packer.clear();
        let frame = self.encode_one_frame(
            pcm,
            frame_size,
            max_data_bytes,
            lsb_depth,
            bitrate_bps,
            equiv_rate,
            redundancy,
            celt_to_silk,
            is_silence,
        )?;
        self.packer.commit_frame(frame.length)?;
        let pad_to =
            (!vbr && frame.length > 0).then(|| (max_data_bytes as usize).min(output.len()));
        let bytes = self.packer.write(frame.toc, output, pad_to)?;
        self.finish_frame(to_celt);
        Ok(EncodeResult {
            bytes,
            mode: self.mode,
            bandwidth: self.bandwidth,
            stream_channels: self.stream_channels,
            final_range: self.final_range,
        })
    }

    /// Roll the per-packet decision state forward (`opus_encoder.c:2355-2362`).
    fn finish_frame(&mut self, to_celt: bool) {
        self.previous_mode = Some(if to_celt { Mode::Celt } else { self.mode });
        self.previous_channels = self.stream_channels;
        self.first = false;
    }

    /// Whether the analysis-gated code paths run. libopus computes `is_silence` alongside the
    /// tonality analysis and therefore only above complexity 7 at 16 kHz and up
    /// (`opus_encoder.c:1115-1120`); the generalised DTX rides on the same gate. Reproduced so the
    /// decisions match the reference at every complexity, rather than turning DTX on at a setting
    /// where libopus leaves it off.
    fn analysis_is_enabled(&self, _lsb_depth: i32) -> bool {
        self.complexity >= 7 && self.sample_rate_hz >= 16_000
    }

    /// `opus_encode_frame_native` (`opus_encoder.c:1698`) — one Opus frame: the high-pass, the SILK
    /// layer, the redundancy signalling, the CELT layer, and the TOC that describes all of it.
    ///
    /// The payload (everything but the TOC) is staged into the packet builder.
    #[allow(clippy::too_many_arguments)]
    fn encode_one_frame(
        &mut self,
        pcm: &[f32],
        frame_size: usize,
        max_data_bytes: i32,
        lsb_depth: i32,
        bitrate_bps: i32,
        equiv_rate: i32,
        mut redundancy: bool,
        mut celt_to_silk: bool,
        is_silence: bool,
    ) -> Result<EncodedFrame, CodecError> {
        let frame_rate = self.sample_rate_hz / frame_size as i32;
        let vbr = self.rate_control != RateControl::Constant;
        let mut curr_bandwidth = self.bandwidth;
        // Restricted low-delay is exactly that: no look-ahead, so no delay compensation
        // (`opus_encoder.c:1740-1744`).
        let total_buffer = if self.application == Application::RestrictedLowdelay {
            0
        } else {
            self.sample_rate_hz as usize / 250
        };
        let encoder_buffer = self.sample_rate_hz as usize / 100;

        // "For the first frame at a new SILK bandwidth" (`opus_encoder.c:1765-1772`).
        if self.silk_bandwidth_switch {
            redundancy = true;
            celt_to_silk = true;
            self.silk_bandwidth_switch = false;
        }
        // "If we decided to go with CELT, make sure redundancy is off, no matter what we decided
        // earlier."
        if self.mode == Mode::Celt {
            redundancy = false;
        }
        let mut redundancy_bytes = if redundancy {
            let bytes = compute_redundancy_bytes(
                max_data_bytes,
                bitrate_bps,
                frame_rate,
                self.stream_channels,
            );
            if bytes == 0 {
                redundancy = false;
            }
            bytes
        } else {
            0
        };

        let bytes_target = max_data_bytes
            .saturating_sub(redundancy_bytes)
            .min(bitrate_bps * frame_size as i32 / (self.sample_rate_hz * 8))
            - 1;

        // The payload lives here until it is staged; the TOC is the packet's, not the frame's. The
        // redundant frame gets its own buffer rather than sharing this one: libopus writes it into
        // the tail of the same block and then `OPUS_MOVE`s it down when CELT turns out to have used
        // fewer bytes (`opus_encoder.c:2306-2310`), which only exists because the two share storage.
        let mut payload = [0u8; MAX_PACKET_BYTES + 1];
        let mut redundant_payload = [0u8; 257];
        let mut redundant_length = 0usize;
        let payload_capacity = ((max_data_bytes - 1).max(1) as usize).min(payload.len());
        let mut enc = RangeEncoder::new(&mut payload[..payload_capacity]);

        // ── The input high-pass, into the staging buffer behind the delay compensation ──────────
        self.stage_input(pcm, frame_size, total_buffer, encoder_buffer);

        // ── SILK ────────────────────────────────────────────────────────────────────────────────
        let mut high_band_gain = 1.0f32;
        let mut silk_target_bitrate = 0i32;
        let mut silk_info = SilkInfo::default();
        if self.mode != Mode::Celt {
            let total_bitrate = 8 * bytes_target * frame_rate;
            let silk_bitrate = if self.mode == Mode::Hybrid {
                let silk_bitrate = compute_silk_rate_for_hybrid(
                    total_bitrate,
                    curr_bandwidth,
                    self.sample_rate_hz == 50 * frame_size as i32,
                    vbr,
                    self.lbrr_coded,
                    self.stream_channels,
                );
                // "Increasingly attenuate high band when it gets allocated fewer bits."
                let celt_rate = total_bitrate - silk_bitrate;
                high_band_gain = 1.0 - 0.5 * (-(celt_rate as f32) / 1024.0).exp2();
                silk_bitrate
            } else {
                total_bitrate
            };

            let internal_rate = self.silk_internal_rate(curr_bandwidth, max_data_bytes, frame_rate);
            let silk_max_bits = self.silk_max_bits(
                max_data_bytes,
                redundancy,
                redundancy_bytes,
                silk_bitrate,
                frame_size,
                vbr,
            );
            let config = SilkConfig {
                internal_rate,
                duration_ms: 1000 * frame_size / self.sample_rate_hz as usize,
                channels: self.stream_channels,
                bitrate_bps: silk_bitrate.max(1),
                complexity: self.complexity as u8,
                rate_mode: if vbr {
                    if self.rate_control == RateControl::ConstrainedVariable {
                        SilkRateMode::ConstrainedVariable
                    } else {
                        SilkRateMode::Variable
                    }
                } else if self.mode == Mode::Hybrid {
                    // "When we're in CBR mode, but we have non-SILK data to encode, switch SILK to
                    // VBR with cap ... any variations will be absorbed by CELT."
                    SilkRateMode::ConstrainedVariable
                } else {
                    SilkRateMode::Constant
                },
                max_bytes: (silk_max_bits / 8).clamp(2, MAX_PACKET_BYTES as i32) as usize,
                use_in_band_fec: self.lbrr_coded,
                use_dtx: self.use_dtx && !is_silence,
                packet_loss_percent: self.packet_loss_percent,
                to_mono: self.to_mono,
            };
            self.configure_silk(config)?;

            silk_target_bitrate = silk_bitrate;
            let result = self.run_silk(frame_size, total_buffer, internal_rate, &mut enc)?;
            let silk_bytes = result.payload_bytes;
            silk_info = SilkInfo {
                signal_type: result.signal_type,
                offset: result.offset,
            };

            // "Extract SILK internal bandwidth for signaling in first byte."
            if self.mode == Mode::Silk {
                curr_bandwidth = match internal_rate {
                    InternalRate::Narrow8k => Bandwidth::Narrowband,
                    InternalRate::Medium12k => Bandwidth::Mediumband,
                    InternalRate::Wide16k => Bandwidth::Wideband,
                };
            }

            if silk_bytes == 0 {
                // DTX: the packet is the TOC alone (`opus_encoder.c:2067-2073`).
                self.final_range = 0;
                return Ok(EncodedFrame {
                    toc: generate_toc(self.mode, frame_rate, curr_bandwidth, self.stream_channels),
                    length: 0,
                });
            }
        } else {
            // SILK is not running, so its cutoff tracker is stale: pin the high-pass to the floor
            // (`opus_encoder.c:1796-1799`). Already applied inside `stage_input`.
        }

        // ── CELT configuration (`opus_encoder.c:2085-2116`) ─────────────────────────────────────
        self.celt
            .set_band_range(0, CeltEncoder::end_band_for_bandwidth(curr_bandwidth))?;
        self.celt.set_stream_channels(self.stream_channels)?;
        self.celt.set_bitrate(-1);
        if self.mode != Mode::Silk {
            self.celt.set_prediction(2)?;
        }

        // The 2.5 ms of history a CELT frame needs when it follows a mode it has no overlap from.
        let quarter = self.sample_rate_hz as usize / 400;
        let mut prefill = [0f32; 2 * 480];
        let needs_prefill = self.mode != Mode::Silk
            && Some(self.mode) != self.previous_mode
            && self.previous_mode.is_some();
        if needs_prefill {
            let start = (encoder_buffer - total_buffer - quarter) * self.channels;
            prefill[..quarter * self.channels]
                .copy_from_slice(&self.delay_buffer[start..start + quarter * self.channels]);
        }

        self.roll_delay_buffer(frame_size, total_buffer, encoder_buffer);

        // "gain_fade() and stereo_fade() need to be after the buffer copying because we don't want
        // any of this to affect the SILK part" (`opus_encoder.c:2133-2166`).
        if self.previous_hb_gain < 1.0 || high_band_gain < 1.0 {
            let channels = self.channels;
            gain_fade(
                &mut self.pcm_buffer[..(frame_size + total_buffer) * channels],
                self.previous_hb_gain,
                high_band_gain,
                frame_size + total_buffer,
                channels,
                self.sample_rate_hz,
            );
        }
        self.previous_hb_gain = high_band_gain;
        if self.mode != Mode::Hybrid || self.stream_channels == 1 {
            self.stereo_width_q14 = if equiv_rate > 32_000 {
                16_384
            } else if equiv_rate < 16_000 {
                0
            } else {
                16_384 - 2_048 * (32_000 - equiv_rate) / (equiv_rate - 14_000)
            };
        }
        if self.channels == 2
            && (self.hybrid_stereo_width_q14 < (1 << 14) || self.stereo_width_q14 < (1 << 14))
        {
            let g1 = self.hybrid_stereo_width_q14 as f32 / 16_384.0;
            let g2 = self.stereo_width_q14 as f32 / 16_384.0;
            let channels = self.channels;
            stereo_fade(
                &mut self.pcm_buffer[..(frame_size + total_buffer) * channels],
                g1,
                g2,
                frame_size + total_buffer,
                channels,
                self.sample_rate_hz,
            );
            self.hybrid_stereo_width_q14 = self.stereo_width_q14;
        }

        // ── Redundancy signalling (`opus_encoder.c:2168-2200`) ──────────────────────────────────
        // The flag itself has to be coded whenever there is room, redundancy or not: a hybrid
        // decoder reads it unconditionally, so skipping it desynchronises the packet.
        if self.mode != Mode::Celt
            && enc.tell() + 17 + 20 * i32::from(self.mode == Mode::Hybrid)
                <= 8 * (max_data_bytes - 1)
        {
            if self.mode == Mode::Hybrid {
                enc.enc_bit_logp(redundancy, 12);
            }
            if redundancy {
                enc.enc_bit_logp(celt_to_silk, 1);
                let max_redundancy = if self.mode == Mode::Hybrid {
                    // "Reserve the 8 bits needed for the redundancy length, and at least a few bits
                    // for CELT if possible."
                    (max_data_bytes - 1) - ((enc.tell() + 8 + 3 + 7) >> 3)
                } else {
                    (max_data_bytes - 1) - ((enc.tell() + 7) >> 3)
                };
                redundancy_bytes = redundancy_bytes.min(max_redundancy).clamp(2, 257);
                if self.mode == Mode::Hybrid {
                    enc.enc_uint((redundancy_bytes - 2) as u32, 256);
                }
            }
        } else {
            redundancy = false;
        }
        if !redundancy {
            self.silk_bandwidth_switch = false;
            redundancy_bytes = 0;
        }

        // ── How many bytes CELT may use (`opus_encoder.c:2203-2225`) ────────────────────────────
        let start_band = if self.mode != Mode::Celt { 17 } else { 0 };
        let mut range_bytes;
        if self.mode == Mode::Silk {
            // "When in LPC only mode ... strip off trailing zero bytes": shrink to what SILK used,
            // so a decoder does not find 17 spare bits and go looking for a redundancy frame.
            range_bytes = ((enc.tell() + 7) >> 3) as usize;
            enc.done();
        } else {
            range_bytes = ((max_data_bytes - 1) - redundancy_bytes) as usize;
            enc.shrink(range_bytes as u32);
        }
        if self.mode == Mode::Hybrid {
            self.celt.set_silk_info(silk_info);
        }

        // ── The 5 ms redundant CELT frame, before the main one for a CELT->SILK switch ──────────
        let mut redundant_range = 0u32;
        if redundancy && celt_to_silk {
            // Only `start` moves (`opus_encoder.c:2242`): the redundant frame covers the whole
            // spectrum from band 0, but still stops where this packet's bandwidth stops. Coding it to
            // band 21 would put a band count in the bitstream that the decoder does not expect.
            self.celt
                .set_band_range(0, CeltEncoder::end_band_for_bandwidth(curr_bandwidth))?;
            self.celt.set_rate_control(CeltRateControl::ConstantBitrate);
            self.celt.set_bitrate(-1);
            let half = self.sample_rate_hz as usize / 200;
            redundant_length = {
                let channels = self.channels;
                let pcm = &self.pcm_buffer[..half * channels];
                self.celt.encode(
                    pcm,
                    half,
                    &mut redundant_payload[..redundancy_bytes as usize],
                )?
            };
            redundant_range = self.celt.final_range();
            self.celt.reset_state();
        }

        if self.mode != Mode::Silk {
            // Only meaningful when CELT actually runs. In SILK-only mode the C sets `start` anyway
            // (`opus_encoder.c:2255`) and its ctl does not range-check it against `end`; ours does,
            // and a SILK-only frame's `end` is 13 or 17, so setting `start = 17` there would be
            // rejected for a band range nothing is going to code.
            self.celt.set_band_range(
                start_band,
                CeltEncoder::end_band_for_bandwidth(curr_bandwidth),
            )?;
            self.celt.set_rate_control(if vbr {
                if self.mode == Mode::Hybrid || self.rate_control == RateControl::Variable {
                    // Hybrid always runs CELT unconstrained: the reservoir is SILK's business.
                    CeltRateControl::Vbr
                } else {
                    CeltRateControl::ConstrainedVbr
                }
            } else {
                CeltRateControl::ConstantBitrate
            });
            if vbr {
                // Hybrid gives CELT what SILK's *target* left over, not what SILK happened to
                // spend (`opus_encoder.c:2263`) — the actual spend varies frame to frame and using
                // it would make CELT's own reservoir chase SILK's noise.
                self.celt.set_bitrate(if self.mode == Mode::Hybrid {
                    (bitrate_bps - silk_target_bitrate).max(1)
                } else {
                    bitrate_bps
                });
            }
            if Some(self.mode) != self.previous_mode && self.previous_mode.is_some() {
                self.celt.reset_state();
                // "Prefilling": run a throwaway 2.5 ms frame so the overlap and the energy history
                // are not cold on the frame that matters (`opus_encoder.c:2287-2295`).
                let mut scratch = [0u8; 2];
                let channels = self.channels;
                let _ = self
                    .celt
                    .encode(&prefill[..quarter * channels], quarter, &mut scratch);
                self.celt.set_prediction(0)?;
            }
            if enc.tell() <= 8 * range_bytes as i32 {
                let produced = {
                    let channels = self.channels;
                    let pcm = &self.pcm_buffer[..frame_size * channels];
                    self.celt.encode_with_range_encoder(
                        pcm,
                        frame_size,
                        &mut enc,
                        range_bytes as i32,
                    )?
                };
                // The C's "put CELT->SILK redundancy data in the right place" move is unnecessary
                // here: the redundant frame was never written into this buffer, so shrinking the
                // range-coded part just changes where it is appended.
                range_bytes = produced;
            }
            enc.done();
        }

        // ── The 5 ms redundant CELT frame, after the main one for a SILK->CELT switch ───────────
        if redundancy && !celt_to_silk {
            let half = self.sample_rate_hz as usize / 200;
            let quarter = self.sample_rate_hz as usize / 400;
            self.celt.reset_state();
            self.celt
                .set_band_range(0, CeltEncoder::end_band_for_bandwidth(curr_bandwidth))?;
            self.celt.set_prediction(0)?;
            self.celt.set_rate_control(CeltRateControl::ConstantBitrate);
            self.celt.set_bitrate(-1);
            redundant_length = {
                let channels = self.channels;
                let mut scratch = [0u8; 2];
                // Counted from the start of the staging buffer, which is where libopus counts from
                // too: `pcm_buf` there already has the delay compensation in front of it, so the
                // redundant frame lands on the *last* 5 ms of the frame CELT just coded, not 4 ms
                // past its end.
                let warm_start = (frame_size - half - quarter) * channels;
                let _ = self.celt.encode(
                    &self.pcm_buffer[warm_start..warm_start + quarter * channels],
                    quarter,
                    &mut scratch,
                );
                let start = (frame_size - half) * channels;
                self.celt.encode(
                    &self.pcm_buffer[start..start + half * channels],
                    half,
                    &mut redundant_payload[..redundancy_bytes as usize],
                )?
            };
            redundant_range = self.celt.final_range();
        }

        let toc = generate_toc(self.mode, frame_rate, curr_bandwidth, self.stream_channels);
        // Everything the range coder still has to say is read out here, so the borrow it holds on
        // `payload` ends before the payload is staged.
        let range_tell = enc.tell();
        self.final_range = enc.rng() ^ redundant_range;

        // ── The generalised DTX decision (`opus_encoder.c:2364-2378`) ───────────────────────────
        if self.use_dtx && self.analysis_is_enabled(lsb_depth) && is_silence {
            let frame_ms_q1 = 2 * 1000 * frame_size as i32 / self.sample_rate_hz;
            if decide_dtx_mode(!is_silence, &mut self.no_activity_ms_q1, frame_ms_q1) {
                self.final_range = 0;
                return Ok(EncodedFrame { toc, length: 0 });
            }
        } else {
            self.no_activity_ms_q1 = 0;
        }

        // "In the unlikely case that the SILK encoder busted its target, tell the decoder to call
        // the PLC" (`opus_encoder.c:2380-2391`).
        if range_tell > (max_data_bytes - 1) * 8 {
            self.final_range = 0;
            return Ok(EncodedFrame { toc, length: 0 });
        }
        if self.mode == Mode::Silk && !redundancy {
            while range_bytes > 2 && payload[range_bytes - 1] == 0 {
                range_bytes -= 1;
            }
        }

        let length = range_bytes + redundant_length;
        let buffer = self.packer.next_frame_buffer();
        if buffer.len() < length {
            return Err(CodecError::OutputTooSmall {
                needed: length,
                have: buffer.len(),
            });
        }
        buffer[..range_bytes].copy_from_slice(&payload[..range_bytes]);
        buffer[range_bytes..length].copy_from_slice(&redundant_payload[..redundant_length]);
        Ok(EncodedFrame { toc, length })
    }

    /// High-pass this frame into [`OpusEncoder::pcm_buffer`], behind the delay compensation the CELT
    /// layer needs as look-behind (`opus_encoder.c:1793-1847`).
    fn stage_input(
        &mut self,
        pcm: &[f32],
        frame_size: usize,
        total_buffer: usize,
        encoder_buffer: usize,
    ) {
        let channels = self.channels;
        // The tail of the previous frame's filtered input.
        let start = (encoder_buffer - total_buffer) * channels;
        self.pcm_buffer[..total_buffer * channels]
            .copy_from_slice(&self.delay_buffer[start..start + total_buffer * channels]);

        // SILK owns the cutoff tracker; with SILK idle its value is stale, so CELT-only pins the
        // cutoff to the 60 Hz floor.
        let smth1 = if self.mode == Mode::Celt {
            VariableHighPass::celt_only_smth1_q15()
        } else {
            self.silk.high_pass_smth1_q15()
        };
        let cutoff = self.high_pass.advance(smth1);

        let Self {
            high_pass,
            pcm_buffer,
            application,
            sample_rate_hz,
            ..
        } = self;
        let out = &mut pcm_buffer[total_buffer * channels..(total_buffer + frame_size) * channels];
        if *application == Application::Voip {
            high_pass.filter_voip(
                pcm,
                out,
                cutoff,
                frame_size,
                channels,
                *sample_rate_hz as u32,
            );
        } else {
            high_pass.filter_dc_reject(pcm, out, frame_size, channels, *sample_rate_hz as u32);
        }

        // "This should filter out both NaNs and ridiculous signals that could cause NaNs further
        // down" (`opus_encoder.c:1836-1843`).
        let energy: f32 = out.iter().map(|&sample| sample * sample).sum();
        // `!(sum < 1e9f)` in the C, which catches a NaN as well as a runaway magnitude.
        if !energy.is_finite() || energy >= 1e9 {
            out.fill(0.0);
            high_pass.reset_memory();
        }
    }

    /// Slide the delay buffer along by one frame (`opus_encoder.c:2124-2132`).
    fn roll_delay_buffer(&mut self, frame_size: usize, total_buffer: usize, encoder_buffer: usize) {
        let channels = self.channels;
        let staged = (frame_size + total_buffer) * channels;
        if encoder_buffer > frame_size + total_buffer {
            let keep = (encoder_buffer - frame_size - total_buffer) * channels;
            self.delay_buffer.copy_within(frame_size * channels.., 0);
            self.delay_buffer[keep..keep + staged].copy_from_slice(&self.pcm_buffer[..staged]);
        } else {
            let skip = (frame_size + total_buffer - encoder_buffer) * channels;
            let take = encoder_buffer * channels;
            self.delay_buffer[..take].copy_from_slice(&self.pcm_buffer[skip..skip + take]);
        }
    }

    /// The SILK internal rate this bandwidth and budget allow (`opus_encoder.c:1939-1970`).
    fn silk_internal_rate(
        &self,
        curr_bandwidth: Bandwidth,
        max_data_bytes: i32,
        frame_rate: i32,
    ) -> InternalRate {
        let mut desired = match curr_bandwidth {
            Bandwidth::Narrowband => 8_000,
            Bandwidth::Mediumband => 12_000,
            _ => 16_000,
        };
        // "Don't allow bandwidth reduction at lowest bitrates in hybrid mode."
        let minimum = if self.mode == Mode::Hybrid {
            16_000
        } else {
            8_000
        };
        let mut maximum = 16_000;
        if self.mode == Mode::Silk {
            let mut effective_max_rate = frame_rate * max_data_bytes * 8;
            if frame_rate > 50 {
                effective_max_rate = effective_max_rate * 2 / 3;
            }
            if effective_max_rate < 8_000 {
                maximum = 12_000;
                desired = desired.min(12_000);
            }
            if effective_max_rate < 7_000 {
                maximum = 8_000;
                desired = desired.min(8_000);
            }
        }
        let rate = desired.clamp(minimum, maximum);
        match rate {
            8_000 => InternalRate::Narrow8k,
            12_000 => InternalRate::Medium12k,
            _ => InternalRate::Wide16k,
        }
    }

    /// SILK's `maxBits` for this frame (`opus_encoder.c:1976-2011`).
    fn silk_max_bits(
        &self,
        max_data_bytes: i32,
        redundancy: bool,
        redundancy_bytes: i32,
        silk_bitrate: i32,
        frame_size: usize,
        vbr: bool,
    ) -> i32 {
        let mut max_bits = (max_data_bytes - 1) * 8;
        if redundancy && redundancy_bytes >= 2 {
            // "Counting 1 bit for redundancy position and 20 bits for flag+size (only for hybrid)."
            max_bits -= redundancy_bytes * 8 + 1;
            if self.mode == Mode::Hybrid {
                max_bits -= 20;
            }
        }
        if !vbr {
            if self.mode == Mode::Hybrid {
                // "Allow SILK to steal up to 25% of the remaining bits."
                let other =
                    (max_bits - silk_bitrate * frame_size as i32 / self.sample_rate_hz).max(0);
                max_bits = (max_bits - other * 3 / 4).max(0);
            }
        } else if self.mode == Mode::Hybrid {
            // Constrained VBR: cap SILK at the share the *total* budget would give it.
            let max_rate = compute_silk_rate_for_hybrid(
                max_bits * self.sample_rate_hz / frame_size as i32,
                self.bandwidth,
                self.sample_rate_hz == 50 * frame_size as i32,
                vbr,
                self.lbrr_coded,
                self.stream_channels,
            );
            max_bits = max_rate * frame_size as i32 / self.sample_rate_hz;
        }
        max_bits.max(64)
    }

    /// Apply a SILK configuration, building or retuning as required.
    fn configure_silk(&mut self, config: SilkConfig) -> Result<(), CodecError> {
        match self.silk_configured {
            Some(_) => self.silk.reconfigure(config)?,
            None => self.silk = SilkEncoder::new(config)?,
        }
        self.silk_configured = Some(config);
        Ok(())
    }

    /// Resample this frame down to the SILK internal rate and encode it into `enc`.
    fn run_silk(
        &mut self,
        frame_size: usize,
        total_buffer: usize,
        internal_rate: InternalRate,
        enc: &mut RangeEncoder<'_>,
    ) -> Result<SilkOutcome, CodecError> {
        let channels = self.channels;
        let internal_channels = self.stream_channels;
        let internal_hz = internal_rate.khz() as u32 * 1000;
        let api_hz = self.sample_rate_hz as u32;
        let produced = frame_size * internal_rate.khz() / (self.sample_rate_hz as usize / 1000);

        let Self {
            pcm_buffer,
            resamplers,
            resample_in,
            resample_out,
            silk_pcm,
            silk,
            ..
        } = self;

        for channel in 0..internal_channels {
            resamplers[channel].configure_for_encoder(api_hz, internal_hz)?;
            // De-interleave, converting to the 16-bit domain SILK works in. A mono SILK layer under
            // a stereo input averages the two channels, as `silk_Encode` does (`enc_API.c:305-310`).
            let frame =
                &pcm_buffer[total_buffer * channels..(total_buffer + frame_size) * channels];
            for index in 0..frame_size {
                let sample = if channels == 2 && internal_channels == 1 {
                    let left = float_to_int16(frame[2 * index]);
                    let right = float_to_int16(frame[2 * index + 1]);
                    ((i32::from(left) + i32::from(right) + 1) >> 1) as i16
                } else {
                    float_to_int16(frame[index * channels + channel])
                };
                resample_in[index] = sample;
            }
            let written = resamplers[channel]
                .process(&mut resample_out[..produced], &resample_in[..frame_size])?;
            for index in 0..written {
                silk_pcm[index * internal_channels + channel] = resample_out[index];
            }
        }

        let result = silk.encode(&silk_pcm[..produced * internal_channels], enc)?;
        Ok(SilkOutcome {
            payload_bytes: result.payload_bytes,
            // `silk_mode.signalType` / `silk_mode.offset` as the CELT layer reads them. The SILK
            // encoder reports activity rather than the three-way type, which is the distinction the
            // hybrid branches actually use: they only ever test `!= 2` (voiced).
            signal_type: i32::from(result.active),
            offset: if result.active { 80 } else { 120 },
        })
    }
}

/// One encoded Opus frame, minus its TOC. `length == 0` is DTX.
#[derive(Debug, Clone, Copy)]
struct EncodedFrame {
    toc: u8,
    length: usize,
}

/// What the SILK layer reported for one frame.
#[derive(Debug, Clone, Copy)]
struct SilkOutcome {
    payload_bytes: usize,
    signal_type: i32,
    offset: i32,
}

/// `FLOAT2INT16` (`celt/float_cast.h`) — scale to the 16-bit domain, round to nearest, saturate.
fn float_to_int16(sample: f32) -> i16 {
    let scaled = (sample * 32768.0).clamp(-32768.0, 32767.0);
    // `lrintf` rounds half to even; `round_ties_even` is the same rule.
    scaled.round_ties_even() as i16
}

/// `gain_fade` (`opus_encoder.c:503-540`) — crossfade a gain change over the MDCT overlap so a
/// hybrid frame whose high-band allocation just moved does not step.
fn gain_fade(
    pcm: &mut [f32],
    from: f32,
    to: f32,
    frame_size: usize,
    channels: usize,
    sample_rate_hz: i32,
) {
    let increment = (48_000 / sample_rate_hz) as usize;
    let overlap = (OVERLAP / increment).min(frame_size);
    for index in 0..overlap {
        let window = WINDOW120[index * increment] * WINDOW120[index * increment];
        let gain = window * to + (1.0 - window) * from;
        for channel in 0..channels {
            pcm[index * channels + channel] *= gain;
        }
    }
    for index in overlap..frame_size {
        for channel in 0..channels {
            pcm[index * channels + channel] *= to;
        }
    }
}

/// `stereo_fade` (`opus_encoder.c:471-501`) — narrow the stereo image by pulling the two channels
/// towards their mid, crossfaded over the overlap.
fn stereo_fade(
    pcm: &mut [f32],
    from: f32,
    to: f32,
    frame_size: usize,
    channels: usize,
    sample_rate_hz: i32,
) {
    if channels != 2 {
        return;
    }
    let increment = (48_000 / sample_rate_hz) as usize;
    let overlap = (OVERLAP / increment).min(frame_size);
    let from = 1.0 - from;
    let to = 1.0 - to;
    for index in 0..frame_size {
        let gain = if index < overlap {
            let window = WINDOW120[index * increment] * WINDOW120[index * increment];
            window * to + (1.0 - window) * from
        } else {
            to
        };
        let difference = gain * 0.5 * (pcm[2 * index] - pcm[2 * index + 1]);
        pcm[2 * index] -= difference;
        pcm[2 * index + 1] += difference;
    }
}

impl std::fmt::Debug for OpusEncoder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpusEncoder")
            .field("sample_rate_hz", &self.sample_rate_hz)
            .field("channels", &self.channels)
            .field("application", &self.application)
            .field("bitrate_bps", &self.bitrate_bps)
            .field("rate_control", &self.rate_control)
            .field("mode", &self.mode)
            .field("bandwidth", &self.bandwidth)
            .field("stream_channels", &self.stream_channels)
            .finish_non_exhaustive()
    }
}

impl OpusEncoder {
    /// The "not enough space to be useful" packet (`opus_encoder.c:1203-1269`): a bare TOC that
    /// tells the decoder to conceal.
    fn emit_plc_packet(
        &mut self,
        frame_rate: i32,
        output: &mut [u8],
        max_data_bytes: i32,
        vbr: bool,
    ) -> Result<EncodeResult, CodecError> {
        let mut mode = self.mode;
        let mut bandwidth = self.bandwidth;
        let mut rate = frame_rate;
        let mut packet_code = 0u8;
        let mut multiframes = 0u8;

        if rate > 100 {
            mode = Mode::Celt;
        }
        // "40 ms -> 2 x 20 ms if in CELT_ONLY or HYBRID mode."
        if rate == 25 && mode != Mode::Silk {
            rate = 50;
            packet_code = 1;
        }
        if rate <= 16 {
            if output.len() == 1 || (mode == Mode::Silk && rate != 10) {
                mode = Mode::Silk;
                packet_code = u8::from(rate <= 12);
                rate = if rate == 12 { 25 } else { 16 };
            } else {
                multiframes = (50 / rate) as u8;
                rate = 50;
                packet_code = 3;
            }
        }
        if mode == Mode::Silk && bandwidth_index(bandwidth) > bandwidth_index(Bandwidth::Wideband) {
            bandwidth = Bandwidth::Wideband;
        } else if mode == Mode::Celt && bandwidth == Bandwidth::Mediumband {
            bandwidth = Bandwidth::Narrowband;
        } else if mode == Mode::Hybrid
            && bandwidth_index(bandwidth) <= bandwidth_index(Bandwidth::SuperWideband)
        {
            bandwidth = Bandwidth::SuperWideband;
        }

        output[0] = generate_toc(mode, rate, bandwidth, self.stream_channels) | packet_code;
        let mut bytes = if packet_code <= 1 { 1usize } else { 2 };
        if packet_code == 3 {
            if output.len() < 2 {
                return Err(CodecError::OutputTooSmall {
                    needed: 2,
                    have: output.len(),
                });
            }
            output[1] = multiframes;
        }
        if !vbr {
            let target = (max_data_bytes.max(bytes as i32) as usize).min(output.len());
            // Padding a bare TOC needs code 3, which the packer knows how to write.
            self.packer.clear();
            self.packer.commit_frame(0)?;
            bytes = self.packer.write(output[0], output, Some(target))?;
        }
        self.final_range = 0;
        self.previous_mode = Some(mode);
        self.first = false;
        Ok(EncodeResult {
            bytes,
            mode,
            bandwidth,
            stream_channels: self.stream_channels,
            final_range: 0,
        })
    }
}

/// Clamp a bandwidth to a ceiling.
fn cap_bandwidth(bandwidth: Bandwidth, ceiling: Bandwidth) -> Bandwidth {
    if bandwidth_index(bandwidth) > bandwidth_index(ceiling) {
        ceiling
    } else {
        bandwidth
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::packet;

    /// A deterministic speech-ish signal: a pitch pulse train through a resonance, plus noise.
    fn speech(samples: usize, channels: usize) -> Vec<i16> {
        let mut state = 13_579u32;
        let mut history = [0.0f32; 2];
        let mut out = Vec::with_capacity(samples * channels);
        for index in 0..samples {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let noise = ((state >> 20) as i32 - 2048) as f32 * 1.5;
            let pulse = if index % 240 == 0 { 6000.0 } else { 0.0 };
            let value = pulse + noise + 1.5 * history[0] - 0.85 * history[1];
            history[1] = history[0];
            history[0] = value;
            let sample = value.clamp(-24_000.0, 24_000.0) as i16;
            out.push(sample);
            if channels == 2 {
                // A genuinely wide image: the right channel is a delayed, attenuated copy.
                out.push((i32::from(sample) / 3) as i16);
            }
        }
        out
    }

    /// Encode a stream and return one result per packet, along with the packets.
    fn run(
        encoder: &mut OpusEncoder,
        source: &[i16],
        frame_size: usize,
        packets: usize,
    ) -> Vec<(EncodeResult, Vec<u8>)> {
        let channels = encoder.channels();
        let mut results = Vec::new();
        for index in 0..packets {
            let start = index * frame_size * channels;
            if start + frame_size * channels > source.len() {
                break;
            }
            let mut output = vec![0u8; 1500];
            let result = encoder
                .encode(
                    &source[start..start + frame_size * channels],
                    frame_size,
                    &mut output,
                )
                .expect("encode");
            output.truncate(result.bytes);
            results.push((result, output));
        }
        results
    }

    /// A configuration Opus does not define must be refused rather than silently coerced.
    #[test]
    fn illegal_configurations_are_rejected() {
        assert!(OpusEncoder::new(44_100, 1, Application::Voip).is_err());
        assert!(OpusEncoder::new(48_000, 0, Application::Voip).is_err());
        assert!(OpusEncoder::new(48_000, 3, Application::Voip).is_err());

        let mut encoder = OpusEncoder::new(48_000, 2, Application::Audio).expect("new");
        assert!(encoder.set_complexity(11).is_err());
        assert!(encoder.set_complexity(-1).is_err());
        assert!(encoder.set_packet_loss_percent(101).is_err());
        assert!(encoder.set_lsb_depth(7).is_err());
        assert!(encoder.set_lsb_depth(25).is_err());
        assert!(encoder.set_bitrate(Some(100)).is_err());
        assert!(encoder.set_forced_channels(Some(3)).is_err());
        assert!(encoder.set_forced_channels(Some(0)).is_err());
        assert!(encoder.set_bitrate(Some(64_000)).is_ok());

        // A frame size Opus has no configuration for.
        let source = speech(1_000, 2);
        let mut output = [0u8; 1500];
        assert!(encoder.encode(&source, 700, &mut output).is_err());
        // Too little PCM for the frame size asked for.
        assert!(encoder.encode(&source[..10], 960, &mut output).is_err());
        // Nowhere to put the packet.
        assert!(encoder.encode(&source, 960, &mut []).is_err());
    }

    /// Every frame duration Opus defines must produce a packet whose TOC says exactly that
    /// duration — including the ones that have to be split across several frames.
    #[test]
    fn every_frame_duration_round_trips_through_the_toc() {
        // 2.5 to 120 ms at 48 kHz.
        let durations = [120usize, 240, 480, 960, 1920, 2880, 3840, 4800, 5760];
        let source = speech(6_000 * 4, 1);
        for frame_size in durations {
            let mut encoder = OpusEncoder::new(48_000, 1, Application::Voip).expect("new");
            encoder.set_bitrate(Some(32_000)).expect("bitrate");
            for (index, (result, packet)) in run(&mut encoder, &source, frame_size, 4)
                .into_iter()
                .enumerate()
            {
                let parsed = packet::parse(&packet).expect("our own packet must parse");
                let samples = parsed.toc.samples_per_frame(48_000) * parsed.frame_count();
                assert_eq!(
                    samples, frame_size,
                    "{frame_size} samples, packet {index}: TOC says {samples}"
                );
                assert!(result.bytes >= 1, "packet {index} was empty");
                assert_eq!(usize::from(parsed.toc.channels()), result.stream_channels);
            }
        }
    }

    /// The mode must be *decided*, not fixed: the rate ladder has to walk SILK to hybrid to
    /// CELT-only on the same input, and the application has to move where it does so.
    #[test]
    fn the_mode_follows_the_rate_and_the_application() {
        let source = speech(960 * 12, 1);
        let modes_at = |application: Application, bitrate: i32| -> Mode {
            let mut encoder = OpusEncoder::new(48_000, 1, application).expect("new");
            encoder.set_bitrate(Some(bitrate)).expect("bitrate");
            let results = run(&mut encoder, &source, 960, 10);
            results.last().expect("packets").0.mode
        };

        // `Mode` is deliberately not `Ord` (it is a wire enum, not an ordered one), so coverage is
        // collected as a list and checked by membership.
        let seen: Vec<Mode> = [
            8_000i32, 12_000, 16_000, 24_000, 32_000, 48_000, 96_000, 160_000,
        ]
        .into_iter()
        .map(|bitrate| modes_at(Application::Audio, bitrate))
        .collect();
        for expected in [Mode::Silk, Mode::Hybrid, Mode::Celt] {
            assert!(
                seen.contains(&expected),
                "the rate ladder never reached {expected:?}: {seen:?}"
            );
        }

        // Restricted low delay is CELT-only whatever the rate.
        for bitrate in [8_000i32, 32_000, 160_000] {
            assert_eq!(
                modes_at(Application::RestrictedLowdelay, bitrate),
                Mode::Celt,
                "restricted low delay at {bitrate}"
            );
        }
        // And a forced mode is honoured.
        let mut forced = OpusEncoder::new(48_000, 1, Application::Audio).expect("new");
        forced.set_bitrate(Some(96_000)).expect("bitrate");
        forced.set_forced_mode(Some(Mode::Silk));
        forced.set_bandwidth(Some(Bandwidth::Wideband));
        let results = run(&mut forced, &source, 960, 6);
        assert!(results.iter().all(|(result, _)| result.mode == Mode::Silk));
    }

    /// The bandwidth must climb with the rate and must honour both the cap and the override.
    #[test]
    fn the_bandwidth_follows_the_rate_and_the_caps() {
        let source = speech(960 * 12, 1);
        let bandwidth_at = |bitrate: i32| -> Bandwidth {
            let mut encoder = OpusEncoder::new(48_000, 1, Application::Audio).expect("new");
            encoder.set_bitrate(Some(bitrate)).expect("bitrate");
            run(&mut encoder, &source, 960, 8)
                .last()
                .expect("packets")
                .0
                .bandwidth
        };
        assert!(
            bandwidth_index(bandwidth_at(8_000)) < bandwidth_index(bandwidth_at(96_000)),
            "the bandwidth must widen with the rate"
        );

        let mut capped = OpusEncoder::new(48_000, 1, Application::Audio).expect("new");
        capped.set_bitrate(Some(160_000)).expect("bitrate");
        capped.set_max_bandwidth(Bandwidth::Wideband);
        for (result, _) in run(&mut capped, &source, 960, 6) {
            assert!(
                bandwidth_index(result.bandwidth) <= bandwidth_index(Bandwidth::Wideband),
                "the cap was ignored: {:?}",
                result.bandwidth
            );
        }

        // A sub-48 kHz input cannot be coded above its own Nyquist.
        let narrow_source = speech(160 * 12, 1);
        let mut narrow = OpusEncoder::new(8_000, 1, Application::Voip).expect("new");
        narrow.set_bitrate(Some(64_000)).expect("bitrate");
        for (result, _) in run(&mut narrow, &narrow_source, 160, 6) {
            assert_eq!(
                result.bandwidth,
                Bandwidth::Narrowband,
                "8 kHz input coded above its Nyquist"
            );
        }
    }

    /// The stereo decision must be rate-driven and must be honoured on the wire, and a forced count
    /// must win.
    #[test]
    fn the_stream_channel_count_follows_the_rate() {
        let source = speech(960 * 12, 2);
        let channels_at = |bitrate: i32| -> usize {
            let mut encoder = OpusEncoder::new(48_000, 2, Application::Audio).expect("new");
            encoder.set_bitrate(Some(bitrate)).expect("bitrate");
            let results = run(&mut encoder, &source, 960, 8);
            let (result, packet) = results.last().expect("packets");
            let parsed = packet::parse(packet).expect("parse");
            assert_eq!(usize::from(parsed.toc.channels()), result.stream_channels);
            result.stream_channels
        };
        assert_eq!(channels_at(8_000), 1, "a low rate must collapse to mono");
        assert_eq!(channels_at(160_000), 2, "a high rate must stay stereo");

        let mut forced = OpusEncoder::new(48_000, 2, Application::Audio).expect("new");
        forced.set_bitrate(Some(160_000)).expect("bitrate");
        forced.set_forced_channels(Some(1)).expect("force mono");
        for (result, _) in run(&mut forced, &source, 960, 6) {
            assert_eq!(result.stream_channels, 1, "forced mono was ignored");
        }
    }

    /// CBR must produce exactly the target size on every packet; VBR must not.
    #[test]
    fn cbr_packets_are_exactly_the_target_size() {
        let source = speech(960 * 20, 1);
        let target = 32_000 * 20 / 1000 / 8;

        let mut cbr = OpusEncoder::new(48_000, 1, Application::Audio).expect("new");
        cbr.set_bitrate(Some(32_000)).expect("bitrate");
        cbr.set_rate_control(RateControl::Constant);
        let cbr_sizes: Vec<usize> = run(&mut cbr, &source, 960, 16)
            .into_iter()
            .map(|(result, _)| result.bytes)
            .collect();
        assert!(
            cbr_sizes.iter().all(|&size| size == target as usize),
            "CBR sizes were not constant at {target}: {cbr_sizes:?}"
        );

        let mut vbr = OpusEncoder::new(48_000, 1, Application::Audio).expect("new");
        vbr.set_bitrate(Some(32_000)).expect("bitrate");
        vbr.set_rate_control(RateControl::Variable);
        let vbr_sizes: Vec<usize> = run(&mut vbr, &source, 960, 16)
            .into_iter()
            .map(|(result, _)| result.bytes)
            .collect();
        assert!(
            vbr_sizes.iter().any(|&size| size != target as usize),
            "VBR produced constant sizes, so the knob does nothing: {vbr_sizes:?}"
        );

        // Constrained VBR must respect a hard `output` ceiling, which is the constraint that
        // matters to a caller with a fixed MTU.
        let mut constrained = OpusEncoder::new(48_000, 1, Application::Audio).expect("new");
        constrained.set_bitrate(Some(96_000)).expect("bitrate");
        constrained.set_rate_control(RateControl::ConstrainedVariable);
        for index in 0..16 {
            let mut output = [0u8; 80];
            let result = constrained
                .encode(&source[index * 960..(index + 1) * 960], 960, &mut output)
                .expect("encode");
            assert!(
                result.bytes <= 80,
                "packet {index} was {} bytes",
                result.bytes
            );
        }
    }

    /// DTX must drop a silent stream to bare TOC packets, and must not touch a live one. The knob
    /// has to be wired both ways.
    #[test]
    fn dtx_drops_silence_and_leaves_speech_alone() {
        let silence = vec![0i16; 960 * 60];
        let count = |dtx: bool, source: &[i16]| -> usize {
            let mut encoder = OpusEncoder::new(48_000, 1, Application::Voip).expect("new");
            encoder.set_bitrate(Some(24_000)).expect("bitrate");
            encoder.set_dtx(dtx);
            run(&mut encoder, source, 960, 50)
                .into_iter()
                .filter(|(result, _)| result.bytes <= 2)
                .count()
        };
        let dropped = count(true, &silence);
        assert!(
            dropped > 10,
            "DTX only dropped {dropped} of 50 silent packets"
        );
        assert_eq!(
            count(false, &silence),
            0,
            "silence was dropped with DTX disabled"
        );

        let speech_source = speech(960 * 60, 1);
        assert_eq!(
            count(true, &speech_source),
            0,
            "DTX dropped a packet of real speech"
        );
    }

    /// In-band FEC must cost real bits, and only where SILK is running to carry it.
    #[test]
    fn in_band_fec_costs_bits_and_only_exists_in_silk() {
        let source = speech(960 * 24, 1);
        let total = |fec: bool| -> usize {
            let mut encoder = OpusEncoder::new(48_000, 1, Application::Voip).expect("new");
            encoder.set_bitrate(Some(24_000)).expect("bitrate");
            encoder.set_in_band_fec(fec);
            encoder.set_packet_loss_percent(20).expect("loss");
            run(&mut encoder, &source, 960, 20)
                .into_iter()
                .map(|(result, _)| result.bytes)
                .sum()
        };
        assert!(
            total(true) > total(false),
            "FEC cost nothing: {} vs {}",
            total(true),
            total(false)
        );

        // With loss reported and FEC on, the mode must be one that can carry it.
        let mut encoder = OpusEncoder::new(48_000, 1, Application::Audio).expect("new");
        encoder.set_bitrate(Some(96_000)).expect("bitrate");
        encoder.set_in_band_fec(true);
        encoder.set_packet_loss_percent(30).expect("loss");
        for (result, _) in run(&mut encoder, &source, 960, 8) {
            assert_ne!(
                result.mode,
                Mode::Celt,
                "FEC was requested but the mode cannot carry it"
            );
        }
    }

    /// Every input rate must encode, and the packet must describe itself correctly at that rate.
    #[test]
    fn every_input_rate_encodes() {
        for rate in [8_000u32, 12_000, 16_000, 24_000, 48_000] {
            for channels in [1usize, 2] {
                let frame_size = rate as usize / 50;
                let source = speech(frame_size * 12, channels);
                let mut encoder = OpusEncoder::new(rate, channels, Application::Voip).expect("new");
                encoder.set_bitrate(Some(32_000)).expect("bitrate");
                let results = run(&mut encoder, &source, frame_size, 8);
                assert_eq!(results.len(), 8, "{rate} Hz / {channels} ch");
                for (index, (result, packet)) in results.into_iter().enumerate() {
                    let parsed = packet::parse(&packet).expect("parse");
                    assert_eq!(
                        parsed.toc.samples_per_frame(rate) * parsed.frame_count(),
                        frame_size,
                        "{rate} Hz / {channels} ch packet {index}"
                    );
                    assert!(result.bytes > 1);
                }
            }
        }
    }

    /// A NaN or a runaway input must be discarded rather than poisoning the encoder: the packet must
    /// still be legal and the *next* frame of real audio must come back normally.
    #[test]
    fn a_poisoned_frame_does_not_poison_the_encoder() {
        let mut encoder = OpusEncoder::new(48_000, 1, Application::Voip).expect("new");
        encoder.set_bitrate(Some(32_000)).expect("bitrate");
        let mut output = vec![0u8; 1500];

        let poison = vec![f32::NAN; 960];
        let result = encoder
            .encode_float(&poison, 960, &mut output)
            .expect("a NaN frame must encode, not error");
        packet::parse(&output[..result.bytes]).expect("the packet must still be legal");

        let source = speech(960 * 4, 1);
        for index in 0..4 {
            let result = encoder
                .encode(&source[index * 960..(index + 1) * 960], 960, &mut output)
                .expect("encode");
            assert!(
                result.bytes > 2,
                "the encoder did not recover: packet {index}"
            );
        }
    }

    /// The float and integer entry points must describe the same signal the same way.
    #[test]
    fn the_float_and_integer_entry_points_agree() {
        let source = speech(960 * 8, 1);
        let float: Vec<f32> = source
            .iter()
            .map(|&sample| f32::from(sample) * (1.0 / 32768.0))
            .collect();

        let mut integer_encoder = OpusEncoder::new(48_000, 1, Application::Voip).expect("new");
        integer_encoder.set_bitrate(Some(32_000)).expect("bitrate");
        let mut float_encoder = OpusEncoder::new(48_000, 1, Application::Voip).expect("new");
        float_encoder.set_bitrate(Some(32_000)).expect("bitrate");
        // The float path declares a 24-bit input depth where the integer one declares 16, which is
        // the only difference between them; pin the depth so the two are genuinely comparable.
        float_encoder.set_lsb_depth(16).expect("depth");

        for index in 0..6 {
            let range = index * 960..(index + 1) * 960;
            let mut a = vec![0u8; 1500];
            let mut b = vec![0u8; 1500];
            let integer = integer_encoder
                .encode(&source[range.clone()], 960, &mut a)
                .expect("integer");
            let floating = float_encoder
                .encode_float(&float[range], 960, &mut b)
                .expect("float");
            assert_eq!(integer.mode, floating.mode, "packet {index}");
            assert_eq!(integer.bandwidth, floating.bandwidth, "packet {index}");
            assert_eq!(a[..integer.bytes], b[..floating.bytes], "packet {index}");
        }
    }

    /// A mode switch must not desynchronise the packet's own accounting: the TOC must describe what
    /// was coded, and the final range must be non-zero for every non-DTX packet.
    #[test]
    fn a_mode_switch_produces_self_consistent_packets() {
        let source = speech(960 * 40, 1);
        let mut encoder = OpusEncoder::new(48_000, 1, Application::Audio).expect("new");
        let mut modes: Vec<Mode> = Vec::new();
        for index in 0..30 {
            // Sweep the rate across the SILK/CELT boundary every few packets, which is what forces
            // the switch and the redundancy frames that bridge it.
            let bitrate = if (index / 5) % 2 == 0 {
                12_000
            } else {
                128_000
            };
            encoder.set_bitrate(Some(bitrate)).expect("bitrate");
            let mut output = vec![0u8; 1500];
            let result = encoder
                .encode(&source[index * 960..(index + 1) * 960], 960, &mut output)
                .expect("encode");
            let parsed = packet::parse(&output[..result.bytes]).expect("parse");
            assert_eq!(parsed.toc.mode(), result.mode, "packet {index}");
            assert_eq!(parsed.toc.bandwidth(), result.bandwidth, "packet {index}");
            assert_eq!(
                parsed.toc.samples_per_frame(48_000) * parsed.frame_count(),
                960,
                "packet {index}"
            );
            assert_ne!(result.final_range, 0, "packet {index} reported no range");
            if !modes.contains(&result.mode) {
                modes.push(result.mode);
            }
        }
        assert!(
            modes.len() >= 2,
            "the rate sweep never switched mode: {modes:?}"
        );
    }
}
