//! The SILK encoder's packet driver (libopus `silk/enc_API.c:110-590`) — the entry point that ties
//! the VAD, the stereo conversion, the analysis, the noise-shaping quantiser and the bitstream
//! writer into one Opus frame's SILK layer.
//!
//! # What one call does
//!
//! ```text
//!   per 20 ms (or 10 ms) SILK frame interval, up to three per packet:
//!     stereo_LR_to_MS              -> mid/side + predictor indices + the mid/side rate split
//!     VAD (both channels)          -> signal type, DTX eligibility, the analysis' measures
//!     control_SNR                  -> the quality target from this frame's share of the budget
//!     encode_frame (per channel)   -> analysis -> NSQ -> encode_indices + encode_pulses
//!   once, at the head of the packet:
//!     the LBRR flags and the previous packet's LBRR frames
//!   once, at the end:
//!     patch the VAD/LBRR flag bits back into the first bytes
//! ```
//!
//! # Three things about this layer that are easy to get wrong
//!
//! * **The flags are written twice.** The LP-layer header's VAD and LBRR bits sit at the very start
//!   of the packet, but they are not known until every frame has been encoded. libopus reserves the
//!   space up front by coding a zero with a tailored ICDF and then rewrites those bits in place with
//!   `ec_enc_patch_initial_bits` (`enc_API.c:345-349`, `:535-537`). Anything else would either cost
//!   a whole extra pass or put the flags at the wrong end of the packet.
//! * **LBRR is a packet late.** The redundant copy of frame *n* is carried in packet *n + 1*, which
//!   is the entire point — a receiver that lost packet *n* still has it. So this driver writes the
//!   LBRR frames it generated **last** call, then generates this call's, and the two never appear
//!   in the same packet.
//! * **DTX is decided per packet, not per frame.** A frame being inactive is not enough; every
//!   channel of every frame in the packet has to be in DTX before the payload is dropped
//!   (`enc_API.c:540-542`). Otherwise a 60 ms packet with one active frame would lose the other two.
//!
//! # The seam above this
//!
//! [`SilkEncoder::encode`] takes PCM **at the SILK internal rate** (8, 12 or 16 kHz) and produces the
//! SILK layer of one Opus frame into a caller-supplied [`RangeEncoder`]. The API-rate resampler is
//! the *Opus* layer's (`silk_resampler` driven from `enc_API.c:292-329`), and so is the adaptive
//! high-pass **filter** (`opus_encoder.c:1799-1809`); the mode/bandwidth decision that chooses the
//! internal rate is the same layer's business.
//!
//! The high-pass's *tracker* is the one part of that split that lives here, because libopus puts it
//! here too: `silk_HP_variable_cutoff` (`enc_API.c:398`) drives `variable_HP_smth1_Q15` from SILK's
//! own pitch lag, signal type, speech activity and input quality, none of which the Opus layer can
//! see. [`SilkEncoder::high_pass_smth1_q15`] is what the Opus layer reads out of it, exactly as
//! `opus_encoder.c:1799` reaches into `state_Fxx[0].sCmn`.

use crate::opus::range_coder::RangeEncoder;
use crate::opus::silk::enc::bitstream::{encode_indices, encode_pulses};
use crate::opus::silk::enc::fixed::lin2log;
use crate::opus::silk::enc::frame::{AnalysisConfig, ComplexitySettings};
use crate::opus::silk::enc::lp_transition::{
    low_pass_variable_cutoff, LowPassState, TRANSITION_FRAMES,
};
use crate::opus::silk::enc::rate_control::{
    control_snr, encode_frame, FrameEncodeRequest, FrameEncoderState, LbrrFrame,
};
use crate::opus::silk::enc::stereo::{
    encode_mid_only, encode_predictors, left_right_to_mid_side, StereoEncoderState, StereoIndices,
};
use crate::opus::silk::enc::vad::{
    analyse, classify, DtxState, VadState, LBRR_SPEECH_ACTIVITY_THRESHOLD_Q8,
};
use crate::opus::silk::enc::{SignalMeasures, LA_SHAPE_MS};
use crate::opus::silk::fixed::{smlawb, smulbb, smulwb};
use crate::opus::silk::tables::{LBRR_FLAGS_2_ICDF, LBRR_FLAGS_3_ICDF};
use crate::opus::silk::types::{
    CondCoding, InternalRate, SignalType, SubframeLayout, MAX_FRAMES_PER_PACKET, MAX_FRAME_LENGTH,
};
use crate::CodecError;

/// `ftb` for every SILK ICDF symbol.
const ICDF_FTB: u32 = 8;

/// The float input buffer each channel keeps: `2 * MAX_FRAME_LENGTH + LA_SHAPE_MAX`, as libopus'
/// `x_buf` (`structs_FLP.h:57`).
const INPUT_BUFFER: usize = 2 * MAX_FRAME_LENGTH + LA_SHAPE_MS * 16;

/// `BITRESERVOIR_DECAY_TIME_MS` (`tuning_parameters.h:44`) — how fast the bit reservoir forgives an
/// overspend.
const BIT_RESERVOIR_DECAY_MS: i32 = 500;

/// `VARIABLE_HP_MIN_CUTOFF_HZ` (`tuning_parameters.h:72`).
pub const MIN_CUTOFF_HZ: i32 = 60;
/// `VARIABLE_HP_MAX_CUTOFF_HZ` (`tuning_parameters.h:73`).
pub const MAX_CUTOFF_HZ: i32 = 100;

/// How the encoder should spend its bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateMode {
    /// Variable bitrate: a frame that fits its share of the budget is kept whatever it cost.
    Variable,
    /// Constrained VBR: still variable, but no packet may exceed `max_bytes`.
    ConstrainedVariable,
    /// Constant bitrate: every packet is driven up to the target.
    Constant,
}

/// What the encoder is configured to produce.
#[derive(Debug, Clone, Copy)]
pub struct EncoderConfig {
    /// `desiredInternalSampleRate` — the internal rate the Opus layer *wants*
    /// (`opus_encoder.c:1939-1946`).
    ///
    /// **This is a request, not a setting.** SILK owns its own rate and moves to a new one only
    /// when the bandwidth state machine says it may — see [`SilkEncoder::control`] and
    /// [`SilkEncoder::internal_rate`], which is the rate the input must actually be supplied at.
    pub internal_rate: InternalRate,
    /// `minInternalSampleRate` (`opus_encoder.c:1947-1952`) — 16 kHz in hybrid, where the CELT half
    /// assumes SILK covers the whole low band, and 8 kHz otherwise. Unlike
    /// [`EncoderConfig::internal_rate`] this is a *bound*: a current rate below it changes at once,
    /// with no transition and no redundancy, because the alternative is an illegal stream.
    pub min_internal_rate: InternalRate,
    /// `maxInternalSampleRate` (`opus_encoder.c:1954-1970`) — 16 kHz, dropped to 12 or 8 when the
    /// packet budget cannot carry a wider band. A bound, like
    /// [`EncoderConfig::min_internal_rate`].
    pub max_internal_rate: InternalRate,
    /// `API_sampleRate` — the rate the Opus layer's own resampler feeds from. SILK never resamples
    /// here (the Opus layer owns that), but the rate still bounds the internal one: coding above
    /// the input's own Nyquist is wasted bits (`control_audio_bandwidth.c:56-61`).
    pub api_rate_hz: i32,
    /// `opusCanSwitch` — the Opus layer's answer to the previous packet's
    /// [`ControlOutcome::switch_ready`]: it has committed to covering the seam with a redundancy
    /// frame, so SILK may now actually move to the new rate
    /// (`opus_encoder.c:2065`, `control_audio_bandwidth.c:68`).
    pub opus_can_switch: bool,
    /// Opus frame duration in ms — 10, 20, 40 or 60.
    pub duration_ms: usize,
    /// Internal channels: 1 (mono) or 2 (mid/side).
    pub channels: usize,
    /// Target bitrate in bits per second.
    pub bitrate_bps: i32,
    /// Complexity, 0..=10. Genuinely wired: it selects the search depths in
    /// [`ComplexitySettings`], including how many noise-shaping quantiser paths stay alive.
    pub complexity: u8,
    /// How to spend the budget.
    pub rate_mode: RateMode,
    /// Hard cap on the payload, in bytes. Ignored by [`RateMode::Variable`] except as a safety
    /// ceiling.
    pub max_bytes: usize,
    /// Whether in-band FEC (LBRR) may be generated.
    pub use_in_band_fec: bool,
    /// Whether DTX may drop a silent packet.
    pub use_dtx: bool,
    /// The far end's reported packet loss, 0..=100. Moves the LBRR gain increase and the LTP
    /// scaling decision.
    pub packet_loss_percent: i32,
    /// `silk_mode.toMono` — the Opus layer is about to drop this stream to one coded channel, so
    /// fade the side channel out over this packet rather than cutting it (`silk_stereo_LR_to_MS`'s
    /// `toMono`, `stereo_LR_to_MS.c:117-127`). It is set for exactly one packet before the switch.
    pub to_mono: bool,
}

impl EncoderConfig {
    /// A sane mono configuration at one rate and duration.
    #[must_use]
    pub fn new(internal_rate: InternalRate, duration_ms: usize, bitrate_bps: i32) -> Self {
        Self {
            internal_rate,
            min_internal_rate: InternalRate::Narrow8k,
            max_internal_rate: InternalRate::Wide16k,
            api_rate_hz: 48_000,
            opus_can_switch: false,
            duration_ms,
            channels: 1,
            bitrate_bps,
            complexity: 10,
            rate_mode: RateMode::Variable,
            max_bytes: 1275,
            use_in_band_fec: false,
            use_dtx: false,
            packet_loss_percent: 0,
            to_mono: false,
        }
    }

    /// `nFramesPerPacket` and `nb_subfr` for this duration.
    fn layout(&self) -> Result<SubframeLayout, CodecError> {
        SubframeLayout::from_duration_ms(self.duration_ms)
    }
}

/// One internal channel's whole encoder state.
#[derive(Debug, Clone, Copy)]
struct ChannelState {
    /// The analysis, quantiser and entropy state.
    frame: FrameEncoderState,
    /// The VAD's own state.
    vad: VadState,
    /// DTX bookkeeping.
    dtx: DtxState,
    /// `x_buf` — the float input history, lookahead included.
    input: [f32; INPUT_BUFFER],
    /// `VAD_flags` for this packet.
    vad_flags: [bool; MAX_FRAMES_PER_PACKET],
    /// `LBRR_flags` — set while generating, cleared once written into the *next* packet.
    lbrr_flags: [bool; MAX_FRAMES_PER_PACKET],
    /// `pulses_LBRR` / `indices_LBRR` — the redundant frames awaiting the next packet.
    lbrr: [LbrrFrame; MAX_FRAMES_PER_PACKET],
    /// `LBRR_flag` — whether this channel wrote any LBRR data into the packet being built.
    ///
    /// Deliberately **not** `lbrr_flags.iter().any(...)` at patch time: by then those flags have been
    /// cleared and repopulated with the frames generated for the *next* packet, so reading them
    /// would advertise redundancy this packet does not carry. libopus keeps the two apart for the
    /// same reason (`enc_API.c:359`, `:527`).
    lbrr_flag: bool,
    /// `LBRR_GainIncreases`.
    lbrr_gain_increase: i32,
    /// Whether LBRR was enabled for the previous packet, which decides the gain increase.
    lbrr_was_enabled: bool,
    /// The VAD's verdict on the frame just analysed. Kept whole rather than reduced to
    /// `speech_activity_Q8`: the stereo smoother reads the activity, the analysis front end reads
    /// all four fields (see [`SignalMeasures`]), and `silk_HP_variable_cutoff` reads the activity
    /// and the lowest input-quality band.
    measures: SignalMeasures,
    /// `fs_kHz` — this channel's *current* internal rate in kHz, or 0 before it has ever been
    /// controlled. Per channel because that is where libopus keeps it
    /// (`silk_encoder_state.fs_kHz`); the two are held equal by `force_fs_kHz`
    /// (`enc_API.c:251-253`).
    fs_khz: i32,
    /// `sLP` — the bandwidth-transition low-pass. Per channel, and it survives the rate reset that
    /// `silk_setup_fs` performs, because it is what carries the transition *schedule*.
    low_pass: LowPassState,
}

impl Default for ChannelState {
    fn default() -> Self {
        let mut frame = FrameEncoderState::default();
        // `silk_control_encoder`'s reset (`control_codec.c:246-258`).
        frame.analysis.shape.last_gain_index = 10;
        frame.analysis.previous_lag = 100;
        Self {
            frame,
            vad: VadState::default(),
            dtx: DtxState::default(),
            input: [0.0; INPUT_BUFFER],
            vad_flags: [false; MAX_FRAMES_PER_PACKET],
            lbrr_flags: [false; MAX_FRAMES_PER_PACKET],
            lbrr: [LbrrFrame::default(); MAX_FRAMES_PER_PACKET],
            lbrr_flag: false,
            lbrr_gain_increase: 7,
            lbrr_was_enabled: false,
            measures: SignalMeasures::default(),
            fs_khz: 0,
            low_pass: LowPassState::default(),
        }
    }
}

/// What [`SilkEncoder::control`] resolved for the packet about to be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlOutcome {
    /// The rate SILK will actually code at, which is the rate the caller must resample its input to.
    /// It is **not** necessarily [`EncoderConfig::internal_rate`]: a move between rates is gated on
    /// the Opus layer covering the seam.
    pub internal_rate: InternalRate,
    /// `encControl->switchReady` (`control_audio_bandwidth.c:88`, `:116`) — SILK wants a different
    /// internal rate and has finished whatever ramp that needs, so it is asking the Opus layer to
    /// emit a redundancy frame and set [`EncoderConfig::opus_can_switch`] on the next packet. Room
    /// for that frame has already been taken out of this packet's SILK budget.
    pub switch_ready: bool,
}

/// What one `encode` call produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeResult {
    /// Payload size in bytes. **Zero means DTX**: every channel of every frame was inactive and the
    /// packet should not be sent at all (`enc_API.c:540-542`).
    pub payload_bytes: usize,
    /// Whether any frame of the packet was voice-active.
    pub active: bool,
    /// Whether this packet carries LBRR data for the *previous* one.
    pub carries_redundancy: bool,
}

/// The SILK encoder.
///
/// Stateful and single-owner by construction: the analysis, quantiser, VAD, stereo and bit
/// reservoir all carry state across packets, so one instance encodes exactly one stream.
#[derive(Debug, Clone)]
pub struct SilkEncoder {
    config: EncoderConfig,
    channels: [ChannelState; 2],
    stereo: StereoEncoderState,
    /// `predIx` / `mid_only_flags` for the packet being built.
    stereo_indices: [StereoIndices; MAX_FRAMES_PER_PACKET],
    /// `prev_decode_only_middle`.
    previous_mid_only: bool,
    /// `nBitsExceeded` — the bit reservoir, in bits, 0..=10000.
    bits_exceeded: i32,
    /// `nBitsUsedLBRR` — an exponential moving average of what LBRR costs.
    lbrr_bits_used: i32,
    /// `state_Fxx[0].sCmn.variable_HP_smth1_Q15` — the SILK-side half of the adaptive high-pass
    /// (`silk_HP_variable_cutoff`). The filter itself is the Opus layer's; only the tracking state
    /// belongs here, because it is driven by SILK's own pitch and quality measures.
    high_pass_smth1_q15: i32,
    /// The rate SILK is currently coding at — `state_Fxx[0].sCmn.fs_kHz`, resolved by
    /// [`SilkEncoder::control`] and **not** simply whatever the Opus layer asked for.
    internal_rate: InternalRate,
    /// `allowBandwidthSwitch` (`enc_API.c:548-557`) — whether the last completed packet was quiet
    /// enough for a rate change to be worth starting. Read back by the Opus layer, which uses it to
    /// decide whether to re-run its own bandwidth choice at all (`opus_encoder.c:1441`).
    allow_bandwidth_switch: bool,
    /// `timeSinceSwitchAllowed_ms` — how long the stream has been too active to allow a switch. The
    /// activity threshold relaxes with it, so a permanently loud talker is not stuck at one
    /// bandwidth for ever (`enc_API.c:549-556`).
    time_since_switch_allowed_ms: i32,
    /// `encControl->maxBits` after [`SilkEncoder::control`] has taken out whatever a pending
    /// bandwidth switch reserves. Bits, not bytes, because the reservation the C applies
    /// (`control_audio_bandwidth.c:90`) is a fraction of the whole budget.
    max_bits: i32,
}

impl SilkEncoder {
    /// Create an encoder for one stream.
    ///
    /// Returns an error only for a configuration SILK does not define — a frame duration outside
    /// 10/20/40/60 ms, or a channel count outside 1..=2.
    pub fn new(config: EncoderConfig) -> Result<Self, CodecError> {
        if config.channels == 0 || config.channels > 2 {
            return Err(CodecError::Unsupported(
                "silk enc: internal channels must be 1 or 2",
            ));
        }
        config.layout()?;
        let mut encoder = Self::init();
        encoder.control(config)?;
        Ok(encoder)
    }

    /// `silk_InitEncoder` (`init_encoder.c:46-68`) — a SILK encoder with **no resolved internal
    /// rate**.
    ///
    /// That is not an oversight, it is the state the reference starts in: `fs_kHz == 0` is what
    /// tells `silk_control_audio_bandwidth` that the first `control` may go straight to whatever the
    /// Opus layer asks for, rather than treating it as a mid-call bandwidth change that has to be
    /// ramped and covered by a redundancy frame. An encoder built with [`SilkEncoder::new`] has
    /// already been controlled once and is past that point, which is why the Opus layer — which does
    /// not know its own starting bandwidth until it has seen a frame — builds one this way instead.
    ///
    /// Crate-visible: `control` **must** run before `encode`, and inside this crate it always does.
    pub(crate) fn init() -> Self {
        let config = EncoderConfig::new(InternalRate::Wide16k, 20, 25_000);
        Self {
            config,
            channels: [ChannelState::default(); 2],
            stereo: StereoEncoderState::default(),
            stereo_indices: [StereoIndices::default(); MAX_FRAMES_PER_PACKET],
            previous_mid_only: false,
            bits_exceeded: 0,
            lbrr_bits_used: 0,
            // `init_encoder.c:58`: start at the minimum cutoff. The C reaches it through the Q16
            // form and the `-(16<<7)` correction rather than `lin2log(60)` directly, and the two are
            // not quite identical — keep its arithmetic.
            high_pass_smth1_q15: (lin2log(MIN_CUTOFF_HZ << 16) - (16 << 7)) << 8,
            internal_rate: config.internal_rate,
            allow_bandwidth_switch: false,
            time_since_switch_allowed_ms: 0,
            max_bits: config.max_bytes as i32 * 8,
        }
    }

    /// The configuration this encoder was last controlled with.
    ///
    /// [`EncoderConfig::internal_rate`] in it is the rate that was *requested*; the rate SILK is
    /// coding at is [`SilkEncoder::internal_rate`].
    #[must_use]
    pub fn config(&self) -> &EncoderConfig {
        &self.config
    }

    /// The internal rate SILK is currently coding at — `state_Fxx[0].sCmn.fs_kHz`, reported to the
    /// Opus layer as `encControl->internalSampleRate` (`enc_API.c:573`).
    ///
    /// This is the rate [`SilkEncoder::encode`] expects its input at, and for a SILK-only packet it
    /// is also what the TOC's bandwidth field must be derived from (`opus_encoder.c:2052-2060`).
    #[must_use]
    pub fn internal_rate(&self) -> InternalRate {
        self.internal_rate
    }

    /// `encControl->allowBandwidthSwitch` (`enc_API.c:571`) — whether SILK considers the stream
    /// quiet enough right now to start moving between internal rates.
    #[must_use]
    pub fn allow_bandwidth_switch(&self) -> bool {
        self.allow_bandwidth_switch
    }

    /// Apply a configuration and resolve the internal rate for the packet about to be encoded
    /// (libopus `silk_control_encoder`, `control_codec.c:64-132`).
    ///
    /// The Opus layer calls this every packet, before it resamples: the bitrate, the reported loss
    /// and the FEC and DTX flags can all move without anything else changing, and those are pure
    /// retunes that reset nothing. Two things are **not** retunes:
    ///
    /// * **The internal rate.** It is not set here, it is *negotiated*: the caller states a desired
    ///   rate and a legal window, and `silk_control_audio_bandwidth`
    ///   (`silk_control_audio_bandwidth`, ported below) decides whether it may move to it now,
    ///   has to ramp its input bandwidth first, or must ask the Opus layer for a redundancy frame
    ///   before it can. When it does move, `silk_setup_fs` (`control_codec.c:243-299`) clears the
    ///   shaping state, the NSQ, the previous NLSFs and the transition filter's memory and re-seeds
    ///   `prevLag = 100`, `LastGainIndex = 10`, `prevSignalType = inactive`,
    ///   `first_frame_after_reset = 1` — every filter below is defined at one rate, so carrying
    ///   their state across is meaningless. The VAD, the stereo state and the bit reservoir survive,
    ///   as they do in the C.
    /// * **A frame-duration or channel-count change** (`transition`, `enc_API.c:198`): the pending
    ///   LBRR frames were generated for a layout this packet no longer has, so their flags are
    ///   cleared rather than written into a packet that cannot carry them.
    ///
    /// One deliberate deviation: on a rate change the C resamples the float analysis history
    /// `x_buf` through the API rate into the new internal rate (`control_codec.c:148-189`) so the
    /// first frame at the new rate still has real history. Here it is cleared instead. The gated
    /// path — the one this whole state machine exists for — reaches a rate change through
    /// [`SilkEncoder::prefill`], which resets and refills that history from real audio anyway, so
    /// the deviation is confined to the ungated path where the rate is forced out of range, and
    /// there `first_frame_after_reset` already constrains the predictor.
    ///
    /// Errors on a configuration SILK does not define, leaving the encoder untouched.
    pub fn control(&mut self, config: EncoderConfig) -> Result<ControlOutcome, CodecError> {
        if config.channels == 0 || config.channels > 2 {
            return Err(CodecError::Unsupported(
                "silk enc: internal channels must be 1 or 2",
            ));
        }
        config.layout()?;

        // `silk_Encode` clears it once per call, before any channel is controlled
        // (`enc_API.c:179`).
        let mut switch_ready = false;
        // `enc_API.c:198` — computed against the *previous* packet's geometry.
        let transition = config.duration_ms != self.config.duration_ms
            || config.channels != self.config.channels;
        if config.channels > self.config.channels {
            // Mono to stereo: the side channel has no history at all (`enc_API.c:181-196`).
            self.channels[1] = ChannelState::default();
            self.stereo = StereoEncoderState::default();
        }

        self.max_bits = config.max_bytes as i32 * 8;
        let allow = self.allow_bandwidth_switch;
        let mut resolved_khz = 0i32;
        for channel_index in 0..config.channels {
            // "Force the side channel to the same rate as the mid" (`enc_API.c:252-253`). The state
            // machine still runs for it: it owns that channel's own transition filter, and libopus
            // lets it take its own share of the redundancy reservation out of `maxBits` too.
            let forced = (channel_index == 1).then_some(resolved_khz);
            let mut max_bits = self.max_bits;
            let khz = Self::control_audio_bandwidth(
                &mut self.channels[channel_index],
                &config,
                allow,
                &mut switch_ready,
                &mut max_bits,
            );
            self.max_bits = max_bits;
            let khz = forced.unwrap_or(khz);
            if channel_index == 0 {
                resolved_khz = khz;
            }
            self.setup_fs(channel_index, khz);
        }

        let internal_rate = match resolved_khz {
            8 => InternalRate::Narrow8k,
            12 => InternalRate::Medium12k,
            _ => InternalRate::Wide16k,
        };
        let rate_changed = internal_rate != self.internal_rate;
        self.internal_rate = internal_rate;

        // `silk_setup_fs` sets `first_frame_after_reset`, and `enc_API.c:259-263` clears the pending
        // LBRR flags on either that or a layout transition. Both matter for the same reason: those
        // redundant frames were generated at the *old* rate and layout, and writing them into a
        // packet coded at the new one desynchronises the decoder outright — which is exactly what it
        // did, at the second packet of a rate-switching FEC stream.
        if transition || rate_changed {
            for channel in self.channels.iter_mut() {
                channel.lbrr_flags = [false; MAX_FRAMES_PER_PACKET];
            }
            self.stereo_indices = [StereoIndices::default(); MAX_FRAMES_PER_PACKET];
            self.previous_mid_only = false;
        }
        self.config = config;
        Ok(ControlOutcome {
            internal_rate,
            switch_ready,
        })
    }

    /// `silk_control_audio_bandwidth` (`control_audio_bandwidth.c:36-132`) — the internal-rate state
    /// machine, for one channel.
    ///
    /// Three outcomes, and the difference between them is the whole point of the function:
    ///
    /// * **Out of the legal window** (or above the API rate). The rate changes *now*, with no ramp
    ///   and no redundancy, because staying is not an option — a hybrid packet whose SILK half is
    ///   below 16 kHz is not a legal stream.
    /// * **`opus_can_switch`.** The Opus layer has already committed to a redundancy frame, so the
    ///   rate moves this frame and any ramp in progress is stopped.
    /// * **Neither.** The rate stays. Going *down* needs the input band-limited first, so a
    ///   transition is armed and `switch_ready` waits until it has run out; going *up* needs no
    ///   ramp, so `switch_ready` is raised immediately. Either way the caller is asked for
    ///   redundancy and this packet's SILK budget gives up room for it.
    fn control_audio_bandwidth(
        channel: &mut ChannelState,
        config: &EncoderConfig,
        allow_bandwidth_switch: bool,
        switch_ready: &mut bool,
        max_bits: &mut i32,
    ) -> i32 {
        // "Handle a bandwidth-switching reset where we need to be aware what the last sampling rate
        // was" — after a prefill the channel's own rate is gone and only `sLP` remembers it.
        let mut original_khz = channel.fs_khz;
        if original_khz == 0 {
            original_khz = channel.low_pass.saved_fs_khz;
        }
        let mut rate_khz = original_khz;
        let rate_hz = rate_khz * 1000;
        let desired_hz = config.internal_rate.hz() as i32;
        let minimum_hz = config.min_internal_rate.hz() as i32;
        let maximum_hz = config.max_internal_rate.hz() as i32;

        if rate_hz == 0 {
            // "Encoder has just been initialized."
            rate_khz = desired_hz.min(config.api_rate_hz) / 1000;
        } else if rate_hz > config.api_rate_hz || rate_hz > maximum_hz || rate_hz < minimum_hz {
            // "Make sure internal rate is not higher than external rate or maximum allowed, or
            // lower than minimum allowed."
            rate_khz = config.api_rate_hz.min(maximum_hz).max(minimum_hz) / 1000;
        } else {
            // The state machine proper.
            if channel.low_pass.transition_frame_no >= TRANSITION_FRAMES {
                // "Stop transition phase."
                channel.low_pass.mode = 0;
            }
            if !(allow_bandwidth_switch || config.opus_can_switch) {
                return rate_khz;
            }
            if rate_khz * 1000 > desired_hz {
                // Switch down.
                if channel.low_pass.mode == 0 {
                    // "New transition."
                    channel.low_pass.transition_frame_no = TRANSITION_FRAMES;
                    channel.low_pass.reset_memory();
                }
                if config.opus_can_switch {
                    channel.low_pass.mode = 0;
                    rate_khz = if original_khz == 16 { 12 } else { 8 };
                } else if channel.low_pass.transition_frame_no <= 0 {
                    *switch_ready = true;
                    // "Make room for redundancy."
                    *max_bits -= *max_bits * 5 / (config.duration_ms as i32 + 5);
                } else {
                    // "Direction: down (at double speed)."
                    channel.low_pass.mode = -2;
                }
            } else if rate_khz * 1000 < desired_hz {
                // Switch up.
                if config.opus_can_switch {
                    rate_khz = if original_khz == 8 { 12 } else { 16 };
                    // "New transition" — from the *narrowest* cutoff, walked back open.
                    channel.low_pass.transition_frame_no = 0;
                    channel.low_pass.reset_memory();
                    channel.low_pass.mode = 1;
                } else if channel.low_pass.mode == 0 {
                    *switch_ready = true;
                    *max_bits -= *max_bits * 5 / (config.duration_ms as i32 + 5);
                } else {
                    channel.low_pass.mode = 1;
                }
            } else if channel.low_pass.mode < 0 {
                // The target moved back to where we already are: unwind the ramp instead of
                // finishing it.
                channel.low_pass.mode = 1;
            }
        }
        rate_khz
    }

    /// `silk_setup_fs` (`control_codec.c:199-305`) for one channel — the reset a rate change forces.
    ///
    /// A no-op when the rate has not moved, which is every packet of a stream that never switches.
    fn setup_fs(&mut self, channel_index: usize, rate_khz: i32) {
        let channel = &mut self.channels[channel_index];
        if channel.fs_khz == rate_khz {
            return;
        }
        let mut frame = FrameEncoderState::default();
        // `control_codec.c:253-259`'s non-zero re-seeds.
        frame.analysis.shape.last_gain_index = 10;
        frame.analysis.previous_lag = 100;
        channel.frame = frame;
        // See the deviation note on `control`: the C resamples this history into the new rate.
        channel.input = [0.0; INPUT_BUFFER];
        channel.low_pass.reset_memory();
        channel.fs_khz = rate_khz;
    }

    /// Samples per channel one [`SilkEncoder::encode`] call consumes, at the *resolved* internal
    /// rate.
    #[must_use]
    pub fn samples_per_packet(&self) -> usize {
        self.config.duration_ms * self.internal_rate.khz()
    }

    /// Samples per SILK frame at the resolved internal rate.
    fn frame_length(&self) -> Result<usize, CodecError> {
        Ok(self.config.layout()?.subframe_count * 5 * self.internal_rate.khz())
    }

    /// Encode one Opus frame's worth of SILK.
    ///
    /// `input` is interleaved PCM at the internal rate, `samples_per_packet()` frames of
    /// `config.channels` samples each. `encoder` is written in place; the caller owns the buffer and
    /// is responsible for calling [`RangeEncoder::done`] once the Opus layers above this one have
    /// had their turn.
    pub fn encode(
        &mut self,
        input: &[i16],
        encoder: &mut RangeEncoder<'_>,
    ) -> Result<EncodeResult, CodecError> {
        let layout = self.config.layout()?;
        let frame_length = self.frame_length()?;
        let channels = self.config.channels;
        let rate_khz = self.internal_rate.khz();
        let required = self.samples_per_packet() * channels;
        if input.len() < required {
            return Err(CodecError::Unsupported(
                "silk enc: input is shorter than one packet",
            ));
        }

        // ── The previous packet's LBRR, and the space the flags will be patched into ───────────
        let carries_redundancy = self.write_packet_header(encoder, layout, channels)?;
        let lbrr_bits = encoder.tell();

        let mut any_active = false;
        for interval in 0..layout.frames_per_packet {
            self.encode_interval(
                encoder,
                input,
                interval,
                layout,
                frame_length,
                rate_khz,
                channels,
                lbrr_bits,
                &mut any_active,
            )?;
        }

        // ── Patch the VAD and LBRR flags back into the head of the packet ─────────────────────
        // Bit order: per channel, one VAD flag per frame (MSB first), then the channel's LBRR flag.
        let mut flags = 0u32;
        for channel in self.channels.iter().take(channels) {
            for frame in 0..layout.frames_per_packet {
                flags = (flags << 1) | u32::from(channel.vad_flags[frame]);
            }
            flags = (flags << 1) | u32::from(channel.lbrr_flag);
        }
        let flag_bits = (layout.frames_per_packet as u32 + 1) * channels as u32;
        encoder.patch_initial_bits(flags, flag_bits);

        let payload_bytes = (encoder.tell() as usize).div_ceil(8);

        // ── DTX is a whole-packet decision ────────────────────────────────────────────────────
        let all_silent = self.channels[..channels]
            .iter()
            .all(|channel| channel.dtx.in_dtx);
        let payload_bytes = if all_silent { 0 } else { payload_bytes };

        // ── The bit reservoir ─────────────────────────────────────────────────────────────────
        self.bits_exceeded += payload_bytes as i32 * 8;
        self.bits_exceeded -= self.config.bitrate_bps * self.config.duration_ms as i32 / 1000;
        self.bits_exceeded = self.bits_exceeded.clamp(0, 10_000);

        self.previous_mid_only = self.stereo_indices[layout.frames_per_packet - 1].mid_only;
        self.update_lbrr_gain_increase();
        self.update_allow_bandwidth_switch(payload_bytes > 0);

        Ok(EncodeResult {
            payload_bytes,
            active: any_active,
            carries_redundancy,
        })
    }

    /// Reserve the flag bits and write the previous packet's LBRR frames (`enc_API.c:345-395`).
    ///
    /// Returns whether any LBRR data was written.
    fn write_packet_header(
        &mut self,
        encoder: &mut RangeEncoder<'_>,
        layout: SubframeLayout,
        channels: usize,
    ) -> Result<bool, CodecError> {
        // Reserve `(frames + 1) * channels` bits by coding a zero from a table sized to exactly
        // that many symbols; `patch_initial_bits` rewrites them at the end.
        let flag_bits = (layout.frames_per_packet + 1) * channels;
        let reserve = [(256 - (256 >> flag_bits)) as u8, 0];
        encoder.enc_icdf(0, &reserve, ICDF_FTB);

        // The per-channel LBRR bit patterns. The global flag itself is patched in at the end, so
        // only the multi-frame pattern symbol is coded here.
        let mut any = false;
        for channel in self.channels.iter_mut().take(channels) {
            let mut symbol = 0usize;
            for frame in 0..layout.frames_per_packet {
                symbol |= usize::from(channel.lbrr_flags[frame]) << frame;
            }
            // `LBRR_flag` is latched here, from what is about to be written, and read again when the
            // header flags are patched in — long after `lbrr_flags` has been reused.
            channel.lbrr_flag = symbol > 0;
            if symbol > 0 {
                any = true;
                if layout.frames_per_packet > 1 {
                    let icdf: &[u8] = if layout.frames_per_packet == 2 {
                        &LBRR_FLAGS_2_ICDF
                    } else {
                        &LBRR_FLAGS_3_ICDF
                    };
                    encoder.enc_icdf(symbol - 1, icdf, ICDF_FTB);
                }
            }
        }

        // The LBRR frames themselves, in frame-then-channel order.
        for frame in 0..layout.frames_per_packet {
            for channel_index in 0..channels {
                if !self.channels[channel_index].lbrr_flags[frame] {
                    continue;
                }
                if channels == 2 && channel_index == 0 {
                    encode_predictors(encoder, &self.stereo_indices[frame].indices);
                    // With the side channel's own LBRR flag set there is nothing to disambiguate,
                    // so the mid-only flag is not coded (`enc_API.c:373-376`).
                    if !self.channels[1].lbrr_flags[frame] {
                        encode_mid_only(encoder, self.stereo_indices[frame].mid_only);
                    }
                }
                let cond_coding = if frame > 0 && self.channels[channel_index].lbrr_flags[frame - 1]
                {
                    CondCoding::Conditionally
                } else {
                    CondCoding::Independently
                };
                let channel = &mut self.channels[channel_index];
                let redundant = channel.lbrr[frame];
                encode_indices(
                    encoder,
                    &redundant.indices,
                    redundant.seed,
                    self.internal_rate,
                    layout.subframe_count,
                    cond_coding,
                    true,
                    &mut channel.frame.entropy,
                );
                let mut pulses = redundant.pulses;
                encode_pulses(
                    encoder,
                    redundant.indices.signal_type,
                    redundant.indices.quant_offset_type,
                    &mut pulses[..],
                    self.frame_length()?,
                );
            }
        }

        // The flags belong to the packet just written; clear them so this packet's own LBRR
        // generation starts from zero (`enc_API.c:391-394`).
        for channel in self.channels.iter_mut().take(channels) {
            channel.lbrr_flags = [false; MAX_FRAMES_PER_PACKET];
        }
        Ok(any)
    }

    /// Encode one 10/20 ms interval of the packet, both channels.
    #[allow(clippy::too_many_arguments)]
    fn encode_interval(
        &mut self,
        encoder: &mut RangeEncoder<'_>,
        input: &[i16],
        interval: usize,
        layout: SubframeLayout,
        frame_length: usize,
        rate_khz: usize,
        channels: usize,
        lbrr_bits: i32,
        any_active: &mut bool,
    ) -> Result<(), CodecError> {
        // ── The adaptive high-pass tracker (`enc_API.c:398`) ──────────────────────────────────
        // Runs before this interval's VAD and analysis, so it sees the previous interval's pitch,
        // activity and quality — which is exactly what the C does.
        self.update_high_pass_smoother();

        // ── This interval's share of the packet budget ────────────────────────────────────────
        let mut frame_bits =
            self.config.bitrate_bps * self.config.duration_ms as i32 / 1000 - self.lbrr_bits_used;
        frame_bits /= layout.frames_per_packet as i32;
        let mut target_bps = if self.config.duration_ms == 10 {
            frame_bits * 100
        } else {
            frame_bits * 50
        };
        // The reservoir: an overspend is repaid gradually rather than all at once.
        target_bps -= self.bits_exceeded * 1000 / BIT_RESERVOIR_DECAY_MS;
        if interval > 0 {
            let balance = encoder.tell() - lbrr_bits - frame_bits * interval as i32;
            target_bps -= balance * 1000 / BIT_RESERVOIR_DECAY_MS;
        }
        target_bps = target_bps.clamp(5_000, self.config.bitrate_bps.max(5_000));

        // ── Stereo conversion, or the mono pass-through ───────────────────────────────────────
        let mut mid = [0i16; MAX_FRAME_LENGTH + 2];
        let mut side = [0i16; MAX_FRAME_LENGTH + 2];
        let (mid_bps, side_bps) = self.prepare_interval(
            input,
            interval,
            frame_length,
            rate_khz,
            channels,
            target_bps,
            &mut mid,
            &mut side,
        );

        // ── The VAD, per channel ──────────────────────────────────────────────────────────────
        // Order matters: the side channel is analysed first when it is coded at all, because the
        // stereo decision for the *next* interval reads the mid's activity from this one.
        // Every read of the frame is from index 1, which is what `inputBuf + 1`
        // (`enc_API.c:469`, `encode_frame_FLP.c:129`) means: the coded frame lags the resampler's
        // output by one sample and starts on the previous frame's carry, so it is continuous across
        // the boundary.
        let mid_only = self.stereo_indices[interval].mid_only;
        if channels == 2 {
            if mid_only {
                self.channels[1].vad_flags[interval] = false;
            } else {
                self.run_vad(1, &side[1..frame_length + 1], interval);
            }
        }
        self.run_vad(0, &mid[1..frame_length + 1], interval);

        if channels == 2 {
            encode_predictors(encoder, &self.stereo_indices[interval].indices);
            if !self.channels[1].vad_flags[interval] {
                encode_mid_only(encoder, mid_only);
            }
        }

        // ── Encode each channel ───────────────────────────────────────────────────────────────
        for channel_index in 0..channels {
            let channel_bps = if channels == 1 {
                target_bps
            } else if channel_index == 0 {
                mid_bps
            } else {
                side_bps
            };
            if channel_bps <= 0 {
                continue;
            }

            // Independent coding when there is no previous frame of this channel in the packet; the
            // no-LTP-scaling variant when the side channel skipped one earlier in this same packet.
            let cond_coding = if interval as i32 - channel_index as i32 <= 0 {
                CondCoding::Independently
            } else if channel_index > 0 && self.previous_mid_only {
                CondCoding::IndependentlyNoLtpScaling
            } else {
                CondCoding::Conditionally
            };

            let samples = if channel_index == 0 {
                &mut mid[1..frame_length + 1]
            } else {
                &mut side[1..frame_length + 1]
            };
            self.encode_channel_frame(
                encoder,
                channel_index,
                interval,
                samples,
                layout,
                channel_bps,
                cond_coding,
            )?;
            if self.channels[channel_index].vad_flags[interval] {
                *any_active = true;
            }
        }
        Ok(())
    }

    /// De-interleave (and, in stereo, mid/side-convert) one interval's input.
    ///
    /// Returns the mid and side bitrates. In mono both are the caller's target.
    #[allow(clippy::too_many_arguments)]
    fn prepare_interval(
        &mut self,
        input: &[i16],
        interval: usize,
        frame_length: usize,
        rate_khz: usize,
        channels: usize,
        target_bps: i32,
        mid: &mut [i16; MAX_FRAME_LENGTH + 2],
        side: &mut [i16; MAX_FRAME_LENGTH + 2],
    ) -> (i32, i32) {
        let start = interval * frame_length;
        if channels == 1 {
            for (slot, &sample) in mid[2..frame_length + 2]
                .iter_mut()
                .zip(input[start..].iter())
            {
                *slot = sample;
            }
            // "Buffering" (`enc_API.c:465-467`): the two samples in front of the frame are the
            // previous frame's last two, and this frame's last two become the next one's. Dropping
            // that carry would put two zeros into the signal at every frame boundary — the same
            // state the stereo path keeps in `sMid`, which is why it lives on the stereo state even
            // in mono.
            mid[..2].copy_from_slice(&self.stereo.mid_history);
            self.stereo
                .mid_history
                .copy_from_slice(&mid[frame_length..frame_length + 2]);
            self.stereo_indices[interval] = StereoIndices::default();
            return (target_bps, 0);
        }

        for index in 0..frame_length {
            mid[index + 2] = input[2 * (start + index)];
            side[index + 2] = input[2 * (start + index) + 1];
        }
        let previous_activity = self.channels[0].measures.speech_activity_q8;
        let (indices, rates) = left_right_to_mid_side(
            &mut self.stereo,
            &mut mid[..frame_length + 2],
            &mut side[..frame_length + 2],
            target_bps,
            previous_activity,
            self.config.to_mono,
            rate_khz,
            frame_length,
        );
        self.stereo_indices[interval] = indices;
        (rates.mid_bps, rates.side_bps)
    }

    /// Run the VAD for one channel and record its verdict.
    fn run_vad(&mut self, channel_index: usize, frame: &[i16], interval: usize) {
        let rate = self.internal_rate;
        let use_dtx = self.config.use_dtx;
        let channel = &mut self.channels[channel_index];
        let previous_type = channel.frame.analysis.previous_signal_type;
        let mut measures = analyse(&mut channel.vad, frame, rate, previous_type);
        // The Opus layer's own VAD is not modelled here; SILK's own verdict stands.
        let verdict = classify(&mut measures, &mut channel.dtx, use_dtx, true);
        channel.vad_flags[interval] = verdict.active;
        channel.measures = verdict.measures;
    }

    /// `silk_HP_variable_cutoff` (`HP_variable_cutoff.c:39-77`) — track the low end of the pitch
    /// frequency range and move the high-pass cutoff towards it.
    ///
    /// Only the state lives here; the filter itself is the Opus layer's, which is where libopus puts
    /// it too (`opus_encoder.c:1799-1809`). Reading it out is [`SilkEncoder::high_pass_smth1_q15`].
    /// Everything is the *previous* interval's: libopus calls this at the head of an interval,
    /// before the VAD and the analysis have run on the new one (`enc_API.c:398`).
    fn update_high_pass_smoother(&mut self) {
        let channel = &self.channels[0];
        if channel.frame.analysis.previous_signal_type != SignalType::Voiced {
            return;
        }
        let previous_lag = channel.frame.analysis.previous_lag.max(1);
        // Estimate the low end of the pitch frequency range, in the log domain.
        let pitch_freq_hz_q16 = ((self.internal_rate.khz() as i32 * 1000) << 16) / previous_lag;
        let mut pitch_freq_log_q7 = lin2log(pitch_freq_hz_q16) - (16 << 7);

        // Adjustment based on quality: a noisy input pulls the estimate back down towards the
        // minimum cutoff rather than trusting its pitch track.
        let quality_q15 = channel.measures.input_quality_bands_q15[0];
        pitch_freq_log_q7 = smlawb(
            pitch_freq_log_q7,
            smulwb(-quality_q15 << 2, quality_q15),
            pitch_freq_log_q7 - (lin2log(MIN_CUTOFF_HZ << 16) - (16 << 7)),
        );

        let mut delta_freq_q7 = pitch_freq_log_q7 - (self.high_pass_smth1_q15 >> 8);
        if delta_freq_q7 < 0 {
            // "less smoothing for decreasing pitch frequency, to track something close to the
            // minimum" (`HP_variable_cutoff.c:61`).
            delta_freq_q7 *= 3;
        }
        // SILK_FIX_CONST( VARIABLE_HP_MAX_DELTA_FREQ, 7 ) with VARIABLE_HP_MAX_DELTA_FREQ = 0.4.
        const MAX_DELTA_FREQ_Q7: i32 = 51;
        delta_freq_q7 = delta_freq_q7.clamp(-MAX_DELTA_FREQ_Q7, MAX_DELTA_FREQ_Q7);

        // SILK_FIX_CONST( VARIABLE_HP_SMTH_COEF1, 16 ) with VARIABLE_HP_SMTH_COEF1 = 0.1.
        const SMTH_COEF1_Q16: i32 = 6554;
        self.high_pass_smth1_q15 = smlawb(
            self.high_pass_smth1_q15,
            smulbb(channel.measures.speech_activity_q8, delta_freq_q7),
            SMTH_COEF1_Q16,
        );
        self.high_pass_smth1_q15 = self
            .high_pass_smth1_q15
            .clamp(lin2log(MIN_CUTOFF_HZ) << 8, lin2log(MAX_CUTOFF_HZ) << 8);
    }

    /// `variable_HP_smth1_Q15` — the SILK-side smoother the Opus layer's high-pass reads
    /// (`opus_encoder.c:1799`). Q15 log2 of the cutoff in Hz.
    #[must_use]
    pub fn high_pass_smth1_q15(&self) -> i32 {
        self.high_pass_smth1_q15
    }

    /// Band-limit one channel's frame for a bandwidth transition, slide its float input buffer along
    /// and stage the frame into it (`encode_frame_FLP.c:123-139`).
    ///
    /// The low-pass runs here and not at the packet level because that is where the C puts it: after
    /// the VAD and the stereo conversion have read the unfiltered signal, and only for a channel
    /// that is actually being coded this frame.
    fn stage_analysis_input(&mut self, channel_index: usize, samples: &mut [i16]) {
        let (history, lookahead) = self.analysis_buffer_geometry();
        let frame_length = samples.len();

        let channel = &mut self.channels[channel_index];
        // "Ensure smooth bandwidth transitions" (`encode_frame_FLP.c:126-129`). A no-op unless a
        // transition is in flight.
        low_pass_variable_cutoff(&mut channel.low_pass, samples);

        // The encoder codes a frame that ends `lookahead` samples before the newest input, which is
        // how the noise-shaping analysis gets its look-ahead (`encode_frame_FLP.c:123-134`).
        for (slot, &sample) in channel.input[history + lookahead..]
            .iter_mut()
            .zip(samples.iter())
            .take(frame_length)
        {
            *slot = f32::from(sample);
        }
        // "Add tiny signal to avoid high CPU load from denormalized floating point numbers"
        // (`encode_frame_FLP.c:136-139`).
        for step in 0..8 {
            channel.input[history + lookahead + step * (frame_length >> 3)] +=
                (1 - (step as i32 & 2)) as f32 * 1e-6;
        }
    }

    /// Slide the analysis history down by one frame (`encode_frame_FLP.c:353-355`).
    ///
    /// Deliberately at the **end** of the frame rather than folded into the staging at the start of
    /// the next one, because the two are not the same thing: the slide is by *this* frame's length,
    /// and the next frame may not have the same length. A prefill is exactly that case — it runs as
    /// 10 ms whatever the packet duration is — so a deferred slide would move the history by the
    /// wrong amount on the very frame the prefill exists to prepare.
    fn slide_analysis_input(&mut self, channel_index: usize, frame_length: usize) {
        let (history, lookahead) = self.analysis_buffer_geometry();
        self.channels[channel_index]
            .input
            .copy_within(frame_length..frame_length + history + lookahead, 0);
    }

    /// Where the frame being coded sits inside `x_buf`, as `(history, lookahead)`
    /// (`encode_frame_FLP.c:123`, `:134`, `:354-355`).
    ///
    /// Both are the **constants** `ltp_mem_length` and `LA_SHAPE_MS`, not the complexity-dependent
    /// `la_shape`. That distinction is load-bearing: `la_shape` is how much look-ahead the
    /// noise-shaping analysis chooses to *look at* (3 ms below complexity 3, 5 ms above), while the
    /// buffer always *carries* 5 ms. Tying the geometry to the complexity instead would move the
    /// coded frame 2 ms against the input the moment the complexity changed — and a prefill changes
    /// it to 0 for one frame (`enc_API.c:230-231`), so the frame after every mode switch would read
    /// its own history from the wrong offset.
    fn analysis_buffer_geometry(&self) -> (usize, usize) {
        let khz = self.internal_rate.khz();
        (self.internal_rate.ltp_memory_length(), LA_SHAPE_MS * khz)
    }

    /// Slide one channel's float input buffer along and encode its frame.
    #[allow(clippy::too_many_arguments)]
    fn encode_channel_frame(
        &mut self,
        encoder: &mut RangeEncoder<'_>,
        channel_index: usize,
        interval: usize,
        samples: &mut [i16],
        layout: SubframeLayout,
        channel_bps: i32,
        cond_coding: CondCoding,
    ) -> Result<(), CodecError> {
        let settings = ComplexitySettings::for_complexity(self.config.complexity);
        let (history, _) = self.analysis_buffer_geometry();

        let config = AnalysisConfig {
            internal_rate: self.internal_rate,
            layout,
            settings,
            snr_db_q7: control_snr(channel_bps, self.internal_rate, layout.subframe_count),
            use_cbr: self.config.rate_mode == RateMode::Constant,
            packet_loss_percent: self.config.packet_loss_percent,
            frames_per_packet: layout.frames_per_packet as i32,
            lbrr_enabled: self.config.use_in_band_fec,
        };

        self.stage_analysis_input(channel_index, samples);

        // The frame's own budget. Constrained VBR and CBR both clamp against the packet cap; plain
        // VBR gets the packet cap as a ceiling only, so a frame it wants to spend on is not
        // truncated by an arbitrary per-frame share. `max_bits` is the packet cap the Opus layer set
        // *minus* whatever `control` reserved for a bandwidth-switch redundancy frame.
        let packet_cap_bits = self.max_bits - encoder.tell();
        let share = packet_cap_bits.max(0) / (layout.frames_per_packet - interval).max(1) as i32;
        let target_bits =
            channel_bps * self.config.duration_ms as i32 / (1000 * layout.frames_per_packet as i32);
        let max_bits = match self.config.rate_mode {
            RateMode::Variable => packet_cap_bits.max(0),
            RateMode::ConstrainedVariable => share,
            RateMode::Constant => target_bits.min(share),
        }
        .max(64);

        let use_cbr = self.config.rate_mode == RateMode::Constant;

        // LBRR: only for a frame active enough to be worth a redundant copy.
        let lbrr_wanted = self.config.use_in_band_fec
            && self.channels[channel_index].measures.speech_activity_q8
                > LBRR_SPEECH_ACTIVITY_THRESHOLD_Q8;
        let lbrr_continues = interval > 0 && self.channels[channel_index].lbrr_flags[interval - 1];
        let gain_increase = self.channels[channel_index].lbrr_gain_increase;

        let mut pulses = [0i8; MAX_FRAME_LENGTH];
        let channel = &mut self.channels[channel_index];
        let signal_type = if channel.vad_flags[interval] {
            SignalType::Unvoiced
        } else {
            SignalType::Inactive
        };
        // The VAD's whole verdict, not just its activity: `input_quality_bands_Q15` sets the shaping
        // and the lambda, `input_tilt_Q15` moves the pitch threshold and the voiced quantisation
        // offset, and `previous_signal_type` biases the pitch search — see [`SignalMeasures`].
        let measures = channel.measures;

        let request = FrameEncodeRequest {
            signal: &channel.input,
            frame_start: history,
            signal_type,
            cond_coding,
            measures: &measures,
            config: &config,
            max_bits,
            use_cbr,
            lbrr_gain_increase: lbrr_wanted.then_some(gain_increase),
            lbrr_continues,
        };
        // `request` borrows `channel.input`, so the frame encoder gets its own borrow of the rest.
        let mut frame_state = channel.frame;
        let result = encode_frame(&mut frame_state, encoder, &request, &mut pulses)?;
        channel.frame = frame_state;

        if let Some(redundant) = result.lbrr {
            channel.lbrr[interval] = redundant;
            channel.lbrr_flags[interval] = true;
        }
        let frame_length = samples.len();
        self.slide_analysis_input(channel_index, frame_length);
        Ok(())
    }

    /// `enc_API.c:336`, `:548-557` — decide whether the *next* packet may start a rate change.
    ///
    /// The rule is "only while the talker is quiet enough that a bandwidth step will not be heard",
    /// with the threshold relaxing linearly from `SPEECH_ACTIVITY_DTX_THRES` towards 1 over
    /// `MAX_BANDWIDTH_SWITCH_DELAY_MS` of continuous activity — otherwise a stream that is never
    /// quiet would be stuck at whatever bandwidth it started on for the whole call.
    ///
    /// A DTXed packet produces no bytes and leaves the flag at the "default" 0 the C sets before
    /// every frame, so a silent stretch does not itself authorise a switch.
    fn update_allow_bandwidth_switch(&mut self, produced_payload: bool) {
        self.allow_bandwidth_switch = false;
        if !produced_payload {
            return;
        }
        // SILK_FIX_CONST( SPEECH_ACTIVITY_DTX_THRES, 8 ) and
        // SILK_FIX_CONST( ( 1 - SPEECH_ACTIVITY_DTX_THRES ) / MAX_BANDWIDTH_SWITCH_DELAY_MS, 24 ).
        const ACTIVITY_THRESHOLD_Q8: i32 = 13;
        const THRESHOLD_RELAXATION_Q24: i32 = 3_188;
        let threshold_q8 = smlawb(
            ACTIVITY_THRESHOLD_Q8,
            THRESHOLD_RELAXATION_Q24,
            self.time_since_switch_allowed_ms,
        );
        if self.channels[0].measures.speech_activity_q8 < threshold_q8 {
            self.allow_bandwidth_switch = true;
            self.time_since_switch_allowed_ms = 0;
        } else {
            self.time_since_switch_allowed_ms += self.config.duration_ms as i32;
        }
    }

    /// Reset for a **prefill** and resolve the internal rate it will run at
    /// (`enc_API.c:206-235`, `:251-265`).
    ///
    /// A prefill is how libopus enters SILK warm rather than cold: the encoder is reset and then run
    /// over 10 ms of the audio that has already gone past, so the frame that matters starts with
    /// real history instead of zeros. Because that reset destroys `fs_kHz`, the rate has to be
    /// resolved here — and the caller has to know it, since it owns the resampler that feeds
    /// [`SilkEncoder::prefill`].
    ///
    /// `keep_rate_control` is the C's `prefillFlag == 2` (`opus_encoder.c:1771`): on the frame that
    /// *is* the bandwidth switch, the transition state must survive the reset or the state machine
    /// would forget which rate it was switching from and never complete the move. On a plain
    /// CELT→SILK entry (`prefillFlag == 1`) it is cleared with everything else.
    ///
    /// Returns the rate the 10 ms of `prefill` input must be supplied at.
    pub fn control_for_prefill(
        &mut self,
        config: EncoderConfig,
        keep_rate_control: bool,
    ) -> Result<InternalRate, CodecError> {
        let mut saved = [LowPassState::default(); 2];
        for (slot, channel) in saved.iter_mut().zip(self.channels.iter()) {
            *slot = LowPassState {
                // "Save the sampling rate so the bandwidth switching code can keep handling
                // transitions" (`enc_API.c:216-217`).
                saved_fs_khz: channel.fs_khz,
                ..channel.low_pass
            };
        }

        // `silk_init_encoder` for every channel — and *only* the per-channel state. The bit
        // reservoir, the LBRR cost average, the stereo predictor memory and the bandwidth-switch
        // permission live on `silk_encoder`, one level up, and libopus does not reset them here
        // (`enc_API.c:220-227`).
        self.reset_channel_states();
        if keep_rate_control {
            for (channel, restored) in self.channels.iter_mut().zip(saved) {
                channel.low_pass = restored;
            }
        } else {
            // A plain CELT→SILK entry is always preceded by `silk_InitEncoder`
            // (`opus_encoder.c:1435-1437`), which memsets the *whole* `silk_encoder` — one level
            // above what `silk_init_encoder` reaches. There is nothing to carry over: SILK has not
            // been running, so its reservoir and stereo memory describe audio from before the CELT
            // stretch.
            self.stereo = StereoEncoderState::default();
            self.stereo_indices = [StereoIndices::default(); MAX_FRAMES_PER_PACKET];
            self.previous_mid_only = false;
            self.bits_exceeded = 0;
            self.lbrr_bits_used = 0;
            self.allow_bandwidth_switch = false;
            self.time_since_switch_allowed_ms = 0;
        }

        // "encControl->payloadSize_ms = 10" and "complexity = 0" (`enc_API.c:228-231`): a prefill
        // runs no analysis, so its complexity only has to be legal.
        let outcome = self.control(EncoderConfig {
            duration_ms: 10,
            complexity: 0,
            ..config
        })?;
        Ok(outcome.internal_rate)
    }

    /// `silk_init_encoder` for both channels (`init_encoder.c:46-68`) — everything in
    /// `silk_encoder_state_Fxx`, and nothing above it.
    fn reset_channel_states(&mut self) {
        self.channels = [ChannelState::default(); 2];
        self.high_pass_smth1_q15 = (lin2log(MIN_CUTOFF_HZ << 16) - (16 << 7)) << 8;
    }

    /// Run the 10 ms of history a [`SilkEncoder::control_for_prefill`] asked for
    /// (`silk_Encode` with `prefillFlag`, `enc_API.c:398-521` under `encode_frame_FLP.c:141`).
    ///
    /// Nothing is coded and nothing is returned: the analysis, the quantiser and the bitstream are
    /// all skipped. What runs is exactly what leaves *state* behind — the high-pass tracker, the
    /// stereo mid/side conversion, the VAD, the transition low-pass and the analysis history buffer.
    /// That is the difference between a warm and a cold encoder, and it is why this cannot be
    /// replaced by "encode a throwaway frame": a throwaway frame would also advance the quantiser
    /// and the entropy predictors, which libopus deliberately leaves at their reset values.
    ///
    /// `input` is interleaved PCM at the rate `control_for_prefill` returned, 10 ms of it.
    pub fn prefill(&mut self, input: &[i16]) -> Result<(), CodecError> {
        let layout = self.config.layout()?;
        let frame_length = self.frame_length()?;
        let channels = self.config.channels;
        let rate_khz = self.internal_rate.khz();
        if input.len() < 10 * rate_khz * channels {
            return Err(CodecError::Unsupported(
                "silk enc: a prefill needs exactly 10 ms of input",
            ));
        }

        self.update_high_pass_smoother();

        // The same per-frame target the real path computes, minus the two terms the C skips while
        // prefilling: the LBRR average (`enc_API.c:403`) and the in-packet bit balance
        // (`:426`, guarded on `nFramesEncoded > 0`, which is 0 here).
        let frame_bits = self.config.bitrate_bps * self.config.duration_ms as i32 / 1000;
        let mut target_bps = frame_bits * 100;
        target_bps -= self.bits_exceeded * 1000 / BIT_RESERVOIR_DECAY_MS;
        target_bps = target_bps.clamp(5_000, self.config.bitrate_bps.max(5_000));

        let mut mid = [0i16; MAX_FRAME_LENGTH + 2];
        let mut side = [0i16; MAX_FRAME_LENGTH + 2];
        let (mid_bps, side_bps) = self.prepare_interval(
            input,
            0,
            frame_length,
            rate_khz,
            channels,
            target_bps,
            &mut mid,
            &mut side,
        );

        let mid_only = self.stereo_indices[0].mid_only;
        if channels == 2 {
            if mid_only {
                self.channels[1].vad_flags[0] = false;
            } else {
                self.run_vad(1, &side[1..frame_length + 1], 0);
            }
        }
        self.run_vad(0, &mid[1..frame_length + 1], 0);

        for channel_index in 0..channels {
            let channel_bps = if channels == 1 {
                target_bps
            } else if channel_index == 0 {
                mid_bps
            } else {
                side_bps
            };
            if channel_bps <= 0 {
                continue;
            }
            let samples = if channel_index == 0 {
                &mut mid[1..frame_length + 1]
            } else {
                &mut side[1..frame_length + 1]
            };
            self.stage_analysis_input(channel_index, samples);
            self.slide_analysis_input(channel_index, frame_length);
        }

        // "Exit without entropy coding" — and put the real geometry back
        // (`enc_API.c:575-582`). `controlled_since_last_payload` is cleared there too, which for
        // this port is implicit: the caller's next `control` always runs in full.
        self.previous_mid_only = self.stereo_indices[layout.frames_per_packet - 1].mid_only;
        // `enc_API.c:336` clears the permission before every frame and only the *completed packet*
        // branch at `:548` puts it back — which a prefill never reaches, because it produces no
        // bytes. So a prefill always leaves the next packet needing to earn the permission again.
        self.allow_bandwidth_switch = false;
        Ok(())
    }

    /// Recompute the LBRR gain increase for the next packet (`control_codec.c:403-422`).
    ///
    /// It is 7 whenever the previous packet carried no LBRR (that packet was coded at a higher rate,
    /// so the redundant copy has more headroom to give up), and tapers towards 3 as the reported
    /// loss rises — a lossy line needs the redundancy to be *good*, not merely present.
    fn update_lbrr_gain_increase(&mut self) {
        let enabled = self.config.use_in_band_fec;
        for channel in self.channels.iter_mut() {
            channel.lbrr_gain_increase = if !channel.lbrr_was_enabled {
                7
            } else {
                // SILK_FIX_CONST( 0.2, 16 ) = 13107.
                (7 - smulwb(self.config.packet_loss_percent, 13107)).max(3)
            };
            channel.lbrr_was_enabled = enabled;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same deterministic LCG the libopus prefill oracle was driven with — a plain linear
    /// congruential generator whose top bits are recentred on zero. Broadband noise rather than
    /// speech, deliberately: a prefill runs no analysis, so what matters is that both sides see the
    /// identical sample stream, not that it sounds like anything.
    struct Source(u32);

    impl Source {
        fn new() -> Self {
            Self(12_345)
        }

        fn fill(&mut self, frame: &mut [i16]) {
            for slot in frame.iter_mut() {
                self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *slot = ((self.0 >> 18) as i32 - 8_192) as i16;
            }
        }
    }

    /// A deterministic voiced-ish mono signal at a known pitch.
    fn voiced(samples: usize, period: usize) -> Vec<i16> {
        let mut state = 24_680u32;
        let mut history = [0.0f32; 2];
        (0..samples)
            .map(|index| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let noise = ((state >> 20) as i32 - 2048) as f32 * 1.5;
                let pulse = if index % period == 0 { 6000.0 } else { 0.0 };
                let value = pulse + noise + 1.5 * history[0] - 0.85 * history[1];
                history[1] = history[0];
                history[0] = value;
                value.clamp(-24_000.0, 24_000.0) as i16
            })
            .collect()
    }

    fn encode_stream(config: EncoderConfig, packets: usize) -> (Vec<Vec<u8>>, Vec<EncodeResult>) {
        let mut encoder = SilkEncoder::new(config).expect("config");
        let per_packet = encoder.samples_per_packet();
        let source = voiced(per_packet * (packets + 1), 5 * config.internal_rate.khz());
        let mut payloads = Vec::new();
        let mut results = Vec::new();
        for packet in 0..packets {
            let mut buffer = vec![0u8; config.max_bytes];
            let mut range = RangeEncoder::new(&mut buffer);
            let start = packet * per_packet * config.channels;
            let result = encoder
                .encode(
                    &source[start..start + per_packet * config.channels],
                    &mut range,
                )
                .expect("encode");
            let used = (range.tell() as usize).div_ceil(8);
            range.done();
            payloads.push(buffer[..used.max(1)].to_vec());
            results.push(result);
        }
        (payloads, results)
    }

    /// Every bandwidth and duration must encode a plausible payload without erroring.
    #[test]
    fn every_bandwidth_and_duration_encodes() {
        for internal_rate in [
            InternalRate::Narrow8k,
            InternalRate::Medium12k,
            InternalRate::Wide16k,
        ] {
            for duration_ms in [10usize, 20, 40, 60] {
                let bitrate = 8_000 + 1_000 * internal_rate.khz() as i32;
                let config = EncoderConfig::new(internal_rate, duration_ms, bitrate);
                let (payloads, results) = encode_stream(config, 6);
                for (index, result) in results.iter().enumerate() {
                    assert!(
                        result.payload_bytes > 0,
                        "{internal_rate:?} {duration_ms} ms packet {index} was empty"
                    );
                    assert!(
                        result.payload_bytes <= config.max_bytes,
                        "{internal_rate:?} {duration_ms} ms packet {index} overflowed"
                    );
                }
                assert!(payloads.iter().all(|payload| !payload.is_empty()));
            }
        }
    }

    /// Stereo must produce a payload and must exercise the side channel at a rate that can afford
    /// one.
    #[test]
    fn stereo_encodes_both_channels() {
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 48_000);
        config.channels = 2;
        let mut encoder = SilkEncoder::new(config).expect("config");
        let per_packet = encoder.samples_per_packet();
        let mono = voiced(per_packet * 8, 80);
        // Decorrelate the two channels so the image is genuinely wide.
        let mut interleaved = vec![0i16; mono.len() * 2];
        for (index, &sample) in mono.iter().enumerate() {
            interleaved[2 * index] = sample;
            interleaved[2 * index + 1] = mono[mono.len() - 1 - index];
        }

        for packet in 0..6 {
            let mut buffer = vec![0u8; config.max_bytes];
            let mut range = RangeEncoder::new(&mut buffer);
            let start = packet * per_packet * 2;
            let result = encoder
                .encode(&interleaved[start..start + per_packet * 2], &mut range)
                .expect("encode");
            range.done();
            assert!(result.payload_bytes > 0, "packet {packet} was empty");
        }
        // A wide image at 48 kb/s must not have collapsed to mid-only.
        assert!(!encoder.stereo_indices[0].mid_only);
    }

    /// CBR must hold every packet at its per-packet target; VBR must not be bound by that target.
    ///
    /// "Hold", not "hit exactly": at this layer CBR is the gain loop driving the frame to within a
    /// few bits of its budget, and the gain multiplier is floored at 64 in Q8, so a frame the
    /// analysis aimed well below the budget cannot always be inflated all the way to it. Exact
    /// constant packet sizes are the *Opus* layer's job, which pads the packet — that is why
    /// `opus_encoder.c` still tracks a padding length after SILK has finished.
    ///
    /// The distinguishing property is the **ceiling**, not the total. VBR's per-frame `max_bits` is
    /// the whole remaining packet cap, so a frame worth spending on is allowed straight past the
    /// nominal per-packet target; CBR's is `min(target, share)` and cannot be. Comparing the two
    /// totals instead would be reading a rate-distortion outcome as if it were a rule, and which way
    /// it falls depends on the content.
    #[test]
    fn cbr_holds_the_target_where_vbr_is_free_to_pass_it() {
        let target_bytes = (24_000 * 20 / 1000 / 8) as usize;
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 24_000);
        // A cap well above the target, so the two modes differ by their own decision rather than by
        // running into the same ceiling.
        config.max_bytes = 100;

        config.rate_mode = RateMode::Variable;
        let (_, vbr) = encode_stream(config, 8);
        config.rate_mode = RateMode::Constant;
        let (_, cbr) = encode_stream(config, 8);

        let cbr_sizes: Vec<usize> = cbr.iter().map(|result| result.payload_bytes).collect();
        let vbr_sizes: Vec<usize> = vbr.iter().map(|result| result.payload_bytes).collect();

        for (index, &size) in cbr_sizes.iter().enumerate() {
            assert!(
                size <= target_bytes + 1,
                "cbr packet {index} overshot its target: {size} of {target_bytes}"
            );
            assert!(
                size * 4 >= target_bytes * 3,
                "cbr packet {index} under-filled badly: {size} of {target_bytes}"
            );
        }
        assert!(
            vbr_sizes.iter().any(|&size| size > target_bytes),
            "vbr {vbr_sizes:?} never passed the per-packet target, so the cap it does not have was \
             never demonstrated (cbr was {cbr_sizes:?})"
        );
    }

    /// Constrained VBR must never exceed the cap, whatever the signal does.
    #[test]
    fn constrained_vbr_respects_the_cap() {
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 64_000);
        config.rate_mode = RateMode::ConstrainedVariable;
        config.max_bytes = 40;
        let (payloads, results) = encode_stream(config, 8);
        for (index, result) in results.iter().enumerate() {
            assert!(
                result.payload_bytes <= 40,
                "packet {index} was {} bytes",
                result.payload_bytes
            );
        }
        assert!(payloads.iter().all(|payload| payload.len() <= 40));
    }

    /// DTX must eventually drop a silent stream to a zero-byte payload, and must not do so while
    /// there is speech.
    #[test]
    fn dtx_drops_a_silent_stream_and_not_a_live_one() {
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 16_000);
        config.use_dtx = true;
        let mut encoder = SilkEncoder::new(config).expect("config");
        let per_packet = encoder.samples_per_packet();

        let mut dropped = 0usize;
        for _ in 0..40 {
            let mut buffer = vec![0u8; config.max_bytes];
            let mut range = RangeEncoder::new(&mut buffer);
            let result = encoder
                .encode(&vec![0i16; per_packet], &mut range)
                .expect("encode");
            range.done();
            if result.payload_bytes == 0 {
                dropped += 1;
            }
        }
        assert!(dropped > 20, "silence produced only {dropped} DTX packets");

        // Speech must bring it straight back.
        let speech = voiced(per_packet * 4, 80);
        let mut buffer = vec![0u8; config.max_bytes];
        let mut range = RangeEncoder::new(&mut buffer);
        let result = encoder
            .encode(&speech[..per_packet], &mut range)
            .expect("encode");
        range.done();
        assert!(result.payload_bytes > 0, "speech was dropped by DTX");
    }

    /// With DTX off, silence must still be coded — the knob has to be wired both ways.
    #[test]
    fn dtx_disabled_always_emits_a_payload() {
        let config = EncoderConfig::new(InternalRate::Wide16k, 20, 16_000);
        let mut encoder = SilkEncoder::new(config).expect("config");
        let per_packet = encoder.samples_per_packet();
        for packet in 0..30 {
            let mut buffer = vec![0u8; config.max_bytes];
            let mut range = RangeEncoder::new(&mut buffer);
            let result = encoder
                .encode(&vec![0i16; per_packet], &mut range)
                .expect("encode");
            range.done();
            assert!(result.payload_bytes > 0, "packet {packet} was dropped");
        }
    }

    /// LBRR must appear one packet *after* the frame it protects, and must cost real bits.
    #[test]
    fn in_band_fec_carries_the_previous_packet() {
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 32_000);
        config.use_in_band_fec = true;
        config.packet_loss_percent = 20;
        let (_, with_fec) = encode_stream(config, 8);

        config.use_in_band_fec = false;
        let (_, without_fec) = encode_stream(config, 8);

        assert!(
            !with_fec[0].carries_redundancy,
            "the first packet cannot carry redundancy for a packet that does not exist"
        );
        assert!(
            with_fec[2..].iter().any(|result| result.carries_redundancy),
            "no packet carried redundancy"
        );
        let with: usize = with_fec.iter().map(|r| r.payload_bytes).sum();
        let without: usize = without_fec.iter().map(|r| r.payload_bytes).sum();
        assert!(with > without, "fec cost nothing: {with} vs {without}");
    }

    /// The adaptive high-pass tracker must start at the minimum cutoff, stay inside
    /// `[VARIABLE_HP_MIN_CUTOFF_HZ, VARIABLE_HP_MAX_CUTOFF_HZ]` forever, and actually *move* on
    /// voiced speech — a tracker pinned at its initial value would read as working.
    #[test]
    fn the_high_pass_tracker_starts_at_the_minimum_and_tracks_voiced_pitch() {
        let config = EncoderConfig::new(InternalRate::Wide16k, 20, 24_000);
        let mut encoder = SilkEncoder::new(config).expect("config");
        let initial = encoder.high_pass_smth1_q15();
        assert_eq!(
            initial,
            (lin2log(MIN_CUTOFF_HZ << 16) - (16 << 7)) << 8,
            "init_encoder.c:58"
        );

        let lower = lin2log(MIN_CUTOFF_HZ) << 8;
        let upper = lin2log(MAX_CUTOFF_HZ) << 8;

        // Nothing but a *voiced* previous frame moves it (`HP_variable_cutoff.c:48`), so drive the
        // state directly rather than hoping a synthetic signal trips the pitch search: an inactive
        // stream would make a broken tracker look correct.
        encoder.channels[0].frame.analysis.previous_signal_type = SignalType::Unvoiced;
        encoder.channels[0].frame.analysis.previous_lag = 80;
        encoder.channels[0].measures.speech_activity_q8 = 256;
        encoder.channels[0].measures.input_quality_bands_q15 = [22_000; 4];
        encoder.update_high_pass_smoother();
        assert_eq!(
            encoder.high_pass_smth1_q15(),
            initial,
            "an unvoiced previous frame must leave the tracker alone"
        );

        // A 200 Hz pitch at 16 kHz — a lag of 80 samples — is well above the 60 Hz floor, so the
        // smoother must climb towards it and then settle inside the legal band.
        encoder.channels[0].frame.analysis.previous_signal_type = SignalType::Voiced;
        let mut previous = initial;
        for step in 0..200 {
            encoder.update_high_pass_smoother();
            let smoothed = encoder.high_pass_smth1_q15();
            assert!(
                (lower..=upper).contains(&smoothed),
                "step {step}: {smoothed} left [{lower}, {upper}]"
            );
            assert!(
                smoothed >= previous,
                "step {step}: the smoother went backwards on a constant pitch"
            );
            previous = smoothed;
        }
        assert!(
            previous > initial,
            "the tracker never left its initial value on voiced speech"
        );

        // Silence has no speech activity, so the update is multiplied by zero and holds.
        encoder.channels[0].measures.speech_activity_q8 = 0;
        let held = encoder.high_pass_smth1_q15();
        for _ in 0..10 {
            encoder.update_high_pass_smoother();
        }
        assert_eq!(
            encoder.high_pass_smth1_q15(),
            held,
            "with no speech activity the smoother's step is zero"
        );

        // And the whole thing must survive a real stream without leaving the band.
        let per_packet = encoder.samples_per_packet();
        let speech = voiced(per_packet * 12, 80);
        for packet in 0..10 {
            let mut buffer = vec![0u8; config.max_bytes];
            let mut range = RangeEncoder::new(&mut buffer);
            let start = packet * per_packet;
            encoder
                .encode(&speech[start..start + per_packet], &mut range)
                .expect("encode");
            range.done();
            let smoothed = encoder.high_pass_smth1_q15();
            assert!(
                (lower..=upper).contains(&smoothed),
                "packet {packet}: {smoothed} left [{lower}, {upper}]"
            );
        }
    }

    /// A retune must not disturb the stream; an internal-rate change must reset the rate-dependent
    /// state and nothing else.
    #[test]
    fn controlling_resets_exactly_what_the_rate_depends_on() {
        let config = EncoderConfig::new(InternalRate::Wide16k, 20, 24_000);
        let mut encoder = SilkEncoder::new(config).expect("config");
        let per_packet = encoder.samples_per_packet();
        let speech = voiced(per_packet * 12, 80);
        let encode = |encoder: &mut SilkEncoder, packet: usize| -> Vec<u8> {
            let mut buffer = vec![0u8; 1275];
            let mut range = RangeEncoder::new(&mut buffer);
            let start = packet * encoder.samples_per_packet();
            let count = encoder.samples_per_packet();
            let result = encoder
                .encode(&speech[start..start + count], &mut range)
                .expect("encode");
            range.done();
            buffer[..result.payload_bytes.max(1)].to_vec()
        };
        for packet in 0..4 {
            encode(&mut encoder, packet);
        }

        // A pure retune: the bitrate moves and nothing resets.
        let before_lag = encoder.channels[0].frame.analysis.previous_lag;
        let mut retuned = config;
        retuned.bitrate_bps = 32_000;
        retuned.packet_loss_percent = 10;
        let outcome = encoder.control(retuned).expect("retune");
        assert_eq!(outcome.internal_rate, InternalRate::Wide16k);
        assert!(!outcome.switch_ready);
        assert_eq!(
            encoder.channels[0].frame.analysis.previous_lag, before_lag,
            "a retune must not reset the analysis"
        );
        assert_eq!(encoder.config().bitrate_bps, 32_000);
        assert_eq!(encoder.config().packet_loss_percent, 10);

        // A rate forced *outside* the legal window is the one change that happens on the spot: 16
        // kHz is no longer allowed, so there is nothing to negotiate and the rate-dependent state
        // is reset to its documented seeds.
        let mut narrowed = retuned;
        narrowed.internal_rate = InternalRate::Narrow8k;
        narrowed.max_internal_rate = InternalRate::Narrow8k;
        let outcome = encoder.control(narrowed).expect("rate change");
        assert_eq!(outcome.internal_rate, InternalRate::Narrow8k);
        assert_eq!(encoder.internal_rate(), InternalRate::Narrow8k);
        assert_eq!(encoder.channels[0].frame.analysis.previous_lag, 100);
        assert_eq!(encoder.channels[0].frame.analysis.shape.last_gain_index, 10);
        assert!(encoder.channels[0].frame.analysis.first_frame_after_reset);
        assert_eq!(encoder.samples_per_packet(), 160);
        // The VAD and the reservoir are *not* reset, as in the C.
        assert!(encoder.channels[0].measures.speech_activity_q8 > 0);

        // And the reconfigured encoder still produces packets.
        let mut buffer = vec![0u8; 1275];
        let mut range = RangeEncoder::new(&mut buffer);
        let result = encoder
            .encode(&vec![0i16; encoder.samples_per_packet()], &mut range)
            .expect("encode after control");
        range.done();
        assert!(result.payload_bytes > 0);

        // An illegal configuration must be refused without disturbing the encoder.
        let mut illegal = narrowed;
        illegal.duration_ms = 30;
        assert!(encoder.control(illegal).is_err());
        assert_eq!(encoder.config().duration_ms, 20);
        illegal.duration_ms = 20;
        illegal.channels = 3;
        assert!(encoder.control(illegal).is_err());
        assert_eq!(encoder.config().channels, 1);
    }

    /// Drive `packets` packets through an encoder, re-controlling with `config` each time and
    /// returning every [`ControlOutcome`]. `config.opus_can_switch` is fed from the previous
    /// packet's `switch_ready`, which is exactly what the Opus layer does.
    ///
    /// The input is silence: `allow_bandwidth_switch` is gated on speech activity, and a loud
    /// source would make these tests measure the activity threshold rather than the state machine.
    fn run_with_switching(
        encoder: &mut SilkEncoder,
        mut config: EncoderConfig,
        packets: usize,
    ) -> Vec<ControlOutcome> {
        let mut outcomes = Vec::new();
        let mut can_switch = false;
        for _ in 0..packets {
            config.opus_can_switch = can_switch;
            let outcome = encoder.control(config).expect("control");
            let per_packet = encoder.samples_per_packet() * config.channels;
            let mut buffer = vec![0u8; config.max_bytes];
            let mut range = RangeEncoder::new(&mut buffer);
            encoder
                .encode(&vec![0i16; per_packet], &mut range)
                .expect("encode");
            range.done();
            can_switch = outcome.switch_ready;
            outcomes.push(outcome);
        }
        outcomes
    }

    /// The core of the bandwidth state machine: a rate change *inside* the legal window never
    /// happens on its own. SILK raises `switch_ready`, and only once the Opus layer answers with
    /// `opus_can_switch` — its promise that a redundancy frame will cover the seam — does the rate
    /// actually move.
    #[test]
    fn a_rate_inside_the_window_moves_only_once_the_opus_layer_covers_the_seam() {
        let mut config = EncoderConfig::new(InternalRate::Narrow8k, 20, 24_000);
        let mut encoder = SilkEncoder::new(config).expect("config");
        assert_eq!(encoder.internal_rate(), InternalRate::Narrow8k);

        // One rung of the ladder: the state machine only ever steps to the adjacent rate
        // (`control_audio_bandwidth.c:104`), so ask for the adjacent one.
        config.internal_rate = InternalRate::Medium12k;
        let outcomes = run_with_switching(&mut encoder, config, 8);

        let asked = outcomes
            .iter()
            .position(|outcome| outcome.switch_ready)
            .expect("SILK never asked to switch up over 8 packets");
        for outcome in &outcomes[..=asked] {
            assert_eq!(
                outcome.internal_rate,
                InternalRate::Narrow8k,
                "the rate moved before the Opus layer had agreed to cover the seam"
            );
        }
        assert_eq!(
            outcomes[asked + 1].internal_rate,
            InternalRate::Medium12k,
            "the packet after the request is answered must be the one that switches"
        );
        assert!(
            !outcomes[asked + 1].switch_ready,
            "the request must not repeat once it has been satisfied"
        );
        assert_eq!(encoder.internal_rate(), InternalRate::Medium12k);
    }

    /// The two directions are not symmetric, and the asymmetry is the whole reason the transition
    /// filter exists. Going **up** needs no ramp — there is nothing above the old Nyquist to
    /// remove — so the request is raised on the first opportunity. Going **down** has to band-limit
    /// the input first, so the request waits out a `TRANSITION_FRAMES` sweep at two frames a frame.
    #[test]
    fn switching_up_asks_at_once_while_switching_down_ramps_first() {
        let mut up = EncoderConfig::new(InternalRate::Narrow8k, 20, 24_000);
        let mut encoder = SilkEncoder::new(up).expect("config");
        up.internal_rate = InternalRate::Medium12k;
        let outcomes = run_with_switching(&mut encoder, up, 8);
        let first_up = outcomes
            .iter()
            .position(|outcome| outcome.switch_ready)
            .expect("no upward request");
        assert!(
            first_up <= 1,
            "the upward request took {first_up} packets — the first is only spent earning \
             `allow_bandwidth_switch`, and anything beyond that is a ramp it should not be running"
        );

        let mut down = EncoderConfig::new(InternalRate::Wide16k, 20, 24_000);
        let mut encoder = SilkEncoder::new(down).expect("config");
        down.internal_rate = InternalRate::Medium12k;
        // The ramp is armed on the packet that earns the permission and then walked down two per
        // frame, so the request cannot arrive before `TRANSITION_FRAMES / 2` packets have gone by.
        let held = (TRANSITION_FRAMES / 2) as usize - 8;
        let outcomes = run_with_switching(&mut encoder, down, held);
        assert!(
            outcomes.iter().all(|outcome| !outcome.switch_ready),
            "a downward switch asked before its ramp had run out"
        );
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.internal_rate == InternalRate::Wide16k),
            "and the rate must not have moved either"
        );
        assert_eq!(encoder.channels[0].low_pass.mode, -2);

        // Run out the rest of the sweep and the request finally arrives.
        let rest = run_with_switching(&mut encoder, down, 24);
        assert!(
            rest.iter().any(|outcome| outcome.switch_ready),
            "the downward request never arrived even after the ramp finished"
        );
        assert_eq!(encoder.internal_rate(), InternalRate::Medium12k);
    }

    /// The packet that asks for a switch gives up part of its own budget, so the redundancy frame
    /// the Opus layer is about to append has somewhere to go (`control_audio_bandwidth.c:90`).
    #[test]
    fn asking_to_switch_reserves_room_for_the_redundancy_frame() {
        let mut config = EncoderConfig::new(InternalRate::Narrow8k, 20, 24_000);
        config.max_bytes = 100;
        let mut encoder = SilkEncoder::new(config).expect("config");
        assert_eq!(encoder.max_bits, 800);

        config.internal_rate = InternalRate::Wide16k;
        let mut can_switch = false;
        let source = voiced(encoder.samples_per_packet() * 64, 80);
        let mut consumed = 0usize;
        for _ in 0..40 {
            config.opus_can_switch = can_switch;
            let outcome = encoder.control(config).expect("control");
            if outcome.switch_ready {
                // 800 - 800 * 5 / 25.
                assert_eq!(encoder.max_bits, 640);
                return;
            }
            assert_eq!(encoder.max_bits, 800);
            let per_packet = encoder.samples_per_packet();
            let mut buffer = vec![0u8; config.max_bytes];
            let mut range = RangeEncoder::new(&mut buffer);
            encoder
                .encode(&source[consumed..consumed + per_packet], &mut range)
                .expect("encode");
            range.done();
            consumed += per_packet;
            can_switch = outcome.switch_ready;
        }
        panic!("SILK never asked to switch, so the reservation went untested");
    }

    /// A prefill leaves the encoder *warm*: the analysis history holds the audio it was fed, and the
    /// per-channel state is otherwise at its reset seeds. The `prefillFlag == 2` form additionally
    /// keeps the rate-control state, which is what lets a switch complete.
    #[test]
    fn a_prefill_fills_the_analysis_history_without_coding_anything() {
        let config = EncoderConfig::new(InternalRate::Wide16k, 20, 24_000);
        let mut encoder = SilkEncoder::new(config).expect("config");
        let source = voiced(encoder.samples_per_packet() * 8, 80);
        let mut buffer = vec![0u8; 1275];
        let mut range = RangeEncoder::new(&mut buffer);
        encoder
            .encode(&source[..encoder.samples_per_packet()], &mut range)
            .expect("encode");
        range.done();

        let rate = encoder
            .control_for_prefill(config, false)
            .expect("control_for_prefill");
        assert_eq!(rate, InternalRate::Wide16k);
        assert_eq!(
            encoder.config().duration_ms,
            10,
            "a prefill always runs as a single 10 ms frame"
        );
        assert!(
            encoder.channels[0]
                .input
                .iter()
                .all(|&sample| sample == 0.0),
            "the reset must have cleared the analysis history before it is refilled"
        );

        encoder
            .prefill(&source[..10 * rate.khz()])
            .expect("prefill");
        assert!(
            encoder.channels[0]
                .input
                .iter()
                .any(|&sample| sample != 0.0),
            "the prefill left no history behind, which is the one thing it exists to do"
        );
        // Nothing was coded: the quantiser and the entropy predictors are still at their seeds.
        assert!(encoder.channels[0].frame.analysis.first_frame_after_reset);
        assert_eq!(encoder.channels[0].frame.analysis.previous_lag, 100);
        assert_eq!(encoder.channels[0].frame.analysis.shape.last_gain_index, 10);

        // Too little audio is an error, not a short prefill.
        assert!(encoder.prefill(&source[..10 * rate.khz() - 1]).is_err());
    }

    /// `prefillFlag == 2` exists so a bandwidth switch survives the reset that goes with it: the
    /// transition schedule and the rate it is switching *from* have to outlive
    /// `silk_init_encoder`.
    #[test]
    fn a_rate_control_preserving_prefill_still_knows_which_rate_it_came_from() {
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 24_000);
        let mut encoder = SilkEncoder::new(config).expect("config");
        assert_eq!(encoder.internal_rate(), InternalRate::Wide16k);

        // Pretend the Opus layer has just agreed to cover a downward switch.
        config.internal_rate = InternalRate::Medium12k;
        config.opus_can_switch = true;
        let rate = encoder
            .control_for_prefill(config, true)
            .expect("control_for_prefill");
        assert_eq!(
            rate,
            InternalRate::Medium12k,
            "the prefill must land on the *new* rate; forgetting the old one strands the switch"
        );
        assert_eq!(encoder.internal_rate(), InternalRate::Medium12k);

        // The same prefill without keeping the rate control has nothing to switch from, so it falls
        // back to whatever was asked for outright.
        let mut encoder = SilkEncoder::new(EncoderConfig::new(InternalRate::Wide16k, 20, 24_000))
            .expect("config");
        let rate = encoder
            .control_for_prefill(config, false)
            .expect("control_for_prefill");
        assert_eq!(rate, InternalRate::Medium12k);
        assert_eq!(
            encoder.channels[0].low_pass,
            LowPassState::default(),
            "a full reset must leave no transition state behind"
        );
    }

    /// What a prefill left behind, in the shape the libopus oracle prints it.
    ///
    /// See [`a_prefill_leaves_the_state_libopus_leaves`] for how the reference values were produced.
    #[derive(Debug, PartialEq)]
    struct PrefillState {
        internal_khz: usize,
        low_pass: LowPassState,
        high_pass_smth1_q15: i32,
        speech_activity_q8: i32,
        input_tilt_q15: i32,
        input_quality_bands_q15: [i32; 4],
        first_frame_after_reset: bool,
        analysis_history_digest: u64,
        analysis_history_head: [f32; 4],
        analysis_history_tail: [f32; 4],
    }

    /// FNV-1a over the raw little-endian IEEE-754 bytes, byte for byte with the C oracle's.
    fn fnv_f32(values: &[f32]) -> u64 {
        let mut hash = 14_695_981_039_346_656_037u64;
        for &value in values {
            for byte in value.to_bits().to_le_bytes() {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(1_099_511_628_211);
            }
        }
        hash
    }

    /// Drive four ordinary 20 ms packets and then one prefill, exactly as the C oracle does, and
    /// report what the prefill left behind.
    ///
    /// The API rate is the internal rate so the sequence is short, but the resampler is still in the
    /// path on both sides — even an identity rate pair carries a 10-sample encoder delay
    /// (`delay_matrix_enc[16k][16k]`), so leaving it out would compare against a differently aligned
    /// signal.
    fn prefill_state(
        keep_rate_control: bool,
        desired_after: InternalRate,
        opus_can_switch: bool,
    ) -> PrefillState {
        use crate::opus::silk::resampler::Resampler;

        const API_HZ: u32 = 16_000;
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 24_000);
        config.complexity = 6;
        config.max_bytes = 100;
        config.api_rate_hz = API_HZ as i32;

        let mut source = Source::new();
        let mut resampler = Resampler::new();
        resampler
            .configure_for_encoder(API_HZ, API_HZ)
            .expect("identity resampler");

        let mut encoder = SilkEncoder::new(config).expect("config");
        let mut raw = [0i16; 320];
        let mut resampled = [0i16; 320];
        for packet in 0..4 {
            if packet > 0 {
                encoder.control(config).expect("control");
            }
            source.fill(&mut raw);
            let written = resampler
                .process(&mut resampled, &raw)
                .expect("identity resample");
            assert_eq!(written, 320);
            let mut buffer = [0u8; 100];
            let mut range = RangeEncoder::new(&mut buffer);
            encoder.encode(&resampled, &mut range).expect("encode");
            range.done();
        }

        let prefill_config = EncoderConfig {
            internal_rate: desired_after,
            opus_can_switch,
            ..config
        };
        let rate = encoder
            .control_for_prefill(prefill_config, keep_rate_control)
            .expect("control_for_prefill");
        // `silk_setup_resamplers` re-initialises after the reset (`control_codec.c:142-146`).
        resampler
            .reinitialize_for_encoder(API_HZ, rate.khz() as u32 * 1_000)
            .expect("prefill resampler");
        let mut prefill_in = [0i16; 160];
        source.fill(&mut prefill_in);
        let produced = 10 * rate.khz();
        let mut prefill_out = [0i16; 160];
        let written = resampler
            .process(&mut prefill_out[..produced], &prefill_in)
            .expect("prefill resample");
        assert_eq!(written, produced);
        encoder.prefill(&prefill_out[..produced]).expect("prefill");

        let (history, lookahead) = encoder.analysis_buffer_geometry();
        let surviving = &encoder.channels[0].input[..history + lookahead];
        PrefillState {
            internal_khz: encoder.internal_rate().khz(),
            low_pass: encoder.channels[0].low_pass,
            high_pass_smth1_q15: encoder.high_pass_smth1_q15(),
            speech_activity_q8: encoder.channels[0].measures.speech_activity_q8,
            input_tilt_q15: encoder.channels[0].measures.input_tilt_q15,
            input_quality_bands_q15: encoder.channels[0].measures.input_quality_bands_q15,
            first_frame_after_reset: encoder.channels[0].frame.analysis.first_frame_after_reset,
            analysis_history_digest: fnv_f32(surviving),
            analysis_history_head: [surviving[0], surviving[1], surviving[2], surviving[3]],
            analysis_history_tail: [
                surviving[surviving.len() - 4],
                surviving[surviving.len() - 3],
                surviving[surviving.len() - 2],
                surviving[surviving.len() - 1],
            ],
        }
    }

    /// **The prefill state, diffed against libopus.**
    ///
    /// "Sounds fine" is not a bar for a prefill: its whole purpose is to leave *state* behind, and
    /// state that is subtly wrong produces audio that is subtly wrong for the next several frames
    /// and is invisible in any single packet. So the reference values below are what the real
    /// `silk_Encode(..., prefillFlag)` leaves in a `silk_encoder`, read straight out of the struct
    /// after driving four ordinary packets and then a prefill through libopus itself — the same LCG
    /// input, the same control structure, the same resampler.
    ///
    /// Three cases, because the two prefill forms and the switching one differ in exactly the state
    /// this is checking:
    ///
    /// * `prefillFlag == 1` — a plain CELT→SILK entry. Everything resets; `sLP` included, so it
    ///   comes back all zeros.
    /// * `prefillFlag == 2` with no rate change — the same, except `sLP.saved_fs_kHz` remembers the
    ///   rate the encoder was at. Nothing else may differ, and this case is what proves the "keep"
    ///   is narrow rather than a general state carry-over.
    /// * `prefillFlag == 2` with `opusCanSwitch` — the real bandwidth switch. The rate moves to 12
    ///   kHz, the transition counter is parked at its ceiling with the filter switched off, and the
    ///   analysis history is 300 samples of the *new* rate rather than 400 of the old.
    #[test]
    fn a_prefill_leaves_the_state_libopus_leaves() {
        // `prefillFlag == 1`, staying at 16 kHz.
        assert_eq!(
            prefill_state(false, InternalRate::Wide16k, false),
            PrefillState {
                internal_khz: 16,
                low_pass: LowPassState::default(),
                high_pass_smth1_q15: 193_536,
                speech_activity_q8: 255,
                input_tilt_q15: -32_768,
                input_quality_bands_q15: [23_731, 23_731, 24_261, 25_179],
                first_frame_after_reset: true,
                analysis_history_digest: 0x854b_4186_e756_e617,
                analysis_history_head: [0.0, 0.0, 0.0, 0.0],
                analysis_history_tail: [-385.0, -792.0, 6802.0, -4211.0],
            }
        );

        // `prefillFlag == 2`, no rate change: the same signal, but `saved_fs_kHz` remembers the
        // rate and the stereo carry survives — which is why the history digest differs by exactly
        // its first sample.
        assert_eq!(
            prefill_state(true, InternalRate::Wide16k, false),
            PrefillState {
                internal_khz: 16,
                low_pass: LowPassState {
                    saved_fs_khz: 16,
                    ..LowPassState::default()
                },
                high_pass_smth1_q15: 193_536,
                speech_activity_q8: 255,
                input_tilt_q15: -32_768,
                input_quality_bands_q15: [23_731, 23_731, 24_261, 25_179],
                first_frame_after_reset: true,
                analysis_history_digest: 0xe714_4de6_26c4_d2b8,
                analysis_history_head: [0.0, 0.0, 0.0, 0.0],
                analysis_history_tail: [-385.0, -792.0, 6802.0, -4211.0],
            }
        );

        // `prefillFlag == 2` on the switching frame: 16 kHz down to 12 kHz.
        assert_eq!(
            prefill_state(true, InternalRate::Medium12k, true),
            PrefillState {
                internal_khz: 12,
                low_pass: LowPassState {
                    state: [0, 0],
                    transition_frame_no: TRANSITION_FRAMES,
                    mode: 0,
                    saved_fs_khz: 16,
                },
                high_pass_smth1_q15: 193_536,
                speech_activity_q8: 255,
                input_tilt_q15: -32_768,
                input_quality_bands_q15: [23_731, 23_731, 24_108, 24_567],
                first_frame_after_reset: true,
                analysis_history_digest: 0xd379_ed40_8245_f257,
                analysis_history_head: [0.0, 0.0, 0.0, 0.0],
                analysis_history_tail: [6082.0, -237.0, 1486.0, 2645.0],
            }
        );
    }

    /// The permission to start a switch tracks speech activity: silence grants it, a loud talker
    /// does not — until the threshold has relaxed far enough that the stream is not stuck for ever.
    #[test]
    fn the_switch_permission_follows_speech_activity() {
        let config = EncoderConfig::new(InternalRate::Wide16k, 20, 24_000);
        let mut encoder = SilkEncoder::new(config).expect("config");
        let per_packet = encoder.samples_per_packet();
        let speech = voiced(per_packet * 4, 80);

        let encode = |encoder: &mut SilkEncoder, samples: &[i16]| {
            let mut buffer = vec![0u8; 1275];
            let mut range = RangeEncoder::new(&mut buffer);
            let result = encoder.encode(samples, &mut range).expect("encode");
            range.done();
            result
        };

        encode(&mut encoder, &speech[..per_packet]);
        assert!(
            !encoder.allow_bandwidth_switch(),
            "a loud frame must not authorise a bandwidth step"
        );
        assert!(encoder.time_since_switch_allowed_ms > 0);

        for _ in 0..4 {
            encode(&mut encoder, &vec![0i16; per_packet]);
        }
        assert!(
            encoder.allow_bandwidth_switch(),
            "silence must authorise one"
        );
        assert_eq!(encoder.time_since_switch_allowed_ms, 0);
    }

    /// A configuration SILK does not define must be rejected rather than silently coerced.
    #[test]
    fn illegal_configurations_are_rejected() {
        for duration in [0usize, 5, 15, 30, 80] {
            assert!(
                SilkEncoder::new(EncoderConfig::new(InternalRate::Wide16k, duration, 16_000))
                    .is_err(),
                "{duration} ms must be rejected"
            );
        }
        let mut config = EncoderConfig::new(InternalRate::Wide16k, 20, 16_000);
        config.channels = 3;
        assert!(SilkEncoder::new(config).is_err());
        config.channels = 0;
        assert!(SilkEncoder::new(config).is_err());
    }

    /// Too little input must be an error, not an out-of-bounds read.
    #[test]
    fn a_short_input_is_rejected() {
        let config = EncoderConfig::new(InternalRate::Wide16k, 20, 16_000);
        let mut encoder = SilkEncoder::new(config).expect("config");
        let mut buffer = [0u8; 256];
        let mut range = RangeEncoder::new(&mut buffer);
        assert!(encoder.encode(&[0i16; 100], &mut range).is_err());
    }
}
