//! Persistent SILK decoder state (libopus `silk_decoder` / `silk_decoder_state`, `silk/structs.h`).
//!
//! SILK is a **stateful** predictive codec: almost every symbol in a frame is decoded relative to
//! something the previous frame left behind (the gain index, the NLSF vector, the pitch lag, the LPC
//! and LTP history, the stereo prediction weights). This module owns that carry-over so the per-frame
//! decode functions can stay pure, and so a decoder reset (RFC 6716 §4.5.2) is one obvious operation
//! rather than a scattering of zeroings.
//!
//! Layout mirrors the C: a [`SilkDecoder`] holds up to two [`ChannelState`]s (mid and side) plus the
//! shared [`StereoState`], exactly as `silk_decoder` holds `channel_state[2]` and `sStereo`.
//!
//! **Everything is fixed-size.** The C's `MAX_FRAME_LENGTH`-sized arrays are inline `[i32; N]` /
//! `[i16; N]` fields, so a decoder allocates once at construction and never again — the repo's
//! zero-per-frame-heap-allocation invariant.
//!
//! Deliberately **not** modelled here, because the phases that own them are not written yet:
//! `resampler_state` (§4.2.9), `sCNG` / `sPLC` (§4.4), the NLSF codebook and pitch-table pointers
//! (`psNLSF_CB`, `pitch_lag_low_bits_iCDF`, `pitch_contour_iCDF` — those are selected from
//! [`InternalRate`] and belong with the NLSF/LTP decode), and `SideInfoIndices` (the per-frame index
//! bag: each decode phase returns its own indices instead, see the module docs in `silk/mod.rs`).

use crate::opus::silk::types::{
    CondCoding, InternalRate, SignalType, SubframeLayout, MAX_FRAMES_PER_PACKET, MAX_FRAME_LENGTH,
    MAX_LPC_ORDER, MAX_SUB_FRAME_LENGTH,
};
use crate::CodecError;

/// Length of the per-channel output history buffer (`outBuf`, `structs.h:293`):
/// `MAX_FRAME_LENGTH + 2 * MAX_SUB_FRAME_LENGTH`. It holds the LTP memory (the previous
/// `ltp_mem_length` samples) plus room for the current frame.
pub const OUT_BUF_LENGTH: usize = MAX_FRAME_LENGTH + 2 * MAX_SUB_FRAME_LENGTH;

/// Reset value of `prev_gain_Q16` — 1.0 in Q16 (`init_decoder.c:52`).
const PREV_GAIN_RESET_Q16: i32 = 65536;

/// Reset value of `lagPrev` (`decoder_set_fs.c:92`), a mid-range pitch lag.
const LAG_PREV_RESET: i32 = 100;

/// Reset value of `LastGainIndex` (`decoder_set_fs.c:93`). Not zero: the first delta-coded gain in a
/// stream is measured against this, so it has to be a plausible mid-scale log-gain.
const LAST_GAIN_INDEX_RESET: i8 = 10;

/// Per-channel SILK decoder state (libopus `silk_decoder_state`, `structs.h:285-337`).
///
/// The C resets everything from `prev_gain_Q16` onward (`SILK_DECODER_STATE_RESET_START`,
/// `init_decoder.c:48`); [`ChannelState::reset`] does the same.
///
/// Fields are public because they are the working surface every SILK decode phase writes to (the C
/// passes `psDec` around for exactly this reason). The *configuration* — internal rate and subframe
/// layout — is private, so it can only change through [`ChannelState::set_internal_rate`], which
/// performs the same side effects `silk_decoder_set_fs` does.
#[derive(Debug, Clone)]
pub struct ChannelState {
    // ── Configuration (private: changing it has side effects) ─────────────────────────────────
    /// `fs_kHz` — the internal sample rate. `None` until the first
    /// [`ChannelState::set_internal_rate`], matching the C's `fs_kHz == 0` fresh state (which is
    /// what makes the first call always take the "rate changed" branch).
    internal_rate: Option<InternalRate>,
    /// `nb_subfr` + `nFramesPerPacket`, as one value.
    layout: SubframeLayout,

    // ── Cross-frame prediction state ──────────────────────────────────────────────────────────
    /// `prev_gain_Q16` — the last subframe gain of the previous frame, in Q16. `silk_decode_core`
    /// interpolates the first subframe's gain change from it.
    pub prev_gain_q16: i32,
    /// `exc_Q14[MAX_FRAME_LENGTH]` — the reconstructed excitation of the current frame in Q14. Kept
    /// on the state because comfort-noise generation reads it back (`silk_CNG`).
    pub excitation_q14: [i32; MAX_FRAME_LENGTH],
    /// `sLPC_Q14_buf[MAX_LPC_ORDER]` — short-term (LPC) synthesis filter memory in Q14, carried into
    /// the next frame so the filter is continuous across frame boundaries.
    pub lpc_state_q14: [i32; MAX_LPC_ORDER],
    /// `outBuf[MAX_FRAME_LENGTH + 2*MAX_SUB_FRAME_LENGTH]` — decoded output history. The LTP
    /// predictor reaches back into it for the pitch-lagged signal, so it must survive the frame.
    pub out_buf: [i16; OUT_BUF_LENGTH],
    /// `lagPrev` — pitch lag of the last subframe of the previous frame, the fallback lag for PLC and
    /// for an unvoiced-to-voiced transition.
    pub lag_prev: i32,
    /// `LastGainIndex` — the previous subframe's 6-bit log-gain index. Every delta-coded gain
    /// (§4.2.7.4) is relative to this, and it is the one piece of gain state that crosses frames.
    pub last_gain_index: i8,
    /// `prevNLSF_Q15[MAX_LPC_ORDER]` — the previous frame's normalized LSFs in Q15, the anchor for
    /// LSF interpolation (§4.2.7.5.5).
    pub prev_nlsf_q15: [i16; MAX_LPC_ORDER],
    /// `first_frame_after_reset` — suppresses LSF interpolation and pitch prediction for one frame
    /// after a reset, since the "previous" values are synthetic.
    pub first_frame_after_reset: bool,

    // ── Packet bookkeeping ────────────────────────────────────────────────────────────────────
    /// `nFramesDecoded` — how many 20 ms SILK frames of the current Opus frame are already decoded.
    /// Indexes [`ChannelState::vad_flags`] / [`ChannelState::lbrr_flags`].
    pub frames_decoded: usize,

    // ── Entropy-coding context (values the *next* frame's symbols are coded against) ──────────
    /// `ec_prevSignalType` — previous frame's signal type; gates delta pitch-lag coding
    /// (§4.2.7.6.1).
    pub ec_prev_signal_type: SignalType,
    /// `ec_prevLagIndex` — previous frame's absolute pitch-lag index, the base for a delta lag.
    pub ec_prev_lag_index: i16,

    // ── LP-layer header flags for the current Opus frame (RFC 6716 §4.2.3, §4.2.4) ────────────
    /// `VAD_flags[MAX_FRAMES_PER_PACKET]` — one per 20 ms SILK frame in this Opus frame.
    pub vad_flags: [bool; MAX_FRAMES_PER_PACKET],
    /// `LBRR_flag` — this channel carries at least one LBRR frame.
    pub lbrr_flag: bool,
    /// `LBRR_flags[MAX_FRAMES_PER_PACKET]` — which 20 ms intervals carry an LBRR frame.
    pub lbrr_flags: [bool; MAX_FRAMES_PER_PACKET],

    // ── Loss concealment context ──────────────────────────────────────────────────────────────
    /// `lossCnt` — consecutive concealed frames; non-zero triggers bandwidth expansion of the LPC
    /// coefficients on the next good frame (`decode_parameters.c:81-84`).
    pub loss_count: i32,
    /// `prevSignalType` — signal type of the last *successfully decoded* frame (distinct from
    /// `ec_prev_signal_type`, which the entropy coder maintains even for skipped frames).
    pub prev_signal_type: SignalType,
}

impl ChannelState {
    /// A fresh channel in the reset state (libopus `silk_init_decoder` → `silk_reset_decoder`).
    #[must_use]
    pub fn new() -> Self {
        let mut state = Self {
            internal_rate: None,
            // 20 ms / 4 subframes is the C's post-`memset` state only in the sense that `nb_subfr` is
            // overwritten before use (`dec_API.c:183-203` sets it from the payload size on the first
            // frame of every packet). We start from the 20 ms layout so the struct is never in an
            // impossible state.
            layout: SubframeLayout {
                frames_per_packet: 1,
                subframe_count: 4,
            },
            prev_gain_q16: PREV_GAIN_RESET_Q16,
            excitation_q14: [0; MAX_FRAME_LENGTH],
            lpc_state_q14: [0; MAX_LPC_ORDER],
            out_buf: [0; OUT_BUF_LENGTH],
            lag_prev: 0,
            last_gain_index: 0,
            prev_nlsf_q15: [0; MAX_LPC_ORDER],
            first_frame_after_reset: true,
            frames_decoded: 0,
            ec_prev_signal_type: SignalType::Inactive,
            ec_prev_lag_index: 0,
            vad_flags: [false; MAX_FRAMES_PER_PACKET],
            lbrr_flag: false,
            lbrr_flags: [false; MAX_FRAMES_PER_PACKET],
            loss_count: 0,
            prev_signal_type: SignalType::Inactive,
        };
        state.reset();
        state
    }

    /// Reset all prediction state (libopus `silk_reset_decoder`, `init_decoder.c:43-67`), as RFC 6716
    /// §4.5.2 requires when the decoder is reset or the mode switches away from and back to SILK.
    ///
    /// `first_frame_after_reset` is set and `prev_gain_Q16` becomes 1.0 in Q16; everything else is
    /// zeroed. The internal rate is cleared too, so the next [`ChannelState::set_internal_rate`]
    /// re-runs the full rate-change path exactly as the C does from `fs_kHz == 0`.
    pub fn reset(&mut self) {
        self.internal_rate = None;
        self.prev_gain_q16 = PREV_GAIN_RESET_Q16;
        self.excitation_q14 = [0; MAX_FRAME_LENGTH];
        self.lpc_state_q14 = [0; MAX_LPC_ORDER];
        self.out_buf = [0; OUT_BUF_LENGTH];
        self.lag_prev = 0;
        self.last_gain_index = 0;
        self.prev_nlsf_q15 = [0; MAX_LPC_ORDER];
        self.first_frame_after_reset = true;
        self.frames_decoded = 0;
        self.ec_prev_signal_type = SignalType::Inactive;
        self.ec_prev_lag_index = 0;
        self.vad_flags = [false; MAX_FRAMES_PER_PACKET];
        self.lbrr_flag = false;
        self.lbrr_flags = [false; MAX_FRAMES_PER_PACKET];
        self.loss_count = 0;
        self.prev_signal_type = SignalType::Inactive;
    }

    /// Configure the internal rate and subframe layout for the current packet (libopus
    /// `silk_decoder_set_fs`, `decoder_set_fs.c:35-107`).
    ///
    /// A **change of internal rate** invalidates every sample-domain history buffer, so the C clears
    /// `outBuf` and `sLPC_Q14_buf` and re-seeds `lagPrev`, `LastGainIndex`, and `prevSignalType`
    /// (`decoder_set_fs.c:91-96`). Reproduced here, including the seeds — `LastGainIndex = 10` in
    /// particular is load-bearing, since the very first delta-coded gain of a stream is measured
    /// against it.
    ///
    /// A change of *layout* alone (e.g. 20 ms → 40 ms at the same rate) keeps the history.
    pub fn set_internal_rate(&mut self, rate: InternalRate, layout: SubframeLayout) {
        self.layout = layout;
        if self.internal_rate == Some(rate) {
            return;
        }
        self.internal_rate = Some(rate);
        self.out_buf = [0; OUT_BUF_LENGTH];
        self.lpc_state_q14 = [0; MAX_LPC_ORDER];
        self.lag_prev = LAG_PREV_RESET;
        self.last_gain_index = LAST_GAIN_INDEX_RESET;
        self.prev_signal_type = SignalType::Inactive;
        self.first_frame_after_reset = true;
    }

    /// The configured internal rate, or `Err` if the channel has not been configured yet.
    pub fn internal_rate(&self) -> Result<InternalRate, CodecError> {
        self.internal_rate.ok_or(CodecError::Unsupported(
            "silk: internal rate not configured",
        ))
    }

    /// The configured subframe layout (`nb_subfr` / `nFramesPerPacket`).
    #[must_use]
    pub fn layout(&self) -> SubframeLayout {
        self.layout
    }

    /// `nb_subfr` — 5 ms subframes in the current SILK frame.
    #[must_use]
    pub fn subframe_count(&self) -> usize {
        self.layout.subframe_count
    }

    /// `nFramesPerPacket` — 20 ms SILK frames in the current Opus frame.
    #[must_use]
    pub fn frames_per_packet(&self) -> usize {
        self.layout.frames_per_packet
    }

    /// `frame_length` — samples in one SILK frame at the configured rate.
    pub fn frame_length(&self) -> Result<usize, CodecError> {
        Ok(self.layout.frame_length(self.internal_rate()?))
    }

    /// `subfr_length` — samples in one 5 ms subframe at the configured rate.
    pub fn subframe_length(&self) -> Result<usize, CodecError> {
        Ok(self.internal_rate()?.subframe_length())
    }

    /// `ltp_mem_length` — samples of output history the LTP predictor may reach back into.
    pub fn ltp_memory_length(&self) -> Result<usize, CodecError> {
        Ok(self.internal_rate()?.ltp_memory_length())
    }

    /// `LPC_order` — 10 (NB/MB) or 16 (WB).
    pub fn lpc_order(&self) -> Result<usize, CodecError> {
        Ok(self.internal_rate()?.lpc_order())
    }

    /// The conditional-coding regime for the SILK frame at `frame_index` of the current Opus frame
    /// (libopus `dec_API.c:342-354`, the `FrameIndex <= 0` / `CODE_CONDITIONALLY` decision).
    ///
    /// `previous_frame_coded` answers "was the previous SILK frame of the same type (regular or LBRR)
    /// for this channel actually coded?". For regular frames it is always true — a regular SILK frame
    /// exists for every interval even when its VAD flag is clear (§4.2.6). For LBRR frames it is the
    /// previous interval's LBRR flag (`dec_API.c:267-271, 347`).
    ///
    /// `side_channel_skipped_a_frame` is the C's `n > 0 && psDec->prev_decode_only_middle` case: the
    /// side channel skipped a frame earlier in this packet, so its LTP state is well defined and no
    /// LTP scaling factor needs coding — but the gain still cannot be delta-coded.
    #[must_use]
    pub fn cond_coding(
        frame_index: usize,
        previous_frame_coded: bool,
        side_channel_skipped_a_frame: bool,
    ) -> CondCoding {
        if frame_index == 0 || !previous_frame_coded {
            CondCoding::Independently
        } else if side_channel_skipped_a_frame {
            CondCoding::IndependentlyNoLtpScaling
        } else {
            CondCoding::Conditionally
        }
    }
}

impl Default for ChannelState {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared mid/side state (libopus `stereo_dec_state`, `structs.h:127-131`).
///
/// The stereo prediction weights are interpolated over the first 8 ms of every frame (§4.2.8), so the
/// *previous* frame's weights have to survive; `s_mid` / `s_side` hold the two-sample overlap the
/// unmixing filter needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StereoState {
    /// `pred_prev_Q13[2]` — the previous frame's two prediction weights in Q13. Zero after a reset
    /// and on any mono→stereo transition, which is what RFC 6716 §4.2.7.1 means by "using zeros for
    /// the previous weights if none are available".
    pub pred_prev_q13: [i16; 2],
    /// `sMid[2]` — last two mid-channel samples of the previous frame.
    pub mid_history: [i16; 2],
    /// `sSide[2]` — last two side-channel samples of the previous frame.
    pub side_history: [i16; 2],
}

impl StereoState {
    /// All-zero state (libopus `silk_memset(&psDec->sStereo, 0, ...)`, `dec_API.c:124`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            pred_prev_q13: [0; 2],
            mid_history: [0; 2],
            side_history: [0; 2],
        }
    }
}

impl Default for StereoState {
    fn default() -> Self {
        Self::new()
    }
}

/// Index of the mid channel in [`SilkDecoder::channels`]-style accessors.
pub const MID_CHANNEL: usize = 0;
/// Index of the side channel.
pub const SIDE_CHANNEL: usize = 1;

/// Complete SILK decoder state (libopus `silk_decoder`, `dec_API.c:47-56`): one
/// [`ChannelState`] per internal channel plus the shared [`StereoState`].
///
/// "Internal" channels are what the *bitstream* carries (`nChannelsInternal`), which is not
/// necessarily what the caller asked for (`nChannelsAPI`): a mono stream feeding a stereo API
/// duplicates the channel, and a stereo stream feeding a mono API drops the side channel
/// (`dec_API.c:404-435`). Both counts are tracked because a change in either one forces parts of the
/// state to reset (`dec_API.c:214-220`).
#[derive(Debug, Clone)]
pub struct SilkDecoder {
    /// `channel_state[DECODER_NUM_CHANNELS]` — mid first, side second. The side channel is kept
    /// allocated even for a mono stream so a mid-packet mono→stereo switch costs no allocation.
    channels: [ChannelState; 2],
    /// `nChannelsInternal` — 1 or 2, from the Opus TOC stereo flag (RFC 6716 §3.1).
    channel_count: usize,
    /// `nChannelsAPI` — channels the caller wants out.
    api_channel_count: usize,
    /// `fs_API_hz` — the caller's output rate, the target of the §4.2.9 resampler. SILK itself never
    /// decodes at this rate.
    api_rate_hz: u32,
    /// `sStereo`.
    stereo: StereoState,
    /// `prev_decode_only_middle` — the previous frame coded no side channel. Feeds both the
    /// "reset the side channel's prediction memory" rule (`dec_API.c:303-310`) and the
    /// `CODE_INDEPENDENTLY_NO_LTP_SCALING` decision.
    prev_decode_only_middle: bool,
}

impl SilkDecoder {
    /// A fresh decoder (libopus `silk_InitDecoder`, `dec_API.c:107-129`).
    ///
    /// `api_rate_hz` must be 8000..=48000 (`dec_API.c:222-226`) and `api_channel_count` 1 or 2.
    /// `channel_count` (the bitstream's internal channel count) is set per packet with
    /// [`SilkDecoder::configure`], since the TOC stereo flag may change from packet to packet.
    pub fn new(api_rate_hz: u32, api_channel_count: usize) -> Result<Self, CodecError> {
        if !(8_000..=48_000).contains(&api_rate_hz) {
            return Err(CodecError::Unsupported(
                "silk: API sample rate must be 8000..=48000 Hz",
            ));
        }
        if api_channel_count != 1 && api_channel_count != 2 {
            return Err(CodecError::Unsupported("silk: API channels must be 1 or 2"));
        }
        Ok(Self {
            channels: [ChannelState::new(), ChannelState::new()],
            channel_count: 1,
            api_channel_count,
            api_rate_hz,
            stereo: StereoState::new(),
            prev_decode_only_middle: false,
        })
    }

    /// Full decoder reset (libopus `silk_ResetDecoder`, `dec_API.c:88-104`): both channels reset and
    /// the stereo state zeroed. Required when the Opus decoder switches into SILK from CELT-only
    /// (`opus_decoder.c:389-390`) and on an explicit `OPUS_RESET_STATE`.
    pub fn reset(&mut self) {
        for channel in &mut self.channels {
            channel.reset();
        }
        self.stereo = StereoState::new();
        self.prev_decode_only_middle = false;
    }

    /// Configure for the current packet: internal channel count, internal rate, and Opus frame
    /// duration (libopus `dec_API.c:166-220` plus `silk_decoder_set_fs`).
    ///
    /// Two transitions are handled exactly as the C does:
    ///
    /// * **mono → stereo** re-initialises the side channel from scratch (`dec_API.c:173-175`) — its
    ///   history is meaningless, and reusing it would leak the mid channel's LPC state into the side.
    /// * **first stereo frame after mono** zeroes the stereo prediction memory
    ///   (`dec_API.c:214-218`), which is RFC 6716 §4.2.7.1's "the previous weights are reset to zeros
    ///   on any transition from mono to stereo".
    pub fn configure(
        &mut self,
        channel_count: usize,
        rate: InternalRate,
        duration_ms: usize,
    ) -> Result<(), CodecError> {
        if channel_count != 1 && channel_count != 2 {
            return Err(CodecError::Unsupported(
                "silk: internal channels must be 1 or 2",
            ));
        }
        let layout = SubframeLayout::from_duration_ms(duration_ms)?;

        // Mono -> stereo in the bitstream: bring the second channel up from a clean slate.
        if channel_count > self.channel_count {
            self.channels[SIDE_CHANNEL].reset();
        }
        // First genuinely stereo frame after mono: the interpolation anchor must be zero.
        if self.api_channel_count == 2 && channel_count == 2 && self.channel_count == 1 {
            self.stereo.pred_prev_q13 = [0; 2];
            self.stereo.side_history = [0; 2];
        }
        self.channel_count = channel_count;

        for channel in self.channels.iter_mut().take(channel_count) {
            channel.set_internal_rate(rate, layout);
            channel.frames_decoded = 0;
        }
        Ok(())
    }

    /// `nChannelsInternal` — internal (bitstream) channel count for the current packet.
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.channel_count
    }

    /// `nChannelsAPI` — the caller's output channel count.
    #[must_use]
    pub fn api_channel_count(&self) -> usize {
        self.api_channel_count
    }

    /// `fs_API_hz` — the caller's output sample rate in Hz.
    #[must_use]
    pub fn api_rate_hz(&self) -> u32 {
        self.api_rate_hz
    }

    /// Immutable access to one channel's state ([`MID_CHANNEL`] or [`SIDE_CHANNEL`]).
    pub fn channel(&self, index: usize) -> Result<&ChannelState, CodecError> {
        self.channels
            .get(index)
            .ok_or(CodecError::Unsupported("silk: channel index out of range"))
    }

    /// Mutable access to one channel's state ([`MID_CHANNEL`] or [`SIDE_CHANNEL`]).
    pub fn channel_mut(&mut self, index: usize) -> Result<&mut ChannelState, CodecError> {
        self.channels
            .get_mut(index)
            .ok_or(CodecError::Unsupported("silk: channel index out of range"))
    }

    /// The shared mid/side state.
    #[must_use]
    pub fn stereo(&self) -> &StereoState {
        &self.stereo
    }

    /// The shared mid/side state, mutably.
    pub fn stereo_mut(&mut self) -> &mut StereoState {
        &mut self.stereo
    }

    /// `prev_decode_only_middle` — the previous frame coded the mid channel only.
    #[must_use]
    pub fn prev_decode_only_middle(&self) -> bool {
        self.prev_decode_only_middle
    }

    /// Record whether the frame just decoded coded the mid channel only (`dec_API.c:437`).
    ///
    /// A `true` → `false` edge means the side channel is coming back after being skipped, so its
    /// prediction memory has to be dropped before it is used again (`dec_API.c:303-310`): the LTP
    /// history it would otherwise reach into belongs to a different time interval.
    pub fn set_decode_only_middle(&mut self, decode_only_middle: bool) {
        if !decode_only_middle && self.prev_decode_only_middle && self.channel_count == 2 {
            let side = &mut self.channels[SIDE_CHANNEL];
            side.out_buf = [0; OUT_BUF_LENGTH];
            side.lpc_state_q14 = [0; MAX_LPC_ORDER];
            side.lag_prev = LAG_PREV_RESET;
            side.last_gain_index = LAST_GAIN_INDEX_RESET;
            side.prev_signal_type = SignalType::Inactive;
            side.first_frame_after_reset = true;
        }
        self.prev_decode_only_middle = decode_only_middle;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::silk::types::MAX_NB_SUBFR;

    #[test]
    fn out_buf_length_matches_the_c_expression() {
        // outBuf[ MAX_FRAME_LENGTH + 2 * MAX_SUB_FRAME_LENGTH ] (structs.h:293).
        assert_eq!(OUT_BUF_LENGTH, 320 + 160);
    }

    #[test]
    fn fresh_channel_is_in_the_reset_state() {
        let channel = ChannelState::new();
        assert_eq!(channel.prev_gain_q16, 65536, "prev_gain_Q16 = 1.0 in Q16");
        assert!(channel.first_frame_after_reset);
        assert_eq!(channel.frames_decoded, 0);
        assert_eq!(channel.loss_count, 0);
        assert!(channel.excitation_q14.iter().all(|&x| x == 0));
        assert!(channel.out_buf.iter().all(|&x| x == 0));
        assert!(channel.lpc_state_q14.iter().all(|&x| x == 0));
        assert!(channel.prev_nlsf_q15.iter().all(|&x| x == 0));
        assert!(channel.vad_flags.iter().all(|&x| !x));
        assert!(channel.lbrr_flags.iter().all(|&x| !x));
        assert!(!channel.lbrr_flag);
        assert_eq!(channel.prev_signal_type, SignalType::Inactive);
        assert_eq!(channel.ec_prev_signal_type, SignalType::Inactive);
        // Not configured yet: the C's fs_kHz == 0.
        assert!(channel.internal_rate().is_err());
        assert!(channel.frame_length().is_err());
    }

    #[test]
    fn setting_the_rate_seeds_the_prediction_state() {
        let mut channel = ChannelState::new();
        let layout = SubframeLayout::from_duration_ms(20).expect("20 ms");
        channel.set_internal_rate(InternalRate::Wide16k, layout);
        // decoder_set_fs.c:91-96 seeds these three, and they are not zeros.
        assert_eq!(channel.lag_prev, 100);
        assert_eq!(channel.last_gain_index, 10);
        assert_eq!(channel.prev_signal_type, SignalType::Inactive);
        assert!(channel.first_frame_after_reset);
        assert_eq!(
            channel.internal_rate().expect("configured"),
            InternalRate::Wide16k
        );
        assert_eq!(channel.frame_length().expect("configured"), 320);
        assert_eq!(channel.subframe_length().expect("configured"), 80);
        assert_eq!(channel.ltp_memory_length().expect("configured"), 320);
        assert_eq!(channel.lpc_order().expect("configured"), 16);
        assert_eq!(channel.subframe_count(), MAX_NB_SUBFR);
        assert_eq!(channel.frames_per_packet(), 1);
    }

    #[test]
    fn changing_the_rate_clears_the_sample_history_but_a_layout_change_does_not() {
        let mut channel = ChannelState::new();
        let twenty = SubframeLayout::from_duration_ms(20).expect("20 ms");
        channel.set_internal_rate(InternalRate::Narrow8k, twenty);
        channel.out_buf[7] = 1234;
        channel.lpc_state_q14[3] = 5678;
        channel.last_gain_index = 42;
        channel.first_frame_after_reset = false;

        // Same rate, different layout: history survives (decoder_set_fs.c only clears on fs change).
        let sixty = SubframeLayout::from_duration_ms(60).expect("60 ms");
        channel.set_internal_rate(InternalRate::Narrow8k, sixty);
        assert_eq!(channel.out_buf[7], 1234);
        assert_eq!(channel.lpc_state_q14[3], 5678);
        assert_eq!(channel.last_gain_index, 42);
        assert!(!channel.first_frame_after_reset);
        assert_eq!(channel.frames_per_packet(), 3);

        // Rate change: cleared and re-seeded.
        channel.set_internal_rate(InternalRate::Wide16k, sixty);
        assert_eq!(channel.out_buf[7], 0);
        assert_eq!(channel.lpc_state_q14[3], 0);
        assert_eq!(channel.last_gain_index, 10);
        assert!(channel.first_frame_after_reset);
    }

    #[test]
    fn reset_clears_the_configured_rate_too() {
        let mut channel = ChannelState::new();
        let layout = SubframeLayout::from_duration_ms(20).expect("20 ms");
        channel.set_internal_rate(InternalRate::Wide16k, layout);
        channel.last_gain_index = 63;
        channel.reset();
        assert!(channel.internal_rate().is_err());
        assert_eq!(channel.last_gain_index, 0);
        assert_eq!(channel.prev_gain_q16, 65536);
    }

    /// The full `dec_API.c:342-354` decision table.
    #[test]
    fn cond_coding_decision_table() {
        // First frame of the packet: always independent, whatever else is true.
        assert_eq!(
            ChannelState::cond_coding(0, true, false),
            CondCoding::Independently
        );
        assert_eq!(
            ChannelState::cond_coding(0, true, true),
            CondCoding::Independently
        );
        // Previous frame of the same type not coded (an LBRR gap): independent.
        assert_eq!(
            ChannelState::cond_coding(1, false, false),
            CondCoding::Independently
        );
        // Previous frame available: conditional.
        assert_eq!(
            ChannelState::cond_coding(1, true, false),
            CondCoding::Conditionally
        );
        assert_eq!(
            ChannelState::cond_coding(2, true, false),
            CondCoding::Conditionally
        );
        // Side channel skipped a frame in this packet: independent, but no LTP scaling symbol.
        assert_eq!(
            ChannelState::cond_coding(1, true, true),
            CondCoding::IndependentlyNoLtpScaling
        );
    }

    #[test]
    fn decoder_rejects_out_of_range_api_parameters() {
        assert!(SilkDecoder::new(7_999, 1).is_err());
        assert!(SilkDecoder::new(48_001, 1).is_err());
        assert!(SilkDecoder::new(48_000, 0).is_err());
        assert!(SilkDecoder::new(48_000, 3).is_err());
        assert!(SilkDecoder::new(8_000, 1).is_ok());
        assert!(SilkDecoder::new(48_000, 2).is_ok());
    }

    #[test]
    fn configure_sets_both_channels_and_rejects_bad_input() {
        let mut decoder = SilkDecoder::new(48_000, 2).expect("decoder");
        assert!(decoder.configure(3, InternalRate::Wide16k, 20).is_err());
        assert!(decoder.configure(2, InternalRate::Wide16k, 33).is_err());

        decoder
            .configure(2, InternalRate::Medium12k, 40)
            .expect("configured");
        assert_eq!(decoder.channel_count(), 2);
        for index in [MID_CHANNEL, SIDE_CHANNEL] {
            let channel = decoder.channel(index).expect("channel");
            assert_eq!(
                channel.internal_rate().expect("configured"),
                InternalRate::Medium12k
            );
            assert_eq!(channel.frames_per_packet(), 2);
            assert_eq!(channel.frame_length().expect("configured"), 240);
        }
        assert!(decoder.channel(2).is_err());
    }

    #[test]
    fn mono_to_stereo_transition_resets_the_side_channel_and_stereo_memory() {
        let mut decoder = SilkDecoder::new(48_000, 2).expect("decoder");
        decoder
            .configure(1, InternalRate::Wide16k, 20)
            .expect("mono");
        // Dirty the side channel and the stereo memory as a stale mono decode would leave them.
        decoder.channel_mut(SIDE_CHANNEL).expect("side").out_buf[0] = 999;
        decoder.stereo_mut().pred_prev_q13 = [1234, -1234];
        decoder.stereo_mut().side_history = [5, 6];

        decoder
            .configure(2, InternalRate::Wide16k, 20)
            .expect("stereo");
        assert_eq!(
            decoder.channel(SIDE_CHANNEL).expect("side").out_buf[0],
            0,
            "side channel re-initialised (dec_API.c:173-175)"
        );
        assert_eq!(
            decoder.stereo().pred_prev_q13,
            [0, 0],
            "previous stereo weights zeroed on mono->stereo (RFC 6716 §4.2.7.1)"
        );
        assert_eq!(decoder.stereo().side_history, [0, 0]);
    }

    #[test]
    fn side_channel_returning_after_a_skip_drops_its_prediction_memory() {
        let mut decoder = SilkDecoder::new(48_000, 2).expect("decoder");
        decoder
            .configure(2, InternalRate::Wide16k, 20)
            .expect("stereo");
        let side = decoder.channel_mut(SIDE_CHANNEL).expect("side");
        side.out_buf[0] = 4242;
        side.lpc_state_q14[0] = 77;
        side.last_gain_index = 55;
        side.first_frame_after_reset = false;

        // Frame 1 was mid-only, frame 2 has a side channel again.
        decoder.set_decode_only_middle(true);
        assert!(decoder.prev_decode_only_middle());
        decoder.set_decode_only_middle(false);

        let side = decoder.channel(SIDE_CHANNEL).expect("side");
        assert_eq!(side.out_buf[0], 0);
        assert_eq!(side.lpc_state_q14[0], 0);
        assert_eq!(side.last_gain_index, 10);
        assert_eq!(side.lag_prev, 100);
        assert!(side.first_frame_after_reset);
        assert!(!decoder.prev_decode_only_middle());
    }

    #[test]
    fn consecutive_mid_only_frames_do_not_re_clear_the_side_channel() {
        let mut decoder = SilkDecoder::new(48_000, 2).expect("decoder");
        decoder
            .configure(2, InternalRate::Wide16k, 20)
            .expect("stereo");
        decoder.set_decode_only_middle(true);
        decoder.channel_mut(SIDE_CHANNEL).expect("side").out_buf[0] = 11;
        decoder.set_decode_only_middle(true);
        assert_eq!(decoder.channel(SIDE_CHANNEL).expect("side").out_buf[0], 11);
    }

    #[test]
    fn full_reset_returns_every_channel_to_the_fresh_state() {
        let mut decoder = SilkDecoder::new(16_000, 1).expect("decoder");
        decoder
            .configure(2, InternalRate::Narrow8k, 60)
            .expect("configured");
        decoder.channel_mut(MID_CHANNEL).expect("mid").out_buf[1] = 5;
        decoder.stereo_mut().pred_prev_q13 = [9, 9];
        decoder.set_decode_only_middle(true);

        decoder.reset();
        assert_eq!(decoder.channel(MID_CHANNEL).expect("mid").out_buf[1], 0);
        assert!(decoder
            .channel(MID_CHANNEL)
            .expect("mid")
            .internal_rate()
            .is_err());
        assert_eq!(decoder.stereo().pred_prev_q13, [0, 0]);
        assert!(!decoder.prev_decode_only_middle());
        // The API-side configuration is not part of the reset (the C keeps `fs_API_hz`).
        assert_eq!(decoder.api_rate_hz(), 16_000);
        assert_eq!(decoder.api_channel_count(), 1);
    }
}
