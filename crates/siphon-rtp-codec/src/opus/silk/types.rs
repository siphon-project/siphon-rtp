//! SILK constants and the small shared types every decode sub-phase needs.
//!
//! The constants are transcribed from libopus `silk/define.h`; the enums replace the C's bare
//! `opus_int8` side-info fields (`silk/structs.h` `SideInfoIndices`) so an illegal value cannot be
//! constructed in the first place.

use crate::opus::packet::Bandwidth;
use crate::CodecError;

/// Maximum 20 ms SILK frames in one Opus frame — 60 ms / 20 ms (`MAX_FRAMES_PER_PACKET`).
pub const MAX_FRAMES_PER_PACKET: usize = 3;
/// Maximum 5 ms subframes in one SILK frame (`MAX_NB_SUBFR`).
pub const MAX_NB_SUBFR: usize = 4;
/// Subframe duration in ms (`SUB_FRAME_LENGTH_MS`).
pub const SUB_FRAME_LENGTH_MS: usize = 5;
/// Highest SILK internal sample rate in kHz (`MAX_FS_KHZ`).
pub const MAX_FS_KHZ: usize = 16;
/// Longest 5 ms subframe in samples — 5 ms at 16 kHz (`MAX_SUB_FRAME_LENGTH`).
pub const MAX_SUB_FRAME_LENGTH: usize = SUB_FRAME_LENGTH_MS * MAX_FS_KHZ;
/// Longest SILK frame in samples — 20 ms at 16 kHz (`MAX_FRAME_LENGTH`).
pub const MAX_FRAME_LENGTH: usize = SUB_FRAME_LENGTH_MS * MAX_NB_SUBFR * MAX_FS_KHZ;
/// Long-term-prediction history kept before the current frame, in ms (`LTP_MEM_LENGTH_MS`).
pub const LTP_MEM_LENGTH_MS: usize = 20;
/// Short-term (LPC) predictor order for wideband (`MAX_LPC_ORDER`).
pub const MAX_LPC_ORDER: usize = 16;
/// Short-term (LPC) predictor order for narrow/mediumband (`MIN_LPC_ORDER`).
pub const MIN_LPC_ORDER: usize = 10;
/// Long-term (LTP) predictor order, taps per subframe (`LTP_ORDER`).
pub const LTP_ORDER: usize = 5;
/// Number of quantization-gain levels — the 6-bit log-gain index (`N_LEVELS_QGAIN`).
pub const N_LEVELS_QGAIN: i32 = 64;
/// dB level of the lowest quantization-gain level (`MIN_QGAIN_DB`).
pub const MIN_QGAIN_DB: i32 = 2;
/// dB level of the highest quantization-gain level (`MAX_QGAIN_DB`).
pub const MAX_QGAIN_DB: i32 = 88;
/// Largest delta-gain index step upward (`MAX_DELTA_GAIN_QUANT`).
pub const MAX_DELTA_GAIN_QUANT: i32 = 36;
/// Largest delta-gain index step downward (`MIN_DELTA_GAIN_QUANT`).
pub const MIN_DELTA_GAIN_QUANT: i32 = -4;
/// Stereo predictor quantization table length (`STEREO_QUANT_TAB_SIZE`).
pub const STEREO_QUANT_TAB_SIZE: usize = 16;
/// Stereo predictor interpolation sub-steps between two table entries (`STEREO_QUANT_SUB_STEPS`).
pub const STEREO_QUANT_SUB_STEPS: i32 = 5;

/// The SILK *internal* sample rate. SILK never decodes at the Opus API rate: it reconstructs at
/// 8, 12, or 16 kHz — chosen by the packet's audio bandwidth (`opus_decoder.c:398-412`) — and the
/// result is resampled to the API rate afterwards (RFC 6716 §4.2.9). The C carries this as
/// `silk_decoder_state.fs_kHz`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalRate {
    /// 8 kHz — narrowband (RFC 6716 §2: 4 kHz audio bandwidth).
    Narrow8k,
    /// 12 kHz — mediumband (6 kHz audio bandwidth). SILK-only; no CELT/hybrid config selects it.
    Medium12k,
    /// 16 kHz — wideband (8 kHz audio bandwidth), and the rate the SILK half of every Hybrid frame
    /// runs at regardless of the packet's (SWB/FB) bandwidth (`opus_decoder.c:409-412`).
    Wide16k,
}

impl InternalRate {
    /// Rate in kHz (`fs_kHz`) — 8, 12, or 16.
    #[must_use]
    pub fn khz(self) -> usize {
        match self {
            Self::Narrow8k => 8,
            Self::Medium12k => 12,
            Self::Wide16k => 16,
        }
    }

    /// Rate in Hz (`decControl->internalSampleRate`).
    #[must_use]
    pub fn hz(self) -> u32 {
        self.khz() as u32 * 1000
    }

    /// Short-term predictor order: 10 for NB/MB, 16 for WB (`decoder_set_fs.c:74-80`). This also
    /// selects which NLSF codebook the frame uses (`silk_NLSF_CB_NB_MB` vs `silk_NLSF_CB_WB`).
    #[must_use]
    pub fn lpc_order(self) -> usize {
        match self {
            Self::Narrow8k | Self::Medium12k => MIN_LPC_ORDER,
            Self::Wide16k => MAX_LPC_ORDER,
        }
    }

    /// LTP history length in samples — `LTP_MEM_LENGTH_MS * fs_kHz` (`decoder_set_fs.c:73`).
    #[must_use]
    pub fn ltp_memory_length(self) -> usize {
        LTP_MEM_LENGTH_MS * self.khz()
    }

    /// Subframe length in samples — `SUB_FRAME_LENGTH_MS * fs_kHz` (`decoder_set_fs.c:47`).
    #[must_use]
    pub fn subframe_length(self) -> usize {
        SUB_FRAME_LENGTH_MS * self.khz()
    }

    /// The internal rate an Opus packet's bandwidth selects (`opus_decoder.c:398-412`).
    ///
    /// SILK-only packets map NB→8, MB→12, WB→16 kHz. A Hybrid packet (SWB/FB) runs its SILK layer
    /// at 16 kHz, since CELT carries everything above 8 kHz.
    #[must_use]
    pub fn from_bandwidth(bandwidth: Bandwidth) -> Self {
        match bandwidth {
            Bandwidth::Narrowband => Self::Narrow8k,
            Bandwidth::Mediumband => Self::Medium12k,
            // Wideband, plus the SWB/FB hybrid configs whose SILK layer is always 16 kHz.
            Bandwidth::Wideband | Bandwidth::SuperWideband | Bandwidth::Fullband => Self::Wide16k,
        }
    }
}

/// How many 20 ms SILK frames an Opus frame carries, and how many 5 ms subframes each one has
/// (`dec_API.c:183-203`, driven by `decControl->payloadSize_ms`).
///
/// A 10 ms Opus frame is the only short case: one SILK frame of **two** subframes. Everything from
/// 20 ms up uses four subframes and simply repeats the SILK frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubframeLayout {
    /// `nFramesPerPacket` — 1, 2, or 3.
    pub frames_per_packet: usize,
    /// `nb_subfr` — 2 (10 ms only) or 4.
    pub subframe_count: usize,
}

impl SubframeLayout {
    /// Layout for an Opus frame duration in ms (`dec_API.c:183-203`). Only 10/20/40/60 ms exist for
    /// SILK (RFC 6716 §3.1, Table 2); anything else is rejected, as `SILK_DEC_INVALID_FRAME_SIZE` is
    /// in the C.
    pub fn from_duration_ms(duration_ms: usize) -> Result<Self, CodecError> {
        match duration_ms {
            10 => Ok(Self {
                frames_per_packet: 1,
                subframe_count: 2,
            }),
            20 => Ok(Self {
                frames_per_packet: 1,
                subframe_count: 4,
            }),
            40 => Ok(Self {
                frames_per_packet: 2,
                subframe_count: 4,
            }),
            60 => Ok(Self {
                frames_per_packet: 3,
                subframe_count: 4,
            }),
            _ => Err(CodecError::Unsupported(
                "silk: frame duration must be 10, 20, 40 or 60 ms",
            )),
        }
    }

    /// SILK frame length in samples — `nb_subfr * subfr_length` (`decoder_set_fs.c:48`).
    #[must_use]
    pub fn frame_length(&self, rate: InternalRate) -> usize {
        self.subframe_count * rate.subframe_length()
    }
}

/// Which of the three conditional-coding regimes the current SILK frame uses (`define.h:74-77`).
///
/// It decides whether the first subframe gain is coded absolutely or as a delta (§4.2.7.4), whether
/// the pitch lag is delta-coded against the previous frame (§4.2.7.6.1), and whether an LTP scaling
/// factor is present at all (§4.2.7.6.3). The caller derives it from position in the packet
/// (`dec_API.c:342-354`), never from the bitstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CondCoding {
    /// `CODE_INDEPENDENTLY` — no usable previous frame: absolute gain, absolute lag, LTP scaling
    /// coded.
    Independently,
    /// `CODE_INDEPENDENTLY_NO_LTP_SCALING` — as above, but the LTP state is already well-defined
    /// (the side channel skipped a frame in this same packet), so no LTP scaling symbol is coded.
    IndependentlyNoLtpScaling,
    /// `CODE_CONDITIONALLY` — the previous SILK frame of the same type in this Opus frame is
    /// available: delta gain, possibly delta lag, no LTP scaling symbol.
    Conditionally,
}

impl CondCoding {
    /// True when the first subframe gain is delta-coded — the C passes
    /// `condCoding == CODE_CONDITIONALLY` as `silk_gains_dequant`'s `conditional` argument
    /// (`decode_parameters.c:46-47`).
    #[must_use]
    pub fn is_conditional(self) -> bool {
        matches!(self, Self::Conditionally)
    }
}

/// Signal type of a SILK frame (`define.h:70-72`; RFC 6716 Table 10). Selects the gain MSB PDF
/// (§4.2.7.4), the NLSF stage-1 PDF (§4.2.7.5.1), and whether pitch/LTP parameters are coded at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalType {
    /// `TYPE_NO_VOICE_ACTIVITY` — an inactive frame (its VAD flag was clear).
    Inactive,
    /// `TYPE_UNVOICED`.
    Unvoiced,
    /// `TYPE_VOICED` — the only type that carries pitch lags and LTP filter coefficients.
    Voiced,
}

impl SignalType {
    /// The C's `opus_int8 signalType` value, 0..=2 — the index into the per-signal-type tables.
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            Self::Inactive => 0,
            Self::Unvoiced => 1,
            Self::Voiced => 2,
        }
    }
}

/// Quantization offset type of a SILK frame (`define.h:129-133`; RFC 6716 Table 10). Picks the
/// constant added to every reconstructed excitation sample (§4.2.7.8.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantOffsetType {
    /// `low` — `OFFSET_UVL_Q10` / `OFFSET_VL_Q10`.
    Low,
    /// `high` — `OFFSET_UVH_Q10` / `OFFSET_VH_Q10`.
    High,
}

impl QuantOffsetType {
    /// The excitation quantization offset in Q10 (libopus `silk_Quantization_Offsets_Q10`,
    /// `tables_other.c:81-83`, indexed `[signalType >> 1][quantOffsetType]`).
    ///
    /// Note the C's `signalType >> 1`: inactive (0) and unvoiced (1) share the *unvoiced* row, and
    /// only voiced (2) selects the second row. RFC 6716 §4.2.7.8.6 Table 53 lists the same four
    /// values keyed on "inactive or unvoiced" vs "voiced".
    #[must_use]
    pub fn offset_q10(self, signal_type: SignalType) -> i16 {
        /// `{ { OFFSET_UVL_Q10, OFFSET_UVH_Q10 }, { OFFSET_VL_Q10, OFFSET_VH_Q10 } }`.
        const OFFSETS_Q10: [[i16; 2]; 2] = [[100, 240], [32, 100]];
        let row = signal_type.index() >> 1;
        let column = match self {
            Self::Low => 0,
            Self::High => 1,
        };
        OFFSETS_Q10[row][column]
    }
}

/// The joint "frame type" symbol (RFC 6716 §4.2.7.3, Table 10) that codes the signal type and the
/// quantization offset type together as one value 0..=5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameType {
    /// The raw symbol, 0..=5 — `Ix` in `decode_indices.c:52-57`.
    symbol: u8,
}

impl FrameType {
    /// Build from the raw joint symbol (RFC 6716 Table 10). Rejects anything above 5.
    pub fn from_symbol(symbol: u8) -> Result<Self, CodecError> {
        if symbol > 5 {
            return Err(CodecError::Malformed(
                "silk: frame type symbol out of range",
            ));
        }
        Ok(Self { symbol })
    }

    /// The raw joint symbol, 0..=5.
    #[must_use]
    pub fn symbol(self) -> u8 {
        self.symbol
    }

    /// Signal type — `silk_RSHIFT(Ix, 1)` (`decode_indices.c:56`).
    #[must_use]
    pub fn signal_type(self) -> SignalType {
        match self.symbol >> 1 {
            0 => SignalType::Inactive,
            1 => SignalType::Unvoiced,
            // `from_symbol` caps the symbol at 5, so `symbol >> 1` is 0..=2.
            _ => SignalType::Voiced,
        }
    }

    /// Quantization offset type — `Ix & 1` (`decode_indices.c:57`).
    #[must_use]
    pub fn quant_offset_type(self) -> QuantOffsetType {
        if self.symbol & 1 == 0 {
            QuantOffsetType::Low
        } else {
            QuantOffsetType::High
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_lengths_match_the_c_derivation() {
        // MAX_FRAME_LENGTH = SUB_FRAME_LENGTH_MS * MAX_NB_SUBFR * MAX_FS_KHZ (define.h:96-97).
        assert_eq!(MAX_FRAME_LENGTH, 320);
        assert_eq!(MAX_SUB_FRAME_LENGTH, 80);
        assert_eq!(MAX_FRAME_LENGTH, MAX_NB_SUBFR * MAX_SUB_FRAME_LENGTH);
    }

    #[test]
    fn internal_rate_derived_quantities() {
        for (rate, khz, order, ltp, subfr) in [
            (InternalRate::Narrow8k, 8, 10, 160, 40),
            (InternalRate::Medium12k, 12, 10, 240, 60),
            (InternalRate::Wide16k, 16, 16, 320, 80),
        ] {
            assert_eq!(rate.khz(), khz);
            assert_eq!(rate.hz(), khz as u32 * 1000);
            assert_eq!(rate.lpc_order(), order);
            assert_eq!(rate.ltp_memory_length(), ltp);
            assert_eq!(rate.subframe_length(), subfr);
        }
        // The longest subframe/frame really are the 16 kHz ones, i.e. the buffer bounds hold.
        assert_eq!(
            InternalRate::Wide16k.subframe_length(),
            MAX_SUB_FRAME_LENGTH
        );
        assert_eq!(InternalRate::Wide16k.ltp_memory_length(), MAX_FRAME_LENGTH);
    }

    #[test]
    fn internal_rate_from_bandwidth_matches_opus_decoder() {
        assert_eq!(
            InternalRate::from_bandwidth(Bandwidth::Narrowband),
            InternalRate::Narrow8k
        );
        assert_eq!(
            InternalRate::from_bandwidth(Bandwidth::Mediumband),
            InternalRate::Medium12k
        );
        assert_eq!(
            InternalRate::from_bandwidth(Bandwidth::Wideband),
            InternalRate::Wide16k
        );
        // Hybrid: SILK always runs at 16 kHz (opus_decoder.c:409-412).
        assert_eq!(
            InternalRate::from_bandwidth(Bandwidth::SuperWideband),
            InternalRate::Wide16k
        );
        assert_eq!(
            InternalRate::from_bandwidth(Bandwidth::Fullband),
            InternalRate::Wide16k
        );
    }

    #[test]
    fn subframe_layout_matches_payload_size_table() {
        let ten = SubframeLayout::from_duration_ms(10).expect("10 ms");
        assert_eq!((ten.frames_per_packet, ten.subframe_count), (1, 2));
        let twenty = SubframeLayout::from_duration_ms(20).expect("20 ms");
        assert_eq!((twenty.frames_per_packet, twenty.subframe_count), (1, 4));
        let forty = SubframeLayout::from_duration_ms(40).expect("40 ms");
        assert_eq!((forty.frames_per_packet, forty.subframe_count), (2, 4));
        let sixty = SubframeLayout::from_duration_ms(60).expect("60 ms");
        assert_eq!((sixty.frames_per_packet, sixty.subframe_count), (3, 4));
    }

    #[test]
    fn subframe_layout_rejects_non_silk_durations() {
        for bad in [0usize, 1, 5, 15, 25, 30, 80, 120] {
            assert!(
                SubframeLayout::from_duration_ms(bad).is_err(),
                "{bad} ms must be rejected"
            );
        }
    }

    #[test]
    fn subframe_layout_frame_lengths() {
        let ten = SubframeLayout::from_duration_ms(10).expect("10 ms");
        // 10 ms at 16 kHz = 160 samples, and 2 subframes of 5 ms.
        assert_eq!(ten.frame_length(InternalRate::Wide16k), 160);
        assert_eq!(ten.frame_length(InternalRate::Narrow8k), 80);
        let twenty = SubframeLayout::from_duration_ms(20).expect("20 ms");
        assert_eq!(twenty.frame_length(InternalRate::Wide16k), MAX_FRAME_LENGTH);
        assert_eq!(twenty.frame_length(InternalRate::Medium12k), 240);
    }

    /// RFC 6716 Table 10 in full: the joint symbol splits into signal type and offset type.
    #[test]
    fn frame_type_table_10() {
        let expected = [
            (0u8, SignalType::Inactive, QuantOffsetType::Low),
            (1, SignalType::Inactive, QuantOffsetType::High),
            (2, SignalType::Unvoiced, QuantOffsetType::Low),
            (3, SignalType::Unvoiced, QuantOffsetType::High),
            (4, SignalType::Voiced, QuantOffsetType::Low),
            (5, SignalType::Voiced, QuantOffsetType::High),
        ];
        for (symbol, signal, offset) in expected {
            let frame_type = FrameType::from_symbol(symbol).expect("valid symbol");
            assert_eq!(frame_type.symbol(), symbol);
            assert_eq!(frame_type.signal_type(), signal, "symbol {symbol}");
            assert_eq!(frame_type.quant_offset_type(), offset, "symbol {symbol}");
        }
    }

    #[test]
    fn frame_type_rejects_out_of_range_symbols() {
        for bad in [6u8, 7, 8, 255] {
            assert!(FrameType::from_symbol(bad).is_err(), "symbol {bad}");
        }
    }

    #[test]
    fn signal_type_indices_match_the_c_enum() {
        assert_eq!(SignalType::Inactive.index(), 0);
        assert_eq!(SignalType::Unvoiced.index(), 1);
        assert_eq!(SignalType::Voiced.index(), 2);
    }

    /// `silk_Quantization_Offsets_Q10` verbatim, including the `signalType >> 1` row fold.
    #[test]
    fn quantization_offsets_q10() {
        // Row 0 (inactive *and* unvoiced): { OFFSET_UVL_Q10 = 100, OFFSET_UVH_Q10 = 240 }.
        for signal in [SignalType::Inactive, SignalType::Unvoiced] {
            assert_eq!(QuantOffsetType::Low.offset_q10(signal), 100);
            assert_eq!(QuantOffsetType::High.offset_q10(signal), 240);
        }
        // Row 1 (voiced): { OFFSET_VL_Q10 = 32, OFFSET_VH_Q10 = 100 }.
        assert_eq!(QuantOffsetType::Low.offset_q10(SignalType::Voiced), 32);
        assert_eq!(QuantOffsetType::High.offset_q10(SignalType::Voiced), 100);
    }

    #[test]
    fn cond_coding_conditional_predicate() {
        assert!(CondCoding::Conditionally.is_conditional());
        assert!(!CondCoding::Independently.is_conditional());
        assert!(!CondCoding::IndependentlyNoLtpScaling.is_conditional());
    }
}
