//! AMR-NB (3GPP TS 26.071, RTP RFC 4867) and AMR-WB (TS 26.171) — the VoLTE codecs.
//!
//! This module currently provides the **foundation**: the fixed-point [`basic_ops`], the mode
//! tables (bit/byte sizes, frame-type mapping), and RFC 4867 payload framing. The ACELP
//! encode/decode DSP is the multi-week bit-exact effort tracked separately; until it lands the
//! [`AmrNb`]/[`AmrWb`] codecs return [`CodecError::Unsupported`] rather than panicking.

pub mod basic_ops;
pub mod math_op;
pub mod nb;
pub mod oper_32b;
pub mod payload;
pub mod wb;

use crate::{CodecError, CodecParams, Decoder, Encoder};

/// AMR-NB speech frame sizes in bits, indexed by frame type (0..=7). RFC 4867 Table 1.
pub const AMRNB_SPEECH_BITS: [u16; 8] = [95, 103, 118, 134, 148, 159, 204, 244];
/// AMR-NB SID (comfort-noise) frame size in bits (frame type 8).
pub const AMRNB_SID_BITS: u16 = 39;

/// AMR-WB speech frame sizes in bits, indexed by frame type (0..=8). RFC 4867 Table 1a.
pub const AMRWB_SPEECH_BITS: [u16; 9] = [132, 177, 253, 285, 317, 365, 397, 461, 477];
/// AMR-WB SID (comfort-noise) frame size in bits (frame type 9).
pub const AMRWB_SID_BITS: u16 = 40;

#[inline]
const fn bits_to_bytes(bits: u16) -> usize {
    (bits as usize).div_ceil(8)
}

/// AMR-NB bitrate modes. The discriminant is the RFC 4867 frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AmrNbMode {
    /// 4.75 kbit/s
    Mr475 = 0,
    /// 5.15 kbit/s
    Mr515 = 1,
    /// 5.90 kbit/s
    Mr590 = 2,
    /// 6.70 kbit/s
    Mr670 = 3,
    /// 7.40 kbit/s
    Mr740 = 4,
    /// 7.95 kbit/s
    Mr795 = 5,
    /// 10.2 kbit/s
    Mr1020 = 6,
    /// 12.2 kbit/s (GSM-EFR)
    Mr1220 = 7,
}

impl AmrNbMode {
    /// The RFC 4867 frame type (0..=7).
    #[must_use]
    pub const fn frame_type(self) -> u8 {
        self as u8
    }

    /// Speech frame size in bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        AMRNB_SPEECH_BITS[self as usize]
    }

    /// Speech frame size in bytes (octet-aligned).
    #[must_use]
    pub const fn bytes(self) -> usize {
        bits_to_bytes(self.bits())
    }

    /// Map an RFC 4867 frame type to a speech mode (None for SID/reserved/no-data).
    #[must_use]
    pub const fn from_frame_type(frame_type: u8) -> Option<Self> {
        match frame_type {
            0 => Some(Self::Mr475),
            1 => Some(Self::Mr515),
            2 => Some(Self::Mr590),
            3 => Some(Self::Mr670),
            4 => Some(Self::Mr740),
            5 => Some(Self::Mr795),
            6 => Some(Self::Mr1020),
            7 => Some(Self::Mr1220),
            _ => None,
        }
    }
}

/// AMR-WB bitrate modes. The discriminant is the RFC 4867 frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AmrWbMode {
    /// 6.60 kbit/s
    Mr660 = 0,
    /// 8.85 kbit/s
    Mr885 = 1,
    /// 12.65 kbit/s
    Mr1265 = 2,
    /// 14.25 kbit/s
    Mr1425 = 3,
    /// 15.85 kbit/s
    Mr1585 = 4,
    /// 18.25 kbit/s
    Mr1825 = 5,
    /// 19.85 kbit/s
    Mr1985 = 6,
    /// 23.05 kbit/s
    Mr2305 = 7,
    /// 23.85 kbit/s
    Mr2385 = 8,
}

impl AmrWbMode {
    /// The RFC 4867 frame type (0..=8).
    #[must_use]
    pub const fn frame_type(self) -> u8 {
        self as u8
    }

    /// Speech frame size in bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        AMRWB_SPEECH_BITS[self as usize]
    }

    /// Speech frame size in bytes (octet-aligned).
    #[must_use]
    pub const fn bytes(self) -> usize {
        bits_to_bytes(self.bits())
    }

    /// Map an RFC 4867 frame type to a speech mode (None for SID/reserved/no-data).
    #[must_use]
    pub const fn from_frame_type(frame_type: u8) -> Option<Self> {
        match frame_type {
            0 => Some(Self::Mr660),
            1 => Some(Self::Mr885),
            2 => Some(Self::Mr1265),
            3 => Some(Self::Mr1425),
            4 => Some(Self::Mr1585),
            5 => Some(Self::Mr1825),
            6 => Some(Self::Mr1985),
            7 => Some(Self::Mr2305),
            8 => Some(Self::Mr2385),
            _ => None,
        }
    }
}

/// One RFC 4867 Table-of-Contents entry (octet-aligned form).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Toc {
    /// Follow bit: another ToC entry follows this one.
    pub follow: bool,
    /// Frame type index (mode, SID, or no-data marker).
    pub frame_type: u8,
    /// Quality bit: frame is not damaged.
    pub quality_ok: bool,
}

impl Toc {
    /// Parse a ToC byte (octet-aligned): `F(1) | FT(4) | Q(1) | padding(2)`.
    #[must_use]
    pub const fn from_octet(byte: u8) -> Self {
        Self {
            follow: byte & 0x80 != 0,
            frame_type: (byte >> 3) & 0x0F,
            quality_ok: byte & 0x04 != 0,
        }
    }

    /// Serialize to a ToC byte (octet-aligned).
    #[must_use]
    pub const fn to_octet(self) -> u8 {
        ((self.follow as u8) << 7)
            | ((self.frame_type & 0x0F) << 3)
            | ((self.quality_ok as u8) << 2)
    }
}

/// A parsed RFC 4867 octet-aligned payload header: requested mode + ToC list + frame-data offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OctetAlignedHeader {
    /// Codec Mode Request (top nibble of the first byte).
    pub cmr: u8,
    /// Table-of-contents entries, one per speech frame in the payload.
    pub entries: Vec<Toc>,
    /// Byte offset at which speech-frame data begins.
    pub data_offset: usize,
}

/// Parse the header of an octet-aligned AMR (RFC 4867 §4.4.2) RTP payload.
///
/// Returns the CMR, the ToC list, and the offset to the first frame's data. The
/// bandwidth-efficient mode (bit-packed) is a separate parser, not yet implemented.
pub fn parse_octet_aligned(payload: &[u8]) -> Result<OctetAlignedHeader, CodecError> {
    if payload.is_empty() {
        return Err(CodecError::Malformed("empty AMR payload"));
    }
    let cmr = payload[0] >> 4;
    let mut entries = Vec::new();
    let mut index = 1;
    loop {
        let byte = *payload
            .get(index)
            .ok_or(CodecError::Malformed("truncated AMR ToC"))?;
        index += 1;
        let toc = Toc::from_octet(byte);
        let follow = toc.follow;
        entries.push(toc);
        if !follow {
            break;
        }
    }
    Ok(OctetAlignedHeader {
        cmr,
        entries,
        data_offset: index,
    })
}

/// AMR-NB codec (8 kHz, mono, 20 ms = 160 samples).
///
/// Decode is wired for **all 8 speech modes** (4.75 .. 12.2 kbit/s) end to end, bit-exact against
/// the 3GPP TS 26.074 `T_<mode>` vectors. DTX/CNG and error-concealment (the bad-frame branch) are
/// not yet implemented; [`Decoder::conceal`] therefore returns [`CodecError::Unsupported`]. The
/// encoder is a separate, later tier.
#[derive(Debug, Clone)]
pub struct AmrNb {
    params: CodecParams,
    decoder: Box<nb::dec_main::SpeechDecoder>,
    encoder: Box<nb::enc_main::EncoderState>,
    /// Target speech mode for [`Encoder::encode`]. Defaults to MR122 (12.2 kbit/s, GSM-EFR — the
    /// highest-quality wired mode). Only MR122 and MR475 are wired; other modes return
    /// [`CodecError::Unsupported`]. Set via [`AmrNb::with_encode_mode`].
    encode_mode: AmrNbMode,
}

impl Default for AmrNb {
    fn default() -> Self {
        Self::new()
    }
}

impl AmrNb {
    /// Create an AMR-NB codec at the canonical 8 kHz / 20 ms configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            params: CodecParams {
                sample_rate_hz: 8000,
                channels: 1,
                ptime_ms: 20,
            },
            decoder: Box::new(nb::dec_main::SpeechDecoder::new()),
            encoder: Box::new(nb::enc_main::EncoderState::new()),
            encode_mode: AmrNbMode::Mr1220,
        }
    }

    /// Set the target speech mode for [`Encoder::encode`] (e.g. from the SDP `mode-set` / RFC 4867
    /// CMR). Only MR122 and MR475 are wired; other modes make [`Encoder::encode`] return
    /// [`CodecError::Unsupported`].
    #[must_use]
    pub fn with_encode_mode(mut self, mode: AmrNbMode) -> Self {
        self.encode_mode = mode;
        self
    }

    /// Encode one 20 ms frame (160 samples @ 8 kHz) at `mode` into its serial speech bits in
    /// encoder/`Prm2bits` order (the `.COD` order, `0`/`1` per word), writing
    /// [`AmrNbMode::bits`]`(mode)` words to `out_bits`. This is the bit-exact core used by the
    /// vector tests; the RTP [`Encoder::encode`] path re-sorts these into RFC 4867 payload order.
    /// The 13-bit input mask, pre-processing and encoder homing are applied internally.
    pub fn encode_mode_bits(
        &mut self,
        mode: AmrNbMode,
        pcm: &[i16],
        out_bits: &mut [i16],
    ) -> Result<usize, CodecError> {
        if pcm.len() < nb::constants::L_FRAME {
            return Err(CodecError::Malformed("AMR-NB input frame too small"));
        }
        let nb_bits = mode.bits() as usize;
        if out_bits.len() < nb_bits {
            return Err(CodecError::Malformed("AMR-NB output bit buffer too small"));
        }
        let mut prm = [0i16; nb::bitstream::MAX_PRM_SIZE];
        let nprm = self.encoder.encode_frame(mode, pcm, &mut prm)?;
        nb::bitstream::prm2bits(mode.frame_type() as usize, &prm[..nprm], &mut out_bits[..nb_bits]);
        Ok(nb_bits)
    }

    /// Decode one speech frame of `mode` (0..=7) from its serial speech bits already in
    /// encoder/`Bits2prm` order (the `.COD` order, `0`/`1` per word). Writes [`nb::constants::L_FRAME`]
    /// (160) samples to `out`. This is the bit-exact core used by the vector tests; the RTP
    /// [`Decoder::decode`] path un-sorts the RFC 4867 payload before calling into the same core.
    pub fn decode_mode_bits(
        &mut self,
        mode: usize,
        bits: &[i16],
        out: &mut [i16],
    ) -> Result<usize, CodecError> {
        if mode > 7 {
            return Err(CodecError::Unsupported("AMR-NB mode out of range"));
        }
        if out.len() < nb::constants::L_FRAME {
            return Err(CodecError::Malformed("AMR-NB output buffer too small"));
        }
        self.decoder.decode_frame(mode, bits, out);
        Ok(nb::constants::L_FRAME)
    }

    /// The codec's native parameters (inherent shortcut; the trait methods also expose this).
    #[must_use]
    pub fn params(&self) -> CodecParams {
        self.params
    }

    /// Samples in one packetization interval.
    #[must_use]
    pub fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }
}

impl Decoder for AmrNb {
    fn params(&self) -> CodecParams {
        self.params
    }
    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }

    /// Decode one AMR-NB RTP frame. All 8 speech modes (0..=7) are wired bit-exact; the payload's
    /// first frame is un-sorted from RFC 4867 order to encoder order before the core decode.
    /// SID/no-data frames are not yet supported (DTX/CNG is a separate tier).
    fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
        // Default to octet-aligned framing (the common VoLTE posture); fall back to
        // bandwidth-efficient if that does not parse cleanly.
        let parsed = payload::AmrPayload::parse_amr_nb(payload, true)
            .or_else(|_| payload::AmrPayload::parse_amr_nb(payload, false))?;
        let frame = parsed
            .frames
            .first()
            .ok_or(CodecError::Malformed("AMR-NB payload has no frames"))?;
        match frame.frame_type {
            mode @ 0..=7 => {
                let nb_mode = AmrNbMode::from_frame_type(mode)
                    .ok_or(CodecError::Unsupported("AMR-NB invalid speech mode"))?;
                if frame.data.len() < nb_mode.bytes() {
                    return Err(CodecError::Malformed("AMR-NB speech frame truncated"));
                }
                let bits = nb::bitstream::unsort(&frame.data, mode as usize);
                self.decode_mode_bits(mode as usize, &bits, out)
            }
            _ => Err(CodecError::Unsupported(
                "AMR-NB SID/no-data decode not yet implemented",
            )),
        }
    }
    fn conceal(&mut self, _out: &mut [i16]) -> Result<usize, CodecError> {
        Err(CodecError::Unsupported("AMR-NB PLC not yet implemented"))
    }
}

impl Encoder for AmrNb {
    fn params(&self) -> CodecParams {
        self.params
    }
    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }
    /// Encode one 20 ms frame (160 samples @ 8 kHz) into an RFC 4867 **octet-aligned** single-frame
    /// AMR-NB payload at the configured [`AmrNb::with_encode_mode`] mode (default MR122 / 12.2 kbit/s):
    /// the bit-exact core ([`AmrNb::encode_mode_bits`]) → RFC 4867 sort/pack → `CMR | ToC | speech`.
    /// CMR = 15 (no mode request); ToC = `F=0, FT=mode, Q=1` (RFC 4867 §4.3.2 / §4.4).
    fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, CodecError> {
        let mode = self.encode_mode;
        let nb_bits = mode.bits() as usize;
        let mut bits = [0i16; 244]; // max AMR-NB serial size (MR122)
        self.encode_mode_bits(mode, pcm, &mut bits[..nb_bits])?;
        let speech = nb::bitstream::pack(&bits, mode.frame_type() as usize);
        // Octet-aligned single-frame payload: CMR byte + ToC byte + speech bytes.
        let total = 2 + speech.len();
        if out.len() < total {
            return Err(CodecError::OutputTooSmall {
                needed: total,
                have: out.len(),
            });
        }
        out[0] = 0xF0; // CMR = 15 (no codec-mode request), low 4 bits reserved = 0
        out[1] = (mode.frame_type() << 3) | 0x04; // F=0 (last frame), FT=mode, Q=1 (good)
        out[2..total].copy_from_slice(&speech);
        Ok(total)
    }
}

/// AMR-WB codec (16 kHz, mono, 20 ms = 320 samples).
///
/// Decode is wired for **all 9 speech modes** (6.60 .. 23.85 kbit/s) end to end, bit-exact against
/// the 3GPP `tst_mN` vectors, plus bad-frame concealment ([`Decoder::conceal`]). DTX/CNG (comfort
/// noise) remains WIP and returns [`CodecError::Unsupported`].
#[derive(Debug, Clone)]
pub struct AmrWb {
    params: CodecParams,
    decoder_state: Box<wb::dec_main::DecoderState>,
    encoder_state: Box<wb::enc_main::EncoderState>,
    /// Last decoded speech mode (0..=8), used to size concealed frames after a loss.
    last_mode: u8,
    /// Target speech mode for [`Encoder::encode`] (0..=8). Defaults to 2 (12.65 kbit/s) — the common
    /// VoLTE rate. Per-call selection (SDP `mode-set` / RFC 4867 CMR) is set via
    /// [`AmrWb::with_encode_mode`]; per-frame CMR adaptation is a follow-up.
    encode_mode: u8,
}

impl Default for AmrWb {
    fn default() -> Self {
        Self::new()
    }
}

impl AmrWb {
    /// Create an AMR-WB codec at the canonical 16 kHz / 20 ms configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            params: CodecParams {
                sample_rate_hz: 16000,
                channels: 1,
                ptime_ms: 20,
            },
            decoder_state: Box::new(wb::dec_main::DecoderState::new()),
            encoder_state: Box::new(wb::enc_main::EncoderState::new()),
            last_mode: 0,
            encode_mode: 2,
        }
    }

    /// Set the target speech mode (0..=8) for [`Encoder::encode`] (e.g. from the SDP `mode-set`).
    /// Out-of-range values are clamped to mode 8.
    #[must_use]
    pub fn with_encode_mode(mut self, mode: u8) -> Self {
        self.encode_mode = mode.min(8);
        self
    }

    /// Encode one 20 ms frame (320 samples @ 16 kHz) at `mode` (0..=8) into its speech bits in
    /// encoder/`Prm2bits` order (the `.cod` order), writing `AMRWB_SPEECH_BITS[mode]` `±127` words to
    /// `out_bits`. This is the bit-exact core used by the `tst_mN` acceptance tests; the RTP
    /// [`Encoder::encode`] path re-sorts these into RFC 4867 payload order.
    ///
    /// Mirrors the reference `coder()`'s input conditioning: the encoder homing detection is the
    /// caller's responsibility; the two LSBs of each input sample are masked (`signal & 0xfffC`,
    /// 14-bit input) before analysis, exactly as `cod_main.c` does.
    pub fn encode_mode_bits(
        &mut self,
        mode: u8,
        pcm: &[i16],
        out_bits: &mut [i16],
    ) -> Result<usize, CodecError> {
        if mode > 8 {
            return Err(CodecError::Unsupported("AMR-WB mode out of range"));
        }
        if pcm.len() < wb::constants::L_FRAME16K {
            return Err(CodecError::Malformed("AMR-WB input frame too small"));
        }
        let nb_bits = AmrWbMode::from_frame_type(mode)
            .ok_or(CodecError::Unsupported("AMR-WB invalid speech mode"))?
            .bits() as usize;
        if out_bits.len() < nb_bits {
            return Err(CodecError::Malformed("AMR-WB output bit buffer too small"));
        }
        // Encoder homing detection runs on the *raw* input (cod_main.c, before the LSB delete).
        let reset_flag = wb::enc_main::encoder_homing_frame_test(pcm);
        // 14-bit input: delete the 2 LSBs (cod_main.c).
        let mut signal = [0i16; wb::constants::L_FRAME16K];
        for (dst, &src) in signal.iter_mut().zip(pcm.iter()) {
            *dst = src & 0xFFFCu16 as i16;
        }
        let written = wb::enc_main::coder(&mut self.encoder_state, mode, &signal, out_bits);
        // A homing frame fully resets the encoder *after* it is coded (cod_main.c
        // `if (reset_flag) Reset_encoder(st, 1)`).
        if reset_flag {
            *self.encoder_state = wb::enc_main::EncoderState::new();
        }
        Ok(written)
    }

    /// Decode one speech frame of `mode` (0..=8) from its speech bits already in encoder/`Bits2prm`
    /// order (the `.cod` order). Writes `L_FRAME16K` (320) samples to `out`.
    ///
    /// This is the bit-exact core used by the `tst_mN` acceptance tests; the RTP [`Decoder::decode`]
    /// path un-sorts the RFC 4867 payload before calling into the same core.
    pub fn decode_mode_bits(
        &mut self,
        mode: u8,
        bits: &[i16],
        out: &mut [i16],
    ) -> Result<usize, CodecError> {
        if mode > 8 {
            return Err(CodecError::Unsupported("AMR-WB mode out of range"));
        }
        if out.len() < wb::constants::L_FRAME16K {
            return Err(CodecError::Malformed("AMR-WB output buffer too small"));
        }
        self.last_mode = mode;
        Ok(wb::dec_main::decode_frame(
            &mut self.decoder_state,
            mode,
            bits,
            out,
        ))
    }

    /// Decode one mode-0 (6.60 kbit/s) frame from its 132 encoder-order speech bits (compat shim for
    /// [`Self::decode_mode_bits`] with `mode = 0`).
    pub fn decode_mode0_bits(
        &mut self,
        bits: &[i16],
        out: &mut [i16],
    ) -> Result<usize, CodecError> {
        self.decode_mode_bits(0, bits, out)
    }

    /// The codec's native parameters (inherent shortcut; the trait methods also expose this).
    #[must_use]
    pub fn params(&self) -> CodecParams {
        self.params
    }

    /// Samples in one packetization interval.
    #[must_use]
    pub fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }
}

impl Decoder for AmrWb {
    fn params(&self) -> CodecParams {
        self.params
    }
    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }

    /// Decode one AMR-WB RTP frame. All 9 speech modes (0..=8) are wired bit-exact; the payload's
    /// first frame is un-sorted from RFC 4867 order to encoder order before the core decode.
    /// SID/no-data frames are not yet supported (DTX/CNG is a separate tier).
    fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
        // Default to octet-aligned framing (the common VoLTE posture); fall back to
        // bandwidth-efficient if that does not parse cleanly.
        let parsed = payload::AmrPayload::parse_amr_wb(payload, true)
            .or_else(|_| payload::AmrPayload::parse_amr_wb(payload, false))?;
        let frame = parsed
            .frames
            .first()
            .ok_or(CodecError::Malformed("AMR-WB payload has no frames"))?;
        match frame.frame_type {
            mode @ 0..=8 => {
                let wb_mode = AmrWbMode::from_frame_type(mode)
                    .ok_or(CodecError::Unsupported("AMR-WB invalid speech mode"))?;
                if frame.data.len() < wb_mode.bytes() {
                    return Err(CodecError::Malformed("AMR-WB speech frame truncated"));
                }
                let bits = wb::bitstream::unsort(&frame.data, mode);
                self.decode_mode_bits(mode, &bits, out)
            }
            _ => Err(CodecError::Unsupported(
                "AMR-WB SID/no-data decode not yet implemented",
            )),
        }
    }

    /// Conceal one lost/erased AMR-WB frame (bad-frame branch of `dec_main.c`): lag/gain/ISF
    /// extrapolation and energy fade, producing a faded continuation of the last decoded mode.
    /// Writes `L_FRAME16K` (320) samples. Never panics, never emits guessed bitstream audio.
    fn conceal(&mut self, out: &mut [i16]) -> Result<usize, CodecError> {
        if out.len() < wb::constants::L_FRAME16K {
            return Err(CodecError::Malformed("AMR-WB output buffer too small"));
        }
        Ok(wb::dec_main::conceal(
            &mut self.decoder_state,
            self.last_mode,
            out,
        ))
    }
}

impl Encoder for AmrWb {
    fn params(&self) -> CodecParams {
        self.params
    }
    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }
    /// Encode one 20 ms frame (320 samples @ 16 kHz) into an RFC 4867 **octet-aligned** single-frame
    /// AMR-WB payload at the configured [`AmrWb::with_encode_mode`] mode (default 2 / 12.65 kbit/s):
    /// the bit-exact core ([`AmrWb::encode_mode_bits`]) → RFC 4867 sort/pack → `CMR | ToC | speech`.
    /// CMR = 15 (no mode request); ToC = `F=0, FT=mode, Q=1` (RFC 4867 §4.3.2 / §4.4).
    fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, CodecError> {
        let mode = self.encode_mode;
        let nb_bits = AmrWbMode::from_frame_type(mode)
            .ok_or(CodecError::Unsupported("AMR-WB invalid speech mode"))?
            .bits() as usize;
        let mut bits = [0i16; 477]; // max AMRWB_SPEECH_BITS (mode 8)
        self.encode_mode_bits(mode, pcm, &mut bits[..nb_bits])?;
        let speech = wb::bitstream::pack(&bits[..nb_bits], mode);
        // Octet-aligned single-frame payload: CMR byte + ToC byte + speech bytes.
        let total = 2 + speech.len();
        if out.len() < total {
            return Err(CodecError::OutputTooSmall {
                needed: total,
                have: out.len(),
            });
        }
        out[0] = 0xF0; // CMR = 15 (no codec-mode request), low 4 bits reserved = 0
        out[1] = (mode << 3) | 0x04; // F=0 (last frame), FT=mode, Q=1 (good)
        out[2..total].copy_from_slice(&speech);
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amrnb_mode_sizes() {
        assert_eq!(AmrNbMode::Mr475.bits(), 95);
        assert_eq!(AmrNbMode::Mr475.bytes(), 12);
        assert_eq!(AmrNbMode::Mr1220.bits(), 244);
        assert_eq!(AmrNbMode::Mr1220.bytes(), 31);
        assert_eq!(AmrNbMode::Mr1220.frame_type(), 7);
    }

    #[test]
    fn amrwb_mode_sizes() {
        assert_eq!(AmrWbMode::Mr660.bits(), 132);
        assert_eq!(AmrWbMode::Mr660.bytes(), 17);
        assert_eq!(AmrWbMode::Mr2385.bits(), 477);
        assert_eq!(AmrWbMode::Mr2385.bytes(), 60);
        assert_eq!(AmrWbMode::Mr1265.frame_type(), 2);
    }

    #[test]
    fn amr_wb_encode_produces_a_decodable_octet_aligned_payload() {
        // A deterministic 20 ms input frame (integer pattern — encode is deterministic in it).
        let pcm: Vec<i16> = (0..wb::constants::L_FRAME16K)
            .map(|i| (((i as i32 * 137) % 8000) - 4000) as i16)
            .collect();
        let mut encoder = AmrWb::new(); // default encode mode 2 (12.65 kbit/s — VoLTE)
        let mut payload = [0u8; 64];
        let len = encoder.encode(&pcm, &mut payload).expect("AMR-WB encode");
        // CMR(1) + ToC(1) + ceil(253/8)=32 speech bytes for mode 2.
        assert_eq!(len, 2 + 32);
        let parsed =
            payload::AmrPayload::parse_amr_wb(&payload[..len], true).expect("parse octet-aligned");
        assert_eq!(parsed.cmr, 15, "CMR = no codec-mode request");
        assert_eq!(parsed.frames.len(), 1);
        assert_eq!(parsed.frames[0].frame_type, 2, "mode 2 / 12.65k");
        assert!(parsed.frames[0].quality_ok, "Q bit set (good frame)");
        // The emitted payload round-trips through the public RTP decode path.
        let mut decoder = AmrWb::new();
        let mut out = [0i16; wb::constants::L_FRAME16K];
        assert_eq!(
            decoder
                .decode(&payload[..len], &mut out)
                .expect("AMR-WB decode"),
            wb::constants::L_FRAME16K
        );
    }

    #[test]
    fn frame_type_roundtrip() {
        for ft in 0u8..=7 {
            let mode = AmrNbMode::from_frame_type(ft).expect("nb mode");
            assert_eq!(mode.frame_type(), ft);
        }
        for ft in 0u8..=8 {
            let mode = AmrWbMode::from_frame_type(ft).expect("wb mode");
            assert_eq!(mode.frame_type(), ft);
        }
        assert_eq!(AmrNbMode::from_frame_type(8), None); // SID
        assert_eq!(AmrWbMode::from_frame_type(9), None); // SID
        assert_eq!(AmrWbMode::from_frame_type(15), None); // no-data
    }

    #[test]
    fn toc_octet_roundtrip() {
        for follow in [false, true] {
            for quality_ok in [false, true] {
                for frame_type in 0u8..=15 {
                    let toc = Toc {
                        follow,
                        frame_type,
                        quality_ok,
                    };
                    assert_eq!(Toc::from_octet(toc.to_octet()), toc);
                }
            }
        }
    }

    #[test]
    fn toc_bit_layout() {
        // FT=7 (MR1220), follow=1, quality=1 -> bits 1_0111_1_00 = 0b1011_1100 = 0xBC.
        let toc = Toc {
            follow: true,
            frame_type: 7,
            quality_ok: true,
        };
        assert_eq!(toc.to_octet(), 0b1011_1100);
    }

    #[test]
    fn parse_single_frame_payload() {
        // CMR=0xF (no request), one ToC (FT=7, no follow, quality ok), then frame data.
        let toc = Toc {
            follow: false,
            frame_type: 7,
            quality_ok: true,
        };
        let mut payload = vec![0xF0, toc.to_octet()];
        payload.extend(std::iter::repeat_n(0u8, AmrNbMode::Mr1220.bytes()));

        let header = parse_octet_aligned(&payload).expect("parse");
        assert_eq!(header.cmr, 0xF);
        assert_eq!(header.entries.len(), 1);
        assert_eq!(header.entries[0].frame_type, 7);
        assert_eq!(header.data_offset, 2);
    }

    #[test]
    fn parse_multi_frame_payload() {
        let first = Toc {
            follow: true,
            frame_type: 2,
            quality_ok: true,
        };
        let second = Toc {
            follow: false,
            frame_type: 2,
            quality_ok: true,
        };
        let payload = vec![0x00, first.to_octet(), second.to_octet(), 0x11, 0x22];
        let header = parse_octet_aligned(&payload).expect("parse");
        assert_eq!(header.entries.len(), 2);
        assert!(header.entries[0].follow);
        assert!(!header.entries[1].follow);
        assert_eq!(header.data_offset, 3);
    }

    #[test]
    fn parse_rejects_empty_and_truncated() {
        assert_eq!(
            parse_octet_aligned(&[]),
            Err(CodecError::Malformed("empty AMR payload"))
        );
        // CMR byte with follow bit set but no ToC byte present.
        assert_eq!(
            parse_octet_aligned(&[0xF0]),
            Err(CodecError::Malformed("truncated AMR ToC"))
        );
    }

    #[test]
    fn amr_codecs_report_params() {
        // AMR-NB decode (all 8 modes) is wired; encode is wired for MR122 (default) + MR475.
        let mut nb = AmrNb::new();
        assert_eq!(nb.frame_samples(), 160);
        assert_eq!(nb.params().sample_rate_hz, 8000);
        // A well-formed octet-aligned MR475 single-frame payload (CMR=0xF, ToC FT=0 Q=1, 12 bytes)
        // decodes to one 160-sample frame.
        let mut nb_payload = vec![
            0xF0u8,
            Toc {
                follow: false,
                frame_type: 0,
                quality_ok: true,
            }
            .to_octet(),
        ];
        nb_payload.extend(std::iter::repeat_n(0u8, AmrNbMode::Mr475.bytes()));
        assert!(matches!(nb.decode(&nb_payload, &mut [0i16; 160]), Ok(160)));
        // Encode is wired (default MR122): a deterministic frame encodes to a well-formed
        // octet-aligned payload (CMR + ToC + 31 speech bytes).
        let pcm: Vec<i16> = (0..nb::constants::L_FRAME)
            .map(|i| (((i as i32 * 137) % 8000) - 4000) as i16)
            .collect();
        let mut nb_out = [0u8; 64];
        let n = nb.encode(&pcm, &mut nb_out).expect("AMR-NB encode");
        assert_eq!(n, 2 + AmrNbMode::Mr1220.bytes());

        let mut wb = AmrWb::new();
        assert_eq!(wb.frame_samples(), 320);
        assert_eq!(wb.params().sample_rate_hz, 16000);
        // AMR-WB encode is wired: a silent frame encodes to a well-formed mode-2 octet-aligned payload.
        assert!(matches!(wb.encode(&[0i16; 320], &mut [0u8; 64]), Ok(34)));
    }

    /// Build an octet-aligned RFC 4867 mode-0 payload from a `.cod` frame's encoder-order bits by
    /// re-sorting them into RTP payload order (the inverse of `unsort_mode0`).
    fn rtp_payload_from_encoder_bits(enc_bits: &[i16]) -> Vec<u8> {
        use wb::bitstream::{BIT_1, SORT_660};
        let mut data = vec![0u8; AmrWbMode::Mr660.bytes()];
        for (i, &src) in SORT_660.iter().enumerate() {
            if enc_bits[src as usize] == BIT_1 {
                data[i / 8] |= 1 << (7 - (i % 8));
            }
        }
        // CMR=0xF (no request) + one ToC (FT=0, no follow, quality ok) + frame data.
        let mut payload = vec![
            0xF0u8,
            Toc {
                follow: false,
                frame_type: 0,
                quality_ok: true,
            }
            .to_octet(),
        ];
        payload.extend_from_slice(&data);
        payload
    }

    /// Encode the reference input PCM at `mode` and compare every frame's encoder-order speech bits
    /// against the official `tst_mN.cod` (G.192 framing: `[TXRXFLAG, FrameType, Mode, bit_0..]`,
    /// +127/-127 per databit). Returns `(frames_checked, first_mismatch)` where `first_mismatch` is
    /// `Some((frame, bit_index, got, want))` on the first differing bit.
    #[allow(clippy::type_complexity)]
    fn check_mode_vector(mode: u8) -> (usize, Option<(usize, usize, i16, i16)>) {
        let nb_bits = AmrWbMode::from_frame_type(mode).expect("mode").bits() as usize;
        let mut inp_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        inp_path.push("../../reference/amr-wb/testv/tst.inp");
        let mut cod_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        cod_path.push(format!("../../reference/amr-wb/testv/tst_m{mode}.cod"));
        // Vectors are gitignored / LFS-pending, so skip gracefully when absent (matches g722/g726).
        let (Some(inp), Some(cod)) = (std::fs::read(&inp_path).ok(), std::fs::read(&cod_path).ok())
        else {
            eprintln!("AMR-WB reference vectors absent — skipping encode mode {mode} conformance");
            return (0, None);
        };
        let pcm: Vec<i16> = inp
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        let cod_words: Vec<i16> = cod
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();

        let cod_frame_words = 3 + nb_bits;
        let n_frames = cod_words.len() / cod_frame_words;
        assert_eq!(pcm.len() / 320, n_frames, "frame count mismatch");

        let mut wb = AmrWb::new();
        let mut out = vec![0i16; nb_bits];
        for f in 0..n_frames {
            let frame_pcm = &pcm[f * 320..(f + 1) * 320];
            let written = wb
                .encode_mode_bits(mode, frame_pcm, &mut out)
                .expect("encode");
            assert_eq!(written, nb_bits);
            let base = f * cod_frame_words + 3;
            for (b, (&got, &want)) in out.iter().zip(&cod_words[base..base + nb_bits]).enumerate() {
                // Normalize: reference databits are +127/-127; treat anything else (shouldn't occur)
                // as a mismatch.
                if got != want {
                    return (n_frames, Some((f, b, got, want)));
                }
            }
        }
        (n_frames, None)
    }

    /// Mode 0 (6.60 kbit/s) uses the 2-track `ACELP_2t64_fx` codebook and 36-bit ISF path.
    #[test]
    fn encodes_full_mode0_vector_bit_exact() {
        let (frames, mismatch) = check_mode_vector(0);
        assert!(
            mismatch.is_none(),
            "mode 0: {frames} frames, first mismatch {mismatch:?}"
        );
    }

    /// Mode 1 (8.85 kbit/s): same 2t64 codebook as mode 0 but the higher-rate per-mode packing.
    #[test]
    fn encodes_full_mode1_vector_bit_exact() {
        let (frames, mismatch) = check_mode_vector(1);
        assert!(
            mismatch.is_none(),
            "mode 1: {frames} frames, first mismatch {mismatch:?}"
        );
    }

    #[test]
    fn encodes_full_mode2_vector_bit_exact() {
        let (frames, mismatch) = check_mode_vector(2);
        assert!(
            mismatch.is_none(),
            "mode 2: {frames} frames, first mismatch {mismatch:?}"
        );
    }

    /// The 4-track ACELP (`ACELP_4t64_fx`) modes share the same encode pipeline as mode 2 and the
    /// same per-mode `Prm2bits` packing; once mode 2 is byte-exact the rest of the 4t64 family
    /// (modes 2..=7) encodes the reference `tst.inp` byte-for-byte against `tst_mN.cod` too. Mode 8
    /// additionally runs the high-band `synthesis()` tier (4-bit HF correction gain per subframe).
    #[test]
    fn encodes_full_mode3_vector_bit_exact() {
        let (frames, mismatch) = check_mode_vector(3);
        assert!(
            mismatch.is_none(),
            "mode 3: {frames} frames, first mismatch {mismatch:?}"
        );
    }

    #[test]
    fn encodes_full_mode4_vector_bit_exact() {
        let (frames, mismatch) = check_mode_vector(4);
        assert!(
            mismatch.is_none(),
            "mode 4: {frames} frames, first mismatch {mismatch:?}"
        );
    }

    #[test]
    fn encodes_full_mode5_vector_bit_exact() {
        let (frames, mismatch) = check_mode_vector(5);
        assert!(
            mismatch.is_none(),
            "mode 5: {frames} frames, first mismatch {mismatch:?}"
        );
    }

    #[test]
    fn encodes_full_mode6_vector_bit_exact() {
        let (frames, mismatch) = check_mode_vector(6);
        assert!(
            mismatch.is_none(),
            "mode 6: {frames} frames, first mismatch {mismatch:?}"
        );
    }

    #[test]
    fn encodes_full_mode7_vector_bit_exact() {
        let (frames, mismatch) = check_mode_vector(7);
        assert!(
            mismatch.is_none(),
            "mode 7: {frames} frames, first mismatch {mismatch:?}"
        );
    }

    /// Mode 8 (23.85 kbit/s): the 4t64 ACELP pipeline plus the high-band `synthesis()` tier, which
    /// transmits a 4-bit HF correction-gain index per subframe (16 extra bits/frame → 477 total).
    /// The reference `tst_m8.cod` is generated with DTX enabled (`testv/test_enc.bat`), so the
    /// `synthesis()` `gain_alpha` update is driven by the live DTX speech-hangover count.
    #[test]
    fn encodes_full_mode8_vector_bit_exact() {
        let (frames, mismatch) = check_mode_vector(8);
        assert!(
            mismatch.is_none(),
            "mode 8: {frames} frames, first mismatch {mismatch:?}"
        );
    }

    #[test]
    fn decode_rtp_mode0_matches_the_reference_vector() {
        // End-to-end RTP path: parse → un-sort → mode-0 decode → homing, over the first 3 frames of
        // tst_m0, compared sample-for-sample with the official .out. Exercises decode() + unsort.
        let mut cod_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        cod_path.push("../../reference/amr-wb/testv/tst_m0.cod");
        let mut out_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        out_path.push("../../reference/amr-wb/testv/tst_m0.out");
        // Vectors are gitignored / LFS-pending, so skip gracefully when absent (matches g722/g726).
        let (Some(cod), Some(out)) = (std::fs::read(&cod_path).ok(), std::fs::read(&out_path).ok())
        else {
            eprintln!("AMR-WB reference vectors absent — skipping decode_rtp_mode0 conformance");
            return;
        };
        let cod_words: Vec<i16> = cod
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        let ref_pcm: Vec<i16> = out
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();

        const COD_FRAME_WORDS: usize = 3 + 132;
        let mut wb = AmrWb::new();
        let mut decoded = [0i16; 320];
        for f in 0..3 {
            let base = f * COD_FRAME_WORDS;
            let enc_bits = &cod_words[base + 3..base + COD_FRAME_WORDS];
            let payload = rtp_payload_from_encoder_bits(enc_bits);
            let n = wb.decode(&payload, &mut decoded).expect("decode");
            assert_eq!(n, 320);
            assert_eq!(
                &decoded[..],
                &ref_pcm[f * 320..(f + 1) * 320],
                "RTP decode frame {f} must equal the reference vector"
            );
        }
    }

    /// Build an octet-aligned RFC 4867 AMR-NB single-frame payload from a frame's serial speech bits
    /// (encoder/`Bits2prm` order, `0`/`1`) by re-sorting into RTP payload order.
    fn nb_rtp_payload_from_serial_bits(serial: &[i16], mode: usize) -> Vec<u8> {
        let data = nb::bitstream::pack(serial, mode);
        let mut payload = vec![
            0xF0u8,
            Toc {
                follow: false,
                frame_type: mode as u8,
                quality_ok: true,
            }
            .to_octet(),
        ];
        payload.extend_from_slice(&data);
        payload
    }

    /// End-to-end AMR-NB RTP path: parse → un-sort → MR475 core decode → homing, over the first few
    /// frames of T01_475, compared sample-for-sample with the official `.OUT`. Exercises the public
    /// `Decoder::decode` + `unsort`/`pack` round-trip against the bit-exact core.
    #[test]
    fn decode_rtp_amrnb_mr475_matches_the_reference_vector() {
        let mut cod_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        cod_path.push("../../reference/amr-nb/testv/NODTX/T_475/T01_475.COD");
        let mut out_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        out_path.push("../../reference/amr-nb/testv/NODTX/T_475/T01_475.OUT");
        // The 3GPP reference vectors are gitignored — skip (not fail) when absent from the checkout.
        let (Ok(cod), Ok(out)) = (std::fs::read(&cod_path), std::fs::read(&out_path)) else {
            return;
        };
        let cod_words: Vec<i16> = cod
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        let ref_pcm: Vec<i16> = out
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();

        const COD_FRAME_WORDS: usize = 250; // 1 + 244 + 1 + 4
        let mut nb = AmrNb::new();
        let mut decoded = [0i16; 160];
        for f in 0..5 {
            let base = f * COD_FRAME_WORDS;
            // serial[1..1+95] are the MR475 speech bits in encoder order.
            let serial = &cod_words[base + 1..base + 1 + 95];
            let payload = nb_rtp_payload_from_serial_bits(serial, 0);
            let n = nb.decode(&payload, &mut decoded).expect("decode");
            assert_eq!(n, 160);
            assert_eq!(
                &decoded[..],
                &ref_pcm[f * 160..(f + 1) * 160],
                "AMR-NB RTP decode frame {f} must equal the reference vector"
            );
        }
    }

    /// Encode the reference input PCM at `mode` (MR122 / MR475) frame-by-frame through the public
    /// [`AmrNb::encode_mode_bits`] and compare every frame's serial speech bits against the official
    /// 3GPP TS 26.074 `.COD` (250 words/frame: `[TXtype][244 bits][mode][4 unused]`). Returns
    /// `(frames_checked, first_mismatch)`. Skip-when-absent (the vectors are gitignored).
    #[allow(clippy::type_complexity)]
    fn check_nb_encode_vector(mode: AmrNbMode, cod_rel: &str) -> (usize, Option<(usize, usize)>) {
        let nb_bits = mode.bits() as usize;
        let mut inp_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        inp_path.push("../../reference/amr-nb/testv/NODTX/T_INP/T01.INP");
        let mut cod_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        cod_path.push(cod_rel);
        let (Ok(inp), Ok(cod)) = (std::fs::read(&inp_path), std::fs::read(&cod_path)) else {
            return (0, None);
        };
        let pcm: Vec<i16> = inp
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        let cod_words: Vec<i16> = cod
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        const COD_FRAME_WORDS: usize = 250; // 1 + 244 + 1 + 4
        let n_frames = cod_words.len() / COD_FRAME_WORDS;
        let mut nb = AmrNb::new();
        let mut bits = [0i16; 244];
        for f in 0..n_frames {
            let frame_pcm = &pcm[f * 160..(f + 1) * 160];
            nb.encode_mode_bits(mode, frame_pcm, &mut bits[..nb_bits])
                .expect("AMR-NB encode");
            let base = f * COD_FRAME_WORDS + 1; // skip the TX-type word
            for (b, (&got, &want)) in bits[..nb_bits]
                .iter()
                .zip(&cod_words[base..base + nb_bits])
                .enumerate()
            {
                if got != want {
                    return (n_frames, Some((f, b)));
                }
            }
        }
        (n_frames, None)
    }

    /// End-to-end public encode path (MR122): every serial speech bit matches `T01_122.COD`.
    #[test]
    fn encodes_amrnb_mr122_serial_bits_bit_exact() {
        let (frames, mismatch) =
            check_nb_encode_vector(AmrNbMode::Mr1220, "../../reference/amr-nb/testv/NODTX/T_122/T01_122.COD");
        assert!(
            mismatch.is_none(),
            "MR122: {frames} frames, first mismatch {mismatch:?}"
        );
    }

    /// End-to-end public encode path (MR475, joint gain): every serial speech bit matches `T01_475.COD`.
    #[test]
    fn encodes_amrnb_mr475_serial_bits_bit_exact() {
        let (frames, mismatch) =
            check_nb_encode_vector(AmrNbMode::Mr475, "../../reference/amr-nb/testv/NODTX/T_475/T01_475.COD");
        assert!(
            mismatch.is_none(),
            "MR475: {frames} frames, first mismatch {mismatch:?}"
        );
    }

    /// `AmrNb::encode` produces a well-formed RFC 4867 octet-aligned payload that round-trips through
    /// the public RTP decode path (default mode MR122).
    #[test]
    fn amr_nb_encode_produces_a_decodable_octet_aligned_payload() {
        let pcm: Vec<i16> = (0..nb::constants::L_FRAME)
            .map(|i| (((i as i32 * 149) % 7000) - 3500) as i16)
            .collect();
        let mut encoder = AmrNb::new();
        let mut payload = [0u8; 64];
        let len = encoder.encode(&pcm, &mut payload).expect("AMR-NB encode");
        // CMR(1) + ToC(1) + ceil(244/8)=31 speech bytes for MR122.
        assert_eq!(len, 2 + AmrNbMode::Mr1220.bytes());
        let parsed =
            payload::AmrPayload::parse_amr_nb(&payload[..len], true).expect("parse octet-aligned");
        assert_eq!(parsed.cmr, 15, "CMR = no codec-mode request");
        assert_eq!(parsed.frames.len(), 1);
        assert_eq!(parsed.frames[0].frame_type, 7, "MR122 / 12.2k");
        assert!(parsed.frames[0].quality_ok, "Q bit set (good frame)");
        let mut decoder = AmrNb::new();
        let mut out = [0i16; nb::constants::L_FRAME];
        assert_eq!(
            decoder
                .decode(&payload[..len], &mut out)
                .expect("AMR-NB decode"),
            nb::constants::L_FRAME
        );
    }
}
