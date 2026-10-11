//! One negotiated AMR or AMR-WB stream on RTP: the payload format it uses, the modes it may send,
//! and how a payload becomes PCM and PCM a payload. Shared by both codecs, which differ only in the
//! speech codec underneath.
//!
//! # What a received frame becomes
//!
//! Every frame of a payload yields 20 ms of PCM:
//!
//! - A speech frame with Q set is decoded, whatever its mode.
//! - A speech frame with Q clear is "severely damaged" (RFC 4867 §4.3.2) and concealed, as is a
//!   SPEECH_LOST frame.
//! - A SID frame starts a silence period. This port has no comfort noise synthesis (3GPP
//!   TS 26.092 / TS 26.192 are not implemented), so the period is rendered as silence: the SID
//!   frame itself and every NO_DATA frame until speech returns.
//! - A NO_DATA frame outside a silence period is a frame that did not arrive, and is concealed.

use crate::CodecError;

use super::mode_control::ModeControl;
use super::rtp::{
    self, FrameSource, PayloadFormat, Variant, MAX_FRAME_OCTETS, NO_DATA, NO_MODE_REQUEST,
};

/// The most frames the encoder puts in one packet. 3GPP TS 26.114 §7.4.2: a client "shall not
/// encapsulate more than 4 non-redundant speech frames in the RTP packets".
pub const MAX_FRAMES_SENT: usize = 4;

/// What a stream negotiated, as far as the codec acts on it (RFC 4867 §8.1, §8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpConfig<'a> {
    /// `octet-align`.
    pub format: PayloadFormat,
    /// `mode-set`, empty when the stream is not restricted to a subset.
    pub mode_set: &'a [u8],
    /// The mode to send when nothing restricts it: the highest of the mode set at or below this
    /// one. `None` is the highest mode of the set.
    pub preferred_mode: Option<u8>,
    /// `mode-change-period` as the peer requires it of what it receives: 1 or 2.
    pub mode_change_period: u8,
    /// `mode-change-neighbor` as the peer asks for it.
    pub mode_change_neighbor: bool,
    /// The codec mode request to put in every payload sent, `None` for 15 (no request). A mode
    /// outside the mode set is not requested (RFC 4867 §8.1: modes outside the subset MUST NOT be
    /// "used in codec mode requests").
    pub mode_request: Option<u8>,
    /// Frames per packet sent, from the negotiated `ptime`; 1 to [`MAX_FRAMES_SENT`].
    pub frames_per_packet: u8,
}

impl Default for RtpConfig<'_> {
    /// The RFC 4867 defaults: bandwidth-efficient, every mode, no restriction, one frame a packet.
    fn default() -> Self {
        Self {
            format: PayloadFormat::BandwidthEfficient,
            mode_set: &[],
            preferred_mode: None,
            mode_change_period: 1,
            mode_change_neighbor: false,
            mode_request: None,
            frames_per_packet: 1,
        }
    }
}

/// Frames of `ptime_ms` at 20 ms a frame, within what the encoder sends in one packet.
#[must_use]
pub fn frames_per_packet(ptime_ms: u8) -> u8 {
    (ptime_ms / 20).clamp(1, MAX_FRAMES_SENT as u8)
}

/// The RTP state of one codec instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RtpStream {
    pub(super) variant: Variant,
    pub(super) format: PayloadFormat,
    pub(super) modes: ModeControl,
    /// The CMR sent in every payload.
    pub(super) mode_request: u8,
    pub(super) frames_per_packet: u8,
    /// The speech mode the peer asked for in the payload decoded last, `None` for no request.
    pub(super) last_request: Option<u8>,
    /// A SID frame arrived and no speech frame has since: the peer is in a silence period.
    in_silence_period: bool,
    /// Speech frames received in a mode the negotiated mode set does not have. They are decoded:
    /// the frame says what it is, and dropping audio the peer did send helps nobody.
    pub(super) frames_outside_mode_set: u64,
}

impl RtpStream {
    /// The state of the bare codec, outside any negotiation: octet-aligned, every mode allowed,
    /// `preferred` sent, one frame a packet, no codec mode request.
    pub(super) fn bare(variant: Variant, preferred: u8) -> Self {
        Self {
            variant,
            format: PayloadFormat::OctetAligned,
            modes: ModeControl::unrestricted(variant.highest_mode(), preferred),
            mode_request: NO_MODE_REQUEST,
            frames_per_packet: 1,
            last_request: None,
            in_silence_period: false,
            frames_outside_mode_set: 0,
        }
    }

    /// The state for a stream as negotiated, or why this codec cannot carry it.
    pub(super) fn new(variant: Variant, config: &RtpConfig<'_>) -> Result<Self, CodecError> {
        let modes = ModeControl::new(
            variant.highest_mode(),
            config.mode_set,
            config.preferred_mode,
        )
        .ok_or(CodecError::Unsupported(
            "the AMR mode-set or preferred mode names a mode the codec does not have",
        ))?
        .with_change_restrictions(config.mode_change_period, config.mode_change_neighbor);
        let mode_request = config
            .mode_request
            .filter(|&mode| mode <= variant.highest_mode() && modes.is_allowed(mode))
            .unwrap_or(NO_MODE_REQUEST);
        Ok(Self {
            variant,
            format: config.format,
            modes,
            mode_request,
            frames_per_packet: config.frames_per_packet.clamp(1, MAX_FRAMES_SENT as u8),
            last_request: None,
            in_silence_period: false,
            frames_outside_mode_set: 0,
        })
    }

    /// Note the codec mode request of a received payload (RFC 4867 §4.3.1): a speech mode is a
    /// request, 15 withdraws it, and any other value "MUST be ignored by the receiver".
    fn note_request(&mut self, cmr: u8) {
        if cmr <= self.variant.highest_mode() {
            self.last_request = Some(cmr);
        } else if cmr == NO_MODE_REQUEST {
            self.last_request = None;
        }
    }
}

/// The speech codec under the payload format: one 20 ms frame at a time.
pub(super) trait FrameCodec {
    /// Decode one good speech frame of `mode` from its bits in payload order into `pcm`.
    fn decode_speech(&mut self, mode: u8, frame: &[u8], pcm: &mut [i16]) -> Result<(), CodecError>;
    /// Fill `pcm` for a frame that is lost or damaged.
    fn conceal_frame(&mut self, pcm: &mut [i16]);
    /// Encode `pcm` at `mode` into `frame`, bits in payload order.
    fn encode_speech(
        &mut self,
        mode: u8,
        pcm: &[i16],
        frame: &mut [u8; MAX_FRAME_OCTETS],
    ) -> Result<(), CodecError>;
}

/// Decode every frame of `payload` into `out`, 20 ms of PCM for each, and return the samples
/// written. The module documentation says what each frame type becomes.
pub(super) fn decode_payload<C: FrameCodec>(
    codec: &mut C,
    stream: &mut RtpStream,
    payload: &[u8],
    out: &mut [i16],
) -> Result<usize, CodecError> {
    let layout = rtp::read_payload(payload, stream.format, stream.variant)?;
    let frame_samples = stream.variant.frame_samples();
    let needed = layout.frames().len() * frame_samples;
    let Some(out) = out.get_mut(..needed) else {
        return Err(CodecError::OutputTooSmall {
            needed,
            have: out.len(),
        });
    };
    stream.note_request(layout.cmr);
    let mut frame = [0u8; MAX_FRAME_OCTETS];
    for (slot, pcm) in layout.frames().iter().zip(out.chunks_mut(frame_samples)) {
        if slot.frame_type <= stream.variant.highest_mode() {
            if !stream.modes.is_allowed(slot.frame_type) {
                stream.frames_outside_mode_set += 1;
            }
            if slot.quality_ok {
                slot.copy_bits(payload, &mut frame);
                codec.decode_speech(slot.frame_type, &frame, pcm)?;
                stream.in_silence_period = false;
            } else {
                codec.conceal_frame(pcm);
            }
        } else if slot.frame_type == NO_DATA && stream.in_silence_period {
            pcm.fill(0);
        } else if slot.bits != 0 {
            // The SID frame: the only frame type left that carries bits.
            stream.in_silence_period = true;
            pcm.fill(0);
        } else {
            codec.conceal_frame(pcm);
        }
    }
    Ok(needed)
}

/// Encode `pcm`, the stream's frames per packet of it, into one payload in `out`.
pub(super) fn encode_payload<C: FrameCodec>(
    codec: &mut C,
    stream: &mut RtpStream,
    pcm: &[i16],
    out: &mut [u8],
) -> Result<usize, CodecError> {
    let frame_samples = stream.variant.frame_samples();
    let frames = usize::from(stream.frames_per_packet);
    let Some(pcm) = pcm.get(..frames * frame_samples) else {
        return Err(CodecError::BadFrameSize {
            expected: frames * frame_samples,
            got: pcm.len(),
        });
    };
    let mut modes = [0u8; MAX_FRAMES_SENT];
    let mut data = [[0u8; MAX_FRAME_OCTETS]; MAX_FRAMES_SENT];
    for ((mode, frame), pcm) in modes
        .iter_mut()
        .zip(data.iter_mut())
        .zip(pcm.chunks(frame_samples))
    {
        *mode = stream.modes.next_frame_mode();
        codec.encode_speech(*mode, pcm, frame)?;
    }
    let sources: [FrameSource<'_>; MAX_FRAMES_SENT] = std::array::from_fn(|index| FrameSource {
        frame_type: modes[index],
        quality_ok: true,
        data: &data[index],
    });
    rtp::write_payload(
        stream.format,
        stream.variant,
        stream.mode_request,
        &sources[..frames],
        out,
    )
}
