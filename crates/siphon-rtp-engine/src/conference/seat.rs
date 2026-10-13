//! Whether a room can hold a participant, and the reason when it cannot.
//!
//! A refused seat is answered as an error on the `conference_join` that asked for it: the join waits
//! for the room actor's verdict rather than answering `ok` for a seat the room then drops. The same
//! frame rule decides which of an offer's codecs a participant can be seated in at all, so a codec the
//! room would refuse is never chosen in the first place.

use std::fmt;

use siphon_rtp_codec::{Decoder, Encoder};
use siphon_rtp_media::mixer::MAX_PARTICIPANTS;

use super::{MAX_NATIVE_FRAME, MAX_PTIME_MS};

/// How long a join waits for the room actor to seat its participant. The actor answers between two
/// datagrams of its mailbox, so this bounds a wedged or overloaded room, not ordinary work.
pub const SEAT_VERDICT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Why a room did not seat a participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeatRefusal {
    /// The room already holds [`MAX_PARTICIPANTS`] seats.
    RoomFull,
    /// A participant with this from-tag is already seated in the room.
    DuplicateTag(String),
    /// The packetization interval is outside 1 to 120 ms (the RFC 7587 §6.1 `maxptime` ceiling).
    Ptime(u8),
    /// One decoded frame holds this many interleaved values, which the room's scratch buffers cannot
    /// take (or none at all).
    Frame(usize),
    /// The participant's decoder and encoder disagree on rate, packetization interval or channels, so
    /// one frame length cannot serve both halves of the leg.
    Mismatch {
        decode_rate_hz: u32,
        decode_ptime_ms: u8,
        encode_rate_hz: u32,
        encode_ptime_ms: u8,
        encode_channels: u8,
    },
    /// The room actor is gone, or did not answer within [`SEAT_VERDICT_TIMEOUT`].
    NoVerdict,
}

impl fmt::Display for SeatRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoomFull => write!(formatter, "the room is full ({MAX_PARTICIPANTS} seats)"),
            Self::DuplicateTag(tag) => {
                write!(formatter, "from-tag {tag} is already seated in this room")
            }
            Self::Ptime(ptime_ms) => write!(
                formatter,
                "packetization interval {ptime_ms} ms is outside 1..={MAX_PTIME_MS} ms"
            ),
            Self::Frame(values) => write!(
                formatter,
                "a decoded frame of {values} values is outside the room's 1..={MAX_NATIVE_FRAME}"
            ),
            Self::Mismatch {
                decode_rate_hz,
                decode_ptime_ms,
                encode_rate_hz,
                encode_ptime_ms,
                encode_channels,
            } => write!(
                formatter,
                "decoder ({decode_rate_hz} Hz, {decode_ptime_ms} ms) and encoder ({encode_rate_hz} \
                 Hz, {encode_ptime_ms} ms, {encode_channels} channels) disagree"
            ),
            Self::NoVerdict => write!(
                formatter,
                "the room did not seat the participant within {} ms",
                SEAT_VERDICT_TIMEOUT.as_millis()
            ),
        }
    }
}

/// The frame a seated participant works in, as [`fit`] measured it.
pub struct SeatFrame {
    /// The decoder's native sample rate.
    pub(crate) native_rate: u32,
    /// Channels of a decoded frame, at least 1.
    pub(crate) native_channels: u8,
    /// Samples per channel in one decoded (and one encoded) frame.
    pub(crate) native_frame: usize,
}

/// Whether one frame length can serve a participant's decoder and encoder in a room.
///
/// The interval is bounded directly rather than only through the frame length: a leg whose interval
/// is not the room tick carries an ingress carry and an egress accumulator sized from it, and the
/// jitter buffer holds a fixed number of its frames, so an unbounded `a=ptime` would buy the peer
/// arbitrary buffering and playout latency. The ceiling is the RFC 7587 §6.1 `maxptime`, 120 ms.
///
/// `Decoder::frame_samples` is the interleaved value count (the channel contract in
/// `siphon_rtp_codec`), and that is what the scratch buffer is decoded into, so it is the count bounded.
///
/// **The `native_frame` invariant.** The room decodes each tick into a `native_frame`-sample buffer and
/// encodes the participant's egress out of one. That is only sound while both halves agree on sample
/// rate and interval and the egress is mono, since the mix bus is mono: a mismatched pair would hand
/// the encoder a wrong-length frame on every tick.
pub fn fit(decoder: &dyn Decoder, encoder: &dyn Encoder) -> Result<SeatFrame, SeatRefusal> {
    let native_params = decoder.params();
    let native_channels = native_params.channels.max(1);
    if native_params.ptime_ms == 0 || native_params.ptime_ms > MAX_PTIME_MS {
        return Err(SeatRefusal::Ptime(native_params.ptime_ms));
    }
    let native_values = decoder.frame_samples();
    let native_frame = native_values / native_channels as usize;
    if native_values > MAX_NATIVE_FRAME || native_frame == 0 {
        return Err(SeatRefusal::Frame(native_values));
    }
    let egress_params = encoder.params();
    if egress_params.sample_rate_hz != native_params.sample_rate_hz
        || egress_params.ptime_ms != native_params.ptime_ms
        || egress_params.channels > 1
        || encoder.frame_samples() != native_frame
    {
        return Err(SeatRefusal::Mismatch {
            decode_rate_hz: native_params.sample_rate_hz,
            decode_ptime_ms: native_params.ptime_ms,
            encode_rate_hz: egress_params.sample_rate_hz,
            encode_ptime_ms: egress_params.ptime_ms,
            encode_channels: egress_params.channels,
        });
    }
    Ok(SeatFrame {
        native_rate: native_params.sample_rate_hz,
        native_channels,
        native_frame,
    })
}
