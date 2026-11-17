//! The vocabulary of a runtime recording ([`crate::Command::StartRecording`]): its format, which
//! audio it captures, how many channels it has, why it ended, and the extra source calls a SIPREC
//! recording or tee is fed by. Re-exported from the crate root.

use serde::{Deserialize, Serialize};

#[allow(unused_imports, reason = "named by the intra-doc links below")]
use crate::{Command, Event};

/// Smallest [`Command::StartRecording`] `bitrate_bps` the engine accepts for an
/// [`RecordingFormat::OggOpus`] recording: the bottom of Opus' own range (RFC 6716 §2.1.1).
///
/// Exported for the same reason as the echo bounds: a controller validating at config load must
/// read the engine's range, not restate it.
pub const RECORDING_OPUS_BITRATE_BPS_MIN: u32 = 6_000;
/// Largest [`Command::StartRecording`] `bitrate_bps` the engine accepts: the top of Opus' range
/// (RFC 6716 §2.1.1). See [`RECORDING_OPUS_BITRATE_BPS_MIN`].
pub const RECORDING_OPUS_BITRATE_BPS_MAX: u32 = 510_000;
/// The bitrate an [`RecordingFormat::OggOpus`] recording gets per channel when `bitrate_bps` is
/// absent: 16 kbit/s for mono, 32 kbit/s for stereo. Transparent for narrowband speech and
/// comfortable for wideband.
pub const RECORDING_OPUS_BITRATE_BPS_PER_CHANNEL_DEFAULT: u32 = 16_000;

/// See the echo-bound asserts above.
const _: () = assert!(RECORDING_OPUS_BITRATE_BPS_MIN < RECORDING_OPUS_BITRATE_BPS_MAX);
const _: () = assert!(
    RECORDING_OPUS_BITRATE_BPS_PER_CHANNEL_DEFAULT >= RECORDING_OPUS_BITRATE_BPS_MIN
        && 2 * RECORDING_OPUS_BITRATE_BPS_PER_CHANNEL_DEFAULT <= RECORDING_OPUS_BITRATE_BPS_MAX
);

/// What [`Command::StartRecording`] writes.
///
/// Deliberately **not** `#[non_exhaustive]`: a controller that asks for a format the engine answers
/// with something else has been silently given a different artefact, and the two here are not
/// substitutes — one is raw wire bytes for an audit, the others decoded audio for a person to
/// listen to. Losing compilation on a new format is the feature, and so is an engine that predates
/// a format refusing it: an unknown variant fails to deserialize, so the command fails instead of
/// falling back to the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingFormat {
    /// Raw RTP/RTCP datagrams, verbatim, in a `.pcap`. The historical behaviour and the default.
    #[default]
    Pcap,
    /// Decoded 16-bit linear PCM, streamed to a RIFF/WAVE file as it arrives.
    Wav,
    /// The same decoded audio, Opus-encoded into an Ogg file (RFC 7845) as it arrives. On the wire
    /// as `"ogg_opus"`; a generated file name ends `.opus`.
    OggOpus,
}

/// Which audio a decoded ([`RecordingFormat::Wav`] or [`RecordingFormat::OggOpus`]) recording
/// captures.
///
/// "Ingress" and "egress" are relative to the **engine**: ingress is what the parties sent *to* it
/// (a voicemail message, a call recording), egress is what the engine sent *to* them (its prompts,
/// an injected announcement, the mixed audio a party heard).
///
/// Exhaustive for the same reason as [`RecordingFormat`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingDirection {
    /// What the parties sent. On a two-party call this is both legs' inbound audio; on a single-leg
    /// (`answer_local`) call it is the caller's. The default, and what a voicemail needs.
    #[default]
    Ingress,
    /// What the engine sent to the parties — prompts, announcements, the conference mix it produced.
    Egress,
    /// Both, which on a mono recording is the two summed and on a stereo one is the two separated.
    Both,
}

/// Whether a decoded recording is one mixed track or two separated ones.
///
/// Exhaustive for the same reason as [`RecordingFormat`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingChannels {
    /// One track. Sources selected by [`RecordingDirection`] are summed (saturating).
    #[default]
    Mono,
    /// Two tracks, interleaved: the caller's audio left, the other side right. Needs two sources
    /// ([`RecordingDirection::Both`] on a single-leg call, or two parties). On a single-leg call the
    /// right channel is what the caller heard: the engine's prompts, or the voice bot that has taken
    /// the leg over. With one source the recording is mono whatever is asked for.
    Stereo,
}

/// How a decoded recording ended ([`Event::RecordingFinished`]).
///
/// `#[non_exhaustive]`: engine-emitted and informational. A consumer that does not recognise a reason
/// still has the finished file, which is the part it acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecordingEndReason {
    /// Ended by [`Command::StopRecording`].
    Stopped,
    /// The `max_duration_ms` limit was reached.
    MaxDuration,
    /// `silence_ms` elapsed with no speech.
    Silence,
    /// The call ended (hangup, `delete`, or a media timeout) while the recording was running.
    CallEnded,
    /// The recording aborted — a write failed, or the file could not be finalized. The file may be
    /// truncated or missing; its `duration_ms` is what had been written when the error hit.
    Error,
    /// The recorded party never sent audio, so no file was kept: `path` is absent and `duration_ms`
    /// is 0. Reported by a `record_call` stream (one per party), so a consumer waiting on every
    /// party's file can tell "this one will never come" from "still being written".
    NoAudio,
}

/// The most calls one recording or tee can be fed by ([`crate::Command::StartRecording`] and
/// [`crate::Command::AttachWsTee`] with `additional_sources`), source 0 included.
pub const MAX_RECORDING_SOURCES: usize = 8;

/// One more call feeding a recording or a WebSocket tee, beyond the one the verb names.
///
/// SIPREC (RFC 7866) answers each recorded stream on a call of its own; this is how one recording
/// or one tee is fed by several of them, a channel per source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingSource {
    /// The source call.
    pub call_id: String,
    /// Its offerer tag, as every verb that names a call carries it.
    pub from_tag: String,
}
