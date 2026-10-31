//! Forwarding rooms: push-to-talk group-call media (3GPP TS 24.379).
//!
//! A mixing conference ([`crate::conference`]) decodes every seat, mixes, and encodes a different
//! stream per listener on a 20 ms tick. A group call does none of that: one seat holds the floor at a
//! time, and its RTP is handed on to everyone else with the payload untouched. So a forwarding room
//! has no jitter buffer, no codec and no tick for media; it forwards each packet when it arrives,
//! through one RTP translator per receiving seat (RFC 3550 §7) so that every receiver sees a single
//! stream with a stable SSRC however often the talker changes.
//!
//! * [`codec`]: the room's one codec and which offered codecs may join it.
//! * [`room`]: the synchronous core (seats, source, fan-out, reports). No sockets, no clock.
//! * `transcode`: seats in another codec than the room's (decode once, encode once per codec
//!   group).
//! * [`registry`]: the actor that owns a core, its mailbox, and the registry the redirect
//!   dispatcher and the engine verbs go through.

pub mod codec;
pub mod registry;
pub mod room;
mod transcode;

pub use codec::RoomCodec;
pub use registry::{ForwardControl, ForwardRefusal, ForwardRegistry};
pub use room::{
    AppRequest, AppSendError, AppTarget, FloorConfig, FloorKeysError, ForwardError, ForwardRoom,
    ForwardSeatConfig, ForwardSeatStats, MAX_SEATS,
};
pub use transcode::TranscodeStats;
