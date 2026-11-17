//! The success results a verb answers with.

use siphon_rtp_proto::CmdResult;

/// A success that carries the SDP the verb wrote, and the to-tag of the leg when it has one.
pub(super) fn ok_sdp(sdp: String, to_tag: Option<String>) -> CmdResult {
    CmdResult::Ok {
        sdp: Some(sdp),
        duration_ms: None,
        play_id: None,
        recording_id: None,
        to_tag,
        stats: None,
        streams: Vec::new(),
        video_declined: None,
    }
}

/// A bare success (no SDP/stats) — the reply to control verbs like block/silence.
pub(super) fn ok_empty() -> CmdResult {
    CmdResult::Ok {
        sdp: None,
        duration_ms: None,
        play_id: None,
        recording_id: None,
        to_tag: None,
        stats: None,
        streams: Vec::new(),
        video_declined: None,
    }
}
