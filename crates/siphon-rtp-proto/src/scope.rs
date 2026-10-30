//! The optional call **scope**: a second key beside `call_id`, so one engine can hold several
//! independent calls under one SIP `Call-ID`.
//!
//! A SIP proxy does not change the `Call-ID`, so every function that anchors media on one call
//! path names its engine call by the same id: the originating and the terminating P-CSCF (which
//! is one instance, twice, for an on-net call), a BGCF on breakout, an MRF playing into it. Each
//! of those is its own pair of legs with its own offer/answer state. A controller keeps them
//! apart by naming a scope, and the engine keys the call by `(scope, call_id)`.
//!
//! # On the wire
//!
//! `scope` is one more top-level key of a frame, beside `id` and `command` on a request and
//! beside `event` on an event. It is **omitted** when unset, so a frame without one is byte for
//! byte the frame every earlier release wrote:
//!
//! ```json
//! {"scope": "bgcf", "id": 4, "command": "delete", "call_id": "7f9a2b1c@198.51.100.20", "from_tag": "a7c31f"}
//! ```
//!
//! ```json
//! {"scope": "bgcf", "event": "media_timeout", "call_id": "7f9a2b1c@198.51.100.20", "from_tag": "a7c31f", "reason": "no_media"}
//! ```
//!
//! In Rust it is [`Scoped`] around the frame type, [`Scoped<Request>`](crate::Request) and
//! [`Scoped<Event>`](crate::Event), rather than a field on each [`Command`] and [`Event`] variant:
//! adding a field to an existing variant breaks every crate that constructs or destructures it,
//! and this does not. `Request` and `Event` themselves are unchanged and still decode a frame that
//! carries a scope, ignoring it.
//!
//! # What it is not
//!
//! A scope is a name, not a credential. Any client that may speak to the control port may name
//! any scope, and a scoped call is reachable by every client that names its scope: that is how
//! two instances of one function answer and release each other's offers. Only an unscoped call
//! stays private to the client that created it.

use serde::{Deserialize, Serialize};

use crate::{Command, Event};

/// The longest scope the engine accepts, in bytes.
pub const MAX_SCOPE_LEN: usize = 64;

/// Why a scope was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeError {
    /// Longer than [`MAX_SCOPE_LEN`] bytes.
    #[error("scope is {len} bytes; the maximum is {max}", max = MAX_SCOPE_LEN)]
    TooLong { len: usize },
    /// Holds a byte outside `A-Z a-z 0-9 - _`.
    #[error("scope may hold only ASCII letters, digits, '-' and '_'")]
    Character,
}

/// Check a scope a controller named: 1 to [`MAX_SCOPE_LEN`] bytes of ASCII letters, digits, `-`
/// and `_`.
///
/// The set is deliberately small. A scope ends up in log lines, in recording file names and in
/// stream identifiers, and none of those should need escaping. The empty string is not a scope at
/// all; it reads as "unscoped" wherever a scope is optional (see [`normalize_scope`]).
pub fn validate_scope(scope: &str) -> Result<(), ScopeError> {
    if scope.len() > MAX_SCOPE_LEN {
        return Err(ScopeError::TooLong { len: scope.len() });
    }
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_';
    if scope.is_empty() || !scope.bytes().all(allowed) {
        return Err(ScopeError::Character);
    }
    Ok(())
}

/// Read an optional scope off a frame: absent and empty both mean unscoped, anything else must
/// pass [`validate_scope`].
pub fn normalize_scope(scope: Option<&str>) -> Result<Option<&str>, ScopeError> {
    match scope {
        None | Some("") => Ok(None),
        Some(scope) => validate_scope(scope).map(|()| Some(scope)),
    }
}

/// A frame together with the scope it addresses, or was emitted for.
///
/// `scope` is omitted from the wire when `None`, so `Scoped<T>` with no scope serializes to exactly
/// the bytes of `T`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scoped<T> {
    /// The scope of the call this frame names. `None` is the unscoped call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The frame itself.
    #[serde(flatten)]
    pub inner: T,
}

impl<T> Scoped<T> {
    /// `inner` addressed to `scope`.
    pub fn new(scope: Option<String>, inner: T) -> Self {
        Self { scope, inner }
    }

    /// `inner` with no scope: the frame as every release before scopes wrote it.
    pub fn unscoped(inner: T) -> Self {
        Self { scope: None, inner }
    }
}

impl Command {
    /// The `call_id` this command names, if it names a call.
    ///
    /// `None` for the verbs that address no call (liveness, census, cluster, `restore`, whose
    /// snapshot carries its own identity) and for the conference verbs, which name a
    /// `conference_id` instead.
    pub fn call_id_mut(&mut self) -> Option<&mut String> {
        match self {
            Command::Offer { call_id, .. }
            | Command::Reoffer { call_id, .. }
            | Command::IceCandidate { call_id, .. }
            | Command::Answer { call_id, .. }
            | Command::AnswerLocal { call_id, .. }
            | Command::OfferFar { call_id, .. }
            | Command::Delete { call_id, .. }
            | Command::Query { call_id, .. }
            | Command::Checkpoint { call_id, .. }
            | Command::PlayMedia { call_id, .. }
            | Command::StopMedia { call_id, .. }
            | Command::SetPlayGain { call_id, .. }
            | Command::PlayDtmf { call_id, .. }
            | Command::SilenceMedia { call_id, .. }
            | Command::UnsilenceMedia { call_id, .. }
            | Command::Echo { call_id, .. }
            | Command::BlockMedia { call_id, .. }
            | Command::UnblockMedia { call_id, .. }
            | Command::BlockDtmf { call_id, .. }
            | Command::UnblockDtmf { call_id, .. }
            | Command::StartRecording { call_id, .. }
            | Command::StopRecording { call_id, .. }
            | Command::SubscribeRequest { call_id, .. }
            | Command::SubscribeAnswer { call_id, .. }
            | Command::Unsubscribe { call_id, .. }
            | Command::AttachWsTee { call_id, .. }
            | Command::DetachWsTee { call_id, .. }
            | Command::AttachWsBridge { call_id, .. }
            | Command::DetachWsBridge { call_id, .. }
            | Command::AttachX3 { call_id, .. }
            | Command::DetachX3 { call_id, .. }
            // Names a call (the leg it moves) as well as a room, so the frame's scope keys it.
            | Command::ConferenceSeat { call_id, .. } => Some(call_id),
            // A two-party send names a call; a room-wide one names a room and has no call.
            Command::SendRtcpApp { call_id, .. } => call_id.as_mut(),
            Command::Ping
            | Command::List
            | Command::Statistics
            | Command::Load
            | Command::NodeInfo
            | Command::Drain
            | Command::Undrain
            | Command::Restore { .. }
            | Command::Authenticate { .. }
            | Command::ConferenceJoin { .. }
            | Command::ConferenceOffer { .. }
            | Command::ConferenceAnswer { .. }
            | Command::ConferenceLeave { .. }
            | Command::ConferenceRoute { .. }
            | Command::ConferenceBridge { .. }
            | Command::ConferenceUnbridge { .. }
            | Command::ConferencePlay { .. }
            | Command::ConferenceStopPlay { .. }
            | Command::ConferenceSetPlayGain { .. }
            | Command::ConferenceStartRecording { .. }
            | Command::ConferenceStopRecording { .. }
            | Command::ForwardJoin { .. }
            | Command::ForwardOffer { .. }
            | Command::ForwardAnswer { .. }
            | Command::ForwardLeave { .. }
            | Command::ForwardSetSource { .. } => None,
        }
    }

    /// Whether this is one of the conference verbs, which name a room rather than a call.
    pub fn is_conference(&self) -> bool {
        matches!(
            self,
            Command::ConferenceJoin { .. }
                | Command::ConferenceOffer { .. }
                | Command::ConferenceAnswer { .. }
                | Command::ConferenceLeave { .. }
                | Command::ConferenceRoute { .. }
                | Command::ConferenceBridge { .. }
                | Command::ConferenceUnbridge { .. }
                | Command::ConferencePlay { .. }
                | Command::ConferenceStopPlay { .. }
                | Command::ConferenceSetPlayGain { .. }
                | Command::ConferenceStartRecording { .. }
                | Command::ConferenceStopRecording { .. }
                | Command::ForwardJoin { .. }
                | Command::ForwardOffer { .. }
                | Command::ForwardAnswer { .. }
                | Command::ForwardLeave { .. }
                | Command::ForwardSetSource { .. }
                | Command::SendRtcpApp {
                    conference_id: Some(_),
                    ..
                }
        )
    }
}

impl Event {
    /// The `call_id` this event is about, if it is about a call.
    ///
    /// `None` for an event about a conference room, and for [`Event::Unknown`]. The match is
    /// exhaustive inside this crate on purpose: a new event has to say here whether it names a
    /// call, or it would not build.
    pub fn call_id_mut(&mut self) -> Option<&mut String> {
        match self {
            Event::Dtmf { call_id, .. }
            | Event::Text { call_id, .. }
            | Event::MediaTimeout { call_id, .. }
            | Event::MediaStarted { call_id, .. }
            | Event::PlayFinished { call_id, .. }
            | Event::RecordingFinished { call_id, .. }
            | Event::CallSummary { call_id, .. }
            | Event::WsTeeStarted { call_id, .. }
            | Event::BeepDetected { call_id, .. }
            | Event::WsTeeEnded { call_id, .. }
            | Event::X3Started { call_id, .. }
            | Event::X3Loss { call_id, .. }
            | Event::X3Ended { call_id, .. }
            | Event::WsBridgeStarted { call_id, .. }
            | Event::WsBridgeEnded { call_id, .. } => Some(call_id),
            Event::CallQuality { call_id, .. } | Event::RtcpApp { call_id, .. } => call_id.as_mut(),
            Event::ActiveSpeaker { .. }
            | Event::ForwardSourceStarted { .. }
            | Event::ForwardSeatInactive { .. }
            | Event::Unknown => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{frame, MediaTimeoutReason, Request};

    /// Request frames as the release before scopes wrote them.
    const RECORDED_REQUESTS: &[&str] = &[
        r#"{"id":1,"command":"ping"}"#,
        r#"{"id":2,"command":"list"}"#,
        r#"{"id":3,"command":"offer","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f","sdp":"v=0\r\n","profile":{}}"#,
        r#"{"id":4,"command":"answer","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f","to_tag":"b19e02","sdp":"v=0\r\n","profile":{}}"#,
        r#"{"id":5,"command":"delete","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f"}"#,
        r#"{"id":6,"command":"query","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f"}"#,
        r#"{"id":7,"command":"authenticate","token":"","controller_id":"proxy-1"}"#,
        r#"{"id":8,"command":"play_media","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f","source":{"source":"tone","tone":"ringback_eu"}}"#,
        r#"{"id":9,"command":"conference_leave","conference_id":"room-1","from_tag":"a7c31f"}"#,
    ];

    /// Event frames as the release before scopes wrote them.
    const RECORDED_EVENTS: &[&str] = &[
        r#"{"event":"media_timeout","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f","reason":"no_media"}"#,
        r#"{"event":"dtmf","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f","digit":"5","duration_ms":120,"volume":-8}"#,
        r#"{"event":"play_finished","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f","play_id":42,"reason":"completed","played_ms":3400}"#,
        r#"{"event":"active_speaker","conference_id":"room-1","from_tag":"a7c31f"}"#,
    ];

    #[test]
    fn a_scope_is_a_short_name() {
        for scope in [
            "pcscf-orig",
            "pcscf_term",
            "bgcf",
            "MRF2",
            &"a".repeat(MAX_SCOPE_LEN),
        ] {
            assert_eq!(validate_scope(scope), Ok(()), "{scope}");
        }
    }

    #[test]
    fn a_scope_outside_the_set_is_refused() {
        assert_eq!(
            validate_scope(&"a".repeat(MAX_SCOPE_LEN + 1)),
            Err(ScopeError::TooLong {
                len: MAX_SCOPE_LEN + 1
            })
        );
        for scope in ["", "a b", "a/b", "a.b", "a\u{1f}b", "caf\u{e9}", "a\n"] {
            assert_eq!(
                validate_scope(scope),
                Err(ScopeError::Character),
                "{scope:?}"
            );
        }
    }

    #[test]
    fn an_absent_and_an_empty_scope_both_mean_unscoped() {
        assert_eq!(normalize_scope(None), Ok(None));
        assert_eq!(normalize_scope(Some("")), Ok(None));
        assert_eq!(normalize_scope(Some("bgcf")), Ok(Some("bgcf")));
        assert_eq!(normalize_scope(Some("b g")), Err(ScopeError::Character));
    }

    /// Old controller, new engine: the engine reads requests as `Scoped<Request>`, and a frame
    /// written before scopes existed reads as the same request with no scope.
    #[test]
    fn a_recorded_request_decodes_as_unscoped_and_reencodes_to_the_same_bytes() {
        for recorded in RECORDED_REQUESTS {
            let plain: Request = serde_json::from_str(recorded).expect("decode as Request");
            let scoped: Scoped<Request> = serde_json::from_str(recorded).expect("decode as Scoped");
            assert_eq!(scoped, Scoped::unscoped(plain.clone()), "{recorded}");
            assert_eq!(
                serde_json::to_string(&scoped).expect("encode scoped"),
                serde_json::to_string(&plain).expect("encode plain"),
                "an unscoped request is the bytes of the request itself: {recorded}"
            );
        }
    }

    /// Old controller, new engine: an unscoped event leaves as the bytes it always had, and those
    /// bytes still read as the event.
    #[test]
    fn a_recorded_event_survives_the_scoped_envelope_byte_for_byte() {
        for recorded in RECORDED_EVENTS {
            let scoped: Scoped<Event> = serde_json::from_str(recorded).expect("decode as Scoped");
            assert_eq!(scoped.scope, None, "{recorded}");
            assert_eq!(
                serde_json::to_string(&scoped).expect("encode scoped"),
                *recorded,
                "an unscoped event is written exactly as recorded"
            );
            let plain: Event = serde_json::from_str(recorded).expect("decode as Event");
            assert_eq!(plain, scoped.inner);
        }
    }

    /// New controller, old engine: the old engine reads `Request`, which is unchanged here. An
    /// unscoped frame from a scope-aware controller is the old frame, and a scoped one still
    /// decodes, with the scope dropped. That second half is why `node_info` advertises the feature.
    #[test]
    fn the_request_type_of_an_older_engine_reads_frames_from_a_scope_aware_controller() {
        let request = Request {
            id: 5,
            command: Command::Delete {
                call_id: "7f9a2b1c@192.0.2.20".into(),
                from_tag: "a7c31f".into(),
                to_tag: None,
            },
        };
        let unscoped = frame::encode(&Scoped::unscoped(request.clone())).expect("encode");
        assert_eq!(unscoped, frame::encode(&request).expect("encode plain"));
        assert_eq!(&unscoped[4..], RECORDED_REQUESTS[4].as_bytes());

        let scoped = Scoped::new(Some("bgcf".into()), request.clone());
        let body = serde_json::to_string(&scoped).expect("encode scoped");
        assert_eq!(
            body,
            r#"{"scope":"bgcf","id":5,"command":"delete","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f"}"#
        );
        let seen_by_old: Request = serde_json::from_str(&body).expect("old decoder accepts it");
        assert_eq!(seen_by_old, request);
        let seen_by_new: Scoped<Request> = serde_json::from_str(&body).expect("new decoder");
        assert_eq!(seen_by_new, scoped);
    }

    /// Old controller, new engine, the other direction: a controller that reads `Event` and never
    /// named a scope is never sent one. One that is sent one anyway still decodes the event.
    #[test]
    fn the_event_type_of_an_older_controller_reads_a_scoped_event() {
        let event = Event::MediaTimeout {
            call_id: "7f9a2b1c@192.0.2.20".into(),
            from_tag: "a7c31f".into(),
            conference_id: None,
            reason: MediaTimeoutReason::NoMedia,
        };
        let body = serde_json::to_string(&Scoped::new(Some("bgcf".into()), event.clone()))
            .expect("encode");
        assert_eq!(
            body,
            r#"{"scope":"bgcf","event":"media_timeout","call_id":"7f9a2b1c@192.0.2.20","from_tag":"a7c31f","reason":"no_media"}"#
        );
        assert_eq!(
            serde_json::from_str::<Event>(&body).expect("old decoder"),
            event
        );
        let scoped: Scoped<Event> = serde_json::from_str(&body).expect("new decoder");
        assert_eq!(scoped.scope.as_deref(), Some("bgcf"));
        assert_eq!(scoped.inner, event);
    }

    #[test]
    fn an_event_kind_this_build_does_not_know_keeps_its_scope() {
        let scoped: Scoped<Event> =
            serde_json::from_str(r#"{"scope":"mrf","event":"not_invented_yet","call_id":"c"}"#)
                .expect("an unknown event still decodes");
        assert_eq!(scoped.scope.as_deref(), Some("mrf"));
        assert_eq!(scoped.inner, Event::Unknown);
    }

    #[test]
    fn a_command_exposes_the_call_it_names_and_a_room_verb_does_not() {
        let mut delete: Request = serde_json::from_str(RECORDED_REQUESTS[4]).expect("decode");
        assert_eq!(
            delete.command.call_id_mut().map(|id| id.as_str()),
            Some("7f9a2b1c@192.0.2.20")
        );
        assert!(!delete.command.is_conference());
        let mut leave: Request = serde_json::from_str(RECORDED_REQUESTS[8]).expect("decode");
        assert_eq!(leave.command.call_id_mut(), None);
        assert!(leave.command.is_conference());
        assert_eq!(Command::Ping.call_id_mut(), None);
    }

    #[test]
    fn an_event_exposes_the_call_it_is_about() {
        let mut timeout: Event = serde_json::from_str(RECORDED_EVENTS[0]).expect("decode");
        assert_eq!(
            timeout.call_id_mut().map(|id| id.as_str()),
            Some("7f9a2b1c@192.0.2.20")
        );
        let mut speaker: Event = serde_json::from_str(RECORDED_EVENTS[3]).expect("decode");
        assert_eq!(speaker.call_id_mut(), None);
        assert_eq!(Event::Unknown.call_id_mut(), None);
    }

    #[test]
    fn forward_verbs_are_room_verbs() {
        for json in [
            r#"{"command":"forward_join","conference_id":"g","from_tag":"f","sdp":"v=0"}"#,
            r#"{"command":"forward_offer","conference_id":"g","from_tag":"f"}"#,
            r#"{"command":"forward_answer","conference_id":"g","from_tag":"f","sdp":"v=0"}"#,
            r#"{"command":"forward_leave","conference_id":"g","from_tag":"f"}"#,
            r#"{"command":"forward_set_source","conference_id":"g"}"#,
        ] {
            let mut command: Command = serde_json::from_str(json).expect(json);
            assert!(command.is_conference(), "{json}");
            assert_eq!(command.call_id_mut(), None, "{json}");
        }
    }

    #[test]
    fn send_rtcp_app_is_scoped_by_its_call_and_unscoped_by_its_room() {
        let mut to_call: Command = serde_json::from_str(
            r#"{"command":"send_rtcp_app","call_id":"c1","from_tag":"f","stream":"floor","name":"MCPT","subtype":0,"payload":""}"#,
        )
        .expect("decode");
        assert!(!to_call.is_conference());
        assert_eq!(to_call.call_id_mut().map(|id| id.as_str()), Some("c1"));
        let mut to_room: Command = serde_json::from_str(
            r#"{"command":"send_rtcp_app","conference_id":"g","stream":"floor","name":"MCPT","subtype":0,"payload":""}"#,
        )
        .expect("decode");
        assert!(to_room.is_conference());
        assert_eq!(to_room.call_id_mut(), None);
    }

    #[test]
    fn an_rtcp_app_event_is_scoped_only_when_it_names_a_call() {
        let mut from_call = Event::RtcpApp {
            call_id: Some("c1".into()),
            conference_id: None,
            from_tag: "f".into(),
            stream: crate::RtcpAppStream::Floor,
            ssrc: 1,
            name: "MCPT".into(),
            subtype: 0,
            payload: Vec::new(),
        };
        assert_eq!(from_call.call_id_mut().map(|id| id.as_str()), Some("c1"));
        let mut inactive = Event::ForwardSeatInactive {
            conference_id: "g".into(),
            from_tag: "f".into(),
        };
        assert_eq!(inactive.call_id_mut(), None);
    }
}
