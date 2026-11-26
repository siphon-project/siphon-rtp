//! Forward compatibility of the engine-emitted end reasons on the wire.
//!
//! `#[non_exhaustive]` only covers a Rust `match`. A consumer built against an older proto must also
//! *decode* an event carrying a reason a newer engine added, or the whole event is lost and the state
//! change it announces never reaches the controller. Every reason enum carried by an event therefore
//! decodes an unknown string to its `Unknown` variant.

use crate::{
    Event, MediaTimeoutReason, PlayEndReason, RecordingEndReason, WsBridgeEndReason,
    WsSplitEndReason, WsTeeEndReason, X3EndReason,
};

const FUTURE: &str = r#""a_reason_added_by_a_newer_engine""#;

#[test]
fn every_end_reason_decodes_a_reason_it_does_not_know() {
    assert_eq!(
        serde_json::from_str::<WsTeeEndReason>(FUTURE).expect("decodes"),
        WsTeeEndReason::Unknown
    );
    assert_eq!(
        serde_json::from_str::<WsBridgeEndReason>(FUTURE).expect("decodes"),
        WsBridgeEndReason::Unknown
    );
    assert_eq!(
        serde_json::from_str::<PlayEndReason>(FUTURE).expect("decodes"),
        PlayEndReason::Unknown
    );
    assert_eq!(
        serde_json::from_str::<MediaTimeoutReason>(FUTURE).expect("decodes"),
        MediaTimeoutReason::Unknown
    );
    assert_eq!(
        serde_json::from_str::<X3EndReason>(FUTURE).expect("decodes"),
        X3EndReason::Unknown
    );
    assert_eq!(
        serde_json::from_str::<RecordingEndReason>(FUTURE).expect("decodes"),
        RecordingEndReason::Unknown
    );
    assert_eq!(
        serde_json::from_str::<WsSplitEndReason>(FUTURE).expect("decodes"),
        WsSplitEndReason::Unknown
    );
}

#[test]
fn known_reasons_still_decode_as_themselves() {
    assert_eq!(
        serde_json::from_str::<WsSplitEndReason>(r#""restored""#).expect("decodes"),
        WsSplitEndReason::Restored
    );
    assert_eq!(
        serde_json::from_str::<MediaTimeoutReason>(r#""setup_timeout""#).expect("decodes"),
        MediaTimeoutReason::SetupTimeout
    );
}

/// The case that matters: the whole event survives, so a split that ended for a new reason still
/// reaches the controller as "ended", and the call it left isolated is still detached.
#[test]
fn a_split_end_with_a_newer_reason_still_arrives_as_an_end() {
    let frame = r#"{"event":"ws_split_ended","call_id":"c1","from_tag":"a","stream_id":"split-c1","reason":"a_reason_added_by_a_newer_engine"}"#;
    let Event::WsSplitEnded(ended) = serde_json::from_str(frame).expect("decodes") else {
        panic!("a ws_split_ended");
    };
    assert_eq!(ended.call_id, "c1");
    assert_eq!(ended.reason, WsSplitEndReason::Unknown);
}
