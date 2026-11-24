//! The **split bridge**: both legs of a live two-party call streamed to one duplex stereo WebSocket.
//!
//! [`Command::AttachWsSplit`](crate::Command::AttachWsSplit) dials `ws_uri` once for the call. The
//! `start` frame announces `direction: duplex` and `channels: 2`; channel 0 carries the offerer's
//! audio and channel 1 the answerer's, in both directions. What the server sends on channel 0 is
//! played to the offerer, what it sends on channel 1 to the answerer. For as long as the split is
//! attached nothing crosses between the two parties directly: each hears only its own channel, and
//! a channel the server leaves silent plays silence. [`Command::DetachWsSplit`](crate::Command::DetachWsSplit)
//! puts the direct path back without a re-INVITE.
//!
//! On the wire both are flat, like every other verb:
//!
//! ```json
//! {"command":"attach_ws_split","call_id":"c1","from_tag":"a","ws_uri":"wss://bot.example.net/call","sample_rate":16000}
//! ```
//!
//! A native siphon-rtp extension; the NG/bencode front-end does not carry it.

use serde::{Deserialize, Serialize};

use crate::ProfileFlags;

/// The wire sample rates a split serves, in Hz: what a speech bot asks for, and what every leg codec
/// of the engine converts to and from.
pub const WS_SPLIT_SAMPLE_RATES: [u32; 4] = [8_000, 16_000, 24_000, 48_000];

/// The wire sample rate of a split that names none.
pub const WS_SPLIT_DEFAULT_SAMPLE_RATE: u32 = 16_000;

/// [`Command::AttachWsSplit`](crate::Command::AttachWsSplit): what to attach and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSplitAttach {
    pub call_id: String,
    /// The offerer's tag, as on every call verb.
    pub from_tag: String,
    /// `ws://` or `wss://` URI of the bot the engine dials as a client.
    pub ws_uri: String,
    /// L16 wire rate in Hz, both ways: one of [`WS_SPLIT_SAMPLE_RATES`]. `None` is
    /// [`WS_SPLIT_DEFAULT_SAMPLE_RATE`]. Anything else is refused before the call is touched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_rate: Option<u32>,
    /// What runs on the offerer's uplink before it is sent (boxed: a profile is large and most
    /// commands carry none): read like the profile of
    /// `attach_ws_bridge`, of which only `noise_suppression` applies to a split. Echo cancellation and
    /// the `ws_vad*` turn-taking are refused rather than ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offerer_profile: Option<Box<ProfileFlags>>,
    /// The same for the answerer's uplink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answerer_profile: Option<Box<ProfileFlags>>,
}

/// [`Command::DetachWsSplit`](crate::Command::DetachWsSplit): end the split and restore the direct
/// path. Idempotent: a call with no split is not an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSplitDetach {
    pub call_id: String,
    pub from_tag: String,
}

/// [`Event::WsSplitStarted`](crate::Event::WsSplitStarted): the bot was dialled, `start` was sent and
/// both parties are now isolated from each other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSplitStarted {
    pub call_id: String,
    pub from_tag: String,
    /// The `streamId` of the `start` frame: `split-` and the call id.
    pub stream_id: String,
    pub ws_uri: String,
    /// The negotiated L16 wire rate in Hz.
    pub sample_rate: u32,
}

/// [`Event::WsSplitEnded`](crate::Event::WsSplitEnded): the split stopped. Emitted exactly once per
/// started split, and only after its [`WsSplitStarted`].
///
/// **After any `ws_split_ended` but `detached` and `call_deleted`, the call is still isolated and
/// silent** in both directions, whatever the reason. A split's isolation is lifted by a
/// [`Command::DetachWsSplit`](crate::Command::DetachWsSplit) the controller sent and the engine
/// confirmed, and by nothing else: not the bot going away, not a re-offer, not a failure, not a
/// failover. The controller detaches to get direct audio back, or detaches and attaches again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSplitEnded {
    pub call_id: String,
    pub from_tag: String,
    pub stream_id: String,
    pub reason: WsSplitEndReason,
}

/// Why a split ended.
///
/// `#[non_exhaustive]`: engine-emitted and informational; a reason a consumer has not heard of still
/// means "the split ended".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WsSplitEndReason {
    /// The controller detached it.
    Detached,
    /// The bot closed the WebSocket.
    WsClosed,
    /// The bot sent a `stop` control frame.
    WsStopped,
    /// A WebSocket or transport error ended it.
    WsError,
    /// The call was deleted, so the split went with it.
    CallDeleted,
    /// A re-offer changed the call in a way the split could not follow, and the engine could not put
    /// it back on the actor. The call is **still isolated and silent**: detach to get direct audio.
    Renegotiated,
    /// The call was restored on a standby from a checkpoint taken while it was split. The bot's
    /// socket did not move: the call is isolated and silent until you detach it (direct audio) or
    /// detach and attach again (a new bot).
    Restored,
}

/// Why a requested split wire rate is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("ws split sample_rate {requested} Hz is not one of 8000, 16000, 24000 or 48000")]
pub struct WsSplitRateError {
    pub requested: u32,
}

/// The wire rate of a split: the requested one if it is served, the default when none was asked for.
pub fn resolve_ws_split_sample_rate(requested: Option<u32>) -> Result<u32, WsSplitRateError> {
    match requested {
        None => Ok(WS_SPLIT_DEFAULT_SAMPLE_RATE),
        Some(rate) if WS_SPLIT_SAMPLE_RATES.contains(&rate) => Ok(rate),
        Some(requested) => Err(WsSplitRateError { requested }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_rate_is_16_khz_and_the_served_rates_pass() {
        assert_eq!(resolve_ws_split_sample_rate(None), Ok(16_000));
        for rate in WS_SPLIT_SAMPLE_RATES {
            assert_eq!(resolve_ws_split_sample_rate(Some(rate)), Ok(rate));
        }
    }

    #[test]
    fn a_rate_that_is_not_served_is_refused_not_clamped() {
        for rate in [0, 7_999, 11_025, 12_000, 32_000, 44_100, 96_000] {
            assert_eq!(
                resolve_ws_split_sample_rate(Some(rate)),
                Err(WsSplitRateError { requested: rate })
            );
        }
    }

    #[test]
    fn the_refusal_names_the_rate() {
        let text = WsSplitRateError { requested: 44_100 }.to_string();
        assert!(text.contains("44100"), "{text}");
    }

    use crate::{Command, Event};

    /// The frames, written out as text: what a controller puts on the wire and reads back.
    #[test]
    fn the_verbs_and_events_are_flat_frames_on_the_wire() {
        let attach = r#"{"command":"attach_ws_split","call_id":"c1","from_tag":"a","ws_uri":"wss://bot.example.net/s","sample_rate":24000,"offerer_profile":{"noise_suppression":true}}"#;
        let Command::AttachWsSplit(parsed) = serde_json::from_str(attach).expect("parses") else {
            panic!("an attach_ws_split");
        };
        assert_eq!(parsed.call_id, "c1");
        assert_eq!(parsed.sample_rate, Some(24_000));
        assert!(parsed.offerer_profile.is_some_and(|p| p.noise_suppression));
        assert!(parsed.answerer_profile.is_none());

        let minimal =
            r#"{"command":"attach_ws_split","call_id":"c1","from_tag":"a","ws_uri":"ws://h/s"}"#;
        let again: Command = serde_json::from_str(minimal).expect("parses");
        assert_eq!(
            serde_json::to_string(&again).expect("serialises"),
            minimal,
            "absent options stay absent"
        );

        let detach = r#"{"command":"detach_ws_split","call_id":"c1","from_tag":"a"}"#;
        let parsed: Command = serde_json::from_str(detach).expect("parses");
        assert_eq!(serde_json::to_string(&parsed).expect("serialises"), detach);

        let started = Event::WsSplitStarted(WsSplitStarted {
            call_id: "c1".into(),
            from_tag: "a".into(),
            stream_id: "split-c1".into(),
            ws_uri: "ws://h/s".into(),
            sample_rate: 16_000,
        });
        assert_eq!(
            serde_json::to_string(&started).expect("serialises"),
            r#"{"event":"ws_split_started","call_id":"c1","from_tag":"a","stream_id":"split-c1","ws_uri":"ws://h/s","sample_rate":16000}"#
        );
        let ended = Event::WsSplitEnded(WsSplitEnded {
            call_id: "c1".into(),
            from_tag: "a".into(),
            stream_id: "split-c1".into(),
            reason: WsSplitEndReason::Renegotiated,
        });
        let text = serde_json::to_string(&ended).expect("serialises");
        assert_eq!(
            text,
            r#"{"event":"ws_split_ended","call_id":"c1","from_tag":"a","stream_id":"split-c1","reason":"renegotiated"}"#
        );
        assert_eq!(serde_json::from_str::<Event>(&text).expect("parses"), ended);
    }

    #[test]
    fn a_scope_reaches_the_call_id_of_a_split_frame() {
        let mut command = Command::DetachWsSplit(WsSplitDetach {
            call_id: "c1".into(),
            from_tag: "a".into(),
        });
        assert_eq!(
            command.call_id_mut().map(|id| id.clone()),
            Some("c1".into())
        );
        let mut event = Event::WsSplitEnded(WsSplitEnded {
            call_id: "c1".into(),
            from_tag: "a".into(),
            stream_id: "s".into(),
            reason: WsSplitEndReason::Detached,
        });
        assert_eq!(event.call_id_mut().map(|id| id.clone()), Some("c1".into()));
    }

    #[test]
    fn end_reasons_serialise_in_snake_case() {
        for (reason, text) in [
            (WsSplitEndReason::Detached, "detached"),
            (WsSplitEndReason::WsClosed, "ws_closed"),
            (WsSplitEndReason::WsStopped, "ws_stopped"),
            (WsSplitEndReason::WsError, "ws_error"),
            (WsSplitEndReason::CallDeleted, "call_deleted"),
            (WsSplitEndReason::Renegotiated, "renegotiated"),
            (WsSplitEndReason::Restored, "restored"),
        ] {
            assert_eq!(
                serde_json::to_string(&reason).expect("serialise"),
                format!("\"{text}\"")
            );
        }
    }
}
