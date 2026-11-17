//! The video stream of a forwarding room seat (3GPP TS 24.281 §6.2: `m=audio` + `m=video` + the
//! transmission control stream), as a controller asks for it.
//!
//! Video is opaque to the engine: a room never transcodes it, so the controller's say is only what
//! the room advertises about it, and whether it carries any at all ([`crate::ProfileFlags::video`] is
//! `None`: video stays declined at port 0, as before).

use serde::{Deserialize, Serialize};

/// Why a [`VideoProfile`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VideoProfileError {
    /// `fmtp` carries a CR or LF, which would end the SDP line and let the controller's text inject
    /// further lines.
    #[error("video.fmtp must not contain a line break")]
    LineBreak,
    /// `bandwidth_kbps` is zero: a `b=AS:0` line would tell the peer it may send nothing.
    #[error("video.bandwidth_kbps must be at least 1")]
    ZeroBandwidth,
}

/// What a forwarding room does with the video of a seat, on `forward_join` and `forward_offer`.
///
/// Present: the room carries video (a translate room, plain RTP/AVP seats; a seat whose video it
/// cannot carry joins audio-only and the reason is in the result's `video_declined`). Absent
/// ([`crate::ProfileFlags::video`]): every `m=video` is declined at port 0.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VideoProfile {
    /// The parameters of the `a=fmtp` line the engine writes on every video section, e.g.
    /// `profile-level-id=640c1f;packetization-mode=1` (RFC 6184 §8.1; 3GPP TS 26.281 §4.1.1 makes
    /// H.264 mandatory, Constrained High Profile level 3.1 being `640c1f`). Emitted exactly as given,
    /// never edited, and it fixes the room's video format: a seat must offer the same
    /// `packetization-mode` and `profile-level-id`. `None`: the first seat with video fixes the
    /// format from its offer and the room writes that seat's own parameters. A line break inside is
    /// refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmtp: Option<String>,
    /// The `b=AS` (RFC 4566 §5.8, kilobits per second) written on every video section: the most the
    /// room wants to be sent, and what it will send. `None` writes no bandwidth line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth_kbps: Option<u32>,
}

impl VideoProfile {
    /// Check the profile before anything is allocated for it.
    ///
    /// # Errors
    /// [`VideoProfileError`] for a line break in `fmtp` or a zero `bandwidth_kbps`.
    pub fn validate(&self) -> Result<(), VideoProfileError> {
        if self
            .fmtp
            .as_deref()
            .is_some_and(|fmtp| fmtp.contains(['\r', '\n']))
        {
            return Err(VideoProfileError::LineBreak);
        }
        if self.bandwidth_kbps == Some(0) {
            return Err(VideoProfileError::ZeroBandwidth);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::{Command, ProfileFlags};

    #[test]
    fn a_line_break_in_the_fmtp_is_refused() {
        for fmtp in ["a\r\nm=video 0", "a\nb", "a\rb"] {
            let profile = VideoProfile {
                fmtp: Some(fmtp.to_string()),
                bandwidth_kbps: None,
            };
            assert_eq!(
                profile.validate(),
                Err(VideoProfileError::LineBreak),
                "{fmtp:?}"
            );
        }
    }

    #[test]
    fn a_zero_bandwidth_is_refused() {
        let profile = VideoProfile {
            fmtp: None,
            bandwidth_kbps: Some(0),
        };
        assert_eq!(profile.validate(), Err(VideoProfileError::ZeroBandwidth));
        assert!(VideoProfileError::ZeroBandwidth
            .to_string()
            .contains("at least 1"));
        assert!(VideoProfileError::LineBreak
            .to_string()
            .contains("line break"));
    }

    #[test]
    fn a_plain_profile_validates() {
        assert_eq!(VideoProfile::default().validate(), Ok(()));
        let profile = VideoProfile {
            fmtp: Some("profile-level-id=640c1f;packetization-mode=1".to_string()),
            bandwidth_kbps: Some(1200),
        };
        assert_eq!(profile.validate(), Ok(()));
    }

    #[test]
    fn the_profile_wire_shape_omits_what_is_unset() {
        let none = serde_json::to_string(&VideoProfile::default()).unwrap();
        assert_eq!(none, "{}");
        let full = VideoProfile {
            fmtp: Some("packetization-mode=1".to_string()),
            bandwidth_kbps: Some(900),
        };
        assert_eq!(
            serde_json::to_string(&full).unwrap(),
            r#"{"fmtp":"packetization-mode=1","bandwidth_kbps":900}"#
        );
        let back: VideoProfile =
            serde_json::from_str(&serde_json::to_string(&full).unwrap()).unwrap();
        assert_eq!(back, full);
        assert!(serde_json::from_str::<VideoProfile>(r#"{"rtcp_fb":["nack"]}"#).is_err());
    }

    #[test]
    fn forward_join_carries_the_video_profile_and_an_old_frame_has_none() {
        let frame = r#"{"command":"forward_join","conference_id":"g","from_tag":"f","sdp":"v=0","profile":{"video":{"bandwidth_kbps":800}}}"#;
        let Command::ForwardJoin { profile, .. } = serde_json::from_str(frame).unwrap() else {
            panic!("forward_join");
        };
        assert_eq!(
            profile.video,
            Some(VideoProfile {
                fmtp: None,
                bandwidth_kbps: Some(800)
            })
        );
        let old: ProfileFlags = serde_json::from_str("{}").unwrap();
        assert_eq!(old.video, None);
        assert_eq!(serde_json::to_string(&old).unwrap(), "{}");
    }

    #[test]
    fn an_ok_result_reports_the_streams_answered_and_why_video_was_not() {
        let result = crate::CmdResult::Ok {
            sdp: Some("v=0".to_string()),
            duration_ms: None,
            play_id: None,
            recording_id: None,
            to_tag: Some("f".to_string()),
            stats: None,
            streams: vec!["audio".to_string(), "floor".to_string()],
            video_declined: Some("the seat's video is SRTP".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(
            json,
            r#"{"result":"ok","sdp":"v=0","to_tag":"f","streams":["audio","floor"],"video_declined":"the seat's video is SRTP"}"#
        );
        assert_eq!(
            serde_json::from_str::<crate::CmdResult>(&json).unwrap(),
            result
        );
        // An older engine's result has neither field.
        let old: crate::CmdResult = serde_json::from_str(r#"{"result":"ok","sdp":"v=0"}"#).unwrap();
        assert!(matches!(
            old,
            crate::CmdResult::Ok { streams, video_declined: None, .. } if streams.is_empty()
        ));
    }
}
