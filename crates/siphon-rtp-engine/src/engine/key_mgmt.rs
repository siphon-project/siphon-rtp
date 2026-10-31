//! The controller's `a=key-mgmt` (RFC 4567) on the SDP a two-party verb returns.
//!
//! `profile.key_mgmt` is a passthrough exactly like `floor_fmtp`: written verbatim on the audio
//! section of the SDP the engine produces, never echoed from the SDP it rewrites, never invented
//! (see [`crate::sdp::apply_key_mgmt`]). The one thing refused is the controller's line beside keying
//! the engine terminates itself on the same stream: SDES (RFC 4568) or DTLS-SRTP (RFC 5764) would
//! make two sources of keys for one stream, so the peer's pick between them decides whether its SRTP
//! is end to end or hop by hop.

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, ProfileFlags};

use crate::sdp;

use super::{error_result, ok_sdp, Engine};

/// `sdp` as the controller's profile wants it presented: the other side's `a=key-mgmt` removed and
/// the controller's written, or an error when the SDP carries the engine's own keying beside it.
///
/// # Errors
/// The reason, ready to return as a `CmdResult::Error`.
pub(super) fn keyed_sdp(sdp: &str, profile: &ProfileFlags) -> Result<String, String> {
    if profile.key_mgmt.is_some() && sdp::terminates_keying(sdp) {
        return Err(
            "key_mgmt cannot be advertised on a stream whose SRTP the engine terminates (SDES or \
             DTLS-SRTP): RFC 4567 and RFC 4568 are alternative keying mechanisms for one stream"
                .to_string(),
        );
    }
    Ok(sdp::apply_key_mgmt(sdp, profile.key_mgmt.as_deref()))
}

/// [`keyed_sdp`] as a reply, for a verb that has nothing to release when it refuses.
pub(super) fn ok_sdp_keyed_in_place(sdp: &str, profile: &ProfileFlags) -> CmdResult {
    match keyed_sdp(sdp, profile) {
        Ok(keyed) => ok_sdp(keyed, None),
        Err(reason) => error_result("key_mgmt", &reason),
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// [`keyed_sdp`] for a call being set up: on a refusal the call is torn down and the error is
    /// the reply.
    pub(super) async fn keyed_or_teardown(
        &self,
        call_id: &str,
        sdp: &str,
        profile: &ProfileFlags,
    ) -> Result<String, Box<CmdResult>> {
        match keyed_sdp(sdp, profile) {
            Ok(keyed) => Ok(keyed),
            Err(reason) => {
                self.teardown_call(call_id).await;
                Err(Box::new(error_result("key_mgmt", &reason)))
            }
        }
    }

    /// Return `sdp` to the controller with `profile`'s `a=key-mgmt` applied. A call being set up
    /// that cannot carry it is torn down, so nothing stays allocated for a refused verb.
    pub(super) async fn ok_sdp_keyed(
        &self,
        call_id: &str,
        sdp: String,
        to_tag: Option<String>,
        profile: &ProfileFlags,
    ) -> CmdResult {
        match self.keyed_or_teardown(call_id, &sdp, profile).await {
            Ok(keyed) => ok_sdp(keyed, to_tag),
            Err(refusal) => *refusal,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn profile(key_mgmt: Option<&str>) -> ProfileFlags {
        ProfileFlags {
            key_mgmt: key_mgmt.map(str::to_string),
            ..ProfileFlags::default()
        }
    }

    const PLAIN: &str =
        "v=0\r\nm=audio 4000 RTP/AVP 0\r\na=key-mgmt:mikey PEER\r\na=rtpmap:0 PCMU/8000\r\n";

    #[test]
    fn the_peers_line_is_dropped_and_the_controllers_written() {
        let none = keyed_sdp(PLAIN, &profile(None)).unwrap();
        assert!(!none.contains("key-mgmt"), "{none}");
        let own = keyed_sdp(PLAIN, &profile(Some("mikey OWN"))).unwrap();
        assert_eq!(own.matches("a=key-mgmt:").count(), 1, "{own}");
        assert!(own.contains("a=key-mgmt:mikey OWN\r\n"));
    }

    #[test]
    fn the_controllers_line_beside_engine_keying_is_refused() {
        let sdes =
            "v=0\r\nm=audio 4000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:x\r\n";
        let reason = keyed_sdp(sdes, &profile(Some("mikey OWN"))).unwrap_err();
        assert!(
            reason.contains("RFC 4567") && reason.contains("RFC 4568"),
            "{reason}"
        );
        // Without a controller line the engine's own keying is untouched.
        assert!(keyed_sdp(sdes, &profile(None))
            .unwrap()
            .contains("a=crypto:"));
    }
}
