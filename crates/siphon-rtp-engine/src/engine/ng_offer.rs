//! The rtpengine NG front end's `offer` on a call that is already live.
//!
//! A SIP proxy speaking NG sends `offer` again for every re-INVITE: a hold, a resume, a session
//! refresh. NG has no separate re-offer verb, so the same `offer` that sets a call up renegotiates
//! it (rtpengine keeps the call and its ports). The native JSON `offer` instead replaces the call
//! (see `replace_offered_call`), and keeps doing so; the JSON front end has `reoffer` for this.
//!
//! This is the one place the two are told apart. [`Engine::handle_ng`] turns an `offer` on a live
//! call, from a tag the call knows, into a [`Command::Reoffer`]: the ports stay, the interception
//! rides through, and the NG `answer` that follows completes it (same tags for A's re-offer,
//! reversed tags for B's, as `resolve_answer_exchange` accepts).

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, Command};

use super::{ClientId, Engine};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Handle one command that came in over the rtpengine NG front end.
    ///
    /// Everything but `offer` is exactly [`Self::handle`]. An `offer` whose call-id is live and
    /// owned by `client`, and whose from-tag is the call's A tag, or its B tag once answered, is
    /// handled as a [`Command::Reoffer`]. If the re-offer is refused (a codec change, a secure leg
    /// losing its keying, a far offer pending) it falls back to the replace an `offer` has always
    /// done, so NG loses nothing it had; an interception then ends loudly as `call_ended`.
    ///
    /// An unknown from-tag on a live call-id (a forked call, a second dialog on one call-id) is not
    /// supported as a fork: it replaces the call, as before.
    pub async fn handle_ng(&self, client: ClientId, command: Command) -> CmdResult {
        let Command::Offer {
            call_id,
            from_tag,
            sdp,
            profile,
        } = &command
        else {
            return self.handle(client, command).await;
        };
        let known_party = self
            .owned_call(client, call_id, |call| {
                call.from_tag == *from_tag || call.to_tag.as_deref() == Some(from_tag.as_str())
            })
            .unwrap_or(false);
        if !known_party {
            return self.handle(client, command).await;
        }
        let reoffer = Command::Reoffer {
            call_id: call_id.clone(),
            from_tag: from_tag.clone(),
            sdp: sdp.clone(),
            profile: profile.clone(),
        };
        match self.handle(client, reoffer).await {
            CmdResult::Error { reason } => {
                tracing::info!(
                    target: "siphon_rtp::control",
                    %call_id,
                    %reason,
                    "NG offer on a live call cannot be a re-offer — replacing the call instead"
                );
                self.handle(client, command).await
            }
            result => result,
        }
    }
}
