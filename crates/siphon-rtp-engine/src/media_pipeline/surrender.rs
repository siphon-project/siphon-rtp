//! Handing a running call's legs to another owner: a leg moved into a conference room
//! (`conference_seat`) takes its party's SRTP contexts, source gate and stream identity from the actor
//! that carried it, and the actor stops without a second owner ever running beside it.

use std::sync::{Arc, Mutex};

use siphon_rtp_datapath::{EndpointId, SourceFilter};
use siphon_rtp_srtp::leg::SecureLeg;

use super::{
    CallHandle, FinalCallQuality, MediaCall, MediaControl, MediaInput, MediaRegistry,
    ACTOR_TEARDOWN_GRACE,
};

/// What a media actor hands back when its call's legs move to another owner
/// ([`MediaControl::Surrender`]).
pub struct SurrenderedCall {
    /// A's SRTP contexts — the leg decrypting A's ingress — when A is a secure party.
    pub near_leg: Option<Arc<Mutex<SecureLeg>>>,
    /// B's SRTP contexts — the leg decrypting B's ingress — when B is a secure party.
    pub far_leg: Option<Arc<Mutex<SecureLeg>>>,
    /// Each party's ingress endpoint and the source gate in force on it: A, then B. Read here rather
    /// than from the call record because an ICE selection narrows a gate inside the actor.
    pub gates: [(EndpointId, SourceFilter); 2],
    /// Per-direction quality, whose SSRCs say which stream each party has been receiving.
    pub quality: FinalCallQuality,
}

impl MediaCall {
    /// What the actor hands over when its call's legs move to another owner
    /// ([`MediaControl::Surrender`]): each party's SRTP contexts, the gate on each ingress, and the
    /// final quality.
    pub fn surrender(&self) -> SurrenderedCall {
        SurrenderedCall {
            near_leg: self.a_to_b.secure_ingress.clone(),
            far_leg: self.b_to_a.secure_ingress.clone(),
            gates: [
                (self.a_to_b.ingress_endpoint, self.a_to_b.accepted_source),
                (self.b_to_a.ingress_endpoint, self.b_to_a.accepted_source),
            ],
            quality: self.final_quality(),
        }
    }
}

impl MediaRegistry {
    /// Take `call_id`'s actor out of the registry and have it hand its legs over
    /// ([`MediaControl::Surrender`]), returning only once it has exited, so the caller holds the only
    /// remaining reference to each party's SRTP contexts. `None` when there is no such call or the
    /// actor could not answer (its mailbox full, or it did not reply within the teardown grace); the
    /// actor is stopped either way.
    pub async fn surrender(&self, call_id: &str) -> Option<SurrenderedCall> {
        let (_, handle) = self.calls.remove(call_id)?;
        let CallHandle {
            mailbox,
            endpoints,
            rtcp_endpoints,
            mut task,
            ..
        } = handle;
        for endpoint in endpoints.iter().chain(rtcp_endpoints.iter()) {
            self.routes.remove(endpoint);
            self.observed.remove(endpoint);
        }
        let (reply, surrendered) = tokio::sync::oneshot::channel();
        let answered = if mailbox
            .try_send(MediaInput::Control(MediaControl::Surrender { reply }))
            .is_ok()
        {
            tokio::time::timeout(ACTOR_TEARDOWN_GRACE, surrendered)
                .await
                .ok()
                .and_then(Result::ok)
        } else {
            let _ = mailbox.try_send(MediaInput::Control(MediaControl::Stop));
            None
        };
        if tokio::time::timeout(ACTOR_TEARDOWN_GRACE, &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = task.await;
        }
        answered
    }
}
