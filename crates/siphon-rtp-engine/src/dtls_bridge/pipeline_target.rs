//! Media pipeline targets and the parties keyed by a DTLS leg.

use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use siphon_rtp_datapath::{EndpointId, RxPacket};
use siphon_rtp_srtp::leg::SecureLeg;

/// Which party of a media-pipeline call a DTLS leg keys — the topologies
/// [`crate::media_pipeline::MediaCall`] threads a `SecureLeg` into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyedParty {
    /// The callee of a two-party call (`PipelineKind::DtlsMedia`): A plaintext, B keyed.
    Callee,
    /// The one party of a single-leg call the engine answered itself: both directions face it.
    SoleParty,
    /// The caller of a two-party call (`PipelineKind::DtlsOffererMedia`): A keyed, B plaintext.
    Caller,
}

/// Which slow-path owner a keyed DTLS leg's media belongs to. Both own the `SecureLeg` themselves and
/// decrypt on their own ingress, so the bridge forwards the datagram untouched either way — the only
/// difference is which mailbox it lands in and which control message keys it.
#[derive(Clone)]
pub enum PipelineTarget {
    /// A 2-party call's [`crate::media_pipeline::MediaCall`] actor (`PipelineKind::DtlsMedia`).
    Call {
        media: Arc<crate::media_pipeline::MediaRegistry>,
        call_id: String,
        party: KeyedParty,
    },
    /// A conference seat — the room actor mixes this participant once its handshake keys the seat.
    Conference {
        conference: Arc<crate::conference::ConferenceRegistry>,
        conference_id: String,
        tag: String,
    },
    /// A forwarding-room seat: the room actor forwards this member's source once its handshake keys
    /// the seat.
    Forward {
        forward: Arc<crate::forward::ForwardRegistry>,
        room_id: String,
        tag: String,
    },
    /// A WebSocket-**takeover** leg (`PipelineKind::Ws`): the WS media server is this leg's far side,
    /// so the leg's own [`crate::ws_bridge::WsSecureLeg`] decrypts its ingress and encrypts the
    /// bridge's downlink. Until the handshake keys it the registry drops ingress and refuses egress.
    Ws {
        ws: Arc<crate::ws_bridge::WsRegistry>,
        call_id: String,
    },
}

impl KeyedParty {
    /// The control that threads `leg` into a media actor for this party.
    fn attach(self, leg: Arc<Mutex<SecureLeg>>) -> crate::media_pipeline::MediaControl {
        match self {
            Self::Callee => crate::media_pipeline::MediaControl::AttachSecureLeg { leg },
            Self::SoleParty => crate::media_pipeline::MediaControl::AttachNearSecureLeg { leg },
            Self::Caller => crate::media_pipeline::MediaControl::AttachCallerSecureLeg { leg },
        }
    }
}

impl PipelineTarget {
    /// Route one accepted media datagram to the owning actor.
    pub(super) fn dispatch(&self, packet: RxPacket) {
        match self {
            Self::Call { media, .. } => media.dispatch(packet),
            Self::Conference { conference, .. } => conference.dispatch(packet),
            Self::Forward { forward, .. } => forward.dispatch(packet),
            Self::Ws { ws, .. } => ws.dispatch(packet),
        }
    }

    /// Hand the handshake's key to the owning actor. Returns `false` when it is already gone, in
    /// which case the caller leaves the leg unkeyed so media keeps being dropped.
    ///
    /// A [`Self::Call`] target's leg is also **retained** under its secure endpoint, because that
    /// actor is rebuilt by every renegotiation of the call: without a copy here, the rebuilt actor
    /// would sit pending forever waiting for a handshake the peer has no reason to repeat (RFC 8842
    /// §5.5 — it keeps the association). The other two targets own legs that no re-offer rebuilds.
    pub(crate) fn key(
        &self,
        leg: SecureLeg,
        retained: &DashMap<EndpointId, Arc<Mutex<SecureLeg>>>,
        secure_endpoint: EndpointId,
    ) -> bool {
        match self {
            Self::Call {
                media,
                call_id,
                party,
            } => {
                let leg = Arc::new(Mutex::new(leg));
                retained.insert(secure_endpoint, leg.clone());
                media.control(call_id, party.attach(leg))
            }
            Self::Conference {
                conference,
                conference_id,
                tag,
            } => conference.control(
                conference_id,
                crate::conference::ConferenceControl::AttachSecureLeg {
                    tag: tag.clone(),
                    leg: Box::new(leg),
                },
            ),
            Self::Forward {
                forward,
                room_id,
                tag,
            } => forward.control(
                room_id,
                crate::forward::ForwardControl::AttachSecureLeg {
                    tag: tag.clone(),
                    leg: Box::new(leg),
                },
            ),
            // No mailbox hop: the WS leg's crypto is shared state the registry writes synchronously,
            // so the key is in place before `keyed` is published and therefore before this bridge
            // releases the first media packet.
            Self::Ws { ws, call_id } => ws.attach_secure_leg(call_id, leg),
        }
    }

    /// Re-key an actor the caller has just rebuilt, with the leg its predecessor was using — the
    /// renegotiation counterpart of [`Self::key`]. Only a [`Self::Call`] target is rebuilt that way
    /// (a conference seat and a WS takeover leg are re-registered through their own verbs, which
    /// handshake afresh), so the others report `false` and keep whatever key they hold.
    pub(super) fn reattach(&self, leg: Arc<Mutex<SecureLeg>>) -> bool {
        match self {
            Self::Call {
                media,
                call_id,
                party,
            } => media.control(call_id, party.attach(leg)),
            Self::Conference { .. } | Self::Forward { .. } | Self::Ws { .. } => false,
        }
    }
}
