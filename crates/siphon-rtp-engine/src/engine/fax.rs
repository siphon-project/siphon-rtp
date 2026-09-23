//! Wiring a call's T.38 fax stream: the UDPTL relay an answered `m=image` section gets.
//!
//! Separate from [`super::install`] because the fax stream is separate from the audio path in
//! every way that matters — its own endpoints, its own source gate, its own latch, its own
//! datapath action — and because a failure to bring it up must never fail the call's audio.
//! The relay itself lives in [`crate::udptl_pipeline`]; this is only the answer-time wiring.

use siphon_rtp_datapath::{Datapath, FlowAction};
use siphon_rtp_proto::ProfileFlags;
use std::net::SocketAddr;

use crate::sdp;
use crate::udptl_pipeline::{UdptlCall, UdptlDirectionConfig};

use super::negotiate::{apply_received_from, bridge_source_filter};
use super::{Engine, Leg};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Install the T.38 fax relay for an answered call, if both legs anchored one and the answerer
    /// accepted it.
    ///
    /// Always `FlowAction::Redirect` on both image endpoints, never `Forward`: UDPTL is not RTP, so
    /// the datapath's `Forward` path would drop most of the stream at its layer-1 demux and pin a
    /// meaningless latch on the rest (see [`crate::udptl_pipeline`]). The relay's own gate and latch
    /// are reconstructed from the same signalled/`received-from` addresses the audio leg uses, so
    /// the fax stream gets its own full copy of layers 2 and 3 rather than riding the audio's
    /// (docs/security-and-nat.md §4 layer 5g — RTPBleed is per-stream).
    ///
    /// Returns B's signalled fax address when a relay was installed.
    pub(super) fn install_answer_image(
        &self,
        call_id: &str,
        profile: &ProfileFlags,
        info: &sdp::MediaInfo,
        near: &Leg,
        far: &Leg,
        offer_received_from: Option<std::net::IpAddr>,
    ) -> Option<SocketAddr> {
        let (near_image, far_image, answered) = (near.image?, far.image?, info.image.as_ref()?);
        // RFC 3264 §6: port 0 is the answerer declining the stream. An unrelayable transport in the
        // *answer* is the same refusal by another route — the engine offered `udptl` and got back
        // something it cannot carry.
        if answered.remote.port() == 0 || !answered.transport.is_relayable() {
            return None;
        }
        // A's own fax address came in with the offer that anchored the stream, so it is known by the
        // time an answer arrives. Without it there is nothing to gate A's side to, and a relay whose
        // gate cannot be set is not installed — never installed with the gate left open.
        let Some(near_signalled) = near.image_remote else {
            tracing::warn!(
                target: "siphon_rtp::fax",
                %call_id,
                "the offerer's fax address is unknown; the T.38 stream is not relayed"
            );
            return None;
        };
        let far_gate = apply_received_from(Some(answered.remote), profile.received_from)
            .unwrap_or(answered.remote);
        let near_gate = apply_received_from(Some(near_signalled), offer_received_from)
            .unwrap_or(near_signalled);
        for (endpoint, label) in [(near_image.id, "near"), (far_image.id, "far")] {
            if let Err(error) = self.datapath.install_flow(endpoint, FlowAction::Redirect) {
                tracing::warn!(
                    target: "siphon_rtp::fax",
                    %call_id, %error, leg = label,
                    "could not redirect a fax endpoint; the T.38 stream is not relayed"
                );
                return None;
            }
        }
        self.udptl.register(
            UdptlCall::new(
                call_id.to_string(),
                UdptlDirectionConfig {
                    ingress_endpoint: near_image.id,
                    accepted_source: bridge_source_filter(profile, near_gate),
                    egress_endpoint: far_image.id,
                    egress_dst: Some(far_gate),
                },
                UdptlDirectionConfig {
                    ingress_endpoint: far_image.id,
                    accepted_source: bridge_source_filter(profile, far_gate),
                    egress_endpoint: near_image.id,
                    egress_dst: Some(near_gate),
                },
            ),
            self.datapath.clone(),
        );
        tracing::info!(
            target: "siphon_rtp::fax",
            %call_id,
            "relaying a T.38 fax stream over UDPTL"
        );
        Some(answered.remote)
    }
}
