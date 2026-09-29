//! The first packet on each leg: [`Event::MediaStarted`].
//!
//! Nothing else tells a controller that media is flowing. Every failure above the media path — a
//! gate refusing a NATed peer, a one-way SRTP key, a bot that never speaks — looks identical from
//! outside until the call ends, and a controller that has to wait for media before playing a prompt
//! can only guess how long to wait.
//!
//! Detected from the datapath's own per-endpoint activity stamp ([`Datapath::last_activity`]) rather
//! than from each packet path, for two reasons. Both backends already keep it, and keep it for
//! exactly this meaning — stamped only for a packet that cleared the source gate (§4 layer 6 of
//! docs/security-and-nat.md), `0` until one has — on every path: the userspace relay, each
//! `Redirect` consumer, and the XDP kernel program, which stamps flows userspace never sees and so
//! has no per-packet hook to raise an event from. And a poll over only the endpoints still waiting
//! costs nothing per packet.

use siphon_rtp_datapath::{Datapath, EndpointId};
use siphon_rtp_proto::{Event, LegSide};

use super::Engine;

/// How often the daemon polls for a first packet: one packetization interval, so a controller
/// waiting on media before it plays a prompt waits at most one frame longer than it had to.
pub(crate) const MEDIA_STARTED_POLL_MS: u64 = 20;

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Watch `endpoints` (a new call's RTP endpoints) for their first accepted packet. Teardown takes
    /// them out again alongside `endpoint_calls`.
    pub(super) fn watch_for_media(&self, endpoints: impl IntoIterator<Item = EndpointId>) {
        for endpoint in endpoints {
            self.awaiting_media.insert(endpoint, ());
        }
    }

    /// Emit [`Event::MediaStarted`] for every leg whose first accepted packet has landed since the
    /// last poll, once per leg. Returns how many were emitted. Cheap when nothing is waiting: it
    /// visits only endpoints still awaiting media, and a call's endpoints leave the set on their
    /// first packet or with the call.
    pub fn detect_media_started(&self) -> usize {
        // Only the legs that have started (or whose endpoint is gone) are collected, so a tick where
        // nothing arrived allocates nothing and reads nothing but each endpoint's activity stamp.
        // `0` is the datapath's "no packet accepted yet", on both backends; `None` is an endpoint
        // already released, which teardown normally takes out of the set first.
        let started: Vec<_> = self
            .awaiting_media
            .iter()
            .map(|entry| *entry.key())
            .filter(|endpoint| self.datapath.last_activity(*endpoint) != Some(0))
            .collect();
        let mut emitted = 0;
        for endpoint in started {
            self.awaiting_media.remove(&endpoint);
            let Some(call_id) = self
                .endpoint_calls
                .get(&endpoint)
                .map(|entry| entry.value().clone())
            else {
                continue;
            };
            let now = super::unix_time_ms();
            let Some((side, leg, from_tag, to_tag)) =
                self.calls.get_mut(&call_id).and_then(|mut call| {
                    let (side, leg) = if call.near.rtp.id == endpoint {
                        call.near_media_started_at_unix_ms = now;
                        (LegSide::Near, call.near)
                    } else {
                        let far = call.far.filter(|far| far.rtp.id == endpoint)?;
                        call.far_media_started_at_unix_ms = now;
                        (LegSide::Far, far)
                    };
                    Some((side, leg, call.from_tag.clone(), call.to_tag.clone()))
                })
            else {
                continue;
            };
            // Read after the call's guard is released: it consults the bridge and media registries.
            let source = self.latched_remote(&leg);
            tracing::info!(
                target: "siphon_rtp::media",
                %call_id,
                leg = ?side,
                ?source,
                signalled = ?leg.remote_rtp,
                "media started"
            );
            self.emit_call_event(
                &call_id,
                Event::MediaStarted {
                    call_id: call_id.clone(),
                    from_tag,
                    to_tag,
                    leg: side,
                    source,
                    signalled: leg.remote_rtp,
                },
            );
            emitted += 1;
        }
        emitted
    }
}
