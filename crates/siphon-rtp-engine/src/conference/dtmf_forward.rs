//! Forwarding a seat's RFC 4733 telephone-events to the other seats of a mixing room.
//!
//! A seat set to [`ConferenceDtmf::Forward`] has each telephone-event packet it sends regenerated
//! toward every other seat, live, packet by packet (the start, the updates and the redundant End
//! packets), so the tone lasts as long as the key is held. Each target gets the event in its own
//! negotiated payload type and clock, on its own egress stream: its SSRC, the next sequence number of
//! its audio stream and a timestamp taken from its own audio clock (RFC 4733 §2.5.1.2).
//!
//! The room mixes audio and drops the source's event packets from the mix, so this is a second path
//! beside the mix, not part of it.

use siphon_rtp_datapath::EndpointId;
use siphon_rtp_media::dtmf::rescale_event;
use siphon_rtp_proto::ConferenceDtmf;

use super::{destination_usable, Conference, Participant};
use crate::media_pipeline::Outbound;
use bytes::Bytes;

/// The longest telephone-event payload forwarded: four 4-octet blocks (RFC 4733 §2.3). A packet
/// that carries more is forwarded up to this many blocks.
pub(super) const MAX_EVENT_PAYLOAD: usize = 16;

/// RFC 4733 §2.3: a telephone-event payload is made of 4-octet blocks.
const EVENT_BLOCK_LEN: usize = 4;

/// The event a target seat is in the middle of being sent on behalf of another seat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ForwardedEvent {
    /// The seat the event comes from (its ingress endpoint).
    source: EndpointId,
    /// The RTP timestamp the source gave every packet of the event (RFC 4733 §2.5.1.2).
    source_timestamp: u32,
    /// The timestamp this target's copy carries: its audio clock when the event started, held for
    /// the whole event (RFC 4733 §2.5.1.2).
    base_timestamp: u32,
}

impl Conference {
    /// Switch a seat's telephone-event forwarding. Returns `false` when no seat has that tag.
    pub fn set_dtmf(&mut self, tag: &str, mode: ConferenceDtmf) -> bool {
        match self
            .participants
            .iter_mut()
            .find(|participant| participant.tag == tag)
        {
            Some(participant) => {
                participant.dtmf_mode = mode;
                true
            }
            None => false,
        }
    }

    /// Move the telephone-event packets [`Conference::ingest`] regenerated into `out`, to be sent.
    pub fn drain_forwarded(&mut self, out: &mut Vec<Outbound>) {
        out.append(&mut self.forwarded);
    }

    /// Regenerate one telephone-event packet of seat `source_index` (RTP `timestamp`, `payload`)
    /// toward every other seat that can take it.
    pub(super) fn forward_telephone_event(
        &mut self,
        source_index: usize,
        timestamp: u32,
        payload: &[u8],
    ) {
        let Some(source_event) = self.participants[source_index].telephone_event else {
            return;
        };
        let source = self.participants[source_index].ingress_endpoint;
        let whole_blocks = payload.len() / EVENT_BLOCK_LEN * EVENT_BLOCK_LEN;
        let payload = &payload[..whole_blocks.min(MAX_EVENT_PAYLOAD)];
        if payload.is_empty() {
            return;
        }
        for index in 0..self.participants.len() {
            if index == source_index {
                continue;
            }
            if let Some(reason) = skip_reason(&self.participants[index]) {
                tracing::debug!(
                    conference = %self.conference_id,
                    tag = %self.participants[index].tag,
                    reason,
                    "telephone-event not forwarded to this seat"
                );
                continue;
            }
            let target = &mut self.participants[index];
            let Some(target_event) = target.telephone_event else {
                continue;
            };
            // RFC 4733 §2.5.1.2: a new timestamp starts a new event, whose first packet carries the
            // marker (§2.5.1.3); the repeats and the End packets keep the event's start timestamp.
            let (state, first) = match target.forwarded {
                Some(state) if state.source == source && state.source_timestamp == timestamp => {
                    (state, false)
                }
                _ => (
                    ForwardedEvent {
                        source,
                        source_timestamp: timestamp,
                        base_timestamp: target.leg.egress_timestamp(),
                    },
                    true,
                ),
            };
            target.forwarded = Some(state);
            // RFC 4733 §2.3.5: durations count in the event stream's clock, so a different clock
            // rescales them.
            rescale_event(
                payload,
                source_event.clock_rate_hz,
                target_event.clock_rate_hz,
                &mut self.event_scratch,
            );
            let length = match target.leg.packetize_event(
                &self.event_scratch,
                target_event.payload_type,
                state.base_timestamp,
                first,
                &mut self.rtp,
            ) {
                Ok(length) => length,
                Err(error) => {
                    tracing::warn!(
                        conference = %self.conference_id,
                        tag = %target.tag,
                        %error,
                        "telephone-event packet could not be built"
                    );
                    continue;
                }
            };
            // SRTP: a secure seat gets the event under its own keys, like its audio (RFC 3711).
            let wire: &[u8] = if let Some(secure) = target.secure.as_mut() {
                self.secure_out.clear();
                if let Err(error) = secure.protect(&self.rtp[..length], &mut self.secure_out) {
                    tracing::warn!(
                        conference = %self.conference_id,
                        tag = %target.tag,
                        %error,
                        "telephone-event packet could not be protected; dropped"
                    );
                    continue;
                }
                &self.secure_out
            } else {
                &self.rtp[..length]
            };
            self.forwarded.push(Outbound {
                endpoint: target.egress_endpoint,
                dst: target.egress_dst,
                data: Bytes::copy_from_slice(wire),
            });
        }
    }
}

/// Why `target` is sent no forwarded event, or `None` when it can take one.
fn skip_reason(target: &Participant) -> Option<&'static str> {
    // RFC 4733 §2.1: never sent to a peer that did not accept telephone-events.
    let Some(event) = target.telephone_event else {
        return Some("no telephone-event negotiated");
    };
    // RFC 4733 §2.1: the event stream runs on the clock of the audio it accompanies. A seat whose
    // event clock is not its audio clock cannot be sent a correctly timed event.
    if event.clock_rate_hz != target.egress_clock_hz {
        return Some("telephone-event clock differs from the audio clock");
    }
    // The same guards `Conference::emit` applies to the mix: an unkeyed or unselected seat is sent
    // nothing, and a blocked, silenced or unresolved one is sent no media of any kind.
    if target.secure_pending || target.ice_pending {
        return Some("seat is not keyed or its ICE pair is not selected yet");
    }
    if target.call_seat.blocked || target.call_seat.silenced {
        return Some("seat is blocked or silenced");
    }
    if !destination_usable(target.egress_dst) {
        return Some("seat has no destination yet");
    }
    None
}
