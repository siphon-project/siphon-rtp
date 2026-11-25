//! Holding a crypto-bridged call in the decoding actor, and giving it back.
//!
//! A call on an SRTP or DTLS-SRTP crypto bridge relays ciphertext it never decodes. Holding it in
//! userspace means a [`MediaCall`] takes over the two legs' media: the same [`SecureLeg`]s (master
//! keys, rollover counters, replay windows and SRTCP index untouched), and, on each egress, the same
//! RTP stream the bridge was forwarding, so the party receiving it sees one stream throughout
//! (RFC 3711 §3.3.1, RFC 3550 §5.1). This module is the actor's half: continuing a stream, taking
//! over the taps a bridge flow carried, and reporting the same on the way back.

use std::net::SocketAddr;
use std::time::Instant;

use siphon_rtp_datapath::{EndpointId, SourceFilter};

use crate::egress_track::{continuation_timestamp, LastForwarded, StreamPosition};
use crate::plain_tap::PlainTaps;
use crate::reply_latch::SymmetricLatch;
use crate::x3::X3Taps;

use super::{Direction, MediaCall};

/// What a party's egress continues from: the last packet the bridge flow forwarded toward it and the
/// address its flow was sending to when it did.
#[derive(Clone, Copy, Debug, Default)]
pub struct HeldEgress {
    /// The stream the bridge was sending the party. `None` when it had sent nothing yet, in which
    /// case the actor numbers its own.
    pub last: Option<LastForwarded>,
    /// Where the party is now, when the bridge has learned an address newer than the signalled one.
    pub destination: Option<SocketAddr>,
    /// The position the stream's next packet is to carry, when the previous owner reports one outright
    /// (an actor handing its stream to its replacement) rather than as a last packet.
    pub next: Option<StreamPosition>,
    /// Where RTCP toward this party goes when it keeps RTCP on a port of its own (RFC 5761 §5.1.1).
    pub rtcp: Option<(EndpointId, SocketAddr)>,
}

/// The taps a bridge flow carried on one party's plaintext ingress, which move with the party.
#[derive(Clone, Default)]
pub struct HeldTaps {
    /// Lawful-interception content taps (ETSI TS 103 221-2 X3).
    pub x3: X3Taps,
    /// The plaintext RTP taps a tee or a decoded recording rides on a bridged call.
    pub plain: PlainTaps,
    /// The reply latch of the party's ingress: the source and SSRC the flow had learned. Carried so
    /// that on a symmetric leg (open gate, `SourceFilter::Any`) a stranger who sends first after a
    /// hand-over meets an established latch and is refused, not adopted as the reply destination
    /// (RTPBleed, docs/security-and-nat.md §4 layer 3).
    pub latch: SymmetricLatch,
}

/// Everything [`MediaControl::ResumeHeld`](super::MediaControl::ResumeHeld) hands the actor once the
/// bridge has let go of the call.
pub struct HeldResume {
    /// The stream toward A (the `b_to_a` direction's egress).
    pub toward_a: HeldEgress,
    /// The stream toward B (the `a_to_b` direction's egress).
    pub toward_b: HeldEgress,
    /// A's ingress taps (the `a_to_b` direction).
    pub taps_a: HeldTaps,
    /// B's ingress taps (the `b_to_a` direction).
    pub taps_b: HeldTaps,
    /// Lift the gate the actor was registered under. `false` when a DTLS key still has to arrive,
    /// which lifts it itself.
    pub ungate: bool,
}

#[derive(Clone)]
/// What the actor reports of one direction when its call goes back to a bridge: where its egress
/// stream stands and where it was sending, and the taps it was carrying.
pub struct HeldBack {
    /// The position the direction's next egress packet would have had.
    pub next: StreamPosition,
    /// Where the direction was sending.
    pub destination: SocketAddr,
    /// The ingress endpoint of the direction, and the gate in force on it.
    pub ingress: (EndpointId, SourceFilter),
    /// The direction's ingress taps.
    pub taps: HeldTaps,
}

impl Direction {
    /// The RTP clock of the egress stream and the timestamp step of one packet, in RTP ticks.
    /// Derived rather than stored: the clock is not the sample rate for every codec (G.722 samples
    /// at 16 kHz and clocks RTP at 8 kHz, RFC 3551 §4.5.2), but the step and the frame size say it.
    fn egress_ticks(&self) -> (u32, u32) {
        let frame_ticks = self.egress_timestamp_increment;
        let per_second = if self.egress_frame_samples == 0 {
            0
        } else {
            u64::from(frame_ticks) * u64::from(self.egress_sample_rate)
                / u64::from(self.egress_frame_samples)
        };
        (u32::try_from(per_second).unwrap_or(u32::MAX), frame_ticks)
    }

    /// Continue the stream a bridge was sending: the same SSRC, the next sequence number, and a
    /// timestamp advanced by the time that has passed since its last packet (RFC 3550 §5.1).
    fn continue_egress(&mut self, held: &HeldEgress, now: Instant) {
        if let Some(next) = held.next {
            self.egress_ssrc = next.ssrc;
            self.egress_sequence = next.sequence;
            self.egress_timestamp = next.timestamp;
        } else if let Some(last) = held.last {
            let (per_second, frame_ticks) = self.egress_ticks();
            self.egress_ssrc = last.position.ssrc;
            self.egress_sequence = last.position.sequence.wrapping_add(1);
            self.egress_timestamp = continuation_timestamp(
                last.position.timestamp,
                now.saturating_duration_since(last.at),
                per_second,
                frame_ticks,
            );
        }
        if let Some(destination) = held.destination {
            self.egress_dst = destination;
        }
        if held.rtcp.is_some() {
            self.rtcp_out = held.rtcp;
        }
    }

    fn adopt_taps(&mut self, taps: HeldTaps) {
        self.x3 = taps.x3;
        self.plain_taps = taps.plain;
        self.source_latch = taps.latch;
    }

    fn held_back(&mut self) -> HeldBack {
        HeldBack {
            next: StreamPosition {
                ssrc: self.egress_ssrc,
                sequence: self.egress_sequence,
                timestamp: self.egress_timestamp,
            },
            destination: self.egress_dst,
            ingress: (self.ingress_endpoint, self.accepted_source),
            taps: HeldTaps {
                x3: std::mem::take(&mut self.x3),
                plain: std::mem::take(&mut self.plain_taps),
                latch: std::mem::take(&mut self.source_latch),
            },
        }
    }
}

impl MediaCall {
    /// Register this call inert: both directions drop what reaches them until
    /// [`MediaCall::resume_held`] (or a DTLS key) lifts the gate. The bridge is still forwarding when
    /// the actor is registered, and the first packet the actor takes must already be sent under the
    /// stream the bridge was sending, which only the bridge's final position can say.
    #[must_use]
    pub fn gated_for_hold(mut self) -> Self {
        self.a_to_b.secure_pending = true;
        self.b_to_a.secure_pending = true;
        self
    }

    /// Take over what the bridge held: continue each egress stream, adopt each party's taps, and,
    /// unless a DTLS key is still to come, start taking media.
    pub fn resume_held(&mut self, resume: HeldResume) {
        let now = Instant::now();
        self.b_to_a.continue_egress(&resume.toward_a, now);
        self.a_to_b.continue_egress(&resume.toward_b, now);
        self.a_to_b.adopt_taps(resume.taps_a);
        self.b_to_a.adopt_taps(resume.taps_b);
        self.derive_x3_toward();
        if resume.ungate {
            self.a_to_b.secure_pending = false;
            self.b_to_a.secure_pending = false;
        }
    }

    /// What goes back to a bridge: A's side (the `a_to_b` direction) and B's (the `b_to_a`).
    pub fn held_back(&mut self) -> [HeldBack; 2] {
        let held = [self.a_to_b.held_back(), self.b_to_a.held_back()];
        self.derive_x3_toward();
        held
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gating_a_call_for_hold_drops_media_until_resumed() {
        let mut call = super::super::tests::ulaw_alaw_call();
        assert!(!call.a_to_b.secure_pending);
        call = call.gated_for_hold();
        assert!(call.a_to_b.secure_pending && call.b_to_a.secure_pending);
        call.resume_held(HeldResume {
            toward_a: HeldEgress::default(),
            toward_b: HeldEgress::default(),
            taps_a: HeldTaps::default(),
            taps_b: HeldTaps::default(),
            ungate: true,
        });
        assert!(!call.a_to_b.secure_pending && !call.b_to_a.secure_pending);
    }

    #[test]
    fn resuming_continues_each_stream_where_the_bridge_left_it() {
        let mut call = super::super::tests::ulaw_alaw_call().gated_for_hold();
        let at = Instant::now();
        let destination: SocketAddr = "198.51.100.7:4000".parse().expect("addr");
        call.resume_held(HeldResume {
            toward_a: HeldEgress {
                last: Some(LastForwarded {
                    position: StreamPosition {
                        ssrc: 0x1111_1111,
                        sequence: 65_535,
                        timestamp: 4_000_000_000,
                    },
                    at,
                }),
                destination: Some(destination),
                ..HeldEgress::default()
            },
            toward_b: HeldEgress::default(),
            taps_a: HeldTaps::default(),
            taps_b: HeldTaps::default(),
            ungate: false,
        });
        assert_eq!(call.b_to_a.egress_ssrc, 0x1111_1111);
        assert_eq!(call.b_to_a.egress_sequence, 0, "65535 + 1 wraps");
        assert_eq!(
            call.b_to_a.egress_timestamp,
            4_000_000_000u32.wrapping_add(call.b_to_a.egress_timestamp_increment),
            "one frame on, as no time has passed"
        );
        assert_eq!(call.b_to_a.egress_dst, destination);
        assert_ne!(
            call.a_to_b.egress_ssrc, 0x1111_1111,
            "a stream the bridge had not started keeps the actor's own SSRC"
        );
        assert!(
            call.a_to_b.secure_pending,
            "the gate stays until a key lands"
        );
    }

    #[test]
    fn handing_back_reports_the_next_position_and_takes_the_taps() {
        let mut call = super::super::tests::ulaw_alaw_call();
        let before = call.b_to_a.egress_sequence;
        let [a, b] = call.held_back();
        assert_eq!(b.next.sequence, before);
        assert_eq!(b.next.ssrc, call.b_to_a.egress_ssrc);
        assert_eq!(a.destination, call.a_to_b.egress_dst);
        assert_eq!(a.ingress.0, call.a_to_b.ingress_endpoint);
    }
}
