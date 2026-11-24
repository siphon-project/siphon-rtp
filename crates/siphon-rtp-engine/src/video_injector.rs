//! Handing a far party's out-of-band H.264 parameter sets to a caller that cannot be told them
//! (RFC 6184 §8.1, `sprop-parameter-sets`).
//!
//! On an `answer_local` + `offer_far` call the caller's SDP answer was frozen before the far party
//! answered (RFC 3264 §8). If the far encoder does not repeat its SPS and PPS in-band, the caller has
//! nothing to start its decoder with. This injector sits in the far-to-caller video flow of the
//! [`SrtpBridge`](crate::srtp_bridge::SrtpBridge) until the first IDR picture has gone through:
//!
//! 1. The caller can decode nothing before an IDR, so every far RTP packet that does not begin one is
//!    dropped ([`Verdict::Drop`]); the SPS and PPS the far party does send in-band are remembered
//!    (RFC 6184 §5.6 single NAL unit packets, §5.7.1 STAP-A).
//! 2. At the packet that begins the IDR (sequence number `S`) the sets that packet does not itself
//!    carry are sent ahead of it as single NAL unit packets (valid in packetization modes 0 and 1,
//!    RFC 6184 §5.6) under sequence numbers `S-2` and `S-1`, on the IDR's timestamp (RFC 6184 §5.1:
//!    one access unit shares one timestamp) and SSRC, marker clear (RFC 3550 §5.1), and the IDR
//!    payload type. The sets the far party sent in-band win over its `sprop-parameter-sets`, which are
//!    only its SDP's promise.
//! 3. Those two numbers were never delivered to the caller, so the IDR and everything after it pass
//!    through untouched: no renumbering, no rewritten reports or retransmission requests (RFC 3550
//!    §6.4.1 receivers compute loss from sequence numbers alone). While the flow is in userspace every
//!    packet at or before `S-1` (wrap-aware, RFC 3550 §5.1) is dropped, so a late original can never
//!    reach the caller under a number the injector used.
//! 4. The flow stays in userspace until the sequence has advanced [`SETTLE_PACKETS`] past `S` (or the
//!    timeout), then reports itself finished and the engine returns the stream to the kernel fast
//!    path, which is stateless for what remains. [`SETTLE_PACKETS`] is the reordering tolerance of
//!    RFC 3550 §A.1 (`MAX_MISORDER`, 100) and §6.4.1's loss accounting, kept a little under it for
//!    the common video rate: a packet more than that many places late is, to every RFC 3550
//!    receiver, a restart or a duplicate, not a reordered packet. The residual risk after demotion
//!    is therefore bounded: a late original `S-1` or `S-2` would have to arrive more than 64
//!    packets late, and a receiver that de-duplicates by sequence number (RFC 3550 §A.1 does)
//!    already holds the injected packet, which arrived first.
//!
//! A set that cannot be sent (the datapath refused the datagram) abandons the IDR
//! ([`VideoInjector::abandon_idr`]): nothing of that picture is forwarded, the injector goes back to
//! waiting inside its timeout, and the far party is asked for another keyframe
//! ([`VideoInjector::take_retry`]).
//!
//! If no IDR comes within [`TIMEOUT_TICKS`] sweeps the injector forwards everything unchanged (a far
//! party that cannot or will not send a keyframe must not be muted) and the engine asks it for one
//! more. Packetization mode 2 is never armed: it forbids single NAL unit packets (RFC 6184 §5.4).
//!
//! Time is the engine's once-a-second sweep ([`VideoInjector::tick`]); the injector reads no clock.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use siphon_rtp_media::h264::{self, ParameterSets, MAX_PARAMETER_SET};
use siphon_rtp_media::rtp::{write_packet, RtpHeader, RtpPacket, FIXED_HEADER_LEN};
use siphon_rtp_srtp::leg::is_rtcp;

/// How many sweeps, one a second, the injector waits for an IDR before it forwards anyway. Three, so
/// that the wait is never under the 2 s the keyframe wait of a forwarding room is (the first sweep
/// can come at once after arming).
pub const TIMEOUT_TICKS: u8 = 3;

/// How many packets past the IDR's sequence number the flow stays in userspace before it hands the
/// stream to the kernel, see the module documentation (RFC 3550 §A.1, §6.4.1).
pub const SETTLE_PACKETS: i16 = 64;

/// The most one injected packet takes: an RTP header and the largest parameter set.
const SLOT: usize = FIXED_HEADER_LEN + MAX_PARAMETER_SET;

/// What the injector decided for one datagram of the far party's stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Do not forward the datagram.
    Drop,
    /// Forward the datagram, first sending the packets [`Injection`] describes from the buffer
    /// handed to [`VideoInjector::admit`].
    Forward(Injection),
}

/// The packets [`VideoInjector::admit`] wrote into the caller's buffer, back to back, in the order
/// to send them: up to two single NAL unit packets, the SPS first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Injection {
    lengths: [usize; 2],
}

impl Injection {
    /// How many packets were written.
    #[must_use]
    pub fn count(&self) -> usize {
        self.lengths.iter().filter(|length| **length > 0).count()
    }

    /// The written packets, in sending order, out of `buffer`.
    pub fn packets<'a>(&self, buffer: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
        let mut offset = 0;
        self.lengths
            .into_iter()
            .filter(|length| *length > 0)
            .map(move |length| {
                let packet = &buffer[offset..offset + length];
                offset += length;
                packet
            })
    }
}

/// What a sweep should do about the injector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// Still waiting for the IDR (or for the stream behind it to settle).
    Pending,
    /// The injector is finished: return the stream to the kernel fast path and call
    /// [`VideoInjector::mark_demoted`]. `timed_out` is set when no IDR came, so the far party is
    /// to be asked for one more.
    Demote {
        /// No IDR arrived within [`TIMEOUT_TICKS`] sweeps.
        timed_out: bool,
    },
    /// The kernel path has carried the stream for a sweep: the bridge flow can go.
    Retire,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// No IDR yet: everything but RTCP is dropped.
    Waiting,
    /// The IDR starting at this sequence number has been forwarded; older packets are still dropped.
    Settling { start: u16 },
    /// Everything is forwarded unchanged.
    Done,
    /// No IDR came in time; everything is forwarded unchanged.
    TimedOut,
}

struct Inner {
    stage: Stage,
    ticks: u8,
    demoted: bool,
    /// What the far party sent in-band, kept for the IDR that follows.
    in_band: Box<ParameterSets>,
    /// What its SDP named.
    sprop: Box<ParameterSets>,
}

/// The first-IDR injector of one far-to-caller video flow. Shared between the bridge flow that
/// applies it and the call that tracks it.
pub struct VideoInjector {
    inner: Mutex<Inner>,
    /// Mirror of "stage is `Done` or `TimedOut`", so a settled flow takes no lock per packet.
    settled: AtomicBool,
    /// An IDR was abandoned for a failed send: the far party is to be asked for another.
    retry: AtomicBool,
}

impl std::fmt::Debug for VideoInjector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VideoInjector")
            .field("settled", &self.settled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl VideoInjector {
    /// An armed injector that falls back on `sprop`, the far party's `sprop-parameter-sets`.
    #[must_use]
    pub fn new(sprop: Box<ParameterSets>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                stage: Stage::Waiting,
                ticks: 0,
                demoted: false,
                in_band: ParameterSets::new(),
                sprop,
            }),
            settled: AtomicBool::new(false),
            retry: AtomicBool::new(false),
        }
    }

    /// The IDR [`Self::admit`] last let through could not be delivered with its parameter sets: take
    /// it back. The injector waits for the next IDR within its timeout, and [`Self::take_retry`]
    /// says a keyframe is to be asked for.
    pub fn abandon_idr(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            if matches!(inner.stage, Stage::Settling { .. }) {
                inner.stage = Stage::Waiting;
                self.settled.store(false, Ordering::Release);
                self.retry.store(true, Ordering::Release);
            }
        }
    }

    /// Whether an abandoned IDR is waiting to be asked about again; clears the mark.
    pub fn take_retry(&self) -> bool {
        self.retry.swap(false, Ordering::AcqRel)
    }

    /// Whether the injector has stopped touching the stream (it forwards everything).
    #[must_use]
    pub fn is_settled(&self) -> bool {
        self.settled.load(Ordering::Acquire)
    }

    /// Decide what to do with one datagram `datagram` that arrived from the far party, writing any
    /// packets to send ahead of it into `buffer` (reused from call to call; it grows once).
    ///
    /// RTCP (muxed on the media port, RFC 5761 §4) always passes. A datagram that is neither RTCP nor
    /// parses as RTP is dropped while the injector is armed: it is not something a decoder needs.
    pub fn admit(&self, datagram: &[u8], buffer: &mut Vec<u8>) -> Verdict {
        if self.is_settled() || is_rtcp(datagram) {
            return Verdict::Forward(Injection::default());
        }
        let Ok(mut inner) = self.inner.lock() else {
            tracing::error!(
                target: "siphon_rtp::media",
                "video injector lock poisoned; dropping the datagram"
            );
            return Verdict::Drop;
        };
        let Ok(packet) = RtpPacket::parse(datagram) else {
            return Verdict::Drop;
        };
        match inner.stage {
            Stage::Done | Stage::TimedOut => Verdict::Forward(Injection::default()),
            Stage::Waiting => {
                let found = h264::scan(packet.payload);
                inner.in_band.note(&found);
                if !found.keyframe_start {
                    return Verdict::Drop;
                }
                let injection = write_missing_sets(&inner, &found, &packet, buffer);
                inner.stage = Stage::Settling {
                    start: packet.sequence,
                };
                Verdict::Forward(injection)
            }
            Stage::Settling { start } => {
                // RFC 3550 §5.1: sequence numbers wrap, so "older" is the signed distance.
                let distance = packet.sequence.wrapping_sub(start) as i16;
                if distance < 0 {
                    return Verdict::Drop;
                }
                if distance >= SETTLE_PACKETS {
                    inner.stage = Stage::Done;
                    self.settled.store(true, Ordering::Release);
                }
                Verdict::Forward(Injection::default())
            }
        }
    }

    /// One once-a-second sweep: what the engine is to do about this injector.
    pub fn tick(&self) -> Tick {
        let Ok(mut inner) = self.inner.lock() else {
            // A poisoned injector can no longer decide; hand the stream back rather than hold it.
            return Tick::Demote { timed_out: true };
        };
        if inner.demoted {
            return Tick::Retire;
        }
        match inner.stage {
            Stage::Done => return Tick::Demote { timed_out: false },
            Stage::TimedOut => return Tick::Demote { timed_out: true },
            Stage::Waiting | Stage::Settling { .. } => {}
        }
        inner.ticks += 1;
        if inner.ticks < TIMEOUT_TICKS {
            return Tick::Pending;
        }
        // RFC 6184 §1.1: without an IDR there is nothing to decode, but a far party that never sends
        // one must not mute the call, so forward what there is.
        let timed_out = inner.stage == Stage::Waiting;
        inner.stage = if timed_out {
            Stage::TimedOut
        } else {
            Stage::Done
        };
        self.settled.store(true, Ordering::Release);
        Tick::Demote { timed_out }
    }

    /// Record that the stream is back on the kernel path: the next [`Self::tick`] says to retire.
    pub fn mark_demoted(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.demoted = true;
        }
    }

    /// Whether [`Self::tick`] has finished the injector's work and it was marked demoted.
    #[must_use]
    pub fn is_demoted(&self) -> bool {
        self.inner.lock().is_ok_and(|inner| inner.demoted)
    }
}

/// Write the SPS and PPS the IDR packet `packet` does not carry into `buffer`, under the two
/// sequence numbers before it. In-band sets win over `sprop`.
fn write_missing_sets(
    inner: &Inner,
    found: &h264::Scan<'_>,
    packet: &RtpPacket<'_>,
    buffer: &mut Vec<u8>,
) -> Injection {
    let wanted = [
        found
            .sps
            .is_none()
            .then(|| inner.in_band.sps().or_else(|| inner.sprop.sps()))
            .flatten(),
        found
            .pps
            .is_none()
            .then(|| inner.in_band.pps().or_else(|| inner.sprop.pps()))
            .flatten(),
    ];
    let count = wanted.iter().flatten().count();
    let mut injection = Injection::default();
    if count == 0 {
        return injection;
    }
    buffer.clear();
    buffer.resize(2 * SLOT, 0);
    let mut offset = 0;
    let mut distance = count as u16;
    for (index, unit) in wanted.into_iter().enumerate() {
        let Some(unit) = unit else {
            continue;
        };
        let header = RtpHeader {
            marker: false,
            payload_type: packet.payload_type,
            sequence: packet.sequence.wrapping_sub(distance),
            timestamp: packet.timestamp,
            ssrc: packet.ssrc,
        };
        // Cannot fail: each slot holds the header and the largest set. If it did, the set is simply
        // not sent and the IDR still goes.
        let Ok(length) = write_packet(&header, unit, &mut buffer[offset..]) else {
            continue;
        };
        injection.lengths[index] = length;
        offset += length;
        distance -= 1;
    }
    buffer.truncate(offset);
    injection
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    const SPS: [u8; 4] = [0x67, 0x42, 0xE0, 0x1F];
    const PPS: [u8; 3] = [0x68, 0xCE, 0x3C];
    const IN_BAND_SPS: [u8; 4] = [0x67, 0x4D, 0x00, 0x2A];
    const IDR: [u8; 4] = [0x65, 0x88, 0x84, 0x01];
    const P_SLICE: [u8; 3] = [0x41, 0x9A, 0x00];
    const SSRC: u32 = 0xAABB_CCDD;

    fn sprop() -> Box<ParameterSets> {
        let mut sets = ParameterSets::new();
        sets.store(&SPS, true);
        sets.store(&PPS, false);
        sets
    }

    fn rtp(sequence: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
        let header = RtpHeader {
            marker,
            payload_type: 97,
            sequence,
            timestamp,
            ssrc: SSRC,
        };
        let mut out = vec![0; FIXED_HEADER_LEN + payload.len()];
        let length = write_packet(&header, payload, &mut out).unwrap();
        out.truncate(length);
        out
    }

    /// A STAP-A (RFC 6184 §5.7.1) of `units`.
    fn stap_a(units: &[&[u8]]) -> Vec<u8> {
        let mut payload = vec![0x78];
        for unit in units {
            payload.extend_from_slice(&(unit.len() as u16).to_be_bytes());
            payload.extend_from_slice(unit);
        }
        payload
    }

    /// The injected packets as `(sequence, timestamp, ssrc, marker, payload type, payload)`.
    fn injected(verdict: Verdict, buffer: &[u8]) -> Vec<(u16, u32, u32, bool, u8, Vec<u8>)> {
        let Verdict::Forward(injection) = verdict else {
            panic!("expected a forward, got {verdict:?}");
        };
        injection
            .packets(buffer)
            .map(|datagram| {
                let packet = RtpPacket::parse(datagram).unwrap();
                (
                    packet.sequence,
                    packet.timestamp,
                    packet.ssrc,
                    packet.marker,
                    packet.payload_type,
                    packet.payload.to_vec(),
                )
            })
            .collect()
    }

    fn forwards_plain(verdict: Verdict) -> bool {
        verdict == Verdict::Forward(Injection::default())
    }

    #[test]
    fn everything_but_the_start_of_an_idr_is_dropped_before_it() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        for (sequence, payload) in [(1, &P_SLICE[..]), (2, &[0x7C, 0x05, 0x88][..])] {
            let datagram = rtp(sequence, 100, false, payload);
            assert_eq!(injector.admit(&datagram, &mut buffer), Verdict::Drop);
        }
        // An FU-A middle fragment of an IDR is not its start.
        let middle = rtp(3, 100, false, &[0x7C, 0x05, 0x88]);
        assert_eq!(injector.admit(&middle, &mut buffer), Verdict::Drop);
        assert!(!injector.is_settled());
    }

    #[test]
    fn an_idr_without_the_sets_is_preceded_by_the_sprop_sets_under_the_two_numbers_before_it() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        let verdict = injector.admit(&rtp(500, 9_000, true, &IDR), &mut buffer);
        let packets = injected(verdict, &buffer);
        assert_eq!(
            packets,
            vec![
                (498, 9_000, SSRC, false, 97, SPS.to_vec()),
                (499, 9_000, SSRC, false, 97, PPS.to_vec()),
            ],
            "SPS at S-2, PPS at S-1, the IDR's timestamp, SSRC and payload type, marker clear"
        );
    }

    #[test]
    fn an_idr_that_carries_both_sets_goes_through_unchanged() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        let datagram = rtp(7, 9_000, true, &stap_a(&[&IN_BAND_SPS, &PPS, &IDR]));
        assert!(forwards_plain(injector.admit(&datagram, &mut buffer)));
        assert!(buffer.is_empty());
    }

    #[test]
    fn an_idr_carrying_only_the_sps_is_sent_the_pps_alone_at_the_number_before_it() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        let datagram = rtp(7, 9_000, false, &stap_a(&[&IN_BAND_SPS, &IDR]));
        let packets = injected(injector.admit(&datagram, &mut buffer), &buffer);
        assert_eq!(packets, vec![(6, 9_000, SSRC, false, 97, PPS.to_vec())]);
    }

    #[test]
    fn sets_sent_in_band_before_the_idr_are_preferred_to_the_sprop() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        // They are not delivered at once: the injector keeps them for the IDR.
        let first = rtp(10, 9_000, false, &IN_BAND_SPS);
        let second = rtp(11, 9_000, false, &PPS);
        assert_eq!(injector.admit(&first, &mut buffer), Verdict::Drop);
        assert_eq!(injector.admit(&second, &mut buffer), Verdict::Drop);
        let verdict = injector.admit(&rtp(12, 9_000, true, &IDR), &mut buffer);
        let packets = injected(verdict, &buffer);
        assert_eq!(
            packets[0].5, IN_BAND_SPS,
            "the in-band SPS beats the sprop one"
        );
        assert_eq!(packets[1].5, PPS);
        assert_eq!((packets[0].0, packets[1].0), (10, 11));
    }

    #[test]
    fn a_missing_source_for_one_set_sends_the_other_alone() {
        let mut only_sps = ParameterSets::new();
        only_sps.store(&SPS, true);
        let injector = VideoInjector::new(only_sps);
        let mut buffer = Vec::new();
        let packets = injected(
            injector.admit(&rtp(20, 5, true, &IDR), &mut buffer),
            &buffer,
        );
        assert_eq!(packets, vec![(19, 5, SSRC, false, 97, SPS.to_vec())]);
    }

    #[test]
    fn nothing_at_or_before_the_idr_minus_one_passes_until_the_stream_is_well_past_it() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        assert!(matches!(
            injector.admit(&rtp(500, 9_000, true, &IDR), &mut buffer),
            Verdict::Forward(_)
        ));
        // The IDR's marker does not end the wait: older packets may still be in flight.
        assert!(!injector.is_settled());
        for old in [499, 498, 497] {
            let late = rtp(old, 8_000, false, &P_SLICE);
            assert_eq!(injector.admit(&late, &mut buffer), Verdict::Drop, "{old}");
        }
        // Packets after it go through but do not settle it until SETTLE_PACKETS past.
        for sequence in 501..500 + SETTLE_PACKETS as u16 {
            let next = rtp(sequence, 9_000, false, &P_SLICE);
            assert!(
                forwards_plain(injector.admit(&next, &mut buffer)),
                "{sequence}"
            );
            assert!(!injector.is_settled(), "{sequence}");
        }
        let last = rtp(500 + SETTLE_PACKETS as u16, 9_000, false, &P_SLICE);
        assert!(forwards_plain(injector.admit(&last, &mut buffer)));
        assert!(injector.is_settled());
        // Settled: the kernel path carries the stream.
        let old = rtp(499, 8_000, false, &P_SLICE);
        assert!(forwards_plain(injector.admit(&old, &mut buffer)));
    }

    #[test]
    fn a_late_zero_is_dropped_when_the_idr_is_one_and_the_sets_took_65535_and_zero() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        let verdict = injector.admit(&rtp(1, 9_000, false, &IDR), &mut buffer);
        let sequences: Vec<u16> = injected(verdict, &buffer).iter().map(|p| p.0).collect();
        assert_eq!(sequences, [65_535, 0]);
        for late in [0u16, 65_535, 65_534] {
            let packet = rtp(late, 8_000, false, &P_SLICE);
            assert_eq!(
                injector.admit(&packet, &mut buffer),
                Verdict::Drop,
                "{late}"
            );
        }
        // Across the wrap the stream still advances to the settle point.
        let past = rtp(
            1u16.wrapping_add(SETTLE_PACKETS as u16),
            9_000,
            false,
            &P_SLICE,
        );
        assert!(forwards_plain(injector.admit(&past, &mut buffer)));
        assert!(injector.is_settled());
    }

    #[test]
    fn a_duplicate_of_the_idr_start_is_forwarded_and_does_not_settle_it() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        injector.admit(&rtp(500, 9_000, false, &IDR), &mut buffer);
        let duplicate = rtp(500, 9_000, false, &IDR);
        assert!(forwards_plain(injector.admit(&duplicate, &mut buffer)));
        assert!(!injector.is_settled());
    }

    #[test]
    fn an_abandoned_idr_waits_for_the_next_one_and_asks_for_it() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        assert!(matches!(
            injector.admit(&rtp(500, 9_000, true, &IDR), &mut buffer),
            Verdict::Forward(_)
        ));
        assert!(!injector.take_retry());
        injector.abandon_idr();
        assert!(injector.take_retry());
        assert!(!injector.take_retry(), "the mark is cleared once read");
        // Back to waiting: a slice is dropped again, and the next IDR is injected again.
        let slice = rtp(501, 9_000, false, &P_SLICE);
        assert_eq!(injector.admit(&slice, &mut buffer), Verdict::Drop);
        let packets = injected(
            injector.admit(&rtp(600, 12_000, true, &IDR), &mut buffer),
            &buffer,
        );
        assert_eq!(packets.iter().map(|p| p.0).collect::<Vec<_>>(), [598, 599]);
        // Abandoning is a no-op once settled.
        injector.tick();
        injector.tick();
        injector.tick();
        injector.abandon_idr();
        assert!(!injector.take_retry());
    }

    #[test]
    fn rtcp_passes_and_an_unparsable_datagram_is_dropped_while_armed() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        let report = [0x80, 201, 0, 1, 0xCA, 0xFE, 0xBA, 0xBE];
        assert!(forwards_plain(injector.admit(&report, &mut buffer)));
        assert_eq!(injector.admit(&[0x80, 96, 0], &mut buffer), Verdict::Drop);
        assert_eq!(injector.admit(&[], &mut buffer), Verdict::Drop);
        assert!(!injector.is_settled());
    }

    #[test]
    fn the_timeout_forwards_unchanged_and_says_it_ran_out() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        assert_eq!(injector.tick(), Tick::Pending);
        assert_eq!(injector.tick(), Tick::Pending);
        assert_eq!(injector.tick(), Tick::Demote { timed_out: true });
        assert!(injector.is_settled());
        let slice = rtp(1, 100, false, &P_SLICE);
        assert!(forwards_plain(injector.admit(&slice, &mut buffer)));
    }

    #[test]
    fn a_finished_injection_demotes_on_the_next_sweep_and_retires_once_marked() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        injector.admit(&rtp(500, 9_000, true, &IDR), &mut buffer);
        let past = rtp(500 + SETTLE_PACKETS as u16, 9_000, false, &P_SLICE);
        injector.admit(&past, &mut buffer);
        assert_eq!(injector.tick(), Tick::Demote { timed_out: false });
        // Until the engine reports the kernel rule back, the sweep asks again.
        assert_eq!(injector.tick(), Tick::Demote { timed_out: false });
        injector.mark_demoted();
        assert!(injector.is_demoted());
        assert_eq!(injector.tick(), Tick::Retire);
    }

    #[test]
    fn an_idr_that_never_settles_is_given_up_on_by_the_timeout_without_asking_again() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        injector.admit(&rtp(500, 9_000, false, &IDR), &mut buffer);
        assert_eq!(injector.tick(), Tick::Pending);
        assert_eq!(injector.tick(), Tick::Pending);
        assert_eq!(injector.tick(), Tick::Demote { timed_out: false });
    }

    #[test]
    fn a_far_party_that_changes_ssrc_before_its_idr_is_still_served() {
        let injector = VideoInjector::new(sprop());
        let mut buffer = Vec::new();
        let mut restarted = rtp(40, 7, true, &IDR);
        restarted[11] ^= 0xFF;
        let verdict = injector.admit(&restarted, &mut buffer);
        let packets = injected(verdict, &buffer);
        assert_eq!(packets.len(), 2);
        assert_eq!(
            packets[0].2,
            SSRC ^ 0xFF,
            "the injected sets follow the IDR's SSRC"
        );
    }

    use proptest::prelude::*;

    proptest! {
        /// Whatever arrives from the far party, the injector neither panics nor writes more than two
        /// parameter-set packets, each of which parses as RTP on the datagram's own SSRC.
        #[test]
        fn arbitrary_datagrams_never_panic_and_inject_well_formed_packets(
            datagrams in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..200), 1..40)
        ) {
            let injector = VideoInjector::new(sprop());
            let mut buffer = Vec::new();
            for datagram in &datagrams {
                if let Verdict::Forward(found) = injector.admit(datagram, &mut buffer) {
                    prop_assert!(found.count() <= 2);
                    for written in found.packets(&buffer) {
                        let parsed = RtpPacket::parse(written).unwrap();
                        prop_assert_eq!(parsed.ssrc, u32::from_be_bytes([datagram[8], datagram[9], datagram[10], datagram[11]]));
                    }
                }
            }
        }
    }
}
