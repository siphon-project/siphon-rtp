//! What a crypto bridge flow forwarded last, so one RTP stream can change hands without the party
//! receiving it seeing a new stream.
//!
//! A call held in the decoding media actor and released back to its crypto bridge moves each
//! party's egress between two owners that would otherwise number it independently. On an SRTP leg
//! that is not cosmetic: the receiver estimates the rollover counter from the sequence numbers of one
//! SSRC (RFC 3711 §3.3.1), so a sequence that jumps by more than half the number space under the same
//! SSRC makes the receiver's index guess wrong and every following packet fail authentication.
//! Continuing the same SSRC with `sequence + 1` keeps that estimate right.
//!
//! Each bridge flow therefore records the position of the stream it forwards ([`EgressTrack`]). Going
//! to the actor, [`EgressTrack::seal`] stops the flow and hands that position over. Coming back, the
//! rebuilt flow starts from [`EgressTrack::continuing`] and, on the first packet of the same SSRC,
//! fixes a constant sequence and timestamp offset for the rest of the call.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Where one RTP stream stands (RFC 3550 §5.1): its SSRC, sequence number and timestamp. Whether it
/// names the last packet sent or the next one to send is said by whatever holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamPosition {
    pub ssrc: u32,
    pub sequence: u16,
    pub timestamp: u32,
}

/// The last packet a flow forwarded, and when.
#[derive(Clone, Copy, Debug)]
pub struct LastForwarded {
    pub position: StreamPosition,
    pub at: Instant,
}

/// What a flow does with one RTP packet it is about to forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Forward it as it is.
    Forward,
    /// Forward it with this sequence number and timestamp instead, which continue the stream the
    /// previous owner was sending (see [`EgressTrack::continuing`]).
    Rewrite {
        sequence: u16,
        timestamp: u32,
        /// The SSRC to send it under: the packet's own, or the fresh one a flow that could not learn
        /// where the previous owner's stream stood sends under ([`EgressTrack::resolve_lost`]).
        ssrc: u32,
    },
    /// Do not forward it: the flow has been sealed and another owner sends this stream now.
    Refuse,
}

/// A constant shift of one stream's sequence number and timestamp.
#[derive(Clone, Copy, Debug)]
struct Offset {
    ssrc: u32,
    sequence: u16,
    timestamp: u32,
    /// The highest peer sequence number seen, and how far it is past the first one (the base), so a
    /// packet from before the base is told by its wrap-aware distance (RFC 3550 Appendix A.1 style).
    peer_high: u16,
    high: i64,
}

/// How many SSRCs a flow remembers the high-water mark of. A stream that changes SSRC more often than
/// this in one call forgets the oldest; [`SecureLeg`](siphon_rtp_srtp::leg::SecureLeg) still refuses
/// any index it has already sent, whatever this forgot.
const HIGH_WATER_SLOTS: usize = 8;

/// How far behind its highest sequence number a stream may reorder before it is told apart from a
/// restart: the width of the send window beneath it, which refuses anything older anyway.
const REORDER_TOLERANCE: i32 = 64;

/// How many incoming streams a guarded flow follows for discontinuities.
const EPOCH_SLOTS: usize = 8;

/// The longest arrival spacing between consecutive packets a timestamp step is learned from. Past
/// it the gap is silence, not a frame (RFC 3551 §4.1: a suppressed silence leaves a hole in the
/// timestamps).
const MAX_FRAME_SPACING: Duration = Duration::from_secs(1);

/// How far a learned timestamp step may change in one measurement: a few frames of packetisation, not
/// a gap in the clock.
const MAX_STEP_RATIO: u32 = 8;

/// One incoming stream as a guarded flow numbers it on the way out.
///
/// A plain source may restart its sequence number under the same SSRC (legal RTP: a re-INVITE to
/// another media server behind a B2BUA) or reuse an SSRC after a long gap. Relayed verbatim onto an
/// SRTP leg that is a stream whose index the leg has already sent, or whose jump no receiver can place
/// in the right rollover (RFC 3711 §3.3.1), and the leg's send window would refuse it for as long as
/// the old indices stay in range: a one-way outage. A translator may renumber a source's stream
/// (RFC 3550 §7.1, §8.2), so on a discontinuity the flow carries on from its own high-water mark.
#[derive(Clone, Copy)]
struct Epoch {
    ssrc: u32,
    /// The highest sequence number and its timestamp the peer sent, as the peer numbered it.
    peer_high: u16,
    peer_timestamp: u32,
    /// What the flow adds to the peer's numbering, constant until the next discontinuity.
    sequence_offset: u16,
    timestamp_offset: u32,
    /// The highest position sent in the flow's own numbering, and when it advanced.
    out_sequence: u16,
    out_timestamp: u32,
    out_at: Instant,
    /// The timestamp step of consecutive packets and their arrival spacing, to move a continued
    /// timestamp on by the quiet there has been in whole frames, as a hold does.
    step: u32,
    /// Whether `step` was learned from the stream, not guessed: a guessed one may be replaced by any
    /// sane measurement, a learned one only by a plausible change of packetisation.
    step_known: bool,
    interval: Duration,
    arrived: Instant,
    touched: u64,
}

impl Epoch {
    /// Whether the flow moves this stream's numbering on from its own position: the flow has
    /// renumbered it, so the numbering is not the peer's and cannot be dropped and rebuilt.
    fn renumbering(&self) -> bool {
        self.sequence_offset != 0 || self.timestamp_offset != 0
    }
}

#[derive(Default)]
struct TrackState {
    /// The high-water mark of the last few SSRCs forwarded: a delayed packet of one stream, arriving
    /// after another stream's, must not pull that stream's mark back.
    slots: [Option<LastForwarded>; HIGH_WATER_SLOTS],
    /// The slot of the SSRC that most recently advanced: the stream a successor continues.
    current: usize,
    /// Streams a guarded flow follows for restarts of their numbering.
    epochs: [Option<Epoch>; EPOCH_SLOTS],
    /// Counts packets, to give up the least recently used stream.
    tick: u64,
    /// This flow feeds an SRTP leg, so a discontinuity in what it forwards is renumbered.
    guarded: bool,
    /// The position the packet admitted last goes out with, recorded by [`EgressTrack::commit`] once
    /// it has been protected: a packet the sender refused must leave no mark.
    pending: Option<(StreamPosition, Instant)>,
    sealed: bool,
    /// Nothing is forwarded until [`EgressTrack::resolve`] says where the stream stands: the flow was
    /// registered while the actor that owned the stream was still running.
    awaiting: bool,
    /// The position the previous owner's next packet would have had; consumed by the first RTP
    /// packet **of that SSRC**: a packet of another stream does not spend it.
    resume: Option<StreamPosition>,
    offset: Option<Offset>,
    /// Every packet leaves under its own SSRC XOR this, which is never zero: a fresh stream for the
    /// rest of the call.
    fresh_mask: Option<u32>,
}

/// The record of one flow's forwarded stream. One writer (the flow's own datagram handler) and one
/// occasional reader (the engine moving the call), so a plain mutex held for a handful of
/// instructions.
#[derive(Default)]
pub struct EgressTrack {
    state: Mutex<TrackState>,
    /// Mirrors `sealed || awaiting`, so the per-packet "does this flow forward at all" check before the
    /// latch is one relaxed load rather than a second lock.
    refusing: AtomicBool,
}

impl TrackState {
    /// Number a packet of a guarded flow: verbatim while the peer's sequence is continuous, and on a
    /// discontinuity (a jump back beyond reordering, or a jump forward of half the space or more,
    /// which a receiver's rollover estimate reads as one) carrying on from the flow's high-water
    /// mark with a timestamp moved on as a hold moves it. Returns the numbering and whether it
    /// differs from the peer's.
    fn remap(
        &mut self,
        ssrc: u32,
        sequence: u16,
        timestamp: u32,
        now: Instant,
        sent: impl FnOnce(u32) -> Option<u16>,
    ) -> (u16, u32, bool) {
        self.tick += 1;
        let found = self
            .epochs
            .iter()
            .position(|epoch| epoch.is_some_and(|epoch| epoch.ssrc == ssrc));
        let index = match found {
            Some(index) => index,
            None => self.follow(ssrc, sequence, timestamp, now, sent),
        };
        let Some(mut epoch) = self.epochs[index] else {
            return (sequence, timestamp, false);
        };
        let delta = i32::from(i16::from_ne_bytes(
            sequence.wrapping_sub(epoch.peer_high).to_ne_bytes(),
        ));
        if delta < -REORDER_TOLERANCE {
            let quiet = now.saturating_duration_since(epoch.out_at);
            let interval = epoch.interval.max(Duration::from_millis(1));
            let frames = ((quiet.as_nanos() + interval.as_nanos() / 2) / interval.as_nanos())
                .clamp(1, 1_000_000) as u32;
            epoch.sequence_offset = epoch.out_sequence.wrapping_add(1).wrapping_sub(sequence);
            epoch.timestamp_offset = epoch
                .out_timestamp
                .wrapping_add(epoch.step.wrapping_mul(frames))
                .wrapping_sub(timestamp);
            epoch.peer_high = sequence;
            epoch.peer_timestamp = timestamp;
            epoch.arrived = now;
            tracing::warn!(
                target: "siphon_rtp::media",
                ssrc,
                "the sequence number of a relayed stream restarted or jumped; the flow carries on from its \
                 own position (RFC 3550 §7.1) so a secure peer's SRTP index never repeats"
            );
        } else if delta > 0 {
            if delta == 1 {
                // Learned only from consecutive packets with sane spacing: a silence suppressed
                // between two of them (RFC 3551 §4.1, RFC 3389) is a gap in the clock, not a longer
                // frame, and would otherwise be added again at every later restart.
                let spacing = now.saturating_duration_since(epoch.arrived);
                if spacing <= MAX_FRAME_SPACING {
                    let step = timestamp.wrapping_sub(epoch.peer_timestamp);
                    let plausible = step != 0
                        && step < 1 << 20
                        && (!epoch.step_known
                            || (step <= epoch.step.saturating_mul(MAX_STEP_RATIO)
                                && step.saturating_mul(MAX_STEP_RATIO) >= epoch.step));
                    if plausible {
                        epoch.step = step;
                        epoch.step_known = true;
                    }
                    epoch.interval =
                        (epoch.interval * 7 + spacing.max(Duration::from_millis(1))) / 8;
                }
            }
            epoch.peer_high = sequence;
            epoch.peer_timestamp = timestamp;
            epoch.arrived = now;
        }
        let out_sequence = sequence.wrapping_add(epoch.sequence_offset);
        let out_timestamp = timestamp.wrapping_add(epoch.timestamp_offset);
        if i16::from_ne_bytes(out_sequence.wrapping_sub(epoch.out_sequence).to_ne_bytes()) > 0 {
            epoch.out_sequence = out_sequence;
            epoch.out_timestamp = out_timestamp;
            epoch.out_at = now;
        }
        epoch.touched = self.tick;
        self.epochs[index] = Some(epoch);
        (
            out_sequence,
            out_timestamp,
            epoch.sequence_offset != 0 || epoch.timestamp_offset != 0,
        )
    }

    /// Start following a stream this flow has no epoch for, in the slot of the stream whose numbering
    /// matters least (one the flow has not renumbered goes first), and return that slot.
    ///
    /// The sender's own record is the authority on where the stream stands: an SSRC that was followed
    /// before and came back (its epoch given up) carries on from what the leg has sent, not from the
    /// peer's numbering, which has restarted (RFC 3711 §3.3.1, §9.1; RFC 3550 §8.2).
    fn follow(
        &mut self,
        ssrc: u32,
        sequence: u16,
        timestamp: u32,
        now: Instant,
        sent: impl FnOnce(u32) -> Option<u16>,
    ) -> usize {
        let slot = self
            .epochs
            .iter()
            .position(Option::is_none)
            .or_else(|| {
                self.epochs
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, epoch)| {
                        epoch.map(|epoch| (epoch.renumbering(), epoch.touched))
                    })
                    .map(|(index, _)| index)
            })
            .unwrap_or(0);
        let mut epoch = Epoch {
            ssrc,
            peer_high: sequence,
            peer_timestamp: timestamp,
            sequence_offset: 0,
            timestamp_offset: 0,
            out_sequence: sequence,
            out_timestamp: timestamp,
            out_at: now,
            step: 160,
            step_known: false,
            interval: Duration::from_millis(20),
            arrived: now,
            touched: self.tick,
        };
        let out_ssrc = ssrc ^ self.fresh_mask.unwrap_or(0);
        if self.guarded {
            if let Some(highest) = sent(out_ssrc) {
                let behind = i32::from(i16::from_ne_bytes(
                    highest.wrapping_sub(sequence).to_ne_bytes(),
                ));
                if behind >= 0 {
                    // The peer's first packet of this stream is at or below what was already sent
                    // under its SSRC (a restore or rebuild closed everything up to there, or the
                    // flow gave this stream up): carry on from the sender's own position at once,
                    // not when the peer has caught up.
                    let last = self
                        .slots
                        .iter()
                        .flatten()
                        .find(|last| last.position.ssrc == out_ssrc)
                        .map(|last| last.position.timestamp);
                    epoch.sequence_offset = highest.wrapping_add(1).wrapping_sub(sequence);
                    epoch.out_sequence = highest;
                    if let Some(last) = last {
                        epoch.timestamp_offset =
                            last.wrapping_add(epoch.step).wrapping_sub(timestamp);
                        epoch.out_timestamp = last;
                    }
                    tracing::warn!(
                        target: "siphon_rtp::media",
                        ssrc,
                        "a relayed stream returned with numbering behind what was already sent under                          its SSRC; the flow carries on from the sender's own position (RFC 3550 §8.2)"
                    );
                }
            }
        }
        self.epochs[slot] = Some(epoch);
        slot
    }

    /// The most recent advancing stream's high-water mark.
    fn current(&self) -> Option<LastForwarded> {
        self.slots[self.current]
    }

    /// Fold a packet sent as `position` into the per-SSRC high-water marks: the mark only moves
    /// forward, by wrap-aware distance, and the stream that advanced becomes the current one.
    fn record(&mut self, position: StreamPosition, at: Instant) {
        let found = self
            .slots
            .iter()
            .position(|slot| slot.is_some_and(|last| last.position.ssrc == position.ssrc));
        match found {
            Some(index) => {
                let advances = self.slots[index].is_none_or(|last| {
                    i16::from_ne_bytes(
                        position
                            .sequence
                            .wrapping_sub(last.position.sequence)
                            .to_ne_bytes(),
                    ) > 0
                });
                if advances {
                    self.slots[index] = Some(LastForwarded { position, at });
                    self.current = index;
                }
            }
            None => {
                // A free slot, else the stream that advanced least recently.
                let index = self
                    .slots
                    .iter()
                    .position(Option::is_none)
                    .or_else(|| {
                        self.slots
                            .iter()
                            .enumerate()
                            .min_by_key(|(_, slot)| slot.map(|last| last.at))
                            .map(|(index, _)| index)
                    })
                    .unwrap_or(0);
                self.slots[index] = Some(LastForwarded { position, at });
                self.current = index;
            }
        }
    }
}

/// The SSRC, sequence number and timestamp of an RTP packet, or `None` for anything that is not one
/// (too short, not version 2, or an RTCP packet, told apart by its payload-type byte, RFC 5761 §4).
fn rtp_header(packet: &[u8]) -> Option<(u32, u16, u32)> {
    let header = packet.get(..12)?;
    if header[0] >> 6 != 2 || (64..=95).contains(&(header[1] & 0x7f)) {
        return None;
    }
    Some((
        u32::from_be_bytes([header[8], header[9], header[10], header[11]]),
        u16::from_be_bytes([header[2], header[3]]),
        u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
    ))
}

/// Write `sequence`, `timestamp` and `ssrc` into the RTP header of `packet` (a no-op on a short one).
pub fn write_header_fields(packet: &mut [u8], sequence: u16, timestamp: u32, ssrc: u32) {
    if let Some(header) = packet.get_mut(..12) {
        header[2..4].copy_from_slice(&sequence.to_be_bytes());
        header[4..8].copy_from_slice(&timestamp.to_be_bytes());
        header[8..12].copy_from_slice(&ssrc.to_be_bytes());
    }
}

impl EgressTrack {
    /// A track for a flow that takes over a stream another owner was sending: `next` is the position
    /// that owner's next packet would have had. The first RTP packet of that SSRC the flow forwards
    /// is numbered `next`, and every later one keeps the same offset.
    pub fn continuing(next: Option<StreamPosition>) -> Self {
        Self {
            state: Mutex::new(TrackState {
                resume: next,
                ..TrackState::default()
            }),
            refusing: AtomicBool::new(false),
        }
    }

    /// A track for a flow registered **before** the actor that owns its stream has stopped, so the
    /// endpoint never has no owner. It refuses everything until [`Self::resolve`].
    pub fn awaiting() -> Self {
        Self {
            state: Mutex::new(TrackState {
                awaiting: true,
                ..TrackState::default()
            }),
            refusing: AtomicBool::new(true),
        }
    }

    /// Say where the stream stands now the previous owner has stopped (`next`: the position its next
    /// packet would have had; `None` when it is not known, in which case the peer's own numbering
    /// stands) and start forwarding.
    pub fn resolve(&self, next: Option<StreamPosition>) {
        if let Ok(mut state) = self.state.lock() {
            state.resume = next;
            state.awaiting = false;
            self.refusing.store(state.sealed, Ordering::Relaxed);
        }
    }

    /// Start forwarding with **no** knowledge of where the previous owner's stream stood. Its position
    /// is unknown, so it may have sent under the peer's SSRC well past the peer's own numbering (an
    /// actor sends on a clock of its own, a peer in DTX sends little): resuming the peer's numbering
    /// under that SSRC could reuse an SRTP index under the same key, which breaks the keystream
    /// (RFC 3711 §3.3.1, §9.1). So every packet of this flow leaves under a **fresh random SSRC** for
    /// the rest of the call, keeping the peer's sequence number and timestamp. A new SSRC is a new
    /// SRTP crypto context at the receiver and at the sending `SecureLeg` (rollover counter 0,
    /// RFC 3711 §3.2.1), and a source changing SSRC is legitimate (RFC 3550 §8.2).
    pub fn resolve_lost(&self) {
        let mut bytes = [0u8; 4];
        let mask = match getrandom::fill(&mut bytes) {
            Ok(()) => u32::from_be_bytes(bytes),
            Err(_) => 0,
        };
        if let Ok(mut state) = self.state.lock() {
            // Zero would be the identity, so a failed or unlucky draw falls back to a fixed mask.
            state.fresh_mask = Some(if mask == 0 { 0x5A5A_5A5A } else { mask });
            state.resume = None;
            state.awaiting = false;
            self.refusing.store(state.sealed, Ordering::Relaxed);
        }
    }

    /// Decide what to do with one RTP packet of the stream this flow forwards, and record the
    /// position it goes out with. Packets that are not RTP are [`Admission::Forward`]ed unrecorded.
    pub fn admit(&self, packet: &[u8]) -> Admission {
        self.admit_at(packet, Instant::now())
    }

    /// [`Self::admit`] with the arrival instant supplied, so a test controls the clock.
    pub fn admit_at(&self, packet: &[u8], now: Instant) -> Admission {
        self.admit_with(packet, now, |_| None)
    }

    /// [`Self::admit_at`] where `sent` reports the highest sequence number the sender has sent under
    /// an SSRC. Asked only when a guarded flow meets a stream it is not following, so the common
    /// packet pays nothing for it.
    pub fn admit_with(
        &self,
        packet: &[u8],
        now: Instant,
        sent: impl FnOnce(u32) -> Option<u16>,
    ) -> Admission {
        let Some((ssrc, sequence, timestamp)) = rtp_header(packet) else {
            return Admission::Forward;
        };
        let Ok(mut state) = self.state.lock() else {
            // Poisoned by a panic elsewhere: forwarding unrecorded beats dropping the call's media.
            return Admission::Forward;
        };
        state.pending = None;
        if state.sealed || state.awaiting {
            return Admission::Refuse;
        }
        let (sequence, timestamp, renumbered) = if state.guarded {
            state.remap(ssrc, sequence, timestamp, now, sent)
        } else {
            (sequence, timestamp, false)
        };
        if let Some(mask) = state.fresh_mask {
            let out_ssrc = ssrc ^ mask;
            state.pending = Some((
                StreamPosition {
                    ssrc: out_ssrc,
                    sequence,
                    timestamp,
                },
                now,
            ));
            return Admission::Rewrite {
                sequence,
                timestamp,
                ssrc: out_ssrc,
            };
        }
        // RFC 3550 §8.2: a stream that is not the one the previous owner was sending is a new
        // source, and numbers itself. Only the same SSRC continues, and it continues whenever it
        // shows up: another stream arriving first does not spend the position.
        if state.resume.is_some_and(|next| next.ssrc == ssrc) {
            if let Some(next) = state.resume.take() {
                state.offset = Some(Offset {
                    ssrc,
                    sequence: next.sequence.wrapping_sub(sequence),
                    timestamp: next.timestamp.wrapping_sub(timestamp),
                    peer_high: sequence,
                    high: 0,
                });
            }
        }
        let (admission, out_sequence, out_timestamp) = match state.offset.as_mut() {
            Some(offset) if offset.ssrc == ssrc => {
                // A packet from before the first one this flow took over would land on an index the
                // previous owner already used under the same SSRC and key (RFC 3711 §3.3.1, §9.1).
                let relative = offset.high
                    + i64::from(i16::from_ne_bytes(
                        sequence.wrapping_sub(offset.peer_high).to_ne_bytes(),
                    ));
                if relative < 0 {
                    return Admission::Refuse;
                }
                if relative > offset.high {
                    offset.high = relative;
                    offset.peer_high = sequence;
                }
                let out_sequence = sequence.wrapping_add(offset.sequence);
                let out_timestamp = timestamp.wrapping_add(offset.timestamp);
                (
                    Admission::Rewrite {
                        sequence: out_sequence,
                        timestamp: out_timestamp,
                        ssrc,
                    },
                    out_sequence,
                    out_timestamp,
                )
            }
            _ if renumbered => (
                Admission::Rewrite {
                    sequence,
                    timestamp,
                    ssrc,
                },
                sequence,
                timestamp,
            ),
            _ => (Admission::Forward, sequence, timestamp),
        };
        // The position is the high-water mark of its SSRC, not the last arrival (a delayed packet
        // must not pull it back, or whoever takes over would restart at an index already sent), and
        // it is recorded only by `commit`, once the packet has actually been protected.
        state.pending = Some((
            StreamPosition {
                ssrc,
                sequence: out_sequence,
                timestamp: out_timestamp,
            },
            now,
        ));
        admission
    }

    /// Record the packet [`Self::admit`] last allowed as sent. Called once it has been protected (or,
    /// toward a plain peer, at once): a packet the sender refused leaves no mark, so a delayed packet
    /// of a stream whose mark was forgotten cannot become its high-water.
    pub fn commit(&self) {
        if let Ok(mut state) = self.state.lock() {
            if let Some((position, at)) = state.pending.take() {
                state.record(position, at);
            }
        }
    }

    /// Follow this flow's forwarded streams for restarts of their numbering and renumber one that
    /// restarts: the flow feeds an SRTP leg. See `Epoch`.
    pub fn guard(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.guarded = true;
        }
    }

    /// A track for a flow that feeds an SRTP leg, which renumbers a stream that restarts.
    #[must_use]
    pub fn guarded() -> Self {
        let track = Self::default();
        track.guard();
        track
    }

    /// The packet [`Self::admit`] last allowed was refused by the sender with `error`. For an index it
    /// had already sent, or a jump it cannot place, a packet merely reordered or repeated within the
    /// send window is the window's to refuse; one far from where the sender stands means this flow
    /// lost track of the stream, so it is renumbered from the sender's own position, whatever its
    /// record says.
    pub fn refused(
        &self,
        error: &siphon_rtp_srtp::SrtpError,
        sent: impl FnOnce(u32) -> Option<u16>,
    ) {
        use siphon_rtp_srtp::SrtpError;
        if matches!(error, SrtpError::IndexReused | SrtpError::SequenceJump) {
            self.resync(sent);
        }
    }

    fn resync(&self, sent: impl FnOnce(u32) -> Option<u16>) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some((position, _)) = state.pending.take() else {
            return;
        };
        if !state.guarded {
            return;
        }
        let Some(highest) = sent(position.ssrc) else {
            return;
        };
        let behind = i32::from(i16::from_ne_bytes(
            highest.wrapping_sub(position.sequence).to_ne_bytes(),
        ));
        if (0..=REORDER_TOLERANCE).contains(&behind) {
            return;
        }
        let in_ssrc = position.ssrc ^ state.fresh_mask.unwrap_or(0);
        let Some(epoch) = state
            .epochs
            .iter_mut()
            .flatten()
            .find(|epoch| epoch.ssrc == in_ssrc)
        else {
            return;
        };
        epoch.sequence_offset = highest.wrapping_sub(epoch.peer_high);
        epoch.out_sequence = highest;
        tracing::warn!(
            target: "siphon_rtp::media",
            ssrc = in_ssrc,
            "the sender refused a relayed packet far from where it stands; the flow carries on from \
             the sender's own position (RFC 3711 §3.3.1)"
        );
    }

    /// Stop this flow forwarding and report the last packet it sent. Every packet admitted after
    /// this is [`Admission::Refuse`]d, so the position returned is final: the engine reads it and
    /// the new owner numbers its first packet after it without the two ever sending the same one.
    pub fn seal(&self) -> Option<LastForwarded> {
        let mut state = self.state.lock().ok()?;
        state.sealed = true;
        self.refusing.store(true, Ordering::Relaxed);
        state.current()
    }

    /// Whether this flow forwards nothing at the moment (sealed, or awaiting its stream's position).
    /// Read before any latch decision, so a packet that cannot be forwarded cannot teach a fresh
    /// latch a source either.
    pub fn refusing(&self) -> bool {
        self.refusing.load(Ordering::Relaxed)
    }

    /// The high-water mark of `ssrc`, if this flow forwarded it.
    #[cfg(test)]
    pub(crate) fn position_of(&self, ssrc: u32) -> Option<StreamPosition> {
        let state = self.state.lock().ok()?;
        state
            .slots
            .iter()
            .flatten()
            .find(|last| last.position.ssrc == ssrc)
            .map(|last| last.position)
    }

    /// The last packet forwarded, if any.
    #[cfg(test)]
    pub fn last(&self) -> Option<LastForwarded> {
        self.state.lock().ok().and_then(|state| state.current())
    }
}

/// The datagram to forward in place of `packet`, per `track`'s verdict: `packet` itself, a copy in
/// `scratch` carrying the continued sequence number and timestamp, or `None` when the flow has been
/// sealed and must send nothing more. `sent` reports what the sender has sent under an SSRC, for a
/// flow that feeds an SRTP leg (see [`EgressTrack::admit_with`]).
pub fn continue_stream<'a>(
    track: &EgressTrack,
    packet: &'a [u8],
    scratch: &'a mut Vec<u8>,
    sent: impl FnOnce(u32) -> Option<u16>,
) -> Option<&'a [u8]> {
    match track.admit_with(packet, Instant::now(), sent) {
        Admission::Forward => Some(packet),
        Admission::Refuse => None,
        Admission::Rewrite {
            sequence,
            timestamp,
            ssrc,
        } => {
            scratch.clear();
            scratch.extend_from_slice(packet);
            write_header_fields(scratch, sequence, timestamp, ssrc);
            Some(scratch.as_slice())
        }
    }
}

/// [`continue_stream`] for a packet the caller already owns: continue it in place. `false` when the
/// flow has been sealed and the packet must not be sent.
pub fn continue_in_place(track: &EgressTrack, packet: &mut [u8]) -> bool {
    match track.admit(packet) {
        Admission::Forward => true,
        Admission::Refuse => false,
        Admission::Rewrite {
            sequence,
            timestamp,
            ssrc,
        } => {
            write_header_fields(packet, sequence, timestamp, ssrc);
            true
        }
    }
}

/// Report why a packet could not be encrypted for a peer. A refusal for reusing an SRTP index is
/// never routine (it means a stream was handed between owners with the wrong numbering, and the
/// sender context stopped a keystream being reused, RFC 3711 §9.1), so it is an `error!` with its
/// context; anything else stays a `debug!`.
pub fn log_protect_failure(error: &siphon_rtp_srtp::SrtpError, context: &str, refused_so_far: u64) {
    use siphon_rtp_srtp::SrtpError;
    if matches!(
        error,
        SrtpError::IndexReused | SrtpError::SequenceJump | SrtpError::IndexExhausted
    ) {
        tracing::error!(
            target: "siphon_rtp::media",
            context,
            refused_so_far,
            %error,
            "refused to protect a packet that would reuse a keystream under this key (RFC 3711 §9.1); \
             a changed key or a renumbered stream is needed"
        );
    } else {
        tracing::debug!(?error, context, "egress encrypt failed; dropping packet");
    }
}

/// The timestamp the first packet after a hand-over carries: the last one's, advanced by the time
/// that has passed on the stream's own clock (RFC 3550 §5.1 — a timestamp is a sampling instant, so a
/// silence between two packets is in the numbers), counted in whole frames and never less than one.
///
/// `ticks_per_second` is the RTP clock of the stream and `frame_ticks` the timestamp step of one
/// packet, both in RTP clock units. Pure arithmetic, so the clock is a parameter.
pub fn continuation_timestamp(
    last_timestamp: u32,
    elapsed: Duration,
    ticks_per_second: u32,
    frame_ticks: u32,
) -> u32 {
    if frame_ticks == 0 {
        return last_timestamp;
    }
    let elapsed_ticks = elapsed
        .as_micros()
        .saturating_mul(u128::from(ticks_per_second))
        / 1_000_000;
    // Round to the nearest frame, and never go backwards: the next packet is at least one frame on.
    let frames = ((elapsed_ticks + u128::from(frame_ticks) / 2) / u128::from(frame_ticks)).max(1);
    let advance = frames.saturating_mul(u128::from(frame_ticks));
    // Truncation is the RTP timestamp's own modulo-2^32 arithmetic.
    last_timestamp.wrapping_add((advance & u128::from(u32::MAX)) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Admit a packet and, if it is let through, record it as sent: the sender protected it.
    trait Sent {
        fn sent(&self, packet: &[u8]) -> Admission;
    }

    impl Sent for EgressTrack {
        fn sent(&self, packet: &[u8]) -> Admission {
            let admission = self.admit(packet);
            if admission != Admission::Refuse {
                self.commit();
            }
            admission
        }
    }

    fn rtp(sequence: u16, timestamp: u32, ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&timestamp.to_be_bytes());
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0xFF; 160]);
        packet
    }

    #[test]
    fn records_the_position_of_what_it_forwards() {
        let track = EgressTrack::default();
        let now = Instant::now();
        assert_eq!(
            track.admit_at(&rtp(7, 1120, 0xAABB_CCDD), now),
            Admission::Forward
        );
        track.commit();
        let last = track.last().expect("a packet was forwarded");
        assert_eq!(
            last.position,
            StreamPosition {
                ssrc: 0xAABB_CCDD,
                sequence: 7,
                timestamp: 1120,
            }
        );
        assert_eq!(last.at, now);
    }

    #[test]
    fn rtcp_and_short_datagrams_are_forwarded_unrecorded() {
        let track = EgressTrack::default();
        // A sender report: payload-type byte 200 is 72 under the marker bit (RFC 5761 §4).
        let mut report = rtp(1, 1, 1);
        report[1] = 200;
        assert_eq!(track.sent(&report), Admission::Forward);
        assert_eq!(track.sent(&[0x80, 0x00, 0x00]), Admission::Forward);
        assert!(track.last().is_none());
    }

    #[test]
    fn seal_reports_the_last_packet_and_refuses_everything_after() {
        let track = EgressTrack::default();
        track.sent(&rtp(41, 6560, 9));
        let sealed = track.seal().expect("last packet");
        assert_eq!(sealed.position.sequence, 41);
        assert_eq!(track.sent(&rtp(42, 6720, 9)), Admission::Refuse);
        assert_eq!(
            track.seal().expect("still the same").position.sequence,
            41,
            "a refused packet is not recorded"
        );
    }

    #[test]
    fn a_continuing_track_numbers_its_first_packet_after_the_previous_owner() {
        let track = EgressTrack::continuing(Some(StreamPosition {
            ssrc: 5,
            sequence: 1001,
            timestamp: 160_160,
        }));
        // The peer's own numbering is unrelated to what the previous owner sent.
        assert_eq!(
            track.sent(&rtp(50, 8000, 5)),
            Admission::Rewrite {
                sequence: 1001,
                timestamp: 160_160,
                ssrc: 5,
            }
        );
        assert_eq!(
            track.sent(&rtp(51, 8160, 5)),
            Admission::Rewrite {
                sequence: 1002,
                timestamp: 160_320,
                ssrc: 5,
            },
            "the offset holds for the rest of the stream"
        );
        assert_eq!(
            track.last().expect("recorded").position.sequence,
            1002,
            "what is recorded is what went out, so a second hold continues from it"
        );
    }

    #[test]
    fn the_offset_follows_the_sequence_number_across_its_wrap() {
        let track = EgressTrack::continuing(Some(StreamPosition {
            ssrc: 5,
            sequence: 3,
            timestamp: 0,
        }));
        assert_eq!(
            track.sent(&rtp(65_534, 0, 5)),
            Admission::Rewrite {
                sequence: 3,
                timestamp: 0,
                ssrc: 5,
            }
        );
        // Peer 65535 -> 4, peer 0 -> 5: wrapping arithmetic on both sides.
        assert_eq!(
            track.sent(&rtp(65_535, 160, 5)),
            Admission::Rewrite {
                sequence: 4,
                timestamp: 160,
                ssrc: 5,
            }
        );
        assert_eq!(
            track.sent(&rtp(0, 320, 5)),
            Admission::Rewrite {
                sequence: 5,
                timestamp: 320,
                ssrc: 5,
            }
        );
    }

    #[test]
    fn another_ssrc_is_a_new_stream_and_is_not_renumbered() {
        let track = EgressTrack::continuing(Some(StreamPosition {
            ssrc: 5,
            sequence: 1001,
            timestamp: 160_160,
        }));
        assert_eq!(track.sent(&rtp(50, 8000, 6)), Admission::Forward);
        assert_eq!(
            track.sent(&rtp(51, 8160, 6)),
            Admission::Forward,
            "RFC 3550 §8.2: a different source numbers itself"
        );
    }

    #[test]
    fn a_track_with_nothing_to_continue_forwards_untouched() {
        let track = EgressTrack::continuing(None);
        assert_eq!(track.sent(&rtp(50, 8000, 5)), Admission::Forward);
    }

    #[test]
    fn continuing_a_stream_copies_only_when_it_rewrites() {
        let track = EgressTrack::continuing(Some(StreamPosition {
            ssrc: 5,
            sequence: 100,
            timestamp: 5000,
        }));
        let mut scratch = Vec::new();
        let packet = rtp(7, 70, 5);
        let sent = continue_stream(&track, &packet, &mut scratch, |_| None).expect("forwarded");
        assert_eq!(&sent[2..4], &100u16.to_be_bytes());
        assert_eq!(&sent[4..8], &5000u32.to_be_bytes());
        assert_eq!(
            &packet[2..4],
            &7u16.to_be_bytes(),
            "the original is untouched"
        );
        let mut in_place = rtp(8, 230, 5);
        assert!(continue_in_place(&track, &mut in_place));
        assert_eq!(&in_place[2..4], &101u16.to_be_bytes());
        track.seal();
        assert!(continue_stream(&track, &packet, &mut scratch, |_| None).is_none());
        assert!(!continue_in_place(&track, &mut in_place));
    }

    #[test]
    fn a_reordered_packet_does_not_move_the_recorded_position_back() {
        // Forwarded 100, then the delayed 99: the stream stands at 100, so whoever takes over starts
        // at 101 and never reuses the SRTP index 100 (RFC 3711 §3.3.1, §9.1).
        let track = EgressTrack::default();
        track.sent(&rtp(100, 16_000, 9));
        assert_eq!(track.sent(&rtp(99, 15_840, 9)), Admission::Forward);
        let sealed = track.seal().expect("last");
        assert_eq!(sealed.position.sequence, 100);
        assert_eq!(sealed.position.timestamp, 16_000);
    }

    #[test]
    fn the_high_water_position_follows_the_sequence_across_its_wrap() {
        let track = EgressTrack::default();
        track.sent(&rtp(65_535, 0, 9));
        track.sent(&rtp(0, 160, 9));
        track.sent(&rtp(65_534, 0, 9));
        assert_eq!(track.seal().expect("last").position.sequence, 0);
    }

    #[test]
    fn a_delayed_packet_from_before_the_takeover_is_refused_not_mapped_onto_a_used_index() {
        // The actor sent through 1000, so the first packet (peer 50) is 1001. A late peer 49 would map
        // to 1000: an index already used under this SSRC and key.
        let track = EgressTrack::continuing(Some(StreamPosition {
            ssrc: 5,
            sequence: 1001,
            timestamp: 160_160,
        }));
        assert!(matches!(
            track.sent(&rtp(50, 8000, 5)),
            Admission::Rewrite { sequence: 1001, .. }
        ));
        assert_eq!(track.sent(&rtp(49, 7840, 5)), Admission::Refuse);
        assert!(matches!(
            track.sent(&rtp(52, 8320, 5)),
            Admission::Rewrite { sequence: 1003, .. }
        ));
        // Behind the high-water mark but not before the base: reordering inside the stream is fine.
        assert!(matches!(
            track.sent(&rtp(51, 8160, 5)),
            Admission::Rewrite { sequence: 1002, .. }
        ));
    }

    #[test]
    fn the_refusal_of_packets_before_the_base_survives_the_sequence_wrap() {
        let track = EgressTrack::continuing(Some(StreamPosition {
            ssrc: 5,
            sequence: 10,
            timestamp: 0,
        }));
        assert!(matches!(
            track.sent(&rtp(65_535, 0, 5)),
            Admission::Rewrite { sequence: 10, .. }
        ));
        assert!(matches!(
            track.sent(&rtp(1, 320, 5)),
            Admission::Rewrite { sequence: 12, .. }
        ));
        assert_eq!(track.sent(&rtp(65_534, 0, 5)), Admission::Refuse);
    }

    #[test]
    fn a_track_awaiting_its_position_forwards_nothing_until_it_is_resolved() {
        let track = EgressTrack::awaiting();
        assert_eq!(track.sent(&rtp(7, 70, 5)), Admission::Refuse);
        assert!(track.last().is_none(), "a refused packet is not recorded");
        track.resolve(Some(StreamPosition {
            ssrc: 5,
            sequence: 300,
            timestamp: 9_000,
        }));
        assert!(matches!(
            track.sent(&rtp(8, 80, 5)),
            Admission::Rewrite { sequence: 300, .. }
        ));
        let none = EgressTrack::awaiting();
        none.resolve(None);
        assert_eq!(none.sent(&rtp(8, 80, 5)), Admission::Forward);
    }

    #[test]
    fn a_flow_that_lost_its_stream_position_sends_under_a_fresh_ssrc_keeping_the_peers_numbering() {
        let track = EgressTrack::awaiting();
        track.resolve_lost();
        let Admission::Rewrite {
            sequence,
            timestamp,
            ssrc,
        } = track.sent(&rtp(700, 112_000, 0x0A0A_0A0A))
        else {
            panic!("a fresh stream is rewritten");
        };
        assert_eq!(
            (sequence, timestamp),
            (700, 112_000),
            "the peer's own numbering"
        );
        assert_ne!(
            ssrc, 0x0A0A_0A0A,
            "never the SSRC the previous owner may have used"
        );
        // The same peer stream keeps the same fresh SSRC, and another peer SSRC gets another.
        let Admission::Rewrite { ssrc: again, .. } = track.sent(&rtp(701, 112_160, 0x0A0A_0A0A))
        else {
            panic!("rewritten");
        };
        assert_eq!(again, ssrc);
        let Admission::Rewrite { ssrc: other, .. } = track.sent(&rtp(1, 1, 0x0C0C_0C0C)) else {
            panic!("rewritten");
        };
        assert_ne!(other, again);
        assert_eq!(track.seal().expect("last").position.ssrc, other);
        // And in the packet that goes out.
        let mut packet = rtp(5, 5, 0x0A0A_0A0A);
        let fresh = EgressTrack::default();
        fresh.resolve_lost();
        assert!(continue_in_place(&fresh, &mut packet));
        assert_ne!(&packet[8..12], &0x0A0A_0A0Au32.to_be_bytes());
        assert_eq!(&packet[2..4], &5u16.to_be_bytes());
    }

    #[test]
    fn a_delayed_packet_after_another_stream_does_not_pull_its_own_mark_back() {
        let track = EgressTrack::default();
        track.sent(&rtp(100, 16_000, 0xA));
        track.sent(&rtp(1, 160, 0xB));
        track.sent(&rtp(99, 15_840, 0xA));
        assert_eq!(track.position_of(0xA).expect("A").sequence, 100);
        assert_eq!(track.position_of(0xB).expect("B").sequence, 1);
        assert_eq!(
            track.seal().expect("current").position.ssrc,
            0xB,
            "the stream that last advanced is the one a successor continues"
        );
    }

    #[test]
    fn another_stream_arriving_first_does_not_spend_the_position_to_resume() {
        let track = EgressTrack::continuing(Some(StreamPosition {
            ssrc: 0xA,
            sequence: 500,
            timestamp: 80_000,
        }));
        assert_eq!(track.sent(&rtp(7, 70, 0xB)), Admission::Forward);
        assert!(matches!(
            track.sent(&rtp(30, 4_800, 0xA)),
            Admission::Rewrite {
                sequence: 500,
                timestamp: 80_000,
                ssrc: 0xA
            }
        ));
        assert_eq!(track.sent(&rtp(8, 230, 0xB)), Admission::Forward);
    }

    #[test]
    fn a_flow_remembers_the_marks_of_a_few_streams_and_gives_up_the_oldest() {
        let track = EgressTrack::default();
        for ssrc in 1..=9u32 {
            track.sent(&rtp(10, 0, ssrc));
        }
        assert!(track.position_of(1).is_none(), "the oldest went");
        for ssrc in 2..=9u32 {
            assert!(track.position_of(ssrc).is_some());
        }
    }

    fn guarded() -> EgressTrack {
        EgressTrack::guarded()
    }

    /// The numbering a guarded flow sends `packet` under.
    fn numbered(track: &EgressTrack, packet: &[u8]) -> (u16, u32, u32) {
        match track.sent(packet) {
            Admission::Forward => {
                let (ssrc, sequence, timestamp) = rtp_header(packet).expect("rtp");
                (sequence, timestamp, ssrc)
            }
            Admission::Rewrite {
                sequence,
                timestamp,
                ssrc,
            } => (sequence, timestamp, ssrc),
            Admission::Refuse => panic!("refused"),
        }
    }

    #[test]
    fn a_guarded_flow_forwards_a_continuous_stream_verbatim_through_loss_and_reordering() {
        let track = guarded();
        for (sequence, timestamp) in [
            (100u16, 16_000u32),
            (101, 16_160),
            (105, 16_800),
            (103, 16_480),
        ] {
            assert_eq!(track.sent(&rtp(sequence, timestamp, 9)), Admission::Forward);
        }
        // Wrapping is not a discontinuity either.
        let track = guarded();
        for sequence in [65_534u16, 65_535, 0, 1] {
            assert_eq!(track.sent(&rtp(sequence, 0, 9)), Admission::Forward);
        }
    }

    #[test]
    fn a_stream_that_restarts_at_zero_after_30000_carries_on_from_the_flows_own_position() {
        let track = guarded();
        for sequence in 29_998..=30_000u16 {
            track.sent(&rtp(sequence, u32::from(sequence) * 160, 9));
        }
        let (sequence, timestamp, ssrc) = numbered(&track, &rtp(0, 0, 9));
        assert_eq!(sequence, 30_001, "high-water + 1");
        assert!(
            timestamp > 30_000 * 160,
            "the timestamp moves forward too: {timestamp}"
        );
        assert_eq!(ssrc, 9);
        let (next, next_timestamp, _) = numbered(&track, &rtp(1, 160, 9));
        assert_eq!(next, 30_002);
        assert_eq!(next_timestamp.wrapping_sub(timestamp), 160);
    }

    #[test]
    fn a_forward_jump_of_49000_is_renumbered_not_forwarded() {
        // At rollover 0 a receiver reads 1000 -> 50000 as an old packet of a rollover that never was.
        let track = guarded();
        track.sent(&rtp(1_000, 160_000, 9));
        let (sequence, _, _) = numbered(&track, &rtp(50_000, 8_000_000, 9));
        assert_eq!(sequence, 1_001);
        let (sequence, _, _) = numbered(&track, &rtp(50_001, 8_000_160, 9));
        assert_eq!(sequence, 1_002);
    }

    #[test]
    fn an_ssrc_reused_after_a_gap_with_a_new_sequence_base_is_renumbered() {
        let track = guarded();
        for sequence in 500..510u16 {
            track.sent(&rtp(sequence, u32::from(sequence) * 160, 9));
        }
        let (sequence, _, ssrc) = numbered(&track, &rtp(61_000, 3, 9));
        assert_eq!((sequence, ssrc), (510, 9));
    }

    #[test]
    fn a_flow_that_does_not_feed_an_srtp_leg_forwards_a_restart_verbatim() {
        let track = EgressTrack::default();
        track.sent(&rtp(30_000, 0, 9));
        assert_eq!(track.sent(&rtp(0, 0, 9)), Admission::Forward);
    }

    #[test]
    fn a_packet_the_sender_refused_leaves_no_mark() {
        let track = EgressTrack::default();
        track.sent(&rtp(100, 0, 9));
        // Admitted, then the sender refused it: not committed.
        assert_eq!(track.admit(&rtp(150, 0, 9)), Admission::Forward);
        assert_eq!(track.admit(&rtp(101, 0, 9)), Admission::Forward);
        track.commit();
        assert_eq!(track.position_of(9).expect("mark").sequence, 101);
    }

    #[test]
    fn eviction_gives_up_the_stream_that_advanced_least_recently() {
        let track = EgressTrack::default();
        for ssrc in 1..=8u32 {
            track.sent(&rtp(10, 0, ssrc));
        }
        // 1 advances, so 2 is now the least recently advanced.
        track.sent(&rtp(11, 0, 1));
        track.sent(&rtp(10, 0, 9));
        assert!(track.position_of(1).is_some(), "recently advanced: kept");
        assert!(
            track.position_of(2).is_none(),
            "least recently advanced: given up"
        );
        assert!(track.position_of(9).is_some());
    }

    /// What a sender has sent, by SSRC: the authority a guarded flow asks when it meets a stream it is
    /// not following.
    #[derive(Default)]
    struct Sender(std::collections::HashMap<u32, u16>);

    impl Sender {
        /// Admit, record in the sender as protected, and commit.
        fn send(&mut self, track: &EgressTrack, packet: &[u8], now: Instant) -> (u16, u32, u32) {
            let known = self.0.clone();
            let admission = track.admit_with(packet, now, |ssrc| known.get(&ssrc).copied());
            let (ssrc, sequence, timestamp) = rtp_header(packet).expect("rtp");
            let numbered = match admission {
                Admission::Forward => (sequence, timestamp, ssrc),
                Admission::Rewrite {
                    sequence,
                    timestamp,
                    ssrc,
                } => (sequence, timestamp, ssrc),
                Admission::Refuse => panic!("refused"),
            };
            let entry = self.0.entry(numbered.2).or_insert(numbered.0);
            if i16::from_ne_bytes(numbered.0.wrapping_sub(*entry).to_ne_bytes()) > 0 {
                *entry = numbered.0;
            }
            track.commit();
            numbered
        }
    }

    #[test]
    fn a_restarted_stream_keeps_its_renumbering_when_more_streams_than_epochs_follow() {
        let (mut sender, track, now) = (Sender::default(), guarded(), Instant::now());
        for sequence in 29_998..=30_000u16 {
            sender.send(&track, &rtp(sequence, u32::from(sequence) * 160, 1), now);
        }
        // SSRC 1 restarts at zero and is renumbered from 30001.
        assert_eq!(sender.send(&track, &rtp(0, 0, 1), now).0, 30_001);
        // Eight more streams follow, each fresh: the oldest epoch used to be the one given up.
        for ssrc in 2..=9u32 {
            sender.send(&track, &rtp(500, 0, ssrc), now);
        }
        assert_eq!(
            sender.send(&track, &rtp(1, 160, 1), now).0,
            30_002,
            "the renumbering of the restarted stream survived"
        );
    }

    #[test]
    fn a_restarted_stream_whose_epoch_was_given_up_carries_on_from_the_senders_own_position() {
        let (mut sender, track, now) = (Sender::default(), guarded(), Instant::now());
        // Nine streams, every one restarted so that every epoch is renumbering.
        for ssrc in 1..=9u32 {
            for sequence in 29_998..=30_000u16 {
                sender.send(&track, &rtp(sequence, u32::from(sequence) * 160, ssrc), now);
            }
            assert_eq!(sender.send(&track, &rtp(0, 0, ssrc), now).0, 30_001);
        }
        // The first one comes back still numbering from its restart: verbatim it would be an index
        // the sender sent long ago.
        let (sequence, _, ssrc) = sender.send(&track, &rtp(1, 160, 1), now);
        assert_eq!((sequence, ssrc), (30_002, 1));
    }

    #[test]
    fn a_packet_the_sender_refused_far_from_where_it_stands_renumbers_the_stream() {
        let (mut sender, track, now) = (Sender::default(), guarded(), Instant::now());
        for sequence in 1_000..=1_010u16 {
            sender.send(&track, &rtp(sequence, u32::from(sequence) * 160, 9), now);
        }
        // The peer's numbering jumps to a place the flow does not place, and the sender refuses it.
        track.admit_with(&rtp(1_300, 0, 9), now, |_| None);
        track.refused(&siphon_rtp_srtp::SrtpError::IndexReused, |ssrc| {
            sender.0.get(&ssrc).copied()
        });
        let (sequence, _, _) = sender.send(&track, &rtp(1_301, 160, 9), now);
        assert_eq!(sequence, 1_011, "from the sender's own position");
    }

    #[test]
    fn a_peer_resuming_below_a_restored_mark_is_heard_at_once_by_an_independent_receiver() {
        use siphon_rtp_srtp::leg::SecureLeg;
        use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
        use siphon_rtp_srtp::SrtpContext;
        let local = SrtpKeyMaterial::from_inline_bytes(&[1; 30]).expect("key");
        let remote = SrtpKeyMaterial::from_inline_bytes(&[2; 30]).expect("key");
        // The leg that sent up to 1000 under SSRC 9, and the standby rebuilt from its checkpoint.
        let mut sent = SecureLeg::new(&local, &remote);
        let mut wire = Vec::new();
        sent.protect(&rtp(1_000, 160_000, 9), &mut wire)
            .expect("sent");
        let mut restored = SecureLeg::new(&local, &remote);
        restored.seed_rollover(&sent.rollover_snapshot());
        let track = guarded();
        let now = Instant::now();
        // The peer resumes at 950 (a call restored behind the stream's high-water mark).
        let packet = rtp(950, 152_000, 9);
        let Admission::Rewrite {
            sequence,
            timestamp,
            ssrc,
        } = track.admit_with(&packet, now, |ssrc| restored.highest_sent(ssrc))
        else {
            panic!("a packet below the restored mark must be renumbered");
        };
        assert_eq!(sequence, 1_001);
        let mut renumbered = packet.clone();
        write_header_fields(&mut renumbered, sequence, timestamp, ssrc);
        restored
            .protect(&renumbered, &mut wire)
            .expect("protects at once");
        track.commit();
        // Anyone holding the key decrypts it: the receiver that saw index 1000 estimates 1001.
        let mut receiver = SrtpContext::from_key_material(&local);
        let mut seen = Vec::new();
        let mut plain = Vec::new();
        let mut earlier = SecureLeg::new(&local, &remote);
        earlier
            .protect(&rtp(1_000, 160_000, 9), &mut seen)
            .expect("sent");
        receiver.unprotect(&seen, &mut plain).expect("index 1000");
        receiver
            .unprotect(&wire, &mut plain)
            .expect("index 1001 decrypts at once");
        assert_eq!(&plain[2..4], &1_001u16.to_be_bytes());
    }

    #[test]
    fn a_repeat_inside_the_send_window_does_not_renumber_the_stream() {
        let (mut sender, track, now) = (Sender::default(), guarded(), Instant::now());
        for sequence in 1_000..=1_010u16 {
            sender.send(&track, &rtp(sequence, u32::from(sequence) * 160, 9), now);
        }
        track.admit_with(&rtp(1_008, 0, 9), now, |_| None);
        track.refused(&siphon_rtp_srtp::SrtpError::IndexReused, |ssrc| {
            sender.0.get(&ssrc).copied()
        });
        let (sequence, _, _) = sender.send(&track, &rtp(1_011, 160, 9), now);
        assert_eq!(
            sequence, 1_011,
            "a duplicate is the send window's to refuse"
        );
    }

    #[test]
    fn a_silence_between_two_consecutive_packets_does_not_become_the_timestamp_step() {
        let (mut sender, track) = (Sender::default(), guarded());
        let start = Instant::now();
        let at = |milliseconds: u64| start + Duration::from_millis(milliseconds);
        for sequence in 100..=105u16 {
            let elapsed = u64::from(sequence - 100) * 20;
            sender.send(
                &track,
                &rtp(sequence, u32::from(sequence) * 160, 9),
                at(elapsed),
            );
        }
        // Ten seconds of suppressed silence between two consecutive sequence numbers.
        let (_, after_silence, _) =
            sender.send(&track, &rtp(106, 106 * 160 + 80_000, 9), at(100 + 10_000));
        // The peer restarts its numbering 20 ms later: the flow moves on by one frame, not by the
        // silence it mistook for one.
        let (_, restarted, _) = sender.send(&track, &rtp(1, 0, 9), at(100 + 10_020));
        assert_eq!(
            restarted.wrapping_sub(after_silence),
            160,
            "one frame after the last packet, not another ten seconds"
        );
    }

    #[test]
    fn writes_the_sequence_and_timestamp_into_the_header() {
        let mut packet = rtp(1, 2, 3);
        write_header_fields(&mut packet, 0xABCD, 0x0102_0304, 0x0A0B_0C0D);
        assert_eq!(&packet[2..8], &[0xAB, 0xCD, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&packet[8..12], &0x0A0B_0C0Du32.to_be_bytes());
        let mut short = [0u8; 4];
        write_header_fields(&mut short, 1, 1, 1);
        assert_eq!(short, [0u8; 4]);
    }

    #[test]
    fn the_continuation_timestamp_advances_by_the_elapsed_clock_in_whole_frames() {
        // 8 kHz clock, 20 ms frames of 160 ticks.
        let advance = |elapsed_ms: u64| {
            continuation_timestamp(1000, Duration::from_millis(elapsed_ms), 8000, 160) - 1000
        };
        assert_eq!(advance(0), 160, "never less than one frame");
        assert_eq!(advance(5), 160);
        assert_eq!(advance(20), 160);
        assert_eq!(advance(41), 320, "nearest whole frame");
        assert_eq!(
            advance(1000),
            8000,
            "a second of silence is a second of ticks"
        );
    }

    #[test]
    fn the_continuation_timestamp_wraps_like_an_rtp_timestamp() {
        assert_eq!(
            continuation_timestamp(u32::MAX - 79, Duration::ZERO, 8000, 160),
            80
        );
        assert_eq!(continuation_timestamp(7, Duration::ZERO, 8000, 0), 7);
    }
}
