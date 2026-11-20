//! Starting a video receiver on a keyframe, and serving the feedback a video seat sends the room
//! (3GPP TS 24.581: a transmission grant starts a new video transmission; TS 26.281: the video
//! must stay decodable).
//!
//! H.264 is predictive: a receiver that is handed a stream in the middle of a group of pictures shows
//! nothing usable until the next IDR picture (RFC 6184 §1.1). A source change therefore
//!
//! 1. gates every receiver ([`Gate::Waiting`]): its packets are dropped until one begins an IDR
//!    slice, so the receiver never decodes a stream it cannot start;
//! 2. asks the new source for a keyframe, a Picture Loss Indication (RFC 4585 §6.3.1) first and then
//!    Full Intra Requests (RFC 5104 §4.3.1) retried every [`KEYFRAME_RETRY_MS`], for what the source
//!    accepted in its SDP (`a=rtcp-fb`; a source that accepted none is sent nothing);
//! 3. opens the gate on the IDR, first replaying the source's last SPS and PPS as single NAL unit
//!    packets (valid in packetization modes 0 and 1, RFC 6184 §5.6) so a receiver that missed them
//!    can decode the picture, and drops anything older than the IDR;
//! 4. forwards anyway after [`KEYFRAME_MAX_WAIT_MS`] (a source that cannot or will not send a keyframe
//!    must not mute the room), and tells the controller either way ([`Event::ForwardKeyframe`]).
//!
//! A receiver's own PLI or FIR (addressed to the stream the room sends it) is passed on to the source,
//! at most once per [`RECEIVER_REQUEST_INTERVAL_MS`] however many receivers ask, and a receiver's
//! Generic NACK (RFC 4585 §6.2.1) is answered from a history of the source's last
//! [`HISTORY_SLOTS`] packets, sent again through that receiver's translator so the packet carries
//! the very sequence number it was lost under. No RTX stream (RFC 4588) is offered.
//!
//! Everything here is synchronous and driven by a caller-supplied millisecond clock
//! ([`ForwardRoom::poll_keyframe`]); the room reads no clock of its own.

use std::net::SocketAddr;

use bytes::Bytes;

use siphon_rtp_datapath::EndpointId;
use siphon_rtp_media::h264::Scan;
use siphon_rtp_media::rtcp::{self, Feedback};
use siphon_rtp_media::rtp::{write_packet, RtpHeader};
use siphon_rtp_media::translator::Forwarded;
use siphon_rtp_proto::Event;

use super::video::{seal, VideoStream};
use super::{ticks, ForwardRoom, StreamPoint, MAX_DATAGRAM};
use crate::media_pipeline::Outbound;
use crate::sdp::video::VIDEO_CLOCK_RATE_HZ;

/// How long after a keyframe request to the source, with no IDR yet, the next one is sent
/// (RFC 5104 §4.3.1.2: an unanswered request is repeated; half a second is well over a
/// round trip and well under the wait a viewer notices).
pub(crate) const KEYFRAME_RETRY_MS: u64 = 500;
/// Requests repeated after the first before the room stops asking.
pub(crate) const KEYFRAME_RETRIES: u8 = 3;
/// How long a receiver waits for the IDR before the room forwards anyway.
pub(crate) const KEYFRAME_MAX_WAIT_MS: u64 = 2000;
/// The least time between two keyframe requests the room sends because receivers asked
/// (RFC 4585 §6.3.1: a PLI costs the sender an intra picture, so a crowd is answered by one).
pub(crate) const RECEIVER_REQUEST_INTERVAL_MS: u64 = 1000;
/// Packets of the source the room can send again.
const HISTORY_SLOTS: usize = 256;
/// The largest SPS or PPS the room keeps to replay (a whole NAL unit, header included).
const MAX_PARAMETER_SET: usize = 512;
/// The most packets one NACK datagram makes the room send again; the rest are counted as missed.
const MAX_RETRANSMISSIONS: usize = 32;
/// The payload type a replayed parameter set is built under: the receiver's translator overwrites it
/// with the receiver's own (RFC 3550 §7.1).
const REPLAY_PAYLOAD_TYPE: u8 = 96;
/// The largest feedback compound the room writes: an empty report, a source description with a
/// CNAME of up to 255 octets, and one request.
const REQUEST_BUFFER: usize = 320;

/// Serial-number "a is ahead of b" on 16 bits (RFC 1982).
fn ahead(a: u16, b: u16) -> bool {
    (a.wrapping_sub(b) as i16) > 0
}

/// Whether a receiver's video is held back until a keyframe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Gate {
    /// Forward whatever arrives.
    Open,
    /// Drop everything until a packet begins an IDR slice.
    Waiting,
}

/// What the gate decided about one source packet for one receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admission {
    /// Not sent: counted as dropped awaiting a keyframe.
    Dropped,
    /// Sent as it is.
    Forward,
    /// The packet begins the keyframe that opened the gate: the parameter sets go first.
    Opened,
}

/// What a source packet is, for the fan-out that follows it.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct KeyframePlan {
    /// The packet begins an IDR slice.
    pub(super) start: bool,
    /// The packet carries an SPS / a PPS itself (a STAP-A of the access unit), so it needs no replay.
    pub(super) has_sps: bool,
    pub(super) has_pps: bool,
    /// Which part of a receiver's keyframe the fan-out is on: [`STEP_NONE`] not started, the SPS
    /// replay, the PPS replay, or the packet itself.
    pub(super) step: u8,
    /// The receiver `step` belongs to.
    pub(super) receiver: usize,
    /// Which parameter sets the receiver that opened is sent before the IDR.
    pub(super) replay_sps: bool,
    pub(super) replay_pps: bool,
}

pub(super) const STEP_NONE: u8 = 0;
pub(super) const STEP_SPS: u8 = 1;
pub(super) const STEP_PPS: u8 = 2;
pub(super) const STEP_PACKET: u8 = 3;

/// The last SPS and PPS a seat sent, in buffers fixed at their largest.
pub(super) struct ParameterSets {
    sps: [u8; MAX_PARAMETER_SET],
    sps_length: usize,
    pps: [u8; MAX_PARAMETER_SET],
    pps_length: usize,
}

impl ParameterSets {
    fn new() -> Box<Self> {
        Box::new(Self {
            sps: [0; MAX_PARAMETER_SET],
            sps_length: 0,
            pps: [0; MAX_PARAMETER_SET],
            pps_length: 0,
        })
    }

    fn sps(&self) -> Option<&[u8]> {
        (self.sps_length > 0).then(|| &self.sps[..self.sps_length])
    }

    fn pps(&self) -> Option<&[u8]> {
        (self.pps_length > 0).then(|| &self.pps[..self.pps_length])
    }
}

/// What the room knows of the media a seat sends, for starting a receiver on it.
#[derive(Default)]
pub(super) struct SourceMedia {
    /// The SSRC of the last video packet the seat sent: what a request to it names.
    /// (`IngressStats::ssrc` keeps the first one for ever, which is not it after a restart.)
    pub(super) ssrc: Option<u32>,
    sets: Option<Box<ParameterSets>>,
}

impl SourceMedia {
    /// Keep the SPS and PPS of `found`, copied: the packet's buffer is not the room's.
    pub(super) fn note(&mut self, found: &Scan<'_>) {
        for (part, is_sps) in [(found.sps, true), (found.pps, false)] {
            let Some(unit) = part.filter(|unit| unit.len() <= MAX_PARAMETER_SET) else {
                continue;
            };
            let sets = self.sets.get_or_insert_with(ParameterSets::new);
            let (buffer, length) = if is_sps {
                (&mut sets.sps, &mut sets.sps_length)
            } else {
                (&mut sets.pps, &mut sets.pps_length)
            };
            buffer[..unit.len()].copy_from_slice(unit);
            *length = unit.len();
        }
    }
}

/// A receiver's state toward keyframes.
pub(super) struct ReceiverKeyframe {
    pub(super) gate: Gate,
    /// Until a packet ahead of the IDR that opened the gate has been seen, the IDR's sequence number:
    /// an older packet of the source (a reordered one) is behind the picture the receiver started on.
    settling: Option<u16>,
    /// The source sequence number of the IDR that opened the gate, and how many parameter sets were
    /// replayed just before it (under the two sequence numbers before it): a NACK for those names no
    /// packet of the source.
    run_start: Option<u16>,
    replayed: u8,
}

impl ReceiverKeyframe {
    pub(super) fn new() -> Self {
        Self {
            gate: Gate::Open,
            settling: None,
            run_start: None,
            replayed: 0,
        }
    }

    pub(super) fn arm(&mut self) {
        *self = Self::new();
        self.gate = Gate::Waiting;
    }

    pub(super) fn open(&mut self) {
        *self = Self::new();
    }

    /// Decide what to do with the source packet `sequence` (whose nature is `plan`).
    pub(super) fn admit(&mut self, plan: &KeyframePlan, sequence: u16) -> Admission {
        match self.gate {
            Gate::Waiting if plan.start => {
                self.gate = Gate::Open;
                self.settling = Some(sequence);
                self.run_start = Some(sequence);
                self.replayed = 0;
                Admission::Opened
            }
            Gate::Waiting => Admission::Dropped,
            Gate::Open => match self.settling {
                Some(start) if !ahead(sequence, start) => Admission::Dropped,
                Some(_) => {
                    self.settling = None;
                    Admission::Forward
                }
                None => Admission::Forward,
            },
        }
    }
}

/// One slot of the history: which packet it holds.
#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    sequence: u16,
    length: u16,
    valid: bool,
}

/// The last [`HISTORY_SLOTS`] packets of the source, in fixed buffers allocated once.
pub(super) struct History {
    ssrc: u32,
    data: Vec<u8>,
    slots: [Slot; HISTORY_SLOTS],
}

impl History {
    fn new() -> Box<Self> {
        Box::new(Self {
            ssrc: 0,
            data: vec![0; HISTORY_SLOTS * MAX_DATAGRAM],
            slots: [Slot::default(); HISTORY_SLOTS],
        })
    }

    fn clear(&mut self) {
        self.slots.fill(Slot::default());
    }

    /// Copy `datagram` in (never a `Bytes` clone: a clone of a copied buffer allocates).
    fn store(&mut self, ssrc: u32, sequence: u16, datagram: &[u8]) {
        let Ok(length) = u16::try_from(datagram.len()) else {
            return;
        };
        if datagram.len() > MAX_DATAGRAM {
            return;
        }
        if ssrc != self.ssrc {
            // A new stream: sequence numbers of the old one name nothing in it.
            self.clear();
            self.ssrc = ssrc;
        }
        let index = usize::from(sequence) % HISTORY_SLOTS;
        self.data[index * MAX_DATAGRAM..index * MAX_DATAGRAM + datagram.len()]
            .copy_from_slice(datagram);
        self.slots[index] = Slot {
            sequence,
            length,
            valid: true,
        };
    }

    fn get(&self, ssrc: u32, sequence: u16) -> Option<&[u8]> {
        let index = usize::from(sequence) % HISTORY_SLOTS;
        let slot = self.slots[index];
        (slot.valid && slot.sequence == sequence && self.ssrc == ssrc).then(|| {
            &self.data[index * MAX_DATAGRAM..index * MAX_DATAGRAM + usize::from(slot.length)]
        })
    }
}

/// Packets a receiver's NACK asked for, found, and waiting to be sent from the history.
#[derive(Default)]
struct Retransmissions {
    receiver: usize,
    sequences: [u16; MAX_RETRANSMISSIONS],
    count: usize,
    next: usize,
}

/// A keyframe request in flight to the new source.
#[derive(Debug, Clone, Copy)]
struct Request {
    /// When it was made, once the clock has been read.
    since: Option<u64>,
    last_sent: Option<u64>,
    /// How many requests went to the source for it.
    sent: u8,
    /// The command sequence number of its FIR (RFC 5104 §4.3.1.2): one per request, repeated as it is.
    fir_sequence: u8,
    /// Whether the controller is told how it ended (a source change; not a late joiner's).
    report: bool,
    /// The IDR arrived.
    satisfied: bool,
}

/// The room's keyframe state.
pub(super) struct Keyframes {
    history: Option<Box<History>>,
    /// Scratch for a parameter set built into an RTP packet.
    replay: Vec<u8>,
    request: Option<Request>,
    /// A receiver asked for a keyframe and the source was not yet asked on its behalf.
    receiver_wanted: bool,
    last_request_ms: Option<u64>,
    fir_sequence: u8,
    retransmit: Retransmissions,
}

impl Keyframes {
    pub(super) fn new() -> Self {
        Self {
            history: None,
            replay: vec![0; MAX_DATAGRAM],
            request: None,
            receiver_wanted: false,
            last_request_ms: None,
            fir_sequence: 0,
            retransmit: Retransmissions::default(),
        }
    }

    /// Whether anything waits on [`ForwardRoom::poll_keyframe`].
    pub(super) fn active(&self) -> bool {
        self.request.is_some() || self.receiver_wanted
    }

    pub(super) fn reset(&mut self) {
        self.request = None;
        self.receiver_wanted = false;
        self.retransmit = Retransmissions::default();
        if let Some(history) = self.history.as_mut() {
            history.clear();
        }
    }

    /// A packet of the source: the keyframe it carries answers the request, and the history keeps it.
    pub(super) fn source_packet(
        &mut self,
        keyframe: bool,
        ssrc: u32,
        sequence: u16,
        datagram: &[u8],
    ) {
        if keyframe {
            self.receiver_wanted = false;
            if let Some(request) = self.request.as_mut() {
                request.satisfied = true;
            }
        }
        if let Some(history) = self.history.as_mut() {
            history.store(ssrc, sequence, datagram);
        }
    }

    pub(super) fn retransmissions_pending(&self) -> bool {
        self.retransmit.next < self.retransmit.count
    }

    /// A datagram of `receiver`'s feedback is about to be read: what an earlier one asked is gone.
    pub(super) fn start_feedback(&mut self, receiver: usize) {
        self.retransmit.receiver = receiver;
        self.retransmit.count = 0;
        self.retransmit.next = 0;
    }

    /// Read a receiver's feedback about the stream the room sends it (`egress_ssrc`).
    ///
    /// A PLI or FIR for that stream asks for a keyframe; a Generic NACK for it asks for packets,
    /// which are found in the history now and sent by [`ForwardRoom::next_datagram`].
    pub(super) fn receiver_feedback(
        &mut self,
        video: &VideoStream,
        feedback: Feedback<'_>,
        counters: &mut super::ForwardSeatStats,
    ) {
        let egress_ssrc = video.translator.egress_ssrc();
        match feedback {
            Feedback::Pli { media_ssrc, .. } if media_ssrc == egress_ssrc => self.wanted(),
            Feedback::Fir { mut entries, .. } => {
                if entries.any(|entry| entry.ssrc == egress_ssrc) {
                    self.wanted();
                }
            }
            Feedback::GenericNack {
                media_ssrc,
                pid,
                blp,
                ..
            } if media_ssrc == egress_ssrc && video.feedback.nack => {
                let lost = std::iter::once(pid).chain(
                    (0..16u16)
                        .filter(|bit| blp & (1 << bit) != 0)
                        .map(|bit| pid.wrapping_add(bit + 1)),
                );
                for egress_sequence in lost {
                    self.find(video, egress_sequence, counters);
                }
            }
            _ => {}
        }
    }

    fn wanted(&mut self) {
        // A request in flight to the source answers every receiver.
        if self.request.is_none() {
            self.receiver_wanted = true;
        }
    }

    /// Look up the packet the receiver lost under `egress_sequence`.
    fn find(
        &mut self,
        video: &VideoStream,
        egress_sequence: u16,
        counters: &mut super::ForwardSeatStats,
    ) {
        let found = video
            .translator
            .source_ssrc()
            .zip(video.translator.source_sequence_of(egress_sequence))
            .filter(|&(_, sequence)| !video.keyframe.replayed_packet(sequence))
            .filter(|&(ssrc, sequence)| {
                self.history
                    .as_ref()
                    .is_some_and(|history| history.get(ssrc, sequence).is_some())
            });
        let retransmit = &mut self.retransmit;
        match found {
            Some((_, sequence)) if retransmit.count < MAX_RETRANSMISSIONS => {
                retransmit.sequences[retransmit.count] = sequence;
                retransmit.count += 1;
            }
            _ => counters.nack_missed += 1,
        }
    }
}

impl ReceiverKeyframe {
    /// Whether `sequence` is one of the parameter sets replayed before the IDR (not a packet of the
    /// source's own).
    fn replayed_packet(&self, sequence: u16) -> bool {
        self.run_start.is_some_and(|start| {
            let behind = start.wrapping_sub(sequence);
            behind >= 1 && behind <= u16::from(self.replayed)
        })
    }
}

/// What a request to the source is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Pli,
    Fir,
}

impl ForwardRoom {
    /// Whether [`Self::poll_keyframe`] has something to do: a request in flight, or a receiver's.
    #[must_use]
    pub fn keyframe_active(&self) -> bool {
        self.keyframes.active()
    }

    /// Whether the source being forwarded sends video a receiver could be started on.
    fn source_carries_video(&self) -> bool {
        self.source
            .and_then(|source| self.seats[source].video.as_ref())
            .is_some_and(|video| video.sends)
    }

    /// Start every receiver on a keyframe of the new source, and ask the source for one. Called when
    /// the source changes; with no source, or one that sends no video, every gate is open.
    pub(super) fn arm_keyframe_gate(&mut self) {
        self.keyframes.reset();
        let carries_video = self.source_carries_video();
        for (index, seat) in self.seats.iter_mut().enumerate() {
            if let Some(video) = seat.video.as_mut() {
                if carries_video && Some(index) != self.source && video.receives {
                    video.keyframe.arm();
                } else {
                    video.keyframe.open();
                }
            }
        }
        if carries_video {
            self.begin_request(true);
        }
    }

    /// The last seat added is in: it keeps the history when it accepted NACK, and a seat that joins
    /// while a source is streaming starts on a keyframe too.
    pub(super) fn keyframe_seat_joined(&mut self) {
        let index = self.seats.len() - 1;
        let Some(joined) = self.seats[index].video.as_mut() else {
            return;
        };
        if joined.feedback.nack && self.keyframes.history.is_none() {
            self.keyframes.history = Some(History::new());
        }
        self.start_receiver_on_keyframe(index);
    }

    /// Hold seat `index` until a keyframe of the source it is sent from now on, and ask the source for
    /// one: a seat that joins, or switches its video back on, while the source streams. Nothing for a
    /// seat that is the source, receives no video, or a source that sends none.
    pub(super) fn start_receiver_on_keyframe(&mut self, index: usize) {
        let receives = self.seats[index]
            .video
            .as_ref()
            .is_some_and(|video| video.receives);
        if receives && Some(index) != self.source && self.source_carries_video() {
            if let Some(video) = self.seats[index].video.as_mut() {
                video.keyframe.arm();
            }
            self.begin_request(false);
        }
    }

    /// Make a request unless one is already in flight (it answers this joiner too).
    fn begin_request(&mut self, report: bool) {
        if self.keyframes.request.is_some() {
            return;
        }
        let fir_sequence = self.keyframes.fir_sequence;
        self.keyframes.fir_sequence = fir_sequence.wrapping_add(1);
        self.keyframes.request = Some(Request {
            since: None,
            last_sent: None,
            sent: 0,
            fir_sequence,
            report,
            satisfied: false,
        });
    }

    /// The millisecond (on the clock [`Self::poll_keyframe`] is given) at which it next has something
    /// to do, or `None`. `0` means now: the clock has not been read for a request yet.
    #[must_use]
    pub fn next_keyframe_deadline(&self) -> Option<u64> {
        let mut deadline: Option<u64> = None;
        let mut earlier = |at: u64| deadline = Some(deadline.map_or(at, |known| known.min(at)));
        if let Some(request) = &self.keyframes.request {
            let Some(since) = request.since else {
                return Some(0);
            };
            if request.satisfied {
                return Some(0);
            }
            earlier(since.saturating_add(KEYFRAME_MAX_WAIT_MS));
            if request.sent <= KEYFRAME_RETRIES && self.source_can_be_asked() {
                earlier(
                    request
                        .last_sent
                        .map_or(since, |sent| sent.saturating_add(KEYFRAME_RETRY_MS)),
                );
            }
        }
        if self.keyframes.receiver_wanted && self.source_can_be_asked() {
            earlier(
                self.keyframes
                    .last_request_ms
                    .map_or(0, |sent| sent.saturating_add(RECEIVER_REQUEST_INTERVAL_MS)),
            );
        }
        deadline
    }

    /// The source is known well enough to be written to: it has sent video (its SSRC is the media
    /// source a request names), it can be reached, and it accepted some feedback.
    fn source_can_be_asked(&self) -> bool {
        self.source
            .map(|source| &self.seats[source])
            .is_some_and(|seat| {
                seat.video.as_ref().is_some_and(|video| {
                    video.keyframe_media.ssrc.is_some()
                        && seat.video_reachable()
                        && (video.feedback.pli || video.feedback.fir)
                })
            })
    }

    /// Do what is due at `now_ms`: stamp a new request, send or repeat it to the source, report how
    /// it ended, open the gates that waited too long, and pass on what receivers asked. The datagrams
    /// to send are pushed onto `out`; events are staged for [`Self::drain_events`].
    pub fn poll_keyframe(&mut self, now_ms: u64, out: &mut Vec<Outbound>) {
        let Some(mut request) = self.keyframes.request else {
            self.send_receiver_request(now_ms, out);
            return;
        };
        let since = *request.since.get_or_insert(now_ms);
        let waited = now_ms.saturating_sub(since);
        if request.satisfied {
            self.keyframes.request = None;
            // A receiver still waiting (unreachable when the picture went by) starts on whatever comes.
            self.open_every_gate();
            if let Some(source) = self.source.filter(|_| request.report) {
                self.report_keyframe(source, waited, false);
            }
            return;
        }
        if waited >= KEYFRAME_MAX_WAIT_MS {
            self.keyframes.request = None;
            self.open_every_gate();
            if let Some(source) = self.source {
                self.seats[source].counters.keyframe_timeouts += 1;
                tracing::warn!(
                    target: "siphon_rtp::media", room = %self.room_id, tag = %self.seats[source].tag,
                    waited_ms = waited,
                    "no keyframe from the new video source in time; forwarding without one"
                );
                if request.report {
                    self.report_keyframe(source, waited, true);
                }
            }
            return;
        }
        let due = request.last_sent.is_none_or(|sent| {
            now_ms.saturating_sub(sent) >= KEYFRAME_RETRY_MS && request.sent <= KEYFRAME_RETRIES
        });
        if due && self.source_can_be_asked() {
            let kind = self.kind_of_request(request.sent);
            if let Some(source) = self.source {
                // An attempt counts even when the request could not be built (an oversized CNAME):
                // it is not retried in a loop, only on the schedule.
                if !self.send_request(source, kind, request.fir_sequence, out) {
                    self.request_not_built(source);
                }
                request.sent += 1;
                request.last_sent = Some(now_ms);
                self.keyframes.last_request_ms = Some(now_ms);
            }
        }
        self.keyframes.request = Some(request);
    }

    /// Which request the `attempt`th is: a PLI first, then FIR (the harder ask), by what the source
    /// accepted; a source that accepted one kind is sent that one every time.
    fn kind_of_request(&self, attempt: u8) -> Kind {
        let feedback = self
            .source
            .and_then(|source| self.seats[source].video.as_ref())
            .map(|video| video.feedback)
            .unwrap_or_default();
        match (attempt, feedback.pli, feedback.fir) {
            (0, true, _) | (_, true, false) => Kind::Pli,
            _ => Kind::Fir,
        }
    }

    fn open_every_gate(&mut self) {
        for seat in &mut self.seats {
            if let Some(video) = seat.video.as_mut() {
                if video.keyframe.gate == Gate::Waiting {
                    video.keyframe.open();
                }
            }
        }
    }

    fn report_keyframe(&mut self, source: usize, latency_ms: u64, timed_out: bool) {
        self.events.push(Event::ForwardKeyframe {
            conference_id: self.room_id.clone(),
            from_tag: self.seats[source].tag.clone(),
            latency_ms,
            timed_out,
        });
    }

    /// Pass receivers' PLIs and FIRs on to the source as one request per
    /// [`RECEIVER_REQUEST_INTERVAL_MS`].
    fn send_receiver_request(&mut self, now_ms: u64, out: &mut Vec<Outbound>) {
        if !self.keyframes.receiver_wanted {
            return;
        }
        if !self.source_can_be_asked() {
            // Nothing the source accepted: the request has nowhere to go.
            self.keyframes.receiver_wanted = self.source.is_some() && self.source_unreachable_yet();
            return;
        }
        let spaced = self
            .keyframes
            .last_request_ms
            .is_none_or(|sent| now_ms.saturating_sub(sent) >= RECEIVER_REQUEST_INTERVAL_MS);
        if !spaced {
            return;
        }
        let kind = self.kind_of_request(0);
        let fir_sequence = self.keyframes.fir_sequence;
        if let Some(source) = self.source {
            if !self.send_request(source, kind, fir_sequence, out) {
                self.request_not_built(source);
            }
            self.keyframes.fir_sequence = fir_sequence.wrapping_add(1);
            self.keyframes.last_request_ms = Some(now_ms);
            self.keyframes.receiver_wanted = false;
        }
    }

    /// The source has sent no video yet or cannot be reached yet, so a receiver's request waits.
    fn source_unreachable_yet(&self) -> bool {
        self.source
            .map(|source| &self.seats[source])
            .is_some_and(|seat| {
                seat.video.as_ref().is_some_and(|video| {
                    (video.feedback.pli || video.feedback.fir)
                        && (video.keyframe_media.ssrc.is_none() || !seat.video_reachable())
                })
            })
    }

    fn request_not_built(&self, source: usize) {
        tracing::warn!(
            target: "siphon_rtp::media", room = %self.room_id, tag = %self.seats[source].tag,
            "could not build a keyframe request for the video source"
        );
    }

    /// Write the request to the source as a compound (RFC 4585 §3.1: an empty Receiver Report, the
    /// source description with the CNAME, then the feedback) from the stream the room sends it, and
    /// queue it for its video endpoint. `false` when it could not be built (the schedule goes on).
    fn send_request(
        &mut self,
        source: usize,
        kind: Kind,
        fir_sequence: u8,
        out: &mut Vec<Outbound>,
    ) -> bool {
        let seat = &mut self.seats[source];
        let Some((endpoint, destination)) = seat.video_route() else {
            return false;
        };
        let Some(video) = seat.video.as_ref() else {
            return false;
        };
        let Some(media_ssrc) = video.keyframe_media.ssrc else {
            return false;
        };
        let sender_ssrc = video.translator.egress_ssrc();
        let mut buffer = [0u8; REQUEST_BUFFER];
        let mut length = 0;
        for written in [
            rtcp::write_empty_receiver_report(sender_ssrc, &mut buffer),
            rtcp::write_sdes_cname(sender_ssrc, &video.cname, &mut buffer[8..]),
        ] {
            let Some(written) = written else {
                return false;
            };
            length += written;
        }
        let request = match kind {
            Kind::Pli => rtcp::write_pli(sender_ssrc, media_ssrc, &mut buffer[length..]),
            Kind::Fir => {
                rtcp::write_fir(sender_ssrc, media_ssrc, fir_sequence, &mut buffer[length..])
            }
        };
        let Some(written) = request else {
            return false;
        };
        length += written;
        // A request to a bundled seat is SRTCP under the seat's key (RFC 3711 §3.4).
        let Some(sealed) = seal(
            video.bundled,
            seat.secure.as_mut(),
            &buffer[..length],
            &mut self.secure_out,
        ) else {
            return false;
        };
        let wire = if sealed {
            &self.secure_out[..]
        } else {
            &buffer[..length]
        };
        out.push(Outbound {
            endpoint,
            dst: destination,
            data: Bytes::copy_from_slice(wire),
        });
        match kind {
            Kind::Pli => seat.counters.pli_sent += 1,
            Kind::Fir => seat.counters.fir_sent += 1,
        }
        true
    }

    /// The parameter set `sps` (else the PPS) of the source, built into the room's replay buffer as
    /// the RTP packet that precedes the IDR at `point` by `distance` sequence numbers (RFC 6184
    /// §5.6: a single NAL unit packet; the access unit shares the IDR's timestamp, RFC 6184 §5.1),
    /// so the receiver's sequence numbers run on into the IDR without a gap. `None` when the source
    /// has none.
    fn build_replay(
        &mut self,
        source: usize,
        sps: bool,
        point: StreamPoint,
        distance: u16,
    ) -> Option<usize> {
        let sets = self.seats[source]
            .video
            .as_ref()?
            .keyframe_media
            .sets
            .as_ref()?;
        let unit = if sps { sets.sps() } else { sets.pps() }?;
        let header = RtpHeader {
            marker: false,
            payload_type: REPLAY_PAYLOAD_TYPE,
            sequence: point.sequence.wrapping_sub(distance),
            timestamp: point.timestamp,
            ssrc: point.ssrc,
        };
        write_packet(&header, unit, &mut self.keyframes.replay).ok()
    }

    /// Which parameter sets the receiver that has just been opened on the IDR packet of `plan` is
    /// sent before it: the source's last SPS and PPS, except one the packet carries itself.
    pub(super) fn plan_replay(&self, plan: &mut KeyframePlan, source: usize) {
        let sets = self.seats[source]
            .video
            .as_ref()
            .and_then(|video| video.keyframe_media.sets.as_ref());
        plan.replay_sps = !plan.has_sps && sets.is_some_and(|sets| sets.sps().is_some());
        plan.replay_pps = !plan.has_pps && sets.is_some_and(|sets| sets.pps().is_some());
    }

    /// Translate the replayed SPS (`sps`) or PPS for receiver `index` into the scratch buffer, ahead
    /// of the IDR at `point`. `None` when there is nothing to send or the translator refused it.
    pub(super) fn translate_replay(
        &mut self,
        index: usize,
        plan: &KeyframePlan,
        sps: bool,
        point: StreamPoint,
        arrival: u64,
    ) -> Option<usize> {
        let source = self.source?;
        // The parameter sets sit right before the IDR: the PPS at distance 1, the SPS before it.
        let distance = if sps && plan.replay_pps { 2 } else { 1 };
        let length = self.build_replay(source, sps, point, distance)?;
        let video = self.seats[index].video.as_mut()?;
        let clock = ticks(arrival, VIDEO_CLOCK_RATE_HZ);
        match video.translator.translate(
            &self.keyframes.replay[..length],
            video.payload_type,
            clock,
            &mut self.scratch,
        ) {
            Ok(Forwarded::Packet { length, .. }) => {
                video.last_forward_clock = clock;
                video.keyframe.replayed += 1;
                Some(length)
            }
            Ok(Forwarded::DroppedStale) => None,
            Err(error) => {
                tracing::debug!(
                    target: "siphon_rtp::media", room = %self.room_id, %error,
                    "forwarding room could not translate a replayed parameter set"
                );
                None
            }
        }
    }

    /// The next packet a receiver's NACK asked for, sent again through its translator, which writes
    /// it under the sequence number it was lost under. `None` when they are all sent.
    pub(super) fn next_retransmission(&mut self) -> Option<(EndpointId, SocketAddr, &[u8])> {
        loop {
            let retransmit = &mut self.keyframes.retransmit;
            if retransmit.next >= retransmit.count {
                self.plan = None;
                return None;
            }
            let sequence = retransmit.sequences[retransmit.next];
            retransmit.next += 1;
            let index = retransmit.receiver;
            let history = self.keyframes.history.as_deref();
            let receiver = self.seats.get_mut(index)?;
            if !receiver.reception.video {
                receiver.counters.reception_off_dropped_video += 1;
                continue;
            }
            let video = receiver.video.as_mut()?;
            let original = video
                .translator
                .source_ssrc()
                .and_then(|ssrc| history?.get(ssrc, sequence));
            let Some(original) = original else {
                receiver.counters.nack_missed += 1;
                continue;
            };
            let clock = video.last_forward_clock;
            let Ok(Forwarded::Packet { length, .. }) =
                video
                    .translator
                    .translate(original, video.payload_type, clock, &mut self.scratch)
            else {
                receiver.counters.nack_missed += 1;
                continue;
            };
            let (endpoint, destination) = receiver.video_route()?;
            let bundled = receiver.video.as_ref().is_some_and(|video| video.bundled);
            // SRTP again, under the seat's key: the same packet index gives the same bytes, which is
            // what a receiver that never saw the first one needs (RFC 3711 §3.3.1).
            let Some(sealed) = seal(
                bundled,
                receiver.secure.as_mut(),
                &self.scratch[..length],
                &mut self.secure_out,
            ) else {
                receiver.counters.nack_missed += 1;
                continue;
            };
            receiver.counters.nack_answered += 1;
            let wire = if sealed {
                &self.secure_out[..]
            } else {
                &self.scratch[..length]
            };
            return Some((endpoint, destination, wire));
        }
    }
}
