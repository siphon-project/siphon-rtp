//! DTMF telephone-event detection **and generation** (RFC 4733).
//!
//! A named telephone-event RTP stream carries one event across several redundant packets that
//! share the start RTP timestamp; the last packets set the End bit. [`DtmfDetector`] collapses
//! that into **one logical event per key press**, emitted when the End bit is seen (and de-duped
//! across the redundant End packets). The in-band Goertzel fallback (for streams that do not
//! signal events out-of-band) is a separate, later detector.
//!
//! [`DtmfGenerator`] is the inverse for `PlayDtmf`: it produces the sequence of 4-byte
//! telephone-event payloads for one key press — periodic update packets with the cumulative event
//! duration, then the final End packets repeated for redundancy (RFC 4733 §2.5.1.3). The engine
//! packetizes them into RTP (reusing [`crate::rtp::write_packet`]) at the telephone-event payload
//! type, holding the RTP timestamp constant for the whole event (RFC 4733 §2.5.1.2).

/// Errors from telephone-event parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DtmfError {
    /// The payload was shorter than the 4-byte telephone-event format.
    #[error("telephone-event payload too short")]
    TooShort,
}

/// Map a DTMF digit character to its RFC 4733 §3.2 event code (0-9 = digits, 10 = `*`, 11 = `#`,
/// 12-15 = `A`-`D`), or `None` for an unsupported character. Shared by the parser ([`TelephoneEvent
/// ::digit`]) and the generator so the table is defined once.
#[must_use]
pub fn digit_to_event_code(digit: char) -> Option<u8> {
    Some(match digit {
        '0'..='9' => digit as u8 - b'0',
        '*' => 10,
        '#' => 11,
        'A'..='D' => 12 + (digit as u8 - b'A'),
        // Some dialplans use lowercase a-d for the same A-D tones.
        'a'..='d' => 12 + (digit as u8 - b'a'),
        _ => return None,
    })
}

/// Map an RFC 4733 §3.2 event code to its DTMF digit character, or `None` for non-DTMF tones
/// (event ≥ 16). The inverse of [`digit_to_event_code`]; shared by parser and generator.
#[must_use]
pub fn event_code_to_digit(event_code: u8) -> Option<char> {
    Some(match event_code {
        0..=9 => (b'0' + event_code) as char,
        10 => '*',
        11 => '#',
        12..=15 => (b'A' + (event_code - 12)) as char,
        _ => return None,
    })
}

/// A parsed RFC 4733 telephone-event payload (4 bytes: event, E/R/volume, duration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelephoneEvent {
    /// Event code (0-9 = digits, 10 = `*`, 11 = `#`, 12-15 = `A`-`D`; ≥16 = tones).
    pub event: u8,
    /// End bit: this packet marks the end of the event.
    pub end: bool,
    /// Volume in -dBm0 (0-63).
    pub volume: u8,
    /// Event duration so far, in RTP timestamp units.
    pub duration: u16,
}

impl TelephoneEvent {
    /// Parse a 4-byte telephone-event payload (RFC 4733 §2.3).
    pub fn parse(payload: &[u8]) -> Result<Self, DtmfError> {
        if payload.len() < 4 {
            return Err(DtmfError::TooShort);
        }
        Ok(Self {
            event: payload[0],
            end: payload[1] & 0x80 != 0,
            volume: payload[1] & 0x3F,
            duration: u16::from_be_bytes([payload[2], payload[3]]),
        })
    }

    /// The DTMF digit character for this event, or `None` for non-DTMF tones (event ≥ 16).
    #[must_use]
    pub fn digit(&self) -> Option<char> {
        event_code_to_digit(self.event)
    }
}

/// One detected key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtmfEvent {
    /// The DTMF digit.
    pub digit: char,
    /// The raw event code.
    pub event_code: u8,
    /// Total duration in RTP timestamp units (from the End packet).
    pub duration: u16,
    /// Volume in -dBm0.
    pub volume: u8,
}

/// How many recently completed events the detector remembers, so a late retransmission of an
/// earlier event's End packet is not mistaken for a new press (RFC 4733 §2.5.1.3 sends it three
/// times, and the packets can reorder).
const COMPLETED_RING: usize = 4;

/// How far back, in RTP timestamp units, a packet may be from the newest event and still be a late
/// packet of an earlier one: about 21 s at 48 kHz and 131 s at 8 kHz, far longer than reordering or
/// the End redundancy can delay a packet. A timestamp further back than that is a sender whose
/// timeline restarted (RFC 3550 §5.1 starts it at a random value, and a sender may be reset or
/// replaced mid-call), so it is a new event and the old timeline is forgotten.
const LATE_PACKET_WINDOW: i32 = 1 << 20;

/// How long an event may go without an update before it is taken as over, in milliseconds: ten
/// missed updates of the 50 ms cadence (RFC 4733 §2.5.1.2). A receiver must cope with a lost End
/// (§2.5.1.4), so the press is completed with the duration of the last update.
pub const LOST_END_TIMEOUT_MS: u32 = 500;

/// The presses one call to a [`DtmfDetector`] completed: none, one, or the lost-End press of an
/// earlier event together with the one that completed it. A value, not a queue: the detector keeps
/// nothing for a caller to forget to collect, and the type is `#[must_use]`.
#[derive(Debug, Clone, Copy, Default)]
#[must_use = "the presses a packet completed are reported here and nowhere else"]
pub struct DtmfPresses {
    presses: [Option<DtmfEvent>; 3],
    next: usize,
}

impl DtmfPresses {
    fn push(&mut self, press: DtmfEvent) {
        if let Some(slot) = self.presses.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(press);
        }
    }
}

impl Iterator for DtmfPresses {
    type Item = DtmfEvent;

    fn next(&mut self) -> Option<DtmfEvent> {
        let press = self.presses.get(self.next).copied().flatten()?;
        self.next += 1;
        Some(press)
    }
}

/// The event being tracked.
#[derive(Debug, Clone, Copy)]
struct Tracked {
    timestamp: u32,
    event: u8,
    volume: u8,
    /// The longest duration any packet of the event has reported.
    duration: u16,
    /// Whether the press has been completed (by its End, or by one of the lost-End triggers).
    completed: bool,
}

impl Tracked {
    fn press(&self) -> Option<DtmfEvent> {
        Some(DtmfEvent {
            digit: event_code_to_digit(self.event)?,
            event_code: self.event,
            duration: self.duration,
            volume: self.volume,
        })
    }
}

/// How `timestamp` stands to `newest`, in RTP serial-number arithmetic (RFC 3550 §5.1, RFC 1982):
/// positive when it is later, zero when equal, negative when earlier.
fn serial_distance(timestamp: u32, newest: u32) -> i32 {
    timestamp.wrapping_sub(newest) as i32
}

/// Collapses a redundant RFC 4733 telephone-event stream into one [`DtmfEvent`] per press.
///
/// A press is completed by its End bit, de-duplicated across the three End packets (RFC 4733
/// §2.5.1.3) and across a reordered retransmission of an earlier press. Timestamps are compared in
/// serial arithmetic: only a **newer** start completes the open event, and an older packet is a late
/// packet that is deduplicated or completed on its own and never touches the open event. A lost End
/// does not lose the press (§2.5.1.4): it is completed when a newer event starts
/// ([`Self::on_packet`]), when audio resumes ([`Self::audio_resumed`]), or when no update has come
/// for [`LOST_END_TIMEOUT_MS`] ([`Self::tick`]), reporting the duration of the last update. All of it
/// runs on packet timestamps and a caller-supplied elapsed time, never a wall clock, and without
/// allocating. Every call returns the presses it completed.
#[derive(Debug, Default)]
pub struct DtmfDetector {
    current: Option<Tracked>,
    /// The newest event timestamp seen, started or completed.
    newest: Option<u32>,
    completed: [Option<u32>; COMPLETED_RING],
    completed_next: usize,
    /// Milliseconds since the last packet of an unfinished event.
    idle_ms: u32,
}

impl DtmfDetector {
    /// Create an idle detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one telephone-event RTP packet (its timestamp and payload): the presses it completed.
    pub fn on_packet(
        &mut self,
        rtp_timestamp: u32,
        payload: &[u8],
    ) -> Result<DtmfPresses, DtmfError> {
        let event = TelephoneEvent::parse(payload)?;
        let mut presses = DtmfPresses::default();
        self.idle_ms = 0;
        let distance = self
            .newest
            .map(|newest| serial_distance(rtp_timestamp, newest));
        match distance {
            // Exactly half the timestamp range away is neither later nor earlier in serial order
            // (RFC 1982 leaves it undefined), and not a restart either: it must neither complete the
            // open event nor clear history. Treated as a late packet and dropped.
            Some(i32::MIN) => return Ok(presses),
            // The event in progress (or the newest, already complete: a redundant End).
            Some(0) => {}
            // Earlier than the newest event, within reach of a reordered packet: a late packet of
            // an event that is not the open one. Never touches the open event.
            Some(distance) if (-LATE_PACKET_WINDOW..0).contains(&distance) => {
                self.late_packet(rtp_timestamp, &event, &mut presses);
                return Ok(presses);
            }
            // Further back than a late packet can be: the sender's timeline restarted. Forget the
            // old one; what follows is a new event.
            Some(distance) if distance < 0 => {
                self.complete_current(&mut presses);
                self.current = None;
                self.completed = [None; COMPLETED_RING];
                self.newest = Some(rtp_timestamp);
            }
            // Newer than everything seen: a new event, even if it reuses a remembered timestamp.
            // The open event never ended (that End was lost).
            Some(_) => {
                self.complete_current(&mut presses);
                self.current = None;
                self.newest = Some(rtp_timestamp);
            }
            None => self.newest = Some(rtp_timestamp),
        }
        // A packet at the newest timestamp that is not the open event is a retransmission of an
        // event already completed.
        if self.current.is_none() && distance == Some(0) {
            return Ok(presses);
        }
        let tracked = self.current.get_or_insert(Tracked {
            timestamp: rtp_timestamp,
            event: event.event,
            volume: event.volume,
            duration: 0,
            completed: false,
        });
        tracked.event = event.event;
        tracked.volume = event.volume;
        tracked.duration = tracked.duration.max(event.duration);
        if event.end {
            self.complete_current(&mut presses);
        }
        Ok(presses)
    }

    /// A packet older than the newest event: dropped when its event is known to be complete, and
    /// reported on its own when it is an End of an event this detector never saw (its other packets
    /// were lost), so the digit is not.
    fn late_packet(&mut self, timestamp: u32, event: &TelephoneEvent, presses: &mut DtmfPresses) {
        if self.completed.contains(&Some(timestamp)) || !event.end {
            return;
        }
        // Older than everything still remembered: the End of an event long since completed whose
        // record has been evicted, almost certainly a delayed retransmission (RFC 4733 §2.5.1.3).
        // A lone End is reported only when it falls among the remembered completions (or none is
        // remembered) and none of them matches.
        let oldest = self
            .completed
            .iter()
            .flatten()
            .copied()
            .reduce(|oldest, next| {
                if serial_distance(next, oldest) < 0 {
                    next
                } else {
                    oldest
                }
            });
        if oldest.is_some_and(|oldest| serial_distance(timestamp, oldest) < 0) {
            return;
        }
        self.remember_completed(timestamp);
        let Some(digit) = event.digit() else {
            return;
        };
        presses.push(DtmfEvent {
            digit,
            event_code: event.event,
            duration: event.duration,
            volume: event.volume,
        });
    }

    /// Audio is flowing again on the stream the events share: an event still unfinished is over.
    pub fn audio_resumed(&mut self) -> DtmfPresses {
        let mut presses = DtmfPresses::default();
        self.complete_current(&mut presses);
        presses
    }

    /// Advance the idle clock by `elapsed_ms` (a tick of the caller's own clock): an unfinished event
    /// with no update for [`LOST_END_TIMEOUT_MS`] is over.
    pub fn tick(&mut self, elapsed_ms: u32) -> DtmfPresses {
        let mut presses = DtmfPresses::default();
        if self.current.is_some_and(|tracked| !tracked.completed) {
            self.idle_ms = self.idle_ms.saturating_add(elapsed_ms);
            if self.idle_ms >= LOST_END_TIMEOUT_MS {
                self.complete_current(&mut presses);
            }
        }
        presses
    }

    fn remember_completed(&mut self, timestamp: u32) {
        self.completed[self.completed_next] = Some(timestamp);
        self.completed_next = (self.completed_next + 1) % COMPLETED_RING;
    }

    /// Complete the tracked event once: remember its timestamp, and report the press when it is a
    /// digit.
    fn complete_current(&mut self, presses: &mut DtmfPresses) {
        let Some(tracked) = self.current.as_mut().filter(|tracked| !tracked.completed) else {
            return;
        };
        tracked.completed = true;
        let tracked = *tracked;
        self.remember_completed(tracked.timestamp);
        if let Some(press) = tracked.press() {
            presses.push(press);
        }
    }
}

/// RFC 4733 §2.3: a telephone-event payload is one or more 4-octet blocks, the duration in the last
/// two octets of each.
const EVENT_BLOCK_LEN: usize = 4;

/// Copy a telephone-event `payload` into `out`, rescaling the duration of each event block from
/// `from_hz` to `to_hz` ticks (RFC 4733 §2.3.5: the duration is in timestamp units of the event
/// stream's clock). A duration that does not fit in 16 bits saturates, which RFC 4733 §2.5.1.5
/// handles by ending the event and starting another; the receiver just sees a long event.
pub fn rescale_event(payload: &[u8], from_hz: u32, to_hz: u32, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(payload);
    if from_hz == 0 || from_hz == to_hz {
        return;
    }
    let (blocks, _) = out.as_chunks_mut::<EVENT_BLOCK_LEN>();
    for block in blocks {
        let duration = u32::from(u16::from_be_bytes([block[2], block[3]]));
        let scaled = (u64::from(duration) * u64::from(to_hz) / u64::from(from_hz))
            .min(u64::from(u16::MAX)) as u16;
        block[2..4].copy_from_slice(&scaled.to_be_bytes());
    }
}

/// Default telephone-event volume in -dBm0 (RFC 4733 §2.3.4 recommends ≤ 0; -10 dBm0 is a common
/// playout level for generated digits).
pub const DEFAULT_DTMF_VOLUME_DBM0: u8 = 10;

/// Default inter-digit silence for a multi-digit `PlayDtmf` sequence when the request omits
/// `pause_ms`. RFC 4733 events are separated by a gap so the receiver's detector resolves distinct
/// presses (each event also carries its own start timestamp, §2.5.1.2); 40 ms is a short,
/// widely-interoperable inter-digit pause.
pub const DEFAULT_DTMF_PAUSE_MS: u32 = 40;

/// Number of times the final End packet is repeated for redundancy (RFC 4733 §2.5.1.3).
const END_PACKET_REDUNDANCY: u32 = 3;

/// One 4-byte telephone-event payload plus the metadata the engine needs to packetize it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtmfPayload {
    /// The 4-byte RFC 4733 telephone-event payload (event, E|R|volume, duration high/low).
    pub bytes: [u8; 4],
    /// `true` for the very first packet of the event — the engine sets the RTP marker bit on it
    /// (RFC 4733 §2.5.1.3: "the first packet ... SHOULD have the marker bit set").
    pub is_first: bool,
    /// `true` for an End packet (the last three, carrying the E bit).
    pub is_end: bool,
}

/// Generates the RFC 4733 telephone-event payload sequence for one DTMF key press (`PlayDtmf`).
///
/// The event is sent as a burst of packets that all share **one RTP timestamp** (the event start),
/// with the duration field counting cumulative samples. Update packets are emitted every `ptime`
/// until the requested duration is reached; the final state is then sent three times (the End
/// packet redundancy of RFC 4733 §2.5.1.3) with the End bit set. The engine pulls payloads via
/// [`DtmfGenerator::next_payload`] and writes each into RTP with [`crate::rtp::write_packet`],
/// advancing the RTP **sequence** per packet but holding the **timestamp** constant for the event.
#[derive(Debug, Clone)]
pub struct DtmfGenerator {
    /// RFC 4733 event code for the digit (0-15).
    event_code: u8,
    /// Volume magnitude in -dBm0 (0-63).
    volume: u8,
    /// Samples added per packet at the clock rate (e.g. 160 for 20 ms @ 8 kHz).
    samples_per_packet: u16,
    /// Total event duration in samples (clamped to `u16` per the 16-bit duration field).
    total_samples: u16,
    /// Cumulative duration carried by the next update packet.
    next_duration: u16,
    /// `true` until the first packet has been produced (drives the marker semantics).
    first_pending: bool,
    /// End packets still to emit once the update phase completes.
    end_packets_remaining: u32,
}

impl DtmfGenerator {
    /// Build a generator for `digit`, played for `duration_ms` at `clock_rate_hz` (8000 for DTMF),
    /// packetized every `ptime_ms`, at `volume` -dBm0. Returns `None` for a non-DTMF character.
    ///
    /// The duration is rounded up to a whole number of `ptime` packets so the last update packet's
    /// cumulative duration is exact. The 16-bit RFC 4733 duration field caps the event at 65535
    /// samples (≈ 8.19 s @ 8 kHz); longer requests are clamped.
    #[must_use]
    pub fn new(
        digit: char,
        duration_ms: u32,
        volume: u8,
        clock_rate_hz: u32,
        ptime_ms: u8,
    ) -> Option<Self> {
        let event_code = digit_to_event_code(digit)?;
        let ptime_ms = ptime_ms.max(1);
        let samples_per_packet = ((clock_rate_hz as u64 * u64::from(ptime_ms)) / 1000)
            .clamp(1, u64::from(u16::MAX)) as u16;
        let requested_samples = (clock_rate_hz as u64 * u64::from(duration_ms)) / 1000;
        // Round up to a whole packet so the final update carries the full requested duration.
        let packets = requested_samples
            .div_ceil(u64::from(samples_per_packet))
            .max(1);
        let total_samples =
            (packets * u64::from(samples_per_packet)).min(u64::from(u16::MAX)) as u16;

        Some(Self {
            event_code,
            volume: volume & 0x3F,
            samples_per_packet,
            total_samples,
            next_duration: 0,
            first_pending: true,
            end_packets_remaining: END_PACKET_REDUNDANCY,
        })
    }

    /// The RFC 4733 event code being generated.
    #[must_use]
    pub fn event_code(&self) -> u8 {
        self.event_code
    }

    /// Total event duration in samples (cumulative duration the End packets carry).
    #[must_use]
    pub fn total_samples(&self) -> u16 {
        self.total_samples
    }

    /// Build a 4-byte telephone-event payload (RFC 4733 §2.3).
    fn payload_bytes(&self, end: bool, duration: u16) -> [u8; 4] {
        // Byte 1: E (bit 7), R (bit 6, always 0), volume (bits 5-0).
        let end_reserved_volume = (u8::from(end) << 7) | self.volume;
        let [duration_high, duration_low] = duration.to_be_bytes();
        [
            self.event_code,
            end_reserved_volume,
            duration_high,
            duration_low,
        ]
    }

    /// Pull the next telephone-event payload, or `None` once the whole burst (updates + redundant
    /// End packets) has been produced. The first call yields the marker packet; the final three
    /// carry the End bit and the total cumulative duration.
    pub fn next_payload(&mut self) -> Option<DtmfPayload> {
        // Update phase: advance the cumulative duration one packet at a time until it reaches the
        // total. Each packet reports the duration *as of that packet* (RFC 4733 §2.5.1.2).
        if self.next_duration < self.total_samples {
            self.next_duration = self
                .next_duration
                .saturating_add(self.samples_per_packet)
                .min(self.total_samples);
            let is_first = self.first_pending;
            self.first_pending = false;
            return Some(DtmfPayload {
                bytes: self.payload_bytes(false, self.next_duration),
                is_first,
                is_end: false,
            });
        }

        // End phase: repeat the final packet with the End bit set for redundancy (§2.5.1.3).
        if self.end_packets_remaining > 0 {
            self.end_packets_remaining -= 1;
            // Edge case: a zero-length request never sent an update packet, so the very first End
            // packet still owns the marker semantics.
            let is_first = self.first_pending;
            self.first_pending = false;
            return Some(DtmfPayload {
                bytes: self.payload_bytes(true, self.total_samples),
                is_first,
                is_end: true,
            });
        }

        None
    }
}

/// One playout tick's action while a [`DtmfSequence`] is playing (`PlayDtmf` with a multi-digit code).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DtmfStep {
    /// Emit this telephone-event payload. `timestamp_offset` is the number of samples from the
    /// sequence's base RTP timestamp to *this digit's* event start: every digit is a distinct RFC 4733
    /// event with its own start timestamp (RFC 4733 §2.5.1.2), so consecutive digits get strictly
    /// increasing offsets and the receiver's detector resolves them as separate presses.
    Event {
        payload: DtmfPayload,
        timestamp_offset: u32,
    },
    /// Inter-digit silence — emit no telephone-event this tick (the RFC 4733 gap between events).
    Silence,
    /// The whole multi-digit sequence has been produced.
    Done,
}

/// Plays a multi-digit DTMF string (`PlayDtmf` `code`, e.g. `"123#"`) as a sequence of RFC 4733
/// telephone events: each digit is one event of `duration_ms` (a [`DtmfGenerator`]), separated by
/// `pause_ms` of inter-digit silence. Each digit event carries its own start RTP timestamp — the
/// engine adds the step's `timestamp_offset` to the frozen base so the receiver's detector
/// distinguishes consecutive presses (RFC 4733 §2.5.1.2). Driven one packet per playout tick via
/// [`DtmfSequence::next_step`], mirroring how [`DtmfGenerator::next_payload`] drives a single digit.
#[derive(Debug, Clone)]
pub struct DtmfSequence {
    /// Digits still to play, in order.
    digits: std::collections::VecDeque<char>,
    /// Per-digit generation parameters (each digit builds its own [`DtmfGenerator`]).
    duration_ms: u32,
    volume: u8,
    clock_rate_hz: u32,
    ptime_ms: u8,
    /// Whole-packet inter-digit silence ticks emitted between one event's end and the next's start.
    pause_ticks: u32,
    /// Samples per packet at the clock rate (e.g. 160 for 20 ms @ 8 kHz), for the inter-digit gap.
    samples_per_packet: u16,
    /// The generator for the digit currently playing, if one is active.
    current: Option<DtmfGenerator>,
    /// Inter-digit silence ticks still to emit before the next digit starts.
    pause_remaining: u32,
    /// The currently-playing (or next) digit event's start offset in samples from the sequence base.
    current_offset: u32,
}

impl DtmfSequence {
    /// Build a sequence for `code` (each digit played for `duration_ms` at `volume` -dBm0), packetized
    /// every `ptime_ms` at `clock_rate_hz`, with `pause_ms` of silence between digits. Returns `None`
    /// when `code` is empty or carries a non-DTMF character — the caller validates the code up front
    /// and treats `None` as "cannot start".
    #[must_use]
    pub fn new(
        code: &str,
        duration_ms: u32,
        volume: u8,
        clock_rate_hz: u32,
        ptime_ms: u8,
        pause_ms: u32,
    ) -> Option<Self> {
        if code.is_empty()
            || code
                .chars()
                .any(|digit| digit_to_event_code(digit).is_none())
        {
            return None;
        }
        let ptime_ms = ptime_ms.max(1);
        let samples_per_packet = ((u64::from(clock_rate_hz) * u64::from(ptime_ms)) / 1000)
            .clamp(1, u64::from(u16::MAX)) as u16;
        // The inter-digit gap is a whole number of playout packets (§2.5 leaves the exact gap to the
        // sender); round up so a sub-ptime pause still yields at least one silence tick.
        let pause_ticks = u64::from(pause_ms)
            .div_ceil(u64::from(ptime_ms))
            .min(u64::from(u32::MAX)) as u32;
        Some(Self {
            digits: code.chars().collect(),
            duration_ms,
            volume,
            clock_rate_hz,
            ptime_ms,
            pause_ticks,
            samples_per_packet,
            current: None,
            pause_remaining: 0,
            current_offset: 0,
        })
    }

    /// Pop the next digit off the queue and arm its generator. Returns `false` once the queue is empty
    /// (the whole sequence has played).
    fn start_next_digit(&mut self) -> bool {
        while let Some(digit) = self.digits.pop_front() {
            if let Some(generator) = DtmfGenerator::new(
                digit,
                self.duration_ms,
                self.volume,
                self.clock_rate_hz,
                self.ptime_ms,
            ) {
                self.current = Some(generator);
                return true;
            }
            // `new()` validated every character, so a non-DTMF digit here is unreachable; skip it
            // defensively rather than emit a bogus event.
        }
        false
    }

    /// Produce the next tick's action: one telephone-event payload for the current digit, an
    /// inter-digit silence tick, or [`DtmfStep::Done`] once the whole sequence has played.
    pub fn next_step(&mut self) -> DtmfStep {
        loop {
            if self.pause_remaining > 0 {
                self.pause_remaining -= 1;
                return DtmfStep::Silence;
            }
            if self.current.is_none() && !self.start_next_digit() {
                return DtmfStep::Done;
            }
            let offset = self.current_offset;
            let finished_total = match self.current.as_mut() {
                Some(generator) => match generator.next_payload() {
                    Some(payload) => {
                        return DtmfStep::Event {
                            payload,
                            timestamp_offset: offset,
                        }
                    }
                    // The digit's event drained; capture its media duration to advance the base offset.
                    None => generator.total_samples(),
                },
                None => return DtmfStep::Done, // unreachable: start_next_digit set `current`
            };
            self.current = None;
            // The inter-digit gap only separates *consecutive* events — no trailing silence after the
            // final digit. When another digit remains, advance the base offset past this event plus the
            // gap and arm the silence; then loop to emit the pause / next digit (RFC 4733 §2.5.1.2).
            if !self.digits.is_empty() {
                let gap = self
                    .pause_ticks
                    .saturating_mul(u32::from(self.samples_per_packet));
                self.current_offset = self
                    .current_offset
                    .wrapping_add(u32::from(finished_total))
                    .wrapping_add(gap);
                self.pause_remaining = self.pause_ticks;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_payload(event: u8, end: bool, duration: u16) -> [u8; 4] {
        let [high, low] = duration.to_be_bytes();
        [event, if end { 0x8A } else { 0x0A }, high, low]
    }

    /// Feed one packet and collect the presses it completed as (digit, duration).
    fn feed(
        detector: &mut DtmfDetector,
        timestamp: u32,
        event: u8,
        end: bool,
        duration: u16,
    ) -> Vec<(char, u16)> {
        detector
            .on_packet(timestamp, &event_payload(event, end, duration))
            .expect("packet")
            .map(|press| (press.digit, press.duration))
            .collect()
    }

    fn collect(presses: DtmfPresses) -> Vec<(char, u16)> {
        presses.map(|press| (press.digit, press.duration)).collect()
    }

    #[test]
    fn a_late_end_of_an_earlier_event_is_not_a_second_press() {
        // RFC 4733 §2.5.1.3: the End is sent three times and packets reorder. A ends, B starts, then
        // A's End arrives again: one press for A, one for B.
        let mut detector = DtmfDetector::new();
        assert_eq!(feed(&mut detector, 1000, 1, true, 800), [('1', 800)]);
        assert_eq!(feed(&mut detector, 2000, 2, false, 160), []);
        assert_eq!(
            feed(&mut detector, 1000, 1, true, 800),
            [],
            "A's End again is ignored"
        );
        assert_eq!(feed(&mut detector, 2000, 2, true, 800), [('2', 800)]);
    }

    #[test]
    fn an_older_packet_never_completes_the_open_event() {
        // B updates at 2000; A's late End (an event this detector never saw) arrives at 1000; B's End
        // follows. B is reported once with 800, and A's digit is not lost either.
        let mut detector = DtmfDetector::new();
        assert_eq!(feed(&mut detector, 2000, 2, false, 160), []);
        assert_eq!(
            feed(&mut detector, 1000, 1, true, 800),
            [('1', 800)],
            "A on its own"
        );
        assert_eq!(
            feed(&mut detector, 2000, 2, false, 480),
            [],
            "B is still open"
        );
        assert_eq!(
            feed(&mut detector, 2000, 2, true, 800),
            [('2', 800)],
            "B once, with 800"
        );
        assert_eq!(feed(&mut detector, 2000, 2, true, 800), [], "and not again");
        // The same when A was already reported: its retransmission is simply dropped.
        let mut detector = DtmfDetector::new();
        assert_eq!(feed(&mut detector, 1000, 1, true, 800), [('1', 800)]);
        assert_eq!(feed(&mut detector, 2000, 2, false, 160), []);
        assert_eq!(feed(&mut detector, 1000, 1, true, 800), []);
        assert_eq!(feed(&mut detector, 2000, 2, true, 800), [('2', 800)]);
    }

    #[test]
    fn timestamps_compare_across_the_32_bit_wrap() {
        // 0xFFFF_FF00 then 0x0000_0100 is 512 units later, not 4 billion earlier.
        let mut detector = DtmfDetector::new();
        assert_eq!(feed(&mut detector, 0xFFFF_FF00, 1, false, 160), []);
        assert_eq!(
            feed(&mut detector, 0x0000_0100, 2, false, 160),
            [('1', 160)],
            "the later event completes the one whose End was lost"
        );
        assert_eq!(feed(&mut detector, 0x0000_0100, 2, true, 800), [('2', 800)]);
        // And an older packet across the wrap is late, not new.
        assert_eq!(feed(&mut detector, 0xFFFF_FF00, 1, true, 800), []);
    }

    #[test]
    fn a_delayed_end_older_than_everything_remembered_is_a_retransmission() {
        // A updates, then B, C, D and E complete and evict A from the ring; A's delayed End arrives.
        // It is reported once (the first time A was completed), never as a lone press afterwards.
        let mut detector = DtmfDetector::new();
        assert_eq!(feed(&mut detector, 1000, 1, false, 160), []);
        assert_eq!(
            feed(&mut detector, 2000, 2, true, 800),
            [('1', 160), ('2', 800)]
        );
        assert_eq!(feed(&mut detector, 3000, 3, true, 800), [('3', 800)]);
        assert_eq!(feed(&mut detector, 4000, 4, true, 800), [('4', 800)]);
        assert_eq!(feed(&mut detector, 5000, 5, true, 800), [('5', 800)]);
        assert_eq!(
            feed(&mut detector, 1000, 1, true, 800),
            [],
            "A is not reported twice"
        );
        // An End between remembered completions that none matches is still a lone End.
        let mut detector = DtmfDetector::new();
        assert_eq!(feed(&mut detector, 1000, 1, true, 800), [('1', 800)]);
        assert_eq!(feed(&mut detector, 3000, 3, true, 800), [('3', 800)]);
        assert_eq!(
            feed(&mut detector, 2000, 2, true, 800),
            [('2', 800)],
            "between 1000 and 3000"
        );
    }

    #[test]
    fn timestamps_half_the_range_apart_never_clear_history_or_complete_the_open_event() {
        // 0 and 0x8000_0000 are neither earlier nor later than each other.
        let mut detector = DtmfDetector::new();
        let mut reported = Vec::new();
        for _ in 0..4 {
            reported.extend(feed(&mut detector, 0, 1, true, 800));
            reported.extend(feed(&mut detector, 0x8000_0000, 2, true, 800));
        }
        assert_eq!(reported, [('1', 800)], "each digit at most once");
        // And an open event is left alone by a packet half the range away.
        let mut detector = DtmfDetector::new();
        assert_eq!(feed(&mut detector, 0, 1, false, 160), []);
        assert_eq!(feed(&mut detector, 0x8000_0000, 2, true, 800), []);
        assert_eq!(feed(&mut detector, 0, 1, true, 800), [('1', 800)]);
    }

    #[test]
    fn a_sender_reset_is_a_new_event_even_on_a_remembered_timestamp() {
        // The timeline restarts far behind (RFC 3550 §5.1: the sender picked a new origin): C reuses
        // the timestamp A had, and is a press of its own.
        let mut detector = DtmfDetector::new();
        assert_eq!(feed(&mut detector, 1_000_000, 1, true, 800), [('1', 800)]);
        assert_eq!(feed(&mut detector, 5_000_000, 2, true, 800), [('2', 800)]);
        // 4 million units back is far past any late packet (see `LATE_PACKET_WINDOW`): a restart.
        assert_eq!(feed(&mut detector, 1_000_000, 3, true, 800), [('3', 800)]);
        // The restarted timeline is the live one: C's own End, again, is a retransmission.
        assert_eq!(feed(&mut detector, 1_000_000, 3, true, 800), []);
        // And a small step back to a remembered timestamp is a late packet, not a new press.
        assert_eq!(feed(&mut detector, 1_000_500, 4, true, 800), [('4', 800)]);
        assert_eq!(feed(&mut detector, 1_000_000, 3, true, 800), []);
        // A reset while an event is open completes it, and nothing is double counted.
        let mut detector = DtmfDetector::new();
        assert_eq!(feed(&mut detector, 5_000_000, 4, false, 320), []);
        assert_eq!(
            feed(&mut detector, 100, 5, true, 800),
            [('4', 320), ('5', 800)]
        );
    }

    #[test]
    fn a_lost_end_and_the_next_events_only_surviving_packet_are_both_reported() {
        // A never ends; B's only surviving packet is its End. Both come out of that one call.
        let mut detector = DtmfDetector::new();
        assert_eq!(feed(&mut detector, 1000, 1, false, 160), []);
        assert_eq!(feed(&mut detector, 1000, 1, false, 480), []);
        assert_eq!(
            feed(&mut detector, 2000, 2, true, 800),
            [('1', 480), ('2', 800)]
        );
    }

    #[test]
    fn a_lost_end_is_completed_by_the_next_events_first_packet_with_the_last_duration() {
        let mut detector = DtmfDetector::new();
        assert_eq!(feed(&mut detector, 1000, 1, false, 160), []);
        assert_eq!(feed(&mut detector, 1000, 1, false, 480), []);
        // A's whole End burst is lost; B starts: A is completed with the last update's duration.
        assert_eq!(feed(&mut detector, 2000, 2, false, 160), [('1', 480)]);
        // A late End of A changes nothing, and B still completes normally, once.
        assert_eq!(feed(&mut detector, 1000, 1, true, 800), []);
        assert_eq!(feed(&mut detector, 2000, 2, true, 800), [('2', 800)]);
    }

    #[test]
    fn a_lost_end_is_completed_when_audio_resumes() {
        let mut detector = DtmfDetector::new();
        assert_eq!(feed(&mut detector, 1000, 5, false, 320), []);
        assert_eq!(collect(detector.audio_resumed()), [('5', 320)]);
        assert_eq!(collect(detector.audio_resumed()), [], "once only");
    }

    #[test]
    fn a_lost_end_is_completed_after_the_timeout_on_the_callers_clock() {
        let mut detector = DtmfDetector::new();
        assert_eq!(feed(&mut detector, 1000, 11, false, 400), []);
        for _ in 0..24 {
            assert_eq!(collect(detector.tick(20)), []);
        }
        assert_eq!(collect(detector.tick(20)), [('#', 400)], "500 ms: over");
        // An idle detector never completes anything; updates keep an event alive.
        assert_eq!(collect(detector.tick(10_000)), []);
        assert_eq!(feed(&mut detector, 3000, 1, false, 160), []);
        assert_eq!(collect(detector.tick(400)), []);
        assert_eq!(feed(&mut detector, 3000, 1, false, 320), []);
        assert_eq!(collect(detector.tick(400)), [], "updates keep it alive");
    }

    fn payload(event: u8, end: bool, volume: u8, duration: u16) -> [u8; 4] {
        let end_volume = (u8::from(end) << 7) | (volume & 0x3F);
        let [duration_hi, duration_lo] = duration.to_be_bytes();
        [event, end_volume, duration_hi, duration_lo]
    }

    #[test]
    fn parses_payload_fields() {
        let event = TelephoneEvent::parse(&payload(5, true, 10, 800)).expect("parse");
        assert_eq!(event.event, 5);
        assert!(event.end);
        assert_eq!(event.volume, 10);
        assert_eq!(event.duration, 800);
        assert_eq!(event.digit(), Some('5'));
    }

    #[test]
    fn maps_all_dtmf_digits() {
        let cases = [
            (0u8, '0'),
            (9, '9'),
            (10, '*'),
            (11, '#'),
            (12, 'A'),
            (13, 'B'),
            (14, 'C'),
            (15, 'D'),
        ];
        for (code, digit) in cases {
            assert_eq!(
                TelephoneEvent::parse(&payload(code, false, 0, 0))
                    .unwrap()
                    .digit(),
                Some(digit)
            );
        }
        // A tone (event >= 16) is not a DTMF digit.
        assert_eq!(
            TelephoneEvent::parse(&payload(16, false, 0, 0))
                .unwrap()
                .digit(),
            None
        );
    }

    #[test]
    fn emits_once_per_press_on_end_bit() {
        let mut detector = DtmfDetector::new();
        // Three packets of one event at timestamp 1000; only the last sets End.
        assert_eq!(
            detector
                .on_packet(1000, &payload(7, false, 8, 160))
                .unwrap()
                .next(),
            None
        );
        assert_eq!(
            detector
                .on_packet(1000, &payload(7, false, 8, 320))
                .unwrap()
                .next(),
            None
        );
        let emitted = detector
            .on_packet(1000, &payload(7, true, 8, 480))
            .unwrap()
            .next();
        assert_eq!(
            emitted,
            Some(DtmfEvent {
                digit: '7',
                event_code: 7,
                duration: 480,
                volume: 8
            })
        );
    }

    #[test]
    fn dedupes_redundant_end_packets() {
        let mut detector = DtmfDetector::new();
        let _ = detector
            .on_packet(2000, &payload(3, false, 8, 160))
            .unwrap();
        assert!(detector
            .on_packet(2000, &payload(3, true, 8, 320))
            .unwrap()
            .next()
            .is_some());
        // RFC 4733 sends the End packet up to three times; only the first emits.
        for _ in 0..2 {
            assert_eq!(
                detector
                    .on_packet(2000, &payload(3, true, 8, 320))
                    .unwrap()
                    .next(),
                None
            );
        }
    }

    #[test]
    fn distinguishes_consecutive_presses_by_timestamp() {
        let mut detector = DtmfDetector::new();
        // Press '1' at ts 100.
        assert!(detector
            .on_packet(100, &payload(1, true, 8, 160))
            .unwrap()
            .next()
            .is_some());
        // Press '2' at a new timestamp.
        let second = detector
            .on_packet(260, &payload(2, true, 8, 160))
            .unwrap()
            .next();
        assert_eq!(second.map(|event| event.digit), Some('2'));
    }

    #[test]
    fn rejects_short_payload() {
        assert_eq!(TelephoneEvent::parse(&[0u8; 3]), Err(DtmfError::TooShort));
        let mut detector = DtmfDetector::new();
        assert!(matches!(
            detector.on_packet(0, &[0u8; 2]),
            Err(DtmfError::TooShort)
        ));
    }

    #[test]
    fn shared_digit_event_mapping_is_consistent() {
        // The generator's digit→code table and the parser's code→digit table are inverses across
        // every DTMF key (RFC 4733 §3.2).
        let cases = [
            ('0', 0u8),
            ('5', 5),
            ('9', 9),
            ('*', 10),
            ('#', 11),
            ('A', 12),
            ('B', 13),
            ('C', 14),
            ('D', 15),
        ];
        for (digit, code) in cases {
            assert_eq!(digit_to_event_code(digit), Some(code), "digit {digit}");
            assert_eq!(event_code_to_digit(code), Some(digit), "code {code}");
        }
        // Lowercase a-d alias onto the A-D tones for dialplan convenience.
        assert_eq!(digit_to_event_code('c'), Some(14));
        // Non-DTMF characters and tone codes have no mapping.
        assert_eq!(digit_to_event_code('!'), None);
        assert_eq!(event_code_to_digit(16), None);
    }

    #[test]
    fn rejects_non_dtmf_digit() {
        assert!(DtmfGenerator::new('Z', 100, 10, 8000, 20).is_none());
    }

    #[test]
    fn generates_digit_5_for_100ms_at_8khz() {
        // '5' for 100 ms @ 8 kHz, 20 ms ptime → 5 update packets (160 samples each) + 3 End.
        let mut generator =
            DtmfGenerator::new('5', 100, DEFAULT_DTMF_VOLUME_DBM0, 8000, 20).expect("generator");
        assert_eq!(generator.event_code(), 5);
        assert_eq!(generator.total_samples(), 800);

        let mut payloads = Vec::new();
        while let Some(payload) = generator.next_payload() {
            payloads.push(payload);
        }
        // 5 updates + 3 End redundancy packets.
        assert_eq!(payloads.len(), 8);

        // First packet carries the marker semantics; no later packet does.
        assert!(payloads[0].is_first);
        assert!(payloads[1..].iter().all(|payload| !payload.is_first));

        // Update packets: cumulative duration 160, 320, 480, 640, 800; E bit clear; event 5.
        let expected_durations = [160u16, 320, 480, 640, 800];
        for (index, &expected) in expected_durations.iter().enumerate() {
            let parsed = TelephoneEvent::parse(&payloads[index].bytes).expect("parse update");
            assert_eq!(parsed.event, 5);
            assert!(!parsed.end, "update packet {index} must not set End");
            assert_eq!(
                parsed.duration, expected,
                "cumulative duration at packet {index}"
            );
            assert_eq!(parsed.volume, DEFAULT_DTMF_VOLUME_DBM0);
            assert!(!payloads[index].is_end);
        }

        // Final 3 packets: E bit set, all carry the full event duration (800).
        for end_payload in &payloads[5..] {
            assert!(end_payload.is_end);
            let parsed = TelephoneEvent::parse(&end_payload.bytes).expect("parse end");
            assert!(parsed.end, "End packet must set the E bit");
            assert_eq!(parsed.duration, 800, "End packets carry the total duration");
            assert_eq!(parsed.event, 5);
        }
    }

    #[test]
    fn generated_payload_roundtrips_through_parser() {
        // A generated payload fed back through the existing parser reconstructs the same digit.
        let mut generator = DtmfGenerator::new('#', 40, 12, 8000, 20).expect("generator");
        let first = generator.next_payload().expect("first");
        let parsed = TelephoneEvent::parse(&first.bytes).expect("parse");
        assert_eq!(parsed.digit(), Some('#'));
        assert_eq!(parsed.event, 11);
        assert_eq!(parsed.volume, 12);
    }

    #[test]
    fn end_packets_drive_the_detector_to_emit_the_digit() {
        // End-to-end: generate '7', packetize at a constant RTP timestamp (RFC 4733 §2.5.1.2), feed
        // the detector — it must emit exactly one press for the digit.
        let mut generator = DtmfGenerator::new('7', 60, 8, 8000, 20).expect("generator");
        let mut detector = DtmfDetector::new();
        let event_timestamp = 5000u32; // constant for the whole event
        let mut emitted = Vec::new();
        while let Some(payload) = generator.next_payload() {
            for event in detector
                .on_packet(event_timestamp, &payload.bytes)
                .expect("detector")
            {
                emitted.push(event);
            }
        }
        assert_eq!(emitted.len(), 1, "exactly one press emitted");
        assert_eq!(emitted[0].digit, '7');
    }

    #[test]
    fn duration_rounds_up_to_whole_packets() {
        // 30 ms @ 8 kHz with a 20 ms ptime needs 2 packets (160 + 160 = 320 samples), not 1.5.
        let mut generator = DtmfGenerator::new('1', 30, 10, 8000, 20).expect("generator");
        assert_eq!(generator.total_samples(), 320);
        let mut updates = 0;
        let mut ends = 0;
        while let Some(payload) = generator.next_payload() {
            if payload.is_end {
                ends += 1;
            } else {
                updates += 1;
            }
        }
        assert_eq!(updates, 2);
        assert_eq!(ends, 3);
    }

    #[test]
    fn zero_duration_still_sends_redundant_end_packets() {
        // A 0 ms request rounds up to one packet's worth of duration but produces no update
        // packets; the End burst still carries the marker on the first packet.
        let mut generator = DtmfGenerator::new('0', 0, 10, 8000, 20).expect("generator");
        let payloads: Vec<_> = std::iter::from_fn(|| generator.next_payload()).collect();
        // One rounded-up update packet + 3 End packets.
        assert_eq!(payloads.iter().filter(|payload| payload.is_end).count(), 3);
        assert!(payloads[0].is_first);
    }

    #[test]
    fn long_duration_clamps_to_16bit_field() {
        // A request longer than the 16-bit duration field (>65535 samples @ 8 kHz ≈ 8.19 s) clamps
        // to the field maximum: 60 s would be 480000 samples, capped at u16::MAX = 65535.
        let mut generator = DtmfGenerator::new('2', 60_000, 10, 8000, 20).expect("generator");
        assert_eq!(generator.total_samples(), 65535);
        // Pulling the whole burst must terminate (no infinite loop on the saturating duration).
        let count = std::iter::from_fn(|| generator.next_payload()).count();
        assert!(count > 3);
    }

    /// Drain a whole [`DtmfSequence`], collecting each emitted step (events + silence ticks).
    fn drain_sequence(sequence: &mut DtmfSequence) -> Vec<DtmfStep> {
        let mut steps = Vec::new();
        loop {
            match sequence.next_step() {
                DtmfStep::Done => break,
                step => steps.push(step),
            }
        }
        steps
    }

    #[test]
    fn sequence_rejects_empty_or_non_dtmf_code() {
        assert!(DtmfSequence::new("", 100, 10, 8000, 20, 40).is_none());
        assert!(DtmfSequence::new("1X2", 100, 10, 8000, 20, 40).is_none());
        assert!(DtmfSequence::new("12", 100, 10, 8000, 20, 40).is_some());
    }

    #[test]
    fn single_digit_sequence_matches_the_lone_generator() {
        // A one-digit sequence emits exactly the same telephone-event payloads a bare DtmfGenerator
        // does, all at offset 0 — so the single-digit path is unchanged by multi-digit support.
        let mut sequence =
            DtmfSequence::new("5", 100, DEFAULT_DTMF_VOLUME_DBM0, 8000, 20, 40).expect("sequence");
        let mut generator =
            DtmfGenerator::new('5', 100, DEFAULT_DTMF_VOLUME_DBM0, 8000, 20).expect("generator");
        while let Some(expected) = generator.next_payload() {
            match sequence.next_step() {
                DtmfStep::Event {
                    payload,
                    timestamp_offset,
                } => {
                    assert_eq!(payload, expected);
                    assert_eq!(
                        timestamp_offset, 0,
                        "a single digit starts at the base timestamp"
                    );
                }
                other => panic!("expected an event, got {other:?}"),
            }
        }
        assert_eq!(sequence.next_step(), DtmfStep::Done);
    }

    #[test]
    fn multi_digit_sequence_separates_events_by_pause_and_timestamp() {
        // "12" @ 100 ms / 8 kHz / 20 ms ptime with a 40 ms pause → each digit is 5 updates + 3 End
        // packets, and the two events are separated by 2 silence ticks (40 ms / 20 ms) with the
        // second event's start timestamp advanced past the first (RFC 4733 §2.5.1.2).
        let mut sequence = DtmfSequence::new("12", 100, 10, 8000, 20, 40).expect("sequence");
        let steps = drain_sequence(&mut sequence);

        let events: Vec<_> = steps
            .iter()
            .filter_map(|step| match step {
                DtmfStep::Event {
                    payload,
                    timestamp_offset,
                } => Some((*payload, *timestamp_offset)),
                DtmfStep::Silence => None,
                DtmfStep::Done => None,
            })
            .collect();
        let silence_ticks = steps.iter().filter(|s| **s == DtmfStep::Silence).count();
        assert_eq!(
            silence_ticks, 2,
            "40 ms pause at 20 ms ptime is 2 silence ticks"
        );
        // 8 packets per digit (5 update + 3 End) × 2 digits.
        assert_eq!(events.len(), 16);

        // First digit '1' at offset 0; second digit '2' at offset 800 (its total) + 320 (2-tick gap).
        let first_offset = events[0].1;
        let second_offset = events[8].1;
        assert_eq!(first_offset, 0);
        assert_eq!(
            second_offset,
            800 + 320,
            "second event starts past the first + the gap"
        );
        assert!(events[..8]
            .iter()
            .all(|(_, offset)| *offset == first_offset));
        assert!(events[8..]
            .iter()
            .all(|(_, offset)| *offset == second_offset));

        // Each digit's very first packet carries the marker (a new event); event codes are 1 then 2.
        assert!(events[0].0.is_first, "digit 1 opens with the marker");
        assert!(events[8].0.is_first, "digit 2 opens with the marker");
        assert_eq!(events[0].0.bytes[0], 1);
        assert_eq!(events[8].0.bytes[0], 2);
    }

    #[test]
    fn multi_digit_sequence_decodes_back_to_every_press() {
        // End-to-end: play "123#", packetize each event at base + its timestamp offset (§2.5.1.2),
        // feed the redundant stream through the detector, and recover all four presses in order.
        let mut sequence = DtmfSequence::new("123#", 80, 8, 8000, 20, 40).expect("sequence");
        let mut detector = DtmfDetector::new();
        let base_timestamp = 5000u32;
        let mut pressed = Vec::new();
        loop {
            match sequence.next_step() {
                DtmfStep::Event {
                    payload,
                    timestamp_offset,
                } => {
                    let timestamp = base_timestamp.wrapping_add(timestamp_offset);
                    for event in detector
                        .on_packet(timestamp, &payload.bytes)
                        .expect("detector")
                    {
                        pressed.push(event.digit);
                    }
                }
                DtmfStep::Silence => {}
                DtmfStep::Done => break,
            }
        }
        assert_eq!(pressed, vec!['1', '2', '3', '#']);
    }

    #[test]
    fn zero_pause_still_distinguishes_consecutive_digits_by_timestamp() {
        // With no inter-digit pause the sequence emits no silence, but each event still gets a fresh
        // start timestamp (advanced by the prior digit's duration), so a repeated digit "11" decodes
        // as two presses rather than collapsing into one.
        let mut sequence = DtmfSequence::new("11", 40, 10, 8000, 20, 0).expect("sequence");
        let mut detector = DtmfDetector::new();
        let base = 1000u32;
        let mut pressed = Vec::new();
        loop {
            match sequence.next_step() {
                DtmfStep::Event {
                    payload,
                    timestamp_offset,
                } => {
                    for event in detector
                        .on_packet(base.wrapping_add(timestamp_offset), &payload.bytes)
                        .expect("detector")
                    {
                        pressed.push(event.digit);
                    }
                }
                DtmfStep::Silence => panic!("a zero pause emits no silence ticks"),
                DtmfStep::Done => break,
            }
        }
        assert_eq!(pressed, vec!['1', '1']);
    }
}
