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

/// Collapses a redundant RFC 4733 telephone-event stream into one [`DtmfEvent`] per press.
#[derive(Debug, Default)]
pub struct DtmfDetector {
    /// The start timestamp of the event currently being tracked, and whether it was emitted.
    current: Option<(u32, bool)>,
}

impl DtmfDetector {
    /// Create an idle detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one telephone-event RTP packet (its timestamp and payload). Returns the press exactly
    /// once, when the event's End bit is observed.
    pub fn on_packet(
        &mut self,
        rtp_timestamp: u32,
        payload: &[u8],
    ) -> Result<Option<DtmfEvent>, DtmfError> {
        let event = TelephoneEvent::parse(payload)?;

        let is_new = !matches!(self.current, Some((timestamp, _)) if timestamp == rtp_timestamp);
        if is_new {
            self.current = Some((rtp_timestamp, false));
        }

        if event.end {
            if let Some((timestamp, emitted)) = self.current {
                if timestamp == rtp_timestamp && !emitted {
                    self.current = Some((timestamp, true));
                    if let Some(digit) = event.digit() {
                        return Ok(Some(DtmfEvent {
                            digit,
                            event_code: event.event,
                            duration: event.duration,
                            volume: event.volume,
                        }));
                    }
                }
            }
        }
        Ok(None)
    }
}

/// Default telephone-event volume in -dBm0 (RFC 4733 §2.3.4 recommends ≤ 0; -10 dBm0 is a common
/// playout level for generated digits).
pub const DEFAULT_DTMF_VOLUME_DBM0: u8 = 10;

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a telephone-event payload.
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
                .unwrap(),
            None
        );
        assert_eq!(
            detector
                .on_packet(1000, &payload(7, false, 8, 320))
                .unwrap(),
            None
        );
        let emitted = detector.on_packet(1000, &payload(7, true, 8, 480)).unwrap();
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
        detector
            .on_packet(2000, &payload(3, false, 8, 160))
            .unwrap();
        assert!(detector
            .on_packet(2000, &payload(3, true, 8, 320))
            .unwrap()
            .is_some());
        // RFC 4733 sends the End packet up to three times; only the first emits.
        assert_eq!(
            detector.on_packet(2000, &payload(3, true, 8, 320)).unwrap(),
            None
        );
        assert_eq!(
            detector.on_packet(2000, &payload(3, true, 8, 320)).unwrap(),
            None
        );
    }

    #[test]
    fn distinguishes_consecutive_presses_by_timestamp() {
        let mut detector = DtmfDetector::new();
        // Press '1' at ts 100.
        assert!(detector
            .on_packet(100, &payload(1, true, 8, 160))
            .unwrap()
            .is_some());
        // Press '2' at a new timestamp.
        let second = detector.on_packet(260, &payload(2, true, 8, 160)).unwrap();
        assert_eq!(second.map(|event| event.digit), Some('2'));
    }

    #[test]
    fn rejects_short_payload() {
        assert_eq!(TelephoneEvent::parse(&[0u8; 3]), Err(DtmfError::TooShort));
        let mut detector = DtmfDetector::new();
        assert_eq!(detector.on_packet(0, &[0u8; 2]), Err(DtmfError::TooShort));
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
            if let Some(event) = detector
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
}
