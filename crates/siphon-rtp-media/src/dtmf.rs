//! DTMF telephone-event detection (RFC 4733).
//!
//! A named telephone-event RTP stream carries one event across several redundant packets that
//! share the start RTP timestamp; the last packets set the End bit. [`DtmfDetector`] collapses
//! that into **one logical event per key press**, emitted when the End bit is seen (and de-duped
//! across the redundant End packets). The in-band Goertzel fallback (for streams that do not
//! signal events out-of-band) is a separate, later detector.

/// Errors from telephone-event parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DtmfError {
    /// The payload was shorter than the 4-byte telephone-event format.
    #[error("telephone-event payload too short")]
    TooShort,
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
        Some(match self.event {
            0..=9 => (b'0' + self.event) as char,
            10 => '*',
            11 => '#',
            12..=15 => (b'A' + (self.event - 12)) as char,
            _ => return None,
        })
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
    pub fn on_packet(&mut self, rtp_timestamp: u32, payload: &[u8]) -> Result<Option<DtmfEvent>, DtmfError> {
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
            (0u8, '0'), (9, '9'), (10, '*'), (11, '#'), (12, 'A'), (13, 'B'), (14, 'C'), (15, 'D'),
        ];
        for (code, digit) in cases {
            assert_eq!(TelephoneEvent::parse(&payload(code, false, 0, 0)).unwrap().digit(), Some(digit));
        }
        // A tone (event >= 16) is not a DTMF digit.
        assert_eq!(TelephoneEvent::parse(&payload(16, false, 0, 0)).unwrap().digit(), None);
    }

    #[test]
    fn emits_once_per_press_on_end_bit() {
        let mut detector = DtmfDetector::new();
        // Three packets of one event at timestamp 1000; only the last sets End.
        assert_eq!(detector.on_packet(1000, &payload(7, false, 8, 160)).unwrap(), None);
        assert_eq!(detector.on_packet(1000, &payload(7, false, 8, 320)).unwrap(), None);
        let emitted = detector.on_packet(1000, &payload(7, true, 8, 480)).unwrap();
        assert_eq!(
            emitted,
            Some(DtmfEvent { digit: '7', event_code: 7, duration: 480, volume: 8 })
        );
    }

    #[test]
    fn dedupes_redundant_end_packets() {
        let mut detector = DtmfDetector::new();
        detector.on_packet(2000, &payload(3, false, 8, 160)).unwrap();
        assert!(detector.on_packet(2000, &payload(3, true, 8, 320)).unwrap().is_some());
        // RFC 4733 sends the End packet up to three times; only the first emits.
        assert_eq!(detector.on_packet(2000, &payload(3, true, 8, 320)).unwrap(), None);
        assert_eq!(detector.on_packet(2000, &payload(3, true, 8, 320)).unwrap(), None);
    }

    #[test]
    fn distinguishes_consecutive_presses_by_timestamp() {
        let mut detector = DtmfDetector::new();
        // Press '1' at ts 100.
        assert!(detector.on_packet(100, &payload(1, true, 8, 160)).unwrap().is_some());
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
}
