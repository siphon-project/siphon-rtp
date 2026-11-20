//! The ingress media clock a transcode's egress clock keeps time with, so discontinuous
//! transmission and loss on the ingress side keep their length on the egress timeline.

/// `ticks` of one RTP clock (`from_hz`) in another (`to_hz`), rounded down; 0 for a clock of 0.
pub(super) fn rescale_ticks(ticks: u32, from_hz: u32, to_hz: u32) -> u32 {
    if from_hz == 0 {
        return 0;
    }
    ((u64::from(ticks) * u64::from(to_hz)) / u64::from(from_hz)) as u32
}

/// The longest stretch of the ingress media clock with no packet that is still taken for silence
/// the sender did not send (discontinuous transmission, RFC 4867 §4.3.2) or loss. Anything longer
/// is a clock reset, not audio, and is not carried into the egress clock.
const MAX_CARRIED_GAP_SECONDS: u32 = 10;

/// Where the ingress media clock is, so the egress clock of a transcode keeps time with it.
///
/// The transcode emits a packet per ingress packet and stamps each one frame after the last. A
/// sender in discontinuous transmission (an AMR phone between talkspurts: a SID frame every 160 ms,
/// RFC 4867 §4.3.2) or a lossy network leaves stretches of its clock with no packet, and stamped
/// back to back those stretches vanish from the egress timeline: the receiver gets a stream its
/// timestamps call continuous at a fraction of the packet rate, and its jitter buffer runs dry over
/// and over. The stretch is measured here and the egress clock moved on by it.
#[derive(Debug, Clone, Copy)]
pub(super) struct IngressClock {
    /// The ingress codec's sample rate, which a decoded frame's sample count is in.
    sample_rate_hz: u32,
    /// The ingress RTP clock (RFC 3551 §4.5.2: not always the sample rate).
    rtp_clock_hz: u32,
    /// The egress RTP clock the gap is spent on.
    egress_rtp_clock_hz: u32,
    /// The SSRC of the stream last decoded and the timestamp its next packet is due at.
    next: Option<(u32, u32)>,
}

impl IngressClock {
    pub(super) fn new(sample_rate_hz: u32, rtp_clock_hz: u32, egress_rtp_clock_hz: u32) -> Self {
        Self {
            sample_rate_hz,
            rtp_clock_hz,
            egress_rtp_clock_hz,
            next: None,
        }
    }

    /// A decoded ingress packet of `samples` (per channel, at the ingress sample rate): the egress
    /// RTP ticks of media clock that passed before it with no packet, 0 when it came on time. A new
    /// SSRC, a timestamp behind the one due, or a jump past [`MAX_CARRIED_GAP_SECONDS`] carries
    /// nothing.
    pub(super) fn advance(&mut self, ssrc: u32, timestamp: u32, samples: usize) -> u32 {
        let duration = rescale_ticks(
            u32::try_from(samples).unwrap_or(u32::MAX),
            self.sample_rate_hz,
            self.rtp_clock_hz,
        );
        let gap = match self.next {
            Some((stream, due)) if stream == ssrc => {
                let ahead = timestamp.wrapping_sub(due);
                // Ahead by less than half the clock's range: the packet is later than due (RFC 3550
                // §5.1 modular arithmetic), else it is behind it, reordered or a reset.
                if ahead < (1 << 31)
                    && ahead <= self.rtp_clock_hz.saturating_mul(MAX_CARRIED_GAP_SECONDS)
                {
                    rescale_ticks(ahead, self.rtp_clock_hz, self.egress_rtp_clock_hz)
                } else {
                    0
                }
            }
            _ => 0,
        };
        self.next = Some((ssrc, timestamp.wrapping_add(duration)));
        gap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSRC: u32 = 0x1234_5678;

    /// G.711: 8 kHz audio on an 8 kHz RTP clock, 160 samples per 20 ms frame.
    fn g711() -> IngressClock {
        IngressClock::new(8_000, 8_000, 8_000)
    }

    #[test]
    fn a_packet_on_time_carries_no_gap() {
        let mut clock = g711();
        assert_eq!(clock.advance(SSRC, 160, 160), 0);
        assert_eq!(clock.advance(SSRC, 320, 160), 0);
    }

    #[test]
    fn a_stretch_without_packets_is_carried_in_egress_ticks() {
        let mut clock = g711();
        clock.advance(SSRC, 320, 160);
        // Due at 480, arrived at 1600: 1120 ticks the sender did not fill.
        assert_eq!(clock.advance(SSRC, 1600, 160), 1120);
    }

    #[test]
    fn the_gap_is_converted_into_the_egress_clock() {
        // 8 kHz ingress into a 16 kHz egress clock: the gap doubles.
        let mut clock = IngressClock::new(8_000, 8_000, 16_000);
        clock.advance(SSRC, 0, 160);
        assert_eq!(clock.advance(SSRC, 480, 160), 640);
    }

    #[test]
    fn a_new_ssrc_a_late_timestamp_or_a_reset_carries_nothing() {
        let mut clock = g711();
        clock.advance(SSRC, 1_000, 160);
        assert_eq!(clock.advance(SSRC + 1, 50_000, 160), 0, "new SSRC");
        assert_eq!(
            clock.advance(SSRC + 1, 40_000, 160),
            0,
            "behind the one due"
        );
        let past_limit = 50_160 + 8_000 * MAX_CARRIED_GAP_SECONDS + 1;
        assert_eq!(clock.advance(SSRC + 1, past_limit, 160), 0, "clock reset");
    }

    #[test]
    fn the_due_timestamp_wraps_with_the_rtp_clock() {
        let mut clock = g711();
        clock.advance(SSRC, u32::MAX - 79, 160);
        // Due at 80 after the wrap; arriving at 240 leaves 160 unfilled (RFC 3550 §5.1).
        assert_eq!(clock.advance(SSRC, 240, 160), 160);
    }

    #[test]
    fn a_zero_clock_rescales_to_zero() {
        assert_eq!(rescale_ticks(160, 0, 8_000), 0);
        assert_eq!(rescale_ticks(160, 8_000, 16_000), 320);
    }
}
