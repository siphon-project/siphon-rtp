//! Per-source receiver-side reception statistics (RFC 3550 §6.4.1 / Appendix A) — the SSRC latch,
//! extended-sequence + received count, interarrival-jitter recurrence, per-interval / cumulative
//! packet loss, and round-trip time derived from an inbound reception report.
//!
//! This is the estimator behind a leg's call-quality report. It is intentionally **decoupled from
//! any jitter buffer**: loss is computed the canonical RFC 3550 way — `lost = expected − received`
//! over the sequence space — so it works for a packet-driven transcode/relay direction that has no
//! playout buffer, as well as for a buffered [`crate::leg::MediaLeg`] (which embeds one of these for
//! its jitter/seq/RTT tracking and overlays its own buffer-derived loss).
//!
//! Pure integer / `f64` arithmetic, zero allocation on the per-packet path, deterministic — every
//! clock reading (`observe_arrival`, `record_sent_report`, `record_reception_report`) is a
//! caller-supplied logical microsecond value, never `Instant::now()`, so tests stay reproducible.

use crate::rtcp::ReportBlock;

/// Entries kept in the per-source sent-Sender-Report ring. A reception report echoes the LSR of the
/// *last* SR its sender received, so only recent history is ever looked up (RFC 3550 §6.4.1).
const SENT_REPORT_TABLE_LEN: usize = 8;

/// Receiver-side reception statistics for one inbound RTP source (RFC 3550 §6.4.1).
#[derive(Debug, Clone)]
pub struct IngressStats {
    /// Ingress RTP clock rate (Hz) — the unit inbound RTP timestamps (and the interarrival jitter)
    /// advance in (RFC 3550 §6.4.1). Fixed for the source's codec.
    clock_rate_hz: u32,
    /// SSRC of the inbound stream (first packet seen), the source the reception report describes.
    ssrc: Option<u32>,
    /// Highest inbound RTP sequence seen + the wrap count, for the extended-highest-seq field
    /// (RFC 3550 Appendix A.1).
    max_sequence: u16,
    cycles: u16,
    /// First inbound sequence number seen, the base for `expected = highest − base + 1`
    /// (RFC 3550 Appendix A.3); `None` before the first packet.
    base_sequence: Option<u16>,
    /// Count of packets actually received (RFC 3550 Appendix A.3 `received`), including duplicates —
    /// the counterpart to `expected` for the canonical `lost = expected − received`.
    received: u64,
    /// RTP timestamp of the most recent inbound packet, captured so [`Self::observe_arrival`] can form
    /// the transit time without re-parsing the header.
    last_rtp_timestamp: u32,
    /// Previous packet's transit (arrival − RTP timestamp, in RTP-clock units); `None` until the
    /// second packet — the running input to the interarrival-jitter recurrence (RFC 3550 §A.8).
    last_transit: Option<i32>,
    /// Smoothed interarrival jitter, in RTP-clock units (RFC 3550 §6.4.1 / §A.8: the
    /// `J += (|D| − J)/16` recurrence in floating point, reported truncated to a `u32`).
    jitter: f64,
    /// Cumulative `expected` at the previous [`Self::fraction_lost_since_last_report`] call, so the
    /// fraction describes just the interval since (RFC 3550 §6.4.1 / Appendix A.3). `0` before the
    /// first report.
    fraction_lost_expected_prior: u32,
    /// Cumulative `received` at the previous report (the counterpart snapshot). `0` before the first.
    fraction_lost_received_prior: u64,
    /// Fixed-size ring of the Sender Reports the owning leg has **sent**: each entry maps a report's
    /// NTP middle-32 (the value a peer echoes back as LSR) to the logical send time (µs). Bounded —
    /// the oldest entry is overwritten — so it never grows; lookups are O(len) (RFC 3550 §6.4.1 RTT).
    sent_reports: [Option<(u32, u64)>; SENT_REPORT_TABLE_LEN],
    /// Next write slot in `sent_reports` (ring cursor).
    sent_reports_next: usize,
    /// The most recent round-trip time measured from an inbound reception report (µs), or `None`
    /// until one is derived (RFC 3550 §6.4.1).
    last_rtt_micros: Option<u64>,
}

impl IngressStats {
    /// A fresh estimator for a source whose RTP clock runs at `clock_rate_hz` (the ingress codec's
    /// RTP clock rate, e.g. 8000 for G.711, 16000 for AMR-WB).
    #[must_use]
    pub fn new(clock_rate_hz: u32) -> Self {
        Self {
            clock_rate_hz,
            ssrc: None,
            max_sequence: 0,
            cycles: 0,
            base_sequence: None,
            received: 0,
            last_rtp_timestamp: 0,
            last_transit: None,
            jitter: 0.0,
            fraction_lost_expected_prior: 0,
            fraction_lost_received_prior: 0,
            sent_reports: [None; SENT_REPORT_TABLE_LEN],
            sent_reports_next: 0,
            last_rtt_micros: None,
        }
    }

    /// Fold one accepted inbound RTP packet into the statistics: latch the SSRC + base sequence on the
    /// first packet, advance the extended highest sequence (RFC 3550 Appendix A.1), count it toward
    /// `received`, and remember its RTP timestamp for the next [`Self::observe_arrival`]. O(1), no
    /// allocation. Call once per accepted ingress packet (audio *and* RFC 4733 telephone-events, which
    /// share the audio SSRC + sequence space).
    pub fn on_rtp(&mut self, ssrc: u32, sequence: u16, rtp_timestamp: u32) {
        self.last_rtp_timestamp = rtp_timestamp;
        if self.ssrc.is_none() {
            self.ssrc = Some(ssrc);
            self.max_sequence = sequence;
            self.base_sequence = Some(sequence);
        } else if sequence.wrapping_sub(self.max_sequence) < 0x8000 {
            // `sequence` is ahead of the current max (RFC 1982 serial order); bump the wrap count when
            // it rolled over.
            if sequence < self.max_sequence {
                self.cycles = self.cycles.wrapping_add(1);
            }
            self.max_sequence = sequence;
        }
        self.received = self.received.wrapping_add(1);
    }

    /// Fold one inbound packet's arrival into the interarrival-jitter estimate (RFC 3550 §6.4.1 /
    /// §A.8). Call once per accepted ingress packet, right after [`Self::on_rtp`] (which records the
    /// packet's RTP timestamp). `arrival_micros` is the receive-time clock reading the datapath
    /// stamped on the datagram — *not* an actor-ingest time, so it reflects network timing.
    pub fn observe_arrival(&mut self, arrival_micros: u64) {
        // Arrival sampled at the RTP clock rate as a wrapping u32 (§A.8 `arrival`). The u128
        // intermediate keeps the rate multiply from overflowing on long-running streams.
        let arrival_rtp =
            ((u128::from(arrival_micros) * u128::from(self.clock_rate_hz)) / 1_000_000) as u32;
        let transit = arrival_rtp.wrapping_sub(self.last_rtp_timestamp) as i32;
        if let Some(previous) = self.last_transit {
            let delta = (i64::from(transit) - i64::from(previous)).unsigned_abs() as f64;
            self.jitter += (delta - self.jitter) / 16.0;
        }
        self.last_transit = Some(transit);
    }

    /// SSRC of this source's inbound stream (RFC 3550 §5.1), or `None` before the first packet.
    #[must_use]
    pub fn ssrc(&self) -> Option<u32> {
        self.ssrc
    }

    /// Extended highest inbound sequence received: `cycles << 16 | highest_seq` (RFC 3550 Appendix
    /// A.1) — the reception report's "extended highest sequence number" field.
    #[must_use]
    pub fn extended_highest_sequence(&self) -> u32 {
        (u32::from(self.cycles) << 16) | u32::from(self.max_sequence)
    }

    /// Packets expected on the source so far: `highest − base + 1` (RFC 3550 Appendix A.3), or `0`
    /// before the first packet.
    #[must_use]
    pub fn expected(&self) -> u32 {
        match self.base_sequence {
            Some(base) => self
                .extended_highest_sequence()
                .wrapping_sub(u32::from(base))
                .wrapping_add(1),
            None => 0,
        }
    }

    /// Packets actually received on the source so far (RFC 3550 Appendix A.3 `received`).
    #[must_use]
    pub fn received(&self) -> u64 {
        self.received
    }

    /// Cumulative packets lost: `expected − received`, clamped at `0` (RFC 3550 Appendix A.3 — a
    /// negative count, when duplicates outrun loss, is reported as no loss).
    #[must_use]
    pub fn cumulative_lost(&self) -> u32 {
        u64::from(self.expected()).saturating_sub(self.received) as u32
    }

    /// Residual inbound packet loss as a percentage — cumulative lost over packets expected so far
    /// (RFC 3550 Appendix A.3), the loss input to the G.107 MOS estimate. `0` before any packet, and
    /// clamped to `0..=100`.
    #[must_use]
    pub fn loss_percent(&self) -> f64 {
        let expected = self.expected();
        if expected == 0 {
            return 0.0;
        }
        (f64::from(self.cumulative_lost()) / f64::from(expected) * 100.0).clamp(0.0, 100.0)
    }

    /// The fraction of packets lost **since the previous call** as the RTCP reception report's 8-bit
    /// fixed-point field (RFC 3550 §6.4.1 / Appendix A.3): `(lost_interval << 8) / expected_interval`,
    /// saturating at 255. Snapshots the cumulative `(expected, received)` on every call, so successive
    /// reports each describe their own interval — the value resets per interval, it is **not**
    /// cumulative. Returns `0` before the first inbound packet, or for an interval that expected no
    /// packets / saw no net loss. Deterministic: it reads only sequence / receive counters, never a
    /// clock.
    #[must_use]
    pub fn fraction_lost_since_last_report(&mut self) -> u8 {
        if self.base_sequence.is_none() {
            return 0;
        }
        let expected = self.expected();
        let received = self.received;
        let expected_interval = expected.wrapping_sub(self.fraction_lost_expected_prior);
        let received_interval = received.wrapping_sub(self.fraction_lost_received_prior);
        self.fraction_lost_expected_prior = expected;
        self.fraction_lost_received_prior = received;
        // RFC 3550 A.3: no packets expected this interval ⇒ fraction 0. `received` never exceeds
        // `expected` within an interval except through duplicates, which we treat as no loss.
        if expected_interval == 0 || received_interval >= u64::from(expected_interval) {
            return 0;
        }
        let lost_interval = u64::from(expected_interval) - received_interval;
        ((lost_interval << 8) / u64::from(expected_interval)).min(255) as u8
    }

    /// The current interarrival-jitter estimate in RTP-clock units (RFC 3550 §6.4.1), truncated to
    /// the `u32` a reception report carries.
    #[must_use]
    pub fn jitter_rtp_units(&self) -> u32 {
        self.jitter as u32
    }

    /// The interarrival-jitter estimate in **milliseconds** — the form the G.107 MOS estimator folds
    /// into one-way delay. Converts the RTP-clock-unit jitter by the ingress codec's clock rate;
    /// derived from the same truncated value the reception report carries, so ms and RR agree.
    #[must_use]
    pub fn jitter_ms(&self) -> f64 {
        if self.clock_rate_hz == 0 {
            return 0.0;
        }
        f64::from(self.jitter_rtp_units()) * 1000.0 / f64::from(self.clock_rate_hz)
    }

    /// Record a Sender Report the owning leg has **sent**: map its NTP timestamp's middle 32 bits (the
    /// value a peer echoes back as LSR, RFC 3550 §6.4.1) to `send_micros`, the logical send time, in a
    /// fixed-size ring (oldest entry overwritten). A later inbound reception report looks this send
    /// time up by its LSR to derive round-trip time. `send_micros` is a logical-clock reading (never
    /// `Instant::now()`), so the RTT it feeds stays deterministic in tests.
    pub fn record_sent_report(&mut self, ntp_timestamp: u64, send_micros: u64) {
        let ntp_middle = ((ntp_timestamp >> 16) & 0xFFFF_FFFF) as u32;
        self.sent_reports[self.sent_reports_next] = Some((ntp_middle, send_micros));
        self.sent_reports_next = (self.sent_reports_next + 1) % SENT_REPORT_TABLE_LEN;
    }

    /// Consume an inbound reception report block that reports on the owning leg's egress stream
    /// (`egress_ssrc`) and derive the round-trip time (RFC 3550 §6.4.1): `rtt = arrival − DLSR − LSR`,
    /// where LSR selects the Sender Report we sent (via [`Self::record_sent_report`]) and DLSR is the
    /// peer's processing delay. Returns the RTT in microseconds (also stored for [`Self::rtt_ms`]), or
    /// `None` when the block reports a different SSRC, carries no LSR, references an SR we do not
    /// recognise, or the arithmetic underflows (a stale / clock-skewed report). `arrival_micros` is a
    /// logical-clock reading, so the RTT is deterministic.
    pub fn record_reception_report(
        &mut self,
        egress_ssrc: u32,
        block: &ReportBlock,
        arrival_micros: u64,
    ) -> Option<u64> {
        // The block must report on the stream the leg sends (its SSRC field, RFC 3550 §6.4.1).
        if block.ssrc != egress_ssrc {
            return None;
        }
        let last_sender_report = block.last_sender_report;
        if last_sender_report == 0 {
            return None; // no SR echoed back ⇒ RTT not computable (RFC 3550 §6.4.1)
        }
        let send_micros = self
            .sent_reports
            .iter()
            .flatten()
            .find(|(ntp_middle, _)| *ntp_middle == last_sender_report)
            .map(|(_, send_micros)| *send_micros)?;
        // DLSR is in units of 1/65536 s; convert to microseconds.
        let delay_micros = (u64::from(block.delay_since_last_sr) * 1_000_000) / 65_536;
        let round_trip_micros = arrival_micros
            .checked_sub(delay_micros)?
            .checked_sub(send_micros)?;
        self.last_rtt_micros = Some(round_trip_micros);
        Some(round_trip_micros)
    }

    /// The most recent round-trip time measured from an inbound reception report (µs), or `None` until
    /// one is derived (RFC 3550 §6.4.1).
    #[must_use]
    pub fn rtt_micros(&self) -> Option<u64> {
        self.last_rtt_micros
    }

    /// The most recent measured round-trip time in **milliseconds** — the form the G.107 MOS estimator
    /// halves into one-way mouth-to-ear delay. `None` until an RTT is measured.
    #[must_use]
    pub fn rtt_ms(&self) -> Option<f64> {
        self.last_rtt_micros.map(|micros| micros as f64 / 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latches_ssrc_and_base_on_the_first_packet() {
        let mut stats = IngressStats::new(8000);
        assert_eq!(stats.ssrc(), None);
        stats.on_rtp(0xDEAD_BEEF, 100, 0);
        assert_eq!(stats.ssrc(), Some(0xDEAD_BEEF));
        assert_eq!(stats.extended_highest_sequence(), 100);
        assert_eq!(stats.expected(), 1);
        assert_eq!(stats.received(), 1);
        // The SSRC latch holds — a later packet does not change the reported source.
        stats.on_rtp(0x1111_2222, 101, 160);
        assert_eq!(stats.ssrc(), Some(0xDEAD_BEEF));
    }

    #[test]
    fn counts_expected_and_received_across_a_sequence_gap() {
        let mut stats = IngressStats::new(8000);
        // Seq 0,1,3,4 — packet 2 is lost. expected = 5 (0..=4), received = 4 ⇒ 1 lost.
        for sequence in [0u16, 1, 3, 4] {
            stats.on_rtp(1, sequence, u32::from(sequence) * 160);
        }
        assert_eq!(stats.extended_highest_sequence(), 4);
        assert_eq!(stats.expected(), 5);
        assert_eq!(stats.received(), 4);
        assert_eq!(stats.cumulative_lost(), 1);
        assert!((stats.loss_percent() - 20.0).abs() < 1e-9, "1/5 = 20%");
    }

    #[test]
    fn no_loss_for_an_in_order_stream() {
        let mut stats = IngressStats::new(8000);
        for sequence in 0..10u16 {
            stats.on_rtp(1, sequence, u32::from(sequence) * 160);
        }
        assert_eq!(stats.cumulative_lost(), 0);
        assert_eq!(stats.loss_percent(), 0.0);
    }

    #[test]
    fn tracks_a_sequence_wrap() {
        let mut stats = IngressStats::new(8000);
        stats.on_rtp(1, 0xFFFE, 0);
        stats.on_rtp(1, 0xFFFF, 160);
        stats.on_rtp(1, 0x0000, 320); // wrapped
        stats.on_rtp(1, 0x0001, 480);
        assert_eq!(stats.extended_highest_sequence(), (1 << 16) | 1);
        // base 0xFFFE ⇒ expected = 0x1_0001 − 0xFFFE + 1 = 4, received = 4 ⇒ no loss.
        assert_eq!(stats.expected(), 4);
        assert_eq!(stats.cumulative_lost(), 0);
    }

    #[test]
    fn duplicates_do_not_manufacture_negative_loss() {
        let mut stats = IngressStats::new(8000);
        stats.on_rtp(1, 0, 0);
        stats.on_rtp(1, 0, 0); // duplicate: received 2, expected 1
        assert_eq!(stats.received(), 2);
        assert_eq!(stats.expected(), 1);
        assert_eq!(stats.cumulative_lost(), 0, "clamped, never negative");
        assert_eq!(stats.loss_percent(), 0.0);
    }

    #[test]
    fn interarrival_jitter_rises_with_drifting_arrivals() {
        // RFC 3550 §A.8: equally-spaced RTP timestamps but drifting arrivals build jitter.
        let mut stats = IngressStats::new(8000);
        for (sequence, &arrival) in [0u64, 20_000, 60_000, 80_000].iter().enumerate() {
            stats.on_rtp(1, sequence as u16, sequence as u32 * 160);
            stats.observe_arrival(arrival);
        }
        assert!(stats.jitter_rtp_units() > 0, "drifting arrivals ⇒ jitter");
        assert!(stats.jitter_ms() > 0.0);
    }

    #[test]
    fn perfectly_paced_arrivals_have_zero_jitter() {
        let mut stats = IngressStats::new(8000);
        // Arrival advances exactly one 20 ms frame per packet, matching the RTP timestamp step.
        for sequence in 0..5u64 {
            stats.on_rtp(1, sequence as u16, sequence as u32 * 160);
            stats.observe_arrival(sequence * 20_000);
        }
        assert_eq!(stats.jitter_rtp_units(), 0, "constant transit ⇒ no jitter");
    }

    #[test]
    fn fraction_lost_is_per_interval_not_cumulative() {
        let mut stats = IngressStats::new(8000);
        // Interval 1: seq 0,1,2,3 all present ⇒ fraction 0.
        for sequence in 0..4u16 {
            stats.on_rtp(1, sequence, u32::from(sequence) * 160);
        }
        assert_eq!(stats.fraction_lost_since_last_report(), 0);
        // Interval 2: seq 4,6,7 — one of {4,5,6,7} lost ⇒ expected_interval 4, lost 1 ⇒ 1/4 = 64/256.
        for sequence in [4u16, 6, 7] {
            stats.on_rtp(1, sequence, u32::from(sequence) * 160);
        }
        assert_eq!(stats.fraction_lost_since_last_report(), 64);
        // Interval 3: seq 8,9 clean ⇒ back to 0 (not cumulative).
        for sequence in [8u16, 9] {
            stats.on_rtp(1, sequence, u32::from(sequence) * 160);
        }
        assert_eq!(stats.fraction_lost_since_last_report(), 0);
    }

    #[test]
    fn round_trip_time_from_a_reception_report() {
        // RFC 3550 §6.4.1: the leg sends an SR at t=100 ms recording NTP middle-32; the peer replies
        // (arriving at t=1.0 s) with a reception block echoing that LSR and DLSR=0.5 s.
        let mut stats = IngressStats::new(8000);
        let egress_ssrc = 0xC000_0000;
        let engine_ntp = 0x0000_1234_5678_0000u64;
        stats.record_sent_report(engine_ntp, 100_000);
        let block = ReportBlock {
            ssrc: egress_ssrc,
            fraction_lost: 0,
            cumulative_lost: 0,
            highest_sequence: 0,
            jitter: 0,
            last_sender_report: 0x1234_5678,
            delay_since_last_sr: 32_768, // 0.5 s in 1/65536 s units
        };
        let rtt = stats
            .record_reception_report(egress_ssrc, &block, 1_000_000)
            .expect("rtt derived");
        // rtt = 1_000_000 − 500_000 − 100_000 = 400 ms.
        assert_eq!(rtt, 400_000);
        assert_eq!(stats.rtt_micros(), Some(400_000));
        assert!((stats.rtt_ms().expect("ms") - 400.0).abs() < 1e-9);
    }

    #[test]
    fn reception_report_for_a_foreign_ssrc_is_ignored() {
        let mut stats = IngressStats::new(8000);
        stats.record_sent_report(0x0000_1234_5678_0000, 100_000);
        let block = ReportBlock {
            ssrc: 0x9999_9999, // not our egress SSRC
            fraction_lost: 0,
            cumulative_lost: 0,
            highest_sequence: 0,
            jitter: 0,
            last_sender_report: 0x1234_5678,
            delay_since_last_sr: 0,
        };
        assert_eq!(
            stats.record_reception_report(0xC000_0000, &block, 1_000_000),
            None
        );
        assert_eq!(stats.rtt_micros(), None);
    }

    #[test]
    fn reception_report_without_a_matching_sent_sr_yields_no_rtt() {
        let mut stats = IngressStats::new(8000);
        let block = ReportBlock {
            ssrc: 0xC000_0000,
            fraction_lost: 0,
            cumulative_lost: 0,
            highest_sequence: 0,
            jitter: 0,
            last_sender_report: 0xDEAD_BEEF, // never recorded
            delay_since_last_sr: 0,
        };
        assert_eq!(
            stats.record_reception_report(0xC000_0000, &block, 1_000_000),
            None
        );
    }
}
