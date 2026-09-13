//! Delivery and latency accounting for a capacity run.
//!
//! Loss is computed as **sent minus received** per stream rather than by walking sequence gaps.
//! Gap-walking has to take a position on reordering and duplication, and a relay under the load
//! that makes it drop packets is also the relay most likely to reorder them — so a gap-based
//! counter is least trustworthy exactly where it matters. The sender knows precisely how many
//! packets it wrote; the difference is the honest figure. Reordering is tracked separately, as its
//! own observation rather than as a correction to loss.

/// Latency histogram resolution. 10 µs is finer than any scheduling effect this measures and keeps
/// the whole histogram inside a few hundred kilobytes.
const BUCKET_MICROSECONDS: u64 = 10;
/// Buckets covering 0..200 ms. Anything beyond is counted in the overflow bucket: at a 20 ms ptime,
/// a packet 200 ms late is not "high latency", it is a call that has already failed.
const BUCKET_COUNT: usize = 20_000;

/// A fixed-resolution latency histogram.
///
/// Fixed buckets rather than retained samples so recording is O(1) with no allocation on the
/// receive path, and so a run of many million packets costs the same memory as a short one.
#[derive(Debug, Clone)]
pub struct LatencyHistogram {
    buckets: Vec<u64>,
    overflow: u64,
    count: u64,
    maximum_microseconds: u64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyHistogram {
    /// An empty histogram.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: vec![0; BUCKET_COUNT],
            overflow: 0,
            count: 0,
            maximum_microseconds: 0,
        }
    }

    /// Record one observation.
    pub fn record(&mut self, microseconds: u64) {
        self.count = self.count.saturating_add(1);
        self.maximum_microseconds = self.maximum_microseconds.max(microseconds);

        let index = (microseconds / BUCKET_MICROSECONDS) as usize;
        match self.buckets.get_mut(index) {
            Some(bucket) => *bucket = bucket.saturating_add(1),
            None => self.overflow = self.overflow.saturating_add(1),
        }
    }

    /// How many observations were recorded.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The largest observation, exactly (not bucketed).
    #[must_use]
    pub fn maximum_microseconds(&self) -> u64 {
        self.maximum_microseconds
    }

    /// The nearest-rank percentile, in microseconds, or `None` if nothing was recorded.
    ///
    /// `percent` is clamped to `0..=100`. The value returned is the **upper edge** of the bucket the
    /// rank falls in, so it never understates latency.
    #[must_use]
    pub fn percentile(&self, percent: f64) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let clamped = percent.clamp(0.0, 100.0);
        // Nearest-rank: the smallest value at or below which at least `percent` of observations lie.
        let rank = ((clamped / 100.0) * self.count as f64).ceil().max(1.0) as u64;

        let mut cumulative = 0u64;
        for (index, bucket) in self.buckets.iter().enumerate() {
            cumulative = cumulative.saturating_add(*bucket);
            if cumulative >= rank {
                return Some((index as u64 + 1) * BUCKET_MICROSECONDS);
            }
        }
        // The rank fell in the overflow bucket; report the true maximum rather than a bucket edge.
        Some(self.maximum_microseconds)
    }

    /// Fold another histogram into this one — used to merge per-worker histograms at the end.
    pub fn merge(&mut self, other: &Self) {
        for (slot, bucket) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            *slot = slot.saturating_add(*bucket);
        }
        self.overflow = self.overflow.saturating_add(other.overflow);
        self.count = self.count.saturating_add(other.count);
        self.maximum_microseconds = self.maximum_microseconds.max(other.maximum_microseconds);
    }
}

/// Delivery counters for a run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Delivery {
    /// Packets the generator wrote to a socket.
    pub sent: u64,
    /// Probe packets that arrived on the far side.
    pub received: u64,
    /// Arrivals whose ordinal was below the highest already seen on that stream.
    pub out_of_order: u64,
    /// Datagrams that arrived but were not recognisable probe packets.
    pub foreign: u64,
}

impl Delivery {
    /// Packets that were sent and never arrived.
    ///
    /// Saturating: a receive that races the final sample can briefly exceed `sent`, and a negative
    /// loss figure is worse than a zero one.
    #[must_use]
    pub fn lost(self) -> u64 {
        self.sent.saturating_sub(self.received)
    }

    /// Loss as a percentage of packets sent, or `None` if nothing was sent.
    #[must_use]
    pub fn loss_percent(self) -> Option<f64> {
        if self.sent == 0 {
            return None;
        }
        Some((self.lost() as f64 / self.sent as f64) * 100.0)
    }

    /// Accumulate another set of counters.
    pub fn merge(&mut self, other: Self) {
        self.sent = self.sent.saturating_add(other.sent);
        self.received = self.received.saturating_add(other.received);
        self.out_of_order = self.out_of_order.saturating_add(other.out_of_order);
        self.foreign = self.foreign.saturating_add(other.foreign);
    }
}

/// Per-stream receive state, tracking the highest ordinal so reordering can be counted.
#[derive(Debug, Clone, Copy, Default)]
pub struct StreamReceiver {
    highest_ordinal: Option<u32>,
}

impl StreamReceiver {
    /// Note an arrival; returns `true` if it arrived out of order.
    pub fn accept(&mut self, ordinal: u32) -> bool {
        match self.highest_ordinal {
            Some(highest) if ordinal < highest => true,
            _ => {
                self.highest_ordinal = Some(ordinal);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_histogram_has_no_percentile() {
        let histogram = LatencyHistogram::new();
        assert_eq!(histogram.percentile(50.0), None);
        assert_eq!(histogram.count(), 0);
        assert_eq!(histogram.maximum_microseconds(), 0);
    }

    #[test]
    fn a_single_observation_is_every_percentile() {
        let mut histogram = LatencyHistogram::new();
        histogram.record(95);
        // 95 µs lands in bucket 9 (90..100), whose upper edge is 100.
        assert_eq!(histogram.percentile(0.0), Some(100));
        assert_eq!(histogram.percentile(50.0), Some(100));
        assert_eq!(histogram.percentile(100.0), Some(100));
        assert_eq!(histogram.maximum_microseconds(), 95);
    }

    #[test]
    fn percentiles_follow_nearest_rank_over_a_known_distribution() {
        let mut histogram = LatencyHistogram::new();
        // 100 observations: 1..=100 tens of microseconds.
        for step in 1..=100u64 {
            histogram.record(step * 10);
        }
        assert_eq!(histogram.count(), 100);
        // Value n*10 lands in bucket n (since n*10/10 == n), upper edge (n+1)*10.
        assert_eq!(histogram.percentile(50.0), Some(510));
        assert_eq!(histogram.percentile(99.0), Some(1000));
        assert_eq!(histogram.percentile(100.0), Some(1010));
        assert_eq!(histogram.maximum_microseconds(), 1000);
    }

    #[test]
    fn never_understates_latency_because_it_reports_the_bucket_upper_edge() {
        let mut histogram = LatencyHistogram::new();
        histogram.record(0);
        // A zero-microsecond observation still reports the 10 µs edge, not 0.
        assert_eq!(histogram.percentile(100.0), Some(10));
    }

    #[test]
    fn an_observation_past_the_histogram_ceiling_reports_the_true_maximum() {
        let mut histogram = LatencyHistogram::new();
        histogram.record(10);
        // 1 second, far beyond the 200 ms ceiling.
        histogram.record(1_000_000);
        assert_eq!(histogram.maximum_microseconds(), 1_000_000);
        // The p100 rank falls in overflow, so the exact maximum is reported rather than a bucket edge.
        assert_eq!(histogram.percentile(100.0), Some(1_000_000));
        // The low observation is still bucketed normally.
        assert_eq!(histogram.percentile(1.0), Some(20));
    }

    #[test]
    fn percentile_arguments_outside_the_range_are_clamped() {
        let mut histogram = LatencyHistogram::new();
        histogram.record(50);
        assert_eq!(histogram.percentile(-10.0), histogram.percentile(0.0));
        assert_eq!(histogram.percentile(140.0), histogram.percentile(100.0));
    }

    #[test]
    fn merging_histograms_sums_counts_and_keeps_the_larger_maximum() {
        let mut left = LatencyHistogram::new();
        left.record(10);
        left.record(20);
        let mut right = LatencyHistogram::new();
        right.record(30);
        right.record(500_000);

        left.merge(&right);
        assert_eq!(left.count(), 4);
        assert_eq!(left.maximum_microseconds(), 500_000);
    }

    #[test]
    fn loss_is_sent_minus_received() {
        let delivery = Delivery {
            sent: 1000,
            received: 990,
            out_of_order: 3,
            foreign: 0,
        };
        assert_eq!(delivery.lost(), 10);
        assert_eq!(delivery.loss_percent(), Some(1.0));
    }

    #[test]
    fn loss_saturates_rather_than_going_negative_when_a_receive_races_the_sample() {
        let delivery = Delivery {
            sent: 10,
            received: 12,
            out_of_order: 0,
            foreign: 0,
        };
        assert_eq!(delivery.lost(), 0);
        assert_eq!(delivery.loss_percent(), Some(0.0));
    }

    #[test]
    fn loss_percent_is_absent_when_nothing_was_sent() {
        assert_eq!(Delivery::default().loss_percent(), None);
    }

    #[test]
    fn merging_delivery_counters_accumulates_every_field() {
        let mut total = Delivery {
            sent: 10,
            received: 9,
            out_of_order: 1,
            foreign: 2,
        };
        total.merge(Delivery {
            sent: 5,
            received: 5,
            out_of_order: 0,
            foreign: 1,
        });
        assert_eq!(total.sent, 15);
        assert_eq!(total.received, 14);
        assert_eq!(total.out_of_order, 1);
        assert_eq!(total.foreign, 3);
    }

    #[test]
    fn a_stream_receiver_counts_only_genuinely_late_arrivals_as_reordered() {
        let mut receiver = StreamReceiver::default();
        assert!(!receiver.accept(0), "first arrival is in order");
        assert!(!receiver.accept(1));
        assert!(!receiver.accept(2));
        assert!(
            receiver.accept(1),
            "ordinal below the highest seen is reordered"
        );
        assert!(!receiver.accept(3), "the stream continues from the highest");
        // A gap is not reordering: 5 skips 4, but arrives in order.
        assert!(!receiver.accept(5));
        assert!(receiver.accept(4), "the late filler is reordered");
    }

    #[test]
    fn a_repeated_ordinal_is_not_counted_as_reordered() {
        // Equal, not less: a duplicate of the highest is not evidence of reordering.
        let mut receiver = StreamReceiver::default();
        assert!(!receiver.accept(7));
        assert!(!receiver.accept(7));
    }
}
