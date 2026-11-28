//! Stable machine-readable and human-readable run summaries.
use super::media::{MediaResult, StreamTotals};
use crate::stats::LatencyHistogram;
use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Debug, Default, serde::Serialize)]
pub struct Percentiles {
    pub p50_microseconds: Option<u64>,
    pub p99_microseconds: Option<u64>,
    pub max_microseconds: u64,
}
impl From<&LatencyHistogram> for Percentiles {
    fn from(histogram: &LatencyHistogram) -> Self {
        Self {
            p50_microseconds: histogram.percentile(50.0),
            p99_microseconds: histogram.percentile(99.0),
            max_microseconds: histogram.maximum_microseconds(),
        }
    }
}
#[derive(Debug, Default, serde::Serialize)]
pub struct MediaSummary {
    pub sent: u64,
    pub received: u64,
    pub lost: u64,
    pub loss_percent: Option<f64>,
    pub reordered: u64,
    pub foreign: u64,
    pub skipped_at_send: u64,
    pub media_send_errors: u64,
    pub media_receive_errors: u64,
    pub latency: Percentiles,
    pub jitter: Percentiles,
}
#[derive(Debug, Default, serde::Serialize)]
pub struct Summary {
    pub attempted: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub failed_by_reason: BTreeMap<String, u64>,
    pub uas_failures: u64,
    pub uas_failed_by_reason: BTreeMap<String, u64>,
    pub sip_messages_dropped: BTreeMap<String, u64>,
    pub sip_send_errors: BTreeMap<String, u64>,
    pub sip_retransmissions_sent: u64,
    pub sip_retransmissions_received: u64,
    pub setup: Percentiles,
    pub bye: Percentiles,
    pub peak_concurrent_calls: usize,
    pub media: MediaSummary,
    pub streams: BTreeMap<u32, StreamTotals>,
    pub generator_cpu_cores: f64,
    pub elapsed_seconds: f64,
    pub active_calls: usize,
    pub pending_transactions: usize,
    pub active_streams: usize,
}
impl Summary {
    pub fn set_media(&mut self, result: MediaResult) {
        // Sum per-stream deficits: excess arrivals on one stream must never mask loss on another.
        let lost: u64 = result
            .streams
            .values()
            .map(|stream| stream.sent.saturating_sub(stream.received))
            .sum();
        self.media = MediaSummary {
            sent: result.delivery.sent,
            received: result.delivery.received,
            lost,
            loss_percent: (result.delivery.sent > 0)
                .then(|| lost as f64 * 100.0 / result.delivery.sent as f64),
            reordered: result.delivery.out_of_order,
            foreign: result.delivery.foreign,
            skipped_at_send: result.skipped,
            media_send_errors: result.media_send_errors,
            media_receive_errors: result.media_receive_errors,
            latency: Percentiles::from(&result.latency),
            jitter: Percentiles::from(&result.jitter),
        };
        self.streams = result.streams;
        self.active_streams = result.active_streams;
    }
    pub fn to_text(&self) -> String {
        let number =
            |value: Option<u64>| value.map_or_else(|| "n/a".into(), |value| value.to_string());
        let mut output = String::new();
        let _ = writeln!(
            output,
            "calls attempted/succeeded/failed  {} / {} / {}",
            self.attempted, self.succeeded, self.failed
        );
        let _ = writeln!(
            output,
            "failures by reason                {:?}",
            self.failed_by_reason
        );
        let _ = writeln!(
            output,
            "UAS failures                      {} ({:?})",
            self.uas_failures, self.uas_failed_by_reason
        );
        let _ = writeln!(
            output,
            "SIP retransmissions sent/received {} / {}",
            self.sip_retransmissions_sent, self.sip_retransmissions_received
        );
        let _ = writeln!(
            output,
            "SIP messages dropped by reason    {:?}",
            self.sip_messages_dropped
        );
        let _ = writeln!(
            output,
            "SIP send errors by reason         {:?}",
            self.sip_send_errors
        );
        let _ = writeln!(
            output,
            "setup p50/p99/max (us)            {} / {} / {}",
            number(self.setup.p50_microseconds),
            number(self.setup.p99_microseconds),
            self.setup.max_microseconds
        );
        let _ = writeln!(
            output,
            "BYE p50/p99/max (us)              {} / {} / {}",
            number(self.bye.p50_microseconds),
            number(self.bye.p99_microseconds),
            self.bye.max_microseconds
        );
        let _ = writeln!(
            output,
            "peak concurrent calls            {}",
            self.peak_concurrent_calls
        );
        let _ = writeln!(
            output,
            "media sent/received/lost          {} / {} / {} ({:.3}%)",
            self.media.sent,
            self.media.received,
            self.media.lost,
            self.media.loss_percent.unwrap_or(0.0)
        );
        let _ = writeln!(
            output,
            "reordered/foreign/skipped         {} / {} / {}",
            self.media.reordered, self.media.foreign, self.media.skipped_at_send
        );
        let _ = writeln!(
            output,
            "media send/receive errors         {} / {}",
            self.media.media_send_errors, self.media.media_receive_errors
        );
        let _ = writeln!(
            output,
            "latency p50/p99/max (us)           {} / {} / {}",
            number(self.media.latency.p50_microseconds),
            number(self.media.latency.p99_microseconds),
            self.media.latency.max_microseconds
        );
        let _ = writeln!(
            output,
            "jitter p50/p99 (us)               {} / {}",
            number(self.media.jitter.p50_microseconds),
            number(self.media.jitter.p99_microseconds)
        );
        let _ = writeln!(
            output,
            "generator CPU (cores)             {:.3}",
            self.generator_cpu_cores
        );
        let _ = writeln!(
            output,
            "active calls/transactions/streams {} / {} / {}",
            self.active_calls, self.pending_transactions, self.active_streams
        );
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn error_counters_are_preserved_in_text_and_json() {
        let mut summary = Summary::default();
        summary
            .sip_messages_dropped
            .insert("missing branch".into(), 2);
        summary.sip_send_errors.insert("ENOBUFS".into(), 3);
        summary.set_media(MediaResult {
            media_send_errors: 4,
            media_receive_errors: 5,
            ..MediaResult::default()
        });
        let text = summary.to_text();
        assert!(text.contains("missing branch"));
        assert!(text.contains("ENOBUFS"));
        assert!(text.contains("media send/receive errors         4 / 5"));
        let json = serde_json::to_value(summary).unwrap();
        assert_eq!(json["sip_messages_dropped"]["missing branch"], 2);
        assert_eq!(json["sip_send_errors"]["ENOBUFS"], 3);
        assert_eq!(json["media"]["media_send_errors"], 4);
        assert_eq!(json["media"]["media_receive_errors"], 5);
    }
    #[test]
    fn excess_arrivals_cannot_hide_another_streams_loss() {
        let mut result = MediaResult::default();
        result.delivery.sent = 20;
        result.delivery.received = 20;
        result.streams.insert(
            1,
            StreamTotals {
                sent: 10,
                received: 5,
            },
        );
        result.streams.insert(
            2,
            StreamTotals {
                sent: 10,
                received: 15,
            },
        );
        let mut summary = Summary::default();
        summary.set_media(result);
        assert_eq!(summary.media.lost, 5);
        assert_eq!(summary.media.loss_percent, Some(25.0));
    }
    #[test]
    fn histogram_summary_preserves_max_and_percentiles() {
        let mut histogram = LatencyHistogram::new();
        histogram.record(15);
        histogram.record(100);
        let summary = Percentiles::from(&histogram);
        assert_eq!(summary.p50_microseconds, Some(20));
        assert_eq!(summary.p99_microseconds, Some(110));
        assert_eq!(summary.max_microseconds, 100);
    }
    #[test]
    fn report_text_and_json_include_loss_and_leaks() {
        let summary = Summary::default();
        assert!(summary
            .to_text()
            .contains("calls attempted/succeeded/failed"));
        let json = serde_json::to_value(summary).unwrap();
        assert_eq!(json["active_streams"], 0);
        assert_eq!(json["media"]["lost"], 0);
    }
}
