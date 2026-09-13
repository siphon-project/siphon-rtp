//! Turning a run into something a human reads and a script parses.
//!
//! Deliberately opinionated about what leads: the per-packet engine cost and the extrapolated
//! calls-per-core, because those are the figures a sizing table is built from. "500 calls ran with
//! no loss" is a weaker claim than it looks — it says the box was not saturated, not where
//! saturation is.

use std::time::Duration;

use serde::Serialize;

use crate::runner::RunOutcome;

/// A machine-readable summary of one run.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    /// Concurrent relay calls established.
    pub calls: usize,
    /// Length of the measured window, in seconds.
    pub measured_seconds: f64,
    /// Packetisation interval, in milliseconds.
    pub ptime_milliseconds: u64,
    /// Packets the generator offered during the window.
    pub packets_sent: u64,
    /// Packets that arrived on the far side during the window.
    pub packets_relayed: u64,
    /// Packets sent that never arrived.
    pub packets_lost: u64,
    /// Loss as a percentage of packets offered.
    pub loss_percent: Option<f64>,
    /// Arrivals whose ordinal was below the highest already seen on that stream.
    pub out_of_order: u64,
    /// Datagrams that arrived but were not probe packets.
    pub foreign: u64,
    /// Packets per second the engine forwarded.
    pub relayed_packets_per_second: f64,
    /// Engine CPU microseconds per relayed packet — the headline figure.
    pub engine_microseconds_per_relayed_packet: Option<f64>,
    /// Fraction of one core the engine consumed.
    pub engine_cores_used: f64,
    /// Fraction of one core the generator consumed, for methodology transparency.
    pub generator_cores_used: f64,
    /// Engine CPU split into user and system microseconds.
    pub engine_user_microseconds: u64,
    /// System time is the syscall bill; on this workload it should dominate.
    pub engine_system_microseconds: u64,
    /// Share of engine CPU spent in the kernel, as a percentage.
    pub engine_system_percent: Option<f64>,
    /// Median relay latency, microseconds.
    pub latency_p50_microseconds: Option<u64>,
    /// 99th percentile relay latency, microseconds.
    pub latency_p99_microseconds: Option<u64>,
    /// Worst observed relay latency, microseconds.
    pub latency_max_microseconds: u64,
    /// Extrapolated concurrent calls one core sustains at the measured per-packet cost.
    pub calls_per_core: Option<f64>,
    /// Sessions the engine reported live at the close of the window.
    pub engine_sessions: usize,
    /// Descriptors the run needed.
    pub file_descriptors_required: u64,
    /// The process's soft descriptor limit, if readable.
    pub file_descriptor_soft_limit: Option<u64>,
    /// True when too little CPU was consumed for the per-packet figure to be trustworthy.
    ///
    /// `/proc` reports CPU in 10 ms `USER_HZ` ticks *per thread*, so a run that burns only a few
    /// ticks is reporting quantisation noise, not cost. Small runs prove the harness relays
    /// correctly; they cannot price a packet.
    pub cpu_measurement_is_coarse: bool,
}

/// Engine CPU below which the per-packet figure is quantisation noise rather than a measurement.
/// One CPU-second is 100 ticks, comfortably above the per-thread rounding error.
const COARSE_CPU_THRESHOLD_MICROSECONDS: u64 = 1_000_000;

impl Summary {
    /// Derive a summary from a finished run.
    #[must_use]
    pub fn from_outcome(outcome: &RunOutcome, ptime: Duration) -> Self {
        let engine = outcome.engine_cpu;
        let measured_seconds = outcome.measured.as_secs_f64();
        let generator_cores_used = if measured_seconds > 0.0 {
            (outcome.generator_cpu.total_microseconds() as f64 / 1_000_000.0) / measured_seconds
        } else {
            0.0
        };
        let engine_total = engine.total_microseconds();

        Self {
            calls: outcome.calls,
            measured_seconds,
            ptime_milliseconds: ptime.as_millis() as u64,
            packets_sent: outcome.delivery.sent,
            packets_relayed: outcome.delivery.received,
            packets_lost: outcome.delivery.lost(),
            loss_percent: outcome.delivery.loss_percent(),
            out_of_order: outcome.delivery.out_of_order,
            foreign: outcome.delivery.foreign,
            relayed_packets_per_second: outcome.relayed_packets_per_second(),
            engine_microseconds_per_relayed_packet: outcome
                .engine_microseconds_per_relayed_packet(),
            engine_cores_used: outcome.engine_cores_used(),
            generator_cores_used,
            engine_user_microseconds: engine.user_microseconds,
            engine_system_microseconds: engine.system_microseconds,
            engine_system_percent: (engine_total > 0)
                .then(|| (engine.system_microseconds as f64 / engine_total as f64) * 100.0),
            latency_p50_microseconds: outcome.latency.percentile(50.0),
            latency_p99_microseconds: outcome.latency.percentile(99.0),
            latency_max_microseconds: outcome.latency.maximum_microseconds(),
            calls_per_core: outcome.calls_per_core(ptime),
            engine_sessions: outcome.engine_sessions,
            file_descriptors_required: outcome.file_descriptors.required,
            file_descriptor_soft_limit: outcome.file_descriptors.soft_limit,
            cpu_measurement_is_coarse: engine_total < COARSE_CPU_THRESHOLD_MICROSECONDS,
        }
    }

    /// Render the summary as an aligned human-readable block.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let optional = |value: Option<f64>, unit: &str| match value {
            Some(number) => format!("{number:.2} {unit}"),
            None => "n/a".to_string(),
        };
        let optional_integer = |value: Option<u64>, unit: &str| match value {
            Some(number) => format!("{number} {unit}"),
            None => "n/a".to_string(),
        };

        out.push_str(&format!("calls established        {}\n", self.calls));
        out.push_str(&format!(
            "measured window          {:.1} s at {} ms ptime\n",
            self.measured_seconds, self.ptime_milliseconds
        ));
        out.push_str(&format!(
            "packets offered/relayed  {} / {}\n",
            self.packets_sent, self.packets_relayed
        ));
        out.push_str(&format!(
            "loss                     {} ({})\n",
            self.packets_lost,
            optional(self.loss_percent, "%")
        ));
        out.push_str(&format!(
            "out of order / foreign   {} / {}\n",
            self.out_of_order, self.foreign
        ));
        out.push_str(&format!(
            "relayed rate             {:.0} pps\n",
            self.relayed_packets_per_second
        ));
        out.push_str(&format!(
            "latency p50/p99/max      {} / {} / {} us\n",
            optional_integer(self.latency_p50_microseconds, "").trim(),
            optional_integer(self.latency_p99_microseconds, "").trim(),
            self.latency_max_microseconds
        ));
        out.push('\n');
        out.push_str(&format!(
            "ENGINE cost per packet   {}{}\n",
            optional(self.engine_microseconds_per_relayed_packet, "us"),
            if self.cpu_measurement_is_coarse {
                "   <-- NOT TRUSTWORTHY: too little CPU consumed to measure; raise --calls/--duration"
            } else {
                ""
            }
        ));
        out.push_str(&format!(
            "engine cores used        {:.3} (user {} us, system {} us, {} in kernel)\n",
            self.engine_cores_used,
            self.engine_user_microseconds,
            self.engine_system_microseconds,
            optional(self.engine_system_percent, "%")
        ));
        out.push_str(&format!(
            "generator cores used     {:.3} (methodology: not part of the figure above)\n",
            self.generator_cores_used
        ));
        out.push_str(&format!(
            "extrapolated per core    {}\n",
            optional(self.calls_per_core, "concurrent calls (zero headroom)")
        ));
        out.push('\n');
        out.push_str(&format!(
            "engine sessions at close {}\n",
            self.engine_sessions
        ));
        out.push_str(&format!(
            "descriptors needed/limit {} / {}\n",
            self.file_descriptors_required,
            match self.file_descriptor_soft_limit {
                Some(u64::MAX) => "unlimited".to_string(),
                Some(limit) => limit.to_string(),
                None => "unknown".to_string(),
            }
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::CpuTime;
    use crate::runner::FileDescriptorBudget;
    use crate::stats::{Delivery, LatencyHistogram};

    fn outcome() -> RunOutcome {
        let mut latency = LatencyHistogram::new();
        for _ in 0..99 {
            latency.record(120);
        }
        latency.record(9_000);

        RunOutcome {
            calls: 250,
            measured: Duration::from_secs(10),
            delivery: Delivery {
                sent: 250_000,
                received: 249_500,
                out_of_order: 12,
                foreign: 3,
            },
            latency,
            engine_cpu: CpuTime {
                user_microseconds: 400_000,
                system_microseconds: 1_600_000,
            },
            generator_cpu: CpuTime {
                user_microseconds: 500_000,
                system_microseconds: 1_500_000,
            },
            total_cpu: CpuTime {
                user_microseconds: 900_000,
                system_microseconds: 3_100_000,
            },
            engine_sessions: 250,
            file_descriptors: FileDescriptorBudget {
                soft_limit: Some(1024),
                required: 1564,
            },
        }
    }

    #[test]
    fn derives_the_headline_figures_from_an_outcome() {
        let summary = Summary::from_outcome(&outcome(), Duration::from_millis(20));

        assert_eq!(summary.calls, 250);
        assert_eq!(summary.packets_lost, 500);
        // 2_000_000 us of engine CPU over 249_500 relayed packets.
        let per_packet = summary
            .engine_microseconds_per_relayed_packet
            .expect("per packet");
        assert!((per_packet - 8.016).abs() < 0.01, "got {per_packet}");
        // 2 s of engine CPU over a 10 s window.
        assert!((summary.engine_cores_used - 0.2).abs() < 1e-9);
        assert!((summary.generator_cores_used - 0.2).abs() < 1e-9);
        // 1.6 of 2.0 seconds in the kernel.
        let system_percent = summary.engine_system_percent.expect("system percent");
        assert!((system_percent - 80.0).abs() < 1e-9, "got {system_percent}");
    }

    #[test]
    fn reports_latency_percentiles_separating_the_tail_from_the_median() {
        let summary = Summary::from_outcome(&outcome(), Duration::from_millis(20));
        // 99 observations at 120 us, one at 9 ms: the median is the bucket edge above 120.
        assert_eq!(summary.latency_p50_microseconds, Some(130));
        assert_eq!(summary.latency_p99_microseconds, Some(130));
        assert_eq!(summary.latency_max_microseconds, 9_000);
    }

    #[test]
    fn the_text_rendering_names_the_engine_cost_and_flags_the_descriptor_shortfall() {
        let text = Summary::from_outcome(&outcome(), Duration::from_millis(20)).to_text();
        assert!(
            text.contains("ENGINE cost per packet"),
            "leads with the per-packet cost"
        );
        assert!(text.contains("calls established        250"));
        assert!(text.contains("descriptors needed/limit 1564 / 1024"));
        // The generator's share is disclosed rather than hidden.
        assert!(text.contains("generator cores used"));
    }

    #[test]
    fn absent_figures_render_as_not_available_rather_than_nan() {
        let empty = RunOutcome {
            calls: 0,
            measured: Duration::ZERO,
            delivery: Delivery::default(),
            latency: LatencyHistogram::new(),
            engine_cpu: CpuTime::default(),
            generator_cpu: CpuTime::default(),
            total_cpu: CpuTime::default(),
            engine_sessions: 0,
            file_descriptors: FileDescriptorBudget {
                soft_limit: None,
                required: 64,
            },
        };
        let summary = Summary::from_outcome(&empty, Duration::from_millis(20));
        let text = summary.to_text();
        assert!(
            !text.contains("NaN"),
            "no NaN leaks into the report:\n{text}"
        );
        assert!(
            !text.contains("inf"),
            "no infinity leaks into the report:\n{text}"
        );
        assert!(text.contains("n/a"));
        assert!(text.contains("descriptors needed/limit 64 / unknown"));
        assert_eq!(summary.engine_system_percent, None);
    }

    #[test]
    fn a_run_that_burned_real_cpu_is_not_flagged_as_coarse() {
        // 2 CPU-seconds is 200 ticks, well clear of per-thread rounding.
        let summary = Summary::from_outcome(&outcome(), Duration::from_millis(20));
        assert!(!summary.cpu_measurement_is_coarse);
        assert!(!summary.to_text().contains("NOT TRUSTWORTHY"));
    }

    #[test]
    fn a_run_too_small_to_price_a_packet_says_so_next_to_the_figure() {
        // The single-call smoke case: a few ticks of CPU, which is quantisation noise. The figure
        // is still computed, but it must never be quotable without the warning attached.
        let mut tiny = outcome();
        tiny.engine_cpu = CpuTime {
            user_microseconds: 30_000,
            system_microseconds: 0,
        };
        tiny.delivery = Delivery {
            sent: 402,
            received: 402,
            out_of_order: 0,
            foreign: 0,
        };
        let summary = Summary::from_outcome(&tiny, Duration::from_millis(20));
        assert!(summary.cpu_measurement_is_coarse);
        let text = summary.to_text();
        assert!(
            text.contains("NOT TRUSTWORTHY"),
            "the warning must sit on the same line as the figure:\n{text}"
        );
    }

    #[test]
    fn the_coarse_threshold_sits_at_one_cpu_second() {
        let mut exactly_at = outcome();
        exactly_at.engine_cpu = CpuTime {
            user_microseconds: COARSE_CPU_THRESHOLD_MICROSECONDS,
            system_microseconds: 0,
        };
        assert!(
            !Summary::from_outcome(&exactly_at, Duration::from_millis(20))
                .cpu_measurement_is_coarse
        );

        let mut just_under = outcome();
        just_under.engine_cpu = CpuTime {
            user_microseconds: COARSE_CPU_THRESHOLD_MICROSECONDS - 1,
            system_microseconds: 0,
        };
        assert!(
            Summary::from_outcome(&just_under, Duration::from_millis(20)).cpu_measurement_is_coarse
        );
    }

    #[test]
    fn an_unlimited_descriptor_limit_renders_as_a_word_not_a_huge_number() {
        let mut base = outcome();
        base.file_descriptors = FileDescriptorBudget {
            soft_limit: Some(u64::MAX),
            required: 1564,
        };
        let text = Summary::from_outcome(&base, Duration::from_millis(20)).to_text();
        assert!(text.contains("1564 / unlimited"));
    }

    #[test]
    fn serialises_to_json_with_the_headline_key_present() {
        let summary = Summary::from_outcome(&outcome(), Duration::from_millis(20));
        let json = serde_json::to_string(&summary).expect("serialise");
        assert!(json.contains("\"engine_microseconds_per_relayed_packet\""));
        assert!(json.contains("\"calls_per_core\""));
        // Round-trips through a generic value, so a consumer can read it.
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse back");
        assert_eq!(value["calls"], 250);
    }
}
