//! `siphon-rtp-loadgen` — measure how many concurrent relay calls one node sustains.
//!
//! Run a single point:
//!
//! ```sh
//! siphon-rtp-loadgen --calls 500 --duration 30
//! ```
//!
//! Or sweep several, which is the usual thing, because one point cannot show where the cost curve
//! bends:
//!
//! ```sh
//! siphon-rtp-loadgen --sweep 100,250,500,1000,2000 --duration 30 --json results.json
//! ```
//!
//! The output to read is **engine microseconds per relayed packet**. See the crate docs for why
//! that, and not "N calls worked", is the number a sizing table is built from.

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use siphon_rtp_loadgen::report::Summary;
use siphon_rtp_loadgen::runner::{self, RunPlan};

#[derive(Parser, Debug)]
#[command(
    name = "siphon-rtp-loadgen",
    about = "Relay capacity harness for siphon-rtp (development tool)"
)]
struct Arguments {
    /// Concurrent relay calls to establish. Ignored when --sweep is given.
    #[arg(long, default_value_t = 100)]
    calls: usize,

    /// Comma-separated call counts to measure in sequence, e.g. 100,250,500,1000.
    #[arg(long, value_delimiter = ',')]
    sweep: Option<Vec<usize>>,

    /// Seconds of traffic to measure, per point.
    #[arg(long, default_value_t = 20)]
    duration: u64,

    /// Seconds of traffic to discard before measuring, per point.
    #[arg(long, default_value_t = 5)]
    warmup: u64,

    /// Packetisation interval in milliseconds.
    #[arg(long, default_value_t = 20)]
    ptime: u64,

    /// Engine runtime worker threads. Defaults to the host's parallelism, as the daemon does.
    #[arg(long)]
    engine_workers: Option<usize>,

    /// Generator runtime worker threads.
    #[arg(long)]
    generator_workers: Option<usize>,

    /// Streams one sender task drives. Larger batches keep the generator cheaper.
    #[arg(long, default_value_t = 64)]
    streams_per_sender: usize,

    /// Sockets one receive task drives. Each shard keeps one latency histogram, so this also sets
    /// the harness's own memory footprint.
    #[arg(long, default_value_t = 64)]
    sockets_per_receiver: usize,

    /// Also write the results as JSON to this path.
    #[arg(long)]
    json: Option<String>,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    let ptime = Duration::from_millis(arguments.ptime.max(1));

    let points = match &arguments.sweep {
        Some(points) if !points.is_empty() => points.clone(),
        _ => vec![arguments.calls],
    };

    // Warn before running rather than after failing: a descriptor shortfall shows up as confusing
    // bind errors deep into the largest point, which is the most expensive time to discover it.
    if let Some(largest) = points.iter().copied().max() {
        let budget = runner::FileDescriptorBudget::for_calls(largest);
        if budget.is_exceeded() {
            let limit = budget
                .soft_limit
                .map_or_else(|| "unknown".to_string(), |value| value.to_string());
            eprintln!(
                "warning: {} calls needs about {} file descriptors but the soft limit is {}.\n\
                 Raise it (ulimit -n, or --ulimit nofile= on a container) or the run will fail to \
                 bind.\n",
                largest, budget.required, limit
            );
        }
    }

    let mut summaries = Vec::with_capacity(points.len());

    for calls in points {
        let plan = RunPlan {
            calls,
            duration: Duration::from_secs(arguments.duration),
            ptime,
            warmup: Duration::from_secs(arguments.warmup),
            engine_workers: arguments.engine_workers,
            generator_workers: arguments.generator_workers,
            streams_per_sender: arguments.streams_per_sender,
            sockets_per_receiver: arguments.sockets_per_receiver,
        };

        println!("=== {calls} concurrent relay calls ===");
        match runner::run(&plan) {
            Ok(outcome) => {
                let summary = Summary::from_outcome(&outcome, ptime);
                print!("{}", summary.to_text());
                println!();
                summaries.push(summary);
            }
            Err(error) => {
                eprintln!("run at {calls} calls failed: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    if let Some(path) = arguments.json {
        match serde_json::to_string_pretty(&summaries) {
            Ok(text) => {
                if let Err(error) = std::fs::write(&path, text) {
                    eprintln!("could not write {path}: {error}");
                    return ExitCode::FAILURE;
                }
                println!("wrote {path}");
            }
            Err(error) => {
                eprintln!("could not serialise results: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}
