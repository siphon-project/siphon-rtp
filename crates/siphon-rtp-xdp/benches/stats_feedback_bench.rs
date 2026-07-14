//! Criterion benches for the Stage 3a per-flow feedback path — the host-side cost the loader pays
//! when the engine queries a flow's stats / `last_activity`.
//!
//! The in-kernel accepted-packet bookkeeping (the per-CPU stats bump + `bpf_ktime_get_ns()` stamp)
//! runs in the kernel and can't be criterion-benched directly, exactly like the Stage 2 rewrite math
//! in `rewrite_bench`. What *is* host-testable is the loader-side reduction of the per-CPU values into
//! one [`FlowStats`] ([`sum_flow_stats`], run once per stats query, O(CPUs)) and the ns→tick
//! conversion for `last_activity` ([`kernel_ns_to_tick`], run once per activity query). Benching them
//! here regression-gates the feedback path (ns/query) and, since both take/return scalars + a stack
//! accumulator, keeps it allocation-free.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_ebpf_common::FlowStats;
use siphon_rtp_xdp::{kernel_ns_to_tick, sum_flow_stats};

/// A plausible per-CPU `FlowStats` slice: `cpus` entries, each with some traffic and a distinct
/// `last_seen_ns`, as the loader reads them out of the `FLOW_STATS` per-CPU hash map.
fn per_cpu_values(cpus: usize) -> Vec<FlowStats> {
    (0..cpus)
        .map(|index| FlowStats {
            packets_in: 1_000 + index as u64,
            packets_out: 900 + index as u64,
            bytes_in: 160_000 + index as u64,
            bytes_out: 144_000 + index as u64,
            packets_dropped: index as u64,
            last_seen_ns: 5_000_000_000 + (index as u64) * 1_000_000,
            packets_lost: index as u64,
            last_rtp_seq: 0,
        })
        .collect()
}

fn stats_reduction(criterion: &mut Criterion) {
    // 16 CPUs: a typical media box. The reduction sums five counters and maxes last_seen_ns per CPU.
    let per_cpu = per_cpu_values(16);
    criterion.bench_function("sum_flow_stats_16_cpus", |bencher| {
        bencher.iter(|| sum_flow_stats(black_box(&per_cpu).iter().copied()))
    });
}

fn last_activity_conversion(criterion: &mut Criterion) {
    let origin: u64 = 5_000_000_000; // CLOCK_MONOTONIC origin captured at construction
    let last_seen_ns: u64 = origin + 1_234_567_890; // ~1.23 s of media later
    criterion.bench_function("kernel_ns_to_tick", |bencher| {
        bencher.iter(|| kernel_ns_to_tick(black_box(last_seen_ns), black_box(origin)))
    });
}

criterion_group!(benches, stats_reduction, last_activity_conversion);
criterion_main!(benches);
