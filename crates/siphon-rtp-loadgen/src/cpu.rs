//! Per-thread CPU accounting, read from `/proc/self/task/<tid>/stat`.
//!
//! The harness and the engine share a process, so a whole-process CPU figure would charge the
//! engine for the load generator's own syscalls — and the generator does the same volume of
//! `recv`/`send` work the engine does, so that error is roughly a factor of two. Bucketing by
//! thread name separates them, which is what makes **engine CPU per relayed packet** a number that
//! survives the generator running next door.
//!
//! That per-packet figure, not "N calls worked", is the harness's primary output: it is
//! independent of how saturated the box got, and it is what a sizing table is derived from.

use std::collections::BTreeMap;
use std::fs;

/// `/proc/[pid]/stat` reports CPU times in `USER_HZ` units. This is a property of the *procfs ABI*,
/// not of `CONFIG_HZ`: the kernel converts internally and `sysconf(_SC_CLK_TCK)` returns 100 on
/// every Linux/glibc target this tool runs on. Hardcoded so the crate needs no `libc` dependency
/// for one constant.
const USER_HZ: u64 = 100;

/// Field offsets within `/proc/[pid]/stat`, counting from the documented 1-based field numbers.
/// Fields 1 (`pid`) and 2 (`comm`) are consumed before the split, so a field `N` lands at index
/// `N - 3` in the remainder.
const FIELD_UTIME: usize = 14;
const FIELD_STIME: usize = 15;

/// CPU time consumed by one bucket of threads, in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuTime {
    /// Time spent in user space.
    pub user_microseconds: u64,
    /// Time spent in the kernel — for this workload, overwhelmingly `recvmsg`/`sendmsg`.
    pub system_microseconds: u64,
}

impl CpuTime {
    /// User plus system.
    #[must_use]
    pub fn total_microseconds(self) -> u64 {
        self.user_microseconds
            .saturating_add(self.system_microseconds)
    }

    /// The CPU consumed between an earlier sample and this one.
    #[must_use]
    pub fn since(self, earlier: Self) -> Self {
        Self {
            user_microseconds: self
                .user_microseconds
                .saturating_sub(earlier.user_microseconds),
            system_microseconds: self
                .system_microseconds
                .saturating_sub(earlier.system_microseconds),
        }
    }
}

/// A snapshot of CPU time for every thread bucket in this process, keyed by thread name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpuSample {
    /// Thread name (`/proc/self/task/<tid>/comm`) to accumulated CPU time.
    pub buckets: BTreeMap<String, CpuTime>,
}

impl CpuSample {
    /// CPU time for every thread whose name starts with `prefix`, summed.
    ///
    /// A prefix rather than an exact match because tokio may suffix worker threads, and because it
    /// lets one call cover `sr-engine` plus any helper thread named under the same prefix.
    #[must_use]
    pub fn bucket_starting_with(&self, prefix: &str) -> CpuTime {
        self.buckets
            .iter()
            .filter(|(name, _)| name.starts_with(prefix))
            .fold(CpuTime::default(), |accumulated, (_, time)| CpuTime {
                user_microseconds: accumulated
                    .user_microseconds
                    .saturating_add(time.user_microseconds),
                system_microseconds: accumulated
                    .system_microseconds
                    .saturating_add(time.system_microseconds),
            })
    }

    /// CPU time across every thread in the process.
    #[must_use]
    pub fn total(&self) -> CpuTime {
        self.bucket_starting_with("")
    }

    /// The per-bucket delta between an earlier sample and this one.
    #[must_use]
    pub fn since(&self, earlier: &Self) -> Self {
        let mut buckets = BTreeMap::new();
        for (name, time) in &self.buckets {
            let previous = earlier.buckets.get(name).copied().unwrap_or_default();
            buckets.insert(name.clone(), time.since(previous));
        }
        Self { buckets }
    }
}

/// Read CPU time for every thread in this process, bucketed by thread name.
///
/// Threads that vanish between the directory listing and the read are skipped rather than failing
/// the sample: thread churn is normal and a capacity run must not abort because one exited.
#[must_use]
pub fn sample() -> CpuSample {
    let mut buckets: BTreeMap<String, CpuTime> = BTreeMap::new();

    let Ok(entries) = fs::read_dir("/proc/self/task") else {
        return CpuSample { buckets };
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(stat) = fs::read_to_string(path.join("stat")) else {
            continue;
        };
        let Some((name, time)) = parse_stat(&stat) else {
            continue;
        };
        let slot = buckets.entry(name).or_default();
        slot.user_microseconds = slot
            .user_microseconds
            .saturating_add(time.user_microseconds);
        slot.system_microseconds = slot
            .system_microseconds
            .saturating_add(time.system_microseconds);
    }

    CpuSample { buckets }
}

/// Parse one `/proc/[pid]/stat` line into its thread name and CPU time.
///
/// The `comm` field is parenthesised and may itself contain spaces and parentheses, so it is
/// delimited by the **last** `)` in the line, not the first — splitting the whole line on
/// whitespace misparses any thread whose name contains a space.
fn parse_stat(stat: &str) -> Option<(String, CpuTime)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close <= open {
        return None;
    }
    let name = stat.get(open + 1..close)?.to_string();

    let remainder = stat.get(close + 1..)?;
    let fields: Vec<&str> = remainder.split_whitespace().collect();

    let utime: u64 = fields.get(FIELD_UTIME - 3)?.parse().ok()?;
    let stime: u64 = fields.get(FIELD_STIME - 3)?.parse().ok()?;

    Some((
        name,
        CpuTime {
            user_microseconds: ticks_to_microseconds(utime),
            system_microseconds: ticks_to_microseconds(stime),
        },
    ))
}

/// Convert `USER_HZ` clock ticks to microseconds.
fn ticks_to_microseconds(ticks: u64) -> u64 {
    ticks.saturating_mul(1_000_000 / USER_HZ)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `/proc/self/task/<tid>/stat` line, truncated after the fields we read.
    const SAMPLE_STAT: &str =
        "1234 (sr-engine) R 1 1234 1234 0 -1 4194304 512 0 0 0 37 11 0 0 20 0 8 0 99 0 0";

    #[test]
    fn parses_thread_name_and_cpu_time_from_a_real_stat_line() {
        let (name, time) = parse_stat(SAMPLE_STAT).expect("parse stat");
        assert_eq!(name, "sr-engine");
        // utime 37 ticks, stime 11 ticks, at 100 Hz => 10 ms per tick.
        assert_eq!(time.user_microseconds, 370_000);
        assert_eq!(time.system_microseconds, 110_000);
        assert_eq!(time.total_microseconds(), 480_000);
    }

    #[test]
    fn delimits_the_comm_field_by_the_last_paren_so_a_name_containing_parens_survives() {
        // A thread named "od)d (name" would break any parser that split on the first ')'.
        let stat = "7 (od)d (name) S 1 7 7 0 -1 0 0 0 0 0 5 3 0 0 20 0 1 0 0 0 0";
        let (name, time) = parse_stat(stat).expect("parse stat");
        assert_eq!(name, "od)d (name");
        assert_eq!(time.user_microseconds, 50_000);
        assert_eq!(time.system_microseconds, 30_000);
    }

    #[test]
    fn rejects_malformed_stat_lines_rather_than_panicking() {
        assert!(parse_stat("").is_none());
        assert!(parse_stat("1234 no-parens 0 0").is_none());
        assert!(parse_stat("1234 )backwards( R 1").is_none());
        // Well-formed prefix but truncated before utime/stime.
        assert!(parse_stat("1234 (short) R 1 2 3").is_none());
        // Non-numeric where a tick count belongs.
        assert!(parse_stat("1 (x) R 1 1 1 0 -1 0 0 0 0 0 abc def 0 0 20 0 1 0 0 0 0").is_none());
    }

    #[test]
    fn sums_buckets_by_name_prefix() {
        let mut buckets = BTreeMap::new();
        buckets.insert(
            "sr-engine".to_string(),
            CpuTime {
                user_microseconds: 100,
                system_microseconds: 400,
            },
        );
        buckets.insert(
            "sr-engine-aux".to_string(),
            CpuTime {
                user_microseconds: 10,
                system_microseconds: 20,
            },
        );
        buckets.insert(
            "sr-loadgen".to_string(),
            CpuTime {
                user_microseconds: 7,
                system_microseconds: 9,
            },
        );
        let sample = CpuSample { buckets };

        let engine = sample.bucket_starting_with("sr-engine");
        assert_eq!(engine.user_microseconds, 110);
        assert_eq!(engine.system_microseconds, 420);

        let loadgen = sample.bucket_starting_with("sr-loadgen");
        assert_eq!(loadgen.total_microseconds(), 16);

        assert_eq!(sample.total().total_microseconds(), 546);
    }

    #[test]
    fn a_delta_subtracts_the_earlier_sample_per_bucket() {
        let mut earlier = BTreeMap::new();
        earlier.insert(
            "sr-engine".to_string(),
            CpuTime {
                user_microseconds: 100,
                system_microseconds: 200,
            },
        );
        let mut later = BTreeMap::new();
        later.insert(
            "sr-engine".to_string(),
            CpuTime {
                user_microseconds: 175,
                system_microseconds: 500,
            },
        );

        let delta = CpuSample { buckets: later }.since(&CpuSample { buckets: earlier });
        let engine = delta.bucket_starting_with("sr-engine");
        assert_eq!(engine.user_microseconds, 75);
        assert_eq!(engine.system_microseconds, 300);
    }

    #[test]
    fn a_bucket_absent_from_the_earlier_sample_counts_its_whole_time() {
        // A thread that started mid-run has no baseline; all of its CPU belongs to the delta.
        let mut later = BTreeMap::new();
        later.insert(
            "sr-loadgen".to_string(),
            CpuTime {
                user_microseconds: 42,
                system_microseconds: 8,
            },
        );
        let delta = CpuSample { buckets: later }.since(&CpuSample::default());
        assert_eq!(
            delta
                .bucket_starting_with("sr-loadgen")
                .total_microseconds(),
            50
        );
    }

    #[test]
    fn a_counter_that_went_backwards_saturates_to_zero_rather_than_wrapping() {
        let mut earlier = BTreeMap::new();
        earlier.insert(
            "sr-engine".to_string(),
            CpuTime {
                user_microseconds: 900,
                system_microseconds: 900,
            },
        );
        let mut later = BTreeMap::new();
        later.insert(
            "sr-engine".to_string(),
            CpuTime {
                user_microseconds: 100,
                system_microseconds: 100,
            },
        );
        let delta = CpuSample { buckets: later }.since(&CpuSample { buckets: earlier });
        assert_eq!(
            delta.bucket_starting_with("sr-engine").total_microseconds(),
            0
        );
    }

    #[test]
    fn sampling_this_process_sees_at_least_the_current_thread() {
        // Not a fixture: proves the /proc walk works on the host running the tests.
        let sample = sample();
        assert!(
            !sample.buckets.is_empty(),
            "expected at least one thread bucket from /proc/self/task"
        );
    }
}
