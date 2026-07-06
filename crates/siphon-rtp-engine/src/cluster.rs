//! Cluster primitives: this node's identity, capacity, drain state, and a best-effort host-CPU
//! sampler — the single-owner state behind the `load`, `node_info`, `drain` and `undrain` control
//! commands.
//!
//! siphon-rtp scales horizontally behind the SIP control layer: the SIP proxy (SIPhon / Kamailio) is
//! the media *dispatcher*, and each engine exposes its live load and capabilities so placement is
//! load-aware instead of round-robin — and a node can be drained gracefully for a rolling upgrade
//! without dropping live calls. This module holds the small state that answers those queries; the
//! per-packet datapath never touches it.
//!
//! Everything here is lock-light: the drain flag is one [`AtomicBool`], the CPU sample one
//! [`AtomicU32`] cache refreshed ~1 Hz by a background task, and the identity/capacity is set-once
//! config read by shared reference. Answering `load` is a few relaxed atomic loads — no allocation
//! beyond the reply itself.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_proto::{NodeInfo, NodeLoad};

/// Sentinel stored in the CPU cache meaning "no valid sample yet". `u32::MAX` is far outside the
/// valid `0..=1000` per-mille range, so it can never collide with a real reading.
const CPU_NONE: u32 = u32::MAX;

/// How often the background sampler reads `/proc/stat`. ~1 Hz keeps the reading fresh while the cost
/// (one pseudo-file read on a blocking thread) stays negligible.
pub const DEFAULT_CPU_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// This engine instance's cluster identity, capacity, and live drain flag — the single-owner state
/// behind the cluster control commands.
#[derive(Debug)]
pub struct ClusterState {
    node_id: String,
    /// Configured maximum concurrent sessions; `0` = unlimited / not advertised.
    max_sessions: u64,
    /// Media addresses advertised in `node_info` (the reachable relay IPs).
    media_addresses: Vec<String>,
    /// `true` while draining — new sessions are refused, live calls run to completion.
    draining: AtomicBool,
    /// Best-effort host CPU utilization in per-mille, or [`CPU_NONE`] until the sampler publishes one.
    cpu_permille: AtomicU32,
}

impl ClusterState {
    /// Build the cluster state from set-once config. `node_id` should be stable across restarts (a
    /// hostname or an operator-assigned id); `max_sessions` of `0` advertises "unlimited".
    #[must_use]
    pub fn new(node_id: String, max_sessions: u64, media_addresses: Vec<String>) -> Self {
        Self {
            node_id,
            max_sessions,
            media_addresses,
            draining: AtomicBool::new(false),
            cpu_permille: AtomicU32::new(CPU_NONE),
        }
    }

    /// Whether this node is draining (refusing new sessions).
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Advertised maximum concurrent sessions; `0` = unlimited. Read by the `/metrics` surface for the
    /// `siphon_rtp_max_sessions` gauge and the load-score computation.
    #[must_use]
    pub fn max_sessions(&self) -> u64 {
        self.max_sessions
    }

    /// Enter (`true`) or leave (`false`) drain mode. Idempotent.
    pub fn set_draining(&self, draining: bool) {
        self.draining.store(draining, Ordering::Relaxed);
    }

    /// The most recent host CPU sample in per-mille, or `None` if no sampler has published one.
    #[must_use]
    pub fn cpu_permille(&self) -> Option<u16> {
        match self.cpu_permille.load(Ordering::Relaxed) {
            CPU_NONE => None,
            value => Some(value.min(1000) as u16),
        }
    }

    /// Publish a fresh host CPU sample (per-mille, clamped to `0..=1000`). Called by the sampler task.
    pub fn set_cpu_permille(&self, permille: u16) {
        self.cpu_permille
            .store(u32::from(permille.min(1000)), Ordering::Relaxed);
    }

    /// Static identity + capabilities for the `node_info` command.
    #[must_use]
    pub fn info(&self, version: &str, codecs: Vec<String>, features: Vec<String>) -> NodeInfo {
        NodeInfo {
            node_id: self.node_id.clone(),
            version: version.to_string(),
            media_addresses: self.media_addresses.clone(),
            codecs,
            features,
            max_sessions: self.max_sessions,
            draining: self.is_draining(),
        }
    }

    /// Live load snapshot for the `load` command. `sessions` and `transcode_sessions` are the current
    /// registry gauges; `allocated_bytes` is jemalloc `stats.allocated`. The load score is the higher
    /// of session utilization and host CPU — the tighter constraint (see [`load_permille`]).
    #[must_use]
    pub fn load(&self, sessions: u64, transcode_sessions: u64, allocated_bytes: u64) -> NodeLoad {
        let cpu = self.cpu_permille();
        NodeLoad {
            node_id: self.node_id.clone(),
            sessions,
            max_sessions: self.max_sessions,
            load_permille: load_permille(sessions, self.max_sessions, cpu),
            transcode_sessions,
            cpu_permille: cpu,
            jemalloc_allocated_bytes: allocated_bytes,
            draining: self.is_draining(),
        }
    }
}

/// Normalized node load in per-mille (`0..=1000`): the higher of session utilization and host CPU,
/// so a node that is CPU-bound at a low session count still reports busy. With `max_sessions == 0`
/// (unlimited) the session term is `0` and only CPU (when known) drives the score.
#[must_use]
pub fn load_permille(sessions: u64, max_sessions: u64, cpu_permille: Option<u16>) -> u16 {
    // `sessions * 1000` cannot overflow u64 for any realistic session count. `checked_div` is `None`
    // only when `max_sessions == 0` (unlimited) — then the session term is 0 and only CPU (when
    // known) drives the score. Clamp to 1000 so an over-capacity node still reports a saturated score.
    let session_permille = sessions
        .saturating_mul(1000)
        .checked_div(max_sessions)
        .map_or(0, |permille| permille.min(1000) as u16);
    session_permille.max(cpu_permille.unwrap_or(0))
}

/// A CPU-time reading from the aggregate `cpu` line of `/proc/stat`: total and idle jiffies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuTimes {
    /// Sum of every field on the `cpu` line (busy + idle jiffies since boot).
    pub total: u64,
    /// Idle jiffies (`idle + iowait`) — the CPU had no runnable work.
    pub idle: u64,
}

/// Parse the aggregate `cpu` line of `/proc/stat` into total and idle jiffies (Linux). Returns
/// `None` if the line is absent or malformed — the sampler then simply publishes no update.
///
/// The `cpu` line is `cpu  user nice system idle iowait irq softirq steal guest guest_nice`. For
/// utilization, `idle` is `idle + iowait` (no runnable work) and `total` is the sum of every field
/// (Linux `Documentation/filesystems/proc.rst`, the `stat` file).
#[must_use]
pub fn parse_proc_stat_cpu(text: &str) -> Option<CpuTimes> {
    let line = text.lines().find(|line| {
        line.strip_prefix("cpu")
            .is_some_and(|rest| rest.starts_with([' ', '\t']))
    })?;
    let mut fields = line.split_whitespace();
    let _tag = fields.next()?; // "cpu"
    let values: Vec<u64> = fields
        .map(|field| field.parse().ok())
        .collect::<Option<_>>()?;
    if values.len() < 4 {
        return None; // need at least user, nice, system, idle
    }
    let idle = values[3] + values.get(4).copied().unwrap_or(0); // idle + iowait
    let total: u64 = values.iter().sum();
    Some(CpuTimes { total, idle })
}

/// Compute CPU utilization in per-mille from two `/proc/stat` samples (`prev` → `now`). Returns
/// `None` if the interval advanced no jiffies (division guard) or the counters went backwards.
#[must_use]
pub fn cpu_permille_between(prev: CpuTimes, now: CpuTimes) -> Option<u16> {
    let total_delta = now.total.checked_sub(prev.total)?;
    let idle_delta = now.idle.checked_sub(prev.idle)?;
    if total_delta == 0 {
        return None;
    }
    let busy = total_delta.saturating_sub(idle_delta);
    Some((busy.saturating_mul(1000) / total_delta).min(1000) as u16)
}

/// Spawn a background task that samples host CPU from `/proc/stat` at `interval` and publishes each
/// reading into `state`. Best effort: on a platform without `/proc/stat`, or on a read error, it
/// publishes nothing and `cpu_permille` stays `None`. The `/proc` read (a pseudo-file, but still a
/// blocking syscall) runs on `spawn_blocking`, never a reactor thread (the concurrency rule: block never).
pub fn spawn_cpu_sampler(state: Arc<ClusterState>, interval: Duration) {
    tokio::spawn(async move {
        let mut previous: Option<CpuTimes> = None;
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let Ok(Some(text)) = tokio::task::spawn_blocking(read_proc_stat).await else {
                continue;
            };
            let Some(now) = parse_proc_stat_cpu(&text) else {
                continue;
            };
            if let Some(prev) = previous {
                if let Some(permille) = cpu_permille_between(prev, now) {
                    state.set_cpu_permille(permille);
                }
            }
            previous = Some(now);
        }
    });
}

/// Read `/proc/stat` (blocking). `None` if unreadable (non-Linux, sandbox, permissions).
fn read_proc_stat() -> Option<String> {
    std::fs::read_to_string("/proc/stat").ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_permille_is_session_utilization_when_no_cpu() {
        // 812 / 4000 = 0.203 → 203 ‰.
        assert_eq!(load_permille(812, 4000, None), 203);
        // Exactly at capacity is 1000 ‰.
        assert_eq!(load_permille(4000, 4000, None), 1000);
        // Over capacity saturates at 1000 (never wraps or exceeds).
        assert_eq!(load_permille(9000, 4000, None), 1000);
        // Empty node is 0.
        assert_eq!(load_permille(0, 4000, None), 0);
    }

    #[test]
    fn load_permille_unlimited_capacity_uses_only_cpu() {
        // max_sessions == 0 → session term is 0; CPU (when known) drives the score.
        assert_eq!(load_permille(10_000, 0, None), 0);
        assert_eq!(load_permille(10_000, 0, Some(420)), 420);
    }

    #[test]
    fn load_permille_takes_the_higher_of_sessions_and_cpu() {
        // Sessions say 203 ‰ but CPU says 700 ‰ → the tighter constraint wins.
        assert_eq!(load_permille(812, 4000, Some(700)), 700);
        // CPU low, sessions high → sessions win.
        assert_eq!(load_permille(3800, 4000, Some(100)), 950);
    }

    #[test]
    fn drain_flag_toggles_and_defaults_off() {
        let state = ClusterState::new("n1".into(), 4000, vec!["203.0.113.10".into()]);
        assert!(!state.is_draining(), "defaults to not draining");
        state.set_draining(true);
        assert!(state.is_draining());
        state.set_draining(true); // idempotent
        assert!(state.is_draining());
        state.set_draining(false);
        assert!(!state.is_draining());
    }

    #[test]
    fn cpu_sample_defaults_none_and_round_trips_clamped() {
        let state = ClusterState::new("n1".into(), 0, vec![]);
        assert_eq!(state.cpu_permille(), None, "no sample published yet");
        state.set_cpu_permille(247);
        assert_eq!(state.cpu_permille(), Some(247));
        state.set_cpu_permille(5000); // out of range → clamped to 1000
        assert_eq!(state.cpu_permille(), Some(1000));
    }

    #[test]
    fn info_reports_identity_capacity_and_drain() {
        let state = ClusterState::new("rtp-ams-3".into(), 4000, vec!["203.0.113.10".into()]);
        state.set_draining(true);
        let info = state.info("0.1.0", vec!["PCMU".into()], vec!["relay".into()]);
        assert_eq!(info.node_id, "rtp-ams-3");
        assert_eq!(info.version, "0.1.0");
        assert_eq!(info.media_addresses, vec!["203.0.113.10".to_string()]);
        assert_eq!(info.codecs, vec!["PCMU".to_string()]);
        assert_eq!(info.max_sessions, 4000);
        assert!(info.draining);
    }

    #[test]
    fn load_snapshot_reflects_gauges_and_drain() {
        let state = ClusterState::new("n1".into(), 4000, vec![]);
        state.set_cpu_permille(300);
        let load = state.load(812, 140, 734_003_200);
        assert_eq!(load.node_id, "n1");
        assert_eq!(load.sessions, 812);
        assert_eq!(load.max_sessions, 4000);
        assert_eq!(load.transcode_sessions, 140);
        assert_eq!(load.cpu_permille, Some(300));
        // 812/4000 = 203 ‰ < 300 ‰ CPU → CPU wins.
        assert_eq!(load.load_permille, 300);
        assert_eq!(load.jemalloc_allocated_bytes, 734_003_200);
        assert!(!load.draining);
    }

    #[test]
    fn parse_proc_stat_reads_the_aggregate_cpu_line() {
        // A representative /proc/stat: the aggregate `cpu` line (two spaces), then per-core lines.
        let text = concat!(
            "cpu  100 20 80 700 40 0 10 0 0 0\n",
            "cpu0 50 10 40 350 20 0 5 0 0 0\n",
            "intr 12345\n",
        );
        let times = parse_proc_stat_cpu(text).expect("aggregate cpu line parses");
        // total = 100+20+80+700+40+0+10+0+0+0 = 950; idle = idle(700)+iowait(40) = 740.
        assert_eq!(times.total, 950);
        assert_eq!(times.idle, 740);
    }

    #[test]
    fn parse_proc_stat_rejects_malformed_or_absent() {
        assert!(parse_proc_stat_cpu("").is_none(), "empty");
        assert!(
            parse_proc_stat_cpu("cpu0 1 2 3 4\nintr 5\n").is_none(),
            "no aggregate cpu line (only per-core)"
        );
        assert!(
            parse_proc_stat_cpu("cpu  1 2\n").is_none(),
            "too few fields (need >= 4)"
        );
        assert!(
            parse_proc_stat_cpu("cpu  a b c d\n").is_none(),
            "non-numeric fields"
        );
    }

    #[test]
    fn cpu_permille_between_computes_busy_fraction() {
        let prev = CpuTimes {
            total: 1000,
            idle: 800,
        };
        // +1000 total, +250 idle → busy 750/1000 = 750 ‰.
        let now = CpuTimes {
            total: 2000,
            idle: 1050,
        };
        assert_eq!(cpu_permille_between(prev, now), Some(750));
    }

    #[test]
    fn cpu_permille_between_guards_zero_and_backwards() {
        let a = CpuTimes {
            total: 1000,
            idle: 800,
        };
        assert_eq!(cpu_permille_between(a, a), None, "no elapsed jiffies");
        let backwards = CpuTimes {
            total: 500,
            idle: 400,
        };
        assert_eq!(
            cpu_permille_between(a, backwards),
            None,
            "counters went backwards (e.g. after a suspend)"
        );
        // Fully busy: all delta is non-idle → 1000 ‰.
        let busy = CpuTimes {
            total: 2000,
            idle: 800,
        };
        assert_eq!(cpu_permille_between(a, busy), Some(1000));
    }
}
