//! Relay capacity harness for siphon-rtp.
//!
//! This crate answers a question no criterion bench in the tree can: **how many concurrent relay
//! calls does one node sustain?** The existing benches measure per-packet *compute* (RTP parse,
//! SSRC rewrite, SRTP) with no socket I/O, and the relay's real cost is not compute — it is two
//! syscalls and a handful of map lookups per packet, spread one-packet-per-20 ms across one socket
//! per media stream. That is a property of the whole running system, so it is measured by running
//! the whole system.
//!
//! The harness boots the real engine on the real userspace UDP datapath, allocates N plain relay
//! calls through the engine's own control surface, and drives real RTP through all of them.
//!
//! # The number this produces
//!
//! The headline output is **engine CPU microseconds per relayed packet**, not "N calls worked".
//! The generator shares the process with the engine and does comparable syscall work, so a
//! whole-process CPU figure would roughly double-count; [`cpu`] buckets by thread name to separate
//! them. A per-packet cost attributed to the engine's own threads is then independent of how
//! saturated the box got, and a sizing table for any core count follows from it by arithmetic.
//!
//! # Deliberate deviation from the house clock rule
//!
//! The project bans `Instant::now()` in DSP tests, because a logical sample clock is what makes
//! jitter/resampler/AEC tests deterministic. This harness uses the wall clock on purpose: throughput
//! and scheduling latency *are* wall-clock questions, and there is nothing to make deterministic.
//! The rule is about determinism where determinism is achievable, and it does not reach here.

#![forbid(unsafe_code)]

pub mod cpu;
pub mod probe;
pub mod report;
pub mod runner;
pub mod stats;
