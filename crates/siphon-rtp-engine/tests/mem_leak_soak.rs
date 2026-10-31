//! Memory-leak soak for the session engine.
//!
//! `cargo test -p siphon-rtp-engine --test mem_leak_soak`
//!
//! Churns `offer → answer → delete` over the NIC-free UDP-loopback datapath and proves the engine
//! gives memory back: the session registry drains to **0** and jemalloc's live `allocated` stays
//! flat across thousands of completed calls. Gate on `allocated` (live bytes), never RSS — jemalloc
//! retains freed pages, so RSS is too noisy to gate on. A rising `allocated` at steady state is a
//! real leak (a stranded `Call`, a recv task whose socket/buffer never freed).
//!
//! Two things have to be true before `allocated` means that, and both are set up here rather than
//! assumed: the counter has to report live bytes rather than thread-cache residue (see
//! [`malloc_conf`]), and the engine's own *bounded* one-off steady-state cost has to be behind us
//! before the window opens (see [`LeakGate`]).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_engine::{ClientId, Engine};
use siphon_rtp_proto::{
    CmdResult, Command, ConferenceRole, FloorKey, ProfileFlags, WsTeeDirection,
};

/// The soak drives the engine as a single control client.
const CLIENT: ClientId = ClientId(1);

/// Serializes the soaks in this binary. libtest runs them **concurrently in one process**, and every
/// one of them measures the same *process-global* jemalloc counter — so without this, one soak's
/// allocations land inside another's before/after window and report as that other soak's leak. (A
/// thread-local arm-flag, the trick the zero-alloc tests use, cannot help: `stats.allocated` is
/// process-wide by construction.) `tokio::sync::Mutex` because the guard is held across `.await`.
static SOAK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Turns jemalloc's thread cache off **for this test binary only**, because with it on
/// `stats.allocated` does not mean live bytes.
///
/// A free that lands in a thread's cache does not move the bin's `ndalloc`; only flushing the cache
/// back to the arena does. `stats.allocated` is derived from `nmalloc - ndalloc`, so every region
/// sitting in some Tokio worker's cache is still counted as allocated. At a quiesced steady state
/// that residue is whatever the workers happened to be holding when the sample was taken: measured
/// on this file it moved the same 2400-cycle churn between −165 KB and +451 KB run to run, the same
/// order as the leak budget itself. That is the noise these soaks were flaking on.
///
/// With the cache off the counter is exact and the same churn reports the *identical* byte count
/// segment after segment. It can only remove false positives, never hide a leak — a leak still
/// allocates, and an allocation is counted the moment it is made whether or not a cache exists.
///
/// `_rjem_` is the symbol prefix `tikv-jemalloc-sys` builds jemalloc with. If that ever changes the
/// symbol is silently ignored, so [`LeakGate::new`] asserts `opt.tcache` actually came back off
/// rather than letting the soaks quietly go back to measuring cache residue.
#[allow(non_upper_case_globals)]
#[export_name = "_rjem_malloc_conf"]
pub static malloc_conf: &[u8; 13] = b"tcache:false\0";

/// Live bytes currently allocated, per jemalloc. Advancing the epoch refreshes the cached stats.
fn allocated_bytes() -> usize {
    tikv_jemalloc_ctl::epoch::advance().expect("advance jemalloc epoch");
    tikv_jemalloc_ctl::stats::allocated::read().expect("read jemalloc allocated")
}

/// Live bytes once teardown has actually finished, rather than whenever the sample was asked for.
///
/// Aborting a task only *schedules* it: the socket, the actor's buffers and its codec state come
/// back when the runtime next polls it, on whichever worker owns it. A fixed number of yields gives
/// that a chance but no guarantee, and sampling into the window reads a call that is on its way out
/// as still live. Measured on the conference soak that transient is 75–260 KB — most of the old leak
/// budget, appearing and vanishing between otherwise identical runs, which is exactly the shape that
/// makes a soak flake.
///
/// So a sample is not one read. It is reads separated by yields until the number stops moving, which
/// is the observable actually being waited on. Bounded, so a genuine hang fails the soak on its
/// assertion rather than spinning forever.
///
/// Yields alone are not enough. An actor that only observes its own shutdown on its next tick does
/// not retire because the loop spun — a promoted overlay leg is one ptime away from noticing, and
/// until it does, its jitter buffer, codec state and four overlay slots are counted as live. That
/// showed up as the overlay soak sitting on either of two exact values 135 864 bytes apart, flipping
/// between them segment after segment for thousands of cycles and never converging. So the loop lets
/// real time pass as well, which is what those teardowns are actually waiting on.
async fn allocated_when_quiesced() -> usize {
    let mut previous = allocated_bytes();
    for _ in 0..256 {
        quiesce().await;
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let settled = allocated_bytes();
        if settled == previous {
            return settled;
        }
        previous = settled;
    }
    previous
}

/// Churn until live bytes stop growing, then prove they stay there.
///
/// A single `warm up → before → churn → after` pair cannot tell a leak from the engine's *bounded*
/// one-off steady-state cost, and that cost is not small. Every `DashMap` in the engine, the media
/// pipeline and the datapath allocates its shard array up front but each shard's hash table only on
/// that shard's first insert — and a hash table is never given back when its last entry is removed.
/// Churning calls with fresh keys walks the shards in effectively random order, so the soak keeps
/// discovering untouched ones for hundreds of cycles before it has hit them all. `DashMap` sizes
/// itself as `(available_parallelism * 4).next_power_of_two()` shards, so both the height of that
/// plateau and the number of cycles needed to top out scale with the core count of the machine
/// running the test: measured here, ~1 KB reached inside ~200 cycles on 2 cores against ~600 KB
/// needing ~800 cycles on 24. No fixed warmup is right on both, and when it is too short the
/// leftover ramp lands inside the measurement window and reads as a leak.
///
/// So this does not guess a warmup. It churns segment after segment until several in a row come
/// back flat, and only the growth *after* that counts. Bounded work converges; a leak does not, and
/// fails either by never settling or by the growth once it has.
struct LeakGate {
    /// Names the soak in the failure message.
    label: &'static str,
    /// Churn cycles per measured segment.
    cycles_per_segment: usize,
    /// Segments the steady state is allowed to converge in before the soak gives up.
    max_settle_segments: usize,
    /// `allocated` before any churn, then after every segment.
    samples: Vec<usize>,
    /// Consecutive flat segments ending at the most recent sample.
    flat_streak: usize,
}

impl LeakGate {
    /// Growth per churned cycle that still counts as flat. Per cycle rather than per segment so the
    /// bar means the same thing whatever a soak sizes its segments at. Measured across every soak in
    /// this file with the thread cache off, a converged one moves by single-digit bytes per cycle
    /// (the last few shards being discovered) while one still on the ramp moves by hundreds.
    const FLAT_BYTES_PER_CYCLE: usize = 16;

    /// Consecutive flat segments that declare the steady state reached. The plateau is not
    /// approached smoothly — it is climbed in ~6 KB steps, one shard's hash table at a time, and the
    /// last few of those are hundreds of cycles apart. A short streak keeps landing between two of
    /// them and calls the ramp finished while it is not, which puts the next step inside the
    /// verification window and reads as a leak. Five, so a soak has to be genuinely quiet for
    /// [`Self::SETTLE_STREAK`] × its segment length before anything is measured.
    const SETTLE_STREAK: usize = 5;

    /// Segments that must stay flat once live bytes have converged. Each of them has to clear the
    /// per-segment bar on its own *and* their combined growth has to clear the same bar over their
    /// combined cycles — so a single late shard does not get a budget to hide in. It simply resets
    /// the streak and the soak keeps churning, which a bounded plateau survives and a leak does not.
    const VERIFY_SEGMENTS: usize = 5;

    /// The unbroken run of flat segments the soak is looking for: long enough to be sure the ramp
    /// is over, then the ones that are actually measured.
    const FLAT_RUN: usize = Self::SETTLE_STREAK + Self::VERIFY_SEGMENTS;

    /// The flat bar over `cycles` churned cycles.
    fn flat_bytes(cycles: usize) -> usize {
        Self::FLAT_BYTES_PER_CYCLE * cycles
    }

    async fn new(
        label: &'static str,
        cycles_per_segment: usize,
        max_settle_segments: usize,
    ) -> Self {
        assert!(
            !tikv_jemalloc_ctl::opt::tcache::read().expect("read opt.tcache"),
            "{label}: jemalloc's thread cache is on, so `stats.allocated` counts cache-resident \
             frees as live and this soak would measure noise — see `malloc_conf`"
        );
        assert!(
            max_settle_segments >= Self::SETTLE_STREAK + Self::VERIFY_SEGMENTS,
            "{label}: the settle budget cannot be shorter than the flat run it has to find"
        );
        // Sized so no segment sample can reallocate inside a measurement window.
        let mut samples = Vec::with_capacity(max_settle_segments + 1);
        // Prime jemalloc's stat machinery so the baseline is not itself a first-read allocation.
        let _prime = allocated_bytes();
        samples.push(allocated_when_quiesced().await);
        Self {
            label,
            cycles_per_segment,
            max_settle_segments,
            samples,
            flat_streak: 0,
        }
    }

    /// Churn cycles the caller should run before the next [`Self::sample`].
    fn cycles_per_segment(&self) -> usize {
        self.cycles_per_segment
    }

    /// Segments churned so far.
    fn segments_run(&self) -> usize {
        self.samples.len() - 1
    }

    /// Whether another segment of churn is needed — `false` once a long enough flat run has been
    /// seen, or once the settle budget is spent, which [`Self::assert_no_leak`] then reports as the
    /// leak it is.
    fn needs_more_churn(&self) -> bool {
        self.flat_streak < Self::FLAT_RUN && self.segments_run() < self.max_settle_segments
    }

    /// Sample live bytes after a segment of churn, once teardown has finished.
    async fn sample(&mut self) {
        let now = allocated_when_quiesced().await;
        let previous = self.samples[self.samples.len() - 1];
        self.samples.push(now);
        if now.saturating_sub(previous) <= Self::flat_bytes(self.cycles_per_segment) {
            self.flat_streak += 1;
        } else {
            // Not the plateau after all. Nothing measured so far counts.
            self.flat_streak = 0;
        }
    }

    /// The whole series, so a CI failure is diagnosable without a rerun.
    fn series(&self) -> String {
        self.samples
            .iter()
            .enumerate()
            .map(|(segment, allocated)| {
                format!("{}:{allocated}", segment * self.cycles_per_segment)
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The gate: live bytes converged, and stayed converged.
    fn assert_no_leak(&self) {
        assert!(
            self.flat_streak >= Self::FLAT_RUN,
            "{} never reached a steady state — live bytes were still climbing after {} churned \
             cycles, which is what a leak looks like (cycle:allocated {})",
            self.label,
            self.segments_run() * self.cycles_per_segment,
            self.series()
        );
        let settled_at = self.segments_run() - Self::VERIFY_SEGMENTS;
        let verified_cycles = Self::VERIFY_SEGMENTS * self.cycles_per_segment;
        let grew = self.samples[self.samples.len() - 1].saturating_sub(self.samples[settled_at]);
        let budget = Self::flat_bytes(verified_cycles);
        // Captured by libtest unless `--nocapture`, and replayed when the assertion below fires.
        println!(
            "{}: settled at cycle {}, grew {grew} bytes (budget {budget}) over the \
             {verified_cycles} verified cycles (cycle:allocated {})",
            self.label,
            settled_at * self.cycles_per_segment,
            self.series()
        );
        assert!(
            grew <= budget,
            "{} leaked {grew} bytes (budget {budget}) over the {verified_cycles} cycles churned \
             after live bytes settled at cycle {} (cycle:allocated {})",
            self.label,
            settled_at * self.cycles_per_segment,
            self.series()
        );
    }
}

/// A two-port SDP (RTP + default RTCP at port+1). Documentation-range address (RFC 5737), never real.
fn sdp_for(host: &str, port: u16) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {host}\r\ns=-\r\nc=IN IP4 {host}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n"
    )
}

fn assert_ok(result: &CmdResult, what: &str) {
    assert!(
        matches!(result, CmdResult::Ok { .. }),
        "{what} should succeed, got {result:?}"
    );
}

async fn offer_answer_delete(engine: &Engine<UdpLoopbackDatapath>, index: usize) {
    let call_id = format!("soak-{index}");

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                sdp: sdp_for("198.51.100.1", 40_000),
                profile: Default::default(),
            },
        )
        .await;
    assert_ok(&offer, "offer");

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for("203.0.113.1", 41_000),
                profile: Default::default(),
            },
        )
        .await;
    assert_ok(&answer, "answer");

    let delete = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id,
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert_ok(&delete, "delete");
}

/// Churn one control connection that presents a **new** stable identity, carries a call through
/// `offer → answer → delete`, and disconnects — the shape that retains most.
///
/// An identity row outlives the connection that created it, deliberately: that retention is what
/// lets a reconnect find the calls it already owns. So it is also the one piece of engine state a
/// peer could make grow without bound, one row per id it is ever shown, and on a control plane
/// reachable without a secret it can choose every one of them. Hence a distinct id per cycle rather
/// than a realistic handful: the row, its reverse index and its event channel all have to come back
/// once no connection is attached and no call is left under it.
async fn controller_connect_call_disconnect(engine: &Engine<UdpLoopbackDatapath>, index: usize) {
    let controller_id = format!("soak-controller-{index}");
    let call_id = format!("soak-identity-{index}");
    let attachment = engine
        .attach_controller(&controller_id, ClientId(1_000_000 + index as u64))
        .expect("claim");

    let offer = engine
        .handle(
            attachment.client,
            Command::Offer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                sdp: sdp_for("198.51.100.1", 40_000),
                profile: Default::default(),
            },
        )
        .await;
    assert_ok(&offer, "offer");

    let answer = engine
        .handle(
            attachment.client,
            Command::Answer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for("203.0.113.1", 41_000),
                profile: Default::default(),
            },
        )
        .await;
    assert_ok(&answer, "answer");

    let delete = engine
        .handle(
            attachment.client,
            Command::Delete {
                call_id,
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert_ok(&delete, "delete");

    // The connection ends, which is what releases the identity now that it owns nothing.
    engine.deregister_client(attachment.client, attachment.generation);
    engine.detach_controller(&controller_id, attachment.generation);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_identity_churn_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    let mut gate = LeakGate::new("controller identity churn", 100, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            controller_connect_call_disconnect(&engine, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        assert_eq!(
            engine.controller_count(),
            0,
            "no identity outlives both its connection and its last call"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// Churn one relay through `offer → answer → re-offer from A → answer → re-offer from B → A's
/// reversed answer → delete`. Each re-offer records its party's state and each answer re-runs the
/// media wiring on the live call; a re-offer from B also holds its SDP on the call until A answers.
/// None of that may outlive the call.
async fn offer_answer_reoffer_both_ways_delete(engine: &Engine<UdpLoopbackDatapath>, index: usize) {
    let call_id = format!("soak-reoffer-{index}");
    let a_sdp = || sdp_for("198.51.100.1", 40_000);
    let b_sdp = || sdp_for("203.0.113.1", 41_000);
    let answer = |from_tag: &str, to_tag: &str, sdp: String| Command::Answer {
        call_id: call_id.clone(),
        from_tag: from_tag.into(),
        to_tag: to_tag.into(),
        sdp,
        profile: Default::default(),
    };
    let reoffer = |from_tag: &str, sdp: String| Command::Reoffer {
        call_id: call_id.clone(),
        from_tag: from_tag.into(),
        sdp,
        profile: Default::default(),
    };

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                sdp: a_sdp(),
                profile: Default::default(),
            },
        )
        .await;
    assert_ok(&offer, "offer");
    assert_ok(
        &engine
            .handle(CLIENT, answer("tag-a", "tag-b", b_sdp()))
            .await,
        "answer",
    );
    assert_ok(
        &engine.handle(CLIENT, reoffer("tag-a", a_sdp())).await,
        "re-offer from A",
    );
    assert_ok(
        &engine
            .handle(CLIENT, answer("tag-a", "tag-b", b_sdp()))
            .await,
        "B's answer to it",
    );
    assert_ok(
        &engine.handle(CLIENT, reoffer("tag-b", b_sdp())).await,
        "re-offer from B",
    );
    assert_ok(
        &engine
            .handle(CLIENT, answer("tag-b", "tag-a", a_sdp()))
            .await,
        "A's reversed answer to it",
    );
    let delete = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert_ok(&delete, "delete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reoffer_from_either_party_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    let mut gate = LeakGate::new("re-offer both ways", 100, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            offer_answer_reoffer_both_ways_delete(&engine, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// Churn one single-leg call through `answer_local → answer_local (replace) → delete`, plus one relay
/// through `offer → answer → answer_local (refused) → delete`.
///
/// A re-answer on the client's own single-leg call replaces it, and the replaced call's ports,
/// endpoint index entries and quota slot have to come back. An `answer_local` over a live relay is
/// refused, and the refusal has to allocate nothing that outlives it.
async fn answer_local_replace_and_refuse_delete(
    engine: &Engine<UdpLoopbackDatapath>,
    index: usize,
) {
    let local_id = format!("soak-local-{index}");
    for what in ["answer_local", "answer_local replace"] {
        let answer = engine
            .handle(
                CLIENT,
                Command::AnswerLocal {
                    call_id: local_id.clone(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for("198.51.100.1", 40_000),
                    profile: Default::default(),
                },
            )
            .await;
        assert_ok(&answer, what);
    }

    let relay_id = format!("soak-relay-{index}");
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: relay_id.clone(),
                from_tag: "tag-a".into(),
                sdp: sdp_for("198.51.100.1", 42_000),
                profile: Default::default(),
            },
        )
        .await;
    assert_ok(&offer, "offer");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: relay_id.clone(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for("203.0.113.1", 41_000),
                profile: Default::default(),
            },
        )
        .await;
    assert_ok(&answer, "answer");
    let refused = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: relay_id.clone(),
                from_tag: "tag-a".into(),
                sdp: sdp_for("198.51.100.1", 42_000),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(refused, CmdResult::Error { .. }),
        "answer_local over a relay is refused, got {refused:?}"
    );
    assert_eq!(
        engine.session_count(),
        2,
        "one single-leg call and one relay"
    );

    for call_id in [local_id, relay_id] {
        let delete = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id,
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert_ok(&delete, "delete");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answer_local_replace_and_refusal_do_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    let mut gate = LeakGate::new("answer_local replace/refuse", 100, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            answer_local_replace_and_refuse_delete(&engine, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// Churn one announcement call through `answer_local → offer_far → delete (far leg) → offer_far →
/// answer → delete (far leg) → delete`: the far leg grown and released twice, once unanswered and
/// once answered, must give back its ports and endpoint index entries each time.
async fn offer_far_grow_and_release(engine: &Engine<UdpLoopbackDatapath>, index: usize) {
    let call_id = format!("soak-far-{index}");
    let answer = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                sdp: sdp_for("198.51.100.1", 40_000),
                profile: Default::default(),
            },
        )
        .await;
    assert_ok(&answer, "answer_local");
    for answered in [false, true] {
        let offer = engine
            .handle(
                CLIENT,
                Command::OfferFar {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    profile: Default::default(),
                },
            )
            .await;
        assert_ok(&offer, "offer_far");
        if answered {
            let answer = engine
                .handle(
                    CLIENT,
                    Command::Answer {
                        call_id: call_id.clone(),
                        from_tag: "tag-a".into(),
                        to_tag: "tag-b".into(),
                        sdp: sdp_for("203.0.113.1", 41_000),
                        profile: Default::default(),
                    },
                )
                .await;
            assert_ok(&answer, "answer the far leg");
        }
        let release = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    to_tag: Some("tag-b".into()),
                },
            )
            .await;
        assert_ok(&release, "delete the far leg");
    }
    let delete = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id,
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert_ok(&delete, "delete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_far_grow_and_release_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    let mut gate = LeakGate::new("offer_far grow/release", 100, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            offer_far_grow_and_release(&engine, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// Let aborted receive tasks actually drop (freeing their socket + recv buffer) so a measurement
/// reflects quiesced steady state, not in-flight teardown.
async fn quiesce() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_answer_delete_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    // Each call allocates four endpoints (2× RTP + 2× RTCP) plus SDP strings and a registry entry,
    // and frees them all on delete. Once live bytes settle they must stay settled.
    let mut gate = LeakGate::new("plain relay", 100, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            offer_answer_delete(&engine, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// A plain two-party call carrying an MCPTT floor stream (3GPP TS 24.379 `m=application ... udp
/// MCPTT`), churned through `offer → answer → delete`. It is the call shape that installs the
/// userspace RTCP relay (an actor, its mailbox and its routes) on top of the plain relay's flows, so
/// everything that relay holds has to come back with the call.
async fn floor_call_offer_answer_delete(engine: &Engine<UdpLoopbackDatapath>, index: usize) {
    let call_id = format!("soak-floor-{index}");
    let profile = || ProfileFlags {
        floor_fmtp: Some("mc_queueing;mc_priority=5;mc_granted".to_string()),
        ..ProfileFlags::default()
    };
    let with_floor = |host: &str, port: u16, floor_port: u16| {
        format!(
            "{}m=application {floor_port} udp MCPTT\r\na=fmtp:MCPTT mc_queueing\r\n",
            sdp_for(host, port)
        )
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                sdp: with_floor("198.51.100.1", 40_000, 40_010),
                profile: profile(),
            },
        )
        .await;
    assert_ok(&offer, "floor offer");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: with_floor("203.0.113.1", 41_000, 41_010),
                profile: profile(),
            },
        )
        .await;
    assert_ok(&answer, "floor answer");
    assert!(
        engine.media().rtcp_relays().has_call(&call_id),
        "the floor call installed its RTCP relay"
    );
    let delete = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id,
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert_ok(&delete, "floor delete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn floor_call_rtcp_relay_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    let mut gate = LeakGate::new("floor call rtcp relay", 100, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            floor_call_offer_answer_delete(&engine, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        assert_eq!(
            engine.media().rtcp_relays().call_count(),
            0,
            "every RTCP relay went with its call"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// A keyed floor call (3GPP TS 33.180 §9.4) churned through `offer → answer → checkpoint → delete →
/// restore → delete`: the HA path that re-binds the floor ports, rebuilds the call-floor legs with
/// their keys, latch and index, and re-registers the RTCP relay. Every one of them has to leave
/// with the call.
async fn floor_call_checkpoint_restore_delete(engine: &Engine<UdpLoopbackDatapath>, index: usize) {
    let call_id = format!("soak-floor-ha-{index}");
    let profile = |mki: u32| ProfileFlags {
        floor_fmtp: Some("mc_queueing;mc_priority=5;mc_granted".to_string()),
        floor_keys: vec![FloorKey {
            mki,
            key: vec![0x31; 16],
            salt: vec![0x6B; 12],
        }],
        ..ProfileFlags::default()
    };
    let with_floor = |host: &str, port: u16, floor_port: u16| {
        format!(
            "{}m=application {floor_port} udp MCPTT\r\na=fmtp:MCPTT mc_queueing\r\n",
            sdp_for(host, port)
        )
    };
    let delete = |call_id: String| Command::Delete {
        call_id,
        from_tag: "tag-a".into(),
        to_tag: None,
    };
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    sdp: with_floor("198.51.100.1", 40_000, 40_010),
                    profile: profile(1),
                },
            )
            .await,
        "keyed floor offer",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: with_floor("203.0.113.1", 41_000, 41_010),
                    profile: profile(2),
                },
            )
            .await,
        "keyed floor answer",
    );
    let CmdResult::Checkpoint { snapshot } = engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
            },
        )
        .await
    else {
        panic!("a floor call checkpoints");
    };
    assert_ok(
        &engine.handle(CLIENT, delete(call_id.clone())).await,
        "floor delete before restore",
    );
    assert_ok(
        &engine.handle(CLIENT, Command::Restore { snapshot }).await,
        "floor restore",
    );
    assert!(
        engine.media().rtcp_relays().has_call(&call_id),
        "the restored floor call has its RTCP relay"
    );
    assert_eq!(
        engine.conference().floors().leg_count(),
        2,
        "both floor legs were restored"
    );
    assert_ok(
        &engine.handle(CLIENT, delete(call_id)).await,
        "restored floor delete",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn floor_call_checkpoint_restore_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    let mut gate = LeakGate::new("floor call checkpoint restore", 100, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            floor_call_checkpoint_restore_delete(&engine, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        assert_eq!(
            engine.media().rtcp_relays().call_count(),
            0,
            "every RTCP relay went with its call"
        );
        assert_eq!(
            engine.conference().floors().leg_count(),
            0,
            "every floor leg went with its call"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// Churn one **transcoding** call through `offer → answer → delete`. A transcode call is heavier
/// than a relay in exactly the way a leak likes: it builds a per-direction codec pair and a media
/// actor on top of the endpoints a relay allocates, and a G.729 codec carries far more state than a
/// G.711 one (excitation history, three predictor memories, the voice-activity background estimate).
#[cfg(feature = "g729")]
async fn g729_transcode_offer_answer_delete(engine: &Engine<UdpLoopbackDatapath>, index: usize) {
    let call_id = format!("soak-g729-{index}");
    let g729_sdp =
        "v=0\r\no=- 1 1 IN IP4 198.51.100.1\r\ns=-\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n\
         m=audio 40000 RTP/AVP 18\r\na=rtpmap:18 G729/8000\r\n"
            .to_owned();

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                sdp: g729_sdp,
                profile: siphon_rtp_proto::ProfileFlags {
                    flags: vec!["codec-transcode-PCMA".into()],
                    ..Default::default()
                },
            },
        )
        .await;
    assert_ok(&offer, "g729 offer");

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for("203.0.113.1", 41_000),
                profile: Default::default(),
            },
        )
        .await;
    assert_ok(&answer, "g729 answer");

    let delete = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id,
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert_ok(&delete, "g729 delete");
}

#[cfg(feature = "g729")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g729_transcode_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    // Fewer cycles per segment than the relay soak: each one builds two codecs and a media actor,
    // so the same number of segments covers the same ground in less wall clock.
    let mut gate = LeakGate::new("g729 transcode", 40, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            g729_transcode_offer_answer_delete(&engine, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// Churn one conference room through `join ×3 → leave ×3` — the room actor spawns on the first join
/// and is torn down (task aborted, endpoint freed) on the last leave.
async fn conference_join_leave(engine: &Engine<UdpLoopbackDatapath>, index: usize) {
    let conference_id = format!("soak-room-{index}");
    for participant in 0..3 {
        let join = engine
            .handle(
                CLIENT,
                Command::ConferenceJoin {
                    conference_id: conference_id.clone(),
                    from_tag: format!("p{participant}"),
                    sdp: sdp_for("198.51.100.1", 40_000 + participant as u16),
                    role: ConferenceRole::Talker,
                    profile: Default::default(),
                },
            )
            .await;
        assert_ok(&join, "conference_join");
    }
    for participant in 0..3 {
        let leave = engine
            .handle(
                CLIENT,
                Command::ConferenceLeave {
                    conference_id: conference_id.clone(),
                    from_tag: format!("p{participant}"),
                },
            )
            .await;
        assert_ok(&leave, "conference_leave");
    }
}

/// Churn one forwarding room through `join ×3 → set_source → set_source(None) → leave ×3` (the last
/// leave ends the room actor and frees its endpoints), with the seat codec negotiated from an AMR-WB
/// offer the build cannot transcode.
async fn forward_join_leave(engine: &Engine<UdpLoopbackDatapath>, index: usize) {
    let conference_id = format!("soak-forward-{index}");
    let amr_wb_sdp = |port: u16| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 198.51.100.1\r\ns=-\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n"
        )
    };
    for participant in 0..3 {
        let join = engine
            .handle(
                CLIENT,
                Command::ForwardJoin {
                    media: siphon_rtp_proto::ForwardMedia::Translate,
                    conference_id: conference_id.clone(),
                    from_tag: format!("p{participant}"),
                    sdp: amr_wb_sdp(40_000 + participant as u16),
                    profile: Default::default(),
                },
            )
            .await;
        assert_ok(&join, "forward_join");
    }
    for source in [Some("p1".to_string()), None] {
        let chosen = engine
            .handle(
                CLIENT,
                Command::ForwardSetSource {
                    conference_id: conference_id.clone(),
                    from_tag: source,
                },
            )
            .await;
        assert_ok(&chosen, "forward_set_source");
    }
    for participant in 0..3 {
        let leave = engine
            .handle(
                CLIENT,
                Command::ForwardLeave {
                    conference_id: conference_id.clone(),
                    from_tag: format!("p{participant}"),
                },
            )
            .await;
        assert_ok(&leave, "forward_leave");
    }
}

/// Churn the conference dial-out verbs through every way an offered seat ends: answered and seated
/// beside a joined participant, bridged to a second room and unbridged, then left; left while still
/// pending; and refused on its answer. The pending-seat store, the bridge records and the rooms must
/// all drain to nothing.
async fn conference_dial_out(engine: &Engine<UdpLoopbackDatapath>, index: usize) {
    let room = format!("soak-dial-{index}");
    let other_room = format!("soak-dial-other-{index}");
    let offer = |conference_id: &str, from_tag: &str| Command::ConferenceOffer {
        conference_id: conference_id.to_string(),
        from_tag: from_tag.to_string(),
        role: ConferenceRole::Talker,
        profile: Default::default(),
    };
    let leave = |conference_id: &str, from_tag: &str| Command::ConferenceLeave {
        conference_id: conference_id.to_string(),
        from_tag: from_tag.to_string(),
    };
    for (conference_id, tag, port) in [(&room, "joined", 41_000), (&other_room, "other", 41_001)] {
        let join = engine
            .handle(
                CLIENT,
                Command::ConferenceJoin {
                    conference_id: conference_id.clone(),
                    from_tag: tag.into(),
                    sdp: sdp_for("198.51.100.1", port),
                    role: ConferenceRole::Talker,
                    profile: Default::default(),
                },
            )
            .await;
        assert_ok(&join, "conference_join");
    }
    assert_ok(
        &engine.handle(CLIENT, offer(&room, "dialled")).await,
        "conference_offer",
    );
    let answer = engine
        .handle(
            CLIENT,
            Command::ConferenceAnswer {
                conference_id: room.clone(),
                from_tag: "dialled".into(),
                sdp: sdp_for("198.51.100.2", 41_002),
                received_from: None,
            },
        )
        .await;
    assert_ok(&answer, "conference_answer");
    let bridge = engine
        .handle(
            CLIENT,
            Command::ConferenceBridge {
                conference_id_a: room.clone(),
                conference_id_b: other_room.clone(),
                direction: Default::default(),
            },
        )
        .await;
    assert_ok(&bridge, "conference_bridge");
    let unbridge = engine
        .handle(
            CLIENT,
            Command::ConferenceUnbridge {
                conference_id_a: other_room.clone(),
                conference_id_b: room.clone(),
            },
        )
        .await;
    assert_ok(&unbridge, "conference_unbridge");

    assert_ok(
        &engine.handle(CLIENT, offer(&room, "pending")).await,
        "conference_offer",
    );
    assert_ok(
        &engine.handle(CLIENT, leave(&room, "pending")).await,
        "leave pending",
    );
    assert_ok(
        &engine.handle(CLIENT, offer(&room, "refused")).await,
        "conference_offer",
    );
    let refused = engine
        .handle(
            CLIENT,
            Command::ConferenceAnswer {
                conference_id: room.clone(),
                from_tag: "refused".into(),
                sdp: "not sdp".into(),
                received_from: None,
            },
        )
        .await;
    assert!(matches!(refused, CmdResult::Error { .. }), "{refused:?}");

    for (conference_id, tag) in [
        (&room, "joined"),
        (&room, "dialled"),
        (&other_room, "other"),
    ] {
        assert_ok(
            &engine.handle(CLIENT, leave(conference_id, tag)).await,
            "conference_leave",
        );
    }
}

/// Churn one relay through `offer → answer → start recording → stop recording → delete`. Each cycle
/// promotes the passthrough relay to a userspace media actor (spawning the pcap drain task), then
/// demotes it back on stop and tears the whole call down on delete — so the promotion reason set, the
/// capture channel, and the drain task must all drain to nothing.
async fn record_start_stop(engine: &Engine<UdpLoopbackDatapath>, dir: &str, index: usize) {
    let call_id = format!("soak-rec-{index}");
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                sdp: sdp_for("198.51.100.1", 40_000),
                profile: Default::default(),
            },
        )
        .await;
    assert_ok(&offer, "offer");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for("203.0.113.1", 41_000),
                profile: Default::default(),
            },
        )
        .await;
    assert_ok(&answer, "answer");
    let start = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                recording_dir: Some(dir.to_string()),
                format: None,
                direction: None,
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: None,
                bitrate_bps: None,
            },
        )
        .await;
    assert_ok(&start, "start recording");
    let stop = engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                recording_id: None,
            },
        )
        .await;
    assert_ok(&stop, "stop recording");
    let delete = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id,
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert_ok(&delete, "delete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn record_start_stop_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_string_lossy().into_owned();
    let engine = Engine::new(UdpLoopbackDatapath::new());

    // Each cycle promotes a relay (spawning a drain task) and demotes + deletes it. Once live bytes
    // settle they must stay settled — no stranded promoted actor, capture channel, or drain task.
    let mut gate = LeakGate::new("recording", 100, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            record_start_stop(&engine, &path, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// One `record_call` call: answered with the profile flag (two streamed recordings, one per party),
/// renegotiated (which pins, re-installs and re-taps both), then deleted. Nothing is sent, so each
/// stream ends as `no_audio` and removes its own file — the directory must stay empty too.
async fn record_call_cycle(engine: &Engine<UdpLoopbackDatapath>, dir: &str, index: usize) {
    let call_id = format!("soak-record-call-{index}");
    let offer = |sdp: String| Command::Offer {
        call_id: call_id.clone(),
        from_tag: "tag-a".into(),
        sdp,
        profile: Default::default(),
    };
    let answer = |profile: ProfileFlags| Command::Answer {
        call_id: call_id.clone(),
        from_tag: "tag-a".into(),
        to_tag: "tag-b".into(),
        sdp: sdp_for("203.0.113.1", 41_000),
        profile,
    };
    assert_ok(
        &engine
            .handle(CLIENT, offer(sdp_for("198.51.100.1", 40_000)))
            .await,
        "offer",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                answer(ProfileFlags {
                    record_call: true,
                    record_path: Some(dir.to_string()),
                    ..Default::default()
                }),
            )
            .await,
        "answer",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Reoffer {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for("198.51.100.1", 40_000),
                    profile: Default::default(),
                },
            )
            .await,
        "re-offer",
    );
    assert_ok(
        &engine.handle(CLIENT, answer(Default::default())).await,
        "re-answer",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await,
        "delete",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn record_call_streams_do_not_leak() {
    let _serialized = SOAK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_string_lossy().into_owned();
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let mut gate = LeakGate::new("record_call", 100, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            record_call_cycle(&engine, &path, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        assert_eq!(
            engine.recording_count(),
            0,
            "every record_call stream finished with its call"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
    let left: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read dir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect();
    assert!(
        left.is_empty(),
        "no file outlives a stream with no audio: {left:?}"
    );
}

/// One overlay-playback cycle on a fresh call: promote by starting four tone overlays (the slot
/// cap), retune one, stop one by id, then delete the call with the rest still running — so the
/// teardown path is what frees them, which is where a stranded `Playback` (its resampler, re-framer
/// and scratch buffers) would show up.
async fn overlay_play_cycle(engine: &Engine<UdpLoopbackDatapath>, index: usize) {
    use siphon_rtp_proto::PlayMediaSource;
    let call_id = format!("overlay-soak-{index}");

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                sdp: sdp_for("198.51.100.1", 40_000),
                profile: Default::default(),
            },
        )
        .await;
    assert_ok(&offer, "offer");

    let mut play_ids = Vec::new();
    for slot in 0..4u8 {
        let started = engine
            .handle(
                CLIENT,
                Command::PlayMedia {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    source: PlayMediaSource::Tone {
                        // Alternate a preset and an explicitly-parsed cadence, so both paths churn.
                        tone: if slot % 2 == 0 {
                            "ringback_eu".into()
                        } else {
                            "440+480/500,0/500*inf".into()
                        },
                    },
                    repeat_times: None,
                    start_pos_ms: None,
                    duration_ms: None,
                    overlay: true,
                    gain_decibels: Some(-6),
                    to_tag: None,
                },
            )
            .await;
        match started {
            CmdResult::Ok {
                play_id: Some(id), ..
            } => play_ids.push(id),
            other => panic!("overlay {slot} should start, got {other:?}"),
        }
    }

    let retuned = engine
        .handle(
            CLIENT,
            Command::SetPlayGain {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                play_id: play_ids[0],
                gain_decibels: -20,
                to_tag: None,
            },
        )
        .await;
    assert_ok(&retuned, "set_play_gain");

    let stopped = engine
        .handle(
            CLIENT,
            Command::StopMedia {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                play_id: Some(play_ids[1]),
            },
        )
        .await;
    assert_ok(&stopped, "targeted stop");

    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id,
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert_ok(&deleted, "delete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlay_playback_start_stop_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    // Each cycle promotes a relay, fills all four overlay slots (each with its own tone generator,
    // re-framer and mix scratch), retunes one, stops one, and tears the call down with two still
    // running. Once live bytes settle they must stay settled.
    let mut gate = LeakGate::new("overlay playback", 100, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            overlay_play_cycle(&engine, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conference_join_leave_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    // Each cycle spawns a room actor + 3 participant legs/endpoints and frees them all on leave.
    let mut gate = LeakGate::new("conferences", 100, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            conference_join_leave(&engine, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.conference().room_count(),
            0,
            "rooms drained after every segment"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_join_leave_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    // Each cycle spawns a forwarding room actor and three seats (a translator and an endpoint each)
    // and frees them all on leave.
    let mut gate = LeakGate::new("forwarding rooms", 100, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            forward_join_leave(&engine, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.conference().forward().room_count(),
            0,
            "forwarding rooms drained after every segment"
        );
        assert_eq!(
            engine.conference().forward().seat_count(),
            0,
            "forwarding seats drained"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conference_dial_out_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    let mut gate = LeakGate::new("conference dial-out", 60, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            conference_dial_out(&engine, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(engine.pending_seat_count(), 0, "pending seats drained");
        assert_eq!(engine.conference().room_count(), 0, "rooms drained");
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// Churn a live call's leg through `conference_seat` and out again in every order the verbs allow —
/// `seat → delete`, `seat → leave → delete`, `seat → leave → seat → delete` — with a joined
/// participant leaving the room before or after the call, so the room is torn down by either side.
/// Each cycle moves a leg into a room and frees its peer leg, then frees the leg and the room.
async fn conference_seat_leave_delete(
    engine: &Engine<UdpLoopbackDatapath>,
    index: usize,
    recordings: &std::path::Path,
) {
    let call_id = format!("seat-soak-{index}");
    let room = format!("seat-soak-room-{index}");
    let seat = || Command::ConferenceSeat {
        call_id: call_id.clone(),
        from_tag: "tag-b".into(),
        conference_id: room.clone(),
        role: ConferenceRole::Talker,
    };
    let leave = |tag: &str| Command::ConferenceLeave {
        conference_id: room.clone(),
        from_tag: tag.into(),
    };
    for (command, what) in [
        (
            Command::Offer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                sdp: sdp_for("198.51.100.1", 40_000),
                profile: Default::default(),
            },
            "offer",
        ),
        (
            Command::Answer {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for("203.0.113.1", 41_000),
                profile: Default::default(),
            },
            "answer",
        ),
        (
            Command::ConferenceJoin {
                conference_id: room.clone(),
                from_tag: "joined".into(),
                sdp: sdp_for("203.0.113.2", 42_000),
                role: ConferenceRole::Talker,
                profile: Default::default(),
            },
            "conference_join",
        ),
    ] {
        assert_ok(&engine.handle(CLIENT, command).await, what);
    }
    // A decoded recording runs across the seat, the leave and the re-seat on two cycles in three,
    // alternating WAV and Ogg Opus, and ends with the call.
    let format = match index % 3 {
        0 => Some(siphon_rtp_proto::RecordingFormat::Wav),
        1 => Some(siphon_rtp_proto::RecordingFormat::OggOpus),
        _ => None,
    };
    if let Some(format) = format {
        assert_ok(
            &engine
                .handle(
                    CLIENT,
                    Command::StartRecording {
                        call_id: call_id.clone(),
                        from_tag: "tag-a".into(),
                        recording_dir: Some(recordings.to_string_lossy().into_owned()),
                        format: Some(format),
                        direction: Some(siphon_rtp_proto::RecordingDirection::Both),
                        channels: Some(siphon_rtp_proto::RecordingChannels::Stereo),
                        max_duration_ms: None,
                        silence_ms: None,
                        path: None,
                        bitrate_bps: None,
                    },
                )
                .await,
            "start_recording",
        );
    }
    let mut steps = vec![(seat(), "conference_seat")];
    match index % 3 {
        0 => {}
        1 => steps.push((leave("tag-b"), "conference_leave (seated call leg)")),
        _ => {
            steps.push((leave("tag-b"), "conference_leave (seated call leg)"));
            steps.push((seat(), "conference_seat (again)"));
        }
    }
    // The joined participant leaves before the call ends on even cycles, after it on odd ones.
    let joiner_first = index.is_multiple_of(2);
    if joiner_first {
        steps.push((leave("joined"), "conference_leave (joined)"));
    }
    steps.push((
        Command::Delete {
            call_id: call_id.clone(),
            from_tag: "tag-b".into(),
            to_tag: None,
        },
        "delete (seated call)",
    ));
    if !joiner_first {
        steps.push((leave("joined"), "conference_leave (joined)"));
    }
    for (command, what) in steps {
        assert_ok(&engine.handle(CLIENT, command).await, what);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conference_seat_leave_delete_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    // Six cycles cover every seat/leave/delete order against both room-teardown orders.
    let recordings = tempfile::tempdir().expect("recording directory");
    let mut gate = LeakGate::new("conference seat", 120, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            conference_seat_leave_delete(&engine, index, recordings.path()).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(engine.session_count(), 0, "calls drained");
        assert_eq!(engine.recording_count(), 0, "recordings drained");
        assert_eq!(engine.conference().room_count(), 0, "rooms drained");
        assert_eq!(engine.conference().participant_count(), 0, "seats drained");
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// A local WebSocket server that accepts connection after connection and drains every frame — the
/// consumer side of the tee soak. Returns its `ws://` URI; the task lives for the test.
async fn tee_sink_server() -> (String, Arc<AtomicUsize>) {
    use futures_util::StreamExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tee ws");
    let addr = listener.local_addr().expect("tee ws addr");
    // Connections currently being served. Each cycle of the soak dials a real TCP + WebSocket
    // connection, and the task serving it exits *asynchronously* after the engine drops its end — so
    // without waiting for this to drain, `allocated` is sampled while an unknown number of the
    // harness's own server tasks and socket buffers are still alive. That made the soak read its own
    // teardown as an engine leak (flaky, and the drift varied by ~2x run to run, which is the
    // signature of a race rather than a real per-cycle leak).
    let live = Arc::new(AtomicUsize::new(0));
    let accept_live = live.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let live = accept_live.clone();
            live.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if let Ok(socket) = tokio_tungstenite::accept_async(stream).await {
                    let (_sink, mut source) = socket.split();
                    while let Some(Ok(_frame)) = source.next().await {}
                }
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (format!("ws://{addr}/tee"), live)
}

/// Wait until the tee server has finished tearing down every connection it accepted, so a following
/// `allocated` sample measures the engine and not the harness. Bounded, so a genuine hang fails the
/// test on its assertion rather than spinning forever.
async fn drain_tee_server(live: &Arc<AtomicUsize>) {
    for _ in 0..2_000 {
        if live.load(Ordering::SeqCst) == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    quiesce().await;
}

/// One tee churn cycle: offer → answer → attach a WS tee (which promotes the relay into the userspace
/// media pipeline and dials the server) → detach (demoting it again) → delete.
async fn ws_tee_attach_detach(engine: &Engine<UdpLoopbackDatapath>, uri: &str, index: usize) {
    let call_id = format!("tee-soak-{index}");
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for("198.51.100.1", 40_000),
                    profile: Default::default(),
                },
            )
            .await,
        "offer",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for("203.0.113.1", 41_000),
                    profile: Default::default(),
                },
            )
            .await,
        "answer",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::AttachWsTee {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    ws_uri: uri.to_string(),
                    direction: WsTeeDirection::Both,
                    channels: Some(2),
                    sample_rate: None,
                },
            )
            .await,
        "attach_ws_tee",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::DetachWsTee {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                },
            )
            .await,
        "detach_ws_tee",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id,
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await,
        "delete",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_tee_attach_detach_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let (uri, live) = tee_sink_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    // Each cycle dials a WebSocket, promotes a relay into a processing media actor with two tee
    // sinks, then detaches and demotes it — no stranded mixer, sink, transport task or promoted
    // actor. Every cycle burns a real TCP connection, so this one gets a shorter settle budget than
    // the socket-free soaks: a build that never converges should fail on the assertion rather than
    // churn its way through the ephemeral-port range first.
    let mut gate = LeakGate::new("ws tee", 100, 40).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            ws_tee_attach_detach(&engine, &uri, index).await;
            index += 1;
        }
        drain_tee_server(&live).await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        assert_eq!(
            engine.ws_tee_count(),
            0,
            "tee registry drained after every segment"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// One takeover-bridge churn cycle: offer → answer → attach a bridge to the live relay (which
/// displaces its `Forward` rules, dials a WS server and spawns the bridge + drain tasks) → re-point
/// it at a second connection → detach (reinstalling the relay) → delete.
///
/// Two dialled WebSockets per cycle, and the re-point in the middle is the interesting one: it tears
/// a bridge down and stands another up on the *same* leg, reusing the egress watch and the source
/// gate. That is exactly where a stranded bridge task, drain task, socket or `WsBridge` record would
/// accumulate without the call ever ending.
async fn ws_bridge_attach_repoint_detach(
    engine: &Engine<UdpLoopbackDatapath>,
    uri: &str,
    index: usize,
) {
    let call_id = format!("ws-bridge-soak-{index}");
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for("198.51.100.1", 40_000),
                    profile: Default::default(),
                },
            )
            .await,
        "offer",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for("203.0.113.1", 41_000),
                    profile: Default::default(),
                },
            )
            .await,
        "answer",
    );
    for what in ["attach_ws_bridge", "re-point"] {
        assert_ok(
            &engine
                .handle(
                    CLIENT,
                    Command::AttachWsBridge {
                        call_id: call_id.clone(),
                        from_tag: "tag-a".into(),
                        ws_uri: uri.to_string(),
                        profile: None,
                    },
                )
                .await,
            what,
        );
    }
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::DetachWsBridge {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                },
            )
            .await,
        "detach_ws_bridge",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id,
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await,
        "delete",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_bridge_attach_repoint_detach_does_not_leak() {
    let _serialized = SOAK.lock().await;
    // The takeover bridge speaks the same `ws://` envelope as the tee, so the drain-everything sink
    // server serves both; only the direction differs, and this soak never sends media.
    let (uri, live) = tee_sink_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());

    // Two real TCP connections per cycle (attach + re-point), so this gets the tee soak's shorter
    // settle budget for the same reason: a build that never converges should fail on its assertion
    // rather than churn through the ephemeral-port range first.
    let mut gate = LeakGate::new("ws bridge", 100, 40).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            ws_bridge_attach_repoint_detach(&engine, &uri, index).await;
            index += 1;
        }
        drain_tee_server(&live).await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        assert_eq!(
            engine.ws_bridge_count(),
            0,
            "bridge registry drained after every segment — a re-point must not strand the record it \
             replaced, and a detach must not leave one behind"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// One decoded recording carried across every hand-over a call can make: answered by the engine,
/// recorded, handed to a bot, re-pointed to a second, handed back, stopped, deleted. The recording's
/// sinks move between the pipeline and two bridge sessions without ever being dropped, so this is
/// where a sink stranded on a stopped actor or an aborted bridge would accumulate.
async fn recording_handover_cycle(
    engine: &Engine<UdpLoopbackDatapath>,
    uri: &str,
    dir: &str,
    index: usize,
) {
    let call_id = format!("handover-soak-{index}");
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::AnswerLocal {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for("198.51.100.1", 40_000),
                    profile: Default::default(),
                },
            )
            .await,
        "answer_local",
    );
    let started = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                recording_dir: Some(dir.to_string()),
                format: Some(siphon_rtp_proto::RecordingFormat::Wav),
                direction: Some(siphon_rtp_proto::RecordingDirection::Both),
                channels: Some(siphon_rtp_proto::RecordingChannels::Stereo),
                max_duration_ms: None,
                silence_ms: None,
                path: None,
                bitrate_bps: None,
            },
        )
        .await;
    assert_ok(&started, "start_recording");
    for what in ["attach_ws_bridge", "re-point"] {
        assert_ok(
            &engine
                .handle(
                    CLIENT,
                    Command::AttachWsBridge {
                        call_id: call_id.clone(),
                        from_tag: "tag-a".into(),
                        ws_uri: uri.to_string(),
                        profile: None,
                    },
                )
                .await,
            what,
        );
    }
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::DetachWsBridge {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                },
            )
            .await,
        "detach_ws_bridge",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::StopRecording {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    recording_id: None,
                },
            )
            .await,
        "stop_recording",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id,
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await,
        "delete",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recording_carried_across_hand_overs_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let (uri, live) = tee_sink_server().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_string_lossy().into_owned();
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let mut gate = LeakGate::new("recording hand-over", 100, 40).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            recording_handover_cycle(&engine, &uri, &path, index).await;
            index += 1;
        }
        drain_tee_server(&live).await;
        quiesce().await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        assert_eq!(engine.recording_count(), 0, "every recording finished");
        assert_eq!(engine.ws_bridge_count(), 0, "no bridge left behind");
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// Stand up a plain caller toward an SDES callee on a shared codec: the SRTP crypto bridge.
async fn secure_bridge_call(engine: &Engine<UdpLoopbackDatapath>, call_id: &str) {
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: call_id.to_string(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for("198.51.100.1", 40_000),
                    profile: siphon_rtp_proto::ProfileFlags {
                        transport_protocol: Some("RTP/SAVP".into()),
                        ..Default::default()
                    },
                },
            )
            .await,
        "offer toward a secure callee",
    );
    let key = siphon_rtp_srtp::sdes::CryptoAttribute::generate(
        1,
        siphon_rtp_srtp::sdes::CryptoSuite::AesCm128HmacSha1_80,
    )
    .expect("key");
    let answer = format!(
        "v=0\r\no=- 1 1 IN IP4 203.0.113.1\r\ns=-\r\nc=IN IP4 203.0.113.1\r\nt=0 0\r\n\
         m=audio 41000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\na={}\r\n",
        key.to_attribute_value()
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: call_id.to_string(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: answer,
                    profile: Default::default(),
                },
            )
            .await,
        "secure answer",
    );
}

/// One bridged-tee cycle: a plain caller toward an SDES callee on a shared codec (the SRTP bridge),
/// a tee attached mid-call (a plaintext tap on the bridge plus a decoder task per leg), detached,
/// and the call deleted. The tap, the decoders and the transport must all go with the detach.
async fn bridged_tee_attach_detach(engine: &Engine<UdpLoopbackDatapath>, uri: &str, index: usize) {
    let call_id = format!("bridged-tee-soak-{index}");
    secure_bridge_call(engine, &call_id).await;
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::AttachWsTee {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    ws_uri: uri.to_string(),
                    direction: WsTeeDirection::Both,
                    channels: Some(2),
                    sample_rate: None,
                },
            )
            .await,
        "tee the bridge",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::DetachWsTee {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                },
            )
            .await,
        "detach the tee",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id,
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await,
        "delete",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridged_tee_attach_detach_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let (uri, live) = tee_sink_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let mut gate = LeakGate::new("bridged tee", 100, 40).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            bridged_tee_attach_detach(&engine, &uri, index).await;
            index += 1;
        }
        drain_tee_server(&live).await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        assert_eq!(engine.ws_tee_count(), 0, "no tee outlives its detach");
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// One bridged-recording cycle: a decoded recording started on the SRTP bridge (a plaintext tap
/// plus a decoder task per party, and the file writer), stopped, and the call deleted. The taps, the
/// decoders and the writer must all go with the stop.
async fn bridged_recording_start_stop(
    engine: &Engine<UdpLoopbackDatapath>,
    format: siphon_rtp_proto::RecordingFormat,
    path: &str,
    index: usize,
) {
    let call_id = format!("bridged-recording-soak-{index}");
    secure_bridge_call(engine, &call_id).await;
    let started = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: call_id.clone(),
                from_tag: "tag-a".into(),
                recording_dir: None,
                format: Some(format),
                direction: None,
                channels: Some(siphon_rtp_proto::RecordingChannels::Stereo),
                max_duration_ms: None,
                silence_ms: None,
                path: Some(path.to_string()),
                bitrate_bps: None,
            },
        )
        .await;
    assert_ok(&started, "record the bridge");
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::StopRecording {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    recording_id: None,
                },
            )
            .await,
        "stop the recording",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id,
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await,
        "delete",
    );
}

/// Churn decoded recordings in `format` on SRTP bridges until the leak gate is satisfied.
async fn soak_bridged_recordings(
    name: &'static str,
    format: siphon_rtp_proto::RecordingFormat,
    file: &str,
) {
    let _serialized = SOAK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    // One file, rewritten every cycle, so the soak measures the engine and not the directory.
    let path = dir.path().join(file).to_string_lossy().into_owned();
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let mut gate = LeakGate::new(name, 100, 40).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            bridged_recording_start_stop(&engine, format, &path, index).await;
            index += 1;
        }
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridged_recording_start_stop_does_not_leak() {
    soak_bridged_recordings(
        "bridged recording",
        siphon_rtp_proto::RecordingFormat::Wav,
        "soak.wav",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridged_ogg_opus_recording_start_stop_does_not_leak() {
    // The Ogg Opus writer owns an encoder, a staging frame and a page buffer per recording; all of
    // it must go with the writer task.
    soak_bridged_recordings(
        "bridged ogg_opus recording",
        siphon_rtp_proto::RecordingFormat::OggOpus,
        "soak.opus",
    )
    .await;
}

/// One detach-to-anchor cycle: `answer_local` with `ws_uri` (a bot answers), `detach_ws_bridge`
/// (the bridge stops and the leg is promoted onto the engine's own pipeline, with a media actor),
/// then `delete`. Every stage owns different state — the WS route and its two tasks, then the
/// media actor — and each hand-over has to release what the previous one held.
async fn ws_takeover_detach_to_anchor(
    engine: &Engine<UdpLoopbackDatapath>,
    uri: &str,
    index: usize,
) {
    let call_id = format!("ws-anchor-soak-{index}");
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::AnswerLocal {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for("198.51.100.1", 40_000),
                    profile: siphon_rtp_proto::ProfileFlags {
                        ws_uri: Some(uri.to_string()),
                        ..Default::default()
                    },
                },
            )
            .await,
        "answer_local with a bot",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::DetachWsBridge {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                },
            )
            .await,
        "detach to the anchor",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id,
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await,
        "delete",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_takeover_detach_to_anchor_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let (uri, live) = tee_sink_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let mut gate = LeakGate::new("ws detach to anchor", 100, 40).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            ws_takeover_detach_to_anchor(&engine, &uri, index).await;
            index += 1;
        }
        drain_tee_server(&live).await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        assert_eq!(
            engine.ws_bridge_count(),
            0,
            "no bridge record outlives its detach"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// One anchor round trip: `answer_local` (the engine's own pipeline), `attach_ws_bridge` (the
/// pipeline stops and a bot takes the leg), `detach_ws_bridge` (back to a pipeline), `delete`.
async fn anchor_attach_detach(engine: &Engine<UdpLoopbackDatapath>, uri: &str, index: usize) {
    let call_id = format!("anchor-bot-soak-{index}");
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::AnswerLocal {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for("198.51.100.1", 40_000),
                    profile: siphon_rtp_proto::ProfileFlags::default(),
                },
            )
            .await,
        "answer_local",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::AttachWsBridge {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    ws_uri: uri.to_string(),
                    profile: None,
                },
            )
            .await,
        "attach a bot to the anchor",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::DetachWsBridge {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                },
            )
            .await,
        "detach back to the anchor",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id,
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await,
        "delete",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchor_attach_detach_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let (uri, live) = tee_sink_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let mut gate = LeakGate::new("anchor attach/detach", 100, 40).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            anchor_attach_detach(&engine, &uri, index).await;
            index += 1;
        }
        drain_tee_server(&live).await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        assert_eq!(
            engine.ws_bridge_count(),
            0,
            "no bridge record outlives its detach"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// A DTLS-SRTP offerer's SDP (RFC 5764 / RFC 5763 §5). Documentation-range address (RFC 5737).
fn dtls_offerer_sdp(host: &str, port: u16, fingerprint: &siphon_rtp_dtls::Fingerprint) -> String {
    let hex = fingerprint
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    format!(
        "v=0\r\no=- 1 1 IN IP4 {host}\r\ns=-\r\nc=IN IP4 {host}\r\nt=0 0\r\n\
         m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
         a=setup:active\r\na=fingerprint:{hash} {hex}\r\n",
        hash = fingerprint.hash_function,
    )
}

/// One secure-takeover churn cycle: `answer_local` on a DTLS-SRTP offerer with `ws_uri` (which dials
/// the WS server, registers the takeover route with its pending `WsSecureLeg`, and spawns the DTLS
/// handshake + record-drain tasks against a peer that never answers) → `delete`.
///
/// The handshake deliberately never completes, so this is the worst case for the teardown path: every
/// cycle strands a waiting handshake task, a record drain, a WS bridge task and a downlink drain that
/// `delete` has to abort.
async fn secure_ws_takeover_answer_delete(
    engine: &Engine<UdpLoopbackDatapath>,
    uri: &str,
    fingerprint: &siphon_rtp_dtls::Fingerprint,
    index: usize,
) {
    let call_id = format!("secure-takeover-soak-{index}");
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::AnswerLocal {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    sdp: dtls_offerer_sdp("198.51.100.1", 40_000, fingerprint),
                    profile: siphon_rtp_proto::ProfileFlags {
                        ws_uri: Some(uri.to_string()),
                        ..Default::default()
                    },
                },
            )
            .await,
        "answer_local secure takeover",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id,
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await,
        "delete",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secure_ws_takeover_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let (uri, live) = tee_sink_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let certificate = siphon_rtp_dtls::DtlsCertificate::generate().expect("peer cert");
    let fingerprint = certificate.fingerprint();

    // Same reasoning (and segment size) as the tee soak — this cycle also dials a real connection,
    // and spawns four tasks per call that `delete` has to abort.
    let mut gate = LeakGate::new("secure ws takeover", 100, 40).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            secure_ws_takeover_answer_delete(&engine, &uri, &fingerprint, index).await;
            index += 1;
        }
        drain_tee_server(&live).await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}

/// One terminated DTLS-SRTP offerer churn cycle: `offer` from a WebRTC-shaped caller asking for a
/// plain far leg (the caller's keying is kept on the call) → a plain `answer` from a callee that keeps
/// RTCP on its own port (which registers the DTLS bridge, spawning its handshake and record-drain
/// tasks against a caller that never answers) → `delete`, which has to abort both tasks and free
/// every port.
///
/// The caller offers `a=setup:active`, so the engine waits as the DTLS server and sends nothing
/// toward the documentation address the caller signals.
async fn dtls_offerer_offer_answer_delete(
    engine: &Engine<UdpLoopbackDatapath>,
    fingerprint: &siphon_rtp_dtls::Fingerprint,
    index: usize,
) {
    let call_id = format!("dtls-offerer-soak-{index}");
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    sdp: dtls_offerer_sdp("198.51.100.1", 40_000, fingerprint),
                    profile: siphon_rtp_proto::ProfileFlags {
                        transport_protocol: Some("RTP/AVP".into()),
                        ..Default::default()
                    },
                },
            )
            .await,
        "offer from a DTLS-SRTP caller toward a plain callee",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: sdp_for("203.0.113.1", 41_000),
                    profile: Default::default(),
                },
            )
            .await,
        "plain answer",
    );
    assert_ok(
        &engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id,
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await,
        "delete",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dtls_offerer_relay_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let certificate = siphon_rtp_dtls::DtlsCertificate::generate().expect("caller cert");
    let fingerprint = certificate.fingerprint();

    // On top of a relay's endpoints and registry entry, each call registers a DTLS bridge whose two
    // tasks `delete` has to abort. Same segment size as the plain relay.
    let mut gate = LeakGate::new("dtls offerer relay", 100, 50).await;
    let mut index = 0;
    while gate.needs_more_churn() {
        for _ in 0..gate.cycles_per_segment() {
            dtls_offerer_offer_answer_delete(&engine, &fingerprint, index).await;
            index += 1;
        }
        quiesce().await;
        assert_eq!(
            engine.session_count(),
            0,
            "registry drained after every segment"
        );
        gate.sample().await;
    }
    gate.assert_no_leak();
}
