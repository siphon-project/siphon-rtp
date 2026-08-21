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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_engine::{ClientId, Engine};
use siphon_rtp_proto::{CmdResult, Command, ConferenceRole, WsTeeDirection};

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
