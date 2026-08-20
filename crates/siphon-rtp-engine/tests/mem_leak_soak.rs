//! Memory-leak soak for the session engine.
//!
//! `cargo test -p siphon-rtp-engine --test mem_leak_soak`
//!
//! Churns `offer → answer → delete` over the NIC-free UDP-loopback datapath and proves the engine
//! gives memory back: the session registry drains to **0** and jemalloc's live `allocated` stays
//! flat across thousands of completed calls. Gate on `allocated` (live bytes), never RSS — jemalloc
//! retains freed pages, so RSS is too noisy to gate on. A rising `allocated` at steady state is a
//! real leak (a stranded `Call`, a recv task whose socket/buffer never freed).

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

/// Live bytes currently allocated, per jemalloc. Advancing the epoch refreshes the cached stats.
fn allocated_bytes() -> usize {
    tikv_jemalloc_ctl::epoch::advance().expect("advance jemalloc epoch");
    tikv_jemalloc_ctl::stats::allocated::read().expect("read jemalloc allocated")
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
    let _prime = allocated_bytes();

    // Warm up to steady state (jemalloc arenas, tokio caches, DashMap shards all settled).
    for index in 0..200 {
        offer_answer_delete(&engine, index).await;
    }
    quiesce().await;
    assert_eq!(engine.session_count(), 0, "registry empty after warmup");
    let before = allocated_bytes();

    // Each call allocates four endpoints (2× RTP + 2× RTCP) plus SDP strings and a registry entry,
    // and frees them all on delete. Across 2000 completed calls, live bytes must not climb.
    for index in 200..2_200 {
        offer_answer_delete(&engine, index).await;
    }
    quiesce().await;
    let after = allocated_bytes();

    assert_eq!(engine.session_count(), 0, "registry drained after soak");

    // A small steady-state drift is allowed (lazy arena / thread-cache growth); a real leak over
    // 2000 churned calls would dwarf it.
    let tolerance = 512 * 1024;
    assert!(
        after <= before + tolerance,
        "engine leaked {} bytes over 2000 churned calls (before={before}, after={after})",
        after.saturating_sub(before)
    );
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
    let _prime = allocated_bytes();

    // Warm up: promote/demote paths, the drain task's blocking-pool threads, and jemalloc all settle.
    for index in 0..100 {
        record_start_stop(&engine, &path, index).await;
    }
    quiesce().await;
    assert_eq!(engine.session_count(), 0, "registry empty after warmup");
    let before = allocated_bytes();

    // Each cycle promotes a relay (spawning a drain task) and demotes + deletes it. Across 500 cycles
    // live bytes must not climb — no stranded promoted actor, capture channel, or drain task.
    for index in 100..600 {
        record_start_stop(&engine, &path, index).await;
    }
    quiesce().await;
    let after = allocated_bytes();

    assert_eq!(engine.session_count(), 0, "registry drained after soak");
    let tolerance = 512 * 1024;
    assert!(
        after <= before + tolerance,
        "recording leaked {} bytes over 500 churned record cycles (before={before}, after={after})",
        after.saturating_sub(before)
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
    let _prime = allocated_bytes();

    // Warm up: the promote path, the media actor, its overlay bus and every slot's scratch settle.
    for index in 0..50 {
        overlay_play_cycle(&engine, index).await;
    }
    quiesce().await;
    assert_eq!(engine.session_count(), 0, "registry empty after warmup");
    let before = allocated_bytes();

    // Each cycle promotes a relay, fills all four overlay slots (each with its own tone generator,
    // re-framer and mix scratch), retunes one, stops one, and tears the call down with two still
    // running. Across 300 cycles live bytes must not climb.
    for index in 50..350 {
        overlay_play_cycle(&engine, index).await;
    }
    quiesce().await;
    let after = allocated_bytes();

    assert_eq!(engine.session_count(), 0, "registry drained after soak");
    let tolerance = 512 * 1024;
    assert!(
        after <= before + tolerance,
        "overlay playback leaked {} bytes over 300 churned calls (before={before}, after={after})",
        after.saturating_sub(before)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conference_join_leave_does_not_leak() {
    let _serialized = SOAK.lock().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let _prime = allocated_bytes();

    // Warm up: rooms, per-participant mixers/jitter, endpoints all settle into steady state.
    for index in 0..100 {
        conference_join_leave(&engine, index).await;
    }
    quiesce().await;
    assert_eq!(
        engine.conference().room_count(),
        0,
        "rooms drained after warmup"
    );
    let before = allocated_bytes();

    // Each cycle spawns a room actor + 3 participant legs/endpoints and frees them all on leave.
    for index in 100..1_100 {
        conference_join_leave(&engine, index).await;
    }
    quiesce().await;
    let after = allocated_bytes();

    assert_eq!(
        engine.conference().room_count(),
        0,
        "rooms drained after soak"
    );
    let tolerance = 512 * 1024;
    assert!(
        after <= before + tolerance,
        "conferences leaked {} bytes over 1000 churned rooms (before={before}, after={after})",
        after.saturating_sub(before)
    );
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
    let _prime = allocated_bytes();

    // Warm up: the promote/demote paths, the dialled TCP+WebSocket stack, the tee's preallocated
    // buffer pool and jemalloc's arenas all settle into steady state.
    // The longest warmup in this file, because this is by far the heaviest cycle in it: each one
    // dials a TCP + WebSocket connection, promotes a relay into a processing actor with two tee
    // sinks, then detaches and demotes it. That touches many more jemalloc size classes than the
    // other soaks, so the arenas need proportionally longer to reach the steady state `before` is
    // meant to sample — undersized, the measured delta is arena growth rather than engine state.
    for index in 0..200 {
        ws_tee_attach_detach(&engine, &uri, index).await;
    }
    drain_tee_server(&live).await;
    assert_eq!(engine.session_count(), 0, "registry empty after warmup");
    assert_eq!(engine.ws_tee_count(), 0, "no tee retained after warmup");
    let before = allocated_bytes();

    // Each cycle dials a WebSocket, promotes a relay into a processing media actor with two tee sinks,
    // then detaches and demotes it. Across 300 cycles live bytes must not climb — no stranded mixer,
    // sink, transport task or promoted actor.
    for index in 200..500 {
        ws_tee_attach_detach(&engine, &uri, index).await;
    }
    drain_tee_server(&live).await;
    let after = allocated_bytes();

    assert_eq!(engine.session_count(), 0, "registry drained after soak");
    assert_eq!(engine.ws_tee_count(), 0, "tee registry drained after soak");
    let tolerance = 512 * 1024;
    assert!(
        after <= before + tolerance,
        "ws tee leaked {} bytes over 300 churned attach/detach cycles (before={before}, after={after})",
        after.saturating_sub(before)
    );
}
