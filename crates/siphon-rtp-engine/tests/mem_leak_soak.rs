//! Memory-leak soak for the session engine.
//!
//! `cargo test -p siphon-rtp-engine --test mem_leak_soak`
//!
//! Churns `offer → answer → delete` over the NIC-free UDP-loopback datapath and proves the engine
//! gives memory back: the session registry drains to **0** and jemalloc's live `allocated` stays
//! flat across thousands of completed calls. Gate on `allocated` (live bytes), never RSS — jemalloc
//! retains freed pages, so RSS is too noisy to gate on. A rising `allocated` at steady state is a
//! real leak (a stranded `Call`, a recv task whose socket/buffer never freed).

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_engine::{ClientId, Engine};
use siphon_rtp_proto::{CmdResult, Command, ConferenceRole};

/// The soak drives the engine as a single control client.
const CLIENT: ClientId = ClientId(1);

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conference_join_leave_does_not_leak() {
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
