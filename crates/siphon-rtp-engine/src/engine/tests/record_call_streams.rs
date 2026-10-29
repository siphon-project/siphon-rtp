//! The `record_call` profile recording: one streamed file per party, and one `recording_finished`
//! per file, exactly as `start_recording` reports its own.
//!
//! Before this, `record_call` buffered each direction in memory and wrote both files from the media
//! actor's teardown with no event, so a recording server watching the directory could not tell a
//! file still being written from a party that never spoke from a file lost to the teardown grace.

use super::*;
use siphon_rtp_proto::RecordingEndReason;

/// Every `recording_finished` that arrives within `window`, by recording id.
async fn finished_within(
    events: &flume::Receiver<Event>,
    window: Duration,
) -> Vec<(String, Option<String>, u64, RecordingEndReason)> {
    let mut finished = Vec::new();
    let deadline = tokio::time::Instant::now() + window;
    while let Ok(Ok(event)) = tokio::time::timeout_at(deadline, events.recv_async()).await {
        if let Event::RecordingFinished {
            recording_id,
            path,
            duration_ms,
            reason,
            ..
        } = event
        {
            finished.push((recording_id, path, duration_ms, reason));
        }
    }
    finished
}

/// A two-party plain call answered with `record_call` into `directory`, and both phones.
async fn recorded_call(
    call_id: &str,
    directory: &std::path::Path,
) -> (
    Engine<UdpLoopbackDatapath>,
    flume::Receiver<Event>,
    (UdpSocket, SocketAddr),
    (UdpSocket, SocketAddr),
) {
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let engine_far = sdp::parse(&ok_sdp_text(&offered))
        .expect("offer toward B")
        .remote_rtp;
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: ProfileFlags {
                    record_call: true,
                    record_path: Some(directory.to_string_lossy().into_owned()),
                    ..Default::default()
                },
            },
        )
        .await;
    let engine_near = sdp::parse(&ok_sdp_text(&answered))
        .expect("answer toward A")
        .remote_rtp;
    (
        engine,
        events,
        (phone_a, engine_near),
        (phone_b, engine_far),
    )
}

/// Send `frames` 20 ms µ-law frames from `phone` toward `to`, paced roughly in real time.
async fn talk(phone: &UdpSocket, to: SocketAddr, ssrc: u32, first: u16, frames: u16) {
    for sequence in first..first + frames {
        phone
            .send_to(&g711_rtp(0, sequence, ssrc, 0x20), to)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn hang_up(engine: &Engine<UdpLoopbackDatapath>, call_id: &str) {
    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
}

/// Nothing named `*.partial` is left behind in `directory`.
fn no_partial_files(directory: &std::path::Path) -> bool {
    std::fs::read_dir(directory)
        .expect("read directory")
        .filter_map(Result::ok)
        .all(|entry| entry.path().extension().is_none_or(|ext| ext != "partial"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recorded_call_reports_one_finished_file_per_party() {
    let directory = tempfile::tempdir().expect("tempdir");
    let (engine, events, (phone_a, near), (phone_b, far)) =
        recorded_call("rec-both", directory.path()).await;
    talk(&phone_a, near, 0x0A0A_0A0A, 0, 10).await;
    talk(&phone_b, far, 0x0B0B_0B0B, 0, 10).await;
    hang_up(&engine, "rec-both").await;

    let mut finished = finished_within(&events, Duration::from_secs(3)).await;
    finished.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(
        finished.len(),
        2,
        "exactly one event per party, got {finished:?}"
    );
    for ((recording_id, path, duration_ms, reason), (expected_id, file)) in finished.iter().zip([
        ("rec-both-a", "rec-both-a.wav"),
        ("rec-both-b", "rec-both-b.wav"),
    ]) {
        assert_eq!(recording_id, expected_id, "a predictable id per party");
        assert_eq!(*reason, RecordingEndReason::CallEnded);
        assert!(*duration_ms > 0, "{recording_id} carries the party's audio");
        let path = path.as_deref().expect("the event names the file");
        assert_eq!(
            std::path::Path::new(path),
            directory.path().join(file),
            "the file name is unchanged from the buffered recorder's"
        );
        let bytes = std::fs::read(path).expect("the file exists when the event arrives");
        let parsed = siphon_rtp_media::player::WavSource::parse(&bytes)
            .expect("the finished file is a valid WAV");
        assert_eq!(parsed.sample_rate_hz(), 8_000);
        assert_eq!(parsed.channels(), 1, "one party per file, mono");
    }
    assert!(
        no_partial_files(directory.path()),
        "the event is sent only after the rename"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_party_that_never_spoke_reports_no_audio_and_leaves_no_file() {
    let directory = tempfile::tempdir().expect("tempdir");
    let (engine, events, (phone_a, near), _callee) =
        recorded_call("rec-one-way", directory.path()).await;
    talk(&phone_a, near, 0x0A0A_0A0A, 0, 10).await;
    hang_up(&engine, "rec-one-way").await;

    let finished = finished_within(&events, Duration::from_secs(3)).await;
    let callee = finished
        .iter()
        .find(|(recording_id, ..)| recording_id == "rec-one-way-b")
        .expect("the silent party still gets its terminal event");
    assert_eq!(callee.1, None, "no file to name");
    assert_eq!(callee.2, 0);
    assert_eq!(callee.3, RecordingEndReason::NoAudio);
    assert!(
        !directory.path().join("rec-one-way-b.wav").exists(),
        "a party with no audio leaves no file"
    );
    assert!(no_partial_files(directory.path()));
    assert!(
        finished
            .iter()
            .any(|(id, path, _, reason)| id == "rec-one-way-a"
                && path.is_some()
                && *reason == RecordingEndReason::CallEnded),
        "the party that spoke is reported as usual: {finished:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recorded_call_keeps_one_file_per_party_across_a_renegotiation() {
    // A re-offer and its answer re-install the media path. The streams must carry onto it: one file
    // and one event per party for the whole call, not one per media path, and not a file the second
    // half overwrote. The re-answer does not repeat `record_call` — the recording asked for at answer
    // runs until the call ends.
    let directory = tempfile::tempdir().expect("tempdir");
    let (engine, events, (phone_a, near), (phone_b, _far)) =
        recorded_call("rec-reinvite", directory.path()).await;
    let addr_a = phone_a.local_addr().expect("a addr");
    let addr_b = phone_b.local_addr().expect("b addr");
    talk(&phone_a, near, 0x0A0A_0A0A, 0, 15).await;

    let codecs = [(0, "PCMU")];
    renegotiate(
        &engine,
        "rec-reinvite",
        sdp_codecs_direction(addr_a, &codecs, "sendrecv"),
        sdp_codecs_direction(addr_b, &codecs, "sendrecv"),
    )
    .await;
    assert!(
        finished_within(&events, Duration::from_millis(300))
            .await
            .is_empty(),
        "a renegotiation does not end the recording"
    );
    talk(&phone_a, near, 0x0A0A_0A0A, 15, 15).await;
    hang_up(&engine, "rec-reinvite").await;

    let finished = finished_within(&events, Duration::from_secs(3)).await;
    let caller: Vec<_> = finished
        .iter()
        .filter(|(recording_id, ..)| recording_id == "rec-reinvite-a")
        .collect();
    assert_eq!(caller.len(), 1, "one file for the whole call: {finished:?}");
    // 30 frames of 20 ms were sent across both halves. Allow for jitter-buffer start-up and the
    // frames in flight at the hand-over, but a file holding only one half is 300 ms.
    assert!(
        caller[0].2 >= 450,
        "both halves are in the one file ({} ms)",
        caller[0].2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_runtime_recording_keeps_recording_across_a_renegotiation() {
    // The same carry for `start_recording`, which shares the mechanism. Before it, the re-answer's
    // fresh actor replaced the one holding the recording's sinks, and the recording ended at the
    // first re-INVITE with a short file and no stop from anyone.
    let directory = tempfile::tempdir().expect("tempdir");
    let (engine, (phone_a, near), (phone_b, _far)) = two_party_relay("rt-reinvite").await;
    let events = engine.register_client(CLIENT);
    let addr_a = phone_a.local_addr().expect("a addr");
    let addr_b = phone_b.local_addr().expect("b addr");
    let started = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: "rt-reinvite".into(),
                from_tag: "tag-a".into(),
                recording_dir: Some(directory.path().to_string_lossy().into_owned()),
                format: Some(siphon_rtp_proto::RecordingFormat::Wav),
                direction: Some(siphon_rtp_proto::RecordingDirection::Ingress),
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: None,
                bitrate_bps: None,
            },
        )
        .await;
    let recording_id = match started {
        CmdResult::Ok {
            recording_id: Some(id),
            ..
        } => id,
        other => panic!("the recording starts, got {other:?}"),
    };
    talk(&phone_a, near, 0x0A0A_0A0A, 0, 15).await;
    // A codec change, so the re-answer has to stand up a transcoding actor and the carried sinks
    // decode PCMA from then on.
    renegotiate(
        &engine,
        "rt-reinvite",
        sdp_codecs_direction(addr_a, &[(0, "PCMU")], "sendrecv"),
        sdp_codecs_direction(addr_b, &[(8, "PCMA")], "sendrecv"),
    )
    .await;
    assert!(
        finished_within(&events, Duration::from_millis(300))
            .await
            .is_empty(),
        "a renegotiation does not end the recording"
    );
    talk(&phone_a, near, 0x0A0A_0A0A, 15, 15).await;
    let stopped = engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: "rt-reinvite".into(),
                from_tag: "tag-a".into(),
                recording_id: Some(recording_id.clone()),
            },
        )
        .await;
    assert!(matches!(stopped, CmdResult::Ok { .. }), "{stopped:?}");
    let finished = finished_within(&events, Duration::from_secs(2)).await;
    assert_eq!(finished.len(), 1, "one event: {finished:?}");
    assert_eq!(finished[0].0, recording_id);
    assert_eq!(finished[0].3, RecordingEndReason::Stopped);
    assert!(
        finished[0].2 >= 450,
        "both halves are in the one file ({} ms)",
        finished[0].2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stopping_one_recording_leaves_another_on_the_same_call_running() {
    // The userspace hold is one reason per call. Released by the first recording to stop, it
    // demoted a promoted relay under the second, whose sinks then went with the actor: two
    // recordings on one call is ordinary now (`record_call` is two by construction).
    let directory = tempfile::tempdir().expect("tempdir");
    let (engine, (phone_a, near), _callee) = two_party_relay("two-recs").await;
    let events = engine.register_client(CLIENT);
    let start = |name: &str| Command::StartRecording {
        call_id: "two-recs".into(),
        from_tag: "tag-a".into(),
        recording_dir: None,
        format: Some(siphon_rtp_proto::RecordingFormat::Wav),
        direction: Some(siphon_rtp_proto::RecordingDirection::Ingress),
        channels: None,
        max_duration_ms: None,
        silence_ms: None,
        path: Some(directory.path().join(name).to_string_lossy().into_owned()),
        bitrate_bps: None,
    };
    let id_of = |result: CmdResult| match result {
        CmdResult::Ok {
            recording_id: Some(id),
            ..
        } => id,
        other => panic!("the recording starts, got {other:?}"),
    };
    let first = id_of(engine.handle(CLIENT, start("first.wav")).await);
    let second = id_of(engine.handle(CLIENT, start("second.wav")).await);
    talk(&phone_a, near, 0x0A0A_0A0A, 0, 10).await;
    engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: "two-recs".into(),
                from_tag: "tag-a".into(),
                recording_id: Some(first.clone()),
            },
        )
        .await;
    let after_first = finished_within(&events, Duration::from_millis(500)).await;
    assert_eq!(
        after_first.len(),
        1,
        "only the stopped one ends: {after_first:?}"
    );
    assert_eq!(after_first[0].0, first);
    talk(&phone_a, near, 0x0A0A_0A0A, 10, 15).await;
    engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: "two-recs".into(),
                from_tag: "tag-a".into(),
                recording_id: Some(second.clone()),
            },
        )
        .await;
    let after_second = finished_within(&events, Duration::from_secs(2)).await;
    assert_eq!(after_second.len(), 1, "{after_second:?}");
    assert_eq!(after_second[0].0, second);
    assert_eq!(after_second[0].3, RecordingEndReason::Stopped);
    assert!(
        after_second[0].2 > after_first[0].2 + 200,
        "the second kept recording after the first stopped ({} ms vs {} ms)",
        after_second[0].2,
        after_first[0].2
    );
}
