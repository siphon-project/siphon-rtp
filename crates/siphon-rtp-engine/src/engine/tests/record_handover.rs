//! One decoded recording across the hand-over of a call to a voice bot and back: the recording's
//! sinks move between the engine's pipeline and the bot's bridge session with the leg, so the file
//! and the event are one for the whole call.

use super::*;
use siphon_rtp_proto::{
    RecordingChannels, RecordingDirection, RecordingEndReason, RecordingFormat,
};

fn start_stereo(call_id: &str, directory: &std::path::Path) -> Command {
    Command::StartRecording {
        call_id: call_id.into(),
        from_tag: "tag-a".into(),
        recording_dir: Some(directory.to_string_lossy().into_owned()),
        format: Some(RecordingFormat::Wav),
        direction: Some(RecordingDirection::Both),
        channels: Some(RecordingChannels::Stereo),
        max_duration_ms: None,
        silence_ms: None,
        path: None,
        bitrate_bps: None,
    }
}

fn recording_id(result: CmdResult) -> String {
    match result {
        CmdResult::Ok {
            recording_id: Some(id),
            ..
        } => id,
        other => panic!("the recording starts, got {other:?}"),
    }
}

async fn attach(engine: &Engine<UdpLoopbackDatapath>, call_id: &str, ws_uri: String) {
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsBridge {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                ws_uri,
                profile: Some(ProfileFlags {
                    ws_sample_rate: Some(16_000),
                    ..Default::default()
                }),
            },
        )
        .await;
    assert!(
        matches!(attached, CmdResult::Ok { .. }),
        "attach: {attached:?}"
    );
}

/// `frames` ptimes of the caller at the loudest negative µ-law level, and — when `bot` is given —
/// the bot at a constant positive level on its 16 kHz wire, so the two parties are told apart by
/// sign in the file.
async fn talk(
    phone: &UdpSocket,
    target: SocketAddr,
    bot: Option<&flume::Sender<Vec<u8>>>,
    first: u16,
    frames: u16,
) {
    let mut l16 = vec![0u8; 640];
    siphon_rtp_media::bridge::pcm_to_l16_le(&[8000i16; 320], &mut l16);
    for sequence in first..first + frames {
        phone
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0x00), target)
            .await
            .expect("caller send");
        if let Some(bot) = bot {
            bot.send(l16.clone()).expect("bot send");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Every `recording_finished` within `window`.
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

async fn stop(engine: &Engine<UdpLoopbackDatapath>, call_id: &str, recording_id: &str) {
    let stopped = engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                recording_id: Some(recording_id.into()),
            },
        )
        .await;
    assert!(matches!(stopped, CmdResult::Ok { .. }), "stop: {stopped:?}");
}

/// The interleaved stereo samples of the file `path` names, checked to be 8 kHz stereo.
fn stereo_samples(path: Option<String>) -> Vec<i16> {
    let bytes = std::fs::read(path.expect("a file")).expect("read");
    let wav = siphon_rtp_media::player::WavSource::parse(&bytes).expect("valid WAV");
    assert_eq!(wav.channels(), 2);
    assert_eq!(wav.sample_rate_hz(), 8_000);
    wav.samples().to_vec()
}

/// How many 20 ms frames of one channel carry its party (a sample past `threshold` in the party's
/// sign), across the whole file.
fn frames_with(samples: &[i16], channel: usize, party: impl Fn(i16) -> bool) -> usize {
    samples
        .chunks(320)
        .filter(|frame| {
            frame
                .iter()
                .skip(channel)
                .step_by(2)
                .any(|&sample| party(sample))
        })
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_recording_runs_from_the_anchor_through_the_bot_and_back() {
    let (engine, phone, target) = anchored_call("handover-rec").await;
    let events = engine.register_client(CLIENT);
    let directory = tempfile::tempdir().expect("tempdir");
    let id = recording_id(
        engine
            .handle(CLIENT, start_stereo("handover-rec", directory.path()))
            .await,
    );

    // 1. On the anchor: the caller alone.
    talk(&phone, target, None, 0, 15).await;
    // 2. Handed to a bot: the caller and the bot.
    let (ws_uri, frames, bot) = takeover_ws_server().await;
    attach(&engine, "handover-rec", ws_uri).await;
    let _ = expect_bridge_start(&frames).await;
    talk(&phone, target, Some(&bot), 15, 25).await;
    // 3. Back on the anchor: the caller alone again.
    let detached = engine
        .handle(
            CLIENT,
            Command::DetachWsBridge {
                call_id: "handover-rec".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    assert!(
        matches!(detached, CmdResult::Ok { .. }),
        "detach: {detached:?}"
    );
    talk(&phone, target, None, 40, 15).await;

    assert!(
        finished_within(&events, Duration::from_millis(200))
            .await
            .is_empty(),
        "neither hand-over ended the recording"
    );
    stop(&engine, "handover-rec", &id).await;
    let finished = finished_within(&events, Duration::from_secs(2)).await;
    assert_eq!(
        finished.len(),
        1,
        "one recording for the call: {finished:?}"
    );
    let (finished_id, path, duration_ms, reason) = finished[0].clone();
    assert_eq!(finished_id, id);
    assert_eq!(reason, RecordingEndReason::Stopped);
    // 55 ptimes of 20 ms were sent across the three stretches. Allow for start-up, the frames in
    // flight at each swap and the assembler's padding; one stretch alone would be 300–500 ms.
    assert!(
        duration_ms >= 800,
        "the whole call is in the one file ({duration_ms} ms)"
    );

    let samples = stereo_samples(path);
    let caller_frames = frames_with(&samples, 0, |sample| sample < -4000);
    let bot_frames = frames_with(&samples, 1, |sample| sample > 4000);
    assert!(
        caller_frames >= 40,
        "the caller is on the left before, during and after the bot ({caller_frames} frames)"
    );
    assert!(
        (15..=30).contains(&bot_frames),
        "the bot is on the right only while it had the leg ({bot_frames} frames)"
    );
    assert_eq!(engine.recording_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_over_that_does_not_happen_leaves_the_recording_running() {
    // The bot cannot be reached: the attach is refused before the pipeline is touched, and the
    // recording carries on as if nothing had been asked.
    let (engine, phone, target) = anchored_call("handover-refused").await;
    let events = engine.register_client(CLIENT);
    let directory = tempfile::tempdir().expect("tempdir");
    let id = recording_id(
        engine
            .handle(CLIENT, start_stereo("handover-refused", directory.path()))
            .await,
    );
    let unreachable = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind")
        .local_addr()
        .expect("addr");
    let refused = engine
        .handle(
            CLIENT,
            Command::AttachWsBridge {
                call_id: "handover-refused".into(),
                from_tag: "tag-a".into(),
                ws_uri: format!("ws://{unreachable}/stream"),
                profile: None,
            },
        )
        .await;
    assert!(matches!(refused, CmdResult::Error { .. }), "{refused:?}");
    talk(&phone, target, None, 0, 20).await;
    stop(&engine, "handover-refused", &id).await;
    let finished = finished_within(&events, Duration::from_secs(2)).await;
    assert_eq!(finished.len(), 1, "{finished:?}");
    let samples = stereo_samples(finished[0].1.clone());
    assert!(frames_with(&samples, 0, |sample| sample < -4000) >= 15);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recording_follows_the_leg_from_one_bot_to_the_next() {
    let (engine, phone, target) = anchored_call("handover-repoint").await;
    let events = engine.register_client(CLIENT);
    let directory = tempfile::tempdir().expect("tempdir");
    let (first_uri, first_frames, first_bot) = takeover_ws_server().await;
    attach(&engine, "handover-repoint", first_uri).await;
    let _ = expect_bridge_start(&first_frames).await;
    let id = recording_id(
        engine
            .handle(CLIENT, start_stereo("handover-repoint", directory.path()))
            .await,
    );
    talk(&phone, target, Some(&first_bot), 0, 15).await;
    let (second_uri, second_frames, second_bot) = takeover_ws_server().await;
    attach(&engine, "handover-repoint", second_uri).await;
    let _ = expect_bridge_start(&second_frames).await;
    talk(&phone, target, Some(&second_bot), 15, 15).await;
    stop(&engine, "handover-repoint", &id).await;
    let finished = finished_within(&events, Duration::from_secs(2)).await;
    assert_eq!(
        finished.len(),
        1,
        "one recording across both bots: {finished:?}"
    );
    let samples = stereo_samples(finished[0].1.clone());
    assert!(
        frames_with(&samples, 1, |sample| sample > 4000) >= 20,
        "both bots are on the right"
    );
}
