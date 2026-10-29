//! A decoded recording of a call a voice bot has taken over: the caller, and what the caller heard
//! from the bot, tapped from the bridge session that decodes one and renders the other.

use super::*;
use siphon_rtp_proto::{
    RecordingChannels, RecordingDirection, RecordingEndReason, RecordingFormat,
};

fn start_recording(
    call_id: &str,
    directory: &std::path::Path,
    direction: RecordingDirection,
    channels: RecordingChannels,
) -> Command {
    Command::StartRecording {
        call_id: call_id.into(),
        from_tag: "tag-a".into(),
        recording_dir: Some(directory.to_string_lossy().into_owned()),
        format: Some(RecordingFormat::Wav),
        direction: Some(direction),
        channels: Some(channels),
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

/// Hand the anchored call to a bot on a 16 kHz wire (so the bot's downlink is resampled back into
/// the leg's 8 kHz), returning the server's frames and its downlink sender.
async fn hand_to_bot(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
) -> (
    flume::Receiver<tokio_tungstenite::tungstenite::Message>,
    flume::Sender<Vec<u8>>,
) {
    let (ws_uri, frames, downlink) = takeover_ws_server().await;
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
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let _ = expect_bridge_start(&frames).await;
    (frames, downlink)
}

/// 20 ms of the bot at 16 kHz: a constant positive level.
fn bot_frame() -> Vec<u8> {
    let mut l16 = vec![0u8; 640];
    siphon_rtp_media::bridge::pcm_to_l16_le(&[8000i16; 320], &mut l16);
    l16
}

/// The caller and the bot talking at once for `frames` ptimes: µ-law `0x00` is the loudest
/// negative level (ITU-T G.711), and the bot is positive, so the two are told apart by sign.
async fn both_talk(
    phone: &UdpSocket,
    caller_target: SocketAddr,
    downlink: &flume::Sender<Vec<u8>>,
    frames: u16,
) {
    for sequence in 0..frames {
        phone
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0x00), caller_target)
            .await
            .expect("caller send");
        downlink.send(bot_frame()).expect("bot sends");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn finished(
    events: &flume::Receiver<Event>,
) -> (String, Option<String>, u64, RecordingEndReason) {
    for _ in 0..60u16 {
        match timeout(Duration::from_millis(200), events.recv_async()).await {
            Ok(Ok(Event::RecordingFinished {
                recording_id,
                path,
                duration_ms,
                reason,
                ..
            })) => return (recording_id, path, duration_ms, reason),
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    panic!("no recording_finished arrived");
}

/// Mean of one channel of an interleaved stereo buffer.
fn channel_mean(samples: &[i16], channel: usize) -> i64 {
    let picked: Vec<i64> = samples
        .iter()
        .skip(channel)
        .step_by(2)
        .map(|&sample| i64::from(sample))
        .collect();
    picked.iter().sum::<i64>() / picked.len().max(1) as i64
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_handed_to_a_bot_is_recorded_caller_left_and_bot_right() {
    let (engine, phone, caller_target) = anchored_call("bot-rec").await;
    let events = engine.register_client(CLIENT);
    let (_frames, downlink) = hand_to_bot(&engine, "bot-rec").await;
    let directory = tempfile::tempdir().expect("tempdir");
    let id = recording_id(
        engine
            .handle(
                CLIENT,
                start_recording(
                    "bot-rec",
                    directory.path(),
                    RecordingDirection::Both,
                    RecordingChannels::Stereo,
                ),
            )
            .await,
    );
    both_talk(&phone, caller_target, &downlink, 25).await;
    let stopped = engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: "bot-rec".into(),
                from_tag: "tag-a".into(),
                recording_id: Some(id.clone()),
            },
        )
        .await;
    assert!(matches!(stopped, CmdResult::Ok { .. }), "{stopped:?}");

    let (finished_id, path, duration_ms, reason) = finished(&events).await;
    assert_eq!(finished_id, id);
    assert_eq!(reason, RecordingEndReason::Stopped);
    assert!(duration_ms > 200, "both parties' audio ({duration_ms} ms)");
    let bytes = std::fs::read(path.expect("a file")).expect("read");
    let wav = siphon_rtp_media::player::WavSource::parse(&bytes).expect("valid WAV");
    assert_eq!(wav.channels(), 2, "the bot is the second party");
    assert_eq!(wav.sample_rate_hz(), 8_000, "at the caller leg's rate");
    assert!(
        channel_mean(wav.samples(), 0) < -1000,
        "the caller is on the left"
    );
    assert!(
        channel_mean(wav.samples(), 1) > 1000,
        "the bot, resampled from its 16 kHz wire, is on the right"
    );
    assert!(
        engine.ws().is_ws_call("bot-rec"),
        "recording never disturbed the takeover"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_takeover_recording_is_finished_when_the_call_ends_under_it() {
    let (engine, phone, caller_target) = anchored_call("bot-rec-end").await;
    let events = engine.register_client(CLIENT);
    let (_frames, downlink) = hand_to_bot(&engine, "bot-rec-end").await;
    let directory = tempfile::tempdir().expect("tempdir");
    let id = recording_id(
        engine
            .handle(
                CLIENT,
                start_recording(
                    "bot-rec-end",
                    directory.path(),
                    RecordingDirection::Ingress,
                    RecordingChannels::Mono,
                ),
            )
            .await,
    );
    both_talk(&phone, caller_target, &downlink, 10).await;
    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "bot-rec-end".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    let (finished_id, path, duration_ms, reason) = finished(&events).await;
    assert_eq!(finished_id, id);
    assert_eq!(reason, RecordingEndReason::CallEnded);
    assert!(duration_ms > 0);
    let bytes = std::fs::read(path.expect("a file")).expect("read");
    let wav = siphon_rtp_media::player::WavSource::parse(&bytes).expect("valid WAV");
    assert_eq!(wav.channels(), 1);
    assert!(
        wav.samples().iter().any(|&sample| sample < -1000),
        "the caller's audio is in it"
    );
    assert_eq!(engine.recording_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bot_that_displaced_a_relayed_party_refuses_a_recording() {
    // Handing that leg back restores an in-kernel relay, which has no decoded audio to carry the
    // recording on — so it is refused up front rather than ended at the hand-over.
    let (engine, _caller, _callee) = two_party_relay("relay-bot-rec").await;
    let (ws_uri, frames, _downlink) = takeover_ws_server().await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsBridge {
                call_id: "relay-bot-rec".into(),
                from_tag: "tag-a".into(),
                ws_uri,
                profile: None,
            },
        )
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let _ = expect_bridge_start(&frames).await;
    let directory = tempfile::tempdir().expect("tempdir");
    match engine
        .handle(
            CLIENT,
            start_recording(
                "relay-bot-rec",
                directory.path(),
                RecordingDirection::Both,
                RecordingChannels::Stereo,
            ),
        )
        .await
    {
        CmdResult::Error { reason } => assert!(
            reason.contains("recording-needs-an-anchored-takeover"),
            "the refusal names why: {reason}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(
        engine.ws().is_ws_call("relay-bot-rec"),
        "the bot keeps the leg"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_anchor_recording_of_what_the_caller_heard_holds_the_engines_prompt() {
    // On an engine-answered call the right channel is what the caller heard. Before a bot joins,
    // that is the engine's own prompt — pinned here because a recording started on the anchor
    // keeps that meaning across a hand-over.
    let (engine, _phone, _caller_target) = anchored_call("anchor-heard").await;
    let events = engine.register_client(CLIENT);
    let directory = tempfile::tempdir().expect("tempdir");
    let id = recording_id(
        engine
            .handle(
                CLIENT,
                start_recording(
                    "anchor-heard",
                    directory.path(),
                    RecordingDirection::Egress,
                    RecordingChannels::Mono,
                ),
            )
            .await,
    );
    let played = engine
        .handle(
            CLIENT,
            Command::PlayMedia {
                call_id: "anchor-heard".into(),
                from_tag: "tag-a".into(),
                source: siphon_rtp_proto::PlayMediaSource::Tone {
                    tone: "ringback_eu".into(),
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: Some(400),
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(played, CmdResult::Ok { .. }), "{played:?}");
    tokio::time::sleep(Duration::from_millis(600)).await;
    engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: "anchor-heard".into(),
                from_tag: "tag-a".into(),
                recording_id: Some(id),
            },
        )
        .await;
    let (_, path, _, _) = finished(&events).await;
    let bytes = std::fs::read(path.expect("a file")).expect("read");
    let wav = siphon_rtp_media::player::WavSource::parse(&bytes).expect("valid WAV");
    assert!(
        wav.samples()
            .iter()
            .any(|&sample| sample.unsigned_abs() > 500),
        "the prompt the caller heard is in the recording"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_answered_straight_into_a_bot_is_recorded_too() {
    // The bot named at answer (`answer_local` with `ws_uri`): the bridge is the call's own media
    // path from the first packet, with no anchor before it.
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
    let (ws_uri, frames, downlink) = takeover_ws_server().await;
    let (phone, addr) = phone().await;
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "answered-bot".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr, 0, "PCMU"),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ws_sample_rate: Some(16_000),
                    ..Default::default()
                },
            },
        )
        .await;
    let caller_target = sdp::parse(&ok_sdp_text(&answered))
        .expect("answer sdp")
        .remote_rtp;
    let _ = expect_bridge_start(&frames).await;
    assert!(engine.ws().is_ws_call("answered-bot"));

    let directory = tempfile::tempdir().expect("tempdir");
    let id = recording_id(
        engine
            .handle(
                CLIENT,
                start_recording(
                    "answered-bot",
                    directory.path(),
                    RecordingDirection::Both,
                    RecordingChannels::Stereo,
                ),
            )
            .await,
    );
    both_talk(&phone, caller_target, &downlink, 25).await;
    engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: "answered-bot".into(),
                from_tag: "tag-a".into(),
                recording_id: Some(id),
            },
        )
        .await;
    let (_, path, _, reason) = finished(&events).await;
    assert_eq!(reason, RecordingEndReason::Stopped);
    let bytes = std::fs::read(path.expect("a file")).expect("read");
    let wav = siphon_rtp_media::player::WavSource::parse(&bytes).expect("valid WAV");
    assert_eq!(wav.channels(), 2);
    assert!(channel_mean(wav.samples(), 0) < -1000, "caller left");
    assert!(channel_mean(wav.samples(), 1) > 1000, "bot right");
}
