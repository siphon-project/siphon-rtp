//! One WebSocket tee fed by several calls (SIPREC streams, each answered on a call of its own): a
//! channel per stream, exactly one `ws_tee_started` and `ws_tee_ended`, ended by whichever call goes
//! first. Every stream shares one `from_tag`, as a SIPREC session does; see `multi_source_recording`
//! for the levels that tell the streams apart.

use super::multi_source_recording::{
    siprec_streams, Stream, LOUD_NEGATIVE, QUIET_POSITIVE, SESSION_TAG,
};
use super::*;
use siphon_rtp_proto::{RecordingSource, WsTeeEndReason};
use tokio_tungstenite::tungstenite::Message;

fn attach(
    streams: &[Stream],
    ws_uri: &str,
    direction: WsTeeDirection,
    channels: Option<u8>,
) -> Command {
    Command::AttachWsTee {
        call_id: streams[0].call_id.clone(),
        from_tag: SESSION_TAG.into(),
        ws_uri: ws_uri.to_string(),
        direction,
        channels,
        sample_rate: None,
        additional_sources: streams[1..].iter().map(Stream::source).collect(),
    }
}

fn refusal(result: CmdResult) -> String {
    match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Send `frames` 20 ms frames on every stream in step.
async fn speak(streams: &[Stream], levels: &[u8], frames: u16) {
    for sequence in 0..frames {
        for (stream, &level) in streams.iter().zip(levels) {
            stream.send(sequence, level).await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Every binary frame the server has received so far, as samples.
fn audio_so_far(frames: &flume::Receiver<Message>) -> Vec<i16> {
    let mut samples = Vec::new();
    while let Ok(message) = frames.try_recv() {
        if let Message::Binary(bytes) = message {
            samples.extend(
                bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|p| i16::from_le_bytes(*p)),
            );
        }
    }
    samples
}

/// All `ws_tee_ended` events seen within `wait`, plus the started ones.
async fn tee_events(events: &flume::Receiver<Event>, wait: Duration) -> (usize, Vec<Event>) {
    let deadline = tokio::time::Instant::now() + wait;
    let (mut started, mut ended) = (0, Vec::new());
    while let Ok(Ok(event)) = tokio::time::timeout_at(deadline, events.recv_async()).await {
        match event {
            Event::WsTeeStarted { .. } => started += 1,
            Event::WsTeeEnded { .. } => ended.push(event),
            _ => {}
        }
    }
    (started, ended)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_sendonly_calls_stream_as_one_stereo_tee() {
    let (engine, events, streams) = siprec_streams(2).await;
    let (uri, frames) = tee_server().await;
    let attached = engine
        .handle(
            CLIENT,
            attach(&streams, &uri, WsTeeDirection::Caller, Some(2)),
        )
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let start = expect_tee_start(&frames).await;
    assert_eq!(start.media.channels, 2);
    assert_eq!(start.media.sample_rate, 8000);
    assert_eq!(engine.ws_tee_count(), 1, "one tee for both calls");

    speak(&streams, &[LOUD_NEGATIVE, QUIET_POSITIVE], 40).await;
    let samples = audio_so_far(&frames);
    let both = samples
        .chunks(2)
        .filter(|pair| pair.len() == 2 && pair[0] < -30_000 && (1_500..2_200).contains(&pair[1]))
        .count();
    assert!(
        both >= 4_000,
        "left is the first stream, right the second: {both} frames of {}",
        samples.len() / 2
    );
    assert!(!samples
        .chunks(2)
        .any(|pair| pair.len() == 2 && (pair[0] > 1_000 || pair[1] < -1_000)));

    // Detaching from the first source ends it, once.
    let detached = engine
        .handle(
            CLIENT,
            Command::DetachWsTee {
                call_id: streams[0].call_id.clone(),
                from_tag: SESSION_TAG.into(),
            },
        )
        .await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert_eq!(engine.ws_tee_count(), 0);
    let (started, ended) = tee_events(&events, Duration::from_millis(500)).await;
    assert_eq!(started, 1, "exactly one ws_tee_started");
    let [Event::WsTeeEnded {
        call_id,
        reason,
        frames_sent,
        ..
    }] = ended.as_slice()
    else {
        panic!("exactly one ws_tee_ended: {ended:?}");
    };
    assert_eq!(call_id, &streams[0].call_id);
    assert_eq!(*reason, WsTeeEndReason::Detached);
    assert!(frames_sent.is_some_and(|sent| sent > 20), "{frames_sent:?}");

    // Both calls are still live and tee-free: the tee can be attached again.
    let (uri, frames) = tee_server().await;
    let again = engine
        .handle(CLIENT, attach(&streams, &uri, WsTeeDirection::Both, None))
        .await;
    assert!(matches!(again, CmdResult::Ok { .. }), "{again:?}");
    assert_eq!(expect_tee_start(&frames).await.media.channels, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mono_tee_mixes_every_source() {
    let (engine, _events, streams) = siprec_streams(3).await;
    let (uri, frames) = tee_server().await;
    let attached = engine
        .handle(CLIENT, attach(&streams, &uri, WsTeeDirection::Caller, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    assert_eq!(
        expect_tee_start(&frames).await.media.channels,
        1,
        "three sources default to a mix"
    );
    speak(
        &streams,
        &[LOUD_NEGATIVE, QUIET_POSITIVE, QUIET_POSITIVE],
        40,
    )
    .await;
    let samples = audio_so_far(&frames);
    let mixed = samples
        .iter()
        .filter(|&&sample| (-29_500..-27_500).contains(&sample))
        .count();
    assert!(mixed >= 4_000, "{mixed} mixed samples of {}", samples.len());
}

async fn deleting_a_source_ends_the_tee(deleted: usize) {
    let (engine, events, streams) = siprec_streams(2).await;
    let (uri, frames) = tee_server().await;
    let attached = engine
        .handle(
            CLIENT,
            attach(&streams, &uri, WsTeeDirection::Caller, Some(2)),
        )
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    expect_tee_start(&frames).await;
    speak(&streams, &[LOUD_NEGATIVE, QUIET_POSITIVE], 15).await;

    let result = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: streams[deleted].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    assert_eq!(engine.ws_tee_count(), 0);
    let (started, ended) = tee_events(&events, Duration::from_millis(500)).await;
    assert_eq!(started, 1);
    let [Event::WsTeeEnded {
        call_id, reason, ..
    }] = ended.as_slice()
    else {
        panic!("exactly one ws_tee_ended: {ended:?}");
    };
    assert_eq!(call_id, &streams[0].call_id, "events name source 0");
    assert_eq!(*reason, WsTeeEndReason::CallEnded);

    // The call that was not deleted carries no tee any more, and deleting it ends nothing again.
    let other = 1 - deleted;
    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: streams[other].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                to_tag: None,
            },
        )
        .await;
    let (_, again) = tee_events(&events, Duration::from_millis(300)).await;
    assert!(again.is_empty(), "no second ws_tee_ended: {again:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_the_first_source_call_ends_the_tee_once_as_call_ended() {
    deleting_a_source_ends_the_tee(0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_the_second_source_call_ends_the_tee_once_as_call_ended() {
    deleting_a_source_ends_the_tee(1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_source_tee_that_is_not_allowed_is_refused_and_touches_nothing() {
    let (engine, _events, streams) = siprec_streams(9).await;
    let (uri, _frames) = tee_server().await;

    let reason = refusal(
        engine
            .handle(CLIENT, attach(&streams, &uri, WsTeeDirection::Caller, None))
            .await,
    );
    assert!(reason.contains("2 to 8"), "{reason}");
    let reason = refusal(
        engine
            .handle(
                CLIENT,
                attach(&streams[..3], &uri, WsTeeDirection::Caller, Some(2)),
            )
            .await,
    );
    assert!(reason.contains("exactly 2"), "{reason}");
    let reason = refusal(
        engine
            .handle(
                CLIENT,
                attach(&streams[..2], &uri, WsTeeDirection::Callee, None),
            )
            .await,
    );
    assert!(reason.contains("callee"), "{reason}");
    // The same call twice, under the same tag.
    let mut twice = attach(&streams[..2], &uri, WsTeeDirection::Caller, None);
    if let Command::AttachWsTee {
        additional_sources, ..
    } = &mut twice
    {
        additional_sources[0] = RecordingSource {
            call_id: streams[0].call_id.clone(),
            from_tag: SESSION_TAG.into(),
        };
    }
    let reason = refusal(engine.handle(CLIENT, twice).await);
    assert!(reason.contains("twice"), "{reason}");
    // Another client's call is as unknown as none.
    let stranger = ClientId(2);
    let _stranger_events = engine.register_client(stranger);
    let reason = refusal(
        engine
            .handle(
                stranger,
                attach(&streams[..2], &uri, WsTeeDirection::Caller, None),
            )
            .await,
    );
    assert!(reason.contains("unknown call"), "{reason}");
    assert_eq!(engine.ws_tee_count(), 0, "no refusal left a tee");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_source_that_already_carries_a_tee_refuses_a_multi_source_tee() {
    let (engine, _events, streams) = siprec_streams(2).await;
    // A single-call tee on the second source.
    let (uri_single, frames_single) = tee_server().await;
    let single = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: streams[1].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                ws_uri: uri_single,
                direction: WsTeeDirection::Caller,
                channels: None,
                sample_rate: None,
                additional_sources: Vec::new(),
            },
        )
        .await;
    assert!(matches!(single, CmdResult::Ok { .. }), "{single:?}");
    expect_tee_start(&frames_single).await;

    let (uri, _frames) = tee_server().await;
    let reason = refusal(
        engine
            .handle(CLIENT, attach(&streams, &uri, WsTeeDirection::Caller, None))
            .await,
    );
    assert!(reason.contains("already carries"), "{reason}");
    assert_eq!(engine.ws_tee_count(), 1, "the existing tee is untouched");

    // And a single-call tee cannot be put on a source another tee holds.
    engine
        .handle(
            CLIENT,
            Command::DetachWsTee {
                call_id: streams[1].call_id.clone(),
                from_tag: SESSION_TAG.into(),
            },
        )
        .await;
    let (uri, frames) = tee_server().await;
    let multi = engine
        .handle(CLIENT, attach(&streams, &uri, WsTeeDirection::Caller, None))
        .await;
    assert!(matches!(multi, CmdResult::Ok { .. }), "{multi:?}");
    expect_tee_start(&frames).await;
    let (uri_second, _frames_second) = tee_server().await;
    let reason = refusal(
        engine
            .handle(
                CLIENT,
                Command::AttachWsTee {
                    call_id: streams[1].call_id.clone(),
                    from_tag: SESSION_TAG.into(),
                    ws_uri: uri_second,
                    direction: WsTeeDirection::Caller,
                    channels: None,
                    sample_rate: None,
                    additional_sources: Vec::new(),
                },
            )
            .await,
    );
    assert!(reason.contains("multi-source"), "{reason}");
}
