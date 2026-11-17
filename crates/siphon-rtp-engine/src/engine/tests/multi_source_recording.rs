//! One recording fed by several calls: SIPREC (RFC 7866) answers each recorded stream on an
//! `answer_local` call of its own, and the recorder needs ONE file, a channel per stream, kept on
//! one timeline, ending once whichever call ends first.
//!
//! Every source below carries the **same** `from_tag`, as a SIPREC session does (the SRC's From-tag
//! on every stream), on different call ids: nothing may tell sources apart by tag.
//!
//! µ-law levels tell the streams apart in the file: stored byte `0x00` decodes to -32124 (the
//! loudest negative level) and `0xC0` to +1884, so a left sample is source 0's and a right sample
//! source 1's, and a mono mix of the two is -30240.

use super::tee_sendonly::sendonly_offer;
use super::*;
use siphon_rtp_proto::{
    RecordingChannels, RecordingDirection, RecordingEndReason, RecordingFormat, RecordingSource,
};

/// The From-tag every stream of a SIPREC session shares.
pub(super) const SESSION_TAG: &str = "siprec-session";
/// Stored µ-law byte for -32124.
pub(super) const LOUD_NEGATIVE: u8 = 0x00;
/// Stored µ-law byte for +1884.
pub(super) const QUIET_POSITIVE: u8 = 0xC0;

/// One recorded stream: a sendonly phone and the engine address answering it.
pub(super) struct Stream {
    pub(super) call_id: String,
    pub(super) phone: UdpSocket,
    pub(super) engine_near: SocketAddr,
    ssrc: u32,
}

impl Stream {
    /// A stream that is not an `answer_local` sendonly call: any call whose caller `phone` sends to
    /// `engine_near`.
    pub(super) fn from_parts(call_id: &str, phone: UdpSocket, engine_near: SocketAddr) -> Self {
        Self {
            call_id: call_id.to_string(),
            phone,
            engine_near,
            ssrc: 0x0C0C_0000,
        }
    }

    /// Send one 20 ms frame of `level` as RTP packet number `sequence`.
    pub(super) async fn send(&self, sequence: u16, level: u8) {
        self.phone
            .send_to(&g711_rtp(0, sequence, self.ssrc, level), self.engine_near)
            .await
            .expect("send");
    }

    /// The source entry naming this stream.
    pub(super) fn source(&self) -> RecordingSource {
        RecordingSource {
            call_id: self.call_id.clone(),
            from_tag: SESSION_TAG.to_string(),
        }
    }
}

/// An engine with `count` sendonly streams answered locally, all under [`SESSION_TAG`].
pub(super) async fn siprec_streams(
    count: usize,
) -> (
    Engine<UdpLoopbackDatapath>,
    flume::Receiver<Event>,
    Vec<Stream>,
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
    let mut streams = Vec::new();
    for index in 0..count {
        let call_id = format!("siprec-call~{index}");
        let (phone, addr) = phone().await;
        let answered = engine
            .handle(
                CLIENT,
                Command::AnswerLocal {
                    call_id: call_id.clone(),
                    from_tag: SESSION_TAG.into(),
                    sdp: sendonly_offer(addr),
                    profile: Default::default(),
                },
            )
            .await;
        let engine_near = sdp::parse(&ok_sdp_text(&answered))
            .expect("answer sdp")
            .remote_rtp;
        streams.push(Stream {
            call_id,
            phone,
            engine_near,
            ssrc: 0x0B0B_0000 + index as u32,
        });
    }
    (engine, events, streams)
}

/// A decoded `start_recording` over `streams[0]` plus the rest as additional sources.
pub(super) fn start_command(
    streams: &[Stream],
    path: &std::path::Path,
    format: RecordingFormat,
    channels: RecordingChannels,
) -> Command {
    Command::StartRecording {
        call_id: streams[0].call_id.clone(),
        from_tag: SESSION_TAG.into(),
        recording_dir: None,
        format: Some(format),
        direction: Some(RecordingDirection::Ingress),
        channels: Some(channels),
        max_duration_ms: None,
        silence_ms: None,
        path: Some(path.to_string_lossy().into_owned()),
        bitrate_bps: None,
        additional_sources: streams[1..].iter().map(Stream::source).collect(),
    }
}

fn accepted_recording_id(result: CmdResult) -> String {
    match result {
        CmdResult::Ok {
            recording_id: Some(id),
            ..
        } => id,
        other => panic!("the multi-source recording is accepted with a recording_id: {other:?}"),
    }
}

fn error_reason(result: CmdResult) -> String {
    match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Both streams speak for `frames` 20 ms frames.
async fn speak_together(streams: &[Stream], levels: &[u8], frames: u16) {
    for sequence in 0..frames {
        for (stream, &level) in streams.iter().zip(levels) {
            stream.send(sequence, level).await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The finished WAV at `path`: interleaved samples and channel count.
fn read_wav(path: &str) -> (Vec<i16>, u16) {
    let bytes = std::fs::read(path).expect("the file exists");
    let wav = siphon_rtp_media::player::WavSource::parse(&bytes).expect("a complete WAV");
    assert_eq!(wav.sample_rate_hz(), 8000);
    (wav.samples().to_vec(), wav.channels())
}

/// The next `recording_finished`: `(call_id, path, duration_ms, reason)`.
pub(super) async fn finished(
    events: &flume::Receiver<Event>,
) -> (String, String, u64, RecordingEndReason) {
    for _ in 0..60 {
        match timeout(Duration::from_millis(200), events.recv_async()).await {
            Ok(Ok(Event::RecordingFinished {
                call_id,
                path,
                duration_ms,
                reason,
                ..
            })) => {
                let path = path.expect("the event names the file");
                return (call_id, path, duration_ms, reason);
            }
            Ok(Ok(_)) => {}
            _ => break,
        }
    }
    panic!("no recording_finished arrived");
}

/// No second `recording_finished` follows within `wait`.
async fn assert_no_more_finished(events: &flume::Receiver<Event>, wait: Duration) {
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Ok(event)) = tokio::time::timeout_at(deadline, events.recv_async()).await {
        assert!(
            !matches!(event, Event::RecordingFinished { .. }),
            "a second recording_finished: {event:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_sendonly_calls_make_one_stereo_file_with_a_channel_each() {
    let (engine, events, streams) = siprec_streams(2).await;
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("siprec.wav");
    let recording_id = accepted_recording_id(
        engine
            .handle(
                CLIENT,
                start_command(
                    &streams,
                    &path,
                    RecordingFormat::Wav,
                    RecordingChannels::Stereo,
                ),
            )
            .await,
    );
    assert_eq!(engine.recording_count(), 1, "one recording, not one a call");

    speak_together(&streams, &[LOUD_NEGATIVE, QUIET_POSITIVE], 40).await;
    let stopped = engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: streams[0].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                recording_id: Some(recording_id.clone()),
            },
        )
        .await;
    assert!(matches!(stopped, CmdResult::Ok { .. }), "{stopped:?}");
    let (call_id, file, duration_ms, reason) = finished(&events).await;
    assert_eq!(call_id, streams[0].call_id, "events name source 0");
    assert_eq!(reason, RecordingEndReason::Stopped);
    assert!(duration_ms >= 500, "{duration_ms} ms recorded");
    let (samples, channels) = read_wav(&file);
    assert_eq!(channels, 2);
    let frames: Vec<&[i16]> = samples.chunks(2).collect();
    let both = frames
        .iter()
        .filter(|pair| pair[0] < -30_000 && (1_500..2_200).contains(&pair[1]))
        .count();
    assert!(
        both >= 4_000,
        "left is the first stream and right the second for most of the file: {both} frames of {}",
        frames.len()
    );
    assert!(
        !frames
            .iter()
            .any(|pair| pair[0] > 1_000 || pair[1] < -1_000),
        "no channel carries the other's audio"
    );
    assert_eq!(engine.recording_count(), 0);
    assert_no_more_finished(&events, Duration::from_millis(300)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_source_that_starts_late_and_one_that_goes_quiet_stay_on_one_timeline() {
    const TICK_MS: u64 = 20;
    // Source 0 speaks from the start, pauses for ticks 15..30, and resumes. Source 1 starts 300 ms
    // in. The sample offsets in the file must show exactly that, whatever the arrival jitter.
    let (engine, events, streams) = siprec_streams(2).await;
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("aligned.wav");
    let recording_id = accepted_recording_id(
        engine
            .handle(
                CLIENT,
                start_command(
                    &streams,
                    &path,
                    RecordingFormat::Wav,
                    RecordingChannels::Stereo,
                ),
            )
            .await,
    );
    let started = tokio::time::Instant::now();
    for tick in 0..70u16 {
        if tick < 15 || (30..55).contains(&tick) {
            streams[0].send(tick, LOUD_NEGATIVE).await;
        }
        if tick >= 15 {
            streams[1].send(tick - 15, QUIET_POSITIVE).await;
        }
        tokio::time::sleep_until(started + Duration::from_millis(TICK_MS * (u64::from(tick) + 1)))
            .await;
    }
    engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: streams[0].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                recording_id: Some(recording_id),
            },
        )
        .await;
    let (_, file, _, reason) = finished(&events).await;
    assert_eq!(reason, RecordingEndReason::Stopped);
    let (samples, _) = read_wav(&file);

    // Per 20 ms block (160 sample frames): whether each channel carries its stream.
    let blocks: Vec<(bool, bool)> = samples
        .chunks(320)
        .map(|block| {
            (
                block.chunks(2).any(|pair| pair[0] < -5_000),
                block.chunks(2).any(|pair| pair[1] > 1_000),
            )
        })
        .collect();
    let first_left = blocks.iter().position(|b| b.0).expect("source 0 is heard");
    let first_right = blocks.iter().position(|b| b.1).expect("source 1 is heard");
    // The tolerance is 4 blocks (80 ms): two for each stream's priming and a margin for scheduling.
    let late = first_right as i64 - first_left as i64;
    assert!(
        (15 - 4..=15 + 4).contains(&late),
        "source 1 starts {late} blocks after source 0, expected 15 (+/- 4)"
    );
    // The quiet stretch of source 0: the longest run of blocks without it between its first and
    // last block, while source 1 never stops.
    let last_left = blocks.iter().rposition(|b| b.0).expect("source 0 resumes");
    let (mut longest, mut run) = (0usize, 0usize);
    for block in &blocks[first_left..=last_left] {
        run = if block.0 { 0 } else { run + 1 };
        longest = longest.max(run);
    }
    assert!(
        (15 - 4..=15 + 4).contains(&longest),
        "source 0 is quiet for {longest} blocks, expected 15 (+/- 4)"
    );
    let right_through_the_gap = blocks[first_right + 2..last_left]
        .iter()
        .filter(|block| block.1)
        .count();
    assert!(
        right_through_the_gap + 3 >= last_left - first_right - 2,
        "source 1 is present for the whole of source 0's pause"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mono_recording_mixes_every_source() {
    let (engine, events, streams) = siprec_streams(3).await;
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("mixed.wav");
    let recording_id = accepted_recording_id(
        engine
            .handle(
                CLIENT,
                start_command(
                    &streams,
                    &path,
                    RecordingFormat::Wav,
                    RecordingChannels::Mono,
                ),
            )
            .await,
    );
    // -32124 + 1884 + 1884 = -28356
    speak_together(
        &streams,
        &[LOUD_NEGATIVE, QUIET_POSITIVE, QUIET_POSITIVE],
        40,
    )
    .await;
    engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: streams[0].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                recording_id: Some(recording_id),
            },
        )
        .await;
    let (_, file, _, _) = finished(&events).await;
    let (samples, channels) = read_wav(&file);
    assert_eq!(channels, 1);
    let mixed = samples
        .iter()
        .filter(|&&sample| (-29_500..-27_500).contains(&sample))
        .count();
    assert!(mixed >= 4_000, "{mixed} mixed samples of {}", samples.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ogg_opus_stereo_recording_carries_two_channels() {
    let (engine, events, streams) = siprec_streams(2).await;
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("siprec.opus");
    let recording_id = accepted_recording_id(
        engine
            .handle(
                CLIENT,
                start_command(
                    &streams,
                    &path,
                    RecordingFormat::OggOpus,
                    RecordingChannels::Stereo,
                ),
            )
            .await,
    );
    speak_together(&streams, &[LOUD_NEGATIVE, QUIET_POSITIVE], 40).await;
    engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: streams[0].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                recording_id: Some(recording_id),
            },
        )
        .await;
    let (_, file, duration_ms, reason) = finished(&events).await;
    assert_eq!(reason, RecordingEndReason::Stopped);
    let bytes = std::fs::read(file).expect("the file exists");
    assert!(bytes.starts_with(b"OggS"), "an Ogg stream");
    // RFC 7845 §5.1: OpusHead is version, channel count, pre-skip.
    let head = bytes
        .windows(8)
        .position(|window| window == b"OpusHead")
        .expect("an identification header");
    assert_eq!(bytes[head + 9], 2, "two channels");
    // RFC 7845 §4: the last page's granule position counts 48 kHz samples; the end-of-stream page
    // is flagged, and its position matches what was recorded to within a frame.
    let last = bytes
        .windows(4)
        .rposition(|window| window == b"OggS")
        .expect("a last page");
    assert_eq!(bytes[last + 5] & 0x04, 0x04, "the end-of-stream flag");
    let granule = u64::from_le_bytes(bytes[last + 6..last + 14].try_into().expect("8 bytes"));
    let expected = duration_ms * 48;
    assert!(
        granule.abs_diff(expected) <= 48 * 120,
        "granule {granule} against {expected} for {duration_ms} ms"
    );
}

/// Deleting either source call ends the recording once, with `call_ended`, and the file is
/// complete by the time the event is seen.
async fn deleting_a_source_ends_the_recording(deleted: usize) {
    let (engine, events, streams) = siprec_streams(2).await;
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("ended.wav");
    accepted_recording_id(
        engine
            .handle(
                CLIENT,
                start_command(
                    &streams,
                    &path,
                    RecordingFormat::Wav,
                    RecordingChannels::Stereo,
                ),
            )
            .await,
    );
    speak_together(&streams, &[LOUD_NEGATIVE, QUIET_POSITIVE], 25).await;
    let deleted_call = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: streams[deleted].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                to_tag: None,
            },
        )
        .await;
    assert!(
        matches!(deleted_call, CmdResult::Ok { .. }),
        "{deleted_call:?}"
    );
    // `delete` returns only once the file is closed and the event queued.
    assert_eq!(engine.recording_count(), 0, "the recording is gone with it");
    let (call_id, file, duration_ms, reason) = finished(&events).await;
    assert_eq!(call_id, streams[0].call_id);
    assert_eq!(reason, RecordingEndReason::CallEnded);
    assert!(duration_ms >= 300, "{duration_ms} ms");
    let (samples, channels) = read_wav(&file);
    assert_eq!(channels, 2);
    assert!(
        samples.len() as u64 >= duration_ms * 8 * 2 * 9 / 10,
        "the file holds what the event reports"
    );
    assert_no_more_finished(&events, Duration::from_millis(300)).await;

    // The other call is still there and records nothing more: it can be deleted on its own.
    let other = 1 - deleted;
    let result = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: streams[other].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    assert_no_more_finished(&events, Duration::from_millis(300)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_the_first_source_call_ends_the_recording_once_as_call_ended() {
    deleting_a_source_ends_the_recording(0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_the_second_source_call_ends_the_recording_once_as_call_ended() {
    deleting_a_source_ends_the_recording(1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_recording_by_id_ends_it_and_leaves_both_calls_alive() {
    let (engine, events, streams) = siprec_streams(2).await;
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("stopped.wav");
    let recording_id = accepted_recording_id(
        engine
            .handle(
                CLIENT,
                start_command(
                    &streams,
                    &path,
                    RecordingFormat::Wav,
                    RecordingChannels::Stereo,
                ),
            )
            .await,
    );
    speak_together(&streams, &[LOUD_NEGATIVE, QUIET_POSITIVE], 20).await;
    // Named through the *second* source: any source call reaches the recording.
    let stopped = engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: streams[1].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                recording_id: Some(recording_id.clone()),
            },
        )
        .await;
    assert!(matches!(stopped, CmdResult::Ok { .. }), "{stopped:?}");
    let (_, _, _, reason) = finished(&events).await;
    assert_eq!(reason, RecordingEndReason::Stopped);
    assert_eq!(engine.recording_count(), 0);
    for stream in &streams {
        let queried = engine
            .handle(
                CLIENT,
                Command::Query {
                    call_id: stream.call_id.clone(),
                    from_tag: SESSION_TAG.into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(
            !matches!(queried, CmdResult::Error { .. }),
            "{} is still a live call: {queried:?}",
            stream.call_id
        );
    }
    // A second stop names a recording that no longer exists.
    let again = engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: streams[0].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                recording_id: Some(recording_id),
            },
        )
        .await;
    assert!(matches!(again, CmdResult::Error { .. }), "{again:?}");
    assert_no_more_finished(&events, Duration::from_millis(300)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_does_not_own_every_source_cannot_stop_the_recording() {
    let (engine, _events, streams) = siprec_streams(2).await;
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("owned.wav");
    let recording_id = accepted_recording_id(
        engine
            .handle(
                CLIENT,
                start_command(
                    &streams,
                    &path,
                    RecordingFormat::Wav,
                    RecordingChannels::Stereo,
                ),
            )
            .await,
    );
    let stranger = ClientId(2);
    let _stranger_events = engine.register_client(stranger);
    let refused = engine
        .handle(
            stranger,
            Command::StopRecording {
                call_id: streams[0].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                recording_id: Some(recording_id.clone()),
            },
        )
        .await;
    assert!(matches!(refused, CmdResult::Error { .. }), "{refused:?}");
    assert_eq!(engine.recording_count(), 1, "the owner's recording runs on");
    engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: streams[0].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                recording_id: Some(recording_id),
            },
        )
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_source_recording_that_is_not_allowed_is_refused_and_touches_nothing() {
    let (engine, _events, streams) = siprec_streams(9).await;
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("refused.wav");
    let start =
        |streams: &[Stream], format, channels| start_command(streams, &path, format, channels);

    // Nine sources.
    let reason = error_reason(
        engine
            .handle(
                CLIENT,
                start(&streams, RecordingFormat::Wav, RecordingChannels::Mono),
            )
            .await,
    );
    assert!(reason.contains("2 to 8"), "{reason}");
    // Stereo has two channels.
    let reason = error_reason(
        engine
            .handle(
                CLIENT,
                start(
                    &streams[..3],
                    RecordingFormat::Wav,
                    RecordingChannels::Stereo,
                ),
            )
            .await,
    );
    assert!(reason.contains("exactly 2"), "{reason}");
    // Only the audio each call received.
    for direction in [RecordingDirection::Egress, RecordingDirection::Both] {
        let Command::StartRecording {
            call_id,
            from_tag,
            additional_sources,
            ..
        } = start(&streams[..2], RecordingFormat::Wav, RecordingChannels::Mono)
        else {
            unreachable!()
        };
        let reason = error_reason(
            engine
                .handle(
                    CLIENT,
                    Command::StartRecording {
                        call_id,
                        from_tag,
                        recording_dir: None,
                        format: Some(RecordingFormat::Wav),
                        direction: Some(direction),
                        channels: None,
                        max_duration_ms: None,
                        silence_ms: None,
                        path: Some(path.to_string_lossy().into_owned()),
                        bitrate_bps: None,
                        additional_sources,
                    },
                )
                .await,
        );
        assert!(reason.contains("ingress"), "{reason}");
    }
    // A raw capture is not decoded audio.
    let reason = error_reason(
        engine
            .handle(
                CLIENT,
                start(
                    &streams[..2],
                    RecordingFormat::Pcap,
                    RecordingChannels::Mono,
                ),
            )
            .await,
    );
    assert!(reason.contains("pcap"), "{reason}");
    // The same (call_id, from_tag) twice.
    let mut twice = start_command(
        &streams[..2],
        &path,
        RecordingFormat::Wav,
        RecordingChannels::Mono,
    );
    if let Command::StartRecording {
        additional_sources, ..
    } = &mut twice
    {
        additional_sources[0] = RecordingSource {
            call_id: streams[0].call_id.clone(),
            from_tag: SESSION_TAG.into(),
        };
    }
    let reason = error_reason(engine.handle(CLIENT, twice).await);
    assert!(reason.contains("twice"), "{reason}");
    // A call nobody has.
    let mut unknown = start_command(
        &streams[..2],
        &path,
        RecordingFormat::Wav,
        RecordingChannels::Mono,
    );
    if let Command::StartRecording {
        additional_sources, ..
    } = &mut unknown
    {
        additional_sources[0].call_id = "no-such-call".into();
    }
    let reason = error_reason(engine.handle(CLIENT, unknown).await);
    assert!(reason.contains("unknown call"), "{reason}");
    // A call another client owns is as unknown as one nobody has.
    let stranger = ClientId(2);
    let _stranger_events = engine.register_client(stranger);
    let reason = error_reason(
        engine
            .handle(
                stranger,
                start(&streams[..2], RecordingFormat::Wav, RecordingChannels::Mono),
            )
            .await,
    );
    assert!(reason.contains("unknown call"), "{reason}");

    assert_eq!(engine.recording_count(), 0, "no refusal left a recording");
    assert!(!path.exists(), "no refusal created the file");
}

#[tokio::test]
async fn node_info_advertises_multi_source_recording_and_tee() {
    let cluster = std::sync::Arc::new(crate::cluster::ClusterState::new(
        "rtp-test-multi-source".to_string(),
        100,
        vec!["203.0.113.12".to_string()],
    ));
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_cluster(cluster);
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("expected node_info result");
    };
    for feature in ["record_multi_source", "ws_tee_multi_source"] {
        assert!(
            node.features.iter().any(|name| name == feature),
            "{feature}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_source_that_renegotiates_keeps_its_channel_in_the_same_file() {
    // The second source is an ordinary two-party relay whose caller is what gets recorded. Its answer
    // is repeated (RFC 3264 §8), which replaces the call's media actor and the recording sink on it:
    // the file, the mixer and the other source must carry on, and the channel must not go quiet.
    let (engine, events, mut streams) = siprec_streams(1).await;
    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "relay".into(),
                from_tag: SESSION_TAG.into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }), "{offer:?}");
    let answer_command = || Command::Answer {
        call_id: "relay".into(),
        from_tag: SESSION_TAG.into(),
        to_tag: "tag-b".into(),
        sdp: sdp_single_codec(addr_b, 0, "PCMU"),
        profile: Default::default(),
    };
    let answer = engine.handle(CLIENT, answer_command()).await;
    let near = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer")
        .remote_rtp;
    streams.push(Stream::from_parts("relay", phone_a, near));

    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("renegotiated.wav");
    let recording_id = accepted_recording_id(
        engine
            .handle(
                CLIENT,
                start_command(
                    &streams,
                    &path,
                    RecordingFormat::Wav,
                    RecordingChannels::Stereo,
                ),
            )
            .await,
    );
    speak_together(&streams, &[LOUD_NEGATIVE, QUIET_POSITIVE], 20).await;
    let reanswered = engine.handle(CLIENT, answer_command()).await;
    assert!(matches!(reanswered, CmdResult::Ok { .. }), "{reanswered:?}");
    assert_eq!(engine.recording_count(), 1, "the renegotiation kept it");
    for sequence in 20..60u16 {
        streams[0].send(sequence, LOUD_NEGATIVE).await;
        streams[1].send(sequence, QUIET_POSITIVE).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: streams[0].call_id.clone(),
                from_tag: SESSION_TAG.into(),
                recording_id: Some(recording_id),
            },
        )
        .await;
    let (_, file, _, reason) = finished(&events).await;
    assert_eq!(reason, RecordingEndReason::Stopped);
    let (samples, _) = read_wav(&file);
    // The last 400 ms, which are after the renegotiation, still carry both channels.
    let tail = &samples[samples.len() - 2 * 3200..];
    assert!(
        tail.chunks(2).filter(|pair| pair[0] < -30_000).count() >= 1_500,
        "the first stream is still recorded"
    );
    assert!(
        tail.chunks(2)
            .filter(|pair| (1_500..2_200).contains(&pair[1]))
            .count()
            >= 1_500,
        "the renegotiated stream is still recorded"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bot_cannot_take_over_a_call_that_is_a_source_of_a_recording() {
    // The takeover would replace the call's media actor and with it the recording's sink, so one
    // channel would go silent without anything saying so. It is refused instead.
    let (engine, _events, streams) = siprec_streams(2).await;
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("takeover.wav");
    accepted_recording_id(
        engine
            .handle(
                CLIENT,
                start_command(
                    &streams,
                    &path,
                    RecordingFormat::Wav,
                    RecordingChannels::Stereo,
                ),
            )
            .await,
    );
    let (uri, _frames) = tee_server().await;
    for stream in &streams {
        let reason = error_reason(
            engine
                .handle(
                    CLIENT,
                    Command::AttachWsBridge {
                        call_id: stream.call_id.clone(),
                        from_tag: SESSION_TAG.into(),
                        ws_uri: uri.clone(),
                        profile: None,
                    },
                )
                .await,
        );
        assert!(reason.contains("anchor-busy"), "{reason}");
    }
    assert_eq!(engine.recording_count(), 1, "the recording runs on");
}
