//! `start_recording` with `format: "ogg_opus"`: the decoded recording a `wav` one makes,
//! Opus-encoded into an Ogg file.
//!
//! The audio checks decode with `opusdec` (opus-tools), an independent decoder that reads through
//! libogg and libopusfile, so a bug shared by our writer and our own decoder cannot pass them. They
//! skip that part when opus-tools is not installed, as the Wireshark-backed tests do.

use super::*;
use siphon_rtp_proto::{RecordingChannels, RecordingDirection, RecordingFormat};

/// A `start_recording` on `call_id`, with everything but the format knobs left to defaults.
fn start(
    call_id: &str,
    directory: &std::path::Path,
    format: RecordingFormat,
    channels: RecordingChannels,
    bitrate_bps: Option<u32>,
) -> Command {
    Command::StartRecording {
        call_id: call_id.into(),
        from_tag: "tag-a".into(),
        recording_dir: Some(directory.to_string_lossy().into_owned()),
        format: Some(format),
        direction: Some(RecordingDirection::Ingress),
        channels: Some(channels),
        max_duration_ms: None,
        silence_ms: None,
        path: None,
        bitrate_bps,
    }
}

/// One 20 ms µ-law frame of a sine at `hz`, continuing from frame `index`.
fn tone_packet(sequence: u16, ssrc: u32, hz: f32) -> Vec<u8> {
    let pcm: Vec<i16> = (0..160)
        .map(|offset| {
            let index = usize::from(sequence) * 160 + offset;
            let phase = 2.0 * std::f32::consts::PI * hz * index as f32 / 8000.0;
            (phase.sin() * 8000.0) as i16
        })
        .collect();
    ulaw_rtp_pcm(sequence, ssrc, &pcm)
}

/// Decode `path` with `opusdec` at 48 kHz, or `None` when opus-tools is not installed.
fn opusdec(path: &str) -> Option<(Vec<i16>, u16)> {
    let decoded = format!("{path}.decoded.wav");
    let output = match std::process::Command::new("opusdec")
        .args(["--quiet", "--rate", "48000", "--force-wav", path, &decoded])
        .output()
    {
        Ok(output) => output,
        Err(_) => {
            eprintln!("skipping the opusdec check: opus-tools not installed");
            return None;
        }
    };
    assert!(
        output.status.success(),
        "opusdec rejected the recording: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed = siphon_rtp_media::player::WavSource::parse(
        &std::fs::read(&decoded).expect("opusdec wrote its output"),
    )
    .expect("opusdec writes a WAV");
    assert_eq!(parsed.sample_rate_hz(), 48_000);
    Some((parsed.samples().to_vec(), parsed.channels()))
}

/// Energy at `hz` (a single DFT bin, 48 kHz samples).
fn power_at(samples: &[i16], hz: f64) -> f64 {
    let step = 2.0 * std::f64::consts::PI * hz / 48_000.0;
    let (mut real, mut imaginary) = (0.0, 0.0);
    for (index, &sample) in samples.iter().enumerate() {
        let phase = step * index as f64;
        real += f64::from(sample) * phase.cos();
        imaginary += f64::from(sample) * phase.sin();
    }
    real * real + imaginary * imaginary
}

/// The strongest frequency over 200..=1500 Hz in 5 Hz steps.
fn dominant_hz(samples: &[i16]) -> u32 {
    (40..=300u32)
        .map(|step| step * 5)
        .max_by(|&a, &b| {
            power_at(samples, f64::from(a)).total_cmp(&power_at(samples, f64::from(b)))
        })
        .expect("range")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ogg_opus_voicemail_names_an_opus_file_once_it_is_closed() {
    // The voicemail shape of the `wav` test, in the new format: a single-leg call, recording
    // started at runtime, and a completion event that names a closed `.opus` file.
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
    let (phone, addr) = phone().await;
    let engine_near = voicemail_call(&engine, "vm-opus", addr).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let started = engine
        .handle(
            CLIENT,
            start(
                "vm-opus",
                dir.path(),
                RecordingFormat::OggOpus,
                RecordingChannels::Mono,
                None,
            ),
        )
        .await;
    let recording_id = match started {
        CmdResult::Ok {
            recording_id: Some(id),
            ..
        } => id,
        other => panic!("an ogg_opus recording accepts with a recording_id, got {other:?}"),
    };

    for sequence in 0..25u16 {
        phone
            .send_to(&tone_packet(sequence, 0x0A0A_0A0A, 440.0), engine_near)
            .await
            .expect("caller send");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(80)).await;
    let stopped = engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: "vm-opus".into(),
                from_tag: "tag-a".into(),
                recording_id: Some(recording_id.clone()),
            },
        )
        .await;
    assert!(matches!(stopped, CmdResult::Ok { .. }), "{stopped:?}");

    let (finished_id, path, duration_ms, reason) = next_recording_finished(&events)
        .await
        .expect("a recording_finished event arrives");
    assert_eq!(finished_id, recording_id);
    assert_eq!(reason, siphon_rtp_proto::RecordingEndReason::Stopped);
    assert!(duration_ms > 0, "the caller's audio was recorded");
    let path = path.expect("the event names the file");
    assert!(
        path.ends_with(&format!("vm-opus-{recording_id}.opus")),
        "a generated name ends .opus (RFC 7845 §9): {path}"
    );
    let bytes = std::fs::read(&path).expect("the file exists when the event arrives");
    assert_eq!(&bytes[..4], b"OggS");
    assert_eq!(
        &bytes[28..36],
        b"OpusHead",
        "the identification header opens the stream"
    );

    if let Some((samples, channels)) = opusdec(&path) {
        assert_eq!(channels, 1);
        // The decoded length is the duration the event reported, to the sample: pre-skip and the
        // end trim are both honoured by the reference decoder.
        assert_eq!(samples.len() as u64, duration_ms * 48);
        assert!(samples.iter().any(|&sample| sample.unsigned_abs() > 1000));
    }
}

/// Record a 440 Hz caller and a 1000 Hz callee on a plain two-party call in stereo at
/// `bitrate_bps`, decode with `opusdec`, and return how far below each party's own tone the other
/// party's sits on its channel, in dB. `None` when opus-tools is not installed.
async fn stereo_separation(call_id: &str, bitrate_bps: Option<u32>) -> Option<(f64, f64)> {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    let ((phone_a, near_addr), (phone_b, far_addr)) = plain_two_party_call(&engine, call_id).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let started = engine
        .handle(
            CLIENT,
            start(
                call_id,
                dir.path(),
                RecordingFormat::OggOpus,
                RecordingChannels::Stereo,
                bitrate_bps,
            ),
        )
        .await;
    let recording_id = match started {
        CmdResult::Ok {
            recording_id: Some(id),
            ..
        } => id,
        other => panic!("accepted with an id, got {other:?}"),
    };
    for sequence in 0..60u16 {
        phone_a
            .send_to(&tone_packet(sequence, 0x0A0A_0A0A, 440.0), near_addr)
            .await
            .expect("a send");
        phone_b
            .send_to(&tone_packet(sequence, 0x0B0B_0B0B, 1000.0), far_addr)
            .await
            .expect("b send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(120)).await;
    engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                recording_id: Some(recording_id),
            },
        )
        .await;
    let (_, path, duration_ms, _) = next_recording_finished(&events)
        .await
        .expect("a recording_finished event arrives");
    let (samples, channels) = opusdec(&path.expect("the event names the file"))?;
    assert_eq!(
        channels, 2,
        "stereo was asked for and two parties were recorded"
    );
    assert_eq!(samples.len() as u64 / 2, duration_ms * 48);

    // A steady half second from the middle of the call.
    let middle = samples.len() / 2 / 2;
    let window = middle - 12_000..middle + 12_000;
    let left: Vec<i16> = samples.iter().step_by(2).copied().collect();
    let right: Vec<i16> = samples.iter().skip(1).step_by(2).copied().collect();
    let (left, right) = (&left[window.clone()], &right[window]);
    assert_eq!(dominant_hz(left), 440, "the caller is on the left");
    assert_eq!(dominant_hz(right), 1000, "the callee is on the right");
    let separation = |channel: &[i16], own: f64, other: f64| {
        10.0 * (power_at(channel, own) / power_at(channel, other)).log10()
    };
    Some((
        separation(left, 440.0, 1000.0),
        separation(right, 1000.0, 440.0),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ogg_opus_recording_keeps_the_caller_left_and_the_callee_right() {
    // The audio is the audio: each party comes back from an independent decoder on its own channel
    // at its own frequency.
    //
    // How far apart the channels stay is the codec's call, not the tee's. Opus codes stereo jointly
    // (SILK mid/side, RFC 6716 §4.2.8), and at the default 16 kbit/s per channel the side signal
    // gets few bits, so each party bleeds into the other's channel about 30 dB down — libopus' own
    // encoder measures 20-30 dB on the same input. At 128 kbit/s the bleed is gone, which is what
    // proves the tee itself keeps the parties apart (a `wav` of the same call separates them by
    // over 80 dB).
    let Some((left, right)) = stereo_separation("stereo-opus", None).await else {
        return;
    };
    assert!(
        left > 25.0 && right > 25.0,
        "at the default bitrate: left {left:.1} dB, right {right:.1} dB"
    );
    let Some((left, right)) = stereo_separation("stereo-opus-128k", Some(128_000)).await else {
        return;
    };
    assert!(
        left > 60.0 && right > 60.0,
        "at 128 kbit/s: left {left:.1} dB, right {right:.1} dB"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_misplaced_or_out_of_range_bitrate_fails_the_verb_with_the_call_untouched() {
    // A controller that asked for a bitrate it will not get must hear so: with `wav` or `pcap` the
    // bitrate is not ignored, and outside RFC 6716's range it is not clamped. Each refusal leaves
    // the call exactly as it was: no recording, no promotion out of the kernel path, no file.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let _events = engine.register_client(CLIENT);
    let _phones = plain_two_party_call(&engine, "refuse-opus").await;
    let dir = tempfile::tempdir().expect("tempdir");
    for (format, bitrate, expected) in [
        (
            RecordingFormat::Wav,
            32_000,
            "applies only to an ogg_opus recording, not wav",
        ),
        (
            RecordingFormat::Pcap,
            32_000,
            "applies only to an ogg_opus recording, not pcap",
        ),
        (RecordingFormat::OggOpus, 5_999, "outside 6000..=510000"),
        (RecordingFormat::OggOpus, 510_001, "outside 6000..=510000"),
    ] {
        let result = engine
            .handle(
                CLIENT,
                start(
                    "refuse-opus",
                    dir.path(),
                    format,
                    RecordingChannels::Mono,
                    Some(bitrate),
                ),
            )
            .await;
        match result {
            CmdResult::Error { reason } => assert!(
                reason.contains(expected),
                "{format:?} at {bitrate}: {reason}"
            ),
            other => panic!("{format:?} at {bitrate} must fail, got {other:?}"),
        }
        assert!(engine.recordings.is_empty(), "no recording was started");
        assert!(
            !engine.media().is_media_call("refuse-opus"),
            "the relay was not promoted"
        );
        assert_eq!(
            std::fs::read_dir(dir.path()).expect("dir").count(),
            0,
            "no file was created"
        );
    }

    // The bounds themselves are accepted.
    for bitrate in [6_000, 510_000] {
        let result = engine
            .handle(
                CLIENT,
                start(
                    "refuse-opus",
                    dir.path(),
                    RecordingFormat::OggOpus,
                    RecordingChannels::Mono,
                    Some(bitrate),
                ),
            )
            .await;
        assert!(
            matches!(result, CmdResult::Ok { .. }),
            "{bitrate} is in range: {result:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recording_rate_opus_cannot_take_is_refused_not_resampled() {
    // L16 at 11025 Hz decodes at 11025 Hz, which Opus does not accept as an input rate. The verb
    // fails with the call untouched instead of resampling behind the controller's back; the same
    // call records as `wav` without complaint.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let _events = engine.register_client(CLIENT);
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (_phone, addr) = phone().await;
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "l16-opus".into(),
                from_tag: "tag-a".into(),
                sdp: format!(
                    "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
                     m=audio {port} RTP/AVP 96\r\na=rtpmap:96 L16/11025\r\na=rtcp-mux\r\n",
                    ip = addr.ip(),
                    port = addr.port(),
                ),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(answered, CmdResult::Ok { .. }),
        "an L16/11025 call answers: {answered:?}"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let refused = engine
        .handle(
            CLIENT,
            start(
                "l16-opus",
                dir.path(),
                RecordingFormat::OggOpus,
                RecordingChannels::Mono,
                None,
            ),
        )
        .await;
    match refused {
        CmdResult::Error { reason } => assert!(
            reason.contains("decodes at 11025 Hz"),
            "the refusal names the rate: {reason}"
        ),
        other => panic!("an 11025 Hz recording cannot be Opus, got {other:?}"),
    }
    assert!(engine.recordings.is_empty());
    assert_eq!(std::fs::read_dir(dir.path()).expect("dir").count(), 0);

    let as_wav = engine
        .handle(
            CLIENT,
            start(
                "l16-opus",
                dir.path(),
                RecordingFormat::Wav,
                RecordingChannels::Mono,
                None,
            ),
        )
        .await;
    assert!(matches!(as_wav, CmdResult::Ok { .. }), "{as_wav:?}");
}

#[tokio::test]
async fn node_info_advertises_ogg_opus_recording() {
    // How a controller avoids sending `ogg_opus` to an engine that cannot read it: an engine that
    // predates the variant fails the whole control frame, so the controller checks this first.
    let cluster = std::sync::Arc::new(crate::cluster::ClusterState::new(
        "rtp-test-opus".to_string(),
        100,
        vec!["203.0.113.12".to_string()],
    ));
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_cluster(cluster);
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("expected node_info result");
    };
    assert!(node
        .features
        .iter()
        .any(|feature| feature == "record_ogg_opus"));
}
