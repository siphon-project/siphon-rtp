//! A WebSocket tee on a single-leg call that answered a `sendonly` offer — one stream of a SIPREC
//! recording session (RFC 7866 §6: the SRC sends, the SRS only receives) answered as its own
//! `answer_local` call. The tee must stream what the party sends, and the engine must send it no
//! media back: an answer to `sendonly` is `recvonly` (RFC 3264 §6.1).

use super::*;

pub(super) fn sendonly_offer(rtp: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendonly\r\na=rtcp-mux\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tee_on_a_call_that_answered_a_sendonly_offer_streams_it_and_sends_nothing_back() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (sender, sender_addr) = phone().await;
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "siprec-stream".into(),
                from_tag: "tag-a".into(),
                sdp: sendonly_offer(sender_addr),
                profile: Default::default(),
            },
        )
        .await;
    let answer = ok_sdp_text(&answered);
    assert!(
        answer.contains("a=recvonly") && !answer.contains("a=sendonly"),
        "the answer to a sendonly offer is recvonly: {answer}"
    );
    let engine_near = sdp::parse(&answer).expect("answer sdp").remote_rtp;

    let (uri, frames) = tee_server().await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: "siprec-stream".into(),
                from_tag: "tag-a".into(),
                ws_uri: uri,
                direction: WsTeeDirection::Caller,
                channels: None,
                sample_rate: None,
                additional_sources: Vec::new(),
            },
        )
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    expect_tee_start(&frames).await;

    // µ-law 0x00: the loudest negative level, so the tee's audio is unmistakably this stream's.
    for sequence in 0..15u16 {
        sender
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0x00), engine_near)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let audio = next_tee_audio(&frames).await;
    let samples: Vec<i16> = audio
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| i16::from_le_bytes(*pair))
        .collect();
    assert!(
        samples.iter().any(|&sample| sample < -4000),
        "the tee streams what the sender sent"
    );

    // Nothing but RTCP may come back: a receiver report is legitimate on a recvonly leg, RTP is
    // not (RFC 5761 §4: RTCP packet types 200..=204 sit in the second byte).
    let mut buffer = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
    while let Ok(Ok((len, from))) =
        tokio::time::timeout_at(deadline, sender.recv_from(&mut buffer)).await
    {
        // Only what this engine's own socket sends is the engine's doing. The suite binds hundreds
        // of loopback sockets on ephemeral ports, so under load a port can be handed to this
        // sender just after a neighbouring test's engine, whose comfort-noise actor outlives that
        // test's phone socket by a runtime teardown, was still sending to it: a datagram from any
        // other source says nothing about this call.
        if from != engine_near {
            continue;
        }
        let is_rtcp = len >= 2 && (200..=204).contains(&buffer[1]);
        assert!(
            is_rtcp,
            "the engine sent RTP toward a sendonly party ({len} bytes) from {from} (engine_near={engine_near} sender={:?}): {:02x?}",
            sender.local_addr(),
            &buffer[..len.min(24)]
        );
    }
}

#[tokio::test]
async fn node_info_advertises_that_answer_local_honours_the_offered_direction() {
    // The behaviour above is the engine's, not the contract crate's, so a controller cannot require
    // it through a dependency version; it checks this before answering a SIPREC stream locally.
    let cluster = std::sync::Arc::new(crate::cluster::ClusterState::new(
        "rtp-test-direction".to_string(),
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
        .any(|feature| feature == "answer_local_direction"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recording_on_a_call_that_answered_a_sendonly_offer_records_it_and_sends_nothing_back() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_proto::{RecordingDirection, RecordingEndReason, RecordingFormat};
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let events = engine.register_client(CLIENT);
    let (sender, sender_addr) = phone().await;
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "siprec-record".into(),
                from_tag: "tag-a".into(),
                sdp: sendonly_offer(sender_addr),
                profile: Default::default(),
            },
        )
        .await;
    let answer = ok_sdp_text(&answered);
    assert!(answer.contains("a=recvonly"), "{answer}");
    let engine_near = sdp::parse(&answer).expect("answer sdp").remote_rtp;

    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("stream.wav");
    let started = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: "siprec-record".into(),
                from_tag: "tag-a".into(),
                recording_dir: None,
                format: Some(RecordingFormat::Wav),
                direction: Some(RecordingDirection::Ingress),
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: Some(path.to_string_lossy().into_owned()),
                bitrate_bps: None,
                additional_sources: Vec::new(),
            },
        )
        .await;
    let CmdResult::Ok {
        recording_id: Some(recording_id),
        ..
    } = started
    else {
        panic!("the recording starts on a sendonly local answer: {started:?}");
    };

    // µ-law 0x00: the loudest negative level, so the file's audio is unmistakably this stream's.
    for sequence in 0..25u16 {
        sender
            .send_to(&g711_rtp(0, sequence, 0x0B0B_0B0B, 0x00), engine_near)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: "siprec-record".into(),
                from_tag: "tag-a".into(),
                recording_id: Some(recording_id.clone()),
            },
        )
        .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let finished = loop {
        match tokio::time::timeout_at(deadline, events.recv_async()).await {
            Ok(Ok(Event::RecordingFinished {
                recording_id: id,
                duration_ms,
                reason,
                ..
            })) if id == recording_id => break (duration_ms, reason),
            Ok(Ok(_)) => {}
            other => panic!("no recording_finished: {other:?}"),
        }
    };
    assert_eq!(finished.1, RecordingEndReason::Stopped);
    assert!(finished.0 >= 300, "{} ms recorded", finished.0);

    let bytes = std::fs::read(&path).expect("the wav is written before recording_finished");
    let data = bytes
        .windows(4)
        .position(|window| window == b"data")
        .expect("a data chunk")
        + 8;
    let samples: Vec<i16> = bytes[data..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| i16::from_le_bytes(*pair))
        .collect();
    assert!(
        samples.iter().any(|&sample| sample < -4000),
        "the recording holds what the sendonly party sent"
    );

    // Nothing at all may come back toward a sendonly party: no RTP (RFC 3264 §6.1).
    let mut buffer = [0u8; 2048];
    let quiet = tokio::time::Instant::now() + Duration::from_millis(400);
    while let Ok(Ok((len, from))) =
        tokio::time::timeout_at(quiet, sender.recv_from(&mut buffer)).await
    {
        // Only what this engine's own socket sends is the engine's doing. The suite binds hundreds
        // of loopback sockets on ephemeral ports, so under load a port can be handed to this
        // sender just after a neighbouring test's engine, whose comfort-noise actor outlives that
        // test's phone socket by a runtime teardown, was still sending to it: a datagram from any
        // other source says nothing about this call.
        if from != engine_near {
            continue;
        }
        let is_rtcp = len >= 2 && (200..=204).contains(&buffer[1]);
        assert!(
            is_rtcp,
            "the engine sent RTP toward a sendonly party ({len} bytes) from {from} (engine_near={engine_near} sender={:?}): {:02x?}",
            sender.local_addr(),
            &buffer[..len.min(24)]
        );
    }
}

#[tokio::test]
async fn a_sendonly_callers_pipeline_starts_with_its_egress_already_withheld() {
    // RFC 3264 §6.1: the actor's first playout tick fires the moment it is registered, so a control
    // message sent after the promotion can lose the race and let one comfort-noise frame out toward
    // a party that only sends. The state has to be the one the actor starts in.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_sender, addr) = phone().await;
    for (call_id, direction, withheld) in [
        ("sendonly-start", "sendonly", true),
        ("inactive-start", "inactive", true),
        ("sendrecv-start", "sendrecv", false),
        // The reverse: a party that only receives is answered `sendonly` and sent media at once.
        ("recvonly-start", "recvonly", false),
    ] {
        let sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na={direction}\r\n",
            ip = addr.ip(),
            port = addr.port(),
        );
        let result = engine
            .handle(
                CLIENT,
                Command::AnswerLocal {
                    call_id: call_id.into(),
                    from_tag: "tag-a".into(),
                    sdp,
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
        assert_eq!(
            engine.media().started_withholding_egress(call_id),
            Some(withheld),
            "{direction}"
        );
    }
}

#[tokio::test]
async fn a_call_that_answered_a_recvonly_offer_is_sent_media_from_the_engines_own_socket() {
    // The reverse of the withheld egress, and the proof the source filter above cannot hide a real
    // send: the engine answers `recvonly` with `sendonly` and its idle stream reaches that party
    // from the very address the answer advertised (RFC 3264 §6.1).
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (receiver, receiver_addr) = phone().await;
    let sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=recvonly\r\na=rtcp-mux\r\n",
        ip = receiver_addr.ip(),
        port = receiver_addr.port(),
    );
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "recvonly-sent".into(),
                from_tag: "tag-a".into(),
                sdp,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let answer = ok_sdp_text(&answered);
    assert!(answer.contains("a=sendonly"), "{answer}");
    let engine_near = sdp::parse(&answer).expect("answer sdp").remote_rtp;
    let mut buffer = [0u8; 2048];
    let (len, from) = tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buffer))
        .await
        .expect("a recvonly party is sent its idle stream")
        .expect("recv");
    assert_eq!(from, engine_near);
    assert!(len >= 12, "{len} bytes");
}
