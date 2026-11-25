//! EVS has a decoder and no encoder, so what the engine does with an EVS leg has two halves:
//! whatever only needs the audio works, and whatever needs EVS to be *sent* is refused with the
//! reason, never answered and left silent.
//!
//! - A relay of EVS to EVS runs no codec, in any build, and forwards every packet as it arrived.
//! - With the `evs` feature, a WebSocket tee, a decoded recording (`start_recording`, and the
//!   `record_call` profile) decode the leg's audio in both payload formats of TS 26.445 Annex A.
//! - A call that would transcode to or from EVS, a leg that needs the audio put back (noise
//!   suppression, echo cancellation, a WebSocket takeover, a conference seat) is refused with the
//!   codec factory's own reason, which names the missing encoder.
//! - EVS is never offered as a transcode target and is not a capability the node advertises.

use super::tee_undecodable::{relay_on, rtp_packet};
use super::*;

const EVS_PAYLOAD_TYPE: u8 = 110;

/// The media section of an EVS leg with `a=fmtp` parameters (`bw=nb-wb` keeps the decoder at
/// 16 kHz, which is what the audio checks below count samples at).
fn evs_media(fmtp: &'static str) -> impl Fn(SocketAddr) -> String {
    move |addr: SocketAddr| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP {pt}\r\na=rtpmap:{pt} EVS/16000\r\n\
             a=fmtp:{pt} {fmtp}\r\na=rtcp-mux\r\n",
            ip = addr.ip(),
            port = addr.port(),
            pt = EVS_PAYLOAD_TYPE,
        )
    }
}

/// `count` pseudo-random octets: any bit pattern decodes, which is what the decoder is held to.
fn noise(count: usize, seed: u32) -> Vec<u8> {
    let mut state = seed | 1;
    (0..count)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

/// A header-full payload of one 13.2 kbit/s frame: the table-of-contents octet and 33 octets.
fn header_full_13k2(seed: u32) -> Vec<u8> {
    let mut payload = vec![0x04];
    payload.extend(noise(33, seed));
    payload.push(0); // 35 octets: not the size of any compact payload
    payload
}

/// A compact payload of one 13.2 kbit/s frame: 264 bits and nothing else.
fn compact_13k2(seed: u32) -> Vec<u8> {
    noise(33, seed)
}

/// A header-full payload of one AMR-WB IO 12.65 kbit/s frame (Q set), in the AMR-WB bit order.
fn header_full_io_12k65(seed: u32) -> Vec<u8> {
    let mut payload = vec![0xFF, 0x32];
    payload.extend(noise(32, seed));
    payload
}

fn evs_packet(sequence: u16, payload: &[u8]) -> Vec<u8> {
    rtp_packet(
        EVS_PAYLOAD_TYPE,
        sequence,
        u32::from(sequence) * 320,
        0x0E0E_0E0E,
        payload,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_evs_relay_forwards_every_packet_and_decodes_nothing() {
    // Holds in every build, `evs` or not: a relay never reaches the codec factory.
    let (engine, (phone_a, near_addr), (phone_b, _far_addr)) =
        relay_on("evs-relay", evs_media("bw=nb-wb"), evs_media("bw=nb-wb")).await;
    let payloads = [
        header_full_13k2(1),
        compact_13k2(2),
        header_full_io_12k65(3),
        vec![0x0F],
        vec![0x0D, 1, 2, 3], // a reserved frame type: relayed all the same, the engine does not read it
        Vec::new(),
    ];
    for (index, payload) in payloads.iter().enumerate() {
        let packet = evs_packet(index as u16, payload);
        phone_a.send_to(&packet, near_addr).await.expect("a send");
        let (received, _) = recv(&phone_b).await;
        assert_eq!(received, packet, "packet {index} is relayed as it arrived");
    }
    assert!(
        !engine.media().is_media_call("evs-relay"),
        "an EVS relay is the in-kernel forward: no media actor, no codec"
    );
    assert_eq!(
        engine
            .calls
            .get("evs-relay")
            .expect("call present")
            .pipeline,
        PipelineKind::Passthrough
    );
}

#[cfg(feature = "evs")]
mod decoding {
    use super::super::tee_undecodable::{
        assert_relayed_verbatim, attach_caller_tee, detach_and_count,
    };
    use super::*;
    use siphon_rtp_proto::{RecordingDirection, RecordingEndReason, RecordingFormat};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_ws_tee_hears_an_evs_leg_in_both_payload_formats_and_the_relay_is_untouched() {
        let (engine, (phone_a, near_addr), (phone_b, _far_addr)) =
            relay_on("evs-tee", evs_media("bw=nb-wb"), evs_media("bw=nb-wb")).await;
        let events = engine.register_client(CLIENT);
        let frames = attach_caller_tee(&engine, "evs-tee").await;

        // Six payloads the decoder takes (header-full, compact, AMR-WB IO, a two-frame packet, a
        // SID and a NO_DATA, which conceal or comfort noise) and two it cannot: a reserved frame
        // type and a table of contents longer than the packet.
        let mut two_frames = vec![0x44, 0x04];
        two_frames.extend(noise(66, 9));
        let mut sid = vec![0x0C];
        sid.extend(noise(6, 10));
        let payloads: Vec<(Vec<u8>, bool)> = vec![
            (header_full_13k2(1), true),
            (compact_13k2(2), true),
            (header_full_io_12k65(3), true),
            (two_frames, true),
            (sid, true),
            (vec![0x0F], true),
            (vec![0x0D, 1, 2, 3], false),
            (vec![0x04, 1, 2], false),
        ];
        let packets: Vec<Vec<u8>> = payloads
            .iter()
            .enumerate()
            .map(|(index, (payload, _))| evs_packet(index as u16, payload))
            .collect();
        assert_relayed_verbatim((&phone_a, near_addr), &phone_b, &packets).await;

        // the tee's frames are the decoder's 16 kHz PCM, 20 ms of 16-bit samples each
        let audio = next_tee_audio(&frames).await;
        assert_eq!(audio.len(), 640, "one 20 ms frame at 16 kHz");
        assert!(audio.iter().any(|&octet| octet != 0), "the tee hears audio");

        let (sent, dropped) = detach_and_count(&engine, &events, "evs-tee").await;
        let decodable = payloads.iter().filter(|(_, decodable)| *decodable).count() as u64;
        assert_eq!(
            sent,
            decodable + 1,
            "one tee frame per decodable packet, the two-frame packet counting for two"
        );
        assert_eq!(
            dropped, 2,
            "the two payloads that are not EVS count against the tee"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_decoded_recording_of_an_evs_call_holds_its_audio() {
        let (engine, (phone_a, near_addr), (phone_b, _far_addr)) =
            relay_on("evs-record", evs_media("bw=nb-wb"), evs_media("bw=nb-wb")).await;
        let events = engine.register_client(CLIENT);
        let directory = tempfile::tempdir().expect("tempdir");
        let started = engine
            .handle(
                CLIENT,
                Command::StartRecording {
                    call_id: "evs-record".into(),
                    from_tag: "tag-a".into(),
                    recording_dir: Some(directory.path().display().to_string()),
                    format: Some(RecordingFormat::Wav),
                    direction: Some(RecordingDirection::Ingress),
                    channels: None,
                    max_duration_ms: None,
                    silence_ms: None,
                    path: None,
                    bitrate_bps: None,
                    additional_sources: Vec::new(),
                },
            )
            .await;
        let recording_id = match started {
            CmdResult::Ok {
                recording_id: Some(id),
                ..
            } => id,
            other => panic!("an EVS leg records: {other:?}"),
        };
        let packets: Vec<Vec<u8>> = (0..30u16)
            .map(|sequence| {
                evs_packet(
                    sequence,
                    &if sequence % 2 == 0 {
                        header_full_13k2(u32::from(sequence))
                    } else {
                        compact_13k2(u32::from(sequence))
                    },
                )
            })
            .collect();
        assert_relayed_verbatim((&phone_a, near_addr), &phone_b, &packets).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let stopped = engine
            .handle(
                CLIENT,
                Command::StopRecording {
                    call_id: "evs-record".into(),
                    from_tag: "tag-a".into(),
                    recording_id: Some(recording_id.clone()),
                },
            )
            .await;
        assert!(matches!(stopped, CmdResult::Ok { .. }), "stop: {stopped:?}");
        let (finished_id, path, duration_ms, reason) = next_recording_finished(&events)
            .await
            .expect("a recording_finished event arrives");
        assert_eq!(finished_id, recording_id);
        assert_eq!(reason, RecordingEndReason::Stopped);
        let bytes = std::fs::read(path.expect("the file")).expect("the file exists");
        let wav = siphon_rtp_media::player::WavSource::parse(&bytes).expect("a valid WAV");
        assert_eq!(wav.sample_rate_hz(), 16_000, "the decoder's own rate");
        assert_eq!(wav.samples().len(), 30 * 320, "20 ms of audio per packet");
        assert!(duration_ms >= 590, "{duration_ms} ms of audio");
        assert!(wav.samples().iter().any(|&sample| sample != 0));
    }

    /// `record_call` on EVS: nothing decodes and re-encodes, because there is no encoder to do it
    /// with, and nothing needs to. The call stays a relay, each party is decoded beside it into its
    /// own file, and what the parties hear is what they were sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn record_call_on_an_evs_call_records_both_parties_off_a_relay() {
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
        let directory = tempfile::tempdir().expect("tempdir");
        let offered = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "evs-rc".into(),
                    from_tag: "tag-a".into(),
                    sdp: evs_media("bw=nb-wb")(addr_a),
                    profile: Default::default(),
                },
            )
            .await;
        let far_addr = sdp::parse(&ok_sdp_text(&offered))
            .expect("offer")
            .remote_rtp;
        let answered = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "evs-rc".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: evs_media("bw=nb-wb")(addr_b),
                    profile: ProfileFlags {
                        record_call: true,
                        record_path: Some(directory.path().display().to_string()),
                        ..Default::default()
                    },
                },
            )
            .await;
        assert!(
            matches!(answered, CmdResult::Ok { .. }),
            "an EVS call is recorded, not refused: {answered:?}"
        );
        let near_addr = sdp::parse(&ok_sdp_text(&answered))
            .expect("answer")
            .remote_rtp;
        {
            // held in userspace by the recording as a promoted relay (its in-kernel `Forward` rules
            // are what a demotion puts back), not rebuilt as a decode and re-encode pipeline
            let call = engine.calls.get("evs-rc").expect("call");
            assert!(
                !call.relay_flows.is_empty(),
                "a promoted relay keeps its flows"
            );
            assert!(call
                .promotion_reasons
                .contains(&PromotionReason::AudioRecording));
        }

        for sequence in 0..20u16 {
            let toward_b = evs_packet(sequence, &header_full_13k2(u32::from(sequence)));
            phone_a.send_to(&toward_b, near_addr).await.expect("a send");
            assert_eq!(recv(&phone_b).await.0, toward_b, "B hears what A sent");
            let toward_a = evs_packet(sequence, &compact_13k2(100 + u32::from(sequence)));
            phone_b.send_to(&toward_a, far_addr).await.expect("b send");
            assert_eq!(recv(&phone_a).await.0, toward_a, "A hears what B sent");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: "evs-rc".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        let mut finished = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while finished.len() < 2 {
            let Ok(Ok(event)) = tokio::time::timeout_at(deadline, events.recv_async()).await else {
                break;
            };
            if let Event::RecordingFinished {
                recording_id, path, ..
            } = event
            {
                finished.push((recording_id, path));
            }
        }
        finished.sort();
        assert_eq!(
            finished
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            ["evs-rc-a", "evs-rc-b"]
        );
        for (id, path) in finished {
            let bytes = std::fs::read(path.expect("the file")).expect("the file exists");
            let wav = siphon_rtp_media::player::WavSource::parse(&bytes).expect("a valid WAV");
            assert_eq!(wav.sample_rate_hz(), 16_000, "{id}");
            assert_eq!(
                wav.samples().len(),
                20 * 320,
                "{id}: one frame per packet that party sent"
            );
            assert!(wav.samples().iter().any(|&sample| sample != 0), "{id}");
        }
    }

    /// What needs the audio put back is refused with the factory's reason on an untouched call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn what_needs_an_evs_encoder_is_refused_with_the_missing_encoder_as_the_reason() {
        use crate::srtp_bridge::run_redirect_dispatcher;
        for (name, profile) in [
            (
                "noise suppression",
                ProfileFlags {
                    noise_suppression: true,
                    ..Default::default()
                },
            ),
            (
                "echo cancellation",
                ProfileFlags {
                    echo_cancellation: true,
                    ..Default::default()
                },
            ),
            (
                "beep detection",
                ProfileFlags {
                    beep_detection: true,
                    ..Default::default()
                },
            ),
        ] {
            let engine = Engine::new(UdpLoopbackDatapath::new());
            tokio::spawn(run_redirect_dispatcher(
                engine.datapath().rx(),
                engine.bridge(),
                engine.media(),
                engine.ws(),
                engine.conference(),
                None,
            ));
            let (_phone_a, addr_a) = phone().await;
            let (_phone_b, addr_b) = phone().await;
            engine
                .handle(
                    CLIENT,
                    Command::Offer {
                        call_id: "evs-refused".into(),
                        from_tag: "tag-a".into(),
                        sdp: evs_media("bw=nb-wb")(addr_a),
                        profile: Default::default(),
                    },
                )
                .await;
            let answered = engine
                .handle(
                    CLIENT,
                    Command::Answer {
                        call_id: "evs-refused".into(),
                        from_tag: "tag-a".into(),
                        to_tag: "tag-b".into(),
                        sdp: evs_media("bw=nb-wb")(addr_b),
                        profile,
                    },
                )
                .await;
            match answered {
                CmdResult::Error { reason } => {
                    assert!(reason.contains("EVS/16000"), "{name}: {reason}");
                    assert!(
                        reason.contains("there is no EVS encoder"),
                        "{name}: {reason}"
                    );
                }
                other => panic!(
                    "{name} on EVS needs the audio re-encoded and must be refused: {other:?}"
                ),
            }
            assert!(!engine.media().is_media_call("evs-refused"), "{name}");
        }
    }

    /// Echo and prompts put audio back on the leg: a relay held for them is decoded and re-encoded,
    /// which an EVS call cannot do. The verb is refused with the missing encoder and the call is
    /// left forwarding exactly as before.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn echo_and_prompts_on_an_evs_leg_are_refused_and_the_relay_goes_on() {
        let (engine, (phone_a, near_addr), (phone_b, _far_addr)) =
            relay_on("evs-echo", evs_media("bw=nb-wb"), evs_media("bw=nb-wb")).await;
        for (name, command) in [
            (
                "echo",
                Command::Echo {
                    call_id: "evs-echo".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                    enabled: true,
                },
            ),
            (
                "play media",
                Command::PlayMedia {
                    call_id: "evs-echo".into(),
                    from_tag: "tag-a".into(),
                    source: PlayMediaSource::Tone {
                        tone: "ringback_eu".into(),
                    },
                    repeat_times: None,
                    start_pos_ms: None,
                    duration_ms: None,
                    overlay: false,
                    gain_decibels: None,
                    to_tag: None,
                },
            ),
        ] {
            match engine.handle(CLIENT, command).await {
                CmdResult::Error { reason } => assert!(
                    reason.contains("there is no EVS encoder"),
                    "{name}: {reason}"
                ),
                other => panic!("{name} needs the leg encoded and must be refused: {other:?}"),
            }
        }
        let packet = evs_packet(3, &header_full_13k2(3));
        phone_a.send_to(&packet, near_addr).await.expect("a send");
        assert_eq!(
            recv(&phone_b).await.0,
            packet,
            "the call was left as it was"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_websocket_takeover_of_an_evs_leg_is_refused_and_the_relay_goes_on() {
        let (engine, (phone_a, near_addr), (phone_b, _far_addr)) =
            relay_on("evs-takeover", evs_media("bw=nb-wb"), evs_media("bw=nb-wb")).await;
        let attached = engine
            .handle(
                CLIENT,
                Command::AttachWsBridge {
                    call_id: "evs-takeover".into(),
                    from_tag: "tag-a".into(),
                    ws_uri: "ws://192.0.2.1:9/unreachable".into(),
                    profile: None,
                },
            )
            .await;
        match attached {
            CmdResult::Error { reason } => {
                assert!(reason.contains("there is no EVS encoder"), "{reason}");
            }
            other => {
                panic!("a takeover sends audio back to the leg, EVS cannot be sent: {other:?}")
            }
        }
        assert!(!engine.ws().is_ws_call("evs-takeover"));
        let packet = evs_packet(7, &header_full_13k2(7));
        phone_a.send_to(&packet, near_addr).await.expect("a send");
        assert_eq!(
            recv(&phone_b).await.0,
            packet,
            "the call was left as it was"
        );
    }
}

/// With the `evs` feature a G.711 side and an EVS side are a transcode the engine cannot do: the
/// answer is refused and names the EVS encoder, in either direction.
#[cfg(feature = "evs")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_g711_to_evs_call_is_refused_in_both_directions_with_the_encoder_as_the_reason() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    for (evs_first, pcma_first) in [(true, false), (false, true)] {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        tokio::spawn(run_redirect_dispatcher(
            engine.datapath().rx(),
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        let (offer, answer): (String, String) = if evs_first {
            (
                evs_media("bw=nb-wb")(addr_a),
                sdp_single_codec(addr_b, 8, "PCMA"),
            )
        } else {
            (
                sdp_single_codec(addr_a, 8, "PCMA"),
                evs_media("bw=nb-wb")(addr_b),
            )
        };
        assert_ne!(evs_first, pcma_first);
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: "mixed".into(),
                    from_tag: "tag-a".into(),
                    sdp: offer,
                    profile: Default::default(),
                },
            )
            .await;
        let answered = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "mixed".into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: answer,
                    profile: Default::default(),
                },
            )
            .await;
        match answered {
            CmdResult::Error { reason } => {
                assert!(
                    reason.contains("EVS/16000") && reason.contains("PCMA/8000"),
                    "{reason}"
                );
                assert!(reason.contains("there is no EVS encoder"), "{reason}");
            }
            other => panic!("EVS to G.711 is a transcode and cannot be answered: {other:?}"),
        }
    }
}

/// EVS is never a codec this engine offers to transcode to, and not one the node advertises.
#[test]
fn evs_is_neither_a_transcode_target_nor_an_advertised_capability() {
    assert!(super::transcode_codec_specs("EVS").is_empty());
    assert!(super::transcode_codec_specs("evs").is_empty());
    let codecs = super::supported_codecs();
    assert!(
        !codecs.iter().any(|name| name.eq_ignore_ascii_case("EVS")),
        "{codecs:?}"
    );
}
