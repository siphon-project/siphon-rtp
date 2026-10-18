//! A WebSocket tee is a copy of a call's audio, so nothing it does may change the call.
//!
//! On a plain relay the tee is fed from a decode of each forwarded packet, and the packet itself
//! still goes to the far party exactly as the near party sent it: same header, same payload, same
//! SSRC and sequence. A frame the tee cannot decode (a codec mode this build lacks, a corrupted
//! packet, a test UE sending filler) costs the transcript that frame and is counted in the tee's
//! `frames_dropped`; it never costs the call its audio.
//!
//! The AMR-WB cases also cover what a VoLTE handset really sends between talk spurts (RFC 4867
//! §4.3.2 and 3GPP TS 26.201): a SID frame, NO_DATA frames, a SPEECH_LOST frame, and speech in
//! another mode after it, in both payload formats.

use super::*;

/// Offer `offer_media` from A, answer `answer_media` from B, and return the engine plus each
/// phone with the engine address it sends to. Both media sections are complete `m=` blocks.
async fn relay_on(
    call_id: &str,
    offer_media: impl Fn(SocketAddr) -> String,
    answer_media: impl Fn(SocketAddr) -> String,
) -> (
    Engine<UdpLoopbackDatapath>,
    (UdpSocket, SocketAddr),
    (UdpSocket, SocketAddr),
) {
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
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                sdp: offer_media(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    let far_addr = sdp::parse(&ok_sdp_text(&offer))
        .expect("offer reply")
        .remote_rtp;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: answer_media(addr_b),
                profile: Default::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;
    (engine, (phone_a, near_addr), (phone_b, far_addr))
}

/// An RTP packet carrying `payload` under PT `payload_type`.
fn rtp_packet(
    payload_type: u8,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0x80, payload_type];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// Attach a caller-only tee at the caller's own rate: one wire frame per decoded packet, so the
/// counts on its end event are exact.
async fn attach_caller_tee(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
) -> flume::Receiver<tokio_tungstenite::tungstenite::Message> {
    let (uri, frames) = tee_server().await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                ws_uri: uri,
                direction: WsTeeDirection::Caller,
                channels: None,
                sample_rate: None,
            },
        )
        .await;
    assert!(
        matches!(attached, CmdResult::Ok { .. }),
        "attach: {attached:?}"
    );
    expect_tee_start(&frames).await;
    frames
}

/// Send every packet from A and assert B receives each one byte for byte, in order.
async fn assert_relayed_verbatim(
    (phone_a, near_addr): (&UdpSocket, SocketAddr),
    phone_b: &UdpSocket,
    packets: &[Vec<u8>],
) {
    for (index, packet) in packets.iter().enumerate() {
        phone_a.send_to(packet, near_addr).await.expect("a send");
        let (received, _) = recv(phone_b).await;
        assert_eq!(
            &received, packet,
            "packet {index} must reach the far party exactly as the near party sent it"
        );
    }
}

/// Detach the tee and return its `(frames_sent, frames_dropped)`.
async fn detach_and_count(
    engine: &Engine<UdpLoopbackDatapath>,
    events: &flume::Receiver<Event>,
    call_id: &str,
) -> (u64, u64) {
    // Let the actor finish the last packet before the tee comes off.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let detached = engine
        .handle(
            CLIENT,
            Command::DetachWsTee {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    assert!(
        matches!(detached, CmdResult::Ok { .. }),
        "detach: {detached:?}"
    );
    loop {
        match next_ws_tee_event(events).await {
            Some(Event::WsTeeEnded {
                frames_sent,
                frames_dropped,
                ..
            }) => {
                return (
                    frames_sent.expect("frames_sent"),
                    frames_dropped.expect("frames_dropped"),
                )
            }
            Some(_) => continue,
            None => panic!("no ws_tee_ended"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_teed_relay_forwards_every_packet_byte_for_byte() {
    // The tee decodes for itself; the call is not decoded and re-encoded for it. The far party
    // receives the near party's own packets, header included, with or without a tee.
    let (engine, (phone_a, near_addr), (phone_b, _far_addr)) =
        two_party_relay("tee-verbatim").await;
    let events = engine.register_client(CLIENT);
    let frames = attach_caller_tee(&engine, "tee-verbatim").await;

    let packets: Vec<Vec<u8>> = (0..8u16)
        .map(|sequence| g711_rtp(0, 1000 + sequence, 0x0A0A_0A0A, 0x10 + sequence as u8))
        .collect();
    assert_relayed_verbatim((&phone_a, near_addr), &phone_b, &packets).await;
    let audio = next_tee_audio(&frames).await;
    assert_eq!(audio.len(), 320, "the tee still hears the caller");

    let (sent, dropped) = detach_and_count(&engine, &events, "tee-verbatim").await;
    assert_eq!(sent, 8, "one tee frame per relayed packet");
    assert_eq!(dropped, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_teed_relay_forwards_frames_the_tee_cannot_decode() {
    // GSM 06.10 frames are 33 octets (RFC 3551 §4.5.8); a 32-octet payload is not one. The tee
    // cannot decode it, but it is the near party's packet and the far party gets it.
    let gsm = |addr: SocketAddr| sdp_single_codec(addr, 3, "GSM");
    let (engine, (phone_a, near_addr), (phone_b, _far_addr)) = relay_on("tee-gsm", gsm, gsm).await;
    let events = engine.register_client(CLIENT);
    let _frames = attach_caller_tee(&engine, "tee-gsm").await;

    let mut good = [0u8; 33];
    good[0] = 0xD0; // the GSM magic nibble
    let bad = [0xD0u8; 32];
    let payloads: [&[u8]; 8] = [&good, &good, &bad, &good, &bad, &bad, &good, &good];
    let packets: Vec<Vec<u8>> = payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| {
            let sequence = 500 + index as u16;
            rtp_packet(3, sequence, u32::from(sequence) * 160, 0x0C0C_0C0C, payload)
        })
        .collect();
    assert_relayed_verbatim((&phone_a, near_addr), &phone_b, &packets).await;

    let (sent, dropped) = detach_and_count(&engine, &events, "tee-gsm").await;
    assert_eq!(sent, 5, "every decodable frame reached the tee");
    assert_eq!(
        dropped, 3,
        "every undecodable frame is counted against the tee"
    );
}

/// The AMR-WB media section, octet-aligned or bandwidth-efficient (RFC 4867 §8.1).
#[cfg(feature = "amr")]
fn amr_wb_media(octet_aligned: bool) -> impl Fn(SocketAddr) -> String {
    move |addr: SocketAddr| {
        let fmtp = if octet_aligned {
            "a=fmtp:96 octet-align=1\r\n"
        } else {
            ""
        };
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n{fmtp}a=rtcp-mux\r\n",
            ip = addr.ip(),
            port = addr.port(),
        )
    }
}

/// One AMR-WB speech payload at `mode`, in the given payload format, from our encoder.
#[cfg(feature = "amr")]
fn amr_wb_speech(octet_aligned: bool, mode: u8, frame: u16) -> Vec<u8> {
    use siphon_rtp_codec::factory::{encoder_for, AmrParams};
    let mut spec = CodecSpec::new(96, "AMR-WB", 16000, 1, 20);
    spec.encode_mode = Some(mode);
    spec.amr = Some(AmrParams {
        octet_align: Some(octet_aligned),
        ..AmrParams::default()
    });
    let mut encoder = encoder_for(&spec).expect("amr-wb encoder");
    let pcm: Vec<i16> = (0..320)
        .map(|index| {
            let sample = f32::from(frame) * 320.0 + index as f32;
            ((sample * 0.07).sin() * 9000.0) as i16
        })
        .collect();
    let mut payload = vec![0u8; 128];
    let written = encoder.encode(&pcm, &mut payload).expect("encode");
    payload.truncate(written);
    payload
}

/// What a VoLTE handset sends around a silence period, plus two frames nobody can decode, as
/// `(payload, decodable)`. The fixed payloads are written out by hand from RFC 4867 §4.3 / §4.4:
///
/// - bandwidth-efficient: CMR (4 bits) = 15, then one ToC entry F=0 / FT (4) / Q=1, then the
///   frame bits, padded to an octet;
/// - octet-aligned: CMR octet `0xF0`, ToC octet `F FT(4) Q 0 0`, then the frame octets.
///
/// SID is frame type 9 (40 bits, TS 26.201 §4.2), SPEECH_LOST 14 and NO_DATA 15 (no bits). The
/// undecodable one is the shape the defect was seen with: a NO_DATA ToC followed by 30 octets the
/// table of contents does not account for, 32 octets in all.
#[cfg(feature = "amr")]
fn volte_talk_spurt(octet_aligned: bool) -> Vec<(Vec<u8>, bool)> {
    let (sid, no_data, speech_lost, garbage): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) =
        if octet_aligned {
            let mut garbage = vec![0xF0, 0x7C];
            garbage.extend_from_slice(&[0x55; 30]);
            (
                vec![0xF0, 0x4C, 0x12, 0x34, 0x56, 0x78, 0x9A],
                vec![0xF0, 0x7C],
                vec![0xF0, 0x74],
                garbage,
            )
        } else {
            let mut garbage = vec![0xF7, 0xC0];
            garbage.extend_from_slice(&[0x55; 30]);
            (
                vec![0xF4, 0xC4, 0x8D, 0x15, 0x9E, 0x26, 0x80],
                vec![0xF7, 0xC0],
                vec![0xF7, 0x40],
                garbage,
            )
        };
    let speech = |mode: u8, frame: u16| (amr_wb_speech(octet_aligned, mode, frame), true);
    vec![
        speech(2, 0),
        speech(2, 1),
        speech(2, 2),
        (sid, true),
        (no_data.clone(), true),
        (no_data.clone(), true),
        (no_data, true),
        // Speech returns in another mode: a handset follows the network's mode request.
        speech(8, 3),
        speech(8, 4),
        (garbage.clone(), false),
        (garbage, false),
        (speech_lost, true),
        speech(0, 5),
        speech(0, 6),
    ]
}

#[cfg(feature = "amr")]
async fn amr_wb_tee_case(call_id: &str, octet_aligned: bool) {
    let (engine, (phone_a, near_addr), (phone_b, _far_addr)) = relay_on(
        call_id,
        amr_wb_media(octet_aligned),
        amr_wb_media(octet_aligned),
    )
    .await;
    let events = engine.register_client(CLIENT);
    let frames = attach_caller_tee(&engine, call_id).await;

    let spurt = volte_talk_spurt(octet_aligned);
    let packets: Vec<Vec<u8>> = spurt
        .iter()
        .enumerate()
        .map(|(index, (payload, _))| {
            let sequence = 7000 + index as u16;
            rtp_packet(
                96,
                sequence,
                u32::from(sequence) * 320,
                0x0D0D_0D0D,
                payload,
            )
        })
        .collect();
    assert_relayed_verbatim((&phone_a, near_addr), &phone_b, &packets).await;

    // The tee heard the speech, not only the silence around it.
    let mut heard_speech = false;
    for _ in 0..spurt.len() {
        let audio = next_tee_audio(&frames).await;
        assert_eq!(audio.len(), 640, "16 kHz / 20 ms mono L16");
        if audio.iter().any(|&byte| byte != 0) {
            heard_speech = true;
        }
        if frames.is_empty() {
            break;
        }
    }
    assert!(heard_speech, "the tee decoded the speech frames");

    let decodable = spurt.iter().filter(|(_, decodable)| *decodable).count() as u64;
    let (sent, dropped) = detach_and_count(&engine, &events, call_id).await;
    assert_eq!(
        sent, decodable,
        "speech, SID, NO_DATA and SPEECH_LOST each give the tee 20 ms"
    );
    assert_eq!(dropped, 2, "the two undecodable payloads are counted");
}

#[cfg(feature = "amr")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_teed_amr_wb_relay_forwards_dtx_and_undecodable_frames_bandwidth_efficient() {
    amr_wb_tee_case("tee-amr-be", false).await;
}

#[cfg(feature = "amr")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_teed_amr_wb_relay_forwards_dtx_and_undecodable_frames_octet_aligned() {
    amr_wb_tee_case("tee-amr-oa", true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_decoded_recording_on_a_relay_forwards_every_packet_byte_for_byte() {
    // A decoded recording is the same kind of copy as a tee, and has the same obligation.
    let directory = tempfile::tempdir().expect("tempdir");
    let gsm = |addr: SocketAddr| sdp_single_codec(addr, 3, "GSM");
    let (engine, (phone_a, near_addr), (phone_b, _far_addr)) = relay_on("rec-gsm", gsm, gsm).await;
    let started = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: "rec-gsm".into(),
                from_tag: "tag-a".into(),
                recording_dir: Some(directory.path().to_string_lossy().into_owned()),
                format: Some(siphon_rtp_proto::RecordingFormat::Wav),
                direction: None,
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: None,
                bitrate_bps: None,
            },
        )
        .await;
    assert!(
        matches!(started, CmdResult::Ok { .. }),
        "start_recording: {started:?}"
    );
    let mut good = [0u8; 33];
    good[0] = 0xD0;
    let bad = [0xD0u8; 32];
    let payloads: [&[u8]; 4] = [&good, &bad, &good, &bad];
    let packets: Vec<Vec<u8>> = payloads
        .iter()
        .enumerate()
        .map(|(index, payload)| {
            let sequence = 40 + index as u16;
            rtp_packet(3, sequence, u32::from(sequence) * 160, 0x0E0E_0E0E, payload)
        })
        .collect();
    assert_relayed_verbatim((&phone_a, near_addr), &phone_b, &packets).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prompt_played_on_a_teed_relay_keeps_the_tee() {
    // Playing a prompt needs the call decoded and re-encoded. The tee that was on the relay moves
    // to the processing pipeline with it and keeps streaming the caller.
    let (engine, (phone_a, near_addr), (_phone_b, _far_addr)) =
        two_party_relay("tee-then-play").await;
    let frames = attach_caller_tee(&engine, "tee-then-play").await;
    let played = engine
        .handle(
            CLIENT,
            Command::PlayMedia {
                call_id: "tee-then-play".into(),
                from_tag: "tag-a".into(),
                source: siphon_rtp_proto::PlayMediaSource::Tone {
                    tone: "440/300".into(),
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: Some(200),
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(played, CmdResult::Ok { .. }), "play: {played:?}");
    assert!(
        engine.media().is_transcoding_call("tee-then-play"),
        "a prompt needs the processing pipeline"
    );
    while frames.try_recv().is_ok() {}
    for sequence in 0..6u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0x00), near_addr)
            .await
            .expect("a send");
    }
    let audio = next_tee_audio(&frames).await;
    assert_eq!(audio.len(), 320, "the tee still hears the caller");
}
