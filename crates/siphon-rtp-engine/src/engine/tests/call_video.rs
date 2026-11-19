//! Anchored video on a two-party relayed call (`video_relay: anchor`), over the UDP loopback datapath.

use super::*;
use siphon_rtp_proto::VideoRelay;

pub(super) const CAMERA_PAYLOAD: &str = "a=rtpmap:96 H264/90000\r\na=fmtp:96 profile-level-id=42e01f;packetization-mode=1\r\na=rtcp-fb:96 nack pli\r\n";

pub(super) fn anchor() -> ProfileFlags {
    ProfileFlags {
        video_relay: VideoRelay::Anchor,
        ..ProfileFlags::default()
    }
}

fn video_declined_of(result: &CmdResult) -> Option<String> {
    match result {
        CmdResult::Ok { video_declined, .. } => video_declined.clone(),
        other => panic!("expected Ok, got {other:?}"),
    }
}

/// Audio plus one video section on `video` (RTP), its RTCP on the next port unless `mux`.
fn call_sdp(
    audio: SocketAddr,
    video: SocketAddr,
    direction: &str,
    transport: &str,
    mux: bool,
) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {audio_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
         m=video {video_port} {transport} 96\r\n{CAMERA_PAYLOAD}a={direction}\r\n{mux_line}",
        ip = audio.ip(),
        audio_port = audio.port(),
        video_port = video.port(),
        mux_line = if mux { "a=rtcp-mux\r\n" } else { "" },
    )
}

struct VideoCall {
    engine: Engine<UdpLoopbackDatapath>,
    camera_rtp: UdpSocket,
    camera_rtcp: UdpSocket,
    desk_rtp: UdpSocket,
    desk_rtcp: UdpSocket,
    /// What the desk phone was offered, and what the camera was answered.
    to_desk: String,
    to_camera: String,
}

/// Camera (A) offers `sendonly` video, desk phone (B) answers `recvonly`; non-muxed RTCP.
async fn answered_door_call(call_id: &str, profile: ProfileFlags) -> VideoCall {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (camera_audio, camera_audio_addr) = phone().await;
    let (camera_rtp, camera_rtp_addr) = phone().await;
    let (camera_rtcp, _) = phone_pair(&camera_rtp_addr).await;
    let (desk_audio, desk_audio_addr) = phone().await;
    let (desk_rtp, desk_rtp_addr) = phone().await;
    let (desk_rtcp, _) = phone_pair(&desk_rtp_addr).await;
    let _ = (&camera_audio, &desk_audio);
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "camera".into(),
                sdp: call_sdp(
                    camera_audio_addr,
                    camera_rtp_addr,
                    "sendonly",
                    "RTP/AVP",
                    false,
                ),
                profile: profile.clone(),
            },
        )
        .await;
    let to_desk = ok_sdp_text(&offered);
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "camera".into(),
                to_tag: "desk".into(),
                sdp: call_sdp(desk_audio_addr, desk_rtp_addr, "recvonly", "RTP/AVP", false),
                profile,
            },
        )
        .await;
    let to_camera = ok_sdp_text(&answered);
    VideoCall {
        engine,
        camera_rtp,
        camera_rtcp,
        desk_rtp,
        desk_rtcp,
        to_desk,
        to_camera,
    }
}

/// A socket on the port after `rtp`'s, the RTCP port of a non-muxed stream (RFC 3550 §11).
pub(super) async fn phone_pair(rtp: &SocketAddr) -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, rtp.port() + 1))
        .await
        .or_else(|_| futures_free_bind())
        .expect("bind rtcp");
    let addr = socket.local_addr().expect("addr");
    (socket, addr)
}

fn futures_free_bind() -> std::io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

pub(super) async fn received(socket: &UdpSocket) -> Option<Vec<u8>> {
    let mut buffer = [0u8; 2048];
    match timeout(Duration::from_millis(400), socket.recv_from(&mut buffer)).await {
        Ok(Ok((len, _))) => Some(buffer[..len].to_vec()),
        _ => None,
    }
}

pub(super) fn video_packet(sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 96];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF]);
    packet.extend_from_slice(b"h264-nal");
    packet
}

pub(super) fn receiver_report() -> Vec<u8> {
    vec![0x80, 201, 0, 1, 0xCA, 0xFE, 0xBA, 0xBE]
}

#[tokio::test]
async fn an_anchored_offer_presents_the_engine_for_video_and_keeps_the_codec_lines() {
    let call = answered_door_call("video-sdp", anchor()).await;
    let stream = sdp::parse_video_stream(&call.to_desk).expect("the desk phone is offered video");
    assert_ne!(
        stream.remote_rtp,
        call.camera_rtp.local_addr().expect("addr"),
        "the desk phone is told the engine's video port, not the camera's: {}",
        call.to_desk
    );
    for line in [
        "a=rtpmap:96 H264/90000",
        "a=fmtp:96 profile-level-id=42e01f;packetization-mode=1",
        "a=rtcp-fb:96 nack pli",
        "a=sendonly",
    ] {
        assert!(
            call.to_desk.contains(line),
            "{line} kept verbatim: {}",
            call.to_desk
        );
    }
    let answered = sdp::parse_video_stream(&call.to_camera).expect("the camera is answered video");
    assert_ne!(
        answered.remote_rtp,
        call.desk_rtp.local_addr().expect("addr")
    );
    assert!(call.to_camera.contains("a=recvonly"), "{}", call.to_camera);
}

#[tokio::test]
async fn a_sendonly_camera_answered_recvonly_relays_one_way_and_both_ways_for_rtcp() {
    let call = answered_door_call("video-door", anchor()).await;
    // The camera sends to the port it was answered with; the desk phone to the one it was offered.
    let near_video = sdp::parse_video_stream(&call.to_camera)
        .expect("video")
        .remote_rtp;
    let far_video = sdp::parse_video_stream(&call.to_desk)
        .expect("video")
        .remote_rtp;
    // Camera to desk phone: relayed.
    call.camera_rtp
        .send_to(&video_packet(1), near_video)
        .await
        .expect("send");
    let relayed = received(&call.desk_rtp)
        .await
        .expect("the picture reaches the desk phone");
    assert_eq!(relayed, video_packet(1));
    // Desk phone to camera: the desk phone said recvonly, so its RTP is dropped.
    call.desk_rtp
        .send_to(&video_packet(2), far_video)
        .await
        .expect("send");
    assert!(
        received(&call.camera_rtp).await.is_none(),
        "no video toward a sendonly camera"
    );
    // The receiver's RTCP (reports, picture loss) still reaches the camera, on the RTCP ports.
    let far_rtcp = sdp::parse_video_stream(&call.to_desk)
        .expect("video")
        .remote_rtcp;
    call.desk_rtcp
        .send_to(&receiver_report(), far_rtcp)
        .await
        .expect("send");
    assert_eq!(
        received(&call.camera_rtcp)
            .await
            .expect("the report reaches the camera"),
        receiver_report()
    );
}

#[tokio::test]
async fn video_from_an_unexpected_source_is_dropped_not_latched() {
    let call = answered_door_call("video-gate", anchor()).await;
    let near_video = sdp::parse_video_stream(&call.to_camera)
        .expect("video")
        .remote_rtp;
    // RTPBleed: another host races the camera to the engine's video port.
    let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    attacker
        .send_to(&video_packet(66), near_video)
        .await
        .expect("send");
    assert!(
        received(&call.desk_rtp).await.is_none(),
        "the stranger's picture is dropped"
    );
    // The camera, still the signalled source, is relayed afterwards.
    call.camera_rtp
        .send_to(&video_packet(1), near_video)
        .await
        .expect("send");
    assert!(received(&call.desk_rtp).await.is_some());
}

#[tokio::test]
async fn the_default_leaves_video_unanchored_and_the_phones_own_addresses_in_it() {
    let call = answered_door_call("video-default", ProfileFlags::default()).await;
    let stream = sdp::parse_video_stream(&call.to_desk).expect("video");
    assert_eq!(
        stream.remote_rtp,
        call.camera_rtp.local_addr().expect("addr")
    );
}

#[tokio::test]
async fn dtls_video_is_declined_with_the_reason_and_decline_mode_says_no() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_audio, audio_addr) = phone().await;
    let (_video, video_addr) = phone().await;
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "video-secure".into(),
                from_tag: "a".into(),
                sdp: call_sdp(
                    audio_addr,
                    video_addr,
                    "sendrecv",
                    "UDP/TLS/RTP/SAVPF",
                    true,
                ),
                profile: anchor(),
            },
        )
        .await;
    let presented = ok_sdp_text(&offered);
    assert!(
        presented.contains("m=video 0 UDP/TLS/RTP/SAVPF 96"),
        "{presented}"
    );
    assert!(
        video_declined_of(&offered).is_some_and(|reason| reason.contains("DTLS-SRTP video")),
        "{offered:?}"
    );
    let declined = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "video-decline".into(),
                from_tag: "a".into(),
                sdp: call_sdp(audio_addr, video_addr, "sendrecv", "RTP/AVP", true),
                profile: ProfileFlags {
                    video_relay: VideoRelay::Decline,
                    ..ProfileFlags::default()
                },
            },
        )
        .await;
    assert!(ok_sdp_text(&declined).contains("m=video 0 RTP/AVP 96"));
}

#[tokio::test]
async fn the_latch_refresh_aims_the_video_flow_at_the_source_the_kernel_learned() {
    // A NATed camera whose real source differs from its signalled address: the kernel latches it on
    // the engine's far video endpoint, and the sweep must reprogram the near video flow toward it
    // exactly as it does for audio (RFC 3550 §8; docs/security-and-nat.md §4 layer 3).
    let datapath = LatchLearningDatapath::new();
    let engine = Engine::new(datapath.clone());
    let (_audio_a, audio_a) = phone().await;
    let (_video_a, video_a) = phone().await;
    let (_audio_b, audio_b) = phone().await;
    let (_video_b, video_b) = phone().await;
    for command in [
        Command::Offer {
            call_id: "video-nat".into(),
            from_tag: "a".into(),
            sdp: call_sdp(audio_a, video_a, "sendrecv", "RTP/AVP", true),
            profile: anchor(),
        },
        Command::Answer {
            call_id: "video-nat".into(),
            from_tag: "a".into(),
            to_tag: "b".into(),
            sdp: call_sdp(audio_b, video_b, "sendrecv", "RTP/AVP", true),
            profile: anchor(),
        },
    ] {
        let result = engine.handle(CLIENT, command).await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    }
    let (near_video, far_video) = {
        let call = engine.calls.get("video-nat").expect("call");
        (
            call.near.video.expect("near video").rtp.id,
            call.far_leg().video.expect("far video").rtp.id,
        )
    };
    let learned: SocketAddr = "203.0.113.7:40004".parse().expect("addr");
    datapath.set_learned(far_video, learned);
    let _ = datapath.take_installs();
    engine.refresh_latched_destinations().await;
    let installs = datapath.take_installs();
    assert!(
        installs
            .iter()
            .any(|(endpoint, action)| *endpoint == near_video
                && matches!(action, FlowAction::Forward(rule) if rule.out_dst == Some(learned))),
        "the near video flow now forwards to the learned source: {installs:?}"
    );
    let stored = engine.calls.get("video-nat").expect("call");
    assert!(stored
        .video
        .flows
        .iter()
        .any(|(endpoint, action)| *endpoint == near_video
            && matches!(action, FlowAction::Forward(rule) if rule.out_dst == Some(learned))));
}

#[tokio::test]
async fn the_latch_refresh_also_aims_the_text_flow_at_the_source_the_kernel_learned() {
    // The same gap the video stream closes: the sweep walked the audio flows only, so a NATed
    // peer's text kept going to its signalled, private address.
    let datapath = LatchLearningDatapath::new();
    let engine = Engine::new(datapath.clone());
    let (_audio_a, audio_a) = phone().await;
    let (_text_a, text_a) = phone().await;
    let (_audio_b, audio_b) = phone().await;
    let (_text_b, text_b) = phone().await;
    for command in [
        Command::Offer {
            call_id: "text-nat".into(),
            from_tag: "a".into(),
            sdp: audio_plaintext_text_sdp(audio_a, text_a),
            profile: ProfileFlags::default(),
        },
        Command::Answer {
            call_id: "text-nat".into(),
            from_tag: "a".into(),
            to_tag: "b".into(),
            sdp: audio_plaintext_text_sdp(audio_b, text_b),
            profile: ProfileFlags::default(),
        },
    ] {
        let result = engine.handle(CLIENT, command).await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    }
    let (near_text, far_text) = {
        let call = engine.calls.get("text-nat").expect("call");
        (
            call.near.text.expect("near text").id,
            call.far_leg().text.expect("far text").id,
        )
    };
    let learned: SocketAddr = "203.0.113.8:40006".parse().expect("addr");
    datapath.set_learned(far_text, learned);
    let _ = datapath.take_installs();
    engine.refresh_latched_destinations().await;
    assert!(
        datapath
            .take_installs()
            .iter()
            .any(|(endpoint, action)| *endpoint == near_text
                && matches!(action, FlowAction::Forward(rule) if rule.out_dst == Some(learned))),
        "the near text flow now forwards to the learned source"
    );
}

/// `call_sdp` with audio and video both on `ip` (a loopback address standing for a moved phone).
fn call_sdp_at(audio: SocketAddr, video: SocketAddr, direction: &str) -> String {
    call_sdp(
        SocketAddr::new(video.ip(), audio.port()),
        video,
        direction,
        "RTP/AVP",
        true,
    )
}

#[tokio::test]
async fn a_reoffer_from_a_moved_caller_re_gates_video_and_keeps_the_far_party_anchored() {
    // A re-INVITE from a phone that moved network: its video address changes, and the re-answer must
    // gate and aim the relay at the new one, never at the old (docs/security-and-nat.md §4 layer 2).
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_audio_a, audio_a) = phone().await;
    let (video_a, video_a_addr) = phone().await;
    let (_audio_b, audio_b) = phone().await;
    let (video_b, video_b_addr) = phone().await;
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "video-move".into(),
                from_tag: "a".into(),
                sdp: call_sdp_at(audio_a, video_a_addr, "sendrecv"),
                profile: anchor(),
            },
        )
        .await;
    let to_b = ok_sdp_text(&offered);
    let far_video = sdp::parse_video_stream(&to_b).expect("video").remote_rtp;
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "video-move".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: call_sdp_at(audio_b, video_b_addr, "sendrecv"),
                profile: anchor(),
            },
        )
        .await;
    let near_video = sdp::parse_video_stream(&ok_sdp_text(&answered))
        .expect("video")
        .remote_rtp;
    // A re-offers from another host, with a hold (`sendonly`) on its video.
    let (moved_a, moved_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let reoffered = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "video-move".into(),
                from_tag: "a".into(),
                sdp: call_sdp_at(audio_a, moved_addr, "sendrecv"),
                profile: anchor(),
            },
        )
        .await;
    let again_to_b = ok_sdp_text(&reoffered);
    let again = sdp::parse_video_stream(&again_to_b).expect("B is still offered video");
    assert_eq!(
        again.remote_rtp, far_video,
        "the engine's video port does not move"
    );
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "video-move".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: call_sdp_at(audio_b, video_b_addr, "sendrecv"),
                profile: anchor(),
            },
        )
        .await;
    // The old address is no longer the gated source; the new one is relayed.
    video_a
        .send_to(&video_packet(1), near_video)
        .await
        .expect("send");
    assert!(
        received(&video_b).await.is_none(),
        "the old address is dropped"
    );
    moved_a
        .send_to(&video_packet(2), near_video)
        .await
        .expect("send");
    assert_eq!(received(&video_b).await, Some(video_packet(2)));
}

#[tokio::test]
async fn a_reoffer_from_a_moved_caller_re_gates_its_text_stream_too() {
    // The text stream follows the caller like audio and video do: a re-INVITE from a phone on a new
    // network restates the text address, and the relay must gate and aim at it, never at the old one.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_audio_a, audio_a) = phone().await;
    let (text_a, text_a_addr) = phone().await;
    let (_audio_b, audio_b) = phone().await;
    let (text_b, text_b_addr) = phone().await;
    for command in [
        Command::Offer {
            call_id: "text-move".into(),
            from_tag: "a".into(),
            sdp: audio_plaintext_text_sdp(audio_a, text_a_addr),
            profile: ProfileFlags::default(),
        },
        Command::Answer {
            call_id: "text-move".into(),
            from_tag: "a".into(),
            to_tag: "b".into(),
            sdp: audio_plaintext_text_sdp(audio_b, text_b_addr),
            profile: ProfileFlags::default(),
        },
    ] {
        let result = engine.handle(CLIENT, command).await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    }
    let near_text_engine = {
        let call = engine.calls.get("text-move").expect("call");
        call.near.text.expect("near text").local_addr
    };
    let (moved_audio_a, moved_audio_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let (moved_text_a, moved_text_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let _keep = moved_audio_a;
    let reoffered = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "text-move".into(),
                from_tag: "a".into(),
                sdp: audio_plaintext_text_sdp(moved_audio_addr, moved_text_addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(reoffered, CmdResult::Ok { .. }), "{reoffered:?}");
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "text-move".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: audio_plaintext_text_sdp(audio_b, text_b_addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    assert_eq!(
        engine
            .calls
            .get("text-move")
            .expect("call")
            .near
            .text_remote_rtp,
        Some(moved_text_addr),
        "the call remembers the caller's moved text address"
    );
    text_a
        .send_to(&video_packet(1), near_text_engine)
        .await
        .expect("send");
    assert!(
        received(&text_b).await.is_none(),
        "the old text address is dropped"
    );
    moved_text_a
        .send_to(&video_packet(2), near_text_engine)
        .await
        .expect("send");
    assert_eq!(received(&text_b).await, Some(video_packet(2)));
}

#[tokio::test]
async fn a_reoffer_that_drops_video_frees_the_video_endpoints() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_audio_a, audio_a) = phone().await;
    let (_video_a, video_a) = phone().await;
    let (_audio_b, audio_b) = phone().await;
    let (_video_b, video_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "video-drop".into(),
                from_tag: "a".into(),
                sdp: call_sdp_at(audio_a, video_a, "sendrecv"),
                profile: anchor(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "video-drop".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: call_sdp_at(audio_b, video_b, "sendrecv"),
                profile: anchor(),
            },
        )
        .await;
    assert!(engine
        .calls
        .get("video-drop")
        .expect("call")
        .near
        .video
        .is_some());
    let without = call_sdp_at(audio_a, video_a, "sendrecv")
        .replace(&format!("m=video {} ", video_a.port()), "m=video 0 ");
    let result = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "video-drop".into(),
                from_tag: "a".into(),
                sdp: without,
                profile: anchor(),
            },
        )
        .await;
    assert!(ok_sdp_text(&result).contains("m=video 0 "), "{result:?}");
    let call = engine.calls.get("video-drop").expect("call");
    assert!(call.near.video.is_none() && call.far_leg().video.is_none());
    assert!(call.video.flows.is_empty());
}

#[tokio::test]
async fn a_room_refuses_the_two_party_video_mode_it_has_no_use_for() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_audio, audio_addr) = phone().await;
    let (_video, video_addr) = phone().await;
    let sdp = call_sdp(audio_addr, video_addr, "sendrecv", "RTP/AVP", true);
    for command in [
        Command::ConferenceJoin {
            conference_id: "room".into(),
            from_tag: "a".into(),
            sdp: sdp.clone(),
            role: siphon_rtp_proto::ConferenceRole::Talker,
            profile: anchor(),
            dtmf: siphon_rtp_proto::ConferenceDtmf::Events,
        },
        Command::ForwardJoin {
            conference_id: "room".into(),
            from_tag: "a".into(),
            sdp,
            profile: anchor(),
            media: siphon_rtp_proto::ForwardMedia::Translate,
        },
        Command::ForwardOffer {
            conference_id: "room".into(),
            from_tag: "a".into(),
            profile: anchor(),
            media: siphon_rtp_proto::ForwardMedia::Translate,
        },
    ] {
        match engine.handle(CLIENT, command).await {
            CmdResult::Error { reason } => {
                assert!(reason.contains("video_relay"), "{reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}

/// `command` carries `video_relay: anchor` on a verb that has no video stream to anchor: it must
/// come back as a refusal naming the field, not as a silent success.
async fn assert_video_relay_refused(verb: &str, command: Command) {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    match engine.handle(CLIENT, command).await {
        CmdResult::Error { reason } => {
            assert!(reason.contains("video_relay"), "{verb}: {reason}");
        }
        other => panic!("{verb}: expected a refusal, got {other:?}"),
    }
}

fn any_sdp() -> String {
    call_sdp(
        "192.0.2.10:4000".parse().unwrap(),
        "192.0.2.10:4002".parse().unwrap(),
        "sendrecv",
        "RTP/AVP",
        true,
    )
}

#[tokio::test]
async fn answer_local_refuses_video_relay_instead_of_ignoring_it() {
    let command = Command::AnswerLocal {
        call_id: "no-video".into(),
        from_tag: "a".into(),
        sdp: any_sdp(),
        profile: anchor(),
    };
    assert_video_relay_refused("answer_local", command).await;
}

#[tokio::test]
async fn offer_far_refuses_video_relay_instead_of_ignoring_it() {
    let command = Command::OfferFar {
        call_id: "no-video".into(),
        from_tag: "a".into(),
        profile: anchor(),
    };
    assert_video_relay_refused("offer_far", command).await;
}

#[tokio::test]
async fn subscribe_request_refuses_video_relay_instead_of_ignoring_it() {
    let command = Command::SubscribeRequest {
        call_id: "no-video".into(),
        from_tags: vec!["a".into()],
        sdp: None,
        profile: anchor(),
    };
    assert_video_relay_refused("subscribe_request", command).await;
}

#[tokio::test]
async fn subscribe_answer_refuses_video_relay_instead_of_ignoring_it() {
    let command = Command::SubscribeAnswer {
        call_id: "no-video".into(),
        from_tag: "a".into(),
        to_tag: "b".into(),
        sdp: any_sdp(),
        profile: anchor(),
    };
    assert_video_relay_refused("subscribe_answer", command).await;
}

#[tokio::test]
async fn attach_ws_bridge_refuses_video_relay_instead_of_ignoring_it() {
    let command = Command::AttachWsBridge {
        call_id: "no-video".into(),
        from_tag: "a".into(),
        ws_uri: "ws://192.0.2.1:9/".into(),
        profile: Some(anchor()),
    };
    assert_video_relay_refused("attach_ws_bridge", command).await;
}

#[tokio::test]
async fn a_call_carrying_anchored_video_is_not_seated_in_a_room() {
    let call = answered_door_call("video-seat", anchor()).await;
    let result = call
        .engine
        .handle(
            CLIENT,
            Command::ConferenceSeat {
                call_id: "video-seat".into(),
                from_tag: "camera".into(),
                conference_id: "room".into(),
                role: siphon_rtp_proto::ConferenceRole::Talker,
                dtmf: siphon_rtp_proto::ConferenceDtmf::Events,
            },
        )
        .await;
    match result {
        CmdResult::Error { reason } => assert!(reason.contains("video"), "{reason}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn query_reports_the_video_stream_beside_the_audio_counters() {
    let call = answered_door_call("video-stats", anchor()).await;
    let near_video = sdp::parse_video_stream(&call.to_camera)
        .expect("video")
        .remote_rtp;
    for sequence in 0..3 {
        call.camera_rtp
            .send_to(&video_packet(sequence), near_video)
            .await
            .expect("send");
    }
    for _ in 0..3 {
        received(&call.desk_rtp).await.expect("relayed");
    }
    let result = call
        .engine
        .handle(
            CLIENT,
            Command::Query {
                call_id: "video-stats".into(),
                from_tag: "camera".into(),
                to_tag: None,
            },
        )
        .await;
    let CmdResult::Ok {
        stats: Some(stats), ..
    } = result
    else {
        panic!("expected stats, got {result:?}");
    };
    let video = stats.video.expect("the call carries video");
    assert_eq!(video.packets_in, 3, "{video:?}");
    assert_eq!(video.packets_out, 3, "{video:?}");
    assert_eq!(video.bytes_in, 3 * video_packet(0).len() as u64);
}

#[tokio::test]
async fn node_info_advertises_call_video_anchor() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("node_info answers a node");
    };
    assert!(node.features.iter().any(|name| name == "call_video_anchor"));
    assert!(node.features.iter().any(|name| name == "call_video_sdes"));
}

#[tokio::test]
async fn a_checkpoint_restores_the_video_stream_on_its_ports_with_its_gate_and_directions() {
    // The primary is lost; a standby on the same port range re-binds the video sockets and the relay
    // comes back gated on the signalled camera address, one way only.
    let range = (52_400u16, 52_460u16);
    let primary = Engine::new(UdpLoopbackDatapath::with_port_range(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        range.0,
        range.1,
    ));
    let (_camera_audio, camera_audio_addr) = phone().await;
    let (camera_rtp, camera_rtp_addr) = phone().await;
    let (_desk_audio, desk_audio_addr) = phone().await;
    let (desk_rtp, desk_rtp_addr) = phone().await;
    let offered = primary
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "video-ha".into(),
                from_tag: "camera".into(),
                sdp: call_sdp(
                    camera_audio_addr,
                    camera_rtp_addr,
                    "sendonly",
                    "RTP/AVP",
                    false,
                ),
                profile: anchor(),
            },
        )
        .await;
    let to_desk = ok_sdp_text(&offered);
    let answered = primary
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "video-ha".into(),
                from_tag: "camera".into(),
                to_tag: "desk".into(),
                sdp: call_sdp(desk_audio_addr, desk_rtp_addr, "recvonly", "RTP/AVP", false),
                profile: anchor(),
            },
        )
        .await;
    let near_video = sdp::parse_video_stream(&ok_sdp_text(&answered))
        .expect("video")
        .remote_rtp;
    let far_video = sdp::parse_video_stream(&to_desk).expect("video").remote_rtp;
    let CmdResult::Checkpoint { snapshot } = primary
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "video-ha".into(),
                from_tag: "camera".into(),
            },
        )
        .await
    else {
        panic!("a video call checkpoints");
    };
    let parsed = crate::ha::CallSnapshot::from_json(&snapshot).expect("snapshot parses");
    assert_eq!(parsed.version, crate::ha::SNAPSHOT_VERSION_VIDEO);
    primary
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "video-ha".into(),
                from_tag: "camera".into(),
                to_tag: None,
            },
        )
        .await;
    drop(primary);
    let standby = Engine::new(UdpLoopbackDatapath::with_port_range(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        range.0,
        range.1,
    ));
    let restored = standby.handle(CLIENT, Command::Restore { snapshot }).await;
    assert!(matches!(restored, CmdResult::Ok { .. }), "{restored:?}");
    camera_rtp
        .send_to(&video_packet(1), near_video)
        .await
        .expect("send");
    assert_eq!(received(&desk_rtp).await, Some(video_packet(1)));
    desk_rtp
        .send_to(&video_packet(2), far_video)
        .await
        .expect("send");
    assert!(
        received(&camera_rtp).await.is_none(),
        "the restored relay is still one way"
    );
    let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    attacker
        .send_to(&video_packet(66), near_video)
        .await
        .expect("send");
    assert!(
        received(&desk_rtp).await.is_none(),
        "the restored gate still drops a stranger"
    );
}
