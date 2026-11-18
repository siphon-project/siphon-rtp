//! Video in a translating forwarding room end to end on the UDP-loopback datapath (3GPP TS 24.281
//! §6.2): a phone offers `m=audio` + `m=video` + `m=application ... udp MCVideo`, the engine answers
//! all three, and the chosen source's video comes out of every other seat on that seat's own stream.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_media::rtp::{write_packet, RtpHeader, RtpPacket};
use siphon_rtp_proto::{ControlFormat, ForwardMedia, VideoProfile};

const ROOM: &str = "group-1";
const SHORT: Duration = Duration::from_secs(2);
const NEGATIVE: Duration = Duration::from_millis(250);
const FLOOR_FMTP: &str = "mc_queueing;mc_priority=5;mc_granted";
const CHP_L31: &str = "profile-level-id=640c1f;packetization-mode=1";

/// An engine with a bounded port pool and the redirect dispatcher running, so a leaked endpoint
/// shows as a later allocation failing.
fn engine_of(endpoints: usize) -> Engine<UdpLoopbackDatapath> {
    let engine = Engine::new(UdpLoopbackDatapath::with_max_endpoints(endpoints));
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    engine
}

fn offer(
    audio: SocketAddr,
    video: Option<(SocketAddr, u8, &str, &str)>,
    control: Option<SocketAddr>,
) -> String {
    let mut text = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n\
         a=fmtp:96 octet-align=1\r\na=rtcp-mux\r\n",
        ip = audio.ip(),
        port = audio.port()
    );
    if let Some((address, payload_type, direction, fmtp)) = video {
        text.push_str(&format!(
            "m=video {} RTP/AVP {payload_type}\r\na=rtpmap:{payload_type} H264/90000\r\n\
             a=fmtp:{payload_type} {fmtp};sprop-parameter-sets=Z2QAH6zZQFAFuhAAAAMAEAAAAwPA8YMZYA==\r\n\
             a={direction}\r\na=rtcp-mux\r\na=extmap:1 urn:ietf:params:rtp-hdrext:toffset\r\n",
            address.port()
        ));
    }
    if let Some(control) = control {
        text.push_str(&format!(
            "m=application {} udp MCVideo\r\na=fmtp:MCVideo mc_queueing\r\n",
            control.port()
        ));
    }
    text
}

fn profile(video: Option<VideoProfile>) -> ProfileFlags {
    ProfileFlags {
        video,
        ..ProfileFlags::default()
    }
}

fn carry_video() -> Option<VideoProfile> {
    Some(VideoProfile {
        fmtp: None,
        bandwidth_kbps: Some(1200),
    })
}

fn with_control(mut flags: ProfileFlags) -> ProfileFlags {
    flags.floor_fmtp = Some(FLOOR_FMTP.to_string());
    flags.transmission_control_formats = vec![ControlFormat::Mcvideo];
    flags
}

async fn join(
    engine: &Engine<UdpLoopbackDatapath>,
    media: ForwardMedia,
    tag: &str,
    sdp: String,
    profile: ProfileFlags,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media,
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                sdp,
                profile,
            },
        )
        .await
}

/// A seated phone with a video socket and the engine port its video goes to.
struct Phone {
    audio: UdpSocket,
    video: UdpSocket,
    engine_video: SocketAddr,
    answer: String,
}

async fn video_phone(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    payload_type: u8,
    direction: &str,
    fmtp: &str,
) -> Phone {
    let (audio, audio_address) = phone().await;
    let (video, video_address) = phone().await;
    let result = join(
        engine,
        ForwardMedia::Translate,
        tag,
        offer(
            audio_address,
            Some((video_address, payload_type, direction, fmtp)),
            None,
        ),
        profile(carry_video()),
    )
    .await;
    let answer = ok_sdp_text(&result);
    let engine_video = sdp::video::parse_video(&answer)
        .expect("a live video section")
        .remote;
    Phone {
        audio,
        video,
        engine_video,
        answer,
    }
}

fn video_packet(
    payload_type: u8,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
    marker: bool,
    payload: &[u8],
) -> Vec<u8> {
    let header = RtpHeader {
        marker,
        payload_type,
        sequence,
        timestamp,
        ssrc,
    };
    let mut buffer = vec![0u8; 12 + payload.len()];
    write_packet(&header, payload, &mut buffer).expect("write");
    buffer
}

async fn recv_rtp(socket: &UdpSocket, window: Duration) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + window;
    let mut buffer = [0u8; 2048];
    while let Ok(Ok((length, _))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await
    {
        if length >= 2 && !(64..=95).contains(&(buffer[1] & 0x7f)) {
            return Some(buffer[..length].to_vec());
        }
    }
    None
}

async fn set_source(engine: &Engine<UdpLoopbackDatapath>, tag: &str) {
    let result = engine
        .handle(
            CLIENT,
            Command::ForwardSetSource {
                conference_id: ROOM.into(),
                from_tag: Some(tag.to_string()),
            },
        )
        .await;
    assert_eq!(result, ok_empty());
}

fn streams(result: &CmdResult) -> Vec<String> {
    match result {
        CmdResult::Ok { streams, .. } => streams.clone(),
        other => panic!("expected Ok, got {other:?}"),
    }
}

fn video_declined(result: &CmdResult) -> Option<String> {
    match result {
        CmdResult::Ok { video_declined, .. } => video_declined.clone(),
        other => panic!("expected Ok, got {other:?}"),
    }
}

/// `(media, port)` for every m-line of an SDP.
fn m_lines(text: &str) -> Vec<(String, u16)> {
    text.split("\r\n")
        .filter_map(|line| line.strip_prefix("m="))
        .map(|line| {
            let mut fields = line.split(' ');
            (
                fields.next().unwrap().to_string(),
                fields.next().unwrap().parse().unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn audio_video_and_control_are_answered_live_and_the_streams_are_reported() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let (_, audio) = phone().await;
    let (_, video) = phone().await;
    let (_, control) = phone().await;
    let result = join(
        &engine,
        ForwardMedia::Translate,
        "a",
        offer(audio, Some((video, 99, "sendrecv", CHP_L31)), Some(control)),
        with_control(profile(carry_video())),
    )
    .await;
    assert_eq!(streams(&result), ["audio", "video", "floor"]);
    assert_eq!(video_declined(&result), None);
    let answer = ok_sdp_text(&result);
    let lines = m_lines(&answer);
    assert_eq!(lines.len(), 3, "{answer}");
    assert!(lines.iter().all(|(_, port)| *port != 0), "{answer}");
    let ports: std::collections::HashSet<u16> = lines.iter().map(|(_, port)| *port).collect();
    assert_eq!(ports.len(), 3, "three endpoints of their own: {answer}");
    // The video section: the engine's own answer, not an echo of the offer.
    let section = answer.split("m=video").nth(1).unwrap();
    let section = section.split("m=application").next().unwrap();
    assert!(section.contains(" RTP/AVP 99\r\n"), "{section}");
    assert!(section.contains("b=AS:1200\r\n"), "{section}");
    assert!(
        section.contains(&format!("a=fmtp:99 {CHP_L31}\r\n")),
        "{section}"
    );
    assert!(section.contains("a=sendrecv\r\n"), "{section}");
    assert!(section.contains("a=ssrc:"), "our own SSRC: {section}");
    for gone in ["extmap", "sprop-parameter-sets", "toffset"] {
        assert!(!section.contains(gone), "{gone}: {section}");
    }
    assert!(
        answer.contains("m=application") && answer.contains("udp MCVideo"),
        "{answer}"
    );
}

#[tokio::test]
async fn without_a_video_profile_the_video_stream_is_declined_as_before() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let (_, audio) = phone().await;
    let (_, video) = phone().await;
    let result = join(
        &engine,
        ForwardMedia::Translate,
        "a",
        offer(audio, Some((video, 99, "sendrecv", CHP_L31)), None),
        profile(None),
    )
    .await;
    assert_eq!(streams(&result), ["audio"]);
    let reason = video_declined(&result).expect("a reason");
    assert!(reason.contains("profile.video"), "{reason}");
    let answer = ok_sdp_text(&result);
    assert_eq!(m_lines(&answer)[1], ("video".to_string(), 0), "{answer}");
    assert_eq!(engine.endpoint_calls.len(), 1, "only the audio endpoint");
}

#[tokio::test]
async fn video_goes_from_the_source_to_the_other_seat_under_its_own_payload_type_and_ssrc() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let talker = video_phone(&engine, "a", 99, "sendrecv", CHP_L31).await;
    let listener = video_phone(&engine, "b", 105, "sendrecv", CHP_L31).await;
    set_source(&engine, "a").await;
    // An FU-A start fragment (RFC 6184 §5.8): the marker is clear.
    let payload = [0x7C, 0x85, 1, 2, 3];
    talker
        .video
        .send_to(
            &video_packet(99, 10, 90_000, 0xA0A0_A0A0, false, &payload),
            talker.engine_video,
        )
        .await
        .expect("send");
    let heard = recv_rtp(&listener.video, SHORT).await.expect("video");
    let packet = RtpPacket::parse(&heard).expect("rtp");
    assert_eq!(packet.payload_type, 105, "the listener's own number");
    assert_ne!(packet.ssrc, 0xA0A0_A0A0);
    assert!(!packet.marker, "an FU-A start is not marked at a rebase");
    assert_eq!(packet.payload, payload);
    assert!(
        recv_rtp(&talker.video, NEGATIVE).await.is_none(),
        "the source never hears itself"
    );
    // The listener's own video goes nowhere while it is not the source.
    listener
        .video
        .send_to(
            &video_packet(105, 1, 0, 0xB0B0_B0B0, true, &payload),
            listener.engine_video,
        )
        .await
        .expect("send");
    assert!(recv_rtp(&talker.video, NEGATIVE).await.is_none());
    // The switch moves video with it, on the same stream of the other receiver.
    set_source(&engine, "b").await;
    listener
        .video
        .send_to(
            &video_packet(105, 2, 3_000, 0xB0B0_B0B0, true, &payload),
            listener.engine_video,
        )
        .await
        .expect("send");
    let back = recv_rtp(&talker.video, SHORT).await.expect("video");
    let packet = RtpPacket::parse(&back).expect("rtp");
    assert_eq!(packet.payload_type, 99);
    assert!(packet.marker, "the sender's own marker");
    drop((talker.audio, listener.audio));
}

#[tokio::test]
async fn a_receive_only_video_offer_is_answered_send_only_and_is_never_a_source() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let talker = video_phone(&engine, "a", 99, "sendrecv", CHP_L31).await;
    let viewer = video_phone(&engine, "b", 105, "recvonly", CHP_L31).await;
    let video = sdp::video::parse_video(&viewer.answer).expect("video");
    assert_eq!(video.direction, sdp::MediaDirection::SendOnly);
    set_source(&engine, "b").await;
    viewer
        .video
        .send_to(
            &video_packet(105, 1, 0, 0xB0B0_B0B0, true, &[0x65]),
            viewer.engine_video,
        )
        .await
        .expect("send");
    assert!(recv_rtp(&talker.video, NEGATIVE).await.is_none());
    set_source(&engine, "a").await;
    talker
        .video
        .send_to(
            &video_packet(99, 1, 0, 0xA0A0_A0A0, true, &[0x65]),
            talker.engine_video,
        )
        .await
        .expect("send");
    assert!(
        recv_rtp(&viewer.video, SHORT).await.is_some(),
        "a viewer still receives"
    );
}

#[tokio::test]
async fn a_send_only_video_offer_is_answered_receive_only() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let camera = video_phone(&engine, "a", 99, "sendonly", CHP_L31).await;
    let video = sdp::video::parse_video(&camera.answer).expect("video");
    assert_eq!(video.direction, sdp::MediaDirection::RecvOnly);
    let other = video_phone(&engine, "b", 105, "sendrecv", CHP_L31).await;
    set_source(&engine, "b").await;
    other
        .video
        .send_to(
            &video_packet(105, 1, 0, 0xB0B0_B0B0, true, &[0x65]),
            other.engine_video,
        )
        .await
        .expect("send");
    assert!(
        recv_rtp(&camera.video, NEGATIVE).await.is_none(),
        "a camera is sent no video"
    );
}

#[tokio::test]
async fn a_seat_in_another_profile_level_joins_audio_only_with_the_reason() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let first = video_phone(&engine, "a", 99, "sendrecv", CHP_L31).await;
    assert!(first.answer.contains("640c1f"));
    let (_, audio) = phone().await;
    let (_, video) = phone().await;
    let result = join(
        &engine,
        ForwardMedia::Translate,
        "b",
        offer(
            audio,
            Some((
                video,
                99,
                "sendrecv",
                "profile-level-id=42e01f;packetization-mode=1",
            )),
            None,
        ),
        profile(carry_video()),
    )
    .await;
    assert_eq!(streams(&result), ["audio"]);
    let reason = video_declined(&result).expect("a reason");
    assert!(reason.contains("640c1f"), "{reason}");
    assert_eq!(m_lines(&ok_sdp_text(&result))[1], ("video".to_string(), 0));
    assert_eq!(engine.conference().forward().seat_count(), 2);
    assert_eq!(engine.endpoint_calls.len(), 3, "two audio and one video");
}

#[tokio::test]
async fn interleaved_mode_is_declined_with_its_reason() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let (_, audio) = phone().await;
    let (_, video) = phone().await;
    let result = join(
        &engine,
        ForwardMedia::Translate,
        "a",
        offer(
            audio,
            Some((video, 99, "sendrecv", "packetization-mode=2")),
            None,
        ),
        profile(carry_video()),
    )
    .await;
    assert_eq!(streams(&result), ["audio"]);
    assert!(video_declined(&result)
        .unwrap()
        .contains("packetization-mode 2"));
}

#[tokio::test]
async fn the_controllers_video_fmtp_fixes_the_format_and_is_answered_as_given() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let (_, audio) = phone().await;
    let (_, video) = phone().await;
    let controller = VideoProfile {
        fmtp: Some(CHP_L31.to_string()),
        bandwidth_kbps: None,
    };
    let result = join(
        &engine,
        ForwardMedia::Translate,
        "a",
        offer(
            audio,
            Some((
                video,
                99,
                "sendrecv",
                "profile-level-id=42e01f;packetization-mode=1",
            )),
            None,
        ),
        profile(Some(controller)),
    )
    .await;
    assert_eq!(streams(&result), ["audio"], "the seat did not offer 640c1f");
    assert!(video_declined(&result).unwrap().contains("640c1f"));
}

#[tokio::test]
async fn a_video_fmtp_with_a_line_break_refuses_the_join_before_anything_is_allocated() {
    let engine = engine_of(16);
    let (_, audio) = phone().await;
    let (_, video) = phone().await;
    let result = join(
        &engine,
        ForwardMedia::Translate,
        "a",
        offer(audio, Some((video, 99, "sendrecv", CHP_L31)), None),
        profile(Some(VideoProfile {
            fmtp: Some("packetization-mode=1\r\na=sendrecv".to_string()),
            bandwidth_kbps: None,
        })),
    )
    .await;
    let CmdResult::Error { reason } = result else {
        panic!("expected a refusal");
    };
    assert!(reason.contains("line break"), "{reason}");
    assert!(engine.endpoint_calls.is_empty());
    assert_eq!(engine.conference().forward().seat_count(), 0);
}

#[tokio::test]
async fn a_preserve_room_declines_video_with_the_reason() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let (_, audio) = phone().await;
    let (_, video) = phone().await;
    let result = join(
        &engine,
        ForwardMedia::Preserve,
        "a",
        offer(audio, Some((video, 99, "sendrecv", CHP_L31)), None),
        profile(carry_video()),
    )
    .await;
    assert_eq!(streams(&result), ["audio"]);
    assert!(video_declined(&result).unwrap().contains("translate"));
    assert_eq!(m_lines(&ok_sdp_text(&result))[1], ("video".to_string(), 0));
}

#[tokio::test]
async fn an_sdes_seat_declines_video_with_the_reason() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let (_, audio) = phone().await;
    let (_, video) = phone().await;
    let mut text = offer(audio, Some((video, 99, "sendrecv", CHP_L31)), None);
    text = text.replacen("RTP/AVP 96", "RTP/SAVP 96", 1).replacen(
        "a=rtcp-mux\r\nm=video",
        "a=rtcp-mux\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd\r\nm=video",
        1,
    );
    let result = join(
        &engine,
        ForwardMedia::Translate,
        "a",
        text,
        profile(carry_video()),
    )
    .await;
    assert_eq!(streams(&result), ["audio"]);
    assert!(video_declined(&result).unwrap().contains("SRTP"));
    assert_eq!(m_lines(&ok_sdp_text(&result))[1], ("video".to_string(), 0));
}

#[tokio::test]
async fn leaving_frees_the_video_endpoint() {
    // Two endpoints: a video seat holds both, and joining again proves both came back.
    let engine = engine_of(2);
    let _events = engine.register_client(CLIENT);
    for _ in 0..3 {
        let _phone = video_phone(&engine, "a", 99, "sendrecv", CHP_L31).await;
        assert_eq!(engine.endpoint_calls.len(), 2);
        let result = engine
            .handle(
                CLIENT,
                Command::ForwardLeave {
                    conference_id: ROOM.into(),
                    from_tag: "a".into(),
                },
            )
            .await;
        assert_eq!(result, ok_empty());
        assert!(engine.endpoint_calls.is_empty());
    }
}

#[tokio::test]
async fn a_video_offer_the_room_would_refuse_leaks_nothing() {
    // A seat the room refuses after its endpoints were allocated (here a duplicate tag) must free
    // them all: with three in the pool, the seed holds one, and the refused seat's audio and video
    // would hold the others.
    let engine = engine_of(3);
    let _events = engine.register_client(CLIENT);
    let (_, seed) = phone().await;
    let seeded = join(
        &engine,
        ForwardMedia::Translate,
        "b",
        offer(seed, None, None),
        profile(None),
    )
    .await;
    assert!(matches!(seeded, CmdResult::Ok { .. }), "{seeded:?}");
    let (_, audio) = phone().await;
    let (_, video) = phone().await;
    let refused = join(
        &engine,
        ForwardMedia::Translate,
        "b",
        offer(audio, Some((video, 99, "sendrecv", CHP_L31)), None),
        profile(carry_video()),
    )
    .await;
    assert!(matches!(refused, CmdResult::Error { .. }), "{refused:?}");
    assert_eq!(engine.conference().forward().seat_count(), 1);
    assert_eq!(engine.endpoint_calls.len(), 1, "only the seed's endpoint");
    // The freed endpoint is usable: a video seat of the right format takes both.
    let (_, audio) = phone().await;
    let (_, video) = phone().await;
    let seated = join(
        &engine,
        ForwardMedia::Translate,
        "c",
        offer(audio, Some((video, 99, "sendrecv", CHP_L31)), None),
        profile(carry_video()),
    )
    .await;
    assert_eq!(streams(&seated), ["audio", "video"]);
}

/// The first audio format an offer lists: its payload type, `a=rtpmap` body and `a=fmtp` body.
fn first_audio(offered: &str) -> (u8, String, Option<String>) {
    let audio = offered
        .split("m=audio ")
        .nth(1)
        .and_then(|rest| rest.split("m=video").next())
        .expect("an audio section");
    let rtpmap = audio
        .split("\r\n")
        .find_map(|line| line.strip_prefix("a=rtpmap:"))
        .expect("an rtpmap");
    let (payload_type, mapping) = rtpmap.split_once(' ').expect("rtpmap fields");
    let fmtp = audio
        .split("\r\n")
        .find_map(|line| line.strip_prefix(&format!("a=fmtp:{payload_type} ")))
        .map(str::to_string);
    (
        payload_type.parse().expect("payload type"),
        mapping.to_string(),
        fmtp,
    )
}

/// A member's answer to `offered`: its first audio format, and video at `video_port` (0 declines it).
fn member_answer(
    offered: &str,
    audio: SocketAddr,
    video_port: u16,
    direction: &str,
    fmtp: &str,
) -> String {
    let (audio_type, mapping, audio_fmtp) = first_audio(offered);
    let audio_fmtp = audio_fmtp
        .map(|parameters| format!("a=fmtp:{audio_type} {parameters}\r\n"))
        .unwrap_or_default();
    let video_type = sdp::video::OFFER_PAYLOAD_TYPE;
    format!(
        "v=0\r\no=- 7 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {audio_type}\r\na=rtpmap:{audio_type} {mapping}\r\n{audio_fmtp}\
         a=sendrecv\r\na=rtcp-mux\r\n\
         m=video {video_port} RTP/AVP {video_type}\r\na=rtpmap:{video_type} H264/90000\r\n\
         a=fmtp:{video_type} {fmtp}\r\na={direction}\r\na=rtcp-mux\r\n",
        ip = audio.ip(),
        port = audio.port()
    )
}

async fn offer_member(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    profile: ProfileFlags,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                media: ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                profile,
            },
        )
        .await
}

async fn answer_member(engine: &Engine<UdpLoopbackDatapath>, tag: &str, sdp: String) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardAnswer {
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                sdp,
                received_from: None,
            },
        )
        .await
}

#[tokio::test]
async fn a_forward_offer_with_a_video_profile_offers_video_and_its_answer_seats_it() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let talker = video_phone(&engine, "a", 99, "sendrecv", CHP_L31).await;
    let offered = ok_sdp_text(&offer_member(&engine, "b", profile(carry_video())).await);
    let video = sdp::video::parse_video(&offered).expect("the offer carries video");
    // RFC 4585 §4.2: RTP/AVPF, offering the three feedback types the room supports.
    assert_eq!(video.transport, "RTP/AVPF");
    assert_eq!(
        video.payloads[0].feedback,
        sdp::video::VideoFeedback::SUPPORTED
    );
    assert_eq!(video.direction, sdp::MediaDirection::SendRecv);
    assert_eq!(
        video.payloads[0].payload_type,
        sdp::video::OFFER_PAYLOAD_TYPE
    );
    assert!(offered.contains("b=AS:1200"), "{offered}");
    // The room exists and carries 640c1f: the offer says so.
    assert!(offered.contains(CHP_L31), "{offered}");
    let (member_audio, audio_address) = phone().await;
    let (member_video, video_address) = phone().await;
    let result = answer_member(
        &engine,
        "b",
        member_answer(
            &offered,
            audio_address,
            video_address.port(),
            "sendrecv",
            CHP_L31,
        ),
    )
    .await;
    assert_eq!(streams(&result), ["audio", "video"]);
    assert_eq!(video_declined(&result), None);
    set_source(&engine, "a").await;
    talker
        .video
        .send_to(
            &video_packet(99, 1, 0, 0xA0A0_A0A0, true, &[0x65, 9]),
            talker.engine_video,
        )
        .await
        .expect("send");
    let heard = recv_rtp(&member_video, SHORT).await.expect("video");
    assert_eq!(RtpPacket::parse(&heard).expect("rtp").payload_type, 126);
    drop(member_audio);
}

#[tokio::test]
async fn a_member_that_declines_the_offered_video_is_seated_audio_only_and_the_endpoint_is_freed() {
    // Four endpoints: a seed seat takes two, the offer takes the other two, the declined video gives
    // one back, and a second seat proves it.
    let engine = engine_of(4);
    let _events = engine.register_client(CLIENT);
    let _seed = video_phone(&engine, "seed", 99, "sendrecv", CHP_L31).await;
    let offered = ok_sdp_text(&offer_member(&engine, "a", profile(carry_video())).await);
    assert!(sdp::video::parse_video(&offered).is_some());
    let (_audio, audio_address) = phone().await;
    let result = answer_member(
        &engine,
        "a",
        member_answer(&offered, audio_address, 0, "sendrecv", CHP_L31),
    )
    .await;
    assert_eq!(streams(&result), ["audio"]);
    assert!(video_declined(&result).unwrap().contains("declined"));
    assert_eq!(
        engine.endpoint_calls.len(),
        3,
        "the seed's two and the member's audio"
    );
    let (_, second) = phone().await;
    let seated = join(
        &engine,
        ForwardMedia::Translate,
        "b",
        offer(second, None, None),
        profile(None),
    )
    .await;
    assert!(matches!(seated, CmdResult::Ok { .. }), "{seated:?}");
}

#[tokio::test]
async fn an_expired_unanswered_video_offer_frees_both_endpoints() {
    let engine = engine_of(2);
    let _events = engine.register_client(CLIENT);
    offer_member(&engine, "a", profile(carry_video())).await;
    let left = engine
        .handle(
            CLIENT,
            Command::ForwardLeave {
                conference_id: ROOM.into(),
                from_tag: "a".into(),
            },
        )
        .await;
    assert_eq!(left, ok_empty());
    // Both came back.
    let _phone = video_phone(&engine, "b", 99, "sendrecv", CHP_L31).await;
}

#[tokio::test]
async fn an_offer_in_a_room_that_cannot_carry_video_says_so() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let result = engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                media: ForwardMedia::Preserve,
                conference_id: ROOM.into(),
                from_tag: "a".into(),
                profile: profile(carry_video()),
            },
        )
        .await;
    let CmdResult::Ok {
        sdp: Some(offered),
        video_declined: Some(reason),
        ..
    } = result
    else {
        panic!("expected an offer with a reason");
    };
    assert!(sdp::video::parse_video(&offered).is_none());
    assert!(reason.contains("translate"), "{reason}");
}

#[tokio::test]
async fn node_info_advertises_forward_video() {
    let engine = engine_of(2);
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("node_info answers a node");
    };
    assert!(node.features.iter().any(|name| name == "forward_video"));
    assert!(node
        .features
        .iter()
        .any(|name| name == "forward_video_keyframe"));
}

/// The first RTCP datagram carrying feedback (a PLI, FIR or NACK) that arrives on `socket` within
/// `window`; the room's periodic Sender Reports are skipped.
async fn recv_feedback(socket: &UdpSocket, window: Duration) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + window;
    let mut buffer = [0u8; 2048];
    while let Ok(Ok((length, _))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await
    {
        let datagram = &buffer[..length];
        if length >= 2
            && (64..=95).contains(&(buffer[1] & 0x7f))
            && siphon_rtp_media::rtcp::feedback_packets(datagram).any(|item| item.is_ok())
        {
            return Some(datagram.to_vec());
        }
    }
    None
}

/// A seated phone that offered `RTP/AVPF` video with all three feedback types (RFC 4585 §4.2).
async fn avpf_video_phone(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    payload_type: u8,
) -> Phone {
    let (audio, audio_address) = phone().await;
    let (video, video_address) = phone().await;
    let text = offer(
        audio_address,
        Some((video_address, payload_type, "sendrecv", CHP_L31)),
        None,
    )
    .replace(
        &format!("m=video {} RTP/AVP {payload_type}", video_address.port()),
        &format!("m=video {} RTP/AVPF {payload_type}", video_address.port()),
    )
    .replace(
        "a=extmap:1",
        &format!(
            "a=rtcp-fb:{payload_type} nack\r\na=rtcp-fb:{payload_type} nack pli\r\n\
             a=rtcp-fb:{payload_type} ccm fir\r\na=extmap:1"
        ),
    );
    let result = join(
        engine,
        ForwardMedia::Translate,
        tag,
        text,
        profile(carry_video()),
    )
    .await;
    let answer = ok_sdp_text(&result);
    let engine_video = sdp::video::parse_video(&answer)
        .expect("a live video section")
        .remote;
    Phone {
        audio,
        video,
        engine_video,
        answer,
    }
}

/// The next `forward_keyframe` event: `(from_tag, timed_out)`.
async fn next_keyframe_event(events: &flume::Receiver<Event>) -> (String, bool) {
    let deadline = tokio::time::Instant::now() + SHORT;
    while let Ok(Ok(event)) = tokio::time::timeout_at(deadline, events.recv_async()).await {
        if let Event::ForwardKeyframe {
            conference_id,
            from_tag,
            timed_out,
            ..
        } = event
        {
            assert_eq!(conference_id, ROOM);
            return (from_tag, timed_out);
        }
    }
    panic!("no forward_keyframe event");
}

#[tokio::test]
async fn a_switch_asks_the_source_for_a_keyframe_and_the_receiver_is_started_on_it() {
    let engine = engine_of(16);
    let events = engine.register_client(CLIENT);
    let talker = avpf_video_phone(&engine, "a", 99).await;
    let listener = avpf_video_phone(&engine, "b", 105).await;
    // The answer accepted what both offered, and says so (RFC 4585 §4.2).
    for line in [
        "a=rtcp-fb:99 nack\r\n",
        "a=rtcp-fb:99 nack pli\r\n",
        "a=rtcp-fb:99 ccm fir\r\n",
    ] {
        assert!(talker.answer.contains(line), "{line}: {}", talker.answer);
    }
    let (sps, pps, idr) = (
        [0x67u8, 0x64, 0x00, 0x1F],
        [0x68u8, 0xEE, 0x3C],
        [0x65u8, 0x88, 0x84],
    );
    // The talker has been sending its stream; only the source's reaches the others.
    for (sequence, payload) in [(1u16, &sps[..]), (2, &pps[..])] {
        talker
            .video
            .send_to(
                &video_packet(99, sequence, 9_000, 0xA0A0_A0A0, false, payload),
                talker.engine_video,
            )
            .await
            .expect("send");
    }
    // The room has taken them in before the switch.
    tokio::time::sleep(Duration::from_millis(100)).await;
    set_source(&engine, "a").await;
    // A compound arrives at the talker's video socket: RR, SDES, then a PLI about its stream.
    let request = recv_feedback(&talker.video, SHORT)
        .await
        .expect("a keyframe request");
    let feedback: Vec<_> = siphon_rtp_media::rtcp::feedback_packets(&request)
        .map(|item| item.expect("well formed"))
        .collect();
    assert!(
        matches!(
            feedback[..],
            [siphon_rtp_media::rtcp::Feedback::Pli {
                media_ssrc: 0xA0A0_A0A0,
                ..
            }]
        ),
        "{feedback:?}"
    );
    // Pictures before the keyframe are not sent on.
    talker
        .video
        .send_to(
            &video_packet(99, 3, 12_000, 0xA0A0_A0A0, true, &[0x41, 0x9A, 0]),
            talker.engine_video,
        )
        .await
        .expect("send");
    assert!(recv_rtp(&listener.video, NEGATIVE).await.is_none());
    talker
        .video
        .send_to(
            &video_packet(99, 4, 15_000, 0xA0A0_A0A0, true, &idr),
            talker.engine_video,
        )
        .await
        .expect("send");
    let mut heard = Vec::new();
    for _ in 0..3 {
        let datagram = recv_rtp(&listener.video, SHORT).await.expect("video");
        let packet = RtpPacket::parse(&datagram).expect("rtp");
        assert_eq!(packet.payload_type, 105, "the listener's own number");
        heard.push((packet.sequence, packet.payload.to_vec()));
    }
    let sequences: Vec<u16> = heard.iter().map(|(sequence, _)| *sequence).collect();
    assert_eq!(sequences[1], sequences[0].wrapping_add(1));
    assert_eq!(sequences[2], sequences[1].wrapping_add(1));
    let payloads: Vec<&[u8]> = heard
        .iter()
        .map(|(_, payload)| payload.as_slice())
        .collect();
    assert_eq!(payloads, [&sps[..], &pps[..], &idr[..]]);
    assert_eq!(next_keyframe_event(&events).await, ("a".to_string(), false));
    drop((talker.audio, listener.audio));
}

#[tokio::test]
async fn a_source_that_offered_plain_avp_is_sent_no_feedback() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let talker = video_phone(&engine, "a", 99, "sendrecv", CHP_L31).await;
    let _listener = video_phone(&engine, "b", 105, "sendrecv", CHP_L31).await;
    assert!(!talker.answer.contains("rtcp-fb"), "{}", talker.answer);
    talker
        .video
        .send_to(
            &video_packet(99, 1, 0, 0xA0A0_A0A0, false, &[0x41, 0]),
            talker.engine_video,
        )
        .await
        .expect("send");
    set_source(&engine, "a").await;
    assert!(
        recv_feedback(&talker.video, NEGATIVE).await.is_none(),
        "RTP/AVP has no feedback to send"
    );
}

#[tokio::test]
async fn a_member_that_answers_an_offer_with_avpf_feedback_is_asked_for_keyframes_as_a_source() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let listener = avpf_video_phone(&engine, "a", 99).await;
    let offered = ok_sdp_text(&offer_member(&engine, "b", profile(carry_video())).await);
    let (member_audio, audio_address) = phone().await;
    let (member_video, video_address) = phone().await;
    let video_type = sdp::video::OFFER_PAYLOAD_TYPE;
    // RFC 4585 §4.2: the answer keeps the offer's RTP/AVPF and accepts nack pli only.
    let answer = member_answer(
        &offered,
        audio_address,
        video_address.port(),
        "sendrecv",
        CHP_L31,
    )
    .replace(
        &format!("RTP/AVP {video_type}"),
        &format!("RTP/AVPF {video_type}"),
    ) + &format!("a=rtcp-fb:{video_type} nack pli\r\n");
    let result = answer_member(&engine, "b", answer).await;
    assert_eq!(streams(&result), ["audio", "video"]);
    // The member's own stream, so the room knows its SSRC before the switch.
    let engine_video = sdp::video::parse_video(&offered).expect("video").remote;
    member_video
        .send_to(
            &video_packet(126, 1, 0, 0xC0C0_C0C0, false, &[0x41, 0]),
            engine_video,
        )
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(100)).await;
    set_source(&engine, "b").await;
    let request = recv_feedback(&member_video, SHORT)
        .await
        .expect("a keyframe request");
    let feedback: Vec<_> = siphon_rtp_media::rtcp::feedback_packets(&request)
        .map(|item| item.expect("well formed"))
        .collect();
    assert!(
        matches!(
            feedback[..],
            [siphon_rtp_media::rtcp::Feedback::Pli {
                media_ssrc: 0xC0C0_C0C0,
                ..
            }]
        ),
        "only what the member accepted: {feedback:?}"
    );
    drop((member_audio, listener.audio));
}
