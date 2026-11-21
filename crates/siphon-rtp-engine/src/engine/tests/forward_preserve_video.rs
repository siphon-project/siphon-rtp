//! Video in a `media: preserve` forwarding room end to end on the UDP-loopback datapath (3GPP
//! TS 24.281 §6.2, TS 33.180 §7.5.2, §9.4): the source's SRTP video leaves every other seat byte for
//! byte under the one payload type the room fixed, its RTCP is hop by hop under each seat's media key,
//! the engine holds no key of its own for it, and the controller's `a=key-mgmt` is written on the
//! video section as on the audio one.

use super::forward_video::{
    answer_member, carry_video, engine_of, join, m_lines, recv_rtp, streams, video_declined,
    video_packet, CHP_L31, NEGATIVE, ROOM, SHORT,
};
use super::*;
use siphon_rtp_media::rtcp::{self, Feedback};
use siphon_rtp_proto::{FloorKey, ForwardMedia};
use siphon_rtp_srtp::srtcp_gcm::{FloorMasterKey, SrtcpGcmContext};

const KEY_MGMT: &str = "mikey AQAFgM0XflABAAAAAAAAAAAAAAsAyONQ";

fn media_key(index: u32) -> FloorKey {
    FloorKey {
        mki: index,
        key: vec![0x30 + index as u8; 16],
        salt: vec![0x50 + index as u8; 12],
    }
}

/// What a phone holds for [`media_key`], read independently of the engine's conversion: one context
/// per stream, as a client holds one SRTCP index per SSRC.
fn phone_context(index: u32) -> SrtcpGcmContext {
    SrtcpGcmContext::new(&[FloorMasterKey::from_salt_96(
        index,
        [0x30 + index as u8; 16],
        &[0x50 + index as u8; 12],
    )])
    .expect("context")
}

fn protect(context: &mut SrtcpGcmContext, rtcp: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    context.protect(rtcp, true, &mut wire).expect("protect");
    wire
}

/// An offer of `RTP/SAVP` audio and `RTP/SAVPF` video (all three feedback types) with no `a=crypto`,
/// and the offerer's own `a=key-mgmt` on each, which must never be echoed.
fn secure_offer(audio: SocketAddr, video: SocketAddr, video_type: u8, extra_video: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {audio_port} RTP/SAVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n\
         a=rtcp-mux\r\na=key-mgmt:mikey PEER-AUDIO\r\n\
         m=video {video_port} RTP/SAVPF {video_type}\r\na=rtpmap:{video_type} H264/90000\r\n\
         a=fmtp:{video_type} {CHP_L31}\r\na=rtcp-fb:{video_type} nack\r\n\
         a=rtcp-fb:{video_type} nack pli\r\na=rtcp-fb:{video_type} ccm fir\r\n\
         a=sendrecv\r\na=rtcp-mux\r\na=key-mgmt:mikey PEER-VIDEO\r\n{extra_video}",
        ip = audio.ip(),
        audio_port = audio.port(),
        video_port = video.port(),
    )
}

fn preserve_profile(keys: Vec<FloorKey>) -> ProfileFlags {
    ProfileFlags {
        video: carry_video(),
        key_mgmt: Some(KEY_MGMT.to_string()),
        media_srtcp_keys: keys,
        ..ProfileFlags::default()
    }
}

fn key_mgmt_lines(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .filter(|line| line.starts_with("a=key-mgmt:"))
        .collect()
}

struct SecurePhone {
    audio: UdpSocket,
    video: UdpSocket,
    engine_video: SocketAddr,
    answer: String,
}

async fn secure_phone(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    video_type: u8,
    keys: Vec<FloorKey>,
) -> SecurePhone {
    let (audio, audio_address) = phone().await;
    let (video, video_address) = phone().await;
    let result = join(
        engine,
        ForwardMedia::Preserve,
        tag,
        secure_offer(audio_address, video_address, video_type, ""),
        preserve_profile(keys),
    )
    .await;
    assert_eq!(streams(&result), ["audio", "video"], "{result:?}");
    let answer = ok_sdp_text(&result);
    let engine_video = sdp::video::parse_video(&answer)
        .expect("a live video section")
        .remote;
    SecurePhone {
        audio,
        video,
        engine_video,
        answer,
    }
}

/// An RTP header followed by what an SRTP sender would produce: ciphertext and an auth tag.
fn srtp_video(payload_type: u8, sequence: u16, ssrc: u32) -> Vec<u8> {
    let mut payload: Vec<u8> = (0..60u8)
        .map(|byte| byte.wrapping_mul(29) ^ (sequence as u8))
        .collect();
    payload.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 1, 2, 3, 4, 5, 6]);
    video_packet(
        payload_type,
        sequence,
        90_000 + u32::from(sequence) * 3000,
        ssrc,
        false,
        &payload,
    )
}

fn pli(sender: u32, media: u32) -> Vec<u8> {
    let mut buffer = [0u8; 64];
    let mut length = rtcp::write_empty_receiver_report(sender, &mut buffer).expect("rr");
    length += rtcp::write_pli(sender, media, &mut buffer[length..]).expect("pli");
    buffer[..length].to_vec()
}

fn nack(sender: u32, media: u32, pid: u16) -> Vec<u8> {
    let mut buffer = [0u8; 64];
    let mut length = rtcp::write_empty_receiver_report(sender, &mut buffer).expect("rr");
    length += rtcp::write_nack(sender, media, pid, 0, &mut buffer[length..]).expect("nack");
    buffer[..length].to_vec()
}

/// The next SRTCP datagram that arrives on `socket` within `window`. Its payload is encrypted, but the
/// first RTCP header is in the clear (RFC 3711 §3.4): version 2 and a packet type of 200 to 206.
async fn recv_srtcp(socket: &UdpSocket, window: Duration) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + window;
    let mut buffer = [0u8; 2048];
    while let Ok(Ok((length, _))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await
    {
        if length >= 8 && buffer[0] >> 6 == 2 && (200..=206).contains(&buffer[1]) {
            return Some(buffer[..length].to_vec());
        }
    }
    None
}

const SSRC_A: u32 = 0xA0A0_A0A0;
const SSRC_B: u32 = 0xB0B0_B0B0;

#[tokio::test]
async fn the_sources_srtp_video_reaches_the_other_seat_byte_for_byte() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let a = secure_phone(&engine, "a", 99, vec![]).await;
    let b = secure_phone(&engine, "b", 99, vec![]).await;
    super::forward_video::set_source(&engine, "a").await;
    let sent = srtp_video(99, 7, SSRC_A);
    a.video.send_to(&sent, a.engine_video).await.expect("send");
    let heard = recv_rtp(&b.video, SHORT).await.expect("video");
    assert_eq!(heard, sent, "SSRC, sequence, payload and tag untouched");
    assert!(
        recv_rtp(&a.video, NEGATIVE).await.is_none(),
        "the source never hears itself"
    );
    // The listener's own video goes nowhere while it is not the source.
    b.video
        .send_to(&srtp_video(99, 1, SSRC_B), b.engine_video)
        .await
        .expect("send");
    assert!(recv_rtp(&a.video, NEGATIVE).await.is_none());
    // The switch moves video with it.
    super::forward_video::set_source(&engine, "b").await;
    let back = srtp_video(99, 2, SSRC_B);
    b.video.send_to(&back, b.engine_video).await.expect("send");
    assert_eq!(recv_rtp(&a.video, SHORT).await.expect("video"), back);
    drop((a.audio, b.audio));
}

#[tokio::test]
async fn the_answer_keeps_the_offered_secure_transport_holds_no_key_and_carries_the_controllers_line_on_both_streams(
) {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let a = secure_phone(&engine, "a", 99, vec![]).await;
    let answer = &a.answer;
    let video = sdp::video::parse_video(answer).expect("video");
    assert_eq!(video.transport, "RTP/SAVPF");
    assert_eq!(
        video.payloads[0].feedback,
        sdp::video::VideoFeedback::SUPPORTED,
        "the offer's feedback is answered"
    );
    assert!(
        !answer.contains("a=crypto") && !answer.contains("a=fingerprint"),
        "the engine holds no key: {answer}"
    );
    assert!(!answer.contains("PEER"), "never an echo: {answer}");
    assert_eq!(
        key_mgmt_lines(answer),
        vec![format!("a=key-mgmt:{KEY_MGMT}"); 2],
        "the same line at the end of the audio and of the video section: {answer}"
    );
    let audio_end = answer.find("m=video").unwrap();
    assert!(answer[..audio_end].contains("a=key-mgmt:"), "{answer}");
}

#[tokio::test]
async fn a_video_with_an_a_crypto_or_a_fingerprint_is_declined_with_the_reason_and_the_seat_is_audio_only(
) {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    for (tag, extra, expected) in [
        (
            "a",
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd\r\n",
            "a=crypto",
        ),
        ("b", "a=fingerprint:sha-256 AA:BB:CC\r\n", "a=fingerprint"),
    ] {
        let (_, audio) = phone().await;
        let (_, video) = phone().await;
        let result = join(
            &engine,
            ForwardMedia::Preserve,
            tag,
            secure_offer(audio, video, 99, extra),
            preserve_profile(vec![]),
        )
        .await;
        assert_eq!(streams(&result), ["audio"], "{result:?}");
        let reason = video_declined(&result).expect("a reason");
        assert!(reason.contains(expected), "{reason}");
        assert_eq!(m_lines(&ok_sdp_text(&result))[1], ("video".to_string(), 0));
    }
    assert_eq!(engine.endpoint_calls.len(), 2, "only the audio endpoints");
}

#[tokio::test]
async fn a_seat_whose_video_payload_type_differs_from_the_rooms_is_declined_audio_only() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let _a = secure_phone(&engine, "a", 99, vec![]).await;
    let (_, audio) = phone().await;
    let (_, video) = phone().await;
    let result = join(
        &engine,
        ForwardMedia::Preserve,
        "b",
        secure_offer(audio, video, 100, ""),
        preserve_profile(vec![]),
    )
    .await;
    assert_eq!(streams(&result), ["audio"], "{result:?}");
    let reason = video_declined(&result).expect("a reason");
    assert!(
        reason.contains("payload type 100") && reason.contains("unchanged"),
        "{reason}"
    );
    assert_eq!(m_lines(&ok_sdp_text(&result))[1], ("video".to_string(), 0));
}

#[tokio::test]
async fn video_bundled_with_the_audio_is_declined_in_a_preserve_room() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let (_, audio) = phone().await;
    let (_, video) = phone().await;
    let text = secure_offer(audio, video, 99, "a=mid:1\r\n")
        .replacen("a=rtcp-mux\r\n", "a=rtcp-mux\r\na=mid:0\r\n", 1)
        .replacen("c=IN IP4", "a=group:BUNDLE 0 1\r\nc=IN IP4", 1);
    let result = join(
        &engine,
        ForwardMedia::Preserve,
        "a",
        text,
        preserve_profile(vec![]),
    )
    .await;
    assert_eq!(streams(&result), ["audio"], "{result:?}");
    assert!(video_declined(&result).unwrap().contains("BUNDLE"));
}

#[tokio::test]
async fn a_switch_sends_the_keyed_source_one_sealed_pli_and_a_receivers_pli_and_nack_are_served() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let a = secure_phone(&engine, "a", 99, vec![media_key(1)]).await;
    let b = secure_phone(&engine, "b", 99, vec![media_key(2)]).await;
    // The source's video SSRC is what a request names: it must have sent video before it is chosen.
    a.video
        .send_to(&srtp_video(99, 1, SSRC_A), a.engine_video)
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(100)).await;
    super::forward_video::set_source(&engine, "a").await;
    let request = recv_srtcp(&a.video, SHORT)
        .await
        .expect("a PLI at the switch");
    let mut opened = Vec::new();
    phone_context(1)
        .unprotect(&request, &mut opened)
        .expect("sealed under the source's own media key");
    let feedback: Vec<_> = rtcp::feedback_packets(&opened)
        .collect::<Result<_, _>>()
        .expect("feedback");
    assert!(
        matches!(feedback.as_slice(), [Feedback::Pli { media_ssrc, .. }] if *media_ssrc == SSRC_A),
        "{feedback:?}"
    );
    assert!(
        recv_srtcp(&a.video, Duration::from_millis(1500))
            .await
            .is_none(),
        "one request for the switch, then silence"
    );
    // The source's video, then a receiver that lost it asks for it again under its own key.
    let sent = srtp_video(99, 2, SSRC_A);
    a.video.send_to(&sent, a.engine_video).await.expect("send");
    assert_eq!(recv_rtp(&b.video, SHORT).await.expect("video"), sent);
    let mut receiver = phone_context(2);
    b.video
        .send_to(
            &protect(&mut receiver, &nack(SSRC_B, SSRC_A, 2)),
            b.engine_video,
        )
        .await
        .expect("send");
    assert_eq!(
        recv_rtp(&b.video, SHORT)
            .await
            .expect("the stored original"),
        sent
    );
    // A receiver's PLI is passed to the source, sealed under the source's key.
    b.video
        .send_to(
            &protect(&mut receiver, &pli(SSRC_B, SSRC_A)),
            b.engine_video,
        )
        .await
        .expect("send");
    let relayed = recv_srtcp(&a.video, SHORT)
        .await
        .expect("a PLI for the receiver");
    let mut opened = Vec::new();
    phone_context(1)
        .unprotect(&relayed, &mut opened)
        .expect("sealed under the source's key");
    assert!(rtcp::feedback_packets(&opened).any(|item| item.is_ok()));
    drop((a.audio, b.audio));
}

async fn offer_preserve_member(engine: &Engine<UdpLoopbackDatapath>, tag: &str) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                media: ForwardMedia::Preserve,
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                profile: preserve_profile(vec![]),
            },
        )
        .await
}

/// A member's answer to a preserve offer: its audio, and its video under `video_type` on `transport`.
fn preserve_answer(
    offered: &str,
    audio: SocketAddr,
    video: SocketAddr,
    video_type: u8,
    transport: &str,
) -> String {
    let (audio_type, mapping, audio_fmtp) = super::forward_video::first_audio(offered);
    let audio_fmtp = audio_fmtp
        .map(|parameters| format!("a=fmtp:{audio_type} {parameters}\r\n"))
        .unwrap_or_default();
    format!(
        "v=0\r\no=- 7 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/SAVP {audio_type}\r\na=rtpmap:{audio_type} {mapping}\r\n{audio_fmtp}\
         a=sendrecv\r\na=rtcp-mux\r\n\
         m=video {video_port} {transport} {video_type}\r\na=rtpmap:{video_type} H264/90000\r\n\
         a=fmtp:{video_type} {CHP_L31}\r\na=sendrecv\r\na=rtcp-mux\r\n",
        ip = audio.ip(),
        port = audio.port(),
        video_port = video.port(),
    )
}

#[tokio::test]
async fn a_forward_offer_offers_secure_video_with_the_controllers_key_line_and_seats_the_answer() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let offered = ok_sdp_text(&offer_preserve_member(&engine, "a").await);
    let video = sdp::video::parse_video(&offered).expect("the offer carries video");
    assert_eq!(video.transport, "RTP/SAVPF", "{offered}");
    assert!(m_lines(&offered).iter().all(|(_, port)| *port != 0));
    assert!(
        !offered.contains("a=crypto") && !offered.contains("a=fingerprint"),
        "{offered}"
    );
    assert_eq!(
        key_mgmt_lines(&offered),
        vec![format!("a=key-mgmt:{KEY_MGMT}"); 2],
        "one line on the audio and one on the video section: {offered}"
    );
    let offered_type = video.payloads[0].payload_type;
    let (audio, audio_address) = phone().await;
    let (member_video, video_address) = phone().await;
    let result = answer_member(
        &engine,
        "a",
        preserve_answer(
            &offered,
            audio_address,
            video_address,
            offered_type,
            "RTP/SAVPF",
        ),
    )
    .await;
    assert_eq!(streams(&result), ["audio", "video"], "{result:?}");
    assert_eq!(video_declined(&result), None);
    // The room now fixed the payload type: the next offer names it, and carries on from there.
    let second = ok_sdp_text(&offer_preserve_member(&engine, "b").await);
    assert_eq!(
        sdp::video::parse_video(&second).expect("video").payloads[0].payload_type,
        offered_type
    );
    drop((audio, member_video));
}

#[tokio::test]
async fn an_answer_in_another_transport_or_payload_type_leaves_the_seat_audio_only_and_frees_the_endpoint(
) {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    let offered = ok_sdp_text(&offer_preserve_member(&engine, "a").await);
    let offered_type = sdp::video::parse_video(&offered).unwrap().payloads[0].payload_type;
    let (_audio, audio_address) = phone().await;
    let (_video, video_address) = phone().await;
    // RFC 3264 §6: the answer keeps the offer's transport.
    let result = answer_member(
        &engine,
        "a",
        preserve_answer(
            &offered,
            audio_address,
            video_address,
            offered_type,
            "RTP/AVPF",
        ),
    )
    .await;
    assert_eq!(streams(&result), ["audio"], "{result:?}");
    assert!(video_declined(&result).unwrap().contains("RTP/SAVPF"));
    // A second member is offered and answers in the number the first fixed? No video seat fixed one
    // yet, so seat one with video first, then refuse a different number.
    let offered = ok_sdp_text(&offer_preserve_member(&engine, "b").await);
    let (_audio, audio_address) = phone().await;
    let (_video, video_address) = phone().await;
    let seated = answer_member(
        &engine,
        "b",
        preserve_answer(
            &offered,
            audio_address,
            video_address,
            offered_type,
            "RTP/SAVPF",
        ),
    )
    .await;
    assert_eq!(streams(&seated), ["audio", "video"], "{seated:?}");
    let offered = ok_sdp_text(&offer_preserve_member(&engine, "c").await);
    let (_audio, audio_address) = phone().await;
    let (_video, video_address) = phone().await;
    let result = answer_member(
        &engine,
        "c",
        preserve_answer(
            &offered,
            audio_address,
            video_address,
            offered_type + 1,
            "RTP/SAVPF",
        ),
    )
    .await;
    assert_eq!(streams(&result), ["audio"], "{result:?}");
    assert!(video_declined(&result).unwrap().contains("payload type"));
}

#[tokio::test]
async fn node_info_advertises_forward_video_preserve() {
    let engine = engine_of(2);
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("node_info answers a node");
    };
    assert!(node
        .features
        .iter()
        .any(|name| name == "forward_video_preserve"));
}

#[tokio::test]
async fn leaving_frees_the_video_endpoint_of_a_preserve_seat() {
    // Two endpoints: a seat with video holds both, and joining again proves both came back.
    let engine = engine_of(2);
    let _events = engine.register_client(CLIENT);
    for _ in 0..3 {
        let _phone = secure_phone(&engine, "a", 99, vec![]).await;
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
async fn an_answer_is_checked_against_the_offer_that_was_sent_before_the_room() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    // No video seat yet: the offer names the default number, 126.
    let offered = ok_sdp_text(&offer_preserve_member(&engine, "a").await);
    let offered_type = sdp::video::parse_video(&offered).unwrap().payloads[0].payload_type;
    assert_eq!(offered_type, sdp::video::OFFER_PAYLOAD_TYPE);
    let (_audio, audio_address) = phone().await;
    let (_video, video_address) = phone().await;
    // An answer in 99 is not to this offer, and there is no room number to excuse it.
    let result = answer_member(
        &engine,
        "a",
        preserve_answer(&offered, audio_address, video_address, 99, "RTP/SAVPF"),
    )
    .await;
    assert_eq!(streams(&result), ["audio"], "{result:?}");
    let reason = video_declined(&result).unwrap();
    assert!(
        reason.contains("not the offered 126"),
        "the offer is checked first: {reason}"
    );
}

#[tokio::test]
async fn a_join_between_the_offer_and_its_answer_that_fixes_another_number_declines_the_video() {
    let engine = engine_of(16);
    let _events = engine.register_client(CLIENT);
    // An audio-only seat fixes the room's codec, so the offer that follows lists it first.
    let (_, first_audio) = phone().await;
    let (_, first_video) = phone().await;
    let first = join(
        &engine,
        ForwardMedia::Preserve,
        "first",
        secure_offer(first_audio, first_video, 99, ""),
        ProfileFlags {
            video: None,
            ..preserve_profile(vec![])
        },
    )
    .await;
    assert_eq!(streams(&first), ["audio"], "{first:?}");
    let offered = ok_sdp_text(&offer_preserve_member(&engine, "m").await);
    // The room has no video seat, so the offer named 126. Another seat now joins and fixes 99.
    let _joined = secure_phone(&engine, "j", 99, vec![]).await;
    let (_audio, audio_address) = phone().await;
    let (_video, video_address) = phone().await;
    // Keeping the offered number no longer fits the room.
    let kept = answer_member(
        &engine,
        "m",
        preserve_answer(&offered, audio_address, video_address, 126, "RTP/SAVPF"),
    )
    .await;
    assert_eq!(streams(&kept), ["audio"], "{kept:?}");
    let reason = video_declined(&kept).unwrap();
    assert!(
        reason.contains("126") && reason.contains("forwards payload type 99"),
        "{reason}"
    );
    // And the room's number is not the offer's: refused on the offer first.
    let offered = ok_sdp_text(&offer_preserve_member(&engine, "n").await);
    assert_eq!(
        sdp::video::parse_video(&offered).unwrap().payloads[0].payload_type,
        99,
        "an offer made now names the room's number"
    );
}
