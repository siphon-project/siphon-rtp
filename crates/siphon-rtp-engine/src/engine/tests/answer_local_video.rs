//! Video through `answer_local` and `offer_far` (`video_relay: anchor`): the engine answers a caller's
//! `m=video` up front on its own endpoints (the answer is frozen, RFC 3264 §8), drops the caller's
//! picture until a far party answers, and relays it both ways from then on, over the UDP loopback
//! datapath.

use super::call_video::{
    anchor, phone_with_rtcp, received, receiver_report, video_packet, CAMERA_PAYLOAD,
};
use super::*;
use siphon_rtp_proto::VideoRelay;

pub(super) const CALL: &str = "al-video-call";

/// A caller's offer: µ-law audio (muxed) and one H.264 video section with its RTCP on the next port.
pub(super) fn caller_offer(audio: SocketAddr, video: SocketAddr, direction: &str) -> String {
    format!(
        "v=0\r\no=caller 10 10 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {audio_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\na=rtcp-mux\r\n\
         m=video {video_port} RTP/AVPF 96\r\n{CAMERA_PAYLOAD}a={direction}\r\n",
        ip = audio.ip(),
        audio_port = audio.port(),
        video_port = video.port(),
    )
}

/// The far party's answer: µ-law audio and `video_line` (a whole `m=video` section) when given.
pub(super) fn far_answer(audio: SocketAddr, video_section: &str) -> String {
    format!(
        "v=0\r\no=callee 20 20 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\na=rtcp-mux\r\n\
         {video_section}",
        ip = audio.ip(),
        port = audio.port(),
    )
}

pub(super) fn far_video_section(video: SocketAddr, payload_type: u8, direction: &str) -> String {
    format!(
        "m=video {port} RTP/AVPF {payload_type}\r\na=rtpmap:{payload_type} H264/90000\r\n\
         a=fmtp:{payload_type} profile-level-id=42e01f;packetization-mode=1\r\n\
         a=rtcp-fb:{payload_type} nack pli\r\na={direction}\r\n",
        port = video.port(),
    )
}

pub(super) fn engine_with_dispatcher() -> Engine<UdpLoopbackDatapath> {
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
    engine
}

/// The caller's sockets: audio, video RTP and video RTCP.
pub(super) struct Caller {
    pub(super) _audio: UdpSocket,
    pub(super) video: UdpSocket,
    pub(super) video_rtcp: UdpSocket,
    pub(super) audio_addr: SocketAddr,
    pub(super) video_addr: SocketAddr,
}

pub(super) async fn caller() -> Caller {
    let (audio, audio_addr) = phone().await;
    let (video, video_addr, video_rtcp) = phone_with_rtcp().await;
    Caller {
        _audio: audio,
        video,
        video_rtcp,
        audio_addr,
        video_addr,
    }
}

pub(super) async fn answer_locally(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    offer: String,
    profile: ProfileFlags,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                sdp: offer,
                profile,
            },
        )
        .await
}

pub(super) async fn offer_far(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    profile: ProfileFlags,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::OfferFar {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                profile,
            },
        )
        .await
}

pub(super) async fn answer_far(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    to_tag: &str,
    sdp: String,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                to_tag: to_tag.into(),
                sdp,
                profile: ProfileFlags::default(),
            },
        )
        .await
}

pub(super) async fn delete(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    to_tag: Option<&str>,
) {
    let result = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                to_tag: to_tag.map(str::to_string),
            },
        )
        .await;
    assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
}

fn video_declined(result: &CmdResult) -> Option<String> {
    match result {
        CmdResult::Ok { video_declined, .. } => video_declined.clone(),
        other => panic!("expected Ok, got {other:?}"),
    }
}

fn video_section(sdp_text: &str) -> Vec<&str> {
    let mut lines = sdp_text
        .split("\r\n")
        .skip_while(|line| !line.starts_with("m=video"));
    let mut section = Vec::new();
    if let Some(first) = lines.next() {
        section.push(first);
    }
    section.extend(lines.take_while(|line| !line.starts_with("m=")));
    section
}

/// A call that has been answered locally with video anchored, the far leg offered and (when
/// `far_video` is given) answered.
pub(super) struct Grown {
    pub(super) engine: Engine<UdpLoopbackDatapath>,
    pub(super) caller: Caller,
    pub(super) callee_video: UdpSocket,
    pub(super) callee_video_rtcp: UdpSocket,
    pub(super) local_answer: String,
    pub(super) far_offer: String,
    pub(super) answered: CmdResult,
}

pub(super) async fn grown(
    call_id: &str,
    caller_direction: &str,
    far_video: Option<(u8, &str)>,
) -> Grown {
    grown_edited(
        call_id,
        caller_direction,
        far_video,
        &|text| text,
        &|text| text,
    )
    .await
}

/// [`grown`] with the caller's offer and the far video section edited by the test.
pub(super) async fn grown_edited(
    call_id: &str,
    caller_direction: &str,
    far_video: Option<(u8, &str)>,
    edit_offer: &dyn Fn(String) -> String,
    edit_far: &dyn Fn(String) -> String,
) -> Grown {
    let engine = engine_with_dispatcher();
    let caller = caller().await;
    let (callee_audio, callee_audio_addr) = phone().await;
    let (callee_video, callee_video_addr, callee_video_rtcp) = phone_with_rtcp().await;
    let _ = &callee_audio;
    let local = answer_locally(
        &engine,
        call_id,
        edit_offer(caller_offer(
            caller.audio_addr,
            caller.video_addr,
            caller_direction,
        )),
        anchor(),
    )
    .await;
    let local_answer = ok_sdp_text(&local);
    let far_offer = ok_sdp_text(&offer_far(&engine, call_id, ProfileFlags::default()).await);
    let section = far_video
        .map(|(payload_type, direction)| {
            far_video_section(callee_video_addr, payload_type, direction)
        })
        .map(edit_far)
        .unwrap_or_default();
    let answered = answer_far(
        &engine,
        call_id,
        "tag-b",
        far_answer(callee_audio_addr, &section),
    )
    .await;
    Grown {
        engine,
        caller,
        callee_video,
        callee_video_rtcp,
        local_answer,
        far_offer,
        answered,
    }
}

#[tokio::test]
async fn an_anchored_local_answer_answers_video_on_an_engine_port_with_the_callers_formats() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let caller = caller().await;
    for (offered, answered) in [
        ("sendrecv", "a=sendrecv"),
        ("sendonly", "a=recvonly"),
        ("recvonly", "a=sendonly"),
    ] {
        let call_id = format!("{CALL}-{offered}");
        let result = answer_locally(
            &engine,
            &call_id,
            caller_offer(caller.audio_addr, caller.video_addr, offered),
            anchor(),
        )
        .await;
        let answer = ok_sdp_text(&result);
        let stream = sdp::parse_video_stream(&answer).expect("video is answered live");
        assert_ne!(stream.remote_rtp.port(), 0, "{answer}");
        assert_ne!(
            stream.remote_rtp, caller.video_addr,
            "the engine's port: {answer}"
        );
        assert_eq!(stream.remote_rtp.ip(), caller.video_addr.ip(), "{answer}");
        let section = video_section(&answer);
        assert_eq!(
            section[0],
            format!("m=video {} RTP/AVPF 96", stream.remote_rtp.port())
        );
        for line in [
            "a=rtpmap:96 H264/90000",
            "a=fmtp:96 profile-level-id=42e01f;packetization-mode=1",
            "a=rtcp-fb:96 nack pli",
            answered,
        ] {
            assert!(section.contains(&line), "{line} in {section:?}");
        }
        assert!(
            !section.iter().any(
                |line| ["a=sendrecv", "a=sendonly", "a=recvonly"].contains(line)
                    && *line != answered
            ),
            "only the complement direction: {section:?}"
        );
        assert_eq!(video_declined(&result), None);
        assert_eq!(
            engine.calls.get(&call_id).expect("call").video.mode,
            VideoRelay::Anchor
        );
    }
}

#[tokio::test]
async fn a_local_answer_without_video_relay_still_declines_the_video_stream() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let caller = caller().await;
    let result = answer_locally(
        &engine,
        CALL,
        caller_offer(caller.audio_addr, caller.video_addr, "sendrecv"),
        ProfileFlags::default(),
    )
    .await;
    let answer = ok_sdp_text(&result);
    assert_eq!(
        video_section(&answer)[0],
        "m=video 0 RTP/AVPF 96",
        "{answer}"
    );
    assert!(engine.calls.get(CALL).expect("call").near.video.is_none());
}

#[tokio::test]
async fn the_callers_video_is_dropped_and_nothing_is_sent_before_a_far_party_answers() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let caller = caller().await;
    let answer = ok_sdp_text(
        &answer_locally(
            &engine,
            CALL,
            caller_offer(caller.audio_addr, caller.video_addr, "sendrecv"),
            anchor(),
        )
        .await,
    );
    let near_video = sdp::parse_video_stream(&answer).expect("video").remote_rtp;
    let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    for sequence in 1..=3 {
        caller
            .video
            .send_to(&video_packet(sequence), near_video)
            .await
            .expect("send");
        attacker
            .send_to(&video_packet(100 + sequence), near_video)
            .await
            .expect("send");
    }
    assert!(
        received(&caller.video).await.is_none(),
        "nothing is sent toward the caller's video port"
    );
    assert!(received(&caller.video_rtcp).await.is_none());
    let stats = {
        let call = engine.calls.get(CALL).expect("call");
        engine
            .video_stats(&call.near)
            .expect("the near leg reports its video")
    };
    assert_eq!(stats.packets_out, 0, "{stats:?}");
}

#[tokio::test]
async fn offer_far_presents_the_callers_video_formats_on_the_far_leg() {
    let engine = engine_with_dispatcher();
    let caller = caller().await;
    let answer = ok_sdp_text(
        &answer_locally(
            &engine,
            CALL,
            caller_offer(caller.audio_addr, caller.video_addr, "sendonly"),
            anchor(),
        )
        .await,
    );
    let near_video = sdp::parse_video_stream(&answer).expect("video").remote_rtp;
    let offered = offer_far(&engine, CALL, ProfileFlags::default()).await;
    let far_offer = ok_sdp_text(&offered);
    let stream = sdp::parse_video_stream(&far_offer).expect("the far party is offered video");
    assert_ne!(
        stream.remote_rtp, near_video,
        "a far video leg of its own: {far_offer}"
    );
    assert_ne!(stream.remote_rtp, caller.video_addr, "{far_offer}");
    assert_eq!(stream.direction, sdp::MediaDirection::SendOnly);
    let section = video_section(&far_offer);
    assert_eq!(
        section[0],
        format!("m=video {} RTP/AVPF 96", stream.remote_rtp.port())
    );
    for line in ["a=rtpmap:96 H264/90000", "a=rtcp-fb:96 nack pli"] {
        assert!(section.contains(&line), "{line} in {section:?}");
    }
    assert_eq!(video_declined(&offered), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_answer_with_the_offered_payload_relays_video_both_ways_and_counts_it() {
    let call = grown(CALL, "sendrecv", Some((96, "sendrecv"))).await;
    assert!(
        matches!(&call.answered, CmdResult::Ok { to_tag: Some(tag), .. } if tag == "tag-b"),
        "{:?}",
        call.answered
    );
    assert_eq!(
        ok_sdp_text(&call.answered),
        call.local_answer,
        "the caller's answer is frozen"
    );
    assert_eq!(video_declined(&call.answered), None);
    let near_video = sdp::parse_video_stream(&call.local_answer)
        .expect("video")
        .remote_rtp;
    let far_video = sdp::parse_video_stream(&call.far_offer)
        .expect("video")
        .remote_rtp;

    call.caller
        .video
        .send_to(&video_packet(1), near_video)
        .await
        .expect("send");
    assert_eq!(
        received(&call.callee_video)
            .await
            .expect("the picture reaches the callee"),
        video_packet(1)
    );
    call.callee_video
        .send_to(&video_packet(2), far_video)
        .await
        .expect("send");
    assert_eq!(
        received(&call.caller.video)
            .await
            .expect("and the callee's reaches the caller"),
        video_packet(2)
    );
    // RTCP both ways.
    let far_rtcp = sdp::parse_video_stream(&call.far_offer)
        .expect("video")
        .remote_rtcp;
    call.callee_video_rtcp
        .send_to(&receiver_report(), far_rtcp)
        .await
        .expect("send");
    assert_eq!(
        received(&call.caller.video_rtcp).await.expect("report"),
        receiver_report()
    );

    // RTPBleed: a stranger racing the caller to the engine's video port is dropped.
    let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    attacker
        .send_to(&video_packet(66), near_video)
        .await
        .expect("send");
    assert!(
        received(&call.callee_video).await.is_none(),
        "the stranger is not relayed"
    );

    let guard = call.engine.calls.get(CALL).expect("call");
    let near = engine_video_stats(&call.engine, &guard.near);
    let far = engine_video_stats(&call.engine, guard.far.as_ref().expect("far"));
    assert!(near.packets_in >= 1 && near.packets_out >= 1, "{near:?}");
    assert!(far.packets_in >= 1 && far.packets_out >= 1, "{far:?}");
}

fn engine_video_stats(
    engine: &Engine<UdpLoopbackDatapath>,
    leg: &Leg,
) -> siphon_rtp_proto::VideoStats {
    engine.video_stats(leg).expect("the leg carries video")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_answer_with_a_foreign_payload_declines_the_video_only() {
    let call = grown(CALL, "sendrecv", Some((97, "sendrecv"))).await;
    assert!(
        matches!(&call.answered, CmdResult::Ok { .. }),
        "{:?}",
        call.answered
    );
    assert_eq!(
        ok_sdp_text(&call.answered),
        call.local_answer,
        "the caller's answer is unchanged"
    );
    assert!(
        video_declined(&call.answered).is_some_and(|reason| reason.contains("payload")),
        "{:?}",
        call.answered
    );
    let near_video = sdp::parse_video_stream(&call.local_answer)
        .expect("video")
        .remote_rtp;
    call.caller
        .video
        .send_to(&video_packet(1), near_video)
        .await
        .expect("send");
    assert!(
        received(&call.callee_video).await.is_none(),
        "no video is relayed"
    );
    {
        let guard = call.engine.calls.get(CALL).expect("call");
        assert!(
            guard.near.video.is_some(),
            "the caller's answered video endpoints stay"
        );
        assert!(guard.far.as_ref().expect("far").video.is_none());
        assert!(!guard.is_held());
    }
    // The audio relay is up regardless.
    let audio_far = sdp::parse(&call.far_offer).expect("far offer").remote_rtp;
    assert_ne!(audio_far.port(), 0);
    assert!(
        !call.engine.media().is_media_call(CALL),
        "audio is a plain relay"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_party_that_declines_video_leaves_the_audio_relay_and_reports_it() {
    let call = grown(CALL, "sendrecv", None).await;
    assert!(
        matches!(&call.answered, CmdResult::Ok { .. }),
        "{:?}",
        call.answered
    );
    assert_eq!(ok_sdp_text(&call.answered), call.local_answer);
    assert!(
        video_declined(&call.answered).is_some(),
        "{:?}",
        call.answered
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_the_far_leg_parks_the_video_and_a_second_far_leg_relays_it_again() {
    let call = grown(CALL, "sendrecv", Some((96, "sendrecv"))).await;
    let near_video = sdp::parse_video_stream(&call.local_answer)
        .expect("video")
        .remote_rtp;
    let endpoints_with_far = call.engine.endpoint_calls.len();
    delete(&call.engine, CALL, Some("tag-b")).await;
    {
        let guard = call.engine.calls.get(CALL).expect("call");
        assert!(guard.far.is_none());
        assert_eq!(guard.video.far_direction, sdp::MediaDirection::default());
        assert!(
            guard
                .video
                .flows
                .iter()
                .all(|(_, action)| *action == FlowAction::Drop),
            "{:?}",
            guard.video.flows
        );
        assert!(
            guard.near.video.is_some(),
            "the caller's answered video stays"
        );
    }
    assert!(
        call.engine.endpoint_calls.len() < endpoints_with_far,
        "the far leg's endpoints are released"
    );
    call.caller
        .video
        .send_to(&video_packet(5), near_video)
        .await
        .expect("send");
    assert!(
        received(&call.callee_video).await.is_none(),
        "nothing reaches the old far party"
    );

    // Another far party takes the call.
    let (callee_audio, callee_audio_addr) = phone().await;
    let (callee_video, callee_video_addr) = phone().await;
    let _ = &callee_audio;
    let far_offer = ok_sdp_text(&offer_far(&call.engine, CALL, ProfileFlags::default()).await);
    assert!(
        sdp::parse_video_stream(&far_offer).is_some(),
        "video is offered again"
    );
    let answered = answer_far(
        &call.engine,
        CALL,
        "tag-c",
        far_answer(
            callee_audio_addr,
            &far_video_section(callee_video_addr, 96, "sendrecv"),
        ),
    )
    .await;
    assert_eq!(ok_sdp_text(&answered), call.local_answer);
    call.caller
        .video
        .send_to(&video_packet(6), near_video)
        .await
        .expect("send");
    assert_eq!(
        received(&callee_video)
            .await
            .expect("relayed to the new party"),
        video_packet(6)
    );
    delete(&call.engine, CALL, None).await;
    assert_eq!(call.engine.session_count(), 0);
    assert_eq!(
        call.engine.endpoint_calls.len(),
        0,
        "every endpoint released, video included"
    );
}

#[tokio::test]
async fn a_re_answer_frees_the_video_endpoints_of_the_call_it_replaces() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let caller = caller().await;
    for _ in 0..2 {
        let result = answer_locally(
            &engine,
            CALL,
            caller_offer(caller.audio_addr, caller.video_addr, "sendrecv"),
            anchor(),
        )
        .await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
        assert_eq!(
            engine.endpoint_calls.len(),
            1 + 2,
            "audio (muxed) plus video RTP and RTCP, and nothing left of the first answer"
        );
    }
    delete(&engine, CALL, None).await;
    assert_eq!(engine.endpoint_calls.len(), 0);
}

#[tokio::test]
async fn a_secure_caller_asking_for_anchored_video_is_refused_loudly() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let caller = caller().await;
    let offer = caller_offer(caller.audio_addr, caller.video_addr, "sendrecv");
    let offer = offer.replacen(
        "RTP/AVP 0\r\n",
        "RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz\r\n",
        1,
    );
    let result = answer_locally(&engine, CALL, offer, anchor()).await;
    assert!(
        matches!(&result, CmdResult::Error { reason } if reason.contains("video") && reason.contains("plain")),
        "{result:?}"
    );
    assert_eq!(engine.session_count(), 0, "a refusal has no side effect");
    assert_eq!(engine.endpoint_calls.len(), 0);
}

#[tokio::test]
async fn offer_far_still_refuses_what_it_refused_with_video_relay_on_a_call_without_a_local_answer()
{
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let result = offer_far(&engine, "nobody", anchor()).await;
    assert!(
        matches!(&result, CmdResult::Error { reason } if !reason.contains("video_relay applies")),
        "the verb now accepts video_relay and fails on the call, not the field: {result:?}"
    );
}

pub(super) fn video_rtp(sequence: u16, ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 96];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(b"h264-nal");
    packet
}

/// `(sender ssrc, media ssrc)` of the Picture Loss Indication that ends the compound `datagram`
/// (RFC 4585 §6.1, §6.3.1), after a receiver report and a source description (RFC 3550 §6.1).
pub(super) fn parse_picture_loss(datagram: &[u8]) -> (u32, u32) {
    let packets = siphon_rtp_media::rtcp::feedback_packets(datagram).collect::<Vec<_>>();
    assert_eq!(packets.len(), 1, "one feedback message: {datagram:02x?}");
    assert_eq!(
        datagram[1], 201,
        "the compound opens with a receiver report"
    );
    assert_eq!(
        datagram[8 + 1],
        202,
        "then the source description with its CNAME"
    );
    let pli = &datagram[datagram.len() - 12..];
    assert_eq!(pli[..4], [0x81, 206, 0, 2], "PSFB, FMT 1, two words");
    (
        u32::from_be_bytes(pli[4..8].try_into().expect("four octets")),
        u32::from_be_bytes(pli[8..12].try_into().expect("four octets")),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_sending_party_is_asked_once_for_a_keyframe_when_the_relay_goes_live() {
    let call = grown(CALL, "sendrecv", Some((96, "sendrecv"))).await;
    let near_video = sdp::parse_video_stream(&call.local_answer)
        .expect("video")
        .remote_rtp;
    let far_video = sdp::parse_video_stream(&call.far_offer)
        .expect("video")
        .remote_rtp;
    // No stream has been seen, so no media SSRC is known and nothing is sent about one.
    call.engine.request_video_keyframes().await;
    assert!(received(&call.caller.video_rtcp).await.is_none());
    assert!(received(&call.callee_video_rtcp).await.is_none());

    const CALLER_SSRC: u32 = 0xC0DE_0001;
    const CALLEE_SSRC: u32 = 0xC0DE_0002;
    call.caller
        .video
        .send_to(&video_rtp(1, CALLER_SSRC), near_video)
        .await
        .expect("send");
    call.callee_video
        .send_to(&video_rtp(1, CALLEE_SSRC), far_video)
        .await
        .expect("send");
    assert!(received(&call.callee_video).await.is_some());
    assert!(received(&call.caller.video).await.is_some());

    call.engine.request_video_keyframes().await;
    let to_caller = received(&call.caller.video_rtcp)
        .await
        .expect("the caller is asked");
    let to_callee = received(&call.callee_video_rtcp)
        .await
        .expect("the callee is asked");
    let (caller_sender, caller_media) = parse_picture_loss(&to_caller);
    let (callee_sender, callee_media) = parse_picture_loss(&to_callee);
    assert_eq!(
        caller_media, CALLER_SSRC,
        "about the stream the caller sends"
    );
    assert_eq!(callee_media, CALLEE_SSRC);
    assert_eq!(caller_sender, callee_sender, "one engine SSRC for the call");
    assert_ne!(caller_sender, 0);
    assert!(![CALLER_SSRC, CALLEE_SSRC].contains(&caller_sender));

    // Once: a later sweep asks for nothing more.
    call.engine.request_video_keyframes().await;
    assert!(received(&call.caller.video_rtcp).await.is_none());
    assert!(received(&call.callee_video_rtcp).await.is_none());

    // An independent decoder reads the bytes the engine wrote.
    if let Some(reading) = tshark_reading(&to_caller) {
        assert!(!reading.contains("Malformed"), "{reading}");
        assert!(reading.contains("Picture Loss Indication (1)"), "{reading}");
        assert!(
            reading.contains("Packet type: Payload-specific Feedback (206)"),
            "{reading}"
        );
        assert!(
            reading.contains("Media source SSRC: 0xc0de0001"),
            "{reading}"
        );
        assert!(reading.contains("Type: CNAME"), "{reading}");
    } else {
        eprintln!("tshark/text2pcap not installed: the Wireshark cross-check was skipped");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_party_that_did_not_accept_pli_or_does_not_send_is_not_asked() {
    // The caller is `recvonly` (it never sends video) and the callee's section carries no PLI.
    let engine = engine_with_dispatcher();
    let caller = caller().await;
    let (_audio, callee_audio_addr) = phone().await;
    let (callee_video, callee_video_addr, callee_video_rtcp) = phone_with_rtcp().await;
    answer_locally(
        &engine,
        CALL,
        caller_offer(caller.audio_addr, caller.video_addr, "recvonly"),
        anchor(),
    )
    .await;
    let far_offer = ok_sdp_text(&offer_far(&engine, CALL, ProfileFlags::default()).await);
    let section = far_video_section(callee_video_addr, 96, "sendonly")
        .replace("a=rtcp-fb:96 nack pli\r\n", "");
    answer_far(
        &engine,
        CALL,
        "tag-b",
        far_answer(callee_audio_addr, &section),
    )
    .await;
    let far_video = sdp::parse_video_stream(&far_offer)
        .expect("video")
        .remote_rtp;
    callee_video
        .send_to(&video_rtp(1, 0xC0DE_0003), far_video)
        .await
        .expect("send");
    assert!(
        received(&caller.video).await.is_some(),
        "the picture is relayed"
    );
    engine.request_video_keyframes().await;
    assert!(
        received(&caller.video_rtcp).await.is_none(),
        "the caller sends no video"
    );
    assert!(
        received(&callee_video_rtcp).await.is_none(),
        "the callee never accepted PLI"
    );
}

/// What Wireshark makes of `datagram` as RTCP, or `None` when it or `text2pcap` is not installed.
fn tshark_reading(datagram: &[u8]) -> Option<String> {
    use std::io::Write;
    let directory = std::env::temp_dir().join(format!("siphon-pli-{}", std::process::id()));
    std::fs::create_dir_all(&directory).ok()?;
    let dump: String = datagram
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let hex: Vec<String> = chunk.iter().map(|octet| format!("{octet:02x}")).collect();
            format!("{:04x}  {}\n", row * 16, hex.join(" "))
        })
        .collect();
    let (text, pcap) = (directory.join("pli.txt"), directory.join("pli.pcap"));
    std::fs::File::create(&text)
        .ok()?
        .write_all(dump.as_bytes())
        .ok()?;
    let converted = std::process::Command::new("text2pcap")
        .arg("-u")
        .arg("6001,6002")
        .arg(&text)
        .arg(&pcap)
        .output()
        .ok()?;
    if !converted.status.success() {
        return None;
    }
    // Wireshark reads a preferences file from the home directory; the test gives it an empty one.
    let output = std::process::Command::new("tshark")
        .env("HOME", &directory)
        .env("XDG_CONFIG_HOME", &directory)
        .arg("-r")
        .arg(&pcap)
        .args(["-d", "udp.port==6002,rtcp", "-V"])
        .output()
        .ok()?;
    let reading = String::from_utf8_lossy(&output.stdout).into_owned();
    let _ = std::fs::remove_dir_all(&directory);
    output.status.success().then_some(reading)
}

#[tokio::test]
async fn node_info_advertises_answer_local_video() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("node_info answers a node");
    };
    assert!(node
        .features
        .iter()
        .any(|name| name == "answer_local_video"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_checkpoint_keeps_the_callers_video_when_the_far_party_declined_its_own() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    let range = (19_800u16, 19_840u16);
    let node = || {
        let engine = Engine::new(UdpLoopbackDatapath::with_port_range(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            range.0,
            range.1,
        ));
        tokio::spawn(run_redirect_dispatcher(
            engine.datapath().rx(),
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));
        engine
    };
    let primary = node();
    let caller = caller().await;
    let (_callee_audio, callee_audio_addr) = phone().await;
    let answer = ok_sdp_text(
        &answer_locally(
            &primary,
            CALL,
            caller_offer(caller.audio_addr, caller.video_addr, "sendrecv"),
            anchor(),
        )
        .await,
    );
    let near_video = sdp::parse_video_stream(&answer).expect("video").remote_rtp;
    offer_far(&primary, CALL, ProfileFlags::default()).await;
    let answered = answer_far(&primary, CALL, "tag-b", far_answer(callee_audio_addr, "")).await;
    assert!(video_declined(&answered).is_some(), "{answered:?}");
    let snapshot = match primary
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
            },
        )
        .await
    {
        CmdResult::Checkpoint { snapshot } => snapshot,
        other => panic!("expected a checkpoint, got {other:?}"),
    };
    delete(&primary, CALL, None).await;
    drop(primary);

    let standby = node();
    let _events = standby.register_client(CLIENT);
    let restored = standby.handle(CLIENT, Command::Restore { snapshot }).await;
    assert!(matches!(restored, CmdResult::Ok { .. }), "{restored:?}");
    {
        let call = standby.calls.get(CALL).expect("restored");
        let video = call
            .near
            .video
            .expect("the caller's answered video comes back");
        assert_eq!(
            video.rtp.local_addr, near_video,
            "on the port it was answered with"
        );
        assert!(call.far.as_ref().expect("far").video.is_none());
        assert_eq!(call.video.mode, VideoRelay::Anchor);
        assert_eq!(call.video.near_direction, sdp::MediaDirection::SendRecv);
        assert!(
            call.video
                .flows
                .iter()
                .all(|(_, action)| *action == FlowAction::Drop),
            "{:?}",
            call.video.flows
        );
        assert!(
            standby.video_stats(&call.near).is_some(),
            "the leg still reports its video"
        );
    }
    // The restored endpoints relay nothing, and the call frees them with the rest.
    caller
        .video
        .send_to(&video_packet(1), near_video)
        .await
        .expect("send");
    assert!(received(&caller.video).await.is_none());
    delete(&standby, CALL, None).await;
    assert_eq!(standby.endpoint_calls.len(), 0);
}

const TWO_FORMATS: &str = "a=rtpmap:97 VP8/90000\r\n";

fn two_formats(offer: String) -> String {
    offer.replace("RTP/AVPF 96", "RTP/AVPF 96 97") + TWO_FORMATS
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_caller_is_answered_one_video_format_and_the_far_party_is_offered_only_it() {
    let call = grown_edited(
        CALL,
        "sendrecv",
        Some((96, "sendrecv")),
        &two_formats,
        &|text| text,
    )
    .await;
    for text in [&call.local_answer, &call.far_offer] {
        let section = video_section(text);
        assert!(section[0].ends_with("RTP/AVPF 96"), "{section:?}");
        assert!(
            !section.iter().any(|line| line.contains(":97")),
            "{section:?}"
        );
        assert!(section.contains(&"a=rtpmap:96 H264/90000"), "{section:?}");
    }
    assert_eq!(video_declined(&call.answered), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_answer_that_carries_more_than_the_offered_format_declines_the_video_only() {
    let call = grown_edited(
        CALL,
        "sendrecv",
        Some((96, "sendrecv")),
        &two_formats,
        &|text| text.replace("RTP/AVPF 96", "RTP/AVPF 96 97"),
    )
    .await;
    assert!(
        video_declined(&call.answered).is_some_and(|reason| reason.contains("payload type 97")),
        "{:?}",
        call.answered
    );
    assert_eq!(ok_sdp_text(&call.answered), call.local_answer);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_answer_with_a_lower_h264_level_declines_the_video_only() {
    let call = grown_edited(
        CALL,
        "sendrecv",
        Some((96, "sendrecv")),
        &|text| text,
        &|text| text.replace("profile-level-id=42e01f", "profile-level-id=42e015"),
    )
    .await;
    assert!(
        video_declined(&call.answered).is_some_and(|reason| reason.contains("level")),
        "{:?}",
        call.answered
    );
    let near_video = sdp::parse_video_stream(&call.local_answer)
        .expect("video")
        .remote_rtp;
    call.caller
        .video
        .send_to(&video_packet(1), near_video)
        .await
        .expect("send");
    assert!(received(&call.callee_video).await.is_none());
}

#[tokio::test]
async fn a_video_section_that_inherits_its_direction_is_answered_with_an_explicit_one() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let caller = caller().await;
    // Session level sendonly, audio recvonly, and a video section that says nothing of its own.
    let offer = caller_offer(caller.audio_addr, caller.video_addr, "x-inherit")
        .replace("t=0 0\r\n", "t=0 0\r\na=sendonly\r\n")
        .replace("a=sendrecv\r\na=rtcp-mux", "a=recvonly\r\na=rtcp-mux");
    let answer = ok_sdp_text(&answer_locally(&engine, CALL, offer, anchor()).await);
    let section = video_section(&answer);
    assert!(section.contains(&"a=recvonly"), "{section:?}");
    assert!(!section.contains(&"a=sendonly"), "{section:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_declined_far_answers_never_free_the_callers_answered_video() {
    let call = grown(CALL, "sendrecv", None).await;
    let near_video = sdp::parse_video_stream(&call.local_answer)
        .expect("video")
        .remote_rtp;
    let near_before = call
        .engine
        .calls
        .get(CALL)
        .expect("call")
        .near
        .video
        .expect("video")
        .rtp;
    // The same declined answer again (a retransmission, a re-answer).
    let (_audio, audio_addr) = phone().await;
    let again = answer_far(&call.engine, CALL, "tag-b", far_answer(audio_addr, "")).await;
    assert!(matches!(again, CmdResult::Ok { .. }), "{again:?}");
    {
        let guard = call.engine.calls.get(CALL).expect("call");
        let near = guard.near.video.expect("the caller's answered video stays");
        assert_eq!(near.rtp.local_addr, near_before.local_addr);
        assert!(call.engine.endpoint_calls.contains_key(&near.rtp.id));
    }
    // A later far party that accepts video lands on the same caller ports.
    delete(&call.engine, CALL, Some("tag-b")).await;
    let (_audio, audio_addr) = phone().await;
    let (callee_video, callee_video_addr) = phone().await;
    let far_offer = ok_sdp_text(&offer_far(&call.engine, CALL, ProfileFlags::default()).await);
    assert!(sdp::parse_video_stream(&far_offer).is_some());
    let answered = answer_far(
        &call.engine,
        CALL,
        "tag-c",
        far_answer(
            audio_addr,
            &far_video_section(callee_video_addr, 96, "sendrecv"),
        ),
    )
    .await;
    assert_eq!(ok_sdp_text(&answered), call.local_answer);
    assert_eq!(
        call.engine
            .calls
            .get(CALL)
            .expect("call")
            .near
            .video
            .expect("video")
            .rtp
            .local_addr,
        near_before.local_addr
    );
    call.caller
        .video
        .send_to(&video_packet(9), near_video)
        .await
        .expect("send");
    assert_eq!(
        received(&callee_video).await.expect("relayed"),
        video_packet(9)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_keyframe_request_names_the_ssrc_each_party_declared_before_any_media_is_seen() {
    // RFC 5576 §4.1: a=ssrc in the caller's offer and the far party's answer name their streams, so
    // the request needs no latch (a backend without one, an XDP datapath, still asks).
    let call = grown_edited(
        CALL,
        "sendrecv",
        Some((96, "sendrecv")),
        &|text| text + "a=ssrc:3405643777 cname:caller\r\n",
        &|text| text + "a=ssrc:3405643778 cname:callee\r\n",
    )
    .await;
    call.engine.request_video_keyframes().await;
    let to_caller = received(&call.caller.video_rtcp)
        .await
        .expect("the caller is asked");
    let to_callee = received(&call.callee_video_rtcp)
        .await
        .expect("the callee is asked");
    assert_eq!(parse_picture_loss(&to_caller).1, 3_405_643_777);
    assert_eq!(parse_picture_loss(&to_callee).1, 3_405_643_778);
}

/// How many endpoints `datapath` can still bind: it counts by binding every free port and freeing
/// them again.
async fn free_ports(datapath: &UdpLoopbackDatapath) -> usize {
    let mut bound = Vec::new();
    while let Ok(endpoint) = datapath.alloc_endpoint().await {
        bound.push(endpoint);
    }
    let count = bound.len();
    for endpoint in bound {
        datapath.remove_endpoint(endpoint.id).await;
    }
    count
}

#[tokio::test]
async fn a_video_drop_that_cannot_be_installed_frees_every_endpoint_of_the_call_floor_included() {
    let inner =
        UdpLoopbackDatapath::with_port_range(IpAddr::V4(Ipv4Addr::LOCALHOST), 19_900, 19_915);
    let datapath = LatchLearningDatapath::over(inner.clone());
    let engine = Engine::new(datapath.clone());
    let capacity = free_ports(&inner).await;
    let caller = caller().await;
    // The caller offers a floor stream too: it is allocated before the video's endpoints.
    let offer = caller_offer(caller.audio_addr, caller.video_addr, "sendrecv")
        + "m=application 49000 udp MCPTT\r\na=fmtp:MCPTT mc_queueing\r\n";
    datapath.fail_drop_installs(true);
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                sdp: offer,
                profile: anchor(),
            },
        )
        .await;
    assert!(
        matches!(&result, CmdResult::Error { reason } if reason.contains("video")),
        "{result:?}"
    );
    assert_eq!(engine.session_count(), 0);
    assert_eq!(
        free_ports(&inner).await,
        capacity,
        "no endpoint of the refused call is left bound (the floor's included)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pli_accepted_only_for_a_discarded_format_asks_for_no_keyframe() {
    // RFC 4585 §4.2: feedback is per payload type. The caller accepts PLI for 97 only, and the answer
    // keeps 96, so the caller's stream is not one a PLI may be sent about.
    let call = grown_edited(
        CALL,
        "sendrecv",
        Some((96, "sendrecv")),
        &|text| two_formats(text).replace("a=rtcp-fb:96 nack pli", "a=rtcp-fb:97 nack pli"),
        &|text| text.replace("a=rtcp-fb:96 nack pli\r\n", ""),
    )
    .await;
    let near_video = sdp::parse_video_stream(&call.local_answer)
        .expect("video")
        .remote_rtp;
    let far_video = sdp::parse_video_stream(&call.far_offer)
        .expect("video")
        .remote_rtp;
    call.caller
        .video
        .send_to(&video_rtp(1, 0xC0DE_0011), near_video)
        .await
        .expect("send");
    call.callee_video
        .send_to(&video_rtp(1, 0xC0DE_0012), far_video)
        .await
        .expect("send");
    assert!(received(&call.callee_video).await.is_some());
    assert!(received(&call.caller.video).await.is_some());
    call.engine.request_video_keyframes().await;
    assert!(received(&call.caller.video_rtcp).await.is_none());
    assert!(received(&call.callee_video_rtcp).await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_answer_in_another_packetization_mode_declines_the_video_only() {
    let call = grown_edited(
        CALL,
        "sendrecv",
        Some((96, "sendrecv")),
        &|text| text,
        &|text| text.replace("packetization-mode=1", "packetization-mode=0"),
    )
    .await;
    assert!(
        video_declined(&call.answered).is_some_and(|reason| reason.contains("packetization-mode")),
        "{:?}",
        call.answered
    );
}
