//! A forwarding-room seat's answer is written from the participant's offer, so it must not echo the
//! participant's own stream identity (`a=ssrc`, `a=msid`, `a=extmap`) back: a WebRTC receiver binds
//! its receive stream to the SSRC the answer names, and would drop everything the room sends. The
//! answer names the SSRC the room forwards to the seat instead (RFC 5576 §4.1, RFC 8830 §2).

use super::stream_identity::{
    assert_nothing_of_the_offerer, browser_shaped_offer, signalled_ssrcs, OFFERER_SSRC,
};
use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_media::rtp::RtpPacket;

const ROOM: &str = "identity-forward-room";

async fn forward_join(
    engine: &Engine<UdpLoopbackDatapath>,
    from_tag: &str,
    sdp: String,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: from_tag.into(),
                sdp,
                profile: ProfileFlags::default(),
            },
        )
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forward_join_answer_names_the_ssrc_the_room_sends_and_none_of_the_offerers() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (listener, listener_addr) = phone().await;
    let (talker, talker_addr) = phone().await;

    let answered = forward_join(&engine, "listener", browser_shaped_offer(listener_addr)).await;
    let answer = ok_sdp_text(&answered);
    let engine_listener = sdp::parse(&answer).expect("listener answer").remote_rtp;
    let talker_answer = forward_join(&engine, "talker", sdp_for(talker_addr, true)).await;
    let engine_talker = sdp::parse(&ok_sdp_text(&talker_answer))
        .expect("talker answer")
        .remote_rtp;

    assert_nothing_of_the_offerer(&answer);
    let named = signalled_ssrcs(&answer);
    assert_eq!(
        named.len(),
        1,
        "the answer names one SSRC of its own:\n{answer}"
    );
    // RFC 8843 §7.3: the answer keeps what bundling needs; stripping the identity must not touch it.
    assert!(answer.contains("m=audio"), "{answer}");

    let chosen = engine
        .handle(
            CLIENT,
            Command::ForwardSetSource {
                conference_id: ROOM.into(),
                from_tag: Some("talker".into()),
            },
        )
        .await;
    assert!(matches!(chosen, CmdResult::Ok { .. }), "{chosen:?}");
    for sequence in 0..30u16 {
        talker
            .send_to(&g711_rtp(0, sequence, 0x0B0B_0B0B, 0x00), engine_talker)
            .await
            .expect("talker send");
        listener
            .send_to(&g711_rtp(0, sequence, OFFERER_SSRC, 0x00), engine_listener)
            .await
            .expect("listener send");
    }
    // The room's Sender Report (RFC 3550 §6.4.1) can arrive first: wait for the RTP itself, whose
    // payload type is outside the RTCP range (RFC 5761 §4).
    let forwarded = loop {
        let (datagram, _) = recv(&listener).await;
        if !(64..=95).contains(&(datagram[1] & 0x7f)) {
            break datagram;
        }
    };
    let packet = RtpPacket::parse(&forwarded).expect("forwarded RTP");
    assert_eq!(
        packet.ssrc, named[0],
        "the SSRC the answer names is the one on the room's packets"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forward_join_answer_keeps_the_bundle_mid_of_a_browser_offer() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_listener, listener_addr) = phone().await;
    let offer = browser_shaped_offer(listener_addr)
        .replace("t=0 0\r\n", "t=0 0\r\na=group:BUNDLE 0\r\n")
        + "a=mid:0\r\n";
    let answer = ok_sdp_text(&forward_join(&engine, "listener", offer).await);
    assert_nothing_of_the_offerer(&answer);
    assert!(answer.contains("a=mid:0"), "a=mid must survive:\n{answer}");
    assert!(
        answer.contains("a=group:BUNDLE 0"),
        "a=group:BUNDLE must survive:\n{answer}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forward_join_answer_echoes_no_stream_identity_in_the_floor_section_either() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_listener, listener_addr) = phone().await;
    let (_floor, floor_addr) = phone().await;
    let offer = format!(
        "{}m=application {} udp MCPTT\r\nc=IN IP4 {}\r\na=extmap:5 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\
         a=msid:stream-a track-floor\r\na=ssrc:{OFFERER_SSRC} cname:offerer-cname\r\n\
         a=fmtp:MCPTT mc_queueing\r\n",
        browser_shaped_offer(listener_addr),
        floor_addr.port(),
        floor_addr.ip()
    );
    let answered = engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: "listener".into(),
                sdp: offer,
                profile: ProfileFlags {
                    floor_fmtp: Some("mc_granted".into()),
                    ..ProfileFlags::default()
                },
            },
        )
        .await;
    let answer = ok_sdp_text(&answered);
    assert_nothing_of_the_offerer(&answer);
    assert!(
        answer.contains("udp MCPTT") && answer.contains("a=fmtp:MCPTT mc_granted"),
        "the floor section is still answered:\n{answer}"
    );
    assert!(!answer.contains("m=application 0"), "{answer}");
}

/// The engine's own `forward_offer` is written from nothing the member sent, so it carries no
/// stream identity of anybody's (audio section and floor section alike), and the member's answer to
/// it, which may carry a browser's identity, is consumed by `forward_answer` without any SDP coming
/// back to echo it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forward_offer_carries_no_stream_identity_and_its_answer_echoes_none() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_member, member_addr) = phone().await;
    let offered = engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: "member".into(),
                profile: ProfileFlags {
                    floor_fmtp: Some("mc_granted".into()),
                    ..ProfileFlags::default()
                },
            },
        )
        .await;
    let offer = ok_sdp_text(&offered);
    assert_nothing_of_the_offerer(&offer);
    assert!(
        !offer.contains("a=ssrc") && !offer.contains("a=extmap"),
        "{offer}"
    );
    assert!(
        offer.contains("udp MCPTT"),
        "the floor is offered:\n{offer}"
    );

    let answered = engine
        .handle(
            CLIENT,
            Command::ForwardAnswer {
                conference_id: ROOM.into(),
                from_tag: "member".into(),
                sdp: browser_shaped_offer(member_addr),
                received_from: None,
            },
        )
        .await;
    assert!(
        matches!(answered, CmdResult::Ok { sdp: None, .. }),
        "{answered:?}"
    );
}
