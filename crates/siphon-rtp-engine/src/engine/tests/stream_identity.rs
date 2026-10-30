//! An answer the engine writes from an offer (a conference seat, `answer_local`) must not echo the
//! offerer's own stream identity back. A WebRTC receiver binds its receive stream to the SSRC the
//! answer names; told the offerer's own SSRC, it drops every packet the engine really sends.

use super::*;

/// The offerer's SSRC, as a browser would signal it.
const OFFERER_SSRC: u32 = 2_712_110_744;

/// A plain RTP offer carrying the stream identity and header extensions a browser signals (RFC 5576
/// `a=ssrc`, RFC 8830 `a=msid`, RFC 8285 `a=extmap`), so the test needs no DTLS.
fn browser_shaped_offer(rtp: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nt=0 0\r\na=msid-semantic: WMS stream-a\r\n\
             m=audio {port} RTP/AVP 0\r\nc=IN IP4 {ip}\r\na=rtpmap:0 PCMU/8000\r\n\
             a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\na=msid:stream-a track-a\r\n\
             a=ssrc:{OFFERER_SSRC} cname:offerer-cname\r\na=ssrc:{OFFERER_SSRC} msid:stream-a track-a\r\n\
             a=rtcp-mux\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
    )
}

/// The `a=ssrc` values an SDP names.
fn signalled_ssrcs(sdp: &str) -> Vec<u32> {
    let mut ssrcs: Vec<u32> = sdp
        .lines()
        .filter_map(|line| line.strip_prefix("a=ssrc:"))
        .filter_map(|rest| rest.split(' ').next()?.parse().ok())
        .collect();
    ssrcs.dedup();
    ssrcs
}

fn assert_nothing_of_the_offerer(answer: &str) {
    assert!(
        !answer.contains(&OFFERER_SSRC.to_string()),
        "the offerer's SSRC came back:\n{answer}"
    );
    for line in ["msid", "extmap", "offerer-cname"] {
        assert!(!answer.contains(line), "{line} came back:\n{answer}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seat_answer_names_the_ssrc_the_room_sends_and_none_of_the_offerers() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_media::rtp::RtpPacket;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (app, app_addr) = phone().await;
    let (caller, caller_addr) = phone().await;
    let join = |from_tag: &str, sdp: String| Command::ConferenceJoin {
        conference_id: "identity-room".into(),
        from_tag: from_tag.into(),
        sdp,
        role: ConferenceRole::Talker,
        profile: ProfileFlags::default(),
    };
    let answered = engine
        .handle(CLIENT, join("app", browser_shaped_offer(app_addr)))
        .await;
    let answer = ok_sdp_text(&answered);
    let engine_app = sdp::parse(&answer).expect("app answer").remote_rtp;
    let caller_join = engine
        .handle(CLIENT, join("caller", sdp_for(caller_addr, true)))
        .await;
    let engine_caller = sdp::parse(&ok_sdp_text(&caller_join))
        .expect("caller answer")
        .remote_rtp;

    assert_nothing_of_the_offerer(&answer);
    let named = signalled_ssrcs(&answer);
    assert_eq!(
        named.len(),
        1,
        "the answer names one SSRC of its own:\n{answer}"
    );

    // The caller talks, so the room sends the app the mix; the app keeps its own stream up.
    for sequence in 0..30u16 {
        caller
            .send_to(&g711_rtp(0, sequence, 0x0B0B_0B0B, 0x00), engine_caller)
            .await
            .expect("caller send");
        app.send_to(&g711_rtp(0, sequence, OFFERER_SSRC, 0x00), engine_app)
            .await
            .expect("app send");
    }
    let (mix, _) = recv(&app).await;
    let packet = RtpPacket::parse(&mix).expect("room egress RTP");
    assert_eq!(
        packet.ssrc, named[0],
        "the SSRC the answer names is the one on the room's packets"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_answer_echoes_none_of_the_offerers_stream_identity() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "identity-local".into(),
                from_tag: "tag-a".into(),
                sdp: browser_shaped_offer(addr),
                profile: Default::default(),
            },
        )
        .await;
    let answer = ok_sdp_text(&answered);
    assert_nothing_of_the_offerer(&answer);
    assert!(signalled_ssrcs(&answer).is_empty(), "{answer}");
}
