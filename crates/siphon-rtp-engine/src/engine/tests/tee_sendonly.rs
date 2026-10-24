//! A WebSocket tee on a single-leg call that answered a `sendonly` offer — one stream of a SIPREC
//! recording session (RFC 7866 §6: the SRC sends, the SRS only receives) answered as its own
//! `answer_local` call. The tee must stream what the party sends, and the engine must send it no
//! media back: an answer to `sendonly` is `recvonly` (RFC 3264 §6.1).

use super::*;

fn sendonly_offer(rtp: SocketAddr) -> String {
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
    while let Ok(Ok((len, _))) =
        tokio::time::timeout_at(deadline, sender.recv_from(&mut buffer)).await
    {
        let is_rtcp = len >= 2 && (200..=204).contains(&buffer[1]);
        assert!(
            is_rtcp,
            "the engine sent RTP toward a sendonly party ({len} bytes, PT byte {:#04x})",
            buffer.get(1).copied().unwrap_or(0)
        );
    }
}
