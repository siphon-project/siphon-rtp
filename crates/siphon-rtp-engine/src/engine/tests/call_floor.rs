//! The MCPTT floor-control stream of two-party calls (3GPP TS 24.380), end to end on the UDP-loopback
//! datapath: each party that offers or answers `m=application <port> udp MCPTT` has it terminated on
//! its own engine endpoint, floor messages reach the controller as `rtcp_app`, and `send_rtcp_app`
//! reaches the party. Nothing is relayed from one party's floor stream to the other's.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_proto::RtcpAppStream;

const CALL: &str = "call-floor";
const SHORT: Duration = Duration::from_secs(2);
const NEGATIVE: Duration = Duration::from_millis(250);
const FLOOR_FMTP: &str = "mc_queueing;mc_priority=5;mc_granted";

/// TS 24.380 §8.2.4 Floor Request: SSRC 0x11223344, name MCPT, subtype 0.
const FLOOR_REQUEST: [u8; 16] = [
    0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05, 0x00,
];
const FLOOR_GRANTED_PAYLOAD: [u8; 12] = [
    0x01, 0x02, 0x00, 0x1E, 0x0E, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
];

fn engine_with_dispatcher() -> Engine<UdpLoopbackDatapath> {
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

fn sdp_with_floor(audio: SocketAddr, floor: Option<SocketAddr>) -> String {
    let mut text = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = audio.ip(),
        port = audio.port()
    );
    if let Some(floor) = floor {
        text.push_str(&format!(
            "m=application {} udp MCPTT\r\na=fmtp:MCPTT mc_queueing\r\n",
            floor.port()
        ));
    }
    text
}

fn profile() -> ProfileFlags {
    ProfileFlags {
        floor_fmtp: Some(FLOOR_FMTP.to_string()),
        ..ProfileFlags::default()
    }
}

struct Party {
    /// Held so the audio port stays bound for the life of the test.
    _audio: UdpSocket,
    floor: UdpSocket,
    audio_addr: SocketAddr,
    floor_addr: SocketAddr,
}

async fn party() -> Party {
    let (audio, audio_addr) = phone().await;
    let (floor, floor_addr) = phone().await;
    Party {
        _audio: audio,
        floor,
        audio_addr,
        floor_addr,
    }
}

async fn offer(engine: &Engine<UdpLoopbackDatapath>, a: &Party, with_floor: bool) -> String {
    let result = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_with_floor(a.audio_addr, with_floor.then_some(a.floor_addr)),
                profile: profile(),
            },
        )
        .await;
    ok_sdp_text(&result)
}

async fn answer(engine: &Engine<UdpLoopbackDatapath>, b: &Party, with_floor: bool) -> String {
    let result = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_with_floor(b.audio_addr, with_floor.then_some(b.floor_addr)),
                profile: profile(),
            },
        )
        .await;
    ok_sdp_text(&result)
}

/// A two-party call with a floor stream on both sides. Returns the engine's floor ports toward A and
/// B, from the answer A receives and the offer B received.
async fn floor_call(
    engine: &Engine<UdpLoopbackDatapath>,
    a: &Party,
    b: &Party,
) -> (SocketAddr, SocketAddr, String, String) {
    let to_b = offer(engine, a, true).await;
    let to_a = answer(engine, b, true).await;
    let toward_b = sdp::parse_floor(&to_b)
        .expect("floor in the offer to B")
        .remote;
    let toward_a = sdp::parse_floor(&to_a)
        .expect("floor in the answer to A")
        .remote;
    (toward_a, toward_b, to_b, to_a)
}

async fn next_app(events: &flume::Receiver<Event>) -> Event {
    tokio::time::timeout(SHORT, events.recv_async())
        .await
        .expect("an rtcp_app event")
        .expect("open queue")
}

async fn recv_datagram(socket: &UdpSocket, window: Duration) -> Option<Vec<u8>> {
    let mut buffer = [0u8; 2048];
    match tokio::time::timeout(window, socket.recv_from(&mut buffer)).await {
        Ok(Ok((length, _))) => Some(buffer[..length].to_vec()),
        _ => None,
    }
}

async fn send_to_leg(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    from_tag: Option<&str>,
    stream: RtcpAppStream,
    ssrc: Option<u32>,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::SendRtcpApp {
                call_id: Some(call_id.into()),
                conference_id: None,
                from_tag: from_tag.map(str::to_string),
                except_from_tags: Vec::new(),
                stream,
                ssrc,
                name: "MCPT".into(),
                subtype: 17,
                payload: FLOOR_GRANTED_PAYLOAD.to_vec(),
            },
        )
        .await
}

#[tokio::test]
async fn both_sides_floor_streams_are_anchored_with_the_controllers_fmtp() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (a, b) = (party().await, party().await);
    let (toward_a, toward_b, to_b, to_a) = floor_call(&engine, &a, &b).await;
    assert_ne!(toward_a.port(), 0);
    assert_ne!(toward_b.port(), 0);
    assert_ne!(toward_a, toward_b, "one endpoint per party");
    for (text, parties) in [(&to_b, &a), (&to_a, &b)] {
        assert!(text.contains("udp MCPTT"), "{text}");
        assert!(
            text.contains(&format!("a=fmtp:MCPTT {FLOOR_FMTP}\r\n"))
                || text.ends_with(&format!("a=fmtp:MCPTT {FLOOR_FMTP}")),
            "{text}"
        );
        assert!(
            !text.contains("mc_queueing\r\n"),
            "the offerer's fmtp is replaced: {text}"
        );
        assert!(
            !text.contains(&parties.floor_addr.port().to_string()),
            "the party's own floor port does not leak: {text}"
        );
    }
}

#[tokio::test]
async fn floor_messages_reach_the_controller_with_the_call_and_leg_and_are_not_relayed() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let (a, b) = (party().await, party().await);
    let (toward_a, toward_b, _, _) = floor_call(&engine, &a, &b).await;

    a.floor
        .send_to(&FLOOR_REQUEST, toward_a)
        .await
        .expect("send");
    let Event::RtcpApp {
        call_id,
        conference_id,
        from_tag,
        stream,
        ssrc,
        name,
        subtype,
        payload,
    } = next_app(&app_events).await
    else {
        panic!("rtcp_app");
    };
    assert_eq!(call_id.as_deref(), Some(CALL));
    assert_eq!(conference_id, None);
    assert_eq!(from_tag, "tag-a");
    assert_eq!(stream, RtcpAppStream::Floor);
    assert_eq!((ssrc, name.as_str(), subtype), (0x1122_3344, "MCPT", 0));
    assert_eq!(payload, [0x00, 0x02, 0x05, 0x00]);

    b.floor
        .send_to(&FLOOR_REQUEST, toward_b)
        .await
        .expect("send");
    let Event::RtcpApp { from_tag, .. } = next_app(&app_events).await else {
        panic!("rtcp_app");
    };
    assert_eq!(from_tag, "tag-b");
    assert!(app_events.try_recv().is_err(), "exactly one each");
    assert!(
        recv_datagram(&b.floor, NEGATIVE).await.is_none(),
        "A's floor message is not relayed to B"
    );
    assert!(recv_datagram(&a.floor, NEGATIVE).await.is_none());
}

#[tokio::test]
async fn a_floor_granted_reaches_the_named_party_byte_exact() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (a, b) = (party().await, party().await);
    floor_call(&engine, &a, &b).await;

    assert_eq!(
        send_to_leg(
            &engine,
            CALL,
            Some("tag-b"),
            RtcpAppStream::Floor,
            Some(0xCAFE_F00D)
        )
        .await,
        ok_empty()
    );
    let received = recv_datagram(&b.floor, SHORT).await.expect("floor granted");
    let mut expected = vec![0x91, 0xCC, 0x00, 0x05, 0xCA, 0xFE, 0xF0, 0x0D];
    expected.extend_from_slice(b"MCPT");
    expected.extend_from_slice(&FLOOR_GRANTED_PAYLOAD);
    assert_eq!(received, expected);
    assert!(recv_datagram(&a.floor, NEGATIVE).await.is_none());

    // Without an SSRC the packet carries the leg's own, the same on every send.
    assert_eq!(
        send_to_leg(&engine, CALL, Some("tag-a"), RtcpAppStream::Floor, None).await,
        ok_empty()
    );
    let first = recv_datagram(&a.floor, SHORT).await.expect("floor");
    send_to_leg(&engine, CALL, Some("tag-a"), RtcpAppStream::Floor, None).await;
    let second = recv_datagram(&a.floor, SHORT).await.expect("floor");
    assert_eq!(first[4..8], second[4..8]);
}

#[tokio::test]
async fn send_rtcp_app_to_a_call_refuses_what_it_cannot_send() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (a, b) = (party().await, party().await);
    floor_call(&engine, &a, &b).await;
    let reason = |result: CmdResult| match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected an error, got {other:?}"),
    };
    // No leg named.
    assert!(
        reason(send_to_leg(&engine, CALL, None, RtcpAppStream::Floor, None).await)
            .contains("from_tag")
    );
    // A leg the call does not have, and a call that does not exist.
    assert!(
        reason(send_to_leg(&engine, CALL, Some("tag-z"), RtcpAppStream::Floor, None).await)
            .contains("no leg tag-z")
    );
    assert!(matches!(
        send_to_leg(&engine, "nope", Some("tag-a"), RtcpAppStream::Floor, None).await,
        CmdResult::Error { .. }
    ));
    // Audio on a relayed stream needs an explicit SSRC.
    assert!(
        reason(send_to_leg(&engine, CALL, Some("tag-a"), RtcpAppStream::Audio, None).await)
            .contains("explicit ssrc")
    );
}

#[tokio::test]
async fn audio_app_goes_out_of_the_legs_audio_endpoint_to_its_rtcp_address() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (a, b) = (party().await, party().await);
    floor_call(&engine, &a, &b).await;
    // A's offer carried no a=rtcp, so its RTCP is the port after its RTP port (RFC 3550 §11). The
    // loopback phone listens on a second socket there to prove the datagram left toward it.
    let rtcp_port = a.audio_addr.port() + 1;
    let Ok(listener) = UdpSocket::bind((Ipv4Addr::LOCALHOST, rtcp_port)).await else {
        eprintln!("RTCP port {rtcp_port} is taken on this host; audio APP check skipped");
        return;
    };
    assert_eq!(
        send_to_leg(&engine, CALL, Some("tag-a"), RtcpAppStream::Audio, Some(7)).await,
        ok_empty()
    );
    let received = recv_datagram(&listener, SHORT).await.expect("audio APP");
    assert_eq!(received[1], 204);
    assert_eq!(&received[4..8], &7u32.to_be_bytes());
}

#[tokio::test]
async fn a_party_that_declines_the_floor_stream_is_not_served_it() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (a, b) = (party().await, party().await);
    offer(&engine, &a, true).await;
    let to_a = answer(&engine, &b, false).await;
    assert!(
        sdp::parse_floor(&to_a).is_none(),
        "A is not told a floor stream exists: {to_a}"
    );
    let result = send_to_leg(&engine, CALL, Some("tag-a"), RtcpAppStream::Floor, None).await;
    assert!(matches!(result, CmdResult::Error { .. }), "{result:?}");
    assert_eq!(engine.conference().floors().leg_count(), 0);
}

#[tokio::test]
async fn a_reoffer_keeps_the_floor_endpoint_and_delete_frees_it() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (a, b) = (party().await, party().await);
    let (_, toward_b, _, _) = floor_call(&engine, &a, &b).await;
    assert_eq!(engine.conference().floors().leg_count(), 2);

    let reoffered = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_with_floor(a.audio_addr, Some(a.floor_addr)),
                profile: profile(),
            },
        )
        .await;
    let presented = ok_sdp_text(&reoffered);
    assert_eq!(
        sdp::parse_floor(&presented).expect("floor kept").remote,
        toward_b,
        "B is shown the same engine floor endpoint"
    );
    assert!(presented.contains(&format!("a=fmtp:MCPTT {FLOOR_FMTP}")));
    assert_eq!(engine.conference().floors().leg_count(), 2);

    // A mid-call floor stream the leg never had is declined, never handed on with A's address.
    let (a2, b2) = (party().await, party().await);
    let plain = engine_with_dispatcher();
    let _plain_events = plain.register_client(CLIENT);
    offer(&plain, &a2, false).await;
    answer(&plain, &b2, false).await;
    let added = plain
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_with_floor(a2.audio_addr, Some(a2.floor_addr)),
                profile: profile(),
            },
        )
        .await;
    assert!(sdp::parse_floor(&ok_sdp_text(&added)).is_none());

    assert!(matches!(
        engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: CALL.into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                }
            )
            .await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(engine.conference().floors().leg_count(), 0);
    assert!(engine.endpoint_calls.is_empty(), "every endpoint freed");
}

#[tokio::test]
async fn a_floor_stream_keeps_a_call_alive_for_the_idle_sweep() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (a, b) = (party().await, party().await);
    let (toward_a, _, _, _) = floor_call(&engine, &a, &b).await;
    let floor_endpoint = engine
        .calls
        .get(CALL)
        .and_then(|call| call.near.floor)
        .expect("near floor endpoint")
        .id;
    a.floor
        .send_to(&FLOOR_REQUEST, toward_a)
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        engine
            .datapath()
            .last_activity(floor_endpoint)
            .is_some_and(|tick| tick > 0),
        "floor traffic stamps the floor endpoint, which the call's sweep reads"
    );
}

#[tokio::test]
async fn checkpoint_refuses_a_call_with_a_floor_stream() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (a, b) = (party().await, party().await);
    floor_call(&engine, &a, &b).await;
    let result = engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    let CmdResult::Error { reason } = result else {
        panic!("expected a refusal");
    };
    assert!(reason.contains("MCPTT floor stream"), "{reason}");
}

#[tokio::test]
async fn a_single_leg_local_answer_terminates_the_floor_stream() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let a = party().await;
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "local".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_with_floor(a.audio_addr, Some(a.floor_addr)),
                profile: profile(),
            },
        )
        .await;
    let answer = ok_sdp_text(&result);
    let engine_floor = sdp::parse_floor(&answer).expect("floor answered").remote;
    assert!(
        answer.contains(&format!("a=fmtp:MCPTT {FLOOR_FMTP}")),
        "{answer}"
    );
    a.floor
        .send_to(&FLOOR_REQUEST, engine_floor)
        .await
        .expect("send");
    let Event::RtcpApp {
        call_id, from_tag, ..
    } = next_app(&app_events).await
    else {
        panic!("rtcp_app");
    };
    assert_eq!(
        (call_id.as_deref(), from_tag.as_str()),
        (Some("local"), "tag-a")
    );
    assert_eq!(
        send_to_leg(
            &engine,
            "local",
            Some("tag-a"),
            RtcpAppStream::Floor,
            Some(9)
        )
        .await,
        ok_empty()
    );
    assert!(recv_datagram(&a.floor, SHORT).await.is_some());
    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "local".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert_eq!(engine.conference().floors().leg_count(), 0);
    assert!(engine.endpoint_calls.is_empty());
}

#[tokio::test]
async fn a_floor_fmtp_with_a_line_break_refuses_offer_answer_and_answer_local() {
    let engine = engine_with_dispatcher();
    let a = party().await;
    let bad = ProfileFlags {
        floor_fmtp: Some("x\r\na=sendrecv".to_string()),
        ..ProfileFlags::default()
    };
    for command in [
        Command::Offer {
            call_id: "c1".into(),
            from_tag: "t".into(),
            sdp: sdp_with_floor(a.audio_addr, Some(a.floor_addr)),
            profile: bad.clone(),
        },
        Command::Answer {
            call_id: "c1".into(),
            from_tag: "t".into(),
            to_tag: "u".into(),
            sdp: sdp_with_floor(a.audio_addr, Some(a.floor_addr)),
            profile: bad.clone(),
        },
        Command::AnswerLocal {
            call_id: "c2".into(),
            from_tag: "t".into(),
            sdp: sdp_with_floor(a.audio_addr, Some(a.floor_addr)),
            profile: bad.clone(),
        },
    ] {
        let CmdResult::Error { reason } = engine.handle(CLIENT, command).await else {
            panic!("expected a refusal");
        };
        assert!(reason.contains("line break"), "{reason}");
    }
    assert!(engine.endpoint_calls.is_empty(), "nothing was allocated");
}

#[tokio::test]
async fn a_single_leg_local_answer_with_a_floor_stream_echoes_no_stream_identity() {
    use super::stream_identity::{
        assert_nothing_of_the_offerer, browser_shaped_offer, OFFERER_SSRC,
    };
    let engine = engine_with_dispatcher();
    let a = party().await;
    // Beside the audio, the floor section carries what a browser would signal, so the answer's
    // floor section is checked as well as its audio section (RFC 5576, RFC 8830, RFC 8285).
    let offer = format!(
        "{}m=application {} udp MCPTT\r\nc=IN IP4 {}\r\na=extmap:5 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\
         a=msid:stream-a track-floor\r\na=ssrc:{OFFERER_SSRC} cname:offerer-cname\r\n",
        browser_shaped_offer(a.audio_addr),
        a.floor_addr.port(),
        a.floor_addr.ip(),
    );
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "local-identity".into(),
                from_tag: "tag-a".into(),
                sdp: offer,
                profile: profile(),
            },
        )
        .await;
    let answer = ok_sdp_text(&result);
    assert_nothing_of_the_offerer(&answer);
    assert!(
        sdp::parse_floor(&answer).is_some(),
        "floor answered:\n{answer}"
    );
}
