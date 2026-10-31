//! The MCPTT floor-control stream of a forwarding-room seat end to end on the UDP-loopback
//! datapath (3GPP TS 24.380): a phone offers `m=application <port> udp MCPTT`, the engine anchors
//! it, floor messages come out as `rtcp_app` events, and `send_rtcp_app` puts floor messages on the
//! wire.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_media::rtcp;
use siphon_rtp_media::rtp::{write_packet, RtpHeader, RtpPacket};
use siphon_rtp_proto::RtcpAppStream;

const ROOM: &str = "group-1";
const SHORT: Duration = Duration::from_secs(2);
const NEGATIVE: Duration = Duration::from_millis(250);
/// The parameters the controller declares for the floor stream.
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

/// An AMR-WB offer for a phone, with an MCPTT floor stream when `floor` is a port.
fn offer(audio: SocketAddr, floor: Option<SocketAddr>) -> String {
    let mut text = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n\
         a=fmtp:96 octet-align=1\r\na=rtcp-mux\r\n",
        ip = audio.ip(),
        port = audio.port()
    );
    if let Some(floor) = floor {
        text.push_str(&format!(
            "m=application {} udp MCPTT\r\na=fmtp:MCPTT mc_queueing;mc_priority=1\r\n",
            floor.port()
        ));
    }
    text
}

fn profile(floor_fmtp: Option<&str>) -> ProfileFlags {
    ProfileFlags {
        floor_fmtp: floor_fmtp.map(str::to_string),
        ..ProfileFlags::default()
    }
}

/// A seated phone: its audio and floor sockets and the engine ports each talks to.
struct Phone {
    audio: UdpSocket,
    floor: UdpSocket,
    engine_audio: SocketAddr,
    engine_floor: SocketAddr,
    answer: String,
}

async fn seat(engine: &Engine<UdpLoopbackDatapath>, tag: &str, fmtp: Option<&str>) -> Phone {
    let (audio, audio_addr) = phone().await;
    let (floor, floor_addr) = phone().await;
    let answer = engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                sdp: offer(audio_addr, Some(floor_addr)),
                profile: profile(fmtp),
            },
        )
        .await;
    let answer = ok_sdp_text(&answer);
    let engine_audio = sdp::parse(&answer).expect("answer").remote_rtp;
    let engine_floor = sdp::parse_floor(&answer).expect("floor section").remote;
    Phone {
        audio,
        floor,
        engine_audio,
        engine_floor,
        answer,
    }
}

async fn send_app(
    engine: &Engine<UdpLoopbackDatapath>,
    from_tag: Option<&str>,
    except: &[&str],
    stream: RtcpAppStream,
    ssrc: Option<u32>,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::SendRtcpApp {
                call_id: None,
                conference_id: Some(ROOM.into()),
                from_tag: from_tag.map(str::to_string),
                except_from_tags: except.iter().map(|tag| (*tag).to_string()).collect(),
                stream,
                ssrc,
                name: "MCPT".into(),
                subtype: 17,
                payload: FLOOR_GRANTED_PAYLOAD.to_vec(),
            },
        )
        .await
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

fn media(sequence: u16, ssrc: u32) -> Vec<u8> {
    let header = RtpHeader {
        marker: false,
        payload_type: 96,
        sequence,
        timestamp: 0,
        ssrc,
    };
    let mut buffer = vec![0u8; 15];
    write_packet(&header, &[1, 2, 3], &mut buffer).expect("write");
    buffer
}

#[tokio::test]
async fn the_floor_stream_is_anchored_with_the_controllers_fmtp() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let phone = seat(&engine, "a", Some(FLOOR_FMTP)).await;
    assert_ne!(phone.engine_floor.port(), 0, "a real port, not a decline");
    assert_ne!(phone.engine_floor.port(), phone.engine_audio.port());
    let lines: Vec<&str> = phone.answer.split("\r\n").collect();
    let m_line = lines
        .iter()
        .position(|line| line.starts_with("m=application"))
        .expect("floor m-line");
    assert_eq!(
        lines[m_line],
        format!("m=application {} udp MCPTT", phone.engine_floor.port())
    );
    assert!(
        lines.contains(&format!("a=fmtp:MCPTT {FLOOR_FMTP}").as_str()),
        "{lines:?}"
    );
    assert!(
        !phone.answer.contains("mc_priority=1"),
        "the offerer's own fmtp is not echoed"
    );
}

#[tokio::test]
async fn no_floor_fmtp_means_no_fmtp_line() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let phone = seat(&engine, "a", None).await;
    assert!(phone.answer.contains("m=application"));
    assert!(!phone.answer.contains("a=fmtp:MCPTT"), "{}", phone.answer);
}

#[tokio::test]
async fn a_floor_fmtp_with_a_line_break_refuses_the_join() {
    let engine = engine_with_dispatcher();
    let (_, audio) = phone().await;
    let result = engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: "a".into(),
                sdp: offer(audio, None),
                profile: profile(Some("mc_granted\r\na=sendrecv")),
            },
        )
        .await;
    let CmdResult::Error { reason } = result else {
        panic!("expected a refusal");
    };
    assert!(reason.contains("line break"), "{reason}");
    assert_eq!(engine.conference().forward().seat_count(), 0);
    assert!(engine.endpoint_calls.is_empty(), "nothing was allocated");
}

#[tokio::test]
async fn other_unknown_media_is_still_declined_and_a_second_floor_section_too() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (_, audio) = phone().await;
    let mut text = offer(audio, Some("127.0.0.1:20032".parse().unwrap()));
    text.push_str("m=video 30000 RTP/AVP 97\r\na=rtpmap:97 H264/90000\r\n");
    text.push_str("m=application 20034 udp MCPTT\r\n");
    let answer = engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: "a".into(),
                sdp: text,
                profile: profile(Some(FLOOR_FMTP)),
            },
        )
        .await;
    let answer = ok_sdp_text(&answer);
    let ports: Vec<(String, String)> = answer
        .split("\r\n")
        .filter_map(|line| line.strip_prefix("m="))
        .map(|line| {
            let mut fields = line.split(' ');
            (
                fields.next().unwrap().to_string(),
                fields.next().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(ports.len(), 4, "{answer}");
    assert_ne!(ports[0].1, "0", "audio");
    assert_ne!(ports[1].1, "0", "the first floor section");
    assert_eq!(ports[2], ("video".to_string(), "0".to_string()));
    assert_eq!(ports[3], ("application".to_string(), "0".to_string()));
}

#[tokio::test]
async fn a_floor_request_reaches_the_controller_as_one_rtcp_app_event() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let phone = seat(&engine, "a", Some(FLOOR_FMTP)).await;
    phone
        .floor
        .send_to(&FLOOR_REQUEST, phone.engine_floor)
        .await
        .expect("send");
    assert_eq!(
        next_app(&app_events).await,
        Event::RtcpApp {
            call_id: None,
            conference_id: Some(ROOM.into()),
            from_tag: "a".into(),
            stream: RtcpAppStream::Floor,
            ssrc: 0x1122_3344,
            name: "MCPT".into(),
            subtype: 0,
            payload: vec![0x00, 0x02, 0x05, 0x00],
        }
    );
    assert!(app_events.try_recv().is_err(), "exactly one");
}

#[tokio::test]
async fn two_app_packets_in_one_datagram_arrive_as_two_events_in_order() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let phone = seat(&engine, "a", Some(FLOOR_FMTP)).await;
    let mut second = FLOOR_REQUEST;
    second[0] = 0x80 | 3;
    let mut datagram = FLOOR_REQUEST.to_vec();
    datagram.extend_from_slice(&second);
    phone
        .floor
        .send_to(&datagram, phone.engine_floor)
        .await
        .expect("send");
    for expected in [0u8, 3] {
        let Event::RtcpApp { subtype, .. } = next_app(&app_events).await else {
            panic!("rtcp_app");
        };
        assert_eq!(subtype, expected);
    }
}

#[tokio::test]
async fn a_floor_granted_reaches_the_seat_byte_exact_under_its_stream_ssrc() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let talker = seat(&engine, "a", Some(FLOOR_FMTP)).await;
    let listener = seat(&engine, "b", Some(FLOOR_FMTP)).await;
    // The default SSRC is the one the seat's RTP is announced under: read it off a forwarded packet.
    assert_eq!(
        engine
            .handle(
                CLIENT,
                Command::ForwardSetSource {
                    conference_id: ROOM.into(),
                    from_tag: Some("a".into()),
                }
            )
            .await,
        ok_empty()
    );
    talker
        .audio
        .send_to(&media(1, 0xA0A0_A0A0), talker.engine_audio)
        .await
        .expect("send");
    let heard = loop {
        let datagram = recv_datagram(&listener.audio, SHORT)
            .await
            .expect("forwarded rtp");
        if !(64..=95).contains(&(datagram[1] & 0x7f)) {
            break datagram;
        }
    };
    let ssrc = RtpPacket::parse(&heard).expect("rtp").ssrc;

    assert_eq!(
        send_app(&engine, Some("b"), &[], RtcpAppStream::Floor, None).await,
        ok_empty()
    );
    let received = recv_datagram(&listener.floor, SHORT).await.expect("floor");
    let mut expected = vec![0x91, 0xCC, 0x00, 0x05];
    expected.extend_from_slice(&ssrc.to_be_bytes());
    expected.extend_from_slice(b"MCPT");
    expected.extend_from_slice(&FLOOR_GRANTED_PAYLOAD);
    assert_eq!(received, expected);
    assert!(
        recv_datagram(&talker.floor, NEGATIVE).await.is_none(),
        "only the addressed seat"
    );
}

#[tokio::test]
async fn a_room_wide_send_reaches_every_seat_but_the_excepted_one() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let a = seat(&engine, "a", None).await;
    let b = seat(&engine, "b", None).await;
    let c = seat(&engine, "c", None).await;
    assert_eq!(
        send_app(
            &engine,
            None,
            &["a"],
            RtcpAppStream::Floor,
            Some(0xCAFE_F00D)
        )
        .await,
        ok_empty()
    );
    for phone in [&b, &c] {
        let received = recv_datagram(&phone.floor, SHORT).await.expect("floor");
        assert_eq!(&received[4..8], &0xCAFE_F00Du32.to_be_bytes());
        assert_eq!(received[0], 0x91);
    }
    assert!(recv_datagram(&a.floor, NEGATIVE).await.is_none());
}

#[tokio::test]
async fn send_rtcp_app_on_the_audio_stream_uses_the_audio_endpoint() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let a = seat(&engine, "a", None).await;
    assert_eq!(
        send_app(&engine, Some("a"), &[], RtcpAppStream::Audio, Some(7)).await,
        ok_empty()
    );
    // The room's report timer fires at once when the room starts, so a Sender Report (RFC 3550
    // §6.4.1) can reach the seat ahead of the APP packet: skip datagrams that carry none.
    let (subtype, ssrc) = loop {
        let received = recv_datagram(&a.audio, SHORT).await.expect("audio rtcp");
        let mut apps = rtcp::app_packets(&received);
        if let Some(app) = apps.next() {
            let app = app.expect("app");
            break (app.subtype, app.ssrc);
        }
    };
    assert_eq!(subtype, 17);
    assert_eq!(ssrc, 7);
    assert!(recv_datagram(&a.floor, NEGATIVE).await.is_none());
}

#[tokio::test]
async fn send_rtcp_app_refuses_what_it_cannot_send() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let _a = seat(&engine, "a", None).await;
    let command = |call_id: Option<&str>,
                   conference_id: Option<&str>,
                   from_tag: Option<&str>,
                   except: &[&str],
                   name: &str,
                   subtype: u8,
                   payload: Vec<u8>| Command::SendRtcpApp {
        call_id: call_id.map(Into::into),
        conference_id: conference_id.map(Into::into),
        from_tag: from_tag.map(Into::into),
        except_from_tags: except.iter().map(|tag| (*tag).to_string()).collect(),
        stream: RtcpAppStream::Floor,
        ssrc: None,
        name: name.into(),
        subtype,
        payload,
    };
    let reason = |result: CmdResult| match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected an error, got {other:?}"),
    };
    let four = vec![0u8; 4];
    // Both or neither of call and room.
    let both = command(Some("c"), Some(ROOM), None, &[], "MCPT", 0, four.clone());
    assert!(reason(engine.handle(CLIENT, both).await).contains("not both"));
    let neither = command(None, None, None, &[], "MCPT", 0, four.clone());
    assert!(reason(engine.handle(CLIENT, neither).await).contains("call_id or a conference_id"));
    // The packet.
    for (name, subtype, payload) in [
        ("MCP", 0, four.clone()),
        ("MCPT", 32, four.clone()),
        ("MCPT", 0, vec![0; 3]),
    ] {
        let bad = command(None, Some(ROOM), Some("a"), &[], name, subtype, payload);
        assert!(matches!(
            engine.handle(CLIENT, bad).await,
            CmdResult::Error { .. }
        ));
    }
    // except_from_tags with a single seat.
    let single = command(None, Some(ROOM), Some("a"), &["b"], "MCPT", 0, four.clone());
    assert!(reason(engine.handle(CLIENT, single).await).contains("except_from_tags"));
    // Unknown seat, unknown room.
    let ghost = command(
        None,
        Some(ROOM),
        Some("ghost"),
        &[],
        "MCPT",
        0,
        four.clone(),
    );
    assert!(reason(engine.handle(CLIENT, ghost).await).contains("no seat ghost"));
    let nowhere = command(None, Some("nowhere"), None, &[], "MCPT", 0, four.clone());
    assert!(reason(engine.handle(CLIENT, nowhere).await).contains("unknown forwarding room"));
}

#[tokio::test]
async fn floor_to_a_seat_without_a_floor_stream_is_an_error() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (_, audio) = phone().await;
    let answer = engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: "plain".into(),
                sdp: offer(audio, None),
                profile: profile(Some(FLOOR_FMTP)),
            },
        )
        .await;
    assert!(!ok_sdp_text(&answer).contains("m=application"));
    let CmdResult::Error { reason } =
        send_app(&engine, Some("plain"), &[], RtcpAppStream::Floor, None).await
    else {
        panic!("expected an error");
    };
    assert!(reason.contains("plain (no floor stream)"), "{reason}");
}

#[tokio::test]
async fn floor_traffic_keeps_a_seat_from_going_inactive() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let a = seat(&engine, "a", Some(FLOOR_FMTP)).await;
    let _b = seat(&engine, "b", Some(FLOOR_FMTP)).await;
    engine.datapath().advance_clock(40);
    a.floor
        .send_to(&FLOOR_REQUEST, a.engine_floor)
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        engine.scan_inactive_forward_seats(30),
        1,
        "only b, which sent nothing, is quiet"
    );
    let quiet: Vec<String> = events
        .try_iter()
        .filter_map(|event| match event {
            Event::ForwardSeatInactive { from_tag, .. } => Some(from_tag),
            _ => None,
        })
        .collect();
    assert_eq!(quiet, ["b"]);
}

#[tokio::test]
async fn app_in_a_seats_audio_rtcp_is_reported_on_the_audio_stream() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let a = seat(&engine, "a", None).await;
    let mut buffer = [0u8; 128];
    let mut length = rtcp::write_sender_report(0xA0A0_A0A0, 0, 0, 0, 0, &[], &mut buffer)
        .expect("sender report");
    length += rtcp::write_app(
        5,
        0xA0A0_A0A0,
        *b"MCPT",
        &[0, 0, 0, 1],
        &mut buffer[length..],
    )
    .expect("app");
    a.audio
        .send_to(&buffer[..length], a.engine_audio)
        .await
        .expect("send");
    let Event::RtcpApp {
        stream,
        subtype,
        from_tag,
        ..
    } = next_app(&app_events).await
    else {
        panic!("rtcp_app");
    };
    assert_eq!(stream, RtcpAppStream::Audio);
    assert_eq!(subtype, 5);
    assert_eq!(from_tag, "a");
}

#[tokio::test]
async fn leaving_frees_the_floor_endpoint_and_stops_its_ingress() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let a = seat(&engine, "a", Some(FLOOR_FMTP)).await;
    let _b = seat(&engine, "b", Some(FLOOR_FMTP)).await;
    let forward = engine.conference().forward().clone();
    assert_eq!(engine.endpoint_calls.len(), 4, "two endpoints per seat");
    let floor_endpoint = engine
        .endpoint_calls
        .iter()
        .map(|entry| *entry.key())
        .filter(|endpoint| forward.owns(*endpoint))
        .count();
    assert_eq!(floor_endpoint, 4);
    assert_eq!(
        engine
            .handle(
                CLIENT,
                Command::ForwardLeave {
                    conference_id: ROOM.into(),
                    from_tag: "a".into()
                }
            )
            .await,
        ok_empty()
    );
    assert_eq!(
        engine.endpoint_calls.len(),
        2,
        "both of a's endpoints freed"
    );
    // Floor sent to the freed port is not delivered anywhere.
    let _ = a.floor.send_to(&FLOOR_REQUEST, a.engine_floor).await;
    assert_eq!(
        engine
            .handle(
                CLIENT,
                Command::ForwardLeave {
                    conference_id: ROOM.into(),
                    from_tag: "b".into()
                }
            )
            .await,
        ok_empty()
    );
    assert!(engine.endpoint_calls.is_empty());
    assert_eq!(engine.conference().forward().room_count(), 0);
}

#[tokio::test]
async fn node_info_advertises_floor_control_and_statistics_count_dropped_app_events() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("node_info answers a node");
    };
    for feature in ["mcptt_floor", "rtcp_app", "webrtc_floor_channel"] {
        assert!(
            node.features.iter().any(|name| name == feature),
            "{feature}"
        );
    }
    // Fill the controller's APP queue past its capacity: the oldest are shed and counted.
    let _events = engine.register_client(CLIENT);
    let queue = engine.app_event_queue(CLIENT).expect("queue");
    let app = |sequence: u32| Event::RtcpApp {
        call_id: None,
        conference_id: Some(ROOM.into()),
        from_tag: "a".into(),
        stream: RtcpAppStream::Floor,
        ssrc: sequence,
        name: "MCPT".into(),
        subtype: 0,
        payload: Vec::new(),
    };
    let capacity = crate::app_events::APP_EVENT_QUEUE_CAPACITY as u32;
    for sequence in 0..capacity + 3 {
        queue.push(app(sequence));
    }
    let CmdResult::Statistics { statistics } = engine.handle(CLIENT, Command::Statistics).await
    else {
        panic!("statistics");
    };
    assert_eq!(statistics.rtcp_app_dropped_total, 3);
    // What is left is the newest `capacity`, still in order.
    let receiver = engine.app_event_receiver(CLIENT).expect("queue");
    let first = receiver.try_recv().expect("an event");
    assert!(matches!(first, Event::RtcpApp { ssrc: 3, .. }));
    assert_eq!(receiver.len() as u32, capacity - 1);
}
