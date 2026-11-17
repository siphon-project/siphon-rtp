//! The MCVideo transmission control stream (`m=application <rtcp port> udp MCVideo`, 3GPP TS 24.581
//! §4.3.3.1 table 4.3.3.1-1) end to end on the UDP-loopback datapath, for a forwarding-room seat and
//! a two-party call. It is the MCPTT floor stream's shape with another token: the engine terminates
//! it, raises what a party sends as `rtcp_app` and puts `send_rtcp_app` on the wire. The APP names
//! (`MCV0`/`MCV1`/`MCV2`, TS 24.581 §9.1.2) and subtypes are opaque to the engine.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_proto::{ControlFormat, RtcpAppStream};

const ROOM: &str = "video-group";
const CALL: &str = "call-transmission";
const SHORT: Duration = Duration::from_secs(2);
const NEGATIVE: Duration = Duration::from_millis(250);
/// TS 24.581 §12.1.2 shaped parameters the controller declares for the stream.
const CONTROL_FMTP: &str = "mc_queueing;mc_priority=5;mc_granted;mc_transmission_ssrc=12345678";
const MCVIDEO: &[ControlFormat] = &[ControlFormat::Mcvideo];

/// An RTCP APP packet (RFC 3550 §6.7): SSRC 0x11223344, the given name and subtype, 4 data octets.
fn app_packet(name: &[u8; 4], subtype: u8) -> Vec<u8> {
    let mut packet = vec![0x80 | subtype, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44];
    packet.extend_from_slice(name);
    packet.extend_from_slice(&[0x00, 0x02, 0x05, 0x00]);
    packet
}

fn mcvideo_profile() -> ProfileFlags {
    ProfileFlags {
        floor_fmtp: Some(CONTROL_FMTP.to_string()),
        transmission_control_formats: vec![ControlFormat::Mcvideo],
        ..ProfileFlags::default()
    }
}

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

fn offer(audio: SocketAddr, control: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
         m=application {control_port} udp MCVideo\r\na=fmtp:MCVideo mc_queueing\r\n",
        ip = audio.ip(),
        port = audio.port(),
        control_port = control.port()
    )
}

struct Party {
    /// Held so the audio port stays bound for the life of the test.
    _audio: UdpSocket,
    control: UdpSocket,
    audio_addr: SocketAddr,
    control_addr: SocketAddr,
}

async fn party() -> Party {
    let (audio, audio_addr) = phone().await;
    let (control, control_addr) = phone().await;
    Party {
        _audio: audio,
        control,
        audio_addr,
        control_addr,
    }
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

/// The ports of an SDP's `m=` lines, in order.
fn media_ports(text: &str) -> Vec<(String, String)> {
    text.split("\r\n")
        .filter_map(|line| line.strip_prefix("m="))
        .map(|line| {
            let mut fields = line.split(' ');
            (
                fields.next().unwrap().to_string(),
                fields.next().unwrap().to_string(),
            )
        })
        .collect()
}

async fn join(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    party: &Party,
    profile: ProfileFlags,
) -> String {
    let result = engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                sdp: offer(party.audio_addr, party.control_addr),
                profile,
            },
        )
        .await;
    ok_sdp_text(&result)
}

#[tokio::test]
async fn a_seat_with_audio_and_an_mcvideo_control_stream_is_answered_under_the_same_token() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let seat = party().await;
    let answer = join(&engine, "a", &seat, mcvideo_profile()).await;
    let info = sdp::parse_floor(&answer, MCVIDEO).expect("control section");
    assert_eq!(info.format, ControlFormat::Mcvideo);
    assert_ne!(info.remote.port(), 0);
    assert!(
        answer.contains(&format!(
            "m=application {} udp MCVideo\r\n",
            info.remote.port()
        )),
        "{answer}"
    );
    assert!(
        answer.contains(&format!("a=fmtp:MCVideo {CONTROL_FMTP}\r\n")),
        "{answer}"
    );
    assert!(
        !answer.contains("mc_queueing\r\n"),
        "the offerer's own fmtp is not echoed: {answer}"
    );
    assert!(
        !answer.contains(&seat.control_addr.port().to_string()),
        "the offerer's own control port does not leak: {answer}"
    );
}

#[tokio::test]
async fn an_mcvideo_seat_under_the_default_profile_is_declined_at_port_0() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let seat = party().await;
    let profile = ProfileFlags {
        floor_fmtp: Some(CONTROL_FMTP.to_string()),
        ..ProfileFlags::default()
    };
    let answer = join(&engine, "a", &seat, profile).await;
    let ports = media_ports(&answer);
    assert_eq!(ports.len(), 2, "{answer}");
    assert_ne!(ports[0].1, "0", "audio");
    assert_eq!(ports[1], ("application".to_string(), "0".to_string()));
    assert!(sdp::parse_floor(&answer, MCVIDEO).is_none());
    assert!(
        !answer.contains(&seat.control_addr.port().to_string()),
        "never passed through: {answer}"
    );
}

#[tokio::test]
async fn an_mcv0_app_from_a_seat_raises_rtcp_app_with_name_and_subtype_unchanged() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let seat = party().await;
    let answer = join(&engine, "a", &seat, mcvideo_profile()).await;
    let engine_control = sdp::parse_floor(&answer, MCVIDEO).unwrap().remote;
    seat.control
        .send_to(&app_packet(b"MCV0", 9), engine_control)
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
            name: "MCV0".into(),
            subtype: 9,
            payload: vec![0x00, 0x02, 0x05, 0x00],
        }
    );
    assert!(app_events.try_recv().is_err(), "exactly one");
}

#[tokio::test]
async fn two_apps_in_one_datagram_raise_two_events() {
    // TS 24.581 §9.1.1: transmission control messages may be concatenated in one RTCP packet.
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let seat = party().await;
    let answer = join(&engine, "a", &seat, mcvideo_profile()).await;
    let engine_control = sdp::parse_floor(&answer, MCVIDEO).unwrap().remote;
    let mut datagram = app_packet(b"MCV0", 1);
    datagram.extend_from_slice(&app_packet(b"MCV2", 7));
    seat.control
        .send_to(&datagram, engine_control)
        .await
        .expect("send");
    for (expected_name, expected_subtype) in [("MCV0", 1u8), ("MCV2", 7)] {
        let Event::RtcpApp { name, subtype, .. } = next_app(&app_events).await else {
            panic!("rtcp_app");
        };
        assert_eq!((name.as_str(), subtype), (expected_name, expected_subtype));
    }
    assert!(app_events.try_recv().is_err(), "exactly two");
}

#[tokio::test]
async fn send_rtcp_app_named_mcv1_reaches_the_seat() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let seat = party().await;
    join(&engine, "a", &seat, mcvideo_profile()).await;
    let payload = vec![0x01, 0x02, 0x00, 0x1E];
    assert_eq!(
        engine
            .handle(
                CLIENT,
                Command::SendRtcpApp {
                    call_id: None,
                    conference_id: Some(ROOM.into()),
                    from_tag: Some("a".into()),
                    except_from_tags: Vec::new(),
                    stream: RtcpAppStream::Floor,
                    ssrc: Some(0xCAFE_F00D),
                    name: "MCV1".into(),
                    subtype: 4,
                    payload: payload.clone(),
                }
            )
            .await,
        ok_empty()
    );
    let received = recv_datagram(&seat.control, SHORT).await.expect("app");
    assert_eq!(received[0], 0x80 | 4, "V=2, subtype 4");
    assert_eq!(received[1], 204, "PT=APP");
    assert_eq!(&received[4..8], &0xCAFE_F00Du32.to_be_bytes());
    assert_eq!(&received[8..12], b"MCV1");
    assert_eq!(&received[12..], &payload[..]);
}

async fn call_offer(
    engine: &Engine<UdpLoopbackDatapath>,
    a: &Party,
    profile: ProfileFlags,
) -> String {
    ok_sdp_text(
        &engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: CALL.into(),
                    from_tag: "tag-a".into(),
                    sdp: offer(a.audio_addr, a.control_addr),
                    profile,
                },
            )
            .await,
    )
}

async fn call_answer(
    engine: &Engine<UdpLoopbackDatapath>,
    b: &Party,
    profile: ProfileFlags,
) -> String {
    ok_sdp_text(
        &engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: CALL.into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: offer(b.audio_addr, b.control_addr),
                    profile,
                },
            )
            .await,
    )
}

#[tokio::test]
async fn a_two_party_call_terminates_mcvideo_on_both_sides() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let (a, b) = (party().await, party().await);
    let to_b = call_offer(&engine, &a, mcvideo_profile()).await;
    let to_a = call_answer(&engine, &b, mcvideo_profile()).await;
    let toward_b = sdp::parse_floor(&to_b, MCVIDEO)
        .expect("control toward B")
        .remote;
    let toward_a = sdp::parse_floor(&to_a, MCVIDEO)
        .expect("control toward A")
        .remote;
    for text in [&to_a, &to_b] {
        assert!(text.contains("udp MCVideo\r\n"), "{text}");
        assert!(
            text.contains(&format!("a=fmtp:MCVideo {CONTROL_FMTP}")),
            "{text}"
        );
    }

    // Inbound: a datagram with two concatenated APPs from A raises two events under A's leg.
    let mut datagram = app_packet(b"MCV0", 2);
    datagram.extend_from_slice(&app_packet(b"MCV1", 6));
    a.control.send_to(&datagram, toward_a).await.expect("send");
    for (expected_name, expected_subtype) in [("MCV0", 2u8), ("MCV1", 6)] {
        let Event::RtcpApp {
            call_id,
            from_tag,
            name,
            subtype,
            ..
        } = next_app(&app_events).await
        else {
            panic!("rtcp_app");
        };
        assert_eq!(call_id.as_deref(), Some(CALL));
        assert_eq!(from_tag, "tag-a");
        assert_eq!((name.as_str(), subtype), (expected_name, expected_subtype));
    }
    b.control
        .send_to(&app_packet(b"MCV2", 1), toward_b)
        .await
        .expect("send");
    let Event::RtcpApp { from_tag, name, .. } = next_app(&app_events).await else {
        panic!("rtcp_app");
    };
    assert_eq!((from_tag.as_str(), name.as_str()), ("tag-b", "MCV2"));
    assert!(
        recv_datagram(&b.control, NEGATIVE).await.is_none(),
        "not relayed"
    );

    // Outbound: send_rtcp_app named MCV1 reaches B.
    let sent = engine
        .handle(
            CLIENT,
            Command::SendRtcpApp {
                call_id: Some(CALL.into()),
                conference_id: None,
                from_tag: Some("tag-b".into()),
                except_from_tags: Vec::new(),
                stream: RtcpAppStream::Floor,
                ssrc: None,
                name: "MCV1".into(),
                subtype: 3,
                payload: vec![0, 0, 0, 0],
            },
        )
        .await;
    assert_eq!(sent, ok_empty());
    let received = recv_datagram(&b.control, SHORT).await.expect("app to B");
    assert_eq!(&received[8..12], b"MCV1");
    assert_eq!(received[0] & 0x1F, 3);
}

#[tokio::test]
async fn an_mcvideo_offer_under_the_default_profile_is_declined_toward_the_other_party() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let a = party().await;
    let to_b = call_offer(&engine, &a, ProfileFlags::default()).await;
    assert!(sdp::parse_floor(&to_b, MCVIDEO).is_none(), "{to_b}");
    assert!(
        media_ports(&to_b).contains(&("application".to_string(), "0".to_string())),
        "{to_b}"
    );
    assert!(
        !to_b.contains(&a.control_addr.port().to_string()),
        "A's own control port is never handed to B: {to_b}"
    );
    assert_eq!(engine.conference().floors().leg_count(), 0);
}

#[tokio::test]
async fn a_reoffer_keeps_mcvideo_whatever_the_reoffers_profile_accepts() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (a, b) = (party().await, party().await);
    call_offer(&engine, &a, mcvideo_profile()).await;
    call_answer(&engine, &b, mcvideo_profile()).await;
    assert_eq!(
        engine.conference().floors().format(CALL, "tag-a"),
        Some(ControlFormat::Mcvideo)
    );
    let reoffered = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                sdp: offer(a.audio_addr, a.control_addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let presented = ok_sdp_text(&reoffered);
    assert!(
        sdp::parse_floor(&presented, MCVIDEO).is_some(),
        "{presented}"
    );
    assert!(
        presented.contains(&format!("a=fmtp:MCVideo {CONTROL_FMTP}")),
        "{presented}"
    );
}

#[tokio::test]
async fn a_standby_restores_the_stream_with_its_format_and_a_reoffer_keeps_it() {
    let range = (50_760u16, 50_800u16);
    let node = |min, max| {
        let engine = Engine::new(UdpLoopbackDatapath::with_port_range(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            min,
            max,
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
    let primary = node(range.0, range.1);
    let _events = primary.register_client(CLIENT);
    let (a, b) = (party().await, party().await);
    call_offer(&primary, &a, mcvideo_profile()).await;
    call_answer(&primary, &b, mcvideo_profile()).await;
    let CmdResult::Checkpoint { snapshot } = primary
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
            },
        )
        .await
    else {
        panic!("expected a checkpoint");
    };
    assert!(snapshot.contains(r#""format":"MCVideo""#), "{snapshot}");
    primary
        .handle(
            CLIENT,
            Command::Delete {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    drop(primary);
    let standby = node(range.0, range.1);
    let _standby_events = standby.register_client(CLIENT);
    let restored = standby.handle(CLIENT, Command::Restore { snapshot }).await;
    assert!(matches!(restored, CmdResult::Ok { .. }), "{restored:?}");
    assert_eq!(
        standby.conference().floors().format(CALL, "tag-a"),
        Some(ControlFormat::Mcvideo)
    );
    let result = standby
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                sdp: offer(a.audio_addr, a.control_addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let presented = ok_sdp_text(&result);
    assert!(
        sdp::parse_floor(&presented, MCVIDEO).is_some(),
        "{presented}"
    );
    assert!(
        presented.contains(&format!("a=fmtp:MCVideo {CONTROL_FMTP}")),
        "{presented}"
    );
}

#[tokio::test]
async fn a_forward_offer_writes_the_profiles_first_format_and_reads_the_answer_under_it() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let seat = party().await;
    let offered = engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: "d".into(),
                profile: ProfileFlags {
                    transmission_control_formats: vec![
                        ControlFormat::Mcvideo,
                        ControlFormat::Mcptt,
                    ],
                    ..mcvideo_profile()
                },
            },
        )
        .await;
    let offered = ok_sdp_text(&offered);
    let engine_control = sdp::parse_floor(&offered, MCVIDEO)
        .expect("an MCVideo control section")
        .remote;
    assert!(offered.contains("udp MCVideo\r\n"), "{offered}");
    assert!(!offered.contains("udp MCPTT"), "{offered}");
    assert!(
        offered.contains(&format!("a=fmtp:MCVideo {CONTROL_FMTP}\r\n")),
        "{offered}"
    );
    let engine_audio = sdp::parse(&offered).expect("parse").remote_rtp;
    assert_ne!(engine_control.port(), engine_audio.port());

    let answer = format!(
        "v=0\r\no=- 7 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\na=rtcp-mux\r\n\
         m=application {control_port} udp MCVideo\r\n",
        ip = seat.audio_addr.ip(),
        port = seat.audio_addr.port(),
        control_port = seat.control_addr.port()
    );
    let answered = engine
        .handle(
            CLIENT,
            Command::ForwardAnswer {
                conference_id: ROOM.into(),
                from_tag: "d".into(),
                sdp: answer,
                received_from: None,
            },
        )
        .await;
    assert_eq!(answered, seated_with(&["audio", "floor"]));
    seat.control
        .send_to(&app_packet(b"MCV0", 5), engine_control)
        .await
        .expect("send");
    let Event::RtcpApp {
        from_tag,
        name,
        subtype,
        ..
    } = next_app(&app_events).await
    else {
        panic!("rtcp_app");
    };
    assert_eq!(
        (from_tag.as_str(), name.as_str(), subtype),
        ("d", "MCV0", 5)
    );
}

#[tokio::test]
async fn a_forward_offer_answered_under_another_token_has_no_control_stream() {
    // RFC 3264 §6: the answer echoes the offered format. An MCPTT answer to an MCVideo offer is not
    // the stream that was offered, so the seat is audio-only and nothing is served.
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let seat = party().await;
    let offered = engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: "d".into(),
                profile: mcvideo_profile(),
            },
        )
        .await;
    let engine_control = sdp::parse_floor(&ok_sdp_text(&offered), MCVIDEO)
        .expect("control section")
        .remote;
    let answer = format!(
        "v=0\r\no=- 7 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\na=rtcp-mux\r\n\
         m=application {control_port} udp MCPTT\r\n",
        ip = seat.audio_addr.ip(),
        port = seat.audio_addr.port(),
        control_port = seat.control_addr.port()
    );
    let answered = engine
        .handle(
            CLIENT,
            Command::ForwardAnswer {
                conference_id: ROOM.into(),
                from_tag: "d".into(),
                sdp: answer,
                received_from: None,
            },
        )
        .await;
    assert_eq!(answered, seated_with(&["audio"]));
    seat.control
        .send_to(&app_packet(b"MCV0", 5), engine_control)
        .await
        .expect("send");
    assert!(
        tokio::time::timeout(NEGATIVE, app_events.recv_async())
            .await
            .is_err(),
        "no control stream is served"
    );
}

#[tokio::test]
async fn a_bad_floor_channel_label_refuses_the_command_before_anything_is_allocated() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let seat = party().await;
    for bad in ["", "a\nb", "x".repeat(256).as_str()] {
        let profile = ProfileFlags {
            floor_channel_label: Some(bad.to_string()),
            ..ProfileFlags::default()
        };
        let offered = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: CALL.into(),
                    from_tag: "tag-a".into(),
                    sdp: offer(seat.audio_addr, seat.control_addr),
                    profile: profile.clone(),
                },
            )
            .await;
        let CmdResult::Error { reason } = offered else {
            panic!("expected a refusal for {bad:?}");
        };
        assert!(reason.contains("floor_channel_label"), "{reason}");
        let joined = engine
            .handle(
                CLIENT,
                Command::ForwardJoin {
                    media: siphon_rtp_proto::ForwardMedia::Translate,
                    conference_id: ROOM.into(),
                    from_tag: "a".into(),
                    sdp: offer(seat.audio_addr, seat.control_addr),
                    profile,
                },
            )
            .await;
        assert!(matches!(joined, CmdResult::Error { .. }), "{bad:?}");
    }
    assert_eq!(engine.conference().forward().seat_count(), 0);
}

/// The datagram the engine writes for an `MCV1` APP (TS 24.581 §9.1.2; the writer `send_rtcp_app`
/// uses), pinned to bytes an independent decoder read back: `text2pcap` as UDP, then
/// `tshark -d udp.port==<port>,rtcp -T fields -e rtcp.app.name -e rtcp.app.subtype` gave `MCV1`, 4.
#[test]
fn mcv1_app_datagram_matches_the_bytes_wireshark_decoded() {
    let mut buffer = [0u8; 64];
    let length = siphon_rtp_media::rtcp::write_app(
        4,
        0xCAFE_F00D,
        *b"MCV1",
        &[0x01, 0x02, 0x00, 0x1E],
        &mut buffer,
    )
    .unwrap();
    assert_eq!(
        &buffer[..length],
        &[
            0x84, 0xCC, 0x00, 0x03, 0xCA, 0xFE, 0xF0, 0x0D, b'M', b'C', b'V', b'1', 0x01, 0x02,
            0x00, 0x1E,
        ]
    );
}
