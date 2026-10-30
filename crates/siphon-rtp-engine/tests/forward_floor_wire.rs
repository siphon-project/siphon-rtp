//! MCPTT floor control over the real JSON-over-TCP control connection: a phone's Floor Request
//! comes out as an `rtcp_app` event frame (payload in base64), and `send_rtcp_app` puts a Floor
//! Granted on the phone's floor socket. NIC-free (UDP-loopback datapath + loopback control socket).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::Datapath;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_engine::{sdp, server, Engine};
use siphon_rtp_proto::{frame, CmdResult, Command, ProfileFlags, Request, RtcpAppStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const FLOOR_REQUEST: [u8; 16] = [
    0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05, 0x00,
];

async fn phone() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind phone");
    let addr = socket.local_addr().expect("phone addr");
    (socket, addr)
}

/// Read frames off `stream` until `wanted` accepts one; every other frame is skipped.
async fn frame_where(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    wanted: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((value, consumed)) =
            frame::decode::<serde_json::Value>(buffer).expect("decode frame")
        {
            buffer.drain(..consumed);
            if wanted(&value) {
                return value;
            }
            continue;
        }
        let read = timeout(Duration::from_secs(3), stream.read(&mut chunk))
            .await
            .expect("frame not timed out")
            .expect("read");
        assert_ne!(read, 0, "control connection closed");
        buffer.extend_from_slice(&chunk[..read]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn floor_request_is_an_event_frame_and_floor_granted_reaches_the_phone() {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind control");
    let control_addr = listener.local_addr().expect("control addr");
    tokio::spawn(async move {
        let _ = server::serve(engine, listener).await;
    });
    let mut stream = TcpStream::connect(control_addr).await.expect("connect");
    let mut buffer = Vec::new();

    let (audio, audio_addr) = phone().await;
    let (floor, floor_addr) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {audio} RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n\
         a=rtcp-mux\r\nm=application {floor} udp MCPTT\r\n",
        ip = audio_addr.ip(),
        audio = audio_addr.port(),
        floor = floor_addr.port()
    );
    let join = Request {
        id: 1,
        command: Command::ForwardJoin {
            conference_id: "group-1".into(),
            from_tag: "a".into(),
            sdp: offer,
            profile: ProfileFlags {
                floor_fmtp: Some("mc_queueing;mc_granted".into()),
                ..ProfileFlags::default()
            },
        },
    };
    stream
        .write_all(&frame::encode(&join).expect("encode"))
        .await
        .expect("write");
    let response = frame_where(&mut stream, &mut buffer, |value| value.get("id").is_some()).await;
    let answer: CmdResult = serde_json::from_value(response["result"].clone())
        .or_else(|_| serde_json::from_value(response.clone()))
        .expect("result");
    let CmdResult::Ok {
        sdp: Some(answer), ..
    } = answer
    else {
        panic!("join refused: {response}");
    };
    let engine_floor = sdp::parse_floor(&answer).expect("floor section").remote;
    let _keep_audio_alive = audio;

    floor
        .send_to(&FLOOR_REQUEST, engine_floor)
        .await
        .expect("send");
    let event = frame_where(&mut stream, &mut buffer, |value| {
        value.get("event").and_then(|name| name.as_str()) == Some("rtcp_app")
    })
    .await;
    assert_eq!(event["conference_id"], "group-1");
    assert_eq!(event["from_tag"], "a");
    assert_eq!(event["stream"], "floor");
    assert_eq!(event["name"], "MCPT");
    assert_eq!(event["subtype"], 0);
    assert_eq!(event["ssrc"], 0x1122_3344);
    assert_eq!(event["payload"], "AAIFAA==", "00 02 05 00 in base64");

    let send = Request {
        id: 2,
        command: Command::SendRtcpApp {
            call_id: None,
            conference_id: Some("group-1".into()),
            from_tag: Some("a".into()),
            except_from_tags: Vec::new(),
            stream: RtcpAppStream::Floor,
            ssrc: Some(0x0102_0304),
            name: "MCPT".into(),
            subtype: 17,
            payload: vec![0x01, 0x02, 0x00, 0x1E],
        },
    };
    stream
        .write_all(&frame::encode(&send).expect("encode"))
        .await
        .expect("write");
    let response = frame_where(&mut stream, &mut buffer, |value| value.get("id").is_some()).await;
    assert_eq!(response["id"], 2);
    let mut datagram = [0u8; 64];
    let (length, _) = timeout(Duration::from_secs(2), floor.recv_from(&mut datagram))
        .await
        .expect("floor granted in time")
        .expect("recv");
    assert_eq!(
        &datagram[..length],
        [
            0x91, 0xCC, 0x00, 0x03, 0x01, 0x02, 0x03, 0x04, 0x4D, 0x43, 0x50, 0x54, 0x01, 0x02,
            0x00, 0x1E
        ]
    );
}
