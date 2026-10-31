//! Audio RTCP APP on a two-party call that runs on the plain in-kernel relay and carries an MCPTT
//! floor stream (3GPP TS 24.380 §8), end to end on the UDP-loopback datapath. The relay hands the
//! RTCP to the engine (RFC 3550 §6), which reports each APP packet as `rtcp_app { stream: audio }`
//! and relays the compound to the peer byte for byte; RTP stays on the relay. A call without a floor
//! stream is untouched.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_proto::RtcpAppStream;

const CALL: &str = "call-floor-rtcp";
const SHORT: Duration = Duration::from_secs(2);
const NEGATIVE: Duration = Duration::from_millis(250);

/// TS 24.380 §8.2.4 Floor Request: SSRC 0x11223344, name MCPT, subtype 0.
const FLOOR_REQUEST: [u8; 16] = [
    0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05, 0x00,
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

/// A sender report (RFC 3550 §6.4.1) from `ssrc` followed by the Floor Request APP: a compound.
fn compound(ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 200, 0x00, 0x06];
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&[0u8; 20]);
    packet.extend_from_slice(&FLOOR_REQUEST);
    packet
}

fn rtp(ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0];
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&[0xD5; 160]);
    packet
}

/// One party: its RTP socket, its RTCP socket (the same socket when RTCP is muxed, RFC 5761), and
/// a floor socket.
struct Party {
    rtp: UdpSocket,
    rtcp: Option<UdpSocket>,
    rtp_addr: SocketAddr,
    rtcp_addr: SocketAddr,
    floor_addr: SocketAddr,
    /// Held so the floor port stays bound.
    _floor: UdpSocket,
}

impl Party {
    async fn new(muxed: bool) -> Self {
        let (rtp, rtp_addr) = phone().await;
        let (floor, floor_addr) = phone().await;
        if muxed {
            return Self {
                rtp,
                rtcp: None,
                rtp_addr,
                rtcp_addr: rtp_addr,
                floor_addr,
                _floor: floor,
            };
        }
        let (rtcp, rtcp_addr) = phone().await;
        Self {
            rtp,
            rtcp: Some(rtcp),
            rtp_addr,
            rtcp_addr,
            floor_addr,
            _floor: floor,
        }
    }

    /// The socket this party's RTCP arrives on.
    fn rtcp_socket(&self) -> &UdpSocket {
        self.rtcp.as_ref().unwrap_or(&self.rtp)
    }

    fn sdp(&self, with_floor: bool) -> String {
        let rtcp_line = if self.rtcp.is_some() {
            format!("a=rtcp:{}\r\n", self.rtcp_addr.port())
        } else {
            "a=rtcp-mux\r\n".to_string()
        };
        let mut text = format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n{rtcp_line}",
            ip = self.rtp_addr.ip(),
            port = self.rtp_addr.port()
        );
        if with_floor {
            text.push_str(&format!(
                "m=application {} udp MCPTT\r\na=fmtp:MCPTT mc_queueing\r\n",
                self.floor_addr.port()
            ));
        }
        text
    }
}

fn profile(with_floor: bool) -> ProfileFlags {
    ProfileFlags {
        floor_fmtp: with_floor.then(|| "mc_queueing;mc_priority=5;mc_granted".to_string()),
        ..ProfileFlags::default()
    }
}

/// Offer and answer a plain call; returns the engine's addresses toward A and toward B (RTP, RTCP).
async fn call(
    engine: &Engine<UdpLoopbackDatapath>,
    a: &Party,
    b: &Party,
    with_floor: bool,
) -> (sdp::MediaInfo, sdp::MediaInfo) {
    let to_b = ok_sdp_text(
        &engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: CALL.into(),
                    from_tag: "tag-a".into(),
                    sdp: a.sdp(with_floor),
                    profile: profile(with_floor),
                },
            )
            .await,
    );
    let to_a = ok_sdp_text(
        &engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: CALL.into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: b.sdp(with_floor),
                    profile: profile(with_floor),
                },
            )
            .await,
    );
    (
        sdp::parse(&to_a).expect("answer to A"),
        sdp::parse(&to_b).expect("offer to B"),
    )
}

async fn datagram(socket: &UdpSocket, window: Duration) -> Option<Vec<u8>> {
    let mut buffer = [0u8; 2048];
    match tokio::time::timeout(window, socket.recv_from(&mut buffer)).await {
        Ok(Ok((length, _))) => Some(buffer[..length].to_vec()),
        _ => None,
    }
}

async fn each_shape(check: impl AsyncFn(bool)) {
    check(true).await;
    check(false).await;
}

#[tokio::test]
async fn audio_app_on_a_kernel_relayed_floor_call_is_reported_and_the_compound_is_relayed() {
    each_shape(async |muxed| {
        let engine = engine_with_dispatcher();
        let _events = engine.register_client(CLIENT);
        let app_events = engine.app_event_receiver(CLIENT).expect("queue");
        let (a, b) = (Party::new(muxed).await, Party::new(muxed).await);
        let (toward_a, toward_b) = call(&engine, &a, &b, true).await;
        assert_eq!(
            engine.owned_call_internal(CALL, |call| call.pipeline),
            Some(PipelineKind::Passthrough),
            "the call stays on the plain relay"
        );

        // A's compound: one event for A, and B receives the datagram unchanged.
        let from_a = compound(0xA0A0_0001);
        a.rtcp_socket()
            .send_to(&from_a, toward_a.remote_rtcp)
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
        } = tokio::time::timeout(SHORT, app_events.recv_async())
            .await
            .expect("an rtcp_app event")
            .expect("open queue")
        else {
            panic!("rtcp_app");
        };
        assert_eq!(call_id.as_deref(), Some(CALL));
        assert_eq!(conference_id, None);
        assert_eq!(from_tag, "tag-a");
        assert_eq!(stream, RtcpAppStream::Audio, "muxed={muxed}");
        assert_eq!((ssrc, name.as_str(), subtype), (0x1122_3344, "MCPT", 0));
        assert_eq!(payload, [0x00, 0x02, 0x05, 0x00]);
        assert_eq!(
            datagram(b.rtcp_socket(), SHORT).await.as_deref(),
            Some(&from_a[..]),
            "B receives A's compound byte for byte, muxed={muxed}"
        );
        assert!(app_events.try_recv().is_err(), "exactly one event");
        assert!(
            datagram(b.rtcp_socket(), NEGATIVE).await.is_none(),
            "and exactly one datagram"
        );

        // B's compound: the other direction, tagged for B.
        let from_b = compound(0xB0B0_0002);
        b.rtcp_socket()
            .send_to(&from_b, toward_b.remote_rtcp)
            .await
            .expect("send");
        let Event::RtcpApp {
            from_tag, stream, ..
        } = tokio::time::timeout(SHORT, app_events.recv_async())
            .await
            .expect("an rtcp_app event")
            .expect("open queue")
        else {
            panic!("rtcp_app");
        };
        assert_eq!((from_tag.as_str(), stream), ("tag-b", RtcpAppStream::Audio));
        assert_eq!(
            datagram(a.rtcp_socket(), SHORT).await.as_deref(),
            Some(&from_b[..])
        );

        // RTP is still relayed by the relay itself.
        let media = rtp(0xA0A0_0001);
        a.rtp
            .send_to(&media, toward_a.remote_rtp)
            .await
            .expect("send rtp");
        assert_eq!(datagram(&b.rtp, SHORT).await.as_deref(), Some(&media[..]));
        assert!(app_events.try_recv().is_err(), "RTP raises no event");
    })
    .await;
}

#[tokio::test]
async fn rtcp_from_an_unsignalled_source_is_neither_reported_nor_relayed() {
    each_shape(async |muxed| {
        let engine = engine_with_dispatcher();
        let _events = engine.register_client(CLIENT);
        let app_events = engine.app_event_receiver(CLIENT).expect("queue");
        let (a, b) = (Party::new(muxed).await, Party::new(muxed).await);
        let (toward_a, _) = call(&engine, &a, &b, true).await;

        // 127.0.0.66 is loopback, but not the address A signalled.
        let attacker = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 66), 0))
            .await
            .expect("bind");
        attacker
            .send_to(&compound(0xBAD0_0001), toward_a.remote_rtcp)
            .await
            .expect("send");
        assert!(datagram(b.rtcp_socket(), NEGATIVE).await.is_none());
        assert!(app_events.try_recv().is_err(), "muxed={muxed}");
    })
    .await;
}

#[tokio::test]
async fn a_plain_call_without_a_floor_stream_keeps_its_rtcp_in_the_relay() {
    each_shape(async |muxed| {
        let engine = engine_with_dispatcher();
        let _events = engine.register_client(CLIENT);
        let app_events = engine.app_event_receiver(CLIENT).expect("queue");
        let (a, b) = (Party::new(muxed).await, Party::new(muxed).await);
        let (toward_a, _) = call(&engine, &a, &b, false).await;
        assert!(!engine.media().rtcp_relays().has_call(CALL));

        let from_a = compound(0xA0A0_0001);
        a.rtcp_socket()
            .send_to(&from_a, toward_a.remote_rtcp)
            .await
            .expect("send");
        assert_eq!(
            datagram(b.rtcp_socket(), SHORT).await.as_deref(),
            Some(&from_a[..]),
            "still relayed, muxed={muxed}"
        );
        assert!(
            app_events.try_recv().is_err(),
            "and not shown to the engine (the documented behaviour of a call with no floor)"
        );
    })
    .await;
}

#[tokio::test]
async fn deleting_a_floor_call_removes_its_rtcp_relay() {
    each_shape(async |muxed| {
        let engine = engine_with_dispatcher();
        let _events = engine.register_client(CLIENT);
        let (a, b) = (Party::new(muxed).await, Party::new(muxed).await);
        call(&engine, &a, &b, true).await;
        assert!(engine.media().rtcp_relays().has_call(CALL));

        let deleted = engine
            .handle(
                CLIENT,
                Command::Delete {
                    call_id: CALL.into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await;
        assert!(matches!(deleted, CmdResult::Ok { .. }), "{deleted:?}");
        assert!(!engine.media().rtcp_relays().has_call(CALL));
        assert_eq!(
            engine.media().rtcp_relays().call_count(),
            0,
            "muxed={muxed}"
        );
    })
    .await;
}
