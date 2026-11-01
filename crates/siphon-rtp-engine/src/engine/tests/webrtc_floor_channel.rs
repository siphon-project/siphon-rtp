//! MCPTT floor control over a WebRTC data channel (docs/control/json.md), end to end on the
//! UDP-loopback datapath. The browser is an in-process peer: a DTLS session (`rtc-dtls`) with an SCTP
//! association (`rtc-sctp`) and DCEP (`rtc-datachannel`) on top, speaking to the engine over a real
//! socket. The engine's DTLS driver, its SCTP association and the room are the production ones.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use bytes::Bytes;
use siphon_rtp_dtls::{
    DataChannelEvent, DataChannelHost, DtlsCertificate, DtlsEvent, DtlsRole, DtlsSession,
};
use siphon_rtp_media::rtcp;
use siphon_rtp_proto::RtcpAppStream;
use std::time::Instant;

pub(super) const ROOM: &str = "browser-group";
pub(super) const SHORT: Duration = Duration::from_secs(5);
pub(super) const NEGATIVE: Duration = Duration::from_millis(300);

/// TS 24.380 §8.2.4 Floor Request: SSRC 0x11223344, name MCPT, subtype 0.
pub(super) const FLOOR_REQUEST: [u8; 16] = [
    0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05, 0x00,
];
const FLOOR_GRANTED_PAYLOAD: [u8; 12] = [
    0x01, 0x02, 0x00, 0x1E, 0x0E, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
];

pub(super) fn engine_with_dispatcher() -> Engine<UdpLoopbackDatapath> {
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

fn fingerprint_line(certificate: &DtlsCertificate) -> String {
    let fingerprint = certificate.fingerprint();
    let hex = fingerprint
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    format!("a=fingerprint:{} {hex}\r\n", fingerprint.hash_function)
}

/// A Chrome-shaped offer: audio and a data channel in one BUNDLE group, DTLS on both.
pub(super) fn browser_offer(
    address: SocketAddr,
    certificate: &DtlsCertificate,
    setup: &str,
    with_channel: bool,
) -> String {
    let fingerprint = fingerprint_line(certificate);
    let mut text = format!(
        "v=0\r\no=- 4611731400430051336 2 IN IP4 {ip}\r\ns=-\r\nt=0 0\r\n\
         a=group:BUNDLE 0 1\r\n\
         m=audio {port} UDP/TLS/RTP/SAVPF 0\r\nc=IN IP4 {ip}\r\n\
         a=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\na=mid:0\r\na=setup:{setup}\r\n{fingerprint}",
        ip = address.ip(),
        port = address.port(),
    );
    if with_channel {
        text.push_str(&format!(
            "m=application {port} UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 {ip}\r\n\
             a=mid:1\r\na=sctp-port:5000\r\na=max-message-size:262144\r\n\
             a=setup:{setup}\r\n{fingerprint}",
            ip = address.ip(),
            port = address.port(),
        ));
    }
    text
}

async fn join(engine: &Engine<UdpLoopbackDatapath>, tag: &str, offer: String) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: siphon_rtp_proto::ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                sdp: offer,
                profile: ProfileFlags::default(),
            },
        )
        .await
}

pub(super) enum Order {
    Open(&'static str),
    Binary(Vec<u8>),
    Text(&'static str),
}

/// The in-process browser: DTLS + SCTP + DCEP over `socket`, driven by [`Order`]s, reporting what the
/// SCTP side saw.
pub(super) struct Browser {
    orders: flume::Sender<Order>,
    events: flume::Receiver<DataChannelEvent>,
    task: tokio::task::JoinHandle<()>,
}

impl Browser {
    pub(super) fn start(
        socket: Arc<UdpSocket>,
        engine: SocketAddr,
        certificate: DtlsCertificate,
        engine_fingerprint: &sdp::Fingerprint,
        role: DtlsRole,
    ) -> Self {
        let expected = siphon_rtp_dtls::Fingerprint::new(
            engine_fingerprint.hash_function.clone(),
            engine_fingerprint.bytes.clone(),
        );
        let (orders, order_queue) = flume::unbounded();
        let (event_sink, events) = flume::unbounded();
        let task = tokio::spawn(async move {
            let mut session =
                DtlsSession::new(&certificate, role, expected, Duration::from_millis(200))
                    .expect("browser session");
            let mut host = DataChannelHost::new(role);
            let mut stream = 0u16;
            session.start(Instant::now()).expect("first flight");
            let mut buffer = [0u8; 2048];
            loop {
                while let Some(record) = session.poll_transmit() {
                    socket.send_to(&record, engine).await.expect("browser send");
                }
                let now = Instant::now();
                while let Some(packet) = host.poll_transmit(now) {
                    session
                        .write_application_data(now, &packet)
                        .expect("browser writes SCTP");
                    while let Some(record) = session.poll_transmit() {
                        socket.send_to(&record, engine).await.expect("browser send");
                    }
                }
                let deadline = [session.poll_timeout(), host.poll_timeout()]
                    .into_iter()
                    .flatten()
                    .min();
                let wait = deadline.map_or(Duration::from_secs(3600), |at| {
                    at.saturating_duration_since(Instant::now())
                });
                tokio::select! {
                    received = socket.recv_from(&mut buffer) => {
                        let Ok((length, _)) = received else { return };
                        // RFC 7983 §7: a DTLS record.
                        if !(20..=63).contains(&buffer[0]) {
                            continue;
                        }
                        let Ok(events) = session.handle_datagram(Instant::now(), &buffer[..length]) else {
                            return;
                        };
                        for event in events {
                            match event {
                                DtlsEvent::Keyed => host.start(Instant::now()).expect("SCTP starts"),
                                DtlsEvent::ApplicationData(data) => {
                                    for event in host.handle_packet(Instant::now(), &data) {
                                        let _ = event_sink.send(event);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    order = order_queue.recv_async() => {
                        let Ok(order) = order else { return };
                        let now = Instant::now();
                        match order {
                            Order::Open(label) => {
                                stream = host.open_channel(now, label).expect("open channel");
                            }
                            Order::Binary(data) => {
                                host.send(now, stream, true, &Bytes::from(data)).expect("send binary");
                            }
                            Order::Text(text) => {
                                host.send(now, stream, false, &Bytes::from(text)).expect("send text");
                            }
                        }
                    }
                    () = tokio::time::sleep(wait) => {
                        let now = Instant::now();
                        let _ = session.handle_timeout(now);
                        for event in host.handle_timeout(now) {
                            let _ = event_sink.send(event);
                        }
                    }
                }
            }
        });
        Self {
            orders,
            events,
            task,
        }
    }

    /// Wait for an SCTP event satisfying `wanted`, skipping the others.
    pub(super) async fn expect(
        &self,
        wanted: impl Fn(&DataChannelEvent) -> bool,
    ) -> DataChannelEvent {
        let deadline = tokio::time::Instant::now() + SHORT;
        loop {
            let event = tokio::time::timeout_at(deadline, self.events.recv_async())
                .await
                .expect("an SCTP event in time")
                .expect("the browser task is alive");
            if wanted(&event) {
                return event;
            }
        }
    }

    pub(super) fn order(&self, order: Order) {
        self.orders.send(order).expect("browser task alive");
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A seated browser: its socket is already pointed at the engine's audio port.
struct Seated {
    browser: Browser,
    answer: String,
}

async fn seat_browser(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    setup: &str,
    role: DtlsRole,
) -> Seated {
    let socket = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind"),
    );
    let address = socket.local_addr().expect("addr");
    let certificate = DtlsCertificate::generate().expect("browser certificate");
    let offer = browser_offer(address, &certificate, setup, true);
    let answer = ok_sdp_text(&join(engine, tag, offer).await);
    let parsed = sdp::parse(&answer).expect("answer");
    let fingerprint = parsed.fingerprint.clone().expect("engine fingerprint");
    let browser = Browser::start(socket, parsed.remote_rtp, certificate, &fingerprint, role);
    Seated { browser, answer }
}

pub(super) async fn send_floor(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    ssrc: Option<u32>,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::SendRtcpApp {
                call_id: None,
                conference_id: Some(ROOM.into()),
                from_tag: Some(tag.into()),
                except_from_tags: vec![],
                stream: RtcpAppStream::Floor,
                ssrc,
                name: "MCPT".into(),
                subtype: 17,
                payload: FLOOR_GRANTED_PAYLOAD.to_vec(),
            },
        )
        .await
}

pub(super) async fn next_app(events: &flume::Receiver<Event>) -> Event {
    tokio::time::timeout(SHORT, events.recv_async())
        .await
        .expect("an rtcp_app event")
        .expect("open queue")
}

/// A browser offer that also carries the stream identity and header extensions a browser signals
/// (RFC 5576 `a=ssrc`, RFC 8830 `a=msid`, RFC 8285 `a=extmap`).
fn identity_laden_browser_offer(address: SocketAddr, certificate: &DtlsCertificate) -> String {
    use super::stream_identity::OFFERER_SSRC;
    browser_offer(address, certificate, "active", true)
        .replace(
            "t=0 0\r\n",
            "t=0 0\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS stream-a\r\n",
        )
        .replace(
            "a=mid:0\r\n",
            &format!(
                "a=mid:0\r\na=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\
                 a=msid:stream-a track-a\r\na=ssrc:{OFFERER_SSRC} cname:offerer-cname\r\n"
            ),
        )
}

/// A single-leg `answer_local` answer to the same offer: it echoes none of the browser's identity
/// either, names no SSRC of its own, and keeps what bundling the data channel needs.
#[tokio::test]
async fn a_local_answer_drops_the_browsers_stream_identity_but_keeps_what_the_channel_needs() {
    use super::stream_identity::{assert_nothing_of_the_offerer, signalled_ssrcs};
    let engine = engine_with_dispatcher();
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let address = socket.local_addr().expect("addr");
    let certificate = DtlsCertificate::generate().expect("browser certificate");
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "ivr-identity".into(),
                from_tag: "caller".into(),
                sdp: identity_laden_browser_offer(address, &certificate),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let answer = ok_sdp_text(&answered);
    assert_nothing_of_the_offerer(&answer);
    assert!(!answer.contains("extmap"), "{answer}");
    assert!(signalled_ssrcs(&answer).is_empty(), "{answer}");
    let lines: Vec<&str> = answer.split("\r\n").collect();
    for expected in [
        "a=group:BUNDLE 0 1",
        "a=mid:0",
        "a=mid:1",
        "a=sctp-port:5000",
    ] {
        assert!(lines.contains(&expected), "{expected} in {answer}");
    }
    assert!(
        answer.contains("UDP/DTLS/SCTP webrtc-datachannel") && !answer.contains("m=application 0"),
        "the channel is still answered: {answer}"
    );
}

/// The browser's own stream identity is dropped from the answer in every section, and what bundling
/// the data channel needs (`a=mid`, `a=group:BUNDLE`, `a=sctp-port`, the channel's own port) is not.
#[tokio::test]
async fn the_answer_drops_the_browsers_stream_identity_but_keeps_what_the_channel_needs() {
    use super::stream_identity::{assert_nothing_of_the_offerer, signalled_ssrcs};
    let engine = engine_with_dispatcher();
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let address = socket.local_addr().expect("addr");
    let certificate = DtlsCertificate::generate().expect("browser certificate");
    let offer = identity_laden_browser_offer(address, &certificate);
    let answer = ok_sdp_text(&join(&engine, "a", offer).await);
    assert_nothing_of_the_offerer(&answer);
    assert!(!answer.contains("extmap"), "{answer}");
    assert_eq!(
        signalled_ssrcs(&answer).len(),
        1,
        "only the room's: {answer}"
    );
    let lines: Vec<&str> = answer.split("\r\n").collect();
    for expected in [
        "a=group:BUNDLE 0 1",
        "a=mid:0",
        "a=mid:1",
        "a=sctp-port:5000",
    ] {
        assert!(lines.contains(&expected), "{expected} in {answer}");
    }
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("m=application ") && line.contains("webrtc-datachannel")),
        "the channel is still answered: {answer}"
    );
}

#[tokio::test]
async fn the_answer_carries_the_data_channel_on_the_audio_transport() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let seated = seat_browser(&engine, "a", "active", DtlsRole::Client).await;
    let lines: Vec<&str> = seated.answer.split("\r\n").collect();
    let audio = lines
        .iter()
        .position(|line| line.starts_with("m=audio"))
        .expect("audio");
    let channel = lines
        .iter()
        .position(|line| line.starts_with("m=application"))
        .expect("data channel");
    let audio_port = lines[audio].split(' ').nth(1).expect("port");
    assert_eq!(
        lines[channel],
        format!("m=application {audio_port} UDP/DTLS/SCTP webrtc-datachannel"),
        "same port as the audio it is bundled with (RFC 8843)"
    );
    let section: Vec<&str> = lines[channel..].to_vec();
    for expected in [
        "a=mid:1",
        "a=sctp-port:5000",
        "a=max-message-size:65536",
        "a=setup:passive",
    ] {
        assert!(section.contains(&expected), "{expected} in {section:?}");
    }
    assert!(
        section
            .iter()
            .any(|line| line.starts_with("a=fingerprint:")),
        "{section:?}"
    );
    assert!(
        lines.contains(&"a=group:BUNDLE 0 1"),
        "the group is echoed: {lines:?}"
    );
    // The same fingerprint on both sections: one DTLS association.
    let fingerprints: Vec<&&str> = lines
        .iter()
        .filter(|line| line.starts_with("a=fingerprint:"))
        .collect();
    assert_eq!(fingerprints.len(), 2);
    assert_eq!(fingerprints[0], fingerprints[1]);
}

#[tokio::test]
async fn a_leg_that_is_not_dtls_cannot_have_a_data_channel_and_it_is_declined() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (_phone, address) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0 1\r\n\
         m=audio {port} RTP/AVP 0\r\nc=IN IP4 {ip}\r\na=rtpmap:0 PCMU/8000\r\na=mid:0\r\n\
         m=application {port} UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 {ip}\r\na=mid:1\r\n\
         a=sctp-port:5000\r\n",
        ip = address.ip(),
        port = address.port(),
    );
    let answer = ok_sdp_text(&join(&engine, "plain", offer).await);
    assert!(
        answer.contains("m=application 0 UDP/DTLS/SCTP webrtc-datachannel"),
        "{answer}"
    );
}

#[tokio::test]
async fn a_data_channel_outside_the_bundle_is_declined() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let address = socket.local_addr().expect("addr");
    let certificate = DtlsCertificate::generate().expect("certificate");
    let offer = browser_offer(address, &certificate, "actpass", true)
        .replace("a=group:BUNDLE 0 1", "a=group:BUNDLE 0");
    let answer = ok_sdp_text(&join(&engine, "a", offer).await);
    assert!(
        answer.contains("m=application 0 UDP/DTLS/SCTP webrtc-datachannel"),
        "{answer}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_floor_request_on_the_data_channel_reaches_the_controller_once_and_a_grant_comes_back() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let seated = seat_browser(&engine, "a", "active", DtlsRole::Client).await;
    let browser = &seated.browser;

    // Before the browser opens the channel there is nothing to send on.
    let early = send_floor(&engine, "a", None).await;
    let CmdResult::Error { reason } = early else {
        panic!("expected a refusal, got {early:?}");
    };
    assert!(reason.contains("not open"), "{reason}");

    browser
        .expect(|event| matches!(event, DataChannelEvent::Connected))
        .await;
    browser.order(Order::Open("mcptt-floor"));
    browser
        .expect(|event| matches!(event, DataChannelEvent::ChannelOpened { .. }))
        .await;

    browser.order(Order::Binary(FLOOR_REQUEST.to_vec()));
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
    assert!(
        tokio::time::timeout(NEGATIVE, app_events.recv_async())
            .await
            .is_err(),
        "exactly one event"
    );

    // The grant, with an explicit SSRC, is one binary message, byte for byte the RTCP APP packet.
    assert!(matches!(
        send_floor(&engine, "a", Some(0x5566_7788)).await,
        CmdResult::Ok { .. }
    ));
    let DataChannelEvent::Message {
        binary,
        data,
        stream_id,
    } = browser
        .expect(|event| matches!(event, DataChannelEvent::Message { .. }))
        .await
    else {
        panic!("a message");
    };
    assert!(binary && stream_id == 0);
    let mut expected = vec![
        0x91, 0xCC, 0x00, 0x05, 0x55, 0x66, 0x77, 0x88, 0x4D, 0x43, 0x50, 0x54,
    ];
    expected.extend_from_slice(&FLOOR_GRANTED_PAYLOAD);
    assert_eq!(&data[..], &expected[..]);
    let parsed: Vec<_> = rtcp::app_packets(&data).collect();
    assert_eq!(parsed.len(), 1);

    // Without an SSRC the packet carries the seat's own egress SSRC: still one well-formed packet.
    assert!(matches!(
        send_floor(&engine, "a", None).await,
        CmdResult::Ok { .. }
    ));
    let DataChannelEvent::Message { data, .. } = browser
        .expect(|event| matches!(event, DataChannelEvent::Message { .. }))
        .await
    else {
        panic!("a message");
    };
    let app = rtcp::app_packets(&data)
        .next()
        .expect("one packet")
        .expect("well formed");
    assert_eq!((app.subtype, app.name), (17, *b"MCPT"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_works_when_the_engine_is_the_dtls_client() {
    // An `actpass` offer makes the engine the active DTLS peer (RFC 5763 §5), so the browser is the
    // DTLS server: the opposite role pairing, with the same floor traffic.
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let seated = seat_browser(&engine, "a", "actpass", DtlsRole::Server).await;
    assert!(
        seated.answer.contains("a=setup:active"),
        "{}",
        seated.answer
    );
    let browser = &seated.browser;
    browser
        .expect(|event| matches!(event, DataChannelEvent::Connected))
        .await;
    browser.order(Order::Open("mcptt-floor"));
    browser
        .expect(|event| matches!(event, DataChannelEvent::ChannelOpened { .. }))
        .await;
    browser.order(Order::Binary(FLOOR_REQUEST.to_vec()));
    let Event::RtcpApp { subtype, .. } = next_app(&app_events).await else {
        panic!("rtcp_app");
    };
    assert_eq!(subtype, 0);
    assert!(matches!(
        send_floor(&engine, "a", None).await,
        CmdResult::Ok { .. }
    ));
    browser
        .expect(|event| matches!(event, DataChannelEvent::Message { .. }))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_string_or_malformed_message_raises_no_event_and_a_later_request_still_does() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let seated = seat_browser(&engine, "a", "active", DtlsRole::Client).await;
    let browser = &seated.browser;
    browser
        .expect(|event| matches!(event, DataChannelEvent::Connected))
        .await;
    browser.order(Order::Open("mcptt-floor"));
    browser
        .expect(|event| matches!(event, DataChannelEvent::ChannelOpened { .. }))
        .await;

    browser.order(Order::Text("Floor Request please"));
    browser.order(Order::Binary(FLOOR_REQUEST[..9].to_vec()));
    assert!(
        tokio::time::timeout(NEGATIVE, app_events.recv_async())
            .await
            .is_err(),
        "neither a string nor a truncated packet is an event"
    );
    browser.order(Order::Binary(FLOOR_REQUEST.to_vec()));
    assert!(matches!(next_app(&app_events).await, Event::RtcpApp { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_channel_with_another_label_never_opens_the_floor() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let seated = seat_browser(&engine, "a", "active", DtlsRole::Client).await;
    let browser = &seated.browser;
    browser
        .expect(|event| matches!(event, DataChannelEvent::Connected))
        .await;
    browser.order(Order::Open("chat"));
    browser
        .expect(|event| matches!(event, DataChannelEvent::ChannelOpened { .. }))
        .await;
    browser.order(Order::Binary(FLOOR_REQUEST.to_vec()));
    assert!(
        tokio::time::timeout(NEGATIVE, app_events.recv_async())
            .await
            .is_err(),
        "messages on another channel are ignored"
    );
    let refused = send_floor(&engine, "a", None).await;
    assert!(matches!(refused, CmdResult::Error { .. }), "{refused:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leaving_the_room_frees_the_association_with_the_seat() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let seated = seat_browser(&engine, "a", "active", DtlsRole::Client).await;
    let browser = &seated.browser;
    browser
        .expect(|event| matches!(event, DataChannelEvent::Connected))
        .await;
    browser.order(Order::Open("mcptt-floor"));
    browser
        .expect(|event| matches!(event, DataChannelEvent::ChannelOpened { .. }))
        .await;
    assert_eq!(engine.dtls_bridge().session_count(), 1);
    assert_eq!(engine.dtls_bridge().floor_channel_count(), 1);

    let left = engine
        .handle(
            CLIENT,
            Command::ForwardLeave {
                conference_id: ROOM.into(),
                from_tag: "a".into(),
            },
        )
        .await;
    assert!(matches!(left, CmdResult::Ok { .. }), "{left:?}");
    assert_eq!(engine.dtls_bridge().session_count(), 0, "driver gone");
    assert_eq!(engine.dtls_bridge().floor_channel_count(), 0, "plan gone");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_single_leg_local_answer_carries_floor_control_on_the_data_channel_too() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let socket = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind"),
    );
    let address = socket.local_addr().expect("addr");
    let certificate = DtlsCertificate::generate().expect("browser certificate");
    let offer = browser_offer(address, &certificate, "active", true);
    let answer = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "ivr-1".into(),
                from_tag: "caller".into(),
                sdp: offer,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let answer = ok_sdp_text(&answer);
    assert!(
        answer.contains("UDP/DTLS/SCTP webrtc-datachannel"),
        "{answer}"
    );
    assert!(
        !answer.contains("m=application 0"),
        "answered, not declined: {answer}"
    );
    let parsed = sdp::parse(&answer).expect("answer");
    let fingerprint = parsed.fingerprint.clone().expect("fingerprint");
    let browser = Browser::start(
        socket,
        parsed.remote_rtp,
        certificate,
        &fingerprint,
        DtlsRole::Client,
    );

    browser
        .expect(|event| matches!(event, DataChannelEvent::Connected))
        .await;
    browser.order(Order::Open("mcptt-floor"));
    browser
        .expect(|event| matches!(event, DataChannelEvent::ChannelOpened { .. }))
        .await;
    browser.order(Order::Binary(FLOOR_REQUEST.to_vec()));
    assert_eq!(
        next_app(&app_events).await,
        Event::RtcpApp {
            call_id: Some("ivr-1".into()),
            conference_id: None,
            from_tag: "caller".into(),
            stream: RtcpAppStream::Floor,
            ssrc: 0x1122_3344,
            name: "MCPT".into(),
            subtype: 0,
            payload: vec![0x00, 0x02, 0x05, 0x00],
        }
    );
    let sent = engine
        .handle(
            CLIENT,
            Command::SendRtcpApp {
                call_id: Some("ivr-1".into()),
                conference_id: None,
                from_tag: Some("caller".into()),
                except_from_tags: vec![],
                stream: RtcpAppStream::Floor,
                ssrc: Some(0x5566_7788),
                name: "MCPT".into(),
                subtype: 17,
                payload: FLOOR_GRANTED_PAYLOAD.to_vec(),
            },
        )
        .await;
    assert!(matches!(sent, CmdResult::Ok { .. }), "{sent:?}");
    let DataChannelEvent::Message { data, binary, .. } = browser
        .expect(|event| matches!(event, DataChannelEvent::Message { .. }))
        .await
    else {
        panic!("a message");
    };
    assert!(binary);
    assert_eq!(&data[..4], &[0x91, 0xCC, 0x00, 0x05]);
    assert_eq!(&data[12..], &FLOOR_GRANTED_PAYLOAD);

    // Deleting the call frees the driver, its plan and the send handle.
    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "ivr-1".into(),
                from_tag: "caller".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }), "{deleted:?}");
    assert_eq!(engine.dtls_bridge().session_count(), 0);
    assert_eq!(engine.dtls_bridge().floor_channel_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_two_party_call_answers_a_browsers_data_channel_and_carries_its_floor() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let socket = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind"),
    );
    let address = socket.local_addr().expect("addr");
    let (_callee, callee_address) = phone().await;
    let certificate = DtlsCertificate::generate().expect("browser certificate");

    // A browser calls a plain callee: the engine terminates A's DTLS and the callee is offered plain
    // RTP, with the data channel declined (it is A's to answer, not the callee's).
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dc-call".into(),
                from_tag: "browser".into(),
                sdp: browser_offer(address, &certificate, "active", true),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/AVP".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let to_callee = ok_sdp_text(&offered);
    assert!(
        to_callee.contains("m=application 0 UDP/DTLS/SCTP webrtc-datachannel"),
        "{to_callee}"
    );
    assert!(
        !to_callee.contains("a=group:BUNDLE"),
        "the callee is not told of a bundle: {to_callee}"
    );

    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "dc-call".into(),
                from_tag: "browser".into(),
                to_tag: "callee".into(),
                sdp: sdp_for(callee_address, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let to_browser = ok_sdp_text(&answered);
    let lines: Vec<&str> = to_browser.split("\r\n").collect();
    let audio = lines
        .iter()
        .position(|line| line.starts_with("m=audio"))
        .expect("audio");
    let channel = lines
        .iter()
        .position(|line| line.starts_with("m=application"))
        .expect("data channel");
    let audio_port = lines[audio].split(' ').nth(1).expect("port");
    assert_eq!(
        lines[channel],
        format!("m=application {audio_port} UDP/DTLS/SCTP webrtc-datachannel"),
        "{to_browser}"
    );
    assert!(lines.contains(&"a=group:BUNDLE 0 1"), "{to_browser}");
    assert!(lines[audio..channel].contains(&"a=mid:0"), "{to_browser}");
    assert!(lines[channel..].contains(&"a=mid:1"), "{to_browser}");
    assert!(
        lines[channel..].contains(&"a=sctp-port:5000"),
        "{to_browser}"
    );
    assert!(
        lines[channel..].contains(&"a=max-message-size:65536"),
        "{to_browser}"
    );

    let parsed = sdp::parse(&to_browser).expect("answer");
    let fingerprint = parsed.fingerprint.clone().expect("fingerprint");
    let browser = Browser::start(
        socket,
        parsed.remote_rtp,
        certificate,
        &fingerprint,
        DtlsRole::Client,
    );
    browser
        .expect(|event| matches!(event, DataChannelEvent::Connected))
        .await;
    browser.order(Order::Open("mcptt-floor"));
    browser
        .expect(|event| matches!(event, DataChannelEvent::ChannelOpened { .. }))
        .await;
    browser.order(Order::Binary(FLOOR_REQUEST.to_vec()));
    assert_eq!(
        next_app(&app_events).await,
        Event::RtcpApp {
            call_id: Some("dc-call".into()),
            conference_id: None,
            from_tag: "browser".into(),
            stream: RtcpAppStream::Floor,
            ssrc: 0x1122_3344,
            name: "MCPT".into(),
            subtype: 0,
            payload: vec![0x00, 0x02, 0x05, 0x00],
        }
    );
    let sent = engine
        .handle(
            CLIENT,
            Command::SendRtcpApp {
                call_id: Some("dc-call".into()),
                conference_id: None,
                from_tag: Some("browser".into()),
                except_from_tags: vec![],
                stream: RtcpAppStream::Floor,
                ssrc: Some(0x5566_7788),
                name: "MCPT".into(),
                subtype: 17,
                payload: FLOOR_GRANTED_PAYLOAD.to_vec(),
            },
        )
        .await;
    assert!(matches!(sent, CmdResult::Ok { .. }), "{sent:?}");
    let DataChannelEvent::Message { data, binary, .. } = browser
        .expect(|event| matches!(event, DataChannelEvent::Message { .. }))
        .await
    else {
        panic!("a message");
    };
    assert!(binary);
    assert_eq!(&data[..4], &[0x91, 0xCC, 0x00, 0x05]);
    assert_eq!(&data[12..], &FLOOR_GRANTED_PAYLOAD);

    // The callee has no data channel: floor control toward it is refused, not queued.
    let to_callee = engine
        .handle(
            CLIENT,
            Command::SendRtcpApp {
                call_id: Some("dc-call".into()),
                conference_id: None,
                from_tag: Some("callee".into()),
                except_from_tags: vec![],
                stream: RtcpAppStream::Floor,
                ssrc: Some(1),
                name: "MCPT".into(),
                subtype: 17,
                payload: FLOOR_GRANTED_PAYLOAD.to_vec(),
            },
        )
        .await;
    assert!(
        matches!(to_callee, CmdResult::Error { .. }),
        "{to_callee:?}"
    );

    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "dc-call".into(),
                from_tag: "browser".into(),
                to_tag: Some("callee".into()),
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }), "{deleted:?}");
    assert_eq!(engine.dtls_bridge().session_count(), 0);
    assert_eq!(engine.dtls_bridge().floor_channel_count(), 0);
}

#[tokio::test]
async fn a_dtls_caller_with_an_unbundled_channel_gets_no_floor_channel_and_the_callee_sees_it_declined(
) {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let address = socket.local_addr().expect("addr");
    let (_callee, callee_address) = phone().await;
    let certificate = DtlsCertificate::generate().expect("certificate");
    let offer = browser_offer(address, &certificate, "active", true)
        .replace("a=group:BUNDLE 0 1", "a=group:BUNDLE 0");
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dc-unbundled".into(),
                from_tag: "browser".into(),
                sdp: offer,
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/AVP".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    assert!(
        ok_sdp_text(&offered).contains("m=application 0 UDP/DTLS/SCTP"),
        "never relayed to the callee"
    );
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "dc-unbundled".into(),
                from_tag: "browser".into(),
                to_tag: "callee".into(),
                sdp: sdp_for(callee_address, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    assert_eq!(engine.dtls_bridge().floor_channel_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_with_a_data_channel_floor_is_still_refused_by_checkpoint() {
    // The floor channel rides a DTLS association whose keys come from the handshake, so it cannot
    // move to a standby: the pipeline kind refuses the whole call, floor stream included.
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let socket = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind"),
    );
    let address = socket.local_addr().expect("addr");
    let (_callee, callee_address) = phone().await;
    let certificate = DtlsCertificate::generate().expect("browser certificate");
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dc-ha".into(),
                from_tag: "browser".into(),
                sdp: browser_offer(address, &certificate, "active", true),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/AVP".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "dc-ha".into(),
                from_tag: "browser".into(),
                to_tag: "callee".into(),
                sdp: sdp_for(callee_address, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let result = engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "dc-ha".into(),
                from_tag: "browser".into(),
            },
        )
        .await;
    let CmdResult::Error { reason } = result else {
        panic!("expected a refusal, got {result:?}");
    };
    assert!(reason.contains("DTLS-SRTP"), "{reason}");
}
