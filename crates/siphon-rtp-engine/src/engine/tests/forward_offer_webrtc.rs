//! A browser as a pre-arranged member of a forwarding room: `forward_offer` with a WebRTC profile,
//! the browser answering, then `forward_answer`. The browser is the in-process peer of
//! `webrtc_floor_channel` (DTLS + SCTP + DCEP over a loopback socket); this time it answers the
//! engine's offer instead of offering to it, so the engine is the DTLS-SRTP/ICE offerer.

use super::webrtc_floor_channel::{
    browser_offer, engine_with_dispatcher, next_app, send_floor, Browser, Order, FLOOR_REQUEST,
    NEGATIVE, ROOM,
};
use super::*;
use siphon_rtp_dtls::{DataChannelEvent, DtlsCertificate, DtlsRole};
use siphon_rtp_proto::ForwardMedia;

const FLOOR_FMTP: &str = "mc_queueing;mc_priority=5;mc_granted";

fn webrtc_profile(with_floor: bool) -> ProfileFlags {
    ProfileFlags {
        transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
        floor_fmtp: with_floor.then(|| FLOOR_FMTP.to_string()),
        ..Default::default()
    }
}

async fn offer_browser(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    profile: ProfileFlags,
    media: ForwardMedia,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                media,
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                profile,
            },
        )
        .await
}

async fn answer_browser(engine: &Engine<UdpLoopbackDatapath>, tag: &str, sdp: String) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardAnswer {
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                sdp,
                received_from: None,
            },
        )
        .await
}

fn refusal(result: &CmdResult) -> &str {
    match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A browser that has set the engine's offer as its remote description and answers it with `setup`.
struct Answering {
    socket: Arc<UdpSocket>,
    certificate: DtlsCertificate,
    engine: SocketAddr,
    fingerprint: sdp::Fingerprint,
    answer: String,
}

/// Offer a browser seat and write its answer (same shape as a Chrome answer: audio and the data
/// channel bundled, `setup` as the DTLS role). Nothing is sent to the engine yet.
async fn browser_answering(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    setup: &str,
    with_channel: bool,
) -> Answering {
    let offer = ok_sdp_text(
        &offer_browser(engine, tag, webrtc_profile(true), ForwardMedia::Translate).await,
    );
    let parsed = sdp::parse(&offer).expect("the engine's own offer parses");
    let socket = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind"),
    );
    let certificate = DtlsCertificate::generate().expect("browser certificate");
    let answer = browser_offer(
        socket.local_addr().expect("addr"),
        &certificate,
        setup,
        with_channel,
    );
    Answering {
        socket,
        certificate,
        engine: parsed.remote_rtp,
        fingerprint: parsed.fingerprint.expect("the offer's fingerprint"),
        answer,
    }
}

impl Answering {
    fn start(self, role: DtlsRole) -> Browser {
        Browser::start(
            self.socket,
            self.engine,
            self.certificate,
            &self.fingerprint,
            role,
        )
    }
}

#[tokio::test]
async fn the_offer_is_a_webrtc_offer_with_the_floor_on_a_data_channel() {
    let engine = engine_with_dispatcher();
    let offer = ok_sdp_text(
        &offer_browser(&engine, "a", webrtc_profile(true), ForwardMedia::Translate).await,
    );
    let lines: Vec<&str> = offer.split("\r\n").collect();
    let port = lines
        .iter()
        .find(|line| line.starts_with("m=audio "))
        .and_then(|line| line.split(' ').nth(1))
        .expect("audio port");
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("m=audio ") && line.contains("UDP/TLS/RTP/SAVPF")),
        "{offer}"
    );
    for expected in [
        "a=ice-lite",
        "a=group:BUNDLE 0 1",
        "a=setup:actpass",
        "a=rtcp-mux",
        "a=sctp-port:5000",
        "a=end-of-candidates",
    ] {
        assert!(lines.contains(&expected), "{expected} in {offer}");
    }
    assert!(
        lines.contains(&format!("m=application {port} UDP/DTLS/SCTP webrtc-datachannel").as_str()),
        "the channel rides the audio port: {offer}"
    );
    assert!(
        !offer.contains("MCPTT") && !offer.contains("a=crypto"),
        "the UDP floor section is replaced, not added to: {offer}"
    );
    // Our own parser reads it, with the engine's certificate in it and a candidate on the audio port.
    let info = sdp::parse(&offer).expect("parse");
    assert!(info.dtls && info.is_ice() && info.ice_lite && info.fingerprint.is_some());
    assert!(
        info.candidates
            .iter()
            .any(|candidate| candidate.address.port().to_string() == port),
        "{offer}"
    );
    assert_eq!(engine.pending_seat_count(), 1);
}

#[tokio::test]
async fn an_audio_only_webrtc_offer_has_no_data_channel() {
    let engine = engine_with_dispatcher();
    let offer = ok_sdp_text(
        &offer_browser(&engine, "a", webrtc_profile(false), ForwardMedia::Translate).await,
    );
    assert!(!offer.contains("m=application"), "{offer}");
    assert!(offer.contains("a=group:BUNDLE 0\r\n"), "{offer}");
}

async fn floor_round_trip(setup: &str, browser_role: DtlsRole) {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let answering = browser_answering(&engine, "a", setup, true).await;
    let answer = answering.answer.clone();
    let browser = answering.start(browser_role);
    let answered = answer_browser(&engine, "a", answer).await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    assert_eq!(engine.pending_seat_count(), 0);

    browser
        .expect(|event| matches!(event, DataChannelEvent::Connected))
        .await;
    browser.order(Order::Open("mcptt-floor"));
    browser
        .expect(|event| matches!(event, DataChannelEvent::ChannelOpened { .. }))
        .await;
    browser.order(Order::Binary(FLOOR_REQUEST.to_vec()));
    let Event::RtcpApp {
        conference_id,
        from_tag,
        subtype,
        ..
    } = next_app(&app_events).await
    else {
        panic!("an rtcp_app event");
    };
    assert_eq!(
        (conference_id.as_deref(), from_tag.as_str(), subtype),
        (Some(ROOM), "a", 0)
    );
    assert!(matches!(
        send_floor(&engine, "a", Some(0x5566_7788)).await,
        CmdResult::Ok { .. }
    ));
    browser
        .expect(|event| matches!(event, DataChannelEvent::Message { binary: true, .. }))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_active_answer_makes_the_engine_the_dtls_server_and_floor_control_runs() {
    floor_round_trip("active", DtlsRole::Client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_passive_answer_makes_the_engine_the_dtls_client_and_floor_control_runs() {
    floor_round_trip("passive", DtlsRole::Server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leaving_frees_the_offered_seats_association() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let answering = browser_answering(&engine, "a", "active", true).await;
    let answer = answering.answer.clone();
    let browser = answering.start(DtlsRole::Client);
    assert!(matches!(
        answer_browser(&engine, "a", answer).await,
        CmdResult::Ok { .. }
    ));
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
    assert!(engine.endpoint_calls.is_empty(), "every endpoint was freed");
}

#[tokio::test]
async fn an_answer_that_declines_the_channel_seats_an_audio_only_member() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let answering = browser_answering(&engine, "a", "active", true).await;
    // RFC 8841 §5 / RFC 3264 §6: a section is declined with port 0.
    let declined = answering
        .answer
        .split("\r\n")
        .map(|line| {
            if line.starts_with("m=application ") {
                "m=application 0 UDP/DTLS/SCTP webrtc-datachannel"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n");
    assert!(matches!(
        answer_browser(&engine, "a", declined).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(engine.conference().forward().seat_count(), 1);
    assert_eq!(engine.dtls_bridge().floor_channel_count(), 0);
}

#[tokio::test]
async fn a_plain_answer_to_a_webrtc_offer_is_refused_and_frees_the_seat() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let _offer = browser_answering(&engine, "a", "active", true).await;
    let (_phone, address) = phone().await;
    let plain = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = address.ip(),
        port = address.port(),
    );
    let refused = answer_browser(&engine, "a", plain).await;
    assert!(
        refusal(&refused).contains("UDP/TLS/RTP/SAVPF"),
        "{refused:?}"
    );
    assert_eq!(engine.pending_seat_count(), 0);
    assert_eq!(engine.conference().forward().seat_count(), 0);
    assert!(engine.endpoint_calls.is_empty());
}

#[tokio::test]
async fn a_dtls_answer_to_a_plain_offer_is_refused_and_frees_the_seat() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let offered = offer_browser(
        &engine,
        "a",
        ProfileFlags::default(),
        ForwardMedia::Translate,
    )
    .await;
    assert!(!ok_sdp_text(&offered).contains("UDP/TLS"));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let certificate = DtlsCertificate::generate().expect("certificate");
    let answer = browser_offer(
        socket.local_addr().expect("addr"),
        &certificate,
        "active",
        false,
    );
    let refused = answer_browser(&engine, "a", answer).await;
    assert!(
        refusal(&refused).contains("offer was RTP/AVP"),
        "{refused:?}"
    );
    assert_eq!(engine.pending_seat_count(), 0);
}

#[tokio::test]
async fn an_answer_without_a_fingerprint_or_a_dtls_role_is_refused_and_frees_the_seat() {
    for (mutate, why) in [
        (
            (|answer: String| {
                answer
                    .lines()
                    .filter(|line| !line.starts_with("a=fingerprint:"))
                    .collect::<Vec<_>>()
                    .join("\r\n")
                    + "\r\n"
            }) as fn(String) -> String,
            "a=fingerprint",
        ),
        (
            |answer: String| answer.replace("a=setup:active", "a=setup:actpass"),
            "a=setup",
        ),
    ] {
        let engine = engine_with_dispatcher();
        let _events = engine.register_client(CLIENT);
        let answering = browser_answering(&engine, "a", "active", true).await;
        let refused = answer_browser(&engine, "a", mutate(answering.answer.clone())).await;
        assert!(refusal(&refused).contains(why), "{why}: {refused:?}");
        assert_eq!(engine.pending_seat_count(), 0);
        assert_eq!(engine.conference().forward().seat_count(), 0);
        assert!(engine.endpoint_calls.is_empty());
    }
}

#[tokio::test]
async fn a_webrtc_offer_on_a_preserve_room_is_refused_before_anything_is_allocated() {
    let engine = engine_with_dispatcher();
    let refused = offer_browser(&engine, "a", webrtc_profile(true), ForwardMedia::Preserve).await;
    assert!(refusal(&refused).contains("preserve room"), "{refused:?}");
    assert_eq!(engine.pending_seat_count(), 0);
}

#[tokio::test]
async fn conference_offer_still_refuses_a_webrtc_profile() {
    let engine = engine_with_dispatcher();
    let refused = engine
        .handle(
            CLIENT,
            Command::ConferenceOffer {
                conference_id: "mixing".into(),
                from_tag: "a".into(),
                role: siphon_rtp_proto::ConferenceRole::default(),
                profile: webrtc_profile(false),
            },
        )
        .await;
    assert!(refusal(&refused).contains("only RTP/AVP"), "{refused:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_with_ice_holds_the_handshake_until_a_check_validates_the_peer() {
    // The offer is ICE-lite: the member's checks, not its `c=` line, decide where media comes from
    // (RFC 8445 §7.3.1.3), and DTLS keys the transport ICE chose (RFC 8445 §12). The in-process
    // browser sends no connectivity check, so its handshake must not complete.
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let answering = browser_answering(&engine, "a", "active", true).await;
    let with_ice = answering.answer.replace(
        "a=setup:active\r\n",
        "a=ice-ufrag:BROW\r\na=ice-pwd:browserpassword0123456789\r\na=setup:active\r\n",
    );
    let browser = answering.start(DtlsRole::Client);
    assert!(matches!(
        answer_browser(&engine, "a", with_ice).await,
        CmdResult::Ok { .. }
    ));
    let connected = tokio::time::timeout(
        NEGATIVE * 3,
        browser.expect(|event| matches!(event, DataChannelEvent::Connected)),
    )
    .await;
    assert!(
        connected.is_err(),
        "no DTLS before a check validated the source"
    );
}
