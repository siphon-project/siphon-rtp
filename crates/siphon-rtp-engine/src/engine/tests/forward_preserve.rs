//! `media: preserve` forwarding rooms end to end on the UDP-loopback datapath, and the controller's
//! `a=key-mgmt` (RFC 4567) passthrough: the talker's RTP and SRTCP leave every other seat byte for
//! byte (3GPP TS 33.180 §7.5.2 NOTE 3), nothing is ever echoed from an offer, and a seat the engine
//! would have to terminate is refused.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_media::rtp::{write_packet, RtpHeader};
use siphon_rtp_proto::ForwardMedia;

const ROOM: &str = "secure-group";
const SHORT: Duration = Duration::from_secs(2);
const QUIET: Duration = Duration::from_millis(400);
const KEY_MGMT: &str = "mikey AQAFgM0XflABAAAAAAAAAAAAAAsAyONQ";

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

/// A PCMU offer on `profile` (`RTP/SAVP` or `RTP/AVP`), optionally with the offerer's own
/// `a=key-mgmt` and `a=crypto`.
fn offer(rtp: SocketAddr, profile: &str, key_mgmt: bool, crypto: bool) -> String {
    let mut text = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} {profile} 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n",
        ip = rtp.ip(),
        port = rtp.port()
    );
    if key_mgmt {
        text.push_str("a=key-mgmt:mikey PEER-OFFERED\r\n");
    }
    if crypto {
        text.push_str("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz\r\n");
    }
    text
}

fn key_mgmt_profile(key_mgmt: Option<&str>) -> ProfileFlags {
    ProfileFlags {
        key_mgmt: key_mgmt.map(str::to_string),
        ..ProfileFlags::default()
    }
}

async fn join(
    engine: &Engine<UdpLoopbackDatapath>,
    media: ForwardMedia,
    tag: &str,
    sdp: String,
    profile: ProfileFlags,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                sdp,
                profile,
                media,
            },
        )
        .await
}

fn reason(result: CmdResult) -> String {
    match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Seat a plain `RTP/SAVP` phone with no `a=crypto` in a preserve room.
async fn seat(engine: &Engine<UdpLoopbackDatapath>, tag: &str) -> (UdpSocket, SocketAddr) {
    let (socket, addr) = phone().await;
    let answer = join(
        engine,
        ForwardMedia::Preserve,
        tag,
        offer(addr, "RTP/SAVP", false, false),
        ProfileFlags::default(),
    )
    .await;
    let text = ok_sdp_text(&answer);
    assert!(
        text.contains("m=audio") && text.contains("RTP/SAVP"),
        "{text}"
    );
    assert!(
        !text.contains("a=crypto"),
        "the engine holds no key: {text}"
    );
    (socket, sdp::parse(&text).expect("answer").remote_rtp)
}

async fn set_source(engine: &Engine<UdpLoopbackDatapath>, tag: &str) {
    let result = engine
        .handle(
            CLIENT,
            Command::ForwardSetSource {
                conference_id: ROOM.into(),
                from_tag: Some(tag.into()),
            },
        )
        .await;
    assert_eq!(result, ok_empty());
}

/// An RTP header followed by bytes an SRTP sender would produce: ciphertext and an auth tag.
fn srtp_datagram(sequence: u16, ssrc: u32) -> Vec<u8> {
    let payload: Vec<u8> = (0..50u8)
        .map(|byte| byte.wrapping_mul(31) ^ (sequence as u8))
        .collect();
    let header = RtpHeader {
        marker: false,
        payload_type: 0,
        sequence,
        timestamp: u32::from(sequence) * 160,
        ssrc,
    };
    let mut buffer = vec![0u8; 12 + payload.len()];
    write_packet(&header, &payload, &mut buffer).expect("write");
    buffer
}

/// A sender-report-shaped datagram whose body is not RTCP (SRTCP is encrypted).
fn srtcp_datagram(ssrc: u32) -> Vec<u8> {
    let mut datagram = vec![0x80, 200, 0x00, 0x0C];
    datagram.extend_from_slice(&ssrc.to_be_bytes());
    datagram.extend((0..44u8).map(|byte| byte.wrapping_mul(17) ^ 0x3C));
    datagram
}

/// Every datagram `phone` receives within `window`.
async fn drain(phone: &UdpSocket, window: Duration) -> Vec<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + window;
    let mut buffer = [0u8; 2048];
    let mut heard = Vec::new();
    while let Ok(Ok((length, _))) =
        tokio::time::timeout_at(deadline, phone.recv_from(&mut buffer)).await
    {
        heard.push(buffer[..length].to_vec());
    }
    heard
}

async fn expect(phone: &UdpSocket, count: usize) -> Vec<Vec<u8>> {
    let mut heard = Vec::new();
    let mut buffer = [0u8; 2048];
    while heard.len() < count {
        let (length, _) = tokio::time::timeout(SHORT, phone.recv_from(&mut buffer))
            .await
            .expect("a forwarded datagram")
            .expect("recv");
        heard.push(buffer[..length].to_vec());
    }
    heard
}

fn started(events: &flume::Receiver<Event>) -> Vec<String> {
    events
        .try_iter()
        .filter_map(|event| match event {
            Event::ForwardSourceStarted { from_tag, .. } => Some(from_tag),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn the_talkers_srtp_reaches_the_other_seats_byte_identical_and_a_switch_keeps_each_ssrc() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let (phone_a, port_a) = seat(&engine, "a").await;
    let (phone_b, port_b) = seat(&engine, "b").await;
    let (phone_c, _) = seat(&engine, "c").await;

    set_source(&engine, "a").await;
    let from_a: Vec<Vec<u8>> = (1..=3).map(|n| srtp_datagram(n, 0xA0A0_A0A0)).collect();
    for datagram in &from_a {
        phone_a.send_to(datagram, port_a).await.expect("send");
    }
    assert_eq!(
        expect(&phone_b, 3).await,
        from_a,
        "seat b: SSRC, seq, ts, payload, tag"
    );
    assert_eq!(expect(&phone_c, 3).await, from_a, "seat c");

    set_source(&engine, "b").await;
    let from_b: Vec<Vec<u8>> = (500..=502).map(|n| srtp_datagram(n, 0xB0B0_B0B0)).collect();
    for datagram in &from_b {
        phone_b.send_to(datagram, port_b).await.expect("send");
    }
    assert_eq!(
        expect(&phone_a, 3).await,
        from_b,
        "seat a hears b's own SSRC"
    );
    assert_eq!(
        expect(&phone_c, 3).await,
        from_b,
        "seat c hears b's own SSRC"
    );
    assert_eq!(started(&events), vec!["a".to_string(), "b".to_string()]);
    assert!(
        drain(&phone_b, QUIET).await.is_empty(),
        "the source never hears itself"
    );
}

#[tokio::test]
async fn the_talkers_srtcp_is_forwarded_the_receivers_is_dropped_and_the_engine_sends_no_report() {
    let engine = engine_with_dispatcher();
    let (phone_a, port_a) = seat(&engine, "a").await;
    let (phone_b, port_b) = seat(&engine, "b").await;
    let (phone_c, _) = seat(&engine, "c").await;
    set_source(&engine, "a").await;

    let report = srtcp_datagram(0xA0A0_A0A0);
    let media = srtp_datagram(1, 0xA0A0_A0A0);
    phone_a.send_to(&report, port_a).await.expect("send");
    phone_a.send_to(&media, port_a).await.expect("send");
    // A receiver's own SRTCP must not reach anyone.
    phone_b
        .send_to(&srtcp_datagram(0xB0B0_B0B0), port_b)
        .await
        .expect("send");

    // Exactly the talker's two datagrams, in order, and nothing else (no SR, RR or BYE from the
    // engine, not even the one a translating room sends at start) within the window.
    for phone in [&phone_b, &phone_c] {
        let heard = drain(phone, Duration::from_millis(800)).await;
        assert_eq!(heard, vec![report.clone(), media.clone()]);
    }
    assert!(
        drain(&phone_a, QUIET).await.is_empty(),
        "the receiver's SRTCP was not relayed to the talker, and the engine sent it nothing"
    );
}

#[tokio::test]
async fn a_dtls_seat_is_refused_in_a_preserve_room() {
    let engine = engine_with_dispatcher();
    let (_, addr) = phone().await;
    let dtls = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\n\
         a=fingerprint:sha-256 {fingerprint}\r\na=setup:actpass\r\n",
        ip = addr.ip(),
        port = addr.port(),
        fingerprint = ["AB"; 32].join(":"),
    );
    let refused = reason(
        join(
            &engine,
            ForwardMedia::Preserve,
            "w",
            dtls,
            ProfileFlags::default(),
        )
        .await,
    );
    assert!(
        refused.contains("DTLS-SRTP") && refused.contains("preserve"),
        "{refused}"
    );
    assert_eq!(engine.conference().forward().seat_count(), 0);
    assert!(engine.endpoint_calls.is_empty(), "nothing was allocated");
}

#[tokio::test]
async fn a_seat_offering_crypto_is_refused_in_a_preserve_room() {
    let engine = engine_with_dispatcher();
    let (_, addr) = phone().await;
    let refused = reason(
        join(
            &engine,
            ForwardMedia::Preserve,
            "s",
            offer(addr, "RTP/SAVP", false, true),
            ProfileFlags::default(),
        )
        .await,
    );
    assert!(
        refused.contains("a=crypto") && refused.contains("must not terminate"),
        "{refused}"
    );
    assert_eq!(engine.conference().forward().seat_count(), 0);
    assert!(engine.endpoint_calls.is_empty(), "nothing was allocated");
}

#[tokio::test]
async fn a_plain_seat_in_a_preserve_room_is_answered_on_its_own_transport() {
    let engine = engine_with_dispatcher();
    let (_, addr) = phone().await;
    let answer = join(
        &engine,
        ForwardMedia::Preserve,
        "p",
        offer(addr, "RTP/AVP", false, false),
        ProfileFlags::default(),
    )
    .await;
    assert!(ok_sdp_text(&answer).contains("RTP/AVP 0"));
}

#[tokio::test]
async fn a_second_codec_or_payload_type_is_refused_in_a_preserve_room() {
    let engine = engine_with_dispatcher();
    let (_a, _) = seat(&engine, "a").await;
    let (_, addr) = phone().await;
    let pcma = offer(addr, "RTP/SAVP", false, false)
        .replace(" 0\r\na=rtpmap:0 PCMU/8000", " 8\r\na=rtpmap:8 PCMA/8000");
    let refused = reason(
        join(
            &engine,
            ForwardMedia::Preserve,
            "b",
            pcma,
            ProfileFlags::default(),
        )
        .await,
    );
    assert!(
        refused.contains("preserve rooms forward the talker's packets unchanged"),
        "{refused}"
    );
    let dynamic = offer(addr, "RTP/SAVP", false, false).replace(
        " 0\r\na=rtpmap:0 PCMU/8000",
        " 100\r\na=rtpmap:100 PCMU/8000",
    );
    let refused = reason(
        join(
            &engine,
            ForwardMedia::Preserve,
            "c",
            dynamic,
            ProfileFlags::default(),
        )
        .await,
    );
    assert!(refused.contains("payload type 100"), "{refused}");
    assert_eq!(engine.conference().forward().seat_count(), 1);
}

#[tokio::test]
async fn the_first_seat_fixes_the_media_mode_both_ways() {
    let engine = engine_with_dispatcher();
    let (_, addr) = phone().await;
    let (_a, _) = seat(&engine, "a").await;
    let refused = reason(
        join(
            &engine,
            ForwardMedia::Translate,
            "t",
            offer(addr, "RTP/AVP", false, false),
            ProfileFlags::default(),
        )
        .await,
    );
    assert!(
        refused.contains("media: preserve") && refused.contains("media: translate"),
        "{refused}"
    );
    let offered = reason(
        engine
            .handle(
                CLIENT,
                Command::ForwardOffer {
                    conference_id: ROOM.into(),
                    from_tag: "o".into(),
                    profile: ProfileFlags::default(),
                    media: ForwardMedia::Translate,
                },
            )
            .await,
    );
    assert!(offered.contains("media: preserve"), "{offered}");

    let other = Engine::new(UdpLoopbackDatapath::new());
    let result = join(
        &other,
        ForwardMedia::Translate,
        "a",
        offer(addr, "RTP/AVP", false, false),
        ProfileFlags::default(),
    )
    .await;
    assert!(matches!(result, CmdResult::Ok { .. }));
    let refused = reason(
        join(
            &other,
            ForwardMedia::Preserve,
            "b",
            offer(addr, "RTP/SAVP", false, false),
            ProfileFlags::default(),
        )
        .await,
    );
    assert!(refused.contains("media: translate"), "{refused}");
}

fn key_mgmt_lines(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .filter(|line| line.starts_with("a=key-mgmt:"))
        .collect()
}

#[tokio::test]
async fn a_forward_join_answer_never_echoes_the_offerers_key_mgmt_and_carries_the_controllers() {
    for media in [ForwardMedia::Preserve, ForwardMedia::Translate] {
        let profile = if media == ForwardMedia::Preserve {
            "RTP/SAVP"
        } else {
            "RTP/AVP"
        };
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_, addr) = phone().await;
        let without = join(
            &engine,
            media,
            "a",
            offer(addr, profile, true, false),
            key_mgmt_profile(None),
        )
        .await;
        assert!(
            key_mgmt_lines(&ok_sdp_text(&without)).is_empty(),
            "{without:?}"
        );
        let (_, addr) = phone().await;
        let with = join(
            &engine,
            media,
            "b",
            offer(addr, profile, true, false),
            key_mgmt_profile(Some(KEY_MGMT)),
        )
        .await;
        assert_eq!(
            key_mgmt_lines(&ok_sdp_text(&with)),
            vec![format!("a=key-mgmt:{KEY_MGMT}").as_str()]
        );
    }
}

#[tokio::test]
async fn key_mgmt_is_refused_in_a_translate_room_on_join_and_offer_allocating_nothing() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_, addr) = phone().await;
    let refused = reason(
        join(
            &engine,
            ForwardMedia::Translate,
            "a",
            offer(addr, "RTP/AVP", false, false),
            key_mgmt_profile(Some(KEY_MGMT)),
        )
        .await,
    );
    assert!(refused.contains("\"media\": \"preserve\""), "{refused}");
    let offered = reason(
        engine
            .handle(
                CLIENT,
                Command::ForwardOffer {
                    conference_id: ROOM.into(),
                    from_tag: "o".into(),
                    profile: key_mgmt_profile(Some(KEY_MGMT)),
                    media: ForwardMedia::Translate,
                },
            )
            .await,
    );
    assert!(offered.contains("\"media\": \"preserve\""), "{offered}");
    assert_eq!(engine.conference().forward().seat_count(), 0);
    assert_eq!(engine.pending_seat_count(), 0);
    assert!(engine.endpoint_calls.is_empty(), "nothing was allocated");
}

#[tokio::test]
async fn a_forward_offer_carries_the_controllers_key_mgmt_and_a_preserve_offer_is_savp() {
    let engine = engine_with_dispatcher();
    let offered = engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                conference_id: ROOM.into(),
                from_tag: "o".into(),
                profile: key_mgmt_profile(Some(KEY_MGMT)),
                media: ForwardMedia::Preserve,
            },
        )
        .await;
    let text = ok_sdp_text(&offered);
    assert_eq!(
        key_mgmt_lines(&text),
        vec![format!("a=key-mgmt:{KEY_MGMT}").as_str()]
    );
    let media_line = text
        .lines()
        .find(|line| line.starts_with("m=audio"))
        .expect("m=audio");
    assert!(media_line.contains("RTP/SAVP"), "{media_line}");
    assert!(!text.contains("a=crypto"));

    // The member answers on the same transport with no key of the engine's to answer.
    let (_, addr) = phone().await;
    let answer = offer(addr, "RTP/SAVP", false, false);
    let result = engine
        .handle(
            CLIENT,
            Command::ForwardAnswer {
                conference_id: ROOM.into(),
                from_tag: "o".into(),
                sdp: answer,
                received_from: None,
            },
        )
        .await;
    assert_eq!(result, ok_empty());
    assert_eq!(engine.conference().forward().seat_count(), 1);
}

#[tokio::test]
async fn a_preserve_offer_refuses_an_answer_that_would_make_the_engine_terminate_media() {
    let engine = engine_with_dispatcher();
    for (profile, crypto) in [("RTP/SAVP", true), ("RTP/AVP", false)] {
        engine
            .handle(
                CLIENT,
                Command::ForwardOffer {
                    conference_id: ROOM.into(),
                    from_tag: "o".into(),
                    profile: key_mgmt_profile(Some(KEY_MGMT)),
                    media: ForwardMedia::Preserve,
                },
            )
            .await;
        let (_, addr) = phone().await;
        let result = engine
            .handle(
                CLIENT,
                Command::ForwardAnswer {
                    conference_id: ROOM.into(),
                    from_tag: "o".into(),
                    sdp: offer(addr, profile, false, crypto),
                    received_from: None,
                },
            )
            .await;
        assert!(
            matches!(result, CmdResult::Error { .. }),
            "{profile} crypto={crypto}"
        );
    }
    assert_eq!(engine.conference().forward().seat_count(), 0);
}

#[tokio::test]
async fn a_plain_forward_offer_without_key_mgmt_carries_none() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let offered = engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                conference_id: ROOM.into(),
                from_tag: "o".into(),
                profile: ProfileFlags::default(),
                media: ForwardMedia::Translate,
            },
        )
        .await;
    let text = ok_sdp_text(&offered);
    assert!(key_mgmt_lines(&text).is_empty());
    assert!(text.contains("RTP/AVP"));
}

#[tokio::test]
async fn a_two_party_offer_and_answer_never_echo_key_mgmt_and_carry_the_controllers() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_, addr_a) = phone().await;
    let (_, addr_b) = phone().await;
    for (call_id, profile, expected) in [
        ("call-none", key_mgmt_profile(None), vec![]),
        (
            "call-own",
            key_mgmt_profile(Some(KEY_MGMT)),
            vec![format!("a=key-mgmt:{KEY_MGMT}")],
        ),
    ] {
        let offered = engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: call_id.into(),
                    from_tag: "ft".into(),
                    sdp: offer(addr_a, "RTP/AVP", true, false),
                    profile: profile.clone(),
                },
            )
            .await;
        let text = ok_sdp_text(&offered);
        assert_eq!(
            key_mgmt_lines(&text),
            expected.iter().map(String::as_str).collect::<Vec<_>>(),
            "offer to the far side"
        );
        let answered = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: call_id.into(),
                    from_tag: "ft".into(),
                    to_tag: "tt".into(),
                    sdp: offer(addr_b, "RTP/AVP", true, false),
                    profile,
                },
            )
            .await;
        let text = ok_sdp_text(&answered);
        assert_eq!(
            key_mgmt_lines(&text),
            expected.iter().map(String::as_str).collect::<Vec<_>>(),
            "answer to the caller"
        );
    }
}

#[tokio::test]
async fn a_locally_answered_call_never_echoes_key_mgmt() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_, addr) = phone().await;
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "local".into(),
                from_tag: "ft".into(),
                sdp: offer(addr, "RTP/AVP", true, false),
                profile: key_mgmt_profile(Some(KEY_MGMT)),
            },
        )
        .await;
    assert_eq!(
        key_mgmt_lines(&ok_sdp_text(&answered)),
        vec![format!("a=key-mgmt:{KEY_MGMT}").as_str()]
    );
}
