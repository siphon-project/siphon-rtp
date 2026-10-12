//! Offer/answer on a call whose offer lists several audio codecs and both telephone-event clock
//! rates, as a VoLTE terminal's does (GSMA IR.92 §3.2): what the far side is offered under each
//! codec directive, which codec the offerer is answered, and which telephone-event payload type
//! comes back with it.
//!
//! The SDP the engine emits is read here line by line, never through `sdp::parse`: the engine's own
//! reader agreeing with its own writer says nothing about either.

use super::*;

/// The audio formats of a terminal's offer, by payload type: `a=rtpmap` encoding and `a=fmtp`
/// parameters. EVS is one the engine relays and cannot decode.
const TERMINAL_FORMATS: [(u8, &str, &str); 5] = [
    (110, "EVS/16000", "br=5.9-24.4;bw=nb-swb;max-red=220"),
    (104, "AMR-WB/16000", "mode-change-capability=2;max-red=220"),
    (102, "AMR/8000", "mode-change-capability=2;max-red=220"),
    (105, "telephone-event/16000", "0-15"),
    (100, "telephone-event/8000", "0-15"),
];

/// The full offer of the known-answer case: EVS first, then AMR-WB and AMR, then both events.
const EVS_FIRST: [u8; 5] = [110, 104, 102, 105, 100];

/// The same terminal with EVS switched off.
const AMR_WB_FIRST: [u8; 4] = [104, 102, 105, 100];

/// A terminal's offer from `rtp`, listing `payload_types` in that order.
fn terminal_offer(rtp: SocketAddr, payload_types: &[u8]) -> String {
    let formats: Vec<String> = payload_types.iter().map(u8::to_string).collect();
    let mut offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {formats}\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
        formats = formats.join(" "),
    );
    for payload_type in payload_types {
        let (_, encoding, parameters) = TERMINAL_FORMATS
            .iter()
            .find(|(number, _, _)| number == payload_type)
            .expect("a format of the terminal");
        offer.push_str(&format!(
            "a=rtpmap:{payload_type} {encoding}\r\na=fmtp:{payload_type} {parameters}\r\n"
        ));
    }
    offer.push_str("a=ptime:20\r\na=maxptime:240\r\na=sendrecv\r\na=rtcp-mux\r\n");
    offer
}

/// A G.711 gateway's answer from `rtp`: A-law and telephone-event at its 8 kHz clock.
fn gateway_answer(rtp: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 2 2 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
    )
}

/// `offer` on `engine` with the codec directives `flags`; the result is what the far side is sent.
async fn offer_with(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    sdp: String,
    flags: &[&str],
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                sdp,
                profile: ProfileFlags {
                    flags: flags.iter().map(|flag| (*flag).to_string()).collect(),
                    ..Default::default()
                },
            },
        )
        .await
}

/// `answer` on `engine`; the result is what the offerer is sent.
async fn answer_with(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    sdp: String,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp,
                profile: Default::default(),
            },
        )
        .await
}

/// The format list of the `m=audio` line (RFC 4566 §5.14), read off the text.
fn audio_formats(sdp: &str) -> String {
    let media = sdp
        .lines()
        .find(|line| line.starts_with("m=audio "))
        .expect("an m=audio line");
    media.splitn(4, ' ').nth(3).unwrap_or_default().to_string()
}

/// Every `a=rtpmap` value of the body, in the order written.
fn rtpmaps(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .filter_map(|line| line.strip_prefix("a=rtpmap:"))
        .collect()
}

/// The payload types an `a=fmtp` line is written for, in the order written.
fn fmtp_payload_types(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .filter_map(|line| line.strip_prefix("a=fmtp:"))
        .filter_map(|value| value.split(' ').next())
        .collect()
}

/// The codec directives of a profile that masks the terminal's codecs and transcodes to G.711.
#[cfg(feature = "amr")]
const MASK_TERMINAL_CODECS: [&str; 5] = [
    "codec-mask-EVS",
    "codec-mask-AMR-WB",
    "codec-mask-AMR",
    "codec-transcode-PCMA",
    "codec-transcode-PCMU",
];

/// The known-answer case. A terminal offers EVS, AMR-WB and AMR with telephone-event at both clock
/// rates; the profile masks all three and transcodes to G.711; the far side answers A-law. The far
/// side is offered G.711 and nothing it was masked from, and the terminal is answered AMR-WB, the
/// first codec of its offer the engine can transcode, with the telephone-event payload type it
/// offered at AMR-WB's clock rate (RFC 4733 §2.1) under the rtpmap it gave it (RFC 3264 §6.1).
#[cfg(feature = "amr")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_masked_offer_led_by_an_undecodable_codec_is_answered_the_next_one() {
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
    let (terminal, terminal_addr) = phone().await;
    let (gateway, gateway_addr) = phone().await;
    let offered = offer_with(
        &engine,
        "evs-first",
        terminal_offer(terminal_addr, &EVS_FIRST),
        &MASK_TERMINAL_CODECS,
    )
    .await;
    let far_offer = ok_sdp_text(&offered);
    assert_eq!(audio_formats(&far_offer), "8 0 105 100", "{far_offer}");
    assert_eq!(
        rtpmaps(&far_offer),
        [
            "8 PCMA/8000",
            "0 PCMU/8000",
            "105 telephone-event/16000",
            "100 telephone-event/8000"
        ],
        "{far_offer}"
    );
    assert_eq!(
        fmtp_payload_types(&far_offer),
        ["105", "100"],
        "{far_offer}"
    );

    let answered = answer_with(&engine, "evs-first", gateway_answer(gateway_addr)).await;
    let near_answer = ok_sdp_text(&answered);
    assert_eq!(audio_formats(&near_answer), "104 105", "{near_answer}");
    assert_eq!(
        rtpmaps(&near_answer),
        ["104 AMR-WB/16000", "105 telephone-event/16000"],
        "{near_answer}"
    );
    assert!(
        engine.media().is_media_call("evs-first"),
        "the call transcodes"
    );

    // The media path runs what the two bodies say. AMR-WB on the terminal's payload type 104
    // reaches the gateway as A-law, and A-law comes back as payload type 104.
    let near = SocketAddr::new(terminal_addr.ip(), media_port(&near_answer));
    let far = SocketAddr::new(gateway_addr.ip(), media_port(&far_offer));
    let mut speech = amr_wb_rtp(0, 0xAAAA_AAAA);
    speech[1] = 104;
    terminal
        .send_to(&speech, near)
        .await
        .expect("terminal send");
    assert_eq!(received_payload_type(&gateway).await, 8);
    let alaw = g711_rtp(8, 200, 0x0B0B_0B0B, 0x55);
    gateway.send_to(&alaw, far).await.expect("gateway send");
    assert_eq!(received_payload_type(&terminal).await, 104);

    // An event crosses on each side's own payload type: 105 from the terminal leaves as the
    // gateway's 101, and 101 from the gateway as 105. Only the payload type is asserted: the
    // duration field is forwarded as received, in the units of the clock it arrived on.
    terminal
        .send_to(&event_rtp(105, 1), near)
        .await
        .expect("terminal event");
    assert_eq!(received_payload_type(&gateway).await, 101);
    gateway
        .send_to(&event_rtp(101, 201), far)
        .await
        .expect("gateway event");
    assert_eq!(received_payload_type(&terminal).await, 105);
}

/// The payload type of the next RTP packet `socket` receives.
#[cfg(feature = "amr")]
async fn received_payload_type(socket: &UdpSocket) -> u8 {
    let (packet, _) = recv(socket).await;
    siphon_rtp_media::rtp::RtpPacket::parse(&packet)
        .expect("an RTP packet")
        .payload_type
}

/// The other direction: a G.711 gateway offers A-law with telephone-event at 8 kHz, and the
/// profile adds AMR-WB toward a terminal that answers it. The terminal is offered the gateway's
/// formats and then AMR-WB, the gateway is answered its own A-law and event payload type, and
/// audio and events cross both ways. No telephone-event at 16 kHz is put in the far offer: the
/// terminal's events ride the 8 kHz payload type it was offered.
#[cfg(feature = "amr")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_g711_offer_is_bridged_to_a_terminal_that_answers_amr_wb() {
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
    let (gateway, gateway_addr) = phone().await;
    let (terminal, terminal_addr) = phone().await;
    let offered = offer_with(
        &engine,
        "inbound",
        gateway_answer(gateway_addr),
        &["codec-transcode-AMR-WB", "codec-transcode-AMR"],
    )
    .await;
    let far_offer = ok_sdp_text(&offered);
    assert!(
        audio_formats(&far_offer).starts_with("8 101 96"),
        "{far_offer}"
    );
    for mapped in ["96 AMR-WB/16000", "8 PCMA/8000", "101 telephone-event/8000"] {
        assert!(rtpmaps(&far_offer).contains(&mapped), "{far_offer}");
    }

    let terminal_answer = format!(
        "v=0\r\no=- 3 3 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 96 101\r\na=rtpmap:96 AMR-WB/16000\r\n\
         a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\n",
        ip = terminal_addr.ip(),
        port = terminal_addr.port(),
    );
    let answered = answer_with(&engine, "inbound", terminal_answer).await;
    let near_answer = ok_sdp_text(&answered);
    assert_eq!(audio_formats(&near_answer), "8 101", "{near_answer}");
    assert_eq!(
        rtpmaps(&near_answer),
        ["8 PCMA/8000", "101 telephone-event/8000"],
        "{near_answer}"
    );

    let near = SocketAddr::new(gateway_addr.ip(), media_port(&near_answer));
    let far = SocketAddr::new(terminal_addr.ip(), media_port(&far_offer));
    let alaw = g711_rtp(8, 200, 0x0B0B_0B0B, 0x55);
    gateway.send_to(&alaw, near).await.expect("gateway send");
    assert_eq!(received_payload_type(&terminal).await, 96);
    let speech = amr_wb_rtp(0, 0xAAAA_AAAA);
    terminal.send_to(&speech, far).await.expect("terminal send");
    assert_eq!(received_payload_type(&gateway).await, 8);
    gateway
        .send_to(&event_rtp(101, 201), near)
        .await
        .expect("gateway event");
    assert_eq!(received_payload_type(&terminal).await, 101);
    terminal
        .send_to(&event_rtp(101, 1), far)
        .await
        .expect("terminal event");
    assert_eq!(received_payload_type(&gateway).await, 101);
}

/// The last packet of an RFC 4733 event for digit 5 (end bit set, 1600 timestamp units long) on
/// `payload_type`.
#[cfg(feature = "amr")]
fn event_rtp(payload_type: u8, sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 0x80 | payload_type];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0x40, 0, 0x0C, 0x0C, 0x0C, 0x0C]);
    packet.extend_from_slice(&[5, 0x8A, 0x06, 0x40]);
    packet
}

/// The same offer with only `codec-transcode`: nothing is removed, the far side still answers a
/// codec the terminal never offered, and the terminal is still answered AMR-WB instead of having
/// the answer refused over the EVS it listed first.
#[cfg(feature = "amr")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unmasked_offer_led_by_an_undecodable_codec_is_answered_the_next_one() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_terminal, terminal_addr) = phone().await;
    let (_gateway, gateway_addr) = phone().await;
    let offered = offer_with(
        &engine,
        "evs-kept",
        terminal_offer(terminal_addr, &EVS_FIRST),
        &["codec-transcode-PCMA", "codec-transcode-PCMU"],
    )
    .await;
    assert_eq!(
        audio_formats(&ok_sdp_text(&offered)),
        "110 104 102 105 100 8 0"
    );
    let answered = answer_with(&engine, "evs-kept", gateway_answer(gateway_addr)).await;
    let near_answer = ok_sdp_text(&answered);
    assert_eq!(audio_formats(&near_answer), "104 105", "{near_answer}");
    assert_eq!(
        rtpmaps(&near_answer),
        ["104 AMR-WB/16000", "105 telephone-event/16000"],
        "{near_answer}"
    );
}

/// AMR-WB first, which was answered before and still is, now with its own telephone-event rate.
#[cfg(feature = "amr")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_masked_offer_led_by_amr_wb_is_answered_amr_wb() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_terminal, terminal_addr) = phone().await;
    let (_gateway, gateway_addr) = phone().await;
    let offered = offer_with(
        &engine,
        "wb-first",
        terminal_offer(terminal_addr, &AMR_WB_FIRST),
        &MASK_TERMINAL_CODECS,
    )
    .await;
    assert_eq!(audio_formats(&ok_sdp_text(&offered)), "8 0 105 100");
    let answered = answer_with(&engine, "wb-first", gateway_answer(gateway_addr)).await;
    let near_answer = ok_sdp_text(&answered);
    assert_eq!(
        rtpmaps(&near_answer),
        ["104 AMR-WB/16000", "105 telephone-event/16000"],
        "{near_answer}"
    );
    assert!(engine.media().is_media_call("wb-first"));
}

/// An offer whose selected codec runs at 8 kHz is answered the telephone-event payload type it
/// offered at 8 kHz, not the first one it listed.
#[cfg(feature = "amr")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_narrowband_leg_is_answered_the_narrowband_telephone_event() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_terminal, terminal_addr) = phone().await;
    let (_gateway, gateway_addr) = phone().await;
    offer_with(
        &engine,
        "nb-first",
        terminal_offer(terminal_addr, &[102, 105, 100]),
        &["codec-mask-AMR", "codec-transcode-PCMA"],
    )
    .await;
    let answered = answer_with(&engine, "nb-first", gateway_answer(gateway_addr)).await;
    let near_answer = ok_sdp_text(&answered);
    assert_eq!(audio_formats(&near_answer), "102 100", "{near_answer}");
    assert_eq!(
        rtpmaps(&near_answer),
        ["102 AMR/8000", "100 telephone-event/8000"],
        "{near_answer}"
    );
}

/// An offer with no telephone-event at the selected codec's clock rate keeps the one it has, under
/// the rtpmap it was offered with: a 16 kHz event stays a 16 kHz event next to G.711.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_telephone_event_keeps_the_clock_rate_it_was_offered_at() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_caller, caller_addr) = phone().await;
    let (_gateway, gateway_addr) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0 105\r\na=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:105 telephone-event/16000\r\n",
        ip = caller_addr.ip(),
        port = caller_addr.port(),
    );
    offer_with(
        &engine,
        "odd-rate",
        offer,
        &["codec-mask-PCMU", "codec-transcode-PCMA"],
    )
    .await;
    let answered = answer_with(&engine, "odd-rate", gateway_answer(gateway_addr)).await;
    assert_eq!(
        rtpmaps(&ok_sdp_text(&answered)),
        ["0 PCMU/8000", "105 telephone-event/16000"]
    );
}

/// The clock rate of the selected event payload type survives a failover: the standby restores
/// it from the snapshot, where a snapshot written without it reads as the 8 kHz it was presented
/// at then.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restored_call_keeps_the_clock_rate_of_its_telephone_event() {
    let (min, max) = (46_400u16, 46_440u16);
    let bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let active = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
    let (_caller, caller_addr) = phone().await;
    let (_gateway, gateway_addr) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0 105\r\na=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:105 telephone-event/16000\r\na=rtcp-mux\r\n",
        ip = caller_addr.ip(),
        port = caller_addr.port(),
    );
    let flags = ["codec-mask-PCMU", "codec-transcode-PCMA"];
    offer_with(&active, "failover", offer, &flags).await;
    let answered = answer_with(&active, "failover", gateway_answer(gateway_addr)).await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    let CmdResult::Checkpoint { snapshot } = active
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "failover".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await
    else {
        panic!("expected a checkpoint result");
    };
    active
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "failover".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    drop(active);

    let standby = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
    let restored = standby.handle(CLIENT, Command::Restore { snapshot }).await;
    assert!(matches!(restored, CmdResult::Ok { .. }), "{restored:?}");
    let wideband_event = sdp::TelephoneEvent {
        payload_type: 105,
        clock_rate_hz: 16_000,
    };
    assert_eq!(
        standby
            .calls
            .get("failover")
            .expect("restored")
            .near_telephone_event,
        Some(wideband_event)
    );
}

/// EVS alone toward a far side that answers G.711: nothing in the offer can be transcoded, so the
/// answer is refused, and the refusal names the offered codec and the answered one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offer_with_nothing_to_transcode_is_refused_naming_both_codecs() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_terminal, terminal_addr) = phone().await;
    let (_gateway, gateway_addr) = phone().await;
    let offered = offer_with(
        &engine,
        "evs-only",
        terminal_offer(terminal_addr, &[110, 105]),
        &["codec-transcode-PCMA"],
    )
    .await;
    assert_eq!(audio_formats(&ok_sdp_text(&offered)), "110 105 8");
    let answered = answer_with(&engine, "evs-only", gateway_answer(gateway_addr)).await;
    let CmdResult::Error { reason } = &answered else {
        panic!("an answer the engine cannot bridge is refused, got {answered:?}");
    };
    assert!(
        reason.contains("EVS/16000") && reason.contains("PCMA/8000"),
        "the refusal names the offered and the answered codec: {reason}"
    );
    assert!(
        reason.contains("EVS transcoding is not implemented"),
        "and keeps the reason the codec gave: {reason}"
    );
}

/// EVS alone toward a far side that answers EVS is a relay: no codec is run, so none is needed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undecodable_codec_both_sides_share_is_relayed() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_terminal, terminal_addr) = phone().await;
    let (_peer, peer_addr) = phone().await;
    offer_with(
        &engine,
        "evs-relay",
        terminal_offer(terminal_addr, &[110, 105]),
        &["codec-transcode-PCMA"],
    )
    .await;
    let answered = answer_with(&engine, "evs-relay", terminal_offer(peer_addr, &[110, 105])).await;
    assert_eq!(audio_formats(&ok_sdp_text(&answered)), "110 105");
    assert!(!engine.media().is_media_call("evs-relay"));
}

/// The far offer under each codec directive, for an offer of `payload_types`: every row of the
/// table is a profile that removes the terminal's codecs and transcodes to G.711, and the first
/// codec of the offer is removed like the others. The last two rows are the rule that used to keep
/// it: with nothing to put in its place, the first codec stays (RFC 4566 §5.14 needs a format).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_codec_directive_removes_the_first_offered_codec_like_any_other() {
    const TRANSCODE: [&str; 2] = ["codec-transcode-PCMA", "codec-transcode-PCMU"];
    let rows: [(&[&str], &[u8], &str); 9] = [
        (&[], &AMR_WB_FIRST, "104 102 105 100 8 0"),
        (
            &["codec-mask-EVS", "codec-mask-AMR-WB", "codec-mask-AMR"],
            &AMR_WB_FIRST,
            "8 0 105 100",
        ),
        (&["codec-mask-all"], &AMR_WB_FIRST, "8 0 105 100"),
        (&["codec-strip-all"], &AMR_WB_FIRST, "8 0 105 100"),
        (
            &[
                "codec-offer-PCMA",
                "codec-offer-PCMU",
                "codec-offer-telephone-event",
            ],
            &AMR_WB_FIRST,
            "8 0 105 100",
        ),
        (
            &[
                "codec-consume-EVS",
                "codec-consume-AMR-WB",
                "codec-consume-AMR",
            ],
            &AMR_WB_FIRST,
            "8 0 105 100",
        ),
        (
            &["codec-strip-EVS", "codec-mask-AMR-WB", "codec-mask-AMR"],
            &EVS_FIRST,
            "8 0 105 100",
        ),
        (&["codec-strip-EVS"], &EVS_FIRST, "104 102 105 100 8 0"),
        (&["codec-mask-AMR-WB"], &EVS_FIRST, "110 102 105 100 8 0"),
    ];
    let mut wrong: Vec<String> = Vec::new();
    for (index, (removal, payload_types, expected)) in rows.into_iter().enumerate() {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_terminal, terminal_addr) = phone().await;
        let flags: Vec<&str> = removal.iter().chain(TRANSCODE.iter()).copied().collect();
        let call_id = format!("row-{index}");
        let offered = offer_with(
            &engine,
            &call_id,
            terminal_offer(terminal_addr, payload_types),
            &flags,
        )
        .await;
        let far_offer = ok_sdp_text(&offered);
        if audio_formats(&far_offer) != expected {
            wrong.push(format!(
                "{removal:?} on {payload_types:?}: offered {}, expected {expected}",
                audio_formats(&far_offer)
            ));
            continue;
        }
        // A removed format takes its attributes with it; a kept or added one has its rtpmap.
        let mut listed: Vec<&str> = expected.split(' ').collect();
        for payload_type in fmtp_payload_types(&far_offer) {
            assert!(
                listed.contains(&payload_type),
                "{flags:?}: a=fmtp left for removed payload type {payload_type}: {far_offer}"
            );
        }
        let mut mapped: Vec<&str> = rtpmaps(&far_offer)
            .into_iter()
            .filter_map(|value| value.split(' ').next())
            .collect();
        listed.sort_unstable();
        mapped.sort_unstable();
        assert_eq!(mapped, listed, "{flags:?}: {far_offer}");
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));

    // Without a transcode target there is nothing to offer in the first codec's place.
    for flags in [
        &["codec-mask-all"][..],
        &["codec-strip-AMR-WB", "codec-strip-AMR"][..],
    ] {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_terminal, terminal_addr) = phone().await;
        let offered = offer_with(
            &engine,
            "kept",
            terminal_offer(terminal_addr, &AMR_WB_FIRST),
            flags,
        )
        .await;
        assert_eq!(
            audio_formats(&ok_sdp_text(&offered)),
            "104 105 100",
            "{flags:?}"
        );
    }
}

/// Removing the first codec with nothing to transcode to is not a request to transcode. EVS is
/// stripped, masked or consumed, the far side is offered the rest and answers AMR-WB, which the
/// terminal offered too: a relay on AMR-WB, with no codec run and the answer passed through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_the_first_codec_alone_leaves_a_relay_on_the_answered_one() {
    for directive in ["codec-strip-EVS", "codec-mask-EVS", "codec-consume-EVS"] {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let (_terminal, terminal_addr) = phone().await;
        let (_peer, peer_addr) = phone().await;
        let offer = terminal_offer(terminal_addr, &EVS_FIRST);
        let offered = offer_with(&engine, "removed", offer, &[directive]).await;
        let far_offer = ok_sdp_text(&offered);
        assert_eq!(audio_formats(&far_offer), "104 102 105 100", "{directive}");
        assert!(!far_offer.contains("EVS"), "{directive}: {far_offer}");

        let answer = terminal_offer(peer_addr, &[104, 105]);
        let answered = answer_with(&engine, "removed", answer.clone()).await;
        let near_answer = ok_sdp_text(&answered);
        assert_eq!(
            near_answer,
            with_media_port(&answer, peer_addr.port(), media_port(&near_answer)),
            "{directive}: the answer is relayed as received"
        );
        assert!(!engine.media().is_media_call("removed"), "{directive}");
    }
}

/// `codec-strip` of a first codec the engine does run is the same plain removal: the offerer
/// follows the far side's answer and the call is a relay. `codec-mask` of it is the request to
/// hold the offerer there and transcode
/// (`codec_mask_still_holds_the_near_leg_on_the_masked_codec`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stripping_the_first_codec_does_not_hold_the_offerer_on_it() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_caller, caller_addr) = phone().await;
    let (_callee, callee_addr) = phone().await;
    let offered = offer_with(
        &engine,
        "stripped",
        sdp_for(caller_addr, true),
        &["codec-strip-PCMU"],
    )
    .await;
    assert_eq!(audio_formats(&ok_sdp_text(&offered)), "8");
    let answered = answer_with(
        &engine,
        "stripped",
        sdp_single_codec(callee_addr, 8, "PCMA"),
    )
    .await;
    assert_eq!(audio_formats(&ok_sdp_text(&answered)), "8");
    assert!(!engine.media().is_media_call("stripped"));
}

/// A `codec-offer` whitelist that names every codec only reorders the format list. The far side
/// answers the codec now first and the call is a relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_whitelist_that_only_reorders_leaves_a_relay() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_terminal, terminal_addr) = phone().await;
    let (_peer, peer_addr) = phone().await;
    let offered = offer_with(
        &engine,
        "reordered",
        terminal_offer(terminal_addr, &EVS_FIRST),
        &[
            "codec-offer-AMR-WB",
            "codec-offer-AMR",
            "codec-offer-telephone-event",
            "codec-offer-EVS",
        ],
    )
    .await;
    assert_eq!(audio_formats(&ok_sdp_text(&offered)), "104 102 105 100 110");
    let answered = answer_with(&engine, "reordered", terminal_offer(peer_addr, &[104, 105])).await;
    assert_eq!(audio_formats(&ok_sdp_text(&answered)), "104 105");
    assert!(!engine.media().is_media_call("reordered"));
}

/// A far side that knows AMR-WB itself is not offered it once it is masked, and when it then
/// answers G.711 the terminal stays on AMR-WB.
#[cfg(feature = "amr")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_masked_codec_is_not_offered_to_a_far_side_that_supports_it() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_terminal, terminal_addr) = phone().await;
    let (_peer, peer_addr) = phone().await;
    let offered = offer_with(
        &engine,
        "masked-wb",
        terminal_offer(terminal_addr, &AMR_WB_FIRST),
        &[
            "codec-mask-AMR-WB",
            "codec-mask-AMR",
            "codec-transcode-PCMA",
        ],
    )
    .await;
    let far_offer = ok_sdp_text(&offered);
    assert_eq!(audio_formats(&far_offer), "8 105 100", "{far_offer}");
    assert!(!far_offer.contains("AMR"), "{far_offer}");
    let answered = answer_with(&engine, "masked-wb", gateway_answer(peer_addr)).await;
    assert_eq!(audio_formats(&ok_sdp_text(&answered)), "104 105");
}

/// The path that never transcodes: no codec directive, EVS first, and a far side that answers EVS.
/// Both bodies are the input with the engine's own address and port in place of the party's, byte
/// for byte. Recorded before any of the changes above, so they hold what the relay did then.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relayed_offer_led_by_an_undecodable_codec_is_passed_through_unchanged() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_terminal, terminal_addr) = phone().await;
    let (_peer, peer_addr) = phone().await;
    let offer = terminal_offer(terminal_addr, &EVS_FIRST);
    let offered = offer_with(&engine, "relay", offer.clone(), &[]).await;
    let far_offer = ok_sdp_text(&offered);
    assert_eq!(
        far_offer,
        with_media_port(&offer, terminal_addr.port(), media_port(&far_offer)),
        "the far offer is the offer on the engine's port"
    );

    let answer = terminal_offer(peer_addr, &[110, 105]);
    let answered = answer_with(&engine, "relay", answer.clone()).await;
    let near_answer = ok_sdp_text(&answered);
    assert_eq!(
        near_answer,
        with_media_port(&answer, peer_addr.port(), media_port(&near_answer)),
        "the answer is the answer on the engine's port"
    );
    assert!(!engine.media().is_media_call("relay"));
}

/// The port of the `m=audio` line, read off the text.
fn media_port(sdp: &str) -> u16 {
    sdp.lines()
        .find_map(|line| line.strip_prefix("m=audio "))
        .and_then(|rest| rest.split(' ').next())
        .and_then(|port| port.parse().ok())
        .expect("an m=audio port")
}

/// `sdp` with the port of its `m=audio` line changed from `from` to `to`.
fn with_media_port(sdp: &str, from: u16, to: u16) -> String {
    sdp.replace(&format!("m=audio {from} "), &format!("m=audio {to} "))
}

/// The selection on its own, with codecs every build has: G.723.1 is one the engine only relays.
#[test]
fn the_near_codec_is_the_first_offered_one_the_engine_can_bridge() {
    let g723 = CodecSpec::new(4, "G723", 8000, 1, 20);
    let g722 = CodecSpec::new(9, "G722", 8000, 1, 20);
    let pcmu = CodecSpec::new(0, "PCMU", 8000, 1, 20);
    let pcma = CodecSpec::new(8, "PCMA", 8000, 1, 20);
    let offered = [g723.clone(), g722.clone(), pcmu.clone()];
    let select = |answered: &CodecSpec, withheld: bool| {
        negotiated_near_codec(&offered, Some(g723.clone()), Some(answered), withheld)
    };
    // B answered a codec A never offered: the first of A's the engine runs, in A's order.
    assert_eq!(select(&pcma, false), Ok(Some(g722.clone())));
    assert_eq!(select(&pcma, true), Ok(Some(g722.clone())));
    // A's first codec was withheld and cannot be held: B's pick from A's own offer is a relay when
    // nothing A prefers to it can be bridged, and the transcode A prefers when something can.
    assert_eq!(select(&g722, true), Ok(Some(g722.clone())));
    assert_eq!(select(&pcmu, true), Ok(Some(g722)));
    // A codec both sides share is never held to what the engine can build.
    assert_eq!(select(&g723, true), Ok(Some(g723.clone())));

    // Nothing to fall back on: refused, naming A's codec, B's, and the codec's own reason.
    let refused = negotiated_near_codec(
        std::slice::from_ref(&g723),
        Some(g723.clone()),
        Some(&pcma),
        false,
    )
    .expect_err("nothing offered can be bridged");
    assert!(
        refused.starts_with(
            "none of the offered codecs, G723/8000 (payload type 4) first, can be transcoded to \
             the answered PCMA/8000 (payload type 8): G723/8000 (payload type 4): unsupported: \
             G.723.1 transcoding is not implemented"
        ),
        "{refused}"
    );
    // And the other way round: an answered codec the engine cannot build bridges to nothing.
    let unbuildable_answer = negotiated_near_codec(
        std::slice::from_ref(&pcmu),
        Some(pcmu.clone()),
        Some(&g723),
        false,
    );
    assert!(unbuildable_answer.is_err(), "{unbuildable_answer:?}");
}
