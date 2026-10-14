//! `offer_far`: a call the engine answered itself (`answer_local`, a pre-call announcement) grows a far
//! leg, the far party's answer connects the two, and the caller's answer never changes.
//!
//! The SDP the engine emits is read line by line here, and the media is real RTP over the loopback
//! datapath in both directions.

use super::*;

/// The caller's offer: µ-law and A-law, telephone-event at 8 kHz, and EVS, which the engine relays
/// but cannot transcode.
fn caller_offer(rtp: SocketAddr) -> String {
    format!(
        "v=0\r\no=caller 10 10 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0 110 8 101\r\na=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:110 EVS/16000\r\na=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\n\
         a=sendrecv\r\na=rtcp-mux\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
    )
}

/// The far party's answer from `rtp`, selecting `payload_type` / `name` and telephone-event.
fn far_answer(rtp: SocketAddr, payload_type: u8, name: &str) -> String {
    format!(
        "v=0\r\no=callee 20 20 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {payload_type} 101\r\na=rtpmap:{payload_type} {name}/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=sendrecv\r\na=rtcp-mux\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
    )
}

/// An engine with the userspace dispatcher running, so the local pipeline and a transcoder see
/// their packets.
fn engine_with_dispatcher() -> Engine<UdpLoopbackDatapath> {
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
    engine
}

async fn answer_locally(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    rtp: SocketAddr,
) -> String {
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                sdp: caller_offer(rtp),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    ok_sdp_text(&answered)
}

async fn offer_far(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    flags: &[&str],
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::OfferFar {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                profile: ProfileFlags {
                    flags: flags.iter().map(|flag| (*flag).to_string()).collect(),
                    ..Default::default()
                },
            },
        )
        .await
}

async fn answer_far(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    to_tag: &str,
    sdp: String,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                to_tag: to_tag.into(),
                sdp,
                profile: ProfileFlags::default(),
            },
        )
        .await
}

async fn delete(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    to_tag: Option<&str>,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                to_tag: to_tag.map(str::to_string),
            },
        )
        .await
}

async fn play_tone(engine: &Engine<UdpLoopbackDatapath>, call_id: &str) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::PlayMedia {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                source: PlayMediaSource::Blob {
                    data: prompt_blob(1600, 6000),
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: None,
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
        )
        .await
}

/// The first `m=audio` line of `sdp_text`.
fn audio_line(sdp_text: &str) -> &str {
    sdp_text
        .split("\r\n")
        .find(|line| line.starts_with("m=audio "))
        .expect("an m=audio line")
}

fn is_error_containing(result: &CmdResult, token: &str) -> bool {
    matches!(result, CmdResult::Error { reason } if reason.contains(token))
}

/// The next RTP packet `socket` receives with `ssrc`, and where it came from. Anything else (the
/// local pipeline's comfort noise, an RTCP report) is skipped.
async fn next_from_ssrc(socket: &UdpSocket, ssrc: u32) -> (Vec<u8>, SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let mut buffer = [0u8; 2048];
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let (len, from) = timeout(remaining, socket.recv_from(&mut buffer))
            .await
            .expect("a packet with the expected ssrc before the deadline")
            .expect("recv");
        if len >= 12 && buffer[8..12] == ssrc.to_be_bytes() {
            return (buffer[..len].to_vec(), from);
        }
    }
}

/// The next RTP packet `socket` receives that is not RTCP.
async fn next_rtp(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    loop {
        let (packet, from) = recv(socket).await;
        if packet.len() >= 12 && !matches!(packet[1] & 0x7F, 72..=76) {
            return (packet, from);
        }
    }
}

/// Discard what `socket` receives for the next 200 ms, which is bounded even while the local
/// pipeline keeps sending.
async fn drain(socket: &UdpSocket) {
    let mut buffer = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
    while let Ok(Ok(_)) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await {}
}

#[tokio::test]
async fn the_far_offer_leads_with_the_callers_codec_then_its_others_then_transcode_then_events() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_caller, caller_addr) = phone().await;
    let answer = answer_locally(&engine, "of-order", caller_addr).await;
    assert_eq!(
        audio_line(&answer).split(' ').skip(3).collect::<Vec<_>>(),
        ["0", "101"],
        "the caller is answered µ-law: {answer}"
    );
    let near = sdp::parse(&answer).expect("answer").remote_rtp;

    let offered = offer_far(&engine, "of-order", &["codec-transcode-G722"]).await;
    let far_offer = ok_sdp_text(&offered);
    // µ-law first (the caller's), then A-law (the caller's other one the engine can transcode µ-law
    // to), then the G.722 transcode target, then telephone-event. EVS is gone: the engine cannot
    // bridge it to µ-law, so a far party picking it could never be connected.
    assert_eq!(
        audio_line(&far_offer)
            .split(' ')
            .skip(3)
            .collect::<Vec<_>>(),
        ["0", "8", "9", "101"],
        "{far_offer}"
    );
    assert!(!far_offer.contains("EVS"), "{far_offer}");
    assert!(
        far_offer.contains("a=rtpmap:9 G722/8000\r\n"),
        "{far_offer}"
    );
    assert!(
        far_offer.contains("a=rtpmap:101 telephone-event/8000\r\n"),
        "{far_offer}"
    );
    // The far offer advertises a socket of its own, never the caller's or the caller's address.
    let far = sdp::parse(&far_offer).expect("far offer").remote_rtp;
    assert_ne!(far.port(), near.port(), "a far leg of its own");
    assert_ne!(far, caller_addr);
    assert!(!far_offer.contains(&format!("m=audio {} ", caller_addr.port())));
    // The caller's leg is untouched by the offer.
    let near_now = engine
        .calls
        .get("of-order")
        .map(|call| call.near.rtp.local_addr.port())
        .expect("call");
    assert_eq!(near_now, near.port());
    assert!(
        engine.media().is_media_call("of-order"),
        "the local pipeline keeps running until the far party answers"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_party_on_the_callers_codec_is_relayed_both_ways_and_the_caller_keeps_its_answer() {
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let (callee, callee_addr) = phone().await;
    let answer = answer_locally(&engine, "of-relay", caller_addr).await;
    let near = sdp::parse(&answer).expect("answer").remote_rtp;

    // The announcement plays while the far party is being dialled.
    assert!(matches!(
        play_tone(&engine, "of-relay").await,
        CmdResult::Ok { .. }
    ));
    let far = sdp::parse(&ok_sdp_text(&offer_far(&engine, "of-relay", &[]).await))
        .expect("far offer")
        .remote_rtp;
    let (_, from) = next_rtp(&caller).await;
    assert_eq!(from, near, "the caller still hears the local pipeline");

    let completed = answer_far(
        &engine,
        "of-relay",
        "tag-b",
        far_answer(callee_addr, 0, "PCMU"),
    )
    .await;
    assert_eq!(
        ok_sdp_text(&completed),
        answer,
        "the caller is given back the very answer it already holds, byte for byte"
    );
    assert!(
        matches!(&completed, CmdResult::Ok { to_tag: Some(tag), .. } if tag == "tag-b"),
        "{completed:?}"
    );
    assert!(
        !engine.media().is_media_call("of-relay"),
        "one codec on both sides: the call leaves the userspace pipeline for a plain relay"
    );

    // Caller to callee, out of the far leg, untouched.
    let from_caller = g711_rtp(0, 1, 0x0A0A_0A0A, 0x21);
    caller
        .send_to(&from_caller, near)
        .await
        .expect("caller send");
    let (relayed, from) = next_from_ssrc(&callee, 0x0A0A_0A0A).await;
    assert_eq!(from, far, "the callee hears the far leg");
    assert_eq!(relayed, from_caller, "relayed verbatim");

    // Callee to caller, out of the caller's own unchanged port.
    let from_callee = g711_rtp(0, 1, 0x0B0B_0B0B, 0x42);
    callee
        .send_to(&from_callee, far)
        .await
        .expect("callee send");
    let (relayed, from) = next_from_ssrc(&caller, 0x0B0B_0B0B).await;
    assert_eq!(
        from, near,
        "the caller hears its own engine port, as it was answered"
    );
    assert_eq!(relayed, from_callee);

    let near_now = engine
        .calls
        .get("of-relay")
        .map(|call| call.near.rtp.local_addr)
        .expect("call");
    assert_eq!(near_now, near, "the caller's socket never moved");
    assert!(matches!(
        delete(&engine, "of-relay", None).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(engine.session_count(), 0);
    assert_eq!(engine.endpoint_calls.len(), 0, "every endpoint released");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_party_on_another_codec_is_transcoded_and_the_caller_stays_on_its_own() {
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let (callee, callee_addr) = phone().await;
    let answer = answer_locally(&engine, "of-transcode", caller_addr).await;
    let near = sdp::parse(&answer).expect("answer").remote_rtp;
    let far = sdp::parse(&ok_sdp_text(&offer_far(&engine, "of-transcode", &[]).await))
        .expect("far offer")
        .remote_rtp;

    // The callee picks A-law, the caller's second codec, while the caller was answered µ-law.
    let completed = answer_far(
        &engine,
        "of-transcode",
        "tag-b",
        far_answer(callee_addr, 8, "PCMA"),
    )
    .await;
    assert_eq!(
        ok_sdp_text(&completed),
        answer,
        "the caller's answer stands"
    );
    assert!(
        engine.media().is_transcoding_call("of-transcode"),
        "µ-law to A-law runs through the transcoder"
    );
    drain(&caller).await;

    caller
        .send_to(&g711_rtp(0, 1, 0x0A0A_0A0A, 0x21), near)
        .await
        .expect("caller send");
    let (packet, from) = next_rtp(&callee).await;
    assert_eq!(from, far);
    let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&packet).expect("rtp");
    assert_eq!(parsed.payload_type, 8, "the callee hears A-law");
    assert_eq!(parsed.payload.len(), 160);

    callee
        .send_to(&g711_rtp(8, 1, 0x0B0B_0B0B, 0x42), far)
        .await
        .expect("callee send");
    let (packet, from) = next_rtp(&caller).await;
    assert_eq!(from, near, "out of the caller's unchanged port");
    let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&packet).expect("rtp");
    assert_eq!(
        parsed.payload_type, 0,
        "the caller hears the µ-law it was answered with"
    );
    assert_eq!(parsed.payload.len(), 160);
    assert!(matches!(
        delete(&engine, "of-transcode", None).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(engine.endpoint_calls.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_the_far_leg_puts_the_caller_back_on_the_local_pipeline() {
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let (callee, callee_addr) = phone().await;
    let answer = answer_locally(&engine, "of-retry", caller_addr).await;
    let near = sdp::parse(&answer).expect("answer").remote_rtp;
    let near_endpoints = engine.endpoint_calls.len();

    // The callee refuses: the controller drops the far leg with the callee's tag.
    assert!(matches!(
        offer_far(&engine, "of-retry", &[]).await,
        CmdResult::Ok { .. }
    ));
    assert!(engine.endpoint_calls.len() > near_endpoints);
    assert!(matches!(
        delete(&engine, "of-retry", Some("busy-callee")).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(engine.session_count(), 1, "the call itself lives on");
    assert_eq!(
        engine.endpoint_calls.len(),
        near_endpoints,
        "the far ports are released"
    );
    // Another prompt plays to the caller, from the same port.
    assert!(matches!(
        play_tone(&engine, "of-retry").await,
        CmdResult::Ok { .. }
    ));
    drain(&caller).await;
    let (_, from) = next_rtp(&caller).await;
    assert_eq!(from, near);

    // A second dial: a fresh far offer, answered, then the far party hangs up.
    assert!(matches!(
        offer_far(&engine, "of-retry", &[]).await,
        CmdResult::Ok { .. }
    ));
    let completed = answer_far(
        &engine,
        "of-retry",
        "tag-b2",
        far_answer(callee_addr, 0, "PCMU"),
    )
    .await;
    assert_eq!(ok_sdp_text(&completed), answer);
    assert!(is_error_containing(
        &delete(&engine, "of-retry", Some("someone-else")).await,
        "names no far leg"
    ));
    assert!(matches!(
        delete(&engine, "of-retry", Some("tag-b2")).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(engine.endpoint_calls.len(), near_endpoints);
    assert!(
        engine.media().is_media_call("of-retry"),
        "back on the local pipeline after the far party left"
    );
    assert!(matches!(
        play_tone(&engine, "of-retry").await,
        CmdResult::Ok { .. }
    ));
    drain(&callee).await;
    assert!(matches!(
        delete(&engine, "of-retry", None).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(engine.session_count(), 0);
    assert_eq!(engine.endpoint_calls.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_answer_outside_the_offer_is_refused_and_the_caller_keeps_the_local_pipeline() {
    let engine = engine_with_dispatcher();
    let (_caller, caller_addr) = phone().await;
    let (_callee, callee_addr) = phone().await;
    answer_locally(&engine, "of-488", caller_addr).await;
    assert!(matches!(
        offer_far(&engine, "of-488", &[]).await,
        CmdResult::Ok { .. }
    ));

    let refused = answer_far(
        &engine,
        "of-488",
        "tag-b",
        far_answer(callee_addr, 9, "G722"),
    )
    .await;
    assert!(
        is_error_containing(&refused, "codec-not-offered"),
        "{refused:?}"
    );
    let renumbered = answer_far(
        &engine,
        "of-488",
        "tag-b",
        far_answer(callee_addr, 96, "PCMU"),
    )
    .await;
    assert!(
        is_error_containing(&renumbered, "renumbered-near-codec"),
        "{renumbered:?}"
    );
    assert!(
        engine
            .calls
            .get("of-488")
            .is_some_and(|call| call.far_offer_pending()),
        "the far leg is still offered, for the controller to delete"
    );
    assert!(matches!(
        play_tone(&engine, "of-488").await,
        CmdResult::Ok { .. }
    ));
    assert!(matches!(
        delete(&engine, "of-488", Some("tag-b")).await,
        CmdResult::Ok { .. }
    ));
}

#[tokio::test]
async fn offer_far_is_refused_where_it_cannot_grow_a_relay() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_caller, caller_addr) = phone().await;

    assert!(is_error_containing(
        &offer_far(&engine, "of-none", &[]).await,
        "unknown call"
    ));

    // A two-party offer is not a locally answered call.
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "of-offer".into(),
                from_tag: "tag-a".into(),
                sdp: caller_offer(caller_addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(offered, CmdResult::Ok { .. }));
    assert!(is_error_containing(
        &offer_far(&engine, "of-offer", &[]).await,
        "not-a-local-answer"
    ));

    answer_locally(&engine, "of-twice", caller_addr).await;
    let wrong_tag = engine
        .handle(
            CLIENT,
            Command::OfferFar {
                call_id: "of-twice".into(),
                from_tag: "tag-z".into(),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(is_error_containing(&wrong_tag, "from_tag mismatch"));
    assert!(matches!(
        offer_far(&engine, "of-twice", &[]).await,
        CmdResult::Ok { .. }
    ));
    assert!(is_error_containing(
        &offer_far(&engine, "of-twice", &[]).await,
        "far-leg-exists"
    ));

    // Nothing renegotiates toward, or snapshots, a far party that has not answered.
    let reoffer = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "of-twice".into(),
                from_tag: "tag-a".into(),
                sdp: caller_offer(caller_addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(
        is_error_containing(&reoffer, "far-offer-pending"),
        "{reoffer:?}"
    );
    let checkpoint = engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "of-twice".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    assert!(
        matches!(checkpoint, CmdResult::Error { .. }),
        "{checkpoint:?}"
    );

    // Another client cannot see it at all.
    let stranger = engine
        .handle(
            ClientId(99),
            Command::OfferFar {
                call_id: "of-twice".into(),
                from_tag: "tag-a".into(),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(is_error_containing(&stranger, "unknown call"));
}

#[tokio::test]
async fn deleting_a_call_with_an_offered_far_leg_releases_both_legs() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_caller, caller_addr) = phone().await;
    answer_locally(&engine, "of-drain", caller_addr).await;
    assert!(matches!(
        offer_far(&engine, "of-drain", &[]).await,
        CmdResult::Ok { .. }
    ));
    assert!(matches!(
        delete(&engine, "of-drain", None).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(engine.session_count(), 0);
    assert_eq!(engine.endpoint_calls.len(), 0);
    assert_eq!(engine.client_calls.get(&CLIENT).map(|count| *count), None);
}
