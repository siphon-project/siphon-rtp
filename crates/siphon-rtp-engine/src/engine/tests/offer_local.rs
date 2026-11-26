#![cfg(test)]

//! `offer_local`: the engine makes its own offer for a one-legged call, the caller's answer
//! completes it, and from then on the call is an `answer_local` one.
//!
//! The SDP the engine emits is read line by line, and the media is real RTP over the loopback
//! datapath in both directions, for every security shape: plain, SDES, DTLS-SRTP, ICE and DTLS-SRTP
//! over ICE.

use super::answer_local_video::engine_with_dispatcher;
use super::*;
use crate::engine::negotiate::SourcePosture;
use siphon_rtp_dtls::{DtlsCertificate, DtlsRole, DtlsSession};
use siphon_rtp_media::bridge::pcm_to_l16_le;
use std::time::Instant;

const CALL: &str = "offer-local-call";
const CALLER_TAG: &str = "tag-a";
const CONTROLLER_TAG: &str = "tag-b";

fn only(codecs: &[&str]) -> Vec<String> {
    let mut flags = vec!["codec-strip-all".to_string()];
    flags.extend(codecs.iter().map(|name| format!("codec-except-{name}")));
    flags
}

fn profile(transport: Option<&str>, codecs: &[&str]) -> ProfileFlags {
    ProfileFlags {
        transport_protocol: transport.map(str::to_string),
        flags: only(codecs),
        ..Default::default()
    }
}

async fn offer_local(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    profile: ProfileFlags,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::OfferLocal {
                call_id: call_id.into(),
                from_tag: CALLER_TAG.into(),
                profile,
            },
        )
        .await
}

async fn complete(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    sdp: String,
    profile: ProfileFlags,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: CALLER_TAG.into(),
                to_tag: CONTROLLER_TAG.into(),
                sdp,
                profile,
            },
        )
        .await
}

async fn delete(engine: &Engine<UdpLoopbackDatapath>, call_id: &str) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: call_id.into(),
                from_tag: CALLER_TAG.into(),
                to_tag: None,
            },
        )
        .await
}

fn is_error_containing(result: &CmdResult, token: &str) -> bool {
    matches!(result, CmdResult::Error { reason } if reason.contains(token))
}

/// The caller's answer from `addr` choosing `payload_type` / `name`, with `extra` attribute lines
/// and `transport` on the `m=` line.
fn caller_answer(
    addr: SocketAddr,
    transport: &str,
    payload_type: u8,
    name: &str,
    extra: &str,
) -> String {
    format!(
        "v=0\r\no=caller 10 10 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} {transport} {payload_type} 101\r\na=rtpmap:{payload_type} {name}/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=sendrecv\r\n{extra}",
        ip = addr.ip(),
        port = addr.port(),
    )
}

fn plain_answer(addr: SocketAddr) -> String {
    caller_answer(addr, "RTP/AVP", 0, "PCMU", "")
}

async fn play_prompt(engine: &Engine<UdpLoopbackDatapath>, call_id: &str) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::PlayMedia {
                call_id: call_id.into(),
                from_tag: CALLER_TAG.into(),
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

async fn echo(engine: &Engine<UdpLoopbackDatapath>, call_id: &str) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::Echo {
                call_id: call_id.into(),
                from_tag: CALLER_TAG.into(),
                to_tag: None,
                enabled: true,
            },
        )
        .await
}

/// The next datagram `socket` receives that is RTP and not RTCP, and where it came from.
async fn next_rtp(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    loop {
        let (packet, from) = recv(socket).await;
        if packet.len() >= 12 && !matches!(packet[1] & 0x7F, 72..=76) {
            return (packet, from);
        }
    }
}

/// Whether `socket` receives an RTP datagram carrying `marker` in its payload within `wait`.
async fn hears_marker(socket: &UdpSocket, marker: u8, wait: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + wait;
    let mut buffer = [0u8; 2048];
    while let Ok(Ok((len, _))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await
    {
        if len > 12 && buffer[12..len].iter().all(|byte| *byte == marker) {
            return true;
        }
    }
    false
}

fn engine_address(offer: &str) -> SocketAddr {
    sdp::parse(offer).expect("the offer parses").remote_rtp
}

fn pending(engine: &Engine<UdpLoopbackDatapath>, call_id: &str) -> bool {
    engine
        .calls
        .get(call_id)
        .is_some_and(|call| call.local_offer_pending())
}

// ---- the offer ---------------------------------------------------------------------------------

#[tokio::test]
async fn the_offer_is_one_audio_stream_of_runnable_codecs_then_telephone_event() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let offer = ok_sdp_text(&offer_local(&engine, CALL, ProfileFlags::default()).await);
    let info = sdp::parse(&offer).expect("parse");
    assert!(!info.secure && info.ice_ufrag.is_none() && info.fingerprint.is_none());
    assert!(!offer.contains("m=video"), "{offer}");
    assert_eq!(offer.matches("m=").count(), 1, "one media section: {offer}");
    // Every offered codec runs both ways, and telephone-event follows the codecs.
    let codecs = info.audio_codecs();
    assert!(codecs.iter().any(|codec| codec.encoding_name == "PCMU"));
    for codec in &codecs {
        assert!(factory::decoder_for(codec).is_ok() && factory::encoder_for(codec).is_ok());
    }
    assert!(!info.telephone_events().is_empty());
    let formats: Vec<&str> = offer
        .lines()
        .find(|line| line.starts_with("m=audio "))
        .expect("audio line")
        .split(' ')
        .skip(3)
        .collect();
    assert_eq!(formats.len(), info.payload_types.len());
    // The engine's own address, on a socket of its own, and a separate RTCP port by default.
    assert_eq!(info.remote_rtp.ip(), Ipv4Addr::LOCALHOST);
    assert!(!info.rtcp_mux);
    assert!(pending(&engine, CALL));
}

#[tokio::test]
async fn the_codec_flags_order_and_filter_the_offer() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let offer = ok_sdp_text(&offer_local(&engine, CALL, profile(None, &["PCMA", "PCMU"])).await);
    let info = sdp::parse(&offer).expect("parse");
    let names: Vec<String> = info
        .audio_codecs()
        .into_iter()
        .map(|codec| codec.encoding_name)
        .collect();
    assert_eq!(names, ["PCMU", "PCMA"], "{offer}");
    let none = offer_local(&engine, "none", profile(None, &["NOSUCHCODEC"])).await;
    assert!(is_error_containing(&none, "no-offerable-codec"), "{none:?}");
}

#[tokio::test]
async fn a_second_offer_local_on_a_live_call_id_is_refused_and_leaves_the_call() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let first = ok_sdp_text(&offer_local(&engine, CALL, ProfileFlags::default()).await);
    let second = offer_local(&engine, CALL, ProfileFlags::default()).await;
    assert!(is_error_containing(&second, "call-exists"), "{second:?}");
    assert_eq!(
        engine
            .calls
            .get(CALL)
            .map(|call| call.near.rtp.local_addr.port()),
        Some(engine_address(&first).port()),
        "the first offer's leg is untouched"
    );
    // A live answered call is refused alike.
    let (_phone, addr) = phone().await;
    assert!(matches!(
        complete(&engine, CALL, plain_answer(addr), ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    let third = offer_local(&engine, CALL, ProfileFlags::default()).await;
    assert!(is_error_containing(&third, "call-exists"), "{third:?}");
}

#[tokio::test]
async fn an_answer_before_the_offer_is_an_unknown_call() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let result = complete(&engine, CALL, plain_answer(addr), ProfileFlags::default()).await;
    assert!(is_error_containing(&result, "unknown call"), "{result:?}");
}

#[tokio::test]
async fn another_client_cannot_see_or_complete_the_offer() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    offer_local(&engine, CALL, ProfileFlags::default()).await;
    let (_phone, addr) = phone().await;
    let result = engine
        .handle(
            ClientId(2),
            Command::Answer {
                call_id: CALL.into(),
                from_tag: CALLER_TAG.into(),
                to_tag: CONTROLLER_TAG.into(),
                sdp: plain_answer(addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(is_error_containing(&result, "unknown call"), "{result:?}");
    assert!(pending(&engine, CALL));
}

#[tokio::test]
async fn unsupported_profiles_are_refused_before_anything_is_allocated() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let fax = ProfileFlags {
        fax_passthrough: true,
        ..Default::default()
    };
    assert!(is_error_containing(
        &offer_local(&engine, "fax", fax).await,
        "fax-passthrough-needs-a-peer-leg"
    ));
    let video = ProfileFlags {
        video_relay: siphon_rtp_proto::VideoRelay::Anchor,
        ..Default::default()
    };
    assert!(is_error_containing(
        &offer_local(&engine, "video", video).await,
        "video-not-supported"
    ));
    let ice = ProfileFlags {
        ice: Some("force".into()),
        ..Default::default()
    };
    assert!(
        is_error_containing(&offer_local(&engine, "ice", ice).await, "ice-unsupported"),
        "an engine without --ice-full cannot run ICE on this leg"
    );
    assert!(engine.calls.is_empty(), "nothing is left allocated");
    assert!(engine.endpoint_calls.is_empty());
}

// ---- before the answer -------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nothing_is_sent_and_nothing_received_before_the_answer_is_forwarded_or_latched() {
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let (stranger, _) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let offer = ok_sdp_text(&offer_local(&engine, CALL, profile(None, &["PCMU"])).await);
    let engine_addr = engine_address(&offer);

    // Nothing is sent toward anyone, and a datagram from anywhere is dropped.
    for sequence in 0..5 {
        let packet = ulaw_rtp_packet(sequence, 0x0A0A_0A0A, 0x11);
        caller.send_to(&packet, engine_addr).await.expect("send");
        let packet = ulaw_rtp_packet(sequence, 0x0B0B_0B0B, 0x22);
        stranger.send_to(&packet, engine_addr).await.expect("send");
    }
    assert!(!hears_marker(&caller, 0x22, Duration::from_millis(300)).await);
    let mut buffer = [0u8; 2048];
    assert!(
        timeout(Duration::from_millis(100), stranger.recv_from(&mut buffer))
            .await
            .is_err(),
        "no datagram of any kind is sent before the answer"
    );
    assert!(
        timeout(Duration::from_millis(100), caller.recv_from(&mut buffer))
            .await
            .is_err()
    );

    // After the answer the latch is gated on the address it signalled, and echo reflects only what
    // that gate accepts: the caller's own later audio comes back, the stranger's never does, and
    // nothing sent before the answer was kept.
    complete(
        &engine,
        CALL,
        plain_answer(caller_addr),
        ProfileFlags::default(),
    )
    .await;
    echo(&engine, CALL).await;
    for sequence in 10..30 {
        let packet = ulaw_rtp_packet(sequence, 0x0B0B_0B0B, 0x22);
        stranger.send_to(&packet, engine_addr).await.expect("send");
        let packet = ulaw_rtp_packet(sequence, 0x0A0A_0A0A, 0x33);
        caller.send_to(&packet, engine_addr).await.expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !hears_marker(&stranger, 0x33, Duration::from_millis(200)).await,
        "the caller's audio is not reflected to a stranger"
    );
    assert!(
        !hears_marker(&caller, 0x22, Duration::from_millis(200)).await,
        "a stranger's audio is dropped after the answer too"
    );
}

#[tokio::test]
async fn verbs_that_need_a_pipeline_are_refused_until_the_answer() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    offer_local(&engine, CALL, profile(None, &["PCMU"])).await;
    let refused = play_prompt(&engine, CALL).await;
    assert!(
        is_error_containing(&refused, "offer-local-pending"),
        "{refused:?}"
    );
    let re_answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: CALL.into(),
                from_tag: CALLER_TAG.into(),
                sdp: "v=0\r\n".into(),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(is_error_containing(&re_answered, "offer-local-pending"));
    // Checkpoint is refused with its own reason: nothing negotiated to replicate.
    let checkpoint = engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: CALL.into(),
                from_tag: CALLER_TAG.into(),
            },
        )
        .await;
    assert!(
        is_error_containing(&checkpoint, "awaiting its answer"),
        "{checkpoint:?}"
    );
    assert!(pending(&engine, CALL), "refusals change nothing");
    // The verbs it does serve work on a pending call.
    let queried = engine
        .handle(
            CLIENT,
            Command::Query {
                call_id: CALL.into(),
                from_tag: CALLER_TAG.into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(queried, CmdResult::Ok { .. }), "{queried:?}");
}

#[tokio::test]
async fn deleting_an_unanswered_offer_frees_everything() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let _events = engine.register_client(CLIENT);
    offer_local(&engine, CALL, profile(Some("RTP/SAVP"), &["PCMU"])).await;
    assert_eq!(engine.calls.len(), 1);
    assert!(matches!(delete(&engine, CALL).await, CmdResult::Ok { .. }));
    assert!(engine.calls.is_empty());
    assert!(
        engine.endpoint_calls.is_empty(),
        "every endpoint is released"
    );
    assert_eq!(engine.client_call_count(CLIENT), 0);
    // And the call-id is free for a fresh offer.
    assert!(matches!(
        offer_local(&engine, CALL, ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
}

// ---- a bad answer ------------------------------------------------------------------------------

#[tokio::test]
async fn a_bad_answer_is_an_error_with_a_token_and_the_call_stays_allocated() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    offer_local(&engine, CALL, profile(None, &["PCMU"])).await;

    let no_codec = caller_answer(addr, "RTP/AVP", 8, "PCMA", "");
    let declined = plain_answer(addr).replace(&format!("m=audio {} ", addr.port()), "m=audio 0 ");
    let secure = caller_answer(addr, "RTP/SAVP", 0, "PCMU", "");
    for (bad, token) in [
        (no_codec, "codec-not-offered"),
        (declined, "answer-rejected"),
        (secure, "security-mismatch"),
        ("not an sdp".to_string(), "answer-sdp-invalid"),
    ] {
        let result = complete(&engine, CALL, bad, ProfileFlags::default()).await;
        assert!(is_error_containing(&result, token), "{token}: {result:?}");
        assert!(pending(&engine, CALL), "{token}: the call stays pending");
    }
    // A wrong from-tag completes nothing either.
    let wrong = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: CALL.into(),
                from_tag: "someone-else".into(),
                to_tag: CONTROLLER_TAG.into(),
                sdp: plain_answer(addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(
        is_error_containing(&wrong, "from_tag mismatch"),
        "{wrong:?}"
    );
    assert!(pending(&engine, CALL));
    // The controller can still delete it (there is no way to 488 an ACK), and a good answer would
    // still have completed it.
    assert!(matches!(delete(&engine, CALL).await, CmdResult::Ok { .. }));
    assert!(engine.calls.is_empty());
}

// ---- plain: the call runs as an answer_local one ----------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plain_answer_completes_the_call_and_media_flows_both_ways() {
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let offer = ok_sdp_text(&offer_local(&engine, CALL, profile(None, &["PCMU", "PCMA"])).await);
    let engine_addr = engine_address(&offer);

    let completed = complete(
        &engine,
        CALL,
        plain_answer(caller_addr),
        ProfileFlags::default(),
    )
    .await;
    // The engine's own offer comes back unchanged, with the controller's to_tag.
    match &completed {
        CmdResult::Ok { sdp, to_tag, .. } => {
            assert_eq!(sdp.as_deref(), Some(offer.as_str()));
            assert_eq!(to_tag.as_deref(), Some(CONTROLLER_TAG));
        }
        other => panic!("{other:?}"),
    }
    // It is an answer_local call now: one leg, the chosen codec, the engine's pipeline.
    {
        let call = engine.calls.get(CALL).expect("call");
        assert!(call.far.is_none() && call.is_single_leg());
        assert!(call.local_answer.is_some());
        assert_eq!(
            call.near_codec.as_ref().map(|c| c.encoding_name.as_str()),
            Some("PCMU")
        );
        assert_eq!(call.pipeline, PipelineKind::Media);
        assert_eq!(call.near.remote_rtp, Some(caller_addr));
        assert!(!call.local_offer_pending());
    }

    // Downlink: a prompt reaches the caller, in the answered codec, from the engine's socket.
    assert!(matches!(
        play_prompt(&engine, CALL).await,
        CmdResult::Ok { .. }
    ));
    let (packet, from) = next_rtp(&caller).await;
    assert_eq!(from, engine_addr);
    assert_eq!(packet[1] & 0x7F, 0, "µ-law, the codec the caller answered");

    // Uplink: the caller's audio is decoded and, with echo on, comes back.
    assert!(matches!(echo(&engine, CALL).await, CmdResult::Ok { .. }));
    for sequence in 0..30 {
        caller
            .send_to(&ulaw_rtp_packet(sequence, 0x0A0A_0A0A, 0x5A), engine_addr)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(hears_marker(&caller, 0x5A, Duration::from_secs(1)).await);

    // The same verbs answer_local serves: a re-answer replaces the call on fresh ports.
    let again = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: CALL.into(),
                from_tag: CALLER_TAG.into(),
                sdp: plain_answer(caller_addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(again, CmdResult::Ok { .. }), "{again:?}");
    // A second answer on the offer is refused: the offer was answered.
    let second = complete(
        &engine,
        CALL,
        plain_answer(caller_addr),
        ProfileFlags::default(),
    )
    .await;
    assert!(matches!(second, CmdResult::Error { .. }), "{second:?}");
}

#[tokio::test]
async fn a_second_answer_names_the_first_to_tag() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    offer_local(&engine, CALL, profile(None, &["PCMU"])).await;
    assert!(matches!(
        complete(&engine, CALL, plain_answer(addr), ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    let second = complete(&engine, CALL, plain_answer(addr), ProfileFlags::default()).await;
    assert!(
        is_error_containing(&second, "offer-local-already-answered")
            && is_error_containing(&second, CONTROLLER_TAG),
        "{second:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_answer_decides_the_codec_among_those_offered() {
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let offer = ok_sdp_text(&offer_local(&engine, CALL, profile(None, &["PCMU", "PCMA"])).await);
    let answer = caller_answer(caller_addr, "RTP/AVP", 8, "PCMA", "");
    assert!(matches!(
        complete(&engine, CALL, answer, ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    assert!(matches!(
        play_prompt(&engine, CALL).await,
        CmdResult::Ok { .. }
    ));
    let (packet, from) = next_rtp(&caller).await;
    assert_eq!(from, engine_address(&offer));
    assert_eq!(packet[1] & 0x7F, 8, "A-law, the answered codec");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answered_offer_local_call_can_grow_a_far_leg_like_an_answer_local_one() {
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let (callee, callee_addr) = phone().await;
    let offer = ok_sdp_text(&offer_local(&engine, CALL, profile(None, &["PCMU"])).await);
    complete(
        &engine,
        CALL,
        plain_answer(caller_addr),
        ProfileFlags::default(),
    )
    .await;
    let far_offer = engine
        .handle(
            CLIENT,
            Command::OfferFar {
                call_id: CALL.into(),
                from_tag: CALLER_TAG.into(),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let far_offer = ok_sdp_text(&far_offer);
    let far_engine = engine_address(&far_offer);
    assert_ne!(far_engine, engine_address(&offer), "a leg of its own");
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: CALL.into(),
                from_tag: CALLER_TAG.into(),
                to_tag: "tag-far".into(),
                sdp: plain_answer(callee_addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    // The caller's audio now reaches the callee, and the other way.
    caller
        .send_to(
            &ulaw_rtp_packet(1, 0x0A0A_0A0A, 0x61),
            engine_address(&offer),
        )
        .await
        .expect("send");
    assert!(hears_marker(&callee, 0x61, Duration::from_secs(1)).await);
    callee
        .send_to(&ulaw_rtp_packet(1, 0x0C0C_0C0C, 0x62), far_engine)
        .await
        .expect("send");
    assert!(hears_marker(&caller, 0x62, Duration::from_secs(1)).await);
}

// ---- a takeover WebSocket ---------------------------------------------------------------------

async fn uplink_and_downlink(
    frames: &flume::Receiver<tokio_tungstenite::tungstenite::Message>,
    downlink: &flume::Sender<Vec<u8>>,
) {
    let uplink = next_uplink_frame(frames)
        .await
        .expect("the WS server received the caller's audio");
    assert_eq!(uplink.len(), 320, "8 kHz / 20 ms L16 uplink");
    let mut l16 = [0u8; 320];
    pcm_to_l16_le(&[2000i16; 160], &mut l16);
    downlink.send(l16.to_vec()).expect("queue downlink");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ws_uri_takeover_is_dialled_at_the_answer_and_carries_the_callers_audio() {
    let (ws_uri, frames, downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let mut takeover = profile(None, &["PCMU"]);
    takeover.ws_uri = Some(ws_uri);
    let offer = ok_sdp_text(&offer_local(&engine, CALL, takeover).await);
    let engine_addr = engine_address(&offer);
    assert!(
        !engine.ws().is_ws_call(CALL),
        "nothing is dialled at the offer: the codec of the bridge is unknown until the answer"
    );
    assert!(matches!(
        complete(
            &engine,
            CALL,
            plain_answer(caller_addr),
            ProfileFlags::default()
        )
        .await,
        CmdResult::Ok { .. }
    ));
    assert!(engine.ws().is_ws_call(CALL));

    caller
        .send_to(&ulaw_rtp_packet(7, 0x0A0A_0A0A, 0xFF), engine_addr)
        .await
        .expect("send");
    uplink_and_downlink(&frames, &downlink).await;
    let (packet, from) = next_rtp(&caller).await;
    assert_eq!(from, engine_addr);
    assert_eq!(packet[1] & 0x7F, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_is_not_heard_by_the_takeover_before_or_after_the_answer() {
    let (ws_uri, frames, _downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let (_caller, caller_addr) = phone().await;
    let (stranger, _) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let mut takeover = profile(None, &["PCMU"]);
    takeover.ws_uri = Some(ws_uri);
    let offer = ok_sdp_text(&offer_local(&engine, CALL, takeover).await);
    let engine_addr = engine_address(&offer);
    stranger
        .send_to(&ulaw_rtp_packet(1, 0x0B0B_0B0B, 0xFF), engine_addr)
        .await
        .expect("send");
    complete(
        &engine,
        CALL,
        plain_answer(caller_addr),
        ProfileFlags::default(),
    )
    .await;
    expect_ws_start(&frames).await;
    for sequence in 2..12 {
        stranger
            .send_to(&ulaw_rtp_packet(sequence, 0x0B0B_0B0B, 0xFF), engine_addr)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        timeout(Duration::from_millis(500), frames.recv_async())
            .await
            .is_err(),
        "a stranger's audio never reaches the WebSocket server"
    );
}

// ---- SDES --------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_offer_is_keyed_by_the_answers_key_both_ways() {
    let (ws_uri, frames, downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let mut secure = profile(Some("RTP/SAVP"), &["PCMU"]);
    secure.ws_uri = Some(ws_uri);
    let offer = ok_sdp_text(&offer_local(&engine, CALL, secure).await);
    let info = sdp::parse(&offer).expect("offer");
    assert!(info.secure && !info.dtls, "{offer}");
    assert_eq!(info.crypto.len(), 1, "one crypto line: {offer}");
    let engine_key = info.crypto[0];
    let engine_addr = info.remote_rtp;

    // The caller answers with its own key under the offered tag (RFC 4568 §5.1.2).
    let caller_key = CryptoAttribute::answer_to(&engine_key).expect("caller key");
    let answer = caller_answer(
        caller_addr,
        "RTP/SAVP",
        0,
        "PCMU",
        &format!("a={}\r\n", caller_key.to_attribute_value()),
    );
    assert!(matches!(
        complete(&engine, CALL, answer, ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(
        engine.ws().secure_state(CALL),
        Some(true),
        "SDES is keyed the moment the answer is installed"
    );
    let mut caller_leg = SecureLeg::new(&caller_key.key, &engine_key.key);
    let mut sealed = Vec::new();
    caller_leg
        .protect(&ulaw_rtp_packet(7, 0x0A0A_0A0A, 0xFF), &mut sealed)
        .expect("protect");
    caller.send_to(&sealed, engine_addr).await.expect("send");
    uplink_and_downlink(&frames, &downlink).await;
    let mut buffer = [0u8; 2048];
    let mut decrypted = false;
    for _ in 0..40 {
        let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), caller.recv_from(&mut buffer)).await
        else {
            continue;
        };
        let mut clear = Vec::new();
        if caller_leg.unprotect(&buffer[..len], &mut clear).is_ok() {
            assert_eq!(len, clear.len() + 10, "the downlink carries an SRTP tag");
            decrypted = true;
            break;
        }
    }
    assert!(
        decrypted,
        "the caller decrypts the downlink with the engine's key"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_sdes_call_on_the_local_pipeline_sends_the_prompt_as_srtp() {
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let offer =
        ok_sdp_text(&offer_local(&engine, CALL, profile(Some("RTP/SAVP"), &["PCMU"])).await);
    let engine_key = sdp::parse(&offer).expect("offer").crypto[0];
    let caller_key = CryptoAttribute::answer_to(&engine_key).expect("caller key");
    let answer = caller_answer(
        caller_addr,
        "RTP/SAVP",
        0,
        "PCMU",
        &format!("a={}\r\n", caller_key.to_attribute_value()),
    );
    assert!(matches!(
        complete(&engine, CALL, answer, ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    assert!(matches!(
        play_prompt(&engine, CALL).await,
        CmdResult::Ok { .. }
    ));
    let mut caller_leg = SecureLeg::new(&caller_key.key, &engine_key.key);
    let mut buffer = [0u8; 2048];
    let mut heard = false;
    for _ in 0..40 {
        let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), caller.recv_from(&mut buffer)).await
        else {
            continue;
        };
        let mut clear = Vec::new();
        if caller_leg.unprotect(&buffer[..len], &mut clear).is_ok() && clear.len() >= 12 {
            heard = true;
            break;
        }
    }
    assert!(
        heard,
        "the prompt reaches the caller as SRTP it can decrypt"
    );
}

#[tokio::test]
async fn an_sdes_answer_with_no_acceptable_crypto_is_refused_and_the_call_stays() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    offer_local(&engine, CALL, profile(Some("RTP/SAVP"), &["PCMU"])).await;
    let none = caller_answer(addr, "RTP/SAVP", 0, "PCMU", "");
    let result = complete(&engine, CALL, none, ProfileFlags::default()).await;
    assert!(
        is_error_containing(&result, "sdes-no-acceptable-crypto"),
        "{result:?}"
    );
    assert!(pending(&engine, CALL));
}

// ---- DTLS-SRTP ---------------------------------------------------------------------------------

fn dtls_answer(addr: SocketAddr, certificate: &DtlsCertificate, setup: &str) -> String {
    let fingerprint = certificate.fingerprint();
    let fingerprint = sdp::Fingerprint {
        hash_function: fingerprint.hash_function,
        bytes: fingerprint.bytes,
    };
    caller_answer(
        addr,
        "UDP/TLS/RTP/SAVPF",
        0,
        "PCMU",
        &format!(
            "a=rtcp-mux\r\na=setup:{setup}\r\na={}\r\n",
            fingerprint.to_attribute_value()
        ),
    )
}

async fn dtls_both_ways(answer_setup: &str, caller_role: DtlsRole) {
    let (ws_uri, frames, downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let caller = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind"),
    );
    let caller_addr = caller.local_addr().expect("addr");
    let caller_certificate = DtlsCertificate::generate().expect("certificate");
    let mut secure = profile(Some("UDP/TLS/RTP/SAVPF"), &["PCMU"]);
    secure.ws_uri = Some(ws_uri);
    let offer = ok_sdp_text(&offer_local(&engine, CALL, secure).await);
    let info = sdp::parse(&offer).expect("offer");
    assert!(info.dtls && info.rtcp_mux, "{offer}");
    assert_eq!(info.setup, Some(sdp::Setup::Actpass), "{offer}");
    assert!(info.tls_id.is_some(), "{offer}");
    let engine_fingerprint = info.fingerprint.clone().expect("fingerprint");
    let engine_addr = info.remote_rtp;

    assert!(matches!(
        complete(
            &engine,
            CALL,
            dtls_answer(caller_addr, &caller_certificate, answer_setup),
            ProfileFlags::default()
        )
        .await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(
        engine.ws().secure_state(CALL),
        Some(false),
        "the leg is unkeyed until the handshake runs"
    );
    let mut caller_leg = drive_peer_dtls(
        caller.clone(),
        engine_addr,
        &caller_certificate,
        &engine_fingerprint,
        caller_role,
        false,
    )
    .await;
    for _ in 0..100 {
        if engine.ws().secure_state(CALL) == Some(true) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(engine.ws().secure_state(CALL), Some(true));

    let mut sealed = Vec::new();
    caller_leg
        .protect(&ulaw_rtp_packet(11, 0x0C0C_0C0C, 0xFF), &mut sealed)
        .expect("protect");
    caller.send_to(&sealed, engine_addr).await.expect("send");
    uplink_and_downlink(&frames, &downlink).await;
    let mut buffer = [0u8; 2048];
    let mut decrypted = false;
    for _ in 0..40 {
        let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), caller.recv_from(&mut buffer)).await
        else {
            continue;
        };
        let mut clear = Vec::new();
        if caller_leg.unprotect(&buffer[..len], &mut clear).is_ok() {
            decrypted = true;
            break;
        }
    }
    assert!(decrypted, "the downlink is SRTP under the DTLS-derived key");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_answer_of_active_makes_the_engine_the_server_and_media_flows_both_ways() {
    dtls_both_ways("active", DtlsRole::Client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_answer_of_passive_makes_the_engine_the_client_and_media_flows_both_ways() {
    dtls_both_ways("passive", DtlsRole::Server).await;
}

#[tokio::test]
async fn a_dtls_answer_without_a_fingerprint_is_refused_and_the_call_stays() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    offer_local(&engine, CALL, profile(Some("UDP/TLS/RTP/SAVPF"), &["PCMU"])).await;
    let no_fingerprint = caller_answer(
        addr,
        "UDP/TLS/RTP/SAVPF",
        0,
        "PCMU",
        "a=rtcp-mux\r\na=setup:active\r\n",
    );
    let result = complete(&engine, CALL, no_fingerprint, ProfileFlags::default()).await;
    assert!(
        is_error_containing(&result, "dtls-fingerprint-missing"),
        "{result:?}"
    );
    assert!(pending(&engine, CALL));
}

// ---- ICE ---------------------------------------------------------------------------------------

const CALLER_UFRAG: &str = "CALR";
const CALLER_PWD: &str = "callerpasswordcallerpass";

/// The caller's agent for an engine offer: the engine is the offerer and so controls (RFC 8445
/// §6.1.1), which makes the caller the controlled agent.
fn controlled_peer(offer: &sdp::MediaInfo, local: SocketAddr) -> siphon_rtp_ice::IceAgent {
    use siphon_rtp_ice::agent::{AgentConfig, Credentials};
    let candidate = siphon_rtp_ice::Candidate::new(
        "peer".to_string(),
        1,
        local,
        siphon_rtp_ice::CandidateKind::Host,
        65535,
    );
    siphon_rtp_ice::IceAgent::new(
        AgentConfig::new(
            Credentials::new(CALLER_UFRAG, CALLER_PWD),
            Credentials::new(
                offer.ice_ufrag.clone().expect("engine ufrag"),
                offer.ice_pwd.clone().expect("engine pwd"),
            ),
            false,
            0x0000_FFFF_0000_FFFF,
        )
        .with_candidates(
            vec![candidate],
            offer
                .candidates
                .iter()
                .filter(|candidate| candidate.component == 1)
                .cloned()
                .collect(),
        ),
        0,
    )
}

fn ice_attributes(addr: SocketAddr) -> String {
    format!(
        "a=rtcp-mux\r\na=ice-ufrag:{CALLER_UFRAG}\r\na=ice-pwd:{CALLER_PWD}\r\n\
         a=candidate:peer 1 UDP 2130706431 {ip} {port} typ host\r\na=end-of-candidates\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

/// Run the caller's agent against the engine's until the engine selected a pair, and its DTLS
/// session too when there is one. Returns the keyed leg.
async fn run_ice_and_dtls(
    engine: &Engine<UdpLoopbackDatapath>,
    socket: &UdpSocket,
    peer: &mut siphon_rtp_ice::IceAgent,
    mut dtls: Option<&mut DtlsSession>,
    near: EndpointId,
) -> bool {
    let mut buffer = [0u8; 2048];
    let engine_target = engine
        .calls
        .get(CALL)
        .map(|call| call.near.rtp.local_addr)
        .expect("call");
    let local = socket.local_addr().expect("addr");
    let started = Instant::now();
    let mut now = 0u64;
    while now < 8_000 {
        for action in peer.poll(now) {
            if let siphon_rtp_ice::AgentAction::Send { to, datagram, .. } = action {
                socket.send_to(&datagram, to).await.expect("peer send");
            }
        }
        engine.drive_ice_agents(now).await;
        if let Some(session) = dtls.as_deref_mut() {
            if engine.datapath().ice_validated_source(near).is_some() {
                if let Some(at) = session.poll_timeout() {
                    if at <= Instant::now() {
                        session.handle_timeout(Instant::now()).expect("timer");
                    }
                }
                while let Some(record) = session.poll_transmit() {
                    socket
                        .send_to(&record, engine_target)
                        .await
                        .expect("peer dtls send");
                }
            }
        }
        while let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(20), socket.recv_from(&mut buffer)).await
        {
            let first = buffer[0];
            if first < 4 {
                for action in peer.on_datagram(local, from, &buffer[..len], now) {
                    if let siphon_rtp_ice::AgentAction::Send { to, datagram, .. } = action {
                        socket.send_to(&datagram, to).await.expect("peer send");
                    }
                }
                engine.drive_ice_agents(now).await;
            } else if (20..=63).contains(&first) {
                if let Some(session) = dtls.as_deref_mut() {
                    session
                        .handle_datagram(Instant::now(), &buffer[..len])
                        .expect("peer accepts the record");
                    while let Some(record) = session.poll_transmit() {
                        socket
                            .send_to(&record, engine_target)
                            .await
                            .expect("peer dtls send");
                    }
                }
            }
        }
        let selected = engine.datapath().ice_validated_source(near).is_some();
        let keyed = dtls.as_deref().is_none_or(DtlsSession::is_keyed);
        if selected && keyed {
            return true;
        }
        now += 20;
    }
    let _ = started;
    false
}

async fn ice_rig() -> Engine<UdpLoopbackDatapath> {
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let _events = engine.register_client(CLIENT);
    tokio::spawn(crate::srtp_bridge::run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    engine
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ice_offer_runs_the_agent_as_controlling_and_media_flows_on_the_selected_pair() {
    let engine = ice_rig().await;
    let (caller, caller_addr) = phone().await;
    let mut ice = profile(None, &["PCMU"]);
    ice.ice = Some("force".into());
    let offer = ok_sdp_text(&offer_local(&engine, CALL, ice).await);
    let info = sdp::parse(&offer).expect("offer");
    assert!(
        info.is_ice() && !info.ice_lite && !info.candidates.is_empty(),
        "{offer}"
    );
    assert!(info.rtcp_mux, "an ICE leg is multiplexed: {offer}");
    let near = engine
        .calls
        .get(CALL)
        .map(|call| call.near.rtp.id)
        .expect("call");

    // Before the answer the engine has no agent: a check from the caller's agent gets no answer.
    let mut peer = controlled_peer(&info, caller_addr);
    assert!(
        engine.datapath().ice_validated_source(near).is_none(),
        "nothing is validated before the answer"
    );

    let answer = caller_answer(
        caller_addr,
        "RTP/AVP",
        0,
        "PCMU",
        &ice_attributes(caller_addr),
    );
    assert!(matches!(
        complete(&engine, CALL, answer, ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(
        engine
            .calls
            .get(CALL)
            .map(|call| call.caller_source_posture),
        Some(SourcePosture::Ice)
    );
    assert!(run_ice_and_dtls(&engine, &caller, &mut peer, None, near).await);
    assert_eq!(
        engine.datapath().ice_validated_source(near),
        Some(caller_addr)
    );

    assert!(matches!(
        play_prompt(&engine, CALL).await,
        CmdResult::Ok { .. }
    ));
    let (packet, from) = next_rtp(&caller).await;
    assert_eq!(from, info.remote_rtp);
    assert_eq!(packet[1] & 0x7F, 0);
    echo(&engine, CALL).await;
    for sequence in 0..30 {
        caller
            .send_to(
                &ulaw_rtp_packet(sequence, 0x0A0A_0A0A, 0x4B),
                info.remote_rtp,
            )
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(hears_marker(&caller, 0x4B, Duration::from_secs(1)).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ice_answer_without_candidates_is_refused_and_one_without_ice_runs_on_the_address() {
    let engine = ice_rig().await;
    let (_caller, caller_addr) = phone().await;
    let mut ice = profile(None, &["PCMU"]);
    ice.ice = Some("force".into());
    offer_local(&engine, CALL, ice).await;
    let no_candidates = caller_answer(
        caller_addr,
        "RTP/AVP",
        0,
        "PCMU",
        &format!("a=rtcp-mux\r\na=ice-ufrag:{CALLER_UFRAG}\r\na=ice-pwd:{CALLER_PWD}\r\n"),
    );
    let result = complete(&engine, CALL, no_candidates, ProfileFlags::default()).await;
    assert!(
        is_error_containing(&result, "ice-no-candidates"),
        "{result:?}"
    );
    assert!(pending(&engine, CALL));
    // RFC 8839 §5.1: an answer without ICE means ICE is not used; the leg runs on the signalled
    // address.
    let without = caller_answer(caller_addr, "RTP/AVP", 0, "PCMU", "a=rtcp-mux\r\n");
    assert!(matches!(
        complete(&engine, CALL, without, ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    assert_ne!(
        engine
            .calls
            .get(CALL)
            .map(|call| call.caller_source_posture),
        Some(SourcePosture::Ice)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dtls_over_ice_keys_the_pair_ice_selected_and_media_flows() {
    let engine = ice_rig().await;
    let caller = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let caller_addr = caller.local_addr().expect("addr");
    let caller_certificate = DtlsCertificate::generate().expect("certificate");
    let mut secure = profile(Some("UDP/TLS/RTP/SAVPF"), &["PCMU"]);
    secure.ice = Some("force".into());
    let offer = ok_sdp_text(&offer_local(&engine, CALL, secure).await);
    let info = sdp::parse(&offer).expect("offer");
    assert!(info.dtls && info.is_ice(), "{offer}");
    let engine_fingerprint = info.fingerprint.clone().expect("fingerprint");
    let near = engine
        .calls
        .get(CALL)
        .map(|call| call.near.rtp.id)
        .expect("call");
    let mut peer = controlled_peer(&info, caller_addr);

    // The caller answers active: it is the DTLS client, the engine the server.
    let answer = {
        let mut text = dtls_answer(caller_addr, &caller_certificate, "active");
        text.push_str(&ice_attributes(caller_addr).replace("a=rtcp-mux\r\n", ""));
        text
    };
    assert!(matches!(
        complete(&engine, CALL, answer, ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    let mut session = DtlsSession::new(
        &caller_certificate,
        DtlsRole::Client,
        siphon_rtp_dtls::Fingerprint::new(
            engine_fingerprint.hash_function.clone(),
            engine_fingerprint.bytes.clone(),
        ),
        Duration::from_millis(200),
    )
    .expect("session");
    session.start(Instant::now()).expect("first flight");
    assert!(
        run_ice_and_dtls(&engine, &caller, &mut peer, Some(&mut session), near).await,
        "ICE selected a pair and DTLS keyed it"
    );
    let mut caller_leg = session.keying().expect("keyed").to_secure_leg();

    assert!(matches!(
        play_prompt(&engine, CALL).await,
        CmdResult::Ok { .. }
    ));
    let mut buffer = [0u8; 2048];
    let mut heard = false;
    for _ in 0..40 {
        let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), caller.recv_from(&mut buffer)).await
        else {
            continue;
        };
        let mut clear = Vec::new();
        if buffer[0] >= 128 && caller_leg.unprotect(&buffer[..len], &mut clear).is_ok() {
            heard = true;
            break;
        }
    }
    assert!(
        heard,
        "the prompt reaches the caller as SRTP under the DTLS key"
    );
}

// ---- the control connection and checkpoints ----------------------------------------------------

fn answer_command(sdp: String) -> Command {
    Command::Answer {
        call_id: CALL.into(),
        from_tag: CALLER_TAG.into(),
        to_tag: CONTROLLER_TAG.into(),
        sdp,
        profile: ProfileFlags::default(),
    }
}

#[tokio::test]
async fn the_answer_that_dials_the_takeover_runs_off_the_control_loop() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let command = answer_command(plain_answer(addr));
    let mut takeover = profile(None, &["PCMU"]);
    takeover.ws_uri = Some("ws://127.0.0.1:9/stream".into());
    offer_local(&engine, CALL, takeover).await;
    assert!(
        engine.command_completes_a_dial(CALL, &command),
        "the completing answer dials the offer's ws_uri, so it must not hold the connection's loop"
    );
    assert!(
        !engine.command_completes_a_dial(CALL, &Command::Ping),
        "only the answer dials"
    );
    assert!(!engine.command_completes_a_dial("another-call", &command));
    offer_local(&engine, "no-dial", profile(None, &["PCMU"])).await;
    assert!(!engine.command_completes_a_dial("no-dial", &command));
}

#[tokio::test]
async fn an_answered_offer_is_checkpointed_exactly_like_an_answer_local_call() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    offer_local(&engine, CALL, profile(None, &["PCMU"])).await;
    complete(&engine, CALL, plain_answer(addr), ProfileFlags::default()).await;
    let from_offer_local = engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: CALL.into(),
                from_tag: CALLER_TAG.into(),
            },
        )
        .await;
    let answer_local = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "answered".into(),
                from_tag: CALLER_TAG.into(),
                sdp: plain_answer(addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(answer_local, CmdResult::Ok { .. }));
    let from_answer_local = engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "answered".into(),
                from_tag: CALLER_TAG.into(),
            },
        )
        .await;
    assert!(
        is_error_containing(&from_offer_local, "single-leg call"),
        "{from_offer_local:?}"
    );
    assert_eq!(from_offer_local, from_answer_local);
}

#[tokio::test]
async fn an_offer_that_is_never_answered_is_reaped_by_the_setup_timeout() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    offer_local(&engine, CALL, profile(None, &["PCMU"])).await;
    // Well past the media ceiling, which is not the rule for a call nobody has answered.
    engine.datapath().advance_clock(60);
    assert!(
        engine.reap_idle(30, 30, 300).await.is_empty(),
        "no media was due before the answer"
    );
    engine.datapath().advance_clock(300);
    assert_eq!(engine.reap_idle(30, 30, 300).await, vec![CALL.to_string()]);
    assert!(engine.calls.is_empty() && engine.endpoint_calls.is_empty());
    let reported = events.try_iter().any(|event| {
        matches!(
            event,
            Event::MediaTimeout {
                reason: siphon_rtp_proto::MediaTimeoutReason::SetupTimeout,
                ..
            }
        )
    });
    assert!(reported, "reported as a call that never connected");
}

#[tokio::test]
async fn node_info_lists_the_offer_local_feature() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    match engine.handle(CLIENT, Command::NodeInfo).await {
        CmdResult::NodeInfo { node } => {
            assert!(node.features.iter().any(|feature| feature == "offer_local"));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ws_tee_in_the_offers_profile_streams_the_call_once_it_is_answered() {
    let (ws_uri, frames, _downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let (_caller, caller_addr) = phone().await;
    let mut tee = profile(None, &["PCMU"]);
    tee.ws_tee = Some(ws_uri);
    offer_local(&engine, CALL, tee).await;
    assert!(
        timeout(Duration::from_millis(200), frames.recv_async())
            .await
            .is_err(),
        "nothing is dialled at the offer"
    );
    assert!(matches!(
        complete(
            &engine,
            CALL,
            plain_answer(caller_addr),
            ProfileFlags::default()
        )
        .await,
        CmdResult::Ok { .. }
    ));
    expect_ws_start(&frames).await;
}

// ---- review fixes -----------------------------------------------------------------------------

fn raw_answer(addr: SocketAddr, lines: &str) -> String {
    format!(
        "v=0\r\no=caller 10 10 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n{lines}",
        ip = addr.ip()
    )
}

/// An RTP packet from the caller on `payload_type`, carrying `payload`.
fn rtp_on(payload_type: u8, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x80, payload_type];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// Whether `socket` receives an RTP datagram on `payload_type` within `wait`.
async fn hears_payload_type(socket: &UdpSocket, payload_type: u8, wait: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + wait;
    let mut buffer = [0u8; 2048];
    while let Ok(Ok((len, _))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await
    {
        if len > 12 && buffer[1] & 0x7F == payload_type && !(64..=95).contains(&(buffer[1] & 0x7F))
        {
            return true;
        }
    }
    false
}

// 1. nothing latches or stamps before the answer, and an answer without ICE runs on the address

fn stun_engine(stun: SocketAddr) -> Engine<UdpLoopbackDatapath> {
    let engine = Engine::new(UdpLoopbackDatapath::new())
        .with_full_ice()
        .with_stun_servers(vec![stun]);
    let _events = engine.register_client(CLIENT);
    tokio::spawn(crate::srtp_bridge::run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    engine
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authenticated_check_before_the_answer_neither_latches_nor_keeps_the_call_alive() {
    // A silent STUN server makes the gathering run to its deadline with the datapath's responder
    // installed on the endpoint.
    let (_silent, stun) = phone().await;
    let engine = stun_engine(stun);
    let mut ice = profile(None, &["PCMU"]);
    ice.ice = Some("force".into());
    let offer = ok_sdp_text(&offer_local(&engine, CALL, ice).await);
    let info = sdp::parse(&offer).expect("offer");
    let near = engine
        .calls
        .get(CALL)
        .map(|call| call.near.rtp.id)
        .expect("call");
    let (holder, _) = phone().await;
    // Whoever holds the offered credentials: an authenticated nominating check.
    let check = siphon_rtp_stun::client::binding_request_ice(
        &[7u8; 12],
        &format!("{}:peer", info.ice_ufrag.expect("ufrag")),
        info.ice_pwd.expect("pwd").as_bytes(),
        100,
        siphon_rtp_stun::client::IceRole::Controlling(7),
        true,
    );
    holder.send_to(&check, info.remote_rtp).await.expect("send");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        engine.datapath().ice_validated_source(near),
        None,
        "no source may be latched before the answer"
    );
    assert_eq!(
        engine.datapath().last_activity(near).unwrap_or(0),
        0,
        "a check before the answer is not liveness: the setup reap still applies"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ice_offer_answered_without_ice_runs_media_on_the_signalled_address() {
    let (_silent, stun) = phone().await;
    let engine = stun_engine(stun);
    let (caller, caller_addr) = phone().await;
    let mut ice = profile(None, &["PCMU"]);
    ice.ice = Some("force".into());
    let offer = ok_sdp_text(&offer_local(&engine, CALL, ice).await);
    let engine_addr = engine_address(&offer);
    let without = caller_answer(caller_addr, "RTP/AVP", 0, "PCMU", "a=rtcp-mux\r\n");
    assert!(matches!(
        complete(&engine, CALL, without, ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    echo(&engine, CALL).await;
    for sequence in 0..30 {
        caller
            .send_to(&ulaw_rtp_packet(sequence, 0x0A0A_0A0A, 0x5C), engine_addr)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        hears_marker(&caller, 0x5C, Duration::from_secs(1)).await,
        "the legitimate caller's RTP is not gated by ICE state the answer never used"
    );
}

// 2. one decoder: another answered payload type is refused, never decoded as the wrong codec

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audio_on_another_answered_format_is_refused_and_the_selected_one_is_decoded() {
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let offer = ok_sdp_text(&offer_local(&engine, CALL, profile(None, &["PCMU", "PCMA"])).await);
    let engine_addr = engine_address(&offer);
    // The answer lists both, PCMU first: the engine runs on PCMU.
    let answer = raw_answer(
        caller_addr,
        "m=audio 4000 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n",
    )
    .replace("m=audio 4000", &format!("m=audio {}", caller_addr.port()));
    assert!(matches!(
        complete(&engine, CALL, answer, ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    echo(&engine, CALL).await;
    // PCMA bytes go nowhere near the PCMU decoder.
    for sequence in 0..25 {
        caller
            .send_to(&rtp_on(8, sequence, &[0x5D; 160]), engine_addr)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !hears_marker(&caller, 0x5D, Duration::from_millis(300)).await
            && !hears_payload_type(&caller, 8, Duration::from_millis(100)).await,
        "a PCMA packet is not decoded as PCMU"
    );
    for sequence in 100..125 {
        caller
            .send_to(&rtp_on(0, sequence, &[0x5E; 160]), engine_addr)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(hears_marker(&caller, 0x5E, Duration::from_secs(1)).await);
}

// 3. renumbering

fn g726_answer(addr: SocketAddr, audio: u8, event: u8) -> String {
    raw_answer(
        addr,
        &format!(
            "m=audio {port} RTP/AVP {audio} {event}\r\na=rtpmap:{audio} G726-32/8000\r\n\
             a=rtpmap:{event} telephone-event/8000\r\na=fmtp:{event} 0-15\r\na=sendrecv\r\n",
            port = addr.port()
        ),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renumbered_dynamic_format_is_received_on_the_offered_number_and_sent_on_the_answered_one(
) {
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let offer = ok_sdp_text(&offer_local(&engine, CALL, profile(None, &["G726-32"])).await);
    let info = sdp::parse(&offer).expect("offer");
    let offered_audio = info.payload_types[0];
    assert!(offered_audio >= 96, "a dynamic number: {offer}");
    let engine_addr = info.remote_rtp;
    let answered_audio = offered_audio + 1;
    assert!(matches!(
        complete(
            &engine,
            CALL,
            g726_answer(caller_addr, answered_audio, 111),
            ProfileFlags::default()
        )
        .await,
        CmdResult::Ok { .. }
    ));
    echo(&engine, CALL).await;
    // The caller sends on the number the engine offered; what comes back is on the caller's own.
    for sequence in 0..25 {
        caller
            .send_to(&rtp_on(offered_audio, sequence, &[0x11; 80]), engine_addr)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(hears_payload_type(&caller, answered_audio, Duration::from_secs(1)).await);
    // The answer's number is the caller's, not one the engine receives on.
    let heard_before = hears_payload_type(&caller, offered_audio, Duration::from_millis(100)).await;
    assert!(!heard_before, "nothing is sent on the offered number");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renumbered_telephone_event_keeps_dtmf_both_ways() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let (caller, caller_addr) = phone().await;
    let offer = ok_sdp_text(&offer_local(&engine, CALL, profile(None, &["G726-32"])).await);
    let info = sdp::parse(&offer).expect("offer");
    let offered_event = info.telephone_events()[0].payload_type;
    let engine_addr = info.remote_rtp;
    let answered_event = if offered_event == 111 { 112 } else { 111 };
    assert!(matches!(
        complete(
            &engine,
            CALL,
            g726_answer(caller_addr, info.payload_types[0], answered_event),
            ProfileFlags::default()
        )
        .await,
        CmdResult::Ok { .. }
    ));
    // Received on the offered number: the engine reports the digit.
    for sequence in 0..4u16 {
        let mut packet = rtp_on(offered_event, sequence, &[5, 0x8A, 0x03, 0x20]);
        packet[4..8].copy_from_slice(&1600u32.to_be_bytes());
        caller.send_to(&packet, engine_addr).await.expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut digit = None;
    for _ in 0..50 {
        if let Ok(Event::Dtmf { digit: heard, .. }) = events.try_recv() {
            digit = Some(heard);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        digit.as_deref(),
        Some("5"),
        "DTMF received on the offered number"
    );
    // Sent on the answered number.
    let played = engine
        .handle(
            CLIENT,
            Command::PlayDtmf {
                call_id: CALL.into(),
                from_tag: CALLER_TAG.into(),
                code: "7".into(),
                duration_ms: None,
                volume_dbm0: None,
                pause_ms: None,
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(played, CmdResult::Ok { .. }), "{played:?}");
    assert!(
        hears_payload_type(&caller, answered_event, Duration::from_secs(1)).await,
        "DTMF is sent on the number the answer gave"
    );
}

// 4. rtcp-mux: offered is not required

#[tokio::test]
async fn an_offered_mux_keeps_a_fallback_port_and_accepts_an_answer_that_declines_it() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let mut offered = profile(None, &["PCMU"]);
    offered.rtcp_mux = vec!["offer".into()];
    let offer = ok_sdp_text(&offer_local(&engine, CALL, offered.clone()).await);
    assert!(
        offer.contains("a=rtcp-mux\r\n") && offer.contains("a=rtcp:"),
        "{offer}"
    );
    assert!(!offer.contains("mux-only"), "{offer}");
    // Declined: separate RTCP, on the port the answer names.
    let declined = raw_answer(
        addr,
        &format!(
            "m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp:{rtcp}\r\n",
            port = addr.port(),
            rtcp = addr.port() + 1
        ),
    );
    assert!(matches!(
        complete(&engine, CALL, declined, ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    let call = engine.calls.get(CALL).expect("call");
    assert!(call.near.rtcp.is_some(), "the fallback RTCP port is kept");
    assert_eq!(
        call.near.remote_rtcp,
        Some(SocketAddr::new(addr.ip(), addr.port() + 1))
    );
    drop(call);
    // Accepted: the fallback port is released.
    let offer = ok_sdp_text(&offer_local(&engine, "mux", offered).await);
    let held = engine.endpoint_calls.len();
    let accepted = raw_answer(
        addr,
        &format!(
            "m=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n",
            addr.port()
        ),
    );
    let _ = offer;
    assert!(matches!(
        engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: "mux".into(),
                    from_tag: CALLER_TAG.into(),
                    to_tag: CONTROLLER_TAG.into(),
                    sdp: accepted,
                    profile: ProfileFlags::default(),
                },
            )
            .await,
        CmdResult::Ok { .. }
    ));
    assert_eq!(
        engine.endpoint_calls.len(),
        held - 1,
        "the unused RTCP port is freed"
    );
    assert!(engine.calls.get("mux").expect("call").near.rtcp.is_none());
}

#[tokio::test]
async fn a_required_mux_is_offered_exclusively_and_refuses_an_answer_that_declines_it() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let mut required = profile(None, &["PCMU"]);
    required.rtcp_mux = vec!["require".into()];
    let offer = ok_sdp_text(&offer_local(&engine, CALL, required).await);
    assert!(
        offer.contains("a=rtcp-mux\r\na=rtcp-mux-only\r\n"),
        "{offer}"
    );
    assert!(!offer.contains("a=rtcp:"), "{offer}");
    let declined = raw_answer(
        addr,
        &format!(
            "m=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
            addr.port()
        ),
    );
    let result = complete(&engine, CALL, declined, ProfileFlags::default()).await;
    assert!(
        is_error_containing(&result, "rtcp-mux-not-accepted"),
        "{result:?}"
    );
    assert!(pending(&engine, CALL));
}

// 5. the answer's direction applies to a takeover, for both verbs

async fn assert_a_sendonly_caller_is_sent_nothing(
    frames: &flume::Receiver<tokio_tungstenite::tungstenite::Message>,
    caller: &UdpSocket,
    engine_addr: SocketAddr,
) {
    caller
        .send_to(&ulaw_rtp_packet(7, 0x0A0A_0A0A, 0xFF), engine_addr)
        .await
        .expect("send");
    let uplink = next_uplink_frame(frames)
        .await
        .expect("the caller is still heard");
    assert_eq!(uplink.len(), 320);
    let mut buffer = [0u8; 2048];
    for _ in 0..10 {
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(60), caller.recv_from(&mut buffer)).await
        {
            panic!("a sendonly caller was sent {len} bytes (RFC 3264 §6.1)");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sendonly_answer_gets_no_bot_audio_and_no_comfort_idle_from_an_offer_local_takeover() {
    let (ws_uri, frames, _downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let mut takeover = profile(None, &["PCMU"]);
    takeover.ws_uri = Some(ws_uri);
    let offer = ok_sdp_text(&offer_local(&engine, CALL, takeover).await);
    let answer = plain_answer(caller_addr).replace("a=sendrecv", "a=sendonly");
    assert!(matches!(
        complete(&engine, CALL, answer, ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    assert_a_sendonly_caller_is_sent_nothing(&frames, &caller, engine_address(&offer)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sendonly_offer_gets_no_bot_audio_and_no_comfort_idle_from_an_answer_local_takeover() {
    let (ws_uri, frames, _downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\nm=audio {port} RTP/AVP 0\r\n\
         a=rtpmap:0 PCMU/8000\r\na=sendonly\r\n",
        ip = caller_addr.ip(),
        port = caller_addr.port()
    );
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al".into(),
                from_tag: CALLER_TAG.into(),
                sdp: offer,
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    let engine_addr = engine_address(&ok_sdp_text(&answered));
    assert_a_sendonly_caller_is_sent_nothing(&frames, &caller, engine_addr).await;
}

// 6. an answer consumes only the offer it was validated against

#[tokio::test]
async fn an_answer_validated_against_a_deleted_offer_cannot_complete_its_replacement() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let ingress = super::super::offer_local::LocalIngress {
        audio_payload_type: 0,
        event_payload_type: None,
        event_clock_rate_hz: None,
        other_formats_answered: false,
    };
    offer_local(&engine, CALL, profile(None, &["PCMU"])).await;
    let validated = engine
        .calls
        .get(CALL)
        .and_then(|call| call.pending_generation())
        .expect("generation of the first offer");
    // The interleaving: the call is deleted and offered again before the answer is consumed.
    delete(&engine, CALL).await;
    offer_local(&engine, CALL, profile(None, &["PCMU"])).await;
    let replacement = engine
        .calls
        .get(CALL)
        .and_then(|call| call.pending_generation())
        .expect("generation of the replacement");
    assert_ne!(validated, replacement);
    let refused =
        engine.consume_pending_offer(CLIENT, CALL, CALLER_TAG, validated, CONTROLLER_TAG, ingress);
    assert!(
        matches!(&refused, Err(reason) if reason.starts_with("offer-local-superseded")),
        "{refused:?}"
    );
    assert!(pending(&engine, CALL), "the replacement is left pending");
    // The right generation, the right owner and tag consume it; another tag or client does not.
    assert!(engine
        .consume_pending_offer(CLIENT, CALL, "other", replacement, CONTROLLER_TAG, ingress)
        .is_err());
    assert!(engine
        .consume_pending_offer(
            ClientId(2),
            CALL,
            CALLER_TAG,
            replacement,
            CONTROLLER_TAG,
            ingress
        )
        .is_err());
    assert!(engine
        .consume_pending_offer(
            CLIENT,
            CALL,
            CALLER_TAG,
            replacement,
            CONTROLLER_TAG,
            ingress
        )
        .is_ok());
}

// 7. an answered call is reaped like an answer_local one, from the moment of the answer

#[tokio::test]
async fn an_answer_just_before_the_setup_deadline_is_not_reaped_and_then_ages_by_the_media_timeout()
{
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    let (_phone, addr) = phone().await;
    offer_local(&engine, CALL, profile(None, &["PCMU"])).await;
    engine.datapath().advance_clock(299);
    assert!(matches!(
        complete(&engine, CALL, plain_answer(addr), ProfileFlags::default()).await,
        CmdResult::Ok { .. }
    ));
    engine.datapath().advance_clock(2);
    assert!(
        engine.reap_idle(30, 30, 300).await.is_empty(),
        "past the setup deadline of the offer, but the answer restarted the clock"
    );
    engine.datapath().advance_clock(40);
    assert_eq!(engine.reap_idle(30, 30, 300).await, vec![CALL.to_string()]);
    let reason = events.try_iter().find_map(|event| match event {
        Event::MediaTimeout { reason, .. } => Some(reason),
        _ => None,
    });
    assert_eq!(
        reason,
        Some(siphon_rtp_proto::MediaTimeoutReason::NoMedia),
        "reaped by the media timeout, as an answer_local call is"
    );
}

// ---- round 3 ------------------------------------------------------------------------------------

fn sendonly_offer(addr: SocketAddr, direction: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\nm=audio {port} RTP/AVP 0\r\n\
         a=rtpmap:0 PCMU/8000\r\na={direction}\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

async fn reoffer(engine: &Engine<UdpLoopbackDatapath>, call_id: &str, sdp: String) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: call_id.into(),
                from_tag: CALLER_TAG.into(),
                sdp,
                profile: ProfileFlags::default(),
            },
        )
        .await
}

async fn answer_local_with(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    sdp: String,
    ws_uri: Option<String>,
) -> SocketAddr {
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: call_id.into(),
                from_tag: CALLER_TAG.into(),
                sdp,
                profile: ProfileFlags {
                    ws_uri,
                    ..Default::default()
                },
            },
        )
        .await;
    engine_address(&ok_sdp_text(&answered))
}

fn push_downlink(downlink: &flume::Sender<Vec<u8>>) {
    let mut l16 = [0u8; 320];
    pcm_to_l16_le(&[2000i16; 160], &mut l16);
    for _ in 0..10 {
        downlink.send(l16.to_vec()).expect("queue downlink");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_takeover_started_held_resumes_its_downlink_after_a_sendrecv_reoffer() {
    let (ws_uri, _frames, downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let engine_addr = answer_local_with(
        &engine,
        "held",
        sendonly_offer(caller_addr, "sendonly"),
        Some(ws_uri),
    )
    .await;
    push_downlink(&downlink);
    assert!(
        !hears_payload_type(&caller, 0, Duration::from_millis(300)).await,
        "held: nothing is sent"
    );
    let resumed = reoffer(&engine, "held", sendonly_offer(caller_addr, "sendrecv")).await;
    assert!(matches!(resumed, CmdResult::Ok { .. }), "{resumed:?}");
    push_downlink(&downlink);
    let _ = engine_addr;
    assert!(
        hears_payload_type(&caller, 0, Duration::from_secs(1)).await,
        "resumed: the downlink flows again"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_takeover_started_sendrecv_stops_its_downlink_after_a_hold() {
    let (ws_uri, _frames, downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    answer_local_with(
        &engine,
        "live",
        sendonly_offer(caller_addr, "sendrecv"),
        Some(ws_uri),
    )
    .await;
    push_downlink(&downlink);
    assert!(hears_payload_type(&caller, 0, Duration::from_secs(1)).await);
    let held = reoffer(&engine, "live", sendonly_offer(caller_addr, "sendonly")).await;
    assert!(matches!(held, CmdResult::Ok { .. }), "{held:?}");
    // Whatever was in flight when the hold landed is gone after a moment.
    let _ = hears_payload_type(&caller, 0, Duration::from_millis(150)).await;
    push_downlink(&downlink);
    assert!(
        !hears_payload_type(&caller, 0, Duration::from_millis(400)).await,
        "held: the downlink stops"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attached_bridge_follows_the_callers_direction_across_a_resume() {
    let (ws_uri, _frames, downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    answer_local_with(
        &engine,
        "attach",
        sendonly_offer(caller_addr, "sendonly"),
        None,
    )
    .await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsBridge {
                call_id: "attach".into(),
                from_tag: CALLER_TAG.into(),
                ws_uri,
                profile: None,
            },
        )
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    push_downlink(&downlink);
    assert!(
        !hears_payload_type(&caller, 0, Duration::from_millis(300)).await,
        "a bridge attached to a held caller sends nothing"
    );
    let resumed = reoffer(&engine, "attach", sendonly_offer(caller_addr, "sendrecv")).await;
    assert!(matches!(resumed, CmdResult::Ok { .. }), "{resumed:?}");
    push_downlink(&downlink);
    assert!(hears_payload_type(&caller, 0, Duration::from_secs(1)).await);
}

// offer_far on a renumbered offer_local call

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_far_is_refused_on_a_renumbered_or_multi_format_answer_and_changes_nothing() {
    let engine = engine_with_dispatcher();
    let (_caller, caller_addr) = phone().await;
    let offer = ok_sdp_text(&offer_local(&engine, CALL, profile(None, &["G726-32"])).await);
    let info = sdp::parse(&offer).expect("offer");
    complete(
        &engine,
        CALL,
        g726_answer(
            caller_addr,
            info.payload_types[0] + 1,
            info.payload_types[1],
        ),
        ProfileFlags::default(),
    )
    .await;
    let far_offer = |call: &'static str| {
        engine.handle(
            CLIENT,
            Command::OfferFar {
                call_id: call.into(),
                from_tag: CALLER_TAG.into(),
                profile: ProfileFlags::default(),
            },
        )
    };
    let refused = far_offer(CALL).await;
    assert!(
        is_error_containing(&refused, "renumbered-payload-types"),
        "{refused:?}"
    );
    assert!(
        engine.calls.get(CALL).expect("call").far.is_none(),
        "no far leg was bound"
    );

    // Several answered formats: the caller may send any, and a relay would forward them unchanged.
    let multi = "multi";
    offer_local(&engine, multi, profile(None, &["PCMU", "PCMA"])).await;
    let answer = raw_answer(
        caller_addr,
        &format!(
            "m=audio {} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n",
            caller_addr.port()
        ),
    );
    complete_call(&engine, multi, answer).await;
    let refused = far_offer("multi").await;
    assert!(
        is_error_containing(&refused, "several-formats-answered"),
        "{refused:?}"
    );
}

async fn complete_call(engine: &Engine<UdpLoopbackDatapath>, call_id: &str, sdp: String) {
    let completed = complete(engine, call_id, sdp, ProfileFlags::default()).await;
    assert!(matches!(completed, CmdResult::Ok { .. }), "{completed:?}");
}

// the separate RTCP port of a single-leg call is not serviced: a counted drop, as for answer_local

fn rtcp_receiver_report() -> Vec<u8> {
    let mut packet = vec![0x80, 201, 0x00, 0x01];
    packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
    packet
}

async fn rtcp_drops(
    engine: &Engine<UdpLoopbackDatapath>,
    endpoint: siphon_rtp_datapath::EndpointId,
) -> u64 {
    engine
        .datapath()
        .stats(endpoint)
        .map_or(0, |stats| stats.packets_dropped)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_separate_rtcp_port_of_an_offer_local_call_is_a_counted_drop_like_answer_local() {
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let mut offered = profile(None, &["PCMU"]);
    offered.rtcp_mux = vec!["offer".into()];
    offer_local(&engine, CALL, offered).await;
    let declined = raw_answer(
        caller_addr,
        &format!(
            "m=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
            caller_addr.port()
        ),
    );
    complete_call(&engine, CALL, declined).await;
    let rtcp = engine
        .calls
        .get(CALL)
        .and_then(|call| call.near.rtcp)
        .expect("fallback port");
    let before = rtcp_drops(&engine, rtcp.id).await;
    caller
        .send_to(&rtcp_receiver_report(), rtcp.local_addr)
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        rtcp_drops(&engine, rtcp.id).await > before,
        "counted as dropped"
    );

    // answer_local does exactly the same with a caller that offered a separate RTCP port.
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-rtcp".into(),
                from_tag: CALLER_TAG.into(),
                sdp: sendonly_offer(caller_addr, "sendrecv"),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }));
    let rtcp = engine
        .calls
        .get("al-rtcp")
        .and_then(|call| call.near.rtcp)
        .expect("rtcp port");
    let before = rtcp_drops(&engine, rtcp.id).await;
    caller
        .send_to(&rtcp_receiver_report(), rtcp.local_addr)
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        rtcp_drops(&engine, rtcp.id).await > before,
        "answer_local counts the same drop"
    );
}

// telephone-events on a takeover are not refused with the audio

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_telephone_event_on_the_offered_type_reaches_a_takeover_and_is_not_dropped() {
    let (ws_uri, _frames, _downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let mut takeover = profile(None, &["PCMU"]);
    takeover.ws_uri = Some(ws_uri);
    let offer = ok_sdp_text(&offer_local(&engine, CALL, takeover).await);
    let info = sdp::parse(&offer).expect("offer");
    let event_pt = info.telephone_events()[0].payload_type;
    complete_call(&engine, CALL, plain_answer(caller_addr)).await;
    let near = engine
        .calls
        .get(CALL)
        .map(|call| call.near.rtp.id)
        .expect("call");
    for sequence in 0..5u16 {
        caller
            .send_to(
                &rtp_on(event_pt, sequence, &[5, 0x8A, 0x03, 0x20]),
                info.remote_rtp,
            )
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        engine.datapath().last_activity(near).unwrap_or(0) > 0,
        "the event is accepted: it stamps the leg alive"
    );
    assert_eq!(
        rtcp_drops(&engine, near).await,
        0,
        "and is not counted as a refusal"
    );
    // Audio on any other number is still refused, and counted.
    caller
        .send_to(&rtp_on(8, 9, &[0x55; 160]), info.remote_rtp)
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        rtcp_drops(&engine, near).await > 0,
        "audio on another payload type is counted"
    );
}

// ---- round 4 ------------------------------------------------------------------------------------

/// A WebSocket endpoint that accepts the TCP connection and holds it, so the engine's dial blocks
/// until the test lets go: `accepted` says the dial is in flight, `release` fails it.
async fn stalling_endpoint() -> (
    String,
    flume::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let (accepted_tx, accepted_rx) = flume::unbounded();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        accepted_tx.send(()).expect("announce");
        let _ = release_rx.await;
        drop(stream);
    });
    (format!("ws://{address}/stream"), accepted_rx, release_tx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_dial_of_an_answer_local_takeover_never_ends_a_replacement_call() {
    let (ws_uri, accepted, release) = stalling_endpoint().await;
    let engine = Arc::new(engine_with_dispatcher());
    let (_caller, caller_addr) = phone().await;
    let first = {
        let engine = engine.clone();
        tokio::spawn(async move {
            engine
                .handle(
                    CLIENT,
                    Command::AnswerLocal {
                        call_id: CALL.into(),
                        from_tag: CALLER_TAG.into(),
                        sdp: sendonly_offer(caller_addr, "sendrecv"),
                        profile: ProfileFlags {
                            ws_uri: Some(ws_uri),
                            ..Default::default()
                        },
                    },
                )
                .await
        })
    };
    accepted.recv_async().await.expect("the dial is in flight");
    // Another connection deletes the call and creates the call-id again while the dial is blocked.
    delete(&engine, CALL).await;
    let replacement = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: CALL.into(),
                from_tag: CALLER_TAG.into(),
                sdp: sendonly_offer(caller_addr, "sendrecv"),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(
        matches!(replacement, CmdResult::Ok { .. }),
        "{replacement:?}"
    );
    let replacement_instance = engine
        .calls
        .get(CALL)
        .map(|call| call.instance)
        .expect("replacement");
    release.send(()).expect("release the dial");
    let failed = first.await.expect("task");
    assert!(matches!(failed, CmdResult::Error { .. }), "{failed:?}");
    let call = engine
        .calls
        .get(CALL)
        .expect("the replacement survives the failed dial");
    assert_eq!(call.instance, replacement_instance);
    assert_eq!(
        call.pipeline,
        PipelineKind::Media,
        "and is still on its own pipeline"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_dial_of_an_offer_local_completion_never_ends_a_replacement_offer() {
    let (ws_uri, accepted, release) = stalling_endpoint().await;
    let engine = Arc::new(engine_with_dispatcher());
    let (_caller, caller_addr) = phone().await;
    let mut takeover = profile(None, &["PCMU"]);
    takeover.ws_uri = Some(ws_uri);
    offer_local(&engine, CALL, takeover).await;
    let completing = {
        let engine = engine.clone();
        tokio::spawn(async move {
            complete(
                &engine,
                CALL,
                plain_answer(caller_addr),
                ProfileFlags::default(),
            )
            .await
        })
    };
    accepted.recv_async().await.expect("the dial is in flight");
    delete(&engine, CALL).await;
    offer_local(&engine, CALL, profile(None, &["PCMU"])).await;
    release.send(()).expect("release the dial");
    let failed = completing.await.expect("task");
    assert!(matches!(failed, CmdResult::Error { .. }), "{failed:?}");
    assert!(
        pending(&engine, CALL),
        "the replacement offer survives, still pending and untouched"
    );
}

// events are not audio

async fn frames_within(
    frames: &flume::Receiver<tokio_tungstenite::tungstenite::Message>,
    wait: Duration,
) -> Vec<tokio_tungstenite::tungstenite::Message> {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Ok(message)) = tokio::time::timeout_at(deadline, frames.recv_async()).await {
        seen.push(message);
    }
    seen
}

async fn a_digit_is_a_dtmf_message_and_never_audio(
    ws_uri: String,
    frames: flume::Receiver<tokio_tungstenite::tungstenite::Message>,
    caller: UdpSocket,
    engine_addr: SocketAddr,
    event_pt: u8,
) {
    use tokio_tungstenite::tungstenite::Message;
    expect_ws_start(&frames).await;
    for (sequence, end) in [(0u16, false), (1, false), (2, true), (3, true)] {
        let mut packet = rtp_on(
            event_pt,
            sequence,
            &[5, if end { 0x8A } else { 0x0A }, 0x03, 0x20],
        );
        packet[4..8].copy_from_slice(&1600u32.to_be_bytes());
        caller.send_to(&packet, engine_addr).await.expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let seen = frames_within(&frames, Duration::from_millis(600)).await;
    let _ = ws_uri;
    assert!(
        seen.iter()
            .all(|message| !matches!(message, Message::Binary(_))),
        "the event payload produced an audio frame: {seen:?}"
    );
    let digits: Vec<&str> = seen
        .iter()
        .filter_map(|message| match message {
            Message::Text(text) if text.contains("\"dtmf\"") => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(digits.len(), 1, "one press, one dtmf message: {seen:?}");
    assert!(digits[0].contains("\"5\""), "{}", digits[0]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_digit_on_an_offer_local_takeover_is_a_dtmf_message_and_no_audio() {
    let (ws_uri, frames, _downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let mut takeover = profile(None, &["PCMU"]);
    takeover.ws_uri = Some(ws_uri.clone());
    let offer = ok_sdp_text(&offer_local(&engine, CALL, takeover).await);
    let info = sdp::parse(&offer).expect("offer");
    let event_pt = info.telephone_events()[0].payload_type;
    complete_call(&engine, CALL, plain_answer(caller_addr)).await;
    a_digit_is_a_dtmf_message_and_never_audio(ws_uri, frames, caller, info.remote_rtp, event_pt)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_digit_on_an_answer_local_takeover_is_a_dtmf_message_and_no_audio() {
    let (ws_uri, frames, _downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\nm=audio {port} RTP/AVP 0 101\r\n\
         a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=sendrecv\r\n",
        ip = caller_addr.ip(),
        port = caller_addr.port()
    );
    let engine_addr = answer_local_with(&engine, "al-dtmf", offer, Some(ws_uri.clone())).await;
    a_digit_is_a_dtmf_message_and_never_audio(ws_uri, frames, caller, engine_addr, 101).await;
}

// ---- round 5 ------------------------------------------------------------------------------------

/// A WebSocket endpoint that accepts the TCP connection, holds it until released, and then completes
/// the handshake and keeps the connection open: the dial blocks, then succeeds.
async fn gated_endpoint() -> (
    String,
    flume::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let (accepted_tx, accepted_rx) = flume::unbounded();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        use futures_util::StreamExt;
        let (stream, _) = listener.accept().await.expect("accept");
        accepted_tx.send(()).expect("announce");
        let _ = release_rx.await;
        if let Ok(socket) = tokio_tungstenite::accept_async(stream).await {
            let (_sink, mut source) = socket.split();
            while source.next().await.is_some() {}
        }
    });
    (format!("ws://{address}/stream"), accepted_rx, release_tx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_dial_on_the_offer_path_never_ends_a_replacement_call() {
    let (ws_uri, accepted, release) = stalling_endpoint().await;
    let engine = Arc::new(engine_with_dispatcher());
    let (_caller, caller_addr) = phone().await;
    let first = {
        let engine = engine.clone();
        tokio::spawn(async move {
            engine
                .handle(
                    CLIENT,
                    Command::Offer {
                        call_id: CALL.into(),
                        from_tag: CALLER_TAG.into(),
                        sdp: sdp_for(caller_addr, false),
                        profile: ProfileFlags {
                            ws_uri: Some(ws_uri),
                            ..Default::default()
                        },
                    },
                )
                .await
        })
    };
    accepted.recv_async().await.expect("the dial is in flight");
    delete(&engine, CALL).await;
    let replacement = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: CALL.into(),
                from_tag: CALLER_TAG.into(),
                sdp: sdp_for(caller_addr, false),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(
        matches!(replacement, CmdResult::Ok { .. }),
        "{replacement:?}"
    );
    let replacement_instance = engine
        .calls
        .get(CALL)
        .map(|call| call.instance)
        .expect("replacement");
    release.send(()).expect("release the dial");
    let failed = first.await.expect("task");
    assert!(matches!(failed, CmdResult::Error { .. }), "{failed:?}");
    assert_eq!(
        engine.calls.get(CALL).map(|call| call.instance),
        Some(replacement_instance),
        "the replacement offer survives the failed dial"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repoint_that_dials_while_the_call_is_replaced_never_takes_the_replacement_over() {
    let (first_uri, _frames, _downlink) = takeover_ws_server().await;
    let (second_uri, accepted, release) = gated_endpoint().await;
    let engine = Arc::new(engine_with_dispatcher());
    let (_caller, caller_addr) = phone().await;
    answer_local_with(
        &engine,
        CALL,
        sendonly_offer(caller_addr, "sendrecv"),
        Some(first_uri),
    )
    .await;
    let repoint = {
        let engine = engine.clone();
        tokio::spawn(async move {
            engine
                .handle(
                    CLIENT,
                    Command::AttachWsBridge {
                        call_id: CALL.into(),
                        from_tag: CALLER_TAG.into(),
                        ws_uri: second_uri,
                        profile: None,
                    },
                )
                .await
        })
    };
    accepted
        .recv_async()
        .await
        .expect("the re-point dial is in flight");
    delete(&engine, CALL).await;
    answer_local_with(&engine, CALL, sendonly_offer(caller_addr, "sendrecv"), None).await;
    release.send(()).expect("let the dial succeed");
    let result = repoint.await.expect("task");
    assert!(
        matches!(&result, CmdResult::Error { reason } if reason.contains("call-superseded")),
        "{result:?}"
    );
    assert!(
        !engine.ws().is_ws_call(CALL),
        "the replacement was not taken over by the stale re-point"
    );
    assert_eq!(
        engine.calls.get(CALL).map(|call| call.pipeline),
        Some(PipelineKind::Media)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_event_is_timed_by_its_own_clock_not_the_audio_codecs() {
    // Opus runs at 48 kHz and the caller declared telephone-event/8000: 800 units are 100 ms, not
    // 16 ms.
    let (ws_uri, frames, _downlink) = takeover_ws_server().await;
    let engine = engine_with_dispatcher();
    let (caller, caller_addr) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\nm=audio {port} RTP/AVP 111 101\r\n\
         a=rtpmap:111 opus/48000/2\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=sendrecv\r\n",
        ip = caller_addr.ip(),
        port = caller_addr.port()
    );
    let engine_addr = answer_local_with(&engine, "opus-dtmf", offer, Some(ws_uri)).await;
    expect_ws_start(&frames).await;
    for sequence in 0..3u16 {
        let mut packet = rtp_on(101, sequence, &[5, 0x8A, 0x03, 0x20]);
        packet[4..8].copy_from_slice(&1600u32.to_be_bytes());
        caller.send_to(&packet, engine_addr).await.expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let seen = frames_within(&frames, Duration::from_millis(600)).await;
    let dtmf = seen
        .iter()
        .find_map(|message| match message {
            tokio_tungstenite::tungstenite::Message::Text(text) if text.contains("\"dtmf\"") => {
                serde_json::from_str::<serde_json::Value>(text.as_str()).ok()
            }
            _ => None,
        })
        .expect("a dtmf message");
    assert_eq!(dtmf["data"]["durationMs"], 100, "{dtmf}");
}
