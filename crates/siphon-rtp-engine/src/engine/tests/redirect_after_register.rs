//! A redirected endpoint's handler is registered before the redirect lands. The instant a `Redirect`
//! is installed on an endpoint its first datagram reaches the dispatcher, and one that finds no
//! handler there is dropped ("redirected datagram with no consumer"). So the registry that owns the
//! endpoint must already know it when the flow is installed, and the gate it carries must already be
//! in place: registering first lets nothing through, because nothing reaches a registry until the
//! `Redirect` routes it there, and the registered flow checks the source before it relays.

use super::*;
use siphon_rtp_proto::{ProfileFlags, VideoRelay};

/// `(endpoint, whether a handler owned it the moment its redirect landed)`, in install order.
type Redirects = Arc<Mutex<Vec<(EndpointId, bool)>>>;

/// Which registry has to own an endpoint when its redirect lands.
#[derive(Clone, Copy)]
enum Handler {
    Bridge,
    Media,
    Text,
    Udptl,
    DtlsBridge,
}

fn recording_engine(handler: Handler) -> (Engine<LatchLearningDatapath>, Redirects) {
    let datapath = LatchLearningDatapath::new();
    let engine = Engine::new(datapath.clone());
    let redirects: Redirects = Arc::new(Mutex::new(Vec::new()));
    let (seen, bridge, media) = (redirects.clone(), engine.bridge(), engine.media());
    let (text, udptl, dtls) = (engine.text(), engine.udptl(), engine.dtls_bridge());
    datapath.on_redirect(move |endpoint| {
        let owned = match handler {
            Handler::Bridge => bridge.owns(endpoint),
            Handler::Media => media.owns(endpoint),
            Handler::Text => text.owns(endpoint),
            Handler::Udptl => udptl.owns(endpoint),
            Handler::DtlsBridge => dtls.owns(endpoint),
        };
        seen.lock().expect("redirect log").push((endpoint, owned));
    });
    (engine, redirects)
}

fn sdp_with_video(
    audio: SocketAddr,
    video: SocketAddr,
    video_key: Option<&CryptoAttribute>,
) -> String {
    let (profile, key) = match video_key {
        Some(key) => ("RTP/SAVP", format!("a={}\r\n", key.to_attribute_value())),
        None => ("RTP/AVP", String::new()),
    };
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {audio_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
         m=video {video_port} {profile} 96\r\na=rtpmap:96 H264/90000\r\na=sendrecv\r\na=rtcp-mux\r\n{key}",
        ip = audio.ip(),
        audio_port = audio.port(),
        video_port = video.port(),
    )
}

fn plain_sdp(audio: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\na=rtcp-mux\r\n",
        ip = audio.ip(),
        port = audio.port(),
    )
}

async fn plain_call(engine: &Engine<LatchLearningDatapath>, call_id: &str) {
    let (_a, a_addr) = phone().await;
    let (_b, b_addr) = phone().await;
    for command in [
        Command::Offer {
            call_id: call_id.into(),
            from_tag: "a".into(),
            sdp: plain_sdp(a_addr),
            profile: ProfileFlags::default(),
        },
        Command::Answer {
            call_id: call_id.into(),
            from_tag: "a".into(),
            to_tag: "b".into(),
            sdp: plain_sdp(b_addr),
            profile: ProfileFlags::default(),
        },
    ] {
        let result = engine.handle(CLIENT, command).await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    }
}

fn assert_owned_at_redirect(redirects: &Redirects, what: &str) {
    let seen = redirects.lock().expect("redirect log").clone();
    assert!(!seen.is_empty(), "{what}: no endpoint was redirected");
    for (endpoint, owned) in seen {
        assert!(
            owned,
            "{what}: {endpoint:?} was redirected before a handler owned it, so its first datagram is dropped"
        );
    }
}

#[tokio::test]
async fn a_secure_video_bridge_owns_its_endpoints_before_they_are_redirected() {
    let (engine, redirects) = recording_engine(Handler::Bridge);
    let (_a_audio, a_audio) = phone().await;
    let (_a_video, a_video) = phone().await;
    let (_b_audio, b_audio) = phone().await;
    let (_b_video, b_video) = phone().await;
    let key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
    let profile = ProfileFlags {
        video_relay: VideoRelay::Anchor,
        ..ProfileFlags::default()
    };
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "secure-video".into(),
                from_tag: "a".into(),
                sdp: sdp_with_video(a_audio, a_video, Some(&key)),
                profile: profile.clone(),
            },
        )
        .await;
    assert!(matches!(offered, CmdResult::Ok { .. }), "{offered:?}");
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "secure-video".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_with_video(b_audio, b_video, None),
                profile,
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    assert_owned_at_redirect(&redirects, "secure video");
}

#[tokio::test]
async fn a_promoted_relay_owns_its_endpoints_before_they_are_redirected() {
    let (engine, redirects) = recording_engine(Handler::Media);
    plain_call(&engine, "relay-promotion").await;
    assert!(redirects.lock().expect("redirect log").is_empty());
    let held = engine
        .hold_in_userspace(
            "relay-promotion",
            PromotionReason::MediaOp,
            PromoteMode::RelayOnly,
        )
        .await;
    assert!(held.is_ok(), "{held:?}");
    assert_owned_at_redirect(&redirects, "relay promotion");
}

#[tokio::test]
async fn a_promoted_processing_call_owns_its_endpoints_before_they_are_redirected() {
    let (engine, redirects) = recording_engine(Handler::Media);
    plain_call(&engine, "processing-promotion").await;
    let held = engine
        .hold_in_userspace(
            "processing-promotion",
            PromotionReason::MediaOp,
            PromoteMode::Processing,
        )
        .await;
    assert!(held.is_ok(), "{held:?}");
    assert_owned_at_redirect(&redirects, "processing promotion");
}

fn text_sdp(audio: SocketAddr, text: SocketAddr, key: Option<&CryptoAttribute>) -> String {
    match key {
        Some(key) => audio_secure_text_sdp(audio, text, key),
        None => audio_plaintext_text_sdp(audio, text),
    }
}

async fn text_call(engine: &Engine<LatchLearningDatapath>, call_id: &str, secure: bool) {
    let (_a_audio, a_audio) = phone().await;
    let (_a_text, a_text) = phone().await;
    let (_b_audio, b_audio) = phone().await;
    let (_b_text, b_text) = phone().await;
    let key = |tag| CryptoAttribute::generate(tag, CryptoSuite::AesCm128HmacSha1_80).expect("key");
    let (a_key, b_key) = (key(1), key(1));
    let (a_key, b_key) = (secure.then_some(&a_key), secure.then_some(&b_key));
    for command in [
        Command::Offer {
            call_id: call_id.into(),
            from_tag: "a".into(),
            sdp: text_sdp(a_audio, a_text, a_key),
            profile: ProfileFlags::default(),
        },
        Command::Answer {
            call_id: call_id.into(),
            from_tag: "a".into(),
            to_tag: "b".into(),
            sdp: text_sdp(b_audio, b_text, b_key),
            profile: ProfileFlags::default(),
        },
    ] {
        let result = engine.handle(CLIENT, command).await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    }
}

#[tokio::test]
async fn a_promoted_text_stream_owns_its_endpoints_before_they_are_redirected() {
    let (engine, redirects) = recording_engine(Handler::Text);
    text_call(&engine, "text-promotion", false).await;
    assert!(redirects.lock().expect("redirect log").is_empty());
    let held = engine
        .hold_text_in_userspace("text-promotion", PromotionReason::TextEvents)
        .await;
    assert!(held.is_ok(), "{held:?}");
    assert_owned_at_redirect(&redirects, "text promotion");
}

#[tokio::test]
async fn a_secure_text_stream_owns_its_endpoints_before_they_are_redirected() {
    let (engine, redirects) = recording_engine(Handler::Text);
    text_call(&engine, "secure-text", true).await;
    assert_owned_at_redirect(&redirects, "secure text");
}

#[tokio::test]
async fn a_udptl_fax_relay_owns_its_endpoints_before_they_are_redirected() {
    let (engine, redirects) = recording_engine(Handler::Udptl);
    let image_sdp = |audio: SocketAddr, image: SocketAddr| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {aport} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
             m=image {iport} udptl t38\r\n\
             a=T38FaxVersion:0\r\na=T38MaxBitRate:14400\r\n\
             a=T38FaxRateManagement:transferredTCF\r\na=T38FaxUdpEC:t38UDPRedundancy\r\n",
            ip = audio.ip(),
            aport = audio.port(),
            iport = image.port(),
        )
    };
    let (_a_audio, a_audio) = phone().await;
    let (_a_image, a_image) = phone().await;
    let (_b_audio, b_audio) = phone().await;
    let (_b_image, b_image) = phone().await;
    for command in [
        Command::Offer {
            call_id: "fax".into(),
            from_tag: "a".into(),
            sdp: image_sdp(a_audio, a_image),
            profile: ProfileFlags::default(),
        },
        Command::Answer {
            call_id: "fax".into(),
            from_tag: "a".into(),
            to_tag: "b".into(),
            sdp: image_sdp(b_audio, b_image),
            profile: ProfileFlags::default(),
        },
    ] {
        let result = engine.handle(CLIENT, command).await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    }
    assert_owned_at_redirect(&redirects, "udptl fax");
}

async fn dtls_video_call(
    call_id: &str,
    bundled: bool,
) -> (Engine<LatchLearningDatapath>, Redirects) {
    let (engine, redirects) = recording_engine(Handler::DtlsBridge);
    let (_a, a_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (_a_video, a_video) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (_b_audio, b_audio) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let (_b_video, b_video) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let caller = siphon_rtp_dtls::DtlsCertificate::generate().expect("caller cert");
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                sdp: call_video_dtls::dtls_offer(
                    a_addr,
                    if bundled { a_addr } else { a_video },
                    &caller.fingerprint(),
                    bundled,
                    "sendrecv",
                ),
                profile: call_video_dtls::dtls_caller_profile(),
            },
        )
        .await;
    assert!(matches!(offered, CmdResult::Ok { .. }), "{offered:?}");
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: call_video_dtls::plain_answer(b_audio, b_video, "sendrecv"),
                profile: call_video_dtls::dtls_caller_profile(),
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    (engine, redirects)
}

/// Every endpoint the DTLS video install redirected was owned by the DTLS bridge at that instant. The
/// audio association's own endpoints are not this install's, so only the video flows are judged.
fn assert_video_owned_at_redirect(
    engine: &Engine<LatchLearningDatapath>,
    call_id: &str,
    redirects: &Redirects,
    what: &str,
) {
    let video_redirects: Vec<EndpointId> = engine
        .calls
        .get(call_id)
        .expect("call")
        .video
        .flows
        .iter()
        .filter(|(_, action)| *action == FlowAction::Redirect)
        .map(|(endpoint, _)| *endpoint)
        .collect();
    assert!(!video_redirects.is_empty(), "{what}: no video redirect");
    let seen = redirects.lock().expect("redirect log").clone();
    for endpoint in video_redirects {
        let owned = seen
            .iter()
            .find(|(redirected, _)| *redirected == endpoint)
            .map(|(_, owned)| *owned);
        assert_eq!(
            owned,
            Some(true),
            "{what}: {endpoint:?} was redirected before the DTLS bridge owned it"
        );
    }
}

#[tokio::test]
async fn a_bundled_dtls_video_leg_owns_its_endpoint_before_it_is_redirected() {
    let (engine, redirects) = dtls_video_call("dtls-bundled", true).await;
    assert_video_owned_at_redirect(&engine, "dtls-bundled", &redirects, "bundled dtls video");
}

#[tokio::test]
async fn an_unbundled_dtls_video_leg_owns_its_endpoints_before_they_are_redirected() {
    let (engine, redirects) = dtls_video_call("dtls-unbundled", false).await;
    assert_video_owned_at_redirect(
        &engine,
        "dtls-unbundled",
        &redirects,
        "unbundled dtls video",
    );
}
