//! A redirected endpoint's handler is registered before the redirect lands. The instant a `Redirect`
//! is installed on an endpoint its first datagram reaches the dispatcher, and one that finds no
//! handler there is dropped ("redirected datagram with no consumer"). So the registry that owns the
//! endpoint must already know it when the flow is installed, and the gate it carries must already be
//! in place: registering first lets nothing through, because nothing reaches a registry until the
//! `Redirect` routes it there, and the registered flow checks the source before it relays.

use super::*;
use siphon_rtp_proto::{ProfileFlags, VideoRelay};

/// `(endpoint, whether a handler owned it the moment its redirect landed)`, in install order.
pub(super) type Redirects = Arc<Mutex<Vec<(EndpointId, bool)>>>;

/// Which registry has to own an endpoint when its redirect lands.
#[derive(Clone, Copy)]
pub(super) enum Handler {
    Bridge,
    Media,
    Text,
    Udptl,
    /// Any registry that terminates or relays a call's audio: the SRTP and DTLS bridges or the media
    /// registry.
    Audio,
    /// The call-floor registry.
    Floor,
}

fn recording_engine(handler: Handler) -> (Engine<LatchLearningDatapath>, Redirects) {
    recording_engine_over(LatchLearningDatapath::new(), handler)
}

pub(super) fn recording_engine_over(
    datapath: LatchLearningDatapath,
    handler: Handler,
) -> (Engine<LatchLearningDatapath>, Redirects) {
    let engine = Engine::new(datapath.clone());
    let redirects: Redirects = Arc::new(Mutex::new(Vec::new()));
    let (seen, bridge, media) = (redirects.clone(), engine.bridge(), engine.media());
    let (text, udptl) = (engine.text(), engine.udptl());
    let floors = engine.conference().floors().clone();
    datapath.on_redirect(move |endpoint| {
        let owned = match handler {
            Handler::Bridge => bridge.owns(endpoint),
            Handler::Media => media.owns(endpoint),
            Handler::Text => text.owns(endpoint),
            Handler::Udptl => udptl.owns(endpoint),
            Handler::Audio => bridge.owns(endpoint) || media.owns(endpoint),
            Handler::Floor => floors.owns(endpoint),
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

pub(super) fn assert_owned_at_redirect(redirects: &Redirects, what: &str) {
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
    let (engine, redirects) = recording_engine(Handler::Audio);
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

#[tokio::test]
async fn a_bundled_dtls_video_leg_owns_its_endpoint_before_it_is_redirected() {
    let (_engine, redirects) = dtls_video_call("dtls-bundled", true).await;
    assert_owned_at_redirect(&redirects, "bundled dtls video call");
}

#[tokio::test]
async fn an_unbundled_dtls_video_leg_owns_its_endpoints_before_they_are_redirected() {
    let (_engine, redirects) = dtls_video_call("dtls-unbundled", false).await;
    assert_owned_at_redirect(&redirects, "unbundled dtls video call");
}

/// Offer from a plain caller with `offer_profile`, answer with `answer_sdp`, and return what every
/// redirect of the call found owning its endpoint.
async fn audio_call(
    call_id: &str,
    offer_sdp: String,
    offer_profile: ProfileFlags,
    answer_sdp: impl FnOnce(&sdp::MediaInfo) -> String,
) -> Redirects {
    let (engine, redirects) = recording_engine(Handler::Audio);
    negotiate(&engine, call_id, offer_sdp, offer_profile, answer_sdp).await;
    redirects
}

async fn negotiate<D: Datapath + Clone + Send + 'static>(
    engine: &Engine<D>,
    call_id: &str,
    offer_sdp: String,
    offer_profile: ProfileFlags,
    answer_sdp: impl FnOnce(&sdp::MediaInfo) -> String,
) {
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                sdp: offer_sdp,
                profile: offer_profile.clone(),
            },
        )
        .await;
    let to_b = sdp::parse(&ok_sdp_text(&offered)).expect("the offer sent to B");
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: answer_sdp(&to_b),
                profile: offer_profile,
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
}

fn secure_far(record: bool) -> ProfileFlags {
    ProfileFlags {
        transport_protocol: Some("RTP/SAVP".into()),
        record_call: record,
        ..ProfileFlags::default()
    }
}

fn savp_key() -> CryptoAttribute {
    CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key")
}

#[tokio::test]
async fn an_srtp_bridge_owns_both_legs_before_they_are_redirected() {
    let (_a, a_addr) = phone().await;
    let (_b, b_addr) = phone().await;
    let key = savp_key();
    let redirects = audio_call(
        "srtp-bridge",
        sdp_for(a_addr, true),
        secure_far(false),
        |_| savp_answer_sdp(b_addr, &key),
    )
    .await;
    assert_owned_at_redirect(&redirects, "srtp bridge");
}

#[tokio::test]
async fn a_transcrypt_bridge_owns_both_legs_before_they_are_redirected() {
    let (_a, a_addr) = phone().await;
    let (_b, b_addr) = phone().await;
    let (a_key, b_key) = (savp_key(), savp_key());
    let redirects = audio_call(
        "transcrypt-bridge",
        savp_answer_sdp(a_addr, &a_key),
        secure_far(false),
        |_| savp_answer_sdp(b_addr, &b_key),
    )
    .await;
    assert_owned_at_redirect(&redirects, "transcrypt bridge");
}

#[tokio::test]
async fn a_secure_transcode_owns_both_legs_before_they_are_redirected() {
    let (_a, a_addr) = phone().await;
    let (_b, b_addr) = phone().await;
    let key = savp_key();
    let redirects = audio_call(
        "srtp-media",
        sdp_single_codec(a_addr, 0, "PCMU"),
        secure_far(false),
        |_| savp_answer_codec(b_addr, 8, "PCMA", &key),
    )
    .await;
    assert_owned_at_redirect(&redirects, "secure transcode");
}

#[tokio::test]
async fn a_secure_to_secure_media_pipeline_owns_both_legs_before_they_are_redirected() {
    let (_a, a_addr) = phone().await;
    let (_b, b_addr) = phone().await;
    let (a_key, b_key) = (savp_key(), savp_key());
    let redirects = audio_call(
        "transcrypt-media",
        savp_answer_sdp(a_addr, &a_key),
        secure_far(true),
        |_| savp_answer_sdp(b_addr, &b_key),
    )
    .await;
    assert_owned_at_redirect(&redirects, "secure to secure media");
}

#[tokio::test]
async fn a_transcoding_call_owns_both_legs_before_they_are_redirected() {
    let (_a, a_addr) = phone().await;
    let (_b, b_addr) = phone().await;
    let redirects = audio_call(
        "plain-media",
        sdp_single_codec(a_addr, 0, "PCMU"),
        ProfileFlags::default(),
        |_| sdp_single_codec(b_addr, 8, "PCMA"),
    )
    .await;
    assert_owned_at_redirect(&redirects, "plain media pipeline");
}

/// The answer a DTLS-SRTP callee gives: its own certificate, `setup:active`.
fn dtls_answer(addr: SocketAddr) -> String {
    let certificate = siphon_rtp_dtls::DtlsCertificate::generate().expect("cert");
    let fingerprint = certificate.fingerprint();
    let hex = fingerprint
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
         a=setup:active\r\na=fingerprint:{hash} {hex}\r\n",
        ip = addr.ip(),
        port = addr.port(),
        hash = fingerprint.hash_function,
    )
}

fn dtls_far(record: bool) -> ProfileFlags {
    ProfileFlags {
        transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
        record_call: record,
        ..ProfileFlags::default()
    }
}

#[tokio::test]
async fn a_dtls_far_bridge_owns_both_legs_before_they_are_redirected() {
    let (_a, a_addr) = phone().await;
    let (_b, b_addr) = phone().await;
    let redirects = audio_call(
        "dtls-bridge",
        sdp_for(a_addr, true),
        dtls_far(false),
        |_| dtls_answer(b_addr),
    )
    .await;
    assert_owned_at_redirect(&redirects, "dtls far bridge");
}

#[tokio::test]
async fn a_dtls_far_media_pipeline_owns_both_legs_before_they_are_redirected() {
    let (_a, a_addr) = phone().await;
    let (_b, b_addr) = phone().await;
    let redirects = audio_call("dtls-media", sdp_for(a_addr, true), dtls_far(true), |_| {
        dtls_answer(b_addr)
    })
    .await;
    assert_owned_at_redirect(&redirects, "dtls far media");
}

#[tokio::test]
async fn a_dtls_offerer_media_pipeline_owns_both_legs_before_they_are_redirected() {
    // A DTLS caller toward a plain callee, with recording: the actor holds the decoded audio.
    let (_a, a_addr) = phone().await;
    let (_b, b_addr) = phone().await;
    let certificate = siphon_rtp_dtls::DtlsCertificate::generate().expect("cert");
    let fingerprint = certificate.fingerprint();
    let hex = fingerprint
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
         a=setup:actpass\r\na=fingerprint:{hash} {hex}\r\n",
        ip = a_addr.ip(),
        port = a_addr.port(),
        hash = fingerprint.hash_function,
    );
    let profile = ProfileFlags {
        transport_protocol: Some("RTP/AVP".into()),
        record_call: true,
        ..ProfileFlags::default()
    };
    let redirects = audio_call("dtls-offerer-media", offer, profile, |_| {
        sdp_for(b_addr, true)
    })
    .await;
    assert_owned_at_redirect(&redirects, "dtls offerer media");
}

/// Fail a call over to a standby on the same ports and return what every redirect of its restore
/// found owning its endpoint. The standby's ports are the primary's, so the phones keep sending to
/// them: the first datagram of a restored call arrives the instant its `Redirect` lands.
async fn restored_redirects(
    range: (u16, u16),
    call_id: &str,
    offer_sdp: String,
    profile: ProfileFlags,
    answer_sdp: impl FnOnce(&sdp::MediaInfo) -> String,
) -> Redirects {
    let bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let primary = Engine::new(UdpLoopbackDatapath::with_port_range(bind, range.0, range.1));
    let _events = primary.register_client(CLIENT);
    negotiate(&primary, call_id, offer_sdp, profile, answer_sdp).await;
    let CmdResult::Checkpoint { snapshot } = primary
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: call_id.into(),
                from_tag: "a".into(),
            },
        )
        .await
    else {
        panic!("expected a checkpoint");
    };
    primary
        .handle(
            CLIENT,
            Command::Delete {
                call_id: call_id.into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    drop(primary);
    let datapath =
        LatchLearningDatapath::over(UdpLoopbackDatapath::with_port_range(bind, range.0, range.1));
    let (standby, redirects) = recording_engine_over(datapath, Handler::Audio);
    let _events = standby.register_client(CLIENT);
    let restored = standby.handle(CLIENT, Command::Restore { snapshot }).await;
    assert!(matches!(restored, CmdResult::Ok { .. }), "{restored:?}");
    redirects
}

#[tokio::test]
async fn a_restored_srtp_bridge_owns_its_endpoints_before_they_are_redirected() {
    let (_a, a_addr) = phone().await;
    let (_b, b_addr) = phone().await;
    let key = savp_key();
    let redirects = restored_redirects(
        (31_100, 31_140),
        "restore-srtp-bridge",
        sdp_for(a_addr, true),
        secure_far(false),
        |_| savp_answer_sdp(b_addr, &key),
    )
    .await;
    assert_owned_at_redirect(&redirects, "restored srtp bridge");
}

#[tokio::test]
async fn a_restored_transcoding_call_owns_its_endpoints_before_they_are_redirected() {
    let (_a, a_addr) = phone().await;
    let (_b, b_addr) = phone().await;
    let redirects = restored_redirects(
        (31_200, 31_240),
        "restore-media",
        sdp_single_codec(a_addr, 0, "PCMU"),
        ProfileFlags::default(),
        |_| sdp_single_codec(b_addr, 8, "PCMA"),
    )
    .await;
    assert_owned_at_redirect(&redirects, "restored media pipeline");
}

#[tokio::test]
async fn a_restored_secure_transcode_owns_its_endpoints_before_they_are_redirected() {
    let (_a, a_addr) = phone().await;
    let (_b, b_addr) = phone().await;
    let key = savp_key();
    let redirects = restored_redirects(
        (31_300, 31_340),
        "restore-srtp-media",
        sdp_single_codec(a_addr, 0, "PCMU"),
        secure_far(false),
        |_| savp_answer_codec(b_addr, 8, "PCMA", &key),
    )
    .await;
    assert_owned_at_redirect(&redirects, "restored secure transcode");
}

#[tokio::test]
async fn an_injected_far_video_leg_owns_its_endpoint_before_it_is_redirected() {
    let (engine, redirects) = recording_engine(Handler::Audio);
    let (_caller_audio, caller_audio) = phone().await;
    let (_caller_video, caller_video) = phone().await;
    let (_callee_audio, callee_audio) = phone().await;
    let (_callee_video, callee_video) = phone().await;
    let caller_offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {audio_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\na=rtcp-mux\r\n\
         m=video {video_port} RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n\
         a=fmtp:96 profile-level-id=42e01f;packetization-mode=1\r\na=sendrecv\r\na=rtcp-mux\r\n",
        ip = caller_audio.ip(),
        audio_port = caller_audio.port(),
        video_port = caller_video.port(),
    );
    let callee_answer = format!(
        "v=0\r\no=- 2 2 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {audio_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\na=rtcp-mux\r\n\
         m=video {video_port} RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n\
         a=fmtp:96 profile-level-id=42e01f;packetization-mode=1;sprop-parameter-sets=Z0LAHtoCgPZA,aM48gA==\r\n\
         a=sendrecv\r\na=rtcp-mux\r\n",
        ip = callee_audio.ip(),
        audio_port = callee_audio.port(),
        video_port = callee_video.port(),
    );
    let profile = ProfileFlags {
        video_relay: VideoRelay::Anchor,
        ..ProfileFlags::default()
    };
    for command in [
        Command::AnswerLocal {
            call_id: "injected".into(),
            from_tag: "a".into(),
            sdp: caller_offer,
            profile: profile.clone(),
        },
        Command::OfferFar {
            call_id: "injected".into(),
            from_tag: "a".into(),
            profile: ProfileFlags::default(),
        },
        Command::Answer {
            call_id: "injected".into(),
            from_tag: "a".into(),
            to_tag: "b".into(),
            sdp: callee_answer,
            profile: ProfileFlags::default(),
        },
    ] {
        let result = engine.handle(CLIENT, command).await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    }
    assert_owned_at_redirect(&redirects, "injected far video");
    let far_video = engine
        .calls
        .get("injected")
        .and_then(|call| call.far.as_ref().and_then(|far| far.video))
        .expect("the far video leg")
        .rtp
        .id;
    assert!(
        engine.bridge().owns(far_video),
        "the far video endpoint is carried by the bridge"
    );
    // The far video endpoint is never given a Forward rule it would relay the first IDR by: it goes
    // from parked straight to the redirect the bridge already owns.
    let installed: Vec<FlowAction> = engine
        .datapath()
        .take_installs()
        .into_iter()
        .filter(|(endpoint, _)| *endpoint == far_video)
        .map(|(_, action)| action)
        .collect();
    assert!(
        !installed
            .iter()
            .any(|action| matches!(action, FlowAction::Forward(_))),
        "no Forward before the Redirect: {installed:?}"
    );
    assert_eq!(installed.last(), Some(&FlowAction::Redirect));
    let seen = redirects.lock().expect("redirect log").clone();
    assert!(
        seen.contains(&(far_video, true)),
        "the far video endpoint was redirected, owned: {seen:?}"
    );
}
