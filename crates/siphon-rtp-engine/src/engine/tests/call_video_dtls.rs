//! DTLS-SRTP on an anchored two-party video stream, over the UDP loopback datapath with real DTLS
//! handshakes on the phones' side: a DTLS party keys its own [`SecureLeg`] from the handshake it runs
//! against the engine, so a packet only decrypts when the engine keyed the association the way the
//! SDP said (RFC 5764, RFC 8843).

use super::call_video::{anchor, received, receiver_report, video_packet, CAMERA_PAYLOAD};
use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_dtls::DtlsCertificate;
use siphon_rtp_srtp::leg::SecureLeg;

fn hex(fingerprint: &siphon_rtp_dtls::Fingerprint) -> String {
    fingerprint
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A DTLS caller's offer: audio and one video section, both `UDP/TLS/RTP/SAVPF` with the caller's
/// certificate. Bundled (RFC 8843), the two share `audio`'s address, a group and mids; unbundled, the
/// video has its own address.
pub(super) fn dtls_offer(
    audio: SocketAddr,
    video: SocketAddr,
    fingerprint: &siphon_rtp_dtls::Fingerprint,
    bundled: bool,
    direction: &str,
) -> String {
    let (group, audio_mid, video_mid, video_port) = if bundled {
        (
            "a=group:BUNDLE 0 1\r\n",
            "a=mid:0\r\n",
            "a=mid:1\r\n",
            audio.port(),
        )
    } else {
        ("", "", "", video.port())
    };
    let dtls = format!(
        "a=setup:actpass\r\na=fingerprint:{} {}\r\n",
        fingerprint.hash_function,
        hex(fingerprint)
    );
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n{group}\
         m=audio {audio_port} UDP/TLS/RTP/SAVPF 0\r\n{audio_mid}a=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n{dtls}\
         m=video {video_port} UDP/TLS/RTP/SAVPF 96\r\n{video_mid}{CAMERA_PAYLOAD}a={direction}\r\na=rtcp-mux\r\n{dtls}",
        ip = audio.ip(),
        audio_port = audio.port(),
    )
}

/// A plain, multiplexed callee's answer: audio and video at their own addresses.
pub(super) fn plain_answer(audio: SocketAddr, video: SocketAddr, direction: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {audio_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
         m=video {video_port} RTP/AVPF 96\r\n{CAMERA_PAYLOAD}a={direction}\r\na=rtcp-mux\r\n",
        ip = audio.ip(),
        audio_port = audio.port(),
        video_port = video.port(),
    )
}

pub(super) fn dtls_caller_profile() -> ProfileFlags {
    ProfileFlags {
        transport_protocol: Some("RTP/AVP".to_string()),
        ..anchor()
    }
}

fn spawn_dispatcher(engine: &Engine<UdpLoopbackDatapath>) {
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
}

/// A DTLS caller (A) bundled onto one socket, and a plain callee (B) with an audio and a video socket.
struct DtlsCall {
    engine: Engine<UdpLoopbackDatapath>,
    a: Arc<UdpSocket>,
    a_leg: SecureLeg,
    b_audio: UdpSocket,
    b_video: UdpSocket,
    /// Where A sends: the engine's audio address, which A's bundled video shares.
    engine_near: SocketAddr,
    /// Where B sends its video.
    engine_far_video: SocketAddr,
    to_b: String,
    to_a: String,
    caller: DtlsCertificate,
    a_addr: SocketAddr,
    b_addresses: (SocketAddr, SocketAddr),
    call_id: String,
}

async fn bundled_call(call_id: &str, direction_a: &str, direction_b: &str) -> DtlsCall {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    spawn_dispatcher(&engine);
    let a = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .expect("bind a"),
    );
    let a_addr = a.local_addr().expect("addr");
    let (b_audio, b_audio_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let (b_video, b_video_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let caller = DtlsCertificate::generate().expect("caller cert");
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                sdp: dtls_offer(a_addr, a_addr, &caller.fingerprint(), true, direction_a),
                profile: dtls_caller_profile(),
            },
        )
        .await;
    let to_b = ok_sdp_text(&offered);
    let engine_far_video = sdp::parse_video_stream(&to_b)
        .expect("video offered to B")
        .remote_rtp;
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: plain_answer(b_audio_addr, b_video_addr, direction_b),
                profile: dtls_caller_profile(),
            },
        )
        .await;
    let to_a = ok_sdp_text(&answered);
    let answer = sdp::parse(&to_a).expect("parse the answer A receives");
    let engine_fingerprint = answer
        .fingerprint
        .clone()
        .expect("the engine's fingerprint");
    let a_leg = peer_dtls_handshake_server(
        a.clone(),
        a_addr,
        answer.remote_rtp,
        &caller,
        &engine_fingerprint,
    )
    .await;
    DtlsCall {
        engine,
        a,
        a_leg,
        b_audio,
        b_video,
        engine_near: answer.remote_rtp,
        engine_far_video,
        to_b,
        to_a,
        caller,
        a_addr,
        b_addresses: (b_audio_addr, b_video_addr),
        call_id: call_id.to_string(),
    }
}

impl DtlsCall {
    /// Seal `plain` as A and send it to the engine, retrying across the window between A finishing its
    /// handshake and the engine installing its leg, until `to` receives something.
    async fn a_sends(&mut self, plain: &[u8], to_video: bool) -> Option<Vec<u8>> {
        // Sealed once and resent: sealing the same packet again would reuse its SRTP index (RFC 3711
        // §9.1), which the sender refuses.
        let mut sealed = Vec::new();
        self.a_leg.protect(plain, &mut sealed).expect("protect");
        for _ in 0..25 {
            self.a
                .send_to(&sealed, self.engine_near)
                .await
                .expect("a send");
            let to = if to_video {
                &self.b_video
            } else {
                &self.b_audio
            };
            let mut buffer = [0u8; 2048];
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(150), to.recv_from(&mut buffer)).await
            {
                return Some(buffer[..len].to_vec());
            }
        }
        None
    }

    /// What A receives and decrypts within the window.
    async fn a_receives(&mut self) -> Option<Vec<u8>> {
        let mut buffer = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(2), self.a.recv_from(&mut buffer))
            .await
            .ok()?
            .ok()?;
        let mut plain = Vec::new();
        self.a_leg.unprotect(&buffer[..len], &mut plain).ok()?;
        Some(plain)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bundled_dtls_caller_and_a_plain_callee_exchange_video_both_ways() {
    let mut call = bundled_call("dtls-video-bundled", "sendrecv", "sendrecv").await;

    // The answer keeps the bundle: the group, both mids, and the video on the audio's address, with
    // the engine's own fingerprint written once (RFC 8843 §7.3, RFC 5763 §5).
    let to_a = call.to_a.clone();
    assert!(to_a.contains("a=group:BUNDLE 0 1"), "{to_a}");
    let video = sdp::parse_video_stream(&to_a).expect("video answered");
    assert_eq!(video.remote_rtp, call.engine_near, "{to_a}");
    assert!(
        video.is_dtls() && video.mid.as_deref() == Some("1"),
        "{to_a}"
    );
    assert_eq!(
        to_a.matches("a=fingerprint:").count(),
        1,
        "once, on the audio section: {to_a}"
    );
    // B is offered plain video on an address of its own, and is not told of the bundle.
    assert!(!call.to_b.contains("a=group:BUNDLE"), "{}", call.to_b);
    assert!(!call.to_b.contains("a=fingerprint:"), "{}", call.to_b);

    // A → B: SRTP video on A's one address reaches B's video socket in the clear, not its audio one.
    let from_a = video_packet(1);
    let at_b = call.a_sends(&from_a, true).await;
    assert_eq!(at_b.as_deref(), Some(from_a.as_slice()));
    assert!(
        received(&call.b_audio).await.is_none(),
        "video is not audio"
    );

    // Audio on the same association still reaches B's audio socket.
    let audio = rtp(0x0A0A_0A0A);
    let audio_at_b = call.a_sends(&audio, false).await;
    assert_eq!(audio_at_b.as_deref(), Some(audio.as_slice()));

    // B → A: plain video becomes SRTP on A's one address, and decrypts under A's key.
    let from_b = video_packet(7);
    call.b_video
        .send_to(&from_b, call.engine_far_video)
        .await
        .expect("b send");
    assert_eq!(call.a_receives().await.as_deref(), Some(from_b.as_slice()));

    // B's receiver report crosses as SRTCP.
    call.b_video
        .send_to(&receiver_report(), call.engine_far_video)
        .await
        .expect("b rtcp");
    assert_eq!(
        call.a_receives().await.as_deref(),
        Some(receiver_report().as_slice())
    );

    // A's report about B's video (SSRC DEADBEEF, learned from B's packet) reaches B's video socket.
    let mut report = vec![0x81, 201, 0x00, 0x07, 0x99, 0x99, 0x00, 0x01];
    report.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    report.extend_from_slice(&[0u8; 20]);
    assert_eq!(
        call.a_sends(&report, true).await.as_deref(),
        Some(report.as_slice())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_is_dropped_on_both_sides_of_bundled_video() {
    let mut call = bundled_call("dtls-video-stranger", "sendrecv", "sendrecv").await;
    let first = video_packet(1);
    assert!(call.a_sends(&first, true).await.is_some(), "the call works");
    let stranger = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 9), 0))
        .await
        .expect("bind");
    // Toward A: a source the callee never signalled cannot use the video endpoint.
    stranger
        .send_to(&video_packet(9), call.engine_far_video)
        .await
        .expect("send");
    let mut buffer = [0u8; 2048];
    assert!(
        timeout(Duration::from_millis(400), call.a.recv_from(&mut buffer))
            .await
            .is_err(),
        "a stranger's video never reaches the DTLS party"
    );
    // Toward B: SRTP from a source other than A's cannot reach B's video socket either.
    let mut sealed = Vec::new();
    call.a_leg
        .protect(&video_packet(2), &mut sealed)
        .expect("protect");
    stranger
        .send_to(&sealed, call.engine_near)
        .await
        .expect("send");
    assert!(received(&call.b_video).await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reoffer_keeps_the_association_and_the_video() {
    let mut call = bundled_call("dtls-video-reoffer", "sendrecv", "sendrecv").await;
    assert!(call.a_sends(&video_packet(1), true).await.is_some());
    let reoffered = reoffer_from(
        &call.engine,
        &call.call_id,
        "a",
        dtls_offer(
            call.a_addr,
            call.a_addr,
            &call.caller.fingerprint(),
            true,
            "sendrecv",
        ),
        dtls_caller_profile(),
    )
    .await;
    let again = ok_sdp_text(&reoffered);
    assert!(sdp::parse_video_stream(&again).is_some(), "{again}");
    assert!(!again.contains("a=group:BUNDLE"), "B is plain: {again}");
    let answered = answer_from_b(
        &call.engine,
        &call.call_id,
        plain_answer(call.b_addresses.0, call.b_addresses.1, "sendrecv"),
        dtls_caller_profile(),
    )
    .await;
    assert!(answered.fingerprint.is_some());
    // The same SRTP context, no new handshake: video keeps flowing both ways.
    assert!(call.a_sends(&video_packet(3), true).await.is_some());
    call.b_video
        .send_to(&video_packet(8), call.engine_far_video)
        .await
        .expect("send");
    assert_eq!(
        call.a_receives().await.as_deref(),
        Some(video_packet(8).as_slice())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sendonly_dtls_camera_relays_one_way_and_both_ways_for_rtcp() {
    let mut call = bundled_call("dtls-video-oneway", "sendonly", "recvonly").await;
    assert!(call.a_sends(&video_packet(1), true).await.is_some());
    // B may not send video toward a sendonly camera...
    call.b_video
        .send_to(&video_packet(5), call.engine_far_video)
        .await
        .expect("send");
    let mut buffer = [0u8; 2048];
    assert!(
        timeout(Duration::from_millis(400), call.a.recv_from(&mut buffer))
            .await
            .is_err(),
        "video against the direction is dropped"
    );
    // ...but its receiver report still reaches the camera (RFC 3550 §6.4).
    call.b_video
        .send_to(&receiver_report(), call.engine_far_video)
        .await
        .expect("send");
    assert_eq!(
        call.a_receives().await.as_deref(),
        Some(receiver_report().as_slice())
    );
}

/// What a DTLS-aware phone with one socket per stream is offered and answers (unbundled, no ICE).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unbundled_dtls_caller_runs_a_second_association_on_the_video_endpoint() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    spawn_dispatcher(&engine);
    let a_audio = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .expect("bind"),
    );
    let a_video = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .expect("bind"),
    );
    let (a_audio_addr, a_video_addr) = (
        a_audio.local_addr().expect("addr"),
        a_video.local_addr().expect("addr"),
    );
    let (_b_audio, b_audio_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let (b_video, b_video_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let caller = DtlsCertificate::generate().expect("cert");
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dtls-video-own".into(),
                from_tag: "a".into(),
                sdp: dtls_offer(
                    a_audio_addr,
                    a_video_addr,
                    &caller.fingerprint(),
                    false,
                    "sendrecv",
                ),
                profile: dtls_caller_profile(),
            },
        )
        .await;
    let far_video = sdp::parse_video_stream(&ok_sdp_text(&offered))
        .expect("video offered to B")
        .remote_rtp;
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "dtls-video-own".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: plain_answer(b_audio_addr, b_video_addr, "sendrecv"),
                profile: dtls_caller_profile(),
            },
        )
        .await;
    let to_a = ok_sdp_text(&answered);
    let video = sdp::parse_video_stream(&to_a).expect("video answered");
    let audio = sdp::parse(&to_a).expect("audio");
    assert_ne!(
        video.remote_rtp, audio.remote_rtp,
        "its own address: {to_a}"
    );
    assert_eq!(
        video.setup,
        Some(sdp::Setup::Active),
        "the engine's own role for the section: {to_a}"
    );
    assert!(!to_a.contains("a=group:BUNDLE"), "{to_a}");
    let engine_fingerprint = audio.fingerprint.clone().expect("fingerprint");
    // Two handshakes, one per association, with the one certificate.
    let _audio_leg = peer_dtls_handshake_server(
        a_audio.clone(),
        a_audio_addr,
        audio.remote_rtp,
        &caller,
        &engine_fingerprint,
    )
    .await;
    let mut video_leg = peer_dtls_handshake_server(
        a_video.clone(),
        a_video_addr,
        video.remote_rtp,
        &caller,
        &engine_fingerprint,
    )
    .await;
    let from_a = video_packet(1);
    let mut at_b = None;
    // Sealed once and resent (RFC 3711 §9.1: the same packet sealed again reuses its index).
    let mut sealed = Vec::new();
    video_leg.protect(&from_a, &mut sealed).expect("protect");
    for _ in 0..25 {
        a_video
            .send_to(&sealed, video.remote_rtp)
            .await
            .expect("send");
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(150), b_video.recv_from(&mut buffer)).await
        {
            at_b = Some(buffer[..len].to_vec());
            break;
        }
    }
    assert_eq!(at_b.as_deref(), Some(from_a.as_slice()));
    b_video
        .send_to(&video_packet(4), far_video)
        .await
        .expect("send");
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(2), a_video.recv_from(&mut buffer))
        .await
        .expect("A hears video")
        .expect("recv");
    let mut plain = Vec::new();
    video_leg
        .unprotect(&buffer[..len], &mut plain)
        .expect("unprotect");
    assert_eq!(plain, video_packet(4));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_callee_is_offered_video_on_an_association_of_its_own() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    spawn_dispatcher(&engine);
    let (a_audio, a_audio_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (a_video, a_video_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let _ = &a_audio;
    let b_audio = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind"),
    );
    let b_video = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind"),
    );
    let profile = ProfileFlags {
        transport_protocol: Some("UDP/TLS/RTP/SAVPF".to_string()),
        ..anchor()
    };
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dtls-video-callee".into(),
                from_tag: "a".into(),
                sdp: plain_answer(a_audio_addr, a_video_addr, "sendrecv"),
                profile: profile.clone(),
            },
        )
        .await;
    let to_b = ok_sdp_text(&offered);
    let video_offer = sdp::parse_video_stream(&to_b).expect("video offered to B");
    assert!(video_offer.is_dtls(), "{to_b}");
    assert_eq!(video_offer.setup, Some(sdp::Setup::Actpass), "{to_b}");
    let audio_offer = sdp::parse(&to_b).expect("audio");
    let engine_fingerprint = audio_offer.fingerprint.clone().expect("fingerprint");
    let callee = DtlsCertificate::generate().expect("cert");
    let print = callee.fingerprint();
    let answer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.3\r\ns=-\r\nc=IN IP4 127.0.0.3\r\nt=0 0\r\n\
         m=audio {audio_port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
         a=setup:active\r\na=fingerprint:{hash} {hex}\r\n\
         m=video {video_port} UDP/TLS/RTP/SAVPF 96\r\n{CAMERA_PAYLOAD}a=sendrecv\r\na=rtcp-mux\r\n\
         a=setup:active\r\na=fingerprint:{hash} {hex}\r\n",
        audio_port = b_audio.local_addr().expect("addr").port(),
        video_port = b_video.local_addr().expect("addr").port(),
        hash = print.hash_function,
        hex = hex(&print),
    );
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "dtls-video-callee".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: answer_sdp,
                profile,
            },
        )
        .await;
    let to_a = ok_sdp_text(&answered);
    let near_video = sdp::parse_video_stream(&to_a).expect("A is answered video");
    assert!(near_video.is_plain(), "A stays plain: {to_a}");
    let _audio_leg = drive_peer_dtls(
        b_audio.clone(),
        audio_offer.remote_rtp,
        &callee,
        &engine_fingerprint,
        siphon_rtp_dtls::DtlsRole::Client,
        false,
    )
    .await;
    let mut video_leg = drive_peer_dtls(
        b_video.clone(),
        video_offer.remote_rtp,
        &callee,
        &engine_fingerprint,
        siphon_rtp_dtls::DtlsRole::Client,
        false,
    )
    .await;
    // A's plain video arrives at B as SRTP under the video association.
    let mut plain = None;
    for _ in 0..25 {
        a_video
            .send_to(&video_packet(1), near_video.remote_rtp)
            .await
            .expect("send");
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(150), b_video.recv_from(&mut buffer)).await
        {
            let mut opened = Vec::new();
            video_leg
                .unprotect(&buffer[..len], &mut opened)
                .expect("unprotect");
            plain = Some(opened);
            break;
        }
    }
    assert_eq!(plain, Some(video_packet(1)));
    // And B's SRTP video reaches A in the clear.
    let mut sealed = Vec::new();
    video_leg
        .protect(&video_packet(6), &mut sealed)
        .expect("protect");
    b_video
        .send_to(&sealed, video_offer.remote_rtp)
        .await
        .expect("send");
    assert_eq!(received(&a_video).await, Some(video_packet(6)));
}

#[tokio::test]
async fn unbundled_dtls_video_with_ice_is_declined_with_the_reason() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_a, a_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (_v, v_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let caller = DtlsCertificate::generate().expect("cert");
    // The ICE credentials close the SDP, so they belong to the video section.
    let offer = dtls_offer(a_addr, v_addr, &caller.fingerprint(), false, "sendrecv")
        + "a=ice-ufrag:abcd\r\na=ice-pwd:efghefghefghefghefghefgh\r\n";
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dtls-video-ice".into(),
                from_tag: "a".into(),
                sdp: offer,
                profile: dtls_caller_profile(),
            },
        )
        .await;
    let CmdResult::Ok {
        video_declined,
        sdp: Some(sdp),
        ..
    } = offered
    else {
        panic!("{offered:?}");
    };
    assert!(sdp.contains("m=video 0 "), "{sdp}");
    let reason = video_declined.expect("declined with a reason");
    assert!(reason.contains("ICE"), "{reason}");
}

#[tokio::test]
async fn dtls_video_whose_audio_dtls_passes_through_is_declined_with_the_reason() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_a, a_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let caller = DtlsCertificate::generate().expect("cert");
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dtls-video-passthrough".into(),
                from_tag: "a".into(),
                sdp: dtls_offer(a_addr, a_addr, &caller.fingerprint(), true, "sendrecv"),
                profile: anchor(),
            },
        )
        .await;
    let CmdResult::Ok { video_declined, .. } = offered else {
        panic!("{offered:?}");
    };
    let reason = video_declined.expect("declined");
    assert!(reason.contains("passes through"), "{reason}");
}

#[tokio::test]
async fn a_dtls_caller_toward_an_sdes_callee_is_refused_as_audio_is() {
    // Audio refuses the posture at the offer, so no video of it is ever negotiated: two keying
    // mechanisms need a transcrypt, which is not carried.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_a, a_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let caller = DtlsCertificate::generate().expect("cert");
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dtls-video-sdes".into(),
                from_tag: "a".into(),
                sdp: dtls_offer(a_addr, a_addr, &caller.fingerprint(), true, "sendrecv"),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/SAVP".to_string()),
                    ..anchor()
                },
            },
        )
        .await;
    let CmdResult::Error { reason } = offered else {
        panic!("{offered:?}");
    };
    assert!(reason.contains("secure-offerer-unsupported"), "{reason}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_checkpoint_of_a_dtls_video_call_is_refused_as_audio_dtls_is() {
    let call = bundled_call("dtls-video-ha", "sendrecv", "sendrecv").await;
    let result = call
        .engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: call.call_id.clone(),
                from_tag: "a".into(),
            },
        )
        .await;
    let CmdResult::Error { reason } = result else {
        panic!("a DTLS call does not checkpoint: {result:?}");
    };
    assert!(reason.contains("DTLS-SRTP call"), "{reason}");
}
