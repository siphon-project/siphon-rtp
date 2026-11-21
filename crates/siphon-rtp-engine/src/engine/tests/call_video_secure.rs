//! SDES-SRTP on an anchored two-party video stream, over the UDP loopback datapath with real SRTP on
//! the phones' side: each handset keys its own [`SecureLeg`] from the keys the SDP carried, so a
//! packet only decrypts when the engine's bridge keyed the leg the way the SDP said.

use super::call_video::{
    anchor, phone_pair, received, receiver_report, video_packet, CAMERA_PAYLOAD,
};
use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_srtp::leg::SecureLeg;

fn key(tag: u32) -> CryptoAttribute {
    CryptoAttribute::generate(tag, CryptoSuite::AesCm128HmacSha1_80).expect("key")
}

/// Audio and one `sendrecv` video section; a `Some` key makes that section `RTP/SAVP` with it.
fn call_sdp(
    audio: (SocketAddr, Option<&CryptoAttribute>),
    video: (SocketAddr, Option<&CryptoAttribute>),
    mux: bool,
) -> String {
    let section = |key: Option<&CryptoAttribute>| match key {
        Some(key) => ("RTP/SAVP", format!("a={}\r\n", key.to_attribute_value())),
        None => ("RTP/AVP", String::new()),
    };
    let (audio_profile, audio_key) = section(audio.1);
    let (video_profile, video_key) = section(video.1);
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {audio_port} {audio_profile} 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n{audio_key}\
         m=video {video_port} {video_profile} 96\r\n{CAMERA_PAYLOAD}a=sendrecv\r\n{mux_line}{video_key}",
        ip = audio.0.ip(),
        audio_port = audio.0.port(),
        video_port = video.0.port(),
        mux_line = if mux { "a=rtcp-mux\r\n" } else { "" },
    )
}

/// One party's video: its sockets, the engine address it sends to, and its SRTP leg when secure.
struct Handset {
    rtp: UdpSocket,
    rtcp: Option<UdpSocket>,
    engine_rtp: SocketAddr,
    engine_rtcp: SocketAddr,
    leg: Option<SecureLeg>,
}

impl Handset {
    /// What this handset puts on the wire for `plain`: protected when it is secure.
    fn seal(&mut self, plain: &[u8]) -> Vec<u8> {
        let Some(leg) = self.leg.as_mut() else {
            return plain.to_vec();
        };
        let mut sealed = Vec::new();
        leg.protect(plain, &mut sealed).expect("protect");
        sealed
    }

    /// What this handset reads out of `wire`, or `None` when it does not authenticate.
    fn open(&mut self, wire: &[u8]) -> Option<Vec<u8>> {
        let Some(leg) = self.leg.as_mut() else {
            return Some(wire.to_vec());
        };
        let mut plain = Vec::new();
        leg.unprotect(wire, &mut plain).ok()?;
        Some(plain)
    }
}

struct SecureCall {
    engine: Engine<UdpLoopbackDatapath>,
    a: Handset,
    b: Handset,
    /// What the far party was offered, and what the near party was answered.
    to_b: String,
    to_a: String,
    /// The two parties' own keys, the audio and video lines of A's offer, for a re-offer.
    a_audio_key: Option<CryptoAttribute>,
    a_video_key: Option<CryptoAttribute>,
    b_audio_key: Option<CryptoAttribute>,
    b_video_key: Option<CryptoAttribute>,
    a_addresses: (SocketAddr, SocketAddr),
    b_addresses: (SocketAddr, SocketAddr),
    mux: bool,
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

/// Set a call up: A offers video (SDES when `near_secure`), the far leg is offered SDES when
/// `far_secure` (the profile's far transport, as for audio), B answers in kind.
async fn secure_call(call_id: &str, near_secure: bool, far_secure: bool, mux: bool) -> SecureCall {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    spawn_dispatcher(&engine);
    let (a_audio, a_audio_addr) = phone().await;
    let (a_video, a_video_addr) = phone().await;
    let a_rtcp = if mux {
        None
    } else {
        Some(phone_pair(&a_video_addr).await.0)
    };
    let (b_audio, b_audio_addr) = phone().await;
    let (b_video, b_video_addr) = phone().await;
    let b_rtcp = if mux {
        None
    } else {
        Some(phone_pair(&b_video_addr).await.0)
    };
    let _ = (&a_audio, &b_audio);
    let a_audio_key = near_secure.then(|| key(1));
    let a_video_key = near_secure.then(|| key(2));
    let mut profile = anchor();
    if far_secure {
        profile.transport_protocol = Some("RTP/SAVP".to_string());
    }
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                sdp: call_sdp(
                    (a_audio_addr, a_audio_key.as_ref()),
                    (a_video_addr, a_video_key.as_ref()),
                    mux,
                ),
                profile: profile.clone(),
            },
        )
        .await;
    let to_b = ok_sdp_text(&offered);
    let offered_video = sdp::parse_video_stream(&to_b).expect("video offered to B");
    let offered_audio = sdp::parse(&to_b).expect("audio offered to B");
    // RFC 4568 §5.1.2: the answer names the offered line by its tag.
    let b_audio_key = far_secure.then(|| {
        CryptoAttribute::answer_to(offered_audio.crypto.first().expect("audio key to B"))
            .expect("key")
    });
    let b_video_key = far_secure.then(|| {
        CryptoAttribute::answer_to(offered_video.crypto.first().expect("video key to B"))
            .expect("key")
    });
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: call_sdp(
                    (b_audio_addr, b_audio_key.as_ref()),
                    (b_video_addr, b_video_key.as_ref()),
                    mux,
                ),
                profile,
            },
        )
        .await;
    let to_a = ok_sdp_text(&answered);
    let answered_video = sdp::parse_video_stream(&to_a).expect("video answered to A");
    let a_leg = near_secure.then(|| {
        let engine_key = answered_video.crypto.first().expect("video key to A");
        SecureLeg::new(&a_video_key.expect("key").key, &engine_key.key)
    });
    let b_leg = far_secure.then(|| {
        let engine_key = offered_video.crypto.first().expect("video key to B");
        SecureLeg::new(&b_video_key.expect("key").key, &engine_key.key)
    });
    SecureCall {
        a: Handset {
            rtp: a_video,
            rtcp: a_rtcp,
            engine_rtp: answered_video.remote_rtp,
            engine_rtcp: answered_video.remote_rtcp,
            leg: a_leg,
        },
        b: Handset {
            rtp: b_video,
            rtcp: b_rtcp,
            engine_rtp: offered_video.remote_rtp,
            engine_rtcp: offered_video.remote_rtcp,
            leg: b_leg,
        },
        engine,
        to_b,
        to_a,
        a_audio_key,
        a_video_key,
        b_audio_key,
        b_video_key,
        a_addresses: (a_audio_addr, a_video_addr),
        b_addresses: (b_audio_addr, b_video_addr),
        mux,
    }
}

/// `plain` sent from `from` to the engine and what `to` reads of what comes out.
async fn relay(from: &mut Handset, to: &mut Handset, plain: &[u8], rtcp: bool) -> Option<Vec<u8>> {
    let wire = from.seal(plain);
    match from.rtcp.as_ref().filter(|_| rtcp) {
        Some(socket) => socket.send_to(&wire, from.engine_rtcp).await,
        None => from.rtp.send_to(&wire, from.engine_rtp).await,
    }
    .expect("send");
    let socket = to.rtcp.as_ref().filter(|_| rtcp).unwrap_or(&to.rtp);
    let arrived = received(socket).await?;
    if arrived == plain && to.leg.is_some() {
        return None; // plaintext reached a secure handset
    }
    to.open(&arrived)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plain_door_station_reaches_an_sdes_phone_with_video_and_srtcp() {
    let mut call = secure_call("door-to-sdes", false, true, false).await;
    // The phone was offered SRTP video under an engine key; the door was answered plain.
    let offered = sdp::parse_video_stream(&call.to_b).expect("video");
    assert!(
        offered.is_sdes() && offered.crypto.len() == 1,
        "{}",
        call.to_b
    );
    assert!(sdp::parse_video_stream(&call.to_a)
        .expect("video")
        .is_plain());
    let (a, b) = (&mut call.a, &mut call.b);
    // Door to phone: plain in, SRTP on the wire to the phone, plain at the phone after decrypt.
    assert_eq!(
        relay(a, b, &video_packet(1), false).await,
        Some(video_packet(1))
    );
    // Phone to door: SRTP in, plain at the door.
    assert_eq!(
        relay(b, a, &video_packet(2), false).await,
        Some(video_packet(2))
    );
    // RTCP is SRTCP toward the phone and plain toward the door, per stream.
    assert_eq!(
        relay(b, a, &receiver_report(), true).await,
        Some(receiver_report())
    );
    assert_eq!(
        relay(a, b, &receiver_report(), true).await,
        Some(receiver_report())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_sdes_phone_reaches_a_plain_door_station() {
    let mut call = secure_call("sdes-to-door", true, false, true).await;
    assert!(sdp::parse_video_stream(&call.to_b)
        .expect("video")
        .is_plain());
    let answered = sdp::parse_video_stream(&call.to_a).expect("video");
    assert!(
        answered.is_sdes() && answered.crypto.len() == 1,
        "{}",
        call.to_a
    );
    let (a, b) = (&mut call.a, &mut call.b);
    assert_eq!(
        relay(a, b, &video_packet(1), false).await,
        Some(video_packet(1))
    );
    assert_eq!(
        relay(b, a, &video_packet(2), false).await,
        Some(video_packet(2))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_sdes_phones_are_transcrypted_under_their_own_keys() {
    let mut call = secure_call("sdes-to-sdes", true, true, false).await;
    let (a, b) = (&mut call.a, &mut call.b);
    assert_eq!(
        relay(a, b, &video_packet(1), false).await,
        Some(video_packet(1))
    );
    assert_eq!(
        relay(b, a, &video_packet(2), false).await,
        Some(video_packet(2))
    );
    assert_eq!(
        relay(a, b, &receiver_report(), true).await,
        Some(receiver_report())
    );
    assert_eq!(
        relay(b, a, &receiver_report(), true).await,
        Some(receiver_report())
    );
    // The wire toward B is not what A sent: A's ciphertext is never passed on.
    let sealed_by_a = a.seal(&video_packet(3));
    a.rtp
        .send_to(&sealed_by_a, a.engine_rtp)
        .await
        .expect("send");
    let on_the_wire = received(&b.rtp).await.expect("relayed");
    assert_ne!(on_the_wire, sealed_by_a, "the engine re-keys, not forwards");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_offer_and_answer_carry_a_crypto_line_per_video_section_with_minted_keys_and_the_offered_tag(
) {
    let call = secure_call("sdp-keys", true, true, true).await;
    let a_video_key = call.a_video_key.expect("A's video key");
    // Toward B: the engine's own key, a fresh one, never A's.
    let to_b = sdp::parse_video_stream(&call.to_b).expect("video");
    assert!(to_b.is_sdes());
    assert_eq!(to_b.crypto.len(), 1);
    assert_ne!(to_b.crypto[0].key.master_key, a_video_key.key.master_key);
    // Toward A: the engine's key under the tag A offered (2), not A's key.
    let to_a = sdp::parse_video_stream(&call.to_a).expect("video");
    assert_eq!(to_a.crypto.len(), 1);
    assert_eq!(to_a.crypto[0].tag, a_video_key.tag);
    assert_ne!(to_a.crypto[0].key.master_key, a_video_key.key.master_key);
    assert_ne!(to_a.crypto[0].key.master_key, to_b.crypto[0].key.master_key);
    // The audio section keeps its own, separate key line.
    let audio = sdp::parse(&call.to_b).expect("audio");
    assert_ne!(
        audio.crypto[0].key.master_key,
        to_b.crypto[0].key.master_key
    );
    // Neither party's key reaches the other.
    assert!(!call.to_b.contains(&a_video_key.to_attribute_value()));
    assert!(!call
        .to_a
        .contains(&call.b_video_key.expect("key").to_attribute_value()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stranger_is_dropped_by_the_gated_latch_even_with_a_well_formed_packet() {
    let mut call = secure_call("stranger", false, true, true).await;
    // A stranger on another address sends plain media at the door's engine port: it is not the
    // signalled source, so it is dropped before the bridge relays it.
    let stranger = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 9), 0))
        .await
        .expect("bind");
    stranger
        .send_to(&video_packet(7), call.a.engine_rtp)
        .await
        .expect("send");
    assert!(
        received(&call.b.rtp).await.is_none(),
        "a stranger is not relayed"
    );
    // And one that mimics the phone, protected under a key of its own, is dropped at the phone's port.
    let mut forged = SecureLeg::new(&key(1).key, &key(1).key);
    let mut sealed = Vec::new();
    forged
        .protect(&video_packet(8), &mut sealed)
        .expect("protect");
    stranger
        .send_to(&sealed, call.b.engine_rtp)
        .await
        .expect("send");
    assert!(
        received(&call.a.rtp).await.is_none(),
        "forged media is dropped"
    );
    // The real source still gets through, so the drop was the gate, not a dead bridge.
    let (a, b) = (&mut call.a, &mut call.b);
    assert_eq!(
        relay(a, b, &video_packet(9), false).await,
        Some(video_packet(9))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_keeps_the_secure_stream_and_carries_the_srtp_rollover() {
    let mut call = secure_call("rollover", true, true, true).await;
    // Run both directions past a sequence wrap, so each secure leg's rollover counter is 1.
    for sequence in [65_534u16, 65_535, 0, 1] {
        let (a, b) = (&mut call.a, &mut call.b);
        assert_eq!(
            relay(a, b, &video_packet(sequence), false).await,
            Some(video_packet(sequence)),
            "A to B at {sequence}"
        );
        assert_eq!(
            relay(b, a, &video_packet(sequence), false).await,
            Some(video_packet(sequence)),
            "B to A at {sequence}"
        );
    }
    // A re-offers (same keys, as a hold/resume would) and B answers: the bridge is rebuilt.
    let reoffered = call
        .engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "rollover".into(),
                from_tag: "a".into(),
                sdp: call_sdp(
                    (call.a_addresses.0, call.a_audio_key.as_ref()),
                    (call.a_addresses.1, call.a_video_key.as_ref()),
                    call.mux,
                ),
                profile: anchor(),
            },
        )
        .await;
    let to_b = ok_sdp_text(&reoffered);
    assert!(
        sdp::parse_video_stream(&to_b).expect("video").is_sdes(),
        "{to_b}"
    );
    let answered = call
        .engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "rollover".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: call_sdp(
                    (call.b_addresses.0, call.b_audio_key.as_ref()),
                    (call.b_addresses.1, call.b_video_key.as_ref()),
                    call.mux,
                ),
                profile: anchor(),
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    // The streams continue past the wrap: a bridge rebuilt with fresh counters would estimate the
    // wrong index here and fail to authenticate in either direction.
    let (a, b) = (&mut call.a, &mut call.b);
    for sequence in [2u16, 3] {
        assert_eq!(
            relay(a, b, &video_packet(sequence), false).await,
            Some(video_packet(sequence)),
            "A to B after the re-offer at {sequence}"
        );
        assert_eq!(
            relay(b, a, &video_packet(sequence), false).await,
            Some(video_packet(sequence)),
            "B to A after the re-offer at {sequence}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn teardown_removes_the_video_endpoints_from_the_srtp_bridge() {
    let call = secure_call("teardown", true, true, false).await;
    let endpoints: Vec<_> = {
        let stored = call.engine.calls.get("teardown").expect("call");
        stored
            .near
            .video
            .iter()
            .chain(stored.far.as_ref().and_then(|far| far.video.as_ref()))
            .flat_map(super::super::call_video::VideoLeg::endpoint_ids)
            .collect()
    };
    assert_eq!(endpoints.len(), 4, "a rtp and rtcp endpoint per leg");
    let bridge = call.engine.bridge();
    assert!(endpoints.iter().all(|endpoint| bridge.owns(*endpoint)));
    call.engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "teardown".into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(
        endpoints.iter().all(|endpoint| !bridge.owns(*endpoint)),
        "no video flow outlives the call"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_checkpoint_restores_an_sdes_video_call_with_its_keys_and_rollover() {
    let (min, max) = (28_100u16, 28_160u16);
    let bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let engine_a = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
    spawn_dispatcher(&engine_a);
    // The call is built by hand on the first node: the helper above builds its own engine.
    let (_a_audio, a_audio_addr) = phone().await;
    let (a_video, a_video_addr) = phone().await;
    let (_b_audio, b_audio_addr) = phone().await;
    let (b_video, b_video_addr) = phone().await;
    let profile = ProfileFlags {
        transport_protocol: Some("RTP/SAVP".to_string()),
        ..anchor()
    };
    let offered = engine_a
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ha-video".into(),
                from_tag: "a".into(),
                sdp: call_sdp((a_audio_addr, None), (a_video_addr, None), true),
                profile: profile.clone(),
            },
        )
        .await;
    let to_b = ok_sdp_text(&offered);
    let engine_b_video = sdp::parse_video_stream(&to_b).expect("video");
    let engine_b_key = *engine_b_video.crypto.first().expect("video key to B");
    let b_audio_key = CryptoAttribute::answer_to(
        sdp::parse(&to_b)
            .expect("audio")
            .crypto
            .first()
            .expect("key"),
    )
    .expect("key");
    let b_video_key = CryptoAttribute::answer_to(&engine_b_key).expect("key");
    let answered = engine_a
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "ha-video".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: call_sdp(
                    (b_audio_addr, Some(&b_audio_key)),
                    (b_video_addr, Some(&b_video_key)),
                    true,
                ),
                profile,
            },
        )
        .await;
    let engine_a_video = sdp::parse_video_stream(&ok_sdp_text(&answered))
        .expect("video")
        .remote_rtp;
    let mut phone_b = SecureLeg::new(&b_video_key.key, &engine_b_key.key);
    // Run A to B past a wrap: the engine's outbound leg toward B reaches rollover 1.
    for sequence in [65_534u16, 65_535, 0] {
        a_video
            .send_to(&video_packet(sequence), engine_a_video)
            .await
            .expect("send");
        let wire = received(&b_video).await.expect("relayed");
        let mut plain = Vec::new();
        phone_b.unprotect(&wire, &mut plain).expect("B decrypts");
        assert_eq!(plain, video_packet(sequence));
    }
    let CmdResult::Checkpoint { snapshot } = engine_a
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "ha-video".into(),
                from_tag: "a".into(),
            },
        )
        .await
    else {
        panic!("expected a checkpoint");
    };
    let parsed = crate::ha::CallSnapshot::from_json(&snapshot).expect("parse");
    assert_eq!(parsed.version, crate::ha::SNAPSHOT_VERSION_VIDEO_SECURE);
    let secure = parsed
        .video
        .as_ref()
        .and_then(|video| video.secure.as_ref())
        .expect("the video keys and rollover are recorded");
    assert!(secure.far_local.is_some() && secure.far_remote.is_some());
    assert!(secure.near_local.is_none(), "the near party is plain");
    assert!(secure.far_rollover.is_some());
    engine_a
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "ha-video".into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    drop(engine_a);
    let engine_b = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
    spawn_dispatcher(&engine_b);
    let restored = engine_b.handle(CLIENT, Command::Restore { snapshot }).await;
    assert!(matches!(restored, CmdResult::Ok { .. }), "{restored:?}");
    // A to B continues at the same ports, and B (whose counters kept running) still decrypts what the
    // restored bridge sends: only a seeded rollover authenticates here.
    for sequence in [1u16, 2] {
        a_video
            .send_to(&video_packet(sequence), engine_a_video)
            .await
            .expect("send");
        let wire = received(&b_video).await.expect("relayed after restore");
        let mut plain = Vec::new();
        phone_b
            .unprotect(&wire, &mut plain)
            .expect("B decrypts the restored bridge");
        assert_eq!(plain, video_packet(sequence));
    }
    // B to A: B's own packets decrypt at the restored bridge and arrive plain.
    let mut sealed = Vec::new();
    phone_b
        .protect(&video_packet(50), &mut sealed)
        .expect("protect");
    b_video
        .send_to(&sealed, engine_b_video.remote_rtp)
        .await
        .expect("send");
    assert_eq!(received(&a_video).await, Some(video_packet(50)));
}
