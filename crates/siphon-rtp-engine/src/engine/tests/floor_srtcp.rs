//! The MCPTT floor stream protected with AEAD_AES_128_GCM SRTCP (3GPP TS 33.180 §9.4), end to end on
//! the UDP-loopback datapath, for a forwarding-room seat and for both legs of a two-party call.
//!
//! The test phone protects and unprotects with its own `SrtcpGcmContext`, built from the key bytes
//! here and not through the engine's conversion, so the engine's key handling is checked against an
//! independent reading of the same key.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_proto::{FloorKey, ForwardMedia, RtcpAppStream};
use siphon_rtp_srtp::srtcp_gcm::{FloorMasterKey, SrtcpGcmContext};

const ROOM: &str = "group-1";
const CALL: &str = "call-keyed";
const SHORT: Duration = Duration::from_secs(2);
const NEGATIVE: Duration = Duration::from_millis(250);
const FLOOR_FMTP: &str = "mc_queueing;mc_priority=5;mc_granted";

/// TS 24.380 §8.2.4 Floor Request: SSRC 0x11223344, name MCPT, subtype 0.
const FLOOR_REQUEST: [u8; 16] = [
    0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05, 0x00,
];
const FLOOR_GRANTED_PAYLOAD: [u8; 12] = [
    0x01, 0x02, 0x00, 0x1E, 0x0E, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
];

/// A floor key; `salt_length` is 12 (RFC 7714 §12) or 14 (RFC 3711).
fn key(mki: u32, fill: u8, salt_length: usize) -> FloorKey {
    FloorKey {
        mki,
        key: vec![fill; 16],
        salt: vec![fill ^ 0x5A; salt_length],
    }
}

/// The phone's reading of a [`FloorKey`], independent of the engine's conversion.
fn phone_key(key: &FloorKey) -> FloorMasterKey {
    let master_key: [u8; 16] = key.key.clone().try_into().unwrap();
    if key.salt.len() == 12 {
        FloorMasterKey::from_salt_96(key.mki, master_key, &key.salt.clone().try_into().unwrap())
    } else {
        FloorMasterKey {
            mki: key.mki,
            master_key,
            master_salt: key.salt.clone().try_into().unwrap(),
        }
    }
}

fn phone_context(keys: &[FloorKey]) -> SrtcpGcmContext {
    let keys: Vec<FloorMasterKey> = keys.iter().map(phone_key).collect();
    SrtcpGcmContext::new(&keys).unwrap()
}

fn protect(context: &mut SrtcpGcmContext, rtcp: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    context.protect(rtcp, true, &mut wire).unwrap();
    wire
}

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

fn sdp_with_floor(audio: SocketAddr, floor: SocketAddr, codec: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 {codec}\r\na=rtcp-mux\r\n\
         m=application {floor_port} udp MCPTT\r\na=fmtp:MCPTT mc_queueing\r\n",
        ip = audio.ip(),
        port = audio.port(),
        floor_port = floor.port()
    )
}

fn keyed_profile(keys: Vec<FloorKey>) -> ProfileFlags {
    ProfileFlags {
        floor_fmtp: Some(FLOOR_FMTP.to_string()),
        floor_keys: keys,
        ..ProfileFlags::default()
    }
}

async fn recv_datagram(socket: &UdpSocket, window: Duration) -> Option<Vec<u8>> {
    let mut buffer = [0u8; 2048];
    match tokio::time::timeout(window, socket.recv_from(&mut buffer)).await {
        Ok(Ok((length, _))) => Some(buffer[..length].to_vec()),
        _ => None,
    }
}

async fn next_app(events: &flume::Receiver<Event>) -> Event {
    tokio::time::timeout(SHORT, events.recv_async())
        .await
        .expect("an rtcp_app event")
        .expect("open queue")
}

fn expect_error(result: CmdResult) -> String {
    match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected an error, got {other:?}"),
    }
}

/// A seated phone: its floor socket and the engine floor port it talks to.
struct Phone {
    _audio: UdpSocket,
    floor: UdpSocket,
    engine_floor: SocketAddr,
}

async fn seat(engine: &Engine<UdpLoopbackDatapath>, tag: &str, keys: Vec<FloorKey>) -> Phone {
    let (audio, audio_addr) = phone().await;
    let (floor, floor_addr) = phone().await;
    let answer = engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                sdp: sdp_with_floor(audio_addr, floor_addr, "PCMU/8000"),
                profile: keyed_profile(keys),
            },
        )
        .await;
    let engine_floor = sdp::parse_floor(&ok_sdp_text(&answer))
        .expect("floor section")
        .remote;
    Phone {
        _audio: audio,
        floor,
        engine_floor,
    }
}

async fn send_app(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: Option<&str>,
    tag: &str,
    stream: RtcpAppStream,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::SendRtcpApp {
                call_id: call_id.map(str::to_string),
                conference_id: call_id.is_none().then(|| ROOM.to_string()),
                from_tag: Some(tag.into()),
                except_from_tags: Vec::new(),
                stream,
                ssrc: Some(0xCAFE_F00D),
                name: "MCPT".into(),
                subtype: 17,
                payload: FLOOR_GRANTED_PAYLOAD.to_vec(),
            },
        )
        .await
}

async fn set_keys(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: Option<&str>,
    tag: &str,
    keys: Vec<FloorKey>,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::SetFloorKeys {
                call_id: call_id.map(str::to_string),
                conference_id: call_id.is_none().then(|| ROOM.to_string()),
                from_tag: tag.into(),
                keys,
            },
        )
        .await
}

fn granted_plain() -> Vec<u8> {
    let mut expected = vec![0x91, 0xCC, 0x00, 0x05, 0xCA, 0xFE, 0xF0, 0x0D];
    expected.extend_from_slice(b"MCPT");
    expected.extend_from_slice(&FLOOR_GRANTED_PAYLOAD);
    expected
}

/// The mki a protected packet carries (the last four octets, RFC 7714 §9.2).
fn wire_mki(wire: &[u8]) -> u32 {
    u32::from_be_bytes(wire[wire.len() - 4..].try_into().unwrap())
}

fn floor_request_event(tag: &str, call_id: Option<&str>) -> Event {
    Event::RtcpApp {
        call_id: call_id.map(str::to_string),
        conference_id: call_id.is_none().then(|| ROOM.to_string()),
        from_tag: tag.into(),
        stream: RtcpAppStream::Floor,
        ssrc: 0x1122_3344,
        name: "MCPT".into(),
        subtype: 0,
        payload: vec![0x00, 0x02, 0x05, 0x00],
    }
}

#[tokio::test]
async fn a_keyed_seat_reads_a_protected_floor_request_and_sends_a_protected_floor_granted() {
    // The 12-octet (RFC 7714 §12) and the 14-octet (RFC 3711) salt both work end to end.
    for salt_length in [12, 14] {
        let engine = engine_with_dispatcher();
        let _events = engine.register_client(CLIENT);
        let app_events = engine.app_event_receiver(CLIENT).expect("queue");
        let keys = vec![key(0xCAFE_0001, 0x31, salt_length)];
        let phone = seat(&engine, "a", keys.clone()).await;
        let mut ue = phone_context(&keys);

        phone
            .floor
            .send_to(&protect(&mut ue, &FLOOR_REQUEST), phone.engine_floor)
            .await
            .unwrap();
        assert_eq!(next_app(&app_events).await, floor_request_event("a", None));
        assert!(app_events.try_recv().is_err(), "exactly one");

        assert_eq!(
            send_app(&engine, None, "a", RtcpAppStream::Floor).await,
            ok_empty()
        );
        let wire = recv_datagram(&phone.floor, SHORT).await.expect("granted");
        assert_eq!(wire_mki(&wire), 0xCAFE_0001, "the KFC-ID names the key");
        assert_ne!(wire, granted_plain(), "never in the clear");
        let mut plain = Vec::new();
        ue.unprotect(&wire, &mut plain).unwrap();
        assert_eq!(plain, granted_plain());
    }
}

#[tokio::test]
async fn a_keyed_seat_drops_plaintext_a_wrong_key_a_wrong_mki_and_a_replay() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let keys = vec![key(7, 0x31, 12)];
    let phone = seat(&engine, "a", keys.clone()).await;
    let mut ue = phone_context(&keys);

    // Plaintext APP: dropped, no event, even though it is a valid packet.
    phone
        .floor
        .send_to(&FLOOR_REQUEST, phone.engine_floor)
        .await
        .unwrap();
    // An MKI the seat does not hold, and the right MKI under the wrong key (the tag fails).
    let mut stranger = phone_context(&[key(99, 0x31, 12)]);
    let mut wrong_key = phone_context(&[key(7, 0x32, 12)]);
    for context in [&mut stranger, &mut wrong_key] {
        phone
            .floor
            .send_to(&protect(context, &FLOOR_REQUEST), phone.engine_floor)
            .await
            .unwrap();
    }
    assert!(
        tokio::time::timeout(NEGATIVE, app_events.recv_async())
            .await
            .is_err(),
        "nothing unauthenticated reaches the controller"
    );

    // The genuine packet gets through, and its replay does not.
    let genuine = protect(&mut ue, &FLOOR_REQUEST);
    phone
        .floor
        .send_to(&genuine, phone.engine_floor)
        .await
        .unwrap();
    assert_eq!(next_app(&app_events).await, floor_request_event("a", None));
    phone
        .floor
        .send_to(&genuine, phone.engine_floor)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(NEGATIVE, app_events.recv_async())
            .await
            .is_err(),
        "a replay is dropped"
    );
}

#[tokio::test]
async fn set_floor_keys_rekeys_a_room_seat_with_the_overlap_the_contract_describes() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let (k1, k2, k3) = (key(1, 0x31, 12), key(2, 0x32, 14), key(3, 0x33, 12));
    let phone = seat(&engine, "a", vec![k1.clone()]).await;
    let (mut ue1, mut ue2, mut ue3) = (
        phone_context(std::slice::from_ref(&k1)),
        phone_context(std::slice::from_ref(&k2)),
        phone_context(std::slice::from_ref(&k3)),
    );
    let heard = |wire: Vec<u8>| {
        let socket = &phone.floor;
        let target = phone.engine_floor;
        async move {
            socket.send_to(&wire, target).await.unwrap();
        }
    };

    // [k1] -> [k1, k2]: outbound moves to k2, k1 inbound is still accepted, k2 inbound too.
    assert_eq!(
        set_keys(&engine, None, "a", vec![k1.clone(), k2.clone()]).await,
        ok_empty()
    );
    send_app(&engine, None, "a", RtcpAppStream::Floor).await;
    let wire = recv_datagram(&phone.floor, SHORT).await.expect("granted");
    assert_eq!(wire_mki(&wire), 2, "outbound uses the newest key");
    let mut plain = Vec::new();
    ue2.unprotect(&wire, &mut plain).unwrap();
    assert_eq!(plain, granted_plain());
    heard(protect(&mut ue1, &FLOOR_REQUEST)).await;
    assert_eq!(next_app(&app_events).await, floor_request_event("a", None));
    heard(protect(&mut ue2, &FLOOR_REQUEST)).await;
    assert_eq!(next_app(&app_events).await, floor_request_event("a", None));

    // [k2, k3]: k1 is gone.
    assert_eq!(
        set_keys(&engine, None, "a", vec![k2.clone(), k3.clone()]).await,
        ok_empty()
    );
    heard(protect(&mut ue1, &FLOOR_REQUEST)).await;
    assert!(
        tokio::time::timeout(NEGATIVE, app_events.recv_async())
            .await
            .is_err(),
        "the dropped key no longer authenticates"
    );
    heard(protect(&mut ue3, &FLOOR_REQUEST)).await;
    assert_eq!(next_app(&app_events).await, floor_request_event("a", None));
    send_app(&engine, None, "a", RtcpAppStream::Floor).await;
    let wire = recv_datagram(&phone.floor, SHORT).await.expect("granted");
    assert_eq!(wire_mki(&wire), 3);
}

#[tokio::test]
async fn set_floor_keys_switches_an_unkeyed_seat_to_protected_and_refuses_what_it_cannot_apply() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let phone = seat(&engine, "a", Vec::new()).await;

    // Unkeyed: plain in, plain out.
    phone
        .floor
        .send_to(&FLOOR_REQUEST, phone.engine_floor)
        .await
        .unwrap();
    assert_eq!(next_app(&app_events).await, floor_request_event("a", None));

    let late = key(11, 0x41, 12);
    assert_eq!(
        set_keys(&engine, None, "a", vec![late.clone()]).await,
        ok_empty()
    );
    phone
        .floor
        .send_to(&FLOOR_REQUEST, phone.engine_floor)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(NEGATIVE, app_events.recv_async())
            .await
            .is_err(),
        "plaintext is refused once the seat is keyed"
    );
    send_app(&engine, None, "a", RtcpAppStream::Floor).await;
    let wire = recv_datagram(&phone.floor, SHORT).await.expect("granted");
    assert_eq!(wire_mki(&wire), 11);

    // An unknown seat, an unknown room, and a duplicate MKI are refused.
    let reason = expect_error(set_keys(&engine, None, "nobody", vec![late.clone()]).await);
    assert!(reason.contains("no seat nobody"), "{reason}");
    let reason = expect_error(
        engine
            .handle(
                CLIENT,
                Command::SetFloorKeys {
                    call_id: None,
                    conference_id: Some("no-such-room".into()),
                    from_tag: "a".into(),
                    keys: vec![late.clone()],
                },
            )
            .await,
    );
    assert!(reason.contains("no-such-room"), "{reason}");
    let reason = expect_error(set_keys(&engine, None, "a", vec![late.clone(), late]).await);
    assert!(reason.contains("duplicate MKI"), "{reason}");
}

#[tokio::test]
async fn audio_rtcp_app_on_a_keyed_seat_never_uses_the_floor_keys() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (audio, audio_addr) = phone().await;
    let (floor, floor_addr) = phone().await;
    let keys = vec![key(7, 0x31, 12)];
    let offer = sdp_with_floor(audio_addr, floor_addr, "PCMU/8000");
    engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: "a".into(),
                sdp: offer,
                profile: keyed_profile(keys),
            },
        )
        .await;
    assert_eq!(
        send_app(&engine, None, "a", RtcpAppStream::Audio).await,
        ok_empty()
    );
    let received = loop {
        let datagram = recv_datagram(&audio, SHORT).await.expect("audio rtcp");
        if siphon_rtp_media::rtcp::app_packets(&datagram)
            .next()
            .is_some()
        {
            break datagram;
        }
    };
    let app = siphon_rtp_media::rtcp::app_packets(&received)
        .next()
        .unwrap()
        .unwrap();
    assert_eq!((app.subtype, app.ssrc), (17, 0xCAFE_F00D), "plain APP");
    assert!(recv_datagram(&floor, NEGATIVE).await.is_none());
}

struct Party {
    _audio: UdpSocket,
    floor: UdpSocket,
    audio_addr: SocketAddr,
    floor_addr: SocketAddr,
}

async fn party() -> Party {
    let (audio, audio_addr) = phone().await;
    let (floor, floor_addr) = phone().await;
    Party {
        _audio: audio,
        floor,
        audio_addr,
        floor_addr,
    }
}

/// A call whose parties each carry their own floor keys. Returns the engine floor ports toward A and B.
async fn keyed_call(
    engine: &Engine<UdpLoopbackDatapath>,
    a: &Party,
    b: &Party,
    a_keys: Vec<FloorKey>,
    b_keys: Vec<FloorKey>,
) -> (SocketAddr, SocketAddr) {
    let to_b = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_with_floor(a.audio_addr, a.floor_addr, "PCMU/8000"),
                profile: keyed_profile(a_keys),
            },
        )
        .await;
    let to_a = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_with_floor(b.audio_addr, b.floor_addr, "PCMU/8000"),
                profile: keyed_profile(b_keys),
            },
        )
        .await;
    let toward_b = sdp::parse_floor(&ok_sdp_text(&to_b)).unwrap().remote;
    let toward_a = sdp::parse_floor(&ok_sdp_text(&to_a)).unwrap().remote;
    (toward_a, toward_b)
}

#[tokio::test]
async fn both_legs_of_a_call_are_protected_under_their_own_keys_in_both_directions() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let (a, b) = (party().await, party().await);
    let (a_keys, b_keys) = (vec![key(0xA1, 0x31, 12)], vec![key(0xB2, 0x62, 14)]);
    let (toward_a, toward_b) = keyed_call(&engine, &a, &b, a_keys.clone(), b_keys.clone()).await;
    let (mut ue_a, mut ue_b) = (phone_context(&a_keys), phone_context(&b_keys));

    a.floor
        .send_to(&protect(&mut ue_a, &FLOOR_REQUEST), toward_a)
        .await
        .unwrap();
    assert_eq!(
        next_app(&app_events).await,
        floor_request_event("tag-a", Some(CALL))
    );
    b.floor
        .send_to(&protect(&mut ue_b, &FLOOR_REQUEST), toward_b)
        .await
        .unwrap();
    assert_eq!(
        next_app(&app_events).await,
        floor_request_event("tag-b", Some(CALL))
    );
    // A's key does not open B's leg.
    b.floor
        .send_to(&protect(&mut ue_a, &FLOOR_REQUEST), toward_b)
        .await
        .unwrap();
    assert!(tokio::time::timeout(NEGATIVE, app_events.recv_async())
        .await
        .is_err());

    for (tag, party, ue, mki) in [
        ("tag-a", &a, &mut ue_a, 0xA1),
        ("tag-b", &b, &mut ue_b, 0xB2),
    ] {
        assert_eq!(
            send_app(&engine, Some(CALL), tag, RtcpAppStream::Floor).await,
            ok_empty()
        );
        let wire = recv_datagram(&party.floor, SHORT).await.expect("granted");
        assert_eq!(wire_mki(&wire), mki);
        let mut plain = Vec::new();
        ue.unprotect(&wire, &mut plain).unwrap();
        assert_ne!(plain.len(), 0);
        assert_eq!(&plain[4..8], &0xCAFE_F00Du32.to_be_bytes());
    }
}

#[tokio::test]
async fn a_keyed_call_leg_drops_plaintext_and_a_replay_and_one_party_can_stay_unkeyed() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let (a, b) = (party().await, party().await);
    let a_keys = vec![key(0xA1, 0x31, 12)];
    let (toward_a, toward_b) = keyed_call(&engine, &a, &b, a_keys.clone(), Vec::new()).await;
    let mut ue_a = phone_context(&a_keys);

    a.floor.send_to(&FLOOR_REQUEST, toward_a).await.unwrap();
    assert!(tokio::time::timeout(NEGATIVE, app_events.recv_async())
        .await
        .is_err());
    let genuine = protect(&mut ue_a, &FLOOR_REQUEST);
    a.floor.send_to(&genuine, toward_a).await.unwrap();
    assert_eq!(
        next_app(&app_events).await,
        floor_request_event("tag-a", Some(CALL))
    );
    a.floor.send_to(&genuine, toward_a).await.unwrap();
    assert!(tokio::time::timeout(NEGATIVE, app_events.recv_async())
        .await
        .is_err());

    // B has no keys: plain behaviour, unchanged.
    b.floor.send_to(&FLOOR_REQUEST, toward_b).await.unwrap();
    assert_eq!(
        next_app(&app_events).await,
        floor_request_event("tag-b", Some(CALL))
    );
    send_app(&engine, Some(CALL), "tag-b", RtcpAppStream::Floor).await;
    assert_eq!(
        recv_datagram(&b.floor, SHORT).await.expect("granted"),
        granted_plain()
    );
}

#[tokio::test]
async fn set_floor_keys_on_a_call_rekeys_one_leg_and_is_scoped_to_the_owner() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let _other = engine.register_client(ClientId(2));
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");
    let (a, b) = (party().await, party().await);
    let (k1, k2) = (key(1, 0x31, 12), key(2, 0x32, 12));
    let (toward_a, _) = keyed_call(&engine, &a, &b, vec![k1.clone()], Vec::new()).await;
    let (mut ue1, mut ue2) = (
        phone_context(std::slice::from_ref(&k1)),
        phone_context(std::slice::from_ref(&k2)),
    );

    assert_eq!(
        set_keys(&engine, Some(CALL), "tag-a", vec![k1.clone(), k2.clone()]).await,
        ok_empty()
    );
    send_app(&engine, Some(CALL), "tag-a", RtcpAppStream::Floor).await;
    let wire = recv_datagram(&a.floor, SHORT).await.expect("granted");
    assert_eq!(wire_mki(&wire), 2);
    a.floor
        .send_to(&protect(&mut ue1, &FLOOR_REQUEST), toward_a)
        .await
        .unwrap();
    assert_eq!(
        next_app(&app_events).await,
        floor_request_event("tag-a", Some(CALL))
    );
    a.floor
        .send_to(&protect(&mut ue2, &FLOOR_REQUEST), toward_a)
        .await
        .unwrap();
    assert_eq!(
        next_app(&app_events).await,
        floor_request_event("tag-a", Some(CALL))
    );

    // Another client cannot see the call, so it cannot rekey it, exactly as for send_rtcp_app.
    let refused = engine
        .handle(
            ClientId(2),
            Command::SetFloorKeys {
                call_id: Some(CALL.into()),
                conference_id: None,
                from_tag: "tag-a".into(),
                keys: vec![k2.clone()],
            },
        )
        .await;
    assert!(expect_error(refused).contains("unknown call"));
    // An unknown leg tag.
    let reason = expect_error(set_keys(&engine, Some(CALL), "tag-z", vec![k2]).await);
    assert!(reason.contains("tag-z"), "{reason}");
}

#[tokio::test]
async fn invalid_keys_are_refused_before_a_call_is_set_up() {
    let engine = engine_with_dispatcher();
    let (_, audio) = phone().await;
    let (_, floor) = phone().await;
    let result = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_with_floor(audio, floor, "PCMU/8000"),
                profile: keyed_profile(vec![key(5, 0x31, 12), key(5, 0x32, 12)]),
            },
        )
        .await;
    assert!(expect_error(result).contains("duplicate MKI"));
    assert!(engine.endpoint_calls.is_empty(), "nothing was allocated");
}

#[tokio::test]
async fn a_single_leg_local_answer_and_an_engine_offered_seat_are_keyed_too() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let app_events = engine.app_event_receiver(CLIENT).expect("queue");

    // answer_local: the caller's own profile keys its only leg.
    let a = party().await;
    let keys = vec![key(0xA1, 0x31, 12)];
    let answer = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "local".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_with_floor(a.audio_addr, a.floor_addr, "PCMU/8000"),
                profile: keyed_profile(keys.clone()),
            },
        )
        .await;
    let engine_floor = sdp::parse_floor(&ok_sdp_text(&answer)).unwrap().remote;
    let mut ue = phone_context(&keys);
    a.floor.send_to(&FLOOR_REQUEST, engine_floor).await.unwrap();
    a.floor
        .send_to(&protect(&mut ue, &FLOOR_REQUEST), engine_floor)
        .await
        .unwrap();
    assert_eq!(
        next_app(&app_events).await,
        floor_request_event("tag-a", Some("local"))
    );
    assert!(
        app_events.try_recv().is_err(),
        "the plaintext one was dropped"
    );
    send_app(&engine, Some("local"), "tag-a", RtcpAppStream::Floor).await;
    let wire = recv_datagram(&a.floor, SHORT).await.expect("granted");
    assert_eq!(wire_mki(&wire), 0xA1);

    // forward_offer / forward_answer: the offering profile keys the seat the answer seats.
    let (audio, audio_addr) = phone().await;
    let (floor, floor_addr) = phone().await;
    let keys = vec![key(0xB2, 0x62, 14)];
    let offered = engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                media: ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: "d".into(),
                profile: keyed_profile(keys.clone()),
            },
        )
        .await;
    assert!(
        sdp::parse_floor(&ok_sdp_text(&offered)).is_some(),
        "{offered:?}"
    );
    let answered = engine
        .handle(
            CLIENT,
            Command::ForwardAnswer {
                conference_id: ROOM.into(),
                from_tag: "d".into(),
                sdp: sdp_with_floor(audio_addr, floor_addr, "PCMU/8000"),
                received_from: None,
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
    let engine_floor = sdp::parse_floor(&ok_sdp_text(&offered)).unwrap().remote;
    let mut ue = phone_context(&keys);
    floor.send_to(&FLOOR_REQUEST, engine_floor).await.unwrap();
    floor
        .send_to(&protect(&mut ue, &FLOOR_REQUEST), engine_floor)
        .await
        .unwrap();
    assert_eq!(next_app(&app_events).await, floor_request_event("d", None));
    send_app(&engine, None, "d", RtcpAppStream::Floor).await;
    let wire = recv_datagram(&floor, SHORT).await.expect("granted");
    assert_eq!(wire_mki(&wire), 0xB2);
    drop(audio);
}
