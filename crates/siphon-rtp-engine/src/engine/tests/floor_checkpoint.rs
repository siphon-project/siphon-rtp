//! HA checkpoint and restore of two-party calls that carry an MCPTT floor stream (3GPP TS 24.380 §8),
//! on two engines over the UDP-loopback datapath. The standby re-binds the primary's ports, so the
//! phones keep sending to the addresses they were given: the floor stream resumes with its latch,
//! its SSRC and, when keyed, its SRTCP keys and an outgoing index that never repeats one the primary
//! sent (RFC 7714 §9.4; 3GPP TS 33.180 §9.4).

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_proto::{FloorKey, RtcpAppStream};
use siphon_rtp_srtp::srtcp_gcm::{FloorMasterKey, SrtcpGcmContext};

const CALL: &str = "call-floor-ha";
const SHORT: Duration = Duration::from_secs(2);
const NEGATIVE: Duration = Duration::from_millis(250);
const FLOOR_FMTP: &str = "mc_queueing;mc_priority=5;mc_granted";
const MARGIN: u32 = 1 << 16;

/// TS 24.380 §8.2.4 Floor Request: SSRC 0x11223344, name MCPT, subtype 0.
const FLOOR_REQUEST: [u8; 16] = [
    0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05, 0x00,
];
const FLOOR_GRANTED_PAYLOAD: [u8; 12] = [
    0x01, 0x02, 0x00, 0x1E, 0x0E, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
];

fn bind() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// An engine on a fixed port range with the redirect dispatcher the floor streams need.
fn node(min: u16, max: u16) -> Engine<UdpLoopbackDatapath> {
    let engine = Engine::new(UdpLoopbackDatapath::with_port_range(bind(), min, max));
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

fn key(mki: u32, fill: u8) -> FloorKey {
    FloorKey {
        mki,
        key: vec![fill; 16],
        salt: vec![fill ^ 0x5A; 12],
    }
}

/// The phone's reading of a key, independent of the engine's conversion.
fn phone_context(key: &FloorKey) -> SrtcpGcmContext {
    let master_key: [u8; 16] = key.key.clone().try_into().unwrap();
    let salt: [u8; 12] = key.salt.clone().try_into().unwrap();
    SrtcpGcmContext::new(&[FloorMasterKey::from_salt_96(key.mki, master_key, &salt)]).unwrap()
}

fn protect(context: &mut SrtcpGcmContext, rtcp: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    context.protect(rtcp, true, &mut wire).unwrap();
    wire
}

/// The SRTCP index of a protected packet (RFC 7714 §9.1: the E|index word before the MKI).
fn wire_index(wire: &[u8]) -> u32 {
    let word = &wire[wire.len() - 8..wire.len() - 4];
    u32::from_be_bytes(word.try_into().unwrap()) & 0x7FFF_FFFF
}

fn profile(keys: Vec<FloorKey>) -> ProfileFlags {
    ProfileFlags {
        floor_fmtp: Some(FLOOR_FMTP.to_string()),
        floor_keys: keys,
        ..ProfileFlags::default()
    }
}

fn sdp_with_floor(audio: SocketAddr, floor: SocketAddr, muxed: bool) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n{mux}\
         m=application {floor_port} udp MCPTT\r\na=fmtp:MCPTT mc_queueing\r\n",
        ip = audio.ip(),
        port = audio.port(),
        mux = if muxed { "a=rtcp-mux\r\n" } else { "" },
        floor_port = floor.port()
    )
}

struct Party {
    audio: UdpSocket,
    audio_rtcp: UdpSocket,
    floor: UdpSocket,
    audio_addr: SocketAddr,
    floor_addr: SocketAddr,
}

async fn party() -> Party {
    let (audio, audio_addr) = phone().await;
    let (audio_rtcp, _) = phone().await;
    let (floor, floor_addr) = phone().await;
    Party {
        audio,
        audio_rtcp,
        floor,
        audio_addr,
        floor_addr,
    }
}

/// What the primary told the phones: the engine's floor ports and its audio RTP and RTCP ports.
struct Call {
    floor_toward_a: SocketAddr,
    floor_toward_b: SocketAddr,
    audio_toward_a: sdp::MediaInfo,
}

async fn set_up(
    engine: &Engine<UdpLoopbackDatapath>,
    (a, b): (&Party, &Party),
    (a_keys, b_keys): (Vec<FloorKey>, Vec<FloorKey>),
    muxed: bool,
) -> Call {
    let to_b = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_with_floor(a.audio_addr, a.floor_addr, muxed),
                profile: profile(a_keys),
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
                sdp: sdp_with_floor(b.audio_addr, b.floor_addr, muxed),
                profile: profile(b_keys),
            },
        )
        .await;
    let (to_b, to_a) = (ok_sdp_text(&to_b), ok_sdp_text(&to_a));
    Call {
        floor_toward_a: sdp::parse_floor(&to_a).unwrap().remote,
        floor_toward_b: sdp::parse_floor(&to_b).unwrap().remote,
        audio_toward_a: sdp::parse(&to_a).unwrap(),
    }
}

async fn checkpoint(engine: &Engine<UdpLoopbackDatapath>) -> String {
    match engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
            },
        )
        .await
    {
        CmdResult::Checkpoint { snapshot } => snapshot,
        other => panic!("expected a checkpoint, got {other:?}"),
    }
}

/// The primary goes away (its ports are freed) and the standby on the same range restores the call.
async fn fail_over(
    primary: Engine<UdpLoopbackDatapath>,
    snapshot: String,
    (min, max): (u16, u16),
) -> Engine<UdpLoopbackDatapath> {
    primary
        .handle(
            CLIENT,
            Command::Delete {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    drop(primary);
    let standby = node(min, max);
    let _events = standby.register_client(CLIENT);
    let restored = standby.handle(CLIENT, Command::Restore { snapshot }).await;
    assert!(matches!(restored, CmdResult::Ok { .. }), "{restored:?}");
    standby
}

async fn send_granted(engine: &Engine<UdpLoopbackDatapath>, tag: &str) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::SendRtcpApp {
                call_id: Some(CALL.into()),
                conference_id: None,
                from_tag: Some(tag.into()),
                except_from_tags: Vec::new(),
                stream: RtcpAppStream::Floor,
                ssrc: None,
                name: "MCPT".into(),
                subtype: 17,
                payload: FLOOR_GRANTED_PAYLOAD.to_vec(),
            },
        )
        .await
}

async fn next_app(events: &flume::Receiver<Event>) -> Event {
    tokio::time::timeout(SHORT, events.recv_async())
        .await
        .expect("an rtcp_app event")
        .expect("open queue")
}

async fn silent(events: &flume::Receiver<Event>) -> bool {
    tokio::time::timeout(NEGATIVE, events.recv_async())
        .await
        .is_err()
}

async fn datagram(socket: &UdpSocket, window: Duration) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buffer = [0u8; 2048];
    match tokio::time::timeout(window, socket.recv_from(&mut buffer)).await {
        Ok(Ok((length, from))) => Some((buffer[..length].to_vec(), from)),
        _ => None,
    }
}

/// The SSRC of the first RTCP packet of a plain datagram.
fn ssrc_of(plain: &[u8]) -> u32 {
    u32::from_be_bytes(plain[4..8].try_into().unwrap())
}

fn is_floor_request(event: &Event, tag: &str) -> bool {
    matches!(
        event,
        Event::RtcpApp { call_id, from_tag, stream: RtcpAppStream::Floor, name, .. }
            if call_id.as_deref() == Some(CALL) && from_tag == tag && name == "MCPT"
    )
}

#[tokio::test]
async fn a_plain_floor_call_resumes_on_the_standby_with_its_ports_and_ssrc() {
    let range = (50_000u16, 50_040u16);
    let primary = node(range.0, range.1);
    let _events = primary.register_client(CLIENT);
    let app_events = primary.app_event_receiver(CLIENT).unwrap();
    let (a, b) = (party().await, party().await);
    let call = set_up(&primary, (&a, &b), (Vec::new(), Vec::new()), true).await;

    // The primary serves both legs; A's request latches its source, and the SSRC the engine
    // uses toward A is read off a grant.
    a.floor
        .send_to(&FLOOR_REQUEST, call.floor_toward_a)
        .await
        .unwrap();
    assert!(is_floor_request(&next_app(&app_events).await, "tag-a"));
    assert_eq!(send_granted(&primary, "tag-a").await, ok_empty());
    let (before, from) = datagram(&a.floor, SHORT).await.expect("grant");
    assert_eq!(from, call.floor_toward_a);

    let snapshot = checkpoint(&primary).await;
    let standby = fail_over(primary, snapshot, range).await;
    let app_events = standby.app_event_receiver(CLIENT).unwrap();

    // A's request reaches the standby's controller through the same engine port, and so does B's.
    a.floor
        .send_to(&FLOOR_REQUEST, call.floor_toward_a)
        .await
        .unwrap();
    assert!(is_floor_request(&next_app(&app_events).await, "tag-a"));
    b.floor
        .send_to(&FLOOR_REQUEST, call.floor_toward_b)
        .await
        .unwrap();
    assert!(is_floor_request(&next_app(&app_events).await, "tag-b"));

    // What the standby sends comes from the same floor port, under the same SSRC.
    assert_eq!(send_granted(&standby, "tag-a").await, ok_empty());
    let (after, from) = datagram(&a.floor, SHORT).await.expect("grant");
    assert_eq!(from, call.floor_toward_a, "same floor port");
    assert_eq!(ssrc_of(&after), ssrc_of(&before), "same engine SSRC");
    assert_eq!(
        after, before,
        "the same bytes: an unkeyed leg is deterministic"
    );
}

#[tokio::test]
async fn a_keyed_floor_call_resumes_with_an_index_past_everything_the_primary_sent() {
    let range = (50_100u16, 50_140u16);
    let primary = node(range.0, range.1);
    let _events = primary.register_client(CLIENT);
    let app_events = primary.app_event_receiver(CLIENT).unwrap();
    let (a, b) = (party().await, party().await);
    let (a_key, b_key) = (key(0xA1, 0x31), key(0xB2, 0x62));
    let call = set_up(
        &primary,
        (&a, &b),
        (vec![a_key.clone()], vec![b_key.clone()]),
        true,
    )
    .await;
    let (mut ue_a, mut ue_b) = (phone_context(&a_key), phone_context(&b_key));

    // Traffic in both directions before the checkpoint: two grants to A (indices 0 and 1).
    let pre_failover_request = protect(&mut ue_a, &FLOOR_REQUEST);
    a.floor
        .send_to(&pre_failover_request, call.floor_toward_a)
        .await
        .unwrap();
    assert!(is_floor_request(&next_app(&app_events).await, "tag-a"));
    for _ in 0..2 {
        send_granted(&primary, "tag-a").await;
        datagram(&a.floor, SHORT).await.expect("grant");
    }
    let snapshot = checkpoint(&primary).await;
    // The primary sends one more after the checkpoint: index 2, which the snapshot does not know.
    send_granted(&primary, "tag-a").await;
    let (last_sent, _) = datagram(&a.floor, SHORT).await.expect("grant");
    assert_eq!(wire_index(&last_sent), 2);

    let standby = fail_over(primary, snapshot, range).await;
    let app_events = standby.app_event_receiver(CLIENT).unwrap();

    // Standby to A: protected under A's key (MKI) and strictly past anything the primary sent.
    assert_eq!(send_granted(&standby, "tag-a").await, ok_empty());
    let (first, from) = datagram(&a.floor, SHORT).await.expect("grant");
    assert_eq!(from, call.floor_toward_a);
    assert_eq!(
        u32::from_be_bytes(first[first.len() - 4..].try_into().unwrap()),
        0xA1
    );
    assert!(wire_index(&first) > wire_index(&last_sent));
    assert_eq!(wire_index(&first), 2 + MARGIN, "checkpoint index + margin");
    let mut plain = Vec::new();
    ue_a.unprotect(&first, &mut plain).expect("A opens it");
    // And the next one counts on from there.
    send_granted(&standby, "tag-a").await;
    let (second, _) = datagram(&a.floor, SHORT).await.expect("grant");
    assert_eq!(wire_index(&second), 3 + MARGIN);

    // The same for B, which the primary never wrote to: it resumes at 0 + margin.
    send_granted(&standby, "tag-b").await;
    let (to_b, _) = datagram(&b.floor, SHORT).await.expect("grant");
    assert_eq!(wire_index(&to_b), MARGIN);
    ue_b.unprotect(&to_b, &mut plain).expect("B opens it");

    // Phone to standby: protected requests are read, in both legs.
    a.floor
        .send_to(&protect(&mut ue_a, &FLOOR_REQUEST), call.floor_toward_a)
        .await
        .unwrap();
    assert!(is_floor_request(&next_app(&app_events).await, "tag-a"));
    b.floor
        .send_to(&protect(&mut ue_b, &FLOOR_REQUEST), call.floor_toward_b)
        .await
        .unwrap();
    assert!(is_floor_request(&next_app(&app_events).await, "tag-b"));

    // What the primary had already consumed is not accepted twice, and plaintext still is not.
    a.floor
        .send_to(&pre_failover_request, call.floor_toward_a)
        .await
        .unwrap();
    a.floor
        .send_to(&FLOOR_REQUEST, call.floor_toward_a)
        .await
        .unwrap();
    assert!(
        silent(&app_events).await,
        "replay and plaintext are dropped"
    );
}

#[tokio::test]
async fn a_restored_latch_stays_closed_to_a_new_source() {
    let range = (50_200u16, 50_240u16);
    let primary = node(range.0, range.1);
    let _events = primary.register_client(CLIENT);
    let app_events = primary.app_event_receiver(CLIENT).unwrap();
    let (a, b) = (party().await, party().await);
    let call = set_up(&primary, (&a, &b), (Vec::new(), Vec::new()), true).await;
    // A's request latches its source on the primary.
    a.floor
        .send_to(&FLOOR_REQUEST, call.floor_toward_a)
        .await
        .unwrap();
    next_app(&app_events).await;

    let snapshot = checkpoint(&primary).await;
    let standby = fail_over(primary, snapshot, range).await;
    let app_events = standby.app_event_receiver(CLIENT).unwrap();

    // Another host's socket on the signalled address passes the source gate but not the latch: a
    // restart does not reopen learning to whoever sends first.
    let (intruder, _) = phone().await;
    intruder
        .send_to(&FLOOR_REQUEST, call.floor_toward_a)
        .await
        .unwrap();
    assert!(silent(&app_events).await, "a new source is refused");
    a.floor
        .send_to(&FLOOR_REQUEST, call.floor_toward_a)
        .await
        .unwrap();
    assert!(is_floor_request(&next_app(&app_events).await, "tag-a"));
    // Replies still go to the latched phone.
    send_granted(&standby, "tag-a").await;
    assert!(datagram(&a.floor, SHORT).await.is_some());
    assert!(datagram(&intruder, NEGATIVE).await.is_none());
}

#[tokio::test]
async fn audio_rtcp_app_is_reported_on_the_standby_of_a_plain_relay_floor_call() {
    for (muxed, range) in [(true, (50_300u16, 50_340u16)), (false, (50_400, 50_440))] {
        let primary = node(range.0, range.1);
        let _events = primary.register_client(CLIENT);
        let (a, b) = (party().await, party().await);
        let call = set_up(&primary, (&a, &b), (Vec::new(), Vec::new()), muxed).await;
        assert_eq!(
            primary.owned_call_internal(CALL, |call| call.pipeline),
            Some(PipelineKind::Passthrough)
        );
        let snapshot = checkpoint(&primary).await;
        assert!(snapshot.contains("rtcp_to_userspace"), "{snapshot}");
        let standby = fail_over(primary, snapshot, range).await;
        let app_events = standby.app_event_receiver(CLIENT).unwrap();

        let mut compound = vec![0x80, 200, 0x00, 0x06];
        compound.extend_from_slice(&0xA0A0_0001u32.to_be_bytes());
        compound.extend_from_slice(&[0u8; 20]);
        compound.extend_from_slice(&FLOOR_REQUEST);
        let (sender, destination) = if muxed {
            (&a.audio, call.audio_toward_a.remote_rtcp)
        } else {
            (&a.audio_rtcp, call.audio_toward_a.remote_rtcp)
        };
        sender.send_to(&compound, destination).await.unwrap();
        let event = next_app(&app_events).await;
        assert!(
            matches!(
                &event,
                Event::RtcpApp { stream: RtcpAppStream::Audio, from_tag, .. } if from_tag == "tag-a"
            ),
            "muxed={muxed}: {event:?}"
        );
    }
}

#[tokio::test]
async fn a_floor_call_checkpoint_carries_the_stream_and_a_blob_without_it_still_restores() {
    let range = (50_500u16, 50_540u16);
    let primary = node(range.0, range.1);
    let _events = primary.register_client(CLIENT);
    let (a, b) = (party().await, party().await);
    let a_key = key(0xA1, 0x31);
    set_up(&primary, (&a, &b), (vec![a_key], Vec::new()), true).await;
    let snapshot = checkpoint(&primary).await;

    // The record names the stream, under the version an older standby refuses.
    let mut record: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(record["version"], 4);
    let floor = &record["near"]["floor"];
    assert_eq!(floor["fmtp"], FLOOR_FMTP);
    assert_eq!(floor["keys"].as_array().map(Vec::len), Some(1));
    assert!(record["far"]["floor"]["keys"].is_null(), "B is unkeyed");
    assert!(record["far"]["floor"].is_object());

    // A blob written before floor streams were checkpointed has neither field and restores as the
    // audio-only call it describes.
    for leg in ["near", "far"] {
        record[leg].as_object_mut().unwrap().remove("floor");
    }
    for flow in record["flows"].as_array_mut().unwrap() {
        flow.as_object_mut().unwrap().remove("rtcp_to_userspace");
    }
    record["version"] = 2.into();
    let standby = fail_over(primary, record.to_string(), range).await;
    assert_eq!(
        standby.owned_call_internal(CALL, |call| call.near.floor.is_none()),
        Some(true)
    );
    assert_eq!(standby.conference().floors().leg_count(), 0);
}

#[tokio::test]
async fn a_restore_that_cannot_keep_the_index_margin_is_refused_and_binds_nothing() {
    let range = (50_600u16, 50_640u16);
    let primary = node(range.0, range.1);
    let _events = primary.register_client(CLIENT);
    let (a, b) = (party().await, party().await);
    set_up(
        &primary,
        (&a, &b),
        (vec![key(0xA1, 0x31)], Vec::new()),
        true,
    )
    .await;
    let snapshot = checkpoint(&primary).await;
    let mut record: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
    // An index so close to 2^31 that the margin would wrap it (RFC 7714 §9.4).
    record["near"]["floor"]["send_index"] = 0x7FFF_FFFFu32.into();
    primary
        .handle(
            CLIENT,
            Command::Delete {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    drop(primary);
    let standby = node(range.0, range.1);
    let _events = standby.register_client(CLIENT);
    let CmdResult::Error { reason } = standby
        .handle(
            CLIENT,
            Command::Restore {
                snapshot: record.to_string(),
            },
        )
        .await
    else {
        panic!("expected a refusal");
    };
    assert!(reason.contains("RFC 7714"), "{reason}");
    assert!(standby.owned_call_internal(CALL, |_| ()).is_none());
    // Nothing stayed bound: the same ports can be taken by a restore of the genuine record.
    record["near"]["floor"]["send_index"] = 5.into();
    let restored = standby
        .handle(
            CLIENT,
            Command::Restore {
                snapshot: record.to_string(),
            },
        )
        .await;
    assert!(matches!(restored, CmdResult::Ok { .. }), "{restored:?}");
}

#[tokio::test]
async fn a_reoffer_on_the_standby_keeps_the_floor_parameters_the_controller_supplied() {
    let range = (50_700u16, 50_740u16);
    let primary = node(range.0, range.1);
    let _events = primary.register_client(CLIENT);
    let (a, b) = (party().await, party().await);
    set_up(&primary, (&a, &b), (Vec::new(), Vec::new()), true).await;
    let snapshot = checkpoint(&primary).await;
    let standby = fail_over(primary, snapshot, range).await;

    // The re-offer's profile names no floor_fmtp: the restored stream still presents the held one.
    let result = standby
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_with_floor(a.audio_addr, a.floor_addr, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let presented = ok_sdp_text(&result);
    assert!(
        presented.contains(&format!("a=fmtp:MCPTT {FLOOR_FMTP}")),
        "{presented}"
    );
}
