#![cfg(test)]

//! An owner app drives an IVR on a merged call: the digits it sends into a conference reach the
//! other seats as RFC 4733 telephone-events in each seat's own format, when its seat is set to
//! forward them (`dtmf: forward`), and stay `dtmf` events otherwise.
//!
//! The owner is a plain RTP/AVP Opus seat with `telephone-event/48000` (a WebRTC owner minus the
//! browser); the other seats are two live G.711 A-law calls seated in place. Real loopback sockets,
//! the redirect dispatcher live.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_codec::Decoder as _;
use siphon_rtp_media::dtmf::TelephoneEvent;
use siphon_rtp_media::rtp::{write_packet, RtpHeader, RtpPacket};
use siphon_rtp_proto::ConferenceDtmf;

const ROOM: &str = "ivr";
const OWNER_SSRC: u32 = 0x0B0B_0B0B;

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

/// A carrier-side offer: A-law with `telephone-event/8000` on payload type 101.
fn carrier_sdp(rtp: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\na=rtcp-mux\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
    )
}

/// The owner's offer: Opus plus `telephone-event/48000` (RFC 7587 / RFC 4733 §2.1).
fn owner_sdp(rtp: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 111 101\r\na=rtpmap:111 opus/48000/2\r\n\
         a=rtpmap:101 telephone-event/48000\r\na=fmtp:101 0-15\r\na=ptime:20\r\na=sendrecv\r\n\
         a=rtcp-mux\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
    )
}

/// A carrier's call up through the engine: the subscriber's leg and the far leg that gets seated.
struct CarrierCall {
    /// Held so the subscriber's socket stays open until the leg is seated.
    _near_phone: UdpSocket,
    far_phone: UdpSocket,
    engine_far: SocketAddr,
}

async fn carrier_call(engine: &Engine<UdpLoopbackDatapath>, call_id: &str) -> CarrierCall {
    let (near_phone, near_addr) = phone().await;
    let (far_phone, far_addr) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: format!("{call_id}-near"),
                sdp: carrier_sdp(near_addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let engine_far = sdp::parse(&ok_sdp_text(&offer))
        .expect("offer reply")
        .remote_rtp;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: format!("{call_id}-near"),
                to_tag: format!("{call_id}-far"),
                sdp: carrier_sdp(far_addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(answer, CmdResult::Ok { .. }), "{answer:?}");
    CarrierCall {
        _near_phone: near_phone,
        far_phone,
        engine_far,
    }
}

async fn seat_far_leg(engine: &Engine<UdpLoopbackDatapath>, call_id: &str) {
    let seated = engine
        .handle(
            CLIENT,
            Command::ConferenceSeat {
                call_id: call_id.into(),
                from_tag: format!("{call_id}-far"),
                conference_id: ROOM.into(),
                role: ConferenceRole::Talker,
                dtmf: ConferenceDtmf::Events,
            },
        )
        .await;
    assert!(matches!(seated, CmdResult::Ok { .. }), "{seated:?}");
}

/// The owner joins the room with its digits forwarded or not.
async fn join_owner(
    engine: &Engine<UdpLoopbackDatapath>,
    dtmf: ConferenceDtmf,
) -> (UdpSocket, SocketAddr) {
    let (phone, addr) = phone().await;
    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: ROOM.into(),
                from_tag: "owner".into(),
                sdp: owner_sdp(addr),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
                dtmf,
            },
        )
        .await;
    let engine_addr = sdp::parse(&ok_sdp_text(&joined))
        .expect("join answer")
        .remote_rtp;
    (phone, engine_addr)
}

/// One telephone-event packet from the owner at its 48 kHz event clock.
fn owner_event(sequence: u16, timestamp: u32, end: bool, duration: u16) -> Vec<u8> {
    let [high, low] = duration.to_be_bytes();
    let payload = [5u8, (u8::from(end) << 7) | 10, high, low];
    let header = RtpHeader {
        marker: sequence == 0,
        payload_type: 101,
        sequence,
        timestamp,
        ssrc: OWNER_SSRC,
    };
    let mut buffer = vec![0u8; 16];
    let length = write_packet(&header, &payload, &mut buffer).expect("write");
    buffer.truncate(length);
    buffer
}

/// The owner holds `5` for 60 ms and releases it (RFC 4733 §2.5.1.3: updates, then three Ends).
async fn owner_presses_five(phone: &UdpSocket, to: SocketAddr, timestamp: u32, sequence: u16) {
    let packets = [
        owner_event(sequence, timestamp, false, 960),
        owner_event(sequence + 1, timestamp, false, 1920),
        owner_event(sequence + 2, timestamp, true, 2880),
        owner_event(sequence + 3, timestamp, true, 2880),
        owner_event(sequence + 4, timestamp, true, 2880),
    ];
    for packet in packets {
        phone.send_to(&packet, to).await.expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn collect(socket: &UdpSocket, window: Duration) -> Vec<Vec<u8>> {
    let mut received = Vec::new();
    let mut buffer = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + window;
    while let Ok(Ok((length, _))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await
    {
        received.push(buffer[..length].to_vec());
    }
    received
}

/// The telephone-event packets (payload type 101) among `datagrams`.
fn events_of(datagrams: &[Vec<u8>]) -> Vec<(RtpHeader, TelephoneEvent)> {
    datagrams
        .iter()
        .filter_map(|datagram| {
            let packet = RtpPacket::parse(datagram).ok()?;
            if packet.payload_type != 101 {
                return None;
            }
            let header = RtpHeader {
                marker: packet.marker,
                payload_type: packet.payload_type,
                sequence: packet.sequence,
                timestamp: packet.timestamp,
                ssrc: packet.ssrc,
            };
            Some((header, TelephoneEvent::parse(packet.payload).ok()?))
        })
        .collect()
}

/// The loudest A-law audio packet among `datagrams`, as frame energy.
fn loudest_audio(datagrams: &[Vec<u8>]) -> i64 {
    let mut decoder = siphon_rtp_codec::g711::G711::alaw();
    datagrams
        .iter()
        .filter_map(|datagram| {
            let packet = RtpPacket::parse(datagram).ok()?;
            if packet.payload_type != 8 {
                return None;
            }
            let mut pcm = vec![0i16; 320];
            let samples = decoder.decode(packet.payload, &mut pcm).ok()?;
            Some(siphon_rtp_dsp::EnergyVad::energy(&pcm[..samples]))
        })
        .max()
        .unwrap_or(0)
}

/// Keep each carrier phone sending (so the room latches it) and let the room settle.
async fn settle(carriers: &[&CarrierCall]) {
    for sequence in 0..5u16 {
        for carrier in carriers {
            carrier
                .far_phone
                .send_to(
                    &g711_rtp(8, sequence, 0x0A0A_0A0A, 0xD5),
                    carrier.engine_far,
                )
                .await
                .expect("send");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for carrier in carriers {
        let _ = collect(&carrier.far_phone, Duration::from_millis(60)).await;
    }
}

fn dtmf_events(events: &flume::Receiver<Event>) -> Vec<(String, String, u32)> {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|event| match event {
            Event::Dtmf {
                from_tag,
                digit,
                duration_ms,
                ..
            } => Some((from_tag, digit, duration_ms)),
            _ => None,
        })
        .collect()
}

/// The owner forwards: each carrier phone gets the digit as PT 101 events at its own 8 kHz clock,
/// on its own stream, and the audio mix it receives carries no tone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owners_digit_reaches_every_carrier_as_events_and_not_as_audio() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let x = carrier_call(&engine, "call-x").await;
    let y = carrier_call(&engine, "call-y").await;
    let (owner, engine_owner) = join_owner(&engine, ConferenceDtmf::Forward).await;
    seat_far_leg(&engine, "call-x").await;
    seat_far_leg(&engine, "call-y").await;
    settle(&[&x, &y]).await;

    owner_presses_five(&owner, engine_owner, 960_000, 100).await;

    let mut ssrcs = Vec::new();
    for carrier in [&x, &y] {
        let received = collect(&carrier.far_phone, Duration::from_millis(300)).await;
        let forwarded = events_of(&received);
        assert_eq!(forwarded.len(), 5, "every packet of the press arrives");
        assert!(forwarded.iter().all(|(_, event)| event.event == 5));
        assert!(forwarded[0].0.marker, "the first packet is marked");
        assert!(forwarded[1..].iter().all(|(header, _)| !header.marker));
        assert!(
            forwarded
                .iter()
                .all(|(header, _)| header.timestamp == forwarded[0].0.timestamp),
            "one event, one timestamp (RFC 4733 §2.5.1.2)"
        );
        assert_eq!(
            forwarded.iter().filter(|(_, event)| event.end).count(),
            3,
            "the three redundant End packets"
        );
        let durations: Vec<u16> = forwarded.iter().map(|(_, event)| event.duration).collect();
        assert_eq!(
            durations,
            [160, 320, 480, 480, 480],
            "48 kHz durations at the carrier's 8 kHz"
        );
        assert!(
            loudest_audio(&received) < 100_000,
            "the tone is an event, not audio in the mix"
        );
        ssrcs.push(forwarded[0].0.ssrc);
    }
    assert_ne!(ssrcs[0], ssrcs[1], "each carrier has its own stream");
    assert_ne!(ssrcs[0], OWNER_SSRC);
    let raised = dtmf_events(&events);
    assert!(
        raised.contains(&("owner".to_string(), "5".to_string(), 60)),
        "the dtmf event is raised with the owner's 48 kHz duration: {raised:?}"
    );
}

/// Off by default, and off again after `conference_route`: no event packet reaches a carrier, and the
/// `dtmf` event is still raised.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_forwarding_the_carriers_get_no_events() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let x = carrier_call(&engine, "call-x").await;
    let (owner, engine_owner) = join_owner(&engine, ConferenceDtmf::Events).await;
    seat_far_leg(&engine, "call-x").await;
    settle(&[&x]).await;

    owner_presses_five(&owner, engine_owner, 960_000, 100).await;
    let received = collect(&x.far_phone, Duration::from_millis(300)).await;
    assert!(
        events_of(&received).is_empty(),
        "the default is events only"
    );
    assert_eq!(
        dtmf_events(&events).len(),
        1,
        "the dtmf event still arrives"
    );

    // Switch it on, then off again, with `conference_route`.
    let route = |dtmf: Option<ConferenceDtmf>| Command::ConferenceRoute {
        conference_id: ROOM.into(),
        from_tag: "owner".into(),
        role: ConferenceRole::Talker,
        dtmf,
    };
    let on = engine
        .handle(CLIENT, route(Some(ConferenceDtmf::Forward)))
        .await;
    assert!(matches!(on, CmdResult::Ok { .. }), "{on:?}");
    owner_presses_five(&owner, engine_owner, 1_200_000, 200).await;
    let received = collect(&x.far_phone, Duration::from_millis(300)).await;
    assert_eq!(events_of(&received).len(), 5, "switched on live");

    // A role-only route leaves the setting alone.
    let kept = engine.handle(CLIENT, route(None)).await;
    assert!(matches!(kept, CmdResult::Ok { .. }), "{kept:?}");
    owner_presses_five(&owner, engine_owner, 1_400_000, 300).await;
    let received = collect(&x.far_phone, Duration::from_millis(300)).await;
    assert_eq!(
        events_of(&received).len(),
        5,
        "a route without dtmf keeps it"
    );

    let off = engine
        .handle(CLIENT, route(Some(ConferenceDtmf::Events)))
        .await;
    assert!(matches!(off, CmdResult::Ok { .. }), "{off:?}");
    owner_presses_five(&owner, engine_owner, 1_600_000, 400).await;
    let received = collect(&x.far_phone, Duration::from_millis(300)).await;
    assert!(events_of(&received).is_empty(), "switched off live");
    assert_eq!(
        dtmf_events(&events).len(),
        3,
        "every press still raised its dtmf event"
    );
}

/// `conference_route` names a seat the room does not have: the error the verb promises, not a
/// silent `ok`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routing_an_unknown_tag_is_an_error() {
    let engine = engine_with_dispatcher();
    let (_owner, _) = join_owner(&engine, ConferenceDtmf::Events).await;
    let result = engine
        .handle(
            CLIENT,
            Command::ConferenceRoute {
                conference_id: ROOM.into(),
                from_tag: "nobody".into(),
                role: ConferenceRole::Muted,
                dtmf: None,
            },
        )
        .await;
    assert!(matches!(result, CmdResult::Error { .. }), "{result:?}");
}

/// The seat verbs carry the option into the room: a `conference_seat` leg forwards its own digits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seated_call_leg_can_forward_its_digits_too() {
    let engine = engine_with_dispatcher();
    let x = carrier_call(&engine, "call-x").await;
    let (listener, _) = join_owner(&engine, ConferenceDtmf::Events).await;
    let seated = engine
        .handle(
            CLIENT,
            Command::ConferenceSeat {
                call_id: "call-x".into(),
                from_tag: "call-x-far".into(),
                conference_id: ROOM.into(),
                role: ConferenceRole::Talker,
                dtmf: ConferenceDtmf::Forward,
            },
        )
        .await;
    assert!(matches!(seated, CmdResult::Ok { .. }), "{seated:?}");
    settle(&[&x]).await;
    // The carrier presses 5 at its 8 kHz clock; the Opus seat has telephone-event/48000, so it
    // receives the event rescaled to its 48 kHz event clock and audio clock.
    let press = |sequence: u16, end: bool, duration: u16| {
        let [high, low] = duration.to_be_bytes();
        let header = RtpHeader {
            marker: false,
            payload_type: 101,
            sequence,
            timestamp: 8_000,
            ssrc: 0x0A0A_0A0A,
        };
        let mut buffer = vec![0u8; 16];
        let length = write_packet(
            &header,
            &[5, (u8::from(end) << 7) | 10, high, low],
            &mut buffer,
        )
        .expect("write");
        buffer.truncate(length);
        buffer
    };
    for packet in [press(10, false, 160), press(11, true, 480)] {
        x.far_phone
            .send_to(&packet, x.engine_far)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let received = collect(&listener, Duration::from_millis(300)).await;
    let forwarded = events_of(&received);
    assert_eq!(forwarded.len(), 2, "both packets reach the Opus seat");
    assert_eq!(forwarded[1].1.duration, 2880, "8 kHz rescaled to 48 kHz");
}

/// A controller gates sending the option on the advertised feature.
#[tokio::test]
async fn node_info_advertises_the_conference_dtmf_feature() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("node_info answers a node");
    };
    assert!(
        node.features.iter().any(|name| name == "conference_dtmf"),
        "{:?}",
        node.features
    );
}
