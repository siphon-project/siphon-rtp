//! A NATed participant advertises a private `c=` and sends from its NAT's public address, which
//! the SIP proxy saw its request arrive from (rtpengine's `received-from`). A seat honours that hint
//! the way a two-party answer does: it admits the participant's media from that address and sends
//! the mix there, instead of gating on and aiming at the unroutable private address.
//!
//! The "NAT" is a second loopback address: the phone binds `127.0.0.5` and signals `10.0.0.7`.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_codec::Decoder as _;
use siphon_rtp_media::rtp::RtpPacket;

/// The public address the NATed phone's media comes from, and the private one its SDP advertises.
const PUBLIC: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 5);
const PRIVATE: &str = "10.0.0.7";

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

/// A PCMU SDP whose `c=` is the private address but whose port is the phone's real one.
fn natted_sdp(port: u16) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {PRIVATE}\r\ns=-\r\nc=IN IP4 {PRIVATE}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\na=rtcp-mux\r\n"
    )
}

/// Whether loud µ-law audio reaches `phone` from `engine_port` within `window`.
async fn hears_loud_within(phone: &UdpSocket, engine_port: SocketAddr, window: Duration) -> bool {
    let mut decoder = siphon_rtp_codec::g711::G711::ulaw();
    let deadline = tokio::time::Instant::now() + window;
    let mut buffer = [0u8; 2048];
    while let Ok(Ok((length, from))) =
        tokio::time::timeout_at(deadline, phone.recv_from(&mut buffer)).await
    {
        if from != engine_port {
            continue;
        }
        let Ok(packet) = RtpPacket::parse(&buffer[..length]) else {
            continue;
        };
        let mut pcm = vec![0i16; 320];
        let Ok(samples) = decoder.decode(packet.payload, &mut pcm) else {
            continue;
        };
        if siphon_rtp_dsp::EnergyVad::energy(&pcm[..samples]) > 1_000_000 {
            return true;
        }
    }
    false
}

/// A plain talker joined to `room`, returning its phone and its engine port.
async fn join_talker(engine: &Engine<UdpLoopbackDatapath>, room: &str) -> (UdpSocket, SocketAddr) {
    let (phone, addr) = phone().await;
    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: room.into(),
                from_tag: "talker".into(),
                sdp: sdp_for(addr, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let port = sdp::parse(&ok_sdp_text(&joined))
        .expect("answer")
        .remote_rtp;
    (phone, port)
}

/// How the NATed seat gets into the room, so the same checks run on both verbs.
#[derive(Clone, Copy)]
enum Verb {
    Join,
    Answer,
}

/// Seat a NATed participant (`hint` is what the proxy would send as `received-from`), returning its
/// phone and the engine port it talks to.
async fn seat_natted(
    engine: &Engine<UdpLoopbackDatapath>,
    verb: Verb,
    hint: Option<Ipv4Addr>,
) -> (UdpSocket, SocketAddr) {
    let (phone, addr) = phone_at(PUBLIC).await;
    let hint = hint.map(IpAddr::V4);
    let engine_port = match verb {
        Verb::Join => {
            let joined = engine
                .handle(
                    CLIENT,
                    Command::ConferenceJoin {
                        conference_id: "room".into(),
                        from_tag: "natted".into(),
                        sdp: natted_sdp(addr.port()),
                        role: ConferenceRole::Talker,
                        profile: ProfileFlags {
                            received_from: hint,
                            ..Default::default()
                        },
                    },
                )
                .await;
            sdp::parse(&ok_sdp_text(&joined))
                .expect("answer")
                .remote_rtp
        }
        Verb::Answer => {
            let offered = engine
                .handle(
                    CLIENT,
                    Command::ConferenceOffer {
                        conference_id: "room".into(),
                        from_tag: "natted".into(),
                        role: ConferenceRole::Talker,
                        profile: ProfileFlags::default(),
                    },
                )
                .await;
            let engine_port = sdp::parse(&ok_sdp_text(&offered))
                .expect("offer")
                .remote_rtp;
            let answered = engine
                .handle(
                    CLIENT,
                    Command::ConferenceAnswer {
                        conference_id: "room".into(),
                        from_tag: "natted".into(),
                        sdp: natted_sdp(addr.port()),
                        received_from: hint,
                    },
                )
                .await;
            assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
            engine_port
        }
    };
    (phone, engine_port)
}

/// Send loud frames from `phone` to `to` for about `frames` x 20 ms.
async fn talk_loud(phone: &UdpSocket, to: SocketAddr, ssrc: u32, frames: u16) {
    for sequence in 0..frames {
        phone
            .send_to(&g711_rtp(0, sequence, ssrc, 0x00), to)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// With the hint, the NATed seat is admitted from its public address and is sent the mix there:
/// it hears the other participant before it has sent a single packet (so the destination is the
/// hint, not a latch), and the other participant hears it.
async fn a_hinted_seat_is_heard_and_hears(verb: Verb) {
    let engine = engine_with_dispatcher();
    let (talker, talker_port) = join_talker(&engine, "room").await;
    let (natted, natted_port) = seat_natted(&engine, verb, Some(PUBLIC)).await;

    // Downlink: the talker speaks, the NATed seat has sent nothing.
    let listen = hears_loud_within(&natted, natted_port, Duration::from_secs(2));
    let speak = talk_loud(&talker, talker_port, 0x0A0A_0A0A, 60);
    let (heard, ()) = tokio::join!(listen, speak);
    assert!(heard, "the mix reaches the hinted public address");

    // Uplink: the NATed seat speaks from its public address; the talker hears it.
    let listen = hears_loud_within(&talker, talker_port, Duration::from_secs(2));
    let speak = talk_loud(&natted, natted_port, 0x0B0B_0B0B, 60);
    let (heard, ()) = tokio::join!(listen, speak);
    assert!(heard, "media from the hinted public address is admitted");
}

/// Without the hint nothing changes: the gate is the private `c=`, so the NATed seat's packets are
/// dropped, and the mix goes to the unroutable private address, not the phone.
async fn an_unhinted_seat_is_silent_both_ways(verb: Verb) {
    let engine = engine_with_dispatcher();
    let (talker, talker_port) = join_talker(&engine, "room").await;
    let (natted, natted_port) = seat_natted(&engine, verb, None).await;

    let listen = hears_loud_within(&natted, natted_port, Duration::from_millis(1_200));
    let speak = talk_loud(&talker, talker_port, 0x0A0A_0A0A, 50);
    let (heard, ()) = tokio::join!(listen, speak);
    assert!(!heard, "no hint: the mix is not sent to the public address");

    let listen = hears_loud_within(&talker, talker_port, Duration::from_millis(1_200));
    let speak = talk_loud(&natted, natted_port, 0x0B0B_0B0B, 50);
    let (heard, ()) = tokio::join!(listen, speak);
    assert!(
        !heard,
        "no hint: media from the public address stays gated out"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hinted_join_is_admitted_and_sent_the_mix_at_the_received_from_address() {
    a_hinted_seat_is_heard_and_hears(Verb::Join).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hinted_answer_is_admitted_and_sent_the_mix_at_the_received_from_address() {
    a_hinted_seat_is_heard_and_hears(Verb::Answer).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_join_without_the_hint_is_gated_on_the_private_c_line_as_before() {
    an_unhinted_seat_is_silent_both_ways(Verb::Join).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_without_the_hint_is_gated_on_the_private_c_line_as_before() {
    an_unhinted_seat_is_silent_both_ways(Verb::Answer).await;
}

/// A hint from a different address than the one media comes from does not widen the gate: the
/// phone on `127.0.0.5` stays out when the proxy said `198.51.100.9`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hint_names_the_only_source_the_gate_admits() {
    let engine = engine_with_dispatcher();
    let (talker, talker_port) = join_talker(&engine, "room").await;
    let (natted, natted_port) =
        seat_natted(&engine, Verb::Join, Some(Ipv4Addr::new(198, 51, 100, 9))).await;
    let listen = hears_loud_within(&talker, talker_port, Duration::from_millis(1_200));
    let speak = talk_loud(&natted, natted_port, 0x0B0B_0B0B, 50);
    let (heard, ()) = tokio::join!(listen, speak);
    assert!(
        !heard,
        "a source other than the hinted address is not admitted"
    );
}

/// An ICE seat keeps its existing behaviour: the hint changes neither its open gate nor where it is
/// aimed before its transport is chosen.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hint_does_not_aim_an_ice_seat() {
    let engine = engine_with_dispatcher();
    let (_phone, addr) = phone_at(PUBLIC).await;
    let sdp_text = format!(
        "{}a=ice-ufrag:abcd\r\na=ice-pwd:0123456789012345678901\r\n",
        natted_sdp(addr.port())
    );
    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "room".into(),
                from_tag: "ice".into(),
                sdp: sdp_text,
                role: ConferenceRole::Talker,
                profile: ProfileFlags {
                    received_from: Some(IpAddr::V4(PUBLIC)),
                    ..Default::default()
                },
            },
        )
        .await;
    assert!(matches!(joined, CmdResult::Ok { .. }), "{joined:?}");
}

/// A controller gates sending the hint on the advertised feature.
#[tokio::test]
async fn node_info_advertises_the_received_from_feature() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("node_info answers a node");
    };
    assert!(
        node.features
            .iter()
            .any(|name| name == "conference_received_from"),
        "{:?}",
        node.features
    );
}
