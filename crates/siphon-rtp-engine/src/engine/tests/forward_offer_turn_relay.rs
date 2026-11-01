//! A browser offered through `forward_offer` while the engine runs a full ICE agent and a TURN
//! client, against the real in-process `siphon-rtp-turn` server: the offer carries the allocation's
//! relayed candidate in the BUNDLE'd audio section (RFC 8839 §5.1), the browser's answer makes the
//! engine permit and bind the browser's address on the allocation, and a datagram the seat sends
//! toward the browser then leaves the relay, not the engine (RFC 8656 §12 / §11).

use super::turn_client::{drive_until, real_turn_server, rest_client, RealTurn};
use super::webrtc_floor_channel::{browser_offer, engine_with_dispatcher};
use super::*;
use siphon_rtp_dtls::DtlsCertificate;
use siphon_rtp_proto::ForwardMedia;

const ROOM: &str = "browser-group";

fn relay_engine(server: &RealTurn) -> Engine<UdpLoopbackDatapath> {
    engine_with_dispatcher()
        .with_full_ice()
        .with_turn_client(rest_client(server.address))
}

async fn offer(engine: &Engine<UdpLoopbackDatapath>) -> String {
    let result = engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                media: ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: "a".into(),
                profile: ProfileFlags {
                    transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
                    floor_fmtp: Some("mc_queueing;mc_priority=5;mc_granted".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    ok_sdp_text(&result)
}

/// A browser answer in the shape of Chrome's: the engine's bundle, plus ICE credentials and one
/// host candidate on the browser's own socket (RFC 8839 §5.1), so the engine arms a full agent.
fn browser_answer_with_candidate(socket: &UdpSocket) -> String {
    let address = socket.local_addr().expect("browser address");
    let certificate = DtlsCertificate::generate().expect("browser certificate");
    browser_offer(address, &certificate, "active", true).replace(
        "a=mid:0\r\n",
        &format!(
            "a=mid:0\r\na=ice-ufrag:BROW\r\na=ice-pwd:browserpassword0123456789\r\n\
             a=candidate:1 1 udp 2130706431 {} {} typ host\r\n",
            address.ip(),
            address.port()
        ),
    )
}

async fn answer(engine: &Engine<UdpLoopbackDatapath>, sdp: String) {
    let answered = engine
        .handle(
            CLIENT,
            Command::ForwardAnswer {
                conference_id: ROOM.into(),
                from_tag: "a".into(),
                sdp,
                received_from: None,
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
}

fn the_only_relay(engine: &Engine<UdpLoopbackDatapath>) -> EndpointId {
    assert_eq!(
        engine.ice_relays.len(),
        1,
        "one allocation for the one seat"
    );
    engine
        .ice_relays
        .iter()
        .map(|entry| *entry.key())
        .next()
        .expect("allocation")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_webrtc_offer_advertises_the_allocations_relayed_address_next_to_the_host() {
    let server = real_turn_server().await;
    let engine = relay_engine(&server);
    let offered = offer(&engine).await;

    let endpoint = the_only_relay(&engine);
    let relayed = engine
        .ice_relays
        .get(&endpoint)
        .and_then(|allocation| allocation.client.relayed_address())
        .expect("allocated");
    let lines: Vec<&str> = offered.split("\r\n").collect();
    let audio = lines
        .iter()
        .position(|line| line.starts_with("m=audio "))
        .expect("audio section");
    let channel = lines
        .iter()
        .position(|line| line.starts_with("m=application "))
        .expect("data channel section");
    let audio_section = &lines[audio..channel];
    assert!(lines.contains(&"a=group:BUNDLE 0 1"), "{offered}");
    let relay_line = audio_section
        .iter()
        .find(|line| line.starts_with("a=candidate:") && line.contains("typ relay"))
        .unwrap_or_else(|| panic!("a relay candidate in the audio section: {offered}"));
    assert!(
        relay_line.contains(&format!(
            " {} {} typ relay raddr ",
            relayed.ip(),
            relayed.port()
        )) && relay_line.contains(" rport "),
        "RFC 8839 §5.1: the relayed address with raddr/rport: {relay_line}"
    );
    assert!(
        audio_section
            .iter()
            .any(|line| line.starts_with("a=candidate:") && line.contains("typ host")),
        "the host candidate stays next to it: {offered}"
    );
    assert!(server.turn.allocation_count().await >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_browsers_answer_makes_the_engine_permit_and_bind_its_address_on_the_allocation() {
    let server = real_turn_server().await;
    let engine = relay_engine(&server);
    let _events = engine.register_client(CLIENT);
    let _offered = offer(&engine).await;
    let endpoint = the_only_relay(&engine);
    let browser = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let browser_address = browser.local_addr().expect("addr");
    answer(&engine, browser_answer_with_candidate(&browser)).await;

    let bound = drive_until(&engine, 0, 20_000, || {
        engine.ice_relays.get(&endpoint).is_some_and(|allocation| {
            allocation.client.may_send_to(browser_address)
                && allocation.client.channel_for(browser_address).is_some()
        })
    })
    .await;
    assert!(
        bound,
        "the browser's candidate got a permission and a channel on the seat's allocation"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_datagram_the_seat_sends_to_the_browser_leaves_the_relayed_address() {
    let server = real_turn_server().await;
    let engine = relay_engine(&server);
    let _events = engine.register_client(CLIENT);
    let _offered = offer(&engine).await;
    let endpoint = the_only_relay(&engine);
    let relayed = engine
        .ice_relays
        .get(&endpoint)
        .and_then(|allocation| allocation.client.relayed_address())
        .expect("allocated");
    let browser = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let browser_address = browser.local_addr().expect("addr");
    answer(&engine, browser_answer_with_candidate(&browser)).await;
    assert!(
        drive_until(&engine, 0, 20_000, || {
            engine
                .ice_relays
                .get(&endpoint)
                .is_some_and(|allocation| allocation.client.channel_for(browser_address).is_some())
        })
        .await,
        "channel bound"
    );
    // Let the channel reach the datapath on the next tick.
    engine.drive_ice_agents(30_000).await;

    engine
        .datapath()
        .send(endpoint, browser_address, b"through-the-relay")
        .await
        .expect("send");
    // The agent's own checks leave directly from the engine's endpoint, so read until the payload.
    let mut buffer = [0u8; 2048];
    let mut arrived = false;
    for _ in 0..20 {
        let (len, from) = timeout(Duration::from_secs(2), browser.recv_from(&mut buffer))
            .await
            .expect("a datagram arrives")
            .expect("recv");
        if &buffer[..len] == b"through-the-relay" {
            assert_eq!(from, relayed, "sourced from the relayed address");
            arrived = true;
            break;
        }
    }
    assert!(arrived, "the payload was relayed to the browser");
}
