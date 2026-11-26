//! A TURN-only client reaches the engine's own media endpoint through the engine's own TURN server,
//! with the secure default peer denylist in force (RFC 8656 §21, docs/security-and-nat.md §11 R3).
//!
//! The engine and the TURN server share one UDP-loopback datapath, as in the daemon. The "browser"
//! is a plain UDP client speaking TURN: it allocates, signals the relayed address as its media
//! address, permits the engine's near-leg endpoint and sends RTP to it through the relay, and the
//! call's far leg receives it; the far leg's reply comes back to the browser as a Data indication.
//! Loopback is a denylisted range, so everything that passes does so through the own-endpoint rule.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_engine::{sdp, ClientId, Engine};
use siphon_rtp_proto::{CmdResult, Command};
use siphon_rtp_stun::{self as stun, turn};
use siphon_rtp_turn::{FixedUnixClock, Turn, TurnConfig};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const REALM: &str = "siphon.test";
const SECRET: &[u8] = b"static-auth-secret";
const CLIENT: ClientId = ClientId(1);
const SHORT: Duration = Duration::from_secs(2);
const NEGATIVE: Duration = Duration::from_millis(300);

struct Rig {
    engine: Arc<Engine<UdpLoopbackDatapath>>,
    turn_address: SocketAddr,
}

/// An engine and a TURN server with the **default** denylist over one datapath.
async fn rig() -> Rig {
    let datapath = UdpLoopbackDatapath::new();
    let engine = Arc::new(Engine::new(datapath.clone()));
    let mut config = TurnConfig::new(REALM, SECRET);
    config.own_media_endpoints = Some(engine.own_media_endpoints());
    let turn = Turn::spawn(
        Arc::new(datapath),
        config,
        Arc::new(FixedUnixClock::new(1_000)),
    )
    .expect("spawn turn");
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("listener");
    let turn_address = socket.local_addr().expect("address");
    tokio::spawn(async move {
        let _ = turn.serve_udp(socket).await;
    });
    Rig {
        engine,
        turn_address,
    }
}

async fn udp() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("bind");
    let address = socket.local_addr().expect("address");
    (socket, address)
}

async fn silent(socket: &UdpSocket) -> bool {
    let mut buffer = [0u8; 2048];
    timeout(NEGATIVE, socket.recv_from(&mut buffer))
        .await
        .is_err()
}

async fn received(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buffer = [0u8; 2048];
    let (length, from) = timeout(SHORT, socket.recv_from(&mut buffer))
        .await
        .expect("datagram in time")
        .expect("recv");
    (buffer[..length].to_vec(), from)
}

/// A minimal TURN client over UDP (RFC 8656 long-term credentials with a coturn REST username).
struct Browser {
    socket: UdpSocket,
    server: SocketAddr,
    relay: SocketAddr,
    nonce: Vec<u8>,
    key: [u8; 16],
    transaction: u8,
}

const USER: &str = "2000000000:browser";

impl Browser {
    async fn allocate(server: SocketAddr) -> Self {
        let (socket, _) = udp().await;
        let mut browser = Self {
            socket,
            server,
            relay: server,
            nonce: Vec::new(),
            key: {
                let password = turn::base64_encode(&stun::hmac_sha1(SECRET, USER.as_bytes()));
                turn::long_term_key(USER, REALM, &password)
            },
            transaction: 1,
        };
        let challenge = browser.exchange(&allocate_request(None)).await;
        browser.nonce = turn::nonce(&challenge).expect("nonce").to_vec();
        let response = browser.request(turn::METHOD_ALLOCATE, &[]).await;
        assert_eq!(turn::class_of(response.message_type), turn::CLASS_SUCCESS);
        browser.relay = turn::xor_relayed_address(&response).expect("relayed address");
        browser
    }

    async fn exchange(&self, request: &[u8]) -> stun::StunMessage {
        self.socket
            .send_to(request, self.server)
            .await
            .expect("send");
        let mut buffer = [0u8; 2048];
        let (length, _) = timeout(SHORT, self.socket.recv_from(&mut buffer))
            .await
            .expect("response in time")
            .expect("recv");
        stun::parse(&buffer[..length]).expect("parse")
    }

    async fn request(&mut self, method: u16, attributes: &[(u16, Vec<u8>)]) -> stun::StunMessage {
        let transaction = [self.transaction; 12];
        self.transaction += 1;
        let mut builder = stun::MessageBuilder::new(
            turn::message_type(method, turn::CLASS_REQUEST),
            &transaction,
        )
        .attribute(turn::ATTR_USERNAME, USER.as_bytes())
        .attribute(turn::ATTR_REALM, REALM.as_bytes())
        .attribute(turn::ATTR_NONCE, &self.nonce);
        if method == turn::METHOD_ALLOCATE {
            builder = builder.attribute(
                turn::ATTR_REQUESTED_TRANSPORT,
                &turn::requested_transport_value(turn::TRANSPORT_UDP),
            );
        }
        for (kind, value) in attributes {
            builder = builder.attribute(*kind, value);
        }
        self.exchange(&builder.finish(Some(&self.key[..]), true))
            .await
    }

    async fn permit(&mut self, peer: SocketAddr) -> stun::StunMessage {
        let transaction = [self.transaction; 12];
        self.request(
            turn::METHOD_CREATE_PERMISSION,
            &[(
                turn::ATTR_XOR_PEER_ADDRESS,
                turn::xor_address_value(peer, &transaction).to_vec(),
            )],
        )
        .await
    }

    async fn send(&self, peer: SocketAddr, payload: &[u8]) {
        let transaction = [0x55u8; 12];
        let indication = stun::MessageBuilder::new(
            turn::message_type(turn::METHOD_SEND, turn::CLASS_INDICATION),
            &transaction,
        )
        .attribute(
            turn::ATTR_XOR_PEER_ADDRESS,
            &turn::xor_address_value(peer, &transaction),
        )
        .attribute(turn::ATTR_DATA, payload)
        .finish(None, false);
        self.socket
            .send_to(&indication, self.server)
            .await
            .expect("send indication");
    }

    /// The next Data indication: the peer it came from and its payload.
    async fn next_data(&self) -> (SocketAddr, Vec<u8>) {
        let (bytes, _) = received(&self.socket).await;
        let indication = stun::parse(&bytes).expect("data indication");
        (
            turn::xor_peer_address(&indication).expect("peer"),
            turn::data(&indication).expect("data").to_vec(),
        )
    }
}

fn allocate_request(nonce: Option<&[u8]>) -> Vec<u8> {
    let builder = stun::MessageBuilder::new(
        turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_REQUEST),
        &[0u8; 12],
    )
    .attribute(
        turn::ATTR_REQUESTED_TRANSPORT,
        &turn::requested_transport_value(turn::TRANSPORT_UDP),
    );
    match nonce {
        Some(nonce) => builder.attribute(turn::ATTR_NONCE, nonce),
        None => builder,
    }
    .finish(None, true)
}

fn is_forbidden(response: &stun::StunMessage) -> bool {
    turn::class_of(response.message_type) == turn::CLASS_ERROR
        && turn::error_code(response) == Some(turn::ERROR_FORBIDDEN)
}

fn audio_sdp(address: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = address.ip(),
        port = address.port()
    )
}

fn rtp(ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0];
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(b"voice");
    packet
}

fn media_address(result: &CmdResult) -> SocketAddr {
    match result {
        CmdResult::Ok {
            sdp: Some(text), ..
        } => sdp::parse(text).expect("sdp").remote_rtp,
        other => panic!("expected Ok with sdp, got {other:?}"),
    }
}

/// A call whose near party signals `near_media` (the browser's relayed address) and whose far party
/// is `far_media`. Returns the engine's `(near_leg, far_leg)` endpoints.
async fn call(
    rig: &Rig,
    call_id: &str,
    near_media: SocketAddr,
    far_media: SocketAddr,
) -> (SocketAddr, SocketAddr) {
    let offer = rig
        .engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                sdp: audio_sdp(near_media),
                profile: Default::default(),
            },
        )
        .await;
    let far_leg = media_address(&offer);
    let answer = rig
        .engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: audio_sdp(far_media),
                profile: Default::default(),
            },
        )
        .await;
    (media_address(&answer), far_leg)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_turn_only_client_reaches_the_engine_media_endpoint_and_gets_the_far_leg_back() {
    let rig = rig().await;
    let mut browser = Browser::allocate(rig.turn_address).await;
    let (far_phone, far_address) = udp().await;
    let (near_leg, far_leg) = call(&rig, "turn-own", browser.relay, far_address).await;
    assert_eq!(
        near_leg.ip(),
        browser.relay.ip(),
        "engine and relay share a host"
    );

    // Loopback is denylisted, yet the engine's own live media IP is accepted.
    let response = browser.permit(near_leg).await;
    assert_eq!(turn::class_of(response.message_type), turn::CLASS_SUCCESS);

    // Browser to far party: through the relay, into the engine's near leg, out of its far leg.
    browser.send(near_leg, &rtp(0x0A0A_0A0A)).await;
    let (data, from) = received(&far_phone).await;
    assert_eq!(data, rtp(0x0A0A_0A0A));
    assert_eq!(from, far_leg);

    // Far party to browser: the engine sends from its near leg to the signalled relay address.
    far_phone
        .send_to(&rtp(0x0B0B_0B0B), far_leg)
        .await
        .expect("send");
    let (peer, data) = browser.next_data().await;
    assert_eq!(peer, near_leg);
    assert_eq!(data, rtp(0x0B0B_0B0B));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_port_on_the_engine_ip_that_is_not_a_live_endpoint_is_dropped() {
    let rig = rig().await;
    let mut browser = Browser::allocate(rig.turn_address).await;
    let (far_phone, far_address) = udp().await;
    let (near_leg, _) = call(&rig, "turn-bystander", browser.relay, far_address).await;
    let (bystander, bystander_address) = udp().await;

    assert_eq!(
        turn::class_of(browser.permit(near_leg).await.message_type),
        turn::CLASS_SUCCESS
    );
    // The permission is per IP, so this port is permitted by IP and must still be dropped, and so
    // must the far party's own socket (not an engine endpoint either).
    browser.send(bystander_address, &rtp(1)).await;
    browser.send(far_address, &rtp(2)).await;
    assert!(silent(&bystander).await);
    assert!(silent(&far_phone).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_private_ip_and_another_allocations_relay_are_still_refused() {
    let rig = rig().await;
    let mut browser = Browser::allocate(rig.turn_address).await;
    let mut other = Browser::allocate(rig.turn_address).await;
    let (_far_phone, far_address) = udp().await;
    let (near_leg, _) = call(&rig, "turn-private", browser.relay, far_address).await;

    let elsewhere: SocketAddr = "127.0.0.2:30000".parse().expect("address");
    assert!(is_forbidden(&browser.permit(elsewhere).await));

    // Both clients hold the permission on the engine's IP, which is also the IP of both relays;
    // neither relay endpoint is a media endpoint, so neither may reach the other.
    for session in [&mut browser, &mut other] {
        assert_eq!(
            turn::class_of(session.permit(near_leg).await.message_type),
            turn::CLASS_SUCCESS
        );
    }
    browser.send(other.relay, &rtp(3)).await;
    assert!(silent(&other.socket).await, "relay to relay hairpin");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_torn_down_calls_port_is_dropped_even_when_something_else_binds_it() {
    let rig = rig().await;
    let mut browser = Browser::allocate(rig.turn_address).await;
    let (_far_phone, far_address) = udp().await;
    let (near_leg, _) = call(&rig, "turn-teardown", browser.relay, far_address).await;
    assert_eq!(
        turn::class_of(browser.permit(near_leg).await.message_type),
        turn::CLASS_SUCCESS
    );
    assert!(rig
        .engine
        .own_media_endpoints()
        .is_live_media_endpoint(near_leg));

    let deleted = rig
        .engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "turn-teardown".into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));
    assert!(!rig
        .engine
        .own_media_endpoints()
        .is_live_media_endpoint(near_leg));
    assert!(
        !rig.engine
            .own_media_endpoints()
            .hosts_media_on(near_leg.ip()),
        "no endpoint left on the IP"
    );

    // The port is free again; whatever binds it next must not be reachable through the still-valid
    // permission (it is the per-packet check that stops this, not a closed socket).
    // Another test in this process can take the freed port first; then the registry assertions above
    // are what is left to check, and the squatter is that other test's socket anyway.
    if let Ok(squatter) = UdpSocket::bind(near_leg).await {
        browser.send(near_leg, &rtp(4)).await;
        assert!(silent(&squatter).await);
    }
}
