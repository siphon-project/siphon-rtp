//! The counters the built-in TURN server keeps for the host's metrics exposition, driven through
//! real allocate, refresh, refuse and relay flows over the UDP-loopback datapath: the allocation
//! gauge per client transport (and its return to zero on delete and on expiry), the relayed byte
//! counters per direction, and the refusal counters per reason.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_stun::{self as stun, turn};
use siphon_rtp_turn::{
    FixedUnixClock, OwnMediaEndpoints, PeerIpPolicy, RefusalReason, RelayDirection,
    TransportProtocol, Turn, TurnConfig, TurnMetricsSnapshot,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const REALM: &str = "siphon.test";
const SECRET: &[u8] = b"static-auth-secret";
const USER: &str = "2000000000:webrtc";
const OTHER_USER: &str = "2000000000:second";
const SHORT: Duration = Duration::from_secs(2);
const NEGATIVE: Duration = Duration::from_millis(250);

struct Server {
    addr: SocketAddr,
    datapath: UdpLoopbackDatapath,
    turn: Turn,
}

impl Server {
    fn snapshot(&self) -> TurnMetricsSnapshot {
        self.turn.metrics().snapshot()
    }

    /// Wait (bounded) until `condition` holds of the counters: the actor updates them on its own
    /// task, a moment after the datagram that caused the change.
    async fn until(&self, condition: impl Fn(&TurnMetricsSnapshot) -> bool) -> TurnMetricsSnapshot {
        for _ in 0..200 {
            let snapshot = self.snapshot();
            if condition(&snapshot) {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "counters never reached the expected state: {:?}",
            self.snapshot()
        );
    }
}

async fn start(mutate: impl FnOnce(&mut TurnConfig)) -> Server {
    let mut config = TurnConfig::new(REALM, SECRET);
    config.denied_peers = PeerIpPolicy::permissive();
    mutate(&mut config);
    let datapath = UdpLoopbackDatapath::new();
    let turn = Turn::spawn(
        Arc::new(datapath.clone()),
        config,
        Arc::new(FixedUnixClock::new(1_000)),
    )
    .expect("spawn turn");
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("listener");
    let addr = socket.local_addr().expect("addr");
    let serving = turn.clone();
    tokio::spawn(async move {
        let _ = serving.serve_udp(socket).await;
    });
    Server {
        addr,
        datapath,
        turn,
    }
}

async fn udp() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("bind");
    let addr = socket.local_addr().expect("addr");
    (socket, addr)
}

async fn exchange(socket: &UdpSocket, server: SocketAddr, request: &[u8]) -> stun::StunMessage {
    socket.send_to(request, server).await.expect("send");
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(SHORT, socket.recv_from(&mut buffer))
        .await
        .expect("response")
        .expect("recv");
    stun::parse(&buffer[..len]).expect("parse")
}

async fn received(socket: &UdpSocket) -> Vec<u8> {
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(SHORT, socket.recv_from(&mut buffer))
        .await
        .expect("datagram")
        .expect("recv");
    buffer[..len].to_vec()
}

async fn silent(socket: &UdpSocket) -> bool {
    let mut buffer = [0u8; 2048];
    timeout(NEGATIVE, socket.recv_from(&mut buffer))
        .await
        .is_err()
}

fn key_for(user: &str) -> [u8; 16] {
    let password = turn::base64_encode(&stun::hmac_sha1(SECRET, user.as_bytes()));
    turn::long_term_key(user, REALM, &password)
}

struct Session {
    client: UdpSocket,
    server: SocketAddr,
    user: &'static str,
    nonce: Vec<u8>,
    key: [u8; 16],
    next_transaction: u8,
}

impl Session {
    /// A client past its 401 challenge, holding a nonce but no allocation yet.
    async fn challenged(server: SocketAddr, user: &'static str) -> Self {
        let (client, _) = udp().await;
        let challenge = exchange(
            &client,
            server,
            &stun::MessageBuilder::new(
                turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_REQUEST),
                &[0u8; 12],
            )
            .attribute(
                turn::ATTR_REQUESTED_TRANSPORT,
                &turn::requested_transport_value(turn::TRANSPORT_UDP),
            )
            .finish(None, true),
        )
        .await;
        Self {
            client,
            server,
            user,
            nonce: turn::nonce(&challenge).expect("nonce").to_vec(),
            key: key_for(user),
            next_transaction: 1,
        }
    }

    async fn request(&mut self, method: u16, attributes: &[(u16, Vec<u8>)]) -> stun::StunMessage {
        let transaction = [self.next_transaction; 12];
        self.next_transaction += 1;
        let mut builder = stun::MessageBuilder::new(
            turn::message_type(method, turn::CLASS_REQUEST),
            &transaction,
        )
        .attribute(turn::ATTR_USERNAME, self.user.as_bytes())
        .attribute(turn::ATTR_REALM, REALM.as_bytes())
        .attribute(turn::ATTR_NONCE, &self.nonce);
        for (kind, value) in attributes {
            builder = builder.attribute(*kind, value);
        }
        exchange(
            &self.client,
            self.server,
            &builder.finish(Some(&self.key[..]), true),
        )
        .await
    }

    async fn allocate(&mut self) -> stun::StunMessage {
        self.request(
            turn::METHOD_ALLOCATE,
            &[(
                turn::ATTR_REQUESTED_TRANSPORT,
                turn::requested_transport_value(turn::TRANSPORT_UDP).to_vec(),
            )],
        )
        .await
    }

    /// An allocated client; returns the session and its relayed address.
    async fn allocated(server: SocketAddr, user: &'static str) -> (Self, SocketAddr) {
        let mut session = Self::challenged(server, user).await;
        let response = session.allocate().await;
        assert_eq!(turn::class_of(response.message_type), turn::CLASS_SUCCESS);
        let relay = turn::xor_relayed_address(&response).expect("relayed address");
        (session, relay)
    }

    async fn permit(&mut self, peer: SocketAddr) -> stun::StunMessage {
        let transaction = [self.next_transaction; 12];
        self.request(
            turn::METHOD_CREATE_PERMISSION,
            &[(
                turn::ATTR_XOR_PEER_ADDRESS,
                turn::xor_address_value(peer, &transaction).to_vec(),
            )],
        )
        .await
    }

    async fn refresh(&mut self, lifetime: u32) -> stun::StunMessage {
        self.request(
            turn::METHOD_REFRESH,
            &[(turn::ATTR_LIFETIME, turn::lifetime_value(lifetime).to_vec())],
        )
        .await
    }

    async fn send(&self, peer: SocketAddr, payload: &[u8]) {
        let transaction = [0x66u8; 12];
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
        self.client
            .send_to(&indication, self.server)
            .await
            .expect("send indication");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_allocation_is_gauged_per_transport_and_returns_to_zero_on_delete() {
    let server = start(|_| {}).await;
    assert_eq!(server.snapshot(), TurnMetricsSnapshot::default());

    let (mut session, _relay) = Session::allocated(server.addr, USER).await;
    let snapshot = server.snapshot();
    assert_eq!(snapshot.allocations(TransportProtocol::Udp), 1);
    assert_eq!(snapshot.allocations(TransportProtocol::Tcp), 0);
    assert_eq!(snapshot.allocations(TransportProtocol::Tls), 0);

    // A refresh keeps it; Refresh with LIFETIME 0 deletes it (RFC 8656 §7.3).
    assert_eq!(
        turn::class_of(session.refresh(300).await.message_type),
        turn::CLASS_SUCCESS
    );
    assert_eq!(server.snapshot().allocations(TransportProtocol::Udp), 1);
    assert_eq!(
        turn::class_of(session.refresh(0).await.message_type),
        turn::CLASS_SUCCESS
    );
    assert_eq!(server.snapshot().allocations(TransportProtocol::Udp), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_allocation_leaves_the_gauge() {
    let server = start(|config| config.default_lifetime = 60).await;
    let (_session, _relay) = Session::allocated(server.addr, USER).await;
    assert_eq!(server.snapshot().allocations(TransportProtocol::Udp), 1);

    server.datapath.advance_clock(61);
    server.turn.reap();
    let snapshot = server
        .until(|snapshot| snapshot.allocations(TransportProtocol::Udp) == 0)
        .await;
    assert_eq!(snapshot.allocations(TransportProtocol::Udp), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relayed_payload_bytes_are_counted_per_direction() {
    let server = start(|_| {}).await;
    let (mut session, relay) = Session::allocated(server.addr, USER).await;
    let (peer, peer_addr) = udp().await;
    assert_eq!(
        turn::class_of(session.permit(peer_addr).await.message_type),
        turn::CLASS_SUCCESS
    );

    session.send(peer_addr, &[0xAB; 160]).await;
    assert_eq!(received(&peer).await.len(), 160);
    peer.send_to(&[0xCD; 90], relay).await.expect("send");
    received(&session.client).await;

    let snapshot = server.snapshot();
    assert_eq!(snapshot.relayed_bytes(RelayDirection::ClientToPeer), 160);
    assert_eq!(snapshot.relayed_bytes(RelayDirection::PeerToClient), 90);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_packet_with_no_permission_relays_nothing_and_counts_no_bytes() {
    let server = start(|_| {}).await;
    let (session, _relay) = Session::allocated(server.addr, USER).await;
    let (peer, peer_addr) = udp().await;

    session.send(peer_addr, &[1; 50]).await;
    assert!(silent(&peer).await);
    let snapshot = server.snapshot();
    assert_eq!(snapshot.relayed_bytes(RelayDirection::ClientToPeer), 0);
    assert_eq!(snapshot.relayed_bytes(RelayDirection::PeerToClient), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_or_stale_credential_counts_as_unauthorized_or_stale_nonce() {
    let server = start(|_| {}).await;
    // The challenge of the first request is a 401 (RFC 5389 §10.2) and is counted.
    let mut session = Session::challenged(server.addr, USER).await;
    assert_eq!(server.snapshot().refused(RefusalReason::Unauthorized), 1);

    // A request signed with the wrong key is a 401 as well.
    session.key = key_for(OTHER_USER);
    let response = session.allocate().await;
    assert_eq!(turn::error_code(&response), Some(turn::ERROR_UNAUTHORIZED));
    assert_eq!(server.snapshot().refused(RefusalReason::Unauthorized), 2);

    // An old nonce is a 438.
    session.key = key_for(USER);
    server
        .datapath
        .advance_clock(TurnConfig::new(REALM, SECRET).nonce_lifetime + 1);
    let response = session.allocate().await;
    assert_eq!(turn::error_code(&response), Some(turn::ERROR_STALE_NONCE));
    let snapshot = server.snapshot();
    assert_eq!(snapshot.refused(RefusalReason::StaleNonce), 1);
    assert_eq!(snapshot.refused(RefusalReason::Quota), 0);
    assert_eq!(snapshot.allocations(TransportProtocol::Udp), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_per_credential_quota_counts_a_refusal_and_frees_with_the_allocation() {
    let server = start(|config| config.max_allocations_per_user = 1).await;
    let (mut first, _) = Session::allocated(server.addr, USER).await;
    let mut second = Session::challenged(server.addr, USER).await;
    let response = second.allocate().await;
    assert_eq!(
        turn::error_code(&response),
        Some(turn::ERROR_ALLOCATION_QUOTA_REACHED)
    );
    let snapshot = server.snapshot();
    assert_eq!(snapshot.refused(RefusalReason::Quota), 1);
    assert_eq!(snapshot.allocations(TransportProtocol::Udp), 1);

    first.refresh(0).await;
    assert_eq!(
        turn::class_of(second.allocate().await.message_type),
        turn::CLASS_SUCCESS
    );
    assert_eq!(server.snapshot().allocations(TransportProtocol::Udp), 1);
}

/// A host whose live media endpoints a test edits while the server runs.
#[derive(Default)]
struct FakeHost {
    live: Mutex<HashSet<SocketAddr>>,
}

impl OwnMediaEndpoints for FakeHost {
    fn hosts_media_on(&self, ip: IpAddr) -> bool {
        self.live
            .lock()
            .expect("lock")
            .iter()
            .any(|endpoint| endpoint.ip() == ip)
    }
    fn is_live_media_endpoint(&self, endpoint: SocketAddr) -> bool {
        self.live.lock().expect("lock").contains(&endpoint)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forbidden_peer_and_a_dropped_packet_count_as_peer_denied() {
    let host = Arc::new(FakeHost::default());
    let hosted = host.clone();
    let server = start(move |config| {
        config.denied_peers = PeerIpPolicy::default();
        config.own_media_endpoints = Some(hosted);
    })
    .await;
    let (mut session, relay) = Session::allocated(server.addr, USER).await;

    // 403 at CreatePermission: another private address, not hosted by the engine.
    let elsewhere: SocketAddr = "127.0.0.2:40000".parse().expect("addr");
    assert_eq!(
        turn::error_code(&session.permit(elsewhere).await),
        Some(turn::ERROR_FORBIDDEN)
    );
    assert_eq!(server.snapshot().refused(RefusalReason::PeerDenied), 1);

    // An own endpoint is accepted at CreatePermission; a packet to another port of its IP is
    // dropped per packet, in both directions, and each drop counts.
    let (engine_media, engine_addr) = udp().await;
    host.live.lock().expect("lock").insert(engine_addr);
    assert_eq!(
        turn::class_of(session.permit(engine_addr).await.message_type),
        turn::CLASS_SUCCESS
    );
    let (bystander, bystander_addr) = udp().await;
    session.send(bystander_addr, &[2; 20]).await;
    assert!(silent(&bystander).await);
    bystander.send_to(&[3; 20], relay).await.expect("send");
    assert!(silent(&session.client).await);
    let snapshot = server
        .until(|snapshot| snapshot.refused(RefusalReason::PeerDenied) == 3)
        .await;
    assert_eq!(snapshot.relayed_bytes(RelayDirection::ClientToPeer), 0);
    assert_eq!(snapshot.relayed_bytes(RelayDirection::PeerToClient), 0);

    // The live endpoint still relays, and counts bytes, not a refusal.
    session.send(engine_addr, &[4; 30]).await;
    assert_eq!(received(&engine_media).await.len(), 30);
    let snapshot = server.snapshot();
    assert_eq!(snapshot.relayed_bytes(RelayDirection::ClientToPeer), 30);
    assert_eq!(snapshot.refused(RefusalReason::PeerDenied), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopping_the_server_takes_every_allocation_off_the_gauge() {
    let server = start(|_| {}).await;
    let (_first, _) = Session::allocated(server.addr, USER).await;
    let (_second, _) = Session::allocated(server.addr, OTHER_USER).await;
    assert_eq!(server.snapshot().allocations(TransportProtocol::Udp), 2);

    server.turn.shutdown();
    let snapshot = server
        .until(|snapshot| snapshot.allocations(TransportProtocol::Udp) == 0)
        .await;
    assert_eq!(snapshot.allocations(TransportProtocol::Udp), 0);
}

/// Read one STUN message off a TCP stream (a 20-byte header, then its length).
async fn read_stun(stream: &mut tokio::net::TcpStream) -> stun::StunMessage {
    use tokio::io::AsyncReadExt;
    let mut header = [0u8; 20];
    timeout(SHORT, stream.read_exact(&mut header))
        .await
        .expect("header in time")
        .expect("read header");
    let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let mut message = header.to_vec();
    message.resize(20 + length, 0);
    timeout(SHORT, stream.read_exact(&mut message[20..]))
        .await
        .expect("body in time")
        .expect("read body");
    stun::parse(&message).expect("parse")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_packet_for_a_client_whose_connection_is_closed_is_not_counted_as_relayed() {
    use tokio::io::AsyncWriteExt;
    let mut config = TurnConfig::new(REALM, SECRET);
    config.denied_peers = PeerIpPolicy::permissive();
    let turn = Turn::spawn(
        Arc::new(UdpLoopbackDatapath::new()),
        config,
        Arc::new(FixedUnixClock::new(1_000)),
    )
    .expect("spawn turn");
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let serving = turn.clone();
    tokio::spawn(async move {
        let _ = serving.serve_tcp(listener).await;
    });

    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let unauthenticated = stun::MessageBuilder::new(
        turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_REQUEST),
        &[0u8; 12],
    )
    .attribute(
        turn::ATTR_REQUESTED_TRANSPORT,
        &turn::requested_transport_value(turn::TRANSPORT_UDP),
    )
    .finish(None, true);
    stream.write_all(&unauthenticated).await.expect("write");
    let challenge = read_stun(&mut stream).await;
    let nonce = turn::nonce(&challenge).expect("nonce").to_vec();
    let key = key_for(USER);
    let signed = |method: u16, transaction: u8, extra: &[(u16, Vec<u8>)]| {
        let mut builder = stun::MessageBuilder::new(
            turn::message_type(method, turn::CLASS_REQUEST),
            &[transaction; 12],
        )
        .attribute(turn::ATTR_USERNAME, USER.as_bytes())
        .attribute(turn::ATTR_REALM, REALM.as_bytes())
        .attribute(turn::ATTR_NONCE, &nonce);
        for (kind, value) in extra {
            builder = builder.attribute(*kind, value);
        }
        builder.finish(Some(&key[..]), true)
    };
    let (peer, peer_address) = udp().await;
    stream
        .write_all(&signed(
            turn::METHOD_ALLOCATE,
            1,
            &[(
                turn::ATTR_REQUESTED_TRANSPORT,
                turn::requested_transport_value(turn::TRANSPORT_UDP).to_vec(),
            )],
        ))
        .await
        .expect("write");
    let allocated = read_stun(&mut stream).await;
    let relay = turn::xor_relayed_address(&allocated).expect("relayed address");
    stream
        .write_all(&signed(
            turn::METHOD_CREATE_PERMISSION,
            2,
            &[(
                turn::ATTR_XOR_PEER_ADDRESS,
                turn::xor_address_value(peer_address, &[2u8; 12]).to_vec(),
            )],
        ))
        .await
        .expect("write");
    assert_eq!(
        turn::class_of(read_stun(&mut stream).await.message_type),
        turn::CLASS_SUCCESS
    );
    let snapshot = turn.metrics().snapshot();
    assert_eq!(snapshot.allocations(TransportProtocol::Tcp), 1);

    // The client goes away. Its allocation stays (RFC 8656 leaves it to its lifetime), but the
    // server can no longer reach the client, so a peer's packet is delivered to no one and must not
    // be counted as relayed.
    drop(stream);
    tokio::time::sleep(Duration::from_millis(300)).await;
    peer.send_to(&[9; 40], relay).await.expect("send");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let snapshot = turn.metrics().snapshot();
    assert_eq!(snapshot.relayed_bytes(RelayDirection::PeerToClient), 0);
    assert_eq!(snapshot.allocations(TransportProtocol::Tcp), 1);
}
