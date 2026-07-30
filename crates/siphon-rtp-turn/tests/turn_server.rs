//! End-to-end TURN server tests over the NIC-free UDP-loopback datapath.
//!
//! Each test stands up a real `Turn` server (its UDP listener + the allocation actor + the relay
//! dispatcher) on loopback and drives it as a TURN client would — building wire messages with the
//! `siphon-rtp-stun` codec, completing the 401 long-term-credential dance with a coturn REST
//! credential, then relaying media to/from real loopback "peer" sockets. These are the M-T1–M-T4
//! acceptance tests: the full Allocate → CreatePermission → ChannelBind → relay round-trip plus the
//! error paths (401/437/438/403, relay-without-permission, Refresh(0) teardown).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use std::sync::Mutex;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_stun::{self as stun, turn};
use siphon_rtp_turn::{ChannelRoute, FixedUnixClock, PeerIpPolicy, Turn, TurnConfig, TurnFastPath};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const REALM: &str = "siphon.test";
const SECRET: &[u8] = b"static-auth-secret";
const SHORT: Duration = Duration::from_secs(2);
const NEGATIVE: Duration = Duration::from_millis(200);

/// A running server plus the handles a test needs to drive it deterministically.
struct Server {
    datapath: UdpLoopbackDatapath,
    turn: Turn,
    clock: Arc<FixedUnixClock>,
    addr: SocketAddr,
}

async fn start(config: TurnConfig) -> Server {
    let datapath = UdpLoopbackDatapath::new();
    let clock = Arc::new(FixedUnixClock::new(1_000));
    let turn = Turn::spawn(Arc::new(datapath.clone()), config, clock.clone()).expect("spawn turn");
    let socket = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .expect("bind listener");
    let addr = socket.local_addr().expect("listener addr");
    let serving = turn.clone();
    tokio::spawn(async move {
        let _ = serving.serve_udp(socket).await;
    });
    Server {
        datapath,
        turn,
        clock,
        addr,
    }
}

fn permissive_config() -> TurnConfig {
    let mut config = TurnConfig::new(REALM, SECRET);
    // The loopback peers live on 127.0.0.0/8, which the secure default denies.
    config.denied_peers = PeerIpPolicy::permissive();
    config
}

async fn udp() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("bind");
    let addr = socket.local_addr().expect("addr");
    (socket, addr)
}

async fn exchange(socket: &UdpSocket, server: SocketAddr, request: &[u8]) -> stun::StunMessage {
    socket.send_to(request, server).await.expect("send request");
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(SHORT, socket.recv_from(&mut buffer))
        .await
        .expect("response did not time out")
        .expect("recv response");
    stun::parse(&buffer[..len]).expect("parse response")
}

async fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buffer = [0u8; 2048];
    let (len, from) = timeout(SHORT, socket.recv_from(&mut buffer))
        .await
        .expect("did not time out")
        .expect("recv");
    (buffer[..len].to_vec(), from)
}

/// The credential key for a coturn REST `username` (expiry far in the future relative to clock=1000).
fn rest_key(username: &str) -> [u8; 16] {
    let password = turn::base64_encode(&stun::hmac_sha1(SECRET, username.as_bytes()));
    turn::long_term_key(username, REALM, &password)
}

fn allocate_unauth(txid: &[u8; 12]) -> Vec<u8> {
    stun::MessageBuilder::new(
        turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_REQUEST),
        txid,
    )
    .attribute(
        turn::ATTR_REQUESTED_TRANSPORT,
        &turn::requested_transport_value(turn::TRANSPORT_UDP),
    )
    .finish(None, true)
}

fn authed(method: u16, txid: &[u8; 12], username: &str, nonce: &[u8], key: &[u8]) -> AuthedBuilder {
    AuthedBuilder {
        builder: stun::MessageBuilder::new(turn::message_type(method, turn::CLASS_REQUEST), txid)
            .attribute(turn::ATTR_USERNAME, username.as_bytes())
            .attribute(turn::ATTR_REALM, REALM.as_bytes())
            .attribute(turn::ATTR_NONCE, nonce),
        key: {
            let mut k = [0u8; 16];
            k.copy_from_slice(key);
            k
        },
    }
}

/// A small builder wrapper that appends USERNAME/REALM/NONCE up front and signs on `finish`. The
/// USERNAME/REALM/NONCE order before the request-specific attributes is irrelevant to STUN.
struct AuthedBuilder {
    builder: stun::MessageBuilder,
    key: [u8; 16],
}

impl AuthedBuilder {
    fn attribute(mut self, attr_type: u16, value: &[u8]) -> Self {
        self.builder = self.builder.attribute(attr_type, value);
        self
    }
    fn finish(self) -> Vec<u8> {
        self.builder.finish(Some(&self.key[..]), true)
    }
}

/// Complete the 401 challenge and return the issued NONCE.
async fn obtain_nonce(socket: &UdpSocket, server: SocketAddr) -> Vec<u8> {
    let challenge = exchange(socket, server, &allocate_unauth(&[0u8; 12])).await;
    assert_eq!(turn::class_of(challenge.message_type), turn::CLASS_ERROR);
    assert_eq!(turn::error_code(&challenge), Some(turn::ERROR_UNAUTHORIZED));
    assert_eq!(turn::realm(&challenge), Some(REALM));
    turn::nonce(&challenge)
        .expect("nonce in challenge")
        .to_vec()
}

const USER: &str = "2000000000:webrtc"; // expiry far beyond the test clock (1000)

/// Allocate, returning the relayed transport address and the nonce/key for further requests.
async fn allocate(socket: &UdpSocket, server: SocketAddr) -> (SocketAddr, Vec<u8>, [u8; 16]) {
    let nonce = obtain_nonce(socket, server).await;
    let key = rest_key(USER);
    let request = authed(turn::METHOD_ALLOCATE, &[1u8; 12], USER, &nonce, &key)
        .attribute(
            turn::ATTR_REQUESTED_TRANSPORT,
            &turn::requested_transport_value(turn::TRANSPORT_UDP),
        )
        .finish();
    let raw_request = request.clone();
    socket
        .send_to(&raw_request, server)
        .await
        .expect("send allocate");
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(SHORT, socket.recv_from(&mut buffer))
        .await
        .expect("no timeout")
        .expect("recv");
    let response = stun::parse(&buffer[..len]).expect("parse allocate response");
    assert_eq!(
        turn::class_of(response.message_type),
        turn::CLASS_SUCCESS,
        "allocate should succeed"
    );
    assert!(
        stun::verify_message_integrity(&buffer[..len], &key),
        "allocate success carries valid MESSAGE-INTEGRITY"
    );
    let relay = turn::xor_relayed_address(&response).expect("relayed address");
    (relay, nonce, key)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allocate_permission_channel_bind_relays_both_ways() {
    let server = start(permissive_config()).await;
    let (client, _client_addr) = udp().await;
    let (peer, peer_addr) = udp().await;

    let (relay, nonce, key) = allocate(&client, server.addr).await;

    // CreatePermission for the peer's IP.
    let response = exchange(
        &client,
        server.addr,
        &authed(
            turn::METHOD_CREATE_PERMISSION,
            &[2u8; 12],
            USER,
            &nonce,
            &key,
        )
        .attribute(
            turn::ATTR_XOR_PEER_ADDRESS,
            &turn::xor_address_value(peer_addr, &[2u8; 12]),
        )
        .finish(),
    )
    .await;
    assert_eq!(turn::class_of(response.message_type), turn::CLASS_SUCCESS);

    // ChannelBind 0x4001 → peer.
    let channel = 0x4001u16;
    let response = exchange(
        &client,
        server.addr,
        &authed(turn::METHOD_CHANNEL_BIND, &[3u8; 12], USER, &nonce, &key)
            .attribute(
                turn::ATTR_CHANNEL_NUMBER,
                &turn::channel_number_value(channel),
            )
            .attribute(
                turn::ATTR_XOR_PEER_ADDRESS,
                &turn::xor_address_value(peer_addr, &[3u8; 12]),
            )
            .finish(),
    )
    .await;
    assert_eq!(turn::class_of(response.message_type), turn::CLASS_SUCCESS);

    // client → peer over ChannelData: the peer receives the payload from the relay address.
    let to_peer = b"audio-from-client";
    client
        .send_to(
            &turn::encode_channel_data(channel, to_peer, false),
            server.addr,
        )
        .await
        .expect("send channel data");
    let (data, from) = recv(&peer).await;
    assert_eq!(data, to_peer);
    assert_eq!(from, relay, "peer sees the relay address as the source");

    // peer → client: delivered as ChannelData (a channel is bound), from the server's address.
    let to_client = b"audio-from-peer";
    peer.send_to(to_client, relay).await.expect("send to relay");
    let (data, from) = recv(&client).await;
    assert_eq!(from, server.addr);
    let channel_data = turn::parse_channel_data(&data).expect("channel data to client");
    assert_eq!(channel_data.channel, channel);
    assert_eq!(channel_data.data, to_client);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_indication_and_data_indication_relay_with_only_a_permission() {
    let server = start(permissive_config()).await;
    let (client, _) = udp().await;
    let (peer, peer_addr) = udp().await;
    let (relay, nonce, key) = allocate(&client, server.addr).await;

    // Only a permission (no channel).
    let response = exchange(
        &client,
        server.addr,
        &authed(
            turn::METHOD_CREATE_PERMISSION,
            &[2u8; 12],
            USER,
            &nonce,
            &key,
        )
        .attribute(
            turn::ATTR_XOR_PEER_ADDRESS,
            &turn::xor_address_value(peer_addr, &[2u8; 12]),
        )
        .finish(),
    )
    .await;
    assert_eq!(turn::class_of(response.message_type), turn::CLASS_SUCCESS);

    // client → peer via a Send indication.
    let txid = [7u8; 12];
    let send = stun::MessageBuilder::new(
        turn::message_type(turn::METHOD_SEND, turn::CLASS_INDICATION),
        &txid,
    )
    .attribute(
        turn::ATTR_XOR_PEER_ADDRESS,
        &turn::xor_address_value(peer_addr, &txid),
    )
    .attribute(turn::ATTR_DATA, b"hello-peer")
    .finish(None, false);
    client
        .send_to(&send, server.addr)
        .await
        .expect("send indication");
    let (data, from) = recv(&peer).await;
    assert_eq!(data, b"hello-peer");
    assert_eq!(from, relay);

    // peer → client: delivered as a Data indication (no channel bound).
    peer.send_to(b"hello-client", relay)
        .await
        .expect("send to relay");
    let (data, _) = recv(&client).await;
    let indication = stun::parse(&data).expect("data indication");
    assert_eq!(turn::method_of(indication.message_type), turn::METHOD_DATA);
    assert_eq!(
        turn::class_of(indication.message_type),
        turn::CLASS_INDICATION
    );
    assert_eq!(turn::xor_peer_address(&indication), Some(peer_addr));
    assert_eq!(turn::data(&indication), Some(&b"hello-client"[..]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_without_permission_is_dropped() {
    let server = start(permissive_config()).await;
    let (client, _) = udp().await;
    let (peer, _peer_addr) = udp().await;
    let (relay, _nonce, _key) = allocate(&client, server.addr).await;

    // No permission installed: the peer's datagram on the relay must not reach the client.
    peer.send_to(b"unsolicited", relay)
        .await
        .expect("send to relay");
    let mut buffer = [0u8; 2048];
    assert!(
        timeout(NEGATIVE, client.recv_from(&mut buffer))
            .await
            .is_err(),
        "a peer with no permission must not be relayed to the client (RFC 5766 §8)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_a_plain_stun_binding_request() {
    // RFC 8656 §12: a TURN server MUST support Binding requests. That conformance is also what lets
    // the built-in server be the STUN server our own ICE gathering asks for a server-reflexive
    // address, instead of requiring a separate STUN service next to it.
    let server = start(permissive_config()).await;
    let (client, client_addr) = udp().await;

    // A bare Binding request: no USERNAME, no MESSAGE-INTEGRITY. RFC 8489 §9.1 makes authentication
    // optional for Binding, and a client discovering its reflexive address has no credentials yet.
    let request = stun::MessageBuilder::new(stun::BINDING_REQUEST, &[42u8; 12]).finish(None, true);
    let response = exchange(&client, server.addr, &request).await;

    assert_eq!(response.message_type, stun::BINDING_SUCCESS);
    assert_eq!(response.transaction_id, [42u8; 12]);
    assert_eq!(
        response.xor_mapped_address(),
        Some(client_addr),
        "the response reports the source the server saw — the reflexive address"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_binding_request_never_grants_an_allocation() {
    // Answering Binding without credentials must not weaken TURN itself: an allocation still
    // requires the long-term credential dance (RFC 8656 §7.2).
    let server = start(permissive_config()).await;
    let (client, _) = udp().await;

    let request = stun::MessageBuilder::new(stun::BINDING_REQUEST, &[1u8; 12]).finish(None, true);
    let binding = exchange(&client, server.addr, &request).await;
    assert_eq!(binding.message_type, stun::BINDING_SUCCESS);

    // The very same 5-tuple still gets 401-challenged for an Allocate.
    let challenge = exchange(&client, server.addr, &allocate_unauth(&[2u8; 12])).await;
    assert_eq!(turn::class_of(challenge.message_type), turn::CLASS_ERROR);
    assert_eq!(turn::error_code(&challenge), Some(turn::ERROR_UNAUTHORIZED));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_request_is_challenged() {
    let server = start(permissive_config()).await;
    let (client, _) = udp().await;
    let nonce = obtain_nonce(&client, server.addr).await;
    assert!(!nonce.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_allocate_on_a_live_5_tuple_is_mismatch() {
    let server = start(permissive_config()).await;
    let (client, _) = udp().await;
    let (_relay, nonce, key) = allocate(&client, server.addr).await;

    // A *different* Allocate (new transaction id) on the same 5-tuple → 437 Allocation Mismatch.
    let response = exchange(
        &client,
        server.addr,
        &authed(turn::METHOD_ALLOCATE, &[9u8; 12], USER, &nonce, &key)
            .attribute(
                turn::ATTR_REQUESTED_TRANSPORT,
                &turn::requested_transport_value(turn::TRANSPORT_UDP),
            )
            .finish(),
    )
    .await;
    assert_eq!(turn::class_of(response.message_type), turn::CLASS_ERROR);
    assert_eq!(
        turn::error_code(&response),
        Some(turn::ERROR_ALLOCATION_MISMATCH)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retransmitted_allocate_replays_the_same_response() {
    let server = start(permissive_config()).await;
    let (client, _) = udp().await;
    let nonce = obtain_nonce(&client, server.addr).await;
    let key = rest_key(USER);
    let request = authed(turn::METHOD_ALLOCATE, &[1u8; 12], USER, &nonce, &key)
        .attribute(
            turn::ATTR_REQUESTED_TRANSPORT,
            &turn::requested_transport_value(turn::TRANSPORT_UDP),
        )
        .finish();

    let first = exchange(&client, server.addr, &request).await;
    assert_eq!(turn::class_of(first.message_type), turn::CLASS_SUCCESS);
    // Same transaction id again → the cached success response, not a 437 (RFC 5766 §6.2).
    let second = exchange(&client, server.addr, &request).await;
    assert_eq!(turn::class_of(second.message_type), turn::CLASS_SUCCESS);
    assert_eq!(
        turn::xor_relayed_address(&first),
        turn::xor_relayed_address(&second),
        "a retransmitted Allocate returns the same relay address"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_nonce_is_rejected() {
    let server = start(permissive_config()).await;
    let (client, _) = udp().await;
    let (_relay, nonce, key) = allocate(&client, server.addr).await;

    // Advance the logical clock past the nonce lifetime; the old nonce is now stale.
    server.datapath.advance_clock(server_nonce_lifetime() + 1);
    let response = exchange(
        &client,
        server.addr,
        &authed(turn::METHOD_REFRESH, &[5u8; 12], USER, &nonce, &key)
            .attribute(turn::ATTR_LIFETIME, &turn::lifetime_value(600))
            .finish(),
    )
    .await;
    assert_eq!(turn::class_of(response.message_type), turn::CLASS_ERROR);
    assert_eq!(turn::error_code(&response), Some(turn::ERROR_STALE_NONCE));
    // The challenge carries a fresh nonce the client can retry with.
    assert!(turn::nonce(&response).is_some());
}

fn server_nonce_lifetime() -> u64 {
    TurnConfig::new(REALM, SECRET).nonce_lifetime
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denied_peer_is_forbidden() {
    // Default (secure) denylist rejects loopback peers with 403.
    let server = start(TurnConfig::new(REALM, SECRET)).await;
    let (client, _) = udp().await;
    let (_peer, peer_addr) = udp().await; // a 127.0.0.x peer — denied by default
    let (_relay, nonce, key) = allocate(&client, server.addr).await;

    let response = exchange(
        &client,
        server.addr,
        &authed(
            turn::METHOD_CREATE_PERMISSION,
            &[2u8; 12],
            USER,
            &nonce,
            &key,
        )
        .attribute(
            turn::ATTR_XOR_PEER_ADDRESS,
            &turn::xor_address_value(peer_addr, &[2u8; 12]),
        )
        .finish(),
    )
    .await;
    assert_eq!(turn::class_of(response.message_type), turn::CLASS_ERROR);
    assert_eq!(turn::error_code(&response), Some(turn::ERROR_FORBIDDEN));
}

/// A recording [`TurnFastPath`] so the test can observe what the actor would program in the kernel.
#[derive(Clone, Default)]
struct RecordingFastPath {
    installed: Arc<Mutex<Vec<ChannelRoute>>>,
    removed: Arc<Mutex<Vec<ChannelRoute>>>,
}

impl TurnFastPath for RecordingFastPath {
    fn install_channel(&self, route: ChannelRoute) {
        self.installed.lock().expect("lock").push(route);
    }
    fn remove_channel(&self, route: ChannelRoute) {
        self.removed.lock().expect("lock").push(route);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn channel_bind_programs_the_fast_path_and_delete_withdraws_it() {
    let datapath = UdpLoopbackDatapath::new();
    let recorder = RecordingFastPath::default();
    let installed = recorder.installed.clone();
    let removed = recorder.removed.clone();
    let turn = Turn::spawn_with_fast_path(
        Arc::new(datapath),
        permissive_config(),
        Arc::new(FixedUnixClock::new(1_000)),
        Box::new(recorder),
    )
    .expect("spawn");
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("listener");
    let server = socket.local_addr().expect("addr");
    let serving = turn.clone();
    tokio::spawn(async move {
        let _ = serving.serve_udp(socket).await;
    });

    let (client, client_addr) = udp().await;
    let (_peer, peer_addr) = udp().await;
    let (relay, nonce, key) = allocate(&client, server).await;

    // ChannelBind → the actor offers the route to the fast path (before answering).
    let channel = 0x4007u16;
    let response = exchange(
        &client,
        server,
        &authed(turn::METHOD_CHANNEL_BIND, &[3u8; 12], USER, &nonce, &key)
            .attribute(
                turn::ATTR_CHANNEL_NUMBER,
                &turn::channel_number_value(channel),
            )
            .attribute(
                turn::ATTR_XOR_PEER_ADDRESS,
                &turn::xor_address_value(peer_addr, &[3u8; 12]),
            )
            .finish(),
    )
    .await;
    assert_eq!(turn::class_of(response.message_type), turn::CLASS_SUCCESS);

    let route = installed.lock().expect("lock")[0];
    assert_eq!(route.channel, channel);
    assert_eq!(route.client, client_addr);
    assert_eq!(route.listener, server);
    assert_eq!(route.peer, peer_addr);
    assert_eq!(route.relay, relay, "fast-path relay == XOR-RELAYED-ADDRESS");

    // Refresh(0) tears the allocation down → the route is withdrawn.
    exchange(
        &client,
        server,
        &authed(turn::METHOD_REFRESH, &[6u8; 12], USER, &nonce, &key)
            .attribute(turn::ATTR_LIFETIME, &turn::lifetime_value(0))
            .finish(),
    )
    .await;
    let withdrawn = removed.lock().expect("lock");
    assert_eq!(withdrawn.len(), 1);
    assert_eq!(withdrawn[0].channel, channel);
    assert_eq!(withdrawn[0].peer, peer_addr);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_zero_deletes_allocation_and_frees_the_relay() {
    let server = start(permissive_config()).await;
    let (client, _) = udp().await;
    let (peer, peer_addr) = udp().await;
    let (relay, nonce, key) = allocate(&client, server.addr).await;

    // Permit the peer, prove the relay works, then delete with Refresh(0).
    exchange(
        &client,
        server.addr,
        &authed(
            turn::METHOD_CREATE_PERMISSION,
            &[2u8; 12],
            USER,
            &nonce,
            &key,
        )
        .attribute(
            turn::ATTR_XOR_PEER_ADDRESS,
            &turn::xor_address_value(peer_addr, &[2u8; 12]),
        )
        .finish(),
    )
    .await;

    let response = exchange(
        &client,
        server.addr,
        &authed(turn::METHOD_REFRESH, &[6u8; 12], USER, &nonce, &key)
            .attribute(turn::ATTR_LIFETIME, &turn::lifetime_value(0))
            .finish(),
    )
    .await;
    assert_eq!(turn::class_of(response.message_type), turn::CLASS_SUCCESS);
    assert_eq!(turn::lifetime(&response), Some(0));

    // The allocation is gone: a peer datagram on the (freed) relay reaches no one.
    peer.send_to(b"after-delete", relay)
        .await
        .expect("send to relay");
    let mut buffer = [0u8; 2048];
    assert!(
        timeout(NEGATIVE, client.recv_from(&mut buffer))
            .await
            .is_err(),
        "a deleted allocation relays nothing"
    );
    // Keep the handle alive until the end so the server task isn't dropped early.
    let _ = &server.turn;
    let _ = &server.clock;
}
