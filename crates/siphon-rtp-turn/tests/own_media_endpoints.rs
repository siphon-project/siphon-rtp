//! The own-media-endpoint exemption of the peer denylist (RFC 8656 §21, docs/security-and-nat.md §11
//! R3): a peer IP the default policy denies is accepted at CreatePermission / ChannelBind only when
//! the host hands over its own live media endpoints, and then only the live `(IP, port)` pairs get
//! packets, in both directions, checked per packet.

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
    ChannelRoute, FixedUnixClock, OwnMediaEndpoints, PeerIpPolicy, Turn, TurnConfig, TurnFastPath,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const REALM: &str = "siphon.test";
const SECRET: &[u8] = b"static-auth-secret";
const USER: &str = "2000000000:webrtc";
const SHORT: Duration = Duration::from_secs(2);
const NEGATIVE: Duration = Duration::from_millis(250);

/// A host whose live media endpoints a test edits while the server runs.
#[derive(Default)]
struct FakeHost {
    live: Mutex<HashSet<SocketAddr>>,
}

impl FakeHost {
    fn set_live(&self, endpoint: SocketAddr, live: bool) {
        let mut set = self.live.lock().expect("lock");
        if live {
            set.insert(endpoint);
        } else {
            set.remove(&endpoint);
        }
    }
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

#[derive(Clone, Default)]
struct RecordingFastPath {
    installed: Arc<Mutex<Vec<ChannelRoute>>>,
}

impl TurnFastPath for RecordingFastPath {
    fn install_channel(&self, route: ChannelRoute) {
        self.installed.lock().expect("lock").push(route);
    }
    fn remove_channel(&self, _route: ChannelRoute) {}
}

struct Server {
    addr: SocketAddr,
    host: Arc<FakeHost>,
    fast_path: RecordingFastPath,
}

/// A server with the secure default denylist plus `host` as its own-endpoint view.
async fn start(mutate: impl FnOnce(&mut TurnConfig)) -> Server {
    let host = Arc::new(FakeHost::default());
    let mut config = TurnConfig::new(REALM, SECRET);
    config.own_media_endpoints = Some(host.clone());
    mutate(&mut config);
    let fast_path = RecordingFastPath::default();
    let turn = Turn::spawn_with_fast_path(
        Arc::new(UdpLoopbackDatapath::new()),
        config,
        Arc::new(FixedUnixClock::new(1_000)),
        Box::new(fast_path.clone()),
    )
    .expect("spawn turn");
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("listener");
    let addr = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = turn.serve_udp(socket).await;
    });
    Server {
        addr,
        host,
        fast_path,
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

async fn silent(socket: &UdpSocket) -> bool {
    let mut buffer = [0u8; 2048];
    timeout(NEGATIVE, socket.recv_from(&mut buffer))
        .await
        .is_err()
}

async fn received(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buffer = [0u8; 2048];
    let (len, from) = timeout(SHORT, socket.recv_from(&mut buffer))
        .await
        .expect("datagram")
        .expect("recv");
    (buffer[..len].to_vec(), from)
}

fn rest_key() -> [u8; 16] {
    let password = turn::base64_encode(&stun::hmac_sha1(SECRET, USER.as_bytes()));
    turn::long_term_key(USER, REALM, &password)
}

struct Session {
    client: UdpSocket,
    server: SocketAddr,
    relay: SocketAddr,
    nonce: Vec<u8>,
    key: [u8; 16],
    next_txid: u8,
}

impl Session {
    async fn open(server: SocketAddr) -> Self {
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
        let nonce = turn::nonce(&challenge).expect("nonce").to_vec();
        let key = rest_key();
        let mut session = Self {
            client,
            server,
            relay: server,
            nonce,
            key,
            next_txid: 1,
        };
        let response = session
            .request(
                turn::METHOD_ALLOCATE,
                &[(
                    turn::ATTR_REQUESTED_TRANSPORT,
                    turn::requested_transport_value(turn::TRANSPORT_UDP).to_vec(),
                )],
            )
            .await;
        assert_eq!(turn::class_of(response.message_type), turn::CLASS_SUCCESS);
        session.relay = turn::xor_relayed_address(&response).expect("relayed address");
        session
    }

    async fn request(&mut self, method: u16, attributes: &[(u16, Vec<u8>)]) -> stun::StunMessage {
        let txid = [self.next_txid; 12];
        self.next_txid += 1;
        let mut builder =
            stun::MessageBuilder::new(turn::message_type(method, turn::CLASS_REQUEST), &txid)
                .attribute(turn::ATTR_USERNAME, USER.as_bytes())
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

    async fn permit(&mut self, peer: SocketAddr) -> stun::StunMessage {
        let txid = [self.next_txid; 12];
        self.request(
            turn::METHOD_CREATE_PERMISSION,
            &[(
                turn::ATTR_XOR_PEER_ADDRESS,
                turn::xor_address_value(peer, &txid).to_vec(),
            )],
        )
        .await
    }

    async fn bind(&mut self, channel: u16, peer: SocketAddr) -> stun::StunMessage {
        let txid = [self.next_txid; 12];
        self.request(
            turn::METHOD_CHANNEL_BIND,
            &[
                (
                    turn::ATTR_CHANNEL_NUMBER,
                    turn::channel_number_value(channel).to_vec(),
                ),
                (
                    turn::ATTR_XOR_PEER_ADDRESS,
                    turn::xor_address_value(peer, &txid).to_vec(),
                ),
            ],
        )
        .await
    }

    async fn send_indication(&self, peer: SocketAddr, payload: &[u8]) {
        let txid = [0x77u8; 12];
        let message = stun::MessageBuilder::new(
            turn::message_type(turn::METHOD_SEND, turn::CLASS_INDICATION),
            &txid,
        )
        .attribute(
            turn::ATTR_XOR_PEER_ADDRESS,
            &turn::xor_address_value(peer, &txid),
        )
        .attribute(turn::ATTR_DATA, payload)
        .finish(None, false);
        self.client
            .send_to(&message, self.server)
            .await
            .expect("send indication");
    }
}

fn is_success(response: &stun::StunMessage) -> bool {
    turn::class_of(response.message_type) == turn::CLASS_SUCCESS
}

fn is_forbidden(response: &stun::StunMessage) -> bool {
    turn::class_of(response.message_type) == turn::CLASS_ERROR
        && turn::error_code(response) == Some(turn::ERROR_FORBIDDEN)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_own_endpoint_is_reachable_both_ways_over_a_send_indication() {
    let server = start(|_| {}).await;
    let (engine_media, engine_addr) = udp().await;
    server.host.set_live(engine_addr, true);
    let mut session = Session::open(server.addr).await;

    assert!(is_success(&session.permit(engine_addr).await));
    session.send_indication(engine_addr, b"rtp-to-engine").await;
    let (data, from) = received(&engine_media).await;
    assert_eq!(data, b"rtp-to-engine");
    assert_eq!(from, session.relay);

    engine_media
        .send_to(b"rtp-from-engine", session.relay)
        .await
        .expect("send to relay");
    let (data, _) = received(&session.client).await;
    let indication = stun::parse(&data).expect("data indication");
    assert_eq!(turn::xor_peer_address(&indication), Some(engine_addr));
    assert_eq!(turn::data(&indication), Some(&b"rtp-from-engine"[..]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_own_endpoint_is_reachable_over_a_bound_channel_without_the_kernel_fast_path() {
    let server = start(|_| {}).await;
    let (engine_media, engine_addr) = udp().await;
    server.host.set_live(engine_addr, true);
    let mut session = Session::open(server.addr).await;

    assert!(is_success(&session.bind(0x4001, engine_addr).await));
    assert!(
        server.fast_path.installed.lock().expect("lock").is_empty(),
        "the kernel rewrite cannot check liveness per packet, so an exempt peer stays in userspace"
    );
    session
        .client
        .send_to(
            &turn::encode_channel_data(0x4001, b"channel-rtp", false),
            server.addr,
        )
        .await
        .expect("send channel data");
    let (data, _) = received(&engine_media).await;
    assert_eq!(data, b"channel-rtp");

    engine_media
        .send_to(b"back", session.relay)
        .await
        .expect("send to relay");
    let (data, _) = received(&session.client).await;
    let channel_data = turn::parse_channel_data(&data).expect("channel data");
    assert_eq!(channel_data.channel, 0x4001);
    assert_eq!(channel_data.data, b"back");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_that_is_not_a_live_engine_endpoint_gets_nothing_though_its_ip_is_permitted() {
    let server = start(|_| {}).await;
    let (_engine_media, engine_addr) = udp().await;
    let (bystander, bystander_addr) = udp().await; // same IP, not an engine endpoint
    server.host.set_live(engine_addr, true);
    let mut session = Session::open(server.addr).await;

    // Permissions are IP-only (RFC 8656 §9), so the IP is accepted.
    assert!(is_success(&session.permit(engine_addr).await));
    session.send_indication(bystander_addr, b"probe").await;
    assert!(silent(&bystander).await, "client to peer on a dead port");

    // The same bystander cannot reach the client through the relay either.
    bystander
        .send_to(b"probe-back", session.relay)
        .await
        .expect("send");
    assert!(
        silent(&session.client).await,
        "peer to client on a dead port"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_endpoint_that_stops_being_live_is_dropped_at_once_in_both_directions() {
    let server = start(|_| {}).await;
    let (engine_media, engine_addr) = udp().await;
    server.host.set_live(engine_addr, true);
    let mut session = Session::open(server.addr).await;
    assert!(is_success(&session.permit(engine_addr).await));
    assert!(is_success(&session.bind(0x4002, engine_addr).await));

    // The call is torn down: the permission and the channel are still there, the endpoint is not.
    server.host.set_live(engine_addr, false);
    session.send_indication(engine_addr, b"late").await;
    assert!(
        silent(&engine_media).await,
        "send indication after teardown"
    );
    session
        .client
        .send_to(
            &turn::encode_channel_data(0x4002, b"late", false),
            server.addr,
        )
        .await
        .expect("send");
    assert!(silent(&engine_media).await, "channel data after teardown");
    engine_media
        .send_to(b"late", session.relay)
        .await
        .expect("send");
    assert!(
        silent(&session.client).await,
        "peer to client after teardown"
    );

    // A new call on the same port is reachable again, with no fresh permission.
    server.host.set_live(engine_addr, true);
    session.send_indication(engine_addr, b"again").await;
    let (data, _) = received(&engine_media).await;
    assert_eq!(data, b"again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_private_ip_is_still_forbidden() {
    let server = start(|_| {}).await;
    let (_engine_media, engine_addr) = udp().await;
    server.host.set_live(engine_addr, true);
    let mut session = Session::open(server.addr).await;
    let other: SocketAddr = "127.0.0.2:40000".parse().expect("addr");

    assert!(is_forbidden(&session.permit(other).await));
    assert!(is_forbidden(&session.bind(0x4003, other).await));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn link_local_multicast_and_explicitly_denied_stay_forbidden_even_for_a_hosted_ip() {
    /// A host that claims every address, to prove the denylist wins.
    struct Everything;
    impl OwnMediaEndpoints for Everything {
        fn hosts_media_on(&self, _ip: IpAddr) -> bool {
            true
        }
        fn is_live_media_endpoint(&self, _endpoint: SocketAddr) -> bool {
            true
        }
    }
    let server = start(|config| {
        config.own_media_endpoints = Some(Arc::new(Everything));
        config
            .denied_peers
            .denied
            .push("127.0.0.9".parse().expect("ip"));
    })
    .await;
    let mut session = Session::open(server.addr).await;
    for peer in [
        "169.254.7.7:5000",
        "[fe80::1]:5000",
        "224.0.0.1:5000",
        "127.0.0.9:5000",
        "0.0.0.0:5000",
    ] {
        let peer: SocketAddr = peer.parse().expect("addr");
        assert!(is_forbidden(&session.permit(peer).await), "{peer}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_host_the_default_denylist_is_unchanged() {
    let server = start(|config| config.own_media_endpoints = None).await;
    let (_engine_media, engine_addr) = udp().await;
    let mut session = Session::open(server.addr).await;
    assert!(is_forbidden(&session.permit(engine_addr).await));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_the_default_policy_permits_never_asks_the_host() {
    /// A host that must not be consulted for a peer the policy already allows.
    struct Forbidden;
    impl OwnMediaEndpoints for Forbidden {
        fn hosts_media_on(&self, _ip: IpAddr) -> bool {
            panic!("hosts_media_on consulted for a permitted peer")
        }
        fn is_live_media_endpoint(&self, _endpoint: SocketAddr) -> bool {
            panic!("is_live_media_endpoint consulted for a permitted peer")
        }
    }
    let server = start(|config| {
        config.own_media_endpoints = Some(Arc::new(Forbidden));
        config.denied_peers = PeerIpPolicy::permissive();
    })
    .await;
    let (peer, peer_addr) = udp().await;
    let mut session = Session::open(server.addr).await;
    assert!(is_success(&session.permit(peer_addr).await));
    session.send_indication(peer_addr, b"plain").await;
    let (data, _) = received(&peer).await;
    assert_eq!(data, b"plain");
}

fn mapped(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        other => other,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ipv4_mapped_peer_gets_no_looser_a_rule_than_the_plain_form() {
    let server = start(|config| {
        config
            .denied_peers
            .denied
            .push("127.0.0.9".parse().expect("ip"));
    })
    .await;
    let (engine_media, engine_addr) = udp().await;
    let (bystander, bystander_addr) = udp().await;
    server.host.set_live(engine_addr, true);
    let mut session = Session::open(server.addr).await;

    // Mapped loopback not hosted, mapped private, mapped explicitly denied: all 403, both verbs.
    for refused in [
        "[::ffff:127.0.0.2]:5000",
        "[::ffff:10.1.2.3]:5000",
        "[::ffff:127.0.0.9]:5000",
    ] {
        let peer: SocketAddr = refused.parse().expect("addr");
        assert!(is_forbidden(&session.permit(peer).await), "permit {peer}");
        assert!(
            is_forbidden(&session.bind(0x4010, peer).await),
            "bind {peer}"
        );
    }

    // A mapped own endpoint is accepted, is judged per port exactly like the plain form, stays out of
    // the kernel fast path, and is relayed to the plain IPv4 address.
    let mapped_engine = mapped(engine_addr);
    assert!(is_success(&session.permit(mapped_engine).await));
    session.send_indication(mapped_engine, b"via-mapped").await;
    let (data, _) = received(&engine_media).await;
    assert_eq!(data, b"via-mapped");
    session
        .send_indication(mapped(bystander_addr), b"dead-port")
        .await;
    assert!(
        silent(&bystander).await,
        "a mapped dead port is dropped like a plain one"
    );
    assert!(is_success(&session.bind(0x4011, mapped_engine).await));
    assert!(server.fast_path.installed.lock().expect("lock").is_empty());
    server.host.set_live(engine_addr, false);
    session.send_indication(mapped_engine, b"late").await;
    assert!(
        silent(&engine_media).await,
        "a mapped endpoint that is no longer live"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mapped_explicit_denial_wins_even_for_a_hosted_ip() {
    /// A host that claims every address.
    struct Everything;
    impl OwnMediaEndpoints for Everything {
        fn hosts_media_on(&self, _ip: IpAddr) -> bool {
            true
        }
        fn is_live_media_endpoint(&self, _endpoint: SocketAddr) -> bool {
            true
        }
    }
    let server = start(|config| {
        config.own_media_endpoints = Some(Arc::new(Everything));
        config
            .denied_peers
            .denied
            .push("127.0.0.9".parse().expect("ip"));
    })
    .await;
    let mut session = Session::open(server.addr).await;
    let peer: SocketAddr = "[::ffff:127.0.0.9]:5000".parse().expect("addr");
    assert!(is_forbidden(&session.permit(peer).await));
}
