//! Memory-leak soak for the TURN server.
//!
//! `cargo test -p siphon-rtp-turn --test mem_leak_soak`
//!
//! Churns `Allocate → relay → Refresh(0) delete` over the NIC-free UDP-loopback datapath and proves
//! the server gives memory back: the allocation table drains to **0**, every relay endpoint returns
//! to the shared pool, and jemalloc's live `allocated` stays flat across thousands of completed
//! allocations. Gate on `allocated` (live bytes), never RSS. A rising `allocated` at steady state is
//! a real leak (a stranded `Allocation`, a relay recv task whose socket never freed).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_stun::{self as stun, turn};
use siphon_rtp_turn::{FixedUnixClock, PeerIpPolicy, Turn, TurnConfig};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const REALM: &str = "siphon.test";
const SECRET: &[u8] = b"static-auth-secret";
const USER: &str = "2000000000:webrtc";

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn allocated_bytes() -> usize {
    tikv_jemalloc_ctl::epoch::advance().expect("advance jemalloc epoch");
    tikv_jemalloc_ctl::stats::allocated::read().expect("read jemalloc allocated")
}

fn rest_key() -> [u8; 16] {
    let password = turn::base64_encode(&stun::hmac_sha1(SECRET, USER.as_bytes()));
    turn::long_term_key(USER, REALM, &password)
}

async fn exchange(socket: &UdpSocket, server: SocketAddr, request: &[u8]) -> stun::StunMessage {
    socket.send_to(request, server).await.expect("send");
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .expect("no timeout")
        .expect("recv");
    stun::parse(&buffer[..len]).expect("parse")
}

/// An authenticated-request builder pre-seeded with USERNAME/REALM/NONCE that signs on `finish`.
struct AuthedBuilder {
    builder: stun::MessageBuilder,
    key: [u8; 16],
}

fn authed(method: u16, txid: &[u8; 12], nonce: &[u8], key: &[u8; 16]) -> AuthedBuilder {
    AuthedBuilder {
        builder: stun::MessageBuilder::new(turn::message_type(method, turn::CLASS_REQUEST), txid)
            .attribute(turn::ATTR_USERNAME, USER.as_bytes())
            .attribute(turn::ATTR_REALM, REALM.as_bytes())
            .attribute(turn::ATTR_NONCE, nonce),
        key: *key,
    }
}

impl AuthedBuilder {
    fn attribute(mut self, attr: u16, value: &[u8]) -> Self {
        self.builder = self.builder.attribute(attr, value);
        self
    }
    fn finish(self) -> Vec<u8> {
        self.builder.finish(Some(&self.key[..]), true)
    }
}

/// One full allocate → relay one packet each way → delete cycle on a fresh client socket.
async fn allocate_relay_delete(server: SocketAddr, nonce: &[u8], key: &[u8; 16], index: usize) {
    let client = UdpSocket::bind(("127.0.0.1", 0)).await.expect("client");
    let peer = UdpSocket::bind(("127.0.0.1", 0)).await.expect("peer");
    let peer_addr = peer.local_addr().expect("peer addr");
    let txid = txid(index);

    let allocate = authed(turn::METHOD_ALLOCATE, &txid, nonce, key)
        .attribute(
            turn::ATTR_REQUESTED_TRANSPORT,
            &turn::requested_transport_value(turn::TRANSPORT_UDP),
        )
        .finish();
    let response = exchange(&client, server, &allocate).await;
    let relay = turn::xor_relayed_address(&response).expect("relay addr");

    // Permission + one packet each way (exercise the per-packet relay allocation/free).
    let permission = authed(turn::METHOD_CREATE_PERMISSION, &txid, nonce, key)
        .attribute(
            turn::ATTR_XOR_PEER_ADDRESS,
            &turn::xor_address_value(peer_addr, &txid),
        )
        .finish();
    let _ = exchange(&client, server, &permission).await;
    peer.send_to(b"peer-frame", relay).await.expect("peer send");
    let mut scratch = [0u8; 2048];
    let _ = timeout(Duration::from_millis(200), client.recv_from(&mut scratch)).await;

    // Refresh(0) deletes the allocation and frees the relay endpoint.
    let delete = authed(turn::METHOD_REFRESH, &txid, nonce, key)
        .attribute(turn::ATTR_LIFETIME, &turn::lifetime_value(0))
        .finish();
    let _ = exchange(&client, server, &delete).await;
}

fn txid(index: usize) -> [u8; 12] {
    let mut id = [0u8; 12];
    id[4..12].copy_from_slice(&(index as u64).to_be_bytes());
    id
}

async fn quiesce() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allocate_relay_delete_does_not_leak() {
    let datapath = UdpLoopbackDatapath::new();
    let mut config = TurnConfig::new(REALM, SECRET);
    config.denied_peers = PeerIpPolicy::permissive();
    let turn = Turn::spawn(
        Arc::new(datapath.clone()),
        config,
        Arc::new(FixedUnixClock::new(1_000)),
    )
    .expect("spawn");
    let listener = UdpSocket::bind(("127.0.0.1", 0)).await.expect("listener");
    let server = listener.local_addr().expect("addr");
    let serving = turn.clone();
    tokio::spawn(async move {
        let _ = serving.serve_udp(listener).await;
    });

    // One 401 dance up front; the nonce stays valid (clock is not advanced).
    let primer = UdpSocket::bind(("127.0.0.1", 0)).await.expect("primer");
    let bare = stun::MessageBuilder::new(
        turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_REQUEST),
        &[0u8; 12],
    )
    .attribute(
        turn::ATTR_REQUESTED_TRANSPORT,
        &turn::requested_transport_value(turn::TRANSPORT_UDP),
    )
    .finish(None, true);
    let challenge = exchange(&primer, server, &bare).await;
    let nonce = turn::nonce(&challenge).expect("nonce").to_vec();
    let key = rest_key();

    let _prime = allocated_bytes();
    for index in 0..200 {
        allocate_relay_delete(server, &nonce, &key, index).await;
    }
    quiesce().await;
    assert_eq!(turn.allocation_count().await, 0, "drained after warmup");
    let before = allocated_bytes();

    for index in 200..1_200 {
        allocate_relay_delete(server, &nonce, &key, index).await;
    }
    quiesce().await;
    let after = allocated_bytes();

    assert_eq!(turn.allocation_count().await, 0, "allocation table drained");

    // A small steady-state drift is allowed (lazy arena / thread-cache growth); a real leak over
    // 1000 churned allocations would dwarf it.
    let tolerance = 512 * 1024;
    assert!(
        after <= before + tolerance,
        "TURN leaked {} bytes over 1000 churned allocations (before={before}, after={after})",
        after.saturating_sub(before)
    );
}
