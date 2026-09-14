//! Backend-agnostic security conformance checks for a [`Datapath`].
//!
//! Each check is an adversarial test written against the trait rather than a backend, so every
//! backend proves the RTPBleed defences docs/security-and-nat.md §4 requires of it: the RFC 7983
//! demux (layer 1), the signalled-source gate (layer 2) and the SSRC-consistent latch (layer 3). A
//! backend that only reused the latch state machine would otherwise inherit none of the cover the
//! UDP-loopback backend's own tests give it. The UDP-loopback backend runs these from its unit tests;
//! another backend enables the `conformance` feature and runs them against its own endpoints.
//!
//! A check drives the backend from real UDP sockets on distinct source addresses, because the gate
//! keys on the address. [`Peers`] carries them; [`Peers::loopback`] binds them inside 127.0.0.0/8,
//! which is all loopback on Linux.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "conformance harness: a panic reports the failed check"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::{Datapath, FlowAction, ForwardRule};

/// How long a check waits for a datagram it expects the backend to deliver.
const DELIVERY: Duration = Duration::from_secs(1);

/// How long a check waits before concluding the backend did **not** deliver a datagram.
const NON_DELIVERY: Duration = Duration::from_millis(150);

/// Receive buffer size; every datagram a check sends is a few dozen bytes.
const MAX_DATAGRAM: usize = 2048;

/// The header of a STUN Binding request (RFC 8489 §5): first byte `0x00`, so the RFC 7983 demux
/// classifies it as STUN, never as media.
const STUN_BINDING_REQUEST_HEADER: [u8; 8] = [0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];

/// The UDP sockets a check drives a backend with, each bound on its own source address.
pub struct Peers {
    /// The SDP-signalled party whose media the backend must accept.
    pub caller: UdpSocket,
    /// The same party after a NAT rebind: a new source address carrying the same RTP stream.
    pub rebound_caller: UdpSocket,
    /// An off-path source spraying media at the backend.
    pub attacker: UdpSocket,
    /// The party the backend forwards toward.
    pub callee: UdpSocket,
}

impl Peers {
    /// Peers on distinct 127.0.0.0/8 addresses, for a backend whose endpoints loopback reaches.
    pub async fn loopback() -> Self {
        Self {
            caller: bind(Ipv4Addr::new(127, 0, 0, 2)).await,
            rebound_caller: bind(Ipv4Addr::new(127, 0, 0, 5)).await,
            attacker: bind(Ipv4Addr::new(127, 0, 0, 6)).await,
            callee: bind(Ipv4Addr::new(127, 0, 0, 4)).await,
        }
    }
}

/// Layer 2, the RTPBleed race: media from an off-path source that arrives **before** the signalled
/// peer's is neither forwarded nor latched and is counted as dropped, and the signalled peer's media
/// then flows out of the callee-facing endpoint (docs/security-and-nat.md §4 layer 2; RFC 3264).
pub async fn an_off_path_source_is_gated_out<D: Datapath>(datapath: &D, peers: &Peers) {
    let leg_a = datapath.alloc_endpoint().await.expect("alloc leg a");
    let leg_b = datapath.alloc_endpoint().await.expect("alloc leg b");
    datapath
        .install_flow(
            leg_a.id,
            FlowAction::Forward(ForwardRule::signalled(
                leg_b.id,
                Some(address(&peers.callee)),
                address(&peers.caller).ip(),
            )),
        )
        .expect("install flow on leg a");

    // The attacker races first; the gate rejects it and nothing reaches the callee.
    send(&peers.attacker, &rtp(0xAAAA_AAAA, 1), leg_a.local_addr).await;
    assert_not_delivered(
        &peers.callee,
        "off-path attacker media must not be forwarded (RTPBleed)",
    )
    .await;

    // The signalled peer's media flows.
    send(&peers.caller, &rtp(0x1234_5678, 1), leg_a.local_addr).await;
    let (data, from) = receive(&peers.callee).await;
    assert_eq!(data, rtp(0x1234_5678, 1));
    assert_eq!(from, leg_b.local_addr);

    // The rejected datagram is counted as dropped.
    let mut dropped = 0;
    for _ in 0..50 {
        dropped = datapath.stats(leg_a.id).expect("stats").packets_dropped;
        if dropped >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(dropped, 1, "attacker datagram counted as dropped");

    datapath.remove_endpoint(leg_a.id).await;
    datapath.remove_endpoint(leg_b.id).await;
}

/// Layer 3, hijack versus rebind: on a `symmetric` (any-source) leg the SSRC alone separates them. A
/// new source carrying a different SSRC is neither forwarded nor latched; a new source carrying the
/// latched stream's SSRC re-latches and flows (docs/security-and-nat.md §4 layer 3; RFC 3550 §8).
pub async fn the_latch_follows_a_same_ssrc_rebind_but_rejects_a_hijack<D: Datapath>(
    datapath: &D,
    peers: &Peers,
) {
    let leg_a = datapath.alloc_endpoint().await.expect("alloc leg a");
    let leg_b = datapath.alloc_endpoint().await.expect("alloc leg b");
    datapath
        .install_flow(
            leg_a.id,
            FlowAction::Forward(ForwardRule::symmetric(
                leg_b.id,
                Some(address(&peers.callee)),
            )),
        )
        .expect("install flow on leg a");

    // The first source latches and flows.
    send(&peers.caller, &rtp(0x1111_1111, 1), leg_a.local_addr).await;
    let (data, _) = receive(&peers.callee).await;
    assert_eq!(data, rtp(0x1111_1111, 1));

    // A new source with a DIFFERENT SSRC is a hijack attempt: rejected, not forwarded.
    send(&peers.attacker, &rtp(0x9999_9999, 2), leg_a.local_addr).await;
    assert_not_delivered(
        &peers.callee,
        "a wrong-SSRC source must not hijack the latched stream",
    )
    .await;

    // A new source with the SAME SSRC is a genuine NAT rebind: re-latched, and it flows.
    send(
        &peers.rebound_caller,
        &rtp(0x1111_1111, 3),
        leg_a.local_addr,
    )
    .await;
    let (data, _) = receive(&peers.callee).await;
    assert_eq!(data, rtp(0x1111_1111, 3));

    datapath.remove_endpoint(leg_a.id).await;
    datapath.remove_endpoint(leg_b.id).await;
}

/// Layer 1, the demux: a datagram outside the RTP/RTCP range (a STUN Binding request) on a media port
/// is dropped, never forwarded and never latched, even on a `symmetric` leg. The proof that it left no
/// latch behind is that a **different** source's RTP still latches and flows afterwards, which a
/// latch pinned by the STUN datagram would reject (docs/security-and-nat.md §4 layer 1; RFC 7983).
pub async fn a_non_media_datagram_is_dropped_without_latching<D: Datapath>(
    datapath: &D,
    peers: &Peers,
) {
    let leg_a = datapath.alloc_endpoint().await.expect("alloc leg a");
    let leg_b = datapath.alloc_endpoint().await.expect("alloc leg b");
    datapath
        .install_flow(
            leg_a.id,
            FlowAction::Forward(ForwardRule::symmetric(
                leg_b.id,
                Some(address(&peers.callee)),
            )),
        )
        .expect("install flow on leg a");

    send(
        &peers.attacker,
        &STUN_BINDING_REQUEST_HEADER,
        leg_a.local_addr,
    )
    .await;
    assert_not_delivered(&peers.callee, "a non-RTP datagram must not be forwarded").await;

    send(&peers.caller, &rtp(0x2222_2222, 1), leg_a.local_addr).await;
    let (data, _) = receive(&peers.callee).await;
    assert_eq!(data, rtp(0x2222_2222, 1));

    datapath.remove_endpoint(leg_a.id).await;
    datapath.remove_endpoint(leg_b.id).await;
}

async fn bind(ip: Ipv4Addr) -> UdpSocket {
    UdpSocket::bind((ip, 0)).await.expect("bind a peer socket")
}

fn address(socket: &UdpSocket) -> SocketAddr {
    socket.local_addr().expect("peer socket address")
}

async fn send(socket: &UdpSocket, datagram: &[u8], destination: SocketAddr) {
    socket
        .send_to(datagram, destination)
        .await
        .expect("peer send");
}

async fn receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buffer = [0u8; MAX_DATAGRAM];
    let (length, from) = timeout(DELIVERY, socket.recv_from(&mut buffer))
        .await
        .expect("the backend delivered the datagram in time")
        .expect("peer receive");
    (buffer[..length].to_vec(), from)
}

async fn assert_not_delivered(socket: &UdpSocket, message: &str) {
    let mut buffer = [0u8; MAX_DATAGRAM];
    assert!(
        timeout(NON_DELIVERY, socket.recv_from(&mut buffer))
            .await
            .is_err(),
        "{message}"
    );
}

/// A minimal RTP packet (V=2, PT=0/PCMU) carrying `ssrc` and `sequence`: enough for the latch to read
/// an SSRC (RFC 3550 §5.1).
fn rtp(ssrc: u32, sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&0u32.to_be_bytes()); // timestamp
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(b"audio");
    packet
}
