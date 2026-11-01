//! The TURN client over TCP and TLS (RFC 8656 §3.1) against the real in-process `siphon-rtp-turn`
//! server on `serve_tcp` / `serve_tls`: allocation, permission and channel, a relayed datagram in
//! both directions, refresh, delete, and the stream closing under a live allocation. The relay leg
//! to the peers is UDP in every case.
//!
//! Every connection goes through a small proxy the test can cut, which is how a server-side close
//! is provoked: the in-process server has no API to drop a connection.

use super::turn_client::{drive_until, REALM, SECRET};
use super::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use siphon_rtp_turn::{FixedUnixClock, PeerIpPolicy, Turn, TurnConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Copy, Debug)]
enum Wire {
    Tcp,
    Tls,
}

/// A TCP forwarder in front of the TURN listener that can drop every connection it carries.
struct CuttableProxy {
    address: SocketAddr,
    cut: Arc<tokio::sync::Notify>,
}

impl CuttableProxy {
    async fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind proxy");
        let address = listener.local_addr().expect("proxy address");
        let cut = Arc::new(tokio::sync::Notify::new());
        let signal = cut.clone();
        tokio::spawn(async move {
            while let Ok((mut downstream, _)) = listener.accept().await {
                let Ok(mut forward) = tokio::net::TcpStream::connect(upstream).await else {
                    continue;
                };
                let signal = signal.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut downstream, &mut forward) => {}
                        _ = signal.notified() => {}
                    }
                });
            }
        });
        Self { address, cut }
    }

    fn cut_connections(&self) {
        self.cut.notify_waiters();
    }
}

struct StreamTurn {
    datapath: UdpLoopbackDatapath,
    turn: Turn,
    proxy: CuttableProxy,
    wire: Wire,
    client_tls: Arc<rustls::ClientConfig>,
}

impl StreamTurn {
    fn server(&self) -> TurnServer {
        match self.wire {
            Wire::Tcp => TurnServer::tcp(self.proxy.address),
            Wire::Tls => TurnServer::tls(self.proxy.address, "localhost"),
        }
    }

    fn client_config(&self) -> TurnClientConfig {
        TurnClientConfig {
            servers: vec![self.server()],
            credentials: TurnCredentialSource::Rest {
                secret: SECRET.to_string(),
                identity: "node-a".to_string(),
                ttl_secs: 3_600,
            },
            // Trust the test certificate only: the production default (web roots) would refuse it.
            tls: Some(self.client_tls.clone()),
        }
    }
}

/// A self-signed `localhost` certificate as a server acceptor plus a client config trusting it.
fn tls_pair() -> (TlsAcceptor, Arc<rustls::ClientConfig>) {
    siphon_rtp_turn::tls::install_crypto_provider();
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("certificate");
    let certificate = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .expect("server config");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).expect("root");
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (TlsAcceptor::from(Arc::new(server)), Arc::new(client))
}

async fn stream_turn(wire: Wire, max_lifetime: u32) -> StreamTurn {
    let datapath = UdpLoopbackDatapath::new();
    let mut config = TurnConfig::new(REALM, SECRET);
    config.max_lifetime = max_lifetime;
    // The peers in these tests live on loopback, which the secure default denies.
    config.denied_peers = PeerIpPolicy::permissive();
    let unix_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("unix time")
        .as_secs();
    let turn = Turn::spawn(
        Arc::new(datapath.clone()),
        config,
        Arc::new(FixedUnixClock::new(unix_now)),
    )
    .expect("spawn turn");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind turn listener");
    let upstream = listener.local_addr().expect("turn address");
    let (acceptor, client_tls) = tls_pair();
    let serving = turn.clone();
    tokio::spawn(async move {
        let _ = match wire {
            Wire::Tcp => serving.serve_tcp(listener).await,
            Wire::Tls => serving.serve_tls(listener, acceptor).await,
        };
    });
    StreamTurn {
        datapath,
        turn,
        proxy: CuttableProxy::start(upstream).await,
        wire,
        client_tls,
    }
}

/// An engine with the full agent and the stream TURN client, a call offered with ICE (so the
/// relay is gathered) and answered, the far leg's socket, and the near leg's RTP endpoint.
async fn relayed_stream_call(
    server: &StreamTurn,
    remote: SocketAddr,
) -> (Engine<UdpLoopbackDatapath>, EndpointId, UdpSocket, String) {
    let (far, far_addr) = phone().await;
    let engine = Engine::new(UdpLoopbackDatapath::new())
        .with_full_ice()
        .with_turn_client(server.client_config());
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "relayed".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(remote),
                profile: Default::default(),
            },
        )
        .await;
    let offered = ok_sdp_text(&offer);
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "relayed".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(far_addr, false),
                profile: Default::default(),
            },
        )
        .await;
    let near_rtp = engine
        .calls
        .get("relayed")
        .map(|call| call.near.rtp.id)
        .expect("call");
    (engine, near_rtp, far, offered)
}

fn has_channel(
    engine: &Engine<UdpLoopbackDatapath>,
    endpoint: EndpointId,
    peer: SocketAddr,
) -> bool {
    engine
        .ice_relays
        .get(&endpoint)
        .is_some_and(|allocation| allocation.client.channel_for(peer).is_some())
}

async fn allocates_over_a_stream(wire: Wire) {
    let server = stream_turn(wire, 600).await;
    let (_remote, remote_addr) = phone().await;
    let (engine, near_rtp, _far, offered) = relayed_stream_call(&server, remote_addr).await;

    assert!(
        offered.contains("typ relay raddr"),
        "{wire:?}: a relayed candidate with its related address is advertised: {offered}"
    );
    assert!(server.turn.allocation_count().await >= 1);
    let allocation = engine.ice_relays.get(&near_rtp).expect("allocation kept");
    assert!(
        allocation.stream.is_some(),
        "the allocation owns its stream"
    );
    assert!(allocation.client.is_reliable());
    // The relay is always UDP toward peers: REQUESTED-TRANSPORT stays 17 (RFC 8656 §7.1), so the
    // advertised candidate is a udp candidate whatever carries the client leg.
    let parsed = sdp::parse(&offered).expect("offer sdp");
    let relay = parsed
        .candidates
        .iter()
        .find(|candidate| candidate.kind == siphon_rtp_ice::CandidateKind::Relayed)
        .expect("relayed candidate");
    assert!(relay.transport.is_supported(), "{wire:?}: a UDP candidate");
}

async fn relays_a_datagram_both_ways(wire: Wire) {
    let server = stream_turn(wire, 600).await;
    let (remote, remote_addr) = phone().await;
    let (engine, near_rtp, far, _offered) = relayed_stream_call(&server, remote_addr).await;
    let relayed = engine
        .ice_relays
        .get(&near_rtp)
        .and_then(|allocation| allocation.client.relayed_address())
        .expect("allocated");
    assert!(
        drive_until(&engine, 0, 20_000, || has_channel(
            &engine,
            near_rtp,
            remote_addr
        ))
        .await,
        "{wire:?}: permission and channel bound over the stream"
    );
    // Let the channel reach the datapath on the next tick.
    engine.drive_ice_agents(30_000).await;

    // Engine to peer: ChannelData (padded, RFC 8656 §12.5) over the stream; the peer sees UDP from
    // the allocation's relayed address.
    engine
        .datapath()
        .send(near_rtp, remote_addr, b"through-the-relay")
        .await
        .expect("send");
    let mut buffer = [0u8; 2048];
    let mut arrived = false;
    for _ in 0..20 {
        let (len, from) = timeout(Duration::from_secs(2), remote.recv_from(&mut buffer))
            .await
            .expect("a relayed datagram arrives")
            .expect("recv");
        if &buffer[..len] == b"through-the-relay" {
            assert_eq!(from, relayed, "{wire:?}: sourced from the relayed address");
            arrived = true;
            break;
        }
    }
    assert!(arrived, "{wire:?}: engine to peer");

    // Peer to engine: the server wraps the peer's UDP into ChannelData on the stream, the reader
    // injects it into the datapath, and it passes the ICE gate and the relay flow to the far leg.
    // Nominating the remote candidate is what the agent does when ICE selects a pair.
    engine.datapath().adopt_source(near_rtp, remote_addr);
    let media = rtp_packet(0x5151_5151, 7);
    let mut delivered = false;
    for _ in 0..20 {
        remote.send_to(&media, relayed).await.expect("peer sends");
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(250), far.recv_from(&mut buffer)).await
        {
            assert_eq!(&buffer[..len], &media[..], "{wire:?}: payload intact");
            delivered = true;
            break;
        }
    }
    assert!(
        delivered,
        "{wire:?}: peer to engine, through ingest and the flow"
    );
}

/// A minimal RTP packet (version 2, PCMU) with `ssrc` and `sequence`.
fn rtp_packet(ssrc: u32, sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&[0xFF; 160]);
    packet
}

async fn refreshes_before_it_lapses(wire: Wire) {
    let server = stream_turn(wire, 30).await;
    let (_remote, remote_addr) = phone().await;
    let (engine, near_rtp, _far, _offered) = relayed_stream_call(&server, remote_addr).await;
    assert!(
        drive_until(&engine, 0, 20_000, || has_channel(
            &engine,
            near_rtp,
            remote_addr
        ))
        .await
    );
    let allocations = server.turn.allocation_count().await;
    assert!(allocations >= 1);

    server.datapath.advance_clock(20);
    drive_until(&engine, 20_000, 24_000, || false).await;
    assert!(engine.calls.contains_key("relayed"));
    server.datapath.advance_clock(20);
    server.turn.reap();
    assert_eq!(
        server.turn.allocation_count().await,
        allocations,
        "{wire:?}: the refresh over the stream extended the allocation past its first expiry"
    );
    assert!(engine
        .ice_relays
        .get(&near_rtp)
        .is_some_and(|allocation| !allocation.client.is_terminal()));
}

async fn deleting_the_call_frees_the_allocation_and_closes_the_stream(wire: Wire) {
    let server = stream_turn(wire, 600).await;
    let (_remote, remote_addr) = phone().await;
    let (engine, near_rtp, _far, _offered) = relayed_stream_call(&server, remote_addr).await;
    assert!(server.turn.allocation_count().await >= 1);
    drive_until(&engine, 0, 20_000, || {
        has_channel(&engine, near_rtp, remote_addr)
    })
    .await;

    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "relayed".into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;

    assert!(engine.ice_relays.is_empty());
    let mut remaining = server.turn.allocation_count().await;
    for _ in 0..100 {
        if remaining == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        remaining = server.turn.allocation_count().await;
    }
    assert_eq!(
        remaining, 0,
        "{wire:?}: the delete was written to the stream before it was closed"
    );
}

async fn a_closed_stream_fails_the_allocation_and_clears_the_relay(wire: Wire) {
    let server = stream_turn(wire, 600).await;
    let (remote, remote_addr) = phone().await;
    let (engine, near_rtp, _far, _offered) = relayed_stream_call(&server, remote_addr).await;
    assert!(
        drive_until(&engine, 0, 20_000, || has_channel(
            &engine,
            near_rtp,
            remote_addr
        ))
        .await
    );
    engine.drive_ice_agents(30_000).await;

    server.proxy.cut_connections();
    let cleared = drive_until(&engine, 31_000, 60_000, || engine.ice_relays.is_empty()).await;
    assert!(cleared, "{wire:?}: the closed stream ended the allocation");
    assert!(
        engine.calls.contains_key("relayed"),
        "the call survives on its other candidates"
    );

    // With the relay cleared, a send to the peer no longer goes through the (dead) stream: it
    // leaves the endpoint's own socket directly.
    engine
        .datapath()
        .send(near_rtp, remote_addr, b"direct-now")
        .await
        .expect("send");
    let mut buffer = [0u8; 2048];
    let mut direct = false;
    for _ in 0..20 {
        let (len, from) = timeout(Duration::from_secs(2), remote.recv_from(&mut buffer))
            .await
            .expect("a datagram arrives")
            .expect("recv");
        if &buffer[..len] == b"direct-now" {
            assert_eq!(
                from.port(),
                engine.endpoint_address(near_rtp).expect("address").port(),
                "{wire:?}: sourced from the endpoint itself, not a relay"
            );
            direct = true;
            break;
        }
    }
    assert!(direct, "{wire:?}: falls back to the direct path");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_allocates_and_advertises_a_relayed_candidate() {
    allocates_over_a_stream(Wire::Tcp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_allocates_and_advertises_a_relayed_candidate() {
    allocates_over_a_stream(Wire::Tls).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_relays_a_datagram_both_ways() {
    relays_a_datagram_both_ways(Wire::Tcp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_relays_a_datagram_both_ways() {
    relays_a_datagram_both_ways(Wire::Tls).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_refreshes_before_it_lapses() {
    refreshes_before_it_lapses(Wire::Tcp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_refreshes_before_it_lapses() {
    refreshes_before_it_lapses(Wire::Tls).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_delete_frees_the_allocation() {
    deleting_the_call_frees_the_allocation_and_closes_the_stream(Wire::Tcp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_delete_frees_the_allocation() {
    deleting_the_call_frees_the_allocation_and_closes_the_stream(Wire::Tls).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_close_fails_the_allocation_and_clears_the_relay() {
    a_closed_stream_fails_the_allocation_and_clears_the_relay(Wire::Tcp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_close_fails_the_allocation_and_clears_the_relay() {
    a_closed_stream_fails_the_allocation_and_clears_the_relay(Wire::Tls).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tls_server_the_client_does_not_trust_yields_no_relay_and_a_host_only_list() {
    // The default trust store is the public web roots: a self-signed server certificate must be
    // refused, and the offer still completes without a relayed candidate.
    let server = stream_turn(Wire::Tls, 600).await;
    let engine = Engine::new(UdpLoopbackDatapath::new())
        .with_full_ice()
        .with_turn_client(TurnClientConfig {
            tls: None,
            ..server.client_config()
        });
    let (_remote, remote_addr) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "untrusted".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(remote_addr),
                profile: Default::default(),
            },
        )
        .await;
    let text = ok_sdp_text(&offer);
    assert!(!text.contains("typ relay"), "{text}");
    assert!(text.contains("typ host"), "{text}");
    assert_eq!(server.turn.allocation_count().await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_udp_first_server_does_not_delay_a_live_stream_server() {
    let server = stream_turn(Wire::Tcp, 600).await;
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind silent");
    let silent_addr = silent.local_addr().expect("address");
    let engine = Engine::new(UdpLoopbackDatapath::new())
        .with_full_ice()
        .with_turn_client(TurnClientConfig {
            servers: vec![silent_addr.into(), server.server()],
            ..server.client_config()
        });
    let (_remote, remote_addr) = phone().await;
    let started = std::time::Instant::now();
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "mixed".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(remote_addr),
                profile: Default::default(),
            },
        )
        .await;
    assert!(ok_sdp_text(&offer).contains("typ relay"));
    assert!(started.elapsed() < Duration::from_millis(1_000));
    drop(silent);
}
