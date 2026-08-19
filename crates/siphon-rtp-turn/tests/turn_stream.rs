//! End-to-end TURN over the stream transports — TCP (RFC 6062 framing) and TLS (rustls) — on the
//! NIC-free loopback datapath. One session driver runs the full Allocate → CreatePermission →
//! ChannelBind → bidirectional relay over any `AsyncRead + AsyncWrite` stream, exercised over a raw
//! TCP connection and over a rustls-encrypted one (with a self-signed cert) against real UDP peers.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_stun::{self as stun, turn};
use siphon_rtp_turn::{FixedUnixClock, PeerIpPolicy, Turn, TurnConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const REALM: &str = "siphon.test";
const SECRET: &[u8] = b"static-auth-secret";
const USER: &str = "2000000000:webrtc";
const SHORT: Duration = Duration::from_secs(2);

fn config() -> TurnConfig {
    let mut config = TurnConfig::new(REALM, SECRET);
    config.denied_peers = PeerIpPolicy::permissive();
    config
}

fn rest_key() -> [u8; 16] {
    let password = turn::base64_encode(&stun::hmac_sha1(SECRET, USER.as_bytes()));
    turn::long_term_key(USER, REALM, &password)
}

/// Hold the server pieces alive for the test's lifetime.
struct Server {
    _datapath: UdpLoopbackDatapath,
    _turn: Turn,
}

async fn start(transport: Listener) -> (Server, SocketAddr) {
    let datapath = UdpLoopbackDatapath::new();
    let clock = Arc::new(FixedUnixClock::new(1_000));
    let turn = Turn::spawn(Arc::new(datapath.clone()), config(), clock).expect("spawn");
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let serving = turn.clone();
    match transport {
        Listener::Tcp => {
            tokio::spawn(async move {
                let _ = serving.serve_tcp(listener).await;
            });
        }
        Listener::Tls(acceptor) => {
            tokio::spawn(async move {
                let _ = serving.serve_tls(listener, acceptor).await;
            });
        }
    }
    (
        Server {
            _datapath: datapath,
            _turn: turn,
        },
        addr,
    )
}

enum Listener {
    Tcp,
    Tls(TlsAcceptor),
}

async fn udp_peer() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("bind peer");
    let addr = socket.local_addr().expect("peer addr");
    (socket, addr)
}

// --- transport-agnostic message builders ------------------------------------------------------

fn allocate_unauth() -> Vec<u8> {
    stun::MessageBuilder::new(
        turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_REQUEST),
        &[0u8; 12],
    )
    .attribute(
        turn::ATTR_REQUESTED_TRANSPORT,
        &turn::requested_transport_value(turn::TRANSPORT_UDP),
    )
    .finish(None, true)
}

fn authed(method: u16, txid: &[u8; 12], nonce: &[u8]) -> stun::MessageBuilder {
    stun::MessageBuilder::new(turn::message_type(method, turn::CLASS_REQUEST), txid)
        .attribute(turn::ATTR_USERNAME, USER.as_bytes())
        .attribute(turn::ATTR_REALM, REALM.as_bytes())
        .attribute(turn::ATTR_NONCE, nonce)
}

// --- stream framing client ---------------------------------------------------------------------

/// Length of the next complete TURN message at the head of `buffer`, or `None` if incomplete.
fn frame_len(buffer: &[u8]) -> Option<usize> {
    let first = *buffer.first()?;
    if first & 0xC0 == 0x40 {
        if buffer.len() < 4 {
            return None;
        }
        let length = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
        let total = (4 + length).div_ceil(4) * 4;
        (buffer.len() >= total).then_some(total)
    } else {
        if buffer.len() < 20 {
            return None;
        }
        let length = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
        let total = 20 + length;
        (buffer.len() >= total).then_some(total)
    }
}

async fn read_frame<S>(stream: &mut S) -> Vec<u8>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(len) = frame_len(&buffer) {
            return buffer[..len].to_vec();
        }
        let read = timeout(SHORT, stream.read(&mut chunk))
            .await
            .expect("read did not time out")
            .expect("read");
        assert!(read > 0, "unexpected EOF");
        buffer.extend_from_slice(&chunk[..read]);
    }
}

async fn request<S>(stream: &mut S, bytes: &[u8]) -> stun::StunMessage
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(bytes).await.expect("write request");
    stun::parse(&read_frame(stream).await).expect("parse response")
}

async fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buffer = [0u8; 2048];
    let (len, from) = timeout(SHORT, socket.recv_from(&mut buffer))
        .await
        .expect("no timeout")
        .expect("recv");
    (buffer[..len].to_vec(), from)
}

/// Run the full TURN client flow over `stream` and assert media relays both ways with a UDP `peer`.
async fn drive_session<S>(stream: &mut S, peer: &UdpSocket, peer_addr: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 401 challenge → nonce.
    let challenge = request(stream, &allocate_unauth()).await;
    assert_eq!(turn::error_code(&challenge), Some(turn::ERROR_UNAUTHORIZED));
    let nonce = turn::nonce(&challenge).expect("nonce").to_vec();
    let key = rest_key();

    // Allocate.
    let allocate = authed(turn::METHOD_ALLOCATE, &[1u8; 12], &nonce)
        .attribute(
            turn::ATTR_REQUESTED_TRANSPORT,
            &turn::requested_transport_value(turn::TRANSPORT_UDP),
        )
        .finish(Some(&key[..]), true);
    let response = request(stream, &allocate).await;
    assert_eq!(turn::class_of(response.message_type), turn::CLASS_SUCCESS);
    let relay = turn::xor_relayed_address(&response).expect("relay addr");

    // CreatePermission.
    let permission = authed(turn::METHOD_CREATE_PERMISSION, &[2u8; 12], &nonce)
        .attribute(
            turn::ATTR_XOR_PEER_ADDRESS,
            &turn::xor_address_value(peer_addr, &[2u8; 12]),
        )
        .finish(Some(&key[..]), true);
    assert_eq!(
        turn::class_of(request(stream, &permission).await.message_type),
        turn::CLASS_SUCCESS
    );

    // ChannelBind.
    let channel = 0x4001u16;
    let bind = authed(turn::METHOD_CHANNEL_BIND, &[3u8; 12], &nonce)
        .attribute(
            turn::ATTR_CHANNEL_NUMBER,
            &turn::channel_number_value(channel),
        )
        .attribute(
            turn::ATTR_XOR_PEER_ADDRESS,
            &turn::xor_address_value(peer_addr, &[3u8; 12]),
        )
        .finish(Some(&key[..]), true);
    assert_eq!(
        turn::class_of(request(stream, &bind).await.message_type),
        turn::CLASS_SUCCESS
    );

    // client → peer over a (stream-padded) ChannelData.
    stream
        .write_all(&turn::encode_channel_data(channel, b"client-to-peer", true))
        .await
        .expect("write channel data");
    let (data, from) = recv(peer).await;
    assert_eq!(data, b"client-to-peer");
    assert_eq!(from, relay);

    // peer → client, delivered back as ChannelData over the stream.
    peer.send_to(b"peer-to-client", relay)
        .await
        .expect("peer send");
    let frame = read_frame(stream).await;
    let channel_data = turn::parse_channel_data(&frame).expect("channel data");
    assert_eq!(channel_data.channel, channel);
    assert_eq!(channel_data.data, b"peer-to-client");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turn_over_tcp_relays_both_ways() {
    let (_server, addr) = start(Listener::Tcp).await;
    let (peer, peer_addr) = udp_peer().await;
    let mut stream = TcpStream::connect(addr).await.expect("connect tcp");
    drive_session(&mut stream, &peer, peer_addr).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turn_over_tls_relays_both_ways() {
    let (acceptor, connector) = tls_pair();
    let (_server, addr) = start(Listener::Tls(acceptor)).await;
    let (peer, peer_addr) = udp_peer().await;

    let tcp = TcpStream::connect(addr).await.expect("connect tcp");
    let domain = ServerName::try_from("localhost").expect("server name");
    let mut stream = connector.connect(domain, tcp).await.expect("tls handshake");
    drive_session(&mut stream, &peer, peer_addr).await;
}

/// A rustls acceptor + connector pair sharing a fresh self-signed `localhost` certificate.
fn tls_pair() -> (TlsAcceptor, TlsConnector) {
    // Install the ring crypto provider once per process (ignored if already installed).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("add root");
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    (acceptor, connector)
}
