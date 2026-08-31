//! End-to-end proof of lawful-interception content delivery (ETSI TS 103 221-2 X3): stand up a stub
//! Mediation Function behind mutual TLS, run the real delivery task against it, and assert that what
//! arrives is well-formed X3 PDUs carrying the intercepted RTP.
//!
//! This is the test that stops the delivery path being a plausible-looking pipe that never puts
//! anything on the wire. Everything else about X3 is unit-tested — the framing against an
//! independent decoder, the taps against the media pipeline and the crypto bridges — but only this
//! exercises the PKI, the handshake, the framing and the socket together.
//!
//! NIC-free: a loopback TCP listener, and certificates generated in-process.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_engine::x3::{
    build_tls_client_config, ingress_directions, run_x3_delivery, x3_channel, X3Config,
    X3DeliveryTask,
};
use siphon_rtp_li::attributes::attribute_type;
use siphon_rtp_li::inbound::InboundHeader;
use siphon_rtp_li::{PayloadDirection, PduType, HEADER_LEN};
use siphon_rtp_proto::Xid;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::time::timeout;

const SHORT: Duration = Duration::from_secs(5);

/// The interception task identifier under test (fixed bytes, not provisioning data).
const XID_TEXT: &str = "8c292fa1-5831-46ec-86be-bd85f2083299";
/// A non-zero session correlation (TS 103 221-2 clause 6).
const CORRELATION_ID: u64 = 0x0102_0304_0506_0708;

/// The generated PKI: a CA that signs both ends, written out as the PEM files the engine config
/// names, plus the DER the stub server needs.
struct Pki {
    _directory: tempfile::TempDir,
    config: X3Config,
    server_certs: Vec<rustls_pki_types::CertificateDer<'static>>,
    server_key: rustls_pki_types::PrivateKeyDer<'static>,
    client_roots: rustls::RootCertStore,
}

/// Generate a CA, a server certificate for `127.0.0.1` and a client certificate, and write the
/// engine's three PEM files. Mutual TLS is the point: the Mediation Function authenticates the
/// network element by certificate, and its own certificate is signed by a private CA that the public
/// Mozilla bundle would never contain.
fn pki() -> Pki {
    siphon_rtp_turn::tls::install_crypto_provider();

    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "siphon-rtp test LI CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");
    let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

    // The Mediation Function's certificate, with an IP SAN so rustls validates the
    // `ServerName::IpAddress` derived from a `127.0.0.1:port` delivery address.
    let server_key = rcgen::KeyPair::generate().expect("server key");
    let server_params =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("server params");
    let server_cert = server_params
        .signed_by(&server_key, &ca_issuer)
        .expect("sign server");

    // The engine's own certificate, which the Mediation Function verifies.
    let client_key = rcgen::KeyPair::generate().expect("client key");
    let mut client_params = rcgen::CertificateParams::new(Vec::new()).expect("client params");
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "siphon-rtp-sbc-01");
    let client_cert = client_params
        .signed_by(&client_key, &ca_issuer)
        .expect("sign client");

    let directory = tempfile::tempdir().expect("tempdir");
    let write = |name: &str, contents: String| -> PathBuf {
        let path = directory.path().join(name);
        std::fs::write(&path, contents).expect("write pem");
        path
    };
    let config = X3Config {
        client_cert: write("client.pem", client_cert.pem()),
        client_key: write("client.key", client_key.serialize_pem()),
        ca: write("ca.pem", ca_cert.pem()),
        network_function_id: "siphon-rtp-sbc-01".to_string(),
        interception_point_id: "media-relay-a".to_string(),
        buffer_packets: 256,
        keepalive: Duration::from_secs(30),
    };

    // The stub server trusts the same CA for client authentication.
    let mut client_roots = rustls::RootCertStore::empty();
    client_roots
        .add(rustls_pki_types::CertificateDer::from(
            ca_cert.der().to_vec(),
        ))
        .expect("trust ca for client auth");

    Pki {
        _directory: directory,
        config,
        server_certs: vec![rustls_pki_types::CertificateDer::from(
            server_cert.der().to_vec(),
        )],
        server_key: rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
        ),
        client_roots,
    }
}

/// A TLS acceptor that **requires** a client certificate signed by the test CA.
fn acceptor(pki: &Pki) -> tokio_rustls::TlsAcceptor {
    let verifier =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(pki.client_roots.clone()))
            .build()
            .expect("client verifier");
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(pki.server_certs.clone(), pki.server_key.clone_key())
        .expect("server tls config");
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// One decoded PDU: its header plus the raw attribute block and payload.
struct DecodedPdu {
    header: InboundHeader,
    attributes: Vec<u8>,
    payload: Vec<u8>,
}

/// Read exactly `count` PDUs off the stream, honouring the length fields rather than guessing at
/// message boundaries — the same framing a real Mediation Function does.
async fn read_pdus<S>(stream: &mut S, count: usize) -> Vec<DecodedPdu>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut decoded = Vec::new();
    let mut chunk = [0u8; 4096];
    while decoded.len() < count {
        // Drain every complete PDU already buffered before reading more.
        while let Ok(header) = InboundHeader::parse(&buffer) {
            let total = header.total_len().expect("plausible total length");
            if buffer.len() < total {
                break; // need more bytes for the body
            }
            let attributes_end = header.header_length as usize;
            decoded.push(DecodedPdu {
                attributes: buffer[HEADER_LEN..attributes_end].to_vec(),
                payload: buffer[attributes_end..total].to_vec(),
                header,
            });
            buffer.drain(..total);
            if decoded.len() == count {
                return decoded;
            }
        }
        let read = timeout(SHORT, stream.read(&mut chunk))
            .await
            .expect("no timeout")
            .expect("read");
        assert!(read > 0, "the delivery connection closed early");
        buffer.extend_from_slice(&chunk[..read]);
    }
    decoded
}

/// Find one TLV in an attribute block, walking it strictly as `4 + length`.
fn attribute(block: &[u8], wanted: u16) -> Option<Vec<u8>> {
    let mut offset = 0usize;
    while offset + 4 <= block.len() {
        let kind = u16::from_be_bytes([block[offset], block[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([block[offset + 2], block[offset + 3]]));
        let value_start = offset + 4;
        let value_end = value_start.checked_add(length)?;
        if value_end > block.len() {
            return None;
        }
        if kind == wanted {
            return Some(block[value_start..value_end].to_vec());
        }
        offset = value_end;
    }
    None
}

/// A G.711 RTP packet with a recognisable sequence number and SSRC.
fn rtp(sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&0xdead_beefu32.to_be_bytes());
    packet.extend_from_slice(&[0xd5; 160]);
    packet
}

/// Build the delivery task for `address` from `pki`.
fn delivery_task(
    pki: &Pki,
    address: SocketAddr,
    delivery: siphon_rtp_engine::x3::X3Delivery,
) -> X3DeliveryTask {
    X3DeliveryTask {
        delivery,
        address: address.to_string(),
        xid: XID_TEXT.parse::<Xid>().expect("xid"),
        correlation_id: CORRELATION_ID,
        network_function_id: pki.config.network_function_id.clone(),
        interception_point_id: pki.config.interception_point_id.clone(),
        keepalive: pki.config.keepalive,
        tls: build_tls_client_config(&pki.config).expect("client tls config"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delivers_framed_x3_pdus_to_a_mediation_function_over_mutual_tls() {
    let pki = pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mdf");
    let address = listener.local_addr().expect("mdf addr");
    let acceptor = acceptor(&pki);

    let (factory, delivery) = x3_channel(pki.config.buffer_packets);
    // Target on the caller leg, so its ingress is "sent from the target".
    let (direction_a, direction_b) = ingress_directions(true);
    let local_a: SocketAddr = "127.0.0.1:20000".parse().expect("local a");
    let local_b: SocketAddr = "127.0.0.1:20002".parse().expect("local b");
    let tap_a = factory.tap(local_a, direction_a);
    let tap_b = factory.tap(local_b, direction_b);

    let task = delivery_task(&pki, address, delivery);
    let delivery_handle = tokio::spawn(async move { run_x3_delivery(task, |_, _| {}).await });

    // Intercepted media: two packets from the target, one toward it.
    let source_a: SocketAddr = "203.0.113.9:16384".parse().expect("source a");
    let source_b: SocketAddr = "198.51.100.4:16386".parse().expect("source b");
    tap_a.deliver(source_a, 1_000, &rtp(1));
    tap_b.deliver(source_b, 21_000, &rtp(500));
    tap_a.deliver(source_a, 41_000, &rtp(2));

    let (stream, _) = timeout(SHORT, listener.accept())
        .await
        .expect("no timeout")
        .expect("accept");
    let mut tls = timeout(SHORT, acceptor.accept(stream))
        .await
        .expect("no timeout")
        .expect("mutual TLS handshake — the engine must present a client certificate");

    let pdus = read_pdus(&mut tls, 3).await;

    // Every PDU is a well-formed X3 carrying the task's identifiers.
    for pdu in &pdus {
        assert_eq!(pdu.header.pdu_type, PduType::X3.to_u16());
        assert!(
            pdu.header.version_matches(),
            "version {}.{} is not the PDU format version",
            pdu.header.version_major,
            pdu.header.version_minor
        );
        assert_eq!(pdu.header.payload_format, 8, "8 = RTP packet");
        assert_eq!(pdu.header.correlation_id, CORRELATION_ID);
        assert_eq!(
            Xid::from_bytes(pdu.header.xid).to_string(),
            XID_TEXT,
            "the X1 task identifier is carried through unchanged"
        );
    }

    // The payloads are the intercepted RTP, verbatim and in arrival order.
    assert_eq!(pdus[0].payload, rtp(1));
    assert_eq!(pdus[1].payload, rtp(500));
    assert_eq!(pdus[2].payload, rtp(2));

    // Direction is target-relative: leg A is the target, leg B is the far end.
    assert_eq!(
        pdus[0].header.payload_direction,
        PayloadDirection::FromTarget.to_u16()
    );
    assert_eq!(
        pdus[1].header.payload_direction,
        PayloadDirection::ToTarget.to_u16()
    );
    assert_eq!(
        pdus[2].header.payload_direction,
        PayloadDirection::FromTarget.to_u16()
    );

    // The conditional attributes describe the intercepted 5-tuple and carry the node identity.
    let first = &pdus[0].attributes;
    assert_eq!(
        attribute(first, attribute_type::NETWORK_FUNCTION_ID).as_deref(),
        Some(b"siphon-rtp-sbc-01".as_slice())
    );
    assert_eq!(
        attribute(first, attribute_type::INTERCEPTION_POINT_ID).as_deref(),
        Some(b"media-relay-a".as_slice())
    );
    assert_eq!(
        attribute(first, attribute_type::SOURCE_IPV4).as_deref(),
        Some([203, 0, 113, 9].as_slice())
    );
    assert_eq!(
        attribute(first, attribute_type::SOURCE_PORT).as_deref(),
        Some(16384u16.to_be_bytes().as_slice())
    );
    assert_eq!(
        attribute(first, attribute_type::DESTINATION_PORT).as_deref(),
        Some(20000u16.to_be_bytes().as_slice())
    );
    assert_eq!(
        attribute(first, attribute_type::IP_PROTOCOL).as_deref(),
        Some([17u8].as_slice()),
        "relayed RTP always rides UDP"
    );

    // The per-connection sequence number counts up from zero across both legs' packets.
    let sequences: Vec<u32> = pdus
        .iter()
        .map(|pdu| {
            let value =
                attribute(&pdu.attributes, attribute_type::SEQUENCE_NUMBER).expect("sequence");
            u32::from_be_bytes([value[0], value[1], value[2], value[3]])
        })
        .collect();
    assert_eq!(sequences, vec![0, 1, 2]);

    // The timestamp is absolute Unix time, not the datapath's relative receive clock. A monotonic
    // since-boot reading leaking through would land in 1970 — the defect `WallClockAnchor` prevents.
    let timestamp = attribute(first, attribute_type::TIMESTAMP).expect("timestamp");
    let seconds = u32::from_be_bytes([timestamp[0], timestamp[1], timestamp[2], timestamp[3]]);
    let nanoseconds = u32::from_be_bytes([timestamp[4], timestamp[5], timestamp[6], timestamp[7]]);
    assert!(
        seconds > 1_577_836_800,
        "the interception timestamp must be absolute Unix time, got {seconds}"
    );
    assert!(nanoseconds < 1_000_000_000);

    // The second leg-A packet is 40 ms later on the receive clock, and the delivered timestamps must
    // preserve exactly that spacing — the whole reason the wall clock is anchored once, not sampled
    // per packet.
    let later = attribute(&pdus[2].attributes, attribute_type::TIMESTAMP).expect("timestamp");
    let later_seconds = u32::from_be_bytes([later[0], later[1], later[2], later[3]]);
    let later_nanoseconds = u32::from_be_bytes([later[4], later[5], later[6], later[7]]);
    let elapsed_nanos = (u64::from(later_seconds) * 1_000_000_000 + u64::from(later_nanoseconds))
        .saturating_sub(u64::from(seconds) * 1_000_000_000 + u64::from(nanoseconds));
    assert_eq!(
        elapsed_nanos, 40_000_000,
        "40 ms of receive clock must be 40 ms of delivered timestamp"
    );

    delivery_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn buffers_across_a_mediation_outage_and_delivers_late_rather_than_discarding() {
    // The loss policy that separates X3 from the pcap recorder: warranted content buffered while the
    // Mediation Function is unreachable must be delivered when it comes back, not discarded through
    // the outage. The listener exists (so the port is reserved) but nothing accepts until after the
    // packets have been handed to the tap.
    let pki = pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mdf");
    let address = listener.local_addr().expect("mdf addr");
    let acceptor = acceptor(&pki);

    let (factory, delivery) = x3_channel(pki.config.buffer_packets);
    let tap = factory.tap(
        "127.0.0.1:20000".parse().expect("local"),
        PayloadDirection::FromTarget,
    );
    let counters = factory.counters().clone();

    let task = delivery_task(&pki, address, delivery);
    let delivery_handle = tokio::spawn(async move { run_x3_delivery(task, |_, _| {}).await });

    let source: SocketAddr = "203.0.113.9:16384".parse().expect("source");
    for sequence in 1..=5u16 {
        tap.deliver(source, u64::from(sequence) * 20_000, &rtp(sequence));
    }
    // Nothing has been delivered — no handshake has completed — and nothing has been dropped either.
    assert_eq!(counters.delivered(), 0);
    assert_eq!(
        counters.dropped(),
        0,
        "a reachable-but-unaccepted MDF is not loss"
    );

    // The Mediation Function comes back.
    let (stream, _) = timeout(SHORT, listener.accept())
        .await
        .expect("no timeout")
        .expect("accept");
    let mut tls = timeout(SHORT, acceptor.accept(stream))
        .await
        .expect("no timeout")
        .expect("tls handshake");

    let pdus = read_pdus(&mut tls, 5).await;
    let payloads: Vec<Vec<u8>> = pdus.into_iter().map(|pdu| pdu.payload).collect();
    assert_eq!(
        payloads,
        (1..=5u16).map(rtp).collect::<Vec<_>>(),
        "everything buffered during the outage is delivered, in order"
    );
    assert_eq!(counters.dropped(), 0);

    delivery_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_buffer_reports_loss_and_keeps_a_contiguous_prefix() {
    // When the outage outlasts the buffer, content is lost — and that must be loud. The delivered
    // stream stays a contiguous prefix so the gap is one reportable range.
    let pki = pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mdf");
    let address = listener.local_addr().expect("mdf addr");
    let acceptor = acceptor(&pki);

    let mut config = pki.config.clone();
    config.buffer_packets = 4;
    let (factory, delivery) = x3_channel(config.buffer_packets);
    let tap = factory.tap(
        "127.0.0.1:20000".parse().expect("local"),
        PayloadDirection::FromTarget,
    );
    let counters = factory.counters().clone();

    let (loss_tx, loss_rx) = flume::unbounded::<(u64, u64)>();
    let task = delivery_task(&pki, address, delivery);
    let delivery_handle = tokio::spawn(async move {
        run_x3_delivery(task, move |dropped, delivered| {
            let _ = loss_tx.send((dropped, delivered));
        })
        .await
    });

    let source: SocketAddr = "203.0.113.9:16384".parse().expect("source");
    for sequence in 1..=10u16 {
        tap.deliver(source, u64::from(sequence) * 20_000, &rtp(sequence));
    }
    assert!(
        counters.dropped() > 0,
        "an over-cap outage must drop and count"
    );

    let (stream, _) = timeout(SHORT, listener.accept())
        .await
        .expect("no timeout")
        .expect("accept");
    let mut tls = timeout(SHORT, acceptor.accept(stream))
        .await
        .expect("no timeout")
        .expect("tls handshake");

    // What survived is the oldest packets, contiguously — the newest were discarded on arrival.
    let pdus = read_pdus(&mut tls, 4).await;
    let payloads: Vec<Vec<u8>> = pdus.into_iter().map(|pdu| pdu.payload).collect();
    assert_eq!(
        payloads,
        (1..=4u16).map(rtp).collect::<Vec<_>>(),
        "the delivered stream is a contiguous prefix, not the most recent packets"
    );

    // …and the loss is reported to the controller, which owes a destination-level report.
    let (dropped, _delivered) = timeout(SHORT, loss_rx.recv_async())
        .await
        .expect("a loss report must be raised")
        .expect("loss report");
    assert_eq!(dropped, 6);

    delivery_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mediation_function_that_rejects_our_certificate_delivers_nothing() {
    // Fail-closed: if the Mediation Function will not authenticate this engine, content must stay
    // buffered rather than be sent in the clear or dropped on the floor.
    // A server that trusts a *different* CA, so our client certificate is rejected.
    let unrelated = pki();
    let pki = pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mdf");
    let address = listener.local_addr().expect("mdf addr");
    let acceptor = acceptor(&unrelated);

    let (factory, delivery) = x3_channel(64);
    let tap = factory.tap(
        "127.0.0.1:20000".parse().expect("local"),
        PayloadDirection::FromTarget,
    );
    let counters = factory.counters().clone();

    let task = delivery_task(&pki, address, delivery);
    let delivery_handle = tokio::spawn(async move { run_x3_delivery(task, |_, _| {}).await });

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            // The handshake fails; keep accepting so the client keeps retrying.
            let _ = acceptor.accept(stream).await;
        }
    });

    tap.deliver(
        "203.0.113.9:16384".parse().expect("source"),
        20_000,
        &rtp(1),
    );
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        counters.delivered(),
        0,
        "nothing may be delivered to a peer that would not authenticate us"
    );

    delivery_handle.abort();
}

/// Reading a PDU header off the wire is the framing a stream reader depends on; a plain TCP peer
/// that is not the configured Mediation Function must not be able to reach it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delivery_never_speaks_plaintext_to_a_non_tls_peer() {
    let pki = pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mdf");
    let address = listener.local_addr().expect("mdf addr");

    let (factory, delivery) = x3_channel(64);
    let tap = factory.tap(
        "127.0.0.1:20000".parse().expect("local"),
        PayloadDirection::FromTarget,
    );

    let task = delivery_task(&pki, address, delivery);
    let delivery_handle = tokio::spawn(async move { run_x3_delivery(task, |_, _| {}).await });

    tap.deliver(
        "203.0.113.9:16384".parse().expect("source"),
        20_000,
        &rtp(1),
    );

    // Accept the TCP connection but never complete a TLS handshake. Whatever the engine sends must
    // be a ClientHello, never an X3 PDU: a Mediation Function that cannot terminate TLS gets no
    // intercepted media.
    let (mut stream, _) = timeout(SHORT, listener.accept())
        .await
        .expect("no timeout")
        .expect("accept");
    let mut buffer = [0u8; 1024];
    let read = timeout(Duration::from_millis(500), stream.read(&mut buffer))
        .await
        .expect("no timeout")
        .expect("read");
    assert!(read > 0, "the engine must at least start a handshake");
    assert_eq!(
        buffer[0], 0x16,
        "the first byte on the wire must be a TLS handshake record, not a PDU"
    );
    // Stronger than the first-byte check: nothing on this connection may parse as an X3 PDU.
    if let Ok(header) = InboundHeader::parse(&buffer[..read]) {
        assert_ne!(
            header.pdu_type,
            PduType::X3.to_u16(),
            "no X3 PDU may appear before the TLS handshake completes"
        );
    }

    delivery_handle.abort();
}
