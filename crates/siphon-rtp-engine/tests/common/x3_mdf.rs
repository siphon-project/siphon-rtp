//! Shared stub Mediation Function for the X3 integration tests: an in-process mutual-TLS PKI, a
//! listener-side acceptor, and a PDU reader that honours the length fields the way a real MDF does.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure, and each test binary uses a subset"
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use siphon_rtp_engine::x3::{build_tls_client_config, X3Clock, X3Config, X3DeliveryTask};
use siphon_rtp_li::inbound::InboundHeader;
use siphon_rtp_li::HEADER_LEN;
use siphon_rtp_proto::Xid;
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, timeout_at};

pub const SHORT: Duration = Duration::from_secs(5);

/// The interception task identifier under test (fixed bytes, not provisioning data).
pub const XID_TEXT: &str = "8c292fa1-5831-46ec-86be-bd85f2083299";
/// A non-zero session correlation (TS 103 221-2 clause 6).
pub const CORRELATION_ID: u64 = 0x0102_0304_0506_0708;

/// The generated PKI: a CA that signs both ends, written out as the PEM files the engine config
/// names, plus the DER the stub server needs.
pub struct Pki {
    pub _directory: tempfile::TempDir,
    pub config: X3Config,
    pub server_certs: Vec<rustls_pki_types::CertificateDer<'static>>,
    pub server_key: rustls_pki_types::PrivateKeyDer<'static>,
    pub client_roots: rustls::RootCertStore,
}

/// Generate a CA, a server certificate for `127.0.0.1` and a client certificate, and write the
/// engine's three PEM files. Mutual TLS is the point: the Mediation Function authenticates the
/// network element by certificate, and its own certificate is signed by a private CA that the public
/// Mozilla bundle would never contain.
pub fn pki() -> Pki {
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
pub fn acceptor(pki: &Pki) -> tokio_rustls::TlsAcceptor {
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
pub struct DecodedPdu {
    pub header: InboundHeader,
    pub attributes: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Read exactly `count` PDUs off the stream, honouring the length fields rather than guessing at
/// message boundaries — the same framing a real Mediation Function does.
pub async fn read_pdus<S>(stream: &mut S, count: usize) -> Vec<DecodedPdu>
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
pub fn attribute(block: &[u8], wanted: u16) -> Option<Vec<u8>> {
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
pub fn rtp(sequence: u16) -> Vec<u8> {
    rtp_from(0xdead_beef, sequence)
}

/// [`rtp`] from the source `ssrc`, so a test with several parties can tell them apart.
pub fn rtp_from(ssrc: u32, sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&[0xd5; 160]);
    packet
}

/// The SSRC of an RTP packet.
pub fn ssrc_of(packet: &[u8]) -> u32 {
    u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]])
}

/// The RTP sequence number of a packet.
pub fn rtp_sequence(packet: &[u8]) -> u16 {
    u16::from_be_bytes([packet[2], packet[3]])
}

/// A plain `RTP/AVP` PCMU session description for one phone, with a direction attribute.
pub fn plain_sdp(address: SocketAddr, direction: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\na={direction}\r\n",
        ip = address.ip(),
        port = address.port(),
    )
}

/// The PDU's X3 sequence number (a per-connection counter).
pub fn pdu_sequence(pdu: &DecodedPdu) -> u32 {
    let value = attribute(
        &pdu.attributes,
        siphon_rtp_li::attributes::attribute_type::SEQUENCE_NUMBER,
    )
    .expect("sequence");
    u32::from_be_bytes([value[0], value[1], value[2], value[3]])
}

/// A delivery connection read one PDU at a time, keeping the bytes of the PDUs that arrived
/// together so none is lost between reads (unlike [`read_pdus`], which is for a known count).
pub struct PduStream<S> {
    stream: S,
    buffer: Vec<u8>,
}

impl<S: tokio::io::AsyncRead + Unpin> PduStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    /// The next PDU, or `None` when nothing arrives within `wait`.
    pub async fn next_within(&mut self, wait: Duration) -> Option<DecodedPdu> {
        let deadline = tokio::time::Instant::now() + wait;
        let mut chunk = [0u8; 4096];
        loop {
            if let Ok(header) = InboundHeader::parse(&self.buffer) {
                let total = header.total_len().expect("plausible total length");
                if self.buffer.len() >= total {
                    let attributes_end = header.header_length as usize;
                    let decoded = DecodedPdu {
                        attributes: self.buffer[HEADER_LEN..attributes_end].to_vec(),
                        payload: self.buffer[attributes_end..total].to_vec(),
                        header,
                    };
                    self.buffer.drain(..total);
                    return Some(decoded);
                }
            }
            let read = timeout_at(deadline, self.stream.read(&mut chunk))
                .await
                .ok()?;
            let read = read.expect("read");
            assert!(read > 0, "the delivery connection closed early");
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// The next PDU, within the shared timeout.
    pub async fn next(&mut self) -> DecodedPdu {
        self.next_within(SHORT)
            .await
            .expect("a PDU arrives on the delivery connection")
    }
}

/// Build the delivery task for `address` from `pki`.
pub fn delivery_task(
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
        connect_timeout: siphon_rtp_engine::x3::DEFAULT_CONNECT_TIMEOUT,
        tls: build_tls_client_config(&pki.config).expect("client tls config"),
    }
}

/// An interception clock the test advances by hand, so timestamps are exact and nothing in the
/// assertion path reads the host clock.
#[derive(Debug)]
pub struct ManualClock(std::sync::atomic::AtomicU64);

impl ManualClock {
    pub fn at(unix_nanos: u64) -> Self {
        Self(std::sync::atomic::AtomicU64::new(unix_nanos))
    }

    pub fn advance_millis(&self, milliseconds: u64) {
        self.0.fetch_add(
            milliseconds * 1_000_000,
            std::sync::atomic::Ordering::SeqCst,
        );
    }
}

impl X3Clock for ManualClock {
    fn unix_nanos(&self) -> u128 {
        u128::from(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}
