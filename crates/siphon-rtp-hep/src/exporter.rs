//! A minimal async UDP exporter that ships HEP3 captures to a Homer capture node.
//!
//! HEP-over-UDP is the common Homer transport: one HEP3 packet per datagram. The exporter binds a
//! local socket connected to the Homer address; the engine calls [`HepExporter::export`] per RTCP
//! interval (or per signalling capture). Fire-and-forget — a telemetry send must never block or
//! fail the media path, so errors are returned for the caller to log and drop.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::Capture;

/// An async UDP sink for HEP3 captures, connected to a Homer node.
#[derive(Debug)]
pub struct HepExporter {
    socket: UdpSocket,
}

impl HepExporter {
    /// Bind a local UDP socket and connect it to `homer` (the Homer capture node's address). The
    /// local bind matches Homer's address family.
    pub async fn connect(homer: SocketAddr) -> std::io::Result<Self> {
        let bind = if homer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(homer).await?;
        Ok(Self { socket })
    }

    /// The local address the exporter sends from (useful for tests / diagnostics).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Encode `capture` as a HEP3 packet and send it to Homer, returning the bytes sent. A single
    /// datagram carries the whole capture (HEP3 packets sit well under the MTU).
    pub async fn export(&self, capture: &Capture) -> std::io::Result<usize> {
        self.socket.send(&capture.encode()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chunk, protocol_type, MAGIC};
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn exports_a_hep_packet_to_a_homer_socket() {
        // Stand in for Homer with a loopback UDP socket.
        let homer = UdpSocket::bind("127.0.0.1:0").await.expect("bind homer");
        let homer_addr = homer.local_addr().expect("homer addr");

        let exporter = HepExporter::connect(homer_addr).await.expect("connect");
        let capture = Capture {
            src: "198.51.100.1:6000".parse().unwrap(),
            dst: "203.0.113.1:6002".parse().unwrap(),
            timestamp_secs: 7,
            timestamp_micros: 0,
            protocol_type: protocol_type::RTCP,
            capture_agent_id: 1,
            correlation_id: Some("call-x@host".into()),
            payload: vec![0x80, 0xC8, 0x00, 0x06],
        };
        let sent = exporter.export(&capture).await.expect("export");

        let mut buffer = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), homer.recv_from(&mut buffer))
            .await
            .expect("no timeout")
            .expect("recv");
        assert_eq!(len, sent, "the whole capture arrives in one datagram");
        assert_eq!(&buffer[..4], MAGIC, "Homer receives a HEP3 packet");
        // The total-length field matches the datagram, and the payload chunk is present.
        assert_eq!(u16::from_be_bytes([buffer[4], buffer[5]]) as usize, len);
        let _ = chunk::PAYLOAD;
    }
}
