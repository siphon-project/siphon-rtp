//! A [`webrtc_util::Conn`] that carries DTLS records over channels, so a DTLS handshake can run on the
//! datapath's `Redirect` path instead of owning a socket.
//!
//! The engine feeds inbound DTLS datagrams (the ones the RFC 7983 demux classified `PacketClass::Dtls`
//! on a secure WebRTC endpoint) into the transport, and drains outbound DTLS records from it to send
//! to the peer via `Datapath::send`. This keeps `siphon-rtp-dtls` free of any datapath dependency —
//! the only coupling is two byte channels — and lets the handshake be driven in-memory in tests.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use webrtc_util::Conn;

/// One end of the DTLS record transport. Built by [`DtlsTransport::new`], which also hands back the
/// two channel ends the engine drives.
pub struct DtlsTransport {
    /// Inbound DTLS records from the datapath dispatcher.
    inbound: flume::Receiver<Bytes>,
    /// Outbound DTLS records for the engine to send to the peer.
    outbound: flume::Sender<Bytes>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    closed: AtomicBool,
}

/// The channel ends the engine uses to drive a [`DtlsTransport`]: push inbound DTLS datagrams into
/// `inbound`, drain outbound DTLS records from `outbound` and send each to the peer.
pub struct DtlsChannels {
    /// Push each inbound `PacketClass::Dtls` datagram here.
    pub inbound: flume::Sender<Bytes>,
    /// Drain outbound DTLS records here and send them to the peer.
    pub outbound: flume::Receiver<Bytes>,
}

impl DtlsTransport {
    /// Build a transport plus the [`DtlsChannels`] the engine drives. `local_addr` is the engine's own
    /// media endpoint; `remote_addr` is the peer's media address.
    #[must_use]
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> (Self, DtlsChannels) {
        // Bounded so a stalled handshake cannot grow an unbounded queue (the datapath drops on a full
        // channel, which for a handshake just triggers DTLS retransmission).
        let (inbound_tx, inbound_rx) = flume::bounded(64);
        let (outbound_tx, outbound_rx) = flume::bounded(64);
        let transport = Self {
            inbound: inbound_rx,
            outbound: outbound_tx,
            local_addr,
            remote_addr,
            closed: AtomicBool::new(false),
        };
        let channels = DtlsChannels {
            inbound: inbound_tx,
            outbound: outbound_rx,
        };
        (transport, channels)
    }
}

#[async_trait]
impl Conn for DtlsTransport {
    async fn connect(&self, _addr: SocketAddr) -> webrtc_util::Result<()> {
        // The transport is already "connected" to its single peer; nothing to dial.
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
        let datagram = self.inbound.recv_async().await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "dtls transport closed")
        })?;
        let len = datagram.len().min(buf.len());
        buf[..len].copy_from_slice(&datagram[..len]);
        Ok(len)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        let len = self.recv(buf).await?;
        Ok((len, self.remote_addr))
    }

    async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
        self.outbound
            .send_async(Bytes::copy_from_slice(buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "dtls transport closed")
            })?;
        Ok(buf.len())
    }

    async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> webrtc_util::Result<usize> {
        // Single peer — the target is always `remote_addr`.
        self.send(buf).await
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr)
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[tokio::test]
    async fn inbound_datagrams_are_received_in_order() {
        let (transport, channels) = DtlsTransport::new(addr(5000), addr(6000));
        channels
            .inbound
            .send(Bytes::from_static(&[0x16, 0x01]))
            .unwrap();
        channels
            .inbound
            .send(Bytes::from_static(&[0x16, 0x02]))
            .unwrap();

        let mut buf = [0u8; 16];
        let n = transport.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0x16, 0x01]);
        let n = transport.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0x16, 0x02]);
    }

    #[tokio::test]
    async fn sent_records_drain_to_the_outbound_channel() {
        let (transport, channels) = DtlsTransport::new(addr(5000), addr(6000));
        let n = transport.send(&[0x14, 0xAB, 0xCD]).await.unwrap();
        assert_eq!(n, 3);
        let record = channels.outbound.recv_async().await.unwrap();
        assert_eq!(&record[..], &[0x14, 0xAB, 0xCD]);
    }

    #[tokio::test]
    async fn recv_errors_once_the_inbound_channel_closes() {
        let (transport, channels) = DtlsTransport::new(addr(5000), addr(6000));
        drop(channels); // engine gone
        let mut buf = [0u8; 16];
        assert!(transport.recv(&mut buf).await.is_err());
    }

    #[test]
    fn addresses_are_reported() {
        let (transport, _channels) = DtlsTransport::new(addr(5000), addr(6000));
        assert_eq!(transport.local_addr().unwrap(), addr(5000));
        assert_eq!(transport.remote_addr(), Some(addr(6000)));
    }
}
