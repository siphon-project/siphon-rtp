//! Transport listeners — the TURN front doors that feed the allocation actor.
//!
//! Three listeners, one job: turn an inbound message into a [`Message::Client`] and write the
//! actor's replies back out the transport. They share the [`ClientTransport`] reply abstraction, and
//! the two stream transports (TCP per RFC 6062, TLS via rustls) share [`handle_stream_connection`]
//! and [`next_frame`] — so the framing and relay logic are identical and tested once.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use siphon_rtp_stun::{self as stun, turn};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;

use crate::manager::Message;
use crate::{ClientTransport, FiveTuple, TransportProtocol};

/// Receive buffer: TURN datagrams (STUN messages, ChannelData) sit well under the MTU.
const MAX_DATAGRAM: usize = 2048;

/// Serve TURN over UDP on `socket` until it errors. Every UDP client shares this one socket; the
/// allocation actor keys their state on the source 5-tuple and replies via the same socket.
pub(crate) async fn serve_udp(
    client_tx: flume::Sender<Message>,
    socket: UdpSocket,
) -> std::io::Result<()> {
    let socket = Arc::new(socket);
    let server = socket.local_addr()?;
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    loop {
        let (len, client) = socket.recv_from(&mut buffer).await?;
        let message = Message::Client {
            five_tuple: FiveTuple {
                client,
                server,
                transport: TransportProtocol::Udp,
            },
            transport: ClientTransport::Udp {
                socket: socket.clone(),
                peer: client,
            },
            datagram: Bytes::copy_from_slice(&buffer[..len]),
        };
        if client_tx.send_async(message).await.is_err() {
            return Ok(()); // the actor is gone
        }
    }
}

/// Serve TURN over TCP (RFC 6062 client↔server framing) until the listener errors.
pub(crate) async fn serve_tcp(
    client_tx: flume::Sender<Message>,
    listener: TcpListener,
) -> std::io::Result<()> {
    loop {
        let (stream, client) = listener.accept().await?;
        let server = stream.local_addr()?;
        let _ = stream.set_nodelay(true);
        let client_tx = client_tx.clone();
        tokio::spawn(async move {
            handle_stream_connection(client_tx, stream, client, server, TransportProtocol::Tcp)
                .await;
        });
    }
}

/// Serve TURN over TLS (`turns:`) until the listener errors. Each accepted TCP connection completes a
/// rustls handshake before the same stream framing as TCP runs over the encrypted stream.
pub(crate) async fn serve_tls(
    client_tx: flume::Sender<Message>,
    listener: TcpListener,
    acceptor: TlsAcceptor,
) -> std::io::Result<()> {
    loop {
        let (stream, client) = listener.accept().await?;
        let server = stream.local_addr()?;
        let _ = stream.set_nodelay(true);
        let acceptor = acceptor.clone();
        let client_tx = client_tx.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls) => {
                    handle_stream_connection(
                        client_tx,
                        tls,
                        client,
                        server,
                        TransportProtocol::Tls,
                    )
                    .await;
                }
                Err(error) => tracing::debug!(%client, %error, "TURN TLS handshake failed"),
            }
        });
    }
}

/// What [`next_frame`] found at the head of a stream buffer.
enum FramePeek {
    /// Not enough bytes yet for a complete message.
    Need,
    /// A complete message of this many bytes is buffered.
    Ready(usize),
    /// A protocol desync (bad STUN cookie / unaligned length / non-STUN-non-ChannelData) — the
    /// connection is hostile or broken and must be closed.
    Invalid,
}

/// Determine the next message boundary in a TURN stream (RFC 5766 §11.5 / RFC 6062): a STUN message
/// is its 20-byte header plus its declared (4-aligned) length; a ChannelData message is its 4-byte
/// header plus payload, padded to a 4-byte boundary. Never reads past `buffer`.
fn next_frame(buffer: &[u8]) -> FramePeek {
    let Some(&first) = buffer.first() else {
        return FramePeek::Need;
    };
    if turn::is_channel_data(first) {
        if buffer.len() < 4 {
            return FramePeek::Need;
        }
        let length = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
        let total = turn::channel_data_frame_len(length, true);
        if buffer.len() < total {
            return FramePeek::Need;
        }
        FramePeek::Ready(total)
    } else if first & 0xC0 == 0 {
        // STUN: top two bits 00.
        if buffer.len() < 20 {
            return FramePeek::Need;
        }
        let cookie = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        let length = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
        if cookie != stun::MAGIC_COOKIE || !length.is_multiple_of(4) {
            return FramePeek::Invalid;
        }
        let total = 20 + length;
        if buffer.len() < total {
            return FramePeek::Need;
        }
        FramePeek::Ready(total)
    } else {
        // Top two bits 10/11: neither a STUN message nor ChannelData.
        FramePeek::Invalid
    }
}

/// Drive one stream (TCP or TLS) connection: frame inbound messages to the actor and write its
/// replies out a per-connection writer task (never holding the write half across the read loop).
async fn handle_stream_connection<S>(
    client_tx: flume::Sender<Message>,
    stream: S,
    client: SocketAddr,
    server: SocketAddr,
    transport_protocol: TransportProtocol,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (writer_tx, writer_rx) = flume::bounded::<Bytes>(256);
    let writer_task = tokio::spawn(async move {
        while let Ok(bytes) = writer_rx.recv_async().await {
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });
    let transport = ClientTransport::Stream { writer: writer_tx };
    let five_tuple = FiveTuple {
        client,
        server,
        transport: transport_protocol,
    };

    let mut buffer = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    'connection: loop {
        loop {
            match next_frame(&buffer) {
                FramePeek::Ready(len) => {
                    let datagram = Bytes::copy_from_slice(&buffer[..len]);
                    buffer.drain(..len);
                    let message = Message::Client {
                        five_tuple,
                        transport: transport.clone(),
                        datagram,
                    };
                    if client_tx.send_async(message).await.is_err() {
                        break 'connection; // actor gone
                    }
                }
                FramePeek::Need => break,
                FramePeek::Invalid => {
                    tracing::debug!(%client, "TURN stream framing desync; closing");
                    break 'connection;
                }
            }
        }
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    }
    writer_task.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_stun_and_channel_data_and_rejects_garbage() {
        // A STUN message frames by its 20-byte header + 4-aligned length.
        let stun_message = stun::binding_request(&[0u8; 12], "user", b"key");
        assert!(
            matches!(next_frame(&stun_message), FramePeek::Ready(n) if n == stun_message.len())
        );
        // Incomplete → Need.
        assert!(matches!(next_frame(&stun_message[..10]), FramePeek::Need));

        // A ChannelData message frames by its padded length (RFC 5766 §11.5).
        let channel_data = turn::encode_channel_data(0x4001, b"odd", true);
        assert!(
            matches!(next_frame(&channel_data), FramePeek::Ready(n) if n == channel_data.len())
        );

        // A STUN-shaped header with a bad cookie is a desync.
        let mut bad = stun_message.clone();
        bad[4] ^= 0xFF;
        assert!(matches!(next_frame(&bad), FramePeek::Invalid));
        // Top-bits 11 is neither STUN nor ChannelData.
        assert!(matches!(next_frame(&[0xC0, 0, 0, 0]), FramePeek::Invalid));
    }

    #[test]
    fn two_back_to_back_frames_are_split() {
        let a = stun::binding_request(&[1u8; 12], "a", b"k");
        let b = turn::encode_channel_data(0x4002, b"data", true);
        let mut buffer = a.clone();
        buffer.extend_from_slice(&b);
        let FramePeek::Ready(first) = next_frame(&buffer) else {
            panic!("first frame");
        };
        assert_eq!(first, a.len());
        let FramePeek::Ready(second) = next_frame(&buffer[first..]) else {
            panic!("second frame");
        };
        assert_eq!(second, b.len());
    }
}
