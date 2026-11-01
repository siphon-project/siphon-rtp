//! Transport listeners — the TURN front doors that feed the allocation actor.
//!
//! Three listeners, one job: turn an inbound message into a [`Message::Client`] and write the
//! actor's replies back out the transport. They share the [`ClientTransport`] reply abstraction, and
//! the two stream transports (TCP per RFC 6062, TLS via rustls) share [`handle_stream_connection`]
//! and [`turn::stream_frame_len`] — so the framing and relay logic are identical and tested once.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use siphon_rtp_stun::turn;
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
            match turn::stream_frame_len(&buffer) {
                turn::StreamFrame::Ready(len) => {
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
                turn::StreamFrame::Need => break,
                turn::StreamFrame::Invalid => {
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
