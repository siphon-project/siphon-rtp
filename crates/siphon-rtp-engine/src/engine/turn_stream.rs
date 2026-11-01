//! The TCP or TLS stream under a TURN allocation (RFC 8656 §3.1).
//!
//! A UDP allocation shares the media endpoint's socket; a stream allocation cannot, so the engine
//! owns one connection per allocation. Two pump tasks sit on it, split the way the in-tree server's
//! connection handler splits them, so a slow write never blocks a read:
//!
//! - the **reader** frames the byte stream with [`turn::stream_frame_len`] (STUN messages and
//!   ChannelData back to back, RFC 8656 §12.5). Allocation responses go to a bounded queue the
//!   allocation's owner drains; ChannelData and Data indications go to the datapath through
//!   [`Datapath::ingest_relayed`], where they pass the same gates as a datagram off the socket;
//! - the **writer** drains a bounded queue of already-framed bytes (the allocation's own requests,
//!   and the datapath's ChannelData through [`siphon_rtp_datapath::TurnCarrier::Stream`]).
//!
//! The queues are bounded and drop on full: late media is worthless, and a stalled server must not
//! grow memory. End of stream or an error sets a flag the owner turns into
//! `TurnClient::on_transport_closed`, which clears the relay.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use siphon_rtp_datapath::{Datapath, EndpointId, TurnCarrier};
use siphon_rtp_stun::turn::{self, StreamFrame};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use super::turn_relay::{TurnServer, TurnTransport};

/// Depth of the queue of framed bytes waiting to be written. A request is one message and media is
/// 50 packets a second, so this is several seconds of slack before packets are shed.
const WRITE_QUEUE_DEPTH: usize = 256;

/// Depth of the queue of allocation responses waiting for the owner. At most one request is in
/// flight, so a handful is plenty; drop-on-full costs a retry at worst.
const RESPONSE_QUEUE_DEPTH: usize = 64;

/// How long a graceful close waits for queued bytes (the allocation delete) to be written.
const CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

/// The cheaply clonable part of a stream allocation: what the allocation's owner and the datapath
/// carrier need, without the task handles.
#[derive(Clone)]
pub(super) struct TurnStreamHandle {
    writer: flume::Sender<Bytes>,
    responses: flume::Receiver<Bytes>,
    closed: Arc<AtomicBool>,
    relay_active: Arc<AtomicBool>,
}

impl TurnStreamHandle {
    /// Queue one already-framed STUN message for writing. `false` when the queue is full or the
    /// stream is gone; the request is then retried (or the allocation fails) by the client's
    /// own timer.
    pub(super) fn send(&self, message: &[u8]) -> bool {
        self.writer
            .try_send(Bytes::copy_from_slice(message))
            .is_ok()
    }

    /// The datapath carrier that frames and queues relayed traffic on this stream.
    pub(super) fn carrier(&self) -> TurnCarrier {
        TurnCarrier::Stream(self.writer.clone())
    }

    /// Every allocation response received since the last call.
    pub(super) fn drain_responses(&self) -> Vec<Bytes> {
        self.responses.try_iter().collect()
    }

    /// Whether the stream ended (end of stream, a read or write error, or a framing desync).
    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Let relayed data reach the datapath. Called once the allocation has won and its relay is
    /// installed: until then, and for a losing server, ChannelData would be attributed with another
    /// allocation's channels, so it is dropped.
    pub(super) fn activate_relay(&self) {
        self.relay_active.store(true, Ordering::Release);
    }
}

/// One live stream and its pump tasks. Dropping it aborts them; [`Self::close`] flushes first.
pub(super) struct TurnStream {
    handle: TurnStreamHandle,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    writer_task: Option<JoinHandle<()>>,
    reader_task: Option<JoinHandle<()>>,
}

impl TurnStream {
    /// Connect to `server` over TCP, and run TLS over it for a `turns:` server.
    ///
    /// # Errors
    /// The connect, the TLS handshake, or an invalid server name failed, or `server` is not a
    /// stream transport.
    pub(super) async fn connect<D>(
        server: TurnServer,
        tls: Arc<rustls::ClientConfig>,
        datapath: D,
        endpoint: EndpointId,
    ) -> io::Result<Self>
    where
        D: Datapath + Clone + Send + 'static,
    {
        let tcp = TcpStream::connect(server.address).await?;
        // A request and its answer are tiny and latency-bound; Nagle would hold them back.
        tcp.set_nodelay(true)?;
        match server.transport {
            TurnTransport::Tcp => Ok(Self::spawn(tcp, datapath, endpoint)),
            TurnTransport::Tls { server_name } => {
                let name = rustls_pki_types::ServerName::try_from(server_name)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                let stream = tokio_rustls::TlsConnector::from(tls)
                    .connect(name, tcp)
                    .await?;
                Ok(Self::spawn(stream, datapath, endpoint))
            }
            TurnTransport::Udp => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a UDP TURN server has no stream",
            )),
        }
    }

    /// Start the reader and writer over an established stream.
    pub(super) fn spawn<S, D>(stream: S, datapath: D, endpoint: EndpointId) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        D: Datapath + Clone + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(stream);
        let (writer_tx, writer_rx) = flume::bounded::<Bytes>(WRITE_QUEUE_DEPTH);
        let (response_tx, response_rx) = flume::bounded::<Bytes>(RESPONSE_QUEUE_DEPTH);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let handle = TurnStreamHandle {
            writer: writer_tx,
            responses: response_rx,
            closed: Arc::new(AtomicBool::new(false)),
            relay_active: Arc::new(AtomicBool::new(false)),
        };
        let writer_task = tokio::spawn(write_frames(
            writer,
            writer_rx,
            shutdown_rx,
            handle.closed.clone(),
        ));
        let reader_task = tokio::spawn(read_frames(
            reader,
            response_tx,
            handle.closed.clone(),
            handle.relay_active.clone(),
            datapath,
            endpoint,
        ));
        Self {
            handle,
            shutdown: Some(shutdown_tx),
            writer_task: Some(writer_task),
            reader_task: Some(reader_task),
        }
    }

    /// The clonable view of this stream.
    pub(super) fn handle(&self) -> &TurnStreamHandle {
        &self.handle
    }

    /// Close gracefully: write what is queued (the allocation delete), then end the stream (a TLS
    /// `close_notify`, then the TCP FIN) and stop the reader.
    pub(super) async fn close(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(writer) = self.writer_task.take() {
            // The abort-on-timeout is the handle's own drop below; a stuck peer cannot hold a
            // release past the flush window.
            let _ = tokio::time::timeout(CLOSE_FLUSH_TIMEOUT, writer).await;
        }
        if let Some(reader) = self.reader_task.take() {
            reader.abort();
        }
    }
}

impl Drop for TurnStream {
    fn drop(&mut self) {
        if let Some(writer) = self.writer_task.take() {
            writer.abort();
        }
        if let Some(reader) = self.reader_task.take() {
            reader.abort();
        }
    }
}

/// Whether a STUN message is a Data indication (RFC 8656 §11.4): peer data, not an allocation
/// response.
fn is_data_indication(message: &[u8]) -> bool {
    let expected = turn::message_type(turn::METHOD_DATA, turn::CLASS_INDICATION).to_be_bytes();
    message.len() >= 2 && message[..2] == expected
}

/// Read framed messages off the stream until it ends.
async fn read_frames<R, D>(
    mut reader: R,
    responses: flume::Sender<Bytes>,
    closed: Arc<AtomicBool>,
    relay_active: Arc<AtomicBool>,
    datapath: D,
    endpoint: EndpointId,
) where
    R: AsyncRead + Unpin,
    D: Datapath + Clone + Send + 'static,
{
    let mut buffer: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        loop {
            match turn::stream_frame_len(&buffer) {
                StreamFrame::Ready(length) => {
                    let frame: Vec<u8> = buffer.drain(..length).collect();
                    if turn::is_channel_data(frame[0]) || is_data_indication(&frame) {
                        if relay_active.load(Ordering::Acquire) {
                            datapath.ingest_relayed(endpoint, &frame).await;
                        }
                    } else if responses.try_send(Bytes::from(frame)).is_err() {
                        tracing::debug!(
                            target: "siphon_rtp::media",
                            ?endpoint,
                            "TURN stream response queue full — dropped"
                        );
                    }
                }
                StreamFrame::Need => break,
                StreamFrame::Invalid => {
                    tracing::warn!(
                        target: "siphon_rtp::media",
                        ?endpoint,
                        "TURN stream framing desync — closing"
                    );
                    closed.store(true, Ordering::Release);
                    return;
                }
            }
        }
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => {
                closed.store(true, Ordering::Release);
                return;
            }
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    }
}

/// Write queued frames until told to shut down or the queue's senders are gone.
async fn write_frames<W>(
    mut writer: W,
    queue: flume::Receiver<Bytes>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
    closed: Arc<AtomicBool>,
) where
    W: AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            // Queued bytes first, so a delete queued just before the shutdown signal is written.
            biased;
            frame = queue.recv_async() => {
                let Ok(bytes) = frame else { break };
                if writer.write_all(&bytes).await.is_err() {
                    closed.store(true, Ordering::Release);
                    return;
                }
            }
            _ = &mut shutdown => {
                while let Ok(bytes) = queue.try_recv() {
                    if writer.write_all(&bytes).await.is_err() {
                        closed.store(true, Ordering::Release);
                        return;
                    }
                }
                break;
            }
        }
    }
    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_datapath::udp::UdpLoopbackDatapath;

    fn binding_response(id: u8) -> Vec<u8> {
        siphon_rtp_stun::MessageBuilder::new(
            turn::message_type(turn::METHOD_BINDING, turn::CLASS_SUCCESS),
            &[id; 12],
        )
        .finish(None, false)
    }

    /// Collect `count` allocation responses, in arrival order.
    async fn responses(handle: &TurnStreamHandle, count: usize) -> Vec<Bytes> {
        let mut collected = Vec::new();
        for _ in 0..400 {
            collected.extend(handle.drain_responses());
            if collected.len() >= count {
                return collected;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("only {} of {count} responses arrived", collected.len());
    }

    #[tokio::test]
    async fn messages_split_across_reads_and_padded_channel_data_are_framed() {
        let (client, mut server) = tokio::io::duplex(64);
        let stream = TurnStream::spawn(client, UdpLoopbackDatapath::new(), EndpointId(1));
        // A ChannelData message padded to four bytes, then two STUN messages, written one byte at a
        // time: the framer must reassemble across reads and skip exactly the padding.
        let mut wire = turn::encode_channel_data(0x4001, b"odd", true);
        wire.extend_from_slice(&binding_response(1));
        wire.extend_from_slice(&binding_response(2));
        for byte in wire {
            server.write_all(&[byte]).await.expect("write");
        }
        let received = responses(stream.handle(), 2).await;
        assert_eq!(received[0].as_ref(), binding_response(1).as_slice());
        assert_eq!(received[1].as_ref(), binding_response(2).as_slice());
        assert!(!stream.handle().is_closed());
    }

    #[tokio::test]
    async fn the_end_of_the_stream_marks_it_closed() {
        let (client, server) = tokio::io::duplex(64);
        let stream = TurnStream::spawn(client, UdpLoopbackDatapath::new(), EndpointId(1));
        drop(server);
        for _ in 0..200 {
            if stream.handle().is_closed() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the closed stream was not noticed");
    }

    #[tokio::test]
    async fn a_framing_desync_closes_the_stream() {
        let (client, mut server) = tokio::io::duplex(64);
        let stream = TurnStream::spawn(client, UdpLoopbackDatapath::new(), EndpointId(1));
        server.write_all(&[0xC0, 0, 0, 0]).await.expect("write");
        for _ in 0..200 {
            if stream.handle().is_closed() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("a desynchronised stream must be closed");
    }

    #[tokio::test]
    async fn close_writes_what_is_queued_before_ending_the_stream() {
        let (client, mut server) = tokio::io::duplex(1024);
        let stream = TurnStream::spawn(client, UdpLoopbackDatapath::new(), EndpointId(1));
        let message = binding_response(9);
        assert!(stream.handle().send(&message));
        stream.close().await;
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.expect("read");
        assert_eq!(received, message, "the queued message is flushed, then EOF");
    }

    #[tokio::test]
    async fn a_full_write_queue_sheds_instead_of_growing() {
        let (client, _server) = tokio::io::duplex(1);
        let stream = TurnStream::spawn(client, UdpLoopbackDatapath::new(), EndpointId(1));
        let message = binding_response(3);
        let accepted = (0..WRITE_QUEUE_DEPTH * 4)
            .filter(|_| stream.handle().send(&message))
            .count();
        // The writer drains at most one message into the 1-byte pipe, then blocks.
        assert!(accepted <= WRITE_QUEUE_DEPTH + 2, "accepted {accepted}");
    }
}
