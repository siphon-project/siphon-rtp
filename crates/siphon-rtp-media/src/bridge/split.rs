//! The **split bridge** transport: both legs of a call on one duplex stereo WebSocket.
//!
//! The uplink is a tee's ([`super::tee`]): each leg's decoded PCM feeds a shared stereo
//! [`super::tee::TeeMixer`] and its wire frames go out as binary frames. This module adds the
//! downlink. The server's stereo L16 is deinterleaved here, on the transport task, into two **playout
//! queues**, one per party (channel 0 the offerer, channel 1 the answerer), which the media actor
//! reads on its own 20 ms clock ([`PlayoutReader`]). The actor takes one chunk per party per tick and
//! plays silence when a queue is empty, so the two parties never wait on each other and a channel the
//! server leaves quiet is silence rather than a stall.
//!
//! **Queues are bounded and drop the oldest.** A server answers faster than real time in bursts (a
//! synthesised sentence arrives whole), so the bound is [`PLAYOUT_BOUND_MS`] per party: long enough to
//! absorb a burst, short enough that a stalled actor cannot grow a queue without limit and that audio
//! never plays more than that late. Past it the oldest chunk is dropped and counted: late audio is
//! worth less than current audio. The chunk buffers are recycled through a return queue, so a
//! steady-state tick allocates nothing.

use bytes::Bytes;
use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::bridge::protocol::ControlMessage;
use crate::bridge::ws::{send_within, BridgeError};

/// How much audio one playout chunk carries, in milliseconds: the actor's tick.
pub const PLAYOUT_CHUNK_MS: usize = 20;

/// The most audio each party's playout queue holds, in milliseconds.
pub const PLAYOUT_BOUND_MS: usize = 1_000;

/// Chunks a playout queue holds ([`PLAYOUT_BOUND_MS`] of them).
pub const PLAYOUT_CHUNKS: usize = PLAYOUT_BOUND_MS / PLAYOUT_CHUNK_MS;

/// Samples in one playout chunk at `sample_rate_hz`.
#[must_use]
pub fn playout_chunk_samples(sample_rate_hz: u32) -> usize {
    sample_rate_hz as usize / 1000 * PLAYOUT_CHUNK_MS
}

/// Why a split's transport ended, reported once when [`run_ws_split`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitEndReason {
    /// The server closed the connection (or the stream just ended).
    ServerClosed,
    /// The server sent a `stop` control frame.
    ServerStopped,
    /// The call side went away: every uplink sink was dropped.
    CallEnded,
}

/// One party's end of the playout queue, read by the media actor.
#[derive(Clone)]
pub struct PlayoutReader {
    chunks: flume::Receiver<Vec<i16>>,
    spare: flume::Sender<Vec<i16>>,
}

impl PlayoutReader {
    /// The oldest queued chunk, or `None` when the queue is empty or the writer is gone (the party
    /// then hears silence). Hand the buffer back through [`Self::recycle`] once it has been read.
    #[must_use]
    pub fn pop(&self) -> Option<Vec<i16>> {
        self.chunks.try_recv().ok()
    }

    /// Return a buffer taken from [`Self::pop`], so the writer fills it again instead of allocating.
    pub fn recycle(&self, buffer: Vec<i16>) {
        // A full spare queue means the buffer is surplus: drop it.
        let _ = self.spare.try_send(buffer);
    }

    /// Chunks waiting.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.chunks.len()
    }

    /// Drop everything queued. The queue outlives its writer, so a transport that ended (or was
    /// aborted) leaves up to [`PLAYOUT_BOUND_MS`] of the bot's audio here to play out unless the
    /// engine clears it.
    pub fn flush(&self) {
        while self.chunks.try_recv().is_ok() {}
    }
}

/// One party's queue, writer side.
struct PlayoutQueue {
    chunks: flume::Sender<Vec<i16>>,
    /// A second receiver on `chunks`, used only to drop the oldest chunk when the queue is full.
    oldest: flume::Receiver<Vec<i16>>,
    spare: flume::Receiver<Vec<i16>>,
    /// Samples of the party waiting to fill a chunk.
    pending: Vec<i16>,
    dropped: u64,
}

impl PlayoutQueue {
    fn new(chunk_samples: usize) -> (Self, PlayoutReader) {
        let (chunks, reader_chunks) = flume::bounded(PLAYOUT_CHUNKS);
        let (spare_tx, spare) = flume::bounded(PLAYOUT_CHUNKS + 2);
        let queue = Self {
            oldest: reader_chunks.clone(),
            chunks,
            spare,
            pending: Vec::with_capacity(chunk_samples),
            dropped: 0,
        };
        let reader = PlayoutReader {
            chunks: reader_chunks,
            spare: spare_tx,
        };
        (queue, reader)
    }

    /// Queue the full chunk waiting in `pending`, dropping the oldest queued one if the queue is full.
    fn emit(&mut self, chunk_samples: usize) {
        let mut buffer = self
            .spare
            .try_recv()
            .unwrap_or_else(|_| Vec::with_capacity(chunk_samples));
        buffer.clear();
        buffer.extend_from_slice(&self.pending[..chunk_samples]);
        self.pending.drain(..chunk_samples);
        match self.chunks.try_send(buffer) {
            Ok(()) => {}
            Err(flume::TrySendError::Full(buffer)) => {
                if self.oldest.try_recv().is_ok() {
                    self.dropped += 1;
                }
                if self.chunks.try_send(buffer).is_err() {
                    self.dropped += 1;
                }
            }
            // The reader is gone: nobody is playing this party any more.
            Err(flume::TrySendError::Disconnected(_)) => {}
        }
    }

    fn flush(&mut self) {
        self.pending.clear();
        while self.oldest.try_recv().is_ok() {}
    }
}

/// The server's downlink: stereo L16 in, two playout queues out. Owned by the transport task.
pub struct PlayoutWriter {
    queues: [PlayoutQueue; 2],
    chunk_samples: usize,
    /// A trailing odd byte of the last frame, awaiting its partner.
    carry_byte: Option<u8>,
    /// A decoded channel-0 sample awaiting its channel-1 partner (a frame ending mid-pair).
    carry_left: Option<i16>,
}

/// The two playout queues of a split at `sample_rate_hz`: the writer for the transport and one
/// reader per party (the offerer's first).
#[must_use]
pub fn playout(sample_rate_hz: u32) -> (PlayoutWriter, [PlayoutReader; 2]) {
    let chunk_samples = playout_chunk_samples(sample_rate_hz).max(1);
    let (first, first_reader) = PlayoutQueue::new(chunk_samples);
    let (second, second_reader) = PlayoutQueue::new(chunk_samples);
    (
        PlayoutWriter {
            queues: [first, second],
            chunk_samples,
            carry_byte: None,
            carry_left: None,
        },
        [first_reader, second_reader],
    )
}

impl PlayoutWriter {
    /// Take one binary frame of interleaved little-endian L16 stereo. A frame may end anywhere: a
    /// half sample or a lone left sample waits for the next one.
    pub fn push_wire(&mut self, bytes: &[u8]) {
        let mut bytes = bytes;
        if let Some(low) = self.carry_byte.take() {
            let Some((&high, rest)) = bytes.split_first() else {
                self.carry_byte = Some(low);
                return;
            };
            self.push_sample(i16::from_le_bytes([low, high]));
            bytes = rest;
        }
        let (pairs, tail) = bytes.as_chunks::<2>();
        for pair in pairs {
            self.push_sample(i16::from_le_bytes(*pair));
        }
        self.carry_byte = tail.first().copied();
    }

    fn push_sample(&mut self, sample: i16) {
        match self.carry_left.take() {
            None => self.carry_left = Some(sample),
            Some(left) => {
                self.queues[0].pending.push(left);
                self.queues[1].pending.push(sample);
                if self.queues[0].pending.len() >= self.chunk_samples {
                    let chunk_samples = self.chunk_samples;
                    for queue in &mut self.queues {
                        queue.emit(chunk_samples);
                    }
                }
            }
        }
    }

    /// Drop everything queued and half-assembled (the server's `clear`: a barge-in).
    pub fn flush(&mut self) {
        for queue in &mut self.queues {
            queue.flush();
        }
        self.carry_byte = None;
        self.carry_left = None;
    }

    /// Chunks dropped because a queue was full (the party's side of the bot ran ahead of playout).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.queues[0].dropped + self.queues[1].dropped
    }
}

/// Run a split's transport until the server closes, sends `stop`, or the call side goes away: send
/// `start`, write each assembled uplink frame as a binary frame (handing its buffer back through
/// `recycle`), and feed every inbound binary frame to `downlink`. A `clear` control frame flushes the
/// playout queues; other control frames have nothing to act on.
///
/// Every write is bounded by [`crate::bridge::WS_WRITE_TIMEOUT`]. Generic over the socket IO so it
/// tests over an in-memory duplex.
pub async fn run_ws_split<S>(
    socket: WebSocketStream<S>,
    start: ControlMessage,
    frames: flume::Receiver<Vec<u8>>,
    recycle: flume::Sender<Vec<u8>>,
    mut downlink: PlayoutWriter,
) -> Result<SplitEndReason, BridgeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let outcome = drive_ws_split(socket, start, frames, recycle, &mut downlink).await;
    // However the stream ended, what the bot had sent and the actor had not yet played goes with it,
    // before the end is reported: queued audio outlives its writer, and up to a second of a bot that
    // is gone would otherwise play on into a call the controller has been told is silent.
    downlink.flush();
    outcome
}

async fn drive_ws_split<S>(
    socket: WebSocketStream<S>,
    start: ControlMessage,
    frames: flume::Receiver<Vec<u8>>,
    recycle: flume::Sender<Vec<u8>>,
    downlink: &mut PlayoutWriter,
) -> Result<SplitEndReason, BridgeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut sink, mut stream) = socket.split();
    send_within(&mut sink, Message::text(start.to_json()?)).await?;

    let reason = loop {
        tokio::select! {
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Binary(bytes))) => downlink.push_wire(&bytes),
                Some(Ok(Message::Text(text))) => match ControlMessage::from_json(text.as_str()) {
                    Ok(ControlMessage::Stop(_)) => break SplitEndReason::ServerStopped,
                    Ok(ControlMessage::Clear(_)) => downlink.flush(),
                    Ok(_) => {}
                    Err(error) => tracing::debug!(%error, "ws split ignoring malformed control frame"),
                },
                Some(Ok(Message::Close(_))) | None => break SplitEndReason::ServerClosed,
                Some(Ok(_)) => {} // ping / pong: handled by tungstenite
                Some(Err(error)) => return Err(error.into()),
            },
            received = frames.recv_async() => match received {
                Ok(frame) => {
                    let result =
                        send_within(&mut sink, Message::binary(Bytes::copy_from_slice(&frame))).await;
                    let _ = recycle.send(frame);
                    result?;
                }
                Err(_) => break SplitEndReason::CallEnded,
            },
        }
    };
    let _ = send_within(&mut sink, Message::Close(None)).await;
    Ok(reason)
}

/// Interleave two mono channels into stereo little-endian L16 bytes, as the server sends them.
#[cfg(test)]
fn interleave(left: &[i16], right: &[i16]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (l, r) in left.iter().zip(right) {
        bytes.extend_from_slice(&l.to_le_bytes());
        bytes.extend_from_slice(&r.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::l16_le_to_pcm;
    use crate::bridge::protocol::{
        ClearData, Direction, Encoding, Endianness, MediaFormat, StopData,
    };
    use crate::bridge::tee::{plan_ws_tee, start_message};
    use futures_util::SinkExt;
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::protocol::Role;

    fn drain(reader: &PlayoutReader) -> Vec<i16> {
        let mut samples = Vec::new();
        while let Some(chunk) = reader.pop() {
            samples.extend_from_slice(&chunk);
            reader.recycle(chunk);
        }
        samples
    }

    #[test]
    fn a_stereo_frame_is_deinterleaved_into_the_two_party_queues() {
        let (mut writer, [first, second]) = playout(8_000);
        let left = vec![100i16; 160];
        let right = vec![-200i16; 160];
        writer.push_wire(&interleave(&left, &right));
        assert_eq!(drain(&first), left, "channel 0 is the offerer's");
        assert_eq!(drain(&second), right, "channel 1 is the answerer's");
    }

    #[test]
    fn a_frame_may_end_mid_sample_or_mid_pair_and_nothing_shifts() {
        let (mut writer, [first, second]) = playout(8_000);
        let left: Vec<i16> = (0..160).map(|n| n as i16 + 1).collect();
        let right: Vec<i16> = (0..160).map(|n| -(n as i16) - 1).collect();
        let bytes = interleave(&left, &right);
        // Odd split points: inside a sample, and between a left and its right.
        for piece in [&bytes[..3], &bytes[3..4], &bytes[4..5], &bytes[5..]] {
            writer.push_wire(piece);
        }
        assert_eq!(drain(&first), left);
        assert_eq!(drain(&second), right);
    }

    #[test]
    fn a_partial_chunk_waits_and_a_whole_one_is_released() {
        let (mut writer, [first, _second]) = playout(16_000);
        let chunk = playout_chunk_samples(16_000);
        assert_eq!(chunk, 320);
        writer.push_wire(&interleave(&vec![1i16; chunk - 1], &vec![2i16; chunk - 1]));
        assert_eq!(first.queued(), 0, "less than 20 ms is not a chunk yet");
        writer.push_wire(&interleave(&[1i16], &[2i16]));
        assert_eq!(first.queued(), 1);
    }

    #[test]
    fn a_full_queue_drops_the_oldest_chunk_and_counts_it() {
        let (mut writer, [first, second]) = playout(8_000);
        let total = PLAYOUT_CHUNKS + 5;
        for index in 0..total {
            let value = index as i16;
            writer.push_wire(&interleave(&vec![value; 160], &vec![-value; 160]));
        }
        assert_eq!(first.queued(), PLAYOUT_CHUNKS, "bounded at one second");
        assert_eq!(second.queued(), PLAYOUT_CHUNKS);
        assert_eq!(writer.dropped(), 10, "five oldest chunks of each party");
        let oldest = first.pop().expect("a chunk");
        assert_eq!(oldest[0], 5, "the newest audio is kept");
    }

    #[test]
    fn a_flush_drops_everything_queued_and_half_assembled() {
        let (mut writer, [first, second]) = playout(8_000);
        writer.push_wire(&interleave(&vec![9i16; 200], &vec![9i16; 200]));
        assert_eq!(first.queued(), 1);
        writer.flush();
        assert_eq!(first.queued() + second.queued(), 0);
        writer.push_wire(&interleave(&vec![3i16; 160], &vec![3i16; 160]));
        assert_eq!(
            drain(&first),
            vec![3i16; 160],
            "the 40 samples left over from before the flush are gone"
        );
    }

    #[test]
    fn a_recycled_buffer_is_the_one_the_writer_fills_next() {
        let (mut writer, [first, _second]) = playout(8_000);
        writer.push_wire(&interleave(&[1i16; 160], &[1i16; 160]));
        let chunk = first.pop().expect("a chunk");
        let address = chunk.as_ptr();
        first.recycle(chunk);
        writer.push_wire(&interleave(&[2i16; 160], &[2i16; 160]));
        let again = first.pop().expect("a chunk");
        assert_eq!(again.as_ptr(), address, "no new allocation");
        assert_eq!(again[0], 2);
    }

    #[test]
    fn a_reader_can_flush_what_the_writer_left_behind() {
        let (mut writer, [first, second]) = playout(8_000);
        writer.push_wire(&interleave(&[1i16; 480], &[2i16; 480]));
        drop(writer);
        assert_eq!((first.queued(), second.queued()), (3, 3));
        first.flush();
        second.flush();
        assert_eq!((first.queued(), second.queued()), (0, 0));
    }

    #[test]
    fn a_reader_that_is_gone_does_not_stall_or_panic_the_writer() {
        let (mut writer, [first, second]) = playout(8_000);
        drop(first);
        drop(second);
        for _ in 0..(PLAYOUT_CHUNKS * 2) {
            writer.push_wire(&interleave(&[1i16; 160], &[1i16; 160]));
        }
    }

    fn format() -> MediaFormat {
        MediaFormat {
            encoding: Encoding::L16,
            sample_rate: 8_000,
            channels: 2,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime: 20,
        }
    }

    async fn socket_pair() -> (
        WebSocketStream<tokio::io::DuplexStream>,
        WebSocketStream<tokio::io::DuplexStream>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = WebSocketStream::from_raw_socket(server_io, Role::Server, None).await;
        let client = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;
        (client, server)
    }

    #[tokio::test]
    async fn the_transport_announces_a_duplex_stereo_stream_then_moves_audio_both_ways() {
        let (client, mut server) = socket_pair().await;
        let plan = plan_ws_tee(format(), true, false);
        let start = start_message(
            "split-1",
            "call-1",
            plan.format,
            plan.tracks.clone(),
            Direction::Duplex,
        );
        let (writer, [first, second]) = playout(8_000);
        let task = tokio::spawn(run_ws_split(
            client,
            start,
            plan.frames.clone(),
            plan.recycle.clone(),
            writer,
        ));

        let announced = server.next().await.expect("frame").expect("ok");
        let Message::Text(text) = announced else {
            panic!("start is a text frame");
        };
        let ControlMessage::Start(data) = ControlMessage::from_json(text.as_str()).expect("json")
        else {
            panic!("a start message");
        };
        assert_eq!(data.direction, Direction::Duplex);
        assert_eq!(data.media.channels, 2);

        // Downlink: the server's stereo lands in the two queues.
        server
            .send(Message::binary(interleave(&[7i16; 160], &[-7i16; 160])))
            .await
            .expect("server sends");
        tokio::time::timeout(Duration::from_secs(2), async {
            while first.queued() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the chunk arrives");
        assert_eq!(drain(&first), vec![7i16; 160]);
        assert_eq!(drain(&second), vec![-7i16; 160]);

        // `clear` flushes what is queued.
        server
            .send(Message::binary(interleave(&[1i16; 160], &[1i16; 160])))
            .await
            .expect("server sends");
        let clear = ControlMessage::Clear(ClearData {
            stream_id: "split-1".into(),
            play_id: None,
            reason: None,
        });
        server
            .send(Message::text(clear.to_json().expect("json")))
            .await
            .expect("clear");

        // Uplink: a stereo mixer frame goes out as one binary frame.
        {
            use crate::bridge::tee::{TeeChannel, WsTeeSink};
            use crate::fanout::MediaSink;
            let mut offerer = WsTeeSink::new(TeeChannel::Caller, plan.mixer.clone(), "split", None);
            let mut answerer =
                WsTeeSink::new(TeeChannel::Callee, plan.mixer.clone(), "split", None);
            offerer.write_pcm(&[500i16; 160]);
            answerer.write_pcm(&[-500i16; 160]);
        }
        let frame = server.next().await.expect("frame").expect("ok");
        let Message::Binary(bytes) = frame else {
            panic!("uplink is a binary frame");
        };
        let mut pcm = vec![0i16; bytes.len() / 2];
        l16_le_to_pcm(&bytes, &mut pcm);
        assert_eq!((pcm[0], pcm[1]), (500, -500), "ch0 offerer, ch1 answerer");

        let stop = ControlMessage::Stop(StopData {
            stream_id: "split-1".into(),
            reason: "done".into(),
        });
        server
            .send(Message::text(stop.to_json().expect("json")))
            .await
            .expect("stop");
        let reason = task.await.expect("joined").expect("ended cleanly");
        assert_eq!(reason, SplitEndReason::ServerStopped);
    }

    /// Whatever the bot had sent and the actor had not played yet does not play on after the stream
    /// ended: the call goes quiet at once, whichever way it ended.
    #[tokio::test]
    async fn the_queues_are_flushed_however_the_stream_ends() {
        for how in ["stop", "close", "drop"] {
            let (client, mut server) = socket_pair().await;
            let plan = plan_ws_tee(format(), true, false);
            let start = start_message("s", "c", plan.format, plan.tracks, Direction::Duplex);
            let (writer, [first, second]) = playout(8_000);
            let task = tokio::spawn(run_ws_split(
                client,
                start,
                plan.frames,
                plan.recycle,
                writer,
            ));
            let _ = server.next().await;
            for _ in 0..10 {
                server
                    .send(Message::binary(interleave(&[5i16; 160], &[5i16; 160])))
                    .await
                    .expect("server sends");
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                while first.queued() < 10 {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .expect("the audio is queued");
            match how {
                "stop" => {
                    let stop = ControlMessage::Stop(StopData {
                        stream_id: "s".into(),
                        reason: "done".into(),
                    });
                    server
                        .send(Message::text(stop.to_json().expect("json")))
                        .await
                        .expect("stop");
                }
                "close" => server.close(None).await.expect("close"),
                _ => drop(server),
            }
            let _ = task.await.expect("joined");
            assert_eq!(
                (first.queued(), second.queued()),
                (0, 0),
                "{how}: nothing is left to play after the end"
            );
        }
    }

    #[tokio::test]
    async fn a_closing_server_ends_the_transport_as_closed() {
        let (client, mut server) = socket_pair().await;
        let plan = plan_ws_tee(format(), true, false);
        let start = start_message("s", "c", plan.format, plan.tracks, Direction::Duplex);
        let (writer, _readers) = playout(8_000);
        let task = tokio::spawn(run_ws_split(
            client,
            start,
            plan.frames,
            plan.recycle,
            writer,
        ));
        let _ = server.next().await;
        server.close(None).await.expect("close");
        assert_eq!(
            task.await.expect("joined").expect("ended cleanly"),
            SplitEndReason::ServerClosed
        );
    }
}
