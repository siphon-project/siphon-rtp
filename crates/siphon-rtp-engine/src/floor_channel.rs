//! MCPTT floor control over a WebRTC data channel, for a browser seat.
//!
//! A browser cannot send RTCP APP, so the floor control of a browser seat runs over a data channel
//! instead. **3GPP TS 24.380 defines no WebRTC binding; this is siphon-rtp's own convention**, kept
//! as small as possible:
//!
//! * the browser opens a data channel labelled [`FLOOR_CHANNEL_LABEL`] (`"mcptt-floor"`) on the SCTP
//!   association that rides the seat's DTLS association (RFC 8831, RFC 8261). The engine opens none
//!   itself and accepts the channel the browser opens whatever its ordering and reliability;
//! * one complete floor message is one **binary** message, encoded exactly as the RTCP APP packet
//!   (RFC 3550 §6.7) would be on the wire: the 12-byte header, then the data. So the engine reads it
//!   with the parser the UDP floor stream uses and raises the same `rtcp_app` event (`stream: floor`),
//!   and builds a `send_rtcp_app` with the same writer. A controller has one interface for both;
//! * a string message, or a binary one that is not an APP packet, is counted and dropped (a debug
//!   log, no event). Any other channel label is accepted at the DCEP level (RFC 8832) and its
//!   messages are ignored.
//!
//! The data channel is not a new ingress: its bytes arrive only inside the seat's authenticated DTLS
//! association (docs/security-and-nat.md, "WebRTC data channel").
//!
//! The association is owned by the DTLS driver task of the seat's leg (`dtls_session`),
//! which already owns the DTLS session: one owner, no lock, no task per packet. The driver reaches
//! the controller through the [`FloorSink`] it was given and the engine reaches the driver through a
//! bounded mailbox behind a [`FloorChannelHandle`].

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use siphon_rtp_dtls::{DataChannelEvent, DataChannelHost, DtlsRole, DtlsSession};
use siphon_rtp_proto::RtcpAppStream;

use crate::app_events::{surface_app_to_queue, AppEventQueue, AppScope};

/// The label of the data channel that carries the floor (this crate's convention, see the module
/// documentation).
pub const FLOOR_CHANNEL_LABEL: &str = "mcptt-floor";

/// Floor messages queued toward the driver before a send is refused. A floor message is a few dozen
/// octets and the controller sends them at human pace, so this is a backstop, not a buffer.
const WRITER_QUEUE_CAPACITY: usize = 64;

/// Why a floor message could not be handed to the channel.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FloorChannelError {
    /// The browser has not opened the `mcptt-floor` channel (yet, or any more).
    #[error("floor data channel not open yet")]
    NotOpen,
    /// The writer queue is full: the association is not draining.
    #[error("floor data channel congested")]
    Congested,
    /// The seat's DTLS driver is gone.
    #[error("floor data channel closed")]
    Gone,
    /// The association or the datapath refused the message after it was queued.
    #[error("floor message not sent: {0}")]
    Refused(String),
    /// The driver did not answer in time (or dropped the message with the channel).
    #[error("floor data channel did not confirm the send within {} ms", SEND_TIMEOUT.as_millis())]
    NoVerdict,
}

/// How long a send waits for the driver to put the message on the wire.
pub const SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// One floor message queued for the driver, with the channel its verdict goes back on.
pub struct Outbound {
    message: Bytes,
    reply: tokio::sync::oneshot::Sender<Result<(), String>>,
}

/// A send the driver has accepted into its mailbox; [`Self::wait`] returns once the message is on the
/// wire (the SCTP association took it and the DTLS records reached the datapath) or has failed.
pub struct PendingSend(tokio::sync::oneshot::Receiver<Result<(), String>>);

impl PendingSend {
    /// Wait for the driver's verdict, at most [`SEND_TIMEOUT`].
    ///
    /// # Errors
    /// [`FloorChannelError::Refused`] with the reason, or [`FloorChannelError::NoVerdict`].
    pub async fn wait(self) -> Result<(), FloorChannelError> {
        match tokio::time::timeout(SEND_TIMEOUT, self.0).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(reason))) => Err(FloorChannelError::Refused(reason)),
            Ok(Err(_)) | Err(_) => Err(FloorChannelError::NoVerdict),
        }
    }
}

/// Whose party the channel's events are for: a two-party call, or a forwarding room's seat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FloorScope {
    /// A two-party call, by call key.
    Call(String),
    /// A forwarding room, by room id.
    Room(String),
}

/// Where the channel's inbound floor messages go.
#[derive(Clone)]
pub struct FloorSink {
    /// The call or room the events name.
    pub scope: FloorScope,
    /// The leg or seat tag.
    pub tag: String,
    /// The `rtcp_app` queue of the controller that owns the party.
    pub events: Option<AppEventQueue>,
}

/// What the channel counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FloorChannelStats {
    /// APP packets read from binary messages, each raised as an event.
    pub app_events: u64,
    /// Binary messages that were not (all) readable APP packets.
    pub malformed: u64,
    /// String messages on the floor channel.
    pub text_messages: u64,
    /// Messages on channels that are not the floor channel.
    pub other_channel_messages: u64,
    /// Outbound floor messages the association refused.
    pub send_failures: u64,
}

#[derive(Default)]
struct Counters {
    app_events: AtomicU64,
    malformed: AtomicU64,
    text_messages: AtomicU64,
    other_channel_messages: AtomicU64,
    send_failures: AtomicU64,
}

struct Shared {
    open: AtomicBool,
    counters: Counters,
}

/// The engine's end of a seat's floor channel: cheap to clone, shared by whoever sends floor control
/// to the seat.
#[derive(Clone)]
pub struct FloorChannelHandle {
    shared: Arc<Shared>,
    writer: flume::Sender<Outbound>,
}

impl FloorChannelHandle {
    /// Whether the browser has opened the `mcptt-floor` channel.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.shared.open.load(Ordering::Acquire)
    }

    /// Queue one floor message (a complete RTCP APP packet) for the channel. Await the returned
    /// [`PendingSend`] for the verdict.
    ///
    /// # Errors
    /// [`FloorChannelError`]: the channel is not open, the mailbox is full, or the driver is gone.
    pub fn submit(&self, message: Bytes) -> Result<PendingSend, FloorChannelError> {
        if !self.is_open() {
            return Err(FloorChannelError::NotOpen);
        }
        let (reply, verdict) = tokio::sync::oneshot::channel();
        self.writer
            .try_send(Outbound { message, reply })
            .map_err(|error| match error {
                flume::TrySendError::Full(_) => FloorChannelError::Congested,
                flume::TrySendError::Disconnected(_) => FloorChannelError::Gone,
            })?;
        Ok(PendingSend(verdict))
    }

    /// What the channel counted so far.
    #[must_use]
    pub fn stats(&self) -> FloorChannelStats {
        let counters = &self.shared.counters;
        FloorChannelStats {
            app_events: counters.app_events.load(Ordering::Relaxed),
            malformed: counters.malformed.load(Ordering::Relaxed),
            text_messages: counters.text_messages.load(Ordering::Relaxed),
            other_channel_messages: counters.other_channel_messages.load(Ordering::Relaxed),
            send_failures: counters.send_failures.load(Ordering::Relaxed),
        }
    }
}

/// The driver's end of a seat's floor channel. Cloned into each driver the bridge spawns for the
/// seat's endpoint, so a re-registration keeps the channel.
#[derive(Clone)]
pub struct FloorChannelPlan {
    sink: FloorSink,
    shared: Arc<Shared>,
    writer: flume::Receiver<Outbound>,
}

/// A new floor channel: the handle the engine sends through, and the plan the DTLS driver runs.
#[must_use]
pub fn floor_channel(sink: FloorSink) -> (FloorChannelHandle, FloorChannelPlan) {
    let shared = Arc::new(Shared {
        open: AtomicBool::new(false),
        counters: Counters::default(),
    });
    let (sender, receiver) = flume::bounded(WRITER_QUEUE_CAPACITY);
    (
        FloorChannelHandle {
            shared: shared.clone(),
            writer: sender,
        },
        FloorChannelPlan {
            sink,
            shared,
            writer: receiver,
        },
    )
}

/// The DTLS driver's data channel state: the SCTP association, and which stream is the floor. Public
/// so the per-message benchmark can drive it without sockets.
pub struct ChannelDriver {
    host: DataChannelHost,
    plan: FloorChannelPlan,
    /// The SCTP stream of the `mcptt-floor` channel once the browser opened it.
    floor_stream: Option<u16>,
    writer: Option<flume::Receiver<Outbound>>,
    /// Sends written to the association whose verdict waits for the DTLS records to be sent.
    awaiting_wire: Vec<tokio::sync::oneshot::Sender<Result<(), String>>>,
}

impl ChannelDriver {
    pub fn new(role: DtlsRole, plan: FloorChannelPlan) -> Self {
        Self {
            host: DataChannelHost::new(role),
            writer: Some(plan.writer.clone()),
            awaiting_wire: Vec::new(),
            plan,
            floor_stream: None,
        }
    }

    /// The mailbox the engine's floor sends arrive on, until it closes.
    pub fn writer(&self) -> Option<flume::Receiver<Outbound>> {
        self.writer.clone()
    }

    /// The writer mailbox closed (every handle was dropped): stop reading it.
    pub fn writer_closed(&mut self) {
        self.writer = None;
    }

    /// The DTLS handshake keyed the leg: send the SCTP INIT (RFC 8841 §6; the host breaks a tie with
    /// the peer's INIT by DTLS role).
    pub fn on_keyed(&mut self, now: Instant) {
        if let Err(error) = self.host.start(now) {
            tracing::warn!(
                target: "siphon_rtp::media", tag = %self.plan.sink.tag, %error,
                "SCTP association could not be started; the floor data channel stays closed"
            );
        }
    }

    /// An SCTP packet arrived as DTLS application data.
    pub fn on_packet(&mut self, now: Instant, packet: &[u8]) {
        let events = self.host.handle_packet(now, packet);
        self.apply(&events);
    }

    /// The SCTP timer fired.
    pub fn on_timeout(&mut self, now: Instant) {
        let events = self.host.handle_timeout(now);
        self.apply(&events);
    }

    /// When the SCTP association next needs [`Self::on_timeout`].
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.host.poll_timeout()
    }

    /// The controller sent a floor message toward the browser: write it as one binary message. The
    /// verdict is held until [`Self::complete_sends`] says the DTLS records left; a message the
    /// association refuses is answered at once.
    pub fn on_outbound(&mut self, now: Instant, outbound: Outbound) {
        let Outbound { message, reply } = outbound;
        let counters = &self.plan.shared.counters;
        let Some(stream) = self.floor_stream else {
            // The channel closed between the handle's check and now.
            counters.send_failures.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                target: "siphon_rtp::media", tag = %self.plan.sink.tag,
                "floor message queued for a channel that closed; dropped"
            );
            let _ = reply.send(Err("floor data channel closed".to_owned()));
            return;
        };
        match self.host.send(now, stream, true, &message) {
            Ok(()) => self.awaiting_wire.push(reply),
            Err(error) => {
                counters.send_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    target: "siphon_rtp::media", tag = %self.plan.sink.tag, %error,
                    "floor message could not be written to the data channel"
                );
                let _ = reply.send(Err(error.to_string()));
            }
        }
    }

    /// Answer every send written since the last call: `Ok` when its DTLS records were handed to the
    /// datapath, else the reason they were not.
    pub fn complete_sends(&mut self, result: &Result<(), String>) {
        for reply in self.awaiting_wire.drain(..) {
            if result.is_err() {
                self.plan
                    .shared
                    .counters
                    .send_failures
                    .fetch_add(1, Ordering::Relaxed);
            }
            let _ = reply.send(result.clone());
        }
    }

    /// Hand every SCTP packet the association has queued to `send`.
    pub fn drain_with(&mut self, now: Instant, mut send: impl FnMut(Bytes)) {
        while let Some(packet) = self.host.poll_transmit(now) {
            send(packet);
        }
    }

    /// Write every SCTP packet the association has queued into the DTLS session.
    ///
    /// # Errors
    /// The first packet DTLS refused (the message is then not on the wire).
    pub fn drain(&mut self, now: Instant, session: &mut DtlsSession) -> Result<(), String> {
        let mut outcome = Ok(());
        while let Some(packet) = self.host.poll_transmit(now) {
            if let Err(error) = session.write_application_data(now, &packet) {
                tracing::debug!(
                    target: "siphon_rtp::media", tag = %self.plan.sink.tag, %error,
                    "SCTP packet could not be sent over DTLS; dropped"
                );
                if outcome.is_ok() {
                    outcome = Err(error.to_string());
                }
            }
        }
        outcome
    }

    fn apply(&mut self, events: &[DataChannelEvent]) {
        for event in events {
            match event {
                DataChannelEvent::ChannelOpened { stream_id, label } => {
                    if label == FLOOR_CHANNEL_LABEL && self.floor_stream.is_none() {
                        self.floor_stream = Some(*stream_id);
                        self.plan.shared.open.store(true, Ordering::Release);
                        tracing::info!(
                            target: "siphon_rtp::media", tag = %self.plan.sink.tag,
                            stream = stream_id, "floor data channel open"
                        );
                    } else {
                        tracing::debug!(
                            target: "siphon_rtp::media", tag = %self.plan.sink.tag,
                            stream = stream_id, label = %label,
                            "data channel accepted but not the floor channel; its messages are ignored"
                        );
                    }
                }
                DataChannelEvent::Message {
                    stream_id,
                    binary,
                    data,
                } => self.on_message(*stream_id, *binary, data),
                DataChannelEvent::Lost => {
                    self.floor_stream = None;
                    self.plan.shared.open.store(false, Ordering::Release);
                    tracing::info!(
                        target: "siphon_rtp::media", tag = %self.plan.sink.tag,
                        "SCTP association lost; floor data channel closed"
                    );
                }
                DataChannelEvent::Connected => {
                    tracing::debug!(
                        target: "siphon_rtp::media", tag = %self.plan.sink.tag,
                        "SCTP association established"
                    );
                }
                _ => {}
            }
        }
    }

    fn on_message(&self, stream_id: u16, binary: bool, data: &Bytes) {
        let counters = &self.plan.shared.counters;
        if self.floor_stream != Some(stream_id) {
            counters
                .other_channel_messages
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !binary {
            counters.text_messages.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                target: "siphon_rtp::media", tag = %self.plan.sink.tag,
                "string message on the floor data channel; dropped (floor messages are binary)"
            );
            return;
        }
        let (mut raised, mut malformed) = (0u64, 0u64);
        let scope = match &self.plan.sink.scope {
            FloorScope::Call(call) => AppScope::Call(call),
            FloorScope::Room(room) => AppScope::Room(room),
        };
        surface_app_to_queue(
            scope,
            &self.plan.sink.tag,
            self.plan.sink.events.as_ref(),
            RtcpAppStream::Floor,
            data,
            &mut raised,
            &mut malformed,
        );
        counters.app_events.fetch_add(raised, Ordering::Relaxed);
        counters.malformed.fetch_add(malformed, Ordering::Relaxed);
    }
}

impl Drop for ChannelDriver {
    fn drop(&mut self) {
        // The association dies with the driver, so the channel is closed to every sender.
        self.plan.shared.open.store(false, Ordering::Release);
    }
}

/// Why a floor message could not be framed for the channel.
#[derive(Debug, thiserror::Error)]
pub enum FloorFrameError {
    /// The request is not a valid RTCP APP packet.
    #[error("{0}")]
    Packet(#[from] siphon_rtp_media::rtcp::AppWriteError),
    /// The channel refused it.
    #[error("{0}")]
    Channel(#[from] FloorChannelError),
}

/// Build the RTCP APP packet of a floor `request` (RFC 3550 §6.7) and queue it as one binary message
/// on `channel`. `ssrc` is the packet's SSRC; the controller's, else the caller's default.
///
/// # Errors
/// [`FloorFrameError`] for an invalid packet or a channel that is not open.
pub fn submit_floor_message(
    channel: &FloorChannelHandle,
    ssrc: u32,
    name: [u8; 4],
    subtype: u8,
    payload: &[u8],
) -> Result<PendingSend, FloorFrameError> {
    let mut buffer = vec![0u8; crate::app_events::MAX_APP_DATAGRAM];
    let length = siphon_rtp_media::rtcp::write_app(subtype, ssrc, name, payload, &mut buffer)?;
    buffer.truncate(length);
    Ok(channel.submit(Bytes::from(buffer))?)
}

/// [`submit_floor_message`], then wait until the message is on the wire.
///
/// # Errors
/// [`FloorFrameError`] for an invalid packet, a channel that is not open, or a send that failed.
pub async fn send_floor_message(
    channel: &FloorChannelHandle,
    ssrc: u32,
    name: [u8; 4],
    subtype: u8,
    payload: &[u8],
) -> Result<(), FloorFrameError> {
    submit_floor_message(channel, ssrc, name, subtype, payload)?
        .wait()
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use siphon_rtp_proto::Event;

    use super::*;
    use crate::metrics::Metrics;

    /// RFC 3550 §6.7 APP packet: version 2, subtype 0, name "MCPT", data `00 02 05 00`.
    const FLOOR_REQUEST: [u8; 16] = [
        0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05,
        0x00,
    ];

    fn driver() -> (ChannelDriver, FloorChannelHandle, AppEventQueue) {
        let queue = AppEventQueue::new(16, Arc::new(Metrics::new()));
        let (handle, plan) = floor_channel(FloorSink {
            scope: FloorScope::Room("room".into()),
            tag: "seat".into(),
            events: Some(queue.clone()),
        });
        (ChannelDriver::new(DtlsRole::Server, plan), handle, queue)
    }

    fn open(driver: &mut ChannelDriver, stream_id: u16, label: &str) {
        driver.apply(&[DataChannelEvent::ChannelOpened {
            stream_id,
            label: label.into(),
        }]);
    }

    fn message(binary: bool, data: &[u8]) -> DataChannelEvent {
        DataChannelEvent::Message {
            stream_id: 0,
            binary,
            data: Bytes::copy_from_slice(data),
        }
    }

    #[test]
    fn a_binary_floor_message_raises_one_rtcp_app_event() {
        let (mut driver, handle, queue) = driver();
        open(&mut driver, 0, FLOOR_CHANNEL_LABEL);
        assert!(handle.is_open());
        driver.apply(&[message(true, &FLOOR_REQUEST)]);
        let events: Vec<Event> = queue.receiver().try_iter().collect();
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::RtcpApp {
                conference_id,
                call_id,
                from_tag,
                stream,
                ssrc,
                name,
                subtype,
                payload,
            } => {
                assert_eq!(conference_id.as_deref(), Some("room"));
                assert_eq!(*call_id, None);
                assert_eq!(from_tag, "seat");
                assert_eq!(*stream, RtcpAppStream::Floor);
                assert_eq!(*ssrc, 0x1122_3344);
                assert_eq!(name, "MCPT");
                assert_eq!(*subtype, 0);
                assert_eq!(payload, &[0x00, 0x02, 0x05, 0x00]);
            }
            other => panic!("unexpected event {other:?}"),
        }
        assert_eq!(handle.stats().app_events, 1);
    }

    #[test]
    fn a_call_scope_names_the_call_not_a_room() {
        let queue = AppEventQueue::new(4, Arc::new(Metrics::new()));
        let (_handle, plan) = floor_channel(FloorSink {
            scope: FloorScope::Call("call-1".into()),
            tag: "leg".into(),
            events: Some(queue.clone()),
        });
        let mut driver = ChannelDriver::new(DtlsRole::Server, plan);
        open(&mut driver, 0, FLOOR_CHANNEL_LABEL);
        driver.apply(&[message(true, &FLOOR_REQUEST)]);
        match queue.receiver().try_recv() {
            Ok(Event::RtcpApp {
                call_id,
                conference_id,
                ..
            }) => {
                assert_eq!(call_id.as_deref(), Some("call-1"));
                assert_eq!(conference_id, None);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_string_message_is_counted_and_raises_nothing() {
        let (mut driver, handle, queue) = driver();
        open(&mut driver, 0, FLOOR_CHANNEL_LABEL);
        driver.apply(&[message(false, b"hello")]);
        assert!(queue.is_empty());
        assert_eq!(handle.stats().text_messages, 1);
    }

    #[test]
    fn a_malformed_binary_message_is_counted_and_raises_nothing() {
        let (mut driver, handle, queue) = driver();
        open(&mut driver, 0, FLOOR_CHANNEL_LABEL);
        driver.apply(&[message(true, &FLOOR_REQUEST[..9])]);
        assert!(queue.is_empty());
        assert_eq!(handle.stats().malformed, 1);
        assert_eq!(handle.stats().app_events, 0);
    }

    #[test]
    fn a_channel_with_another_label_is_accepted_but_its_messages_are_ignored() {
        let (mut driver, handle, queue) = driver();
        open(&mut driver, 0, "chat");
        assert!(!handle.is_open(), "only mcptt-floor opens the floor");
        driver.apply(&[message(true, &FLOOR_REQUEST)]);
        assert!(queue.is_empty());
        assert_eq!(handle.stats().other_channel_messages, 1);
    }

    #[test]
    fn a_second_floor_channel_does_not_replace_the_first() {
        let (mut driver, _handle, _queue) = driver();
        open(&mut driver, 0, FLOOR_CHANNEL_LABEL);
        open(&mut driver, 2, FLOOR_CHANNEL_LABEL);
        assert_eq!(driver.floor_stream, Some(0));
    }

    #[test]
    fn sending_before_the_channel_opens_is_refused() {
        let (_driver, handle, _queue) = driver();
        assert!(matches!(
            handle.submit(Bytes::from_static(b"x")),
            Err(FloorChannelError::NotOpen)
        ));
    }

    #[test]
    fn a_full_writer_queue_refuses_rather_than_growing() {
        let (mut driver, handle, _queue) = driver();
        open(&mut driver, 0, FLOOR_CHANNEL_LABEL);
        for _ in 0..WRITER_QUEUE_CAPACITY {
            let _ = handle.submit(Bytes::from_static(b"x")).expect("room");
        }
        assert!(matches!(
            handle.submit(Bytes::from_static(b"x")),
            Err(FloorChannelError::Congested)
        ));
    }

    #[test]
    fn dropping_the_driver_closes_the_channel_to_every_sender() {
        let (mut driver, handle, _queue) = driver();
        open(&mut driver, 0, FLOOR_CHANNEL_LABEL);
        assert!(handle.is_open());
        drop(driver);
        assert!(matches!(
            handle.submit(Bytes::from_static(b"x")),
            Err(FloorChannelError::NotOpen)
        ));
    }

    #[test]
    fn losing_the_association_closes_the_channel() {
        let (mut driver, handle, _queue) = driver();
        open(&mut driver, 0, FLOOR_CHANNEL_LABEL);
        driver.apply(&[DataChannelEvent::Lost]);
        assert!(!handle.is_open());
    }

    #[test]
    fn a_floor_message_is_framed_as_the_rtcp_app_packet() {
        let (mut driver, handle, _queue) = driver();
        open(&mut driver, 0, FLOOR_CHANNEL_LABEL);
        let granted = [
            0x01, 0x02, 0x00, 0x1E, 0x0E, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
        ];
        let _pending =
            submit_floor_message(&handle, 0x1122_3344, *b"MCPT", 17, &granted).expect("queued");
        let writer = driver.writer().expect("mailbox");
        let queued = writer.try_recv().expect("queued").message;
        // RFC 3550 §6.7: V=2, P=0, subtype 17, PT=204, length 5 words, SSRC, name, data.
        assert_eq!(
            &queued[..12],
            &[0x91, 0xCC, 0x00, 0x05, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54]
        );
        assert_eq!(&queued[12..], &granted);
    }

    #[test]
    fn an_invalid_floor_message_is_refused_before_the_channel() {
        let (mut driver, handle, _queue) = driver();
        open(&mut driver, 0, FLOOR_CHANNEL_LABEL);
        // RFC 3550 §6.7: the data is a multiple of 4 octets.
        assert!(matches!(
            submit_floor_message(&handle, 1, *b"MCPT", 0, &[1, 2, 3]),
            Err(FloorFrameError::Packet(_))
        ));
        assert!(driver.writer().expect("mailbox").try_recv().is_err());
    }

    #[tokio::test]
    async fn a_send_to_a_closed_channel_is_an_error() {
        let (mut driver, handle, _queue) = driver();
        open(&mut driver, 0, FLOOR_CHANNEL_LABEL);
        drop(driver);
        let result = send_floor_message(&handle, 1, *b"MCPT", 0, &[0, 0, 0, 0]).await;
        assert!(
            matches!(
                result,
                Err(FloorFrameError::Channel(FloorChannelError::NotOpen))
            ),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn a_send_the_association_cannot_take_is_answered_with_the_reason() {
        // The channel is marked open but the SCTP association never came up: the driver refuses the
        // message at once and the waiting sender hears why, rather than waiting for a timeout.
        let (mut driver, handle, _queue) = driver();
        open(&mut driver, 0, FLOOR_CHANNEL_LABEL);
        let pending = submit_floor_message(&handle, 1, *b"MCPT", 0, &[0, 0, 0, 0]).expect("queued");
        let outbound = driver
            .writer()
            .expect("mailbox")
            .try_recv()
            .expect("queued");
        driver.on_outbound(Instant::now(), outbound);
        let result = pending.wait().await;
        assert!(
            matches!(result, Err(FloorChannelError::Refused(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn a_send_is_confirmed_only_when_the_driver_says_it_left() {
        let (mut driver, handle, _queue) = driver();
        open(&mut driver, 0, FLOOR_CHANNEL_LABEL);
        // Stand in for a connected association: record the reply the driver would hold.
        let (reply, verdict) = tokio::sync::oneshot::channel();
        driver.awaiting_wire.push(reply);
        let pending = PendingSend(verdict);
        driver.complete_sends(&Err("datapath send failed: closed".to_owned()));
        assert_eq!(
            pending.wait().await,
            Err(FloorChannelError::Refused(
                "datapath send failed: closed".into()
            ))
        );
        assert!(handle.is_open());
    }
}
