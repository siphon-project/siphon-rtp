//! WebRTC data channels over the DTLS association: an SCTP association (RFC 9260) carried as DTLS
//! application data (RFC 8261), with the Data Channel Establishment Protocol (RFC 8832) on top and
//! the channel semantics of RFC 8831.
//!
//! [`DataChannelHost`] is sans-I/O like [`crate::DtlsSession`]: it owns no socket, reads no clock and
//! spawns no task. The caller feeds it the SCTP packets a DTLS session surfaced
//! ([`crate::DtlsEvent::ApplicationData`]) through [`DataChannelHost::handle_packet`], writes the
//! packets it drains from [`DataChannelHost::poll_transmit`] back as DTLS application data
//! ([`crate::DtlsSession::write_application_data`]), and arms one timer from
//! [`DataChannelHost::poll_timeout`]. After **every** call that advances it the caller drains
//! `poll_transmit` again and recomputes the deadline.
//!
//! # Who opens the association
//!
//! RFC 8841 §6 leaves the SCTP INIT to either side once the DTLS association is up, and browsers
//! may initiate it (whichever DTLS role they ended up with), so a host always *accepts* an INIT. It also
//! initiates one itself ([`DataChannelHost::start`]) once the DTLS association is keyed, so the
//! association comes up whether or not the peer sends an INIT. The SCTP stack does not resolve two
//! crossing INITs (RFC 9260 §5.2), so the tie is broken by DTLS role: the server yields to the
//! client's INIT and the client ignores the server's. Channels the peer opens (RFC 8832 §6: a DATA_CHANNEL_OPEN on a stream) are accepted whatever their label;
//! the engine opens none itself.
//!
//! # What a message is
//!
//! Each complete SCTP user message on an open channel surfaces as one
//! [`DataChannelEvent::Message`], tagged binary or string by its payload protocol identifier
//! (RFC 8831 §8). A message longer than [`MAX_MESSAGE_SIZE`] is dropped and counted, never
//! delivered.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use rtc_datachannel::message::message_channel_ack::DataChannelAck;
use rtc_datachannel::message::message_channel_open::{
    ChannelType, DataChannelOpen, CHANNEL_PRIORITY_NORMAL,
};
use rtc_datachannel::message::Message;
use rtc_sctp::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig, Event,
    Payload, PayloadProtocolIdentifier, ServerConfig, StreamEvent, TransportConfig,
};
use rtc_shared::marshal::{Marshal, Unmarshal};
use rtc_shared::TransportProtocol;

use crate::DtlsRole;

/// The largest SCTP user message this host accepts or sends, and the `a=max-message-size` the engine
/// advertises (RFC 8841 §5). A floor message is a few dozen octets; the bound only
/// keeps a hostile (but DTLS-authenticated) peer from making the engine reassemble megabytes.
pub const MAX_MESSAGE_SIZE: usize = 65_536;

/// The receive window advertised to the peer (RFC 9260 §3.3.2 `a_rwnd`): how much unacknowledged data
/// it may have in flight toward us. Two messages' worth, so one slow reader cannot pin memory.
const RECEIVE_WINDOW: u32 = 2 * MAX_MESSAGE_SIZE as u32;

/// RFC 8841 §5: the SCTP port both ends use inside the DTLS association. The SCTP
/// stack here keys an association by address pair only, so the number is purely what the SDP's
/// `a=sctp-port` signals and the SCTP common header carries.
const SCTP_PORT: u16 = 5000;

/// The association's fixed identity, as in [`crate::DtlsSession`]: documentation addresses
/// (RFC 5737), never routed. The DTLS association is the only transport, so there is no real address.
const LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), SCTP_PORT);
const REMOTE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), SCTP_PORT);

/// Errors from a data channel operation.
#[derive(Debug, thiserror::Error)]
pub enum DataChannelError {
    /// The SCTP association is not established yet (or is gone).
    #[error("the SCTP association is not established")]
    NotConnected,
    /// No open channel has this SCTP stream identifier.
    #[error("no open data channel on stream {0}")]
    UnknownChannel(u16),
    /// The message is longer than [`MAX_MESSAGE_SIZE`].
    #[error("message of {length} bytes exceeds the {MAX_MESSAGE_SIZE} byte limit")]
    TooLarge {
        /// The offending length.
        length: usize,
    },
    /// The SCTP stack refused the operation.
    #[error("SCTP: {0}")]
    Sctp(String),
}

/// What a host reports to its caller.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq)]
pub enum DataChannelEvent {
    /// The SCTP association is established (RFC 9260 §5.1).
    Connected,
    /// A channel is open: the peer's DATA_CHANNEL_OPEN was accepted and acknowledged, or the peer
    /// acknowledged ours (RFC 8832 §6).
    ChannelOpened {
        /// The SCTP stream identifier.
        stream_id: u16,
        /// The channel label (RFC 8832 §5.1), UTF-8.
        label: String,
    },
    /// One complete user message on an open channel.
    Message {
        /// The SCTP stream identifier.
        stream_id: u16,
        /// Whether the payload protocol identifier says binary (RFC 8831 §8); `false` is a string.
        binary: bool,
        /// The message bytes (empty for the empty-message identifiers).
        data: Bytes,
    },
    /// The association failed or was closed by the peer; the host is dead.
    Lost,
}

/// What a host dropped, by cause. Every drop is also a `debug!`/`warn!` at the point it happens.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DataChannelCounters {
    /// User messages on a stream that never completed a DATA_CHANNEL_OPEN.
    pub unopened_stream: u64,
    /// DATA_CHANNEL_OPEN or other DCEP messages that did not parse, or carried a non-UTF-8 label.
    pub malformed_dcep: u64,
    /// Messages longer than [`MAX_MESSAGE_SIZE`].
    pub oversize: u64,
    /// User messages with a payload protocol identifier RFC 8831 §8 does not define.
    pub unknown_protocol_identifier: u64,
    /// Offers of a second SCTP association on the one DTLS association.
    pub extra_associations: u64,
    /// DATA_CHANNEL_ACKs the SCTP stack would not queue.
    pub unsent_acknowledgements: u64,
}

#[derive(Debug)]
enum ChannelState {
    /// We sent a DATA_CHANNEL_OPEN and wait for the ACK.
    Pending(String),
    /// Open both ways.
    Open,
}

/// One SCTP association and its data channels.
pub struct DataChannelHost {
    role: DtlsRole,
    endpoint: Endpoint,
    handle: Option<AssociationHandle>,
    association: Option<Association>,
    channels: HashMap<u16, ChannelState>,
    /// Packets drained from the association, not yet handed out.
    outbox: VecDeque<Bytes>,
    connected: bool,
    lost: bool,
    counters: DataChannelCounters,
}

impl DataChannelHost {
    /// A host for the DTLS `role`. It accepts an inbound INIT whatever the role; a client also
    /// initiates through [`Self::start`].
    #[must_use]
    pub fn new(role: DtlsRole) -> Self {
        let transport = Self::transport();
        Self {
            role,
            endpoint: Endpoint::new(
                LOCAL,
                TransportProtocol::UDP,
                Arc::new(EndpointConfig::default()),
                Some(Arc::new(ServerConfig::new(transport))),
            ),
            handle: None,
            association: None,
            channels: HashMap::new(),
            outbox: VecDeque::new(),
            connected: false,
            lost: false,
            counters: DataChannelCounters::default(),
        }
    }

    fn transport() -> TransportConfig {
        TransportConfig::default()
            .with_sctp_port(SCTP_PORT)
            .with_max_message_size(MAX_MESSAGE_SIZE as u32)
            .with_max_receive_buffer_size(RECEIVE_WINDOW)
    }

    /// Send the SCTP INIT (RFC 9260 §5.1), whatever the DTLS role. Idempotent, and a no-op once the
    /// peer's INIT has created the association.
    ///
    /// # Errors
    /// [`DataChannelError::Sctp`] when the SCTP stack cannot start the association.
    pub fn start(&mut self, now: Instant) -> Result<(), DataChannelError> {
        if self.association.is_some() || self.lost {
            return Ok(());
        }
        let (handle, association) = self
            .endpoint
            .connect(now, ClientConfig::new(Self::transport()), REMOTE)
            .map_err(|error| DataChannelError::Sctp(error.to_string()))?;
        self.handle = Some(handle);
        self.association = Some(association);
        Ok(())
    }

    /// Feed one SCTP packet from the DTLS association and report what it produced. Drain
    /// [`Self::poll_transmit`] afterwards.
    pub fn handle_packet(&mut self, now: Instant, packet: &[u8]) -> Vec<DataChannelEvent> {
        let mut events = Vec::new();
        if self.lost {
            return events;
        }
        if let Some((handle, event)) =
            self.endpoint
                .handle(now, REMOTE, None, Bytes::copy_from_slice(packet))
        {
            match event {
                DatagramEvent::NewAssociation(association) => {
                    // A peer INIT. With no association of ours it is simply accepted. If both ends
                    // sent an INIT at once the stack does not resolve the collision (RFC 9260 §5.2),
                    // so the tie is broken by DTLS role: the server abandons its own unconnected
                    // attempt for the client's, and the client ignores the server's INIT, which
                    // leaves exactly the client-initiated association.
                    let yield_to_peer = self.association.is_none()
                        || (self.role == DtlsRole::Server && !self.connected);
                    if yield_to_peer {
                        self.handle = Some(handle);
                        self.association = Some(association);
                    } else {
                        self.counters.extra_associations += 1;
                    }
                }
                DatagramEvent::AssociationEvent(event) => {
                    if let Some(association) = self.association.as_mut() {
                        association.handle_event(event);
                    }
                }
                _ => {}
            }
        }
        self.pump(now, &mut events);
        events
    }

    /// The next SCTP packet to send to the peer (as DTLS application data), if any.
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Bytes> {
        if self.outbox.is_empty() {
            let association = self.association.as_mut()?;
            while let Some(transmit) = association.poll_transmit(now) {
                if let Payload::RawEncode(packets) = transmit.message {
                    self.outbox.extend(packets);
                }
            }
        }
        self.outbox.pop_front()
    }

    /// When the association next needs [`Self::handle_timeout`], or `None` when no timer is pending.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        if !self.outbox.is_empty() {
            return None;
        }
        self.association.as_ref()?.poll_timeout()
    }

    /// Fire the association's timer (RFC 9260 §6.3 retransmission, §8.3 heartbeat). Drain
    /// [`Self::poll_transmit`] afterwards.
    pub fn handle_timeout(&mut self, now: Instant) -> Vec<DataChannelEvent> {
        let mut events = Vec::new();
        if let Some(association) = self.association.as_mut() {
            association.handle_timeout(now);
        }
        self.pump(now, &mut events);
        events
    }

    /// Whether the SCTP association is established.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connected && !self.lost
    }

    /// Whether the association failed or was closed; the host is dead then.
    #[must_use]
    pub fn is_lost(&self) -> bool {
        self.lost
    }

    /// Whether `stream_id` is an open channel.
    #[must_use]
    pub fn is_open(&self, stream_id: u16) -> bool {
        matches!(self.channels.get(&stream_id), Some(ChannelState::Open))
    }

    /// What this host dropped so far.
    #[must_use]
    pub fn counters(&self) -> DataChannelCounters {
        self.counters
    }

    /// Open a channel labelled `label` (RFC 8832 §5.1: reliable, ordered). The stream identifier
    /// follows RFC 8832 §6: even for the DTLS client, odd for the server. The channel is usable once
    /// [`DataChannelEvent::ChannelOpened`] reports the peer's ACK.
    ///
    /// # Errors
    /// [`DataChannelError::NotConnected`] before the association is up, or the SCTP stack's refusal.
    pub fn open_channel(&mut self, now: Instant, label: &str) -> Result<u16, DataChannelError> {
        if !self.is_connected() {
            return Err(DataChannelError::NotConnected);
        }
        let first: u16 = if self.role == DtlsRole::Client { 0 } else { 1 };
        let stream_id = (0..=u16::MAX / 2)
            .map(|index| first + index * 2)
            .find(|candidate| !self.channels.contains_key(candidate))
            .ok_or_else(|| DataChannelError::Sctp("no free stream identifier".to_owned()))?;
        let open = Message::DataChannelOpen(DataChannelOpen {
            channel_type: ChannelType::Reliable,
            priority: CHANNEL_PRIORITY_NORMAL,
            reliability_parameter: 0,
            label: label.as_bytes().to_vec(),
            protocol: Vec::new(),
        })
        .marshal()
        .map_err(|error| DataChannelError::Sctp(error.to_string()))?;
        let association = self
            .association
            .as_mut()
            .ok_or(DataChannelError::NotConnected)?;
        let mut stream = association
            .open_stream(stream_id, PayloadProtocolIdentifier::Binary)
            .map_err(|error| DataChannelError::Sctp(error.to_string()))?;
        stream
            .write_sctp(
                now,
                &Bytes::from(open.to_vec()),
                PayloadProtocolIdentifier::Dcep,
            )
            .map_err(|error| DataChannelError::Sctp(error.to_string()))?;
        self.channels
            .insert(stream_id, ChannelState::Pending(label.to_owned()));
        Ok(stream_id)
    }

    /// Send one message on an open channel (RFC 8831 §6.6: one SCTP user message). Drain
    /// [`Self::poll_transmit`] afterwards.
    ///
    /// # Errors
    /// [`DataChannelError`] for a channel that is not open, a message over [`MAX_MESSAGE_SIZE`], or the
    /// SCTP stack's refusal.
    pub fn send(
        &mut self,
        now: Instant,
        stream_id: u16,
        binary: bool,
        data: &Bytes,
    ) -> Result<(), DataChannelError> {
        if !self.is_connected() {
            return Err(DataChannelError::NotConnected);
        }
        if !self.is_open(stream_id) {
            return Err(DataChannelError::UnknownChannel(stream_id));
        }
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(DataChannelError::TooLarge { length: data.len() });
        }
        // RFC 8831 §6.6: SCTP cannot carry an empty user message, so an empty one travels as one
        // zero byte under the "empty" identifier, which the receiver reads back as empty.
        let (payload, identifier) = match (binary, data.is_empty()) {
            (true, false) => (data.clone(), PayloadProtocolIdentifier::Binary),
            (true, true) => (
                Bytes::from_static(&[0]),
                PayloadProtocolIdentifier::BinaryEmpty,
            ),
            (false, false) => (data.clone(), PayloadProtocolIdentifier::String),
            (false, true) => (
                Bytes::from_static(&[0]),
                PayloadProtocolIdentifier::StringEmpty,
            ),
        };
        let association = self
            .association
            .as_mut()
            .ok_or(DataChannelError::NotConnected)?;
        association
            .stream(stream_id)
            .and_then(|mut stream| stream.write_sctp(now, &payload, identifier))
            .map(|_| ())
            .map_err(|error| DataChannelError::Sctp(error.to_string()))
    }

    /// Drain the association's events, accept new streams and read every readable one.
    fn pump(&mut self, now: Instant, events: &mut Vec<DataChannelEvent>) {
        let mut readable: Vec<u16> = Vec::new();
        {
            let Some(association) = self.association.as_mut() else {
                return;
            };
            while let Some(event) = association.poll() {
                match event {
                    Event::Connected => {
                        self.connected = true;
                        events.push(DataChannelEvent::Connected);
                    }
                    Event::HandshakeFailed { .. } | Event::AssociationLost { .. } => {
                        self.lost = true;
                        events.push(DataChannelEvent::Lost);
                    }
                    Event::Stream(StreamEvent::Readable { id }) if !readable.contains(&id) => {
                        readable.push(id);
                    }
                    _ => {}
                }
            }
            while let Some(event) = association.poll_endpoint_event() {
                if let Some(handle) = self.handle {
                    self.endpoint.handle_event(handle, event);
                }
            }
            while let Some(stream) = association.accept_stream() {
                let id = stream.stream_identifier();
                if !readable.contains(&id) {
                    readable.push(id);
                }
            }
        }
        for stream_id in readable {
            self.read_stream(now, stream_id, events);
        }
    }

    /// Read every complete message waiting on `stream_id`.
    fn read_stream(&mut self, now: Instant, stream_id: u16, events: &mut Vec<DataChannelEvent>) {
        loop {
            let Some(association) = self.association.as_mut() else {
                return;
            };
            let message = match association.stream(stream_id) {
                Ok(mut stream) => match stream.read_sctp() {
                    Ok(Some(chunks)) => (chunks.ppi, chunks.to_payload(MAX_MESSAGE_SIZE)),
                    Ok(None) | Err(_) => return,
                },
                Err(_) => return,
            };
            let (identifier, payload) = message;
            let Ok(payload) = payload else {
                self.counters.oversize += 1;
                continue;
            };
            let payload = payload.freeze();
            match identifier {
                PayloadProtocolIdentifier::Dcep => {
                    self.handle_dcep(now, stream_id, &payload, events);
                }
                PayloadProtocolIdentifier::Binary | PayloadProtocolIdentifier::String => {
                    self.deliver(
                        stream_id,
                        identifier == PayloadProtocolIdentifier::Binary,
                        payload,
                        events,
                    );
                }
                PayloadProtocolIdentifier::BinaryEmpty | PayloadProtocolIdentifier::StringEmpty => {
                    self.deliver(
                        stream_id,
                        identifier == PayloadProtocolIdentifier::BinaryEmpty,
                        Bytes::new(),
                        events,
                    );
                }
                _ => {
                    self.counters.unknown_protocol_identifier += 1;
                }
            }
        }
    }

    fn deliver(
        &mut self,
        stream_id: u16,
        binary: bool,
        data: Bytes,
        events: &mut Vec<DataChannelEvent>,
    ) {
        if self.is_open(stream_id) {
            events.push(DataChannelEvent::Message {
                stream_id,
                binary,
                data,
            });
        } else {
            self.counters.unopened_stream += 1;
        }
    }

    /// RFC 8832 §6: a DATA_CHANNEL_OPEN is acknowledged on the same stream; a DATA_CHANNEL_ACK opens
    /// the channel we proposed.
    fn handle_dcep(
        &mut self,
        now: Instant,
        stream_id: u16,
        payload: &Bytes,
        events: &mut Vec<DataChannelEvent>,
    ) {
        let mut cursor = payload.clone();
        match Message::unmarshal(&mut cursor) {
            Ok(Message::DataChannelOpen(open)) => {
                let Ok(label) = String::from_utf8(open.label) else {
                    self.counters.malformed_dcep += 1;
                    return;
                };
                if self.channels.contains_key(&stream_id) {
                    // A repeated OPEN (the ACK was lost): acknowledge again, report nothing new.
                    self.write_ack(now, stream_id);
                    return;
                }
                self.channels.insert(stream_id, ChannelState::Open);
                self.write_ack(now, stream_id);
                events.push(DataChannelEvent::ChannelOpened { stream_id, label });
            }
            Ok(Message::DataChannelAck(_)) => {
                if let Some(ChannelState::Pending(label)) = self.channels.get(&stream_id) {
                    let label = label.clone();
                    self.channels.insert(stream_id, ChannelState::Open);
                    events.push(DataChannelEvent::ChannelOpened { stream_id, label });
                }
            }
            Ok(_) | Err(_) => {
                self.counters.malformed_dcep += 1;
            }
        }
    }

    fn write_ack(&mut self, now: Instant, stream_id: u16) {
        let Ok(ack) = Message::DataChannelAck(DataChannelAck {}).marshal() else {
            return;
        };
        let Some(association) = self.association.as_mut() else {
            return;
        };
        let written = association.stream(stream_id).and_then(|mut stream| {
            stream.write_sctp(
                now,
                &Bytes::from(ack.to_vec()),
                PayloadProtocolIdentifier::Dcep,
            )
        });
        if written.is_err() {
            self.counters.unsent_acknowledgements += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Move every queued packet from `source` to `destination`, returning how many moved and what
    /// the destination reported.
    fn transfer(
        now: Instant,
        source: &mut DataChannelHost,
        destination: &mut DataChannelHost,
    ) -> (usize, Vec<DataChannelEvent>) {
        let (mut moved, mut events) = (0, Vec::new());
        while let Some(packet) = source.poll_transmit(now) {
            moved += 1;
            events.extend(destination.handle_packet(now, &packet));
        }
        (moved, events)
    }

    /// Run both sides until neither has anything to say, collecting what each reported.
    fn settle(
        now: Instant,
        client: &mut DataChannelHost,
        server: &mut DataChannelHost,
    ) -> (Vec<DataChannelEvent>, Vec<DataChannelEvent>) {
        let (mut client_events, mut server_events) = (Vec::new(), Vec::new());
        for _ in 0..32 {
            let (to_server, server_reported) = transfer(now, client, server);
            let (to_client, client_reported) = transfer(now, server, client);
            server_events.extend(server_reported);
            client_events.extend(client_reported);
            if to_server == 0 && to_client == 0 {
                break;
            }
        }
        (client_events, server_events)
    }

    fn connected_pair(now: Instant) -> (DataChannelHost, DataChannelHost) {
        let mut client = DataChannelHost::new(DtlsRole::Client);
        let mut server = DataChannelHost::new(DtlsRole::Server);
        client.start(now).expect("client starts");
        settle(now, &mut client, &mut server);
        assert!(client.is_connected() && server.is_connected());
        (client, server)
    }

    #[test]
    fn a_client_and_server_host_establish_an_association() {
        let now = Instant::now();
        let mut client = DataChannelHost::new(DtlsRole::Client);
        let mut server = DataChannelHost::new(DtlsRole::Server);
        client.start(now).expect("client starts");
        let (client_events, server_events) = settle(now, &mut client, &mut server);
        assert!(client_events.contains(&DataChannelEvent::Connected));
        assert!(server_events.contains(&DataChannelEvent::Connected));
    }

    #[test]
    fn two_hosts_that_start_at_once_still_end_with_one_working_association() {
        // A browser may initiate SCTP whichever DTLS role it has, so both sides can send an INIT at
        // the same instant (RFC 9260 §5.2 collision handling).
        let now = Instant::now();
        let mut client = DataChannelHost::new(DtlsRole::Client);
        let mut server = DataChannelHost::new(DtlsRole::Server);
        client.start(now).expect("client starts");
        server.start(now).expect("server starts");
        settle(now, &mut client, &mut server);
        assert!(client.is_connected(), "client up");
        assert!(server.is_connected(), "server up");
        client.open_channel(now, "mcptt-floor").expect("opens");
        let (_, server_events) = settle(now, &mut client, &mut server);
        assert!(server_events.iter().any(|event| matches!(
            event,
            DataChannelEvent::ChannelOpened { label, .. } if label == "mcptt-floor"
        )));
        let message = Bytes::from_static(b"\x80\xCC\x00\x00");
        client.send(now, 0, true, &message).expect("sends");
        let (_, server_events) = settle(now, &mut client, &mut server);
        assert!(server_events.contains(&DataChannelEvent::Message {
            stream_id: 0,
            binary: true,
            data: message
        }));
    }

    #[test]
    fn a_host_that_never_starts_waits_for_the_peers_init() {
        let now = Instant::now();
        let mut server = DataChannelHost::new(DtlsRole::Server);
        assert!(server.poll_transmit(now).is_none());
        assert!(!server.is_connected());
    }

    #[test]
    fn the_channel_the_peer_opens_is_acknowledged_and_carries_binary_messages() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);
        let stream = client.open_channel(now, "mcptt-floor").expect("opens");
        assert_eq!(stream, 0, "the DTLS client uses even stream identifiers");
        let (client_events, server_events) = settle(now, &mut client, &mut server);
        assert!(server_events.contains(&DataChannelEvent::ChannelOpened {
            stream_id: 0,
            label: "mcptt-floor".to_owned()
        }));
        assert!(client_events.contains(&DataChannelEvent::ChannelOpened {
            stream_id: 0,
            label: "mcptt-floor".to_owned()
        }));

        let message = Bytes::from_static(&[
            0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02,
            0x05, 0x00,
        ]);
        client.send(now, 0, true, &message).expect("sends");
        let (_, server_events) = settle(now, &mut client, &mut server);
        assert_eq!(
            server_events,
            vec![DataChannelEvent::Message {
                stream_id: 0,
                binary: true,
                data: message.clone()
            }]
        );

        server.send(now, 0, true, &message).expect("answers");
        let (client_events, _) = settle(now, &mut client, &mut server);
        assert_eq!(
            client_events,
            vec![DataChannelEvent::Message {
                stream_id: 0,
                binary: true,
                data: message
            }]
        );
    }

    #[test]
    fn a_string_message_is_reported_as_a_string() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);
        client.open_channel(now, "chat").expect("opens");
        settle(now, &mut client, &mut server);
        client
            .send(now, 0, false, &Bytes::from_static(b"hello"))
            .expect("sends");
        let (_, server_events) = settle(now, &mut client, &mut server);
        assert_eq!(
            server_events,
            vec![DataChannelEvent::Message {
                stream_id: 0,
                binary: false,
                data: Bytes::from_static(b"hello")
            }]
        );
    }

    #[test]
    fn an_empty_message_travels_under_the_empty_identifier_and_reads_back_empty() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);
        client.open_channel(now, "chat").expect("opens");
        settle(now, &mut client, &mut server);
        client.send(now, 0, true, &Bytes::new()).expect("sends");
        let (_, server_events) = settle(now, &mut client, &mut server);
        assert_eq!(
            server_events,
            vec![DataChannelEvent::Message {
                stream_id: 0,
                binary: true,
                data: Bytes::new()
            }]
        );
    }

    #[test]
    fn the_server_side_uses_odd_stream_identifiers() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);
        assert_eq!(server.open_channel(now, "from-engine").expect("opens"), 1);
        let (_, _) = settle(now, &mut client, &mut server);
        assert!(client.is_open(1) && server.is_open(1));
    }

    #[test]
    fn sending_on_a_channel_that_is_not_open_is_refused() {
        let now = Instant::now();
        let (mut client, _server) = connected_pair(now);
        assert!(matches!(
            client.send(now, 0, true, &Bytes::from_static(b"x")),
            Err(DataChannelError::UnknownChannel(0))
        ));
    }

    #[test]
    fn nothing_can_be_opened_or_sent_before_the_association_is_up() {
        let now = Instant::now();
        let mut server = DataChannelHost::new(DtlsRole::Server);
        assert!(matches!(
            server.open_channel(now, "x"),
            Err(DataChannelError::NotConnected)
        ));
        assert!(matches!(
            server.send(now, 1, true, &Bytes::from_static(b"x")),
            Err(DataChannelError::NotConnected)
        ));
    }

    #[test]
    fn a_message_over_the_limit_is_refused_on_send() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);
        client.open_channel(now, "chat").expect("opens");
        settle(now, &mut client, &mut server);
        let too_big = Bytes::from(vec![0u8; MAX_MESSAGE_SIZE + 1]);
        assert!(matches!(
            client.send(now, 0, true, &too_big),
            Err(DataChannelError::TooLarge { .. })
        ));
    }

    #[test]
    fn garbage_is_ignored_and_does_not_kill_the_host() {
        let now = Instant::now();
        let mut server = DataChannelHost::new(DtlsRole::Server);
        assert!(server.handle_packet(now, &[]).is_empty());
        assert!(server.handle_packet(now, &[0xFF; 7]).is_empty());
        assert!(server.handle_packet(now, &[0x13; 64]).is_empty());
        assert!(!server.is_lost());
    }

    /// RFC 8832 §5.1 DATA_CHANNEL_OPEN, written out byte for byte (message type 3, reliable, priority
    /// 256, no reliability parameter, a label and no protocol) and delivered by a raw `rtc-sctp`
    /// client that shares no code with the host: the host must read the label and answer with the
    /// one-octet DATA_CHANNEL_ACK of §5.2 (message type 2).
    #[test]
    fn a_rfc_8832_data_channel_open_is_acknowledged_with_the_rfc_ack() {
        let now = Instant::now();
        let mut server = DataChannelHost::new(DtlsRole::Server);
        let mut endpoint = Endpoint::new(
            REMOTE,
            TransportProtocol::UDP,
            Arc::new(EndpointConfig::default()),
            None,
        );
        let (handle, mut raw) = endpoint
            .connect(now, ClientConfig::new(TransportConfig::default()), LOCAL)
            .expect("raw client");
        let mut connected = false;
        let mut acknowledged = Vec::new();
        for _ in 0..16 {
            while let Some(transmit) = raw.poll_transmit(now) {
                if let Payload::RawEncode(packets) = transmit.message {
                    for packet in packets {
                        server.handle_packet(now, &packet);
                    }
                }
            }
            while let Some(packet) = server.poll_transmit(now) {
                if let Some((_, DatagramEvent::AssociationEvent(event))) =
                    endpoint.handle(now, LOCAL, None, packet)
                {
                    raw.handle_event(event);
                }
            }
            while let Some(event) = raw.poll() {
                connected |= matches!(event, Event::Connected);
            }
            while let Some(event) = raw.poll_endpoint_event() {
                endpoint.handle_event(handle, event);
            }
            if connected && raw.stream_ids().is_empty() {
                const OPEN: [u8; 23] = [
                    0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, b'm',
                    b'c', b'p', b't', b't', b'-', b'f', b'l', b'o', b'o', b'r',
                ];
                let mut stream = raw
                    .open_stream(4, PayloadProtocolIdentifier::Dcep)
                    .expect("stream");
                stream
                    .write_sctp(
                        now,
                        &Bytes::from_static(&OPEN),
                        PayloadProtocolIdentifier::Dcep,
                    )
                    .expect("writes the OPEN");
            }
            if let Ok(mut stream) = raw.stream(4) {
                if let Ok(Some(chunks)) = stream.read_sctp() {
                    acknowledged = chunks.to_payload(16).expect("fits").to_vec();
                    assert_eq!(chunks.ppi, PayloadProtocolIdentifier::Dcep);
                    break;
                }
            }
        }
        assert_eq!(
            acknowledged,
            vec![0x02],
            "the DATA_CHANNEL_ACK of RFC 8832 §5.2"
        );
        assert!(server.is_open(4));
    }

    #[test]
    fn a_data_channel_open_with_a_label_that_is_not_utf8_is_refused() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);
        // Open a stream by hand on the client's association and write a bad-label OPEN.
        let bad = Bytes::from_static(&[
            0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0xFF, 0xFE,
        ]);
        let association = client.association.as_mut().expect("association");
        association
            .open_stream(6, PayloadProtocolIdentifier::Dcep)
            .expect("stream")
            .write_sctp(now, &bad, PayloadProtocolIdentifier::Dcep)
            .expect("writes");
        settle(now, &mut client, &mut server);
        assert!(!server.is_open(6));
        assert_eq!(server.counters().malformed_dcep, 1);
    }

    #[test]
    fn a_user_message_on_a_stream_that_never_opened_is_counted_and_dropped() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);
        let association = client.association.as_mut().expect("association");
        association
            .open_stream(8, PayloadProtocolIdentifier::Binary)
            .expect("stream")
            .write_sctp(
                now,
                &Bytes::from_static(b"no open first"),
                PayloadProtocolIdentifier::Binary,
            )
            .expect("writes");
        let (_, server_events) = settle(now, &mut client, &mut server);
        assert!(server_events.is_empty());
        assert_eq!(server.counters().unopened_stream, 1);
    }

    #[test]
    fn the_association_retransmits_a_lost_packet_from_its_timer() {
        let mut now = Instant::now();
        let mut client = DataChannelHost::new(DtlsRole::Client);
        let mut server = DataChannelHost::new(DtlsRole::Server);
        client.start(now).expect("starts");
        // The INIT is lost on the wire.
        assert!(client.poll_transmit(now).is_some());
        let deadline = client.poll_timeout().expect("an INIT timer is armed");
        assert!(deadline > now);
        now = deadline + Duration::from_millis(1);
        client.handle_timeout(now);
        settle(now, &mut client, &mut server);
        assert!(client.is_connected() && server.is_connected());
    }
}
