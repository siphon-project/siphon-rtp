//! The TURN relay seam of the UDP backend: framing what leaves through a TURN allocation (RFC 8656
//! §11.1 Send indications, §12 ChannelData, padded over a stream) and de-encapsulating what the
//! server relays back (§11.4 Data indications, §12 ChannelData), with the trust checks that keep a
//! forged datagram from being attributed to a peer. Pure functions over a [`TurnRelay`]; the
//! backend in [`crate::udp`] owns the state and the sockets.

use std::net::SocketAddr;

use bytes::Bytes;
use tokio::net::UdpSocket;

use crate::TurnRelay;

/// What the TURN de-encapsulation decided about one inbound datagram.
pub(crate) enum RelayIngress {
    /// Not relayed traffic — use the datagram and source as they arrived.
    Direct,
    /// A ChannelData message from the allocation's server: use `range` of the buffer as the payload
    /// and attribute it to `peer` rather than the server.
    Unwrapped {
        range: std::ops::Range<usize>,
        peer: SocketAddr,
    },
    /// A Data indication from the allocation's server (RFC 8656 §11.4): `payload` is its DATA,
    /// attributed to the permitted `peer` named by its XOR-PEER-ADDRESS.
    Indication { payload: Vec<u8>, peer: SocketAddr },
    /// Relayed-looking traffic we cannot attribute — a malformed ChannelData message, or one on a
    /// channel this allocation never bound. Dropped rather than passed up as if it came from the
    /// server, which would let the TURN server's address reach the media gate.
    Drop,
}

/// Whether `datagram` is a STUN Data indication (RFC 8656 §11.4): method DATA, class indication.
pub(crate) fn is_data_indication(datagram: &[u8]) -> bool {
    use siphon_rtp_stun::turn;
    let expected = turn::message_type(turn::METHOD_DATA, turn::CLASS_INDICATION).to_be_bytes();
    datagram.len() >= 20 && datagram[..2] == expected
}

/// Unwrap a Data indication from the allocation's server. Dropped unless it is well formed and names
/// a peer the server holds a permission for (RFC 8656 §9): the server relays nothing else, so any
/// other peer address did not come from our allocation.
fn unwrap_data_indication(relay: &TurnRelay, datagram: &[u8]) -> RelayIngress {
    use siphon_rtp_stun::turn;
    let Ok(message) = siphon_rtp_stun::parse(datagram) else {
        return RelayIngress::Drop;
    };
    let (Some(peer), Some(payload)) = (turn::xor_peer_address(&message), turn::data(&message))
    else {
        return RelayIngress::Drop;
    };
    if !relay.is_permitted(peer) {
        return RelayIngress::Drop;
    }
    RelayIngress::Indication {
        payload: payload.to_vec(),
        peer,
    }
}

/// How a datagram for `dst` leaves a leg that relays through a TURN allocation.
pub(crate) enum RelayEgress {
    /// Not a relayed destination: send the bytes to `dst` untouched.
    Direct,
    /// Send `wire` to the TURN server instead: from the endpoint's socket, or queued on the stream
    /// when the allocation rides one.
    Wrapped {
        wire: Vec<u8>,
        server: SocketAddr,
        stream: Option<flume::Sender<Bytes>>,
    },
    /// A relayed destination whose framing could not be built (no OS randomness for the Send
    /// indication's transaction id). Never fall back to sending it direct: the peer is only
    /// reachable through the allocation.
    Unavailable,
}

/// Frame `payload` for `dst` through `relay`: ChannelData for a bound peer (RFC 8656 §12), a Send
/// indication for a permitted peer with no channel (§11.1), nothing for anyone else.
pub(crate) fn relay_egress(relay: &TurnRelay, dst: SocketAddr, payload: &[u8]) -> RelayEgress {
    use siphon_rtp_stun::turn;
    let stream = match &relay.carrier {
        crate::TurnCarrier::Udp => None,
        crate::TurnCarrier::Stream(sender) => Some(sender.clone()),
    };
    if let Some(channel) = relay.channel_for(dst) {
        return RelayEgress::Wrapped {
            // RFC 8656 §12.5: padded to four bytes over a stream, optional over UDP.
            wire: turn::encode_channel_data(channel, payload, stream.is_some()),
            server: relay.server,
            stream,
        };
    }
    if !relay.permitted.contains(&dst) {
        return RelayEgress::Direct;
    }
    // RFC 8489 §6.3.2 / §5: the transaction id of an indication is still random.
    let Some(id) = siphon_rtp_stun::client::TransactionId::new() else {
        return RelayEgress::Unavailable;
    };
    let id = id.as_bytes();
    RelayEgress::Wrapped {
        wire: siphon_rtp_stun::MessageBuilder::new(
            turn::message_type(turn::METHOD_SEND, turn::CLASS_INDICATION),
            id,
        )
        .attribute(
            turn::ATTR_XOR_PEER_ADDRESS,
            &turn::xor_address_value(dst, id),
        )
        .attribute(turn::ATTR_DATA, payload)
        .finish(None, false),
        server: relay.server,
        stream,
    }
}

/// Put framed `egress` on the wire: queue it on the allocation's stream, or send it from `socket`.
/// A full or closed stream queue sheds the packet (`WouldBlock`), because late media is worthless.
pub(crate) async fn emit(
    socket: &UdpSocket,
    egress: RelayEgress,
    dst: SocketAddr,
    payload: &[u8],
) -> std::io::Result<usize> {
    match egress {
        RelayEgress::Direct => socket.send_to(payload, dst).await,
        RelayEgress::Wrapped {
            wire,
            stream: None,
            server,
        } => socket.send_to(&wire, server).await,
        RelayEgress::Wrapped {
            wire,
            stream: Some(stream),
            ..
        } => {
            let sent = wire.len();
            stream
                .try_send(Bytes::from(wire))
                .map(|()| sent)
                .map_err(|_| std::io::ErrorKind::WouldBlock.into())
        }
        RelayEgress::Unavailable => Err(std::io::Error::other(
            "no randomness for a TURN Send indication",
        )),
    }
}

/// Strip RFC 5766 §11 ChannelData framing from a datagram that arrived on a relaying endpoint.
///
/// Only datagrams **from the allocation's own server** are considered, so ChannelData-shaped bytes
/// from any other source stay untouched and cannot be used to forge a peer address.
pub(crate) fn relay_unwrap(
    relay: Option<&TurnRelay>,
    source: SocketAddr,
    datagram: &[u8],
) -> RelayIngress {
    let Some(relay) = relay else {
        return RelayIngress::Direct;
    };
    if source != relay.server {
        return RelayIngress::Direct;
    }
    let Some(&first) = datagram.first() else {
        return RelayIngress::Direct;
    };
    // The server also sends us STUN on this 5-tuple (allocation responses); those are not
    // ChannelData and must reach the client state machine untouched.
    if !siphon_rtp_stun::turn::is_channel_data(first) {
        // RFC 8656 §11.4: a peer's data also arrives as a Data indication until the channel is
        // bound (and for good when ChannelBind fails). Every other STUN message is the client
        // state machine's.
        if is_data_indication(datagram) {
            return unwrap_data_indication(relay, datagram);
        }
        return RelayIngress::Direct;
    }
    let Some(message) = siphon_rtp_stun::turn::parse_channel_data(datagram) else {
        return RelayIngress::Drop;
    };
    let Some(peer) = relay.peer_for_channel(message.channel) else {
        return RelayIngress::Drop;
    };
    // `parse_channel_data` validated the declared length against the buffer, so this range is in
    // bounds by construction.
    let start = 4;
    let end = start + message.data.len();
    RelayIngress::Unwrapped {
        range: start..end,
        peer,
    }
}
