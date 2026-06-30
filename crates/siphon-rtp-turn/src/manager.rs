//! The allocation actor — the single owner of all TURN allocation state (RFC 5766).
//!
//! Per the project's concurrency rules this is one task holding its state directly (an
//! [`IndexMap`] of allocations, not a shared `Arc<Mutex<…>>`); peers reach it only through the
//! bounded `flume` mailbox of [`Message`]s. It never holds a borrow across an `.await`: each handler
//! reads the decision it needs out of the allocation table, drops the borrow, then performs its
//! socket I/O. Lifetimes (allocation / permission / channel / nonce) all run on the datapath's
//! injected logical clock so the reaper is deterministic.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use indexmap::IndexMap;
use siphon_rtp_datapath::{Datapath, Endpoint, EndpointId, FlowAction};
use siphon_rtp_stun::{self as stun, turn, StunMessage};

use crate::credentials::{AuthResult, CredentialVerifier, NonceFactory};
use crate::fastpath::{ChannelRoute, TurnFastPath};
use crate::{ClientTransport, FiveTuple, TransportProtocol, TurnConfig, UnixClock};

/// A message into the allocation actor.
pub(crate) enum Message {
    /// A datagram from a client (any listener): a STUN request/indication or a ChannelData message.
    Client {
        /// The allocation key derived from the listener.
        five_tuple: FiveTuple,
        /// How to write replies back to this client.
        transport: ClientTransport,
        /// The raw datagram.
        datagram: Bytes,
    },
    /// A datagram a peer sent to a relay endpoint, delivered by the datapath Redirect dispatcher.
    RelayInbound {
        /// The relay endpoint it arrived on.
        endpoint: EndpointId,
        /// The peer's transport address.
        peer: SocketAddr,
        /// The relayed payload.
        data: Bytes,
    },
    /// Sweep expired allocations/permissions/channels against the logical clock.
    Tick,
    /// Reply with the current live-allocation count (observability + the leak-soak drain check).
    Count(tokio::sync::oneshot::Sender<usize>),
    /// Stop the actor.
    Shutdown,
}

/// One channel binding (RFC 5766 §11): the peer it targets and when it expires.
struct ChannelBinding {
    peer: SocketAddr,
    expires_at: u64,
}

/// One TURN allocation (RFC 5766 §2.2).
struct Allocation {
    /// How to reach the client (the reply path for Data/ChannelData).
    transport: ClientTransport,
    /// The relay endpoint drawn from the datapath pool.
    relay: Endpoint,
    /// The credential username (for the per-credential quota).
    username: String,
    /// Expiry tick (logical clock).
    expires_at: u64,
    /// Install-time permissions: peer IP → expiry tick (RFC 5766 §8; per-IP, port-independent).
    permissions: IndexMap<std::net::IpAddr, u64>,
    /// Channel bindings: channel number → binding (RFC 5766 §11).
    channels: IndexMap<u16, ChannelBinding>,
    /// Reverse index: peer address → its bound channel.
    peer_to_channel: HashMap<SocketAddr, u16>,
    /// The last Allocate `(transaction_id, response)` for idempotent retransmission (RFC 5766 §6.2).
    last_allocate: Option<([u8; 12], Bytes)>,
    /// Total bytes relayed, for the per-allocation bandwidth cap.
    bytes_relayed: u64,
}

/// The single-owner allocation manager.
pub struct AllocationManager<D> {
    datapath: Arc<D>,
    config: TurnConfig,
    unix_clock: Arc<dyn UnixClock>,
    nonce: NonceFactory,
    verifier: CredentialVerifier,
    allocations: IndexMap<FiveTuple, Allocation>,
    relay_index: HashMap<EndpointId, FiveTuple>,
    quota: HashMap<String, usize>,
    indication_counter: u64,
    fast_path: Box<dyn TurnFastPath>,
}

impl<D: Datapath> AllocationManager<D> {
    /// Build a manager over `datapath`, authenticating with `config`'s realm + secret.
    #[must_use]
    pub fn new(
        datapath: Arc<D>,
        config: TurnConfig,
        unix_clock: Arc<dyn UnixClock>,
        nonce: NonceFactory,
        fast_path: Box<dyn TurnFastPath>,
    ) -> Self {
        let verifier =
            CredentialVerifier::new(config.static_auth_secret.clone(), config.realm.clone());
        Self {
            datapath,
            config,
            unix_clock,
            nonce,
            verifier,
            allocations: IndexMap::new(),
            relay_index: HashMap::new(),
            quota: HashMap::new(),
            indication_counter: 0,
            fast_path,
        }
    }

    /// Run the actor until the mailbox closes or a [`Message::Shutdown`] arrives.
    pub(crate) async fn run(mut self, mailbox: flume::Receiver<Message>) {
        while let Ok(message) = mailbox.recv_async().await {
            match message {
                Message::Client {
                    five_tuple,
                    transport,
                    datagram,
                } => self.handle_client(five_tuple, transport, &datagram).await,
                Message::RelayInbound {
                    endpoint,
                    peer,
                    data,
                } => self.handle_relay_inbound(endpoint, peer, &data).await,
                Message::Tick => self.reap().await,
                Message::Count(reply) => {
                    let _ = reply.send(self.allocations.len());
                }
                Message::Shutdown => break,
            }
        }
    }

    /// Demultiplex a client datagram (RFC 5766 §11: ChannelData vs STUN) and dispatch it.
    async fn handle_client(
        &mut self,
        five_tuple: FiveTuple,
        transport: ClientTransport,
        datagram: &[u8],
    ) {
        let Some(&first) = datagram.first() else {
            return;
        };
        if turn::is_channel_data(first) {
            self.handle_channel_data(five_tuple, datagram).await;
            return;
        }
        let Ok(message) = stun::parse(datagram) else {
            return; // malformed STUN → drop (never panic, A4)
        };
        let method = turn::method_of(message.message_type);
        let class = turn::class_of(message.message_type);
        match class {
            turn::CLASS_INDICATION if method == turn::METHOD_SEND => {
                self.handle_send_indication(five_tuple, &message).await;
            }
            turn::CLASS_REQUEST => match method {
                turn::METHOD_ALLOCATE => {
                    self.handle_allocate(five_tuple, transport, &message, datagram)
                        .await;
                }
                turn::METHOD_REFRESH => {
                    self.handle_refresh(five_tuple, transport, &message, datagram)
                        .await;
                }
                turn::METHOD_CREATE_PERMISSION => {
                    self.handle_create_permission(five_tuple, transport, &message, datagram)
                        .await;
                }
                turn::METHOD_CHANNEL_BIND => {
                    self.handle_channel_bind(five_tuple, transport, &message, datagram)
                        .await;
                }
                _ => {} // unknown method → ignore
            },
            _ => {} // responses / other indications → ignore
        }
    }

    /// Handle an Allocate request (RFC 5766 §6.2).
    async fn handle_allocate(
        &mut self,
        five_tuple: FiveTuple,
        transport: ClientTransport,
        message: &StunMessage,
        raw: &[u8],
    ) {
        let txid = message.transaction_id;
        let method = turn::METHOD_ALLOCATE;
        let Some((username, key)) = self
            .require_auth(method, &txid, five_tuple.client, &transport, message, raw)
            .await
        else {
            return;
        };

        if let Some(existing) = self.allocations.get(&five_tuple) {
            // Idempotent retransmission: same transaction id → resend the cached response.
            if let Some((cached_txid, cached)) = &existing.last_allocate {
                if *cached_txid == txid {
                    let response = cached.clone();
                    transport.send(&response).await;
                    return;
                }
            }
            // A different Allocate on a live 5-tuple → 437 Allocation Mismatch.
            self.send_error(
                method,
                &txid,
                &transport,
                turn::ERROR_ALLOCATION_MISMATCH,
                "Allocation Mismatch",
                Some(&key),
            )
            .await;
            return;
        }

        // REQUESTED-TRANSPORT must be UDP (RFC 5766 §6.2).
        if turn::requested_transport(message) != Some(turn::TRANSPORT_UDP) {
            self.send_error(
                method,
                &txid,
                &transport,
                turn::ERROR_UNSUPPORTED_TRANSPORT,
                "Unsupported Transport Protocol",
                Some(&key),
            )
            .await;
            return;
        }
        // EVEN-PORT / RESERVATION-TOKEN are unsatisfiable on the ephemeral-port pool, which hands
        // out `:0` ports with no number control — reject honestly with 508 rather than silently
        // ignoring the request (deviation from RFC 5766 §6.2; WebRTC never asks for these).
        if turn::has_even_port(message) || turn::has_reservation_token(message) {
            self.send_error(
                method,
                &txid,
                &transport,
                turn::ERROR_INSUFFICIENT_CAPACITY,
                "Insufficient Capacity",
                Some(&key),
            )
            .await;
            return;
        }
        // Per-credential allocation quota → 486 (docs/security-and-nat.md §11, R4).
        if self.quota.get(&username).copied().unwrap_or(0) >= self.config.max_allocations_per_user {
            self.send_error(
                method,
                &txid,
                &transport,
                turn::ERROR_ALLOCATION_QUOTA_REACHED,
                "Allocation Quota Reached",
                Some(&key),
            )
            .await;
            return;
        }
        // Draw a relay endpoint from the bounded datapath pool → 508 on exhaustion (R4).
        let relay = match self.datapath.alloc_endpoint().await {
            Ok(endpoint) => endpoint,
            Err(error) => {
                tracing::debug!(%error, "TURN relay pool exhausted");
                self.send_error(
                    method,
                    &txid,
                    &transport,
                    turn::ERROR_INSUFFICIENT_CAPACITY,
                    "Insufficient Capacity",
                    Some(&key),
                )
                .await;
                return;
            }
        };
        // Peer datagrams on the relay socket come back to this actor via the Redirect dispatcher.
        if self
            .datapath
            .install_flow(relay.id, FlowAction::Redirect)
            .is_err()
        {
            self.datapath.remove_endpoint(relay.id).await;
            self.send_error(
                method,
                &txid,
                &transport,
                turn::ERROR_INSUFFICIENT_CAPACITY,
                "Insufficient Capacity",
                Some(&key),
            )
            .await;
            return;
        }

        let now_tick = self.datapath.now_ticks();
        let lifetime = self.granted_lifetime(message);
        let relay_addr = self.advertised_relay_address(&relay);
        let response = self
            .message_builder(turn::message_type(method, turn::CLASS_SUCCESS), &txid)
            .attribute(
                turn::ATTR_XOR_RELAYED_ADDRESS,
                &turn::xor_address_value(relay_addr, &txid),
            )
            .attribute(turn::ATTR_LIFETIME, &turn::lifetime_value(lifetime))
            .attribute(
                turn::ATTR_XOR_MAPPED_ADDRESS,
                &turn::xor_address_value(five_tuple.client, &txid),
            )
            .finish(Some(&key), self.config.include_fingerprint);

        let allocation = Allocation {
            transport: transport.clone(),
            relay,
            username: username.clone(),
            expires_at: now_tick + u64::from(lifetime),
            permissions: IndexMap::new(),
            channels: IndexMap::new(),
            peer_to_channel: HashMap::new(),
            last_allocate: Some((txid, Bytes::copy_from_slice(&response))),
            bytes_relayed: 0,
        };
        self.relay_index.insert(relay.id, five_tuple);
        self.allocations.insert(five_tuple, allocation);
        *self.quota.entry(username).or_insert(0) += 1;
        tracing::debug!(client = %five_tuple.client, relay = %relay_addr, "TURN allocation created");
        transport.send(&response).await;
    }

    /// Handle a Refresh request (RFC 5766 §7): a LIFETIME of 0 deletes the allocation.
    async fn handle_refresh(
        &mut self,
        five_tuple: FiveTuple,
        transport: ClientTransport,
        message: &StunMessage,
        raw: &[u8],
    ) {
        let txid = message.transaction_id;
        let method = turn::METHOD_REFRESH;
        let Some((_username, key)) = self
            .require_auth(method, &txid, five_tuple.client, &transport, message, raw)
            .await
        else {
            return;
        };
        if !self.allocations.contains_key(&five_tuple) {
            self.send_error(
                method,
                &txid,
                &transport,
                turn::ERROR_ALLOCATION_MISMATCH,
                "Allocation Mismatch",
                Some(&key),
            )
            .await;
            return;
        }
        let requested = turn::lifetime(message).unwrap_or(self.config.default_lifetime);
        let granted = if requested == 0 {
            self.delete_allocation(&five_tuple).await;
            0
        } else {
            let lifetime = requested.min(self.config.max_lifetime).max(1);
            let now_tick = self.datapath.now_ticks();
            if let Some(allocation) = self.allocations.get_mut(&five_tuple) {
                allocation.expires_at = now_tick + u64::from(lifetime);
            }
            lifetime
        };
        let response = self
            .message_builder(turn::message_type(method, turn::CLASS_SUCCESS), &txid)
            .attribute(turn::ATTR_LIFETIME, &turn::lifetime_value(granted))
            .finish(Some(&key), self.config.include_fingerprint);
        transport.send(&response).await;
    }

    /// Handle a CreatePermission request (RFC 5766 §9).
    async fn handle_create_permission(
        &mut self,
        five_tuple: FiveTuple,
        transport: ClientTransport,
        message: &StunMessage,
        raw: &[u8],
    ) {
        let txid = message.transaction_id;
        let method = turn::METHOD_CREATE_PERMISSION;
        let Some((_username, key)) = self
            .require_auth(method, &txid, five_tuple.client, &transport, message, raw)
            .await
        else {
            return;
        };
        if !self.allocations.contains_key(&five_tuple) {
            self.send_error(
                method,
                &txid,
                &transport,
                turn::ERROR_ALLOCATION_MISMATCH,
                "Allocation Mismatch",
                Some(&key),
            )
            .await;
            return;
        }
        let peers = turn::xor_peer_addresses(message);
        if peers.is_empty() {
            self.send_error(
                method,
                &txid,
                &transport,
                turn::ERROR_BAD_REQUEST,
                "Bad Request",
                Some(&key),
            )
            .await;
            return;
        }
        // Any denied peer rejects the whole request (anti-SSRF, R3) — install nothing.
        if peers
            .iter()
            .any(|peer| !self.config.denied_peers.permits(peer.ip()))
        {
            self.send_error(
                method,
                &txid,
                &transport,
                turn::ERROR_FORBIDDEN,
                "Forbidden",
                Some(&key),
            )
            .await;
            return;
        }
        let expiry = self.datapath.now_ticks() + u64::from(self.config.permission_lifetime);
        if let Some(allocation) = self.allocations.get_mut(&five_tuple) {
            for peer in peers {
                allocation.permissions.insert(peer.ip(), expiry);
            }
        }
        let response = self
            .message_builder(turn::message_type(method, turn::CLASS_SUCCESS), &txid)
            .finish(Some(&key), self.config.include_fingerprint);
        transport.send(&response).await;
    }

    /// Handle a ChannelBind request (RFC 5766 §11): bind a channel to a peer (and imply a permission).
    async fn handle_channel_bind(
        &mut self,
        five_tuple: FiveTuple,
        transport: ClientTransport,
        message: &StunMessage,
        raw: &[u8],
    ) {
        let txid = message.transaction_id;
        let method = turn::METHOD_CHANNEL_BIND;
        let Some((_username, key)) = self
            .require_auth(method, &txid, five_tuple.client, &transport, message, raw)
            .await
        else {
            return;
        };
        if !self.allocations.contains_key(&five_tuple) {
            self.send_error(
                method,
                &txid,
                &transport,
                turn::ERROR_ALLOCATION_MISMATCH,
                "Allocation Mismatch",
                Some(&key),
            )
            .await;
            return;
        }
        let (Some(channel), Some(peer)) = (
            turn::channel_number(message),
            turn::xor_peer_address(message),
        ) else {
            self.send_error(
                method,
                &txid,
                &transport,
                turn::ERROR_BAD_REQUEST,
                "Bad Request",
                Some(&key),
            )
            .await;
            return;
        };
        // The channel number must be in range, and the peer must be permitted (R3).
        let consistent = self.allocations.get(&five_tuple).is_some_and(|allocation| {
            // RFC 5766 §11.2: a channel must not rebind to a different peer, nor a peer to a
            // different channel.
            allocation
                .channels
                .get(&channel)
                .is_none_or(|binding| binding.peer == peer)
                && allocation
                    .peer_to_channel
                    .get(&peer)
                    .is_none_or(|bound| *bound == channel)
        });
        if !turn::valid_channel_number(channel) || !consistent {
            self.send_error(
                method,
                &txid,
                &transport,
                turn::ERROR_BAD_REQUEST,
                "Bad Request",
                Some(&key),
            )
            .await;
            return;
        }
        if !self.config.denied_peers.permits(peer.ip()) {
            self.send_error(
                method,
                &txid,
                &transport,
                turn::ERROR_FORBIDDEN,
                "Forbidden",
                Some(&key),
            )
            .await;
            return;
        }
        let now_tick = self.datapath.now_ticks();
        let channel_expiry = now_tick + u64::from(self.config.channel_lifetime);
        let permission_expiry = now_tick + u64::from(self.config.permission_lifetime);
        let mut relay_addr = None;
        if let Some(allocation) = self.allocations.get_mut(&five_tuple) {
            allocation.channels.insert(
                channel,
                ChannelBinding {
                    peer,
                    expires_at: channel_expiry,
                },
            );
            allocation.peer_to_channel.insert(peer, channel);
            // ChannelBind installs/refreshes a permission for the peer (RFC 5766 §11).
            allocation.permissions.insert(peer.ip(), permission_expiry);
            relay_addr = Some(allocation.relay.local_addr);
        }
        // Offer the bound channel to the kernel fast path — UDP client legs only, since the kernel
        // rewrite is UDP-to-UDP (M-T8). The default NoFastPath ignores it.
        if let (TransportProtocol::Udp, Some(relay)) = (five_tuple.transport, relay_addr) {
            self.fast_path.install_channel(ChannelRoute {
                channel,
                client: five_tuple.client,
                listener: five_tuple.server,
                peer,
                relay,
            });
        }
        let response = self
            .message_builder(turn::message_type(method, turn::CLASS_SUCCESS), &txid)
            .finish(Some(&key), self.config.include_fingerprint);
        transport.send(&response).await;
    }

    /// Handle a Send indication (RFC 5766 §10): client → peer, no auth, no response.
    async fn handle_send_indication(&mut self, five_tuple: FiveTuple, message: &StunMessage) {
        let (Some(peer), Some(data)) = (turn::xor_peer_address(message), turn::data(message))
        else {
            return;
        };
        if !self.config.denied_peers.permits(peer.ip()) {
            return;
        }
        let now_tick = self.datapath.now_ticks();
        let relay_id = {
            let Some(allocation) = self.allocations.get(&five_tuple) else {
                return;
            };
            // A Send to a peer with no permission is silently discarded (RFC 5766 §10).
            if allocation
                .permissions
                .get(&peer.ip())
                .is_none_or(|expiry| *expiry <= now_tick)
            {
                return;
            }
            allocation.relay.id
        };
        self.relay_to_peer(&five_tuple, relay_id, peer, data).await;
    }

    /// Handle a ChannelData message (RFC 5766 §11.5): client → peer over a bound channel.
    async fn handle_channel_data(&mut self, five_tuple: FiveTuple, datagram: &[u8]) {
        let Some(channel_data) = turn::parse_channel_data(datagram) else {
            return;
        };
        let now_tick = self.datapath.now_ticks();
        let target = {
            let Some(allocation) = self.allocations.get(&five_tuple) else {
                return;
            };
            match allocation.channels.get(&channel_data.channel) {
                Some(binding) if binding.expires_at > now_tick => {
                    Some((allocation.relay.id, binding.peer))
                }
                _ => None, // no/expired channel → drop
            }
        };
        let Some((relay_id, peer)) = target else {
            return;
        };
        if !self.config.denied_peers.permits(peer.ip()) {
            return;
        }
        self.relay_to_peer(&five_tuple, relay_id, peer, channel_data.data)
            .await;
    }

    /// Relay `data` from the allocation's relay endpoint toward `peer`, honouring the bandwidth cap.
    async fn relay_to_peer(
        &mut self,
        five_tuple: &FiveTuple,
        relay_id: EndpointId,
        peer: SocketAddr,
        data: &[u8],
    ) {
        if !self.within_budget(five_tuple, data.len()) {
            return;
        }
        if let Err(error) = self.datapath.send(relay_id, peer, data).await {
            tracing::debug!(%peer, %error, "TURN relay send failed");
            return;
        }
        if let Some(allocation) = self.allocations.get_mut(five_tuple) {
            allocation.bytes_relayed += data.len() as u64;
        }
    }

    /// Handle a peer's datagram arriving on a relay endpoint (RFC 5766 §8/§10): permission-gate it,
    /// then deliver to the client as ChannelData (if a channel is bound) or a Data indication.
    async fn handle_relay_inbound(&mut self, endpoint: EndpointId, peer: SocketAddr, data: &[u8]) {
        let Some(&five_tuple) = self.relay_index.get(&endpoint) else {
            return;
        };
        let now_tick = self.datapath.now_ticks();

        enum Frame {
            Channel(u16),
            Indication,
        }
        let routed = {
            let Some(allocation) = self.allocations.get(&five_tuple) else {
                return;
            };
            // No permission for this peer's IP → drop (RFC 5766 §8).
            if allocation
                .permissions
                .get(&peer.ip())
                .is_none_or(|expiry| *expiry <= now_tick)
            {
                return;
            }
            if !self.config.denied_peers.permits(peer.ip()) {
                return;
            }
            if !self.within_budget(&five_tuple, data.len()) {
                return;
            }
            let frame = match allocation.peer_to_channel.get(&peer) {
                Some(&channel)
                    if allocation
                        .channels
                        .get(&channel)
                        .is_some_and(|binding| binding.expires_at > now_tick) =>
                {
                    Frame::Channel(channel)
                }
                _ => Frame::Indication,
            };
            (
                allocation.transport.clone(),
                frame,
                allocation.transport.is_stream(),
            )
        };
        let (transport, frame, pad) = routed;
        let message = match frame {
            // ChannelData is padded to 4 bytes only on a stream (TCP/TLS) transport (RFC 5766 §11.5).
            Frame::Channel(channel) => turn::encode_channel_data(channel, data, pad),
            Frame::Indication => self.data_indication(peer, data),
        };
        transport.send(&message).await;
        if let Some(allocation) = self.allocations.get_mut(&five_tuple) {
            allocation.bytes_relayed += data.len() as u64;
        }
    }

    /// Authenticate a request; on failure, send the 401/438 challenge and return `None`.
    async fn require_auth(
        &self,
        method: u16,
        txid: &[u8; 12],
        client: SocketAddr,
        transport: &ClientTransport,
        message: &StunMessage,
        raw: &[u8],
    ) -> Option<(String, [u8; 16])> {
        let now_tick = self.datapath.now_ticks();
        let unix_now = self.unix_clock.now_unix();
        match self
            .verifier
            .authenticate(message, raw, unix_now, &self.nonce, now_tick, client)
        {
            AuthResult::Ok { username, key } => Some((username, key)),
            AuthResult::Unauthorized => {
                self.send_challenge(
                    method,
                    txid,
                    client,
                    transport,
                    turn::ERROR_UNAUTHORIZED,
                    "Unauthorized",
                )
                .await;
                None
            }
            AuthResult::StaleNonce => {
                self.send_challenge(
                    method,
                    txid,
                    client,
                    transport,
                    turn::ERROR_STALE_NONCE,
                    "Stale Nonce",
                )
                .await;
                None
            }
        }
    }

    /// Send a long-term-credential challenge: an error response carrying REALM + a fresh NONCE and no
    /// MESSAGE-INTEGRITY (the client is not yet authenticated). RFC 5389 §10.2.
    async fn send_challenge(
        &self,
        method: u16,
        txid: &[u8; 12],
        client: SocketAddr,
        transport: &ClientTransport,
        code: u16,
        reason: &str,
    ) {
        let nonce = self.nonce.issue(client, self.datapath.now_ticks());
        let response = self
            .message_builder(turn::message_type(method, turn::CLASS_ERROR), txid)
            .attribute(turn::ATTR_ERROR_CODE, &turn::error_code_value(code, reason))
            .attribute(turn::ATTR_REALM, self.config.realm.as_bytes())
            .attribute(turn::ATTR_NONCE, nonce.as_bytes())
            .finish(None, self.config.include_fingerprint);
        transport.send(&response).await;
    }

    /// Send an error response, signed with MESSAGE-INTEGRITY when `key` is `Some` (an authenticated
    /// failure such as 437/442/486/508/403).
    async fn send_error(
        &self,
        method: u16,
        txid: &[u8; 12],
        transport: &ClientTransport,
        code: u16,
        reason: &str,
        key: Option<&[u8; 16]>,
    ) {
        let response = self
            .message_builder(turn::message_type(method, turn::CLASS_ERROR), txid)
            .attribute(turn::ATTR_ERROR_CODE, &turn::error_code_value(code, reason))
            .finish(key.map(|k| &k[..]), self.config.include_fingerprint);
        transport.send(&response).await;
    }

    /// A response builder pre-seeded with the configured SOFTWARE attribute.
    fn message_builder(&self, message_type: u16, txid: &[u8; 12]) -> stun::MessageBuilder {
        let builder = stun::MessageBuilder::new(message_type, txid);
        match &self.config.software {
            Some(software) => builder.attribute(turn::ATTR_SOFTWARE, software.as_bytes()),
            None => builder,
        }
    }

    /// Build a Data indication (RFC 5766 §10) for `data` from `peer` — no SOFTWARE, no integrity, to
    /// keep the per-packet relay path lean.
    fn data_indication(&mut self, peer: SocketAddr, data: &[u8]) -> Vec<u8> {
        let txid = self.next_indication_txid();
        stun::MessageBuilder::new(
            turn::message_type(turn::METHOD_DATA, turn::CLASS_INDICATION),
            &txid,
        )
        .attribute(
            turn::ATTR_XOR_PEER_ADDRESS,
            &turn::xor_address_value(peer, &txid),
        )
        .attribute(turn::ATTR_DATA, data)
        .finish(None, false)
    }

    /// A distinct transaction id for each Data indication (indications are uncorrelated, RFC 5389 §6).
    fn next_indication_txid(&mut self) -> [u8; 12] {
        self.indication_counter = self.indication_counter.wrapping_add(1);
        let mut txid = [0u8; 12];
        txid[4..12].copy_from_slice(&self.indication_counter.to_be_bytes());
        txid
    }

    /// The lifetime to grant: the requested value (or the default) clamped to `[1, max_lifetime]`.
    fn granted_lifetime(&self, message: &StunMessage) -> u32 {
        turn::lifetime(message)
            .unwrap_or(self.config.default_lifetime)
            .min(self.config.max_lifetime)
            .max(1)
    }

    /// The address to advertise in XOR-RELAYED-ADDRESS: the configured public IP (keeping the
    /// datapath-assigned port), or the relay socket's own address when none is configured.
    fn advertised_relay_address(&self, relay: &Endpoint) -> SocketAddr {
        match self.config.relay_address {
            Some(ip) => SocketAddr::new(ip, relay.local_addr.port()),
            None => relay.local_addr,
        }
    }

    /// Whether relaying `additional` bytes stays within the per-allocation bandwidth cap (R6).
    fn within_budget(&self, five_tuple: &FiveTuple, additional: usize) -> bool {
        match self.config.max_bytes_per_allocation {
            None => true,
            Some(cap) => self
                .allocations
                .get(five_tuple)
                .is_some_and(|allocation| allocation.bytes_relayed + additional as u64 <= cap),
        }
    }

    /// Tear down an allocation: free its relay endpoint and quota slot.
    async fn delete_allocation(&mut self, five_tuple: &FiveTuple) {
        if let Some(allocation) = self.allocations.swap_remove(five_tuple) {
            self.relay_index.remove(&allocation.relay.id);
            self.datapath.remove_endpoint(allocation.relay.id).await;
            // Withdraw every fast-path channel route this allocation installed.
            if five_tuple.transport == TransportProtocol::Udp {
                for (channel, binding) in &allocation.channels {
                    self.fast_path.remove_channel(ChannelRoute {
                        channel: *channel,
                        client: five_tuple.client,
                        listener: five_tuple.server,
                        peer: binding.peer,
                        relay: allocation.relay.local_addr,
                    });
                }
            }
            if let Some(count) = self.quota.get_mut(&allocation.username) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.quota.remove(&allocation.username);
                }
            }
            tracing::debug!(client = %five_tuple.client, "TURN allocation freed");
        }
    }

    /// Sweep expired permissions, channels, and allocations against the logical clock (RFC 5766
    /// §6.2/§8/§11; the TURN analogue of the media-timeout reaper).
    async fn reap(&mut self) {
        let now = self.datapath.now_ticks();
        let mut expired_allocations = Vec::new();
        let mut withdrawn_channels = Vec::new();
        for (five_tuple, allocation) in &mut self.allocations {
            allocation.permissions.retain(|_ip, expiry| *expiry > now);
            let dead: Vec<u16> = allocation
                .channels
                .iter()
                .filter(|(_, binding)| binding.expires_at <= now)
                .map(|(channel, _)| *channel)
                .collect();
            for channel in dead {
                if let Some(binding) = allocation.channels.swap_remove(&channel) {
                    allocation.peer_to_channel.remove(&binding.peer);
                    if five_tuple.transport == TransportProtocol::Udp {
                        withdrawn_channels.push(ChannelRoute {
                            channel,
                            client: five_tuple.client,
                            listener: five_tuple.server,
                            peer: binding.peer,
                            relay: allocation.relay.local_addr,
                        });
                    }
                }
            }
            if allocation.expires_at <= now {
                expired_allocations.push(*five_tuple);
            }
        }
        for route in withdrawn_channels {
            self.fast_path.remove_channel(route);
        }
        for five_tuple in expired_allocations {
            self.delete_allocation(&five_tuple).await;
        }
    }
}
