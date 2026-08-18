//! The TURN **client** (RFC 5766, updated by RFC 8656): the allocation lifecycle a relayed ICE
//! candidate needs, as a pure state machine.
//!
//! Pure codec + logic, **zero I/O**, like [`client`](crate::client): [`TurnClient::poll`] says what to
//! transmit at a given logical millisecond, [`TurnClient::on_datagram`] takes the replies back, and the
//! owning task does the socket work. That is what makes the long-term-credential challenge, the
//! refresh schedule, and the permission/channel bookkeeping testable without a server or a runtime.
//!
//! # What it does
//!
//! - **Allocate** (RFC 5766 §6): the first request is sent *without* credentials, because the client
//!   does not know the server's realm or a nonce yet. The server answers `401 Unauthorized` carrying
//!   REALM and NONCE (§6.2); the request is then retried with USERNAME/REALM/NONCE and a
//!   MESSAGE-INTEGRITY keyed by `MD5(username:realm:password)` (§4). This unauthenticated-then-
//!   challenged exchange is mandatory — a client that sends credentials up front does not know the
//!   realm to key them with.
//! - **Refresh** (§7): the allocation dies at its LIFETIME unless refreshed. Refreshes are scheduled
//!   well inside it, and a `Refresh` with `LIFETIME: 0` deletes it on teardown (§7.1) rather than
//!   leaving the server holding a relay port until it times out.
//! - **CreatePermission** (§9): the server drops traffic from a peer with no permission installed, so
//!   each remote candidate ICE may check against needs one. Permissions expire after 5 minutes (§8),
//!   so they are refreshed on the same clock as the allocation.
//! - **ChannelBind** (§11): binds a 4-byte channel number to a peer, after which data uses
//!   `ChannelData` framing instead of 36-byte Send/Data indications. For 20 ms audio that is the
//!   difference between 4 and 36 bytes of overhead per packet, so the client binds a channel for
//!   every peer it sends to rather than staying on indications.
//! - **Stale nonce** (`438`, §10): the server rotates its nonce; the request is retried once with the
//!   new one. Any request may draw it, so the retry is handled centrally rather than per-method.
//!
//! # Bounded by construction
//!
//! Every request retransmits per RFC 8489 §6.2.1 and gives up; a server that is down costs one
//! bounded delay and yields *no* relayed candidate, never a hung call. The client never retries a
//! `401` more than once (a second challenge to an authenticated request means the credentials are
//! wrong, not that the nonce was stale), so a misconfigured secret cannot loop.

use std::net::SocketAddr;

use crate::client::{RetransmitSchedule, Transaction, TransactionAction, TransactionId};
use crate::turn::{self, long_term_key};
use crate::{parse, MessageBuilder, StunMessage};

/// The lifetime the client asks for in an Allocate (RFC 5766 §6.2 recommends 600 s; the server may
/// shorten it, and the granted value is what the refresh schedule uses).
pub const DEFAULT_LIFETIME_SECONDS: u32 = 600;

/// How far inside the granted lifetime a refresh is sent, as a percentage. RFC 5766 §7 says a client
/// should refresh "before expiration"; 75 % leaves room for a full RFC 8489 retransmission run before
/// the allocation would actually lapse.
const REFRESH_AT_PERCENT: u32 = 75;

/// The lifetime the server grants a permission, in seconds (RFC 5766 §8 — fixed at 5 minutes, not
/// negotiable and not carried in the response).
pub const PERMISSION_LIFETIME_SECONDS: u32 = 300;

/// The lifetime the server grants a channel binding, in seconds (RFC 5766 §11 — fixed at 10 minutes).
pub const CHANNEL_LIFETIME_SECONDS: u32 = 600;

/// The first channel number the client hands out (RFC 5766 §11: `0x4000`–`0x7FFF`).
const FIRST_CHANNEL: u16 = turn::MIN_CHANNEL_NUMBER;

/// Long-term credentials for a TURN server (RFC 5766 §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnCredentials {
    /// The username, as the server knows it (for a coturn REST deployment, the timestamped one).
    pub username: String,
    /// The shared secret.
    pub password: String,
}

impl TurnCredentials {
    /// Build credentials from a username and password.
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

/// What [`TurnClient::poll`] asks the owning task to do at this millisecond.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TurnAction {
    /// Nothing due — poll again later.
    Idle,
    /// Transmit `datagram` to the TURN server (a first request or a retransmit).
    Send {
        /// The raw STUN/TURN message bytes.
        datagram: Vec<u8>,
    },
}

/// Why an allocation ended, for the caller's log line. Never a panic and never silent: a relayed
/// candidate that cannot be obtained is a real capability loss, so the reason is always stated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TurnFailure {
    /// The server never answered — every retransmission of a request timed out.
    Timeout,
    /// The server rejected us with this error code and reason (RFC 5389 §15.6). `401` here means the
    /// credentials are wrong: the challenge was already answered once.
    Rejected {
        /// The numeric ERROR-CODE.
        code: u16,
        /// The reason phrase, if the server sent a readable one.
        reason: String,
    },
    /// A response arrived that we could not use — unparseable, or a success with no
    /// XOR-RELAYED-ADDRESS (RFC 5766 §6.3 requires one).
    Malformed(&'static str),
    /// The OS RNG was unavailable, so no transaction id could be drawn. Never `unwrap`ed.
    NoRandomness,
}

/// The lifecycle of one allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TurnState {
    /// The Allocate exchange is in flight (either the unauthenticated probe or the credentialed
    /// retry).
    Allocating,
    /// The allocation is live; `relayed` is the address peers reach us at.
    Allocated {
        /// The relayed transport address the server assigned (RFC 5766 §6.3 XOR-RELAYED-ADDRESS) —
        /// this is what becomes the ICE relayed candidate.
        relayed: SocketAddr,
        /// Our reflexive address as the TURN server saw it (XOR-MAPPED-ADDRESS). A TURN server is
        /// required to answer Binding requests (RFC 8656 §12), and an Allocate response carries this
        /// too — so one exchange yields both the relayed *and* the server-reflexive candidate.
        mapped: Option<SocketAddr>,
    },
    /// The allocation is gone. Terminal.
    Failed(TurnFailure),
    /// The allocation was deleted by us (a `Refresh` with lifetime 0). Terminal.
    Closed,
}

/// What a request in flight is trying to achieve — decides how its response is interpreted and what
/// is retried after a `438 Stale Nonce`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Pending {
    /// The credential-less first Allocate, whose only useful answer is the `401` challenge.
    AllocateProbe,
    /// The credentialed Allocate.
    Allocate,
    /// Keeping the allocation alive, or (`lifetime == 0`) deleting it.
    Refresh { lifetime: u32 },
    /// Installing/refreshing a permission for a peer (RFC 5766 §9).
    CreatePermission { peer: SocketAddr },
    /// Binding a channel to a peer (RFC 5766 §11).
    ChannelBind { peer: SocketAddr, channel: u16 },
}

/// One request in flight: its transaction and what it is for.
#[derive(Clone, Debug)]
struct InFlight {
    transaction: Transaction,
    /// The encoded request, kept so a retransmit re-sends the identical bytes — RFC 8489 §6.2.1
    /// retransmits *the same* message (same transaction id), it does not build a new one.
    datagram: Vec<u8>,
    pending: Pending,
}

/// A peer this allocation can exchange data with: its permission and (once bound) its channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerBinding {
    /// The peer's transport address.
    pub peer: SocketAddr,
    /// The bound channel number, once ChannelBind succeeded. Until then data must go as a Send
    /// indication (36 bytes of overhead), which is why the client binds one as soon as it can.
    pub channel: Option<u16>,
    /// Millisecond at which the permission must be refreshed (RFC 5766 §8, 5 minutes).
    permission_refresh_at_ms: u64,
    /// Millisecond at which the channel binding must be refreshed (RFC 5766 §11, 10 minutes).
    channel_refresh_at_ms: u64,
    /// Whether a permission has been confirmed at least once (data is dropped by the server until
    /// then, so the caller must not treat the peer as reachable before it).
    pub permitted: bool,
}

/// A TURN allocation, as a state machine.
#[derive(Clone, Debug)]
pub struct TurnClient {
    server: SocketAddr,
    credentials: TurnCredentials,
    state: TurnState,
    /// The server's realm and nonce from its `401` challenge (RFC 5766 §6.2).
    realm: Option<String>,
    nonce: Option<Vec<u8>>,
    in_flight: Option<InFlight>,
    /// Requests waiting for the one in flight to finish. TURN has no request pipelining requirement,
    /// and serialising keeps the nonce handling single-threaded: a `438` retry cannot race a second
    /// request built with the stale nonce.
    queue: Vec<Pending>,
    peers: Vec<PeerBinding>,
    next_channel: u16,
    /// Millisecond at which the allocation must be refreshed.
    refresh_at_ms: u64,
    schedule: RetransmitSchedule,
    /// The lifetime the server last granted, in seconds.
    granted_lifetime: u32,
    /// Whether a request has already been re-sent after a `438 Stale Nonce`. Cleared on any success,
    /// so a server that legitimately rotates its nonce over a long allocation keeps working, while a
    /// server that answers `438` to every request cannot make us loop.
    stale_nonce_retried: bool,
}

impl TurnClient {
    /// Start an allocation against `server` with `credentials`.
    ///
    /// Nothing is transmitted until the first [`poll`](Self::poll) — the caller owns the clock and the
    /// socket.
    #[must_use]
    pub fn new(server: SocketAddr, credentials: TurnCredentials, rto_ms: u64) -> Self {
        Self {
            server,
            credentials,
            state: TurnState::Allocating,
            realm: None,
            nonce: None,
            in_flight: None,
            queue: vec![Pending::AllocateProbe],
            peers: Vec::new(),
            next_channel: FIRST_CHANNEL,
            refresh_at_ms: u64::MAX,
            schedule: RetransmitSchedule::new(rto_ms),
            granted_lifetime: DEFAULT_LIFETIME_SECONDS,
            stale_nonce_retried: false,
        }
    }

    /// The TURN server this allocation is against.
    #[must_use]
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// The current lifecycle state.
    #[must_use]
    pub fn state(&self) -> &TurnState {
        &self.state
    }

    /// The relayed transport address, once allocated — the address to advertise as an ICE relayed
    /// candidate (RFC 8445 §5.1.1.2).
    #[must_use]
    pub fn relayed_address(&self) -> Option<SocketAddr> {
        match self.state {
            TurnState::Allocated { relayed, .. } => Some(relayed),
            _ => None,
        }
    }

    /// Our address as the TURN server saw it — a server-reflexive candidate obtained from the same
    /// exchange, at no extra round trip (RFC 8656 §12).
    #[must_use]
    pub fn mapped_address(&self) -> Option<SocketAddr> {
        match self.state {
            TurnState::Allocated { mapped, .. } => mapped,
            _ => None,
        }
    }

    /// Whether the allocation is live.
    #[must_use]
    pub fn is_allocated(&self) -> bool {
        matches!(self.state, TurnState::Allocated { .. })
    }

    /// Whether the lifecycle has ended (failed or deleted) — the caller stops polling.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, TurnState::Failed(_) | TurnState::Closed)
    }

    /// The peers this allocation has (or is getting) permission for.
    #[must_use]
    pub fn peers(&self) -> &[PeerBinding] {
        &self.peers
    }

    /// The channel bound to `peer`, if ChannelBind has succeeded for it. Data to a peer with a
    /// channel uses 4-byte [`ChannelData`](crate::turn::ChannelData) framing; without one it must go
    /// as a Send indication.
    #[must_use]
    pub fn channel_for(&self, peer: SocketAddr) -> Option<u16> {
        self.peers
            .iter()
            .find(|binding| binding.peer == peer)
            .and_then(|binding| binding.channel)
    }

    /// The peer a bound channel belongs to — the inverse of [`channel_for`](Self::channel_for), used
    /// to rewrite an inbound `ChannelData` message's source back to the peer that sent it.
    #[must_use]
    pub fn peer_for_channel(&self, channel: u16) -> Option<SocketAddr> {
        self.peers
            .iter()
            .find(|binding| binding.channel == Some(channel))
            .map(|binding| binding.peer)
    }

    /// Whether data may be sent to `peer` — i.e. a permission has been confirmed. The server silently
    /// drops data for an unpermitted peer (RFC 5766 §9), so sending before this is wasted.
    #[must_use]
    pub fn may_send_to(&self, peer: SocketAddr) -> bool {
        self.peers
            .iter()
            .any(|binding| binding.peer == peer && binding.permitted)
    }

    /// Ask for a permission (and then a channel) for `peer` — every remote candidate ICE may check
    /// against needs one, because the server drops traffic from a peer with no permission (§9).
    ///
    /// Idempotent: a peer already known is not re-queued. The request is queued, not sent — the next
    /// [`poll`](Self::poll) transmits it.
    pub fn add_peer(&mut self, peer: SocketAddr) {
        if self.peers.iter().any(|binding| binding.peer == peer) {
            return;
        }
        self.peers.push(PeerBinding {
            peer,
            channel: None,
            permission_refresh_at_ms: u64::MAX,
            channel_refresh_at_ms: u64::MAX,
            permitted: false,
        });
        self.queue.push(Pending::CreatePermission { peer });
    }

    /// Delete the allocation (RFC 5766 §7.1: a `Refresh` with `LIFETIME: 0`).
    ///
    /// Queued like any other request so it is retransmitted if lost; the state becomes
    /// [`TurnState::Closed`] when the server confirms. Calling this rather than just dropping the
    /// client is what stops the server holding a relay port until the lifetime lapses.
    pub fn close(&mut self) {
        if self.is_terminal() {
            return;
        }
        self.queue
            .retain(|pending| matches!(pending, Pending::Refresh { lifetime: 0 }));
        self.queue.push(Pending::Refresh { lifetime: 0 });
    }

    /// Drive the allocation at `now_ms`: retransmit or start the next request, or report that a
    /// request has timed out.
    pub fn poll(&mut self, now_ms: u64) -> TurnAction {
        if self.is_terminal() {
            return TurnAction::Idle;
        }
        // A request already in flight: retransmit per RFC 8489 §6.2.1, or fail on timeout.
        if let Some(mut in_flight) = self.in_flight.take() {
            match in_flight.transaction.poll(now_ms) {
                TransactionAction::Wait => {
                    self.in_flight = Some(in_flight);
                    return TurnAction::Idle;
                }
                TransactionAction::Retransmit(_) => {
                    let datagram = in_flight.datagram.clone();
                    self.in_flight = Some(in_flight);
                    return TurnAction::Send { datagram };
                }
                TransactionAction::Failed => {
                    // An allocation that never came up is a failure; a refresh/permission that timed
                    // out kills it too, because without them the relay stops carrying data anyway.
                    self.state = TurnState::Failed(TurnFailure::Timeout);
                    return TurnAction::Idle;
                }
            }
        }
        // Nothing in flight: schedule maintenance, then start the next queued request.
        self.enqueue_due_maintenance(now_ms);
        let Some(pending) = self.next_request() else {
            return TurnAction::Idle;
        };
        self.start(pending, now_ms)
    }

    /// Queue whatever is due: the allocation refresh, plus any permission or channel that is about to
    /// lapse. Their lifetimes are fixed by the RFC, so this is pure arithmetic on the caller's clock.
    fn enqueue_due_maintenance(&mut self, now_ms: u64) {
        if !self.is_allocated() {
            return;
        }
        if now_ms >= self.refresh_at_ms {
            let lifetime = self.granted_lifetime;
            self.refresh_at_ms = u64::MAX; // re-armed when the refresh succeeds
            self.queue.push(Pending::Refresh { lifetime });
        }
        // Collected first so the borrow of `self.peers` ends before pushing onto the queue.
        let mut due: Vec<Pending> = Vec::new();
        for binding in &mut self.peers {
            match binding.channel {
                // RFC 5766 §11: a ChannelBind refreshes the channel *and* the permission. So a bound
                // peer is kept alive by ChannelBind alone, on the permission's tighter clock (5 min
                // vs the channel's 10) — one request per interval instead of two, and both lifetimes
                // stay satisfied. Sending a separate CreatePermission here would be redundant work
                // on every refresh for the whole life of the call.
                Some(channel) => {
                    if now_ms
                        >= binding
                            .permission_refresh_at_ms
                            .min(binding.channel_refresh_at_ms)
                    {
                        binding.permission_refresh_at_ms = u64::MAX;
                        binding.channel_refresh_at_ms = u64::MAX;
                        due.push(Pending::ChannelBind {
                            peer: binding.peer,
                            channel,
                        });
                    }
                }
                // No channel bound (the bind is still in flight, or failed): the permission is the
                // only thing keeping the peer reachable, so it must be refreshed on its own.
                None => {
                    if now_ms >= binding.permission_refresh_at_ms {
                        binding.permission_refresh_at_ms = u64::MAX;
                        due.push(Pending::CreatePermission { peer: binding.peer });
                    }
                }
            }
        }
        self.queue.extend(due);
    }

    fn next_request(&mut self) -> Option<Pending> {
        if self.queue.is_empty() {
            return None;
        }
        Some(self.queue.remove(0))
    }

    /// Build and arm the transaction for `pending`.
    fn start(&mut self, pending: Pending, now_ms: u64) -> TurnAction {
        let Some(transaction_id) = TransactionId::new() else {
            self.state = TurnState::Failed(TurnFailure::NoRandomness);
            return TurnAction::Idle;
        };
        let datagram = self.build(&pending, &transaction_id);
        // `Transaction::start` counts the first request as already sent — which it is: we return it
        // as the action, and the caller transmits it.
        let transaction = Transaction::start(transaction_id, self.schedule, now_ms);
        self.in_flight = Some(InFlight {
            transaction,
            datagram: datagram.clone(),
            pending,
        });
        TurnAction::Send { datagram }
    }

    /// Encode one request. The credential attributes (USERNAME/REALM/NONCE + MESSAGE-INTEGRITY) are
    /// attached to everything except the first probe, which cannot carry them: the realm the key is
    /// derived from is only learned from the `401` (RFC 5766 §6.2).
    fn build(&self, pending: &Pending, transaction_id: &TransactionId) -> Vec<u8> {
        let raw_id = transaction_id.as_bytes();
        let builder = match pending {
            Pending::AllocateProbe | Pending::Allocate => MessageBuilder::new(
                turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_REQUEST),
                raw_id,
            )
            .attribute(
                turn::ATTR_REQUESTED_TRANSPORT,
                &turn::requested_transport_value(turn::TRANSPORT_UDP),
            )
            .attribute(
                turn::ATTR_LIFETIME,
                &turn::lifetime_value(DEFAULT_LIFETIME_SECONDS),
            ),
            Pending::Refresh { lifetime } => MessageBuilder::new(
                turn::message_type(turn::METHOD_REFRESH, turn::CLASS_REQUEST),
                raw_id,
            )
            .attribute(turn::ATTR_LIFETIME, &turn::lifetime_value(*lifetime)),
            Pending::CreatePermission { peer } => MessageBuilder::new(
                turn::message_type(turn::METHOD_CREATE_PERMISSION, turn::CLASS_REQUEST),
                raw_id,
            )
            .attribute(
                turn::ATTR_XOR_PEER_ADDRESS,
                &turn::xor_address_value(*peer, raw_id),
            ),
            Pending::ChannelBind { peer, channel } => MessageBuilder::new(
                turn::message_type(turn::METHOD_CHANNEL_BIND, turn::CLASS_REQUEST),
                raw_id,
            )
            .attribute(
                turn::ATTR_CHANNEL_NUMBER,
                &turn::channel_number_value(*channel),
            )
            .attribute(
                turn::ATTR_XOR_PEER_ADDRESS,
                &turn::xor_address_value(*peer, raw_id),
            ),
        };
        if matches!(pending, Pending::AllocateProbe) {
            return builder.finish(None, false);
        }
        self.with_credentials(builder)
    }

    /// Attach the long-term credential attributes and sign the message (RFC 5766 §4). Without a realm
    /// and nonce there is nothing to sign with, so the message goes unauthenticated and the server's
    /// `401` supplies them.
    fn with_credentials(&self, builder: MessageBuilder) -> Vec<u8> {
        let (Some(realm), Some(nonce)) = (self.realm.as_ref(), self.nonce.as_ref()) else {
            return builder.finish(None, false);
        };
        let key = long_term_key(
            &self.credentials.username,
            realm,
            &self.credentials.password,
        );
        builder
            .attribute(turn::ATTR_USERNAME, self.credentials.username.as_bytes())
            .attribute(turn::ATTR_REALM, realm.as_bytes())
            .attribute(turn::ATTR_NONCE, nonce)
            .finish(Some(&key), false)
    }

    /// Feed a datagram received from the TURN server. Returns `true` when it was consumed as a
    /// response to our outstanding request; anything else (ChannelData, a Data indication, a stray
    /// message) is left to the caller, which owns the data path.
    pub fn on_datagram(&mut self, datagram: &[u8], now_ms: u64) -> bool {
        if self.is_terminal() {
            return false;
        }
        let Ok(message) = parse(datagram) else {
            return false;
        };
        let Some(in_flight) = self.in_flight.as_ref() else {
            return false;
        };
        // Correlate by transaction id (RFC 8489 §6.2.1) — a response for anything else is not ours.
        if message.transaction_id != *in_flight.transaction.id().as_bytes() {
            return false;
        }
        let class = turn::class_of(message.message_type);
        let pending = in_flight.pending.clone();
        self.in_flight = None;
        match class {
            turn::CLASS_SUCCESS => {
                self.stale_nonce_retried = false;
                self.on_success(&pending, &message, now_ms)
            }
            turn::CLASS_ERROR => self.on_error(&pending, &message),
            // Neither a success nor an error for our transaction id: not a usable answer.
            _ => self.state = TurnState::Failed(TurnFailure::Malformed("unexpected message class")),
        }
        true
    }

    fn on_success(&mut self, pending: &Pending, message: &StunMessage, now_ms: u64) {
        match pending {
            Pending::AllocateProbe => {
                // RFC 5766 §6.2: an Allocate with no credentials must be challenged. A server that
                // answers it with success is not doing long-term credentials at all; take the
                // allocation, since the relay works, but this is unusual enough to be worth stating.
                self.finish_allocation(message);
                self.arm_refresh(now_ms);
            }
            Pending::Allocate => {
                self.finish_allocation(message);
                self.arm_refresh(now_ms);
            }
            Pending::Refresh { lifetime: 0 } => self.state = TurnState::Closed,
            Pending::Refresh { .. } => {
                if let Some(granted) = turn::lifetime(message) {
                    self.granted_lifetime = granted;
                }
                self.arm_refresh(now_ms);
            }
            Pending::CreatePermission { peer } => {
                let peer = *peer;
                let refresh_at =
                    now_ms.saturating_add(refresh_interval_ms(PERMISSION_LIFETIME_SECONDS));
                let mut bind_channel = None;
                if let Some(binding) = self.peers.iter_mut().find(|entry| entry.peer == peer) {
                    binding.permitted = true;
                    binding.permission_refresh_at_ms = refresh_at;
                    // First permission for this peer: bind a channel so data costs 4 bytes of
                    // overhead instead of 36 (RFC 5766 §11 vs §10).
                    if binding.channel.is_none() {
                        bind_channel = Some(());
                    }
                }
                if bind_channel.is_some() {
                    let channel = self.take_channel_number();
                    self.queue.push(Pending::ChannelBind { peer, channel });
                }
            }
            Pending::ChannelBind { peer, channel } => {
                let refresh_at =
                    now_ms.saturating_add(refresh_interval_ms(CHANNEL_LIFETIME_SECONDS));
                if let Some(binding) = self.peers.iter_mut().find(|entry| entry.peer == *peer) {
                    binding.channel = Some(*channel);
                    binding.channel_refresh_at_ms = refresh_at;
                    // RFC 5766 §11: a ChannelBind also refreshes the permission, so the two clocks
                    // stay together rather than drifting into a redundant CreatePermission.
                    binding.permitted = true;
                    binding.permission_refresh_at_ms =
                        now_ms.saturating_add(refresh_interval_ms(PERMISSION_LIFETIME_SECONDS));
                }
            }
        }
    }

    /// Read the allocation out of a successful Allocate response (RFC 5766 §6.3).
    fn finish_allocation(&mut self, message: &StunMessage) {
        let Some(relayed) = turn::xor_relayed_address(message) else {
            self.state = TurnState::Failed(TurnFailure::Malformed(
                "Allocate success without XOR-RELAYED-ADDRESS",
            ));
            return;
        };
        if let Some(granted) = turn::lifetime(message) {
            self.granted_lifetime = granted;
        }
        self.state = TurnState::Allocated {
            relayed,
            mapped: message.xor_mapped_address(),
        };
    }

    fn arm_refresh(&mut self, now_ms: u64) {
        self.refresh_at_ms = now_ms.saturating_add(refresh_interval_ms(self.granted_lifetime));
    }

    fn on_error(&mut self, pending: &Pending, message: &StunMessage) {
        let code = turn::error_code(message).unwrap_or(0);
        let reason = error_reason(message);
        match code {
            // RFC 5766 §6.2: the challenge. Learn the realm + nonce and retry *once* with
            // credentials. A second `401` on an authenticated request means the secret is wrong.
            turn::ERROR_UNAUTHORIZED if matches!(pending, Pending::AllocateProbe) => {
                let (Some(realm), Some(nonce)) = (turn::realm(message), turn::nonce(message))
                else {
                    self.state = TurnState::Failed(TurnFailure::Malformed(
                        "401 challenge without REALM/NONCE",
                    ));
                    return;
                };
                self.realm = Some(realm.to_string());
                self.nonce = Some(nonce.to_vec());
                self.queue.insert(0, Pending::Allocate);
            }
            // RFC 5766 §10: the nonce went stale. Take the new one and retry the same request once.
            turn::ERROR_STALE_NONCE if !self.stale_nonce_retried => {
                let Some(nonce) = turn::nonce(message) else {
                    self.state = TurnState::Failed(TurnFailure::Malformed(
                        "438 Stale Nonce without a NONCE",
                    ));
                    return;
                };
                self.nonce = Some(nonce.to_vec());
                if let Some(realm) = turn::realm(message) {
                    self.realm = Some(realm.to_string());
                }
                self.retry(pending.clone());
            }
            // Anything else. How fatal it is depends on *what* was rejected — a failed allocation is
            // the end of the relay, but a failed binding for one peer is not.
            _ => match pending {
                // No allocation (or no way to keep one alive) means no relayed candidate at all.
                Pending::AllocateProbe | Pending::Allocate | Pending::Refresh { .. } => {
                    self.state = TurnState::Failed(TurnFailure::Rejected { code, reason });
                }
                // RFC 5766 §9: without a permission the server drops this peer's traffic. That makes
                // *this peer* unreachable over the relay — ICE will simply fail its pairs and use
                // another candidate — but the allocation and every other peer are unaffected, so
                // tearing it down would throw away a working relay over one bad pair.
                Pending::CreatePermission { peer } => {
                    let peer = *peer;
                    self.peers.retain(|binding| binding.peer != peer);
                }
                // RFC 5766 §11 is an optimisation, not a requirement: without a channel, data still
                // flows as Send/Data indications at 36 bytes of overhead instead of 4. Keep the
                // permission (which is what actually makes the peer reachable) and stay on
                // indications rather than failing a usable path.
                Pending::ChannelBind { peer, .. } => {
                    let peer = *peer;
                    if let Some(binding) = self.peers.iter_mut().find(|entry| entry.peer == peer) {
                        binding.channel = None;
                    }
                }
            },
        }
    }

    /// Re-queue `pending` with the refreshed nonce. Queued rather than sent from here so the next
    /// `poll` transmits it immediately on the caller's clock — and, being a fresh transaction
    /// (RFC 8489 §6.2.1: the old request *was* answered, just unfavourably), it gets its own id.
    fn retry(&mut self, pending: Pending) {
        self.stale_nonce_retried = true;
        self.queue.insert(0, pending);
    }

    /// The next channel number to hand out (RFC 5766 §11: `0x4000`–`0x7FFF`). Saturates rather than
    /// wrapping past the range — a client that has burned 16384 channels on one allocation is broken,
    /// and reusing a live channel number would misroute a peer's data.
    fn take_channel_number(&mut self) -> u16 {
        let channel = self.next_channel;
        self.next_channel = self
            .next_channel
            .saturating_add(1)
            .min(turn::MAX_CHANNEL_NUMBER);
        channel
    }
}

/// When to refresh something the server granted for `lifetime` seconds: [`REFRESH_AT_PERCENT`] of the
/// way in, as milliseconds. Saturating, so an absurd lifetime cannot overflow the clock.
fn refresh_interval_ms(lifetime_seconds: u32) -> u64 {
    u64::from(lifetime_seconds)
        .saturating_mul(1_000)
        .saturating_mul(u64::from(REFRESH_AT_PERCENT))
        / 100
}

/// The reason phrase of an ERROR-CODE attribute (RFC 5389 §15.6), if the server sent readable UTF-8.
fn error_reason(message: &StunMessage) -> String {
    message
        .attribute(turn::ATTR_ERROR_CODE)
        .and_then(|value| value.get(4..))
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::turn::{class_of, method_of};

    const SERVER: &str = "203.0.113.10:3478";
    const RELAYED: &str = "203.0.113.10:50000";
    const PEER: &str = "198.51.100.20:40000";
    const REALM: &str = "siphon.invalid";
    const NONCE: &[u8] = b"nonce-one";
    const USER: &str = "turnuser";
    const PASSWORD: &str = "turnpassword";

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("addr")
    }

    fn client() -> TurnClient {
        TurnClient::new(addr(SERVER), TurnCredentials::new(USER, PASSWORD), 500)
    }

    /// Pull the next datagram the client wants to send, failing the test if it is idle.
    fn take_send(client: &mut TurnClient, now_ms: u64) -> Vec<u8> {
        match client.poll(now_ms) {
            TurnAction::Send { datagram } => datagram,
            TurnAction::Idle => panic!("expected a request at {now_ms} ms"),
        }
    }

    fn transaction_id_of(datagram: &[u8]) -> [u8; 12] {
        parse(datagram).expect("parse").transaction_id
    }

    /// A `401 Unauthorized` challenge carrying REALM + NONCE (RFC 5766 §6.2).
    fn challenge(request: &[u8]) -> Vec<u8> {
        MessageBuilder::new(
            turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_ERROR),
            &transaction_id_of(request),
        )
        .attribute(
            turn::ATTR_ERROR_CODE,
            &turn::error_code_value(turn::ERROR_UNAUTHORIZED, "Unauthorized"),
        )
        .attribute(turn::ATTR_REALM, REALM.as_bytes())
        .attribute(turn::ATTR_NONCE, NONCE)
        .finish(None, false)
    }

    /// An Allocate success carrying the relayed address (and a reflexive one).
    fn allocate_success(request: &[u8], lifetime: u32) -> Vec<u8> {
        let id = transaction_id_of(request);
        MessageBuilder::new(
            turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_SUCCESS),
            &id,
        )
        .attribute(
            turn::ATTR_XOR_RELAYED_ADDRESS,
            &turn::xor_address_value(addr(RELAYED), &id),
        )
        .attribute(
            turn::ATTR_XOR_MAPPED_ADDRESS,
            &turn::xor_address_value(addr("192.0.2.5:6000"), &id),
        )
        .attribute(turn::ATTR_LIFETIME, &turn::lifetime_value(lifetime))
        .finish(None, false)
    }

    fn success_for(request: &[u8], method: u16) -> Vec<u8> {
        MessageBuilder::new(
            turn::message_type(method, turn::CLASS_SUCCESS),
            &transaction_id_of(request),
        )
        .finish(None, false)
    }

    fn error_for(request: &[u8], method: u16, code: u16, nonce: Option<&[u8]>) -> Vec<u8> {
        let mut builder = MessageBuilder::new(
            turn::message_type(method, turn::CLASS_ERROR),
            &transaction_id_of(request),
        )
        .attribute(turn::ATTR_ERROR_CODE, &turn::error_code_value(code, "nope"));
        if let Some(nonce) = nonce {
            builder = builder
                .attribute(turn::ATTR_REALM, REALM.as_bytes())
                .attribute(turn::ATTR_NONCE, nonce);
        }
        builder.finish(None, false)
    }

    /// Drive a client from construction to a live allocation, returning it.
    fn allocated() -> TurnClient {
        let mut client = client();
        let probe = take_send(&mut client, 0);
        client.on_datagram(&challenge(&probe), 0);
        let authed = take_send(&mut client, 0);
        client.on_datagram(&allocate_success(&authed, DEFAULT_LIFETIME_SECONDS), 0);
        client
    }

    #[test]
    fn the_first_allocate_carries_no_credentials_because_the_realm_is_not_known_yet() {
        // RFC 5766 §6.2: the key is MD5(username:realm:password), and the realm comes from the
        // server's challenge — so credentials on the first request would have to be guessed.
        let mut client = client();
        let probe = take_send(&mut client, 0);
        let message = parse(&probe).expect("parse");

        assert_eq!(method_of(message.message_type), turn::METHOD_ALLOCATE);
        assert_eq!(class_of(message.message_type), turn::CLASS_REQUEST);
        assert!(message.attribute(turn::ATTR_USERNAME).is_none());
        assert!(message.attribute(turn::ATTR_MESSAGE_INTEGRITY).is_none());
        // RFC 5766 §6.1: REQUESTED-TRANSPORT is mandatory, and UDP is transport 17.
        assert_eq!(
            turn::requested_transport(&message),
            Some(turn::TRANSPORT_UDP)
        );
    }

    #[test]
    fn the_challenge_is_answered_with_a_signed_allocate() {
        let mut client = client();
        let probe = take_send(&mut client, 0);
        assert!(client.on_datagram(&challenge(&probe), 0));

        let authed = take_send(&mut client, 0);
        let message = parse(&authed).expect("parse");
        assert_eq!(
            message.attribute(turn::ATTR_USERNAME),
            Some(USER.as_bytes())
        );
        assert_eq!(turn::realm(&message), Some(REALM));
        assert_eq!(turn::nonce(&message), Some(NONCE));
        // Signed with MD5(username:realm:password) — the long-term key, not the raw password.
        let key = long_term_key(USER, REALM, PASSWORD);
        assert!(crate::verify_message_integrity(&authed, &key));
        assert!(
            !crate::verify_message_integrity(&authed, PASSWORD.as_bytes()),
            "the raw password must not be the integrity key (RFC 5766 §4)"
        );
    }

    #[test]
    fn a_successful_allocate_yields_the_relayed_and_reflexive_addresses() {
        let client = allocated();
        assert!(client.is_allocated());
        assert_eq!(client.relayed_address(), Some(addr(RELAYED)));
        // RFC 8656 §12: the same exchange gives us a server-reflexive address at no extra round trip.
        assert_eq!(client.mapped_address(), Some(addr("192.0.2.5:6000")));
    }

    #[test]
    fn a_second_401_on_an_authenticated_request_fails_rather_than_looping() {
        // Wrong credentials must not become an infinite challenge/retry loop.
        let mut client = client();
        let probe = take_send(&mut client, 0);
        client.on_datagram(&challenge(&probe), 0);
        let authed = take_send(&mut client, 0);
        client.on_datagram(&challenge(&authed), 0);

        assert!(matches!(
            client.state(),
            TurnState::Failed(TurnFailure::Rejected { code: 401, .. })
        ));
        assert_eq!(client.poll(1_000), TurnAction::Idle);
    }

    #[test]
    fn an_allocate_success_without_a_relayed_address_is_rejected() {
        // RFC 5766 §6.3 requires XOR-RELAYED-ADDRESS. Without it there is no candidate to advertise,
        // so treating the allocation as live would advertise nothing usable.
        let mut client = client();
        let probe = take_send(&mut client, 0);
        client.on_datagram(&challenge(&probe), 0);
        let authed = take_send(&mut client, 0);
        let hollow = MessageBuilder::new(
            turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_SUCCESS),
            &transaction_id_of(&authed),
        )
        .finish(None, false);
        client.on_datagram(&hollow, 0);

        assert!(matches!(
            client.state(),
            TurnState::Failed(TurnFailure::Malformed(_))
        ));
        assert_eq!(client.relayed_address(), None);
    }

    #[test]
    fn a_stale_nonce_is_retried_once_with_the_new_nonce() {
        // RFC 5766 §10: the server rotates its nonce mid-allocation; the same request is re-sent with
        // the new one rather than failing the allocation.
        const ROTATED: &[u8] = b"nonce-two";
        let mut client = client();
        let probe = take_send(&mut client, 0);
        client.on_datagram(&challenge(&probe), 0);
        let authed = take_send(&mut client, 0);
        client.on_datagram(
            &error_for(
                &authed,
                turn::METHOD_ALLOCATE,
                turn::ERROR_STALE_NONCE,
                Some(ROTATED),
            ),
            0,
        );

        let retried = take_send(&mut client, 0);
        let message = parse(&retried).expect("parse");
        assert_eq!(turn::nonce(&message), Some(ROTATED));
        assert!(!client.is_terminal(), "a stale nonce is recoverable");
    }

    #[test]
    fn a_second_stale_nonce_on_the_same_request_fails_rather_than_looping() {
        const ROTATED: &[u8] = b"nonce-two";
        let mut client = client();
        let probe = take_send(&mut client, 0);
        client.on_datagram(&challenge(&probe), 0);
        let authed = take_send(&mut client, 0);
        client.on_datagram(
            &error_for(
                &authed,
                turn::METHOD_ALLOCATE,
                turn::ERROR_STALE_NONCE,
                Some(ROTATED),
            ),
            0,
        );
        let retried = take_send(&mut client, 0);
        client.on_datagram(
            &error_for(
                &retried,
                turn::METHOD_ALLOCATE,
                turn::ERROR_STALE_NONCE,
                Some(b"three"),
            ),
            0,
        );

        assert!(matches!(
            client.state(),
            TurnState::Failed(TurnFailure::Rejected { code: 438, .. })
        ));
    }

    #[test]
    fn a_permission_is_created_for_a_peer_and_then_a_channel_is_bound() {
        // RFC 5766 §9 then §11: the permission makes the peer reachable at all; the channel drops the
        // per-packet overhead from 36 bytes to 4, which for 20 ms audio is the difference worth having.
        let mut client = allocated();
        client.add_peer(addr(PEER));
        assert!(
            !client.may_send_to(addr(PEER)),
            "not until the server confirms"
        );

        let permission = take_send(&mut client, 0);
        let message = parse(&permission).expect("parse");
        assert_eq!(
            method_of(message.message_type),
            turn::METHOD_CREATE_PERMISSION
        );
        assert_eq!(turn::xor_peer_address(&message), Some(addr(PEER)));
        client.on_datagram(&success_for(&permission, turn::METHOD_CREATE_PERMISSION), 0);
        assert!(client.may_send_to(addr(PEER)));
        assert_eq!(client.channel_for(addr(PEER)), None);

        let bind = take_send(&mut client, 0);
        let message = parse(&bind).expect("parse");
        assert_eq!(method_of(message.message_type), turn::METHOD_CHANNEL_BIND);
        assert_eq!(turn::xor_peer_address(&message), Some(addr(PEER)));
        let channel = turn::channel_number(&message).expect("CHANNEL-NUMBER");
        assert!(
            turn::valid_channel_number(channel),
            "channel {channel:#06x} outside the RFC 5766 §11 range"
        );
        client.on_datagram(&success_for(&bind, turn::METHOD_CHANNEL_BIND), 0);

        assert_eq!(client.channel_for(addr(PEER)), Some(channel));
        // And the inverse mapping, which is how an inbound ChannelData is attributed to its peer.
        assert_eq!(client.peer_for_channel(channel), Some(addr(PEER)));
    }

    #[test]
    fn adding_the_same_peer_twice_does_not_queue_a_second_permission() {
        let mut client = allocated();
        client.add_peer(addr(PEER));
        client.add_peer(addr(PEER));
        let first = take_send(&mut client, 0);
        client.on_datagram(&success_for(&first, turn::METHOD_CREATE_PERMISSION), 0);
        // The only thing left to do is bind the channel — not a duplicate permission.
        let next = take_send(&mut client, 0);
        assert_eq!(
            method_of(parse(&next).expect("parse").message_type),
            turn::METHOD_CHANNEL_BIND
        );
        assert_eq!(client.peers().len(), 1);
    }

    #[test]
    fn the_allocation_is_refreshed_inside_the_granted_lifetime() {
        // RFC 5766 §7: refresh before expiry. With a 600 s grant the refresh is due at 450 s, leaving
        // a full retransmission run before the allocation would actually lapse.
        let mut client = allocated();
        assert_eq!(client.poll(1_000), TurnAction::Idle, "nothing due yet");
        assert_eq!(client.poll(449_000), TurnAction::Idle);

        let refresh = take_send(&mut client, 450_000);
        let message = parse(&refresh).expect("parse");
        assert_eq!(method_of(message.message_type), turn::METHOD_REFRESH);
        assert_eq!(turn::lifetime(&message), Some(DEFAULT_LIFETIME_SECONDS));
        // Signed, like every request after the challenge.
        let key = long_term_key(USER, REALM, PASSWORD);
        assert!(crate::verify_message_integrity(&refresh, &key));
    }

    #[test]
    fn a_shorter_granted_lifetime_shortens_the_refresh_interval() {
        // The server may grant less than we asked for; refreshing on our own asked-for figure would
        // then let the allocation lapse.
        let mut client = client();
        let probe = take_send(&mut client, 0);
        client.on_datagram(&challenge(&probe), 0);
        let authed = take_send(&mut client, 0);
        client.on_datagram(&allocate_success(&authed, 60), 0);

        assert_eq!(client.poll(44_000), TurnAction::Idle);
        let refresh = take_send(&mut client, 45_000);
        assert_eq!(
            method_of(parse(&refresh).expect("parse").message_type),
            turn::METHOD_REFRESH
        );
    }

    #[test]
    fn a_permission_is_refreshed_before_its_five_minute_lifetime_lapses() {
        // RFC 5766 §8: permissions last 5 minutes and are not negotiable. Letting one lapse silently
        // stops the server relaying that peer's media — a call that dies mid-conversation.
        //
        // This is the case where CreatePermission is the only thing keeping the peer reachable: the
        // ChannelBind was rejected, so there is no channel refresh to piggyback on.
        let mut client = allocated();
        client.add_peer(addr(PEER));
        let permission = take_send(&mut client, 0);
        client.on_datagram(&success_for(&permission, turn::METHOD_CREATE_PERMISSION), 0);
        let bind = take_send(&mut client, 0);
        client.on_datagram(
            &error_for(
                &bind,
                turn::METHOD_CHANNEL_BIND,
                turn::ERROR_BAD_REQUEST,
                None,
            ),
            0,
        );
        // A rejected ChannelBind is not fatal — data can still flow as Send indications, so the
        // permission must keep being refreshed rather than the allocation being torn down.
        assert!(client.may_send_to(addr(PEER)));
        assert_eq!(client.channel_for(addr(PEER)), None);

        assert_eq!(client.poll(200_000), TurnAction::Idle);
        // 75% of 300 s = 225 s.
        let refresh = take_send(&mut client, 225_000);
        assert_eq!(
            method_of(parse(&refresh).expect("parse").message_type),
            turn::METHOD_CREATE_PERMISSION
        );
    }

    #[test]
    fn a_channel_binding_is_refreshed_before_its_ten_minute_lifetime_lapses() {
        let mut client = allocated();
        client.add_peer(addr(PEER));
        let permission = take_send(&mut client, 0);
        client.on_datagram(&success_for(&permission, turn::METHOD_CREATE_PERMISSION), 0);
        let bind = take_send(&mut client, 0);
        let channel = turn::channel_number(&parse(&bind).expect("parse")).expect("channel");
        client.on_datagram(&success_for(&bind, turn::METHOD_CHANNEL_BIND), 0);

        // A bound peer is refreshed by ChannelBind alone, on the permission's tighter 5-minute clock
        // (RFC 5766 §11: a ChannelBind refreshes the permission too). So at 225 s the request is a
        // ChannelBind, not a CreatePermission — one request keeps both alive.
        assert_eq!(client.poll(224_000), TurnAction::Idle);
        let refresh = take_send(&mut client, 225_000);
        let message = parse(&refresh).expect("parse");
        assert_eq!(method_of(message.message_type), turn::METHOD_CHANNEL_BIND);
        assert_eq!(
            turn::channel_number(&message),
            Some(channel),
            "a refresh re-binds the SAME channel — a new number would strand the peer's data"
        );
        assert_eq!(turn::xor_peer_address(&message), Some(addr(PEER)));
    }

    #[test]
    fn a_bound_peer_is_refreshed_with_one_request_not_two() {
        // The redundant-work check behind the rule above: over a long allocation, a bound peer must
        // never draw a CreatePermission *and* a ChannelBind for the same interval.
        let mut client = allocated();
        client.add_peer(addr(PEER));
        let permission = take_send(&mut client, 0);
        client.on_datagram(&success_for(&permission, turn::METHOD_CREATE_PERMISSION), 0);
        let bind = take_send(&mut client, 0);
        client.on_datagram(&success_for(&bind, turn::METHOD_CHANNEL_BIND), 0);

        let mut permissions = 0;
        let mut binds = 0;
        let mut now = 0u64;
        while now < 1_800_000 {
            if let TurnAction::Send { datagram } = client.poll(now) {
                let message = parse(&datagram).expect("parse");
                match method_of(message.message_type) {
                    turn::METHOD_CREATE_PERMISSION => permissions += 1,
                    turn::METHOD_CHANNEL_BIND => binds += 1,
                    _ => {}
                }
                // Answer everything so the schedule keeps advancing.
                let method = method_of(message.message_type);
                client.on_datagram(&success_for(&datagram, method), now);
            }
            now += 1_000;
        }
        assert!(binds >= 5, "the channel is refreshed across 30 minutes");
        assert_eq!(
            permissions, 0,
            "a bound peer draws no CreatePermission at all — ChannelBind refreshes both"
        );
    }

    #[test]
    fn a_rejected_permission_loses_that_peer_but_keeps_the_allocation() {
        // One unreachable peer is not a dead relay: ICE simply fails that pair and uses another
        // candidate. Tearing the allocation down would throw away a working relay over one bad pair.
        let mut client = allocated();
        client.add_peer(addr(PEER));
        client.add_peer(addr("198.51.100.21:40000"));
        let first = take_send(&mut client, 0);
        client.on_datagram(
            &error_for(
                &first,
                turn::METHOD_CREATE_PERMISSION,
                turn::ERROR_FORBIDDEN,
                None,
            ),
            0,
        );

        assert!(client.is_allocated(), "the allocation survives");
        assert!(!client.may_send_to(addr(PEER)));
        assert_eq!(client.peers().len(), 1, "only the rejected peer is dropped");
        // And the other peer's permission still goes out.
        let second = take_send(&mut client, 0);
        let message = parse(&second).expect("parse");
        assert_eq!(
            turn::xor_peer_address(&message),
            Some(addr("198.51.100.21:40000"))
        );
    }

    #[test]
    fn a_rejected_refresh_ends_the_allocation() {
        // There is no way to keep it alive, so continuing to advertise the relayed candidate would
        // advertise an address that has stopped relaying.
        let mut client = allocated();
        let refresh = take_send(&mut client, 450_000);
        client.on_datagram(
            &error_for(
                &refresh,
                turn::METHOD_REFRESH,
                turn::ERROR_ALLOCATION_MISMATCH,
                None,
            ),
            450_000,
        );
        assert!(matches!(
            client.state(),
            TurnState::Failed(TurnFailure::Rejected { code: 437, .. })
        ));
        assert_eq!(client.relayed_address(), None);
    }

    #[test]
    fn close_deletes_the_allocation_with_a_zero_lifetime_refresh() {
        // RFC 5766 §7.1. Without this the server holds the relay port until the lifetime lapses,
        // which on a busy node is a real resource leak across call teardowns.
        let mut client = allocated();
        client.close();
        let delete = take_send(&mut client, 0);
        let message = parse(&delete).expect("parse");
        assert_eq!(method_of(message.message_type), turn::METHOD_REFRESH);
        assert_eq!(turn::lifetime(&message), Some(0));

        client.on_datagram(&success_for(&delete, turn::METHOD_REFRESH), 0);
        assert_eq!(client.state(), &TurnState::Closed);
        assert!(client.is_terminal());
        assert_eq!(client.poll(1_000), TurnAction::Idle);
    }

    #[test]
    fn a_server_that_never_answers_fails_the_allocation_rather_than_hanging() {
        let mut client = client();
        let _probe = take_send(&mut client, 0);
        // RFC 8489 §6.2.1 with Rc=7, Rm=16 and a 500 ms RTO gives up at 39.5 s.
        let mut now = 0;
        while now < 60_000 && !client.is_terminal() {
            let _ = client.poll(now);
            now += 500;
        }
        assert_eq!(client.state(), &TurnState::Failed(TurnFailure::Timeout));
    }

    #[test]
    fn a_rejected_allocation_reports_the_servers_code_and_reason() {
        // e.g. 486 Allocation Quota Reached — the operator needs to see which, not just "no relay".
        let mut client = client();
        let probe = take_send(&mut client, 0);
        client.on_datagram(&challenge(&probe), 0);
        let authed = take_send(&mut client, 0);
        client.on_datagram(
            &error_for(
                &authed,
                turn::METHOD_ALLOCATE,
                turn::ERROR_ALLOCATION_QUOTA_REACHED,
                None,
            ),
            0,
        );
        assert!(matches!(
            client.state(),
            TurnState::Failed(TurnFailure::Rejected { code: 486, .. })
        ));
    }

    #[test]
    fn a_response_for_a_different_transaction_is_ignored() {
        // The transaction id is the anti-spoofing token (RFC 8489 §5): an off-path attacker who
        // cannot see it must not be able to plant a relayed address in our candidate list.
        let mut client = client();
        let probe = take_send(&mut client, 0);
        client.on_datagram(&challenge(&probe), 0);
        let authed = take_send(&mut client, 0);

        let mut forged = allocate_success(&authed, 600);
        forged[8] ^= 0xFF; // corrupt the transaction id
        assert!(!client.on_datagram(&forged, 0));
        assert!(!client.is_allocated());

        // The genuine response still lands.
        assert!(client.on_datagram(&allocate_success(&authed, 600), 0));
        assert!(client.is_allocated());
    }

    #[test]
    fn garbage_from_the_server_is_not_consumed_and_never_panics() {
        let mut client = client();
        let _probe = take_send(&mut client, 0);
        for datagram in [
            [].as_slice(),
            &[0x00],
            &[0x00, 0x03, 0xFF, 0xFF],
            &[0xFF; 64],
        ] {
            assert!(!client.on_datagram(datagram, 0));
        }
        assert!(
            !client.is_terminal(),
            "garbage does not kill the allocation"
        );
    }
}
