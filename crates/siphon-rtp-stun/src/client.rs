//! STUN **client** side of ICE (RFC 8445): outbound Binding requests for connectivity checks and
//! consent freshness (RFC 7675), the transaction machinery that drives their retransmission, and the
//! ICE-specific STUN attributes (PRIORITY, USE-CANDIDATE, ICE-CONTROLL(ED|ING), ERROR-CODE).
//!
//! Pure codec + logic, **zero I/O**: the owning leg task sends the bytes and feeds arrival ticks
//! back in. Retransmission is expressed in the datapath's **logical ticks** and driven by
//! [`Transaction::poll`] — never a timer thread, never `Instant::now()` — so the whole state machine
//! is deterministic under test. Builds on the base [`MessageBuilder`] /
//! HMAC-SHA1 / CRC-32 in [`crate`], adding no new crypto dependency; the only new dependency is
//! `getrandom`, for the 96-bit transaction id (the mirror of `siphon-rtp-engine`'s credential RNG).
//!
//! The [`turn`](crate::turn) sibling is the same idea for TURN; this module is the ICE client.
//! See `docs/security-and-nat.md` §4 layer 4.

use std::fmt;

use super::{MessageBuilder, StunMessage, ATTR_USERNAME, BINDING_REQUEST};

/// PRIORITY attribute (RFC 8445 §7.1.1 / §16.1) — the candidate priority a check advertises, a
/// big-endian `u32`.
pub const ATTR_PRIORITY: u16 = 0x0024;
/// USE-CANDIDATE attribute (RFC 8445 §7.1.1 / §16.1) — a flag (empty value); the controlling agent
/// sets it on the check for the pair it nominates.
pub const ATTR_USE_CANDIDATE: u16 = 0x0025;
/// ICE-CONTROLLED attribute (RFC 8445 §7.1.3 / §16.1) — carried by the controlled agent; value is
/// its 64-bit tie-breaker.
pub const ATTR_ICE_CONTROLLED: u16 = 0x8029;
/// ICE-CONTROLLING attribute (RFC 8445 §7.1.3 / §16.1) — carried by the controlling agent; value is
/// its 64-bit tie-breaker.
pub const ATTR_ICE_CONTROLLING: u16 = 0x802A;
/// ERROR-CODE attribute (RFC 5389 §15.6) — carried by an error response (e.g. 487 Role Conflict).
pub const ATTR_ERROR_CODE: u16 = 0x0009;

/// Binding **error** response message type (class = error, method = Binding) — RFC 5389 §6. The
/// error-class counterpart of [`BINDING_SUCCESS`](super::BINDING_SUCCESS) (`0x0101`).
pub const BINDING_ERROR: u16 = 0x0111;

/// Default number of Binding requests sent before a transaction is abandoned (`Rc`, RFC 8489
/// §6.2.1). 7 requests at doubling intervals.
pub const DEFAULT_RC: u32 = 7;
/// Default multiple of the RTO to wait after the *last* request before declaring failure (`Rm`,
/// RFC 8489 §6.2.1). With `Rc`=7, `Rm`=16 and a 500 ms RTO the transaction fails at 39.5 s.
pub const DEFAULT_RM: u32 = 16;

/// The 96-bit STUN transaction id (RFC 8489 §5) — both the response-correlation key and the
/// off-path-attacker anti-spoofing token (an attacker who cannot see it cannot forge a response).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId([u8; 12]);

impl TransactionId {
    /// Draw a fresh transaction id from the OS CSPRNG. Returns `None` if the OS RNG is unavailable
    /// (the caller then declines to start the transaction), mirroring
    /// `siphon_rtp_engine::ice::generate_credentials` — never `unwrap`.
    #[must_use]
    pub fn new() -> Option<Self> {
        let mut id = [0u8; 12];
        getrandom::fill(&mut id).ok()?;
        Some(Self(id))
    }

    /// The raw 12 bytes, for [`MessageBuilder::new`](super::MessageBuilder::new) and correlation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

impl From<[u8; 12]> for TransactionId {
    fn from(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The ICE role of the sending agent plus its 64-bit tie-breaker (RFC 8445 §5.2). Selects
/// ICE-CONTROLLING vs ICE-CONTROLLED on an outgoing check and resolves a role conflict (§7.3.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    /// The controlling agent — nominates the pair (sets USE-CANDIDATE); tie-breaker in
    /// ICE-CONTROLLING.
    Controlling(u64),
    /// The controlled agent; tie-breaker in ICE-CONTROLLED.
    Controlled(u64),
}

/// The retransmission timetable for a STUN request over an unreliable transport (RFC 8489 §6.2.1),
/// in **logical ticks**. Requests go out at cumulative doubling offsets (0, RTO, 3·RTO, 7·RTO, …)
/// for `rc` requests total; the transaction fails `rm`·RTO after the last one. Pure arithmetic — the
/// owning task supplies the current tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetransmitSchedule {
    /// The retransmission timeout, in logical ticks (RFC 8489 recommends a 500 ms initial RTO; the
    /// tick↔wall-time mapping is the caller's — the engine drives this off the datapath sweeper).
    rto_ticks: u64,
    /// Total requests to send before giving up (`Rc`).
    rc: u32,
    /// Multiple of RTO to wait after the last request before failing (`Rm`).
    rm: u32,
}

impl RetransmitSchedule {
    /// A schedule with the RFC 8489 default `Rc`=7 / `Rm`=16 and the given RTO in ticks.
    #[must_use]
    pub fn new(rto_ticks: u64) -> Self {
        Self {
            rto_ticks,
            rc: DEFAULT_RC,
            rm: DEFAULT_RM,
        }
    }

    /// A schedule with explicit limits (for tests / non-default policy).
    #[must_use]
    pub fn with_limits(rto_ticks: u64, rc: u32, rm: u32) -> Self {
        Self { rto_ticks, rc, rm }
    }

    /// The tick offset (from the transaction start) at which request number `attempt` (0-indexed) is
    /// due: `(2^attempt − 1)·RTO`. `None` once `attempt` reaches `Rc` — no further request is sent,
    /// only the final [`timeout_offset`](Self::timeout_offset) wait remains. Saturating / `checked_shl`
    /// so an out-of-range `attempt` can never panic.
    #[must_use]
    pub fn send_offset(&self, attempt: u32) -> Option<u64> {
        if attempt >= self.rc {
            return None;
        }
        let factor = match 1u64.checked_shl(attempt) {
            Some(power) => power - 1,
            None => u64::MAX,
        };
        Some(factor.saturating_mul(self.rto_ticks))
    }

    /// The tick offset at which the transaction is declared failed: the last request's offset plus
    /// `Rm`·RTO (RFC 8489 §6.2.1).
    #[must_use]
    pub fn timeout_offset(&self) -> u64 {
        let last = self.send_offset(self.rc.saturating_sub(1)).unwrap_or(0);
        last.saturating_add(u64::from(self.rm).saturating_mul(self.rto_ticks))
    }
}

/// Why a transaction ended without success.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransactionFailure {
    /// No valid response arrived within the RFC 8489 §6.2.1 retransmission window.
    #[error("STUN transaction timed out with no response")]
    Timeout,
}

/// The lifecycle of one outstanding Binding transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionState {
    /// Awaiting a response (possibly mid-retransmit).
    Pending,
    /// A valid, correlated response was received.
    Succeeded,
    /// The transaction gave up.
    Failed(TransactionFailure),
}

/// What [`Transaction::poll`] asks the owning task to do this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionAction {
    /// Nothing due yet (or the transaction already settled); poll again on a later tick.
    Wait,
    /// Re-send the request now; the argument is the running request count (for logging).
    Retransmit(u32),
    /// The transaction just transitioned to [`TransactionState::Failed`].
    Failed,
}

/// One outstanding Binding request, driving its own RFC 8489 retransmission off the **logical
/// clock**. The caller sends the first request when it calls [`start`](Self::start), then calls
/// [`poll`](Self::poll) each tick (re-sending on [`TransactionAction::Retransmit`]) and
/// [`on_response`](Self::on_response) when a datagram arrives. No I/O, no wall clock, no timer task.
#[derive(Debug, Clone)]
pub struct Transaction {
    id: TransactionId,
    schedule: RetransmitSchedule,
    started_tick: u64,
    requests_sent: u32,
    state: TransactionState,
}

impl Transaction {
    /// Begin a transaction whose first request the caller sends now, at `now_tick`.
    #[must_use]
    pub fn start(id: TransactionId, schedule: RetransmitSchedule, now_tick: u64) -> Self {
        Self {
            id,
            schedule,
            started_tick: now_tick,
            requests_sent: 1,
            state: TransactionState::Pending,
        }
    }

    /// The transaction id (the correlation key).
    #[must_use]
    pub fn id(&self) -> &TransactionId {
        &self.id
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> &TransactionState {
        &self.state
    }

    /// Whether the transaction is still awaiting a response.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self.state, TransactionState::Pending)
    }

    /// Correlate an arrived response by its transaction id. On a match while pending, transitions to
    /// [`TransactionState::Succeeded`] and returns `true`. The caller MUST have already verified the
    /// response's MESSAGE-INTEGRITY (with the peer's password) — the transaction id alone is the
    /// correlation key, not the authenticator.
    pub fn on_response(&mut self, response_id: &[u8; 12]) -> bool {
        if self.is_pending() && response_id == self.id.as_bytes() {
            self.state = TransactionState::Succeeded;
            true
        } else {
            false
        }
    }

    /// Drive the retransmission clock at `now_tick`. Returns the single action due this tick;
    /// settles the state to `Failed(Timeout)` once the RFC 8489 window elapses.
    pub fn poll(&mut self, now_tick: u64) -> TransactionAction {
        if !self.is_pending() {
            return TransactionAction::Wait;
        }
        let elapsed = now_tick.saturating_sub(self.started_tick);
        if elapsed >= self.schedule.timeout_offset() {
            self.state = TransactionState::Failed(TransactionFailure::Timeout);
            return TransactionAction::Failed;
        }
        if let Some(due) = self.schedule.send_offset(self.requests_sent) {
            if elapsed >= due {
                self.requests_sent += 1;
                return TransactionAction::Retransmit(self.requests_sent);
            }
        }
        TransactionAction::Wait
    }
}

// --- Message builders -------------------------------------------------------------------------

/// Build an ICE connectivity-check Binding request (RFC 8445 §7.1.1): PRIORITY, the role attribute
/// (ICE-CONTROLLING/ICE-CONTROLLED with the tie-breaker), an optional USE-CANDIDATE, and USERNAME
/// (`<peer-ufrag>:<local-ufrag>`), authenticated with `integrity_key` (the peer's password) and a
/// FINGERPRINT — MESSAGE-INTEGRITY and FINGERPRINT appended last, in that order.
#[must_use]
pub fn binding_request_ice(
    transaction_id: &[u8; 12],
    username: &str,
    integrity_key: &[u8],
    priority: u32,
    role: IceRole,
    use_candidate: bool,
) -> Vec<u8> {
    let (role_attr, tie_breaker) = match role {
        IceRole::Controlling(tie) => (ATTR_ICE_CONTROLLING, tie),
        IceRole::Controlled(tie) => (ATTR_ICE_CONTROLLED, tie),
    };
    let mut builder = MessageBuilder::new(BINDING_REQUEST, transaction_id)
        .attribute(ATTR_PRIORITY, &priority.to_be_bytes())
        .attribute(role_attr, &tie_breaker.to_be_bytes());
    if use_candidate {
        builder = builder.attribute(ATTR_USE_CANDIDATE, &[]);
    }
    builder
        .attribute(ATTR_USERNAME, username.as_bytes())
        .finish(Some(integrity_key), true)
}

/// Build a Binding **error** response (RFC 5389 §6/§15.6) carrying an ERROR-CODE (`code` = e.g. 487
/// Role Conflict, 400 Bad Request), authenticated with `integrity_key` when `Some` (the local
/// password) and a FINGERPRINT. Reuses [`crate::turn::error_code_value`] for the ERROR-CODE encoding.
#[must_use]
pub fn binding_error_response(
    transaction_id: &[u8; 12],
    code: u16,
    reason: &str,
    integrity_key: Option<&[u8]>,
) -> Vec<u8> {
    MessageBuilder::new(BINDING_ERROR, transaction_id)
        .attribute(
            ATTR_ERROR_CODE,
            &crate::turn::error_code_value(code, reason),
        )
        .finish(integrity_key, true)
}

// --- ICE attribute accessors ------------------------------------------------------------------

/// The PRIORITY value a check advertises (RFC 8445 §7.1.1), if present and well-formed.
#[must_use]
pub fn priority(message: &StunMessage) -> Option<u32> {
    let bytes: [u8; 4] = message
        .attribute(ATTR_PRIORITY)?
        .get(0..4)?
        .try_into()
        .ok()?;
    Some(u32::from_be_bytes(bytes))
}

/// The ICE-CONTROLLING tie-breaker (RFC 8445 §7.1.3), if present.
#[must_use]
pub fn ice_controlling(message: &StunMessage) -> Option<u64> {
    tie_breaker(message, ATTR_ICE_CONTROLLING)
}

/// The ICE-CONTROLLED tie-breaker (RFC 8445 §7.1.3), if present.
#[must_use]
pub fn ice_controlled(message: &StunMessage) -> Option<u64> {
    tie_breaker(message, ATTR_ICE_CONTROLLED)
}

fn tie_breaker(message: &StunMessage, attr: u16) -> Option<u64> {
    let bytes: [u8; 8] = message.attribute(attr)?.get(0..8)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// Whether the check carries USE-CANDIDATE (RFC 8445 §7.1.1) — the controlling agent nominating this
/// pair.
#[must_use]
pub fn has_use_candidate(message: &StunMessage) -> bool {
    message.attribute(ATTR_USE_CANDIDATE).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse, verify_message_integrity};

    #[test]
    fn transaction_id_is_twelve_random_bytes_and_hex_displays() {
        let id = TransactionId::new().expect("OS RNG available");
        assert_eq!(id.as_bytes().len(), 12);
        // Display is 24 lowercase hex chars.
        let shown = id.to_string();
        assert_eq!(shown.len(), 24);
        assert!(shown.chars().all(|character| character.is_ascii_hexdigit()));
        // Two draws differ (96 bits — a collision is astronomically unlikely).
        let other = TransactionId::new().expect("rng");
        assert_ne!(id, other);
        // Round-trips through the raw bytes.
        assert_eq!(TransactionId::from(*id.as_bytes()), id);
    }

    #[test]
    fn retransmit_schedule_matches_rfc8489_doubling() {
        // With RTO = 1 tick and the RFC defaults, requests are due at 0, 1, 3, 7, 15, 31, 63 ticks.
        let schedule = RetransmitSchedule::new(1);
        let offsets: Vec<Option<u64>> = (0..8).map(|n| schedule.send_offset(n)).collect();
        assert_eq!(
            offsets,
            vec![
                Some(0),
                Some(1),
                Some(3),
                Some(7),
                Some(15),
                Some(31),
                Some(63),
                None, // attempt 7 == Rc: no further request
            ]
        );
        // Failure at 63 (last request) + 16·RTO = 79 ticks.
        assert_eq!(schedule.timeout_offset(), 79);
    }

    #[test]
    fn retransmit_schedule_scales_with_rto_and_limits() {
        // RTO = 25 ticks (a 500 ms RTO at 20 ms/tick), Rc = 3, Rm = 16.
        let schedule = RetransmitSchedule::with_limits(25, 3, 16);
        assert_eq!(schedule.send_offset(0), Some(0));
        assert_eq!(schedule.send_offset(1), Some(25));
        assert_eq!(schedule.send_offset(2), Some(75));
        assert_eq!(schedule.send_offset(3), None);
        // last request at 75, + 16·25 = 475 ticks.
        assert_eq!(schedule.timeout_offset(), 75 + 400);
    }

    #[test]
    fn out_of_range_attempt_never_panics() {
        // A pathological schedule must not panic on a huge attempt index (shift overflow guard).
        let schedule = RetransmitSchedule::with_limits(3, 200, 16);
        assert_eq!(schedule.send_offset(199), Some(u64::MAX)); // saturated, not panicked
        assert_eq!(schedule.send_offset(200), None);
        let _ = schedule.timeout_offset();
    }

    #[test]
    fn transaction_retransmits_then_times_out_on_the_logical_clock() {
        let schedule = RetransmitSchedule::new(1); // requests due at 0,1,3,7,15,31,63; fail at 79
        let mut transaction = Transaction::start(TransactionId::from([9u8; 12]), schedule, 100);
        // Right after start nothing is due (first request already sent by the caller).
        assert_eq!(transaction.poll(100), TransactionAction::Wait);
        // At +1 tick the 2nd request is due, at +3 the 3rd, etc.
        assert_eq!(transaction.poll(101), TransactionAction::Retransmit(2));
        assert_eq!(transaction.poll(102), TransactionAction::Wait);
        assert_eq!(transaction.poll(103), TransactionAction::Retransmit(3));
        for tick in [107, 115, 131, 163] {
            assert!(matches!(
                transaction.poll(tick),
                TransactionAction::Retransmit(_)
            ));
        }
        // All Rc requests sent; still pending, waiting out the final Rm·RTO window.
        assert!(transaction.is_pending());
        assert_eq!(transaction.poll(178), TransactionAction::Wait);
        // At start + 79 ticks the transaction fails.
        assert_eq!(transaction.poll(179), TransactionAction::Failed);
        assert_eq!(
            transaction.state(),
            &TransactionState::Failed(TransactionFailure::Timeout)
        );
        // Once settled, poll is inert.
        assert_eq!(transaction.poll(500), TransactionAction::Wait);
    }

    #[test]
    fn transaction_succeeds_only_on_a_matching_response_id() {
        let mut transaction = Transaction::start(
            TransactionId::from([7u8; 12]),
            RetransmitSchedule::new(1),
            0,
        );
        assert!(!transaction.on_response(&[1u8; 12])); // wrong id ignored
        assert!(transaction.is_pending());
        assert!(transaction.on_response(&[7u8; 12])); // correct id
        assert_eq!(transaction.state(), &TransactionState::Succeeded);
        // A settled transaction no longer retransmits or re-succeeds.
        assert_eq!(transaction.poll(1000), TransactionAction::Wait);
        assert!(!transaction.on_response(&[7u8; 12]));
    }

    #[test]
    fn binding_request_ice_roundtrips_attributes_and_verifies_integrity() {
        let transaction_id = [3u8; 12];
        let key = b"remote-ice-password-000";
        let request = binding_request_ice(
            &transaction_id,
            "peerFrag:localFrag",
            key,
            0x6e00_01ff,
            IceRole::Controlling(0x932f_f9b1_5126_3b36),
            true,
        );
        let parsed = parse(&request).expect("parse our own check");
        assert!(parsed.is_binding_request());
        assert_eq!(parsed.username(), Some("peerFrag:localFrag"));
        assert_eq!(priority(&parsed), Some(0x6e00_01ff));
        assert_eq!(ice_controlling(&parsed), Some(0x932f_f9b1_5126_3b36));
        assert_eq!(ice_controlled(&parsed), None);
        assert!(has_use_candidate(&parsed));
        // MESSAGE-INTEGRITY verifies with the key and fails with a wrong one.
        assert!(verify_message_integrity(&request, key));
        assert!(!verify_message_integrity(&request, b"wrong"));
    }

    #[test]
    fn controlled_role_and_no_nomination_encode_the_other_way() {
        let request = binding_request_ice(
            &[0u8; 12],
            "a:b",
            b"key",
            100,
            IceRole::Controlled(42),
            false,
        );
        let parsed = parse(&request).expect("parse");
        assert_eq!(ice_controlled(&parsed), Some(42));
        assert_eq!(ice_controlling(&parsed), None);
        assert!(!has_use_candidate(&parsed));
    }

    #[test]
    fn binding_error_response_carries_the_code_and_verifies() {
        let transaction_id = [5u8; 12];
        let key = b"local-password";
        let response = binding_error_response(&transaction_id, 487, "Role Conflict", Some(key));
        let parsed = parse(&response).expect("parse error response");
        assert_eq!(parsed.message_type, BINDING_ERROR);
        assert_eq!(parsed.transaction_id, transaction_id);
        // ERROR-CODE decodes back to 487 via the shared TURN accessor (no duplicate decoder).
        assert_eq!(crate::turn::error_code(&parsed), Some(487));
        assert!(verify_message_integrity(&response, key));
    }
}
