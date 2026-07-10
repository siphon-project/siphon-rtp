//! RFC 7675 ICE **consent freshness** — the per-endpoint checker that keeps proving a remote ICE
//! peer still wants our media, and declares the pair dead when it stops answering.
//!
//! Pure logic, **zero I/O**, driven entirely by the datapath's **logical clock** (never
//! `Instant::now()`): the daemon sweeper calls [`ConsentChecker::poll`] once per tick and transmits
//! whatever [`ConsentAction::SendCheck`] returns, and calls [`ConsentChecker::on_response`] with each
//! STUN datagram the full-agent seam ([`siphon_rtp_datapath::IceDatapathEvent`]) delivers back. A
//! valid, correlated, MI-verified Binding response refreshes consent; after `timeout_ticks` with no
//! refresh the checker returns [`ConsentAction::Failed`] and the sweeper tears the call down.
//!
//! Behaviour (RFC 7675 §5.1): send a Binding request to the peer with USERNAME
//! `<remote-ufrag>:<local-ufrag>`, MESSAGE-INTEGRITY keyed by the **remote** password, plus PRIORITY
//! and the ICE role for interop; retransmit an in-flight check per the RFC 8489 RTO
//! ([`RetransmitSchedule`]); a lost check is not immediate failure — only the `timeout_ticks` (30 s)
//! window with no response fails the pair. Checks recur every `interval_ticks` (~5 s) with a
//! deterministic, seedable jitter so many endpoints do not synchronise.

use std::net::SocketAddr;

use siphon_rtp_stun::{
    self as stun,
    client::{
        binding_request_ice, IceRole, RetransmitSchedule, Transaction, TransactionAction,
        TransactionId,
    },
};

/// Construction parameters for a [`ConsentChecker`]. A struct (not a long argument list) so the
/// engine wiring reads clearly and clippy stays quiet.
#[derive(Debug, Clone)]
pub struct ConsentParams {
    /// Where to send checks — the peer's media transport address.
    pub remote_addr: SocketAddr,
    /// Our local ICE username fragment (the second half of the check USERNAME).
    pub local_ufrag: String,
    /// The peer's ICE username fragment (the first half of the check USERNAME).
    pub remote_ufrag: String,
    /// The peer's ICE password — keys our check's MESSAGE-INTEGRITY and verifies the response.
    pub remote_pwd: String,
    /// The PRIORITY we advertise on the check (RFC 8445 §7.1.1).
    pub priority: u32,
    /// Our ICE role + tie-breaker (RFC 8445 §5.2).
    pub role: IceRole,
    /// Ticks between fresh checks (~5 s at the 1 Hz sweeper), before jitter.
    pub interval_ticks: u64,
    /// Ticks with no correlated response after which consent is declared failed (~30 s).
    pub timeout_ticks: u64,
    /// Per-check retransmission timeout in ticks (RFC 8489 §6.2.1 initial RTO).
    pub rto_ticks: u64,
    /// Seed for the deterministic jitter PRNG (per endpoint, so checks de-synchronise).
    pub seed: u64,
}

/// What [`ConsentChecker::poll`] asks the sweeper to do this tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentAction {
    /// Nothing due this tick.
    Idle,
    /// Transmit `datagram` (a fresh check or a retransmit) to `dst` via `Datapath::send`.
    SendCheck {
        /// The peer transport to send to.
        dst: SocketAddr,
        /// The STUN Binding request bytes.
        datagram: Vec<u8>,
    },
    /// Consent has expired — no response within the window; tear the pair down.
    Failed,
}

/// Per-endpoint RFC 7675 consent state. One owner (the sweeper task); no shared locks.
#[derive(Debug, Clone)]
pub struct ConsentChecker {
    remote_addr: SocketAddr,
    /// Precomputed `<remote-ufrag>:<local-ufrag>` (RFC 8445 §7.1.2), built once.
    username: String,
    remote_pwd: String,
    priority: u32,
    role: IceRole,
    interval_ticks: u64,
    timeout_ticks: u64,
    schedule: RetransmitSchedule,
    /// Tick of the last correlated, MI-verified response (initialised to creation: a fresh pair has
    /// the full window to earn its first response).
    last_consent_tick: u64,
    /// Tick at which the next *fresh* check is due.
    next_check_tick: u64,
    /// The in-flight check transaction, if any.
    pending: Option<Transaction>,
    /// Deterministic jitter PRNG state (xorshift64; seeded, never `Instant::now()`).
    rng_state: u64,
}

impl ConsentChecker {
    /// Start consent for a freshly established pair at `now_tick`. The first check is due
    /// immediately (the next [`poll`](Self::poll) emits it).
    #[must_use]
    pub fn new(params: ConsentParams, now_tick: u64) -> Self {
        let username = format!("{}:{}", params.remote_ufrag, params.local_ufrag);
        Self {
            remote_addr: params.remote_addr,
            username,
            remote_pwd: params.remote_pwd,
            priority: params.priority,
            role: params.role,
            interval_ticks: params.interval_ticks.max(1),
            timeout_ticks: params.timeout_ticks.max(1),
            schedule: RetransmitSchedule::new(params.rto_ticks.max(1)),
            last_consent_tick: now_tick,
            next_check_tick: now_tick,
            pending: None,
            // A zero seed would make xorshift stick at zero; force it non-zero.
            rng_state: params.seed | 1,
        }
    }

    /// The tick of the last refreshed consent (for the wiring layer's diagnostics).
    #[must_use]
    pub fn last_consent_tick(&self) -> u64 {
        self.last_consent_tick
    }

    /// Drive consent at `now_tick`. Returns the single action due this tick. The sweeper MUST call
    /// [`on_response`](Self::on_response) for any arrived STUN *before* `poll` so a just-received
    /// refresh is seen this tick.
    pub fn poll(&mut self, now_tick: u64) -> ConsentAction {
        // 1. Expiry: no correlated response within the window.
        if now_tick.saturating_sub(self.last_consent_tick) >= self.timeout_ticks {
            return ConsentAction::Failed;
        }
        // 2. Drive the in-flight check's retransmission (copy the txn id out so no borrow of
        //    `self.pending` is held across `build_check`).
        let outcome = self
            .pending
            .as_mut()
            .map(|transaction| (transaction.poll(now_tick), *transaction.id()));
        if let Some((action, transaction_id)) = outcome {
            match action {
                TransactionAction::Retransmit(_) => {
                    return ConsentAction::SendCheck {
                        dst: self.remote_addr,
                        datagram: self.build_check(&transaction_id),
                    };
                }
                TransactionAction::Failed => self.pending = None,
                TransactionAction::Wait => return ConsentAction::Idle,
            }
        }
        // 3. Start a fresh check when due.
        if self.pending.is_none() && now_tick >= self.next_check_tick {
            let Some(transaction_id) = TransactionId::new() else {
                // OS RNG unavailable this tick — retry next tick, never panic.
                return ConsentAction::Idle;
            };
            self.pending = Some(Transaction::start(transaction_id, self.schedule, now_tick));
            self.next_check_tick = now_tick + self.next_interval();
            return ConsentAction::SendCheck {
                dst: self.remote_addr,
                datagram: self.build_check(&transaction_id),
            };
        }
        ConsentAction::Idle
    }

    /// Correlate an arrived STUN datagram. Refreshes consent (and returns `true`) only for a Binding
    /// **success** response whose transaction id matches the in-flight check and whose
    /// MESSAGE-INTEGRITY verifies with the remote password. Requests and forged/uncorrelated
    /// datagrams are ignored (the datapath responder already answered any inbound checks).
    pub fn on_response(&mut self, datagram: &[u8], now_tick: u64) -> bool {
        let Some(pending_id) = self.pending.as_ref().map(|transaction| *transaction.id()) else {
            return false;
        };
        let Ok(message) = stun::parse(datagram) else {
            return false;
        };
        if message.message_type != stun::BINDING_SUCCESS
            || &message.transaction_id != pending_id.as_bytes()
            || !stun::verify_message_integrity(datagram, self.remote_pwd.as_bytes())
        {
            return false;
        }
        self.pending = None;
        self.last_consent_tick = now_tick;
        true
    }

    /// Build a consent Binding request for `transaction_id` (RFC 7675 §5.1 / RFC 8445 §7.1.2).
    fn build_check(&self, transaction_id: &TransactionId) -> Vec<u8> {
        binding_request_ice(
            transaction_id.as_bytes(),
            &self.username,
            self.remote_pwd.as_bytes(),
            self.priority,
            self.role,
            false, // consent checks never nominate (USE-CANDIDATE is for the checklist, M2)
        )
    }

    /// The next inter-check interval with a deterministic ±20 % jitter (RFC 7675 §5.1 recommends
    /// randomisation so endpoints do not synchronise). xorshift64 keeps it seedable and test-stable.
    fn next_interval(&mut self) -> u64 {
        let mut state = self.rng_state;
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        self.rng_state = state;
        let spread = (self.interval_ticks / 5).max(1);
        let offset = (state % (2 * spread + 1)) as i64 - spread as i64;
        (self.interval_ticks as i64 + offset).max(1) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ConsentParams {
        ConsentParams {
            remote_addr: "192.0.2.7:40000".parse().expect("addr"),
            local_ufrag: "lFrag".into(),
            remote_ufrag: "rFrag".into(),
            remote_pwd: "remote-ice-password-000".into(),
            priority: 0x6e00_01ff,
            role: IceRole::Controlling(0x0123_4567_89ab_cdef),
            interval_ticks: 5,
            timeout_ticks: 30,
            rto_ticks: 1,
            seed: 0xdead_beef,
        }
    }

    /// Extract the STUN datagram from a `SendCheck` action (test helper).
    fn sent(action: ConsentAction) -> Vec<u8> {
        match action {
            ConsentAction::SendCheck { datagram, .. } => datagram,
            other => panic!("expected SendCheck, got {other:?}"),
        }
    }

    #[test]
    fn first_poll_sends_a_check_addressed_to_the_peer() {
        let mut checker = ConsentChecker::new(params(), 0);
        let action = checker.poll(0);
        assert!(matches!(
            action,
            ConsentAction::SendCheck { dst, .. } if dst == "192.0.2.7:40000".parse().unwrap()
        ));
        let datagram = sent(action);
        let message = stun::parse(&datagram).expect("valid check");
        assert!(message.is_binding_request());
        assert_eq!(message.username(), Some("rFrag:lFrag"));
        assert_eq!(stun::client::priority(&message), Some(0x6e00_01ff));
        assert_eq!(
            stun::client::ice_controlling(&message),
            Some(0x0123_4567_89ab_cdef)
        );
        // Signed with the remote password (what the peer verifies + signs its response with).
        assert!(stun::verify_message_integrity(
            &datagram,
            b"remote-ice-password-000"
        ));
    }

    /// Build the peer's success response to whatever check the checker just sent.
    fn peer_response(datagram: &[u8], pwd: &[u8]) -> Vec<u8> {
        let request = stun::parse(datagram).expect("parse check");
        stun::binding_success_response(
            &request.transaction_id,
            "192.0.2.7:40000".parse().expect("addr"),
            Some(pwd),
        )
    }

    #[test]
    fn correlated_response_refreshes_consent_and_reschedules() {
        let mut checker = ConsentChecker::new(params(), 0);
        let check = sent(checker.poll(0));
        // The peer answers next tick; the sweeper feeds it in before polling.
        let response = peer_response(&check, b"remote-ice-password-000");
        assert!(
            checker.on_response(&response, 1),
            "correlated + MI-verified"
        );
        assert_eq!(checker.last_consent_tick(), 1);
        assert_eq!(
            checker.poll(1),
            ConsentAction::Idle,
            "next check not due yet"
        );

        // A fresh check goes out around one interval later (jittered ±20 %), never Failed.
        let mut next_check = None;
        for tick in 2..=8 {
            match checker.poll(tick) {
                ConsentAction::SendCheck { .. } => {
                    next_check = Some(tick);
                    break;
                }
                ConsentAction::Idle => {}
                ConsentAction::Failed => panic!("must not fail while consent is fresh"),
            }
        }
        let tick = next_check.expect("a fresh check within the jittered interval");
        assert!((4..=6).contains(&tick), "check at ~interval, got {tick}");
    }

    #[test]
    fn retransmits_a_lost_check_without_failing() {
        let mut checker = ConsentChecker::new(params(), 0);
        assert!(matches!(checker.poll(0), ConsentAction::SendCheck { .. }));
        // rto = 1 tick: the check is retransmitted while no response arrives.
        assert!(
            matches!(checker.poll(1), ConsentAction::SendCheck { .. }),
            "a lost check is retransmitted, not failed"
        );
        // Still within the window: never Failed before the timeout.
        for tick in 2..30 {
            assert_ne!(checker.poll(tick), ConsentAction::Failed, "tick {tick}");
        }
    }

    #[test]
    fn fails_after_timeout_with_no_response() {
        let mut checker = ConsentChecker::new(params(), 0);
        let _ = checker.poll(0);
        // No response ever arrives; at exactly timeout_ticks the pair is declared dead.
        for tick in 1..30 {
            assert_ne!(checker.poll(tick), ConsentAction::Failed, "tick {tick}");
        }
        assert_eq!(checker.poll(30), ConsentAction::Failed);
    }

    #[test]
    fn ignores_forged_and_uncorrelated_responses() {
        let mut checker = ConsentChecker::new(params(), 0);
        let check = sent(checker.poll(0));

        // Wrong transaction id.
        let wrong_txn = stun::binding_success_response(
            &[0xffu8; 12],
            "192.0.2.7:40000".parse().unwrap(),
            Some(b"remote-ice-password-000"),
        );
        assert!(!checker.on_response(&wrong_txn, 5));

        // Right transaction id but signed with the wrong password (an off-path forgery).
        let request = stun::parse(&check).expect("parse");
        let forged = stun::binding_success_response(
            &request.transaction_id,
            "192.0.2.7:40000".parse().unwrap(),
            Some(b"WRONG-PASSWORD"),
        );
        assert!(!checker.on_response(&forged, 5));

        // Consent was never refreshed, so it still expires on schedule.
        assert_eq!(checker.last_consent_tick(), 0);
        assert_eq!(checker.poll(30), ConsentAction::Failed);
    }

    #[test]
    fn jitter_is_deterministic_for_a_fixed_seed() {
        let mut first = ConsentChecker::new(params(), 0);
        let mut second = ConsentChecker::new(params(), 0);
        // Two checkers with the same seed must schedule checks on the same ticks. Compare the action
        // *variant* only — each SendCheck carries a fresh random transaction id, so the bytes differ.
        for tick in 0..40 {
            assert_eq!(
                std::mem::discriminant(&first.poll(tick)),
                std::mem::discriminant(&second.poll(tick)),
                "scheduling diverged at tick {tick}"
            );
        }
    }
}
