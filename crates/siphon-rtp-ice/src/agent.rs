//! The RFC 8445 full ICE agent: connectivity checks, both roles, peer-reflexive discovery, and
//! regular nomination.
//!
//! Pure like the rest of the crate. [`IceAgent::poll`] says what to transmit at a given logical
//! millisecond and [`IceAgent::on_datagram`] takes the wire back; the caller owns every socket. Two
//! agents can therefore be driven against each other in a unit test and complete a real ICE exchange
//! with no network at all, which is how the behaviour below is verified against the specification.
//!
//! # What this implements
//!
//! - **Checks** (§7.1): a Binding request with PRIORITY, the role attribute, and MESSAGE-INTEGRITY
//!   over `<remote-ufrag>:<local-ufrag>` keyed by the **remote** password.
//! - **Request handling** (§7.3): authenticate, answer, discover peer-reflexive *remote* candidates
//!   (§7.3.1.3), enqueue a triggered check (§7.3.1.4), honour USE-CANDIDATE (§7.3.1.5).
//! - **Response handling** (§7.2.5): symmetry check (§7.2.5.2.1), peer-reflexive *local* candidate
//!   discovery (§7.2.5.3.1), success + foundation unfreezing (§7.2.5.3.3).
//! - **Role conflict** (§7.3.1.1 / §7.2.5.1): tie-breaker comparison, the 487 error response, and the
//!   role switch on receiving one.
//! - **Regular nomination** (§8.1.1) and completion/failure (§8.1.2).
//!
//! # Aggressive nomination
//!
//! Never sent: RFC 8445 removed it. It is still *accepted* from an RFC 5245 peer when we are
//! controlled — such a peer sets USE-CANDIDATE on every check, and refusing to select would fail
//! calls against deployed SIP UAs.

use std::collections::HashMap;
use std::net::SocketAddr;

use siphon_rtp_stun::{
    self as stun,
    client::{
        self, binding_error_response, binding_request_ice, IceRole, RetransmitSchedule,
        Transaction, TransactionAction, TransactionId,
    },
};

use crate::candidate::{Candidate, CandidateKind, Transport};
use crate::checklist::{CandidatePair, Checklist, PairState};

/// RFC 8445 §14.2 `Ta`: minimum spacing between checks.
pub const DEFAULT_PACING_MS: u64 = 50;
/// RFC 8489 §6.2.1 initial RTO for a connectivity check.
pub const DEFAULT_RTO_MS: u64 = 500;
/// RFC 8445 §7.3.1.1 error code for a role conflict.
const ERROR_ROLE_CONFLICT: u16 = 487;

/// One side's short-term ICE credentials (RFC 8445 §5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// The username fragment.
    pub ufrag: String,
    /// The password.
    pub pwd: String,
}

impl Credentials {
    /// Build credentials from borrowed parts.
    #[must_use]
    pub fn new(ufrag: impl Into<String>, pwd: impl Into<String>) -> Self {
        Self {
            ufrag: ufrag.into(),
            pwd: pwd.into(),
        }
    }
}

/// How the agent is doing (a coarse view of RFC 8445 §6.1.2.6 / §8.1.2 for the caller).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceState {
    /// Checks are running; no pair has succeeded yet.
    Running,
    /// At least one pair is valid — media can flow, but nothing is nominated yet.
    Connected,
    /// A pair has been nominated and selected. ICE is done.
    Completed,
    /// Every pair failed. There is no usable path.
    Failed,
}

/// What the agent asks the caller to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentAction {
    /// Transmit `datagram` from the local candidate `from` to `to`.
    Send {
        /// The local transport address to send from (the pair's local candidate base).
        from: SocketAddr,
        /// The peer transport address to send to.
        to: SocketAddr,
        /// The STUN datagram.
        datagram: Vec<u8>,
    },
    /// The agent's state changed.
    StateChanged(IceState),
    /// A pair was selected (RFC 8445 §8.1.1). This is the path media must use from now on.
    Selected {
        /// Our side of the selected pair.
        local: SocketAddr,
        /// The peer's side.
        remote: SocketAddr,
    },
}

/// How to build an [`IceAgent`].
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Our credentials, as advertised in our SDP.
    pub local_credentials: Credentials,
    /// The peer's credentials, from its SDP.
    pub remote_credentials: Credentials,
    /// Our candidates (from gathering).
    pub local_candidates: Vec<Candidate>,
    /// The peer's candidates (from its SDP).
    pub remote_candidates: Vec<Candidate>,
    /// Whether we are the controlling agent (RFC 8445 §6.1.1: the offerer controls; against an
    /// ICE-lite peer the full agent always controls).
    pub controlling: bool,
    /// Our tie-breaker for role conflicts (RFC 8445 §5.2). MUST be drawn from a CSPRNG by the caller.
    pub tie_breaker: u64,
    /// `Ta` pacing between checks, in milliseconds.
    pub pacing_ms: u64,
    /// Initial RTO per check, in milliseconds.
    pub rto_ms: u64,
}

impl AgentConfig {
    /// A configuration with the RFC's default timers.
    #[must_use]
    pub fn new(
        local_credentials: Credentials,
        remote_credentials: Credentials,
        controlling: bool,
        tie_breaker: u64,
    ) -> Self {
        Self {
            local_credentials,
            remote_credentials,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            controlling,
            tie_breaker,
            pacing_ms: DEFAULT_PACING_MS,
            rto_ms: DEFAULT_RTO_MS,
        }
    }

    /// Set the candidate sets.
    #[must_use]
    pub fn with_candidates(mut self, local: Vec<Candidate>, remote: Vec<Candidate>) -> Self {
        self.local_candidates = local;
        self.remote_candidates = remote;
        self
    }
}

/// An outstanding connectivity check.
#[derive(Debug, Clone)]
struct OutstandingCheck {
    transaction: Transaction,
    /// Whether this check carried USE-CANDIDATE (so a success nominates the pair, §7.2.5.3.4).
    nominating: bool,
}

/// A full RFC 8445 ICE agent for one media component set.
#[derive(Debug)]
pub struct IceAgent {
    config: AgentConfig,
    checklist: Checklist,
    state: IceState,
    /// Pair index → its outstanding check.
    checks: HashMap<usize, OutstandingCheck>,
    /// Transaction id → pair index, for correlating responses.
    transactions: HashMap<[u8; 12], usize>,
    /// RFC 8445 §7.3.1.4 triggered-check queue — pairs to check ahead of the ordinary list.
    triggered: Vec<usize>,
    /// Earliest millisecond at which the next check may be transmitted (`Ta`).
    next_check_ms: u64,
    /// Checked pair → the valid pair its check produced (RFC 8445 §7.2.5.3.2). They differ whenever a
    /// peer-reflexive *local* candidate was discovered, and §7.3.1.5 nominates the **valid** one, so
    /// the peer's USE-CANDIDATE (which names the pair it checked) has to be resolved through this.
    generated_valid: HashMap<usize, usize>,
    /// The selected pair's index once nominated (§8.1.1).
    selected: Option<usize>,
    /// Set while we have nominated a pair and are awaiting its check (controlling side).
    nomination_sent: bool,
}

impl IceAgent {
    /// Build an agent and form its checklist.
    #[must_use]
    pub fn new(config: AgentConfig, now_ms: u64) -> Self {
        let checklist = Checklist::form(
            &config.local_candidates,
            &config.remote_candidates,
            config.controlling,
        );
        let state = if checklist.is_empty() {
            IceState::Failed
        } else {
            IceState::Running
        };
        Self {
            config,
            checklist,
            state,
            checks: HashMap::new(),
            transactions: HashMap::new(),
            triggered: Vec::new(),
            generated_valid: HashMap::new(),
            next_check_ms: now_ms,
            selected: None,
            nomination_sent: false,
        }
    }

    /// The agent's current state.
    #[must_use]
    pub fn state(&self) -> IceState {
        self.state
    }

    /// Whether we are currently the controlling agent (this can flip on a role conflict).
    #[must_use]
    pub fn is_controlling(&self) -> bool {
        self.config.controlling
    }

    /// The selected pair's transport addresses, once ICE has completed.
    #[must_use]
    pub fn selected_pair(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.selected.map(|index| {
            let pair = &self.checklist.pairs()[index];
            (pair.local.address, pair.remote.address)
        })
    }

    /// Read-only access to the checklist (diagnostics and tests).
    #[must_use]
    pub fn checklist(&self) -> &Checklist {
        &self.checklist
    }

    /// Drive the agent at `now_ms`: retransmit outstanding checks, start the next one, and nominate
    /// when we are controlling and have something valid to nominate.
    pub fn poll(&mut self, now_ms: u64) -> Vec<AgentAction> {
        let mut actions = Vec::new();
        if matches!(self.state, IceState::Failed | IceState::Completed) {
            return actions;
        }

        // 1. Retransmissions (RFC 8489 §6.2.1). These are not paced by `Ta` — the schedule owns them.
        let indices: Vec<usize> = self.checks.keys().copied().collect();
        for index in indices {
            let Some(check) = self.checks.get_mut(&index) else {
                continue;
            };
            let transaction_id = *check.transaction.id();
            let nominating = check.nominating;
            match check.transaction.poll(now_ms) {
                TransactionAction::Retransmit(_) => {
                    actions.push(self.build_check_action(index, &transaction_id, nominating));
                }
                TransactionAction::Failed => {
                    self.checks.remove(&index);
                    self.transactions.remove(transaction_id.as_bytes());
                    self.checklist.pairs_mut()[index].state = PairState::Failed;
                    self.recompute_state(&mut actions);
                }
                TransactionAction::Wait => {}
            }
        }

        // 2. Nominate (RFC 8445 §8.1.1, regular nomination): the controlling agent picks the
        //    highest-priority valid pair and re-checks it with USE-CANDIDATE.
        if self.config.controlling && !self.nomination_sent && self.selected.is_none() {
            if let Some(&best) = self.checklist.valid().first() {
                self.nomination_sent = true;
                if let Some(action) = self.start_check(best, now_ms, true) {
                    actions.push(action);
                    return actions;
                }
            }
        }

        // 3. Ordinary + triggered checks, paced at `Ta` (§6.1.4.2, §7.3.1.4).
        if now_ms < self.next_check_ms {
            return actions;
        }
        // Triggered checks take precedence over the ordinary list.
        let next = self
            .take_triggered()
            .or_else(|| self.checklist.next_waiting());
        if let Some(index) = next {
            if let Some(action) = self.start_check(index, now_ms, false) {
                self.next_check_ms = now_ms.saturating_add(self.config.pacing_ms.max(1));
                actions.push(action);
            }
        }
        actions
    }

    /// Pop the next triggered pair that is still worth checking.
    fn take_triggered(&mut self) -> Option<usize> {
        while !self.triggered.is_empty() {
            let index = self.triggered.remove(0);
            if self.checks.contains_key(&index) {
                continue; // already in flight
            }
            if index < self.checklist.len() {
                return Some(index);
            }
        }
        None
    }

    /// Begin a check on `index`, optionally nominating.
    fn start_check(&mut self, index: usize, now_ms: u64, nominating: bool) -> Option<AgentAction> {
        let transaction_id = TransactionId::new()?;
        let schedule = RetransmitSchedule::new(self.config.rto_ms.max(1));
        self.checks.insert(
            index,
            OutstandingCheck {
                transaction: Transaction::start(transaction_id, schedule, now_ms),
                nominating,
            },
        );
        self.transactions.insert(*transaction_id.as_bytes(), index);
        self.checklist.pairs_mut()[index].state = PairState::InProgress;
        Some(self.build_check_action(index, &transaction_id, nominating))
    }

    /// Build the Binding request for a pair (RFC 8445 §7.1.2).
    fn build_check_action(
        &self,
        index: usize,
        transaction_id: &TransactionId,
        nominating: bool,
    ) -> AgentAction {
        let pair = &self.checklist.pairs()[index];
        // §7.1.2.1: USERNAME is <remote-ufrag>:<local-ufrag>, keyed by the REMOTE password.
        let username = format!(
            "{}:{}",
            self.config.remote_credentials.ufrag, self.config.local_credentials.ufrag
        );
        AgentAction::Send {
            from: pair.local.address,
            to: pair.remote.address,
            datagram: binding_request_ice(
                transaction_id.as_bytes(),
                &username,
                self.config.remote_credentials.pwd.as_bytes(),
                pair.local.priority,
                self.role(),
                nominating,
            ),
        }
    }

    /// Our role plus tie-breaker, in the form the STUN client encodes.
    fn role(&self) -> IceRole {
        if self.config.controlling {
            IceRole::Controlling(self.config.tie_breaker)
        } else {
            IceRole::Controlled(self.config.tie_breaker)
        }
    }

    /// Feed a datagram that arrived on `local` from `source`.
    pub fn on_datagram(
        &mut self,
        local: SocketAddr,
        source: SocketAddr,
        datagram: &[u8],
        now_ms: u64,
    ) -> Vec<AgentAction> {
        let mut actions = Vec::new();
        let Ok(message) = stun::parse(datagram) else {
            return actions;
        };
        if message.is_binding_request() {
            self.on_request(local, source, datagram, &message, now_ms, &mut actions);
        } else if message.message_type == stun::BINDING_SUCCESS {
            self.on_success(source, datagram, &message, now_ms, &mut actions);
        } else {
            self.on_error_response(datagram, &message, now_ms, &mut actions);
        }
        actions
    }

    /// RFC 8445 §7.3: an inbound connectivity check.
    fn on_request(
        &mut self,
        local: SocketAddr,
        source: SocketAddr,
        datagram: &[u8],
        message: &stun::StunMessage,
        now_ms: u64,
        actions: &mut Vec<AgentAction>,
    ) {
        // §7.3: the USERNAME must address us and MESSAGE-INTEGRITY must verify with OUR password.
        // An unauthenticated check is dropped — it proves nothing and must not move any state.
        let addressed_to_us = message
            .username()
            .and_then(|username| username.split(':').next())
            .is_some_and(|ufrag| ufrag == self.config.local_credentials.ufrag);
        if !addressed_to_us
            || !stun::verify_message_integrity(
                datagram,
                self.config.local_credentials.pwd.as_bytes(),
            )
        {
            return;
        }

        // §7.3.1.1 role conflict: the peer claims the same role we hold. The higher tie-breaker
        // keeps its role; the loser switches. Resolved before anything else, because the answer we
        // send depends on it.
        if let Some(theirs) = client::ice_controlling(message) {
            if self.config.controlling {
                if self.config.tie_breaker >= theirs {
                    // We keep controlling; tell them to switch.
                    actions.push(AgentAction::Send {
                        from: local,
                        to: source,
                        datagram: binding_error_response(
                            &message.transaction_id,
                            ERROR_ROLE_CONFLICT,
                            "Role Conflict",
                            Some(self.config.local_credentials.pwd.as_bytes()),
                        ),
                    });
                    return;
                }
                self.switch_role(false);
            }
        } else if let Some(theirs) = client::ice_controlled(message) {
            if !self.config.controlling {
                if self.config.tie_breaker >= theirs {
                    actions.push(AgentAction::Send {
                        from: local,
                        to: source,
                        datagram: binding_error_response(
                            &message.transaction_id,
                            ERROR_ROLE_CONFLICT,
                            "Role Conflict",
                            Some(self.config.local_credentials.pwd.as_bytes()),
                        ),
                    });
                    return;
                }
                self.switch_role(true);
            }
        }

        // §7.3.1.3: a check from a source we have no candidate for reveals a peer-reflexive remote
        // candidate. This is the piece that makes ICE work through a NAT whose mapping neither side
        // could have signalled — without it, a symmetric-NAT peer is simply unreachable.
        let index = match self.checklist.find(local, source) {
            Some(index) => index,
            None => {
                let priority = client::priority(message).unwrap_or(0);
                let remote = Candidate {
                    foundation: Candidate::compute_foundation(
                        CandidateKind::PeerReflexive,
                        source.ip(),
                        &Transport::Udp,
                        None,
                    ),
                    priority,
                    ..Candidate::new(String::new(), 1, source, CandidateKind::PeerReflexive, 0)
                };
                // Pair it with the local candidate the check arrived on.
                let Some(local_candidate) = self.local_candidate_for(local) else {
                    return;
                };
                let mut pair = CandidatePair::new(local_candidate, remote, self.config.controlling);
                pair.state = PairState::Waiting;
                self.checklist.push(pair)
            }
        };

        // Answer the check (§7.3.1.4). The response is signed with OUR password and reports the
        // source we saw, which is how the peer discovers *its* reflexive address.
        actions.push(AgentAction::Send {
            from: local,
            to: source,
            datagram: stun::binding_success_response(
                &message.transaction_id,
                source,
                Some(self.config.local_credentials.pwd.as_bytes()),
            ),
        });

        // §7.3.1.5: a controlled agent honours USE-CANDIDATE. (An RFC 5245 peer sets it on every
        // check — aggressive nomination — so this is also the interop path for deployed SIP UAs.)
        if client::has_use_candidate(message) && !self.config.controlling {
            // §7.3.1.5: the flag belongs on the **valid** pair this pair's check produced, which is a
            // different pair whenever a peer-reflexive local candidate was discovered from it
            // (§7.2.5.3.2). Marking the checked pair instead would leave a NATed controlled agent
            // nominated-but-never-selected.
            let nominate = self.generated_valid.get(&index).copied().unwrap_or(index);
            self.checklist.pairs_mut()[nominate].nominated = true;
            // Mark the checked pair too, so a success still in flight inherits it.
            self.checklist.pairs_mut()[index].nominated = true;
            if self.checklist.pairs()[nominate].state == PairState::Succeeded {
                self.select(nominate, actions);
            }
        }

        // §7.3.1.4: enqueue a triggered check on this pair unless one is already outstanding or the
        // pair has already succeeded.
        let state = self.checklist.pairs()[index].state;
        if matches!(
            state,
            PairState::Frozen | PairState::Waiting | PairState::Failed
        ) {
            self.checklist.pairs_mut()[index].state = PairState::Waiting;
            if !self.triggered.contains(&index) {
                self.triggered.push(index);
            }
        }
        let _ = now_ms;
    }

    /// RFC 8445 §7.2.5: a success response to one of our checks.
    fn on_success(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
        message: &stun::StunMessage,
        now_ms: u64,
        actions: &mut Vec<AgentAction>,
    ) {
        let Some(&index) = self.transactions.get(&message.transaction_id) else {
            return;
        };
        // The response is signed with the *peer's* password (it is the responder).
        if !stun::verify_message_integrity(datagram, self.config.remote_credentials.pwd.as_bytes())
        {
            return;
        }
        // §7.2.5.2.1: the response must come from the address the check went to, and arrive on the
        // address it left from. A non-symmetric response fails the pair — it is not the same path.
        if self.checklist.pairs()[index].remote.address != source {
            self.fail_check(index, message, actions);
            return;
        }

        let Some(check) = self.checks.remove(&index) else {
            return;
        };
        self.transactions.remove(&message.transaction_id);

        // §7.2.5.3.1: if the mapped address is not one of our local candidates, we have just learned
        // a peer-reflexive *local* candidate — our own address as the peer sees it. The valid pair is
        // the one built from it, not the one we checked.
        let valid_index = match message.xor_mapped_address() {
            Some(mapped) if self.local_candidate_for(mapped).is_none() => {
                self.discover_local_reflexive(index, mapped)
            }
            _ => index,
        };
        if valid_index != index {
            self.generated_valid.insert(index, valid_index);
        }
        if valid_index != index && self.checklist.pairs()[index].nominated {
            // The valid pair was *generated from* the pair we checked (§7.2.5.3.2), so it inherits
            // that pair's nomination (§7.2.5.3.4, §7.3.1.5). Without this the controlled side of a
            // NATed call never completes: the peer's USE-CANDIDATE marks the pair it addressed, while
            // the success discovers a peer-reflexive local candidate and produces a *different* valid
            // pair — the nomination would land on one pair and the validity on another.
            self.checklist.pairs_mut()[valid_index].nominated = true;
        }

        self.checklist.pairs_mut()[valid_index].state = PairState::Succeeded;
        // §7.2.5.3.3: success unfreezes the rest of this foundation.
        let foundation = self.checklist.pairs()[valid_index].foundation();
        self.checklist.unfreeze_foundation(&foundation);

        // §7.2.5.3.4: a successful *nominating* check selects the pair (controlling side). On the
        // controlled side the pair was already marked by the peer's USE-CANDIDATE.
        if check.nominating || self.checklist.pairs()[valid_index].nominated {
            self.checklist.pairs_mut()[valid_index].nominated = true;
            self.select(valid_index, actions);
        } else {
            self.recompute_state(actions);
        }
        let _ = now_ms;
    }

    /// RFC 8445 §7.2.5.1: an error response. The one we must act on is 487 Role Conflict.
    fn on_error_response(
        &mut self,
        datagram: &[u8],
        message: &stun::StunMessage,
        now_ms: u64,
        actions: &mut Vec<AgentAction>,
    ) {
        let Some(&index) = self.transactions.get(&message.transaction_id) else {
            return;
        };
        if !stun::verify_message_integrity(datagram, self.config.remote_credentials.pwd.as_bytes())
        {
            // An unsigned error response could be forged by anyone who saw the request go by.
            return;
        }
        self.checks.remove(&index);
        self.transactions.remove(&message.transaction_id);

        if stun::turn::error_code(message) == Some(ERROR_ROLE_CONFLICT) {
            // §7.2.5.1: switch to the role the peer insists on and retry the pair immediately.
            self.switch_role(!self.config.controlling);
            self.checklist.pairs_mut()[index].state = PairState::Waiting;
            if !self.triggered.contains(&index) {
                self.triggered.push(index);
            }
            // A conflict invalidates any nomination we had in flight.
            self.nomination_sent = false;
            let _ = now_ms;
            return;
        }
        self.checklist.pairs_mut()[index].state = PairState::Failed;
        self.recompute_state(actions);
    }

    /// Mark a pair failed after a non-symmetric response.
    fn fail_check(
        &mut self,
        index: usize,
        message: &stun::StunMessage,
        actions: &mut Vec<AgentAction>,
    ) {
        self.checks.remove(&index);
        self.transactions.remove(&message.transaction_id);
        self.checklist.pairs_mut()[index].state = PairState::Failed;
        self.recompute_state(actions);
    }

    /// §7.2.5.3.1: build the pair for a newly discovered peer-reflexive local candidate.
    fn discover_local_reflexive(&mut self, checked: usize, mapped: SocketAddr) -> usize {
        if let Some(existing) = self
            .checklist
            .find(mapped, self.checklist.pairs()[checked].remote.address)
        {
            return existing;
        }
        let base = self.checklist.pairs()[checked].local.address;
        let local = Candidate {
            foundation: Candidate::compute_foundation(
                CandidateKind::PeerReflexive,
                base.ip(),
                &Transport::Udp,
                None,
            ),
            related: Some(base),
            ..Candidate::new(
                String::new(),
                self.checklist.pairs()[checked].component(),
                mapped,
                CandidateKind::PeerReflexive,
                65535,
            )
        };
        let remote = self.checklist.pairs()[checked].remote.clone();
        let pair = CandidatePair::new(local, remote, self.config.controlling);
        self.checklist.push(pair)
    }

    /// Our local candidate whose transport address is `address`, if any.
    fn local_candidate_for(&self, address: SocketAddr) -> Option<Candidate> {
        self.config
            .local_candidates
            .iter()
            .find(|candidate| candidate.address == address)
            .cloned()
            .or_else(|| {
                self.checklist
                    .pairs()
                    .iter()
                    .find(|pair| pair.local.address == address)
                    .map(|pair| pair.local.clone())
            })
    }

    /// Select a nominated pair and complete (RFC 8445 §8.1.1).
    fn select(&mut self, index: usize, actions: &mut Vec<AgentAction>) {
        if self.selected == Some(index) {
            return;
        }
        self.selected = Some(index);
        let pair = &self.checklist.pairs()[index];
        actions.push(AgentAction::Selected {
            local: pair.local.address,
            remote: pair.remote.address,
        });
        self.set_state(IceState::Completed, actions);
    }

    /// Recompute Connected/Failed from the checklist (RFC 8445 §8.1.2).
    fn recompute_state(&mut self, actions: &mut Vec<AgentAction>) {
        if self.selected.is_some() {
            return;
        }
        if !self.checklist.valid().is_empty() {
            self.set_state(IceState::Connected, actions);
        } else if self.checklist.is_exhausted() && self.checks.is_empty() {
            // Every pair settled and none is valid: there is no path.
            self.set_state(IceState::Failed, actions);
        }
    }

    fn set_state(&mut self, state: IceState, actions: &mut Vec<AgentAction>) {
        if self.state != state {
            self.state = state;
            actions.push(AgentAction::StateChanged(state));
        }
    }

    /// Switch roles and re-price every pair — the §6.1.2.3 priority depends on who controls, and both
    /// agents must keep agreeing on it.
    fn switch_role(&mut self, controlling: bool) {
        if self.config.controlling == controlling {
            return;
        }
        self.config.controlling = controlling;
        for pair in self.checklist.pairs_mut() {
            pair.priority = crate::checklist::pair_priority(
                pair.local.priority,
                pair.remote.priority,
                controlling,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const LEFT_ADDR: &str = "192.0.2.1:40000";
    const RIGHT_ADDR: &str = "198.51.100.1:50000";
    /// The public address a NATed right-hand agent's packets appear to come from.
    const RIGHT_PUBLIC: &str = "203.0.113.9:60000";

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("addr")
    }

    fn host(text: &str, foundation: &str) -> Candidate {
        Candidate {
            foundation: foundation.to_string(),
            ..Candidate::new(String::new(), 1, address(text), CandidateKind::Host, 65535)
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Side {
        Left,
        Right,
    }

    impl Side {
        fn other(self) -> Self {
            match self {
                Side::Left => Side::Right,
                Side::Right => Side::Left,
            }
        }
    }

    /// A test network joining two agents with **no sockets**: whatever one emits is handed to the
    /// other as if it had arrived. `translate` models the middle of the path — the identity for a
    /// direct link, or a NAT that rewrites addresses.
    ///
    /// Returning `None` from `translate` drops the datagram, which is how an unroutable private
    /// address is modelled.
    struct Wire<F> {
        left: IceAgent,
        right: IceAgent,
        queue: VecDeque<(Side, SocketAddr, SocketAddr, Vec<u8>)>,
        translate: F,
    }

    impl<F> Wire<F>
    where
        F: Fn(Side, SocketAddr, SocketAddr) -> Option<(SocketAddr, SocketAddr)>,
    {
        fn new(left: IceAgent, right: IceAgent, translate: F) -> Self {
            Self {
                left,
                right,
                queue: VecDeque::new(),
                translate,
            }
        }

        fn agent(&mut self, side: Side) -> &mut IceAgent {
            match side {
                Side::Left => &mut self.left,
                Side::Right => &mut self.right,
            }
        }

        /// Queue everything `side` just emitted, translated for the path.
        fn emit(&mut self, side: Side, actions: Vec<AgentAction>) {
            for action in actions {
                if let AgentAction::Send { from, to, datagram } = action {
                    // (source, destination-local) as the far side observes them.
                    if let Some((source, local)) = (self.translate)(side, from, to) {
                        self.queue
                            .push_back((side.other(), local, source, datagram));
                    }
                }
            }
        }

        /// Run both agents to `now_ms`, delivering everything in flight.
        fn step(&mut self, now_ms: u64) {
            for side in [Side::Left, Side::Right] {
                let actions = self.agent(side).poll(now_ms);
                self.emit(side, actions);
            }
            // Deliver until quiet — a response can immediately provoke another datagram.
            let mut guard = 0;
            while let Some((side, local, source, datagram)) = self.queue.pop_front() {
                let actions = self
                    .agent(side)
                    .on_datagram(local, source, &datagram, now_ms);
                self.emit(side, actions);
                guard += 1;
                assert!(guard < 500, "the exchange is not converging");
            }
        }

        /// Step until both agents complete, or `limit_ms` elapses.
        fn run(&mut self, limit_ms: u64) {
            let mut now = 0;
            while now <= limit_ms {
                self.step(now);
                if self.left.state() == IceState::Completed
                    && self.right.state() == IceState::Completed
                {
                    return;
                }
                now += 10;
            }
        }
    }

    /// A direct link: nothing between the agents.
    fn direct(_side: Side, from: SocketAddr, to: SocketAddr) -> Option<(SocketAddr, SocketAddr)> {
        Some((from, to))
    }

    fn agents(left_controlling: bool, right_controlling: bool) -> (IceAgent, IceAgent) {
        let left_credentials = Credentials::new("LEFTUF", "leftpasswordleftpassword");
        let right_credentials = Credentials::new("RIGHTUF", "rightpasswordrightpassw");
        let left = IceAgent::new(
            AgentConfig::new(
                left_credentials.clone(),
                right_credentials.clone(),
                left_controlling,
                0xAAAA_AAAA_AAAA_AAAA,
            )
            .with_candidates(vec![host(LEFT_ADDR, "l1")], vec![host(RIGHT_ADDR, "r1")]),
            0,
        );
        let right = IceAgent::new(
            AgentConfig::new(
                right_credentials,
                left_credentials,
                right_controlling,
                0x1111_1111_1111_1111,
            )
            .with_candidates(vec![host(RIGHT_ADDR, "r1")], vec![host(LEFT_ADDR, "l1")]),
            0,
        );
        (left, right)
    }

    #[test]
    fn two_agents_complete_a_full_exchange_and_agree_on_the_pair() {
        let (left, right) = agents(true, false);
        let mut wire = Wire::new(left, right, direct);
        wire.run(2_000);

        assert_eq!(wire.left.state(), IceState::Completed, "controlling side");
        assert_eq!(wire.right.state(), IceState::Completed, "controlled side");
        // Both agents select the same path, seen from their own end.
        let (left_local, left_remote) = wire.left.selected_pair().expect("left selected");
        let (right_local, right_remote) = wire.right.selected_pair().expect("right selected");
        assert_eq!(left_local, address(LEFT_ADDR));
        assert_eq!(left_remote, address(RIGHT_ADDR));
        assert_eq!(right_local, address(RIGHT_ADDR));
        assert_eq!(right_remote, address(LEFT_ADDR));
    }

    #[test]
    fn a_natted_peer_is_reached_through_peer_reflexive_discovery() {
        // The piece half-agents skip. The right agent sits behind a symmetric NAT: the address it
        // signalled is unroutable, and the only way left can ever reach it is by learning the
        // translated source of right's own checks (RFC 8445 §7.3.1.3).
        let (left, right) = agents(true, false);
        let mut wire = Wire::new(left, right, |side, from, to| match side {
            // Right's packets are translated to its public address on the way out.
            Side::Right => Some((address(RIGHT_PUBLIC), to)),
            // Left's packets reach right only via that public address; the signalled private one is
            // unroutable and simply disappears, exactly as it would in production.
            Side::Left if to == address(RIGHT_PUBLIC) => Some((from, address(RIGHT_ADDR))),
            Side::Left => None,
        });
        wire.run(3_000);

        assert_eq!(wire.left.state(), IceState::Completed);
        assert_eq!(wire.right.state(), IceState::Completed);
        let (_, left_remote) = wire.left.selected_pair().expect("left selected");
        assert_eq!(
            left_remote,
            address(RIGHT_PUBLIC),
            "left selected the peer-reflexive candidate, not the unroutable signalled one"
        );
        // And that candidate really is peer-reflexive — it was discovered, never signalled.
        assert!(
            wire.left
                .checklist()
                .pairs()
                .iter()
                .any(|pair| pair.remote.kind == CandidateKind::PeerReflexive
                    && pair.remote.address == address(RIGHT_PUBLIC)),
            "a peer-reflexive remote candidate was created"
        );
    }

    #[test]
    fn a_role_conflict_is_resolved_by_the_tie_breaker_and_the_exchange_still_completes() {
        // Both sides think they control (a re-INVITE glare, or two offerers). RFC 8445 §7.3.1.1: the
        // higher tie-breaker keeps the role, the other switches — and exactly one switches, or the
        // pair priorities would disagree forever.
        let (left, right) = agents(true, true);
        assert!(left.is_controlling() && right.is_controlling());
        let mut wire = Wire::new(left, right, direct);
        wire.run(3_000);

        assert_ne!(
            wire.left.is_controlling(),
            wire.right.is_controlling(),
            "exactly one agent controls after the conflict is resolved"
        );
        assert!(
            wire.left.is_controlling(),
            "the higher tie-breaker (left) keeps the controlling role"
        );
        assert_eq!(wire.left.state(), IceState::Completed);
        assert_eq!(wire.right.state(), IceState::Completed);
    }

    #[test]
    fn the_lower_tie_breaker_switching_is_symmetric() {
        // The same conflict with the tie-breakers the other way round: the *other* agent keeps it.
        let left_credentials = Credentials::new("LEFTUF", "leftpasswordleftpassword");
        let right_credentials = Credentials::new("RIGHTUF", "rightpasswordrightpassw");
        let left = IceAgent::new(
            AgentConfig::new(
                left_credentials.clone(),
                right_credentials.clone(),
                true,
                1, // lowest possible
            )
            .with_candidates(vec![host(LEFT_ADDR, "l1")], vec![host(RIGHT_ADDR, "r1")]),
            0,
        );
        let right = IceAgent::new(
            AgentConfig::new(right_credentials, left_credentials, true, u64::MAX)
                .with_candidates(vec![host(RIGHT_ADDR, "r1")], vec![host(LEFT_ADDR, "l1")]),
            0,
        );
        let mut wire = Wire::new(left, right, direct);
        wire.run(3_000);
        assert!(
            !wire.left.is_controlling(),
            "left had the lower tie-breaker"
        );
        assert!(wire.right.is_controlling());
    }

    #[test]
    fn an_unauthenticated_check_moves_no_state() {
        // A check that fails MESSAGE-INTEGRITY proves nothing. It must not be answered, must not
        // create a peer-reflexive candidate, and must not touch the checklist.
        let (mut left, _right) = agents(true, false);
        let forged = stun::binding_request(&[7u8; 12], "LEFTUF:RIGHTUF", b"WRONG-PASSWORD");
        let before = left.checklist().len();
        let actions =
            left.on_datagram(address(LEFT_ADDR), address("203.0.113.66:1234"), &forged, 0);
        assert!(
            actions.is_empty(),
            "no response to an unauthenticated check"
        );
        assert_eq!(left.checklist().len(), before, "no candidate was invented");
    }

    #[test]
    fn a_check_addressed_to_another_agent_is_ignored() {
        // Right ufrag, wrong agent: the USERNAME must address *us* (RFC 8445 §7.3).
        let (mut left, _right) = agents(true, false);
        let wrong = stun::binding_request(
            &[7u8; 12],
            "SOMEONEELSE:RIGHTUF",
            b"leftpasswordleftpassword",
        );
        assert!(left
            .on_datagram(address(LEFT_ADDR), address(RIGHT_ADDR), &wrong, 0)
            .is_empty());
    }

    #[test]
    fn a_response_from_the_wrong_source_fails_the_pair() {
        // RFC 8445 §7.2.5.2.1: a response must return on the same path the check took. One that does
        // not is not evidence about that pair.
        let (mut left, _right) = agents(true, false);
        let actions = left.poll(0);
        let Some(AgentAction::Send { datagram, .. }) = actions.first() else {
            panic!("expected a check, got {actions:?}");
        };
        let request = stun::parse(datagram).expect("parse check");
        let response = stun::binding_success_response(
            &request.transaction_id,
            address(LEFT_ADDR),
            Some(b"rightpasswordrightpassw"),
        );
        // Correct transaction, correct signature — but from an address we never checked.
        left.on_datagram(
            address(LEFT_ADDR),
            address("203.0.113.77:9999"),
            &response,
            10,
        );
        assert_eq!(left.checklist().pairs()[0].state, PairState::Failed);
        assert_eq!(left.state(), IceState::Failed, "no pair left to try");
    }

    #[test]
    fn an_agent_with_no_compatible_pair_fails_immediately() {
        // A v6-only peer against a v4-only agent: nothing can be paired (§6.1.2.2), so there is no
        // point pretending to check.
        let agent = IceAgent::new(
            AgentConfig::new(
                Credentials::new("A", "passwordpasswordpasswo"),
                Credentials::new("B", "passwordpasswordpasswo"),
                true,
                1,
            )
            .with_candidates(
                vec![host(LEFT_ADDR, "l1")],
                vec![host("[2001:db8::1]:50000", "r1")],
            ),
            0,
        );
        assert_eq!(agent.state(), IceState::Failed);
        assert!(agent.checklist().is_empty());
    }

    #[test]
    fn checks_are_paced_and_retransmitted_on_the_logical_clock() {
        let (mut left, _right) = agents(true, false);
        // First check goes out immediately.
        assert!(matches!(
            left.poll(0).first(),
            Some(AgentAction::Send { .. })
        ));
        // Nothing else before `Ta` — the pacing is what keeps a big checklist from bursting.
        for now in 1..DEFAULT_PACING_MS {
            assert!(
                left.poll(now).is_empty(),
                "a check went out inside the Ta window at {now}"
            );
        }
        // With one pair, the only thing due later is its RFC 8489 retransmission at the initial RTO.
        let mut retransmit_at = None;
        for now in DEFAULT_PACING_MS..=DEFAULT_RTO_MS {
            if !left.poll(now).is_empty() {
                retransmit_at = Some(now);
                break;
            }
        }
        assert_eq!(retransmit_at, Some(DEFAULT_RTO_MS));
    }

    #[test]
    fn aggressive_nomination_from_an_rfc_5245_peer_is_honoured_when_controlled() {
        // RFC 5245 §8.1.1.2: a legacy peer sets USE-CANDIDATE on every check. RFC 8445 removed that,
        // but refusing to select would fail calls against deployed SIP UAs, so a controlled agent
        // still honours it.
        let (_left, mut right) = agents(true, false);
        assert!(!right.is_controlling());

        // The peer's check, nominating on the first try.
        let check = binding_request_ice(
            &[5u8; 12],
            "RIGHTUF:LEFTUF",
            b"rightpasswordrightpassw",
            2_130_706_431,
            IceRole::Controlling(0xAAAA_AAAA_AAAA_AAAA),
            true, // USE-CANDIDATE
        );
        let actions = right.on_datagram(address(RIGHT_ADDR), address(LEFT_ADDR), &check, 0);
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, AgentAction::Send { .. })),
            "the check is answered"
        );
        assert!(
            right.checklist().pairs().iter().any(|pair| pair.nominated),
            "the pair is marked nominated by USE-CANDIDATE"
        );

        // Once our own check on that pair succeeds, the nomination selects it.
        let mut wire = Wire::new(agents(true, false).0, right, direct);
        wire.run(2_000);
        assert_eq!(wire.right.state(), IceState::Completed);
    }

    #[test]
    fn a_controlling_agent_never_sends_use_candidate_on_a_first_check() {
        // RFC 8445 removed aggressive nomination: our first check must not nominate. Nomination is a
        // second, deliberate check on a pair already known to be valid (§8.1.1).
        let (mut left, _right) = agents(true, false);
        let actions = left.poll(0);
        let Some(AgentAction::Send { datagram, .. }) = actions.first() else {
            panic!("expected a check");
        };
        let message = stun::parse(datagram).expect("parse");
        assert!(
            !client::has_use_candidate(&message),
            "regular nomination only — never aggressive"
        );
        assert_eq!(
            client::ice_controlling(&message),
            Some(0xAAAA_AAAA_AAAA_AAAA),
            "and the check carries our role + tie-breaker (RFC 8445 §7.1.2)"
        );
    }
}
