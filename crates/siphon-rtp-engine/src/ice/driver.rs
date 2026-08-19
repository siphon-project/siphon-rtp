//! The engine-side supervisor that actually **runs** RFC 7675 consent freshness: one
//! [`ConsentChecker`] per ICE endpoint, registered when a leg negotiates ICE, driven once per
//! media-sweep tick, and torn down with its call.
//!
//! The checker itself is pure logic; this module is the registry plus the tick loop around it, and is
//! deliberately **still free of I/O**. It never touches a socket and never calls the datapath: it is
//! given the current ICE-validated source per endpoint and returns [`ConsentOutcome`]s the engine
//! executes (`Datapath::send` for a check, teardown for a failure). That keeps the whole consent path
//! testable on a logical tick clock with no runtime, no sockets, and no `Instant::now()`.
//!
//! **Where checks are sent (the load-bearing decision).** A consent check goes to the endpoint's
//! [`Datapath::ice_validated_source`] — the address the peer proved it can receive on by answering a
//! MESSAGE-INTEGRITY-signed connectivity check (RFC 8445 §7.3). Never the signalled `c=` address: for
//! a NATed peer that is an unusable private address, so probing it would fail consent on healthy
//! calls and reap them. An endpoint with no validated source yet is simply not probed — it has no
//! pair to keep alive, and a genuinely dead leg is still reaped by the media-timeout sweep
//! (`docs/security-and-nat.md` §4 layer 6).
//!
//! [`Datapath::ice_validated_source`]: siphon_rtp_datapath::Datapath::ice_validated_source

use std::net::SocketAddr;

use dashmap::DashMap;
use siphon_rtp_datapath::{EndpointId, IceDatapathEvent};
use siphon_rtp_ice::agent::{AgentAction, AgentConfig, IceAgent, IceState};
use siphon_rtp_stun::client::IceRole;

use super::consent::{ConsentAction, ConsentChecker, ConsentParams};

/// Bound on the datapath→engine STUN event queue. Consent traffic is a handful of datagrams per
/// endpoint per interval, and the queue is drained every sweep tick, so this is deep enough that a
/// burst of peer checks is never lost while still bounding memory under a flood (drop-on-full — a
/// dropped response only delays a refresh; it never blocks the datapath's receive loop).
const EVENT_QUEUE_DEPTH: usize = 1024;

/// Consent-freshness tunables, in **sweep ticks** (the daemon advances one tick per wall second).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentConfig {
    /// Ticks between fresh checks, before jitter (RFC 7675 §5.1 recommends ~5 s, randomised).
    pub interval_ticks: u64,
    /// Ticks with no correlated response after which the pair is declared dead (RFC 7675 §5.1: 30 s).
    pub timeout_ticks: u64,
    /// Per-check retransmission timeout in ticks (RFC 8489 §6.2.1).
    pub rto_ticks: u64,
}

impl Default for ConsentConfig {
    /// The RFC 7675 §5.1 defaults: probe every ~5 s, give up after 30 s without a response.
    fn default() -> Self {
        Self {
            interval_ticks: 5,
            timeout_ticks: 30,
            rto_ticks: 1,
        }
    }
}

/// What the engine must do for one endpoint as a result of [`ConsentSupervisor::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentOutcome {
    /// Transmit `datagram` from `endpoint` to `dst` (a fresh check or a retransmit).
    Send {
        /// The endpoint to source the check from — checks egress the same port the media does.
        endpoint: EndpointId,
        /// The validated peer path being probed.
        dst: SocketAddr,
        /// The STUN Binding request bytes.
        datagram: Vec<u8>,
    },
    /// Consent expired on `endpoint`: the peer stopped answering. Tear `call_id` down.
    Failed {
        /// The endpoint whose pair went dead.
        endpoint: EndpointId,
        /// The call that owns it.
        call_id: String,
    },
}

/// One registered ICE endpoint's consent state.
#[derive(Debug)]
struct ConsentEntry {
    /// The call this endpoint belongs to — carried so a failure names the call to tear down.
    call_id: String,
    /// Our own ufrag (the second half of the check USERNAME, RFC 8445 §7.1.2).
    local_ufrag: String,
    /// The peer's ufrag (the first half).
    remote_ufrag: String,
    /// The peer's password — signs our check and verifies its response.
    remote_pwd: String,
    /// Our ICE role + tie-breaker (RFC 8445 §5.2). An ICE-lite agent is always **controlled**
    /// (RFC 8445 §6.1.1), which is our posture until the full agent lands.
    role: IceRole,
    /// `None` until the peer has validated a source; created at the tick the pair first appears, so a
    /// leg is never failed for a window in which it had nothing to probe.
    checker: Option<ConsentChecker>,
}

/// The per-engine registry of consent checkers. Shared (`DashMap`) because registration happens on
/// the control path (`answer`) while polling happens on the sweeper task.
#[derive(Debug)]
pub struct ConsentSupervisor {
    config: ConsentConfig,
    entries: DashMap<EndpointId, ConsentEntry>,
    /// The sink handed to `Datapath::set_ice_agent`, and the matching receiver drained each tick.
    events_tx: flume::Sender<IceDatapathEvent>,
    events_rx: flume::Receiver<IceDatapathEvent>,
}

impl ConsentSupervisor {
    /// Build a supervisor with the given cadence.
    #[must_use]
    pub fn new(config: ConsentConfig) -> Self {
        let (events_tx, events_rx) = flume::bounded(EVENT_QUEUE_DEPTH);
        Self {
            config,
            entries: DashMap::new(),
            events_tx,
            events_rx,
        }
    }

    /// The STUN event sink to hand to [`siphon_rtp_datapath::Datapath::set_ice_agent`]. Cloned per
    /// endpoint; all endpoints feed this one queue, drained by [`Self::drain_events`].
    #[must_use]
    pub fn events(&self) -> flume::Sender<IceDatapathEvent> {
        self.events_tx.clone()
    }

    /// Number of endpoints currently under consent — the leak assertion's hook (it must drain to 0
    /// once every call is torn down).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no endpoint is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Start (or replace) consent for `endpoint`. Called once per ICE-enabled endpoint at answer
    /// time, with the credentials of the peer that endpoint faces — checks are signed with the
    /// **peer's** password (RFC 8445 §7.1.2), so the near and far legs of one call use different
    /// credentials and must be registered separately.
    pub fn register(
        &self,
        endpoint: EndpointId,
        call_id: &str,
        local_ufrag: &str,
        remote_ufrag: &str,
        remote_pwd: &str,
    ) {
        self.entries.insert(
            endpoint,
            ConsentEntry {
                call_id: call_id.to_string(),
                local_ufrag: local_ufrag.to_string(),
                remote_ufrag: remote_ufrag.to_string(),
                remote_pwd: remote_pwd.to_string(),
                role: IceRole::Controlled(tie_breaker(endpoint)),
                checker: None,
            },
        );
    }

    /// Stop consent for `endpoint` (its call was torn down, or the endpoint was freed).
    pub fn unregister(&self, endpoint: EndpointId) {
        self.entries.remove(&endpoint);
    }

    /// Stop consent for every endpoint of `call_id`.
    pub fn unregister_call(&self, call_id: &str) {
        self.entries.retain(|_, entry| entry.call_id != call_id);
    }

    /// Drain the datapath's STUN queue into the checkers, correlating each Binding response with the
    /// endpoint that sent the check. MUST run before [`Self::poll`] each tick so a response that
    /// arrived this second refreshes consent before expiry is evaluated. Requests and uncorrelated
    /// datagrams are ignored by the checker (the datapath responder already answered any check).
    pub fn drain_events(&self) {
        // `try_recv` in a loop, never `recv`: the sweeper must not block on an empty queue.
        while let Ok(event) = self.events_rx.try_recv() {
            let Some(mut entry) = self.entries.get_mut(&event.endpoint) else {
                continue;
            };
            if let Some(checker) = entry.checker.as_mut() {
                // Stamp the refresh at the datapath's arrival tick, not "now" — the response may have
                // waited in the queue, and consent is a freshness measure of the *path*.
                checker.on_response(&event.datagram, event.arrival_tick);
            }
        }
    }

    /// Drive every registered endpoint at `now_tick`, resolving each one's current validated peer via
    /// `validated_source`. Returns the datagrams to transmit and the calls whose consent expired.
    pub fn poll(
        &self,
        validated_source: impl Fn(EndpointId) -> Option<SocketAddr>,
        now_tick: u64,
    ) -> Vec<ConsentOutcome> {
        let mut outcomes = Vec::new();
        for mut entry in self.entries.iter_mut() {
            let endpoint = *entry.key();
            let entry = entry.value_mut();
            // No validated pair yet (or any more): nothing to probe. Do not start — or keep — a
            // consent clock against a path the peer never proved; the media-timeout sweep is what
            // reaps a leg that never comes alive.
            let Some(dst) = validated_source(endpoint) else {
                entry.checker = None;
                continue;
            };
            // Arm on first sight of the pair, and re-arm if the peer re-validated from a new address
            // (NAT rebind): consent follows the validated path, it does not chase the old one.
            let checker = match entry.checker.as_mut() {
                Some(checker) if checker.remote_addr() == dst => checker,
                _ => entry.checker.insert(ConsentChecker::new(
                    ConsentParams {
                        remote_addr: dst,
                        local_ufrag: entry.local_ufrag.clone(),
                        remote_ufrag: entry.remote_ufrag.clone(),
                        remote_pwd: entry.remote_pwd.clone(),
                        priority: crate::sdp::HOST_CANDIDATE_PRIORITY,
                        role: entry.role,
                        interval_ticks: self.config.interval_ticks,
                        timeout_ticks: self.config.timeout_ticks,
                        rto_ticks: self.config.rto_ticks,
                        // Per-endpoint seed so many calls' checks do not synchronise, yet a given
                        // endpoint's schedule stays reproducible in tests.
                        seed: tie_breaker(endpoint),
                    },
                    now_tick,
                )),
            };
            match checker.poll(now_tick) {
                ConsentAction::Idle => {}
                ConsentAction::SendCheck { dst, datagram } => outcomes.push(ConsentOutcome::Send {
                    endpoint,
                    dst,
                    datagram,
                }),
                ConsentAction::Failed => outcomes.push(ConsentOutcome::Failed {
                    endpoint,
                    call_id: entry.call_id.clone(),
                }),
            }
        }
        outcomes
    }
}

/// A per-endpoint 64-bit value used as the ICE tie-breaker (RFC 8445 §5.2) and the jitter seed.
/// Derived by splitmix64 from the endpoint id so it is well-spread and reproducible: as an ICE-lite
/// agent we are always the **controlled** side and never resolve a role conflict, so this value is
/// never security-relevant. The full agent (which does resolve conflicts) must mint it from the CSPRNG
/// instead — flagged where that lands, not silently inherited.
fn tie_breaker(endpoint: EndpointId) -> u64 {
    let mut state = endpoint.0.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    state = (state ^ (state >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    state = (state ^ (state >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    state ^ (state >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use siphon_rtp_stun as stun;

    const ENDPOINT: EndpointId = EndpointId(7);
    const PEER: &str = "192.0.2.7:40000";

    fn supervisor() -> ConsentSupervisor {
        ConsentSupervisor::new(ConsentConfig {
            interval_ticks: 5,
            timeout_ticks: 30,
            rto_ticks: 1,
        })
    }

    fn registered() -> ConsentSupervisor {
        let supervisor = supervisor();
        supervisor.register(
            ENDPOINT,
            "call-1",
            "engUfrag",
            "peerUfrag",
            "peer-password-000000000",
        );
        supervisor
    }

    fn peer_addr() -> SocketAddr {
        PEER.parse().expect("addr")
    }

    /// The validated-source resolver for a peer that has passed a connectivity check.
    fn validated(_endpoint: EndpointId) -> Option<SocketAddr> {
        Some(peer_addr())
    }

    /// The resolver for an endpoint on which no check has validated anything yet.
    fn unvalidated(_endpoint: EndpointId) -> Option<SocketAddr> {
        None
    }

    #[test]
    fn does_not_probe_an_endpoint_with_no_validated_pair() {
        let supervisor = registered();
        // 100 ticks — well past the 30-tick timeout. A leg whose peer never ran a check must never be
        // failed by consent: there is no pair to have lost. (The media-timeout sweep reaps it.)
        for tick in 0..100 {
            assert!(
                supervisor.poll(unvalidated, tick).is_empty(),
                "no outcome at tick {tick}"
            );
        }
    }

    #[test]
    fn probes_the_validated_source_not_the_signalled_address() {
        let supervisor = registered();
        let outcomes = supervisor.poll(validated, 0);
        let [ConsentOutcome::Send {
            endpoint,
            dst,
            datagram,
        }] = outcomes.as_slice()
        else {
            panic!("expected exactly one check, got {outcomes:?}");
        };
        assert_eq!(*endpoint, ENDPOINT, "checks egress the media endpoint");
        assert_eq!(*dst, peer_addr(), "the check goes to the validated path");

        let message = stun::parse(datagram).expect("a valid STUN check");
        assert!(message.is_binding_request());
        // RFC 8445 §7.1.2: USERNAME is <remote-ufrag>:<local-ufrag>, signed with the peer's password.
        assert_eq!(message.username(), Some("peerUfrag:engUfrag"));
        assert!(stun::verify_message_integrity(
            datagram,
            b"peer-password-000000000"
        ));
        // An ICE-lite agent is always the controlled side (RFC 8445 §6.1.1).
        assert!(
            stun::client::ice_controlled(&message).is_some(),
            "the check advertises ICE-CONTROLLED"
        );
    }

    /// Build the peer's success response to a check the supervisor emitted, as the datapath would
    /// deliver it through the full-agent seam.
    fn response_event(datagram: &[u8], password: &[u8], arrival_tick: u64) -> IceDatapathEvent {
        let request = stun::parse(datagram).expect("parse check");
        let response =
            stun::binding_success_response(&request.transaction_id, peer_addr(), Some(password));
        IceDatapathEvent {
            endpoint: ENDPOINT,
            source: peer_addr(),
            arrival_tick,
            datagram: Bytes::from(response),
        }
    }

    fn sent(outcomes: &[ConsentOutcome]) -> Vec<u8> {
        match outcomes {
            [ConsentOutcome::Send { datagram, .. }] => datagram.clone(),
            other => panic!("expected one check, got {other:?}"),
        }
    }

    #[test]
    fn an_answered_check_keeps_the_call_alive_indefinitely() {
        let supervisor = registered();
        // Run well past the 30-tick timeout, answering every check the peer receives.
        for tick in 0..90 {
            supervisor.drain_events();
            let outcomes = supervisor.poll(validated, tick);
            for outcome in &outcomes {
                match outcome {
                    ConsentOutcome::Send { datagram, .. } => {
                        let event = response_event(datagram, b"peer-password-000000000", tick);
                        supervisor
                            .events()
                            .try_send(event)
                            .expect("queue has capacity");
                    }
                    ConsentOutcome::Failed { .. } => {
                        panic!("consent must not fail while the peer answers (tick {tick})")
                    }
                }
            }
        }
    }

    #[test]
    fn a_silent_peer_fails_consent_at_the_timeout() {
        let supervisor = registered();
        for tick in 0..30 {
            let outcomes = supervisor.poll(validated, tick);
            assert!(
                !outcomes
                    .iter()
                    .any(|outcome| matches!(outcome, ConsentOutcome::Failed { .. })),
                "must not fail before the timeout (tick {tick})"
            );
        }
        // At exactly timeout_ticks past arming, the pair is declared dead and names its call.
        let outcomes = supervisor.poll(validated, 30);
        assert_eq!(
            outcomes,
            vec![ConsentOutcome::Failed {
                endpoint: ENDPOINT,
                call_id: "call-1".to_string(),
            }]
        );
    }

    #[test]
    fn a_forged_response_does_not_refresh_consent() {
        let supervisor = registered();
        let check = sent(&supervisor.poll(validated, 0));
        // Correct transaction id, wrong password — an off-path forgery must not hold the call up.
        supervisor
            .events()
            .try_send(response_event(&check, b"WRONG-PASSWORD", 1))
            .expect("capacity");
        supervisor.drain_events();
        for tick in 1..30 {
            let _ = supervisor.poll(validated, tick);
        }
        assert!(
            supervisor
                .poll(validated, 30)
                .iter()
                .any(|outcome| matches!(outcome, ConsentOutcome::Failed { .. })),
            "a forged response must leave consent expiring on schedule"
        );
    }

    #[test]
    fn a_rebinding_peer_re_arms_consent_on_the_new_validated_path() {
        let supervisor = registered();
        let _ = supervisor.poll(validated, 0);
        // The peer re-validates from a new source (NAT rebind); the datapath adopts it.
        let rebound: SocketAddr = "192.0.2.9:41000".parse().expect("addr");
        let outcomes = supervisor.poll(|_| Some(rebound), 1);
        let [ConsentOutcome::Send { dst, .. }] = outcomes.as_slice() else {
            panic!("expected a check on the new path, got {outcomes:?}");
        };
        assert_eq!(*dst, rebound, "consent follows the newly validated path");
        // The re-arm resets the window, so the old path's elapsed time cannot fail the new pair.
        for tick in 2..=30 {
            assert!(
                !supervisor
                    .poll(|_| Some(rebound), tick)
                    .iter()
                    .any(|outcome| matches!(outcome, ConsentOutcome::Failed { .. })),
                "re-armed consent must not inherit the old pair's clock (tick {tick})"
            );
        }
    }

    #[test]
    fn unregistering_drains_the_registry() {
        let supervisor = registered();
        supervisor.register(
            EndpointId(8),
            "call-2",
            "eng",
            "peer",
            "password-0000000000000",
        );
        assert_eq!(supervisor.len(), 2);
        supervisor.unregister_call("call-1");
        assert_eq!(supervisor.len(), 1);
        supervisor.unregister(EndpointId(8));
        assert!(supervisor.is_empty(), "no consent state outlives its calls");
    }

    #[test]
    fn events_for_an_unregistered_endpoint_are_discarded() {
        let supervisor = supervisor();
        supervisor
            .events()
            .try_send(IceDatapathEvent {
                endpoint: EndpointId(99),
                source: peer_addr(),
                arrival_tick: 0,
                datagram: Bytes::from_static(b"not even stun"),
            })
            .expect("capacity");
        supervisor.drain_events();
        assert!(supervisor.is_empty());
    }

    #[test]
    fn endpoints_get_distinct_jitter_seeds() {
        // Two endpoints must not schedule their checks on identical ticks (RFC 7675 §5.1 asks for
        // randomisation so a box full of calls does not emit one synchronised burst).
        assert_ne!(tie_breaker(EndpointId(1)), tie_breaker(EndpointId(2)));
        assert_ne!(tie_breaker(EndpointId(1)), 0, "a zero seed would stick");
    }
}

// ---- RFC 8445 full agent -----------------------------------------------------------------------

/// What [`AgentSupervisor::poll`] asks the engine to do for one endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentOutcome {
    /// Transmit `datagram` from `endpoint` to `dst` (a connectivity check).
    Send {
        /// The endpoint to source it from.
        endpoint: EndpointId,
        /// Where to send it.
        dst: SocketAddr,
        /// The STUN datagram.
        datagram: Vec<u8>,
    },
    /// ICE selected a pair (RFC 8445 §8.1.1). `remote` is now the media path for `endpoint`.
    Selected {
        /// The endpoint whose path was decided.
        endpoint: EndpointId,
        /// The call that owns it.
        call_id: String,
        /// The peer transport address media must use.
        remote: SocketAddr,
    },
    /// A datagram from this endpoint's TURN server (RFC 5766), not from an ICE peer. The allocation
    /// shares the endpoint's 5-tuple with the checks, so the two are told apart by source: only the
    /// server's own address lands here, and it goes to the `TurnClient` rather than the checklist —
    /// an Allocate/Refresh response fed to the agent would simply be dropped as uncorrelated, and
    /// the allocation would never come up.
    TurnDatagram {
        /// The endpoint whose allocation it belongs to.
        endpoint: EndpointId,
        /// The raw STUN/TURN bytes.
        datagram: Vec<u8>,
    },
    /// Every candidate pair failed (RFC 8445 §8.1.2): there is no usable path. Tear the call down.
    Failed {
        /// The endpoint whose checklist was exhausted.
        endpoint: EndpointId,
        /// The call that owns it.
        call_id: String,
    },
}

/// One endpoint's registered agent.
#[derive(Debug)]
struct AgentEntry {
    call_id: String,
    /// The local transport address the agent's checks egress from.
    local: SocketAddr,
    agent: IceAgent,
    /// Whether a `Selected` outcome has already been reported (so it is reported exactly once).
    announced: bool,
    /// The TURN server this endpoint relays through, when it gathered a relayed candidate. Traffic
    /// from this address is the allocation's, not a peer's.
    turn_server: Option<SocketAddr>,
}

/// The per-engine registry of full ICE agents, one per ICE-enabled endpoint.
///
/// Mirrors [`ConsentSupervisor`]: shared (`DashMap`) because registration happens on the control path
/// while polling happens on the driver task, and pure with respect to I/O — it returns
/// [`AgentOutcome`]s for the engine to execute.
#[derive(Debug)]
pub struct AgentSupervisor {
    agents: DashMap<EndpointId, AgentEntry>,
    events_tx: flume::Sender<IceDatapathEvent>,
    events_rx: flume::Receiver<IceDatapathEvent>,
}

impl Default for AgentSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentSupervisor {
    /// Build an empty supervisor.
    #[must_use]
    pub fn new() -> Self {
        let (events_tx, events_rx) = flume::bounded(EVENT_QUEUE_DEPTH);
        Self {
            agents: DashMap::new(),
            events_tx,
            events_rx,
        }
    }

    /// The STUN sink to hand to [`siphon_rtp_datapath::Datapath::set_ice_agent`].
    #[must_use]
    pub fn events(&self) -> flume::Sender<IceDatapathEvent> {
        self.events_tx.clone()
    }

    /// How many endpoints are running an agent (the leak assertion's hook).
    #[must_use]
    pub fn len(&self) -> usize {
        self.agents.len()
    }

    /// Whether no endpoint has an agent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    /// Start an agent on `endpoint`.
    pub fn register(
        &self,
        endpoint: EndpointId,
        call_id: &str,
        local: SocketAddr,
        config: AgentConfig,
        now_ms: u64,
    ) {
        self.agents.insert(
            endpoint,
            AgentEntry {
                call_id: call_id.to_string(),
                local,
                agent: IceAgent::new(config, now_ms),
                announced: false,
                turn_server: None,
            },
        );
    }

    /// Stop every agent belonging to `call_id`.
    pub fn unregister_call(&self, call_id: &str) {
        self.agents.retain(|_, entry| entry.call_id != call_id);
    }

    /// The agent state for `endpoint` (diagnostics and tests).
    #[must_use]
    pub fn state(&self, endpoint: EndpointId) -> Option<IceState> {
        self.agents.get(&endpoint).map(|entry| entry.agent.state())
    }

    /// How many pairs `endpoint`'s checklist holds — diagnostics and tests.
    #[must_use]
    pub fn checklist_len(&self, endpoint: EndpointId) -> Option<usize> {
        self.agents
            .get(&endpoint)
            .map(|entry| entry.agent.checklist().len())
    }

    /// Hand a trickled remote candidate to `endpoint`'s agent (RFC 8838 §4.2). Returns how many
    /// pairs it created — `0` for an endpoint with no agent, or a candidate its component/family
    /// cannot pair with.
    pub fn add_remote_candidate(
        &self,
        endpoint: EndpointId,
        candidate: &siphon_rtp_ice::Candidate,
    ) -> usize {
        self.agents
            .get_mut(&endpoint)
            .map_or(0, |mut entry| entry.agent.add_remote_candidate(candidate))
    }

    /// Feed the datapath's forwarded STUN into the agents. MUST run before [`Self::poll`], so a check
    /// that arrived this tick is answered on this tick rather than the next.
    /// Every remote transport address this endpoint's checklist may probe.
    ///
    /// A relayed candidate can only reach a peer the TURN server holds a permission for (RFC 5766
    /// §9), so the allocation needs exactly this set: the remotes of every pair, including the
    /// peer-reflexive ones discovered mid-session, which is why it is read each tick rather than once
    /// from the offer.
    #[must_use]
    pub fn remote_addresses(&self, endpoint: EndpointId) -> Vec<SocketAddr> {
        let Some(entry) = self.agents.get(&endpoint) else {
            return Vec::new();
        };
        let mut seen: Vec<SocketAddr> = Vec::new();
        for pair in entry.agent.checklist().pairs() {
            if !seen.contains(&pair.remote.address) {
                seen.push(pair.remote.address);
            }
        }
        seen
    }

    /// Declare the TURN server `endpoint` relays through, so its datagrams are routed to the
    /// allocation instead of the checklist. Called once the allocation is live; a no-op for an
    /// endpoint with no registered agent.
    pub fn set_turn_server(&self, endpoint: EndpointId, server: Option<SocketAddr>) {
        if let Some(mut entry) = self.agents.get_mut(&endpoint) {
            entry.turn_server = server;
        }
    }

    pub fn drain_events(&self, now_ms: u64) -> Vec<AgentOutcome> {
        let mut outcomes = Vec::new();
        while let Ok(event) = self.events_rx.try_recv() {
            let Some(mut entry) = self.agents.get_mut(&event.endpoint) else {
                continue;
            };
            // RFC 5766: the allocation shares this 5-tuple with the connectivity checks, so tell them
            // apart by source. The TURN server's own responses drive the `TurnClient`; feeding them
            // to the checklist would drop them as uncorrelated and the allocation would never come up.
            if entry.turn_server == Some(event.source) {
                outcomes.push(AgentOutcome::TurnDatagram {
                    endpoint: event.endpoint,
                    datagram: event.datagram.to_vec(),
                });
                continue;
            }
            let local = entry.local;
            let actions = entry
                .agent
                .on_datagram(local, event.source, &event.datagram, now_ms);
            let endpoint = event.endpoint;
            Self::translate(&mut entry, endpoint, actions, &mut outcomes);
        }
        outcomes
    }

    /// Drive every agent at `now_ms`.
    pub fn poll(&self, now_ms: u64) -> Vec<AgentOutcome> {
        let mut outcomes = Vec::new();
        for mut entry in self.agents.iter_mut() {
            let endpoint = *entry.key();
            let entry = entry.value_mut();
            let actions = entry.agent.poll(now_ms);
            Self::translate(entry, endpoint, actions, &mut outcomes);
        }
        outcomes
    }

    /// Convert the agent's actions into engine outcomes, reporting a selection exactly once.
    fn translate(
        entry: &mut AgentEntry,
        endpoint: EndpointId,
        actions: Vec<AgentAction>,
        outcomes: &mut Vec<AgentOutcome>,
    ) {
        for action in actions {
            match action {
                AgentAction::Send { to, datagram, .. } => outcomes.push(AgentOutcome::Send {
                    endpoint,
                    dst: to,
                    datagram,
                }),
                AgentAction::Selected { remote, .. } => {
                    if !entry.announced {
                        entry.announced = true;
                        outcomes.push(AgentOutcome::Selected {
                            endpoint,
                            call_id: entry.call_id.clone(),
                            remote,
                        });
                    }
                }
                AgentAction::StateChanged(IceState::Failed) => {
                    outcomes.push(AgentOutcome::Failed {
                        endpoint,
                        call_id: entry.call_id.clone(),
                    });
                }
                AgentAction::StateChanged(_) => {}
            }
        }
    }
}
