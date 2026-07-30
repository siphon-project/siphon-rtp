//! RFC 8445 §5.1.1 candidate gathering — the plan, not the plumbing.
//!
//! Pure and clock-free like the rest of the crate: [`Gatherer::poll`] says what to transmit at a
//! given logical millisecond, [`Gatherer::on_datagram`] takes the replies back, and the caller does
//! the I/O. That is what makes the RFC's pacing, retransmission, and pruning testable without a
//! socket or a runtime.
//!
//! # What it gathers
//!
//! - The **host** candidate (RFC 8445 §5.1.1.1): the address the engine's media endpoint is reachable
//!   at. Known before any packet moves, so it exists the moment the gatherer is constructed.
//! - A **server-reflexive** candidate per configured STUN server (§5.1.1.2): a Binding request goes
//!   out, and the XOR-MAPPED-ADDRESS that comes back is the outside of our NAT.
//!
//! Relayed candidates (a TURN Allocate) are **not** gathered here — see the crate's scope notes. On a
//! public-address engine they add a hop and no reachability; they matter when the engine itself sits
//! behind a NAT it cannot be addressed through, which is a deployment we do not currently support.
//!
//! # Bounded by construction
//!
//! Gathering happens on the offer/answer control path, so it can never run unbounded: every probe
//! retransmits per RFC 8489 §6.2.1 and the whole plan gives up at `deadline_ms`, after which the
//! caller advertises whatever was gathered. A STUN server that is down costs one bounded delay and
//! yields a host-only candidate list — never a failed call.

use std::net::SocketAddr;

use siphon_rtp_stun::{
    self as stun,
    client::{RetransmitSchedule, Transaction, TransactionAction, TransactionId},
};

use crate::candidate::{Candidate, CandidateKind, Transport};

/// RFC 8445 §14.2 `Ta`: the minimum spacing between two transmissions the agent paces. 50 ms is the
/// RFC's recommended value for a single media stream.
pub const DEFAULT_PACING_MS: u64 = 50;

/// RFC 8489 §6.2.1 initial RTO. 500 ms is the specified default.
pub const DEFAULT_RTO_MS: u64 = 500;

/// How long gathering may take before the caller gives up and advertises what it has. Not from a
/// spec — it is the bound that keeps a dead STUN server from holding an offer open. Three RTOs is
/// enough for the RFC 8489 retransmission to have tried several times on a live server.
pub const DEFAULT_DEADLINE_MS: u64 = 1_500;

/// The local preference the engine gives its own candidates (RFC 8445 §5.1.2.1). A single-endpoint
/// leg has nothing to rank against, so it takes the maximum; multi-interface gathering would use
/// [`crate::interleaved_local_preferences`] instead.
pub const DEFAULT_LOCAL_PREFERENCE: u16 = 65535;

/// What to gather, and how hard to try.
#[derive(Debug, Clone)]
pub struct GatherConfig {
    /// The media endpoint's own bound address — the base of every candidate gathered here, and the
    /// source the probes are sent from.
    pub base: SocketAddr,
    /// The address to advertise for the **host** candidate. Usually `base`; different when the engine
    /// binds a private address behind 1:1 NAT and advertises a routable one, in which case the host
    /// candidate must carry the routable address or a peer could never reach it.
    pub advertised: SocketAddr,
    /// STUN servers to ask for a reflexive address. Empty ⇒ host-only gathering, which is correct for
    /// a directly-addressable engine and costs nothing.
    pub stun_servers: Vec<SocketAddr>,
    /// The ICE component this candidate set is for: 1 = RTP, 2 = RTCP (RFC 8445 §4.1.1.1).
    pub component: u16,
    /// RFC 8445 §14.2 `Ta` pacing between transmissions, in milliseconds.
    pub pacing_ms: u64,
    /// RFC 8489 §6.2.1 initial RTO for each probe, in milliseconds.
    pub rto_ms: u64,
    /// Overall bound on gathering, in milliseconds.
    pub deadline_ms: u64,
}

impl GatherConfig {
    /// A host-only configuration for a leg bound (and advertised) at `address`, component 1.
    #[must_use]
    pub fn host_only(address: SocketAddr) -> Self {
        Self {
            base: address,
            advertised: address,
            stun_servers: Vec::new(),
            component: 1,
            pacing_ms: DEFAULT_PACING_MS,
            rto_ms: DEFAULT_RTO_MS,
            deadline_ms: DEFAULT_DEADLINE_MS,
        }
    }

    /// Add the STUN servers to probe for a server-reflexive candidate.
    #[must_use]
    pub fn with_stun_servers(mut self, servers: Vec<SocketAddr>) -> Self {
        self.stun_servers = servers;
        self
    }

    /// Advertise `advertised` for the host candidate instead of the bound address (1:1 NAT).
    #[must_use]
    pub fn advertising(mut self, advertised: SocketAddr) -> Self {
        self.advertised = advertised;
        self
    }
}

/// What [`Gatherer::poll`] asks the caller to do at this millisecond.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatherAction {
    /// Nothing due yet — poll again later.
    Idle,
    /// Transmit `datagram` to `server` from the gathering endpoint (a first probe or a retransmit).
    Probe {
        /// The STUN server to send to.
        server: SocketAddr,
        /// The Binding request bytes.
        datagram: Vec<u8>,
    },
    /// Gathering is finished: every probe has answered or given up, or the deadline passed. The
    /// candidate list is final; read it with [`Gatherer::candidates`].
    Complete,
}

/// One STUN server being probed for a reflexive address.
#[derive(Debug, Clone)]
struct ServerProbe {
    address: SocketAddr,
    /// `None` until the first probe goes out (the pacer decides when).
    transaction: Option<Transaction>,
    /// Set once this server has answered or given up — either way we stop asking.
    settled: bool,
}

/// The gathering state machine for one media endpoint.
#[derive(Debug, Clone)]
pub struct Gatherer {
    config: GatherConfig,
    started_ms: u64,
    /// Earliest millisecond at which the next transmission may go out (RFC 8445 §14.2 `Ta`).
    next_transmit_ms: u64,
    probes: Vec<ServerProbe>,
    candidates: Vec<Candidate>,
    complete: bool,
}

impl Gatherer {
    /// Start gathering at `now_ms`. The host candidate exists immediately — it needs no network — so
    /// a host-only configuration is [`complete`](Self::is_complete) from the first poll.
    #[must_use]
    pub fn new(config: GatherConfig, now_ms: u64) -> Self {
        // RFC 8445 §5.1.1.1: the host candidate's base is itself. Its foundation involves no server.
        let host = Candidate {
            foundation: Candidate::compute_foundation(
                CandidateKind::Host,
                config.base.ip(),
                &Transport::Udp,
                None,
            ),
            ..Candidate::new(
                String::new(),
                config.component,
                config.advertised,
                CandidateKind::Host,
                DEFAULT_LOCAL_PREFERENCE,
            )
        };
        let probes = config
            .stun_servers
            .iter()
            .map(|address| ServerProbe {
                address: *address,
                transaction: None,
                settled: false,
            })
            .collect::<Vec<_>>();
        let complete = probes.is_empty();
        Self {
            started_ms: now_ms,
            next_transmit_ms: now_ms,
            probes,
            candidates: vec![host],
            complete,
            config,
        }
    }

    /// The candidates gathered so far, host first, in the order they were learned.
    #[must_use]
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// Whether gathering has finished (every probe settled, or the deadline passed).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// The STUN servers that never answered, for the caller's log line. Empty until gathering
    /// completes; a non-empty list means the advertised set is smaller than it should have been,
    /// which is worth saying out loud rather than silently shipping a host-only offer.
    #[must_use]
    pub fn unanswered_servers(&self) -> Vec<SocketAddr> {
        self.probes
            .iter()
            .filter(|probe| {
                !self
                    .candidates
                    .iter()
                    .any(|candidate| candidate.kind == CandidateKind::ServerReflexive)
                    || probe
                        .transaction
                        .as_ref()
                        .is_none_or(Transaction::is_pending)
            })
            .map(|probe| probe.address)
            .collect()
    }

    /// Drive gathering at `now_ms`.
    pub fn poll(&mut self, now_ms: u64) -> GatherAction {
        if self.complete {
            return GatherAction::Complete;
        }
        // The hard bound: whatever has not answered by now never will, as far as this offer is
        // concerned. Advertise what we have rather than hold the control response open.
        if now_ms.saturating_sub(self.started_ms) >= self.config.deadline_ms {
            self.complete = true;
            return GatherAction::Complete;
        }
        // RFC 8445 §14.2: transmissions are paced at Ta, never bursted.
        if now_ms < self.next_transmit_ms {
            return GatherAction::Idle;
        }

        for index in 0..self.probes.len() {
            if self.probes[index].settled {
                continue;
            }
            match self.probes[index].transaction.as_mut() {
                // Not yet started: send the first probe.
                None => {
                    let Some(transaction_id) = TransactionId::new() else {
                        // OS RNG unavailable this instant — try again next poll, never panic.
                        return GatherAction::Idle;
                    };
                    let schedule = RetransmitSchedule::new(self.config.rto_ms.max(1));
                    self.probes[index].transaction =
                        Some(Transaction::start(transaction_id, schedule, now_ms));
                    return self.transmit(index, &transaction_id, now_ms);
                }
                // Running: let its RFC 8489 clock decide.
                Some(transaction) => {
                    let transaction_id = *transaction.id();
                    match transaction.poll(now_ms) {
                        TransactionAction::Retransmit(_) => {
                            return self.transmit(index, &transaction_id, now_ms);
                        }
                        TransactionAction::Failed => self.probes[index].settled = true,
                        TransactionAction::Wait => {}
                    }
                }
            }
        }

        if self.probes.iter().all(|probe| probe.settled) {
            self.complete = true;
            return GatherAction::Complete;
        }
        GatherAction::Idle
    }

    /// Emit a probe for `index` and re-arm the pacer.
    fn transmit(
        &mut self,
        index: usize,
        transaction_id: &TransactionId,
        now_ms: u64,
    ) -> GatherAction {
        self.next_transmit_ms = now_ms.saturating_add(self.config.pacing_ms.max(1));
        GatherAction::Probe {
            server: self.probes[index].address,
            // A gathering Binding request carries no credentials: RFC 8489 §9.1 leaves
            // authentication optional for Binding, and we have none to offer a STUN server.
            datagram: stun::MessageBuilder::new(stun::BINDING_REQUEST, transaction_id.as_bytes())
                .finish(None, true),
        }
    }

    /// Feed back a datagram that arrived on the gathering endpoint. Returns `true` when it was one of
    /// our probe responses (so the caller knows it was consumed and should not be handled elsewhere).
    ///
    /// A response is accepted only if its transaction id matches an outstanding probe **and** it came
    /// from the server that probe was sent to: without that check, anyone who could guess a
    /// transaction id could plant a reflexive candidate.
    pub fn on_datagram(&mut self, source: SocketAddr, datagram: &[u8], now_ms: u64) -> bool {
        let Ok(message) = stun::parse(datagram) else {
            return false;
        };
        if message.message_type != stun::BINDING_SUCCESS {
            return false;
        }
        for index in 0..self.probes.len() {
            if self.probes[index].address != source {
                continue;
            }
            let matched = self.probes[index]
                .transaction
                .as_mut()
                .is_some_and(|transaction| transaction.on_response(&message.transaction_id));
            if !matched {
                continue;
            }
            self.probes[index].settled = true;
            if let Some(mapped) = message.xor_mapped_address() {
                self.add_reflexive(mapped, source);
            }
            if self.probes.iter().all(|probe| probe.settled) {
                self.complete = true;
            }
            let _ = now_ms;
            return true;
        }
        false
    }

    /// Record a server-reflexive candidate, applying RFC 8445 §5.1.3 redundancy pruning.
    fn add_reflexive(&mut self, mapped: SocketAddr, server: SocketAddr) {
        // §5.1.3: a candidate is redundant when its transport address equals another's and its base
        // equals that other's base. An engine on a public address sees its own address come back, so
        // the reflexive candidate *is* the host candidate — advertising both would double every
        // check for no reachability.
        if mapped == self.config.base || mapped == self.config.advertised {
            return;
        }
        // The same applies across STUN servers: two servers behind the same NAT report the same
        // mapped address, and only the first is worth advertising.
        if self
            .candidates
            .iter()
            .any(|candidate| candidate.address == mapped)
        {
            return;
        }
        self.candidates.push(Candidate {
            foundation: Candidate::compute_foundation(
                CandidateKind::ServerReflexive,
                self.config.base.ip(),
                &Transport::Udp,
                Some(server),
            ),
            // RFC 8839 §5.1: a reflexive candidate's related address is its base.
            related: Some(self.config.base),
            ..Candidate::new(
                String::new(),
                self.config.component,
                mapped,
                CandidateKind::ServerReflexive,
                DEFAULT_LOCAL_PREFERENCE,
            )
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "192.0.2.10:40000";
    const STUN: &str = "198.51.100.1:3478";
    const OTHER_STUN: &str = "198.51.100.2:3478";
    const MAPPED: &str = "203.0.113.5:52000";

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("addr")
    }

    fn config() -> GatherConfig {
        GatherConfig::host_only(address(BASE)).with_stun_servers(vec![address(STUN)])
    }

    /// The peer STUN server's answer to whatever probe was emitted.
    fn server_response(datagram: &[u8], mapped: &str) -> Vec<u8> {
        let request = stun::parse(datagram).expect("parse probe");
        stun::binding_success_response(&request.transaction_id, address(mapped), None)
    }

    fn probe(action: GatherAction) -> Vec<u8> {
        match action {
            GatherAction::Probe { datagram, .. } => datagram,
            other => panic!("expected a probe, got {other:?}"),
        }
    }

    #[test]
    fn host_only_gathering_completes_immediately_without_any_network() {
        let mut gatherer = Gatherer::new(GatherConfig::host_only(address(BASE)), 0);
        assert_eq!(gatherer.poll(0), GatherAction::Complete);
        assert!(gatherer.is_complete());
        let candidates = gatherer.candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, CandidateKind::Host);
        assert_eq!(candidates[0].address, address(BASE));
        assert_eq!(candidates[0].priority, 2_130_706_431, "host, component 1");
        assert_eq!(candidates[0].related, None, "a host candidate has no raddr");
    }

    #[test]
    fn a_reflexive_address_becomes_a_candidate_with_the_base_as_its_related_address() {
        let mut gatherer = Gatherer::new(config(), 0);
        let datagram = probe(gatherer.poll(0));
        let request = stun::parse(&datagram).expect("a valid Binding request");
        assert!(request.is_binding_request());
        assert_eq!(
            request.username(),
            None,
            "a gathering probe carries no credentials (RFC 8489 §9.1)"
        );

        assert!(gatherer.on_datagram(address(STUN), &server_response(&datagram, MAPPED), 10));
        assert!(gatherer.is_complete(), "the only probe settled");

        let candidates = gatherer.candidates();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[1].kind, CandidateKind::ServerReflexive);
        assert_eq!(candidates[1].address, address(MAPPED));
        assert_eq!(
            candidates[1].related,
            Some(address(BASE)),
            "RFC 8839 §5.1: raddr is the base"
        );
        assert!(
            candidates[1].priority < candidates[0].priority,
            "srflx ranks below host (RFC 8445 §5.1.2.2)"
        );
        assert_ne!(
            candidates[1].foundation, candidates[0].foundation,
            "different type ⇒ different foundation"
        );
        assert!(gatherer.unanswered_servers().is_empty());
    }

    #[test]
    fn a_reflexive_address_equal_to_the_base_is_pruned_as_redundant() {
        // The engine on a public address: the STUN server reports back the address we already
        // advertise. RFC 8445 §5.1.3 — advertising it twice doubles every check for nothing.
        let mut gatherer = Gatherer::new(config(), 0);
        let datagram = probe(gatherer.poll(0));
        assert!(gatherer.on_datagram(address(STUN), &server_response(&datagram, BASE), 10));
        assert_eq!(
            gatherer.candidates().len(),
            1,
            "only the host candidate survives"
        );
        assert!(gatherer.is_complete());
    }

    #[test]
    fn two_servers_behind_one_nat_yield_a_single_reflexive_candidate() {
        let mut gatherer = Gatherer::new(
            GatherConfig::host_only(address(BASE))
                .with_stun_servers(vec![address(STUN), address(OTHER_STUN)]),
            0,
        );
        // Both probes go out, paced Ta apart.
        let first = probe(gatherer.poll(0));
        assert_eq!(gatherer.poll(0), GatherAction::Idle, "paced, not bursted");
        let second = probe(gatherer.poll(DEFAULT_PACING_MS));

        // Both report the same mapped address (one NAT in front of us).
        assert!(gatherer.on_datagram(address(STUN), &server_response(&first, MAPPED), 100));
        assert!(gatherer.on_datagram(address(OTHER_STUN), &server_response(&second, MAPPED), 110));
        assert_eq!(
            gatherer.candidates().len(),
            2,
            "host + one reflexive, not two identical reflexives"
        );
        assert!(gatherer.is_complete());
    }

    #[test]
    fn a_response_from_the_wrong_source_is_not_accepted() {
        // Transaction-id correlation alone is not enough: the response must come from the server we
        // asked, or an off-path guess could plant a candidate.
        let mut gatherer = Gatherer::new(config(), 0);
        let datagram = probe(gatherer.poll(0));
        let forged = server_response(&datagram, "198.51.100.66:1");
        assert!(
            !gatherer.on_datagram(address("203.0.113.99:3478"), &forged, 10),
            "a response from an unasked source is ignored"
        );
        assert_eq!(gatherer.candidates().len(), 1);
        assert!(!gatherer.is_complete());
    }

    #[test]
    fn an_uncorrelated_or_malformed_datagram_is_ignored() {
        let mut gatherer = Gatherer::new(config(), 0);
        let _ = gatherer.poll(0);
        // Right source, wrong transaction id.
        let wrong = stun::binding_success_response(&[0xAB; 12], address(MAPPED), None);
        assert!(!gatherer.on_datagram(address(STUN), &wrong, 10));
        // Not STUN at all.
        assert!(!gatherer.on_datagram(address(STUN), b"this is not stun", 10));
        // A Binding *request* arriving here is not a gathering response.
        let request =
            stun::MessageBuilder::new(stun::BINDING_REQUEST, &[1u8; 12]).finish(None, true);
        assert!(!gatherer.on_datagram(address(STUN), &request, 10));
        assert_eq!(gatherer.candidates().len(), 1);
    }

    #[test]
    fn a_silent_stun_server_retransmits_then_gives_up_at_the_deadline() {
        let mut gatherer = Gatherer::new(config(), 0);
        let _ = probe(gatherer.poll(0));

        // RFC 8489 §6.2.1 schedules request n at (2^n − 1)·RTO, so with the 500 ms initial RTO the
        // second request is due at exactly 500 ms — not before, and not only at the deadline.
        let mut retransmit_at = None;
        for now in 1..=DEFAULT_RTO_MS {
            if let GatherAction::Probe { .. } = gatherer.poll(now) {
                retransmit_at = Some(now);
                break;
            }
        }
        assert_eq!(
            retransmit_at,
            Some(DEFAULT_RTO_MS),
            "the probe is retransmitted at the RFC 8489 initial RTO, not abandoned"
        );

        // And the plan is bounded: at the deadline it completes with what it has.
        assert_eq!(gatherer.poll(DEFAULT_DEADLINE_MS), GatherAction::Complete);
        assert!(gatherer.is_complete());
        assert_eq!(
            gatherer.candidates().len(),
            1,
            "a dead STUN server yields a host-only list, never a failed offer"
        );
        assert_eq!(
            gatherer.unanswered_servers(),
            vec![address(STUN)],
            "and the caller can say which server went quiet"
        );
    }

    #[test]
    fn the_host_candidate_carries_the_advertised_address_not_the_bound_one() {
        // 1:1 NAT (an elastic IP): binding a private address but advertising a public one. The host
        // candidate must carry the routable address or no peer could ever reach it.
        let advertised = address("203.0.113.10:40000");
        let mut gatherer = Gatherer::new(
            GatherConfig::host_only(address("10.0.0.5:40000")).advertising(advertised),
            0,
        );
        assert_eq!(gatherer.poll(0), GatherAction::Complete);
        assert_eq!(gatherer.candidates()[0].address, advertised);
    }

    #[test]
    fn a_reflexive_address_equal_to_the_advertised_address_is_also_pruned() {
        // Same 1:1-NAT deployment: the STUN server reports the elastic IP we already advertise.
        let advertised = address("203.0.113.10:40000");
        let mut gatherer = Gatherer::new(
            GatherConfig::host_only(address("10.0.0.5:40000"))
                .advertising(advertised)
                .with_stun_servers(vec![address(STUN)]),
            0,
        );
        let datagram = probe(gatherer.poll(0));
        assert!(gatherer.on_datagram(
            address(STUN),
            &server_response(&datagram, "203.0.113.10:40000"),
            10
        ));
        assert_eq!(gatherer.candidates().len(), 1, "redundant with the host");
    }

    #[test]
    fn component_2_candidates_rank_just_below_component_1() {
        // Non-mux legs gather for the RTCP component too (RFC 8445 §4.1.1.1).
        let mut config = GatherConfig::host_only(address(BASE));
        config.component = 2;
        let mut gatherer = Gatherer::new(config, 0);
        assert_eq!(gatherer.poll(0), GatherAction::Complete);
        assert_eq!(gatherer.candidates()[0].component, 2);
        assert_eq!(gatherer.candidates()[0].priority, 2_130_706_430);
    }
}
