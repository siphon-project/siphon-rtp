//! RFC 8445 §6.1.2 candidate pairs and the checklist that orders them.
//!
//! The checklist is the agent's work queue: every local candidate paired with every compatible remote
//! one, ordered by the §6.1.2.3 priority, pruned of redundancy, and started in the frozen/waiting
//! arrangement §6.1.2.6 prescribes so that one foundation is probed at a time rather than all of them
//! at once.
//!
//! Pure data and ordering. Sending checks, correlating responses, and nominating live in
//! [`crate::agent`]; this module only decides *which pair is next* and *what a pair's state is*.

use std::net::SocketAddr;

use crate::candidate::{Candidate, CandidateKind};

/// The lifecycle of one candidate pair (RFC 8445 §6.1.2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PairState {
    /// Not yet eligible: another pair with the same foundation is being checked first. Unfreezes when
    /// that one succeeds (§7.2.5.3.3).
    Frozen,
    /// Eligible and waiting its turn in the `Ta` pacing.
    Waiting,
    /// A connectivity check is outstanding.
    InProgress,
    /// The check succeeded — the pair is valid and can carry media.
    Succeeded,
    /// The check failed or timed out.
    Failed,
}

/// One local↔remote candidate pair (RFC 8445 §6.1.2.2).
#[derive(Debug, Clone)]
pub struct CandidatePair {
    /// Our candidate.
    pub local: Candidate,
    /// The peer's candidate.
    pub remote: Candidate,
    /// The RFC 8445 §6.1.2.3 pair priority — the checklist's sort key.
    pub priority: u64,
    /// Where this pair is in its lifecycle.
    pub state: PairState,
    /// Whether this pair has been nominated (RFC 8445 §8.1.1): the controlling agent asked for it
    /// with USE-CANDIDATE, or we are controlled and received that request.
    pub nominated: bool,
}

impl CandidatePair {
    /// Build a pair and compute its priority for the given role.
    #[must_use]
    pub fn new(local: Candidate, remote: Candidate, controlling: bool) -> Self {
        let priority = pair_priority(local.priority, remote.priority, controlling);
        Self {
            local,
            remote,
            priority,
            state: PairState::Frozen,
            nominated: false,
        }
    }

    /// The pair's foundation (RFC 8445 §6.1.2.6): the two candidate foundations together. Pairs
    /// sharing one are unfrozen together, because if one works the others probably do too.
    #[must_use]
    pub fn foundation(&self) -> (String, String) {
        (
            self.local.foundation.clone(),
            self.remote.foundation.clone(),
        )
    }

    /// The component this pair carries (both candidates share it by construction).
    #[must_use]
    pub fn component(&self) -> u16 {
        self.local.component
    }
}

/// The RFC 8445 §6.1.2.3 pair-priority formula:
///
/// ```text
/// pair priority = 2^32 * MIN(G,D) + 2 * MAX(G,D) + (G > D ? 1 : 0)
/// ```
///
/// where `G` is the **controlling** agent's candidate priority and `D` the **controlled** agent's.
/// Both agents must compute the same number for a pair, which is why the roles — not "local" and
/// "remote" — decide which is which.
#[must_use]
pub fn pair_priority(local_priority: u32, remote_priority: u32, controlling: bool) -> u64 {
    let (g, d) = if controlling {
        (u64::from(local_priority), u64::from(remote_priority))
    } else {
        (u64::from(remote_priority), u64::from(local_priority))
    };
    (1u64 << 32)
        .saturating_mul(g.min(d))
        .saturating_add(2u64.saturating_mul(g.max(d)))
        .saturating_add(u64::from(g > d))
}

/// The ordered set of pairs for one media stream (RFC 8445 §6.1.2).
#[derive(Debug, Clone, Default)]
pub struct Checklist {
    pairs: Vec<CandidatePair>,
}

impl Checklist {
    /// Form the checklist from the local and remote candidate sets (RFC 8445 §6.1.2.2), prune it
    /// (§6.1.2.4), order it by priority, and set the initial frozen/waiting states (§6.1.2.6).
    #[must_use]
    pub fn form(local: &[Candidate], remote: &[Candidate], controlling: bool) -> Self {
        let mut pairs = Vec::new();
        for local_candidate in local {
            for remote_candidate in remote {
                // §6.1.2.2: pair only within a component, only within an address family, and only
                // over a transport we actually check. A v4↔v6 pair can never work, and forming it
                // would just burn checks.
                if local_candidate.component != remote_candidate.component
                    || local_candidate.address.is_ipv4() != remote_candidate.address.is_ipv4()
                    || !local_candidate.transport.is_supported()
                    || !remote_candidate.transport.is_supported()
                {
                    continue;
                }
                pairs.push(CandidatePair::new(
                    local_candidate.clone(),
                    remote_candidate.clone(),
                    controlling,
                ));
            }
        }
        let mut checklist = Self { pairs };
        checklist.prune();
        checklist.sort();
        checklist.freeze_initial();
        checklist
    }

    /// RFC 8445 §6.1.2.4: a server-reflexive local candidate is replaced by its base for pairing —
    /// checks are sent from the base either way — and the pair that leaves redundant (same base, same
    /// remote) is removed, keeping the higher-priority one.
    fn prune(&mut self) {
        for pair in &mut self.pairs {
            if pair.local.kind == CandidateKind::ServerReflexive {
                if let Some(base) = pair.local.related {
                    pair.local.address = base;
                }
            }
        }
        let mut seen: Vec<(SocketAddr, SocketAddr)> = Vec::new();
        // Highest priority first, so the survivor of a redundant set is the best one.
        self.pairs
            .sort_by_key(|pair| std::cmp::Reverse(pair.priority));
        self.pairs.retain(|pair| {
            let key = (pair.local.address, pair.remote.address);
            if seen.contains(&key) {
                return false;
            }
            seen.push(key);
            true
        });
    }

    fn sort(&mut self) {
        self.pairs
            .sort_by_key(|pair| std::cmp::Reverse(pair.priority));
    }

    /// RFC 8445 §6.1.2.6: for each distinct foundation, the pair with the lowest component id — and,
    /// among those, the highest priority — starts `Waiting`; everything else starts `Frozen`. That is
    /// what keeps the agent from checking every foundation simultaneously.
    fn freeze_initial(&mut self) {
        let mut started: Vec<(String, String)> = Vec::new();
        // The list is already priority-ordered, so the first pair seen per foundation is the best
        // one; among equals, prefer the lowest component id.
        let mut order: Vec<usize> = (0..self.pairs.len()).collect();
        order.sort_by_key(|&index| self.pairs[index].component());
        for index in order {
            let foundation = self.pairs[index].foundation();
            if started.contains(&foundation) {
                continue;
            }
            started.push(foundation);
            self.pairs[index].state = PairState::Waiting;
        }
    }

    /// The pairs, highest priority first.
    #[must_use]
    pub fn pairs(&self) -> &[CandidatePair] {
        &self.pairs
    }

    /// Mutable access for the agent's state transitions.
    pub fn pairs_mut(&mut self) -> &mut [CandidatePair] {
        &mut self.pairs
    }

    /// Whether the checklist has no pairs at all (nothing compatible was offered).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// The number of pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// The index of the next pair to check: the highest-priority `Waiting` one (RFC 8445 §6.1.4.2).
    ///
    /// Selected by priority rather than by position, because indices are **stable** — a pair
    /// discovered mid-session is appended, never spliced in — and the agent keys its outstanding
    /// checks by index.
    #[must_use]
    pub fn next_waiting(&self) -> Option<usize> {
        self.pairs
            .iter()
            .enumerate()
            .filter(|(_, pair)| pair.state == PairState::Waiting)
            .max_by_key(|(_, pair)| pair.priority)
            .map(|(index, _)| index)
    }

    /// Find a pair by its local and remote transport addresses.
    #[must_use]
    pub fn find(&self, local: SocketAddr, remote: SocketAddr) -> Option<usize> {
        self.pairs
            .iter()
            .position(|pair| pair.local.address == local && pair.remote.address == remote)
    }

    /// Add a pair discovered at runtime (a peer-reflexive one, RFC 8445 §7.3.1.3/§7.2.5.3.1) and
    /// return its index.
    ///
    /// **Appended, not spliced by priority**: the agent keys its outstanding checks by pair index, so
    /// inserting into the middle would silently re-point every check after it. Ordering is applied
    /// where it matters instead — [`next_waiting`](Self::next_waiting) and [`valid`](Self::valid)
    /// both select by priority.
    pub fn push(&mut self, pair: CandidatePair) -> usize {
        self.pairs.push(pair);
        self.pairs.len() - 1
    }

    /// RFC 8445 §7.2.5.3.3: when a pair succeeds, every `Frozen` pair with the same foundation
    /// becomes `Waiting` — that foundation is now known to work, so its siblings are worth trying.
    /// Returns how many were unfrozen.
    pub fn unfreeze_foundation(&mut self, foundation: &(String, String)) -> usize {
        let mut unfrozen = 0;
        for pair in &mut self.pairs {
            if pair.state == PairState::Frozen && pair.foundation() == *foundation {
                pair.state = PairState::Waiting;
                unfrozen += 1;
            }
        }
        unfrozen
    }

    /// The valid list (RFC 8445 §7.2.5.3.3): the pairs whose checks succeeded, **highest priority
    /// first** — the order the controlling agent nominates from (§8.1.1).
    #[must_use]
    pub fn valid(&self) -> Vec<usize> {
        let mut valid: Vec<usize> = self
            .pairs
            .iter()
            .enumerate()
            .filter(|(_, pair)| pair.state == PairState::Succeeded)
            .map(|(index, _)| index)
            .collect();
        valid.sort_by_key(|&index| std::cmp::Reverse(self.pairs[index].priority));
        valid
    }

    /// Whether every pair has settled (nothing `Frozen`, `Waiting`, or `InProgress` remains) — the
    /// condition for declaring the checklist failed when no pair is valid (RFC 8445 §8.1.2).
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.pairs
            .iter()
            .all(|pair| matches!(pair.state, PairState::Succeeded | PairState::Failed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::{CandidateKind, Transport};

    fn candidate(
        address: &str,
        kind: CandidateKind,
        component: u16,
        foundation: &str,
    ) -> Candidate {
        let address: SocketAddr = address.parse().expect("addr");
        Candidate {
            foundation: foundation.to_string(),
            ..Candidate::new(String::new(), component, address, kind, 65535)
        }
    }

    fn host(address: &str) -> Candidate {
        candidate(address, CandidateKind::Host, 1, "h")
    }

    #[test]
    fn pair_priority_matches_the_rfc_8445_formula() {
        // §6.1.2.3 with G = controlling, D = controlled. Both agents must agree on the number, so
        // the same pair computed from either side is identical.
        let (ours, theirs) = (2_130_706_431u32, 1_694_498_815u32);
        let as_controlling = pair_priority(ours, theirs, true);
        let as_controlled = pair_priority(theirs, ours, false);
        assert_eq!(
            as_controlling, as_controlled,
            "both agents compute the same pair priority"
        );

        // Known value: 2^32*MIN + 2*MAX + (G>D).
        let expected = (1u64 << 32) * u64::from(theirs) + 2 * u64::from(ours) + 1;
        assert_eq!(as_controlling, expected);

        // The tie-break bit is the only difference when the priorities are equal.
        assert_eq!(pair_priority(5, 5, true), pair_priority(5, 5, false));
    }

    #[test]
    fn pairs_are_formed_only_within_a_component_and_family() {
        let local = vec![
            host("192.0.2.1:1000"),
            candidate("[2001:db8::1]:1000", CandidateKind::Host, 1, "h6"),
            candidate("192.0.2.1:1001", CandidateKind::Host, 2, "h2"),
        ];
        let remote = vec![
            host("198.51.100.1:2000"),
            candidate("[2001:db8::2]:2000", CandidateKind::Host, 1, "r6"),
            candidate("198.51.100.1:2001", CandidateKind::Host, 2, "r2"),
        ];
        let checklist = Checklist::form(&local, &remote, true);
        // v4/c1, v6/c1, v4/c2 — never a cross-family or cross-component pair (§6.1.2.2).
        assert_eq!(checklist.len(), 3);
        for pair in checklist.pairs() {
            assert_eq!(pair.local.component, pair.remote.component);
            assert_eq!(pair.local.address.is_ipv4(), pair.remote.address.is_ipv4());
        }
    }

    #[test]
    fn a_tcp_candidate_is_never_paired() {
        // The agent is UDP-only; an RFC 6544 peer's TCP candidate parses but must not enter a pair.
        let mut tcp = host("198.51.100.1:2000");
        tcp.transport = Transport::Other("TCP".into());
        let checklist = Checklist::form(&[host("192.0.2.1:1000")], &[tcp], true);
        assert!(checklist.is_empty());
    }

    #[test]
    fn a_reflexive_local_candidate_is_paired_from_its_base_and_the_redundant_pair_dropped() {
        // §6.1.2.4: checks leave from the base either way, so the srflx pair collapses onto the host
        // pair. Keeping both would double every check for one path.
        let base = "192.0.2.1:1000";
        let mut reflexive = candidate("203.0.113.9:40000", CandidateKind::ServerReflexive, 1, "s");
        reflexive.related = Some(base.parse().expect("addr"));
        let checklist =
            Checklist::form(&[host(base), reflexive], &[host("198.51.100.1:2000")], true);
        assert_eq!(checklist.len(), 1, "one pair, not two");
        assert_eq!(
            checklist.pairs()[0].local.address,
            base.parse::<SocketAddr>().expect("addr"),
            "paired from the base"
        );
        assert_eq!(
            checklist.pairs()[0].local.kind,
            CandidateKind::Host,
            "the higher-priority (host) pair is the survivor"
        );
    }

    #[test]
    fn the_checklist_is_ordered_by_priority() {
        let low = candidate("192.0.2.1:1000", CandidateKind::Relayed, 1, "a");
        let high = candidate("192.0.2.2:1000", CandidateKind::Host, 1, "b");
        let checklist = Checklist::form(&[low, high], &[host("198.51.100.1:2000")], true);
        assert!(checklist.pairs()[0].priority > checklist.pairs()[1].priority);
        assert_eq!(checklist.pairs()[0].local.kind, CandidateKind::Host);
    }

    #[test]
    fn one_pair_per_foundation_starts_waiting_and_the_rest_frozen() {
        // §6.1.2.6: the frozen algorithm. Two foundations ⇒ exactly two Waiting pairs, whatever the
        // total pair count.
        let local = vec![
            candidate("192.0.2.1:1000", CandidateKind::Host, 1, "f1"),
            candidate("192.0.2.2:1000", CandidateKind::Host, 1, "f2"),
        ];
        let remote = vec![
            candidate("198.51.100.1:2000", CandidateKind::Host, 1, "r1"),
            candidate("198.51.100.2:2000", CandidateKind::Host, 1, "r1"),
        ];
        let checklist = Checklist::form(&local, &remote, true);
        assert_eq!(checklist.len(), 4);
        let waiting = checklist
            .pairs()
            .iter()
            .filter(|pair| pair.state == PairState::Waiting)
            .count();
        assert_eq!(waiting, 2, "one per distinct foundation pair");
        assert_eq!(
            checklist
                .pairs()
                .iter()
                .filter(|pair| pair.state == PairState::Frozen)
                .count(),
            2
        );
        // And the next check is the highest-priority waiting pair.
        let next = checklist.next_waiting().expect("a waiting pair");
        assert_eq!(checklist.pairs()[next].state, PairState::Waiting);
    }

    #[test]
    fn a_succeeding_pair_unfreezes_its_foundation_siblings() {
        let local = vec![
            candidate("192.0.2.1:1000", CandidateKind::Host, 1, "f1"),
            candidate("192.0.2.2:1000", CandidateKind::Host, 1, "f1"),
        ];
        let mut checklist = Checklist::form(&local, &[host("198.51.100.1:2000")], true);
        // Same local foundation and the same remote ⇒ one foundation ⇒ one Waiting, one Frozen.
        assert_eq!(checklist.len(), 2);
        let foundation = checklist.pairs()[0].foundation();
        assert_eq!(checklist.unfreeze_foundation(&foundation), 1);
        assert!(checklist
            .pairs()
            .iter()
            .all(|pair| pair.state != PairState::Frozen));
        // Unfreezing again is a no-op — nothing frozen is left.
        assert_eq!(checklist.unfreeze_foundation(&foundation), 0);
    }

    #[test]
    fn exhaustion_and_the_valid_list_track_pair_states() {
        let mut checklist = Checklist::form(
            &[host("192.0.2.1:1000")],
            &[host("198.51.100.1:2000")],
            true,
        );
        assert!(!checklist.is_exhausted());
        assert!(checklist.valid().is_empty());

        checklist.pairs_mut()[0].state = PairState::Succeeded;
        assert!(checklist.is_exhausted());
        assert_eq!(checklist.valid(), vec![0]);

        checklist.pairs_mut()[0].state = PairState::Failed;
        assert!(checklist.is_exhausted(), "failed also counts as settled");
        assert!(checklist.valid().is_empty());
    }

    #[test]
    fn a_discovered_pair_is_appended_but_still_ordered_where_it_matters() {
        let mut checklist = Checklist::form(
            &[host("192.0.2.1:1000")],
            &[host("198.51.100.1:2000")],
            true,
        );
        // A peer-reflexive discovery with a *higher* priority is appended (indices stay stable for
        // the agent's outstanding checks) but still wins the next-check selection.
        let mut remote = candidate("203.0.113.7:5000", CandidateKind::PeerReflexive, 1, "prflx");
        remote.priority = u32::MAX;
        let mut pair = CandidatePair::new(host("192.0.2.1:1000"), remote, true);
        pair.state = PairState::Waiting;
        let index = checklist.push(pair);
        assert_eq!(index, 1, "appended, not spliced");
        assert_eq!(
            checklist.next_waiting(),
            Some(1),
            "but selection is by priority, not position"
        );

        // The valid list is priority-ordered too — that is the order nomination picks from.
        checklist.pairs_mut()[0].state = PairState::Succeeded;
        checklist.pairs_mut()[1].state = PairState::Succeeded;
        assert_eq!(checklist.valid(), vec![1, 0]);
    }

    #[test]
    fn finding_a_pair_by_its_transport_addresses() {
        let checklist = Checklist::form(
            &[host("192.0.2.1:1000")],
            &[host("198.51.100.1:2000")],
            true,
        );
        let local: SocketAddr = "192.0.2.1:1000".parse().expect("addr");
        let remote: SocketAddr = "198.51.100.1:2000".parse().expect("addr");
        assert_eq!(checklist.find(local, remote), Some(0));
        assert_eq!(
            checklist.find(local, "203.0.113.1:1".parse().expect("a")),
            None
        );
    }
}
