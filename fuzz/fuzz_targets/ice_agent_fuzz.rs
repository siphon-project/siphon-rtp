#![no_main]
//! Fuzz the ICE agent's datagram ingest, which eats untrusted packets off the media socket: an ICE
//! endpoint accepts STUN from anyone who can reach the port, before any pair is validated.
//!
//! House rule: hostile input must be handled-or-ignored — never panic, never spin. This drives the
//! whole §7.2/§7.3 path (authentication, role-conflict comparison, peer-reflexive discovery,
//! transaction correlation, nomination) with arbitrary bytes and arbitrary source addresses.
//!
//! Two invariants are asserted, not just absence-of-panic:
//!   1. An agent never selects a pair without at least one valid pair to select.
//!   2. Unauthenticated input never produces a peer-reflexive candidate — otherwise anyone who can
//!      reach the port could plant a path into the checklist.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_ice::{
    agent::{AgentConfig, Credentials, IceAgent, IceState},
    Candidate, CandidateKind,
};
use std::net::SocketAddr;

fn address(text: &str) -> SocketAddr {
    text.parse().expect("static address")
}

fn host(text: &str, foundation: &str) -> Candidate {
    Candidate {
        foundation: foundation.to_string(),
        ..Candidate::new(String::new(), 1, address(text), CandidateKind::Host, 65535)
    }
}

fuzz_target!(|data: &[u8]| {
    let local = address("192.0.2.1:40000");
    let mut agent = IceAgent::new(
        AgentConfig::new(
            Credentials::new("LOCALUF", "localpasswordlocalpass"),
            Credentials::new("PEERUF", "peerpasswordpeerpasswo"),
            true,
            0x0123_4567_89ab_cdef,
        )
        .with_candidates(
            vec![host("192.0.2.1:40000", "l")],
            vec![host("198.51.100.1:50000", "r")],
        ),
        0,
    );

    // Vary the apparent source with the input, so peer-reflexive discovery is exercised too.
    let source = if data.first().copied().unwrap_or(0) % 2 == 0 {
        address("198.51.100.1:50000")
    } else {
        address("203.0.113.9:60000")
    };

    let pairs_before = agent.checklist().len();
    let _ = agent.on_datagram(local, source, data, 0);
    let _ = agent.poll(10);
    let _ = agent.on_datagram(local, source, data, 20);
    let _ = agent.poll(1_000);

    // A pair can only be selected once something is valid.
    if agent.selected_pair().is_some() {
        assert!(
            !agent.checklist().valid().is_empty(),
            "selected a pair with an empty valid list"
        );
        assert_eq!(agent.state(), IceState::Completed);
    }

    // Arbitrary bytes cannot authenticate (they would have to forge HMAC-SHA1 over our password), so
    // no peer-reflexive candidate may ever be created from them.
    assert_eq!(
        agent.checklist().len(),
        pairs_before,
        "unauthenticated input created a candidate pair"
    );
});
