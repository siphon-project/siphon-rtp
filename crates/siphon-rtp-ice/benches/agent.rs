//! Criterion benches for the ICE agent — per-call-setup and per-check cost.
//!
//! Checklist formation is paid once per ICE leg and grows with the product of the candidate sets, so
//! it is benched at a realistic worst case (8 local × 8 remote). Check construction and inbound
//! request processing are paid per connectivity check, which on a busy box is per call times the
//! checklist size.

use std::net::SocketAddr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_ice::{
    agent::{AgentConfig, Credentials, IceAgent},
    Candidate, CandidateKind, Checklist,
};
use siphon_rtp_stun as stun;

fn candidates(base_port: u16, octet: u8, count: usize) -> Vec<Candidate> {
    (0..count)
        .map(|index| {
            let address: SocketAddr = format!("192.0.2.{octet}:{}", base_port + index as u16)
                .parse()
                .expect("addr");
            Candidate {
                foundation: format!("f{index}"),
                ..Candidate::new(String::new(), 1, address, CandidateKind::Host, 65535)
            }
        })
        .collect()
}

fn benchmark(criterion: &mut Criterion) {
    let local = candidates(40000, 1, 8);
    let remote = candidates(50000, 2, 8);

    criterion.bench_function("checklist_form_8x8", |bencher| {
        bencher.iter(|| Checklist::form(black_box(&local), black_box(&remote), true));
    });

    let config = AgentConfig::new(
        Credentials::new("LOCALUF", "localpasswordlocalpass"),
        Credentials::new("PEERUF", "peerpasswordpeerpasswo"),
        true,
        1,
    )
    .with_candidates(local.clone(), remote.clone());

    criterion.bench_function("agent_new_8x8", |bencher| {
        bencher.iter(|| IceAgent::new(black_box(config.clone()), 0));
    });

    criterion.bench_function("agent_build_check", |bencher| {
        bencher.iter_batched(
            || IceAgent::new(config.clone(), 0),
            |mut agent| agent.poll(black_box(0)),
            criterion::BatchSize::SmallInput,
        );
    });

    // An inbound connectivity check: authenticate, answer, and run the §7.3 path.
    let check = stun::client::binding_request_ice(
        &[3u8; 12],
        "LOCALUF:PEERUF",
        b"localpasswordlocalpass",
        2_130_706_431,
        stun::client::IceRole::Controlled(7),
        false,
    );
    let local_addr: SocketAddr = "192.0.2.1:40000".parse().expect("addr");
    let peer: SocketAddr = "192.0.2.2:50000".parse().expect("addr");
    criterion.bench_function("agent_process_inbound_check", |bencher| {
        bencher.iter_batched(
            || IceAgent::new(config.clone(), 0),
            |mut agent| {
                agent.on_datagram(black_box(local_addr), black_box(peer), black_box(&check), 0)
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
