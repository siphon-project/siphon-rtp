//! Criterion benches for RFC 8445 §5.1.1 candidate gathering — per-call-setup cost.
//!
//! Gathering runs once per ICE leg on the offer/answer path, so its CPU cost sits directly in call
//! setup. The host-only case is the one that matters most: it is the default deployment, it must stay
//! free of any network round trip, and it is pure computation the engine pays on every ICE call.

use std::net::SocketAddr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_ice::{gather::GatherConfig, GatherAction, Gatherer};
use siphon_rtp_stun as stun;

fn address(text: &str) -> SocketAddr {
    text.parse().expect("addr")
}

fn benchmark(criterion: &mut Criterion) {
    let base = address("192.0.2.10:40000");
    let stun_server = address("198.51.100.1:3478");

    // The default deployment: construct the plan and complete it, no I/O at all.
    criterion.bench_function("gather_host_only_complete", |bencher| {
        bencher.iter(|| {
            let mut gatherer = Gatherer::new(GatherConfig::host_only(black_box(base)), 0);
            let action = gatherer.poll(0);
            debug_assert!(matches!(action, GatherAction::Complete));
            gatherer.candidates().len()
        });
    });

    // Building one reflexive probe (transaction id + STUN encode) — what a configured STUN server
    // adds to call setup, excluding the network.
    criterion.bench_function("gather_build_reflexive_probe", |bencher| {
        bencher.iter(|| {
            let mut gatherer = Gatherer::new(
                GatherConfig::host_only(black_box(base)).with_stun_servers(vec![stun_server]),
                0,
            );
            gatherer.poll(0)
        });
    });

    // Consuming the server's response: parse, correlate, prune, and record the candidate.
    let mut primed = Gatherer::new(
        GatherConfig::host_only(base).with_stun_servers(vec![stun_server]),
        0,
    );
    let probe = match primed.poll(0) {
        GatherAction::Probe { datagram, .. } => datagram,
        other => panic!("expected a probe, got {other:?}"),
    };
    let request = stun::parse(&probe).expect("parse probe");
    let response =
        stun::binding_success_response(&request.transaction_id, address("203.0.113.5:52000"), None);
    criterion.bench_function("gather_consume_reflexive_response", |bencher| {
        bencher.iter_batched(
            || {
                let mut gatherer = Gatherer::new(
                    GatherConfig::host_only(base).with_stun_servers(vec![stun_server]),
                    0,
                );
                // Re-issue a probe so the transaction id matches the canned response.
                let _ = gatherer.poll(0);
                gatherer
            },
            |mut gatherer| gatherer.on_datagram(black_box(stun_server), black_box(&response), 10),
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
