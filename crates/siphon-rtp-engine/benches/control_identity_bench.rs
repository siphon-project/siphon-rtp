//! The cost of resolving a control client's stable identity.
//!
//! This is a **per-connection** number, not a per-packet or per-call one: `attach_controller` runs
//! once per control connection that presents a `controller_id`, which for a healthy controller is
//! once per process and otherwise once per reconnect. The relay never resolves an identity, and a
//! call-scoped verb only reads the `ClientId` the connection already holds. It is benched anyway
//! because it is new state on the control plane, and because one arm is a rate rather than a
//! one-off: a controller *pool* sharing an identity would take `attach_evicts_previous` on every
//! connection it opened.
//!
//! The registry grows as the run proceeds — `attach_first_sight` mints a new identity per
//! iteration — so the figure already covers a populated map rather than an empty one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_engine::{ClientId, Engine};

fn identity_benches(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("control_identity");

    // First sight: the id has never been seen, so the registry mints a `ClientId` from the
    // connection's own ordinal, registers an event channel and indexes the identity both ways.
    group.bench_function("attach_first_sight", |bencher| {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let mut ordinal = 0u64;
        bencher.iter(|| {
            ordinal += 1;
            black_box(
                engine
                    .attach_controller(&format!("sbc-{ordinal}"), ClientId(ordinal))
                    .expect("mint"),
            );
        });
    });

    // A second connection claiming an identity that is already attached: resolve to the existing
    // `ClientId`, re-register over the same channel, and trip the connection being superseded.
    // Every iteration after the first takes the eviction path.
    group.bench_function("attach_evicts_previous", |bencher| {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let mut ordinal = 0u64;
        bencher.iter(|| {
            ordinal += 1;
            black_box(
                engine
                    .attach_controller("sbc-shared", ClientId(ordinal))
                    .expect("resolve"),
            );
        });
    });

    // The whole per-connection lifecycle of an identity that owns no calls: claim it, then release
    // it — which finds nothing left to re-attach to and drops the row and its channel. The reap is
    // what keeps a control plane reachable without a secret from retaining a row per identity it is
    // ever shown.
    group.bench_function("attach_then_detach_and_reap", |bencher| {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let mut ordinal = 0u64;
        bencher.iter(|| {
            ordinal += 1;
            let identity = format!("sbc-{ordinal}");
            let attachment = engine
                .attach_controller(&identity, ClientId(ordinal))
                .expect("mint");
            engine.deregister_client(attachment.client, attachment.generation);
            engine.detach_controller(&identity, attachment.generation);
            black_box(attachment.client);
        });
    });

    group.finish();
}

criterion_group!(benches, identity_benches);
criterion_main!(benches);
