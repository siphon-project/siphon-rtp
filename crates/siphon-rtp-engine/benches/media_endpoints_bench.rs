//! The per-packet cost of the TURN own-media-endpoint check
//! ([`MediaEndpointRegistry`]): the sharded-map read the built-in TURN server runs for every relayed
//! packet whose peer is in the denied loopback or private range, against a registry holding a busy
//! node's worth of endpoints.
//!
//! `cargo bench -p siphon-rtp --bench media_endpoints_bench`

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use std::net::SocketAddr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_datapath::{Endpoint, EndpointId};
use siphon_rtp_engine::media_endpoints::MediaEndpointRegistry;
use siphon_rtp_turn::OwnMediaEndpoints;

/// 20 000 live endpoints: 10 000 calls with an RTP and an RTCP port each.
const ENDPOINTS: u16 = 20_000;

fn registry() -> MediaEndpointRegistry {
    let registry = MediaEndpointRegistry::new();
    for index in 0..ENDPOINTS {
        registry.register(Endpoint {
            id: EndpointId(u64::from(index)),
            local_addr: SocketAddr::from(([192, 0, 2, 10], 10_000 + index)),
        });
    }
    registry
}

fn liveness_check(criterion: &mut Criterion) {
    let registry = registry();
    let live: SocketAddr = "192.0.2.10:20000".parse().expect("address");
    let dead_port: SocketAddr = "192.0.2.10:9000".parse().expect("address");
    let other_ip: SocketAddr = "192.0.2.99:20000".parse().expect("address");
    let mut group = criterion.benchmark_group("turn_own_endpoints/is_live_media_endpoint");
    group.bench_function("live", |bencher| {
        bencher.iter(|| registry.is_live_media_endpoint(black_box(live)));
    });
    group.bench_function("dead_port_same_ip", |bencher| {
        bencher.iter(|| registry.is_live_media_endpoint(black_box(dead_port)));
    });
    group.bench_function("unknown_ip", |bencher| {
        bencher.iter(|| registry.is_live_media_endpoint(black_box(other_ip)));
    });
    group.finish();
}

fn host_check(criterion: &mut Criterion) {
    let registry = registry();
    let ip = "192.0.2.10".parse().expect("ip");
    criterion.bench_function("turn_own_endpoints/hosts_media_on", |bencher| {
        bencher.iter(|| registry.hosts_media_on(black_box(ip)));
    });
}

criterion_group!(benches, liveness_check, host_check);
criterion_main!(benches);
