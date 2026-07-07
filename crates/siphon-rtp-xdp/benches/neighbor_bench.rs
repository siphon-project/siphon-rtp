//! Microbench for the per-TX-frame cost the next-hop MAC resolver adds to the AF_XDP TX path.
//!
//! The busy-poll datapath thread pays exactly one [`NeighborResolver::resolve`] per outbound frame.
//! In steady state (neighbour already resolved) that is a synchronous, allocation-free cache read;
//! this bench measures it in nanoseconds so a regression is caught by the CI perf gate. The cold /
//! unresolved path deliberately does no netlink here — it just enqueues and returns `Pending` — so it
//! is not the steady-state cost and is not benched.

use std::net::Ipv4Addr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_xdp::neighbor::{NeighborResolver, ResolverConfig};

fn resolved_cache_hit(criterion: &mut Criterion) {
    let resolver = NeighborResolver::new(ResolverConfig::default());
    let destination = Ipv4Addr::new(203, 0, 113, 5);
    let next_hop = Ipv4Addr::new(198, 51, 100, 1);
    resolver.set_now(100);
    // Pin a fully-resolved entry so every `resolve` is the steady-state hit path.
    resolver.insert_resolved(
        destination,
        next_hop,
        7,
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        100,
    );

    criterion.bench_function("neighbor_resolve_cache_hit", |bencher| {
        bencher.iter(|| black_box(resolver.resolve(black_box(destination))));
    });
}

criterion_group!(benches, resolved_cache_hit);
criterion_main!(benches);
