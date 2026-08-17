//! Criterion benches for the ICE candidate layer — the per-call-setup cost of the offer/answer path.
//!
//! Every ICE offer and answer parses the peer's candidate list and formats our own, so this is on the
//! call-setup hot path even though it never touches a media packet. Both directions are measured,
//! plus the priority/foundation arithmetic that gathering will run once per candidate.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_ice::{priority, Candidate, CandidateKind, Transport};

const HOST: &str = "a=candidate:1 1 UDP 2130706431 203.0.113.7 30000 typ host";
const SRFLX: &str =
    "a=candidate:3 1 UDP 1694498815 198.51.100.7 45000 typ srflx raddr 10.0.0.5 rport 45000";

fn benchmark(criterion: &mut Criterion) {
    criterion.bench_function("candidate_parse_host", |bencher| {
        bencher.iter(|| Candidate::parse(black_box(HOST)).expect("parses"));
    });

    criterion.bench_function("candidate_parse_srflx_with_raddr", |bencher| {
        bencher.iter(|| Candidate::parse(black_box(SRFLX)).expect("parses"));
    });

    let candidate = Candidate::parse(SRFLX).expect("parses");
    criterion.bench_function("candidate_format", |bencher| {
        bencher.iter(|| black_box(&candidate).to_attribute_line());
    });

    let base = "192.0.2.1".parse().expect("ip");
    criterion.bench_function("candidate_foundation", |bencher| {
        bencher.iter(|| {
            Candidate::compute_foundation(
                black_box(CandidateKind::Host),
                black_box(base),
                &Transport::Udp,
                None,
            )
        });
    });

    criterion.bench_function("candidate_priority", |bencher| {
        bencher.iter(|| priority(black_box(126), black_box(65535), black_box(1)));
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
