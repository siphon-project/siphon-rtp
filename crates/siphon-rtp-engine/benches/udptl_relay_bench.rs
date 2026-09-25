//! The per-datagram cost of relaying a T.38 fax stream over UDPTL.
//!
//! A fax runs at tens of datagrams per second against audio's fifty per second per leg, so this is
//! never going to be a capacity number. It is here because the house rule is that anything with a
//! per-packet cost ships a bench, and because the number is the evidence for the design decision
//! this path rests on: UDPTL is relayed in **userspace** (`FlowAction::Redirect`) rather than on the
//! datapath's RTP-only `Forward` fast path, and the question "what does that cost?" deserves a
//! measurement rather than an assurance.
//!
//! What is measured is the relay's own work — the layer-2 source gate, the opaque latch, and staging
//! the outbound datagram. The `send` syscall that follows is the datapath's and is measured by the
//! capacity harness, not here.
//!
//! All addresses are the RFC 5737 documentation range.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::udptl_pipeline::{UdptlCall, UdptlDirectionConfig};

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("addr")
}

const NEAR: EndpointId = EndpointId(1);
const FAR: EndpointId = EndpointId(2);

/// A relay of one fax call, each direction gated to its peer's signalled address.
fn relay(near_source: SourceFilter) -> UdptlCall {
    UdptlCall::new(
        "fax-bench".to_string(),
        UdptlDirectionConfig {
            ingress_endpoint: NEAR,
            accepted_source: near_source,
            egress_endpoint: FAR,
            egress_dst: Some(addr("203.0.113.9:5004")),
        },
        UdptlDirectionConfig {
            ingress_endpoint: FAR,
            accepted_source: SourceFilter::Exact(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
            egress_endpoint: NEAR,
            egress_dst: Some(addr("198.51.100.1:5004")),
        },
    )
}

/// A UDPTL datagram (T.38 Annex D): a 16-bit sequence number then an opaque IFP payload. `bytes` is
/// the total datagram length — a V.29 image-data frame with redundancy is a few hundred bytes, a
/// T.30 control frame a couple of dozen.
fn udptl(sequence: u16, bytes: usize, source: SocketAddr) -> RxPacket {
    let mut data = Vec::with_capacity(bytes);
    data.extend_from_slice(&sequence.to_be_bytes());
    data.resize(bytes, 0x5a);
    RxPacket {
        endpoint: NEAR,
        source,
        arrival: 0,
        data: Bytes::from(data),
    }
}

fn benches(criterion: &mut Criterion) {
    let peer = addr("198.51.100.1:5004");
    let gated = SourceFilter::Exact(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));

    let mut group = criterion.benchmark_group("udptl_relay");

    // Every datagram is built **outside** the measured loop. Building one allocates, and an
    // allocation is several times the work being measured here — a loop that constructs its own
    // input measures the constructor.
    //
    // The steady-state datagram: gate, latch already formed, stage the forward.
    for (label, bytes) in [("control_frame_32b", 32), ("image_frame_320b", 320)] {
        let mut call = relay(gated);
        let mut out = Vec::with_capacity(1);
        let packet = udptl(1, bytes, peer);
        // Form the latch outside the loop too — the first datagram is not the steady state.
        call.process(&packet, &mut out);
        out.clear();
        group.bench_function(label, |bencher| {
            bencher.iter(|| {
                out.clear();
                let accepted = call.process(black_box(&packet), &mut out);
                black_box(accepted);
            });
        });
    }

    // The drop paths, which is where a flood lands. Both must be cheaper than relaying, or refusing
    // traffic would cost more than accepting it.
    let spoofed_packet = udptl(7, 32, addr("192.0.2.66:5004"));
    let mut call = relay(gated);
    let mut out = Vec::with_capacity(1);
    group.bench_function("dropped_by_source_gate_32b", |bencher| {
        bencher.iter(|| {
            out.clear();
            let accepted = call.process(black_box(&spoofed_packet), &mut out);
            black_box(accepted);
        });
    });

    // With the gate wide open (the opt-in `symmetric` posture) the latch is the only constraint
    // left, so this is the cost of the check that keeps an SSRC-less stream from being stealable.
    let mut call = relay(SourceFilter::Any);
    let mut out = Vec::with_capacity(1);
    let latching = udptl(0, 32, peer);
    call.process(&latching, &mut out);
    out.clear();
    group.bench_function("dropped_by_latch_32b", |bencher| {
        bencher.iter(|| {
            out.clear();
            let accepted = call.process(black_box(&spoofed_packet), &mut out);
            black_box(accepted);
        });
    });

    group.finish();
}

criterion_group!(udptl_relay, benches);
criterion_main!(udptl_relay);
