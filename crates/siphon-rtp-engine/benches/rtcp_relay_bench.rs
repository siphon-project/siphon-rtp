#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

//! The per-datagram cost of the userspace RTCP relay a kernel-relayed MCPTT floor call pays for its
//! audio RTCP (RFC 3550 §6): source gate, APP-packet scan and `rtcp_app` event, telemetry offer and
//! the relayed copy, with no sockets (the datapath transmit is the backend's cost, not this one's).
//! RTP never takes this path. Two arms: a plain sender report (the common compound, nothing to
//! report) and a sender report carrying a Floor Request APP packet (one event: owned strings and a
//! payload the controller keeps).

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::app_events::AppEventQueue;
use siphon_rtp_engine::media_pipeline::RtcpRelay;
use siphon_rtp_engine::metrics::Metrics;
use siphon_rtp_engine::rtcp_relay::{RtcpRelayCall, RtcpRelayLeg};

/// TS 24.380 §8.2.4 Floor Request APP packet.
const FLOOR_REQUEST: [u8; 16] = [
    0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05, 0x00,
];

fn sender_report() -> Vec<u8> {
    let mut packet = vec![0x80, 200, 0x00, 0x06, 0, 0, 0, 1];
    packet.extend_from_slice(&[0u8; 20]);
    packet
}

fn relay_benches(criterion: &mut Criterion) {
    let near: SocketAddr = "127.0.0.2:5001".parse().unwrap();
    let far: SocketAddr = "127.0.0.3:5001".parse().unwrap();
    let queue = AppEventQueue::new(4096, Arc::new(Metrics::new()));
    let events = queue.receiver();
    let relay = RtcpRelayCall::new(
        "bench-call",
        vec![RtcpRelayLeg::new(
            RtcpRelay::new(
                EndpointId(1),
                SourceFilter::Exact(near.ip()),
                EndpointId(2),
                far,
            ),
            "tag-a",
        )],
        Some(queue),
    );
    let datapath = UdpLoopbackDatapath::new();
    let report = sender_report();
    let mut with_app = report.clone();
    with_app.extend_from_slice(&FLOOR_REQUEST);

    let mut group = criterion.benchmark_group("rtcp_relay");
    for (name, data) in [
        ("sender_report", report),
        ("sender_report_with_app", with_app),
    ] {
        let packet = RxPacket {
            endpoint: EndpointId(1),
            source: near,
            arrival: 0,
            data: Bytes::from(data),
        };
        let mut out = Vec::with_capacity(1);
        group.bench_function(name, |bencher| {
            bencher.iter(|| {
                out.clear();
                black_box(relay.process(&datapath, black_box(&packet), &mut out));
                // The controller drains its queue; keep it from filling and shedding.
                while events.try_recv().is_ok() {}
            });
        });
    }
    group.finish();
}

criterion_group!(benches, relay_benches);
criterion_main!(benches);
