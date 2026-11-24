#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

//! The per-datagram cost the first-IDR injector (RFC 6184 §8.1, `answer_local` far video) adds to a
//! plain bridge flow. Four arms through the same `SrtpBridge::handle` over the UDP loopback datapath:
//! the plain flow with no injector (the baseline the others are held to), the injector settled (what
//! the flow costs for the few hundred milliseconds between the IDR and the sweep that returns the
//! stream to the kernel), the injector armed and dropping a non-IDR slice (no send), and the
//! injector's own `admit` on a settled and on an armed flow with no sockets.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::srtp_bridge::{BridgeCallPlan, BridgeFlowPlan, SrtpBridge};
use siphon_rtp_engine::video_injector::VideoInjector;
use siphon_rtp_media::h264::ParameterSets;
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;

const SOURCE: [u8; 4] = [127, 0, 0, 2];

fn sets() -> Box<ParameterSets> {
    let mut sets = ParameterSets::new();
    sets.store(&[0x67, 0x42, 0xC0, 0x1E, 0xDA], true);
    sets.store(&[0x68, 0xCE, 0x3C, 0x80], false);
    sets
}

/// A 1200 byte H.264-sized RTP packet (PT 96).
fn video_packet(sequence: u16, marker: bool, nal: u8) -> Vec<u8> {
    let mut packet = vec![0x80, if marker { 0x80 | 96 } else { 96 }];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&90_000u32.to_be_bytes());
    packet.extend_from_slice(&0xCAFE_F00Du32.to_be_bytes());
    packet.push(nal);
    packet.resize(1200, 0xAB);
    packet
}

/// A plain flow, with `injector` on it when given, and the sink its datagrams go to.
fn flow(
    runtime: &Runtime,
    injector: Option<Arc<VideoInjector>>,
) -> (SrtpBridge<UdpLoopbackDatapath>, EndpointId, UdpSocket) {
    runtime.block_on(async {
        let datapath = UdpLoopbackDatapath::new();
        let ingress = datapath.alloc_endpoint().await.unwrap().id;
        let egress = datapath.alloc_endpoint().await.unwrap().id;
        let sink = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let bridge = SrtpBridge::new(datapath);
        bridge.register(BridgeCallPlan {
            near_leg: None,
            far_leg: None,
            flows: vec![BridgeFlowPlan {
                endpoint: ingress,
                ingress_leg: None,
                egress_leg: None,
                accepted_source: SourceFilter::Exact(SOURCE.into()),
                latch: false,
                out_endpoint: egress,
                out_dst: sink.local_addr().unwrap(),
            }],
        });
        if let Some(injector) = injector {
            assert!(bridge.attach_video_injector(ingress, injector));
        }
        (bridge, ingress, sink)
    })
}

fn injector_benches(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let source: SocketAddr = (SOURCE, 5000).into();
    let slice = video_packet(10, false, 0x41);
    let settled = || {
        let injector = Arc::new(VideoInjector::new(sets()));
        injector.admit(&video_packet(1, true, 0x65), &mut Vec::new());
        assert!(injector.is_settled());
        injector
    };

    let mut group = criterion.benchmark_group("video_injector");
    for (name, injector) in [
        ("bridge_plain_baseline", None),
        ("bridge_settled_injector", Some(settled())),
        (
            "bridge_armed_drops_a_slice",
            Some(Arc::new(VideoInjector::new(sets()))),
        ),
    ] {
        let (bridge, ingress, _sink) = flow(&runtime, injector);
        let packet = RxPacket {
            endpoint: ingress,
            source,
            arrival: 0,
            data: Bytes::from(slice.clone()),
        };
        group.bench_function(name, |bencher| {
            bencher.iter(|| runtime.block_on(bridge.handle(black_box(packet.clone()))));
        });
    }

    let mut buffer = Vec::new();
    let settled = settled();
    group.bench_function("admit_settled", |bencher| {
        bencher.iter(|| black_box(settled.admit(black_box(&slice), &mut buffer)));
    });
    let armed = VideoInjector::new(sets());
    group.bench_function("admit_armed_drops_a_slice", |bencher| {
        bencher.iter(|| black_box(armed.admit(black_box(&slice), &mut buffer)));
    });
    let idr = video_packet(11, false, 0x65);
    group.bench_function("admit_idr_writes_two_parameter_sets", |bencher| {
        bencher.iter_batched(
            || VideoInjector::new(sets()),
            |injector| black_box(injector.admit(black_box(&idr), &mut buffer)),
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, injector_benches);
criterion_main!(benches);
