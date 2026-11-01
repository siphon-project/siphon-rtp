//! Criterion perf gate for the UDP-loopback datapath's per-packet dispatch.
//! `cargo bench -p siphon-rtp-datapath`.
//!
//! Two things are measured, because they answer two different questions:
//!
//! * **`redirect_*` / `forward_relay`** — datagrams all the way through the receive loop,
//!   [`FlowAction`] dispatch and delivery, reported per packet over a burst of
//!   [`BURST`] so one scheduler wakeup is amortised rather than measured. This is the real
//!   per-packet cost, syscalls included, so it says what a dispatch change is worth *in
//!   proportion*. It is loopback-socket bound and drifts several percent run to run — read it for
//!   scale, not as a tight gate.
//! * **`ice_gate_*`** — the layer-4 ICE gate's map lookups in isolation
//!   (`docs/security-and-nat.md` §4 layer 4). [`Datapath::ice_validated_source`] performs exactly
//!   the lookups the gate performs — `ice.contains_key`, then `latched.get` only when that hit — so
//!   it isolates what the `Redirect` arm newly pays per packet from the syscall noise above it.
//!   This is the number to gate on.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use std::net::{Ipv4Addr, SocketAddr};

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::{
    Datapath, Endpoint, FlowAction, ForwardRule, IceConfig, LatchPolicy, SourceFilter,
};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;

/// Datagrams pushed through the loop per measured iteration. A single round trip is one scheduler
/// wakeup and measures the reactor more than the dispatch; a burst amortises that. Kept well under
/// the socket's default receive buffer so the sender never blocks mid-burst.
const BURST: usize = 32;

/// A G.711 µ-law RTP packet: 12-byte header + 160-byte (20 ms @ 8 kHz) payload.
fn sample_packet() -> Vec<u8> {
    let mut packet = vec![0x80, 0x00, 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4];
    packet.extend_from_slice(&[0xABu8; 160]);
    packet
}

async fn phone() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind peer socket");
    let addr = socket.local_addr().expect("peer address");
    (socket, addr)
}

/// Install ICE credentials on `endpoint` and adopt `source` as the check-validated media path, the
/// same write the STUN responder performs (`Datapath::adopt_source`).
fn arm_ice(datapath: &UdpLoopbackDatapath, endpoint: &Endpoint, source: SocketAddr) {
    datapath.set_ice(
        endpoint.id,
        Some(IceConfig {
            local_ufrag: "ENG".to_string(),
            local_pwd: "engpass".to_string(),
        }),
    );
    datapath.adopt_source(endpoint.id, source);
}

fn bench_dispatch(criterion: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let packet = sample_packet();

    // --- Redirect, no ICE: the plain userspace slow path (TURN relay, WS takeover, a promoted
    // non-ICE call). Pays one `ice.contains_key` miss and nothing else.
    let (datapath, endpoint, peer) = runtime.block_on(async {
        let datapath = UdpLoopbackDatapath::new();
        let endpoint = datapath.alloc_endpoint().await.expect("alloc");
        datapath
            .install_flow(endpoint.id, FlowAction::Redirect)
            .expect("redirect flow");
        let (peer, _) = phone().await;
        (datapath, endpoint, peer)
    });
    let receiver = datapath.rx();
    let mut group = criterion.benchmark_group("datapath_dispatch");
    group.throughput(Throughput::Elements(BURST as u64));
    group.bench_function("redirect_non_ice_160", |bencher| {
        bencher.iter(|| {
            runtime.block_on(async {
                for _ in 0..BURST {
                    peer.send_to(black_box(&packet), endpoint.local_addr)
                        .await
                        .expect("send");
                }
                for _ in 0..BURST {
                    black_box(receiver.recv_async().await.expect("redirected packet"));
                }
            });
        });
    });

    // --- Redirect on an ICE endpoint whose source a connectivity check validated: the gate hits
    // both maps and accepts. This is the worst case the change adds.
    let (ice_datapath, ice_endpoint, ice_peer) = runtime.block_on(async {
        let datapath = UdpLoopbackDatapath::new();
        let endpoint = datapath.alloc_endpoint().await.expect("alloc");
        datapath
            .install_flow(endpoint.id, FlowAction::Redirect)
            .expect("redirect flow");
        let (peer, peer_addr) = phone().await;
        arm_ice(&datapath, &endpoint, peer_addr);
        (datapath, endpoint, peer)
    });
    let ice_receiver = ice_datapath.rx();
    group.bench_function("redirect_ice_validated_160", |bencher| {
        bencher.iter(|| {
            runtime.block_on(async {
                for _ in 0..BURST {
                    ice_peer
                        .send_to(black_box(&packet), ice_endpoint.local_addr)
                        .await
                        .expect("send");
                }
                for _ in 0..BURST {
                    black_box(ice_receiver.recv_async().await.expect("redirected packet"));
                }
            });
        });
    });

    // --- The relay path, for scale: parse-free forward out the peer endpoint's socket.
    let (relay_datapath, relay_in, relay_peer, relay_out_socket) = runtime.block_on(async {
        let datapath = UdpLoopbackDatapath::new();
        let ingress = datapath.alloc_endpoint().await.expect("alloc ingress");
        let egress = datapath.alloc_endpoint().await.expect("alloc egress");
        let (peer, peer_addr) = phone().await;
        let (far, far_addr) = phone().await;
        datapath
            .install_flow(
                ingress.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: egress.id,
                    out_dst: Some(far_addr),
                    accepted_source: SourceFilter::Exact(peer_addr.ip()),
                    latch: LatchPolicy::SignalledOnly,
                    rtcp_to_userspace: false,
                }),
            )
            .expect("forward flow");
        (datapath, ingress, peer, far)
    });
    let _ = &relay_datapath;
    group.bench_function("forward_relay_160", |bencher| {
        bencher.iter(|| {
            runtime.block_on(async {
                let mut scratch = [0u8; 2048];
                for _ in 0..BURST {
                    relay_peer
                        .send_to(black_box(&packet), relay_in.local_addr)
                        .await
                        .expect("send");
                }
                for _ in 0..BURST {
                    black_box(
                        relay_out_socket
                            .recv_from(&mut scratch)
                            .await
                            .expect("relayed packet"),
                    );
                }
            });
        });
    });
    // --- The same relay with the far peer behind a TURN allocation: the egress is ChannelData-wrapped
    // and addressed to the server (RFC 8656 §12). The extra cost over `forward_relay_160` is the
    // wrap; with no allocation installed the check itself is one relaxed atomic load.
    let (turn_datapath, turn_in, turn_peer, turn_server) = runtime.block_on(async {
        let datapath = UdpLoopbackDatapath::new();
        let ingress = datapath.alloc_endpoint().await.expect("alloc ingress");
        let egress = datapath.alloc_endpoint().await.expect("alloc egress");
        let (peer, peer_addr) = phone().await;
        let (server, server_addr) = phone().await;
        let far_addr: SocketAddr = (Ipv4Addr::new(192, 0, 2, 7), 4000).into();
        datapath.set_turn_relay(
            egress.id,
            Some(siphon_rtp_datapath::TurnRelay {
                carrier: siphon_rtp_datapath::TurnCarrier::Udp,
                server: server_addr,
                channels: vec![(far_addr, 0x4001)],
                permitted: vec![far_addr],
            }),
        );
        datapath
            .install_flow(
                ingress.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: egress.id,
                    out_dst: Some(far_addr),
                    accepted_source: SourceFilter::Exact(peer_addr.ip()),
                    latch: LatchPolicy::SignalledOnly,
                    rtcp_to_userspace: false,
                }),
            )
            .expect("forward flow");
        (datapath, ingress, peer, server)
    });
    let _ = &turn_datapath;
    group.bench_function("forward_relay_turn_channel_160", |bencher| {
        bencher.iter(|| {
            runtime.block_on(async {
                let mut scratch = [0u8; 2048];
                for _ in 0..BURST {
                    turn_peer
                        .send_to(black_box(&packet), turn_in.local_addr)
                        .await
                        .expect("send");
                }
                for _ in 0..BURST {
                    black_box(
                        turn_server
                            .recv_from(&mut scratch)
                            .await
                            .expect("wrapped packet"),
                    );
                }
            });
        });
    });
    // --- The same relay with the TURN allocation on a TCP/TLS stream: the egress is ChannelData
    // padded to four bytes (RFC 8656 §12.5) and queued for the engine's stream task instead of
    // being sent from the socket, so there is no egress syscall at all; what is measured is the
    // wrap, the bounded-queue push and the ingress.
    let (stream_datapath, stream_in, stream_peer, stream_queue) = runtime.block_on(async {
        let datapath = UdpLoopbackDatapath::new();
        let ingress = datapath.alloc_endpoint().await.expect("alloc ingress");
        let egress = datapath.alloc_endpoint().await.expect("alloc egress");
        let (peer, peer_addr) = phone().await;
        let far_addr: SocketAddr = (Ipv4Addr::new(192, 0, 2, 7), 4000).into();
        let (queue_tx, queue_rx) = flume::bounded(256);
        datapath.set_turn_relay(
            egress.id,
            Some(siphon_rtp_datapath::TurnRelay {
                carrier: siphon_rtp_datapath::TurnCarrier::Stream(queue_tx),
                server: (Ipv4Addr::new(192, 0, 2, 1), 3478).into(),
                channels: vec![(far_addr, 0x4001)],
                permitted: vec![far_addr],
            }),
        );
        datapath
            .install_flow(
                ingress.id,
                FlowAction::Forward(ForwardRule {
                    out_endpoint: egress.id,
                    out_dst: Some(far_addr),
                    accepted_source: SourceFilter::Exact(peer_addr.ip()),
                    latch: LatchPolicy::SignalledOnly,
                    rtcp_to_userspace: false,
                }),
            )
            .expect("forward flow");
        (datapath, ingress, peer, queue_rx)
    });
    let _ = &stream_datapath;
    group.bench_function("forward_relay_turn_stream_160", |bencher| {
        bencher.iter(|| {
            runtime.block_on(async {
                for _ in 0..BURST {
                    stream_peer
                        .send_to(black_box(&packet), stream_in.local_addr)
                        .await
                        .expect("send");
                }
                for _ in 0..BURST {
                    black_box(stream_queue.recv_async().await.expect("queued frame"));
                }
            });
        });
    });
    group.finish();

    // --- The gate's own lookups, isolated from the syscalls above.
    criterion.bench_function("ice_gate_non_ice_miss", |bencher| {
        bencher.iter(|| black_box(datapath.ice_validated_source(black_box(endpoint.id))));
    });
    criterion.bench_function("ice_gate_validated_hit", |bencher| {
        bencher.iter(|| black_box(ice_datapath.ice_validated_source(black_box(ice_endpoint.id))));
    });
}

criterion_group!(benches, bench_dispatch);
criterion_main!(benches);
