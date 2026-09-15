//! Criterion perf gate for the **DTLS-SRTP bridge relay** — the per-packet cost of a call whose one
//! leg is keyed by a DTLS handshake and whose other leg is plain RTP (`PipelineKind::Dtls`).
//!
//! `DtlsBridge::handle` is that whole per-packet path: flow lookup → source gate → RFC 7983 demux →
//! SRTP/SRTCP (de)crypt → forward send. The points, all on one call keyed by a real handshake run
//! during setup:
//!
//! - `plain_rtp_to_secure` — plain RTP encrypted toward the DTLS peer.
//! - `secure_rtp_to_plain` — the DTLS peer's SRTP decrypted toward the plain peer.
//! - `secure_rtcp_to_plain_rtcp_port` — the DTLS peer's SRTCP decrypted onto the plain peer's
//!   separate RTCP port (RFC 5761 §5.1.1). The delta against `secure_rtp_to_plain` is the RTCP split.
//! - `plain_rtcp_port_to_secure` — plain RTCP from that port, encrypted as SRTCP.
//! - `unkeyed_drop` — SRTP arriving before any handshake has keyed the leg. It has to stay cheaper
//!   than a keyed packet: a peer that floods before the handshake must not cost more than one that
//!   completes it.
//!
//! Every accepted point includes the forward send on the loopback datapath, because that is part of
//! what one relayed packet costs. Each iteration runs `handle` to completion on a current-thread
//! runtime, so every point includes the same `block_on` and the deltas stay comparable.
//!
//! The decrypt points seal a fresh packet per iteration in `iter_batched`, outside the measurement:
//! SRTP and SRTCP replay protection (RFC 3711 §3.3, §3.4) reject a repeated index, so re-sending one
//! sealed packet would measure the replay-reject branch and report the crypto as free.
//!
//! `cargo bench -p siphon-rtp --bench dtls_bridge_bench`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::{Datapath, EndpointId, FlowAction, RxPacket, SourceFilter};
use siphon_rtp_dtls::{handshake, DtlsCertificate, DtlsChannels, DtlsRole, DtlsTransport};
use siphon_rtp_engine::dtls_bridge::{DtlsBridge, DtlsCallPlan, PlainRtcp};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// 8 kHz / 20 ms of µ-law.
const FRAME_BYTES: usize = 160;

/// A µ-law RTP packet (PT 0).
fn rtp_packet(sequence: u16, ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&[0xFFu8; FRAME_BYTES]);
    packet
}

/// An empty RTCP receiver report (RFC 3550 §6.4.2).
fn rtcp_receiver_report(ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 201, 0x00, 0x01];
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet
}

fn packet(endpoint: EndpointId, source: SocketAddr, data: Bytes) -> RxPacket {
    RxPacket {
        endpoint,
        source,
        arrival: 0,
        data,
    }
}

/// Carry the DTLS peer's handshake over its socket: datagrams in, records out to `engine_secure`.
fn pump(
    socket: Arc<UdpSocket>,
    channels: DtlsChannels,
    engine_secure: SocketAddr,
) -> (JoinHandle<()>, JoinHandle<()>) {
    let recv_socket = socket.clone();
    let inbound = channels.inbound;
    let reader = tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((len, _)) = recv_socket.recv_from(&mut buffer).await {
            if inbound
                .send_async(Bytes::copy_from_slice(&buffer[..len]))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let outbound = channels.outbound;
    let writer = tokio::spawn(async move {
        while let Ok(record) = outbound.recv_async().await {
            if socket.send_to(&record, engine_secure).await.is_err() {
                break;
            }
        }
    });
    (reader, writer)
}

fn dtls_bridge_handle(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let _guard = runtime.enter();

    let datapath = UdpLoopbackDatapath::new();
    let (plain, plain_rtcp, secure, unkeyed_plain, unkeyed_secure) = runtime.block_on(async {
        (
            datapath.alloc_endpoint().await.expect("plain"),
            datapath.alloc_endpoint().await.expect("plain rtcp"),
            datapath.alloc_endpoint().await.expect("secure"),
            datapath.alloc_endpoint().await.expect("unkeyed plain"),
            datapath.alloc_endpoint().await.expect("unkeyed secure"),
        )
    });
    // Only the handshake travels the datapath's receive path; the measured packets are handed to
    // `handle` directly.
    datapath
        .install_flow(secure.id, FlowAction::Redirect)
        .expect("redirect secure");

    let (phone_a, phone_a_rtcp, peer_b) = runtime.block_on(async {
        (
            UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
                .await
                .expect("bind a"),
            UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
                .await
                .expect("bind a rtcp"),
            Arc::new(
                UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
                    .await
                    .expect("bind b"),
            ),
        )
    });
    let addr_a = phone_a.local_addr().expect("addr a");
    let addr_a_rtcp = phone_a_rtcp.local_addr().expect("addr a rtcp");
    let addr_b = peer_b.local_addr().expect("addr b");

    let engine_cert = DtlsCertificate::generate().expect("engine cert");
    let peer_cert = DtlsCertificate::generate().expect("peer cert");
    let plan = |plain_endpoint: EndpointId, secure_endpoint: EndpointId, secure_local, rtcp| {
        DtlsCallPlan {
            plain_endpoint,
            plain_source: SourceFilter::Exact(addr_a.ip()),
            plain_dst: addr_a,
            secure_endpoint,
            secure_source: SourceFilter::Exact(addr_b.ip()),
            secure_dst: addr_b,
            secure_local,
            certificate: engine_cert.clone(),
            role: DtlsRole::Server,
            peer_fingerprint: peer_cert.fingerprint(),
            gate_on_ice: false,
            ice_validated: None,
            plain_rtcp: rtcp,
        }
    };

    let bridge = Arc::new(DtlsBridge::new(datapath.clone()));
    bridge.register(plan(
        plain.id,
        secure.id,
        secure.local_addr,
        Some(PlainRtcp {
            endpoint: plain_rtcp.id,
            source: SourceFilter::Exact(addr_a_rtcp.ip()),
            dst: addr_a_rtcp,
        }),
    ));
    // A second call that never handshakes, for the unkeyed drop.
    let unkeyed = DtlsBridge::new(datapath.clone());
    unkeyed.register(plan(
        unkeyed_plain.id,
        unkeyed_secure.id,
        unkeyed_secure.local_addr,
        None,
    ));

    let mut peer_leg = runtime.block_on(async {
        let rx = datapath.rx();
        let dispatch = bridge.clone();
        let dispatcher = tokio::spawn(async move {
            while let Ok(packet) = rx.recv_async().await {
                dispatch.handle(packet).await;
            }
        });
        let (b_transport, b_channels) = DtlsTransport::new(addr_b, secure.local_addr);
        let (reader, writer) = pump(peer_b.clone(), b_channels, secure.local_addr);
        let mut leg = handshake(
            Arc::new(b_transport),
            &peer_cert,
            DtlsRole::Client,
            &engine_cert.fingerprint(),
        )
        .await
        .expect("peer handshake");
        reader.abort();
        writer.abort();
        dispatcher.abort();

        // The engine installs its leg a moment after the peer finishes: wait until a packet relays.
        let mut buffer = [0u8; 2048];
        for sequence in 0..50u16 {
            let mut sealed = Vec::new();
            leg.protect(&rtp_packet(sequence, 0x0B0B_0B0B), &mut sealed)
                .expect("peer protect");
            bridge
                .handle(packet(secure.id, addr_b, Bytes::from(sealed)))
                .await;
            if tokio::time::timeout(Duration::from_millis(100), phone_a.recv_from(&mut buffer))
                .await
                .is_ok()
            {
                return leg;
            }
        }
        panic!("the bridge never keyed its leg");
    });

    let mut group = criterion.benchmark_group("dtls_bridge_handle");

    let mut sequence = 1_000u16;
    group.bench_function("plain_rtp_to_secure", |bencher| {
        bencher.iter_batched(
            || {
                sequence = sequence.wrapping_add(1);
                Bytes::from(rtp_packet(sequence, 0x0A0A_0A0A))
            },
            |frame| runtime.block_on(bridge.handle(black_box(packet(plain.id, addr_a, frame)))),
            BatchSize::SmallInput,
        )
    });

    let mut sequence = 1_000u16;
    group.bench_function("secure_rtp_to_plain", |bencher| {
        bencher.iter_batched(
            || {
                sequence = sequence.wrapping_add(1);
                let mut sealed = Vec::new();
                peer_leg
                    .protect(&rtp_packet(sequence, 0x0B0B_0B0B), &mut sealed)
                    .expect("peer protect rtp");
                Bytes::from(sealed)
            },
            |sealed| runtime.block_on(bridge.handle(black_box(packet(secure.id, addr_b, sealed)))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("secure_rtcp_to_plain_rtcp_port", |bencher| {
        bencher.iter_batched(
            || {
                let mut sealed = Vec::new();
                peer_leg
                    .protect(&rtcp_receiver_report(0x0B0B_0B0B), &mut sealed)
                    .expect("peer protect rtcp");
                Bytes::from(sealed)
            },
            |sealed| runtime.block_on(bridge.handle(black_box(packet(secure.id, addr_b, sealed)))),
            BatchSize::SmallInput,
        )
    });

    let report = Bytes::from(rtcp_receiver_report(0x0A0A_0A0A));
    group.bench_function("plain_rtcp_port_to_secure", |bencher| {
        bencher.iter(|| {
            runtime.block_on(bridge.handle(black_box(packet(
                plain_rtcp.id,
                addr_a_rtcp,
                report.clone(),
            ))))
        })
    });

    let unkeyed_frame = Bytes::from(rtp_packet(1, 0x0B0B_0B0B));
    group.bench_function("unkeyed_drop", |bencher| {
        bencher.iter(|| {
            runtime.block_on(unkeyed.handle(black_box(packet(
                unkeyed_secure.id,
                addr_b,
                unkeyed_frame.clone(),
            ))))
        })
    });

    group.finish();
}

criterion_group!(benches, dtls_bridge_handle);
criterion_main!(benches);
