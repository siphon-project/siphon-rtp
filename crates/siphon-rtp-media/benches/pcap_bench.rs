//! Criterion perf gate for the raw-RTP pcap recorder (`cargo bench -p siphon-rtp-media`).
//!
//! The per-packet recording cost: wrap one accepted RTP datagram in synthetic Ethernet + IPv4/IPv6 +
//! UDP headers (with checksums) plus the libpcap record header — the work the recording drain task
//! does per captured packet. Reported as ns/packet. The actor-side capture cost (a `Bytes` clone + a
//! bounded `try_send`) is off this path and amortized by the fork/relay benches; framing runs in the
//! engine's drain task, never on the media reactor.

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_media::pcap::{frame, CapturedPacket};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A typical 172-byte µ-law RTP-over-UDP payload (12-byte RTP header + 160-byte frame).
fn rtp_payload() -> Bytes {
    let mut packet = vec![0x80, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0xA0, 0xDE, 0xAD, 0xBE, 0xEF];
    packet.extend_from_slice(&[0x7F; 160]);
    Bytes::from(packet)
}

fn bench_pcap_frame_ipv4(criterion: &mut Criterion) {
    let packet = CapturedPacket::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 40_000),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 7_000),
        rtp_payload(),
        1_234_567,
    );
    criterion.bench_function("pcap_frame_ipv4_172", |bencher| {
        bencher.iter(|| black_box(frame(black_box(&packet))));
    });
}

fn bench_pcap_frame_ipv6(criterion: &mut Criterion) {
    let packet = CapturedPacket::new(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 40_000),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)), 7_000),
        rtp_payload(),
        1_234_567,
    );
    criterion.bench_function("pcap_frame_ipv6_172", |bencher| {
        bencher.iter(|| black_box(frame(black_box(&packet))));
    });
}

criterion_group!(benches, bench_pcap_frame_ipv4, bench_pcap_frame_ipv6);
criterion_main!(benches);
