//! Criterion perf gate for the X3 delivery framing hot path. `cargo bench -p siphon-rtp-li`.
//!
//! This is the per-packet cost the engine pays on every intercepted frame, on top of relaying it.
//! Both output buffers are caller-owned and reused across iterations, because the delivery path
//! recycles one allocation per session rather than allocating per frame — a bench that let them
//! regrow would measure the allocator instead of the framing.
//!
//! Benched paths:
//!   - `x3_frame_rtp_full` — the real per-packet shape: build the full conditional-attribute block
//!     (NFID, IPID, sequence, timestamp, source/destination address + port, IP protocol) and frame a
//!     172-byte G.711 RTP packet (12-byte header + 160-byte payload, 20 ms @ 8 kHz) around it.
//!   - `x3_attributes_only` / `x3_encode_only` — the same work split, so a regression can be
//!     attributed to the TLV writer or to the header encode rather than guessed at.
//!   - `x3_frame_rtp_ipv6` — the same full path on an IPv6 leg, where the two address attributes are
//!     16 bytes instead of 4.
//!   - `x3_timestamp` — the wall-clock anchor arithmetic alone, run once per intercepted packet.
//!   - `x3_keepalive` — the idle-connection PDU; not media-rate, but it shares the encoder.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::net::SocketAddr;

use siphon_rtp_li::attributes::{AttributeWriter, IP_PROTOCOL_UDP};
use siphon_rtp_li::clock::WallClockAnchor;
use siphon_rtp_li::{encode, PayloadDirection, PduHeader};

/// A 16-byte interception task identifier (fixed test bytes, not provisioning data).
const XID: [u8; 16] = [0x5a; 16];
/// A non-zero session correlation (clause 6).
const CORRELATION_ID: u64 = 0x0102_0304_0506_0708;
/// Operator identity attributes, sized like realistic deployment values.
const NETWORK_FUNCTION_ID: &str = "siphon-rtp-sbc-01";
const INTERCEPTION_POINT_ID: &str = "media-relay-a";

/// One G.711 frame: a 12-byte RTP header plus 160 bytes of payload, 20 ms at 8 kHz.
fn rtp_packet() -> Vec<u8> {
    let mut packet = vec![
        0x80, 0x00, 0x12, 0x34, 0x00, 0x00, 0x01, 0x40, 0xde, 0xad, 0xbe, 0xef,
    ];
    packet.extend(std::iter::repeat_n(0xd5, 160));
    packet
}

/// Build the full attribute block one intercepted packet carries.
fn write_attributes(
    out: &mut Vec<u8>,
    sequence: u32,
    anchor: &WallClockAnchor,
    arrival_micros: u64,
    source: SocketAddr,
    destination: SocketAddr,
) {
    let (seconds, nanoseconds) = anchor.timestamp(arrival_micros);
    AttributeWriter::new(out)
        .network_function_id(NETWORK_FUNCTION_ID)
        .interception_point_id(INTERCEPTION_POINT_ID)
        .sequence_number(sequence)
        .timestamp(seconds, nanoseconds)
        .source(source)
        .destination(destination)
        .ip_protocol(IP_PROTOCOL_UDP);
}

fn benchmark(criterion: &mut Criterion) {
    let packet = rtp_packet();
    let anchor = WallClockAnchor::new(1_788_177_600 * 1_000_000_000, 0);
    let header = PduHeader::x3_rtp(XID, CORRELATION_ID, PayloadDirection::FromTarget);

    let source_v4: SocketAddr = "203.0.113.9:16384".parse().expect("v4 source");
    let destination_v4: SocketAddr = "198.51.100.4:20000".parse().expect("v4 destination");
    let source_v6: SocketAddr = "[2001:db8::1]:16384".parse().expect("v6 source");
    let destination_v6: SocketAddr = "[2001:db8::2]:20000".parse().expect("v6 destination");

    // Pre-sized once and reused, exactly as the delivery path recycles them.
    let mut attributes = Vec::with_capacity(256);
    let mut pdu = Vec::with_capacity(512);

    criterion.bench_function("x3_frame_rtp_full", |bencher| {
        let mut sequence = 0u32;
        bencher.iter(|| {
            sequence = sequence.wrapping_add(1);
            write_attributes(
                &mut attributes,
                sequence,
                &anchor,
                u64::from(sequence) * 20_000,
                source_v4,
                destination_v4,
            );
            encode(
                &header,
                black_box(&attributes),
                black_box(&packet),
                &mut pdu,
            )
            .expect("frame");
            black_box(pdu.len())
        });
    });

    criterion.bench_function("x3_frame_rtp_ipv6", |bencher| {
        let mut sequence = 0u32;
        bencher.iter(|| {
            sequence = sequence.wrapping_add(1);
            write_attributes(
                &mut attributes,
                sequence,
                &anchor,
                u64::from(sequence) * 20_000,
                source_v6,
                destination_v6,
            );
            encode(
                &header,
                black_box(&attributes),
                black_box(&packet),
                &mut pdu,
            )
            .expect("frame");
            black_box(pdu.len())
        });
    });

    criterion.bench_function("x3_attributes_only", |bencher| {
        let mut sequence = 0u32;
        bencher.iter(|| {
            sequence = sequence.wrapping_add(1);
            write_attributes(
                &mut attributes,
                sequence,
                &anchor,
                u64::from(sequence) * 20_000,
                source_v4,
                destination_v4,
            );
            black_box(attributes.len())
        });
    });

    // Frame with an attribute block already built, so this isolates the 40-byte header write and
    // the two payload copies.
    write_attributes(
        &mut attributes,
        1,
        &anchor,
        20_000,
        source_v4,
        destination_v4,
    );
    criterion.bench_function("x3_encode_only", |bencher| {
        bencher.iter(|| {
            encode(
                &header,
                black_box(&attributes),
                black_box(&packet),
                &mut pdu,
            )
            .expect("frame");
            black_box(pdu.len())
        });
    });

    criterion.bench_function("x3_timestamp", |bencher| {
        let mut arrival = 0u64;
        bencher.iter(|| {
            arrival = arrival.wrapping_add(20_000);
            black_box(anchor.timestamp(black_box(arrival)))
        });
    });

    let keepalive = PduHeader::keepalive();
    criterion.bench_function("x3_keepalive", |bencher| {
        bencher.iter(|| {
            encode(&keepalive, &[], &[], &mut pdu).expect("frame");
            black_box(pdu.len())
        });
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
