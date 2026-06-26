//! Criterion benches for the TURN hot paths, reported as ns/op.
//!
//! `cargo bench -p siphon-rtp-turn`
//!
//! The per-packet relay path (ChannelData framing) and the per-request auth path (the long-term
//! credential key + the stateless nonce) are what scale with traffic, so they are the numbers to
//! watch for regressions. The codec/crypto here is pure and synchronous; the async actor dispatch
//! around it is not benched (it is dominated by the socket I/O it wraps).

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use siphon_rtp_stun::{self as stun, turn};

/// A 160-byte payload — a 20 ms G.711 frame, the canonical relayed packet size.
const FRAME: [u8; 160] = [0x42; 160];

fn channel_data_framing(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("turn/channel_data");
    group.throughput(Throughput::Bytes(FRAME.len() as u64));
    group.bench_function("encode", |bencher| {
        bencher.iter(|| turn::encode_channel_data(black_box(0x4001), black_box(&FRAME), false));
    });
    let frame = turn::encode_channel_data(0x4001, &FRAME, false);
    group.bench_function("parse", |bencher| {
        bencher.iter(|| turn::parse_channel_data(black_box(&frame)));
    });
    group.finish();
}

fn credentials(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("turn/credentials");
    // The REST credential derivation run on every authenticated request:
    // password = base64(HMAC-SHA1(secret, username)); key = MD5(username:realm:password).
    let secret = b"static-auth-secret";
    let username = "2000000000:webrtc-user";
    let realm = "siphon.example";
    group.bench_function("rest_key_derivation", |bencher| {
        bencher.iter(|| {
            let password = turn::base64_encode(&stun::hmac_sha1(secret, username.as_bytes()));
            turn::long_term_key(black_box(username), black_box(realm), black_box(&password))
        });
    });
    group.bench_function("md5_16b", |bencher| {
        bencher.iter(|| turn::md5(black_box(b"user:realm:password")));
    });
    group.finish();
}

fn message_build(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("turn/message");
    let key = turn::long_term_key("user", "realm", "pass");
    let relay: std::net::SocketAddr = "192.0.2.15:49152".parse().expect("addr");
    group.bench_function("allocate_success_build", |bencher| {
        bencher.iter(|| {
            stun::MessageBuilder::new(
                turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_SUCCESS),
                black_box(&[1u8; 12]),
            )
            .attribute(
                turn::ATTR_XOR_RELAYED_ADDRESS,
                &turn::xor_address_value(relay, &[1u8; 12]),
            )
            .attribute(turn::ATTR_LIFETIME, &turn::lifetime_value(600))
            .finish(Some(&key[..]), true)
        });
    });
    group.finish();
}

criterion_group!(benches, channel_data_framing, credentials, message_build);
criterion_main!(benches);
