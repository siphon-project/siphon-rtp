//! Criterion perf gate for the ICE STUN client path. `cargo bench -p siphon-rtp-stun`.
//!
//! STUN is a per-check cost, not a per-media-packet cost — an ICE connectivity check / consent
//! refresh runs at ~O(1 per few seconds) per leg, off the RTP fast path. It is benched anyway
//! (project rule: any new codec/hot path ships a criterion bench in the same change) so a
//! regression in the hand-rolled HMAC-SHA1 / CRC-32 that also backs the media SRTP path can't hide.
//!
//! Benched paths:
//!   - `binding_request_ice` — build one ICE check (PRIORITY + ICE-CONTROLLING + USERNAME + the
//!     MESSAGE-INTEGRITY HMAC-SHA1 + FINGERPRINT CRC-32): what the consent checker emits per tick.
//!   - `verify_message_integrity` — validate an inbound check's MI: the responder's per-check cost.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_stun::client::{binding_request_ice, IceRole};
use siphon_rtp_stun::verify_message_integrity;

/// A fixed transaction id and short-term key — not subscriber data.
const TRANSACTION_ID: [u8; 12] = [0x11; 12];
const KEY: &[u8] = b"VOkJxbRl1RmTxUk/WvJxBt";

fn benchmarks(criterion: &mut Criterion) {
    criterion.bench_function("binding_request_ice", |bencher| {
        bencher.iter(|| {
            binding_request_ice(
                black_box(&TRANSACTION_ID),
                black_box("peerFrag:localFrag"),
                black_box(KEY),
                black_box(0x6e00_01ff),
                black_box(IceRole::Controlling(0x932f_f9b1_5126_3b36)),
                black_box(false),
            )
        });
    });

    // Verify against a real, well-formed check (built once, then re-verified in the loop).
    let check = binding_request_ice(
        &TRANSACTION_ID,
        "peerFrag:localFrag",
        KEY,
        0x6e00_01ff,
        IceRole::Controlling(0x932f_f9b1_5126_3b36),
        false,
    );
    criterion.bench_function("verify_message_integrity", |bencher| {
        bencher.iter(|| verify_message_integrity(black_box(&check), black_box(KEY)));
    });
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
