//! Deterministic instruction-count gate (valgrind/callgrind) for the SRTP per-packet hot path.
//!
//! The wall-clock numbers live in `srtp_bench.rs`; this counts instructions (stable on CI) to fail on
//! a `>10%` regression. This is the surcharge a secure leg pays per packet over a plaintext leg:
//! AES-CM + HMAC-SHA1-80 on protect, verify + decrypt on unprotect (RFC 3711). Key setup and packet
//! sealing run in the `setup` fn and are not counted. See the CI `perf-gate` job.

use iai_callgrind::{
    library_benchmark, library_benchmark_group, main, Callgrind, EventKind, LibraryBenchmarkConfig,
};
use std::hint::black_box;

use siphon_rtp_srtp::kdf::MASTER_SALT_LEN;
use siphon_rtp_srtp::{SrtpContext, MASTER_KEY_LEN};

const MASTER_KEY: [u8; MASTER_KEY_LEN] = [0x11; MASTER_KEY_LEN];
const MASTER_SALT: [u8; MASTER_SALT_LEN] = [0x22; MASTER_SALT_LEN];

/// A G.711 µ-law RTP packet: V2/PT0, 12-byte header + 160-byte payload.
fn rtp_packet(seq: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    packet.extend_from_slice(&[0xABu8; 160]);
    packet
}

fn protect_setup() -> (SrtpContext, Vec<u8>, Vec<u8>) {
    (
        SrtpContext::new(&MASTER_KEY, &MASTER_SALT),
        rtp_packet(0x1234),
        Vec::with_capacity(256),
    )
}

/// A fresh receiver plus one sealed packet, so the measured `unprotect` sees a monotone (never
/// replayed) index on a clean anti-replay window.
fn unprotect_setup() -> (SrtpContext, Vec<u8>, Vec<u8>) {
    let mut sender = SrtpContext::new(&MASTER_KEY, &MASTER_SALT);
    let mut sealed = Vec::with_capacity(256);
    sender
        .protect(&rtp_packet(0x1234), &mut sealed)
        .expect("seed protect");
    (
        SrtpContext::new(&MASTER_KEY, &MASTER_SALT),
        sealed,
        Vec::with_capacity(256),
    )
}

#[library_benchmark]
#[bench::g711(setup = protect_setup)]
fn srtp_protect(input: (SrtpContext, Vec<u8>, Vec<u8>)) {
    let (mut context, plain, mut out) = input;
    context
        .protect(black_box(&plain), &mut out)
        .expect("protect");
    black_box(out.len());
}

#[library_benchmark]
#[bench::g711(setup = unprotect_setup)]
fn srtp_unprotect(input: (SrtpContext, Vec<u8>, Vec<u8>)) {
    let (mut context, sealed, mut out) = input;
    context
        .unprotect(black_box(&sealed), &mut out)
        .expect("unprotect");
    black_box(out.len());
}

library_benchmark_group!(name = srtp; benchmarks = srtp_protect, srtp_unprotect);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().soft_limits([(EventKind::Ir, 10.0)]));
    library_benchmark_groups = srtp
);
