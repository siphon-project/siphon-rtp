//! Criterion benches for the in-kernel `XDP_TX` relay hot path — the per-packet rewrite the eBPF
//! program does for every `action::FORWARD` datagram.
//!
//! The eBPF program itself can't be criterion-benched (it runs in the kernel), but its per-packet
//! cost *is* the [`siphon_rtp_ebpf_common::rewrite`] math: the RFC 1624 incremental IPv4 + UDP
//! checksum fixups and the RFC 3550 §8 latch decision. Benching them here tracks and regression-gates
//! that cost like every other siphon-rtp hot path (ns/packet), and asserts it is allocation-free (the
//! functions take/return scalars only). The FIB lookup and the packet-memory writes are kernel
//! helpers / DMA and are measured by the veth smoke, not here.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_ebpf_common::rewrite::{
    ipv4_checksum_after_addr_rewrite, latch_decision, udp_checksum_after_rewrite, LatchVerdict,
    Latched,
};

// Documentation-range addresses/ports only (no real subscriber data): RFC 5737 / TEST-NET.
const OLD_SRC_IP: u32 = u32::from_be_bytes([198, 51, 100, 1]);
const NEW_SRC_IP: u32 = u32::from_be_bytes([192, 0, 2, 9]);
const OLD_DST_IP: u32 = u32::from_be_bytes([203, 0, 113, 5]);
const NEW_DST_IP: u32 = u32::from_be_bytes([198, 51, 100, 42]);
const OLD_SRC_PORT: u16 = 30000;
const NEW_SRC_PORT: u16 = 40000;
const OLD_DST_PORT: u16 = 6000;
const NEW_DST_PORT: u16 = 7000;
const SSRC: u32 = 0x1122_3344;

fn ipv4_checksum(criterion: &mut Criterion) {
    criterion.bench_function("ipv4_checksum_after_addr_rewrite", |bencher| {
        bencher.iter(|| {
            ipv4_checksum_after_addr_rewrite(
                black_box(0x1234),
                black_box(OLD_SRC_IP),
                black_box(NEW_SRC_IP),
                black_box(OLD_DST_IP),
                black_box(NEW_DST_IP),
            )
        })
    });
}

fn udp_checksum(criterion: &mut Criterion) {
    criterion.bench_function("udp_checksum_after_rewrite", |bencher| {
        bencher.iter(|| {
            udp_checksum_after_rewrite(
                black_box(0xABCD),
                black_box(OLD_SRC_IP),
                black_box(NEW_SRC_IP),
                black_box(OLD_DST_IP),
                black_box(NEW_DST_IP),
                black_box(OLD_SRC_PORT),
                black_box(NEW_SRC_PORT),
                black_box(OLD_DST_PORT),
                black_box(NEW_DST_PORT),
            )
        })
    });
}

fn latch(criterion: &mut Criterion) {
    let current = Some(Latched {
        ipv4: OLD_SRC_IP,
        port: OLD_SRC_PORT,
        ssrc: SSRC,
    });
    criterion.bench_function("latch_decision_same_source", |bencher| {
        bencher.iter(|| {
            latch_decision(
                black_box(current),
                black_box(OLD_SRC_IP),
                black_box(OLD_SRC_PORT),
                black_box(Some(SSRC)),
            )
        })
    });
}

/// The full per-packet fixup a Forward datagram pays in-kernel: the latch decision plus both
/// checksum recomputations (the total scalar cost around the FIB lookup + memory writes).
fn full_forward_fixup(criterion: &mut Criterion) {
    let current = Some(Latched {
        ipv4: OLD_SRC_IP,
        port: OLD_SRC_PORT,
        ssrc: SSRC,
    });
    criterion.bench_function("forward_fixup_latch_plus_both_checksums", |bencher| {
        bencher.iter(|| {
            let verdict = latch_decision(
                black_box(current),
                black_box(OLD_SRC_IP),
                black_box(OLD_SRC_PORT),
                black_box(Some(SSRC)),
            );
            // Model the kernel path: only rewrite when the latch accepts (it does here).
            debug_assert_eq!(verdict, LatchVerdict::Forward);
            let ip = ipv4_checksum_after_addr_rewrite(
                black_box(0x1234),
                black_box(OLD_SRC_IP),
                black_box(NEW_SRC_IP),
                black_box(OLD_DST_IP),
                black_box(NEW_DST_IP),
            );
            let udp = udp_checksum_after_rewrite(
                black_box(0xABCD),
                black_box(OLD_SRC_IP),
                black_box(NEW_SRC_IP),
                black_box(OLD_DST_IP),
                black_box(NEW_DST_IP),
                black_box(OLD_SRC_PORT),
                black_box(NEW_SRC_PORT),
                black_box(OLD_DST_PORT),
                black_box(NEW_DST_PORT),
            );
            (ip, udp)
        })
    });
}

criterion_group!(
    benches,
    ipv4_checksum,
    udp_checksum,
    latch,
    full_forward_fixup
);
criterion_main!(benches);
