//! Criterion perf gate for the SRTP/SRTCP per-packet hot path. `cargo bench -p siphon-rtp-srtp`.
//!
//! This is the per-channel relay cost a *secure* leg pays that a plaintext leg does not: AES-CM
//! encrypt of the payload + HMAC-SHA1-80 over `header || ciphertext || ROC` (RFC 3711 §3.3, §4).
//! Output buffers are caller-owned and reused across iterations — the protect/unprotect path must
//! not allocate per packet, so the bench pre-sizes `out` and never lets it regrow.
//!
//! Benched paths:
//!   - `srtp_protect_160` / `srtp_unprotect_160` — one G.711 frame (12-byte header + 160-byte
//!     payload, 20 ms @ 8 kHz): the dominant cost, run at 50 packets/s per stream per direction.
//!   - `srtcp_protect` / `srtcp_unprotect` — a compound RTCP SR (RFC 3711 §3.4): explicit index,
//!     8-byte header in the clear; runs at RTCP rate, not media rate, but on the same datapath.
//!   - `secure_leg_protect_rtp` / `secure_leg_unprotect_rtp` — the full leg path incl. the RFC 5761
//!     RTP/RTCP demux dispatch, i.e. what the bridge adapter actually calls per packet.
//!   - `srtp_context_new` — per-leg key setup (three RFC 3711 §4.3 KDF derives); call-setup cost,
//!     not per-packet, but tracked so a KDF regression can't hide behind the media benches.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
use siphon_rtp_srtp::srtcp::SrtcpContext;
use siphon_rtp_srtp::{kdf::MASTER_SALT_LEN, SrtpContext, MASTER_KEY_LEN};

/// A test master key (`0x11` repeated) — fixed, not subscriber data.
const MASTER_KEY: [u8; MASTER_KEY_LEN] = [0x11; MASTER_KEY_LEN];
/// A test master salt (`0x22` repeated).
const MASTER_SALT: [u8; MASTER_SALT_LEN] = [0x22; MASTER_SALT_LEN];

fn srtp_context() -> SrtpContext {
    SrtpContext::new(&MASTER_KEY, &MASTER_SALT)
}

fn srtcp_context() -> SrtcpContext {
    SrtcpContext::new(&MASTER_KEY, &MASTER_SALT)
}

/// A G.711 µ-law RTP packet: 12-byte header (V2, PT0, given seq/SSRC) + 160-byte payload.
fn rtp_packet(seq: u16, ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // timestamp
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&[0xABu8; 160]);
    packet
}

/// A compound RTCP sender report: V2, PT=200 (SR), 4-byte header + sender SSRC + 20-byte sender info.
fn rtcp_packet(ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 200, 0x00, 0x06];
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&[0x5Au8; 20]); // NTP/RTP timestamps + packet/octet counts
    packet
}

fn bench_srtp(criterion: &mut Criterion) {
    let plain = rtp_packet(0x1234, 0x0102_0304);

    criterion.bench_function("srtp_protect_160", |bencher| {
        let mut context = srtp_context();
        let mut out = Vec::with_capacity(256);
        bencher.iter(|| {
            context.protect(black_box(&plain), &mut out).expect("protect");
            black_box(out.len())
        });
    });

    criterion.bench_function("srtp_unprotect_160", |bencher| {
        // One sealed packet, verified+decrypted each iteration. unprotect commits rollover only on
        // success and the seq is constant, so the index is stable and the tag re-verifies.
        let mut sender = srtp_context();
        let mut srtp = Vec::with_capacity(256);
        sender.protect(&plain, &mut srtp).expect("seed protect");

        let mut receiver = srtp_context();
        let mut out = Vec::with_capacity(256);
        bencher.iter(|| {
            receiver.unprotect(black_box(&srtp), &mut out).expect("unprotect");
            black_box(out.len())
        });
    });
}

fn bench_srtcp(criterion: &mut Criterion) {
    let plain = rtcp_packet(0x0A0B_0C0D);

    criterion.bench_function("srtcp_protect", |bencher| {
        let mut context = srtcp_context();
        let mut out = Vec::with_capacity(256);
        bencher.iter(|| {
            context.protect(black_box(&plain), &mut out).expect("protect");
            black_box(out.len())
        });
    });

    criterion.bench_function("srtcp_unprotect", |bencher| {
        let mut sender = srtcp_context();
        let mut srtcp = Vec::with_capacity(256);
        sender.protect(&plain, &mut srtcp).expect("seed protect");

        let mut receiver = srtcp_context();
        let mut out = Vec::with_capacity(256);
        bencher.iter(|| {
            receiver.unprotect(black_box(&srtcp), &mut out).expect("unprotect");
            black_box(out.len())
        });
    });
}

fn bench_secure_leg(criterion: &mut Criterion) {
    let local = SrtpKeyMaterial::from_inline_bytes(&[0xAA; 30]).expect("30 bytes");
    let remote = SrtpKeyMaterial::from_inline_bytes(&[0xBB; 30]).expect("30 bytes");
    let plain = rtp_packet(0x2000, 0x1111_1111);

    criterion.bench_function("secure_leg_protect_rtp", |bencher| {
        let mut leg = SecureLeg::new(&local, &remote);
        let mut out = Vec::with_capacity(256);
        bencher.iter(|| {
            let kind = leg.protect(black_box(&plain), &mut out).expect("protect");
            black_box(kind)
        });
    });

    criterion.bench_function("secure_leg_unprotect_rtp", |bencher| {
        // The peer encrypts inbound media with the remote key; the leg decrypts it with the same.
        let mut peer = SrtpContext::from_key_material(&remote);
        let mut srtp = Vec::with_capacity(256);
        peer.protect(&plain, &mut srtp).expect("seed protect");

        let mut leg = SecureLeg::new(&local, &remote);
        let mut out = Vec::with_capacity(256);
        bencher.iter(|| {
            let kind = leg.unprotect(black_box(&srtp), &mut out).expect("unprotect");
            black_box(kind)
        });
    });
}

fn bench_setup(criterion: &mut Criterion) {
    criterion.bench_function("srtp_context_new", |bencher| {
        bencher.iter(|| {
            let context = SrtpContext::new(black_box(&MASTER_KEY), black_box(&MASTER_SALT));
            black_box(context)
        });
    });
}

criterion_group!(benches, bench_srtp, bench_srtcp, bench_secure_leg, bench_setup);
criterion_main!(benches);
