//! Memory-leak / zero-allocation gates for the codec hot path.
//!
//! `cargo test -p siphon-rtp-codec --test mem_leak`
//!
//! These run under jemalloc and read `stats.allocated` (current **live** bytes) before and after a
//! tight encode/decode loop. The hot path writes into caller-owned buffers, so a correct codec
//! allocates *nothing* per frame — any per-frame `malloc` shows up as a non-zero delta and fails
//! the gate. Always gate on `allocated` (live bytes), never RSS: jemalloc retains freed pages, so
//! RSS is too noisy to mean anything here.

use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::{Decoder, Encoder};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// One 20 ms frame of 8 kHz audio.
const FRAME: usize = 160;

/// Live bytes currently allocated, per jemalloc. Advancing the epoch refreshes the cached stats.
fn allocated_bytes() -> usize {
    tikv_jemalloc_ctl::epoch::advance().expect("advance jemalloc epoch");
    tikv_jemalloc_ctl::stats::allocated::read().expect("read jemalloc allocated")
}

fn sample_pcm() -> Vec<i16> {
    // A deterministic sweep so the encoder exercises multiple G.711 segments.
    (0..FRAME)
        .map(|i| (((i as i32 * 401) % 65536) - 32768) as i16)
        .collect()
}

#[test]
fn g711_encode_decode_allocates_nothing_per_frame() {
    let pcm = sample_pcm();
    let mut payload = vec![0u8; FRAME];
    let mut out = vec![0i16; FRAME];
    let mut ulaw = G711::ulaw();
    let mut alaw = G711::alaw();

    // Prime jemalloc-ctl's stat MIBs and fault in the decode tables / thread cache so the measured
    // window is purely the hot path.
    let _prime = allocated_bytes();
    for _ in 0..2_000 {
        ulaw.encode(&pcm, &mut payload).expect("encode");
        ulaw.decode(&payload, &mut out).expect("decode");
    }

    let before = allocated_bytes();
    for _ in 0..200_000 {
        ulaw.encode(&pcm, &mut payload).expect("encode");
        ulaw.decode(&payload, &mut out).expect("decode");
        alaw.encode(&pcm, &mut payload).expect("encode");
        alaw.decode(&payload, &mut out).expect("decode");
    }
    let after = allocated_bytes();

    // Live bytes must not grow: the hot path writes into caller-owned buffers, so a per-frame
    // `malloc` would accumulate visibly. (A decrease is fine — that is jemalloc reclaiming, not a
    // leak.)
    assert!(
        after <= before,
        "G.711 encode/decode must not allocate on the hot path — grew {} bytes over 200k frames",
        after.saturating_sub(before)
    );
}

#[test]
fn codec_construct_churn_does_not_leak() {
    let pcm = sample_pcm();
    let mut payload = vec![0u8; FRAME];
    let mut out = vec![0i16; FRAME];

    let mut cycle = || {
        let mut ulaw = G711::ulaw();
        let mut alaw = G711::alaw();
        ulaw.encode(&pcm, &mut payload).expect("encode");
        ulaw.decode(&payload, &mut out).expect("decode");
        alaw.encode(&pcm, &mut payload).expect("encode");
        alaw.decode(&payload, &mut out).expect("decode");
    };

    let _prime = allocated_bytes();
    for _ in 0..1_000 {
        cycle();
    }
    let before = allocated_bytes();
    for _ in 0..50_000 {
        cycle();
    }
    let after = allocated_bytes();

    assert!(
        after <= before,
        "codec construct/encode/decode churn leaked {} bytes over 50k cycles",
        after.saturating_sub(before)
    );
}
