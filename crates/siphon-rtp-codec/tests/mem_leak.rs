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

/// Churning whole G.729 codec instances through construct → encode → decode → drop, which is what a
/// node carrying short calls does all day: one codec pair per leg, built at answer and dropped at
/// delete. The state is large for a codec of this rate (excitation history, predictor memories, the
/// background estimate), so a constructor that leaked would show up as a node that grows with call
/// count rather than with concurrency — the shape that is hardest to catch in production.
#[cfg(feature = "g729")]
#[test]
fn g729_call_churn_does_not_leak() {
    use siphon_rtp_codec::g729::G729;

    let pcm: Vec<i16> = (0..160)
        .map(|i| {
            let t = i as f32;
            (((t * 0.21).sin() + 0.6 * (t * 0.63).sin()) * 9000.0) as i16
        })
        .collect();
    let mut payload = vec![0u8; 20];
    let mut out = vec![0i16; 160];

    // One "call": a codec pair built, a few packets each way, then dropped. Annex B on, because a
    // real call spends most of its time inactive and that is the path with the most state.
    let mut call = || {
        let mut encoder = G729::new(20).with_annex_b(true);
        let mut decoder = G729::new(20).with_annex_b(true);
        for _ in 0..5 {
            let written = Encoder::encode(&mut encoder, &pcm, &mut payload).expect("encode");
            if written > 0 {
                Decoder::decode(&mut decoder, &payload[..written], &mut out).expect("decode");
            }
        }
    };

    let _prime = allocated_bytes();
    for _ in 0..200 {
        call();
    }
    let before = allocated_bytes();
    for _ in 0..5_000 {
        call();
    }
    let after = allocated_bytes();

    assert!(
        after <= before,
        "G.729 call churn leaked {} bytes over 5k calls",
        after.saturating_sub(before)
    );
}

// NOTE: the AMR encode-core zero-allocation gates (AMR-NB *and* AMR-WB) live in the sibling
// `tests/amr_zero_alloc.rs`, which uses a **counting** global allocator. A jemalloc `stats.allocated`
// byte-delta (this file's instrument) moves in coarse arena-sized steps, so it is too noisy to gate a
// hot encode loop on a shared CI runner; counting allocator calls is exact and strictly stronger (it
// also catches allocate-then-free churn a live-bytes delta misses).
