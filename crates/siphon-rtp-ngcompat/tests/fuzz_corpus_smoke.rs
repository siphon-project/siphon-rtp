//! `cargo test`-buildable smoke harness for the NG/bencode control parser — the stable-toolchain
//! stand-in for `fuzz/fuzz_targets/bencode_fuzz.rs` (which needs nightly + `cargo-fuzz`). Feeds
//! crafted-malformed datagrams and the seed corpus through the whole untrusted path (bencode decode
//! → cookie split → NG command map) and asserts none of it panics, reads out of bounds, or spins.
//!
//! CLAUDE.md hard rule: a hostile control datagram must decode-or-error, never crash. The
//! deeply-nested case is the regression for the fixed recursive-descent stack-overflow DoS.

use std::path::PathBuf;

use siphon_rtp_ngcompat::{bencode, ng};

fn corpus_seeds() -> Vec<Vec<u8>> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("../../fuzz/corpus/bencode_fuzz");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .collect()
}

/// Drive every byte slice and every truncation prefix of it through the full NG path.
fn drive(bytes: &[u8]) {
    if let Ok(value) = bencode::decode(bytes) {
        let _ = ng::parse_command(&value);
    }
    let _ = bencode::decode_prefix(bytes);
    if let Ok((_cookie, body)) = ng::split_cookie(bytes) {
        if let Ok(value) = bencode::decode(body) {
            let _ = ng::parse_command(&value);
        }
    }
}

#[test]
fn crafted_malformed_ng_datagrams_never_panic() {
    let samples: &[&[u8]] = &[
        b"",
        b"i",
        b"ie",
        b"i-0e",
        b"i99999999999999999999999999e", // overflows i64 → BadInteger
        b"99999999999999999999:",        // byte-string length overflows usize
        b"1:",                           // declared 1 byte, none present
        b"d",
        b"de",
        b"d1:a",
        b"l1:al",                        // unterminated nested list
        b"d1:ai1e1:ai2ee",              // duplicate key
        b"cookie d7:command4:pinge",     // full NG datagram
        b"no-space-here",
        b" ",                            // empty cookie + empty body
        b"x",
    ];
    for sample in samples {
        for end in 0..=sample.len() {
            drive(&sample[..end]);
        }
    }
}

#[test]
fn corpus_seeds_never_panic() {
    let seeds = corpus_seeds();
    assert!(!seeds.is_empty(), "seed corpus must exist at fuzz/corpus/bencode_fuzz/");
    for seed in seeds {
        drive(&seed);
    }
}

#[test]
fn deeply_nested_datagram_errors_instead_of_overflowing_the_stack() {
    // The fixed bug: a datagram of nothing but `l`/`d` openers recursed once per byte and aborted
    // the process via stack overflow. Driven on a small stack so the depth cap is what saves it.
    for opener in [b'l', b'd'] {
        let payload: Vec<u8> = std::iter::repeat(opener).take(500_000).collect();
        let result = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || bencode::decode(&payload))
            .expect("spawn")
            .join()
            .expect("decode must not crash the thread");
        assert!(result.is_err(), "deeply nested input must be rejected");
    }
}
