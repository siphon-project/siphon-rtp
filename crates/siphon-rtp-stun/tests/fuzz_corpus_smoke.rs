//! `cargo test`-buildable smoke harness for the STUN/TURN message parser — the stable-toolchain
//! stand-in for `fuzz/fuzz_targets/stun_fuzz.rs` (which needs nightly + `cargo-fuzz`). Feeds
//! crafted-malformed datagrams and the seed corpus through the STUN header/attribute parser, the
//! TURN accessors and ChannelData framing, and MESSAGE-INTEGRITY verification, asserting none
//! panics, reads out of bounds, or spins.
//!
//! CLAUDE.md hard rule: a hostile datagram on the media port must decode-or-error, never crash.

use std::path::PathBuf;

use siphon_rtp_stun::{self as stun, turn};

fn corpus_seeds() -> Vec<Vec<u8>> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("../../fuzz/corpus/stun_fuzz");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .collect()
}

fn drive(bytes: &[u8]) {
    if let Ok(message) = stun::parse(bytes) {
        let _ = message.is_binding_request();
        let _ = message.username();
        let _ = message.xor_mapped_address();
        let _ = turn::requested_transport(&message);
        let _ = turn::lifetime(&message);
        let _ = turn::channel_number(&message);
        let _ = turn::xor_peer_address(&message);
        let _ = turn::xor_peer_addresses(&message);
        let _ = turn::xor_relayed_address(&message);
        let _ = turn::data(&message);
        let _ = turn::error_code(&message);
        let _ = turn::realm(&message);
        let _ = turn::nonce(&message);
    }
    let _ = stun::verify_message_integrity(bytes, b"fuzz-key");
    let _ = turn::parse_channel_data(bytes);
}

#[test]
fn crafted_malformed_datagrams_never_panic() {
    let samples: &[&[u8]] = &[
        b"",
        b"\x00\x01\x00\x00",                                     // shorter than a 20-byte header
        // length 0xFFFF > buffer:
        b"\x00\x01\xff\xff\x21\x12\xa4\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        // attr_len 0xFFFF overruns the message:
        b"\x00\x01\x00\x08\x21\x12\xa4\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\xff\xff",
        // bad magic cookie:
        b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\x40\x00\xff\xff\xde\xad",                             // ChannelData length overruns
        b"\x40\x00\x00\x04\xde\xad\xbe\xef",                     // valid ChannelData
    ];
    for sample in samples {
        for end in 0..=sample.len() {
            drive(&sample[..end]);
        }
    }
}

// The seed corpus (`fuzz/corpus/stun_fuzz/`) is fuzzer-generated and gitignored, so a clean checkout
// (CI) has nothing to replay — the no-panic guarantee there rests on
// `crafted_malformed_datagrams_never_panic` above and the crate's inline proptests. When a developer
// has run the fuzzer locally, this additionally replays every retained seed; none may panic, read out
// of bounds, or spin.
#[test]
fn corpus_seeds_never_panic() {
    for seed in corpus_seeds() {
        drive(&seed);
    }
}
