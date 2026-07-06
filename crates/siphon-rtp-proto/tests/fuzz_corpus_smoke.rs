//! `cargo test`-buildable smoke harness for the JSON control framing — the stable-toolchain
//! stand-in for `fuzz/fuzz_targets/proto_frame_fuzz.rs` (which needs nightly + `cargo-fuzz`). Feeds
//! crafted-malformed frames and the seed corpus through `frame::decode::<Request>` and asserts it
//! never panics, reads out of bounds, or spins.
//!
//! House rule: a corrupt length prefix or JSON body must decode-or-error, never crash;
//! an oversized declared length must be rejected (MAX_FRAME_LEN), not used to slice past the buffer.

use std::path::PathBuf;

use siphon_rtp_proto::{frame, Request};

fn corpus_seeds() -> Vec<Vec<u8>> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("../../fuzz/corpus/proto_frame_fuzz");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .collect()
}

#[test]
fn crafted_malformed_frames_never_panic() {
    let samples: &[&[u8]] = &[
        b"",
        b"\x00",
        b"\x00\x00\x00",                                    // partial header
        b"\x00\x00\x00\x00",                                // zero-length body
        b"\xff\xff\xff\xff{}", // length > MAX_FRAME_LEN → FrameTooLarge
        b"\x00\x00\x00\x02{}", // valid length, malformed Request
        b"\x00\x00\x00\x19{\"id\":1,\"command\":\"ping\"}", // valid frame
        b"\x00\x00\x00\x19{\"id\":1,\"command\":\"pin", // truncated body
    ];
    for sample in samples {
        for end in 0..=sample.len() {
            let _ = frame::decode::<Request>(&sample[..end]);
        }
    }
}

// The seed corpus (`fuzz/corpus/proto_frame_fuzz/`) is fuzzer-generated and gitignored, so a clean
// checkout (CI) has nothing to replay — the no-panic guarantee there rests on
// `crafted_malformed_frames_never_panic` above (which includes a valid frame) and the crate's inline
// proptests. When a developer has run the fuzzer locally, this additionally replays every retained
// seed; none may panic, and at least one valid seed must still decode to a `Request`.
#[test]
fn corpus_seeds_never_panic_and_valid_seed_decodes() {
    let seeds = corpus_seeds();
    if seeds.is_empty() {
        eprintln!("proto seed corpus absent — skipping corpus replay");
        return;
    }
    let mut decoded_a_full_frame = false;
    for seed in seeds {
        if let Ok(Some((_request, _consumed))) = frame::decode::<Request>(&seed) {
            decoded_a_full_frame = true;
        }
    }
    assert!(
        decoded_a_full_frame,
        "at least one valid seed must decode to a Request"
    );
}
