//! `cargo test`-buildable smoke harness for the RTP/RTCP parsers — the stable-toolchain stand-in
//! for `fuzz/fuzz_targets/rtp_parser_fuzz.rs` (which needs nightly + `cargo-fuzz`). Feeds
//! crafted-malformed datagrams and the seed corpus through the RTP header parser (RFC 3550 §5.1),
//! the compound RTCP parser (§6), and the rtcp-mux classifier (RFC 5761), asserting none panics,
//! reads out of bounds, or spins.
//!
//! CLAUDE.md hard rule: a hostile datagram off the network must decode-or-error, never crash.
//! (The crates' inline `parse_never_panics` proptests fuzz the same property structurally; this
//! file additionally exercises the persisted seed corpus and a battery of hand-picked attacks.)

use std::path::PathBuf;

use siphon_rtp_media::rtcp;
use siphon_rtp_media::rtp::RtpPacket;

fn corpus_seeds() -> Vec<Vec<u8>> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("../../fuzz/corpus/rtp_parser_fuzz");
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
    let _ = RtpPacket::parse(bytes);
    let _ = rtcp::parse_compound(bytes);
    let _ = rtcp::demux(bytes);
}

#[test]
fn crafted_malformed_datagrams_never_panic() {
    let samples: &[&[u8]] = &[
        &[0xFF; 16],                                              // every bit set
        &[0x8F, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],             // CC=15, no CSRCs present
        // X=1, extension word count = 0xFFFF (claims a giant extension):
        &[0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xBE, 0xDE, 0xFF, 0xFF],
        &[0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF],          // P=1, pad byte 255 > payload
        &[0x80, 200, 0xFF, 0xFF, 0, 0, 0, 0],                    // SR claiming 0xFFFF length words
        &[0x80, 201, 0x00, 0x00],                                // RR length-words=0 (packet_len=4)
        &[0x81, 202, 0x00, 0x01, 0, 0, 0, 0],                    // SDES (Other)
    ];
    for sample in samples {
        for end in 0..=sample.len() {
            drive(&sample[..end]);
        }
    }
}

// The seed corpus (`fuzz/corpus/rtp_parser_fuzz/`) is fuzzer-generated and gitignored, so a clean
// checkout (CI) has nothing to replay — the no-panic guarantee there rests on
// `crafted_malformed_datagrams_never_panic` above and the crates' inline `parse_never_panics`
// proptests. When a developer has run the fuzzer locally, this additionally replays every retained
// seed; none may panic, read out of bounds, or spin.
#[test]
fn corpus_seeds_never_panic() {
    for seed in corpus_seeds() {
        drive(&seed);
    }
}
