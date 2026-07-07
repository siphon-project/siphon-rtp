//! `cargo test`-buildable smoke harness for the SDP parser + rewriter — the stable-toolchain
//! stand-in for `fuzz/fuzz_targets/sdp_fuzz.rs` (which needs nightly + `cargo-fuzz`). Feeds
//! crafted-malformed SDP bodies and the seed corpus through `sdp::parse` and `sdp::rewrite` against
//! a fixed engine endpoint, asserting neither panics, reads out of bounds, or spins.
//!
//! House rule: a malformed / hostile SDP off the signalling path must decode-or-error,
//! never crash. (The crate's inline `parsers_never_panic` proptest fuzzes the same property over
//! arbitrary text; this file additionally exercises the persisted seed corpus and hand-picked
//! attacks. All addresses are the 3GPP/documentation test range — never real subscriber endpoints.)

use std::path::PathBuf;

use siphon_rtp_engine::sdp::{self, EngineMedia};

fn corpus_seeds() -> Vec<Vec<u8>> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("../../fuzz/corpus/sdp_fuzz");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .collect()
}

fn engine() -> EngineMedia {
    EngineMedia {
        rtp: "192.0.2.1:10000"
            .parse()
            .expect("static valid socket address"),
        rtcp: None,
    }
}

fn drive(text: &str) {
    let _ = sdp::parse(text);
    let _ = sdp::rewrite(text, engine(), sdp::IceRewrite::Keep, None, None);
}

#[test]
fn crafted_malformed_sdp_never_panics() {
    let samples: &[&str] = &[
        "",
        "=",
        "m=audio\r\n",
        "m=audio notaport RTP/AVP 0\r\n",
        "m=audio 999999999999 RTP/AVP 0\r\nc=IN IP4 192.0.2.1\r\n", // port overflows u16
        "c=IN IP4 not-an-address\r\nm=audio 5000 RTP/AVP 0\r\n",
        "c=IN IP4 192.0.2.1\nm=audio 5000 RTP/AVP\na=rtpmap:\na=rtcp:\na=ptime:\n",
        "a=rtpmap:300 X/0/0/0/0\r\n", // payload type out of u8 range
        "m=audio 5000 RTP/SAVP 0\r\nc=IN IP4 192.0.2.1\r\na=crypto:bogus\r\n",
        "\r\n\r\n\r\n",
        "v=0\rc=IN IP4 192.0.2.1\rm=audio 5000 RTP/AVP 0\r", // CR-only line endings
    ];
    for sample in samples {
        drive(sample);
    }
}

// The seed corpus (`fuzz/corpus/sdp_fuzz/`) is fuzzer-generated and gitignored, so a clean checkout
// (CI) has nothing to replay — the no-panic guarantee there rests on `crafted_malformed_sdp_never_panics`
// above and the crate's inline `parsers_never_panic` proptest. When a developer has run the fuzzer
// locally, this additionally replays every retained seed; none may panic, read out of bounds, or spin.
#[test]
fn corpus_seeds_never_panic() {
    for seed in corpus_seeds() {
        drive(&String::from_utf8_lossy(&seed));
    }
}
