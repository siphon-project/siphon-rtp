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
    EngineMedia::new(
        "192.0.2.1:10000"
            .parse()
            .expect("static valid socket address"),
        None,
    )
}

/// The same endpoint with a **non-adjacent** RTCP port, so the rewrite has to insert an `a=rtcp:`
/// (RFC 3605 §2.1 — an adjacent port is the RFC 3550 §11 default and is left unsaid).
fn engine_demuxed() -> EngineMedia {
    EngineMedia::new(
        "192.0.2.1:10000"
            .parse()
            .expect("static valid socket address"),
        Some(
            "192.0.2.1:11001"
                .parse()
                .expect("static valid socket address"),
        ),
    )
}

/// RFC 4566 §5 rank of a line inside a media description: `m=`, `i=`, `c=`, `b=`, `k=`, then `a=`.
/// Anything unrecognised ranks with the attribute region, so a blank line or a line from a broken UA
/// is never read as ordering evidence.
fn section_line_rank(line: &str) -> usize {
    ["m=", "i=", "c=", "b=", "k="]
        .iter()
        .position(|prefix| line.starts_with(prefix))
        .unwrap_or(5)
}

/// Every media description in a rewritten body must be in RFC 4566 §5 order. Rewriting was only ever
/// checked for "did not panic" and for the presence of individual lines, which is why the engine
/// emitting its own attributes at the `m=` line — ahead of a media-level `c=`, which several of these
/// corpus inputs carry — survived: every line was present and the section was still malformed.
fn assert_rfc4566_line_order(sdp: &str, input: &str) {
    // Scoped to the media descriptions: the session region has its own §5 order (`v=`, `o=`, `s=`,
    // …, `c=`, …), which these ranks do not describe and this rewrite does not reorder.
    let mut highest = None;
    for line in sdp.lines() {
        if line.starts_with("m=") {
            highest = Some(0);
        }
        let Some(previous) = highest else {
            continue;
        };
        let rank = section_line_rank(line);
        assert!(
            rank >= previous,
            "`{line}` breaks RFC 4566 §5 line order in the rewrite of {input:?}:\n{sdp}"
        );
        highest = Some(rank);
    }
}

fn drive(text: &str) {
    let _ = sdp::parse(text);
    // Three rewrites, because the defect this order assertion guards lives in what the engine *adds*:
    // a pass-through rewrite that contributes no attribute of its own cannot misplace one. The
    // second inserts an `a=rtcp:`, the third an `a=rtcp-mux` and an `a=ice-mismatch`.
    let rewrites = [
        (engine(), sdp::IceRewrite::Keep, None),
        (engine_demuxed(), sdp::IceRewrite::Keep, None),
        (engine(), sdp::IceRewrite::Mismatch, Some(true)),
    ];
    for (engine, ice, mux_override) in rewrites {
        let rewritten = sdp::rewrite(
            text,
            engine,
            ice,
            None,
            mux_override,
            sdp::TextRewrite::None,
        );
        // A body the rewriter *accepted* is one it re-originated and put on the wire, so it has to be
        // conformant — whatever the input looked like. (A rejected body never reaches a peer.)
        if let Ok(rewritten) = rewritten {
            assert_rfc4566_line_order(&rewritten.sdp, text);
        }
    }
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
        // Media-level `c=` (RFC 4566 §5.7), with no session-level one to fall back on — the layout
        // the rewriter used to emit its own attributes ahead of. These carry the whole §5 prelude,
        // an already-misordered section, and a second media description, so the order assertion in
        // `drive` has something real to check.
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n\
         m=audio 5000 RTP/AVP 0 8\r\nc=IN IP4 192.0.2.1\r\na=rtpmap:0 PCMU/8000\r\n",
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n\
         m=audio 5000 RTP/AVP 0\r\ni=voice\r\nc=IN IP4 192.0.2.1\r\nb=AS:64\r\nk=prompt\r\n\
         a=rtpmap:0 PCMU/8000\r\n",
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n\
         m=audio 5000 RTP/AVP 0\r\na=rtcp:5001\r\nc=IN IP4 192.0.2.1\r\na=sendrecv\r\n",
        "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n\
         m=audio 5000 RTP/AVP 0\r\nc=IN IP4 192.0.2.1\r\na=rtpmap:0 PCMU/8000\r\n\
         m=video 5004 RTP/AVP 96\r\nc=IN IP4 192.0.2.1\r\na=rtpmap:96 VP8/90000\r\n",
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
