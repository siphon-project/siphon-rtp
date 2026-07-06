#![no_main]
//! Fuzz the SDP parser + rewriter, which eats the offer/answer SDP off the signalling path.
//!
//! House rule: a malformed / hostile SDP body must decode-or-error — never panic, never
//! read out of bounds, never spin. The body arrives as text, so we feed `String::from_utf8_lossy`
//! to both [`parse`](siphon_rtp_engine::sdp::parse) and
//! [`rewrite`](siphon_rtp_engine::sdp::rewrite) against a fixed engine endpoint (RFC 4566 / 3264).

use libfuzzer_sys::fuzz_target;
use siphon_rtp_engine::sdp::{self, EngineMedia};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = sdp::parse(&text);

    let engine = EngineMedia {
        // 3GPP test range / documentation address — never a real subscriber endpoint.
        rtp: "192.0.2.1:10000".parse().expect("static valid socket address"),
        rtcp: None,
    };
    // Rewrite against arbitrary input with no ICE / security advertisement / mux override: must
    // never panic.
    let _ = sdp::rewrite(&text, engine, None, None, None);
});
