#![no_main]
//! Fuzz the SDP parser + rewriter, which eats the offer/answer SDP off the signalling path.
//!
//! House rule: a malformed / hostile SDP body must decode-or-error — never panic, never
//! read out of bounds, never spin. The body arrives as text, so we feed `String::from_utf8_lossy`
//! to both [`parse`](siphon_rtp_engine::sdp::parse) and
//! [`rewrite`](siphon_rtp_engine::sdp::rewrite) against a fixed engine endpoint (RFC 4566 / 3264).

use libfuzzer_sys::fuzz_target;
use siphon_rtp_engine::sdp::{self, EngineMedia, IceRewrite, TextRewrite};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = sdp::parse(&text);

    // 3GPP test range / documentation address — never a real subscriber endpoint. No advertised-IP
    // override here (advertise the bound address), so the rewriter exercises its default path.
    let engine = EngineMedia::new(
        "192.0.2.1:10000"
            .parse()
            .expect("static valid socket address"),
        None,
    );
    // Rewrite against arbitrary input passing the peer's ICE through (no re-origination) with no
    // security advertisement / mux override and no text-stream directive: must never panic.
    let _ = sdp::rewrite(&text, engine, IceRewrite::Keep, None, None, TextRewrite::None);
});
