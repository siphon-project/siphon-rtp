#![no_main]
//! Fuzz the ICE candidate grammar (RFC 8839 §5.1), which eats untrusted text: every `a=candidate`
//! line in a peer's SDP arrives from the network before the call is answered.
//!
//! House rule: a hostile line must parse-or-error — never panic, never spin. The parser walks
//! whitespace-separated fields and indexes into them, so this covers truncation at every field
//! boundary, bogus numerics, address literals, and the optional `raddr`/`rport`/extension tail.
//! `a=ice-options` is fuzzed alongside it (same untrusted SDP, same call site).
//!
//! Both the string and the byte view are exercised: SDP is text, but the bytes reaching us are not
//! guaranteed to be UTF-8, and the lossy conversion is what the parser would really see.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_ice::{Candidate, IceOptions};

fuzz_target!(|data: &[u8]| {
    let line = String::from_utf8_lossy(data);

    // Anything that parses must re-serialise and re-parse to the same candidate: a round trip that
    // disagrees would mean the formatter can emit a line we ourselves cannot read back.
    if let Ok(candidate) = Candidate::parse(&line) {
        let formatted = candidate.to_attribute_line();
        match Candidate::parse(&formatted) {
            Ok(reparsed) => assert_eq!(reparsed, candidate, "round trip diverged: {formatted:?}"),
            Err(error) => panic!("our own output failed to parse: {formatted:?} ({error})"),
        }
    }

    // With the attribute prefixes the engine actually strips before calling in.
    let _ = Candidate::parse(&format!("a=candidate:{line}"));
    let _ = Candidate::parse(&format!("candidate:{line}"));

    // The other untrusted ICE attribute parsed off the same SDP.
    let _ = IceOptions::parse(&line);
    let _ = IceOptions::parse(&format!("a=ice-options:{line}"));
});
