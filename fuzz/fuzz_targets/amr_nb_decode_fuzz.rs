#![no_main]
//! Fuzz the AMR-NB decode path with a hostile RTP payload (3GPP TS 26.071 / RFC 4867).
//!
//! CLAUDE.md hard rule: a hostile codec bitstream off the network must decode-or-error, never panic,
//! never read out of bounds, never spin. `Decoder::decode` runs the full RFC 4867 payload parse
//! (ToC + frame un-sort) and the ACELP decode over arbitrary bytes.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_codec::amr::AmrNb;
use siphon_rtp_codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut codec = AmrNb::new();
    let mut out = [0i16; 8192];
    let _ = codec.decode(data, &mut out);
    // AMR-NB concealment currently returns Unsupported rather than panicking; exercise it anyway so
    // that contract can never silently regress into a panic.
    let _ = codec.conceal(&mut out);
});
