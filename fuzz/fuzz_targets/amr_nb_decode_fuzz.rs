#![no_main]
//! Fuzz the AMR-NB decode path with a hostile RTP payload (3GPP TS 26.071 / RFC 4867).
//!
//! House rule: a hostile codec bitstream off the network must decode-or-error, never panic,
//! never read out of bounds, never spin. `Decoder::decode` runs the full RFC 4867 payload parse
//! (ToC + frame un-sort) and the ACELP decode over arbitrary bytes.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_codec::amr::{AmrNb, PayloadFormat, RtpConfig};
use siphon_rtp_codec::Decoder;

fuzz_target!(|data: &[u8]| {
    // The same bytes as a payload of each RFC 4867 payload format: a stream is read in the one it
    // negotiated, so both depacketisers face the network.
    for format in [PayloadFormat::BandwidthEfficient, PayloadFormat::OctetAligned] {
        let config = RtpConfig {
            format,
            ..RtpConfig::default()
        };
        let Ok(mut codec) = AmrNb::negotiated(&config) else {
            return;
        };
        // Oversized so a well-formed multi-frame payload never errors purely on buffer size; the
        // point is to reach the decode logic, not to bounce on a short output.
        let mut out = [0i16; 8192];
        let _ = codec.decode(data, &mut out);
        // Concealment from whatever state the (possibly partial) decode left behind.
        let _ = codec.conceal(&mut out);
        let _ = codec.decode(data, &mut out);
    }
});
