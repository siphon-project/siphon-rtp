#![no_main]
//! Fuzz the media-plane parsers that eat untrusted bytes straight off the wire.
//!
//! House rule: a malformed / truncated / hostile datagram must decode-or-error — never
//! panic, never read out of bounds, never spin. We feed the same raw bytes to the RTP header
//! parser (RFC 3550 §5.1), the possibly-compound RTCP parser (§6), and the rtcp-mux classifier
//! (RFC 5761), since on a muxed socket any of the three can see arbitrary input. The RTCP APP reader
//! (RFC 3550 §6.7) gets the same bytes: an MCPTT floor-control port (3GPP TS 24.380) feeds it
//! whatever arrives, and so does the RTCP feedback reader (RFC 4585, RFC 5104) of a video seat.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_media::rtcp;
use siphon_rtp_media::rtp::RtpPacket;

fuzz_target!(|data: &[u8]| {
    // Each call must return Ok/Err (or Some/None) without panicking on any input.
    let _ = RtpPacket::parse(data);
    let _ = rtcp::parse_compound(data);
    let _ = rtcp::demux(data);
    for app in rtcp::app_packets(data) {
        let _ = app;
    }
    // RFC 4585 / RFC 5104 feedback: PLI, FIR and Generic NACK a video seat sends the room.
    for feedback in rtcp::feedback_packets(data) {
        if let Ok(rtcp::Feedback::Fir { entries, .. }) = feedback {
            for entry in entries {
                let _ = entry;
            }
        }
    }
});
