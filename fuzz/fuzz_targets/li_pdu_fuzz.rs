#![no_main]

use libfuzzer_sys::fuzz_target;
use siphon_rtp_li::inbound::InboundHeader;

// ETSI TS 103 221-2 §5.2 — the PDU header a Mediation Function sends back over the X2/X3 delivery
// connection (keepalive acknowledgements, and anything a newer peer emits). Untrusted bytes from a
// network peer: it must never panic, and a header it accepts must be self-consistent enough that
// the stream framing built on it cannot be walked off the rails.
fuzz_target!(|data: &[u8]| {
    if let Ok(header) = InboundHeader::parse(data) {
        // `attributes_len` subtracts the fixed header, so an accepted header must never undercut
        // it — that is the underflow the parser exists to reject.
        let attributes_len = header.attributes_len();
        // A parsed total must be at least the header it came from, or a stream reader advancing by
        // it would resume mid-PDU.
        if let Ok(total) = header.total_len() {
            assert!(total >= header.header_length as usize);
            assert!(total >= attributes_len);
        }
        let _ = header.version_matches();
        let _ = header.is_keepalive_acknowledgement();
    }
});
