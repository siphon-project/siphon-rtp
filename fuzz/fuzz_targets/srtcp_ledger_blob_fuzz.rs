#![no_main]
//! Fuzz the SRTCP send-index ledger restore blob (`restore_srtcp_indices`) and the hex decoder under it.
//!
//! House rule: a hostile blob must decode-or-error and import-or-refuse, never panic, never slice a
//! string inside a multi-byte character, never spin. The blob is JSON with hex fingerprints and an
//! hex origin tag, sent by the controller.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_engine::engine::decode_srtcp_indices_blob;
use siphon_rtp_engine::ha::from_hex;
use siphon_rtp_engine::srtcp_ledger::SrtcpLedger;

fuzz_target!(|data: &[u8]| {
    // Lossy as well as strict UTF-8: the replacement character is a multi-byte character too.
    let text = String::from_utf8_lossy(data);
    let _ = from_hex(&text);
    if let Ok(checkpoint) = decode_srtcp_indices_blob(&text) {
        let ledger = SrtcpLedger::default();
        ledger.set_max_entries(64);
        let _ = ledger.import(&checkpoint, 1 << 16);
    }
});
