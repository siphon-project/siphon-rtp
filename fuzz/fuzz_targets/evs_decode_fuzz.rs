#![no_main]
//! Fuzz the EVS decode path with a hostile RTP payload (3GPP TS 26.445 Annex A, TS 26.442 decoder).
//!
//! House rule: a hostile codec bitstream off the network must decode-or-error, never panic, never
//! read out of bounds, never spin. `Decoder::decode` runs the payload parse of both formats and the
//! EVS decoder (the primary modes and the AMR-WB interoperable mode, the DTX handler, the
//! concealment), so arbitrary bytes reach all of it. The decoder is kept across payloads so that
//! what one leaves behind (a SID, a lost frame, a mode switch) meets the next; the first byte picks
//! the negotiated bandwidth and `hf-only`.

use libfuzzer_sys::fuzz_target;
use siphon_rtp_codec::factory::{decoder_for, CodecSpec, EvsParams};

const FMTP: [&str; 6] = [
    "",
    "bw=nb;hf-only=1",
    "bw=wb",
    "bw=swb;hf-only=1",
    "bw=fb",
    "bw=nb-wb;hf-only=1",
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payloads)) = data.split_first() else {
        return;
    };
    let fmtp = FMTP[usize::from(selector) % FMTP.len()];
    let Ok(params) = EvsParams::parse(fmtp) else {
        return;
    };
    let spec = CodecSpec::new(96, "EVS", 16_000, 1, 20).with_evs_params(Some(params));
    let Ok(mut decoder) = decoder_for(&spec) else {
        return;
    };
    // room for the most frames one packet may carry at the highest output rate
    let mut out = vec![0i16; 12 * 960];
    // one payload per length-prefixed chunk, so a single input drives a stream
    let mut rest = payloads;
    while let Some((&length, tail)) = rest.split_first() {
        let length = usize::from(length).min(tail.len());
        let (payload, next) = tail.split_at(length);
        let _ = decoder.decode(payload, &mut out);
        if length % 7 == 0 {
            let _ = decoder.conceal(&mut out);
        }
        rest = next;
    }
});
