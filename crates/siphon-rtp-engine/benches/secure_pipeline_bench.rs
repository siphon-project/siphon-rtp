//! Criterion perf gate for the **secure media pipeline** — the per-packet cost a call pays when its
//! far leg is encrypted and its media still has to be decoded.
//!
//! `MediaCall::process` is the whole per-packet transform (source gate → SRTP `unprotect` → decode →
//! resample → encode → SRTP `protect`), so benching it end-to-end measures exactly what a
//! `SrtpMedia` / `DtlsMedia` leg costs against a plaintext `Media` leg of the same shape. Three
//! points:
//!
//! - `plaintext` — a µ-law↔A-law transcode with no crypto: the baseline.
//! - `secure` — the same transcode with the far leg's SRTP (de)crypt on both directions. The delta is
//!   the crypto, and it is what a WebRTC (DTLS) leg pays once its handshake has keyed the pipeline —
//!   a keyed `DtlsMedia` leg *is* this path, byte for byte.
//! - `pending_key` — the same call before its DTLS handshake completed, where every packet must be
//!   dropped. This exists to keep the security gate honest about its cost: it has to be a branch on
//!   the way in, not work that gets thrown away, so an unkeyed leg must be cheaper than a keyed one
//!   rather than more expensive (a peer that floods before the handshake must not cost more than one).
//!
//! `cargo bench -p siphon-rtp --bench secure_pipeline_bench`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::media_pipeline::{DirectionConfig, MediaCall};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::SrtpKeyMaterial;

const A_ADDR: &str = "127.0.0.2:5000";
const B_ADDR: &str = "127.0.0.3:6000";
/// 8 kHz / 20 ms.
const FRAME_SAMPLES: usize = 160;

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("addr")
}

fn spec(payload_type: u8, name: &str) -> CodecSpec {
    CodecSpec::new(payload_type, name, 8_000, 1, 20)
}

/// One direction of a µ-law(A) ↔ A-law(B) transcode.
fn direction(
    ingress: u64,
    egress: u64,
    egress_dst: &str,
    source: &str,
    ingress_codec: &CodecSpec,
    egress_codec: &CodecSpec,
    egress_ssrc: u32,
) -> DirectionConfig {
    DirectionConfig {
        ingress_endpoint: EndpointId(ingress),
        accepted_source: SourceFilter::Exact(addr(source).ip()),
        egress_endpoint: EndpointId(egress),
        egress_dst: addr(egress_dst),
        decoder: siphon_rtp_codec::factory::decoder_for(ingress_codec).expect("decoder"),
        encoder: siphon_rtp_codec::factory::encoder_for(egress_codec).expect("encoder"),
        egress_ssrc,
        egress_payload_type: egress_codec.payload_type,
        telephone_event_in: None,
        telephone_event_out: None,
        recorder: None,
        noise_suppression: false,
        echo_cancellation: false,
        beep_detection: false,
        beep_cadence_guard_ms: None,
        produce_echo_reference: false,
        ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
    }
}

/// A µ-law(A) ↔ A-law(B) transcoding call. `secure` picks the far-leg crypto posture.
fn call(secure: Secure) -> MediaCall {
    let ulaw = spec(0, "PCMU");
    let alaw = spec(8, "PCMA");
    let a_to_b = direction(1, 2, B_ADDR, A_ADDR, &ulaw, &alaw, 0xB000_0001);
    let b_to_a = direction(2, 1, A_ADDR, B_ADDR, &alaw, &ulaw, 0xA000_0001);
    let call = MediaCall::new(
        "bench",
        "tag-a",
        Some("tag-b".into()),
        a_to_b,
        b_to_a,
        true,
        None,
    );
    match secure {
        Secure::None => call,
        Secure::Keyed => {
            let key = SrtpKeyMaterial::from_inline_bytes(&[7u8; 30]).expect("30 bytes");
            call.with_far_secure_leg(Arc::new(Mutex::new(SecureLeg::new(&key, &key))))
        }
        // The DTLS shape before its handshake lands: keyed later, dropping until then.
        Secure::Pending => call.with_far_secure_pending(),
    }
}

#[derive(Clone, Copy)]
enum Secure {
    None,
    Keyed,
    Pending,
}

/// A µ-law RTP packet (12-byte header + 160-byte payload) arriving from A.
fn ulaw_packet(sequence: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * FRAME_SAMPLES as u32).to_be_bytes());
    packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
    packet.extend_from_slice(&[0xFFu8; FRAME_SAMPLES]);
    packet
}

fn bench_secure_pipeline(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("media_pipeline_process_8k_20ms");
    for (label, secure) in [
        ("plaintext", Secure::None),
        ("secure", Secure::Keyed),
        ("pending_key", Secure::Pending),
    ] {
        group.bench_function(label, |bencher| {
            let mut call = call(secure);
            // One packet whose sequence is bumped in place each iteration (monotonic, no per-iter
            // allocation), so the ingress stats and the SRTP replay window both see a real stream.
            let mut packet = ulaw_packet(0);
            let mut sequence: u16 = 0;
            let mut out = Vec::with_capacity(4);
            let mut events = Vec::with_capacity(4);
            bencher.iter(|| {
                sequence = sequence.wrapping_add(1);
                packet[2..4].copy_from_slice(&sequence.to_be_bytes());
                out.clear();
                events.clear();
                let accepted = call.process(
                    &RxPacket {
                        endpoint: EndpointId(1),
                        source: addr(A_ADDR),
                        arrival: u64::from(sequence) * 20_000,
                        data: bytes::Bytes::copy_from_slice(&packet),
                    },
                    &mut out,
                    &mut events,
                );
                black_box(accepted)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_secure_pipeline);
criterion_main!(benches);
