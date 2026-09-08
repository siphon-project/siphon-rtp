//! The per-call cost of rewriting an offer's SDP — the control-plane serialize on the call-setup
//! path. `rewrite` runs once per leg per offer/answer, so this is a per-call number, not a
//! per-packet one; it had no baseline until the RFC 4566 §5 section reorder gave it one.
//!
//! The reorder buffers a re-originated section rather than emitting it line by line, which trades a
//! few small `Vec`s per section for the ordering guarantee. Both connection-line layouts are
//! measured (session-level `c=`, the shape every fixture used to have, and media-level `c=`, the
//! shape the reorder exists for), across the configurations that differ in how much the engine
//! contributes: a plain anchor that adds nothing, one that inserts an `a=rtcp`, a forced-mux one,
//! and the largest block — a re-originated ICE-lite offer.
//!
//! All addresses are the RFC 5737 documentation range.

use std::net::SocketAddr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_engine::sdp::{self, EngineMedia, IceAdvertisement, IceRewrite, TextRewrite};
use siphon_rtp_ice::{Candidate, CandidateKind, GatherConfig, Gatherer};

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("addr")
}

/// A typical mobile-client offer with the connection line at **session** level.
fn session_level_offer() -> String {
    "v=0\r\n\
     o=alice 2890844526 2890844526 IN IP4 host.invalid\r\n\
     s=-\r\n\
     c=IN IP4 192.0.2.10\r\n\
     t=0 0\r\n\
     m=audio 20100 RTP/AVP 18 8 101\r\n\
     a=rtpmap:8 PCMA/8000\r\n\
     a=rtpmap:101 telephone-event/8000\r\n\
     a=fmtp:101 0-15\r\n\
     a=ptime:20\r\n\
     a=sendrecv\r\n"
        .to_string()
}

/// The same offer with the connection line at **media** level (RFC 4566 §5.7), which is the layout
/// the section reorder exists for — here the rewrite has a prelude to keep its additions behind.
fn media_level_offer() -> String {
    "v=0\r\n\
     o=alice 2890844526 2890844526 IN IP4 host.invalid\r\n\
     s=-\r\n\
     t=0 0\r\n\
     m=audio 20100 RTP/AVP 18 8 101\r\n\
     c=IN IP4 192.0.2.10\r\n\
     a=rtpmap:8 PCMA/8000\r\n\
     a=rtpmap:101 telephone-event/8000\r\n\
     a=fmtp:101 0-15\r\n\
     a=ptime:20\r\n\
     a=sendrecv\r\n"
        .to_string()
}

/// An offer carrying the peer's ICE, so `Reoriginate` has something to strip as well as replace.
fn media_level_ice_offer() -> String {
    "v=0\r\n\
     o=alice 2890844526 2890844526 IN IP4 host.invalid\r\n\
     s=-\r\n\
     t=0 0\r\n\
     m=audio 20100 RTP/AVP 8\r\n\
     c=IN IP4 192.0.2.10\r\n\
     a=rtpmap:8 PCMA/8000\r\n\
     a=ice-ufrag:PEERUF\r\n\
     a=ice-pwd:peerpassword01234567\r\n\
     a=candidate:1 1 UDP 2130706431 192.0.2.10 20100 typ host\r\n\
     a=sendrecv\r\n"
        .to_string()
}

fn muxed_engine() -> EngineMedia {
    EngineMedia::new(addr("198.51.100.20:30168"), None)
}

/// A non-adjacent RTCP port, so the rewrite has to insert an `a=rtcp` (RFC 3605 §2.1).
fn demuxed_engine() -> EngineMedia {
    EngineMedia::new(
        addr("198.51.100.20:30168"),
        Some(addr("198.51.100.20:41001")),
    )
}

/// The engine's own host candidate, gathered the way the control path gathers it (host-only, so it
/// completes without touching a socket).
fn host_candidates() -> Vec<Candidate> {
    let mut gatherer = Gatherer::new(GatherConfig::host_only(addr("198.51.100.20:30168")), 0);
    let _ = gatherer.poll(0);
    gatherer.candidates().to_vec()
}

fn sdp_rewrite(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("sdp_rewrite");

    let session_level = session_level_offer();
    let media_level = media_level_offer();
    let ice_offer = media_level_ice_offer();
    let candidates = host_candidates();
    assert_eq!(
        candidates.first().map(|candidate| candidate.kind),
        Some(CandidateKind::Host),
        "the ICE arm must have a candidate to emit"
    );

    // The control: a plain anchor contributing no attribute of its own, on the layout every fixture
    // used to have. This is the floor the reorder must not move.
    group.bench_function("passthrough_session_level_c", |bencher| {
        bencher.iter(|| {
            sdp::rewrite(
                black_box(&session_level),
                muxed_engine(),
                IceRewrite::Keep,
                None,
                None,
                TextRewrite::None,
            )
            .expect("rewrite")
        });
    });

    group.bench_function("passthrough_media_level_c", |bencher| {
        bencher.iter(|| {
            sdp::rewrite(
                black_box(&media_level),
                muxed_engine(),
                IceRewrite::Keep,
                None,
                None,
                TextRewrite::None,
            )
            .expect("rewrite")
        });
    });

    // One inserted attribute, on the layout that has a prelude to keep it behind.
    group.bench_function("inserts_rtcp_media_level_c", |bencher| {
        bencher.iter(|| {
            sdp::rewrite(
                black_box(&media_level),
                demuxed_engine(),
                IceRewrite::Keep,
                None,
                None,
                TextRewrite::None,
            )
            .expect("rewrite")
        });
    });

    // The largest block the engine contributes: ICE-lite re-origination.
    group.bench_function("reoriginates_ice_media_level_c", |bencher| {
        bencher.iter(|| {
            sdp::rewrite(
                black_box(&ice_offer),
                muxed_engine(),
                IceRewrite::Reoriginate(IceAdvertisement {
                    ufrag: "ENGUF",
                    pwd: "engpassword01234567",
                    candidates: &candidates,
                }),
                None,
                None,
                TextRewrite::None,
            )
            .expect("rewrite")
        });
    });

    group.finish();
}

criterion_group!(benches, sdp_rewrite);
criterion_main!(benches);
