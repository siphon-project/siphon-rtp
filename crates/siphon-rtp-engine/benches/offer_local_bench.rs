//! The call-setup cost of `offer_local`: the engine's own offer (the SDP it writes, and the leg it
//! binds), the caller's answer that completes it, and the delete that frees it again.
//!
//! A per-call number, not a per-packet one: it runs once per delayed-offer INVITE. The three rows
//! split where the time goes: writing the offer text alone, offer plus answer plus delete over the
//! UDP-loopback datapath (the plain shape, with the endpoint bind and the single-leg pipeline start
//! that dominate it), and the same with SDES keying, whose extra cost is minting and parsing the key.
//!
//! All addresses are the RFC 5737 documentation range or loopback.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use std::net::SocketAddr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_engine::sdp::{self, LocalOffer, LocalOfferKeying, TelephoneEvent};
use siphon_rtp_engine::{ClientId, Engine};
use siphon_rtp_proto::{CmdResult, Command, ProfileFlags};
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};

fn write_offer(criterion: &mut Criterion) {
    let codecs = [
        CodecSpec::new(9, "G722", 8000, 1, 20),
        CodecSpec::new(0, "PCMU", 8000, 1, 20),
        CodecSpec::new(8, "PCMA", 8000, 1, 20),
    ];
    let events = [TelephoneEvent {
        payload_type: 101,
        clock_rate_hz: 8000,
    }];
    let crypto = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
    let rtp: SocketAddr = "127.0.0.1:30000".parse().expect("addr");
    let advertised = "192.0.2.1".parse().expect("ip");
    let mut group = criterion.benchmark_group("offer_local_write");
    for (name, keying) in [
        ("plain", LocalOfferKeying::Plain),
        ("sdes", LocalOfferKeying::Sdes(&crypto)),
    ] {
        group.bench_function(name, |bencher| {
            bencher.iter(|| {
                black_box(sdp::local_audio_offer(&LocalOffer {
                    rtp,
                    rtcp_port: Some(30001),
                    rtcp_mux: false,
                    rtcp_mux_only: false,
                    advertised,
                    session_id: 1,
                    codecs: &codecs,
                    events: &events,
                    keying,
                    ice: None,
                }))
            });
        });
    }
    group.finish();
}

fn answer_sdp(address: SocketAddr, crypto: Option<&CryptoAttribute>) -> String {
    let (transport, line) = match crypto {
        Some(crypto) => ("RTP/SAVP", format!("a={}\r\n", crypto.to_attribute_value())),
        None => ("RTP/AVP", String::new()),
    };
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} {transport} 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n{line}",
        ip = address.ip(),
        port = address.port(),
    )
}

fn setup_cycle(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let caller: SocketAddr = "127.0.0.1:40000".parse().expect("addr");
    let mut group = criterion.benchmark_group("offer_local_cycle");
    for (name, transport) in [("plain", None), ("sdes", Some("RTP/SAVP"))] {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let profile = ProfileFlags {
            transport_protocol: transport.map(str::to_string),
            flags: vec!["codec-strip-all".into(), "codec-except-PCMU".into()],
            ..Default::default()
        };
        group.bench_function(name, |bencher| {
            bencher.iter(|| {
                runtime.block_on(async {
                    let offered = engine
                        .handle(
                            ClientId(1),
                            Command::OfferLocal {
                                call_id: "bench".into(),
                                from_tag: "tag-a".into(),
                                profile: profile.clone(),
                            },
                        )
                        .await;
                    let CmdResult::Ok {
                        sdp: Some(offer), ..
                    } = offered
                    else {
                        panic!("offer_local failed: {offered:?}");
                    };
                    let key = sdp::parse(&offer)
                        .expect("offer")
                        .crypto
                        .first()
                        .map(|offered| CryptoAttribute::answer_to(offered).expect("key"));
                    let completed = engine
                        .handle(
                            ClientId(1),
                            Command::Answer {
                                call_id: "bench".into(),
                                from_tag: "tag-a".into(),
                                to_tag: "tag-b".into(),
                                sdp: answer_sdp(caller, key.as_ref()),
                                profile: ProfileFlags::default(),
                            },
                        )
                        .await;
                    assert!(matches!(completed, CmdResult::Ok { .. }), "{completed:?}");
                    black_box(
                        engine
                            .handle(
                                ClientId(1),
                                Command::Delete {
                                    call_id: "bench".into(),
                                    from_tag: "tag-a".into(),
                                    to_tag: None,
                                },
                            )
                            .await,
                    )
                })
            });
        });
    }
    group.finish();
}

criterion_group!(benches, write_offer, setup_cycle);
criterion_main!(benches);
