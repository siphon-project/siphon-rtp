//! The cost of the first-media poll (`Engine::detect_media_started`).
//!
//! A **per-tick** number, paid every 20 ms by the daemon: it visits each RTP endpoint still waiting
//! for its first packet. A leg leaves that set on its first packet, so on a settled box the set holds
//! only calls in setup — ringing, or answered but not yet sending. The rows are that set's size.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_engine::{ClientId, Engine};
use siphon_rtp_proto::{CmdResult, Command, ProfileFlags};

/// A PCMU offer from a documentation-range address, which never sends: its leg stays waiting.
fn offer_sdp(port: u16) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    )
}

fn media_started_benches(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let mut group = criterion.benchmark_group("media_started_poll");
    for waiting in [0usize, 100, 1000] {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        runtime.block_on(async {
            for index in 0..waiting {
                let port = 20_000 + u16::try_from(index * 2).expect("port");
                let answered = engine
                    .handle(
                        ClientId(1),
                        Command::AnswerLocal {
                            call_id: format!("call-{index}"),
                            from_tag: "tag-a".into(),
                            sdp: offer_sdp(port),
                            profile: ProfileFlags::default(),
                        },
                    )
                    .await;
                assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");
            }
        });
        group.bench_with_input(
            BenchmarkId::from_parameter(waiting),
            &waiting,
            |bencher, _| bencher.iter(|| black_box(engine.detect_media_started())),
        );
    }
    group.finish();
}

criterion_group!(benches, media_started_benches);
criterion_main!(benches);
