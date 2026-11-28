//! Full direct SIP/UDP and bidirectional probe run, without a proxy or relay.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use siphon_rtp_loadgen::sipload::{runner, RunPlan};
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

#[test]
fn fifty_calls_drain_all_media_and_leave_no_live_state() {
    let reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    let plan = RunPlan {
        target: format!("127.0.0.1:{port}").parse().unwrap(),
        local: Ipv4Addr::LOCALHOST,
        domain: "127.0.0.1".into(),
        cps: 25,
        duration: Duration::from_secs(2),
        hold: Duration::from_secs(1),
        users: 1,
        password: "secret".into(),
        uas_base_port: port - 1,
        uac_sockets: 2,
        media_sockets: 4,
        media_threads: 3,
        sip_threads: 2,
        media_base_port: 0,
        ptime: Duration::from_millis(20),
        skip_registration: true,
    };
    drop(reservation);
    let result = runner::run(plan).unwrap();
    assert_eq!(result.attempted, 50);
    assert_eq!(result.succeeded, 50);
    assert_eq!(result.failed, 0, "{:?}", result.failed_by_reason);
    assert_eq!(result.uas_failures, 0);
    assert_eq!(result.media.foreign, 0);
    assert!(result.media.sent > 0);
    assert_eq!(result.streams.len(), 100);
    for (id, stream) in &result.streams {
        assert_eq!(stream.sent, stream.received, "stream {id}");
    }
    assert_eq!(result.active_calls, 0);
    assert_eq!(result.pending_transactions, 0);
    assert_eq!(result.active_streams, 0);
}
