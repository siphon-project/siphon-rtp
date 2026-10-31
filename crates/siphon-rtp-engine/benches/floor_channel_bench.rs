#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

//! The per-message cost of MCPTT floor control over a WebRTC data channel (docs/control/json.md),
//! with no sockets: SCTP (RFC 9260) and DCEP (RFC 8832) run in memory between a browser-side host and
//! the engine's channel driver, minus only the DTLS record layer, whose per-record cost is the DTLS
//! bridge bench's. One Floor Request from the browser's SCTP packet to the controller's `rtcp_app`
//! event, and one Floor Granted from the controller's `send_rtcp_app` to the browser's SCTP packet.
//! The event and the SCTP user message allocate (owned strings and payloads the controller connection
//! and the SCTP stack keep); there is no per-message task or lock.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_dtls::{DataChannelEvent, DataChannelHost, DtlsRole};
use siphon_rtp_engine::app_events::AppEventQueue;
use siphon_rtp_engine::floor_channel::{
    floor_channel, submit_floor_message, ChannelDriver, FloorChannelHandle, FloorScope, FloorSink,
    FLOOR_CHANNEL_LABEL,
};
use siphon_rtp_engine::metrics::Metrics;

/// TS 24.380 §8.2.4 Floor Request.
const FLOOR_REQUEST: [u8; 16] = [
    0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05, 0x00,
];
/// TS 24.380 Floor Granted data.
const FLOOR_GRANTED_PAYLOAD: [u8; 12] = [
    0x01, 0x02, 0x00, 0x1E, 0x0E, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
];

/// Move packets both ways until neither side has any.
fn settle(browser: &mut DataChannelHost, driver: &mut ChannelDriver) {
    for _ in 0..32 {
        let now = Instant::now();
        let mut moved = false;
        while let Some(packet) = browser.poll_transmit(now) {
            moved = true;
            driver.on_packet(now, &packet);
        }
        let mut replies = Vec::new();
        driver.drain_with(now, |packet| replies.push(packet));
        moved |= !replies.is_empty();
        for packet in replies {
            browser.handle_packet(now, &packet);
        }
        if !moved {
            return;
        }
    }
}

struct Rig {
    browser: DataChannelHost,
    driver: ChannelDriver,
    handle: FloorChannelHandle,
    events: AppEventQueue,
}

fn rig() -> Rig {
    let events = AppEventQueue::new(4096, Arc::new(Metrics::new()));
    let (handle, plan) = floor_channel(FloorSink {
        scope: FloorScope::Room("bench".into()),
        tag: "seat".into(),
        events: Some(events.clone()),
    });
    let mut driver = ChannelDriver::new(DtlsRole::Server, plan);
    let mut browser = DataChannelHost::new(DtlsRole::Client);
    browser.start(Instant::now()).unwrap();
    settle(&mut browser, &mut driver);
    browser
        .open_channel(Instant::now(), FLOOR_CHANNEL_LABEL)
        .unwrap();
    settle(&mut browser, &mut driver);
    assert!(handle.is_open(), "the floor channel opened");
    Rig {
        browser,
        driver,
        handle,
        events,
    }
}

fn bench(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("floor_channel");

    // Browser -> controller: the SCTP packet of a binary floor message to the `rtcp_app` event.
    let mut inbound = rig();
    let request = Bytes::from_static(&FLOOR_REQUEST);
    let receiver = inbound.events.receiver();
    group.bench_function("ingress_to_event", |bencher| {
        bencher.iter(|| {
            let now = Instant::now();
            inbound.browser.send(now, 0, true, &request).unwrap();
            while let Some(packet) = inbound.browser.poll_transmit(now) {
                inbound.driver.on_packet(now, black_box(&packet));
            }
            // The SACK the engine answers with keeps the association's window moving.
            let mut acknowledgements = Vec::new();
            inbound
                .driver
                .drain_with(now, |packet| acknowledgements.push(packet));
            for packet in acknowledgements {
                inbound.browser.handle_packet(now, &packet);
            }
            black_box(receiver.try_recv().unwrap());
        });
    });

    // Controller -> browser: `send_rtcp_app` on the floor stream to the SCTP packet.
    let mut outbound = rig();
    let writer = outbound.driver.writer().unwrap();
    group.bench_function("send_to_packet", |bencher| {
        bencher.iter(|| {
            let now = Instant::now();
            let pending = submit_floor_message(
                &outbound.handle,
                0x5566_7788,
                *b"MCPT",
                17,
                &FLOOR_GRANTED_PAYLOAD,
            )
            .unwrap();
            let message = writer.try_recv().unwrap();
            outbound.driver.on_outbound(now, message);
            let mut packets = Vec::new();
            outbound
                .driver
                .drain_with(now, |packet| packets.push(packet));
            for packet in packets {
                for event in outbound.browser.handle_packet(now, black_box(&packet)) {
                    black_box(matches!(event, DataChannelEvent::Message { .. }));
                }
            }
            outbound.driver.complete_sends(&Ok(()));
            drop(pending);
            // The browser's SACK back to the engine.
            while let Some(packet) = outbound.browser.poll_transmit(now) {
                outbound.driver.on_packet(now, &packet);
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
