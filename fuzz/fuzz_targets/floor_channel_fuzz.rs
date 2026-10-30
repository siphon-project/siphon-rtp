#![no_main]
//! The MCPTT floor data channel (docs/control/json.md): a DTLS-authenticated browser peer is still
//! hostile input. Bring up an SCTP association and a `mcptt-floor` channel between a peer host and the
//! engine's channel driver, then send the fuzz input as binary and string messages and as a channel
//! label. Whatever it is, the driver must decode-or-drop: never panic, never read out of bounds, and
//! every APP packet it does read is a well-formed event.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use siphon_rtp_dtls::{DataChannelHost, DtlsRole};
use siphon_rtp_engine::app_events::AppEventQueue;
use siphon_rtp_engine::floor_channel::{
    floor_channel, ChannelDriver, FloorScope, FloorSink, FLOOR_CHANNEL_LABEL,
};
use siphon_rtp_engine::metrics::Metrics;

fn exchange(browser: &mut DataChannelHost, driver: &mut ChannelDriver) {
    for _ in 0..16 {
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

fuzz_target!(|data: &[u8]| {
    let events = AppEventQueue::new(64, Arc::new(Metrics::new()));
    let (_handle, plan) = floor_channel(FloorSink {
        scope: FloorScope::Room("fuzz".into()),
        tag: "seat".into(),
        events: Some(events.clone()),
    });
    let mut driver = ChannelDriver::new(DtlsRole::Server, plan);
    let mut browser = DataChannelHost::new(DtlsRole::Client);
    let now = Instant::now();
    if browser.start(now).is_err() {
        return;
    }
    exchange(&mut browser, &mut driver);

    // A channel whose label is the input: a hostile label must not open the floor or panic.
    let label = String::from_utf8_lossy(&data[..data.len().min(64)]).into_owned();
    if browser.open_channel(now, &label).is_ok() {
        exchange(&mut browser, &mut driver);
    }
    if browser.open_channel(now, FLOOR_CHANNEL_LABEL).is_err() {
        return;
    }
    exchange(&mut browser, &mut driver);

    let message = Bytes::copy_from_slice(data);
    for stream in [0u16, 2] {
        let _ = browser.send(now, stream, true, &message);
        let _ = browser.send(now, stream, false, &message);
    }
    exchange(&mut browser, &mut driver);
    for event in events.receiver().try_iter() {
        // An event is only ever raised for a well-formed APP packet.
        assert!(matches!(
            event,
            siphon_rtp_proto::Event::RtcpApp { .. }
        ));
    }
});
