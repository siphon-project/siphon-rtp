#![allow(clippy::unwrap_used, reason = "tests")]

use super::*;
use crate::sdp;
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::SourceFilter;
use std::cell::Cell;

fn offered(fmtp: &str) -> Vec<CodecSpec> {
    let text = format!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
         m=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 {fmtp}\r\n"
    );
    sdp::parse(&text).unwrap().audio_codecs()
}

fn config(index: u64) -> ForwardSeatConfig {
    ForwardSeatConfig {
        tag: format!("seat-{index}"),
        endpoint: EndpointId(index),
        egress_destination: format!("192.0.2.{index}:4000").parse().unwrap(),
        accepted_source: SourceFilter::Any,
        latch: true,
        audio_payload_type: 96,
        telephone_event: None,
        secure: None,
        secure_pending: false,
        ice_pending: false,
        egress_ssrc: index as u32,
        initial_sequence: 0,
        initial_timestamp: 0,
        floor: None,
        app_events: None,
    }
}

async fn join(
    registry: &ForwardRegistry,
    datapath: &UdpLoopbackDatapath,
    index: u64,
    fmtp: &str,
    events: Option<flume::Sender<Event>>,
) -> Result<(), ForwardRefusal> {
    let offer = offered(fmtp);
    let (proposed, _) = RoomCodec::from_offer(&offer).unwrap();
    registry
        .join(
            "group",
            proposed,
            &offer[0],
            config(index),
            1,
            events,
            datapath.clone(),
        )
        .await
}

#[tokio::test]
async fn the_first_join_creates_the_room_and_the_last_leave_ends_it() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    join(&registry, &datapath, 1, "octet-align=1", None)
        .await
        .unwrap();
    join(&registry, &datapath, 2, "octet-align=1", None)
        .await
        .unwrap();
    assert_eq!(registry.room_count(), 1);
    assert_eq!(registry.seat_count(), 2);
    assert!(registry.owns(EndpointId(1)) && registry.owns(EndpointId(2)));
    assert_eq!(registry.seat_at(EndpointId(2)).unwrap().1, "seat-2");
    assert_eq!(registry.leave("group", "seat-1"), vec![EndpointId(1)]);
    assert!(!registry.owns(EndpointId(1)));
    assert!(registry.contains("group"));
    assert!(registry.leave("group", "ghost").is_empty());
    assert_eq!(registry.leave("group", "seat-2"), vec![EndpointId(2)]);
    assert_eq!(registry.room_count(), 0, "the last leave removes the room");
    assert_eq!(registry.seat_count(), 0);
}

#[tokio::test]
async fn a_seat_that_cannot_read_the_rooms_codec_is_refused_and_leaves_nothing() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    join(&registry, &datapath, 1, "octet-align=1", None)
        .await
        .unwrap();
    let refusal = join(&registry, &datapath, 2, "octet-align=0", None)
        .await
        .unwrap_err();
    assert!(
        refusal
            .to_string()
            .starts_with("the room carries AMR-WB/16000 (octet-aligned)"),
        "{refusal}"
    );
    assert_eq!(registry.seat_count(), 1);
    assert!(!registry.owns(EndpointId(2)));
}

#[tokio::test]
async fn a_duplicate_tag_takes_nothing_from_the_room() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    join(&registry, &datapath, 1, "octet-align=1", None)
        .await
        .unwrap();
    join(&registry, &datapath, 1, "octet-align=1", None)
        .await
        .unwrap_err();
    assert_eq!(registry.seat_count(), 1, "a duplicate tag takes nothing");
    registry.leave("group", "seat-1");
    assert_eq!(registry.room_count(), 0);
}

#[tokio::test]
async fn set_source_answers_for_an_unknown_tag_and_an_unknown_room() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    assert_eq!(
        registry.set_source("group", None, None).await,
        Err(ForwardRefusal::UnknownRoom("group".to_string()))
    );
    join(&registry, &datapath, 1, "octet-align=1", None)
        .await
        .unwrap();
    assert_eq!(
        registry
            .set_source("group", Some("ghost".to_string()), None)
            .await,
        Err(ForwardRefusal::Room(ForwardError::UnknownTag(
            "ghost".to_string()
        )))
    );
    registry
        .set_source("group", Some("seat-1".to_string()), None)
        .await
        .unwrap();
    registry.set_source("group", None, None).await.unwrap();
}

#[tokio::test]
async fn a_quiet_seat_is_reported_once_and_never_freed() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    let (sink, events) = flume::unbounded();
    join(&registry, &datapath, 1, "octet-align=1", Some(sink))
        .await
        .unwrap();
    let last = Cell::new(Some(5u64));
    let activity = |_endpoint: EndpointId| last.get();

    // Joined at tick 1, heard at tick 5: 9 ticks quiet at tick 14 is under a 10-tick budget.
    assert_eq!(registry.scan_inactive(14, 10, activity), 0);
    assert!(events.try_recv().is_err());
    // 10 ticks quiet: reported.
    assert_eq!(registry.scan_inactive(15, 10, activity), 1);
    assert_eq!(
        events.try_recv().unwrap(),
        Event::ForwardSeatInactive {
            conference_id: "group".to_string(),
            from_tag: "seat-1".to_string(),
        }
    );
    // Still quiet: not raised again.
    assert_eq!(registry.scan_inactive(300, 10, activity), 0);
    assert!(events.try_recv().is_err());
    assert_eq!(registry.seat_count(), 1, "silence never frees a seat");
    // Heard from again: re-armed, and the next silence is reported once more.
    last.set(Some(400));
    assert_eq!(registry.scan_inactive(401, 10, activity), 0);
    assert_eq!(registry.scan_inactive(411, 10, activity), 1);
    assert!(events.try_recv().is_ok());
}

#[tokio::test]
async fn a_seat_that_never_sent_anything_is_measured_from_its_join() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    let (sink, events) = flume::unbounded();
    join(&registry, &datapath, 1, "octet-align=1", Some(sink))
        .await
        .unwrap();
    // The datapath has no activity for it: the join tick (1) is the baseline.
    assert_eq!(registry.scan_inactive(5, 10, |_| None), 0);
    assert_eq!(registry.scan_inactive(11, 10, |_| None), 1);
    assert!(events.try_recv().is_ok());
}

#[tokio::test]
async fn a_zero_budget_disables_the_inactivity_scan() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    let (sink, events) = flume::unbounded();
    join(&registry, &datapath, 1, "octet-align=1", Some(sink))
        .await
        .unwrap();
    assert_eq!(registry.scan_inactive(1_000_000, 0, |_| None), 0);
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn deregister_hands_back_every_seat_endpoint() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    join(&registry, &datapath, 1, "octet-align=1", None)
        .await
        .unwrap();
    join(&registry, &datapath, 2, "octet-align=1", None)
        .await
        .unwrap();
    let mut freed = registry.deregister("group");
    freed.sort_by_key(|endpoint| endpoint.0);
    assert_eq!(freed, vec![EndpointId(1), EndpointId(2)]);
    assert_eq!(registry.room_count(), 0);
    assert!(!registry.owns(EndpointId(1)));
    assert!(registry.deregister("group").is_empty());
}
