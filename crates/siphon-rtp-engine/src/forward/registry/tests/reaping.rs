//! The room backstop and the transcoded join, at the registry.

#![allow(clippy::unwrap_used, reason = "tests")]

use super::*;

fn timeouts(events: &flume::Receiver<Event>) -> Vec<(String, String)> {
    events
        .try_iter()
        .map(|event| match event {
            Event::MediaTimeout {
                call_id,
                from_tag,
                conference_id,
                reason,
            } => {
                assert_eq!(call_id, "", "a room seat has no call");
                assert_eq!(reason, siphon_rtp_proto::MediaTimeoutReason::NoMedia);
                (conference_id.unwrap(), from_tag)
            }
            other => panic!("expected media_timeout, got {other:?}"),
        })
        .collect()
}

#[tokio::test]
async fn a_room_where_every_seat_is_silent_is_freed_with_one_timeout_per_seat() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    let (first_sink, first_events) = flume::unbounded();
    let (second_sink, second_events) = flume::unbounded();
    join(&registry, &datapath, 1, "octet-align=1", Some(first_sink))
        .await
        .unwrap();
    join(&registry, &datapath, 2, "octet-align=1", Some(second_sink))
        .await
        .unwrap();
    // Joined at tick 1; the datapath has heard nothing. Just under the ceiling: kept.
    assert!(registry.reap_silent_rooms(100, 100, |_| None).is_empty());
    assert_eq!(registry.room_count(), 1);
    assert!(timeouts(&first_events).is_empty());

    let mut freed = registry.reap_silent_rooms(101, 100, |_| None);
    freed.sort_by_key(|endpoint| endpoint.0);
    assert_eq!(freed, vec![EndpointId(1), EndpointId(2)]);
    assert_eq!(registry.room_count(), 0);
    assert!(!registry.owns(EndpointId(1)) && !registry.owns(EndpointId(2)));
    assert_eq!(
        timeouts(&first_events),
        vec![("group".to_string(), "seat-1".to_string())]
    );
    assert_eq!(
        timeouts(&second_events),
        vec![("group".to_string(), "seat-2".to_string())]
    );
    assert!(registry.reap_silent_rooms(10_000, 100, |_| None).is_empty());
}

#[tokio::test]
async fn one_seat_that_was_heard_recently_keeps_the_whole_room() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    let (sink, events) = flume::unbounded();
    join(&registry, &datapath, 1, "octet-align=1", Some(sink))
        .await
        .unwrap();
    join(&registry, &datapath, 2, "octet-align=1", None)
        .await
        .unwrap();
    // Seat 2 sent an RTCP receiver report at tick 950; seat 1 has said nothing since it joined.
    let activity = |endpoint: EndpointId| (endpoint == EndpointId(2)).then_some(950);
    assert!(registry.reap_silent_rooms(1000, 100, activity).is_empty());
    assert_eq!(registry.seat_count(), 2, "no seat is reaped on its own");
    assert!(timeouts(&events).is_empty());
    // Once seat 2 has gone quiet too, the room goes.
    assert_eq!(registry.reap_silent_rooms(1050, 100, activity).len(), 2);
    assert_eq!(timeouts(&events).len(), 1);
}

#[tokio::test]
async fn floor_traffic_counts_as_the_seat_being_heard_from() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    let mut seat = config(1);
    seat.floor = Some(crate::forward::FloorConfig {
        endpoint: EndpointId(11),
        destination: "192.0.2.1:4002".parse().unwrap(),
        accepted_source: SourceFilter::Any,
        ice_gated: false,
    });
    let offer = offered("octet-align=1");
    let (proposed, _) = RoomCodec::from_offer(&offer).unwrap();
    registry
        .join(
            "group",
            proposed,
            &offer[0],
            seat,
            1,
            None,
            datapath.clone(),
        )
        .await
        .unwrap();
    let activity = |endpoint: EndpointId| (endpoint == EndpointId(11)).then_some(990);
    assert!(registry.reap_silent_rooms(1000, 100, activity).is_empty());
}

#[tokio::test]
async fn a_zero_ceiling_disables_the_room_backstop() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    join(&registry, &datapath, 1, "octet-align=1", None)
        .await
        .unwrap();
    assert!(registry
        .reap_silent_rooms(u64::MAX / 2, 0, |_| None)
        .is_empty());
    assert_eq!(registry.room_count(), 1);
}

fn pcmu_spec(payload_type: u8) -> CodecSpec {
    CodecSpec::new(payload_type, "PCMU", 8000, 1, 20)
}

#[tokio::test]
async fn a_transcoded_seat_joins_an_existing_room_and_never_creates_one() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    let (room_codec, _) = RoomCodec::from_offer(&[pcmu_spec(0)]).unwrap();
    let pcma = CodecSpec::new(8, "PCMA", 8000, 1, 20);

    // No room yet: refused rather than creating a room whose codec the seat does not speak.
    let refusal = registry
        .join_transcoded(
            "group",
            room_codec.clone(),
            &pcma,
            config(2),
            1,
            None,
            datapath.clone(),
        )
        .await
        .unwrap_err();
    assert_eq!(refusal, ForwardRefusal::UnknownRoom("group".to_string()));
    assert_eq!(registry.room_count(), 0);

    registry
        .join(
            "group",
            room_codec.clone(),
            &pcmu_spec(0),
            config(1),
            1,
            None,
            datapath.clone(),
        )
        .await
        .unwrap();
    registry
        .join_transcoded(
            "group",
            room_codec,
            &pcma,
            config(2),
            1,
            None,
            datapath.clone(),
        )
        .await
        .unwrap();
    assert_eq!(registry.seat_count(), 2);
    assert!(registry.owns(EndpointId(2)));
}

#[tokio::test]
async fn a_transcoded_seat_checked_against_another_codec_is_refused() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    join(&registry, &datapath, 1, "octet-align=1", None)
        .await
        .unwrap();
    let (stale, _) = RoomCodec::from_offer(&[pcmu_spec(0)]).unwrap();
    let refusal = registry
        .join_transcoded(
            "group",
            stale,
            &CodecSpec::new(8, "PCMA", 8000, 1, 20),
            config(2),
            1,
            None,
            datapath.clone(),
        )
        .await
        .unwrap_err();
    assert!(refusal.to_string().contains("codec changed"), "{refusal}");
    assert_eq!(registry.seat_count(), 1);
}

#[tokio::test]
async fn a_codec_the_room_cannot_transcode_is_refused_by_the_room_and_leaves_nothing() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    let (room_codec, _) = RoomCodec::from_offer(&[pcmu_spec(0)]).unwrap();
    registry
        .join(
            "group",
            room_codec.clone(),
            &pcmu_spec(0),
            config(1),
            1,
            None,
            datapath.clone(),
        )
        .await
        .unwrap();
    let refusal = registry
        .join_transcoded(
            "group",
            room_codec,
            &CodecSpec::new(13, "CN", 8000, 1, 20),
            config(2),
            1,
            None,
            datapath.clone(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        refusal,
        ForwardRefusal::Room(ForwardError::Transcode(_))
    ));
    assert_eq!(registry.seat_count(), 1, "the refused seat left nothing");
    assert!(!registry.owns(EndpointId(2)));
}
