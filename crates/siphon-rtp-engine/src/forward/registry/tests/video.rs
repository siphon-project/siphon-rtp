//! The registry's bookkeeping of a seat's video endpoint and of the room's video format.

use super::*;
use crate::forward::VideoConfig;
use crate::sdp::video::{RoomVideoFormat, VideoFeedback};
use crate::sdp::MediaDirection;

fn format(level: &str) -> RoomVideoFormat {
    RoomVideoFormat {
        packetization_mode: 1,
        profile_level_id: Some(level.to_string()),
        fmtp: Some(format!("profile-level-id={level};packetization-mode=1")),
    }
}

/// Seat `index` with a video endpoint `100 + index`.
fn video_config(index: u64, video_format: RoomVideoFormat) -> ForwardSeatConfig {
    let mut seat = config(index);
    seat.video = Some(VideoConfig {
        endpoint: EndpointId(100 + index),
        destination: format!("192.0.2.{index}:5000").parse().unwrap(),
        accepted_source: SourceFilter::Any,
        payload_type: 99,
        direction: MediaDirection::SendRecv,
        egress_ssrc: 0xF000_0000 | index as u32,
        initial_sequence: 0,
        initial_timestamp: 0,
        format: video_format,
        feedback: VideoFeedback::default(),
        cname: String::new(),
        bundled: false,
    });
    seat
}

async fn join_with_video(
    registry: &ForwardRegistry,
    datapath: &UdpLoopbackDatapath,
    seat: ForwardSeatConfig,
) -> Result<(), ForwardRefusal> {
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
}

#[tokio::test]
async fn a_video_endpoint_is_routed_resolved_and_freed_with_its_seat() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    join_with_video(&registry, &datapath, video_config(1, format("640c1f")))
        .await
        .unwrap();
    assert!(registry.owns(EndpointId(1)) && registry.owns(EndpointId(101)));
    assert_eq!(
        registry.seat_at(EndpointId(101)),
        Some(("group".to_string(), "seat-1".to_string()))
    );
    assert_eq!(
        registry.leave("group", "seat-1"),
        vec![EndpointId(1), EndpointId(101)],
        "audio first, then video"
    );
    assert!(!registry.owns(EndpointId(101)));
    assert_eq!(registry.room_count(), 0);
}

#[tokio::test]
async fn deregister_hands_back_the_video_endpoints_too() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    join_with_video(&registry, &datapath, video_config(1, format("640c1f")))
        .await
        .unwrap();
    join_with_video(&registry, &datapath, video_config(2, format("640c1f")))
        .await
        .unwrap();
    let mut freed = registry.deregister("group");
    freed.sort_by_key(|endpoint| endpoint.0);
    assert_eq!(
        freed,
        vec![
            EndpointId(1),
            EndpointId(2),
            EndpointId(101),
            EndpointId(102)
        ]
    );
    assert!(!registry.owns(EndpointId(102)));
}

#[tokio::test]
async fn the_first_seat_with_video_fixes_the_rooms_video_format() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    // An audio-only first seat fixes none.
    join(&registry, &datapath, 1, "octet-align=1", None)
        .await
        .unwrap();
    assert_eq!(registry.room_video_format("group"), None);
    join_with_video(&registry, &datapath, video_config(2, format("640c1f")))
        .await
        .unwrap();
    assert_eq!(registry.room_video_format("group"), Some(format("640c1f")));
    assert_eq!(registry.room_video_format("nowhere"), None);
}

#[tokio::test]
async fn a_seat_in_another_video_format_is_refused_and_leaves_nothing() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    join_with_video(&registry, &datapath, video_config(1, format("640c1f")))
        .await
        .unwrap();
    let refusal = join_with_video(&registry, &datapath, video_config(2, format("42e01f")))
        .await
        .unwrap_err();
    assert!(refusal.to_string().contains("video format"), "{refusal}");
    assert_eq!(registry.seat_count(), 1);
    assert!(!registry.owns(EndpointId(2)) && !registry.owns(EndpointId(102)));
    assert_eq!(registry.room_video_format("group"), Some(format("640c1f")));
}

#[tokio::test]
async fn the_format_is_forgotten_when_the_last_video_seat_leaves() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    join(&registry, &datapath, 1, "octet-align=1", None)
        .await
        .unwrap();
    join_with_video(&registry, &datapath, video_config(2, format("640c1f")))
        .await
        .unwrap();
    registry.leave("group", "seat-2");
    assert_eq!(registry.room_video_format("group"), None);
    // A new video seat may now fix another format.
    join_with_video(&registry, &datapath, video_config(3, format("42e01f")))
        .await
        .unwrap();
    assert_eq!(registry.room_video_format("group"), Some(format("42e01f")));
}

#[tokio::test]
async fn video_traffic_counts_as_the_seat_being_alive() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    let (sink, events) = flume::unbounded();
    let offer = offered("octet-align=1");
    let (proposed, _) = RoomCodec::from_offer(&offer).unwrap();
    registry
        .join(
            "group",
            proposed,
            &offer[0],
            video_config(1, format("640c1f")),
            1,
            Some(sink),
            datapath.clone(),
        )
        .await
        .unwrap();
    // Only the video endpoint was heard from, at tick 500.
    let activity = |endpoint: EndpointId| (endpoint == EndpointId(101)).then_some(500);
    assert_eq!(registry.scan_inactive(505, 10, activity), 0);
    assert!(events.try_recv().is_err());
    assert_eq!(registry.scan_inactive(510, 10, activity), 1);
}

/// A video RTP packet of seat `index`, at its video endpoint.
fn video_packet_of(index: u64, sequence: u16, payload: &[u8]) -> RxPacket {
    let mut datagram = vec![0u8; 12];
    datagram[0] = 0x80;
    datagram[1] = 99;
    datagram[2..4].copy_from_slice(&sequence.to_be_bytes());
    datagram[8..12].copy_from_slice(&(0x1000_0000 | index as u32).to_be_bytes());
    datagram.extend_from_slice(payload);
    RxPacket {
        endpoint: EndpointId(100 + index),
        source: format!("192.0.2.{index}:5000").parse().unwrap(),
        arrival: 0,
        data: bytes::Bytes::from(datagram),
    }
}

#[tokio::test(start_paused = true)]
async fn the_actor_gives_up_on_a_keyframe_after_two_seconds_of_its_own_clock_and_says_so() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    join_with_video(&registry, &datapath, video_config(1, format("640c1f")))
        .await
        .unwrap();
    join_with_video(&registry, &datapath, video_config(2, format("640c1f")))
        .await
        .unwrap();
    let (sink, events) = flume::unbounded();
    registry
        .set_source("group", Some("seat-1".to_string()), Some(sink))
        .await
        .unwrap();
    // A picture that is not a keyframe, so the receiver stays held back.
    registry.dispatch(video_packet_of(1, 1, &[0x41, 0x9A]));
    tokio::time::sleep(std::time::Duration::from_millis(1900)).await;
    assert!(
        events
            .try_iter()
            .all(|event| !matches!(event, Event::ForwardKeyframe { .. })),
        "not yet: the room waits two seconds"
    );
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let reported: Vec<_> = events
        .try_iter()
        .filter_map(|event| match event {
            Event::ForwardKeyframe {
                from_tag,
                latency_ms,
                timed_out,
                ..
            } => Some((from_tag, latency_ms, timed_out)),
            _ => None,
        })
        .collect();
    assert_eq!(reported, [("seat-1".to_string(), 2000, true)]);
}

#[tokio::test(start_paused = true)]
async fn the_actor_reports_the_keyframe_that_answered_the_switch_with_its_latency() {
    let registry = ForwardRegistry::default();
    let datapath = UdpLoopbackDatapath::new();
    join_with_video(&registry, &datapath, video_config(1, format("640c1f")))
        .await
        .unwrap();
    join_with_video(&registry, &datapath, video_config(2, format("640c1f")))
        .await
        .unwrap();
    let (sink, events) = flume::unbounded();
    registry
        .set_source("group", Some("seat-1".to_string()), Some(sink))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    registry.dispatch(video_packet_of(1, 1, &[0x65, 0x88]));
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let reported: Vec<_> = events
        .try_iter()
        .filter_map(|event| match event {
            Event::ForwardKeyframe {
                latency_ms,
                timed_out,
                ..
            } => Some((latency_ms, timed_out)),
            _ => None,
        })
        .collect();
    assert_eq!(reported, [(300, false)]);
}
