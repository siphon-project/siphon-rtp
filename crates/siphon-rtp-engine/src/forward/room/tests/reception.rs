//! What a seat receives, per stream (3GPP TS 24.581 §6.3.7: the receiver's Active SSRC List): the
//! audio and the video can each be switched off for one seat, and back on, while its own media and
//! its control stream are untouched.

use super::floor::{floor_granted, floor_room, sent_app};
use super::preserve::{preserve_room, srtp_like};
use super::video::{all_sendrecv, fu_a, rx_video, video_rtp, video_seat, FIRST_VIDEO_PAYLOAD_TYPE};
use super::video_webrtc::{clear_of, mixed_room, phone};
use super::*;
use crate::sdp::video::VideoFeedback;
use crate::sdp::MediaDirection;
use siphon_rtp_media::rtcp::{self, Feedback};
use siphon_rtp_proto::RtcpAppStream;
use siphon_rtp_srtp::leg::PacketKind;

const SPS: [u8; 4] = [0x67, 0x64, 0x00, 0x1F];
const PPS: [u8; 3] = [0x68, 0xEE, 0x3C];
const IDR: [u8; 3] = [0x65, 0x88, 0x84];
const SLICE: [u8; 3] = [0x41, 0x9A, 0x00];

/// Seat `index`'s audio, sequence `sequence`, as the source `seat-1` sends it.
fn audio_from_one(room: &mut ForwardRoom, sequence: u16) -> Vec<(u64, Vec<u8>)> {
    let packet = rx(
        1,
        u64::from(sequence) * 20_000,
        rtp(
            96,
            sequence,
            u32::from(sequence) * 320,
            0x1111_1111,
            &[1, 2, 3],
        ),
    );
    room.ingest(&packet);
    forwarded(room, &packet)
        .into_iter()
        .map(|(endpoint, _, data)| (endpoint.0, data))
        .collect()
}

fn endpoints(sent: &[(u64, Vec<u8>)]) -> Vec<u64> {
    sent.iter().map(|(endpoint, _)| *endpoint).collect()
}

/// A room of video seats that all accept every feedback, so the source can be asked for a keyframe.
fn video_room_with_feedback(seats: u8) -> ForwardRoom {
    let mut room = amr_wb_room();
    for index in 1..=seats {
        let mut config = video_seat(index, MediaDirection::SendRecv);
        if let Some(video) = config.video.as_mut() {
            video.feedback = VideoFeedback::SUPPORTED;
            video.cname = format!("seat-{index}-cname");
        }
        room.add_seat(config, 0).unwrap();
    }
    room
}

/// Seat 1's video packet; what the room sent, `(endpoint, datagram)` each.
fn video_from_one(room: &mut ForwardRoom, sequence: u16, payload: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let packet = rx_video(
        1,
        u64::from(sequence) * 33_000,
        video_rtp(
            FIRST_VIDEO_PAYLOAD_TYPE + 1,
            sequence,
            u32::from(sequence) * 3000,
            0x1000_0001,
            false,
            payload,
        ),
    );
    room.ingest(&packet);
    forwarded(room, &packet)
        .into_iter()
        .map(|(endpoint, _, data)| (endpoint.0, data))
        .collect()
}

fn poll(room: &mut ForwardRoom, now_ms: u64) -> Vec<Outbound> {
    let mut out = Vec::new();
    room.poll_keyframe(now_ms, &mut out);
    out
}

/// A room whose source `seat-1` has sent its parameter sets and a first IDR, so every receiver
/// streams, and whose switch request is over.
fn streaming(seats: u8) -> ForwardRoom {
    let mut room = video_room_with_feedback(seats);
    video_from_one(&mut room, 10, &SPS);
    video_from_one(&mut room, 11, &PPS);
    room.set_source(Some("seat-1")).unwrap();
    poll(&mut room, 0);
    assert_eq!(
        video_from_one(&mut room, 12, &IDR).len(),
        3 * (seats as usize - 1)
    );
    poll(&mut room, 10);
    room
}

#[test]
fn audio_off_drops_for_that_seat_only_and_on_resumes_with_a_continuous_sequence() {
    let mut room = room_of(3);
    room.set_source(Some("seat-1")).unwrap();
    let sent = audio_from_one(&mut room, 1);
    assert_eq!(endpoints(&sent), [2, 3]);
    let before = parsed(&sent.iter().find(|(endpoint, _)| *endpoint == 2).unwrap().1);

    room.set_reception("seat-2", false, true).unwrap();
    for sequence in [2u16, 3] {
        let sent = audio_from_one(&mut room, sequence);
        assert_eq!(
            endpoints(&sent),
            [3],
            "seat-2 is sent nothing, seat-3 still is"
        );
    }

    room.set_reception("seat-2", true, true).unwrap();
    let sent = audio_from_one(&mut room, 4);
    assert_eq!(endpoints(&sent), [2, 3]);
    let after = parsed(&sent.iter().find(|(endpoint, _)| *endpoint == 2).unwrap().1);
    // RFC 3550 §5.1: the seat's own stream carries on from where it stopped, no jump in sequence.
    assert_eq!(
        after.2,
        before.2.wrapping_add(1),
        "continuous sequence number"
    );
    assert_eq!(after.4, before.4, "the same egress SSRC");
    assert!(after.0, "a new run starts with the marker bit");
    assert!(
        after.3.wrapping_sub(before.3) < 0x8000_0000,
        "the timestamp never steps back"
    );
}

#[test]
fn setting_the_same_reception_twice_changes_nothing() {
    let mut room = room_of(2);
    room.set_source(Some("seat-1")).unwrap();
    audio_from_one(&mut room, 1);
    room.set_reception("seat-2", true, true).unwrap();
    assert_eq!(endpoints(&audio_from_one(&mut room, 2)), [2]);
    room.set_reception("seat-2", false, true).unwrap();
    room.set_reception("seat-2", false, true).unwrap();
    assert!(audio_from_one(&mut room, 3).is_empty());
    assert_eq!(
        room.seat_stats("seat-2")
            .unwrap()
            .reception_off_dropped_audio,
        1
    );
}

#[test]
fn an_unknown_seat_is_refused() {
    let mut room = room_of(1);
    assert_eq!(
        room.set_reception("nobody", false, false),
        Err(ForwardError::UnknownTag("nobody".to_string()))
    );
}

#[test]
fn an_off_seat_still_sends_and_can_be_the_audio_source() {
    let mut room = room_of(2);
    room.set_reception("seat-1", false, false).unwrap();
    room.set_source(Some("seat-1")).unwrap();
    let sent = audio_from_one(&mut room, 1);
    assert_eq!(
        endpoints(&sent),
        [2],
        "the off seat's own audio is forwarded"
    );
    assert_eq!(room.seat_stats("seat-1").unwrap().not_source_dropped, 0);
    // ... and it is not sent what seat 2 says once seat 2 is the source.
    room.set_source(Some("seat-2")).unwrap();
    let packet = rx(2, 100_000, rtp(96, 1, 0, 0x2222_2222, &[9]));
    room.ingest(&packet);
    assert!(forwarded(&mut room, &packet).is_empty());
}

#[test]
fn an_off_seat_can_be_the_video_source() {
    let mut room = video_room_with_feedback(2);
    room.set_reception("seat-1", false, false).unwrap();
    room.set_source(Some("seat-1")).unwrap();
    let sent = video_from_one(&mut room, 1, &IDR);
    assert_eq!(endpoints(&sent), [102], "the source's video reaches seat 2");
}

#[test]
fn a_seat_in_another_codec_is_gated_too() {
    use super::transcode::{
        add_cross, add_same, config_for, fan_out, pcma, pcmu_room, tone_stream,
    };
    let mut room = pcmu_room();
    add_same(&mut room, config_for(1, 0));
    add_cross(&mut room, config_for(2, 8), &pcma());
    add_same(&mut room, config_for(3, 0));
    room.set_source(Some("seat-1")).unwrap();
    let tone = tone_stream(&super::transcode::pcmu(), 3);
    room.set_reception("seat-2", false, true).unwrap();
    let packet = rx(1, 20_000, rtp(0, 10, 1600, 0x1111_1111, &tone[0]));
    let sent = fan_out(&mut room, &packet);
    assert_eq!(endpoints(&sent), [3], "the transcoded seat is sent nothing");
    assert_eq!(
        room.seat_stats("seat-2")
            .unwrap()
            .reception_off_dropped_audio,
        1
    );
    room.set_reception("seat-2", true, true).unwrap();
    let packet = rx(1, 40_000, rtp(0, 11, 1760, 0x1111_1111, &tone[1]));
    let sent = fan_out(&mut room, &packet);
    assert_eq!(endpoints(&sent), [2, 3]);
}

#[test]
fn video_off_then_on_waits_for_the_keyframe_and_asks_the_source_for_one() {
    let mut room = streaming(3);
    room.set_reception("seat-2", true, false).unwrap();
    // Off: nothing to seat 2, seat 3 carries on.
    assert_eq!(endpoints(&video_from_one(&mut room, 13, &SLICE)), [103]);
    // An IDR that goes by while it is off is not sent to it either, nor are the parameter sets
    // replayed before it.
    assert_eq!(endpoints(&video_from_one(&mut room, 14, &IDR)), [103]);
    assert_eq!(
        room.seat_stats("seat-2")
            .unwrap()
            .reception_off_dropped_video,
        2
    );
    assert!(
        poll(&mut room, 100).is_empty(),
        "no request while it is off"
    );

    room.drain_events().for_each(drop); // the switch's own keyframe event
    room.set_reception("seat-2", true, true).unwrap();
    let out = poll(&mut room, 200);
    assert_eq!(out.len(), 1, "a PLI to the source for the seat: {out:?}");
    assert_eq!(out[0].endpoint, EndpointId(101));
    let feedback: Vec<_> = rtcp::feedback_packets(&out[0].data)
        .map(|item| item.unwrap())
        .collect();
    assert!(matches!(feedback[0], Feedback::Pli { .. }), "{feedback:?}");
    // The gate: nothing until the keyframe.
    assert_eq!(endpoints(&video_from_one(&mut room, 15, &SLICE)), [103]);
    assert_eq!(
        room.seat_stats("seat-2")
            .unwrap()
            .video_dropped_awaiting_keyframe,
        1
    );
    // The keyframe: parameter sets and the IDR, on the seat's own stream where it stopped.
    let sent = video_from_one(&mut room, 16, &IDR);
    let to_two: Vec<_> = sent
        .iter()
        .filter(|(endpoint, _)| *endpoint == 102)
        .map(|(_, data)| parsed(data))
        .collect();
    assert_eq!(to_two.len(), 3, "SPS, PPS and the IDR");
    assert_eq!(
        to_two.iter().map(|sent| sent.2).collect::<Vec<_>>(),
        [2003, 2004, 2005],
        "continuous after the three packets it received before"
    );
    poll(&mut room, 300);
    // A keyframe the seat asked for itself is not a source change: no event.
    assert!(room
        .drain_events()
        .all(|event| !matches!(event, siphon_rtp_proto::Event::ForwardKeyframe { .. })));
}

#[test]
fn turning_video_on_with_no_source_asks_nothing() {
    let mut room = all_sendrecv(2);
    room.set_reception("seat-2", true, false).unwrap();
    room.set_reception("seat-2", true, true).unwrap();
    assert!(poll(&mut room, 0).is_empty());
    assert!(!room.keyframe_active());
}

#[test]
fn a_nack_from_an_off_seat_is_not_answered() {
    let mut room = streaming(2);
    for sequence in 13..=14u16 {
        video_from_one(&mut room, sequence, &SLICE);
    }
    let nack = |room: &mut ForwardRoom| {
        let mut data = vec![0u8; 16];
        rtcp::write_nack(0xF000_0002, 0xF000_0002, 2003, 0, &mut data).unwrap();
        let packet = rx_video(2, 0, data);
        room.ingest(&packet);
        forwarded(room, &packet)
    };
    assert_eq!(nack(&mut room).len(), 1, "answered while it receives");
    room.set_reception("seat-2", true, false).unwrap();
    assert!(
        nack(&mut room).is_empty(),
        "nothing is resent to an off seat"
    );
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!(stats.nack_answered, 1);
    assert_eq!(stats.reception_off_dropped_video, 1);
}

#[test]
fn the_preserved_rtp_is_not_forwarded_to_an_off_seat_and_resumes_byte_for_byte() {
    let mut room = preserve_room(3);
    room.set_source(Some("seat-1")).unwrap();
    room.set_reception("seat-2", false, true).unwrap();
    let original = srtp_like(7, 0x1111_1111);
    let packet = rx(1, 1_000_000, original.clone());
    room.ingest(&packet);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, EndpointId(3));
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!(
        (stats.forwarded_packets, stats.reception_off_dropped_audio),
        (0, 1)
    );
    room.set_reception("seat-2", true, true).unwrap();
    let packet = rx(1, 1_020_000, srtp_like(8, 0x1111_1111));
    room.ingest(&packet);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|(_, _, data)| data == &packet.data[..]));
}

#[test]
fn a_bundled_browser_seat_honours_both_streams() {
    let mut room = mixed_room(&[1], &[2]);
    room.set_source(Some("seat-1")).unwrap();
    room.set_reception("seat-2", false, false).unwrap();
    // Video.
    let packet = rx_video(
        1,
        1_000_000,
        video_rtp(
            FIRST_VIDEO_PAYLOAD_TYPE + 1,
            7,
            9000,
            0x1000_0001,
            false,
            &fu_a(true, false, &[1, 2, 3]),
        ),
    );
    room.ingest(&packet);
    assert!(
        forwarded(&mut room, &packet).is_empty(),
        "no video to the browser"
    );
    // Audio.
    let audio = rx(1, 1_020_000, rtp(96, 1, 0, 0x1111_1111, &[5, 6]));
    room.ingest(&audio);
    assert!(
        forwarded(&mut room, &audio).is_empty(),
        "no audio to the browser"
    );
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!(
        (
            stats.reception_off_dropped_audio,
            stats.reception_off_dropped_video
        ),
        (1, 1)
    );
    // Audio on: it arrives as SRTP the browser can read.
    room.set_reception("seat-2", true, false).unwrap();
    let audio = rx(1, 1_040_000, rtp(96, 2, 320, 0x1111_1111, &[5, 6]));
    room.ingest(&audio);
    let sent = forwarded(&mut room, &audio);
    assert_eq!(sent.len(), 1);
    let (kind, clear) = clear_of(&mut phone(2), &sent[0].2);
    assert_eq!(kind, PacketKind::Rtp);
    assert_eq!(parsed(&clear).5, [5, 6]);
}

#[test]
fn a_seat_with_both_streams_off_is_still_sent_its_floor_and_audio_app_packets() {
    let (mut room, _queue) = floor_room(2);
    room.set_reception("seat-2", false, false).unwrap();
    let (result, sent) = sent_app(
        &mut room,
        &AppTarget::Seat("seat-2".into()),
        &floor_granted(),
    );
    result.unwrap();
    assert_eq!(sent.len(), 1, "the floor stream still carries control");
    assert_eq!(sent[0].0, EndpointId(102));
    let mut request = floor_granted();
    request.stream = RtcpAppStream::Audio;
    let (result, sent) = sent_app(&mut room, &AppTarget::Seat("seat-2".into()), &request);
    result.unwrap();
    assert_eq!(sent[0].0, EndpointId(2), "audio RTCP APP is control too");
    let everyone = AppTarget::Room { except: Vec::new() };
    let (result, sent) = sent_app(&mut room, &everyone, &floor_granted());
    result.unwrap();
    assert_eq!(sent.len(), 2, "a room-wide send reaches the off seat");
}

#[test]
fn a_browser_seat_with_both_streams_off_is_still_sent_floor_on_its_data_channel() {
    use crate::floor_channel::{floor_channel, ChannelDriver, FloorScope, FloorSink};
    use siphon_rtp_dtls::DtlsRole;
    let mut room = room_of(2);
    let (handle, plan) = floor_channel(FloorSink {
        scope: FloorScope::Room("group-1".into()),
        tag: "seat-2".into(),
        events: None,
        label: "mcptt-floor".into(),
    });
    let driver = ChannelDriver::new(DtlsRole::Server, plan);
    let writer = driver.writer().unwrap();
    handle.open_for_test();
    assert!(room.attach_floor_channel("seat-2", handle));
    room.set_reception("seat-2", false, false).unwrap();
    let (result, sent) = sent_app(
        &mut room,
        &AppTarget::Seat("seat-2".into()),
        &floor_granted(),
    );
    result.unwrap();
    assert!(sent.is_empty(), "a data channel has no UDP endpoint");
    let message = writer.try_recv().unwrap();
    assert_eq!(&message.message_for_test()[4..8], &[0xE0, 0, 0, 2]);
    assert_eq!(message.message_for_test()[1], 0xCC, "an RTCP APP packet");
}

/// The RTCP packet type each report built for `endpoint` carries: 200 an SR, 201 an RR.
fn report_types(room: &mut ForwardRoom, now_micros: u64, endpoint: u64) -> Vec<u8> {
    let mut out = Vec::new();
    room.build_reports(0xE000_0000_0000_0000, now_micros, &mut out);
    out.iter()
        .filter(|outbound| outbound.endpoint == EndpointId(endpoint))
        .map(|outbound| outbound.data[1])
        .collect()
}

const SECOND: u64 = 1_000_000;

#[test]
fn an_off_audio_stream_is_reported_with_an_rr_after_two_intervals_and_an_sr_once_packets_flow() {
    // RFC 3550 §6.4: an SR only when data packets were sent since the last report or the one before.
    let mut room = room_of(2);
    room.set_source(Some("seat-1")).unwrap();
    assert_eq!(endpoints(&audio_from_one(&mut room, 1)), [2]);
    room.set_reception("seat-2", false, true).unwrap();
    assert_eq!(
        report_types(&mut room, 5 * SECOND, 2),
        [200],
        "sent in the interval"
    );
    assert_eq!(
        report_types(&mut room, 10 * SECOND, 2),
        [200],
        "or in the one before"
    );
    assert_eq!(
        report_types(&mut room, 15 * SECOND, 2),
        [201],
        "two intervals of nothing"
    );
    assert_eq!(report_types(&mut room, 20 * SECOND, 2), [201]);
    room.set_reception("seat-2", true, true).unwrap();
    assert_eq!(endpoints(&audio_from_one(&mut room, 2)), [2]);
    assert_eq!(
        report_types(&mut room, 25 * SECOND, 2),
        [200],
        "packets flow again"
    );
}

#[test]
fn the_receiver_report_still_carries_the_block_about_the_seats_own_media() {
    let mut room = room_of(2);
    room.set_source(Some("seat-1")).unwrap();
    audio_from_one(&mut room, 1);
    // Seat 1 is the source and is sent nothing, so it is reported with an RR from its own SSRC.
    let mut out = Vec::new();
    room.build_reports(1, 5 * SECOND, &mut out);
    let to_one = out
        .iter()
        .find(|outbound| outbound.endpoint == EndpointId(1))
        .unwrap();
    let packets = rtcp::parse_compound(&to_one.data).unwrap();
    let rtcp::RtcpPacket::ReceiverReport(report) = &packets[0] else {
        panic!("{packets:?}");
    };
    assert_eq!(report.ssrc, 0xE000_0001);
    assert_eq!(report.reports.len(), 1);
    assert_eq!(report.reports[0].ssrc, 0x1111_1111);
}

#[test]
fn a_room_with_no_source_sends_receiver_reports_until_packets_flow() {
    let mut room = room_of(2);
    assert_eq!(report_types(&mut room, 5 * SECOND, 2), [201]);
    assert_eq!(report_types(&mut room, 10 * SECOND, 2), [201]);
    room.set_source(Some("seat-1")).unwrap();
    assert_eq!(endpoints(&audio_from_one(&mut room, 1)), [2]);
    assert_eq!(report_types(&mut room, 15 * SECOND, 2), [200]);
}

#[test]
fn an_off_video_stream_is_reported_with_an_rr_after_two_intervals() {
    let mut room = streaming(2);
    // Video endpoint 102: the IDR reached seat 2 (and its parameter sets).
    room.set_reception("seat-2", true, false).unwrap();
    assert_eq!(report_types(&mut room, 5 * SECOND, 102), [200]);
    assert_eq!(report_types(&mut room, 10 * SECOND, 102), [200]);
    assert_eq!(report_types(&mut room, 15 * SECOND, 102), [201]);
    room.set_reception("seat-2", true, true).unwrap();
    video_from_one(&mut room, 20, &SLICE);
    video_from_one(&mut room, 21, &IDR);
    assert_eq!(report_types(&mut room, 20 * SECOND, 102), [200]);
}

#[test]
fn the_counters_are_per_seat_and_per_stream() {
    let mut room = room_of(3);
    room.set_source(Some("seat-1")).unwrap();
    room.set_reception("seat-2", false, true).unwrap();
    room.set_reception("seat-3", true, false).unwrap();
    for sequence in 1..=3u16 {
        audio_from_one(&mut room, sequence);
    }
    let two = room.seat_stats("seat-2").unwrap();
    let three = room.seat_stats("seat-3").unwrap();
    assert_eq!(
        (
            two.reception_off_dropped_audio,
            two.reception_off_dropped_video
        ),
        (3, 0)
    );
    assert_eq!(
        (
            three.reception_off_dropped_audio,
            three.reception_off_dropped_video
        ),
        (0, 0),
        "the audio of seat 3 is on, and it has no video to drop"
    );
    assert_eq!(three.forwarded_packets, 3);
}
