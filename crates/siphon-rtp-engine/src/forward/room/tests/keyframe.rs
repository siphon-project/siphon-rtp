//! A source change starts every video receiver on a keyframe: the gate, the request to the source
//! (RFC 4585 PLI, RFC 5104 FIR), the parameter-set replay, the receivers' own feedback and the NACK
//! history. The room is driven by an explicit millisecond clock, so nothing here sleeps.

use super::video::{fu_a, rx_video, video_rtp, video_seat, FIRST_VIDEO_PAYLOAD_TYPE};
use super::*;
use crate::sdp::video::VideoFeedback;
use crate::sdp::MediaDirection;
use siphon_rtp_media::rtcp::{self, Feedback};
use siphon_rtp_proto::Event;

const SPS: [u8; 4] = [0x67, 0x64, 0x00, 0x1F];
const PPS: [u8; 3] = [0x68, 0xEE, 0x3C];
const IDR: [u8; 3] = [0x65, 0x88, 0x84];
const SLICE: [u8; 3] = [0x41, 0x9A, 0x00];

const ALL: VideoFeedback = VideoFeedback::SUPPORTED;
const NOTHING: VideoFeedback = VideoFeedback {
    nack: false,
    pli: false,
    fir: false,
};

/// The SSRC seat `index` sends its video under.
fn media_ssrc(index: u8) -> u32 {
    0x1000_0000 | u32::from(index)
}

/// The SSRC the room sends seat `index` its video under (`video_seat`).
fn egress_ssrc(index: u8) -> u32 {
    0xF000_0000 | u32::from(index)
}

/// A room of video seats `1..=feedbacks.len()`, the seat's accepted feedback as given.
fn room(feedbacks: &[VideoFeedback]) -> ForwardRoom {
    let mut room = amr_wb_room();
    for (position, feedback) in feedbacks.iter().enumerate() {
        let index = position as u8 + 1;
        let mut config = video_seat(index, MediaDirection::SendRecv);
        if let Some(video) = config.video.as_mut() {
            video.feedback = *feedback;
            video.cname = format!("seat-{index}-cname");
        }
        room.add_seat(config, 0).unwrap();
    }
    room
}

/// Seat `index` sends one video packet; what the room sent for it, `(endpoint, datagram)` each.
fn send(
    room: &mut ForwardRoom,
    index: u8,
    arrival: u64,
    sequence: u16,
    timestamp: u32,
    payload: &[u8],
) -> Vec<(u64, Vec<u8>)> {
    let packet = rx_video(
        index,
        arrival,
        video_rtp(
            FIRST_VIDEO_PAYLOAD_TYPE + index,
            sequence,
            timestamp,
            media_ssrc(index),
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

fn feedback_of(outbound: &Outbound) -> Vec<(u32, Feedback<'_>)> {
    rtcp::feedback_packets(&outbound.data)
        .map(|item| {
            let feedback = item.unwrap();
            let sender = match feedback {
                Feedback::Pli { sender_ssrc, .. }
                | Feedback::Fir { sender_ssrc, .. }
                | Feedback::GenericNack { sender_ssrc, .. } => sender_ssrc,
            };
            (sender, feedback)
        })
        .collect()
}

/// The keyframe events the room staged.
fn keyframe_events(room: &mut ForwardRoom) -> Vec<(String, u64, bool)> {
    room.drain_events()
        .filter_map(|event| match event {
            Event::ForwardKeyframe {
                from_tag,
                latency_ms,
                timed_out,
                ..
            } => Some((from_tag, latency_ms, timed_out)),
            _ => None,
        })
        .collect()
}

/// A room of `count` seats in which seat 1 has sent video (so its SSRC is known) and is the source;
/// the PLI of the switch has been sent at 1000 ms.
fn switched(feedbacks: &[VideoFeedback]) -> ForwardRoom {
    let mut room = room(feedbacks);
    send(&mut room, 1, 0, 1, 1, &SLICE);
    room.set_source(Some("seat-1")).unwrap();
    room
}

#[test]
fn a_switch_asks_the_new_source_for_a_keyframe_with_a_pli_in_a_compound() {
    let mut room = switched(&[ALL, ALL, ALL]);
    let out = poll(&mut room, 1000);
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(
        out[0].endpoint,
        EndpointId(101),
        "the source's video endpoint"
    );
    assert_eq!(out[0].dst, address("192.0.2.1:5000"));
    // RFC 4585 §3.1: an empty receiver report, the source description with the CNAME, then the PLI,
    // all from the stream the room sends the source.
    let packets = rtcp::parse_compound(&out[0].data).unwrap();
    assert!(matches!(
        &packets[0],
        rtcp::RtcpPacket::ReceiverReport(report) if report.ssrc == egress_ssrc(1) && report.reports.is_empty()
    ));
    assert!(matches!(
        &packets[1],
        rtcp::RtcpPacket::Other { packet_type: 202 }
    ));
    assert!(
        out[0]
            .data
            .windows(12)
            .any(|window| window == b"seat-1-cname"),
        "the CNAME is in the source description"
    );
    assert_eq!(
        feedback_of(&out[0]),
        [(
            egress_ssrc(1),
            Feedback::Pli {
                sender_ssrc: egress_ssrc(1),
                media_ssrc: media_ssrc(1)
            }
        )]
    );
    assert_eq!(room.seat_stats("seat-1").unwrap().pli_sent, 1);
    assert!(
        poll(&mut room, 1001).is_empty(),
        "one request, not one per poll"
    );
}

#[test]
fn the_pli_compound_is_pinned_byte_for_byte() {
    // Wireshark reads these bytes as a Receiver Report (SSRC 0xF0000001, no blocks), a Source
    // Description with the CNAME "abc", and a Picture Loss Indication from 0xF0000001 about 0x10000001.
    let mut room = amr_wb_room();
    let mut config = video_seat(1, MediaDirection::SendRecv);
    if let Some(video) = config.video.as_mut() {
        video.feedback = ALL;
        video.cname = "abc".to_string();
    }
    room.add_seat(config, 0).unwrap();
    room.add_seat(video_seat(2, MediaDirection::SendRecv), 0)
        .unwrap();
    send(&mut room, 1, 0, 1, 1, &SLICE);
    room.set_source(Some("seat-1")).unwrap();
    let out = poll(&mut room, 0);
    assert_eq!(
        out[0].data.as_ref(),
        [
            0x80, 0xC9, 0x00, 0x01, 0xF0, 0x00, 0x00, 0x01, // RR, RC=0
            0x81, 0xCA, 0x00, 0x03, 0xF0, 0x00, 0x00, 0x01, 0x01, 0x03, b'a', b'b', b'c', 0, 0,
            0, // SDES, one chunk, CNAME
            0x81, 0xCE, 0x00, 0x02, 0xF0, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x01, // PLI
        ]
    );
}

#[test]
fn the_fir_compound_is_pinned_byte_for_byte() {
    // A source that accepted only `ccm fir`: header media SSRC 0, the entry names the stream, and the
    // command sequence number is the room's first (0).
    let mut room = amr_wb_room();
    let mut config = video_seat(1, MediaDirection::SendRecv);
    if let Some(video) = config.video.as_mut() {
        video.feedback = VideoFeedback {
            fir: true,
            ..NOTHING
        };
        video.cname = "abc".to_string();
    }
    room.add_seat(config, 0).unwrap();
    room.add_seat(video_seat(2, MediaDirection::SendRecv), 0)
        .unwrap();
    send(&mut room, 1, 0, 1, 1, &SLICE);
    room.set_source(Some("seat-1")).unwrap();
    let out = poll(&mut room, 0);
    assert_eq!(
        out[0].data.as_ref()[24..],
        [
            0x84, 0xCE, 0x00, 0x04, 0xF0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00
        ]
    );
}

#[test]
fn without_a_ssrc_for_the_source_nothing_is_sent_until_it_has_sent_video() {
    let mut room = room(&[ALL, ALL]);
    room.set_source(Some("seat-1")).unwrap();
    assert!(poll(&mut room, 0).is_empty(), "no media SSRC to name yet");
    send(&mut room, 1, 0, 1, 1, &SLICE);
    let out = poll(&mut room, 10);
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(
        feedback_of(&out[0])[0].1,
        Feedback::Pli {
            sender_ssrc: egress_ssrc(1),
            media_ssrc: media_ssrc(1)
        }
    );
}

#[test]
fn a_fir_follows_every_half_second_with_the_same_sequence_and_the_room_gives_up_at_two_seconds() {
    let mut room = switched(&[ALL, ALL]);
    assert_eq!(poll(&mut room, 0).len(), 1, "the PLI");
    assert!(poll(&mut room, 499).is_empty());
    let mut firs = Vec::new();
    for now in [500, 1000, 1500] {
        let out = poll(&mut room, now);
        assert_eq!(out.len(), 1, "at {now}");
        let (_, Feedback::Fir { entries, .. }) = feedback_of(&out[0])[0] else {
            panic!("a FIR at {now}: {out:?}");
        };
        firs.extend(entries.map(|entry| (entry.ssrc, entry.sequence)));
    }
    // RFC 5104 §4.3.1.2: a repeat of an unanswered request keeps its command sequence number.
    assert_eq!(firs, [(media_ssrc(1), 0); 3]);
    assert!(poll(&mut room, 1999).is_empty(), "at most three repeats");
    assert!(keyframe_events(&mut room).is_empty());
    assert!(poll(&mut room, 2000).is_empty());
    assert_eq!(
        keyframe_events(&mut room),
        [("seat-1".to_string(), 2000, true)]
    );
    let stats = room.seat_stats("seat-1").unwrap();
    assert_eq!(
        (stats.pli_sent, stats.fir_sent, stats.keyframe_timeouts),
        (1, 3, 1)
    );
    assert!(!room.keyframe_active(), "nothing left to do");
    assert_eq!(room.next_keyframe_deadline(), None);
}

#[test]
fn the_next_switch_is_a_new_request_with_the_next_fir_sequence() {
    let mut room = switched(&[ALL, ALL]);
    poll(&mut room, 0);
    for now in [500, 2000] {
        poll(&mut room, now);
    }
    send(&mut room, 2, 2100, 1, 1, &SLICE);
    room.set_source(Some("seat-2")).unwrap();
    poll(&mut room, 3000);
    let out = poll(&mut room, 3500);
    let (_, Feedback::Fir { entries, .. }) = feedback_of(&out[0])[0] else {
        panic!("a FIR");
    };
    assert_eq!(
        entries.map(|entry| entry.sequence).collect::<Vec<_>>(),
        [1],
        "a new request increments"
    );
}

#[test]
fn a_source_that_accepted_only_pli_is_sent_pli_every_time_and_one_that_accepted_only_fir_fir() {
    let pli_only = VideoFeedback {
        pli: true,
        ..NOTHING
    };
    let mut room = switched(&[pli_only, ALL]);
    for now in [0, 500, 1000, 1500] {
        let out = poll(&mut room, now);
        assert!(
            matches!(feedback_of(&out[0])[0].1, Feedback::Pli { .. }),
            "{now}"
        );
    }
    assert_eq!(room.seat_stats("seat-1").unwrap().fir_sent, 0);
    let fir_only = VideoFeedback {
        fir: true,
        ..NOTHING
    };
    let mut room = switched(&[fir_only, ALL]);
    for now in [0, 500] {
        let out = poll(&mut room, now);
        assert!(
            matches!(feedback_of(&out[0])[0].1, Feedback::Fir { .. }),
            "{now}"
        );
    }
    assert_eq!(room.seat_stats("seat-1").unwrap().pli_sent, 0);
}

#[test]
fn nothing_is_sent_to_a_source_that_accepted_no_feedback_and_the_room_forwards_after_the_wait() {
    let mut room = switched(&[NOTHING, ALL]);
    for now in [0, 500, 1000, 1500, 1999] {
        assert!(poll(&mut room, now).is_empty(), "{now}");
    }
    // Held back while it waits for a keyframe that no one was asked for.
    assert!(send(&mut room, 1, 100, 2, 2, &SLICE).is_empty());
    assert!(poll(&mut room, 2000).is_empty());
    assert_eq!(
        keyframe_events(&mut room),
        [("seat-1".to_string(), 2000, true)]
    );
    // The gate is open: whatever arrives is forwarded.
    let sent = send(&mut room, 1, 200, 3, 3, &SLICE);
    assert_eq!(sent.len(), 1);
    let stats = room.seat_stats("seat-1").unwrap();
    assert_eq!((stats.pli_sent, stats.fir_sent), (0, 0));
}

#[test]
fn a_source_with_no_video_starts_no_gate_no_request_and_no_event() {
    let mut room = amr_wb_room();
    room.add_seat(seat_config(1), 0).unwrap();
    room.add_seat(video_seat(2, MediaDirection::SendRecv), 0)
        .unwrap();
    room.set_source(Some("seat-1")).unwrap();
    assert!(!room.keyframe_active());
    assert!(poll(&mut room, 0).is_empty());
    assert!(keyframe_events(&mut room).is_empty());
    assert_eq!(room.next_keyframe_deadline(), None);
}

#[test]
fn the_gate_drops_packets_before_the_keyframe_then_the_parameter_sets_and_the_idr_come_out_in_order(
) {
    let mut room = room(&[ALL, ALL, ALL]);
    // Seat 1 has sent its parameter sets before it becomes the source.
    send(&mut room, 1, 0, 10, 100, &SPS);
    send(&mut room, 1, 0, 11, 100, &PPS);
    room.set_source(Some("seat-1")).unwrap();
    poll(&mut room, 1000);
    // Pictures that are not the keyframe: held back from both receivers, and counted.
    for (sequence, timestamp) in [(12u16, 3100u32), (13, 6100), (14, 9100)] {
        assert!(send(&mut room, 1, 1_000_000, sequence, timestamp, &SLICE).is_empty());
    }
    assert_eq!(
        room.seat_stats("seat-2")
            .unwrap()
            .video_dropped_awaiting_keyframe,
        3
    );
    // The keyframe: each receiver is sent the SPS, the PPS and the IDR, in that order, under its own
    // sequence numbers (continuous, from 2000) and payload type, with the IDR's timestamp.
    let sent = send(&mut room, 1, 1_100_000, 15, 12_100, &IDR);
    assert_eq!(sent.len(), 6, "three datagrams to each of two receivers");
    for index in [2u8, 3] {
        let to_receiver: Vec<_> = sent
            .iter()
            .filter(|(endpoint, _)| *endpoint == 100 + u64::from(index))
            .map(|(_, data)| parsed(data))
            .collect();
        assert_eq!(to_receiver.len(), 3);
        let payloads: Vec<&[u8]> = to_receiver.iter().map(|sent| sent.5.as_slice()).collect();
        assert_eq!(payloads, [&SPS[..], &PPS[..], &IDR[..]], "receiver {index}");
        let sequences: Vec<u16> = to_receiver.iter().map(|sent| sent.2).collect();
        assert_eq!(sequences, [2000, 2001, 2002]);
        assert!(
            to_receiver
                .iter()
                .all(|sent| sent.1 == FIRST_VIDEO_PAYLOAD_TYPE + index
                    && sent.4 == egress_ssrc(index))
        );
        let timestamps: Vec<u32> = to_receiver.iter().map(|sent| sent.3).collect();
        assert_eq!(
            timestamps[0], timestamps[2],
            "one access unit, one timestamp"
        );
        assert_eq!(timestamps[1], timestamps[2]);
    }
    // And on from there with no gap.
    let next = send(&mut room, 1, 1_140_000, 16, 15_100, &SLICE);
    assert_eq!(next.len(), 2);
    assert_eq!(parsed(&next[0].1).2, 2003);
    // The controller hears of it once, with how long it took.
    poll(&mut room, 1240);
    assert_eq!(
        keyframe_events(&mut room),
        [("seat-1".to_string(), 240, false)]
    );
    poll(&mut room, 1500);
    assert!(keyframe_events(&mut room).is_empty(), "once per switch");
    assert_eq!(room.seat_stats("seat-1").unwrap().keyframes_seen, 1);
    assert!(!room.keyframe_active());
}

#[test]
fn the_replayed_parameter_sets_run_into_the_idr_across_a_sequence_wrap() {
    let mut room = room(&[ALL, ALL]);
    send(&mut room, 1, 0, 10, 100, &SPS);
    send(&mut room, 1, 0, 11, 100, &PPS);
    room.set_source(Some("seat-1")).unwrap();
    // The IDR is the first packet after the wrap: the parameter sets are built at 65535 and 0
    // (RFC 3550 §5.1: sequence numbers are mod 2^16), so the receiver's run has no hole.
    let sent = send(&mut room, 1, 100, 1, 500, &IDR);
    let sequences: Vec<u16> = sent.iter().map(|(_, data)| parsed(data).2).collect();
    assert_eq!(sequences, [2000, 2001, 2002]);
    let next = send(&mut room, 1, 200, 2, 600, &SLICE);
    assert_eq!(parsed(&next[0].1).2, 2003);
}

#[test]
fn an_idr_that_carries_its_own_parameter_sets_is_not_replayed() {
    let mut room = room(&[ALL, ALL]);
    send(&mut room, 1, 0, 10, 100, &SPS);
    send(&mut room, 1, 0, 11, 100, &PPS);
    room.set_source(Some("seat-1")).unwrap();
    // A STAP-A (RFC 6184 §5.7.1) of SPS, PPS and the IDR slice opens the gate by itself.
    let mut stap = vec![0x78];
    for unit in [&SPS[..], &PPS[..], &IDR[..]] {
        stap.extend_from_slice(&(unit.len() as u16).to_be_bytes());
        stap.extend_from_slice(unit);
    }
    let sent = send(&mut room, 1, 100, 12, 900, &stap);
    assert_eq!(sent.len(), 1, "no second copy of the parameter sets");
    assert_eq!(parsed(&sent[0].1).5, stap);
    assert_eq!(parsed(&sent[0].1).2, 2000);
}

#[test]
fn an_idr_stap_a_with_only_the_pps_is_sent_the_missing_sps_first() {
    let mut room = room(&[ALL, ALL]);
    send(&mut room, 1, 0, 10, 100, &SPS);
    send(&mut room, 1, 0, 11, 100, &PPS);
    room.set_source(Some("seat-1")).unwrap();
    let mut stap = vec![0x78];
    for unit in [&PPS[..], &IDR[..]] {
        stap.extend_from_slice(&(unit.len() as u16).to_be_bytes());
        stap.extend_from_slice(unit);
    }
    let sent = send(&mut room, 1, 100, 12, 900, &stap);
    let sequences: Vec<u16> = sent.iter().map(|(_, data)| parsed(data).2).collect();
    assert_eq!(
        sequences,
        [2000, 2001],
        "the SPS right before the packet, no gap"
    );
    assert_eq!(parsed(&sent[0].1).5, SPS);
}

#[test]
fn an_fu_a_start_of_an_idr_opens_the_gate_and_its_later_fragments_follow() {
    let mut room = room(&[ALL, ALL]);
    send(&mut room, 1, 0, 10, 100, &SPS);
    send(&mut room, 1, 0, 11, 100, &PPS);
    room.set_source(Some("seat-1")).unwrap();
    // A middle fragment of a picture the receiver never saw the start of: held back.
    assert!(send(&mut room, 1, 50, 12, 800, &fu_a(false, false, &[1])).is_empty());
    let start = send(&mut room, 1, 100, 13, 900, &fu_a(true, false, &[0x88, 2]));
    assert_eq!(start.len(), 3, "SPS, PPS, then the FU-A start");
    let end = send(&mut room, 1, 110, 14, 900, &fu_a(false, true, &[3]));
    assert_eq!(end.len(), 1);
    assert_eq!(parsed(&end[0].1).2, 2003);
}

#[test]
fn a_packet_older_than_the_keyframe_is_dropped_once_the_receiver_is_on_it() {
    let mut room = room(&[ALL, ALL]);
    room.set_source(Some("seat-1")).unwrap();
    send(&mut room, 1, 0, 1, 1, &SLICE);
    assert_eq!(send(&mut room, 1, 100, 20, 900, &IDR).len(), 1);
    // A reordered packet from before the keyframe, and a duplicate of it: behind the picture the
    // receiver started on.
    assert!(send(&mut room, 1, 110, 19, 800, &SLICE).is_empty());
    assert!(send(&mut room, 1, 120, 20, 900, &IDR).is_empty());
    assert_eq!(send(&mut room, 1, 130, 21, 1000, &SLICE).len(), 1);
    assert_eq!(
        room.seat_stats("seat-2")
            .unwrap()
            .video_dropped_awaiting_keyframe,
        3,
        "the slice before the keyframe, and the two behind it"
    );
}

#[test]
fn a_seat_that_joins_mid_stream_waits_for_the_next_keyframe_and_asks_for_one() {
    let mut room = room(&[ALL, ALL]);
    send(&mut room, 1, 0, 10, 100, &SPS);
    send(&mut room, 1, 0, 11, 100, &PPS);
    room.set_source(Some("seat-1")).unwrap();
    poll(&mut room, 0);
    assert_eq!(send(&mut room, 1, 10, 12, 200, &IDR).len(), 3);
    poll(&mut room, 10);
    assert_eq!(keyframe_events(&mut room).len(), 1);
    // Seat 3 joins while the source streams.
    let mut config = video_seat(3, MediaDirection::SendRecv);
    if let Some(video) = config.video.as_mut() {
        video.feedback = ALL;
    }
    room.add_seat(config, 0).unwrap();
    let out = poll(&mut room, 5000);
    assert_eq!(out.len(), 1, "a PLI to the source for the joiner");
    // Seat 2 keeps its stream; seat 3 gets nothing until the next keyframe.
    let sent = send(&mut room, 1, 5010, 13, 300, &SLICE);
    assert_eq!(
        sent.iter()
            .map(|(endpoint, _)| *endpoint)
            .collect::<Vec<_>>(),
        [102]
    );
    assert_eq!(
        room.seat_stats("seat-3")
            .unwrap()
            .video_dropped_awaiting_keyframe,
        1
    );
    let sent = send(&mut room, 1, 5020, 14, 400, &IDR);
    let to_two = sent.iter().filter(|(endpoint, _)| *endpoint == 102).count();
    let to_three = sent.iter().filter(|(endpoint, _)| *endpoint == 103).count();
    assert_eq!(
        (to_two, to_three),
        (1, 3),
        "the joiner is sent the parameter sets too"
    );
    poll(&mut room, 5030);
    assert!(
        keyframe_events(&mut room).is_empty(),
        "a joiner's keyframe is not a source change"
    );
}

#[test]
fn a_joiner_before_any_source_is_not_gated() {
    let mut room = room(&[ALL]);
    room.add_seat(video_seat(2, MediaDirection::SendRecv), 0)
        .unwrap();
    assert!(!room.keyframe_active());
    room.set_source(Some("seat-1")).unwrap();
    send(&mut room, 1, 0, 1, 1, &IDR);
    assert!(room.keyframe_active(), "the switch armed it");
}

#[test]
fn the_latency_is_measured_from_the_poll_that_stamped_the_switch() {
    let mut room = switched(&[ALL, ALL]);
    poll(&mut room, 100);
    // An IDR at 650 ms: the keyframe took 550 ms from the poll that stamped the switch.
    send(&mut room, 1, 0, 2, 2, &IDR);
    poll(&mut room, 650);
    assert_eq!(
        keyframe_events(&mut room),
        [("seat-1".to_string(), 550, false)]
    );
}

#[test]
fn many_receivers_asking_in_one_interval_make_one_request_to_the_source() {
    let mut room = room(&[ALL, ALL, ALL, ALL]);
    send(&mut room, 1, 0, 1, 1, &SLICE);
    room.set_source(Some("seat-1")).unwrap();
    send(&mut room, 1, 0, 2, 2, &IDR);
    poll(&mut room, 0);
    poll(&mut room, 1);
    for receiver in [2u8, 3, 4] {
        let mut data = vec![0u8; 12];
        // The seat addresses the stream the room sends it (RFC 4585 §6.1: media source SSRC).
        rtcp::write_pli(
            0xA000_0000 | u32::from(receiver),
            egress_ssrc(receiver),
            &mut data,
        )
        .unwrap();
        room.ingest(&rx_video(receiver, 0, data));
    }
    let out = poll(&mut room, 5000);
    assert_eq!(out.len(), 1, "one PLI, whoever asked: {out:?}");
    // The keyframe had already arrived when the switch was first polled, so only this one was sent.
    assert_eq!(room.seat_stats("seat-1").unwrap().pli_sent, 1);
    // Asking again inside the interval waits for it.
    let mut data = vec![0u8; 12];
    rtcp::write_pli(egress_ssrc(2), egress_ssrc(2), &mut data).unwrap();
    room.ingest(&rx_video(2, 0, data));
    assert!(poll(&mut room, 5500).is_empty());
    assert_eq!(room.next_keyframe_deadline(), Some(6000));
    assert_eq!(poll(&mut room, 6000).len(), 1);
}

#[test]
fn a_receivers_fir_for_its_stream_is_a_request_and_one_for_another_stream_is_not() {
    let mut room = room(&[ALL, ALL]);
    send(&mut room, 1, 0, 1, 1, &SLICE);
    room.set_source(Some("seat-1")).unwrap();
    send(&mut room, 1, 0, 2, 2, &IDR);
    poll(&mut room, 0);
    let mut data = vec![0u8; 20];
    rtcp::write_fir(egress_ssrc(2), 0xDEAD_BEEF, 7, &mut data).unwrap();
    room.ingest(&rx_video(2, 0, data));
    assert!(
        !room.keyframe_active(),
        "a FIR for some other stream asks nothing"
    );
    let mut data = vec![0u8; 20];
    rtcp::write_fir(egress_ssrc(2), egress_ssrc(2), 7, &mut data).unwrap();
    room.ingest(&rx_video(2, 0, data));
    assert!(room.keyframe_active());
    assert_eq!(poll(&mut room, 5000).len(), 1);
}

#[test]
fn a_receivers_request_is_answered_by_the_switch_request_already_in_flight() {
    let mut room = room(&[ALL, ALL]);
    room.set_source(Some("seat-1")).unwrap();
    poll(&mut room, 0);
    let mut data = vec![0u8; 12];
    rtcp::write_pli(egress_ssrc(2), egress_ssrc(2), &mut data).unwrap();
    room.ingest(&rx_video(2, 0, data));
    assert!(poll(&mut room, 10).is_empty());
}

/// Source seat 1 sent packets 10..=14 to seats 2 and 3 after the keyframe; the egress sequence of
/// packet `n` is `2000 + (n - 10)` for each receiver.
fn streaming() -> (ForwardRoom, Vec<Vec<u8>>) {
    let mut room = room(&[ALL, ALL, NOTHING]);
    room.set_source(Some("seat-1")).unwrap();
    let mut to_two = Vec::new();
    for sequence in 10..=14u16 {
        let payload: &[u8] = if sequence == 10 { &IDR } else { &SLICE };
        for (endpoint, data) in send(
            &mut room,
            1,
            0,
            sequence,
            900 + u32::from(sequence),
            payload,
        ) {
            if endpoint == 102 {
                to_two.push(data);
            }
        }
    }
    (room, to_two)
}

fn nack_from(receiver: u8, pid: u16, blp: u16) -> RxPacket {
    let mut data = vec![0u8; 16];
    rtcp::write_nack(
        egress_ssrc(receiver),
        egress_ssrc(receiver),
        pid,
        blp,
        &mut data,
    )
    .unwrap();
    rx_video(receiver, 0, data)
}

#[test]
fn a_nack_is_served_from_the_history_with_the_original_egress_sequence() {
    let (mut room, to_two) = streaming();
    assert_eq!(to_two.len(), 5);
    // Packets 2001 and 2003 (pid 2001, bit 1 of BLP: 2001 + 2) were lost.
    let nack = nack_from(2, 2001, 0b10);
    assert_eq!(room.ingest(&nack), Ingress::Accepted);
    let resent = forwarded(&mut room, &nack);
    assert_eq!(resent.len(), 2);
    assert!(resent.iter().all(|(endpoint, destination, _)| {
        *endpoint == EndpointId(102) && *destination == address("192.0.2.2:5000")
    }));
    assert_eq!(resent[0].2, to_two[1], "byte for byte what was sent");
    assert_eq!(resent[1].2, to_two[3]);
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!((stats.nack_answered, stats.nack_missed), (2, 0));
    assert!(room.next_datagram(&nack).is_none());
}

#[test]
fn a_nack_for_a_packet_the_room_never_sent_or_no_longer_has_is_counted_as_missed() {
    let (mut room, _) = streaming();
    // 2005 was never sent; 1999 is before the receiver's run.
    let nack = nack_from(2, 1999, 0b0000_0000_0010_0000);
    room.ingest(&nack);
    assert!(forwarded(&mut room, &nack).is_empty());
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!((stats.nack_answered, stats.nack_missed), (0, 2));
}

#[test]
fn a_nack_for_a_packet_that_left_the_history_is_missed() {
    let (mut room, _) = streaming();
    // 300 packets later the slot of packet 10 holds another sequence number.
    for sequence in 15..315u16 {
        send(
            &mut room,
            1,
            0,
            sequence,
            1000 + u32::from(sequence),
            &SLICE,
        );
    }
    let nack = nack_from(2, 2000, 0);
    room.ingest(&nack);
    assert!(forwarded(&mut room, &nack).is_empty());
    assert_eq!(room.seat_stats("seat-2").unwrap().nack_missed, 1);
}

#[test]
fn a_nack_from_a_receiver_that_did_not_accept_nack_is_ignored() {
    let (mut room, _) = streaming();
    let nack = nack_from(3, 2001, 0);
    room.ingest(&nack);
    assert!(forwarded(&mut room, &nack).is_empty());
    let stats = room.seat_stats("seat-3").unwrap();
    assert_eq!((stats.nack_answered, stats.nack_missed), (0, 0));
}

#[test]
fn a_nack_about_another_stream_is_ignored() {
    let (mut room, _) = streaming();
    let mut data = vec![0u8; 16];
    rtcp::write_nack(egress_ssrc(2), 0xDEAD_BEEF, 2001, 0, &mut data).unwrap();
    let nack = rx_video(2, 0, data);
    room.ingest(&nack);
    assert!(forwarded(&mut room, &nack).is_empty());
    assert_eq!(room.seat_stats("seat-2").unwrap().nack_missed, 0);
}

#[test]
fn a_nack_does_not_reach_across_a_source_change() {
    let (mut room, _) = streaming();
    send(&mut room, 2, 0, 1, 1, &SLICE);
    room.set_source(Some("seat-2")).unwrap();
    let nack = nack_from(1, 2001, 0);
    room.ingest(&nack);
    assert!(
        forwarded(&mut room, &nack).is_empty(),
        "the history was the old source's"
    );
}

#[test]
fn a_nack_for_a_replayed_parameter_set_is_missed_not_answered_with_another_packet() {
    let mut room = room(&[ALL, ALL]);
    send(&mut room, 1, 0, 10, 100, &SPS);
    send(&mut room, 1, 0, 11, 100, &PPS);
    room.set_source(Some("seat-1")).unwrap();
    // Real packets sit at the sequence numbers the replay borrows (an unrelated slice at 20).
    send(&mut room, 1, 0, 20, 500, &SLICE);
    send(&mut room, 1, 0, 21, 500, &SLICE);
    let sent = send(&mut room, 1, 100, 22, 900, &IDR);
    assert_eq!(sent.len(), 3);
    let nack = nack_from(2, 2000, 0b1);
    room.ingest(&nack);
    assert!(forwarded(&mut room, &nack).is_empty());
    assert_eq!(room.seat_stats("seat-2").unwrap().nack_missed, 2);
    // The IDR itself is the receiver's third packet and can be asked for.
    let nack = nack_from(2, 2002, 0);
    room.ingest(&nack);
    assert_eq!(forwarded(&mut room, &nack).len(), 1);
}

#[test]
fn the_source_leaving_mid_request_resets_the_state() {
    let mut room = switched(&[ALL, ALL, ALL]);
    poll(&mut room, 0);
    assert!(room.keyframe_active());
    assert!(room.remove_seat("seat-1"));
    assert!(!room.keyframe_active());
    assert_eq!(room.next_keyframe_deadline(), None);
    assert!(poll(&mut room, 3000).is_empty());
    assert!(
        keyframe_events(&mut room).is_empty(),
        "no event for a source that left"
    );
}

#[test]
fn a_seat_leaving_below_the_source_does_not_lose_the_request() {
    let mut room = room(&[ALL, ALL, ALL]);
    send(&mut room, 3, 0, 1, 1, &SLICE);
    room.set_source(Some("seat-3")).unwrap();
    poll(&mut room, 0);
    assert!(room.remove_seat("seat-1"));
    send(&mut room, 3, 0, 2, 2, &IDR);
    poll(&mut room, 100);
    assert_eq!(
        keyframe_events(&mut room),
        [("seat-3".to_string(), 100, false)]
    );
}

#[test]
fn choosing_no_source_opens_every_gate_and_ends_the_request() {
    let mut room = switched(&[ALL, ALL]);
    poll(&mut room, 0);
    room.set_source(None).unwrap();
    assert!(!room.keyframe_active());
    assert!(keyframe_events(&mut room).is_empty());
}

#[test]
fn choosing_the_same_source_again_asks_nothing_more() {
    let mut room = switched(&[ALL, ALL]);
    poll(&mut room, 0);
    room.set_source(Some("seat-1")).unwrap();
    assert!(poll(&mut room, 100).is_empty());
}

#[test]
fn a_receive_only_seat_is_never_held_and_a_send_only_one_is_never_a_receiver() {
    let mut room = amr_wb_room();
    for (index, direction) in [
        (1u8, MediaDirection::SendRecv),
        (2, MediaDirection::RecvOnly),
        (3, MediaDirection::SendOnly),
    ] {
        let mut config = video_seat(index, direction);
        if let Some(video) = config.video.as_mut() {
            video.feedback = ALL;
        }
        room.add_seat(config, 0).unwrap();
    }
    send(&mut room, 1, 0, 1, 1, &SLICE);
    room.set_source(Some("seat-1")).unwrap();
    // The send-only seat is not a receiver at all; the receive-only one is gated like any.
    assert!(send(&mut room, 1, 10, 2, 2, &SLICE).is_empty());
    let sent = send(&mut room, 1, 20, 3, 3, &IDR);
    assert_eq!(
        sent.iter()
            .map(|(endpoint, _)| *endpoint)
            .collect::<Vec<_>>(),
        [102]
    );
}

#[test]
fn the_deadline_asks_for_the_next_retry_or_the_limit_and_for_now_when_the_clock_is_unread() {
    let mut room = switched(&[ALL, ALL]);
    assert_eq!(room.next_keyframe_deadline(), Some(0), "not stamped yet");
    poll(&mut room, 100);
    assert_eq!(room.next_keyframe_deadline(), Some(600), "the first repeat");
    poll(&mut room, 600);
    poll(&mut room, 1100);
    poll(&mut room, 1600);
    assert_eq!(
        room.next_keyframe_deadline(),
        Some(2100),
        "after the last repeat only the limit remains"
    );
    send(&mut room, 1, 0, 2, 2, &IDR);
    assert_eq!(
        room.next_keyframe_deadline(),
        Some(0),
        "answered: report it now"
    );
}

#[test]
fn the_replayed_parameter_sets_and_the_idr_are_pinned_byte_for_byte() {
    // What seat 2 is sent when seat 1's keyframe opens its gate: the SPS and the PPS as single NAL
    // unit packets (RFC 6184 §5.6) and then the IDR slice, one access unit under one timestamp, with
    // consecutive sequence numbers from 2000, payload type 100 and SSRC 0xF0000002. The parameter
    // sets are a real Constrained High level 3.1 SPS and its PPS, so Wireshark's H.264 dissector reads
    // these bytes as NAL unit types 7, 8 and 5, with no malformed packet.
    const REAL_SPS: [u8; 25] = [
        0x67, 0x64, 0x00, 0x1F, 0xAC, 0xD9, 0x40, 0x50, 0x05, 0xBA, 0x10, 0x00, 0x00, 0x03, 0x00,
        0x10, 0x00, 0x00, 0x03, 0x03, 0xC0, 0xF1, 0x83, 0x19, 0x60,
    ];
    const REAL_PPS: [u8; 6] = [0x68, 0xEB, 0xE3, 0xCB, 0x22, 0xC0];
    const IDR_SLICE: [u8; 6] = [0x65, 0x88, 0x84, 0x00, 0x33, 0xFF];
    let mut room = room(&[ALL, ALL]);
    send(&mut room, 1, 0, 10, 100, &REAL_SPS);
    send(&mut room, 1, 0, 11, 100, &REAL_PPS);
    room.set_source(Some("seat-1")).unwrap();
    let sent = send(&mut room, 1, 100, 12, 900, &IDR_SLICE);
    let datagrams: Vec<&[u8]> = sent.iter().map(|(_, data)| data.as_slice()).collect();
    let header = |sequence: u8| {
        vec![
            0x80, 0x64, 0x07, sequence, 0x00, 0x01, 0x11, 0x70, 0xF0, 0x00, 0x00, 0x02,
        ]
    };
    assert_eq!(
        datagrams,
        [
            [header(0xD0), REAL_SPS.to_vec()].concat(),
            [header(0xD1), REAL_PPS.to_vec()].concat(),
            [header(0xD2), IDR_SLICE.to_vec()].concat(),
        ]
    );
    // The leading bytes, spelled out so a reader checks them against RFC 3550 §5.1 and RFC 6184:
    // V=2, marker 0, payload type 100, sequence 2000, timestamp 70000, SSRC, then NAL header 0x67.
    assert_eq!(
        datagrams[0][..13],
        [0x80, 0x64, 0x07, 0xD0, 0x00, 0x01, 0x11, 0x70, 0xF0, 0x00, 0x00, 0x02, 0x67]
    );
}

#[test]
fn a_request_that_cannot_be_built_is_kept_to_the_schedule_and_never_spins() {
    // A CNAME over the 255 octets an SDES item holds (RFC 3550 §6.5) cannot be written.
    let mut room = amr_wb_room();
    let mut config = video_seat(1, MediaDirection::SendRecv);
    if let Some(video) = config.video.as_mut() {
        video.feedback = ALL;
        video.cname = "x".repeat(300);
    }
    room.add_seat(config, 0).unwrap();
    room.add_seat(video_seat(2, MediaDirection::SendRecv), 0)
        .unwrap();
    send(&mut room, 1, 0, 1, 1, &SLICE);
    room.set_source(Some("seat-1")).unwrap();
    assert!(poll(&mut room, 100).is_empty(), "nothing could be written");
    assert_eq!(
        room.next_keyframe_deadline(),
        Some(600),
        "the next attempt is a retry away, not now"
    );
}
