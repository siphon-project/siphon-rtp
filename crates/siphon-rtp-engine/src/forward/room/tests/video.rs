//! The video stream of a seat: one source for audio and video, a translator per receiver and
//! stream, the sender's marker bit, and the direction a seat offered (3GPP TS 24.281 §6.2).

use super::*;
use crate::sdp::video::RoomVideoFormat;
use crate::sdp::MediaDirection;

const FIRST_VIDEO_PAYLOAD_TYPE: u8 = 98;

fn format() -> RoomVideoFormat {
    RoomVideoFormat {
        packetization_mode: 1,
        profile_level_id: Some("640c1f".to_string()),
        fmtp: Some("profile-level-id=640c1f;packetization-mode=1".to_string()),
    }
}

/// Seat `index` with a video endpoint `100 + index` at `192.0.2.<index>:5000`, its own payload type
/// `98 + index`, and egress SSRC `0xF000_0000 | index`.
fn video_seat(index: u8, direction: MediaDirection) -> ForwardSeatConfig {
    let mut config = seat_config(index);
    let remote = address(&format!("192.0.2.{index}:5000"));
    config.video = Some(VideoConfig {
        endpoint: EndpointId(100 + u64::from(index)),
        destination: remote,
        accepted_source: SourceFilter::Exact(remote.ip()),
        payload_type: FIRST_VIDEO_PAYLOAD_TYPE + index,
        direction,
        egress_ssrc: 0xF000_0000 | u32::from(index),
        initial_sequence: 2000,
        initial_timestamp: 70_000,
        format: format(),
    });
    config
}

fn video_room(directions: &[MediaDirection]) -> ForwardRoom {
    let mut room = amr_wb_room();
    for (position, direction) in directions.iter().enumerate() {
        room.add_seat(video_seat(position as u8 + 1, *direction), 0)
            .unwrap();
    }
    room
}

fn all_sendrecv(seats: usize) -> ForwardRoom {
    video_room(&vec![MediaDirection::SendRecv; seats])
}

/// A video RTP datagram.
fn video_rtp(
    payload_type: u8,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
    marker: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut datagram = rtp(payload_type, sequence, timestamp, ssrc, payload);
    if marker {
        datagram[1] |= 0x80;
    }
    datagram
}

fn rx_video(index: u8, arrival: u64, data: Vec<u8>) -> RxPacket {
    RxPacket {
        endpoint: EndpointId(100 + u64::from(index)),
        source: address(&format!("192.0.2.{index}:5000")),
        arrival,
        data: Bytes::from(data),
    }
}

/// An FU-A fragment of an H.264 NAL unit (RFC 6184 §5.8): indicator, header, then `data`.
fn fu_a(start: bool, end: bool, data: &[u8]) -> Vec<u8> {
    let header = (u8::from(start) << 7) | (u8::from(end) << 6) | 5; // type 5, an IDR slice
    let mut payload = vec![0x7C, header]; // F=0, NRI=3, type 28
    payload.extend_from_slice(data);
    payload
}

#[test]
fn video_is_forwarded_to_every_other_seat_on_its_own_endpoint_ssrc_and_payload_type() {
    let mut room = all_sendrecv(3);
    room.set_source(Some("seat-1")).unwrap();
    let payload = fu_a(true, false, &[1, 2, 3, 4]);
    let packet = rx_video(
        1,
        1_000_000,
        video_rtp(99, 7, 9000, 0x1111_1111, false, &payload),
    );
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 2, "two receivers, the source is not one");
    for (endpoint, destination, datagram) in &sent {
        let index = (endpoint.0 - 100) as u8;
        assert_eq!(*destination, address(&format!("192.0.2.{index}:5000")));
        let (marker, payload_type, _, _, ssrc, body) = parsed(datagram);
        assert!(
            !marker,
            "a first fragment is not the end of the access unit"
        );
        assert_eq!(
            payload_type,
            FIRST_VIDEO_PAYLOAD_TYPE + index,
            "the receiver's own number"
        );
        assert_eq!(ssrc, 0xF000_0000 | u32::from(index));
        assert_eq!(body, payload, "payload byte-identical");
    }
    assert!(room.next_datagram(&packet).is_none());
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!(stats.video_forwarded_packets, 1);
    assert_eq!(stats.video_forwarded_octets, payload.len() as u32);
    assert_eq!(stats.forwarded_packets, 0, "no audio was sent");
}

#[test]
fn a_video_switch_keeps_each_receivers_stream_continuous_and_never_marks_a_run_start() {
    let mut room = all_sendrecv(3);
    room.set_source(Some("seat-1")).unwrap();
    // seat-1: a picture in three packets, the last one marked (RFC 6184 §5.1).
    let mut sent_to_three = Vec::new();
    for (step, (sequence, marker, start, end)) in [
        (10u16, false, true, false),
        (11, false, false, false),
        (12, true, false, true),
    ]
    .into_iter()
    .enumerate()
    {
        let arrival = 1_000_000 + step as u64 * 1_000;
        let packet = rx_video(
            1,
            arrival,
            video_rtp(
                99,
                sequence,
                90_000,
                0x1111_1111,
                marker,
                &fu_a(start, end, &[9]),
            ),
        );
        room.ingest(&packet);
        for (endpoint, _, datagram) in forwarded(&mut room, &packet) {
            if endpoint == EndpointId(103) {
                sent_to_three.push(parsed(&datagram));
            }
        }
    }
    // The talker changes in the middle of seat-2's picture: its first packet we see is a middle
    // fragment, marker clear. A rebase must not mark it.
    room.set_source(Some("seat-2")).unwrap();
    let middle = rx_video(
        2,
        2_000_000,
        video_rtp(
            100,
            500,
            3_000_000,
            0x2222_2222,
            false,
            &fu_a(false, false, &[7]),
        ),
    );
    room.ingest(&middle);
    for (endpoint, _, datagram) in forwarded(&mut room, &middle) {
        if endpoint == EndpointId(103) {
            sent_to_three.push(parsed(&datagram));
        }
    }
    let last = rx_video(
        2,
        2_033_000,
        video_rtp(
            100,
            501,
            3_003_000,
            0x2222_2222,
            true,
            &fu_a(false, true, &[8]),
        ),
    );
    room.ingest(&last);
    for (endpoint, _, datagram) in forwarded(&mut room, &last) {
        if endpoint == EndpointId(103) {
            sent_to_three.push(parsed(&datagram));
        }
    }
    let markers: Vec<bool> = sent_to_three.iter().map(|sent| sent.0).collect();
    assert_eq!(
        markers,
        [false, false, true, false, true],
        "the sender's own marker bits"
    );
    let sequences: Vec<u16> = sent_to_three.iter().map(|sent| sent.2).collect();
    assert_eq!(
        sequences,
        [2000, 2001, 2002, 2003, 2004],
        "continuous across the switch"
    );
    assert!(
        sent_to_three.iter().all(|sent| sent.4 == 0xF000_0003),
        "one stable SSRC"
    );
    // Timestamps run on the 90 kHz clock: the first packet of the new run sits the elapsed time
    // after the last one of the old run (2_000_000 - 1_002_000 µs = 998_000 µs).
    let timestamps: Vec<u32> = sent_to_three.iter().map(|sent| sent.3).collect();
    assert_eq!(timestamps[0], 70_000);
    assert_eq!(
        timestamps[2], 70_000,
        "inside a run the sender's own timestamps are kept"
    );
    assert_eq!(timestamps[3], 70_000 + 89_820, "998_000 µs at 90 kHz");
    assert_eq!(
        timestamps[4],
        timestamps[3] + 3_000,
        "the new run keeps its own spacing"
    );
}

#[test]
fn a_source_change_moves_audio_and_video_together() {
    let mut room = all_sendrecv(3);
    room.set_source(Some("seat-1")).unwrap();
    let audio = rx(1, 1_000, rtp(96, 1, 0, 0x1111_1111, &[1, 2, 3]));
    let video = rx_video(1, 1_000, video_rtp(99, 1, 0, 0x1111_1111, true, &[0x65, 1]));
    for packet in [&audio, &video] {
        assert_eq!(room.ingest(packet), Ingress::Accepted);
        assert_eq!(forwarded(&mut room, packet).len(), 2);
    }
    room.set_source(Some("seat-2")).unwrap();
    for packet in [&audio, &video] {
        assert_eq!(room.ingest(packet), Ingress::DroppedFromPeer);
        assert!(room.next_datagram(packet).is_none());
    }
    let stats = room.seat_stats("seat-1").unwrap();
    assert_eq!(stats.not_source_dropped, 1);
    assert_eq!(stats.video_not_source_dropped, 1);
    let audio_two = rx(2, 2_000, rtp(96, 1, 0, 0x2222_2222, &[1]));
    let video_two = rx_video(
        2,
        2_000,
        video_rtp(100, 1, 0, 0x2222_2222, true, &[0x65, 2]),
    );
    for packet in [&audio_two, &video_two] {
        assert_eq!(room.ingest(packet), Ingress::Accepted);
        assert_eq!(forwarded(&mut room, packet).len(), 2);
    }
}

#[test]
fn one_source_started_event_per_switch_not_one_per_stream() {
    let mut room = all_sendrecv(2);
    room.set_source(Some("seat-1")).unwrap();
    let video = rx_video(1, 1_000, video_rtp(99, 1, 0, 5, true, &[0x65]));
    room.ingest(&video);
    forwarded(&mut room, &video);
    let audio = rx(1, 1_000, rtp(96, 1, 0, 5, &[1]));
    room.ingest(&audio);
    forwarded(&mut room, &audio);
    assert_eq!(room.drain_events().count(), 1);
}

#[test]
fn a_receive_only_seat_is_never_forwarded_from_and_still_receives() {
    let mut room = video_room(&[
        MediaDirection::SendRecv,
        MediaDirection::RecvOnly,
        MediaDirection::SendRecv,
    ]);
    room.set_source(Some("seat-2")).unwrap();
    let uplink = rx_video(2, 0, video_rtp(100, 1, 0, 0x2222_2222, true, &[0x65]));
    assert_eq!(room.ingest(&uplink), Ingress::DroppedFromPeer);
    assert!(room.next_datagram(&uplink).is_none());
    assert_eq!(
        room.seat_stats("seat-2")
            .unwrap()
            .video_receive_only_dropped,
        1
    );
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx_video(1, 0, video_rtp(99, 1, 0, 0x1111_1111, true, &[0x65]));
    room.ingest(&packet);
    let sent = forwarded(&mut room, &packet);
    let endpoints: Vec<u64> = sent.iter().map(|(endpoint, _, _)| endpoint.0).collect();
    assert!(
        endpoints.contains(&102),
        "the receive-only seat is sent video: {endpoints:?}"
    );
    assert!(endpoints.contains(&103));
}

#[test]
fn a_send_only_seat_is_sent_no_video_but_may_be_the_source() {
    let mut room = video_room(&[
        MediaDirection::SendRecv,
        MediaDirection::SendRecv,
        MediaDirection::SendOnly,
    ]);
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx_video(1, 0, video_rtp(99, 1, 0, 0x1111_1111, true, &[0x65]));
    room.ingest(&packet);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 1, "only seat-2 receives video");
    assert_eq!(sent[0].0, EndpointId(102));
    room.set_source(Some("seat-3")).unwrap();
    let uplink = rx_video(3, 10, video_rtp(101, 1, 0, 0x3333_3333, true, &[0x65]));
    assert_eq!(room.ingest(&uplink), Ingress::Accepted);
    assert_eq!(forwarded(&mut room, &uplink).len(), 2);
}

#[test]
fn an_inactive_seat_neither_sends_nor_receives_video() {
    let mut room = video_room(&[
        MediaDirection::SendRecv,
        MediaDirection::Inactive,
        MediaDirection::SendRecv,
    ]);
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx_video(1, 0, video_rtp(99, 1, 0, 1, true, &[0x65]));
    room.ingest(&packet);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, EndpointId(103));
    room.set_source(Some("seat-2")).unwrap();
    let uplink = rx_video(2, 10, video_rtp(100, 1, 0, 2, true, &[0x65]));
    assert_eq!(room.ingest(&uplink), Ingress::DroppedFromPeer);
}

#[test]
fn an_audio_only_seat_is_never_sent_video_and_has_no_video_endpoint() {
    let mut room = amr_wb_room();
    room.add_seat(video_seat(1, MediaDirection::SendRecv), 0)
        .unwrap();
    room.add_seat(seat_config(2), 0).unwrap();
    room.add_seat(video_seat(3, MediaDirection::SendRecv), 0)
        .unwrap();
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx_video(1, 0, video_rtp(99, 1, 0, 1, true, &[0x65]));
    room.ingest(&packet);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, EndpointId(103));
    // Nothing owns the audio-only seat's would-be video endpoint.
    let stray = rx_video(2, 0, video_rtp(100, 1, 0, 2, true, &[0x65]));
    assert_eq!(room.ingest(&stray), Ingress::Refused);
    assert_eq!(
        room.tag_at(EndpointId(101)),
        Some("seat-1"),
        "video routes to its seat"
    );
}

#[test]
fn a_source_with_no_video_sends_receivers_none() {
    let mut room = amr_wb_room();
    room.add_seat(seat_config(1), 0).unwrap();
    room.add_seat(video_seat(2, MediaDirection::SendRecv), 0)
        .unwrap();
    room.set_source(Some("seat-1")).unwrap();
    let audio = rx(1, 0, rtp(96, 1, 0, 1, &[1, 2, 3]));
    room.ingest(&audio);
    assert_eq!(
        forwarded(&mut room, &audio).len(),
        1,
        "the audio still flows"
    );
    assert_eq!(
        room.seat_stats("seat-2").unwrap().video_forwarded_packets,
        0
    );
}

#[test]
fn video_from_an_unsignalled_address_is_refused_by_the_gate() {
    let mut room = all_sendrecv(2);
    room.set_source(Some("seat-1")).unwrap();
    let mut packet = rx_video(1, 0, video_rtp(99, 1, 0, 1, true, &[0x65]));
    packet.source = address("203.0.113.9:5000");
    assert_eq!(room.ingest(&packet), Ingress::Refused);
    assert!(room.next_datagram(&packet).is_none());
}

#[test]
fn video_does_not_latch_to_another_source_mid_stream() {
    // docs/security-and-nat.md §4 layer 3: a second source that cannot prove it is the seat's stream
    // (another SSRC from another port) is refused, and the reply address stays.
    let mut room = amr_wb_room();
    let mut config = video_seat(1, MediaDirection::SendRecv);
    if let Some(video) = config.video.as_mut() {
        video.accepted_source = SourceFilter::Any;
    }
    room.add_seat(config, 0).unwrap();
    room.add_seat(video_seat(2, MediaDirection::SendRecv), 0)
        .unwrap();
    room.set_source(Some("seat-1")).unwrap();
    let genuine = rx_video(1, 0, video_rtp(99, 1, 0, 0x1111_1111, true, &[0x65]));
    assert_eq!(room.ingest(&genuine), Ingress::Accepted);
    let mut hijack = rx_video(1, 10, video_rtp(99, 2, 0, 0x6666_6666, true, &[0x65]));
    hijack.source = address("198.51.100.66:6000");
    assert_eq!(room.ingest(&hijack), Ingress::Refused);
    assert!(room.next_datagram(&hijack).is_none());
}

#[test]
fn a_video_payload_type_the_seat_did_not_negotiate_is_dropped_and_counted() {
    let mut room = all_sendrecv(2);
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx_video(1, 0, video_rtp(120, 1, 0, 1, true, &[0x65]));
    assert_eq!(room.ingest(&packet), Ingress::DroppedFromPeer);
    assert!(room.next_datagram(&packet).is_none());
    assert_eq!(
        room.seat_stats("seat-1")
            .unwrap()
            .video_unknown_payload_type,
        1
    );
}

#[test]
fn video_rtcp_is_consumed_and_never_forwarded() {
    let mut room = all_sendrecv(2);
    room.set_source(Some("seat-1")).unwrap();
    // A sender report of the source on its video endpoint (RFC 3550 §6.4.1).
    let mut report = vec![0x80, 200, 0, 6];
    report.extend_from_slice(&0x1111_1111u32.to_be_bytes());
    report.extend_from_slice(&[0xE0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
    report.extend_from_slice(&[0; 12]);
    let packet = rx_video(1, 0, report);
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    assert!(room.next_datagram(&packet).is_none());
}

#[test]
fn the_video_report_is_a_sender_report_on_the_video_endpoint_under_the_video_ssrc() {
    let mut room = all_sendrecv(2);
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx_video(
        1,
        1_000_000,
        video_rtp(99, 1, 9000, 0x1111_1111, true, &[0x65, 1, 2]),
    );
    room.ingest(&packet);
    forwarded(&mut room, &packet);
    let mut out = Vec::new();
    room.build_reports(0xE000_0000_0000_0000, 2_000_000, &mut out);
    let video: Vec<_> = out
        .iter()
        .filter(|outbound| outbound.endpoint.0 > 100)
        .collect();
    assert_eq!(video.len(), 2, "one report per video seat: {out:?}");
    let to_two = video
        .iter()
        .find(|outbound| outbound.endpoint == EndpointId(102))
        .unwrap();
    assert_eq!(to_two.dst, address("192.0.2.2:5000"));
    assert_eq!(to_two.data[1], 200, "a sender report");
    assert_eq!(
        u32::from_be_bytes(to_two.data[4..8].try_into().unwrap()),
        0xF000_0002
    );
    // Sender packet count 1 and octet count 3 (RFC 3550 §6.4.1).
    assert_eq!(
        u32::from_be_bytes(to_two.data[20..24].try_into().unwrap()),
        1
    );
    assert_eq!(
        u32::from_be_bytes(to_two.data[24..28].try_into().unwrap()),
        3
    );
    // The RTP timestamp sits on the 90 kHz line: last sent plus the second elapsed since.
    let rtp_timestamp = u32::from_be_bytes(to_two.data[16..20].try_into().unwrap());
    assert_eq!(rtp_timestamp, 70_000u32.wrapping_add(90_000));
}

#[test]
fn a_video_seat_that_left_frees_its_endpoint_and_the_others_still_route() {
    let mut room = all_sendrecv(3);
    assert!(room.remove_seat("seat-1"));
    let gone = rx_video(1, 0, video_rtp(99, 1, 0, 1, true, &[0x65]));
    assert_eq!(room.ingest(&gone), Ingress::Refused);
    // seat-2 and seat-3 moved down one position; their video endpoints still reach them.
    assert_eq!(room.tag_at(EndpointId(102)), Some("seat-2"));
    assert_eq!(room.tag_at(EndpointId(103)), Some("seat-3"));
    room.set_source(Some("seat-3")).unwrap();
    let packet = rx_video(3, 0, video_rtp(101, 1, 0, 3, true, &[0x65]));
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, EndpointId(102));
}

#[test]
fn a_receiver_with_no_video_destination_yet_is_skipped() {
    let mut room = amr_wb_room();
    room.add_seat(video_seat(1, MediaDirection::SendRecv), 0)
        .unwrap();
    let mut unresolved = video_seat(2, MediaDirection::SendRecv);
    if let Some(video) = unresolved.video.as_mut() {
        video.destination = address("0.0.0.0:0");
    }
    room.add_seat(unresolved, 0).unwrap();
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx_video(1, 0, video_rtp(99, 1, 0, 1, true, &[0x65]));
    room.ingest(&packet);
    assert!(
        room.next_datagram(&packet).is_none(),
        "the room never forwards into the void"
    );
}

/// The first bytes of an IDR slice of an x264 stream (RFC 6184 §5.8: what follows the FU header of a
/// start fragment is the NAL unit's own bytes, here its slice header), so a dissector reads them.
const SLICE_HEADER: [u8; 5] = [0x88, 0x84, 0x00, 0x33, 0xFF];

#[test]
fn a_translated_fu_a_start_and_end_pair_is_pinned_byte_for_byte() {
    // The bytes seat-2 is sent for seat-1's two fragments of one IDR slice (RFC 6184 §5.8): its own
    // payload type 100, SSRC 0xF000_0002, the egress sequence from 2000 and the first timestamp
    // 70000 shared by the access unit, the marker on the last fragment only. Wireshark's RTP and
    // H.264 dissectors read these exact bytes back as payload type 100, marker 0 then 1, an FU-A
    // start then an FU-A end, sequence 2000 then 2001, with no malformed packet.
    let mut room = all_sendrecv(2);
    room.set_source(Some("seat-1")).unwrap();
    let start = rx_video(
        1,
        1_000_000,
        video_rtp(
            99,
            7,
            90_000,
            0x1111_1111,
            false,
            &fu_a(true, false, &SLICE_HEADER),
        ),
    );
    let end = rx_video(
        1,
        1_000_100,
        video_rtp(
            99,
            8,
            90_000,
            0x1111_1111,
            true,
            &fu_a(false, true, &[0x12, 0x34]),
        ),
    );
    let mut sent = Vec::new();
    for packet in [&start, &end] {
        room.ingest(packet);
        sent.extend(
            forwarded(&mut room, packet)
                .into_iter()
                .map(|(_, _, data)| data),
        );
    }
    assert_eq!(
        sent,
        [
            vec![
                0x80, 0x64, 0x07, 0xD0, 0x00, 0x01, 0x11, 0x70, 0xF0, 0x00, 0x00, 0x02, 0x7C, 0x85,
                0x88, 0x84, 0x00, 0x33, 0xFF
            ],
            vec![
                0x80, 0xE4, 0x07, 0xD1, 0x00, 0x01, 0x11, 0x70, 0xF0, 0x00, 0x00, 0x02, 0x7C, 0x45,
                0x12, 0x34
            ],
        ]
    );
}
