//! Video on a WebRTC seat: the video is bundled with the seat's audio on one transport (RFC 8843), so
//! it arrives on the seat's one endpoint after the seat's own SRTP is removed, is told from the audio
//! by payload type (RFC 8843 §9.2), and leaves under the seat's own `SecureLeg` to the seat's latched
//! destination. The seat's phone is played by the mirror-image `SecureLeg`.

use super::super::video::rtcp_is_about_video;
use super::video::{fu_a, video_rtp, video_seat, FIRST_VIDEO_PAYLOAD_TYPE};
use super::*;
use crate::sdp::video::VideoFeedback;
use crate::sdp::MediaDirection;
use siphon_rtp_media::rtcp::{self, Feedback};
use siphon_rtp_srtp::leg::PacketKind;
use siphon_rtp_srtp::sdes::SrtpKeyMaterial;

const SLICE: [u8; 3] = [0x41, 0x9A, 0x00];

pub(super) fn key(seed: u8) -> SrtpKeyMaterial {
    SrtpKeyMaterial::from_inline_bytes(&[seed; 30]).unwrap()
}

/// What the room sends seat `index` is protected under `key(10 + index)`; what the seat sends is
/// protected under `key(20 + index)`.
pub(super) fn room_leg(index: u8) -> SecureLeg {
    SecureLeg::new(&key(10 + index), &key(20 + index))
}

/// The seat's phone: the mirror image of [`room_leg`].
pub(super) fn phone(index: u8) -> SecureLeg {
    SecureLeg::new(&key(20 + index), &key(10 + index))
}

/// Seat `index` as a WebRTC seat: audio on endpoint `index`, video bundled on the same endpoint (no
/// endpoint of its own), keyed, with its video payload type `98 + index` and egress SSRC
/// `0xF000_0000 | index`.
pub(super) fn webrtc_seat(index: u8, direction: MediaDirection) -> ForwardSeatConfig {
    let mut config = video_seat(index, direction);
    config.secure = Some(room_leg(index));
    if let Some(video) = config.video.as_mut() {
        video.endpoint = config.endpoint;
        video.destination = config.egress_destination;
        video.accepted_source = config.accepted_source;
        video.feedback = VideoFeedback::SUPPORTED;
        video.cname = format!("seat-{index}-cname");
        video.bundled = true;
    }
    config
}

/// A room of the given seats, seat `n` plain when `plain.contains(n)` and WebRTC otherwise.
pub(super) fn mixed_room(plain: &[u8], webrtc: &[u8]) -> ForwardRoom {
    let mut room = amr_wb_room();
    let mut indexes: Vec<u8> = plain.iter().chain(webrtc).copied().collect();
    indexes.sort_unstable();
    for index in indexes {
        let config = if plain.contains(&index) {
            let mut config = video_seat(index, MediaDirection::SendRecv);
            if let Some(video) = config.video.as_mut() {
                video.feedback = VideoFeedback::SUPPORTED;
            }
            config
        } else {
            webrtc_seat(index, MediaDirection::SendRecv)
        };
        room.add_seat(config, 0).unwrap();
    }
    room
}

/// A datagram from WebRTC seat `index`, protected by its phone.
pub(super) fn rx_secure(phone: &mut SecureLeg, index: u8, arrival: u64, clear: &[u8]) -> RxPacket {
    let mut wire = Vec::new();
    phone.protect(clear, &mut wire).unwrap();
    RxPacket {
        endpoint: EndpointId(u64::from(index)),
        source: address(&format!("192.0.2.{index}:4000")),
        arrival,
        data: Bytes::from(wire),
    }
}

/// The source's media SSRC from seat `index`.
fn media_ssrc(index: u8) -> u32 {
    0x1000_0000 | u32::from(index)
}

pub(super) fn clear_of(phone: &mut SecureLeg, wire: &[u8]) -> (PacketKind, Vec<u8>) {
    let mut clear = Vec::new();
    let kind = phone.unprotect(wire, &mut clear).unwrap();
    (kind, clear)
}

/// Seat `index` (WebRTC) sends one video RTP packet; what the room sent for it.
fn webrtc_sends(
    room: &mut ForwardRoom,
    phone: &mut SecureLeg,
    index: u8,
    arrival: u64,
    sequence: u16,
    payload: &[u8],
) -> (Ingress, Vec<(EndpointId, SocketAddr, Vec<u8>)>) {
    let clear = video_rtp(
        FIRST_VIDEO_PAYLOAD_TYPE + index,
        sequence,
        u32::from(sequence) * 3000,
        media_ssrc(index),
        false,
        payload,
    );
    let packet = rx_secure(phone, index, arrival, &clear);
    let outcome = room.ingest(&packet);
    (outcome, forwarded(room, &packet))
}

/// Plain seat `index` sends one video RTP packet; what the room sent for it.
fn plain_sends(
    room: &mut ForwardRoom,
    index: u8,
    arrival: u64,
    sequence: u16,
    payload: &[u8],
) -> Vec<(EndpointId, SocketAddr, Vec<u8>)> {
    let packet = super::video::rx_video(
        index,
        arrival,
        video_rtp(
            FIRST_VIDEO_PAYLOAD_TYPE + index,
            sequence,
            u32::from(sequence) * 3000,
            media_ssrc(index),
            false,
            payload,
        ),
    );
    room.ingest(&packet);
    forwarded(room, &packet)
}

#[test]
fn video_from_a_plain_seat_reaches_a_webrtc_seat_as_srtp_on_its_one_endpoint() {
    let mut room = mixed_room(&[1], &[2]);
    room.set_source(Some("seat-1")).unwrap();
    let payload = fu_a(true, false, &[1, 2, 3, 4]);
    let sent = plain_sends(&mut room, 1, 1_000_000, 7, &payload);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (endpoint, destination, wire) = &sent[0];
    assert_eq!(
        *endpoint,
        EndpointId(2),
        "the seat's own endpoint, not a video one"
    );
    assert_eq!(*destination, address("192.0.2.2:4000"));
    let (kind, clear) = clear_of(&mut phone(2), wire);
    assert_eq!(kind, PacketKind::Rtp);
    let (_, payload_type, _, _, ssrc, body) = parsed(&clear);
    assert_eq!(
        payload_type,
        FIRST_VIDEO_PAYLOAD_TYPE + 2,
        "the seat's own number"
    );
    assert_eq!(
        ssrc, 0xF000_0002,
        "the video egress SSRC, not the audio one"
    );
    assert_eq!(body, payload, "payload byte-identical");
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!(stats.video_forwarded_packets, 1);
    assert_eq!(stats.forwarded_packets, 0, "no audio was sent");
}

#[test]
fn video_from_a_webrtc_seat_is_unprotected_told_from_its_audio_and_sent_clear_to_a_plain_seat() {
    let mut room = mixed_room(&[2], &[1]);
    room.set_source(Some("seat-1")).unwrap();
    let mut phone = phone(1);
    let payload = fu_a(true, false, &[9, 8, 7]);
    let (outcome, sent) = webrtc_sends(&mut room, &mut phone, 1, 1_000_000, 7, &payload);
    assert_eq!(outcome, Ingress::Accepted);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (endpoint, destination, wire) = &sent[0];
    assert_eq!(
        *endpoint,
        EndpointId(102),
        "the plain seat's own video endpoint"
    );
    assert_eq!(*destination, address("192.0.2.2:5000"));
    let (_, payload_type, _, _, ssrc, body) = parsed(wire);
    assert_eq!(payload_type, FIRST_VIDEO_PAYLOAD_TYPE + 2);
    assert_eq!(ssrc, 0xF000_0002);
    assert_eq!(body, payload);
    // The seat's audio on the same endpoint is still audio: forwarded to the plain seat's audio
    // endpoint, in the room codec, and counted as audio.
    let audio = rx_secure(
        &mut phone,
        1,
        1_020_000,
        &rtp(96, 1, 0, 0x1111_1111, &[5, 6]),
    );
    assert_eq!(room.ingest(&audio), Ingress::Accepted);
    let sent = forwarded(&mut room, &audio);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, EndpointId(2));
    assert_eq!(parsed(&sent[0].2).5, [5, 6]);
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!(
        (stats.forwarded_packets, stats.video_forwarded_packets),
        (1, 1)
    );
}

#[test]
fn a_webrtc_receivers_stream_stays_continuous_across_a_switch_between_two_sources() {
    let mut room = mixed_room(&[1, 3], &[2]);
    room.set_source(Some("seat-1")).unwrap();
    let mut seen = Vec::new();
    let mut receiving = phone(2);
    for (sequence, payload) in [(10u16, fu_a(true, false, &[1])), (11, SLICE.to_vec())] {
        let sent = plain_sends(
            &mut room,
            1,
            1_000_000 + u64::from(sequence),
            sequence,
            &payload,
        );
        for (_, _, wire) in sent
            .into_iter()
            .filter(|(endpoint, _, _)| *endpoint == EndpointId(2))
        {
            let (_, clear) = clear_of(&mut receiving, &wire);
            let (_, _, sequence, timestamp, ssrc, _) = parsed(&clear);
            seen.push((ssrc, sequence, timestamp));
        }
    }
    room.set_source(Some("seat-3")).unwrap();
    // The new talker's picture starts the receiver again (the gate opens on its IDR).
    let sent = plain_sends(&mut room, 3, 2_000_000, 500, &fu_a(true, false, &[2]));
    let to_two: Vec<_> = sent
        .iter()
        .filter(|(endpoint, _, _)| *endpoint == EndpointId(2))
        .collect();
    assert_eq!(to_two.len(), 1, "{sent:?}");
    let (_, clear) = clear_of(&mut receiving, &to_two[0].2);
    let (_, _, sequence, timestamp, ssrc, _) = parsed(&clear);
    seen.push((ssrc, sequence, timestamp));
    assert!(
        seen.iter().all(|(ssrc, _, _)| *ssrc == 0xF000_0002),
        "{seen:?}"
    );
    assert_eq!(
        seen.iter()
            .map(|(_, sequence, _)| *sequence)
            .collect::<Vec<_>>(),
        [2000, 2001, 2002],
        "sequence numbers run on across the switch"
    );
    assert!(
        seen[2].2.wrapping_sub(seen[1].2) > 0 && seen[2].2.wrapping_sub(seen[1].2) < 1_000_000,
        "the timestamp moves forward by the time that passed, not by the talkers' own clocks: {seen:?}"
    );
}

#[test]
fn a_switch_to_a_webrtc_talker_sends_it_a_pli_as_srtcp_and_gates_receivers_until_its_idr() {
    let mut room = mixed_room(&[2], &[1]);
    let mut talker = phone(1);
    // The talker has sent video (so its SSRC is known) before it is chosen.
    webrtc_sends(&mut room, &mut talker, 1, 0, 1, &SLICE);
    room.set_source(Some("seat-1")).unwrap();
    let mut out = Vec::new();
    room.poll_keyframe(1000, &mut out);
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0].endpoint, EndpointId(1), "the seat's one endpoint");
    assert_eq!(out[0].dst, address("192.0.2.1:4000"));
    // It is SRTCP under the seat's key: opens with the phone's key, not before.
    let (kind, clear) = clear_of(&mut talker_phone(), &out[0].data);
    assert_eq!(kind, PacketKind::Rtcp);
    let packets = rtcp::parse_compound(&clear).unwrap();
    assert!(matches!(
        &packets[0],
        rtcp::RtcpPacket::ReceiverReport(report) if report.ssrc == 0xF000_0001
    ));
    let feedback: Vec<_> = rtcp::feedback_packets(&clear).map(Result::unwrap).collect();
    assert_eq!(
        feedback,
        [Feedback::Pli {
            sender_ssrc: 0xF000_0001,
            media_ssrc: media_ssrc(1)
        }]
    );
    assert_eq!(room.seat_stats("seat-1").unwrap().pli_sent, 1);
    // The receiver waits for the talker's picture.
    let (_, held) = webrtc_sends(&mut room, &mut talker, 1, 10, 2, &SLICE);
    assert!(held.is_empty(), "gated until an IDR: {held:?}");
    let (_, opened) = webrtc_sends(&mut room, &mut talker, 1, 20, 3, &fu_a(true, false, &[1]));
    assert_eq!(opened.len(), 1, "{opened:?}");
    assert_eq!(opened[0].0, EndpointId(102));
}

/// A phone that has seen none of what the room sent (SRTCP replay state is per leg).
fn talker_phone() -> SecureLeg {
    phone(1)
}

#[test]
fn a_nack_from_a_webrtc_receiver_is_answered_as_the_same_srtp_packet_on_its_endpoint() {
    let mut room = mixed_room(&[1], &[2]);
    let mut receiving = phone(2);
    room.set_source(Some("seat-1")).unwrap();
    let first = plain_sends(&mut room, 1, 1_000, 1, &fu_a(true, false, &[1, 2]));
    let second = plain_sends(&mut room, 1, 2_000, 2, &SLICE);
    assert_eq!((first.len(), second.len()), (1, 1));
    let (_, original) = clear_of(&mut receiving, &first[0].2);
    // The receiver lost the first packet: pid 2000 (the room's first sequence number).
    let mut nack = vec![0u8; 16];
    rtcp::write_nack(0x2222_2222, 0xF000_0002, 2000, 0, &mut nack).unwrap();
    let request = rx_secure(&mut phone(2), 2, 3_000, &nack);
    assert_eq!(room.ingest(&request), Ingress::Accepted);
    let resent = forwarded(&mut room, &request);
    assert_eq!(resent.len(), 1, "{resent:?}");
    assert_eq!(resent[0].0, EndpointId(2));
    assert_eq!(resent[0].1, address("192.0.2.2:4000"));
    assert_eq!(
        resent[0].2, first[0].2,
        "SRTP: the very bytes that were sent"
    );
    let (kind, again) = clear_of(&mut phone(2), &resent[0].2);
    assert_eq!(kind, PacketKind::Rtp);
    assert_eq!(again, original);
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!((stats.nack_answered, stats.nack_missed), (1, 0));
}

#[test]
fn a_nack_for_a_packet_the_room_no_longer_remembers_is_not_answered_by_encrypting_it_again() {
    // RFC 3711 §9.1: the answer to a NACK is the datagram that was sent, so a packet that has left the
    // receiver's bounded history cannot be answered, and the sender never encrypts at an index it has
    // already used to find out.
    let mut room = mixed_room(&[1], &[2]);
    room.set_source(Some("seat-1")).unwrap();
    let first = plain_sends(&mut room, 1, 1_000, 1, &fu_a(true, false, &[1, 2]));
    assert_eq!(first.len(), 1);
    for sequence in 2..=80u16 {
        let sent = plain_sends(&mut room, 1, 1_000 * u64::from(sequence), sequence, &SLICE);
        assert_eq!(sent.len(), 1);
    }
    let mut nack = vec![0u8; 16];
    rtcp::write_nack(0x2222_2222, 0xF000_0002, 2000, 0, &mut nack).unwrap();
    let request = rx_secure(&mut phone(2), 2, 90_000, &nack);
    assert_eq!(room.ingest(&request), Ingress::Accepted);
    let resent = forwarded(&mut room, &request);
    assert!(resent.is_empty(), "{resent:?}");
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!((stats.nack_answered, stats.nack_missed), (0, 1));
}

#[test]
fn a_nack_after_the_seats_key_is_replaced_is_not_answered_with_what_the_old_key_sealed() {
    // RFC 3711 §9.1: what was sealed under the replaced key is not the answer under the new one.
    let mut room = mixed_room(&[1], &[2]);
    room.set_source(Some("seat-1")).unwrap();
    let first = plain_sends(&mut room, 1, 1_000, 1, &fu_a(true, false, &[1, 2]));
    assert_eq!(first.len(), 1);
    room.attach_secure_leg("seat-2", room_leg(2));
    let mut nack = vec![0u8; 16];
    rtcp::write_nack(0x2222_2222, 0xF000_0002, 2000, 0, &mut nack).unwrap();
    let request = rx_secure(&mut phone(2), 2, 3_000, &nack);
    assert_eq!(room.ingest(&request), Ingress::Accepted);
    let resent = forwarded(&mut room, &request);
    assert!(resent.is_empty(), "{resent:?}");
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!((stats.nack_answered, stats.nack_missed), (0, 1));
}

#[test]
fn a_pli_from_a_webrtc_receiver_reaches_the_source_but_an_audio_report_does_not() {
    let mut room = mixed_room(&[1], &[2]);
    plain_sends(&mut room, 1, 0, 1, &SLICE);
    room.set_source(Some("seat-1")).unwrap();
    // The switch's own request is answered by the source's keyframe, so only a receiver's remains.
    plain_sends(&mut room, 1, 0, 2, &fu_a(true, false, &[1]));
    let mut out = Vec::new();
    room.poll_keyframe(0, &mut out);
    room.poll_keyframe(1, &mut out);
    out.clear();
    // An audio receiver report: about the audio egress stream, so it is audio's and asks for nothing.
    let mut report = vec![0u8; 8];
    rtcp::write_empty_receiver_report(0x2222_2222, &mut report).unwrap();
    let mut seat_two = phone(2);
    let report = rx_secure(&mut seat_two, 2, 20_000, &report);
    assert_eq!(room.ingest(&report), Ingress::Accepted);
    // A PLI about the video egress stream is video's.
    let mut pli = vec![0u8; 12];
    rtcp::write_pli(0x2222_2222, 0xF000_0002, &mut pli).unwrap();
    let request = rx_secure(&mut seat_two, 2, 30_000, &pli);
    assert_eq!(room.ingest(&request), Ingress::Accepted);
    room.poll_keyframe(5_000, &mut out);
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(
        out[0].endpoint,
        EndpointId(101),
        "to the plain source's video endpoint"
    );
}

#[test]
fn the_reports_to_a_webrtc_seat_are_srtcp_one_per_stream_from_its_endpoint() {
    let mut room = mixed_room(&[1], &[2]);
    room.set_source(Some("seat-1")).unwrap();
    plain_sends(&mut room, 1, 1_000, 1, &fu_a(true, false, &[1]));
    let mut out = Vec::new();
    room.build_reports(1 << 32, 50_000, &mut out);
    let to_seat: Vec<_> = out
        .iter()
        .filter(|outbound| outbound.endpoint == EndpointId(2))
        .collect();
    assert_eq!(to_seat.len(), 2, "an audio report and a video one: {out:?}");
    let mut receiving = phone(2);
    let mut senders = Vec::new();
    for outbound in to_seat {
        assert_eq!(outbound.dst, address("192.0.2.2:4000"));
        let (kind, clear) = clear_of(&mut receiving, &outbound.data);
        assert_eq!(kind, PacketKind::Rtcp);
        let packets = rtcp::parse_compound(&clear).unwrap();
        // The audio stream was never sent a packet, so RFC 3550 §6.4 makes its report an RR; the
        // video stream was, so its report is an SR.
        match &packets[0] {
            rtcp::RtcpPacket::SenderReport(report) => senders.push((report.ssrc, 200)),
            rtcp::RtcpPacket::ReceiverReport(report) => senders.push((report.ssrc, 201)),
            other => panic!("{other:?}"),
        }
    }
    senders.sort_unstable();
    assert_eq!(senders, [(0xE000_0002, 201), (0xF000_0002, 200)]);
}

#[test]
fn a_bundled_video_is_never_sent_to_a_seat_whose_key_has_not_arrived() {
    let mut room = amr_wb_room();
    room.add_seat(video_seat(1, MediaDirection::SendRecv), 0)
        .unwrap();
    let mut pending = webrtc_seat(2, MediaDirection::SendRecv);
    pending.secure = None;
    pending.secure_pending = true;
    room.add_seat(pending, 0).unwrap();
    room.set_source(Some("seat-1")).unwrap();
    let sent = plain_sends(&mut room, 1, 0, 1, &fu_a(true, false, &[1]));
    assert!(
        sent.is_empty(),
        "nothing in the clear to an unkeyed seat: {sent:?}"
    );
    room.attach_secure_leg("seat-2", room_leg(2));
    let sent = plain_sends(&mut room, 1, 20_000, 2, &fu_a(true, false, &[2]));
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (kind, _) = clear_of(&mut phone(2), &sent[0].2);
    assert_eq!(kind, PacketKind::Rtp);
}

#[test]
fn a_recvonly_webrtc_video_seat_is_sent_video_and_is_never_a_source() {
    let mut room = amr_wb_room();
    room.add_seat(video_seat(1, MediaDirection::SendRecv), 0)
        .unwrap();
    room.add_seat(webrtc_seat(2, MediaDirection::RecvOnly), 0)
        .unwrap();
    room.set_source(Some("seat-2")).unwrap();
    let mut seat_two = phone(2);
    let (outcome, sent) = webrtc_sends(&mut room, &mut seat_two, 2, 0, 1, &fu_a(true, false, &[1]));
    assert_eq!(
        outcome,
        Ingress::DroppedFromPeer,
        "it said it sends no video"
    );
    assert!(sent.is_empty());
    assert_eq!(
        room.seat_stats("seat-2")
            .unwrap()
            .video_receive_only_dropped,
        1
    );
    room.set_source(Some("seat-1")).unwrap();
    let sent = plain_sends(&mut room, 1, 20_000, 2, &fu_a(true, false, &[2]));
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, EndpointId(2));
}

fn rr(sender: u32, about: &[u32]) -> Vec<u8> {
    let mut packet = vec![
        0x80 | about.len() as u8,
        201,
        0,
        (1 + 6 * about.len()) as u8,
    ];
    packet.extend_from_slice(&sender.to_be_bytes());
    for ssrc in about {
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0; 20]);
    }
    packet
}

#[test]
fn rtcp_is_about_the_video_by_its_blocks_its_feedback_or_its_sender() {
    const EGRESS: u32 = 0xF000_0001;
    // A report block about the stream the room sends the video.
    assert!(rtcp_is_about_video(
        &rr(0x11, &[0x22, EGRESS]),
        EGRESS,
        None
    ));
    assert!(
        !rtcp_is_about_video(&rr(0x11, &[0x22]), EGRESS, None),
        "an audio report"
    );
    // A report from the seat's video sender, however empty.
    assert!(rtcp_is_about_video(&rr(0x33, &[]), EGRESS, Some(0x33)));
    assert!(!rtcp_is_about_video(&rr(0x33, &[]), EGRESS, Some(0x44)));
    // A Sender Report's blocks start after its 20 octets of sender information.
    let mut sender_report = vec![0x81, 200, 0, 12];
    sender_report.extend_from_slice(&0x55u32.to_be_bytes());
    sender_report.extend_from_slice(&[0; 20]);
    sender_report.extend_from_slice(&EGRESS.to_be_bytes());
    sender_report.extend_from_slice(&[0; 20]);
    assert!(rtcp_is_about_video(&sender_report, EGRESS, None));
    // Feedback: a PLI's media SSRC, a FIR's entry SSRC (its header media SSRC is 0).
    let mut pli = vec![0x81, 206, 0, 2];
    pli.extend_from_slice(&0x66u32.to_be_bytes());
    pli.extend_from_slice(&EGRESS.to_be_bytes());
    assert!(rtcp_is_about_video(&pli, EGRESS, None));
    let mut fir = vec![0x84, 206, 0, 4];
    fir.extend_from_slice(&0x66u32.to_be_bytes());
    fir.extend_from_slice(&0u32.to_be_bytes());
    fir.extend_from_slice(&EGRESS.to_be_bytes());
    fir.extend_from_slice(&[7, 0, 0, 0]);
    assert!(rtcp_is_about_video(&fir, EGRESS, None));
    // A compound is read to its end; a packet after another one counts.
    let compound = [rr(0x11, &[0x22]), pli.clone()].concat();
    assert!(rtcp_is_about_video(&compound, EGRESS, None));
    // Truncated or not RTCP: not about anything.
    assert!(!rtcp_is_about_video(&pli[..9], EGRESS, None));
    assert!(!rtcp_is_about_video(
        &[0x40, 201, 0, 1, 0, 0, 0, 1],
        EGRESS,
        None
    ));
    assert!(!rtcp_is_about_video(&[], EGRESS, None));
}
