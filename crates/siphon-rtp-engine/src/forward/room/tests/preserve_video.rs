//! Video in a preserving room (3GPP TS 24.281 §6.2, TS 33.180 §5.2.1, §7.5, §9.4.2): the source's SRTP
//! video forwarded byte for byte, its RTCP hop by hop under each seat's media key, and the feedback
//! the room authors itself (a PLI to the source, the NACK resend) sealed under the source's key.

use super::preserve::{media_key, phone, sealed, srtcp_like};
use super::video::{rx_video, video_rtp, video_seat};
use super::*;
use crate::sdp::video::VideoFeedback;
use crate::sdp::MediaDirection;
use siphon_rtp_media::rtcp::{self, Feedback};
use siphon_rtp_proto::Event;
use siphon_rtp_srtp::srtcp_gcm::SrtcpGcmContext;

const VIDEO_PAYLOAD_TYPE: u8 = 99;
const ALL: VideoFeedback = VideoFeedback::SUPPORTED;
const NOTHING: VideoFeedback = VideoFeedback {
    nack: false,
    pli: false,
    fir: false,
};
const BOTH: MediaDirection = MediaDirection::SendRecv;

/// The SSRC seat `index` sends its video under.
fn media_ssrc(index: u8) -> u32 {
    0x1000_0000 | u32::from(index)
}

/// The SSRC the room writes into the feedback it sends seat `index`'s video endpoint (`video_seat`).
fn egress_ssrc(index: u8) -> u32 {
    0xF000_0000 | u32::from(index)
}

/// A preserving room of one video seat per entry (the seat's direction and accepted feedback), those
/// in `keyed` holding their media SRTCP key. Every seat uses one payload type: the room forwards the
/// talker's packets unchanged.
fn build(keyed: &[u8], seats: &[(MediaDirection, VideoFeedback)]) -> ForwardRoom {
    let codec = amr_wb_room()
        .codec()
        .clone()
        .with_media(siphon_rtp_proto::ForwardMedia::Preserve);
    let mut room = ForwardRoom::new("group-1".to_string(), codec);
    for (position, (direction, feedback)) in seats.iter().enumerate() {
        let index = position as u8 + 1;
        let mut config = video_seat(index, *direction);
        if let Some(video) = config.video.as_mut() {
            video.payload_type = VIDEO_PAYLOAD_TYPE;
            video.feedback = *feedback;
            video.cname = format!("seat-{index}-cname");
        }
        if keyed.contains(&index) {
            config.media_srtcp = vec![media_key(index)];
        }
        room.add_seat(config, 0).unwrap();
    }
    room
}

/// Three seats that send and receive, accepting every feedback type.
fn room_of(keyed: &[u8]) -> ForwardRoom {
    build(keyed, &[(BOTH, ALL), (BOTH, ALL), (BOTH, ALL)])
}

/// An SRTP-like video datagram: opaque bytes and a tag, as the UEs' SRTP leaves them.
fn srtp_video(sequence: u16, ssrc: u32) -> Vec<u8> {
    let mut payload: Vec<u8> = (0..60u8).map(|byte| byte.wrapping_mul(11) ^ 0x3C).collect();
    payload.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 9, 8, 7, 6, 5, 4]);
    video_rtp(
        VIDEO_PAYLOAD_TYPE,
        sequence,
        90_000 + u32::from(sequence) * 3000,
        ssrc,
        false,
        &payload,
    )
}

fn media(index: u8, sequence: u16) -> RxPacket {
    rx_video(index, 1_000_000, srtp_video(sequence, media_ssrc(index)))
}

/// What the room sent for one ingested video datagram, `(endpoint, destination, bytes)` each.
fn sent_for(room: &mut ForwardRoom, packet: &RxPacket) -> Vec<(EndpointId, SocketAddr, Vec<u8>)> {
    forwarded(room, packet)
}

fn video_address(index: u8) -> SocketAddr {
    address(&format!("192.0.2.{index}:5000"))
}

fn poll(room: &mut ForwardRoom, now_ms: u64) -> Vec<Outbound> {
    let mut out = Vec::new();
    room.poll_keyframe(now_ms, &mut out);
    out
}

/// A seat's video SRTCP context: one per stream, as a client holds one SRTCP index per SSRC.
fn video_phone(index: u8) -> SrtcpGcmContext {
    phone(index)
}

fn plain_report(ssrc: u32) -> Vec<u8> {
    let mut buffer = [0u8; 64];
    let length = rtcp::write_sender_report(
        ssrc,
        0x0000_0001_8000_0000,
        90_000,
        5,
        800,
        &[],
        &mut buffer,
    )
    .unwrap();
    buffer[..length].to_vec()
}

/// An empty receiver report, then a PLI about `media`, as RFC 4585 §3.1 compounds it.
fn pli_compound(sender: u32, media: u32) -> Vec<u8> {
    let mut buffer = [0u8; 64];
    let mut length = rtcp::write_empty_receiver_report(sender, &mut buffer).unwrap();
    length += rtcp::write_pli(sender, media, &mut buffer[length..]).unwrap();
    buffer[..length].to_vec()
}

fn nack_compound(sender: u32, media: u32, pid: u16, blp: u16) -> Vec<u8> {
    let mut buffer = [0u8; 64];
    let mut length = rtcp::write_empty_receiver_report(sender, &mut buffer).unwrap();
    length += rtcp::write_nack(sender, media, pid, blp, &mut buffer[length..]).unwrap();
    buffer[..length].to_vec()
}

/// The 31-bit SRTCP index of a sealed datagram (RFC 7714 §9.1: `E | index`, then the MKI).
fn srtcp_index(datagram: &[u8]) -> u32 {
    u32::from_be_bytes(
        datagram[datagram.len() - 8..datagram.len() - 4]
            .try_into()
            .unwrap(),
    ) & 0x7FFF_FFFF
}

#[test]
fn video_reaches_each_receiving_seat_byte_for_byte() {
    let mut room = room_of(&[]);
    room.set_source(Some("seat-1")).unwrap();
    let packet = media(1, 7);
    let original = packet.data.to_vec();
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = sent_for(&mut room, &packet);
    assert_eq!(sent.len(), 2, "two receivers, the source is not one");
    for (endpoint, destination, datagram) in &sent {
        let index = (endpoint.0 - 100) as u8;
        assert_ne!(index, 1);
        assert_eq!(*destination, video_address(index));
        assert_eq!(
            datagram, &original,
            "SSRC, sequence, payload and tag untouched"
        );
    }
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!(stats.video_forwarded_packets, 1);
    assert_eq!(stats.video_forwarded_octets as usize, original.len());
    assert_eq!(
        room.seat_stats("seat-1").unwrap().video_forwarded_packets,
        0
    );
}

#[test]
fn a_seat_that_is_not_the_source_has_its_video_dropped_and_counted() {
    let mut room = room_of(&[]);
    room.set_source(Some("seat-1")).unwrap();
    let packet = media(2, 1);
    assert_eq!(room.ingest(&packet), Ingress::DroppedFromPeer);
    assert!(sent_for(&mut room, &packet).is_empty());
    assert_eq!(
        room.seat_stats("seat-2").unwrap().video_not_source_dropped,
        1
    );
}

#[test]
fn a_send_only_seat_is_sent_no_video_and_a_receive_only_source_sends_none() {
    let mut room = build(
        &[],
        &[
            (BOTH, ALL),
            (MediaDirection::SendOnly, ALL),
            (MediaDirection::RecvOnly, ALL),
        ],
    );
    room.set_source(Some("seat-1")).unwrap();
    let packet = media(1, 1);
    room.ingest(&packet);
    let sent = sent_for(&mut room, &packet);
    assert_eq!(sent.len(), 1, "seat-2 offered send-only video");
    assert_eq!(sent[0].0, EndpointId(103));
    room.set_source(Some("seat-3")).unwrap();
    let packet = media(3, 1);
    assert_eq!(room.ingest(&packet), Ingress::DroppedFromPeer);
    assert!(sent_for(&mut room, &packet).is_empty());
    assert_eq!(
        room.seat_stats("seat-3")
            .unwrap()
            .video_receive_only_dropped,
        1
    );
}

#[test]
fn another_payload_type_is_not_forwarded() {
    let mut room = room_of(&[]);
    room.set_source(Some("seat-1")).unwrap();
    let wrong = rx_video(
        1,
        0,
        video_rtp(98, 1, 0, media_ssrc(1), false, &[1, 2, 3, 4]),
    );
    assert_eq!(room.ingest(&wrong), Ingress::DroppedFromPeer);
    assert!(sent_for(&mut room, &wrong).is_empty());
    assert_eq!(
        room.seat_stats("seat-1")
            .unwrap()
            .video_unknown_payload_type,
        1
    );
}

#[test]
fn there_is_no_keyframe_gate_and_no_keyframe_event_in_a_preserving_room() {
    let mut room = room_of(&[1, 2, 3]);
    room.set_source(Some("seat-1")).unwrap();
    // The first packet after a switch goes out at once: the payload is encrypted, an IDR is invisible.
    let packet = media(1, 1);
    room.ingest(&packet);
    assert_eq!(sent_for(&mut room, &packet).len(), 2);
    for now in [0u64, 500, 1000, 1500, 2000, 2500, 3000] {
        poll(&mut room, now);
    }
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!(stats.video_dropped_awaiting_keyframe, 0);
    assert_eq!(room.seat_stats("seat-1").unwrap().keyframe_timeouts, 0);
    assert!(
        room.drain_events()
            .all(|event| !matches!(event, Event::ForwardKeyframe { .. })),
        "no forward_keyframe in a preserving room"
    );
}

#[test]
fn a_keyed_receivers_pli_is_one_sealed_pli_at_the_source_whoever_asked() {
    let mut room = room_of(&[1, 2, 3]);
    // The source's video SSRC is what a request names: it has to have sent video.
    room.ingest(&media(1, 1));
    room.set_source(Some("seat-1")).unwrap();
    // The switch is one request and then silence: no IDR can ever be seen, so a schedule that waits
    // for one could never be satisfied (RFC 5104 §4.3.1.2 repeats an unanswered request, but the
    // room does not know a request went unanswered).
    let mut asked = 0;
    for now in [0u64, 500, 1000, 1500, 2000] {
        asked += poll(&mut room, now).len();
    }
    assert_eq!(asked, 1, "one PLI for the switch");
    assert!(!room.keyframe_active());
    assert_eq!(room.seat_stats("seat-1").unwrap().keyframe_timeouts, 0);
    // Two keyed receivers ask for a picture, addressed to the source's own stream.
    for receiver in [2u8, 3] {
        let plain = pli_compound(media_ssrc(receiver), media_ssrc(1));
        let wire = sealed(&mut video_phone(receiver), &plain);
        let packet = rx_video(receiver, 2_500_000, wire);
        assert_ne!(room.ingest(&packet), Ingress::Refused);
        assert_eq!(
            room.seat_stats(&format!("seat-{receiver}"))
                .unwrap()
                .media_srtcp_refused,
            0
        );
    }
    let out = poll(&mut room, 3000);
    assert_eq!(out.len(), 1, "one PLI for the crowd: {out:?}");
    assert_eq!(out[0].endpoint, EndpointId(101));
    assert_eq!(out[0].dst, video_address(1));
    let mut opened = Vec::new();
    video_phone(1).unprotect(&out[0].data, &mut opened).unwrap();
    let feedback: Vec<_> = rtcp::feedback_packets(&opened)
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        feedback,
        vec![Feedback::Pli {
            sender_ssrc: egress_ssrc(1),
            media_ssrc: media_ssrc(1)
        }],
        "PSFB FMT 1 about the source's own video stream"
    );
    assert!(poll(&mut room, 3500).is_empty(), "once per interval");
    assert!(!room.keyframe_active());
}

#[test]
fn a_switch_sends_exactly_one_request_and_then_stays_silent() {
    let mut room = room_of(&[1, 2, 3]);
    room.ingest(&media(1, 1));
    room.ingest(&media(3, 1));
    room.set_source(Some("seat-1")).unwrap();
    let mut asked = Vec::new();
    for now in (0..=10_000u64).step_by(250) {
        asked.extend(poll(&mut room, now));
    }
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].endpoint, EndpointId(101));
    // The next switch is one more request, to the new source.
    room.set_source(Some("seat-3")).unwrap();
    let mut asked = Vec::new();
    for now in (10_000..=20_000u64).step_by(250) {
        asked.extend(poll(&mut room, now));
    }
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].endpoint, EndpointId(103));
    let stats = room.seat_stats("seat-3").unwrap();
    assert_eq!((stats.pli_sent, stats.fir_sent), (1, 0));
    assert_eq!(
        room.seat_stats("seat-1").unwrap().keyframe_timeouts,
        0,
        "running out of schedule is not a failure here"
    );
    assert!(room
        .drain_events()
        .all(|event| !matches!(event, Event::ForwardKeyframe { .. })));
}

#[test]
fn the_request_waits_for_the_sources_first_video_packet_then_goes_once() {
    let mut room = room_of(&[1, 2, 3]);
    room.set_source(Some("seat-1")).unwrap();
    // The source has sent no video yet: its SSRC, which the request names, is not known.
    assert!(poll(&mut room, 0).is_empty());
    assert!(poll(&mut room, 500).is_empty());
    assert!(room.keyframe_active());
    room.ingest(&media(1, 1));
    assert_eq!(poll(&mut room, 800).len(), 1);
    assert!(poll(&mut room, 1500).is_empty());
    assert!(!room.keyframe_active());
}

#[test]
fn a_source_with_no_media_keys_is_sent_no_request_ever() {
    let mut room = room_of(&[2, 3]);
    room.ingest(&media(1, 1));
    room.set_source(Some("seat-1")).unwrap();
    let mut asked = 0;
    for now in [0u64, 500, 1000, 2000] {
        asked += poll(&mut room, now).len();
    }
    let wire = sealed(
        &mut video_phone(2),
        &pli_compound(media_ssrc(2), media_ssrc(1)),
    );
    room.ingest(&rx_video(2, 0, wire));
    asked += poll(&mut room, 4000).len();
    assert_eq!(
        asked, 0,
        "a plaintext request would be refused, and it is never made"
    );
    assert!(!room.keyframe_active());
    let stats = room.seat_stats("seat-1").unwrap();
    assert_eq!((stats.pli_sent, stats.fir_sent), (0, 0));
}

#[test]
fn a_source_that_accepted_no_pli_is_sent_fir() {
    let mut room = build(
        &[1, 2],
        &[
            (
                BOTH,
                VideoFeedback {
                    nack: false,
                    pli: false,
                    fir: true,
                },
            ),
            (BOTH, ALL),
        ],
    );
    room.ingest(&media(1, 1));
    room.set_source(Some("seat-1")).unwrap();
    assert_eq!(poll(&mut room, 0).len(), 1);
    let stats = room.seat_stats("seat-1").unwrap();
    assert_eq!((stats.pli_sent, stats.fir_sent), (0, 1));
}

#[test]
fn a_late_joiner_asks_the_source_for_a_keyframe() {
    let mut room = build(&[1, 2], &[(BOTH, ALL), (BOTH, ALL)]);
    room.ingest(&media(1, 1));
    room.set_source(Some("seat-1")).unwrap();
    for now in [0u64, 500, 1000, 1500, 2000] {
        poll(&mut room, now);
    }
    let mut late = video_seat(3, BOTH);
    if let Some(video) = late.video.as_mut() {
        video.payload_type = VIDEO_PAYLOAD_TYPE;
        video.feedback = ALL;
    }
    late.media_srtcp = vec![media_key(3)];
    room.add_seat(late, 3_000_000).unwrap();
    let out = poll(&mut room, 3000);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].endpoint, EndpointId(101));
    let mut opened = Vec::new();
    video_phone(1).unprotect(&out[0].data, &mut opened).unwrap();
    assert!(rtcp::feedback_packets(&opened).count() == 1);
}

#[test]
fn the_sources_video_report_reaches_each_keyed_receiver_resealed_under_its_own_key() {
    let mut room = room_of(&[1, 2]);
    room.set_source(Some("seat-1")).unwrap();
    let plain = plain_report(media_ssrc(1));
    let wire = sealed(&mut video_phone(1), &plain);
    let packet = rx_video(1, 0, wire.clone());
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = sent_for(&mut room, &packet);
    assert_eq!(
        sent.len(),
        1,
        "seat-3 holds no key: it is not sent even the plaintext"
    );
    let (endpoint, destination, datagram) = &sent[0];
    assert_eq!(*endpoint, EndpointId(102));
    assert_eq!(*destination, video_address(2));
    assert_ne!(datagram, &wire);
    let mut opened = Vec::new();
    video_phone(2).unprotect(datagram, &mut opened).unwrap();
    assert_eq!(opened, plain);
    assert_eq!(
        datagram[datagram.len() - 4..],
        2u32.to_be_bytes(),
        "the receiver's own MKI"
    );
    assert_eq!(
        room.seat_stats("seat-3")
            .unwrap()
            .media_srtcp_unkeyed_receiver,
        1
    );
}

#[test]
fn the_room_authored_pli_has_the_srtcp_gcm_layout_of_rfc_7714() {
    let mut room = room_of(&[1]);
    room.ingest(&media(1, 1));
    room.set_source(Some("seat-1")).unwrap();
    let out = poll(&mut room, 0);
    assert_eq!(out.len(), 1);
    let datagram = &out[0].data;
    // Header: V=2, RR (PT 201), the room's video SSRC, in the clear (RFC 3711 §3.4); then the
    // ciphertext, the 16-octet tag, the E flag with index 0, and the MKI.
    assert_eq!(datagram[..2], [0x80, 201]);
    assert_eq!(datagram[4..8], egress_ssrc(1).to_be_bytes());
    assert_eq!(
        datagram[datagram.len() - 8..datagram.len() - 4],
        [0x80, 0, 0, 0]
    );
    assert_eq!(datagram[datagram.len() - 4..], 1u32.to_be_bytes());
}

#[test]
fn a_nack_is_answered_with_the_stored_original_bytes_and_the_ones_it_cannot_are_counted() {
    let mut room = build(&[1, 2, 3], &[(BOTH, ALL), (BOTH, ALL), (BOTH, NOTHING)]);
    room.set_source(Some("seat-1")).unwrap();
    let mut originals = Vec::new();
    for sequence in 10..=14u16 {
        let packet = media(1, sequence);
        room.ingest(&packet);
        sent_for(&mut room, &packet);
        originals.push(packet.data.to_vec());
    }
    // Sequence numbers 11 and 13 were lost on the way to seat-2. One context per phone: its SRTCP
    // index only moves forward.
    let mut phone_two = video_phone(2);
    let wire = sealed(
        &mut phone_two,
        &nack_compound(media_ssrc(2), media_ssrc(1), 11, 0b10),
    );
    let nack = rx_video(2, 0, wire);
    assert_eq!(room.ingest(&nack), Ingress::Accepted);
    let resent = sent_for(&mut room, &nack);
    assert_eq!(resent.len(), 2);
    assert!(resent
        .iter()
        .all(|(endpoint, destination, _)| *endpoint == EndpointId(102)
            && *destination == video_address(2)));
    assert_eq!(
        resent[0].2, originals[1],
        "the very bytes, index and tag included"
    );
    assert_eq!(resent[1].2, originals[3]);
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!((stats.nack_answered, stats.nack_missed), (2, 0));
    // A packet the room never had.
    let wire = sealed(
        &mut phone_two,
        &nack_compound(media_ssrc(2), media_ssrc(1), 500, 0),
    );
    let nack = rx_video(2, 0, wire);
    room.ingest(&nack);
    assert!(sent_for(&mut room, &nack).is_empty());
    assert_eq!(room.seat_stats("seat-2").unwrap().nack_missed, 1);
    // A receiver that did not accept NACK is not answered.
    let wire = sealed(
        &mut video_phone(3),
        &nack_compound(media_ssrc(3), media_ssrc(1), 11, 0),
    );
    let nack = rx_video(3, 0, wire);
    room.ingest(&nack);
    assert!(sent_for(&mut room, &nack).is_empty());
    let stats = room.seat_stats("seat-3").unwrap();
    assert_eq!((stats.nack_answered, stats.nack_missed), (0, 0));
}

#[test]
fn a_source_change_empties_the_nack_ring() {
    let mut room = room_of(&[1, 2, 3]);
    room.set_source(Some("seat-1")).unwrap();
    let packet = media(1, 10);
    room.ingest(&packet);
    sent_for(&mut room, &packet);
    room.set_source(Some("seat-3")).unwrap();
    let wire = sealed(
        &mut video_phone(2),
        &nack_compound(media_ssrc(2), media_ssrc(1), 10, 0),
    );
    let nack = rx_video(2, 0, wire);
    room.ingest(&nack);
    assert!(sent_for(&mut room, &nack).is_empty());
}

#[test]
fn audio_and_video_rtcp_of_one_keyed_seat_both_authenticate_and_its_indices_never_repeat() {
    let mut room = room_of(&[1, 2]);
    room.set_source(Some("seat-1")).unwrap();
    let mut audio_phone = phone(1);
    let mut video_context = video_phone(1);
    let mut indices = Vec::new();
    let mut video_wires = Vec::new();
    for _ in 0..2 {
        // Each stream's SRTCP index starts at 0 and counts on its own (RFC 3711 §3.2.3).
        let audio = rx(1, 0, sealed(&mut audio_phone, &plain_report(0x1111_1111)));
        assert_eq!(room.ingest(&audio), Ingress::Accepted);
        for (_, _, datagram) in forwarded(&mut room, &audio) {
            indices.push(srtcp_index(&datagram));
        }
        let video = rx_video(
            1,
            0,
            sealed(&mut video_context, &plain_report(media_ssrc(1))),
        );
        video_wires.push(video.data.to_vec());
        assert_eq!(
            room.ingest(&video),
            Ingress::Accepted,
            "video RTCP of the same key"
        );
        for (_, _, datagram) in sent_for(&mut room, &video) {
            indices.push(srtcp_index(&datagram));
        }
    }
    // seat-2 is sent one sealed datagram each time, on one key: RFC 7714 §9.2, an IV is never reused.
    assert_eq!(indices, vec![0, 1, 2, 3]);
    assert_eq!(room.seat_stats("seat-1").unwrap().media_srtcp_refused, 0);
    // A replay of a video datagram is refused on its own window, and the audio one is not disturbed.
    let replay = rx_video(1, 0, video_wires[0].clone());
    assert_eq!(room.ingest(&replay), Ingress::Refused);
    assert_eq!(room.seat_stats("seat-1").unwrap().media_srtcp_refused, 1);
}

#[test]
fn video_rtcp_that_does_not_authenticate_is_refused_and_counted() {
    let mut room = room_of(&[1, 2, 3]);
    room.set_source(Some("seat-1")).unwrap();
    let plain = plain_report(media_ssrc(1));
    let good = sealed(&mut video_phone(1), &plain);
    // Plaintext, where SRTCP is required.
    let packet = rx_video(1, 0, plain.clone());
    assert_eq!(room.ingest(&packet), Ingress::Refused);
    assert!(sent_for(&mut room, &packet).is_empty());
    // A flipped ciphertext bit.
    let mut forged = good.clone();
    forged[12] ^= 0x01;
    let packet = rx_video(1, 0, forged);
    assert_eq!(room.ingest(&packet), Ingress::Refused);
    // A key the seat does not hold.
    let mut stranger = SrtcpGcmContext::new(&[media_key(9)]).unwrap();
    let packet = rx_video(1, 0, sealed(&mut stranger, &plain));
    assert_eq!(room.ingest(&packet), Ingress::Refused);
    assert_eq!(room.seat_stats("seat-1").unwrap().media_srtcp_refused, 3);
    let packet = rx_video(1, 0, good.clone());
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    assert_eq!(sent_for(&mut room, &packet).len(), 2);
    let replay = rx_video(1, 0, good);
    assert_eq!(room.ingest(&replay), Ingress::Refused);
    assert_eq!(room.seat_stats("seat-1").unwrap().media_srtcp_refused, 4);
}

#[test]
fn rekeying_the_media_keys_rekeys_the_video_rtcp_too() {
    let mut room = room_of(&[1, 2]);
    room.set_source(Some("seat-1")).unwrap();
    let new_key = FloorMasterKey::from_salt_96(11, [0x99; 16], &[0x98; 12]);
    room.set_media_srtcp_keys("seat-1", &[media_key(1), new_key.clone()])
        .unwrap();
    let mut moved = SrtcpGcmContext::new(std::slice::from_ref(&new_key)).unwrap();
    let packet = rx_video(1, 0, sealed(&mut moved, &plain_report(media_ssrc(1))));
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    // Outbound uses the newest key for video as it does for audio.
    room.set_media_srtcp_keys("seat-2", &[media_key(2), new_key.clone()])
        .unwrap();
    let packet = rx_video(
        1,
        0,
        sealed(&mut video_phone(1), &plain_report(media_ssrc(1))),
    );
    room.ingest(&packet);
    let sent = sent_for(&mut room, &packet);
    assert_eq!(sent[0].2[sent[0].2.len() - 4..], 11u32.to_be_bytes());
}

#[test]
fn an_unkeyed_sources_video_rtcp_is_forwarded_verbatim_and_receivers_rtcp_is_dropped() {
    let mut room = room_of(&[]);
    room.set_source(Some("seat-1")).unwrap();
    let report = srtcp_like(media_ssrc(1));
    let packet = rx_video(1, 0, report.clone());
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = sent_for(&mut room, &packet);
    assert_eq!(sent.len(), 2);
    for (endpoint, destination, datagram) in &sent {
        assert_eq!(datagram, &report, "never parsed, never touched");
        assert_eq!(*destination, video_address((endpoint.0 - 100) as u8));
    }
    let listener = rx_video(2, 0, srtcp_like(media_ssrc(2)));
    assert_eq!(room.ingest(&listener), Ingress::DroppedFromPeer);
    assert!(sent_for(&mut room, &listener).is_empty());
    assert_eq!(room.seat_stats("seat-2").unwrap().receiver_rtcp_dropped, 1);
    // No request is ever made for an unkeyed source.
    for now in [0u64, 500, 3000] {
        assert!(poll(&mut room, now).is_empty());
    }
}

#[test]
fn a_keyed_receiver_is_never_sent_an_unkeyed_talkers_plaintext_it_gets_the_bytes_as_they_came() {
    // The talker is unkeyed, as an unkeyed talker's RTCP is forwarded verbatim to everyone (audio rule).
    let mut room = room_of(&[2]);
    room.set_source(Some("seat-1")).unwrap();
    let report = srtcp_like(media_ssrc(1));
    let packet = rx_video(1, 0, report.clone());
    room.ingest(&packet);
    let sent = sent_for(&mut room, &packet);
    assert!(sent.iter().all(|(_, _, datagram)| datagram == &report));
}

#[test]
fn a_receiver_whose_reception_is_off_is_sent_no_video_and_no_resend() {
    let mut room = room_of(&[1, 2, 3]);
    room.set_source(Some("seat-1")).unwrap();
    let first = media(1, 10);
    room.ingest(&first);
    assert_eq!(sent_for(&mut room, &first).len(), 2);
    room.set_reception("seat-2", true, false).unwrap();
    let packet = media(1, 11);
    room.ingest(&packet);
    let sent = sent_for(&mut room, &packet);
    assert_eq!(sent.len(), 1, "only seat-3 is sent it");
    assert_eq!(sent[0].0, EndpointId(103));
    assert_eq!(
        room.seat_stats("seat-2")
            .unwrap()
            .reception_off_dropped_video,
        1
    );
    // Its NACK for what it did get is not answered either: the stream is off for it.
    let wire = sealed(
        &mut video_phone(2),
        &nack_compound(media_ssrc(2), media_ssrc(1), 10, 0),
    );
    let nack = rx_video(2, 0, wire);
    room.ingest(&nack);
    assert!(sent_for(&mut room, &nack).is_empty());
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!(stats.reception_off_dropped_video, 2);
    assert_eq!(stats.nack_answered, 0);
    // Switched back on, it is sent video again.
    room.set_reception("seat-2", true, true).unwrap();
    let packet = media(1, 12);
    room.ingest(&packet);
    assert_eq!(sent_for(&mut room, &packet).len(), 2);
}

#[test]
fn a_late_joiner_that_switches_its_video_on_asks_the_source_for_a_keyframe() {
    let mut room = room_of(&[1, 2, 3]);
    room.ingest(&media(1, 1));
    room.set_reception("seat-3", true, false).unwrap();
    room.set_source(Some("seat-1")).unwrap();
    assert_eq!(poll(&mut room, 0).len(), 1, "the switch's own request");
    assert!(poll(&mut room, 2000).is_empty());
    room.set_reception("seat-3", true, true).unwrap();
    assert!(room.keyframe_active());
    let out = poll(&mut room, 4000);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].endpoint, EndpointId(101));
    assert!(poll(&mut room, 6000).is_empty(), "and then silence");
    // Nothing is held back for it: the payload is encrypted.
    let packet = media(1, 2);
    room.ingest(&packet);
    assert_eq!(sent_for(&mut room, &packet).len(), 2);
    assert_eq!(
        room.seat_stats("seat-3")
            .unwrap()
            .video_dropped_awaiting_keyframe,
        0
    );
}

#[test]
fn rapid_reception_toggles_do_not_flood_the_source_with_requests() {
    let mut room = room_of(&[1, 2, 3]);
    room.ingest(&media(1, 1));
    room.set_source(Some("seat-1")).unwrap();
    assert_eq!(poll(&mut room, 0).len(), 1);
    room.set_reception("seat-3", true, false).unwrap();
    room.set_reception("seat-3", true, true).unwrap();
    assert!(
        poll(&mut room, 100).is_empty(),
        "within the interval of the last request"
    );
    assert_eq!(poll(&mut room, 1000).len(), 1, "then one");
}

#[test]
fn a_video_seat_is_counted_for_its_forwarded_packets_and_octets_in_the_stats() {
    let mut room = room_of(&[]);
    room.set_source(Some("seat-1")).unwrap();
    let mut total = 0usize;
    for sequence in 1..=3u16 {
        let packet = media(1, sequence);
        total += packet.data.len();
        room.ingest(&packet);
        sent_for(&mut room, &packet);
    }
    let stats = room.seat_stats("seat-3").unwrap();
    assert_eq!(stats.video_forwarded_packets, 3);
    assert_eq!(stats.video_forwarded_octets as usize, total);
}

/// `datagram` with P=1 and `last` as its final octet: what an SRTP sender produces when the padding is
/// inside the encrypted portion and the datagram ends in the tag (RFC 3711 §3.1).
fn with_padding_bit(mut datagram: Vec<u8>, last: u8) -> Vec<u8> {
    datagram[0] |= 0x20;
    let end = datagram.len() - 1;
    datagram[end] = last;
    datagram
}

#[test]
fn padded_srtp_video_is_forwarded_byte_for_byte_whatever_its_last_octet() {
    let mut room = room_of(&[]);
    room.set_source(Some("seat-1")).unwrap();
    // 0 is no padding count at all; 250 is larger than the payload: neither is looked at.
    for (sequence, last) in [(1u16, 0u8), (2, 250), (3, 7)] {
        let datagram = with_padding_bit(srtp_video(sequence, media_ssrc(1)), last);
        let packet = rx_video(1, 1_000_000, datagram.clone());
        assert_eq!(room.ingest(&packet), Ingress::Accepted, "last octet {last}");
        let sent = sent_for(&mut room, &packet);
        assert_eq!(sent.len(), 2);
        assert!(sent.iter().all(|(_, _, bytes)| bytes == &datagram));
    }
    assert_eq!(
        room.seat_stats("seat-1")
            .unwrap()
            .video_unknown_payload_type,
        0
    );
}

#[test]
fn an_audio_srtcp_replayed_onto_the_video_endpoint_is_refused() {
    // RFC 3711 §3.3.2: the replay list is the sender SSRC's, not the endpoint's.
    let mut room = room_of(&[1, 2]);
    room.set_source(Some("seat-1")).unwrap();
    let wire = sealed(&mut phone(1), &plain_report(0x1111_1111));
    let audio = rx(1, 0, wire.clone());
    assert_eq!(room.ingest(&audio), Ingress::Accepted);
    let replayed = rx_video(1, 0, wire);
    assert_eq!(room.ingest(&replayed), Ingress::Refused);
    assert!(sent_for(&mut room, &replayed).is_empty());
    assert_eq!(room.seat_stats("seat-1").unwrap().media_srtcp_refused, 1);
}

#[test]
fn audio_and_video_srtcp_at_very_different_indices_both_authenticate() {
    let mut room = room_of(&[1, 2]);
    room.set_source(Some("seat-1")).unwrap();
    let mut audio_context = phone(1);
    audio_context.set_send_index(1_000_000);
    let audio = rx(1, 0, sealed(&mut audio_context, &plain_report(0x1111_1111)));
    assert_eq!(room.ingest(&audio), Ingress::Accepted);
    // One shared window would now call the video's index 0 too old to be fresh.
    let video = rx_video(
        1,
        0,
        sealed(&mut video_phone(1), &plain_report(media_ssrc(1))),
    );
    assert_eq!(room.ingest(&video), Ingress::Accepted);
    assert_eq!(room.seat_stats("seat-1").unwrap().media_srtcp_refused, 0);
}

#[test]
fn a_sender_ssrc_beyond_the_replay_table_is_refused_and_counted() {
    let mut room = room_of(&[1, 2]);
    room.set_source(Some("seat-1")).unwrap();
    for ssrc in 0..siphon_rtp_srtp::srtcp_gcm::MAX_REPLAY_SSRCS as u32 {
        let packet = rx_video(
            1,
            0,
            sealed(&mut video_phone(1), &plain_report(0x2000 + ssrc)),
        );
        assert_eq!(room.ingest(&packet), Ingress::Accepted, "SSRC {ssrc}");
    }
    let one_more = rx_video(1, 0, sealed(&mut video_phone(1), &plain_report(0x3000)));
    assert_eq!(room.ingest(&one_more), Ingress::Refused);
    assert!(sent_for(&mut room, &one_more).is_empty());
    assert_eq!(room.seat_stats("seat-1").unwrap().media_srtcp_refused, 1);
    // A sender already held still passes at its next index.
    let mut known = video_phone(1);
    known.set_send_index(1);
    let again = rx_video(1, 0, sealed(&mut known, &plain_report(0x2000)));
    assert_eq!(room.ingest(&again), Ingress::Accepted);
}
