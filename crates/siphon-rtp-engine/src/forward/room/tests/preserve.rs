//! A preserving room (`ForwardMedia::Preserve`): the talker's datagrams, byte for byte, with no
//! engine-originated report (3GPP TS 33.180 §7.5.2 NOTE 3, RFC 3550 §7.1).

use super::*;

fn preserve_room(seats: u8) -> ForwardRoom {
    let text = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                m=audio 4000 RTP/SAVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n";
    let offered = sdp::parse(text).unwrap().audio_codecs();
    let (codec, _) = RoomCodec::from_offer(&offered).unwrap();
    let mut room = ForwardRoom::new(
        "group-1".to_string(),
        codec.with_media(siphon_rtp_proto::ForwardMedia::Preserve),
    );
    for index in 1..=seats {
        room.add_seat(seat_config(index), 0).unwrap();
    }
    room
}

/// An RTP datagram whose "payload" is opaque bytes followed by a 10-octet tag, as SRTP would send.
fn srtp_like(sequence: u16, ssrc: u32) -> Vec<u8> {
    let mut payload: Vec<u8> = (0..40u8).map(|byte| byte.wrapping_mul(7) ^ 0xA5).collect();
    payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6]);
    rtp(
        96,
        sequence,
        9000 + u32::from(sequence) * 320,
        ssrc,
        &payload,
    )
}

/// An SRTCP-like sender report: a clear RTCP header, then bytes that are not RTCP at all.
fn srtcp_like(ssrc: u32) -> Vec<u8> {
    let mut datagram = vec![0x80, 200, 0x00, 0x0C];
    datagram.extend_from_slice(&ssrc.to_be_bytes());
    datagram.extend((0..60u8).map(|byte| byte.wrapping_mul(13) ^ 0x5A));
    datagram
}

#[test]
fn the_talkers_datagram_reaches_every_receiver_byte_for_byte() {
    let mut room = preserve_room(3);
    room.set_source(Some("seat-1")).unwrap();
    let original = srtp_like(7, 0x1111_1111);
    let packet = rx(1, 1_000_000, original.clone());
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 2, "two receivers, the source is not one");
    for (endpoint, destination, datagram) in &sent {
        assert_eq!(
            datagram, &original,
            "SSRC, sequence, timestamp, payload and tag untouched"
        );
        assert_eq!(
            *destination,
            address(&format!("192.0.2.{}:4000", endpoint.0))
        );
    }
    let stats = room.seat_stats("seat-2").unwrap();
    assert_eq!(stats.forwarded_packets, 1);
    assert_eq!(stats.forwarded_octets as usize, original.len());
}

#[test]
fn a_talker_switch_shows_each_receiver_the_new_ssrc_unchanged_and_announces_once_per_switch() {
    let mut room = preserve_room(3);
    let second = srtp_like(900, 0xBBBB_0002);

    room.set_source(Some("seat-1")).unwrap();
    let mut first_sent = Vec::new();
    for sequence in [1u16, 2, 3] {
        let packet = rx(1, 1_000_000, srtp_like(sequence, 0xAAAA_0001));
        room.ingest(&packet);
        let sent = forwarded(&mut room, &packet);
        assert_eq!(sent.len(), 2);
        first_sent = sent[0].2.clone();
    }
    let announced: Vec<_> = room.drain_events().collect();
    assert_eq!(
        announced.len(),
        1,
        "one ForwardSourceStarted for the first talker"
    );
    assert_eq!(
        parsed(&first_sent).4,
        0xAAAA_0001,
        "the first talker's own SSRC"
    );

    room.set_source(Some("seat-2")).unwrap();
    let packet = rx(2, 2_000_000, second.clone());
    room.ingest(&packet);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|(_, _, datagram)| datagram == &second));
    let announced: Vec<_> = room.drain_events().collect();
    assert_eq!(announced.len(), 1, "one more for the switch");
    assert!(matches!(
        &announced[0],
        Event::ForwardSourceStarted { from_tag, .. } if from_tag == "seat-2"
    ));
    let (_, _, _, _, ssrc, _) = parsed(&sent[0].2);
    assert_eq!(
        ssrc, 0xBBBB_0002,
        "the talker's own SSRC, not a per-receiver one"
    );
}

#[test]
fn the_talkers_srtcp_is_forwarded_byte_for_byte_and_never_parsed() {
    let mut room = preserve_room(3);
    room.set_source(Some("seat-1")).unwrap();
    let report = srtcp_like(0x1111_1111);
    let packet = rx(1, 1_000_000, report.clone());
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|(_, _, datagram)| datagram == &report));
    assert!(
        room.drain_events().next().is_none(),
        "an RTCP datagram does not announce a talker"
    );
}

#[test]
fn a_receivers_audio_rtcp_is_dropped_and_counted() {
    let mut room = preserve_room(3);
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx(2, 1_000_000, srtcp_like(0x2222_2222));
    assert_eq!(room.ingest(&packet), Ingress::DroppedFromPeer);
    assert!(forwarded(&mut room, &packet).is_empty());
    assert_eq!(room.seat_stats("seat-2").unwrap().receiver_rtcp_dropped, 1);
}

#[test]
fn a_receivers_rtp_is_dropped_and_the_wrong_payload_type_is_not_forwarded() {
    let mut room = preserve_room(3);
    room.set_source(Some("seat-1")).unwrap();
    let listener = rx(2, 1_000_000, srtp_like(1, 0x2222_2222));
    assert_eq!(room.ingest(&listener), Ingress::DroppedFromPeer);
    assert!(forwarded(&mut room, &listener).is_empty());
    let wrong = rx(1, 1_000_000, rtp(97, 1, 0, 0x1111_1111, &[1, 2, 3, 4]));
    assert_eq!(room.ingest(&wrong), Ingress::DroppedFromPeer);
    assert!(forwarded(&mut room, &wrong).is_empty());
    assert_eq!(room.seat_stats("seat-1").unwrap().unknown_payload_type, 1);
}

#[test]
fn a_preserving_room_originates_no_report_however_long_it_runs() {
    let mut room = preserve_room(3);
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx(1, 1_000_000, srtp_like(1, 0x1111_1111));
    room.ingest(&packet);
    forwarded(&mut room, &packet);
    let mut out = Vec::new();
    // The first tick of the report timer fires at room start; later ones follow every 5 s.
    for second in [0u64, 5, 10, 15, 60] {
        room.build_reports(0xE000_0000_0000_0000, second * 1_000_000, &mut out);
    }
    assert!(
        out.is_empty(),
        "no SR, RR or BYE toward a seat: {} built",
        out.len()
    );
}

#[test]
fn a_translating_room_still_builds_reports() {
    let mut room = room_of(2);
    room.set_source(Some("seat-1")).unwrap();
    let mut out = Vec::new();
    room.build_reports(0xE000_0000_0000_0000, 5_000_000, &mut out);
    assert_eq!(out.len(), 2);
}

#[test]
fn an_unreachable_seat_is_not_sent_the_datagram() {
    let mut room = preserve_room(2);
    let mut pending = seat_config(3);
    pending.ice_pending = true;
    room.add_seat(pending, 0).unwrap();
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx(1, 1_000_000, srtp_like(1, 0x1111_1111));
    room.ingest(&packet);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 1, "only seat-2: seat-3 is still gated on ICE");
}
