//! A preserving room (`ForwardMedia::Preserve`): the talker's datagrams, byte for byte, with no
//! engine-originated report (3GPP TS 33.180 §7.5.2 NOTE 3, RFC 3550 §7.1), and its media SRTCP
//! keys (§9.4.1).

use super::*;
use crate::app_events::AppEventQueue;
use siphon_rtp_proto::RtcpAppStream;
use siphon_rtp_srtp::srtcp_gcm::SrtcpGcmContext;

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
fn an_unkeyed_talkers_srtcp_is_forwarded_byte_for_byte_and_never_parsed() {
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
fn an_unkeyed_receivers_audio_rtcp_is_dropped_and_counted() {
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

/// Seat `index`'s media SRTCP key: the MKI is the seat number, so a wrong key is a wrong MKI.
fn media_key(index: u8) -> FloorMasterKey {
    FloorMasterKey::from_salt_96(u32::from(index), [0x40 + index; 16], &[0x60 + index; 12])
}

/// What seat `index`'s phone holds: the same key, as its own context.
fn phone(index: u8) -> SrtcpGcmContext {
    SrtcpGcmContext::new(&[media_key(index)]).unwrap()
}

/// A preserving room of three seats, those in `keyed` holding their media key, and the queue of the
/// APP events they report to.
fn keyed_room(keyed: &[u8]) -> (ForwardRoom, AppEventQueue) {
    let queue = AppEventQueue::new(64, std::sync::Arc::new(crate::metrics::Metrics::new()));
    let mut room = preserve_room(0);
    for index in 1..=3u8 {
        let mut config = seat_config(index);
        config.app_events = Some(queue.clone());
        if keyed.contains(&index) {
            config.media_srtcp = vec![media_key(index)];
        }
        room.add_seat(config, 0).unwrap();
    }
    (room, queue)
}

/// A plaintext RTCP compound, as a phone builds it: an SR under `ssrc`, then an APP packet.
fn plain_report(ssrc: u32) -> Vec<u8> {
    let mut buffer = [0u8; 128];
    let mut length =
        rtcp::write_sender_report(ssrc, 0x0000_0001_8000_0000, 9000, 5, 800, &[], &mut buffer)
            .unwrap();
    length += rtcp::write_app(17, ssrc, *b"MCPT", &[0, 1, 2, 3], &mut buffer[length..]).unwrap();
    buffer[..length].to_vec()
}

fn sealed(phone: &mut SrtcpGcmContext, plain: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    phone.protect(plain, true, &mut wire).unwrap();
    wire
}

#[test]
fn a_keyed_talkers_srtcp_is_resealed_per_receiver_and_each_receiver_opens_it() {
    let (mut room, queue) = keyed_room(&[1, 2, 3]);
    room.set_source(Some("seat-1")).unwrap();
    let plain = plain_report(0x1111_1111);
    let wire = sealed(&mut phone(1), &plain);
    let packet = rx(1, 1_000_000, wire.clone());
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 2, "two receivers, the source is not one");
    for (endpoint, destination, datagram) in &sent {
        let index = endpoint.0 as u8;
        assert_eq!(*destination, address(&format!("192.0.2.{index}:4000")));
        assert_ne!(datagram, &wire, "never the talker's own bytes");
        let mut opened = Vec::new();
        phone(index).unprotect(datagram, &mut opened).unwrap();
        assert_eq!(opened, plain, "seat {index} reads the talker's RTCP");
        // RFC 7714 §9.2 / TS 33.180 §9.4.8: E flag set, index 0, the receiver's own MKI last.
        assert_eq!(datagram[datagram.len() - 8], 0x80);
        assert_eq!(
            datagram[datagram.len() - 4..],
            u32::from(index).to_be_bytes()
        );
        // A receiver cannot read what was sealed for another.
        let other = if index == 2 { 3 } else { 2 };
        assert!(phone(other).unprotect(datagram, &mut Vec::new()).is_err());
    }
    assert_ne!(sent[0].2, sent[1].2, "each under its own key");
    // The talker's own APP part is reported, as a translating room does.
    let events: Vec<_> = queue.receiver().try_iter().collect();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        Event::RtcpApp { from_tag, stream: RtcpAppStream::Audio, subtype: 17, .. }
            if from_tag == "seat-1"
    ));
    assert_eq!(room.seat_stats("seat-1").unwrap().media_srtcp_refused, 0);
}

#[test]
fn the_second_resealed_datagram_of_a_receiver_takes_the_next_index() {
    let (mut room, _queue) = keyed_room(&[1, 2]);
    room.set_source(Some("seat-1")).unwrap();
    let mut talker = phone(1);
    let mut indices = Vec::new();
    for _ in 0..2 {
        let packet = rx(1, 0, sealed(&mut talker, &plain_report(0x1111_1111)));
        room.ingest(&packet);
        let sent = forwarded(&mut room, &packet);
        let datagram = &sent[0].2;
        let word = u32::from_be_bytes(
            datagram[datagram.len() - 8..datagram.len() - 4]
                .try_into()
                .unwrap(),
        );
        indices.push(word & 0x7FFF_FFFF);
    }
    assert_eq!(indices, vec![0, 1], "RFC 7714 §9.2: an IV is never reused");
    assert_eq!(room.media_srtcp_key_state("seat-2").unwrap().1, 2);
}

#[test]
fn a_keyed_receivers_rtcp_is_read_and_never_forwarded() {
    let (mut room, queue) = keyed_room(&[1, 2, 3]);
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx(
        2,
        1_000_000,
        sealed(&mut phone(2), &plain_report(0x2222_2222)),
    );
    assert_eq!(room.ingest(&packet), Ingress::DroppedFromPeer);
    assert!(forwarded(&mut room, &packet).is_empty());
    assert_eq!(room.seat_stats("seat-2").unwrap().receiver_rtcp_dropped, 1);
    // What it carried was read: the APP part is an event and the SR time is our LSR.
    let events: Vec<_> = queue.receiver().try_iter().collect();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        Event::RtcpApp { from_tag, stream: RtcpAppStream::Audio, ssrc: 0x2222_2222, .. }
            if from_tag == "seat-2"
    ));
    assert_eq!(room.seats[1].last_sender_report_ntp_middle, 0x0001_8000);
}

#[test]
fn media_srtcp_that_does_not_authenticate_is_refused_counted_and_raises_nothing() {
    let (mut room, queue) = keyed_room(&[1, 2, 3]);
    room.set_source(Some("seat-1")).unwrap();
    let plain = plain_report(0x1111_1111);
    let good = sealed(&mut phone(1), &plain);

    // Plaintext, where SRTCP is required.
    let packet = rx(1, 0, plain.clone());
    assert_eq!(room.ingest(&packet), Ingress::Refused);
    assert!(forwarded(&mut room, &packet).is_empty());
    // A flipped ciphertext bit: the tag fails.
    let mut forged = good.clone();
    forged[12] ^= 0x01;
    let packet = rx(1, 0, forged);
    assert_eq!(room.ingest(&packet), Ingress::Refused);
    assert!(forwarded(&mut room, &packet).is_empty());
    // A key the seat does not hold: unknown MKI.
    let stranger = SrtcpGcmContext::new(&[media_key(9)]).unwrap();
    let packet = rx(1, 0, sealed(&mut { stranger }, &plain));
    assert_eq!(room.ingest(&packet), Ingress::Refused);
    assert!(forwarded(&mut room, &packet).is_empty());
    assert_eq!(room.seat_stats("seat-1").unwrap().media_srtcp_refused, 3);
    assert!(
        queue.is_empty(),
        "nothing unauthenticated reaches the controller"
    );

    // The genuine datagram is accepted, and a replay of it is refused.
    let packet = rx(1, 0, good.clone());
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    assert_eq!(forwarded(&mut room, &packet).len(), 2);
    let replay = rx(1, 0, good);
    assert_eq!(room.ingest(&replay), Ingress::Refused);
    assert!(forwarded(&mut room, &replay).is_empty());
    assert_eq!(room.seat_stats("seat-1").unwrap().media_srtcp_refused, 4);
}

#[test]
fn a_receiver_without_media_keys_is_sent_nothing_of_a_keyed_talkers_rtcp() {
    let (mut room, _queue) = keyed_room(&[1, 2]);
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx(1, 0, sealed(&mut phone(1), &plain_report(0x1111_1111)));
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 1, "seat-3 has no key: not even the plaintext");
    assert_eq!(sent[0].0, EndpointId(2));
    assert_eq!(
        room.seat_stats("seat-3")
            .unwrap()
            .media_srtcp_unkeyed_receiver,
        1
    );
    assert_eq!(
        room.seat_stats("seat-2")
            .unwrap()
            .media_srtcp_unkeyed_receiver,
        0
    );
}

#[test]
fn an_unkeyed_talkers_srtcp_is_still_forwarded_verbatim_to_keyed_receivers() {
    let (mut room, _queue) = keyed_room(&[2, 3]);
    room.set_source(Some("seat-1")).unwrap();
    let report = srtcp_like(0x1111_1111);
    let packet = rx(1, 0, report.clone());
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|(_, _, datagram)| datagram == &report));
}

#[test]
fn rekeying_media_srtcp_keeps_the_old_key_until_it_is_replaced_and_empty_unkeys() {
    let (mut room, _queue) = keyed_room(&[1, 2]);
    room.set_source(Some("seat-1")).unwrap();
    let mut talker = phone(1);
    let new_key = FloorMasterKey::from_salt_96(11, [0x99; 16], &[0x98; 12]);
    room.set_media_srtcp_keys("seat-1", &[media_key(1), new_key.clone()])
        .unwrap();
    // The old MKI still opens (a rolling key list, SrtcpGcmContext keeps the newest two).
    let packet = rx(1, 0, sealed(&mut talker, &plain_report(0x1111_1111)));
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    // The talker moves to the new key.
    let mut moved = SrtcpGcmContext::new(std::slice::from_ref(&new_key)).unwrap();
    let packet = rx(1, 0, sealed(&mut moved, &plain_report(0x1111_1111)));
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let (keys, _) = room.media_srtcp_key_state("seat-1").unwrap();
    assert_eq!(keys.len(), 2);
    // A third key pushes the oldest out: its MKI is unknown now.
    let third = FloorMasterKey::from_salt_96(12, [0x77; 16], &[0x76; 12]);
    room.set_media_srtcp_keys("seat-1", &[new_key, third])
        .unwrap();
    let mut stale = phone(1);
    let packet = rx(1, 0, sealed(&mut stale, &plain_report(0x1111_1111)));
    assert_eq!(room.ingest(&packet), Ingress::Refused);
    // Receivers are sealed under the receiver's newest key: rekey seat-2 and read it with MKI 21.
    let receiver_key = FloorMasterKey::from_salt_96(21, [0x55; 16], &[0x54; 12]);
    room.set_media_srtcp_keys("seat-2", &[media_key(2), receiver_key.clone()])
        .unwrap();
    let mut moved =
        SrtcpGcmContext::new(&[FloorMasterKey::from_salt_96(12, [0x77; 16], &[0x76; 12])]).unwrap();
    let plain = plain_report(0x1111_1111);
    let packet = rx(1, 0, sealed(&mut moved, &plain));
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = forwarded(&mut room, &packet);
    let mut receiver = SrtcpGcmContext::new(&[receiver_key]).unwrap();
    let mut opened = Vec::new();
    receiver.unprotect(&sent[0].2, &mut opened).unwrap();
    assert_eq!(opened, plain);

    // An empty set removes the keys: the seat is forwarded verbatim again.
    room.set_media_srtcp_keys("seat-1", &[]).unwrap();
    assert!(room.media_srtcp_key_state("seat-1").is_none());
    let report = srtcp_like(0x1111_1111);
    let packet = rx(1, 0, report.clone());
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|(_, _, datagram)| datagram == &report));
}

#[test]
fn media_srtcp_keys_are_refused_for_an_unknown_seat_and_in_a_translating_room() {
    let (mut room, _queue) = keyed_room(&[]);
    assert_eq!(
        room.set_media_srtcp_keys("nobody", &[media_key(1)]),
        Err(FloorKeysError::UnknownSeat("nobody".into()))
    );
    let mut translating = room_of(1);
    assert_eq!(
        translating.set_media_srtcp_keys("seat-1", &[media_key(1)]),
        Err(FloorKeysError::NotPreserving)
    );
    assert!(room.media_srtcp_key_state("seat-1").is_none());
}

#[test]
fn audio_app_to_a_keyed_preserving_seat_is_sealed_under_its_media_key() {
    let (mut room, _queue) = keyed_room(&[2]);
    let request = AppRequest {
        stream: RtcpAppStream::Audio,
        ssrc: Some(0xE000_0002),
        name: *b"MCPT",
        subtype: 17,
        payload: vec![0, 1, 2, 3],
    };
    let mut sent = Vec::new();
    room.send_app(
        &AppTarget::Room { except: vec![] },
        &request,
        |endpoint, _, data| {
            sent.push((endpoint, data.to_vec()));
        },
    )
    .unwrap();
    assert_eq!(sent.len(), 3);
    let keyed = sent
        .iter()
        .find(|(endpoint, _)| *endpoint == EndpointId(2))
        .unwrap();
    let mut opened = Vec::new();
    phone(2).unprotect(&keyed.1, &mut opened).unwrap();
    let apps: Vec<_> = rtcp::app_packets(&opened)
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(apps[0].subtype, 17);
    // Unkeyed seats are sent it as it was built.
    let plain = sent
        .iter()
        .find(|(endpoint, _)| *endpoint == EndpointId(1))
        .unwrap();
    assert_eq!(plain.1.len(), 16, "header, name and four octets of data");
}

/// The bytes a receiver's phone is sent, pinned: header (V=2, SR, length, the talker's SSRC) in the
/// clear, then the ciphertext and tag, the E flag with index 0 and the receiver's MKI (RFC 7714
/// §9.2; TS 33.180 §9.4.8). Wireshark reads the header, the E flag, the index and the MKI of exactly
/// this datagram (`docs/security-and-nat.md`, "Preserve rooms").
#[test]
fn a_resealed_datagram_has_the_srtcp_gcm_layout_of_rfc_7714() {
    let (mut room, _queue) = keyed_room(&[1, 2]);
    room.set_source(Some("seat-1")).unwrap();
    let plain = plain_report(0x1111_1111);
    let packet = rx(1, 0, sealed(&mut phone(1), &plain));
    room.ingest(&packet);
    let sent = forwarded(&mut room, &packet);
    let datagram = &sent[0].2;
    assert_eq!(
        datagram[..8],
        [0x80, 0xC8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11]
    );
    assert_eq!(
        datagram.len(),
        plain.len() + 16 + 4 + 4,
        "tag, E+index, MKI"
    );
    assert_eq!(
        datagram[datagram.len() - 8..datagram.len() - 4],
        [0x80, 0, 0, 0]
    );
    assert_eq!(datagram[datagram.len() - 4..], [0, 0, 0, 2]);
}
