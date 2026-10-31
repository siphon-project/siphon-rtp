#![allow(clippy::unwrap_used, reason = "tests")]

use super::*;
use crate::sdp;
use siphon_rtp_media::rtp::{write_packet, RtpHeader};

const AMR_WB_PAYLOAD_TYPE: u8 = 96;
/// 16 kHz AMR-WB: one 20 ms frame is 320 timestamp units.
const FRAME_TICKS: u32 = 320;

fn address(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn amr_wb_room() -> ForwardRoom {
    let text = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                m=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n";
    let offered = sdp::parse(text).unwrap().audio_codecs();
    let (codec, _) = RoomCodec::from_offer(&offered).unwrap();
    ForwardRoom::new("group-1".to_string(), codec)
}

/// Seat `index` (1-based): endpoint `index`, phone at `192.0.2.<index>:4000`, egress SSRC
/// `0xE000_0000 | index`, payload type `96`.
fn seat_config(index: u8) -> ForwardSeatConfig {
    ForwardSeatConfig {
        tag: format!("seat-{index}"),
        endpoint: EndpointId(u64::from(index)),
        egress_destination: address(&format!("192.0.2.{index}:4000")),
        accepted_source: SourceFilter::Exact(address(&format!("192.0.2.{index}:4000")).ip()),
        latch: true,
        audio_payload_type: AMR_WB_PAYLOAD_TYPE,
        telephone_event: None,
        secure: None,
        secure_pending: false,
        ice_pending: false,
        egress_ssrc: 0xE000_0000 | u32::from(index),
        initial_sequence: 1000,
        initial_timestamp: 50_000,
        floor: None,
        app_events: None,
    }
}

fn room_of(seats: u8) -> ForwardRoom {
    let mut room = amr_wb_room();
    for index in 1..=seats {
        room.add_seat(seat_config(index), 0).unwrap();
    }
    room
}

fn rtp(payload_type: u8, sequence: u16, timestamp: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let header = RtpHeader {
        marker: false,
        payload_type,
        sequence,
        timestamp,
        ssrc,
    };
    let mut buffer = vec![0u8; 12 + payload.len()];
    write_packet(&header, payload, &mut buffer).unwrap();
    buffer
}

fn rx(index: u8, arrival: u64, data: Vec<u8>) -> RxPacket {
    RxPacket {
        endpoint: EndpointId(u64::from(index)),
        source: address(&format!("192.0.2.{index}:4000")),
        arrival,
        data: Bytes::from(data),
    }
}

/// What the room sent for one ingested packet: `(endpoint, destination, datagram)` per receiver.
fn forwarded(room: &mut ForwardRoom, packet: &RxPacket) -> Vec<(EndpointId, SocketAddr, Vec<u8>)> {
    let mut sent = Vec::new();
    while let Some((endpoint, destination, data)) = room.next_datagram(packet) {
        sent.push((endpoint, destination, data.to_vec()));
    }
    sent
}

fn parsed(datagram: &[u8]) -> (bool, u8, u16, u32, u32, Vec<u8>) {
    let packet = RtpPacket::parse(datagram).unwrap();
    (
        packet.marker,
        packet.payload_type,
        packet.sequence,
        packet.timestamp,
        packet.ssrc,
        packet.payload.to_vec(),
    )
}

#[test]
fn the_source_is_forwarded_unchanged_to_every_other_seat_on_their_own_ssrc() {
    let mut room = room_of(3);
    room.set_source(Some("seat-1")).unwrap();
    let payload = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let packet = rx(1, 1_000_000, rtp(96, 7, 9000, 0x1111_1111, &payload));
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 2, "two receivers, the source is not one");
    let to_two = sent
        .iter()
        .find(|(endpoint, _, _)| *endpoint == EndpointId(2))
        .unwrap();
    let to_three = sent
        .iter()
        .find(|(endpoint, _, _)| *endpoint == EndpointId(3))
        .unwrap();
    assert_eq!(to_two.1, address("192.0.2.2:4000"));
    assert_eq!(to_three.1, address("192.0.2.3:4000"));
    let (marker_two, pt_two, _, _, ssrc_two, payload_two) = parsed(&to_two.2);
    let (_, _, _, _, ssrc_three, payload_three) = parsed(&to_three.2);
    assert_eq!(payload_two, payload, "payload byte-identical");
    assert_eq!(payload_three, payload);
    assert_eq!(pt_two, AMR_WB_PAYLOAD_TYPE);
    assert!(marker_two, "the first packet of a run carries the marker");
    assert_eq!(ssrc_two, 0xE000_0002, "each receiver's own stable SSRC");
    assert_eq!(ssrc_three, 0xE000_0003);
    assert_ne!(ssrc_two, 0x1111_1111, "the source's SSRC never leaks");
    assert!(room.next_datagram(&packet).is_none(), "the walk is over");
}

#[test]
fn a_receivers_own_payload_type_is_written() {
    let mut room = amr_wb_room();
    room.add_seat(seat_config(1), 0).unwrap();
    let mut other = seat_config(2);
    other.audio_payload_type = 111;
    room.add_seat(other, 0).unwrap();
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx(1, 0, rtp(96, 1, 0, 5, &[1, 2, 3]));
    room.ingest(&packet);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(parsed(&sent[0].2).1, 111);
}

#[test]
fn rtp_from_a_seat_that_is_not_the_source_is_counted_and_dropped() {
    let mut room = room_of(3);
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx(2, 0, rtp(96, 1, 0, 0x2222_2222, &[1, 2, 3]));
    assert_eq!(
        room.ingest(&packet),
        Ingress::DroppedFromPeer,
        "counted as dropped, still proof the seat is alive"
    );
    assert!(room.next_datagram(&packet).is_none());
    assert_eq!(room.seat_stats("seat-2").unwrap().not_source_dropped, 1);
    assert_eq!(room.seat_stats("seat-1").unwrap().not_source_dropped, 0);
    assert!(Ingress::DroppedFromPeer.is_live());
}

#[test]
fn nothing_is_forwarded_while_there_is_no_source() {
    let mut room = room_of(2);
    let packet = rx(1, 0, rtp(96, 1, 0, 5, &[1]));
    room.ingest(&packet);
    assert!(room.next_datagram(&packet).is_none());
    room.set_source(Some("seat-1")).unwrap();
    room.set_source(None).unwrap();
    room.ingest(&packet);
    assert!(room.next_datagram(&packet).is_none());
}

#[test]
fn an_unknown_source_tag_is_refused_and_changes_nothing() {
    let mut room = room_of(2);
    room.set_source(Some("seat-1")).unwrap();
    assert_eq!(
        room.set_source(Some("ghost")),
        Err(ForwardError::UnknownTag("ghost".to_string()))
    );
    assert_eq!(room.source(), Some("seat-1"));
}

#[test]
fn a_source_switch_keeps_every_receivers_stream_continuous_with_one_marker_per_switch() {
    let mut room = room_of(3);
    let mut last: HashMap<u64, (u16, u32)> = HashMap::new();
    let mut markers = 0;
    // seat-1 talks, then seat-2, then seat-1 again with its old SSRC, as a PTT terminal does.
    let script: [(u8, &str, u32); 3] = [
        (1, "seat-1", 0x1111_1111),
        (2, "seat-2", 0x2222_2222),
        (1, "seat-1", 0x1111_1111),
    ];
    let mut clock = 0u64;
    let mut sequence = 100u16;
    for (talker, tag, ssrc) in script {
        room.set_source(Some(tag)).unwrap();
        for frame in 0..4u32 {
            clock += 20_000;
            sequence = sequence.wrapping_add(1);
            let packet = rx(
                talker,
                clock,
                rtp(96, sequence, frame * FRAME_TICKS, ssrc, &[frame as u8]),
            );
            room.ingest(&packet);
            for (endpoint, _, data) in forwarded(&mut room, &packet) {
                let (marker, _, out_sequence, out_timestamp, _, _) = parsed(&data);
                if marker {
                    markers += 1;
                    assert_eq!(frame, 0, "the marker is only on the first packet of a run");
                }
                if let Some((previous_sequence, previous_timestamp)) = last.get(&endpoint.0) {
                    assert_eq!(out_sequence, previous_sequence.wrapping_add(1));
                    assert!(
                        (out_timestamp.wrapping_sub(*previous_timestamp) as i32) > 0,
                        "timestamp strictly advances across the switch"
                    );
                }
                last.insert(endpoint.0, (out_sequence, out_timestamp));
            }
        }
    }
    // Three runs, each heard by two receivers; each receiver heard two (or three) runs, all marked.
    assert_eq!(markers, 6);
    let events: Vec<Event> = room.drain_events().collect();
    assert_eq!(
        events.len(),
        3,
        "one ForwardSourceStarted per source change"
    );
    assert_eq!(
        events[1],
        Event::ForwardSourceStarted {
            conference_id: "group-1".to_string(),
            from_tag: "seat-2".to_string(),
        }
    );
}

#[test]
fn the_source_started_event_waits_for_the_first_packet_actually_forwarded() {
    let mut room = room_of(2);
    room.set_source(Some("seat-1")).unwrap();
    assert_eq!(room.drain_events().count(), 0, "nothing forwarded yet");
    let packet = rx(1, 0, rtp(96, 1, 0, 5, &[1]));
    room.ingest(&packet);
    assert_eq!(room.drain_events().count(), 0, "armed, not walked");
    forwarded(&mut room, &packet);
    assert_eq!(room.drain_events().count(), 1);
    let again = rx(1, 20_000, rtp(96, 2, 320, 5, &[1]));
    room.ingest(&again);
    forwarded(&mut room, &again);
    assert_eq!(
        room.drain_events().count(),
        0,
        "once per change, not per packet"
    );
}

#[test]
fn choosing_the_current_source_again_neither_rebases_nor_announces() {
    let mut room = room_of(2);
    room.set_source(Some("seat-1")).unwrap();
    let first = rx(1, 0, rtp(96, 1, 0, 5, &[1]));
    room.ingest(&first);
    forwarded(&mut room, &first);
    room.drain_events().for_each(drop);
    room.set_source(Some("seat-1")).unwrap();
    let second = rx(1, 20_000, rtp(96, 2, 320, 5, &[1]));
    room.ingest(&second);
    let sent = forwarded(&mut room, &second);
    assert!(!parsed(&sent[0].2).0, "no new marker");
    assert_eq!(room.drain_events().count(), 0);
}

#[test]
fn a_leaving_source_stops_the_forwarding_until_the_next_set_source() {
    let mut room = room_of(3);
    room.set_source(Some("seat-2")).unwrap();
    assert!(room.remove_seat("seat-2"));
    assert_eq!(room.source(), None);
    // seat-3's endpoint is still 3, and its index moved down.
    let packet = rx(3, 0, rtp(96, 1, 0, 9, &[1]));
    assert_eq!(room.ingest(&packet), Ingress::DroppedFromPeer);
    assert!(room.next_datagram(&packet).is_none());
    room.set_source(Some("seat-3")).unwrap();
    room.ingest(&packet);
    assert_eq!(forwarded(&mut room, &packet).len(), 1);
}

#[test]
fn removing_a_seat_before_the_source_keeps_the_source() {
    let mut room = room_of(3);
    room.set_source(Some("seat-3")).unwrap();
    assert!(room.remove_seat("seat-1"));
    assert_eq!(room.source(), Some("seat-3"));
    assert!(!room.remove_seat("seat-1"));
}

#[test]
fn a_seat_that_cannot_be_reached_is_skipped() {
    let mut room = amr_wb_room();
    room.add_seat(seat_config(1), 0).unwrap();
    let mut unkeyed = seat_config(2);
    unkeyed.secure_pending = true;
    room.add_seat(unkeyed, 0).unwrap();
    let mut unselected = seat_config(3);
    unselected.ice_pending = true;
    room.add_seat(unselected, 0).unwrap();
    let mut unresolved = seat_config(4);
    unresolved.egress_destination = address("0.0.0.0:0");
    room.add_seat(unresolved, 0).unwrap();
    room.add_seat(seat_config(5), 0).unwrap();
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx(1, 0, rtp(96, 1, 0, 5, &[1]));
    room.ingest(&packet);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 1, "only seat-5 is reachable");
    assert_eq!(sent[0].0, EndpointId(5));
}

#[test]
fn a_packet_from_an_unsignalled_source_never_enters_the_room() {
    let mut room = room_of(2);
    room.set_source(Some("seat-1")).unwrap();
    let mut packet = rx(1, 0, rtp(96, 1, 0, 5, &[1]));
    packet.source = address("198.51.100.7:4000");
    assert_eq!(room.ingest(&packet), Ingress::Refused);
    assert!(room.next_datagram(&packet).is_none());
}

#[test]
fn a_datagram_on_an_unknown_endpoint_is_refused() {
    let mut room = room_of(1);
    let packet = rx(9, 0, rtp(96, 1, 0, 5, &[1]));
    assert_eq!(room.ingest(&packet), Ingress::Refused);
}

#[test]
fn the_latch_moves_the_reply_to_the_sources_own_nat_binding() {
    let mut room = amr_wb_room();
    room.add_seat(seat_config(1), 0).unwrap();
    let mut open = seat_config(2);
    open.accepted_source = SourceFilter::Any;
    room.add_seat(open, 0).unwrap();
    room.set_source(Some("seat-1")).unwrap();
    // seat-2 is not the source, but its packet latches its reply address.
    let mut hello = rx(2, 0, rtp(96, 1, 0, 8, &[1]));
    hello.source = address("203.0.113.5:40000");
    assert_eq!(room.ingest(&hello), Ingress::DroppedFromPeer);
    let packet = rx(1, 20_000, rtp(96, 1, 0, 5, &[1]));
    room.ingest(&packet);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent[0].1, address("203.0.113.5:40000"));
}

#[test]
fn telephone_event_is_forwarded_only_between_seats_at_the_same_clock_rate() {
    let mut room = amr_wb_room();
    let mut source = seat_config(1);
    source.telephone_event = Some(TelephoneEvent {
        payload_type: 100,
        clock_rate_hz: 16_000,
    });
    room.add_seat(source, 0).unwrap();
    let mut same = seat_config(2);
    same.telephone_event = Some(TelephoneEvent {
        payload_type: 101,
        clock_rate_hz: 16_000,
    });
    room.add_seat(same, 0).unwrap();
    let mut narrowband = seat_config(3);
    narrowband.telephone_event = Some(TelephoneEvent {
        payload_type: 102,
        clock_rate_hz: 8_000,
    });
    room.add_seat(narrowband, 0).unwrap();
    room.add_seat(seat_config(4), 0).unwrap(); // negotiated none
    room.set_source(Some("seat-1")).unwrap();
    let event = rx(1, 0, rtp(100, 1, 0, 5, &[5, 0x0A, 0x00, 0xA0]));
    assert_eq!(room.ingest(&event), Ingress::Accepted);
    let sent = forwarded(&mut room, &event);
    assert_eq!(
        sent.len(),
        1,
        "only the seat at the same clock rate hears it"
    );
    assert_eq!(sent[0].0, EndpointId(2));
    let (_, payload_type, _, _, _, payload) = parsed(&sent[0].2);
    assert_eq!(payload_type, 101, "mapped to the receiver's own number");
    assert_eq!(payload, [5, 0x0A, 0x00, 0xA0]);
}

#[test]
fn a_payload_type_the_source_did_not_negotiate_is_dropped() {
    let mut room = room_of(2);
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx(1, 0, rtp(120, 1, 0, 5, &[1]));
    assert_eq!(room.ingest(&packet), Ingress::DroppedFromPeer);
    assert!(room.next_datagram(&packet).is_none());
    assert_eq!(room.seat_stats("seat-1").unwrap().unknown_payload_type, 1);
}

#[test]
fn rtcp_from_a_seat_is_consumed_and_never_forwarded() {
    let mut room = room_of(3);
    room.set_source(Some("seat-1")).unwrap();
    let mut buffer = [0u8; 64];
    let length = rtcp::write_sender_report(
        0x1111_1111,
        0x0000_0001_8000_0000,
        0,
        0,
        0,
        &[],
        &mut buffer,
    )
    .unwrap();
    let packet = rx(1, 0, buffer[..length].to_vec());
    assert_eq!(room.ingest(&packet), Ingress::Accepted, "RTCP is liveness");
    assert!(room.next_datagram(&packet).is_none(), "and never relayed");
    // A non-source seat's RTCP is consumed too.
    let packet = rx(2, 0, buffer[..length].to_vec());
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    assert!(room.next_datagram(&packet).is_none());
}

fn sender_report_fields(datagram: &[u8]) -> (u32, u64, u32, u32, u32, Option<rtcp::ReportBlock>) {
    let packets = rtcp::parse_compound(datagram).unwrap();
    match &packets[0] {
        rtcp::RtcpPacket::SenderReport(report) => (
            report.ssrc,
            report.ntp_timestamp,
            report.rtp_timestamp,
            report.packet_count,
            report.octet_count,
            report.reports.first().copied(),
        ),
        other => panic!("expected an SR, got {other:?}"),
    }
}

#[test]
fn the_sender_report_describes_the_stream_the_seat_is_sent() {
    let mut room = room_of(2);
    room.set_source(Some("seat-1")).unwrap();
    // Three 5-octet packets to seat-2, 20 ms apart, starting at t = 1 s.
    for frame in 0..3u32 {
        let packet = rx(
            1,
            1_000_000 + u64::from(frame) * 20_000,
            rtp(
                96,
                frame as u16,
                frame * FRAME_TICKS,
                0x1111_1111,
                &[1, 2, 3, 4, 5],
            ),
        );
        room.ingest(&packet);
        forwarded(&mut room, &packet);
    }
    let mut out = Vec::new();
    // 100 ms after the last packet (t = 1.04 s + 0.1 s).
    room.build_reports(0xAAAA_BBBB_CCCC_DDDD, 1_140_000, &mut out);
    assert_eq!(out.len(), 2, "one SR per reachable seat");
    let to_two = out
        .iter()
        .find(|item| item.endpoint == EndpointId(2))
        .unwrap();
    assert_eq!(to_two.dst, address("192.0.2.2:4000"));
    let (ssrc, ntp, rtp_timestamp, packets, octets, block) = sender_report_fields(&to_two.data);
    assert_eq!(ssrc, 0xE000_0002, "the seat's stable egress SSRC");
    assert_eq!(ntp, 0xAAAA_BBBB_CCCC_DDDD);
    assert_eq!(packets, 3);
    assert_eq!(octets, 15);
    assert!(block.is_none(), "seat-2 has sent the room nothing");
    // Last packet carried 50_000 + 2 * 320; 100 ms later is 1600 ticks on at 16 kHz.
    assert_eq!(rtp_timestamp, 50_000 + 2 * FRAME_TICKS + 1_600);
}

#[test]
fn a_seat_that_has_sent_rtp_gets_a_reception_report_about_it() {
    let mut room = room_of(2);
    room.set_source(Some("seat-1")).unwrap();
    // seat-1 sends packets 10, 11 and 13 (12 lost); it is the source.
    for (index, sequence) in [10u16, 11, 13].into_iter().enumerate() {
        let packet = rx(
            1,
            index as u64 * 20_000,
            rtp(
                96,
                sequence,
                u32::from(sequence) * FRAME_TICKS,
                0x1111_1111,
                &[1],
            ),
        );
        room.ingest(&packet);
        forwarded(&mut room, &packet);
    }
    // seat-1 sent the room an SR; the room echoes its middle 32 NTP bits as LSR.
    let mut buffer = [0u8; 64];
    let length = rtcp::write_sender_report(
        0x1111_1111,
        0x0000_0002_4000_0000,
        0,
        3,
        3,
        &[],
        &mut buffer,
    )
    .unwrap();
    room.ingest(&rx(1, 100_000, buffer[..length].to_vec()));
    let mut out = Vec::new();
    room.build_reports(1, 600_000, &mut out);
    let to_one = out
        .iter()
        .find(|item| item.endpoint == EndpointId(1))
        .unwrap();
    let (_, _, _, packets, _, block) = sender_report_fields(&to_one.data);
    assert_eq!(packets, 0, "nothing was ever forwarded to the source");
    let block = block.expect("a reception report block about seat-1's stream");
    assert_eq!(block.ssrc, 0x1111_1111);
    assert_eq!(block.highest_sequence, 13);
    assert_eq!(block.cumulative_lost, 1);
    assert_eq!(block.last_sender_report, 0x0002_4000);
    // 500 ms between the SR's arrival (0.1 s) and now (0.6 s), in 1/65536 s.
    assert_eq!(block.delay_since_last_sr, 32_768);
}

#[test]
fn a_reception_report_about_the_seats_stream_yields_a_round_trip() {
    let mut room = room_of(2);
    let mut out = Vec::new();
    room.build_reports(0x0000_0010_0000_0000, 1_000_000, &mut out);
    let to_two = out
        .iter()
        .find(|item| item.endpoint == EndpointId(2))
        .unwrap();
    let (ssrc, ntp, ..) = sender_report_fields(&to_two.data);
    // seat-2 answers with an RR about our SSRC: LSR = the SR's middle 32 bits, 10 ms of delay.
    let echoed = ((ntp >> 16) & 0xFFFF_FFFF) as u32;
    let reports = [rtcp::ReceptionReport {
        ssrc,
        fraction_lost: 0,
        cumulative_lost: 0,
        extended_highest_seq: 0,
        jitter: 0,
        last_sr: echoed,
        delay_last_sr: 655, // ~10 ms
    }];
    let mut buffer = [0u8; 64];
    let length = rtcp::write_sender_report(0x2222_2222, 0, 0, 0, 0, &reports, &mut buffer).unwrap();
    room.ingest(&rx(2, 1_060_000, buffer[..length].to_vec()));
    let rtt = room.round_trip_micros("seat-2").unwrap();
    assert!(
        (49_000..=51_000).contains(&rtt),
        "60 ms - 10 ms = ~50 ms, got {rtt}"
    );
}

#[test]
fn a_room_holds_at_most_the_seat_cap_and_rejects_a_duplicate_tag() {
    let mut room = amr_wb_room();
    for index in 0..MAX_SEATS {
        let mut config = seat_config(1);
        config.tag = format!("seat-{index}");
        config.endpoint = EndpointId(index as u64 + 1);
        room.add_seat(config, 0).unwrap();
    }
    assert_eq!(room.seat_count(), MAX_SEATS);
    let mut one_too_many = seat_config(1);
    one_too_many.tag = "extra".to_string();
    one_too_many.endpoint = EndpointId(5000);
    assert_eq!(room.add_seat(one_too_many, 0), Err(ForwardError::RoomFull));
    let mut duplicate = seat_config(1);
    duplicate.endpoint = EndpointId(6000);
    duplicate.tag = "seat-0".to_string();
    room.remove_seat("seat-1");
    assert_eq!(
        room.add_seat(duplicate, 0),
        Err(ForwardError::DuplicateTag("seat-0".to_string()))
    );
}

#[test]
fn a_secure_receiver_is_sent_srtp_and_a_secure_source_is_decrypted_first() {
    use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
    let key = |seed: u8| SrtpKeyMaterial::from_inline_bytes(&[seed; 30]).unwrap();
    let mut room = amr_wb_room();
    let mut source = seat_config(1);
    source.secure = Some(SecureLeg::new(&key(2), &key(1))); // inbound under key 1
    room.add_seat(source, 0).unwrap();
    let mut receiver = seat_config(2);
    receiver.secure = Some(SecureLeg::new(&key(3), &key(4))); // outbound under key 3
    room.add_seat(receiver, 0).unwrap();
    room.set_source(Some("seat-1")).unwrap();

    // The phone protects with the key the room unprotects with.
    let mut phone = SecureLeg::new(&key(1), &key(2));
    let mut protected = Vec::new();
    phone
        .protect(&rtp(96, 1, 0, 0x1111_1111, &[9, 8, 7]), &mut protected)
        .unwrap();
    let packet = rx(1, 0, protected);
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent.len(), 1);
    // The receiver's phone unprotects with key 3.
    let mut receiving_phone = SecureLeg::new(&key(4), &key(3));
    let mut clear = Vec::new();
    receiving_phone.unprotect(&sent[0].2, &mut clear).unwrap();
    assert_eq!(parsed(&clear).5, [9, 8, 7]);

    // A forged packet (wrong key) is refused before it can be forwarded.
    let mut forger = SecureLeg::new(&key(9), &key(9));
    let mut forged = Vec::new();
    forger
        .protect(&rtp(96, 2, 320, 0x1111_1111, &[6]), &mut forged)
        .unwrap();
    let packet = rx(1, 20_000, forged);
    assert_eq!(room.ingest(&packet), Ingress::Refused);
    assert!(room.next_datagram(&packet).is_none());
}

#[test]
fn a_dtls_seat_is_reachable_once_its_key_arrives() {
    use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
    let key = |seed: u8| SrtpKeyMaterial::from_inline_bytes(&[seed; 30]).unwrap();
    let mut room = amr_wb_room();
    room.add_seat(seat_config(1), 0).unwrap();
    let mut pending = seat_config(2);
    pending.secure_pending = true;
    room.add_seat(pending, 0).unwrap();
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx(1, 0, rtp(96, 1, 0, 5, &[1]));
    room.ingest(&packet);
    assert!(forwarded(&mut room, &packet).is_empty());
    room.attach_secure_leg("seat-2", SecureLeg::new(&key(3), &key(4)));
    let packet = rx(1, 20_000, rtp(96, 2, 320, 5, &[1]));
    room.ingest(&packet);
    assert_eq!(forwarded(&mut room, &packet).len(), 1);
}

#[test]
fn ice_selection_opens_a_pending_seat_and_aims_it_at_the_selected_pair() {
    let mut room = amr_wb_room();
    room.add_seat(seat_config(1), 0).unwrap();
    let mut pending = seat_config(2);
    pending.ice_pending = true;
    pending.accepted_source = SourceFilter::Any;
    room.add_seat(pending, 0).unwrap();
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx(1, 0, rtp(96, 1, 0, 5, &[1]));
    room.ingest(&packet);
    assert!(forwarded(&mut room, &packet).is_empty());
    room.ice_selected("seat-2", address("198.51.100.20:5004"));
    let packet = rx(1, 20_000, rtp(96, 2, 320, 5, &[1]));
    room.ingest(&packet);
    let sent = forwarded(&mut room, &packet);
    assert_eq!(sent[0].1, address("198.51.100.20:5004"));
}

mod concealment;
mod floor;
mod mode_request;
mod preserve;
mod transcode;
