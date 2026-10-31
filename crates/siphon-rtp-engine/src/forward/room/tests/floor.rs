//! The MCPTT floor stream and RTCP APP in a forwarding room (3GPP TS 24.380 §8).

use super::*;
use crate::app_events::AppEventQueue;
use siphon_rtp_media::rtcp::AppWriteError;
use siphon_rtp_proto::RtcpAppStream;
use siphon_rtp_srtp::srtcp_gcm::{FloorMasterKey, SrtcpGcmContext};

/// The floor endpoint of seat `index` is `100 + index`; its phone is at `192.0.2.<index>:4100`.
fn floor_config(index: u8) -> FloorConfig {
    FloorConfig {
        endpoint: EndpointId(100 + u64::from(index)),
        destination: address(&format!("192.0.2.{index}:4100")),
        accepted_source: SourceFilter::Exact(address(&format!("192.0.2.{index}:4100")).ip()),
        ice_gated: false,
        keys: Vec::new(),
    }
}

/// A room of `seats` seats that each have a floor stream, all reporting to one APP queue.
fn floor_room(seats: u8) -> (ForwardRoom, AppEventQueue) {
    let queue = AppEventQueue::new(64, std::sync::Arc::new(crate::metrics::Metrics::new()));
    let mut room = amr_wb_room();
    for index in 1..=seats {
        let mut config = seat_config(index);
        config.floor = Some(floor_config(index));
        config.app_events = Some(queue.clone());
        room.add_seat(config, 0).unwrap();
    }
    (room, queue)
}

fn floor_rx(index: u8, data: Vec<u8>) -> RxPacket {
    RxPacket {
        endpoint: EndpointId(100 + u64::from(index)),
        source: address(&format!("192.0.2.{index}:4100")),
        arrival: 0,
        data: Bytes::from(data),
    }
}

/// TS 24.380 §8.2.4 Floor Request as a phone sends it: SSRC 0x11223344, name MCPT, subtype 0.
const FLOOR_REQUEST: [u8; 16] = [
    0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05, 0x00,
];

fn app_events(queue: &AppEventQueue) -> Vec<Event> {
    queue.receiver().try_iter().collect()
}

#[test]
fn a_floor_request_becomes_one_event_and_is_never_forwarded() {
    let (mut room, queue) = floor_room(3);
    room.set_source(Some("seat-2")).unwrap();
    let packet = floor_rx(1, FLOOR_REQUEST.to_vec());
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    assert!(
        room.next_datagram(&packet).is_none(),
        "floor is not relayed"
    );
    assert_eq!(
        app_events(&queue),
        vec![Event::RtcpApp {
            call_id: None,
            conference_id: Some("group-1".into()),
            from_tag: "seat-1".into(),
            stream: RtcpAppStream::Floor,
            ssrc: 0x1122_3344,
            name: "MCPT".into(),
            subtype: 0,
            payload: vec![0x00, 0x02, 0x05, 0x00],
        }]
    );
}

#[test]
fn two_app_packets_in_one_datagram_are_two_events_in_order() {
    let (mut room, queue) = floor_room(1);
    let mut second = FLOOR_REQUEST;
    second[0] = 0x80 | 5;
    second[12..].copy_from_slice(&[9, 9, 9, 9]);
    let mut datagram = FLOOR_REQUEST.to_vec();
    datagram.extend_from_slice(&second);
    assert_eq!(room.ingest(&floor_rx(1, datagram)), Ingress::Accepted);
    let subtypes: Vec<u8> = app_events(&queue)
        .into_iter()
        .map(|event| match event {
            Event::RtcpApp { subtype, .. } => subtype,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(subtypes, [0, 5]);
}

#[test]
fn a_malformed_datagram_is_counted_and_raises_nothing() {
    let (mut room, queue) = floor_room(1);
    // Declares 16 bytes, carries 12.
    let truncated = FLOOR_REQUEST[..12].to_vec();
    assert_eq!(room.ingest(&floor_rx(1, truncated)), Ingress::Accepted);
    assert!(app_events(&queue).is_empty());
    assert_eq!(room.seat_stats("seat-1").unwrap().malformed_app, 1);
    // A good packet followed by garbage still yields the good one.
    let mut datagram = FLOOR_REQUEST.to_vec();
    datagram.extend_from_slice(&[0x00, 0x01, 0x02]);
    assert_eq!(room.ingest(&floor_rx(1, datagram)), Ingress::Accepted);
    assert_eq!(app_events(&queue).len(), 1);
    assert_eq!(room.seat_stats("seat-1").unwrap().malformed_app, 2);
}

#[test]
fn a_non_ascii_name_octet_is_reported_as_a_question_mark() {
    let (mut room, queue) = floor_room(1);
    let mut datagram = FLOOR_REQUEST;
    datagram[9] = 0xE9;
    room.ingest(&floor_rx(1, datagram.to_vec()));
    let Some(Event::RtcpApp { name, .. }) = app_events(&queue).into_iter().next() else {
        panic!("one event");
    };
    assert_eq!(name, "M?PT");
}

#[test]
fn floor_from_an_unsignalled_source_never_reaches_the_controller() {
    let (mut room, queue) = floor_room(2);
    let mut packet = floor_rx(1, FLOOR_REQUEST.to_vec());
    packet.source = address("198.51.100.9:4100");
    assert_eq!(room.ingest(&packet), Ingress::Refused);
    assert!(app_events(&queue).is_empty());
}

#[test]
fn the_floor_latch_learns_one_source_and_never_moves() {
    let (mut room, queue) = floor_room(1);
    // Same IP as signalled, another port than signalled: the first source is learned.
    let mut first = floor_rx(1, FLOOR_REQUEST.to_vec());
    first.source = address("192.0.2.1:5000");
    assert_eq!(room.ingest(&first), Ingress::Accepted);
    // A later datagram from yet another port of the same IP (a hijack, or a rebind: with no SSRC
    // the two cannot be told apart) is refused and the reply address stays.
    let mut later = floor_rx(1, FLOOR_REQUEST.to_vec());
    later.source = address("192.0.2.1:5002");
    assert_eq!(room.ingest(&later), Ingress::Refused);
    assert_eq!(
        app_events(&queue).len(),
        1,
        "only the learned source reports"
    );
    let mut sent = Vec::new();
    room.send_app(
        &AppTarget::Seat("seat-1".into()),
        &AppRequest {
            stream: RtcpAppStream::Floor,
            ssrc: None,
            name: *b"MCPT",
            subtype: 1,
            payload: Vec::new(),
        },
        |endpoint, destination, _| sent.push((endpoint, destination)),
    )
    .unwrap();
    assert_eq!(sent, [(EndpointId(101), address("192.0.2.1:5000"))]);
}

#[test]
fn floor_is_refused_while_the_seats_ice_pair_or_key_is_pending() {
    let (mut room, queue) = floor_room(1);
    let mut config = seat_config(2);
    config.ice_pending = true;
    config.floor = Some(floor_config(2));
    config.app_events = Some(queue.clone());
    room.add_seat(config, 0).unwrap();
    assert_eq!(
        room.ingest(&floor_rx(2, FLOOR_REQUEST.to_vec())),
        Ingress::Refused
    );
    assert!(app_events(&queue).is_empty());
    room.ice_selected("seat-2", address("192.0.2.2:4000"));
    assert_eq!(
        room.ingest(&floor_rx(2, FLOOR_REQUEST.to_vec())),
        Ingress::Accepted
    );
    assert_eq!(app_events(&queue).len(), 1);
}

#[test]
fn app_in_a_seats_audio_rtcp_is_reported_and_its_reports_are_still_read() {
    let (mut room, queue) = floor_room(2);
    let mut buffer = [0u8; 128];
    let mut length = rtcp::write_sender_report(
        0x1111_1111,
        0x0000_0001_8000_0000,
        0,
        0,
        0,
        &[],
        &mut buffer,
    )
    .unwrap();
    length += rtcp::write_app(
        17,
        0x1111_1111,
        *b"MCPT",
        &[0, 1, 2, 3],
        &mut buffer[length..],
    )
    .unwrap();
    let packet = rx(1, 5, buffer[..length].to_vec());
    assert_eq!(room.ingest(&packet), Ingress::Accepted);
    assert!(room.next_datagram(&packet).is_none());
    let events = app_events(&queue);
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        Event::RtcpApp {
            stream: RtcpAppStream::Audio,
            subtype: 17,
            ssrc: 0x1111_1111,
            ..
        }
    ));
    // The SR half was consumed as before: its NTP middle bits became our LSR.
    assert_eq!(room.seats[0].last_sender_report_ntp_middle, 0x0001_8000);
}

fn floor_granted() -> AppRequest {
    AppRequest {
        stream: RtcpAppStream::Floor,
        ssrc: None,
        name: *b"MCPT",
        subtype: 17,
        payload: vec![
            0x01, 0x02, 0x00, 0x1E, 0x0E, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
        ],
    }
}

type Sent = Vec<(EndpointId, SocketAddr, Vec<u8>)>;

fn sent_app(
    room: &mut ForwardRoom,
    target: &AppTarget,
    request: &AppRequest,
) -> (Result<(), AppSendError>, Sent) {
    let mut sent = Vec::new();
    let result = room.send_app(target, request, |endpoint, destination, data| {
        sent.push((endpoint, destination, data.to_vec()));
    });
    (result, sent)
}

#[test]
fn a_floor_granted_is_built_byte_exact_under_the_seats_egress_ssrc() {
    let (mut room, _queue) = floor_room(2);
    let (result, sent) = sent_app(
        &mut room,
        &AppTarget::Seat("seat-2".into()),
        &floor_granted(),
    );
    result.unwrap();
    assert_eq!(
        sent,
        vec![(
            EndpointId(102),
            address("192.0.2.2:4100"),
            vec![
                0x91, 0xCC, 0x00, 0x05, // V=2 P=0 subtype 17, APP, 5 words after the first
                0xE0, 0x00, 0x00, 0x02, // the seat's egress SSRC
                0x4D, 0x43, 0x50, 0x54, // MCPT
                0x01, 0x02, 0x00, 0x1E, 0x0E, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
            ]
        )]
    );
    // An explicit SSRC wins.
    let mut request = floor_granted();
    request.ssrc = Some(0xDEAD_BEEF);
    let (result, sent) = sent_app(&mut room, &AppTarget::Seat("seat-2".into()), &request);
    result.unwrap();
    assert_eq!(&sent[0].2[4..8], &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn a_room_wide_send_skips_the_excepted_seats() {
    let (mut room, _queue) = floor_room(4);
    let target = AppTarget::Room {
        except: vec!["seat-2".into(), "no-such-seat".into()],
    };
    let (result, sent) = sent_app(&mut room, &target, &floor_granted());
    result.unwrap();
    let endpoints: Vec<EndpointId> = sent.iter().map(|(endpoint, _, _)| *endpoint).collect();
    assert_eq!(
        endpoints,
        [EndpointId(101), EndpointId(103), EndpointId(104)]
    );
    // Each seat is written under its own SSRC.
    let ssrcs: Vec<&[u8]> = sent.iter().map(|(_, _, data)| &data[4..8]).collect();
    assert_eq!(ssrcs[0], [0xE0, 0, 0, 1]);
    assert_eq!(ssrcs[2], [0xE0, 0, 0, 4]);
}

#[test]
fn floor_goes_only_to_seats_with_a_floor_stream_and_audio_to_all() {
    let (mut room, queue) = floor_room(1);
    let mut plain = seat_config(2);
    plain.app_events = Some(queue);
    room.add_seat(plain, 0).unwrap();
    let everyone = AppTarget::Room { except: Vec::new() };
    let (result, sent) = sent_app(&mut room, &everyone, &floor_granted());
    result.unwrap();
    assert_eq!(
        sent.len(),
        1,
        "the seat without floor control is not addressed"
    );
    // Addressing that seat by name is an error naming why.
    let (result, sent) = sent_app(
        &mut room,
        &AppTarget::Seat("seat-2".into()),
        &floor_granted(),
    );
    assert_eq!(
        result,
        Err(AppSendError::NotSent("seat-2 (no floor stream)".into()))
    );
    assert!(sent.is_empty());
    // The audio stream reaches both, on the audio endpoints.
    let mut request = floor_granted();
    request.stream = RtcpAppStream::Audio;
    let (result, sent) = sent_app(&mut room, &everyone, &request);
    result.unwrap();
    let endpoints: Vec<EndpointId> = sent.iter().map(|(endpoint, _, _)| *endpoint).collect();
    assert_eq!(endpoints, [EndpointId(1), EndpointId(2)]);
}

/// Wireshark is the independent decoder: it does not share our encoder's bugs. The Floor Granted
/// datagram the room builds is written to a pcap with `text2pcap` and `tshark` must read the
/// Duration field (30 s) and the name and subtype we meant. Skipped, not failed, where the tools
/// are not installed.
#[test]
fn wireshark_reads_the_floor_granted_the_room_builds() {
    use std::process::Command;
    let tool = |name: &str| Command::new(name).arg("--version").output().is_ok();
    if !tool("tshark") || !tool("text2pcap") {
        eprintln!("tshark/text2pcap not installed: Wireshark cross-check skipped");
        return;
    }
    let (mut room, _queue) = floor_room(1);
    let (result, sent) = sent_app(
        &mut room,
        &AppTarget::Seat("seat-1".into()),
        &floor_granted(),
    );
    result.unwrap();
    let hex: String = sent[0]
        .2
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let bytes: Vec<String> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
            format!("{:04x}  {}\n", row * 16, bytes.join(" "))
        })
        .collect();
    let directory = std::env::temp_dir().join(format!("siphon-floor-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let (text, pcap) = (directory.join("floor.txt"), directory.join("floor.pcap"));
    std::fs::write(&text, hex).unwrap();
    let made = Command::new("text2pcap")
        .args(["-u", "5004,5006"])
        .arg(&text)
        .arg(&pcap)
        .output()
        .unwrap();
    assert!(made.status.success(), "text2pcap failed");
    let read = Command::new("tshark")
        .arg("-r")
        .arg(&pcap)
        .args(["-d", "udp.port==5006,rtcp", "-T", "fields"])
        .args(["-e", "rtcp.app_data.mcptt.duration"])
        .args(["-e", "rtcp.app.name", "-e", "rtcp.app.subtype"])
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&directory);
    assert!(read.status.success(), "tshark failed");
    assert_eq!(
        String::from_utf8_lossy(&read.stdout).trim(),
        "30\tMCPT\t17",
        "Wireshark must read the Duration, name and subtype we wrote"
    );
}

#[test]
fn a_bad_packet_or_an_unknown_seat_sends_nothing() {
    let (mut room, _queue) = floor_room(2);
    let mut request = floor_granted();
    request.payload.pop();
    let (result, sent) = sent_app(&mut room, &AppTarget::Room { except: Vec::new() }, &request);
    assert_eq!(
        result,
        Err(AppSendError::Packet(AppWriteError::Unaligned(11)))
    );
    assert!(sent.is_empty());
    let (result, sent) = sent_app(
        &mut room,
        &AppTarget::Seat("ghost".into()),
        &floor_granted(),
    );
    assert_eq!(result, Err(AppSendError::UnknownSeat("ghost".into())));
    assert!(sent.is_empty());
}

#[test]
fn a_seat_without_a_destination_is_named_and_the_rest_are_still_sent() {
    let (mut room, queue) = floor_room(1);
    let mut config = seat_config(2);
    let mut floor = floor_config(2);
    floor.destination = address("0.0.0.0:0");
    config.floor = Some(floor);
    config.app_events = Some(queue);
    room.add_seat(config, 0).unwrap();
    let (result, sent) = sent_app(
        &mut room,
        &AppTarget::Room { except: Vec::new() },
        &floor_granted(),
    );
    assert_eq!(
        result,
        Err(AppSendError::NotSent(
            "seat-2 (no floor destination yet)".into()
        ))
    );
    assert_eq!(sent.len(), 1, "never into the void, but seat-1 still hears");
}

#[test]
fn audio_app_to_a_secure_seat_is_srtcp_protected() {
    use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
    let key = |seed: u8| SrtpKeyMaterial::from_inline_bytes(&[seed; 30]).unwrap();
    let mut room = amr_wb_room();
    let mut config = seat_config(1);
    config.secure = Some(SecureLeg::new(&key(2), &key(1)));
    room.add_seat(config, 0).unwrap();
    let mut request = floor_granted();
    request.stream = RtcpAppStream::Audio;
    request.ssrc = Some(0xE000_0001);
    let (result, sent) = sent_app(&mut room, &AppTarget::Seat("seat-1".into()), &request);
    result.unwrap();
    let wire = &sent[0].2;
    assert!(wire.len() > 24, "SRTCP index and tag follow the packet");
    let mut phone = SecureLeg::new(&key(1), &key(2));
    let mut clear = Vec::new();
    phone.unprotect(wire, &mut clear).unwrap();
    let apps: Vec<_> = rtcp::app_packets(&clear).collect::<Result<_, _>>().unwrap();
    assert_eq!(apps[0].subtype, 17);
}

#[test]
fn removing_a_seat_forgets_its_floor_endpoint() {
    let (mut room, _queue) = floor_room(2);
    assert_eq!(room.tag_at(EndpointId(102)), Some("seat-2"));
    room.remove_seat("seat-1");
    assert_eq!(room.tag_at(EndpointId(101)), None);
    assert_eq!(room.tag_at(EndpointId(102)), Some("seat-2"));
    assert_eq!(
        room.ingest(&floor_rx(1, FLOOR_REQUEST.to_vec())),
        Ingress::Refused
    );
}

fn floor_master_key(mki: u32) -> FloorMasterKey {
    FloorMasterKey::from_salt_96(mki, [0x11; 16], &[0x22; 12])
}

#[test]
fn a_keyed_seat_sends_protected_floor_and_a_rekey_moves_the_sending_key() {
    let (mut room, _queue) = floor_room(1);
    assert!(room.floor_key_state("seat-1").is_none(), "unkeyed to begin");
    room.set_floor_keys("seat-1", &[floor_master_key(1)])
        .unwrap();
    let (result, sent) = sent_app(
        &mut room,
        &AppTarget::Seat("seat-1".into()),
        &floor_granted(),
    );
    result.unwrap();
    let mut phone = SrtcpGcmContext::new(&[floor_master_key(1)]).unwrap();
    let mut plain = Vec::new();
    phone.unprotect(&sent[0].2, &mut plain).unwrap();
    assert_eq!(&plain[8..12], b"MCPT");
    assert_eq!(room.floor_key_state("seat-1").unwrap().1, 1, "next index");

    room.set_floor_keys("seat-1", &[floor_master_key(1), floor_master_key(2)])
        .unwrap();
    let (_, sent) = sent_app(
        &mut room,
        &AppTarget::Seat("seat-1".into()),
        &floor_granted(),
    );
    assert_eq!(sent[0].2[sent[0].2.len() - 4..], 2u32.to_be_bytes());
    let (keys, index) = room.floor_key_state("seat-1").unwrap();
    assert_eq!((keys.len(), index), (2, 2));

    assert_eq!(
        room.set_floor_keys("nobody", &[floor_master_key(1)]),
        Err(FloorKeysError::UnknownSeat("nobody".into()))
    );
    assert!(room.set_floor_keys("seat-1", &[]).is_ok());
    assert!(room.floor_key_state("seat-1").is_none(), "removed");
}

#[test]
fn a_keyed_seat_refuses_plaintext_and_counts_it() {
    let (mut room, queue) = floor_room(1);
    room.set_floor_keys("seat-1", &[floor_master_key(1)])
        .unwrap();
    let plaintext = RxPacket {
        endpoint: EndpointId(101),
        source: address("192.0.2.1:4100"),
        arrival: 0,
        data: bytes::Bytes::from_static(&[
            0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02,
            0x05, 0x00,
        ]),
    };
    assert_eq!(room.ingest(&plaintext), Ingress::Refused);
    assert!(queue.is_empty());
    assert_eq!(room.seat_stats("seat-1").unwrap().floor_refused, 1);
}

/// Emit a protected Floor Granted for `scripts/check-floor-srtcp-tshark.sh`, which feeds it to
/// Wireshark as an independent decoder. Ignored: it writes a file and is driven by the script.
#[test]
#[ignore = "driven by scripts/check-floor-srtcp-tshark.sh"]
fn emit_protected_floor_granted_hex_for_tshark() {
    let Ok(path) = std::env::var("FLOOR_SRTCP_HEX_OUT") else {
        return;
    };
    let (mut room, _queue) = floor_room(1);
    room.set_floor_keys("seat-1", &[floor_master_key(0x0102_0304)])
        .unwrap();
    let (result, sent) = sent_app(
        &mut room,
        &AppTarget::Seat("seat-1".into()),
        &floor_granted(),
    );
    result.unwrap();
    let hex: String = sent[0]
        .2
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let bytes: Vec<String> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
            format!("{:04x}  {}\n", row * 16, bytes.join(" "))
        })
        .collect();
    std::fs::write(path, hex).unwrap();
}
