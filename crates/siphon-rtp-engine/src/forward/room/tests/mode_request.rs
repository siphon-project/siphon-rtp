#![cfg(feature = "amr")]
//! A cross-codec AMR seat's Codec Mode Request (RFC 4867 §4.3.1), read from its own RTP and applied to
//! the group it is sent in, whether or not it is the one talking.

use super::transcode::{add_cross, add_same, config_for, fan_out, tone_stream};
use super::*;
use siphon_rtp_codec::amr::rtp::{
    read_payload, write_payload, FrameSource, PayloadFormat, Variant,
};
use siphon_rtp_codec::factory::{AmrParams, CodecSpec};

const NARROWBAND_PAYLOAD_TYPE: u8 = 97;

/// AMR-NB, octet-aligned, with the mode-set {0, 2, 4}: the seat can be sent nothing above mode 4.
fn narrowband() -> CodecSpec {
    CodecSpec::new(NARROWBAND_PAYLOAD_TYPE, "AMR", 8000, 1, 20)
        .with_allowed_modes(vec![0, 2, 4])
        .with_amr_params(Some(AmrParams {
            octet_align: Some(true),
            ..Default::default()
        }))
}

fn wideband() -> CodecSpec {
    CodecSpec::new(96, "AMR-WB", 16_000, 1, 20).with_amr_params(Some(AmrParams {
        octet_align: Some(true),
        ..Default::default()
    }))
}

/// An AMR-WB room with the source on seat 1 and two AMR-NB seats (2 and 3) that share a codec.
fn room_with_narrowband_seats() -> ForwardRoom {
    let mut room = amr_wb_room();
    add_same(&mut room, seat_config(1));
    for index in [2, 3] {
        add_cross(
            &mut room,
            config_for(index, NARROWBAND_PAYLOAD_TYPE),
            &narrowband(),
        );
    }
    room.set_source(Some("seat-1")).unwrap();
    room
}

/// The speech mode of the first frame in an octet-aligned AMR-NB payload.
fn mode_of(payload: &[u8]) -> u8 {
    let layout = read_payload(payload, PayloadFormat::OctetAligned, Variant::Narrowband).unwrap();
    layout.frames()[0].frame_type
}

/// What seat `index` sends while it is listening: a payload with nothing in it but its request.
fn request(room: &mut ForwardRoom, index: u8, sequence: u16, cmr: u8) {
    let frame = FrameSource {
        frame_type: 15, // NO_DATA
        quality_ok: true,
        data: &[],
    };
    let mut payload = [0u8; 8];
    let length = write_payload(
        PayloadFormat::OctetAligned,
        Variant::Narrowband,
        cmr,
        &[frame],
        &mut payload,
    )
    .unwrap();
    let packet = rx(
        index,
        1_000_000,
        rtp(
            NARROWBAND_PAYLOAD_TYPE,
            sequence,
            u32::from(sequence) * 160,
            0x4000_0000 + u32::from(index),
            &payload[..length],
        ),
    );
    assert_eq!(
        room.ingest(&packet),
        Ingress::DroppedFromPeer,
        "a listener's packet is read for its request and dropped"
    );
}

/// Send one source frame and return the AMR-NB mode each narrowband seat was sent.
fn modes_heard(room: &mut ForwardRoom, stream: &[Vec<u8>], frame: usize) -> (u8, u8) {
    let packet = rx(
        1,
        20_000 * (frame as u64 + 1),
        rtp(
            96,
            100 + frame as u16,
            frame as u32 * 320,
            0x1111_1111,
            &stream[frame],
        ),
    );
    let sent = fan_out(room, &packet);
    let payload_of = |endpoint: u64| {
        let (_, _, _, _, _, payload) = parsed(
            &sent
                .iter()
                .find(|(candidate, _)| *candidate == endpoint)
                .unwrap()
                .1,
        );
        payload
    };
    (mode_of(&payload_of(2)), mode_of(&payload_of(3)))
}

#[test]
fn one_seats_request_changes_only_its_own_encoded_mode() {
    let mut room = room_with_narrowband_seats();
    let stream = tone_stream(&wideband(), 12);
    assert_eq!(
        modes_heard(&mut room, &stream, 0),
        (4, 4),
        "the highest of the set"
    );
    assert_eq!(room.transcoder.as_ref().unwrap().group_count(), 1);

    request(&mut room, 2, 1, 2);
    assert_eq!(room.transcoder.as_ref().unwrap().group_count(), 2);
    assert_eq!(modes_heard(&mut room, &stream, 1), (2, 4));
    assert_eq!(modes_heard(&mut room, &stream, 2), (2, 4));

    // CMR 0 asks for less still; seat 3 is untouched.
    request(&mut room, 2, 2, 0);
    assert_eq!(modes_heard(&mut room, &stream, 3), (0, 4));

    // CMR 15 withdraws the request: the seat is back in the default group, and the group made for
    // it is dropped with its last seat.
    request(&mut room, 2, 3, 15);
    assert_eq!(room.transcoder.as_ref().unwrap().group_count(), 1);
    assert_eq!(modes_heard(&mut room, &stream, 4), (4, 4));
}

#[test]
fn a_request_outside_the_mode_set_is_ignored_and_no_mode_outside_it_is_ever_sent() {
    let mut room = room_with_narrowband_seats();
    let stream = tone_stream(&wideband(), 12);
    request(&mut room, 2, 1, 2);
    assert_eq!(modes_heard(&mut room, &stream, 0).0, 2);
    // RFC 4867 §4.3.1: a request for a mode outside the mode-set MUST be ignored, so the one in
    // force stays; and §8.1: modes outside the set MUST NOT be sent.
    for (step, cmr) in [3u8, 7, 12, 1].into_iter().enumerate() {
        request(&mut room, 2, 2 + step as u16, cmr);
        let (first, other) = modes_heard(&mut room, &stream, 1 + step);
        assert_eq!(first, 2, "request {cmr} is not in the set {{0, 2, 4}}");
        assert_eq!(other, 4);
    }
    // A request above what the encoder would send anyway changes nothing either.
    request(&mut room, 2, 10, 4);
    assert_eq!(room.transcoder.as_ref().unwrap().group_count(), 1);
    assert_eq!(modes_heard(&mut room, &stream, 6), (4, 4));
}

#[test]
fn a_request_is_read_from_a_seat_that_is_not_talking_and_from_one_that_is() {
    let mut room = amr_wb_room();
    add_same(&mut room, seat_config(1));
    for index in [2, 3, 4] {
        add_cross(
            &mut room,
            config_for(index, NARROWBAND_PAYLOAD_TYPE),
            &narrowband(),
        );
    }
    // Seat 4 talks in AMR-NB; seat 2 asked for mode 2, seat 3 asked for nothing.
    room.set_source(Some("seat-4")).unwrap();
    request(&mut room, 2, 1, 2);
    let stream = tone_stream(&narrowband(), 6);
    let packet = rx(4, 20_000, rtp(97, 50, 1600, 0x4444_4444, &stream[0]));
    let sent = fan_out(&mut room, &packet);
    let payload_to =
        |endpoint: u64| parsed(&sent.iter().find(|(e, _)| *e == endpoint).unwrap().1).5;
    assert_eq!(
        payload_to(3),
        stream[0],
        "a seat with no request is sent the talker's bytes as they came"
    );
    assert!(
        mode_of(&payload_to(2)) <= 2,
        "the seat that asked is re-encoded"
    );
    assert_ne!(payload_to(2), stream[0]);
    assert_eq!(sent.len(), 3, "the room-codec seat, and the two listeners");
}

#[test]
fn a_seat_that_leaves_takes_its_group_with_it() {
    let mut room = room_with_narrowband_seats();
    request(&mut room, 2, 1, 2);
    assert_eq!(room.transcoder.as_ref().unwrap().group_count(), 2);
    assert!(room.remove_seat("seat-2"));
    assert_eq!(room.transcoder.as_ref().unwrap().group_count(), 1);
    assert!(room.remove_seat("seat-3"));
    assert_eq!(room.transcoder.as_ref().unwrap().group_count(), 0);
}

#[test]
fn a_seat_with_a_request_does_not_cost_the_others_a_transcode() {
    let mut room = room_with_narrowband_seats();
    let stream = tone_stream(&wideband(), 4);
    modes_heard(&mut room, &stream, 0);
    let one_group = room.transcode_stats().encodes;
    request(&mut room, 2, 1, 2);
    let before = room.transcode_stats().encodes;
    modes_heard(&mut room, &stream, 1);
    assert_eq!(
        room.transcode_stats().encodes - before,
        2,
        "one encode per group, not per seat"
    );
    assert_eq!(one_group, 1);
}
