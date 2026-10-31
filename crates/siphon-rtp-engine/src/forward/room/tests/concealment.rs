//! Loss of source packets in a room with cross-codec seats: each transcoded receiver is sent a
//! concealed frame in place of the gap (RFC 3550 §5.1 sequence numbers), a receiver sent the source's
//! packets as they came is not.

use super::transcode::{
    add_cross, add_same, config_for, decoded_rms, fan_out, opus, pcma, pcmu, pcmu_room, tone_stream,
};
use super::*;
use siphon_rtp_codec::factory::{self, CodecSpec};

/// What the room sent one endpoint, in order: `(sequence, timestamp, payload)`.
type Heard = Vec<(u16, u32, Vec<u8>)>;

/// Feed `stream` (frame `n` as sequence `100 + n`, timestamp `1600 + n * clock_step`) from the
/// seat on `talker` into the room, leaving out the frames in `lost`, and return what each endpoint
/// in `listeners` was sent, plus how many datagrams each ingest produced for the endpoint.
fn run(
    room: &mut ForwardRoom,
    talker: u8,
    payload_type: u8,
    stream: &[Vec<u8>],
    clock_step: u32,
    lost: &[usize],
    listeners: &[u64],
) -> (HashMap<u64, Heard>, Vec<HashMap<u64, usize>>) {
    let mut heard: HashMap<u64, Heard> = HashMap::new();
    let mut per_ingest = Vec::new();
    for (frame, payload) in stream.iter().enumerate() {
        if lost.contains(&frame) {
            continue;
        }
        let packet = rx(
            talker,
            20_000 * (frame as u64 + 1),
            rtp(
                payload_type,
                100 + frame as u16,
                1600 + frame as u32 * clock_step,
                0x1111_1111,
                payload,
            ),
        );
        let mut counts: HashMap<u64, usize> = HashMap::new();
        for (endpoint, datagram) in fan_out(room, &packet) {
            let (_, _, sequence, timestamp, _, payload) = parsed(&datagram);
            heard
                .entry(endpoint)
                .or_default()
                .push((sequence, timestamp, payload));
            *counts.entry(endpoint).or_default() += 1;
        }
        per_ingest.push(counts);
    }
    for listener in listeners {
        heard.entry(*listener).or_default();
    }
    (heard, per_ingest)
}

fn is_continuous(heard: &Heard, clock_step: u32) -> bool {
    heard.windows(2).all(|pair| {
        pair[1].0 == pair[0].0.wrapping_add(1) && pair[1].1.wrapping_sub(pair[0].1) == clock_step
    })
}

/// RMS of each payload decoded in turn by one decoder, so a stateful codec is followed.
fn rms_per_frame(spec: &CodecSpec, payloads: &[&Vec<u8>]) -> Vec<f64> {
    let mut decoder = factory::decoder_for(spec).unwrap();
    let mut pcm = vec![0i16; 11_520];
    payloads
        .iter()
        .map(|payload| {
            let values = decoder.decode(payload, &mut pcm).unwrap();
            let energy: f64 = pcm[..values].iter().map(|&s| f64::from(s).powi(2)).sum();
            (energy / values as f64).sqrt()
        })
        .collect()
}

/// A PCMU room with the source on seat 1 (endpoint 1), a PCMA seat (2), an Opus seat (3) and a PCMU
/// seat (4).
fn room_with_listeners() -> ForwardRoom {
    let mut room = pcmu_room();
    add_same(&mut room, config_for(1, 0));
    add_cross(&mut room, config_for(2, 8), &pcma());
    add_cross(&mut room, config_for(3, 111), &opus());
    add_same(&mut room, config_for(4, 0));
    room.set_source(Some("seat-1")).unwrap();
    room
}

#[test]
fn a_lost_source_packet_is_concealed_for_each_cross_codec_seat() {
    let mut room = room_with_listeners();
    let stream = tone_stream(&pcmu(), 12);
    let (heard, per_ingest) = run(&mut room, 1, 0, &stream, 160, &[5], &[2, 3, 4]);

    // 11 packets arrived; the PCMA and Opus seats were sent 12 each, with no hole.
    assert_eq!(heard[&2].len(), 12);
    assert_eq!(heard[&3].len(), 12);
    assert!(
        is_continuous(&heard[&2], 160),
        "PCMA seat: {:?}",
        heard[&2].iter().map(|h| (h.0, h.1)).collect::<Vec<_>>()
    );
    assert!(
        is_continuous(&heard[&3], 960),
        "Opus seat on its 48 kHz clock"
    );
    // The ingest after the loss produced the concealed frame and the packet for those two seats.
    let after_loss = &per_ingest[5];
    assert_eq!((after_loss[&2], after_loss[&3]), (2, 2));

    // The PCMU seat is sent the originals: one packet, with the hole visible in its sequence.
    assert_eq!(after_loss[&4], 1);
    assert_eq!(heard[&4].len(), 11);
    assert_eq!(heard[&4][5].0, heard[&4][4].0.wrapping_add(2));
    assert_eq!(heard[&4][5].2, stream[6], "bytes as they came");

    // The concealed frame is audio, not silence: G.711 Appendix I continued the tone.
    let original = decoded_rms(&pcmu(), std::slice::from_ref(&stream[4]));
    let concealed = decoded_rms(&pcma(), std::slice::from_ref(&heard[&2][5].2));
    assert!(
        concealed > 0.6 * original,
        "concealed {concealed:.0} against a tone of {original:.0}"
    );
    let payloads: Vec<&Vec<u8>> = heard[&3].iter().map(|h| &h.2).collect();
    let opus_levels = rms_per_frame(&opus(), &payloads);
    assert!(
        opus_levels[5] > 1000.0,
        "the Opus seat decodes the concealed slot to audio: {opus_levels:?}"
    );

    let stats = room.transcode_stats();
    assert_eq!(stats.concealed, 1);
    assert_eq!(stats.conceal_failed, 0);
    assert_eq!(stats.dropped, 0);
}

#[test]
fn a_gap_of_a_hundred_and_twenty_milliseconds_is_concealed_and_a_longer_one_is_not() {
    let stream = tone_stream(&pcmu(), 24);

    let mut room = room_with_listeners();
    let (heard, _) = run(&mut room, 1, 0, &stream, 160, &[5, 6, 7, 8, 9, 10], &[]);
    assert_eq!(room.transcode_stats().concealed, 6, "6 x 20 ms = 120 ms");
    assert!(
        is_continuous(&heard[&2], 160),
        "all six lost frames are filled"
    );
    assert_eq!(heard[&2].len(), 24);

    let mut room = room_with_listeners();
    let (heard, per_ingest) = run(&mut room, 1, 0, &stream, 160, &[5, 6, 7, 8, 9, 10, 11], &[]);
    assert_eq!(room.transcode_stats().concealed, 0, "140 ms is left a gap");
    assert_eq!(per_ingest[5][&2], 1, "no fill, just the packet");
    assert_eq!(heard[&2].len(), 17);
    assert_eq!(heard[&2][5].0, heard[&2][4].0.wrapping_add(8));
    assert_eq!(
        heard[&2][5].1.wrapping_sub(heard[&2][4].1),
        8 * 160,
        "the receiver sees the gap in time too"
    );
}

#[test]
fn a_two_hundred_millisecond_gap_is_not_filled() {
    let mut room = room_with_listeners();
    let stream = tone_stream(&pcmu(), 24);
    let lost: Vec<usize> = (5..15).collect();
    let (heard, per_ingest) = run(&mut room, 1, 0, &stream, 160, &lost, &[]);
    assert_eq!(per_ingest[5][&2], 1);
    assert_eq!(per_ingest[5][&3], 1);
    assert_eq!(per_ingest[5][&4], 1);
    assert_eq!(heard[&2].len(), 14, "14 packets arrived, 14 were sent");
    assert_eq!(room.transcode_stats().concealed, 0);
    // The run carries on: the next packets are in step again.
    assert!(is_continuous(&heard[&2][5..].to_vec(), 160));
}

#[test]
fn a_late_or_duplicate_packet_is_not_concealed_around() {
    let mut room = room_with_listeners();
    let stream = tone_stream(&pcmu(), 8);
    run(&mut room, 1, 0, &stream, 160, &[], &[]);
    let concealed_before = room.transcode_stats().concealed;
    // Frame 3 again, long after: a duplicate of a packet already taken in.
    let again = rx(
        1,
        500_000,
        rtp(0, 103, 1600 + 3 * 160, 0x1111_1111, &stream[3]),
    );
    fan_out(&mut room, &again);
    assert_eq!(room.transcode_stats().concealed, concealed_before);
    // The expectation did not move back: the next real packet is not a gap either.
    let next = rx(
        1,
        520_000,
        rtp(0, 108, 1600 + 8 * 160, 0x1111_1111, &stream[3]),
    );
    fan_out(&mut room, &next);
    assert_eq!(room.transcode_stats().concealed, concealed_before);
}

/// An RTP packet with the marker bit set.
fn marked(sequence: u16, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let header = RtpHeader {
        marker: true,
        payload_type: 0,
        sequence,
        timestamp,
        ssrc: 0x1111_1111,
    };
    let mut buffer = vec![0u8; 12 + payload.len()];
    write_packet(&header, payload, &mut buffer).unwrap();
    buffer
}

#[test]
fn a_talk_spurt_start_and_a_silence_gap_are_not_loss() {
    let stream = tone_stream(&pcmu(), 8);
    // RFC 3551 §4.1: the marker bit starts a talk spurt after silence, so the numbers before it
    // say nothing about loss.
    let mut room = room_with_listeners();
    run(&mut room, 1, 0, &stream[..3], 160, &[], &[]);
    let spurt = rx(1, 200_000, marked(103 + 2, 1600 + 5 * 160, &stream[5]));
    fan_out(&mut room, &spurt);
    assert_eq!(room.transcode_stats().concealed, 0, "marker bit set");

    // Silence suppression with no marker: the sequence jumped by 3 but the clock by 10 frames.
    let mut room = room_with_listeners();
    run(&mut room, 1, 0, &stream[..3], 160, &[], &[]);
    let resumed = rx(
        1,
        200_000,
        rtp(0, 105, 1600 + 12 * 160, 0x1111_1111, &stream[5]),
    );
    fan_out(&mut room, &resumed);
    assert_eq!(
        room.transcode_stats().concealed,
        0,
        "the timestamps do not account for the missing sequence numbers"
    );
}

#[test]
fn a_cross_codec_source_loss_is_concealed_for_the_room_codec_and_other_groups_but_not_its_own() {
    let mut room = pcmu_room();
    add_same(&mut room, config_for(1, 0)); // endpoint 1: room codec
    add_cross(&mut room, config_for(2, 8), &pcma()); // endpoint 2: the source
    add_cross(&mut room, config_for(3, 8), &pcma()); // endpoint 3: the source's group mate
    add_cross(&mut room, config_for(4, 111), &opus()); // endpoint 4: another group
    room.set_source(Some("seat-2")).unwrap();
    let stream = tone_stream(&pcma(), 12);
    let (heard, per_ingest) = run(&mut room, 2, 8, &stream, 160, &[5], &[]);

    assert_eq!(
        heard[&1].len(),
        12,
        "the room-codec seat hears the repaired stream"
    );
    assert!(is_continuous(&heard[&1], 160));
    assert_eq!(heard[&4].len(), 12);
    assert!(is_continuous(&heard[&4], 960));
    // The mate gets the packets as they came, so its own decoder deals with the hole.
    assert_eq!(per_ingest[5][&3], 1);
    assert_eq!(heard[&3].len(), 11);
    assert_eq!(heard[&3][5].0, heard[&3][4].0.wrapping_add(2));
    assert_eq!(room.transcode_stats().concealed, 1);

    // The packets after the loss are intact: decoding them in order after the fill follows the tone.
    let original = decoded_rms(&pcma(), std::slice::from_ref(&stream[4]));
    let payloads: Vec<&Vec<u8>> = heard[&1].iter().map(|h| &h.2).collect();
    let levels = rms_per_frame(&pcmu(), &payloads);
    assert!(
        levels[5] > 0.6 * original && levels[6] > 0.6 * original,
        "{levels:?}"
    );
}

#[cfg(feature = "amr")]
#[test]
fn an_amr_wb_room_conceals_a_lost_packet_for_an_opus_and_a_g711_seat() {
    let mut room = amr_wb_room();
    add_same(&mut room, seat_config(1));
    let mut opus_seat = seat_config(2);
    opus_seat.audio_payload_type = 111;
    add_cross(&mut room, opus_seat, &opus());
    let mut g711_seat = seat_config(3);
    g711_seat.audio_payload_type = 8;
    add_cross(&mut room, g711_seat, &pcma());
    add_same(&mut room, seat_config(4));
    room.set_source(Some("seat-1")).unwrap();
    let spec =
        CodecSpec::new(96, "AMR-WB", 16_000, 1, 20).with_amr_params(Some(factory::AmrParams {
            octet_align: Some(true),
            ..Default::default()
        }));
    let stream = tone_stream(&spec, 14);
    let (heard, per_ingest) = run(&mut room, 1, 96, &stream, 320, &[7], &[]);

    assert!(is_continuous(&heard[&2], 960), "Opus seat has no hole");
    assert!(is_continuous(&heard[&3], 160), "G.711 seat has no hole");
    assert_eq!(heard[&2].len(), 14);
    assert_eq!(heard[&3].len(), 14);
    assert_eq!(per_ingest[7][&2], 2);
    assert_eq!(per_ingest[7][&3], 2);
    assert_eq!(
        per_ingest[7][&4], 1,
        "the AMR-WB seat is sent the original only"
    );
    assert_eq!(heard[&4][7].0, heard[&4][6].0.wrapping_add(2));

    let payloads: Vec<&Vec<u8>> = heard[&2].iter().map(|h| &h.2).collect();
    let levels = rms_per_frame(&opus(), &payloads);
    assert!(
        levels[7] > 1000.0,
        "AMR-WB concealment is audio at the Opus seat: {levels:?}"
    );
    let concealed = decoded_rms(&pcma(), std::slice::from_ref(&heard[&3][7].2));
    assert!(concealed > 1000.0, "and at the G.711 seat: {concealed:.0}");
    assert_eq!(room.transcode_stats().concealed, 1);
}
