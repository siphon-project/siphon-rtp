//! Cross-codec seats in a forwarding room: the source's audio is decoded once per inbound packet,
//! encoded once per codec group and handed to every seat in that group on its own stream.

use super::*;
use siphon_rtp_codec::factory::{self, CodecSpec};

/// 8 kHz, 20 ms.
const PCMU_FRAME: usize = 160;

fn pcmu() -> CodecSpec {
    CodecSpec::new(0, "PCMU", 8000, 1, 20)
}

fn pcma() -> CodecSpec {
    CodecSpec::new(8, "PCMA", 8000, 1, 20)
}

fn g722() -> CodecSpec {
    CodecSpec::new(9, "G722", 8000, 1, 20)
}

fn opus() -> CodecSpec {
    CodecSpec::new(111, "opus", 48_000, 2, 20)
}

/// A room whose codec is PCMU (always built, so these tests need no codec feature).
fn pcmu_room() -> ForwardRoom {
    let text = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                m=audio 4000 RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\n";
    let offered = sdp::parse(text).unwrap().audio_codecs();
    let (codec, _) = RoomCodec::from_offer(&offered).unwrap();
    ForwardRoom::new("group-1".to_string(), codec)
}

fn config_for(index: u8, payload_type: u8) -> ForwardSeatConfig {
    ForwardSeatConfig {
        audio_payload_type: payload_type,
        ..seat_config(index)
    }
}

fn with_events(mut config: ForwardSeatConfig, payload_type: u8, rate: u32) -> ForwardSeatConfig {
    config.telephone_event = Some(TelephoneEvent {
        payload_type,
        clock_rate_hz: rate,
    });
    config
}

fn add_same(room: &mut ForwardRoom, config: ForwardSeatConfig) {
    room.add_seat(config, 0).unwrap();
}

fn add_cross(room: &mut ForwardRoom, config: ForwardSeatConfig, spec: &CodecSpec) {
    let mut spec = spec.clone();
    spec.payload_type = config.audio_payload_type;
    room.add_cross_codec_seat(config, spec, 0).unwrap();
}

/// One 20 ms frame of a 440 Hz tone at `rate`, encoded as `spec`.
fn tone_payload(spec: &CodecSpec, frame_index: usize) -> Vec<u8> {
    let mut encoder = factory::encoder_for(spec).unwrap();
    let rate = encoder.params().sample_rate_hz as usize;
    let frame = rate / 50;
    let mut out = vec![0u8; 1500];
    // Warm the encoder over a few frames so a stateful codec is producing speech, not onset.
    let mut length = 0;
    for step in 0..=frame_index.max(3) {
        let pcm: Vec<i16> = (0..frame)
            .map(|n| {
                let t = (step * frame + n) as f64 / rate as f64;
                ((t * 440.0 * std::f64::consts::TAU).sin() * 8000.0) as i16
            })
            .collect();
        length = encoder.encode(&pcm, &mut out).unwrap();
    }
    out.truncate(length);
    out
}

/// `frames` consecutive 20 ms frames of the same tone through one encoder, so the stream is
/// continuous the way a talker's is.
fn tone_stream(spec: &CodecSpec, frames: usize) -> Vec<Vec<u8>> {
    let mut encoder = factory::encoder_for(spec).unwrap();
    let rate = encoder.params().sample_rate_hz as usize;
    let frame = rate / 50;
    let mut out = vec![0u8; 1500];
    (0..frames)
        .map(|step| {
            let pcm: Vec<i16> = (0..frame)
                .map(|n| {
                    let t = (step * frame + n) as f64 / rate as f64;
                    ((t * 440.0 * std::f64::consts::TAU).sin() * 8000.0) as i16
                })
                .collect();
            let length = encoder.encode(&pcm, &mut out).unwrap();
            out[..length].to_vec()
        })
        .collect()
}

/// RMS of `payloads` decoded as `spec` by one decoder.
fn decoded_rms(spec: &CodecSpec, payloads: &[Vec<u8>]) -> f64 {
    decoded_rms_after(spec, payloads, 0)
}

/// RMS of what `payloads` decode to as `spec` by one decoder, leaving out the first `skip` frames
/// (they still go through the decoder, so it is warm).
fn decoded_rms_after(spec: &CodecSpec, payloads: &[Vec<u8>], skip: usize) -> f64 {
    let mut decoder = factory::decoder_for(spec).unwrap();
    let mut pcm = vec![0i16; 11_520];
    let mut energy = 0f64;
    let mut count = 0usize;
    for (index, payload) in payloads.iter().enumerate() {
        let values = decoder.decode(payload, &mut pcm).unwrap();
        if index < skip {
            continue;
        }
        for sample in &pcm[..values] {
            energy += f64::from(*sample) * f64::from(*sample);
        }
        count += values;
    }
    (energy / count as f64).sqrt()
}

/// Ingest `packet` and return `(endpoint, datagram)` per receiver.
fn fan_out(room: &mut ForwardRoom, packet: &RxPacket) -> Vec<(u64, Vec<u8>)> {
    room.ingest(packet);
    forwarded(room, packet)
        .into_iter()
        .map(|(endpoint, _, data)| (endpoint.0, data))
        .collect()
}

fn datagram_for(sent: &[(u64, Vec<u8>)], endpoint: u64) -> &[u8] {
    &sent
        .iter()
        .find(|(candidate, _)| *candidate == endpoint)
        .unwrap_or_else(|| panic!("nothing was sent to endpoint {endpoint}"))
        .1
}

#[test]
fn a_pcma_seat_hears_a_pcmu_source_decoded_and_re_encoded_while_a_pcmu_seat_hears_it_untouched() {
    let mut room = pcmu_room();
    add_same(&mut room, config_for(1, 0));
    add_same(&mut room, config_for(2, 0));
    add_cross(&mut room, config_for(3, 8), &pcma());
    room.set_source(Some("seat-1")).unwrap();

    let payload = tone_payload(&pcmu(), 0);
    let packet = rx(1, 20_000, rtp(0, 10, 1600, 0x1111_1111, &payload));
    let sent = fan_out(&mut room, &packet);
    assert_eq!(sent.len(), 2);

    let (marker, payload_type, _, _, ssrc, same) = parsed(datagram_for(&sent, 2));
    assert_eq!(
        same, payload,
        "a same-codec seat still gets the bytes as they came"
    );
    assert_eq!((payload_type, ssrc, marker), (0, 0xE000_0002, true));

    let (marker, payload_type, _, _, ssrc, transcoded) = parsed(datagram_for(&sent, 3));
    assert_eq!(payload_type, 8, "the seat's own payload type");
    assert_eq!(ssrc, 0xE000_0003, "the seat's own stream");
    assert!(marker);
    assert_eq!(transcoded.len(), PCMU_FRAME, "one PCMA frame");
    assert_ne!(transcoded, payload, "A-law bytes differ from mu-law bytes");
    let original = decoded_rms(&pcmu(), &[payload]);
    let heard = decoded_rms(&pcma(), &[transcoded]);
    assert!(original > 3000.0, "the fixture is a loud tone: {original}");
    assert!(
        (heard - original).abs() / original < 0.05,
        "the tone survives the transcode: {original} vs {heard}"
    );
}

#[test]
fn the_source_is_decoded_once_and_encoded_once_per_codec_group() {
    let mut room = pcmu_room();
    add_same(&mut room, config_for(1, 0));
    for index in 2..=4 {
        add_cross(&mut room, config_for(index, 8), &pcma());
    }
    for index in 5..=6 {
        add_cross(&mut room, config_for(index, 111), &opus());
    }
    room.set_source(Some("seat-1")).unwrap();
    let payload = tone_payload(&pcmu(), 0);
    let packet = rx(1, 20_000, rtp(0, 10, 1600, 0x1111_1111, &payload));
    let sent = fan_out(&mut room, &packet);
    assert_eq!(sent.len(), 5);
    let stats = room.transcode_stats();
    assert_eq!(stats.decodes, 1, "one decode for the whole room");
    assert_eq!(
        stats.encodes, 2,
        "one encode each for the PCMA and Opus groups"
    );
    // Seats of one group receive the very same payload.
    let (_, _, _, _, _, first) = parsed(datagram_for(&sent, 2));
    for endpoint in [3, 4] {
        assert_eq!(parsed(datagram_for(&sent, endpoint)).5, first);
    }
    let (_, _, _, _, _, first_opus) = parsed(datagram_for(&sent, 5));
    assert_eq!(parsed(datagram_for(&sent, 6)).5, first_opus);
    assert_ne!(first_opus, first);
}

#[test]
fn nothing_is_decoded_when_no_cross_codec_seat_can_be_reached() {
    let mut room = pcmu_room();
    add_same(&mut room, config_for(1, 0));
    add_same(&mut room, config_for(2, 0));
    let mut unreachable = config_for(3, 8);
    unreachable.ice_pending = true;
    add_cross(&mut room, unreachable, &pcma());
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx(1, 0, rtp(0, 1, 160, 5, &tone_payload(&pcmu(), 0)));
    assert_eq!(fan_out(&mut room, &packet).len(), 1);
    assert_eq!(room.transcode_stats().decodes, 0);
    assert_eq!(room.transcode_stats().encodes, 0);
}

#[test]
fn each_cross_codec_seat_runs_on_its_own_clock_with_continuous_sequence_numbers() {
    let mut room = pcmu_room();
    add_same(&mut room, config_for(1, 0));
    add_cross(&mut room, config_for(2, 8), &pcma());
    add_cross(&mut room, config_for(3, 9), &g722());
    add_cross(&mut room, config_for(4, 111), &opus());
    room.set_source(Some("seat-1")).unwrap();
    let payload = tone_payload(&pcmu(), 0);
    let mut previous: HashMap<u64, (u16, u32)> = HashMap::new();
    for frame in 0..5u32 {
        let packet = rx(
            1,
            20_000 * u64::from(frame + 1),
            rtp(
                0,
                100 + frame as u16,
                1600 + frame * 160,
                0x1111_1111,
                &payload,
            ),
        );
        let sent = fan_out(&mut room, &packet);
        assert_eq!(sent.len(), 3);
        for (endpoint, datagram) in sent {
            let (marker, _, sequence, timestamp, _, _) = parsed(&datagram);
            assert_eq!(marker, frame == 0, "endpoint {endpoint} frame {frame}");
            if let Some((last_sequence, last_timestamp)) = previous.get(&endpoint) {
                assert_eq!(sequence, last_sequence.wrapping_add(1));
                // 20 ms in each receiver's own RTP clock: PCMA 8 kHz, G.722 8 kHz (RFC 3551
                // §4.5.2), Opus 48 kHz.
                let expected = if endpoint == 4 { 960 } else { 160 };
                assert_eq!(
                    timestamp.wrapping_sub(*last_timestamp),
                    expected,
                    "endpoint {endpoint}"
                );
            }
            previous.insert(endpoint, (sequence, timestamp));
        }
    }
}

#[test]
fn a_source_change_starts_a_new_run_for_every_cross_codec_receiver_without_a_gap() {
    let mut room = pcmu_room();
    add_same(&mut room, config_for(1, 0));
    add_same(&mut room, config_for(2, 0));
    add_cross(&mut room, config_for(3, 8), &pcma());
    let payload = tone_payload(&pcmu(), 0);
    let mut heard: Vec<(bool, u16, u32)> = Vec::new();
    let script: [(u8, &str, u32); 3] = [
        (1, "seat-1", 0x1111_1111),
        (2, "seat-2", 0x2222_2222),
        (1, "seat-1", 0x1111_1111),
    ];
    let mut clock = 0u64;
    let mut sequence = 50u16;
    for (talker, tag, ssrc) in script {
        room.set_source(Some(tag)).unwrap();
        for _ in 0..3 {
            clock += 20_000;
            sequence = sequence.wrapping_add(1);
            let packet = rx(
                talker,
                clock,
                rtp(0, sequence, sequence as u32 * 160, ssrc, &payload),
            );
            let sent = fan_out(&mut room, &packet);
            let (marker, _, seq, ts, ssrc_out, _) = parsed(datagram_for(&sent, 3));
            assert_eq!(ssrc_out, 0xE000_0003, "one stable SSRC across talkers");
            heard.push((marker, seq, ts));
        }
    }
    assert_eq!(
        heard.iter().filter(|(marker, _, _)| *marker).count(),
        3,
        "one marker per talk spurt"
    );
    for pair in heard.windows(2) {
        assert_eq!(pair[1].1, pair[0].1.wrapping_add(1), "sequence never jumps");
        assert!(
            (pair[1].2.wrapping_sub(pair[0].2) as i32) > 0,
            "timestamps strictly advance"
        );
    }
}

#[test]
fn a_cross_codec_source_is_heard_by_the_room_codec_by_its_own_group_and_by_other_groups() {
    let mut room = pcmu_room();
    add_same(&mut room, config_for(1, 0));
    add_cross(&mut room, config_for(2, 8), &pcma());
    add_cross(&mut room, config_for(3, 8), &pcma());
    add_cross(&mut room, config_for(4, 111), &opus());
    room.set_source(Some("seat-2")).unwrap();

    let payload = tone_payload(&pcma(), 0);
    let packet = rx(2, 20_000, rtp(8, 7, 800, 0x2222_2222, &payload));
    let sent = fan_out(&mut room, &packet);
    assert_eq!(sent.len(), 3, "the source never hears itself");

    let (_, payload_type, _, _, _, heard) = parsed(datagram_for(&sent, 1));
    assert_eq!(payload_type, 0);
    assert_eq!(heard.len(), PCMU_FRAME);
    let original = decoded_rms(&pcma(), std::slice::from_ref(&payload));
    let in_room_codec = decoded_rms(&pcmu(), &[heard]);
    assert!((in_room_codec - original).abs() / original < 0.05);

    let (_, payload_type, _, _, _, mate) = parsed(datagram_for(&sent, 3));
    assert_eq!(payload_type, 8);
    assert_eq!(
        mate, payload,
        "a seat in the source's own codec group gets the bytes as they came"
    );

    let (_, payload_type, _, _, _, opus_payload) = parsed(datagram_for(&sent, 4));
    assert_eq!(payload_type, 111);
    let in_opus = decoded_rms(&opus(), &[tone_payload(&opus(), 0), opus_payload]);
    assert!(
        in_opus > 0.5 * original,
        "Opus seat hears the tone: {in_opus}"
    );
}

#[test]
fn an_opus_source_reaches_a_g711_room_as_valid_g711_frames() {
    let mut room = pcmu_room();
    add_same(&mut room, config_for(1, 0));
    add_cross(&mut room, config_for(2, 111), &opus());
    room.set_source(Some("seat-2")).unwrap();
    let stream = tone_stream(&opus(), 10);
    let mut heard = Vec::new();
    for (frame, payload) in stream.iter().enumerate() {
        let packet = rx(
            2,
            20_000 * (frame as u64 + 1),
            rtp(
                111,
                1 + frame as u16,
                frame as u32 * 960,
                0x3333_3333,
                payload,
            ),
        );
        let sent = fan_out(&mut room, &packet);
        let (_, payload_type, _, _, _, payload) = parsed(datagram_for(&sent, 1));
        assert_eq!(payload_type, 0);
        assert_eq!(payload.len(), PCMU_FRAME, "one 20 ms mu-law frame");
        heard.push(payload);
    }
    // The reference is what the Opus seat's own stream decodes to; the first frames are the
    // encoder and the resampler filling.
    let reference = decoded_rms_after(&opus(), &stream, 2);
    let rms = decoded_rms_after(&pcmu(), &heard, 2);
    assert!(
        reference > 3000.0,
        "the fixture is a loud tone: {reference}"
    );
    assert!(
        (rms - reference).abs() / reference < 0.15,
        "the tone survives Opus to G.711: {reference} vs {rms}"
    );
}

#[test]
fn telephone_events_are_rescaled_for_a_receiver_on_another_clock_and_dropped_for_one_without() {
    let mut room = pcmu_room();
    add_same(&mut room, with_events(config_for(1, 0), 101, 8000));
    add_cross(&mut room, with_events(config_for(2, 8), 101, 8000), &pcma());
    add_cross(
        &mut room,
        with_events(config_for(3, 111), 110, 48_000),
        &opus(),
    );
    add_cross(&mut room, config_for(4, 9), &g722());
    room.set_source(Some("seat-1")).unwrap();
    // RFC 4733 §2.3: event 5, end bit clear, volume 10, duration 800 ticks (100 ms at 8 kHz).
    let event = [5u8, 10, 0x03, 0x20];
    let audio = rx(
        1,
        20_000,
        rtp(0, 1, 1000, 0x1111_1111, &tone_payload(&pcmu(), 0)),
    );
    fan_out(&mut room, &audio);
    let packet = rx(1, 40_000, rtp(101, 2, 1160, 0x1111_1111, &event));
    let sent = fan_out(&mut room, &packet);
    assert_eq!(
        sent.len(),
        2,
        "the PCMA and Opus seats negotiated events; the G.722 seat did not"
    );
    let (_, payload_type, _, timestamp_pcma, _, payload) = parsed(datagram_for(&sent, 2));
    assert_eq!((payload_type, payload.as_slice()), (101, &event[..]));
    let (_, payload_type, _, timestamp_opus, _, payload) = parsed(datagram_for(&sent, 3));
    assert_eq!(payload_type, 110, "the seat's own event payload type");
    assert_eq!(
        payload,
        [5, 10, 0x12, 0xC0],
        "duration 800 ticks at 8 kHz is 4800 at 48 kHz"
    );
    let (_, _, _, audio_pcma, _, _) = parsed(datagram_for(
        &fan_out(
            &mut room,
            &rx(
                1,
                60_000,
                rtp(0, 3, 1320, 0x1111_1111, &tone_payload(&pcmu(), 0)),
            ),
        ),
        2,
    ));
    assert_eq!(
        audio_pcma.wrapping_sub(timestamp_pcma),
        160,
        "events and audio share a timeline"
    );
    assert!(timestamp_opus != 0);
}

#[test]
fn a_frame_of_the_wrong_length_is_dropped_for_cross_codec_seats_and_counted() {
    let mut room = pcmu_room();
    add_same(&mut room, config_for(1, 0));
    add_same(&mut room, config_for(2, 0));
    add_cross(&mut room, config_for(3, 8), &pcma());
    room.set_source(Some("seat-1")).unwrap();
    // 30 ms of mu-law where 20 ms was negotiated.
    let packet = rx(1, 0, rtp(0, 1, 160, 5, &[0x55; 240]));
    let sent = fan_out(&mut room, &packet);
    assert_eq!(sent.len(), 1, "only the same-codec seat is sent it");
    assert_eq!(room.transcode_stats().dropped, 1);
    assert_eq!(room.seat_stats("seat-1").unwrap().transcode_dropped, 1);
}

#[test]
fn a_room_without_a_cross_codec_seat_pays_nothing_for_the_feature() {
    let mut room = pcmu_room();
    add_same(&mut room, config_for(1, 0));
    add_same(&mut room, config_for(2, 0));
    room.set_source(Some("seat-1")).unwrap();
    let packet = rx(1, 0, rtp(0, 1, 160, 5, &[0x55; 160]));
    assert_eq!(fan_out(&mut room, &packet).len(), 1);
    assert_eq!(room.transcode_stats(), TranscodeStats::default());
}

#[test]
fn a_seat_that_cannot_be_transcoded_is_refused_with_the_reason() {
    let mut room = pcmu_room();
    // Comfort noise is a companion payload, not a codec a room can decode.
    let comfort_noise = CodecSpec::new(13, "CN", 8000, 1, 20);
    let refusal = room
        .add_cross_codec_seat(config_for(1, 13), comfort_noise, 0)
        .unwrap_err();
    assert!(matches!(refusal, ForwardError::Transcode(_)), "{refusal}");
    assert!(room.is_empty(), "a refused seat leaves nothing behind");
}

#[test]
fn removing_the_cross_codec_source_ends_its_run() {
    let mut room = pcmu_room();
    add_same(&mut room, config_for(1, 0));
    add_cross(&mut room, config_for(2, 8), &pcma());
    room.set_source(Some("seat-2")).unwrap();
    let packet = rx(2, 0, rtp(8, 1, 160, 5, &tone_payload(&pcma(), 0)));
    assert_eq!(fan_out(&mut room, &packet).len(), 1);
    assert!(room.remove_seat("seat-2"));
    assert_eq!(room.source(), None);
    assert!(room.ingest(&packet) == Ingress::Refused);
}

#[test]
fn admission_names_why_each_offered_codec_cannot_be_transcoded() {
    let (room, _) = RoomCodec::from_offer(&[pcmu()]).unwrap();
    let chosen = room.admit_cross(&[opus(), pcma()]).unwrap();
    assert_eq!(chosen.encoding_name, "OPUS", "the offerer's order decides");

    let slow = CodecSpec::new(8, "PCMA", 8000, 1, 30);
    let reason = room.admit_cross(&[slow]).unwrap_err();
    assert!(reason.contains("PCMA/8000 payload type 8"), "{reason}");
    assert!(reason.contains("packetization"), "{reason}");

    let unknown = CodecSpec::new(100, "NOSUCHCODEC", 8000, 1, 20);
    let reason = room.admit_cross(&[unknown]).unwrap_err();
    assert!(reason.contains("NOSUCHCODEC"), "{reason}");
    assert_eq!(
        room.admit_cross(&[]).unwrap_err(),
        "the offer has no audio codec"
    );
}

#[cfg(not(feature = "amr"))]
#[test]
fn without_the_amr_feature_an_amr_seat_is_refused_naming_the_build() {
    let (room, _) = RoomCodec::from_offer(&[pcmu()]).unwrap();
    let amr_wb = CodecSpec::new(96, "AMR-WB", 16_000, 1, 20);
    let reason = room.admit_cross(&[amr_wb]).unwrap_err();
    assert!(reason.contains("AMR"), "{reason}");
    assert!(reason.contains("this build"), "{reason}");
}

#[cfg(not(feature = "amr"))]
#[test]
fn without_the_amr_feature_an_amr_room_still_forwards_but_refuses_other_codecs() {
    let text = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                m=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n";
    let offered = sdp::parse(text).unwrap().audio_codecs();
    let (room, _) = RoomCodec::from_offer(&offered).unwrap();
    let reason = room.admit_cross(&[pcma()]).unwrap_err();
    assert!(reason.contains("AMR"), "{reason}");
    assert!(reason.contains("this build"), "{reason}");
}

#[cfg(feature = "amr")]
#[test]
fn a_pcmu_seat_in_an_amr_wb_room_hears_the_decoded_and_re_encoded_source() {
    let mut room = amr_wb_room();
    add_same(&mut room, seat_config(1));
    let mut seat = seat_config(2);
    seat.audio_payload_type = 0;
    add_cross(&mut room, seat, &pcmu());
    room.set_source(Some("seat-1")).unwrap();
    let mut spec = CodecSpec::new(96, "AMR-WB", 16_000, 1, 20);
    spec = spec.with_amr_params(Some(siphon_rtp_codec::factory::AmrParams {
        octet_align: Some(true),
        ..Default::default()
    }));
    let stream = tone_stream(&spec, 10);
    let mut heard = Vec::new();
    for (frame, payload) in stream.iter().enumerate() {
        let packet = rx(
            1,
            20_000 * (frame as u64 + 1),
            rtp(
                96,
                1 + frame as u16,
                frame as u32 * 320,
                0x1111_1111,
                payload,
            ),
        );
        let sent = fan_out(&mut room, &packet);
        let (_, payload_type, _, _, _, payload) = parsed(datagram_for(&sent, 2));
        assert_eq!(payload_type, 0);
        assert_eq!(payload.len(), PCMU_FRAME);
        heard.push(payload);
    }
    let reference = decoded_rms_after(&spec, &stream, 2);
    let rms = decoded_rms_after(&pcmu(), &heard, 2);
    assert!(
        reference > 3000.0,
        "the fixture is a loud tone: {reference}"
    );
    assert!(
        (rms - reference).abs() / reference < 0.15,
        "the tone survives AMR-WB to G.711: {reference} vs {rms}"
    );
}
