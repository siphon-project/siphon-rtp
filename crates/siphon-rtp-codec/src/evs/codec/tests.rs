use super::*;
use crate::evs_fmtp::EvsBandwidth;
use crate::factory::{decoder_for, encoder_for, CodecSpec};

fn spec(fmtp: &str, ptime_ms: u8) -> CodecSpec {
    CodecSpec::new(96, "EVS", 16_000, 1, ptime_ms)
        .with_evs_params(Some(EvsParams::parse(fmtp).expect("fmtp")))
}

/// A header-full payload of `frames` 13.2 kbit/s frames, pseudo-random bits.
fn frames_13k2(frames: usize, seed: u32) -> Vec<u8> {
    let mut payload: Vec<u8> = (0..frames)
        .map(|index| 0x04 | if index + 1 < frames { 0x40 } else { 0 })
        .collect();
    let mut state = seed;
    for _ in 0..frames * 33 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        payload.push((state >> 24) as u8);
    }
    payload
}

#[test]
fn the_output_rate_follows_the_widest_bandwidth_the_peer_may_send() {
    for (fmtp, rate) in [
        ("", 48_000),
        ("bw=nb", 8_000),
        ("bw=nb-wb", 16_000),
        ("bw=nb-swb", 32_000),
        ("bw=wb;bw-send=nb-fb", 48_000),
        ("bw-send=wb;bw-recv=fb", 16_000),
    ] {
        let decoder =
            EvsRtpDecoder::negotiated(&EvsParams::parse(fmtp).expect("fmtp"), 20).expect(fmtp);
        assert_eq!(decoder.params().sample_rate_hz, rate, "{fmtp}");
        assert_eq!(decoder.params().channels, 1);
        assert_eq!(decoder.frame_samples(), rate as usize / 50, "{fmtp}");
        // the RTP clock is 16 kHz whatever the output rate (TS 26.445 A.3)
        assert_eq!(decoder.rtp_clock_rate_hz(), 16_000, "{fmtp}");
    }
    assert_eq!(EvsBandwidth::Wideband.sample_rate_hz(), 16_000);
}

#[test]
fn the_packetization_is_a_whole_number_of_20_ms_frames() {
    for (ptime, frames) in [
        (0, 1),
        (10, 1),
        (20, 1),
        (30, 1),
        (40, 2),
        (60, 3),
        (250, 12),
    ] {
        let decoder = EvsRtpDecoder::negotiated(&EvsParams::parse("bw=wb").expect("fmtp"), ptime)
            .expect("decoder");
        assert_eq!(decoder.frame_samples(), frames * 320, "ptime {ptime}");
        assert_eq!(
            usize::from(decoder.params().ptime_ms),
            frames * 20,
            "ptime {ptime}"
        );
    }
}

#[test]
fn a_parameter_the_registration_does_not_permit_is_refused_at_build() {
    let malformed = EvsParams {
        malformed: true,
        ..EvsParams::default()
    };
    assert!(matches!(
        EvsRtpDecoder::negotiated(&malformed, 20),
        Err(CodecError::Unsupported(_))
    ));
    let spec = CodecSpec::new(96, "EVS", 16_000, 1, 20).with_evs_params(Some(malformed));
    assert!(matches!(
        decoder_for(&spec),
        Err(CodecError::Unsupported(_))
    ));
}

#[test]
fn the_factory_refuses_an_evs_clock_other_than_16_khz_and_more_than_one_channel() {
    for (clock, channels) in [(8_000, 1), (48_000, 1), (16_000, 2)] {
        let spec = CodecSpec::new(96, "EVS", clock, channels, 20);
        assert!(spec.evs_unsupported().is_some(), "{clock}/{channels}");
        assert!(
            matches!(decoder_for(&spec), Err(CodecError::Unsupported(_))),
            "{clock}/{channels}"
        );
    }
}

#[test]
fn the_factory_builds_a_decoder_and_refuses_an_encoder_with_a_reason() {
    let spec = spec("bw=nb-wb;br=5.9-24.4", 20);
    let decoder = decoder_for(&spec).expect("EVS decodes");
    assert_eq!(decoder.params().sample_rate_hz, 16_000);
    match encoder_for(&spec) {
        Err(CodecError::Unsupported(reason)) => {
            assert!(reason.contains("no EVS encoder"), "{reason}");
            assert!(reason.contains("passthrough/relay"), "{reason}");
        }
        other => panic!("EVS must have no encoder: {:?}", other.err()),
    }
    assert!(
        !crate::factory::available_codecs().contains(&"EVS"),
        "a decode-only codec is not advertised"
    );
}

#[test]
fn a_header_full_payload_decodes_every_frame_it_carries() {
    let mut decoder = decoder_for(&spec("bw=wb;hf-only=1", 40)).expect("decoder");
    let mut out = vec![0i16; 640];
    let written = decoder
        .decode(&frames_13k2(2, 1), &mut out)
        .expect("two frames");
    assert_eq!(written, 640);
    let mut one = vec![0i16; 320];
    assert_eq!(
        decoder
            .decode(&frames_13k2(1, 2), &mut one)
            .expect("one frame"),
        320
    );
}

#[test]
fn the_compact_format_decodes_unless_hf_only_forbids_it() {
    let compact: Vec<u8> = (0..33u32)
        .map(|index| (index * 29 + 7) as u8 & 0x7F)
        .collect();
    let mut default = decoder_for(&spec("bw=wb", 20)).expect("decoder");
    let mut out = vec![0i16; 320];
    assert_eq!(
        default.decode(&compact, &mut out),
        Ok(320),
        "33 octets is a compact 13.2 kbit/s frame"
    );
    // with hf-only=1 the same octets are a table-of-contents entry (here 0x1E, a reserved 13 +
    // unused bit set) and are refused rather than read as the other format
    let mut forced = decoder_for(&spec("bw=wb;hf-only=1", 20)).expect("decoder");
    let mut header = compact.clone();
    header[0] = 0x0D;
    assert!(matches!(
        forced.decode(&header, &mut out),
        Err(CodecError::Malformed(_))
    ));
}

#[test]
fn what_is_not_an_evs_payload_is_an_error_and_leaves_the_decoder_usable() {
    let mut decoder = decoder_for(&spec("bw=wb", 20)).expect("decoder");
    let mut out = vec![0i16; 320];
    for bad in [
        &[][..],
        &[0xFF][..],
        &[0x4F][..],
        &[0x0D, 0, 0][..],
        &[0x04, 1, 2][..],
    ] {
        assert!(
            matches!(decoder.decode(bad, &mut out), Err(CodecError::Malformed(_))),
            "{bad:02x?}"
        );
    }
    assert_eq!(decoder.decode(&frames_13k2(1, 3), &mut out), Ok(320));
    // and a payload of more frames than the buffer holds is refused, not truncated
    let mut small = vec![0i16; 320];
    assert_eq!(
        decoder.decode(&frames_13k2(2, 4), &mut small),
        Err(CodecError::OutputTooSmall {
            needed: 640,
            have: 320
        })
    );
}

#[test]
fn a_lost_packet_is_concealed_to_the_packetization_interval() {
    let mut decoder = decoder_for(&spec("bw=wb", 40)).expect("decoder");
    let mut out = vec![0i16; 640];
    // concealing before anything was received is a frame of silence-ish audio, not an error
    assert_eq!(decoder.conceal(&mut out), Ok(640));
    for seed in 0..4 {
        assert_eq!(decoder.decode(&frames_13k2(2, seed), &mut out), Ok(640));
    }
    assert_eq!(decoder.conceal(&mut out), Ok(640));
    assert!(
        out.iter().any(|&sample| sample != 0),
        "speech is concealed by continuing it, faded"
    );
    let mut small = vec![0i16; 100];
    assert_eq!(
        decoder.conceal(&mut small),
        Err(CodecError::OutputTooSmall {
            needed: 640,
            have: 100
        })
    );
}

#[test]
fn the_codec_mode_request_of_the_last_payload_is_kept() {
    let mut decoder =
        EvsRtpDecoder::negotiated(&EvsParams::parse("bw=wb;hf-only=1").expect("fmtp"), 20)
            .expect("decoder");
    let mut out = vec![0i16; 320];
    assert_eq!(decoder.last_cmr(), None);
    let mut payload = vec![0xA4];
    payload.extend(frames_13k2(1, 5));
    payload.push(0);
    decoder.decode(&payload, &mut out).expect("with a CMR");
    assert!(matches!(decoder.last_cmr(), Some(Cmr::Primary { .. })));
    decoder
        .decode(&frames_13k2(1, 6), &mut out)
        .expect("without");
    assert_eq!(
        decoder.last_cmr(),
        None,
        "a payload with no CMR withdraws the request"
    );
}

#[test]
fn silence_and_missing_frames_keep_comfort_noise_going() {
    // speech, then a SID, then NO_DATA frames: the decoder is in a silence period and answers each
    // with audio rather than an error
    let mut decoder = decoder_for(&spec("bw=wb;hf-only=1", 20)).expect("decoder");
    let mut out = vec![0i16; 320];
    for seed in 0..3 {
        decoder
            .decode(&frames_13k2(1, seed), &mut out)
            .expect("speech");
    }
    let mut sid = vec![0x0C];
    sid.extend([0x40, 0x01, 0x02, 0x03, 0x04, 0x05]);
    assert_eq!(decoder.decode(&sid, &mut out), Ok(320));
    for _ in 0..4 {
        assert_eq!(decoder.decode(&[0x0F], &mut out), Ok(320));
    }
    assert_eq!(decoder.decode(&[0x0E], &mut out), Ok(320), "SPEECH_LOST");
}

#[test]
fn every_frame_of_the_reference_storage_set_decodes() {
    let mut decoder = decoder_for(&spec("hf-only=1", 20)).expect("decoder");
    let mut out = vec![0i16; 960];
    let mut decoded = 0;
    for line in include_str!("../../../tests/evs_rtp_kat/frames.txt").lines() {
        let storage: Vec<u8> = line
            .split('|')
            .nth(5)
            .map(|hex| {
                (0..hex.len() / 2)
                    .filter_map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok())
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(decoder.decode(&storage, &mut out), Ok(960), "{line}");
        decoded += 1;
    }
    assert!(decoded >= 60);
}
