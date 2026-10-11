//! What a negotiated AMR / AMR-WB stream looks like on the wire, through the codec factory.
//!
//! These tests read the engine's payloads with a reader written here from the RFC 4867 §4.3 and
//! §4.4 layouts, not with the crate's own depacketiser: a payload format has an external
//! definition, so a round trip through one implementation proves nothing about it.
//!
//! `cargo test -p siphon-rtp-codec --features amr --test amr_rtp_negotiated_stream`
#![cfg(feature = "amr")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

use siphon_rtp_codec::factory::{decoder_for, encoder_for, AmrParams, CodecSpec};

/// Speech bits per frame type: 3GPP TS 26.101 Table 1a (AMR) and TS 26.201 Table 1a (AMR-WB), the
/// SID frame included. Every other frame type carries no bits.
fn frame_bits(wideband: bool, frame_type: u8) -> usize {
    const NARROWBAND: [usize; 9] = [95, 103, 118, 134, 148, 159, 204, 244, 39];
    const WIDEBAND: [usize; 10] = [132, 177, 253, 285, 317, 365, 397, 461, 477, 40];
    let table: &[usize] = if wideband { &WIDEBAND } else { &NARROWBAND };
    table.get(frame_type as usize).copied().unwrap_or(0)
}

/// One bit of `payload`, most significant bit of each octet first (RFC 4867 §4.3.4).
fn bit(payload: &[u8], index: usize) -> u8 {
    (payload[index / 8] >> (7 - index % 8)) & 1
}

fn field(payload: &[u8], start: usize, width: usize) -> u8 {
    (0..width).fold(0, |value, offset| {
        (value << 1) | bit(payload, start + offset)
    })
}

/// The frames of a payload as a reader written from the RFC finds them: (frame type, the frame's
/// bits left-aligned in octets).
type Frames = Vec<(u8, Vec<u8>)>;

fn frame_types(frames: &Frames) -> Vec<u8> {
    frames.iter().map(|frame| frame.0).collect()
}

/// The frames of a bandwidth-efficient payload (RFC 4867 §4.3: a 4-bit CMR, a 6-bit ToC entry
/// per frame, the frames bit-packed, then zero padding to the octet), or why it is not one.
fn bandwidth_efficient(payload: &[u8], wideband: bool) -> Result<(u8, Frames), String> {
    let total = payload.len() * 8;
    if total < 10 {
        return Err("shorter than a CMR and one ToC entry".into());
    }
    let cmr = field(payload, 0, 4);
    let mut position = 4;
    let mut frame_types = Vec::new();
    loop {
        if position + 6 > total {
            return Err("ToC runs past the payload".into());
        }
        let follow = bit(payload, position);
        frame_types.push(field(payload, position + 1, 4));
        if bit(payload, position + 5) != 1 {
            return Err("Q bit clear".into());
        }
        position += 6;
        if follow == 0 {
            break;
        }
    }
    let needed: usize = frame_types
        .iter()
        .map(|frame_type| frame_bits(wideband, *frame_type))
        .sum();
    if position + needed > total || total - position - needed > 7 {
        return Err(format!("{} bits used of {total}", position + needed));
    }
    let mut frames = Vec::new();
    for frame_type in frame_types {
        let bits = frame_bits(wideband, frame_type);
        let mut data = vec![0u8; bits.div_ceil(8)];
        for index in 0..bits {
            data[index / 8] |= bit(payload, position + index) << (7 - index % 8);
        }
        position += bits;
        frames.push((frame_type, data));
    }
    if (position..total).any(|index| bit(payload, index) != 0) {
        return Err("padding bits set".into());
    }
    Ok((cmr, frames))
}

/// The frames of an octet-aligned payload (RFC 4867 §4.4: a CMR octet with four reserved
/// bits, a ToC octet per frame with two padding bits, each frame padded to the octet).
fn octet_aligned(payload: &[u8], wideband: bool) -> Result<(u8, Frames), String> {
    if payload.len() < 2 || payload[0] & 0x0F != 0 {
        return Err("no CMR octet with clear reserved bits".into());
    }
    let mut position = 1;
    let mut frame_types = Vec::new();
    loop {
        let Some(&toc) = payload.get(position) else {
            return Err("ToC runs past the payload".into());
        };
        position += 1;
        if toc & 0x03 != 0 || toc & 0x04 == 0 {
            return Err("ToC padding set or Q bit clear".into());
        }
        frame_types.push((toc >> 3) & 0x0F);
        if toc & 0x80 == 0 {
            break;
        }
    }
    let mut frames = Vec::new();
    for frame_type in frame_types {
        let octets = frame_bits(wideband, frame_type).div_ceil(8);
        let Some(data) = payload.get(position..position + octets) else {
            return Err("frame runs past the payload".into());
        };
        frames.push((frame_type, data.to_vec()));
        position += octets;
    }
    if position != payload.len() {
        return Err(format!("{position} octets used of {}", payload.len()));
    }
    Ok((payload[0] >> 4, frames))
}

fn tone(samples: usize, rate: f32) -> Vec<i16> {
    (0..samples)
        .map(|index| {
            ((index as f32 * 2.0 * std::f32::consts::PI * 440.0 / rate).sin() * 8000.0) as i16
        })
        .collect()
}

fn spec(wideband: bool) -> CodecSpec {
    if wideband {
        CodecSpec::new(96, "AMR-WB", 16000, 1, 20)
    } else {
        CodecSpec::new(97, "AMR", 8000, 1, 20)
    }
}

fn encode_frames(spec: &CodecSpec, wideband: bool, frames: usize) -> Vec<Vec<u8>> {
    let mut encoder = encoder_for(spec).expect("encoder");
    let frame = encoder.frame_samples();
    let pcm = tone(frame * frames, if wideband { 16000.0 } else { 8000.0 });
    (0..frames)
        .map(|index| {
            let mut payload = [0u8; 256];
            let length = encoder
                .encode(&pcm[index * frame..(index + 1) * frame], &mut payload)
                .expect("encode");
            payload[..length].to_vec()
        })
        .collect()
}

/// RFC 4867 §8.1, `octet-align`: "If 0 or if not present, bandwidth-efficient operation is
/// employed." A stream negotiated with no `a=fmtp` is therefore bandwidth-efficient.
#[test]
fn a_stream_negotiated_without_octet_align_is_sent_bandwidth_efficient() {
    for wideband in [false, true] {
        for payload in encode_frames(&spec(wideband), wideband, 5) {
            let read = bandwidth_efficient(&payload, wideband);
            assert!(
                read.is_ok(),
                "wideband={wideband}: {read:?}; as octet-aligned: {:?}",
                octet_aligned(&payload, wideband)
            );
            assert_eq!(read.expect("read").0, 15, "CMR 15, no mode request");
        }
    }
}

/// RFC 4867 §8.1, `mode-set`: "frames encoded with modes outside of the subset MUST NOT be sent in
/// any RTP payload". 3GPP TS 26.114 §7.5.2.1.2.1: "the highest codec mode of the negotiated
/// mode-set ... should be used, unless it is restricted by the most recently received CMR."
#[test]
fn the_highest_mode_of_the_mode_set_is_sent() {
    for (wideband, mode_set, highest) in [
        (false, vec![0u8, 2], 2u8),
        (false, vec![0, 2, 4, 7], 7),
        (false, vec![0], 0),
        (true, vec![0, 1, 2], 2),
        (true, vec![0, 1], 1),
    ] {
        let spec = spec(wideband).with_allowed_modes(mode_set.clone());
        for payload in encode_frames(&spec, wideband, 5) {
            let (_cmr, frames) =
                bandwidth_efficient(&payload, wideband).expect("bandwidth-efficient payload");
            assert_eq!(frame_types(&frames), vec![highest], "mode-set {mode_set:?}");
        }
    }
}

/// A SID frame (comfort noise) and a NO_DATA frame are part of any stream from a peer that uses
/// discontinuous transmission. Neither is an error: 20 ms of audio comes back for each.
#[test]
fn sid_and_no_data_frames_decode_without_error() {
    // Narrowband, octet-aligned as the fmtp says: CMR 15 | F=0 FT=8 (SID) Q=1 | 39 bits in 5 octets.
    let mut narrowband = decoder_for(&spec(false).with_octet_align()).expect("decoder");
    let mut pcm = [0i16; 160];
    let sid = [0xF0, 0x44, 0x12, 0x34, 0x56, 0x78, 0x90];
    assert_eq!(narrowband.decode(&sid, &mut pcm), Ok(160));
    // CMR 15 | F=0 FT=15 (NO_DATA) Q=1, no frame bits.
    assert_eq!(narrowband.decode(&[0xF0, 0x7C], &mut pcm), Ok(160));

    // Wideband: FT=9 is the SID frame (40 bits), FT=15 NO_DATA.
    let mut wideband = decoder_for(&spec(true).with_octet_align()).expect("decoder");
    let mut pcm = [0i16; 320];
    let sid = [0xF0, 0x4C, 0x12, 0x34, 0x56, 0x78, 0x9A];
    assert_eq!(wideband.decode(&sid, &mut pcm), Ok(320));
    assert_eq!(wideband.decode(&[0xF0, 0x7C], &mut pcm), Ok(320));
}

/// RFC 4867 §4.3.1: the CMR is "a codec mode request sent to the speech encoder at the site of the
/// receiver of this payload", for AMR as for AMR-WB.
#[test]
fn a_narrowband_codec_mode_request_is_surfaced() {
    let mut decoder = decoder_for(&spec(false).with_octet_align()).expect("decoder");
    let mut pcm = [0i16; 160];
    // CMR 2 | F=0 FT=15 Q=1.
    decoder.decode(&[0x20, 0x7C], &mut pcm).expect("decode");
    assert_eq!(decoder.last_mode_request(), Some(2));
}

/// Test-only shorthand for a stream whose fmtp carried `octet-align=1`.
trait OctetAlign {
    fn with_octet_align(self) -> Self;
}

impl OctetAlign for CodecSpec {
    fn with_octet_align(self) -> Self {
        self.with_amr_params(Some(AmrParams {
            octet_align: Some(true),
            ..AmrParams::default()
        }))
    }
}

// ── The stream as an independent decoder hears it ───────────────────────────────────────────────

fn params(octet_align: bool) -> Option<AmrParams> {
    octet_align.then(|| AmrParams {
        octet_align: Some(true),
        ..AmrParams::default()
    })
}

/// Write frames in the storage format of RFC 4867 §5: the magic number, then for each frame one
/// header octet `P FT(4) Q P P` and the frame's bits padded to the octet.
fn storage_file(wideband: bool, frames: &Frames) -> Vec<u8> {
    let mut file: Vec<u8> = if wideband {
        b"#!AMR-WB\n".to_vec()
    } else {
        b"#!AMR\n".to_vec()
    };
    for (frame_type, data) in frames {
        file.push((frame_type << 3) | 0x04);
        file.extend_from_slice(data);
    }
    file
}

/// Decode a storage-format file with ffmpeg's own AMR decoder into 16-bit PCM, or `None` when
/// ffmpeg is not installed.
fn ffmpeg_decode(name: &str, wideband: bool, file: &[u8]) -> Option<Vec<i16>> {
    let available = std::process::Command::new("ffmpeg")
        .arg("-version")
        .output()
        .is_ok_and(|output| output.status.success());
    if !available {
        eprintln!("skipping: ffmpeg not available");
        return None;
    }
    let path = std::env::temp_dir().join(format!(
        "siphon-rtp-amr-{}-{name}.{}",
        std::process::id(),
        if wideband { "awb" } else { "amr" }
    ));
    std::fs::write(&path, file).expect("write storage file");
    let output = std::process::Command::new("ffmpeg")
        .args(["-v", "error", "-nostdin", "-i"])
        .arg(&path)
        .args(["-f", "s16le", "-acodec", "pcm_s16le", "-"])
        .output()
        .expect("run ffmpeg");
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success() && output.stderr.is_empty(),
        "{name}: ffmpeg faulted the stream: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(
        output
            .stdout
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| i16::from_le_bytes(*pair))
            .collect(),
    )
}

/// The pitch of `pcm` by its zero crossings, and its level.
fn pitch_and_rms(pcm: &[i16], rate: f32) -> (f32, f32) {
    let crossings = pcm
        .windows(2)
        .filter(|pair| pair[0] < 0 && pair[1] >= 0)
        .count();
    let energy: f64 = pcm.iter().map(|&sample| f64::from(sample).powi(2)).sum();
    (
        crossings as f32 * rate / pcm.len() as f32,
        (energy / pcm.len() as f64).sqrt() as f32,
    )
}

/// One second of a 440 Hz tone through the encoder, taken out of the RTP payloads by the reader
/// above, written in the storage format, and decoded by ffmpeg: the tone has to come back, in
/// every payload format, mode and packetisation the engine negotiates.
#[test]
fn an_independent_decoder_hears_the_tone_in_every_negotiated_configuration() {
    // (wideband, octet-align, mode-set, ptime, the mode that has to be sent)
    let cases: [(bool, bool, &[u8], u8, u8); 12] = [
        (false, false, &[], 20, 7),
        (false, true, &[], 20, 7),
        (false, false, &[0, 2, 4, 7], 20, 7),
        (false, true, &[0, 2], 20, 2),
        (false, false, &[0], 20, 0),
        (false, false, &[4], 40, 4),
        (true, false, &[], 20, 8),
        (true, true, &[], 20, 8),
        (true, false, &[0, 1, 2], 20, 2),
        (true, true, &[0, 1, 2], 20, 2),
        (true, false, &[0], 20, 0),
        (true, true, &[2], 60, 2),
    ];
    for (wideband, octet_align, mode_set, ptime, mode) in cases {
        let name = format!(
            "{}-{}-set{mode_set:?}-ptime{ptime}",
            if wideband { "wb" } else { "nb" },
            if octet_align { "oa" } else { "be" }
        );
        let mut spec = spec(wideband)
            .with_amr_params(params(octet_align))
            .with_allowed_modes(mode_set.to_vec());
        spec.ptime_ms = ptime;
        let per_packet = usize::from(ptime / 20);
        let packets = encode_frames(&spec, wideband, 50 / per_packet);
        let mut frames = Frames::new();
        for payload in &packets {
            let (cmr, read) = if octet_align {
                octet_aligned(payload, wideband)
            } else {
                bandwidth_efficient(payload, wideband)
            }
            .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(cmr, 15, "{name}");
            assert_eq!(frame_types(&read), vec![mode; per_packet], "{name}");
            frames.extend(read);
        }
        // The crate's own depacketiser takes the same frames out of the same payloads.
        let mut own = Frames::new();
        for payload in &packets {
            let layout = siphon_rtp_codec::amr::rtp::read_payload(
                payload,
                if octet_align {
                    siphon_rtp_codec::amr::PayloadFormat::OctetAligned
                } else {
                    siphon_rtp_codec::amr::PayloadFormat::BandwidthEfficient
                },
                if wideband {
                    siphon_rtp_codec::amr::rtp::Variant::Wideband
                } else {
                    siphon_rtp_codec::amr::rtp::Variant::Narrowband
                },
            )
            .expect("depacketise");
            for slot in layout.frames() {
                let mut data = [0u8; siphon_rtp_codec::amr::rtp::MAX_FRAME_OCTETS];
                let written = slot.copy_bits(payload, &mut data);
                own.push((slot.frame_type, data[..written].to_vec()));
            }
        }
        assert_eq!(own, frames, "{name}: the two readers disagree");

        let Some(pcm) = ffmpeg_decode(&name, wideband, &storage_file(wideband, &own)) else {
            return;
        };
        let rate = if wideband { 16000.0 } else { 8000.0 };
        let expected = frames.len() * if wideband { 320 } else { 160 };
        assert_eq!(pcm.len(), expected, "{name}: 20 ms of audio a frame");
        // The same payloads through the engine's own decoder, which is sample-exact against the
        // 3GPP reference (below). ffmpeg's decoders are floating-point ones of their own and sit a
        // few dB under it on a pure tone, so the level is bounded loosely and both are printed.
        let mut decoder = decoder_for(&spec).expect("decoder");
        let mut own_pcm = Vec::new();
        let mut scratch = vec![0i16; 320 * 4];
        for payload in &packets {
            let samples = decoder.decode(payload, &mut scratch).expect("decode");
            own_pcm.extend_from_slice(&scratch[..samples]);
        }
        assert_eq!(own_pcm.len(), expected, "{name}");
        // Past the codec's start-up: the last 0.6 s.
        let (pitch, rms) = pitch_and_rms(&pcm[pcm.len() * 2 / 5..], rate);
        let (own_pitch, own_rms) = pitch_and_rms(&own_pcm[own_pcm.len() * 2 / 5..], rate);
        eprintln!(
            "FFMPEG {name}: {} frames in {} packets, mode {mode}, {} samples, {pitch:.0} Hz, \
             rms {rms:.0}; own decoder {own_pitch:.0} Hz, rms {own_rms:.0} (sent 440 Hz, rms 5657)",
            frames.len(),
            packets.len(),
            pcm.len()
        );
        assert!((pitch - 440.0).abs() < 440.0 * 0.03, "{name}: {pitch} Hz");
        assert!(
            (own_pitch - 440.0).abs() < 440.0 * 0.03,
            "{name}: {own_pitch} Hz"
        );
        assert!(
            rms > 5657.0 * 0.5 && rms < 5657.0 * 1.2,
            "{name}: rms {rms}"
        );
        assert!(
            own_rms > 5657.0 * 0.7 && own_rms < 5657.0 * 1.2,
            "{name}: rms {own_rms}"
        );
    }
}

// ── The receive direction against the 3GPP reference coder's own bitstreams ────────────────────

/// 16-bit little-endian words of a reference vector file, `None` when the (licensed, untracked)
/// vectors are not in this checkout.
fn reference_words(relative: &str) -> Option<Vec<i16>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../reference")
        .join(relative);
    let Ok(bytes) = std::fs::read(&path) else {
        assert!(
            std::env::var_os("SIPHON_RTP_REQUIRE_VECTORS").is_none(),
            "reference vector {relative} is required and absent"
        );
        eprintln!("skipping: reference vector {relative} absent");
        return None;
    };
    Some(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| i16::from_le_bytes(*pair))
            .collect(),
    )
}

/// Bit-pack frames into a bandwidth-efficient payload, written here from RFC 4867 §4.3.4.
fn pack_bandwidth_efficient(cmr: u8, wideband: bool, frames: &Frames) -> Vec<u8> {
    let mut bits: Vec<u8> = (0..4).rev().map(|shift| (cmr >> shift) & 1).collect();
    for (index, (frame_type, _)) in frames.iter().enumerate() {
        bits.push(u8::from(index + 1 < frames.len()));
        bits.extend((0..4).rev().map(|shift| (frame_type >> shift) & 1));
        bits.push(1);
    }
    for (frame_type, data) in frames {
        bits.extend((0..frame_bits(wideband, *frame_type)).map(|index| bit(data, index)));
    }
    while !bits.len().is_multiple_of(8) {
        bits.push(0);
    }
    bits.chunks(8)
        .map(|octet| octet.iter().fold(0, |value, bit| (value << 1) | bit))
        .collect()
}

/// The same frames as an octet-aligned payload (RFC 4867 §4.4).
fn pack_octet_aligned(cmr: u8, frames: &Frames) -> Vec<u8> {
    let mut payload = vec![cmr << 4];
    for (index, (frame_type, _)) in frames.iter().enumerate() {
        payload.push((u8::from(index + 1 < frames.len()) << 7) | (frame_type << 3) | 0x04);
    }
    for (_, data) in frames {
        payload.extend_from_slice(data);
    }
    payload
}

/// Feed the reference coder's frames to a factory decoder, `per_packet` to a payload, and hold
/// every sample up to the reference decoder's output.
fn decode_against_reference(
    name: &str,
    wideband: bool,
    octet_align: bool,
    per_packet: usize,
    frames: &Frames,
    reference_pcm: &[i16],
) {
    let frame_samples = if wideband { 320 } else { 160 };
    let mut decoder =
        decoder_for(&spec(wideband).with_amr_params(params(octet_align))).expect("decoder");
    let mut pcm = vec![0i16; frame_samples * per_packet];
    for (packet, chunk) in frames.chunks(per_packet).enumerate() {
        let chunk = chunk.to_vec();
        let payload = if octet_align {
            pack_octet_aligned(15, &chunk)
        } else {
            pack_bandwidth_efficient(15, wideband, &chunk)
        };
        let samples = decoder.decode(&payload, &mut pcm).expect("decode");
        assert_eq!(samples, chunk.len() * frame_samples, "{name}");
        let start = packet * per_packet * frame_samples;
        assert_eq!(
            &pcm[..samples],
            &reference_pcm[start..start + samples],
            "{name}: packet {packet} differs from the reference decoder"
        );
    }
}

/// 3GPP TS 26.174: `tst_mN.cod` is the reference encoder's output, `tst_mN.out` the reference
/// decoder's. Each `.cod` frame is three header words then one word per speech bit (127 for 1).
#[test]
fn reference_wideband_bitstreams_decode_sample_exact_in_both_payload_formats() {
    for mode in [0u8, 2, 8] {
        let (Some(cod), Some(out)) = (
            reference_words(&format!("amr-wb/testv/tst_m{mode}.cod")),
            reference_words(&format!("amr-wb/testv/tst_m{mode}.out")),
        ) else {
            return;
        };
        let bits = frame_bits(true, mode);
        let frames: Frames = cod
            .chunks_exact(3 + bits)
            .map(|frame| {
                (
                    mode,
                    siphon_rtp_codec::amr::wb::bitstream::pack(&frame[3..], mode),
                )
            })
            .collect();
        assert!(frames.len() > 100, "mode {mode}: {} frames", frames.len());
        for (octet_align, per_packet) in [(false, 1), (false, 3), (true, 1), (true, 12)] {
            let name = format!("wb mode {mode} octet-align={octet_align} x{per_packet}");
            decode_against_reference(&name, true, octet_align, per_packet, &frames, &out);
            eprintln!("REFERENCE {name}: {} frames sample-exact", frames.len());
        }
    }
}

/// 3GPP TS 26.074: 250 words a frame, the TX type, 244 bit words (the mode's bits first), the mode.
#[test]
fn reference_narrowband_bitstreams_decode_sample_exact_in_both_payload_formats() {
    for (mode, tag) in [(0u8, "475"), (7, "122")] {
        let (Some(cod), Some(out)) = (
            reference_words(&format!("amr-nb/testv/NODTX/T_{tag}/T01_{tag}.COD")),
            reference_words(&format!("amr-nb/testv/NODTX/T_{tag}/T01_{tag}.OUT")),
        ) else {
            return;
        };
        let frames: Frames = cod
            .as_chunks::<250>()
            .0
            .iter()
            .map(|frame| {
                (
                    mode,
                    siphon_rtp_codec::amr::nb::bitstream::pack(&frame[1..245], usize::from(mode)),
                )
            })
            .collect();
        assert!(frames.len() > 100, "mode {mode}: {} frames", frames.len());
        for (octet_align, per_packet) in [(false, 1), (false, 3), (true, 1), (true, 12)] {
            let name = format!("nb mode {mode} octet-align={octet_align} x{per_packet}");
            decode_against_reference(&name, false, octet_align, per_packet, &frames, &out);
            eprintln!("REFERENCE {name}: {} frames sample-exact", frames.len());
        }
    }
}

// ── Mode control and the receive side, on the stream ────────────────────────────────────────────

/// The modes of `frames` packets from `encoder`, read with the reader above.
fn sent_modes(
    encoder: &mut dyn siphon_rtp_codec::Encoder,
    wideband: bool,
    octet_align: bool,
    packets: usize,
) -> Vec<u8> {
    let pcm = tone(
        encoder.frame_samples(),
        if wideband { 16000.0 } else { 8000.0 },
    );
    let mut modes = Vec::new();
    for _ in 0..packets {
        let mut payload = [0u8; 256];
        let length = encoder.encode(&pcm, &mut payload).expect("encode");
        let (_, frames) = if octet_align {
            octet_aligned(&payload[..length], wideband)
        } else {
            bandwidth_efficient(&payload[..length], wideband)
        }
        .expect("payload");
        modes.extend(frame_types(&frames));
    }
    modes
}

/// 3GPP TS 26.114 §7.5.2.1.2.2: a sender "shall not use higher modes in media-encoding than
/// indicated by the most recently received CMR". RFC 4867 §4.3.1: a request outside the mode set
/// "MUST be ignored", and CMR 15 means "no mode request is present".
#[test]
fn a_codec_mode_request_caps_the_mode_inside_the_mode_set() {
    for wideband in [false, true] {
        let mode_set = if wideband {
            vec![0, 1, 2]
        } else {
            vec![0, 2, 4, 7]
        };
        let highest = *mode_set.last().expect("mode");
        let spec = spec(wideband).with_allowed_modes(mode_set);
        let mut encoder = encoder_for(&spec).expect("encoder");
        assert_eq!(
            sent_modes(encoder.as_mut(), wideband, false, 2),
            [highest; 2]
        );
        encoder.request_mode(0);
        assert_eq!(sent_modes(encoder.as_mut(), wideband, false, 2), [0, 0]);
        // Mode 3 is in neither set, and 8 is not an AMR mode: ignored, the request for 0 stands.
        encoder.request_mode(3);
        encoder.request_mode(if wideband { 8 } else { 9 });
        assert_eq!(sent_modes(encoder.as_mut(), wideband, false, 2), [0, 0]);
        encoder.request_mode(15);
        assert_eq!(
            sent_modes(encoder.as_mut(), wideband, false, 2),
            [highest; 2]
        );
    }
}

/// RFC 4867 §8.3.1: "A mode-change-period=2 in the offer indicates a requirement on the answerer
/// to send with a mode-change period of 2", and `mode-change-neighbor` asks for changes "to the
/// neighboring modes in the active codec mode set". 3GPP TS 26.114 Table A.2.1 offers both.
#[test]
fn negotiated_mode_change_restrictions_shape_every_change() {
    let restricted = AmrParams {
        mode_change_period: Some(2),
        mode_change_neighbor: Some(true),
        mode_change_capability: Some(2),
        max_red: Some(0),
        ..AmrParams::default()
    };
    let spec = spec(false)
        .with_allowed_modes(vec![0, 2, 4, 7])
        .with_amr_params(Some(restricted));
    let mut encoder = encoder_for(&spec).expect("encoder");
    assert_eq!(sent_modes(encoder.as_mut(), false, false, 2), [7, 7]);
    encoder.request_mode(0);
    assert_eq!(
        sent_modes(encoder.as_mut(), false, false, 8),
        [4, 4, 2, 2, 0, 0, 0, 0],
        "one neighbour at a time, on every second frame"
    );
    // The same restrictions hold across the frames of one packet.
    let mut two_per_packet = spec.clone();
    two_per_packet.ptime_ms = 40;
    let mut encoder = encoder_for(&two_per_packet).expect("encoder");
    encoder.request_mode(0);
    assert_eq!(
        sent_modes(encoder.as_mut(), false, false, 3),
        [4, 4, 2, 2, 0, 0]
    );
}

/// The engine's own request to the peer: 15 unless configured, and never a mode outside the mode
/// set (RFC 4867 §8.1: such modes MUST NOT be "used in codec mode requests").
#[test]
fn the_codec_mode_request_sent_is_fifteen_unless_configured() {
    let cmr = |spec: &CodecSpec| {
        let payload = encode_frames(spec, true, 1).remove(0);
        bandwidth_efficient(&payload, true).expect("payload").0
    };
    let with_request = |mode| {
        Some(AmrParams {
            mode_request: Some(mode),
            ..AmrParams::default()
        })
    };
    let base = spec(true).with_allowed_modes(vec![0, 1, 2]);
    assert_eq!(cmr(&base), 15);
    assert_eq!(cmr(&base.clone().with_amr_params(with_request(1))), 1);
    assert_eq!(cmr(&base.with_amr_params(with_request(8))), 15);
}

/// 3GPP TS 26.114 §7.4.2: a client "should encapsulate the number of non-redundant ... speech
/// frames in the RTP packets that corresponds to the ptime value received" and "shall not
/// encapsulate more than 4".
#[test]
fn ptime_sets_the_frames_per_packet_up_to_four() {
    for (ptime, frames) in [
        (10u8, 1usize),
        (20, 1),
        (30, 1),
        (40, 2),
        (60, 3),
        (80, 4),
        (120, 4),
    ] {
        let mut spec = spec(false);
        spec.ptime_ms = ptime;
        let encoder = encoder_for(&spec).expect("encoder");
        assert_eq!(encoder.frame_samples(), frames * 160, "ptime {ptime}");
        let payload = encode_frames(&spec, false, 1).remove(0);
        let (_, read) = bandwidth_efficient(&payload, false).expect("payload");
        assert_eq!(read.len(), frames, "ptime {ptime}");
    }
}

/// What each kind of received frame becomes, and that a bad packet costs one packet only.
#[test]
fn the_receive_side_plays_through_damage_loss_and_silence_periods() {
    for (wideband, octet_align) in [(false, false), (false, true), (true, false), (true, true)] {
        let name = format!("wideband={wideband} octet-align={octet_align}");
        let frame = if wideband { 320 } else { 160 };
        let sid = if wideband { 9 } else { 8 };
        let spec = spec(wideband)
            .with_amr_params(params(octet_align))
            .with_allowed_modes(vec![0, 2]);
        let pack = |cmr: u8, frames: &Frames| {
            if octet_align {
                pack_octet_aligned(cmr, frames)
            } else {
                pack_bandwidth_efficient(cmr, wideband, frames)
            }
        };
        // Real speech frames to feed back in: the encoder's own, taken apart by the reader here.
        let speech: Frames = encode_frames(&spec, wideband, 12)
            .iter()
            .flat_map(|payload| {
                if octet_align {
                    octet_aligned(payload, wideband)
                } else {
                    bandwidth_efficient(payload, wideband)
                }
                .expect("payload")
                .1
            })
            .collect();
        let mut decoder = decoder_for(&spec).expect("decoder");
        let mut pcm = vec![0i16; frame * 12];
        let loud = |pcm: &[i16]| pcm.iter().any(|sample| sample.unsigned_abs() > 500);

        // Several frames in one packet: 20 ms each, and the request is surfaced.
        assert_eq!(
            decoder.decode(&pack(2, &speech[..3].to_vec()), &mut pcm),
            Ok(3 * frame),
            "{name}"
        );
        assert_eq!(decoder.last_mode_request(), Some(2), "{name}");
        assert_eq!(
            decoder.decode(&pack(15, &speech[3..9].to_vec()), &mut pcm),
            Ok(6 * frame)
        );
        assert!(loud(&pcm[5 * frame..6 * frame]), "{name}: speech decodes");
        assert_eq!(
            decoder.last_mode_request(),
            None,
            "{name}: CMR 15 is no request"
        );
        // A reserved CMR value is ignored: the previous one stays.
        decoder
            .decode(&pack(0, &speech[9..10].to_vec()), &mut pcm)
            .expect("decode");
        decoder
            .decode(&pack(12, &speech[10..11].to_vec()), &mut pcm)
            .expect("decode");
        assert_eq!(decoder.last_mode_request(), Some(0), "{name}");

        // A lost packet is concealed and the stream goes on.
        assert_eq!(decoder.conceal(&mut pcm), Ok(frame), "{name}");
        assert_eq!(
            decoder.decode(&pack(15, &speech[11..12].to_vec()), &mut pcm),
            Ok(frame)
        );

        // A silence period: the SID frame and the NO_DATA frames after it are silence, not errors.
        let sid_frame: Frames = vec![(sid, vec![0x5A; 5])];
        pcm.fill(1);
        assert_eq!(
            decoder.decode(&pack(15, &sid_frame), &mut pcm),
            Ok(frame),
            "{name}"
        );
        assert!(pcm[..frame].iter().all(|&sample| sample == 0), "{name}");
        pcm.fill(1);
        let no_data: Frames = vec![(15, Vec::new()), (15, Vec::new())];
        assert_eq!(
            decoder.decode(&pack(15, &no_data), &mut pcm),
            Ok(2 * frame),
            "{name}"
        );
        assert!(pcm[..2 * frame].iter().all(|&sample| sample == 0), "{name}");

        // A table of contents the format does not define, a truncated packet, an empty one: each
        // is an error for that packet, and the next good packet decodes.
        let mut reserved = pack(15, &speech[..1].to_vec());
        if octet_align {
            reserved[1] = (12 << 3) | 0x04;
        } else {
            reserved[0] = 0xF6; // CMR 15, F=0, FT=12 begins 110.
            reserved[1] &= 0x7F;
        }
        let good = pack(15, &speech[..1].to_vec());
        for bad in [&reserved[..], &good[..good.len() - 2], &good[..1], &[]] {
            assert!(decoder.decode(bad, &mut pcm).is_err(), "{name}: {bad:02x?}");
            assert_eq!(decoder.decode(&good, &mut pcm), Ok(frame), "{name}");
        }
        // An output buffer too small for the packet's frames is refused before anything is written.
        assert!(matches!(
            decoder.decode(&pack(15, &speech[..3].to_vec()), &mut pcm[..2 * frame]),
            Err(siphon_rtp_codec::CodecError::OutputTooSmall { .. })
        ));
    }
}

/// A frame in a mode the mode set does not have is decoded all the same, and counted.
#[test]
fn a_frame_outside_the_mode_set_is_decoded_and_counted() {
    use siphon_rtp_codec::amr::{AmrWb, PayloadFormat, RtpConfig};
    use siphon_rtp_codec::Decoder;
    let config = RtpConfig {
        format: PayloadFormat::OctetAligned,
        mode_set: &[0, 1],
        ..RtpConfig::default()
    };
    let sender = spec(true)
        .with_amr_params(params(true))
        .with_allowed_modes(vec![2]);
    let payload = encode_frames(&sender, true, 1).remove(0);
    let mut decoder = AmrWb::negotiated(&config).expect("decoder");
    let mut pcm = [0i16; 320];
    assert_eq!(decoder.decode(&payload, &mut pcm), Ok(320));
    assert_eq!(decoder.frames_outside_mode_set(), 1);
}

/// A frame with the Q bit clear is "severely damaged" (RFC 4867 §4.3.2): it is concealed, never
/// decoded as if it were good.
#[test]
fn a_damaged_frame_is_concealed_not_decoded() {
    let spec = spec(true).with_amr_params(params(true));
    let payloads = encode_frames(&spec, true, 6);
    let mut decoder = decoder_for(&spec).expect("decoder");
    let mut reference = decoder_for(&spec).expect("decoder");
    let mut pcm = [0i16; 320];
    let mut concealed = [0i16; 320];
    for payload in &payloads[..5] {
        decoder.decode(payload, &mut pcm).expect("decode");
        reference.decode(payload, &mut concealed).expect("decode");
    }
    // The sixth frame arrives with Q clear on one decoder and is lost outright on the other: both
    // must produce the same concealment.
    let mut damaged = payloads[5].clone();
    damaged[1] &= !0x04;
    assert_eq!(decoder.decode(&damaged, &mut pcm), Ok(320));
    assert_eq!(reference.conceal(&mut concealed), Ok(320));
    assert_eq!(pcm, concealed);
}

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Whatever arrives, in either format and for either codec: a result, never a panic, and the
    /// decoder keeps working afterwards.
    #[test]
    fn hostile_payloads_never_panic_a_negotiated_decoder(
        payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..200), 1..8),
        wideband: bool,
        octet_align: bool,
    ) {
        let spec = spec(wideband).with_amr_params(params(octet_align));
        let mut decoder = decoder_for(&spec).expect("decoder");
        let mut pcm = vec![0i16; 320 * 12];
        for payload in &payloads {
            if let Ok(samples) = decoder.decode(payload, &mut pcm) {
                prop_assert!(samples <= pcm.len());
                prop_assert_eq!(samples % if wideband { 320 } else { 160 }, 0);
            }
            let _ = decoder.conceal(&mut pcm);
        }
    }
}
