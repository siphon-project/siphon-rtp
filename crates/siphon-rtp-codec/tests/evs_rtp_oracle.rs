//! The RTP path against the reference's own storage-format decoder, on streams the reference encoder
//! makes from a synthetic signal, so this needs the built oracles (`sh reference/evs/oracle/build.sh`)
//! and not the 3GPP sequences.
//!
//! For each configuration the reference encoder writes the TS 26.445 A.2.6 storage format (one
//! header-full frame after another) and the reference decoder (`EVS_dec -mime`) decodes it; the
//! frames are also decoded here through the factory's [`Decoder`], and the PCM must be identical.
//! The signal has a voiced burst, digital silence (so DTX produces SIDs, SID_FIRST and NO_DATA), a
//! second burst and a tone. Then the same frames are packed three at a time and decoded again: the
//! decoder must give the same PCM whether a packet carries one frame or several, with a CMR octet
//! or without.
//!
//! Skips when the oracles are not built; `SIPHON_RTP_REQUIRE_ORACLE=1` makes that a failure.
#![cfg(feature = "evs")]
#![allow(clippy::expect_used, reason = "test harness: a panic reports failure")]

// The sequence readers of the module are for the conformance tests.
#[allow(dead_code)]
mod evs_cases;

use std::process::Command;

use evs_cases::oracle;
use siphon_rtp_codec::factory::{decoder_for, CodecSpec, EvsParams};

/// 16 kHz mono PCM: 1 s of a pulse train through a resonance, 1 s of digital silence, 0.5 s more
/// speech and 0.25 s of a 1 kHz tone (the same signal the frame file was made from).
fn signal() -> Vec<i16> {
    let mut state = 12_345u32;
    let mut noise = move || {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        f64::from((state >> 16) & 0xFFFF) / 65_536.0 - 0.5
    };
    let (mut first, mut second) = (0.0f64, 0.0f64);
    let mut pcm = Vec::new();
    let mut voiced = |count: usize, pitch: usize, pcm: &mut Vec<i16>| {
        for index in 0..count {
            let pulse = if index % pitch == 0 { 6000.0 } else { 0.0 };
            let value = pulse + noise() * 600.0 + 1.6 * first - 0.8 * second;
            second = first;
            first = value;
            pcm.push((value * 0.5).clamp(-20_000.0, 20_000.0) as i16);
        }
    };
    voiced(16_000, 100, &mut pcm);
    pcm.extend(std::iter::repeat_n(0i16, 16_000));
    voiced(8_000, 130, &mut pcm);
    pcm.extend((0..4_000).map(|index| {
        (8000.0 * (2.0 * std::f64::consts::PI * 1000.0 * f64::from(index) / 16_000.0).sin()) as i16
    }));
    pcm
}

fn pcm_bytes(pcm: &[i16]) -> Vec<u8> {
    pcm.iter().flat_map(|sample| sample.to_le_bytes()).collect()
}

/// The frames of a storage-format file: its table-of-contents octet and bits.
fn storage_frames(file: &[u8]) -> Vec<Vec<u8>> {
    const PRIMARY: [usize; 13] = [
        56, 144, 160, 192, 264, 328, 488, 640, 960, 1280, 1920, 2560, 48,
    ];
    const IO: [usize; 10] = [132, 177, 253, 285, 317, 365, 397, 461, 477, 35];
    assert!(file.starts_with(b"#!EVS_MC1.0\n\0\0\0\x01"));
    let mut frames = Vec::new();
    let mut at = 16;
    while at < file.len() {
        let toc = file[at];
        let index = usize::from(toc & 0x0F);
        let io = toc & 0x20 != 0;
        let bits = match (io, index) {
            (false, 0..=12) => PRIMARY[index],
            (true, 0..=9) => IO[index],
            _ => 0,
        };
        // an AMR-WB IO SID carries its STI bit and CMI after the 35 bits
        let stored = if io && index == 9 { 40 } else { bits };
        let end = at + 1 + stored.div_ceil(8);
        frames.push(file[at..end].to_vec());
        at = end;
    }
    frames
}

fn decode(payloads: &[Vec<u8>], output_khz: usize, frames_per_packet: usize) -> Vec<i16> {
    let band = match output_khz {
        8 => "nb",
        16 => "wb",
        32 => "swb",
        _ => "fb",
    };
    let params = EvsParams::parse(&format!("bw-send={band};hf-only=1")).expect("fmtp");
    let spec = CodecSpec::new(96, "EVS", 16_000, 1, 20 * frames_per_packet as u8)
        .with_evs_params(Some(params));
    let mut decoder = decoder_for(&spec).expect("decoder");
    let mut pcm = Vec::new();
    let mut out = vec![0i16; 12 * decoder.frame_samples()];
    for (index, group) in payloads.chunks(frames_per_packet).enumerate() {
        // one packet of these frames: a CMR octet on every other packet, every entry but the
        // last with F set, then the frames' bits
        let mut packet: Vec<u8> = if index % 2 == 0 {
            vec![0xFF]
        } else {
            Vec::new()
        };
        for (position, frame) in group.iter().enumerate() {
            let more = position + 1 < group.len();
            packet.push(frame[0] | if more { 0x40 } else { 0 });
        }
        for frame in group {
            packet.extend_from_slice(&frame[1..]);
        }
        let written = decoder.decode(&packet, &mut out).expect("decode");
        pcm.extend_from_slice(&out[..written]);
    }
    pcm
}

#[test]
fn the_rtp_path_decodes_what_the_reference_storage_format_decoder_decodes() {
    let (Some(encoder), Some(reference)) = (oracle::encoder(), oracle::decoder()) else {
        assert!(
            !oracle::required(),
            "SIPHON_RTP_REQUIRE_ORACLE=1 but reference/evs/build/EVS_cod and EVS_dec are not built"
        );
        eprintln!("skipping: the reference encoder and decoder are not built");
        return;
    };
    let dir = oracle::scratch("oracle");
    let wide = signal();
    let narrow: Vec<i16> = wide
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| ((i32::from(pair[0]) + i32::from(pair[1])) / 2) as i16)
        .collect();
    std::fs::write(dir.join("wide.pcm"), pcm_bytes(&wide)).expect("write");
    std::fs::write(dir.join("narrow.pcm"), pcm_bytes(&narrow)).expect("write");

    // (name, encoder arguments, input, input kHz)
    let configurations: &[(&str, &[&str], &str, usize)] = &[
        ("evs 7.2", &["7200"], "wide", 16),
        ("evs 13.2", &["13200"], "wide", 16),
        ("evs 24.4", &["24400"], "wide", 16),
        ("evs 64", &["64000"], "wide", 16),
        ("evs 9.6 dtx", &["-dtx", "8", "9600"], "wide", 16),
        ("evs 13.2 dtx", &["-dtx", "8", "13200"], "wide", 16),
        (
            "evs 5.9 vbr dtx at 8 kHz",
            &["-dtx", "8", "5900"],
            "narrow",
            8,
        ),
        ("io 6.6", &["6600"], "wide", 16),
        ("io 12.65", &["12650"], "wide", 16),
        ("io 23.85", &["23850"], "wide", 16),
        ("io 12.65 dtx", &["-dtx", "8", "12650"], "wide", 16),
        ("io 23.85 dtx", &["-dtx", "8", "23850"], "wide", 16),
    ];
    for &(name, arguments, input, khz) in configurations {
        let coded = dir.join("coded.mime");
        let khz_text = khz.to_string();
        let output = Command::new(&encoder)
            .args(["-q", "-mime"])
            .args(arguments)
            .arg(&khz_text)
            .arg(dir.join(format!("{input}.pcm")))
            .arg(&coded)
            .output()
            .expect("run EVS_cod");
        assert!(output.status.success(), "{name}: EVS_cod {output:?}");
        let file = std::fs::read(&coded).expect("coded file");
        let frames = storage_frames(&file);
        assert!(frames.len() > 100, "{name}: {} frames", frames.len());

        let said = oracle::decode_storage(&reference, &file, khz);
        assert_eq!(said.len(), frames.len() * khz * 20, "{name}");
        for per_packet in [1, 3] {
            let ours = decode(&frames, khz, per_packet);
            assert_eq!(ours.len(), said.len(), "{name} x{per_packet}");
            if let Some(at) = ours
                .iter()
                .zip(&said)
                .position(|(left, right)| left != right)
            {
                panic!(
                    "{name}, {per_packet} frame(s) a packet: first difference at sample {at} \
                     (frame {}): {} against the reference's {}",
                    at / (khz * 20),
                    ours[at],
                    said[at]
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
