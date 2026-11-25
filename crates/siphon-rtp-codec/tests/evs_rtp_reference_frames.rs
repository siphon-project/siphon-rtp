//! The depacketizer against what the 3GPP reference encoder writes.
//!
//! `evs_rtp_kat/frames.txt` holds frames of the TS 26.442 reference encoder (`EVS_cod`, v16.4.0) for
//! a synthetic signal (a voiced burst, digital silence, a second burst and a tone, so the DTX runs
//! produce SID and NO_DATA frames), each in the two forms the encoder writes: the G.192 frame
//! (`-` the bits the decoder reads, in its order) and the TS 26.445 A.2.6 storage format (`-mime`:
//! one table-of-contents octet and the frame bits as an RTP payload carries them). The pair is the
//! reference's own account of what the bits of a payload are, so a depacketizer that reads the
//! storage frame into exactly the G.192 bits has the bit order, the AMR-WB IO sorting, the SID's
//! STI bit and the frame types right, none of it checked against anything we wrote.
//!
//! One frame a line: `name|index|good|bits|g192 bits (hex, MSB first)|storage frame (hex)`.
//!
//! The frames came from `EVS_cod [-dtx 8] <rate> 16 in.pcm out.192` and again with `-mime`, with
//! `in.pcm` synthetic PCM (an LCG-driven pulse train through a resonance); the 5.9 kbit/s case is
//! the same signal at 8 kHz.
#![cfg(feature = "evs")]
#![allow(clippy::expect_used, reason = "test harness: a panic reports failure")]

use siphon_rtp_codec::evs::frame::FrameKind;
use siphon_rtp_codec::evs::rtp::{FrameType, Packet, PayloadFormat};

const FRAMES: &str = include_str!("evs_rtp_kat/frames.txt");

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn every_reference_storage_frame_reads_as_the_reference_g192_frame() {
    let mut checked = 0;
    let mut kinds = std::collections::BTreeSet::new();
    for line in FRAMES.lines() {
        let fields: Vec<&str> = line.split('|').collect();
        assert_eq!(fields.len(), 6, "{line}");
        let (name, bit_count) = (fields[0], fields[3].parse::<usize>().expect("bits"));
        let g192_bits: Vec<u8> = unhex(fields[4])
            .iter()
            .flat_map(|octet| (0..8).map(move |bit| (octet >> (7 - bit)) & 1))
            .take(bit_count)
            .collect();
        let storage = unhex(fields[5]);

        // a storage frame is a header-full payload of one frame, never compact
        let packet =
            Packet::parse(&storage, true).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(packet.format(), PayloadFormat::HeaderFull, "{name}");
        assert_eq!(packet.frame_count(), 1, "{name}");
        let frame = packet.frames().next().expect("one frame");

        // what the frame is follows from its size in the G.192 frame
        let expected = FrameKind::from_bits(bit_count).expect("kind");
        match (expected, frame.frame_type) {
            (FrameKind::Primary(rate), FrameType::Primary(read)) => {
                assert_eq!(rate, read, "{name}")
            }
            (FrameKind::PrimarySid, FrameType::PrimarySid) => {}
            (FrameKind::AmrWbIo(mode), FrameType::AmrWbIo(read)) => {
                assert_eq!(mode, read, "{name}")
            }
            (FrameKind::AmrWbIoSid, FrameType::AmrWbIoSid) => {
                assert_eq!(
                    frame.sid_update(),
                    Some(true),
                    "{name}: the encoder sends SID_UPDATE"
                );
            }
            (FrameKind::NoData, FrameType::NoData { .. }) => {}
            (expected, read) => {
                panic!("{name}: G.192 says {expected:?}, the payload says {read:?}")
            }
        }
        assert!(frame.quality_ok, "{name}");
        kinds.insert(match frame.frame_type {
            FrameType::Primary(_) => "primary speech",
            FrameType::PrimarySid => "primary SID",
            FrameType::AmrWbIo(_) => "AMR-WB IO speech",
            FrameType::AmrWbIoSid => "AMR-WB IO SID",
            FrameType::NoData { amr_wb_io: false } => "primary NO_DATA",
            FrameType::NoData { amr_wb_io: true } => "AMR-WB IO NO_DATA",
            FrameType::SpeechLost { .. } => "SPEECH_LOST",
        });

        let mut bits = [0u8; 2560];
        let count = frame.decoder_bits(&mut bits);
        assert_eq!(count, bit_count, "{name}");
        assert_eq!(
            &bits[..count],
            &g192_bits[..],
            "{name} frame {}: bits differ",
            fields[1]
        );
        checked += 1;
    }
    assert!(checked >= 60, "{checked} frames");
    // every frame family of the file is there: EVS speech, both SIDs, NO_DATA, AMR-WB IO speech
    for kind in [
        "primary speech",
        "primary SID",
        "primary NO_DATA",
        "AMR-WB IO speech",
        "AMR-WB IO SID",
        "AMR-WB IO NO_DATA",
    ] {
        assert!(
            kinds.contains(kind),
            "no {kind} frame in the file: {kinds:?}"
        );
    }
}
