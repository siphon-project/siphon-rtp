#![cfg(test)]
//! Hand-assembled RFC 4867 payloads, written out field by field from the layouts of §4.3 and §4.4.
//!
//! Each vector is a string of bits in transmission order, grouped as the RFC draws them, so the
//! expected octets come from the specification and not from the packetiser under test. The same
//! vectors are held up to an independent dissector in `tests/amr_rtp_interop.rs`.

use super::*;

/// The octets of a bit string in transmission order; spaces and `|` only group the fields.
pub(crate) fn octets(bits: &str) -> Vec<u8> {
    let bits: Vec<u8> = bits
        .bytes()
        .filter(|character| matches!(character, b'0' | b'1'))
        .map(|character| character - b'0')
        .collect();
    assert_eq!(bits.len() % 8, 0, "a payload is a whole number of octets");
    bits.chunks(8)
        .map(|octet| octet.iter().fold(0, |value, bit| (value << 1) | bit))
        .collect()
}

/// `count` frame bits following a fixed rule, so a vector's speech data can be read off the page:
/// d(i) = 1 where `i % period == 0`.
fn pattern(count: usize, period: usize) -> String {
    (0..count)
        .map(|index| if index % period == 0 { '1' } else { '0' })
        .collect()
}

/// The frame bits of [`pattern`], left-aligned in octets, as a depacketiser returns them.
fn frame_octets(count: usize, period: usize) -> Vec<u8> {
    let mut bits = pattern(count, period);
    while !bits.len().is_multiple_of(8) {
        bits.push('0');
    }
    octets(&bits)
}

/// One hand-assembled payload and what it carries.
struct Vector {
    name: &'static str,
    variant: Variant,
    format: PayloadFormat,
    payload: Vec<u8>,
    cmr: u8,
    /// Frame type, Q bit, frame bits, and the period of their [`pattern`].
    frames: Vec<(u8, bool, usize, usize)>,
}

fn vectors() -> Vec<Vector> {
    use PayloadFormat::{BandwidthEfficient, OctetAligned};
    use Variant::{Narrowband, Wideband};
    vec![
        // ── AMR, bandwidth-efficient (§4.3): CMR(4) | F FT(4) Q | frame bits | padding ──
        Vector {
            name: "nb-be-mode0",
            variant: Narrowband,
            format: BandwidthEfficient,
            // 4 + 6 + 95 = 105 bits, 7 padding bits, 14 octets.
            payload: octets(&format!("1111 | 0 0000 1 | {} | 0000000", pattern(95, 1))),
            cmr: 15,
            frames: vec![(0, true, 95, 1)],
        },
        Vector {
            name: "nb-be-mode7-cmr2",
            variant: Narrowband,
            format: BandwidthEfficient,
            // 4 + 6 + 244 = 254 bits, 2 padding bits, 32 octets.
            payload: octets(&format!("0010 | 0 0111 1 | {} | 00", pattern(244, 2))),
            cmr: 2,
            frames: vec![(7, true, 244, 2)],
        },
        Vector {
            name: "nb-be-sid",
            variant: Narrowband,
            format: BandwidthEfficient,
            // FT=8, the 39-bit SID frame: 4 + 6 + 39 = 49 bits, 7 padding bits, 7 octets.
            payload: octets(&format!("1111 | 0 1000 1 | {} | 0000000", pattern(39, 3))),
            cmr: 15,
            frames: vec![(8, true, 39, 3)],
        },
        Vector {
            name: "nb-be-no-data",
            variant: Narrowband,
            format: BandwidthEfficient,
            // FT=15 carries no bits: 4 + 6 = 10 bits, 6 padding bits.
            payload: octets("1111 | 0 1111 1 | 000000"),
            cmr: 15,
            frames: vec![(15, true, 0, 1)],
        },
        Vector {
            name: "nb-be-two-frames",
            variant: Narrowband,
            format: BandwidthEfficient,
            // Mode 4 (148 bits) then mode 0 (95 bits), the second with Q clear:
            // 4 + 12 + 243 = 259 bits, 5 padding bits, 33 octets.
            payload: octets(&format!(
                "1111 | 1 0100 1 | 0 0000 0 | {} | {} | 00000",
                pattern(148, 2),
                pattern(95, 3)
            )),
            cmr: 15,
            frames: vec![(4, true, 148, 2), (0, false, 95, 3)],
        },
        // ── AMR, octet-aligned (§4.4): CMR(4) RRRR | F FT(4) Q PP | frame, padded to the octet ──
        Vector {
            name: "nb-oa-mode0",
            variant: Narrowband,
            format: OctetAligned,
            // 95 bits in 12 octets, 1 padding bit.
            payload: octets(&format!("1111 0000 | 0 0000 1 00 | {} 0", pattern(95, 1))),
            cmr: 15,
            frames: vec![(0, true, 95, 1)],
        },
        Vector {
            name: "nb-oa-mode7-cmr2",
            variant: Narrowband,
            format: OctetAligned,
            // 244 bits in 31 octets, 4 padding bits.
            payload: octets(&format!(
                "0010 0000 | 0 0111 1 00 | {} 0000",
                pattern(244, 2)
            )),
            cmr: 2,
            frames: vec![(7, true, 244, 2)],
        },
        Vector {
            name: "nb-oa-sid",
            variant: Narrowband,
            format: OctetAligned,
            payload: octets(&format!("1111 0000 | 0 1000 1 00 | {} 0", pattern(39, 3))),
            cmr: 15,
            frames: vec![(8, true, 39, 3)],
        },
        Vector {
            name: "nb-oa-no-data",
            variant: Narrowband,
            format: OctetAligned,
            payload: octets("1111 0000 | 0 1111 1 00"),
            cmr: 15,
            frames: vec![(15, true, 0, 1)],
        },
        Vector {
            name: "nb-oa-two-frames",
            variant: Narrowband,
            format: OctetAligned,
            // 148 bits in 19 octets (4 padding bits), 95 bits in 12 octets (1 padding bit).
            payload: octets(&format!(
                "1111 0000 | 1 0100 1 00 | 0 0000 0 00 | {} 0000 | {} 0",
                pattern(148, 2),
                pattern(95, 3)
            )),
            cmr: 15,
            frames: vec![(4, true, 148, 2), (0, false, 95, 3)],
        },
        // ── AMR-WB, bandwidth-efficient ──
        Vector {
            name: "wb-be-mode0",
            variant: Wideband,
            format: BandwidthEfficient,
            // 4 + 6 + 132 = 142 bits, 2 padding bits, 18 octets.
            payload: octets(&format!("1111 | 0 0000 1 | {} | 00", pattern(132, 1))),
            cmr: 15,
            frames: vec![(0, true, 132, 1)],
        },
        Vector {
            name: "wb-be-mode2-cmr0",
            variant: Wideband,
            format: BandwidthEfficient,
            // 4 + 6 + 253 = 263 bits, 1 padding bit, 33 octets.
            payload: octets(&format!("0000 | 0 0010 1 | {} | 0", pattern(253, 2))),
            cmr: 0,
            frames: vec![(2, true, 253, 2)],
        },
        Vector {
            name: "wb-be-sid",
            variant: Wideband,
            format: BandwidthEfficient,
            // FT=9, the 40-bit SID frame: 4 + 6 + 40 = 50 bits, 6 padding bits.
            payload: octets(&format!("1111 | 0 1001 1 | {} | 000000", pattern(40, 3))),
            cmr: 15,
            frames: vec![(9, true, 40, 3)],
        },
        Vector {
            name: "wb-be-no-data",
            variant: Wideband,
            format: BandwidthEfficient,
            payload: octets("1111 | 0 1111 1 | 000000"),
            cmr: 15,
            frames: vec![(15, true, 0, 1)],
        },
        Vector {
            // RFC 4867 §4.3.5.2, the RFC's own example: CMR=1; a 6.60 kbit/s frame, a SID frame,
            // a NO_DATA frame and an 8.85 kbit/s frame; 28 + 349 = 377 bits, "seven zero bits are
            // padded to the end".
            name: "wb-be-rfc-4-3-5-2",
            variant: Wideband,
            format: BandwidthEfficient,
            payload: octets(&format!(
                "0001 | 1 0000 1 | 1 1001 1 | 1 1111 1 | 0 0001 1 | {} | {} | {} | 0000000",
                pattern(132, 2),
                pattern(40, 3),
                pattern(177, 5)
            )),
            cmr: 1,
            frames: vec![
                (0, true, 132, 2),
                (9, true, 40, 3),
                (15, true, 0, 1),
                (1, true, 177, 5),
            ],
        },
        // ── AMR-WB, octet-aligned ──
        Vector {
            name: "wb-oa-mode0",
            variant: Wideband,
            format: OctetAligned,
            // 132 bits in 17 octets, 4 padding bits.
            payload: octets(&format!(
                "1111 0000 | 0 0000 1 00 | {} 0000",
                pattern(132, 1)
            )),
            cmr: 15,
            frames: vec![(0, true, 132, 1)],
        },
        Vector {
            name: "wb-oa-mode2-cmr0",
            variant: Wideband,
            format: OctetAligned,
            // 253 bits in 32 octets, 3 padding bits.
            payload: octets(&format!(
                "0000 0000 | 0 0010 1 00 | {} 000",
                pattern(253, 2)
            )),
            cmr: 0,
            frames: vec![(2, true, 253, 2)],
        },
        Vector {
            name: "wb-oa-sid",
            variant: Wideband,
            format: OctetAligned,
            payload: octets(&format!("1111 0000 | 0 1001 1 00 | {}", pattern(40, 3))),
            cmr: 15,
            frames: vec![(9, true, 40, 3)],
        },
        Vector {
            name: "wb-oa-no-data",
            variant: Wideband,
            format: OctetAligned,
            payload: octets("1111 0000 | 0 1111 1 00"),
            cmr: 15,
            frames: vec![(15, true, 0, 1)],
        },
        Vector {
            name: "wb-oa-two-frames",
            variant: Wideband,
            format: OctetAligned,
            // Mode 8 (477 bits in 60 octets, 3 padding bits), then SPEECH_LOST (FT=14, no bits).
            payload: octets(&format!(
                "1111 0000 | 1 1000 1 00 | 0 1110 1 00 | {} 000",
                pattern(477, 2)
            )),
            cmr: 15,
            frames: vec![(8, true, 477, 2), (14, true, 0, 1)],
        },
    ]
}

/// A few of the vectors spelled out as octets as well, worked by hand from the same layouts, so
/// the bit-string helper is itself checked against something it did not produce.
#[test]
fn the_vectors_are_the_octets_the_layouts_give() {
    let by_name = |name: &str| {
        vectors()
            .into_iter()
            .find(|vector| vector.name == name)
            .map(|vector| vector.payload)
            .expect("vector")
    };
    // 1111 0000 | 01 111111 | 89 more ones: eleven FF, then 1 and seven padding bits.
    let mut expected = vec![0xF0, 0x7F];
    expected.extend([0xFF; 11]);
    expected.push(0x80);
    assert_eq!(by_name("nb-be-mode0"), expected);
    // 0010 0011 | 11 101010 | 238 more alternating bits: 29 octets AA, then 101010 and 00.
    let mut expected = vec![0x23, 0xEA];
    expected.extend([0xAA; 29]);
    expected.push(0xA8);
    assert_eq!(by_name("nb-be-mode7-cmr2"), expected);
    // 1111 0111 | 11 000000.
    assert_eq!(by_name("nb-be-no-data"), [0xF7, 0xC0]);
    assert_eq!(by_name("nb-oa-no-data"), [0xF0, 0x7C]);
    // 1111 0100 | 01 100100 | 10010010 | 01001001 | 00100100 | 10010010 | 0 0000000.
    assert_eq!(
        by_name("nb-be-sid"),
        [0xF4, 0x64, 0x92, 0x49, 0x24, 0x92, 0x00]
    );
    // F0 | 0 1001 1 00 | 10010010 01001001 00100100 10010010 01001001.
    assert_eq!(
        by_name("wb-oa-sid"),
        [0xF0, 0x4C, 0x92, 0x49, 0x24, 0x92, 0x49]
    );
    // The head of the RFC's own example, CMR=1 and four ToC entries:
    // 0001 1000 | 01 110011 | 111111 00 | 0011 ....
    assert_eq!(by_name("wb-be-rfc-4-3-5-2")[..3], [0x18, 0x73, 0xFC]);
    assert_eq!(by_name("wb-be-rfc-4-3-5-2").len(), 48);
}

#[test]
fn the_depacketiser_reads_every_vector() {
    for vector in vectors() {
        let layout = read_payload(&vector.payload, vector.format, vector.variant)
            .unwrap_or_else(|error| panic!("{}: {error}", vector.name));
        assert_eq!(layout.cmr, vector.cmr, "{}", vector.name);
        assert_eq!(
            layout.frames().len(),
            vector.frames.len(),
            "{}",
            vector.name
        );
        for (slot, &(frame_type, quality_ok, bits, period)) in
            layout.frames().iter().zip(&vector.frames)
        {
            assert_eq!(
                (slot.frame_type, slot.quality_ok, usize::from(slot.bits)),
                (frame_type, quality_ok, bits),
                "{}",
                vector.name
            );
            let mut data = [0xFFu8; MAX_FRAME_OCTETS];
            let written = slot.copy_bits(&vector.payload, &mut data);
            assert_eq!(
                &data[..written],
                frame_octets(bits, period),
                "{} frame type {frame_type}",
                vector.name
            );
        }
    }
}

#[test]
fn the_packetiser_writes_every_vector() {
    for vector in vectors() {
        let data: Vec<Vec<u8>> = vector
            .frames
            .iter()
            .map(|&(_, _, bits, period)| {
                // Bits past the end of the frame in its last octet are not part of the frame and
                // must not reach the payload: set them, so a packetiser that copies octets fails.
                let mut data = frame_octets(bits, period);
                if !bits.is_multiple_of(8) {
                    let last = data.len() - 1;
                    data[last] |= 0xFF >> (bits % 8);
                }
                data
            })
            .collect();
        let frames: Vec<FrameSource<'_>> = vector
            .frames
            .iter()
            .zip(&data)
            .map(|(&(frame_type, quality_ok, _, _), data)| FrameSource {
                frame_type,
                quality_ok,
                data,
            })
            .collect();
        // A dirty buffer: every reserved and padding bit has to be written, not assumed.
        let mut out = [0xFFu8; 256];
        let length = write_payload(vector.format, vector.variant, vector.cmr, &frames, &mut out)
            .unwrap_or_else(|error| panic!("{}: {error}", vector.name));
        assert_eq!(&out[..length], vector.payload, "{}", vector.name);
        assert_eq!(
            payload_len(
                vector.format,
                vector.variant,
                vector.frames.iter().map(|frame| frame.0)
            ),
            Some(length),
            "{}",
            vector.name
        );
    }
}

#[test]
fn a_payload_read_in_the_other_format_is_not_mistaken_for_a_good_one() {
    // RFC 4867 §8.3.1: each configuration "is unique in its bit-pattern and not compatible with any
    // other combination". A single-frame speech payload of one format never passes as the other.
    for vector in vectors() {
        if vector.frames.len() != 1 || vector.frames[0].2 < 95 {
            continue;
        }
        let other = match vector.format {
            PayloadFormat::BandwidthEfficient => PayloadFormat::OctetAligned,
            PayloadFormat::OctetAligned => PayloadFormat::BandwidthEfficient,
        };
        let misread = read_payload(&vector.payload, other, vector.variant);
        let passes = misread.is_ok_and(|layout| {
            layout
                .frames()
                .iter()
                .all(|slot| slot.quality_ok && slot.bits != 0)
        });
        assert!(!passes, "{}", vector.name);
    }
}

#[test]
fn malformed_payloads_are_refused_with_a_reason() {
    use PayloadFormat::{BandwidthEfficient, OctetAligned};
    use Variant::{Narrowband, Wideband};
    let refused = |payload: &[u8], format, variant| match read_payload(payload, format, variant) {
        Err(CodecError::Malformed(reason)) => reason,
        other => panic!("{payload:02x?} was not refused: {other:?}"),
    };
    assert_eq!(refused(&[], OctetAligned, Wideband), "empty AMR payload");
    assert_eq!(
        refused(&[0xF0], OctetAligned, Wideband),
        "truncated AMR ToC"
    );
    assert_eq!(
        refused(&[0xF0], BandwidthEfficient, Wideband),
        "truncated AMR ToC"
    );
    // F set on the last ToC entry the payload has room for.
    assert_eq!(
        refused(&[0xF0, 0x84], OctetAligned, Narrowband),
        "truncated AMR ToC"
    );
    // RFC 4867 §4.3.2: frame types 9 to 14 for AMR and 10 to 13 for AMR-WB mean "the whole packet
    // SHOULD be discarded".
    for frame_type in 9..=14u8 {
        assert_eq!(
            refused(&[0xF0, (frame_type << 3) | 0x04], OctetAligned, Narrowband),
            "reserved AMR frame type"
        );
    }
    for frame_type in 10..=13u8 {
        assert_eq!(
            refused(&[0xF0, (frame_type << 3) | 0x04], OctetAligned, Wideband),
            "reserved AMR frame type"
        );
    }
    // A ToC that promises a frame the payload does not hold.
    assert_eq!(
        refused(&[0xF0, 0x04, 0x00], OctetAligned, Narrowband),
        "truncated AMR frame data"
    );
    assert_eq!(
        refused(&[0xF0, 0x40, 0x00], BandwidthEfficient, Narrowband),
        "truncated AMR frame data"
    );
    // RFC 4867 §4.5.1: a length that does not match the ToC, "the receiver SHOULD discard".
    assert_eq!(
        refused(&[0xF0, 0x7C, 0x00], OctetAligned, Narrowband),
        "AMR payload longer than its table of contents describes"
    );
    assert_eq!(
        refused(&[0xF7, 0xC0, 0x00], BandwidthEfficient, Narrowband),
        "AMR payload longer than its table of contents describes"
    );
    // Thirteen frames: one more than a receiver has to accept (3GPP TS 26.114 §7.5.2.1.2.3).
    let mut thirteen = vec![0xF0];
    thirteen.extend([0xFC; 12]);
    thirteen.push(0x7C);
    assert_eq!(
        refused(&thirteen, OctetAligned, Wideband),
        "more AMR frames in one payload than the 12 a receiver accepts"
    );
    thirteen.remove(1);
    assert_eq!(
        read_payload(&thirteen, OctetAligned, Wideband).map(|layout| layout.frames().len()),
        Ok(12)
    );
}

#[test]
fn reserved_and_padding_bits_are_ignored_on_reception() {
    // RFC 4867 §4.4.1: "All R bits MUST be ignored by the receiver." §4.3.4: padding bits "MUST be
    // ignored on reception".
    let layout = read_payload(
        &[0xFF, 0x7F],
        PayloadFormat::OctetAligned,
        Variant::Narrowband,
    )
    .expect("octet-aligned NO_DATA with every spare bit set");
    assert_eq!((layout.cmr, layout.frames()[0].frame_type), (15, 15));
    let layout = read_payload(
        &[0xF7, 0xFF],
        PayloadFormat::BandwidthEfficient,
        Variant::Narrowband,
    )
    .expect("bandwidth-efficient NO_DATA with every padding bit set");
    assert_eq!((layout.cmr, layout.frames()[0].frame_type), (15, 15));
}

#[test]
fn the_writer_refuses_what_it_cannot_frame() {
    let frame = FrameSource {
        frame_type: 0,
        quality_ok: true,
        data: &[0u8; 12],
    };
    let mut out = [0u8; 64];
    let narrowband = |frames: &[FrameSource<'_>], out: &mut [u8]| {
        write_payload(
            PayloadFormat::BandwidthEfficient,
            Variant::Narrowband,
            15,
            frames,
            out,
        )
    };
    assert!(matches!(
        narrowband(&[], &mut out),
        Err(CodecError::Malformed(_))
    ));
    assert_eq!(
        narrowband(&[frame], &mut out[..13]),
        Err(CodecError::OutputTooSmall {
            needed: 14,
            have: 13
        })
    );
    let short = FrameSource {
        data: &[0u8; 11],
        ..frame
    };
    assert!(matches!(
        narrowband(&[short], &mut out),
        Err(CodecError::Malformed(_))
    ));
    let reserved = FrameSource {
        frame_type: 12,
        ..frame
    };
    assert!(matches!(
        narrowband(&[reserved], &mut out),
        Err(CodecError::Malformed(_))
    ));
}

use proptest::prelude::*;

proptest! {
    /// Arbitrary bytes off the network are read or refused, in either format and for either codec:
    /// never a panic, and whatever is read lies inside the payload.
    #[test]
    fn arbitrary_payloads_never_panic_and_never_read_outside_themselves(
        payload in proptest::collection::vec(any::<u8>(), 0..400),
    ) {
        for format in [PayloadFormat::BandwidthEfficient, PayloadFormat::OctetAligned] {
            for variant in [Variant::Narrowband, Variant::Wideband] {
                if let Ok(layout) = read_payload(&payload, format, variant) {
                    prop_assert!(!layout.frames().is_empty());
                    let mut data = [0u8; MAX_FRAME_OCTETS];
                    for slot in layout.frames() {
                        let written = slot.copy_bits(&payload, &mut data);
                        prop_assert_eq!(written, usize::from(slot.bits).div_ceil(8));
                    }
                }
            }
        }
    }

    /// A valid payload with any one octet changed, or cut short anywhere, is read or refused.
    #[test]
    fn damaged_vectors_never_panic(index in 0usize..20, position in 0usize..64, value: u8, cut in 0usize..64) {
        let vector = &vectors()[index];
        let mut damaged = vector.payload.clone();
        let position = position % damaged.len();
        damaged[position] = value;
        let _ = read_payload(&damaged, vector.format, vector.variant);
        let cut = cut % (damaged.len() + 1);
        let _ = read_payload(&damaged[..cut], vector.format, vector.variant);
    }
}

// ── The same vectors, and what the packetiser writes, read by an independent dissector ──────────

/// Whether an external tool is on `PATH`.
fn tool_available(tool: &str) -> bool {
    std::process::Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

/// What `tshark`'s AMR dissector reads in `payload`: (payload format it decoded as, CMR, F bits,
/// frame types, Q bits, expert messages), or `None` when the Wireshark tools are not installed.
///
/// The dissector is told the codec and the payload format through its two preferences, as a
/// receiver is told them by the SDP; it cannot see either in the packet.
fn dissect(
    name: &str,
    payload: &[u8],
    format: PayloadFormat,
    variant: Variant,
) -> Option<(String, String, String, String, String, String)> {
    if !tool_available("tshark") || !tool_available("text2pcap") {
        eprintln!("skipping: tshark / text2pcap not available");
        return None;
    }
    let scratch =
        std::env::temp_dir().join(format!("siphon-rtp-amr-{}-{name}", std::process::id()));
    std::fs::create_dir_all(scratch.join("wireshark")).expect("scratch directory");
    // A minimal RTP header (RFC 3550 §5.1): version 2, payload type 96, then the payload.
    let mut packet = vec![0x80, 96, 0, 1, 0, 0, 0, 160, 0x11, 0x22, 0x33, 0x44];
    packet.extend_from_slice(payload);
    let mut dump = String::new();
    for (index, chunk) in packet.chunks(16).enumerate() {
        dump.push_str(&format!("{:06x} ", index * 16));
        for octet in chunk {
            dump.push_str(&format!(" {octet:02x}"));
        }
        dump.push('\n');
    }
    std::fs::write(scratch.join("packet.hex"), dump).expect("write hex dump");
    let converted = std::process::Command::new("text2pcap")
        .args(["-q", "-u", "5004,5004"])
        .arg(scratch.join("packet.hex"))
        .arg(scratch.join("packet.pcap"))
        .output()
        .expect("run text2pcap");
    assert!(converted.status.success(), "text2pcap failed");
    let tag = match variant {
        Variant::Narrowband => "nb",
        Variant::Wideband => "wb",
    };
    let output = std::process::Command::new("tshark")
        .env("WIRESHARK_CONFIG_DIR", scratch.join("wireshark"))
        .arg("-r")
        .arg(scratch.join("packet.pcap"))
        .args(["-d", "udp.port==5004,rtp", "-d", "rtp.pt==96,amr"])
        .arg("-o")
        .arg(match format {
            PayloadFormat::BandwidthEfficient => "amr.encoding.version:RFC 3267 BW-efficient",
            PayloadFormat::OctetAligned => "amr.encoding.version:RFC 3267 octet aligned",
        })
        .arg("-o")
        .arg(match variant {
            Variant::Narrowband => "amr.mode:AMR-NB",
            Variant::Wideband => "amr.mode:AMR-WB",
        })
        .args(["-T", "fields", "-E", "separator=|", "-E", "occurrence=a"])
        .args(["-E", "aggregator=,", "-e", "amr.payload_decoded_as"])
        .args(["-e", &format!("amr.{tag}.cmr"), "-e", "amr.toc.f"])
        .args(["-e", &format!("amr.{tag}.toc.ft"), "-e", "amr.toc.q"])
        .args(["-e", "_ws.expert.message"])
        .output()
        .expect("run tshark");
    let _ = std::fs::remove_dir_all(&scratch);
    assert!(output.status.success(), "tshark failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|line| line.matches('|').count() == 5)
        .unwrap_or_else(|| panic!("{name}: no dissection in {stdout:?}"));
    let mut fields = line.split('|').map(str::to_owned);
    let mut next = || fields.next().unwrap_or_default();
    Some((next(), next(), next(), next(), next(), next()))
}

/// The dissector's reading of a payload must be the fields the vector was assembled from.
fn assert_dissected(vector: &Vector, payload: &[u8], source: &str) -> bool {
    let Some((decoded_as, cmr, follow, frame_types, quality, expert)) =
        dissect(vector.name, payload, vector.format, vector.variant)
    else {
        return false;
    };
    let name = vector.name;
    let list = |values: Vec<String>| values.join(",");
    let flag = |set: bool| if set { "True" } else { "False" }.to_owned();
    // 0 is octet-aligned, 1 bandwidth-efficient: the preference took.
    let expected_format = match vector.format {
        PayloadFormat::OctetAligned => "0",
        PayloadFormat::BandwidthEfficient => "1",
    };
    assert_eq!(decoded_as, expected_format, "{name} ({source})");
    assert_eq!(cmr, vector.cmr.to_string(), "{name} ({source}) CMR");
    let count = vector.frames.len();
    assert_eq!(
        follow,
        list((0..count).map(|index| flag(index + 1 < count)).collect()),
        "{name} ({source}) F bits"
    );
    assert_eq!(
        frame_types,
        list(vector.frames.iter().map(|f| f.0.to_string()).collect()),
        "{name} ({source}) frame types"
    );
    assert_eq!(
        quality,
        list(vector.frames.iter().map(|f| flag(f.1)).collect()),
        "{name} ({source}) Q bits"
    );
    // Wireshark 4.6 miscounts the octets of an octet-aligned payload with more than one frame: its
    // loop adds the running bit total of all frames so far for every ToC entry
    // (`packet-amr.c`: `bits_used_for_frames += ...; bytes_needed_for_frames +=
    // (bits_used_for_frames + 7)/8`), so the first frame is counted once per entry. The layout
    // here is the one RFC 4867 §4.4.5.1 draws, each frame on its own octet boundary, and the
    // dissector reads every field of it; only that length check is left out for those vectors.
    if vector.format == PayloadFormat::OctetAligned && count > 1 {
        let mut running_bits = 0;
        let mut miscount = 0;
        for frame in &vector.frames {
            running_bits += frame.2;
            miscount += running_bits.div_ceil(8);
        }
        let available: usize = vector.frames.iter().map(|f| f.2.div_ceil(8)).sum();
        assert!(
            expert.starts_with(&format!(
                "Error: {available} Bytes available, {miscount} would be needed!"
            )),
            "{name}: {expert}"
        );
    } else {
        assert_eq!(expert, "", "{name} ({source}) dissector faults");
    }
    eprintln!(
        "TSHARK {name} ({source}): decoded as {decoded_as}, CMR {cmr}, F [{follow}], \
         FT [{frame_types}], Q [{quality}], faults [{expert}]"
    );
    true
}

#[test]
fn an_independent_dissector_reads_the_vectors_and_the_packetiser_output_alike() {
    for vector in vectors() {
        if !assert_dissected(&vector, &vector.payload, "hand-assembled") {
            return;
        }
        // What the packetiser writes for the same frames, from a dirty buffer.
        let data: Vec<Vec<u8>> = vector
            .frames
            .iter()
            .map(|&(_, _, bits, period)| frame_octets(bits, period))
            .collect();
        let frames: Vec<FrameSource<'_>> = vector
            .frames
            .iter()
            .zip(&data)
            .map(|(&(frame_type, quality_ok, _, _), data)| FrameSource {
                frame_type,
                quality_ok,
                data,
            })
            .collect();
        let mut out = [0xFFu8; 256];
        let length = write_payload(vector.format, vector.variant, vector.cmr, &frames, &mut out)
            .expect("write");
        assert_dissected(&vector, &out[..length], "packetiser");
    }
}

#[test]
fn the_dissector_faults_a_payload_read_in_the_format_it_was_not_sent_in() {
    // The control for the test above: the dissector does tell the two formats apart, so a clean
    // reading there is evidence. A bandwidth-efficient speech frame read as octet-aligned has
    // reserved bits set or the wrong length.
    let vector = vectors()
        .into_iter()
        .find(|vector| vector.name == "wb-be-mode2-cmr0")
        .expect("vector");
    // CMR 0 leaves the reserved bits to the ToC entry: F=0 FT=2 puts a 1 in them.
    let Some((_, _, _, _, _, expert)) = dissect(
        "control",
        &vector.payload,
        PayloadFormat::OctetAligned,
        Variant::Wideband,
    ) else {
        return;
    };
    assert_ne!(expert, "", "a misread payload must not dissect cleanly");
}
