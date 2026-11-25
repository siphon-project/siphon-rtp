use super::*;

/// The 22 compact sizes in octets, with what each is.
const COMPACT: [(usize, &str); 22] = [
    (6, "sid"),
    (7, "2800"),
    (17, "io0"),
    (18, "7200"),
    (20, "8000"),
    (23, "io1"),
    (24, "9600"),
    (32, "io2"),
    (33, "13200"),
    (36, "io3"),
    (40, "io4"),
    (41, "16400"),
    (46, "io5"),
    (50, "io6"),
    (58, "io7"),
    (60, "io8"),
    (61, "24400"),
    (80, "32000"),
    (120, "48000"),
    (160, "64000"),
    (240, "96000"),
    (320, "128000"),
];

fn type_of(payload: &[u8], header_full_only: bool) -> FrameType {
    Packet::parse(payload, header_full_only)
        .expect("parses")
        .frames()
        .next()
        .expect("a frame")
        .frame_type
}

#[test]
fn every_compact_size_is_one_frame_of_the_type_that_size_names() {
    for (octets, label) in COMPACT {
        let payload = vec![0u8; octets];
        let packet = Packet::parse(&payload, false).expect(label);
        assert_eq!(packet.format(), PayloadFormat::Compact, "{label}");
        assert_eq!(packet.frame_count(), 1, "{label}");
        let frame = packet.frames().next().expect(label);
        assert!(frame.quality_ok, "{label}: a compact frame has no Q bit");
        let expected = match label {
            "sid" => FrameType::PrimarySid,
            "2800" => FrameType::Primary(PrimaryRate::Rate2800),
            "7200" => FrameType::Primary(PrimaryRate::Rate7200),
            "8000" => FrameType::Primary(PrimaryRate::Rate8000),
            "9600" => FrameType::Primary(PrimaryRate::Rate9600),
            "13200" => FrameType::Primary(PrimaryRate::Rate13200),
            "16400" => FrameType::Primary(PrimaryRate::Rate16400),
            "24400" => FrameType::Primary(PrimaryRate::Rate24400),
            "32000" => FrameType::Primary(PrimaryRate::Rate32000),
            "48000" => FrameType::Primary(PrimaryRate::Rate48000),
            "64000" => FrameType::Primary(PrimaryRate::Rate64000),
            "96000" => FrameType::Primary(PrimaryRate::Rate96000),
            "128000" => FrameType::Primary(PrimaryRate::Rate128000),
            io => FrameType::AmrWbIo(
                AmrWbIoMode::from_index(io[2..].parse().expect("mode")).expect("mode"),
            ),
        };
        assert_eq!(frame.frame_type, expected, "{label}");
        // an AMR-WB IO frame carries its 3-bit CMR, an EVS primary frame none
        assert_eq!(packet.cmr().is_some(), label.starts_with("io"), "{label}");
    }
}

#[test]
fn a_compact_primary_frame_is_the_payload_bit_for_bit() {
    let payload: Vec<u8> = (0..33u8)
        .map(|index| index.wrapping_mul(37).wrapping_add(5))
        .collect();
    let packet = Packet::parse(&payload, false).expect("compact");
    let frame = packet.frames().next().expect("frame");
    let mut bits = [0u8; 2560];
    assert_eq!(frame.decoder_bits(&mut bits), 264);
    for (index, &bit) in bits[..264].iter().enumerate() {
        assert_eq!(
            bit,
            (payload[index / 8] >> (7 - index % 8)) & 1,
            "bit {index}"
        );
    }
}

/// A.2.1.2: a compact AMR-WB IO frame is CMR (3 bits), `d(1)` .. `d(n-1)`, `d(0)`, padding. Set one
/// payload bit at a time and see where the decoder gets it: payload bit `n + 2` is `d(0)`, payload
/// bit `k + 2` is `d(k)`, and `d(k)` is the decoder's bit `SORT_660[k]`.
#[test]
fn a_compact_amr_wb_io_frame_has_its_first_bit_last_and_is_sorted() {
    let table = &SORT_TABLES[0];
    for position in 0..136 {
        let mut payload = [0u8; 17];
        payload[position / 8] |= 0x80 >> (position % 8);
        let packet = Packet::parse(&payload, false).expect("compact");
        let frame = packet.frames().next().expect("frame");
        let mut bits = [0u8; 2560];
        assert_eq!(frame.decoder_bits(&mut bits), 132);
        let set: Vec<usize> = (0..132).filter(|&index| bits[index] == 1).collect();
        match position {
            0..=2 => {
                // the CMR
                assert!(set.is_empty(), "payload bit {position}");
                assert_eq!(packet.cmr(), Some(Cmr::AmrWbIoCompact(1 << (2 - position))));
            }
            3..=133 => {
                let k = position - 2;
                assert_eq!(
                    set,
                    [usize::from(table[k])],
                    "payload bit {position} is d({k})"
                );
            }
            134 => assert_eq!(set, [usize::from(table[0])], "payload bit 134 is d(0)"),
            _ => assert!(set.is_empty(), "padding bit {position}"),
        }
    }
}

#[test]
fn the_8_85_compact_frame_ends_after_177_speech_bits() {
    // 3 + 177 = 180 bits of 184: the last four are padding (reference: payload bits - 7)
    let table = &SORT_TABLES[1];
    let mut payload = [0u8; 23];
    payload[22] = 0x10; // bit 179 (the last used one) is d(0)
    let packet = Packet::parse(&payload, false).expect("compact");
    let mut bits = [0u8; 2560];
    let frame = packet.frames().next().expect("frame");
    assert_eq!(frame.decoder_bits(&mut bits), 177);
    assert_eq!(
        (0..177)
            .filter(|&index| bits[index] == 1)
            .collect::<Vec<_>>(),
        [usize::from(table[0])]
    );
    // and the last padding bit is nothing
    let mut padded = [0u8; 23];
    padded[22] = 0x01;
    let packet = Packet::parse(&padded, false).expect("compact");
    assert_eq!(
        packet
            .frames()
            .next()
            .expect("frame")
            .decoder_bits(&mut bits),
        177
    );
    assert!(bits[..177].iter().all(|&bit| bit == 0));
}

#[test]
fn header_full_only_reads_a_compact_size_as_header_full() {
    // 33 octets is the compact 13.2 kbit/s frame; with hf-only=1 the first octet is a ToC entry
    let mut payload = vec![0u8; 33];
    payload[0] = 0x0F; // NO_DATA, last
    let packet = Packet::parse(&payload, true).expect("header-full");
    assert_eq!(packet.format(), PayloadFormat::HeaderFull);
    assert_eq!(
        type_of(&payload, true),
        FrameType::NoData { amr_wb_io: false }
    );
    // the same octets without hf-only are a 13.2 kbit/s frame
    assert_eq!(
        type_of(&payload, false),
        FrameType::Primary(PrimaryRate::Rate13200)
    );
    // trailing octets after the last frame are padding (A.2.3.1: a header-full payload of a compact
    // size is padded so it is not mistaken for one), so a zero payload of 61 octets with hf-only is
    // one 2.8 kbit/s frame and 53 octets of padding
    let padded = Packet::parse(&[0u8; 61], true).expect("header-full");
    assert_eq!(padded.frame_count(), 1);
    assert_eq!(
        padded.frames().next().expect("frame").frame_type,
        FrameType::Primary(PrimaryRate::Rate2800)
    );
}

#[test]
fn a_56_bit_payload_is_decided_by_its_first_bit() {
    // first bit 0: the 2.8 kbit/s frame
    let primary = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE];
    assert_eq!(
        type_of(&primary, false),
        FrameType::Primary(PrimaryRate::Rate2800)
    );
    // first bit 1: a CMR octet, an IO SID entry and its 5 octets
    let sid = [0xFF, 0x39, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let packet = Packet::parse(&sid, false).expect("header-full");
    assert_eq!(packet.format(), PayloadFormat::HeaderFull);
    assert_eq!(packet.cmr(), Some(Cmr::NoRequest));
    assert_eq!(type_of(&sid, false), FrameType::AmrWbIoSid);
    // hf-only never reads the first as compact: its first octet is then an 8 kbit/s entry whose
    // 20 octets are not there
    assert_eq!(
        Packet::parse(&primary, true).err(),
        Some(PayloadError::TruncatedFrame)
    );
}

#[test]
fn the_primary_sid_is_the_48_bit_payload() {
    let sid = [0x80 >> 7, 2, 3, 4, 5, 6];
    assert_eq!(type_of(&sid, false), FrameType::PrimarySid);
    assert_eq!(FrameType::PrimarySid.speech_bits(), 48);
}

#[test]
fn a_header_full_payload_carries_every_frame_of_its_table_of_contents() {
    // CMR, three entries (13.2, IO 8.85 with Q, NO_DATA), the frames, one octet of padding
    let mut payload = vec![0xFF, 0x44, 0x71, 0x0F];
    payload.extend((0..33).map(|index| index as u8));
    payload.extend((0..23).map(|index| 100 + index as u8));
    payload.push(0);
    payload.push(0); // sizes are not 60/61 octets
    let packet = Packet::parse(&payload, false).expect("header-full");
    assert_eq!(packet.format(), PayloadFormat::HeaderFull);
    assert_eq!(packet.cmr(), Some(Cmr::NoRequest));
    assert_eq!(packet.frame_count(), 3);
    let frames: Vec<_> = packet.frames().collect();
    assert_eq!(
        frames[0].frame_type,
        FrameType::Primary(PrimaryRate::Rate13200)
    );
    assert_eq!(
        frames[1].frame_type,
        FrameType::AmrWbIo(AmrWbIoMode::from_index(1).expect("mode"))
    );
    assert!(frames[1].quality_ok);
    assert_eq!(frames[2].frame_type, FrameType::NoData { amr_wb_io: false });
    // the first frame's bits are the octets after the table of contents
    let mut bits = [0u8; 2560];
    assert_eq!(frames[0].decoder_bits(&mut bits), 264);
    assert_eq!(
        &bits[..16],
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    // the second frame's first octet is the 34th payload octet after the ToC
    assert_eq!(frames[1].frame_type.stored_bits(), 177);
}

#[test]
fn the_q_bit_is_read_for_amr_wb_io_and_ignored_for_primary() {
    // IO 6.6 with Q clear, then primary 7.2 with the unused bit set
    let mut damaged = vec![0x40 | 0x20, 0x10 | 0x01];
    damaged.extend(vec![0u8; 17 + 18]);
    let packet = Packet::parse(&damaged, true).expect("two frames");
    let frames: Vec<_> = packet.frames().collect();
    assert!(
        !frames[0].quality_ok,
        "an AMR-WB IO entry with Q = 0 is damaged"
    );
    assert!(
        frames[1].quality_ok,
        "the Q position of a primary entry is unused"
    );
}

#[test]
fn a_lost_or_missing_frame_has_no_bits_and_keeps_the_mode_it_names() {
    let payload = [0x4E, 0x6F, 0x6E, 0x0F];
    let packet = Packet::parse(&payload, true).expect("four entries");
    let types: Vec<_> = packet.frames().map(|frame| frame.frame_type).collect();
    assert_eq!(
        types,
        [
            FrameType::SpeechLost { amr_wb_io: false },
            FrameType::NoData { amr_wb_io: true },
            FrameType::SpeechLost { amr_wb_io: true },
            FrameType::NoData { amr_wb_io: false },
        ]
    );
    for frame in packet.frames() {
        let mut bits = [0u8; 8];
        assert_eq!(frame.decoder_bits(&mut bits), 0);
        assert_eq!(frame.frame_type.stored_bits(), 0);
    }
}

#[test]
fn an_amr_wb_io_sid_carries_its_sti_and_cmi_after_the_35_bits() {
    // ToC IO SID with Q; 35 bits (bit 3 set), then STI = 1, then CMI = 0b1010
    let mut bits = [0u8; 40];
    bits[35] = 1; // STI: SID_UPDATE
    bits[36..40].copy_from_slice(&[1, 0, 1, 0]);
    bits[3] = 1;
    let mut octets = [0u8; 5];
    for (index, &bit) in bits.iter().enumerate() {
        octets[index / 8] |= bit << (7 - index % 8);
    }
    let mut payload = vec![0xFF, 0x39];
    payload.extend_from_slice(&octets);
    let packet = Packet::parse(&payload, false).expect("header-full");
    let frame = packet.frames().next().expect("frame");
    assert_eq!(frame.frame_type, FrameType::AmrWbIoSid);
    assert_eq!(frame.sid_update(), Some(true));
    assert_eq!(frame.codec_mode_indication(), Some(0b1010));
    let mut decoded = [0u8; 40];
    assert_eq!(frame.decoder_bits(&mut decoded), 35);
    assert_eq!(decoded[3], 1);
    assert!(decoded[..35]
        .iter()
        .enumerate()
        .all(|(index, &bit)| (index == 3) == (bit == 1)));
    // STI = 0 is SID_FIRST: clear bit 35, the 4th bit from the top of the 5th octet (offset 2 + 4)
    payload[2 + 4] &= !0x10;
    let first = Packet::parse(&payload, false).expect("header-full");
    assert_eq!(
        first.frames().next().expect("frame").sid_update(),
        Some(false)
    );
    // any other frame has neither
    let other = Packet::parse(&[0x0F], true).expect("NO_DATA");
    let nothing = other.frames().next().expect("frame");
    assert_eq!(nothing.sid_update(), None);
    assert_eq!(nothing.codec_mode_indication(), None);
}

#[test]
fn frame_types_the_specification_reserves_are_refused() {
    // primary 13 (0x0D), AMR-WB IO 10 to 13 (0x2A..=0x2D)
    for toc in [0x0D, 0x2A, 0x2B, 0x2C, 0x2D, 0x3A, 0x3D] {
        assert_eq!(
            Packet::parse(&[toc, 0, 0, 0], true).map(|packet| packet.frame_count()),
            Err(PayloadError::ReservedFrameType),
            "{toc:#04x}"
        );
    }
}

#[test]
fn malformed_payloads_are_refused_with_a_reason() {
    assert_eq!(Packet::parse(&[], false).err(), Some(PayloadError::Empty));
    assert_eq!(Packet::parse(&[], true).err(), Some(PayloadError::Empty));
    // a CMR octet and nothing else, and a ToC entry that says another follows
    assert_eq!(
        Packet::parse(&[0xFF], false).err(),
        Some(PayloadError::TruncatedToc)
    );
    assert_eq!(
        Packet::parse(&[0x4F], false).err(),
        Some(PayloadError::TruncatedToc)
    );
    assert_eq!(
        Packet::parse(&[0xFF, 0x4F, 0x4F], false).err(),
        Some(PayloadError::TruncatedToc)
    );
    // two CMR octets
    assert_eq!(
        Packet::parse(&[0xFF, 0xFF, 0x0F], false).err(),
        Some(PayloadError::CmrInsteadOfToc)
    );
    // a ToC entry that follows another with the CMR's H bit set
    assert_eq!(
        Packet::parse(&[0x4F, 0x8F, 0x0F], false).err(),
        Some(PayloadError::CmrInsteadOfToc)
    );
    // a frame that does not fit: 13.2 kbit/s needs 33 octets
    let mut short = vec![0x04];
    short.extend(vec![0u8; 20]);
    assert_eq!(
        Packet::parse(&short, false).err(),
        Some(PayloadError::TruncatedFrame)
    );
    // thirteen NO_DATA entries are more than a packet may carry
    let mut many = vec![0x4F; MAX_FRAMES_PER_PACKET];
    many.push(0x0F);
    assert_eq!(
        Packet::parse(&many, false).err(),
        Some(PayloadError::TooManyFrames)
    );
    let mut allowed = vec![0x4F; MAX_FRAMES_PER_PACKET - 1];
    allowed.push(0x0F);
    assert_eq!(
        Packet::parse(&allowed, false).map(|packet| packet.frame_count()),
        Ok(MAX_FRAMES_PER_PACKET)
    );
}

#[test]
fn every_error_has_a_reason_and_converts_to_a_codec_error() {
    for error in [
        PayloadError::Empty,
        PayloadError::TruncatedToc,
        PayloadError::CmrInsteadOfToc,
        PayloadError::ReservedFrameType,
        PayloadError::TruncatedFrame,
        PayloadError::TooManyFrames,
    ] {
        assert!(!error.reason().is_empty());
        assert!(!error.to_string().is_empty());
        assert_eq!(
            CodecError::from(error),
            CodecError::Malformed(error.reason())
        );
    }
}

#[test]
fn frame_types_know_their_table_of_contents_index_and_mode() {
    assert_eq!(
        FrameType::Primary(PrimaryRate::Rate2800).frame_type_index(),
        0
    );
    assert_eq!(
        FrameType::Primary(PrimaryRate::Rate128000).frame_type_index(),
        11
    );
    assert_eq!(FrameType::PrimarySid.frame_type_index(), 12);
    assert_eq!(FrameType::AmrWbIoSid.frame_type_index(), 9);
    assert_eq!(
        FrameType::SpeechLost { amr_wb_io: true }.frame_type_index(),
        14
    );
    assert_eq!(
        FrameType::NoData { amr_wb_io: false }.frame_type_index(),
        15
    );
    assert!(FrameType::AmrWbIo(AmrWbIoMode::from_index(8).expect("mode")).is_amr_wb_io());
    assert!(!FrameType::PrimarySid.is_amr_wb_io());
    assert_eq!(FrameType::AmrWbIoSid.speech_bits(), 35);
    assert_eq!(FrameType::AmrWbIoSid.stored_bits(), 40);
}

#[test]
fn a_short_output_buffer_is_filled_as_far_as_it_goes() {
    let payload = vec![0xFFu8; 33];
    let packet = Packet::parse(&payload, false).expect("compact");
    let frame = packet.frames().next().expect("frame");
    let mut bits = [9u8; 10];
    assert_eq!(frame.decoder_bits(&mut bits), 10);
    assert_eq!(bits, [1; 10]);
}

proptest::proptest! {
    /// Whatever arrives, the parser answers, and what it accepts it can read to the end: every
    /// frame's bits fit the buffer and the frames fit in the payload.
    #[test]
    fn arbitrary_payloads_are_read_or_refused(
        payload in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..400),
        header_full_only in proptest::prelude::any::<bool>(),
    ) {
        if let Ok(packet) = Packet::parse(&payload, header_full_only) {
            proptest::prop_assert!((1..=MAX_FRAMES_PER_PACKET).contains(&packet.frame_count()));
            let mut seen = 0;
            let mut bits = [0u8; 2560];
            for frame in packet.frames() {
                let count = frame.decoder_bits(&mut bits);
                proptest::prop_assert_eq!(count, frame.frame_type.speech_bits());
                proptest::prop_assert!(bits[..count].iter().all(|&bit| bit <= 1));
                seen += 1;
            }
            proptest::prop_assert_eq!(seen, packet.frame_count());
        }
    }

    /// A.2.3: with hf-only 0 a payload is compact exactly when its size is one of the 22 compact
    /// sizes, except a 7-octet payload with the first bit set; with hf-only 1 it never is.
    #[test]
    fn the_format_follows_the_size_and_the_negotiated_mode(
        payload in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..330),
    ) {
        let compact_size = COMPACT.iter().any(|(octets, _)| *octets == payload.len());
        let io_sid_behind_cmr = payload.len() == 7 && payload[0] & 0x80 != 0;
        let default = Packet::parse(&payload, false);
        proptest::prop_assert_eq!(
            default.as_ref().is_ok_and(|packet| packet.format() == PayloadFormat::Compact),
            compact_size && !io_sid_behind_cmr
        );
        if compact_size && !io_sid_behind_cmr {
            // a compact payload is always readable: it has exactly one frame of the size's type
            proptest::prop_assert_eq!(default.map(|packet| packet.frame_count()), Ok(1));
        }
        let forced = Packet::parse(&payload, true);
        proptest::prop_assert!(forced.is_err() || forced.is_ok_and(|packet| packet.format() == PayloadFormat::HeaderFull));
    }

    /// A header-full payload built from a list of frame types reads back as that list, with its
    /// frame count, whatever CMR octet, padding and bits it has.
    #[test]
    fn a_header_full_payload_reads_back_the_frames_it_was_built_from(
        entries in proptest::collection::vec((0u8..=15, proptest::prelude::any::<bool>(), proptest::prelude::any::<bool>()), 1..=MAX_FRAMES_PER_PACKET),
        cmr in proptest::option::of(0x80u8..=0xFF),
        padding in 0usize..4,
        fill in proptest::prelude::any::<u8>(),
    ) {
        let mut tocs = Vec::new();
        let mut expected = Vec::new();
        for (index, (ft, io, q)) in entries.iter().enumerate() {
            let (ft, io) = (*ft, *io);
            let reserved = if io { (10..=13).contains(&ft) } else { ft == 13 };
            let ft = if reserved { 15 } else { ft };
            let more = index + 1 < entries.len();
            tocs.push(ft | if io { 0x20 | if *q { 0x10 } else { 0 } } else { 0 } | if more { 0x40 } else { 0 });
            expected.push((ft, io, *q));
        }
        let mut payload: Vec<u8> = cmr.into_iter().collect();
        payload.extend_from_slice(&tocs);
        for &(ft, io, _) in &expected {
            let probe = [ft | if io { 0x20 } else { 0 }];
            let size = Packet::parse(&probe, true).map(|packet| packet.frames().next().map_or(0, |frame| frame.frame_type.stored_bits().div_ceil(8)));
            // a lone ToC entry fails for a frame with bits: take the size from the type directly
            let octets = match size {
                Ok(octets) => octets,
                Err(_) => frame_octets(ft, io),
            };
            payload.extend(std::iter::repeat_n(fill, octets));
        }
        payload.extend(std::iter::repeat_n(0u8, padding));
        let packet = Packet::parse(&payload, true).expect("header-full");
        proptest::prop_assert_eq!(packet.frame_count(), expected.len());
        for (frame, (ft, io, q)) in packet.frames().zip(expected) {
            proptest::prop_assert_eq!(frame.frame_type.frame_type_index(), ft);
            proptest::prop_assert_eq!(frame.frame_type.is_amr_wb_io(), io);
            proptest::prop_assert_eq!(frame.quality_ok, !io || q);
        }
    }
}

/// Octets of a frame of table-of-contents type `ft` in the mode `io`.
fn frame_octets(ft: u8, io: bool) -> usize {
    let bits = if io {
        match ft {
            0..=8 => [132, 177, 253, 285, 317, 365, 397, 461, 477][usize::from(ft)],
            9 => 40,
            _ => 0,
        }
    } else {
        match ft {
            0..=11 => PrimaryRate::ALL[usize::from(ft)].bits_per_second() as usize / 50,
            12 => 48,
            _ => 0,
        }
    };
    bits.div_ceil(8)
}
