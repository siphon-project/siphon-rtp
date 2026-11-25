//! The depacketizer against Wireshark's EVS dissector, an independent reader of TS 26.445 Annex A.
//!
//! Test payloads are written as hex dumps, turned into a pcap with `text2pcap -u`, and dissected by
//! `tshark` as RTP with the dynamic payload type decoded as EVS. For each one the dissector's
//! account of the payload (compact or header-full, whether there is a CMR octet and what it says,
//! every table-of-contents entry's `F` bit, EVS-mode bit, `Q` bit and frame type) must be the one
//! the fixture was written to mean, and ours. A payload the dissector shows as malformed is a
//! mistake in the fixture or in our understanding of the format.
//!
//! Skips when `tshark` or `text2pcap` is not installed; `SIPHON_RTP_REQUIRE_WIRESHARK=1` makes that a
//! failure.
#![cfg(feature = "evs")]
#![allow(clippy::expect_used, reason = "test harness: a panic reports failure")]

use std::collections::BTreeMap;
use std::io::Write;
use std::process::Command;

use siphon_rtp_codec::evs::rtp::{Cmr, FrameType, Packet, PayloadFormat};

const UDP_PORT: u16 = 40000;
const DYNAMIC_PAYLOAD_TYPE: u8 = 96;

fn required() -> bool {
    std::env::var("SIPHON_RTP_REQUIRE_WIRESHARK").is_ok_and(|value| value == "1")
}

fn scratch(name: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let serial = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "siphon-rtp-evs-{name}-{}-{serial}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// One `frame number -> field -> values` table from `tshark -T fields`.
type Fields = BTreeMap<usize, BTreeMap<String, Vec<String>>>;

/// Dissect `payloads` (one RTP packet each) and return the values of `fields` per packet, or
/// `None` when Wireshark is not installed.
fn dissect(payloads: &[Vec<u8>], fields: &[&str]) -> Option<Fields> {
    let dir = scratch("ws");
    let mut dump = String::new();
    for payload in payloads {
        let mut packet = vec![
            0x80,
            DYNAMIC_PAYLOAD_TYPE,
            0,
            1,
            0,
            0,
            0,
            160,
            0x11,
            0x22,
            0x33,
            0x44,
        ];
        packet.extend_from_slice(payload);
        for (line, chunk) in packet.chunks(16).enumerate() {
            dump.push_str(&format!("{:04x}", line * 16));
            for octet in chunk {
                dump.push_str(&format!(" {octet:02x}"));
            }
            dump.push('\n');
        }
        dump.push('\n');
    }
    let text = dir.join("in.txt");
    std::fs::File::create(&text)
        .ok()?
        .write_all(dump.as_bytes())
        .ok()?;
    let pcap = dir.join("out.pcap");
    let converted = Command::new("text2pcap")
        .env("HOME", &dir)
        .args(["-q", "-u", &format!("{UDP_PORT},{UDP_PORT}")])
        .arg(&text)
        .arg(&pcap)
        .output()
        .ok()?;
    assert!(converted.status.success(), "text2pcap: {converted:?}");
    let mut command = Command::new("tshark");
    command
        .env("HOME", &dir)
        .arg("-r")
        .arg(&pcap)
        .args(["-d", &format!("udp.port=={UDP_PORT},rtp")])
        .args(["-d", &format!("rtp.pt=={DYNAMIC_PAYLOAD_TYPE},evs")])
        .args([
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=,",
        ])
        .args(["-e", "frame.number"]);
    for field in fields {
        command.args(["-e", field]);
    }
    let output = command.output().ok()?;
    assert!(output.status.success(), "tshark: {output:?}");
    let mut table = Fields::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut columns = line.split('|');
        let number: usize = columns.next()?.parse().ok()?;
        let row = table.entry(number).or_default();
        for (field, value) in fields.iter().zip(columns) {
            row.insert(
                (*field).to_string(),
                value
                    .split(',')
                    .filter(|v| !v.is_empty())
                    .map(str::to_string)
                    .collect(),
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    Some(table)
}

fn wireshark_present() -> bool {
    let present = ["tshark", "text2pcap"].iter().all(|tool| {
        Command::new(tool)
            .arg("--version")
            .env("HOME", std::env::temp_dir())
            .output()
            .is_ok_and(|output| output.status.success())
    });
    if !present {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_WIRESHARK=1 but tshark or text2pcap is not installed"
        );
        eprintln!("skipping: tshark and text2pcap are not installed");
    }
    present
}

/// A header-full payload from its parts: an optional CMR octet, the table-of-contents octets
/// (the last one's `F` bit is set here, the others clear), and each frame's octets.
fn header_full(cmr: Option<u8>, entries: &[(u8, usize)], padding: usize) -> Vec<u8> {
    let mut payload: Vec<u8> = cmr.into_iter().collect();
    for (index, (toc, _)) in entries.iter().enumerate() {
        let more = index + 1 < entries.len();
        payload.push((toc & !0x40) | if more { 0x40 } else { 0 });
    }
    for (index, (_, octets)) in entries.iter().enumerate() {
        payload.extend((0..*octets).map(|offset| (index * 31 + offset * 7 + 1) as u8 & 0x7F));
    }
    payload.resize(payload.len() + padding, 0);
    payload
}

/// Frame type index and octets of each table-of-contents octet used below.
const TOC_PRIMARY_13200: (u8, usize) = (0x04, 33);
const TOC_PRIMARY_SID: (u8, usize) = (0x0C, 6);
const TOC_PRIMARY_2800: (u8, usize) = (0x00, 7);
const TOC_IO_885: (u8, usize) = (0x31, 23);
const TOC_IO_885_DAMAGED: (u8, usize) = (0x21, 23);
const TOC_IO_2385: (u8, usize) = (0x38, 60);
const TOC_IO_SID: (u8, usize) = (0x39, 5);
const TOC_NO_DATA: (u8, usize) = (0x0F, 0);
const TOC_IO_NO_DATA: (u8, usize) = (0x3F, 0);
const TOC_LOST: (u8, usize) = (0x0E, 0);

const FIELDS: &[&str] = &[
    "evs.h_bit",
    "evs.f_bit",
    "evs.mode_bit",
    "evs.amr_wb_q_bit",
    "evs.bit_rate_mode_0",
    "evs.bit_rate_mode_1",
    "evs.cmr_t",
    "evs.packet_length",
    "_ws.malformed",
];

fn bools(values: &[String]) -> Vec<bool> {
    values
        .iter()
        .map(|value| value == "True" || value == "1")
        .collect()
}

fn numbers(values: &[String]) -> Vec<u32> {
    values
        .iter()
        .map(|value| value.parse().expect("number"))
        .collect()
}

#[test]
fn header_full_payloads_read_as_the_dissector_reads_them() {
    if !wireshark_present() {
        return;
    }
    let payloads = vec![
        header_full(None, &[TOC_PRIMARY_13200], 0),
        header_full(Some(0xFF), &[TOC_PRIMARY_13200], 0),
        header_full(Some(0x84), &[TOC_PRIMARY_SID], 0),
        header_full(Some(0xA4), &[TOC_PRIMARY_13200, TOC_PRIMARY_13200], 0),
        header_full(
            Some(0x93),
            &[TOC_IO_885, TOC_IO_885_DAMAGED, TOC_NO_DATA],
            2,
        ),
        header_full(Some(0xFF), &[TOC_IO_SID], 0),
        header_full(Some(0xD5), &[TOC_IO_2385], 3),
        header_full(
            None,
            &[TOC_NO_DATA, TOC_NO_DATA, TOC_IO_NO_DATA, TOC_LOST],
            0,
        ),
        header_full(
            Some(0xC9),
            &[TOC_PRIMARY_13200, TOC_IO_885, TOC_PRIMARY_SID],
            1,
        ),
        header_full(Some(0xFF), &[TOC_PRIMARY_2800], 0),
    ];
    let table = dissect(&payloads, FIELDS).expect("dissect");
    for (index, payload) in payloads.iter().enumerate() {
        let row = &table[&(index + 1)];
        assert!(
            row["_ws.malformed"].is_empty(),
            "payload {index}: {payload:02x?} is malformed"
        );
        assert!(
            row["evs.packet_length"].is_empty(),
            "payload {index} is header-full, not compact"
        );

        let packet =
            Packet::parse(payload, true).unwrap_or_else(|error| panic!("{payload:02x?}: {error}"));
        assert_eq!(packet.format(), PayloadFormat::HeaderFull);
        let frames: Vec<_> = packet.frames().collect();

        // H bits: a leading CMR octet, then one 0 per table-of-contents entry
        let h_bits = bools(&row["evs.h_bit"]);
        assert_eq!(
            h_bits.len(),
            frames.len() + usize::from(packet.cmr().is_some()),
            "payload {index}"
        );
        assert_eq!(
            h_bits.first().copied(),
            Some(packet.cmr().is_some()),
            "payload {index}"
        );

        // F: every entry but the last
        let more: Vec<bool> = (0..frames.len())
            .map(|position| position + 1 < frames.len())
            .collect();
        assert_eq!(bools(&row["evs.f_bit"]), more, "payload {index}: F bits");

        // E and Q
        let modes: Vec<bool> = frames
            .iter()
            .map(|frame| frame.frame_type.is_amr_wb_io())
            .collect();
        assert_eq!(
            bools(&row["evs.mode_bit"]),
            modes,
            "payload {index}: EVS-mode bits"
        );
        let q_bits: Vec<bool> = frames
            .iter()
            .filter(|frame| frame.frame_type.is_amr_wb_io())
            .map(|frame| frame.quality_ok)
            .collect();
        assert_eq!(
            bools(&row["evs.amr_wb_q_bit"]),
            q_bits,
            "payload {index}: Q bits"
        );

        // frame types, primary entries and AMR-WB IO entries in their own fields
        let primary: Vec<u32> = frames
            .iter()
            .filter(|frame| !frame.frame_type.is_amr_wb_io())
            .map(|frame| u32::from(frame.frame_type.frame_type_index()))
            .collect();
        let io: Vec<u32> = frames
            .iter()
            .filter(|frame| frame.frame_type.is_amr_wb_io())
            .map(|frame| u32::from(frame.frame_type.frame_type_index()))
            .collect();
        assert_eq!(
            numbers(&row["evs.bit_rate_mode_0"]),
            primary,
            "payload {index}: primary types"
        );
        assert_eq!(
            numbers(&row["evs.bit_rate_mode_1"]),
            io,
            "payload {index}: AMR-WB IO types"
        );

        // the CMR request type
        match (payload[0] & 0x80 != 0, numbers(&row["evs.cmr_t"]).first()) {
            (true, Some(&selector)) => {
                assert_eq!(
                    selector,
                    u32::from((payload[0] >> 4) & 7),
                    "payload {index}"
                );
                assert!(packet.cmr().is_some());
            }
            (false, None) => assert!(packet.cmr().is_none()),
            other => panic!("payload {index}: CMR disagreement {other:?}"),
        }
    }
}

#[test]
fn every_payload_size_is_compact_or_header_full_as_the_dissector_says() {
    if !wireshark_present() {
        return;
    }
    // zeros of every length up to the largest compact size (the first bit of the 56-bit one is 0)
    let payloads: Vec<Vec<u8>> = (1..=330).map(|octets| vec![0u8; octets]).collect();
    let table = dissect(&payloads, FIELDS).expect("dissect");
    let mut compact_sizes = Vec::new();
    for (index, payload) in payloads.iter().enumerate() {
        let row = &table[&(index + 1)];
        let dissector_compact = !row["evs.packet_length"].is_empty();
        let ours = Packet::parse(payload, false);
        let our_compact = ours
            .as_ref()
            .is_ok_and(|packet| packet.format() == PayloadFormat::Compact);
        assert_eq!(our_compact, dissector_compact, "{} octets", payload.len());
        if dissector_compact {
            let bits: u32 = row["evs.packet_length"][0].parse().expect("bits");
            assert_eq!(bits as usize, payload.len() * 8);
            compact_sizes.push(bits);
        }
    }
    assert_eq!(
        compact_sizes,
        [
            48, 56, 136, 144, 160, 184, 192, 256, 264, 288, 320, 328, 368, 400, 464, 480, 488, 640,
            960, 1280, 1920, 2560
        ],
        "the dissector's 22 compact sizes"
    );
}

#[test]
fn a_56_bit_payload_is_the_2k8_frame_or_an_io_sid_behind_a_cmr_octet() {
    if !wireshark_present() {
        return;
    }
    let primary = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE];
    let io_sid = header_full(Some(0xFF), &[TOC_IO_SID], 0);
    assert_eq!(primary.len(), 7);
    assert_eq!(io_sid.len(), 7);
    let table = dissect(&[primary.clone(), io_sid.clone()], FIELDS).expect("dissect");
    // the first bit decides (A.2.1.3): the dissector agrees with us on both
    assert!(
        !table[&1]["evs.packet_length"].is_empty(),
        "first bit 0 is the compact 2.8 kbit/s frame"
    );
    assert!(
        table[&2]["evs.packet_length"].is_empty(),
        "first bit 1 is header-full"
    );
    assert!(table[&2]["_ws.malformed"].is_empty());
    let compact = Packet::parse(&primary, false).expect("compact");
    assert_eq!(compact.format(), PayloadFormat::Compact);
    assert!(matches!(
        compact.frames().next().expect("frame").frame_type,
        FrameType::Primary(_)
    ));
    let sid = Packet::parse(&io_sid, false).expect("header-full");
    assert_eq!(sid.format(), PayloadFormat::HeaderFull);
    assert_eq!(
        sid.frames().next().expect("frame").frame_type,
        FrameType::AmrWbIoSid
    );
}

#[test]
fn every_cmr_octet_is_labelled_as_we_read_it() {
    if !wireshark_present() {
        return;
    }
    let octets: Vec<u8> = (0x80..=0xFFu8).collect();
    let payloads: Vec<Vec<u8>> = octets
        .iter()
        .map(|&cmr| header_full(Some(cmr), &[TOC_NO_DATA], 0))
        .collect();
    let table = dissect(&payloads, &["evs.cmr_t", "_ws.malformed"]).expect("dissect");
    for (index, &octet) in octets.iter().enumerate() {
        assert!(
            table[&(index + 1)]["_ws.malformed"].is_empty(),
            "{octet:#04x}"
        );
        assert_eq!(
            numbers(&table[&(index + 1)]["evs.cmr_t"]),
            [u32::from((octet >> 4) & 7)]
        );
        assert!(!matches!(Cmr::from_octet(octet), Cmr::AmrWbIoCompact(_)));
    }
}
