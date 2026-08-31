//! Validate the emitted TS 103 221-2 framing against an **independent** decoder.
//!
//! The framing has an authoritative external definition, so a round-trip against this crate's own
//! reader proves nothing — a shared encode/decode bug passes one. These tests hand the bytes we
//! actually emit to a third-party Wireshark dissector via `tshark` and assert it reads back the
//! fields we intended. It does not share our bugs, which is exactly what makes it evidence.
//!
//! A field the dissector shows as missing, malformed or wrong is an encoder bug on our side, not a
//! limitation of the decoder — check our output first.
//!
//! Skips (rather than fails) when the dissector or the Wireshark tools are absent, matching how the
//! codec reference-vector tests behave. Run `reference/x2x3-dissector/fetch.sh` to enable it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;

use siphon_rtp_li::attributes::{attribute_type, AttributeWriter, IP_PROTOCOL_UDP};
use siphon_rtp_li::clock::WallClockAnchor;
use siphon_rtp_li::{encode, PayloadDirection, PduHeader, HEADER_LEN};

/// The UDP port the synthetic capture uses; `tshark` is told to decode it as X2/X3.
const DISSECT_PORT: u16 = 30000;

/// A 16-byte interception task identifier. Fixed test bytes — never provisioning data.
const XID: [u8; 16] = [
    0x8c, 0x29, 0x2f, 0xa1, 0x58, 0x31, 0x46, 0xec, 0x86, 0xbe, 0xbd, 0x85, 0xf2, 0x08, 0x32, 0x99,
];
/// A non-zero session correlation (TS 103 221-2 clause 6).
const CORRELATION_ID: u64 = 0x0102_0304_0506_0708;

/// Path to the fetched dissector, or `None` when it has not been fetched.
fn dissector_path() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../reference/x2x3-dissector/x2x3PduDissector.lua");
    path.exists().then_some(path)
}

/// Whether an external tool is on `PATH`.
fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

/// The prerequisites for these tests, or a reason to skip.
fn prerequisites() -> Option<PathBuf> {
    let Some(dissector) = dissector_path() else {
        eprintln!(
            "skipping: reference/x2x3-dissector/x2x3PduDissector.lua not fetched \
             (run reference/x2x3-dissector/fetch.sh)"
        );
        return None;
    };
    for tool in ["tshark", "text2pcap"] {
        if !tool_available(tool) {
            eprintln!("skipping: {tool} not available");
            return None;
        }
    }
    Some(dissector)
}

/// Render `bytes` as the offset-and-hex dump `text2pcap` consumes.
fn hex_dump(bytes: &[u8]) -> String {
    let mut dump = String::new();
    for (index, chunk) in bytes.chunks(16).enumerate() {
        dump.push_str(&format!("{:06x} ", index * 16));
        for byte in chunk {
            dump.push_str(&format!(" {byte:02x}"));
        }
        dump.push('\n');
    }
    dump
}

/// Wrap `pdu` in a synthetic UDP capture and run the third-party dissector over it, returning
/// `tshark`'s stdout. `output_args` selects the output shape (`-V` for the detail tree, `-T fields`
/// plus `-e` for named fields).
///
/// Everything `tshark` touches — the capture, the Lua script and a writable Wireshark config
/// directory — is staged inside one temporary directory. The dissector is *copied* there rather
/// than referenced in place: it keeps the invocation independent of the working directory, and a
/// sandboxed or confined `tshark` that cannot read the source tree still runs the gate.
fn run_dissector(dissector: &PathBuf, pdu: &[u8], output_args: &[&str]) -> String {
    let scratch = tempfile::tempdir().expect("tempdir");
    let hex_path = scratch.path().join("pdu.hex");
    let pcap_path = scratch.path().join("pdu.pcap");
    let script_path = scratch.path().join("x2x3PduDissector.lua");
    // Wireshark writes a preferences file on startup; point it somewhere writable so a read-only or
    // absent HOME does not turn into a spurious failure.
    let config_dir = scratch.path().join("wireshark");
    std::fs::create_dir_all(&config_dir).expect("config dir");
    std::fs::write(&hex_path, hex_dump(pdu)).expect("write hex dump");
    std::fs::copy(dissector, &script_path).expect("stage dissector");

    let text2pcap = Command::new("text2pcap")
        .arg("-q")
        .arg("-u")
        .arg(format!("{DISSECT_PORT},{DISSECT_PORT}"))
        .arg(&hex_path)
        .arg(&pcap_path)
        .output()
        .expect("run text2pcap");
    assert!(
        text2pcap.status.success(),
        "text2pcap failed: {}",
        String::from_utf8_lossy(&text2pcap.stderr)
    );

    let mut command = Command::new("tshark");
    command
        .env("WIRESHARK_CONFIG_DIR", &config_dir)
        .arg("-q")
        .arg("-r")
        .arg(&pcap_path)
        .arg("-X")
        .arg(format!("lua_script:{}", script_path.display()))
        .arg("-d")
        .arg(format!("udp.port=={DISSECT_PORT},x2x3"));
    for argument in output_args {
        command.arg(argument);
    }
    let output = command.output().expect("run tshark");
    assert!(
        output.status.success(),
        "tshark failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Dissect `pdu` and return the requested field values in order.
///
/// `-T fields` rather than the full tree so each assertion names one field: a failure says which
/// field is wrong, not "the output changed".
fn dissect_fields(dissector: &PathBuf, pdu: &[u8], fields: &[&str]) -> Vec<String> {
    let mut arguments = vec!["-T", "fields"];
    for field in fields {
        arguments.push("-e");
        arguments.push(field);
    }
    let stdout = run_dissector(dissector, pdu, &arguments);
    let line = stdout.lines().next().unwrap_or_default();
    line.split('\t').map(str::to_string).collect()
}

/// Dissect `pdu` and return the decoder's full detail tree, for the attribute assertions.
fn dissect_tree(dissector: &PathBuf, pdu: &[u8]) -> String {
    run_dissector(dissector, pdu, &["-V"])
}

/// One G.711 RTP frame: 12-byte header, PT 0, sequence 4660, timestamp 320, SSRC 0xdeadbeef.
fn rtp_packet() -> Vec<u8> {
    let mut packet = vec![
        0x80, 0x00, 0x12, 0x34, 0x00, 0x00, 0x01, 0x40, 0xde, 0xad, 0xbe, 0xef,
    ];
    packet.extend(std::iter::repeat_n(0xd5, 160));
    packet
}

/// A fully-populated X3 media PDU: every conditional attribute the engine emits, wrapped around one
/// RTP frame.
fn x3_media_pdu(
    direction: PayloadDirection,
    source: SocketAddr,
    destination: SocketAddr,
) -> Vec<u8> {
    let anchor = WallClockAnchor::new(1_788_177_600 * 1_000_000_000, 0);
    let (seconds, nanoseconds) = anchor.timestamp(123_456);

    let mut attributes = Vec::new();
    AttributeWriter::new(&mut attributes)
        .network_function_id("siphon-rtp-sbc-01")
        .interception_point_id("media-relay-a")
        .sequence_number(42)
        .timestamp(seconds, nanoseconds)
        .source(source)
        .destination(destination)
        .ip_protocol(IP_PROTOCOL_UDP);

    let mut pdu = Vec::new();
    encode(
        &PduHeader::x3_rtp(XID, CORRELATION_ID, direction),
        &attributes,
        &rtp_packet(),
        &mut pdu,
    )
    .expect("encode");
    pdu
}

#[test]
fn an_independent_decoder_reads_back_every_header_field() {
    let Some(dissector) = prerequisites() else {
        return;
    };
    let source = "203.0.113.9:16384".parse().expect("source");
    let destination = "198.51.100.4:20000".parse().expect("destination");
    let pdu = x3_media_pdu(PayloadDirection::FromTarget, source, destination);

    let values = dissect_fields(
        &dissector,
        &pdu,
        &[
            "x2x3.version",
            "x2x3.pduType",
            "x2x3.headerLength",
            "x2x3.payloadLength",
            "x2x3.payloadFormat",
            "x2x3.payloadDirection",
            "x2x3.xid",
            "x2x3.correlationId",
        ],
    );

    // The version is the field a real Mediation Function rejects a PDU over, so it is asserted
    // against the third party rather than against our own constant.
    assert_eq!(values[0], "0x0005", "version must be major 0, minor 5");
    assert_eq!(values[1], "2", "PDU type must be 2 (X3)");
    assert_eq!(
        values[2].parse::<usize>().expect("header length"),
        pdu.len() - rtp_packet().len(),
        "header length must cover the fixed header plus the attribute block"
    );
    assert_eq!(
        values[3].parse::<usize>().expect("payload length"),
        rtp_packet().len(),
        "payload length must cover only the RTP packet"
    );
    assert_eq!(values[4], "8", "payload format must be 8 (RTP packet)");
    assert_eq!(
        values[5], "3",
        "payload direction must be 3 (sent from target)"
    );
    assert_eq!(values[6], "8c292fa1-5831-46ec-86be-bd85f2083299");
    assert_eq!(values[7], "0x0102030405060708");
}

#[test]
fn an_independent_decoder_walks_every_conditional_attribute() {
    let Some(dissector) = prerequisites() else {
        return;
    };
    let source = "203.0.113.9:16384".parse().expect("source");
    let destination = "198.51.100.4:20000".parse().expect("destination");
    let tree = dissect_tree(
        &dissector,
        &x3_media_pdu(PayloadDirection::FromTarget, source, destination),
    );

    // Every attribute must be *named* by the decoder, which only happens if the preceding one's
    // length was right — the walk is strictly `4 + length`, so one wrong length desynchronises the
    // whole block and the later attributes come out as unknown types.
    for expected in [
        "Network Function ID",
        "Interception Point ID",
        "Sequence Number",
        "Timestamp",
        "Source IPv4 address",
        "Source Port",
        "Destination IPv4 address",
        "Destination Port",
        "IP Protocol",
    ] {
        assert!(
            tree.contains(expected),
            "decoder did not report the {expected} attribute:\n{tree}"
        );
    }

    // Values, not just presence.
    assert!(tree.contains("siphon-rtp-sbc-01"), "NFID value:\n{tree}");
    assert!(tree.contains("media-relay-a"), "IPID value:\n{tree}");
    assert!(tree.contains("203.0.113.9"), "source address:\n{tree}");
    assert!(tree.contains("16384"), "source port:\n{tree}");
    assert!(
        tree.contains("198.51.100.4"),
        "destination address:\n{tree}"
    );
    assert!(tree.contains("20000"), "destination port:\n{tree}");
    assert!(tree.contains("UDP (Value)"), "IP protocol:\n{tree}");
    // The timestamp is an absolute wall-clock time. A monotonic since-boot reading leaking into it
    // would decode as 1970, which is the defect `WallClockAnchor` exists to prevent.
    assert!(
        tree.contains("2026-08-31"),
        "timestamp must decode as an absolute date:\n{tree}"
    );
}

#[test]
fn an_independent_decoder_parses_the_payload_as_rtp() {
    let Some(dissector) = prerequisites() else {
        return;
    };
    let source = "203.0.113.9:16384".parse().expect("source");
    let destination = "198.51.100.4:20000".parse().expect("destination");
    let tree = dissect_tree(
        &dissector,
        &x3_media_pdu(PayloadDirection::FromTarget, source, destination),
    );

    // The payload is declared as format 8, so the decoder hands it to Wireshark's own RTP
    // dissector. That it reads back as the RTP we framed is end-to-end proof the payload is
    // delivered verbatim and at the right offset.
    assert!(
        tree.contains("Real-Time Transport Protocol"),
        "payload must dissect as RTP:\n{tree}"
    );
    assert!(
        tree.contains("Payload type: ITU-T G.711 PCMU (0)"),
        "{tree}"
    );
    assert!(tree.contains("Sequence number: 4660"), "{tree}");
    assert!(tree.contains("Timestamp: 320"), "{tree}");
    assert!(
        tree.contains("Synchronization Source identifier: 0xdeadbeef"),
        "{tree}"
    );
}

#[test]
fn an_independent_decoder_distinguishes_the_two_target_relative_directions() {
    let Some(dissector) = prerequisites() else {
        return;
    };
    let source = "203.0.113.9:16384".parse().expect("source");
    let destination = "198.51.100.4:20000".parse().expect("destination");

    for (direction, expected) in [
        (PayloadDirection::ToTarget, "2"),
        (PayloadDirection::FromTarget, "3"),
    ] {
        let pdu = x3_media_pdu(direction, source, destination);
        let values = dissect_fields(&dissector, &pdu, &["x2x3.payloadDirection"]);
        assert_eq!(
            values[0], expected,
            "direction {direction:?} must reach the wire as {expected}"
        );
    }
}

#[test]
fn an_independent_decoder_reads_an_ipv6_leg() {
    let Some(dissector) = prerequisites() else {
        return;
    };
    // A v6 leg emits attribute types 12/13 with 16-byte values instead of 10/11 with 4-byte ones.
    // If the family selection or the length were wrong, the walk would desynchronise here.
    let source = "[2001:db8::1]:16384".parse().expect("source");
    let destination = "[2001:db8::2]:20000".parse().expect("destination");
    let tree = dissect_tree(
        &dissector,
        &x3_media_pdu(PayloadDirection::FromTarget, source, destination),
    );

    assert!(tree.contains("Source IPv6 address"), "{tree}");
    assert!(tree.contains("Destination IPv6 address"), "{tree}");
    assert!(tree.contains("2001:db8::1"), "{tree}");
    assert!(tree.contains("2001:db8::2"), "{tree}");
    assert!(
        tree.contains("Real-Time Transport Protocol"),
        "the payload must still be found at the right offset on a v6 leg:\n{tree}"
    );
}

#[test]
fn an_independent_decoder_reads_a_keepalive() {
    let Some(dissector) = prerequisites() else {
        return;
    };
    let mut pdu = Vec::new();
    encode(&PduHeader::keepalive(), &[], &[], &mut pdu).expect("encode");
    assert_eq!(pdu.len(), HEADER_LEN);

    let values = dissect_fields(
        &dissector,
        &pdu,
        &["x2x3.pduType", "x2x3.payloadFormat", "x2x3.payloadLength"],
    );
    assert_eq!(values[0], "3", "PDU type must be 3 (keepalive)");
    assert_eq!(values[1], "0", "payload format must be 0 (keepalive)");
    assert_eq!(values[2], "0", "a keepalive carries no payload");
}

#[test]
fn an_odd_length_attribute_does_not_desynchronise_the_walk() {
    let Some(dissector) = prerequisites() else {
        return;
    };
    // The IP-protocol attribute is one byte. If the writer padded it to a 4-byte boundary — or if
    // the decoder expected padding — everything after it would be misread. Put it first, then two
    // attributes whose values the decoder prints, and assert both survive.
    let mut attributes = Vec::new();
    AttributeWriter::new(&mut attributes)
        .ip_protocol(IP_PROTOCOL_UDP)
        .raw(attribute_type::NETWORK_FUNCTION_ID, b"odd")
        .sequence_number(0x0a0b_0c0d);

    let mut pdu = Vec::new();
    encode(
        &PduHeader::x3_rtp(XID, CORRELATION_ID, PayloadDirection::FromTarget),
        &attributes,
        &rtp_packet(),
        &mut pdu,
    )
    .expect("encode");

    let tree = dissect_tree(&dissector, &pdu);
    assert!(tree.contains("UDP (Value)"), "{tree}");
    assert!(
        tree.contains("odd"),
        "a 3-byte attribute after a 1-byte one must still be read:\n{tree}"
    );
    assert!(
        tree.contains("Sequence Number"),
        "the attribute after two odd-length ones must still be read:\n{tree}"
    );
    assert!(
        tree.contains("Real-Time Transport Protocol"),
        "the payload must still start at Header Length:\n{tree}"
    );
}
