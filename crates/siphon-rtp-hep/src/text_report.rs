//! RFC 4103 Real-Time Text content-QoS report: the per-leg T.140 reception counters the userspace
//! text processor measured over a call, serialized to the compact JSON document the engine ships to a
//! HEP collector (VoIPmonitor / Homer) as the payload of a HEP3 **report** capture
//! (`protocol_type` = [`crate::protocol_type::REPORT_JSON`], type 35).
//!
//! # Why a documented siphon-rtp extension, not a standard chunk
//!
//! HEP3 (Homer/`captagent`) has **no** standard field or chunk for Real-Time Text content QoS — the
//! standard captures are SIP, RTP, RTCP and the JSON "report" (type 35) Homer already ingests for
//! voice MOS. Rather than invent a new vendor chunk (which a collector could not parse and which would
//! risk colliding with the generic chunk ids), this rides the **existing** report-capture transport
//! that [`crate::report::QosReport`] uses — the *same* `protocol_type` 35, the *same* PAYLOAD chunk
//! (`0x000f`) carrying a JSON document, correlated by the *same* [`crate::chunk::CORRELATION_ID`]
//! (`0x0011`) = call-id. Only the **JSON schema** is a siphon-rtp extension, and it is
//! self-describing: the first field is a discriminator `"report":"rtt-text"` so a collector routes it
//! without a full parse and never confuses it with the voice report (which has no `report` field).
//! This does not alter the wire shape of any existing HEP packet — a text report is its own datagram.
//!
//! ## Wire / JSON layout (a siphon-rtp extension over HEP3 report capture type 35)
//!
//! The HEP3 packet is exactly what [`crate::Capture::encode`] emits (magic `HEP3`, 16-bit total
//! length, then the generic TLV chunks: IP family/protocol, src/dst address + port, timestamp,
//! `PROTOCOL_TYPE` = 35, `CAPTURE_AGENT_ID`, `CORRELATION_ID` = call-id, `PAYLOAD`). The PAYLOAD chunk
//! carries this compact UTF-8 JSON document (field order fixed; `report` first as the discriminator):
//!
//! ```json
//! {"report":"rtt-text","correlation_id":"<call-id>","tag":"<leg-tag>","direction":"a_to_b",
//!  "packets":<u64>,"characters":<u64>,"missing_markers":<u64>,"recovered_from_redundancy":<u64>}
//! ```
//!
//! - `packets` — RTP packets accepted on this leg's inbound T.140 stream (RFC 4103).
//! - `characters` — UTF-8 characters delivered after RED depacketization + T.140 reassembly,
//!   including U+FFFD missing-text markers.
//! - `missing_markers` — U+FFFD markers inserted for gaps RED redundancy could not recover
//!   (RFC 4103 §5.3): the unrecoverable-loss signal.
//! - `recovered_from_redundancy` — generations recovered from RFC 2198 RED redundancy (RFC 4103 §4.2).

/// A per-leg RFC 4103 Real-Time Text content-QoS report, emitted at end-of-call as a HEP3 report
/// capture. Distinct from [`crate::report::QosReport`] (voice MOS): text QoS is a *content-level*
/// figure — what the receiver actually recovered — not an E-model score, so it carries no MOS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextQosReport {
    /// The call-id — the HEP correlation id, identical to the call's voice/RTCP captures so a
    /// collector groups this text report with the rest of the call.
    pub correlation_id: String,
    /// The tag of the leg that **sent** this text stream (the offerer's `from_tag` for `a_to_b`, the
    /// answerer's `to_tag` for `b_to_a`) — mirrors the CDR's per-direction attribution.
    pub tag: String,
    /// The observed direction: `"a_to_b"` (offerer → answerer) or `"b_to_a"`.
    pub direction: &'static str,
    /// RTP packets accepted on this leg's inbound text stream (post source-gate).
    pub packets: u64,
    /// UTF-8 characters delivered after reassembly (includes redundancy-recovered characters and the
    /// U+FFFD missing-text markers).
    pub characters: u64,
    /// Missing-text markers (U+FFFD) inserted for gaps redundancy could not recover (RFC 4103 §5.3).
    pub missing_markers: u64,
    /// Generations recovered from RFC 2198 RED redundancy (RFC 4103 §4.2 / §5).
    pub recovered_from_redundancy: u64,
}

impl TextQosReport {
    /// Serialize to the compact JSON document the HEP collector ingests as a report-capture payload.
    /// The `"report":"rtt-text"` discriminator is emitted first (see the module docs). String fields
    /// are JSON-escaped (RFC 8259 §7) via the shared [`crate::report`] escaper — the call-id and leg
    /// tag can carry `@`, quotes, or control bytes.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                r#"{{"report":"rtt-text","correlation_id":"{cid}","tag":"{tag}","#,
                r#""direction":"{direction}","packets":{packets},"characters":{characters},"#,
                r#""missing_markers":{missing},"recovered_from_redundancy":{recovered}}}"#
            ),
            cid = crate::report::escape(&self.correlation_id),
            tag = crate::report::escape(&self.tag),
            direction = self.direction,
            packets = self.packets,
            characters = self.characters,
            missing = self.missing_markers,
            recovered = self.recovered_from_redundancy,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TextQosReport {
        TextQosReport {
            correlation_id: "call-1@host".into(),
            tag: "tag-a".into(),
            direction: "a_to_b",
            packets: 12,
            characters: 40,
            missing_markers: 1,
            recovered_from_redundancy: 2,
        }
    }

    #[test]
    fn json_carries_the_discriminator_first_and_every_counter() {
        let json = sample().to_json();
        // The discriminator is the first field so a streaming collector classifies without a full parse.
        assert!(
            json.starts_with(r#"{"report":"rtt-text","#),
            "rtt-text discriminator leads: {json}"
        );
        assert!(json.contains(r#""correlation_id":"call-1@host""#));
        assert!(json.contains(r#""tag":"tag-a""#));
        assert!(json.contains(r#""direction":"a_to_b""#));
        assert!(json.contains(r#""packets":12"#));
        assert!(json.contains(r#""characters":40"#));
        assert!(json.contains(r#""missing_markers":1"#));
        assert!(json.contains(r#""recovered_from_redundancy":2"#));
        assert!(json.ends_with('}'));
    }

    #[test]
    fn json_is_distinguishable_from_a_voice_report() {
        // A voice QoS report has no "report" field and carries "mos"/"codec"; the text report carries
        // neither, so a collector never confuses the two type-35 payloads.
        let json = sample().to_json();
        assert!(!json.contains(r#""mos""#), "text report carries no MOS");
        assert!(!json.contains(r#""codec""#), "text report carries no codec");
    }

    #[test]
    fn escapes_the_call_id_and_tag() {
        let report = TextQosReport {
            correlation_id: "weird\"id\nwith ctl".into(),
            tag: "t\\g".into(),
            direction: "b_to_a",
            packets: 0,
            characters: 0,
            missing_markers: 0,
            recovered_from_redundancy: 0,
        };
        let json = report.to_json();
        // The quote, newline and backslash are escaped, keeping the JSON well-formed.
        assert!(json.contains(r#"weird\"id\nwith ctl"#));
        assert!(json.contains(r#""tag":"t\\g""#));
        assert!(!json.contains('\n'));
    }

    #[test]
    fn direction_round_trips_both_ways() {
        let mut report = sample();
        report.direction = "b_to_a";
        assert!(report.to_json().contains(r#""direction":"b_to_a""#));
    }
}
