//! QoS report: the RTCP-derived impairments plus an E-model MOS, serialized to the compact JSON
//! document the engine ships to Homer as the payload of a HEP3 report capture (`protocol_type 35`).

use crate::mos::{self, Codec, Impairments};

/// A per-stream voice-quality report over one RTCP interval.
#[derive(Debug, Clone, PartialEq)]
pub struct QosReport {
    /// The call-id (used as the HEP correlation id so Homer groups both legs).
    pub correlation_id: String,
    /// The reporting stream's synchronization source.
    pub ssrc: u32,
    /// The codec name (see [`Codec::name`]).
    pub codec: &'static str,
    /// Packet loss over the interval (percent).
    pub loss_percent: f64,
    /// Interarrival jitter (ms).
    pub jitter_ms: f64,
    /// One-way mouth-to-ear delay (ms).
    pub one_way_delay_ms: f64,
    /// The E-model R-factor.
    pub r_factor: f64,
    /// The estimated Mean Opinion Score.
    pub mos: f64,
}

impl QosReport {
    /// Build a report for `codec` under `impairments`, computing the R-factor and MOS.
    #[must_use]
    pub fn new(
        correlation_id: impl Into<String>,
        ssrc: u32,
        codec: Codec,
        impairments: Impairments,
    ) -> Self {
        let r_factor = mos::r_factor(codec, impairments);
        Self {
            correlation_id: correlation_id.into(),
            ssrc,
            codec: codec.name(),
            loss_percent: impairments.loss_percent,
            jitter_ms: impairments.jitter_ms,
            one_way_delay_ms: impairments.one_way_delay_ms,
            r_factor,
            mos: mos::mos(r_factor),
        }
    }

    /// Serialize to the compact JSON document Homer ingests as a report-capture payload.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                r#"{{"correlation_id":"{cid}","ssrc":{ssrc},"codec":"{codec}","#,
                r#""loss_percent":{loss:.2},"jitter_ms":{jitter:.2},"delay_ms":{delay:.2},"#,
                r#""r_factor":{r:.1},"mos":{mos:.2}}}"#
            ),
            cid = escape(&self.correlation_id),
            ssrc = self.ssrc,
            codec = self.codec,
            loss = self.loss_percent,
            jitter = self.jitter_ms,
            delay = self.one_way_delay_ms,
            r = self.r_factor,
            mos = self.mos,
        )
    }
}

/// Minimal JSON string escaping (RFC 8259 §7) — the call-id can carry `@`, quotes, or control bytes.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> QosReport {
        QosReport::new(
            "call-1@host",
            0x1234_5678,
            Codec::G711,
            Impairments {
                loss_percent: 1.5,
                one_way_delay_ms: 40.0,
                jitter_ms: 5.0,
            },
        )
    }

    #[test]
    fn computes_r_factor_and_mos() {
        let report = sample();
        assert_eq!(report.codec, "G711");
        assert!(report.mos > 4.0 && report.mos < 4.4, "light loss G.711: {}", report.mos);
        assert!(report.r_factor > 80.0);
    }

    #[test]
    fn json_has_expected_fields_and_escapes_the_call_id() {
        let report = QosReport::new(
            "weird\"id\nwith ctl",
            7,
            Codec::Opus,
            Impairments {
                loss_percent: 0.0,
                one_way_delay_ms: 0.0,
                jitter_ms: 0.0,
            },
        );
        let json = report.to_json();
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains(r#""ssrc":7"#));
        assert!(json.contains(r#""codec":"Opus""#));
        assert!(json.contains(r#""mos":"#));
        // The quote and newline in the call-id are escaped, keeping the JSON well-formed.
        assert!(json.contains(r#"weird\"id\nwith ctl"#));
        assert!(!json.contains('\n'));
    }
}
