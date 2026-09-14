//! RFC 6035 voice-quality reports: the `application/vq-rtcpxr` body a SIP reporter sends in the
//! `vq-rtcpxr` event package, by NOTIFY or by PUBLISH (RFC 6035 §3.1, §3.2).
//!
//! The engine measures the media half of a report and ships it in [`Event::CallSummary`]. The SIP
//! half (the Call-ID, the parties' identities, the groups, the dialog) lives in the controller, which
//! is also the one that sends the request. The report is split the same way:
//! [`SessionReport::for_leg`] joins a [`LegSummary`] with the [`SessionIdentity`] the controller
//! supplies, and [`SessionReport::render`] writes the body.
//!
//! The whole RFC 6035 §4.6.1 `SessionReport` grammar is modelled rather than only what the engine
//! measures, so the body is checked against the RFC's own example instead of against itself.
//!
//! # Where the body departs from the RFC's examples
//!
//! The §4.7 examples and the §4.6.1 ABNF disagree in a few places. The ABNF is normative and is
//! followed, except where it cannot be meant literally:
//!
//! - `SSRC` always carries the `0x` prefix the ABNF requires (`%x30.78 1*8HEXDIG`); the examples
//!   leave it off `LocalAddr`.
//! - `SessionInfo` is written in ABNF order, the addresses before the groups, where the examples put
//!   the groups first. Every line is named, so a reader keyed on the names takes either order.
//! - `SessionInfo CRLF` is one line ending, not a line ending and then an empty line, and every
//!   line, the last included, ends in CRLF. That is how both examples read, and an empty line would
//!   end the report early for a line-oriented reader.
//! - No line is folded. The examples continue long lines on an indented line, which the `SWS`
//!   separators allow and which no reader can be required to handle.
//!
//! [`Event::CallSummary`]: crate::Event::CallSummary

use std::net::SocketAddr;

use crate::LegSummary;

/// The SIP event package a report is sent in (RFC 6035 §4.1).
pub const EVENT_PACKAGE: &str = "vq-rtcpxr";

/// The media type of a report body (RFC 6035 §5).
pub const CONTENT_TYPE: &str = "application/vq-rtcpxr";

/// The last second a four-digit RFC 3339 year can express, 9999-12-31T23:59:59Z.
const LAST_REPRESENTABLE_SECOND: u64 = 253_402_300_799;

/// Why a report could not be written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VqReportError {
    /// Something every report has to carry (RFC 6035 §4.6.1) is not known for this leg.
    #[error("{0} is not known for this leg, and RFC 6035 §4.6.1 requires it in every report")]
    Missing(&'static str),
    /// A field holds a character its RFC 6035 §4.6.1 production does not allow there, a line break
    /// above all, which would end the field early and turn the rest of the value into report lines.
    #[error("{0} holds a character RFC 6035 §4.6.1 does not allow there")]
    InvalidText(&'static str),
    /// A number is outside what its RFC 6035 §4.6.1 production can express.
    #[error("{0} is outside the range RFC 6035 §4.6.1 allows")]
    OutOfRange(&'static str),
}

/// The SIP half of a report: what only the controller that owns the dialog knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    /// The dialog's Call-ID (`CallID`, `word ["@" word]`).
    pub call_id: String,
    /// The reporting side, as a SIP name-addr or addr-spec (`LocalID`).
    pub local_id: String,
    /// The other party (`RemoteID`).
    pub remote_id: String,
    /// The party that originated the call (`OrigID`).
    pub originator_id: String,
    /// An aggregation label for the reporting side (`LocalGroup`, `word-plus`).
    pub local_group: String,
    /// An aggregation label for the other party (`RemoteGroup`, `word-plus`).
    pub remote_group: String,
    /// The dialog the media belongs to (`DialogID`), when the controller reports it.
    pub dialog: Option<DialogId>,
}

/// `DialogID` (RFC 6035 §4.6.1): the dialog's Call-ID and, when known, its tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogId {
    /// The dialog's Call-ID (`word ["@" word]`).
    pub call_id: String,
    /// The To tag (`token`).
    pub to_tag: Option<String>,
    /// The From tag (`token`).
    pub from_tag: Option<String>,
}

/// A `VQSessionReport` (RFC 6035 §4.6.1): the report on one media session, the final one when
/// `call_term` is set.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionReport {
    /// `CallTerm`: this is the session's final report.
    pub call_term: bool,
    /// The identification lines.
    pub session: SessionInfo,
    /// What the reporter measured (`LocalMetrics`).
    pub local_metrics: Metrics,
    /// What the peer measured and reported back, when known (`RemoteMetrics`).
    pub remote_metrics: Option<Metrics>,
    /// The dialog the media belongs to (`DialogID`).
    pub dialog: Option<DialogId>,
}

/// The identification lines of a report (RFC 6035 §4.6.1 `SessionInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// `CallID` (`word ["@" word]`).
    pub call_id: String,
    /// `LocalID`: the reporting side, as a SIP name-addr or addr-spec.
    pub local_id: String,
    /// `RemoteID`: the other party.
    pub remote_id: String,
    /// `OrigID`: the party that originated the call.
    pub originator_id: String,
    /// `LocalAddr`: the reporter's media transport and the SSRC it sends (§4.6.2.4).
    pub local_address: MediaSource,
    /// `RemoteAddr`: the peer's media transport and the SSRC it sends (§4.6.2.5).
    pub remote_address: MediaSource,
    /// `LocalGroup` (`word-plus`).
    pub local_group: String,
    /// `RemoteGroup` (`word-plus`).
    pub remote_group: String,
    /// `LocalMAC`, when known.
    pub local_mac: Option<[u8; 6]>,
    /// `RemoteMAC`, when known.
    pub remote_mac: Option<[u8; 6]>,
}

/// One end of the media session: its transport address and the RTP SSRC it sends (§4.6.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaSource {
    /// The IP address and port.
    pub address: SocketAddr,
    /// The RTP SSRC (RFC 3550 §5.1).
    pub ssrc: u32,
}

/// One `LocalMetrics` or `RemoteMetrics` block (RFC 6035 §4.6.1 `Metrics`). Only `Timestamps` is
/// required; a line whose parameters are all absent is left out.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Metrics {
    /// `START`, in seconds since the Unix epoch.
    pub started_at_unix_seconds: u64,
    /// `STOP`, in seconds since the Unix epoch.
    pub stopped_at_unix_seconds: u64,
    /// `SessionDesc`.
    pub session_description: SessionDescription,
    /// `JitterBuffer`.
    pub jitter_buffer: JitterBuffer,
    /// `PacketLoss`.
    pub packet_loss: PacketLoss,
    /// `BurstGapLoss`.
    pub burst_gap_loss: BurstGapLoss,
    /// `Delay`.
    pub delay: Delay,
    /// `Signal`.
    pub signal: Signal,
    /// `QualityEst`.
    pub quality: QualityEstimates,
}

/// `SessionDesc` (RFC 6035 §4.6.2.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionDescription {
    /// `PT`: the RTP payload type.
    pub payload_type: Option<u8>,
    /// `PD`: the codec, by its IANA media-type name where one names it unambiguously.
    pub payload_description: Option<String>,
    /// `SR`: the sample rate in Hz.
    pub sample_rate: Option<u32>,
    /// `PPS`: packets per second.
    pub packets_per_second: Option<u32>,
    /// `FD`: the frame duration in milliseconds.
    pub frame_duration_ms: Option<u32>,
    /// `FO`: octets per frame.
    pub frame_octets: Option<u32>,
    /// `FPP`: frames per packet.
    pub frames_per_packet: Option<u32>,
    /// `FMTP`: the SDP `a=fmtp` parameters.
    pub fmtp: Option<String>,
    /// `PLC`: the packet loss concealment in use.
    pub packet_loss_concealment: Option<PacketLossConcealment>,
    /// `SSUP`: whether silence suppression is on.
    pub silence_suppression: Option<bool>,
}

/// `PLC`: RFC 3611 §4.7.6's packet loss concealment codes, reused unchanged (RFC 6035 §4.6.2.3.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketLossConcealment {
    /// 0.
    Unspecified,
    /// 1.
    Disabled,
    /// 2.
    Enhanced,
    /// 3.
    Standard,
}

impl PacketLossConcealment {
    fn code(self) -> u8 {
        match self {
            PacketLossConcealment::Unspecified => 0,
            PacketLossConcealment::Disabled => 1,
            PacketLossConcealment::Enhanced => 2,
            PacketLossConcealment::Standard => 3,
        }
    }
}

/// `JitterBuffer` (RFC 6035 §4.6.2.6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JitterBuffer {
    /// `JBA`.
    pub adaptation: Option<JitterBufferAdaptation>,
    /// `JBR`: the jitter buffer rate, 0-15 (RFC 3611 §4.7.7).
    pub rate: Option<u8>,
    /// `JBN`: the nominal delay in milliseconds.
    pub nominal_ms: Option<u16>,
    /// `JBM`: the maximum delay in milliseconds.
    pub maximum_ms: Option<u16>,
    /// `JBX`: the absolute maximum delay in milliseconds.
    pub absolute_maximum_ms: Option<u16>,
}

/// `JBA`: RFC 3611 §4.7.7's jitter buffer adaptation codes, reused unchanged (RFC 6035 §4.6.2.6.1).
/// Code 1 is reserved there, so it has no variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterBufferAdaptation {
    /// 0.
    Unknown,
    /// 2.
    NonAdaptive,
    /// 3.
    Adaptive,
}

impl JitterBufferAdaptation {
    fn code(self) -> u8 {
        match self {
            JitterBufferAdaptation::Unknown => 0,
            JitterBufferAdaptation::NonAdaptive => 2,
            JitterBufferAdaptation::Adaptive => 3,
        }
    }
}

/// `PacketLoss` (RFC 6035 §4.6.2.7), as percentages.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PacketLoss {
    /// `NLR`: the network loss rate.
    pub network_loss_percent: Option<f64>,
    /// `JDR`: the jitter buffer discard rate.
    pub discard_percent: Option<f64>,
}

/// `BurstGapLoss` (RFC 6035 §4.6.2.8).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BurstGapLoss {
    /// `BLD`: the burst loss density, as a percentage.
    pub burst_density_percent: Option<f64>,
    /// `BD`: the burst duration in milliseconds.
    pub burst_duration_ms: Option<u32>,
    /// `GLD`: the gap loss density, as a percentage.
    pub gap_density_percent: Option<f64>,
    /// `GD`: the gap duration in milliseconds.
    pub gap_duration_ms: Option<u32>,
    /// `GMIN`: the minimum gap threshold, 1-255.
    pub minimum_gap_threshold: Option<u8>,
}

/// `Delay` (RFC 6035 §4.6.2.9), in milliseconds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Delay {
    /// `RTD`: the round-trip delay.
    pub round_trip_ms: Option<u16>,
    /// `ESD`: the end system delay.
    pub end_system_ms: Option<u16>,
    /// `OWD`: the one-way delay.
    pub one_way_ms: Option<u16>,
    /// `SOWD`: the symmetric one-way delay.
    pub symmetric_one_way_ms: Option<u16>,
    /// `IAJ`: the RFC 3550 interarrival jitter.
    pub interarrival_jitter_ms: Option<u16>,
    /// `MAJ`: the mean absolute jitter.
    pub mean_absolute_jitter_ms: Option<u16>,
}

/// `Signal` (RFC 6035 §4.6.2.10).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signal {
    /// `SL`: the signal level in dBm0.
    pub signal_level_dbm0: Option<i8>,
    /// `NL`: the noise level in dBm0.
    pub noise_level_dbm0: Option<i8>,
    /// `RERL`: the residual echo return loss in dB.
    pub residual_echo_return_loss_db: Option<u8>,
}

/// `QualityEst` (RFC 6035 §4.6.2.11).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QualityEstimates {
    /// `RLQ`: the listening quality R factor.
    pub listening_r: Option<u8>,
    /// `RLQEstAlg`.
    pub listening_r_algorithm: Option<String>,
    /// `RCQ`: the conversational quality R factor.
    pub conversational_r: Option<u8>,
    /// `RCQEstAlg`.
    pub conversational_r_algorithm: Option<String>,
    /// `EXTRI`: the external R factor, inbound.
    pub external_r_in: Option<u8>,
    /// `ExtRIEstAlg`.
    pub external_r_in_algorithm: Option<String>,
    /// `EXTRO`: the external R factor, outbound.
    pub external_r_out: Option<u8>,
    /// `ExtROEstAlg`.
    pub external_r_out_algorithm: Option<String>,
    /// `MOSLQ`: the listening quality MOS.
    pub mos_lq: Option<f64>,
    /// `MOSLQEstAlg`.
    pub mos_lq_algorithm: Option<String>,
    /// `MOSCQ`: the conversational quality MOS.
    pub mos_cq: Option<f64>,
    /// `MOSCQEstAlg`.
    pub mos_cq_algorithm: Option<String>,
    /// `QoEEstAlg`: the one algorithm behind every estimate.
    pub algorithm: Option<String>,
}

impl SessionReport {
    /// The final report (`VQSessionReport: CallTerm`) for one leg of an [`Event::CallSummary`],
    /// reported from the engine's side of that leg. `LocalAddr` is the engine's media address toward
    /// the party with the SSRC the engine sent it, `RemoteAddr` is where the party sent from with the
    /// SSRC it sent, and `LocalMetrics` is what the engine measured on that stream. The timestamps
    /// are the summary's `started_at_unix_ms` and `ended_at_unix_ms`.
    ///
    /// Fails with [`VqReportError::Missing`] when the leg lacks something every report has to carry.
    /// A leg the engine relayed without a userspace media actor has no measured SSRC, so it has no
    /// report.
    ///
    /// The MOS goes into `MOSCQ` only when it includes the G.107 delay term (`mos_basis` is `"full"`).
    /// One estimated from loss and jitter alone is not the conversational score that parameter
    /// defines, so it is left out rather than labelled as one.
    ///
    /// [`Event::CallSummary`]: crate::Event::CallSummary
    pub fn for_leg(
        identity: SessionIdentity,
        leg: &LegSummary,
        started_at_unix_ms: Option<u64>,
        ended_at_unix_ms: Option<u64>,
    ) -> Result<Self, VqReportError> {
        let local_address = leg
            .local_address
            .ok_or(VqReportError::Missing("local_address"))?;
        let egress_ssrc = leg
            .egress_ssrc
            .ok_or(VqReportError::Missing("egress_ssrc"))?;
        let remote_address = leg
            .remote_address
            .ok_or(VqReportError::Missing("remote_address"))?;
        let ssrc = leg.ssrc.ok_or(VqReportError::Missing("ssrc"))?;
        let started_at = started_at_unix_ms.ok_or(VqReportError::Missing("started_at_unix_ms"))?;
        let ended_at = ended_at_unix_ms.ok_or(VqReportError::Missing("ended_at_unix_ms"))?;
        let conversational_mos = leg
            .mos_average
            .filter(|_| leg.mos_basis.as_deref() == Some("full"));
        Ok(Self {
            call_term: true,
            session: SessionInfo {
                call_id: identity.call_id,
                local_id: identity.local_id,
                remote_id: identity.remote_id,
                originator_id: identity.originator_id,
                local_address: MediaSource {
                    address: local_address,
                    ssrc: egress_ssrc,
                },
                remote_address: MediaSource {
                    address: remote_address,
                    ssrc,
                },
                local_group: identity.local_group,
                remote_group: identity.remote_group,
                local_mac: None,
                remote_mac: None,
            },
            local_metrics: Metrics {
                started_at_unix_seconds: started_at / 1000,
                stopped_at_unix_seconds: ended_at / 1000,
                session_description: SessionDescription {
                    payload_type: leg.payload_type,
                    payload_description: leg.codec.clone(),
                    ..SessionDescription::default()
                },
                packet_loss: PacketLoss {
                    network_loss_percent: leg.loss_percent,
                    discard_percent: None,
                },
                delay: Delay {
                    round_trip_ms: leg.rtt_ms.map(whole_milliseconds),
                    interarrival_jitter_ms: leg.jitter_ms.map(whole_milliseconds),
                    ..Delay::default()
                },
                quality: QualityEstimates {
                    mos_cq: conversational_mos,
                    mos_cq_algorithm: conversational_mos.map(|_| "G.107".to_string()),
                    ..QualityEstimates::default()
                },
                ..Metrics::default()
            },
            remote_metrics: None,
            dialog: identity.dialog,
        })
    }

    /// The report body, one CRLF-terminated line per field, to send as [`CONTENT_TYPE`].
    pub fn render(&self) -> Result<String, VqReportError> {
        let mut body = String::new();
        body.push_str(if self.call_term {
            "VQSessionReport: CallTerm\r\n"
        } else {
            "VQSessionReport\r\n"
        });
        self.session.render(&mut body)?;
        body.push_str("LocalMetrics:\r\n");
        self.local_metrics.render(&mut body)?;
        if let Some(remote_metrics) = &self.remote_metrics {
            body.push_str("RemoteMetrics:\r\n");
            remote_metrics.render(&mut body)?;
        }
        if let Some(dialog) = &self.dialog {
            dialog.render(&mut body)?;
        }
        Ok(body)
    }
}

impl SessionInfo {
    fn render(&self, body: &mut String) -> Result<(), VqReportError> {
        push_line(body, "CallID", call_id_parameter("CallID", &self.call_id)?);
        push_line(body, "LocalID", sip_identity("LocalID", &self.local_id)?);
        push_line(body, "RemoteID", sip_identity("RemoteID", &self.remote_id)?);
        push_line(body, "OrigID", sip_identity("OrigID", &self.originator_id)?);
        push_line(body, "LocalAddr", &self.local_address.render());
        push_line(body, "RemoteAddr", &self.remote_address.render());
        push_line(
            body,
            "LocalGroup",
            word_plus("LocalGroup", &self.local_group)?,
        );
        push_line(
            body,
            "RemoteGroup",
            word_plus("RemoteGroup", &self.remote_group)?,
        );
        if let Some(mac) = self.local_mac {
            push_line(body, "LocalMAC", &mac_address(mac));
        }
        if let Some(mac) = self.remote_mac {
            push_line(body, "RemoteMAC", &mac_address(mac));
        }
        Ok(())
    }
}

impl MediaSource {
    fn render(&self) -> String {
        format!(
            "IP={} PORT={} SSRC=0x{:08x}",
            self.address.ip(),
            self.address.port(),
            self.ssrc
        )
    }
}

impl Metrics {
    fn render(&self, body: &mut String) -> Result<(), VqReportError> {
        if self.stopped_at_unix_seconds < self.started_at_unix_seconds {
            return Err(VqReportError::OutOfRange("Timestamps"));
        }
        let timestamps = format!(
            "START={} STOP={}",
            date_time(self.started_at_unix_seconds)?,
            date_time(self.stopped_at_unix_seconds)?
        );
        push_line(body, "Timestamps", &timestamps);
        self.session_description.render(body)?;
        self.jitter_buffer.render(body)?;
        self.packet_loss.render(body)?;
        self.burst_gap_loss.render(body)?;
        self.delay.render(body)?;
        self.signal.render(body)?;
        self.quality.render(body)
    }
}

impl SessionDescription {
    fn render(&self, body: &mut String) -> Result<(), VqReportError> {
        let parameters = [
            self.payload_type
                .map(|value| integer("PT", u32::from(value), 127))
                .transpose()?,
            self.payload_description
                .as_deref()
                .map(payload_description)
                .transpose()?,
            self.sample_rate
                .map(|value| integer("SR", value, 999_999))
                .transpose()?,
            self.packets_per_second
                .map(|value| integer("PPS", value, 99_999))
                .transpose()?,
            self.frame_duration_ms
                .map(|value| integer("FD", value, 9_999))
                .transpose()?,
            self.frame_octets
                .map(|value| integer("FO", value, 99_999))
                .transpose()?,
            self.frames_per_packet
                .map(|value| integer("FPP", value, 99))
                .transpose()?,
            self.fmtp
                .as_deref()
                .map(|value| quoted("FMTP", value))
                .transpose()?,
            self.packet_loss_concealment
                .map(|value| format!("PLC={}", value.code())),
            self.silence_suppression
                .map(|on| format!("SSUP={}", if on { "on" } else { "off" })),
        ];
        push_parameters(body, "SessionDesc", &parameters);
        Ok(())
    }
}

impl JitterBuffer {
    fn render(&self, body: &mut String) -> Result<(), VqReportError> {
        let parameters = [
            self.adaptation.map(|value| format!("JBA={}", value.code())),
            self.rate
                .map(|value| integer("JBR", u32::from(value), 15))
                .transpose()?,
            self.nominal_ms
                .map(|value| integer("JBN", u32::from(value), 65_535))
                .transpose()?,
            self.maximum_ms
                .map(|value| integer("JBM", u32::from(value), 65_535))
                .transpose()?,
            self.absolute_maximum_ms
                .map(|value| integer("JBX", u32::from(value), 65_535))
                .transpose()?,
        ];
        push_parameters(body, "JitterBuffer", &parameters);
        Ok(())
    }
}

impl PacketLoss {
    fn render(&self, body: &mut String) -> Result<(), VqReportError> {
        let parameters = [
            self.network_loss_percent
                .map(|value| percentage("NLR", value))
                .transpose()?,
            self.discard_percent
                .map(|value| percentage("JDR", value))
                .transpose()?,
        ];
        push_parameters(body, "PacketLoss", &parameters);
        Ok(())
    }
}

impl BurstGapLoss {
    fn render(&self, body: &mut String) -> Result<(), VqReportError> {
        let parameters = [
            self.burst_density_percent
                .map(|value| percentage("BLD", value))
                .transpose()?,
            self.burst_duration_ms
                .map(|value| integer("BD", value, 3_600_000))
                .transpose()?,
            self.gap_density_percent
                .map(|value| percentage("GLD", value))
                .transpose()?,
            self.gap_duration_ms
                .map(|value| integer("GD", value, 3_600_000))
                .transpose()?,
            self.minimum_gap_threshold
                .map(|value| {
                    if value == 0 {
                        Err(VqReportError::OutOfRange("GMIN"))
                    } else {
                        Ok(format!("GMIN={value}"))
                    }
                })
                .transpose()?,
        ];
        push_parameters(body, "BurstGapLoss", &parameters);
        Ok(())
    }
}

impl Delay {
    fn render(&self, body: &mut String) -> Result<(), VqReportError> {
        let parameters = [
            self.round_trip_ms.map(|value| format!("RTD={value}")),
            self.end_system_ms.map(|value| format!("ESD={value}")),
            self.one_way_ms.map(|value| format!("OWD={value}")),
            self.symmetric_one_way_ms
                .map(|value| format!("SOWD={value}")),
            self.interarrival_jitter_ms
                .map(|value| format!("IAJ={value}")),
            self.mean_absolute_jitter_ms
                .map(|value| format!("MAJ={value}")),
        ];
        push_parameters(body, "Delay", &parameters);
        Ok(())
    }
}

impl Signal {
    fn render(&self, body: &mut String) -> Result<(), VqReportError> {
        let parameters = [
            self.signal_level_dbm0
                .map(|value| signed_level("SL", value))
                .transpose()?,
            self.noise_level_dbm0
                .map(|value| signed_level("NL", value))
                .transpose()?,
            self.residual_echo_return_loss_db
                .map(|value| integer("RERL", u32::from(value), 127))
                .transpose()?,
        ];
        push_parameters(body, "Signal", &parameters);
        Ok(())
    }
}

impl QualityEstimates {
    fn render(&self, body: &mut String) -> Result<(), VqReportError> {
        let r_factor = |key: &'static str, value: Option<u8>| {
            value
                .map(|value| integer(key, u32::from(value), 120))
                .transpose()
        };
        let algorithm = |key: &'static str, value: &Option<String>| {
            value
                .as_deref()
                .map(|value| word_parameter(key, value))
                .transpose()
        };
        let parameters = [
            r_factor("RLQ", self.listening_r)?,
            algorithm("RLQEstAlg", &self.listening_r_algorithm)?,
            r_factor("RCQ", self.conversational_r)?,
            algorithm("RCQEstAlg", &self.conversational_r_algorithm)?,
            r_factor("EXTRI", self.external_r_in)?,
            algorithm("ExtRIEstAlg", &self.external_r_in_algorithm)?,
            r_factor("EXTRO", self.external_r_out)?,
            algorithm("ExtROEstAlg", &self.external_r_out_algorithm)?,
            self.mos_lq
                .map(|value| mean_opinion_score("MOSLQ", value))
                .transpose()?,
            algorithm("MOSLQEstAlg", &self.mos_lq_algorithm)?,
            self.mos_cq
                .map(|value| mean_opinion_score("MOSCQ", value))
                .transpose()?,
            algorithm("MOSCQEstAlg", &self.mos_cq_algorithm)?,
            algorithm("QoEEstAlg", &self.algorithm)?,
        ];
        push_parameters(body, "QualityEst", &parameters);
        Ok(())
    }
}

impl DialogId {
    fn render(&self, body: &mut String) -> Result<(), VqReportError> {
        let mut value = call_id_parameter("DialogID", &self.call_id)?.to_string();
        for (name, tag) in [("to-tag", &self.to_tag), ("from-tag", &self.from_tag)] {
            if let Some(tag) = tag {
                if !is_token(tag) {
                    return Err(VqReportError::InvalidText("DialogID"));
                }
                value.push(';');
                value.push_str(name);
                value.push('=');
                value.push_str(tag);
            }
        }
        push_line(body, "DialogID", &value);
        Ok(())
    }
}

/// One named line, `Name: value`, CRLF-terminated.
fn push_line(body: &mut String, name: &str, value: &str) {
    body.push_str(name);
    body.push_str(": ");
    body.push_str(value);
    body.push_str("\r\n");
}

/// One metrics line, `Name: KEY=value ...`, written only when at least one parameter is present:
/// every parameter on these lines is optional in the grammar.
fn push_parameters(body: &mut String, name: &str, parameters: &[Option<String>]) {
    let mut present = parameters.iter().flatten();
    let Some(first) = present.next() else {
        return;
    };
    body.push_str(name);
    body.push_str(": ");
    body.push_str(first);
    for parameter in present {
        body.push(' ');
        body.push_str(parameter);
    }
    body.push_str("\r\n");
}

/// `KEY=value` for a count bounded by its `n*mDIGIT` production and the range the RFC gives it.
fn integer(key: &'static str, value: u32, maximum: u32) -> Result<String, VqReportError> {
    if value > maximum {
        return Err(VqReportError::OutOfRange(key));
    }
    Ok(format!("{key}={value}"))
}

/// `KEY=value` for `SL` and `NL`, `[ "-" ] 1*2DIGIT`: two digits, so -99 to 99 dBm0.
fn signed_level(key: &'static str, value: i8) -> Result<String, VqReportError> {
    if !(-99..=99).contains(&value) {
        return Err(VqReportError::OutOfRange(key));
    }
    Ok(format!("{key}={value}"))
}

/// `KEY=value` for a percentage, `1*3DIGIT [ "." 1*2DIGIT ]`, 0 to 100.
fn percentage(key: &'static str, value: f64) -> Result<String, VqReportError> {
    if !(0.0..=100.0).contains(&value) {
        return Err(VqReportError::OutOfRange(key));
    }
    Ok(format!("{key}={}", decimal(value)))
}

/// `KEY=value` for a MOS, `DIGIT [ "." 1*3DIGIT ]`, on the 1 to 5 scale of §4.6.2.11.9.
fn mean_opinion_score(key: &'static str, value: f64) -> Result<String, VqReportError> {
    if !(1.0..=5.0).contains(&value) {
        return Err(VqReportError::OutOfRange(key));
    }
    Ok(format!("{key}={}", decimal(value)))
}

/// At most two decimal places, trailing zeros dropped, which fits both the percentage and the MOS
/// productions.
fn decimal(value: f64) -> String {
    let fixed = format!("{value:.2}");
    fixed
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

/// A fractional millisecond figure as the whole milliseconds a `1*5DIGIT` delay carries.
fn whole_milliseconds(value: f64) -> u16 {
    value.round().clamp(0.0, f64::from(u16::MAX)) as u16
}

/// `PD = "PD" EQUAL (word / DQUOTE word-plus DQUOTE)`: bare when the name is a `word`, quoted when
/// it needs `word-plus`.
fn payload_description(value: &str) -> Result<String, VqReportError> {
    if is_word(value) {
        Ok(format!("PD={value}"))
    } else {
        quoted("PD", value)
    }
}

/// `KEY=DQUOTE word-plus DQUOTE`.
fn quoted(key: &'static str, value: &str) -> Result<String, VqReportError> {
    if is_word_plus(value) {
        Ok(format!("{key}=\"{value}\""))
    } else {
        Err(VqReportError::InvalidText(key))
    }
}

/// `KEY=word`, the form of every estimation algorithm name.
fn word_parameter(key: &'static str, value: &str) -> Result<String, VqReportError> {
    if is_word(value) {
        Ok(format!("{key}={value}"))
    } else {
        Err(VqReportError::InvalidText(key))
    }
}

/// `Call-ID-Parm = word [ "@" word ]`.
fn call_id_parameter<'value>(
    field: &'static str,
    value: &'value str,
) -> Result<&'value str, VqReportError> {
    let valid = match value.split_once('@') {
        Some((local, host)) => is_word(local) && is_word(host),
        None => is_word(value),
    };
    if valid {
        Ok(value)
    } else {
        Err(VqReportError::InvalidText(field))
    }
}

/// `name-addr / addr-spec` (RFC 3261 §25.1). The full SIP grammar is the controller's to enforce;
/// what the report itself cannot survive is a control character, a line break above all, or
/// whitespace at either end that a reader would strip.
fn sip_identity<'value>(
    field: &'static str,
    value: &'value str,
) -> Result<&'value str, VqReportError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(VqReportError::InvalidText(field));
    }
    Ok(value)
}

/// A `word-plus` value (a group name), refused with whitespace at either end, which a reader would
/// strip.
fn word_plus<'value>(
    field: &'static str,
    value: &'value str,
) -> Result<&'value str, VqReportError> {
    if is_word_plus(value) && value.trim() == value {
        Ok(value)
    } else {
        Err(VqReportError::InvalidText(field))
    }
}

fn mac_address(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A `word` character (RFC 6035 §4.6.1).
fn is_word_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || "-.!%*_+`'~()<>:\\\"/[]?".contains(character)
}

/// A `word-plus` character (RFC 6035 §4.6.1): a `word` character other than DQUOTE, or `{`, `}`,
/// `=` or a space.
fn is_word_plus_character(character: char) -> bool {
    character != '"' && (is_word_character(character) || "{}= ".contains(character))
}

/// A `token` character (RFC 3261 §25.1).
fn is_token_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || "-.!%*_+`'~".contains(character)
}

fn is_word(value: &str) -> bool {
    !value.is_empty() && value.chars().all(is_word_character)
}

fn is_word_plus(value: &str) -> bool {
    !value.is_empty() && value.chars().all(is_word_plus_character)
}

fn is_token(value: &str) -> bool {
    !value.is_empty() && value.chars().all(is_token_character)
}

/// `date-time` (RFC 3339 §5.6) in UTC, the only offset RFC 6035 §4.6.1 allows, for `seconds` since
/// the Unix epoch.
fn date_time(seconds: u64) -> Result<String, VqReportError> {
    if seconds > LAST_REPRESENTABLE_SECOND {
        return Err(VqReportError::OutOfRange("Timestamps"));
    }
    let (year, month, day) = civil_date(seconds / 86_400);
    let second_of_day = seconds % 86_400;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        second_of_day / 3_600,
        second_of_day / 60 % 60,
        second_of_day % 60
    ))
}

/// The proleptic Gregorian `(year, month, day)` of the day `days` after 1970-01-01: Howard Hinnant's
/// `civil_from_days`, for days on or after the epoch.
fn civil_date(days: u64) -> (u64, u64, u64) {
    // Count from 0000-03-01, so a leap day falls at the end of its counted year.
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// RFC 6035 §4.7.3, message F13: the end-of-session report body, line for line as the RFC prints
    /// it, including its folded continuation lines. The only substitutions are the RFC's IPv4 and
    /// MAC addresses, replaced by documentation ones (RFC 5737, RFC 7042 §2.1.1).
    const RFC_6035_SECTION_4_7_3_REPORT: &str = concat!(
        "VQSessionReport: CallTerm\n",
        "CallID: 6dg37f1890463\n",
        "LocalID: Alice <sip:alice@example.org>\n",
        "RemoteID: Bill <sip:bill@example.net>\n",
        "OrigID: Alice <sip:alice@example.org>\n",
        "LocalGroup: example-phone-55671\n",
        "RemoteGroup: example-gateway-09871\n",
        "LocalAddr: IP=192.0.2.100 PORT=5000 SSRC=1a3b5c7d\n",
        "LocalMAC: 00:00:5e:00:53:01\n",
        "RemoteAddr:IP=198.51.100.150 PORT=5002 SSRC=0x2468abcd\n",
        "RemoteMAC: 00:00:5e:00:53:02\n",
        "LocalMetrics:\n",
        "Timestamps:START=2004-10-10T18:23:43Z STOP=2004-10-01T18:26:02Z\n",
        "SessionDesc:PT=18 PD=G729 SR=8000 FD=20 FO=20 FPP=2 PPS=50\n",
        "                FMTP=\"annexb=no\" PLC=3 SSUP=on\n",
        "JitterBuffer:JBA=3 JBR=2 JBN=40 JBM=80 JBX=120\n",
        "PacketLoss:NLR=5.0 JDR=2.0\n",
        "BurstGapLoss:BLD=0 BD=0 GLD=2.0 GD=500 GMIN=16\n",
        "Delay:RTD=200 ESD=140 SOWD=200 IAJ=2 MAJ=10\n",
        "Signal:SL=-21 NL=-50 RERL=55\n",
        "QualityEst:RLQ=90 RCQ=85 EXTRI=90 MOSLQ=4.2 MOSCQ=4.3\n",
        "  QoEEstAlg=P.564\n",
        "RemoteMetrics:\n",
        "Timestamps:START=2004-10-10T18:23:43Z STOP=2004-10-01T18:26:02Z\n",
        "SessionDesc:PT=18 PD=G729 SR=8000 FD=20 FO=20 FPP=2 PPS=50\n",
        "                FMTP=\"annexb=no\" PLC=3 SSUP=on\n",
        "JitterBuffer:JBA=3 JBR=2 JBN=40 JBM=80 JBX=120\n",
        "PacketLoss:NLR=5.0 JDR=2.0\n",
        "BurstGapLoss:BLD=0 BD=0 GLD=2.0 GD=500 GMIN=16\n",
        "Delay:RTD=200 ESD=140 SOWD=200 IAJ=2 MAJ=10\n",
        "Signal:SL=-21 NL=-45 RERL=55\n",
        "QualityEst:RLQ=90 RCQ=85 MOSLQ=4.3 MOSCQ=4.2 QoEEstAlg=P.564\n",
        "DialogID:1890463548@alice.example.org;to-tag=8472761;\n",
        "   from-tag=9123dh311\n",
    );

    fn example_metrics(signal: Signal, quality: QualityEstimates) -> Metrics {
        Metrics {
            started_at_unix_seconds: 1_097_432_623,
            stopped_at_unix_seconds: 1_097_432_762,
            session_description: SessionDescription {
                payload_type: Some(18),
                payload_description: Some("G729".to_string()),
                sample_rate: Some(8_000),
                packets_per_second: Some(50),
                frame_duration_ms: Some(20),
                frame_octets: Some(20),
                frames_per_packet: Some(2),
                fmtp: Some("annexb=no".to_string()),
                packet_loss_concealment: Some(PacketLossConcealment::Standard),
                silence_suppression: Some(true),
            },
            jitter_buffer: JitterBuffer {
                adaptation: Some(JitterBufferAdaptation::Adaptive),
                rate: Some(2),
                nominal_ms: Some(40),
                maximum_ms: Some(80),
                absolute_maximum_ms: Some(120),
            },
            packet_loss: PacketLoss {
                network_loss_percent: Some(5.0),
                discard_percent: Some(2.0),
            },
            burst_gap_loss: BurstGapLoss {
                burst_density_percent: Some(0.0),
                burst_duration_ms: Some(0),
                gap_density_percent: Some(2.0),
                gap_duration_ms: Some(500),
                minimum_gap_threshold: Some(16),
            },
            delay: Delay {
                round_trip_ms: Some(200),
                end_system_ms: Some(140),
                one_way_ms: None,
                symmetric_one_way_ms: Some(200),
                interarrival_jitter_ms: Some(2),
                mean_absolute_jitter_ms: Some(10),
            },
            signal,
            quality,
        }
    }

    /// The report §4.7.3 describes, as this crate models it.
    fn example_report() -> SessionReport {
        SessionReport {
            call_term: true,
            session: SessionInfo {
                call_id: "6dg37f1890463".to_string(),
                local_id: "Alice <sip:alice@example.org>".to_string(),
                remote_id: "Bill <sip:bill@example.net>".to_string(),
                originator_id: "Alice <sip:alice@example.org>".to_string(),
                local_address: MediaSource {
                    address: "192.0.2.100:5000".parse().expect("address"),
                    ssrc: 0x1a3b_5c7d,
                },
                remote_address: MediaSource {
                    address: "198.51.100.150:5002".parse().expect("address"),
                    ssrc: 0x2468_abcd,
                },
                local_group: "example-phone-55671".to_string(),
                remote_group: "example-gateway-09871".to_string(),
                local_mac: Some([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]),
                remote_mac: Some([0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]),
            },
            local_metrics: example_metrics(
                Signal {
                    signal_level_dbm0: Some(-21),
                    noise_level_dbm0: Some(-50),
                    residual_echo_return_loss_db: Some(55),
                },
                QualityEstimates {
                    listening_r: Some(90),
                    conversational_r: Some(85),
                    external_r_in: Some(90),
                    mos_lq: Some(4.2),
                    mos_cq: Some(4.3),
                    algorithm: Some("P.564".to_string()),
                    ..QualityEstimates::default()
                },
            ),
            remote_metrics: Some(example_metrics(
                Signal {
                    signal_level_dbm0: Some(-21),
                    noise_level_dbm0: Some(-45),
                    residual_echo_return_loss_db: Some(55),
                },
                QualityEstimates {
                    listening_r: Some(90),
                    conversational_r: Some(85),
                    mos_lq: Some(4.3),
                    mos_cq: Some(4.2),
                    algorithm: Some("P.564".to_string()),
                    ..QualityEstimates::default()
                },
            )),
            dialog: Some(DialogId {
                call_id: "1890463548@alice.example.org".to_string(),
                to_tag: Some("8472761".to_string()),
                from_tag: Some("9123dh311".to_string()),
            }),
        }
    }

    /// A body as its named lines, with folded continuation lines joined back on (the `SWS` the
    /// grammar separates tokens with, RFC 3261 §7.3.1).
    fn logical_lines(body: &str) -> Vec<(String, String)> {
        let mut lines: Vec<(String, String)> = Vec::new();
        for raw in body.split('\n').map(|line| line.trim_end_matches('\r')) {
            if raw.is_empty() {
                continue;
            }
            if raw.starts_with([' ', '\t']) {
                if let Some((_, value)) = lines.last_mut() {
                    value.push(' ');
                    value.push_str(raw.trim());
                }
                continue;
            }
            let (name, value) = raw.split_once(':').unwrap_or((raw, ""));
            lines.push((name.trim().to_string(), value.trim().to_string()));
        }
        lines
    }

    /// A parameter line's values by key, numbers compared by value (`NLR=5.0` is `NLR=5`).
    fn parameters(value: &str) -> BTreeMap<String, String> {
        value
            .split_whitespace()
            .filter_map(|parameter| parameter.split_once('='))
            .map(|(key, value)| {
                let value = value
                    .parse::<f64>()
                    .map_or_else(|_| value.to_string(), |number| number.to_string());
                (key.to_string(), value)
            })
            .collect()
    }

    fn assert_same_value(name: &str, rendered: &str, expected: &str) {
        match name {
            "VQSessionReport" | "CallID" | "LocalID" | "RemoteID" | "OrigID" | "LocalGroup"
            | "RemoteGroup" | "LocalMAC" | "RemoteMAC" | "LocalMetrics" | "RemoteMetrics" => {
                assert_eq!(rendered, expected, "{name}");
            }
            // The example folds after a `;`, which `SEMI` lets whitespace surround.
            "DialogID" => assert_eq!(
                rendered.replace(' ', ""),
                expected.replace(' ', ""),
                "{name}"
            ),
            _ => assert_eq!(parameters(rendered), parameters(expected), "{name}"),
        }
    }

    #[test]
    fn the_rfc_6035_example_report_is_reproduced() {
        let rendered = example_report()
            .render()
            .expect("the RFC's own report renders");
        // Two corrections to the RFC's text, both errors in the example rather than in this module:
        // its `LocalAddr` SSRC lacks the `0x` the ABNF requires (`Ssrc = "SSRC" EQUAL (%x30.78
        // 1*8HEXDIG)`), and its STOP is dated nine days before its START, where the times of day
        // give a call of 2 min 19 s on the same day.
        let expected = RFC_6035_SECTION_4_7_3_REPORT
            .replace("SSRC=1a3b5c7d", "SSRC=0x1a3b5c7d")
            .replace("STOP=2004-10-01T18:26:02Z", "STOP=2004-10-10T18:26:02Z");
        let rendered = logical_lines(&rendered);
        let expected = logical_lines(&expected);
        assert_eq!(rendered.len(), expected.len(), "the same number of lines");
        assert_eq!(
            rendered[0].0, "VQSessionReport",
            "the report type comes first"
        );

        // `SessionInfo` is written in ABNF order, which the example does not follow, so those lines
        // are compared by name. From `LocalMetrics:` on, the order is compared too.
        let split = |lines: &[(String, String)]| {
            let metrics = lines
                .iter()
                .position(|(name, _)| name == "LocalMetrics")
                .expect("a LocalMetrics line");
            (
                lines[..metrics].iter().cloned().collect::<BTreeMap<_, _>>(),
                lines[metrics..].to_vec(),
            )
        };
        let (rendered_session, rendered_metrics) = split(&rendered);
        let (expected_session, expected_metrics) = split(&expected);
        assert_eq!(rendered_session.len(), expected_session.len());
        for (name, expected_value) in &expected_session {
            let rendered_value = rendered_session.get(name).expect("the same session line");
            assert_same_value(name, rendered_value, expected_value);
        }
        for ((rendered_name, rendered_value), (expected_name, expected_value)) in
            rendered_metrics.iter().zip(&expected_metrics)
        {
            assert_eq!(rendered_name, expected_name, "metrics lines in RFC order");
            assert_same_value(expected_name, rendered_value, expected_value);
        }
    }

    #[test]
    fn every_line_ends_in_crlf_and_none_is_empty_or_folded() {
        let rendered = example_report().render().expect("renders");
        let body = rendered
            .strip_suffix("\r\n")
            .expect("the last line ends in CRLF too");
        for line in body.split("\r\n") {
            assert!(
                !line.is_empty(),
                "an empty line would end the report for a line-oriented reader"
            );
            assert!(
                !line.starts_with([' ', '\t']),
                "no folded continuation: {line:?}"
            );
            assert!(!line.contains(['\r', '\n']), "no bare CR or LF: {line:?}");
        }
    }

    #[test]
    fn timestamps_match_an_independent_calendar() {
        // Each expected string is what GNU `date -u -d @<seconds>` prints for the same instant: the
        // epoch, the RFC example's START, the last second of a leap day, 2100-03-01 (which a
        // four-year leap rule alone would place a day early), and the last second a four-digit year
        // can hold.
        for (seconds, expected) in [
            (0, "1970-01-01T00:00:00Z"),
            (1_097_432_623, "2004-10-10T18:23:43Z"),
            (951_868_799, "2000-02-29T23:59:59Z"),
            (4_107_542_400, "2100-03-01T00:00:00Z"),
            (253_402_300_799, "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(date_time(seconds), Ok(expected.to_string()));
        }
        assert_eq!(
            date_time(253_402_300_800),
            Err(VqReportError::OutOfRange("Timestamps"))
        );
    }

    #[test]
    fn a_line_break_in_a_sip_identity_is_refused_rather_than_written_into_the_report() {
        let mut report = example_report();
        report.session.local_id =
            "Alice <sip:alice@example.org>\r\nRemoteID: Mallory <sip:mallory@example.org>"
                .to_string();
        assert_eq!(report.render(), Err(VqReportError::InvalidText("LocalID")));
    }

    #[test]
    fn a_value_its_production_cannot_express_is_refused() {
        let refused = |change: fn(&mut SessionReport)| {
            let mut report = example_report();
            change(&mut report);
            report.render()
        };
        assert_eq!(
            refused(|report| report.local_metrics.packet_loss.network_loss_percent = Some(100.5)),
            Err(VqReportError::OutOfRange("NLR"))
        );
        assert_eq!(
            refused(
                |report| report.local_metrics.packet_loss.network_loss_percent = Some(f64::NAN)
            ),
            Err(VqReportError::OutOfRange("NLR"))
        );
        assert_eq!(
            refused(|report| report.local_metrics.jitter_buffer.rate = Some(16)),
            Err(VqReportError::OutOfRange("JBR"))
        );
        assert_eq!(
            refused(|report| report.local_metrics.burst_gap_loss.minimum_gap_threshold = Some(0)),
            Err(VqReportError::OutOfRange("GMIN"))
        );
        assert_eq!(
            refused(|report| report.local_metrics.signal.signal_level_dbm0 = Some(-100)),
            Err(VqReportError::OutOfRange("SL"))
        );
        assert_eq!(
            refused(|report| report.local_metrics.quality.mos_cq = Some(0.5)),
            Err(VqReportError::OutOfRange("MOSCQ"))
        );
        assert_eq!(
            refused(|report| report.local_metrics.stopped_at_unix_seconds = 0),
            Err(VqReportError::OutOfRange("Timestamps"))
        );
        assert_eq!(
            refused(|report| report.session.local_group = "two\tgroups".to_string()),
            Err(VqReportError::InvalidText("LocalGroup"))
        );
        assert_eq!(
            refused(|report| report.session.call_id = "one@two@three".to_string()),
            Err(VqReportError::InvalidText("CallID"))
        );
    }

    fn identity() -> SessionIdentity {
        SessionIdentity {
            call_id: "a84b4c76e66710".to_string(),
            local_id: "<sip:sbc@example.org>".to_string(),
            remote_id: "Alice <sip:alice@example.org>".to_string(),
            originator_id: "Alice <sip:alice@example.org>".to_string(),
            local_group: "sbc-01".to_string(),
            remote_group: "access".to_string(),
            dialog: None,
        }
    }

    fn measured_leg() -> LegSummary {
        LegSummary {
            tag: "ft-a".to_string(),
            codec: Some("PCMA".to_string()),
            packets_in: 2720,
            bytes_in: 467_840,
            packets_out: 3469,
            bytes_out: 596_468,
            packets_dropped: 0,
            ssrc: Some(0x8a8b_25c0),
            packets_lost: Some(1),
            loss_percent: Some(0.04),
            jitter_ms: Some(0.8),
            rtt_ms: Some(37.8),
            mos_average: Some(4.3),
            mos_min: Some(4.21),
            mos_max: Some(4.4),
            mos_basis: Some("full".to_string()),
            text: None,
            local_address: Some("192.0.2.10:30000".parse().expect("address")),
            remote_address: Some("198.51.100.7:4000".parse().expect("address")),
            egress_ssrc: Some(0x1f2e_3d4c),
            payload_type: Some(8),
        }
    }

    #[test]
    fn a_leg_report_carries_what_the_engine_measured_on_that_leg() {
        let report = SessionReport::for_leg(
            identity(),
            &measured_leg(),
            Some(1_097_432_623_000),
            Some(1_097_432_762_500),
        )
        .expect("a measured leg has a report");
        let body = report.render().expect("renders");
        let lines = logical_lines(&body);
        let value = |name: &str| {
            lines
                .iter()
                .find(|(line, _)| line == name)
                .map(|(_, value)| value.clone())
                .unwrap_or_default()
        };
        assert_eq!(value("VQSessionReport"), "CallTerm");
        assert_eq!(
            value("LocalAddr"),
            "IP=192.0.2.10 PORT=30000 SSRC=0x1f2e3d4c",
            "the engine's side, with the SSRC the engine sent"
        );
        assert_eq!(
            value("RemoteAddr"),
            "IP=198.51.100.7 PORT=4000 SSRC=0x8a8b25c0",
            "the party's side, with the SSRC the party sent"
        );
        assert_eq!(
            value("Timestamps"),
            "START=2004-10-10T18:23:43Z STOP=2004-10-10T18:26:02Z"
        );
        assert_eq!(value("SessionDesc"), "PT=8 PD=PCMA");
        assert_eq!(value("PacketLoss"), "NLR=0.04");
        assert_eq!(value("Delay"), "RTD=38 IAJ=1");
        assert_eq!(value("QualityEst"), "MOSCQ=4.3 MOSCQEstAlg=G.107");
        assert!(
            !body.contains("RemoteMetrics"),
            "the engine reports only what it measured itself"
        );
    }

    #[test]
    fn a_mos_without_the_delay_term_is_left_out_of_a_leg_report() {
        let mut leg = measured_leg();
        leg.rtt_ms = None;
        leg.mos_basis = Some("loss+jitter".to_string());
        let body = SessionReport::for_leg(identity(), &leg, Some(0), Some(1_000))
            .expect("the leg still has a report")
            .render()
            .expect("renders");
        assert!(
            !body.contains("QualityEst"),
            "a loss-and-jitter MOS is not the conversational score MOSCQ defines"
        );
        assert!(!body.contains("RTD="));
    }

    #[test]
    fn a_leg_without_a_measured_stream_has_no_report() {
        let without = |change: fn(&mut LegSummary)| {
            let mut leg = measured_leg();
            change(&mut leg);
            SessionReport::for_leg(identity(), &leg, Some(0), Some(1_000))
        };
        assert_eq!(
            without(|leg| leg.ssrc = None),
            Err(VqReportError::Missing("ssrc"))
        );
        assert_eq!(
            without(|leg| leg.egress_ssrc = None),
            Err(VqReportError::Missing("egress_ssrc"))
        );
        assert_eq!(
            without(|leg| leg.remote_address = None),
            Err(VqReportError::Missing("remote_address"))
        );
        assert_eq!(
            SessionReport::for_leg(identity(), &measured_leg(), None, Some(1_000)),
            Err(VqReportError::Missing("started_at_unix_ms"))
        );
    }
}
