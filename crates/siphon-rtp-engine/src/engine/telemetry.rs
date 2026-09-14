//! QoS and RTCP export to a HEP collector.

use siphon_rtp_datapath::{Datapath, EndpointId, ObservedRtcp};
use siphon_rtp_hep::exporter::HepExporter;
use siphon_rtp_hep::mos::Impairments;
use siphon_rtp_hep::report::QosReport;
use siphon_rtp_hep::text_report::TextQosReport;
use siphon_rtp_hep::{protocol_type, Capture};
use siphon_rtp_proto::Event;
use std::sync::Arc;

use super::{Call, ClientId, Engine, Leg};

/// The HEP telemetry sink and its capture-agent id, shared across the RTCP-export task and the
/// end-of-call text-QoS export. The exporter owns a connected UDP socket, so it is held behind an
/// `Arc` and never re-created per capture.
pub(super) struct HepExport {
    exporter: Arc<HepExporter>,
    capture_agent_id: u32,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Ship this call's per-leg RFC 4103 Real-Time Text content QoS to the HEP collector as a report
    /// capture (`protocol_type` = REPORT_JSON, type 35), correlated by call-id — the wire complement to
    /// the [`Event::CallSummary`]'s `text` field. One capture per leg that carried a measured text
    /// stream: the near leg is party A's inbound A→B stream (offerer sent), the far leg party B's
    /// inbound B→A stream (answerer sent), matching the CDR's per-direction attribution. A no-op when
    /// the call had no promoted text stream (`near`/`far` both `None`, e.g. an audio-only call) or HEP
    /// export is disabled. Fire-and-forget: an export error is logged, never propagated (telemetry must
    /// never disturb teardown).
    pub(super) async fn export_text_qos(
        &self,
        call: &Call,
        call_id: &str,
        near: Option<siphon_rtp_proto::TextStreamStats>,
        far: Option<siphon_rtp_proto::TextStreamStats>,
    ) {
        // Audio-only call, or a text stream left on the in-kernel relay (never measured) ⇒ nothing to
        // emit. Skip before touching the exporter so an audio-only call ships no RTT capture at all.
        if near.is_none() && far.is_none() {
            return;
        }
        let Some(export) = self.hep_export.get() else {
            return; // HEP export disabled (`SIPHON_RTP_HEP_COLLECTOR` unset).
        };
        let (timestamp_secs, timestamp_micros) = wall_clock_now();
        // (leg, this-leg's inbound stats, sending tag, direction) for each measured direction. A
        // single-leg call has no far leg — and never relays text, which is a 2-leg concern — so only
        // the near entry can ever carry stats there.
        let legs = [
            (Some(&call.near), near, call.from_tag.as_str(), "a_to_b"),
            (
                call.far.as_ref(),
                far,
                call.to_tag.as_deref().unwrap_or("-"),
                "b_to_a",
            ),
        ];
        for (leg, stats, tag, direction) in legs {
            let (Some(leg), Some(stats)) = (leg, stats) else {
                continue;
            };
            let (src, dst) = text_stream_addresses(leg);
            let report = TextQosReport {
                correlation_id: call_id.to_string(),
                tag: tag.to_string(),
                direction,
                packets: stats.packets,
                characters: stats.characters,
                missing_markers: stats.missing_markers,
                recovered_from_redundancy: stats.recovered_from_redundancy,
            };
            let capture = Capture::from_text_qos_report(
                src,
                dst,
                timestamp_secs,
                timestamp_micros,
                export.capture_agent_id,
                &report,
            );
            if let Err(error) = export.exporter.export(&capture).await {
                tracing::debug!(%error, direction, "HEP RFC 4103 text QoS export failed");
            }
        }
    }

    /// Install the HEP telemetry export (VoIPmonitor / Homer) for this engine — the connected
    /// [`HepExporter`] and its capture-agent id. Called once at daemon startup from
    /// `SIPHON_RTP_HEP_COLLECTOR`; both [`Self::run_rtcp_export`] (per-interval RTCP/QoS) and the
    /// end-of-call teardown path (`finish_call`, RFC 4103 text QoS) read it from here, so a single
    /// connected socket serves both. Idempotent: a second call is ignored (the first export wins).
    pub fn set_hep_export(&self, exporter: HepExporter, capture_agent_id: u32) {
        let _ = self.hep_export.set(HepExport {
            exporter: Arc::new(exporter),
            capture_agent_id,
        });
    }

    /// Drain observed relayed RTCP and export it as HEP captures to the configured collector (a
    /// VoIPmonitor / Homer node via [`Self::set_hep_export`]), correlated by call-id. Returns
    /// immediately if no exporter is configured. Each observed datagram ships **twice**: once as the raw RTCP
    /// (`protocol_type` = RTCP) for a passive collector, and once — per reception report block it
    /// carries — as a QoS/MOS report (`protocol_type` = REPORT_JSON, HEP3 type 35) built from the
    /// block's loss/jitter through the G.107 E-model (RFC 3550 §6.4.1, ITU-T G.107). Runs until the
    /// datapath's observation stream closes; fire-and-forget — export errors are logged, never
    /// propagated, so telemetry never disturbs the media path.
    ///
    /// Note: `observe_rtcp` taps only the plain-relay (in-kernel `Forward`) path, where the engine
    /// originates no Sender Report of its own, so the QoS report carries no measured RTT (one-way delay
    /// 0). Transcode/conference legs measure RTT on their own path and surface it via `CallQuality`.
    pub async fn run_rtcp_export(self: Arc<Self>) {
        let Some(export) = self.hep_export.get() else {
            tracing::debug!("HEP RTCP export task started without a configured exporter; idle");
            return;
        };
        let exporter = &export.exporter;
        let capture_agent_id = export.capture_agent_id;
        let observations = self.datapath.observe_rtcp();
        while let Ok(observed) = observations.recv_async().await {
            let Some(call_id) = self.call_for_endpoint(observed.endpoint) else {
                continue;
            };
            let (timestamp_secs, timestamp_micros) = wall_clock_now();
            // Raw RTCP passthrough (unchanged) — a passive collector still gets the bytes verbatim.
            let raw = rtcp_capture(
                &observed,
                call_id.clone(),
                capture_agent_id,
                timestamp_secs,
                timestamp_micros,
            );
            if let Err(error) = exporter.export(&raw).await {
                tracing::debug!(%error, "HEP RTCP export failed");
            }
            // ...plus a QoS/MOS report per reception report block (HEP3 type 35).
            let (codec, clock_rate_hz) = self.qos_codec_for_endpoint(observed.endpoint);
            for report in qos_captures(
                &observed,
                &call_id,
                capture_agent_id,
                timestamp_secs,
                timestamp_micros,
                codec,
                clock_rate_hz,
            ) {
                if let Err(error) = exporter.export(&report).await {
                    tracing::debug!(%error, "HEP QoS export failed");
                }
            }
            // ...and the same per-block quality natively on the control channel (RFC 3550 §6.4.1 loss/
            // jitter + G.107 MOS), so SIPhon sees this 2-party plain-relay call's quality the way it
            // sees a conference participant's — the control-channel complement to the HEP QoS export.
            if let Some((owner, from_tag)) = self.owner_and_tag_for_endpoint(observed.endpoint) {
                for event in
                    qos_quality_events(&observed, &call_id, &from_tag, codec, clock_rate_hz)
                {
                    self.push_event(owner, event);
                }
            }
        }
    }

    /// The owner client and leg tag for a call-quality event derived from RTCP observed on `endpoint`:
    /// the client that created the call (the event's recipient) and the tag of the leg the RTCP
    /// traversed — the far (answerer) leg's `to_tag` for a far endpoint, else the near (offerer) leg's
    /// `from_tag`. `None` when the endpoint maps to no live call.
    fn owner_and_tag_for_endpoint(&self, endpoint: EndpointId) -> Option<(ClientId, String)> {
        use crate::ha::EndpointRole;
        let call_id = self.call_for_endpoint(endpoint)?;
        let call = self.calls.get(&call_id)?;
        let from_tag = match call.endpoint_role(endpoint) {
            Some(EndpointRole::FarRtp | EndpointRole::FarRtcp) => {
                call.to_tag.clone().unwrap_or_else(|| call.from_tag.clone())
            }
            _ => call.from_tag.clone(),
        };
        Some((call.owner, from_tag))
    }

    /// The G.107 codec and RTP clock rate for QoS reports on `endpoint` — the negotiated codec of the
    /// leg (near/far) the endpoint belongs to, via [`crate::conference::hep_codec_for_name`]. Falls
    /// back to G.711 at 8 kHz when the call or its codec is not (yet) known.
    fn qos_codec_for_endpoint(&self, endpoint: EndpointId) -> (siphon_rtp_hep::mos::Codec, u32) {
        use crate::ha::EndpointRole;
        let fallback = (siphon_rtp_hep::mos::Codec::G711, 8000);
        let Some(call_id) = self.call_for_endpoint(endpoint) else {
            return fallback;
        };
        let Some(call) = self.calls.get(&call_id) else {
            return fallback;
        };
        let codec = match call.endpoint_role(endpoint) {
            Some(EndpointRole::FarRtp | EndpointRole::FarRtcp) => call.far_codec.as_ref(),
            _ => call.near_codec.as_ref(),
        };
        match codec {
            Some(spec) => (
                crate::conference::hep_codec_for_name(&spec.encoding_name),
                spec.clock_rate_hz.max(1),
            ),
            None => fallback,
        }
    }
}

/// Invoke `handle` for each RFC 3550 §6.4.1 reception report block in an observed compound RTCP
/// datagram — across every Sender Report and Receiver Report it carries. A malformed / unparseable
/// datagram yields nothing (telemetry never disturbs the media path). The single parse both the HEP
/// QoS export ([`qos_captures`]) and the control-channel quality events ([`qos_quality_events`]) share.
fn for_each_reception_block(
    observed: &ObservedRtcp,
    mut handle: impl FnMut(&siphon_rtp_media::rtcp::ReportBlock),
) {
    use siphon_rtp_media::rtcp::RtcpPacket;
    let Ok(packets) = siphon_rtp_media::rtcp::parse_compound(&observed.payload) else {
        return;
    };
    for packet in &packets {
        let blocks = match packet {
            RtcpPacket::SenderReport(report) => report.reports.as_slice(),
            RtcpPacket::ReceiverReport(report) => report.reports.as_slice(),
            RtcpPacket::Other { .. } => continue,
        };
        for block in blocks {
            handle(block);
        }
    }
}

/// Build HEP QoS/MOS report captures (`protocol_type` = REPORT_JSON) from an observed RTCP datagram:
/// one per reception report block (RFC 3550 §6.4.1) in any Sender/Receiver Report it carries. Each
/// block's `fraction_lost` + `jitter` drive the G.107 E-model MOS (ITU-T G.107). `rtt` is 0 — the
/// passive relay path measures none (see [`Engine::run_rtcp_export`]).
pub(super) fn qos_captures(
    observed: &ObservedRtcp,
    call_id: &str,
    capture_agent_id: u32,
    timestamp_secs: u32,
    timestamp_micros: u32,
    codec: siphon_rtp_hep::mos::Codec,
    clock_rate_hz: u32,
) -> Vec<Capture> {
    let mut captures = Vec::new();
    for_each_reception_block(observed, |block| {
        // No measured RTT on the passive relay path ⇒ one-way delay 0 (RFC 3550 §6.4.1).
        let impairments =
            Impairments::from_rtcp(block.fraction_lost, block.jitter, clock_rate_hz, 0.0);
        let report = QosReport::new(call_id, block.ssrc, codec, impairments);
        captures.push(Capture::from_qos_report(
            observed.source,
            observed.destination,
            timestamp_secs,
            timestamp_micros,
            capture_agent_id,
            &report,
        ));
    });
    captures
}

/// Build per-leg [`Event::CallQuality`] control-channel events from an observed RTCP datagram — one
/// per reception report block (RFC 3550 §6.4.1), from the **same** `fraction_lost` + `jitter` +
/// G.107 MOS the HEP QoS export derives ([`qos_captures`]), but delivered natively on the control
/// channel so SIPhon sees a 2-party plain-relay call's quality without parsing RTCP itself (the
/// counterpart to what conference / transcode legs emit). `from_tag` names the leg the RTCP traversed
/// (the reporting peer). `rtt` is 0 — the passive in-kernel relay originates no Sender Report, so it
/// measures no round-trip time (matching the HEP QoS report's one-way delay of 0).
pub(super) fn qos_quality_events(
    observed: &ObservedRtcp,
    call_id: &str,
    from_tag: &str,
    codec: siphon_rtp_hep::mos::Codec,
    clock_rate_hz: u32,
) -> Vec<Event> {
    let mut events = Vec::new();
    for_each_reception_block(observed, |block| {
        let impairments =
            Impairments::from_rtcp(block.fraction_lost, block.jitter, clock_rate_hz, 0.0);
        events.push(Event::CallQuality {
            conference_id: None,
            call_id: Some(call_id.to_string()),
            from_tag: from_tag.to_string(),
            jitter_ms: impairments.jitter_ms,
            loss_percent: impairments.loss_percent,
            mos: siphon_rtp_hep::mos::estimate_mos(codec, impairments),
        });
    });
    events
}

/// Build a HEP RTCP capture from an observed relayed RTCP datagram (`protocol_type` = RTCP).
pub(super) fn rtcp_capture(
    observed: &ObservedRtcp,
    call_id: String,
    capture_agent_id: u32,
    timestamp_secs: u32,
    timestamp_micros: u32,
) -> Capture {
    Capture {
        src: observed.source,
        dst: observed.destination,
        timestamp_secs,
        timestamp_micros,
        protocol_type: protocol_type::RTCP,
        capture_agent_id,
        correlation_id: Some(call_id),
        payload: observed.payload.to_vec(),
    }
}

/// The `(source, destination)` media addresses for a leg's RFC 4103 text-stream HEP report capture:
/// the peer's signalled text RTP address as the source (the stream's sender) and the engine's bound
/// text port as the destination — mirroring how an observed RTCP capture attributes source/destination
/// (sender → engine). Falls back to the leg's audio addresses when the text transport is not (yet)
/// both-ends known, so a family-consistent 5-tuple is always produced; the capture is grouped at the
/// collector by its correlation id (call-id), not the 5-tuple, so the fallback never mis-correlates.
fn text_stream_addresses(leg: &Leg) -> (std::net::SocketAddr, std::net::SocketAddr) {
    let destination = leg
        .text
        .map(|endpoint| endpoint.local_addr)
        .unwrap_or(leg.rtp.local_addr);
    let source = leg
        .text_remote_rtp
        .or(leg.remote_rtp)
        .unwrap_or(leg.rtp.local_addr);
    (source, destination)
}

/// Wall-clock seconds + microseconds since the Unix epoch, for HEP capture timestamps (a genuine
/// real-time capture stamp — distinct from the logical media-timeout clock).
fn wall_clock_now() -> (u32, u32) {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => (elapsed.as_secs() as u32, elapsed.subsec_micros()),
        Err(_) => (0, 0),
    }
}
