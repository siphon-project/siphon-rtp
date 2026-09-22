//! Call teardown: `delete`, the shared end-of-call path, and the CDR.

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{Datapath, EndpointId};
use siphon_rtp_proto::{
    CmdResult, Event, LegSummary, PlayEndReason, RecordingEndReason, WsBridgeEndReason,
    WsTeeEndReason, X3EndReason,
};

use crate::media_pipeline::{DirectionQuality, FinalCallQuality};

use super::{unix_time_ms, unknown_call, Call, ClientId, Engine, Leg};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Tear down a call's datapath + slow-path state without an ownership check (an internal cleanup
    /// for a half-built call). Frees the sockets and drops any bridge / media / WS registration.
    pub(super) async fn teardown_call(&self, call_id: &str) {
        if let Some((_, call)) = self.calls.remove(call_id) {
            let endpoints: Vec<EndpointId> = call.all_endpoint_ids().collect();
            // A URL playback still fetching for this call dies with it: abort the task before the
            // media actor is deregistered, and release the controller awaiting it. Without this the
            // fetch would land on a call that no longer exists (harmless) while the controller waited
            // for a completion that never came (not harmless).
            self.cancel_pending_fetches_for_call(call_id, PlayEndReason::Error);
            // Free any SIPREC subscriptions first (detach forks, abort drains, free subscriber ports)
            // before the media actor is deregistered.
            self.drop_subscriptions(call_id).await;
            // …and any WS tee riding the same fan-out, so its transport closes and the controller
            // gets its `ws_tee_ended` rather than a silently dead stream.
            self.stop_ws_tee(call_id, WsTeeEndReason::Detached).await;
            // …and any decoded recording on it, **before** the media actor is deregistered. This is
            // what turns a hangup into a finished, playable file rather than a valid WAV declaring
            // zero samples: it detaches the sinks, waits for the writer to finalize the header, and
            // lets the completion event go out naming `call_ended`. A voicemail box depends on it —
            // the caller hanging up is the normal way a message ends.
            self.stop_wav_recordings_for_call(call_id, RecordingEndReason::CallEnded)
                .await;
            // …and any lawful interception, so the controller gets a final `x3_ended` carrying the
            // delivered/dropped counts its compliance record needs, rather than a silently dead
            // delivery connection.
            self.stop_x3(call_id, X3EndReason::CallEnded).await;
            self.bridge.deregister(endpoints.iter().copied());
            self.media.deregister(call_id);
            // ...and any WS takeover bridge, so its controller gets a final `ws_bridge_ended` rather
            // than a stream that simply stops.
            self.stop_ws_bridge(call_id, WsBridgeEndReason::CallEnded)
                .await;
            if let Some(consent) = &self.consent {
                consent.unregister_call(call_id);
            }
            if let Some(agents) = &self.ice_agents {
                agents.unregister_call(call_id);
            }
            for endpoint in endpoints {
                self.datapath.remove_endpoint(endpoint).await;
                self.endpoint_calls.remove(&endpoint);
            }
            self.release_client_call(call.owner);
        }
    }

    pub(super) async fn delete(&self, client: ClientId, call_id: &str) -> CmdResult {
        // Only the client that created the call may tear it down (A3 — docs §5). A non-owner (or a
        // missing call) gets `unknown_call`, so it cannot even probe for a call's existence.
        match self
            .calls
            .remove_if(call_id, |_, call| call.owner == client)
        {
            Some((_, call)) => {
                // Emit the CDR and free everything the call held (shared with the media-timeout reaper).
                self.finish_call(call_id, &call, "delete").await;
                CmdResult::Ok {
                    sdp: None,
                    duration_ms: None,
                    play_id: None,
                    recording_id: None,
                    to_tag: None,
                    stats: None,
                }
            }
            None => unknown_call(call_id),
        }
    }

    /// Shared call teardown for both the controller-driven [`Self::delete`] and the media-timeout
    /// reaper ([`Self::reap_idle`]): emit the end-of-call CDR (target `siphon_rtp::cdr`) — the
    /// datapath byte/packet counters plus the media actor's per-direction quality (RFC 3550 loss and
    /// jitter with an ITU-T G.107 MOS) — then free every resource the call held (SIPREC subscriptions,
    /// SRTP/media/WS pipelines, datapath endpoints, and the owner's session quota).
    ///
    /// `call` has already been removed from the registry by the caller, so this runs **exactly once**
    /// per call; `reason` labels why it ended (`delete` / `media_timeout`). The quality half is
    /// best-effort: a plain in-kernel relay has no media actor, and a slow/aborted actor times out
    /// ([`CDR_QUALITY_TIMEOUT`]) — the CDR then carries the byte/packet counters only. Counters are
    /// snapshotted, and the actor is queried, **before** the endpoints and actor are torn down below.
    pub(super) async fn finish_call(&self, call_id: &str, call: &Call, reason: &str) {
        let near_counters = self.leg_counters(&call.near);
        let far_counters = call
            .far
            .as_ref()
            .map(|far| self.leg_counters(far))
            .unwrap_or_default();
        let quality = self.media.final_quality(call_id, CDR_QUALITY_TIMEOUT).await;
        // RFC 4103 content QoS from the userspace text processor, when the text stream was promoted for
        // observability. `None` for an audio-only call, or a text stream left on the in-kernel relay
        // (which contributes only the datapath packet/byte counts, no content-level text QoS). The near
        // leg carries the A→B reassembler's counters, the far leg the B→A — mirroring the audio CDR's
        // per-direction attribution.
        let text_counters = self.text.final_counters(call_id, CDR_QUALITY_TIMEOUT).await;
        let near_text = text_counters.map(|counters| counters.near);
        let far_text = text_counters.map(|counters| counters.far);
        let duration_s = self.datapath.now_ticks().saturating_sub(call.created_tick);

        tracing::info!(
            target: "siphon_rtp::cdr",
            call_id = %call_id,
            reason,
            duration_s,
            pipeline = ?call.pipeline,
            near_codec = call.near_codec.as_ref().map(|codec| codec.encoding_name.as_str()).unwrap_or("-"),
            far_codec = call.far_codec.as_ref().map(|codec| codec.encoding_name.as_str()).unwrap_or("-"),
            // RFC 4103 Real-Time Text stream (when the call relayed one): the negotiated T.140 / RED
            // payload types, `-` for an audio-only call.
            text_t140 = call.text_t140_payload_type.map_or_else(|| "-".to_string(), |pt| pt.to_string()),
            text_red = call.text_red_payload_type.map_or_else(|| "-".to_string(), |pt| pt.to_string()),
            // RFC 4103 content QoS, present only when the text stream was promoted (recording /
            // `text_events`); `-` when text stayed on the in-kernel relay or the call had no text.
            text_chars = text_counters.map_or_else(|| "-".to_string(), |counters| (counters.near.characters + counters.far.characters).to_string()),
            text_missing_markers = text_counters.map_or_else(|| "-".to_string(), |counters| (counters.near.missing_markers + counters.far.missing_markers).to_string()),
            text_recovered = text_counters.map_or_else(|| "-".to_string(), |counters| (counters.near.recovered_from_redundancy + counters.far.recovered_from_redundancy).to_string()),
            "call finished"
        );
        // One record per **party**. A two-party call has two: the near leg is party A (offerer,
        // `from_tag`), whose sent stream is the media actor's `a_to_b` ingress, and the far leg is party
        // B (answerer, `to_tag`) ⇒ the `b_to_a` ingress.
        //
        // A **single-leg** call (IVR / announcement / echo / voice-AI — no `answer`, so no far party)
        // has one. `answer_local` owns a single leg outright, but an offer-only call still holds the far
        // leg its offer allocated, and the caller may be reaching *either* socket (see
        // [`CallerMediaLeg`]) — so the counters are summed rather than picked. Whichever leg is idle
        // contributes 0, so the sum is exactly the caller's traffic either way, and it lands on the
        // record that also carries the caller's tag, address and measured quality.
        let a_to_b = quality
            .as_ref()
            .map(|quality: &FinalCallQuality| &quality.a_to_b);
        let b_to_a = quality.as_ref().map(|quality| &quality.b_to_a);
        let legs = match call.far.as_ref().filter(|_| !call.is_single_leg()) {
            Some(far) => {
                self.log_cdr_leg(
                    call_id,
                    "near",
                    &call.from_tag,
                    call.near.rtp.local_addr,
                    call.near.remote_rtp,
                    &near_counters,
                    a_to_b,
                );
                self.log_cdr_leg(
                    call_id,
                    "far",
                    call.to_tag.as_deref().unwrap_or("-"),
                    far.rtp.local_addr,
                    far.remote_rtp,
                    &far_counters,
                    b_to_a,
                );
                // The stream the engine sends A is the one B→A carries, and the one it sends B is
                // A→B's, so each leg's egress SSRC comes from the other direction.
                let near_media = LegMedia {
                    local_address: advertised_address(&call.near),
                    remote_address: self.observed_remote(&call.near),
                    egress_ssrc: b_to_a.and_then(|quality| quality.egress_ssrc),
                };
                let far_media = LegMedia {
                    local_address: advertised_address(far),
                    remote_address: self.observed_remote(far),
                    egress_ssrc: a_to_b.and_then(|quality| quality.egress_ssrc),
                };
                vec![
                    leg_summary(
                        &call.from_tag,
                        call.near_codec.as_ref(),
                        &near_counters,
                        a_to_b,
                        near_text,
                        near_media,
                    ),
                    leg_summary(
                        call.to_tag.as_deref().unwrap_or("-"),
                        call.far_codec.as_ref(),
                        &far_counters,
                        b_to_a,
                        far_text,
                        far_media,
                    ),
                ]
            }
            None => {
                let mut caller_counters = near_counters;
                caller_counters.packets_in += far_counters.packets_in;
                caller_counters.packets_out += far_counters.packets_out;
                caller_counters.bytes_in += far_counters.bytes_in;
                caller_counters.bytes_out += far_counters.bytes_out;
                caller_counters.packets_dropped += far_counters.packets_dropped;
                caller_counters.packets_lost += far_counters.packets_lost;
                self.log_cdr_leg(
                    call_id,
                    "near",
                    &call.from_tag,
                    call.caller_leg().rtp.local_addr,
                    call.near.remote_rtp,
                    &caller_counters,
                    a_to_b,
                );
                // The caller may reach either socket (see [`CallerMediaLeg`]), but its signalled
                // address is on the near leg, as for the log line above.
                let caller = call.caller_leg();
                let caller_media = LegMedia {
                    local_address: advertised_address(caller),
                    remote_address: self
                        .datapath
                        .latched_source(caller.rtp.id)
                        .or(call.near.remote_rtp),
                    egress_ssrc: b_to_a.and_then(|quality| quality.egress_ssrc),
                };
                vec![leg_summary(
                    &call.from_tag,
                    call.near_codec.as_ref(),
                    &caller_counters,
                    a_to_b,
                    near_text,
                    caller_media,
                )]
            }
        };

        // Structured twin of the CDR for the SBC: SIPhon merges this per-leg media summary with its own
        // SIP-side record into one CDR. Additive `Event::CallSummary` — a consumer predating the variant
        // decodes it as `Event::Unknown` and ignores it. Same assembly as the log block above, so a
        // single-leg call carries exactly one entry here too.
        self.push_event(
            call.owner,
            Event::CallSummary {
                call_id: call_id.to_string(),
                reason: reason.to_string(),
                duration_ms: duration_s.saturating_mul(1000),
                started_at_unix_ms: call.started_at_unix_ms,
                ended_at_unix_ms: unix_time_ms(),
                legs,
            },
        );

        // RFC 4103 Real-Time Text content QoS on the HEP wire (VoIPmonitor / Homer), when the call
        // carried a *promoted* text stream and HEP export is enabled. Correlated by call-id, exactly
        // like the per-interval RTCP/voice QoS the same collector already sees, so a passive collector
        // groups the text report with the rest of the call. A per-call summary (not per-interval like
        // RTCP), because the T.140 content counters are only final at teardown. Fire-and-forget.
        self.export_text_qos(call, call_id, near_text, far_text)
            .await;

        // Free everything the call held (the steps `delete` and `reap_idle` previously duplicated) —
        // including the RFC 4103 text endpoints (`all_endpoint_ids`), so a text stream's ports are
        // released with the call.
        let endpoints: Vec<EndpointId> = call.all_endpoint_ids().collect();
        self.drop_subscriptions(call_id).await;
        // Any WS tee riding the same fan-out closes with the call, so its controller gets a final
        // `ws_tee_ended` (with the lifetime frame counters) rather than a silently dead stream.
        self.stop_ws_tee(call_id, WsTeeEndReason::Detached).await;
        // …and any decoded recording, while the media actor still holds its sinks. Detaching them is
        // what makes the writer finalize the header and emit `recording_finished` naming `call_ended`,
        // and awaiting it is what keeps the call from being reported gone while its file is still
        // being written. Left to `media.deregister` below, the writer finished whenever the dropped
        // actor let go of it, after `delete` had already answered, and the recording stayed registered.
        self.stop_wav_recordings_for_call(call_id, RecordingEndReason::CallEnded)
            .await;
        // …and any lawful interception, for the same reason: a final `x3_ended` with the delivery
        // counts, and no delivery task outliving the call it was intercepting.
        self.stop_x3(call_id, X3EndReason::CallEnded).await;
        self.bridge.deregister(endpoints.iter().copied());
        self.media.deregister(call_id);
        self.text.deregister(call_id);
        // The WS takeover bridge closes with the call, so its controller gets a final
        // `ws_bridge_ended` rather than a stream that simply stops.
        self.stop_ws_bridge(call_id, WsBridgeEndReason::CallEnded)
            .await;
        // Consent state dies with the call — otherwise a torn-down leg keeps a checker (and its
        // credentials) alive forever and the registry never drains to zero.
        if let Some(consent) = &self.consent {
            consent.unregister_call(call_id);
        }
        if let Some(agents) = &self.ice_agents {
            agents.unregister_call(call_id);
        }
        for endpoint in endpoints {
            self.datapath.remove_endpoint(endpoint).await;
            self.endpoint_calls.remove(&endpoint);
        }
        self.release_client_call(call.owner);
    }

    /// Retire `endpoints` from the SRTP/DTLS bridge — the bridge half of dropping a leg that is not a
    /// whole call. Frees each flow, its destination watch and its association, and aborts the tasks
    /// driving it.
    ///
    /// Call teardown reaches the bridge through [`Self::teardown_call`] / [`Self::finish_call`], but a
    /// conference seat can be dropped while its room lives on — `conference_leave`, a failed
    /// checklist, the idle reap. Those paths freed the datapath endpoint and stopped the ICE follower
    /// while leaving the bridge registration behind, so a DTLS seat's handshake and drain tasks
    /// outlived the participant and a long-running room accumulated one set per seat that had come and
    /// gone. Idempotent: an endpoint the bridge never owned has nothing to drop.
    pub(super) fn retire_dtls_endpoints(&self, endpoints: &[EndpointId]) {
        self.bridge.deregister(endpoints.iter().copied());
    }

    /// Sum the datapath byte/packet counters across every endpoint a leg owns (RTP + optional RTCP) —
    /// the same aggregation [`Self::query`] does, for the CDR's per-leg `in/out` figures.
    fn leg_counters(&self, leg: &Leg) -> siphon_rtp_datapath::EndpointStats {
        let mut total = siphon_rtp_datapath::EndpointStats::default();
        for endpoint in leg.endpoint_ids() {
            let stats = self.datapath.stats(endpoint).unwrap_or_default();
            total.packets_in += stats.packets_in;
            total.packets_out += stats.packets_out;
            total.bytes_in += stats.bytes_in;
            total.bytes_out += stats.bytes_out;
            total.packets_dropped += stats.packets_dropped;
            total.packets_lost += stats.packets_lost;
        }
        total
    }

    /// Where a leg's party actually sent from, falling back to the address it signalled.
    ///
    /// Asked of each latch in turn because a leg lives on exactly one of them and none of them can
    /// answer for another: the datapath's, for an in-kernel `Forward` relay; the SRTP bridge's, for
    /// a crypto-bridged or transcrypted leg; the media registry's, for a transcoded one. Only the
    /// first of those existed here, and it is never written for a `Redirect` leg — so every bridged,
    /// transcoded, secure or recorded call reported the party's *signalled* address however far its
    /// media had actually moved. A record that cannot show a leg replying to the wrong place is how
    /// that class of fault stays invisible until someone takes a host capture.
    fn observed_remote(&self, leg: &Leg) -> Option<std::net::SocketAddr> {
        self.datapath
            .latched_source(leg.rtp.id)
            .or_else(|| self.bridge.latched_source(leg.rtp.id))
            .or_else(|| self.media.latched_source(leg.rtp.id))
            .or(leg.remote_rtp)
    }

    /// Render one CDR leg line (target `siphon_rtp::cdr`): the datapath byte/packet counters, plus —
    /// when the media actor reported quality for this direction — the RFC 3550 loss/jitter and the
    /// G.107 MOS shape across the call. `rtt_ms` is `n/a` on the relay/transcode path (no measured
    /// RTT), and `mos_basis` states whether the MOS includes the G.107 delay term (`full`) or is
    /// loss/jitter-only (`loss+jitter`) — the honest marker, never a fabricated zero RTT.
    ///
    /// `local` is the engine socket this party talks to and `remote` its signalled address; they are
    /// passed in rather than read off one [`Leg`] because a single-leg call splits them — the caller's
    /// address is on the near leg while the socket it reaches may be the far one (see
    /// [`CallerMediaLeg`]).
    fn log_cdr_leg(
        &self,
        call_id: &str,
        leg: &str,
        tag: &str,
        local: std::net::SocketAddr,
        remote: Option<std::net::SocketAddr>,
        counters: &siphon_rtp_datapath::EndpointStats,
        quality: Option<&DirectionQuality>,
    ) {
        let remote = remote.map_or_else(|| "-".to_string(), |addr| addr.to_string());
        match quality {
            Some(quality) if quality.ssrc.is_some() || quality.packets_received > 0 => {
                let ssrc = quality
                    .ssrc
                    .map_or_else(|| "-".to_string(), |ssrc| format!("{ssrc:08x}"));
                let rtt_ms = quality
                    .rtt_ms
                    .map_or_else(|| "n/a".to_string(), |rtt| format!("{rtt:.1}"));
                let mos_average = format_optional_mos(quality.mos_average);
                let mos_min = format_optional_mos(quality.mos_min);
                let mos_max = format_optional_mos(quality.mos_max);
                let mos_min_at = format_call_offset(quality.mos_min_at_ms);
                let mos_max_at = format_call_offset(quality.mos_max_at_ms);
                let mos_basis = if quality.rtt_ms.is_some() {
                    "full"
                } else {
                    "loss+jitter"
                };
                tracing::info!(
                    target: "siphon_rtp::cdr",
                    call_id = %call_id,
                    leg,
                    tag,
                    local = %local,
                    remote = %remote,
                    packets_in = counters.packets_in,
                    bytes_in = counters.bytes_in,
                    packets_out = counters.packets_out,
                    bytes_out = counters.bytes_out,
                    packets_dropped = counters.packets_dropped,
                    net_lost = counters.packets_lost,
                    ssrc = %ssrc,
                    lost = quality.packets_lost,
                    loss_percent = quality.loss_percent,
                    loss_percent_max = quality.loss_percent_max,
                    jitter_ms = quality.jitter_ms,
                    jitter_ms_max = quality.jitter_ms_max,
                    rtt_ms = %rtt_ms,
                    mos_avg = %mos_average,
                    mos_min = %mos_min,
                    mos_min_at = %mos_min_at,
                    mos_max = %mos_max,
                    mos_max_at = %mos_max_at,
                    mos_basis,
                    "leg"
                );
            }
            _ => {
                // Counters-only — a plain in-kernel relay (no media actor) or a leg that never received.
                tracing::info!(
                    target: "siphon_rtp::cdr",
                    call_id = %call_id,
                    leg,
                    tag,
                    local = %local,
                    remote = %remote,
                    packets_in = counters.packets_in,
                    bytes_in = counters.bytes_in,
                    packets_out = counters.packets_out,
                    bytes_out = counters.bytes_out,
                    packets_dropped = counters.packets_dropped,
                    net_lost = counters.packets_lost,
                    "leg"
                );
            }
        }
    }
}

/// The `delete`/reap grace window for the CDR quality query: a slow or already-aborted media actor
/// must never stall call teardown, so beyond this the CDR is logged with the byte/packet counters only.
const CDR_QUALITY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// Format a MOS value to two decimals, or `-` when no sample was taken on the leg.
fn format_optional_mos(mos: Option<f64>) -> String {
    mos.map_or_else(|| "-".to_string(), |value| format!("{value:.2}"))
}

/// Render a call-relative millisecond offset as `M:SS` — rtpengine's "lowest MOS ... at 0:33" style.
fn format_call_offset(milliseconds: u64) -> String {
    let seconds = milliseconds / 1000;
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

/// Where one leg's media ran: the addressing half of [`LegSummary`] an RFC 6035 report needs.
struct LegMedia {
    /// The engine's advertised media address toward the party.
    local_address: std::net::SocketAddr,
    /// Where the party sent from, when known.
    remote_address: Option<std::net::SocketAddr>,
    /// The SSRC of the stream the engine sent the party, when a media actor originated it.
    egress_ssrc: Option<u32>,
}

/// A leg's media address as its party sees it: the advertised IP (a named interface's, which need
/// not be the bound one) and the RTP port.
fn advertised_address(leg: &Leg) -> std::net::SocketAddr {
    std::net::SocketAddr::new(leg.advertised_ip, leg.rtp.local_addr.port())
}

/// Assemble one leg's [`LegSummary`] for [`Event::CallSummary`] from its datapath counters and, when a
/// media actor measured it, its reception quality — the structured mirror of [`Engine::log_cdr_leg`].
/// The quality half is filled only when a direction actually measured a stream (an SSRC or inbound
/// packets); otherwise the leg is counters-only (an in-kernel relay, or a leg that never received).
fn leg_summary(
    tag: &str,
    codec: Option<&CodecSpec>,
    counters: &siphon_rtp_datapath::EndpointStats,
    quality: Option<&DirectionQuality>,
    text: Option<siphon_rtp_proto::TextStreamStats>,
    media: LegMedia,
) -> LegSummary {
    let mut summary = LegSummary {
        tag: tag.to_string(),
        codec: codec.map(|codec| codec.encoding_name.clone()),
        payload_type: codec.map(|codec| codec.payload_type),
        local_address: Some(media.local_address),
        remote_address: media.remote_address,
        egress_ssrc: media.egress_ssrc,
        packets_in: counters.packets_in,
        bytes_in: counters.bytes_in,
        packets_out: counters.packets_out,
        bytes_out: counters.bytes_out,
        packets_dropped: counters.packets_dropped,
        ssrc: None,
        packets_lost: None,
        loss_percent: None,
        jitter_ms: None,
        rtt_ms: None,
        mos_average: None,
        mos_min: None,
        mos_max: None,
        mos_basis: None,
        // RFC 4103 content QoS, present only when the call promoted the text stream for observability.
        text,
    };
    if let Some(quality) =
        quality.filter(|quality| quality.ssrc.is_some() || quality.packets_received > 0)
    {
        summary.ssrc = quality.ssrc;
        summary.packets_lost = Some(quality.packets_lost);
        summary.loss_percent = Some(quality.loss_percent);
        summary.jitter_ms = Some(quality.jitter_ms);
        summary.rtt_ms = quality.rtt_ms;
        summary.mos_average = quality.mos_average;
        summary.mos_min = quality.mos_min;
        summary.mos_max = quality.mos_max;
        summary.mos_basis = Some(
            if quality.rtt_ms.is_some() {
                "full"
            } else {
                "loss+jitter"
            }
            .to_string(),
        );
    } else if counters.packets_lost > 0 {
        // Counters-only relay leg (kernelized XDP_TX or UDP-loopback Forward): no jitter buffer to
        // derive the exact expected-minus-received figure, so surface the datapath's RFC 3550 §A.1
        // forward-gap network-loss estimate instead — without it a lossy relay leg reports zero loss
        // in the structured CDR. When the quality half IS present its measured loss wins (above).
        summary.packets_lost = Some(u32::try_from(counters.packets_lost).unwrap_or(u32::MAX));
    }
    summary
}
