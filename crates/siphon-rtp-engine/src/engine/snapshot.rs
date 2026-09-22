//! HA `checkpoint` and `restore`: snapshot a call's replicable state and rebuild it on a standby.

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{
    Datapath, Endpoint, EndpointId, FlowAction, ForwardRule, LatchPolicy, SourceFilter,
};
use siphon_rtp_proto::CmdResult;
use siphon_rtp_srtp::leg::{SecureLeg, SecureLegRollover};
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite, SrtpKeyMaterial};
use siphon_rtp_srtp::StreamRollover;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::ice::IceCredentials;
use crate::media_pipeline::{EchoProfile, MediaCall};
use crate::sdp;
use crate::srtp_bridge::{BridgeCallPlan, BridgeFlowPlan, BridgeLeg};

use super::negotiate::{build_transcode_pair, secure_rtcp_relays, RtcpKeying, TranscodePair};
use super::{
    boxed_error_result, error_result, ok_empty, unknown_call, Call, CallerMediaLeg, ClientId,
    Engine, Leg, PipelineKind,
};

/// Map a [`Leg`] to its portable snapshot (local media ports + the peer's remote addresses). The
/// advertised IP is recorded only when it differs from the bound IP (a named-interface override), so a
/// plain-relay snapshot stays byte-compatible with a pre-interface standby.
pub(super) fn leg_snapshot(leg: &Leg) -> crate::ha::LegSnapshot {
    let advertised_ip = (leg.advertised_ip != leg.rtp.local_addr.ip()).then_some(leg.advertised_ip);
    crate::ha::LegSnapshot {
        rtp_local: leg.rtp.local_addr,
        rtcp_local: leg.rtcp.map(|endpoint| endpoint.local_addr),
        remote_rtp: leg.remote_rtp,
        remote_rtcp: leg.remote_rtcp,
        advertised_ip,
    }
}

/// Map a [`CodecSpec`] to its snapshot (the wire-relevant fields).
pub(super) fn codec_snapshot(codec: &CodecSpec) -> crate::ha::CodecSnapshot {
    crate::ha::CodecSnapshot {
        payload_type: codec.payload_type,
        encoding_name: codec.encoding_name.clone(),
        clock_rate_hz: codec.clock_rate_hz,
        channels: codec.channels,
        ptime_ms: codec.ptime_ms,
        encode_mode: codec.encode_mode,
        allowed_modes: codec.allowed_modes.clone(),
        opus: codec.opus.map(|params| crate::ha::OpusSnapshot {
            max_average_bitrate: params.max_average_bitrate,
            max_playback_rate_hz: params.max_playback_rate_hz,
            max_ptime_ms: params.max_ptime_ms,
            stereo: params.stereo,
            sprop_stereo: params.sprop_stereo,
            cbr: params.cbr,
            use_inband_fec: params.use_inband_fec,
            use_dtx: params.use_dtx,
        }),
    }
}

/// Reconstruct a [`CodecSpec`] from its snapshot on restore (for a transcode call's directions).
pub(super) fn restore_codec(snapshot: &crate::ha::CodecSnapshot) -> CodecSpec {
    CodecSpec::new(
        snapshot.payload_type,
        &snapshot.encoding_name,
        snapshot.clock_rate_hz,
        snapshot.channels,
        snapshot.ptime_ms,
    )
    .with_encode_mode(snapshot.encode_mode)
    .with_allowed_modes(snapshot.allowed_modes.clone())
    .with_opus_params(
        snapshot
            .opus
            .map(|params| siphon_rtp_codec::factory::OpusParams {
                max_average_bitrate: params.max_average_bitrate,
                max_playback_rate_hz: params.max_playback_rate_hz,
                max_ptime_ms: params.max_ptime_ms,
                stereo: params.stereo,
                sprop_stereo: params.sprop_stereo,
                cbr: params.cbr,
                use_inband_fec: params.use_inband_fec,
                use_dtx: params.use_dtx,
            }),
    )
}

/// Map an SDES [`CryptoAttribute`] to its snapshot (suite name + hex key material).
pub(super) fn crypto_snapshot(crypto: &CryptoAttribute) -> crate::ha::CryptoSnapshot {
    crate::ha::CryptoSnapshot {
        tag: crypto.tag,
        suite: crypto.suite.name().to_string(),
        master_key_hex: crate::ha::to_hex(&crypto.key.master_key),
        master_salt_hex: crate::ha::to_hex(&crypto.key.master_salt),
    }
}

/// Map a [`SecureLegRollover`] (from the SRTP bridge) to its snapshot on checkpoint.
fn secure_rollover_snapshot(rollover: &SecureLegRollover) -> crate::ha::SecureLegRolloverSnapshot {
    let stream = |value: &StreamRollover| crate::ha::StreamRolloverSnapshot {
        ssrc: value.ssrc,
        roc: value.roc,
        highest_seq: value.highest_seq,
    };
    crate::ha::SecureLegRolloverSnapshot {
        inbound_rtp: rollover.inbound_rtp.iter().map(stream).collect(),
        outbound_rtp: rollover.outbound_rtp.iter().map(stream).collect(),
        outbound_rtcp_index: rollover.outbound_rtcp_index,
    }
}

/// Map the engine [`PipelineKind`] to its snapshot mirror.
pub(super) fn pipeline_snapshot(pipeline: PipelineKind) -> crate::ha::PipelineSnapshot {
    use crate::ha::PipelineSnapshot;
    match pipeline {
        PipelineKind::Passthrough => PipelineSnapshot::Passthrough,
        // A secure *offerer* bridge is snapshotted as a crypto bridge; the restore path rebuilds a
        // far-secure one from the keys it does carry, and the offerer's own keying is not in the
        // snapshot at all (a restored call treats A as plaintext — see `Call::near_local_crypto`).
        PipelineKind::Srtp | PipelineKind::SrtpOfferer => PipelineSnapshot::Srtp,
        // Deliberately *not* folded into `Srtp`: a transcrypt has two legs and the secure snapshot
        // holds one. `checkpoint` refuses it outright, so this never reaches a blob — it is here so
        // the mapping cannot quietly mis-file a two-legged call as a one-legged one.
        PipelineKind::SrtpTranscrypt => PipelineSnapshot::SrtpTranscrypt,
        // Same reasoning, and the same refusal: the transcode twin holds two legs as well.
        PipelineKind::SrtpTranscryptMedia => PipelineSnapshot::SrtpTranscryptMedia,
        PipelineKind::Media => PipelineSnapshot::Media,
        PipelineKind::SrtpMedia => PipelineSnapshot::SrtpMedia,
        PipelineKind::Ws => PipelineSnapshot::Ws,
        // A terminated DTLS offerer is a DTLS call too, and restore refuses the DTLS kind: an
        // established DTLS association cannot move to a standby.
        PipelineKind::Dtls | PipelineKind::DtlsMedia | PipelineKind::DtlsOfferer => {
            PipelineSnapshot::Dtls
        }
    }
}

/// Map a datapath [`SourceFilter`] to its snapshot mirror.
pub(super) fn source_filter_snapshot(filter: SourceFilter) -> crate::ha::SourceFilterSnapshot {
    use crate::ha::SourceFilterSnapshot;
    match filter {
        SourceFilter::Exact(ip) => SourceFilterSnapshot::Exact(ip),
        SourceFilter::Subnet(ip, bits) => SourceFilterSnapshot::Subnet(ip, bits),
        SourceFilter::Any => SourceFilterSnapshot::Any,
    }
}

/// Map a datapath [`LatchPolicy`] to its snapshot mirror.
pub(super) fn latch_snapshot(latch: LatchPolicy) -> crate::ha::LatchSnapshot {
    use crate::ha::LatchSnapshot;
    match latch {
        LatchPolicy::Off => LatchSnapshot::Off,
        LatchPolicy::SignalledOnly => LatchSnapshot::SignalledOnly,
        LatchPolicy::Symmetric => LatchSnapshot::Symmetric,
    }
}

/// Map a snapshot source-filter back to the datapath [`SourceFilter`] on restore.
fn restore_source_filter(filter: crate::ha::SourceFilterSnapshot) -> SourceFilter {
    use crate::ha::SourceFilterSnapshot;
    match filter {
        SourceFilterSnapshot::Exact(ip) => SourceFilter::Exact(ip),
        SourceFilterSnapshot::Subnet(ip, bits) => SourceFilter::Subnet(ip, bits),
        SourceFilterSnapshot::Any => SourceFilter::Any,
    }
}

/// Map a snapshot latch policy back to the datapath [`LatchPolicy`] on restore.
fn restore_latch(latch: crate::ha::LatchSnapshot) -> LatchPolicy {
    use crate::ha::LatchSnapshot;
    match latch {
        LatchSnapshot::Off => LatchPolicy::Off,
        LatchSnapshot::SignalledOnly => LatchPolicy::SignalledOnly,
        LatchSnapshot::Symmetric => LatchPolicy::Symmetric,
    }
}

/// Reconstruct an SDES [`CryptoAttribute`] from its snapshot (hex-decoding the key/salt). Returns a
/// human-readable error for an unknown suite or malformed key material.
fn restore_crypto(snapshot: &crate::ha::CryptoSnapshot) -> Result<CryptoAttribute, String> {
    let suite = CryptoSuite::from_name(&snapshot.suite)
        .ok_or_else(|| format!("unknown crypto suite {}", snapshot.suite))?;
    let master_key: [u8; 16] = crate::ha::from_hex(&snapshot.master_key_hex)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("invalid master key hex (want 16 bytes)")?;
    let master_salt: [u8; 14] = crate::ha::from_hex(&snapshot.master_salt_hex)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("invalid master salt hex (want 14 bytes)")?;
    Ok(CryptoAttribute {
        tag: snapshot.tag,
        suite,
        key: SrtpKeyMaterial {
            master_key,
            master_salt,
        },
    })
}

/// Reconstruct a [`SecureLegRollover`] from its snapshot on restore.
fn restore_rollover(snapshot: &crate::ha::SecureLegRolloverSnapshot) -> SecureLegRollover {
    let stream = |value: &crate::ha::StreamRolloverSnapshot| StreamRollover {
        ssrc: value.ssrc,
        roc: value.roc,
        highest_seq: value.highest_seq,
    };
    SecureLegRollover {
        inbound_rtp: snapshot.inbound_rtp.iter().map(stream).collect(),
        outbound_rtp: snapshot.outbound_rtp.iter().map(stream).collect(),
        outbound_rtcp_index: snapshot.outbound_rtcp_index,
    }
}

/// Where a secure call's live SRTP rollover is sourced for an HA checkpoint. A plain secure leg
/// (`Srtp`) terminates SRTP in the [`crate::srtp_bridge::SrtpBridge`], so its rollover *and* the
/// in-datapath bridge flow plans are read from the bridge (via the endpoint roles). A secure
/// *transcode* leg (`SrtpMedia`) crypts inside the media actor, so only its shared `SecureLeg`
/// rollover is read (from [`crate::media_pipeline::MediaRegistry`], keyed by call-id) — there are no
/// bridge flows. Both carry the peer's answered SDES key, which lives on the `Call`, not the crypto
/// component.
enum SecureCheckpoint {
    /// A plain SDES-SRTP bridge (`Srtp`): read rollover + flow plans from the SRTP bridge.
    Bridge {
        roles: Vec<(EndpointId, crate::ha::EndpointRole)>,
        far_remote_crypto: crate::ha::CryptoSnapshot,
    },
    /// A secure transcode (`SrtpMedia`): read rollover from the media actor's shared secure leg.
    Media {
        far_remote_crypto: crate::ha::CryptoSnapshot,
    },
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Snapshot a call's replicable state for HA failover ([`Command::Checkpoint`]) — the opaque blob
    /// the SIP proxy stores and hands back to `restore` on a standby. Ownership-gated like `query`: a
    /// non-owner gets `unknown_call`, so it cannot even probe for a call's existence (A3 — docs §5).
    pub(super) fn checkpoint(&self, client: ClientId, call_id: &str) -> CmdResult {
        // `to_snapshot` only sees the `Call`; a secure call's live SRTP rollover lives in a running
        // component — the SRTP bridge for a plain secure leg (`Srtp`), the media actor for a secure
        // *transcode* leg (`SrtpMedia`) — so the closure also hands back what that later query needs
        // (the peer's SDES key, plus the endpoint roles the bridge query maps its flow ids through).
        let Some((snapshot, secure_ctx, transcrypt)) = self.owned_call(client, call_id, |call| {
            let snapshot = call.to_snapshot();
            let transcrypt = matches!(
                call.pipeline,
                PipelineKind::SrtpTranscrypt | PipelineKind::SrtpTranscryptMedia
            );
            let secure_ctx = call
                .far_remote_crypto
                .as_ref()
                .map(crypto_snapshot)
                .and_then(|far_remote_crypto| match call.pipeline {
                    PipelineKind::Srtp => Some(SecureCheckpoint::Bridge {
                        roles: call.endpoint_roles(),
                        far_remote_crypto,
                    }),
                    PipelineKind::SrtpMedia => Some(SecureCheckpoint::Media { far_remote_crypto }),
                    _ => None,
                });
            (snapshot, secure_ctx, transcrypt)
        }) else {
            return unknown_call(call_id);
        };
        // A transcrypt holds two independent `SecureLeg`s, and the secure snapshot record holds one
        // of everything: one peer key, one rollover, one crypto op per flow. Rather than checkpoint
        // half of it — which would restore as a far-secure bridge with the caller silently demoted
        // to plaintext — say so. The call keeps running; only replication is unavailable.
        if transcrypt {
            return CmdResult::Error {
                reason: "checkpoint is unsupported for a secure↔secure (transcrypt) call \
                         (two secure legs, and the snapshot record carries one)"
                    .to_string(),
            };
        }
        // A single-leg call has no far leg to put in the two-leg snapshot record, and nothing a standby
        // could resume: the far side of an IVR / echo / voice-AI call is this engine's own pipeline, not
        // replicable state. Say so rather than handing back a blob that would restore as a two-party
        // relay that never existed (`restore` documents the same limit from the other side).
        let Some(mut snapshot) = snapshot else {
            return CmdResult::Error {
                reason: "checkpoint is unsupported for a single-leg call (no far leg to replicate)"
                    .to_string(),
            };
        };
        // The registry key is the authoritative call-id (the snapshot builder left it blank).
        snapshot.call_id = call_id.to_string();
        // For a secure call, fold in the live SRTP rollover (+ bridge flow plans, for `Srtp`). Sourced
        // from the SRTP bridge for `Srtp`, from the media actor's shared `SecureLeg` for `SrtpMedia`.
        snapshot.secure = match secure_ctx {
            Some(SecureCheckpoint::Bridge {
                roles,
                far_remote_crypto,
            }) => self.build_secure_snapshot(&roles, far_remote_crypto),
            Some(SecureCheckpoint::Media { far_remote_crypto }) => {
                self.build_secure_media_snapshot(call_id, far_remote_crypto)
            }
            None => None,
        };
        match snapshot.to_json() {
            Ok(blob) => CmdResult::Checkpoint { snapshot: blob },
            Err(error) => error_result("checkpoint serialize", &error),
        }
    }

    /// Build the [`crate::ha::SecureSnapshot`] for a secure (`Srtp`) call by querying the SRTP bridge
    /// for the shared leg's rollover and the installed flow plans, mapping endpoint ids back to roles.
    /// `None` if the bridge no longer holds the call (raced a teardown).
    fn build_secure_snapshot(
        &self,
        roles: &[(EndpointId, crate::ha::EndpointRole)],
        far_remote_crypto: crate::ha::CryptoSnapshot,
    ) -> Option<crate::ha::SecureSnapshot> {
        let first = roles.first()?.0;
        let rollover = self.bridge.rollover_snapshot(first)?;
        let role_of = |id: EndpointId| roles.iter().find(|(i, _)| *i == id).map(|(_, r)| *r);
        let endpoint_ids: Vec<EndpointId> = roles.iter().map(|(id, _)| *id).collect();
        let bridge_flows = self
            .bridge
            .flow_plans(&endpoint_ids)
            .iter()
            .filter_map(|plan| {
                Some(crate::ha::BridgeFlowSnapshot {
                    endpoint: role_of(plan.endpoint)?,
                    // The HA record carries a one-sided crypto op, which is all it has ever needed:
                    // `checkpoint` admits only `PipelineKind::Srtp`, where exactly one side of each
                    // flow is keyed. A transcrypt flow has both sides keyed and no single-op mirror,
                    // and `checkpoint` refuses such a call before reaching here.
                    op: match (plan.ingress_leg, plan.egress_leg) {
                        (None, Some(_)) => crate::ha::BridgeOpSnapshot::Encrypt,
                        (Some(_), None) => crate::ha::BridgeOpSnapshot::Decrypt,
                        _ => return None,
                    },
                    accepted_source: source_filter_snapshot(plan.accepted_source),
                    out: role_of(plan.out_endpoint)?,
                    out_dst: plan.out_dst,
                })
            })
            .collect();
        Some(crate::ha::SecureSnapshot {
            far_remote_crypto,
            rollover: secure_rollover_snapshot(&rollover),
            bridge_flows,
        })
    }

    /// Build the [`crate::ha::SecureSnapshot`] for a secure-transcode (`SrtpMedia`) call: the peer's
    /// SDES key plus the media actor's shared [`SecureLeg`] SRTP rollover (RFC 3711 §3.3.1). Unlike an
    /// `Srtp` bridge, an `SrtpMedia` call crypts *inside* the transcode actor — there are no
    /// in-datapath bridge flow plans to snapshot (restore rebuilds the two transcode directions from
    /// the codecs + addresses), so `bridge_flows` is empty. `None` if the media actor no longer holds
    /// the call (raced a teardown) or is somehow not secure.
    fn build_secure_media_snapshot(
        &self,
        call_id: &str,
        far_remote_crypto: crate::ha::CryptoSnapshot,
    ) -> Option<crate::ha::SecureSnapshot> {
        let rollover = self.media.rollover_snapshot(call_id)?;
        Some(crate::ha::SecureSnapshot {
            far_remote_crypto,
            rollover: secure_rollover_snapshot(&rollover),
            bridge_flows: Vec::new(),
        })
    }

    /// Rebuild a call on this (standby) node from a [`Command::Checkpoint`] blob — the HA takeover.
    /// Allocates endpoints at the snapshot's **exact ports** (so a floating-IP standby needs no SIP
    /// re-INVITE), reinstalls the forward rules, and registers the call under the requesting client.
    ///
    /// Restores plain relay (`Passthrough`), the SDES-SRTP bridge (`Srtp`, keys and secure leg
    /// rebuilt), plaintext transcode (`Media`, transcode actor rebuilt), and secure transcode
    /// (`SrtpMedia`, transcode actor **and** the shared SRTP leg rebuilt and re-seeded). A WebSocket
    /// leg (`Ws`, whose bridge is an external session that cannot be resumed from a snapshot) or a DTLS
    /// leg (whose keys are handshake-derived, not signalled) is not restorable and is rejected up
    /// front. Any endpoint bind or flow install that fails rolls back the endpoints already bound.
    pub(super) async fn restore(&self, client: ClientId, blob: &str) -> CmdResult {
        use crate::ha::{self, PipelineSnapshot};
        let snapshot = match ha::CallSnapshot::from_json(blob) {
            Ok(snapshot) => snapshot,
            Err(error) => return error_result("restore: parse snapshot", &error),
        };
        // Supported: a plain relay, a secure SDES-SRTP bridge (`Srtp`), a plaintext transcode (`Media`),
        // and a secure transcode (`SrtpMedia`). `Ws` (external WS-bridge session, unrecoverable from a
        // snapshot) and `Dtls` (handshake-derived keys, not signalled) keep their rejection.
        match snapshot.pipeline {
            PipelineSnapshot::Passthrough => {}
            PipelineSnapshot::Srtp if snapshot.secure.is_some() => {}
            PipelineSnapshot::Media
                if snapshot.near_codec.is_some() && snapshot.far_codec.is_some() => {}
            PipelineSnapshot::SrtpMedia
                if snapshot.secure.is_some()
                    && snapshot.near_codec.is_some()
                    && snapshot.far_codec.is_some() => {}
            other => {
                return CmdResult::Error {
                    reason: format!("restore of a {other:?} call is not yet supported"),
                };
            }
        }
        if self.calls.contains_key(&snapshot.call_id) {
            return CmdResult::Error {
                reason: format!("cannot restore: call {} already exists", snapshot.call_id),
            };
        }

        // Bind the endpoints at their exact ports (shared by every pipeline).
        let bound = match self.bind_snapshot_endpoints(&snapshot).await {
            Ok(bound) => bound,
            Err(reason) => return *reason,
        };
        // Whichever step refuses from here on, the endpoints bound above are rolled back.
        if let Err(result) = self.restore_bound(client, snapshot, &bound) {
            self.free_bound(&bound).await;
            return *result;
        }
        ok_empty()
    }

    /// Rebuild a snapshotted call on endpoints already bound at its ports: the legs, the media path
    /// its pipeline names, and the call record under `client`. The caller rolls `bound` back on any
    /// refusal.
    fn restore_bound(
        &self,
        client: ClientId,
        snapshot: crate::ha::CallSnapshot,
        bound: &[(crate::ha::EndpointRole, Endpoint)],
    ) -> Result<(), Box<CmdResult>> {
        use crate::ha::{EndpointRole, PipelineSnapshot};
        let role_endpoint = |role: EndpointRole| -> Option<Endpoint> {
            bound
                .iter()
                .find(|(role_, _)| *role_ == role)
                .map(|(_, endpoint)| *endpoint)
        };
        // Every call has a near.rtp and a far.rtp; RTCP endpoints are optional (rtcp-mux).
        let (Some(near_rtp), Some(far_rtp)) = (
            role_endpoint(EndpointRole::NearRtp),
            role_endpoint(EndpointRole::FarRtp),
        ) else {
            return Err(Box::new(CmdResult::Error {
                reason: "restore: snapshot is missing a required RTP endpoint".to_string(),
            }));
        };
        let near = Leg {
            rtp: near_rtp,
            rtcp: role_endpoint(EndpointRole::NearRtcp),
            remote_rtp: snapshot.near.remote_rtp,
            remote_rtcp: snapshot.near.remote_rtcp,
            // Restore the advertised IP the primary used; a pre-interface snapshot has none, so fall
            // back to the bound IP (the old behaviour).
            advertised_ip: snapshot
                .near
                .advertised_ip
                .unwrap_or_else(|| near_rtp.local_addr.ip()),
            // RFC 4103 text stream: HA checkpoint/restore of the text endpoints is deferred (consistent
            // with the deferred SrtpMedia/Ws restore) — a restored call carries audio only.
            text: None,
            text_remote_rtp: None,
        };
        let far = Leg {
            rtp: far_rtp,
            rtcp: role_endpoint(EndpointRole::FarRtcp),
            remote_rtp: snapshot.far.remote_rtp,
            remote_rtcp: snapshot.far.remote_rtcp,
            advertised_ip: snapshot
                .far
                .advertised_ip
                .unwrap_or_else(|| far_rtp.local_addr.ip()),
            // RTT text stream: HA checkpoint/restore deferred (see the near leg).
            text: None,
            text_remote_rtp: None,
        };

        // Install the datapath flows and resolve the crypto per pipeline.
        let media = match snapshot.pipeline {
            PipelineSnapshot::Passthrough => self.restore_relay_flows(&snapshot, bound)?,
            PipelineSnapshot::Srtp => self.restore_srtp_bridge(&snapshot, bound)?,
            PipelineSnapshot::Media => {
                self.restore_transcode(client, &snapshot, near, far, false)?
            }
            PipelineSnapshot::SrtpMedia => {
                self.restore_transcode(client, &snapshot, near, far, true)?
            }
            _ => unreachable!("pipeline validated above"),
        };

        // Register the reconstructed call under the requesting (standby) client.
        *self.client_calls.entry(client).or_insert(0) += 1;
        for (_, endpoint) in bound {
            self.endpoint_calls
                .insert(endpoint.id, snapshot.call_id.clone());
        }
        // Read before the snapshot's credentials are moved into the call below.
        let restored_ice = snapshot.ice.is_some();
        self.calls.insert(
            snapshot.call_id.clone(),
            Call {
                owner: client,
                created_tick: self.datapath.now_ticks(),
                // A checkpoint is only taken of an answered call, so the standby adopts a live media
                // path rather than one still being set up: its silence is a dead path from the first
                // tick, and the setup ceiling must not hold it open past the media one.
                anchored_before_answer: false,
                // The checkpoint does not carry when the call started, and the restore time is not
                // it, so a restored call has no start for a voice-quality report to claim.
                started_at_unix_ms: None,
                ice: snapshot.ice.map(|ice| IceCredentials {
                    ufrag: ice.ufrag,
                    pwd: ice.pwd,
                }),
                // The HA snapshot carries only the engine's *own* ICE credentials, never the peer's,
                // so a restored leg cannot address a check to it (RFC 8445 §7.1.2 needs the peer's
                // ufrag + password). A restored ICE call therefore runs no consent freshness — it
                // falls back to the media-timeout sweep — and says so loudly below. Carrying the peer
                // credentials in the snapshot belongs with the full-agent HA work, not here.
                near_remote_ice: None,
                far_remote_ice: None,
                near_remote_candidates: Vec::new(),
                near_peer_is_lite: false,
                // Neither leg's gathered candidates are in the snapshot. A re-offer on a restored ICE
                // call gathers them again — host candidates on the same ports come out the same.
                far_local_candidates: Vec::new(),
                near_local_candidates: Vec::new(),
                // Not in the snapshot. A later re-offer from A presents B's leg with the engine's ICE
                // unless it restates `ice: remove` — the same gap `far_downgraded_to_plain` has below.
                far_ice_removed: false,
                from_tag: snapshot.from_tag,
                to_tag: snapshot.to_tag,
                near,
                // A snapshot is only ever taken of a 2-leg call — `checkpoint` refuses a single-leg one
                // — so a restored call always has both.
                far: Some(far),
                // Both parties own a leg on a restored (2-leg) call, so this is never read there.
                caller_media_leg: CallerMediaLeg::Near,
                far_local_crypto: media.far_local_crypto,
                far_remote_crypto: media.far_remote_crypto,
                // A DTLS-SRTP call is never restored (rejected above), so it is always plaintext/SDES here.
                far_dtls: false,
                far_dtls_role: None,
                // Not in the snapshot. A `dtls: off` far leg is plaintext on the wire, so a restored
                // one relays correctly; a later re-offer from A mirrors A's transport to B instead of
                // forcing `RTP/AVP` — the same gap the other un-snapshotted presentation state has.
                far_downgraded_to_plain: false,
                // Only a terminated DTLS offerer's call holds one, and a DTLS call is never restored.
                far_rtcp_fallback: false,
                // A restored call is a plaintext or SDES *far* leg; the offerer's own posture is
                // not in the snapshot and a restored call is never re-answered.
                near_secure: false,
                // Likewise the offerer's own keying: a secure *offerer* is not carried in the HA
                // snapshot, so a restored call treats A as plaintext rather than inventing a key the
                // peer never received.
                near_local_crypto: None,
                near_remote_crypto: None,
                // A terminated DTLS offerer is never checkpointed (its pipeline maps to the refused
                // DTLS snapshot), so a restored call never carries A's DTLS keying.
                near_dtls: None,
                // Set for a transcode (`Media`) call; `None` for relay/bridge, which don't transcode.
                near_codec: media.near_codec,
                // The offered set is not carried in the HA snapshot: a restored call is already
                // answered, so the answer-time negotiation never runs again, and a re-offer is judged
                // against the negotiated codec itself rather than the original offer.
                near_offered_codecs: Vec::new(),
                near_codec_withheld: false,
                far_codec: media.far_codec,
                // Neither party's direction attribute is carried in the HA snapshot — the standby never
                // saw either SDP. Both default to sendrecv, which is the conservative reading: a
                // restored call is measured against the short dead-path ceiling rather than being
                // granted the long held one on a guess. A re-offer after the restore corrects it.
                near_direction: sdp::MediaDirection::default(),
                far_direction: sdp::MediaDirection::default(),
                near_telephone_event: snapshot.near_telephone_event,
                // The far leg's telephone-event PT is not carried in the HA snapshot (a restored call
                // is not DTMF-blocked — the reason set is cleared above too); resolved only on a fresh
                // answer. `block DTMF` after a restore on a plain relay gates whichever side's PT is
                // known (near), which is the documented relay-path limitation.
                far_telephone_event: None,
                pipeline: media.pipeline,
                relay_flows: media.relay_flows,
                promotion_reasons: HashSet::new(),
                // The source gate is reconstructed from the snapshot's per-flow `accepted_source`
                // (which already folded in any `received-from` at the original answer), so the raw
                // hint is not needed on the restored node — for either leg.
                offer_received_from: None,
                far_received_from: None,
                pending_far_reoffer: None,
                // Single-leg IVR calls are not part of the proven HA-restore set, and the CN PT is not
                // carried in the snapshot; a restored single-leg leg degrades to audio-encoded comfort
                // noise. 2-leg (relay/bridge/transcode) restores never use this.
                comfort_noise_payload_type: None,
                // RTT text stream: not carried in the HA snapshot (restore deferred) — a restored call
                // is audio-only, so no text flows / promotion / events / secure keying either. The near
                // text SDES key is likewise absent, so a re-offer after a secure-text restore cannot yet
                // re-present it (secure-text HA restore is a follow-up).
                text_t140_payload_type: None,
                text_red_payload_type: None,
                text_relay_flows: Vec::new(),
                text_promotion_reasons: HashSet::new(),
                text_events: false,
                text_secure: false,
                near_text_remote_crypto: None,
                far_text_local_crypto: None,
                near_text_local_crypto: None,
            },
        );
        tracing::info!(call_id = %snapshot.call_id, "restored call from HA snapshot");
        // Be loud about the gap rather than let a restored ICE call look fully covered: consent
        // freshness needs the peer's credentials, which the snapshot does not carry.
        if restored_ice && self.consent.is_some() {
            tracing::warn!(
                target: "siphon_rtp::media",
                call_id = %snapshot.call_id,
                "restored ICE call runs WITHOUT RFC 7675 consent freshness — the HA snapshot carries \
                 no peer ICE credentials; dead-path detection falls back to the media-timeout sweep"
            );
        }
        Ok(())
    }

    /// Reinstall a plain relay's forward rules, resolving each snapshot role to its freshly-bound id.
    fn restore_relay_flows(
        &self,
        snapshot: &crate::ha::CallSnapshot,
        bound: &[(crate::ha::EndpointRole, Endpoint)],
    ) -> Result<RestoredMedia, Box<CmdResult>> {
        let mut relay_flows = Vec::new();
        for flow in &snapshot.flows {
            let (Some(installed_on), Some(out)) = (
                bound_endpoint(bound, flow.installed_on),
                bound_endpoint(bound, flow.out),
            ) else {
                return Err(Box::new(CmdResult::Error {
                    reason: "restore: a snapshot flow references an unknown endpoint role"
                        .to_string(),
                }));
            };
            let action = FlowAction::Forward(ForwardRule {
                out_endpoint: out.id,
                out_dst: flow.out_dst,
                accepted_source: restore_source_filter(flow.accepted_source),
                latch: restore_latch(flow.latch),
            });
            if let Err(error) = self.datapath.install_flow(installed_on.id, action) {
                return Err(boxed_error_result("restore: install forward flow", &error));
            }
            relay_flows.push((installed_on.id, action));
        }
        Ok(RestoredMedia::unkeyed(
            PipelineKind::Passthrough,
            relay_flows,
        ))
    }

    /// Rebuild a secure SDES-SRTP bridge: the two keys (the engine's own + the peer's), the bridge flow
    /// plans with roles resolved to freshly-bound ids, a redirect on every endpoint so the bridge crypts
    /// both directions, and the secure leg with its rollover seeded.
    fn restore_srtp_bridge(
        &self,
        snapshot: &crate::ha::CallSnapshot,
        bound: &[(crate::ha::EndpointRole, Endpoint)],
    ) -> Result<RestoredMedia, Box<CmdResult>> {
        // The early validation admits `Srtp` only with `secure` present; if a hand-crafted snapshot
        // violates that, refuse (the caller frees the ports) rather than panic.
        let Some(secure) = snapshot.secure.as_ref() else {
            return Err(Box::new(CmdResult::Error {
                reason: "restore: secure call missing secure snapshot".to_string(),
            }));
        };
        let (far_local, far_remote) = restore_sdes_keys(snapshot, secure, "secure call")?;
        let mut bridge_flows = Vec::with_capacity(secure.bridge_flows.len());
        for plan in &secure.bridge_flows {
            let (Some(endpoint), Some(out)) = (
                bound_endpoint(bound, plan.endpoint),
                bound_endpoint(bound, plan.out),
            ) else {
                return Err(Box::new(CmdResult::Error {
                    reason: "restore: a secure bridge flow references an unknown role".to_string(),
                }));
            };
            // A restored bridge is always the far-secure shape: `restore_srtp_bridge` keys from
            // `far_local`/`far_remote` and rebuilds the call with A plaintext (`near_secure: false`
            // below), so every keyed side is the far party's leg.
            let (ingress_leg, egress_leg) = match plan.op {
                crate::ha::BridgeOpSnapshot::Encrypt => (None, Some(BridgeLeg::Far)),
                crate::ha::BridgeOpSnapshot::Decrypt => (Some(BridgeLeg::Far), None),
            };
            bridge_flows.push(BridgeFlowPlan {
                endpoint: endpoint.id,
                ingress_leg,
                egress_leg,
                accepted_source: restore_source_filter(plan.accepted_source),
                out_endpoint: out.id,
                out_dst: plan.out_dst,
            });
        }
        self.redirect_endpoints(
            bound.iter().map(|(_, endpoint)| endpoint.id),
            "restore: install SRTP bridge redirect",
        )?;
        let mut leg = SecureLeg::new(&far_local.key, &far_remote.key);
        leg.seed_rollover(&restore_rollover(&secure.rollover));
        self.bridge.register(BridgeCallPlan {
            near_leg: None,
            far_leg: Some(leg),
            flows: bridge_flows,
        });
        Ok(RestoredMedia {
            far_local_crypto: Some(far_local),
            far_remote_crypto: Some(far_remote),
            ..RestoredMedia::unkeyed(PipelineKind::Srtp, Vec::new())
        })
    }

    /// Rebuild a transcoding call's actor: plaintext (`Media`), or with a secure far party
    /// (`SrtpMedia`) when `secure`, where the `Srtp` bridge's crypto (both SDES keys and the shared
    /// SecureLeg, its rollover seeded) is threaded into the transcode by `with_far_secure_leg` so the
    /// actor decrypts the secure peer's ingress and encrypts its egress (BGCF/SBC PSTN breakout).
    ///
    /// Jitter / codec state and the egress SSRC-seq-ts restart fresh (the cold-restore glitch), so the
    /// far side re-syncs. The SRTP rollover is *seeded* so the inbound decrypt keeps authenticating
    /// past a sequence wrap and the outbound never re-uses an index — no two-time-pad (RFC 3711
    /// §3.3.1 / §3.4). The source gates are reconstructed from the peers' signalled addresses: a
    /// Redirect pipeline carries no portable `flows`.
    fn restore_transcode(
        &self,
        client: ClientId,
        snapshot: &crate::ha::CallSnapshot,
        near: Leg,
        far: Leg,
        secure: bool,
    ) -> Result<RestoredMedia, Box<CmdResult>> {
        let (call, pipeline) = if secure {
            ("secure transcode call", "secure media pipeline")
        } else {
            ("media call", "media pipeline")
        };
        let refuse = |what: &str| {
            Box::new(CmdResult::Error {
                reason: format!("restore: {call} missing {what}"),
            })
        };
        let secure_snapshot = match (secure, snapshot.secure.as_ref()) {
            (false, _) => None,
            (true, Some(secure_snapshot)) => Some(secure_snapshot),
            (true, None) => return Err(refuse("secure snapshot")),
        };
        // Both codecs were validated present up front; the two remote addresses target egress.
        let (Some(near_codec_snap), Some(far_codec_snap)) =
            (snapshot.near_codec.as_ref(), snapshot.far_codec.as_ref())
        else {
            return Err(refuse("a codec"));
        };
        let (Some(a_rtp), Some(b_rtp)) = (near.remote_rtp, far.remote_rtp) else {
            return Err(refuse("a remote address"));
        };
        let keys = match secure_snapshot {
            Some(secure_snapshot) => Some(restore_sdes_keys(snapshot, secure_snapshot, call)?),
            None => None,
        };
        let near_codec = restore_codec(near_codec_snap);
        let far_codec = restore_codec(far_codec_snap);
        let (a_to_b, b_to_a) = build_transcode_pair(&TranscodePair {
            near_endpoint: near.rtp.id,
            near_source: SourceFilter::Exact(a_rtp.ip()),
            near_dst: a_rtp,
            far_endpoint: far.rtp.id,
            far_source: SourceFilter::Exact(b_rtp.ip()),
            far_dst: b_rtp,
            near_codec: &near_codec,
            far_codec: &far_codec,
            near_telephone_event: snapshot.near_telephone_event,
            far_telephone_event: None,
            record_path: None,
            // Noise suppression, echo cancellation and record-tone detection are not carried in the
            // checkpoint snapshot, so a cold restore resumes without them — matching how recording
            // (`record_path`) is not restored. The controller re-arms them by re-issuing the profile.
            noise_suppression: false,
            echo: EchoProfile::default(),
            beep_detection: false,
            beep_cadence_guard_ms: None,
        })
        .map_err(|(direction, reason)| {
            boxed_error_result(&format!("restore: {pipeline} ({direction})"), &reason)
        })?;
        // Redirect the RTP legs to the actor (rtcp-mux ⇒ RTCP rides them, (de)crypted inside).
        self.redirect_endpoints(
            [near.rtp.id, far.rtp.id],
            &format!(
                "restore: install {} redirect",
                pipeline.trim_end_matches(" pipeline")
            ),
        )?;
        let mut secure_parts = None;
        if let (Some((far_local, far_remote)), Some(secure_snapshot)) = (keys, secure_snapshot) {
            // Rebuild the shared SecureLeg and seed its rollover *before* wrapping it (the fresh leg
            // is unshared, so no lock is needed).
            let mut secure_leg = SecureLeg::new(&far_local.key, &far_remote.key);
            secure_leg.seed_rollover(&restore_rollover(&secure_snapshot.rollover));
            let leg = Arc::new(Mutex::new(secure_leg));
            // Non-muxed companion RTCP relayed through the shared SecureLeg, exactly as the live
            // builder does (RFC 3711 SRTCP; RFC 5761 keeps RTCP on its own port). Muxed: empty.
            let mut rtcp_relays = Vec::new();
            if let (Some(near_rtcp), Some(far_rtcp), Some(a_rtcp), Some(b_rtcp)) =
                (near.rtcp, far.rtcp, near.remote_rtcp, far.remote_rtcp)
            {
                self.redirect_endpoints(
                    [near_rtcp.id, far_rtcp.id],
                    "restore: install secure media RTCP redirect",
                )?;
                rtcp_relays = secure_rtcp_relays(
                    near_rtcp.id,
                    SourceFilter::Exact(a_rtcp.ip()),
                    b_rtcp,
                    far_rtcp.id,
                    SourceFilter::Exact(b_rtcp.ip()),
                    a_rtcp,
                    &RtcpKeying::Leg(leg.clone()),
                );
            }
            secure_parts = Some((far_local, far_remote, leg, rtcp_relays));
        }
        let owner_events = self.event_sink(client);
        let media_call = MediaCall::new(
            snapshot.call_id.clone(),
            snapshot.from_tag.clone(),
            snapshot.to_tag.clone(),
            a_to_b,
            b_to_a,
            true, // relay latch (the `no-latch` flag is not carried in the snapshot)
            None, // recording restarts on the new node if the proxy re-issues it
        );
        let (media_call, far_local_crypto, far_remote_crypto) = match secure_parts {
            Some((far_local, far_remote, leg, rtcp_relays)) => (
                media_call
                    .with_far_secure_leg(leg)
                    .with_rtcp_relays(rtcp_relays),
                Some(far_local),
                Some(far_remote),
            ),
            None => (media_call, None, None),
        };
        self.media
            .register(media_call, self.datapath.clone(), owner_events);
        Ok(RestoredMedia {
            pipeline: if secure {
                PipelineKind::SrtpMedia
            } else {
                PipelineKind::Media
            },
            relay_flows: Vec::new(),
            far_local_crypto,
            far_remote_crypto,
            near_codec: Some(near_codec),
            far_codec: Some(far_codec),
        })
    }

    /// Bind a snapshot's endpoints at their exact ports (HA restore), in role order. On any bind
    /// failure the endpoints already bound are freed and an error result is returned.
    async fn bind_snapshot_endpoints(
        &self,
        snapshot: &crate::ha::CallSnapshot,
    ) -> Result<Vec<(crate::ha::EndpointRole, Endpoint)>, Box<CmdResult>> {
        use crate::ha::EndpointRole;
        let mut targets: Vec<(EndpointRole, std::net::SocketAddr)> =
            vec![(EndpointRole::NearRtp, snapshot.near.rtp_local)];
        if let Some(addr) = snapshot.near.rtcp_local {
            targets.push((EndpointRole::NearRtcp, addr));
        }
        targets.push((EndpointRole::FarRtp, snapshot.far.rtp_local));
        if let Some(addr) = snapshot.far.rtcp_local {
            targets.push((EndpointRole::FarRtcp, addr));
        }
        let mut bound: Vec<(EndpointRole, Endpoint)> = Vec::new();
        for (role, addr) in targets {
            // Re-bind the exact source IP *and* port the primary used, so a call pinned to a named
            // interface resumes on the same source address (not just the datapath's default bind IP).
            match self
                .datapath
                .alloc_endpoint_on_port_at(addr.ip(), addr.port())
                .await
            {
                Ok(endpoint) => bound.push((role, endpoint)),
                Err(error) => {
                    self.free_bound(&bound).await;
                    return Err(Box::new(error_result(
                        "restore: bind endpoint at snapshot port",
                        &error,
                    )));
                }
            }
        }
        Ok(bound)
    }

    /// Free the endpoints bound so far during a [`Self::restore`] that then failed (rollback).
    async fn free_bound(&self, bound: &[(crate::ha::EndpointRole, Endpoint)]) {
        let endpoints: Vec<Endpoint> = bound.iter().map(|(_, endpoint)| *endpoint).collect();
        self.free(&endpoints).await;
    }
}

/// What a restored call's media path installed, for its call record.
struct RestoredMedia {
    pipeline: PipelineKind,
    relay_flows: Vec<(EndpointId, FlowAction)>,
    far_local_crypto: Option<CryptoAttribute>,
    far_remote_crypto: Option<CryptoAttribute>,
    near_codec: Option<CodecSpec>,
    far_codec: Option<CodecSpec>,
}

impl RestoredMedia {
    /// A restored media path with no keys and no transcode codecs.
    fn unkeyed(pipeline: PipelineKind, relay_flows: Vec<(EndpointId, FlowAction)>) -> Self {
        Self {
            pipeline,
            relay_flows,
            far_local_crypto: None,
            far_remote_crypto: None,
            near_codec: None,
            far_codec: None,
        }
    }
}

/// The freshly-bound endpoint a snapshot `role` maps to, if the snapshot bound one.
fn bound_endpoint(
    bound: &[(crate::ha::EndpointRole, Endpoint)],
    role: crate::ha::EndpointRole,
) -> Option<Endpoint> {
    bound
        .iter()
        .find(|(bound_role, _)| *bound_role == role)
        .map(|(_, endpoint)| *endpoint)
}

/// The two SDES keys of a secure restored call — the engine's own and the peer's — or the refusal
/// naming what is missing or malformed. `call` names the call's shape in that refusal.
fn restore_sdes_keys(
    snapshot: &crate::ha::CallSnapshot,
    secure: &crate::ha::SecureSnapshot,
    call: &str,
) -> Result<(CryptoAttribute, CryptoAttribute), Box<CmdResult>> {
    let far_local = match snapshot.far_local_crypto.as_ref().map(restore_crypto) {
        Some(Ok(crypto)) => crypto,
        Some(Err(reason)) => return Err(boxed_error_result("restore: far_local key", &reason)),
        None => {
            return Err(Box::new(CmdResult::Error {
                reason: format!("restore: {call} missing far_local_crypto"),
            }))
        }
    };
    let far_remote = restore_crypto(&secure.far_remote_crypto)
        .map_err(|reason| boxed_error_result("restore: far_remote key", &reason))?;
    Ok((far_local, far_remote))
}
