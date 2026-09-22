//! Installing an answered call's media path: ICE on its endpoints, the SRTP and DTLS crypto
//! bridges, the transcoding media actor (plaintext or with a secure far party), the in-datapath
//! plain relay, and the RFC 4103 text stream.

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{
    Datapath, EndpointId, FlowAction, IceAgentMode, IceConfig, LatchPolicy, SourceFilter,
};
use siphon_rtp_dtls::{DtlsCertificate, DtlsRole, Fingerprint as DtlsFingerprint};
use siphon_rtp_proto::{CmdResult, Event, ProfileFlags};
use siphon_rtp_srtp::leg::{SecureLeg, SecureLegRollover};
use siphon_rtp_srtp::sdes::CryptoAttribute;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use crate::dtls_bridge::DtlsCallPlan;
use crate::ice::IceCredentials;
use crate::media_pipeline::{DirectionConfig, EchoProfile, MediaCall, RtcpRelay};
use crate::sdp;
use crate::srtp_bridge::{BridgeCallPlan, BridgeFlowPlan, BridgeLeg};
use crate::text_pipeline::{TextCall, TextDirectionConfig};

use super::answer::{ingress_rule, with_ptime_override};
use super::negotiate::{
    apply_received_from, bridge_source_filter, build_transcode_pair, filter_component,
    ice_tie_breaker, peer_ice_credentials, secure_rtcp_relays, RtcpKeying, TranscodePair,
};
use super::{boxed_error_result, Engine, Leg, PipelineKind};

/// Which of a bridged call's two parties are secure, and the key pair that keys each: the engine's
/// own key toward that party (what it advertised in the SDP that party received) and that party's
/// own answered key. At least one side is `Some` — a bridge with neither belongs on the datapath's
/// plain `Forward` path, not on the `Redirect` slow path.
struct BridgeKeying {
    /// The near (A, offerer) party's `(engine key toward A, A's own key)`.
    near: Option<(CryptoAttribute, CryptoAttribute)>,
    /// The far (B, answerer) party's `(engine key toward B, B's own key)`.
    far: Option<(CryptoAttribute, CryptoAttribute)>,
}

/// What every media-pipeline arm of [`Engine::answer`] wires from, resolved once so the arms cannot
/// drift on which address gates or aims a leg: both legs, each peer's effective ingress gate and
/// pre-latch destination (the same pair, see `answer`), and what the far party's SDP negotiated.
#[derive(Clone, Copy)]
pub(super) struct AnswerWiring<'a> {
    pub(super) call_id: &'a str,
    pub(super) from_tag: &'a str,
    pub(super) to_tag: &'a str,
    pub(super) profile: &'a ProfileFlags,
    /// The far party's SDP: B's answer, or B's re-offer when A is answering it.
    pub(super) info: &'a sdp::MediaInfo,
    pub(super) near: Leg,
    pub(super) far: Leg,
    pub(super) near_gate_rtp: Option<SocketAddr>,
    pub(super) near_gate_rtcp: Option<SocketAddr>,
    pub(super) far_gate_rtp: SocketAddr,
    pub(super) far_gate_rtcp: SocketAddr,
    pub(super) near_media_dst: Option<SocketAddr>,
    pub(super) near_rtcp_dst: Option<SocketAddr>,
    pub(super) far_media_dst: SocketAddr,
    pub(super) far_rtcp_dst: SocketAddr,
    /// ICE runs on the near (A-facing) leg.
    pub(super) near_ice: bool,
    /// ICE runs on the far (B-facing) leg.
    pub(super) far_ice: bool,
    /// A's codec, with the `ptime=<N>` override applied.
    pub(super) near_codec: Option<&'a CodecSpec>,
    pub(super) near_telephone_event: Option<u8>,
    pub(super) ptime_override: Option<u8>,
    /// The engine's DTLS role on a DTLS-SRTP far leg.
    pub(super) dtls_role: DtlsRole,
    /// A terminated DTLS-SRTP offerer: A's fingerprint, which the handshake verifies, and the role
    /// the engine answered A with. `None` unless the call is a [`PipelineKind::DtlsOfferer`].
    pub(super) near_dtls: Option<(&'a sdp::Fingerprint, DtlsRole)>,
    /// Endpoints a full ICE agent runs on; a DTLS handshake waits for a selection only on those.
    pub(super) agent_endpoints: &'a [EndpointId],
}

/// What a transcoding arm of [`Engine::answer`] reads beyond the legs.
struct TranscodeInputs {
    /// A's signalled RTP address.
    a_rtp: SocketAddr,
    near_codec: CodecSpec,
    /// B's codec, with the `ptime=<N>` override applied.
    far_codec: CodecSpec,
    record_path: Option<String>,
}

impl AnswerWiring<'_> {
    /// A's signalled address, both codecs and the recording path, or the refusal under `context`.
    fn transcode_inputs(&self, context: &str) -> Result<TranscodeInputs, Box<CmdResult>> {
        let Some(a_rtp) = self.near.remote_rtp else {
            return Err(boxed_error_result(
                context,
                &"near leg has no signalled address",
            ));
        };
        let Some(near_codec) = self.near_codec.cloned() else {
            return Err(boxed_error_result(
                context,
                &"offer carried no usable audio codec",
            ));
        };
        let Some(far_codec) = self
            .info
            .primary_codec()
            .map(|codec| with_ptime_override(&codec, self.ptime_override))
        else {
            return Err(boxed_error_result(
                context,
                &"answer carried no usable audio codec",
            ));
        };
        let record_path = self
            .profile
            .record_call
            .then(|| self.profile.record_path.clone())
            .flatten();
        Ok(TranscodeInputs {
            a_rtp,
            near_codec,
            far_codec,
            record_path,
        })
    }

    /// Both transcode directions: each gated to its peer's effective source (the `received-from` IP
    /// when supplied, not a possibly-private `c=`) and aimed at its pre-latch destination, with the
    /// profile's noise suppression, echo cancellation and record-tone detection.
    fn transcode_pair<'b>(&'b self, inputs: &'b TranscodeInputs) -> TranscodePair<'b> {
        TranscodePair {
            near_endpoint: self.near.rtp.id,
            near_source: bridge_source_filter(
                self.profile,
                self.near_gate_rtp.unwrap_or(inputs.a_rtp),
            ),
            near_dst: self.near_media_dst.unwrap_or(inputs.a_rtp),
            far_endpoint: self.far.rtp.id,
            far_source: bridge_source_filter(self.profile, self.far_gate_rtp),
            far_dst: self.far_media_dst,
            near_codec: &inputs.near_codec,
            far_codec: &inputs.far_codec,
            near_telephone_event: self.near_telephone_event,
            far_telephone_event: self.info.telephone_event_payload_type(),
            record_path: inputs.record_path.as_deref(),
            noise_suppression: self.profile.noise_suppression,
            echo: EchoProfile::from_profile(self.profile),
            beep_detection: self.profile.beep_detection,
            beep_cadence_guard_ms: self.profile.beep_cadence_guard_ms,
        }
    }

    /// The transcoding actor for this answer's two directions, latching unless `no-latch` is set.
    fn media_call(
        &self,
        (a_to_b, b_to_a): (DirectionConfig, DirectionConfig),
        record_path: Option<String>,
    ) -> MediaCall {
        let latch = !self.profile.flags.iter().any(|flag| flag == "no-latch");
        MediaCall::new(
            self.call_id.to_string(),
            self.from_tag.to_string(),
            Some(self.to_tag.to_string()),
            a_to_b,
            b_to_a,
            latch,
            record_path,
        )
    }

    /// The secure RTCP relays of the companion RTCP endpoints, each gated to its peer's effective
    /// source: A's toward B's signalled RTCP address, B's toward `a_rtcp`.
    fn rtcp_relays(
        &self,
        near_rtcp: EndpointId,
        far_rtcp: EndpointId,
        a_rtcp: SocketAddr,
        keying: &RtcpKeying,
    ) -> Vec<RtcpRelay> {
        secure_rtcp_relays(
            near_rtcp,
            bridge_source_filter(self.profile, self.near_gate_rtcp.unwrap_or(a_rtcp)),
            self.info.remote_rtcp,
            far_rtcp,
            bridge_source_filter(self.profile, self.far_gate_rtcp),
            a_rtcp,
            keying,
        )
    }

    /// The DTLS-SRTP plan for the far (B) leg: A's side stays plaintext, B's is keyed by the handshake
    /// the engine runs in its negotiated role against B's certificate fingerprint (RFC 5763 §5).
    fn dtls_call_plan(
        &self,
        a_rtp: SocketAddr,
        certificate: DtlsCertificate,
        peer_fingerprint: sdp::Fingerprint,
        ice_validated: Option<tokio::sync::watch::Receiver<Option<SocketAddr>>>,
    ) -> DtlsCallPlan {
        DtlsCallPlan {
            plain_endpoint: self.near.rtp.id,
            plain_source: bridge_source_filter(self.profile, self.near_gate_rtp.unwrap_or(a_rtp)),
            plain_dst: self.near_media_dst.unwrap_or(a_rtp),
            secure_endpoint: self.far.rtp.id,
            secure_source: ice_bridge_source(
                ice_validated.as_ref(),
                bridge_source_filter(self.profile, self.far_gate_rtp),
            ),
            secure_dst: self.far_media_dst,
            secure_local: self.far.rtp.local_addr,
            certificate,
            role: self.dtls_role,
            peer_fingerprint: DtlsFingerprint::new(
                peer_fingerprint.hash_function,
                peer_fingerprint.bytes,
            ),
            // Hold the handshake on an ICE-gated leg, for a full agent's selection or for the first
            // check the ice-lite responder validates (RFC 8445 §12, §12.1.1). A leg without ICE, or on
            // a backend that cannot publish the validated source, starts at its signalled address:
            // nothing would ever release the wait.
            gate_on_ice: ice_validated.is_some() || self.agent_endpoints.contains(&self.far.rtp.id),
            ice_validated,
            // A's separate RTCP port when A does not multiplex, gated to A's effective RTCP source
            // like the RTP side. B, the DTLS peer, multiplexes (see `PlainRtcp`).
            plain_rtcp: self
                .near
                .rtcp
                .zip(self.near.remote_rtcp)
                .map(|(endpoint, a_rtcp)| crate::dtls_bridge::PlainRtcp {
                    endpoint: endpoint.id,
                    source: bridge_source_filter(
                        self.profile,
                        self.near_gate_rtcp.unwrap_or(a_rtcp),
                    ),
                    dst: self.near_rtcp_dst.unwrap_or(a_rtcp),
                }),
        }
    }

    /// The DTLS-SRTP plan for a terminated DTLS **offerer**: A's leg is keyed by the handshake the
    /// engine runs in the role it answered A with, against A's certificate fingerprint (RFC 5763 §5),
    /// and B's stays plaintext. The mirror of [`Self::dtls_call_plan`] with the sides swapped: the
    /// secure endpoint faces A, the plain one faces B, and B's separate RTCP port, when B does not
    /// multiplex, rides the plain side (A, the DTLS peer, multiplexes).
    fn offerer_dtls_call_plan(
        &self,
        a_rtp: SocketAddr,
        certificate: DtlsCertificate,
        peer_fingerprint: &sdp::Fingerprint,
        role: DtlsRole,
        ice_validated: Option<tokio::sync::watch::Receiver<Option<SocketAddr>>>,
    ) -> DtlsCallPlan {
        DtlsCallPlan {
            plain_endpoint: self.far.rtp.id,
            plain_source: bridge_source_filter(self.profile, self.far_gate_rtp),
            plain_dst: self.far_media_dst,
            secure_endpoint: self.near.rtp.id,
            secure_source: ice_bridge_source(
                ice_validated.as_ref(),
                bridge_source_filter(self.profile, self.near_gate_rtp.unwrap_or(a_rtp)),
            ),
            secure_dst: self.near_media_dst.unwrap_or(a_rtp),
            secure_local: self.near.rtp.local_addr,
            certificate,
            role,
            peer_fingerprint: DtlsFingerprint::new(
                peer_fingerprint.hash_function.clone(),
                peer_fingerprint.bytes.clone(),
            ),
            // As on the far leg: hold the handshake wherever A's leg is ICE-gated (RFC 8445 §12,
            // §12.1.1).
            gate_on_ice: ice_validated.is_some()
                || self.agent_endpoints.contains(&self.near.rtp.id),
            ice_validated,
            plain_rtcp: self.far.rtcp.map(|endpoint| crate::dtls_bridge::PlainRtcp {
                endpoint: endpoint.id,
                source: bridge_source_filter(self.profile, self.far_gate_rtcp),
                dst: self.far_rtcp_dst,
            }),
        }
    }
}

/// A DTLS bridge's own source gate on its secure endpoint. On an ICE-gated endpoint it runs open, as
/// every redirected ICE consumer's does: the datapath's layer-4 gate already admits only the source a
/// connectivity check authenticated, and that source legitimately need not be the signalled address
/// (RFC 8445 §7.3.1.3), so gating on the address too would drop a NATed peer's handshake
/// (docs/security-and-nat.md §4 layer 4). Anywhere else, the signalled-source gate.
fn ice_bridge_source(
    ice_validated: Option<&tokio::sync::watch::Receiver<Option<SocketAddr>>>,
    signalled: SourceFilter,
) -> SourceFilter {
    if ice_validated.is_some() {
        SourceFilter::Any
    } else {
        signalled
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Install the media path `pipeline` names for an answered call, returning a plain relay's
    /// forward flows (empty for every other shape) so `block` can flip them to `Drop` and back.
    pub(super) fn install_answer_pipeline(
        &self,
        pipeline: PipelineKind,
        wiring: &AnswerWiring<'_>,
        far_local_crypto: Option<CryptoAttribute>,
        near_local_crypto: Option<CryptoAttribute>,
        near_remote_crypto: Option<CryptoAttribute>,
        owner_events: Option<flume::Sender<Event>>,
    ) -> Result<Vec<(EndpointId, FlowAction)>, Box<CmdResult>> {
        match pipeline {
            PipelineKind::Srtp => {
                // `resolve_pipeline` only yields `Srtp` when `far_local_crypto` is set, so this is an
                // internal invariant; answer gracefully rather than panic on the control path.
                let Some(far_local) = far_local_crypto else {
                    return Err(boxed_error_result(
                        "SRTP bridge",
                        &"far leg has no local crypto (internal)",
                    ));
                };
                // Secure far (B) leg → userspace SRTP bridge: terminate SRTP/SRTCP on B and relay
                // plaintext on A. B's answer must carry its SDES key to key the inbound contexts.
                let Some(far_remote) = wiring.info.crypto.first().copied() else {
                    return Err(boxed_error_result(
                        "SAVP answer",
                        &"missing a=crypto in the answer",
                    ));
                };
                self.install_srtp_bridge(
                    wiring,
                    BridgeKeying {
                        near: None,
                        far: Some((far_local, far_remote)),
                    },
                )?;
            }
            PipelineKind::SrtpOfferer => {
                // A secure **offerer** toward a plain callee: the exact mirror of the arm above, with
                // the crypto ops swapped. The engine is A's cryptographic far side — it advertised its
                // own key in the answer A received — so A's ingress is decrypted here and relayed to B
                // in the clear, and B's plaintext is encrypted toward A under the engine's key. A's own
                // key never reaches B, which is the defect this closes: without a key of its own the
                // engine passed A's `a=crypto` straight through to the callee and answered A in the
                // clear.
                let (Some(near_local), Some(near_remote)) = (near_local_crypto, near_remote_crypto)
                else {
                    return Err(boxed_error_result(
                        "SRTP bridge",
                        &"secure offerer has no engine key or no peer key (internal)",
                    ));
                };
                self.install_srtp_bridge(
                    wiring,
                    BridgeKeying {
                        near: Some((near_local, near_remote)),
                        far: None,
                    },
                )?;
            }
            PipelineKind::SrtpTranscrypt => {
                // Both parties negotiated SDES-SRTP, under keys that have nothing to do with each
                // other — two SRTP-only desk phones calling each other is the ordinary case. The
                // engine is the cryptographic far side of *both*: it advertised its own key to each,
                // so it holds four contexts and re-encrypts every datagram from one party's key to
                // the other's. The payload is never decoded, so any codec crosses, and neither
                // party's key is ever shown to the other.
                let (Some(near_local), Some(near_remote), Some(far_local)) =
                    (near_local_crypto, near_remote_crypto, far_local_crypto)
                else {
                    return Err(boxed_error_result(
                        "SRTP transcrypt",
                        &"a transcrypt is missing one party's engine key or peer key (internal)",
                    ));
                };
                let Some(far_remote) = wiring.info.crypto.first().copied() else {
                    return Err(boxed_error_result(
                        "SAVP answer",
                        &"missing a=crypto in the answer",
                    ));
                };
                self.install_srtp_bridge(
                    wiring,
                    BridgeKeying {
                        near: Some((near_local, near_remote)),
                        far: Some((far_local, far_remote)),
                    },
                )?;
            }
            PipelineKind::Dtls => self.install_dtls_bridge(wiring)?,
            PipelineKind::DtlsOfferer => self.install_dtls_offerer_bridge(wiring)?,
            PipelineKind::DtlsMedia => self.install_dtls_media(wiring, owner_events)?,
            PipelineKind::SrtpMedia => {
                self.install_srtp_media(wiring, far_local_crypto, owner_events)?;
            }
            PipelineKind::Media => self.install_media(wiring, owner_events)?,
            // Named rather than a wildcard, so a new pipeline kind has to choose its install here
            // instead of silently falling through to a plaintext relay.
            PipelineKind::Passthrough | PipelineKind::Ws => {
                return self.install_plain_relay(wiring)
            }
        }
        Ok(Vec::new())
    }

    /// The userspace SDES-SRTP bridge, keyed for whichever of the two parties negotiated SRTP.
    ///
    /// Each party that is secure contributes a [`SecureLeg`] from the engine's own key toward it
    /// (`local`) and that party's answered key (`remote`). Every flow then names which party's leg
    /// decrypts its ingress and which encrypts its egress, so the three shapes are one construction:
    /// B secure only (`Srtp`), A secure only (`SrtpOfferer`), or **both** under different keys
    /// (`SrtpTranscrypt`), where A's ingress is decrypted with A's key and re-encrypted with B's, and
    /// the reverse. Every leg endpoint is redirected so the bridge sees both directions.
    fn install_srtp_bridge(
        &self,
        wiring: &AnswerWiring<'_>,
        keying: BridgeKeying,
    ) -> Result<(), Box<CmdResult>> {
        let AnswerWiring {
            profile,
            near,
            far,
            near_gate_rtp,
            near_gate_rtcp,
            far_gate_rtp,
            far_gate_rtcp,
            near_media_dst,
            near_rtcp_dst,
            far_media_dst,
            far_rtcp_dst,
            ..
        } = *wiring;
        // Which party sits on each side of a flow's transform. A flow whose ingress faces A decrypts
        // with A's leg (if A is secure) and encrypts with B's (if B is); one facing B is the mirror.
        // A party that is plaintext contributes `None` on both sides, which is what collapses this
        // back to the one-sided bridge.
        let near_side = keying.near.is_some().then_some(BridgeLeg::Near);
        let far_side = keying.far.is_some().then_some(BridgeLeg::Far);
        let (Some(a_rtp), Some(a_rtcp)) = (near.remote_rtp, near.remote_rtcp) else {
            return Err(boxed_error_result(
                "SRTP bridge",
                &"near leg has no signalled address",
            ));
        };
        self.redirect_endpoints(
            near.endpoint_ids().chain(far.endpoint_ids()),
            "install SRTP bridge redirect",
        )?;
        let mut flows = vec![
            // A's ingress → out the far endpoint toward B. Gated to A's effective source (its
            // `received-from` public IP when the offer supplied one).
            BridgeFlowPlan {
                endpoint: near.rtp.id,
                ingress_leg: near_side,
                egress_leg: far_side,
                accepted_source: bridge_source_filter(profile, near_gate_rtp.unwrap_or(a_rtp)),
                out_endpoint: far.rtp.id,
                out_dst: far_media_dst,
            },
            // B's ingress → out the near endpoint toward A.
            BridgeFlowPlan {
                endpoint: far.rtp.id,
                ingress_leg: far_side,
                egress_leg: near_side,
                accepted_source: bridge_source_filter(profile, far_gate_rtp),
                out_endpoint: near.rtp.id,
                out_dst: near_media_dst.unwrap_or(a_rtp),
            },
        ];
        if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
            flows.push(BridgeFlowPlan {
                endpoint: near_rtcp.id,
                ingress_leg: near_side,
                egress_leg: far_side,
                accepted_source: bridge_source_filter(profile, near_gate_rtcp.unwrap_or(a_rtcp)),
                out_endpoint: far_rtcp.id,
                out_dst: far_rtcp_dst,
            });
            flows.push(BridgeFlowPlan {
                endpoint: far_rtcp.id,
                ingress_leg: far_side,
                egress_leg: near_side,
                accepted_source: bridge_source_filter(profile, far_gate_rtcp),
                out_endpoint: near_rtcp.id,
                out_dst: near_rtcp_dst.unwrap_or(a_rtcp),
            });
        }
        // RFC 3711 §3.3.1: the rollover counter belongs to the stream, not to the key — both sides
        // estimate it from the sequence numbers they have seen. This runs again on every renegotiation
        // of a live call, so a leg rebuilt from the keys alone would restart both counters at 0 while
        // the peer's keep counting, and every packet past the first sequence wrap would then
        // authenticate against the wrong index. Carry the live legs' rollover into the rebuilt ones,
        // exactly as an HA restore does — including across a re-key, since a new master key does not
        // restart the stream's packet index.
        //
        // Both are read from A's RTP endpoint, whose one flow faces A on ingress and B on egress and
        // so names both parties. Seeding a transcrypt from a single leg would cross-seed one party's
        // counters into the other's, which is worse than not seeding at all.
        let (previous_near, previous_far) = self.bridge.rollover_snapshots(near.rtp.id);
        let build = |keys: Option<(CryptoAttribute, CryptoAttribute)>,
                     previous: Option<SecureLegRollover>| {
            let (local, remote) = keys?;
            let mut leg = SecureLeg::new(&local.key, &remote.key);
            if let Some(rollover) = previous.as_ref() {
                leg.seed_rollover(rollover);
            }
            Some(leg)
        };
        self.bridge.register(BridgeCallPlan {
            near_leg: build(keying.near, previous_near),
            far_leg: build(keying.far, previous_far),
            flows,
        });
        Ok(())
    }

    /// DTLS-SRTP far (B) leg → userspace DTLS bridge: the handshake keys the leg, then SRTP/SRTCP is
    /// terminated on B and plaintext relayed on A. B's answer must carry its certificate fingerprint
    /// (RFC 5763 §5) to authenticate the handshake; the engine takes the DTLS role opposite the peer's
    /// `a=setup`. B multiplexes RTCP, as WebRTC requires; when A does not, A's separate RTCP port is
    /// bridged as well, carried as SRTCP on B's leg (RFC 5761 §5.1.1).
    fn install_dtls_bridge(&self, wiring: &AnswerWiring<'_>) -> Result<(), Box<CmdResult>> {
        let Some(certificate) = self.dtls_certificate.clone() else {
            return Err(boxed_error_result(
                "DTLS-SRTP answer",
                &"engine has no DTLS certificate",
            ));
        };
        let Some(peer_fingerprint) = wiring.info.fingerprint.clone() else {
            return Err(boxed_error_result(
                "DTLS-SRTP answer",
                &"missing a=fingerprint in the answer",
            ));
        };
        let Some(a_rtp) = wiring.near.remote_rtp else {
            return Err(boxed_error_result(
                "DTLS bridge",
                &"near leg has no signalled address",
            ));
        };
        let plan = wiring.dtls_call_plan(
            a_rtp,
            certificate,
            peer_fingerprint,
            self.datapath.watch_ice_validated(wiring.far.rtp.id),
        );
        self.redirect_endpoints(
            [wiring.near.rtp.id, wiring.far.rtp.id]
                .into_iter()
                .chain(plan.plain_rtcp.map(|rtcp| rtcp.endpoint)),
            "install DTLS bridge redirect",
        )?;
        // On a renegotiation of a live call, keep the association already running and just re-point
        // it: B keeps its own (RFC 8842 §5.5 — the fingerprint did not change), so a fresh
        // registration would wait for a handshake that never comes.
        if !self.dtls_bridge().renegotiate(&plan) {
            self.dtls_bridge().register(plan);
        }
        Ok(())
    }

    /// A terminated DTLS-SRTP **offerer** (A) toward a plain callee → the same userspace DTLS bridge
    /// with the sides swapped: the handshake keys A's leg in the role the engine answered A with,
    /// authenticated against the fingerprint A offered (RFC 5763 §5), and B's leg stays plaintext. A
    /// multiplexes RTCP (the offer refuses one that does not); when B does not, B's separate RTCP port
    /// is bridged as well (RFC 5761 §5.1.1).
    fn install_dtls_offerer_bridge(&self, wiring: &AnswerWiring<'_>) -> Result<(), Box<CmdResult>> {
        let Some(certificate) = self.dtls_certificate.clone() else {
            return Err(boxed_error_result(
                "DTLS-SRTP offerer",
                &"engine has no DTLS certificate",
            ));
        };
        // `answer` sets this exactly when it resolved `DtlsOfferer`, so its absence is an internal
        // invariant; refuse rather than install a bridge with nothing to authenticate the peer against.
        let Some((peer_fingerprint, role)) = wiring.near_dtls else {
            return Err(boxed_error_result(
                "DTLS-SRTP offerer",
                &"no stored keying for the offerer (internal)",
            ));
        };
        let Some(a_rtp) = wiring.near.remote_rtp else {
            return Err(boxed_error_result(
                "DTLS bridge",
                &"near leg has no signalled address",
            ));
        };
        let plan = wiring.offerer_dtls_call_plan(
            a_rtp,
            certificate,
            peer_fingerprint,
            role,
            self.datapath.watch_ice_validated(wiring.near.rtp.id),
        );
        self.redirect_endpoints(
            [wiring.near.rtp.id, wiring.far.rtp.id]
                .into_iter()
                .chain(plan.plain_rtcp.map(|rtcp| rtcp.endpoint)),
            "install DTLS offerer bridge redirect",
        )?;
        // As for a DTLS far leg: a renegotiation that keeps A's association re-points it rather than
        // waiting for a handshake A will never start again (RFC 8842 §5.5).
        if !self.dtls_bridge().renegotiate(&plan) {
            self.dtls_bridge().register(plan);
        }
        Ok(())
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// DTLS-SRTP far (B) leg whose media the pipeline must actually see — a different codec per side,
    /// or recording / NS / AEC. The DTLS analogue of `SrtpMedia`, with one difference that shapes the
    /// whole arm: the `SecureLeg` does not exist yet. SDES hands the key over in the answer; DTLS
    /// produces it only when the RFC 5764 handshake finishes, which is after this control command has
    /// returned.
    ///
    /// So the actor is built **pending**: both directions facing B drop media until the handshake
    /// delivers the key over `MediaControl::AttachSecureLeg`. The `DtlsBridge` keeps B's endpoint for
    /// the RFC 7983 demux (STUN → ICE, DTLS → handshake) and forwards accepted media to the actor
    /// still encrypted, so the actor stays the single owner of the crypto exactly as it is for SDES.
    fn install_dtls_media(
        &self,
        wiring: &AnswerWiring<'_>,
        owner_events: Option<flume::Sender<Event>>,
    ) -> Result<(), Box<CmdResult>> {
        let AnswerWiring { near, far, .. } = *wiring;
        let Some(certificate) = self.dtls_certificate.clone() else {
            return Err(boxed_error_result(
                "DTLS media pipeline",
                &"engine has no DTLS certificate",
            ));
        };
        let Some(peer_fingerprint) = wiring.info.fingerprint.clone() else {
            return Err(boxed_error_result(
                "DTLS media pipeline",
                &"missing a=fingerprint in the answer",
            ));
        };
        let inputs = wiring.transcode_inputs("DTLS media pipeline")?;
        let directions = build_transcode_pair(&wiring.transcode_pair(&inputs)).map_err(
            |(direction, reason)| {
                boxed_error_result(&format!("DTLS media pipeline ({direction})"), &reason)
            },
        )?;
        // Both endpoints go to `Redirect`. The dispatcher checks the bridge first, so B's datagrams
        // reach the DTLS demux; A's fall through to the media registry.
        self.redirect_endpoints([near.rtp.id, far.rtp.id], "install DTLS media redirect")?;
        // Non-muxed companion RTCP, keyed with the same deferred leg (RFC 3711 SRTCP on its own port,
        // RFC 5761). Pending until the handshake lands, like the RTP directions.
        let mut rtcp_relays = Vec::new();
        if let (Some(near_rtcp), Some(far_rtcp), Some(a_rtcp)) =
            (near.rtcp, far.rtcp, near.remote_rtcp)
        {
            self.redirect_endpoints(
                [near_rtcp.id, far_rtcp.id],
                "install DTLS media RTCP redirect",
            )?;
            rtcp_relays =
                wiring.rtcp_relays(near_rtcp.id, far_rtcp.id, a_rtcp, &RtcpKeying::Pending);
        }
        let call = wiring
            .media_call(directions, inputs.record_path)
            .with_far_secure_pending()
            .with_rtcp_relays(rtcp_relays);
        self.media
            .register(call, self.datapath.clone(), owner_events);
        // Now the handshake half: the bridge owns B's endpoint for the demux and keys the actor when
        // it completes. As on the bridge path, a renegotiation keeps the live association, which also
        // re-keys the actor this answer just rebuilt (it starts pending, and the handshake that would
        // key it already happened).
        let plan = wiring.dtls_call_plan(
            inputs.a_rtp,
            certificate,
            peer_fingerprint,
            self.datapath.watch_ice_validated(far.rtp.id),
        );
        if !self.dtls_bridge().renegotiate(&plan) {
            self.dtls_bridge().register_for_pipeline(
                plan,
                crate::dtls_bridge::PipelineTarget::Call {
                    media: self.media.clone(),
                    call_id: wiring.call_id.to_string(),
                },
            );
        }
        Ok(())
    }

    /// Secure (RTP/SAVP) far (B) leg whose codec differs from the plaintext near (A) leg: the media
    /// actor decrypts B's SRTP, transcodes, and encrypts toward B (and the reverse), sharing one
    /// SecureLeg across both directions. Under rtcp-mux, RTCP rides the muxed RTP endpoint and is
    /// (de)crypted there too; when not muxed, the companion RTCP endpoints are redirected and
    /// SRTCP-(de)crypted through the same SecureLeg (docs/security-and-nat.md).
    fn install_srtp_media(
        &self,
        wiring: &AnswerWiring<'_>,
        far_local_crypto: Option<CryptoAttribute>,
        owner_events: Option<flume::Sender<Event>>,
    ) -> Result<(), Box<CmdResult>> {
        let AnswerWiring { near, far, .. } = *wiring;
        // `resolve_pipeline` only yields `SrtpMedia` when `far_local_crypto` is set; treat a missing
        // key as an internal error rather than panicking on the control path.
        let Some(far_local) = far_local_crypto else {
            return Err(boxed_error_result(
                "SRTP transcode",
                &"far leg has no local crypto (internal)",
            ));
        };
        let Some(far_remote) = wiring.info.crypto.first().copied() else {
            return Err(boxed_error_result(
                "SAVP answer",
                &"missing a=crypto in the answer",
            ));
        };
        let inputs = wiring.transcode_inputs("secure media pipeline")?;
        let directions = build_transcode_pair(&wiring.transcode_pair(&inputs)).map_err(
            |(direction, reason)| {
                boxed_error_result(&format!("secure media pipeline ({direction})"), &reason)
            },
        )?;
        self.redirect_endpoints([near.rtp.id, far.rtp.id], "install secure media redirect")?;
        // Carry the live actor's SRTP rollover into the rebuilt leg (RFC 3711 §3.3.1) — see the SDES
        // bridge; a renegotiation must not restart either counter at 0.
        let mut secure_leg = SecureLeg::new(&far_local.key, &far_remote.key);
        if let Some(rollover) = self.media.rollover_snapshot(wiring.call_id) {
            secure_leg.seed_rollover(&rollover);
        }
        let leg = Arc::new(Mutex::new(secure_leg));
        // Non-muxed companion RTCP: relayed through the shared SecureLeg — A's RTCP encrypted toward
        // secure B, B's SRTCP decrypted toward plaintext A — so a non-muxed secure-transcode leg keeps
        // RTCP flowing (RFC 3711 SRTCP; RFC 5761 keeps it on its own port). Muxed calls leave this empty.
        let mut rtcp_relays = Vec::new();
        if let (Some(near_rtcp), Some(far_rtcp), Some(a_rtcp)) =
            (near.rtcp, far.rtcp, near.remote_rtcp)
        {
            self.redirect_endpoints(
                [near_rtcp.id, far_rtcp.id],
                "install secure media RTCP redirect",
            )?;
            rtcp_relays = wiring.rtcp_relays(
                near_rtcp.id,
                far_rtcp.id,
                a_rtcp,
                &RtcpKeying::Leg(leg.clone()),
            );
        }
        let call = wiring
            .media_call(directions, inputs.record_path)
            .with_far_secure_leg(leg)
            .with_rtcp_relays(rtcp_relays);
        self.media
            .register(call, self.datapath.clone(), owner_events);
        Ok(())
    }

    /// Userspace media slow path: redirect both RTP legs to a per-call transcode/record/DTMF actor.
    /// A's codec is the offer's primary codec; B's is the answer's. RTCP (non-mux) still relays
    /// in-datapath — it is not transcoded.
    fn install_media(
        &self,
        wiring: &AnswerWiring<'_>,
        owner_events: Option<flume::Sender<Event>>,
    ) -> Result<(), Box<CmdResult>> {
        let AnswerWiring {
            profile,
            info,
            near,
            far,
            near_gate_rtcp,
            far_gate_rtcp,
            near_ice,
            far_ice,
            ..
        } = *wiring;
        let inputs = wiring.transcode_inputs("media pipeline")?;
        let directions = build_transcode_pair(&wiring.transcode_pair(&inputs)).map_err(
            |(direction, reason)| {
                boxed_error_result(&format!("media pipeline ({direction})"), &reason)
            },
        )?;
        // Redirect the RTP legs to the actor (mux ⇒ RTCP rides these; the actor relays it).
        self.redirect_endpoints([near.rtp.id, far.rtp.id], "install media redirect")?;
        // Relay companion RTCP in-datapath when not muxed (RTCP is never transcoded). The gate keys
        // on each side's effective source (`received-from` IP when supplied); the forward destination
        // stays the real signalled address.
        if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
            let _ = self.datapath.install_flow(
                near_rtcp.id,
                FlowAction::Forward(ingress_rule(
                    far_rtcp.id,
                    Some(info.remote_rtcp),
                    near_gate_rtcp,
                    profile,
                    near_ice,
                )),
            );
            let _ = self.datapath.install_flow(
                far_rtcp.id,
                FlowAction::Forward(ingress_rule(
                    near_rtcp.id,
                    near.remote_rtcp,
                    Some(far_gate_rtcp),
                    profile,
                    far_ice,
                )),
            );
        }
        let call = wiring.media_call(directions, inputs.record_path);
        self.media
            .register(call, self.datapath.clone(), owner_events);
        Ok(())
    }

    /// Plain relay: the in-datapath Forward fast path. Each endpoint's rule gates its ingress to the
    /// peer's effective source and latches per policy (RTPBleed fix — docs/security-and-nat.md §4):
    /// `near` receives from A (`near_gate_rtp`, A's `received-from` public IP when supplied, else the
    /// signalled `near.remote_rtp`); `far` from B (`far_gate_rtp`). The forward destination is that
    /// same effective address, so a NATed peer is aimed at its public one from the first packet rather
    /// than at the private `c=` it advertised. Returns the installed flows.
    fn install_plain_relay(
        &self,
        wiring: &AnswerWiring<'_>,
    ) -> Result<Vec<(EndpointId, FlowAction)>, Box<CmdResult>> {
        let AnswerWiring {
            profile,
            near,
            far,
            near_gate_rtp,
            near_gate_rtcp,
            far_gate_rtp,
            far_gate_rtcp,
            near_media_dst,
            near_rtcp_dst,
            far_media_dst,
            far_rtcp_dst,
            near_ice,
            far_ice,
            ..
        } = *wiring;
        let mut relay_flows = Vec::new();
        let near_action = FlowAction::Forward(ingress_rule(
            far.rtp.id,
            Some(far_media_dst),
            near_gate_rtp,
            profile,
            near_ice,
        ));
        if let Err(error) = self.datapath.install_flow(near.rtp.id, near_action) {
            return Err(boxed_error_result("install near->far RTP flow", &error));
        }
        relay_flows.push((near.rtp.id, near_action));
        let far_action = FlowAction::Forward(ingress_rule(
            near.rtp.id,
            near_media_dst,
            Some(far_gate_rtp),
            profile,
            far_ice,
        ));
        if let Err(error) = self.datapath.install_flow(far.rtp.id, far_action) {
            return Err(boxed_error_result("install far->near RTP flow", &error));
        }
        relay_flows.push((far.rtp.id, far_action));

        // Companion RTCP relay when not muxed. (Under mux, RTCP rides the RTP endpoints already.)
        if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
            let near_rtcp_action = FlowAction::Forward(ingress_rule(
                far_rtcp.id,
                Some(far_rtcp_dst),
                near_gate_rtcp,
                profile,
                near_ice,
            ));
            if let Err(error) = self.datapath.install_flow(near_rtcp.id, near_rtcp_action) {
                return Err(boxed_error_result("install near->far RTCP flow", &error));
            }
            relay_flows.push((near_rtcp.id, near_rtcp_action));
            let far_rtcp_action = FlowAction::Forward(ingress_rule(
                near_rtcp.id,
                near_rtcp_dst,
                Some(far_gate_rtcp),
                profile,
                far_ice,
            ));
            if let Err(error) = self.datapath.install_flow(far_rtcp.id, far_rtcp_action) {
                return Err(boxed_error_result("install far->near RTCP flow", &error));
            }
            relay_flows.push((far_rtcp.id, far_rtcp_action));
        }
        Ok(relay_flows)
    }
}

/// What arming an answered call's ICE reads: the engine's credentials, both legs, what each peer
/// signalled, and the candidates each leg presented.
pub(super) struct AnswerIce<'a> {
    pub(super) call_id: &'a str,
    /// The engine's own ICE-lite credentials for the call.
    pub(super) creds: &'a IceCredentials,
    /// The far party's SDP: B's answer, or B's re-offer when A is answering it.
    pub(super) info: &'a sdp::MediaInfo,
    pub(super) near: Leg,
    pub(super) far: Leg,
    pub(super) near_remote_ice: &'a Option<IceCredentials>,
    pub(super) near_remote_candidates: &'a Vec<siphon_rtp_ice::Candidate>,
    /// What the near leg presents to A.
    pub(super) near_ice_candidates: &'a Vec<siphon_rtp_ice::Candidate>,
    /// What the far leg presents to B.
    pub(super) far_ice_candidates: &'a Vec<siphon_rtp_ice::Candidate>,
    /// A is answering a re-offer from B.
    pub(super) reversed: bool,
    pub(super) near_peer_is_lite: bool,
    /// `ice: remove` took ICE off the far leg: B's leg is never armed, whatever B's SDP carries.
    pub(super) far_ice_removed: bool,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Arm ICE on an answered call's endpoints — a full RFC 8445 agent where the operator enabled one
    /// and the peer gave credentials and candidates, RFC 7675 consent or the ice-lite responder
    /// otherwise — and return the endpoints a full agent now runs on.
    pub(super) fn arm_answer_ice(&self, ice: &AnswerIce<'_>) -> Vec<EndpointId> {
        let AnswerIce {
            call_id,
            creds,
            info,
            near,
            far,
            near_remote_ice,
            near_remote_candidates,
            near_ice_candidates,
            far_ice_candidates,
            reversed,
            near_peer_is_lite,
            far_ice_removed,
        } = *ice;
        let mut agent_endpoints: Vec<EndpointId> = Vec::new();
        let config = IceConfig {
            local_ufrag: creds.ufrag.clone(),
            local_pwd: creds.pwd.clone(),
        };
        // `near` faces A (which offered ICE); enable the responder on its RTP and, under
        // non-mux, its companion RTCP endpoint. `far` faces B; enable only when B also offered
        // ICE. With consent freshness on, each side is promoted to the datapath's **full-agent**
        // seam instead (responder + STUN forwarding) and registered with the credentials of the
        // peer *that* side faces — an outbound check is signed with the peer's password, so the
        // two legs are not interchangeable (RFC 8445 §7.1.2).
        let far_remote_ice = if info.ice_mismatch {
            // RFC 8839 §5.3: B says our offer's ICE reached it altered, so ICE is unusable on that
            // leg. Treat B as non-ICE — the endpoints below are cleared and the leg falls back to
            // the signalled-source gate.
            tracing::info!(
                target: "siphon_rtp::control",
                %call_id,
                "peer answered a=ice-mismatch (RFC 8839 §5.3) — running the far leg without ICE"
            );
            None
        } else if far_ice_removed {
            // `ice: remove` took ICE off the far leg at offer: B was never given the engine's
            // credentials (RFC 8839 §4.2.5), so ICE in its SDP cannot describe a session with us.
            None
        } else {
            peer_ice_credentials(info)
        };
        // B's leg uses ICE only when B's SDP carries it unaltered and `ice: remove` left it on.
        let far_uses_ice = info.is_ice() && !info.ice_mismatch && !far_ice_removed;
        if !far_uses_ice {
            // B's leg runs without ICE. Gathering at offer time installed the responder on the far
            // endpoints (that is how it received its own Binding responses), and leaving it there
            // would arm the layer-4 gate — which forwards media *only* from a STUN-validated
            // source — on a leg that will never send a check, blackholing B's media. Clear it, so
            // the far leg falls back to the signalled-source gate like any non-ICE leg.
            for endpoint in far.endpoint_ids() {
                self.datapath.set_ice(endpoint, None);
            }
        }
        let sides = [
            (near.endpoint_ids().collect::<Vec<_>>(), near_remote_ice),
            (
                if far_uses_ice {
                    far.endpoint_ids().collect::<Vec<_>>()
                } else {
                    Vec::new()
                },
                &far_remote_ice,
            ),
        ];
        // RFC 8445 §6.1.1: the offerer of the exchange controls, unless it is a lite agent, which
        // never can. B answering: A offered, so A controls the near leg (we control it only when A
        // is lite), and we offered to B, so we control the far leg either way. A answering B's
        // re-offer is the same rule the other way round: B controls the far leg unless it is lite,
        // and we offered B's re-offer to A, so we control the near leg.
        let (near_controlling, far_controlling) = if reversed {
            (true, info.ice_lite)
        } else {
            (near_peer_is_lite, true)
        };
        // Full RFC 8445 agent, when the operator enabled it and this side's peer gave us both
        // credentials and candidates. It supersedes consent on that side: a full agent runs its
        // own checks, and RFC 7675 consent is what a *lite* agent does instead.
        let full_ice_sides = [
            (
                near.endpoint_ids().collect::<Vec<_>>(),
                near_remote_ice,
                near_remote_candidates,
                near_ice_candidates,
                near_controlling,
            ),
            (
                if far_uses_ice {
                    far.endpoint_ids().collect::<Vec<_>>()
                } else {
                    Vec::new()
                },
                &far_remote_ice,
                &info.candidates,
                far_ice_candidates,
                far_controlling,
            ),
        ];
        if let Some(agents) = &self.ice_agents {
            for (endpoints, remote, remote_candidates, local_candidates, controlling) in
                full_ice_sides
            {
                let (Some(remote), false) = (remote, remote_candidates.is_empty()) else {
                    continue;
                };
                for endpoint in endpoints {
                    let Some(local_addr) = self.endpoint_address(endpoint) else {
                        continue;
                    };
                    // Only this endpoint's own component takes part in its checklist.
                    let component = if endpoint == near.rtp.id || endpoint == far.rtp.id {
                        1
                    } else {
                        2
                    };
                    let agent_config = siphon_rtp_ice::agent::AgentConfig::new(
                        siphon_rtp_ice::agent::Credentials::new(
                            creds.ufrag.clone(),
                            creds.pwd.clone(),
                        ),
                        siphon_rtp_ice::agent::Credentials::new(
                            remote.ufrag.clone(),
                            remote.pwd.clone(),
                        ),
                        controlling,
                        ice_tie_breaker(),
                    )
                    .with_candidates(
                        filter_component(local_candidates, component),
                        filter_component(remote_candidates, component),
                    );
                    self.datapath.set_ice_agent(
                        endpoint,
                        config.clone(),
                        // The agent owns request handling: answering needs the role (§7.3.1.1),
                        // the checklist (§7.3.1.3) and the nomination flag (§7.3.1.5), none of
                        // which the datapath has. It is also then the only thing that may adopt a
                        // source, so media cannot start before ICE has chosen a pair.
                        IceAgentMode::ForwardOnly,
                        agents.events(),
                    );
                    agents.register(endpoint, call_id, local_addr, agent_config, 0);
                    agent_endpoints.push(endpoint);
                }
            }
        }

        for (endpoints, remote) in sides {
            for endpoint in endpoints {
                if agent_endpoints.contains(&endpoint) {
                    continue; // a full agent already owns this endpoint
                }
                match (&self.consent, remote) {
                    (Some(consent), Some(remote)) => {
                        self.datapath.set_ice_agent(
                            endpoint,
                            config.clone(),
                            // Consent is a lite-agent behaviour: the datapath keeps answering
                            // checks, and the sink exists only so Binding *responses* reach the
                            // checker (RFC 7675 §4).
                            IceAgentMode::RespondAndForward,
                            consent.events(),
                        );
                        consent.register(
                            endpoint,
                            call_id,
                            &creds.ufrag,
                            &remote.ufrag,
                            &remote.pwd,
                        );
                    }
                    // Consent is off, or this peer signalled ICE without usable credentials:
                    // the ice-lite responder alone (RFC 7675 §4 — a lite agent answers checks
                    // and never initiates them).
                    _ => self.datapath.set_ice(endpoint, Some(config.clone())),
                }
            }
        }
        agent_endpoints
    }
}

/// What installing an answered call's RFC 4103 text stream reads: both legs, what each party kept,
/// and the keys a secure stream is bridged with.
#[derive(Clone, Copy)]
pub(super) struct AnswerText<'a> {
    pub(super) call_id: &'a str,
    pub(super) from_tag: &'a str,
    pub(super) to_tag: &'a str,
    pub(super) profile: &'a ProfileFlags,
    /// The far party's SDP: B's answer, or B's re-offer when A is answering it.
    pub(super) info: &'a sdp::MediaInfo,
    pub(super) near: Leg,
    pub(super) far: Leg,
    /// Both parties kept a plaintext text stream.
    pub(super) text_accepted: bool,
    /// Both parties kept a secure (SDES-SRTP) text stream.
    pub(super) secure_text_accepted: bool,
    /// A's `received-from`, which tightens the near text gate like the audio one.
    pub(super) offer_received_from: Option<IpAddr>,
    pub(super) near_text_local_crypto: Option<CryptoAttribute>,
    pub(super) near_text_remote_crypto: Option<CryptoAttribute>,
    pub(super) far_text_local_crypto: Option<CryptoAttribute>,
    pub(super) text_t140_payload_type: Option<u8>,
    pub(super) text_red_payload_type: Option<u8>,
}

/// What installing the text stream leaves for the call record.
pub(super) struct AnsweredText {
    /// B's signalled text address, when a text stream was relayed.
    pub(super) far_text_remote: Option<SocketAddr>,
    /// The in-kernel plaintext text flows (near text, then far text); empty otherwise.
    pub(super) text_relay_flows: Vec<(EndpointId, FlowAction)>,
    /// A secure text stream is now registered on the userspace text processor.
    pub(super) secure_text_registered: bool,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Install an answered call's RFC 4103 text stream: the in-kernel relay for a plaintext stream,
    /// or the userspace SDES-SRTP bridge for a secure one. `secure_text_events_sink` receives
    /// `Event::Text` from a secure stream when the controller asked for it.
    pub(super) fn install_answer_text(
        &self,
        text: &AnswerText<'_>,
        secure_text_events_sink: Option<flume::Sender<Event>>,
    ) -> Result<AnsweredText, Box<CmdResult>> {
        let AnswerText {
            call_id,
            from_tag,
            to_tag,
            profile,
            info,
            near,
            far,
            text_accepted,
            secure_text_accepted,
            offer_received_from,
            near_text_local_crypto,
            near_text_remote_crypto,
            far_text_local_crypto,
            text_t140_payload_type,
            text_red_payload_type,
        } = *text;
        // RFC 4103 text relay — a second stream, wired independently of the audio pipeline kind (its
        // endpoints are distinct, so it relays whether audio is a plain relay, transcode, or SRTP
        // bridge). When both legs hold a text endpoint and B accepted a plaintext stream, install the
        // in-datapath Forward flows `near.text ↔ far.text`. Each direction carries its OWN RTPBleed
        // source-gate + symmetric latch (`ingress_rule` — the same defence the audio relay uses; the
        // gate is per-stream, docs/security-and-nat.md §4). Text is forwarded verbatim (RED/T.140 is
        // not parsed in PR 1). Text does not use ICE here (`ice = false`).
        let mut far_text_remote = None;
        // The two installed text `Forward` flows (near text, then far text), kept so a text-observability
        // feature can promote the text stream to userspace and demote it back to these (mirrors the audio
        // `relay_flows`). Empty when no plaintext text stream was negotiated.
        let mut text_relay_flows: Vec<(EndpointId, FlowAction)> = Vec::new();
        if let (Some(near_text), Some(far_text), Some(b_text)) =
            (near.text, far.text, info.text.as_ref())
        {
            // `text_accepted` already excludes a secure-text offer (no plaintext downgrade) and a WS
            // takeover; only a genuine plaintext↔plaintext stream installs the in-kernel `Forward` relay.
            if text_accepted && !b_text.secure && b_text.remote_rtp.port() != 0 {
                let b_text_rtp = b_text.remote_rtp;
                far_text_remote = Some(b_text_rtp);
                // Gate each side's text ingress to its signalled source, tightened to the
                // `received-from` public IP when the proxy supplied one, and aim each direction at
                // that same effective address until the latch forms (the audio-leg posture).
                let near_text_gate = apply_received_from(near.text_remote_rtp, offer_received_from);
                let far_text_gate = apply_received_from(Some(b_text_rtp), profile.received_from)
                    .unwrap_or(b_text_rtp);
                let near_text_action = FlowAction::Forward(ingress_rule(
                    far_text.id,
                    Some(far_text_gate),
                    near_text_gate,
                    profile,
                    false,
                ));
                if let Err(error) = self.datapath.install_flow(near_text.id, near_text_action) {
                    return Err(boxed_error_result("install near->far text flow", &error));
                }
                let far_text_action = FlowAction::Forward(ingress_rule(
                    near_text.id,
                    near_text_gate,
                    Some(far_text_gate),
                    profile,
                    false,
                ));
                if let Err(error) = self.datapath.install_flow(far_text.id, far_text_action) {
                    return Err(boxed_error_result("install far->near text flow", &error));
                }
                text_relay_flows.push((near_text.id, near_text_action));
                text_relay_flows.push((far_text.id, far_text_action));
            }
        }

        // RFC 4103 SECURE text (SDES-SRTP) — the per-leg `SecureLeg` bridge. Unlike the plaintext relay
        // it cannot run in-kernel (SRTP must be terminated in userspace), so it is registered on the
        // text processor from the start: both text endpoints `Redirect`ed, one `SecureLeg` per leg with
        // its OWN SDES keys (near = engine↔A, far = engine↔B), and held there for the call's life
        // (docs/security-and-nat.md Layer 5f — mirrors the audio SDES bridge). A→B text is decrypted on
        // the near leg and re-encrypted on the far leg (and B→A the reverse), so the two sides re-key
        // independently and no plaintext ever crosses to a secure peer. A mixed secure/plaintext text
        // bridge was refused above (declined), never keyed here.
        let mut secure_text_registered = false;
        if secure_text_accepted {
            if let (
                Some(near_text),
                Some(far_text),
                Some(b_text),
                Some(near_local),
                Some(near_remote),
                Some(far_local),
                Some(a_text_dst),
            ) = (
                near.text,
                far.text,
                info.text.as_ref(),
                near_text_local_crypto,
                near_text_remote_crypto,
                far_text_local_crypto,
                near.text_remote_rtp,
            ) {
                if let Some(far_remote) = b_text.crypto.first().copied() {
                    let b_text_rtp = b_text.remote_rtp;
                    far_text_remote = Some(b_text_rtp);
                    // Same per-stream source gate + symmetric-latch posture as the plaintext text relay
                    // and the audio SDES bridge: gate each side to its signalled source, tightened to the
                    // `received-from` public IP when the proxy supplied one, and aim each direction at
                    // that same effective address until the latch forms (docs/security-and-nat.md §4).
                    let near_text_gate =
                        apply_received_from(near.text_remote_rtp, offer_received_from);
                    let far_text_gate =
                        apply_received_from(Some(b_text_rtp), profile.received_from)
                            .unwrap_or(b_text_rtp);
                    let near_rule = ingress_rule(
                        far_text.id,
                        Some(far_text_gate),
                        near_text_gate,
                        profile,
                        false,
                    );
                    let far_rule = ingress_rule(
                        near_text.id,
                        Some(near_text_gate.unwrap_or(a_text_dst)),
                        Some(far_text_gate),
                        profile,
                        false,
                    );
                    let latch =
                        near_rule.latch != LatchPolicy::Off || far_rule.latch != LatchPolicy::Off;
                    // One `SecureLeg` per text leg (its own SDES keys), each shared by both directions —
                    // exactly as the audio bridge shares a leg's contexts (single-owner actor ⇒ the
                    // `Mutex` is uncontended).
                    // Carry the live legs' SRTP rollover into the rebuilt ones (RFC 3711 §3.3.1) — a
                    // renegotiation re-registers the text actor, and restarting either counter at 0
                    // breaks a stream that has already run past a sequence wrap, exactly as it does
                    // on the audio legs above.
                    let previous_rollover = self.text.rollover_snapshots(call_id);
                    let mut near_secure = SecureLeg::new(&near_local.key, &near_remote.key);
                    let mut far_secure = SecureLeg::new(&far_local.key, &far_remote.key);
                    if let Some((near_rollover, far_rollover)) = previous_rollover.as_ref() {
                        near_secure.seed_rollover(near_rollover);
                        far_secure.seed_rollover(far_rollover);
                    }
                    let near_leg = Arc::new(Mutex::new(near_secure));
                    let far_leg = Arc::new(Mutex::new(far_secure));
                    // Redirect both text endpoints so the dispatcher routes them to the text actor.
                    for endpoint in [near_text.id, far_text.id] {
                        if let Err(error) =
                            self.datapath.install_flow(endpoint, FlowAction::Redirect)
                        {
                            return Err(boxed_error_result("install secure text redirect", &error));
                        }
                    }
                    let a_to_b = TextDirectionConfig {
                        ingress_endpoint: near_text.id,
                        accepted_source: near_rule.accepted_source,
                        egress_endpoint: far_text.id,
                        egress_dst: b_text_rtp,
                        t140_payload_type: text_t140_payload_type,
                        red_payload_type: text_red_payload_type,
                        secure_ingress: Some(near_leg.clone()), // decrypt A's ingress
                        secure_egress: Some(far_leg.clone()),   // encrypt egress toward B
                    };
                    let b_to_a = TextDirectionConfig {
                        ingress_endpoint: far_text.id,
                        accepted_source: far_rule.accepted_source,
                        egress_endpoint: near_text.id,
                        egress_dst: a_text_dst,
                        t140_payload_type: text_t140_payload_type,
                        red_payload_type: text_red_payload_type,
                        secure_ingress: Some(far_leg), // decrypt B's ingress
                        secure_egress: Some(near_leg), // encrypt egress toward A
                    };
                    let text_call = TextCall::new(
                        call_id,
                        from_tag,
                        Some(to_tag.to_string()),
                        a_to_b,
                        b_to_a,
                        latch,
                    );
                    // Event::Text flows only when the controller asked for it (parity with the plaintext
                    // path); the CDR content QoS accrues regardless (read via `final_counters`).
                    self.text
                        .register(text_call, self.datapath.clone(), secure_text_events_sink);
                    secure_text_registered = true;
                }
            }
        }
        Ok(AnsweredText {
            far_text_remote,
            text_relay_flows,
            secure_text_registered,
        })
    }
}
