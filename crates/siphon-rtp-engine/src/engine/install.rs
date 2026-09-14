//! Installing an answered call's media path: the SRTP and DTLS crypto bridges, the transcoding
//! media actor (plaintext or with a secure far party), and the in-datapath plain relay.

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{Datapath, EndpointId, FlowAction};
use siphon_rtp_dtls::{DtlsCertificate, DtlsRole, Fingerprint as DtlsFingerprint};
use siphon_rtp_proto::{CmdResult, Event, ProfileFlags};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::CryptoAttribute;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::dtls_bridge::DtlsCallPlan;
use crate::media_pipeline::{DirectionConfig, EchoProfile, MediaCall, RtcpRelay};
use crate::sdp;
use crate::srtp_bridge::{BridgeCallPlan, BridgeFlowPlan, BridgeOp};

use super::answer::{ingress_rule, with_ptime_override};
use super::negotiate::{
    bridge_source_filter, build_transcode_pair, secure_rtcp_relays, RtcpKeying, TranscodePair,
};
use super::{boxed_error_result, Engine, Leg, PipelineKind};

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
    ) -> DtlsCallPlan {
        DtlsCallPlan {
            plain_endpoint: self.near.rtp.id,
            plain_source: bridge_source_filter(self.profile, self.near_gate_rtp.unwrap_or(a_rtp)),
            plain_dst: self.near_media_dst.unwrap_or(a_rtp),
            secure_endpoint: self.far.rtp.id,
            secure_source: bridge_source_filter(self.profile, self.far_gate_rtp),
            secure_dst: self.far_media_dst,
            secure_local: self.far.rtp.local_addr,
            certificate,
            role: self.dtls_role,
            peer_fingerprint: DtlsFingerprint::new(
                peer_fingerprint.hash_function,
                peer_fingerprint.bytes,
            ),
            // Hold the handshake for ICE only when a full agent is actually running on this leg
            // (RFC 8445 §12). Without one there is no selection coming, and gating would hang a
            // leg that works perfectly well against its signalled address.
            gate_on_ice: self.agent_endpoints.contains(&self.far.rtp.id),
        }
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
                self.install_srtp_bridge(wiring, far_local, far_remote, BridgeOp::Encrypt)?;
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
                self.install_srtp_bridge(wiring, near_local, near_remote, BridgeOp::Decrypt)?;
            }
            PipelineKind::Dtls => self.install_dtls_bridge(wiring)?,
            PipelineKind::DtlsMedia => self.install_dtls_media(wiring, owner_events)?,
            PipelineKind::SrtpMedia => {
                self.install_srtp_media(wiring, far_local_crypto, owner_events)?;
            }
            PipelineKind::Media => self.install_media(wiring, owner_events)?,
            _ => return self.install_plain_relay(wiring),
        }
        Ok(Vec::new())
    }

    /// The userspace SDES-SRTP bridge between the plain party and the secure one, keyed with the
    /// engine's own key toward the secure party (`local`) and that party's key (`remote`). `near_op`
    /// is what A's ingress gets — `Encrypt` when B is the secure party, `Decrypt` when A is — and B's
    /// ingress gets the other. Every leg endpoint is redirected so the bridge sees both directions.
    fn install_srtp_bridge(
        &self,
        wiring: &AnswerWiring<'_>,
        local: CryptoAttribute,
        remote: CryptoAttribute,
        near_op: BridgeOp,
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
        let far_op = match near_op {
            BridgeOp::Encrypt => BridgeOp::Decrypt,
            BridgeOp::Decrypt => BridgeOp::Encrypt,
        };
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
                op: near_op,
                accepted_source: bridge_source_filter(profile, near_gate_rtp.unwrap_or(a_rtp)),
                out_endpoint: far.rtp.id,
                out_dst: far_media_dst,
            },
            // B's ingress → out the near endpoint toward A.
            BridgeFlowPlan {
                endpoint: far.rtp.id,
                op: far_op,
                accepted_source: bridge_source_filter(profile, far_gate_rtp),
                out_endpoint: near.rtp.id,
                out_dst: near_media_dst.unwrap_or(a_rtp),
            },
        ];
        if let (Some(near_rtcp), Some(far_rtcp)) = (near.rtcp, far.rtcp) {
            flows.push(BridgeFlowPlan {
                endpoint: near_rtcp.id,
                op: near_op,
                accepted_source: bridge_source_filter(profile, near_gate_rtcp.unwrap_or(a_rtcp)),
                out_endpoint: far_rtcp.id,
                out_dst: far_rtcp_dst,
            });
            flows.push(BridgeFlowPlan {
                endpoint: far_rtcp.id,
                op: far_op,
                accepted_source: bridge_source_filter(profile, far_gate_rtcp),
                out_endpoint: near_rtcp.id,
                out_dst: near_rtcp_dst.unwrap_or(a_rtcp),
            });
        }
        // RFC 3711 §3.3.1: the rollover counter belongs to the stream, not to the key — both sides
        // estimate it from the sequence numbers they have seen. This runs again on every renegotiation
        // of a live call, so a leg rebuilt from the keys alone would restart both counters at 0 while
        // the peer's keep counting, and every packet past the first sequence wrap would then
        // authenticate against the wrong index. Carry the live leg's rollover into the rebuilt one,
        // exactly as an HA restore does — including across a re-key, since a new master key does not
        // restart the stream's packet index.
        let previous_rollover = self.bridge.rollover_snapshot(near.rtp.id);
        let mut leg = SecureLeg::new(&local.key, &remote.key);
        if let Some(rollover) = previous_rollover.as_ref() {
            leg.seed_rollover(rollover);
        }
        self.bridge.register(BridgeCallPlan { leg, flows });
        Ok(())
    }

    /// DTLS-SRTP far (B) leg → userspace DTLS bridge: the handshake keys the leg, then SRTP/SRTCP is
    /// terminated on B and plaintext relayed on A. B's answer must carry its certificate fingerprint
    /// (RFC 5763 §5) to authenticate the handshake; the engine takes the DTLS role opposite the peer's
    /// `a=setup`. (rtcp-mux is assumed, as WebRTC mandates — non-muxed DTLS RTCP is a follow-up.)
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
        self.redirect_endpoints(
            [wiring.near.rtp.id, wiring.far.rtp.id],
            "install DTLS bridge redirect",
        )?;
        let plan = wiring.dtls_call_plan(a_rtp, certificate, peer_fingerprint);
        // On a renegotiation of a live call, keep the association already running and just re-point
        // it: B keeps its own (RFC 8842 §5.5 — the fingerprint did not change), so a fresh
        // registration would wait for a handshake that never comes.
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
        let plan = wiring.dtls_call_plan(inputs.a_rtp, certificate, peer_fingerprint);
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
