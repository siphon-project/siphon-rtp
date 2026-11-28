//! The DTLS-SRTP pipelines an answer installs: the crypto bridges for a DTLS callee or caller, and
//! their transcode twins, where the bridge keeps the RFC 7983 demux and the handshake and a media
//! actor owns the crypto once the handshake keys it (RFC 5764).

use siphon_rtp_datapath::{Datapath, SourceFilter};
use siphon_rtp_dtls::{DtlsCertificate, DtlsRole, Fingerprint as DtlsFingerprint};
use siphon_rtp_proto::{CmdResult, Event};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::CryptoAttribute;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::dtls_bridge::DtlsCallPlan;
use crate::media_pipeline::{RtcpRelay, SecureSide};
use crate::sdp;

use super::super::negotiate::{bridge_source_filter, build_transcode_pair, RtcpKeying};
use super::super::{boxed_error_result, Engine};
use super::AnswerWiring;

impl AnswerWiring<'_> {
    /// The DTLS-SRTP plan for the far (B) leg: A's side stays plaintext, B's is keyed by the handshake
    /// the engine runs in its negotiated role against B's certificate fingerprint (RFC 5763 §5).
    pub(super) fn dtls_call_plan(
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
            plain_rtcp: self.near_plain_rtcp(),
        }
    }

    /// A's separate RTCP port, when A does not multiplex, gated to A's effective RTCP source and
    /// aimed at the address this answer settled. Read by the plan above and by a held call's
    /// re-offer, which takes its RTCP routing from the new answer.
    pub(super) fn near_plain_rtcp(&self) -> Option<crate::dtls_bridge::PlainRtcp> {
        self.near
            .rtcp
            .zip(self.near.remote_rtcp)
            .map(|(endpoint, a_rtcp)| crate::dtls_bridge::PlainRtcp {
                endpoint: endpoint.id,
                source: bridge_source_filter(self.profile, self.near_gate_rtcp.unwrap_or(a_rtcp)),
                dst: self.near_rtcp_dst.unwrap_or(a_rtcp),
            })
    }

    /// B's separate RTCP port, when B does not multiplex: [`Self::near_plain_rtcp`]'s twin.
    pub(super) fn far_plain_rtcp(&self) -> Option<crate::dtls_bridge::PlainRtcp> {
        self.far.rtcp.map(|endpoint| crate::dtls_bridge::PlainRtcp {
            endpoint: endpoint.id,
            source: bridge_source_filter(self.profile, self.far_gate_rtcp),
            dst: self.far_rtcp_dst,
        })
    }

    /// The DTLS-SRTP plan for a terminated DTLS **offerer**: A's leg is keyed by the handshake the
    /// engine runs in the role it answered A with, against A's certificate fingerprint (RFC 5763 §5),
    /// and B's stays plaintext. The mirror of [`Self::dtls_call_plan`] with the sides swapped: the
    /// secure endpoint faces A, the plain one faces B, and B's separate RTCP port, when B does not
    /// multiplex, rides the plain side (A, the DTLS peer, multiplexes).
    pub(super) fn offerer_dtls_call_plan(
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
            plain_rtcp: self.far_plain_rtcp(),
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
    /// Hand A's data channel plan to the bridge before A's association is registered (both offerer
    /// installs below). A kept association (a re-answer) keeps its channel, so a second plan is never
    /// attached.
    fn attach_offerer_data_channel(&self, wiring: &AnswerWiring<'_>) {
        let key = (wiring.call_id.to_string(), wiring.from_tag.to_string());
        if !wiring.near_data_channel || self.call_floor_channels.contains_key(&key) {
            return;
        }
        let Some(owner) = self.owned_call_internal(wiring.call_id, |call| call.owner) else {
            return;
        };
        let plan =
            self.new_call_floor_channel(wiring.call_id, wiring.from_tag, owner, wiring.profile);
        self.dtls_bridge()
            .attach_floor_channel(wiring.near.rtp.id, plan);
    }

    /// DTLS-SRTP far (B) leg → userspace DTLS bridge: the handshake keys the leg, then SRTP/SRTCP is
    /// terminated on B and plaintext relayed on A. B's answer must carry its certificate fingerprint
    /// (RFC 5763 §5) to authenticate the handshake; the engine takes the DTLS role opposite the peer's
    /// `a=setup`. B multiplexes RTCP, as WebRTC requires; when A does not, A's separate RTCP port is
    /// bridged as well, carried as SRTCP on B's leg (RFC 5761 §5.1.1).
    pub(super) fn install_dtls_bridge(
        &self,
        wiring: &AnswerWiring<'_>,
    ) -> Result<(), Box<CmdResult>> {
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
        let redirected: Vec<siphon_rtp_datapath::EndpointId> =
            [wiring.near.rtp.id, wiring.far.rtp.id]
                .into_iter()
                .chain(plan.plain_rtcp.map(|rtcp| rtcp.endpoint))
                .collect();
        // On a renegotiation of a live call, keep the association already running and just re-point
        // it: B keeps its own (RFC 8842 §5.5 — the fingerprint did not change), so a fresh
        // registration would wait for a handshake that never comes.
        if !self.dtls_bridge().renegotiate(&plan) {
            self.dtls_bridge().register(plan);
        }
        // Registered first: the first redirected datagram must find its association.
        self.redirect_registered(
            redirected.iter().copied(),
            "install DTLS bridge redirect",
            || {
                self.dtls_bridge().deregister(redirected.iter().copied());
            },
        )
    }

    /// A terminated DTLS-SRTP **offerer** (A) toward a plain callee → the same userspace DTLS bridge
    /// with the sides swapped: the handshake keys A's leg in the role the engine answered A with,
    /// authenticated against the fingerprint A offered (RFC 5763 §5), and B's leg stays plaintext. A
    /// multiplexes RTCP (the offer refuses one that does not); when B does not, B's separate RTCP port
    /// is bridged as well (RFC 5761 §5.1.1).
    pub(super) fn install_dtls_offerer_bridge(
        &self,
        wiring: &AnswerWiring<'_>,
    ) -> Result<(), Box<CmdResult>> {
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
        self.attach_offerer_data_channel(wiring);
        let plan = wiring.offerer_dtls_call_plan(
            a_rtp,
            certificate,
            peer_fingerprint,
            role,
            self.datapath.watch_ice_validated(wiring.near.rtp.id),
        );
        let redirected: Vec<siphon_rtp_datapath::EndpointId> =
            [wiring.near.rtp.id, wiring.far.rtp.id]
                .into_iter()
                .chain(plan.plain_rtcp.map(|rtcp| rtcp.endpoint))
                .collect();
        // As for a DTLS far leg: a renegotiation that keeps A's association re-points it rather than
        // waiting for a handshake A will never start again (RFC 8842 §5.5).
        if !self.dtls_bridge().renegotiate(&plan) {
            self.dtls_bridge().register(plan);
        }
        // Registered first: the first redirected datagram must find its association.
        self.redirect_registered(
            redirected.iter().copied(),
            "install DTLS offerer bridge redirect",
            || self.dtls_bridge().deregister(redirected.iter().copied()),
        )
    }

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
    pub(super) fn install_dtls_media(
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
        // Both endpoints go to `Redirect`, last, once the actor and the bridge own them. The dispatcher
        // checks the bridge first, so B's datagrams reach the DTLS demux; A's fall through to the
        // media registry.
        let mut redirected = vec![near.rtp.id, far.rtp.id];
        // Non-muxed companion RTCP, keyed with the same deferred leg (RFC 3711 SRTCP on its own port,
        // RFC 5761). Pending until the handshake lands, like the RTP directions.
        let mut rtcp_relays = Vec::new();
        if let (Some(near_rtcp), Some(far_rtcp), Some(a_rtcp)) =
            (near.rtcp, far.rtcp, near.remote_rtcp)
        {
            redirected.extend([near_rtcp.id, far_rtcp.id]);
            rtcp_relays =
                wiring.rtcp_relays(near_rtcp.id, far_rtcp.id, a_rtcp, &RtcpKeying::Pending);
        }
        let call = wiring
            .media_call(directions)
            .with_far_secure_pending()
            .with_rtcp_relays(rtcp_relays);
        // A call held for a split carries its stream positions, taps and plain RTCP port across.
        let call = self.apply_hold_carry(
            wiring.call_id,
            call,
            Some((
                far.rtp.id,
                wiring.far_media_dst,
                false,
                wiring.near_plain_rtcp(),
            )),
            (wiring.near.remote_rtp, Some(wiring.info.remote_rtp)),
        );
        // A rebuilt actor on an intercepted call is tapped before it can take its first packet, not
        // once the carry that follows the answer puts the taps back (ETSI TS 103 221-2 §5.2).
        let mut call = call;
        self.pretap_relay(wiring.call_id, &mut call);
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
                    party: crate::dtls_bridge::KeyedParty::Callee,
                },
            );
        }
        self.redirect_registered(
            redirected.iter().copied(),
            "install DTLS media redirect",
            || {
                self.media.deregister(wiring.call_id);
                self.dtls_bridge().deregister(redirected.iter().copied());
            },
        )
    }

    /// A terminated DTLS-SRTP **offerer** toward a plain callee whose call needs the decoded audio
    /// (`PipelineKind::DtlsOffererMedia`): [`Self::install_dtls_media`] with the sides swapped. The
    /// actor is built pending on A's directions; the bridge keeps A's endpoint for the RFC 7983 demux
    /// and the handshake, which it runs in the role the engine answered A with against A's offered
    /// fingerprint (RFC 5763 §5), and keys the actor when it completes. A multiplexes RTCP (the offer
    /// refuses a DTLS caller that does not), so A's SRTCP rides the RTP directions.
    pub(super) fn install_dtls_offerer_media(
        &self,
        wiring: &AnswerWiring<'_>,
        owner_events: Option<flume::Sender<Event>>,
    ) -> Result<(), Box<CmdResult>> {
        let AnswerWiring { near, far, .. } = *wiring;
        let Some(certificate) = self.dtls_certificate.clone() else {
            return Err(boxed_error_result(
                "DTLS-SRTP offerer transcode",
                &"engine has no DTLS certificate",
            ));
        };
        // `answer` sets this whenever it resolved a DTLS offerer; its absence is an internal
        // invariant, refused rather than keyed against nothing.
        let Some((peer_fingerprint, role)) = wiring.near_dtls else {
            return Err(boxed_error_result(
                "DTLS-SRTP offerer transcode",
                &"no stored keying for the offerer (internal)",
            ));
        };
        let inputs = wiring.transcode_inputs("DTLS-SRTP offerer transcode")?;
        let directions = build_transcode_pair(&wiring.transcode_pair(&inputs)).map_err(
            |(direction, reason)| {
                boxed_error_result(
                    &format!("DTLS-SRTP offerer transcode ({direction})"),
                    &reason,
                )
            },
        )?;
        // Both endpoints go to `Redirect`, last, once the actor and the bridge own them. The dispatcher
        // checks the bridge first, so A's datagrams reach the DTLS demux; B's fall through to the media
        // registry.
        let redirected = [near.rtp.id, far.rtp.id];
        let call = wiring.media_call(directions).with_caller_secure_pending();
        let call = self.apply_hold_carry(
            wiring.call_id,
            call,
            Some((
                near.rtp.id,
                wiring.near_media_dst.unwrap_or(inputs.a_rtp),
                true,
                wiring.far_plain_rtcp(),
            )),
            (wiring.near.remote_rtp, Some(wiring.info.remote_rtp)),
        );
        // A rebuilt actor on an intercepted call is tapped before it can take its first packet, not
        // once the carry that follows the answer puts the taps back (ETSI TS 103 221-2 §5.2).
        let mut call = call;
        self.pretap_relay(wiring.call_id, &mut call);
        self.media
            .register(call, self.datapath.clone(), owner_events);
        self.attach_offerer_data_channel(wiring);
        let plan = wiring.offerer_dtls_call_plan(
            inputs.a_rtp,
            certificate,
            peer_fingerprint,
            role,
            self.datapath.watch_ice_validated(near.rtp.id),
        );
        // A renegotiation that keeps A's association re-keys the actor this answer just rebuilt,
        // rather than waiting for a handshake A will never start again (RFC 8842 §5.5).
        if !self.dtls_bridge().renegotiate(&plan) {
            self.dtls_bridge().register_for_pipeline(
                plan,
                crate::dtls_bridge::PipelineTarget::Call {
                    media: self.media.clone(),
                    call_id: wiring.call_id.to_string(),
                    party: crate::dtls_bridge::KeyedParty::Caller,
                },
            );
        }
        self.redirect_registered(
            redirected,
            "install DTLS offerer transcode redirect",
            || {
                self.media.deregister(wiring.call_id);
                self.dtls_bridge().deregister(redirected);
            },
        )
    }

    /// The engine's SDES-SRTP leg toward the secure far (B) party of a transcoding call: the live
    /// actor's own when the answer repeats its keys (so its send window survives, RFC 3711 §9.1),
    /// rekeyed in place for a key that changed, the leg a held call handed over, or a new one seeded
    /// with the rollover of whatever ran before (RFC 3711 §3.3.1: a renegotiation must not restart
    /// either counter at 0).
    pub(super) fn media_far_sdes_leg(
        &self,
        wiring: &AnswerWiring<'_>,
        far_local: &CryptoAttribute,
        far_remote: &CryptoAttribute,
    ) -> Arc<Mutex<SecureLeg>> {
        // A call held for a split hands its live leg to the replacement (promote/secure_release.rs).
        self.carried_sdes_leg(wiring.call_id, true, (far_local, far_remote))
            .or_else(|| {
                let live = self.media.secure_legs(wiring.call_id).1?;
                live.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .adopt(Some(&far_local.key), Some(&far_remote.key));
                Some(live)
            })
            .unwrap_or_else(|| {
                let mut secure_leg = SecureLeg::new(&far_local.key, &far_remote.key);
                if let Some(rollover) = self.media.rollover_snapshot(wiring.call_id) {
                    secure_leg.seed_rollover(&rollover);
                }
                Arc::new(Mutex::new(secure_leg))
            })
    }

    /// B's keys on a DTLS caller toward an SDES callee: the engine's own key toward B (minted at offer,
    /// RFC 4568 §6.1) and the key B answered with, or the refusal under `context`.
    fn transcrypt_far_keys(
        wiring: &AnswerWiring<'_>,
        far_local_crypto: Option<CryptoAttribute>,
        context: &str,
    ) -> Result<(CryptoAttribute, CryptoAttribute), Box<CmdResult>> {
        // `resolve_pipeline_kind` only yields a transcrypt kind when `far_local_crypto` is set, so its
        // absence is an internal invariant: refuse rather than key B against nothing.
        let Some(far_local) = far_local_crypto else {
            return Err(boxed_error_result(
                context,
                &"far leg has no local crypto (internal)",
            ));
        };
        let Some(far_remote) = wiring.info.crypto.first().copied() else {
            return Err(boxed_error_result(
                "SAVP answer",
                &"missing a=crypto in the answer",
            ));
        };
        Ok((far_local, far_remote))
    }

    /// A terminated DTLS-SRTP **offerer** (A) toward an SDES-SRTP callee (B) → the DTLS bridge with B's
    /// plain side re-keyed by SDES (`PipelineKind::DtlsOffererTranscrypt`): the handshake keys A's leg
    /// as for [`Self::install_dtls_offerer_bridge`], and B's SDES leg (RFC 4568) is installed on the
    /// association so each datagram is unprotected under one keying and protected under the other
    /// (RFC 3711), the plaintext between them seen only by the taps. B's separate RTCP port, when it
    /// does not multiplex, is bridged on the same leg (RFC 5761 §5.1.1).
    pub(super) fn install_dtls_offerer_transcrypt_bridge(
        &self,
        wiring: &AnswerWiring<'_>,
        far_local_crypto: Option<CryptoAttribute>,
    ) -> Result<(), Box<CmdResult>> {
        let Some(certificate) = self.dtls_certificate.clone() else {
            return Err(boxed_error_result(
                "DTLS-SRTP offerer",
                &"engine has no DTLS certificate",
            ));
        };
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
        let (far_local, far_remote) =
            Self::transcrypt_far_keys(wiring, far_local_crypto, "DTLS-SRTP offerer transcrypt")?;
        self.attach_offerer_data_channel(wiring);
        let plan = wiring.offerer_dtls_call_plan(
            a_rtp,
            certificate,
            peer_fingerprint,
            role,
            self.datapath.watch_ice_validated(wiring.near.rtp.id),
        );
        let redirected: Vec<siphon_rtp_datapath::EndpointId> =
            [wiring.near.rtp.id, wiring.far.rtp.id]
                .into_iter()
                .chain(plan.plain_rtcp.map(|rtcp| rtcp.endpoint))
                .collect();
        let secure_endpoint = wiring.near.rtp.id;
        // B's SDES leg belongs to the call, not to one association: a re-answer that repeats its keys
        // keeps the live leg and with it its send window and rollover (RFC 3711 §3.3.1, §9.1), and only
        // a key that changed is replaced, in place. It is read before the association is registered,
        // which rebuilds the flows but carries the leg.
        let leg = match self.dtls_bridge().plain_leg(secure_endpoint) {
            Some(live) => {
                // Key identity, not the whole `a=crypto` line: the replay state belongs to the key
                // (RFC 3711 §3.3.2, §3.4), so the same master key and salt under another tag, or with
                // another MKI, keeps its contexts and only a changed key is replaced.
                live.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .adopt(Some(&far_local.key), Some(&far_remote.key));
                live
            }
            None => Arc::new(Mutex::new(SecureLeg::new(&far_local.key, &far_remote.key))),
        };
        // As for a plain callee: a renegotiation that keeps A's association re-points it rather than
        // waiting for a handshake A will never start again (RFC 8842 §5.5).
        if !self.dtls_bridge().renegotiate(&plan) {
            self.dtls_bridge().register(plan);
        }
        // Before the redirect: a datagram relayed without B's transform would reach B in the clear (or
        // A as B's ciphertext).
        if !self.dtls_bridge().set_plain_leg(secure_endpoint, leg) {
            self.dtls_bridge().deregister(redirected.iter().copied());
            return Err(boxed_error_result(
                "DTLS-SRTP offerer transcrypt",
                &"the association did not take the callee's SDES leg (internal)",
            ));
        }
        self.redirect_registered(
            redirected.iter().copied(),
            "install DTLS offerer transcrypt redirect",
            || self.dtls_bridge().deregister(redirected.iter().copied()),
        )
    }

    /// The transcode twin of [`Self::install_dtls_offerer_transcrypt_bridge`]
    /// (`PipelineKind::DtlsOffererTranscryptMedia`): [`Self::install_dtls_offerer_media`] with B's SDES
    /// leg held by the actor from the start. A's directions stay pending until the handshake delivers
    /// A's leg; B's leg is keyed already, so B's ingress is decrypted from the first packet but nothing
    /// is relayed either way before A is keyed (RFC 5764: no key, no traffic).
    ///
    /// B's separate RTCP port, when it does not multiplex, is relayed here too: B's SRTCP is opened
    /// under B's key and sealed for A once A's leg arrives, and A's multiplexed RTCP is sent to that
    /// port (RFC 5761 §5.1.1), which the plain-callee twin leaves to a held call's carry.
    pub(super) fn install_dtls_offerer_transcrypt_media(
        &self,
        wiring: &AnswerWiring<'_>,
        far_local_crypto: Option<CryptoAttribute>,
        owner_events: Option<flume::Sender<Event>>,
    ) -> Result<(), Box<CmdResult>> {
        let AnswerWiring { near, far, .. } = *wiring;
        let Some(certificate) = self.dtls_certificate.clone() else {
            return Err(boxed_error_result(
                "DTLS-SRTP offerer transcrypt transcode",
                &"engine has no DTLS certificate",
            ));
        };
        let Some((peer_fingerprint, role)) = wiring.near_dtls else {
            return Err(boxed_error_result(
                "DTLS-SRTP offerer transcrypt transcode",
                &"no stored keying for the offerer (internal)",
            ));
        };
        let (far_local, far_remote) = Self::transcrypt_far_keys(
            wiring,
            far_local_crypto,
            "DTLS-SRTP offerer transcrypt transcode",
        )?;
        let inputs = wiring.transcode_inputs("DTLS-SRTP offerer transcrypt transcode")?;
        let directions = build_transcode_pair(&wiring.transcode_pair(&inputs)).map_err(
            |(direction, reason)| {
                boxed_error_result(
                    &format!("DTLS-SRTP offerer transcrypt transcode ({direction})"),
                    &reason,
                )
            },
        )?;
        let mut redirected = vec![near.rtp.id, far.rtp.id];
        let a_destination = wiring.near_media_dst.unwrap_or(inputs.a_rtp);
        let far_leg = self.media_far_sdes_leg(wiring, &far_local, &far_remote);
        let mut call = wiring
            .media_call(directions)
            .with_far_secure_leg(far_leg.clone())
            .with_caller_secure_pending();
        // B's own RTCP port: its SRTCP toward A (A's leg is pending, as A's RTP directions are), and
        // A's multiplexed RTCP toward B's port.
        if let Some(plain_rtcp) = wiring.far_plain_rtcp() {
            redirected.push(plain_rtcp.endpoint);
            call = call
                .with_rtcp_relays(vec![RtcpRelay::new(
                    plain_rtcp.endpoint,
                    plain_rtcp.source,
                    near.rtp.id,
                    a_destination,
                )
                .with_secure_ingress(far_leg)
                .with_pending_secure(SecureSide::Egress)])
                .with_rtcp_toward_b(Some((plain_rtcp.endpoint, plain_rtcp.dst)));
        }
        let call = self.apply_hold_carry(
            wiring.call_id,
            call,
            Some((near.rtp.id, a_destination, true, wiring.far_plain_rtcp())),
            (wiring.near.remote_rtp, Some(wiring.info.remote_rtp)),
        );
        // A rebuilt actor on an intercepted call is tapped before it can take its first packet, not
        // once the carry that follows the answer puts the taps back (ETSI TS 103 221-2 §5.2).
        let mut call = call;
        self.pretap_relay(wiring.call_id, &mut call);
        self.media
            .register(call, self.datapath.clone(), owner_events);
        self.attach_offerer_data_channel(wiring);
        let plan = wiring.offerer_dtls_call_plan(
            inputs.a_rtp,
            certificate,
            peer_fingerprint,
            role,
            self.datapath.watch_ice_validated(near.rtp.id),
        );
        // A renegotiation that keeps A's association re-keys the actor this answer just rebuilt,
        // rather than waiting for a handshake A will never start again (RFC 8842 §5.5).
        if !self.dtls_bridge().renegotiate(&plan) {
            self.dtls_bridge().register_for_pipeline(
                plan,
                crate::dtls_bridge::PipelineTarget::Call {
                    media: self.media.clone(),
                    call_id: wiring.call_id.to_string(),
                    party: crate::dtls_bridge::KeyedParty::Caller,
                },
            );
        }
        self.redirect_registered(
            redirected.clone(),
            "install DTLS offerer transcrypt transcode redirect",
            || {
                self.media.deregister(wiring.call_id);
                self.dtls_bridge().deregister(redirected.iter().copied());
            },
        )
    }
}
