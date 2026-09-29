//! The DTLS-SRTP pipelines an answer installs: the crypto bridges for a DTLS callee or caller, and
//! their transcode twins, where the bridge keeps the RFC 7983 demux and the handshake and a media
//! actor owns the crypto once the handshake keys it (RFC 5764).

use siphon_rtp_datapath::{Datapath, SourceFilter};
use siphon_rtp_dtls::{DtlsCertificate, DtlsRole, Fingerprint as DtlsFingerprint};
use siphon_rtp_proto::{CmdResult, Event};
use std::net::SocketAddr;

use crate::dtls_bridge::DtlsCallPlan;
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
                    party: crate::dtls_bridge::KeyedParty::Callee,
                },
            );
        }
        Ok(())
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
        // Both endpoints go to `Redirect`. The dispatcher checks the bridge first, so A's datagrams
        // reach the DTLS demux; B's fall through to the media registry.
        self.redirect_endpoints(
            [near.rtp.id, far.rtp.id],
            "install DTLS offerer transcode redirect",
        )?;
        let call = wiring
            .media_call(directions, inputs.record_path)
            .with_caller_secure_pending();
        self.media
            .register(call, self.datapath.clone(), owner_events);
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
        Ok(())
    }
}
