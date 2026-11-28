//! Per-packet handling for the DTLS-SRTP bridge.

use siphon_rtp_datapath::{classify, Datapath, ObservedRtcp, PacketClass, RxPacket};
use siphon_rtp_srtp::leg::{is_rtcp, PacketKind};

use crate::egress_track::{continue_in_place, continue_stream};
use crate::ingress::{Refusal, RefusalContext};
use crate::srtp_bridge::Scratch;

use super::{Direction, DtlsBridge, VideoSsrcs};

impl<D: Datapath + Clone + 'static> DtlsBridge<D> {
    /// Handle one redirected datagram: gate the source, then either feed the DTLS handshake or apply
    /// the flow's SRTP crypto and forward it. Anything unkeyed, un-gated, or un-decryptable is dropped.
    pub async fn handle(&self, packet: RxPacket) {
        let Some((
            direction,
            accepted_source,
            out_endpoint,
            out_dst,
            (secure, plain_leg),
            x3,
            plain_taps,
            rtcp_only,
            rtcp_out,
            refusals,
            (video, rtp_closed),
            track,
        )) = self.flows.get(&packet.endpoint).map(|flow| {
            (
                flow.direction.clone(),
                flow.accepted_source,
                flow.out_endpoint,
                // Toward the DTLS peer the destination follows ICE, so read the published one;
                // toward the plain peer it is the signalled address.
                flow.out_dst
                    .or_else(|| flow.secure_dst.as_ref().and_then(|dst| *dst.borrow())),
                (flow.secure.clone(), flow.plain_leg.clone()),
                flow.x3.clone(),
                flow.plain_taps.clone(),
                flow.rtcp_only,
                flow.rtcp_out,
                flow.refusals.clone(),
                (flow.video.clone(), flow.rtp_closed),
                flow.track.clone(),
            )
        })
        else {
            return; // not a DTLS-bridge endpoint
        };
        // A relaying flow needs a destination; a pipeline flow forwards into the actor's mailbox and
        // has none. On a gated leg with no pair selected yet there is nowhere ICE has approved, and
        // the leg is unkeyed anyway (docs/security-and-nat.md §4 layer 4).
        let pipeline_mode = matches!(direction, Direction::Pipeline { .. });
        if out_dst.is_none() && !pipeline_mode {
            self.datapath.note_dropped(packet.endpoint);
            return;
        }
        // The plan carries no call id; the endpoint identifies the flow.
        let context = RefusalContext {
            component: "dtls-bridge",
            call_id: "",
            endpoint: packet.endpoint,
            source: packet.source,
            expected: accepted_source,
        };

        // RTPBleed gate: Redirect skips the datapath's source check, so re-enforce it here.
        if !accepted_source.accepts(packet.source.ip()) {
            refusals.log(Refusal::UnsignalledSource, context);
            self.datapath.note_dropped(packet.endpoint);
            return;
        }

        // On the secure endpoint a DTLS record drives the handshake, never SRTP crypto. Both
        // secure-side modes demux the same way — that is precisely what stays in the bridge.
        match &direction {
            Direction::Decrypt { dtls_in } | Direction::Pipeline { dtls_in, .. }
                if classify(&packet.data) == PacketClass::Dtls =>
            {
                // Drop-newest on a full handshake mailbox → DTLS retransmits; never block the datapath.
                let _ = dtls_in.try_send(packet.data);
                return;
            }
            _ => {}
        }

        // Media path: only relay RTP/RTCP, and only once the handshake has keyed the leg.
        if classify(&packet.data) != PacketClass::Media {
            return;
        }
        // A plain peer's separate RTCP port relays RTCP only (RFC 5761 §4 packet-type demux), so it
        // cannot be used to inject RTP toward the DTLS peer.
        if rtcp_only && !is_rtcp(&packet.data) {
            self.datapath.note_dropped(packet.endpoint);
            return;
        }

        // RTP on a direction negotiated closed is dropped before any crypto (RFC 3264 §6.1); RTCP, which
        // carries receiver feedback against the media's direction, still flows. The video endpoint of
        // a bundled leg also learns the stream it sends, which the DTLS peer's RTCP will speak of.
        if matches!(direction, Direction::Encrypt) && !is_rtcp(&packet.data) {
            if rtp_closed {
                self.datapath.note_dropped(packet.endpoint);
                return;
            }
            if let Some(route) = &video {
                VideoSsrcs::learn(&route.ssrcs.egress, &packet.data);
            }
        }

        // Pipeline mode: hand the still-encrypted media to the per-call actor, which owns the
        // `SecureLeg` and decrypts it on its own `secure_ingress` — the same path SDES secure
        // transcode takes. Before the handshake keys it, drop (the actor could not decrypt anyway,
        // and its own `secure_pending` gate would drop it a second time).
        if let Direction::Pipeline { target, keyed, .. } = &direction {
            if !keyed.load(std::sync::atomic::Ordering::SeqCst) {
                // Handshake not complete — no key, drop the media.
                self.datapath.note_dropped(packet.endpoint);
                return;
            }
            target.dispatch(packet);
            return;
        }
        let Some(out_dst) = out_dst else { return };
        let mut scratch = self.scratch.take();
        let Scratch {
            decrypted: out,
            sealed: resealed,
            injected: opened,
            rewritten,
        } = &mut *scratch;
        // A plain peer keyed by SDES (RFC 4568) sends SRTP, which is opened under its own key before
        // the DTLS protect, and only once the DTLS peer is keyed: an unkeyed association drops before
        // any crypto, so a packet it could not relay never advances the SDES leg's replay window.
        let plaintext_in: &[u8] = match (&plain_leg, &direction) {
            (Some(leg), Direction::Encrypt) => {
                let keyed = secure.lock().is_ok_and(|guard| guard.is_some());
                if !keyed {
                    self.datapath.note_dropped(packet.endpoint);
                    return;
                }
                let Ok(mut leg) = leg.lock() else {
                    tracing::error!("DTLS bridge SDES-leg mutex poisoned; dropping packet");
                    return;
                };
                // RFC 3711 §3.3 / RFC 4568: a packet that does not authenticate is never relayed.
                if let Err(error) = leg.unprotect(&packet.data, opened) {
                    drop(leg);
                    refusals.log_undecryptable(&error, &packet.data, "plain", context);
                    self.datapath.note_dropped(packet.endpoint);
                    return;
                }
                opened.as_slice()
            }
            _ => &packet.data,
        };
        // The stream toward the DTLS peer, continued across a hold in the decoding actor.
        // The sender's own record of a stream, asked only for one the flow is not following.
        let sent = |ssrc| secure.lock().ok()?.as_ref()?.highest_sent(ssrc);
        let toward_peer: &[u8] = if matches!(direction, Direction::Encrypt) {
            let Some(datagram) = continue_stream(&track, plaintext_in, rewritten, sent) else {
                self.datapath.note_dropped(packet.endpoint);
                return;
            };
            datagram
        } else {
            &packet.data
        };
        let transformed = {
            let Ok(mut guard) = secure.lock() else {
                tracing::error!("DTLS secure-leg mutex poisoned; dropping packet");
                return;
            };
            let Some(leg) = guard.as_mut() else {
                // Handshake not complete yet — no key, drop the media.
                drop(guard);
                self.datapath.note_dropped(packet.endpoint);
                return;
            };
            match direction {
                Direction::Encrypt => (leg.protect(toward_peer, out), leg.reuse_refusals()),
                // `Pipeline` returned above; only the two relaying directions reach the crypto here.
                Direction::Decrypt { .. } | Direction::Pipeline { .. } => {
                    (leg.unprotect(&packet.data, out), 0)
                }
            }
        };
        let (transformed, refused) = transformed;
        let kind = match transformed {
            Ok(kind) => kind,
            Err(error) => {
                if matches!(direction, Direction::Decrypt { .. }) {
                    refusals.log_undecryptable(&error, &packet.data, "secure", context);
                } else {
                    crate::egress_track::log_protect_failure(&error, "dtls-bridge", refused);
                    track.refused(&error, sent);
                }
                self.datapath.note_dropped(packet.endpoint);
                return;
            }
        };
        // A bundled leg's video is told from its audio now that it is plaintext (RFC 8843 §9.2) and goes
        // out of the video endpoint. A closed direction drops the video RTP, not its RTCP.
        let mut is_video = false;
        let (out_endpoint, out_dst) = match video.as_deref().filter(|route| {
            matches!(direction, Direction::Decrypt { .. }) && route.claims(kind, out.as_slice())
        }) {
            Some(route) => {
                if kind == PacketKind::Rtp && !route.rtp_open {
                    self.datapath.note_dropped(packet.endpoint);
                    return;
                }
                is_video = true;
                (route.out_endpoint, route.out_dst)
            }
            None => (out_endpoint, out_dst),
        };
        // What the DTLS peer sent, continued toward the plain peer across a hold in the decoding actor.
        if matches!(direction, Direction::Decrypt { .. })
            && !is_video
            && kind == PacketKind::Rtp
            && !continue_in_place(&track, out.as_mut_slice())
        {
            self.datapath.note_dropped(packet.endpoint);
            return;
        }
        // Sent as far as the sender is concerned: only now does it become the flow's high-water mark.
        track.commit();
        // The same for a leg of an association of its own, whose direction was negotiated closed.
        if rtp_closed && kind == PacketKind::Rtp && matches!(direction, Direction::Decrypt { .. }) {
            self.datapath.note_dropped(packet.endpoint);
            return;
        }
        // Decrypted RTCP goes to the plain peer's separate RTCP port when it has one (RFC 5761
        // §5.1.1); RTP, and RTCP toward a multiplexing plain peer, go where the flow forwards.
        let (out_endpoint, out_dst) = match (kind, rtcp_out) {
            (PacketKind::Rtcp, Some(rtcp)) if !is_video => rtcp,
            _ => (out_endpoint, out_dst),
        };

        // A plain peer keyed by SDES is sent what the DTLS peer sent, protected under the key the
        // engine offered it (RFC 3711 §3.3 for RTP, §3.4 for RTCP). After the numbering was continued
        // and the closed direction checked, so what is sealed is exactly what is relayed, and before
        // the taps and liveness stamp, so a packet the SDES leg refuses (a reused index, RFC 3711
        // §9.1) is neither delivered to an interception nor counted as carried.
        let mut sealed_for_plain = false;
        if let (Some(leg), Direction::Decrypt { .. }) = (&plain_leg, &direction) {
            let sealed = {
                let Ok(mut leg) = leg.lock() else {
                    tracing::error!("DTLS bridge SDES-leg mutex poisoned; dropping packet");
                    return;
                };
                (leg.protect(out.as_slice(), resealed), leg.reuse_refusals())
            };
            if let (Err(error), refused) = sealed {
                crate::egress_track::log_protect_failure(&error, "dtls-bridge", refused);
                self.datapath.note_dropped(packet.endpoint);
                return;
            }
            sealed_for_plain = true;
        }

        // Accepted: past the source gate, past the keyed check and past the crypto. Stamp liveness for
        // the idle sweep, exactly as the SDES bridge does and for the same reason — a `Redirect` leg
        // gets no `last_seen` from the datapath (docs/security-and-nat.md §4 layer 6). `Pipeline`-mode
        // media returned above and is stamped by the per-call actor it was handed to.
        self.datapath.note_activity(packet.endpoint);

        // Lawful-interception content (ETSI TS 103 221-2 X3), taken from whichever side of the
        // transform is plaintext — the same placement as the SDES bridge. Reached only after the
        // source gate, after the leg is keyed, and after the crypto succeeded, so an unkeyed,
        // forged or replayed packet is never delivered.
        let plaintext = match direction {
            Direction::Encrypt => plaintext_in,
            Direction::Decrypt { .. } | Direction::Pipeline { .. } => out.as_slice(),
        };
        // Audio only: interception, a tee and a recording take the call's audio, and a bundled
        // video stream is none of it (docs/security-and-nat.md, "Video on a two-party call").
        if !is_video {
            x3.deliver(packet.source, plaintext);
            // A tee's or a recording's copy of the same plaintext (the SDES bridge taps identically).
            if !plain_taps.is_empty() && kind != PacketKind::Rtcp {
                plain_taps.offer(plaintext);
            }
        }
        // Telemetry: the plaintext RTCP either party sent, which the datapath's relay tap never sees
        // on a bridged leg.
        if kind == PacketKind::Rtcp {
            ObservedRtcp::offer(
                self.datapath.rtcp_tap().as_ref(),
                packet.endpoint,
                packet.source,
                out_dst,
                plaintext,
            );
        }

        let wire: &[u8] = if sealed_for_plain {
            resealed.as_slice()
        } else {
            out.as_slice()
        };
        if let Err(error) = self.datapath.send(out_endpoint, out_dst, wire).await {
            tracing::debug!(%error, "DTLS bridge forward send failed");
        }
    }
}
