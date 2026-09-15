//! SIPREC / monitor subscriptions (RFC 7866): offer a call's legs to a send-only subscriber.

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_datapath::{AddressFamily, Datapath, Endpoint};
use siphon_rtp_proto::{CmdResult, ProfileFlags};

use crate::media_pipeline::{MediaControl, RawTee};
use crate::sdp;

use super::{error_result, ok_empty, unknown_call, ClientId, Engine, PipelineKind};

/// A SIPREC / monitor media subscription (RFC 7866): one or more source legs' **raw ingress RTP** is
/// tee'd byte-for-byte toward a send-only subscriber (a Session Recording Server, SRS). Unlike a
/// re-encode fork, the raw tee carries each leg's negotiated codec verbatim — so it works on a plain
/// G.711 relay and on a codec the engine has no encoder for (AMR-WB), with no transcode.
///
/// `subscribe_request` allocates the subscriber endpoint and records the subscription as *pending*
/// (no `srs_rtp`, no installed tee) — media cannot flow until `subscribe_answer` brings the SRS's
/// address. `subscribe_answer` installs a raw tee on each tapped leg of the call's [`MediaCall`]. The
/// subscriber is **send-only** (engine → SRS): the engine never opens a Forward/Redirect flow on
/// `subscriber_endpoint`, so it accepts no inbound media (RTPBleed has no surface here — §4).
pub(super) struct Subscription {
    /// The subscription identity returned to the controller as the UAS to-tag.
    subscription_id: String,
    /// Which source legs are tee'd: each entry is a leg selector (`true` ⇒ leg A, `false` ⇒ leg B).
    /// More than one entry is an MPTY subscription (each named leg is a separate tap into this one
    /// subscriber). Mirrors [`crate::media_pipeline::MediaControl::AddRawTee`]'s `source_a`.
    pub(super) taps: Vec<bool>,
    /// The engine endpoint the tee'd RTP is transmitted from (send-only toward the SRS).
    pub(super) subscriber_endpoint: Endpoint,
    /// The SRS's RTP address, learned from `subscribe_answer`. `None` while the subscription is
    /// pending (offered but not yet answered) — no media flows until it is known.
    pub(super) srs_rtp: Option<std::net::SocketAddr>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// SIPREC / monitor `subscribe_request` (RFC 7866): the engine **offers** one or more source
    /// legs' media to a send-only subscriber (a Session Recording Server, SRS). It resolves the source
    /// legs from `from_tags` (an MPTY subscription taps every named leg), allocates one subscriber
    /// endpoint, advertises the (first) source leg's negotiated codec in the offer's `a=rtpmap`
    /// (RFC 4566 §6) with `a=sendonly` (RFC 3264 §5.1), records a *pending* subscription, and returns
    /// the offer. No media flows until `subscribe_answer` brings the SRS's address.
    ///
    /// The tee copies the source leg's **original ingress RTP byte-for-byte** — its negotiated codec,
    /// no re-encode — so it works on **any** call: a plain G.711 relay, a transcoding call, and a
    /// codec the engine cannot encode (AMR-WB). A plain passthrough relay (the in-kernel `Forward`
    /// fast path) is **promoted** to userspace here so the tee has somewhere to attach; a secure
    /// (SRTP-bridge) or WS-bridge call cannot be tee'd yet and is rejected.
    ///
    /// MPTY: each named leg becomes a separate tap into the one subscription. A true N-way *mix* into
    /// a single stream is a later feature — for now the SRS receives each leg's stream interleaved on
    /// the one subscriber endpoint (distinguishable by SSRC, RFC 3550).
    pub(super) async fn subscribe_request(
        &self,
        client: ClientId,
        call_id: &str,
        from_tags: &[String],
        sdp: Option<&str>,
        _profile: &ProfileFlags,
    ) -> CmdResult {
        // The controller offers media to the SRS — it sends no SDP on the request. (An SDP-bearing
        // request, i.e. the SRS offering to the engine, is a follow-up; reject it clearly for now.)
        if sdp.is_some() {
            return error_result(
                "subscribe_request",
                &"SDP-offer-from-subscriber is not supported (the engine offers; send sdp: null)",
            );
        }
        // Snapshot the leg identity/codecs/pipeline under the ownership guard (A3 — docs §5).
        let Some((call_to, near_codec, far_codec, pipeline, family)) =
            self.owned_call(client, call_id, |call| {
                (
                    call.to_tag.clone(),
                    call.near_codec.clone(),
                    call.far_codec.clone(),
                    call.pipeline,
                    // The subscriber endpoint binds the call's address family (RFC 4566 §5.7), so a
                    // v6 call's SIPREC tee is offered to the SRS on a v6 endpoint (`c=IN IP6`).
                    AddressFamily::of(call.near.rtp.local_addr.ip()),
                )
            })
        else {
            return unknown_call(call_id);
        };
        // A crypto-bridge leg (SDES or DTLS-SRTP, facing either party) or a WS-bridge leg cannot be
        // raw-tee'd: the on-the-wire bytes are encrypted / off to a WS server, not the leg's clear
        // negotiated codec, and a bridge has no media actor for the fork to attach to. Reject clearly
        // rather than answer ok for a subscription that would never carry a packet.
        if pipeline.is_crypto_bridge() || pipeline == PipelineKind::Ws {
            return error_result(
                "subscribe_request",
                &"SIPREC on a secure (SRTP) or WebSocket-bridged call is not supported yet",
            );
        }

        // Resolve each named leg to a tap selector (`true` ⇒ leg A, `false` ⇒ leg B). An empty
        // `from_tags` defaults to leg A. Duplicate / unknown tags collapse to leg A (the offerer).
        let taps: Vec<bool> = if from_tags.is_empty() {
            vec![true]
        } else {
            let mut taps = Vec::with_capacity(from_tags.len());
            for tag in from_tags {
                // The call's to_tag ⇒ leg B; anything else (the from_tag, or unknown) ⇒ leg A.
                let source_a = !matches!(call_to.as_deref(), Some(to_tag) if to_tag == *tag);
                if !taps.contains(&source_a) {
                    taps.push(source_a);
                }
            }
            taps
        };

        // The codec advertised in the offer = the (first tapped) source leg's negotiated codec.
        let first_tap_source_a = taps.first().copied().unwrap_or(true);
        let codec = if first_tap_source_a {
            near_codec
        } else {
            far_codec
        };
        let Some(codec) = codec else {
            return error_result(
                "subscribe_request",
                &"the source leg has no negotiated codec to advertise",
            );
        };

        // Promote a plain passthrough relay to userspace so the tee has an actor to attach to.
        // Idempotent across subscriptions on the same call: a second subscribe finds it already a
        // media call and skips. On a call that already runs in the media slow path (transcode/record)
        // this is a no-op.
        if pipeline == PipelineKind::Passthrough && !self.media.is_media_call(call_id) {
            if let Err(reason) = self.promote_passthrough(call_id).await {
                return error_result("subscribe_request: promote relay", &reason);
            }
        }

        // Allocate the single send-only subscriber endpoint in the call's address family. SIPREC has
        // no per-leg `direction`, so the leg uses the default interface — its bind IP and its
        // advertised (public) address, which the SRS must be able to reach.
        let (bind, advertised_override) =
            Self::leg_binding(self.interfaces.default_interface(), family);
        let subscriber_endpoint = match self.alloc_endpoints(1, family, bind).await {
            Ok(mut endpoints) => endpoints.remove(0),
            Err(reason) => return error_result("subscribe_request", &reason),
        };
        let advertised = advertised_override.unwrap_or_else(|| subscriber_endpoint.local_addr.ip());

        // The subscription id (returned as the UAS to-tag) names this subscription for answer/teardown.
        let subscription_id = subscription_tag();
        let offer = subscriber_offer_sdp(subscriber_endpoint.local_addr, advertised, &codec);

        self.subscriptions
            .entry(call_id.to_string())
            .or_default()
            .push(Subscription {
                subscription_id: subscription_id.clone(),
                taps,
                subscriber_endpoint,
                srs_rtp: None,
            });

        CmdResult::Ok {
            sdp: Some(offer),
            duration_ms: None,
            play_id: None,
            recording_id: None,
            to_tag: Some(subscription_id),
            stats: None,
        }
    }

    /// SIPREC `subscribe_answer` (RFC 7866): the SRS's answer brings its RTP address. Parse it, then
    /// install a raw-RTP tee on each tapped source leg of the call's [`MediaCall`], copying the leg's
    /// original ingress RTP byte-for-byte out the subscriber endpoint toward the SRS. The subscriber is
    /// send-only — the engine installs no inbound flow on `subscriber_endpoint`, so no RTPBleed surface
    /// exists (docs/security-and-nat.md §4).
    pub(super) async fn subscribe_answer(
        &self,
        client: ClientId,
        call_id: &str,
        _from_tag: &str,
        to_tag: &str,
        sdp: &str,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        let info = match sdp::parse(sdp) {
            Ok(info) => info,
            Err(error) => {
                return error_result("subscribe_answer: parse SRS SDP", &error);
            }
        };
        let srs_rtp = info.remote_rtp;

        // Locate the pending subscription named by `to_tag` and read its taps + subscriber endpoint.
        let (taps, subscriber_endpoint) = {
            let Some(subscriptions) = self.subscriptions.get(call_id) else {
                return error_result("subscribe_answer", &"no subscription for this call");
            };
            let Some(subscription) = subscriptions
                .iter()
                .find(|subscription| subscription.subscription_id == to_tag)
            else {
                return error_result(
                    "subscribe_answer",
                    &format!("unknown subscription {to_tag}"),
                );
            };
            if subscription.srs_rtp.is_some() {
                return error_result("subscribe_answer", &"subscription is already answered");
            }
            (subscription.taps.clone(), subscription.subscriber_endpoint)
        };

        // Install a raw tee on each tapped leg of the running media actor (no encoder — the leg's
        // original ingress RTP is copied byte-for-byte toward the SRS, RFC 7866 §6). If the actor is
        // gone (call torn down between the ownership check and here), free the endpoint and report it.
        let tee = RawTee {
            subscriber_endpoint: subscriber_endpoint.id,
            srs_dst: srs_rtp,
        };
        let mut attached = false;
        for source_a in &taps {
            if self.media.control(
                call_id,
                MediaControl::AddRawTee {
                    source_a: *source_a,
                    tee,
                },
            ) {
                attached = true;
            }
        }
        if !attached {
            self.datapath.remove_endpoint(subscriber_endpoint.id).await;
            return error_result("subscribe_answer", &"media call is no longer active");
        }

        // Record the now-active subscription (the SRS address) for unsubscribe / teardown.
        if let Some(mut subscriptions) = self.subscriptions.get_mut(call_id) {
            if let Some(subscription) = subscriptions
                .iter_mut()
                .find(|subscription| subscription.subscription_id == to_tag)
            {
                subscription.srs_rtp = Some(srs_rtp);
            }
        }
        ok_empty()
    }

    /// SIPREC `unsubscribe` (RFC 7866): detach the raw tee from every tapped leg of the media actor,
    /// free the subscriber endpoint, drop the subscription record, and — if this was the last
    /// subscription on a promoted passthrough relay — demote the call back to the in-kernel `Forward`
    /// fast path. Only the owning client may.
    pub(super) async fn unsubscribe(
        &self,
        client: ClientId,
        call_id: &str,
        _from_tag: &str,
        to_tag: &str,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        // Remove the named subscription from the call's list.
        let removed = {
            let Some(mut subscriptions) = self.subscriptions.get_mut(call_id) else {
                return error_result("unsubscribe", &"no subscription for this call");
            };
            let Some(position) = subscriptions
                .iter()
                .position(|subscription| subscription.subscription_id == to_tag)
            else {
                return error_result("unsubscribe", &format!("unknown subscription {to_tag}"));
            };
            subscriptions.remove(position)
        };
        self.subscriptions
            .remove_if(call_id, |_, list| list.is_empty());
        self.detach_subscription(call_id, removed).await;
        // Once no subscription (or other hold — recording, DTMF block) remains on a relay we promoted,
        // demote it back to the in-kernel Forward fast path (the relay leg keeps flowing throughout).
        self.demote_if_idle(call_id).await;
        ok_empty()
    }

    /// Tear one subscription down: remove its raw tee from every tapped leg (if the actor is still
    /// alive) and free its subscriber endpoint. Shared by `unsubscribe` and call teardown. (No drain
    /// task to abort — the raw tee emits through the actor's own send path.)
    async fn detach_subscription(&self, call_id: &str, subscription: Subscription) {
        for source_a in &subscription.taps {
            self.media.control(
                call_id,
                MediaControl::RemoveRawTee {
                    source_a: *source_a,
                    subscriber_endpoint: subscription.subscriber_endpoint.id,
                },
            );
        }
        self.datapath
            .remove_endpoint(subscription.subscriber_endpoint.id)
            .await;
    }

    /// Free every subscription on a call (delete / reap / half-built teardown). Detaches each tee and
    /// frees its subscriber endpoint. (No demotion here — the whole call, including any promoted relay
    /// actor, is being torn down by the caller.)
    pub(super) async fn drop_subscriptions(&self, call_id: &str) {
        if let Some((_, subscriptions)) = self.subscriptions.remove(call_id) {
            for subscription in subscriptions {
                self.detach_subscription(call_id, subscription).await;
            }
        }
    }
}

/// A fresh subscription identity, returned to the controller as the SIPREC UAS to-tag and used to
/// name the subscription on answer / unsubscribe. Random hex from the CSPRNG (a stable fallback when
/// it is unavailable — never panics), prefixed so it is recognisable in logs.
pub(super) fn subscription_tag() -> String {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return "sub-00000000".to_string();
    }
    format!("sub-{}", hex_lower(&bytes))
}

/// Lowercase-hex encode a byte slice (no external dependency; used for the subscription tag).
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Build the SIPREC subscriber SDP **offer** (engine → SRS): a minimal send-only audio stream
/// advertising the engine's subscriber endpoint + the fork codec (RFC 4566 §5 line order
/// `v= o= s= c= t= m=`; RFC 3264 §5.1 `a=sendonly` — the engine only transmits to the SRS, which is
/// the RTPBleed-safe posture: no inbound media is accepted on this endpoint).
fn subscriber_offer_sdp(
    local_addr: std::net::SocketAddr,
    advertised: std::net::IpAddr,
    codec: &CodecSpec,
) -> String {
    let payload_type = codec.payload_type;
    let mut sdp = String::new();
    use std::fmt::Write as _;
    // RFC 4566 §5: mandatory lines in order. o= uses a fixed session id/version (one offer per
    // subscription); s=- is the standard "no name"; t=0 0 is an unbounded session.
    // RFC 4566 §5.7: the addrtype (`IP4`/`IP6`) follows the advertised address' family (which matches
    // the bound endpoint's), so a v6 SIPREC tee is offered to the SRS as `c=IN IP6`. The advertised
    // (public) IP is emitted so the SRS can reach the engine; the port is the bound one.
    let addrtype = if advertised.is_ipv6() { "IP6" } else { "IP4" };
    let _ = write!(
        sdp,
        "v=0\r\n\
         o=- 0 0 IN {addrtype} {ip}\r\n\
         s=siphon-rtp-siprec\r\n\
         c=IN {addrtype} {ip}\r\n\
         t=0 0\r\n\
         m=audio {port} RTP/AVP {payload_type}\r\n\
         a=rtpmap:{payload_type} {name}/{clock}{channels}\r\n\
         a=sendonly\r\n",
        ip = advertised,
        port = local_addr.port(),
        name = codec.encoding_name,
        clock = codec.clock_rate_hz,
        // RFC 4566 §6 / RFC 7587 §7 — the one shared rule for the optional /channels suffix.
        channels = sdp::rtpmap_channel_suffix(codec),
    );
    sdp
}
