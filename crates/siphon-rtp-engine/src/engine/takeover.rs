//! WebSocket takeover bridges: a WebSocket server becomes leg A's far side.

use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_datapath::{Datapath, EndpointId, FlowAction, SourceFilter};
use siphon_rtp_dsp::VoiceDetector;
use siphon_rtp_media::bridge::protocol::{Direction as WsDirection, MediaFormat};
use siphon_rtp_media::bridge::{run_bridge, BridgeEndReason, BridgeSession};
use siphon_rtp_media::jitter::JitterBuffer;
use siphon_rtp_media::leg::MediaLeg;
use siphon_rtp_proto::{CmdResult, Event, ProfileFlags, WsBridgeEndReason, WsVadEngine};
use std::net::SocketAddr;
use std::sync::Arc;

use super::negotiate::{apply_received_from, random_ssrc};
use super::{error_result, ok_empty, unknown_call, ClientId, Engine, PipelineKind};

/// Everything [`Engine::setup_ws_bridge`] needs to stand one WebSocket-takeover bridge up. A struct
/// rather than a parameter list because a secure takeover adds the leg's SRTP state and its ICE gate
/// to an already-wide signature.
pub(super) struct WsBridgeSetup<'a> {
    /// The call the bridge belongs to (also the WS `start` stream id).
    pub(super) call_id: &'a str,
    /// The WebSocket media server to dial (`ws://` or `wss://`).
    pub(super) ws_uri: &'a str,
    /// Leg A's RTP endpoint — redirected to the bridge, and the socket the downlink leaves from.
    pub(super) endpoint_a: EndpointId,
    /// Leg A's signalled transport address: the initial downlink destination (ICE may re-point it).
    pub(super) a_rtp: SocketAddr,
    /// A's negotiated primary codec — the bridge decodes it uplink and encodes it downlink.
    pub(super) codec: Option<&'a CodecSpec>,
    /// The RTPBleed source gate for A's ingress (docs/security-and-nat.md §4 layer 2).
    pub(super) accepted_source: SourceFilter,
    /// A full RFC 8445 agent runs on this leg and has not selected a pair yet: the gate above is open
    /// for peer-reflexive checks, so the registry drops **all** media until the selection lands.
    pub(super) ice_pending: bool,
    /// SRTP crypto for a secure offerer — SDES-keyed up front, or DTLS-pending. `None` = plaintext.
    pub(super) secure: Option<Arc<crate::ws_bridge::WsSecureLeg>>,
    /// The L16 wire rate the WS server exchanges, independent of A's codec rate and applied in both
    /// directions. `None` follows A's codec rate. Validated before anything is installed or dialled.
    pub(super) wire_sample_rate: Option<u32>,
    /// Clean A's uplink toward the WS server.
    pub(super) noise_suppression: bool,
    /// Cancel A's uplink echo against the downlink the bridge plays toward the call, and how — the
    /// search window or long tail, and whether the residual post-filter is chained.
    pub(super) echo: crate::media_pipeline::EchoProfile,
    /// Local energy-VAD turn-taking / barge-in, when the profile asked for it.
    pub(super) vad_config: Option<WsVadConfig>,
    /// The downlink destination + latch to **reuse**, on a re-point ([`Engine::start_ws_bridge`] on
    /// a call that already has a bridge). `None` mints a fresh one aimed at `a_rtp`, which is what
    /// every negotiation-time setup wants. Carried across a re-point because it is leg A's state, not
    /// the connection's: an ICE selection that already landed (RFC 8445 §8.1.1) published the chosen
    /// pair there, and the leg's own media may have latched a source since — a fresh one would send
    /// the replacement bridge's downlink back to the signalled `c=` address the NATed peer cannot
    /// receive on.
    pub(super) egress: Option<Arc<crate::ws_bridge::WsEgress>>,
    /// Set only when this bridge is **taking over a live relay** — the flows to switch off, and the
    /// ones a later detach switches back on. `None` at negotiation time, where there is no relay yet.
    pub(super) takeover: Option<WsRelayTakeover>,
    /// A connection the caller has **already** dialled, used instead of dialling `ws_uri` here.
    ///
    /// Only a re-point supplies one, and it has to: a re-point must stop the outgoing bridge before
    /// the replacement can own the leg, and if the new dial then failed the call would be left
    /// redirected into nothing with the relay-restore plan already dropped. Dialling first turns that
    /// into a clean refusal with the live bridge still up. Everything this function does *before* the
    /// dial — resolving the codec, validating the wire rate, building the resamplers and the detector
    /// — is, on a re-point, a rerun of a computation that already succeeded for these exact
    /// parameters, so nothing between here and the redirect can fail on that path.
    pub(super) socket: Option<WsClientSocket>,
}

/// A dialled WebSocket client connection to a media server — what
/// [`tokio_tungstenite::connect_async_tls_with_config`] hands back, named so it can be dialled by one
/// function and consumed by another.
type WsClientSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Switching a live two-party relay onto a WebSocket takeover, and back again.
///
/// The two halves are recorded together because they are one decision: `displace` is applied with
/// the redirect that hands leg A to the bridge, and `restore` is the exact set of `Forward` rules
/// [`Engine::detach_ws_bridge`] reinstalls to give the call its A↔B path back. Keeping the restore
/// verbatim — rather than recomputing a relay at detach time — is what makes the detach safe: the
/// engine puts back precisely what it took away, gate and latch policy included, and never has to
/// invent a media path from state it does not hold.
#[derive(Clone, Debug)]
pub(super) struct WsRelayTakeover {
    /// Applied when the bridge is installed: every endpoint of the displaced relay goes to
    /// [`FlowAction::Drop`]. Leg B's ingress included — with A's media owned by the bridge there is
    /// nowhere to forward it, and leaving the rule up would mix B's audio into the bridge's downlink
    /// on A's socket. RFC 3264 §8: the parties' negotiated addresses do not move; only what the
    /// engine does with the packets does.
    displace: Vec<(EndpointId, FlowAction)>,
    /// Reinstalled on detach — the call's own `relay_flows`, untouched.
    restore: Vec<(EndpointId, FlowAction)>,
    /// The [`PipelineKind`] the call had before the takeover, restored alongside the flows.
    restore_pipeline: PipelineKind,
}

/// A live WebSocket **takeover** bridge, tracked per call alongside the [`crate::ws_bridge`]
/// registry that routes its packets.
///
/// The registry owns the datapath route and the two tasks; this owns everything the *control plane*
/// needs and the registry has no business knowing: who to send the lifecycle events to, the
/// once-only end latch, the negotiated shape to carry across a re-point, and the relay to restore.
/// It is held here (rather than on the `Call`) for the same reason [`WsTee`] is: the end event is
/// emitted during teardown, *after* `delete` has already removed the call.
pub(super) struct WsBridge {
    /// The call's offerer tag and owning control client, copied at setup so the end event can still
    /// be addressed once the call itself is gone.
    from_tag: String,
    owner: ClientId,
    /// The bridge's `streamId` — the same one the WS `start` frame carries, so a controller can line
    /// the control events up against the media stream.
    stream_id: String,
    /// Where this bridge is currently pointed. Read back by observability and re-point logging.
    ws_uri: String,
    /// Set once an end event has been emitted, so the controller sees exactly one `ws_bridge_ended`
    /// whether the server, the transport or a detach got there first.
    ended: Arc<std::sync::atomic::AtomicBool>,
    /// The leg's negotiated codec, kept so a re-point rebuilds the same coder pair rather than
    /// re-deriving it from a `Call` that (on `answer_local`) may never have recorded one.
    codec: CodecSpec,
    /// Leg A's signalled RTP address — the fresh-watch seed, kept for the record's own sake.
    a_rtp: SocketAddr,
    /// The negotiated L16 wire rate, and the uplink processing the profile asked for. Carried across
    /// a re-point: a controller moving a voice-AI call to a second consumer asked for a different
    /// *destination*, not for its VAD, noise suppression or wire rate to be silently turned off.
    wire_sample_rate: Option<u32>,
    noise_suppression: bool,
    echo: crate::media_pipeline::EchoProfile,
    vad_config: Option<WsVadConfig>,
    /// The relay this bridge displaced, or `None` when the bridge *is* the call's negotiated media
    /// path (`ProfileFlags::ws_uri`). This is exactly what makes a detach possible or not — see
    /// [`Engine::detach_ws_bridge`].
    takeover: Option<WsRelayTakeover>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Stand up the WebSocket bridge for leg A: install `Redirect` on A's RTP endpoint, dial the WS
    /// server as a client, build a [`BridgeSession`] on a [`MediaLeg`] in A's codec, and spawn the
    /// bridge + the rtp_out→datapath drain task, registering both in the [`WsRegistry`]. The bridge's
    /// `rtp_in` is fed by the redirect dispatcher (gated by `accepted_source` — RTPBleed defence,
    /// `Redirect` skips the datapath gate). Dials both `ws://` and `wss://` (TLS on ring/rustls).
    ///
    /// `wire_sample_rate` is the controller's `ProfileFlags::ws_sample_rate`: the L16 rate the server
    /// exchanges, independent of A's codec rate and applied in **both** directions. `None` keeps the
    /// historical behaviour (follow A's codec). It is validated **before** anything is installed or
    /// dialled, so an unserviceable rate is a clean rejection with no redirect, no socket and no
    /// half-attached leg.
    ///
    /// On a **secure** takeover leg (`setup.secure`) the registry SRTP-decrypts A's ingress before the
    /// bridge sees it and the drain task SRTP-encrypts the downlink before it leaves — fail-closed
    /// both ways, so an unkeyed or failing leg emits nothing rather than plaintext (RFC 3711).
    ///
    /// The dial happens **before** any flow is installed. At negotiation time that only shortens the
    /// window in which A's endpoint is redirected with no route behind it; for a runtime attach it is
    /// load-bearing, because the call is *already carrying audio* and a failed dial must leave it
    /// exactly as it was rather than redirected into nothing. `setup.takeover` then switches the
    /// displaced relay off in the same step as the redirect, so B's media never mixes into the
    /// bridge's downlink on A's socket.
    ///
    /// Emits [`Event::WsBridgeStarted`] on success, and arranges the matching
    /// [`Event::WsBridgeEnded`] for whenever the bridge stops — including when the *server* ends it,
    /// which was previously silent. That silence is the failure this reports: a takeover bridge is
    /// leg A's only far side, so a bridge that dies without a word is a live call gone one-way with
    /// nothing anywhere saying so.
    pub(super) async fn setup_ws_bridge(&self, setup: WsBridgeSetup<'_>) -> Result<(), String> {
        let WsBridgeSetup {
            call_id,
            ws_uri,
            endpoint_a,
            a_rtp,
            codec,
            accepted_source,
            ice_pending,
            secure,
            noise_suppression,
            echo,
            vad_config,
            wire_sample_rate,
            egress: existing_egress,
            takeover,
            socket: dialled,
        } = setup;
        use siphon_rtp_media::bridge::wire_rate::{validate_wire_sample_rate, wire_resampler};

        // The lifecycle events are addressed to the call's owner and carry its offerer tag, and both
        // have to be captured now: teardown emits the end event after `delete` has removed the call.
        let Some((from_tag, owner)) =
            self.owned_call_internal(call_id, |call| (call.from_tag.clone(), call.owner))
        else {
            return Err("call no longer exists".to_string());
        };

        let Some(codec) = codec else {
            return Err("offer carried no usable audio codec for the WS bridge".to_string());
        };
        // Build A's codec pair for the leg: decode A's RTP → L16 uplink; encode L16 downlink → A's RTP.
        let decoder = factory::decoder_for(codec).map_err(|error| error.to_string())?;
        let encoder = factory::encoder_for(codec).map_err(|error| error.to_string())?;
        let ptime = std::time::Duration::from_millis(u64::from(codec.ptime_ms.max(1)));

        // The leg's PCM rate is what the *decoder* emits, which is not the RTP clock for G.722
        // (16 kHz audio, 8 kHz RTP clock; RFC 3551 §4.5.2). Read it before the decoder moves into the
        // leg — and before the redirect is installed, because the wire rate is resolved against it and
        // a rejection here must leave the call exactly as it found it.
        let leg_pcm_rate = decoder.params().sample_rate_hz;
        let wire_rate = match wire_sample_rate {
            Some(requested) => {
                validate_wire_sample_rate(requested).map_err(|error| error.to_string())?
            }
            None => leg_pcm_rate,
        };
        // Uplink converts the leg into the wire (what the server hears); downlink converts the wire
        // back into the leg (what the call hears). Both are `None` when the rates already match, so a
        // bridge that did not ask for a rate takes the exact path it always took.
        let uplink_resampler =
            wire_resampler(leg_pcm_rate, wire_rate).map_err(|error| error.to_string())?;
        let downlink_resampler =
            wire_resampler(wire_rate, leg_pcm_rate).map_err(|error| error.to_string())?;

        // Dial the WS server (or take the connection the caller already dialled — see
        // `WsBridgeSetup::socket`). Before anything is installed, so a dial that fails leaves the
        // call's datapath untouched, which for a runtime attach means still relaying.
        let socket = match dialled {
            Some(socket) => socket,
            None => self.dial_ws_bridge(ws_uri).await?,
        };

        // Switch the displaced relay off (all `Drop`) and redirect A's RTP here in one step, so the
        // dispatcher routes A to the bridge and B's ingress stops being forwarded onto A's socket.
        // Empty at negotiation time — there is no relay to displace before the call is answered.
        if let Some(takeover) = takeover.as_ref() {
            for (endpoint, action) in &takeover.displace {
                if let Err(error) = self.datapath.install_flow(*endpoint, *action) {
                    let _ = self.restore_displaced_relay(takeover);
                    return Err(format!("displace relay flow for WS takeover: {error}"));
                }
            }
        }
        if let Err(error) = self.datapath.install_flow(endpoint_a, FlowAction::Redirect) {
            // Nothing owns the leg yet, so put the relay back rather than leave the call half
            // displaced with no bridge and no record to detach.
            if let Some(takeover) = takeover.as_ref() {
                let _ = self.restore_displaced_relay(takeover);
            }
            return Err(format!("install WS bridge redirect: {error}"));
        }

        // A jitter buffer shallow enough for low-latency voice-AI (target 1, cap 16 — the bridge
        // pops one frame per ptime tick, the consumer's cadence being the sample-tick clock).
        let leg = MediaLeg::new(
            decoder,
            encoder,
            JitterBuffer::new(1, 16),
            random_ssrc(),
            codec.payload_type,
        );
        // The WS media format advertised in `start`: L16 at the **negotiated wire rate**, mono, LE.
        // This is authoritative — the server frames binary audio against it in both directions, so it
        // must be the rate the session actually converts to, never the leg's codec rate.
        let format = MediaFormat {
            encoding: siphon_rtp_media::bridge::protocol::Encoding::L16,
            sample_rate: wire_rate,
            channels: 1,
            bit_depth: 16,
            endianness: siphon_rtp_media::bridge::protocol::Endianness::Little,
            ptime: codec.ptime_ms.max(1),
        };
        // The `streamId` the WS `start` frame announces — and, on the control plane, the correlator
        // carried by `ws_bridge_started` / `ws_bridge_ended`. One value, so the two line up.
        let stream_id = format!("ws-{call_id}");
        let mut session = BridgeSession::new(
            leg,
            format,
            stream_id.clone(),
            call_id.to_string(),
            WsDirection::Duplex,
            8, // playout cap (drop-oldest): late audio is worthless
        )
        // Convert between A's codec rate and the wire rate in both directions (no-ops when equal).
        .with_rate_conversion(uplink_resampler, downlink_resampler)
        // A takeover leg is the caller's only far side: nothing else feeds this call, and a WS server
        // is quiet for most of a conversation. Without an idle floor the leg emits RTP only while the
        // bot is speaking, which reads to the caller as dead air, lets the NAT pinhole toward them
        // expire, and leaves the egress clock stopped between turns.
        .with_comfort_idle(true)
        // Clean leg A's uplink audio toward the voice-AI server when requested (rate-gated inside).
        .with_noise_suppression(noise_suppression)
        // Cancel leg A's uplink echo toward the voice-AI server, referenced against the downlink the
        // bridge plays toward the call — so the model does not hear its own speech reflected by the
        // phone. Built at the **wire** rate, because that is the domain both of its inputs are in
        // once the conversion sits in the RTP shell: the near end is the converted uplink and the
        // far-end reference is the server's own downlink frame. Single-sourced from the same
        // `build_echo_canceller` the transcode path uses (an unsupported rate keeps the uplink
        // uncancelled rather than failing the bridge).
        .with_echo_canceller(if echo.enabled {
            crate::media_pipeline::build_echo_canceller(wire_rate, echo)
        } else {
            None
        });
        // Local VAD turn-taking (speech_started/stopped + optional barge-in) when requested. Both
        // the trailing hangover and the leading minimum-speech run are carried in ms and converted
        // to ptime frames now that the codec ptime is known. The neural detector can refuse, which
        // fails the bridge rather than silently downgrading to the detector the controller was
        // trying to avoid.
        //
        // Built at the **wire** rate, not the leg's codec rate: the rate conversion sits in the RTP
        // shell, so by the time a frame reaches the core — where the detector runs — it is already
        // in the wire domain, exactly like the noise suppressor and the echo canceller above.
        // Handing the detector the codec rate would have it frame against a length the audio no
        // longer has. (The neural detector resamples anything that is not 16 kHz into itself.)
        if let Some(vad) = vad_config {
            let ptime_ms = codec.ptime_ms.max(1);
            let detector = vad.build_detector(wire_rate, ptime_ms)?;
            let minimum_speech_frames = vad.minimum_speech_frames(ptime_ms);
            tracing::debug!(
                target: "media",
                %call_id,
                engine = ?vad.engine,
                pcm_rate_hz = wire_rate,
                hangover_frames = vad.hangover_frames(ptime_ms),
                minimum_speech_frames,
                barge_in = vad.barge_in,
                "ws bridge uplink VAD selected"
            );
            session = session.with_voice_detector(detector, minimum_speech_frames, vad.barge_in);
        }

        let (rtp_in_tx, rtp_in_rx) = flume::bounded::<bytes::Bytes>(1024);
        let (rtp_out_tx, rtp_out_rx) = flume::bounded::<bytes::Bytes>(1024);

        // Announce the bridge **before** spawning the task that can report its end. The task starts
        // running the moment it is spawned, and a WS server that closes on the handshake (or a dial
        // onto a socket that is already going away) makes `run_bridge` return almost immediately —
        // so with the announcement after the spawn, `ws_bridge_ended` could be enqueued first and a
        // controller would receive an end for a stream it was never told had started. Keying
        // per-stream state on the start event is the obvious way to consume this, and that consumer
        // would leak or fault on the unknown stream.
        //
        // Enqueue order is the fix, not a lock: the event channel is FIFO and the spawn happens
        // strictly after this `push_event` returns, so the end can only ever be queued behind the
        // start. Everything from here to the registration below is infallible (the last `?` is the
        // VAD detector, above), so this cannot announce a bridge that then fails to come up.
        self.push_event(
            owner,
            Event::WsBridgeStarted {
                call_id: call_id.to_string(),
                from_tag: from_tag.clone(),
                stream_id: stream_id.clone(),
                ws_uri: ws_uri.to_string(),
                sample_rate: wire_rate,
            },
        );

        // The bridge: pump A's RTP (rtp_in) ↔ WS, render WS downlink to RTP (rtp_out). Whichever way
        // it ends, say so once — a detach that beat it to the latch has already reported `Detached`.
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let bridge_task = {
            let events = self.events.get(&owner).map(|sink| sink.value().clone());
            let call_id = call_id.to_string();
            let from_tag = from_tag.clone();
            let stream_id = stream_id.clone();
            let ended = ended.clone();
            tokio::spawn(async move {
                let reason = match run_bridge(socket, session, rtp_in_rx, rtp_out_tx, ptime).await {
                    Ok(BridgeEndReason::ServerClosed) => WsBridgeEndReason::ServerClosed,
                    Ok(BridgeEndReason::ServerStopped) => WsBridgeEndReason::ServerStopped,
                    Ok(BridgeEndReason::CallEnded) => WsBridgeEndReason::CallEnded,
                    Err(error) => {
                        tracing::debug!(%error, %call_id, "ws bridge exited with error");
                        WsBridgeEndReason::TransportError
                    }
                };
                emit_ws_bridge_ended(
                    events.as_ref(),
                    &ended,
                    &call_id,
                    &from_tag,
                    &stream_id,
                    reason,
                );
            })
        };
        // Where the downlink goes. Published rather than captured so the leg's own symmetric-RTP
        // latch and an ICE selection can both re-point it mid-call (RFC 8445 §8.1.1) — a takeover
        // leg's egress belongs to this drain task, not to a datapath forward rule, so neither the
        // datapath's latch nor `Datapath::adopt_source` would ever reach it.
        // Reused verbatim on a re-point (see `WsBridgeSetup::egress`), so a selection or a latch that
        // has already landed keeps steering the downlink; minted at `a_rtp` for a first attach.
        let egress = existing_egress
            .unwrap_or_else(|| Arc::new(crate::ws_bridge::WsEgress::new(a_rtp, ice_pending)));
        // The drain: forward each rendered downlink RTP packet out A's endpoint toward A, encrypting
        // it first on a secure leg. This is the ONLY egress site a takeover call has — `play_media`,
        // `play_dtmf`, recording, SIPREC and the WS tee all refuse a `PipelineKind::Ws` call, and a
        // takeover call has no media actor and no forward rule — so encrypting here covers the whole
        // egress surface of a secure takeover.
        let datapath = self.datapath.clone();
        let drain_endpoint = endpoint_a;
        let drain_secure = secure.clone();
        let drain_egress = egress.subscribe();
        let drain_task = tokio::spawn(async move {
            let mut sealed = Vec::new();
            while let Ok(packet) = rtp_out_rx.recv_async().await {
                // Copy the destination out of the watch before any `.await` — never hold its guard
                // across a yield point.
                let destination = *drain_egress.borrow();
                let datagram: &[u8] = match drain_secure.as_ref() {
                    None => &packet,
                    Some(secure) => {
                        sealed.clear();
                        if !secure.protect_egress(&packet, &mut sealed) {
                            // Fail closed: an unkeyed leg (DTLS still handshaking) or a crypto failure
                            // drops the frame. Sending it in the clear toward a peer that negotiated
                            // SRTP is both unplayable and a confidentiality break.
                            continue;
                        }
                        &sealed
                    }
                };
                if let Err(error) = datapath.send(drain_endpoint, destination, datagram).await {
                    tracing::debug!(%error, "ws bridge downlink send failed");
                }
            }
        });

        self.ws.register(crate::ws_bridge::WsCallPlan {
            call_id: call_id.to_string(),
            endpoint_a,
            accepted_source,
            ice_pending,
            secure,
            egress,
            // A takeover leg has no per-call actor to stamp its liveness from, so the registry
            // carries the datapath itself and stamps on each accepted packet.
            activity: Arc::new(self.datapath.clone()),
            rtp_in: rtp_in_tx,
            bridge_task,
            drain_task,
        });
        self.ws_bridges.insert(
            call_id.to_string(),
            WsBridge {
                from_tag,
                owner,
                stream_id,
                ws_uri: ws_uri.to_string(),
                ended,
                codec: codec.clone(),
                a_rtp,
                wire_sample_rate,
                noise_suppression,
                echo,
                vad_config,
                takeover,
            },
        );
        tracing::info!(
            target: "siphon_rtp::media",
            call_id,
            ws_uri,
            leg_sample_rate = leg_pcm_rate,
            wire_sample_rate = wire_rate,
            converted = wire_rate != leg_pcm_rate,
            "ws bridge attached"
        );
        Ok(())
    }

    /// Dial a WebSocket media server as a client. A `wss://` URI completes the RFC 8446 handshake on
    /// the ring/rustls connector before the RFC 6455 upgrade; a `ws://` URI ignores the connector.
    async fn dial_ws_bridge(&self, ws_uri: &str) -> Result<WsClientSocket, String> {
        let connector = tokio_tungstenite::Connector::Rustls(self.ws_tls_client_config());
        let (socket, _response) =
            tokio_tungstenite::connect_async_tls_with_config(ws_uri, None, false, Some(connector))
                .await
                .map_err(|error| format!("dial {ws_uri}: {error}"))?;
        Ok(socket)
    }

    /// Reinstall the `Forward` rules a takeover displaced. Shared by the detach path and by the
    /// rollback in [`Self::setup_ws_bridge`].
    ///
    /// Every rule is attempted even after one fails, so a partial restore is as complete as it can
    /// be rather than stopping at the first endpoint — but the failure is both logged at ERROR and
    /// returned, because a leg left without a flow has no media path and the controller has to hear
    /// about it.
    fn restore_displaced_relay(&self, takeover: &WsRelayTakeover) -> Result<(), String> {
        let mut failure: Option<String> = None;
        for (endpoint, action) in &takeover.restore {
            if let Err(error) = self.datapath.install_flow(*endpoint, *action) {
                tracing::error!(
                    %error,
                    ?endpoint,
                    "failed to reinstall a displaced relay flow; the leg has no media path"
                );
                failure.get_or_insert_with(|| error.to_string());
            }
        }
        match failure {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }

    /// Attach — or re-point — a call's WebSocket **takeover** bridge ([`Command::AttachWsBridge`]).
    ///
    /// The runtime half of what `ProfileFlags::ws_uri` could previously only do at negotiation.
    /// Ownership is checked here (A3 — docs/security-and-nat.md §5); the work is in
    /// [`Self::start_ws_bridge`].
    pub(super) async fn attach_ws_bridge(
        &self,
        client: ClientId,
        call_id: &str,
        ws_uri: &str,
    ) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        match self.start_ws_bridge(call_id, ws_uri).await {
            Ok(()) => ok_empty(),
            Err(reason) => error_result("attach_ws_bridge", &reason),
        }
    }

    /// Stand a takeover bridge up on `call_id`, or move the one it already has.
    ///
    /// **Re-point** (the call already has a bridge). Everything except the destination belongs to
    /// leg A and is carried across: its codec, the negotiated wire rate and uplink processing, the
    /// RTPBleed source gate, the SRTP keying and the egress watch an ICE selection may already have
    /// re-pointed (RFC 8445 §8.1.1). The outgoing bridge is stopped and **awaited** before the
    /// replacement is registered, so two drain tasks never write to A's socket at once — that would
    /// interleave two RTP sequence-number and timestamp series toward one peer (RFC 3550 §5.1).
    ///
    /// **Takeover** (the call has no bridge). Only a plain, answered, two-party relay with nothing
    /// else attached to it can be taken over, because a takeover unwires A↔B and the engine has to
    /// be able to give that path back verbatim on detach. Everything else is refused rather than
    /// half-served:
    ///
    /// * A **secure offerer** (SDES-SRTP RFC 4568 / DTLS-SRTP RFC 5764) and an **ICE** leg get the
    ///   same `ws-takeover-secure-offerer` / `ws-takeover-ice-offerer` refusals `offer` and `answer`
    ///   already make, for the same reasons: on a two-leg call the engine is not A's cryptographic
    ///   far side, so the bridge would receive ciphertext and answer in the clear; and no agent is
    ///   armed to re-point a takeover leg's egress at the selected pair. Those guards previously ran
    ///   only on the negotiation path — a runtime attach reaches the identical code, so it makes the
    ///   identical checks.
    /// * A **transcoding, secure-bridge or promoted** call, and one held in userspace by a
    ///   recording, a SIPREC subscription, a WS tee or an X3 interception. Each of those owns per-
    ///   packet state built on the media path the takeover would remove; silently stopping an
    ///   interception or a recording is worse than refusing to start.
    /// * A **single-leg** call (`answer_local`, or an offer nobody answered). There is no relay to
    ///   displace and no second party a detach could ever hand it back to.
    async fn start_ws_bridge(&self, call_id: &str, ws_uri: &str) -> Result<(), String> {
        // --- re-point ------------------------------------------------------------------------
        if let Some(state) = self.ws.route_state(call_id) {
            let Some(previous) = self.ws_bridges.get(call_id).map(|bridge| {
                (
                    bridge.codec.clone(),
                    bridge.a_rtp,
                    bridge.wire_sample_rate,
                    bridge.noise_suppression,
                    bridge.echo,
                    bridge.vad_config,
                    bridge.takeover.clone(),
                    bridge.ws_uri.clone(),
                )
            }) else {
                // A route with no record is an engine bug, not a controller error: the two are
                // written together. Refuse rather than rebuild a bridge from guessed parameters.
                return Err(
                    "ws-bridge-untracked: the call has a WebSocket route with no bridge record; \
                     delete the call"
                        .to_string(),
                );
            };
            let (
                codec,
                a_rtp,
                wire_sample_rate,
                noise_suppression,
                echo,
                vad_config,
                takeover,
                old_uri,
            ) = previous;
            // Dial first, while the outgoing bridge still owns the leg: a re-point that cannot reach
            // the new consumer must be a clean refusal on a call that is still up, not a call left
            // redirected into nothing with its relay-restore plan already dropped.
            let socket = self.dial_ws_bridge(ws_uri).await?;
            self.stop_ws_bridge(call_id, WsBridgeEndReason::Detached)
                .await;
            let result = self
                .setup_ws_bridge(WsBridgeSetup {
                    call_id,
                    ws_uri,
                    endpoint_a: state.endpoint_a,
                    a_rtp,
                    codec: Some(&codec),
                    accepted_source: state.accepted_source,
                    ice_pending: state.ice_pending,
                    secure: state.secure,
                    noise_suppression,
                    echo,
                    vad_config,
                    wire_sample_rate,
                    egress: Some(state.egress),
                    // Carried forward: a re-point moves the far side, it does not change what the
                    // bridge displaced, so a detach after one still restores the original relay.
                    takeover,
                    socket: Some(socket),
                })
                .await;
            if result.is_ok() {
                tracing::info!(
                    target: "siphon_rtp::media",
                    call_id,
                    from = %old_uri,
                    to = %ws_uri,
                    "ws bridge re-pointed"
                );
            }
            return result;
        }

        // --- takeover of a live relay ----------------------------------------------------------
        let Some((pipeline, near, near_codec, relay_flows, near_secure, has_ice, received_from)) =
            self.owned_call_internal(call_id, |call| {
                (
                    call.pipeline,
                    call.near,
                    call.near_codec.clone(),
                    call.relay_flows.clone(),
                    call.near_secure,
                    call.ice.is_some(),
                    call.offer_received_from,
                )
            })
        else {
            return Err("call no longer exists".to_string());
        };

        // The same two refusals `offer` and `answer` make for `ws_uri`, checked first because they
        // are about the leg itself rather than about what is attached to it.
        if near_secure {
            return Err(
                "ws-takeover-secure-offerer: a WebSocket takeover on a secure (SRTP) offerer is not \
                 supported on a two-leg call — the engine is not that leg's cryptographic far side, \
                 so the bridge would receive ciphertext and answer in the clear; negotiate the \
                 takeover with answer_local instead"
                    .to_string(),
            );
        }
        if has_ice {
            return Err(
                "ws-takeover-ice-offerer: a WebSocket takeover on an ICE leg is not supported here — \
                 no ICE agent is armed for a takeover leg on a two-leg call, so its downlink would \
                 never follow the selected pair; negotiate the takeover with answer_local, or \
                 ICE=remove to drop ICE"
                    .to_string(),
            );
        }
        // Checked before the pipeline kind, because each of these *promotes* a plain relay into the
        // media pipeline: reporting the promotion ("this call is Media") would name the symptom,
        // where naming the feature tells the controller what to stop.
        if self.ws_tees.contains_key(call_id)
            || self.x3_sessions.contains_key(call_id)
            || self.call_has_userspace_hold(call_id)
        {
            return Err(
                "ws-takeover-call-is-held: a recording, SIPREC subscription, WebSocket tee, DTMF \
                 block or lawful-interception delivery is attached to this call and taps the media \
                 path a takeover removes; stop it first"
                    .to_string(),
            );
        }
        if pipeline != PipelineKind::Passthrough || self.media.is_media_call(call_id) {
            return Err(format!(
                "ws-takeover-not-a-plain-relay: only a plain two-party relay can be taken over at \
                 runtime, and this call is {pipeline:?} — a transcoding, secure-bridge or promoted \
                 call's media path cannot be handed back verbatim on detach"
            ));
        }
        if relay_flows.is_empty() {
            return Err(
                "ws-takeover-not-answered: the call has no two-party relay to take over (it is \
                 unanswered, or was answered locally, so there is no second party a detach could \
                 hand it back to); negotiate the takeover with ws_uri instead"
                    .to_string(),
            );
        }
        let Some(codec) = near_codec else {
            return Err("the call has no negotiated codec on the offerer's leg".to_string());
        };
        let Some(signalled) = near.remote_rtp else {
            return Err(
                "the offerer's leg has no signalled address to send the downlink to".to_string(),
            );
        };

        // Where the bridge's downlink goes. The relay this is taking over may have latched leg A's
        // *observed* source (symmetric RTP, docs/security-and-nat.md §4 layer 3), which for a NATed
        // caller is routinely not the port its `c=` advertised — so follow the media path the call
        // is actually using. With nothing observed yet, fall back to the same `received-from`-seeded
        // address the negotiation paths aim at rather than the raw signalled one; the bridge's own
        // latch then corrects it on leg A's first accepted packet.
        let a_rtp = self
            .datapath
            .latched_source(near.rtp.id)
            .unwrap_or_else(|| ws_takeover_media_address(signalled, received_from));
        // …and the gate stays exactly the one the negotiation installed on this endpoint, rather
        // than a fresh one derived from the signalling: `Redirect` bypasses the datapath's gate, so
        // the registry re-enforces this filter itself and it must not silently widen.
        let accepted_source = relay_flows
            .iter()
            .find_map(|(endpoint, action)| match action {
                FlowAction::Forward(rule) if *endpoint == near.rtp.id => Some(rule.accepted_source),
                _ => None,
            })
            .unwrap_or_else(|| {
                SourceFilter::Exact(ws_takeover_media_address(signalled, received_from).ip())
            });

        let takeover = WsRelayTakeover {
            // Every endpoint of the relay stops: A's because the bridge owns it, B's because there
            // is nowhere to forward B's media to while it does, and the RTCP companions because
            // relaying reports for a stream that is no longer flowing is worse than silence.
            displace: relay_flows
                .iter()
                .map(|(endpoint, _)| (*endpoint, FlowAction::Drop))
                .collect(),
            restore: relay_flows,
            restore_pipeline: pipeline,
        };
        self.setup_ws_bridge(WsBridgeSetup {
            call_id,
            ws_uri,
            endpoint_a: near.rtp.id,
            a_rtp,
            codec: Some(&codec),
            accepted_source,
            // Refused above for both shapes that would need them.
            ice_pending: false,
            secure: None,
            // A runtime attach carries no offer/answer profile, so the uplink processing knobs are
            // off. They are set on the negotiation that armed the bridge, which is where the
            // controller states them; a re-point then carries whatever that negotiation chose.
            noise_suppression: false,
            echo: crate::media_pipeline::EchoProfile::default(),
            vad_config: None,
            wire_sample_rate: None,
            egress: None,
            takeover: Some(takeover),
            // Nothing has been displaced yet — `setup_ws_bridge` dials before it installs a flow, so
            // a dial failure here leaves the relay exactly as it was.
            socket: None,
        })
        .await?;
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = PipelineKind::Ws;
        }
        Ok(())
    }

    /// Detach a call's WebSocket takeover bridge ([`Command::DetachWsBridge`]) and put the media
    /// path back.
    ///
    /// Idempotent on a call with no bridge, so a controller may call it unconditionally on hangup.
    /// On a bridge this engine created by **taking over a live relay** it reinstalls that relay's
    /// exact `Forward` rules — the ones it displaced, gate and latch policy included — and the call
    /// carries on where it left off; the datapath's latch is separate state that a flow install does
    /// not disturb, so a NATed leg keeps the path it had.
    ///
    /// On a bridge that was **negotiated** (`ProfileFlags::ws_uri`) it is refused. That bridge *is*
    /// the call's media path: nothing was displaced, and there is nothing to go back to — a two-leg
    /// negotiated takeover never wired A↔B (leg B's ports exist but its codec was never negotiated
    /// against A's), and a single-leg `answer_local` takeover has no second party at all. Answering
    /// `ok` and leaving the caller connected to nothing is the failure mode this whole verb exists
    /// to prevent, so the controller is told plainly and keeps its two working options: re-point the
    /// bridge, or `delete` the call.
    pub(super) async fn detach_ws_bridge(&self, client: ClientId, call_id: &str) -> CmdResult {
        if self.owned_call(client, call_id, |_| ()).is_none() {
            return unknown_call(call_id);
        }
        let Some(takeover) = self
            .ws_bridges
            .get(call_id)
            .map(|bridge| bridge.takeover.clone())
        else {
            // No bridge at all — including a route left behind by an engine bug, which `delete` will
            // clean up. Idempotent, like `detach_ws_tee`.
            return ok_empty();
        };
        let Some(takeover) = takeover else {
            return error_result(
                "detach_ws_bridge",
                &"ws-bridge-negotiated: this bridge is the call's negotiated media path (ws_uri), \
                  not a takeover of a relay, so there is no media path to return it to; re-point it \
                  with attach_ws_bridge, or end the call with delete",
            );
        };
        self.stop_ws_bridge(call_id, WsBridgeEndReason::Detached)
            .await;
        // Put the relay back exactly as it was. A failure here leaves the call with no audio path,
        // which the controller must hear about — it is the one outcome worse than refusing.
        if let Err(reason) = self.restore_displaced_relay(&takeover) {
            return error_result("detach_ws_bridge: restore relay flow", &reason);
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pipeline = takeover.restore_pipeline;
        }
        tracing::info!(
            target: "siphon_rtp::media",
            call_id,
            "ws bridge detached; the displaced relay is back"
        );
        ok_empty()
    }

    /// Tear a call's takeover bridge down: drop its route, abort **and await** the bridge + drain
    /// tasks, and emit [`Event::WsBridgeEnded`] if the bridge task has not already. A no-op when the
    /// call has no bridge.
    ///
    /// Awaiting matters here for the same reason it does for a tee — an aborted task still holds its
    /// socket until the runtime polls it — plus one this has and a tee does not: a re-point stands a
    /// replacement drain up on the same endpoint, and two drains writing to one peer would interleave
    /// two RTP sequence/timestamp series (RFC 3550 §5.1).
    ///
    /// This does **not** restore anything. Detach owns that decision (see [`Self::detach_ws_bridge`])
    /// because the other callers are call teardown, where the endpoints are being freed anyway.
    pub(super) async fn stop_ws_bridge(&self, call_id: &str, reason: WsBridgeEndReason) {
        let Some((_, bridge)) = self.ws_bridges.remove(call_id) else {
            return;
        };
        // Claim the end latch with the caller's reason **before** the route is dropped. Dropping it
        // closes the bridge's `rtp_in` channel, which the bridge task reads as the call going away —
        // so the two race, and the task would win often enough to report a controller's detach or a
        // re-point as `call_ended`. The reason a caller states is authoritative; the task's own is
        // for the ends nobody asked for.
        let events = self
            .events
            .get(&bridge.owner)
            .map(|sink| sink.value().clone());
        emit_ws_bridge_ended(
            events.as_ref(),
            &bridge.ended,
            call_id,
            &bridge.from_tag,
            &bridge.stream_id,
            reason,
        );
        if let Some(tasks) = self.ws.deregister(call_id) {
            tasks.joined().await;
        }
    }
}

/// Emit a takeover bridge's [`Event::WsBridgeEnded`] **exactly once**, whichever of the bridge task
/// or a detach gets there first (`ended` is the shared latch they race on).
///
/// Unconditionally logged, and at WARN for anything the controller did not ask for: a takeover
/// bridge is leg A's only far side, so the server closing it, stopping it or failing its transport
/// leaves a live call with no audio path. A node with no event consumer registered must still leave
/// a trace of that in its own logs.
fn emit_ws_bridge_ended(
    events: Option<&flume::Sender<Event>>,
    ended: &std::sync::atomic::AtomicBool,
    call_id: &str,
    from_tag: &str,
    stream_id: &str,
    reason: WsBridgeEndReason,
) {
    use std::sync::atomic::Ordering;
    if ended.swap(true, Ordering::SeqCst) {
        return; // already reported
    }
    if matches!(
        reason,
        WsBridgeEndReason::Detached | WsBridgeEndReason::CallEnded
    ) {
        tracing::info!(target: "siphon_rtp::media", call_id, stream_id, ?reason, "ws bridge ended");
    } else {
        tracing::warn!(
            target: "siphon_rtp::media",
            call_id,
            stream_id,
            ?reason,
            "ws takeover bridge ended without a detach — the call has no far side until it is \
             re-pointed or detached"
        );
    }
    if let Some(sender) = events {
        let _ = sender.try_send(Event::WsBridgeEnded {
            call_id: call_id.to_string(),
            from_tag: from_tag.to_string(),
            stream_id: stream_id.to_string(),
            reason,
        });
    }
}

/// Default mean-square energy threshold for the WS uplink VAD (8/16 kHz L16) when the profile does
/// not override it — the 8 kHz/20 ms starting point suggested by `EnergyVad`.
pub(super) const DEFAULT_WS_VAD_THRESHOLD: i64 = 1_000_000;

/// Default trailing hangover for the WS uplink VAD (~200 ms) when the profile does not override it.
pub(super) const DEFAULT_WS_VAD_HANGOVER_MS: u32 = 200;

/// Local-VAD turn-taking config for a WS voice-AI leg, resolved from [`ProfileFlags`] at offer time.
#[derive(Debug, Clone, Copy)]
pub(super) struct WsVadConfig {
    /// Which detector to run (`ws_vad_engine`); the energy gate unless the controller says otherwise.
    pub(super) engine: WsVadEngine,
    /// Mean-square energy at/above which an uplink frame is speech. Energy detector only.
    pub(super) threshold: i64,
    /// Trailing hangover in milliseconds (converted to ptime frames once the codec ptime is known).
    /// Energy detector only — the neural one holds speech with its own probability hysteresis.
    pub(super) hangover_ms: u32,
    /// Leading minimum-speech run in milliseconds before the speech-start edge fires (0 = none).
    pub(super) minimum_speech_ms: u32,
    /// Flush the downlink playout locally on a speech-start edge (barge-in).
    pub(super) barge_in: bool,
}

impl WsVadConfig {
    /// Resolve the turn-taking config from a profile, or `None` when neither VAD nor barge-in was
    /// requested. Barge-in implies VAD, so either flag turns the detector on.
    pub(super) fn from_profile(profile: &ProfileFlags) -> Option<Self> {
        (profile.ws_vad || profile.ws_barge_in).then(|| Self {
            engine: profile.ws_vad_engine.unwrap_or_default(),
            threshold: profile.ws_vad_threshold.unwrap_or(DEFAULT_WS_VAD_THRESHOLD),
            hangover_ms: profile
                .ws_vad_hangover_ms
                .unwrap_or(DEFAULT_WS_VAD_HANGOVER_MS),
            minimum_speech_ms: profile.ws_vad_min_speech_ms.unwrap_or(0),
            barge_in: profile.ws_barge_in,
        })
    }

    /// Build the detector this config selects for a leg running at `pcm_rate_hz` with a
    /// `ptime_ms` packetization.
    ///
    /// The ptime is what turns the energy gate's hangover from the duration the controller asked
    /// for into the frame count the detector counts in. It is a parameter rather than a field
    /// because the config is resolved from the profile at offer time, before a codec — and so a
    /// ptime — has been picked.
    ///
    /// # Errors
    /// A human-readable reason the bridge could not be stood up. The neural detector is refused
    /// rather than silently downgraded to the energy one: a controller that asked for it did so to
    /// stop barge-in firing on noise, and quietly handing back the detector it was avoiding is the
    /// failure mode that costs someone an afternoon.
    pub(super) fn build_detector(
        &self,
        pcm_rate_hz: u32,
        ptime_ms: u8,
    ) -> Result<VoiceDetector, String> {
        match self.engine {
            WsVadEngine::Energy => Ok(VoiceDetector::energy(
                self.threshold,
                self.hangover_frames(ptime_ms),
            )),
            WsVadEngine::Neural => VoiceDetector::neural(pcm_rate_hz).map_err(|error| {
                format!("neural VAD unavailable for a {pcm_rate_hz} Hz leg: {error}")
            }),
        }
    }

    /// Trailing hangover in ptime frames, at least one.
    pub(super) fn hangover_frames(&self, ptime_ms: u8) -> u32 {
        (self.hangover_ms / u32::from(ptime_ms.max(1))).max(1)
    }

    /// Leading minimum-speech run in ptime frames, at least one (one == no leading requirement).
    pub(super) fn minimum_speech_frames(&self, ptime_ms: u8) -> u32 {
        self.minimum_speech_ms
            .div_ceil(u32::from(ptime_ms.max(1)))
            .max(1)
    }
}

/// Where a WebSocket-takeover leg's media is **aimed**, from the peer's signalled transport address
/// and the rtpengine `received-from` hint — the same value its ingress gate keys on.
///
/// One address for both, deliberately. The hint is the real post-NAT source the SIP proxy saw the
/// request arrive from, so pairing it with the signalled media port is a better opening guess than
/// the `c=` address itself, which for a NATed UA is an RFC 1918 address it never receives on
/// (docs/security-and-nat.md §4 layer 2). A relay leg can afford to aim at the signalled address and
/// be corrected by the symmetric-RTP latch on the peer's first accepted packet; a takeover leg has no
/// reverse relay direction, so nothing in the datapath ever corrects it and a wrong seed misaddresses
/// the whole call rather than just its opening window.
///
/// Same bound as everywhere else the hint aims a destination: behind a symmetric NAT the public media
/// port need not be the signalled one, so this is a better guess, never a guarantee and never a
/// substitute for the latch that follows it.
pub(super) fn ws_takeover_media_address(
    signalled: std::net::SocketAddr,
    received_from: Option<std::net::IpAddr>,
) -> std::net::SocketAddr {
    apply_received_from(Some(signalled), received_from).unwrap_or(signalled)
}
