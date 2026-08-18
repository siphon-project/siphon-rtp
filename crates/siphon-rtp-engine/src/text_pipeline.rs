//! Userspace processor for an RFC 4103 Real-Time Text (`m=text`) stream.
//!
//! PR 1 relays a plaintext text stream entirely in-kernel (a per-stream `Forward` flow with its own
//! RTPBleed source-gate + symmetric latch). When a text-observability feature is active for a call
//! (recording, or `text_events`), the engine promotes **only** the low-rate text endpoints to this
//! userspace processor (the audio relay/transcode/SRTP path is never promoted for text — that is the
//! maintainer's hard constraint). This processor, per direction:
//!
//! 1. enforces the *same* RTPBleed source-gate + SSRC-consistent symmetric latch the in-kernel
//!    `Forward` flow did (docs/security-and-nat.md §4 — the `Redirect` path bypasses the datapath's
//!    Forward-path gate, so it is re-enforced here);
//! 2. for a **secure** (SDES-SRTP, `RTP/SAVP`) text leg, decrypts the ingress SRTP packet **first**
//!    (fail-closed: a packet that fails auth/replay is dropped, never forwarded), so everything below
//!    operates on plaintext (RFC 3711; docs/security-and-nat.md Layer 5d) — this is what a secure text
//!    stream runs on *from the start* (SRTP cannot relay in-kernel, so it is never on the `Forward`
//!    fast path);
//! 3. RED-depacketizes (RFC 2198) + reassembles the T.140 stream ([`siphon_rtp_media::t140`]),
//!    accruing per-leg content QoS ([`TextStreamStats`]: packets / characters / unrecoverable
//!    missing-text markers / redundancy-recovered generations) for the end-of-call CDR / `CallSummary`;
//! 4. emits [`Event::Text`] to the control plane for each newly-recovered, non-empty UTF-8 increment;
//! 5. folds the raw (on-the-wire) text RTP into the recording (the same pcap capture sink the audio
//!    recorder uses — ciphertext on a secure leg, matching the audio pcap recorder);
//! 6. forwards the text RTP to the peer text endpoint — verbatim for a plaintext relay, or **re-encrypted
//!    with the peer leg's own key** for a secure↔secure bridge (RFC 4103 relay: observe, don't transform;
//!    the sender's sequence/timestamp/1000 Hz clock pass through untouched). A secure↔insecure text bridge
//!    is never keyed here — the `secure_ingress`/`secure_egress` pairing is fixed at negotiation, which
//!    refuses a mixed case rather than leak.
//!
//! It mirrors [`crate::media_pipeline::MediaRegistry`]'s "registry + dispatcher" shape so the single
//! redirect dispatcher routes text-owned endpoints here by [`EndpointId`]. Deterministic and NIC-free
//! (fed [`RxPacket`]s off the datapath); no per-packet heap beyond the copies the verbatim forward and
//! the (best-effort) event/capture already require.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use dashmap::DashMap;
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket, SourceFilter};
use siphon_rtp_media::pcap::CapturedPacket;
use siphon_rtp_media::rtp::RtpPacket;
use siphon_rtp_media::t140::T140Reassembler;
use siphon_rtp_proto::{Event, TextStreamStats};
use siphon_rtp_srtp::leg::SecureLeg;

use crate::media_pipeline::{rtp_source_ssrc, Outbound, PcapCapture, SymmetricLatch};

/// One direction of the text relay: the sending party's ingress text endpoint (+ its RTPBleed gate and
/// symmetric latch), the peer's egress text endpoint/address, and the RFC 4103 reassembler + content
/// QoS for the stream this party sends.
struct TextDirection {
    /// The endpoint text datagrams arrive on for this direction (the sending party's engine socket).
    ingress_endpoint: EndpointId,
    /// Signalled-source gate for the sending party (RTPBleed defence on the `Redirect` path — the
    /// same gate the in-kernel `Forward` rule carried; docs/security-and-nat.md §4 layer 2).
    accepted_source: SourceFilter,
    /// SSRC-consistent symmetric latch for this ingress stream; an accepted, SSRC-consistent packet
    /// re-points the *reverse* direction's `egress_dst` to the observed source (RFC 3550 §8, layer 3).
    source_latch: SymmetricLatch,
    /// The endpoint to transmit from (the receiving party's engine socket).
    egress_endpoint: EndpointId,
    /// Where to transmit (the receiving party's text address; latched to its observed source).
    egress_dst: SocketAddr,
    /// RFC 4103 T.140 reassembler, recovering RED redundancy losses and marking unrecoverable gaps.
    reassembler: T140Reassembler,
    /// The negotiated RFC 4103 T.140 payload type — a packet on it is bare (redundancy-free) T.140.
    t140_payload_type: Option<u8>,
    /// The negotiated RFC 2198 RED payload type — a packet on it is RED-wrapped T.140.
    red_payload_type: Option<u8>,
    /// The tag of the party that **sends** on this direction (the [`Event::Text`] `from_tag`).
    sender_tag: String,
    /// The receiving party's tag (the [`Event::Text`] `to_tag`).
    receiver_tag: Option<String>,
    /// `"a_to_b"` or `"b_to_a"` — the observed direction, carried on [`Event::Text`].
    direction_label: &'static str,
    /// Accrued content QoS for the CDR / `CallSummary`.
    counters: TextStreamStats,
    /// Secure (SDES-SRTP) ingress: when the *sending* party's text leg is `RTP/SAVP`, this is the
    /// **sending leg's** [`SecureLeg`] — the ingress datagram is decrypted (fail-closed on auth/replay)
    /// before it is observed or forwarded, exactly as the audio SDES leg decrypts before the tee/relay
    /// (RFC 3711; docs/security-and-nat.md Layer 5d). `None` for a plaintext text stream. The `Mutex`
    /// is uncontended in practice — the single owner is this call's actor — and never held across an
    /// `.await` (all crypto happens inside the synchronous [`TextCall::process`]).
    secure_ingress: Option<Arc<Mutex<SecureLeg>>>,
    /// Secure (SDES-SRTP) egress: when the *receiving* party's text leg is `RTP/SAVP`, this is the
    /// **receiving leg's** [`SecureLeg`] — the (decrypted) T.140 RTP is re-encrypted with that leg's own
    /// key before transmit, so a secure↔secure text bridge re-keys per leg. `None` for a plaintext peer.
    /// Invariant: `secure_ingress` and `secure_egress` are set together (a secure text bridge is
    /// secure↔secure) — a mixed secure/plaintext text bridge is refused at negotiation, never keyed here.
    secure_egress: Option<Arc<Mutex<SecureLeg>>>,
}

impl TextDirection {
    /// Observe an accepted text datagram: RED-depacketize + reassemble to surface [`Event::Text`] and
    /// accrue content QoS. Only a recognized T.140 / RED payload type is decoded; anything else (RTCP
    /// on a muxed text port, an unknown PT) was already forwarded verbatim by the caller and is not
    /// reassembled. A malformed RED payload never panics — it is logged and skipped (the verbatim
    /// relay to the peer already happened).
    fn observe(&mut self, data: &[u8], call_id: &str, events: &mut Vec<Event>) {
        let Ok(parsed) = RtpPacket::parse(data) else {
            return; // malformed RTP header — relayed verbatim, but nothing to reassemble
        };
        // Decide RED vs bare T.140 by the negotiated payload types (RFC 4103 §4 / RFC 2198).
        let is_red = if self.red_payload_type == Some(parsed.payload_type) {
            true
        } else if self.t140_payload_type == Some(parsed.payload_type) {
            false
        } else {
            return; // not a text payload type (RTCP / other) — no content to observe
        };
        self.counters.packets += 1;
        match self
            .reassembler
            .on_packet(parsed.sequence, parsed.timestamp, parsed.payload, is_red)
        {
            Ok(output) => {
                // `characters` counts what the receiver actually gets, including recovered generations
                // and the U+FFFD markers (so a consumer can see where loss occurred).
                self.counters.characters += output.text.chars().count() as u64;
                self.counters.missing_markers += output.missing_markers as u64;
                self.counters.recovered_from_redundancy += output.recovered_from_redundancy as u64;
                // Emit only a non-empty increment: a duplicate/reordered packet, an idle keepalive, or
                // an incomplete split character yields empty text and must not spam the control plane.
                if !output.text.is_empty() {
                    events.push(Event::Text {
                        call_id: call_id.to_string(),
                        from_tag: self.sender_tag.clone(),
                        to_tag: self.receiver_tag.clone(),
                        text: output.text.to_string(),
                        direction: Some(self.direction_label.to_string()),
                    });
                }
            }
            Err(error) => {
                // A hostile / malformed RED payload off the network: decode-or-error, never panic. The
                // verbatim relay already forwarded the bytes to the peer; we skip the observe increment.
                tracing::debug!(
                    target: "siphon_rtp::text",
                    %error,
                    "RED depacketization failed; text observe increment skipped"
                );
            }
        }
    }
}

/// Per-direction wiring for [`TextCall::new`] — the transport-only bits (endpoints, gate, PTs). The
/// per-leg tags and direction label are assigned by [`TextCall::new`] from the call identity.
pub struct TextDirectionConfig {
    /// The endpoint the sending party's text arrives on.
    pub ingress_endpoint: EndpointId,
    /// The RTPBleed source gate for the sending party (reconstructed from the in-kernel `Forward` rule).
    pub accepted_source: SourceFilter,
    /// The endpoint to forward verbatim from (the receiving party's engine socket).
    pub egress_endpoint: EndpointId,
    /// Where to forward (the receiving party's signalled text address).
    pub egress_dst: SocketAddr,
    /// The negotiated RFC 4103 T.140 payload type, if any.
    pub t140_payload_type: Option<u8>,
    /// The negotiated RFC 2198 RED payload type, if any.
    pub red_payload_type: Option<u8>,
    /// The sending leg's [`SecureLeg`] when this direction's ingress is SDES-SRTP — decrypts ingress
    /// (fail-closed on auth/replay) before it is observed or forwarded. `None` for a plaintext text
    /// stream.
    pub secure_ingress: Option<Arc<Mutex<SecureLeg>>>,
    /// The receiving leg's [`SecureLeg`] when the peer's text leg is SDES-SRTP — re-encrypts egress with
    /// the peer leg's own key (a secure↔secure re-key). `None` for a plaintext peer. Set together with
    /// `secure_ingress` — a secure text bridge is secure↔secure; a mixed case is refused at negotiation.
    pub secure_egress: Option<Arc<Mutex<SecureLeg>>>,
}

/// A promoted RFC 4103 text stream running in userspace: two directions (A→B and B→A) plus the
/// optional recording capture sink and the shared symmetric-latch policy.
pub struct TextCall {
    call_id: String,
    /// A→B: party A sends (ingress = near text endpoint), forwarded to B's text endpoint.
    a_to_b: TextDirection,
    /// B→A: party B sends (ingress = far text endpoint), forwarded to A's text endpoint.
    b_to_a: TextDirection,
    /// Whether an accepted, SSRC-consistent packet re-points the reverse egress (symmetric latch).
    latch: bool,
    /// Active raw-RTP pcap capture (recording): each accepted text datagram is copied byte-for-byte to
    /// this sink — the *same* mechanism and sink the audio recorder uses (`a_local`/`b_local` are the
    /// text endpoints' engine-local addresses). `None` unless recording.
    capture: Option<PcapCapture>,
}

impl TextCall {
    /// Build a text call from its two directions and the call identity. `from_tag` is party A
    /// (offerer), `to_tag` party B (answerer): A→B text is `from`→`to`, B→A is `to`→`from`.
    #[must_use]
    pub fn new(
        call_id: impl Into<String>,
        from_tag: impl Into<String>,
        to_tag: Option<String>,
        a_to_b: TextDirectionConfig,
        b_to_a: TextDirectionConfig,
        latch: bool,
    ) -> Self {
        let from_tag = from_tag.into();
        Self {
            call_id: call_id.into(),
            a_to_b: TextDirection {
                ingress_endpoint: a_to_b.ingress_endpoint,
                accepted_source: a_to_b.accepted_source,
                source_latch: SymmetricLatch::default(),
                egress_endpoint: a_to_b.egress_endpoint,
                egress_dst: a_to_b.egress_dst,
                reassembler: T140Reassembler::new(),
                t140_payload_type: a_to_b.t140_payload_type,
                red_payload_type: a_to_b.red_payload_type,
                sender_tag: from_tag.clone(),
                receiver_tag: to_tag.clone(),
                direction_label: "a_to_b",
                counters: TextStreamStats::default(),
                secure_ingress: a_to_b.secure_ingress,
                secure_egress: a_to_b.secure_egress,
            },
            b_to_a: TextDirection {
                ingress_endpoint: b_to_a.ingress_endpoint,
                accepted_source: b_to_a.accepted_source,
                source_latch: SymmetricLatch::default(),
                egress_endpoint: b_to_a.egress_endpoint,
                egress_dst: b_to_a.egress_dst,
                reassembler: T140Reassembler::new(),
                t140_payload_type: b_to_a.t140_payload_type,
                red_payload_type: b_to_a.red_payload_type,
                // The B→A sender is party B (`to_tag`); the receiver is party A (`from_tag`).
                sender_tag: to_tag.unwrap_or_else(|| "-".to_string()),
                receiver_tag: Some(from_tag),
                direction_label: "b_to_a",
                counters: TextStreamStats::default(),
                secure_ingress: b_to_a.secure_ingress,
                secure_egress: b_to_a.secure_egress,
            },
            latch,
            capture: None,
        }
    }

    /// The two ingress endpoints this call routes (the dispatcher's routing table entries).
    #[must_use]
    pub fn endpoints(&self) -> [EndpointId; 2] {
        [self.a_to_b.ingress_endpoint, self.b_to_a.ingress_endpoint]
    }

    /// Enable/disable the raw-RTP pcap capture (recording start/stop).
    fn set_capture(&mut self, capture: Option<PcapCapture>) {
        self.capture = capture;
    }

    /// The per-leg content QoS for the CDR: the near (A) leg's inbound text is the A→B reassembler; the
    /// far (B) leg's is the B→A reassembler (mirrors the audio CDR's a_to_b/b_to_a attribution).
    #[must_use]
    fn final_counters(&self) -> TextFinalCounters {
        TextFinalCounters {
            near: self.a_to_b.counters,
            far: self.b_to_a.counters,
        }
    }

    /// Process one redirected text datagram: enforce the source gate, forward it verbatim to the peer,
    /// observe it (Event::Text + QoS), capture it (recording), and drive the symmetric latch. Returns
    /// `true` when the packet was accepted (so the actor stamps datapath activity for the timeout
    /// sweep), `false` when the source gate dropped it or it was for an unowned endpoint.
    pub fn process(
        &mut self,
        packet: &RxPacket,
        out: &mut Vec<Outbound>,
        events: &mut Vec<Event>,
    ) -> bool {
        let from_a = if packet.endpoint == self.a_to_b.ingress_endpoint {
            true
        } else if packet.endpoint == self.b_to_a.ingress_endpoint {
            false
        } else {
            return false;
        };

        // Disjoint field borrows: the sending direction, the reverse (for the latch), and the capture
        // sink are separate fields, so destructuring hands them out without a lock or an `Arc<Mutex>`.
        let TextCall {
            call_id,
            a_to_b,
            b_to_a,
            latch,
            capture,
        } = self;
        let (direction, reverse) = if from_a {
            (a_to_b, b_to_a)
        } else {
            (b_to_a, a_to_b)
        };

        // RTPBleed source gate (docs/security-and-nat.md §4 layer 2): drop a packet from a source the
        // SDP never signalled — the `Redirect` path bypasses the datapath's Forward-path gate, so the
        // exact same gate is re-enforced here, per-stream.
        if !direction.accepted_source.accepts(packet.source.ip()) {
            tracing::debug!(
                target: "siphon_rtp::text",
                source = %packet.source,
                "text-pipeline dropped packet from unsignalled source"
            );
            return false;
        }

        // Recording: copy the accepted text RTP byte-for-byte to the shared pcap sink (RFC 7866-style
        // raw tee), post source-gate, before any decrypt/forward — the same capture the audio recorder
        // (`MediaCall::capture_ingress`) drains to `{call}.pcap`, keyed on the text endpoint's
        // engine-local address. On a secure leg this records the on-the-wire **ciphertext** (the SRTP
        // packet), matching the audio pcap recorder, which also captures pre-decrypt.
        if let Some(capture) = capture.as_ref() {
            let destination = if from_a {
                capture.a_local
            } else {
                capture.b_local
            };
            let captured = CapturedPacket::new(
                packet.source,
                destination,
                Bytes::copy_from_slice(&packet.data),
                packet.arrival,
            );
            if capture.sender.try_send(captured).is_err() {
                tracing::debug!(
                    target: "siphon_rtp::text",
                    "text-pipeline pcap capture dropped a packet (sink full or closed)"
                );
            }
        }

        // Secure (SDES-SRTP) ingress: decrypt before anything observes or forwards it, so the RED/T.140
        // reassembler, the peer forward, and the latch all operate on plaintext (RFC 3711;
        // docs/security-and-nat.md Layer 5d). `SecureLeg` auto-demuxes SRTP vs SRTCP. A failed unprotect
        // (bad auth / replay / wrong key) is **fail-closed**: drop the datagram — never forward garbage
        // to the peer, never observe it, never move the latch — but keep the path alive (the source is
        // the authentic, signalled one; a transient reorder/rekey must not reap a live text call),
        // mirroring the audio SDES leg (`MediaCall::process`).
        let mut decrypted = Vec::new();
        let plaintext: &[u8] = if let Some(leg) = direction.secure_ingress.as_ref() {
            let Ok(mut guard) = leg.lock() else {
                tracing::error!(
                    target: "siphon_rtp::text",
                    "secure text ingress leg mutex poisoned; dropping packet"
                );
                return true;
            };
            if guard.unprotect(&packet.data, &mut decrypted).is_err() {
                drop(guard);
                tracing::debug!(
                    target: "siphon_rtp::text",
                    source = %packet.source,
                    "secure text ingress failed SRTP auth/replay; dropped (never forwarded)"
                );
                return true;
            }
            drop(guard);
            &decrypted
        } else {
            &packet.data
        };

        // Egress toward the peer text endpoint: encrypt with the *receiving* leg's own key when that
        // side is secure (a secure↔secure text bridge re-keys per leg), else forward the plaintext
        // verbatim (RFC 4103 transparent relay — observe, don't transform; the 1000 Hz clock passes
        // through). Never forward plaintext to a secure peer, never forward decrypted media to an
        // insecure peer: the `secure_egress`/`secure_ingress` pairing (both set, or both unset) is fixed
        // at negotiation, so this branch can only encrypt-for-secure or relay-plaintext — a mixed bridge
        // is refused before it is keyed. A failed protect drops the datagram (fail-closed).
        let mut encrypted = Vec::new();
        let wire: &[u8] = if let Some(leg) = direction.secure_egress.as_ref() {
            let Ok(mut guard) = leg.lock() else {
                tracing::error!(
                    target: "siphon_rtp::text",
                    "secure text egress leg mutex poisoned; dropping packet"
                );
                return true;
            };
            if guard.protect(plaintext, &mut encrypted).is_err() {
                drop(guard);
                tracing::debug!(
                    target: "siphon_rtp::text",
                    "secure text egress SRTP protect failed; dropped"
                );
                return true;
            }
            drop(guard);
            &encrypted
        } else {
            plaintext
        };
        out.push(Outbound {
            endpoint: direction.egress_endpoint,
            dst: direction.egress_dst,
            data: Bytes::copy_from_slice(wire),
        });

        // Observe on the DECRYPTED plaintext: RED-parse + T.140 reassemble → Event::Text + content QoS.
        // (Event::Text, the CDR counters, and the recording all see cleartext text — observe after
        // decrypt, before encrypt.)
        direction.observe(plaintext, call_id, events);

        // Symmetric-RTP latch (docs/security-and-nat.md §4 layer 3; RFC 3550 §8): only an authentic,
        // SSRC-consistent packet re-points the reverse direction's egress to the observed source — for a
        // secure leg that means *after* SRTP auth succeeded (a forged packet returned above), so a
        // spoofed source can never move the latch. RTCP / non-RTP yields `None` and never moves it.
        if *latch {
            if let Some(ssrc) = rtp_source_ssrc(plaintext) {
                if let Some(new_dst) = direction.source_latch.observe(packet.source, ssrc) {
                    reverse.egress_dst = new_dst;
                }
            }
        }
        true
    }
}

/// The per-leg content QoS snapshot returned to the engine's end-of-call CDR path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TextFinalCounters {
    /// The near (offerer, A) leg's inbound text stream (the A→B reassembler).
    pub near: TextStreamStats,
    /// The far (answerer, B) leg's inbound text stream (the B→A reassembler).
    pub far: TextStreamStats,
}

/// A control op or a redirected datagram delivered to a text-call actor.
enum TextInput {
    Packet(RxPacket),
    Control(TextControl),
}

/// Control ops sent to a running text-call actor over its mailbox.
pub enum TextControl {
    /// Begin raw-RTP recording of the text stream into the shared pcap sink.
    StartRecording { capture: PcapCapture },
    /// Stop raw-RTP recording (the text stream keeps relaying + observing if `text_events` holds it).
    StopRecording,
    /// Read-only snapshot of the per-leg content QoS for the end-of-call CDR; the actor keeps running.
    Report {
        reply: tokio::sync::oneshot::Sender<TextFinalCounters>,
    },
    /// Stop the actor.
    Stop,
}

/// The registry + dispatcher for promoted text streams — one entry per call, routed by [`EndpointId`]
/// off the single redirect dispatcher, mirroring [`crate::media_pipeline::MediaRegistry`].
#[derive(Default)]
pub struct TextRegistry {
    /// Text endpoint → the owning text-call actor's mailbox (the dispatcher's routing table).
    routes: DashMap<EndpointId, flume::Sender<TextInput>>,
    /// Call-id → control handle (mailbox + endpoints), for control verbs and teardown.
    calls: DashMap<String, TextCallHandle>,
}

/// A handle to a running text-call actor.
struct TextCallHandle {
    mailbox: flume::Sender<TextInput>,
    endpoints: [EndpointId; 2],
    task: tokio::task::JoinHandle<()>,
}

impl TextRegistry {
    /// Whether this registry routes datagrams for `endpoint` (the dispatcher's predicate).
    #[must_use]
    pub fn owns(&self, endpoint: EndpointId) -> bool {
        self.routes.contains_key(&endpoint)
    }

    /// Whether `call_id` has a promoted text stream in this registry.
    #[must_use]
    pub fn is_text_call(&self, call_id: &str) -> bool {
        self.calls.contains_key(call_id)
    }

    /// Route a redirected text datagram to its owning actor (drop on a full/closed mailbox — late text
    /// is worthless, and a bounded mailbox never lets a spray OOM the box).
    pub fn dispatch(&self, packet: RxPacket) {
        if let Some(mailbox) = self.routes.get(&packet.endpoint) {
            if mailbox.try_send(TextInput::Packet(packet)).is_err() {
                tracing::trace!(
                    target: "siphon_rtp::text",
                    "text-call mailbox full or closed; dropping redirected datagram"
                );
            }
        }
    }

    /// Register a built [`TextCall`] and spawn its actor over `datapath`, with `events` as the owner's
    /// async event sink (Event::Text flows there). Returns once the actor is spawned.
    pub fn register<D>(&self, call: TextCall, datapath: D, events: Option<flume::Sender<Event>>)
    where
        D: Datapath + Clone + Send + 'static,
    {
        let call_id = call.call_id.clone();
        let endpoints = call.endpoints();
        let (mailbox, inbox) = flume::bounded(256);
        for endpoint in endpoints {
            self.routes.insert(endpoint, mailbox.clone());
        }
        let task = tokio::spawn(run_text_call(call, inbox, datapath, events));
        self.calls.insert(
            call_id,
            TextCallHandle {
                mailbox,
                endpoints,
                task,
            },
        );
    }

    /// Send a control op to a call's text actor, returning `false` if there is no such text call.
    pub fn control(&self, call_id: &str, control: TextControl) -> bool {
        match self.calls.get(call_id) {
            Some(handle) => handle.mailbox.try_send(TextInput::Control(control)).is_ok(),
            None => false,
        }
    }

    /// Snapshot a live text call's per-leg content QoS for the CDR, by asking its actor. `None` if the
    /// call has no promoted text stream, its mailbox is closed, or the actor does not answer within
    /// `timeout` (teardown must never stall on a slow actor — the CDR then carries no text QoS).
    pub async fn final_counters(
        &self,
        call_id: &str,
        timeout: std::time::Duration,
    ) -> Option<TextFinalCounters> {
        let mailbox = self.calls.get(call_id)?.mailbox.clone();
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if mailbox
            .try_send(TextInput::Control(TextControl::Report { reply: reply_tx }))
            .is_err()
        {
            return None;
        }
        tokio::time::timeout(timeout, reply_rx).await.ok()?.ok()
    }

    /// Tear a text call's actor down: stop it, drop its routes, and abort the task.
    pub fn deregister(&self, call_id: &str) {
        if let Some((_, handle)) = self.calls.remove(call_id) {
            let _ = handle
                .mailbox
                .try_send(TextInput::Control(TextControl::Stop));
            for endpoint in handle.endpoints {
                self.routes.remove(&endpoint);
            }
            handle.task.abort();
        }
    }
}

/// The async actor for one promoted text stream: drain its mailbox, run [`TextCall::process`], perform
/// the datapath I/O + event emission. Exits on `Stop`, mailbox close, or task abort. No periodic tick —
/// the text relay synthesizes no egress (it forwards verbatim), so it does no work between packets.
async fn run_text_call<D>(
    mut call: TextCall,
    inbox: flume::Receiver<TextInput>,
    datapath: D,
    events: Option<flume::Sender<Event>>,
) where
    D: Datapath,
{
    let mut outbound = Vec::new();
    let mut emitted = Vec::new();
    while let Ok(input) = inbox.recv_async().await {
        match input {
            TextInput::Packet(packet) => {
                outbound.clear();
                emitted.clear();
                // Stamp media activity only when the packet passed the source gate (a spoofed spray
                // must not keep an idle path alive) — the `Redirect` arm never touches the datapath's
                // `last_seen`, so without this a live text-only call could be reaped mid-conversation.
                if call.process(&packet, &mut outbound, &mut emitted) {
                    datapath.note_activity(packet.endpoint);
                }
                for out in outbound.drain(..) {
                    if let Err(error) = datapath.send(out.endpoint, out.dst, &out.data).await {
                        tracing::debug!(
                            target: "siphon_rtp::text",
                            %error,
                            "text-pipeline forward send failed"
                        );
                    }
                }
                emit_events(&mut emitted, &events);
            }
            TextInput::Control(TextControl::StartRecording { capture }) => {
                call.set_capture(Some(capture));
            }
            TextInput::Control(TextControl::StopRecording) => call.set_capture(None),
            TextInput::Control(TextControl::Report { reply }) => {
                let _ = reply.send(call.final_counters());
            }
            TextInput::Control(TextControl::Stop) => break,
        }
    }
}

/// Push every queued control event to the owner's per-client sink, draining the buffer. A full/closed
/// sink drops the event (best-effort, never blocks the actor) — the same posture the DTMF path takes.
fn emit_events(emitted: &mut Vec<Event>, sink: &Option<flume::Sender<Event>>) {
    for event in emitted.drain(..) {
        if let Some(sink) = sink {
            if sink.try_send(event).is_err() {
                tracing::debug!(
                    target: "siphon_rtp::text",
                    "text-pipeline event dropped (sink full or closed)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_media::t140::{RedBuilder, RedGeneration};

    const A_ADDR: &str = "127.0.0.2:6000";
    const B_ADDR: &str = "127.0.0.3:6000";
    const NEAR_TEXT: u64 = 10; // engine endpoint facing A
    const FAR_TEXT: u64 = 20; // engine endpoint facing B
    const T140_PT: u8 = 98;
    const RED_PT: u8 = 99;

    fn addr(value: &str) -> SocketAddr {
        value.parse().expect("addr")
    }

    /// Build an RTP/RED text packet: header (PT = RED) + a RED body carrying `primary` at `primary_ts`
    /// plus oldest-first `(rtp_timestamp, data)` redundant generations, all on the t140 PT.
    fn red_rtp(
        sequence: u16,
        timestamp: u32,
        primary: &[u8],
        redundant: &[(u32, &[u8])],
    ) -> Vec<u8> {
        let generations: Vec<RedGeneration> = redundant
            .iter()
            .map(|(rtp_timestamp, data)| RedGeneration {
                payload_type: T140_PT,
                rtp_timestamp: *rtp_timestamp,
                data,
            })
            .collect();
        let builder = RedBuilder {
            primary_payload_type: T140_PT,
            primary_rtp_timestamp: timestamp,
            primary_data: primary,
            redundant: &generations,
        };
        let mut red = Vec::new();
        builder.write_into(&mut red).expect("build RED");
        rtp(RED_PT, sequence, timestamp, &red)
    }

    /// Build a minimal 12-byte RTP header (version 2, SSRC 0x0A0B0C0D) + `payload`.
    fn rtp(payload_type: u8, sequence: u16, timestamp: u32, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(12 + payload.len());
        packet.push(0x80); // V=2, no padding/extension/CSRC
        packet.push(payload_type & 0x7f);
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&timestamp.to_be_bytes());
        packet.extend_from_slice(&[0x0A, 0x0B, 0x0C, 0x0D]); // SSRC
        packet.extend_from_slice(payload);
        packet
    }

    fn rx(endpoint: u64, source: &str, data: Vec<u8>) -> RxPacket {
        RxPacket {
            endpoint: EndpointId(endpoint),
            source: addr(source),
            arrival: 0,
            data: Bytes::from(data),
        }
    }

    /// A text call gated to A on near.text and B on far.text, latching off (exact-source default).
    fn text_call() -> TextCall {
        let a_to_b = TextDirectionConfig {
            ingress_endpoint: EndpointId(NEAR_TEXT),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: EndpointId(FAR_TEXT),
            egress_dst: addr(B_ADDR),
            t140_payload_type: Some(T140_PT),
            red_payload_type: Some(RED_PT),
            secure_ingress: None,
            secure_egress: None,
        };
        let b_to_a = TextDirectionConfig {
            ingress_endpoint: EndpointId(FAR_TEXT),
            accepted_source: SourceFilter::Exact(addr(B_ADDR).ip()),
            egress_endpoint: EndpointId(NEAR_TEXT),
            egress_dst: addr(A_ADDR),
            t140_payload_type: Some(T140_PT),
            red_payload_type: Some(RED_PT),
            secure_ingress: None,
            secure_egress: None,
        };
        TextCall::new(
            "call-1",
            "ft-a",
            Some("tt-b".to_string()),
            a_to_b,
            b_to_a,
            false,
        )
    }

    #[test]
    fn red_text_packet_reassembles_emits_event_and_forwards_verbatim() {
        let mut call = text_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        let packet = red_rtp(1, 1000, b"Hi", &[]);
        assert!(call.process(
            &rx(NEAR_TEXT, A_ADDR, packet.clone()),
            &mut out,
            &mut events
        ));

        // Event::Text carries the recovered increment, the sender (A) tag, and the a_to_b direction.
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Text {
                call_id,
                from_tag,
                to_tag,
                text,
                direction,
            } => {
                assert_eq!(call_id, "call-1");
                assert_eq!(from_tag, "ft-a");
                assert_eq!(to_tag.as_deref(), Some("tt-b"));
                assert_eq!(text, "Hi");
                assert_eq!(direction.as_deref(), Some("a_to_b"));
            }
            other => panic!("expected Event::Text, got {other:?}"),
        }

        // The text RTP is forwarded verbatim to B's text endpoint (bytes untouched, RED and all).
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].endpoint, EndpointId(FAR_TEXT));
        assert_eq!(out[0].dst, addr(B_ADDR));
        assert_eq!(&out[0].data[..], &packet[..], "forwarded verbatim");
    }

    #[test]
    fn qos_counters_accrue_chars_markers_and_recovery() {
        let mut call = text_call();
        let mut out = Vec::new();
        let mut events = Vec::new();

        // seq 1 "H"; seq 2 "e" carrying "H" as redundancy; seq 3/4/5 lost; seq 6 "!" carrying gens 4,5.
        call.process(
            &rx(NEAR_TEXT, A_ADDR, red_rtp(1, 1000, b"H", &[])),
            &mut out,
            &mut events,
        );
        call.process(
            &rx(NEAR_TEXT, A_ADDR, red_rtp(2, 1100, b"e", &[(1000, b"H")])),
            &mut out,
            &mut events,
        );
        // Jump to seq 6: gen 3 is unrecoverable (one U+FFFD), gens 4 ("?") + 5 (".") recovered from RED.
        let recovered = red_rtp(6, 1500, b"!", &[(1300, b"?"), (1400, b".")]);
        events.clear();
        call.process(&rx(NEAR_TEXT, A_ADDR, recovered), &mut out, &mut events);
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Text { text, .. } => assert_eq!(text, "\u{FFFD}?.!"),
            other => panic!("expected Event::Text, got {other:?}"),
        }

        let counters = call.final_counters();
        // near = A→B: 3 accepted packets (seq 1, 2, 6); "H"+"e"+"\u{FFFD}?.!" = 6 characters delivered.
        assert_eq!(counters.near.packets, 3);
        assert_eq!(counters.near.characters, 6);
        assert_eq!(counters.near.missing_markers, 1);
        assert_eq!(counters.near.recovered_from_redundancy, 2);
        // far = B→A untouched.
        assert_eq!(counters.far, TextStreamStats::default());
    }

    #[test]
    fn packet_from_unsignalled_source_is_dropped_by_the_gate() {
        let mut call = text_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // An attacker racing A's text stream from a different source IP (RTPBleed) — gate drops it.
        let accepted = call.process(
            &rx(NEAR_TEXT, "127.0.0.9:6000", red_rtp(1, 1000, b"steal", &[])),
            &mut out,
            &mut events,
        );
        assert!(!accepted, "off-source packet rejected");
        assert!(out.is_empty(), "nothing forwarded to the peer");
        assert!(events.is_empty(), "no Event::Text for a gated-out packet");
        assert_eq!(call.final_counters().near, TextStreamStats::default());
    }

    #[test]
    fn redundant_generations_do_not_double_emit_text() {
        let mut call = text_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // Each packet repeats the prior generation as redundancy; dedup means only the primary emits.
        call.process(
            &rx(NEAR_TEXT, A_ADDR, red_rtp(1, 1000, b"H", &[])),
            &mut out,
            &mut events,
        );
        events.clear();
        call.process(
            &rx(NEAR_TEXT, A_ADDR, red_rtp(2, 1100, b"e", &[(1000, b"H")])),
            &mut out,
            &mut events,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Text { text, .. } => assert_eq!(text, "e", "redundant 'H' not re-emitted"),
            other => panic!("expected Event::Text, got {other:?}"),
        }

        // A duplicate of seq 2 emits nothing (already delivered).
        events.clear();
        call.process(
            &rx(NEAR_TEXT, A_ADDR, red_rtp(2, 1100, b"e", &[(1000, b"H")])),
            &mut out,
            &mut events,
        );
        assert!(events.is_empty(), "a duplicate packet emits no Event::Text");
    }

    #[test]
    fn both_directions_reassemble_independently_with_sender_tags() {
        let mut call = text_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // A→B "Hi" and B→A "Yo": each direction has its own reassembler + sender/receiver tags.
        call.process(
            &rx(NEAR_TEXT, A_ADDR, red_rtp(1, 1000, b"Hi", &[])),
            &mut out,
            &mut events,
        );
        call.process(
            &rx(FAR_TEXT, B_ADDR, red_rtp(1, 2000, b"Yo", &[])),
            &mut out,
            &mut events,
        );
        assert_eq!(events.len(), 2);
        match &events[1] {
            Event::Text {
                from_tag,
                to_tag,
                text,
                direction,
                ..
            } => {
                assert_eq!(from_tag, "tt-b", "B is the sender on b_to_a");
                assert_eq!(to_tag.as_deref(), Some("ft-a"));
                assert_eq!(text, "Yo");
                assert_eq!(direction.as_deref(), Some("b_to_a"));
            }
            other => panic!("expected Event::Text, got {other:?}"),
        }
        let counters = call.final_counters();
        assert_eq!(counters.near.characters, 2);
        assert_eq!(counters.far.characters, 2);
    }

    #[test]
    fn idle_keepalive_and_unowned_endpoint_emit_nothing() {
        let mut call = text_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // Establish the stream, then an empty-primary RED keepalive (RFC 4103 §5.2) — forwarded, no event.
        call.process(
            &rx(NEAR_TEXT, A_ADDR, red_rtp(1, 1000, b"x", &[])),
            &mut out,
            &mut events,
        );
        out.clear();
        events.clear();
        call.process(
            &rx(NEAR_TEXT, A_ADDR, red_rtp(2, 1100, b"", &[])),
            &mut out,
            &mut events,
        );
        assert_eq!(out.len(), 1, "the keepalive still relays to the peer");
        assert!(events.is_empty(), "an idle keepalive emits no Event::Text");

        // A datagram for an endpoint this call does not own is a no-op (defensive).
        assert!(!call.process(
            &rx(999, A_ADDR, red_rtp(3, 1200, b"z", &[])),
            &mut out,
            &mut events
        ));
    }

    #[test]
    fn latch_repoints_reverse_egress_on_ssrc_consistent_source() {
        // A latching call (accept-any + symmetric): B's real source differs from the signalled dst;
        // an SSRC-consistent B packet re-points the A→B egress to B's observed source.
        let a_to_b = TextDirectionConfig {
            ingress_endpoint: EndpointId(NEAR_TEXT),
            accepted_source: SourceFilter::Any,
            egress_endpoint: EndpointId(FAR_TEXT),
            egress_dst: addr("127.0.0.3:9999"), // stale signalled dst toward B
            t140_payload_type: Some(T140_PT),
            red_payload_type: Some(RED_PT),
            secure_ingress: None,
            secure_egress: None,
        };
        let b_to_a = TextDirectionConfig {
            ingress_endpoint: EndpointId(FAR_TEXT),
            accepted_source: SourceFilter::Any,
            egress_endpoint: EndpointId(NEAR_TEXT),
            egress_dst: addr(A_ADDR),
            t140_payload_type: Some(T140_PT),
            red_payload_type: Some(RED_PT),
            secure_ingress: None,
            secure_egress: None,
        };
        let mut call = TextCall::new("c", "ft-a", Some("tt-b".to_string()), a_to_b, b_to_a, true);
        let mut out = Vec::new();
        let mut events = Vec::new();
        // B sends from its real source 127.0.0.3:6000; the latch moves A→B's egress there.
        call.process(
            &rx(FAR_TEXT, B_ADDR, red_rtp(1, 2000, b"Yo", &[])),
            &mut out,
            &mut events,
        );
        // Now A→B forwards toward B's observed source, not the stale signalled dst.
        out.clear();
        events.clear();
        call.process(
            &rx(NEAR_TEXT, A_ADDR, red_rtp(1, 1000, b"Hi", &[])),
            &mut out,
            &mut events,
        );
        assert_eq!(
            out[0].dst,
            addr(B_ADDR),
            "A->B egress latched to B's observed source"
        );
    }

    #[test]
    fn malformed_red_never_panics_and_still_relays() {
        let mut call = text_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // A RED header claiming a block longer than the payload (hostile) — reassembly errors, but the
        // packet is still forwarded verbatim and the actor never panics.
        let malformed = rtp(
            RED_PT,
            1,
            1000,
            &[0x80 | T140_PT, 0x00, 0x03, 0xFF, T140_PT],
        );
        assert!(call.process(
            &rx(NEAR_TEXT, A_ADDR, malformed.clone()),
            &mut out,
            &mut events
        ));
        assert_eq!(&out[0].data[..], &malformed[..], "still relayed verbatim");
        assert!(
            events.is_empty(),
            "no text emitted from a malformed RED payload"
        );
    }

    // ---- Secure (SDES-SRTP) text path ----------------------------------------------------------

    use siphon_rtp_srtp::leg::SecureLeg;
    use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
    use siphon_rtp_srtp::SrtpContext;

    fn key(seed: u8) -> SrtpKeyMaterial {
        SrtpKeyMaterial::from_inline_bytes(&[seed; 30]).expect("30-byte key")
    }

    /// A secure↔secure text call: the near (A) leg is keyed with `(near_local, near_remote)` and the far
    /// (B) leg with `(far_local, far_remote)`, exactly as `engine::answer` wires it. Each direction
    /// decrypts with the sending leg's `SecureLeg` and encrypts with the receiving leg's, so text is
    /// re-keyed A↔B. Returns the call plus the four keys the test's stand-in peers use.
    #[allow(clippy::type_complexity)]
    fn secure_text_call() -> (
        TextCall,
        (
            SrtpKeyMaterial,
            SrtpKeyMaterial,
            SrtpKeyMaterial,
            SrtpKeyMaterial,
        ),
    ) {
        let (near_local, near_remote) = (key(0x11), key(0x22)); // engine→A, A→engine
        let (far_local, far_remote) = (key(0x33), key(0x44)); // engine→B, B→engine
        let near_leg = Arc::new(Mutex::new(SecureLeg::new(&near_local, &near_remote)));
        let far_leg = Arc::new(Mutex::new(SecureLeg::new(&far_local, &far_remote)));
        let a_to_b = TextDirectionConfig {
            ingress_endpoint: EndpointId(NEAR_TEXT),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: EndpointId(FAR_TEXT),
            egress_dst: addr(B_ADDR),
            t140_payload_type: Some(T140_PT),
            red_payload_type: Some(RED_PT),
            secure_ingress: Some(near_leg.clone()), // decrypt A
            secure_egress: Some(far_leg.clone()),   // encrypt to B
        };
        let b_to_a = TextDirectionConfig {
            ingress_endpoint: EndpointId(FAR_TEXT),
            accepted_source: SourceFilter::Exact(addr(B_ADDR).ip()),
            egress_endpoint: EndpointId(NEAR_TEXT),
            egress_dst: addr(A_ADDR),
            t140_payload_type: Some(T140_PT),
            red_payload_type: Some(RED_PT),
            secure_ingress: Some(far_leg), // decrypt B
            secure_egress: Some(near_leg), // encrypt to A
        };
        let call = TextCall::new(
            "sec-1",
            "ft-a",
            Some("tt-b".to_string()),
            a_to_b,
            b_to_a,
            false,
        );
        (call, (near_local, near_remote, far_local, far_remote))
    }

    #[test]
    fn secure_text_decrypts_observes_reencrypts_and_forwards() {
        let (mut call, (near_local, near_remote, far_local, _far_remote)) = secure_text_call();
        let mut out = Vec::new();
        let mut events = Vec::new();

        // A builds a plaintext RED/T.140 "Hi" packet and encrypts it with its own key (A→engine).
        let plaintext = red_rtp(1, 1000, b"Hi", &[]);
        let mut a_encrypt = SrtpContext::from_key_material(&near_remote);
        let mut srtp_in = Vec::new();
        a_encrypt
            .protect(&plaintext, &mut srtp_in)
            .expect("A encrypt");

        assert!(call.process(
            &rx(NEAR_TEXT, A_ADDR, srtp_in.clone()),
            &mut out,
            &mut events
        ));

        // Event::Text carries the DECRYPTED increment (observe after decrypt).
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Text {
                text, direction, ..
            } => {
                assert_eq!(text, "Hi");
                assert_eq!(direction.as_deref(), Some("a_to_b"));
            }
            other => panic!("expected Event::Text, got {other:?}"),
        }

        // The datagram forwarded to B is SRTP (re-encrypted with the FAR leg's key), not the A-side
        // ciphertext and not plaintext — a secure↔secure bridge re-keys per leg.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].endpoint, EndpointId(FAR_TEXT));
        assert_eq!(out[0].dst, addr(B_ADDR));
        assert_ne!(
            &out[0].data[..],
            &plaintext[..],
            "not forwarded in the clear"
        );
        assert_ne!(
            &out[0].data[..],
            &srtp_in[..],
            "re-encrypted with B's key, not A's ciphertext"
        );

        // B, holding the engine's far offered key, decrypts the forwarded packet back to the original.
        let mut b_decrypt = SrtpContext::from_key_material(&far_local);
        let mut recovered = Vec::new();
        b_decrypt
            .unprotect(&out[0].data, &mut recovered)
            .expect("B decrypts the re-keyed text");
        assert_eq!(
            recovered, plaintext,
            "B recovers the exact T.140/RED bytes A sent"
        );

        // The engine never handed A's offered key onward (defence-in-depth: distinct per-leg keys).
        assert_ne!(near_local, far_local);
    }

    #[test]
    fn secure_text_failing_srtp_auth_is_dropped_not_forwarded() {
        let (mut call, _keys) = secure_text_call();
        let mut out = Vec::new();
        let mut events = Vec::new();

        // A datagram from A's signalled source but encrypted under the WRONG key (an attacker who cannot
        // key the leg, or a corrupted packet) fails the leg's SRTP auth — fail-closed: dropped, never
        // forwarded to B, never observed.
        let plaintext = red_rtp(1, 1000, b"steal", &[]);
        let mut wrong = SrtpContext::from_key_material(&key(0x99));
        let mut forged = Vec::new();
        wrong
            .protect(&plaintext, &mut forged)
            .expect("encrypt with wrong key");

        call.process(&rx(NEAR_TEXT, A_ADDR, forged), &mut out, &mut events);
        assert!(
            out.is_empty(),
            "an inauthentic SRTP packet is never forwarded to the peer"
        );
        assert!(
            events.is_empty(),
            "no Event::Text for a packet that failed SRTP auth"
        );
        assert_eq!(call.final_counters().near, TextStreamStats::default());
    }

    #[test]
    fn secure_text_off_source_packet_is_gated_before_any_crypto() {
        let (mut call, (_nl, near_remote, _fl, _fr)) = secure_text_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // A validly-keyed packet, but from an unsignalled source IP (RTPBleed): the source gate drops it
        // before any decrypt happens — the secure leg is protected by the same per-stream gate.
        let plaintext = red_rtp(1, 1000, b"Hi", &[]);
        let mut a_encrypt = SrtpContext::from_key_material(&near_remote);
        let mut srtp = Vec::new();
        a_encrypt.protect(&plaintext, &mut srtp).expect("encrypt");
        let accepted = call.process(
            &rx(NEAR_TEXT, "127.0.0.9:6000", srtp),
            &mut out,
            &mut events,
        );
        assert!(!accepted, "off-source secure packet rejected at the gate");
        assert!(out.is_empty());
        assert!(events.is_empty());
    }

    #[test]
    fn secure_text_both_directions_rekey_with_their_own_legs() {
        let (mut call, (near_local, near_remote, _far_local, far_remote)) = secure_text_call();
        let mut out = Vec::new();
        let mut events = Vec::new();

        // B→A: B encrypts with its own key; the engine decrypts on the far leg and re-encrypts on the
        // near leg, so A decrypts with the engine's near offered key.
        let plaintext = red_rtp(1, 2000, b"Yo", &[]);
        let mut b_encrypt = SrtpContext::from_key_material(&far_remote);
        let mut srtp_in = Vec::new();
        b_encrypt
            .protect(&plaintext, &mut srtp_in)
            .expect("B encrypt");
        call.process(&rx(FAR_TEXT, B_ADDR, srtp_in), &mut out, &mut events);

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].endpoint, EndpointId(NEAR_TEXT));
        assert_eq!(out[0].dst, addr(A_ADDR));
        let mut a_decrypt = SrtpContext::from_key_material(&near_local);
        let mut recovered = Vec::new();
        a_decrypt
            .unprotect(&out[0].data, &mut recovered)
            .expect("A decrypts the re-keyed B→A text");
        assert_eq!(recovered, plaintext);
        match &events[0] {
            Event::Text {
                text,
                direction,
                from_tag,
                ..
            } => {
                assert_eq!(text, "Yo");
                assert_eq!(from_tag, "tt-b");
                assert_eq!(direction.as_deref(), Some("b_to_a"));
            }
            other => panic!("expected Event::Text, got {other:?}"),
        }
        // The two legs use distinct keys in both directions (no key reuse across legs).
        assert_ne!(near_remote, far_remote);
    }

    #[tokio::test]
    async fn registry_owns_dispatches_and_reports_then_deregisters() {
        use siphon_rtp_datapath::udp::UdpLoopbackDatapath;

        let datapath = UdpLoopbackDatapath::new();
        let registry = TextRegistry::default();
        let (event_tx, event_rx) = flume::unbounded();
        registry.register(text_call(), datapath, Some(event_tx));

        assert!(registry.owns(EndpointId(NEAR_TEXT)));
        assert!(registry.owns(EndpointId(FAR_TEXT)));
        assert!(registry.is_text_call("call-1"));

        // A redirected A→B RED packet reaches the actor, which emits Event::Text on the sink.
        registry.dispatch(rx(NEAR_TEXT, A_ADDR, red_rtp(1, 1000, b"Hi", &[])));
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv_async())
            .await
            .expect("event within timeout")
            .expect("event");
        assert!(matches!(event, Event::Text { ref text, .. } if text == "Hi"));

        // The per-leg content QoS is reported for the CDR.
        let counters = registry
            .final_counters("call-1", std::time::Duration::from_secs(1))
            .await
            .expect("counters");
        assert_eq!(counters.near.packets, 1);
        assert_eq!(counters.near.characters, 2);

        registry.deregister("call-1");
        assert!(!registry.owns(EndpointId(NEAR_TEXT)));
        assert!(!registry.is_text_call("call-1"));
    }
}
