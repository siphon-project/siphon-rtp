//! The userspace media slow path: per-call transcode / record / DTMF-extraction actors.
//!
//! Where the datapath `Forward` fast path relays an opaque datagram untouched and the
//! [`crate::srtp_bridge`] terminates SRTP, a **media-processing** call sets every audio endpoint to
//! [`FlowAction::Redirect`](siphon_rtp_datapath::FlowAction::Redirect) and the redirect dispatcher
//! routes each datagram to that call's [`MediaCall`] actor. The actor:
//!
//! - re-enforces the signalled-source gate (RTPBleed defence — `Redirect` bypasses the datapath's
//!   gate, exactly as the SRTP bridge must, docs/security-and-nat.md §4 layer 2),
//! - latches the observed source so the reverse direction replies symmetrically (RFC 3550),
//! - transcodes audio between the two legs' negotiated codecs (decode → resample → encode),
//! - relays RTCP and unknown packets verbatim (RFC 5761 demux),
//! - extracts RFC 4733 telephone-events to `Event::Dtmf` and repacketizes them onto the egress
//!   stream, and
//! - optionally records each direction's decoded audio to a WAV file on teardown.
//!
//! Transcode is **packet-driven**, not clock-driven: each ingress packet produces one egress packet
//! (the receiving endpoint owns the playout jitter buffer), so the actor needs no playout ticker.
//! The per-packet transform lives in [`MediaCall::process`], which is pure (datagrams in → datagrams
//! + events out) so it unit-tests deterministically without sockets.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use dashmap::DashMap;
use siphon_rtp_srtp::leg::{SecureLeg, SecureLegRollover};

use siphon_rtp_codec::{Decoder, Encoder};
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket, SourceFilter};
use siphon_rtp_dsp::resample::Resampler;
use siphon_rtp_media::dtmf::{DtmfDetector, DtmfGenerator};
use siphon_rtp_media::fanout::MediaSink;
use siphon_rtp_media::pcap::CapturedPacket;
use siphon_rtp_media::player::PcmPlayer;
use siphon_rtp_media::repacketize::Repacketizer;
use siphon_rtp_media::rtp::{write_packet, RtpHeader, RtpPacket};
use siphon_rtp_media::wav::WavRecorder;
use siphon_rtp_proto::Event;

/// The playout-clock tick driving injected media (PlayMedia / PlayDtmf): one egress packet per
/// 20 ms, the telephony default ptime (RFC 3551).
pub const INJECT_TICK: std::time::Duration = std::time::Duration::from_millis(20);

/// Largest RTP packet the egress scratch buffers accommodate.
const MAX_RTP: usize = 1500;
/// Largest decoded PCM frame (48 kHz × 40 ms mono, a safe ceiling for any telephony frame).
const MAX_PCM: usize = 1920;

/// An RTP/RTCP datagram the pipeline wants to transmit: from `endpoint` toward `dst`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    /// The endpoint (socket) to transmit from.
    pub endpoint: EndpointId,
    /// Where to transmit it (the peer's latched/signalled address).
    pub dst: SocketAddr,
    /// The datagram bytes.
    pub data: Bytes,
}

/// A SIPREC / monitor raw-RTP tee target on one direction's ingress: the original ingress RTP is
/// copied verbatim out `subscriber_endpoint` toward `srs_dst` (a Session Recording Server, RFC 7866
/// §6). The tee carries the source leg's **negotiated codec, byte-for-byte** — no decode/re-encode —
/// so it works for any codec (G.711, AMR-WB, …) regardless of whether the engine has an encoder for
/// it. The subscriber is send-only: the engine never installs an inbound flow on `subscriber_endpoint`
/// (no RTPBleed surface — docs/security-and-nat.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawTee {
    /// The engine endpoint the forked RTP is transmitted from (send-only toward the SRS).
    pub subscriber_endpoint: EndpointId,
    /// The SRS's RTP address (from `subscribe_answer`).
    pub srs_dst: SocketAddr,
}

/// One direction of a media-processing call: ingress codec → (resample) → egress codec.
///
/// "Direction" means the flow of media from one party toward the other. `a_to_b` decodes party A's
/// ingress and encodes it for party B; `b_to_a` is the reverse. The egress sequence/timestamp/SSRC
/// belong to the *synthesized* stream the engine sends to the receiving party.
///
/// A direction may run in **relay-only** mode (`relay_only`): it forwards the ingress RTP verbatim to
/// the peer (no decode/encode), used when a plain passthrough call is promoted to userspace so a
/// SIPREC raw tee can be added to it. In that mode the codec fields are unused (a no-op G.711 pair).
pub struct Direction {
    /// The endpoint datagrams arrive on for this direction (the sending party's engine socket).
    ingress_endpoint: EndpointId,
    /// Signalled-source gate for the sending party (RTPBleed defence on the Redirect path).
    accepted_source: SourceFilter,
    /// The endpoint to transmit from (the receiving party's engine socket).
    egress_endpoint: EndpointId,
    /// Where to transmit (the receiving party's address; latched to its observed source).
    egress_dst: SocketAddr,
    /// When `true`, forward the ingress RTP verbatim to the peer (no transcode) — a promoted
    /// passthrough relay. The codec fields below are unused in this mode.
    relay_only: bool,
    /// SIPREC / monitor raw-RTP tee targets: each receives the **original ingress RTP** byte-for-byte
    /// (RFC 7866 §6). Independent of transcode/relay — added/removed by `subscribe_answer`/`unsubscribe`.
    raw_tee: Vec<RawTee>,
    decoder: Box<dyn Decoder>,
    encoder: Box<dyn Encoder>,
    /// Sample-rate converter when the ingress codec rate differs from the egress codec rate.
    resampler: Option<Resampler>,
    egress_sequence: u16,
    egress_timestamp: u32,
    egress_ssrc: u32,
    egress_payload_type: u8,
    /// Egress PCM samples per frame at the codec's *native* rate (sizes the encode work / ptime).
    egress_frame_samples: u32,
    /// Egress RTP timestamp step per packet, in *RTP-clock* units (ptime × RTP clock ÷ 1000). Equal
    /// to `egress_frame_samples` for every codec whose RTP clock matches its sample rate, but not for
    /// G.722 (16 kHz audio, 8 kHz RTP clock; RFC 3551 §4.5.2) — there it is half the sample count.
    egress_timestamp_increment: u32,
    /// Re-frames the decoded/resampled ingress PCM to the egress `ptime` (rtpengine `ptime=<N>` override
    /// or an ingress↔egress `a=ptime` mismatch). Accumulates egress-domain samples and drains exactly
    /// `egress_frame_samples` per emitted packet, so one ingress frame can yield zero-or-many egress
    /// packets. Sample-exact FIFO; preallocated (zero per-frame heap alloc on the hot path).
    repacketizer: Repacketizer,
    /// Pending RFC 3550 §5.1 marker: set when an ingress packet flags a talkspurt start (marker bit),
    /// consumed by the next emitted egress packet — never a blind per-packet copy, since one ingress
    /// packet maps to zero-or-many egress packets under repacketization.
    pending_marker: bool,
    /// Ingress RFC 4733 telephone-event payload type, if negotiated.
    telephone_event_in: Option<u8>,
    /// Egress RFC 4733 telephone-event payload type (what the receiving party expects).
    telephone_event_out: Option<u8>,
    dtmf: DtmfDetector,
    /// Records the decoded ingress audio when the call is recorded.
    recorder: Option<WavRecorder>,
    /// SIPREC / monitor fork sinks fed the decoded ingress audio (post-decode, pre-encode — the same
    /// PCM the recorder sees). Each re-encodes for a send-only subscriber (a Session Recording Server,
    /// RFC 7866 §6). Empty unless a `subscribe_request`/`subscribe_answer` attached one.
    forks: Vec<Box<dyn MediaSink>>,
    /// Replace egress audio with comfort silence (digit-suppression / hold).
    silenced: bool,
    /// Drop egress audio entirely (not even silence).
    blocked: bool,
    /// Suppress relaying this leg's RFC 4733 telephone-event (DTMF) packets to the peer while still
    /// detecting them (`block DTMF`). When set, an ingress telephone-event still fires the control
    /// plane's `Event::Dtmf` (observability) but is not repacketized toward the peer — the digit is
    /// seen by the controller but not heard by the far side. Independent of `blocked` (audio drop).
    dtmf_blocked: bool,
    /// Egress codec native sample rate, for resampling injected prompt audio onto this stream.
    egress_sample_rate: u32,
    /// An active prompt / DTMF injection on this egress direction (PlayMedia / PlayDtmf). While set,
    /// transcoded audio toward this party is suppressed and the injected media plays instead.
    injection: Option<Injection>,
    /// SDES-SRTP on a **secure + transcoding** leg (BGCF/SBC: e.g. a secure AMR-WB access leg ↔ a
    /// plaintext G.711 PSTN leg). When the *ingress* faces the secure peer, `secure_ingress` decrypts
    /// each datagram (SRTP→RTP / SRTCP→RTCP) before decode; when the *egress* faces the secure peer,
    /// `secure_egress` encrypts each transcoded/relayed datagram before transmit. Both reference the
    /// one shared [`SecureLeg`] for the call (single-owner actor ⇒ the `Mutex` is uncontended). `None`
    /// on a plaintext leg — the existing transcode path is unchanged.
    secure_ingress: Option<Arc<Mutex<SecureLeg>>>,
    secure_egress: Option<Arc<Mutex<SecureLeg>>>,
}

/// One playout tick's egress action, computed while the injection is borrowed and applied after.
enum InjectStep {
    /// Encode + send this prompt PCM frame at the egress rate.
    Audio(Vec<i16>),
    /// Send this telephone-event packet (bytes already framed by the generator).
    Dtmf {
        bytes: [u8; 4],
        marker: bool,
        payload_type: u8,
        timestamp: u32,
    },
    /// The injection finished — clear it and resume transcode.
    Exhausted,
    /// No injection active.
    Idle,
}

/// Media injected onto an egress direction by a control verb.
enum Injection {
    /// A prompt / announcement from [`super::engine`]'s `PlayMedia`, resampled to the egress rate.
    Audio {
        player: PcmPlayer,
        resampler: Option<Resampler>,
    },
    /// An RFC 4733 DTMF burst from `PlayDtmf`, sharing the egress stream's SSRC + a frozen timestamp.
    Dtmf {
        generator: DtmfGenerator,
        payload_type: u8,
        /// The RTP timestamp held constant across the event (RFC 4733 §2.5.1.2).
        timestamp: u32,
    },
}

/// Per-direction construction parameters, built by the engine from the negotiated SDP.
pub struct DirectionConfig {
    pub ingress_endpoint: EndpointId,
    pub accepted_source: SourceFilter,
    pub egress_endpoint: EndpointId,
    pub egress_dst: SocketAddr,
    pub decoder: Box<dyn Decoder>,
    pub encoder: Box<dyn Encoder>,
    pub egress_ssrc: u32,
    pub egress_payload_type: u8,
    pub telephone_event_in: Option<u8>,
    pub telephone_event_out: Option<u8>,
    /// `Some(WavRecorder)` to record this direction's decoded audio.
    pub recorder: Option<WavRecorder>,
}

/// Per-direction parameters for a **relay-only** direction (a promoted passthrough leg): just the
/// ingress gate and where to forward verbatim. No codecs — the RTP is copied untouched.
pub struct RelayConfig {
    pub ingress_endpoint: EndpointId,
    pub accepted_source: SourceFilter,
    pub egress_endpoint: EndpointId,
    pub egress_dst: SocketAddr,
    /// This leg's negotiated RFC 4733 telephone-event payload type, if known. Carried so `block DTMF`
    /// can drop the verbatim relay of that PT even on a plain (untranscoded) relay. `None` when the
    /// leg negotiated no telephone-event or its PT could not be resolved — DTMF cannot be gated then.
    pub telephone_event: Option<u8>,
}

/// A companion **RTCP** relay for a *non-muxed* secure-transcode (`SrtpMedia`) leg. RTCP is never
/// transcoded — on the secure side it is SRTCP-decrypted (ingress) / SRTCP-encrypted (egress) against
/// the call's shared [`SecureLeg`] (RFC 3711), and on the plaintext side relayed verbatim; RFC 5761
/// keeps it on its own port here (the muxed case rides the RTP endpoint and is handled inside
/// `Direction::handle`). The `SecureLeg` is the *same* instance the RTP directions share — its SRTCP
/// contexts are distinct from the SRTP ones, so the single-owner actor keeps all crypto state in one
/// place. The RTPBleed source gate is enforced on the RTCP endpoint too.
pub struct RtcpRelay {
    ingress_endpoint: EndpointId,
    accepted_source: SourceFilter,
    egress_endpoint: EndpointId,
    /// The peer's signalled RTCP address. (Dynamic RTCP-follows-RTP latching is a follow-up — RTCP is
    /// gated to the signalled source and forwarded to the signalled address, matching the plain SRTP
    /// bridge's RTCP flows.)
    egress_dst: SocketAddr,
    /// Decrypt SRTCP→RTCP when the ingress faces the secure peer.
    secure_ingress: Option<Arc<Mutex<SecureLeg>>>,
    /// Encrypt RTCP→SRTCP when the egress faces the secure peer.
    secure_egress: Option<Arc<Mutex<SecureLeg>>>,
}

impl RtcpRelay {
    /// A plaintext RTCP relay; layer on `with_secure_ingress` / `with_secure_egress` for the secure side.
    #[must_use]
    pub fn new(
        ingress_endpoint: EndpointId,
        accepted_source: SourceFilter,
        egress_endpoint: EndpointId,
        egress_dst: SocketAddr,
    ) -> Self {
        Self {
            ingress_endpoint,
            accepted_source,
            egress_endpoint,
            egress_dst,
            secure_ingress: None,
            secure_egress: None,
        }
    }

    /// SRTCP-decrypt ingress datagrams against `leg` (the ingress faces the secure peer).
    #[must_use]
    pub fn with_secure_ingress(mut self, leg: Arc<Mutex<SecureLeg>>) -> Self {
        self.secure_ingress = Some(leg);
        self
    }

    /// SRTCP-encrypt egress datagrams against `leg` (the egress faces the secure peer).
    #[must_use]
    pub fn with_secure_egress(mut self, leg: Arc<Mutex<SecureLeg>>) -> Self {
        self.secure_egress = Some(leg);
        self
    }

    /// Relay one RTCP datagram: SRTCP-decrypt (if the ingress is secure) → SRTCP-encrypt (if the
    /// egress is secure — [`SecureLeg`] auto-demuxes RTCP) → transmit toward the peer's RTCP address.
    /// Drops on any (de)crypt failure — never forward garbage RTCP.
    fn relay(&self, data: &[u8], out: &mut Vec<Outbound>) {
        let decrypted;
        let plaintext: &[u8] = if let Some(leg) = &self.secure_ingress {
            let mut buffer = Vec::new();
            let Ok(mut guard) = leg.lock() else { return };
            if guard.unprotect(data, &mut buffer).is_err() {
                return;
            }
            drop(guard);
            decrypted = buffer;
            &decrypted
        } else {
            data
        };
        let encrypted;
        let payload: &[u8] = if let Some(leg) = &self.secure_egress {
            let mut buffer = Vec::new();
            let Ok(mut guard) = leg.lock() else { return };
            if guard.protect(plaintext, &mut buffer).is_err() {
                return;
            }
            drop(guard);
            encrypted = buffer;
            &encrypted
        } else {
            plaintext
        };
        out.push(Outbound {
            endpoint: self.egress_endpoint,
            dst: self.egress_dst,
            data: Bytes::copy_from_slice(payload),
        });
    }
}

impl Direction {
    fn new(config: DirectionConfig) -> Self {
        let ingress_rate = config.decoder.params().sample_rate_hz;
        let egress_params = config.encoder.params();
        let egress_rate = egress_params.sample_rate_hz;
        // Build a resampler only when the codecs run at different rates (e.g. AMR-WB 16 k → G.711 8 k).
        let resampler = if ingress_rate == egress_rate {
            None
        } else {
            Resampler::new(ingress_rate, egress_rate).ok()
        };
        // The egress frame the encoder consumes (and the repacketizer drains) is the encoder's own
        // `frame_samples` — sizing it here from the encoder guarantees the repacketizer always feeds
        // the encoder exactly one frame's worth. A ptime override reaches this via the egress
        // `CodecSpec.ptime_ms` the encoder was built with (sample-based codecs honour it; a frame-based
        // codec such as AMR keeps its native 20 ms frame — the override is inert there by construction).
        // Bound it to the scratch ceiling so an adversarial `a=ptime` can never overflow the fixed
        // egress frame buffer; the timestamp step is recomputed from the same bounded count so drain
        // and RTP clock stay in lock-step.
        let egress_frame_samples = (egress_params.frame_samples() as u32).min(MAX_PCM as u32);
        // RFC 3551 §4.5.2: the synthesized-egress RTP timestamp advances at the codec's RTP clock,
        // which is not always the native sample rate — G.722 clocks RTP at 8 kHz while sampling
        // 16 kHz audio. So the per-packet step is native-samples × RTP-clock ÷ native-rate (= the
        // 8 kHz / 16 kHz halving for G.722; an identity for every other telephony codec).
        let egress_rtp_clock = config.encoder.rtp_clock_rate_hz();
        let egress_timestamp_increment = if egress_rate == 0 {
            egress_frame_samples
        } else {
            ((u64::from(egress_frame_samples) * u64::from(egress_rtp_clock))
                / u64::from(egress_rate)) as u32
        };
        // The repacketizer accumulates egress-domain PCM: one push is at most a decoded+resampled
        // ingress frame (≤ `MAX_PCM`), and it holds < one egress frame of leftover, so `MAX_PCM` of
        // push headroom never reallocates it.
        let repacketizer = Repacketizer::new(egress_frame_samples as usize, MAX_PCM);
        Self {
            ingress_endpoint: config.ingress_endpoint,
            accepted_source: config.accepted_source,
            egress_endpoint: config.egress_endpoint,
            egress_dst: config.egress_dst,
            relay_only: false,
            raw_tee: Vec::new(),
            decoder: config.decoder,
            encoder: config.encoder,
            resampler,
            egress_sequence: 0,
            egress_timestamp: 0,
            egress_ssrc: config.egress_ssrc,
            egress_payload_type: config.egress_payload_type,
            egress_frame_samples,
            egress_timestamp_increment,
            repacketizer,
            // RFC 3550 §5.1: don't fabricate a talkspurt marker — propagate the sender's. The first
            // egress packet carries the marker only if the ingress stream flagged one.
            pending_marker: false,
            telephone_event_in: config.telephone_event_in,
            telephone_event_out: config.telephone_event_out,
            dtmf: DtmfDetector::new(),
            recorder: config.recorder,
            forks: Vec::new(),
            silenced: false,
            blocked: false,
            dtmf_blocked: false,
            egress_sample_rate: egress_rate,
            injection: None,
            secure_ingress: None,
            secure_egress: None,
        }
    }

    /// Build a **relay-only** direction: ingress RTP is forwarded verbatim to the peer (no
    /// decode/encode). Used when a plain passthrough call is promoted to userspace so a SIPREC raw
    /// tee can be attached. The codec fields are unused; a trivial G.711 µ-law pair stands in so the
    /// struct is fully constructed (it is never invoked in this mode).
    fn new_relay(config: RelayConfig) -> Self {
        Self {
            ingress_endpoint: config.ingress_endpoint,
            accepted_source: config.accepted_source,
            egress_endpoint: config.egress_endpoint,
            egress_dst: config.egress_dst,
            relay_only: true,
            raw_tee: Vec::new(),
            decoder: Box::new(siphon_rtp_codec::g711::G711::ulaw()),
            encoder: Box::new(siphon_rtp_codec::g711::G711::ulaw()),
            resampler: None,
            egress_sequence: 0,
            egress_timestamp: 0,
            egress_ssrc: 0,
            egress_payload_type: 0,
            egress_frame_samples: 0,
            egress_timestamp_increment: 0,
            // A relay-only direction forwards RTP verbatim; the repacketizer (frame size 0) never drains.
            repacketizer: Repacketizer::new(0, 0),
            pending_marker: false,
            // Carry the leg's telephone-event PT so `block DTMF` can drop the verbatim relay of it even
            // though this direction never transcodes. `telephone_event_out` stays `None` — a relay-only
            // leg never repacketizes; it drops or forwards the packet whole.
            telephone_event_in: config.telephone_event,
            telephone_event_out: None,
            dtmf: DtmfDetector::new(),
            recorder: None,
            forks: Vec::new(),
            silenced: false,
            blocked: false,
            dtmf_blocked: false,
            egress_sample_rate: 0,
            injection: None,
            secure_ingress: None,
            secure_egress: None,
        }
    }

    /// Emit the raw-RTP tee for one accepted ingress datagram: copy the **original ingress bytes**
    /// verbatim out each subscriber endpoint toward its SRS (SIPREC raw tee — RFC 7866 §6). No
    /// decode/re-encode, so it carries the source leg's negotiated codec byte-for-byte and works for
    /// any codec the engine cannot encode (e.g. AMR-WB). Applied to RTP, RTCP, and DTMF alike — the
    /// SRS receives exactly what the leg sent.
    fn tee_raw(&self, data: &[u8], out: &mut Vec<Outbound>) {
        for tee in &self.raw_tee {
            out.push(Outbound {
                endpoint: tee.subscriber_endpoint,
                dst: tee.srs_dst,
                data: Bytes::copy_from_slice(data),
            });
        }
    }

    /// Egress packetization in milliseconds, derived from the codec's frame size and rate.
    fn egress_ptime_ms(&self) -> u32 {
        if self.egress_sample_rate == 0 {
            return 20;
        }
        (self.egress_frame_samples * 1000 / self.egress_sample_rate).max(1)
    }

    /// Advance an active injection by one tick, emitting at most one egress packet. Clears the
    /// injection when the prompt / DTMF burst is exhausted.
    fn tick_injection(&mut self, out: &mut Vec<Outbound>) {
        let ptime = self.egress_ptime_ms() as usize;
        // Produce this tick's egress step while holding the injection borrow, then act on it after
        // the borrow ends (the encode/packetize path needs `&mut self` again).
        let step = match self.injection.as_mut() {
            Some(Injection::Audio { player, resampler }) => {
                let source_rate = player.sample_rate_hz() as usize;
                let source_frame = (source_rate * ptime / 1000).clamp(1, MAX_PCM);
                let mut source = [0i16; MAX_PCM];
                match player.next_frame(&mut source[..source_frame]) {
                    Some(written) => {
                        let frame = match resampler.as_mut() {
                            Some(resampler) => {
                                let mut buffer = Vec::new();
                                resampler.process(&source[..written], &mut buffer);
                                buffer
                            }
                            None => source[..written].to_vec(),
                        };
                        InjectStep::Audio(frame)
                    }
                    None => InjectStep::Exhausted,
                }
            }
            Some(Injection::Dtmf {
                generator,
                payload_type,
                timestamp,
            }) => match generator.next_payload() {
                Some(payload) => InjectStep::Dtmf {
                    bytes: payload.bytes,
                    marker: payload.is_first,
                    payload_type: *payload_type,
                    timestamp: *timestamp,
                },
                None => InjectStep::Exhausted,
            },
            None => InjectStep::Idle,
        };

        match step {
            InjectStep::Audio(frame) => self.emit_encoded(&frame, out),
            InjectStep::Dtmf {
                bytes,
                marker,
                payload_type,
                timestamp,
            } => {
                let header = RtpHeader {
                    marker,
                    payload_type,
                    sequence: self.egress_sequence,
                    timestamp,
                    ssrc: self.egress_ssrc,
                };
                let mut buffer = [0u8; MAX_RTP];
                if let Ok(total) = write_packet(&header, &bytes, &mut buffer) {
                    self.push_egress(&buffer[..total], out);
                    self.egress_sequence = self.egress_sequence.wrapping_add(1);
                }
            }
            InjectStep::Exhausted => self.injection = None,
            InjectStep::Idle => {}
        }
    }

    /// Encode one PCM frame and append it as an egress packet, advancing the egress counters. Shared
    /// by the prompt-injection path; the transcode path in [`Direction::handle`] inlines the same.
    fn emit_encoded(&mut self, pcm: &[i16], out: &mut Vec<Outbound>) {
        let mut payload = [0u8; MAX_RTP];
        let Ok(payload_len) = self.encoder.encode(pcm, &mut payload) else {
            return;
        };
        let header = RtpHeader {
            marker: false,
            payload_type: self.egress_payload_type,
            sequence: self.egress_sequence,
            timestamp: self.egress_timestamp,
            ssrc: self.egress_ssrc,
        };
        let mut buffer = [0u8; MAX_RTP];
        if let Ok(total) = write_packet(&header, &payload[..payload_len], &mut buffer) {
            self.push_egress(&buffer[..total], out);
            self.egress_sequence = self.egress_sequence.wrapping_add(1);
            self.egress_timestamp = self
                .egress_timestamp
                .wrapping_add(self.egress_timestamp_increment);
        }
    }

    /// Transform one accepted datagram for this direction, appending any outbound datagrams and DTMF
    /// events. `source`-gating and latching are the caller's responsibility (it owns both directions).
    fn handle(
        &mut self,
        data: &[u8],
        dtmf_meta: DtmfMeta<'_>,
        out: &mut Vec<Outbound>,
        events: &mut Vec<Event>,
    ) {
        if data.len() < 2 {
            return;
        }
        // Secure ingress (SDES-SRTP): decrypt before anything else, so the tee / relay / RFC 5761
        // demux / decode all operate on plaintext. SecureLeg auto-demuxes SRTP vs SRTCP. A failed
        // unprotect (bad auth / replay / wrong key) drops the datagram — never forward garbage.
        let decrypted;
        let data: &[u8] = if let Some(leg) = self.secure_ingress.as_ref() {
            let mut plain = Vec::new();
            let Ok(mut guard) = leg.lock() else { return };
            if guard.unprotect(data, &mut plain).is_err() {
                return;
            }
            drop(guard);
            decrypted = plain;
            &decrypted
        } else {
            data
        };
        // SIPREC raw tee (RFC 7866 §6): copy the original ingress RTP/RTCP/DTMF byte-for-byte to each
        // subscriber's SRS before any transcode/relay. The SRS records the leg's *actual* media in its
        // negotiated codec — independent of hold/mute/transcode on the A↔B path.
        self.tee_raw(data, out);

        // Relay-only (promoted passthrough): forward the ingress RTP verbatim to the peer — no
        // decode/encode. (The raw tee above already copied it to any subscriber, regardless of
        // `blocked`, so the SRS still records a held leg — RFC 7866 §6.) `blocked` suppresses the
        // peer-bound forward so block/unblock still works after promotion.
        if self.relay_only {
            // `block DTMF` on a plain relay: drop the verbatim forward of this leg's RFC 4733
            // telephone-event PT (still detect + emit the event for the controller), but keep RTCP
            // and ordinary RTP flowing. Only the RTP demux applies (RTCP PT 64..=95 is not DTMF).
            if self.dtmf_blocked {
                let packet_type = data[1] & 0x7f; // RTP payload type = low 7 bits of byte 1
                let is_rtcp = (64..=95).contains(&packet_type);
                if !is_rtcp && Some(packet_type) == self.telephone_event_in {
                    // Detect + emit the event so the controller still sees the digit (observability),
                    // then drop the packet — the peer never hears the tone. A malformed telephone-event
                    // still drops (never forward a blocked DTMF PT).
                    if let Ok(parsed) = RtpPacket::parse(data) {
                        if let Ok(Some(event)) =
                            self.dtmf.on_packet(parsed.timestamp, parsed.payload)
                        {
                            events.push(Event::Dtmf {
                                call_id: dtmf_meta.call_id.to_string(),
                                from_tag: dtmf_meta.from_tag.to_string(),
                                to_tag: dtmf_meta.to_tag.map(str::to_string),
                                digit: event.digit.to_string(),
                                duration_ms: u32::from(event.duration) / 8,
                                volume: -i32::from(event.volume),
                                source: None,
                            });
                        }
                    }
                    return;
                }
            }
            if !self.blocked {
                out.push(Outbound {
                    endpoint: self.egress_endpoint,
                    dst: self.egress_dst,
                    data: Bytes::copy_from_slice(data),
                });
            }
            return;
        }

        // RFC 5761 demux: payload-type byte 64..=95 marks RTCP — relay it (re-encrypting toward a
        // secure egress), untranscoded.
        let packet_type = data[1] & 0x7f;
        if (64..=95).contains(&packet_type) {
            self.push_egress(data, out);
            return;
        }

        let Ok(parsed) = RtpPacket::parse(data) else {
            return; // malformed RTP — drop (never forward garbage)
        };

        // RFC 4733 telephone-event: extract a DTMF event and repacketize onto the egress stream.
        if Some(parsed.payload_type) == self.telephone_event_in {
            if let Ok(Some(event)) = self.dtmf.on_packet(parsed.timestamp, parsed.payload) {
                events.push(Event::Dtmf {
                    call_id: dtmf_meta.call_id.to_string(),
                    from_tag: dtmf_meta.from_tag.to_string(),
                    to_tag: dtmf_meta.to_tag.map(str::to_string),
                    digit: event.digit.to_string(),
                    // RTP timestamp units are samples at the 8 kHz telephone-event clock (RFC 4733).
                    duration_ms: u32::from(event.duration) / 8,
                    volume: -i32::from(event.volume),
                    source: None,
                });
            }
            // `block DTMF`: still detect + emit the event above (the controller sees the digit), but
            // do not relay it to the peer — the far side never hears the tone. v1 = drop mode.
            if !self.dtmf_blocked {
                self.relay_telephone_event(&parsed, out);
            }
            return;
        }

        if self.blocked {
            return;
        }
        // While a prompt / DTMF burst plays toward this party, suppress the transcoded audio so the
        // injection is heard cleanly (the playout clock drives the egress instead — see `tick_injection`).
        if self.injection.is_some() {
            return;
        }

        // Decode → record → (silence) → resample → encode → transmit.
        let mut decoded = [0i16; MAX_PCM];
        let Ok(samples) = self.decoder.decode(parsed.payload, &mut decoded) else {
            return;
        };
        let decoded = &decoded[..samples];
        if let Some(recorder) = self.recorder.as_mut() {
            recorder.write_pcm(decoded);
        }
        // SIPREC / monitor fork: re-encode the decoded ingress PCM toward each subscriber. Fed the
        // same raw decoded audio as the recorder (pre-silence, pre-resample) so a fork captures what
        // the leg actually said, independent of hold/mute state on the A↔B path (RFC 7866 §6). A full
        // or disconnected subscriber drops the frame inside the sink — it never stalls the transcode.
        for fork in &mut self.forks {
            fork.write_pcm(decoded);
        }

        let silence;
        let pre_resample: &[i16] = if self.silenced {
            silence = vec![0i16; samples];
            &silence
        } else {
            decoded
        };

        let resampled;
        let egress_pcm: &[i16] = match self.resampler.as_mut() {
            Some(resampler) => {
                let mut buffer = Vec::new();
                resampler.process(pre_resample, &mut buffer);
                resampled = buffer;
                &resampled
            }
            None => pre_resample,
        };

        // Re-frame to the egress ptime: accumulate in the egress sample domain (post-resample) and
        // emit one RTP packet per full egress frame. Resample **then** accumulate — the resampler is
        // stateful (holds filter history across frames) so it must see the continuous per-ingress-frame
        // stream, and accumulating in the egress domain makes the drain quantum exactly the encoder's
        // frame size.
        self.repacketize(egress_pcm, parsed.marker, out);
    }

    /// Re-frame decoded egress-domain PCM to this direction's egress `ptime` and emit one RTP packet
    /// per full egress frame. The accumulator (preallocated) buffers a partial frame across ingress
    /// packets, so a small ingress frame waits for a full egress frame and a large one emits several —
    /// each with sequence +1 (RFC 3550 §5.1) and timestamp +`egress_timestamp_increment` (in the RTP
    /// clock, RFC 3551 §4.5.2), advanced by [`Direction::emit_pcm`].
    fn repacketize(&mut self, egress_pcm: &[i16], ingress_marker: bool, out: &mut Vec<Outbound>) {
        // RFC 3550 §5.1: the marker flags the first packet of a talkspurt. Carry the sender's talkspurt
        // boundary to the *first* egress packet that follows (repacketization means one ingress packet
        // maps to zero-or-many egress packets), rather than stamping every egress packet with it.
        if ingress_marker {
            self.pending_marker = true;
        }
        // No egress framing (degenerate frame size 0): emit the chunk as one packet, unchanged.
        if self.repacketizer.frame_samples() == 0 {
            let marker = std::mem::take(&mut self.pending_marker);
            self.emit_pcm(egress_pcm, marker, out);
            return;
        }
        self.repacketizer.push(egress_pcm);
        // `egress_frame_samples` is bounded to `MAX_PCM` in `Direction::new`, so one frame always fits.
        let mut frame = [0i16; MAX_PCM];
        while let Some(count) = self.repacketizer.next_frame(&mut frame) {
            let marker = std::mem::take(&mut self.pending_marker);
            self.emit_pcm(&frame[..count], marker, out);
        }
    }

    /// Append one egress datagram toward this direction's peer, encrypting it (SRTP/SRTCP, auto-
    /// demuxed by [`SecureLeg`]) first when the egress faces a secure peer. `plaintext` is a complete
    /// RTP or RTCP packet; on a plaintext leg it is forwarded verbatim. A failed protect drops it.
    fn push_egress(&self, plaintext: &[u8], out: &mut Vec<Outbound>) {
        let data = if let Some(leg) = self.secure_egress.as_ref() {
            let mut sealed = Vec::new();
            let Ok(mut guard) = leg.lock() else { return };
            if guard.protect(plaintext, &mut sealed).is_err() {
                return;
            }
            drop(guard);
            Bytes::from(sealed)
        } else {
            Bytes::copy_from_slice(plaintext)
        };
        out.push(Outbound {
            endpoint: self.egress_endpoint,
            dst: self.egress_dst,
            data,
        });
    }

    /// Encode one frame of egress PCM and append the resulting RTP packet to `out`, advancing this
    /// direction's egress sequence/timestamp. Shared by the transcode path ([`Direction::handle`])
    /// and the echo path ([`Direction::echo_into`]); `pcm` must already be at the egress codec's rate.
    fn emit_pcm(&mut self, pcm: &[i16], marker: bool, out: &mut Vec<Outbound>) {
        let mut payload = [0u8; MAX_RTP];
        let Ok(payload_len) = self.encoder.encode(pcm, &mut payload) else {
            return;
        };
        let header = RtpHeader {
            marker,
            payload_type: self.egress_payload_type,
            sequence: self.egress_sequence,
            timestamp: self.egress_timestamp,
            ssrc: self.egress_ssrc,
        };
        let mut buffer = [0u8; MAX_RTP];
        if let Ok(total) = write_packet(&header, &payload[..payload_len], &mut buffer) {
            self.push_egress(&buffer[..total], out);
            self.egress_sequence = self.egress_sequence.wrapping_add(1);
            self.egress_timestamp = self
                .egress_timestamp
                .wrapping_add(self.egress_timestamp_increment);
        }
    }

    /// Echo this direction's ingress audio straight back to the party that sent it (the classic echo
    /// test). `self` decodes the ingress (its decoder faces the sending party); `egress` is the
    /// direction whose egress faces that same party, used to re-encode + transmit the audio home.
    ///
    /// RFC 4733 telephone-events are still detected and emitted as [`Event::Dtmf`] (so the SBC can end
    /// the test on `#`) but are not echoed; RTCP is ignored. Both directions carry the party's single
    /// negotiated codec, so no resampling is needed — the decoded PCM feeds the egress encoder directly.
    fn echo_into(
        &mut self,
        egress: &mut Direction,
        data: &[u8],
        dtmf_meta: DtmfMeta<'_>,
        out: &mut Vec<Outbound>,
        events: &mut Vec<Event>,
    ) {
        if data.len() < 2 {
            return;
        }
        // RFC 5761 demux: ignore RTCP on the echo path (nothing to reflect).
        let packet_type = data[1] & 0x7f;
        if (64..=95).contains(&packet_type) {
            return;
        }
        let Ok(parsed) = RtpPacket::parse(data) else {
            return;
        };
        // Detect DTMF so the caller can end the echo test on a digit; do not echo the tone itself.
        if Some(parsed.payload_type) == self.telephone_event_in {
            if let Ok(Some(event)) = self.dtmf.on_packet(parsed.timestamp, parsed.payload) {
                events.push(Event::Dtmf {
                    call_id: dtmf_meta.call_id.to_string(),
                    from_tag: dtmf_meta.from_tag.to_string(),
                    to_tag: dtmf_meta.to_tag.map(str::to_string),
                    digit: event.digit.to_string(),
                    duration_ms: u32::from(event.duration) / 8,
                    volume: -i32::from(event.volume),
                    source: None,
                });
            }
            return;
        }
        let mut decoded = [0i16; MAX_PCM];
        let Ok(samples) = self.decoder.decode(parsed.payload, &mut decoded) else {
            return;
        };
        egress.emit_pcm(&decoded[..samples], parsed.marker, out);
    }

    /// Repacketize a telephone-event onto the egress stream: keep the event's RTP timestamp (RFC 4733
    /// holds it constant across the event), but stamp the engine's egress SSRC and sequence so the
    /// receiving party sees a coherent stream. The egress telephone-event payload type is used.
    fn relay_telephone_event(&mut self, parsed: &RtpPacket<'_>, out: &mut Vec<Outbound>) {
        let Some(payload_type) = self.telephone_event_out else {
            return; // the receiving party did not negotiate telephone-event — drop (event already emitted)
        };
        let header = RtpHeader {
            marker: parsed.marker,
            payload_type,
            sequence: self.egress_sequence,
            timestamp: parsed.timestamp,
            ssrc: self.egress_ssrc,
        };
        let mut buffer = [0u8; MAX_RTP];
        if let Ok(total) = write_packet(&header, parsed.payload, &mut buffer) {
            self.push_egress(&buffer[..total], out);
            self.egress_sequence = self.egress_sequence.wrapping_add(1);
        }
    }
}

/// Metadata threaded into [`Direction::handle`] so an extracted DTMF event names its call/leg.
struct DtmfMeta<'a> {
    call_id: &'a str,
    from_tag: &'a str,
    to_tag: Option<&'a str>,
}

/// A media-processing call: two directions plus the call identity for event correlation.
///
/// `process` is pure and synchronous — feed it a redirected datagram, collect the datagrams to send
/// and DTMF events to emit. The async actor (`run_media_call`) wraps it with the datapath I/O.
pub struct MediaCall {
    call_id: String,
    from_tag: String,
    to_tag: Option<String>,
    /// Media from party A toward party B.
    a_to_b: Direction,
    /// Media from party B toward party A.
    b_to_a: Direction,
    /// Latch each party's observed source so the reverse direction replies symmetrically (RFC 3550).
    latch: bool,
    /// Echo-test mode: reflect each party's ingress audio straight back to itself instead of
    /// forwarding it to the peer ([`MediaControl::Echo`]). Off for normal calls.
    echo: bool,
    /// Where to write the recorded WAV on teardown, when recording.
    record_path: Option<String>,
    /// Companion (non-muxed) RTCP relays, for a secure-transcode leg whose RTCP rides its own port
    /// (RFC 5761). Empty for a muxed call — muxed RTCP is (de)crypted/relayed inside [`Direction::handle`].
    rtcp: Vec<RtcpRelay>,
    /// An active raw-RTP pcap capture (`MediaControl::StartRecording`). Each accepted ingress datagram
    /// on either RTP leg is copied byte-for-byte to the sink; the engine owns the drain task that
    /// frames + streams it to disk. `None` unless recording — the actor's per-packet cost is one
    /// bounded `try_send` per captured packet, and dropping under backpressure keeps recording from
    /// ever stalling the media path.
    capture: Option<PcapCapture>,
}

/// The sink + per-leg engine-local addresses for an active raw-RTP pcap capture. The local address
/// is the synthetic destination stamped in the captured frame's 5-tuple (the engine socket the
/// datagram arrived on), so the pcap dissects as `peer → engine`.
pub struct PcapCapture {
    /// The bounded channel the accepted ingress datagrams are streamed to (drained by the engine).
    pub sender: flume::Sender<CapturedPacket>,
    /// Engine-local address of leg A's ingress endpoint (capture destination for A's packets).
    pub a_local: SocketAddr,
    /// Engine-local address of leg B's ingress endpoint (capture destination for B's packets).
    pub b_local: SocketAddr,
}

impl MediaCall {
    /// Install the call's shared SDES-SRTP leg for a **secure + transcoding** topology: the *far*
    /// party (B) is the secure (`RTP/SAVP`) peer, A is plaintext. The A→B egress is encrypted and the
    /// B→A ingress is decrypted against the one shared [`SecureLeg`] (single-owner actor ⇒ the `Mutex`
    /// is uncontended). RTCP rides the same leg (SecureLeg auto-demuxes SRTCP).
    #[must_use]
    pub fn with_far_secure_leg(mut self, leg: Arc<Mutex<SecureLeg>>) -> Self {
        self.a_to_b.secure_egress = Some(leg.clone());
        self.b_to_a.secure_ingress = Some(leg);
        self
    }

    /// The call's shared SDES-SRTP leg, when this is a secure-transcode (`SrtpMedia`) call — so the
    /// registry can retain a handle to it after the actor takes ownership of the `MediaCall`, and read
    /// the leg's SRTP rollover for an HA checkpoint (RFC 3711 §3.3.1). `None` for a plaintext transcode
    /// / relay call (no secure leg). The `a_to_b` egress and `b_to_a` ingress share the one `Arc` (set
    /// together by [`MediaCall::with_far_secure_leg`]), so returning the A→B egress handle is enough.
    #[must_use]
    pub fn far_secure_leg(&self) -> Option<Arc<Mutex<SecureLeg>>> {
        self.a_to_b.secure_egress.clone()
    }

    /// Build a call from its two directions and identity.
    #[must_use]
    pub fn new(
        call_id: impl Into<String>,
        from_tag: impl Into<String>,
        to_tag: Option<String>,
        a_to_b: DirectionConfig,
        b_to_a: DirectionConfig,
        latch: bool,
        record_path: Option<String>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            from_tag: from_tag.into(),
            to_tag,
            a_to_b: Direction::new(a_to_b),
            b_to_a: Direction::new(b_to_a),
            latch,
            echo: false,
            record_path,
            rtcp: Vec::new(),
            capture: None,
        }
    }

    /// Attach companion (non-muxed) RTCP relays for a secure-transcode leg — the RTCP endpoints whose
    /// datagrams the actor SRTCP-(de)crypts and forwards without transcoding (RFC 5761 keeps RTCP on
    /// its own port). Their ingress endpoints must be redirected to this actor and routed in the
    /// [`MediaRegistry`] (see [`MediaCall::rtcp_endpoints`]).
    #[must_use]
    pub fn with_rtcp_relays(mut self, relays: Vec<RtcpRelay>) -> Self {
        self.rtcp = relays;
        self
    }

    /// The companion-RTCP endpoints this call routes (empty unless [`MediaCall::with_rtcp_relays`]),
    /// so the registry can direct their redirected datagrams to this actor.
    #[must_use]
    pub fn rtcp_endpoints(&self) -> Vec<EndpointId> {
        self.rtcp
            .iter()
            .map(|relay| relay.ingress_endpoint)
            .collect()
    }

    /// Build a **relay-only** call: both directions forward their ingress RTP verbatim to the peer
    /// (no transcode). Used when a plain passthrough relay is promoted to userspace so a SIPREC raw
    /// tee can be attached to a leg (the in-kernel `Forward` fast path has no userspace tap). The
    /// per-direction source gate + symmetric latch are re-enforced exactly as the `Forward` rule did
    /// (RTPBleed defence — the Redirect path bypasses the datapath gate, docs/security-and-nat.md §4).
    #[must_use]
    pub fn new_relay(
        call_id: impl Into<String>,
        from_tag: impl Into<String>,
        to_tag: Option<String>,
        a_to_b: RelayConfig,
        b_to_a: RelayConfig,
        latch: bool,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            from_tag: from_tag.into(),
            to_tag,
            a_to_b: Direction::new_relay(a_to_b),
            b_to_a: Direction::new_relay(b_to_a),
            latch,
            echo: false,
            record_path: None,
            rtcp: Vec::new(),
            capture: None,
        }
    }

    /// The endpoints this call owns (for registry routing and teardown).
    #[must_use]
    pub fn endpoints(&self) -> [EndpointId; 2] {
        [self.a_to_b.ingress_endpoint, self.b_to_a.ingress_endpoint]
    }

    /// Whether this is a relay-only call (a promoted passthrough leg, no transcode). Lets the engine
    /// keep its media-only guards (silence / play / DTMF require a transcoding call) correct after a
    /// passthrough call is promoted for SIPREC.
    #[must_use]
    pub fn is_relay_only(&self) -> bool {
        self.a_to_b.relay_only && self.b_to_a.relay_only
    }

    /// Process one redirected datagram, gating its source and latching the reverse direction's
    /// destination, then transcoding/relaying it.
    pub fn process(&mut self, packet: &RxPacket, out: &mut Vec<Outbound>, events: &mut Vec<Event>) {
        let meta = DtmfMeta {
            call_id: &self.call_id,
            from_tag: &self.from_tag,
            to_tag: self.to_tag.as_deref(),
        };
        if packet.endpoint == self.a_to_b.ingress_endpoint {
            // Party A's media: gate A's source; the B→A direction now knows where to reply to A.
            if !self.a_to_b.accepted_source.accepts(packet.source.ip()) {
                tracing::debug!(source = %packet.source, "media-pipeline dropped packet from unsignalled source");
                return;
            }
            // Raw-RTP pcap capture (accepted A→B ingress, post source-gate, before any transcode).
            self.capture_ingress(true, packet.source, packet.arrival, &packet.data);
            if self.latch {
                self.b_to_a.egress_dst = packet.source;
            }
            if self.echo {
                // Echo A back to A: decode on a_to_b (faces A), re-encode on b_to_a (egress faces A).
                self.a_to_b
                    .echo_into(&mut self.b_to_a, &packet.data, meta, out, events);
            } else {
                self.a_to_b.handle(&packet.data, meta, out, events);
                // RFC 4867 §4.3.1: A's Codec Mode Request steers the mode of the stream sent *back* to
                // A (the b_to_a egress encoder). No-op for a fixed-rate codec / no request.
                if let Some(mode) = self.a_to_b.decoder.last_mode_request() {
                    self.b_to_a.encoder.request_mode(mode);
                }
            }
        } else if packet.endpoint == self.b_to_a.ingress_endpoint {
            if !self.b_to_a.accepted_source.accepts(packet.source.ip()) {
                tracing::debug!(source = %packet.source, "media-pipeline dropped packet from unsignalled source");
                return;
            }
            // Raw-RTP pcap capture (accepted B→A ingress, post source-gate, before any transcode).
            self.capture_ingress(false, packet.source, packet.arrival, &packet.data);
            if self.latch {
                self.a_to_b.egress_dst = packet.source;
            }
            if self.echo {
                self.b_to_a
                    .echo_into(&mut self.a_to_b, &packet.data, meta, out, events);
            } else {
                self.b_to_a.handle(&packet.data, meta, out, events);
                // Symmetric: B's CMR steers the a_to_b egress encoder (the stream sent back to B).
                if let Some(mode) = self.b_to_a.decoder.last_mode_request() {
                    self.a_to_b.encoder.request_mode(mode);
                }
            }
        } else if let Some(relay) = self
            .rtcp
            .iter()
            .find(|relay| relay.ingress_endpoint == packet.endpoint)
        {
            // Companion (non-muxed) RTCP on a secure-transcode leg: gate the source (RTPBleed) then
            // SRTCP-(de)crypt and relay it untranscoded toward the peer's RTCP port.
            if !relay.accepted_source.accepts(packet.source.ip()) {
                tracing::debug!(source = %packet.source, "media-pipeline dropped RTCP from unsignalled source");
                return;
            }
            relay.relay(&packet.data, out);
        }
    }

    /// Enable or disable echo-test mode (`Command::Echo`): when on, each party's ingress audio is
    /// reflected straight back to itself instead of being forwarded to the peer.
    pub fn set_echo(&mut self, echo: bool) {
        self.echo = echo;
    }

    /// Toggle comfort-silence on both egress directions (`Command::SilenceMedia`).
    pub fn set_silenced(&mut self, silenced: bool) {
        self.a_to_b.silenced = silenced;
        self.b_to_a.silenced = silenced;
    }

    /// Toggle full egress blocking on both directions (`Command::BlockMedia`).
    pub fn set_blocked(&mut self, blocked: bool) {
        self.a_to_b.blocked = blocked;
        self.b_to_a.blocked = blocked;
    }

    /// Block (`blocked = true`) or resume (`false`) relaying one leg's RFC 4733 telephone-events
    /// (`Command::BlockDtmf`). `source_a` selects the blocked source leg: `true` ⇒ leg A. It is set on
    /// the leg's **ingress** direction (leg A's telephone-events arrive on `a_to_b`), so A's DTMF is
    /// dropped toward B while B's is unaffected. Detection still fires — the controller sees the digit.
    pub fn set_dtmf_blocked(&mut self, source_a: bool, blocked: bool) {
        self.ingress_direction(source_a).dtmf_blocked = blocked;
    }

    /// Begin a raw-RTP pcap capture (`MediaControl::StartRecording`): every accepted ingress datagram
    /// on either leg is copied byte-for-byte to the sink. Replacing an existing capture drops the old
    /// sink, closing its channel so the engine's drain task finalizes that file.
    pub fn start_recording(&mut self, capture: PcapCapture) {
        self.capture = Some(capture);
    }

    /// Stop a raw-RTP pcap capture (`MediaControl::StopRecording`): drop the sink so the engine's
    /// drain task sees the channel close and finalizes the file. A no-op if not recording.
    pub fn stop_recording(&mut self) {
        self.capture = None;
    }

    /// Whether a raw-RTP pcap capture is active (test/observability helper).
    #[must_use]
    pub fn is_recording(&self) -> bool {
        self.capture.is_some()
    }

    /// Copy one accepted ingress datagram to the pcap sink, if recording. `leg_a` selects the capture
    /// destination (leg A's or leg B's engine-local address). Bounded, drop-on-full: a recording is
    /// best-effort and must never backpressure the media path.
    fn capture_ingress(&self, leg_a: bool, source: SocketAddr, arrival: u64, data: &[u8]) {
        let Some(capture) = &self.capture else {
            return;
        };
        let destination = if leg_a {
            capture.a_local
        } else {
            capture.b_local
        };
        let packet =
            CapturedPacket::new(source, destination, Bytes::copy_from_slice(data), arrival);
        if capture.sender.try_send(packet).is_err() {
            tracing::debug!("pcap capture dropped a packet (sink full or closed)");
        }
    }

    /// The egress direction that plays toward party A (`toward_a = true`) or party B.
    fn direction_toward(&mut self, toward_a: bool) -> &mut Direction {
        if toward_a {
            &mut self.b_to_a // its egress socket faces A
        } else {
            &mut self.a_to_b // its egress socket faces B
        }
    }

    /// Start a prompt / announcement toward a party (`Command::PlayMedia`). The player carries the
    /// source-rate PCM; a resampler is built when it differs from the egress codec rate.
    pub fn start_play_audio(&mut self, toward_a: bool, player: PcmPlayer) {
        let direction = self.direction_toward(toward_a);
        let resampler = if player.sample_rate_hz() == direction.egress_sample_rate {
            None
        } else {
            Resampler::new(player.sample_rate_hz(), direction.egress_sample_rate).ok()
        };
        direction.injection = Some(Injection::Audio { player, resampler });
    }

    /// Start a DTMF burst toward a party (`Command::PlayDtmf`). Returns `false` if the party has no
    /// negotiated telephone-event payload type to carry it.
    pub fn start_play_dtmf(
        &mut self,
        toward_a: bool,
        digit: char,
        duration_ms: u32,
        volume: u8,
    ) -> bool {
        let direction = self.direction_toward(toward_a);
        let Some(payload_type) = direction.telephone_event_out else {
            return false;
        };
        let clock_rate = direction.egress_sample_rate;
        let ptime = direction.egress_ptime_ms() as u8;
        let Some(generator) = DtmfGenerator::new(digit, duration_ms, volume, clock_rate, ptime)
        else {
            return false;
        };
        let timestamp = direction.egress_timestamp;
        direction.injection = Some(Injection::Dtmf {
            generator,
            payload_type,
            timestamp,
        });
        true
    }

    /// Stop any prompt / DTMF injection on both directions (`Command::StopMedia`).
    pub fn stop_play(&mut self) {
        self.a_to_b.injection = None;
        self.b_to_a.injection = None;
    }

    /// The direction whose **ingress** decodes a leg's audio: leg A's RTP is decoded by `a_to_b`
    /// (its ingress faces A), leg B's by `b_to_a`. SIPREC forks a source leg's decoded audio, so it
    /// taps the direction that decodes that leg — not the one whose egress faces it (RFC 7866 §6).
    fn ingress_direction(&mut self, source_a: bool) -> &mut Direction {
        if source_a {
            &mut self.a_to_b
        } else {
            &mut self.b_to_a
        }
    }

    /// Attach a SIPREC / monitor fork sink to a source leg's decoded ingress audio
    /// ([`MediaControl::AddFork`]). `source_a` selects which leg is forked: `true` ⇒ leg A's audio,
    /// `false` ⇒ leg B's. The sink (an [`super::engine`]-built `RtpForkSink`) re-encodes each decoded
    /// frame toward the subscriber; the engine drains its output channel to the datapath.
    pub fn add_fork(&mut self, source_a: bool, sink: Box<dyn MediaSink>) {
        self.ingress_direction(source_a).forks.push(sink);
    }

    /// Detach every fork on a source leg's ingress ([`MediaControl::RemoveFork`]). Finalizes each sink
    /// (a no-op for `RtpForkSink`) and drops it, closing its output channel so the engine's drain task
    /// exits cleanly.
    pub fn remove_forks(&mut self, source_a: bool) {
        let direction = self.ingress_direction(source_a);
        for fork in &mut direction.forks {
            fork.finish();
        }
        direction.forks.clear();
    }

    /// Number of forks attached to a source leg's ingress (test/observability helper).
    #[must_use]
    pub fn fork_count(&self, source_a: bool) -> usize {
        if source_a {
            self.a_to_b.forks.len()
        } else {
            self.b_to_a.forks.len()
        }
    }

    /// Attach a SIPREC / monitor **raw-RTP tee** to a source leg's ingress ([`MediaControl::AddRawTee`]).
    /// `source_a` selects the leg: `true` ⇒ leg A's ingress, `false` ⇒ leg B's. Each accepted ingress
    /// datagram is copied byte-for-byte toward the SRS (the leg's negotiated codec, RFC 7866 §6) — no
    /// decode/re-encode, so it works for any codec the engine cannot encode (e.g. AMR-WB).
    pub fn add_raw_tee(&mut self, source_a: bool, tee: RawTee) {
        self.ingress_direction(source_a).raw_tee.push(tee);
    }

    /// Remove the raw tee for a specific subscriber endpoint on a source leg's ingress
    /// ([`MediaControl::RemoveRawTee`]). Removing one subscriber leaves any others intact (MPTY: one
    /// subscription may tap several legs, and a leg may carry several subscriptions).
    pub fn remove_raw_tee(&mut self, source_a: bool, subscriber_endpoint: EndpointId) {
        self.ingress_direction(source_a)
            .raw_tee
            .retain(|tee| tee.subscriber_endpoint != subscriber_endpoint);
    }

    /// Number of raw-tee targets on a source leg's ingress (test/observability helper).
    #[must_use]
    pub fn raw_tee_count(&self, source_a: bool) -> usize {
        if source_a {
            self.a_to_b.raw_tee.len()
        } else {
            self.b_to_a.raw_tee.len()
        }
    }

    /// Advance any active injections by one playout tick, emitting their egress packets.
    pub fn tick(&mut self, out: &mut Vec<Outbound>) {
        self.a_to_b.tick_injection(out);
        self.b_to_a.tick_injection(out);
    }

    /// Whether either direction has an active injection (the actor only needs the ticker while so).
    #[must_use]
    pub fn has_injection(&self) -> bool {
        self.a_to_b.injection.is_some() || self.b_to_a.injection.is_some()
    }

    /// Take the recorded WAV bytes for both directions (mixed into a 2-channel-ish concatenation is
    /// out of scope; we write each direction sequentially as mono), draining the recorders.
    fn take_recordings(&mut self) -> Vec<(String, Vec<u8>)> {
        let mut files = Vec::new();
        let Some(base) = self.record_path.clone() else {
            return files;
        };
        if let Some(recorder) = self.a_to_b.recorder.take() {
            if recorder.sample_count() > 0 {
                files.push((
                    format!("{base}/{}-a.wav", self.call_id),
                    recorder.into_wav(),
                ));
            }
        }
        if let Some(recorder) = self.b_to_a.recorder.take() {
            if recorder.sample_count() > 0 {
                files.push((
                    format!("{base}/{}-b.wav", self.call_id),
                    recorder.into_wav(),
                ));
            }
        }
        files
    }
}

/// A control message to a running [`MediaCall`] actor.
pub enum MediaControl {
    /// Replace egress audio with silence (`true`) or resume (`false`).
    Silence(bool),
    /// Drop egress audio (`true`) or resume (`false`).
    Block(bool),
    /// Echo each party's ingress audio back to itself (`true`) or resume normal forwarding (`false`).
    Echo(bool),
    /// Block (`blocked = true`) or resume (`false`) relaying one leg's RFC 4733 telephone-events
    /// (`block DTMF`). `source_a` selects the blocked source leg (`true` ⇒ leg A). Detection still
    /// fires while blocked, so the controller sees the digit — only the peer-bound relay is dropped.
    BlockDtmf { source_a: bool, blocked: bool },
    /// Play a prompt toward a party (`toward_a`): the player owns its source-rate PCM.
    PlayAudio {
        toward_a: bool,
        player: Box<PcmPlayer>,
    },
    /// Play a DTMF burst toward a party; the reply channel reports whether it could start.
    PlayDtmf {
        toward_a: bool,
        digit: char,
        duration_ms: u32,
        volume: u8,
    },
    /// Stop any prompt / DTMF injection on both directions.
    StopPlay,
    /// Attach a SIPREC / monitor fork to a source leg's decoded ingress audio (`source_a` selects
    /// leg A vs leg B). The engine builds the `RtpForkSink` and owns the matching output channel +
    /// drain task (RFC 7866 SIPREC; the subscriber is send-only — engine → SRS — no inbound media).
    AddFork {
        source_a: bool,
        sink: Box<dyn MediaSink>,
    },
    /// Detach every fork on a source leg's ingress, closing their output channels.
    RemoveFork { source_a: bool },
    /// Attach a SIPREC / monitor **raw-RTP tee** to a source leg's ingress (`source_a` selects leg A
    /// vs leg B). The leg's original ingress RTP is copied byte-for-byte toward the SRS — its
    /// negotiated codec, no re-encode (RFC 7866 §6). Send-only: the engine installs no inbound flow on
    /// the subscriber endpoint, so there is no RTPBleed surface.
    AddRawTee { source_a: bool, tee: RawTee },
    /// Remove the raw tee for a subscriber endpoint on a source leg's ingress.
    RemoveRawTee {
        source_a: bool,
        subscriber_endpoint: EndpointId,
    },
    /// Begin a raw-RTP pcap capture (`start recording`): every accepted ingress datagram on either
    /// leg is copied to `capture.sender`. The engine owns the drain task that frames + streams it to
    /// disk (so the actor never blocks on I/O).
    StartRecording { capture: PcapCapture },
    /// Stop the raw-RTP pcap capture (`stop recording`): drop the sink so the drain task finalizes.
    StopRecording,
    /// Tear the call down: flush recordings and exit the actor loop.
    Stop,
}

/// A message into a [`MediaCall`] actor's single mailbox: a redirected datagram or a control op.
pub enum MediaInput {
    /// A datagram redirected by the datapath for one of this call's endpoints.
    Packet(RxPacket),
    /// A control operation from the engine.
    Control(MediaControl),
}

/// The registry of media-processing calls: routes redirected datagrams to the owning actor's mailbox
/// and holds each call's control handle for teardown. Mirrors the [`crate::srtp_bridge::SrtpBridge`]
/// "registry + dispatcher" shape so the single redirect dispatcher can route by [`EndpointId`].
#[derive(Default)]
pub struct MediaRegistry {
    /// Endpoint → the owning call actor's mailbox (the dispatcher's routing table).
    routes: DashMap<EndpointId, flume::Sender<MediaInput>>,
    /// Call-id → control handle (mailbox + endpoints), for control verbs and teardown.
    calls: DashMap<String, CallHandle>,
}

/// A handle to a running media-call actor.
struct CallHandle {
    mailbox: flume::Sender<MediaInput>,
    endpoints: [EndpointId; 2],
    /// Companion (non-muxed) RTCP endpoints routed to this actor, if any (secure-transcode leg).
    rtcp_endpoints: Vec<EndpointId>,
    task: tokio::task::JoinHandle<()>,
    /// `true` for a promoted passthrough relay (no transcode) — distinguishes it from a transcoding
    /// call so the engine's silence/play/DTMF guards stay correct.
    relay_only: bool,
    /// The call's shared SDES-SRTP leg for a secure-transcode (`SrtpMedia`) call — retained so an HA
    /// checkpoint can read its live SRTP rollover (RFC 3711 §3.3.1), which the running actor otherwise
    /// owns exclusively. `None` for a plaintext transcode / relay call.
    secure_leg: Option<Arc<Mutex<SecureLeg>>>,
}

impl MediaRegistry {
    /// Whether the registry routes datagrams for `endpoint` (the dispatcher's predicate).
    #[must_use]
    pub fn owns(&self, endpoint: EndpointId) -> bool {
        self.routes.contains_key(&endpoint)
    }

    /// Route a redirected datagram to its owning call actor (drop on a full or closed mailbox —
    /// late media is worthless).
    pub fn dispatch(&self, packet: RxPacket) {
        if let Some(mailbox) = self.routes.get(&packet.endpoint) {
            if mailbox.try_send(MediaInput::Packet(packet)).is_err() {
                tracing::trace!("media-call mailbox full or closed; dropping redirected datagram");
            }
        }
    }

    /// Register a built [`MediaCall`] and spawn its actor over `datapath`, with `events` as the
    /// owner's async event sink (DTMF events are pushed there). Returns once the actor is spawned.
    pub fn register<D>(&self, call: MediaCall, datapath: D, events: Option<flume::Sender<Event>>)
    where
        D: Datapath + Clone + Send + 'static,
    {
        let call_id = call.call_id.clone();
        let endpoints = call.endpoints();
        let rtcp_endpoints = call.rtcp_endpoints();
        let relay_only = call.is_relay_only();
        // Clone out the shared secure leg (if any) before the actor takes ownership of the `MediaCall`,
        // so an HA checkpoint can reach its SRTP rollover (RFC 3711 §3.3.1). The `Arc` is the same
        // instance the actor holds — reads are a brief, uncontended lock.
        let secure_leg = call.far_secure_leg();
        let (mailbox, inbox) = flume::bounded(1024);
        for endpoint in endpoints
            .iter()
            .copied()
            .chain(rtcp_endpoints.iter().copied())
        {
            self.routes.insert(endpoint, mailbox.clone());
        }
        let task = tokio::spawn(run_media_call(call, inbox, datapath, events));
        self.calls.insert(
            call_id,
            CallHandle {
                mailbox,
                endpoints,
                rtcp_endpoints,
                task,
                relay_only,
                secure_leg,
            },
        );
    }

    /// Send a control op to a call's actor, returning `false` if there is no such media call.
    pub fn control(&self, call_id: &str, control: MediaControl) -> bool {
        match self.calls.get(call_id) {
            Some(handle) => handle
                .mailbox
                .try_send(MediaInput::Control(control))
                .is_ok(),
            None => false,
        }
    }

    /// Whether `call_id` is registered in the media slow path at all (transcoding **or** a promoted
    /// relay-only call). A SIPREC raw tee can attach to either, so `subscribe_request` checks this.
    #[must_use]
    pub fn is_media_call(&self, call_id: &str) -> bool {
        self.calls.contains_key(call_id)
    }

    /// Snapshot the live SRTP rollover of a secure-transcode (`SrtpMedia`) call's shared [`SecureLeg`]
    /// for an HA checkpoint — the per-SSRC ROC + outbound SRTCP index that are estimated from observed
    /// packets and so cannot be re-derived from the SDES keys on a standby (RFC 3711 §3.3.1 / §3.4).
    /// `None` if the call is unknown or is not a secure-transcode call. The lock is held only for the
    /// snapshot copy (no `.await` under it), so it never blocks the actor's per-packet path materially.
    #[must_use]
    pub fn rollover_snapshot(&self, call_id: &str) -> Option<SecureLegRollover> {
        let handle = self.calls.get(call_id)?;
        let leg = handle.secure_leg.as_ref()?;
        let guard = leg.lock().ok()?;
        Some(guard.rollover_snapshot())
    }

    /// Whether `call_id` is a **transcoding** media call (decode/re-encode), i.e. registered and not
    /// relay-only. The silence/play/DTMF verbs need a transcoding call (they own the egress codec); a
    /// promoted passthrough relay forwards opaque payloads and cannot synthesize audio.
    #[must_use]
    pub fn is_transcoding_call(&self, call_id: &str) -> bool {
        self.calls
            .get(call_id)
            .is_some_and(|handle| !handle.relay_only)
    }

    /// Count of live **transcoding** media calls (excludes promoted relay-only passthrough calls) —
    /// the expensive, decode/re-encode subset the cluster `load` command reports so a dispatcher can
    /// weight a node's real cost above its raw call count.
    #[must_use]
    pub fn transcode_call_count(&self) -> usize {
        self.calls
            .iter()
            .filter(|entry| !entry.value().relay_only)
            .count()
    }

    /// Whether `call_id` is a promoted relay-only call (a passthrough leg taken to userspace for a
    /// SIPREC raw tee). Used to decide whether `unsubscribe` should demote it back to in-kernel
    /// `Forward` once its last subscription is gone.
    #[must_use]
    pub fn is_relay_call(&self, call_id: &str) -> bool {
        self.calls
            .get(call_id)
            .is_some_and(|handle| handle.relay_only)
    }

    /// Tear a call's actor down: stop it (flushing recordings), drop its routes, and abort the task.
    pub fn deregister(&self, call_id: &str) {
        if let Some((_, handle)) = self.calls.remove(call_id) {
            let _ = handle
                .mailbox
                .try_send(MediaInput::Control(MediaControl::Stop));
            for endpoint in handle
                .endpoints
                .iter()
                .copied()
                .chain(handle.rtcp_endpoints.iter().copied())
            {
                self.routes.remove(&endpoint);
            }
            handle.task.abort();
        }
    }
}

/// The async actor for one media-processing call: drain its mailbox, run [`MediaCall::process`], and
/// perform the datapath I/O + event emission. Exits on `Stop`, mailbox close, or task abort.
async fn run_media_call<D>(
    mut call: MediaCall,
    inbox: flume::Receiver<MediaInput>,
    datapath: D,
    events: Option<flume::Sender<Event>>,
) where
    D: Datapath,
{
    let mut outbound = Vec::new();
    let mut emitted = Vec::new();
    // The playout clock drives injected prompts / DTMF (PlayMedia / PlayDtmf). It runs always but is
    // a no-op unless an injection is active; `Skip` keeps it from bursting after a stall.
    let mut ticker = tokio::time::interval(INJECT_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            input = inbox.recv_async() => {
                let Ok(input) = input else { break };
                match input {
                    MediaInput::Packet(packet) => {
                        outbound.clear();
                        emitted.clear();
                        call.process(&packet, &mut outbound, &mut emitted);
                        send_all(&datapath, &mut outbound).await;
                        for event in emitted.drain(..) {
                            if let Some(sink) = &events {
                                if sink.try_send(event).is_err() {
                                    tracing::debug!("media-pipeline event dropped (sink full or closed)");
                                }
                            }
                        }
                    }
                    MediaInput::Control(MediaControl::Silence(on)) => call.set_silenced(on),
                    MediaInput::Control(MediaControl::Block(on)) => call.set_blocked(on),
                    MediaInput::Control(MediaControl::Echo(on)) => call.set_echo(on),
                    MediaInput::Control(MediaControl::BlockDtmf { source_a, blocked }) => {
                        call.set_dtmf_blocked(source_a, blocked);
                    }
                    MediaInput::Control(MediaControl::PlayAudio { toward_a, player }) => {
                        call.start_play_audio(toward_a, *player);
                    }
                    MediaInput::Control(MediaControl::PlayDtmf { toward_a, digit, duration_ms, volume }) => {
                        call.start_play_dtmf(toward_a, digit, duration_ms, volume);
                    }
                    MediaInput::Control(MediaControl::StopPlay) => call.stop_play(),
                    MediaInput::Control(MediaControl::AddFork { source_a, sink }) => {
                        call.add_fork(source_a, sink);
                    }
                    MediaInput::Control(MediaControl::RemoveFork { source_a }) => {
                        call.remove_forks(source_a);
                    }
                    MediaInput::Control(MediaControl::AddRawTee { source_a, tee }) => {
                        call.add_raw_tee(source_a, tee);
                    }
                    MediaInput::Control(MediaControl::RemoveRawTee { source_a, subscriber_endpoint }) => {
                        call.remove_raw_tee(source_a, subscriber_endpoint);
                    }
                    MediaInput::Control(MediaControl::StartRecording { capture }) => {
                        call.start_recording(capture);
                    }
                    MediaInput::Control(MediaControl::StopRecording) => call.stop_recording(),
                    MediaInput::Control(MediaControl::Stop) => break,
                }
            }
            _ = ticker.tick() => {
                if call.has_injection() {
                    outbound.clear();
                    call.tick(&mut outbound);
                    send_all(&datapath, &mut outbound).await;
                }
            }
        }
    }
    // Flush recordings on teardown (one-shot; tokio::fs keeps the runtime non-blocking).
    for (path, bytes) in call.take_recordings() {
        if let Err(error) = tokio::fs::write(&path, &bytes).await {
            tracing::warn!(%error, path, "media-pipeline failed to write recording");
        } else {
            tracing::info!(path, "media-pipeline wrote recording");
        }
    }
}

/// Transmit every queued outbound datagram, draining the buffer. Send errors are logged, never
/// propagated — a transient socket error must not stall the actor.
async fn send_all<D: Datapath>(datapath: &D, outbound: &mut Vec<Outbound>) {
    for datagram in outbound.drain(..) {
        if let Err(error) = datapath
            .send(datagram.endpoint, datagram.dst, &datagram.data)
            .await
        {
            tracing::debug!(%error, "media-pipeline send failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_codec::g711::G711;
    use siphon_rtp_codec::g722::G722;
    use siphon_rtp_codec::l16::L16;
    use std::net::{IpAddr, Ipv4Addr};

    const A_ADDR: &str = "127.0.0.2:5000";
    const B_ADDR: &str = "127.0.0.3:6000";

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("addr")
    }

    fn endpoint(id: u64) -> EndpointId {
        EndpointId(id)
    }

    /// Build a µ-law(A) ↔ A-law(B) transcoding call, both legs 8 kHz/20 ms.
    fn ulaw_alaw_call() -> MediaCall {
        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1), // A's engine socket
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(2), // B's engine socket
            egress_dst: addr(B_ADDR),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::alaw()),
            egress_ssrc: 0xB000_0001,
            egress_payload_type: 8,
            telephone_event_in: Some(101),
            telephone_event_out: Some(101),
            recorder: None,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Exact(addr(B_ADDR).ip()),
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: Box::new(G711::alaw()),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 0xA000_0001,
            egress_payload_type: 0,
            telephone_event_in: Some(101),
            telephone_event_out: Some(101),
            recorder: None,
        };
        MediaCall::new(
            "call-1",
            "tag-a",
            Some("tag-b".into()),
            a_to_b,
            b_to_a,
            true,
            None,
        )
    }

    fn ulaw_rtp(sequence: u16, payload_byte: u8) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 0,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 0x1234_5678,
        };
        let payload = [payload_byte; 160];
        let mut buffer = vec![0u8; 12 + payload.len()];
        let len = write_packet(&header, &payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    fn rx(endpoint_id: u64, source: &str, data: Vec<u8>) -> RxPacket {
        RxPacket {
            endpoint: endpoint(endpoint_id),
            source: addr(source),
            arrival: 0,
            data: Bytes::from(data),
        }
    }

    /// A G.722 RTP packet: PT 9, a 160-byte payload (20 ms of codes), timestamp on the 8 kHz RTP
    /// clock (RFC 3551 §4.5.2 — 160 timestamp units per 20 ms despite 16 kHz audio).
    fn g722_rtp(sequence: u16) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 9,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 0x1234_5678,
        };
        let payload = [0x55u8; 160];
        let mut buffer = vec![0u8; 12 + payload.len()];
        let len = write_packet(&header, &payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    #[test]
    fn transcodes_ulaw_to_alaw_for_the_far_leg() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(100, 0xFF)), &mut out, &mut events);

        assert_eq!(out.len(), 1, "one transcoded packet toward B");
        let datagram = &out[0];
        assert_eq!(datagram.endpoint, endpoint(2), "sent from B's socket");
        let packet = RtpPacket::parse(&datagram.data).expect("parse");
        assert_eq!(packet.payload_type, 8, "re-encoded as A-law (PT 8)");
        assert_eq!(packet.ssrc, 0xB000_0001, "stamped with the A→B egress SSRC");
        assert_eq!(packet.payload.len(), 160);
        // µ-law 0xFF and A-law decode of that sample differ at the byte level → genuinely transcoded.
        assert_ne!(packet.payload, &[0xFFu8; 160][..]);
        assert!(events.is_empty());
    }

    /// Build a µ-law(A) → A-law(B) transcoding call whose **A→B egress** encoder packetizes at
    /// `egress_ptime_ms`, so the repacketizer must re-frame A's 20 ms ingress to that egress ptime.
    fn ulaw_to_alaw_egress_ptime(egress_ptime_ms: u8) -> MediaCall {
        use siphon_rtp_codec::g711::Variant;
        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::new(Variant::Alaw, egress_ptime_ms)),
            egress_ssrc: 0xB000_0001,
            egress_payload_type: 8,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Exact(addr(B_ADDR).ip()),
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: Box::new(G711::alaw()),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 0xA000_0001,
            egress_payload_type: 0,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
        };
        MediaCall::new(
            "call-ptime",
            "tag-a",
            Some("tag-b".into()),
            a_to_b,
            b_to_a,
            true,
            None,
        )
    }

    /// A µ-law RTP packet of `samples` bytes (one sample/byte at 8 kHz) with an explicit marker bit.
    fn ulaw_rtp_frame(sequence: u16, payload_byte: u8, samples: usize, marker: bool) -> Vec<u8> {
        let header = RtpHeader {
            marker,
            payload_type: 0,
            sequence,
            timestamp: u32::from(sequence) * samples as u32,
            ssrc: 0x1234_5678,
        };
        let payload = vec![payload_byte; samples];
        let mut buffer = vec![0u8; 12 + payload.len()];
        let len = write_packet(&header, &payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    #[test]
    fn repacketizes_two_20ms_ingress_frames_into_one_40ms_egress_packet() {
        // A→B egress ptime overridden to 40 ms: two 20 ms µ-law frames in → one 40 ms A-law packet out.
        let mut call = ulaw_to_alaw_egress_ptime(40);
        let mut out = Vec::new();
        let mut events = Vec::new();

        // First 20 ms frame buffers — it is not yet a full 40 ms egress frame.
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut events);
        assert!(
            out.is_empty(),
            "first 20 ms frame buffered, no egress packet yet"
        );

        // Second 20 ms frame completes a 40 ms egress frame → exactly one packet.
        call.process(&rx(1, A_ADDR, ulaw_rtp(2, 0xFF)), &mut out, &mut events);
        assert_eq!(
            out.len(),
            1,
            "two 20 ms ingress frames → one 40 ms egress packet"
        );
        let packet = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(packet.payload_type, 8, "re-encoded as A-law");
        assert_eq!(
            packet.payload.len(),
            320,
            "40 ms at 8 kHz = 320 samples (summed frame count)"
        );
        assert_eq!(packet.sequence, 0, "first egress sequence");
        assert_eq!(packet.timestamp, 0, "first egress timestamp");

        // Two more frames make the next 40 ms packet: sequence +1, timestamp +320 (RFC 3550 §5.1).
        out.clear();
        call.process(&rx(1, A_ADDR, ulaw_rtp(3, 0xFF)), &mut out, &mut events);
        assert!(out.is_empty());
        call.process(&rx(1, A_ADDR, ulaw_rtp(4, 0xFF)), &mut out, &mut events);
        assert_eq!(out.len(), 1);
        let next = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(
            next.sequence, 1,
            "sequence increments by 1 per egress packet"
        );
        assert_eq!(
            next.timestamp, 320,
            "timestamp advances by the 40 ms egress sample count (RFC 3550 §5.1)"
        );
    }

    #[test]
    fn repacketizes_one_20ms_ingress_frame_into_two_10ms_egress_packets() {
        // A→B egress ptime overridden to 10 ms: one 20 ms µ-law frame in → two 10 ms A-law packets out.
        let mut call = ulaw_to_alaw_egress_ptime(10);
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut events);
        assert_eq!(
            out.len(),
            2,
            "one 20 ms ingress frame → two 10 ms egress packets"
        );
        let first = RtpPacket::parse(&out[0].data).expect("parse");
        let second = RtpPacket::parse(&out[1].data).expect("parse");
        assert_eq!(first.payload.len(), 80, "10 ms at 8 kHz");
        assert_eq!(second.payload.len(), 80);
        assert_eq!(
            second.sequence,
            first.sequence.wrapping_add(1),
            "two sequence numbers, +1"
        );
        assert_eq!(
            second.timestamp.wrapping_sub(first.timestamp),
            80,
            "10 ms apart in the 8 kHz egress clock"
        );
    }

    #[test]
    fn fractional_30ms_ingress_to_20ms_egress_loses_no_samples_across_the_stream() {
        // A→B egress ptime 20 ms (default), ingress 30 ms (240-sample µ-law): a fractional 3:2 ratio
        // that buffers across packets. Over the stream the egress packet count and contiguous RTP
        // timestamps prove no samples are lost or duplicated (byte-accounted).
        let mut call = ulaw_to_alaw_egress_ptime(20);
        let mut out = Vec::new();
        let mut events = Vec::new();
        let ingress_frames = 8u16;
        for sequence in 1..=ingress_frames {
            call.process(
                &rx(1, A_ADDR, ulaw_rtp_frame(sequence, 0x40, 240, false)),
                &mut out,
                &mut events,
            );
        }
        // 8 × 240 = 1920 egress samples ÷ 160 (20 ms) = exactly 12 egress packets, 0 leftover.
        assert_eq!(
            out.len(),
            12,
            "1920 egress samples re-framed into twelve 20 ms packets"
        );
        for (index, datagram) in out.iter().enumerate() {
            let packet = RtpPacket::parse(&datagram.data).expect("parse");
            assert_eq!(
                packet.payload.len(),
                160,
                "each egress packet is a full 20 ms frame"
            );
            assert_eq!(packet.sequence, index as u16, "contiguous egress sequence");
            assert_eq!(
                packet.timestamp,
                index as u32 * 160,
                "contiguous egress timestamps — no samples dropped or duplicated"
            );
        }
    }

    /// Build a G.722 ↔ G.722 call whose A→B egress packetizes at `egress_ptime_ms`. G.722 samples
    /// 16 kHz but clocks RTP at 8 kHz (RFC 3551 §4.5.2), so the egress timestamp steps by ptime × 8 kHz.
    fn g722_call(egress_ptime_ms: u8) -> MediaCall {
        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            decoder: Box::new(G722::new(20)),
            encoder: Box::new(G722::new(egress_ptime_ms)),
            egress_ssrc: 0xB000_0009,
            egress_payload_type: 9,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Exact(addr(B_ADDR).ip()),
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: Box::new(G722::new(20)),
            encoder: Box::new(G722::new(20)),
            egress_ssrc: 0xA000_0009,
            egress_payload_type: 9,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
        };
        MediaCall::new(
            "call-g722",
            "tag-a",
            Some("tag-b".into()),
            a_to_b,
            b_to_a,
            true,
            None,
        )
    }

    #[test]
    fn g722_egress_timestamp_uses_the_8khz_rtp_clock_not_the_16khz_sample_rate() {
        // A→B egress ptime overridden to 40 ms: four 20 ms G.722 frames → two 40 ms egress packets.
        let mut call = g722_call(40);
        let mut out = Vec::new();
        for sequence in 1..=4 {
            call.process(
                &rx(1, A_ADDR, g722_rtp(sequence)),
                &mut out,
                &mut Vec::new(),
            );
        }
        assert_eq!(
            out.len(),
            2,
            "four 20 ms G.722 frames → two 40 ms egress packets"
        );
        let first = RtpPacket::parse(&out[0].data).expect("parse");
        let second = RtpPacket::parse(&out[1].data).expect("parse");
        // 40 ms × 8000 Hz ÷ 1000 = 320 ts units — NOT 40 × 16000 ÷ 1000 = 640 (RFC 3551 §4.5.2).
        assert_eq!(
            second.timestamp.wrapping_sub(first.timestamp),
            320,
            "G.722 advances the 8 kHz RTP clock (ptime × 8000 ÷ 1000), not the 16 kHz sample rate"
        );
        assert_eq!(
            first.payload.len(),
            320,
            "40 ms of G.722 codes (2 samples/byte at 16 kHz)"
        );
    }

    #[test]
    fn egress_marker_follows_the_ingress_talkspurt_not_a_blind_copy() {
        // 1:1 20 ms transcode: the egress marker must track the sender's talkspurt boundary
        // (RFC 3550 §5.1), never a blind per-packet copy.
        let mut call = ulaw_to_alaw_egress_ptime(20);
        let mut out = Vec::new();
        let mut events = Vec::new();

        // Mid-stream (no marker) → egress marker clear.
        call.process(
            &rx(1, A_ADDR, ulaw_rtp_frame(1, 0xFF, 160, false)),
            &mut out,
            &mut events,
        );
        assert_eq!(out.len(), 1);
        assert!(
            !RtpPacket::parse(&out[0].data).expect("parse").marker,
            "no talkspurt marker to copy"
        );

        // Talkspurt restart (marker set) → the next egress packet carries the marker.
        out.clear();
        call.process(
            &rx(1, A_ADDR, ulaw_rtp_frame(2, 0xFF, 160, true)),
            &mut out,
            &mut events,
        );
        assert_eq!(out.len(), 1);
        assert!(
            RtpPacket::parse(&out[0].data).expect("parse").marker,
            "talkspurt start propagated"
        );

        // Continuation (no marker) → the marker is not sticky.
        out.clear();
        call.process(
            &rx(1, A_ADDR, ulaw_rtp_frame(3, 0xFF, 160, false)),
            &mut out,
            &mut events,
        );
        assert_eq!(out.len(), 1);
        assert!(
            !RtpPacket::parse(&out[0].data).expect("parse").marker,
            "marker cleared after one packet"
        );
    }

    #[test]
    fn buffered_talkspurt_marker_rides_to_the_first_full_egress_frame() {
        // A marked ingress frame that only buffers (20 ms into a 40 ms egress) must not lose its
        // talkspurt marker — it rides to the first egress packet that carries the talkspurt start.
        let mut call = ulaw_to_alaw_egress_ptime(40);
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(
            &rx(1, A_ADDR, ulaw_rtp_frame(1, 0xFF, 160, true)),
            &mut out,
            &mut events,
        );
        assert!(
            out.is_empty(),
            "marked frame buffered, no egress packet yet"
        );
        call.process(
            &rx(1, A_ADDR, ulaw_rtp_frame(2, 0xFF, 160, false)),
            &mut out,
            &mut events,
        );
        assert_eq!(out.len(), 1);
        assert!(
            RtpPacket::parse(&out[0].data).expect("parse").marker,
            "the buffered talkspurt marker rides to the first full 40 ms egress packet"
        );
    }

    /// An AMR-WB RTP packet (PT 96) carrying `payload`, with the 16 kHz RTP clock (320 ts units per
    /// 20 ms frame).
    #[cfg(feature = "amr")]
    fn amr_wb_rtp(sequence: u16, payload: &[u8]) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 96,
            sequence,
            timestamp: u32::from(sequence) * 320,
            ssrc: 0x1234_5678,
        };
        let mut buffer = vec![0u8; 12 + payload.len()];
        let len = write_packet(&header, payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    /// The BGCF/SBC PSTN-breakout core: a VoLTE AMR-WB (16 kHz) leg transcoded to a PSTN G.711a
    /// (8 kHz) leg through the media slow path — decode → 16→8 kHz resample → re-encode. Drives the
    /// real `process()` (the same call the live actor makes at run_media_call:1116), so it proves the
    /// transcode+resample chain deterministically, independent of the async datapath. Feature-gated
    /// on `amr` (patent-licensed — docs/codec-licensing.md).
    #[cfg(feature = "amr")]
    #[test]
    fn transcodes_amr_wb_to_g711a_with_resampling() {
        use siphon_rtp_codec::factory::{decoder_for, encoder_for, CodecSpec};

        // Encode 20 ms of 16 kHz PCM into an RFC 4867 octet-aligned AMR-WB payload (VoLTE wire form).
        let mut amr_encoder =
            encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20)).expect("amr-wb encoder");
        let pcm: Vec<i16> = (0..320)
            .map(|i| ((i as f32 * 0.20).sin() * 6000.0) as i16)
            .collect();
        let mut amr_payload = vec![0u8; 256];
        let written = amr_encoder
            .encode(&pcm, &mut amr_payload)
            .expect("encode amr-wb");
        amr_payload.truncate(written);
        assert!(written > 0, "AMR-WB encoder produced a payload");

        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            decoder: decoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20))
                .expect("amr-wb decoder"),
            encoder: encoder_for(&CodecSpec::new(8, "PCMA", 8000, 1, 20)).expect("pcma encoder"),
            egress_ssrc: 0xB000_0008,
            egress_payload_type: 8,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Exact(addr(B_ADDR).ip()),
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: decoder_for(&CodecSpec::new(8, "PCMA", 8000, 1, 20)).expect("pcma decoder"),
            encoder: encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20))
                .expect("amr-wb encoder"),
            egress_ssrc: 0xA000_0060,
            egress_payload_type: 96,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
        };
        let mut call = MediaCall::new(
            "amr-call",
            "tag-a",
            Some("tag-b".into()),
            a_to_b,
            b_to_a,
            true,
            None,
        );
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(
            &rx(1, A_ADDR, amr_wb_rtp(1, &amr_payload)),
            &mut out,
            &mut events,
        );

        assert_eq!(out.len(), 1, "one transcoded G.711a packet toward B");
        let datagram = &out[0];
        assert_eq!(
            datagram.endpoint,
            endpoint(2),
            "sent from B's engine socket"
        );
        let packet = RtpPacket::parse(&datagram.data).expect("parse");
        assert_eq!(packet.payload_type, 8, "re-encoded as G.711a (PT 8)");
        assert_eq!(packet.payload.len(), 160, "20 ms at 8 kHz, 1 byte/sample");
        assert_eq!(packet.ssrc, 0xB000_0008, "stamped with the A→B egress SSRC");
        assert!(
            packet.payload.iter().any(|&byte| byte != 0xD5),
            "transcoded G.711a carries non-silence audio"
        );
    }

    /// RFC 4867 §4.3.1: a Codec Mode Request on the A→B stream steers the mode of the AMR-WB stream
    /// the engine sends *back* to A (the b_to_a egress encoder), clamped to any `mode-set`. Proves the
    /// cross-direction wiring in `process()`.
    #[cfg(feature = "amr")]
    #[test]
    fn amr_wb_cmr_steers_the_reverse_direction_encoder() {
        use siphon_rtp_codec::factory::{decoder_for, encoder_for, CodecSpec};

        let amr_dir =
            |ingress: u64, src: &str, egress: u64, dst: &str, ssrc: u32| DirectionConfig {
                ingress_endpoint: endpoint(ingress),
                accepted_source: SourceFilter::Exact(addr(src).ip()),
                egress_endpoint: endpoint(egress),
                egress_dst: addr(dst),
                decoder: decoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20)).expect("dec"),
                encoder: encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20)).expect("enc"),
                egress_ssrc: ssrc,
                egress_payload_type: 96,
                telephone_event_in: None,
                telephone_event_out: None,
                recorder: None,
            };

        // A payload at the default mode 2; flip its CMR nibble to request mode 0 for the B→A stream.
        let mut encoder = encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20)).expect("enc");
        let pcm: Vec<i16> = (0..320)
            .map(|i| ((i as f32 * 0.2).sin() * 6000.0) as i16)
            .collect();
        let mut a_payload = vec![0u8; 256];
        let len_a = encoder.encode(&pcm, &mut a_payload).expect("encode");
        a_payload.truncate(len_a);
        a_payload[0] = 0x00; // CMR = 0 (request mode 0)
                             // B's payload carries no request (CMR 15, as emitted).
        let mut b_payload = vec![0u8; 256];
        let len_b = encoder.encode(&pcm, &mut b_payload).expect("encode");
        b_payload.truncate(len_b);

        let mut call = MediaCall::new(
            "cmr",
            "tag-a",
            Some("tag-b".into()),
            amr_dir(1, A_ADDR, 2, B_ADDR, 0xB000_0060),
            amr_dir(2, B_ADDR, 1, A_ADDR, 0xA000_0060),
            true,
            None,
        );
        let mut out = Vec::new();
        let mut events = Vec::new();

        // A→B carries CMR 0 → the toward-A encoder switches to mode 0.
        call.process(
            &rx(1, A_ADDR, amr_wb_rtp(1, &a_payload)),
            &mut out,
            &mut events,
        );
        out.clear();
        // B→A: the reverse egress toward A is now encoded at the requested mode 0.
        call.process(
            &rx(2, B_ADDR, amr_wb_rtp(1, &b_payload)),
            &mut out,
            &mut events,
        );
        assert_eq!(out.len(), 1, "one AMR-WB packet toward A");
        let packet = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(packet.payload_type, 96, "AMR-WB toward A");
        assert_eq!(
            (packet.payload[1] >> 3) & 0x0F,
            0,
            "toward-A egress adapted to the CMR-requested mode 0"
        );
    }

    /// A minimal RTCP sender-report-shaped datagram (version 2, PT 200) carrying `ssrc` — the shape
    /// [`is_rtcp`] classifies as RTCP and the SRTCP contexts (de)crypt.
    fn rtcp_sr(ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 200, 0x00, 0x00];
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0x33; 16]);
        packet
    }

    #[test]
    fn non_muxed_srtcp_is_relayed_through_the_shared_secure_leg() {
        use siphon_rtp_srtp::sdes::SrtpKeyMaterial;

        // The engine's leg (actor) and the far peer B's leg are key-inverses of one another.
        let engine_key = SrtpKeyMaterial::from_inline_bytes(&[7u8; 30]).expect("engine key");
        let b_key = SrtpKeyMaterial::from_inline_bytes(&[9u8; 30]).expect("b key");
        let actor_leg = Arc::new(Mutex::new(SecureLeg::new(&engine_key, &b_key)));
        let mut peer_leg = SecureLeg::new(&b_key, &engine_key); // stands in for the secure peer B

        // Trivial RTP directions (unused by the RTCP path) on endpoints 1/2; RTCP on 3 (A) / 4 (B).
        let g711 = |ingress: u64, src: &str, egress: u64, dst: &str| DirectionConfig {
            ingress_endpoint: endpoint(ingress),
            accepted_source: SourceFilter::Exact(addr(src).ip()),
            egress_endpoint: endpoint(egress),
            egress_dst: addr(dst),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 0x1111_1111,
            egress_payload_type: 0,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
        };
        let a_rtcp = "127.0.0.2:5001";
        let b_rtcp = "127.0.0.3:6001";
        let relays = vec![
            // A's RTCP (plaintext) → encrypt toward secure B.
            RtcpRelay::new(
                endpoint(3),
                SourceFilter::Exact(addr(a_rtcp).ip()),
                endpoint(4),
                addr(b_rtcp),
            )
            .with_secure_egress(actor_leg.clone()),
            // B's SRTCP → decrypt toward plaintext A.
            RtcpRelay::new(
                endpoint(4),
                SourceFilter::Exact(addr(b_rtcp).ip()),
                endpoint(3),
                addr(a_rtcp),
            )
            .with_secure_ingress(actor_leg.clone()),
        ];
        let mut call = MediaCall::new(
            "srtcp",
            "tag-a",
            Some("tag-b".into()),
            g711(1, A_ADDR, 2, B_ADDR),
            g711(2, B_ADDR, 1, A_ADDR),
            true,
            None,
        )
        .with_far_secure_leg(actor_leg.clone())
        .with_rtcp_relays(relays);
        assert_eq!(call.rtcp_endpoints(), vec![endpoint(3), endpoint(4)]);

        let mut out = Vec::new();
        let mut events = Vec::new();

        // B → A: B encrypts an RTCP SR with its key; the actor decrypts and relays plaintext to A.
        let b_rtcp_plain = rtcp_sr(0xB0B0_B0B0);
        let mut b_srtcp = Vec::new();
        peer_leg
            .protect(&b_rtcp_plain, &mut b_srtcp)
            .expect("peer encrypt SRTCP");
        call.process(&rx(4, b_rtcp, b_srtcp), &mut out, &mut events);
        assert_eq!(out.len(), 1, "one RTCP toward A");
        assert_eq!(out[0].endpoint, endpoint(3));
        assert_eq!(out[0].dst, addr(a_rtcp));
        assert_eq!(
            &out[0].data[..],
            &b_rtcp_plain[..],
            "decrypted plaintext RTCP toward A"
        );

        // A → B: A's plaintext RTCP is encrypted (SRTCP) toward B; the peer recovers it.
        out.clear();
        let a_rtcp_plain = rtcp_sr(0xA0A0_A0A0);
        call.process(&rx(3, a_rtcp, a_rtcp_plain.clone()), &mut out, &mut events);
        assert_eq!(out.len(), 1, "one SRTCP toward B");
        assert_eq!(out[0].endpoint, endpoint(4));
        assert_eq!(out[0].dst, addr(b_rtcp));
        assert_ne!(
            &out[0].data[..],
            &a_rtcp_plain[..],
            "toward B it is encrypted (SRTCP)"
        );
        let mut recovered = Vec::new();
        peer_leg
            .unprotect(&out[0].data, &mut recovered)
            .expect("peer decrypt SRTCP");
        assert_eq!(recovered, a_rtcp_plain, "B recovers A's RTCP");

        // An off-source RTCP is dropped by the RTPBleed gate on the RTCP endpoint.
        out.clear();
        call.process(&rx(4, "127.0.0.9:7000", rtcp_sr(1)), &mut out, &mut events);
        assert!(out.is_empty(), "unsignalled RTCP source dropped");
    }

    #[test]
    fn far_secure_leg_is_exposed_only_for_a_secure_call() {
        use siphon_rtp_srtp::sdes::SrtpKeyMaterial;

        let g711 = |ingress: u64, src: &str, egress: u64, dst: &str| DirectionConfig {
            ingress_endpoint: endpoint(ingress),
            accepted_source: SourceFilter::Exact(addr(src).ip()),
            egress_endpoint: endpoint(egress),
            egress_dst: addr(dst),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 0x1111_1111,
            egress_payload_type: 0,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
        };

        // A plaintext transcode call exposes no secure leg — an HA checkpoint has no SRTP rollover to
        // read (`rollover_snapshot` returns `None`, so `build_secure_media_snapshot` yields no secure
        // section).
        let plain = MediaCall::new(
            "plain",
            "tag-a",
            Some("tag-b".into()),
            g711(1, A_ADDR, 2, B_ADDR),
            g711(2, B_ADDR, 1, A_ADDR),
            true,
            None,
        );
        assert!(
            plain.far_secure_leg().is_none(),
            "a plaintext call has no shared secure leg"
        );

        // A secure-transcode call exposes the *same* shared leg both directions crypt against, so the
        // registry can retain it and checkpoint its rollover after the actor takes ownership.
        let local = SrtpKeyMaterial::from_inline_bytes(&[3u8; 30]).expect("local key");
        let remote = SrtpKeyMaterial::from_inline_bytes(&[4u8; 30]).expect("remote key");
        let leg = Arc::new(Mutex::new(SecureLeg::new(&local, &remote)));
        let secure = MediaCall::new(
            "secure",
            "tag-a",
            Some("tag-b".into()),
            g711(1, A_ADDR, 2, B_ADDR),
            g711(2, B_ADDR, 1, A_ADDR),
            true,
            None,
        )
        .with_far_secure_leg(leg.clone());
        let exposed = secure.far_secure_leg().expect("secure leg exposed");
        assert!(
            Arc::ptr_eq(&exposed, &leg),
            "the exact shared leg instance is returned"
        );
    }

    #[test]
    fn secure_egress_encrypts_relayed_telephone_event() {
        // Regression: a repacketized RFC 4733 telephone-event toward a secure (RTP/SAVP) peer must be
        // encrypted — it previously bypassed `push_egress` and leaked plaintext DTMF on the wire.
        use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
        use siphon_rtp_srtp::SrtpContext;

        let local = SrtpKeyMaterial::from_inline_bytes(&[1u8; 30]).expect("local key");
        let remote = SrtpKeyMaterial::from_inline_bytes(&[2u8; 30]).expect("remote key");
        let leg = Arc::new(Mutex::new(SecureLeg::new(&local, &remote)));

        let direction =
            |ingress: u64, src: &str, egress: u64, dst: &str, ssrc: u32| DirectionConfig {
                ingress_endpoint: endpoint(ingress),
                accepted_source: SourceFilter::Exact(addr(src).ip()),
                egress_endpoint: endpoint(egress),
                egress_dst: addr(dst),
                decoder: Box::new(G711::ulaw()),
                encoder: Box::new(G711::ulaw()),
                egress_ssrc: ssrc,
                egress_payload_type: 0,
                telephone_event_in: Some(101),
                telephone_event_out: Some(101),
                recorder: None,
            };
        let mut call = MediaCall::new(
            "te",
            "a",
            Some("b".into()),
            direction(1, A_ADDR, 2, B_ADDR, 0xB000_0101), // A→B: plaintext in, secure egress
            direction(2, B_ADDR, 1, A_ADDR, 0xA000_0101),
            true,
            None,
        )
        .with_far_secure_leg(leg);

        // A plaintext telephone-event (PT 101, RFC 4733 4-byte event) from A.
        let header = RtpHeader {
            marker: true,
            payload_type: 101,
            sequence: 1,
            timestamp: 160,
            ssrc: 0x1234_5678,
        };
        let mut buffer = vec![0u8; 12 + 4];
        let len = write_packet(&header, &[0x05, 0x0A, 0x01, 0x40], &mut buffer).expect("write");
        buffer.truncate(len);

        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, buffer.clone()), &mut out, &mut events);

        let egress = out
            .iter()
            .find(|outbound| outbound.endpoint == endpoint(2))
            .expect("an egress packet toward the secure peer B");
        assert_ne!(
            &egress.data[..],
            &buffer[..],
            "egress must not be the plaintext telephone-event"
        );
        // It is valid SRTP, decryptable with the engine's outbound (local) key to the event packet.
        let mut decrypt = SrtpContext::from_key_material(&local);
        let mut plain = Vec::new();
        decrypt
            .unprotect(&egress.data, &mut plain)
            .expect("egress is valid SRTP");
        let parsed = RtpPacket::parse(&plain).expect("decrypted telephone-event");
        assert_eq!(
            parsed.payload_type, 101,
            "egress is the repacketized telephone-event"
        );
    }

    #[test]
    fn egress_sequence_and_timestamp_advance_per_packet() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0x00)), &mut out, &mut events);
        call.process(&rx(1, A_ADDR, ulaw_rtp(2, 0x00)), &mut out, &mut events);
        let first = RtpPacket::parse(&out[0].data).expect("first");
        let second = RtpPacket::parse(&out[1].data).expect("second");
        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 1);
        assert_eq!(first.timestamp, 0);
        assert_eq!(second.timestamp, 160, "one 8 kHz/20 ms frame");
    }

    #[test]
    fn g722_egress_timestamp_steps_at_8khz_rtp_clock() {
        // A G.722 leg decodes 320 PCM samples per 20 ms frame, but its RTP timestamp clock is
        // 8 kHz (RFC 3551 §4.5.2), so the synthesized egress timestamp must advance by 160 — not
        // 320 — per packet. This proves Phase 0's RTP-clock-vs-native-rate split composes with the
        // codec's `rtp_clock_rate_hz()` end to end through the transcode path.
        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            decoder: Box::new(G722::new(20)),
            encoder: Box::new(G722::new(20)),
            egress_ssrc: 0xB000_0009,
            egress_payload_type: 9,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Any,
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: Box::new(G722::new(20)),
            encoder: Box::new(G722::new(20)),
            egress_ssrc: 0xA000_0009,
            egress_payload_type: 9,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
        };
        let mut call = MediaCall::new(
            "g722",
            "tag-a",
            Some("tag-b".into()),
            a_to_b,
            b_to_a,
            true,
            None,
        );
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, g722_rtp(1)), &mut out, &mut events);
        call.process(&rx(1, A_ADDR, g722_rtp(2)), &mut out, &mut events);

        assert_eq!(
            out.len(),
            2,
            "one transcoded G.722 packet per ingress frame"
        );
        let first = RtpPacket::parse(&out[0].data).expect("first");
        let second = RtpPacket::parse(&out[1].data).expect("second");
        assert_eq!(first.payload_type, 9, "re-encoded as G.722 (PT 9)");
        assert_eq!(
            first.payload.len(),
            160,
            "320 PCM samples → 160 G.722 bytes"
        );
        assert_eq!(first.timestamp, 0);
        assert_eq!(
            second.timestamp, 160,
            "G.722 egress advances at the 8 kHz RTP clock (160/frame), not the 320-sample count"
        );
    }

    #[test]
    fn drops_packets_from_an_unsignalled_source() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // An attacker on a different IP sprays A's endpoint — gated out before any transcode.
        call.process(
            &rx(1, "127.0.0.9:5000", ulaw_rtp(1, 0xFF)),
            &mut out,
            &mut events,
        );
        assert!(out.is_empty(), "off-source packet must not be forwarded");
    }

    #[test]
    fn latches_observed_source_for_symmetric_reply() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // B sends from a different *port* than signalled (symmetric NAT). The A→B direction must
        // now target B's observed source. Use the signalled IP so the gate passes.
        let observed = "127.0.0.3:44444";
        call.process(&rx(2, observed, alaw_rtp(1, 0x55)), &mut out, &mut events);
        // Now A sends; its packet should go to B's observed (latched) source.
        out.clear();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut events);
        assert_eq!(
            out[0].dst,
            addr(observed),
            "A→B latched to B's observed source"
        );
    }

    fn alaw_rtp(sequence: u16, payload_byte: u8) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 8,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 0x8765_4321,
        };
        let payload = [payload_byte; 160];
        let mut buffer = vec![0u8; 12 + payload.len()];
        let len = write_packet(&header, &payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    #[test]
    fn relays_rtcp_verbatim() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // A minimal RTCP Sender Report (PT 200): version 2, PT 200, length 6.
        let rtcp = vec![0x80, 200, 0x00, 0x06, 0xDE, 0xAD, 0xBE, 0xEF];
        call.process(&rx(1, A_ADDR, rtcp.clone()), &mut out, &mut events);
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0].data[..], &rtcp[..], "RTCP relayed untouched");
        assert_eq!(out[0].endpoint, endpoint(2));
    }

    #[test]
    fn block_suppresses_egress_then_resumes() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.set_blocked(true);
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut events);
        assert!(out.is_empty(), "blocked: no egress");
        call.set_blocked(false);
        call.process(&rx(1, A_ADDR, ulaw_rtp(2, 0xFF)), &mut out, &mut events);
        assert_eq!(out.len(), 1, "unblocked: egress resumes");
    }

    #[test]
    fn silence_replaces_audio_with_comfort_silence() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.set_silenced(true);
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0x00)), &mut out, &mut events);
        assert_eq!(out.len(), 1, "silence still emits a packet");
        let packet = RtpPacket::parse(&out[0].data).expect("parse");
        // A-law encoding of all-zero PCM is a constant byte; assert it is uniform (comfort silence).
        assert!(packet.payload.iter().all(|&byte| byte == packet.payload[0]));
    }

    #[test]
    fn extracts_dtmf_event_and_repacketizes() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // RFC 4733 telephone-event payload (PT 101): event 5, End bit set, volume 10, duration 800.
        let event_payload = [5u8, 0x80 | 10, 0x03, 0x20]; // E=1, volume=10, duration=0x0320=800
        let header = RtpHeader {
            marker: true,
            payload_type: 101,
            sequence: 1,
            timestamp: 16000,
            ssrc: 0x1111_2222,
        };
        let mut buffer = vec![0u8; 16];
        let len = write_packet(&header, &event_payload, &mut buffer).expect("write");
        buffer.truncate(len);

        call.process(&rx(1, A_ADDR, buffer), &mut out, &mut events);
        assert_eq!(events.len(), 1, "one DTMF event extracted");
        match &events[0] {
            Event::Dtmf {
                digit,
                duration_ms,
                call_id,
                ..
            } => {
                assert_eq!(digit, "5");
                assert_eq!(duration_ms, &100, "800 samples / 8 = 100 ms");
                assert_eq!(call_id, "call-1");
            }
            other => panic!("expected DTMF, got {other:?}"),
        }
        assert_eq!(out.len(), 1, "telephone-event repacketized onto egress");
        let relayed = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(relayed.payload_type, 101);
        assert_eq!(
            relayed.ssrc, 0xB000_0001,
            "stamped with the A→B egress SSRC"
        );
        assert_eq!(relayed.timestamp, 16000, "event RTP timestamp preserved");
    }

    #[test]
    fn echo_reflects_ingress_back_to_the_sender() {
        let mut call = ulaw_alaw_call();
        call.set_echo(true);
        let mut out = Vec::new();
        let mut events = Vec::new();

        // A speaks µ-law toward the engine; with echo on, it must come straight back to A.
        call.process(&rx(1, A_ADDR, ulaw_rtp(100, 0xFF)), &mut out, &mut events);

        assert_eq!(
            out.len(),
            1,
            "exactly one packet, reflected back to the sender"
        );
        let datagram = &out[0];
        assert_eq!(
            datagram.endpoint,
            endpoint(1),
            "echoed out A's own socket, not toward B"
        );
        assert_eq!(datagram.dst, addr(A_ADDR), "echoed back to A's address");
        let packet = RtpPacket::parse(&datagram.data).expect("parse");
        assert_eq!(
            packet.payload_type, 0,
            "re-encoded in A's own codec (µ-law PT 0)"
        );
        assert_eq!(
            packet.ssrc, 0xA000_0001,
            "stamped with the toward-A egress SSRC"
        );
        // Same codec in and out → decode+encode is idempotent, so A hears exactly what it sent.
        assert_eq!(packet.payload, &[0xFFu8; 160][..]);
        assert!(events.is_empty());

        // Toggling echo off restores normal forwarding toward the far leg.
        call.set_echo(false);
        out.clear();
        call.process(&rx(1, A_ADDR, ulaw_rtp(101, 0x00)), &mut out, &mut events);
        assert_eq!(
            out[0].endpoint,
            endpoint(2),
            "echo off → transcoded toward B again"
        );
    }

    #[test]
    fn echo_still_detects_dtmf_without_echoing_the_tone() {
        let mut call = ulaw_alaw_call();
        call.set_echo(true);
        let mut out = Vec::new();
        let mut events = Vec::new();

        // RFC 4733 '#' (event 11), End bit set — the digit the SBC echo test uses to hang up.
        let event_payload = [11u8, 0x80 | 10, 0x03, 0x20];
        let header = RtpHeader {
            marker: true,
            payload_type: 101,
            sequence: 1,
            timestamp: 16000,
            ssrc: 0x1111_2222,
        };
        let mut buffer = vec![0u8; 16];
        let len = write_packet(&header, &event_payload, &mut buffer).expect("write");
        buffer.truncate(len);

        call.process(&rx(1, A_ADDR, buffer), &mut out, &mut events);
        assert_eq!(
            events.len(),
            1,
            "DTMF still surfaces during echo (so '#' can end the test)"
        );
        match &events[0] {
            Event::Dtmf { digit, .. } => assert_eq!(digit, "#"),
            other => panic!("expected DTMF, got {other:?}"),
        }
        assert!(out.is_empty(), "the DTMF tone itself is not echoed back");
    }

    #[test]
    fn play_audio_injects_prompt_in_the_target_legs_codec() {
        use siphon_rtp_media::fanout::MediaSink as _;
        use siphon_rtp_media::player::WavSource;

        let mut call = ulaw_alaw_call();
        // An 8 kHz mono prompt: 320 samples = 40 ms → 2 frames at 20 ms ptime.
        let mut recorder = WavRecorder::new(8000, 1);
        recorder.write_pcm(&[2000i16; 320]);
        let wav = recorder.into_wav();
        let source = WavSource::parse(&wav).expect("parse wav");
        let player = PcmPlayer::new(&source, 1, 0);

        call.start_play_audio(true, player); // toward A (the b_to_a egress, µ-law PT 0)
        assert!(call.has_injection());

        let mut out = Vec::new();
        call.tick(&mut out);
        assert_eq!(out.len(), 1, "one prompt packet per playout tick");
        let packet = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(out[0].endpoint, endpoint(1), "prompt goes out A's socket");
        assert_eq!(
            packet.payload_type, 0,
            "prompt encoded in A's codec (µ-law)"
        );

        // While the prompt plays toward A, B→A transcode is suppressed (A hears the prompt only).
        out.clear();
        call.process(&rx(2, B_ADDR, alaw_rtp(1, 0x55)), &mut out, &mut Vec::new());
        assert!(
            out.is_empty(),
            "transcode toward A is suppressed during playback"
        );

        // Second tick drains the rest; a third finds the prompt exhausted and clears the injection.
        out.clear();
        call.tick(&mut out);
        assert_eq!(out.len(), 1);
        out.clear();
        call.tick(&mut out);
        assert!(
            !call.has_injection(),
            "injection cleared when the prompt ends"
        );
    }

    #[test]
    fn play_dtmf_injects_telephone_events_toward_the_target() {
        let mut call = ulaw_alaw_call();
        assert!(
            call.start_play_dtmf(true, '5', 100, 10),
            "A negotiated telephone-event"
        );
        let mut out = Vec::new();
        call.tick(&mut out);
        assert_eq!(out.len(), 1);
        let packet = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(packet.payload_type, 101, "egress telephone-event PT");
        assert_eq!(packet.payload[0], 5, "RFC 4733 event code for '5'");
        assert!(
            packet.marker,
            "first packet of the event carries the marker"
        );
    }

    #[test]
    fn play_dtmf_fails_without_a_negotiated_telephone_event() {
        // A direction with no egress telephone-event PT cannot carry DTMF.
        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Any,
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 1,
            egress_payload_type: 0,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Any,
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 2,
            egress_payload_type: 0,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
        };
        let mut call = MediaCall::new("c", "a", None, a_to_b, b_to_a, true, None);
        assert!(
            !call.start_play_dtmf(true, '5', 100, 10),
            "no telephone-event ⇒ cannot inject"
        );
    }

    #[test]
    fn a_fork_emits_rtp_alongside_the_transcoded_egress() {
        use siphon_rtp_media::fork::RtpForkSink;

        // Fork leg A's decoded audio to a subscriber as µ-law (PT 0, SSRC 0xFEED_F00D), while A→B
        // still transcodes to A-law. One ingress packet ⇒ one transcoded egress AND one forked RTP.
        let mut call = ulaw_alaw_call();
        let (fork_tx, fork_rx) = flume::bounded(8);
        let sink = RtpForkSink::new(Box::new(G711::ulaw()), fork_tx, 0xFEED_F00D, 0);
        call.add_fork(true, Box::new(sink));
        assert_eq!(call.fork_count(true), 1);

        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(100, 0x40)), &mut out, &mut events);

        // The normal transcoded packet toward B is undisturbed (A-law, PT 8, the A→B egress SSRC).
        assert_eq!(out.len(), 1, "one transcoded packet toward B");
        let egress = RtpPacket::parse(&out[0].data).expect("egress parse");
        assert_eq!(egress.payload_type, 8, "B still gets A-law");
        assert_eq!(egress.ssrc, 0xB000_0001);

        // The fork received a well-formed RTP packet with the subscriber's PT/SSRC.
        let forked_bytes = fork_rx.try_recv().expect("one forked packet");
        let forked = RtpPacket::parse(&forked_bytes).expect("fork parse");
        assert_eq!(forked.payload_type, 0, "fork re-encoded as µ-law (PT 0)");
        assert_eq!(
            forked.ssrc, 0xFEED_F00D,
            "fork stamped with the subscriber SSRC"
        );
        assert_eq!(forked.sequence, 0, "fork egress sequence starts at 0");
        assert_eq!(forked.payload.len(), 160);

        // A second ingress packet advances the fork's egress sequence independently of the A→B stream.
        out.clear();
        call.process(&rx(1, A_ADDR, ulaw_rtp(101, 0x40)), &mut out, &mut events);
        let second_bytes = fork_rx.try_recv().expect("second forked packet");
        let second = RtpPacket::parse(&second_bytes).expect("parse");
        assert_eq!(second.sequence, 1, "fork sequence advances per frame");
    }

    #[test]
    fn remove_fork_stops_forwarding_and_keeps_transcode() {
        use siphon_rtp_media::fork::RtpForkSink;

        let mut call = ulaw_alaw_call();
        let (fork_tx, fork_rx) = flume::bounded(8);
        call.add_fork(
            true,
            Box::new(RtpForkSink::new(Box::new(G711::ulaw()), fork_tx, 7, 0)),
        );

        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0x40)), &mut out, &mut events);
        assert!(fork_rx.try_recv().is_ok(), "fork forwarded while attached");

        call.remove_forks(true);
        assert_eq!(call.fork_count(true), 0);
        out.clear();
        call.process(&rx(1, A_ADDR, ulaw_rtp(2, 0x40)), &mut out, &mut events);
        assert_eq!(
            out.len(),
            1,
            "transcode toward B continues after the fork is removed"
        );
        assert!(
            fork_rx.try_recv().is_err(),
            "no more forked packets after remove"
        );
    }

    /// A single RFC 4733 telephone-event RTP packet on PT 101 (digit 5, end bit set) — the fixture
    /// the DTMF tests share. `marker` starts the event, `end` sets the RFC 4733 end bit. `timestamp`
    /// keys the detector's event boundary — each distinct value is a fresh event (RFC 4733 §2.5.1.2).
    fn telephone_event_rtp(sequence: u16, timestamp: u32, marker: bool, end: bool) -> Vec<u8> {
        // event=5, E-bit per `end`, volume 10, duration 0x0320. RFC 4733 §2.3 payload layout.
        let event_payload = [5u8, ((end as u8) << 7) | 10, 0x03, 0x20];
        let header = RtpHeader {
            marker,
            payload_type: 101,
            sequence,
            timestamp,
            ssrc: 0x1111_2222,
        };
        let mut buffer = vec![0u8; 16];
        let len = write_packet(&header, &event_payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    #[test]
    fn block_dtmf_drops_telephone_event_relay_but_still_emits_the_event() {
        // On a transcoding call, a telephone-event from A with dtmf_blocked is NOT relayed to B
        // (no egress telephone-event), but the control-plane Event::Dtmf still fires (observability).
        // Clearing the block restores the relay.
        let mut call = ulaw_alaw_call();
        call.set_dtmf_blocked(true, true); // block A's DTMF toward B

        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(
            &rx(1, A_ADDR, telephone_event_rtp(1, 16000, true, true)),
            &mut out,
            &mut events,
        );
        assert_eq!(
            events.len(),
            1,
            "DTMF still detected + emitted while blocked"
        );
        assert!(
            matches!(&events[0], Event::Dtmf { digit, .. } if digit == "5"),
            "the digit is surfaced to the controller"
        );
        assert!(
            out.is_empty(),
            "no telephone-event relayed to B while dtmf_blocked"
        );

        // Unblock: a fresh event (new RTP timestamp) now repacketizes toward B again.
        call.set_dtmf_blocked(true, false);
        out.clear();
        events.clear();
        call.process(
            &rx(1, A_ADDR, telephone_event_rtp(2, 17600, true, true)),
            &mut out,
            &mut events,
        );
        assert_eq!(events.len(), 1, "still detected after unblock");
        assert_eq!(out.len(), 1, "telephone-event relayed to B after unblock");
        let relayed = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(relayed.payload_type, 101, "egress telephone-event PT");
    }

    #[test]
    fn block_dtmf_on_a_relay_drops_telephone_events_by_pt_but_forwards_ordinary_rtp() {
        // A promoted plain relay with dtmf_blocked drops the verbatim forward of the leg's
        // telephone-event PT (still emitting the event) but forwards ordinary RTP untouched.
        let mut call = relay_call();
        assert!(call.is_relay_only());
        call.set_dtmf_blocked(true, true); // block A's DTMF toward B

        // Ordinary audio RTP (PT 0) still relays byte-for-byte.
        let audio = ulaw_rtp(1, 0xAB);
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, audio.clone()), &mut out, &mut events);
        assert_eq!(out.len(), 1, "ordinary RTP still forwarded verbatim");
        assert_eq!(&out[0].data[..], &audio[..], "forwarded byte-for-byte");
        assert!(events.is_empty(), "no DTMF event for ordinary audio");

        // A telephone-event on PT 101 is dropped (not forwarded) but the event fires.
        out.clear();
        events.clear();
        call.process(
            &rx(1, A_ADDR, telephone_event_rtp(2, 16000, true, true)),
            &mut out,
            &mut events,
        );
        assert!(
            out.is_empty(),
            "telephone-event dropped on the blocked relay leg"
        );
        assert_eq!(
            events.len(),
            1,
            "DTMF still detected + emitted on the relay path"
        );

        // Unblock: a fresh telephone-event (new RTP timestamp) is forwarded verbatim again.
        call.set_dtmf_blocked(true, false);
        out.clear();
        events.clear();
        let event = telephone_event_rtp(3, 17600, true, true);
        call.process(&rx(1, A_ADDR, event.clone()), &mut out, &mut events);
        assert_eq!(
            out.len(),
            1,
            "telephone-event forwarded again after unblock"
        );
        assert_eq!(
            &out[0].data[..],
            &event[..],
            "forwarded byte-for-byte after unblock"
        );
    }

    #[test]
    fn a_fork_does_not_disturb_dtmf_extraction() {
        use siphon_rtp_media::fork::RtpForkSink;

        // A telephone-event packet is handled out of band (no decode), so the fork sees nothing, and
        // the DTMF event + repacketization are unchanged with a fork attached (regression guard).
        let mut call = ulaw_alaw_call();
        let (fork_tx, fork_rx) = flume::bounded(8);
        call.add_fork(
            true,
            Box::new(RtpForkSink::new(Box::new(G711::ulaw()), fork_tx, 9, 0)),
        );

        let event_payload = [5u8, 0x80 | 10, 0x03, 0x20];
        let header = RtpHeader {
            marker: true,
            payload_type: 101,
            sequence: 1,
            timestamp: 16000,
            ssrc: 0x1111_2222,
        };
        let mut buffer = vec![0u8; 16];
        let len = write_packet(&header, &event_payload, &mut buffer).expect("write");
        buffer.truncate(len);

        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, buffer), &mut out, &mut events);
        assert_eq!(events.len(), 1, "DTMF still extracted with a fork attached");
        assert_eq!(out.len(), 1, "telephone-event still repacketized");
        assert!(
            fork_rx.try_recv().is_err(),
            "the fork only sees decoded audio, not DTMF"
        );
    }

    fn tee(subscriber: u64, srs: &str) -> RawTee {
        RawTee {
            subscriber_endpoint: endpoint(subscriber),
            srs_dst: addr(srs),
        }
    }

    #[test]
    fn raw_tee_copies_leg_a_original_rtp_byte_for_byte_alongside_transcode() {
        // SIPREC raw tee: leg A's ORIGINAL ingress RTP is copied verbatim to the subscriber while the
        // A→B transcode (µ-law → A-law) continues. No re-encode — the SRS sees exactly what A sent.
        let mut call = ulaw_alaw_call();
        call.add_raw_tee(true, tee(99, "127.0.0.9:7000"));
        assert_eq!(call.raw_tee_count(true), 1);

        let original = ulaw_rtp(100, 0x40);
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, original.clone()), &mut out, &mut events);

        // Two outbound: the raw tee (emitted first) and the transcoded packet toward B.
        assert_eq!(out.len(), 2, "one raw tee + one transcoded egress");
        let teed = out
            .iter()
            .find(|o| o.endpoint == endpoint(99))
            .expect("tee outbound");
        assert_eq!(teed.dst, addr("127.0.0.9:7000"), "tee goes to the SRS");
        assert_eq!(
            &teed.data[..],
            &original[..],
            "SRS receives A's ORIGINAL RTP byte-for-byte"
        );
        let to_b = out
            .iter()
            .find(|o| o.endpoint == endpoint(2))
            .expect("transcoded egress");
        let parsed = RtpPacket::parse(&to_b.data).expect("parse");
        assert_eq!(
            parsed.payload_type, 8,
            "B still gets A-law (genuinely transcoded)"
        );
    }

    #[test]
    fn raw_tee_tees_rtcp_and_dtmf_verbatim_too() {
        // The raw tee copies whatever arrives — RTP, RTCP, telephone-event — so the SRS records the
        // leg's actual media stream untouched (RFC 7866 §6).
        let mut call = ulaw_alaw_call();
        call.add_raw_tee(true, tee(99, "127.0.0.9:7000"));

        // An RTCP Sender Report on leg A.
        let rtcp = vec![0x80u8, 200, 0x00, 0x06, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut out = Vec::new();
        call.process(&rx(1, A_ADDR, rtcp.clone()), &mut out, &mut Vec::new());
        let teed = out
            .iter()
            .find(|o| o.endpoint == endpoint(99))
            .expect("tee");
        assert_eq!(&teed.data[..], &rtcp[..], "RTCP tee'd verbatim");
    }

    #[test]
    fn remove_raw_tee_stops_only_the_named_subscriber() {
        // Two subscribers tap leg A; removing one leaves the other intact (MPTY / multi-SRS).
        let mut call = ulaw_alaw_call();
        call.add_raw_tee(true, tee(91, "127.0.0.9:7000"));
        call.add_raw_tee(true, tee(92, "127.0.0.9:8000"));
        assert_eq!(call.raw_tee_count(true), 2);

        call.remove_raw_tee(true, endpoint(91));
        assert_eq!(call.raw_tee_count(true), 1);

        let mut out = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0x40)), &mut out, &mut Vec::new());
        assert!(
            out.iter().all(|o| o.endpoint != endpoint(91)),
            "removed subscriber gets nothing"
        );
        assert!(
            out.iter().any(|o| o.endpoint == endpoint(92)),
            "the other subscriber still tee'd"
        );
    }

    /// A relay-only call (a promoted passthrough leg): both directions forward verbatim, no codecs.
    fn relay_call() -> MediaCall {
        let a_to_b = RelayConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            telephone_event: Some(101),
        };
        let b_to_a = RelayConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Exact(addr(B_ADDR).ip()),
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            telephone_event: Some(101),
        };
        MediaCall::new_relay("relay", "tag-a", Some("tag-b".into()), a_to_b, b_to_a, true)
    }

    #[test]
    fn relay_only_forwards_ingress_verbatim_to_the_peer() {
        // A promoted passthrough relay forwards the ingress RTP byte-for-byte to the peer (no encode).
        let mut call = relay_call();
        assert!(call.is_relay_only());
        let original = ulaw_rtp(7, 0xAB);
        let mut out = Vec::new();
        call.process(&rx(1, A_ADDR, original.clone()), &mut out, &mut Vec::new());
        assert_eq!(out.len(), 1, "one verbatim forward toward B");
        assert_eq!(out[0].endpoint, endpoint(2), "forwarded out B's socket");
        assert_eq!(out[0].dst, addr(B_ADDR));
        assert_eq!(&out[0].data[..], &original[..], "forwarded byte-for-byte");
    }

    /// Build a redirected datagram with an explicit arrival time (the capture timestamp).
    fn rx_at(endpoint_id: u64, source: &str, arrival: u64, data: Vec<u8>) -> RxPacket {
        RxPacket {
            endpoint: endpoint(endpoint_id),
            source: addr(source),
            arrival,
            data: Bytes::from(data),
        }
    }

    #[test]
    fn recording_captures_accepted_ingress_on_both_legs_with_the_5_tuple() {
        let mut call = relay_call();
        let (sender, sink) = flume::bounded(16);
        call.start_recording(PcapCapture {
            sender,
            a_local: addr("127.0.0.1:10000"),
            b_local: addr("127.0.0.1:10002"),
        });
        assert!(call.is_recording());

        // A→B accepted packet: captured with A's observed source, leg A's engine-local destination,
        // the verbatim RTP bytes, and the arrival timestamp.
        let a_packet = ulaw_rtp(1, 0x40);
        call.process(
            &rx_at(1, A_ADDR, 123, a_packet.clone()),
            &mut Vec::new(),
            &mut Vec::new(),
        );
        let captured = sink.try_recv().expect("A→B datagram captured");
        assert_eq!(
            captured.source,
            addr(A_ADDR),
            "captured source = A's observed addr"
        );
        assert_eq!(
            captured.destination,
            addr("127.0.0.1:10000"),
            "captured destination = leg A's engine-local addr"
        );
        assert_eq!(
            &captured.payload[..],
            &a_packet[..],
            "RTP captured byte-for-byte"
        );
        assert_eq!(
            captured.timestamp_micros, 123,
            "arrival timestamp propagated"
        );

        // B→A accepted packet is captured with leg B's local address.
        let b_packet = alaw_rtp(1, 0x55);
        call.process(
            &rx_at(2, B_ADDR, 456, b_packet.clone()),
            &mut Vec::new(),
            &mut Vec::new(),
        );
        let captured = sink.try_recv().expect("B→A datagram captured");
        assert_eq!(
            captured.destination,
            addr("127.0.0.1:10002"),
            "captured destination = leg B's engine-local addr"
        );
        assert_eq!(captured.timestamp_micros, 456);

        // An off-source packet is gated out *before* capture — the recording never sees it.
        call.process(
            &rx_at(1, "127.0.0.99:5000", 789, ulaw_rtp(2, 0xFF)),
            &mut Vec::new(),
            &mut Vec::new(),
        );
        assert!(
            sink.try_recv().is_err(),
            "off-source packet is gated before capture"
        );

        // After stop_recording, nothing more is captured.
        call.stop_recording();
        assert!(!call.is_recording());
        call.process(
            &rx_at(1, A_ADDR, 1000, ulaw_rtp(3, 0x41)),
            &mut Vec::new(),
            &mut Vec::new(),
        );
        assert!(sink.try_recv().is_err(), "no capture after stop_recording");
    }

    #[test]
    fn relay_only_gates_off_source_and_tees_to_the_srs() {
        let mut call = relay_call();
        call.add_raw_tee(true, tee(99, "127.0.0.9:7000"));

        // Off-source packet on leg A is gated out (RTPBleed defence) — no forward, no tee.
        let mut out = Vec::new();
        call.process(
            &rx(1, "127.0.0.99:5000", ulaw_rtp(1, 0xFF)),
            &mut out,
            &mut Vec::new(),
        );
        assert!(
            out.is_empty(),
            "off-source packet dropped before forward or tee"
        );

        // A signalled packet forwards to B AND tees to the SRS.
        let original = ulaw_rtp(2, 0x40);
        out.clear();
        call.process(&rx(1, A_ADDR, original.clone()), &mut out, &mut Vec::new());
        let to_b = out
            .iter()
            .find(|o| o.endpoint == endpoint(2))
            .expect("relay to B");
        assert_eq!(&to_b.data[..], &original[..], "relayed verbatim to B");
        let teed = out
            .iter()
            .find(|o| o.endpoint == endpoint(99))
            .expect("tee to SRS");
        assert_eq!(&teed.data[..], &original[..], "tee'd verbatim to the SRS");
    }

    #[test]
    fn relay_only_latches_the_observed_source_for_the_reverse_direction() {
        // B replies from an unexpected port (symmetric NAT); the A→B direction latches it.
        let mut call = relay_call();
        let observed = "127.0.0.3:55555";
        let mut out = Vec::new();
        call.process(
            &rx(2, observed, alaw_rtp(1, 0x55)),
            &mut out,
            &mut Vec::new(),
        );
        out.clear();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut Vec::new());
        assert_eq!(
            out[0].dst,
            addr(observed),
            "A→B latched to B's observed source"
        );
    }

    #[test]
    fn relay_only_block_suppresses_the_forward_but_still_tees() {
        // Block on a promoted relay suppresses the peer forward; the SRS still records the held leg.
        let mut call = relay_call();
        call.add_raw_tee(true, tee(99, "127.0.0.9:7000"));
        call.set_blocked(true);
        let mut out = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut Vec::new());
        assert!(
            out.iter().all(|o| o.endpoint != endpoint(2)),
            "blocked: no forward to B"
        );
        assert!(
            out.iter().any(|o| o.endpoint == endpoint(99)),
            "but the SRS still gets the media"
        );
    }

    #[test]
    fn records_decoded_audio_when_configured() {
        // A recorder on the A→B direction captures A's decoded audio.
        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(L16::new(8000, 20)),
            egress_ssrc: 1,
            egress_payload_type: 11,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: Some(WavRecorder::new(8000, 1)),
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Any,
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: Box::new(L16::new(8000, 20)),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 2,
            egress_payload_type: 0,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
        };
        let mut call = MediaCall::new(
            "rec-call",
            "a",
            None,
            a_to_b,
            b_to_a,
            true,
            Some("/tmp".to_string()),
        );
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut events);
        let files = call.take_recordings();
        assert_eq!(files.len(), 1, "one direction recorded");
        assert!(files[0].0.ends_with("rec-call-a.wav"));
        assert!(files[0].1.starts_with(b"RIFF"), "valid WAV header");
    }
}
