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

use bytes::Bytes;
use dashmap::DashMap;

use siphon_rtp_codec::{Decoder, Encoder};
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket, SourceFilter};
use siphon_rtp_dsp::resample::Resampler;
use siphon_rtp_media::dtmf::{DtmfDetector, DtmfGenerator};
use siphon_rtp_media::player::PcmPlayer;
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

/// One direction of a media-processing call: ingress codec → (resample) → egress codec.
///
/// "Direction" means the flow of media from one party toward the other. `a_to_b` decodes party A's
/// ingress and encodes it for party B; `b_to_a` is the reverse. The egress sequence/timestamp/SSRC
/// belong to the *synthesized* stream the engine sends to the receiving party.
pub struct Direction {
    /// The endpoint datagrams arrive on for this direction (the sending party's engine socket).
    ingress_endpoint: EndpointId,
    /// Signalled-source gate for the sending party (RTPBleed defence on the Redirect path).
    accepted_source: SourceFilter,
    /// The endpoint to transmit from (the receiving party's engine socket).
    egress_endpoint: EndpointId,
    /// Where to transmit (the receiving party's address; latched to its observed source).
    egress_dst: SocketAddr,
    decoder: Box<dyn Decoder>,
    encoder: Box<dyn Encoder>,
    /// Sample-rate converter when the ingress codec rate differs from the egress codec rate.
    resampler: Option<Resampler>,
    egress_sequence: u16,
    egress_timestamp: u32,
    egress_ssrc: u32,
    egress_payload_type: u8,
    /// Egress PCM samples per frame — the timestamp increment for the synthesized stream.
    egress_frame_samples: u32,
    /// Ingress RFC 4733 telephone-event payload type, if negotiated.
    telephone_event_in: Option<u8>,
    /// Egress RFC 4733 telephone-event payload type (what the receiving party expects).
    telephone_event_out: Option<u8>,
    dtmf: DtmfDetector,
    /// Records the decoded ingress audio when the call is recorded.
    recorder: Option<WavRecorder>,
    /// Replace egress audio with comfort silence (digit-suppression / hold).
    silenced: bool,
    /// Drop egress audio entirely (not even silence).
    blocked: bool,
    /// Egress codec native sample rate, for resampling injected prompt audio onto this stream.
    egress_sample_rate: u32,
    /// An active prompt / DTMF injection on this egress direction (PlayMedia / PlayDtmf). While set,
    /// transcoded audio toward this party is suppressed and the injected media plays instead.
    injection: Option<Injection>,
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
        let egress_frame_samples = egress_params.frame_samples() as u32;
        Self {
            ingress_endpoint: config.ingress_endpoint,
            accepted_source: config.accepted_source,
            egress_endpoint: config.egress_endpoint,
            egress_dst: config.egress_dst,
            decoder: config.decoder,
            encoder: config.encoder,
            resampler,
            egress_sequence: 0,
            egress_timestamp: 0,
            egress_ssrc: config.egress_ssrc,
            egress_payload_type: config.egress_payload_type,
            egress_frame_samples,
            telephone_event_in: config.telephone_event_in,
            telephone_event_out: config.telephone_event_out,
            dtmf: DtmfDetector::new(),
            recorder: config.recorder,
            silenced: false,
            blocked: false,
            egress_sample_rate: egress_rate,
            injection: None,
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
                    out.push(Outbound {
                        endpoint: self.egress_endpoint,
                        dst: self.egress_dst,
                        data: Bytes::copy_from_slice(&buffer[..total]),
                    });
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
            out.push(Outbound {
                endpoint: self.egress_endpoint,
                dst: self.egress_dst,
                data: Bytes::copy_from_slice(&buffer[..total]),
            });
            self.egress_sequence = self.egress_sequence.wrapping_add(1);
            self.egress_timestamp = self.egress_timestamp.wrapping_add(self.egress_frame_samples);
        }
    }

    /// Transform one accepted datagram for this direction, appending any outbound datagrams and DTMF
    /// events. `source`-gating and latching are the caller's responsibility (it owns both directions).
    fn handle(&mut self, data: &[u8], dtmf_meta: DtmfMeta<'_>, out: &mut Vec<Outbound>, events: &mut Vec<Event>) {
        if data.len() < 2 {
            return;
        }
        // RFC 5761 demux: payload-type byte 64..=95 marks RTCP — relay it verbatim, untranscoded.
        let packet_type = data[1] & 0x7f;
        if (64..=95).contains(&packet_type) {
            out.push(Outbound {
                endpoint: self.egress_endpoint,
                dst: self.egress_dst,
                data: Bytes::copy_from_slice(data),
            });
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
            self.relay_telephone_event(&parsed, out);
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
            use siphon_rtp_media::fanout::MediaSink as _;
            recorder.write_pcm(decoded);
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

        let mut payload = [0u8; MAX_RTP];
        let Ok(payload_len) = self.encoder.encode(egress_pcm, &mut payload) else {
            return;
        };
        let header = RtpHeader {
            marker: parsed.marker,
            payload_type: self.egress_payload_type,
            sequence: self.egress_sequence,
            timestamp: self.egress_timestamp,
            ssrc: self.egress_ssrc,
        };
        let mut buffer = [0u8; MAX_RTP];
        if let Ok(total) = write_packet(&header, &payload[..payload_len], &mut buffer) {
            out.push(Outbound {
                endpoint: self.egress_endpoint,
                dst: self.egress_dst,
                data: Bytes::copy_from_slice(&buffer[..total]),
            });
            self.egress_sequence = self.egress_sequence.wrapping_add(1);
            self.egress_timestamp = self.egress_timestamp.wrapping_add(self.egress_frame_samples);
        }
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
            out.push(Outbound {
                endpoint: self.egress_endpoint,
                dst: self.egress_dst,
                data: Bytes::copy_from_slice(&buffer[..total]),
            });
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
/// and DTMF events to emit. The async actor ([`run_media_call`]) wraps it with the datapath I/O.
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
    /// Where to write the recorded WAV on teardown, when recording.
    record_path: Option<String>,
}

impl MediaCall {
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
            record_path,
        }
    }

    /// The endpoints this call owns (for registry routing and teardown).
    #[must_use]
    pub fn endpoints(&self) -> [EndpointId; 2] {
        [self.a_to_b.ingress_endpoint, self.b_to_a.ingress_endpoint]
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
            if self.latch {
                self.b_to_a.egress_dst = packet.source;
            }
            self.a_to_b.handle(&packet.data, meta, out, events);
        } else if packet.endpoint == self.b_to_a.ingress_endpoint {
            if !self.b_to_a.accepted_source.accepts(packet.source.ip()) {
                tracing::debug!(source = %packet.source, "media-pipeline dropped packet from unsignalled source");
                return;
            }
            if self.latch {
                self.a_to_b.egress_dst = packet.source;
            }
            self.b_to_a.handle(&packet.data, meta, out, events);
        }
    }

    /// Toggle comfort-silence on both egress directions ([`Command::SilenceMedia`]).
    pub fn set_silenced(&mut self, silenced: bool) {
        self.a_to_b.silenced = silenced;
        self.b_to_a.silenced = silenced;
    }

    /// Toggle full egress blocking on both directions ([`Command::BlockMedia`]).
    pub fn set_blocked(&mut self, blocked: bool) {
        self.a_to_b.blocked = blocked;
        self.b_to_a.blocked = blocked;
    }

    /// The egress direction that plays toward party A (`toward_a = true`) or party B.
    fn direction_toward(&mut self, toward_a: bool) -> &mut Direction {
        if toward_a {
            &mut self.b_to_a // its egress socket faces A
        } else {
            &mut self.a_to_b // its egress socket faces B
        }
    }

    /// Start a prompt / announcement toward a party ([`Command::PlayMedia`]). The player carries the
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

    /// Start a DTMF burst toward a party ([`Command::PlayDtmf`]). Returns `false` if the party has no
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

    /// Stop any prompt / DTMF injection on both directions ([`Command::StopMedia`]).
    pub fn stop_play(&mut self) {
        self.a_to_b.injection = None;
        self.b_to_a.injection = None;
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
                files.push((format!("{base}/{}-a.wav", self.call_id), recorder.into_wav()));
            }
        }
        if let Some(recorder) = self.b_to_a.recorder.take() {
            if recorder.sample_count() > 0 {
                files.push((format!("{base}/{}-b.wav", self.call_id), recorder.into_wav()));
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
    /// Play a prompt toward a party (`toward_a`): the player owns its source-rate PCM.
    PlayAudio { toward_a: bool, player: Box<PcmPlayer> },
    /// Play a DTMF burst toward a party; the reply channel reports whether it could start.
    PlayDtmf {
        toward_a: bool,
        digit: char,
        duration_ms: u32,
        volume: u8,
    },
    /// Stop any prompt / DTMF injection on both directions.
    StopPlay,
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
    task: tokio::task::JoinHandle<()>,
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
        let (mailbox, inbox) = flume::bounded(1024);
        for endpoint in endpoints {
            self.routes.insert(endpoint, mailbox.clone());
        }
        let task = tokio::spawn(run_media_call(call, inbox, datapath, events));
        self.calls.insert(
            call_id,
            CallHandle {
                mailbox,
                endpoints,
                task,
            },
        );
    }

    /// Send a control op to a call's actor, returning `false` if there is no such media call.
    pub fn control(&self, call_id: &str, control: MediaControl) -> bool {
        match self.calls.get(call_id) {
            Some(handle) => handle.mailbox.try_send(MediaInput::Control(control)).is_ok(),
            None => false,
        }
    }

    /// Whether `call_id` is a media-processing call.
    #[must_use]
    pub fn is_media_call(&self, call_id: &str) -> bool {
        self.calls.contains_key(call_id)
    }

    /// Tear a call's actor down: stop it (flushing recordings), drop its routes, and abort the task.
    pub fn deregister(&self, call_id: &str) {
        if let Some((_, handle)) = self.calls.remove(call_id) {
            let _ = handle.mailbox.try_send(MediaInput::Control(MediaControl::Stop));
            for endpoint in handle.endpoints {
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
                    MediaInput::Control(MediaControl::PlayAudio { toward_a, player }) => {
                        call.start_play_audio(toward_a, *player);
                    }
                    MediaInput::Control(MediaControl::PlayDtmf { toward_a, digit, duration_ms, volume }) => {
                        call.start_play_dtmf(toward_a, digit, duration_ms, volume);
                    }
                    MediaInput::Control(MediaControl::StopPlay) => call.stop_play(),
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
        if let Err(error) = datapath.send(datagram.endpoint, datagram.dst, &datagram.data).await {
            tracing::debug!(%error, "media-pipeline send failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_codec::g711::G711;
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
        MediaCall::new("call-1", "tag-a", Some("tag-b".into()), a_to_b, b_to_a, true, None)
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
            data: Bytes::from(data),
        }
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
    fn drops_packets_from_an_unsignalled_source() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // An attacker on a different IP sprays A's endpoint — gated out before any transcode.
        call.process(&rx(1, "127.0.0.9:5000", ulaw_rtp(1, 0xFF)), &mut out, &mut events);
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
        assert_eq!(out[0].dst, addr(observed), "A→B latched to B's observed source");
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
            Event::Dtmf { digit, duration_ms, call_id, .. } => {
                assert_eq!(digit, "5");
                assert_eq!(duration_ms, &100, "800 samples / 8 = 100 ms");
                assert_eq!(call_id, "call-1");
            }
            other => panic!("expected DTMF, got {other:?}"),
        }
        assert_eq!(out.len(), 1, "telephone-event repacketized onto egress");
        let relayed = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(relayed.payload_type, 101);
        assert_eq!(relayed.ssrc, 0xB000_0001, "stamped with the A→B egress SSRC");
        assert_eq!(relayed.timestamp, 16000, "event RTP timestamp preserved");
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
        assert_eq!(packet.payload_type, 0, "prompt encoded in A's codec (µ-law)");

        // While the prompt plays toward A, B→A transcode is suppressed (A hears the prompt only).
        out.clear();
        call.process(&rx(2, B_ADDR, alaw_rtp(1, 0x55)), &mut out, &mut Vec::new());
        assert!(out.is_empty(), "transcode toward A is suppressed during playback");

        // Second tick drains the rest; a third finds the prompt exhausted and clears the injection.
        out.clear();
        call.tick(&mut out);
        assert_eq!(out.len(), 1);
        out.clear();
        call.tick(&mut out);
        assert!(!call.has_injection(), "injection cleared when the prompt ends");
    }

    #[test]
    fn play_dtmf_injects_telephone_events_toward_the_target() {
        let mut call = ulaw_alaw_call();
        assert!(call.start_play_dtmf(true, '5', 100, 10), "A negotiated telephone-event");
        let mut out = Vec::new();
        call.tick(&mut out);
        assert_eq!(out.len(), 1);
        let packet = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(packet.payload_type, 101, "egress telephone-event PT");
        assert_eq!(packet.payload[0], 5, "RFC 4733 event code for '5'");
        assert!(packet.marker, "first packet of the event carries the marker");
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
        assert!(!call.start_play_dtmf(true, '5', 100, 10), "no telephone-event ⇒ cannot inject");
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
