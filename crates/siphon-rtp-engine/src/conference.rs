//! The userspace **conference** slow path: an N-party audio mixer (MCU).
//!
//! Where a [`crate::media_pipeline::MediaCall`] bridges exactly two legs and is *packet-driven* (one
//! ingress packet → one egress packet), a conference mixes **many** legs and is *clock-driven*: a
//! 20 ms room tick pops one frame from every participant, mixes them, and emits one egress frame to
//! every participant — independent of each leg's arrival timing. Each participant is a
//! [`MediaLeg`] (jitter + decode + encode + its own egress SSRC)
//! plus a resampler pair to/from the room rate and an energy VAD; the room math lives in
//! [`Mixer`].
//!
//! Like the other slow-path actors this is split into a **pure, synchronous** core ([`Conference`] —
//! feed it datagrams via [`Conference::ingest`], advance it with [`Conference::tick`], collect the
//! datagrams to send) and a thin async wrapper (`run_conference`) that does the datapath I/O off a
//! `tokio` interval. The core takes a logical clock from its tick cadence (never `Instant::now()`),
//! so it unit-tests deterministically without sockets.
//!
//! ## Security (RTPBleed, docs/security-and-nat.md §4)
//! Unlike a SIPREC tee, every conference endpoint is a full **inbound** surface, so each participant
//! re-enforces the signalled-source gate and a constrained latch on ingress exactly as the media and
//! SRTP paths do — a packet from an unsignalled source is dropped before it can enter the mix, and a
//! participant with no resolved destination is never sent to.

use std::net::SocketAddr;

use bytes::Bytes;
use dashmap::DashMap;

use siphon_rtp_codec::{Decoder, Encoder};
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket, SourceFilter};
use siphon_rtp_dsp::resample::Resampler;
use siphon_rtp_dsp::EnergyVad;
use siphon_rtp_media::dtmf::DtmfDetector;
use siphon_rtp_media::jitter::JitterBuffer;
use siphon_rtp_media::leg::{MediaLeg, PcmFrame};
use siphon_rtp_media::mixer::{MixInputs, Mixer, Monitor, Role, Whisper, MAX_PARTICIPANTS};
use siphon_rtp_media::rtcp;
use siphon_rtp_media::rtp::RtpPacket;
use siphon_rtp_proto::Event;
use siphon_rtp_srtp::leg::SecureLeg;

use crate::media_pipeline::Outbound;

/// The wideband room rate. A room runs at this rate whenever any participant is wideband (>8 kHz) or
/// the room is bridged; an all-narrowband, unbridged room drops to `NARROWBAND_RATE_HZ` so it pays
/// no resampling at all (the common all-G.711 / PSTN conference).
pub const ROOM_RATE_HZ: u32 = 16_000;
/// The narrowband fast-path room rate (all-G.711/G.726/PSTN, unbridged).
const NARROWBAND_RATE_HZ: u32 = 8_000;
/// Samples in one 20 ms room frame at the **maximum** room rate — the scratch-buffer capacity. The
/// live frame is `room_frame` (8 kHz → 160, 16 kHz → 320).
const ROOM_FRAME: usize = (ROOM_RATE_HZ as usize / 1000) * 20;
/// The room playout tick — one mixed frame per participant per 20 ms (RFC 3551 default ptime).
pub const ROOM_TICK: std::time::Duration = std::time::Duration::from_millis(20);
/// Largest decoded native frame the scratch buffers accommodate (48 kHz × 40 ms ceiling).
const MAX_NATIVE_FRAME: usize = 1920;
/// Largest egress RTP packet.
const MAX_RTP: usize = 1500;
/// Jitter buffer: prime at 2 frames (~40 ms), cap at 16 (bounded playout latency).
const JITTER_TARGET: usize = 2;
const JITTER_MAX: usize = 16;
/// Energy VAD: the mean-square speech threshold and the hangover (frames) that bridges short pauses.
const VAD_THRESHOLD: i64 = 1_000_000;
const VAD_HANGOVER_FRAMES: u32 = 5;
/// Default active-speaker cap (`0` = no cap: a plain N-way call hears everyone). Webinars set a cap.
const DEFAULT_TOP_M: usize = 0;
/// Room ticks between per-participant RTCP Sender Reports (250 × 20 ms = 5 s, RFC 3550 §6.2 default).
const SR_INTERVAL_TICKS: u64 = 250;

/// A participant's role plus its routing-matrix targets, named by leg tag (resolved to mixer indices
/// each tick, so the routes survive membership changes).
#[derive(Debug, Clone)]
pub struct Routing {
    /// The participant's mixing role.
    pub role: Role,
    /// If set, this participant's audio is whispered privately to that leg tag (supervisor coach) —
    /// it is excluded from the public room mix.
    pub whisper_target: Option<String>,
    /// If set, this participant hears that leg tag directly, the target unaware (supervisor monitor).
    pub monitor_target: Option<String>,
}

impl Default for Routing {
    fn default() -> Self {
        Self {
            role: Role::Talker,
            whisper_target: None,
            monitor_target: None,
        }
    }
}

/// Everything the engine resolves from a participant's SDP offer/answer to seat them in a room.
pub struct ParticipantConfig {
    /// The leg tag (SIP From/To tag) — the participant's stable id for routing + events.
    pub tag: String,
    /// Decodes this participant's ingress RTP (its negotiated codec).
    pub decoder: Box<dyn Decoder>,
    /// Encodes the mix toward this participant (its negotiated codec — must be encodable).
    pub encoder: Box<dyn Encoder>,
    /// The engine socket this participant's RTP arrives on.
    pub ingress_endpoint: EndpointId,
    /// The engine socket the mix is transmitted from.
    pub egress_endpoint: EndpointId,
    /// The participant's RTP address (latched to its observed source when `latch`). May be unset
    /// until the first packet arrives — the conference never transmits to an unresolved destination.
    pub egress_dst: SocketAddr,
    /// Signalled-source gate (RTPBleed defence on the inbound path).
    pub accepted_source: SourceFilter,
    /// Whether to latch the participant's reply address to its observed source (symmetric RTP).
    pub latch: bool,
    /// The synthesized egress SSRC stamped on this participant's mix stream (RFC 3550 §5.1).
    pub egress_ssrc: u32,
    /// The egress RTP payload type (the participant's negotiated codec PT).
    pub egress_payload_type: u8,
    /// The participant's codec as the G.107 MOS estimator knows it (`siphon-rtp-hep`), resolved from
    /// the negotiated encoding name — so an AMR-WB / G.722 leg is scored on its own impairment, not
    /// the G.711 default. See `hep_codec_for_name`.
    pub mos_codec: siphon_rtp_hep::mos::Codec,
    /// The participant's RFC 4733 telephone-event PT, if negotiated (filtered out of the mix).
    pub telephone_event_in: Option<u8>,
    /// SDES-SRTP crypto for a secure (`RTP/SAVP`) participant: decrypt ingress / encrypt egress with
    /// this leg's keys. `None` for a plain `RTP/AVP` participant.
    pub secure: Option<SecureLeg>,
    /// Initial role / routing.
    pub routing: Routing,
}

/// One seated participant: its leg, resamplers to/from the room rate, VAD, and ingress security state.
struct Participant {
    tag: String,
    leg: MediaLeg,
    ingress_endpoint: EndpointId,
    egress_endpoint: EndpointId,
    egress_dst: SocketAddr,
    accepted_source: SourceFilter,
    latch: bool,
    /// This participant's codec sample rate, kept so its resamplers can be rebuilt if the room rate
    /// flips (e.g. a wideband leg joins an all-narrowband room).
    native_rate: u32,
    native_frame: usize,
    /// The egress RTP payload type (the participant's codec PT) — the shared-encode class key.
    egress_payload_type: u8,
    /// This participant's codec for the G.107 MOS estimate (resolved at join from the encoding name).
    mos_codec: siphon_rtp_hep::mos::Codec,
    /// Whether this participant's encoder is stateless (G.711 / L16) and so can share one encode of
    /// the listener mix with every other listener on the same codec.
    stateless: bool,
    telephone_event_in: Option<u8>,
    /// native → room (None when the participant already runs at the room rate).
    to_room: Option<Resampler>,
    /// room → native (None when the participant already runs at the room rate).
    from_room: Option<Resampler>,
    vad: EnergyVad,
    /// RFC 4733 telephone-event detector — emits one [`Event::Dtmf`] per completed key press.
    dtmf: DtmfDetector,
    /// SDES-SRTP state for a secure participant (decrypt ingress / encrypt egress); `None` if plain.
    secure: Option<SecureLeg>,
    routing: Routing,
    /// Whether the first egress packet has been emitted (sets the RTP marker bit, RFC 3550 §5.1).
    started: bool,
}

/// What [`Conference::tick`] reports about the active (dominant) speaker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveSpeakerChange {
    /// No change since the previous tick.
    Unchanged,
    /// The dominant speaker changed to this leg tag (`None` ⇒ the floor went silent).
    Changed(Option<String>),
}

/// A conference room: the participant set, the mix bus, and all per-tick scratch (sized once so a
/// tick allocates nothing).
pub struct Conference {
    conference_id: String,
    mixer: Mixer,
    participants: Vec<Participant>,
    /// Active-speaker cap (`0` = no cap).
    top_m: usize,
    /// The live room mix rate — [`NARROWBAND_RATE_HZ`] for an all-narrowband, unbridged room, else
    /// [`ROOM_RATE_HZ`]. Recomputed on every membership / bridge change.
    room_rate: u32,
    /// Samples per 20 ms room frame at `room_rate` (≤ [`ROOM_FRAME`], the buffer capacity).
    room_frame: usize,
    // Per-tick scratch — reused every tick.
    room_rows: Vec<Vec<i16>>,
    roles: Vec<Role>,
    energy: Vec<i64>,
    speaking: Vec<bool>,
    whispers: Vec<Whisper>,
    monitors: Vec<Monitor>,
    native_in: Vec<i16>,
    resample_scratch: Vec<i16>,
    native_out: Vec<i16>,
    payload: Vec<u8>,
    rtp: Vec<u8>,
    /// Room bridges (live-configurable, plan §7): each tick this room feeds its participant mix to
    /// every `bridge_out` and hears every `bridge_in` as an extra contributor. A bridged room is
    /// forced to [`ROOM_RATE_HZ`], so both ends of a bridge share the rate and no inter-room
    /// resampling is needed.
    bridge_in: Vec<flume::Receiver<Vec<i16>>>,
    bridge_out: Vec<flume::Sender<Vec<i16>>>,
    /// Scratch for summing bridged-in rooms into one external frame (reused each tick).
    bridge_accum: Vec<i32>,
    external_buf: Vec<i16>,
    /// Per-tick shared-encode cache: the encoded listener-mix payload per egress codec (payload type),
    /// so a room of N stateless listeners on the same codec pays **one** encode, not N. Slots are
    /// reused across ticks (`share_count` is the live length); only the first `share_count` are valid.
    share_classes: Vec<(u8, Vec<u8>)>,
    share_count: usize,
    /// Shared room→8 kHz downsampler for the **mixed-rate** shared-encode path: when the room runs at
    /// 16 kHz, narrowband listeners hear one downsampled copy of the listener mix (not each their own),
    /// so the resample is shared too. `Some` only when the room is wideband.
    listener_downsample: Option<Resampler>,
    /// The listener mix downsampled to 8 kHz this tick (filled lazily by the first narrowband
    /// shared-encode listener), reused by the rest.
    listener_native_buf: Vec<i16>,
    /// Whether `listener_native_buf` has been computed this tick.
    listener_native_ready: bool,
    /// DTMF events detected on ingress this drain cycle (RFC 4733), drained by the actor to the
    /// control channel.
    pending_events: Vec<Event>,
    /// SRTP scratch for secure participants: decrypted ingress (`clear_in`) and encrypted egress
    /// (`secure_out`). Reused per packet — `SecureLeg::protect`/`unprotect` append to a `Vec`.
    clear_in: Vec<u8>,
    secure_out: Vec<u8>,
    /// The dominant speaker's tag as of the previous tick (for change detection).
    last_dominant_tag: Option<String>,
}

impl Conference {
    /// Build an empty room. `top_m` caps the simultaneous active speakers (`0` = no cap).
    #[must_use]
    pub fn new(conference_id: String, top_m: usize) -> Self {
        Self {
            conference_id,
            mixer: Mixer::new(MAX_PARTICIPANTS, ROOM_FRAME),
            participants: Vec::new(),
            top_m,
            room_rate: ROOM_RATE_HZ,
            room_frame: ROOM_FRAME,
            room_rows: (0..MAX_PARTICIPANTS)
                .map(|_| vec![0i16; ROOM_FRAME])
                .collect(),
            roles: vec![Role::Talker; MAX_PARTICIPANTS],
            energy: vec![0i64; MAX_PARTICIPANTS],
            speaking: vec![false; MAX_PARTICIPANTS],
            whispers: Vec::with_capacity(MAX_PARTICIPANTS),
            monitors: Vec::with_capacity(MAX_PARTICIPANTS),
            native_in: vec![0i16; MAX_NATIVE_FRAME],
            resample_scratch: Vec::with_capacity(MAX_NATIVE_FRAME),
            native_out: vec![0i16; MAX_NATIVE_FRAME],
            payload: vec![0u8; MAX_RTP],
            rtp: vec![0u8; MAX_RTP],
            bridge_in: Vec::new(),
            bridge_out: Vec::new(),
            bridge_accum: vec![0i32; ROOM_FRAME],
            external_buf: vec![0i16; ROOM_FRAME],
            share_classes: Vec::new(),
            share_count: 0,
            // The room starts wideband (16 kHz), so the room→8 kHz downsampler exists from the start.
            listener_downsample: Resampler::new(ROOM_RATE_HZ, NARROWBAND_RATE_HZ).ok(),
            listener_native_buf: vec![0i16; ROOM_FRAME],
            listener_native_ready: false,
            pending_events: Vec::new(),
            clear_in: Vec::with_capacity(MAX_RTP),
            secure_out: Vec::with_capacity(MAX_RTP),
            last_dominant_tag: None,
        }
    }

    /// The room's id.
    #[must_use]
    pub fn conference_id(&self) -> &str {
        &self.conference_id
    }

    /// Live participant count.
    #[must_use]
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// The live room mix rate (8 kHz for an all-narrowband, unbridged room, else 16 kHz).
    #[must_use]
    pub fn room_rate(&self) -> u32 {
        self.room_rate
    }

    /// Whether the room has no participants (the actor tears the room down when this becomes true).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }

    /// Set the active-speaker cap (`0` = no cap).
    pub fn set_top_m(&mut self, top_m: usize) {
        self.top_m = top_m;
    }

    /// Seat a participant. Returns `false` if the room is full ([`MAX_PARTICIPANTS`]), the codec's
    /// frame is larger than the scratch ceiling, or a tag is already seated.
    pub fn add_participant(&mut self, config: ParticipantConfig) -> bool {
        if self.participants.len() >= MAX_PARTICIPANTS {
            return false;
        }
        if self
            .participants
            .iter()
            .any(|participant| participant.tag == config.tag)
        {
            return false;
        }
        let native_rate = config.decoder.params().sample_rate_hz;
        let native_frame = config.decoder.frame_samples();
        if native_frame == 0 || native_frame > MAX_NATIVE_FRAME {
            return false;
        }
        let stateless = config.encoder.is_stateless();
        let egress_payload_type = config.egress_payload_type;
        // Build against the current room rate; `recompute_room_rate` below rebuilds these if seating
        // this participant flips the room (e.g. a wideband leg joins an all-narrowband room).
        let (to_room, from_room) = build_resamplers(native_rate, self.room_rate);
        let leg = MediaLeg::new(
            config.decoder,
            config.encoder,
            JitterBuffer::new(JITTER_TARGET, JITTER_MAX),
            config.egress_ssrc,
            config.egress_payload_type,
        );
        self.participants.push(Participant {
            tag: config.tag,
            leg,
            ingress_endpoint: config.ingress_endpoint,
            egress_endpoint: config.egress_endpoint,
            egress_dst: config.egress_dst,
            accepted_source: config.accepted_source,
            latch: config.latch,
            native_rate,
            native_frame,
            egress_payload_type,
            mos_codec: config.mos_codec,
            stateless,
            telephone_event_in: config.telephone_event_in,
            to_room,
            from_room,
            vad: EnergyVad::new(VAD_THRESHOLD, VAD_HANGOVER_FRAMES),
            dtmf: DtmfDetector::new(),
            secure: config.secure,
            routing: config.routing,
            started: false,
        });
        self.recompute_room_rate();
        true
    }

    /// Remove a participant by tag. Returns `true` if it was seated.
    pub fn remove_participant(&mut self, tag: &str) -> bool {
        if let Some(position) = self
            .participants
            .iter()
            .position(|participant| participant.tag == tag)
        {
            self.participants.remove(position);
            self.recompute_room_rate();
            true
        } else {
            false
        }
    }

    /// Live-update a participant's role / routing. Returns `true` if it was seated.
    pub fn set_routing(&mut self, tag: &str, routing: Routing) -> bool {
        if let Some(participant) = self
            .participants
            .iter_mut()
            .find(|participant| participant.tag == tag)
        {
            participant.routing = routing;
            true
        } else {
            false
        }
    }

    /// Ingress one datagram for a participant endpoint: gate its source, latch its reply address,
    /// drop RTCP / telephone-event, and buffer the audio for the next room tick. Never mixes a packet
    /// from an unsignalled source (RTPBleed defence). Returns `true` if the packet passed the
    /// signalled-source gate (so the caller can stamp media activity for the timeout sweep) — RTCP and
    /// telephone-events count as activity even though they are not mixed.
    pub fn ingest(&mut self, packet: &RxPacket) -> bool {
        let conference_id = &self.conference_id;
        let Some(participant) = self
            .participants
            .iter_mut()
            .find(|participant| participant.ingress_endpoint == packet.endpoint)
        else {
            return false;
        };
        // Layer 2 — signalled-source gate (docs/security-and-nat.md §4): an unsignalled source never
        // enters the mix.
        if !participant.accepted_source.accepts(packet.source.ip()) {
            tracing::debug!(
                source = %packet.source,
                conference = %conference_id,
                "conference dropped packet from unsignalled source"
            );
            return false;
        }
        // Layer 3 — constrained latch: learn the reply address from the gated source.
        if participant.latch {
            participant.egress_dst = packet.source;
        }
        // SRTP: decrypt a secure participant's packet first (the auth tag also proves authenticity —
        // a forged/replayed packet fails here and is dropped). Plain legs pass through untouched.
        let data: &[u8] = if let Some(secure) = participant.secure.as_mut() {
            self.clear_in.clear();
            if secure.unprotect(&packet.data, &mut self.clear_in).is_err() {
                return false;
            }
            &self.clear_in
        } else {
            &packet.data
        };
        if data.len() < 2 {
            return true; // gated in; too short to be audio, but the path is alive
        }
        // RFC 5761 demux: payload-type byte 64..=95 marks RTCP. We never mix it, but a Sender Report
        // carries the sender's NTP timestamp, which we echo back as LSR (+ DLSR) in our own reception
        // report so the peer can compute round-trip time; and any reception report block the peer sends
        // *about our egress stream* lets us derive round-trip time from its LSR/DLSR against the SRs we
        // sent (RFC 3550 §6.4.1). Consume both, then drop (RTCP is never mixed).
        let packet_type = data[1] & 0x7f;
        if (64..=95).contains(&packet_type) {
            // Sender Report (V=2, PT=200): the 64-bit NTP timestamp sits at offset 8 (after the
            // 8-byte header), so the packet must hold at least 16 bytes.
            if data[0] >> 6 == 2 && data[1] == 200 && data.len() >= 16 {
                if let Ok(ntp_bytes) = <[u8; 8]>::try_from(&data[8..16]) {
                    participant
                        .leg
                        .record_sender_report(u64::from_be_bytes(ntp_bytes), packet.arrival);
                }
            }
            // Feed every reception report block (in an SR or an RR) to the leg's RTT estimator; it
            // ignores blocks that report a different SSRC or echo an SR we don't recognise.
            if let Ok(packets) = rtcp::parse_compound(data) {
                for rtcp_packet in &packets {
                    let blocks = match rtcp_packet {
                        rtcp::RtcpPacket::SenderReport(report) => report.reports.as_slice(),
                        rtcp::RtcpPacket::ReceiverReport(report) => report.reports.as_slice(),
                        rtcp::RtcpPacket::Other { .. } => &[],
                    };
                    for block in blocks {
                        participant
                            .leg
                            .record_reception_report(block, packet.arrival);
                    }
                }
            }
            return true;
        }
        let Ok(parsed) = RtpPacket::parse(data) else {
            return true;
        };
        // RFC 4733 telephone-event: never feed DTMF to the audio decoder (it would mangle the mix);
        // detect the key press and surface it on the control channel instead.
        if Some(parsed.payload_type) == participant.telephone_event_in {
            if let Ok(Some(event)) = participant.dtmf.on_packet(parsed.timestamp, parsed.payload) {
                self.pending_events.push(Event::Dtmf {
                    call_id: conference_id.to_string(),
                    from_tag: participant.tag.clone(),
                    to_tag: None,
                    digit: event.digit.to_string(),
                    // RTP timestamp units are samples at the 8 kHz telephone-event clock (RFC 4733).
                    duration_ms: u32::from(event.duration) / 8,
                    volume: -i32::from(event.volume),
                    source: None,
                });
            }
            return true;
        }
        if participant.leg.ingest_rtp(data).is_ok() {
            // Fold the receive-time arrival the datapath stamped into this leg's interarrival-jitter
            // estimate (RFC 3550 §6.4.1) — stamped at receive, so it reflects network, not queue, timing.
            participant.leg.observe_arrival(packet.arrival);
        }
        true
    }

    /// Drain the DTMF events detected since the last call (the actor forwards them to the control
    /// channel).
    pub fn drain_events(&mut self) -> std::vec::Drain<'_, Event> {
        self.pending_events.drain(..)
    }

    /// Append a periodic [`Event::CallQuality`] (RFC 3550 jitter/loss + ITU-T G.107 MOS) for every
    /// participant that has received audio. `network_delay_ms` is a fallback one-way network delay used
    /// only for a leg with no measured RTT yet — each leg prefers its own measured `rtt/2` when a
    /// reception report has yielded one (RFC 3550 §6.4.1); pass `0.0` for no fallback. The jitter
    /// buffer's own delay is always folded in.
    pub fn build_quality_events(&self, network_delay_ms: f64, out: &mut Vec<Event>) {
        for participant in &self.participants {
            if participant.leg.ingress_ssrc().is_none() {
                continue; // no inbound stream measured yet
            }
            // One-way mouth-to-ear delay = RTT/2 (ITU-T G.107 §7.4) when this leg has a measured RTT
            // (from an inbound reception report), else the caller's fallback.
            let one_way_delay_ms = participant
                .leg
                .ingress_rtt_ms()
                .map_or(network_delay_ms, |rtt_ms| rtt_ms / 2.0);
            // MOS from the engine's canonical G.107 E-model (`siphon-rtp-hep`, shared with the HEP
            // export path) — fed the leg's measured loss + jitter + one-way delay.
            let impairments = siphon_rtp_hep::mos::Impairments {
                loss_percent: participant.leg.ingress_loss_percent(),
                one_way_delay_ms,
                jitter_ms: participant.leg.ingress_jitter_ms(),
            };
            out.push(Event::CallQuality {
                conference_id: Some(self.conference_id().to_string()),
                call_id: None,
                from_tag: participant.tag.clone(),
                jitter_ms: impairments.jitter_ms,
                loss_percent: impairments.loss_percent,
                mos: siphon_rtp_hep::mos::estimate_mos(participant.mos_codec, impairments),
            });
        }
    }

    /// Build one RTCP **Sender Report** per participant with a resolved destination, for the given NTP
    /// wall-clock time, appending each as an [`Outbound`] toward the participant's endpoint (rtcp-mux,
    /// RFC 5761). The SR carries the NTP↔RTP mapping (lip-sync) + sender counts, plus a reception
    /// report on that participant's inbound stream — cumulative loss + extended highest sequence,
    /// interarrival jitter, and LSR/DLSR (from the peer's last SR, `now_micros` being the engine's
    /// monotonic-clock reading) — so the sender sees reception quality and can derive RTT
    /// (RFC 3550 §6.4.1).
    pub fn build_sender_reports(
        &mut self,
        ntp_timestamp: u64,
        now_micros: u64,
        out: &mut Vec<Outbound>,
    ) {
        let mut buffer = [0u8; rtcp::SENDER_REPORT_LEN + rtcp::RECEPTION_REPORT_LEN];
        for index in 0..self.participants.len() {
            let dst = self.participants[index].egress_dst;
            if !destination_usable(dst) {
                continue;
            }
            let egress_endpoint = self.participants[index].egress_endpoint;
            // `fraction_lost` advances a per-interval snapshot (RFC 3550 §6.4.1), so it needs `&mut`
            // and is taken only when this leg has an inbound stream to report a block for.
            let fraction_lost = if self.participants[index].leg.ingress_ssrc().is_some() {
                self.participants[index]
                    .leg
                    .fraction_lost_since_last_report()
            } else {
                0
            };
            let leg = &self.participants[index].leg;
            let block;
            let reports: &[rtcp::ReceptionReport] = if let Some(ssrc) = leg.ingress_ssrc() {
                block = rtcp::ReceptionReport {
                    ssrc,
                    fraction_lost,
                    cumulative_lost: leg.jitter_stats().losses as u32,
                    extended_highest_seq: leg.ingress_extended_highest_seq(),
                    jitter: leg.ingress_jitter(),
                    last_sr: leg.last_sr(),
                    delay_last_sr: leg.delay_since_last_sr(now_micros),
                };
                std::slice::from_ref(&block)
            } else {
                &[]
            };
            let Some(len) = rtcp::write_sender_report(
                leg.egress_ssrc(),
                ntp_timestamp,
                leg.egress_timestamp(),
                leg.egress_packets(),
                leg.egress_octets(),
                reports,
                &mut buffer,
            ) else {
                continue;
            };
            // SRTCP-encrypt the report for a secure participant; plain legs send it as is.
            let wire: &[u8] = if let Some(secure) = self.participants[index].secure.as_mut() {
                self.secure_out.clear();
                if secure
                    .protect(&buffer[..len], &mut self.secure_out)
                    .is_err()
                {
                    continue;
                }
                &self.secure_out
            } else {
                &buffer[..len]
            };
            out.push(Outbound {
                endpoint: egress_endpoint,
                dst,
                data: Bytes::copy_from_slice(wire),
            });
            // Record the SR we just sent (NTP middle-32 → logical send time) so a later reception
            // report from this peer can derive round-trip time (RFC 3550 §6.4.1).
            self.participants[index]
                .leg
                .record_sent_report(ntp_timestamp, now_micros);
        }
    }

    /// Advance the room one 20 ms tick: decode + resample every participant to the room rate, mix,
    /// then encode + transmit the mix toward each participant. Appends the egress datagrams to `out`
    /// and reports any active-speaker change.
    pub fn tick(&mut self, out: &mut Vec<Outbound>) -> ActiveSpeakerChange {
        let count = self.participants.len();
        if count == 0 {
            return ActiveSpeakerChange::Unchanged;
        }

        // Decode pass: each participant → one room-rate frame + its VAD/energy.
        for index in 0..count {
            self.roles[index] = self.participants[index].routing.role;
            let produced = {
                let participant = &mut self.participants[index];
                match participant.leg.next_pcm(&mut self.native_in) {
                    Ok(PcmFrame::Decoded(samples) | PcmFrame::Concealed(samples)) => Some(samples),
                    Ok(PcmFrame::Starved) | Err(_) => None,
                }
            };
            match produced {
                Some(samples) => {
                    let room_frame = self.room_frame;
                    let participant = &mut self.participants[index];
                    match participant.to_room.as_mut() {
                        Some(resampler) => {
                            self.resample_scratch.clear();
                            resampler
                                .process(&self.native_in[..samples], &mut self.resample_scratch);
                            fill_padded(
                                &mut self.room_rows[index][..room_frame],
                                &self.resample_scratch,
                            );
                        }
                        None => fill_padded(
                            &mut self.room_rows[index][..room_frame],
                            &self.native_in[..samples],
                        ),
                    }
                }
                None => self.room_rows[index][..self.room_frame].fill(0),
            }
            let frame = &self.room_rows[index][..self.room_frame];
            let energy = EnergyVad::energy(frame); // computed once, reused for VAD + top-M ranking
            self.energy[index] = energy;
            self.speaking[index] = self.participants[index].vad.is_speech_with_energy(energy);
        }

        // Resolve the sparse routing matrix (tags → current indices).
        self.build_routes();

        // Pull any bridged rooms' audio into one external frame (heard by everyone this room).
        let have_external = self.gather_external();

        // Mix.
        let active_mask = {
            let external = have_external.then_some(&self.external_buf[..self.room_frame]);
            let inputs = MixInputs {
                pcm: &self.room_rows[..count],
                roles: &self.roles[..count],
                energy: &self.energy[..count],
                speaking: &self.speaking[..count],
                external,
                frame_len: self.room_frame,
            };
            self.mixer
                .mix(&inputs, &self.whispers, &self.monitors, self.top_m)
        };

        // Feed this room's local-participant mix onward to every bridged room.
        self.send_to_bridges();

        // Egress pass: each participant hears its distinct mix (active talker / routed) or the shared
        // listener mix; resample room → native, encode, packetize with the leg's own SSRC, transmit.
        // Stateless listeners on the same codec share one encode of the listener mix (shared-encode).
        self.share_count = 0;
        self.listener_native_ready = false;
        for index in 0..count {
            let dst = self.participants[index].egress_dst;
            if !destination_usable(dst) {
                continue; // never transmit to an unresolved destination
            }
            let egress_endpoint = self.participants[index].egress_endpoint;
            let marker = !self.participants[index].started;
            let native_frame = self.participants[index].native_frame;

            // A listener (no distinct mix) on a stateless codec shares the encode: either the listener
            // mix is already its native PCM (native == room), or it is one shared room→8 kHz downsample
            // (narrowband listener in a wideband room) — encode once per codec and fan out.
            let native_rate = self.participants[index].native_rate;
            let shareable = !self.mixer.has_distinct_output(index)
                && self.participants[index].stateless
                && (native_rate == self.room_rate
                    || (native_rate == NARROWBAND_RATE_HZ && self.room_rate == ROOM_RATE_HZ));

            let payload_len = if shareable {
                match self.shared_encode(index) {
                    Some(len) => len,
                    None => continue,
                }
            } else {
                if let Some(resampler) = self.participants[index].from_room.as_mut() {
                    let output = self.mixer.output_for(index);
                    self.resample_scratch.clear();
                    resampler.process(output, &mut self.resample_scratch);
                    fill_padded(&mut self.native_out[..native_frame], &self.resample_scratch);
                } else {
                    let output = self.mixer.output_for(index);
                    fill_padded(&mut self.native_out[..native_frame], output);
                }
                match self.participants[index]
                    .leg
                    .encode_payload(&self.native_out[..native_frame], &mut self.payload)
                {
                    Ok(len) => len,
                    Err(_) => continue,
                }
            };

            let rtp_len = match self.participants[index].leg.packetize(
                &self.payload[..payload_len],
                marker,
                &mut self.rtp,
            ) {
                Ok(len) => len,
                Err(_) => continue,
            };
            // SRTP: encrypt the egress packet for a secure participant; plain legs send it as is.
            let wire: &[u8] = if let Some(secure) = self.participants[index].secure.as_mut() {
                self.secure_out.clear();
                if secure
                    .protect(&self.rtp[..rtp_len], &mut self.secure_out)
                    .is_err()
                {
                    continue;
                }
                &self.secure_out
            } else {
                &self.rtp[..rtp_len]
            };
            out.push(Outbound {
                endpoint: egress_endpoint,
                dst,
                data: Bytes::copy_from_slice(wire),
            });
            self.participants[index].started = true;
        }

        // Active-speaker change detection (the single loudest active talker).
        let dominant_tag = self
            .dominant_speaker(active_mask)
            .map(|index| self.participants[index].tag.clone());
        if dominant_tag == self.last_dominant_tag {
            ActiveSpeakerChange::Unchanged
        } else {
            self.last_dominant_tag = dominant_tag.clone();
            ActiveSpeakerChange::Changed(dominant_tag)
        }
    }

    /// Rebuild the sparse whisper/monitor index lists from each participant's tag-named routing.
    fn build_routes(&mut self) {
        self.whispers.clear();
        self.monitors.clear();
        for (index, participant) in self.participants.iter().enumerate() {
            if let Some(target_tag) = &participant.routing.whisper_target {
                if let Some(to) = self
                    .participants
                    .iter()
                    .position(|other| &other.tag == target_tag)
                {
                    self.whispers.push(Whisper { from: index, to });
                }
            }
            if let Some(target_tag) = &participant.routing.monitor_target {
                if let Some(target) = self
                    .participants
                    .iter()
                    .position(|other| &other.tag == target_tag)
                {
                    self.monitors.push(Monitor {
                        listener: index,
                        target,
                    });
                }
            }
        }
    }

    /// Produce participant `index`'s shared listener-mix payload into [`Conference::payload`],
    /// encoding the listener mix **once** per egress codec (payload type) per tick and reusing it for
    /// every other stateless listener on that codec. Returns the payload length.
    fn shared_encode(&mut self, index: usize) -> Option<usize> {
        let payload_type = self.participants[index].egress_payload_type;
        if let Some(slot) = self.share_classes[..self.share_count]
            .iter()
            .position(|(class_pt, _)| *class_pt == payload_type)
        {
            // Cache hit: reuse the already-encoded payload (no per-leg encode).
            let len = self.share_classes[slot].1.len();
            self.payload[..len].copy_from_slice(&self.share_classes[slot].1);
            Some(len)
        } else {
            // First listener of this codec this tick: encode the listener mix once and cache it. When
            // the listener's native rate differs from the room (a narrowband leg in a wideband room),
            // encode the shared room→8 kHz downsample instead of the room-rate mix.
            let native_rate = self.participants[index].native_rate;
            let native_frame = self.participants[index].native_frame;
            let len = if native_rate == self.room_rate {
                self.participants[index]
                    .leg
                    .encode_payload(self.mixer.listener_mix(), &mut self.payload)
                    .ok()?
            } else {
                self.ensure_listener_native();
                self.participants[index]
                    .leg
                    .encode_payload(&self.listener_native_buf[..native_frame], &mut self.payload)
                    .ok()?
            };
            if self.share_count < self.share_classes.len() {
                let slot = &mut self.share_classes[self.share_count];
                slot.0 = payload_type;
                slot.1.clear();
                slot.1.extend_from_slice(&self.payload[..len]);
            } else {
                self.share_classes
                    .push((payload_type, self.payload[..len].to_vec()));
            }
            self.share_count += 1;
            Some(len)
        }
    }

    /// Downsample the listener mix to 8 kHz once per tick (shared by every narrowband shared-encode
    /// listener), into [`Conference::listener_native_buf`].
    fn ensure_listener_native(&mut self) {
        if self.listener_native_ready {
            return;
        }
        if let Some(resampler) = self.listener_downsample.as_mut() {
            self.resample_scratch.clear();
            resampler.process(self.mixer.listener_mix(), &mut self.resample_scratch);
            let narrowband_frame = (NARROWBAND_RATE_HZ as usize / 1000) * 20;
            fill_padded(
                &mut self.listener_native_buf[..narrowband_frame],
                &self.resample_scratch,
            );
            self.listener_native_ready = true;
        }
    }

    /// The single loudest active talker this tick (the dominant speaker), if any.
    fn dominant_speaker(&self, active_mask: u64) -> Option<usize> {
        (0..self.participants.len())
            .filter(|&index| active_mask & (1 << index) != 0)
            .max_by_key(|&index| self.energy[index])
    }

    /// Drain each bridged-in room's channel (keeping only the newest frame), sum them into
    /// [`Conference::external_buf`], and report whether any bridged audio is present this tick.
    fn gather_external(&mut self) -> bool {
        if self.bridge_in.is_empty() {
            return false;
        }
        for slot in self.bridge_accum.iter_mut() {
            *slot = 0;
        }
        let mut have = false;
        for receiver in &self.bridge_in {
            let mut latest = None;
            while let Ok(frame) = receiver.try_recv() {
                latest = Some(frame); // keep only the newest (one-frame latency)
            }
            if let Some(frame) = latest {
                for (slot, &sample) in self.bridge_accum.iter_mut().zip(frame.iter()) {
                    *slot += i32::from(sample);
                }
                have = true;
            }
        }
        if have {
            for (dst, &value) in self.external_buf.iter_mut().zip(self.bridge_accum.iter()) {
                *dst = saturate_i16(value);
            }
        }
        have
    }

    /// Feed this room's local-participant mix to every bridged room (drop on a full channel — late
    /// bridge audio is worthless, same policy as the media mailboxes).
    fn send_to_bridges(&self) {
        if self.bridge_out.is_empty() {
            return;
        }
        let mix = self.mixer.participant_mix();
        for sender in &self.bridge_out {
            let _ = sender.try_send(mix.to_vec());
        }
    }

    /// Attach an inbound bridge channel (this room will hear the room on the other end). Bridging
    /// forces the room to the wideband rate so both ends share it (no inter-room resampling).
    pub fn add_bridge_in(&mut self, receiver: flume::Receiver<Vec<i16>>) {
        self.bridge_in.push(receiver);
        self.recompute_room_rate();
    }

    /// Attach an outbound bridge channel (this room feeds its participant mix to the other end).
    pub fn add_bridge_out(&mut self, sender: flume::Sender<Vec<i16>>) {
        self.bridge_out.push(sender);
        self.recompute_room_rate();
    }

    /// Recompute the room mix rate from the current membership + bridge state, rebuilding every
    /// participant's resamplers if it changed. A room is narrowband only when every participant is
    /// narrowband **and** it is not bridged (a bridge forces the wideband rate so both ends match).
    fn recompute_room_rate(&mut self) {
        let bridged = !self.bridge_in.is_empty() || !self.bridge_out.is_empty();
        let all_narrowband = self
            .participants
            .iter()
            .all(|participant| participant.native_rate <= NARROWBAND_RATE_HZ);
        let target = if all_narrowband && !bridged {
            NARROWBAND_RATE_HZ
        } else {
            ROOM_RATE_HZ
        };
        if target != self.room_rate {
            self.room_rate = target;
            self.room_frame = (target as usize / 1000) * 20;
            for participant in &mut self.participants {
                let (to_room, from_room) = build_resamplers(participant.native_rate, target);
                participant.to_room = to_room;
                participant.from_room = from_room;
            }
            // The shared room→8 kHz downsampler exists only when the room is wideband.
            self.listener_downsample = if target == ROOM_RATE_HZ {
                Resampler::new(ROOM_RATE_HZ, NARROWBAND_RATE_HZ).ok()
            } else {
                None
            };
        }
    }
}

/// Build a participant's native↔room resampler pair (both `None` when the rates already match).
fn build_resamplers(native_rate: u32, room_rate: u32) -> (Option<Resampler>, Option<Resampler>) {
    if native_rate == room_rate {
        (None, None)
    } else {
        (
            Resampler::new(native_rate, room_rate).ok(),
            Resampler::new(room_rate, native_rate).ok(),
        )
    }
}

/// One room-rate frame carried over a bridge between two conference rooms.
type BridgeFrame = Vec<i16>;

/// Copy `src` into `dst`, truncating or zero-padding to `dst`'s length (the room/native frames are
/// fixed-size; the resampler's output count can vary by a sample at the edges).
fn fill_padded(dst: &mut [i16], src: &[i16]) {
    let copied = src.len().min(dst.len());
    dst[..copied].copy_from_slice(&src[..copied]);
    dst[copied..].fill(0);
}

/// Whether a destination address is usable (resolved) — never transmit into the void.
fn destination_usable(dst: SocketAddr) -> bool {
    !dst.ip().is_unspecified() && dst.port() != 0
}

/// The current time as a 64-bit NTP timestamp (RFC 3550 §4): seconds since 1900 in the high 32 bits,
/// fractional seconds in the low 32. Wall-clock (RTCP carries real time, unlike the deterministic
/// mixing clock); `0` if the system clock predates the UNIX epoch.
fn ntp_now() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => {
            // UNIX epoch (1970) → NTP epoch (1900) is 2,208,988,800 seconds.
            let seconds = elapsed.as_secs().wrapping_add(2_208_988_800);
            let fraction = (u64::from(elapsed.subsec_nanos()) << 32) / 1_000_000_000;
            (seconds << 32) | fraction
        }
        Err(_) => 0,
    }
}

/// Clamp an `i32` mix sample to the `i16` range (the bridged-room accumulator can exceed it).
fn saturate_i16(value: i32) -> i16 {
    value.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

/// A control message into a running [`Conference`] actor.
pub enum ConferenceControl {
    /// Seat a participant.
    Add(Box<ParticipantConfig>),
    /// Remove a participant by tag.
    Remove(String),
    /// Live-update a participant's role / routing.
    Route(String, Routing),
    /// Set the active-speaker cap.
    SetTopM(usize),
    /// Attach an inbound bridge channel — hear another room (plan §7 room bridging).
    AddBridgeIn(flume::Receiver<BridgeFrame>),
    /// Attach an outbound bridge channel — feed this room's participant mix to another room.
    AddBridgeOut(flume::Sender<BridgeFrame>),
    /// Tear the room down.
    Stop,
}

/// A message into a conference actor's mailbox: a redirected datagram or a control op.
pub enum ConferenceInput {
    /// A datagram redirected by the datapath for one of this room's participant endpoints.
    Packet(RxPacket),
    /// A control operation from the engine.
    Control(ConferenceControl),
}

/// The async actor for one conference: drain the mailbox into [`Conference::ingest`], and on every
/// 20 ms tick run [`Conference::tick`] and transmit the mix. Exits on `Stop`, an empty room, or a
/// closed mailbox.
async fn run_conference<D>(
    mut conference: Conference,
    inbox: flume::Receiver<ConferenceInput>,
    datapath: D,
    events: Option<flume::Sender<Event>>,
) where
    D: Datapath,
{
    let mut outbound = Vec::new();
    let mut quality_events: Vec<Event> = Vec::new();
    let mut ticks_since_report = 0u64;
    let mut ticker = tokio::time::interval(ROOM_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            input = inbox.recv_async() => {
                let Ok(input) = input else { break };
                match input {
                    ConferenceInput::Packet(packet) => {
                        // Stamp media activity for the timeout sweep only when the packet passes the
                        // source gate (a spoofed spray must not keep an idle path alive).
                        if conference.ingest(&packet) {
                            datapath.note_activity(packet.endpoint);
                        }
                        // Forward any detected DTMF (RFC 4733) to the control channel.
                        for event in conference.drain_events() {
                            if let Some(sink) = &events {
                                if sink.try_send(event).is_err() {
                                    tracing::debug!("conference DTMF event dropped (sink full or closed)");
                                }
                            }
                        }
                    }
                    ConferenceInput::Control(ConferenceControl::Add(config)) => {
                        conference.add_participant(*config);
                    }
                    ConferenceInput::Control(ConferenceControl::Remove(tag)) => {
                        conference.remove_participant(&tag);
                        if conference.is_empty() {
                            break; // last leaver tears the room down
                        }
                    }
                    ConferenceInput::Control(ConferenceControl::Route(tag, routing)) => {
                        conference.set_routing(&tag, routing);
                    }
                    ConferenceInput::Control(ConferenceControl::SetTopM(top_m)) => {
                        conference.set_top_m(top_m);
                    }
                    ConferenceInput::Control(ConferenceControl::AddBridgeIn(receiver)) => {
                        conference.add_bridge_in(receiver);
                    }
                    ConferenceInput::Control(ConferenceControl::AddBridgeOut(sender)) => {
                        conference.add_bridge_out(sender);
                    }
                    ConferenceInput::Control(ConferenceControl::Stop) => break,
                }
            }
            _ = ticker.tick() => {
                outbound.clear();
                let change = conference.tick(&mut outbound);
                send_all(&datapath, &mut outbound).await;
                if let (ActiveSpeakerChange::Changed(from_tag), Some(sink)) = (change, &events) {
                    let event = Event::ActiveSpeaker {
                        conference_id: conference.conference_id().to_string(),
                        from_tag,
                    };
                    if sink.try_send(event).is_err() {
                        tracing::debug!("conference active-speaker event dropped (sink full or closed)");
                    }
                }
                // Periodic per-participant RTCP Sender Reports (lip-sync + liveness, RFC 3550 §6.4.1).
                ticks_since_report += 1;
                if ticks_since_report >= SR_INTERVAL_TICKS {
                    ticks_since_report = 0;
                    outbound.clear();
                    conference.build_sender_reports(ntp_now(), datapath.now_micros(), &mut outbound);
                    send_all(&datapath, &mut outbound).await;
                    // Periodic per-participant quality estimate (jitter/loss/MOS) on the control
                    // channel, so SIPhon sees live call quality without parsing RTCP itself.
                    if let Some(sink) = &events {
                        quality_events.clear();
                        conference.build_quality_events(0.0, &mut quality_events);
                        for event in quality_events.drain(..) {
                            if sink.try_send(event).is_err() {
                                tracing::debug!(
                                    "conference quality event dropped (sink full or closed)"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Map a negotiated `a=rtpmap` encoding name (uppercased, per [`CodecSpec`]) to the
/// [`siphon_rtp_hep::mos::Codec`] the G.107 estimator scores. Codecs the estimator does not model
/// (G.726, GSM-FR, CN) fall back to G.711 — the most optimistic, so their MOS is an upper bound.
pub(crate) fn hep_codec_for_name(encoding_name: &str) -> siphon_rtp_hep::mos::Codec {
    use siphon_rtp_hep::mos::Codec;
    match encoding_name.to_ascii_uppercase().as_str() {
        "PCMU" | "PCMA" => Codec::G711,
        "G722" => Codec::G722,
        "G729" | "G729A" | "G729AB" => Codec::G729,
        "G723" | "G723.1" => Codec::G723_1,
        "AMR-WB" | "AMRWB" => Codec::AmrWb,
        "AMR" | "AMR-NB" | "AMRNB" => Codec::AmrNb,
        "OPUS" => Codec::Opus,
        _ => Codec::G711,
    }
}

/// Transmit each queued datagram, draining `outbound`.
async fn send_all<D: Datapath>(datapath: &D, outbound: &mut Vec<Outbound>) {
    for datagram in outbound.drain(..) {
        if let Err(error) = datapath
            .send(datagram.endpoint, datagram.dst, &datagram.data)
            .await
        {
            tracing::debug!(%error, "conference send failed");
        }
    }
}

/// A seated participant as the registry tracks it (for routing teardown + idle reaping).
struct ConferenceMember {
    tag: String,
    endpoint: EndpointId,
    /// The logical tick at which this participant joined — the idle-reap baseline before it has sent
    /// any media (a just-joined silent leg is not reaped until `idle_ticks` elapse).
    joined_tick: u64,
}

/// A handle to a running conference actor.
struct ConferenceHandle {
    mailbox: flume::Sender<ConferenceInput>,
    members: Vec<ConferenceMember>,
    task: tokio::task::JoinHandle<()>,
}

/// The registry of conference rooms: routes redirected datagrams to the owning room's actor by
/// [`EndpointId`] and holds each room's control handle. Mirrors [`crate::media_pipeline::MediaRegistry`]
/// so the single redirect dispatcher can route by endpoint across media calls, SRTP bridges, WS
/// bridges, and conferences alike.
#[derive(Default)]
pub struct ConferenceRegistry {
    /// Participant endpoint → the owning room actor's mailbox (the dispatcher's routing table).
    routes: DashMap<EndpointId, flume::Sender<ConferenceInput>>,
    /// Conference id → control handle (mailbox + members + task).
    rooms: DashMap<String, ConferenceHandle>,
}

impl ConferenceRegistry {
    /// Whether the registry routes datagrams for `endpoint` (the dispatcher's predicate).
    #[must_use]
    pub fn owns(&self, endpoint: EndpointId) -> bool {
        self.routes.contains_key(&endpoint)
    }

    /// Route a redirected datagram to its owning room actor (drop on a full or closed mailbox —
    /// late media is worthless).
    pub fn dispatch(&self, packet: RxPacket) {
        if let Some(mailbox) = self.routes.get(&packet.endpoint) {
            if mailbox.try_send(ConferenceInput::Packet(packet)).is_err() {
                tracing::trace!("conference mailbox full or closed; dropping redirected datagram");
            }
        }
    }

    /// Whether a conference with this id exists.
    #[must_use]
    pub fn contains(&self, conference_id: &str) -> bool {
        self.rooms.contains_key(conference_id)
    }

    /// Number of live conference rooms (used by the memory-leak soak to confirm rooms drain).
    #[must_use]
    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    /// Total live participants across all rooms (the `conference_participants` metrics gauge). Reads
    /// the per-room membership rosters — the source of truth maintained by `join`/`leave`/`reap_idle`
    /// — so it is always exact, with no separate counter to drift.
    #[must_use]
    pub fn participant_count(&self) -> usize {
        self.rooms
            .iter()
            .map(|room| room.value().members.len())
            .sum()
    }

    /// Seat a participant, creating the room actor (over `datapath`, pushing events to `events`) if it
    /// does not yet exist. Returns `false` if the actor's mailbox is gone.
    pub fn join<D>(
        &self,
        conference_id: &str,
        config: ParticipantConfig,
        joined_tick: u64,
        datapath: D,
        events: Option<flume::Sender<Event>>,
    ) -> bool
    where
        D: Datapath + Clone + Send + 'static,
    {
        let endpoint = config.ingress_endpoint;
        let tag = config.tag.clone();
        let mailbox = self
            .rooms
            .entry(conference_id.to_string())
            .or_insert_with(|| {
                let (mailbox, inbox) = flume::bounded(1024);
                let conference = Conference::new(conference_id.to_string(), DEFAULT_TOP_M);
                let task = tokio::spawn(run_conference(conference, inbox, datapath, events));
                ConferenceHandle {
                    mailbox,
                    members: Vec::new(),
                    task,
                }
            })
            .mailbox
            .clone();

        if mailbox
            .try_send(ConferenceInput::Control(ConferenceControl::Add(Box::new(
                config,
            ))))
            .is_err()
        {
            return false;
        }
        self.routes.insert(endpoint, mailbox);
        if let Some(mut handle) = self.rooms.get_mut(conference_id) {
            handle.members.push(ConferenceMember {
                tag,
                endpoint,
                joined_tick,
            });
        }
        true
    }

    /// Remove a participant. Returns its freed ingress endpoint (for the engine to release), and tears
    /// the room down once its last participant leaves.
    pub fn leave(&self, conference_id: &str, tag: &str) -> Option<EndpointId> {
        let (endpoint, empty) = {
            let mut handle = self.rooms.get_mut(conference_id)?;
            let position = handle.members.iter().position(|member| member.tag == tag)?;
            let endpoint = handle.members.remove(position).endpoint;
            let _ = handle
                .mailbox
                .try_send(ConferenceInput::Control(ConferenceControl::Remove(
                    tag.to_string(),
                )));
            (endpoint, handle.members.is_empty())
        };
        self.routes.remove(&endpoint);
        if empty {
            if let Some((_, handle)) = self.rooms.remove(conference_id) {
                let _ = handle
                    .mailbox
                    .try_send(ConferenceInput::Control(ConferenceControl::Stop));
                handle.task.abort();
            }
        }
        Some(endpoint)
    }

    /// Live-update a participant's role / routing. Returns `false` if the room is gone.
    pub fn route(&self, conference_id: &str, tag: &str, routing: Routing) -> bool {
        match self.rooms.get(conference_id) {
            Some(handle) => handle
                .mailbox
                .try_send(ConferenceInput::Control(ConferenceControl::Route(
                    tag.to_string(),
                    routing,
                )))
                .is_ok(),
            None => false,
        }
    }

    /// Bridge two existing rooms (plan §7), wiring a one-frame-latency channel for each enabled
    /// direction so each room hears the other's participants. Returns `false` if either room is gone.
    pub fn bridge(&self, room_a: &str, room_b: &str, a_to_b: bool, b_to_a: bool) -> bool {
        let mailbox_a = self.rooms.get(room_a).map(|handle| handle.mailbox.clone());
        let mailbox_b = self.rooms.get(room_b).map(|handle| handle.mailbox.clone());
        let (Some(mailbox_a), Some(mailbox_b)) = (mailbox_a, mailbox_b) else {
            return false;
        };
        if a_to_b {
            let (sender, receiver) = flume::bounded(2);
            let _ = mailbox_a.try_send(ConferenceInput::Control(ConferenceControl::AddBridgeOut(
                sender,
            )));
            let _ = mailbox_b.try_send(ConferenceInput::Control(ConferenceControl::AddBridgeIn(
                receiver,
            )));
        }
        if b_to_a {
            let (sender, receiver) = flume::bounded(2);
            let _ = mailbox_b.try_send(ConferenceInput::Control(ConferenceControl::AddBridgeOut(
                sender,
            )));
            let _ = mailbox_a.try_send(ConferenceInput::Control(ConferenceControl::AddBridgeIn(
                receiver,
            )));
        }
        true
    }

    /// Tear a whole room down (engine shutdown / forced delete), returning every participant endpoint
    /// for the engine to release.
    pub fn deregister(&self, conference_id: &str) -> Vec<EndpointId> {
        let Some((_, handle)) = self.rooms.remove(conference_id) else {
            return Vec::new();
        };
        let _ = handle
            .mailbox
            .try_send(ConferenceInput::Control(ConferenceControl::Stop));
        let endpoints: Vec<EndpointId> = handle
            .members
            .iter()
            .map(|member| member.endpoint)
            .collect();
        for endpoint in &endpoints {
            self.routes.remove(endpoint);
        }
        handle.task.abort();
        endpoints
    }

    /// Reap participants whose media has been idle (no accepted packet) for at least `idle_ticks`, and
    /// tear down any room left empty. `last_activity` returns an endpoint's last-accepted-packet tick
    /// (the datapath's logical clock). Returns the freed participant endpoints for the engine to
    /// release. Deterministic — driven by the logical clock, never `Instant::now()`
    /// (docs/security-and-nat.md §4 layer 6).
    pub fn reap_idle(
        &self,
        now: u64,
        idle_ticks: u64,
        last_activity: impl Fn(EndpointId) -> Option<u64>,
    ) -> Vec<EndpointId> {
        let mut freed = Vec::new();
        let mut empty_rooms = Vec::new();
        // First pass: drop idle members from each room (no `rooms` re-entrancy inside the iteration).
        for mut room in self.rooms.iter_mut() {
            let handle = room.value_mut();
            let mut kept = Vec::with_capacity(handle.members.len());
            for member in std::mem::take(&mut handle.members) {
                let last = last_activity(member.endpoint)
                    .unwrap_or(member.joined_tick)
                    .max(member.joined_tick);
                if now.saturating_sub(last) >= idle_ticks {
                    let _ = handle.mailbox.try_send(ConferenceInput::Control(
                        ConferenceControl::Remove(member.tag.clone()),
                    ));
                    freed.push(member.endpoint);
                } else {
                    kept.push(member);
                }
            }
            handle.members = kept;
            if handle.members.is_empty() {
                empty_rooms.push(room.key().clone());
            }
        }
        // Second pass (guards from the iteration released): drop the routes and tear down empty rooms.
        for endpoint in &freed {
            self.routes.remove(endpoint);
        }
        for conference_id in empty_rooms {
            if let Some((_, handle)) = self.rooms.remove(&conference_id) {
                let _ = handle
                    .mailbox
                    .try_send(ConferenceInput::Control(ConferenceControl::Stop));
                handle.task.abort();
            }
        }
        freed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_codec::g711::G711;
    use siphon_rtp_media::rtp::{write_packet, RtpHeader};

    const PCMU: u8 = 0;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("addr")
    }

    /// A G.711 µ-law participant at 8 kHz, gated to `source_ip`, replying to `dst`.
    fn ulaw_config(index: usize, source_ip: &str, dst: &str) -> ParticipantConfig {
        ParticipantConfig {
            tag: format!("party-{index}"),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::ulaw()),
            ingress_endpoint: EndpointId(index as u64 + 1),
            egress_endpoint: EndpointId(index as u64 + 1),
            egress_dst: addr(dst),
            accepted_source: SourceFilter::Exact(source_ip.parse().expect("ip")),
            latch: false,
            egress_ssrc: 0xC000_0000 + index as u32,
            egress_payload_type: PCMU,
            mos_codec: siphon_rtp_hep::mos::Codec::G711,
            telephone_event_in: Some(101),
            secure: None,
            routing: Routing::default(),
        }
    }

    /// Encode `pcm` as a G.711 µ-law RTP packet from participant `index` (PT 0, 160-sample frame).
    fn ulaw_rtp(index: usize, sequence: u16, pcm: &[i16]) -> Vec<u8> {
        let mut encoder = G711::ulaw();
        let mut payload = [0u8; 160];
        let len = encoder.encode(pcm, &mut payload).expect("encode");
        let header = RtpHeader {
            marker: false,
            payload_type: PCMU,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 0x1000_0000 + index as u32,
        };
        let mut buffer = vec![0u8; 12 + len];
        let written = write_packet(&header, &payload[..len], &mut buffer).expect("write");
        buffer.truncate(written);
        buffer
    }

    fn rx(endpoint: u64, source: &str, data: Vec<u8>) -> RxPacket {
        rx_at(endpoint, source, data, 0)
    }

    /// Like [`rx`] but with an explicit receive-time `arrival` (µs) — drives the deterministic RTCP
    /// interarrival-jitter / DLSR tests (RFC 3550 §6.4.1) with no wall clock.
    fn rx_at(endpoint: u64, source: &str, data: Vec<u8>, arrival: u64) -> RxPacket {
        RxPacket {
            endpoint: EndpointId(endpoint),
            source: addr(source),
            arrival,
            data: Bytes::from(data),
        }
    }

    fn decode_ulaw(rtp: &[u8]) -> Vec<i16> {
        use siphon_rtp_codec::Decoder as _;
        let packet = RtpPacket::parse(rtp).expect("parse");
        let mut decoder = G711::ulaw();
        let mut out = vec![0i16; 320];
        let samples = decoder.decode(packet.payload, &mut out).expect("decode");
        out.truncate(samples);
        out
    }

    fn frame_energy(pcm: &[i16]) -> i64 {
        EnergyVad::energy(pcm)
    }

    #[test]
    fn three_participants_each_receive_one_mixed_packet() {
        let mut conference = Conference::new("room".into(), 0);
        assert!(conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000")));
        assert!(conference.add_participant(ulaw_config(1, "10.0.0.2", "10.0.0.2:4000")));
        assert!(conference.add_participant(ulaw_config(2, "10.0.0.3", "10.0.0.3:4000")));

        // Each party speaks a loud constant; feed enough to keep the jitter buffers primed.
        let loud = [6000i16; 160];
        for sequence in 0..10 {
            conference.ingest(&rx(1, "10.0.0.1:5000", ulaw_rtp(0, sequence, &loud)));
            conference.ingest(&rx(2, "10.0.0.2:5000", ulaw_rtp(1, sequence, &loud)));
            conference.ingest(&rx(3, "10.0.0.3:5000", ulaw_rtp(2, sequence, &loud)));
        }

        let mut out = Vec::new();
        for _ in 0..3 {
            out.clear();
            conference.tick(&mut out);
        }

        assert_eq!(out.len(), 3, "one mixed packet per participant");
        let mut ssrcs = Vec::new();
        for datagram in &out {
            let packet = RtpPacket::parse(&datagram.data).expect("valid egress RTP");
            assert_eq!(packet.payload_type, PCMU);
            assert_eq!(packet.payload.len(), 160, "G.711 8 kHz / 20 ms frame");
            ssrcs.push(packet.ssrc);
            // Each listener hears the other two loud talkers → non-silent egress.
            assert!(frame_energy(&decode_ulaw(&datagram.data)) > VAD_THRESHOLD);
        }
        ssrcs.sort_unstable();
        ssrcs.dedup();
        assert_eq!(
            ssrcs.len(),
            3,
            "each participant carries a distinct egress SSRC"
        );
    }

    #[test]
    fn unsignalled_source_is_dropped_from_the_mix() {
        // Party 0 is gated to 10.0.0.1; an attacker sprays loud audio from 10.0.0.99. Party 1 must
        // hear silence — the spoofed packets never enter the mix (RTPBleed defence).
        let mut conference = Conference::new("room".into(), 0);
        conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000"));
        conference.add_participant(ulaw_config(1, "10.0.0.2", "10.0.0.2:4000"));

        let loud = [6000i16; 160];
        for sequence in 0..10 {
            conference.ingest(&rx(1, "10.0.0.99:5000", ulaw_rtp(0, sequence, &loud)));
            // wrong source
        }

        let mut out = Vec::new();
        for _ in 0..3 {
            out.clear();
            conference.tick(&mut out);
        }
        let party_one = out
            .iter()
            .find(|datagram| datagram.endpoint == EndpointId(2))
            .expect("party 1 egress");
        assert!(
            frame_energy(&decode_ulaw(&party_one.data)) < VAD_THRESHOLD,
            "the spoofed source was rejected → the listener hears silence"
        );
    }

    #[test]
    fn signalled_source_reaches_the_mix() {
        // Positive control for the gate test: from the correct source, party 1 hears party 0.
        let mut conference = Conference::new("room".into(), 0);
        conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000"));
        conference.add_participant(ulaw_config(1, "10.0.0.2", "10.0.0.2:4000"));

        let loud = [6000i16; 160];
        for sequence in 0..10 {
            conference.ingest(&rx(1, "10.0.0.1:5000", ulaw_rtp(0, sequence, &loud)));
            // correct source
        }

        let mut out = Vec::new();
        for _ in 0..3 {
            out.clear();
            conference.tick(&mut out);
        }
        let party_one = out
            .iter()
            .find(|datagram| datagram.endpoint == EndpointId(2))
            .expect("party 1 egress");
        assert!(
            frame_energy(&decode_ulaw(&party_one.data)) > VAD_THRESHOLD,
            "the gated source is heard by the other party"
        );
    }

    #[test]
    fn participant_without_destination_is_not_transmitted_to() {
        // A participant whose address is not yet resolved (latching, no packet seen) gets no egress.
        let mut conference = Conference::new("room".into(), 0);
        conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000"));
        let mut pending = ulaw_config(1, "10.0.0.2", "10.0.0.2:4000");
        pending.egress_dst = addr("0.0.0.0:0"); // unresolved
        pending.latch = true;
        conference.add_participant(pending);

        let loud = [6000i16; 160];
        for sequence in 0..10 {
            conference.ingest(&rx(1, "10.0.0.1:5000", ulaw_rtp(0, sequence, &loud)));
        }
        let mut out = Vec::new();
        for _ in 0..3 {
            out.clear();
            conference.tick(&mut out);
        }
        assert!(
            out.iter()
                .all(|datagram| datagram.endpoint == EndpointId(1)),
            "only the resolved participant (endpoint 1) is transmitted to"
        );
    }

    #[test]
    fn remove_and_empty_room_lifecycle() {
        let mut conference = Conference::new("room".into(), 0);
        conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000"));
        conference.add_participant(ulaw_config(1, "10.0.0.2", "10.0.0.2:4000"));
        assert_eq!(conference.participant_count(), 2);
        assert!(conference.remove_participant("party-0"));
        assert_eq!(conference.participant_count(), 1);
        assert!(!conference.remove_participant("party-0"), "already gone");
        assert!(conference.remove_participant("party-1"));
        assert!(conference.is_empty());
    }

    #[test]
    fn bridged_room_audio_reaches_the_other_room() {
        // Room A's participant speaks; room B's participant is silent. With a one-way bridge A→B, B's
        // participant hears A's audio even though no one in B is talking.
        let (bridge_sender, bridge_receiver) = flume::bounded(2);
        let mut room_a = Conference::new("a".into(), 0);
        room_a.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000"));
        room_a.add_bridge_out(bridge_sender);

        let mut room_b = Conference::new("b".into(), 0);
        room_b.add_participant(ulaw_config(1, "10.0.0.2", "10.0.0.2:4000"));
        room_b.add_bridge_in(bridge_receiver);

        let loud = [6000i16; 160];
        for sequence in 0..10 {
            room_a.ingest(&rx(1, "10.0.0.1:5000", ulaw_rtp(0, sequence, &loud)));
        }
        // Tick A so it feeds its participant mix across the bridge.
        let mut out_a = Vec::new();
        for _ in 0..3 {
            out_a.clear();
            room_a.tick(&mut out_a);
        }
        // B ticks and hears A across the bridge (B's own participant is silent). The bridged frame is
        // consumed on the tick that drains the channel, so scan a few ticks for the audible one.
        let mut out_b = Vec::new();
        let mut heard_across_bridge = false;
        for _ in 0..3 {
            out_b.clear();
            room_b.tick(&mut out_b);
            if let Some(datagram) = out_b
                .iter()
                .find(|datagram| datagram.endpoint == EndpointId(2))
            {
                if frame_energy(&decode_ulaw(&datagram.data)) > VAD_THRESHOLD {
                    heard_across_bridge = true;
                    break;
                }
            }
        }
        assert!(
            heard_across_bridge,
            "room B hears room A's participant across the bridge"
        );
    }

    #[test]
    fn room_rate_tracks_membership_and_bridging() {
        use siphon_rtp_codec::g722::G722;

        // An all-G.711 (8 kHz) room uses the narrowband fast path.
        let mut conference = Conference::new("room".into(), 0);
        conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000"));
        conference.add_participant(ulaw_config(1, "10.0.0.2", "10.0.0.2:4000"));
        assert_eq!(
            conference.room_rate(),
            8_000,
            "all-narrowband room runs at 8 kHz"
        );

        // A wideband (G.722, 16 kHz) participant joins → the room flips to 16 kHz.
        let mut wideband = ulaw_config(2, "10.0.0.3", "10.0.0.3:4000");
        wideband.decoder = Box::new(G722::new(20));
        wideband.encoder = Box::new(G722::new(20));
        wideband.egress_payload_type = 9;
        conference.add_participant(wideband);
        assert_eq!(
            conference.room_rate(),
            16_000,
            "a wideband leg forces 16 kHz"
        );

        // It leaves → back to the narrowband fast path.
        conference.remove_participant("party-2");
        assert_eq!(
            conference.room_rate(),
            8_000,
            "narrowband again after the wideband leg leaves"
        );

        // Bridging forces the wideband rate even for an all-narrowband room.
        let (sender, _receiver) = flume::bounded(2);
        conference.add_bridge_out(sender);
        assert_eq!(conference.room_rate(), 16_000, "a bridge forces 16 kHz");
    }

    #[test]
    fn narrowband_room_still_mixes_correctly_at_8k() {
        // The 8 kHz fast path must still mix: three G.711 talkers, each hears the others, at 8 kHz.
        let mut conference = Conference::new("room".into(), 0);
        for index in 0..3 {
            conference.add_participant(ulaw_config(
                index,
                &format!("10.0.0.{}", index + 1),
                &format!("10.0.0.{}:4000", index + 1),
            ));
        }
        assert_eq!(conference.room_rate(), 8_000);
        let loud = [6000i16; 160];
        for sequence in 0..10 {
            for index in 0..3 {
                conference.ingest(&rx(
                    index as u64 + 1,
                    &format!("10.0.0.{}:5000", index + 1),
                    ulaw_rtp(index, sequence, &loud),
                ));
            }
        }
        let mut out = Vec::new();
        for _ in 0..3 {
            out.clear();
            conference.tick(&mut out);
        }
        assert_eq!(out.len(), 3, "one mixed packet per participant at 8 kHz");
        for datagram in &out {
            let packet = RtpPacket::parse(&datagram.data).expect("valid egress RTP");
            assert_eq!(packet.payload.len(), 160, "8 kHz / 20 ms G.711 frame");
            assert!(frame_energy(&decode_ulaw(&datagram.data)) > VAD_THRESHOLD);
        }
    }

    #[test]
    fn listeners_share_one_encode_of_the_listener_mix() {
        // One talker + two silent listeners, all G.711. The listeners hear the talker via the shared
        // listener mix; their egress payloads are byte-identical (one encode fanned out) but each is
        // its own RTP stream (distinct SSRC), and they decode to the talker's audio.
        let mut conference = Conference::new("room".into(), 0);
        for index in 0..3 {
            conference.add_participant(ulaw_config(
                index,
                &format!("10.0.0.{}", index + 1),
                &format!("10.0.0.{}:4000", index + 1),
            ));
        }
        let loud = [6000i16; 160];
        for sequence in 0..10 {
            conference.ingest(&rx(1, "10.0.0.1:5000", ulaw_rtp(0, sequence, &loud)));
        }
        let mut out = Vec::new();
        for _ in 0..3 {
            out.clear();
            conference.tick(&mut out);
        }
        let listener_one = out
            .iter()
            .find(|datagram| datagram.endpoint == EndpointId(2))
            .expect("p1");
        let listener_two = out
            .iter()
            .find(|datagram| datagram.endpoint == EndpointId(3))
            .expect("p2");
        let packet_one = RtpPacket::parse(&listener_one.data).expect("p1 rtp");
        let packet_two = RtpPacket::parse(&listener_two.data).expect("p2 rtp");
        assert_eq!(
            packet_one.payload, packet_two.payload,
            "listeners share one encoded listener-mix payload"
        );
        assert_ne!(
            packet_one.ssrc, packet_two.ssrc,
            "but each is its own RTP stream"
        );
        assert!(
            frame_energy(&decode_ulaw(&listener_one.data)) > VAD_THRESHOLD,
            "the listeners hear the talker"
        );
    }

    #[test]
    fn narrowband_listeners_share_a_downsampled_encode_in_a_wideband_room() {
        // An L16/16 kHz talker forces a wideband room; two silent G.711/8 kHz listeners hear one
        // shared room→8 kHz downsample of the listener mix, encoded once and fanned out.
        use siphon_rtp_codec::l16::L16;
        use siphon_rtp_codec::Encoder as _;

        let mut conference = Conference::new("room".into(), 0);
        let mut wideband = ulaw_config(0, "10.0.0.1", "10.0.0.1:4000");
        wideband.decoder = Box::new(L16::new(16_000, 20));
        wideband.encoder = Box::new(L16::new(16_000, 20));
        wideband.egress_payload_type = 97;
        conference.add_participant(wideband);
        conference.add_participant(ulaw_config(1, "10.0.0.2", "10.0.0.2:4000"));
        conference.add_participant(ulaw_config(2, "10.0.0.3", "10.0.0.3:4000"));
        assert_eq!(conference.room_rate(), 16_000, "wideband room");

        // A loud L16 RTP frame (320 samples @ 16 kHz).
        let l16_rtp = |sequence: u16| -> Vec<u8> {
            let mut encoder = L16::new(16_000, 20);
            let mut payload = [0u8; 640];
            let len = encoder
                .encode(&[6000i16; 320], &mut payload)
                .expect("encode");
            let header = RtpHeader {
                marker: false,
                payload_type: 97,
                sequence,
                timestamp: u32::from(sequence) * 320,
                ssrc: 0x5151_5151,
            };
            let mut buffer = vec![0u8; 12 + len];
            let written = write_packet(&header, &payload[..len], &mut buffer).expect("write");
            buffer.truncate(written);
            buffer
        };
        for sequence in 0..10 {
            conference.ingest(&rx(1, "10.0.0.1:5000", l16_rtp(sequence)));
        }
        let mut out = Vec::new();
        for _ in 0..3 {
            out.clear();
            conference.tick(&mut out);
        }
        let listener_one = out
            .iter()
            .find(|datagram| datagram.endpoint == EndpointId(2))
            .expect("l1");
        let listener_two = out
            .iter()
            .find(|datagram| datagram.endpoint == EndpointId(3))
            .expect("l2");
        let packet_one = RtpPacket::parse(&listener_one.data).expect("p1");
        let packet_two = RtpPacket::parse(&listener_two.data).expect("p2");
        assert_eq!(packet_one.payload_type, 0, "G.711 listener egress");
        assert_eq!(
            packet_one.payload.len(),
            160,
            "downsampled 8 kHz / 20 ms G.711 frame"
        );
        assert_eq!(
            packet_one.payload, packet_two.payload,
            "narrowband listeners share one downsampled encode"
        );
        assert_ne!(packet_one.ssrc, packet_two.ssrc, "distinct streams");
        assert!(
            frame_energy(&decode_ulaw(&listener_one.data)) > VAD_THRESHOLD,
            "the listeners hear the wideband talker"
        );
    }

    #[test]
    fn telephone_event_emits_dtmf_event() {
        // An RFC 4733 telephone-event packet is detected as a DTMF press and surfaced on the control
        // channel — never fed to the audio decoder.
        let mut conference = Conference::new("room".into(), 0);
        conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000"));
        // Event 5, End bit set, volume 10, duration 0x0320 = 800 samples (RFC 4733).
        let event_payload = [5u8, 0x80 | 10, 0x03, 0x20];
        let header = RtpHeader {
            marker: true,
            payload_type: 101,
            sequence: 1,
            timestamp: 16_000,
            ssrc: 0x1234_5678,
        };
        let mut buffer = vec![0u8; 16];
        let len = write_packet(&header, &event_payload, &mut buffer).expect("write");
        buffer.truncate(len);

        assert!(conference.ingest(&rx(1, "10.0.0.1:5000", buffer)));
        let events: Vec<Event> = conference.drain_events().collect();
        assert_eq!(events.len(), 1, "one DTMF event extracted");
        match &events[0] {
            Event::Dtmf {
                digit,
                from_tag,
                call_id,
                duration_ms,
                ..
            } => {
                assert_eq!(digit, "5");
                assert_eq!(from_tag, "party-0");
                assert_eq!(call_id, "room");
                assert_eq!(duration_ms, &100, "800 samples / 8 = 100 ms");
            }
            other => panic!("expected DTMF, got {other:?}"),
        }
    }

    #[test]
    fn sender_reports_carry_egress_counters() {
        use siphon_rtp_media::rtcp::{parse_compound, RtcpPacket};

        let mut conference = Conference::new("room".into(), 0);
        conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000"));
        conference.add_participant(ulaw_config(1, "10.0.0.2", "10.0.0.2:4000"));
        let loud = [6000i16; 160];
        for sequence in 0..10 {
            conference.ingest(&rx(1, "10.0.0.1:5000", ulaw_rtp(0, sequence, &loud)));
            conference.ingest(&rx(2, "10.0.0.2:5000", ulaw_rtp(1, sequence, &loud)));
        }
        let ticks = 4u32;
        let mut out = Vec::new();
        for _ in 0..ticks {
            out.clear();
            conference.tick(&mut out);
        }

        let ntp = 0x1122_3344_5566_7788u64;
        let mut reports = Vec::new();
        conference.build_sender_reports(ntp, 0, &mut reports);
        assert_eq!(
            reports.len(),
            2,
            "one SR per participant with a destination"
        );
        let parsed = parse_compound(&reports[0].data).expect("parse SR");
        match &parsed[0] {
            RtcpPacket::SenderReport(report) => {
                assert_eq!(report.ssrc, 0xC000_0000, "party-0's egress SSRC");
                assert_eq!(report.ntp_timestamp, ntp);
                assert_eq!(report.packet_count, ticks, "one egress packet per tick");
                assert_eq!(report.octet_count, ticks * 160, "160-byte G.711 payloads");
                // ...plus a reception report on party-0's inbound stream.
                assert_eq!(report.reports.len(), 1, "a reception report block");
                assert_eq!(
                    report.reports[0].ssrc, 0x1000_0000,
                    "party-0's inbound SSRC"
                );
            }
            other => panic!("expected SR, got {other:?}"),
        }
    }

    #[test]
    fn reception_report_carries_jitter_lsr_and_dlsr() {
        use siphon_rtp_media::rtcp::{parse_compound, RtcpPacket};

        let mut conference = Conference::new("room".into(), 0);
        assert!(conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000")));

        // Four audio packets whose arrivals drift off their RTP timestamps build interarrival jitter
        // (the schedule the MediaLeg unit test uses — jitter settles at 9 RTP units, RFC 3550 §6.4.1).
        let pcm = [3000i16; 160];
        for (sequence, &arrival) in [0u64, 20_000, 60_000, 80_000].iter().enumerate() {
            conference.ingest(&rx_at(
                1,
                "10.0.0.1:5000",
                ulaw_rtp(0, sequence as u16, &pcm),
                arrival,
            ));
        }

        // An inbound Sender Report (received at 90 ms) gives the engine an NTP timestamp to echo as LSR.
        let sr_ntp = 0x1122_3344_5566_7788u64;
        let mut sr_buffer = [0u8; rtcp::SENDER_REPORT_LEN];
        let sr_len = rtcp::write_sender_report(0x1000_0000, sr_ntp, 0, 0, 0, &[], &mut sr_buffer)
            .expect("build inbound SR");
        conference.ingest(&rx_at(
            1,
            "10.0.0.1:5000",
            sr_buffer[..sr_len].to_vec(),
            90_000,
        ));

        // Build the engine's report 1.0 s after the SR arrived ⇒ DLSR = 1 s = 65536 units of 1/65536 s.
        let mut reports = Vec::new();
        conference.build_sender_reports(0xAABB_CCDD_1122_3344, 90_000 + 1_000_000, &mut reports);

        let parsed = parse_compound(&reports[0].data).expect("parse SR");
        let RtcpPacket::SenderReport(report) = &parsed[0] else {
            panic!("expected SR, got {:?}", parsed[0]);
        };
        let block = report.reports[0];
        assert_eq!(block.jitter, 9, "drifting arrivals ⇒ interarrival jitter");
        assert_eq!(
            block.last_sender_report, 0x3344_5566,
            "LSR = middle 32 NTP bits of the inbound SR"
        );
        assert_eq!(
            block.delay_since_last_sr, 65_536,
            "DLSR = 1.0 s in 1/65536 s units"
        );
    }

    #[test]
    fn quality_events_carry_jitter_loss_and_mos() {
        let mut conference = Conference::new("room".into(), 0);
        assert!(conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000")));

        // In-order audio with drifting arrivals: builds jitter, no loss (RFC 3550 §6.4.1).
        let pcm = [3000i16; 160];
        for (sequence, &arrival) in [0u64, 20_000, 60_000, 80_000].iter().enumerate() {
            conference.ingest(&rx_at(
                1,
                "10.0.0.1:5000",
                ulaw_rtp(0, sequence as u16, &pcm),
                arrival,
            ));
        }

        let mut events = Vec::new();
        conference.build_quality_events(0.0, &mut events);
        assert_eq!(
            events.len(),
            1,
            "one quality event for the active participant"
        );
        match &events[0] {
            Event::CallQuality {
                conference_id,
                call_id,
                from_tag,
                jitter_ms,
                loss_percent,
                mos,
            } => {
                assert_eq!(conference_id.as_deref(), Some("room"));
                assert!(call_id.is_none(), "a conference event carries no call_id");
                assert_eq!(from_tag, "party-0");
                assert!(
                    *jitter_ms > 0.0,
                    "drifting arrivals ⇒ jitter, got {jitter_ms}"
                );
                assert_eq!(*loss_percent, 0.0, "all packets in order ⇒ no loss");
                assert!(*mos > 4.0, "clean low-jitter call ⇒ good MOS, got {mos}");
            }
            other => panic!("expected CallQuality, got {other:?}"),
        }
    }

    #[test]
    fn measured_rtt_from_inbound_reception_report_lowers_mos() {
        // End-to-end RTT (RFC 3550 §6.4.1): the engine sends an SR (recording its NTP↔send-time), the
        // peer replies with a reception report on the engine's egress SSRC echoing that LSR + a DLSR,
        // and the engine derives RTT — halved into the E-model one-way delay, which lowers the MOS.
        let mut conference = Conference::new("room".into(), 0);
        assert!(conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000")));

        // In-order audio so there is an inbound stream to report on (no loss).
        let pcm = [3000i16; 160];
        for sequence in 0..4u16 {
            conference.ingest(&rx_at(
                1,
                "10.0.0.1:5000",
                ulaw_rtp(0, sequence, &pcm),
                u64::from(sequence) * 20_000,
            ));
        }

        // Baseline: no reception report yet ⇒ no measured RTT ⇒ delay fallback 0.
        let mut baseline = Vec::new();
        conference.build_quality_events(0.0, &mut baseline);
        let Event::CallQuality {
            mos: baseline_mos, ..
        } = baseline[0]
        else {
            panic!("expected CallQuality, got {:?}", baseline[0]);
        };

        // The engine sends its SR at t = 100 ms with NTP middle-32 = 0x1234_5678.
        let engine_ntp = 0x0000_1234_5678_0000u64;
        let mut out = Vec::new();
        conference.build_sender_reports(engine_ntp, 100_000, &mut out);

        // The peer replies (arriving at t = 1.0 s) with a reception report on the engine's egress SSRC
        // (party-0 = 0xC000_0000), echoing that LSR and DLSR = 0.5 s (32768 units of 1/65536 s):
        // rtt = 1_000_000 − 500_000 − 100_000 = 400 ms ⇒ one-way 200 ms (past the G.107 delay knee).
        let block = rtcp::ReceptionReport {
            ssrc: 0xC000_0000,
            last_sr: 0x1234_5678,
            delay_last_sr: 32_768,
            ..rtcp::ReceptionReport::default()
        };
        let mut buffer = [0u8; rtcp::SENDER_REPORT_LEN + rtcp::RECEPTION_REPORT_LEN];
        let len = rtcp::write_sender_report(0x1000_0000, 0, 0, 0, 0, &[block], &mut buffer)
            .expect("peer SR with reception block");
        conference.ingest(&rx_at(
            1,
            "10.0.0.1:5000",
            buffer[..len].to_vec(),
            1_000_000,
        ));

        // The measured RTT now feeds one-way delay into the MOS, scoring below the delay-free baseline.
        let mut delayed = Vec::new();
        conference.build_quality_events(0.0, &mut delayed);
        let Event::CallQuality {
            mos: delayed_mos, ..
        } = delayed[0]
        else {
            panic!("expected CallQuality, got {:?}", delayed[0]);
        };
        assert!(
            delayed_mos < baseline_mos,
            "measured RTT (200 ms one-way) lowers MOS: {baseline_mos} -> {delayed_mos}"
        );
    }

    #[test]
    fn hep_codec_maps_encoding_names() {
        use siphon_rtp_hep::mos::Codec;
        // Static + dynamic codecs the estimator models map to their own impairment...
        assert_eq!(hep_codec_for_name("PCMU"), Codec::G711);
        assert_eq!(hep_codec_for_name("pcma"), Codec::G711); // case-insensitive
        assert_eq!(hep_codec_for_name("G722"), Codec::G722);
        assert_eq!(hep_codec_for_name("AMR-WB"), Codec::AmrWb);
        assert_eq!(hep_codec_for_name("AMR"), Codec::AmrNb);
        assert_eq!(hep_codec_for_name("OPUS"), Codec::Opus);
        assert_eq!(hep_codec_for_name("G729"), Codec::G729);
        // ...and unmodelled ones (G.726, GSM-FR) fall back to G.711.
        assert_eq!(hep_codec_for_name("G726-32"), Codec::G711);
        assert_eq!(hep_codec_for_name("GSM"), Codec::G711);
    }

    #[cfg(feature = "amr")]
    #[test]
    fn amr_wb_listener_receives_amr_wb_egress() {
        // A G.711 talker forces a 16 kHz room; an AMR-WB (16 kHz) listener receives the mix encoded
        // as a valid RFC 4867 AMR-WB payload (the VoLTE-conference egress case).
        use siphon_rtp_codec::amr::AmrWb;
        use siphon_rtp_codec::Decoder as _;

        let mut conference = Conference::new("room".into(), 0);
        conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000"));
        let mut wideband = ulaw_config(1, "10.0.0.2", "10.0.0.2:4000");
        wideband.decoder = Box::new(AmrWb::new());
        wideband.encoder = Box::new(AmrWb::new());
        wideband.egress_payload_type = 96;
        conference.add_participant(wideband);
        assert_eq!(
            conference.room_rate(),
            16_000,
            "wideband room for the AMR-WB leg"
        );

        let loud = [6000i16; 160];
        for sequence in 0..10 {
            conference.ingest(&rx(1, "10.0.0.1:5000", ulaw_rtp(0, sequence, &loud)));
        }
        let mut out = Vec::new();
        for _ in 0..3 {
            out.clear();
            conference.tick(&mut out);
        }
        let egress = out
            .iter()
            .find(|datagram| datagram.endpoint == EndpointId(2))
            .expect("amr egress");
        let packet = RtpPacket::parse(&egress.data).expect("rtp");
        assert_eq!(packet.payload_type, 96, "AMR-WB egress payload type");
        assert!(packet.payload.len() >= 2, "CMR + ToC + speech");
        assert_eq!(packet.payload[0], 0xF0, "CMR = no codec-mode request");
        // The payload round-trips through the AMR-WB decoder without error.
        let mut decoder = AmrWb::new();
        let mut pcm = vec![0i16; 320];
        assert!(
            decoder.decode(packet.payload, &mut pcm).is_ok(),
            "valid AMR-WB payload"
        );
    }

    #[test]
    fn secure_participant_decrypts_ingress_and_encrypts_egress() {
        // An SDES-SRTP participant: the engine decrypts its inbound audio into the mix and encrypts
        // the room mix back to it. A plain participant validates the decrypt; decrypting the secure
        // leg's egress validates the encrypt.
        use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};
        use siphon_rtp_srtp::SrtpContext;

        let local =
            CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("local key");
        let remote =
            CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("remote key");

        let mut conference = Conference::new("room".into(), 0);
        let mut secure = ulaw_config(0, "10.0.0.1", "10.0.0.1:4000");
        secure.secure = Some(SecureLeg::new(&local.key, &remote.key));
        conference.add_participant(secure);
        conference.add_participant(ulaw_config(1, "10.0.0.2", "10.0.0.2:4000"));

        // The secure leg's UA encrypts its audio with the remote key; the plain leg sends plaintext.
        let mut peer_encrypt = SrtpContext::from_key_material(&remote.key);
        let loud = [6000i16; 160];
        for sequence in 0..10 {
            let mut srtp = Vec::new();
            peer_encrypt
                .protect(&ulaw_rtp(0, sequence, &loud), &mut srtp)
                .expect("peer protect");
            conference.ingest(&rx(1, "10.0.0.1:5000", srtp));
            conference.ingest(&rx(2, "10.0.0.2:5000", ulaw_rtp(1, sequence, &loud)));
        }

        let mut out = Vec::new();
        for _ in 0..3 {
            out.clear();
            conference.tick(&mut out);
        }

        // The plain leg hears the secure talker → the engine decrypted its SRTP into the mix.
        let plain = out
            .iter()
            .find(|datagram| datagram.endpoint == EndpointId(2))
            .expect("plain egress");
        assert!(
            frame_energy(&decode_ulaw(&plain.data)) > VAD_THRESHOLD,
            "the plain leg hears the decrypted secure talker"
        );

        // The secure leg's egress is SRTP; its UA decrypts it with the local key and hears the room.
        let secure_egress = out
            .iter()
            .find(|datagram| datagram.endpoint == EndpointId(1))
            .expect("secure egress");
        let mut peer_decrypt = SrtpContext::from_key_material(&local.key);
        let mut clear = Vec::new();
        peer_decrypt
            .unprotect(&secure_egress.data, &mut clear)
            .expect("secure egress decrypts with the engine's offered key");
        assert_ne!(
            &secure_egress.data[..],
            &clear[..],
            "egress is SRTP, not plaintext"
        );
        assert!(
            frame_energy(&decode_ulaw(&clear)) > VAD_THRESHOLD,
            "the secure leg hears the room after decrypt"
        );
    }

    #[test]
    fn duplicate_tag_is_rejected() {
        let mut conference = Conference::new("room".into(), 0);
        assert!(conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000")));
        let mut duplicate = ulaw_config(9, "10.0.0.9", "10.0.0.9:4000");
        duplicate.tag = "party-0".into();
        assert!(!conference.add_participant(duplicate), "tag already seated");
    }

    proptest::proptest! {
        /// The conference ingest eats untrusted network bytes — RFC 5761 RTCP demux, RTP parse, SRTP
        /// decrypt (secure leg), RFC 4733 telephone-event detect — then the tick decodes/resamples/
        /// mixes/encodes what survived. Arbitrary input on either a plain or a secure leg must never
        /// panic, index out of bounds, or loop: it parses-or-drops and keeps mixing.
        #[test]
        fn ingest_arbitrary_bytes_never_panics(
            packets in proptest::collection::vec(
                (1u64..=2, proptest::collection::vec(proptest::num::u8::ANY, 0usize..400)),
                0usize..24,
            ),
        ) {
            use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};

            let local = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("local");
            let remote = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("remote");
            let mut conference = Conference::new("fuzz".into(), 0);
            conference.add_participant(ulaw_config(0, "10.0.0.1", "10.0.0.1:4000")); // plain (endpoint 1)
            let mut secure = ulaw_config(1, "10.0.0.2", "10.0.0.2:4000"); // SRTP (endpoint 2)
            secure.secure = Some(SecureLeg::new(&local.key, &remote.key));
            conference.add_participant(secure);

            let mut out = Vec::new();
            for (endpoint, data) in packets {
                // Use the gated source so the bytes actually reach the parse/decrypt path.
                let source = if endpoint == 1 { "10.0.0.1:5000" } else { "10.0.0.2:5000" };
                conference.ingest(&rx(endpoint, source, data));
                out.clear();
                conference.tick(&mut out);
                let _ = conference.drain_events().count();
            }
        }
    }
}
