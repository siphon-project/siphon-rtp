//! Seats that do not speak the room's codec.
//!
//! A forwarding room copies the source's payload to every seat that reads it (RFC 3550 §7.1, a
//! translator does not touch the encoding). A seat whose codec is another one is not refused any
//! more: the room decodes the source's packet **once**, and encodes the audio **once per codec
//! group**, a group being the seats that share one codec, rate, packetization interval and payload
//! format parameters (their encoded payload is byte-identical, so a single encoder output serves
//! them all). Each seat is then sent that payload on its own stream, through the same per-receiver
//! [`Translator`](siphon_rtp_media::translator::Translator) a same-codec seat uses, so sequence
//! numbers, timestamps and the marker bit behave the same on every seat whatever it hears.
//!
//! # The room-domain packet
//! Everything downstream of the source is described in the room codec's terms. A source in the room
//! codec is its own *room-domain* packet. A cross-codec source is decoded, resampled to the room
//! codec's rate, encoded once in the room codec and written as a synthetic room-domain packet that
//! keeps the source's SSRC and sequence numbers and has its timestamps rescaled to the room codec's
//! RTP clock. From the room-domain packet on, a cross-codec source and a room-codec source are
//! forwarded the same way.
//!
//! # What is shared, what is per stream
//! Decoder and encoder state belongs to one stream, so the decoder is reset (rebuilt) when the
//! source changes, which the room signals with [`Transcoder::begin_run`]. The encoder of a codec
//! group continues across a source change: it is one stream to its receivers, and its history is the
//! history they decoded.
//!
//! # Codec mode requests
//! A codec group is keyed by its codec **and** the mode ceiling its seats asked for, so one encoder
//! output still serves a whole group. The request is read from the seat's own inbound RTP, whether or
//! not the seat is the source (RFC 4867 §4.3.1: the CMR in the payloads a party sends caps the mode
//! sent back to it; 15 withdraws it), through [`siphon_rtp_codec::mode_request::ModeRequestTracker`],
//! which ignores a request outside the negotiated `mode-set` (RFC 4867 §8.1: such a mode MUST NOT be
//! sent). A seat whose ceiling changes moves to the group of that ceiling, created on demand with an
//! encoder that honours it; a group its last seat left is dropped. A seat in the same codec as the
//! talker that has no ceiling is still sent the talker's packets as they came, which carry the
//! talker's modes: only a seat that asked for a ceiling is re-encoded to honour it. A new group's
//! encoder starts with no history, so the seat hears one short re-convergence at the change.
//!
//! # Loss concealment
//! Inside one source run the transcoder follows the RTP sequence numbers (RFC 3550 §5.1). When up to
//! 120 ms of consecutive audio packets are missing and the timestamp advanced by exactly the missing
//! frames, [`Transcoder::begin_fill`] asks the decoder fed by the source for one concealment frame
//! per missing packet ([`Decoder::conceal`]: waveform substitution for G.711, ITU-T G.711 Appendix I;
//! the codecs' own PLC for AMR-NB, AMR-WB and Opus) and every transcoded receiver is sent it, so it sees a
//! concealed frame in place of a gap, with its sequence and timestamp continuous. A seat that is sent
//! the talker's packets as they came is not given a synthesized frame: its own decoder conceals. A
//! gap longer than 120 ms, a gap across a talk spurt (marker bit) or a silence suppression gap
//! (timestamp advanced by more than the missing frames) is not filled. AMR-NB conceals per 3GPP
//! TS 26.091, as the reference decoder does (no DTX, so a lost frame is concealed as speech).
//!
//! # Limits, stated
//! * The packetization interval of a cross-codec seat must equal the room's, so one inbound packet
//!   maps to one outbound packet. A seat that offers another interval is refused with the reason.
//!   A packet whose decoded length is not the negotiated frame is dropped and counted rather than
//!   re-framed (the room has no jitter buffer to re-frame against).
//! * Everything is mono (the codec trait boundary folds a multi-channel decode, as everywhere else).
//!
//! No allocation per packet: every buffer is sized when the first cross-codec seat arrives. The
//! decoder rebuild at a source change allocates, once per talk spurt.

use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_codec::mode_request::ModeRequestTracker;
use siphon_rtp_codec::{downmix_to_mono, Decoder, Encoder};
use siphon_rtp_dsp::resample::Resampler;
use siphon_rtp_media::rtp::{write_packet, RtpHeader, FIXED_HEADER_LEN};

use crate::conference::seat::fit;

/// The most values (interleaved, across channels) one decoded frame can hold: the RFC 7587 §6.1
/// maximum of 120 ms at 48 kHz in two channels.
const MAX_VALUES: usize = 48 * factory::OPUS_MAX_PTIME_MS as usize * 2;

/// The largest datagram the room builds: an RTP packet inside one Ethernet MTU.
const MAX_DATAGRAM: usize = 1500;

/// The most payload one encoded frame can carry in such a datagram.
const MAX_PAYLOAD: usize = MAX_DATAGRAM - FIXED_HEADER_LEN;

/// The longest gap of lost source packets that is concealed, in milliseconds. Past it the decoders'
/// concealment has faded to nothing (G.711 Appendix I mutes after 60 ms), and a run of invented
/// audio that long is worse than the gap.
const MAX_CONCEAL_MS: u32 = 120;

/// RFC 4733 §2.3: a telephone-event payload is one or more 4-octet blocks, the duration in the last
/// two octets of each.
const EVENT_BLOCK_LEN: usize = 4;

/// What the transcoder has done, for tests, the bench and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TranscodeStats {
    /// Decodes of an inbound packet (a room-codec source's, or a cross-codec source's).
    pub decodes: u64,
    /// Encodes: one per codec group per packet, and one per packet of a cross-codec source (into the
    /// room codec).
    pub encodes: u64,
    /// Inbound packets that could not be transcoded (a payload the decoder refused, or a frame of
    /// another length than the one negotiated).
    pub dropped: u64,
    /// Frames the decoder fed by the source concealed for lost source packets.
    pub concealed: u64,
    /// Concealed frames that could not be made (the decoder refused, or the frame was not the
    /// negotiated length) and were left as a gap.
    pub conceal_failed: u64,
}

/// A codec as the room can hold it: both halves built, and the frame they agree on.
struct Pair {
    decoder: Box<dyn Decoder>,
    encoder: Box<dyn Encoder>,
    /// Mono samples per frame at the codec's native rate.
    frame: usize,
    ptime_ms: u8,
}

/// Why `spec`'s decoder or encoder cannot be built here. Without the `amr` feature the reason names
/// the build, because the same offer works on a build that has it.
fn unavailable(spec: &CodecSpec, half: &str, error: &dyn std::fmt::Display) -> String {
    if spec.is_amr() && !cfg!(feature = "amr") {
        "this build lacks AMR transcoding (built without the `amr` feature)".to_string()
    } else {
        format!("no {half}: {error}")
    }
}

fn build_pair(spec: &CodecSpec) -> Result<Pair, String> {
    if spec.is_telephone_event() || spec.is_comfort_noise() {
        return Err("a companion payload, not an audio codec".to_string());
    }
    if let Some(reason) = spec.amr_unsupported() {
        return Err(reason.to_string());
    }
    let decoder =
        factory::decoder_for(spec).map_err(|error| unavailable(spec, "decoder", &error))?;
    let encoder =
        factory::encoder_for(spec).map_err(|error| unavailable(spec, "encoder", &error))?;
    // The same test every codec a mixing room seats passes: one frame length serves both halves.
    let measured = fit(&*decoder, &*encoder)
        .map_err(|refusal| format!("the room cannot hold it: {refusal}"))?;
    Ok(Pair {
        ptime_ms: decoder.params().ptime_ms,
        decoder,
        encoder,
        frame: measured.native_frame,
    })
}

/// Whether the room codec `room` can carry a seat in `seat`: both must be decodable and encodable
/// here, and share a packetization interval.
///
/// # Errors
/// The reason, naming the build when a missing `amr` feature is the cause.
pub(super) fn check_pair(room: &CodecSpec, seat: &CodecSpec) -> Result<(), String> {
    let room_pair = build_pair(room).map_err(|reason| {
        format!(
            "the room's codec {}/{} cannot be transcoded by this build: {reason}",
            room.encoding_name, room.clock_rate_hz
        )
    })?;
    let seat_pair = build_pair(seat)?;
    if seat_pair.ptime_ms != room_pair.ptime_ms {
        return Err(format!(
            "its packetization interval {} ms is not the room's {} ms",
            seat_pair.ptime_ms, room_pair.ptime_ms
        ));
    }
    Ok(())
}

/// The seats whose encoded payload is byte-identical: same codec, rate, interval and payload format
/// parameters. The payload type is per seat and not part of it.
fn group_key(spec: &CodecSpec) -> CodecSpec {
    let mut key = spec.clone();
    key.payload_type = 0;
    key
}

/// One encoded frame, and the serial of what it was encoded for.
struct Encoded {
    payload: Vec<u8>,
    length: usize,
    /// The packet serial `payload` was encoded for.
    ready_serial: u64,
    /// Whether that encode succeeded.
    ok: bool,
}

impl Encoded {
    fn new() -> Self {
        Self {
            payload: vec![0; MAX_PAYLOAD],
            length: 0,
            ready_serial: 0,
            ok: false,
        }
    }
}

/// One codec group: the seats whose encoded payload is byte-identical (same format, same mode
/// ceiling). Its encoder, the room-to-group resampler and the payload encoded for the packet being
/// fanned out, and for the concealed frame being fanned out.
struct Group {
    key: CodecSpec,
    /// The highest AMR mode the seats of the group asked for (RFC 4867 §4.3.1); `None` for no cap.
    ceiling: Option<u8>,
    /// Seats in the group; it is dropped when the last one leaves.
    members: usize,
    encoder: Box<dyn Encoder>,
    resampler: Option<Resampler>,
    /// Mono samples per frame at the group's rate.
    frame: usize,
    resampled: Vec<i16>,
    packet: Encoded,
    concealed: Encoded,
}

/// A cross-codec seat as the transcoder holds it: the decoder for the audio it may send when it is
/// the source, and the resampler to the room codec's rate.
pub(super) struct SeatLeg {
    spec: CodecSpec,
    group: usize,
    /// Mono samples per frame at the seat codec's native rate, for building a group.
    native_frame: usize,
    /// The seat's codec mode request, read from its own inbound RTP; `None` for a codec without one.
    modes: Option<ModeRequestTracker>,
    decoder: Box<dyn Decoder>,
    channels: u8,
    resampler: Option<Resampler>,
}

impl SeatLeg {
    /// The codec group the seat's audio is sent in.
    pub(super) fn group(&self) -> usize {
        self.group
    }

    /// A fresh stream: new decoder state and an empty resampler history.
    pub(super) fn restart(&mut self) {
        match factory::decoder_for(&self.spec) {
            Ok(decoder) => self.decoder = decoder,
            Err(error) => tracing::error!(
                target: "siphon_rtp::media", %error, codec = %self.spec.encoding_name,
                "could not rebuild a cross-codec seat's decoder; keeping the old state"
            ),
        }
        if let Some(resampler) = self.resampler.as_mut() {
            resampler.reset();
        }
    }
}

/// Where the current source's run began, to map timestamps onto the room's timeline.
#[derive(Clone, Copy)]
struct Run {
    ssrc: u32,
    /// The sequence number the next packet of the run should carry (RFC 3550 §5.1).
    next_sequence: u16,
    /// The timestamp of the last packet taken in, in the source's clock.
    last_timestamp: u32,
    /// Whether that packet was audio (a telephone-event or a talk-spurt start is no basis for
    /// concluding that the next audio packet follows a loss).
    last_was_audio: bool,
    /// The first timestamp seen, in the source's own clock.
    first_in: u32,
    /// The room-domain timestamp that corresponds to it.
    first_domain: u32,
}

/// Where the payload of an event packet being rewritten for a cross-codec receiver is read from.
#[derive(Clone, Copy)]
pub(super) enum EventSource<'a> {
    /// The cross-codec source's room-domain packet of this length, in the transcoder's buffer.
    Domain(usize),
    /// The source's own payload (a source in the room codec).
    Original(&'a [u8]),
}

/// The header of a room-domain packet, which is all a receiver's packet is built from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StreamPoint {
    pub(super) ssrc: u32,
    pub(super) sequence: u16,
    pub(super) timestamp: u32,
    pub(super) marker: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pcm {
    /// Not decoded for this packet yet.
    Stale,
    Ready,
    Failed,
}

/// The room's transcoder: its own decoder and encoder (the room codec), the codec groups, and the
/// scratch every packet goes through.
pub(super) struct Transcoder {
    room_spec: CodecSpec,
    decoder: Box<dyn Decoder>,
    decoder_channels: u8,
    /// The room codec's encoder, for a cross-codec source's audio.
    encoder: Box<dyn Encoder>,
    room_rate_hz: u32,
    room_clock_hz: u32,
    room_frame: usize,
    ptime_ms: u8,
    /// The codec groups; a slot is empty once its last seat left, and is reused.
    groups: Vec<Option<Group>>,
    decode_buffer: Vec<i16>,
    room_pcm: Vec<i16>,
    /// The concealed frame at the room codec's rate, mono.
    conceal_pcm: Vec<i16>,
    /// A cross-codec source's concealed frame as a room-domain packet, and its length.
    fill_domain: Vec<u8>,
    fill_domain_len: usize,
    /// Which concealed frame is being fanned out, and whether it could be made.
    fill_serial: u64,
    fill_ok: bool,
    uplink_payload: Vec<u8>,
    /// A cross-codec source's packet in room-domain form.
    domain: Vec<u8>,
    /// The packet a cross-codec receiver is sent, before its translator rewrites it.
    synthesized: Vec<u8>,
    event_buffer: Vec<u8>,
    pcm: Pcm,
    serial: u64,
    run: Option<Run>,
    stats: TranscodeStats,
}

/// `delta` ticks of `from_hz` as ticks of `to_hz` (truncating toward zero).
fn rescale(delta: i32, from_hz: u32, to_hz: u32) -> i32 {
    if from_hz == 0 || from_hz == to_hz {
        return delta;
    }
    (i64::from(delta) * i64::from(to_hz) / i64::from(from_hz)) as i32
}

/// Copy a telephone-event `payload` into `out`, rescaling the duration of each event block from
/// `from_hz` to `to_hz` ticks (RFC 4733 §2.3.5: the duration is in timestamp units of the event
/// stream's clock). A duration that does not fit in 16 bits saturates, which RFC 4733 §2.5.1.5
/// handles by ending the event and starting another; the receiver just sees a long event.
fn rescale_event(payload: &[u8], from_hz: u32, to_hz: u32, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(payload);
    if from_hz == 0 || from_hz == to_hz {
        return;
    }
    let (blocks, _) = out.as_chunks_mut::<EVENT_BLOCK_LEN>();
    for block in blocks {
        let duration = u32::from(u16::from_be_bytes([block[2], block[3]]));
        let scaled = (u64::from(duration) * u64::from(to_hz) / u64::from(from_hz))
            .min(u64::from(u16::MAX)) as u16;
        block[2..4].copy_from_slice(&scaled.to_be_bytes());
    }
}

impl Transcoder {
    /// A transcoder for a room carrying `room_spec`.
    ///
    /// # Errors
    /// The reason the room's codec cannot be decoded and encoded here.
    pub(super) fn new(room_spec: &CodecSpec) -> Result<Self, String> {
        let pair = build_pair(room_spec).map_err(|reason| {
            format!(
                "the room's codec {}/{} cannot be transcoded by this build: {reason}",
                room_spec.encoding_name, room_spec.clock_rate_hz
            )
        })?;
        let params = pair.decoder.params();
        Ok(Self {
            room_spec: room_spec.clone(),
            decoder_channels: params.channels.max(1),
            room_rate_hz: params.sample_rate_hz,
            room_clock_hz: room_spec.clock_rate_hz,
            room_frame: pair.frame,
            ptime_ms: pair.ptime_ms,
            decoder: pair.decoder,
            encoder: pair.encoder,
            groups: Vec::new(),
            decode_buffer: vec![0; MAX_VALUES],
            room_pcm: Vec::with_capacity(MAX_VALUES),
            conceal_pcm: Vec::with_capacity(MAX_VALUES),
            fill_domain: vec![0; MAX_DATAGRAM],
            fill_domain_len: 0,
            fill_serial: 0,
            fill_ok: false,
            uplink_payload: vec![0; MAX_PAYLOAD],
            domain: vec![0; MAX_DATAGRAM],
            synthesized: vec![0; MAX_DATAGRAM],
            event_buffer: Vec::with_capacity(MAX_PAYLOAD),
            pcm: Pcm::Stale,
            serial: 0,
            run: None,
            stats: TranscodeStats::default(),
        })
    }

    pub(super) fn stats(&self) -> TranscodeStats {
        self.stats
    }

    /// Codec groups in use.
    #[cfg(all(test, feature = "amr"))]
    pub(super) fn group_count(&self) -> usize {
        self.groups.iter().flatten().count()
    }

    /// Take a cross-codec seat in `spec`: build its decoder, find (or open) its codec group.
    ///
    /// # Errors
    /// The reason the seat cannot be transcoded to and from the room codec.
    pub(super) fn seat_leg(&mut self, spec: &CodecSpec) -> Result<SeatLeg, String> {
        let pair = build_pair(spec)?;
        if pair.ptime_ms != self.ptime_ms {
            return Err(format!(
                "its packetization interval {} ms is not the room's {} ms",
                pair.ptime_ms, self.ptime_ms
            ));
        }
        let seat_rate = pair.decoder.params().sample_rate_hz;
        let resampler = if seat_rate == self.room_rate_hz {
            None
        } else {
            Some(
                Resampler::new(seat_rate, self.room_rate_hz)
                    .map_err(|error| format!("no resampler to the room's rate: {error}"))?,
            )
        };
        let group = self.join_group(spec, pair.frame, None, Some(pair.encoder))?;
        Ok(SeatLeg {
            spec: spec.clone(),
            group,
            native_frame: pair.frame,
            modes: ModeRequestTracker::for_spec(spec),
            channels: pair.decoder.params().channels.max(1),
            decoder: pair.decoder,
            resampler,
        })
    }

    /// Put a seat of `spec` in the group of its codec and `ceiling`, opening the group with
    /// `encoder` (or a new one) when no seat is in it yet. Returns the group.
    fn join_group(
        &mut self,
        spec: &CodecSpec,
        frame: usize,
        ceiling: Option<u8>,
        encoder: Option<Box<dyn Encoder>>,
    ) -> Result<usize, String> {
        let key = group_key(spec);
        let existing = self.groups.iter().position(|group| {
            group
                .as_ref()
                .is_some_and(|group| group.key == key && group.ceiling == ceiling)
        });
        if let Some(index) = existing {
            if let Some(group) = self.groups[index].as_mut() {
                group.members += 1;
            }
            return Ok(index);
        }
        let mut encoder = match encoder {
            Some(encoder) => encoder,
            None => {
                factory::encoder_for(spec).map_err(|error| unavailable(spec, "encoder", &error))?
            }
        };
        if let Some(mode) = ceiling {
            // RFC 4867 §4.3.1: no mode above the one the seat asked for.
            encoder.request_mode(mode);
        }
        let rate = encoder.params().sample_rate_hz;
        let resampler = if rate == self.room_rate_hz {
            None
        } else {
            Some(
                Resampler::new(self.room_rate_hz, rate)
                    .map_err(|error| format!("no resampler from the room's rate: {error}"))?,
            )
        };
        let group = Group {
            key,
            ceiling,
            members: 1,
            encoder,
            resampler,
            frame,
            resampled: Vec::with_capacity(frame * 2 + 64),
            packet: Encoded::new(),
            concealed: Encoded::new(),
        };
        match self.groups.iter().position(Option::is_none) {
            Some(index) => {
                self.groups[index] = Some(group);
                Ok(index)
            }
            None => {
                self.groups.push(Some(group));
                Ok(self.groups.len() - 1)
            }
        }
    }

    /// A seat left group `index`; the group goes with its last seat.
    fn leave_group(&mut self, index: usize) {
        if let Some(slot) = self.groups.get_mut(index) {
            if let Some(group) = slot.as_mut() {
                group.members = group.members.saturating_sub(1);
                if group.members == 0 {
                    *slot = None;
                }
            }
        }
        while self.groups.last().is_some_and(Option::is_none) {
            self.groups.pop();
        }
    }

    /// A cross-codec seat left the room: it leaves its group.
    pub(super) fn release(&mut self, leg: SeatLeg) {
        self.leave_group(leg.group);
    }

    /// Read the codec mode request in `payload`, an audio packet of the seat's own stream, whether
    /// or not the seat is the source (RFC 4867 §4.3.1: the CMR the party sends caps the media sent
    /// back to it). When the seat's ceiling changes it moves to the group of that ceiling.
    pub(super) fn note_mode_request(&mut self, leg: &mut SeatLeg, payload: &[u8]) {
        let Some(modes) = leg.modes.as_mut() else {
            return;
        };
        if !modes.observe(payload) {
            return;
        }
        let ceiling = modes.ceiling();
        match self.join_group(&leg.spec, leg.native_frame, ceiling, None) {
            Ok(group) => {
                let previous = std::mem::replace(&mut leg.group, group);
                self.leave_group(previous);
            }
            Err(error) => tracing::error!(
                target: "siphon_rtp::media", %error, codec = %leg.spec.encoding_name, ?ceiling,
                "could not open the codec group of a seat's mode request; keeping its group"
            ),
        }
    }

    /// Whether a seat in group `receiver` is sent the packets of a source in group `source` as they
    /// came: the same payload format, and no mode ceiling of its own to honour (an encoder output
    /// is the only way to apply one).
    pub(super) fn shares_payload(&self, source: usize, receiver: usize) -> bool {
        if source == receiver {
            return true;
        }
        match (self.groups.get(source), self.groups.get(receiver)) {
            (Some(Some(source)), Some(Some(receiver))) => {
                source.key == receiver.key && receiver.ceiling.is_none()
            }
            _ => false,
        }
    }

    /// Start a new inbound packet: nothing is decoded or encoded for it yet.
    pub(super) fn begin_packet(&mut self) {
        self.serial += 1;
        self.pcm = Pcm::Stale;
    }

    /// Note the stream of the packet being fanned out. A new SSRC (or the first packet after
    /// [`Self::end_run`]) is a new run: the room decoder and the resamplers start clean. Returns
    /// whether it was one, so the caller can restart the source seat's own decoder.
    pub(super) fn begin_run(&mut self, ssrc: u32, timestamp: u32, from_cross_codec: bool) -> bool {
        if self.run.is_some_and(|run| run.ssrc == ssrc) {
            return false;
        }
        self.run = Some(Run {
            ssrc,
            next_sequence: 0,
            last_timestamp: timestamp,
            last_was_audio: false,
            first_in: timestamp,
            first_domain: if from_cross_codec { 0 } else { timestamp },
        });
        match factory::decoder_for(&self.room_spec) {
            Ok(decoder) => self.decoder = decoder,
            Err(error) => tracing::error!(
                target: "siphon_rtp::media", %error,
                "could not rebuild the room decoder; keeping the old state"
            ),
        }
        for group in self.groups.iter_mut().flatten() {
            if let Some(resampler) = group.resampler.as_mut() {
                resampler.reset();
            }
        }
        true
    }

    /// Take in the packet `point` of the current run (`audio`: a codec payload, not a telephone
    /// event), whose source clock is `clock_hz`, and return how many audio packets were lost right
    /// before it and are worth concealing (RFC 3550 §5.1: sequence numbers increase by one per
    /// packet, so a forward jump of `n + 1` is `n` lost packets).
    ///
    /// Zero for the first packet of a run, a talk-spurt start (marker bit, RFC 3551 §4.1), a packet
    /// next to a non-audio one, a late or duplicate packet (the expectation does not move back), a
    /// gap longer than [`MAX_CONCEAL_MS`], and a gap whose timestamps advanced by anything but
    /// exactly the missing frames (silence suppression, not loss). Call it once per source packet
    /// after [`Self::begin_run`], with `new_run` as that returned.
    pub(super) fn note_packet(
        &mut self,
        point: StreamPoint,
        clock_hz: u32,
        audio: bool,
        new_run: bool,
    ) -> u16 {
        let ptime_ms = u32::from(self.ptime_ms);
        let Some(run) = self.run.as_mut() else {
            return 0;
        };
        let forward = i32::from(point.sequence.wrapping_sub(run.next_sequence) as i16);
        let mut missing = 0u16;
        if !new_run && audio && run.last_was_audio && !point.marker && forward > 0 {
            let frame_ticks = u64::from(clock_hz) * u64::from(ptime_ms) / 1000;
            let lost = u64::from(forward.unsigned_abs());
            let advanced = u64::from(point.timestamp.wrapping_sub(run.last_timestamp));
            if ptime_ms > 0
                && lost * u64::from(ptime_ms) <= u64::from(MAX_CONCEAL_MS)
                && frame_ticks > 0
                && advanced == (lost + 1) * frame_ticks
            {
                missing = forward.unsigned_abs() as u16;
            }
        }
        if new_run || forward >= 0 {
            run.next_sequence = point.sequence.wrapping_add(1);
            run.last_timestamp = point.timestamp;
            run.last_was_audio = audio;
        }
        missing
    }

    /// The room-domain point of the first of `missing` lost frames before the packet at `point`
    /// (its timestamp in the source's clock `source_clock_hz`), and the room-domain ticks per
    /// frame. `from_cross_codec` maps the timestamp onto the room clock like the packet itself.
    pub(super) fn fill_start(
        &self,
        point: StreamPoint,
        missing: u16,
        source_clock_hz: u32,
        from_cross_codec: bool,
    ) -> (StreamPoint, u32) {
        let source_step = (u64::from(source_clock_hz) * u64::from(self.ptime_ms) / 1000) as u32;
        let first = point
            .timestamp
            .wrapping_sub(source_step.wrapping_mul(u32::from(missing)));
        let (timestamp, step) = if from_cross_codec {
            (
                self.domain_timestamp(first, source_clock_hz),
                rescale(source_step as i32, source_clock_hz, self.room_clock_hz) as u32,
            )
        } else {
            (first, source_step)
        };
        (
            StreamPoint {
                sequence: point.sequence.wrapping_sub(missing),
                timestamp,
                marker: false,
                ..point
            },
            step,
        )
    }

    /// The source went away or changed: the next packet starts a run whatever its SSRC.
    pub(super) fn end_run(&mut self) {
        self.run = None;
    }

    /// The room-domain timestamp of a cross-codec source's `timestamp` (in `source_clock_hz`).
    fn domain_timestamp(&self, timestamp: u32, source_clock_hz: u32) -> u32 {
        let Some(run) = self.run else {
            return timestamp;
        };
        let delta = timestamp.wrapping_sub(run.first_in) as i32;
        run.first_domain
            .wrapping_add(rescale(delta, source_clock_hz, self.room_clock_hz) as u32)
    }

    /// A room-domain timestamp as a receiver on `to_clock_hz` counts it. Relative to the run, which
    /// is all a translator uses.
    fn receiver_timestamp(&self, domain_timestamp: u32, to_clock_hz: u32) -> u32 {
        let first = self.run.map_or(domain_timestamp, |run| run.first_domain);
        let delta = domain_timestamp.wrapping_sub(first) as i32;
        rescale(delta, self.room_clock_hz, to_clock_hz) as u32
    }

    fn note_dropped(&mut self) {
        self.stats.dropped += 1;
    }

    /// Decode a cross-codec source's `payload` and write it as a room-domain packet into
    /// [`Self::domain`]. Returns the packet's length, or `None` when the payload could not be
    /// transcoded (counted).
    pub(super) fn uplink_audio(
        &mut self,
        leg: &mut SeatLeg,
        point: StreamPoint,
        source_clock_hz: u32,
        payload: &[u8],
    ) -> Option<usize> {
        self.stats.decodes += 1;
        let values = match leg.decoder.decode(payload, &mut self.decode_buffer) {
            Ok(values) => values,
            Err(error) => {
                tracing::debug!(
                    target: "siphon_rtp::media", %error, codec = %leg.spec.encoding_name,
                    "a cross-codec source's payload could not be decoded; dropped"
                );
                self.note_dropped();
                self.pcm = Pcm::Failed;
                return None;
            }
        };
        let samples = downmix_to_mono(&mut self.decode_buffer[..values], leg.channels);
        self.room_pcm.clear();
        match leg.resampler.as_mut() {
            Some(resampler) => {
                resampler.process(&self.decode_buffer[..samples], &mut self.room_pcm)
            }
            None => self
                .room_pcm
                .extend_from_slice(&self.decode_buffer[..samples]),
        }
        if self.room_pcm.len() != self.room_frame {
            tracing::debug!(
                target: "siphon_rtp::media",
                got = self.room_pcm.len(), expected = self.room_frame,
                "a cross-codec source's frame is not the negotiated length; dropped"
            );
            self.note_dropped();
            self.pcm = Pcm::Failed;
            return None;
        }
        self.pcm = Pcm::Ready;
        self.stats.encodes += 1;
        let length = self
            .encoder
            .encode(&self.room_pcm, &mut self.uplink_payload)
            .ok()?;
        let header = RtpHeader {
            marker: point.marker,
            payload_type: self.room_spec.payload_type,
            sequence: point.sequence,
            timestamp: self.domain_timestamp(point.timestamp, source_clock_hz),
            ssrc: point.ssrc,
        };
        write_packet(&header, &self.uplink_payload[..length], &mut self.domain).ok()
    }

    /// Write a cross-codec source's telephone-event packet as a room-domain event packet: the
    /// timestamp on the room's clock and the durations rescaled from `event_rate_hz` to the room
    /// codec's clock. Returns its length.
    pub(super) fn uplink_event(
        &mut self,
        point: StreamPoint,
        source_clock_hz: u32,
        event_rate_hz: u32,
        payload: &[u8],
    ) -> Option<usize> {
        rescale_event(
            payload,
            event_rate_hz,
            self.room_clock_hz,
            &mut self.event_buffer,
        );
        let header = RtpHeader {
            marker: point.marker,
            payload_type: self.room_spec.payload_type,
            sequence: point.sequence,
            timestamp: self.domain_timestamp(point.timestamp, source_clock_hz),
            ssrc: point.ssrc,
        };
        write_packet(&header, &self.event_buffer, &mut self.domain).ok()
    }

    /// The room-domain packet a cross-codec source's packet became.
    pub(super) fn domain(&self, length: usize) -> &[u8] {
        &self.domain[..length]
    }

    /// Make the current packet's audio available in codec group `group`'s encoding. Returns whether
    /// it is (a failed decode or encode is counted once per packet by [`Self::note_dropped`]).
    ///
    /// `room_payload` is the room-codec payload to decode, read only on the first group to ask for a
    /// packet that a cross-codec source did not already provide as audio.
    pub(super) fn prepare_group<'a>(
        &mut self,
        group: usize,
        room_payload: impl FnOnce() -> &'a [u8],
    ) -> bool {
        let Some(Some(entry)) = self.groups.get(group) else {
            return false;
        };
        if entry.packet.ready_serial == self.serial {
            return entry.packet.ok;
        }
        if self.pcm == Pcm::Stale {
            self.decode_room_payload(room_payload());
        }
        let ok = self.pcm == Pcm::Ready && self.encode_group(group, false);
        if let Some(Some(entry)) = self.groups.get_mut(group) {
            entry.packet.ready_serial = self.serial;
            entry.packet.ok = ok;
        }
        ok
    }

    /// Make the concealed frame [`Self::begin_fill`] produced available in codec group `group`'s
    /// encoding, once per frame. Returns whether it is.
    pub(super) fn prepare_fill_group(&mut self, group: usize) -> bool {
        let Some(Some(entry)) = self.groups.get(group) else {
            return false;
        };
        if entry.concealed.ready_serial == self.fill_serial {
            return entry.concealed.ok;
        }
        let ok = self.fill_ok && self.encode_group(group, true);
        if let Some(Some(entry)) = self.groups.get_mut(group) {
            entry.concealed.ready_serial = self.fill_serial;
            entry.concealed.ok = ok;
        }
        ok
    }

    fn decode_room_payload(&mut self, payload: &[u8]) {
        self.stats.decodes += 1;
        self.pcm = Pcm::Failed;
        let values = match self.decoder.decode(payload, &mut self.decode_buffer) {
            Ok(values) => values,
            Err(error) => {
                tracing::debug!(
                    target: "siphon_rtp::media", %error,
                    "the source's payload could not be decoded for the cross-codec seats; dropped"
                );
                self.note_dropped();
                return;
            }
        };
        let samples = downmix_to_mono(&mut self.decode_buffer[..values], self.decoder_channels);
        if samples != self.room_frame {
            tracing::debug!(
                target: "siphon_rtp::media", got = samples, expected = self.room_frame,
                "the source's frame is not the negotiated length; dropped for the cross-codec seats"
            );
            self.note_dropped();
            return;
        }
        self.room_pcm.clear();
        self.room_pcm
            .extend_from_slice(&self.decode_buffer[..samples]);
        self.pcm = Pcm::Ready;
    }

    /// Encode the room-rate audio into group `group`: the current packet's (`fill == false`) or the
    /// concealed frame's.
    fn encode_group(&mut self, group: usize, fill: bool) -> bool {
        let Some(Some(entry)) = self.groups.get_mut(group) else {
            return false;
        };
        let room_pcm: &[i16] = if fill {
            &self.conceal_pcm
        } else {
            &self.room_pcm
        };
        let Group {
            encoder,
            resampler,
            frame,
            resampled,
            packet,
            concealed,
            ..
        } = entry;
        let slot = if fill { concealed } else { packet };
        let pcm: &[i16] = match resampler.as_mut() {
            Some(resampler) => {
                resampled.clear();
                resampler.process(room_pcm, resampled);
                resampled
            }
            None => room_pcm,
        };
        if pcm.len() != *frame {
            if fill {
                self.stats.conceal_failed += 1;
            } else {
                self.stats.dropped += 1;
            }
            return false;
        }
        self.stats.encodes += 1;
        match encoder.encode(pcm, &mut slot.payload) {
            Ok(length) => {
                slot.length = length;
                true
            }
            Err(error) => {
                tracing::debug!(
                    target: "siphon_rtp::media", %error,
                    "a codec group's encoder refused a frame; dropped"
                );
                if fill {
                    self.stats.conceal_failed += 1;
                } else {
                    self.stats.dropped += 1;
                }
                false
            }
        }
    }

    /// Conceal one frame lost before the packet being fanned out (RFC 3550 §5.1 sequence gap):
    /// the decoder fed by the source, which is `leg`'s for a cross-codec source and the room codec's
    /// otherwise, synthesizes it ([`Decoder::conceal`]). For a cross-codec source it is also encoded
    /// into the room codec as the room-domain packet `point` (see [`Self::fill_domain`]), because the
    /// room-codec seats hear that stream. Returns whether the frame could be made; the groups encode
    /// it on demand ([`Self::prepare_fill_group`]).
    pub(super) fn begin_fill(&mut self, leg: Option<&mut SeatLeg>, point: StreamPoint) -> bool {
        self.fill_serial += 1;
        self.fill_ok = false;
        let cross_codec = leg.is_some();
        let (decoder, channels, resampler) = match leg {
            Some(leg) => (&mut *leg.decoder, leg.channels, leg.resampler.as_mut()),
            None => (&mut *self.decoder, self.decoder_channels, None),
        };
        let values = match decoder.conceal(&mut self.decode_buffer) {
            Ok(values) => values,
            Err(error) => {
                tracing::debug!(
                    target: "siphon_rtp::media", %error,
                    "the source's decoder could not conceal a lost packet; left as a gap"
                );
                self.stats.conceal_failed += 1;
                return false;
            }
        };
        let samples = downmix_to_mono(&mut self.decode_buffer[..values], channels);
        self.conceal_pcm.clear();
        match resampler {
            Some(resampler) => {
                resampler.process(&self.decode_buffer[..samples], &mut self.conceal_pcm)
            }
            None => self
                .conceal_pcm
                .extend_from_slice(&self.decode_buffer[..samples]),
        }
        if self.conceal_pcm.len() != self.room_frame {
            self.stats.conceal_failed += 1;
            return false;
        }
        if cross_codec {
            self.stats.encodes += 1;
            let Ok(length) = self
                .encoder
                .encode(&self.conceal_pcm, &mut self.uplink_payload)
            else {
                self.stats.conceal_failed += 1;
                return false;
            };
            let header = RtpHeader {
                marker: false,
                payload_type: self.room_spec.payload_type,
                sequence: point.sequence,
                timestamp: point.timestamp,
                ssrc: point.ssrc,
            };
            match write_packet(
                &header,
                &self.uplink_payload[..length],
                &mut self.fill_domain,
            ) {
                Ok(length) => self.fill_domain_len = length,
                Err(_) => {
                    self.stats.conceal_failed += 1;
                    return false;
                }
            }
        }
        self.stats.concealed += 1;
        self.fill_ok = true;
        true
    }

    /// A cross-codec source's concealed frame as a room-domain packet.
    pub(super) fn fill_domain(&self) -> &[u8] {
        &self.fill_domain[..self.fill_domain_len]
    }

    /// Write the audio packet a seat of `group` is sent into [`Self::synthesized`]: the group's
    /// payload (the concealed frame's when `fill`) under the room-domain `point`, timestamps on
    /// `receiver_clock_hz`. Only valid after [`Self::prepare_group`] (or
    /// [`Self::prepare_fill_group`]) returned `true`. Returns the packet's length.
    pub(super) fn synthesize_audio(
        &mut self,
        group: usize,
        point: StreamPoint,
        receiver_clock_hz: u32,
        fill: bool,
    ) -> Option<usize> {
        let header = RtpHeader {
            marker: point.marker,
            payload_type: self.room_spec.payload_type,
            sequence: point.sequence,
            timestamp: self.receiver_timestamp(point.timestamp, receiver_clock_hz),
            ssrc: point.ssrc,
        };
        let entry = self.groups.get(group)?.as_ref()?;
        let slot = if fill {
            &entry.concealed
        } else {
            &entry.packet
        };
        write_packet(&header, &slot.payload[..slot.length], &mut self.synthesized).ok()
    }

    /// Write a telephone-event packet for a cross-codec receiver into [`Self::synthesized`]:
    /// durations rescaled from the stream's `from_event_rate_hz` to the receiver's, timestamps onto
    /// its audio clock. `payload` is the event payload as it arrived on the room-domain packet.
    pub(super) fn synthesize_event(
        &mut self,
        point: StreamPoint,
        source: EventSource<'_>,
        from_event_rate_hz: u32,
        receiver_event_rate_hz: u32,
        receiver_clock_hz: u32,
    ) -> Option<usize> {
        let payload: &[u8] = match source {
            EventSource::Domain(length) => &self.domain[FIXED_HEADER_LEN..length],
            EventSource::Original(payload) => payload,
        };
        rescale_event(
            payload,
            from_event_rate_hz,
            receiver_event_rate_hz,
            &mut self.event_buffer,
        );
        let header = RtpHeader {
            marker: point.marker,
            payload_type: self.room_spec.payload_type,
            sequence: point.sequence,
            timestamp: self.receiver_timestamp(point.timestamp, receiver_clock_hz),
            ssrc: point.ssrc,
        };
        write_packet(&header, &self.event_buffer, &mut self.synthesized).ok()
    }

    /// The packet [`Self::synthesize_audio`] or [`Self::synthesize_event`] wrote.
    pub(super) fn synthesized(&self, length: usize) -> &[u8] {
        &self.synthesized[..length]
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn ticks_are_rescaled_across_clocks_in_both_directions() {
        assert_eq!(rescale(160, 8000, 48_000), 960);
        assert_eq!(rescale(960, 48_000, 8000), 160);
        assert_eq!(
            rescale(-160, 8000, 48_000),
            -960,
            "a packet before the run's start"
        );
        assert_eq!(rescale(160, 8000, 8000), 160);
        assert_eq!(
            rescale(160, 0, 8000),
            160,
            "a zero clock leaves the value alone"
        );
    }

    #[test]
    fn event_durations_are_rescaled_per_block_and_saturate() {
        let mut out = Vec::new();
        // Two blocks: event 5 for 800 ticks, event 6 for 60 000 ticks, both at 8 kHz.
        let payload = [5, 10, 0x03, 0x20, 6, 10, 0xEA, 0x60];
        rescale_event(&payload, 8000, 48_000, &mut out);
        assert_eq!(&out[..4], &[5, 10, 0x12, 0xC0]);
        assert_eq!(&out[4..], &[6, 10, 0xFF, 0xFF], "saturates at 16 bits");
        rescale_event(&payload, 8000, 8000, &mut out);
        assert_eq!(out, payload, "the same clock copies the payload");
        rescale_event(&payload[..6], 8000, 16_000, &mut out);
        assert_eq!(
            &out[4..],
            &[6, 10],
            "a trailing partial block is carried, not scaled"
        );
    }

    #[test]
    fn groups_ignore_the_payload_type_but_not_the_format() {
        let pcma = CodecSpec::new(8, "PCMA", 8000, 1, 20);
        let mut other_number = pcma.clone();
        other_number.payload_type = 110;
        assert_eq!(group_key(&pcma), group_key(&other_number));
        assert_ne!(
            group_key(&pcma),
            group_key(&CodecSpec::new(8, "PCMA", 8000, 1, 40))
        );
        assert_ne!(
            group_key(&pcma),
            group_key(&CodecSpec::new(0, "PCMU", 8000, 1, 20))
        );
    }

    #[test]
    fn a_companion_payload_is_not_a_codec() {
        let room = CodecSpec::new(0, "PCMU", 8000, 1, 20);
        let reason = check_pair(&room, &CodecSpec::new(13, "CN", 8000, 1, 20)).unwrap_err();
        assert!(reason.contains("companion"), "{reason}");
        let reason =
            check_pair(&room, &CodecSpec::new(101, "telephone-event", 8000, 1, 20)).unwrap_err();
        assert!(reason.contains("companion"), "{reason}");
    }

    #[test]
    fn a_room_codec_that_cannot_be_built_is_named_in_the_reason() {
        let unknown = CodecSpec::new(100, "NOSUCHCODEC", 8000, 1, 20);
        let reason = check_pair(&unknown, &CodecSpec::new(0, "PCMU", 8000, 1, 20)).unwrap_err();
        assert!(
            reason.contains("the room's codec NOSUCHCODEC/8000"),
            "{reason}"
        );
        assert!(reason.contains("this build"), "{reason}");
    }

    #[test]
    fn the_transcoder_maps_a_cross_codec_run_onto_the_room_clock() {
        let room = CodecSpec::new(0, "PCMU", 8000, 1, 20);
        let mut transcoder = Transcoder::new(&room).unwrap();
        assert!(
            transcoder.begin_run(7, 48_000, true),
            "the first packet starts a run"
        );
        assert!(
            !transcoder.begin_run(7, 48_960, true),
            "the same SSRC continues it"
        );
        // 48 kHz source: 960 ticks later is 160 room ticks later.
        assert_eq!(transcoder.domain_timestamp(48_960, 48_000), 160);
        assert_eq!(transcoder.receiver_timestamp(160, 48_000), 960);
        transcoder.end_run();
        assert!(
            transcoder.begin_run(7, 0, true),
            "after end_run the same SSRC starts a new run"
        );
    }
}
