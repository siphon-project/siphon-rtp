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
//! history they decoded. Mode requests from a receiver (RFC 4867 §4.3.1 CMR) are not applied: one
//! encoder output serves a whole group, so there is no per-receiver rate to steer.
//!
//! # Limits, stated
//! * The packetization interval of a cross-codec seat must equal the room's, so one inbound packet
//!   maps to one outbound packet. A seat that offers another interval is refused with the reason.
//!   A packet whose decoded length is not the negotiated frame is dropped and counted rather than
//!   re-framed (the room has no jitter buffer to re-frame against).
//! * No packet-loss concealment: a lost source packet is a gap at the receiver, as it is for a
//!   same-codec seat.
//! * Everything is mono (the codec trait boundary folds a multi-channel decode, as everywhere else).
//!
//! No allocation per packet: every buffer is sized when the first cross-codec seat arrives. The
//! decoder rebuild at a source change allocates, once per talk spurt.

use siphon_rtp_codec::factory::{self, CodecSpec};
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

/// One codec group: its encoder, the room-to-group resampler and the payload encoded for the packet
/// being fanned out.
struct Group {
    key: CodecSpec,
    encoder: Box<dyn Encoder>,
    resampler: Option<Resampler>,
    /// Mono samples per frame at the group's rate.
    frame: usize,
    resampled: Vec<i16>,
    payload: Vec<u8>,
    length: usize,
    /// The packet serial `payload` was encoded for.
    ready_serial: u64,
    /// Whether that encode succeeded.
    ok: bool,
}

/// A cross-codec seat as the transcoder holds it: the decoder for the audio it may send when it is
/// the source, and the resampler to the room codec's rate.
pub(super) struct SeatLeg {
    spec: CodecSpec,
    group: usize,
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
    groups: Vec<Group>,
    decode_buffer: Vec<i16>,
    room_pcm: Vec<i16>,
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
        let key = group_key(spec);
        let group = match self.groups.iter().position(|group| group.key == key) {
            Some(group) => group,
            None => {
                let rate = pair.encoder.params().sample_rate_hz;
                let to_group =
                    if rate == self.room_rate_hz {
                        None
                    } else {
                        Some(Resampler::new(self.room_rate_hz, rate).map_err(|error| {
                            format!("no resampler from the room's rate: {error}")
                        })?)
                    };
                self.groups.push(Group {
                    key,
                    encoder: pair.encoder,
                    resampler: to_group,
                    frame: pair.frame,
                    resampled: Vec::with_capacity(pair.frame * 2 + 64),
                    payload: vec![0; MAX_PAYLOAD],
                    length: 0,
                    ready_serial: 0,
                    ok: false,
                });
                self.groups.len() - 1
            }
        };
        Ok(SeatLeg {
            spec: spec.clone(),
            group,
            channels: pair.decoder.params().channels.max(1),
            decoder: pair.decoder,
            resampler,
        })
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
        for group in &mut self.groups {
            if let Some(resampler) = group.resampler.as_mut() {
                resampler.reset();
            }
        }
        true
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
        if self.groups[group].ready_serial == self.serial {
            return self.groups[group].ok;
        }
        if self.pcm == Pcm::Stale {
            self.decode_room_payload(room_payload());
        }
        let ok = self.pcm == Pcm::Ready && self.encode_group(group);
        let entry = &mut self.groups[group];
        entry.ready_serial = self.serial;
        entry.ok = ok;
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

    fn encode_group(&mut self, group: usize) -> bool {
        let entry = &mut self.groups[group];
        let pcm: &[i16] = match entry.resampler.as_mut() {
            Some(resampler) => {
                entry.resampled.clear();
                resampler.process(&self.room_pcm, &mut entry.resampled);
                &entry.resampled
            }
            None => &self.room_pcm,
        };
        if pcm.len() != entry.frame {
            self.stats.dropped += 1;
            return false;
        }
        self.stats.encodes += 1;
        match entry.encoder.encode(pcm, &mut entry.payload) {
            Ok(length) => {
                entry.length = length;
                true
            }
            Err(error) => {
                tracing::debug!(
                    target: "siphon_rtp::media", %error,
                    "a codec group's encoder refused a frame; dropped"
                );
                self.stats.dropped += 1;
                false
            }
        }
    }

    /// Write the audio packet a seat of `group` is sent into [`Self::synthesized`]: the group's
    /// payload under the room-domain `point`, timestamps on `receiver_clock_hz`. Only valid after
    /// [`Self::prepare_group`] returned `true`. Returns the packet's length.
    pub(super) fn synthesize_audio(
        &mut self,
        group: usize,
        point: StreamPoint,
        receiver_clock_hz: u32,
    ) -> Option<usize> {
        let header = RtpHeader {
            marker: point.marker,
            payload_type: self.room_spec.payload_type,
            sequence: point.sequence,
            timestamp: self.receiver_timestamp(point.timestamp, receiver_clock_hz),
            ssrc: point.ssrc,
        };
        let entry = &self.groups[group];
        write_packet(
            &header,
            &entry.payload[..entry.length],
            &mut self.synthesized,
        )
        .ok()
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
