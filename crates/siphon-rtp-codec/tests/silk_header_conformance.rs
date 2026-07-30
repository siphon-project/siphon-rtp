//! SILK LP-layer conformance: decode the header, stereo predictors, frame type and subframe gains of
//! real libopus streams and diff every field against libopus' own decode of the same bits.
//!
//! The finished acceptance gate for SILK is the same two-part oracle the CELT layer uses — exact
//! per-packet range-coder `final_range` equality, then RFC 6716 §6 `opus_compare` — but neither can run
//! until a *whole* SILK frame decodes, because both need the decoder to consume the packet to its end.
//! The sub-phases that exist now stop at the NLSF stage, mid-frame.
//!
//! So this harness uses the strongest check available at this depth: an **instrumented libopus** that
//! prints the side info it decoded, frame by frame (`reference/opus/silk_trace.patch`,
//! `reference/opus/dump_silk_trace.sh`; recipe in CONTRIBUTING.md). Every field this crate decodes is
//! compared against the C's value for the same packet — VAD and LBRR flags, the per-frame LBRR bit
//! layout, stereo prediction weights in Q13, the mid-only flag, signal and quantization-offset type,
//! the raw gain indices, and the dequantized Q16 gains. A single wrong symbol shows up as a named field
//! mismatch on a named packet.
//!
//! **Scope, stated plainly.** Per packet the harness reproduces the LP-layer header for both channels
//! and then the *first* SILK frame's stereo/type/gain symbols for the mid channel. It stops there,
//! since the next symbol is an NLSF stage-1 index and that phase does not exist yet. Two consequences:
//!
//! * A packet carrying LBRR data is checked to the end of the per-frame LBRR flags only — the LBRR
//!   frames themselves interleave NLSF and excitation data that cannot yet be skipped.
//! * Wherever the harness cannot follow the C to the end of a packet — an LBRR-bearing packet, or a
//!   40/60 ms packet whose frames 1.. were not decoded — the running log-gain is re-seeded from the
//!   dump afterwards. For a single-frame packet without LBRR nothing is re-seeded and the gain chain is
//!   verified to carry across packets on its own: the harness asserts that the value it arrived at
//!   already equals the C's, which is what makes the cross-frame gain state a real check rather than a
//!   per-packet one.
//!
//! Skips gracefully (with a notice) when the vectors or traces are absent, and refuses to pass
//! vacuously: with vectors present, at least one stream and a non-trivial number of packets must have
//! been scored.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use siphon_rtp_codec::opus::packet::{self, Mode};
use siphon_rtp_codec::opus::range_coder::RangeDecoder;
use siphon_rtp_codec::opus::silk::decoder::{SilkDecoder, MID_CHANNEL, SIDE_CHANNEL};
use siphon_rtp_codec::opus::silk::frame_type::decode_frame_type;
use siphon_rtp_codec::opus::silk::stereo_pred::{
    decode_mid_only, decode_stereo_weights, mid_only_flag_is_coded,
};
use siphon_rtp_codec::opus::silk::types::{CondCoding, InternalRate, SubframeLayout};

/// The rate the reference decode ran at (`dump_silk_trace.sh` uses `opus_demo -d 48000 2`).
const REFERENCE_RATE_HZ: u32 = 48_000;

/// One packet of an `opus_demo` `.bit` file: `[u32 BE len][u32 BE final_range][payload]`.
struct BitPacket {
    payload: Vec<u8>,
    /// The encoder's range-coder final value. Unused here — the LP-layer decode stops mid-packet, so
    /// the range coder never reaches its final state — but parsed so the framing stays honest and the
    /// field is ready for the full-frame gate.
    #[allow(dead_code)]
    final_range: u32,
}

fn parse_bit_stream(bytes: &[u8]) -> Result<Vec<BitPacket>, String> {
    let mut packets = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if offset + 8 > bytes.len() {
            return Err(format!("truncated packet header at offset {offset}"));
        }
        let length = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        let final_range = u32::from_be_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;
        if length > 1 << 20 || offset + length > bytes.len() {
            return Err(format!(
                "implausible packet length {length} at offset {offset}"
            ));
        }
        packets.push(BitPacket {
            payload: bytes[offset..offset + length].to_vec(),
            final_range,
        });
        offset += length;
    }
    Ok(packets)
}

/// One line of the instrumented libopus dump, parsed into the field group it reports.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceEvent {
    Header {
        channel: usize,
        frames_per_packet: usize,
        subframe_count: usize,
        rate_khz: usize,
        vad: [bool; 3],
        lbrr: bool,
    },
    LbrrFlags {
        channel: usize,
        flags: [bool; 3],
    },
    Stereo {
        lbrr: bool,
        frame: usize,
        w0_q13: i32,
        w1_q13: i32,
    },
    MidOnly {
        lbrr: bool,
        frame: usize,
        mid_only: bool,
    },
    FrameType {
        lbrr: bool,
        frame: usize,
        signal: usize,
        offset: usize,
    },
    GainIndices {
        lbrr: bool,
        frame: usize,
        indices: Vec<i32>,
    },
    Gains {
        subframe_count: usize,
        conditional: bool,
        last_gain_index: i32,
        gains_q16: Vec<i32>,
    },
}

/// Read `key=value` from a token, or fail loudly — a silently mis-parsed dump would make the whole
/// harness vacuous.
fn field<'a>(token: Option<&'a str>, key: &str) -> Result<&'a str, String> {
    let token = token.ok_or_else(|| format!("missing field {key}"))?;
    token
        .strip_prefix(&format!("{key}="))
        .ok_or_else(|| format!("expected {key}=..., got {token}"))
}

fn number(text: &str) -> Result<i32, String> {
    text.parse::<i32>()
        .map_err(|error| format!("not a number: {text} ({error})"))
}

fn flag(text: &str) -> Result<bool, String> {
    match number(text)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(format!("expected a 0/1 flag, got {other}")),
    }
}

fn triple(text: &str) -> Result<[bool; 3], String> {
    let mut out = [false; 3];
    let mut parts = text.split(',');
    for slot in &mut out {
        *slot = flag(
            parts
                .next()
                .ok_or_else(|| format!("short triple: {text}"))?,
        )?;
    }
    Ok(out)
}

/// Parse the dump into per-packet event lists, keyed by the `P<n>` packet index.
fn parse_trace(text: &str) -> Result<BTreeMap<usize, Vec<TraceEvent>>, String> {
    let mut packets: BTreeMap<usize, Vec<TraceEvent>> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let index_token = tokens.next().ok_or("empty line")?;
        let index: usize = index_token
            .strip_prefix('P')
            .ok_or_else(|| format!("expected P<n>, got {index_token}"))?
            .parse()
            .map_err(|_| format!("bad packet index: {index_token}"))?;
        let kind = tokens.next().ok_or("missing event kind")?;
        let event = match kind {
            "HDR" => TraceEvent::Header {
                channel: number(field(tokens.next(), "ch")?)? as usize,
                frames_per_packet: number(field(tokens.next(), "nframes")?)? as usize,
                subframe_count: number(field(tokens.next(), "nsubfr")?)? as usize,
                rate_khz: number(field(tokens.next(), "fskhz")?)? as usize,
                vad: triple(field(tokens.next(), "vad")?)?,
                lbrr: flag(field(tokens.next(), "lbrr")?)?,
            },
            "LBRRFLAGS" => TraceEvent::LbrrFlags {
                channel: number(field(tokens.next(), "ch")?)? as usize,
                flags: triple(tokens.next().ok_or("missing LBRR flags")?)?,
            },
            "STEREO" => TraceEvent::Stereo {
                lbrr: flag(field(tokens.next(), "lbrr")?)?,
                frame: number(field(tokens.next(), "frame")?)? as usize,
                w0_q13: number(field(tokens.next(), "w0")?)?,
                w1_q13: number(field(tokens.next(), "w1")?)?,
            },
            "MIDONLY" => TraceEvent::MidOnly {
                lbrr: flag(field(tokens.next(), "lbrr")?)?,
                frame: number(field(tokens.next(), "frame")?)? as usize,
                mid_only: flag(tokens.next().ok_or("missing mid-only value")?)?,
            },
            "TYPE" => TraceEvent::FrameType {
                lbrr: flag(field(tokens.next(), "lbrr")?)?,
                frame: number(field(tokens.next(), "frame")?)? as usize,
                signal: number(field(tokens.next(), "signal")?)? as usize,
                offset: number(field(tokens.next(), "offset")?)? as usize,
            },
            "GAINIDX" => {
                let lbrr = flag(field(tokens.next(), "lbrr")?)?;
                let frame = number(field(tokens.next(), "frame")?)? as usize;
                let count = number(field(tokens.next(), "n")?)? as usize;
                let indices: Vec<i32> = tokens
                    .map(number)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| format!("gain indices: {error}"))?;
                if indices.len() != count {
                    return Err(format!("GAINIDX n={count} but {} values", indices.len()));
                }
                TraceEvent::GainIndices {
                    lbrr,
                    frame,
                    indices,
                }
            }
            "GAINS" => {
                let count = number(field(tokens.next(), "n")?)? as usize;
                let conditional = flag(field(tokens.next(), "cond")?)?;
                let last_gain_index = number(field(tokens.next(), "last")?)?;
                let gains_q16: Vec<i32> = tokens
                    .map(number)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| format!("gains: {error}"))?;
                if gains_q16.len() != count {
                    return Err(format!("GAINS n={count} but {} values", gains_q16.len()));
                }
                TraceEvent::Gains {
                    subframe_count: count,
                    conditional,
                    last_gain_index,
                    gains_q16,
                }
            }
            // A later sub-phase adds its own field groups to the same dump (the instrumented
            // build is one shared patch). An event this harness does not consume is not an
            // error — it is a field group belonging to a phase that lives elsewhere.
            _ => continue,
        };
        packets.entry(index).or_default().push(event);
    }
    Ok(packets)
}

/// Find the first event of a kind matching `predicate`.
fn find<F>(events: &[TraceEvent], predicate: F) -> Option<&TraceEvent>
where
    F: Fn(&TraceEvent) -> bool,
{
    events.iter().find(|event| predicate(event))
}

/// The running log-gain libopus was left holding after this packet — the `last=` field of its final
/// `GAINS` line. Used to re-seed our decoder wherever the harness could not follow the C to the end of
/// the packet.
fn final_last_gain_index(events: &[TraceEvent]) -> Option<i32> {
    events
        .iter()
        .filter_map(|event| match event {
            TraceEvent::Gains {
                last_gain_index, ..
            } => Some(*last_gain_index),
            _ => None,
        })
        .next_back()
}

/// What one packet's comparison exercised, so the harness can prove it was not vacuous.
#[derive(Default, Debug)]
struct Coverage {
    packets: usize,
    stereo_packets: usize,
    mid_only_flags: usize,
    lbrr_packets: usize,
    gain_frames: usize,
    chained_gain_packets: usize,
}

impl Coverage {
    fn absorb(&mut self, other: &Coverage) {
        self.packets += other.packets;
        self.stereo_packets += other.stereo_packets;
        self.mid_only_flags += other.mid_only_flags;
        self.lbrr_packets += other.lbrr_packets;
        self.gain_frames += other.gain_frames;
        self.chained_gain_packets += other.chained_gain_packets;
    }
}

/// Decode one stream's LP-layer side info and compare it, packet by packet, against the dump.
fn check_stream(
    packets: &[BitPacket],
    trace: &BTreeMap<usize, Vec<TraceEvent>>,
) -> Result<Coverage, String> {
    let mut silk = SilkDecoder::new(REFERENCE_RATE_HZ, 2).map_err(|e| format!("new: {e:?}"))?;
    let mut coverage = Coverage::default();

    for (index, bit_packet) in packets.iter().enumerate() {
        if bit_packet.payload.is_empty() {
            continue; // DTX / dropped packet: libopus emits no side info for it.
        }
        let events = trace
            .get(&index)
            .ok_or_else(|| format!("packet {index}: no trace events"))?;
        let parsed =
            packet::parse(&bit_packet.payload).map_err(|e| format!("packet {index}: {e:?}"))?;
        if parsed.toc.mode() != Mode::Silk {
            return Err(format!(
                "packet {index}: not SILK-only (mode {:?}) — the generator must only produce SILK",
                parsed.toc.mode()
            ));
        }
        if parsed.frame_count() != 1 {
            return Err(format!(
                "packet {index}: {} Opus frames; the SILK-only generator emits one per packet",
                parsed.frame_count()
            ));
        }
        let frame = parsed.frames()[0];
        if frame.is_empty() {
            continue;
        }

        let channel_count = usize::from(parsed.toc.channels());
        let rate = InternalRate::from_bandwidth(parsed.toc.bandwidth());
        let duration_ms =
            parsed.toc.samples_per_frame(REFERENCE_RATE_HZ) / (REFERENCE_RATE_HZ as usize / 1000);
        let layout = SubframeLayout::from_duration_ms(duration_ms)
            .map_err(|e| format!("packet {index}: duration {duration_ms} ms: {e:?}"))?;

        // ── Geometry: the C reports its own view, so this validates the §4.2.2 tables and the
        // bandwidth -> internal-rate mapping across every packet, not just the ones we hand-picked.
        let reference_header = find(
            events,
            |event| matches!(event, TraceEvent::Header { channel, .. } if *channel == MID_CHANNEL),
        )
        .ok_or_else(|| format!("packet {index}: no HDR event for the mid channel"))?;
        if let TraceEvent::Header {
            frames_per_packet,
            subframe_count,
            rate_khz,
            ..
        } = reference_header
        {
            if *rate_khz != rate.khz() {
                return Err(format!(
                    "packet {index}: internal rate {} kHz, libopus decoded at {rate_khz} kHz",
                    rate.khz()
                ));
            }
            if *frames_per_packet != layout.frames_per_packet
                || *subframe_count != layout.subframe_count
            {
                return Err(format!(
                    "packet {index}: layout {}x{} subframes, libopus used {frames_per_packet}x{subframe_count}",
                    layout.frames_per_packet, layout.subframe_count
                ));
            }
        }

        silk.configure(channel_count, rate, duration_ms)
            .map_err(|e| format!("packet {index}: configure: {e:?}"))?;

        let mut decoder = RangeDecoder::new(frame);

        // ── LP-layer header (RFC 6716 §4.2.3-§4.2.4) ──────────────────────────────────────────
        let header = silk
            .decode_lp_layer_header(&mut decoder)
            .map_err(|e| format!("packet {index}: header: {e:?}"))?;
        for channel_index in 0..channel_count {
            let flags = header
                .channel(channel_index)
                .map_err(|e| format!("packet {index}: channel {channel_index}: {e:?}"))?;
            let reference = find(events, |event| {
                matches!(event, TraceEvent::Header { channel, .. } if *channel == channel_index)
            })
            .ok_or_else(|| format!("packet {index}: no HDR for channel {channel_index}"))?;
            if let TraceEvent::Header {
                vad,
                lbrr,
                frames_per_packet,
                ..
            } = reference
            {
                // Only the coded slots are meaningful: libopus leaves the rest of `VAD_flags` at
                // whatever the previous packet left there.
                if flags.vad_flags[..*frames_per_packet] != vad[..*frames_per_packet] {
                    return Err(format!(
                        "packet {index} ch{channel_index}: VAD flags {:?} != libopus {:?}",
                        &flags.vad_flags[..*frames_per_packet],
                        &vad[..*frames_per_packet]
                    ));
                }
                if flags.lbrr_flag != *lbrr {
                    return Err(format!(
                        "packet {index} ch{channel_index}: LBRR flag {} != libopus {lbrr}",
                        flags.lbrr_flag
                    ));
                }
            }
            let reference = find(events, |event| {
                matches!(event, TraceEvent::LbrrFlags { channel, .. } if *channel == channel_index)
            })
            .ok_or_else(|| format!("packet {index}: no LBRRFLAGS for channel {channel_index}"))?;
            if let TraceEvent::LbrrFlags {
                flags: reference, ..
            } = reference
            {
                if &flags.lbrr_flags != reference {
                    return Err(format!(
                        "packet {index} ch{channel_index}: per-frame LBRR flags {:?} != libopus {reference:?}",
                        flags.lbrr_flags
                    ));
                }
            }
        }
        coverage.packets += 1;
        if channel_count == 2 {
            coverage.stereo_packets += 1;
        }

        // An LBRR-bearing packet puts LBRR frames next, and those interleave NLSF/excitation data we
        // cannot skip yet. The header — including the per-frame LBRR bit layout, which is the whole
        // point of these streams — has been fully verified above.
        if header.any_lbrr() {
            coverage.lbrr_packets += 1;
            // libopus still decoded this packet's *regular* frames, which advanced its running
            // log-gain; we could not follow it past the LBRR data, so re-seed from the dump. Without
            // this, the next packet's independently coded gain is measured against a stale index and
            // fails the `max(index, previous - 16)` floor.
            if let Some(last) = final_last_gain_index(events) {
                silk.channel_mut(MID_CHANNEL)
                    .map_err(|e| format!("packet {index}: mid: {e:?}"))?
                    .last_gain_index = last as i8;
            }
            continue;
        }

        // ── Stereo prediction weights and mid-only flag (§4.2.7.1-2) ──────────────────────────
        let mut mid_only = false;
        if channel_count == 2 {
            let weights = decode_stereo_weights(&mut decoder);
            let reference = find(events, |event| {
                matches!(
                    event,
                    TraceEvent::Stereo {
                        lbrr: false,
                        frame: 0,
                        ..
                    }
                )
            })
            .ok_or_else(|| format!("packet {index}: no STEREO event"))?;
            if let TraceEvent::Stereo { w0_q13, w1_q13, .. } = reference {
                if weights.w0_q13 != *w0_q13 || weights.w1_q13 != *w1_q13 {
                    return Err(format!(
                        "packet {index}: stereo weights ({}, {}) != libopus ({w0_q13}, {w1_q13})",
                        weights.w0_q13, weights.w1_q13
                    ));
                }
            }

            // The flag is coded only when the side channel would not be coded anyway (§4.2.7.2).
            let side_coded = header
                .channel(SIDE_CHANNEL)
                .map_err(|e| format!("packet {index}: side: {e:?}"))?
                .vad_flags[0];
            if mid_only_flag_is_coded(side_coded) {
                mid_only = decode_mid_only(&mut decoder);
                let reference = find(events, |event| {
                    matches!(
                        event,
                        TraceEvent::MidOnly {
                            lbrr: false,
                            frame: 0,
                            ..
                        }
                    )
                })
                .ok_or_else(|| {
                    format!("packet {index}: expected a MIDONLY event (side VAD clear)")
                })?;
                if let TraceEvent::MidOnly {
                    mid_only: reference,
                    ..
                } = reference
                {
                    if mid_only != *reference {
                        return Err(format!(
                            "packet {index}: mid-only {mid_only} != libopus {reference}"
                        ));
                    }
                }
                coverage.mid_only_flags += 1;
            } else if find(events, |event| {
                matches!(
                    event,
                    TraceEvent::MidOnly {
                        lbrr: false,
                        frame: 0,
                        ..
                    }
                )
            })
            .is_some()
            {
                return Err(format!(
                    "packet {index}: libopus coded a mid-only flag but the side VAD flag is set"
                ));
            }
        }
        let _ = mid_only; // Consumed by the side-channel decode, which is a later phase.

        // ── Frame type (§4.2.7.3) ─────────────────────────────────────────────────────────────
        let active = header
            .channel(MID_CHANNEL)
            .map_err(|e| format!("packet {index}: mid: {e:?}"))?
            .is_active(0, false);
        let frame_type = decode_frame_type(&mut decoder, active)
            .map_err(|e| format!("packet {index}: frame type: {e:?}"))?;
        let reference = find(events, |event| {
            matches!(
                event,
                TraceEvent::FrameType {
                    lbrr: false,
                    frame: 0,
                    ..
                }
            )
        })
        .ok_or_else(|| format!("packet {index}: no TYPE event"))?;
        if let TraceEvent::FrameType { signal, offset, .. } = reference {
            let decoded_signal = frame_type.signal_type().index();
            let decoded_offset = usize::from(frame_type.symbol() & 1);
            if decoded_signal != *signal || decoded_offset != *offset {
                return Err(format!(
                    "packet {index}: frame type signal={decoded_signal} offset={decoded_offset} != libopus signal={signal} offset={offset}"
                ));
            }
        }

        // ── Subframe gains (§4.2.7.4) ─────────────────────────────────────────────────────────
        // Frame 0 of a packet is always independently coded (dec_API.c:342-345).
        let gains = silk
            .decode_subframe_gains(
                &mut decoder,
                MID_CHANNEL,
                frame_type.signal_type(),
                CondCoding::Independently,
            )
            .map_err(|e| format!("packet {index}: gains: {e:?}"))?;
        let reference = find(events, |event| {
            matches!(
                event,
                TraceEvent::GainIndices {
                    lbrr: false,
                    frame: 0,
                    ..
                }
            )
        })
        .ok_or_else(|| format!("packet {index}: no GAINIDX event"))?;
        if let TraceEvent::GainIndices { indices, .. } = reference {
            let decoded: Vec<i32> = gains.indices[..gains.count]
                .iter()
                .map(|&index| i32::from(index))
                .collect();
            if decoded != indices.as_slice() {
                return Err(format!(
                    "packet {index}: gain indices {decoded:?} != libopus {indices:?}"
                ));
            }
        }
        let reference = find(events, |event| matches!(event, TraceEvent::Gains { .. }))
            .ok_or_else(|| format!("packet {index}: no GAINS event"))?;
        if let TraceEvent::Gains {
            subframe_count,
            conditional,
            last_gain_index,
            gains_q16,
        } = reference
        {
            if *conditional {
                return Err(format!(
                    "packet {index}: libopus reports frame 0 as conditionally coded"
                ));
            }
            if gains.count != *subframe_count {
                return Err(format!(
                    "packet {index}: {} subframes, libopus used {subframe_count}",
                    gains.count
                ));
            }
            let decoded = &gains.gains_q16[..gains.count];
            if decoded != gains_q16.as_slice() {
                return Err(format!(
                    "packet {index}: gains {decoded:?} != libopus {gains_q16:?}"
                ));
            }
            let decoded_last = i32::from(gains.log_gains[gains.count - 1]);
            if decoded_last != *last_gain_index {
                return Err(format!(
                    "packet {index}: running log-gain {decoded_last} != libopus {last_gain_index}"
                ));
            }
            coverage.gain_frames += 1;

            // Cross-packet chaining. For a single-frame packet our state is already exactly libopus'
            // (no later frame touched it), so verify rather than overwrite — that is the check that
            // the running log-gain really carries across packets. For a multi-frame packet, frames
            // 1.. were not decoded, so re-seed from the dump's final GAINS line.
            if layout.frames_per_packet == 1 {
                let ours = i32::from(
                    silk.channel(MID_CHANNEL)
                        .map_err(|e| format!("packet {index}: mid: {e:?}"))?
                        .last_gain_index,
                );
                if ours != *last_gain_index {
                    return Err(format!(
                        "packet {index}: carried log-gain {ours} != libopus {last_gain_index}"
                    ));
                }
                coverage.chained_gain_packets += 1;
            } else {
                let final_gains = final_last_gain_index(events)
                    .ok_or_else(|| format!("packet {index}: no final GAINS event"))?;
                silk.channel_mut(MID_CHANNEL)
                    .map_err(|e| format!("packet {index}: mid: {e:?}"))?
                    .last_gain_index = final_gains as i8;
            }
        }
    }

    Ok(coverage)
}

/// `reference/opus/silk_only`, if present.
fn vector_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus/silk_only");
    dir.is_dir().then_some(dir)
}

#[test]
fn silk_lp_layer_matches_libopus() {
    let Some(dir) = vector_dir() else {
        eprintln!("silk LP-layer conformance: vectors not present — skipping");
        return;
    };
    let mut bit_files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|extension| extension == "bit"))
                .collect()
        })
        .unwrap_or_default();
    bit_files.sort();
    if bit_files.is_empty() {
        eprintln!(
            "silk LP-layer conformance: no .bit files in {} — skipping",
            dir.display()
        );
        return;
    }

    let mut passed: Vec<String> = Vec::new();
    let mut skipped: Vec<(String, String)> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut coverage = Coverage::default();

    for bit_path in &bit_files {
        let name = bit_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let trace_path = bit_path.with_extension("trace");
        let Ok(bytes) = std::fs::read(bit_path) else {
            skipped.push((name, "unreadable .bit".to_string()));
            continue;
        };
        let Ok(trace_text) = std::fs::read_to_string(&trace_path) else {
            skipped.push((
                name,
                "no .trace — run reference/opus/dump_silk_trace.sh".to_string(),
            ));
            continue;
        };
        let packets = match parse_bit_stream(&bytes) {
            Ok(packets) => packets,
            Err(error) => {
                failed.push((name, error));
                continue;
            }
        };
        let trace = match parse_trace(&trace_text) {
            Ok(trace) => trace,
            Err(error) => {
                failed.push((name, format!("trace: {error}")));
                continue;
            }
        };
        match check_stream(&packets, &trace) {
            Ok(stream_coverage) => {
                coverage.absorb(&stream_coverage);
                passed.push(name);
            }
            Err(reason) => failed.push((name, reason)),
        }
    }

    eprintln!(
        "silk LP-layer conformance: {} passed, {} skipped, {} failed",
        passed.len(),
        skipped.len(),
        failed.len()
    );
    eprintln!("  coverage: {coverage:?}");
    if !skipped.is_empty() {
        eprintln!("  skipped: {skipped:?}");
    }
    assert!(
        failed.is_empty(),
        "silk LP-layer: {} stream(s) failed: {failed:?}",
        failed.len()
    );
    // Vectors were present, so the run must not have been vacuous.
    assert!(
        !passed.is_empty(),
        "silk LP-layer: {} stream(s) present but none scored — are the .trace dumps built? skipped={skipped:?}",
        bit_files.len()
    );
    assert!(
        coverage.packets > 10_000,
        "expected the full vector set to score >10k packets, got {}",
        coverage.packets
    );
    assert!(
        coverage.gain_frames > 5_000,
        "expected >5k gain frames scored, got {}",
        coverage.gain_frames
    );
    assert!(
        coverage.chained_gain_packets > 1_000,
        "expected >1k packets to verify the carried log-gain, got {}",
        coverage.chained_gain_packets
    );
    assert!(
        coverage.stereo_packets > 0,
        "no stereo packet scored — the stereo prediction weights were never exercised"
    );
    assert!(
        coverage.lbrr_packets > 0,
        "no LBRR packet scored — the per-frame LBRR flag layout was never exercised"
    );
}
