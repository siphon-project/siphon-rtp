//! An Ogg Opus stream writer (RFC 7845 over RFC 3533): interleaved 16-bit PCM in, file bytes out.
//!
//! Sync and I/O-free — the caller owns the file. Every call appends whole pages to a caller-owned
//! buffer, so what reaches the disk is always a sequence of complete, independently decodable
//! pages, and a writer interrupted between calls leaves a file a decoder plays up to its last page.
//!
//! The encoder configuration is fixed for a stored recording rather than a network leg:
//!
//! * 20 ms frames, VBR, `Application::Voip` with a voice signal hint.
//! * **No in-band FEC**: it spends bits protecting against packet loss a file never has.
//! * **No DTX**: a DTX packet decodes as a gap, and it would make the granule arithmetic depend on
//!   the encoder's speech decision instead of on the audio written.

use siphon_rtp_codec::opus::enc::decision::{Application, SignalHint};
use siphon_rtp_codec::opus::enc::encoder::{OpusEncoder, RateControl};
use siphon_rtp_codec::CodecError;

use crate::ogg::{OggError, OggPageWriter};

/// Every Opus packet here is one 20 ms frame.
pub const FRAME_MS: u32 = 20;

/// Packets per audio page: about one second of audio, so a killed writer loses at most that much.
pub const PACKETS_PER_PAGE: usize = 50;

/// The granule clock: Ogg Opus counts samples at 48 kHz whatever the input rate (RFC 7845 §4).
const GRANULE_RATE_HZ: u32 = 48_000;

/// Largest packet a single 20 ms frame produces: a one-octet TOC plus the RFC 6716 §3.2.1 frame
/// ceiling of 1275 octets.
const MAX_PACKET_BYTES: usize = 1 + 1275;

/// What can stop an Ogg Opus stream.
#[derive(Debug, thiserror::Error)]
pub enum OggOpusError {
    /// The encoder refused its configuration or a frame.
    #[error("opus encoder: {0}")]
    Codec(#[from] CodecError),
    /// The page writer refused a packet.
    #[error("ogg: {0}")]
    Ogg(#[from] OggError),
    /// More PCM was offered after the stream had been finished.
    #[error("the stream has already ended")]
    Finished,
}

/// How to build a stream.
#[derive(Debug, Clone, Copy)]
pub struct OggOpusConfig<'a> {
    /// Input rate: 8, 12, 16, 24 or 48 kHz. Anything else is refused, never resampled.
    pub sample_rate_hz: u32,
    /// 1 or 2. Stereo input is interleaved left/right.
    pub channels: u8,
    /// Target bitrate for the whole stream, in bit/s.
    pub bitrate_bps: u32,
    /// The logical stream's serial number (RFC 3533 §6).
    pub serial: u32,
    /// The vendor string in `OpusTags` (RFC 7845 §5.2).
    pub vendor: &'a str,
}

/// One Ogg Opus logical stream being written.
pub struct OggOpusWriter {
    encoder: Box<OpusEncoder>,
    pages: OggPageWriter,
    channels: usize,
    /// Samples per channel in one frame at the input rate.
    frame_samples: usize,
    /// 48 kHz granule samples per input sample.
    granule_step: u64,
    /// The encoder's lookahead at the input rate: the samples of padding it emits before the audio.
    lookahead: u64,
    /// One frame of interleaved PCM being filled.
    staging: Vec<i16>,
    staged: usize,
    packet: Vec<u8>,
    /// Interleaved samples of real audio accepted, so a partial sample frame is never miscounted.
    input_samples: u64,
    /// Frames encoded so far.
    frames_encoded: u64,
    head: Vec<u8>,
    tags: Vec<u8>,
    finished: bool,
}

impl std::fmt::Debug for OggOpusWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OggOpusWriter")
            .field("channels", &self.channels)
            .field("frame_samples", &self.frame_samples)
            .field("input_samples", &self.input_samples)
            .field("frames_encoded", &self.frames_encoded)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl OggOpusWriter {
    /// Build the encoder and the two header packets. Fails, touching nothing, on an input rate or
    /// channel count Opus cannot take or a bitrate the encoder refuses.
    pub fn new(config: OggOpusConfig<'_>) -> Result<Self, OggOpusError> {
        let channels = usize::from(config.channels);
        let mut encoder = Box::new(OpusEncoder::new(
            config.sample_rate_hz,
            channels,
            Application::Voip,
        )?);
        let bitrate = i32::try_from(config.bitrate_bps).map_err(|_| {
            CodecError::Unsupported("opus enc: bitrate must be 500..=512000 per channel")
        })?;
        encoder.set_bitrate(Some(bitrate))?;
        encoder.set_rate_control(RateControl::Variable);
        encoder.set_signal_hint(SignalHint::Voice);
        encoder.set_in_band_fec(false);
        encoder.set_dtx(false);

        let frame_samples = (config.sample_rate_hz * FRAME_MS / 1000) as usize;
        let granule_step = u64::from(GRANULE_RATE_HZ / config.sample_rate_hz);
        let lookahead = encoder.lookahead() as u64;
        // RFC 7845 §4.2: pre-skip is the encoder's own delay, counted at 48 kHz.
        let pre_skip = u16::try_from(lookahead * granule_step).map_err(|_| {
            CodecError::Unsupported("opus enc: lookahead does not fit the pre-skip field")
        })?;
        Ok(Self {
            encoder,
            pages: OggPageWriter::new(config.serial, PACKETS_PER_PAGE * MAX_PACKET_BYTES),
            channels,
            frame_samples,
            granule_step,
            lookahead,
            staging: vec![0; frame_samples * channels],
            staged: 0,
            packet: vec![0; MAX_PACKET_BYTES],
            input_samples: 0,
            frames_encoded: 0,
            head: opus_head(config.channels, pre_skip, config.sample_rate_hz),
            tags: opus_tags(config.vendor),
            finished: false,
        })
    }

    /// The pre-skip declared in `OpusHead`, in 48 kHz samples.
    #[must_use]
    pub fn pre_skip(&self) -> u64 {
        self.lookahead * self.granule_step
    }

    /// Append the two header pages to `out`: `OpusHead` alone on the beginning-of-stream page, then
    /// `OpusTags` finishing the second page (RFC 7845 §3). Both carry granule position zero (§4).
    pub fn write_headers(&mut self, out: &mut Vec<u8>) -> Result<(), OggOpusError> {
        self.pages.add_packet(&self.head, 0, out)?;
        self.pages.flush(false, out);
        self.pages.add_packet(&self.tags, 0, out)?;
        self.pages.flush(false, out);
        Ok(())
    }

    /// Encode interleaved PCM, appending any page it completes to `out`. Samples that do not fill a
    /// frame wait for the next call.
    pub fn push(&mut self, mut pcm: &[i16], out: &mut Vec<u8>) -> Result<(), OggOpusError> {
        if self.finished {
            return Err(OggOpusError::Finished);
        }
        self.input_samples += pcm.len() as u64;
        while !pcm.is_empty() {
            let take = (self.staging.len() - self.staged).min(pcm.len());
            self.staging[self.staged..self.staged + take].copy_from_slice(&pcm[..take]);
            self.staged += take;
            pcm = &pcm[take..];
            if self.staged == self.staging.len() {
                self.encode_staged(None, out)?;
            }
        }
        Ok(())
    }

    /// End the stream: pad with silence until the encoder has emitted every input sample past its
    /// lookahead, and write the last page with end-of-stream set and a granule position that trims
    /// the padding (RFC 7845 §4.4), so the decoded length is exactly the audio pushed.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), OggOpusError> {
        if self.finished {
            return Err(OggOpusError::Finished);
        }
        self.finished = true;
        let audio = self.input_samples / self.channels as u64;
        // The encoder's output lags its input by `lookahead`, so the last input sample comes out
        // `lookahead` samples after it went in. Encode until that sample is inside a packet.
        let needed = audio + self.lookahead;
        let final_granule = self.pre_skip() + audio * self.granule_step;
        loop {
            self.staging[self.staged..].fill(0);
            self.staged = self.staging.len();
            let last = (self.frames_encoded + 1) * self.frame_samples as u64 >= needed;
            self.encode_staged(last.then_some(final_granule), out)?;
            if last {
                break;
            }
        }
        self.pages.flush(true, out);
        Ok(())
    }

    /// Encode the full staging frame into one packet and add it to the open page, closing the page
    /// first when it already holds a second of audio. `granule` overrides the packet's natural
    /// granule position, which only the end-trimmed final packet needs.
    fn encode_staged(
        &mut self,
        granule: Option<u64>,
        out: &mut Vec<u8>,
    ) -> Result<(), OggOpusError> {
        let result = self
            .encoder
            .encode(&self.staging, self.frame_samples, &mut self.packet)?;
        self.staged = 0;
        self.frames_encoded += 1;
        // RFC 7845 §4: the granule of a packet counts every sample decoded up to its end, pre-skip
        // included — the decoder returns exactly 960 per 20 ms packet from the very first one.
        let natural = self.frames_encoded * self.frame_samples as u64 * self.granule_step;
        if self.pages.packets_pending() >= PACKETS_PER_PAGE {
            self.pages.flush(false, out);
        }
        self.pages.add_packet(
            &self.packet[..result.bytes],
            granule.unwrap_or(natural),
            out,
        )?;
        Ok(())
    }
}

/// The identification header (RFC 7845 §5.1): channel mapping family 0, output gain 0.
fn opus_head(channels: u8, pre_skip: u16, input_rate_hz: u32) -> Vec<u8> {
    let mut head = Vec::with_capacity(19);
    head.extend_from_slice(b"OpusHead");
    head.push(1); // version
    head.push(channels);
    head.extend_from_slice(&pre_skip.to_le_bytes());
    head.extend_from_slice(&input_rate_hz.to_le_bytes());
    head.extend_from_slice(&0i16.to_le_bytes()); // output gain, Q7.8 dB
    head.push(0); // mapping family 0: mono or left/right stereo, no table
    head
}

/// The comment header (RFC 7845 §5.2): the vendor string and no user comments.
fn opus_tags(vendor: &str) -> Vec<u8> {
    let mut tags = Vec::with_capacity(16 + vendor.len());
    tags.extend_from_slice(b"OpusTags");
    tags.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    tags.extend_from_slice(vendor.as_bytes());
    tags.extend_from_slice(&0u32.to_le_bytes());
    tags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ogg::{ogg_crc, PAGE_HEADER_LEN};
    use siphon_rtp_codec::opus::decoder::OpusDecoder;

    /// A parsed page: flags, granule, sequence and its packets.
    #[derive(Debug)]
    struct Page {
        flags: u8,
        granule: u64,
        sequence: u32,
        packets: Vec<Vec<u8>>,
    }

    /// Our own reader, for structure only. The checksum and decode checks that count are the
    /// independent ones in `tests/ogg_opus_independent_decoder.rs`.
    fn parse(file: &[u8]) -> Vec<Page> {
        let mut pages = Vec::new();
        let mut offset = 0;
        while offset < file.len() {
            assert_eq!(&file[offset..offset + 4], b"OggS");
            let segments = usize::from(file[offset + 26]);
            let lacing = &file[offset + PAGE_HEADER_LEN..offset + PAGE_HEADER_LEN + segments];
            let mut body = offset + PAGE_HEADER_LEN + segments;
            let start = offset;
            let mut packets = Vec::new();
            let mut current = Vec::new();
            for &value in lacing {
                current.extend_from_slice(&file[body..body + usize::from(value)]);
                body += usize::from(value);
                if value < 255 {
                    packets.push(std::mem::take(&mut current));
                }
            }
            assert!(current.is_empty(), "no packet spans a page");
            let mut zeroed = file[start..body].to_vec();
            let stored = u32::from_le_bytes([zeroed[22], zeroed[23], zeroed[24], zeroed[25]]);
            zeroed[22..26].fill(0);
            assert_eq!(ogg_crc(&zeroed), stored);
            pages.push(Page {
                flags: file[start + 5],
                granule: u64::from_le_bytes(file[start + 6..start + 14].try_into().expect("8")),
                sequence: u32::from_le_bytes(file[start + 18..start + 22].try_into().expect("4")),
                packets,
            });
            offset = body;
        }
        pages
    }

    fn config(rate: u32, channels: u8) -> OggOpusConfig<'static> {
        OggOpusConfig {
            sample_rate_hz: rate,
            channels,
            bitrate_bps: 16_000 * u32::from(channels),
            serial: 0xC0FF_EE00,
            vendor: "siphon-rtp test",
        }
    }

    fn tone(rate: u32, channels: usize, samples_per_channel: usize, hz: f32) -> Vec<i16> {
        let mut pcm = Vec::with_capacity(samples_per_channel * channels);
        for index in 0..samples_per_channel {
            let phase = 2.0 * std::f32::consts::PI * hz * index as f32 / rate as f32;
            let value = (phase.sin() * 8000.0) as i16;
            for _ in 0..channels {
                pcm.push(value);
            }
        }
        pcm
    }

    fn write(rate: u32, channels: u8, pcm: &[i16], chunk: usize) -> Vec<u8> {
        let mut writer = OggOpusWriter::new(config(rate, channels)).expect("writer");
        let mut out = Vec::new();
        writer.write_headers(&mut out).expect("headers");
        for piece in pcm.chunks(chunk) {
            writer.push(piece, &mut out).expect("push");
        }
        writer.finish(&mut out).expect("finish");
        out
    }

    #[test]
    fn the_headers_are_alone_on_their_own_pages_with_granule_zero() {
        let file = write(8_000, 1, &tone(8_000, 1, 1600, 440.0), 160);
        let pages = parse(&file);
        assert_eq!(pages[0].flags, 0x02, "beginning of stream");
        assert_eq!(pages[0].packets.len(), 1, "OpusHead alone (RFC 7845 §3)");
        assert_eq!(pages[0].granule, 0);
        let head = &pages[0].packets[0];
        assert_eq!(&head[..8], b"OpusHead");
        assert_eq!(head[8], 1, "version");
        assert_eq!(head[9], 1, "channels");
        assert_eq!(u16::from_le_bytes([head[10], head[11]]), 312, "pre-skip");
        assert_eq!(
            u32::from_le_bytes(head[12..16].try_into().expect("4")),
            8_000,
            "input rate"
        );
        assert_eq!(&head[16..19], &[0, 0, 0], "gain 0, mapping family 0");

        assert_eq!(pages[1].flags, 0);
        assert_eq!(pages[1].packets.len(), 1, "OpusTags finishes its page");
        assert_eq!(pages[1].granule, 0);
        let tags = &pages[1].packets[0];
        assert_eq!(&tags[..8], b"OpusTags");
        assert_eq!(u32::from_le_bytes(tags[8..12].try_into().expect("4")), 15);
        assert_eq!(&tags[12..27], b"siphon-rtp test");
        assert_eq!(&tags[27..], &0u32.to_le_bytes(), "no user comments");
    }

    #[test]
    fn audio_pages_hold_a_second_and_the_granule_counts_48k_samples() {
        // 2.5 s at 8 kHz: 125 frames of audio plus one for the lookahead.
        let file = write(8_000, 1, &tone(8_000, 1, 20_000, 440.0), 160);
        let pages = parse(&file);
        let audio = &pages[2..];
        assert_eq!(audio.len(), 3);
        assert_eq!(audio[0].packets.len(), PACKETS_PER_PAGE);
        assert_eq!(
            audio[0].granule,
            50 * 960,
            "pre-skip included, 960 per packet"
        );
        assert_eq!(audio[1].granule, 100 * 960);
        assert_eq!(audio[2].packets.len(), 26);
        assert_eq!(audio[2].flags, 0x04, "end of stream on the last page only");
        assert_eq!(
            audio[2].granule,
            312 + 20_000 * 6,
            "the last page trims to the audio written (RFC 7845 §4.4)"
        );
        for (index, page) in pages.iter().enumerate() {
            assert_eq!(page.sequence, index as u32, "consecutive sequence numbers");
        }
        assert!(pages[..pages.len() - 1]
            .iter()
            .all(|page| page.flags & 0x04 == 0));
    }

    #[test]
    fn the_end_trim_never_exceeds_the_last_packet() {
        // RFC 7845 §4.4: discarded samples SHOULD be no more than the last packet decodes. Every
        // length from one sample to two frames, mono and stereo, at a narrowband and a wideband
        // rate.
        for (rate, channels) in [(8_000u32, 1u8), (16_000, 2)] {
            let frame = (rate / 50) as usize;
            for length in [0, 1, frame - 1, frame, frame + 1, 2 * frame - 53, 2 * frame] {
                let pcm = tone(rate, usize::from(channels), length, 300.0);
                let file = write(rate, channels, &pcm, frame * usize::from(channels));
                let pages = parse(&file);
                let packets: usize = pages[2..].iter().map(|page| page.packets.len()).sum();
                let last = pages.last().expect("pages");
                let decoded = packets as u64 * 960;
                let step = u64::from(48_000 / rate);
                assert_eq!(
                    last.granule,
                    312 + length as u64 * step,
                    "{rate} Hz, {length}"
                );
                assert!(decoded >= last.granule, "every audio sample is in a packet");
                assert!(
                    decoded - last.granule < 960,
                    "trim within one packet: {rate}/{length}"
                );
                assert!(last.granule >= 312, "never below pre-skip (RFC 7845 §4.5)");
            }
        }
    }

    #[test]
    fn the_stream_does_not_depend_on_how_the_pcm_was_chunked() {
        // Tee frames arrive at the leg's ptime, not at 20 ms. The writer re-frames them, so 10 ms,
        // 30 ms and odd-sized pushes must all produce the same packets.
        let pcm = tone(16_000, 2, 16_000, 523.0);
        let reference = write(16_000, 2, &pcm, 640);
        for chunk in [320, 960, 1234, pcm.len()] {
            assert_eq!(write(16_000, 2, &pcm, chunk), reference, "chunk {chunk}");
        }
    }

    #[test]
    fn our_decoder_hears_the_tone_at_its_frequency() {
        // A sanity check with the in-tree decoder; the independent decoder test is the one that
        // counts. Count zero crossings over the steady part of the decoded output.
        let pcm = tone(8_000, 1, 8_000, 440.0);
        let file = write(8_000, 1, &pcm, 160);
        let pages = parse(&file);
        let mut decoder = OpusDecoder::new(48_000, 1).expect("decoder");
        let mut decoded = Vec::new();
        let mut frame = vec![0i16; 960];
        for page in &pages[2..] {
            for packet in &page.packets {
                let samples = decoder
                    .decode(Some(packet), &mut frame, 960, false)
                    .expect("decode");
                decoded.extend_from_slice(&frame[..samples]);
            }
        }
        let steady = &decoded[312 + 4_800..312 + 4_800 + 24_000];
        let crossings = steady
            .windows(2)
            .filter(|pair| (pair[0] < 0) != (pair[1] < 0))
            .count();
        // 0.5 s of 440 Hz has 440 crossings.
        assert!((430..=450).contains(&crossings), "{crossings} crossings");
    }

    #[test]
    fn refusals_touch_nothing() {
        let mut bad_rate = config(44_100, 1);
        assert!(matches!(
            OggOpusWriter::new(bad_rate),
            Err(OggOpusError::Codec(_))
        ));
        bad_rate.sample_rate_hz = 8_000;
        bad_rate.channels = 3;
        assert!(OggOpusWriter::new(bad_rate).is_err());
        let mut too_fast = config(8_000, 1);
        too_fast.bitrate_bps = 600_000;
        assert!(OggOpusWriter::new(too_fast).is_err());
        too_fast.bitrate_bps = u32::MAX;
        assert!(OggOpusWriter::new(too_fast).is_err());
    }

    #[test]
    fn a_finished_stream_takes_no_more_audio() {
        let mut writer = OggOpusWriter::new(config(8_000, 1)).expect("writer");
        let mut out = Vec::new();
        writer.write_headers(&mut out).expect("headers");
        writer.finish(&mut out).expect("finish");
        assert!(matches!(
            writer.push(&[0; 160], &mut out),
            Err(OggOpusError::Finished)
        ));
        assert!(matches!(
            writer.finish(&mut out),
            Err(OggOpusError::Finished)
        ));
        assert_eq!(
            OggOpusError::Finished.to_string(),
            "the stream has already ended"
        );
    }

    #[test]
    fn an_empty_stream_is_still_a_valid_stream() {
        // A recording started and stopped before any audio: one packet of padding, granule equal to
        // pre-skip, so it decodes to zero samples rather than being a file with no audio page.
        let file = write(8_000, 1, &[], 160);
        let pages = parse(&file);
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[2].packets.len(), 1);
        assert_eq!(pages[2].granule, 312);
        assert_eq!(pages[2].flags, 0x04);
    }

    #[test]
    fn debug_does_not_dump_the_encoder() {
        let writer = OggOpusWriter::new(config(8_000, 1)).expect("writer");
        let rendered = format!("{writer:?}");
        assert!(rendered.starts_with("OggOpusWriter"));
        assert!(rendered.contains("frame_samples: 160"));
    }
}
