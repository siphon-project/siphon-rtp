//! A pure-Rust WAV (RIFF/PCM16) reader and PCM frame player source for `PlayMedia`.
//!
//! [`WavSource`] is the inverse of [`crate::wav::WavRecorder`]: it walks a RIFF/WAVE byte buffer
//! (Microsoft WAVE / RFC 2361-registered RIFF container), validates a 16-bit linear-PCM `fmt `
//! chunk, and lifts the `data` chunk into `Vec<i16>`. Unknown chunks are skipped (chunk-walk) and
//! odd-length chunks honour the RIFF pad byte. [`PcmPlayer`] then serves the decoded audio as
//! fixed-size frames on demand (announcements, prompts, music-on-hold), with looping and seek.
//!
//! Resampling to the leg's clock is the engine's job — this source exposes its native rate so the
//! engine can resample; it deliberately does not pull in the dsp crate.

/// WAVE format tag for uncompressed linear PCM (Microsoft `WAVE_FORMAT_PCM`).
const WAVE_FORMAT_PCM: u16 = 1;
/// WAVE format tag for ITU-T G.711 A-law (`WAVE_FORMAT_ALAW`). Telephony prompts exported from
/// another system arrive in this and in µ-law far more often than in 16-bit linear PCM.
const WAVE_FORMAT_ALAW: u16 = 6;
/// WAVE format tag for ITU-T G.711 µ-law (`WAVE_FORMAT_MULAW`).
const WAVE_FORMAT_MULAW: u16 = 7;
/// WAVE format tag for the extensible container (`WAVE_FORMAT_EXTENSIBLE`). Its real format is the
/// first two bytes of the `SubFormat` GUID in the `fmt ` chunk's extension — most modern encoders
/// emit this even for ordinary 16-bit mono PCM, so refusing it refused files that are byte-for-byte
/// playable.
const WAVE_FORMAT_EXTENSIBLE: u16 = 0xFFFE;
/// Bits per sample for the linear-PCM form (matching [`crate::wav::WavRecorder`]).
const SUPPORTED_BITS_PER_SAMPLE: u16 = 16;
/// Bits per sample for the G.711 forms: one byte per sample, decoded to 16-bit linear on load.
const G711_BITS_PER_SAMPLE: u16 = 8;
/// Byte offset of the `SubFormat` GUID inside the `fmt ` chunk's extension block, measured from the
/// start of the chunk body: 16 bytes of `WAVEFORMATEX`, 2 of `cbSize`, 2 of samples-per-block, 4 of
/// the channel mask.
const SUBFORMAT_GUID_OFFSET: usize = 24;
/// Size of a RIFF/WAVE chunk header: 4-byte FourCC + 4-byte little-endian length.
const CHUNK_HEADER_LEN: usize = 8;

/// Errors from parsing a WAV byte buffer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WavError {
    /// The buffer is shorter than the structure it claims to contain.
    #[error("WAV buffer truncated")]
    Truncated,
    /// The `RIFF` magic or `WAVE` form type was missing.
    #[error("not a RIFF/WAVE file")]
    NotRiffWave,
    /// No `fmt ` chunk was found before the data.
    #[error("missing fmt chunk")]
    MissingFmt,
    /// No `data` chunk was present.
    #[error("missing data chunk")]
    MissingData,
    /// The `fmt ` chunk declared a format tag this reader cannot decode.
    #[error("unsupported WAV format tag {0} (linear PCM = 1, A-law = 6, mu-law = 7, extensible = 65534)")]
    NotPcm(u16),
    /// The `fmt ` chunk declared a sample width the format does not use.
    #[error("unsupported bits-per-sample {0} for WAV format tag {1}")]
    BadBitsPerSample(u16, u16),
    /// The `fmt ` chunk declared zero channels.
    #[error("invalid channel count {0}")]
    BadChannels(u16),
}

/// Decoded 16-bit linear PCM lifted from a RIFF/WAVE buffer.
///
/// Samples are interleaved across `channels` at `sample_rate_hz`. This is the source the engine
/// resamples to a leg's clock before handing frames to [`crate::leg::MediaLeg::encode_rtp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WavSource {
    sample_rate_hz: u32,
    channels: u16,
    /// Interleaved 16-bit PCM samples (length = `frames * channels`).
    samples: Vec<i16>,
}

impl WavSource {
    /// Parse a complete RIFF/WAVE (PCM16 LE) byte buffer.
    ///
    /// Validates the `RIFF`/`WAVE` envelope and a linear-PCM 16-bit `fmt ` chunk, then reads the
    /// `data` chunk. Unrecognised chunks (`LIST`, `fact`, `cue `, …) are skipped, and an odd-sized
    /// chunk's trailing RIFF pad byte is consumed. Never panics on a malformed buffer — every
    /// length is bounds-checked.
    pub fn parse(buffer: &[u8]) -> Result<Self, WavError> {
        // RIFF header: "RIFF" <u32 size> "WAVE" (12 bytes). RFC 2361 / Microsoft WAVE.
        if buffer.len() < 12 {
            return Err(WavError::Truncated);
        }
        if &buffer[0..4] != b"RIFF" || &buffer[8..12] != b"WAVE" {
            return Err(WavError::NotRiffWave);
        }

        let mut offset = 12;
        let mut format: Option<(u16, u32, u16)> = None; // (channels, sample_rate, format_tag)
        let mut data: Option<Vec<u8>> = None;

        // Chunk-walk: each sub-chunk is "<FourCC><u32 length><payload>", payload padded to even.
        while offset + CHUNK_HEADER_LEN <= buffer.len() {
            let chunk_id = &buffer[offset..offset + 4];
            let chunk_len = read_u32_le(buffer, offset + 4) as usize;
            let body_start = offset + CHUNK_HEADER_LEN;
            // A chunk that claims more bytes than remain is a truncation.
            if body_start + chunk_len > buffer.len() {
                return Err(WavError::Truncated);
            }
            let body = &buffer[body_start..body_start + chunk_len];

            if chunk_id == b"fmt " {
                // fmt : u16 format, u16 channels, u32 rate, u32 byte_rate, u16 block_align, u16 bits.
                if body.len() < 16 {
                    return Err(WavError::Truncated);
                }
                let declared_tag = read_u16_le(body, 0);
                // `WAVE_FORMAT_EXTENSIBLE` is a container: the real format is the first two bytes of
                // the `SubFormat` GUID in the extension. Resolving it here is what lets an ordinary
                // 16-bit mono file written by a modern encoder load at all.
                let format_tag = if declared_tag == WAVE_FORMAT_EXTENSIBLE {
                    if body.len() < SUBFORMAT_GUID_OFFSET + 2 {
                        return Err(WavError::Truncated);
                    }
                    read_u16_le(body, SUBFORMAT_GUID_OFFSET)
                } else {
                    declared_tag
                };
                let channels = read_u16_le(body, 2);
                if channels == 0 {
                    return Err(WavError::BadChannels(channels));
                }
                let sample_rate = read_u32_le(body, 4);
                let bits_per_sample = read_u16_le(body, 14);
                let expected_bits = match format_tag {
                    WAVE_FORMAT_PCM => SUPPORTED_BITS_PER_SAMPLE,
                    WAVE_FORMAT_ALAW | WAVE_FORMAT_MULAW => G711_BITS_PER_SAMPLE,
                    other => return Err(WavError::NotPcm(other)),
                };
                if bits_per_sample != expected_bits {
                    return Err(WavError::BadBitsPerSample(bits_per_sample, format_tag));
                }
                format = Some((channels, sample_rate, format_tag));
            } else if chunk_id == b"data" {
                // Held undecoded until the `fmt ` chunk is known: RIFF does not require `fmt ` to come
                // first, and the sample width decides how to read these bytes.
                data = Some(body.to_vec());
            }
            // Skip the chunk body plus its pad byte if the length is odd (RIFF alignment rule).
            offset = body_start + chunk_len + (chunk_len & 1);
        }

        let (channels, sample_rate, format_tag) = format.ok_or(WavError::MissingFmt)?;
        let data = data.ok_or(WavError::MissingData)?;
        let samples = match format_tag {
            WAVE_FORMAT_PCM => {
                // Truncate a stray trailing odd byte: 16-bit PCM is always sample-aligned.
                let aligned = data.len() & !1;
                data[..aligned]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| i16::from_le_bytes(*pair))
                    .collect()
            }
            // One byte per sample, decoded through the same tables the G.711 codec uses, so a prompt
            // loaded from a µ-law file is bit-identical to the same audio arriving on the wire.
            WAVE_FORMAT_MULAW => data
                .iter()
                .map(|&byte| siphon_rtp_codec::g711::ULAW_DECODE[usize::from(byte)])
                .collect(),
            WAVE_FORMAT_ALAW => data
                .iter()
                .map(|&byte| siphon_rtp_codec::g711::ALAW_DECODE[usize::from(byte)])
                .collect(),
            other => return Err(WavError::NotPcm(other)),
        };
        Ok(Self {
            sample_rate_hz: sample_rate,
            channels,
            samples,
        })
    }

    /// Native sample rate in Hz (the engine resamples from this to the leg's clock).
    #[must_use]
    pub fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }

    /// Channel count in the source (1 = mono, 2 = stereo, …).
    #[must_use]
    pub fn channels(&self) -> u16 {
        self.channels
    }

    /// The interleaved PCM samples (length = `frame_count * channels`).
    #[must_use]
    pub fn samples(&self) -> &[i16] {
        &self.samples
    }

    /// Number of per-channel sample frames in the source.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.samples.len() / self.channels.max(1) as usize
    }

    /// Downmix to mono by averaging the interleaved channels per frame, into a shared buffer.
    ///
    /// Separate from [`PcmPlayer::new`] so a prompt cache can do the work **once** and hand the same
    /// `Arc` to every player that follows.
    #[must_use]
    pub fn to_mono(&self) -> std::sync::Arc<[i16]> {
        let channels = self.channels.max(1) as usize;
        if channels == 1 {
            return self.samples.as_slice().into();
        }
        let frame_count = self.samples.len() / channels;
        let mut mono = Vec::with_capacity(frame_count);
        for frame in self.samples.chunks_exact(channels) {
            let sum: i32 = frame.iter().map(|&sample| i32::from(sample)).sum();
            mono.push((sum / channels as i32) as i16);
        }
        mono.into()
    }
}

/// Read a little-endian `u32` at `offset` (callers guarantee 4 bytes are present).
#[inline]
fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Read a little-endian `u16` at `offset` (callers guarantee 2 bytes are present).
#[inline]
fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

/// Serves decoded PCM as fixed-size mono frames on demand, with looping and seek.
///
/// The player downmixes multi-channel sources to mono (channel average) and yields one frame per
/// [`PcmPlayer::next_frame`] call into a caller-owned buffer — no per-frame heap allocation. Output
/// is at the source's native rate; the engine resamples to the leg before encoding.
#[derive(Debug, Clone)]
pub struct PcmPlayer {
    /// Downmixed mono samples at the source rate.
    ///
    /// Shared rather than owned: a prompt played to thirty queued callers is one decode and one
    /// buffer, read by thirty players at their own offsets. Nothing here ever mutates it — the cursor
    /// state (`position`, `plays_done`, `loop_start`) is entirely separate — which is exactly what
    /// makes sharing safe, and it also makes `Clone` O(1).
    mono: std::sync::Arc<[i16]>,
    sample_rate_hz: u32,
    /// Read cursor into `mono` (per-channel sample index).
    position: usize,
    /// How many times the body has been played so far.
    plays_done: u32,
    /// Total plays to perform; 0 or 1 means play once.
    repeat_times: u32,
    /// The first sample index a fresh loop rewinds to (the seek point persists across loops).
    loop_start: usize,
}

impl PcmPlayer {
    /// Build a player over a parsed [`WavSource`], downmixing to mono. `repeat_times` is the total
    /// number of plays (`0` or `1` = play once); `start_pos_ms` seeks into the body before the
    /// first frame (and is where each loop rewinds to). A seek past the end yields no frames.
    #[must_use]
    pub fn new(source: &WavSource, repeat_times: u32, start_pos_ms: u32) -> Self {
        Self::from_shared(
            source.to_mono(),
            source.sample_rate_hz(),
            repeat_times,
            start_pos_ms,
        )
    }

    /// Build a player over an **already downmixed** mono buffer — what a prompt cache hands out.
    ///
    /// This is the whole point of the shared buffer: the file read, the RIFF parse and the downmix
    /// happen once per distinct prompt, and every player after that is a cursor over the same
    /// samples. Thirty callers on one hold bed is one buffer, not thirty.
    #[must_use]
    pub fn from_shared(
        mono: std::sync::Arc<[i16]>,
        sample_rate_hz: u32,
        repeat_times: u32,
        start_pos_ms: u32,
    ) -> Self {
        let loop_start = ((start_pos_ms as u64 * sample_rate_hz as u64) / 1000) as usize;
        let loop_start = loop_start.min(mono.len());

        Self {
            mono,
            sample_rate_hz,
            position: loop_start,
            plays_done: 0,
            repeat_times,
            loop_start,
        }
    }

    /// Native sample rate of the produced frames (the engine resamples from this).
    #[must_use]
    pub fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }

    /// Total mono samples available in one pass of the body.
    #[must_use]
    pub fn mono_len(&self) -> usize {
        self.mono.len()
    }

    /// Total plays this player will perform (`0`/`1` both mean once).
    #[must_use]
    fn total_plays(&self) -> u32 {
        self.repeat_times.max(1)
    }

    /// Total playout duration in milliseconds for the whole prompt, measured from the current
    /// position — what a blocking `play_media` reports as `duration_ms` when it drains. Each pass
    /// rewinds to the seek point (`loop_start`), so the remaining time is the tail of the current
    /// pass plus every full pass still to come. Zero for an empty body or an unknown rate.
    #[must_use]
    pub fn duration_ms(&self) -> u64 {
        if self.mono.is_empty() || self.sample_rate_hz == 0 {
            return 0;
        }
        let total_plays = u64::from(self.total_plays());
        let played = u64::from(self.plays_done).min(total_plays);
        let tail_of_pass = self.mono.len().saturating_sub(self.position) as u64;
        let full_passes_left = total_plays.saturating_sub(played + 1);
        let per_pass = self.mono.len().saturating_sub(self.loop_start) as u64;
        let samples = tail_of_pass + full_passes_left * per_pass;
        samples * 1000 / u64::from(self.sample_rate_hz)
    }

    /// Whether the player has produced its last frame and will only yield `None` from now on.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.mono.is_empty()
            || (self.plays_done >= self.total_plays())
            || (self.plays_done + 1 >= self.total_plays() && self.position >= self.mono.len())
    }

    /// Pull the next mono frame into `out`, returning the number of samples written, or `None` when
    /// exhausted. A short final frame is zero-padded to `out.len()` and the produced count reflects
    /// only the real samples. Loops up to `repeat_times`, rewinding to the seek point each pass.
    pub fn next_frame(&mut self, out: &mut [i16]) -> Option<usize> {
        if out.is_empty() {
            return None;
        }
        let total_plays = self.total_plays();
        loop {
            if self.plays_done >= total_plays {
                return None;
            }
            if self.position < self.mono.len() {
                let remaining = self.mono.len() - self.position;
                let take = remaining.min(out.len());
                out[..take].copy_from_slice(&self.mono[self.position..self.position + take]);
                // Zero-pad a short final frame so the caller always gets a full buffer.
                out[take..].fill(0);
                self.position += take;
                return Some(take);
            }
            // Reached the end of this pass — start the next loop, or finish.
            self.plays_done += 1;
            if self.plays_done >= total_plays {
                return None;
            }
            self.position = self.loop_start;
            // An empty body (or a loop_start at the very end) can never advance — bail to avoid
            // spinning forever.
            if self.position >= self.mono.len() {
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fanout::MediaSink;
    use crate::wav::WavRecorder;

    fn read_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    /// Build a RIFF/WAVE buffer directly from explicit byte fixtures (so the reader is not tested
    /// only against the writer). 8 kHz mono, samples [-1, 0, 1].
    fn mono_wav_fixture() -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"RIFF");
        buffer.extend_from_slice(&(36u32 + 6).to_le_bytes());
        buffer.extend_from_slice(b"WAVE");
        buffer.extend_from_slice(b"fmt ");
        buffer.extend_from_slice(&16u32.to_le_bytes());
        buffer.extend_from_slice(&1u16.to_le_bytes()); // PCM
        buffer.extend_from_slice(&1u16.to_le_bytes()); // mono
        buffer.extend_from_slice(&8000u32.to_le_bytes());
        buffer.extend_from_slice(&16000u32.to_le_bytes()); // byte rate
        buffer.extend_from_slice(&2u16.to_le_bytes()); // block align
        buffer.extend_from_slice(&16u16.to_le_bytes()); // bits
        buffer.extend_from_slice(b"data");
        buffer.extend_from_slice(&6u32.to_le_bytes());
        buffer.extend_from_slice(&(-1i16).to_le_bytes());
        buffer.extend_from_slice(&0i16.to_le_bytes());
        buffer.extend_from_slice(&1i16.to_le_bytes());
        buffer
    }

    #[test]
    fn parses_explicit_mono_fixture() {
        let source = WavSource::parse(&mono_wav_fixture()).expect("parse");
        assert_eq!(source.sample_rate_hz(), 8000);
        assert_eq!(source.channels(), 1);
        assert_eq!(source.samples(), &[-1, 0, 1]);
        assert_eq!(source.frame_count(), 3);
    }

    #[test]
    fn roundtrips_recorder_output_sample_exact() {
        // WavRecorder::into_wav → WavSource::parse must be sample-exact.
        let mut recorder = WavRecorder::new(16000, 1);
        let pcm: Vec<i16> = (0..320)
            .map(|index| ((index * 101) as i16).wrapping_sub(160))
            .collect();
        recorder.write_pcm(&pcm);
        let wav = recorder.into_wav();

        let source = WavSource::parse(&wav).expect("parse");
        assert_eq!(source.sample_rate_hz(), 16000);
        assert_eq!(source.channels(), 1);
        assert_eq!(source.samples(), pcm.as_slice());
    }

    #[test]
    fn roundtrips_stereo_recorder_output() {
        let mut recorder = WavRecorder::new(8000, 2);
        // Interleaved L/R.
        recorder.write_pcm(&[100, -100, 200, -200, 300, -300]);
        let wav = recorder.into_wav();
        let source = WavSource::parse(&wav).expect("parse");
        assert_eq!(source.channels(), 2);
        assert_eq!(source.samples(), &[100, -100, 200, -200, 300, -300]);
        assert_eq!(source.frame_count(), 3);
    }

    #[test]
    fn skips_unknown_chunks_and_pad_bytes() {
        // RIFF "LIST" of odd length 3 (1 pad byte) before fmt , then a "fact" chunk after fmt .
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"RIFF");
        // size placeholder; not validated by the reader beyond envelope.
        buffer.extend_from_slice(&0u32.to_le_bytes());
        buffer.extend_from_slice(b"WAVE");
        // Unknown odd-length chunk: "LIST" len=3 + 1 pad byte.
        buffer.extend_from_slice(b"LIST");
        buffer.extend_from_slice(&3u32.to_le_bytes());
        buffer.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        buffer.push(0x00); // pad byte for odd length
                           // fmt
        buffer.extend_from_slice(b"fmt ");
        buffer.extend_from_slice(&16u32.to_le_bytes());
        buffer.extend_from_slice(&1u16.to_le_bytes());
        buffer.extend_from_slice(&1u16.to_le_bytes());
        buffer.extend_from_slice(&8000u32.to_le_bytes());
        buffer.extend_from_slice(&16000u32.to_le_bytes());
        buffer.extend_from_slice(&2u16.to_le_bytes());
        buffer.extend_from_slice(&16u16.to_le_bytes());
        // Unknown "fact" chunk between fmt and data.
        buffer.extend_from_slice(b"fact");
        buffer.extend_from_slice(&4u32.to_le_bytes());
        buffer.extend_from_slice(&42u32.to_le_bytes());
        // data: two samples.
        buffer.extend_from_slice(b"data");
        buffer.extend_from_slice(&4u32.to_le_bytes());
        buffer.extend_from_slice(&7i16.to_le_bytes());
        buffer.extend_from_slice(&(-7i16).to_le_bytes());

        let source = WavSource::parse(&buffer).expect("parse");
        assert_eq!(source.samples(), &[7, -7]);
    }

    #[test]
    fn rejects_garbage_header() {
        assert_eq!(
            WavSource::parse(b"not a wav file at all"),
            Err(WavError::NotRiffWave)
        );
    }

    #[test]
    fn rejects_truncated_buffer() {
        assert_eq!(WavSource::parse(&[0u8; 4]), Err(WavError::Truncated));
        // RIFF/WAVE envelope but a data chunk that claims more than is present.
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"RIFF");
        buffer.extend_from_slice(&0u32.to_le_bytes());
        buffer.extend_from_slice(b"WAVE");
        buffer.extend_from_slice(b"data");
        buffer.extend_from_slice(&100u32.to_le_bytes()); // claims 100 bytes
        buffer.extend_from_slice(&[0x00, 0x01]); // only 2 present
        assert_eq!(WavSource::parse(&buffer), Err(WavError::Truncated));
    }

    #[test]
    fn rejects_a_format_it_cannot_decode() {
        // IEEE float (tag 3) is a real WAVE format this reader does not implement, and must be a
        // typed error rather than garbage samples.
        let buffer = wav_bytes(3, 32, 1, 8000, &[0u8; 8]);
        assert_eq!(WavSource::parse(&buffer), Err(WavError::NotPcm(3)));
    }

    /// Assemble a minimal RIFF/WAVE file around a `fmt ` chunk and a `data` payload.
    fn wav_bytes(
        format_tag: u16,
        bits_per_sample: u16,
        channels: u16,
        sample_rate: u32,
        data: &[u8],
    ) -> Vec<u8> {
        let block_align = channels * bits_per_sample / 8;
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"RIFF");
        buffer.extend_from_slice(&0u32.to_le_bytes());
        buffer.extend_from_slice(b"WAVE");
        buffer.extend_from_slice(b"fmt ");
        buffer.extend_from_slice(&16u32.to_le_bytes());
        buffer.extend_from_slice(&format_tag.to_le_bytes());
        buffer.extend_from_slice(&channels.to_le_bytes());
        buffer.extend_from_slice(&sample_rate.to_le_bytes());
        buffer.extend_from_slice(&(sample_rate * u32::from(block_align)).to_le_bytes());
        buffer.extend_from_slice(&block_align.to_le_bytes());
        buffer.extend_from_slice(&bits_per_sample.to_le_bytes());
        buffer.extend_from_slice(b"data");
        buffer.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buffer.extend_from_slice(data);
        if data.len() % 2 == 1 {
            buffer.push(0);
        }
        buffer
    }

    #[test]
    fn reads_a_mu_law_prompt_through_the_same_tables_the_codec_uses() {
        // Telephony prompts exported from another system are far more often G.711 than 16-bit linear
        // PCM, and refusing them refused files the engine can trivially decode. Decoding through the
        // codec's own tables is what makes a prompt loaded from a file bit-identical to the same
        // audio arriving on the wire.
        let payload: Vec<u8> = vec![0x00, 0x7F, 0x80, 0xFF, 0x20];
        let parsed = WavSource::parse(&wav_bytes(7, 8, 1, 8000, &payload)).expect("mu-law parses");
        assert_eq!(parsed.sample_rate_hz(), 8000);
        assert_eq!(parsed.channels(), 1);
        let expected: Vec<i16> = payload
            .iter()
            .map(|&byte| siphon_rtp_codec::g711::ULAW_DECODE[usize::from(byte)])
            .collect();
        assert_eq!(parsed.samples(), expected.as_slice());
    }

    #[test]
    fn reads_an_a_law_prompt() {
        let payload: Vec<u8> = vec![0x55, 0xD5, 0x00, 0xAA];
        let parsed = WavSource::parse(&wav_bytes(6, 8, 1, 8000, &payload)).expect("A-law parses");
        let expected: Vec<i16> = payload
            .iter()
            .map(|&byte| siphon_rtp_codec::g711::ALAW_DECODE[usize::from(byte)])
            .collect();
        assert_eq!(parsed.samples(), expected.as_slice());
    }

    #[test]
    fn a_g711_prompt_with_the_wrong_sample_width_is_refused() {
        // 16 bits per sample on a G.711 tag is a malformed header, not a linear file: reading it as
        // one byte per sample would halve the pitch and double the length.
        assert_eq!(
            WavSource::parse(&wav_bytes(7, 16, 1, 8000, &[0u8; 8])),
            Err(WavError::BadBitsPerSample(16, 7))
        );
    }

    #[test]
    fn resolves_an_extensible_header_to_its_real_subformat() {
        // `WAVE_FORMAT_EXTENSIBLE` is what most modern encoders emit even for ordinary 16-bit mono
        // PCM, so refusing the tag refused files that are byte-for-byte playable. The real format is
        // the first two bytes of the SubFormat GUID.
        let samples: Vec<i16> = vec![100, -200, 300];
        let mut data = Vec::new();
        for sample in &samples {
            data.extend_from_slice(&sample.to_le_bytes());
        }
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"RIFF");
        buffer.extend_from_slice(&0u32.to_le_bytes());
        buffer.extend_from_slice(b"WAVE");
        buffer.extend_from_slice(b"fmt ");
        buffer.extend_from_slice(&40u32.to_le_bytes()); // extensible fmt chunk
        buffer.extend_from_slice(&0xFFFEu16.to_le_bytes());
        buffer.extend_from_slice(&1u16.to_le_bytes()); // mono
        buffer.extend_from_slice(&8000u32.to_le_bytes());
        buffer.extend_from_slice(&16000u32.to_le_bytes());
        buffer.extend_from_slice(&2u16.to_le_bytes());
        buffer.extend_from_slice(&16u16.to_le_bytes());
        buffer.extend_from_slice(&22u16.to_le_bytes()); // cbSize
        buffer.extend_from_slice(&16u16.to_le_bytes()); // valid bits
        buffer.extend_from_slice(&4u32.to_le_bytes()); // channel mask
                                                       // SubFormat GUID: KSDATAFORMAT_SUBTYPE_PCM begins with the little-endian tag 0x0001.
        buffer.extend_from_slice(&1u16.to_le_bytes());
        buffer.extend_from_slice(&[0u8; 14]);
        buffer.extend_from_slice(b"data");
        buffer.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&data);

        let parsed = WavSource::parse(&buffer).expect("an extensible PCM header parses");
        assert_eq!(parsed.samples(), samples.as_slice());
        assert_eq!(parsed.sample_rate_hz(), 8000);
    }

    #[test]
    fn a_fmt_chunk_after_the_data_chunk_still_decodes() {
        // RIFF does not require `fmt ` to come first, and the sample width decides how to read the
        // data — so the reader must hold the payload undecoded until it knows the format. Before the
        // G.711 support this happened to work because there was only one width.
        let payload: Vec<u8> = vec![0x10, 0x20, 0x30];
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"RIFF");
        buffer.extend_from_slice(&0u32.to_le_bytes());
        buffer.extend_from_slice(b"WAVE");
        buffer.extend_from_slice(b"data");
        buffer.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&payload);
        buffer.push(0); // RIFF pad for the odd length
        buffer.extend_from_slice(b"fmt ");
        buffer.extend_from_slice(&16u32.to_le_bytes());
        buffer.extend_from_slice(&7u16.to_le_bytes()); // mu-law
        buffer.extend_from_slice(&1u16.to_le_bytes());
        buffer.extend_from_slice(&8000u32.to_le_bytes());
        buffer.extend_from_slice(&8000u32.to_le_bytes());
        buffer.extend_from_slice(&1u16.to_le_bytes());
        buffer.extend_from_slice(&8u16.to_le_bytes());

        let parsed = WavSource::parse(&buffer).expect("fmt after data parses");
        assert_eq!(parsed.samples().len(), 3, "one sample per mu-law byte");
    }

    #[test]
    fn players_over_one_cached_prompt_share_its_samples_and_keep_their_own_cursors() {
        // The whole point of the shared buffer: a hold bed playing to many callers is one decode and
        // one allocation, with each caller at its own offset. Nothing mutates the samples, which is
        // what makes that safe.
        let source = five_sample_source();
        let shared = source.to_mono();
        assert_eq!(std::sync::Arc::strong_count(&shared), 1);

        let mut first = PcmPlayer::from_shared(shared.clone(), 8000, 1, 0);
        let mut second = PcmPlayer::from_shared(shared.clone(), 8000, 1, 0);
        assert_eq!(
            std::sync::Arc::strong_count(&shared),
            3,
            "both players read the same buffer rather than copying it"
        );

        let mut out = [0i16; 2];
        assert_eq!(first.next_frame(&mut out), Some(2));
        let first_head = out;
        // The second player is untouched by the first's progress.
        let mut second_out = [0i16; 2];
        assert_eq!(second.next_frame(&mut second_out), Some(2));
        assert_eq!(
            second_out, first_head,
            "the second player starts at its own beginning"
        );
        assert_eq!(first.next_frame(&mut out), Some(2));
        assert_ne!(out, first_head, "and the first has moved on independently");
    }

    #[test]
    fn a_mono_source_shares_its_samples_without_a_downmix_copy() {
        // The common case — a mono prompt — must not pay for a downmix pass that would produce the
        // identical buffer.
        let source = five_sample_source();
        let mono = source.to_mono();
        assert_eq!(&*mono, source.samples());
    }

    #[test]
    fn rejects_non_16bit() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"RIFF");
        buffer.extend_from_slice(&0u32.to_le_bytes());
        buffer.extend_from_slice(b"WAVE");
        buffer.extend_from_slice(b"fmt ");
        buffer.extend_from_slice(&16u32.to_le_bytes());
        buffer.extend_from_slice(&1u16.to_le_bytes()); // PCM
        buffer.extend_from_slice(&1u16.to_le_bytes());
        buffer.extend_from_slice(&8000u32.to_le_bytes());
        buffer.extend_from_slice(&32000u32.to_le_bytes());
        buffer.extend_from_slice(&4u16.to_le_bytes());
        buffer.extend_from_slice(&32u16.to_le_bytes()); // 32-bit
        buffer.extend_from_slice(b"data");
        buffer.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            WavSource::parse(&buffer),
            Err(WavError::BadBitsPerSample(32, WAVE_FORMAT_PCM))
        );
    }

    #[test]
    fn missing_fmt_or_data_is_an_error() {
        // RIFF/WAVE with only a data chunk → missing fmt.
        let mut only_data = Vec::new();
        only_data.extend_from_slice(b"RIFF");
        only_data.extend_from_slice(&0u32.to_le_bytes());
        only_data.extend_from_slice(b"WAVE");
        only_data.extend_from_slice(b"data");
        only_data.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(WavSource::parse(&only_data), Err(WavError::MissingFmt));
    }

    /// A player over a known 5-sample mono body for frame-pull assertions.
    fn five_sample_source() -> WavSource {
        let mut recorder = WavRecorder::new(8000, 1);
        recorder.write_pcm(&[10, 20, 30, 40, 50]);
        WavSource::parse(&recorder.into_wav()).expect("parse")
    }

    #[test]
    fn pulls_frames_then_exhausts() {
        let source = five_sample_source();
        let mut player = PcmPlayer::new(&source, 1, 0);
        let mut out = [0i16; 2];
        assert_eq!(player.next_frame(&mut out), Some(2));
        assert_eq!(out, [10, 20]);
        assert_eq!(player.next_frame(&mut out), Some(2));
        assert_eq!(out, [30, 40]);
        // Short final frame: 1 real sample, zero-padded.
        assert_eq!(player.next_frame(&mut out), Some(1));
        assert_eq!(out, [50, 0]);
        // Exhausted.
        assert!(player.is_exhausted());
        assert_eq!(player.next_frame(&mut out), None);
    }

    #[test]
    fn repeats_the_body_n_times() {
        let source = five_sample_source();
        // Play twice, frame size 5 so each pass is one frame.
        let mut player = PcmPlayer::new(&source, 2, 0);
        let mut out = [0i16; 5];
        assert_eq!(player.next_frame(&mut out), Some(5));
        assert_eq!(out, [10, 20, 30, 40, 50]);
        // Second pass.
        assert_eq!(player.next_frame(&mut out), Some(5));
        assert_eq!(out, [10, 20, 30, 40, 50]);
        // Done after two plays.
        assert_eq!(player.next_frame(&mut out), None);
    }

    #[test]
    fn repeat_zero_plays_once() {
        let source = five_sample_source();
        let mut player = PcmPlayer::new(&source, 0, 0);
        let mut out = [0i16; 5];
        assert_eq!(player.next_frame(&mut out), Some(5));
        assert_eq!(player.next_frame(&mut out), None);
    }

    #[test]
    fn seek_skips_leading_samples() {
        // start_pos_ms maps to floor(ms * rate / 1000) samples. Body of 12000 samples @ 8 kHz, each
        // sample value equal to its index, so the value at a seek point identifies the position.
        let mut recorder = WavRecorder::new(8000, 1);
        let body: Vec<i16> = (0..12000).map(|index| index as i16).collect(); // 1.5 s @ 8 kHz
        recorder.write_pcm(&body);
        let source = WavSource::parse(&recorder.into_wav()).expect("parse");
        // Seek 1000 ms → 8000 samples in; the value at index 8000 is (8000 as i16).
        let mut player = PcmPlayer::new(&source, 1, 1000);
        let mut out = [0i16; 1];
        assert_eq!(player.next_frame(&mut out), Some(1));
        assert_eq!(out[0], body[8000]);
    }

    #[test]
    fn seek_past_end_yields_nothing() {
        let source = five_sample_source();
        // Seek far past the 5-sample body.
        let mut player = PcmPlayer::new(&source, 1, 10_000);
        let mut out = [0i16; 4];
        assert_eq!(player.next_frame(&mut out), None);
        assert!(player.is_exhausted());
    }

    #[test]
    fn loop_rewinds_to_seek_point() {
        let mut recorder = WavRecorder::new(1000, 1); // 1 kHz → 1 ms = 1 sample
        recorder.write_pcm(&[1, 2, 3, 4]);
        let source = WavSource::parse(&recorder.into_wav()).expect("parse");
        // Seek 2 ms (→ sample index 2), play twice. Each pass yields [3, 4].
        let mut player = PcmPlayer::new(&source, 2, 2);
        let mut out = [0i16; 2];
        assert_eq!(player.next_frame(&mut out), Some(2));
        assert_eq!(out, [3, 4]);
        assert_eq!(player.next_frame(&mut out), Some(2));
        assert_eq!(out, [3, 4]); // loop rewound to the seek point, not to 0
        assert_eq!(player.next_frame(&mut out), None);
    }

    #[test]
    fn duration_ms_covers_seek_and_repeat() {
        // 8000 samples @ 8 kHz = exactly 1000 ms for one pass.
        let mut recorder = WavRecorder::new(8000, 1);
        recorder.write_pcm(&vec![0i16; 8000]);
        let source = WavSource::parse(&recorder.into_wav()).expect("parse");

        // One pass = 1000 ms.
        assert_eq!(PcmPlayer::new(&source, 1, 0).duration_ms(), 1000);
        // Three passes = 3000 ms.
        assert_eq!(PcmPlayer::new(&source, 3, 0).duration_ms(), 3000);
        // Seek 250 ms in → 750 ms for the pass; twice = 1500 ms (each loop rewinds to the seek).
        assert_eq!(PcmPlayer::new(&source, 2, 250).duration_ms(), 1500);

        // The estimate shrinks as frames are pulled: after consuming 2000 samples (250 ms) of a
        // single 1000 ms pass, 750 ms remain.
        let mut player = PcmPlayer::new(&source, 1, 0);
        let mut out = [0i16; 2000];
        assert_eq!(player.next_frame(&mut out), Some(2000));
        assert_eq!(player.duration_ms(), 750);

        // An empty body has no duration.
        let mut empty = WavRecorder::new(8000, 1);
        empty.write_pcm(&[]);
        let empty = WavSource::parse(&empty.into_wav()).expect("parse");
        assert_eq!(PcmPlayer::new(&empty, 4, 0).duration_ms(), 0);
    }

    #[test]
    fn downmixes_stereo_to_mono_by_averaging() {
        let mut recorder = WavRecorder::new(8000, 2);
        // L/R pairs: (10, 20) → 15, (-100, 100) → 0, (32767, -1) → 16383.
        recorder.write_pcm(&[10, 20, -100, 100, 32767, -1]);
        let source = WavSource::parse(&recorder.into_wav()).expect("parse");
        let mut player = PcmPlayer::new(&source, 1, 0);
        let mut out = [0i16; 3];
        assert_eq!(player.next_frame(&mut out), Some(3));
        assert_eq!(out, [15, 0, 16383]);
    }

    #[test]
    fn empty_body_yields_nothing() {
        let mut recorder = WavRecorder::new(8000, 1);
        recorder.write_pcm(&[]);
        let source = WavSource::parse(&recorder.into_wav()).expect("parse");
        let mut player = PcmPlayer::new(&source, 5, 0);
        let mut out = [0i16; 4];
        assert_eq!(player.next_frame(&mut out), None);
        assert!(player.is_exhausted());
    }

    #[test]
    fn zero_length_output_buffer_yields_none() {
        let source = five_sample_source();
        let mut player = PcmPlayer::new(&source, 1, 0);
        let mut out: [i16; 0] = [];
        assert_eq!(player.next_frame(&mut out), None);
    }

    #[test]
    fn data_chunk_with_odd_trailing_byte_is_sample_aligned() {
        // data length 5 (odd) — 2 whole samples + 1 stray byte that must be dropped.
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"RIFF");
        buffer.extend_from_slice(&0u32.to_le_bytes());
        buffer.extend_from_slice(b"WAVE");
        buffer.extend_from_slice(b"fmt ");
        buffer.extend_from_slice(&16u32.to_le_bytes());
        buffer.extend_from_slice(&1u16.to_le_bytes());
        buffer.extend_from_slice(&1u16.to_le_bytes());
        buffer.extend_from_slice(&8000u32.to_le_bytes());
        buffer.extend_from_slice(&16000u32.to_le_bytes());
        buffer.extend_from_slice(&2u16.to_le_bytes());
        buffer.extend_from_slice(&16u16.to_le_bytes());
        buffer.extend_from_slice(b"data");
        buffer.extend_from_slice(&5u32.to_le_bytes());
        buffer.extend_from_slice(&[0x01, 0x00, 0x02, 0x00, 0x99]); // 1, 2, stray 0x99
        buffer.push(0x00); // RIFF pad byte for the odd chunk
        let source = WavSource::parse(&buffer).expect("parse");
        assert_eq!(source.samples(), &[1, 2]);
    }

    #[test]
    fn riff_size_field_is_consistent_with_recorder() {
        // Cross-check: the recorder's RIFF size field must equal 36 + data_len, which the reader
        // tolerates regardless. Asserts the fixtures we round-trip are well-formed.
        let mut recorder = WavRecorder::new(8000, 1);
        recorder.write_pcm(&[1, 2, 3, 4]);
        let wav = recorder.into_wav();
        assert_eq!(read_u32(&wav, 4), 36 + 8);
    }
}
