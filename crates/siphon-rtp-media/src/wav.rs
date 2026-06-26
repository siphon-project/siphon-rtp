//! A pure-Rust WAV (RIFF/PCM16) recorder sink for call recording.
//!
//! Accumulates decoded PCM and emits a complete little-endian 16-bit PCM WAV on [`WavRecorder::
//! into_wav`]. In-memory keeps it simple and testable; streaming-to-disk (header finalized by
//! seek, plus S3/object-storage upload) is a later refinement on the same [`MediaSink`].

use crate::fanout::MediaSink;

/// Accumulates PCM samples and renders a RIFF/WAVE (PCM16 LE) byte stream.
#[derive(Debug, Clone)]
pub struct WavRecorder {
    sample_rate: u32,
    channels: u16,
    samples: Vec<i16>,
}

impl WavRecorder {
    /// A recorder for `channels`-channel audio at `sample_rate` Hz.
    #[must_use]
    pub fn new(sample_rate: u32, channels: u16) -> Self {
        Self {
            sample_rate,
            channels: channels.max(1),
            samples: Vec::new(),
        }
    }

    /// Total samples recorded so far (across all channels, interleaved).
    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Render the recording as a complete WAV byte stream.
    #[must_use]
    pub fn into_wav(self) -> Vec<u8> {
        let bits_per_sample: u16 = 16;
        let block_align = self.channels * (bits_per_sample / 8);
        let byte_rate = self.sample_rate * u32::from(block_align);
        let data_len = (self.samples.len() * 2) as u32;

        let mut out = Vec::with_capacity(44 + self.samples.len() * 2);
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&(36 + data_len).to_le_bytes());
        out.extend_from_slice(b"WAVE");
        // fmt chunk
        out.extend_from_slice(b"fmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // PCM
        out.extend_from_slice(&self.channels.to_le_bytes());
        out.extend_from_slice(&self.sample_rate.to_le_bytes());
        out.extend_from_slice(&byte_rate.to_le_bytes());
        out.extend_from_slice(&block_align.to_le_bytes());
        out.extend_from_slice(&bits_per_sample.to_le_bytes());
        // data chunk
        out.extend_from_slice(b"data");
        out.extend_from_slice(&data_len.to_le_bytes());
        for sample in &self.samples {
            out.extend_from_slice(&sample.to_le_bytes());
        }
        out
    }
}

impl MediaSink for WavRecorder {
    fn write_pcm(&mut self, pcm: &[i16]) {
        self.samples.extend_from_slice(pcm);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
    }

    fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
    }

    #[test]
    fn writes_valid_wav_header_and_data() {
        let mut recorder = WavRecorder::new(8000, 1);
        recorder.write_pcm(&[0, 0x0100, -1]); // 3 samples
        assert_eq!(recorder.sample_count(), 3);
        let wav = recorder.into_wav();

        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[12..16], b"fmt ");
        assert_eq!(read_u16_le(&wav, 20), 1, "PCM format");
        assert_eq!(read_u16_le(&wav, 22), 1, "mono");
        assert_eq!(read_u32_le(&wav, 24), 8000, "sample rate");
        assert_eq!(read_u32_le(&wav, 28), 16000, "byte rate = rate*2");
        assert_eq!(read_u16_le(&wav, 32), 2, "block align");
        assert_eq!(read_u16_le(&wav, 34), 16, "bits per sample");
        assert_eq!(&wav[36..40], b"data");
        let data_len = read_u32_le(&wav, 40);
        assert_eq!(data_len, 6, "3 samples * 2 bytes");
        assert_eq!(read_u32_le(&wav, 4), 36 + data_len, "RIFF size");
        // Total size and a sample value.
        assert_eq!(wav.len(), 44 + 6);
        assert_eq!(read_u16_le(&wav, 44 + 2), 0x0100, "second sample little-endian");
    }

    #[test]
    fn records_stereo_byte_rate() {
        let recorder = WavRecorder::new(16000, 2);
        let wav = recorder.into_wav();
        assert_eq!(read_u16_le(&wav, 22), 2, "stereo");
        assert_eq!(read_u32_le(&wav, 28), 64000, "16000 * 2ch * 2B");
        assert_eq!(read_u16_le(&wav, 32), 4, "block align = 4");
    }
}
