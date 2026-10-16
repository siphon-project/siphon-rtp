//! Runtime **decoded-audio** recording: the streaming writer behind `start_recording` with
//! `format: "wav"` or `format: "ogg_opus"`.
//!
//! # Why this exists alongside the two recorders that already did
//!
//! The engine had two recording mechanisms and neither is a voicemail message:
//!
//! * `start_recording` with `format: "pcap"` writes the **raw wire packets** — any codec, undecoded,
//!   and refused outright on a secure or WebSocket-bridged call. An audit artefact.
//! * The offer/answer `record_call` flag writes decoded WAV per direction, but it is set at
//!   offer/answer time (not at a point in the call a controller chooses), it needs two legs, and it
//!   accumulates the whole call in memory ([`siphon_rtp_media::wav::WavRecorder`]'s `Vec<i16>`),
//!   flushing once at teardown with no event. A one-hour 16 kHz call is ~115 MB per direction, and a
//!   hard task abort loses the file entirely.
//!
//! A voicemail box needs neither: it answers locally, plays a greeting and a beep, and then records
//! the *caller* from a point the controller picks, into decoded audio it will email, transcribe and
//! play back — and it must know when the file is complete so it never attaches a half-written one.
//!
//! # Shape
//!
//! The media path is untouched. A recording attaches the **same** [`siphon_rtp_media::fanout::MediaSink`]
//! the WebSocket tee uses, onto the same post-decode fan-out, feeding the same shared frame assembler
//! ([`siphon_rtp_media::bridge::tee::TeeMixer`]) — which already does mono/stereo interleave across two
//! legs, bounded hand-off, and buffer recycling with no per-frame allocation, and whose wire frames are
//! little-endian 16-bit PCM, i.e. exactly a WAV `data` payload.
//!
//! So this module is only the consumer: a task that hands those bytes to a sink and closes the
//! file. **All of the recording's policy lives here**, in the task, off the media path — the
//! duration limit and the silence detector both read the bytes the writer is already holding.
//! Nothing about a stop condition costs the per-packet path a single instruction.
//!
//! # One loop, two sinks
//!
//! The stop conditions operate on PCM, so they live in one loop and run *before* any encoding: a
//! `duration_ms` means the same audio whichever format holds it. What differs is only where the PCM
//! goes — appended verbatim to a RIFF/WAVE `data` chunk, or Opus-encoded into Ogg pages
//! ([`siphon_rtp_media::ogg_opus`]). The encoder runs here too, in the writer task, never on the
//! media path.

use std::path::PathBuf;

use siphon_rtp_dsp::vad::EnergyVad;
use siphon_rtp_media::ogg_opus::OggOpusWriter;
use siphon_rtp_media::wav::{
    wav_header, WAV_DATA_SIZE_OFFSET, WAV_HEADER_LEN, WAV_RIFF_SIZE_OFFSET,
};
use siphon_rtp_proto::RecordingEndReason;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

/// Mean-square energy at or above which a frame counts as speech for `silence_ms`.
///
/// The same order as the conference mixer's speaker gate and the WS bridge's energy VAD default. It
/// is deliberately a *mean square* (per sample), not a whole-frame sum, so it means the same thing at
/// 8 kHz and 16 kHz and for a mono or stereo recording — the class of bug the AEC track kept finding
/// in caps expressed per frame rather than per sample.
const SILENCE_ENERGY_THRESHOLD: i64 = 1_000_000;

/// Hangover frames for the silence detector, so one quiet frame inside speech does not restart the
/// silence clock. At a 20 ms frame this is ~100 ms.
const SILENCE_HANGOVER_FRAMES: u32 = 5;

/// Why the writer stopped, before it is mapped onto the control-plane reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterEnd {
    /// The frame channel closed: every sink was detached, which is what a `stop_recording` and a
    /// call teardown both look like from here.
    SourceGone,
    /// `max_duration_ms` of audio was written.
    MaxDuration,
    /// `silence_ms` elapsed with no speech.
    Silence,
    /// A write or the finalize failed. The file may be truncated.
    Error,
}

impl WriterEnd {
    /// Map onto the control-plane reason, given what the controller asked for.
    ///
    /// `SourceGone` is deliberately resolved by the caller rather than here: the writer cannot tell a
    /// `stop_recording` from a call that ended under it — both simply detach the sinks — and guessing
    /// would report a hangup as an operator action or the reverse.
    #[must_use]
    pub fn into_reason(self, source_gone: RecordingEndReason) -> RecordingEndReason {
        match self {
            WriterEnd::SourceGone => source_gone,
            WriterEnd::MaxDuration => RecordingEndReason::MaxDuration,
            WriterEnd::Silence => RecordingEndReason::Silence,
            WriterEnd::Error => RecordingEndReason::Error,
        }
    }
}

/// Stop conditions the engine evaluates, because the engine is where the decoded audio is.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecordingLimits {
    /// Stop after this much audio has been written.
    pub max_duration_ms: Option<u64>,
    /// Stop after this long with no speech.
    pub silence_ms: Option<u64>,
}

/// What the writer produced.
#[derive(Debug, Clone)]
pub struct RecordingOutcome {
    /// Audio written, in milliseconds.
    pub duration_ms: u64,
    /// Why it stopped.
    pub end: WriterEnd,
}

/// How the recorded PCM is stored.
pub enum RecordingEncoding {
    /// Appended verbatim to a RIFF/WAVE file.
    Wav,
    /// Opus-encoded into Ogg pages. The writer is built — and every input validated — before the
    /// recording starts, so a configuration Opus cannot take fails the verb rather than the task.
    OggOpus(Box<OggOpusWriter>),
}

impl std::fmt::Debug for RecordingEncoding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            RecordingEncoding::Wav => "Wav",
            RecordingEncoding::OggOpus(_) => "OggOpus",
        })
    }
}

/// The file a recording writes and what it holds.
#[derive(Debug)]
pub struct RecordingOutput {
    /// Opened (and so validated) before the recording starts.
    pub file: tokio::fs::File,
    /// For logs only; the file is already open.
    pub path: PathBuf,
    /// The PCM rate of the frames, which is also the rate the file declares.
    pub sample_rate: u32,
    /// 1 or 2; stereo frames are interleaved.
    pub channels: u16,
    /// How the PCM is stored.
    pub encoding: RecordingEncoding,
}

/// The format-specific half of the writer: where PCM goes once the loop has accepted it.
enum Sink {
    Wav {
        sample_rate: u32,
        channels: u16,
    },
    OggOpus {
        writer: Box<OggOpusWriter>,
        /// The frame's samples, decoded from the wire bytes; reused across frames.
        samples: Vec<i16>,
        /// Pages completed by the last push; reused across frames.
        pages: Vec<u8>,
    },
}

impl Sink {
    fn new(sample_rate: u32, channels: u16, encoding: RecordingEncoding) -> Self {
        match encoding {
            RecordingEncoding::Wav => Sink::Wav {
                sample_rate,
                channels,
            },
            RecordingEncoding::OggOpus(writer) => Sink::OggOpus {
                writer,
                samples: Vec::new(),
                pages: Vec::new(),
            },
        }
    }

    /// What goes in the file before any audio.
    async fn begin(&mut self, file: &mut tokio::fs::File) -> std::io::Result<()> {
        match self {
            // The header is written with both sizes zero and fixed by seeking back at the end. A
            // file whose writer was killed mid-recording is therefore a valid WAV declaring zero
            // samples.
            Sink::Wav {
                sample_rate,
                channels,
            } => {
                file.write_all(&wav_header(*sample_rate, *channels, 0))
                    .await
            }
            Sink::OggOpus { writer, pages, .. } => {
                writer.write_headers(pages).map_err(std::io::Error::other)?;
                write_pages(file, pages).await
            }
        }
    }

    /// Store one chunk of little-endian 16-bit PCM.
    async fn write(&mut self, file: &mut tokio::fs::File, pcm: &[u8]) -> std::io::Result<()> {
        match self {
            // The wire bytes are a WAV `data` payload already: no re-encode.
            Sink::Wav { .. } => file.write_all(pcm).await,
            Sink::OggOpus {
                writer,
                samples,
                pages,
            } => {
                samples.clear();
                samples.extend(
                    pcm.as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| i16::from_le_bytes(*pair)),
                );
                writer.push(samples, pages).map_err(std::io::Error::other)?;
                // A page is written — and flushed to the OS — as soon as it completes, so every
                // page on disk is whole and a writer killed mid-recording leaves a file that plays
                // up to its last page. Ogg needs no fix-up at the end for that, unlike the WAV
                // header.
                if pages.is_empty() {
                    Ok(())
                } else {
                    write_pages(file, pages).await
                }
            }
        }
    }

    /// Close the file's structure once the last of `data_len` bytes of PCM has been written.
    async fn finish(&mut self, file: &mut tokio::fs::File, data_len: u64) -> std::io::Result<()> {
        match self {
            Sink::Wav { .. } => finalize(file, u32::try_from(data_len).unwrap_or(u32::MAX)).await,
            Sink::OggOpus { writer, pages, .. } => {
                writer.finish(pages).map_err(std::io::Error::other)?;
                write_pages(file, pages).await?;
                file.sync_all().await
            }
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Sink::Wav { .. } => "WAV",
            Sink::OggOpus { .. } => "Ogg Opus",
        }
    }
}

/// Append whole pages and flush them out of the file's buffer, then reuse the page buffer.
async fn write_pages(file: &mut tokio::fs::File, pages: &mut Vec<u8>) -> std::io::Result<()> {
    file.write_all(pages).await?;
    file.flush().await?;
    pages.clear();
    Ok(())
}

/// Stream L16 frames to a RIFF/WAVE file until the source stops or a limit fires.
///
/// `frames` carries little-endian 16-bit PCM exactly as it goes on the wire, so the bytes are appended
/// verbatim — there is no re-encode, and `sample_rate` / `channels` only ever describe them. Each
/// drained buffer is returned through `recycle` so the sinks keep reusing the same pool and the media
/// path never allocates.
///
/// The header is written **first**, with both sizes zero, and fixed by seeking back when the recording
/// closes. A file whose writer was killed mid-recording is therefore a valid WAV that declares zero
/// samples rather than a corrupt one — which is why the finalize is what the completion event waits
/// for.
pub async fn run_wav_recorder(
    file: tokio::fs::File,
    path: PathBuf,
    sample_rate: u32,
    channels: u16,
    limits: RecordingLimits,
    frames: flume::Receiver<Vec<u8>>,
    recycle: flume::Sender<Vec<u8>>,
) -> RecordingOutcome {
    run_recorder(
        RecordingOutput {
            file,
            path,
            sample_rate,
            channels,
            encoding: RecordingEncoding::Wav,
        },
        limits,
        frames,
        recycle,
    )
    .await
}

/// Stream L16 frames into `output` until the source stops or a limit fires, then close the file.
///
/// The limits are measured on the PCM before it reaches the sink, so `duration_ms` is the same
/// audio for every encoding. Each drained buffer is returned through `recycle`, exactly as for a
/// WAV.
pub async fn run_recorder(
    output: RecordingOutput,
    limits: RecordingLimits,
    frames: flume::Receiver<Vec<u8>>,
    recycle: flume::Sender<Vec<u8>>,
) -> RecordingOutcome {
    let RecordingOutput {
        mut file,
        path,
        sample_rate,
        channels,
        encoding,
    } = output;
    let mut sink = Sink::new(sample_rate, channels, encoding);
    let bytes_per_sample_frame = usize::from(channels.max(1)) * 2;
    // Bytes of audio that make up one millisecond, as a rational — never rounded to an integer number
    // of bytes, which at 8 kHz mono would be 16 bytes/ms exactly but at 11.025 kHz would not be.
    let bytes_per_second = sample_rate as u64 * bytes_per_sample_frame as u64;

    if let Err(error) = sink.begin(&mut file).await {
        tracing::warn!(
            target: "siphon_rtp::media",
            path = %path.display(),
            %error,
            format = sink.name(),
            "recording could not write its header"
        );
        return RecordingOutcome {
            duration_ms: 0,
            end: WriterEnd::Error,
        };
    }

    let max_bytes = limits.max_duration_ms.map(|limit| {
        // Round the limit down to a whole sample frame so the file never ends mid-sample.
        let bytes = limit.saturating_mul(bytes_per_second) / 1000;
        bytes - (bytes % bytes_per_sample_frame as u64)
    });
    let mut vad = limits
        .silence_ms
        .map(|_| EnergyVad::new(SILENCE_ENERGY_THRESHOLD, SILENCE_HANGOVER_FRAMES));
    let mut silent_bytes: u64 = 0;
    let silence_limit_bytes = limits
        .silence_ms
        .map(|limit| limit.saturating_mul(bytes_per_second) / 1000);

    let mut written: u64 = 0;
    let mut end = WriterEnd::SourceGone;
    // Reused across frames so the silence check allocates nothing per frame either.
    let mut samples: Vec<i16> = Vec::new();

    while let Ok(frame) = frames.recv_async().await {
        // Truncate the last frame so an exact `max_duration_ms` is honoured rather than overshot by
        // up to one frame — a voicemail that announces 60 seconds must not write 60.02.
        let mut take = frame.len();
        if let Some(max_bytes) = max_bytes {
            let remaining = max_bytes.saturating_sub(written) as usize;
            if take >= remaining {
                take = remaining;
                end = WriterEnd::MaxDuration;
            }
        }

        if take > 0 {
            if let Err(error) = sink.write(&mut file, &frame[..take]).await {
                tracing::warn!(
                    target: "siphon_rtp::media",
                    path = %path.display(),
                    %error,
                    "recording write failed"
                );
                let _ = recycle.send(frame);
                end = WriterEnd::Error;
                break;
            }
            written += take as u64;
        }

        // Silence: decode the frame we just wrote back into samples and ask the energy VAD. Off the
        // media path entirely — this task owns it — so the per-packet cost of asking for `silence_ms`
        // is zero.
        if let (Some(vad), Some(silence_limit_bytes)) = (vad.as_mut(), silence_limit_bytes) {
            samples.clear();
            samples.extend(
                frame[..take]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| i16::from_le_bytes(*pair)),
            );
            if !samples.is_empty() {
                if vad.is_speech(&samples) {
                    silent_bytes = 0;
                } else {
                    silent_bytes += take as u64;
                    if silent_bytes >= silence_limit_bytes {
                        end = WriterEnd::Silence;
                    }
                }
            }
        }

        // Hand the buffer back to the sink pool. A closed channel means the sinks are already gone,
        // which the next `recv_async` reports as the real end.
        let _ = recycle.send(frame);

        if matches!(end, WriterEnd::MaxDuration | WriterEnd::Silence) {
            break;
        }
    }

    // Close the file: fill in the WAV sizes the header was written with as zero, or flush the
    // encoder and write the end-of-stream page. A failure here is an `Error` end even if every
    // sample was written, because the file a consumer opens would not describe its audio.
    if !matches!(end, WriterEnd::Error) {
        if let Err(error) = sink.finish(&mut file, written).await {
            tracing::warn!(
                target: "siphon_rtp::media",
                path = %path.display(),
                %error,
                format = sink.name(),
                "recording could not close its file"
            );
            end = WriterEnd::Error;
        }
    }

    let duration_ms = (written * 1000).checked_div(bytes_per_second).unwrap_or(0);
    tracing::info!(
        target: "siphon_rtp::media",
        path = %path.display(),
        duration_ms,
        ?end,
        "recording closed"
    );
    RecordingOutcome { duration_ms, end }
}

/// Seek back over the placeholder header and write the two real sizes, then flush.
async fn finalize(file: &mut tokio::fs::File, data_len: u32) -> std::io::Result<()> {
    file.seek(std::io::SeekFrom::Start(WAV_RIFF_SIZE_OFFSET))
        .await?;
    file.write_all(&((WAV_HEADER_LEN as u32 - 8) + data_len).to_le_bytes())
        .await?;
    file.seek(std::io::SeekFrom::Start(WAV_DATA_SIZE_OFFSET))
        .await?;
    file.write_all(&data_len.to_le_bytes()).await?;
    file.flush().await?;
    file.sync_all().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_media::player::WavSource;

    /// One L16 frame of `samples` mono samples at `value`.
    fn frame(samples: usize, value: i16) -> Vec<u8> {
        let mut out = Vec::with_capacity(samples * 2);
        for _ in 0..samples {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }

    /// Drive the writer over a fixed frame list and read the finished file back.
    async fn record(
        limits: RecordingLimits,
        frames_in: Vec<Vec<u8>>,
    ) -> (RecordingOutcome, Vec<u8>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("recording.wav");
        let (sender, frames) = flume::bounded(64);
        let (recycle, _returned) = flume::unbounded();
        for frame in frames_in {
            sender.send(frame).expect("queue frame");
        }
        drop(sender);
        let file = tokio::fs::File::create(&path).await.expect("create");
        let outcome = run_wav_recorder(file, path.clone(), 8000, 1, limits, frames, recycle).await;
        let bytes = std::fs::read(&path).expect("read recording");
        (outcome, bytes, dir)
    }

    #[tokio::test]
    async fn a_finished_recording_is_a_valid_wav_the_reader_accepts() {
        // The point of the streaming form: the header is written with zero sizes up front and fixed
        // by seek at the end, so this proves the finalize actually ran and produced a file the tree's
        // own RIFF reader parses — not merely that bytes reached the disk.
        let (outcome, bytes, _dir) =
            record(RecordingLimits::default(), vec![frame(160, 1000); 5]).await;
        assert_eq!(outcome.end, WriterEnd::SourceGone);
        assert_eq!(outcome.duration_ms, 100, "5 × 20 ms at 8 kHz mono");

        let parsed = WavSource::parse(&bytes).expect("the finished file is a valid WAV");
        assert_eq!(parsed.sample_rate_hz(), 8000);
        assert_eq!(parsed.channels(), 1);
        assert_eq!(parsed.samples().len(), 800);
        assert!(parsed.samples().iter().all(|&sample| sample == 1000));
        assert_eq!(
            bytes.len(),
            WAV_HEADER_LEN + 1600,
            "header plus exactly the audio written"
        );
    }

    #[tokio::test]
    async fn a_stereo_recording_declares_two_channels() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stereo.wav");
        let (sender, frames) = flume::bounded(8);
        let (recycle, _returned) = flume::unbounded();
        sender.send(frame(320, 500)).expect("queue");
        drop(sender);
        let file = tokio::fs::File::create(&path).await.expect("create");
        let outcome = run_wav_recorder(
            file,
            path.clone(),
            8000,
            2,
            RecordingLimits::default(),
            frames,
            recycle,
        )
        .await;
        let parsed = WavSource::parse(&std::fs::read(&path).expect("read")).expect("parse");
        assert_eq!(parsed.channels(), 2);
        assert_eq!(
            parsed.frame_count(),
            160,
            "320 interleaved = 160 per channel"
        );
        assert_eq!(outcome.duration_ms, 20);
    }

    #[tokio::test]
    async fn max_duration_truncates_the_last_frame_rather_than_overshooting() {
        // A voicemail that announces a 50 ms limit must not write 60. The cut lands on a whole sample
        // frame, so the file never ends mid-sample.
        let limits = RecordingLimits {
            max_duration_ms: Some(50),
            ..RecordingLimits::default()
        };
        let (outcome, bytes, _dir) = record(limits, vec![frame(160, 1000); 10]).await;
        assert_eq!(outcome.end, WriterEnd::MaxDuration);
        assert_eq!(outcome.duration_ms, 50);
        let parsed = WavSource::parse(&bytes).expect("parse");
        assert_eq!(parsed.samples().len(), 400, "50 ms at 8 kHz mono");
    }

    #[tokio::test]
    async fn silence_ends_a_recording_and_speech_resets_its_clock() {
        // Two runs over the same frame budget: continuous silence ends at the limit, while speech
        // arriving before the limit pushes it back — otherwise a caller who pauses mid-message would
        // have the message cut off mid-sentence.
        let limits = RecordingLimits {
            silence_ms: Some(60),
            ..RecordingLimits::default()
        };
        let (quiet, _bytes, _dir) = record(limits, vec![frame(160, 0); 10]).await;
        assert_eq!(quiet.end, WriterEnd::Silence);
        assert_eq!(quiet.duration_ms, 60, "ended exactly at the silence limit");

        let mut mixed = vec![frame(160, 0); 2];
        mixed.push(frame(160, 8000)); // speech resets the clock
        mixed.extend(vec![frame(160, 0); 10]);
        let (spoken, _bytes, _dir) = record(limits, mixed).await;
        assert_eq!(spoken.end, WriterEnd::Silence);
        assert!(
            spoken.duration_ms > 60,
            "the speech frame pushed the silence deadline back, got {}",
            spoken.duration_ms
        );
    }

    #[tokio::test]
    async fn a_recording_that_never_received_a_frame_is_still_a_valid_empty_wav() {
        // A controller that starts and immediately stops must not be handed a corrupt file.
        let (outcome, bytes, _dir) = record(RecordingLimits::default(), Vec::new()).await;
        assert_eq!(outcome.duration_ms, 0);
        assert_eq!(bytes.len(), WAV_HEADER_LEN);
        let parsed = WavSource::parse(&bytes).expect("an empty recording is still a valid WAV");
        assert!(parsed.samples().is_empty());
    }

    #[tokio::test]
    async fn buffers_are_returned_to_the_sink_pool() {
        // The whole point of the recycle channel: the media path reuses these, so a writer that
        // swallowed them would make every frame an allocation on the hot path.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("recycle.wav");
        let (sender, frames) = flume::bounded(8);
        let (recycle, returned) = flume::unbounded();
        for _ in 0..4 {
            sender.send(frame(160, 100)).expect("queue");
        }
        drop(sender);
        let file = tokio::fs::File::create(&path).await.expect("create");
        run_wav_recorder(
            file,
            path,
            8000,
            1,
            RecordingLimits::default(),
            frames,
            recycle,
        )
        .await;
        assert_eq!(returned.len(), 4, "every drained buffer went back");
    }

    #[test]
    fn the_writer_never_guesses_why_the_source_went_away() {
        // A stop and a hangup both look like "the sinks are gone" from the writer, so it reports what
        // the caller tells it rather than picking one — reporting a hangup as an operator action (or
        // the reverse) would be wrong in the CDR and wrong in the voicemail box's own bookkeeping.
        assert_eq!(
            WriterEnd::SourceGone.into_reason(RecordingEndReason::Stopped),
            RecordingEndReason::Stopped
        );
        assert_eq!(
            WriterEnd::SourceGone.into_reason(RecordingEndReason::CallEnded),
            RecordingEndReason::CallEnded
        );
        // A limit that fired is the writer's own knowledge and overrides whatever the caller assumed.
        assert_eq!(
            WriterEnd::MaxDuration.into_reason(RecordingEndReason::CallEnded),
            RecordingEndReason::MaxDuration
        );
        assert_eq!(
            WriterEnd::Silence.into_reason(RecordingEndReason::Stopped),
            RecordingEndReason::Silence
        );
    }

    /// An Ogg Opus writer for an 8 kHz mono recording at the default bitrate.
    fn ogg_opus(rate: u32, channels: u8) -> RecordingEncoding {
        use siphon_rtp_media::ogg_opus::{OggOpusConfig, OggOpusWriter};
        RecordingEncoding::OggOpus(Box::new(
            OggOpusWriter::new(OggOpusConfig {
                sample_rate_hz: rate,
                channels,
                bitrate_bps: 16_000 * u32::from(channels),
                serial: 42,
                vendor: "siphon-rtp test",
            })
            .expect("writer"),
        ))
    }

    /// One 20 ms 8 kHz frame of a 440 Hz tone, starting at sample `offset`.
    fn tone_frame(offset: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(320);
        for index in offset..offset + 160 {
            let phase = 2.0 * std::f32::consts::PI * 440.0 * index as f32 / 8000.0;
            out.extend_from_slice(&((phase.sin() * 8000.0) as i16).to_le_bytes());
        }
        out
    }

    /// Each page's header-type flags and granule position, with every checksum verified.
    fn ogg_pages(bytes: &[u8]) -> Vec<(u8, u64)> {
        let mut pages = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            assert_eq!(&bytes[offset..offset + 4], b"OggS");
            let segments = usize::from(bytes[offset + 26]);
            let body: usize = bytes[offset + 27..offset + 27 + segments]
                .iter()
                .map(|&value| usize::from(value))
                .sum();
            let end = offset + 27 + segments + body;
            let mut page = bytes[offset..end].to_vec();
            let stored = u32::from_le_bytes([page[22], page[23], page[24], page[25]]);
            page[22..26].fill(0);
            assert_eq!(siphon_rtp_media::ogg::ogg_crc(&page), stored, "page CRC");
            let granule = u64::from_le_bytes(bytes[offset + 6..offset + 14].try_into().expect("8"));
            pages.push((bytes[offset + 5], granule));
            offset = end;
        }
        pages
    }

    /// Whole pages at the head of `bytes`, tolerating a page still being written after them.
    fn complete_pages(bytes: &[u8]) -> usize {
        let (mut offset, mut count) = (0, 0);
        while let Some(header) = bytes.get(offset..offset + 27) {
            let segments = usize::from(header[26]);
            let Some(lacing) = bytes.get(offset + 27..offset + 27 + segments) else {
                break;
            };
            let end =
                offset + 27 + segments + lacing.iter().map(|&v| usize::from(v)).sum::<usize>();
            if end > bytes.len() {
                break;
            }
            count += 1;
            offset = end;
        }
        count
    }

    async fn record_ogg_opus(
        limits: RecordingLimits,
        frames_in: Vec<Vec<u8>>,
    ) -> (RecordingOutcome, Vec<u8>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("recording.opus");
        let (sender, frames) = flume::bounded(256);
        let (recycle, _returned) = flume::unbounded();
        for frame in frames_in {
            sender.send(frame).expect("queue frame");
        }
        drop(sender);
        let file = tokio::fs::File::create(&path).await.expect("create");
        let outcome = run_recorder(
            RecordingOutput {
                file,
                path: path.clone(),
                sample_rate: 8000,
                channels: 1,
                encoding: ogg_opus(8000, 1),
            },
            limits,
            frames,
            recycle,
        )
        .await;
        let bytes = std::fs::read(&path).expect("read recording");
        (outcome, bytes, dir)
    }

    #[tokio::test]
    async fn an_ogg_opus_recording_ends_on_an_end_of_stream_page_trimmed_to_the_audio() {
        let frames: Vec<Vec<u8>> = (0..5).map(|index| tone_frame(index * 160)).collect();
        let (outcome, bytes, _dir) = record_ogg_opus(RecordingLimits::default(), frames).await;
        assert_eq!(outcome.end, WriterEnd::SourceGone);
        assert_eq!(outcome.duration_ms, 100, "the same PCM arithmetic as a WAV");
        let pages = ogg_pages(&bytes);
        assert_eq!(pages.len(), 3, "OpusHead, OpusTags, one audio page");
        assert_eq!(pages[0].0, 0x02, "beginning of stream");
        assert_eq!(pages[2].0, 0x04, "end of stream");
        assert_eq!(
            pages[2].1,
            312 + 800 * 6,
            "pre-skip plus exactly 100 ms at 48 kHz"
        );
    }

    #[tokio::test]
    async fn limits_are_measured_on_the_pcm_whatever_the_format() {
        // `duration_ms` and `max_duration_ms` mean the same audio for both formats because the cut
        // happens before encoding — and the decoded length agrees with the event.
        let limits = RecordingLimits {
            max_duration_ms: Some(50),
            ..RecordingLimits::default()
        };
        let frames: Vec<Vec<u8>> = (0..10).map(|index| tone_frame(index * 160)).collect();
        let (outcome, bytes, _dir) = record_ogg_opus(limits, frames).await;
        assert_eq!(outcome.end, WriterEnd::MaxDuration);
        assert_eq!(outcome.duration_ms, 50);
        let last = *ogg_pages(&bytes).last().expect("pages");
        assert_eq!(last.1, 312 + 400 * 6, "50 ms at 48 kHz after pre-skip");

        let limits = RecordingLimits {
            silence_ms: Some(60),
            ..RecordingLimits::default()
        };
        let (quiet, _bytes, _dir) = record_ogg_opus(limits, vec![frame(160, 0); 10]).await;
        assert_eq!(quiet.end, WriterEnd::Silence);
        assert_eq!(quiet.duration_ms, 60);
    }

    #[tokio::test]
    async fn an_ogg_opus_recording_that_never_received_a_frame_is_still_a_valid_stream() {
        let (outcome, bytes, _dir) = record_ogg_opus(RecordingLimits::default(), Vec::new()).await;
        assert_eq!(outcome.duration_ms, 0);
        let pages = ogg_pages(&bytes);
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[2], (0x04, 312), "decodes to zero samples");
    }

    #[tokio::test]
    async fn an_ogg_opus_writer_returns_its_buffers_to_the_sink_pool() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("recycle.opus");
        let (sender, frames) = flume::bounded(8);
        let (recycle, returned) = flume::unbounded();
        for index in 0..4 {
            sender.send(tone_frame(index * 160)).expect("queue");
        }
        drop(sender);
        run_recorder(
            RecordingOutput {
                file: tokio::fs::File::create(&path).await.expect("create"),
                path,
                sample_rate: 8000,
                channels: 1,
                encoding: ogg_opus(8000, 1),
            },
            RecordingLimits::default(),
            frames,
            recycle,
        )
        .await;
        assert_eq!(returned.len(), 4, "every drained buffer went back");
    }

    #[tokio::test]
    async fn an_aborted_ogg_opus_writer_leaves_every_written_page_playable() {
        // The property the WAV writer cannot have: a writer killed mid-recording leaves a file that
        // plays up to its last complete page, because each page is flushed out whole as it
        // completes. Abort only once the third audio page is on disk, then check what a player
        // would open.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("killed.opus");
        let (sender, frames) = flume::bounded(256);
        let (recycle, _returned) = flume::unbounded();
        for index in 0..175 {
            sender.send(tone_frame(index * 160)).expect("queue");
        }
        let task = tokio::spawn(run_recorder(
            RecordingOutput {
                file: tokio::fs::File::create(&path).await.expect("create"),
                path: path.clone(),
                sample_rate: 8000,
                channels: 1,
                encoding: ogg_opus(8000, 1),
            },
            RecordingLimits::default(),
            frames,
            recycle,
        ));
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            if complete_pages(&std::fs::read(&path).expect("read")) >= 5 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "three audio pages never landed"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        task.abort();
        let _ = task.await;
        drop(sender);

        let bytes = std::fs::read(&path).expect("read");
        let pages = ogg_pages(&bytes);
        assert_eq!(
            pages.len(),
            5,
            "headers plus three whole seconds; the fourth never closed"
        );
        assert!(
            pages.iter().all(|&(flags, _)| flags & 0x04 == 0),
            "no end of stream"
        );
        assert_eq!(pages[4].1, 150 * 960);

        // The reference decoder plays it to the last page, when opus-tools is installed.
        let decoded = path.with_extension("wav");
        match std::process::Command::new("opusdec")
            .args(["--quiet", "--rate", "48000", "--force-wav"])
            .arg(&path)
            .arg(&decoded)
            .output()
        {
            Ok(output) => {
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let parsed =
                    WavSource::parse(&std::fs::read(&decoded).expect("decoded")).expect("wav");
                assert_eq!(parsed.samples().len(), 150 * 960 - 312);
            }
            Err(_) => eprintln!("skipping the opusdec check: opus-tools not installed"),
        }
    }
}
