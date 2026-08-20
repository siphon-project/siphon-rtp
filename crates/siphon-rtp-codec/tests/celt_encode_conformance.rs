//! CELT **encode** conformance: encode real PCM with our [`CeltEncoder`], have *libopus* decode the
//! result, and score that decode against the original with `opus_compare` (RFC 6716 §6). Mono and
//! stereo.
//!
//! An encoder has no reference `final_range` of its own to match, so this harness stacks the four
//! checks that do exist, from strongest to weakest:
//!
//! 1. **libopus agrees on the entropy state.** Our stream is written in `opus_demo`'s `.bit` framing,
//!    which stores our encoder's `final_range` beside every packet. `opus_demo -d` compares its own
//!    decoder's final range against that value and aborts with "Range coder state mismatch" on any
//!    difference — so a successful decode is an *exact* per-packet bitstream check against libopus.
//! 2. **Our own decoder agrees on the entropy state.** The same packets are decoded with
//!    [`CeltDecoder`] and every packet's `final_range` must equal the encoder's. Encoder and decoder
//!    disagreeing is a bug in one of them, and this localises it to the packet.
//! 3. **Quality at least libopus'.** The same source is encoded by libopus itself at the identical
//!    configuration (`opus_demo -e restricted-lowdelay`, same channels / bandwidth / frame size /
//!    rate / CVBR) and decoded; our segmental SNR against the original must be within
//!    [`SNR_MARGIN_DB`] of libopus'. This runs over the *whole* matrix, including the very low rates,
//!    where `opus_compare` cannot be used as the criterion: it is a *decoder* tolerance metric, and
//!    two independent 12 kb/s encodes legitimately differ by more than it allows.
//! 4. **`opus_compare` passes against the original PCM** — the literal RFC §6 criterion. Required for
//!    fullband at the top of the rate range, where the encode is near-transparent and a decoder
//!    tolerance metric is therefore a fair test of an encoder; scored and reported for everything at
//!    96 kb/s and above.
//!
//! The matrix sweeps all four CELT bandwidths × the four CELT frame sizes (2.5/5/10/20 ms) × a
//! bitrate spread from very low (sparse allocation, folding, anti-collapse active) to very high, over
//! two real source signals, in both mono and stereo.
//!
//! Like the decode harnesses, this is a no-op (with a printed notice) when the reference tree or the
//! oracle binaries are absent, so it never breaks CI on a machine without them — and it does **not**
//! pass vacuously: with the reference present, at least one configuration must actually have been
//! scored.

mod common;

use std::path::{Path, PathBuf};

use siphon_rtp_codec::opus::celt::decoder::CeltDecoder;
use siphon_rtp_codec::opus::celt::encoder::{CeltEncoder, RateControl};
use siphon_rtp_codec::opus::packet::Bandwidth;

/// CELT's only sample rate (`mode->Fs`).
const RATE_HZ: u32 = 48_000;
/// Largest Opus frame payload (RFC 6716 §3.4).
const MAX_PACKET_BYTES: usize = 1275;
/// How much of each source file to encode: 4 seconds is plenty for `opus_compare` to be meaningful
/// while keeping the whole sweep quick.
const SECONDS: usize = 4;
/// The CELT layer's algorithmic delay in samples at 48 kHz — the MDCT overlap, which is also what
/// `OPUS_GET_LOOKAHEAD` reports for `OPUS_APPLICATION_RESTRICTED_LOWDELAY` (`Fs/400` = 120).
///
/// `opus_demo -d` cannot know it (only the encoder reports it), so it writes the decode *unshifted*;
/// `opus_compare` is very sensitive to misalignment, so the harness drops this many samples off the
/// front of the decode before scoring. Verified against libopus itself: its own 256 kb/s fullband
/// round trip scores 0.396 (fail) unaligned and 0.042 (83 % quality) at exactly this shift.
const CODEC_DELAY_SAMPLES: usize = 120;
/// How far below libopus' own encoder our segmental SNR may sit at the same configuration. A real
/// regression (a wrong allocation, a mis-scaled band, a broken TF decision) costs many dB, so this is
/// a tight bound while still tolerating that the two encoders make different legal decisions.
const SNR_MARGIN_DB: f32 = 1.0;

/// The reference tree root (`reference/opus`), if present.
fn reference_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus");
    dir.is_dir().then_some(dir)
}

/// The TOC byte for a CELT-only frame (RFC 6716 §3.1, Table 2): configs 16..31 are CELT-only, four
/// per bandwidth in ascending frame duration, then the stereo flag and `code = 0` (one frame).
fn celt_toc(bandwidth: Bandwidth, lm: usize, channels: usize) -> u8 {
    let bandwidth_index = match bandwidth {
        Bandwidth::Narrowband => 0,
        // CELT-only has no medium-band config; libopus maps MB to WB there too.
        Bandwidth::Mediumband | Bandwidth::Wideband => 1,
        Bandwidth::SuperWideband => 2,
        Bandwidth::Fullband => 3,
    };
    let config = 16 + 4 * bandwidth_index + lm as u8;
    (config << 3) | (u8::from(channels == 2) << 2)
}

/// Read a 16-bit little-endian `.sw` file as `f32` in `[-1, 1)`. `max_values` counts interleaved
/// values, not sample instants.
fn read_sw(path: &Path, max_values: usize) -> Option<Vec<f32>> {
    let bytes = std::fs::read(path).ok()?;
    Some(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .take(max_values)
            .map(|c| f32::from(i16::from_le_bytes([c[0], c[1]])) / 32768.0)
            .collect(),
    )
}

/// One encoded configuration: the `opus_demo`-framed bitstream and the PCM that produced it.
struct Encoded {
    /// `[u32 BE payload_len][u32 BE final_range][payload]` per packet — `opus_demo`'s `.bit` format.
    bit_stream: Vec<u8>,
    /// The exact input samples that were encoded, as interleaved 16-bit LE.
    source_pcm: Vec<u8>,
    /// Total payload bytes, for the reported achieved bitrate.
    payload_bytes: usize,
    /// Number of frames encoded.
    frames: usize,
}

/// Encode `signal` and simultaneously verify that our own decoder tracks the encoder's entropy state
/// packet for packet (check 2). `Err` names the first packet that diverged.
fn encode_and_self_check(
    signal: &[f32],
    frame_size: usize,
    channels: usize,
    bandwidth: Bandwidth,
    bitrate: i32,
    rate_control: RateControl,
) -> Result<Encoded, String> {
    let end = CeltEncoder::end_band_for_bandwidth(bandwidth);
    let lm = [120usize, 240, 480, 960]
        .iter()
        .position(|&f| f == frame_size)
        .ok_or_else(|| format!("frame size {frame_size} is not a CELT frame"))?;
    let toc = celt_toc(bandwidth, lm, channels);

    let mut encoder =
        CeltEncoder::with_channels(channels).map_err(|e| format!("CeltEncoder::new: {e:?}"))?;
    encoder.set_bitrate(bitrate);
    encoder.set_rate_control(rate_control);
    encoder
        .set_band_range(0, end)
        .map_err(|e| format!("set_band_range: {e:?}"))?;
    let mut decoder =
        CeltDecoder::with_channels(channels).map_err(|e| format!("CeltDecoder::new: {e:?}"))?;
    decoder
        .set_band_range(0, end)
        .map_err(|e| format!("set_band_range: {e:?}"))?;

    let mut bit_stream = Vec::new();
    let mut source_pcm = Vec::new();
    let mut payload = vec![0u8; MAX_PACKET_BYTES];
    let mut decoded = vec![0i16; frame_size * channels];
    let mut payload_bytes = 0usize;
    let block_values = frame_size * channels;
    let frames = signal.len() / block_values;

    for frame in 0..frames {
        let lo = frame * block_values;
        let block = &signal[lo..lo + block_values];
        let written = encoder
            .encode(block, frame_size, &mut payload)
            .map_err(|e| format!("frame {frame}: encode: {e:?}"))?;
        payload_bytes += written;

        // Check 2: our decoder must land on the same entropy state.
        decoder
            .decode(&payload[..written], &mut decoded, frame_size)
            .map_err(|e| format!("frame {frame}: our own decode failed: {e:?}"))?;
        if decoder.final_range() != encoder.final_range() {
            return Err(format!(
                "frame {frame}: our decoder ended on final_range {:#010x}, encoder said {:#010x}",
                decoder.final_range(),
                encoder.final_range()
            ));
        }

        // `opus_demo` framing: the payload is a full Opus packet, so prepend the TOC.
        let packet_len = written + 1;
        bit_stream.extend_from_slice(&(packet_len as u32).to_be_bytes());
        bit_stream.extend_from_slice(&encoder.final_range().to_be_bytes());
        bit_stream.push(toc);
        bit_stream.extend_from_slice(&payload[..written]);

        for &sample in block {
            let s = (sample * 32768.0).round().clamp(-32768.0, 32767.0) as i16;
            source_pcm.extend_from_slice(&s.to_le_bytes());
        }
    }
    Ok(Encoded {
        bit_stream,
        source_pcm,
        payload_bytes,
        frames,
    })
}

/// Segmental SNR in dB of `test` against `reference`, both interleaved 16-bit LE (the metric this
/// repo already uses for DSP quality work): per-20 ms-frame SNR, clamped to `[-10, 35]` dB, averaged
/// over the frames where the reference actually has energy. A stereo frame covers both channels.
///
/// Used to compare *our* encoder against *libopus'* at the same configuration. Unlike
/// `opus_compare` — a decoder tolerance metric that both encodes are legitimately outside at low
/// rate — this is a direct, monotone quality measure, so "ours is within X dB of theirs" is a
/// meaningful encoder gate across the whole matrix.
fn segmental_snr_db(reference: &[u8], test: &[u8], channels: usize) -> f32 {
    let frame = 960 * channels; // 20 ms at 48 kHz, interleaved
    let to_i16 = |b: &[u8]| -> Vec<f32> {
        b.as_chunks::<2>()
            .0
            .iter()
            .map(|c| f32::from(i16::from_le_bytes([c[0], c[1]])))
            .collect()
    };
    let r = to_i16(reference);
    let t = to_i16(test);
    let n = r.len().min(t.len());
    let mut total = 0f32;
    let mut frames = 0usize;
    let mut index = 0usize;
    while (index + 1) * frame <= n {
        let lo = index * frame;
        let hi = lo + frame;
        let signal: f32 = r[lo..hi].iter().map(|v| v * v).sum();
        // Skip near-silent frames: their SNR is dominated by the reference's own dither.
        if signal > frame as f32 * 4.0 {
            let noise: f32 = r[lo..hi]
                .iter()
                .zip(&t[lo..hi])
                .map(|(a, b)| (a - b) * (a - b))
                .sum::<f32>()
                .max(1e-9);
            total += (10.0 * (signal / noise).log10()).clamp(-10.0, 35.0);
            frames += 1;
        }
        index += 1;
    }
    if frames == 0 {
        return 0.0;
    }
    total / frames as f32
}

/// Interleave a mono 16-bit LE buffer into stereo (each sample duplicated), which is the shape
/// `opus_compare` requires of its *reference* file (`opus_compare.c:231`).
fn mono_to_stereo(mono: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(mono.len() * 2);
    for pair in mono.as_chunks::<2>().0 {
        out.extend_from_slice(pair);
        out.extend_from_slice(pair);
    }
    out
}

/// Run `opus_compare [-s] -r 48000 <reference> <test>` over two in-memory buffers, trimming both to
/// the shorter length. `Ok(())` on a pass.
///
/// `opus_compare` always reads its reference file as two channels, so a mono reference is duplicated
/// here; a stereo one is already the right shape and `-s` keeps the test file stereo too.
fn compare_pcm(
    opus_compare: &Path,
    tag: &str,
    reference: &[u8],
    test: &[u8],
    channels: usize,
) -> Result<(), String> {
    let values = (reference.len() / 2).min(test.len() / 2);
    // Compare whole sample instants only.
    let values = values - values % channels;
    if values == 0 {
        return Err("nothing to compare".to_string());
    }
    let tmp = std::env::temp_dir();
    let unique = format!("celt_cmp_{}_{}", std::process::id(), tag);
    let ref_path = tmp.join(format!("{unique}.ref.sw"));
    let test_path = tmp.join(format!("{unique}.test.sw"));
    let reference = &reference[..2 * values];
    let reference_stereo = if channels == 2 {
        reference.to_vec()
    } else {
        mono_to_stereo(reference)
    };
    std::fs::write(&ref_path, &reference_stereo).map_err(|e| e.to_string())?;
    std::fs::write(&test_path, &test[..2 * values]).map_err(|e| e.to_string())?;
    let mut command = std::process::Command::new(opus_compare);
    if channels == 2 {
        command.arg("-s");
    }
    let output = command
        .arg("-r")
        .arg(RATE_HZ.to_string())
        .arg(&ref_path)
        .arg(&test_path)
        .output()
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&ref_path);
    let _ = std::fs::remove_file(&test_path);
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .replace('\n', " | "))
    }
}

/// Decode an `opus_demo`-framed bitstream with libopus. **This is check 1**: `opus_demo -d` compares
/// its own decoder's range-coder state against the `final_range` stored beside every packet and
/// aborts on any difference, so a success is an exact per-packet bitstream agreement with libopus.
/// Returns the decoded interleaved 16-bit LE PCM with the codec delay already trimmed.
fn libopus_decode(
    opus_demo: &Path,
    tag: &str,
    bit_stream: &[u8],
    channels: usize,
) -> Result<Vec<u8>, String> {
    let tmp = std::env::temp_dir();
    let unique = format!("celt_dec_{}_{}", std::process::id(), tag);
    let bit_path = tmp.join(format!("{unique}.bit"));
    let dec_path = tmp.join(format!("{unique}.dec.sw"));
    std::fs::write(&bit_path, bit_stream).map_err(|e| e.to_string())?;
    let demo = std::process::Command::new(opus_demo)
        .arg("-d")
        .arg(RATE_HZ.to_string())
        .arg(channels.to_string())
        .arg(&bit_path)
        .arg(&dec_path)
        .output()
        .map_err(|e| e.to_string())?;
    let result = if demo.status.success() {
        std::fs::read(&dec_path).map_err(|e| e.to_string())
    } else {
        Err(format!(
            "opus_demo -d failed ({}): {}",
            demo.status,
            String::from_utf8_lossy(&demo.stderr)
                .trim()
                .replace('\n', " | ")
        ))
    };
    let _ = std::fs::remove_file(&bit_path);
    let _ = std::fs::remove_file(&dec_path);
    let decoded = result?;
    let front = 2 * CODEC_DELAY_SAMPLES * channels;
    if decoded.len() <= front {
        return Err(format!(
            "opus_demo -d produced only {} bytes, less than the codec delay",
            decoded.len()
        ));
    }
    Ok(decoded[front..].to_vec())
}

/// Encode the same source with libopus itself at the identical configuration and decode it — the
/// reference side of check 3. Returns interleaved 16-bit LE PCM with the codec delay trimmed.
#[allow(clippy::too_many_arguments)]
fn libopus_reference_roundtrip(
    opus_demo: &Path,
    tag: &str,
    source: &[u8],
    channels: usize,
    bandwidth_name: &str,
    frame_ms: &str,
    bitrate: i32,
) -> Result<Vec<u8>, String> {
    let tmp = std::env::temp_dir();
    let unique = format!("celt_ref_{}_{}", std::process::id(), tag);
    let src_path = tmp.join(format!("{unique}.src.sw"));
    let bit_path = tmp.join(format!("{unique}.bit"));
    std::fs::write(&src_path, source).map_err(|e| e.to_string())?;
    // `restricted-lowdelay` forces `MODE_CELT_ONLY`, which is what we are comparing against.
    let encode = std::process::Command::new(opus_demo)
        .args([
            "-e",
            "restricted-lowdelay",
            &RATE_HZ.to_string(),
            &channels.to_string(),
            &bitrate.to_string(),
            "-cvbr",
            "-bandwidth",
            bandwidth_name,
            "-framesize",
            frame_ms,
        ])
        .arg(&src_path)
        .arg(&bit_path)
        .output()
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&src_path);
    if !encode.status.success() {
        let _ = std::fs::remove_file(&bit_path);
        return Err(format!(
            "reference opus_demo -e failed ({}): {}",
            encode.status,
            String::from_utf8_lossy(&encode.stderr)
                .trim()
                .replace('\n', " | ")
        ));
    }
    let bit_stream = std::fs::read(&bit_path).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&bit_path);
    libopus_decode(opus_demo, &format!("{tag}_ref"), &bit_stream, channels)
}

/// The rate sweep for a given channel count and frame duration.
///
/// Stereo starts higher at the short frame sizes because libopus' *Opus-layer* stereo decision
/// downmixes to mono below its threshold (64 kb/s at 2.5 ms, 48 kb/s at 5 ms) — its encode would
/// then be a mono one and check 3 would be comparing two different things. Above those floors both
/// encoders code real stereo.
fn bitrates_for(channels: usize, frame_size: usize) -> &'static [i32] {
    if channels == 1 {
        return &[12_000, 32_000, 96_000, 256_000];
    }
    match frame_size {
        120 => &[64_000, 96_000, 256_000],
        240 => &[48_000, 96_000, 256_000],
        _ => &[24_000, 64_000, 96_000, 256_000],
    }
}

#[test]
fn our_celt_encoder_streams_pass_libopus_and_opus_compare() {
    let Some(reference) = reference_dir() else {
        eprintln!("celt encode conformance: reference/opus not present — skipping");
        return;
    };
    let Some(opus_demo) = common::oracle("opus_demo") else {
        eprintln!("celt encode conformance: opus_demo not built — skipping");
        return;
    };
    let Some(opus_compare) = common::oracle("opus_compare") else {
        eprintln!("celt encode conformance: opus_compare not built — skipping");
        return;
    };

    let bandwidths = [
        ("NB", Bandwidth::Narrowband),
        ("WB", Bandwidth::Wideband),
        ("SWB", Bandwidth::SuperWideband),
        ("FB", Bandwidth::Fullband),
    ];
    let frame_sizes = [("2.5", 120usize), ("5", 240), ("10", 480), ("20", 960)];

    let mut passed: Vec<String> = Vec::new();
    let mut transparent_passed: Vec<String> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut stereo_scored = 0usize;

    for channels in [1usize, 2] {
        // Two real sources: speech-like and music-like (the same files the CELT-only decode vectors
        // are generated from), mono or stereo as the configuration needs.
        let names: [&str; 2] = if channels == 1 {
            ["src01.sw", "src09.sw"]
        } else {
            ["src01_stereo.sw", "src09_stereo.sw"]
        };
        let sources: Vec<(String, Vec<f32>)> = names
            .iter()
            .filter_map(|name| {
                read_sw(&reference.join(name), SECONDS * RATE_HZ as usize * channels)
                    .map(|pcm| ((*name).to_string(), pcm))
            })
            .filter(|(_, pcm)| pcm.len() >= 48_000 * channels)
            .collect();
        if sources.is_empty() {
            eprintln!(
                "celt encode conformance: no {channels}-channel source PCM in {} — skipping that \
                 half",
                reference.display()
            );
            continue;
        }

        for (source_name, signal) in &sources {
            for &(bandwidth_name, bandwidth) in &bandwidths {
                for &(frame_ms, frame_size) in &frame_sizes {
                    for &bitrate in bitrates_for(channels, frame_size) {
                        // Skip rates that cannot fill even a 3-byte payload for this frame duration;
                        // libopus refuses such combinations at the Opus layer too.
                        if bitrate * frame_size as i32 / (RATE_HZ as i32 * 8) < 3 {
                            continue;
                        }
                        let tag = format!(
                            "{}_{bandwidth_name}_{frame_ms}ms_{}k_c{channels}",
                            source_name.trim_end_matches(".sw"),
                            bitrate / 1000
                        );
                        // Checks 1 + 2: encode, verify our own decoder tracks the entropy state,
                        // then let libopus decode (which verifies its decoder does too).
                        let encoded = match encode_and_self_check(
                            signal,
                            frame_size,
                            channels,
                            bandwidth,
                            bitrate,
                            RateControl::ConstrainedVbr,
                        ) {
                            Ok(e) => e,
                            Err(reason) => {
                                failed.push((tag, reason));
                                continue;
                            }
                        };
                        let achieved = encoded.payload_bytes * 8 * RATE_HZ as usize
                            / (encoded.frames * frame_size);
                        let ours =
                            match libopus_decode(&opus_demo, &tag, &encoded.bit_stream, channels) {
                                Ok(pcm) => pcm,
                                Err(reason) => {
                                    failed.push((tag, reason));
                                    continue;
                                }
                            };
                        // Check 3: against libopus' own encode of the same source at the same config.
                        let theirs = match libopus_reference_roundtrip(
                            &opus_demo,
                            &tag,
                            &encoded.source_pcm,
                            channels,
                            bandwidth_name,
                            frame_ms,
                            bitrate,
                        ) {
                            Ok(pcm) => pcm,
                            Err(reason) => {
                                failed.push((tag, format!("reference encode: {reason}")));
                                continue;
                            }
                        };
                        // Quality relative to the reference encoder, over the whole matrix.
                        let ours_snr = segmental_snr_db(&encoded.source_pcm, &ours, channels);
                        let theirs_snr = segmental_snr_db(&encoded.source_pcm, &theirs, channels);
                        if ours_snr < theirs_snr - SNR_MARGIN_DB {
                            failed.push((
                                tag,
                                format!(
                                    "quality below libopus: {ours_snr:.2} dB vs {theirs_snr:.2} dB \
                                     segmental SNR (margin {SNR_MARGIN_DB} dB)"
                                ),
                            ));
                            continue;
                        }
                        passed.push(format!(
                            "{tag}@{}k snr {ours_snr:.1}/{theirs_snr:.1}dB",
                            achieved / 1000
                        ));
                        if channels == 2 {
                            stereo_scored += 1;
                        }

                        // Check 4: the literal RFC §6 comparison against the original PCM, for the
                        // configurations where the encode is near-transparent enough for a *decoder*
                        // tolerance metric to be a fair test.
                        // Required only for fullband at the top of the rate range: anything narrower
                        // discards spectrum the original still has (SWB drops 12-20 kHz, which the
                        // music source fills), and anything slower than ~256 kb/s is not transparent
                        // enough for a *decoder* tolerance metric to be a fair encoder test. Lower
                        // rates are still scored and reported, they just do not gate.
                        let gated = bitrate >= 256_000 && bandwidth == Bandwidth::Fullband;
                        if gated || bitrate >= 96_000 {
                            match compare_pcm(
                                &opus_compare,
                                &tag,
                                &encoded.source_pcm,
                                &ours,
                                channels,
                            ) {
                                Ok(()) => transparent_passed.push(tag),
                                Err(reason) if gated => {
                                    failed.push((tag, format!("vs the original PCM: {reason}")));
                                }
                                Err(_) => {}
                            }
                        }
                    }
                }
            }
        }
    }

    eprintln!(
        "celt encode conformance: {} configurations passed (vs libopus' own encode), {} of them \
         also pass against the original PCM, {} failed; {stereo_scored} of the passes were stereo",
        passed.len(),
        transparent_passed.len(),
        failed.len()
    );
    eprintln!("  passed: {passed:?}");
    eprintln!("  transparent (vs original PCM): {transparent_passed:?}");
    if !failed.is_empty() {
        eprintln!("  failed: {failed:#?}");
    }
    assert!(
        failed.is_empty(),
        "celt encode: {} configuration(s) failed: {failed:#?}",
        failed.len()
    );
    // The oracle and the sources were present, so configurations must actually have been scored.
    // Without these the test would pass vacuously if everything were skipped.
    assert!(
        !passed.is_empty(),
        "celt encode: nothing was scored — the sweep produced no runnable configuration"
    );
    assert!(
        !transparent_passed.is_empty(),
        "celt encode: no configuration was scored against the original PCM"
    );
    assert!(
        stereo_scored > 0,
        "celt encode: no stereo configuration was scored — are the stereo sources present?"
    );
}
