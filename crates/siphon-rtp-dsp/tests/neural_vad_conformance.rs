//! Conformance of the hand-written neural VAD forward pass against the reference implementation.
//!
//! ## Why these two gates, and not a bit-exact one
//!
//! The codecs in this tree are validated bit-exact because they are fixed-point and their
//! references are bit-exact. This network is `f32`: the SIMD dot products contract multiplies into
//! FMAs and reduce in lane order, the reference reduces sequentially, and neither is "wrong". So
//! exactness is the wrong gate and the promise is made on two axes instead:
//!
//!   1. **Numeric agreement** — per-window speech probability against the reference, to a stated
//!      tolerance (see [`PROBABILITY_TOLERANCE`]).
//!   2. **Decision agreement** — the speech/non-speech call, which is what a caller actually
//!      consumes, reported as a percentage over a real speech corpus.
//!
//! ## Where the reference numbers came from
//!
//! `tests/vectors/*.f32` were produced once, out of tree, by `onnxruntime` running the published
//! Silero VAD v5 ONNX (`snakers4/silero-vad` v5.1.2) over the matching `*.pcm`. That oracle is a
//! genuine third party: it does not share this port's bugs, which is exactly why a round trip or a
//! self-consistency check would not count here. It is not a build or test dependency — see
//! `reference/silero-vad/` for the scripts that regenerate the vectors.

use std::fs;
use std::path::PathBuf;

use siphon_rtp_dsp::{
    EnergyVad, NeuralVad, NeuralVadStream, NEURAL_VAD_SAMPLE_RATE_HZ, NEURAL_VAD_WINDOW_SAMPLES,
};

/// Absolute tolerance on the per-window speech probability.
///
/// Justification, not a knob turned until the tests went green. Three sources of divergence, none
/// of them a defect:
///
///   * `siphon_rtp_simd::fir_dot_f32` uses `_mm256_fmadd_ps`, so each product is rounded once
///     instead of twice, and reduces eight lanes in parallel rather than left to right. Over the
///     longest dot in the graph (256 taps, the transform) that is a relative error on the order of
///     `sqrt(256) * 2^-24 ≈ 1e-6`.
///   * The reference sums `W·x + b_ih + W·h + b_hh` in a different association than this port.
///   * `exp` and `tanh` are libm here and a vectorised polynomial in the reference runtime; both
///     are within an ULP or two of the true value, but not of each other.
///
/// Those errors pass through a sigmoid, whose derivative is at most 1/4, so the output error is
/// *smaller* than the logit error. 1e-4 is two orders of magnitude above the ~1e-6 that is actually
/// observed and two orders below the 0.15 hysteresis band, so it cannot mask a real porting bug:
/// a wrong weight, a transposed tensor or a mis-ordered gate moves a probability by O(0.1..1).
const PROBABILITY_TOLERANCE: f32 = 1.0e-4;

/// The upstream speech-start threshold, and the decision the agreement gate is measured on.
const SPEECH_THRESHOLD: f32 = 0.5;

/// The engine's default energy-VAD threshold, for the "an energy gate cannot do this" comparisons.
const ENERGY_THRESHOLD: i64 = 1_000_000;

fn vector_path(name: &str, extension: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(format!("{name}.{extension}"))
}

fn load_pcm(name: &str) -> Vec<i16> {
    let bytes = fs::read(vector_path(name, "pcm")).expect("committed PCM vector");
    assert_eq!(bytes.len() % 2, 0, "{name}: PCM is not whole i16 samples");
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| i16::from_le_bytes(*chunk))
        .collect()
}

fn load_reference(name: &str) -> Vec<f32> {
    let bytes = fs::read(vector_path(name, "f32")).expect("committed reference probabilities");
    assert_eq!(
        bytes.len() % 4,
        0,
        "{name}: reference is not whole f32 values"
    );
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| f32::from_le_bytes(*chunk))
        .collect()
}

/// Run the port over a vector, window by window, returning our probability per window.
fn port_probabilities(pcm: &[i16]) -> Vec<f32> {
    let mut detector = NeuralVad::new();
    pcm.as_chunks::<NEURAL_VAD_WINDOW_SAMPLES>()
        .0
        .iter()
        .map(|window| detector.speech_probability(window).expect("full window"))
        .collect()
}

/// Worst absolute probability error and the fraction of windows whose decision matches.
struct Agreement {
    windows: usize,
    worst_absolute_error: f32,
    mean_absolute_error: f32,
    decision_matches: usize,
}

fn compare(name: &str) -> Agreement {
    let pcm = load_pcm(name);
    let reference = load_reference(name);
    let ours = port_probabilities(&pcm);
    assert_eq!(
        ours.len(),
        reference.len(),
        "{name}: window count differs from the reference run"
    );
    assert!(!ours.is_empty(), "{name}: empty vector");

    let mut worst = 0.0f32;
    let mut total = 0.0f64;
    let mut matches = 0usize;
    for (index, (&mine, &theirs)) in ours.iter().zip(reference.iter()).enumerate() {
        assert!(
            (0.0..=1.0).contains(&mine),
            "{name} window {index}: probability {mine} out of range"
        );
        let error = (mine - theirs).abs();
        assert!(
            error <= PROBABILITY_TOLERANCE,
            "{name} window {index}: probability {mine} vs reference {theirs} (error {error:e})"
        );
        worst = worst.max(error);
        total += f64::from(error);
        if (mine >= SPEECH_THRESHOLD) == (theirs >= SPEECH_THRESHOLD) {
            matches += 1;
        }
    }

    Agreement {
        windows: ours.len(),
        worst_absolute_error: worst,
        mean_absolute_error: (total / ours.len() as f64) as f32,
        decision_matches: matches,
    }
}

#[test]
fn speech_corpus_matches_the_reference_numerically_and_by_decision() {
    let agreement = compare("neural_vad_speech");
    // 30 s of the upstream test recording at 16 kHz: 937 windows, 738 of them speech.
    assert_eq!(agreement.windows, 937);
    assert_eq!(
        agreement.decision_matches, agreement.windows,
        "decision agreement {}/{} over the speech corpus",
        agreement.decision_matches, agreement.windows
    );
    eprintln!(
        "speech corpus: {} windows, decision agreement {:.3}%, worst |delta| {:e}, mean |delta| {:e}",
        agreement.windows,
        100.0 * agreement.decision_matches as f64 / agreement.windows as f64,
        agreement.worst_absolute_error,
        agreement.mean_absolute_error
    );
}

#[test]
fn low_frequency_hum_does_not_trigger_although_an_energy_gate_does() {
    // 50 Hz mains plus harmonics at four times the engine's default energy threshold.
    let pcm = load_pcm("neural_vad_hum");
    let agreement = compare("neural_vad_hum");
    assert_eq!(agreement.decision_matches, agreement.windows);

    let mut energy_vad = EnergyVad::new(ENERGY_THRESHOLD, 5);
    let energy_frames = pcm
        .as_chunks::<320>()
        .0
        .iter()
        .filter(|frame| energy_vad.is_speech(*frame))
        .count();
    assert_eq!(
        energy_frames,
        pcm.len() / 320,
        "the energy gate is supposed to fire on all of this — that is the point"
    );

    let worst = port_probabilities(&pcm).into_iter().fold(0.0f32, f32::max);
    assert!(worst < 0.1, "hum reached probability {worst}");
}

#[test]
fn breathing_does_not_trigger_although_an_energy_gate_does() {
    let pcm = load_pcm("neural_vad_breath");
    let agreement = compare("neural_vad_breath");
    assert_eq!(agreement.decision_matches, agreement.windows);

    let mut energy_vad = EnergyVad::new(ENERGY_THRESHOLD, 5);
    let energy_frames = pcm
        .as_chunks::<320>()
        .0
        .iter()
        .filter(|frame| energy_vad.is_speech(*frame))
        .count();
    // The breath vector is bursts separated by quiet gaps, so the energy gate fires on the bursts
    // (~40 of 102 frames) rather than throughout — those are the frames that would false-start a
    // barge-in today. The neural detector fires on none of them.
    assert!(
        energy_frames >= 30,
        "the energy gate should fire on the breath bursts, fired on {energy_frames}"
    );

    let worst = port_probabilities(&pcm).into_iter().fold(0.0f32, f32::max);
    assert!(
        worst < SPEECH_THRESHOLD,
        "breathing reached probability {worst}"
    );
}

#[test]
fn residual_acoustic_echo_does_not_trigger() {
    // Far-end speech through a room impulse response, then ~42 dB of echo-return loss: what a
    // working canceller leaves behind. This is the case barge-in actually depends on.
    let agreement = compare("neural_vad_echo_residual");
    assert_eq!(agreement.decision_matches, agreement.windows);
    let worst = port_probabilities(&load_pcm("neural_vad_echo_residual"))
        .into_iter()
        .fold(0.0f32, f32::max);
    assert!(
        worst < SPEECH_THRESHOLD,
        "residual echo reached probability {worst}"
    );
}

#[test]
fn uncancelled_acoustic_echo_is_classified_as_speech_which_is_why_the_canceller_is_not_optional() {
    // The same echo path at the near-end talker's own level. A speech classifier says speech,
    // because acoustically it *is* speech — no VAD can separate it from a local talker. Pinned as
    // a test so the limitation is a documented property and not a surprise in production: barge-in
    // over a loudspeaker endpoint needs the echo canceller in front of the detector.
    let agreement = compare("neural_vad_echo_coupled");
    assert_eq!(agreement.decision_matches, agreement.windows);
    let speech_windows = port_probabilities(&load_pcm("neural_vad_echo_coupled"))
        .into_iter()
        .filter(|&probability| probability >= SPEECH_THRESHOLD)
        .count();
    assert!(
        speech_windows > agreement.windows / 2,
        "expected coupled echo to read as speech, {speech_windows}/{} did",
        agreement.windows
    );
}

#[test]
fn speech_onset_is_detected_within_one_window() {
    // 1.6 s of a quiet room (window 0..50), then speech. Both the reference and this port must
    // fire on the first window that contains speech; anything later is added turn-taking latency.
    const ONSET_WINDOW: usize = 50;
    let agreement = compare("neural_vad_onset");
    assert_eq!(agreement.decision_matches, agreement.windows);

    let ours = port_probabilities(&load_pcm("neural_vad_onset"));
    let first_speech = ours
        .iter()
        .position(|&probability| probability >= SPEECH_THRESHOLD)
        .expect("the onset vector contains speech");
    assert_eq!(
        first_speech, ONSET_WINDOW,
        "onset detected at window {first_speech}, speech starts at {ONSET_WINDOW}"
    );
    assert!(
        ours[..ONSET_WINDOW]
            .iter()
            .all(|&probability| probability < SPEECH_THRESHOLD),
        "the quiet room before the onset must not read as speech"
    );

    let latency_ms = (first_speech - ONSET_WINDOW + 1) * NEURAL_VAD_WINDOW_SAMPLES * 1000
        / NEURAL_VAD_SAMPLE_RATE_HZ as usize;
    eprintln!("speech-onset latency: {latency_ms} ms (one 512-sample window)");
    assert_eq!(latency_ms, 32);
}

#[test]
fn the_stream_adapter_reaches_the_same_decisions_as_direct_windowing() {
    // Fed 20 ms frames — never aligned to the 512-sample window — the adapter must still produce
    // the reference's decision on every window boundary it crosses.
    let pcm = load_pcm("neural_vad_onset");
    let reference = load_reference("neural_vad_onset");
    let mut stream = NeuralVadStream::new(NEURAL_VAD_SAMPLE_RATE_HZ).expect("build");

    let mut window_index = 0usize;
    let mut consumed = 0usize;
    let mut disagreements = 0usize;
    for frame in pcm.as_chunks::<320>().0 {
        stream.is_speech(frame);
        consumed += frame.len();
        // Every completed window advances the adapter's held probability.
        while window_index < reference.len()
            && (window_index + 1) * NEURAL_VAD_WINDOW_SAMPLES <= consumed
        {
            window_index += 1;
        }
        if window_index > 0 {
            let expected = reference[window_index - 1];
            if (stream.probability() - expected).abs() > PROBABILITY_TOLERANCE {
                disagreements += 1;
            }
        }
    }
    assert_eq!(
        disagreements, 0,
        "the frame-clock adapter drifted from the reference on {disagreements} frames"
    );
}

#[test]
fn an_eight_kilohertz_leg_still_detects_the_speech_onset() {
    // The narrowband path: the leg is 8 kHz, the network is not, so the adapter resamples. The
    // reference probabilities do not apply (the audio has been through a band limit and a rate
    // conversion), but the decision must still land within a couple of windows of the onset.
    const ONSET_WINDOW: usize = 50;
    let pcm = load_pcm("neural_vad_onset");
    let narrowband: Vec<i16> = pcm.as_chunks::<2>().0.iter().map(|pair| pair[0]).collect();

    let mut stream = NeuralVadStream::new(8_000).expect("build");
    let mut fired_at = None;
    for (index, frame) in narrowband.as_chunks::<160>().0.iter().enumerate() {
        if stream.is_speech(frame) {
            fired_at = Some(index);
            break;
        }
    }
    let onset_frame = ONSET_WINDOW * NEURAL_VAD_WINDOW_SAMPLES / 160 / 2;
    let fired_at = fired_at.expect("the 8 kHz path must still detect the onset");
    assert!(
        fired_at >= onset_frame,
        "fired at frame {fired_at}, before the onset at {onset_frame}"
    );
    assert!(
        fired_at - onset_frame <= 4,
        "8 kHz onset latency {} frames after the onset",
        fired_at - onset_frame
    );
    eprintln!(
        "8 kHz leg: onset detected {} ms after the onset",
        (fired_at - onset_frame) * 20
    );
}
