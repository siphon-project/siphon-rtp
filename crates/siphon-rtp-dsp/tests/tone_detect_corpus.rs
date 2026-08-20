//! Corpus validation for [`siphon_rtp_dsp::RecordToneDetector`].
//!
//! A threshold detector is easy to write and easy to fool, so the acceptance criterion here is not
//! "one hand-picked beep fires" but a **measured true/false rate over a synthesised corpus** of the
//! things a media path actually carries. Every waveform is generated in-test from a fixed-seed LCG
//! and a logical sample clock — no audio files, no `Instant::now()`, no randomness that varies
//! between runs — so the counts below are reproducible bit-for-bit.
//!
//! ## Must fire (false negatives counted)
//! Record tones across 400 Hz…2 kHz and 200…800 ms, at several levels, clean; the same tone with
//! additive noise at 20 / 15 / 10 / 5 dB SNR; and a tone that follows a synthetic greeting.
//!
//! ## Must not fire (false positives counted)
//! Connected speech, **sustained vowels** (the hardest negative — steady pitch and steady level),
//! breathing, mains hum, all sixteen DTMF digits, ringback / busy / congestion / special-information
//! cadences, continuous dial tone, fax calling tone, music on hold, silence and comfort noise.
//!
//! The corpus summary is printed (`cargo test -p siphon-rtp-dsp --test tone_detect_corpus --
//! --nocapture`) and the counts are asserted.

use siphon_rtp_dsp::{RecordToneDetector, ToneOutcome};

// ---------------------------------------------------------------------------------------------
// Deterministic signal synthesis
// ---------------------------------------------------------------------------------------------

/// A fixed-seed linear congruential generator — the only source of "randomness" in the corpus.
struct Lcg(u32);

impl Lcg {
    fn new(seed: u32) -> Self {
        Self(seed | 1)
    }

    /// Uniform in `[-1, 1)`.
    fn next_bipolar(&mut self) -> f32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        ((self.0 >> 8) as f32 / (1u32 << 23) as f32) - 1.0
    }
}

/// Samples in `duration_ms` at `rate`.
fn samples_for(rate: u32, duration_ms: u32) -> usize {
    (u64::from(rate) * u64::from(duration_ms) / 1000) as usize
}

/// A mono `f32` waveform under construction, with a phase accumulator per generator call so
/// concatenated segments join without a click.
struct Signal {
    rate: u32,
    samples: Vec<f32>,
}

impl Signal {
    fn new(rate: u32) -> Self {
        Self {
            rate,
            samples: Vec::new(),
        }
    }

    fn silence(&mut self, duration_ms: u32) -> &mut Self {
        self.samples.extend(std::iter::repeat_n(
            0.0,
            samples_for(self.rate, duration_ms),
        ));
        self
    }

    /// A single steady sine of peak `amplitude` (in `i16` full-scale units).
    fn tone(&mut self, frequency_hz: f32, amplitude: f32, duration_ms: u32) -> &mut Self {
        self.tones(&[(frequency_hz, amplitude)], duration_ms)
    }

    /// A sum of steady sines — a DTMF pair, a two-frequency call-progress tone, a chord.
    fn tones(&mut self, components: &[(f32, f32)], duration_ms: u32) -> &mut Self {
        let count = samples_for(self.rate, duration_ms);
        let start = self.samples.len();
        for index in 0..count {
            let time = (start + index) as f32 / self.rate as f32;
            let mut value = 0.0;
            for &(frequency_hz, amplitude) in components {
                value += amplitude * (2.0 * std::f32::consts::PI * frequency_hz * time).sin();
            }
            self.samples.push(value);
        }
        self
    }

    /// A tone whose frequency is modulated (vibrato) — an instrument note, not a record tone.
    fn vibrato_tone(
        &mut self,
        frequency_hz: f32,
        depth_hz: f32,
        rate_hz: f32,
        amplitude: f32,
        duration_ms: u32,
    ) -> &mut Self {
        let count = samples_for(self.rate, duration_ms);
        let mut phase = 0.0f32;
        for index in 0..count {
            let time = index as f32 / self.rate as f32;
            let instantaneous =
                frequency_hz + depth_hz * (2.0 * std::f32::consts::PI * rate_hz * time).sin();
            phase += 2.0 * std::f32::consts::PI * instantaneous / self.rate as f32;
            self.samples.push(amplitude * phase.sin());
        }
        self
    }

    /// Additive white noise of peak `amplitude` over the whole signal built so far.
    fn add_noise(&mut self, amplitude: f32, seed: u32) -> &mut Self {
        let mut lcg = Lcg::new(seed);
        for sample in self.samples.iter_mut() {
            *sample += amplitude * lcg.next_bipolar();
        }
        self
    }

    /// A band of noise with a slow envelope — breathing / line noise.
    fn shaped_noise(
        &mut self,
        amplitude: f32,
        centre_hz: f32,
        envelope_hz: f32,
        duration_ms: u32,
        seed: u32,
    ) -> &mut Self {
        let count = samples_for(self.rate, duration_ms);
        let mut lcg = Lcg::new(seed);
        // A one-pole resonator gives the noise a broad spectral centre without ringing like a tone.
        let theta = 2.0 * std::f32::consts::PI * centre_hz / self.rate as f32;
        let radius = 0.90f32;
        let (mut previous, mut previous2) = (0.0f32, 0.0f32);
        for index in 0..count {
            let excitation = lcg.next_bipolar();
            let value =
                excitation + 2.0 * radius * theta.cos() * previous - radius * radius * previous2;
            previous2 = previous;
            previous = value;
            let time = index as f32 / self.rate as f32;
            let envelope = 0.5 - 0.5 * (2.0 * std::f32::consts::PI * envelope_hz * time).cos();
            self.samples.push(amplitude * envelope * value * 0.2);
        }
        self
    }

    /// A voiced segment: a harmonic stack at `fundamental_hz` shaped by three formants, with a
    /// `-6 dB/octave` source tilt. `modulation` applies a syllabic amplitude envelope (0 ⇒ a
    /// perfectly sustained vowel, the hardest negative in the corpus).
    #[allow(clippy::too_many_arguments)]
    fn voiced(
        &mut self,
        fundamental_hz: f32,
        formants: [(f32, f32); 3],
        amplitude: f32,
        duration_ms: u32,
        modulation: f32,
        jitter_hz: f32,
        seed: u32,
    ) -> &mut Self {
        let count = samples_for(self.rate, duration_ms);
        let nyquist = self.rate as f32 / 2.0;
        let mut lcg = Lcg::new(seed);
        let mut phase = 0.0f32;
        for index in 0..count {
            let time = index as f32 / self.rate as f32;
            // Pitch jitter (a real larynx is never perfectly periodic; a tone generator is).
            let fundamental = fundamental_hz + jitter_hz * lcg.next_bipolar();
            phase += 2.0 * std::f32::consts::PI * fundamental / self.rate as f32;
            let mut value = 0.0f32;
            let mut harmonic = 1u32;
            while (harmonic as f32) * fundamental < nyquist {
                let frequency = harmonic as f32 * fundamental;
                let mut gain = 0.0f32;
                for &(centre, bandwidth) in &formants {
                    let detune =
                        (frequency * frequency - centre * centre) / (frequency * bandwidth);
                    gain += 1.0 / (1.0 + detune * detune).sqrt();
                }
                // Glottal source tilt, ≈ −6 dB/octave above 300 Hz.
                let tilt = 1.0 / (1.0 + (frequency / 300.0).powi(2)).sqrt();
                value += gain * tilt * (harmonic as f32 * phase).sin();
                harmonic += 1;
            }
            let envelope =
                1.0 - modulation * 0.5 * (1.0 - (2.0 * std::f32::consts::PI * 4.0 * time).cos());
            self.samples.push(amplitude * envelope * value);
        }
        self
    }

    /// Quantise to `i16`, saturating.
    fn finish(&self) -> Vec<i16> {
        self.samples
            .iter()
            .map(|&value| value.round().clamp(-32768.0, 32767.0) as i16)
            .collect()
    }
}

/// Male-ish formant targets for the vowels used as negatives (Peterson & Barney centre values,
/// bandwidths from the usual synthesis defaults).
const VOWEL_A: [(f32, f32); 3] = [(730.0, 60.0), (1090.0, 90.0), (2440.0, 120.0)];
const VOWEL_I: [(f32, f32); 3] = [(270.0, 60.0), (2290.0, 90.0), (3010.0, 120.0)];
const VOWEL_U: [(f32, f32); 3] = [(300.0, 60.0), (870.0, 90.0), (2240.0, 120.0)];
const VOWEL_E: [(f32, f32); 3] = [(530.0, 60.0), (1840.0, 90.0), (2480.0, 120.0)];

/// A few seconds of connected speech: alternating vowel targets with syllabic modulation, pitch
/// jitter and short pauses.
fn greeting(rate: u32, seed: u32) -> Signal {
    let mut signal = Signal::new(rate);
    let vowels = [VOWEL_A, VOWEL_E, VOWEL_I, VOWEL_U, VOWEL_A, VOWEL_E];
    for (index, vowel) in vowels.into_iter().enumerate() {
        let fundamental = 105.0 + 12.0 * index as f32;
        signal.voiced(
            fundamental,
            vowel,
            900.0,
            220,
            1.0,
            3.0,
            seed + index as u32,
        );
        signal.silence(60);
    }
    signal
}

/// RFC 4733 / ITU-T Q.23 DTMF frequency pairs, low group × high group.
const DTMF_LOW: [f32; 4] = [697.0, 770.0, 852.0, 941.0];
const DTMF_HIGH: [f32; 4] = [1209.0, 1336.0, 1477.0, 1633.0];

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// Trailing silence appended to every case so a held detection has room to clear the cadence guard.
const TAIL_MS: u32 = 5_200;

/// Feed `signal` (plus the guard tail) through a fresh detector in 20 ms frames and count how many
/// record tones it reported.
fn detections(rate: u32, signal: &Signal) -> usize {
    let mut padded = Signal {
        rate,
        samples: signal.samples.clone(),
    };
    padded.silence(TAIL_MS);
    let pcm = padded.finish();
    let mut detector = RecordToneDetector::new(rate).expect("build detector");
    let frame_len = detector.frame_len();
    let mut fired = 0;
    for frame in pcm.chunks(frame_len) {
        if let ToneOutcome::Detected(_) = detector.process(frame) {
            fired += 1;
        }
    }
    fired
}

/// One corpus row: how many detections a case produced against how many it should have.
struct Row {
    category: &'static str,
    cases: usize,
    wrong: usize,
}

/// Accumulates corpus rows and renders the report the test prints.
#[derive(Default)]
struct Report {
    rows: Vec<Row>,
    detail: Vec<String>,
}

impl Report {
    fn record(&mut self, category: &'static str, cases: usize, wrong: usize) {
        self.rows.push(Row {
            category,
            cases,
            wrong,
        });
    }

    fn note(&mut self, detail: String) {
        self.detail.push(detail);
    }

    fn total_wrong(&self) -> usize {
        self.rows.iter().map(|row| row.wrong).sum()
    }

    fn total_cases(&self) -> usize {
        self.rows.iter().map(|row| row.cases).sum()
    }

    fn render(&self, heading: &str, wrong_label: &str) -> String {
        let mut out = format!("\n{heading}\n");
        for row in &self.rows {
            out.push_str(&format!(
                "  {:<34} {:>4} cases   {:>3} {wrong_label}\n",
                row.category, row.cases, row.wrong
            ));
        }
        out.push_str(&format!(
            "  {:<34} {:>4} cases   {:>3} {wrong_label}\n",
            "TOTAL",
            self.total_cases(),
            self.total_wrong()
        ));
        for detail in &self.detail {
            out.push_str(&format!("  ! {detail}\n"));
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------
// Must fire
// ---------------------------------------------------------------------------------------------

/// Peak amplitudes standing in for a loud, a nominal and a quiet record tone
/// (≈ −6, −16 and −26 dBFS).
const LEVELS: [(f32, &str); 3] = [
    (16000.0, "-6 dBFS"),
    (5200.0, "-16 dBFS"),
    (1650.0, "-26 dBFS"),
];

fn positive_corpus(rate: u32, report: &mut Report) {
    // 1. Clean tones across the whole frequency window and duration window, at three levels.
    let frequencies = [400.0f32, 440.0, 700.0, 1000.0, 1400.0, 1800.0, 2000.0];
    let durations = [200u32, 300, 500, 800];
    let mut cases = 0;
    let mut missed = 0;
    for &frequency_hz in &frequencies {
        for &duration_ms in &durations {
            for &(amplitude, level) in &LEVELS {
                let mut signal = Signal::new(rate);
                signal.silence(300);
                signal.tone(frequency_hz, amplitude, duration_ms);
                signal.silence(300);
                cases += 1;
                if detections(rate, &signal) != 1 {
                    missed += 1;
                    report.note(format!(
                        "{rate} Hz clean {frequency_hz} Hz / {duration_ms} ms / {level}: missed"
                    ));
                }
            }
        }
    }
    report.record("clean tone (freq × duration × level)", cases, missed);

    // 2. The same tone buried in white noise, at stated in-band SNRs.
    //    Noise peak amplitude for a target SNR against a sine of peak `a`: the sine's power is a²/2
    //    and uniform noise of peak `n` has power n²/3, so n = a·sqrt(3 / (2·snr_linear)).
    let mut cases = 0;
    let mut missed = 0;
    for &snr_db in &[20.0f32, 15.0, 10.0, 5.0] {
        for &frequency_hz in &[700.0f32, 1400.0] {
            let amplitude = 8000.0f32;
            let snr_linear = 10f32.powf(snr_db / 10.0);
            let noise = amplitude * (3.0 / (2.0 * snr_linear)).sqrt();
            let mut signal = Signal::new(rate);
            signal.silence(300);
            signal.tone(frequency_hz, amplitude, 400);
            signal.silence(300);
            signal.add_noise(noise, 0x5EED_1234);
            cases += 1;
            if detections(rate, &signal) != 1 {
                missed += 1;
                report.note(format!(
                    "{rate} Hz noisy {frequency_hz} Hz @ {snr_db} dB SNR: missed"
                ));
            }
        }
    }
    report.record("tone + white noise (20/15/10/5 dB)", cases, missed);

    // 3. The realistic shape: greeting, a beat of silence, then the record tone.
    let mut cases = 0;
    let mut missed = 0;
    for &frequency_hz in &[440.0f32, 1000.0, 1400.0] {
        for &duration_ms in &[250u32, 500] {
            let mut signal = greeting(rate, 0xA11C_E000);
            signal.silence(250);
            signal.tone(frequency_hz, 7000.0, duration_ms);
            signal.silence(200);
            cases += 1;
            if detections(rate, &signal) != 1 {
                missed += 1;
                report.note(format!(
                    "{rate} Hz greeting + {frequency_hz} Hz / {duration_ms} ms: missed"
                ));
            }
        }
    }
    report.record("greeting, then the record tone", cases, missed);
}

// ---------------------------------------------------------------------------------------------
// Must not fire
// ---------------------------------------------------------------------------------------------

fn negative_corpus(rate: u32, report: &mut Report) {
    let check = |category: &'static str, signals: Vec<(String, Signal)>, report: &mut Report| {
        let cases = signals.len();
        let mut fired = 0;
        for (name, signal) in signals {
            let count = detections(rate, &signal);
            if count != 0 {
                fired += 1;
                report.note(format!("{rate} Hz {name}: fired {count}×"));
            }
        }
        report.record(category, cases, fired);
    };

    // Connected speech.
    let mut speech = Vec::new();
    for seed in 0..4u32 {
        speech.push((
            format!("speech seed {seed}"),
            greeting(rate, 0x5E00_0000 + seed * 977),
        ));
    }
    check("connected speech", speech, report);

    // Sustained vowels — steady pitch, steady level, no modulation. The hardest negative.
    let mut vowels = Vec::new();
    for (label, formants) in [
        ("a", VOWEL_A),
        ("i", VOWEL_I),
        ("u", VOWEL_U),
        ("e", VOWEL_E),
    ] {
        for &fundamental in &[105.0f32, 145.0, 220.0] {
            for &duration_ms in &[300u32, 700] {
                let mut signal = Signal::new(rate);
                signal.silence(200);
                // No syllabic modulation and no pitch jitter: a synthetic voice holding one note.
                signal.voiced(fundamental, formants, 1200.0, duration_ms, 0.0, 0.0, 7);
                signal.silence(200);
                vowels.push((
                    format!("sustained /{label}/ F0={fundamental} Hz {duration_ms} ms"),
                    signal,
                ));
            }
        }
    }
    check("sustained vowels", vowels, report);

    // Breathing / line noise.
    let mut breathing = Vec::new();
    for (index, &centre) in [400.0f32, 900.0, 1600.0].iter().enumerate() {
        let mut signal = Signal::new(rate);
        signal.silence(200);
        signal.shaped_noise(6000.0, centre, 2.5, 1600, 0xB1EA_0000 + index as u32);
        signal.silence(200);
        breathing.push((format!("breathing @ {centre} Hz"), signal));
    }
    check("breathing / shaped noise", breathing, report);

    // Mains hum and its harmonic stack (50 Hz and 60 Hz families), which reach into the search band.
    let mut hum = Vec::new();
    for &fundamental in &[50.0f32, 60.0, 100.0, 120.0] {
        let components: Vec<(f32, f32)> = (1..=20)
            .map(|harmonic| {
                (
                    fundamental * harmonic as f32,
                    6000.0 / (harmonic as f32).powf(0.7),
                )
            })
            .filter(|&(frequency, _)| frequency < rate as f32 / 2.0)
            .collect();
        let mut signal = Signal::new(rate);
        signal.silence(200);
        signal.tones(&components, 2000);
        signal.silence(200);
        hum.push((format!("{fundamental} Hz hum stack"), signal));
    }
    check("mains hum", hum, report);

    // All sixteen DTMF digits, at a short (real key press) and a long (held key) duration, and at
    // both twist extremes ITU-T Q.24 tolerates.
    let mut dtmf = Vec::new();
    for (row, &low) in DTMF_LOW.iter().enumerate() {
        for (column, &high) in DTMF_HIGH.iter().enumerate() {
            for &duration_ms in &[80u32, 500] {
                for &(low_gain, high_gain, twist) in
                    &[(8000.0f32, 8000.0f32, "0 dB"), (8000.0, 3180.0, "8 dB")]
                {
                    let mut signal = Signal::new(rate);
                    signal.silence(200);
                    signal.tones(&[(low, low_gain), (high, high_gain)], duration_ms);
                    signal.silence(200);
                    dtmf.push((
                        format!("DTMF r{row}c{column} {duration_ms} ms twist {twist}"),
                        signal,
                    ));
                }
            }
        }
    }
    check("DTMF digits", dtmf, report);

    // Cadenced call-progress tones. Each is played for several full cycles.
    let mut cadences = Vec::new();
    let cadence = |name: &str,
                   components: &[(f32, f32)],
                   pattern: &[(u32, u32)],
                   cycles: usize|
     -> (String, Signal) {
        let mut signal = Signal::new(rate);
        signal.silence(200);
        for _ in 0..cycles {
            for &(on_ms, off_ms) in pattern {
                signal.tones(components, on_ms);
                signal.silence(off_ms);
            }
        }
        (name.to_string(), signal)
    };
    cadences.push(cadence(
        "ringback 440+480 Hz 2 s / 4 s",
        &[(440.0, 6000.0), (480.0, 6000.0)],
        &[(2000, 4000)],
        3,
    ));
    cadences.push(cadence(
        "ringback 400+450 Hz 0.4/0.2/0.4/2.0",
        &[(400.0, 6000.0), (450.0, 6000.0)],
        &[(400, 200), (400, 2000)],
        3,
    ));
    cadences.push(cadence(
        "ringback 425 Hz 1 s / 4 s",
        &[(425.0, 9000.0)],
        &[(1000, 4000)],
        3,
    ));
    cadences.push(cadence(
        "ringback 425 Hz 1 s / 3 s",
        &[(425.0, 9000.0)],
        &[(1000, 3000)],
        3,
    ));
    cadences.push(cadence(
        "busy 480+620 Hz 0.5 / 0.5",
        &[(480.0, 6000.0), (620.0, 6000.0)],
        &[(500, 500)],
        6,
    ));
    cadences.push(cadence(
        "busy 425 Hz 0.5 / 0.5",
        &[(425.0, 9000.0)],
        &[(500, 500)],
        6,
    ));
    cadences.push(cadence(
        "congestion 480+620 Hz 0.25 / 0.25",
        &[(480.0, 6000.0), (620.0, 6000.0)],
        &[(250, 250)],
        10,
    ));
    cadences.push(cadence(
        "congestion 425 Hz 0.25 / 0.25",
        &[(425.0, 9000.0)],
        &[(250, 250)],
        10,
    ));
    cadences.push(cadence(
        "fax calling tone 1100 Hz 0.5 / 3.0",
        &[(1100.0, 9000.0)],
        &[(500, 3000)],
        3,
    ));
    check("cadenced call-progress tones", cadences, report);

    // The three-segment special-information tone (ITU-T E.180 / the North American SIT): rising
    // frequency segments played back to back, then the announcement.
    let mut sit = Vec::new();
    for (label, segments) in [
        (
            "SIT (no-circuit)",
            [(913.8f32, 274u32), (1370.6, 274), (1776.7, 380)],
        ),
        (
            "SIT (intercept)",
            [(913.8f32, 380u32), (1428.5, 274), (1776.7, 380)],
        ),
    ] {
        let mut signal = Signal::new(rate);
        signal.silence(200);
        for (frequency_hz, duration_ms) in segments {
            signal.tone(frequency_hz, 9000.0, duration_ms);
        }
        signal.silence(200);
        sit.push((label.to_string(), signal));
    }
    check("special-information tone", sit, report);

    // Continuous tones — dial tone and a held hold-tone. The upper duration bound is the rule here.
    let mut continuous = Vec::new();
    for (label, components) in [
        (
            "dial tone 350+440 Hz",
            vec![(350.0f32, 7000.0f32), (440.0, 7000.0)],
        ),
        ("dial tone 425 Hz", vec![(425.0, 9000.0)]),
        ("hold tone 1000 Hz", vec![(1000.0, 9000.0)]),
    ] {
        let mut signal = Signal::new(rate);
        signal.silence(200);
        signal.tones(&components, 6000);
        signal.silence(200);
        continuous.push((label.to_string(), signal));
    }
    check("continuous tones", continuous, report);

    // Music on hold: a continuous melody, plus a solo note with vibrato.
    let mut music = Vec::new();
    let mut melody = Signal::new(rate);
    melody.silence(200);
    for &note in &[440.0f32, 493.9, 523.3, 587.3, 659.3, 587.3, 523.3, 493.9] {
        melody.tones(
            &[(note, 5000.0), (note * 2.0, 2500.0), (note * 3.0, 1200.0)],
            400,
        );
    }
    music.push(("melody with harmonics".to_string(), melody));
    let mut chord = Signal::new(rate);
    chord.silence(200);
    chord.tones(&[(440.0, 5000.0), (554.4, 5000.0), (659.3, 5000.0)], 600);
    chord.silence(200);
    music.push(("major chord 600 ms".to_string(), chord));
    let mut vibrato = Signal::new(rate);
    vibrato.silence(200);
    vibrato.vibrato_tone(880.0, 25.0, 5.5, 9000.0, 600);
    vibrato.silence(200);
    music.push(("solo note with vibrato".to_string(), vibrato));
    check("music on hold", music, report);

    // Silence and comfort noise.
    let mut quiet = Vec::new();
    let mut silence = Signal::new(rate);
    silence.silence(4000);
    quiet.push(("digital silence".to_string(), silence));
    for &amplitude in &[60.0f32, 200.0, 600.0] {
        let mut signal = Signal::new(rate);
        signal.silence(4000);
        signal.add_noise(amplitude, 0xC0FF_EE00);
        quiet.push((format!("comfort noise peak {amplitude}"), signal));
    }
    check("silence / comfort noise", quiet, report);
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[test]
fn record_tones_are_detected_across_the_corpus() {
    for rate in [8_000u32, 16_000] {
        let mut report = Report::default();
        positive_corpus(rate, &mut report);
        let rendered = report.render(
            &format!("record-tone corpus — MUST FIRE @ {rate} Hz"),
            "false negatives",
        );
        println!("{rendered}");
        assert_eq!(
            report.total_wrong(),
            0,
            "{rate} Hz: {} false negatives out of {} cases{rendered}",
            report.total_wrong(),
            report.total_cases()
        );
    }
}

#[test]
fn the_noise_floor_the_detector_still_works_at_is_measured_not_claimed() {
    // The concentration ratio degrades as SNR/(SNR+1) and the second-tone margin as the noise
    // floor rises, so there is a real SNR below which a record tone stops being detectable. Measure
    // it rather than asserting a round number, and gate on it so a change that trades robustness
    // away shows up here.
    for rate in [8_000u32, 16_000] {
        let mut lowest_firing_db: Option<f32> = None;
        let mut summary = format!("\nrecord-tone SNR sweep @ {rate} Hz (400 ms, 1000 Hz tone)\n");
        for step in 0..=12 {
            let snr_db = 20.0 - 2.0 * step as f32;
            let amplitude = 8000.0f32;
            let snr_linear = 10f32.powf(snr_db / 10.0);
            let noise = amplitude * (3.0 / (2.0 * snr_linear)).sqrt();
            let mut signal = Signal::new(rate);
            signal.silence(300);
            signal.tone(1000.0, amplitude, 400);
            signal.silence(300);
            signal.add_noise(noise, 0x00A0_15E0);
            let fired = detections(rate, &signal) == 1;
            summary.push_str(&format!(
                "  {snr_db:>5.1} dB  {}\n",
                if fired { "detected" } else { "missed" }
            ));
            if fired {
                lowest_firing_db = Some(snr_db);
            }
        }
        println!("{summary}");
        let floor = lowest_firing_db.expect("the tone must be detected at some SNR");
        assert!(
            floor <= 5.0,
            "{rate} Hz: detection stops at {floor} dB SNR, expected to hold to 5 dB or below{summary}"
        );
    }
}

#[test]
fn nothing_else_in_the_corpus_is_mistaken_for_a_record_tone() {
    for rate in [8_000u32, 16_000] {
        let mut report = Report::default();
        negative_corpus(rate, &mut report);
        let rendered = report.render(
            &format!("record-tone corpus — MUST NOT FIRE @ {rate} Hz"),
            "false positives",
        );
        println!("{rendered}");
        assert_eq!(
            report.total_wrong(),
            0,
            "{rate} Hz: {} false positives out of {} cases{rendered}",
            report.total_wrong(),
            report.total_cases()
        );
    }
}
