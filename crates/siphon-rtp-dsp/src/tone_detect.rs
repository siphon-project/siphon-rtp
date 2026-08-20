//! Record-tone ("voicemail beep") detection on a decoded audio stream.
//!
//! [`RecordToneDetector`] answers one question from the media alone: *did this leg just play the
//! short single tone an answering machine emits before it starts recording?* It is the media half of
//! answering-machine detection — a controller that gets the event can abort a transfer instead of
//! bridging a live caller into a voicemail box.
//!
//! ## What a record tone looks like
//!
//! The one standardised anchor is ITU-T E.180 / Q.35's **recording warning tone** (1400 Hz, a 500 ms
//! burst). Deployed voicemail record tones sit in the same neighbourhood: a single, roughly steady
//! tone somewhere in 400 Hz…2 kHz, a few hundred milliseconds long, played once, after the greeting.
//! The detectable signature is therefore *a sustained narrow-band tone of stable frequency and stable
//! amplitude, of a plausible duration, that is not speech and is not part of a cadence*.
//!
//! ## Discriminators (all must hold)
//!
//! Per 16 ms STFT hop of the √Hann WOLA ([`crate::window::WolaAnalyzer`], the same analysis front end
//! the noise suppressor uses — no second spectral path):
//!
//! 1. **Energy gate** — the frame is above [`crate::EnergyVad`]'s threshold. Silence and comfort
//!    noise never reach the spectral tests.
//! 2. **Narrow-band concentration** — the three bins around the in-band spectral peak hold at least
//!    [`RecordToneParameters::minimum_concentration`] of the 200…3400 Hz band power. A tone puts
//!    ≈ 0.99 there (the √Hann analysis window is exactly the sine window `sin(πi/N)`, whose main lobe
//!    is three bins wide); speech, spread over harmonics and formants, puts far less.
//! 3. **No second tone** — the strongest bin more than two bins away from the peak must be at least
//!    [`RecordToneParameters::second_tone_reject_db`] below it. This is what excludes **DTMF**, which
//!    is dual-frequency with at most 8 dB of twist (ITU-T Q.23/Q.24), and any harmonic stack.
//! 4. **Frequency stability** — the parabolically interpolated peak frequency's peak-to-peak
//!    excursion across the run must stay inside [`RecordToneParameters::frequency_tolerance_hz`]. A
//!    vowel's formant, a glide and an instrument's vibrato all wander; a tone does not. It is a
//!    *range* test, not a per-hop step, because a slow drift has small steps and a large excursion.
//! 5. **Amplitude stability** — the run's peak-lobe level must stay inside
//!    [`RecordToneParameters::amplitude_tolerance_db`]. A tone's envelope is flat; speech is
//!    syllabically modulated, and two close tones (440+480 Hz ringback) beat.
//! 6. **Duration** — the run must last between [`RecordToneParameters::minimum_duration_ms`] and
//!    [`RecordToneParameters::maximum_duration_ms`]. Anything longer is a dial/hold tone or music.
//! 7. **Not cadenced** — the tone must be a *lone* burst: no other qualifying burst within
//!    [`RecordToneParameters::cadence_guard_ms`] either side. Ringback, busy, congestion and the
//!    three-segment special-information tone are all repeating, and the repeat is the discriminator.
//!
//! ## Timing, latency and determinism
//!
//! Everything is measured on a **logical sample clock** — the count of samples fed to
//! [`RecordToneDetector::process`] — never a wall clock, so the detector golden-tests
//! deterministically. One STFT hop is `N/2` samples, which is exactly **16 ms at both 8 kHz
//! (128/256) and 16 kHz (256/512)**, so all timing constants are rate-independent.
//!
//! Because rule 7 needs to see what *follows* the tone, the detection is reported
//! `cadence_guard_ms` after the tone ends, not when it ends. With the defaults that is ≈ 4.5 s. Lower
//! [`RecordToneParameters::cadence_guard_ms`] to trade cadence robustness for latency.
//!
//! ## Cost and allocation
//!
//! One forward real FFT per 16 ms hop plus an O(bins) scan — see the `beep_8k_20ms` / `beep_16k_20ms`
//! criterion benches. All state is preallocated in [`RecordToneDetector::new`]; `process` does **zero
//! heap allocation** per frame (proven by `tests/tone_detect_zero_alloc.rs`).

use crate::fft::Complex;
use crate::vad::EnergyVad;
use crate::window::WolaAnalyzer;
use crate::DspError;

/// 8 kHz narrowband: 20 ms frame / FFT size (hop `N/2` = 128 samples = 16 ms).
const NB_FRAME: usize = 160;
const NB_FFT: usize = 256;
/// 16 kHz wideband: 20 ms frame / FFT size (hop `N/2` = 256 samples = 16 ms).
const WB_FRAME: usize = 320;
const WB_FFT: usize = 512;

/// Milliseconds per STFT hop. `N/2` samples at `rate` is 16 ms for both supported rates, so every
/// duration in this module is an exact multiple of it and the two rates behave identically.
const HOP_MS: u32 = 16;

/// Low edge of the band the concentration ratio is measured over, in Hz. Below this sits mains hum,
/// rumble and handset thump — excluding it stops a noisy line depressing the ratio and hiding a real
/// tone, while the hum itself can never *be* the tone (it is below the search band and its harmonic
/// stack fails the second-tone test).
const ANALYSIS_LOW_HZ: f32 = 200.0;
/// High edge of the concentration band, in Hz — the telephony passband ceiling (ITU-T G.712). Fixing
/// it (rather than using Nyquist) makes the ratio identical at 8 and 16 kHz.
const ANALYSIS_HIGH_HZ: f32 = 3400.0;

/// Bins either side of the peak treated as part of its main lobe, and therefore excluded from the
/// second-tone search. The sine analysis window's main lobe is ±1.5 bins wide, so ±2 clears it while
/// leaving the first sidelobe (≈ −23 dB) inside the search — well below the reject threshold.
const LOBE_RADIUS: usize = 2;

/// Guard against `log10(0)` / division by zero on a digitally silent hop.
const POWER_EPSILON: f32 = 1e-12;

/// Tunable thresholds for [`RecordToneDetector`]. [`RecordToneParameters::default`] is the shipped
/// operating point; every field's rationale is on the field.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RecordToneParameters {
    /// Lowest tone frequency accepted, in Hz. Default **400** — below it lie mains hum harmonics and
    /// the 350/425 Hz dial-tone family; deployed record tones start around 400–440 Hz.
    pub minimum_frequency_hz: f32,
    /// Highest tone frequency accepted, in Hz. Default **2000** — above it lie the fax answer tone
    /// (2100 Hz) and modem signalling, and no deployed record tone sits there.
    pub maximum_frequency_hz: f32,
    /// Shortest accepted tone, in milliseconds. Default **120** — short enough that a 150–200 ms beep
    /// still clears the ±32 ms analysis-window quantisation, long enough that a single steady syllable
    /// nucleus or a signalling chirp cannot reach it.
    pub minimum_duration_ms: u32,
    /// Longest accepted tone, in milliseconds. Default **1000** — deployed record tones are 200–600 ms
    /// with a long tail to 1 s; past that it is a dial tone, a hold tone, or music, and the *upper*
    /// bound is what keeps a continuous tone from ever qualifying.
    pub maximum_duration_ms: u32,
    /// Minimum share of the 200…3400 Hz band power that must sit in the three bins around the peak.
    /// Default **0.60**: a clean tone scores ≈ 0.99 and the ratio degrades as `SNR/(SNR+1)`, so 0.60
    /// holds a tone down to roughly 2 dB in-band SNR while sitting far above what speech reaches.
    pub minimum_concentration: f32,
    /// Peak-to-peak excursion allowed in the interpolated peak frequency across a run, in Hz.
    /// Default **30** — just under one 31.25 Hz bin, which comfortably covers a clean tone's
    /// interpolation error even at low SNR while catching a formant glide or an instrument vibrato
    /// (±25 Hz at 880 Hz is a 50 Hz excursion). A *range* test rather than a per-hop step, because a
    /// slow drift has small steps and a large excursion.
    pub frequency_tolerance_hz: f32,
    /// Peak-to-peak level swing allowed across a run, in dB, ignoring its first hop (the onset ramp,
    /// where the analysis window straddles the tone edge). Default **5** — a real tone is flat to
    /// well under a dB, while a syllable swings by tens and two beating tones swing fully.
    pub amplitude_tolerance_db: f32,
    /// How far below the peak the strongest out-of-lobe bin must sit, in dB. Default **12** — DTMF
    /// carries at most 8 dB of twist (ITU-T Q.24), so 12 dB rejects every valid DTMF pair with margin,
    /// while a lone tone's own leakage is ≥ 23 dB down.
    pub second_tone_reject_db: f32,
    /// Quiet period, in milliseconds, that must surround a burst for it to count as a *lone* record
    /// tone. Default **4500** — longer than the 4 s silent interval of the slowest widely deployed
    /// ringback cadence, so no cadenced call-progress tone ever qualifies. This is also the detection
    /// latency: the event is reported this long after the tone ends.
    pub cadence_guard_ms: u32,
    /// Mean-square energy at or above which a 20 ms frame is considered active ([`EnergyVad`]).
    /// Default **20_000** ≈ −44 dBFS RMS: quiet enough to admit a faint beep, loud enough that
    /// silence and comfort noise never reach the spectral tests.
    pub energy_threshold: i64,
}

impl Default for RecordToneParameters {
    fn default() -> Self {
        Self {
            minimum_frequency_hz: 400.0,
            maximum_frequency_hz: 2000.0,
            minimum_duration_ms: 120,
            maximum_duration_ms: 1000,
            minimum_concentration: 0.60,
            frequency_tolerance_hz: 30.0,
            amplitude_tolerance_db: 5.0,
            second_tone_reject_db: 12.0,
            cadence_guard_ms: 4500,
            energy_threshold: 20_000,
        }
    }
}

impl RecordToneParameters {
    /// Reject a parameter set that cannot describe a detectable tone at `sample_rate_hz`.
    fn validate(&self, sample_rate_hz: u32) -> Result<(), DspError> {
        let nyquist = sample_rate_hz as f32 / 2.0;
        let reason = if self.minimum_frequency_hz <= 0.0
            || self.minimum_frequency_hz >= self.maximum_frequency_hz
        {
            Some("minimum_frequency_hz must be positive and below maximum_frequency_hz")
        } else if self.maximum_frequency_hz >= nyquist
            || self.minimum_frequency_hz < ANALYSIS_LOW_HZ
        {
            Some("the frequency window must lie inside 200 Hz .. Nyquist")
        } else if self.minimum_duration_ms == 0
            || self.minimum_duration_ms > self.maximum_duration_ms
        {
            Some("minimum_duration_ms must be non-zero and at most maximum_duration_ms")
        } else if self.minimum_concentration <= 0.0 || self.minimum_concentration > 1.0 {
            Some("minimum_concentration must lie in (0, 1]")
        } else if self.frequency_tolerance_hz < 0.0
            || self.amplitude_tolerance_db < 0.0
            || self.second_tone_reject_db < 0.0
        {
            Some("frequency / amplitude / second-tone tolerances must not be negative")
        } else {
            None
        };
        match reason {
            Some(reason) => Err(DspError::InvalidToneParameters { reason }),
            None => Ok(()),
        }
    }
}

/// A confirmed record tone.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ToneDetection {
    /// Interpolated tone frequency in Hz, averaged over the run (sub-bin accurate: the peak bin is
    /// refined by parabolic interpolation over its two neighbours' log powers).
    pub frequency_hz: f32,
    /// Tone length in milliseconds, counted in 16 ms STFT hops — accurate to about one analysis
    /// window (±32 ms).
    pub duration_ms: u32,
    /// Milliseconds of audio fed to the detector before the tone started, on its logical sample
    /// clock. The offset of the *tone*, not of this event: the event itself is reported
    /// [`RecordToneParameters::cadence_guard_ms`] after the tone ended.
    pub start_offset_ms: u64,
}

/// Why a tone-shaped run did not become a [`ToneDetection`]. Surfaced so an operator debugging a
/// false negative can see that the tone *was* heard and which rule dropped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToneRejection {
    /// The run was shorter than [`RecordToneParameters::minimum_duration_ms`].
    TooShort,
    /// The run was longer than [`RecordToneParameters::maximum_duration_ms`] — a dial/hold tone or
    /// music rather than a record tone.
    TooLong,
    /// Another qualifying burst fell inside [`RecordToneParameters::cadence_guard_ms`], so this is
    /// one burst of a cadence (ringback, busy, congestion, special-information tone).
    Cadenced,
}

/// What [`RecordToneDetector::process`] concluded about one frame.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ToneOutcome {
    /// No tone-shaped audio in flight.
    #[default]
    Idle,
    /// A stable tone is running but has not ended (or has ended and is inside the cadence guard).
    Tracking {
        /// Interpolated frequency of the run so far, in Hz.
        frequency_hz: f32,
        /// How long the run has lasted so far, in milliseconds.
        elapsed_ms: u32,
    },
    /// A tone-shaped run ended without qualifying.
    Rejected {
        /// Interpolated frequency of the rejected run, in Hz.
        frequency_hz: f32,
        /// Length of the rejected run, in milliseconds.
        duration_ms: u32,
        /// Which rule dropped it.
        reason: ToneRejection,
    },
    /// A record tone was confirmed. Fires **once** per tone — the run that produced it is closed
    /// before the outcome is returned, so a caller never sees the same tone twice.
    Detected(ToneDetection),
}

impl ToneOutcome {
    /// Ranking used to collapse several hops' outcomes into the one this frame reports: a terminal
    /// verdict always beats an in-progress one.
    fn priority(self) -> u8 {
        match self {
            ToneOutcome::Idle => 0,
            ToneOutcome::Tracking { .. } => 1,
            ToneOutcome::Rejected { .. } => 2,
            ToneOutcome::Detected(_) => 3,
        }
    }
}

/// A single-tone ("voicemail beep") detector over one decoded audio stream.
///
/// Feed it every decoded 20 ms frame of one direction with [`RecordToneDetector::process`]; it
/// returns [`ToneOutcome::Detected`] exactly once per qualifying tone. See the module docs for the
/// discriminators and the [`RecordToneParameters::cadence_guard_ms`] reporting latency.
#[derive(Debug, Clone)]
pub struct RecordToneDetector {
    sample_rate_hz: u32,
    frame_len: usize,
    /// STFT analysis (√Hann WOLA, forward FFT only) — shared front end with the noise suppressor.
    analyzer: WolaAnalyzer,
    /// Energy gate, so silence and comfort noise never reach the spectral tests. One frame of
    /// hangover covers the hop that straddles a frame boundary at a tone edge.
    vad: EnergyVad,
    /// Preallocated `i16 → f32` input scratch, exactly `frame_len` long — an oversized caller frame
    /// is fed to the STFT in `frame_len` blocks rather than growing this.
    frame_scratch: Vec<f32>,
    /// The per-hop discriminators and the run/cadence state machine.
    tracker: ToneTracker,
}

impl RecordToneDetector {
    /// Build a detector for `sample_rate_hz` with the default [`RecordToneParameters`].
    ///
    /// # Errors
    /// [`DspError::InvalidSampleRate`] for any rate other than 8000 or 16000 Hz.
    pub fn new(sample_rate_hz: u32) -> Result<Self, DspError> {
        Self::with_parameters(sample_rate_hz, RecordToneParameters::default())
    }

    /// Build a detector for `sample_rate_hz` with explicit thresholds.
    ///
    /// # Errors
    /// - [`DspError::InvalidSampleRate`] for any rate other than 8000 or 16000 Hz.
    /// - [`DspError::InvalidToneParameters`] if `parameters` cannot describe a detectable tone.
    pub fn with_parameters(
        sample_rate_hz: u32,
        parameters: RecordToneParameters,
    ) -> Result<Self, DspError> {
        let (frame_len, fft_size) = match sample_rate_hz {
            8_000 => (NB_FRAME, NB_FFT),
            16_000 => (WB_FRAME, WB_FFT),
            rate => return Err(DspError::InvalidSampleRate { rate }),
        };
        parameters.validate(sample_rate_hz)?;
        let analyzer = WolaAnalyzer::new(fft_size, frame_len)?;
        Ok(Self {
            sample_rate_hz,
            frame_len,
            analyzer,
            // One frame of hangover: the STFT hop that straddles a frame boundary at a tone edge is
            // still analysed, so a tone is not clipped by the frame grid.
            vad: EnergyVad::new(parameters.energy_threshold, 1),
            frame_scratch: vec![0.0; frame_len],
            tracker: ToneTracker::new(sample_rate_hz, fft_size, parameters),
        })
    }

    /// The native sample rate this detector was built for (Hz).
    #[inline]
    #[must_use]
    pub fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }

    /// Expected pipeline frame length in samples (160 @ 8 kHz, 320 @ 16 kHz). Any length is accepted;
    /// the STFT is sample-driven.
    #[inline]
    #[must_use]
    pub fn frame_len(&self) -> usize {
        self.frame_len
    }

    /// The thresholds this detector was built with.
    #[inline]
    #[must_use]
    pub fn parameters(&self) -> &RecordToneParameters {
        &self.tracker.parameters
    }

    /// Feed one frame of decoded PCM and get this frame's verdict.
    ///
    /// The frame is read, never modified — this is a detector, not a filter. Zero heap allocation on
    /// the steady path.
    pub fn process(&mut self, frame: &[i16]) -> ToneOutcome {
        let tracker = &mut self.tracker;
        tracker.outcome = ToneOutcome::Idle;
        // Energy gate first (rule 1): silence and comfort noise never reach the spectral tests. The
        // STFT is still fed so its history stays continuous — only the per-hop verdict is forced
        // "not a tone" while the gate is closed.
        tracker.energy_gate = self.vad.is_speech(frame);
        // Feed the STFT in blocks of at most `frame_len`, the quantum the analyzer's pending ring was
        // sized for. On the steady 20 ms path that is exactly one pass over the preallocated scratch;
        // an oversized caller block costs extra passes rather than a reallocation, so `process`
        // allocates nothing whatever length it is handed.
        for block in frame.chunks(self.frame_len) {
            let scratch = &mut self.frame_scratch[..block.len()];
            for (slot, &sample) in scratch.iter_mut().zip(block.iter()) {
                *slot = f32::from(sample);
            }
            self.analyzer
                .analyze_frame(scratch, |spectrum| tracker.on_hop(spectrum));
        }
        tracker.outcome
    }

    /// Reset all framing, run and cadence state (a stream discontinuity, or an explicit re-arm).
    pub fn reset(&mut self) {
        self.analyzer.reset();
        self.vad.reset();
        self.tracker.reset();
    }
}

/// The per-hop discriminators plus the run / cadence-guard state machine.
#[derive(Debug, Clone)]
struct ToneTracker {
    parameters: RecordToneParameters,
    /// Hz per FFT bin (31.25 at both supported rates).
    bin_hz: f32,
    /// Inclusive bin range the concentration ratio's denominator covers (≈ 200…3400 Hz).
    analysis_bins: (usize, usize),
    /// Inclusive bin range the peak is searched in (the configured frequency window), already inset
    /// so `peak ± 1` is always inside `analysis_bins`.
    search_bins: (usize, usize),
    /// Cadence guard expressed in whole hops (`cadence_guard_ms` rounded up).
    guard_hops: u64,
    /// Whether the current frame passed the energy gate.
    energy_gate: bool,
    /// Hops completed since construction — the logical sample clock, in 16 ms units.
    hops: u64,
    /// The run in progress, if any.
    run: Option<Run>,
    /// A qualifying detection waiting out the cadence guard.
    pending: Option<Pending>,
    /// Hop index at which the last cadence-relevant burst ended, if any.
    last_burst_end_hop: Option<u64>,
    /// This frame's collapsed verdict.
    outcome: ToneOutcome,
}

/// A run of consecutive hops that all looked like the same steady tone.
#[derive(Debug, Clone, Copy)]
struct Run {
    /// Hop index the run started at.
    start_hop: u64,
    /// Hops in the run so far.
    hops: u32,
    /// Lowest per-hop frequency estimate in the run.
    lowest_frequency_hz: f32,
    /// Highest per-hop frequency estimate in the run. `highest - lowest` is the run's frequency
    /// excursion — a *range* test, not a distance from the first hop, so a vibrato or a slow glide
    /// breaks the run even though no single hop-to-hop step is large.
    highest_frequency_hz: f32,
    /// Running sum of the per-hop frequency estimates, for the reported average.
    frequency_sum_hz: f32,
    /// Lowest level seen in the run, ignoring its first hop (the onset ramp).
    minimum_level_db: f32,
    /// Highest level seen in the run, ignoring its first hop.
    maximum_level_db: f32,
}

/// A qualifying burst held back until the cadence guard proves nothing follows it.
#[derive(Debug, Clone, Copy)]
struct Pending {
    detection: ToneDetection,
    /// Hop index the burst ended at; the detection fires `cadence_guard_ms` after this.
    end_hop: u64,
}

/// One hop's spectral measurement, once it has passed every per-hop rule.
#[derive(Debug, Clone, Copy)]
struct HopTone {
    frequency_hz: f32,
    level_db: f32,
}

impl ToneTracker {
    fn new(sample_rate_hz: u32, fft_size: usize, parameters: RecordToneParameters) -> Self {
        let bin_hz = sample_rate_hz as f32 / fft_size as f32;
        let last_bin = fft_size / 2;
        let bin_of = |hz: f32| -> usize {
            let bin = (hz / bin_hz).round();
            if bin <= 0.0 {
                0
            } else if bin as usize >= last_bin {
                last_bin
            } else {
                bin as usize
            }
        };
        // Concentration denominator: the telephony passband, identical in bins at 8 and 16 kHz.
        let analysis_low = bin_of(ANALYSIS_LOW_HZ).max(1);
        let analysis_high = bin_of(ANALYSIS_HIGH_HZ).max(analysis_low);
        // Peak search: the configured frequency window, inset by one bin at each end so the peak's
        // two neighbours (the interpolation and the 3-bin lobe) are always inside the analysis band.
        let search_low = bin_of(parameters.minimum_frequency_hz).max(analysis_low + 1);
        let search_high = bin_of(parameters.maximum_frequency_hz)
            .min(analysis_high.saturating_sub(1))
            .max(search_low);
        Self {
            bin_hz,
            analysis_bins: (analysis_low, analysis_high),
            search_bins: (search_low, search_high),
            guard_hops: u64::from(parameters.cadence_guard_ms.div_ceil(HOP_MS)),
            parameters,
            energy_gate: false,
            hops: 0,
            run: None,
            pending: None,
            last_burst_end_hop: None,
            outcome: ToneOutcome::Idle,
        }
    }

    fn reset(&mut self) {
        self.energy_gate = false;
        self.hops = 0;
        self.run = None;
        self.pending = None;
        self.last_burst_end_hop = None;
        self.outcome = ToneOutcome::Idle;
    }

    /// Fold `outcome` into this frame's verdict, keeping the highest-priority one.
    fn report(&mut self, outcome: ToneOutcome) {
        if outcome.priority() >= self.outcome.priority() {
            self.outcome = outcome;
        }
    }

    /// Advance the state machine by one STFT hop.
    fn on_hop(&mut self, spectrum: &[Complex]) {
        self.hops += 1;
        let tone = if self.energy_gate {
            self.measure(spectrum)
        } else {
            None
        };
        match tone {
            Some(tone) => self.extend_run(tone),
            None => self.end_run(),
        }
        self.expire_pending();
    }

    /// Per-hop rules 2–4: concentration, no second tone, and an in-window interpolated frequency.
    /// `None` when this hop is not a lone narrow-band tone.
    fn measure(&self, spectrum: &[Complex]) -> Option<HopTone> {
        let (analysis_low, analysis_high) = self.analysis_bins;
        let (search_low, search_high) = self.search_bins;
        if spectrum.len() <= analysis_high || search_low > search_high {
            return None;
        }

        // Peak of the search band.
        let mut peak_bin = search_low;
        let mut peak_power = 0.0f32;
        for (bin, value) in spectrum
            .iter()
            .enumerate()
            .take(search_high + 1)
            .skip(search_low)
        {
            let power = value.norm_squared();
            if power > peak_power {
                peak_power = power;
                peak_bin = bin;
            }
        }
        if peak_power <= POWER_EPSILON {
            return None;
        }
        // Analysis-band total (the concentration denominator) and the strongest out-of-lobe bin.
        let mut total_power = 0.0f32;
        let mut second_power = 0.0f32;
        for (bin, value) in spectrum
            .iter()
            .enumerate()
            .take(analysis_high + 1)
            .skip(analysis_low)
        {
            let power = value.norm_squared();
            total_power += power;
            if bin.abs_diff(peak_bin) > LOBE_RADIUS && power > second_power {
                second_power = power;
            }
        }
        if total_power <= POWER_EPSILON {
            return None;
        }

        // Rule 2: three-bin concentration. `peak_bin ± 1` is inside the analysis band by construction.
        let left_power = spectrum[peak_bin - 1].norm_squared();
        let right_power = spectrum[peak_bin + 1].norm_squared();
        let lobe_power = left_power + peak_power + right_power;
        if lobe_power / total_power < self.parameters.minimum_concentration {
            return None;
        }

        // Rule 3: reject a second tone (DTMF, a harmonic stack, two-tone ringback/busy).
        let second_below_db = 10.0 * (peak_power / second_power.max(POWER_EPSILON)).log10();
        if second_below_db < self.parameters.second_tone_reject_db {
            return None;
        }

        // Sub-bin frequency by parabolic interpolation on the log powers of the peak and its two
        // neighbours (the standard quadratic peak refinement). Clamped to ±½ bin — a larger excursion
        // means the parabola was ill-conditioned.
        let left = left_power.max(POWER_EPSILON).log10();
        let centre = peak_power.log10();
        let right = right_power.max(POWER_EPSILON).log10();
        let curvature = left - 2.0 * centre + right;
        let offset = if curvature.abs() > f32::EPSILON {
            (0.5 * (left - right) / curvature).clamp(-0.5, 0.5)
        } else {
            0.0
        };
        let frequency_hz = (peak_bin as f32 + offset) * self.bin_hz;
        // The configured window is bin-quantised (a bin covers ±½ bin), so the *interpolated*
        // estimate for a tone sitting exactly on an edge lands just outside it. Widen the check by
        // half a bin, or a tone at the configured minimum/maximum would never be detected at all.
        let half_bin = 0.5 * self.bin_hz;
        if frequency_hz < self.parameters.minimum_frequency_hz - half_bin
            || frequency_hz > self.parameters.maximum_frequency_hz + half_bin
        {
            return None;
        }

        Some(HopTone {
            frequency_hz,
            level_db: 10.0 * lobe_power.max(POWER_EPSILON).log10(),
        })
    }

    /// Rules 4–5 across hops: continue the run, or close it and start a fresh one on a step change.
    fn extend_run(&mut self, tone: HopTone) {
        let start = match self.run.as_mut() {
            None => true,
            Some(run) => {
                // Rule 4: the run's peak-to-peak frequency excursion.
                let lowest = run.lowest_frequency_hz.min(tone.frequency_hz);
                let highest = run.highest_frequency_hz.max(tone.frequency_hz);
                let frequency_step = highest - lowest > self.parameters.frequency_tolerance_hz;
                // Rule 5: the same, on level. The first hop of a run is the onset ramp (the analysis
                // window straddles the tone edge, so its level is low), which is why hop 2 re-seeds
                // the min/max below instead of folding hop 1's level in.
                let minimum = run.minimum_level_db.min(tone.level_db);
                let maximum = run.maximum_level_db.max(tone.level_db);
                let amplitude_step =
                    run.hops >= 2 && maximum - minimum > self.parameters.amplitude_tolerance_db;
                if frequency_step || amplitude_step {
                    true
                } else {
                    run.hops += 1;
                    run.frequency_sum_hz += tone.frequency_hz;
                    run.lowest_frequency_hz = lowest;
                    run.highest_frequency_hz = highest;
                    if run.hops == 2 {
                        run.minimum_level_db = tone.level_db;
                        run.maximum_level_db = tone.level_db;
                    } else {
                        run.minimum_level_db = minimum;
                        run.maximum_level_db = maximum;
                    }
                    false
                }
            }
        };
        if start {
            // A step change ends the run in progress (evaluating it) and opens a new one on this hop
            // — that is what splits the three segments of a special-information tone apart.
            self.end_run();
            self.run = Some(Run {
                start_hop: self.hops - 1,
                hops: 1,
                lowest_frequency_hz: tone.frequency_hz,
                highest_frequency_hz: tone.frequency_hz,
                frequency_sum_hz: tone.frequency_hz,
                minimum_level_db: tone.level_db,
                maximum_level_db: tone.level_db,
            });
        }
        if let Some(run) = self.run {
            self.report(ToneOutcome::Tracking {
                frequency_hz: run.frequency_sum_hz / run.hops as f32,
                elapsed_ms: run.hops * HOP_MS,
            });
        }
    }

    /// Close the run in progress (if any) and apply rules 6–7 to it.
    fn end_run(&mut self) {
        let Some(run) = self.run.take() else {
            return;
        };
        let duration_ms = run.hops * HOP_MS;
        let frequency_hz = run.frequency_sum_hz / run.hops as f32;
        if duration_ms < self.parameters.minimum_duration_ms {
            // Too short to be a record tone, and too short to be a cadence burst either — a blip does
            // not poison the guard for the real tone that may follow.
            self.report(ToneOutcome::Rejected {
                frequency_hz,
                duration_ms,
                reason: ToneRejection::TooShort,
            });
            return;
        }

        // Rule 7 (backward half): a burst that starts inside the guard of the previous burst is part
        // of a cadence. Withdraw any still-pending detection first — a burst landing inside its guard
        // is exactly the repeat the guard exists to catch.
        let cadenced = self
            .last_burst_end_hop
            .is_some_and(|end| run.start_hop.saturating_sub(end) <= self.guard_hops);
        if let Some(pending) = self.pending.take() {
            self.report(ToneOutcome::Rejected {
                frequency_hz: pending.detection.frequency_hz,
                duration_ms: pending.detection.duration_ms,
                reason: ToneRejection::Cadenced,
            });
        }
        // Every burst long enough to be part of a cadence re-arms the guard, including one rejected
        // for length — a 2 s ringback burst must still suppress the next burst of its own cadence.
        let end_hop = self.hops;
        self.last_burst_end_hop = Some(end_hop);

        if duration_ms > self.parameters.maximum_duration_ms {
            self.report(ToneOutcome::Rejected {
                frequency_hz,
                duration_ms,
                reason: ToneRejection::TooLong,
            });
            return;
        }
        if cadenced {
            self.report(ToneOutcome::Rejected {
                frequency_hz,
                duration_ms,
                reason: ToneRejection::Cadenced,
            });
            return;
        }
        // Qualifies on every rule but the forward half of rule 7 — hold it until the guard expires.
        self.pending = Some(Pending {
            detection: ToneDetection {
                frequency_hz,
                duration_ms,
                start_offset_ms: run.start_hop * u64::from(HOP_MS),
            },
            end_hop,
        });
    }

    /// Rule 7 (forward half): emit a held detection once the guard has passed with no further burst.
    fn expire_pending(&mut self) {
        let ready = self
            .pending
            .is_some_and(|pending| self.hops.saturating_sub(pending.end_hop) >= self.guard_hops);
        if ready {
            if let Some(pending) = self.pending.take() {
                self.report(ToneOutcome::Detected(pending.detection));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frame length for `rate` at the pipeline's 20 ms tick.
    fn frame_len(rate: u32) -> usize {
        (rate / 50) as usize
    }

    /// Append `duration_ms` of a single sine at `frequency_hz` and peak `amplitude`, phase-continuous
    /// from `phase` (radians, updated in place) so concatenated segments have no click.
    fn push_tone(
        into: &mut Vec<i16>,
        rate: u32,
        frequency_hz: f32,
        amplitude: f32,
        duration_ms: u32,
        phase: &mut f32,
    ) {
        let samples = (rate as u64 * u64::from(duration_ms) / 1000) as usize;
        let step = 2.0 * std::f32::consts::PI * frequency_hz / rate as f32;
        for _ in 0..samples {
            into.push((amplitude * phase.sin()) as i16);
            *phase += step;
        }
    }

    /// Append `duration_ms` of digital silence.
    fn push_silence(into: &mut Vec<i16>, rate: u32, duration_ms: u32) {
        let samples = (rate as u64 * u64::from(duration_ms) / 1000) as usize;
        into.extend(std::iter::repeat_n(0i16, samples));
    }

    /// Run `signal` through `detector` in 20 ms frames, returning every terminal outcome in order.
    fn run(detector: &mut RecordToneDetector, signal: &[i16]) -> Vec<ToneOutcome> {
        let length = frame_len(detector.sample_rate_hz());
        let mut outcomes = Vec::new();
        for frame in signal.chunks(length) {
            match detector.process(frame) {
                ToneOutcome::Idle | ToneOutcome::Tracking { .. } => {}
                terminal => outcomes.push(terminal),
            }
        }
        outcomes
    }

    fn detections(outcomes: &[ToneOutcome]) -> Vec<ToneDetection> {
        outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                ToneOutcome::Detected(detection) => Some(*detection),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn rejects_an_unsupported_sample_rate() {
        assert_eq!(
            RecordToneDetector::new(44_100).unwrap_err(),
            DspError::InvalidSampleRate { rate: 44_100 }
        );
    }

    #[test]
    fn accepts_both_telephony_rates() {
        for rate in [8_000u32, 16_000] {
            let detector = RecordToneDetector::new(rate).expect("build");
            assert_eq!(detector.sample_rate_hz(), rate);
            assert_eq!(detector.frame_len(), frame_len(rate));
            assert_eq!(detector.parameters().minimum_frequency_hz, 400.0);
        }
    }

    #[test]
    fn rejects_contradictory_parameters() {
        let cases = [
            RecordToneParameters {
                minimum_frequency_hz: 2000.0,
                maximum_frequency_hz: 400.0,
                ..Default::default()
            },
            RecordToneParameters {
                maximum_frequency_hz: 5000.0,
                ..Default::default()
            },
            RecordToneParameters {
                minimum_duration_ms: 900,
                maximum_duration_ms: 300,
                ..Default::default()
            },
            RecordToneParameters {
                minimum_duration_ms: 0,
                ..Default::default()
            },
            RecordToneParameters {
                minimum_concentration: 1.5,
                ..Default::default()
            },
            RecordToneParameters {
                frequency_tolerance_hz: -1.0,
                ..Default::default()
            },
        ];
        for parameters in cases {
            let error = RecordToneDetector::with_parameters(8_000, parameters)
                .expect_err("parameters must be rejected");
            assert!(
                matches!(error, DspError::InvalidToneParameters { .. }),
                "expected InvalidToneParameters, got {error:?}"
            );
            // The Display impl must name the offending constraint (operator-facing).
            assert!(error
                .to_string()
                .contains("invalid tone-detector parameters"));
        }
    }

    #[test]
    fn an_unsupported_rate_is_reported_before_the_parameters() {
        // Rate is the coarser failure, so it must win even with a bad parameter set.
        let parameters = RecordToneParameters {
            minimum_duration_ms: 0,
            ..Default::default()
        };
        assert_eq!(
            RecordToneDetector::with_parameters(48_000, parameters).unwrap_err(),
            DspError::InvalidSampleRate { rate: 48_000 }
        );
    }

    #[test]
    fn silence_never_fires() {
        for rate in [8_000u32, 16_000] {
            let mut detector = RecordToneDetector::new(rate).expect("build");
            let mut signal = Vec::new();
            push_silence(&mut signal, rate, 10_000);
            assert!(
                run(&mut detector, &signal).is_empty(),
                "{rate} Hz: silence produced a terminal outcome"
            );
        }
    }

    #[test]
    fn detects_a_lone_record_tone_at_both_rates() {
        for rate in [8_000u32, 16_000] {
            let mut detector = RecordToneDetector::new(rate).expect("build");
            let mut phase = 0.0;
            let mut signal = Vec::new();
            push_silence(&mut signal, rate, 500);
            push_tone(&mut signal, rate, 1400.0, 8000.0, 400, &mut phase);
            push_silence(&mut signal, rate, 6000);

            let found = detections(&run(&mut detector, &signal));
            assert_eq!(found.len(), 1, "{rate} Hz: expected exactly one detection");
            let detection = found[0];
            assert!(
                (detection.frequency_hz - 1400.0).abs() < 15.0,
                "{rate} Hz: reported {} Hz, expected ≈1400",
                detection.frequency_hz
            );
            assert!(
                detection.duration_ms.abs_diff(400) <= 48,
                "{rate} Hz: reported {} ms, expected ≈400",
                detection.duration_ms
            );
            // The tone starts at 500 ms; the run may open one window early or late.
            assert!(
                detection.start_offset_ms.abs_diff(500) <= 48,
                "{rate} Hz: reported offset {} ms, expected ≈500",
                detection.start_offset_ms
            );
        }
    }

    #[test]
    fn fires_once_per_tone_not_once_per_frame() {
        let rate = 8_000;
        let mut detector = RecordToneDetector::new(rate).expect("build");
        let mut phase = 0.0;
        let mut signal = Vec::new();
        push_silence(&mut signal, rate, 200);
        push_tone(&mut signal, rate, 1000.0, 8000.0, 500, &mut phase);
        push_silence(&mut signal, rate, 8000);
        assert_eq!(detections(&run(&mut detector, &signal)).len(), 1);
    }

    #[test]
    fn a_continuous_tone_is_rejected_as_too_long() {
        let rate = 8_000;
        let mut detector = RecordToneDetector::new(rate).expect("build");
        let mut phase = 0.0;
        let mut signal = Vec::new();
        push_silence(&mut signal, rate, 200);
        // 5 s of a continuous 425 Hz dial tone — well past `maximum_duration_ms`.
        push_tone(&mut signal, rate, 425.0, 8000.0, 5000, &mut phase);
        push_silence(&mut signal, rate, 6000);

        let outcomes = run(&mut detector, &signal);
        assert!(detections(&outcomes).is_empty(), "dial tone must not fire");
        assert!(
            outcomes.iter().any(|outcome| matches!(
                outcome,
                ToneOutcome::Rejected {
                    reason: ToneRejection::TooLong,
                    ..
                }
            )),
            "expected a TooLong rejection, got {outcomes:?}"
        );
    }

    #[test]
    fn a_tone_shorter_than_the_minimum_is_rejected() {
        let rate = 8_000;
        let mut detector = RecordToneDetector::new(rate).expect("build");
        let mut phase = 0.0;
        let mut signal = Vec::new();
        push_silence(&mut signal, rate, 200);
        push_tone(&mut signal, rate, 1000.0, 8000.0, 40, &mut phase);
        push_silence(&mut signal, rate, 6000);

        let outcomes = run(&mut detector, &signal);
        assert!(detections(&outcomes).is_empty(), "40 ms blip must not fire");
        assert!(
            outcomes.iter().any(|outcome| matches!(
                outcome,
                ToneOutcome::Rejected {
                    reason: ToneRejection::TooShort,
                    ..
                }
            )),
            "expected a TooShort rejection, got {outcomes:?}"
        );
    }

    #[test]
    fn a_cadenced_burst_train_never_fires() {
        // Single-frequency busy tone: 425 Hz, 500 ms on / 500 ms off, ten cycles.
        let rate = 8_000;
        let mut detector = RecordToneDetector::new(rate).expect("build");
        let mut phase = 0.0;
        let mut signal = Vec::new();
        push_silence(&mut signal, rate, 200);
        for _ in 0..10 {
            push_tone(&mut signal, rate, 425.0, 8000.0, 500, &mut phase);
            push_silence(&mut signal, rate, 500);
        }
        push_silence(&mut signal, rate, 8000);

        let outcomes = run(&mut detector, &signal);
        assert!(
            detections(&outcomes).is_empty(),
            "a cadenced busy tone must never read as a record tone: {outcomes:?}"
        );
        assert!(
            outcomes.iter().any(|outcome| matches!(
                outcome,
                ToneOutcome::Rejected {
                    reason: ToneRejection::Cadenced,
                    ..
                }
            )),
            "expected a Cadenced rejection, got {outcomes:?}"
        );
    }

    #[test]
    fn a_dual_tone_is_rejected_even_when_steady() {
        // DTMF "1" (ITU-T Q.23: 697 + 1209 Hz, equal level), held far longer than any real key press.
        let rate = 8_000;
        let mut detector = RecordToneDetector::new(rate).expect("build");
        let samples = rate as usize / 2; // 500 ms
        let mut signal = vec![0i16; rate as usize / 5]; // 200 ms of lead-in silence
        for index in 0..samples {
            let time = index as f32 / rate as f32;
            let low = (2.0 * std::f32::consts::PI * 697.0 * time).sin();
            let high = (2.0 * std::f32::consts::PI * 1209.0 * time).sin();
            signal.push((4000.0 * (low + high)) as i16);
        }
        push_silence(&mut signal, rate, 8000);

        assert!(
            detections(&run(&mut detector, &signal)).is_empty(),
            "a DTMF pair must never read as a record tone"
        );
    }

    #[test]
    fn tracking_reports_the_running_frequency_before_the_tone_ends() {
        let rate = 8_000;
        let mut detector = RecordToneDetector::new(rate).expect("build");
        let mut phase = 0.0;
        let mut signal = Vec::new();
        push_silence(&mut signal, rate, 200);
        push_tone(&mut signal, rate, 950.0, 8000.0, 400, &mut phase);

        let mut tracked = None;
        for frame in signal.chunks(frame_len(rate)) {
            if let ToneOutcome::Tracking {
                frequency_hz,
                elapsed_ms,
            } = detector.process(frame)
            {
                tracked = Some((frequency_hz, elapsed_ms));
            }
        }
        let (frequency_hz, elapsed_ms) = tracked.expect("the tone must be tracked while it runs");
        assert!(
            (frequency_hz - 950.0).abs() < 15.0,
            "tracked {frequency_hz} Hz, expected ≈950"
        );
        assert!(
            elapsed_ms >= 300,
            "tracked only {elapsed_ms} ms of a 400 ms tone"
        );
    }

    #[test]
    fn reset_clears_the_cadence_memory_and_the_pending_detection() {
        let rate = 8_000;
        let mut detector = RecordToneDetector::new(rate).expect("build");
        let mut phase = 0.0;
        let mut tone = Vec::new();
        push_tone(&mut tone, rate, 1000.0, 8000.0, 400, &mut phase);

        // A tone, then a reset before the guard expires: the pending detection is discarded.
        assert!(detections(&run(&mut detector, &tone)).is_empty());
        detector.reset();
        let mut tail = Vec::new();
        push_silence(&mut tail, rate, 8000);
        assert!(
            detections(&run(&mut detector, &tail)).is_empty(),
            "reset must discard the pending detection"
        );

        // And the cadence memory is gone too: the very next tone fires as a lone burst.
        let mut second = Vec::new();
        push_silence(&mut second, rate, 200);
        push_tone(&mut second, rate, 1000.0, 8000.0, 400, &mut phase);
        push_silence(&mut second, rate, 8000);
        assert_eq!(detections(&run(&mut detector, &second)).len(), 1);
    }

    #[test]
    fn a_shorter_cadence_guard_shortens_the_reporting_latency() {
        // The guard is the detection latency; a caller may trade cadence robustness for it.
        let rate = 8_000;
        let parameters = RecordToneParameters {
            cadence_guard_ms: 320,
            ..Default::default()
        };
        let mut detector = RecordToneDetector::with_parameters(rate, parameters).expect("build");
        let mut phase = 0.0;
        let mut signal = Vec::new();
        push_silence(&mut signal, rate, 200);
        push_tone(&mut signal, rate, 1000.0, 8000.0, 300, &mut phase);
        push_silence(&mut signal, rate, 1000);

        let length = frame_len(rate);
        let mut fired_at_frame = None;
        for (index, frame) in signal.chunks(length).enumerate() {
            if let ToneOutcome::Detected(_) = detector.process(frame) {
                fired_at_frame = Some(index);
            }
        }
        let index = fired_at_frame.expect("must fire with the short guard");
        // Tone ends at 500 ms (frame 25); the guard adds 320 ms (16 frames), so ≈ frame 41.
        assert!(
            (39..=45).contains(&index),
            "fired at frame {index}, expected ≈41 (tone end + a 320 ms guard)"
        );
    }

    #[test]
    fn an_oversized_frame_is_handled_without_panicking() {
        // The STFT is sample-driven; a caller handing in a 100 ms block must still work.
        let rate = 8_000;
        let mut detector = RecordToneDetector::new(rate).expect("build");
        let mut phase = 0.0;
        let mut signal = Vec::new();
        push_silence(&mut signal, rate, 200);
        push_tone(&mut signal, rate, 1000.0, 8000.0, 400, &mut phase);
        push_silence(&mut signal, rate, 8000);

        let mut found = 0;
        for frame in signal.chunks(800) {
            if let ToneOutcome::Detected(_) = detector.process(frame) {
                found += 1;
            }
        }
        assert_eq!(found, 1, "a 100 ms block must still yield one detection");
    }

    #[test]
    fn an_empty_frame_is_inert() {
        let mut detector = RecordToneDetector::new(8_000).expect("build");
        assert_eq!(detector.process(&[]), ToneOutcome::Idle);
    }

    #[test]
    fn outcome_priority_keeps_a_detection_over_an_in_progress_run() {
        // The per-frame fold must never drop a terminal verdict in favour of a later `Tracking`.
        let detection = ToneDetection {
            frequency_hz: 1000.0,
            duration_ms: 320,
            start_offset_ms: 0,
        };
        assert!(
            ToneOutcome::Detected(detection).priority()
                > ToneOutcome::Rejected {
                    frequency_hz: 1000.0,
                    duration_ms: 320,
                    reason: ToneRejection::Cadenced,
                }
                .priority()
        );
        assert!(
            ToneOutcome::Rejected {
                frequency_hz: 1000.0,
                duration_ms: 320,
                reason: ToneRejection::TooShort,
            }
            .priority()
                > ToneOutcome::Tracking {
                    frequency_hz: 1000.0,
                    elapsed_ms: 32,
                }
                .priority()
        );
        assert!(
            ToneOutcome::Tracking {
                frequency_hz: 1000.0,
                elapsed_ms: 32,
            }
            .priority()
                > ToneOutcome::default().priority()
        );
        assert_eq!(ToneOutcome::default(), ToneOutcome::Idle);
    }

    #[test]
    fn debug_renders_every_public_type() {
        // These land in operator-facing `tracing` fields, so their `Debug` must be meaningful.
        let detection = ToneDetection {
            frequency_hz: 1400.0,
            duration_ms: 496,
            start_offset_ms: 2048,
        };
        assert!(format!("{detection:?}").contains("1400"));
        assert!(format!("{:?}", ToneRejection::Cadenced).contains("Cadenced"));
        assert!(format!("{:?}", ToneOutcome::Detected(detection)).contains("Detected"));
        assert!(format!("{:?}", RecordToneParameters::default()).contains("cadence_guard_ms"));
    }
}
