//! Synthetic call-progress tone generation — ringback, busy, congestion, dial and call-waiting —
//! so a controller can play call-progress audio without shipping and provisioning WAV files.
//!
//! A tone is a [`ToneSpec`]: an ordered list of [`ToneSegment`]s (a set of simultaneous
//! frequencies held for a duration; zero frequencies means silence) plus a repeat count. The spec
//! is either looked up from the [`TonePreset`] table — whose frequencies and cadences are taken
//! from the standards cited on each entry — or written out by an operator in the cadence grammar
//! [`ToneSpec::parse`] accepts.
//!
//! # Cadence grammar
//!
//! ```text
//! tone        = spec / preset-name
//! spec        = segment *( "," segment ) [ "*" repeat ]
//! segment     = components "/" duration
//! components  = component *( "+" component )
//! component   = 1*DIGIT           ; frequency in Hz, 1..=4000; a single "0" means silence
//! duration    = 1*DIGIT           ; segment length in ms, 1..=60000
//! repeat      = 1*DIGIT / "inf"   ; whole-spec cycles, default 1; "inf" plays until stopped
//! ```
//!
//! ASCII whitespace around any token is ignored. A string containing `/` is a cadence spec; any
//! other string is a preset name ([`TonePreset::from_name`]) — the two can never collide because
//! no preset name contains `/` and no spec is valid without one.
//!
//! Examples:
//!
//! - `425/1000,0/4000*inf` — 425 Hz for 1 s, silence for 4 s, forever (the European ringing
//!   cadence).
//! - `440+480/2000,0/4000*3` — a dual-frequency burst repeated three times.
//! - `425/1000*inf` — a continuous 425 Hz tone (back-to-back 1 s segments, no gap).
//!
//! # Synthesis
//!
//! [`ToneGenerator`] renders directly at the egress sample rate — a synthesised source never needs
//! resampling — one frame at a time into a caller-owned buffer, with **zero heap allocation** on
//! the per-frame path. Each component is a 32-bit phase accumulator (exact frequency to within
//! `rate / 2^32` Hz) evaluated through a folded odd-power sine polynomial; components are summed
//! in `i32` and saturated to `i16`, the same accumulate-then-saturate discipline as
//! [`crate::mixer::Mixer`].

/// Maximum simultaneous frequency components in one segment. Every standard call-progress tone is
/// single- or dual-frequency; three leaves room for a national three-tone variant without making
/// the per-sample loop unbounded.
pub const MAX_TONE_COMPONENTS: usize = 3;

/// Maximum segments in one tone spec. The longest cadence in the preset table is four segments
/// (the UK double ring); eight is twice that.
pub const MAX_TONE_SEGMENTS: usize = 8;

/// Highest frequency a component may name, in Hz. Above 4 kHz nothing survives the narrowband
/// telephone path, and a component at or above Nyquist would alias into an audible artefact.
pub const MAX_TONE_FREQUENCY_HZ: u32 = 4_000;

/// Longest a single segment may last, in milliseconds (one minute).
pub const MAX_TONE_SEGMENT_MS: u32 = 60_000;

/// Nominal send level of **each** frequency component, in dBm0.
///
/// ITU-T E.180/Q.35 (03/98) §2 puts the nominal level of a call-progress tone at **−10 dBm0**
/// (recommended limits −5 to −15 dBm0, measured with a continuous tone). Two equal components sum
/// 3 dB hotter than either alone, so −13 dBm0 **per component** lands a dual-frequency tone exactly
/// on that −10 dBm0 nominal; a single-frequency tone then sits 3 dB below nominal, inside the
/// recommended band and on the safe side of §2's warning against tones above −10 dBm at the 2-wire
/// access.
///
/// A note in the same clause gives −8 to −3 dBm0 as the preferred range for a *digital* tone
/// generator. We deliberately stay at the −10 dBm0 combined nominal rather than that hotter band:
/// an overlay tone is mixed **under** live speech, and the mix has to keep headroom for both.
pub const TONE_COMPONENT_LEVEL_DBM0: f64 = -13.0;

/// The G.711 overload point in dBm0 — the level of a sine at digital full scale.
///
/// dBm0 is a line-level unit; the number that ties it to a 16-bit linear sample is the codec's
/// overload point, and ITU-T G.711 puts the A-law/µ-law overload at **+3.14 dBm0**. So a 0 dBm0
/// sine peaks at `32768 / 10^(3.14/20)` ≈ 22826, and everything else scales from there.
// Not π: +3.14 dBm0 is G.711's overload point, and the resemblance is a coincidence.
#[allow(clippy::approx_constant)]
pub const G711_OVERLOAD_DBM0: f64 = 3.14;

/// Peak amplitude of one component, in 16-bit linear PCM.
///
/// `A = 32768 · 10^((L − `[`G711_OVERLOAD_DBM0`]`) / 20)`. At
/// `L` = [`TONE_COMPONENT_LEVEL_DBM0`] that is 5110, so a dual-frequency tone peaks at 10220 —
/// 10 dB of headroom before the renderer's saturation is ever reached. Spelled as a constant
/// because `powf` is not `const`; `tone_amplitude_matches_the_declared_level` recomputes it from
/// the declared level and fails if the two ever drift apart.
pub const TONE_COMPONENT_AMPLITUDE: i32 = 5_110;

/// Errors from [`ToneSpec::parse`] and [`TonePreset::from_name`] — every malformed control-plane
/// tone string resolves to one of these, never a panic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ToneSpecError {
    /// The spec was empty after trimming whitespace.
    #[error("empty tone spec")]
    Empty,
    /// More than [`MAX_TONE_SEGMENTS`] comma-separated segments.
    #[error("too many tone segments (limit {limit})")]
    TooManySegments {
        /// The accepted maximum.
        limit: usize,
    },
    /// More than [`MAX_TONE_COMPONENTS`] `+`-separated frequencies in one segment.
    #[error("segment {segment}: too many frequency components (limit {limit})")]
    TooManyComponents {
        /// Zero-based segment index.
        segment: usize,
        /// The accepted maximum.
        limit: usize,
    },
    /// A segment carried no `/<duration_ms>`.
    #[error("segment {segment}: missing '/<duration_ms>'")]
    MissingDuration {
        /// Zero-based segment index.
        segment: usize,
    },
    /// A frequency component was not a decimal integer.
    #[error("segment {segment}: frequency is not a decimal integer")]
    BadFrequency {
        /// Zero-based segment index.
        segment: usize,
    },
    /// A frequency component was above [`MAX_TONE_FREQUENCY_HZ`] (`0` alone means silence).
    #[error("segment {segment}: frequency {frequency} Hz out of range (1..={limit})")]
    FrequencyOutOfRange {
        /// Zero-based segment index.
        segment: usize,
        /// The rejected frequency.
        frequency: u64,
        /// The accepted maximum.
        limit: u32,
    },
    /// A silent segment (`0`) also named a real frequency — `0+425` is a contradiction.
    #[error("segment {segment}: silence (0) cannot be combined with a frequency")]
    SilenceWithFrequency {
        /// Zero-based segment index.
        segment: usize,
    },
    /// A segment duration was not a decimal integer.
    #[error("segment {segment}: duration is not a decimal integer")]
    BadDuration {
        /// Zero-based segment index.
        segment: usize,
    },
    /// A segment duration was outside `1..=`[`MAX_TONE_SEGMENT_MS`].
    #[error("segment {segment}: duration {duration} ms out of range (1..={limit})")]
    DurationOutOfRange {
        /// Zero-based segment index.
        segment: usize,
        /// The rejected duration.
        duration: u64,
        /// The accepted maximum.
        limit: u32,
    },
    /// The `*repeat` suffix was neither a decimal integer nor `inf`.
    #[error("repeat is neither a decimal integer nor 'inf'")]
    BadRepeat,
    /// `*0` — a tone that plays zero cycles is not a tone.
    #[error("repeat count 0 does not play")]
    ZeroRepeat,
    /// The string named no known [`TonePreset`] (and, having no `/`, was not a cadence spec).
    #[error("unknown tone preset")]
    UnknownPreset,
}

/// One step of a cadence: up to [`MAX_TONE_COMPONENTS`] simultaneous frequencies held for
/// `duration_ms`. Zero components is a silent step (the "off" half of a cadence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToneSegment {
    frequencies_hz: [u16; MAX_TONE_COMPONENTS],
    component_count: u8,
    duration_ms: u32,
}

impl ToneSegment {
    /// A silent segment of `duration_ms`.
    #[must_use]
    pub const fn silence(duration_ms: u32) -> Self {
        Self {
            frequencies_hz: [0; MAX_TONE_COMPONENTS],
            component_count: 0,
            duration_ms,
        }
    }

    /// A single-frequency segment.
    #[must_use]
    pub const fn single(frequency_hz: u16, duration_ms: u32) -> Self {
        Self {
            frequencies_hz: [frequency_hz, 0, 0],
            component_count: 1,
            duration_ms,
        }
    }

    /// A two-frequency segment; the components are summed and saturated.
    #[must_use]
    pub const fn dual(first_hz: u16, second_hz: u16, duration_ms: u32) -> Self {
        Self {
            frequencies_hz: [first_hz, second_hz, 0],
            component_count: 2,
            duration_ms,
        }
    }

    /// The frequencies sounding during this segment (empty ⇒ silence).
    #[must_use]
    pub fn frequencies_hz(&self) -> &[u16] {
        &self.frequencies_hz[..self.component_count as usize]
    }

    /// How long this segment lasts, in milliseconds.
    #[must_use]
    pub const fn duration_ms(&self) -> u32 {
        self.duration_ms
    }
}

/// How many times a [`ToneSpec`]'s segment list plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToneRepeat {
    /// A fixed number of cycles (always ≥ 1).
    Times(u32),
    /// Endless — the tone plays until it is stopped, or until the playback's duration cap expires.
    Forever,
}

/// A complete tone: an ordered cadence of [`ToneSegment`]s plus how many times it cycles.
///
/// Fixed-capacity by construction (no heap), so a [`ToneGenerator`] built from one allocates
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToneSpec {
    segments: [ToneSegment; MAX_TONE_SEGMENTS],
    segment_count: u8,
    repeat: ToneRepeat,
}

impl ToneSpec {
    /// Build a spec from an explicit segment list. Returns [`ToneSpecError::Empty`] for no
    /// segments and [`ToneSpecError::TooManySegments`] beyond [`MAX_TONE_SEGMENTS`].
    pub fn new(segments: &[ToneSegment], repeat: ToneRepeat) -> Result<Self, ToneSpecError> {
        if segments.is_empty() {
            return Err(ToneSpecError::Empty);
        }
        if segments.len() > MAX_TONE_SEGMENTS {
            return Err(ToneSpecError::TooManySegments {
                limit: MAX_TONE_SEGMENTS,
            });
        }
        let mut stored = [ToneSegment::silence(0); MAX_TONE_SEGMENTS];
        stored[..segments.len()].copy_from_slice(segments);
        Ok(Self {
            segments: stored,
            segment_count: segments.len() as u8,
            repeat,
        })
    }

    /// Resolve a control-plane tone string: a cadence spec when it contains `/`, else a preset
    /// name. See the module documentation for the grammar and the preset table.
    pub fn resolve(tone: &str) -> Result<Self, ToneSpecError> {
        if tone.contains('/') {
            Self::parse(tone)
        } else {
            TonePreset::from_name(tone.trim()).map(TonePreset::spec)
        }
    }

    /// Parse a cadence spec (the grammar in the module documentation). Never panics: every
    /// malformed input returns a [`ToneSpecError`] naming the offending segment.
    pub fn parse(spec: &str) -> Result<Self, ToneSpecError> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(ToneSpecError::Empty);
        }
        // Split the optional `*repeat` suffix off the tail first, so a stray `*` inside a segment
        // is a parse error on that segment rather than being silently swallowed.
        let (body, repeat) = match spec.split_once('*') {
            Some((body, tail)) => {
                let tail = tail.trim();
                let repeat = if tail.eq_ignore_ascii_case("inf") {
                    ToneRepeat::Forever
                } else {
                    let times: u32 = tail.parse().map_err(|_| ToneSpecError::BadRepeat)?;
                    if times == 0 {
                        return Err(ToneSpecError::ZeroRepeat);
                    }
                    ToneRepeat::Times(times)
                };
                (body, repeat)
            }
            None => (spec, ToneRepeat::Times(1)),
        };

        let mut segments = [ToneSegment::silence(0); MAX_TONE_SEGMENTS];
        let mut count = 0usize;
        for (index, raw) in body.split(',').enumerate() {
            if count == MAX_TONE_SEGMENTS {
                return Err(ToneSpecError::TooManySegments {
                    limit: MAX_TONE_SEGMENTS,
                });
            }
            segments[count] = parse_segment(raw, index)?;
            count += 1;
        }
        if count == 0 {
            return Err(ToneSpecError::Empty);
        }
        Ok(Self {
            segments,
            segment_count: count as u8,
            repeat,
        })
    }

    /// The cadence's segments, in order.
    #[must_use]
    pub fn segments(&self) -> &[ToneSegment] {
        &self.segments[..self.segment_count as usize]
    }

    /// How many times the cadence cycles.
    #[must_use]
    pub const fn repeat(&self) -> ToneRepeat {
        self.repeat
    }

    /// Total playout duration in milliseconds, or `None` for an endless tone.
    #[must_use]
    pub fn total_duration_ms(&self) -> Option<u64> {
        let cycle: u64 = self
            .segments()
            .iter()
            .map(|segment| u64::from(segment.duration_ms))
            .sum();
        match self.repeat {
            ToneRepeat::Times(times) => Some(cycle * u64::from(times)),
            ToneRepeat::Forever => None,
        }
    }
}

/// Parse one `components/duration` segment; `index` is used only for error reporting.
fn parse_segment(raw: &str, index: usize) -> Result<ToneSegment, ToneSpecError> {
    let raw = raw.trim();
    let Some((components, duration)) = raw.split_once('/') else {
        return Err(ToneSpecError::MissingDuration { segment: index });
    };

    let duration_ms: u64 = duration
        .trim()
        .parse()
        .map_err(|_| ToneSpecError::BadDuration { segment: index })?;
    if duration_ms == 0 || duration_ms > u64::from(MAX_TONE_SEGMENT_MS) {
        return Err(ToneSpecError::DurationOutOfRange {
            segment: index,
            duration: duration_ms,
            limit: MAX_TONE_SEGMENT_MS,
        });
    }

    let mut frequencies_hz = [0u16; MAX_TONE_COMPONENTS];
    let mut component_count = 0usize;
    let mut silent = false;
    for component in components.split('+') {
        let frequency: u64 = component
            .trim()
            .parse()
            .map_err(|_| ToneSpecError::BadFrequency { segment: index })?;
        if frequency == 0 {
            silent = true;
            continue;
        }
        if frequency > u64::from(MAX_TONE_FREQUENCY_HZ) {
            return Err(ToneSpecError::FrequencyOutOfRange {
                segment: index,
                frequency,
                limit: MAX_TONE_FREQUENCY_HZ,
            });
        }
        if component_count == MAX_TONE_COMPONENTS {
            return Err(ToneSpecError::TooManyComponents {
                segment: index,
                limit: MAX_TONE_COMPONENTS,
            });
        }
        frequencies_hz[component_count] = frequency as u16;
        component_count += 1;
    }
    if silent && component_count > 0 {
        return Err(ToneSpecError::SilenceWithFrequency { segment: index });
    }
    Ok(ToneSegment {
        frequencies_hz,
        component_count: component_count as u8,
        duration_ms: duration_ms as u32,
    })
}

/// Renders a [`ToneSpec`] as 16-bit linear PCM at a fixed sample rate.
///
/// Stateful and incremental: one frame per [`ToneGenerator::next_frame`] call into a caller-owned
/// buffer, with no heap allocation and no precomputed rendering of the whole tone. Each component
/// is a 32-bit phase accumulator, restarted at zero on every segment boundary so a burst always
/// begins at a zero crossing (no click at the cadence edge).
#[derive(Debug, Clone)]
pub struct ToneGenerator {
    spec: ToneSpec,
    sample_rate_hz: u32,
    /// Q32 phase, one per component of the current segment.
    phase: [u32; MAX_TONE_COMPONENTS],
    /// Q32 phase increment per sample, one per component of the current segment.
    increment: [u32; MAX_TONE_COMPONENTS],
    component_count: usize,
    segment_index: usize,
    /// Samples still to emit in the current segment.
    samples_left: u64,
    /// Completed cycles of the whole cadence.
    cycles_done: u32,
    exhausted: bool,
}

impl ToneGenerator {
    /// Build a generator rendering `spec` at `sample_rate_hz`.
    ///
    /// A zero sample rate yields an immediately-exhausted generator rather than an error — there
    /// is no clock to render against.
    #[must_use]
    pub fn new(spec: ToneSpec, sample_rate_hz: u32) -> Self {
        let mut generator = Self {
            spec,
            sample_rate_hz,
            phase: [0; MAX_TONE_COMPONENTS],
            increment: [0; MAX_TONE_COMPONENTS],
            component_count: 0,
            segment_index: 0,
            samples_left: 0,
            cycles_done: 0,
            exhausted: sample_rate_hz == 0 || spec.segments().is_empty(),
        };
        if !generator.exhausted {
            generator.enter_segment(0);
        }
        generator
    }

    /// The sample rate the generator renders at (the leg's egress rate — a tone is never
    /// resampled).
    #[must_use]
    pub const fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }

    /// Total playout duration in milliseconds, or `None` for an endless tone.
    #[must_use]
    pub fn total_duration_ms(&self) -> Option<u64> {
        self.spec.total_duration_ms()
    }

    /// Whether the generator has produced its last frame and will only yield `None` from now on.
    /// Always `false` for an endless (`*inf`) tone.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Point the accumulators at segment `index`, restarting each component's phase at zero.
    fn enter_segment(&mut self, index: usize) {
        let segment = self.spec.segments()[index];
        self.segment_index = index;
        self.component_count = segment.component_count as usize;
        for slot in 0..self.component_count {
            self.phase[slot] = 0;
            // Q32 phase step: frequency / rate turns per sample, scaled by 2^32. u64 arithmetic
            // keeps it exact to within one 2^-32 turn, so the rendered frequency error is under
            // rate / 2^32 Hz (sub-microhertz at any telephony rate).
            self.increment[slot] = ((u64::from(segment.frequencies_hz[slot]) << 32)
                / u64::from(self.sample_rate_hz)) as u32;
        }
        self.samples_left =
            (u64::from(segment.duration_ms) * u64::from(self.sample_rate_hz)).div_ceil(1000);
    }

    /// Advance to the next segment (wrapping to the start of the cadence and counting a cycle),
    /// marking the generator exhausted when the repeat count runs out.
    fn advance_segment(&mut self) {
        let next = self.segment_index + 1;
        if next < self.spec.segments().len() {
            self.enter_segment(next);
            return;
        }
        self.cycles_done = self.cycles_done.saturating_add(1);
        if let ToneRepeat::Times(times) = self.spec.repeat() {
            if self.cycles_done >= times {
                self.exhausted = true;
                return;
            }
        }
        self.enter_segment(0);
    }

    /// Render the next frame into `out`, returning the number of samples written, or `None` when
    /// the tone has finished. A short final frame is zero-padded to `out.len()` and the returned
    /// count reflects only the real samples — the same contract as
    /// [`crate::player::PcmPlayer::next_frame`].
    pub fn next_frame(&mut self, out: &mut [i16]) -> Option<usize> {
        if out.is_empty() || self.exhausted {
            return None;
        }
        let mut written = 0usize;
        while written < out.len() && !self.exhausted {
            if self.samples_left == 0 {
                self.advance_segment();
                continue;
            }
            let take = (out.len() - written).min(self.samples_left as usize);
            self.render(&mut out[written..written + take]);
            self.samples_left -= take as u64;
            written += take;
        }
        if written == 0 {
            return None;
        }
        out[written..].fill(0);
        Some(written)
    }

    /// Render `out.len()` samples of the current segment, advancing the phase accumulators.
    fn render(&mut self, out: &mut [i16]) {
        if self.component_count == 0 {
            out.fill(0);
            return;
        }
        // Accumulate the components in i32 and saturate to i16 — the same discipline the
        // conference mix bus uses, so a multi-frequency tone can never wrap.
        let amplitude = TONE_COMPONENT_AMPLITUDE as f32;
        for sample in out.iter_mut() {
            let mut sum = 0i32;
            for slot in 0..self.component_count {
                let phase = self.phase[slot];
                self.phase[slot] = phase.wrapping_add(self.increment[slot]);
                sum += (sine_turns(phase_to_turns(phase)) * amplitude) as i32;
            }
            *sample = sum.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
        }
    }
}

/// Convert a Q32 phase to turns in `[0, 1)`.
#[inline]
fn phase_to_turns(phase_q32: u32) -> f32 {
    // 24 bits is all an f32 mantissa carries, so drop the low 8 bits rather than pretend to a
    // precision the float cannot hold: 2^-24 turns is 0.00002 degrees of phase. The scale is a
    // power of two, so the multiply is exact.
    (phase_q32 >> 8) as f32 * (1.0 / 16_777_216.0)
}

/// Reciprocals of the odd-power series denominators, as multiplications.
///
/// Written out because a float **division** by a constant is not rewritten as a multiply by the
/// compiler (it is not exact in general, so the transform needs fast-math, which we do not enable).
/// Four divisions per sample dominated the whole generator before this; the reciprocals cost one
/// ulp of accuracy, three orders of magnitude below the 16-bit PCM quantum.
const SINE_SERIES_RECIPROCALS: [f32; 4] = [1.0 / 6.0, 1.0 / 20.0, 1.0 / 42.0, 1.0 / 72.0];

/// `sin(2π · turns)` for `turns ∈ [0, 1)`.
///
/// Folded to the first quadrant and evaluated with the odd-power series to `z^9`, whose truncation
/// error over `[0, π/2]` is `(π/2)^11 / 11!` ≈ 2.2e-6 — fourteen times finer than the 16-bit PCM
/// quantum (1/32768 ≈ 3.05e-5), so the rendered tone is quantisation-limited, not approximation-
/// limited. A branch per sample rather than a lookup table: no table to hold, and exact
/// frequencies instead of a table-index rounding error.
#[inline]
fn sine_turns(turns: f32) -> f32 {
    use std::f32::consts::TAU;
    let (angle, sign) = if turns < 0.25 {
        (turns * TAU, 1.0f32)
    } else if turns < 0.5 {
        ((0.5 - turns) * TAU, 1.0f32)
    } else if turns < 0.75 {
        ((turns - 0.5) * TAU, -1.0f32)
    } else {
        ((1.0 - turns) * TAU, -1.0f32)
    };
    let [sixth, twentieth, forty_second, seventy_second] = SINE_SERIES_RECIPROCALS;
    let square = angle * angle;
    let series = angle
        * (1.0
            - square
                * sixth
                * (1.0
                    - square
                        * twentieth
                        * (1.0 - square * forty_second * (1.0 - square * seventy_second))));
    sign * series
}

/// A named call-progress tone. Every entry's frequencies and cadence carry the standard they come
/// from; see [`TonePreset::spec`] for the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TonePreset {
    /// European 425 Hz ringing (ringback) tone.
    RingbackEurope,
    /// European 425 Hz busy tone.
    BusyEurope,
    /// European 425 Hz congestion tone.
    CongestionEurope,
    /// European 425 Hz dial tone.
    DialEurope,
    /// European 425 Hz call-waiting tone.
    CallWaitingEurope,
    /// North American audible-ringing (ringback) tone.
    RingbackNorthAmerica,
    /// North American busy (line-busy) tone.
    BusyNorthAmerica,
    /// North American reorder ("fast busy") / congestion tone.
    CongestionNorthAmerica,
    /// North American dial tone.
    DialNorthAmerica,
    /// North American call-waiting tone.
    CallWaitingNorthAmerica,
    /// United Kingdom ringing (ringback) tone.
    RingbackUnitedKingdom,
    /// United Kingdom busy (engaged) tone.
    BusyUnitedKingdom,
    /// United Kingdom congestion (equipment-engaged) tone.
    CongestionUnitedKingdom,
    /// United Kingdom dial tone.
    DialUnitedKingdom,
}

impl TonePreset {
    /// Every preset, in table order — the set [`TonePreset::from_name`] resolves and the
    /// documentation lists.
    pub const ALL: [TonePreset; 14] = [
        TonePreset::RingbackEurope,
        TonePreset::BusyEurope,
        TonePreset::CongestionEurope,
        TonePreset::DialEurope,
        TonePreset::CallWaitingEurope,
        TonePreset::RingbackNorthAmerica,
        TonePreset::BusyNorthAmerica,
        TonePreset::CongestionNorthAmerica,
        TonePreset::DialNorthAmerica,
        TonePreset::CallWaitingNorthAmerica,
        TonePreset::RingbackUnitedKingdom,
        TonePreset::BusyUnitedKingdom,
        TonePreset::CongestionUnitedKingdom,
        TonePreset::DialUnitedKingdom,
    ];

    /// The control-plane name of this preset.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            TonePreset::RingbackEurope => "ringback_eu",
            TonePreset::BusyEurope => "busy_eu",
            TonePreset::CongestionEurope => "congestion_eu",
            TonePreset::DialEurope => "dial_eu",
            TonePreset::CallWaitingEurope => "call_waiting_eu",
            TonePreset::RingbackNorthAmerica => "ringback_na",
            TonePreset::BusyNorthAmerica => "busy_na",
            TonePreset::CongestionNorthAmerica => "congestion_na",
            TonePreset::DialNorthAmerica => "dial_na",
            TonePreset::CallWaitingNorthAmerica => "call_waiting_na",
            TonePreset::RingbackUnitedKingdom => "ringback_uk",
            TonePreset::BusyUnitedKingdom => "busy_uk",
            TonePreset::CongestionUnitedKingdom => "congestion_uk",
            TonePreset::DialUnitedKingdom => "dial_uk",
        }
    }

    /// Resolve a control-plane preset name.
    pub fn from_name(name: &str) -> Result<Self, ToneSpecError> {
        Self::ALL
            .into_iter()
            .find(|preset| preset.name() == name)
            .ok_or(ToneSpecError::UnknownPreset)
    }

    /// The preset's cadence, with the standard each entry comes from.
    #[must_use]
    pub fn spec(self) -> ToneSpec {
        let (segments, repeat) = self.table_entry();
        // Every table entry is inside the fixed capacities (asserted by
        // `every_preset_fits_the_fixed_capacities`), so this is a copy, never a fallible build.
        let count = segments.len().min(MAX_TONE_SEGMENTS);
        let mut stored = [ToneSegment::silence(0); MAX_TONE_SEGMENTS];
        stored[..count].copy_from_slice(&segments[..count]);
        ToneSpec {
            segments: stored,
            segment_count: count as u8,
            repeat,
        }
    }

    /// The preset table. Every row cites the standard its frequencies and cadence come from; the
    /// `_eu` rows are the concrete pan-European 425 Hz set, the national rows are the
    /// administration's own published values.
    ///
    /// Every preset cycles forever: a call-progress tone plays until the call progresses. Bound it
    /// with the playback's `duration_ms` cap, or stop it.
    fn table_entry(self) -> (&'static [ToneSegment], ToneRepeat) {
        let segments: &'static [ToneSegment] = match self {
            TonePreset::RingbackEurope => &RINGBACK_EUROPE,
            TonePreset::BusyEurope => &BUSY_EUROPE,
            TonePreset::CongestionEurope => &CONGESTION_EUROPE,
            TonePreset::DialEurope => &DIAL_EUROPE,
            TonePreset::CallWaitingEurope => &CALL_WAITING_EUROPE,
            TonePreset::RingbackNorthAmerica => &RINGBACK_NORTH_AMERICA,
            TonePreset::BusyNorthAmerica => &BUSY_NORTH_AMERICA,
            TonePreset::CongestionNorthAmerica => &CONGESTION_NORTH_AMERICA,
            TonePreset::DialNorthAmerica => &DIAL_NORTH_AMERICA,
            TonePreset::CallWaitingNorthAmerica => &CALL_WAITING_NORTH_AMERICA,
            TonePreset::RingbackUnitedKingdom => &RINGBACK_UNITED_KINGDOM,
            TonePreset::BusyUnitedKingdom => &BUSY_UNITED_KINGDOM,
            TonePreset::CongestionUnitedKingdom => &CONGESTION_UNITED_KINGDOM,
            TonePreset::DialUnitedKingdom => &DIAL_UNITED_KINGDOM,
        };
        (segments, ToneRepeat::Forever)
    }
}

// ---------------------------------------------------------------------------------------------
// The preset table.
//
// A word on what ITU-T E.180/Q.35 does and does not give you, because it decides how these rows
// are cited. E.180 §5.1 and §6.1 specify tone/silence as *envelopes* (ringing: tone 0.67–1.5 s,
// silence 3–5 s; busy/congestion: cycle 300–1100 ms, ratio 0.67–1.5), and §4.3/§5.3/§6.4 recommend
// 425 Hz for administrations adopting a new single-frequency tone. It never states one cadence.
// The concrete 425 Hz European set below therefore cites **ETSI ETR 187 (1995-04)**, which does —
// and whose values all sit inside E.180's envelopes.
//
// Two honest caveats on ETR 187: it is an informative ETR rather than a standard (the ETS vote
// failed), and its §1 scope is tones generated in the *terminal*, not in the network. It is the
// closest thing to a published, concrete pan-European table; where it and E.180 could conflict,
// E.180 wins, and here they do not.
//
// National rows are the administration's own published values, which differ from the European
// set — that is the whole reason the national presets exist. Two of them fall outside E.180's
// *recommended* envelope (noted on the row); that is the national administration's choice, not a
// transcription error.
// ---------------------------------------------------------------------------------------------

/// European ringing (ringback) tone: 425 Hz, 1 s on / 4 s off.
/// ETSI ETR 187 (1995-04) §4.2; frequency per ITU-T E.180/Q.35 (03/98) §5.3. Inside E.180 §5.1's
/// recommended envelope (tone 0.67–1.5 s, silence 3–5 s).
static RINGBACK_EUROPE: [ToneSegment; 2] =
    [ToneSegment::single(425, 1_000), ToneSegment::silence(4_000)];

/// European busy tone: 425 Hz, 0.5 s on / 0.5 s off.
/// ETSI ETR 187 (1995-04) §4.3; frequency per ITU-T E.180/Q.35 (03/98) §6.4. Inside E.180 §6.1's
/// envelope (1000 ms cycle, ratio 1.0).
static BUSY_EUROPE: [ToneSegment; 2] = [ToneSegment::single(425, 500), ToneSegment::silence(500)];

/// European congestion tone: 425 Hz, 0.2 s on / 0.2 s off — faster than busy, which is how a
/// caller tells "the network is busy" from "the line is busy" (ITU-T E.180/Q.35 §6.3 requires
/// exactly that ordering).
/// ETSI ETR 187 (1995-04) §4.4; frequency per ITU-T E.180/Q.35 (03/98) §6.4.
static CONGESTION_EUROPE: [ToneSegment; 2] =
    [ToneSegment::single(425, 200), ToneSegment::silence(200)];

/// European dial tone: 425 Hz continuous (rendered as back-to-back 1 s segments).
/// ETSI ETR 187 (1995-04) §4.1; ITU-T E.180/Q.35 (03/98) §4.1 makes dial tone continuous and §4.3
/// recommends 425 Hz.
static DIAL_EUROPE: [ToneSegment; 1] = [ToneSegment::single(425, 1_000)];

/// European call-waiting tone: 425 Hz, 0.2 s on / 0.6 s off / 0.2 s on / 3 s off.
/// ETSI ETR 187 (1995-04) §4.6. ITU-T E.180/Q.35 (03/98) §10.3 pattern (b) allows a
/// 100–200 ms / 100–200 ms / 100–200 ms burst group; ETR 187's silence is shorter than E.180's
/// recommended 8–10 s.
static CALL_WAITING_EUROPE: [ToneSegment; 4] = [
    ToneSegment::single(425, 200),
    ToneSegment::silence(600),
    ToneSegment::single(425, 200),
    ToneSegment::silence(3_000),
];

/// North American audible-ringing (ringback) tone: 440 + 480 Hz, 2 s on / 4 s off.
/// Telcordia GR-506-CORE §17.2.5 (as quoted per-frequency in CableLabs PacketCable NCS
/// PKT-SP-EC-MGCP-I10-040402 Appendix A); ITU-T E.180 Supplement 2 (2003), United States entry.
/// The 2 s tone is longer than E.180 §5.1's *recommended* 1.5 s maximum and sits in its "accepted"
/// 2.5 s band — a national choice, not a transcription error.
static RINGBACK_NORTH_AMERICA: [ToneSegment; 2] = [
    ToneSegment::dual(440, 480, 2_000),
    ToneSegment::silence(4_000),
];

/// North American busy (station-busy) tone: 480 + 620 Hz, 0.5 s on / 0.5 s off (60 interruptions
/// per minute).
/// Telcordia GR-506-CORE §17.2.6 (per PacketCable PKT-SP-EC-MGCP-I10-040402 Appendix A);
/// ITU-T E.180 Supplement 2 (2003), United States entry.
static BUSY_NORTH_AMERICA: [ToneSegment; 2] =
    [ToneSegment::dual(480, 620, 500), ToneSegment::silence(500)];

/// North American reorder / congestion ("fast busy") tone: 480 + 620 Hz, 0.25 s on / 0.25 s off
/// (120 interruptions per minute — twice the busy rate).
/// Telcordia GR-506-CORE §17.2.7 (per PacketCable PKT-SP-EC-MGCP-I10-040402 Appendix A).
/// ITU-T E.180 Supplement 2 (2003), United States entry gives 0.3 / 0.2 s instead: the same
/// 120 interruptions per minute at a different duty cycle. GR-506's symmetric 250/250 is the one
/// shipped here because it is the North American equipment specification.
static CONGESTION_NORTH_AMERICA: [ToneSegment; 2] =
    [ToneSegment::dual(480, 620, 250), ToneSegment::silence(250)];

/// North American dial tone: 350 + 440 Hz continuous.
/// Telcordia GR-506-CORE §17.2.1 (per PacketCable PKT-SP-EC-MGCP-I10-040402 Appendix A);
/// ITU-T E.180 Supplement 2 (2003), United States entry.
static DIAL_NORTH_AMERICA: [ToneSegment; 1] = [ToneSegment::dual(350, 440, 1_000)];

/// North American call-waiting tone: a 440 Hz burst of 0.3 s every 10 s.
/// Telcordia GR-506-CORE §14.2 / GR-571-CORE (FSD 01-02-1201); ITU-T E.180 Supplement 2 (2003),
/// United States entry ("440 Hz, 2 × 0.3 s on / 10.0 s off"). The standard's alert is exactly two
/// of these bursts; the preset cycles endlessly like every other one here, so a controller that
/// wants the two-burst alert caps the playback at ~20.6 s with `duration_ms`.
static CALL_WAITING_NORTH_AMERICA: [ToneSegment; 2] =
    [ToneSegment::single(440, 300), ToneSegment::silence(10_000)];

/// United Kingdom ringing tone: 400 + 450 Hz double ring — 0.4 s on, 0.2 s off, 0.4 s on, 2 s off.
/// ITU-T E.180 Supplement 2 (2003), United Kingdom entry. The 2 s silence is shorter than
/// E.180 §5.1's recommended 3–5 s — again a national choice.
static RINGBACK_UNITED_KINGDOM: [ToneSegment; 4] = [
    ToneSegment::dual(400, 450, 400),
    ToneSegment::silence(200),
    ToneSegment::dual(400, 450, 400),
    ToneSegment::silence(2_000),
];

/// United Kingdom busy (engaged) tone: 400 Hz, 0.375 s on / 0.375 s off.
/// ITU-T E.180 Supplement 2 (2003), United Kingdom entry.
static BUSY_UNITED_KINGDOM: [ToneSegment; 2] =
    [ToneSegment::single(400, 375), ToneSegment::silence(375)];

/// United Kingdom congestion (equipment-engaged) tone: 400 Hz, 0.4 s on / 0.35 s off / 0.225 s on
/// / 0.525 s off.
/// ITU-T E.180 Supplement 2 (2003), United Kingdom entry.
static CONGESTION_UNITED_KINGDOM: [ToneSegment; 4] = [
    ToneSegment::single(400, 400),
    ToneSegment::silence(350),
    ToneSegment::single(400, 225),
    ToneSegment::silence(525),
];

/// United Kingdom dial tone: 350 + 440 Hz continuous.
/// ITU-T E.180 Supplement 2 (2003), United Kingdom entry.
///
/// Two things are worth stating rather than glossing. First, 350 + **450** Hz is widely repeated
/// for the UK; the ITU supplement (the UK administration's own submission) says 350 + **440**, and
/// that is what is shipped. Second, the BT source the secondary references quote has the 440 Hz
/// component about 3 dB below the 350 Hz one; this generator renders every component of a segment
/// at the same [`TONE_COMPONENT_LEVEL_DBM0`], so that per-component tilt is **not** reproduced.
/// Neither difference is audible as anything other than dial tone.
static DIAL_UNITED_KINGDOM: [ToneSegment; 1] = [ToneSegment::dual(350, 440, 1_000)];

#[cfg(test)]
mod tests {
    use super::*;

    /// Amplitude of `samples` at `frequency_hz`, by a direct single-bin DFT (a Goertzel by another
    /// name). Computed here in the test rather than by reusing anything the generator uses, so the
    /// assertion is independent of the implementation. Exact only when the window holds a whole
    /// number of periods, which every caller below arranges.
    fn amplitude_at(samples: &[i16], frequency_hz: f64, rate_hz: f64) -> f64 {
        let step = std::f64::consts::TAU * frequency_hz / rate_hz;
        let mut real = 0.0f64;
        let mut imaginary = 0.0f64;
        for (index, &sample) in samples.iter().enumerate() {
            let angle = step * index as f64;
            real += f64::from(sample) * angle.cos();
            imaginary -= f64::from(sample) * angle.sin();
        }
        2.0 * (real * real + imaginary * imaginary).sqrt() / samples.len() as f64
    }

    /// Render `sample_count` samples of `tone` at `rate_hz` through 20 ms frames, the way the
    /// egress path pulls it.
    fn render(tone: &str, rate_hz: u32, sample_count: usize) -> Vec<i16> {
        let spec = ToneSpec::resolve(tone).expect("tone resolves");
        let mut generator = ToneGenerator::new(spec, rate_hz);
        let frame_samples = (rate_hz as usize) * 20 / 1000;
        let mut frame = vec![0i16; frame_samples];
        let mut rendered = Vec::with_capacity(sample_count);
        while rendered.len() < sample_count {
            let Some(written) = generator.next_frame(&mut frame) else {
                break;
            };
            rendered.extend_from_slice(&frame[..written]);
        }
        rendered.truncate(sample_count);
        rendered
    }

    #[test]
    fn tone_amplitude_matches_the_declared_level() {
        // A = 32768 · 10^((L − overload)/20): the peak of a sine at L dBm0 given G.711's +3.14 dBm0
        // overload point. Recomputed from the declared level so the constant cannot silently drift.
        let expected = (32768.0
            * 10f64.powf((TONE_COMPONENT_LEVEL_DBM0 - G711_OVERLOAD_DBM0) / 20.0))
        .round() as i32;
        assert_eq!(TONE_COMPONENT_AMPLITUDE, expected);
        // Two equal components sum 3 dB hotter, landing on the −10 dBm0 nominal of
        // ITU-T E.180/Q.35 §2, and still 10 dB clear of full scale.
        assert!(2 * TONE_COMPONENT_AMPLITUDE < i32::from(i16::MAX));
    }

    #[test]
    fn parses_a_single_segment_with_the_default_repeat() {
        let spec = ToneSpec::parse("425/1000").expect("parses");
        assert_eq!(spec.segments().len(), 1);
        assert_eq!(spec.segments()[0].frequencies_hz(), &[425]);
        assert_eq!(spec.segments()[0].duration_ms(), 1_000);
        assert_eq!(spec.repeat(), ToneRepeat::Times(1));
        assert_eq!(spec.total_duration_ms(), Some(1_000));
    }

    #[test]
    fn parses_a_cadence_with_silence_and_an_endless_repeat() {
        let spec = ToneSpec::parse("425/1000,0/4000*inf").expect("parses");
        assert_eq!(spec.segments().len(), 2);
        assert_eq!(spec.segments()[0].frequencies_hz(), &[425]);
        assert!(spec.segments()[1].frequencies_hz().is_empty());
        assert_eq!(spec.segments()[1].duration_ms(), 4_000);
        assert_eq!(spec.repeat(), ToneRepeat::Forever);
        assert_eq!(spec.total_duration_ms(), None);
    }

    #[test]
    fn parses_a_dual_frequency_segment_and_a_finite_repeat() {
        let spec = ToneSpec::parse("440+480/2000,0/4000*3").expect("parses");
        assert_eq!(spec.segments()[0].frequencies_hz(), &[440, 480]);
        assert_eq!(spec.repeat(), ToneRepeat::Times(3));
        assert_eq!(spec.total_duration_ms(), Some(18_000));
    }

    #[test]
    fn tolerates_whitespace_around_every_token() {
        let spaced = ToneSpec::parse(" 440 + 480 / 2000 , 0 / 4000 * 2 ").expect("parses");
        let tight = ToneSpec::parse("440+480/2000,0/4000*2").expect("parses");
        assert_eq!(spaced, tight);
    }

    #[test]
    fn rejects_every_malformed_spec_without_panicking() {
        let cases: [(&str, ToneSpecError); 10] = [
            ("", ToneSpecError::Empty),
            ("   ", ToneSpecError::Empty),
            ("425", ToneSpecError::MissingDuration { segment: 0 }),
            ("abc/100", ToneSpecError::BadFrequency { segment: 0 }),
            ("425/abc", ToneSpecError::BadDuration { segment: 0 }),
            (
                "425/0",
                ToneSpecError::DurationOutOfRange {
                    segment: 0,
                    duration: 0,
                    limit: MAX_TONE_SEGMENT_MS,
                },
            ),
            (
                "425/60001",
                ToneSpecError::DurationOutOfRange {
                    segment: 0,
                    duration: 60_001,
                    limit: MAX_TONE_SEGMENT_MS,
                },
            ),
            (
                "9000/100",
                ToneSpecError::FrequencyOutOfRange {
                    segment: 0,
                    frequency: 9_000,
                    limit: MAX_TONE_FREQUENCY_HZ,
                },
            ),
            (
                "0+425/100",
                ToneSpecError::SilenceWithFrequency { segment: 0 },
            ),
            ("425/100*0", ToneSpecError::ZeroRepeat),
        ];
        for (input, expected) in cases {
            assert_eq!(ToneSpec::parse(input), Err(expected), "input {input:?}");
        }
        assert_eq!(ToneSpec::parse("425/100*x"), Err(ToneSpecError::BadRepeat));
        assert_eq!(
            ToneSpec::parse("1+2+3+4/100"),
            Err(ToneSpecError::TooManyComponents {
                segment: 0,
                limit: MAX_TONE_COMPONENTS
            })
        );
        let too_many = (0..MAX_TONE_SEGMENTS + 1)
            .map(|_| "425/100")
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            ToneSpec::parse(&too_many),
            Err(ToneSpecError::TooManySegments {
                limit: MAX_TONE_SEGMENTS
            })
        );
    }

    #[test]
    fn resolve_routes_a_slash_to_the_grammar_and_a_bare_name_to_the_preset_table() {
        assert_eq!(
            ToneSpec::resolve("425/1000"),
            ToneSpec::parse("425/1000"),
            "a string with '/' is a cadence spec"
        );
        assert_eq!(
            ToneSpec::resolve("ringback_eu"),
            Ok(TonePreset::RingbackEurope.spec()),
            "a bare name is a preset"
        );
        assert_eq!(
            ToneSpec::resolve("not_a_preset"),
            Err(ToneSpecError::UnknownPreset)
        );
    }

    #[test]
    fn every_preset_fits_the_fixed_capacities_and_round_trips_its_name() {
        let mut names = Vec::new();
        for preset in TonePreset::ALL {
            let spec = preset.spec();
            assert!(
                !spec.segments().is_empty() && spec.segments().len() <= MAX_TONE_SEGMENTS,
                "{} has {} segments",
                preset.name(),
                spec.segments().len()
            );
            for segment in spec.segments() {
                assert!(segment.frequencies_hz().len() <= MAX_TONE_COMPONENTS);
                assert!(segment.duration_ms() > 0 && segment.duration_ms() <= MAX_TONE_SEGMENT_MS);
                for &frequency in segment.frequencies_hz() {
                    assert!(u32::from(frequency) <= MAX_TONE_FREQUENCY_HZ);
                }
            }
            assert_eq!(TonePreset::from_name(preset.name()), Ok(preset));
            assert!(
                !preset.name().contains('/'),
                "a preset name must never contain '/' — that is how `resolve` tells the two apart"
            );
            names.push(preset.name());
        }
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "preset names must be unique");
    }

    #[test]
    fn every_preset_matches_its_cited_frequency_and_cadence_table() {
        // The cited numbers, written out here independently of the table in the module above, so a
        // typo in either one fails rather than agreeing with itself. Sources, in row order:
        //   *_eu  — ETSI ETR 187 (1995-04) §§4.1–4.4, §4.6; 425 Hz per ITU-T E.180/Q.35 §4.3/5.3/6.4
        //   *_na  — Telcordia GR-506-CORE §§17.2.1/.5/.6/.7 and §14.2; ITU-T E.180 Suppl. 2 (US)
        //   *_uk  — ITU-T E.180 Supplement 2 (2003), United Kingdom entry
        #[allow(clippy::type_complexity)]
        let expected: [(&str, &[(&[u16], u32)]); 14] = [
            ("ringback_eu", &[(&[425], 1_000), (&[], 4_000)]),
            ("busy_eu", &[(&[425], 500), (&[], 500)]),
            ("congestion_eu", &[(&[425], 200), (&[], 200)]),
            ("dial_eu", &[(&[425], 1_000)]),
            (
                "call_waiting_eu",
                &[(&[425], 200), (&[], 600), (&[425], 200), (&[], 3_000)],
            ),
            ("ringback_na", &[(&[440, 480], 2_000), (&[], 4_000)]),
            ("busy_na", &[(&[480, 620], 500), (&[], 500)]),
            ("congestion_na", &[(&[480, 620], 250), (&[], 250)]),
            ("dial_na", &[(&[350, 440], 1_000)]),
            ("call_waiting_na", &[(&[440], 300), (&[], 10_000)]),
            (
                "ringback_uk",
                &[
                    (&[400, 450], 400),
                    (&[], 200),
                    (&[400, 450], 400),
                    (&[], 2_000),
                ],
            ),
            ("busy_uk", &[(&[400], 375), (&[], 375)]),
            (
                "congestion_uk",
                &[(&[400], 400), (&[], 350), (&[400], 225), (&[], 525)],
            ),
            ("dial_uk", &[(&[350, 440], 1_000)]),
        ];
        assert_eq!(
            expected.len(),
            TonePreset::ALL.len(),
            "every preset must be covered by the cited table"
        );
        for (name, rows) in expected {
            let preset = TonePreset::from_name(name).expect("named preset exists");
            let spec = preset.spec();
            assert_eq!(spec.segments().len(), rows.len(), "{name} segment count");
            assert_eq!(
                spec.repeat(),
                ToneRepeat::Forever,
                "{name}: a call-progress tone plays until the call progresses"
            );
            for (index, (frequencies, duration_ms)) in rows.iter().enumerate() {
                let segment = spec.segments()[index];
                assert_eq!(
                    segment.frequencies_hz(),
                    *frequencies,
                    "{name} segment {index} frequencies"
                );
                assert_eq!(
                    segment.duration_ms(),
                    *duration_ms,
                    "{name} segment {index} duration"
                );
            }
        }
    }

    #[test]
    fn the_north_american_ringback_renders_both_cited_frequencies_at_the_cited_cadence() {
        // Telcordia GR-506-CORE §17.2.5: 440 + 480 Hz, 2 s on / 4 s off. Frequencies checked by a
        // single-bin DFT over the first 3200 samples (a whole number of periods for both), cadence
        // by where the audio starts and stops at 8 kHz.
        let rendered = render("ringback_na", 8_000, 56_000);
        for frequency in [440.0, 480.0] {
            let measured = amplitude_at(&rendered[..3_200], frequency, 8_000.0);
            assert!(
                (measured - f64::from(TONE_COMPONENT_AMPLITUDE)).abs() < 10.0,
                "{frequency} Hz measured {measured}"
            );
        }
        assert!(
            rendered[..16_000].iter().any(|&sample| sample != 0),
            "two seconds of tone"
        );
        assert!(
            rendered[16_000..48_000].iter().all(|&sample| sample == 0),
            "four seconds of silence"
        );
        assert!(
            rendered[48_000..].iter().any(|&sample| sample != 0),
            "the cadence repeats at six seconds"
        );
    }

    #[test]
    fn the_european_congestion_tone_is_faster_than_the_busy_tone() {
        // ITU-T E.180/Q.35 §6.3 requires congestion to be the faster of the two — that difference
        // is the whole signal to the caller, so it is worth a test of its own.
        let busy_cycle: u32 = TonePreset::BusyEurope
            .spec()
            .segments()
            .iter()
            .map(ToneSegment::duration_ms)
            .sum();
        let congestion_cycle: u32 = TonePreset::CongestionEurope
            .spec()
            .segments()
            .iter()
            .map(ToneSegment::duration_ms)
            .sum();
        assert!(
            congestion_cycle < busy_cycle,
            "congestion cycle {congestion_cycle} ms must be shorter than busy {busy_cycle} ms"
        );
        // Both inside E.180 §6.1's 300–1100 ms cycle envelope.
        for cycle in [busy_cycle, congestion_cycle] {
            assert!(
                (300..=1_100).contains(&cycle),
                "cycle {cycle} ms out of envelope"
            );
        }
    }

    #[test]
    fn renders_a_single_frequency_at_the_declared_level() {
        // 425 Hz at 8 kHz has a period of 320/17 samples, so 3200 samples is exactly 170 periods —
        // a whole number, which is what makes the single-bin DFT below exact.
        let rendered = render("425/1000", 8_000, 3_200);
        assert_eq!(rendered.len(), 3_200);
        let at_tone = amplitude_at(&rendered, 425.0, 8_000.0);
        assert!(
            (at_tone - f64::from(TONE_COMPONENT_AMPLITUDE)).abs() < 8.0,
            "425 Hz component measured {at_tone}, expected ~{TONE_COMPONENT_AMPLITUDE}"
        );
        // Nothing meaningful anywhere else: an off-bin probe must be tiny next to the tone.
        let off_bin = amplitude_at(&rendered, 1_000.0, 8_000.0);
        assert!(
            off_bin < f64::from(TONE_COMPONENT_AMPLITUDE) / 100.0,
            "1000 Hz probe measured {off_bin}, expected near zero"
        );
    }

    #[test]
    fn renders_both_components_of_a_dual_frequency_tone() {
        // 440 Hz and 480 Hz at 8 kHz both complete a whole number of periods in 3200 samples
        // (176 and 192), so both bins read exactly.
        let rendered = render("440+480/2000", 8_000, 3_200);
        for frequency in [440.0, 480.0] {
            let measured = amplitude_at(&rendered, frequency, 8_000.0);
            assert!(
                (measured - f64::from(TONE_COMPONENT_AMPLITUDE)).abs() < 8.0,
                "{frequency} Hz component measured {measured}, expected ~{TONE_COMPONENT_AMPLITUDE}"
            );
        }
        // Summed, not replaced: the peak must approach both components together.
        let peak = rendered
            .iter()
            .map(|s| i32::from(s.abs()))
            .max()
            .unwrap_or(0);
        assert!(
            peak > 2 * TONE_COMPONENT_AMPLITUDE - 400,
            "dual-tone peak {peak} is too low to be the sum of both components"
        );
        assert!(peak <= i32::from(i16::MAX), "dual-tone peak must not clip");
    }

    #[test]
    fn renders_the_european_ringing_cadence_one_second_on_four_seconds_off() {
        // ETSI ETR 187 §4.2 ringing tone: 1 s on, 4 s off. Rendered at 8 kHz, the boundaries land
        // at sample 8000 and sample 40000 exactly.
        let rendered = render("ringback_eu", 8_000, 48_000);
        assert!(
            rendered[..8_000].iter().any(|&sample| sample != 0),
            "the first second must sound"
        );
        assert!(
            rendered[8_000..40_000].iter().all(|&sample| sample == 0),
            "the next four seconds must be silent"
        );
        assert!(
            rendered[40_000..48_000].iter().any(|&sample| sample != 0),
            "the cadence must start over at five seconds"
        );
    }

    #[test]
    fn renders_the_uk_double_ring_cadence() {
        // ITU-T E.180 Supplement 2 (United Kingdom): 0.4 s on / 0.2 s off / 0.4 s on / 2 s off.
        let rendered = render("ringback_uk", 8_000, 24_000);
        let sounding = |range: std::ops::Range<usize>| rendered[range].iter().any(|&s| s != 0);
        let silent = |range: std::ops::Range<usize>| rendered[range].iter().all(|&s| s == 0);
        assert!(sounding(0..3_200), "first ring");
        assert!(silent(3_200..4_800), "inter-ring gap");
        assert!(sounding(4_800..8_000), "second ring");
        assert!(silent(8_000..24_000), "two-second silence");
    }

    #[test]
    fn a_finite_repeat_ends_and_an_endless_one_does_not() {
        let finite = ToneSpec::parse("425/20*2").expect("parses");
        let mut generator = ToneGenerator::new(finite, 8_000);
        let mut frame = [0i16; 160];
        assert_eq!(generator.next_frame(&mut frame), Some(160));
        assert_eq!(generator.next_frame(&mut frame), Some(160));
        assert_eq!(
            generator.next_frame(&mut frame),
            None,
            "two cycles, then done"
        );
        assert!(generator.is_exhausted());
        assert_eq!(generator.total_duration_ms(), Some(40));

        let endless = ToneSpec::parse("425/20*inf").expect("parses");
        let mut generator = ToneGenerator::new(endless, 8_000);
        for _ in 0..1_000 {
            assert_eq!(generator.next_frame(&mut frame), Some(160));
        }
        assert!(!generator.is_exhausted());
        assert_eq!(generator.total_duration_ms(), None);
    }

    #[test]
    fn a_silent_segment_renders_digital_silence() {
        let rendered = render("0/40", 8_000, 320);
        assert!(rendered.iter().all(|&sample| sample == 0));
    }

    #[test]
    fn renders_the_same_frequency_at_every_telephony_rate() {
        // The phase accumulator is rate-relative, so 425 Hz must read 425 Hz at 8, 16 and 48 kHz.
        for rate in [8_000u32, 16_000, 48_000] {
            let samples = (rate as usize) * 2 / 5; // 400 ms — a whole number of 425 Hz periods
            let rendered = render("425/1000", rate, samples);
            let measured = amplitude_at(&rendered, 425.0, f64::from(rate));
            assert!(
                (measured - f64::from(TONE_COMPONENT_AMPLITUDE)).abs() < 20.0,
                "{rate} Hz render measured {measured} at 425 Hz"
            );
        }
    }

    #[test]
    fn a_zero_sample_rate_yields_an_exhausted_generator_rather_than_dividing_by_zero() {
        let spec = ToneSpec::parse("425/1000").expect("parses");
        let mut generator = ToneGenerator::new(spec, 0);
        assert!(generator.is_exhausted());
        assert_eq!(generator.next_frame(&mut [0i16; 160]), None);
    }

    #[test]
    fn an_empty_output_buffer_yields_nothing() {
        let spec = ToneSpec::parse("425/1000").expect("parses");
        let mut generator = ToneGenerator::new(spec, 8_000);
        assert_eq!(generator.next_frame(&mut []), None);
    }

    #[test]
    fn tone_spec_errors_render_a_message() {
        // Every variant is reachable from the control plane, so every one must format.
        for error in [
            ToneSpecError::Empty,
            ToneSpecError::TooManySegments { limit: 8 },
            ToneSpecError::TooManyComponents {
                segment: 1,
                limit: 3,
            },
            ToneSpecError::MissingDuration { segment: 0 },
            ToneSpecError::BadFrequency { segment: 0 },
            ToneSpecError::FrequencyOutOfRange {
                segment: 0,
                frequency: 9_000,
                limit: 4_000,
            },
            ToneSpecError::SilenceWithFrequency { segment: 0 },
            ToneSpecError::BadDuration { segment: 0 },
            ToneSpecError::DurationOutOfRange {
                segment: 0,
                duration: 0,
                limit: 60_000,
            },
            ToneSpecError::BadRepeat,
            ToneSpecError::ZeroRepeat,
            ToneSpecError::UnknownPreset,
        ] {
            assert!(!error.to_string().is_empty());
        }
    }

    proptest::proptest! {
        /// The tone string arrives from the control plane, so it is untrusted input: any byte
        /// sequence must resolve or error, never panic. (The `cargo-fuzz` target
        /// `tone_spec_fuzz` drives the same entry point with coverage guidance.)
        #[test]
        fn resolving_arbitrary_text_never_panics(input in ".{0,80}") {
            let _ = ToneSpec::resolve(&input);
        }

        /// Grammar-shaped input, so the fuzzer spends its budget past the first character class
        /// rather than rejecting random bytes at byte 0.
        #[test]
        fn resolving_grammar_shaped_text_never_panics(input in "[0-9+/,* a-z]{0,60}") {
            let _ = ToneSpec::resolve(&input);
        }

        /// Whatever parses must render bounded, finite audio: every frame is either a full frame
        /// or `None`, and nothing panics on an odd rate or a one-sample frame.
        #[test]
        fn any_parsed_spec_renders_bounded_frames(
            frequency in 1u32..=MAX_TONE_FREQUENCY_HZ,
            duration in 1u32..=200,
            rate in 8_000u32..=48_000,
        ) {
            let spec = ToneSpec::parse(&format!("{frequency}/{duration}*2"))
                .expect("a generated spec is always in the grammar");
            let mut generator = ToneGenerator::new(spec, rate);
            let mut frame = [0i16; 64];
            let mut frames = 0u32;
            while let Some(written) = generator.next_frame(&mut frame) {
                proptest::prop_assert!(written <= frame.len());
                frames += 1;
                proptest::prop_assert!(frames < 100_000, "a finite tone must terminate");
            }
        }
    }

    #[test]
    fn the_sine_approximation_tracks_the_library_sine_within_the_pcm_quantum() {
        // The folded polynomial must be closer to the truth than one 16-bit LSB (1/32768), or the
        // rendered tone would be approximation-limited instead of quantisation-limited.
        for step in 0..4_096u32 {
            let phase = step << 20;
            let turns = phase_to_turns(phase);
            let approximated = f64::from(sine_turns(turns));
            let exact = (std::f64::consts::TAU * f64::from(turns)).sin();
            assert!(
                (approximated - exact).abs() < 1.0 / 32_768.0,
                "phase {phase}: approximated {approximated}, exact {exact}"
            );
        }
    }
}
