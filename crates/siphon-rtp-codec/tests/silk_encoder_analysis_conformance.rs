//! SILK **encoder** analysis conformance: run the ported analysis front end over the exact input
//! libopus analysed, and diff every kernel's output against libopus' own.
//!
//! # Why this shape of test
//!
//! An encoder has no `final_range` oracle. RFC 6716 is normative for the decoder only, so there is
//! no "correct" encoder bitstream to match — only "libopus decides X here, and so should we, because
//! libopus' decisions are what forty years of speech coding put in that file". The check that
//! actually catches a bug is therefore a **per-kernel golden diff** against an instrumented libopus.
//!
//! `reference/opus/silk_trace.patch` adds `#ifdef SILK_TRACE` dumps to the encoder's analysis path
//! and `reference/opus/dump_silk_enc_trace.sh` drives them (recipe in CONTRIBUTING.md). Each frame's
//! dump is **self-contained**: the input signal window as raw IEEE-754 bit patterns, the cross-frame
//! state the analysis reads, and every configuration value that moves a threshold. This harness
//! rebuilds that state, calls [`analyze_frame`], and compares field by field — so a mismatch is
//! pinned to one kernel in one frame instead of being blamed on drift from the frames before it.
//!
//! # Tolerances, and where a tolerance would be a bug
//!
//! The analysis front end is **float** (`silk/float/`), so bit-equality against the C is not
//! achievable and not the bar:
//!
//! * GCC compiles libopus with `-ffp-contract=fast`, so a C `a * b + c` may fuse into one FMA while
//!   Rust never contracts. That alone is a ~1e-7 relative difference per operation, and the Burg
//!   recursion chains hundreds of them.
//! * `libm`'s `exp`, `pow`, `log10` and `sqrt` are not specified to the last ulp and differ between
//!   Rust's and glibc's implementations.
//!
//! So every **continuous** field carries a stated relative tolerance, listed per group below. Every
//! **discrete** field — a codebook index, a pitch lag, a gain index, a voicing verdict, a
//! quantisation offset, an interpolation weight — is required to match **exactly**, and a tolerance
//! on one of those would be a bug rather than a relaxation: those are the values that reach the
//! bitstream, and one of them differing means the two encoders made different decisions.
//!
//! Two consequences worth stating plainly:
//!
//! * `reference/opus/build-trace` is configured with `-DOPUS_DISABLE_INTRINSICS=ON`. libopus'
//!   `silk/float/x86/inner_product_FLP_avx2.c` accumulates in a different order from
//!   `silk_inner_product_FLP_c`, which is what this port reproduces; leaving it enabled compares
//!   against a *third* implementation and inflates every tolerance for no reason. The fixed-point
//!   SSE4.1 paths libopus also ships are bit-exact, so the decoder harnesses are unaffected.
//! * The NLSF vectors and the shaping coefficients are continuous, but the **NLSF indices** derived
//!   from them are not. If a frame's NLSFs sit exactly on a quantiser decision boundary, a 1e-7
//!   difference can flip an index. The harness reports such frames rather than tolerating them —
//!   see the `EXACT MISMATCH` output and the per-group counters.
//!
//! Skips gracefully when the dumps are absent (`SIPHON_RTP_REQUIRE_VECTORS=1` turns that into a
//! failure, via `reference_vectors.rs`), and refuses to pass vacuously: it requires a non-trivial
//! number of scored frames, both codebook orders, both frame durations, and at least one voiced
//! frame.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use siphon_rtp_codec::opus::silk::enc::frame::{
    analyze_frame, AnalysisConfig, AnalysisState, ComplexitySettings,
};
use siphon_rtp_codec::opus::silk::enc::noise_shape::ShapeState;
use siphon_rtp_codec::opus::silk::enc::pitch::{find_pitch_lags, PitchConfig};
use siphon_rtp_codec::opus::silk::enc::pred_coefs::find_ltp;
use siphon_rtp_codec::opus::silk::enc::{SignalMeasures, MAX_SHAPE_LPC_ORDER};
use siphon_rtp_codec::opus::silk::types::{
    CondCoding, InternalRate, QuantOffsetType, SignalType, SubframeLayout, LTP_ORDER, MAX_LPC_ORDER,
};

/// Relative tolerance on the pitch analysis' prediction gain and normalized correlation. Both are
/// ratios of `double` energy sums over ~400 samples, so the FMA/`libm` slack is tiny.
const TOLERANCE_PITCH: f64 = 1e-4;
/// Relative tolerance on the noise-shaping filter coefficients, tilt, and low-frequency shaping.
/// These come out of `schur` + `k2a` + up to ten bandwidth expansions, and the shaping gain also
/// passes through `pow` and `sqrt`, so the chain is longer than the pitch measures'.
const TOLERANCE_SHAPE: f64 = 2e-3;
/// Relative tolerance on the initial and quantised gains. The quantised ones are exact by
/// construction (they come from `log2lin` of an integer index) whenever the index matches, so this
/// only covers the pre-quantisation value.
const TOLERANCE_GAIN: f64 = 5e-3;
/// Relative tolerance on the LTP prediction gain in dB, the LTP scale and the residual energies.
const TOLERANCE_PRED: f64 = 5e-3;
/// Absolute tolerance on an unquantized NLSF, in Q15 units (1 unit is 1/32768 of the Nyquist rate).
/// The NLSFs come from a fixed-point root finder over float Burg coefficients, so they are integers
/// derived from a continuous quantity — hence an absolute bound rather than a relative one.
const TOLERANCE_NLSF_Q15: i32 = 24;
/// Absolute tolerance on a Q12 LPC coefficient reconstructed from *matching* NLSF indices. Zero
/// would be correct if the indices always matched; it is 2 so a frame whose indices differ still
/// reports the index mismatch rather than drowning it in coefficient noise.
const TOLERANCE_LPC_Q12: i32 = 2;
/// Relative tolerance on the LTP correlation matrix and vector. Tight on purpose: these are the
/// *input* to the entropy-constrained codebook search, they are converted to Q17 integers before
/// the search reads them, and a 1e-3 disagreement there is easily a different codebook vector. If
/// this ever needs loosening, the right response is to find out why the correlations drifted.
const TOLERANCE_LTP_CORR: f64 = 1e-6;

/// `reference/opus/silk_enc`, if the encoder traces have been dumped.
fn trace_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus/silk_enc");
    dir.is_dir().then_some(dir)
}

/// One `KEY ...` trace line, parsed into `name=value` pairs.
#[derive(Debug, Default, Clone)]
struct Record {
    fields: BTreeMap<String, String>,
    /// The whitespace-separated tail after the last `key=value`, used only by `EIN`.
    tail: Vec<String>,
}

impl Record {
    fn parse(line: &str) -> Self {
        let mut record = Self::default();
        for token in line.split_whitespace().skip(1) {
            match token.split_once('=') {
                Some((key, value)) => {
                    record.fields.insert(key.to_string(), value.to_string());
                }
                None => record.tail.push(token.to_string()),
            }
        }
        record
    }

    fn integer(&self, key: &str) -> Option<i64> {
        self.fields.get(key)?.parse().ok()
    }

    fn float(&self, key: &str) -> Option<f64> {
        self.fields.get(key)?.parse().ok()
    }

    fn integers(&self, key: &str) -> Vec<i64> {
        self.fields
            .get(key)
            .map(|value| {
                value
                    .split(',')
                    .filter(|piece| !piece.is_empty())
                    .filter_map(|piece| piece.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn floats(&self, key: &str) -> Vec<f64> {
        self.fields
            .get(key)
            .map(|value| {
                value
                    .split(',')
                    .filter(|piece| !piece.is_empty())
                    .filter_map(|piece| piece.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Every trace group belonging to one SILK frame.
#[derive(Debug, Default, Clone)]
struct FrameTrace {
    input: Option<Record>,
    state: Option<Record>,
    config: Option<Record>,
    pitch: Option<Record>,
    shape: Option<Record>,
    lpc: Option<Record>,
    pred: Option<Record>,
    gains: Option<Record>,
    ltp_corr: Option<Record>,
}

impl FrameTrace {
    fn is_complete(&self) -> bool {
        self.input.is_some()
            && self.state.is_some()
            && self.config.is_some()
            && self.pitch.is_some()
            && self.shape.is_some()
            && self.lpc.is_some()
            && self.pred.is_some()
            && self.gains.is_some()
    }
}

/// Read one `.enctrace` into per-frame groups, keyed by the `u=` counter.
///
/// Groups this harness does not own — the decoder-side `NLSFRES` / `NLSFRAW` / `NLSF` lines the
/// encoder emits when `silk_NLSF_encode` calls `silk_NLSF_decode`, and anything a future stage adds
/// — are ignored. That is the shared patch's contract: a harness must skip what it does not consume,
/// or whichever stage extended the patch last breaks all its siblings.
fn read_trace(path: &Path) -> BTreeMap<i64, FrameTrace> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let mut frames: BTreeMap<i64, FrameTrace> = BTreeMap::new();
    for line in text.lines() {
        let Some(key) = line.split_whitespace().next() else {
            continue;
        };
        let slot: fn(&mut FrameTrace) -> &mut Option<Record> = match key {
            "EIN" => |frame| &mut frame.input,
            "ESTATE" => |frame| &mut frame.state,
            "ECFG" => |frame| &mut frame.config,
            "EPITCH" => |frame| &mut frame.pitch,
            "ESHAPE" => |frame| &mut frame.shape,
            "ELPC" => |frame| &mut frame.lpc,
            "ELTP" => |frame| &mut frame.pred,
            "ELTPCORR" => |frame| &mut frame.ltp_corr,
            "EGAINS" => |frame| &mut frame.gains,
            _ => continue,
        };
        let record = Record::parse(line);
        let Some(unit) = record.integer("u") else {
            continue;
        };
        if unit < 0 {
            continue;
        }
        *slot(frames.entry(unit).or_default()) = Some(record);
    }
    frames
}

/// Running comparison state: one entry per named field group.
#[derive(Debug, Default)]
struct Tally {
    /// Fields compared, per group.
    compared: BTreeMap<String, usize>,
    /// Fields that differed beyond tolerance (continuous) or at all (discrete), per group.
    failed: BTreeMap<String, usize>,
    /// The first few failure descriptions, for the assertion message.
    examples: Vec<String>,
    /// Stream and frame currently being scored, prefixed to every failure so a mismatch names the
    /// configuration it came from rather than leaving it to be bisected.
    context: String,
    /// Frames in which at least one field of a group differed, per group — a far more useful
    /// number than the field count when one bad frame contributes twenty fields.
    frames_failed: BTreeMap<String, usize>,
    /// Groups that have already been counted as failing for the current frame.
    frame_groups_seen: Vec<String>,
}

impl Tally {
    fn begin_frame(&mut self, context: String) {
        self.context = context;
        self.frame_groups_seen.clear();
    }

    fn note(&mut self, group: &str, ok: bool, describe: impl FnOnce() -> String) {
        *self.compared.entry(group.to_string()).or_default() += 1;
        if !ok {
            *self.failed.entry(group.to_string()).or_default() += 1;
            if !self.frame_groups_seen.iter().any(|seen| seen == group) {
                self.frame_groups_seen.push(group.to_string());
                *self.frames_failed.entry(group.to_string()).or_default() += 1;
            }
            if self.examples.len() < 24 {
                self.examples
                    .push(format!("{} {}", self.context, describe()));
            }
        }
    }

    fn exact_i64(&mut self, group: &str, label: &str, ours: i64, theirs: i64) {
        self.note(group, ours == theirs, || {
            format!("EXACT MISMATCH {group}/{label}: ours {ours} != libopus {theirs}")
        });
    }

    fn close_f64(&mut self, group: &str, label: &str, ours: f64, theirs: f64, tolerance: f64) {
        let slack = theirs.abs() * tolerance + tolerance;
        self.note(group, (ours - theirs).abs() <= slack, || {
            format!("{group}/{label}: ours {ours:.9} vs libopus {theirs:.9} (slack {slack:.9})")
        });
    }

    fn near_i64(&mut self, group: &str, label: &str, ours: i64, theirs: i64, tolerance: i64) {
        self.note(group, (ours - theirs).abs() <= tolerance, || {
            format!("{group}/{label}: ours {ours} vs libopus {theirs} (tolerance {tolerance})")
        });
    }
}

/// Rebuild the analysis configuration from the dump, and cross-check the ported complexity table
/// against the settings libopus actually derived — every one of those is a discrete value.
fn config_from(trace: &FrameTrace, tally: &mut Tally) -> Option<(AnalysisConfig, usize)> {
    let input = trace.input.as_ref()?;
    let config = trace.config.as_ref()?;

    let fs_khz = input.integer("fskhz")?;
    let internal_rate = match fs_khz {
        8 => InternalRate::Narrow8k,
        12 => InternalRate::Medium12k,
        16 => InternalRate::Wide16k,
        _ => return None,
    };
    let subframe_count = input.integer("nsubfr")? as usize;
    let duration_ms = subframe_count * 5;
    let layout = SubframeLayout::from_duration_ms(duration_ms).ok()?;
    let complexity = config.integer("complexity")? as u8;

    let analysis = AnalysisConfig {
        internal_rate,
        layout,
        settings: ComplexitySettings::for_complexity(complexity),
        snr_db_q7: config.integer("snr")? as i32,
        use_cbr: config.integer("cbr")? != 0,
        packet_loss_percent: config.integer("loss")? as i32,
        frames_per_packet: config.integer("nframes")? as i32,
        lbrr_enabled: config.integer("lbrr")? != 0,
    };

    // The complexity table is the encoder's whole search-depth contract. Every field of it is
    // discrete, and libopus dumps what it derived, so this is an exact check on all of it.
    tally.exact_i64(
        "CFG",
        "pitch_order",
        analysis.pitch_estimation_lpc_order() as i64,
        config.integer("peorder")?,
    );
    tally.exact_i64(
        "CFG",
        "pitch_complexity",
        analysis.settings.pitch_estimation_complexity as i64,
        config.integer("pecomplex")?,
    );
    tally.exact_i64(
        "CFG",
        "pitch_threshold_q16",
        i64::from(analysis.settings.pitch_estimation_threshold_q16),
        config.integer("pethr")?,
    );
    tally.exact_i64(
        "CFG",
        "shaping_order",
        analysis.settings.shaping_lpc_order as i64,
        config.integer("shapeorder")?,
    );
    tally.exact_i64(
        "CFG",
        "warping_q16",
        i64::from(analysis.warping_q16()),
        config.integer("warp")?,
    );
    tally.exact_i64(
        "CFG",
        "use_interpolated_nlsfs",
        i64::from(analysis.settings.use_interpolated_nlsfs),
        config.integer("interp")?,
    );
    tally.exact_i64(
        "CFG",
        "nlsf_survivors",
        analysis.settings.nlsf_survivors as i64,
        config.integer("surv")?,
    );
    tally.exact_i64(
        "CFG",
        "delayed_decision_states",
        i64::from(analysis.settings.delayed_decision_states),
        config.integer("deldec")?,
    );
    tally.exact_i64(
        "CFG",
        "shape_window",
        analysis.shape_window_length() as i64,
        input.integer("shapewin")?,
    );
    tally.exact_i64(
        "CFG",
        "pitch_window",
        analysis.pitch_lpc_window_length() as i64,
        input.integer("pitchwin")?,
    );
    tally.exact_i64(
        "CFG",
        "la_shape",
        analysis.la_shape() as i64,
        input.integer("lashape")?,
    );
    tally.exact_i64(
        "CFG",
        "la_pitch",
        analysis.la_pitch() as i64,
        input.integer("lapitch")?,
    );
    tally.exact_i64(
        "CFG",
        "ltp_memory",
        analysis.ltp_memory_length() as i64,
        input.integer("ltpmem")?,
    );
    tally.exact_i64(
        "CFG",
        "lpc_order",
        internal_rate.lpc_order() as i64,
        input.integer("order")?,
    );

    Some((analysis, subframe_count))
}

/// What the harness observed about a stream, so a vacuous pass can be detected.
#[derive(Debug, Default)]
struct Coverage {
    frames: usize,
    voiced: usize,
    interpolated: usize,
    warped: usize,
    order_10: usize,
    order_16: usize,
    ten_ms: usize,
    twenty_ms: usize,
}

fn score_frame(
    stream: &str,
    unit: i64,
    trace: &FrameTrace,
    tally: &mut Tally,
    coverage: &mut Coverage,
) -> Option<()> {
    tally.begin_frame(format!("[{stream} u={unit}]"));
    let (config, subframe_count) = config_from(trace, tally)?;
    let input = trace.input.as_ref()?;
    let state_record = trace.state.as_ref()?;
    let config_record = trace.config.as_ref()?;
    let order = config.internal_rate.lpc_order();

    // Rebuild the exact input window from the dumped bit patterns.
    let length = input.integer("n")? as usize;
    if input.tail.len() < length {
        return None;
    }
    let signal: Vec<f32> = input.tail[..length]
        .iter()
        .filter_map(|token| u32::from_str_radix(token, 16).ok())
        .map(f32::from_bits)
        .collect();
    if signal.len() != length {
        return None;
    }
    // The frame starts after the LTP history; the window was dumped from `psEnc->x_buf`.
    let frame_start = config.ltp_memory_length();

    // Rebuild the cross-frame state.
    let previous_nlsf = state_record.integers("prevnlsf");
    let mut previous_nlsf_q15 = [0i16; MAX_LPC_ORDER];
    for (slot, &value) in previous_nlsf_q15.iter_mut().zip(previous_nlsf.iter()) {
        *slot = value as i16;
    }
    let mut state = AnalysisState {
        shape: ShapeState {
            last_gain_index: state_record.integer("lastgain")? as i8,
            harmonic_shape_gain_smoothed: state_record.float("harmsmth")? as f32,
            tilt_smoothed: state_record.float("tiltsmth")? as f32,
        },
        previous_nlsf_q15,
        ltp_correlation: state_record.float("ltpcorr")? as f32,
        previous_lag: state_record.integer("prevlag")? as i32,
        previous_signal_type: signal_type_from(state_record.integer("prevtype")?),
        sum_log_gain_q7: state_record.integer("sumloggain")? as i32,
        first_frame_after_reset: state_record.integer("first")? != 0,
    };

    let quality = config_record.integers("iq");
    let measures = SignalMeasures {
        speech_activity_q8: config_record.integer("sa")? as i32,
        input_quality_bands_q15: [
            *quality.first().unwrap_or(&0) as i32,
            *quality.get(1).unwrap_or(&0) as i32,
            *quality.get(2).unwrap_or(&0) as i32,
            *quality.get(3).unwrap_or(&0) as i32,
        ],
        input_tilt_q15: config_record.integer("tilt")? as i32,
        previous_signal_type: state.previous_signal_type,
    };
    let conditional = match config_record.integer("cond")? {
        0 => CondCoding::Independently,
        1 => CondCoding::IndependentlyNoLtpScaling,
        _ => CondCoding::Conditionally,
    };
    let incoming_type = signal_type_from(config_record.integer("type")?);

    let analysis = analyze_frame(
        &mut state,
        &signal,
        frame_start,
        incoming_type,
        conditional,
        &measures,
        &config,
    )
    .ok()?;

    tally.context = format!("{} type={:?}", tally.context, analysis.indices.signal_type);
    coverage.frames += 1;
    if analysis.indices.signal_type == SignalType::Voiced {
        coverage.voiced += 1;
    }
    if analysis.indices.nlsf.interpolation_factor_q2 < 4 {
        coverage.interpolated += 1;
    }
    if config.warping_q16() > 0 {
        coverage.warped += 1;
    }
    if order == 10 {
        coverage.order_10 += 1;
    } else {
        coverage.order_16 += 1;
    }
    if subframe_count == 2 {
        coverage.ten_ms += 1;
    } else {
        coverage.twenty_ms += 1;
    }

    // ---- EPITCH: every field here except the two measures is discrete ----
    let pitch = trace.pitch.as_ref()?;
    tally.exact_i64(
        "PITCH",
        "signal_type",
        analysis.indices.signal_type.index() as i64,
        pitch.integer("type")?,
    );
    tally.exact_i64(
        "PITCH",
        "lag_index",
        i64::from(analysis.indices.lag_index),
        pitch.integer("lag")?,
    );
    tally.exact_i64(
        "PITCH",
        "contour_index",
        i64::from(analysis.indices.contour_index),
        pitch.integer("contour")?,
    );
    for (subframe, &lag) in pitch
        .integers("lags")
        .iter()
        .enumerate()
        .take(subframe_count)
    {
        tally.exact_i64(
            "PITCH",
            "pitch_lag",
            i64::from(analysis.control.pitch_lags[subframe]),
            lag,
        );
    }
    tally.close_f64(
        "PITCH",
        "prediction_gain",
        f64::from(analysis.control.prediction_gain),
        pitch.float("predgain")?,
        TOLERANCE_PITCH,
    );
    tally.close_f64(
        "PITCH",
        "ltp_correlation",
        f64::from(state.ltp_correlation),
        pitch.float("ltpcorr")?,
        TOLERANCE_PITCH,
    );

    // ---- ESHAPE: the quantisation offset is discrete, everything else continuous ----
    let shape = trace.shape.as_ref()?;
    for (label, ours, theirs) in [
        (
            "input_quality",
            f64::from(analysis.control.input_quality),
            shape.float("iq")?,
        ),
        (
            "coding_quality",
            f64::from(analysis.control.coding_quality),
            shape.float("cq")?,
        ),
    ] {
        tally.close_f64("SHAPE", label, ours, theirs, TOLERANCE_SHAPE);
    }
    for (subframe, &theirs) in shape.floats("tilt").iter().enumerate().take(subframe_count) {
        tally.close_f64(
            "SHAPE",
            "tilt",
            f64::from(analysis.control.tilt[subframe]),
            theirs,
            TOLERANCE_SHAPE,
        );
    }
    for (subframe, &theirs) in shape.floats("harm").iter().enumerate().take(subframe_count) {
        tally.close_f64(
            "SHAPE",
            "harmonic_shape_gain",
            f64::from(analysis.control.harmonic_shape_gain[subframe]),
            theirs,
            TOLERANCE_SHAPE,
        );
    }
    for (subframe, &theirs) in shape.floats("lfma").iter().enumerate().take(subframe_count) {
        tally.close_f64(
            "SHAPE",
            "lf_ma_shp",
            f64::from(analysis.control.lf_ma_shp[subframe]),
            theirs,
            TOLERANCE_SHAPE,
        );
    }
    for (subframe, &theirs) in shape.floats("lfar").iter().enumerate().take(subframe_count) {
        tally.close_f64(
            "SHAPE",
            "lf_ar_shp",
            f64::from(analysis.control.lf_ar_shp[subframe]),
            theirs,
            TOLERANCE_SHAPE,
        );
    }
    let shaping_order = config.settings.shaping_lpc_order;
    for (index, &theirs) in shape
        .floats("ar")
        .iter()
        .enumerate()
        .take(subframe_count * shaping_order)
    {
        let subframe = index / shaping_order;
        let coefficient = index % shaping_order;
        tally.close_f64(
            "SHAPE",
            "shaping_ar",
            f64::from(analysis.control.shaping_ar[subframe * MAX_SHAPE_LPC_ORDER + coefficient]),
            theirs,
            TOLERANCE_SHAPE,
        );
    }

    // ---- ELPC: the interpolation weight is discrete; the unquantized NLSFs are not ----
    let lpc = trace.lpc.as_ref()?;
    tally.close_f64(
        "LPC",
        "min_inverse_gain",
        f64::from(analysis.control.min_inverse_gain),
        lpc.float("mininvgain")?,
        TOLERANCE_PRED,
    );
    tally.exact_i64(
        "LPC",
        "interpolation_factor_q2",
        i64::from(analysis.indices.nlsf.interpolation_factor_q2),
        lpc.integer("interp")?,
    );
    for (position, &theirs) in lpc.integers("nlsf").iter().enumerate().take(order) {
        tally.near_i64(
            "LPC",
            "unquantized_nlsf_q15",
            i64::from(analysis.control.unquantized_nlsf_q15[position]),
            theirs,
            i64::from(TOLERANCE_NLSF_Q15),
        );
    }

    // ---- ELTP: every index is discrete ----
    let pred = trace.pred.as_ref()?;

    // `PERIndex`, `LTPIndex`, `LTP_scaleIndex` and `LTP_scale` are **only defined on a voiced
    // frame**. libopus assigns them exclusively on the voiced path (`find_pred_coefs_FLP.c:59-77`)
    // and `silk_encode_indices` only writes them when `signalType == TYPE_VOICED`, so on an
    // unvoiced frame the C simply carries the previous voiced frame's values forward in an unused
    // struct. This port zeroes them instead — the same defined state the decoder holds
    // (`crate::opus::silk::ltp::LtpIndices::unvoiced`). Comparing stale-versus-zero would be
    // comparing something neither encoder codes, so these four are scored on voiced frames only.
    // Everything else in the group *is* defined on both paths (`LTPCoef` is memset to zero and
    // `LTPredCodGain` to 0.0 at `find_pred_coefs_FLP.c:91-93`) and is compared unconditionally.
    if analysis.indices.signal_type == SignalType::Voiced {
        tally.exact_i64(
            "LTP",
            "periodicity_index",
            i64::from(analysis.indices.periodicity_index),
            pred.integer("per")?,
        );
        tally.exact_i64(
            "LTP",
            "ltp_scale_index",
            i64::from(analysis.indices.ltp_scale_index),
            pred.integer("scale")?,
        );
        for (subframe, &theirs) in pred.integers("idx").iter().enumerate().take(subframe_count) {
            tally.exact_i64(
                "LTP",
                "codebook_index",
                i64::from(analysis.indices.ltp_indices[subframe]),
                theirs,
            );
        }
        tally.close_f64(
            "LTP",
            "ltp_scale",
            f64::from(analysis.control.ltp_scale),
            pred.float("ltpscale")?,
            TOLERANCE_PRED,
        );
    }
    tally.close_f64(
        "LTP",
        "prediction_gain_db",
        f64::from(analysis.control.ltp_prediction_gain_db),
        pred.float("predgain")?,
        TOLERANCE_PRED,
    );
    for (tap, &theirs) in pred
        .floats("taps")
        .iter()
        .enumerate()
        .take(subframe_count * LTP_ORDER)
    {
        tally.close_f64(
            "LTP",
            "tap",
            f64::from(analysis.control.ltp_coefficients[tap]),
            theirs,
            TOLERANCE_PRED,
        );
    }
    for (subframe, &theirs) in pred
        .floats("resnrg")
        .iter()
        .enumerate()
        .take(subframe_count)
    {
        tally.close_f64(
            "LTP",
            "residual_energy",
            f64::from(analysis.control.residual_energy[subframe]),
            theirs,
            TOLERANCE_PRED,
        );
    }

    // ---- ELTPCORR: the LTP search's *input*, re-derived by re-running the two kernels that
    // produce it. `analyze_frame` is deterministic, so this reproduces exactly the correlations it
    // used internally, and it is what separates "we correlated differently" from "we searched the
    // codebook differently" when a codebook index disagrees.
    if let Some(correlations) = trace.ltp_corr.as_ref() {
        if analysis.indices.signal_type == SignalType::Voiced {
            let mut residual = vec![0.0f32; signal.len()];
            let pitch_config = PitchConfig {
                fs_khz: config.internal_rate.khz(),
                subframe_count,
                la_pitch: config.la_pitch(),
                pitch_lpc_win_length: config.pitch_lpc_window_length(),
                pitch_estimation_lpc_order: config.pitch_estimation_lpc_order(),
                pitch_estimation_complexity: config.settings.pitch_estimation_complexity,
                pitch_estimation_threshold_q16: config.settings.pitch_estimation_threshold_q16,
                first_frame_after_reset: state_record.integer("first")? != 0,
            };
            let replay = find_pitch_lags(
                &mut residual,
                &signal[frame_start - config.ltp_memory_length()..],
                incoming_type,
                state_record.integer("prevlag")? as i32,
                state_record.float("ltpcorr")? as f32,
                &pitch_config,
                &measures,
            );
            let mut matrix = [0.0f32; 4 * LTP_ORDER * LTP_ORDER];
            let mut vector = [0.0f32; 4 * LTP_ORDER];
            find_ltp(
                &mut matrix,
                &mut vector,
                &residual,
                config.ltp_memory_length(),
                &replay.analysis.pitch_lags,
                config.subframe_length(),
                subframe_count,
            );
            for (index, &theirs) in correlations
                .floats("xx")
                .iter()
                .enumerate()
                .take(subframe_count * LTP_ORDER * LTP_ORDER)
            {
                tally.close_f64(
                    "LTPCORR",
                    "matrix",
                    f64::from(matrix[index]),
                    theirs,
                    TOLERANCE_LTP_CORR,
                );
            }
            for (index, &theirs) in correlations
                .floats("xv")
                .iter()
                .enumerate()
                .take(subframe_count * LTP_ORDER)
            {
                tally.close_f64(
                    "LTPCORR",
                    "vector",
                    f64::from(vector[index]),
                    theirs,
                    TOLERANCE_LTP_CORR,
                );
            }
        }
    }

    // ---- NLSF quantisation: the indices are the bitstream, so they are exact ----
    for (position, &theirs) in pred.integers("nlsfidx").iter().enumerate().take(order + 1) {
        tally.exact_i64(
            "NLSF",
            "index",
            i64::from(analysis.indices.nlsf.indices[position]),
            theirs,
        );
    }
    for (position, &theirs) in pred.integers("nlsfq").iter().enumerate().take(order) {
        tally.near_i64(
            "NLSF",
            "reconstructed_q15",
            i64::from(state.previous_nlsf_q15[position]),
            theirs,
            i64::from(TOLERANCE_NLSF_Q15),
        );
    }
    for half in 0..2usize {
        let key = if half == 0 { "a0" } else { "a1" };
        for (position, &theirs) in pred.floats(key).iter().enumerate().take(order) {
            // The C stores Q12 coefficients scaled to floats; compare in the Q12 integer domain so
            // the tolerance is in units the decoder actually sees.
            let ours_q12 = (f64::from(analysis.control.prediction_coefficients[half][position])
                * 4096.0)
                .round() as i64;
            let theirs_q12 = (theirs * 4096.0).round() as i64;
            tally.near_i64(
                "NLSF",
                "lpc_q12",
                ours_q12,
                theirs_q12,
                i64::from(TOLERANCE_LPC_Q12),
            );
        }
    }

    // ---- EGAINS: the indices and the offset are discrete; lambda is continuous ----
    let gains = trace.gains.as_ref()?;
    tally.exact_i64(
        "GAINS",
        "quant_offset_type",
        match analysis.indices.quant_offset_type {
            QuantOffsetType::Low => 0,
            QuantOffsetType::High => 1,
        },
        gains.integer("qoff")?,
    );
    tally.exact_i64(
        "GAINS",
        "last_gain_index",
        i64::from(state.shape.last_gain_index),
        gains.integer("lastgain")?,
    );
    for (subframe, &theirs) in gains
        .integers("idx")
        .iter()
        .enumerate()
        .take(subframe_count)
    {
        tally.exact_i64(
            "GAINS",
            "index",
            i64::from(analysis.indices.gains_indices[subframe]),
            theirs,
        );
    }
    for (subframe, &theirs) in gains
        .floats("gains")
        .iter()
        .enumerate()
        .take(subframe_count)
    {
        tally.close_f64(
            "GAINS",
            "gain",
            f64::from(analysis.control.gains[subframe]),
            theirs,
            TOLERANCE_GAIN,
        );
    }
    tally.close_f64(
        "GAINS",
        "lambda",
        f64::from(analysis.control.lambda),
        gains.float("lambda")?,
        TOLERANCE_GAIN,
    );

    Some(())
}

fn signal_type_from(value: i64) -> SignalType {
    match value {
        0 => SignalType::Inactive,
        1 => SignalType::Unvoiced,
        _ => SignalType::Voiced,
    }
}

#[test]
fn silk_encoder_analysis_matches_instrumented_libopus() {
    let Some(dir) = trace_dir() else {
        eprintln!("silk encoder analysis: no encoder traces at reference/opus/silk_enc — skipping");
        return;
    };
    let mut traces: Vec<PathBuf> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("enctrace"))
        .collect();
    traces.sort();
    if traces.is_empty() {
        eprintln!("silk encoder analysis: reference/opus/silk_enc holds no .enctrace — skipping");
        return;
    }

    let mut tally = Tally::default();
    let mut coverage = Coverage::default();
    let mut streams = 0usize;

    for path in &traces {
        let frames = read_trace(path);
        if frames.is_empty() {
            continue;
        }
        streams += 1;
        let name = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("?")
            .to_string();
        for (unit, frame) in &frames {
            if !frame.is_complete() {
                // The last frame of a stream can be cut short by the frame cap.
                continue;
            }
            score_frame(&name, *unit, frame, &mut tally, &mut coverage);
        }
    }

    let total_compared: usize = tally.compared.values().sum();
    let total_failed: usize = tally.failed.values().sum();
    eprintln!(
        "silk encoder analysis: {streams} streams, {} frames, {total_compared} fields compared, \
         {total_failed} mismatched",
        coverage.frames
    );
    for (group, compared) in &tally.compared {
        let failed = tally.failed.get(group).copied().unwrap_or(0);
        let frames = tally.frames_failed.get(group).copied().unwrap_or(0);
        eprintln!("  {group}: {compared} compared, {failed} mismatched in {frames} frames");
    }
    eprintln!(
        "  coverage: voiced {} / interpolated {} / warped {} / order-10 {} / order-16 {} / \
         10 ms {} / 20 ms {}",
        coverage.voiced,
        coverage.interpolated,
        coverage.warped,
        coverage.order_10,
        coverage.order_16,
        coverage.ten_ms,
        coverage.twenty_ms
    );

    assert!(
        total_failed == 0,
        "silk encoder analysis differs from libopus in {total_failed} of {total_compared} fields:\n  {}",
        tally.examples.join("\n  ")
    );

    // Non-vacuous: a run that scored nothing, or that never took a branch, has not tested it.
    assert!(
        coverage.frames >= 200,
        "only {} frames scored; the dumps look truncated",
        coverage.frames
    );
    assert!(
        coverage.order_10 > 0 && coverage.order_16 > 0,
        "one codebook order never ran"
    );
    assert!(
        coverage.ten_ms > 0 && coverage.twenty_ms > 0,
        "one frame duration never ran"
    );
    assert!(coverage.warped > 0, "the warped shaping path never ran");
    assert!(coverage.voiced > 0, "no frame was ever declared voiced");
    assert!(
        total_compared > 50_000,
        "only {total_compared} fields compared; the harness is not exercising the analysis"
    );
}

/// The trace parser itself, on a fixture with the shapes it has to survive: a bit-pattern tail, a
/// comma list, a negative value, and a group this harness does not own.
#[test]
fn trace_parser_handles_the_shapes_it_meets() {
    let record = Record::parse("EIN u=3 fskhz=16 n=2 3F800000 BF800000");
    assert_eq!(record.integer("u"), Some(3));
    assert_eq!(record.integer("fskhz"), Some(16));
    assert_eq!(record.tail, vec!["3F800000", "BF800000"]);

    let record = Record::parse("ESHAPE u=0 tilt=-0.25,-0.5 iq=0.75");
    assert_eq!(record.floats("tilt"), vec![-0.25, -0.5]);
    assert_eq!(record.float("iq"), Some(0.75));
    assert!(record.floats("absent").is_empty());
    assert_eq!(record.integer("absent"), None);

    let record = Record::parse("ELTP u=1 idx=0,-3,4,4");
    assert_eq!(record.integers("idx"), vec![0, -3, 4, 4]);
}
