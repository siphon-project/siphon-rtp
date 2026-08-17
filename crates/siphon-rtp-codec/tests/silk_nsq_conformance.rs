//! SILK **noise-shaping quantiser** conformance: re-run the ported quantiser on the exact state and
//! parameters libopus ran it on, and diff every pulse, every seed and every state word it produced.
//!
//! # Why this exists on top of the end-to-end gate
//!
//! `silk_encode_conformance` already proves a great deal — 6 396 packets whose PCM is sample-exact
//! through both our decoder and libopus', with libopus' range decoder finishing every packet on the
//! `final_range` our encoder claimed. What it cannot do is *localise*. The NSQ is the last stage
//! before the bitstream and every stage above it feeds in, so when the end-to-end gate goes red it
//! says "wrong" without saying where: a mis-set shaping coefficient, a drifted gain, an off-by-one
//! in the rewhitening window and a genuine quantiser bug all look identical from the outside.
//!
//! This harness is the localising check. `reference/opus/silk_trace.patch` instruments
//! `silk_NSQ_wrapper_FLP`, and `reference/opus/dump_silk_nsq_trace.sh` drives it (recipe in
//! CONTRIBUTING.md). Every call to the quantiser dumps four self-contained lines — the state it
//! started from, the fixed-point parameters the wrapper derived, the float control values they were
//! derived from, and everything the call produced — so each call is scored in **isolation**. A
//! mismatch names one call in one frame of one configuration, and says whether it was the Q-domain
//! conversion, the pulse decision or the state the call left behind.
//!
//! # The rate-loop tag
//!
//! The gain-multiplier loop runs the quantiser up to seven times per frame — once for the LBRR copy
//! and once per loop iteration that misses the `gainsID` cache (`encode_frame_FLP.c:167-350`) —
//! each time from the *same* restored entry state but with different gains and sometimes a
//! different `Lambda`. A dump tagged only by the frame therefore cannot be aligned at all, so every
//! line carries `i=`, a per-frame call counter. The vectors here reach seven calls in one frame.
//!
//! # Tolerances: there are none, deliberately
//!
//! The quantiser is integer end to end — that is the whole point of it, since it has to compute
//! bit for bit the same prediction the decoder will compute from the same coded parameters. So
//! every field here is compared for **exact** equality: every pulse, every dither seed, every word
//! of `xq` / `sLTP_shp_Q14` / `sLPC_Q14` / `sAR2_Q14`, and every Q-domain parameter.
//!
//! The one float in scope is the *input* to `silk_float2int`, in the Q-domain conversion the
//! analysis front end leaves to the quantiser (`wrappers_FLP.c:118-153`, ported as
//! [`NsqInput::from_analysis`]). That is carried across as raw IEEE-754 bit patterns rather than as
//! decimal, so this side starts from the identical `f32` and round-half-to-even must land on the
//! identical integer. A tolerance anywhere in this file would be a bug, not a relaxation.
//!
//! Skips gracefully when the dumps are absent (`SIPHON_RTP_REQUIRE_VECTORS=1` turns that into a
//! failure, via `reference_vectors.rs`), and refuses to pass vacuously: it requires a non-trivial
//! number of scored calls, both quantiser variants, the warped and unwarped shaping filters, both
//! codebook orders, both frame durations, voiced and unvoiced frames, the interpolated two-filter
//! path, an LBRR call, and at least one frame that called the quantiser more than once.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use siphon_rtp_codec::opus::silk::enc::float::float2int;
use siphon_rtp_codec::opus::silk::enc::frame::{AnalysisControl, SideIndices};
use siphon_rtp_codec::opus::silk::enc::nsq::{
    quantize, NsqConfig, NsqInput, NsqState, NSQ_LPC_BUF_LENGTH,
};
use siphon_rtp_codec::opus::silk::enc::MAX_SHAPE_LPC_ORDER;
use siphon_rtp_codec::opus::silk::types::{
    QuantOffsetType, SignalType, LTP_ORDER, MAX_FRAME_LENGTH, MAX_LPC_ORDER, MAX_NB_SUBFR,
};

/// `reference/opus/silk_nsq`, if the quantiser traces have been dumped.
fn trace_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus/silk_nsq");
    dir.is_dir().then_some(dir)
}

/// One `KEY ...` trace line, parsed into `name=value` pairs.
#[derive(Debug, Default, Clone)]
struct Record {
    fields: BTreeMap<String, String>,
}

impl Record {
    fn parse(line: &str) -> Self {
        let mut record = Self::default();
        for token in line.split_whitespace().skip(1) {
            if let Some((key, value)) = token.split_once('=') {
                record.fields.insert(key.to_string(), value.to_string());
            }
        }
        record
    }

    fn integer(&self, key: &str) -> Option<i64> {
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

    /// A comma list of raw IEEE-754 bit patterns, as `silk_nsq_trace_fbits` writes them.
    fn floats(&self, key: &str) -> Vec<f32> {
        self.fields
            .get(key)
            .map(|value| {
                value
                    .split(',')
                    .filter(|piece| !piece.is_empty())
                    .filter_map(|piece| u32::from_str_radix(piece, 16).ok())
                    .map(f32::from_bits)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The four trace groups belonging to one call to `silk_NSQ_wrapper_FLP`.
#[derive(Debug, Default, Clone)]
struct CallTrace {
    entry: Option<Record>,
    input: Option<Record>,
    control: Option<Record>,
    output: Option<Record>,
}

impl CallTrace {
    fn is_complete(&self) -> bool {
        self.entry.is_some()
            && self.input.is_some()
            && self.control.is_some()
            && self.output.is_some()
    }
}

/// Read one `.nsqtrace` into per-call groups, keyed by `(frame, call within frame)`.
///
/// Groups this harness does not own — the decoder-side `NLSFRES` / `NLSFRAW` / `NLSF` lines the
/// encoder emits when `silk_NLSF_encode` calls `silk_NLSF_decode`, the analysis groups when the
/// dump was taken without suppressing them, and anything a future stage adds — are ignored. That is
/// the shared patch's contract: a harness must skip what it does not consume, or whichever stage
/// extended the patch last breaks all its siblings.
fn read_trace(path: &Path) -> BTreeMap<(i64, i64), CallTrace> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let mut calls: BTreeMap<(i64, i64), CallTrace> = BTreeMap::new();
    for line in text.lines() {
        let Some(key) = line.split_whitespace().next() else {
            continue;
        };
        let slot: fn(&mut CallTrace) -> &mut Option<Record> = match key {
            "ENSQSTATE" => |call| &mut call.entry,
            "ENSQIN" => |call| &mut call.input,
            "ENSQFLT" => |call| &mut call.control,
            "ENSQ" => |call| &mut call.output,
            _ => continue,
        };
        let record = Record::parse(line);
        let (Some(frame), Some(index)) = (record.integer("u"), record.integer("i")) else {
            continue;
        };
        if frame < 0 || index < 0 {
            continue;
        }
        *slot(calls.entry((frame, index)).or_default()) = Some(record);
    }
    calls
}

/// Running comparison state: one entry per named field group.
#[derive(Debug, Default)]
struct Tally {
    /// Fields compared, per group.
    compared: BTreeMap<String, usize>,
    /// Fields that differed, per group.
    failed: BTreeMap<String, usize>,
    /// The first few failure descriptions, for the assertion message.
    examples: Vec<String>,
    /// Stream, frame and call currently being scored, prefixed to every failure so a mismatch names
    /// the configuration it came from rather than leaving it to be bisected.
    context: String,
    /// Calls in which at least one field of a group differed, per group — a far more useful number
    /// than the field count when one bad call contributes three hundred fields.
    calls_failed: BTreeMap<String, usize>,
    /// Groups already counted as failing for the current call.
    call_groups_seen: Vec<String>,
}

impl Tally {
    fn begin_call(&mut self, context: String) {
        self.context = context;
        self.call_groups_seen.clear();
    }

    /// Add to a group's compared count without allocating its name again — this runs three million
    /// times over a full dump, so it looks the key up rather than building an owned `entry` key.
    fn count(&mut self, group: &str, fields: usize) {
        match self.compared.get_mut(group) {
            Some(slot) => *slot += fields,
            None => {
                self.compared.insert(group.to_string(), fields);
            }
        }
    }

    /// Record one mismatch. Only ever reached off the happy path, so it is free to allocate.
    fn fail(&mut self, group: &str, describe: impl FnOnce() -> String) {
        *self.failed.entry(group.to_string()).or_default() += 1;
        if !self.call_groups_seen.iter().any(|seen| seen == group) {
            self.call_groups_seen.push(group.to_string());
            *self.calls_failed.entry(group.to_string()).or_default() += 1;
        }
        if self.examples.len() < 24 {
            self.examples
                .push(format!("{} {}", self.context, describe()));
        }
    }

    /// Every comparison in this harness is exact — see the module docs on why a tolerance here
    /// would be a bug.
    fn exact(&mut self, group: &str, label: &str, ours: i64, theirs: i64) {
        self.count(group, 1);
        if ours != theirs {
            self.fail(group, || {
                format!("{group}/{label}: ours {ours} != libopus {theirs}")
            });
        }
    }

    /// The same, elementwise over our slice against the dump's list. Only the overlap is scored, so
    /// a truncated dump line shows up as a smaller compared count rather than as a mismatch.
    fn exact_slice(&mut self, group: &str, label: &str, ours: &[i64], theirs: &[i64]) {
        self.count(group, ours.len().min(theirs.len()));
        for (index, (&our, &their)) in ours.iter().zip(theirs.iter()).enumerate() {
            if our != their {
                self.fail(group, || {
                    format!("{group}/{label}[{index}]: ours {our} != libopus {their}")
                });
            }
        }
    }
}

/// What the harness observed, so a vacuous pass can be detected.
#[derive(Debug, Default)]
struct Coverage {
    calls: usize,
    plain: usize,
    delayed_decision: usize,
    warped: usize,
    unwarped_delayed: usize,
    voiced: usize,
    unvoiced: usize,
    interpolated: usize,
    lbrr: usize,
    order_10: usize,
    order_16: usize,
    ten_ms: usize,
    twenty_ms: usize,
    /// Calls that were not the first of their frame — i.e. the rate loop actually re-ran the
    /// quantiser, which is the only reason the `i=` tag exists.
    retries: usize,
    /// Frames whose quantiser ran more than once.
    retried_frames: usize,
}

/// Rebuild the quantiser's geometry and search depth from the dump.
fn config_from(entry: &Record) -> Option<NsqConfig> {
    Some(NsqConfig {
        subframe_length: entry.integer("subfr")? as usize,
        subframe_count: entry.integer("nsubfr")? as usize,
        ltp_memory_length: entry.integer("ltpmem")? as usize,
        predict_lpc_order: entry.integer("order")? as usize,
        shaping_lpc_order: entry.integer("shapeorder")? as usize,
        warping_q16: entry.integer("warp")? as i32,
        delayed_decision_states: entry.integer("deldec")? as usize,
    })
}

fn signal_type_from(value: i64) -> SignalType {
    match value {
        0 => SignalType::Inactive,
        1 => SignalType::Unvoiced,
        _ => SignalType::Voiced,
    }
}

/// Rebuild the entry state. Only the first `ltp_mem_length` entries of `xq` and `sLTP_shp_Q14` are
/// live across a call — the tail is written by the frame itself and then slid back by exactly that
/// much (`NSQ.c:171-172`) — so that is what the dump carries and what is restored here. If the port
/// ever read past it, the zeros left behind would not match libopus' stale tail and the exit-state
/// diff would say so.
fn state_from(entry: &Record, config: &NsqConfig) -> Option<NsqState> {
    let mut state = NsqState {
        lf_ar_shaping_q14: entry.integer("lfar")? as i32,
        difference_shaping_q14: entry.integer("diff")? as i32,
        previous_lag: entry.integer("lagprev")? as i32,
        ltp_buffer_index: entry.integer("ltpidx")? as usize,
        shaping_buffer_index: entry.integer("shpidx")? as usize,
        rand_seed: entry.integer("randseed")? as i32,
        previous_gain_q16: entry.integer("prevgain")? as i32,
        rewhitened: entry.integer("rewhite")? != 0,
        // Everything not restored below starts at zero, which is what the doc comment above is
        // about: `NsqState::default()` zeroes the tail of both long buffers.
        ..NsqState::default()
    };
    for (slot, &value) in state
        .quantised_output
        .iter_mut()
        .zip(entry.integers("xq").iter())
        .take(config.ltp_memory_length)
    {
        *slot = value as i16;
    }
    for (slot, &value) in state
        .shaping_signal_q14
        .iter_mut()
        .zip(entry.integers("shp").iter())
        .take(config.ltp_memory_length)
    {
        *slot = value as i32;
    }
    for (slot, &value) in state
        .lpc_state_q14
        .iter_mut()
        .zip(entry.integers("slpc").iter())
        .take(NSQ_LPC_BUF_LENGTH)
    {
        *slot = value as i32;
    }
    for (slot, &value) in state
        .shaping_state_q14
        .iter_mut()
        .zip(entry.integers("sar2").iter())
        .take(MAX_SHAPE_LPC_ORDER)
    {
        *slot = value as i32;
    }
    Some(state)
}

/// Rebuild the quantiser's parameters straight from the Q-domain values libopus handed the
/// quantiser, so the quantiser itself is scored on libopus' inputs rather than on ours.
fn input_from(input: &Record, config: &NsqConfig) -> Option<NsqInput> {
    let mut nsq = NsqInput {
        gains_q16: [0; MAX_NB_SUBFR],
        prediction_coefficients_q12: [[0; MAX_LPC_ORDER]; 2],
        ltp_coefficients_q14: [0; MAX_NB_SUBFR * LTP_ORDER],
        shaping_ar_q13: [0; MAX_NB_SUBFR * MAX_SHAPE_LPC_ORDER],
        harmonic_shape_gain_q14: [0; MAX_NB_SUBFR],
        tilt_q14: [0; MAX_NB_SUBFR],
        lf_shape_q14: [0; MAX_NB_SUBFR],
        lambda_q10: input.integer("lambda")? as i32,
        ltp_scale_q14: input.integer("ltpscale")? as i32,
        pitch_lags: [0; MAX_NB_SUBFR],
        signal_type: signal_type_from(input.integer("type")?),
        quant_offset_type: if input.integer("qoff")? == 0 {
            QuantOffsetType::Low
        } else {
            QuantOffsetType::High
        },
        interpolation_factor_q2: input.integer("interp")? as i8,
        seed: input.integer("sd")? as u8,
    };
    for (slot, &value) in nsq.gains_q16.iter_mut().zip(input.integers("gains").iter()) {
        *slot = value as i32;
    }
    for (half, key) in ["a0", "a1"].iter().enumerate() {
        for (slot, &value) in nsq.prediction_coefficients_q12[half]
            .iter_mut()
            .zip(input.integers(key).iter())
        {
            *slot = value as i16;
        }
    }
    for (slot, &value) in nsq
        .ltp_coefficients_q14
        .iter_mut()
        .zip(input.integers("ltp").iter())
    {
        *slot = value as i16;
    }
    // The dump packs `AR_Q13` down to `shapingLPCOrder` coefficients per subframe; the port keeps
    // libopus' `MAX_SHAPE_LPC_ORDER` stride, so unpack it back out.
    for (index, &value) in input.integers("ar").iter().enumerate() {
        let subframe = index / config.shaping_lpc_order;
        let tap = index % config.shaping_lpc_order;
        if subframe < MAX_NB_SUBFR && tap < MAX_SHAPE_LPC_ORDER {
            nsq.shaping_ar_q13[subframe * MAX_SHAPE_LPC_ORDER + tap] = value as i16;
        }
    }
    for (key, target) in [
        ("harm", &mut nsq.harmonic_shape_gain_q14),
        ("tilt", &mut nsq.tilt_q14),
        ("lfshp", &mut nsq.lf_shape_q14),
        ("lags", &mut nsq.pitch_lags),
    ] {
        for (slot, &value) in target.iter_mut().zip(input.integers(key).iter()) {
            *slot = value as i32;
        }
    }
    Some(nsq)
}

/// Re-run the Q-domain conversion the analysis front end leaves to the quantiser
/// (`silk_NSQ_wrapper_FLP`, `wrappers_FLP.c:118-153`) from the float control values libopus
/// converted, and diff it against what libopus produced. This is what separates "we converted
/// differently" from "we quantised differently" when a pulse disagrees.
fn score_conversion(
    control: &Record,
    input: &Record,
    theirs: &NsqInput,
    config: &NsqConfig,
    tally: &mut Tally,
) -> Option<()> {
    let order = config.predict_lpc_order;
    let subframes = config.subframe_count;

    let gains = control.floats("fgains");
    let first_half = control.floats("fa0");
    let second_half = control.floats("fa1");
    let taps = control.floats("fltp");
    let shaping_ar = control.floats("far");
    let harmonic = control.floats("fharm");
    let tilt = control.floats("ftilt");
    let lf_ar = control.floats("flfar");
    let lf_ma = control.floats("flfma");
    let lambda = *control.floats("flambda").first()?;

    // Only the fields `from_analysis` reads are rebuilt; the rest of the analysis' output does not
    // reach the quantiser at all and is left at zero rather than invented.
    let mut analysis = AnalysisControl {
        gains: [0.0; MAX_NB_SUBFR],
        gains_q16: [0; MAX_NB_SUBFR],
        unquantized_gains_q16: [0; MAX_NB_SUBFR],
        previous_gain_index_before: 0,
        prediction_coefficients: [[0.0; MAX_LPC_ORDER]; 2],
        ltp_coefficients: [0.0; MAX_NB_SUBFR * LTP_ORDER],
        ltp_scale: 0.0,
        pitch_lags: theirs.pitch_lags,
        shaping_ar: [0.0; MAX_NB_SUBFR * MAX_SHAPE_LPC_ORDER],
        lf_ma_shp: [0.0; MAX_NB_SUBFR],
        lf_ar_shp: [0.0; MAX_NB_SUBFR],
        tilt: [0.0; MAX_NB_SUBFR],
        harmonic_shape_gain: [0.0; MAX_NB_SUBFR],
        lambda,
        input_quality: 0.0,
        coding_quality: 0.0,
        prediction_gain: 0.0,
        ltp_prediction_gain_db: 0.0,
        residual_energy: [0.0; MAX_NB_SUBFR],
        unquantized_nlsf_q15: [0; MAX_LPC_ORDER],
        min_inverse_gain: 0.0,
    };
    for (slot, &value) in analysis.gains.iter_mut().zip(gains.iter()) {
        *slot = value;
    }
    for (half, source) in [first_half, second_half].into_iter().enumerate() {
        for (slot, &value) in analysis.prediction_coefficients[half]
            .iter_mut()
            .zip(source.iter())
        {
            *slot = value;
        }
    }
    for (slot, &value) in analysis.ltp_coefficients.iter_mut().zip(taps.iter()) {
        *slot = value;
    }
    for (index, &value) in shaping_ar.iter().enumerate() {
        let subframe = index / config.shaping_lpc_order;
        let tap = index % config.shaping_lpc_order;
        if subframe < MAX_NB_SUBFR && tap < MAX_SHAPE_LPC_ORDER {
            analysis.shaping_ar[subframe * MAX_SHAPE_LPC_ORDER + tap] = value;
        }
    }
    for (target, source) in [
        (&mut analysis.harmonic_shape_gain, harmonic),
        (&mut analysis.tilt, tilt),
        (&mut analysis.lf_ar_shp, lf_ar),
        (&mut analysis.lf_ma_shp, lf_ma),
    ] {
        for (slot, &value) in target.iter_mut().zip(source.iter()) {
            *slot = value;
        }
    }

    let mut indices = SideIndices::unvoiced(order);
    indices.signal_type = theirs.signal_type;
    indices.quant_offset_type = theirs.quant_offset_type;
    indices.nlsf.interpolation_factor_q2 = theirs.interpolation_factor_q2;
    indices.ltp_scale_index = input.integer("scaleidx")? as i8;

    let ours = NsqInput::from_analysis(&analysis, &indices, theirs.seed, config);

    tally.exact(
        "CONV",
        "lambda_q10",
        i64::from(ours.lambda_q10),
        i64::from(theirs.lambda_q10),
    );
    tally.exact(
        "CONV",
        "ltp_scale_q14",
        i64::from(ours.ltp_scale_q14),
        i64::from(theirs.ltp_scale_q14),
    );
    for subframe in 0..subframes {
        tally.exact(
            "CONV",
            "gain_q16",
            i64::from(ours.gains_q16[subframe]),
            i64::from(theirs.gains_q16[subframe]),
        );
        tally.exact(
            "CONV",
            "harmonic_shape_gain_q14",
            i64::from(ours.harmonic_shape_gain_q14[subframe]),
            i64::from(theirs.harmonic_shape_gain_q14[subframe]),
        );
        tally.exact(
            "CONV",
            "tilt_q14",
            i64::from(ours.tilt_q14[subframe]),
            i64::from(theirs.tilt_q14[subframe]),
        );
        // Two int16 coefficients packed into one word (`wrappers_FLP.c:127-128`); a difference in
        // either half shows up here.
        tally.exact(
            "CONV",
            "lf_shape_q14",
            i64::from(ours.lf_shape_q14[subframe]),
            i64::from(theirs.lf_shape_q14[subframe]),
        );
        for tap in 0..config.shaping_lpc_order {
            let index = subframe * MAX_SHAPE_LPC_ORDER + tap;
            tally.exact(
                "CONV",
                "shaping_ar_q13",
                i64::from(ours.shaping_ar_q13[index]),
                i64::from(theirs.shaping_ar_q13[index]),
            );
        }
        for tap in 0..LTP_ORDER {
            let index = subframe * LTP_ORDER + tap;
            tally.exact(
                "CONV",
                "ltp_coefficient_q14",
                i64::from(ours.ltp_coefficients_q14[index]),
                i64::from(theirs.ltp_coefficients_q14[index]),
            );
        }
    }
    for half in 0..2usize {
        for position in 0..order {
            tally.exact(
                "CONV",
                "prediction_coefficient_q12",
                i64::from(ours.prediction_coefficients_q12[half][position]),
                i64::from(theirs.prediction_coefficients_q12[half][position]),
            );
        }
    }
    Some(())
}

fn score_call(
    stream: &str,
    frame: i64,
    index: i64,
    trace: &CallTrace,
    tally: &mut Tally,
    coverage: &mut Coverage,
) -> Option<()> {
    let entry = trace.entry.as_ref()?;
    let input_record = trace.input.as_ref()?;
    let control_record = trace.control.as_ref()?;
    let output = trace.output.as_ref()?;

    let config = config_from(entry)?;
    let frame_length = config.frame_length();
    if frame_length == 0 || frame_length > MAX_FRAME_LENGTH {
        return None;
    }
    tally.begin_call(format!("[{stream} u={frame} i={index}]"));

    let input = input_from(input_record, &config)?;
    let mut state = state_from(entry, &config)?;

    // The frame driver's own conversion of the float input (`wrappers_FLP.c:151-153`), scored here
    // because this is the only dump that carries both sides of it.
    let float_input = control_record.floats("fx");
    let their_x16 = input_record.integers("x16");
    if float_input.len() < frame_length || their_x16.len() < frame_length {
        return None;
    }
    let mut x16 = [0i16; MAX_FRAME_LENGTH];
    for (position, slot) in x16.iter_mut().enumerate().take(frame_length) {
        *slot = float2int(float_input[position]) as i16;
        tally.exact("X16", "sample", i64::from(*slot), their_x16[position]);
    }

    score_conversion(control_record, input_record, &input, &config, tally)?;

    let mut pulses = [0i8; MAX_FRAME_LENGTH];
    let seed = quantize(&mut state, &input, &x16, &mut pulses, &config);

    coverage.calls += 1;
    if config.uses_delayed_decision() {
        coverage.delayed_decision += 1;
        if config.warping_q16 == 0 {
            coverage.unwarped_delayed += 1;
        }
    } else {
        coverage.plain += 1;
    }
    if config.warping_q16 > 0 {
        coverage.warped += 1;
    }
    match input.signal_type {
        SignalType::Voiced => coverage.voiced += 1,
        _ => coverage.unvoiced += 1,
    }
    if input.interpolation_factor_q2 != 4 {
        coverage.interpolated += 1;
    }
    if entry.integer("lbrr").unwrap_or(0) != 0 {
        coverage.lbrr += 1;
    }
    if config.predict_lpc_order == 10 {
        coverage.order_10 += 1;
    } else {
        coverage.order_16 += 1;
    }
    if config.subframe_count == 2 {
        coverage.ten_ms += 1;
    } else {
        coverage.twenty_ms += 1;
    }
    if index > 0 {
        coverage.retries += 1;
    }

    // ---- The pulse signal: this is the excitation that reaches the bitstream ----
    let their_pulses = output.integers("pulses");
    let ours: Vec<i64> = pulses[..frame_length]
        .iter()
        .map(|&p| i64::from(p))
        .collect();
    tally.exact_slice("PULSES", "pulse", &ours, &their_pulses);

    // ---- The coded seed: the delayed-decision search picks a winner among four ----
    tally.exact("SEED", "coded", i64::from(seed), output.integer("seed")?);

    // ---- The state the call leaves behind, which the next frame starts from ----
    for (label, ours, theirs) in [
        (
            "lf_ar_shaping_q14",
            i64::from(state.lf_ar_shaping_q14),
            output.integer("lfar")?,
        ),
        (
            "difference_shaping_q14",
            i64::from(state.difference_shaping_q14),
            output.integer("diff")?,
        ),
        (
            "previous_lag",
            i64::from(state.previous_lag),
            output.integer("lagprev")?,
        ),
        (
            "ltp_buffer_index",
            state.ltp_buffer_index as i64,
            output.integer("ltpidx")?,
        ),
        (
            "shaping_buffer_index",
            state.shaping_buffer_index as i64,
            output.integer("shpidx")?,
        ),
        (
            "rand_seed",
            i64::from(state.rand_seed),
            output.integer("randseed")?,
        ),
        (
            "previous_gain_q16",
            i64::from(state.previous_gain_q16),
            output.integer("prevgain")?,
        ),
        (
            "rewhitened",
            i64::from(state.rewhitened),
            output.integer("rewhite")?,
        ),
    ] {
        tally.exact("STATE", label, ours, theirs);
    }

    let ours: Vec<i64> = state.lpc_state_q14[..NSQ_LPC_BUF_LENGTH]
        .iter()
        .map(|&value| i64::from(value))
        .collect();
    tally.exact_slice("STATE", "lpc_state_q14", &ours, &output.integers("slpc"));

    let ours: Vec<i64> = state
        .shaping_state_q14
        .iter()
        .map(|&value| i64::from(value))
        .collect();
    tally.exact_slice(
        "STATE",
        "shaping_state_q14",
        &ours,
        &output.integers("sar2"),
    );

    let ours: Vec<i64> = state.quantised_output[..config.ltp_memory_length]
        .iter()
        .map(|&value| i64::from(value))
        .collect();
    tally.exact_slice("STATE", "quantised_output", &ours, &output.integers("xq"));

    let ours: Vec<i64> = state.shaping_signal_q14[..config.ltp_memory_length]
        .iter()
        .map(|&value| i64::from(value))
        .collect();
    tally.exact_slice(
        "STATE",
        "shaping_signal_q14",
        &ours,
        &output.integers("shp"),
    );

    Some(())
}

#[test]
fn silk_noise_shape_quantiser_matches_instrumented_libopus() {
    let Some(dir) = trace_dir() else {
        eprintln!("silk nsq: no quantiser traces at reference/opus/silk_nsq — skipping");
        return;
    };
    let mut traces: Vec<PathBuf> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("nsqtrace"))
        .collect();
    traces.sort();
    if traces.is_empty() {
        eprintln!("silk nsq: reference/opus/silk_nsq holds no .nsqtrace — skipping");
        return;
    }

    let mut tally = Tally::default();
    let mut coverage = Coverage::default();
    let mut streams = 0usize;

    for path in &traces {
        let calls = read_trace(path);
        if calls.is_empty() {
            continue;
        }
        streams += 1;
        let name = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("?")
            .to_string();
        let mut calls_per_frame: BTreeMap<i64, usize> = BTreeMap::new();
        for (&(frame, index), call) in &calls {
            if !call.is_complete() {
                // The last call of a stream can be cut short by the frame cap.
                continue;
            }
            *calls_per_frame.entry(frame).or_default() += 1;
            score_call(&name, frame, index, call, &mut tally, &mut coverage);
        }
        coverage.retried_frames += calls_per_frame.values().filter(|&&n| n > 1).count();
    }

    let total_compared: usize = tally.compared.values().sum();
    let total_failed: usize = tally.failed.values().sum();
    eprintln!(
        "silk nsq: {streams} streams, {} quantiser calls, {total_compared} fields compared, \
         {total_failed} mismatched",
        coverage.calls
    );
    for (group, compared) in &tally.compared {
        let failed = tally.failed.get(group).copied().unwrap_or(0);
        let calls = tally.calls_failed.get(group).copied().unwrap_or(0);
        eprintln!("  {group}: {compared} compared, {failed} mismatched in {calls} calls");
    }
    eprintln!(
        "  coverage: plain {} / delayed-decision {} (warped {}, unwarped {}) / voiced {} / \
         unvoiced {} / interpolated {} / lbrr {} / order-10 {} / order-16 {} / 10 ms {} / \
         20 ms {} / rate-loop retries {} in {} frames",
        coverage.plain,
        coverage.delayed_decision,
        coverage.warped,
        coverage.unwarped_delayed,
        coverage.voiced,
        coverage.unvoiced,
        coverage.interpolated,
        coverage.lbrr,
        coverage.order_10,
        coverage.order_16,
        coverage.ten_ms,
        coverage.twenty_ms,
        coverage.retries,
        coverage.retried_frames,
    );

    assert!(
        total_failed == 0,
        "silk nsq differs from libopus in {total_failed} of {total_compared} fields:\n  {}",
        tally.examples.join("\n  ")
    );

    // Non-vacuous: a run that scored nothing, or that never took a branch, has not tested it.
    assert!(
        coverage.calls >= 1_000,
        "only {} quantiser calls scored; the dumps look truncated",
        coverage.calls
    );
    assert!(
        coverage.plain > 0 && coverage.delayed_decision > 0,
        "one quantiser variant never ran (plain {}, delayed-decision {})",
        coverage.plain,
        coverage.delayed_decision
    );
    assert!(
        coverage.warped > 0 && coverage.unwarped_delayed > 0,
        "the delayed-decision search never ran both shaping filters (warped {}, unwarped {})",
        coverage.warped,
        coverage.unwarped_delayed
    );
    assert!(
        coverage.voiced > 0 && coverage.unvoiced > 0,
        "one signal type never ran, so the LTP and rewhitening paths are unproven"
    );
    assert!(
        coverage.interpolated > 0,
        "no frame used the interpolated two-filter path, so the subframe-2 rewhitening never ran"
    );
    assert!(coverage.lbrr > 0, "the LBRR quantisation never ran");
    assert!(
        coverage.order_10 > 0 && coverage.order_16 > 0,
        "one codebook order never ran"
    );
    assert!(
        coverage.ten_ms > 0 && coverage.twenty_ms > 0,
        "one frame duration never ran"
    );
    assert!(
        coverage.retried_frames > 0,
        "no frame ran the quantiser more than once, so the rate-loop tag proves nothing"
    );
    assert!(
        total_compared > 1_000_000,
        "only {total_compared} fields compared; the harness is not exercising the quantiser"
    );
}

/// The trace parser itself, on the shapes it has to survive: a comma list, a negative value, a
/// bit-pattern list, and a group this harness does not own.
#[test]
fn trace_parser_handles_the_shapes_it_meets() {
    let record = Record::parse("ENSQSTATE u=7 i=2 lbrr=0 lfar=-2412 slpc=1,-2,3");
    assert_eq!(record.integer("u"), Some(7));
    assert_eq!(record.integer("i"), Some(2));
    assert_eq!(record.integer("lfar"), Some(-2412));
    assert_eq!(record.integers("slpc"), vec![1, -2, 3]);
    assert!(record.integers("absent").is_empty());
    assert_eq!(record.integer("absent"), None);

    let record = Record::parse("ENSQFLT u=0 i=0 fgains=43840000,BF800000");
    assert_eq!(record.floats("fgains"), vec![264.0, -1.0]);

    // A group this harness does not own must not become a call.
    let calls = {
        let mut map: BTreeMap<(i64, i64), CallTrace> = BTreeMap::new();
        for line in ["NLSFRES u=-1 n=16 138", "ENSQ u=1 i=0 seed=2 pulses=0,1,-1"] {
            let Some(key) = line.split_whitespace().next() else {
                continue;
            };
            if key != "ENSQ" {
                continue;
            }
            let record = Record::parse(line);
            let (Some(frame), Some(index)) = (record.integer("u"), record.integer("i")) else {
                continue;
            };
            map.entry((frame, index)).or_default().output = Some(record);
        }
        map
    };
    assert_eq!(calls.len(), 1);
    assert!(!calls[&(1, 0)].is_complete());
    assert_eq!(
        calls[&(1, 0)]
            .output
            .as_ref()
            .map(|record| record.integers("pulses")),
        Some(vec![0, 1, -1])
    );
}
