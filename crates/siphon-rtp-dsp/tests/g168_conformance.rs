//! ITU-T **G.168** (digital network echo cancellers) conformance harness for the MDF echo canceller.
//!
//! G.168 is the software-reproducible acceptance yardstick for an echo canceller: it specifies the
//! excitation (the **composite source signal**, CSS — G.168 §6.4.1.2 and Annex C), a set of **echo
//! path models** (G.168 Annex D), and a family of tests (convergence, steady-state returned-echo
//! level, double-talk, non-divergence — G.168 §6.4.2–6.4.4). This harness encodes the core scenarios
//! as deterministic golden thresholds driven by a logical sample-clock and a fixed-seed PRNG (no wall
//! clock, no audio hardware), exercising the [`EchoCanceller`] MDF / partitioned-block frequency-domain
//! backend (with the two-path NCC double-talk detector) added in this PR.
//!
//! ## Documented deviations from the letter of G.168 (with citations)
//! The exact per-sample Annex C CSS waveform and the Annex D echo-path-model coefficient tables are ROM
//! data in the ITU-T Recommendation; they are **not reproduced verbatim here**. Reconstructing those
//! tables from memory would risk being silently wrong (worse than a clearly-labelled approximation), so
//! this harness uses two deterministic stand-ins:
//!
//! - a **deterministic composite CSS** (voiced burst + speech-shaped pseudo-noise burst + pause,
//!   repeated at the canonical ~350 ms period — the temporal/spectral structure G.168 Annex C
//!   prescribes) rather than the exact Annex C ROM; and
//! - a **representative dispersive echo-path FIR** with a G.168-class echo return loss (~12 dB) and a
//!   few-ms dispersion, rather than a specific Annex D model's exact taps.
//!
//! The *test structure, envelope, and pass/fail semantics* follow G.168; the thresholds are stated in
//! ERLE (echo return loss enhancement) so they are independent of the exact model level. Where G.168
//! quotes an absolute returned-echo level, we assert the equivalent ERLE margin. Sampling is 8 kHz
//! (G.168 is a narrowband, 8 kHz specification).
//!
//! ## Why the MDF is exercised (not the time-domain NLMS)
//! This is the MDF PR's acceptance anchor, so the canceller under test is `EchoCanceller::with_mdf(…)`
//! (optionally `.with_two_path_dtd()` / `with_mdf_delay_estimation`). The G.168 model's ~12 dB ERL is a
//! loud echo that trips the fixed-threshold Geigel screen, so the double-talk scenario uses the
//! scale-independent two-path NCC (the detector the two-path PR added, here composed with the MDF).

use siphon_rtp_dsp::EchoCanceller;

/// Narrowband sample rate — G.168 is an 8 kHz specification.
const SAMPLE_RATE_HZ: u32 = 8_000;
/// 20 ms frame (the pipeline cadence the canceller consumes).
const FRAME: usize = 160;
/// i16 full-scale, for normalized-level bookkeeping.
const FULL_SCALE: f64 = 32_768.0;

// ---- deterministic fixed-seed PRNG (splitmix64 → white f32 in [-1, 1)); no external rand ----
struct SplitMix64 {
    state: u64,
}
impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform white noise in `[-amplitude, amplitude)`.
    fn next_noise(&mut self, amplitude: f32) -> f32 {
        let unit = (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32; // [0, 1)
        (unit * 2.0 - 1.0) * amplitude
    }
}

// ---------------------------------------------------------------------------------------------------
// G.168 composite source signal (CSS) — §6.4.1.2 / Annex C (structural approximation, see module doc)
// ---------------------------------------------------------------------------------------------------

/// CSS period: the canonical ~350 ms (2800 samples @ 8 kHz) of G.168 Annex C.
const CSS_PERIOD: usize = 2_800;
/// Voiced burst: ~50 ms of a periodic, decaying tone-complex (pitch + formant-like harmonics).
const CSS_VOICED: usize = 400;
/// Pseudo-noise burst: ~150 ms of speech-spectrum-shaped random noise (the unvoiced component).
const CSS_NOISE: usize = 1_200;
// The remaining ~150 ms (`CSS_PERIOD - CSS_VOICED - CSS_NOISE` = 1200 samples) is the pause (silence).

/// Active (non-pause) speech level of the CSS in normalized full-scale RMS — a G.168-class test level
/// (~−16 dBFS).
const CSS_LEVEL: f32 = 0.16;

/// Generate `periods` of the deterministic composite source signal (voiced + pseudo-noise + pause) as
/// normalized `f32` in `[-1, 1)`. The voiced burst is a fixed harmonic complex (so it is periodic and
/// deterministic); the noise burst is speech-shaped white noise from the fixed-seed PRNG; the pause is
/// silence. This reproduces the CSS *temporal envelope and spectral coverage* G.168 Annex C prescribes
/// (see the module-level deviation note).
fn composite_source_signal(periods: usize, seed: u64) -> Vec<f32> {
    let mut prng = SplitMix64::new(seed);
    let mut signal = vec![0.0f32; periods * CSS_PERIOD];
    for period in 0..periods {
        let base = period * CSS_PERIOD;
        // Voiced: sum of a 150 Hz pitch and its first few harmonics, decaying across the burst.
        for i in 0..CSS_VOICED {
            let t = i as f32 / SAMPLE_RATE_HZ as f32;
            let envelope = (1.0 - i as f32 / CSS_VOICED as f32).max(0.0);
            let harmonics = (2.0 * std::f32::consts::PI * 150.0 * t).sin()
                + 0.6 * (2.0 * std::f32::consts::PI * 300.0 * t).sin()
                + 0.35 * (2.0 * std::f32::consts::PI * 450.0 * t).sin()
                + 0.2 * (2.0 * std::f32::consts::PI * 900.0 * t).sin();
            signal[base + i] = envelope * harmonics;
        }
        // Pseudo-noise: speech-shaped white noise (a light 1-pole low-pass tilt approximates the
        // speech spectrum roll-off).
        let mut previous = 0.0f32;
        for i in 0..CSS_NOISE {
            let white = prng.next_noise(1.0);
            previous = 0.85 * previous + 0.15 * white; // gentle spectral tilt
            signal[base + CSS_VOICED + i] = previous;
        }
        // Pause: the remainder of the period stays silent (already 0.0).
    }
    // Scale the whole signal so the active (non-pause) RMS is exactly the CSS test level.
    let mut active_sum_sq = 0.0f64;
    let mut active_count = 0usize;
    for period in 0..periods {
        for i in 0..CSS_VOICED + CSS_NOISE {
            let value = f64::from(signal[period * CSS_PERIOD + i]);
            active_sum_sq += value * value;
            active_count += 1;
        }
    }
    let active_rms = (active_sum_sq / active_count.max(1) as f64).sqrt();
    if active_rms > 0.0 {
        let scale = (f64::from(CSS_LEVEL) / active_rms) as f32;
        for sample in signal.iter_mut() {
            *sample *= scale;
        }
    }
    signal
}

// ---------------------------------------------------------------------------------------------------
// G.168 echo-path model — Annex D (representative dispersive FIR, see module doc)
// ---------------------------------------------------------------------------------------------------

/// A representative G.168-class **echo-path model** (Annex D): a decaying, oscillatory dispersive
/// impulse response spanning ~8 ms (64 taps @ 8 kHz). The coefficients are scaled to an **echo return
/// loss (ERL) of ~12 dB** (`Σ hₖ² ≈ 0.063`, i.e. echo power ≈ far power − 12 dB), a loud hybrid echo in
/// the G.168 range. This is a stand-in for a specific Annex D model's exact coefficient ROM (see the
/// module-level deviation note); the impulse-response *shape* (a direct coupling plus a decaying
/// dispersive tail) matches a network hybrid.
fn g168_echo_path_model() -> Vec<f32> {
    let taps = 64;
    let mut model = vec![0.0f32; taps];
    for (k, coefficient) in model.iter_mut().enumerate() {
        let decay = (-(k as f32) / 18.0).exp();
        *coefficient = 0.30 * decay * (0.55 * k as f32 + 0.3).cos();
    }
    // Normalize to the target ERL: scale so Σ hₖ² == 10^(-ERL/10).
    let target_erl_db = 12.0f32;
    let energy: f32 = model.iter().map(|h| h * h).sum();
    let target_energy = 10.0f32.powf(-target_erl_db / 10.0);
    let scale = (target_energy / energy).sqrt();
    for coefficient in model.iter_mut() {
        *coefficient *= scale;
    }
    model
}

// ---- signal helpers -------------------------------------------------------------------------------

fn denormalize(value: f32) -> i16 {
    let scaled = (value * FULL_SCALE as f32).round();
    if scaled >= i16::MAX as f32 {
        i16::MAX
    } else if scaled <= i16::MIN as f32 {
        i16::MIN
    } else {
        scaled as i16
    }
}

/// Convolve a continuous normalized far-end stream through the echo-path model (with an optional bulk
/// transport delay), returning the echo at the microphone as i16.
fn synthesize_echo(far: &[f32], model: &[f32], bulk_delay: usize) -> Vec<i16> {
    let mut echo = vec![0i16; far.len()];
    for (n, out) in echo.iter_mut().enumerate() {
        let mut accumulator = 0.0f32;
        for (k, &coefficient) in model.iter().enumerate() {
            let source = n as isize - bulk_delay as isize - k as isize;
            if source >= 0 {
                accumulator += coefficient * far[source as usize];
            }
        }
        *out = denormalize(accumulator);
    }
    echo
}

fn to_i16(stream: &[f32]) -> Vec<i16> {
    stream.iter().map(|&s| denormalize(s)).collect()
}

fn power(samples: &[i16]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum: f64 = samples.iter().map(|&s| f64::from(s) * f64::from(s)).sum();
    sum / samples.len() as f64
}

/// Segmental ERLE (dB) over the samples where the far-end is **active** (above a silence floor), with
/// the residual aligned to the echo by the canceller's block latency so the block-processing delay does
/// not bias the power ratio. Pause samples (no echo) are excluded.
fn active_erle_db(echo: &[i16], residual: &[i16], far: &[f32], latency: usize) -> f64 {
    let active_floor = (CSS_LEVEL as f64 * 0.25).powi(2); // a quarter of the active RMS, squared
    let mut echo_power = 0.0f64;
    let mut residual_power = 0.0f64;
    let mut count = 0usize;
    for index in 0..echo.len() {
        // Far activity that produced this echo sample.
        let far_sample = f64::from(far[index]);
        if far_sample * far_sample < active_floor {
            continue;
        }
        let aligned = index + latency;
        if aligned >= residual.len() {
            break;
        }
        echo_power += f64::from(echo[index]) * f64::from(echo[index]);
        residual_power += f64::from(residual[aligned]) * f64::from(residual[aligned]);
        count += 1;
    }
    if count == 0 {
        return f64::NAN;
    }
    let residual_power = (residual_power / count as f64).max(1.0e-9);
    let echo_power = echo_power / count as f64;
    10.0 * (echo_power / residual_power).log10()
}

/// Drive the canceller frame-by-frame over the whole `far`/`echo` pair (mixing in `near` when present),
/// returning the residual stream. Deterministic (logical clock).
fn run(canceller: &mut EchoCanceller, far: &[i16], echo: &[i16], near: Option<&[i16]>) -> Vec<i16> {
    let total = echo.len();
    let mut residual = vec![0i16; total];
    let frames = total / FRAME;
    for index in 0..frames {
        let range = index * FRAME..(index + 1) * FRAME;
        let mut mic: Vec<i16> = match near {
            Some(near) => echo[range.clone()]
                .iter()
                .zip(&near[range.clone()])
                .map(|(&e, &s)| e.saturating_add(s))
                .collect(),
            None => echo[range.clone()].to_vec(),
        };
        canceller.cancel(&mut mic, &far[range.clone()]);
        residual[range].copy_from_slice(&mic);
    }
    residual
}

// ---------------------------------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------------------------------

/// **CSS sanity** — the composite source signal has the G.168 temporal structure: an active
/// voiced+noise burst followed by a pause, repeated at the ~350 ms period, at the test level.
#[test]
fn g168_css_has_active_burst_and_pause_structure() {
    let css = composite_source_signal(3, 0x6168_0001);
    assert_eq!(css.len(), 3 * CSS_PERIOD);
    // Active portion carries energy at ~the test level; the pause is silent.
    let active = &css[0..CSS_VOICED + CSS_NOISE];
    let pause = &css[CSS_VOICED + CSS_NOISE..CSS_PERIOD];
    let active_rms = (active
        .iter()
        .map(|&s| f64::from(s) * f64::from(s))
        .sum::<f64>()
        / active.len() as f64)
        .sqrt();
    let pause_rms = (pause
        .iter()
        .map(|&s| f64::from(s) * f64::from(s))
        .sum::<f64>()
        / pause.len() as f64)
        .sqrt();
    assert!(
        (0.08..0.30).contains(&active_rms),
        "CSS active RMS {active_rms:.3} outside the G.168 test-level band"
    );
    assert!(
        pause_rms < 1.0e-6,
        "CSS pause must be silent (rms {pause_rms})"
    );
    // Determinism: identical seed → identical signal.
    let again = composite_source_signal(3, 0x6168_0001);
    assert_eq!(css, again);
}

/// **G.168 echo-path model** has the specified ~12 dB echo return loss.
#[test]
fn g168_echo_path_model_has_expected_erl() {
    let model = g168_echo_path_model();
    let energy: f32 = model.iter().map(|h| h * h).sum();
    let erl_db = -10.0 * energy.log10();
    assert!(
        (11.0..13.0).contains(&erl_db),
        "echo-path model ERL {erl_db:.1} dB (want ~12 dB)"
    );
}

/// **G.168 Test 2 — convergence** (§6.4.3): with the CSS as the far-end (Rin) and single-talk (no
/// near-end), the canceller must converge — the returned echo (Sout) drops well below the echo. Assert
/// the ERLE reaches the target within the G.168 convergence time (~1 s ≈ 3 CSS periods) and holds it.
#[test]
fn g168_test2_convergence_within_one_second() {
    let periods = 12;
    let model = g168_echo_path_model();
    let css = composite_source_signal(periods, 0x6168_2000);
    let far = to_i16(&css);
    let echo = synthesize_echo(&css, &model, 0);

    // MDF long-tail + two-path NCC (the loud ~12 dB-ERL echo trips the fixed Geigel screen, so the
    // scale-independent NCC is the double-talk detector).
    let mut canceller = EchoCanceller::with_mdf(SAMPLE_RATE_HZ, 512)
        .expect("build")
        .with_two_path_dtd();
    let latency = canceller.mdf_block_size().expect("mdf");
    let residual = run(&mut canceller, &far, &echo, None);

    // Steady-state ERLE over the last 4 periods must be deeply suppressed. (An ERLE aggregated over the
    // *whole* run would be dragged down by the pre-convergence residual — G.168 measures the settled
    // returned echo, so the steady window excludes the convergence transient.)
    let tail_start = (periods - 4) * CSS_PERIOD;
    let steady = active_erle_db(
        &echo[tail_start..],
        &residual[tail_start..],
        &css[tail_start..],
        latency,
    );
    assert!(
        steady >= 20.0,
        "G.168 test-2 steady ERLE {steady:.1} dB < 20 dB"
    );

    // Convergence *time*: the ERLE measured over period 3 alone (≈ 0.7–1.05 s) must already be high —
    // the filter converged inside the ~1 s G.168 convergence window. (`active_erle_db` aligns the
    // residual by the block latency, so the full residual tail is passed from the window start.)
    let convergence_period = 3;
    let window_start = convergence_period * CSS_PERIOD;
    let window_end = (convergence_period + 1) * CSS_PERIOD;
    let early = active_erle_db(
        &echo[window_start..window_end],
        &residual[window_start..],
        &css[window_start..window_end],
        latency,
    );
    if std::env::var_os("DUMP_G168").is_some() {
        eprintln!("[g168 test2] convergence(period3) {early:.1} dB, steady {steady:.1} dB");
    }
    assert!(
        early >= 15.0,
        "G.168 convergence too slow: ERLE only {early:.1} dB by ~1 s (want ≥ 15 dB)"
    );
}

/// **G.168 returned-echo level / steady-state** (§6.4.2, ACOM): after convergence the steady-state
/// ERLE over the final CSS periods meets a high target (the returned echo is deeply suppressed).
#[test]
fn g168_steady_state_returned_echo_level() {
    let periods = 16;
    let model = g168_echo_path_model();
    let css = composite_source_signal(periods, 0x6168_3000);
    let far = to_i16(&css);
    let echo = synthesize_echo(&css, &model, 0);

    let mut canceller = EchoCanceller::with_mdf(SAMPLE_RATE_HZ, 512)
        .expect("build")
        .with_two_path_dtd();
    let latency = canceller.mdf_block_size().expect("mdf");
    let residual = run(&mut canceller, &far, &echo, None);

    // Steady state = the last 4 periods.
    let tail_start = (periods - 4) * CSS_PERIOD;
    let steady = active_erle_db(
        &echo[tail_start..],
        &residual[tail_start..],
        &css[tail_start..],
        latency,
    );
    if std::env::var_os("DUMP_G168").is_some() {
        eprintln!("[g168 steady-state] {steady:.1} dB");
    }
    assert!(
        steady >= 25.0,
        "G.168 steady-state ERLE {steady:.1} dB < 25 dB (returned echo not suppressed enough)"
    );
}

/// **G.168 Test 3 — double-talk** (§6.4.4): with the CSS far-end and a simultaneous near-end talker,
/// the canceller must not diverge and must preserve the near-end. Assert (a) double-talk is flagged,
/// (b) the near-end is preserved (residual power tracks the near-end during the double-talk — a
/// diverging filter would instead amplify it), and (c) ERLE recovers to the target after the near-end
/// stops (the observable proof the weights survived the double-talk undamaged — G.168 is a black-box
/// returned-echo test, so non-divergence is asserted on the output, not on internal weights).
#[test]
fn g168_test3_double_talk_no_divergence_near_end_preserved() {
    let model = g168_echo_path_model();
    let converge_periods = 8;
    let double_talk_periods = 4;
    let recover_periods = 6;
    let periods = converge_periods + double_talk_periods + recover_periods;
    let css = composite_source_signal(periods, 0x6168_4000);
    let far = to_i16(&css);
    let echo = synthesize_echo(&css, &model, 0);

    // Near-end talker: a second, independent CSS (G.168 test 3 uses speech-like near-end), present only
    // during the double-talk window, at a level comparable to the far-end.
    let near_css = composite_source_signal(periods, 0x6168_4001);
    let mut near = vec![0i16; periods * CSS_PERIOD];
    let dt_start = converge_periods * CSS_PERIOD;
    let dt_end = (converge_periods + double_talk_periods) * CSS_PERIOD;
    for i in dt_start..dt_end {
        near[i] = denormalize(near_css[i]);
    }

    let mut canceller = EchoCanceller::with_mdf(SAMPLE_RATE_HZ, 512)
        .expect("build")
        .with_two_path_dtd();
    let latency = canceller.mdf_block_size().expect("mdf");

    let frames = echo.len() / FRAME;
    let mut residual = vec![0i16; echo.len()];
    let mut double_talk_seen = false;
    for index in 0..frames {
        let range = index * FRAME..(index + 1) * FRAME;
        let mut mic: Vec<i16> = echo[range.clone()]
            .iter()
            .zip(&near[range.clone()])
            .map(|(&e, &s)| e.saturating_add(s))
            .collect();
        canceller.cancel(&mut mic, &far[range.clone()]);
        let frame_start = range.start;
        residual[range].copy_from_slice(&mic);
        if (dt_start..dt_end).contains(&frame_start) {
            double_talk_seen |= canceller.double_talk_active();
        }
    }
    assert!(double_talk_seen, "G.168 test-3 double-talk must be flagged");

    // (b) Near-end preserved (and, by the same token, non-divergent): during double-talk the residual
    //     ≈ near-end (echo cancelled, near passes), so its active power tracks the near-end's within a
    //     few dB. A filter that diverged into the near-end would amplify it far past this band.
    let dt_residual = &residual[dt_start..dt_end];
    let dt_near = &near[dt_start..dt_end];
    let preservation_db = 10.0 * (power(dt_residual) / power(dt_near).max(1.0)).log10();
    if std::env::var_os("DUMP_G168").is_some() {
        eprintln!("[g168 test3] near-end preservation {preservation_db:.1} dB");
    }
    assert!(
        preservation_db.abs() <= 3.5,
        "near-end not preserved through double-talk: residual/near power {preservation_db:.1} dB"
    );

    // (c) Recovery: after the near-end stops, the ERLE over the recover periods returns to the target —
    //     only possible if the weights were protected through the double-talk (the non-divergence proof).
    let recover_start = dt_end + 2 * CSS_PERIOD; // skip the block-latency + re-settle transition
    let recovered = active_erle_db(
        &echo[recover_start..],
        &residual[recover_start..],
        &css[recover_start..],
        latency,
    );
    if std::env::var_os("DUMP_G168").is_some() {
        eprintln!("[g168 test3] recovered ERLE {recovered:.1} dB");
    }
    assert!(
        recovered >= 20.0,
        "G.168 test-3 ERLE recovered to only {recovered:.1} dB after double-talk"
    );
}

/// **G.168 non-divergence over the full CSS** (§6.4.1.2): the CSS's pauses and abrupt onsets must not
/// destabilize the filter. Assert the per-period returned-echo suppression (ERLE) stays healthy across
/// every period after convergence — a diverging FDAF would show a period whose ERLE collapses (residual
/// growing past the echo) — and the final ERLE is high.
#[test]
fn g168_non_divergence_over_full_css() {
    let periods = 14;
    let converged_by = 4; // periods allowed for convergence before the non-divergence floor applies
    let model = g168_echo_path_model();
    let css = composite_source_signal(periods, 0x6168_5000);
    let far = to_i16(&css);
    let echo = synthesize_echo(&css, &model, 0);

    let mut canceller = EchoCanceller::with_mdf(SAMPLE_RATE_HZ, 512)
        .expect("build")
        .with_two_path_dtd();
    let latency = canceller.mdf_block_size().expect("mdf");
    let residual = run(&mut canceller, &far, &echo, None);

    // Per-period active ERLE after convergence: none may collapse (the divergence signature).
    let mut worst = f64::INFINITY;
    for period in converged_by..periods {
        let start = period * CSS_PERIOD;
        let end = (period + 1) * CSS_PERIOD;
        let period_erle = active_erle_db(
            &echo[start..end],
            &residual[start..],
            &css[start..end],
            latency,
        );
        assert!(
            period_erle >= 15.0,
            "G.168 CSS period {period} ERLE {period_erle:.1} dB collapsed (< 15 dB) — divergence"
        );
        worst = worst.min(period_erle);
    }
    // Settled ERLE over the last 4 periods stays deeply suppressed (no late divergence).
    let tail_start = (periods - 4) * CSS_PERIOD;
    let final_erle = active_erle_db(
        &echo[tail_start..],
        &residual[tail_start..],
        &css[tail_start..],
        latency,
    );
    if std::env::var_os("DUMP_G168").is_some() {
        eprintln!("[g168 non-div] worst period {worst:.1} dB, final {final_erle:.1} dB");
    }
    assert!(
        final_erle >= 20.0,
        "G.168 non-divergence final ERLE {final_erle:.1} dB < 20 dB (worst period {worst:.1} dB)"
    );
}

/// **G.168 with an unknown flat delay** — the echo path model carries a bulk transport delay; the
/// composed MDF + GCC-PHAT recovers it and still meets the convergence target (the network echo path is
/// a hybrid delay plus dispersion — G.168 Annex D models include a flat delay).
#[test]
fn g168_convergence_with_unknown_flat_delay() {
    let periods = 16;
    let bulk_delay = 240; // 30 ms flat network delay
    let model = g168_echo_path_model();
    let css = composite_source_signal(periods, 0x6168_6000);
    let far = to_i16(&css);
    let echo = synthesize_echo(&css, &model, bulk_delay);

    let mut canceller = EchoCanceller::with_mdf_delay_estimation(SAMPLE_RATE_HZ, 512, 512)
        .expect("build")
        .with_two_path_dtd();
    let latency = canceller.mdf_block_size().expect("mdf");
    let residual = run(&mut canceller, &far, &echo, None);

    let estimated = canceller
        .estimated_bulk_delay()
        .expect("GCC-PHAT must lock the flat delay");
    assert!(
        estimated.abs_diff(bulk_delay) <= 8,
        "recovered flat delay {estimated} for injected {bulk_delay}"
    );
    let tail_start = (periods - 4) * CSS_PERIOD;
    let steady = active_erle_db(
        &echo[tail_start..],
        &residual[tail_start..],
        &css[tail_start..],
        latency,
    );
    if std::env::var_os("DUMP_G168").is_some() {
        eprintln!("[g168 flat-delay] recovered delay {estimated} (injected {bulk_delay}), steady {steady:.1} dB");
    }
    assert!(
        steady >= 20.0,
        "G.168 + flat-delay steady ERLE {steady:.1} dB < 20 dB"
    );
}
