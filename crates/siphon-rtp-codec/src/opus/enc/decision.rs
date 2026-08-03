//! The Opus encoder's discrete decisions (libopus `src/opus_encoder.c:142-1550`).
//!
//! Mode, bandwidth, stream channels, FEC and the SILK/CELT rate split. Every one of them is a
//! *discrete* choice that the decoder reads back out of the TOC byte, which makes this the one part
//! of an encoder where "close enough" is checkable: at the same configuration and the same input,
//! our TOC bytes must be libopus' TOC bytes, packet for packet. `opus_encode_conformance` asserts
//! exactly that.
//!
//! # The one thing that is deliberately not here: `analysis.c`
//!
//! libopus can drive these decisions from a tonality estimator (`src/analysis.c`, ~1200 lines: a
//! 480-point FFT per subframe, band tonality, a small neural net classifying speech versus music).
//! It is **not implemented**, and nothing here pretends it is — there is no disabled hook and no
//! placeholder `AnalysisInfo`. That is a supported libopus configuration, not an invention: built
//! with `DISABLE_FLOAT_API`, or simply at `complexity < 7`, libopus takes exactly the path this
//! module takes, with
//!
//! * `voice_ratio = -1`, so [`voice_estimate`] falls back to the *application*: 115/127 for VoIP,
//!   48/127 for audio (`opus_encoder.c:1286-1289`);
//! * `detected_bandwidth = 0`, so the bandwidth decision is driven by rate alone and never narrowed
//!   further (`opus_encoder.c:1510-1530`);
//! * `signalBandwidth = end - 1` inside CELT rather than the analysis' own estimate.
//!
//! The consequence, stated plainly so nobody has to measure it to find out: on **music** at a rate
//! where speech and music want different modes, this encoder makes the choice libopus makes without
//! its analysis, which is a slightly more speech-flavoured one. `signal_type` overrides it
//! ([`SignalHint`]) and the mode can be forced outright. Everything else — every threshold, every
//! hysteresis band, the interpolation over stereo width — is the reference's.

use crate::opus::packet::{Bandwidth, Mode};

/// What the caller is encoding for (`OPUS_APPLICATION_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Application {
    /// `OPUS_APPLICATION_VOIP` — speech. Biases the mode decision towards SILK by 8 kb/s, and swaps
    /// the input DC blocker for the pitch-tracking high-pass.
    Voip,
    /// `OPUS_APPLICATION_AUDIO` — general audio, no bias.
    Audio,
    /// `OPUS_APPLICATION_RESTRICTED_LOWDELAY` — CELT-only, no SILK look-ahead, no delay compensation.
    RestrictedLowdelay,
}

/// A caller's assertion about the content (`OPUS_SET_SIGNAL`), which replaces the estimator this
/// encoder does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignalHint {
    /// `OPUS_AUTO` — decide from the application alone (`opus_encoder.c:1286-1289`).
    #[default]
    Auto,
    /// `OPUS_SIGNAL_VOICE` — `voice_est = 127`.
    Voice,
    /// `OPUS_SIGNAL_MUSIC` — `voice_est = 0`.
    Music,
}

/// The five bandwidths as a 0..=4 index, which is how every threshold table here is addressed.
///
/// libopus uses `OPUS_BANDWIDTH_NARROWBAND` = 1101 … `OPUS_BANDWIDTH_FULLBAND` = 1105 and subtracts
/// the base at each use site; the index is the same number with the base already gone.
#[must_use]
pub fn bandwidth_index(bandwidth: Bandwidth) -> usize {
    match bandwidth {
        Bandwidth::Narrowband => 0,
        Bandwidth::Mediumband => 1,
        Bandwidth::Wideband => 2,
        Bandwidth::SuperWideband => 3,
        Bandwidth::Fullband => 4,
    }
}

/// The inverse of [`bandwidth_index`], saturating at the ends.
#[must_use]
pub fn bandwidth_from_index(index: usize) -> Bandwidth {
    match index {
        0 => Bandwidth::Narrowband,
        1 => Bandwidth::Mediumband,
        2 => Bandwidth::Wideband,
        3 => Bandwidth::SuperWideband,
        _ => Bandwidth::Fullband,
    }
}

/// `mono_voice_bandwidth_thresholds` (`opus_encoder.c:145`) — `(threshold, hysteresis)` per
/// NB↔MB / MB↔WB / WB↔SWB / SWB↔FB transition, in bit/s.
const MONO_VOICE_BANDWIDTH_THRESHOLDS: [i32; 8] =
    [9_000, 700, 9_000, 700, 13_500, 1_000, 14_000, 2_000];
/// `mono_music_bandwidth_thresholds` (`opus_encoder.c:151`).
const MONO_MUSIC_BANDWIDTH_THRESHOLDS: [i32; 8] =
    [9_000, 700, 9_000, 700, 11_000, 1_000, 12_000, 2_000];
/// `stereo_voice_bandwidth_thresholds` (`opus_encoder.c:157`).
const STEREO_VOICE_BANDWIDTH_THRESHOLDS: [i32; 8] =
    [9_000, 700, 9_000, 700, 13_500, 1_000, 14_000, 2_000];
/// `stereo_music_bandwidth_thresholds` (`opus_encoder.c:163`).
const STEREO_MUSIC_BANDWIDTH_THRESHOLDS: [i32; 8] =
    [9_000, 700, 9_000, 700, 11_000, 1_000, 12_000, 2_000];

/// `stereo_voice_threshold` / `stereo_music_threshold` (`opus_encoder.c:170`) — the equivalent rate
/// above which a stereo input is worth coding as two channels.
const STEREO_VOICE_THRESHOLD: i32 = 19_000;
const STEREO_MUSIC_THRESHOLD: i32 = 17_000;

/// `mode_thresholds[mono/stereo][voice/music]` (`opus_encoder.c:174`) — the equivalent rate above
/// which CELT-only beats SILK/hybrid.
const MODE_THRESHOLDS: [[i32; 2]; 2] = [
    /* mono   */ [64_000, 10_000],
    /* stereo */ [44_000, 10_000],
];

/// `fec_thresholds` (`opus_encoder.c:180`) — `(threshold, hysteresis)` per bandwidth for whether
/// in-band FEC is affordable.
const FEC_THRESHOLDS: [i32; 10] = [
    12_000, 1_000, // NB
    14_000, 1_000, // MB
    16_000, 1_000, // WB
    20_000, 1_000, // SWB
    22_000, 1_000, // FB
];

/// Probability of voice in Q7, 0..=127 (`opus_encoder.c:1276-1289`).
///
/// The `voice_ratio` branch of the C is unreachable here: it is only ever set from the tonality
/// analysis, which this encoder does not run (see the module docs), so an `Auto` hint lands on the
/// application default exactly as a `DISABLE_FLOAT_API` build does.
#[must_use]
pub fn voice_estimate(hint: SignalHint, application: Application) -> i32 {
    match hint {
        SignalHint::Voice => 127,
        SignalHint::Music => 0,
        SignalHint::Auto => match application {
            Application::Voip => 115,
            Application::Audio | Application::RestrictedLowdelay => 48,
        },
    }
}

/// `compute_equiv_rate` (`opus_encoder.c:898-929`) — the bitrate a 20 ms, complexity-10, VBR frame
/// would need for the same quality, which is the axis every threshold above is calibrated on.
///
/// `mode` is `None` before the mode has been chosen, which is a real state: the decision below runs
/// this three times, once with the mode still unknown.
#[must_use]
pub fn compute_equiv_rate(
    bitrate: i32,
    channels: usize,
    frame_rate: i32,
    vbr: bool,
    mode: Option<Mode>,
    complexity: i32,
    loss: i32,
) -> i32 {
    let mut equiv = bitrate;
    // Smaller frames pay a per-frame header overhead.
    if frame_rate > 50 {
        equiv -= (40 * channels as i32 + 20) * (frame_rate - 50);
    }
    // "CBR is about a 8% penalty for both SILK and CELT."
    if !vbr {
        equiv -= equiv / 12;
    }
    // "Complexity makes about 10% difference (from 0 to 10) in general."
    equiv = equiv * (90 + complexity) / 100;
    match mode {
        Some(Mode::Silk | Mode::Hybrid) => {
            // "SILK complexity 0-1 uses the non-delayed-decision NSQ, which costs about 20%."
            if complexity < 2 {
                equiv = equiv * 4 / 5;
            }
            equiv -= equiv * loss / (6 * loss + 10);
        }
        Some(Mode::Celt) => {
            // "CELT complexity 0-4 doesn't have the pitch filter, which costs about 10%."
            if complexity < 5 {
                equiv = equiv * 9 / 10;
            }
        }
        // Mode not known yet: half the SILK loss allowance.
        None => equiv -= equiv * loss / (12 * loss + 20),
    }
    equiv
}

/// `user_bitrate_to_bitrate` (`opus_encoder.c:639-648`).
///
/// `None` is `OPUS_AUTO`; `Some(bitrate)` is an explicit target. `OPUS_BITRATE_MAX` is expressed by
/// passing the buffer-filling rate directly, which is what the C computes for it.
#[must_use]
pub fn automatic_bitrate(sample_rate_hz: i32, channels: usize, frame_size: i32) -> i32 {
    let frame_size = if frame_size == 0 {
        sample_rate_hz / 400
    } else {
        frame_size
    };
    60 * sample_rate_hz / frame_size + sample_rate_hz * channels as i32
}

/// The running state the stereo-width estimator carries between frames (`StereoWidthState`,
/// `opus_encoder.c:68`).
#[derive(Debug, Clone, Copy, Default)]
pub struct StereoWidthState {
    /// Smoothed `<L,L>`, `<L,R>`, `<R,R>`.
    correlation: [f32; 3],
    /// Smoothed width, one-second time constant.
    smoothed_width: f32,
    /// Peak follower over the smoothed width.
    max_follower: f32,
}

/// `compute_stereo_width` (`opus_encoder.c:729-809`) — how *wide* the stereo image is, 0..=1.
///
/// Not "is it stereo": a hard-panned mono source and a true stereo recording both decorrelate, and
/// the measure is deliberately the product of a decorrelation term and a loudness-difference term so
/// that only a genuinely wide image scores high. It feeds the mode threshold's interpolation, which
/// is why a wide stereo image reaches CELT-only sooner than a narrow one.
pub fn compute_stereo_width(
    pcm: &[f32],
    frame_size: usize,
    sample_rate_hz: i32,
    state: &mut StereoWidthState,
) -> f32 {
    let frame_rate = sample_rate_hz / frame_size as i32;
    let short_alpha = 1.0 - 25.0 / frame_rate.max(50) as f32;
    let mut xx = 0f32;
    let mut xy = 0f32;
    let mut yy = 0f32;
    // "Unroll by 4 … we just discard the last two samples" for the one frame size that is not a
    // multiple of 4 (2.5 ms at 12 kHz).
    let mut index = 0usize;
    while index + 3 < frame_size {
        for offset in 0..4 {
            let left = pcm[2 * (index + offset)];
            let right = pcm[2 * (index + offset) + 1];
            xx += left * left;
            xy += left * right;
            yy += right * right;
        }
        index += 4;
    }
    // `!(x < 1e9)` in the C, which catches a NaN as well as a runaway magnitude; spelled out here
    // because a negated float comparison reads as a mistake.
    if !xx.is_finite() || xx >= 1e9 || !yy.is_finite() || yy >= 1e9 {
        xx = 0.0;
        xy = 0.0;
        yy = 0.0;
    }
    state.correlation[0] += short_alpha * (xx - state.correlation[0]);
    state.correlation[1] += short_alpha * (xy - state.correlation[1]);
    state.correlation[2] += short_alpha * (yy - state.correlation[2]);
    state.correlation[0] = state.correlation[0].max(0.0);
    state.correlation[1] = state.correlation[1].max(0.0);
    state.correlation[2] = state.correlation[2].max(0.0);

    // `QCONST16(8e-4f, 18)` scaled out of the fixed-point domain: the float build compares against
    // the same 8e-4 the fixed one does, because `celt_maxabs` there is already in the [-1,1] domain.
    if state.correlation[0].max(state.correlation[2]) > 8e-4 {
        let sqrt_xx = state.correlation[0].sqrt();
        let sqrt_yy = state.correlation[2].sqrt();
        let qrrt_xx = sqrt_xx.sqrt();
        let qrrt_yy = sqrt_yy.sqrt();
        state.correlation[1] = state.correlation[1].min(sqrt_xx * sqrt_yy);
        const EPSILON: f32 = 1e-15;
        let correlation = state.correlation[1] / (EPSILON + sqrt_xx * sqrt_yy);
        let loudness_difference = (qrrt_xx - qrrt_yy).abs() / (EPSILON + qrrt_xx + qrrt_yy);
        let width = (1.0 - correlation * correlation).max(0.0).sqrt() * loudness_difference;
        // Smoothing over one second.
        state.smoothed_width += (width - state.smoothed_width) / frame_rate as f32;
        // Peak follower.
        state.max_follower =
            (state.max_follower - 0.02 / frame_rate as f32).max(state.smoothed_width);
    }
    (20.0 * state.max_follower).min(1.0)
}

/// The stream-channel decision (`opus_encoder.c:1291-1316`).
///
/// A stereo input is coded as one channel below the rate where two are worth it. The threshold
/// interpolates between the music and voice values by `voice_est²`, and carries ±1 kb/s of
/// hysteresis so a stream hovering at the boundary does not flip channel count every frame.
#[must_use]
pub fn stream_channels(
    input_channels: usize,
    forced_channels: Option<usize>,
    previous_stream_channels: usize,
    equiv_rate: i32,
    voice_estimate: i32,
) -> usize {
    if input_channels != 2 {
        return input_channels;
    }
    if let Some(forced) = forced_channels {
        return forced;
    }
    let mut threshold = STEREO_MUSIC_THRESHOLD
        + ((voice_estimate * voice_estimate * (STEREO_VOICE_THRESHOLD - STEREO_MUSIC_THRESHOLD))
            >> 14);
    if previous_stream_channels == 2 {
        threshold -= 1_000;
    } else {
        threshold += 1_000;
    }
    if equiv_rate > threshold {
        2
    } else {
        1
    }
}

/// What the mode decision needs to know beyond the rate.
#[derive(Debug, Clone, Copy)]
pub struct ModeInputs {
    /// The application, which biases VoIP towards SILK.
    pub application: Application,
    /// Probability of voice in Q7, from [`voice_estimate`].
    pub voice_estimate: i32,
    /// Stereo width, 0..=1, from [`compute_stereo_width`].
    pub stereo_width: f32,
    /// The mode the previous frame used, if any — the hysteresis input.
    pub previous_mode: Option<Mode>,
    /// Whether in-band FEC is requested, and the reported loss: enough loss forces SILK, which is
    /// the only layer that carries FEC.
    pub use_in_band_fec: bool,
    pub packet_loss_percent: i32,
    /// Whether SILK's own DTX is in play, which also forces SILK on speech.
    pub silk_dtx: bool,
    /// `max_data_bytes` and the frame geometry, for the "too little space to be useful" override.
    pub max_data_bytes: i32,
    pub frame_size: i32,
    pub sample_rate_hz: i32,
    pub frame_rate: i32,
}

/// The mode decision (`opus_encoder.c:1330-1394`) — SILK/hybrid versus CELT-only.
///
/// Hybrid is *not* chosen here: `MODE_HYBRID` only appears later, when the bandwidth turns out to be
/// above wideband while the mode is SILK ([`promote_to_hybrid`]). The C is explicit that this
/// function must never switch to or from CELT-only afterwards, because the redundancy and prefill
/// logic keys off it.
#[must_use]
pub fn choose_mode(equiv_rate: i32, forced: Option<Mode>, inputs: &ModeInputs) -> Mode {
    if inputs.application == Application::RestrictedLowdelay {
        return Mode::Celt;
    }
    let mut mode = if let Some(forced) = forced {
        forced
    } else {
        // Interpolate the two thresholds on stereo width, then on the speech/music estimate.
        //
        // Both halves of `mode_music` read `mode_thresholds[1][1]` in the reference
        // (`opus_encoder.c:1358-1359`), so the interpolation collapses and the music threshold is
        // 10 kb/s flat. That is reproduced rather than "corrected": the thresholds either side of it
        // are calibrated against the behaviour libopus actually ships, and quietly using
        // `mode_thresholds[0][1]` for the mono term would move every mono music decision away from
        // the reference.
        let mode_voice = (1.0 - inputs.stereo_width) * MODE_THRESHOLDS[0][0] as f32
            + inputs.stereo_width * MODE_THRESHOLDS[1][0] as f32;
        let mode_music = (1.0 - inputs.stereo_width) * MODE_THRESHOLDS[1][1] as f32
            + inputs.stereo_width * MODE_THRESHOLDS[1][1] as f32;
        let (mode_voice, mode_music) = (mode_voice as i32, mode_music as i32);
        let mut threshold = mode_music
            + ((inputs.voice_estimate * inputs.voice_estimate * (mode_voice - mode_music)) >> 14);
        // "Bias towards SILK for VoIP because of some useful features."
        if inputs.application == Application::Voip {
            threshold += 8_000;
        }
        // Hysteresis.
        match inputs.previous_mode {
            Some(Mode::Celt) => threshold -= 4_000,
            Some(_) => threshold += 4_000,
            None => {}
        }
        let mut mode = if equiv_rate >= threshold {
            Mode::Celt
        } else {
            Mode::Silk
        };
        // FEC only exists in SILK, so enough loss forces it.
        if inputs.use_in_band_fec && inputs.packet_loss_percent > (128 - inputs.voice_estimate) >> 4
        {
            mode = Mode::Silk;
        }
        // Same for SILK's own DTX on speech.
        if inputs.silk_dtx && inputs.voice_estimate > 100 {
            mode = Mode::Silk;
        }
        // "If max_data_bytes represents less than 6 kb/s, switch to CELT-only mode."
        let floor_bps = if inputs.frame_rate > 50 { 9_000 } else { 6_000 };
        if inputs.max_data_bytes < floor_bps * inputs.frame_size / (inputs.sample_rate_hz * 8) {
            mode = Mode::Celt;
        }
        mode
    };
    // "Override the chosen mode to make sure we meet the requested frame size": SILK cannot do
    // anything shorter than 10 ms.
    if mode != Mode::Celt && inputs.frame_size < inputs.sample_rate_hz / 100 {
        mode = Mode::Celt;
    }
    mode
}

/// The automatic bandwidth decision (`opus_encoder.c:1441-1484`).
///
/// Walks down from fullband until the equivalent rate clears that step's threshold, with hysteresis
/// against the bandwidth this same function chose last time (`st->auto_bandwidth`, which is *not*
/// the bandwidth finally used — the caps below it can narrow that further without dragging the
/// hysteresis reference down with them).
#[must_use]
pub fn choose_bandwidth(
    equiv_rate: i32,
    voice_estimate: i32,
    stereo_input: bool,
    first_frame: bool,
    previous_auto_bandwidth: Bandwidth,
) -> Bandwidth {
    let (voice, music) = if stereo_input {
        (
            &STEREO_VOICE_BANDWIDTH_THRESHOLDS,
            &STEREO_MUSIC_BANDWIDTH_THRESHOLDS,
        )
    } else {
        (
            &MONO_VOICE_BANDWIDTH_THRESHOLDS,
            &MONO_MUSIC_BANDWIDTH_THRESHOLDS,
        )
    };
    let mut thresholds = [0i32; 8];
    for index in 0..8 {
        thresholds[index] = music[index]
            + ((voice_estimate * voice_estimate * (voice[index] - music[index])) >> 14);
    }

    let previous = bandwidth_index(previous_auto_bandwidth);
    let mut index = bandwidth_index(Bandwidth::Fullband);
    loop {
        // The table is indexed from mediumband, so the fullband step reads entry 3.
        let mut threshold = thresholds[2 * (index - 1)];
        let hysteresis = thresholds[2 * (index - 1) + 1];
        if !first_frame {
            if previous >= index {
                threshold -= hysteresis;
            } else {
                threshold += hysteresis;
            }
        }
        if equiv_rate >= threshold {
            break;
        }
        index -= 1;
        if index <= bandwidth_index(Bandwidth::Narrowband) {
            break;
        }
    }
    // "We don't use mediumband anymore, except when explicitly requested or during mode
    // transitions."
    if index == bandwidth_index(Bandwidth::Mediumband) {
        index = bandwidth_index(Bandwidth::Wideband);
    }
    bandwidth_from_index(index)
}

/// `decide_fec` (`opus_encoder.c:811-842`) — whether to ask SILK for LBRR, possibly by *narrowing
/// the bandwidth* until the rate is enough for it.
///
/// The bandwidth trade is the interesting half: above 5 % loss, libopus would rather send narrowband
/// with FEC than wideband without, because a concealed 20 ms gap costs more than 2 kHz of top end.
/// Returns the FEC decision and writes the (possibly reduced) bandwidth back.
pub fn decide_fec(
    use_in_band_fec: bool,
    packet_loss_percent: i32,
    last_fec: bool,
    mode: Mode,
    bandwidth: &mut Bandwidth,
    rate: i32,
) -> bool {
    if !use_in_band_fec || packet_loss_percent == 0 || mode == Mode::Celt {
        return false;
    }
    let original = *bandwidth;
    loop {
        let index = bandwidth_index(*bandwidth);
        let mut threshold = FEC_THRESHOLDS[2 * index];
        let hysteresis = FEC_THRESHOLDS[2 * index + 1];
        if last_fec {
            threshold -= hysteresis;
        } else {
            threshold += hysteresis;
        }
        // `silk_SMULWB(silk_MUL(threshold, 125 - min(loss, 25)), SILK_FIX_CONST(0.01, 16))`, i.e.
        // scale the threshold down as loss rises: FEC gets cheaper to justify.
        threshold =
            ((i64::from(threshold * (125 - packet_loss_percent.min(25))) * 655) >> 16) as i32;
        if rate > threshold {
            return true;
        }
        if packet_loss_percent <= 5 {
            return false;
        }
        if index > bandwidth_index(Bandwidth::Narrowband) {
            *bandwidth = bandwidth_from_index(index - 1);
        } else {
            break;
        }
    }
    // "Couldn't find any bandwidth to enable FEC, keep original bandwidth."
    *bandwidth = original;
    false
}

/// `compute_silk_rate_for_hybrid` (`opus_encoder.c:844-894`) — how much of a hybrid frame's budget
/// SILK gets, the rest going to CELT's high band.
///
/// A piecewise-linear table rather than a fraction, because the split is not scale-free: at 12 kb/s
/// SILK needs almost everything, at 64 kb/s it needs well under two thirds.
#[must_use]
pub fn compute_silk_rate_for_hybrid(
    rate: i32,
    bandwidth: Bandwidth,
    frame_20ms: bool,
    vbr: bool,
    fec: bool,
    channels: usize,
) -> i32 {
    /// `rate_table[][5]`: total, then SILK's share for {10 ms, 20 ms} × {no FEC, FEC}.
    const RATE_TABLE: [[i32; 5]; 7] = [
        [0, 0, 0, 0, 0],
        [12_000, 10_000, 10_000, 11_000, 11_000],
        [16_000, 13_500, 13_500, 15_000, 15_000],
        [20_000, 16_000, 16_000, 18_000, 18_000],
        [24_000, 18_000, 18_000, 21_000, 21_000],
        [32_000, 22_000, 22_000, 28_000, 28_000],
        [64_000, 38_000, 38_000, 50_000, 50_000],
    ];
    // "Do the allocation per-channel."
    let rate = rate / channels as i32;
    let entry = 1 + usize::from(frame_20ms) + 2 * usize::from(fec);
    let count = RATE_TABLE.len();
    let mut index = 1usize;
    while index < count {
        if RATE_TABLE[index][0] > rate {
            break;
        }
        index += 1;
    }
    let mut silk_rate = if index == count {
        // "For now, just give 50% of the extra bits to SILK."
        RATE_TABLE[count - 1][entry] + (rate - RATE_TABLE[count - 1][0]) / 2
    } else {
        let low = RATE_TABLE[index - 1][entry];
        let high = RATE_TABLE[index][entry];
        let x0 = RATE_TABLE[index - 1][0];
        let x1 = RATE_TABLE[index][0];
        (low * (x1 - rate) + high * (rate - x0)) / (x1 - x0)
    };
    if !vbr {
        // "Tiny boost to SILK for CBR."
        silk_rate += 100;
    }
    if bandwidth == Bandwidth::SuperWideband {
        silk_rate += 300;
    }
    silk_rate *= channels as i32;
    // "Small adjustment for stereo (calibrated for 32 kb/s)."
    if channels == 2 && rate >= 12_000 {
        silk_rate -= 1_000;
    }
    silk_rate
}

/// `gen_toc` (`opus_encoder.c:299-329`) — the table-of-contents byte (RFC 6716 §3.1, Table 2).
///
/// `frame_rate` is `Fs / frame_size`, so 400 is 2.5 ms and 16 is 60 ms. The frame-count code is
/// **not** set here; the caller ORs it in, exactly as `opus_encode_native` does.
#[must_use]
pub fn generate_toc(mode: Mode, frame_rate: i32, bandwidth: Bandwidth, channels: usize) -> u8 {
    let mut period = 0i32;
    let mut rate = frame_rate;
    while rate < 400 {
        rate <<= 1;
        period += 1;
    }
    let index = bandwidth_index(bandwidth) as i32;
    let mut toc = match mode {
        Mode::Silk => ((index as u8) << 5) | (((period - 2) as u8) << 3),
        Mode::Celt => {
            // CELT has no mediumband, so its table starts one step up and clamps below.
            let step = (index - bandwidth_index(Bandwidth::Mediumband) as i32).max(0) as u8;
            0x80 | (step << 5) | ((period as u8) << 3)
        }
        Mode::Hybrid => {
            let step = (index - bandwidth_index(Bandwidth::SuperWideband) as i32) as u8;
            0x60 | (step << 4) | (((period - 2) as u8) << 3)
        }
    };
    toc |= u8::from(channels == 2) << 2;
    toc
}

/// `compute_redundancy_bytes` (`opus_encoder.c:1017-1043`) — the size of the 5 ms CELT frame that
/// bridges a mode switch, or 0 when it is not worth sending.
#[must_use]
pub fn compute_redundancy_bytes(
    max_data_bytes: i32,
    bitrate_bps: i32,
    frame_rate: i32,
    channels: usize,
) -> i32 {
    let base_bits = 40 * channels as i32 + 20;
    // "Equivalent rate for 5 ms frames", then 1.5x because it is short and artefacts there are
    // expensive.
    let redundancy_rate = 3 * (bitrate_bps + base_bits * (200 - frame_rate)) / 2;
    let mut redundancy_bytes = redundancy_rate / 1600;
    let available_bits = max_data_bytes * 8 - 2 * base_bits;
    let cap = (available_bits * 240 / (240 + 48_000 / frame_rate) + base_bits) / 8;
    redundancy_bytes = redundancy_bytes.min(cap);
    // "If we can't get enough bits for redundancy to be worth it, rely on the decoder PLC."
    if redundancy_bytes > 4 + 8 * channels as i32 {
        redundancy_bytes.min(257)
    } else {
        0
    }
}

/// `is_digital_silence` (`opus_encoder.c:933-950`) — every sample below the input's own LSB.
#[must_use]
pub fn is_digital_silence(pcm: &[f32], lsb_depth: i32) -> bool {
    let floor = 1.0 / (1i32 << lsb_depth) as f32;
    pcm.iter().all(|sample| sample.abs() <= floor)
}

/// `NB_SPEECH_FRAMES_BEFORE_DTX` (`silk/define.h`).
const SPEECH_FRAMES_BEFORE_DTX: i32 = 10;
/// `MAX_CONSECUTIVE_DTX` (`silk/define.h`).
const MAX_CONSECUTIVE_DTX: i32 = 20;

/// `decide_dtx_mode` (`opus_encoder.c:988-1013`) — whether this frame may be dropped to a bare TOC.
///
/// `no_activity_ms_q1` is the running count of consecutive inactive milliseconds in Q1, updated in
/// place. The bounds are SILK's and stated in 20 ms frames, which is why everything is converted to
/// milliseconds first — this is called at any frame duration.
pub fn decide_dtx_mode(activity: bool, no_activity_ms_q1: &mut i32, frame_ms_q1: i32) -> bool {
    if activity {
        *no_activity_ms_q1 = 0;
        return false;
    }
    *no_activity_ms_q1 += frame_ms_q1;
    if *no_activity_ms_q1 > SPEECH_FRAMES_BEFORE_DTX * 20 * 2 {
        if *no_activity_ms_q1 <= (SPEECH_FRAMES_BEFORE_DTX + MAX_CONSECUTIVE_DTX) * 20 * 2 {
            return true;
        }
        // Refresh: send a real packet and start counting again.
        *no_activity_ms_q1 = SPEECH_FRAMES_BEFORE_DTX * 20 * 2;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `gen_toc` must reproduce RFC 6716 Table 2 exactly, which is checkable by parsing the result
    /// back with the decoder's own [`crate::opus::packet::Toc`] and requiring every field to match.
    #[test]
    fn generated_tocs_round_trip_through_the_decoders_parser() {
        use crate::opus::packet::Toc;

        // `(frame_rate, samples at 48 kHz)`. 60 ms is the one duration where `Fs / frame_size`
        // is not exact — 48000/2880 truncates to 16 — and `gen_toc`'s doubling loop lands it on the
        // same `period` as 40 ms, which is why SILK config 3 means 60 ms rather than 40.
        let durations: [(i32, usize); 6] = [
            (400, 120),
            (200, 240),
            (100, 480),
            (50, 960),
            (25, 1920),
            (16, 2880),
        ];
        let cases: [(Mode, &[usize], &[Bandwidth]); 3] = [
            (
                Mode::Silk,
                &[2, 3, 4, 5],
                &[
                    Bandwidth::Narrowband,
                    Bandwidth::Mediumband,
                    Bandwidth::Wideband,
                ],
            ),
            (
                Mode::Hybrid,
                &[2, 3],
                &[Bandwidth::SuperWideband, Bandwidth::Fullband],
            ),
            (
                Mode::Celt,
                &[0, 1, 2, 3],
                &[
                    Bandwidth::Narrowband,
                    Bandwidth::Wideband,
                    Bandwidth::SuperWideband,
                    Bandwidth::Fullband,
                ],
            ),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (mode, duration_indices, bandwidths) in cases {
            for &duration_index in duration_indices {
                let (frame_rate, samples) = durations[duration_index];
                for &bandwidth in bandwidths {
                    for channels in [1usize, 2] {
                        let byte = generate_toc(mode, frame_rate, bandwidth, channels);
                        let toc = Toc::parse(byte);
                        assert_eq!(toc.mode(), mode, "mode of {byte:#04x}");
                        assert_eq!(toc.bandwidth(), bandwidth, "bandwidth of {byte:#04x}");
                        assert_eq!(usize::from(toc.channels()), channels, "channels");
                        assert_eq!(toc.frame_code, 0, "the frame code is the caller's");
                        assert_eq!(
                            toc.samples_per_frame(48_000),
                            samples,
                            "duration of {byte:#04x}"
                        );
                        seen.insert(byte);
                    }
                }
            }
        }
        // The three modes' configs must not collide: 32 configs exist and we exercised a spread.
        assert!(seen.len() >= 40, "only {} distinct TOCs", seen.len());
    }

    /// `gen_toc`'s 60 ms SILK case is the one that does not follow the `2.5 ms << period` pattern —
    /// config 3/7/11 is 60 ms while `period` says 40 ms — so pin the exact bytes.
    #[test]
    fn silk_toc_bytes_match_table_2() {
        // config = bandwidth*4 + duration index, then `<< 3`.
        assert_eq!(
            generate_toc(Mode::Silk, 100, Bandwidth::Narrowband, 1),
            0x00
        );
        assert_eq!(generate_toc(Mode::Silk, 50, Bandwidth::Narrowband, 1), 0x08);
        assert_eq!(generate_toc(Mode::Silk, 25, Bandwidth::Narrowband, 1), 0x10);
        assert_eq!(generate_toc(Mode::Silk, 16, Bandwidth::Narrowband, 1), 0x18);
        assert_eq!(generate_toc(Mode::Silk, 50, Bandwidth::Wideband, 2), 0x4c);
        assert_eq!(
            generate_toc(Mode::Hybrid, 50, Bandwidth::SuperWideband, 1),
            0x68
        );
        assert_eq!(generate_toc(Mode::Hybrid, 50, Bandwidth::Fullband, 1), 0x78);
        assert_eq!(
            generate_toc(Mode::Celt, 400, Bandwidth::Narrowband, 1),
            0x80
        );
        assert_eq!(generate_toc(Mode::Celt, 50, Bandwidth::Fullband, 2), 0xfc);
    }

    /// Rate drives the mode: a low rate must land on SILK and a high one on CELT, with the VoIP bias
    /// and the hysteresis both moving the crossing point in the documented direction.
    #[test]
    fn the_mode_decision_follows_the_rate() {
        let base = ModeInputs {
            application: Application::Audio,
            voice_estimate: 48,
            stereo_width: 0.0,
            previous_mode: None,
            use_in_band_fec: false,
            packet_loss_percent: 0,
            silk_dtx: false,
            max_data_bytes: 1275,
            frame_size: 960,
            sample_rate_hz: 48_000,
            frame_rate: 50,
        };
        assert_eq!(choose_mode(8_000, None, &base), Mode::Silk);
        assert_eq!(choose_mode(120_000, None, &base), Mode::Celt);

        // Find the crossing, then check each modifier moves it the right way.
        let crossing = |inputs: &ModeInputs| {
            (1_000..200_000)
                .step_by(250)
                .find(|&rate| choose_mode(rate, None, inputs) == Mode::Celt)
                .expect("a crossing exists")
        };
        let plain = crossing(&base);

        let voip = ModeInputs {
            application: Application::Voip,
            ..base
        };
        assert!(
            crossing(&voip) > plain,
            "VoIP must hold on to SILK for longer (+8 kb/s)"
        );

        let after_celt = ModeInputs {
            previous_mode: Some(Mode::Celt),
            ..base
        };
        let after_silk = ModeInputs {
            previous_mode: Some(Mode::Silk),
            ..base
        };
        assert!(
            crossing(&after_celt) < plain && plain < crossing(&after_silk),
            "the hysteresis must straddle the memoryless threshold"
        );

        // A wide stereo image lowers the voice threshold from 64 to 44 kb/s.
        let wide = ModeInputs {
            stereo_width: 1.0,
            voice_estimate: 127,
            ..base
        };
        let narrow = ModeInputs {
            stereo_width: 0.0,
            voice_estimate: 127,
            ..base
        };
        assert!(
            crossing(&wide) < crossing(&narrow),
            "a wide image must reach CELT-only sooner"
        );
    }

    /// The overrides must be absolute: restricted-lowdelay is CELT whatever the rate, FEC with real
    /// loss is SILK whatever the rate, and a sub-10 ms frame is CELT because SILK has no such frame.
    #[test]
    fn the_mode_overrides_win_over_the_rate() {
        let base = ModeInputs {
            application: Application::RestrictedLowdelay,
            voice_estimate: 127,
            stereo_width: 0.0,
            previous_mode: None,
            use_in_band_fec: false,
            packet_loss_percent: 0,
            silk_dtx: false,
            max_data_bytes: 1275,
            frame_size: 960,
            sample_rate_hz: 48_000,
            frame_rate: 50,
        };
        assert_eq!(choose_mode(6_000, None, &base), Mode::Celt);
        assert_eq!(choose_mode(6_000, Some(Mode::Silk), &base), Mode::Celt);

        let fec = ModeInputs {
            application: Application::Audio,
            use_in_band_fec: true,
            packet_loss_percent: 20,
            ..base
        };
        assert_eq!(
            choose_mode(200_000, None, &fec),
            Mode::Silk,
            "FEC only exists in SILK"
        );

        let short = ModeInputs {
            application: Application::Voip,
            frame_size: 240,
            frame_rate: 200,
            ..base
        };
        assert_eq!(
            choose_mode(8_000, None, &short),
            Mode::Celt,
            "SILK has no 5 ms frame"
        );

        // A forced mode is honoured, but only where it is legal.
        let audio = ModeInputs {
            application: Application::Audio,
            ..base
        };
        assert_eq!(choose_mode(200_000, Some(Mode::Silk), &audio), Mode::Silk);
        assert_eq!(choose_mode(6_000, Some(Mode::Celt), &audio), Mode::Celt);

        // Too little space to be useful at all.
        let cramped = ModeInputs {
            application: Application::Voip,
            max_data_bytes: 8,
            ..base
        };
        assert_eq!(choose_mode(6_000, None, &cramped), Mode::Celt);
    }

    /// The bandwidth ladder must be monotone in rate, and the hysteresis must stick.
    #[test]
    fn the_bandwidth_decision_climbs_with_the_rate() {
        let mut previous_index = 0usize;
        let mut seen = std::collections::BTreeSet::new();
        for rate in (4_000..40_000).step_by(500) {
            let bandwidth = choose_bandwidth(rate, 48, false, true, Bandwidth::Fullband);
            let index = bandwidth_index(bandwidth);
            assert!(
                index >= previous_index,
                "bandwidth went backwards at {rate} bit/s"
            );
            previous_index = index;
            seen.insert(index);
        }
        assert_eq!(
            seen,
            std::collections::BTreeSet::from([
                bandwidth_index(Bandwidth::Narrowband),
                bandwidth_index(Bandwidth::Wideband),
                bandwidth_index(Bandwidth::SuperWideband),
                bandwidth_index(Bandwidth::Fullband),
            ]),
            "mediumband must never be chosen automatically, and the other four must all appear"
        );

        // Right at a boundary, the hysteresis must hold whichever side we came from.
        let boundary = (4_000..40_000)
            .step_by(100)
            .find(|&rate| {
                choose_bandwidth(rate, 48, false, true, Bandwidth::Fullband) == Bandwidth::Fullband
            })
            .expect("a fullband crossing exists");
        let just_below = boundary - 100;
        assert_eq!(
            choose_bandwidth(just_below, 48, false, false, Bandwidth::Fullband),
            Bandwidth::Fullband,
            "coming down from fullband, the hysteresis must hold it"
        );
        assert_ne!(
            choose_bandwidth(just_below, 48, false, false, Bandwidth::Wideband),
            Bandwidth::Fullband,
            "coming up from wideband, it must not jump early"
        );
    }

    /// `decide_fec` must trade bandwidth for FEC above 5 % loss and never below it.
    #[test]
    fn fec_trades_bandwidth_for_redundancy_only_above_five_percent_loss() {
        let mut bandwidth = Bandwidth::Fullband;
        assert!(
            !decide_fec(false, 20, false, Mode::Silk, &mut bandwidth, 100_000),
            "FEC off means off"
        );
        assert!(
            !decide_fec(true, 0, false, Mode::Silk, &mut bandwidth, 100_000),
            "no loss means no FEC"
        );
        assert!(
            !decide_fec(true, 20, false, Mode::Celt, &mut bandwidth, 100_000),
            "CELT has no FEC"
        );
        assert_eq!(bandwidth, Bandwidth::Fullband, "none of those touched it");

        // Plenty of rate: FEC without giving anything up.
        assert!(decide_fec(
            true,
            10,
            false,
            Mode::Silk,
            &mut bandwidth,
            64_000
        ));
        assert_eq!(bandwidth, Bandwidth::Fullband);

        // Little rate and heavy loss: narrow down until it fits.
        let mut narrowed = Bandwidth::Fullband;
        assert!(decide_fec(
            true,
            25,
            false,
            Mode::Silk,
            &mut narrowed,
            14_000
        ));
        assert!(
            bandwidth_index(narrowed) < bandwidth_index(Bandwidth::Fullband),
            "the bandwidth should have been traded away, got {narrowed:?}"
        );

        // Little rate and light loss: no FEC, and the bandwidth is left alone.
        let mut untouched = Bandwidth::Fullband;
        assert!(!decide_fec(
            true,
            3,
            false,
            Mode::Silk,
            &mut untouched,
            8_000
        ));
        assert_eq!(untouched, Bandwidth::Fullband);

        // Not even narrowband fits: the original bandwidth must be restored.
        let mut restored = Bandwidth::Fullband;
        assert!(!decide_fec(true, 25, false, Mode::Silk, &mut restored, 100));
        assert_eq!(restored, Bandwidth::Fullband);
    }

    /// The hybrid rate split must be monotone, must leave CELT something at every rate, and must
    /// reproduce the table's own interpolation at the knots.
    #[test]
    fn the_hybrid_rate_split_interpolates_the_table() {
        for &(total, expected) in &[
            (12_000i32, 10_000i32),
            (16_000, 13_500),
            (20_000, 16_000),
            (24_000, 18_000),
            (32_000, 22_000),
            (64_000, 38_000),
        ] {
            assert_eq!(
                compute_silk_rate_for_hybrid(total, Bandwidth::Fullband, true, true, false, 1),
                expected,
                "at the {total} knot"
            );
        }
        // Halfway between two knots is halfway between two shares.
        assert_eq!(
            compute_silk_rate_for_hybrid(14_000, Bandwidth::Fullband, true, true, false, 1),
            11_750
        );
        // Past the top knot, half the surplus goes to SILK.
        assert_eq!(
            compute_silk_rate_for_hybrid(80_000, Bandwidth::Fullband, true, true, false, 1),
            38_000 + 8_000
        );

        let mut previous = 0;
        for total in (12_000..96_000).step_by(1_000) {
            let silk =
                compute_silk_rate_for_hybrid(total, Bandwidth::Fullband, true, true, false, 1);
            assert!(silk >= previous, "the split went backwards at {total}");
            assert!(silk < total, "SILK took the whole budget at {total}");
            previous = silk;
        }

        // FEC costs, CBR and SWB each add their documented nudge.
        let plain = compute_silk_rate_for_hybrid(32_000, Bandwidth::Fullband, true, true, false, 1);
        let with_fec =
            compute_silk_rate_for_hybrid(32_000, Bandwidth::Fullband, true, true, true, 1);
        assert!(with_fec > plain, "FEC must buy SILK more of the budget");
        assert_eq!(
            compute_silk_rate_for_hybrid(32_000, Bandwidth::Fullband, true, false, false, 1),
            plain + 100,
            "the CBR boost"
        );
        assert_eq!(
            compute_silk_rate_for_hybrid(32_000, Bandwidth::SuperWideband, true, true, false, 1),
            plain + 300,
            "the SWB boost"
        );
    }

    /// `compute_equiv_rate` must penalise short frames, CBR, low complexity and loss, each in the
    /// documented direction and none of them in the wrong one.
    #[test]
    fn the_equivalent_rate_penalises_what_it_should() {
        let reference = compute_equiv_rate(32_000, 1, 50, true, None, 10, 0);
        assert_eq!(
            reference, 32_000,
            "a 20 ms complexity-10 VBR frame is the unit"
        );

        assert!(
            compute_equiv_rate(32_000, 1, 400, true, None, 10, 0) < reference,
            "2.5 ms frames pay header overhead"
        );
        assert!(
            compute_equiv_rate(32_000, 1, 50, false, None, 10, 0) < reference,
            "CBR costs about 8%"
        );
        assert!(
            compute_equiv_rate(32_000, 1, 50, true, None, 0, 0) < reference,
            "complexity 0 costs about 10%"
        );
        assert!(
            compute_equiv_rate(32_000, 1, 50, true, Some(Mode::Silk), 10, 20) < reference,
            "loss costs SILK"
        );
        assert!(
            compute_equiv_rate(32_000, 1, 50, true, Some(Mode::Celt), 10, 20) == reference,
            "loss does not cost CELT, which has no FEC to pay for"
        );
        assert!(
            compute_equiv_rate(32_000, 1, 50, true, Some(Mode::Silk), 1, 0) < reference * 4 / 5 + 1,
            "SILK complexity below 2 drops the delayed-decision NSQ"
        );
    }

    /// The channel decision must be rate-driven with hysteresis, and a forced count must win.
    #[test]
    fn the_stereo_decision_follows_the_rate_with_hysteresis() {
        assert_eq!(
            stream_channels(1, None, 1, 200_000, 48),
            1,
            "mono stays mono"
        );
        assert_eq!(
            stream_channels(2, Some(1), 2, 200_000, 48),
            1,
            "forced mono"
        );
        assert_eq!(
            stream_channels(2, Some(2), 1, 1_000, 48),
            2,
            "forced stereo"
        );

        assert_eq!(stream_channels(2, None, 1, 6_000, 48), 1);
        assert_eq!(stream_channels(2, None, 1, 200_000, 48), 2);

        // At the crossing, whichever side we came from must be held.
        let crossing = (1_000..60_000)
            .step_by(100)
            .find(|&rate| stream_channels(2, None, 1, rate, 48) == 2)
            .expect("a crossing exists");
        assert_eq!(
            stream_channels(2, None, 2, crossing - 1_500, 48),
            2,
            "coming down from stereo, hysteresis holds"
        );
    }

    /// The stereo-width estimator must call a decorrelated pair wide and a duplicated mono narrow,
    /// and must never leave 0..=1.
    #[test]
    fn the_stereo_width_estimator_separates_a_wide_image_from_a_duplicated_mono() {
        const RATE: i32 = 48_000;
        const FRAME: usize = 960;
        let mut identical = StereoWidthState::default();
        let mut wide = StereoWidthState::default();
        let mut identical_width = 0f32;
        let mut wide_width = 0f32;
        let mut state = 12_345u32;
        let mut next = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 8) as f32 / (1 << 23) as f32 - 1.0
        };
        for _ in 0..100 {
            let mut same = vec![0f32; FRAME * 2];
            let mut different = vec![0f32; FRAME * 2];
            for index in 0..FRAME {
                let left = 0.3 * next();
                same[2 * index] = left;
                same[2 * index + 1] = left;
                different[2 * index] = left;
                // Uncorrelated *and* much quieter, which is what "wide" means to this measure.
                different[2 * index + 1] = 0.02 * next();
            }
            identical_width = compute_stereo_width(&same, FRAME, RATE, &mut identical);
            wide_width = compute_stereo_width(&different, FRAME, RATE, &mut wide);
        }
        assert!(
            (0.0..=1.0).contains(&identical_width) && (0.0..=1.0).contains(&wide_width),
            "width left 0..=1: {identical_width} / {wide_width}"
        );
        assert!(
            identical_width < 0.01,
            "a duplicated mono scored {identical_width}"
        );
        assert!(
            wide_width > identical_width,
            "a decorrelated pair must score higher"
        );
    }

    /// A NaN or a runaway signal must be discarded rather than poisoning the running correlation.
    #[test]
    fn the_stereo_width_estimator_rejects_nan_and_runaway_input() {
        let mut state = StereoWidthState::default();
        let poison = vec![f32::NAN; 8];
        let width = compute_stereo_width(&poison, 4, 48_000, &mut state);
        assert!(width.is_finite(), "NaN leaked into the width");
        assert!(state.correlation.iter().all(|value| value.is_finite()));

        let huge = vec![1e30f32; 8];
        let width = compute_stereo_width(&huge, 4, 48_000, &mut state);
        assert!(width.is_finite());
    }

    /// The DTX counter must wait ten frames before dropping anything, then drop at most twenty in a
    /// row before sending a refresh.
    #[test]
    fn dtx_waits_then_drops_then_refreshes() {
        let mut counter = 0i32;
        // 20 ms in Q1 milliseconds.
        let frame = 40;
        let mut dropped = 0usize;
        let mut sent = 0usize;
        for _ in 0..40 {
            if decide_dtx_mode(false, &mut counter, frame) {
                dropped += 1;
            } else {
                sent += 1;
            }
        }
        assert_eq!(sent, 11, "ten frames of hold-off, then one refresh");
        assert_eq!(dropped, 29);

        // Activity resets it immediately.
        assert!(!decide_dtx_mode(true, &mut counter, frame));
        assert_eq!(counter, 0);
        assert!(
            !decide_dtx_mode(false, &mut counter, frame),
            "the count must start again from zero"
        );
    }

    /// Digital silence is "every sample below the input's own LSB", not "quiet".
    #[test]
    fn digital_silence_is_measured_against_the_lsb() {
        assert!(is_digital_silence(&[0.0; 480], 16));
        assert!(is_digital_silence(&[1.0 / 65536.0; 480], 16));
        assert!(!is_digital_silence(&[1.0 / 1024.0; 480], 16));
        // A single loud sample is enough.
        let mut mostly_silent = vec![0.0f32; 480];
        mostly_silent[100] = 0.5;
        assert!(!is_digital_silence(&mostly_silent, 16));
    }

    /// Redundancy is only worth sending when there is room for it.
    #[test]
    fn redundancy_bytes_vanish_when_they_would_not_help() {
        assert_eq!(
            compute_redundancy_bytes(4, 32_000, 50, 1),
            0,
            "a 4-byte packet has no room for a redundant frame"
        );
        let generous = compute_redundancy_bytes(1275, 64_000, 50, 1);
        assert!(
            (13..=257).contains(&generous),
            "a healthy rate should buy a real redundant frame, got {generous}"
        );
        assert!(
            compute_redundancy_bytes(1275, 64_000, 50, 2)
                >= compute_redundancy_bytes(1275, 64_000, 50, 1),
            "stereo redundancy is not cheaper than mono"
        );
    }
}
