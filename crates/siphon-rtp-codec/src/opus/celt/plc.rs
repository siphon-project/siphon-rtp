//! CELT packet-loss concealment (RFC 6716 §4.4; libopus `celt_decode_lost` + `prefilter_and_fold`,
//! `celt_decoder.c:515,604`, float build).
//!
//! Two concealment strategies, chosen per lost frame (`celt_decoder.c:646`):
//!
//! * **Pitch-based** — the default for the first few lost frames of a voiced passage. Fit an
//!   order-24 LPC to the last 1024 good samples, run them through the inverse (analysis) filter to
//!   get an excitation, then extrapolate that excitation periodically at the searched pitch lag,
//!   fading it by the measured decay per period, and re-synthesise through the LPC filter. What
//!   comes out is time-domain audio, not an MDCT frame, which is why the *next* good frame has to
//!   [`CeltDecoder::prefilter_and_fold`] the ring before it can overlap-add onto it.
//! * **Noise-based (CNG)** — once the loss has run past 40 samples' worth of frames, or the pitch
//!   history is untrustworthy (`skip_plc`), or this is a Hybrid frame where CELT only owns the high
//!   band (`start != 0`). Fill each band with unit-norm noise from the range coder's own PRNG,
//!   scale it by the band energy decayed toward the tracked noise floor, and synthesise normally.
//!
//! The Opus layer reaches both of these on a lost packet, and the noise-based one additionally on
//! every mode transition — `opus_decode_frame` conceals a 5 ms frame in the *previous* mode to
//! cross-fade a CELT↔SILK switch (`opus_decoder.c:346-363, 493-497`).
//!
//! Deliberately omitted: libopus 1.5's `ENABLE_DEEP_PLC` (LACE/NoLACE neural concealment). It is a
//! vendor extension outside RFC 6716, already listed as out of scope in [`super`].

use crate::opus::celt::decoder::{
    CeltDecoder, CELT_LPC_ORDER, DECODE_BUFFER_SIZE, MAX_CHANNELS, MAX_FRAME_SAMPLES,
};
use crate::opus::celt::pitch::{celt_autocorr_windowed, celt_fir, celt_iir, celt_lpc};
use crate::opus::celt::pitch::{pitch_downsample, pitch_search};
use crate::opus::celt::postfilter::{comb_filter_out_of_place, COMBFILTER_MAXPERIOD};
use crate::opus::celt::synthesis::celt_lcg_rand;
use crate::opus::celt::tables::{E_BANDS, NB_BANDS, OVERLAP, WINDOW120};
use crate::opus::celt::vq::renormalise_vector;

/// Longest pitch lag the concealment search considers — 66.67 Hz (libopus `PLC_PITCH_LAG_MAX`,
/// `celt_decoder.c:62`).
const PLC_PITCH_LAG_MAX: usize = 720;
/// Shortest pitch lag the concealment search considers — 480 Hz (libopus `PLC_PITCH_LAG_MIN`,
/// `celt_decoder.c:65`).
const PLC_PITCH_LAG_MIN: usize = 100;

/// History the excitation extrapolation reaches back over (libopus `MAX_PERIOD`, `modes.h:40`).
const MAX_PERIOD: usize = COMBFILTER_MAXPERIOD;

/// Concealed samples past which the pitch-based PLC gives up and hands over to noise
/// (`celt_decoder.c:646`).
const NOISE_PLC_THRESHOLD: i32 = 40;

impl CeltDecoder {
    /// Conceal one lost frame of `n` samples at `LM` (libopus `celt_decode_lost`,
    /// `celt_decoder.c:604`). Leaves the concealed audio in the decode ring; the caller de-emphasises
    /// it exactly as it would a decoded frame.
    pub(super) fn decode_lost(&mut self, n: usize, lm: usize) {
        let channels = self.channels; // C == CC in the PLC path
        let loss_duration = self.loss_duration;
        let start = self.start_band;
        // `start != 0` is the Hybrid case: CELT owns only the high band, so there is no pitch
        // structure of its own to extrapolate (`celt_decoder.c:646`).
        let noise_based = loss_duration >= NOISE_PLC_THRESHOLD || start != 0 || self.skip_plc;

        if noise_based {
            self.conceal_with_noise(n, lm, channels, start, loss_duration);
        } else {
            self.conceal_with_pitch(n, channels, loss_duration);
        }

        // Saturate to something large to avoid wrap-around (`celt_decoder.c:965`).
        self.loss_duration = 10_000.min(loss_duration + (1 << lm));
    }

    /// Noise-based concealment / comfort noise (`celt_decoder.c:648-699`).
    fn conceal_with_noise(
        &mut self,
        n: usize,
        lm: usize,
        channels: usize,
        start: usize,
        loss_duration: i32,
    ) {
        let end = self.end_band;
        let eff_end = start.max(end.min(NB_BANDS));

        for c in 0..channels {
            self.decode_mem[c].copy_within(n.., 0);
        }
        if self.prefilter_and_fold {
            self.prefilter_and_fold(n);
        }

        // Energy decay: 1.5 dB on the first lost frame, 0.5 dB on every one after, floored at the
        // tracked background level so a long gap settles on the room noise rather than on silence.
        let decay = if loss_duration == 0 { 1.5 } else { 0.5 };
        for c in 0..channels {
            let base = c * NB_BANDS;
            for i in start..end {
                self.old_band_energy[base + i] = self.background_log_energy[base + i]
                    .max(self.old_band_energy[base + i] - decay);
            }
        }

        // Unit-norm noise per band from the range coder's PRNG, so the concealed frame's fold seed
        // stays on the same sequence a decoded frame would have left behind.
        let mut x_buf = [0f32; MAX_CHANNELS * MAX_FRAME_SAMPLES];
        let mut seed = self.rng;
        for c in 0..channels {
            for i in start..eff_end {
                let offset = n * c + ((E_BANDS[i] as usize) << lm);
                let length = ((E_BANDS[i + 1] - E_BANDS[i]) as usize) << lm;
                for slot in x_buf.iter_mut().skip(offset).take(length) {
                    seed = celt_lcg_rand(seed);
                    *slot = ((seed as i32) >> 20) as f32;
                }
                renormalise_vector(&mut x_buf[offset..offset + length], length, 1.0);
            }
        }
        self.rng = seed;

        let band_energy = self.old_band_energy;
        self.celt_synthesis(
            &x_buf[..channels * n],
            &band_energy,
            start,
            eff_end,
            channels,
            false,
            lm,
            n,
            false,
        );
        self.prefilter_and_fold = false;
        // Skip regular PLC until we get two consecutive packets (`celt_decoder.c:699`).
        self.skip_plc = true;
    }

    /// Pitch-based concealment (`celt_decoder.c:700-962`).
    #[allow(clippy::too_many_lines)]
    fn conceal_with_pitch(&mut self, n: usize, channels: usize, loss_duration: i32) {
        // The first lost frame searches for the pitch; every following one reuses it and fades.
        let mut fade = 1.0f32;
        let pitch_index = if loss_duration == 0 {
            let index = self.plc_pitch_search(channels);
            self.last_pitch_index = index;
            index
        } else {
            fade = 0.8;
            self.last_pitch_index
        };
        // The search can only return `PLC_PITCH_LAG_MIN..=PLC_PITCH_LAG_MAX`, and that is what keeps
        // every `exc` index below in range; clamping makes the bound hold structurally rather than
        // by reasoning about an unreachable state.
        let pitch_index = pitch_index.clamp(PLC_PITCH_LAG_MIN, PLC_PITCH_LAG_MAX);

        // "We want the excitation for 2 pitch periods in order to look for a decaying signal, but we
        // can't get more than MAX_PERIOD" (`celt_decoder.c:721`).
        let exc_length = (2 * pitch_index).min(MAX_PERIOD);
        let extrapolation_offset = MAX_PERIOD - pitch_index;
        let extrapolation_len = n + OVERLAP;

        let mut exc = [0f32; MAX_PERIOD + CELT_LPC_ORDER];
        let mut fir_tmp = [0f32; MAX_PERIOD];

        for c in 0..channels {
            // The excitation window: the last MAX_PERIOD good samples plus CELT_LPC_ORDER of filter
            // history in front of them. `exc[CELT_LPC_ORDER + k]` is the C's `exc[k]`.
            for (i, slot) in exc.iter_mut().enumerate() {
                *slot = self.decode_mem[c][DECODE_BUFFER_SIZE - MAX_PERIOD - CELT_LPC_ORDER + i];
            }

            if loss_duration == 0 {
                // Fit the LPC to the last good MAX_PERIOD samples so the extrapolation happens in
                // the excitation domain rather than on the waveform.
                let mut autocorrelation = [0f32; CELT_LPC_ORDER + 1];
                celt_autocorr_windowed(
                    &exc[CELT_LPC_ORDER..CELT_LPC_ORDER + MAX_PERIOD],
                    &mut autocorrelation,
                    &WINDOW120,
                    OVERLAP,
                    CELT_LPC_ORDER,
                    MAX_PERIOD,
                );
                // Add a noise floor of -40 dB (`celt_decoder.c:753`).
                autocorrelation[0] *= 1.0001;
                // Lag windowing, to stabilise the Levinson-Durbin recursion.
                for (i, slot) in autocorrelation.iter_mut().enumerate().skip(1) {
                    *slot -= *slot * (0.008 * 0.008) * (i * i) as f32;
                }
                celt_lpc(&mut self.lpc[c], &autocorrelation, CELT_LPC_ORDER);
            }

            // Inverse-filter the tail into the excitation domain. `celt_fir` cannot filter in place,
            // hence the copy back (`celt_decoder.c:787`).
            celt_fir(
                &exc[MAX_PERIOD - exc_length..],
                &self.lpc[c],
                &mut fir_tmp[..exc_length],
                exc_length,
                CELT_LPC_ORDER,
            );
            exc[CELT_LPC_ORDER + MAX_PERIOD - exc_length..CELT_LPC_ORDER + MAX_PERIOD]
                .copy_from_slice(&fir_tmp[..exc_length]);

            // How fast is the waveform already decaying? Extrapolating a dying note at full gain
            // would *add* energy, which is the classic PLC artefact.
            let decay_length = exc_length >> 1;
            let mut energy_recent = 1.0f32;
            let mut energy_older = 1.0f32;
            for i in 0..decay_length {
                let recent = exc[CELT_LPC_ORDER + MAX_PERIOD - decay_length + i];
                energy_recent += recent * recent;
                let older = exc[CELT_LPC_ORDER + MAX_PERIOD - 2 * decay_length + i];
                energy_older += older * older;
            }
            let energy_recent = energy_recent.min(energy_older);
            let decay = (energy_recent / energy_older).sqrt();

            // Room for the new frame. The overlap past the end of the buffer is ignored — it is not
            // going to be used (`celt_decoder.c:816`).
            let buf = &mut self.decode_mem[c];
            buf.copy_within(n..DECODE_BUFFER_SIZE, 0);

            // Extrapolate periodically from the end of the excitation, scaling each period down by
            // another factor of `decay`.
            let mut attenuation = fade * decay;
            let mut energy_before = 0.0f32;
            let mut j = 0usize;
            for i in 0..extrapolation_len {
                if j >= pitch_index {
                    j -= pitch_index;
                    attenuation *= decay;
                }
                buf[DECODE_BUFFER_SIZE - n + i] =
                    attenuation * exc[CELT_LPC_ORDER + extrapolation_offset + j];
                // Energy of the previously decoded signal whose excitation we're copying.
                let previous = buf[DECODE_BUFFER_SIZE - MAX_PERIOD - n + extrapolation_offset + j];
                energy_before += previous * previous;
                j += 1;
            }

            // Back to the signal domain, continuing the synthesis filter from the last good samples.
            let mut lpc_mem = [0f32; CELT_LPC_ORDER];
            for (i, slot) in lpc_mem.iter_mut().enumerate() {
                *slot = buf[DECODE_BUFFER_SIZE - n - 1 - i];
            }
            celt_iir(
                buf,
                DECODE_BUFFER_SIZE - n,
                &self.lpc[c],
                extrapolation_len,
                CELT_LPC_ORDER,
                &mut lpc_mem,
            );

            // Did the synthesis explode? The float test is written as a *negated* comparison on
            // purpose: an unstable IIR can produce a NaN, and `!(a > b)` is the one form that is
            // true for NaN, so the same branch zeroes both an explosion and a NaN
            // (`celt_decoder.c:878`). Rewriting it as `<=` would let a NaN frame through.
            let mut energy_after = 0.0f32;
            for i in 0..extrapolation_len {
                let sample = buf[DECODE_BUFFER_SIZE - n + i];
                energy_after += sample * sample;
            }
            #[allow(clippy::neg_cmp_op_on_partial_ord)]
            if !(energy_before > 0.2 * energy_after) {
                buf[DECODE_BUFFER_SIZE - n..DECODE_BUFFER_SIZE - n + extrapolation_len].fill(0.0);
            } else if energy_before < energy_after {
                let ratio = ((energy_before + 1.0) / (energy_after + 1.0)).sqrt();
                for i in 0..OVERLAP {
                    let gain = 1.0 - WINDOW120[i] * (1.0 - ratio);
                    buf[DECODE_BUFFER_SIZE - n + i] *= gain;
                }
                for i in OVERLAP..extrapolation_len {
                    buf[DECODE_BUFFER_SIZE - n + i] *= ratio;
                }
            }
        }
        // The ring now holds raw time-domain audio; the next real frame must fold it first.
        self.prefilter_and_fold = true;
    }

    /// Find the concealment pitch lag over the whole decode ring (libopus `celt_plc_pitch_search`,
    /// `celt_decoder.c:499`).
    fn plc_pitch_search(&self, channels: usize) -> usize {
        let mut low_pass = [0f32; DECODE_BUFFER_SIZE >> 1];
        let left: &[f32] = &self.decode_mem[0];
        let right: &[f32] = &self.decode_mem[1];
        let inputs: [&[f32]; 2] = [left, right];
        pitch_downsample(
            &inputs[..channels.max(1)],
            &mut low_pass,
            DECODE_BUFFER_SIZE,
            channels,
        );
        let index = pitch_search(
            &low_pass[PLC_PITCH_LAG_MAX >> 1..],
            &low_pass,
            DECODE_BUFFER_SIZE - PLC_PITCH_LAG_MAX,
            PLC_PITCH_LAG_MAX - PLC_PITCH_LAG_MIN,
        );
        PLC_PITCH_LAG_MAX - index
    }

    /// Pre-filter and fold the concealed tail so the next frame's MDCT can overlap-add onto it
    /// (libopus `prefilter_and_fold`, `celt_decoder.c:515`).
    ///
    /// The pitch-based PLC writes plain time-domain audio into the ring. A decoded frame's inverse
    /// MDCT expects to land on a TDAC-shaped tail, so before it can, the concealed tail is run
    /// through the *inverse* comb pre-filter (the post-filter is re-applied after the MDCT overlap)
    /// and time-domain alias-cancellation is simulated on it by hand.
    pub(super) fn prefilter_and_fold(&mut self, n: usize) {
        let channels = self.channels;
        let mut etmp = [0f32; OVERLAP];
        for c in 0..channels {
            comb_filter_out_of_place(
                &mut etmp,
                &self.decode_mem[c],
                DECODE_BUFFER_SIZE - n,
                OVERLAP,
                self.postfilter_period_old,
                self.postfilter_period,
                -self.postfilter_gain_old,
                -self.postfilter_gain,
                self.postfilter_tapset_old,
                self.postfilter_tapset,
                &WINDOW120,
                // The C passes `NULL, 0` for the window/overlap here: there is no crossfade region,
                // the whole `OVERLAP` run uses the two-parameter form directly.
                0,
            );
            for i in 0..OVERLAP / 2 {
                self.decode_mem[c][DECODE_BUFFER_SIZE - n + i] =
                    WINDOW120[i] * etmp[OVERLAP - 1 - i] + WINDOW120[OVERLAP - i - 1] * etmp[i];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::opus::celt::decoder::CeltDecoder;

    /// A decoder that has never seen a packet has `skip_plc` set, so the very first concealed frame
    /// must take the noise path. It emits comfort noise at the reset band energies rather than
    /// silence — the Opus layer is what returns zeros before any packet has arrived
    /// (`opus_decoder.c:302-309`) — and it must stay finite and in range doing so.
    #[test]
    fn concealing_from_a_fresh_decoder_is_bounded_comfort_noise() {
        for channels in [1usize, 2] {
            let mut decoder = CeltDecoder::with_channels(channels).expect("build");
            let mut pcm = vec![0f32; 960 * channels];
            let written = decoder
                .decode_float(None, &mut pcm, 960, None)
                .expect("conceal");
            assert_eq!(written, 960);
            assert!(
                pcm.iter().all(|s| s.is_finite()),
                "{channels}ch: concealment produced a non-finite sample"
            );
            assert!(
                pcm.iter().all(|&s| s.abs() < 4.0),
                "{channels}ch: concealment must stay bounded"
            );
            // The noise path leaves the ring folded, so no pre-fold is owed to the next frame.
            assert!(!decoder.prefilter_and_fold);
            assert!(decoder.skip_plc);
        }
    }

    /// After a real frame the first loss takes the *pitch* path (`skip_plc` cleared, `start == 0`,
    /// `loss_duration == 0`), which must leave `prefilter_and_fold` armed for the next good frame.
    #[test]
    fn the_first_loss_after_a_good_frame_uses_the_pitch_path() {
        let mut frame = vec![0u8; 80];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8;
        }
        frame[0] &= 0x7f;

        let mut decoder = CeltDecoder::new().expect("build");
        let mut pcm = vec![0f32; 960];
        // Two good frames: the second clears `skip_plc` (two consecutive packets received).
        decoder
            .decode_float(Some(&frame), &mut pcm, 960, None)
            .expect("frame 1");
        decoder
            .decode_float(Some(&frame), &mut pcm, 960, None)
            .expect("frame 2");
        assert!(!decoder.skip_plc);
        assert!(!decoder.prefilter_and_fold);

        decoder
            .decode_float(None, &mut pcm, 960, None)
            .expect("lost");
        assert!(
            decoder.prefilter_and_fold,
            "the pitch PLC leaves un-folded audio in the ring"
        );
        assert!(pcm.iter().all(|s| s.is_finite()));
        assert_eq!(decoder.loss_duration, 8, "loss_duration += 1<<LM");

        // A long gap eventually crosses into the noise-based path, which clears the fold flag again.
        for _ in 0..8 {
            decoder
                .decode_float(None, &mut pcm, 960, None)
                .expect("lost");
        }
        assert!(!decoder.prefilter_and_fold);
        assert!(decoder.skip_plc);
        assert!(pcm.iter().all(|s| s.is_finite()));

        // And a good frame after the gap decodes without tripping over the concealed ring.
        decoder
            .decode_float(Some(&frame), &mut pcm, 960, None)
            .expect("recovery frame");
        assert_eq!(decoder.loss_duration, 0);
        assert!(pcm.iter().all(|s| s.is_finite()));
    }

    /// Hybrid concealment (`start != 0`) is always noise-based — CELT owns no pitch structure there.
    #[test]
    fn a_hybrid_band_range_always_conceals_with_noise() {
        let mut decoder = CeltDecoder::new().expect("build");
        decoder.set_band_range(17, 21).expect("hybrid range");
        let mut pcm = vec![0f32; 960];
        decoder
            .decode_float(None, &mut pcm, 960, None)
            .expect("lost");
        assert!(!decoder.prefilter_and_fold);
        assert!(pcm.iter().all(|s| s.is_finite()));
    }

    /// Concealment at a downsampling rate returns the API-rate sample count.
    #[test]
    fn concealment_honours_the_output_rate() {
        let mut decoder = CeltDecoder::with_rate_and_channels(16_000, 1).expect("build");
        let mut pcm = vec![0f32; 320];
        let written = decoder
            .decode_float(None, &mut pcm, 320, None)
            .expect("lost");
        assert_eq!(written, 320);
    }
}
