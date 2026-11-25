//! `TonalMDCTConceal_InsertNoise` (TS 26.442 `lib_dec/tonalMDCTconcealment.c`): fill the MDCT
//! spectrum of a lost frame with shaped noise (outside the tonal groups when the tonal
//! concealment is active), cross-faded with the last good spectrum.

use super::{tci_view, Tonalmdctconceal};
use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::SPEC_EXP_DEC;
use crate::evs::com::basop_util::{basop_util_f_pow, inv16, sqrt16};
use crate::evs::com::tools::set32;
use crate::itu::basic_ops::{
    add, extract_l, l_add, l_deposit_h, l_deposit_l, l_mac, l_msu, l_mult, l_shl, l_shr, mult_r,
    norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{div_l, l_mac0};

/// The noise generator and the running energies of the `FOR` loops of the reference, which all
/// share one body: advance the random seed, scale it with the tilt, and accumulate the energy of
/// the last frame's line and of the white noise line.
struct NoiseFill {
    rnd: i16,
    tilt: i16,
    tilt_factor: i16,
    fac: i16,
    nrg_noise_in_last_frame: i32,
    nrg_white_noise: i32,
}

impl NoiseFill {
    /// One line: the white noise value (15Q16) for the line whose last-frame value is `x`.
    fn line(&mut self, x: i16) -> i32 {
        self.rnd = extract_l(l_mac0(13849, self.rnd, 31821));
        let y = l_mult(self.tilt, self.rnd);

        self.nrg_noise_in_last_frame = l_add(
            self.nrg_noise_in_last_frame,
            mpy_32_16_1(l_msu(0, x, self.fac), x),
        );
        let white = round_word(y);
        self.nrg_white_noise = l_add(
            self.nrg_white_noise,
            mpy_32_16_1(l_msu(0, white, self.fac), white),
        );

        self.tilt = mult_r(self.tilt, self.tilt_factor);
        y
    }

    /// `tilt *= tiltFactor^count` over a skipped tonal group of `count` lines.
    fn skip_group(&mut self, count: i16) {
        let mut exp: i16 = 0;
        let power = round_word(basop_util_f_pow(
            l_deposit_h(self.tilt_factor),
            0,
            l_deposit_h(count),
            15,
            &mut exp,
        ));
        // The result may saturate to 32767 ("next op may result in 32768" in the reference).
        let power = shl(power, exp);
        self.tilt = mult_r(self.tilt, power);
    }
}

/// The cross-fade of the noise towards the last frame's line (`g`, `crossfadeGain`, the shift
/// `exp` and the carried `L_tmp` of the reference).
struct Mix {
    g: i16,
    crossfade_gain: i16,
    exp: i16,
    l_tmp: i32,
}

impl Mix {
    /// One cross-faded line from the last frame's value `x` and the noise `y`.
    fn line(&mut self, x: i16, y: i32) -> i32 {
        if self.g > 0 {
            self.l_tmp = mpy_32_16_1(y, self.g);
        }

        let mut l_tmp2 = l_msu(self.l_tmp, self.crossfade_gain, x);
        if y > 0 {
            l_tmp2 = l_mac(self.l_tmp, self.crossfade_gain, x);
        }
        l_shl(l_tmp2, self.exp)
    }

    /// The gain and exponent matching the noise energy to the last frame's energy. With
    /// `require_white` (the non-tonal path) nothing changes when the white noise energy is not
    /// positive.
    fn match_energy(
        &mut self,
        nrg_noise_in_last_frame: i32,
        nrg_white_noise: i32,
        ld: i16,
        last_spectral_data_exp: i16,
        mdct_spectrum_exp: &mut i16,
        require_white: bool,
    ) {
        let mut exp_last = add(ld, shl(last_spectral_data_exp, 1));
        let mut exp_noise = add(ld, 30);

        if require_white && nrg_white_noise <= 0 {
            return;
        }

        let mut nrg_last = nrg_noise_in_last_frame;
        let mut nrg_white = nrg_white_noise;
        let shift_last = norm_l(nrg_last);
        nrg_last = l_shl(nrg_last, shift_last);
        exp_last = sub(exp_last, shift_last);
        let shift_white = norm_l(nrg_white);
        nrg_white = l_shl(nrg_white, shift_white);
        exp_noise = sub(exp_noise, shift_white);

        let mut exp = sub(exp_last, exp_noise);

        if nrg_last > nrg_white {
            nrg_last = l_shr(nrg_last, 1);
            exp = add(exp, 1);
        }
        let mut tmp = div_l(nrg_last, round_word(nrg_white));
        tmp = sqrt16(tmp, &mut exp);
        self.g = mult_r(self.g, tmp);

        self.l_tmp = l_deposit_h(0);
        let ld = sub(last_spectral_data_exp, 15);
        exp = sub(ld, exp);

        if exp > 0 {
            self.g = shr(self.g, exp);
            *mdct_spectrum_exp = last_spectral_data_exp;
        } else {
            self.crossfade_gain = shl(self.crossfade_gain, exp);
            *mdct_spectrum_exp = sub(last_spectral_data_exp, exp);
        }
        // make a headroom for mdct_shaping
        exp = sub(*mdct_spectrum_exp, SPEC_EXP_DEC);
        if exp < 0 {
            *mdct_spectrum_exp = SPEC_EXP_DEC;
        } else {
            exp = 0;
        }
        self.exp = exp;
    }
}

/// `TonalMDCTConceal_InsertNoise`: `mdct_spectrum` (`last_block_data.n_samples` lines) and its
/// exponent receive the concealment noise; `p_seed` is the noise seed in and out.
pub fn tonal_mdct_conceal_insert_noise(
    this: &mut Tonalmdctconceal,
    mdct_spectrum: &mut [i32],
    mdct_spectrum_exp: &mut i16,
    tonal_concealment_active: i8,
    p_seed: &mut i16,
    tilt_comp_factor: i16,
    crossfade_gain: i16,
    cross_over_freq: i16,
) {
    let mut rnd: i16 = 1977;
    if this.last_block_data.block_is_concealed != 0 {
        rnd = *p_seed;
    }

    if this.last_block_data.block_is_valid == 0 {
        // may just become active if the very first frame is lost
        set32(mdct_spectrum, 0, this.n_samples);
        *mdct_spectrum_exp = SPEC_EXP_DEC;
    } else {
        let last_samples = this.last_block_data.n_samples;
        let last_exp = this.last_block_data.spectral_data_exp;
        // `spectral_data` is always assigned by the init of the concealment.
        let last_spectrum = this.last_block_data.spectral_data.unwrap_or(0);
        // the reference's pointer runs on into the second buffer for a block longer than one
        let last_spectrum = &this.spectral_data_buffers.as_flattened()[last_spectrum * 960..];

        let l_tmp: i32 = 805_306_368; // 0.375 in Q31
        let mut inv_exp: i16 = 15;
        let inv_samples = inv16(last_samples, &mut inv_exp);
        let mut exp: i16 = 0;
        let tilt_factor = round_word(basop_util_f_pow(
            l_tmp.max(l_deposit_h(tilt_comp_factor)),
            0,
            l_deposit_h(inv_samples),
            inv_exp,
            &mut exp,
        ));
        // next op may result in 32768
        let tilt_factor = shl(tilt_factor, exp);

        let ld = sub(14, norm_s(last_samples));
        let mut fill = NoiseFill {
            rnd,
            tilt: 32767, // 1.0 in Q15
            tilt_factor,
            fac: shr(-32768, ld),
            nrg_noise_in_last_frame: l_deposit_h(0),
            nrg_white_noise: l_deposit_h(0),
        };
        let mut mix = Mix {
            g: sub(32767, crossfade_gain),
            crossfade_gain,
            exp,
            l_tmp,
        };

        if tonal_concealment_active == 0 {
            for i in 0..cross_over_freq as usize {
                mdct_spectrum[i] = fill.line(last_spectrum[i]);
            }

            if fill.nrg_noise_in_last_frame == 0 {
                set32(mdct_spectrum, 0, cross_over_freq);
                *mdct_spectrum_exp = SPEC_EXP_DEC;
            } else {
                mix.match_energy(
                    fill.nrg_noise_in_last_frame,
                    fill.nrg_white_noise,
                    ld,
                    last_exp,
                    mdct_spectrum_exp,
                    true,
                );

                for i in 0..cross_over_freq as usize {
                    mdct_spectrum[i] = mix.line(last_spectrum[i], mdct_spectrum[i]);
                }
            }
            let shift = sub(last_exp, sub(*mdct_spectrum_exp, 16));
            for i in cross_over_freq as usize..last_samples as usize {
                mdct_spectrum[i] = l_shl(l_deposit_l(last_spectrum[i]), shift);
            }
        } else {
            let tci = tci_view(&mut this.time_data_buffer);
            // The reference asserts numIndexes > 0.
            let num_indexes = *tci.num_indexes;
            let lower = &*tci.lower_index;
            let upper = &*tci.upper_index;
            let last_group = (num_indexes - 1) as usize;

            for l in lower[0]..=upper[0] {
                mdct_spectrum[l as usize] = l_deposit_l(0);
            }

            for l in 0..lower[0] as usize {
                mdct_spectrum[l] = fill.line(last_spectrum[l]);
            }

            for i in 1..num_indexes as usize {
                fill.skip_group(upper[i - 1] - lower[i - 1] + 1);

                for l in lower[i]..=upper[i] {
                    mdct_spectrum[l as usize] = l_deposit_l(0);
                }

                for l in (upper[i - 1] + 1) as usize..lower[i] as usize {
                    mdct_spectrum[l] = fill.line(last_spectrum[l]);
                }
            }

            fill.skip_group(upper[last_group] - lower[last_group] + 1);

            for l in (add(upper[last_group], 1) as usize)..cross_over_freq as usize {
                mdct_spectrum[l] = fill.line(last_spectrum[l]);
            }

            if fill.nrg_noise_in_last_frame == 0 {
                set32(mdct_spectrum, 0, cross_over_freq);
                *mdct_spectrum_exp = SPEC_EXP_DEC;
            } else {
                mix.match_energy(
                    fill.nrg_noise_in_last_frame,
                    fill.nrg_white_noise,
                    ld,
                    last_exp,
                    mdct_spectrum_exp,
                    false,
                );

                for l in 0..lower[0] as usize {
                    mdct_spectrum[l] = mix.line(last_spectrum[l], mdct_spectrum[l]);
                }

                for i in 1..num_indexes as usize {
                    for l in (upper[i - 1] + 1) as usize..lower[i] as usize {
                        mdct_spectrum[l] = mix.line(last_spectrum[l], mdct_spectrum[l]);
                    }
                }

                // initialize bins of tonal components with zero: basically not necessary, but
                // currently the whole spectrum is rescaled in mdct_noiseShaping() and then there
                // would be a processing of uninitialized values
                for i in 0..num_indexes as usize {
                    for l in lower[i]..=upper[i] {
                        mdct_spectrum[l as usize] = l_deposit_l(0);
                    }
                }

                for l in (add(upper[last_group], 1) as usize)..cross_over_freq as usize {
                    mdct_spectrum[l] = mix.line(last_spectrum[l], mdct_spectrum[l]);
                }
            }
            let shift = sub(last_exp, sub(*mdct_spectrum_exp, 16));
            for l in cross_over_freq as usize..last_samples as usize {
                mdct_spectrum[l] = l_shl(l_deposit_l(last_spectrum[l]), shift);
            }
        }
        rnd = fill.rnd;
    }

    *p_seed = rnd;
}
