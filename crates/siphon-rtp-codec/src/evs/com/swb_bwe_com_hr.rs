//! Noise filling of the high-rate SWB BWE (TS 26.442 `lib_com/swb_bwe_com_hr_fx.c`; TS 26.445
//! §6.3.3.2.2).

use crate::evs::cnst::WIDTH_BAND;
use crate::evs::com::math_op::i_mult2;
use crate::evs::com::tools::random;
use crate::itu::basic_ops::{abs_s, add, div_s, mult_r, negate, shl, shr, sub};
use crate::itu::stl2009::i_mult;

const BAND: usize = WIDTH_BAND as usize;

/// `swb_hr_nonzero_subband_noise_fill_fx`: in a bright frame (`tilt_wb_fx` above 10240) replace
/// every zero bin of the `nsv` sub-bands of `n` bins in `t_audio` by a random-signed half of the
/// sub-band's smallest non-zero magnitude.
fn swb_hr_nonzero_subband_noise_fill(
    tilt_wb_fx: i16,
    t_audio: &mut [i16],
    bwe_highrate_seed: &mut i16,
    n: i16,
    nsv: i16,
    q_audio: i16,
) {
    if sub(tilt_wb_fx, 10240) <= 0 {
        return;
    }
    for i in 0..nsv {
        let mut min_bwe: i16 = 32767;
        let mut max_bwe: i16 = 0;
        let base = i_mult2(i, n) as usize;
        for j in 0..n as usize {
            let tmp_f = abs_s(t_audio[base + j]);
            max_bwe = tmp_f.max(max_bwe);
            if tmp_f > 0 {
                min_bwe = tmp_f.min(min_bwe);
            }
        }

        if sub(max_bwe, min_bwe) == 0 && sub(min_bwe, shl(1, q_audio)) > 0 {
            min_bwe = mult_r(min_bwe, 16384);
        }

        for slot in &mut t_audio[base..base + n as usize] {
            if *slot == 0 {
                let mut tmp = mult_r(min_bwe, 16384);
                if random(bwe_highrate_seed) <= 0 {
                    tmp = negate(tmp);
                }
                *slot = tmp;
            }
        }
    }
}

/// One 8-bin sub-band at `to` filled as `alpha * t_audio[from..] + beta * noise` (Q`q_audio`).
fn swb_hr_noise_fill_copy_band(
    t_audio: &mut [i16],
    to: usize,
    from: usize,
    alpha_fx: i16,
    beta_fx: i16,
    tmp_exp: i16,
    bwe_highrate_seed: &mut i16,
) {
    for k in 0..BAND {
        let tmp2 = mult_r(alpha_fx, t_audio[from + k]);
        let tmp3 = mult_r(beta_fx, shr(random(bwe_highrate_seed), tmp_exp));
        t_audio[to + k] = add(tmp2, tmp3);
    }
}

/// `swb_hr_noise_fill_fx`: fill the sub-bands the AVQ left empty (`nq[i] == 0`) with noise
/// shaped like the coded neighbours, then the zero bins of the coded ones. A transient frame
/// takes plain random noise.
pub fn swb_hr_noise_fill(
    is_transient: i16,
    spect_start: i16,
    spect_end: i16,
    tilt_wb_fx: i16,
    pitch_fx: i16,
    nq: &[i16],
    mut nsv: i16,
    bwe_highrate_seed: &mut i16,
    t_audio: &mut [i16],
    q_audio: i16,
) {
    if is_transient != 0 {
        let tmp_exp = sub(16, q_audio);
        for i in 0..nsv {
            if nq[i as usize] == 0 {
                let tmp = i_mult(i, WIDTH_BAND) as usize;
                for slot in &mut t_audio[tmp..tmp + BAND] {
                    *slot = shr(random(bwe_highrate_seed), tmp_exp); // Q_audio
                }
            }
        }
    } else {
        let tmp_exp = sub(15, q_audio);

        nsv = shr(sub(spect_end, spect_start), 3);
        let alpha_fx: i16 = 8192; // Q15
        let beta_fx: i16 = if sub(tilt_wb_fx, 10240) > 0 || sub(6400, pitch_fx) > 0 {
            8192 // Q15
        } else {
            div_s(1600, pitch_fx) // Q15+4-4 ->Q15
        };

        let mut i: i16 = 0;
        if nq[i as usize] == 0 {
            i = 1;
            while sub(i, nsv) < 0 && nq[i as usize] == 0 {
                i += 1;
            }

            let pos_start = i;
            while sub(i, nsv) < 0 && nq[i as usize] != 0 {
                i += 1;
            }

            let mut pos_end = sub(i, 1);
            if sub(pos_end, shl(pos_start, 1)) > 0 {
                pos_end = sub(shl(pos_start, 1), 1);
            }

            let mut incr = pos_end;
            let mut j = sub(pos_start, 1);
            while j >= 0 {
                swb_hr_noise_fill_copy_band(
                    t_audio,
                    shl(j, 3) as usize,
                    shl(incr, 3) as usize,
                    alpha_fx,
                    beta_fx,
                    tmp_exp,
                    bwe_highrate_seed,
                );
                if sub(incr, pos_start) < 0 {
                    incr = pos_end;
                } else {
                    incr = sub(incr, 1);
                }
                j -= 1;
            }
        }

        while sub(i, nsv) < 0 {
            if nq[i as usize] == 0 {
                let pos_start = i;
                let mut pos_end = i;

                for j in pos_start..nsv {
                    if nq[j as usize] != 0 {
                        i = j;
                        pos_end = j;
                        break;
                    }
                }

                if sub(pos_start, pos_end) == 0 {
                    i = nsv;
                    pos_end = nsv;
                }

                let mut incr = sub(pos_start, 1);
                let mut j = sub(pos_end, 1);
                while j >= pos_start {
                    swb_hr_noise_fill_copy_band(
                        t_audio,
                        shl(j, 3) as usize,
                        shl(incr, 3) as usize,
                        alpha_fx,
                        beta_fx,
                        tmp_exp,
                        bwe_highrate_seed,
                    );
                    incr = sub(incr, 1);
                    if incr < 0 {
                        incr = sub(pos_start, 1);
                    }
                    j -= 1;
                }
            } else {
                i += 1;
            }
        }
    }

    swb_hr_nonzero_subband_noise_fill(
        tilt_wb_fx,
        t_audio,
        bwe_highrate_seed,
        WIDTH_BAND,
        nsv,
        q_audio,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dark_frame_leaves_zero_bins_of_coded_bands_alone() {
        let mut t_audio = [0_i16; 64];
        t_audio[3] = 400;
        let mut seed = 21845;
        swb_hr_nonzero_subband_noise_fill(0, &mut t_audio, &mut seed, 8, 8, 12);
        assert_eq!(t_audio[0], 0);
        assert_eq!(seed, 21845);
    }

    #[test]
    fn bright_frame_fills_zero_bins_with_half_the_smallest_magnitude() {
        let mut t_audio = [0_i16; 8];
        t_audio[1] = 1000;
        t_audio[2] = -2000;
        let mut seed = 1;
        swb_hr_nonzero_subband_noise_fill(20000, &mut t_audio, &mut seed, 8, 1, 4);
        assert_eq!(t_audio[1], 1000);
        for &value in [t_audio[0], t_audio[3], t_audio[7]].iter() {
            assert_eq!(value.abs(), 500);
        }
    }

    #[test]
    fn transient_noise_only_touches_empty_bands() {
        let mut t_audio = [7_i16; 32];
        let nq = [0, 3, 0, 5];
        let mut seed = 5;
        swb_hr_noise_fill(1, 0, 32, 0, 100, &nq, 4, &mut seed, &mut t_audio, 8);
        assert!(t_audio[8..16].iter().all(|&value| value == 7));
        assert!(t_audio[24..32].iter().all(|&value| value == 7));
        assert!(t_audio[0..8].iter().any(|&value| value != 7));
    }
}
