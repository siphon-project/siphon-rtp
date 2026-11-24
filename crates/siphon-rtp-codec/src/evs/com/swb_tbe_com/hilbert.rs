//! SHB spectrum flipping, Hilbert-transform down-mixing and the Gaussian random excitation
//! (TS 26.442 `lib_com/swb_tbe_com_fx.c`; TS 26.445 §6.1.3.1).

use crate::evs::basop::{madd_32_16, mult_32_16};
use crate::evs::com::modif_fs::decimate_allpass_steep;
use crate::evs::com::tools::random;
use crate::evs::com::tools::{copy, copy32};
use crate::evs::rom::{GAUS_DICO_SWB_FX, HILBERT_COEFFS_FX};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_mult, l_shl, l_shr, l_sub,
    mult_r, negate, round_word, sub,
};
use crate::itu::stl2009::l_mult0;

/// `length` of the longest block the down-mix works on (32 kHz, 20 ms).
const MAX_LENGTH: usize = 640;

/// `Hilbert_transform_fx`: one all-pass stage of the 32-bit complex (real/imaginary) Hilbert
/// down-mix, stage `hb_stage_id` 1, 2 or 3 (stages 0 and 2 are the feed-forward halves, 1 and 3 the
/// recursive ones). `tmp_*` is the stage input, `tmpi_*` its output; the recursive stages read
/// their own output history `tmpi_*[i]`, `tmpi_*[i + 2]` and write `tmpi_*[i + 4]`.
pub fn hilbert_transform(
    tmp_r: &[i32],
    tmp_i: &[i32],
    tmpi_r: &mut [i32],
    tmpi_i: &mut [i32],
    length: i16,
    hb_stage_id: i16,
) {
    let hb_filter_stage = (2 * hb_stage_id) as usize;
    let offset: usize = usize::from(hb_stage_id == 0);
    let length = length.max(0) as usize;
    let coeff = |row: usize, column: usize| HILBERT_COEFFS_FX[row][column];

    if hb_stage_id == 0 || hb_stage_id == 2 {
        for i in 0..length {
            let mut l_tmp = mult_32_16(tmp_r[i + 4], coeff(hb_filter_stage, offset));
            l_tmp = madd_32_16(l_tmp, tmp_r[i + 2], coeff(hb_filter_stage, 2 + offset));
            l_tmp = madd_32_16(l_tmp, tmp_r[i], coeff(hb_filter_stage, 4 + offset));
            tmpi_r[i] = l_shl(l_tmp, 1);

            l_tmp = mult_32_16(tmp_i[i + 4 + offset], coeff(hb_filter_stage + 1, 0));
            l_tmp = madd_32_16(l_tmp, tmp_i[i + 2 + offset], coeff(hb_filter_stage + 1, 2));
            l_tmp = madd_32_16(l_tmp, tmp_i[i + offset], coeff(hb_filter_stage + 1, 4));
            tmpi_i[i] = l_shl(l_tmp, 1);
        }
    } else if hb_stage_id == 1 || hb_stage_id == 3 {
        for i in 0..length {
            let mut l_tmp = mult_32_16(tmpi_r[i + 2], coeff(hb_filter_stage, 2));
            l_tmp = madd_32_16(l_tmp, tmpi_r[i], coeff(hb_filter_stage, 4));
            tmpi_r[i + 4] = l_sub(tmp_r[i], l_shl(l_tmp, 1));

            l_tmp = mult_32_16(tmpi_i[i + 2], coeff(hb_filter_stage + 1, 2));
            l_tmp = madd_32_16(l_tmp, tmpi_i[i], coeff(hb_filter_stage + 1, 4));
            tmpi_i[i + 4] = l_sub(tmp_i[i], l_shl(l_tmp, 1));
        }
    }
}

/// `Hilbert_transform_sp_fx`: stage 0 of the down-mix on 16-bit input (`HB_stage_id` 0), into the
/// 32-bit `tmpi_r` / `tmpi_i`.
pub fn hilbert_transform_sp(
    tmp_r: &[i16],
    tmp_i: &[i16],
    tmpi_r: &mut [i32],
    tmpi_i: &mut [i32],
    length: i16,
    hb_stage_id: i16,
) {
    let hb_filter_stage = (2 * hb_stage_id) as usize;
    let offset: usize = usize::from(hb_stage_id == 0);
    let coeff = |row: usize, column: usize| HILBERT_COEFFS_FX[row][column];

    for i in 0..length.max(0) as usize {
        let mut l_tmp = l_mult(tmp_r[i + 4], coeff(hb_filter_stage, offset));
        l_tmp =
            crate::itu::basic_ops::l_mac(l_tmp, tmp_r[i + 2], coeff(hb_filter_stage, 2 + offset));
        l_tmp = crate::itu::basic_ops::l_mac(l_tmp, tmp_r[i], coeff(hb_filter_stage, 4 + offset));
        tmpi_r[i] = l_shl(l_tmp, 1);

        l_tmp = l_mult(tmp_i[i + 4 + offset], coeff(hb_filter_stage + 1, 0));
        l_tmp = crate::itu::basic_ops::l_mac(
            l_tmp,
            tmp_i[i + 2 + offset],
            coeff(hb_filter_stage + 1, 2),
        );
        l_tmp =
            crate::itu::basic_ops::l_mac(l_tmp, tmp_i[i + offset], coeff(hb_filter_stage + 1, 4));
        tmpi_i[i] = l_shl(l_tmp, 1);
    }
}

/// `flip_and_downmix_generic_fx`: flips the spectrum of the 32 kHz `input[0..length]` (it negates
/// the even samples of `input` in place), splits it into its analytic signal by four Hilbert
/// stages and mixes it down by 17-sample-period cos / sin tables into `output`. `mem1_ext` (5),
/// `mem2_ext` (8) and `mem3_ext` (8) hold the stage memories, `phase_state` the mixing phase.
pub fn flip_and_downmix_generic(
    input: &mut [i16],
    output: &mut [i16],
    length: i16,
    mem1_ext: &mut [i32],
    mem2_ext: &mut [i32],
    mem3_ext: &mut [i32],
    phase_state: &mut i16,
) {
    const LOCAL_NEGSIN_TABLE17: [i16; 17] = [
        0, -11793, -22005, -29268, -32609, -31580, -26319, -17530, -6393, 6393, 17530, 26319,
        31580, 32609, 29268, 22005, 11793,
    ];
    const LOCAL_COS_TABLE17: [i16; 17] = [
        32767, 30571, 24279, 14732, 3212, -8739, -19519, -27683, -32137, -32137, -27683, -19519,
        -8739, 3212, 14732, 24279, 30571,
    ];
    const PERIOD: i16 = 17;

    let mut tmp_16 = [0i16; MAX_LENGTH + 5];
    let mut tmpi_r = [0i32; MAX_LENGTH];
    let mut tmpi_i = [0i32; MAX_LENGTH];
    let mut tmpi2_r = [0i32; MAX_LENGTH + 4];
    let mut tmpi2_i = [0i32; MAX_LENGTH + 4];
    let mut tmp_r = [0i32; MAX_LENGTH + 4];
    let mut tmp_i = [0i32; MAX_LENGTH + 4];
    let n = length.max(0) as usize;

    for i in (0..n).step_by(2) {
        input[i] = negate(input[i]);
    }

    // stage 0: 16-bit input with the 5-sample memory in front
    copy(input, &mut tmp_16[5..], length);
    for i in 0..5 {
        tmp_16[i] = extract_h(mem1_ext[i]);
    }
    hilbert_transform_sp(&tmp_16, &tmp_16, &mut tmpi_r, &mut tmpi_i, length, 0);
    for i in 0..5 {
        mem1_ext[i] = l_deposit_h(tmp_16[i + n]);
    }

    // stage 1
    copy32(mem2_ext, &mut tmpi2_r, 4);
    copy32(mem3_ext, &mut tmpi2_i, 4);
    hilbert_transform(&tmpi_r, &tmpi_i, &mut tmpi2_r, &mut tmpi2_i, length, 1);

    // stage 2
    copy32(&mem2_ext[4..], &mut tmp_r, 4);
    copy32(&mem3_ext[4..], &mut tmp_i, 4);
    hilbert_transform(&tmpi2_r, &tmpi2_i, &mut tmpi_r, &mut tmpi_i, length, 2);
    copy32(&tmpi2_r[n..], mem2_ext, 4);
    copy32(&tmpi2_i[n..], mem3_ext, 4);

    // stage 3
    hilbert_transform(&tmpi_r, &tmpi_i, &mut tmp_r, &mut tmp_i, length, 3);
    copy32(&tmp_r[n..], &mut mem2_ext[4..], 4);
    copy32(&tmp_i[n..], &mut mem3_ext[4..], 4);

    if *phase_state >= PERIOD {
        *phase_state = 0;
    }
    let mut i = 0usize;
    let mut j = *phase_state;
    while i < n {
        while j < PERIOD && i < n {
            let mut l_tmp = mult_32_16(tmp_r[i + 4], LOCAL_COS_TABLE17[j as usize]);
            l_tmp = madd_32_16(l_tmp, tmp_i[i + 4], LOCAL_NEGSIN_TABLE17[j as usize]);
            output[i] = round_word(l_tmp);
            i += 1;
            j += 1;
        }
        if j >= PERIOD {
            j = 0;
        }
    }
    *phase_state = j;
}

/// `flip_spectrum_fx`: negates every even sample of `input[0..length]` into `output`.
pub fn flip_spectrum(input: &[i16], output: &mut [i16], length: i16) {
    for i in (0..length.max(0) as usize).step_by(2) {
        output[i] = negate(input[i]);
        output[i + 1] = input[i + 1];
    }
}

/// `flip_spectrum_and_decimby4_fx`: flips the spectrum of the 320-sample `input` (with an
/// optional linear fade-in over its first quarter when `ramp_flag`) and decimates it by four
/// through two all-pass decimators with the memories `mem1` and `mem2`. The decimators always
/// consume 320 samples, as the reference's do; every caller passes `length` 320.
pub fn flip_spectrum_and_decimby4(
    input: &[i16],
    output: &mut [i16],
    length: i16,
    mem1: &mut [i16],
    mem2: &mut [i16],
    ramp_flag: i16,
) {
    let mut tmp = [0i16; 320 / 2];
    let mut input_change = [0i16; 320];
    let n = length.max(0) as usize;

    let mut i = 0usize;
    if ramp_flag != 0 {
        let factor = div_s(4, length);
        while i < n / 4 {
            let tmp1 = extract_l(l_mult0(i as i16, factor));
            let tmp2 = extract_l(l_mult0(add(i as i16, 1), factor));
            input_change[i] = negate(mult_r(input[i], tmp1));
            input_change[i + 1] = mult_r(input[i + 1], tmp2);
            i += 2;
        }
    }
    while i < n {
        input_change[i] = negate(input[i]);
        input_change[i + 1] = input[i + 1];
        i += 2;
    }
    decimate_allpass_steep(&input_change, mem1, 320, &mut tmp);
    decimate_allpass_steep(&tmp, mem2, 320 / 2, output);
}

/// `create_random_vector_fx`: `length` samples of the SHB Gaussian-ish excitation, the sum of two
/// scaled entries of the 256-entry `gaus_dico_swb` table indexed by the two LCG `seed`s.
pub fn create_random_vector(output: &mut [i16], length: i16, seed: &mut [i16]) {
    let mut seed0 = seed[0];
    let mut seed1 = seed[1];
    let mut l_tmp = l_abs(mult_32_16(2144047674, random(&mut seed0)));
    let mut j = extract_l(l_shr(l_tmp, 23));
    j &= 0xff;
    l_tmp = l_abs(mult_32_16(2144047674, random(&mut seed1)));
    let mut k = extract_l(l_shr(l_tmp, 23));
    k &= 0xff;
    while sub(k, j) == 0 {
        l_tmp = l_abs(mult_32_16(2144047674, random(&mut seed1)));
        k = extract_l(l_shr(l_tmp, 23));
        k &= 0xff;
    }

    let scale1: i16 = if random(&mut seed0) < 0 {
        -18021
    } else {
        18021
    };
    let scale2: i16 = if random(&mut seed1) < 0 { -7208 } else { 7208 };
    seed[0] = seed0;
    seed[1] = seed1;

    for out in output.iter_mut().take(length.max(0) as usize) {
        j &= 0xff;
        k &= 0xff;
        *out = round_word(l_add(
            l_mult(scale1, GAUS_DICO_SWB_FX[j as usize]),
            l_mult(scale2, GAUS_DICO_SWB_FX[k as usize]),
        ));
        j += 1;
        k += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flip_spectrum_negates_the_even_samples() {
        let mut output = [0i16; 4];
        flip_spectrum(&[1, 2, 3, -32768], &mut output, 4);
        assert_eq!(output, [-1, 2, -3, -32768]);
    }

    #[test]
    fn create_random_vector_is_deterministic_in_the_seeds() {
        let mut seed_a = [23i16, 59];
        let mut seed_b = seed_a;
        let mut a = [0i16; 16];
        let mut b = [0i16; 16];
        create_random_vector(&mut a, 16, &mut seed_a);
        create_random_vector(&mut b, 16, &mut seed_b);
        assert_eq!(a, b);
        assert_eq!(seed_a, seed_b);
        assert_ne!(seed_a, [23, 59]);
        assert!(a.iter().any(|&sample| sample != 0));
    }

    #[test]
    fn downmix_of_silence_is_silence_and_keeps_the_phase_in_range() {
        let mut input = [0i16; 40];
        let mut output = [1i16; 40];
        let mut mem1 = [0i32; 5];
        let mut mem2 = [0i32; 8];
        let mut mem3 = [0i32; 8];
        let mut phase = 40;
        flip_and_downmix_generic(
            &mut input,
            &mut output,
            40,
            &mut mem1,
            &mut mem2,
            &mut mem3,
            &mut phase,
        );
        assert_eq!(output, [0; 40]);
        assert!((0..17).contains(&phase));
    }
}
