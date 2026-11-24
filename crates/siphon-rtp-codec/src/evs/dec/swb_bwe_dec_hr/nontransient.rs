//! Non-transient frame decoding of `swb_bwe_dec_hr_fx` (TS 26.442 `lib_dec/swb_bwe_dec_hr_fx.c`):
//! one global gain, a four-band envelope, an AVQ-coded spectrum with an optional second stage, and
//! the reconstruction of the 12.2-20 kHz spectrum.

use super::{gain_dequant_hr, HrBranch, HrFrame, FULL_FB_COEFS, Q_32_BITS, Q_GUARD};
use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    BWE_HR_NONTRANS_EN_LIMIT2_FX_Q14, BWE_HR_NONTRANS_EN_LIMIT2_FX_Q15,
    BWE_HR_NONTRANS_EN_LIMIT3_FX_Q15, FB_BWE_HIGHRATE, L_FRAME32K, L_FRAME48K,
    MIN_GLOB_GAIN_BWE_HR_FX, NBITS_ENVELOPE_BWE_HR1, NBITS_ENVELOPE_BWE_HR2,
    NBITS_GLOB_GAIN_BWE_HR, NBITS_HF_GAIN_BWE_HR, NBITS_THRESH_BWE_HR, NSV_MAX, NSV_OVERLAP,
    NUM_NONTRANS_END_FREQ_COEF, NUM_NONTRANS_START_FREQ_COEF, N_BANDS_BWE_HR, SWB_BWE_HIGHRATE,
    WIDTH_BAND, WIDTH_NONTRANS_FREQ_COEF,
};
use crate::evs::com::basop_util::basop_util_divide1616_scale;
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::math_op::i_mult2;
use crate::evs::com::swb_bwe_com_hr::swb_hr_noise_fill;
use crate::evs::com::tools::{copy_scale_sig32_16, find_max_norm32, sqrt_ratio32, sum16};
use crate::evs::dec::avq_dec::avq_demuxdec;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    OVERLAP_COEFS_48KHZ_FX, OVERLAP_COEFS_FX, SWB_HR_ENV_CODE1_FX, SWB_HR_ENV_CODE2_FX,
};
use crate::itu::basic_ops::{
    add, l_add, l_deposit_h, l_mac, l_msu, l_mult, l_shl, l_shr, l_sub, mult, mult_r, round_word,
    shl, shr, sub,
};
use crate::itu::stl2009::{i_mult, l_mac0, l_msu0, l_mult0, mac_r};

const BAND: usize = WIDTH_BAND as usize;
const NSV: usize = NSV_MAX as usize;
/// `NUM_NONTRANS_END_FREQ_COEF - NUM_NONTRANS_START_FREQ_COEF`.
const SPECTRUM_LEN: i16 = NUM_NONTRANS_END_FREQ_COEF - NUM_NONTRANS_START_FREQ_COEF;
const START: usize = NUM_NONTRANS_START_FREQ_COEF as usize;
const END: usize = NUM_NONTRANS_END_FREQ_COEF as usize;

/// The header of a non-transient frame and what the spectrum decoding leaves behind.
struct Header {
    en_band: [i16; N_BANDS_BWE_HR as usize],
    min_env: i16,
    max_env: i16,
    /// Sub-band with the smallest envelope (0..3).
    pos: i16,
    en_noncoded: i16,
    gain_fx: i16,
    exp1: i16,
    env: i16,
    /// Number of AVQ sub-vectors of the first stage.
    nsv: i16,
    nbits: i16,
}

/// `swb_bwe_dec_hr_fx` for a non-transient frame: decode into `t_audio32` (Q`Q_32_BITS`) and save the
/// coefficients for a later erasure. Returns the frame's gain and envelope mean.
pub(super) fn swb_bwe_dec_hr_nontransient(
    st: &mut DecoderState,
    t_audio: &mut [i16],
    t_audio32: &mut [i32],
    frame: &HrFrame,
) -> HrBranch {
    let mut nq = [0i16; NSV];
    let mut t_audio_tmp = [0i16; NSV * BAND];

    let mut header = nontransient_header(st, frame);
    nontransient_spectrum(st, &mut header, &mut nq, &mut t_audio_tmp);
    let max_written = nontransient_reorder(frame, &header, t_audio, &t_audio_tmp, &mut nq);
    nontransient_noise_fill(st, frame, &header, &nq, t_audio, t_audio32, max_written);
    nontransient_reconstruct(st, frame, &mut header, t_audio, t_audio32);

    HrBranch {
        is_transient: 0,
        gain_fx: header.gain_fx,
        env: header.env,
    }
}

/// Global gain, band envelope, the sub-band to drop at low rate and the energy of the non-coded
/// part, read from the bitstream.
fn nontransient_header(st: &mut DecoderState, frame: &HrFrame) -> Header {
    let mut en_band = [0i16; N_BANDS_BWE_HR as usize];
    // subtract one bit for is_transient flag
    let mut nbits = sub(frame.nbits_total, 1);

    // global gain and envelope decoding

    // get global gain
    let mut ind1 = get_next_indice(st, NBITS_GLOB_GAIN_BWE_HR) as i16;
    let mut exp1: i16 = 0;
    let gain_fx = gain_dequant_hr(
        ind1,
        MIN_GLOB_GAIN_BWE_HR_FX,
        NBITS_GLOB_GAIN_BWE_HR,
        &mut exp1,
    );

    // get energy per band
    ind1 = get_next_indice(st, NBITS_ENVELOPE_BWE_HR1) as i16;
    let ind2 = get_next_indice(st, NBITS_ENVELOPE_BWE_HR2) as i16;

    let mut temp = shl(ind1, 1) as usize;
    en_band[0] = SWB_HR_ENV_CODE1_FX[temp];
    en_band[1] = SWB_HR_ENV_CODE1_FX[temp + 1];
    temp = shl(ind2, 1) as usize;
    en_band[2] = SWB_HR_ENV_CODE2_FX[temp];
    en_band[3] = SWB_HR_ENV_CODE2_FX[temp + 1];

    // env = add(add(shr(en_band[0], 2), shr(en_band[1], 2)), add(shr(en_band[2], 2), shr(en_band[3], 2)));
    let env = mac_r(
        l_mac(
            l_mac(l_mult(en_band[0], 8192), en_band[1], 8192),
            en_band[2],
            8192,
        ),
        en_band[3],
        8192,
    );

    // choose sub-bands to be dequantized

    // find the subband with the min envelope
    let mut pos: i16 = 0;
    let mut min_env = en_band[0];
    let mut max_env = en_band[0];
    for j in 1..N_BANDS_BWE_HR as usize {
        if sub(en_band[j], min_env) < 0 {
            pos = j as i16;
        }
        min_env = min_env.min(en_band[j]);
        max_env = max_env.max(en_band[j]);
    }

    // decide the spectrum to be dequantized
    let mut spectrum = SPECTRUM_LEN;
    if sub(frame.nbits_total, NBITS_THRESH_BWE_HR) <= 0 {
        spectrum = sub(SPECTRUM_LEN - 64, shl(pos & 1, 3));
    }

    nbits = sub(
        nbits,
        NBITS_GLOB_GAIN_BWE_HR + NBITS_ENVELOPE_BWE_HR1 + NBITS_ENVELOPE_BWE_HR2,
    );

    // estimate energy of noncoded spectrum (14.4-20kHz)
    let mut en_noncoded = mult_r(min_env, 16384);

    if sub(st.extl, FB_BWE_HIGHRATE) == 0 {
        ind1 = get_next_indice(st, NBITS_HF_GAIN_BWE_HR) as i16;
        nbits = sub(nbits, NBITS_HF_GAIN_BWE_HR);

        if sub(ind1, 1) == 0 {
            // en_noncoded = BWE_HR_NONTRANS_EN_LIMIT1*(0.5*min_env) ==> 0.25*min_env
            en_noncoded = mult_r(min_env, BWE_HR_NONTRANS_EN_LIMIT2_FX_Q15 / 2);
        }
        if sub(ind1, 2) == 0 {
            // en_noncoded = 2.0*BWE_HR_NONTRANS_EN_LIMIT2*(0.5*min_env) ==> 1.2*min_env
            en_noncoded = round_word(l_shl(l_mult(BWE_HR_NONTRANS_EN_LIMIT2_FX_Q14, min_env), 1));
        }
        if sub(ind1, 3) == 0 {
            // en_noncoded = 2.0*BWE_HR_NONTRANS_EN_LIMIT3*(0.5*min_env) ==> 0.8*min_env
            en_noncoded = mult_r(BWE_HR_NONTRANS_EN_LIMIT3_FX_Q15, min_env);
        }
    }

    Header {
        en_band,
        min_env,
        max_env,
        pos,
        en_noncoded,
        gain_fx,
        exp1,
        env,
        // Nsv = i / WIDTH_BAND
        nsv: shr(spectrum, 3),
        nbits,
    }
}

/// AVQ decoding of the spectrum into `t_audio_tmp` (Q10), with the second AVQ stage that refines
/// the coded sub-vectors and fills empty ones when the bit budget allows. Updates `nq`.
fn nontransient_spectrum(
    st: &mut DecoderState,
    header: &mut Header,
    nq: &mut [i16; NSV],
    t_audio_tmp: &mut [i16; NSV * BAND],
) {
    let mut x_norm = [0i16; NSV * (BAND + 1)];
    let mut x_norm1 = [0i16; NSV * (BAND + 1)];
    let mut nq2 = [0i16; NSV];
    let mut nq_tmp = [0i16; NSV];
    let mut gain2_fx: i16 = 0;
    let mut exp2: i16 = 0;
    let mut nsv2: i16 = 0;
    let nsv = header.nsv;

    // AVQ decoding (dequantize normalized spectrum)
    avq_demuxdec(st, &mut x_norm, &mut header.nbits, nsv, nq);

    // second stage decoding
    if sub(header.nbits, 9 + NBITS_GLOB_GAIN_BWE_HR) >= 0 && sum16(nq, nsv) > 0 {
        let ind1 = get_next_indice(st, NBITS_GLOB_GAIN_BWE_HR) as i16;
        gain2_fx = gain_dequant_hr(
            ind1,
            MIN_GLOB_GAIN_BWE_HR_FX,
            NBITS_GLOB_GAIN_BWE_HR,
            &mut exp2,
        );
        // gain2_flt *= 0.0625f
        exp2 = add(exp2, 4);

        // calculate the number of subbands according to the rest bits
        if sub(header.nbits, 396) > 0 {
            nsv2 = 33;
        } else {
            // Here what is acheived is an integer divide by 12 with truncation.
            // nBits/12
            nsv2 = mult(header.nbits, 2731);
            // But, we have imprecision of the fraction so correction is necessary.
            // We crosscheck if 'Nsv2' is either too high or too low.
            // Finally, the result must satisfy:
            //   Nsv2 * 12 <= nBits (Nsv2 is not too high) AND
            //   nBits -  Nsv2 * 12 < 12 (Nsv2 is the highest divisor)
            let l_temp = l_msu0(header.nbits as i32, 12, nsv2);
            if l_sub(l_temp, 12) >= 0 {
                nsv2 = add(nsv2, 1);
            }
            if l_temp < 0 {
                nsv2 = sub(nsv2, 1);
            }
        }

        header.nbits = sub(header.nbits, NBITS_GLOB_GAIN_BWE_HR);
        avq_demuxdec(st, &mut x_norm1, &mut header.nbits, nsv2, &mut nq2);
    }

    // dequantization

    // set 't_audio' exp
    let t_audio_exp: i16 = 10;
    for i in 0..(nsv * WIDTH_BAND) as usize {
        t_audio_tmp[i] = shl(x_norm[i], t_audio_exp);
    }

    nq_tmp[..nsv as usize].copy_from_slice(&nq[..nsv as usize]);
    if sub(nsv2, nsv) > 0 {
        // Safety check, happens rarely
        nq_tmp[nsv as usize..nsv2 as usize].fill(0);
    }

    let mut incr: i16 = 0;
    let mut ptr16: usize = 0; // index into x_norm1
    let temp2 = sub(sub(exp2, 15), t_audio_exp); // go to Q't_audio'
    for i in 0..nsv as usize {
        if nq[i] == 0 && sub(incr, nsv2) < 0 {
            let temp = i << 3;
            for j in 0..BAND {
                let l_temp = l_mult(gain2_fx, x_norm1[ptr16]);
                ptr16 += 1;
                let l_temp = l_shr(l_temp, temp2); // go to Q't_audio'
                t_audio_tmp[temp + j] = round_word(l_temp);
            }
            // 'nq[i] = add(nq[i], nq2[incr])' replaced by 'nq[i] = nq2[incr]' because 'nq[i] == 0'
            nq[i] = nq2[incr as usize];
            incr = add(incr, 1);
        }
    }

    let temp3 = shl(-32768, temp2);
    let mut i: i16 = 0;
    while incr < nsv2 {
        // safety check, happens rarely
        if sub(i, nsv2) >= 0 {
            break;
        }

        if nq_tmp[i as usize] != 0 {
            let temp = (i as usize) << 3;
            for j in 0..BAND {
                let mut l_temp = l_mult(gain2_fx, x_norm1[ptr16]);
                ptr16 += 1;
                l_temp = l_msu(l_temp, t_audio_tmp[temp + j], temp3); // go to -Q't_audio'
                l_temp = l_shr(l_temp, temp2); // go to Q't_audio'
                t_audio_tmp[temp + j] = round_word(l_temp);
            }
            nq[i as usize] = add(nq[i as usize], nq2[incr as usize]);
            incr = add(incr, 1);
        }
        i += 1;
    }
}

/// Place the dequantised spectrum `t_audio_tmp` into `t_audio` from `NUM_NONTRANS_START_FREQ_COEF`.
/// At low rate the sub-band `pos` was not coded, and is rebuilt from a neighbour. Returns the number
/// of bins written.
fn nontransient_reorder(
    frame: &HrFrame,
    header: &Header,
    t_audio: &mut [i16],
    t_audio_tmp: &[i16; NSV * BAND],
    nq: &mut [i16; NSV],
) -> i16 {
    if sub(frame.nbits_total, NBITS_THRESH_BWE_HR) > 0 {
        t_audio[START..END].copy_from_slice(&t_audio_tmp[..SPECTRUM_LEN as usize]);
        // Update Maximum Written Location (from t_audio + NUM_NONTRANS_START_FREQ_COEF)
        return SPECTRUM_LEN;
    }

    let mut pos = header.pos;
    let mut ind1 = add(shl(pos, 6), i_mult2(shr(pos, 1), WIDTH_BAND));
    t_audio[START..START + ind1 as usize].copy_from_slice(&t_audio_tmp[..ind1 as usize]);

    // Update Maximum Written Location (from t_audio + NUM_NONTRANS_START_FREQ_COEF)
    let mut temp4 = ind1;

    let temp = add(pos, 1);
    let mut ind2 = add(shl(temp, 6), i_mult2(shr(temp, 1), WIDTH_BAND));
    let count = (SPECTRUM_LEN - ind2) as usize;
    t_audio[START + ind2 as usize..START + ind2 as usize + count]
        .copy_from_slice(&t_audio_tmp[ind1 as usize..ind1 as usize + count]);
    // Update Maximum Written Location (from t_audio + NUM_NONTRANS_START_FREQ_COEF)
    temp4 = temp4.max(SPECTRUM_LEN);

    // reconstruct non-encoded subband
    if sub(pos, 3) == 0 {
        t_audio.copy_within(START + 128..START + 128 + 72, START + 200);
        // Update Maximum Written Location (from t_audio + NUM_NONTRANS_START_FREQ_COEF)
        temp4 = temp4.max(200 + 72);

        nq.copy_within(16..16 + 9, 25);
    } else {
        pos &= 1;
        let temp3 = add(64, shl(pos, 3));
        t_audio.copy_within(
            START + ind2 as usize..START + ind2 as usize + temp3 as usize,
            START + ind1 as usize,
        );
        // Update Maximum Written Location (from t_audio + NUM_NONTRANS_START_FREQ_COEF)
        temp4 = temp4.max(add(ind1, temp3));

        ind1 = shr(ind1, 3);
        ind2 = shr(ind2, 3);

        let mut j: usize = 33;
        let mut i = sub(header.nsv, 1);
        while i >= ind1 {
            nq[j] = nq[i as usize];
            j -= 1;
            i -= 1;
        }

        let count = add(WIDTH_BAND, pos) as usize;
        nq.copy_within(ind2 as usize..ind2 as usize + count, ind1 as usize);
    }
    temp4
}

/// Noise-fill the empty sub-vectors of a low-rate frame and bring the 16-bit spectrum to Q`Q_32_BITS`
/// in `t_audio32`.
fn nontransient_noise_fill(
    st: &mut DecoderState,
    frame: &HrFrame,
    header: &Header,
    nq: &[i16; NSV],
    t_audio: &mut [i16],
    t_audio32: &mut [i32],
    max_written: i16,
) {
    let t_audio_exp: i16 = 10;
    // apply noise-fill
    if sub(header.nbits, 200) < 0 {
        swb_hr_noise_fill(
            0,
            NUM_NONTRANS_START_FREQ_COEF,
            NUM_NONTRANS_END_FREQ_COEF,
            round_word(l_shl(frame.l_tilt_wb, 3)), // Q(24+3-16) -> Q11
            frame.pitch,
            nq,
            header.nsv,
            &mut st.bwe_highrate_seed,
            &mut t_audio[START..],
            t_audio_exp,
        );
    }

    // Go from Q't_audio_exp' on 16 Bits to Q16 on 32 bits
    let j = shl(1, sub(Q_32_BITS, t_audio_exp));
    for i in 0..max_written as usize {
        // put in 'Q_32_BITS' in a 32 Bits
        t_audio32[START + i] = l_mult0(t_audio[START + i], j);
    }
}

/// Sum of squares of `count` bins from `at`, starting from the reference's epsilon of 1.
fn energy_with_epsilon(t_audio: &[i16], at: usize, count: usize) -> i32 {
    let mut l_temp = l_mac0(1, t_audio[at], t_audio[at]); // EPSILON
    for &value in &t_audio[at + 1..at + count] {
        l_temp = l_mac0(l_temp, value, value);
    }
    l_temp
}

/// Smoothing of 12.6-12.8 kHz at the boundary of the rebuilt sub-band (`pos == 3`, low rate):
/// ramp the level of the last coded 8 bins to that of the 8 after them.
fn nontransient_smooth_12k6(t_audio: &[i16], t_audio32: &mut [i32]) {
    let t_audio_exp: i16 = 10;
    let l_temp = energy_with_epsilon(t_audio, START + 200 - BAND, BAND);
    let l_temp2 = energy_with_epsilon(t_audio, START + 200, BAND);
    let mut temp: i16 = 0;
    let l_temp = sqrt_ratio32(l_temp, 0, l_temp2, 0, &mut temp);

    // if 'temp' is < 0 then it is req to shift right before substracting 1.0
    let mut temp2 = 0.min(temp);
    let mut l_temp = l_shl(l_temp, temp2);
    // Energy_flt - i*(Energy_flt-1.0)/8.0
    let l_temp2 = l_add(l_temp, l_shr(-2_147_483_647 - 1, 0.max(temp))); // 1.0 in same Q as Sqrt minus the Guard
                                                                         // / 8.0
    let l_step = l_shr(l_temp2, 3 + Q_GUARD);
    // Add Guard
    l_temp = l_shr(l_temp, Q_GUARD);
    // Set Exponent (relative to t_audio_exp (from 16 bits vector)
    temp2 = add(
        sub(temp, temp2),
        sub(Q_GUARD - (16 - Q_32_BITS), t_audio_exp),
    );

    for i in 0..BAND {
        let at = START + 200 + i;
        t_audio32[at] = l_shl(mult_32_16(l_temp, t_audio[at]), temp2);
        l_temp = l_sub(l_temp, l_step);
    }
}

/// Reconstruction of a non-transient frame after the spectrum is placed: smoothing, the 14.4-16(20)
/// kHz non-coded band, envelope denormalisation, window overlap, the global gain and the
/// coefficients saved for the next frame.
fn nontransient_reconstruct(
    st: &mut DecoderState,
    frame: &HrFrame,
    header: &mut Header,
    t_audio: &mut [i16],
    t_audio32: &mut [i32],
) {
    let output_frame = frame.output_frame;
    let t_audio_exp: i16 = 10;

    // smoothing 12.6-12.8kHz
    if sub(header.pos, 3) == 0 && sub(frame.nbits_total, 400) <= 0 {
        nontransient_smooth_12k6(t_audio, t_audio32);
    }

    // reconstruct 14.4-16(20) kHz spectrum
    let width_noncoded: i16 =
        if sub(st.extl, SWB_BWE_HIGHRATE) == 0 || sub(output_frame, L_FRAME32K) == 0 {
            L_FRAME32K - NUM_NONTRANS_END_FREQ_COEF
        } else {
            // st->extl == FB_BWE_HIGHRATE
            FULL_FB_COEFS - NUM_NONTRANS_END_FREQ_COEF
        };
    let wn = width_noncoded as usize;

    let l_temp = energy_with_epsilon(t_audio, END - BAND, BAND);
    let l_temp2 = energy_with_epsilon(t_audio, END - wn, BAND);
    let mut temp: i16 = 0;
    let l_temp = sqrt_ratio32(l_temp, 0, l_temp2, 0, &mut temp);

    // So part of the copy can be skipped because the loop that follows
    // will take the values from t_audio (16 bits)
    // Since 'width_noncoded' is always > WIDTH_BAND, we can substract it from the length
    // and adjust the offset accordingly
    let src = END + BAND - wn;
    t_audio32.copy_within(src..src + wn - BAND, END + BAND);

    // smoothing 14.4-14.8kHz
    temp = sub(temp, add(t_audio_exp, 16 - Q_32_BITS));
    for i in 0..BAND {
        let l_temp2 = mult_32_16(l_temp, t_audio[END - wn + i]);
        t_audio32[END + i] = l_shl(l_temp2, temp);
    }

    // envelope denormalization
    let mut at = START;
    for band in &header.en_band {
        for _ in 0..WIDTH_NONTRANS_FREQ_COEF {
            let l_temp = mult_32_16(t_audio32[at], *band);
            t_audio32[at] = l_shl(l_temp, 6); // Because 'en_band' is in Q9
            at += 1;
        }
    }

    nontransient_equalize(header, output_frame, width_noncoded, st.extl, t_audio32);

    // Overlap region
    let overlap: &[i16] = if sub(output_frame, L_FRAME48K) == 0 {
        &OVERLAP_COEFS_48KHZ_FX
    } else {
        &OVERLAP_COEFS_FX
    };
    for i in 0..(NSV_OVERLAP * WIDTH_BAND) as usize {
        t_audio32[START + i] = mult_32_16(t_audio32[START + i], overlap[i]);
    }

    // Apply global gain
    if sub(frame.nbits_total, NBITS_THRESH_BWE_HR) <= 0 {
        header.gain_fx = mult_r(27853, header.gain_fx); // 0.85
    }

    let temp = sub(15, header.exp1); // From Exponent of 'gain_fx' in Q'exp1' to Q15
    let temp2 = add(WIDTH_NONTRANS_FREQ_COEF * N_BANDS_BWE_HR, width_noncoded);
    for i in 0..temp2 as usize {
        let l_temp = mult_32_16(t_audio32[START + i], header.gain_fx);
        t_audio32[START + i] = l_shl(l_temp, temp);
    }

    // Save transform coefficients for the next frame (needed in case of frame erasures)
    let pos = if output_frame == L_FRAME32K {
        L_FRAME32K - NUM_NONTRANS_START_FREQ_COEF
    } else {
        // output_frame == L_FRAME48k
        FULL_FB_COEFS - NUM_NONTRANS_START_FREQ_COEF
    };
    let temp4 = find_max_norm32(&t_audio32[START..], pos);
    copy_scale_sig32_16(&t_audio32[START..], &mut st.t_audio_prev, pos, temp4);
    st.t_audio_prev_fx_exp[0] = add(Q_32_BITS, temp4);

    // attenuate HFs in case of band-width switching
    if st.bws_cnt1 > 0 {
        let temp = i_mult(st.bws_cnt1, 1638); // Q15

        // `t_audio` is not read again, so this has no effect on the output; it mirrors the
        // reference.
        for slot in &mut t_audio[START..START + pos as usize] {
            *slot = mult_r(*slot, temp);
        }
    }
}

/// Equalise the 14.4-16(20) kHz band to the envelope: a ramp from the last band's level down to
/// `en_noncoded` over 8 bins and flat after it, or (when the envelope varies too much) the two
/// ramped segments of the reference.
fn nontransient_equalize(
    header: &Header,
    output_frame: i16,
    width_noncoded: i16,
    extl: i16,
    t_audio32: &mut [i32],
) {
    let en_band = &header.en_band;
    let en_noncoded = header.en_noncoded;

    // equalize 14.4-16(20) kHz spectrum
    // tmpF = max_env / min_env;
    let mut temp2: i16 = 0;
    let temp = basop_util_divide1616_scale(header.max_env, header.min_env, &mut temp2);
    if sub(extl, SWB_BWE_HIGHRATE) == 0 || sub(temp, shl(18022, sub(15 - 13, temp2))) < 0 {
        // 2.2 in Q13 == 18022
        // (en_band_flt[3] - j*(en_band_flt[3]/WIDTH_BAND - en_noncoded_flt/WIDTH_BAND))
        let mut l_temp = l_deposit_h(en_band[3]);
        let l_temp2 = l_mult(
            sub(en_band[3], en_noncoded),
            4096, /* 32768/WIDTH_BAND */
        );
        // in L_temp/L_temp2, value in Q16+9
        for j in 0..BAND {
            t_audio32[END + j] = l_shl(mult_32_16(t_audio32[END + j], round_word(l_temp)), 15 - 9);
            l_temp = l_sub(l_temp, l_temp2);
        }

        for j in BAND..width_noncoded as usize {
            let l_temp = mult_32_16(t_audio32[END + j], en_noncoded);
            t_audio32[END + j] = l_shl(l_temp, 6); // Because 'en_noncoded' is in Q9
        }
    } else {
        let mut tmp_s = L_FRAME32K - NUM_NONTRANS_END_FREQ_COEF;
        if sub(output_frame, L_FRAME48K) == 0 {
            tmp_s = sub(width_noncoded, 2 * WIDTH_NONTRANS_FREQ_COEF);
        }

        let mut l_temp = l_mult(18022, en_noncoded); // 2.2 in Q13, Q13 * Q9 -> Q23
        let mut l_temp2 = mult_32_16(l_temp, 204 /* 32768/160 */); // step
        let mut j: usize = 0;
        while j < tmp_s as usize {
            // t_audio[NUM_NONTRANS_END_FREQ_COEF + j] *= 2.2f * en_noncoded * (1-(float)k/(float)160);
            t_audio32[END + j] = l_shl(mult_32_16(t_audio32[END + j], round_word(l_temp)), 31 - 23);
            l_temp = l_sub(l_temp, l_temp2);
            j += 1;
        }

        l_temp = l_mult(21299, en_noncoded); // 0.65 in Q15, Q15 * Q9 -> Q25
        l_temp2 = mult_32_16(l_temp, 102 /* 32768/320 */); // step
        while j < width_noncoded as usize {
            // t_audio[NUM_NONTRANS_END_FREQ_COEF + j] *= 0.65f * en_noncoded * (1-(float)k/(float)320);
            t_audio32[END + j] = l_shl(mult_32_16(t_audio32[END + j], round_word(l_temp)), 31 - 25);
            l_temp = l_sub(l_temp, l_temp2);
            j += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epsilon_energy_starts_from_one() {
        let bins = [0_i16; 16];
        assert_eq!(energy_with_epsilon(&bins, 4, 8), 1);
        let bins = [2_i16; 16];
        assert_eq!(energy_with_epsilon(&bins, 0, 8), 1 + 8 * 2 * 2);
    }
}
