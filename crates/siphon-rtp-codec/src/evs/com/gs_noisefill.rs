//! Noise filling and high-band reconstruction of the GSC (audio / inactive) excitation spectrum
//! (TS 26.442 `lib_com/gs_noisefill_fx.c`; TS 26.445 §6.1.1.3.5).

use crate::evs::basop::{l_extract_lc, mult_32_16};
use crate::evs::cnst::{
    ACELP_13K20, ACELP_22K60, ACELP_24K40, ACELP_8K00, ACELP_9K60, AUDIO, INACTIVE, L_FRAME, M,
    MBANDS_GN, NB, NOISE_LEVEL_SP0, NOISE_LEVEL_SP3, UNVOICED,
};
use crate::evs::com::gs_gains::{comp_and_apply_gain, ener_per_band_comp};
use crate::evs::com::math_op::{isqrt_lc, pow2};
use crate::evs::com::tools::{copy, copy_scale_sig, random, set16};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_l, l_abs, l_add, l_deposit_l, l_mac, l_mult, l_shl, l_shr, l_sub,
    mult, mult_r, negate, norm_l, norm_s, round_word, shl, shr, shr_r, sub,
};
use crate::itu::stl2009::{i_mult, l_mac0, l_mult0, msu_r};

const FRAME: usize = L_FRAME as usize;

/// `gs_noisf_fx`: fill the sub-bands of `NB_Qbins / 2` bins (2 on inactive frames) of the band at
/// `start_bin` whose quantized pulses carry less energy than `1 << 2·q_noise_fac` with uniform
/// noise of level `noise_fac` (Q15), in `exc_diff_q` (Q`q_noise_fac`).
///
/// The reference's `y_norm` and `exc_diffQ` are the same buffer at its only call site
/// (`Apply_NoiseFill_fx`), so the copy from one to the other is the identity and this works on one
/// buffer in place. The seed advances by one draw per bin whether or not noise is added.
pub fn gs_noisf(
    start_bin: i16,
    nb_qbins: i16,
    noise_fac: i16,
    exc_diff_q: &mut [i16],
    seed_tcx: &mut i16,
    coder_type: i16,
    q_noise_fac: i16,
) {
    let mut nb_zer = shr(nb_qbins, 1);

    let const_1 = l_shl(1, add(q_noise_fac, q_noise_fac));
    if sub(coder_type, INACTIVE) == 0 {
        nb_zer = 2;
    }
    // The bands are 8, 16 or 32 bins wide; an empty sub-band would never advance (the reference
    // would loop forever), so it ends the fill.
    if nb_zer <= 0 {
        return;
    }

    // noise fill-in on unquantized subvector, injected only from 1066Hz to 6400Hz.
    let end = i32::from(nb_qbins) + i32::from(start_bin);
    let mut k = i32::from(start_bin);
    while k < end {
        let range = k as usize..(k + i32::from(nb_zer)) as usize;
        let mut ftmp = l_deposit_l(0);
        for &value in &exc_diff_q[range.clone()] {
            ftmp = l_mac0(ftmp, value, value);
        }

        if l_sub(l_shl(ftmp, 1), const_1) < 0 {
            for value in &mut exc_diff_q[range] {
                // exc_diffQ[i] += Noise_fac*((float)own_random(seed_tcx)/32768.0f);
                let mut tmp = mult(noise_fac, random(seed_tcx)); // Q15
                tmp = shr(tmp, sub(15, q_noise_fac)); // qNoise_fac
                *value = add(*value, tmp);
            }
        } else {
            // This is added only to keep the seed in sync between different compilers
            for _ in range {
                random(seed_tcx);
            }
        }
        k += i32::from(nb_zer);
    }
}

/// `EstimateNoiseLevel_inner_fx`: the noise level per band (Q15) from `i_band` up to `mbands_gn`
/// by bit rate, capped at 0.2 below band 5.
pub fn estimate_noise_level_inner(noisepb: &mut [i16], bitrate: i32, i_band: i16, mbands_gn: i16) {
    let noise_offset: i16 = if bitrate > i32::from(ACELP_24K40) {
        6554 // .2f * 32768
    } else if bitrate >= i32::from(ACELP_22K60) {
        9830 // .3f * 32768
    } else if bitrate >= i32::from(ACELP_9K60) {
        11469 // 0.35f * 32768
    } else {
        13107 // .4f * 32768
    };

    let start = i_band.max(0) as usize;
    set16(&mut noisepb[start..], noise_offset, sub(mbands_gn, i_band));

    for value in noisepb.iter_mut().take(5).skip(start) {
        *value = (*value).min(6554);
    }
}

/// `EstimateNoiseLevel_fx`: the noise level per band (Q15), raised or lowered by the coder type,
/// the pulse dynamics `noise_lev` and the cut-off band.
pub fn estimate_noise_level(
    noisepb: &mut [i16],
    bitrate: i32,
    diff_len: i16,
    mbands_gn: i16,
    coder_type: i16,
    noise_lev: i16,
    pit_band_idx: i16,
    last_bin: i16,
    bwidth: i16,
) {
    let mut i_band: i16 = 0;

    if sub(diff_len, L_FRAME) < 0 {
        estimate_noise_level_inner(noisepb, bitrate, i_band, MBANDS_GN);
        if coder_type != INACTIVE {
            if (l_sub(bitrate, i32::from(ACELP_8K00)) == 0 && sub(last_bin, 8) > 0)
                && sub(bwidth, NB) != 0
            {
                while mbands_gn > i_band {
                    let band = i_band as usize;
                    noisepb[band] = add(noisepb[band], noisepb[band]);
                    i_band += 1;
                }
            } else {
                while pit_band_idx > i_band {
                    let band = i_band as usize;
                    noisepb[band] = mult_r(noisepb[band], 16384); // 1/2=0.5 in Q15
                    i_band += 1;
                }
            }
        }
    }
    if sub(coder_type, INACTIVE) == 0 || sub(noise_lev, NOISE_LEVEL_SP3) >= 0 {
        for value in noisepb.iter_mut().take(mbands_gn.max(9) as usize).skip(9) {
            // noisepb[i_band]*1.15=noisepb[i_band] *(1 + 0.15)
            *value = add(*value, mult_r(*value, 4915));
        }
    }
}

/// `Apply_NoiseFill_fx`: run the noise fill over the first `mbands_gn` bands (widths from
/// `freq_nsbin_per_band`) when the cut-off lies below the frame end.
pub fn apply_noise_fill(
    exc_diff_q: &mut [i16],
    seed_tcx: &mut i16,
    noisepb: &[i16],
    diff_len: i16,
    mbands_gn: i16,
    coder_type: i16,
    freq_nsbin_per_band: &[i16],
    qexc_diff_q: i16,
) {
    let mut start_bin: i16 = 0;
    let mut nb_qbins: i16 = 0;

    for i_band in 0..mbands_gn.max(0) as usize {
        start_bin = start_bin.wrapping_add(nb_qbins);
        nb_qbins = freq_nsbin_per_band[i_band];

        if sub(diff_len, L_FRAME) < 0 {
            gs_noisf(
                start_bin,
                nb_qbins,
                noisepb[i_band],
                exc_diff_q,
                seed_tcx,
                coder_type,
                qexc_diff_q,
            );
        }
    }
}

/// `freq_dnw_scaling_fx`: attenuate the upper part of the quantized spectrum `fy_norm` (Q`qx`) by
/// the pulse dynamics, then clip the bins above 160 at low rates.
pub fn freq_dnw_scaling(
    cor_strong_limit: i16,
    coder_type: i16,
    noise_lev: i16,
    core_brate: i32,
    fy_norm: &mut [i16],
    qx: i16,
) {
    let mut sc_dyn: i16 = 32767; // Q15
    let mut start_sc: i16;
    if l_sub(core_brate, i32::from(ACELP_8K00)) <= 0 && sub(coder_type, INACTIVE) == 0 {
        sc_dyn = mult_r(sc_dyn, 4915); // Q15 (0.15 in Q15)
        start_sc = 64;
    } else if sub(coder_type, INACTIVE) == 0 {
        sc_dyn = mult_r(sc_dyn, 8192); // Q15 (0.25 in Q15)
        start_sc = 80;
    } else {
        // sc_dyn = (float)(NOISE_LEVEL_SP3 - noise_lev)/10.0f + 0.4f;
        sc_dyn = extract_l(l_mac(13107, sub(NOISE_LEVEL_SP3, noise_lev), 1638)); // Q0*Q14x2+Q15 =Q15
        start_sc = add(112, shl(sub(NOISE_LEVEL_SP3, noise_lev), 4));
        if sub(noise_lev, NOISE_LEVEL_SP0) == 0 {
            start_sc = L_FRAME;
        }
    }

    // A start below 0 (only for a pulse dynamics above NOISE_LEVEL_SP3 + 7, which the decoder
    // never produces) would index before the spectrum; it starts at bin 0 instead.
    for value in &mut fy_norm[start_sc.max(0) as usize..FRAME] {
        *value = mult_r(*value, sc_dyn); // Qx
    }

    if (l_sub(core_brate, i32::from(ACELP_13K20)) < 0 && cor_strong_limit == 0)
        || l_sub(core_brate, i32::from(ACELP_9K60)) < 0
    {
        for value in &mut fy_norm[160..FRAME] {
            *value = (*value).min(shl(1, qx));
            *value = (*value).max(shl(-1, qx));
        }
    } else if l_sub(core_brate, i32::from(ACELP_22K60)) < 0 {
        for value in &mut fy_norm[160..FRAME] {
            *value = (*value).min(shr_r(1536, sub(10, qx)));
            *value = (*value).max(shr_r(-1536, sub(10, qx)));
        }
    }
}

/// `Decreas_freqPeak_fx`: above the first LSF past 4 kHz, damp the high-band bins of
/// `exc_diff_q` around LSF pairs that close in faster than `rat` (Q15), then halve the strongest
/// bin (three times, as the reference's loop does) if it stands out.
pub fn decreas_freq_peak(lsf_new: &[i16], exc_diff_q: &mut [i16], rat: i16) {
    let order = M as usize;
    let mut lsf_new_diff = [0i16; M as usize];
    let mut pos: usize = 0;

    lsf_new_diff[0] = 0; // prevent unitialized value
    for j in 1..order - 1 {
        lsf_new_diff[j] = sub(lsf_new[j], lsf_new[j - 1]); // Qx2.56
    }

    let mut l_avrg: i32 = 0;
    let mut max: i16 = 1;
    for (i, &value) in exc_diff_q.iter().enumerate().take(FRAME).skip(160) {
        if sub(abs_s(value), max) > 0 {
            max = abs_s(value);
            pos = i;
        }
        l_avrg = l_add(l_avrg, i32::from(abs_s(value)));
    }
    // avrg /= 96;
    l_avrg = mult_32_16(l_avrg, 21845); // Q_exc+21 -15 ->Q_exc + 6
    let avrg = round_word(l_shl(l_avrg, 10)); // Q_exc

    // When the search is false, should equate the end of the vector, not the beginning
    let mut last_bin = order - 1;
    for (i, &lsf) in lsf_new.iter().enumerate().take(order - 1) {
        if sub(lsf, 10240) > 0 {
            last_bin = i;
            break;
        }
    }

    // The reference reads lsf_new_diff[i - 1]; at i == 0 (the first LSF already above 4 kHz,
    // which the decoder's LSF ordering never produces) that is before the array and the source
    // band before the spectrum, so that iteration is skipped.
    for i in last_bin.max(1)..14 {
        let tmp = mult_r(rat, lsf_new_diff[i - 1]); // Qx2.56
        if sub(tmp, lsf_new_diff[i]) > 0 {
            let start = (i - 1) * 16;
            for src in &mut exc_diff_q[start..start + 32] {
                let tmp = mult_r(16384, abs_s(*src));
                if sub(tmp, avrg) > 0 {
                    let tmp = abs_s(*src);
                    let exp = norm_s(max);
                    let tmp1 = div_s(shl(1, sub(14, exp)), max); // Q(29 - exp - Q_exc)
                    let l_tmp = l_mult(tmp, tmp1); // Q(30 - exp)
                    let tmp = round_word(l_shl(l_tmp, exp)); // Q14
                    let tmp = sub(32767, tmp); // Q14
                    let l_tmp = l_mult(avrg, tmp); // Q_exc +15

                    let tmp = round_word(l_shl(l_tmp, 1));
                    let tmp1 = negate(tmp);

                    let tmp2 = *src;
                    *src = tmp1;
                    if tmp2 > 0 {
                        *src = tmp;
                    }
                }
            }
        }
    }

    let tmp = mult_r(8192, max); // Q_exc
    if sub(abs_s(exc_diff_q[pos]), max) == 0 && sub(tmp, avrg) > 0 {
        // The reference's loop runs over i = pos-1..pos+1 but halves exc_diffQ[pos] each time.
        for _ in 0..3 {
            exc_diff_q[pos] = mult_r(16384, exc_diff_q[pos]);
        }
    }
}

/// `10^(x)·0.4` of a Q12 log energy, as `envelop_modify_fx` computes it: the Q0 band level.
fn envelop_modify_band_level(ener_per_bd_i_q: i16) -> i16 {
    // Ener1 = (float)(0.4f*pow(10, Ener_per_bd_iQ[i])); 3.321928 in Q13 -> Q16
    let l_tmp = l_shr(l_mult0(ener_per_bd_i_q, 27213), 9);

    let (exp, frac) = l_extract_lc(l_tmp); // Extract exponent of L_tmp
                                           // Put 14 as exponent so that output of Pow2() will be 16384 < Pow2() <= 32767
    let tmp = extract_l(pow2(14, frac));
    let exp = sub(exp, 14);
    mult_r(13107, shl(tmp, exp)) // Q0
}

/// `envelop_modify_fx`: rebuild the bins from `last_bin·16` up of `exc_diff_q_fx` (Q`q_exc`) as
/// half the normalised spectrum and half noise, shaped by the quantized band energies
/// `ener_per_bd_i_q` (Q12); the result is in Q`q_hb_exc`.
///
/// The decoder calls this with `last_bin` from 10 to 15. Above 11 the reference reads past the
/// 16 band energies and writes past its 320-entry scratch (stack memory, undefined); here the
/// scratch is sized for the widest case and a band energy past the table reads as 0.
pub fn envelop_modify(
    exc_diff_q_fx: &mut [i16],
    seed_tcx: &mut i16,
    last_bin: i16,
    ener_per_bd_i_q: &[i16],
    q_exc: i16,
    q_hb_exc: &mut i16,
) {
    // 16·(last_bin + 4) + 32 entries for last_bin up to 15
    const SCRATCH: usize = 16 * (15 + 4) + 32;
    let mut l_exc_diff_q_fx = [0i32; SCRATCH];
    let band_energy = |band: i16| {
        usize::try_from(band)
            .ok()
            .and_then(|band| ener_per_bd_i_q.get(band))
            .copied()
            .unwrap_or(0)
    };
    let sample = |exc: &[i16], at: usize| exc.get(at).copied().unwrap_or(0);

    let start_band = i_mult(last_bin, 16).clamp(0, L_FRAME);
    let end_band = L_FRAME;
    let mut ener_fx: i32 = 0;
    for &value in &exc_diff_q_fx[start_band as usize..end_band as usize] {
        let l_tmp = l_mult0(value, value); // 2*Q_exc
        ener_fx = l_add(ener_fx, l_shr(l_tmp, 7)); // 2*Q_exc-7
    }

    let tmp = sub(end_band, start_band);
    let tmp = div_s(1, tmp); // Q15
    ener_fx = mult_32_16(ener_fx, tmp); // Q(2*Q_exc-7+15)->Q(2*Q_exc-7)

    let mut exp1 = norm_l(ener_fx);
    ener_fx = l_shl(ener_fx, exp1);
    exp1 = 31 - exp1 - sub(shl(q_exc, 1), 7);
    ener_fx = isqrt_lc(ener_fx, &mut exp1); // Q(31-exp1)

    let weight_fx: i16 = 16384; // Q15
    let mut src_fx = start_band as usize; // Q_exc
    let mut i = last_bin;
    while i < last_bin + 4 {
        let ener1_fx = envelop_modify_band_level(band_energy(i + 1));
        for j in 0..16 {
            // *src = Ener1*(weight*(*src)*Ener + (1.0f-weight)*own_random(seed_tcx)/32768.0f);
            let l_tmp = mult_32_16(ener_fx, sample(exc_diff_q_fx, src_fx)); // Q(16-exp+Q_exc)
            let tmp = extract_l(l_shr(l_tmp, add(4, sub(q_exc, exp1)))); // Q12
            let tmp = mult_r(weight_fx, tmp); // Q12

            let l_tmp = l_mult0(sub(32767, weight_fx), random(seed_tcx)); // Q30
            let tmp1 = round_word(l_shr(l_tmp, 2));

            if let Some(slot) = l_exc_diff_q_fx.get_mut(16 * i as usize + j) {
                *slot = l_mult0(ener1_fx, add(tmp, tmp1)); // Q12
            }
            src_fx += 1;
        }
        i += 1;
    }

    let ener1_fx = envelop_modify_band_level(band_energy(15));

    src_fx = 224;
    for j in 0..32 {
        // *src = Ener1*(weight*(*src)*Ener + (1.0f-weight)*own_random(seed_tcx)/32768.0f);
        let l_tmp = mult_32_16(ener_fx, sample(exc_diff_q_fx, src_fx)); // Q(16-exp+Q_exc)
        let tmp = extract_l(l_shr(l_tmp, add(4, sub(q_exc, exp1)))); // Q12
        let tmp = mult_r(weight_fx, tmp); // Q12

        let l_tmp = l_mult0(sub(32767, weight_fx), random(seed_tcx)); // Q30
        let tmp1 = round_word(l_shr(l_tmp, 2)); // Q12

        if let Some(slot) = l_exc_diff_q_fx.get_mut(16 * i as usize + j) {
            *slot = l_mult0(ener1_fx, add(tmp, tmp1)); // Q12
        }
        src_fx += 1;
    }

    let range = start_band as usize..FRAME;
    let mut exc_diff_q_max: i32 = 0;
    for &value in &l_exc_diff_q_fx[range.clone()] {
        if l_sub(l_abs(value), exc_diff_q_max) > 0 {
            exc_diff_q_max = l_abs(value);
        }
    }
    let exp = norm_l(exc_diff_q_max);

    if sub(exp, 16) > 0 {
        *q_hb_exc = 12;
        for i in range {
            exc_diff_q_fx[i] = extract_l(l_exc_diff_q_fx[i]);
        }
    } else {
        let q_tmp = sub(16, exp);
        *q_hb_exc = sub(12, q_tmp);
        for i in range {
            exc_diff_q_fx[i] = extract_l(l_shr(l_exc_diff_q_fx[i], q_tmp));
        }
    }
}

/// `highband_exc_dct_in_fx`: noise-fill the quantized GSC spectrum `exc_diff_q` (Q`qexc_diff_q`),
/// apply the decoded band gains `ener_per_bd_i_q` and add it to the DCT excitation `exc_dct_in`
/// (Q`q_exc`); at 8 kbit/s (not NB) also extend the high band and smooth it against the previous
/// frame. `exc_wo_nf`, when present, receives the same without the noise fill. `last_exc_dct_in`,
/// `last_ener`, `last_bitallocation_band` and `lt_ener_per_band` are the decoder's GSC memories.
pub fn highband_exc_dct_in(
    core_brate: i32,
    mfreq_bindiv: &[i16],
    mut last_bin: i16,
    diff_len: i16,
    noise_lev: i16,
    pit_band_idx: i16,
    exc_diff_q: &mut [i16],
    seed_tcx: &mut i16,
    ener_per_bd_i_q: &mut [i16],
    nb_subfr: i16,
    exc_dct_in: &mut [i16],
    last_coder_type: i16,
    bitallocation_band: &[i16],
    lsf_new: &[i16],
    last_exc_dct_in: &mut [i16],
    last_ener: &mut i16,
    last_bitallocation_band: &mut [i16],
    bitallocation_exc: &[i16],
    bfi: i16,
    coder_type: i16,
    bwidth: i16,
    mut exc_wo_nf: Option<&mut [i16]>,
    qexc_diff_q: i16,
    q_exc: i16,
    gsc_noisy_speech: i16,
    lt_ener_per_band: &mut [i16],
) {
    let mut noisepb = [0i16; MBANDS_GN as usize];
    let mut ener_per_bd_y_q = [0i16; MBANDS_GN as usize];
    let mut max_bin: i16 = 0;
    let mut bwe_flag: i16 = 0;
    let last_bin_tmp: i16;

    let mut ener: i16 = 0;
    for &band_energy in &ener_per_bd_i_q[10..MBANDS_GN as usize] {
        // ener += (float)pow(10, Ener_per_bd_iQ[j]); = pow(2, 3.321928*Ener_per_bd_iQ[j])
        let mut l_tmp = l_mult(band_energy, 27213); // 3.321928 in Q13 -> Q27
        l_tmp = l_shr(l_tmp, 10); // From Q27 to Q16

        let (exp, frac) = l_extract_lc(l_tmp); // Extract exponent of L_tmp
                                               // Put 14 as exponent so that output of Pow2() will be 16384 < Pow2() <= 32767
        let tmp = extract_l(pow2(14, frac));
        let exp = sub(exp, 14);
        let tmp1 = shl(tmp, add(exp, 0));
        ener = add(tmp1, ener); // Q0
    }

    let wideband_8k = l_sub(core_brate, i32::from(ACELP_8K00)) == 0 && sub(bwidth, NB) != 0;
    if wideband_8k {
        if sub(last_coder_type, AUDIO) != 0 {
            *last_ener = ener;
        }
        if (sub(last_bin, 8) > 0 || diff_len != 0) && sub(last_coder_type, AUDIO) == 0 {
            max_bin = 10;
            bwe_flag = 1;
        } else {
            max_bin = 15;
        }

        last_bin_tmp = last_bin;
        last_bin = last_bin.max(max_bin);
        last_bin = add(last_bin, 1);
    } else {
        last_bin = MBANDS_GN;
        last_bin_tmp = last_bin;
    }
    if bfi != 0 {
        set16(&mut noisepb, 13107, MBANDS_GN); // 0.4 in Q15
    } else {
        estimate_noise_level(
            &mut noisepb,
            core_brate,
            diff_len,
            last_bin,
            coder_type,
            noise_lev,
            pit_band_idx,
            last_bin_tmp,
            bwidth,
        );
    }

    if let Some(exc_wo_nf) = exc_wo_nf.as_deref_mut() {
        copy(exc_diff_q, exc_wo_nf, L_FRAME);
    }

    if gsc_noisy_speech != 0 && bfi == 0 {
        set16(&mut noisepb, 3277, MBANDS_GN);
    }
    apply_noise_fill(
        exc_diff_q,
        seed_tcx,
        &noisepb,
        diff_len,
        last_bin,
        coder_type,
        mfreq_bindiv,
        qexc_diff_q,
    );

    // Quantize average gain, substract Q averaged gain, VQ of remaining gain per band
    if wideband_8k {
        ener_per_band_comp(
            exc_diff_q,
            &mut ener_per_bd_y_q,
            qexc_diff_q,
            add(last_bin, 1),
            0,
        );
    } else {
        ener_per_band_comp(exc_diff_q, &mut ener_per_bd_y_q, qexc_diff_q, MBANDS_GN, 1);

        if sub(nb_subfr, 4) < 0 {
            for i in L_FRAME - 16..L_FRAME {
                // exc_diffQ[i] *= 0.067f * i - 15.0f; = -15 - (-0.067f * i)
                let tmp = msu_r(-7680 * 65536, -17564, shl(i, 6)); // -15 in Q9; -0.067 in Q18 and i in Q6= Q9
                let l_tmp = l_mult(exc_diff_q[i as usize], tmp); // Q(Qexc_diffQ+10)
                exc_diff_q[i as usize] = round_word(l_shl(l_tmp, 16 - 10)); // Qexc_diffQ
            }
        }
    }

    // Check potential energy excitation overshoot
    if bfi != 0 {
        highband_exc_dct_in_limit_overshoot(
            ener_per_bd_i_q,
            &ener_per_bd_y_q,
            lt_ener_per_band,
            last_bin,
            gsc_noisy_speech,
            coder_type,
        );
    }

    // Apply decoded gain onto the difference signal
    if gsc_noisy_speech != 0 {
        for value in &mut exc_diff_q[..FRAME] {
            *value = mult_r(*value, 29491);
        }
    }

    comp_and_apply_gain(
        exc_diff_q,
        ener_per_bd_i_q,
        &mut ener_per_bd_y_q,
        last_bin,
        0,
        qexc_diff_q,
        q_exc,
    );

    if let Some(exc_wo_nf) = exc_wo_nf {
        comp_and_apply_gain(
            exc_wo_nf,
            ener_per_bd_i_q,
            &mut ener_per_bd_y_q,
            last_bin,
            1,
            qexc_diff_q,
            q_exc,
        );
        // Vr_add(exc_dct_in, exc_wo_nf, exc_wo_nf, L_FRAME): the output is the second input
        for (out, &value) in exc_wo_nf[..FRAME].iter_mut().zip(&exc_dct_in[..FRAME]) {
            *out = add(value, *out);
        }
    }

    // add the correction layer to the LF bins, and add the quantized pulses or the noise for the
    // higher part of the spectrum (non valuable temporal content already zeroed); DC is Zeroed.
    // Vr_add(exc_dct_in, exc_diffQ, exc_dct_in, L_FRAME): the output is the first input
    for (out, &value) in exc_dct_in[..FRAME].iter_mut().zip(&exc_diff_q[..FRAME]) {
        *out = add(*out, value);
    }
    if core_brate == i32::from(ACELP_8K00) && bwidth != NB {
        if sub(bwe_flag, 1) == 0 {
            last_bin = sub(last_bin, 1);
            let tmp = i_mult(max_bin, 16);
            let tmp1 = i_mult(last_bin, 16);

            // Copy exc_dct_in[..tmp] backwards onto exc_diffQ[tmp1..L_FRAME], from the top.
            let mut src = FRAME - 1;
            let mut dst = sub(tmp, 1) as usize;
            let end = sub(tmp1, 1) as usize;
            while src > end {
                exc_diff_q[src] = exc_dct_in[dst];
                src -= 1;
                dst = dst.wrapping_sub(1);
            }
            if (bitallocation_exc[0] != 0 || bitallocation_exc[1] != 0)
                && l_sub(core_brate, i32::from(ACELP_8K00)) == 0
            {
                exc_diff_q[160] = 0;
            }

            let mut q_hb_exc: i16 = 0;
            envelop_modify(
                exc_diff_q,
                seed_tcx,
                last_bin,
                ener_per_bd_i_q,
                q_exc,
                &mut q_hb_exc,
            );
            let from = tmp1 as usize;
            // from Q_hb_exc -> Q_exc as expected
            copy_scale_sig(
                &exc_diff_q[from..],
                &mut exc_dct_in[from..],
                sub(L_FRAME, tmp1),
                sub(q_exc, q_hb_exc),
            );
        }

        highband_exc_dct_in_smooth_8k(
            exc_dct_in,
            last_exc_dct_in,
            last_bitallocation_band,
            bitallocation_band,
            *last_ener,
            ener,
            last_coder_type,
            nb_subfr,
        );
        if sub(bwe_flag, 1) == 0 {
            decreas_freq_peak(lsf_new, exc_dct_in, 9830);
        } else {
            decreas_freq_peak(lsf_new, exc_dct_in, 16384);
        }
    }

    copy(&exc_dct_in[64..], &mut last_exc_dct_in[64..], L_FRAME - 64);
    copy(&bitallocation_band[4..], last_bitallocation_band, 6);
    *last_ener = ener;
}

/// The lost-frame branch of `highband_exc_dct_in_fx`: cap the band energies against the decaying
/// long-term energy so a concealed frame cannot overshoot.
fn highband_exc_dct_in_limit_overshoot(
    ener_per_bd_i_q: &mut [i16],
    ener_per_bd_y_q: &[i16],
    lt_ener_per_band: &mut [i16],
    last_bin: i16,
    gsc_noisy_speech: i16,
    coder_type: i16,
) {
    let last_bin = last_bin.clamp(0, MBANDS_GN) as usize;
    // Here coder_type == last_coder_type because of the bfi
    if gsc_noisy_speech == 0 && sub(coder_type, UNVOICED) > 0 {
        for i in 0..MBANDS_GN as usize {
            let ceiling = if i < last_bin {
                sub(sub(lt_ener_per_band[i], 154), ener_per_bd_y_q[i])
            } else {
                sub(lt_ener_per_band[i], 154)
            };
            ener_per_bd_i_q[i] = ener_per_bd_i_q[i].min(ceiling);
            lt_ener_per_band[i] = sub(lt_ener_per_band[i], 77);
        }
    } else {
        for i in 0..MBANDS_GN as usize {
            let ceiling = if i < last_bin {
                sub(add(lt_ener_per_band[i], 1229), ener_per_bd_y_q[i])
            } else {
                add(lt_ener_per_band[i], 1229)
            };
            ener_per_bd_i_q[i] = ener_per_bd_i_q[i].min(ceiling);
            lt_ener_per_band[i] = sub(lt_ener_per_band[i], 77);
        }
    }
}

/// The 8 kbit/s wideband tail of `highband_exc_dct_in_fx`: the last-16-bin ramp of a frame with
/// fewer than four subframes, then, when the high-band energy is stable across frames, smoothing
/// bands 10..16 against the previous frame.
fn highband_exc_dct_in_smooth_8k(
    exc_dct_in: &mut [i16],
    last_exc_dct_in: &mut [i16],
    last_bitallocation_band: &mut [i16],
    bitallocation_band: &[i16],
    last_ener: i16,
    ener: i16,
    last_coder_type: i16,
    nb_subfr: i16,
) {
    if sub(nb_subfr, 4) < 0 {
        for i in sub(L_FRAME, 16)..L_FRAME {
            // exc_dct_in[i] *= (0.067f*i-15.f);
            let tmp = mult_r(17564, shl(i, 6)); // 0.067 in Q18 and i in Q6= Q9
            let tmp = sub(tmp, 7680); // 15 in Q9 = Q9
            let l_tmp = l_mult(exc_dct_in[i as usize], tmp); // Q(Q_exc+10)
            exc_dct_in[i as usize] = round_word(l_shl(l_tmp, 6)); // Q_exc
        }
    }

    let tmp1 = mult_r(ener, 16384);
    let tmp1 = sub(last_ener, tmp1);
    let tmp = mult_r(last_ener, 16384);
    let tmp = sub(ener, tmp);
    if tmp > 0 && tmp1 > 0 {
        const LENGTH_BIN: usize = 6;
        if last_coder_type != AUDIO {
            set16(last_bitallocation_band, 0, 6);
            let at = (4 + LENGTH_BIN) * 16;
            copy(
                &exc_dct_in[at..],
                &mut last_exc_dct_in[at..],
                (LENGTH_BIN * 16) as i16,
            );
        }

        for i in 4..4 + LENGTH_BIN {
            if !(bitallocation_band[i] == 0 && last_bitallocation_band[i - 4] == 0) {
                let k = (i + LENGTH_BIN) * 16;
                for j in k..k + 16 {
                    let src = exc_dct_in[j];
                    let dst = last_exc_dct_in[j];
                    let tmp = mult_r(10923, abs_s(src));
                    let tmp1 = mult_r(10923, abs_s(dst));

                    if sub(tmp, abs_s(dst)) > 0 {
                        let tmp2 = src;
                        exc_dct_in[j] = mult_r(16384, sub(src, abs_s(dst))); // Q_exc
                        let tmp = mult_r(16384, add(tmp2, abs_s(dst))); // Q_exc
                        if tmp2 > 0 {
                            exc_dct_in[j] = tmp;
                        }
                    } else if sub(tmp1, abs_s(src)) > 0 {
                        let tmp = mult_r(src, 22938);
                        let tmp1 = mult_r(9830, abs_s(dst));
                        let tmp2 = src;
                        exc_dct_in[j] = sub(tmp, tmp1); // Q_exc
                        if tmp2 > 0 {
                            exc_dct_in[j] = add(tmp, tmp1); // Q_exc
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_noise_level_inner_caps_the_low_bands() {
        let mut noisepb = [0i16; 16];
        estimate_noise_level_inner(&mut noisepb, 8000, 0, 16);
        assert_eq!(&noisepb[..5], &[6554; 5]);
        assert_eq!(&noisepb[5..], &[13107; 11]);
    }

    #[test]
    fn freq_dnw_scaling_leaves_the_low_band_alone() {
        let mut fy = [1000i16; 256];
        freq_dnw_scaling(0, INACTIVE, 10, 8000, &mut fy, 5);
        assert!(fy[..64].iter().all(|&v| v == 1000));
        assert!(fy[64..160].iter().all(|&v| v < 1000));
        assert!(fy[160..].iter().all(|&v| v <= 32));
    }

    #[test]
    fn scratch_bound_holds_for_l_frame16k() {
        assert!(16 * (15 + 4) + 32 > crate::evs::cnst::L_FRAME16K as usize);
    }
}
