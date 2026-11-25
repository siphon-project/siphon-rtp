//! Modification of the decoded excitation of unvoiced, inactive and audio frames in AMR-WB IO
//! mode (TS 26.442 `lib_dec/gs_dec_amr_wb_fx.c`; TS 26.445 §6.2.2.5 "Improvement of unvoiced and
//! audio signals"): the excitation goes to the DCT domain, is normalised, noise filled and
//! tilted, matched band by band to the energy of the decoded excitation, and goes back.

use crate::evs::cnst::{
    ACELP_12K65, ACELP_8K85, AUDIO_CLAS, CRIT_NOIS_BAND, INACTIVE, L_FRAME, L_FRAME16K, L_SUBFR, M,
    NB_SUBFR, UNVOICED, UNVOICED_CLAS, VOICED_TRANSITION,
};
use crate::evs::com::edct::edct_16fx;
use crate::evs::com::enr_1_az::{enr_1_az, enr_1_az_flagged};
use crate::evs::com::syn_12k8::syn_12k8;
use crate::evs::com::tools::{
    copy, div_flt32_flt32, emaximum, invert16, random, scale_sig, set16, sqrt_ratio32,
};
use crate::evs::rom::{CRIT_BANDS_LOC_FX, CRIT_BINS, CRIT_BINS_CORR_FX};
use crate::itu::basic_ops::{
    abs_s, add, extract_l, l_deposit_l, l_mac, l_msu, l_mult, l_shl, l_shr, l_sub, mult_r, negate,
    norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0, msu_r};

/// `ALP_FX`: 0.70 in Q15.
const ALP_FX: i16 = 22938;
/// `MALP_FX`: `32768 - ALP_FX`.
const MALP_FX: i16 = 9830;
/// `BIN_1k2`: the 1.2 kHz bin.
const BIN_1K2: i16 = 48;
/// `NORMALIZE_SPECS_Q_OUT`.
const NORMALIZE_SPECS_Q_OUT: i16 = 6;
/// `ENER_FX_Q_GUARD`.
const ENER_FX_Q_GUARD: i16 = 1;

/// `crit_bins[index]`: the width of critical band `index`.
fn crit_bins(index: usize) -> i16 {
    CRIT_BINS.get(index).copied().unwrap_or(0)
}

/// `NoiseFill_fx`: noise fill of the unvoiced / inactive frames' spectrum: every bin of the
/// `mbands_gn` critical bands gets pseudo-random noise (0.75 of full scale at `q_out`) added.
fn noise_fill(exc_diff_q: &mut [i16], seed_tcx: &mut i16, mbands_gn: i16, q_out: i16) {
    let mut cur_bin = 0usize;
    let fact = shr(24576, sub(15, q_out)); // 0.75f

    for i_band in 0..mbands_gn.max(0) as usize {
        let end_bin = cur_bin + crit_bins(i_band).max(0) as usize;
        while cur_bin < end_bin {
            let mut l_temp = l_mult(random(seed_tcx), fact);
            l_temp = l_msu(l_temp, exc_diff_q[cur_bin], -32768);
            exc_diff_q[cur_bin] = round_word(l_temp);
            cur_bin += 1;
        }
    }
}

/// `Ener_per_band_fx`: the energy per critical band of `exc_diff` (Q16 in `y_gain4`), square
/// root of the sum of squares plus a floor of 0.01.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop)]
fn ener_per_band(exc_diff: &[i16], exc_diff_exp: i16, y_gain4: &mut [i32]) {
    let exp = shl(exc_diff_exp, 1);
    // To get 0.01f in Q of (exc_diff_exp-1)^2
    let l_epsilon = l_shr(42_949_673, sub(32 + ENER_FX_Q_GUARD * 2, exp));

    let mut at = 0usize;
    for j in 0..CRIT_NOIS_BAND as usize {
        let temp = shr(exc_diff[at], ENER_FX_Q_GUARD);
        at += 1;
        let mut l_temp = l_mac0(l_epsilon, temp, temp);
        for _ in 1..crit_bins(j) {
            let temp = shr(exc_diff[at], ENER_FX_Q_GUARD);
            at += 1;
            l_temp = l_mac0(l_temp, temp, temp);
        }
        let mut l_temp2 = l_mult0(1, 6554); // sqrt of 0.01f in Q16
        if l_temp != 0 {
            // avoid executing sqrt of 0 (because a div_s is used to invert and then call
            // inv_sqrt)
            let mut i: i16 = 0;
            l_temp2 = sqrt_ratio32(l_temp, exp, 1, 0, &mut i);
            l_temp2 = l_shr(l_temp2, sub(15 - ENER_FX_Q_GUARD, i));
        }
        y_gain4[j] = l_temp2;
    }
}

/// `Apply_gain_fx`: rescale the modified excitation `exc_diff_q` band by band so its energy
/// matches the target energy `l_ener_per_bd_iq` (the energy of the decoded excitation).
fn apply_gain(
    exc_diff_q: &mut [i16],
    l_ener_per_bd_iq: &[i32],
    l_ener_per_bd_yq: &[i32],
    q_out: i16,
) {
    // For all the bands: the energy ratio between the modified vector and the original vector
    let mut cur_bin = 0usize;
    for i_band in 0..CRIT_NOIS_BAND as usize {
        let end_bin = cur_bin + crit_bins(i_band).max(0) as usize;
        let mut y_gain_exp = norm_l(l_ener_per_bd_yq[i_band]);
        // `exp3` is used as the temporary exponent of `L_Ener_per_bd_iQ[]`
        let exp3 = norm_l(l_ener_per_bd_iq[i_band]);
        let numerator = l_shl(l_ener_per_bd_iq[i_band], exp3);
        let denominator = l_shl(l_ener_per_bd_yq[i_band], y_gain_exp);
        let exp_denominator = y_gain_exp;
        let y_gain_fx = round_word(div_flt32_flt32(
            numerator,
            exp3,
            denominator,
            exp_denominator,
            &mut y_gain_exp,
        ));
        y_gain_exp = add(sub(y_gain_exp, 31), q_out);

        // For bands below 400 Hz or for unvoiced/inactive frames only apply the energy ratio
        while cur_bin < end_bin {
            let mut l_temp = l_mult(exc_diff_q[cur_bin], y_gain_fx);
            l_temp = l_shr(l_temp, y_gain_exp);
            exc_diff_q[cur_bin] = round_word(l_temp);
            cur_bin += 1;
        }
    }
}

/// `normalize_spec_fx`: scale the spectrum so its largest-energy bin has the magnitude
/// `fac_up` (Q8, at `q_out`).
fn normalize_spec(fac_up: i16, fy_norm: &mut [i16], l_frame: i16, q_out: i16) {
    let mut l_temp: i32 = 0;
    let idx = emaximum(0, fy_norm, l_frame, &mut l_temp); // the exponent is not important
    let mut exp = sub(q_out, 8); // Q8 of Fac Up/down
    let temp = invert16(abs_s(fy_norm[idx as usize]), &mut exp);
    l_temp = l_mult(temp, fac_up);
    exp = sub(15, exp);
    l_temp = l_shl(l_temp, exp);

    for value in &mut fy_norm[..l_frame.max(0) as usize] {
        *value = round_word(crate::evs::basop::mult_32_16(l_temp, *value));
    }
}

/// The length (in bins) of the temporal contribution: the pitch of the frame sets the lowest
/// harmonic spacing, with a minimum contribution of 1.2 kHz.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop)]
fn temporal_contribution_length(core_brate: i32, pitch: &[i16]) -> i16 {
    let mut temp = pitch[0].min(pitch[1]);
    temp = temp.min(pitch[2]);
    temp = temp.min(pitch[3]);

    // etmp14 = 12800.0f/(temp/16.0f)*8.0f
    let mut exp: i16 = 6; // pitch in Q6
    temp = invert16(temp, &mut exp);
    let mut l_temp = l_mult(temp, 12800);
    l_temp = l_shl(l_temp, sub(3, exp)); // *8.0f

    if l_sub(core_brate, i32::from(ACELP_12K65)) >= 0 {
        l_temp = l_shl(l_temp, 1);
    }

    // (Word16)(etmp14+0.5f)
    let mut m_diff_len = round_word(l_temp);

    let mut temp: i16 = 32767;
    l_temp = l_deposit_l(0);
    for i in 0..CRIT_NOIS_BAND as usize {
        let temp2 = abs_s(sub(CRIT_BANDS_LOC_FX[i], m_diff_len));
        if sub(temp, temp2) > 0 {
            l_temp = l_msu(l_temp, crit_bins(i), -32768);
        }
        temp = temp.min(temp2);
    }

    m_diff_len = round_word(l_temp).max(BIN_1K2);
    m_diff_len
}

/// `gs_dec_amr_wb_fx`: modify the DCT `dct_in` of the decoded excitation by its content type:
/// keep the low-frequency part (the temporal contribution), normalise, noise fill, amplify the
/// high frequencies by the tilt, and match each critical band's energy to `dct_in`'s.
/// `q_dct_in` is the exponent of `dct_in`; the result in `dct_out` has the same exponent.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop)]
fn gs_dec_amr_wb(
    core_brate: i32,
    seed_tcx: &mut i16,
    dct_in: &[i16],
    q_dct_in: i16,
    dct_out: &mut [i16],
    q_dct_out: i16,
    pitch: &[i16],
    voice_fac: i16,
    clas: i16,
    coder_type: i16,
) {
    let mut exc_diff_q = [0i16; L_FRAME16K as usize];
    let mut ener_per_bd_iq = [0i32; CRIT_NOIS_BAND as usize];
    let mut ener_per_bd_yq = [0i32; CRIT_NOIS_BAND as usize];

    // compute the energy per band of the decoded excitation (in the frequency domain)
    ener_per_band(dct_in, q_dct_in, &mut ener_per_bd_iq);

    // adjust the quantization noise for the low level to compensate for the poor 6 bit gainQ
    if l_sub(core_brate, i32::from(ACELP_12K65)) < 0 {
        let mut temp: i16 = 0;
        for &energy in &ener_per_bd_iq {
            temp = round_word(energy).max(temp);
        }

        if (sub(coder_type, INACTIVE) == 0 || sub(clas, VOICED_TRANSITION) == 0)
            && sub(temp, 20) < 0
        {
            for (energy, &correction) in ener_per_bd_iq.iter_mut().zip(CRIT_BINS_CORR_FX.iter()) {
                *energy = crate::evs::basop::mult_32_16(*energy, correction);
            }
        }
    }

    // the length of the temporal contribution, with a minimum contribution of 1.2 kHz
    let m_diff_len = temporal_contribution_length(core_brate, pitch);

    copy(dct_in, &mut exc_diff_q, m_diff_len);
    set16(
        &mut exc_diff_q[m_diff_len as usize..],
        0,
        sub(L_FRAME, m_diff_len),
    );

    // normalization of the spectrum and noise fill
    normalize_spec(4 * 256, &mut exc_diff_q, m_diff_len, NORMALIZE_SPECS_Q_OUT); // Factors in Q8
    noise_fill(
        &mut exc_diff_q,
        seed_tcx,
        CRIT_NOIS_BAND,
        NORMALIZE_SPECS_Q_OUT,
    );

    // recompute the energy per band of the modified excitation vector (in the frequency domain)
    ener_per_band(&exc_diff_q, NORMALIZE_SPECS_Q_OUT, &mut ener_per_bd_yq);

    // compute the tilt factor and amplify the HF accordingly
    let temp = mult_r(sub(32767, voice_fac), 16384); // Q15
    for i in 240..L_FRAME as usize {
        // -15 in Q9; -0.067 in Q18 and i in Q6 = Q9
        let mut temp2 = msu_r(-7680 * 65536, -17564, shl(i as i16, 6));
        temp2 = mult_r(temp2, temp); // Q15*Q9+1-16 -> Q9
        let l_temp = l_mult(exc_diff_q[i], temp2.max(512)); // Q(Qexc_diffQ+10)
        exc_diff_q[i] = round_word(l_shl(l_temp, 16 - 10)); // Qexc_diffQ
    }

    // match the energy of the modified excitation vector to the decoded excitation
    apply_gain(
        &mut exc_diff_q,
        &ener_per_bd_iq,
        &ener_per_bd_yq,
        sub(NORMALIZE_SPECS_Q_OUT, q_dct_out),
    );

    // copy to the output vector
    copy(&exc_diff_q, dct_out, L_FRAME);
}

/// `improv_amr_wb_gs_fx`: modify the decoded excitation to increase the quality of unvoiced and
/// audio signals: for all inactive frames, and for unvoiced frames below 8.85 kbit/s, at most
/// 12.65 kbit/s and without an attack. After an unvoiced frame the LP filters of an inactive
/// frame are first smoothed with the previous ones (the excitation is then left as decoded if
/// the smoothed filter is unstable). The synthesis is redone with the modified excitation.
///
/// `old_aq` and `aq` hold `NB_SUBFR` filters of `M + 1` coefficients; `exc2` (Q`q_exc2`) is
/// modified in place, `syn` receives the new synthesis (Q`q_syn`) from `mem_tmp`.
pub fn improv_amr_wb_gs(
    clas: i16,
    coder_type: i16,
    core_brate: i32,
    seed_tcx: &mut i16,
    old_aq: &mut [i16],
    mem_syn2: &mut [i16],
    lt_voice_fac: i16,
    locattack: i16,
    aq: &mut [i16],
    exc2: &mut [i16],
    q_exc2: i16,
    mem_tmp: &[i16],
    syn: &mut [i16],
    q_syn: i16,
    pitch_buf: &[i16],
    last_ener: i16,
    rate_switching_reset: i16,
    last_coder_type: i16,
) {
    let mut dct_exc_in = [0i16; L_FRAME as usize];
    let mut dct_exc_out = [0i16; L_FRAME as usize];
    let stride = M as usize + 1;

    // Condition to enter the section on excitation modification: all inactive frames and also
    // the unvoiced frames if the bit rate is below 8k85
    if !(locattack == 0
        && l_sub(core_brate, i32::from(ACELP_12K65)) <= 0
        && ((l_sub(core_brate, i32::from(ACELP_8K85)) < 0
            && sub(clas, AUDIO_CLAS) != 0
            && (sub(clas, UNVOICED_CLAS) == 0 || sub(clas, VOICED_TRANSITION) == 0))
            || sub(coder_type, INACTIVE) == 0))
    {
        return;
    }

    // two different paths: unvoiced or inactive, and generic audio sound
    // LP filter smoothing for inactive parts
    *seed_tcx = extract_l(l_mult0(pitch_buf[0], pitch_buf[3]));
    // last_coder_type == UNVOICED should be understood as INACTIVE, but it is forced to UNVOICED
    // in update_dec
    if sub(coder_type, INACTIVE) == 0
        && sub(last_ener, -3 * 256) > 0
        && sub(last_coder_type, UNVOICED) == 0
        && rate_switching_reset == 0
    {
        let mut aq_orig = [0i16; NB_SUBFR as usize * (M as usize + 1)];
        for i in 0..NB_SUBFR as usize {
            aq_orig.copy_from_slice(&aq[..NB_SUBFR as usize * stride]);

            let exp_a = norm_s(aq[i * stride]);
            let exp_b = norm_s(old_aq[i * stride]);
            let exp_diff = sub(exp_a, exp_b);
            if exp_diff > 0 {
                scale_sig(&mut old_aq[i * stride..], M + 1, negate(exp_diff));
            } else {
                scale_sig(&mut aq[i * stride..], M + 1, exp_diff);
            }
            for j in i * stride..(i + 1) * stride {
                aq[j] = round_word(l_mac(l_mult(ALP_FX, old_aq[j]), MALP_FX, aq[j]));
            }
        }

        // check the smoothed LP filter stability
        let mut enr_lp_old = enr_1_az(old_aq, L_SUBFR);
        // `Overflow = 0`: from here on the flag is the one of the energy of each new filter
        for i in 0..NB_SUBFR as usize {
            let (enr_lp_new, overflow) = enr_1_az_flagged(&aq[i * stride..], L_SUBFR);

            if shr(enr_lp_new, 7) > enr_lp_old || overflow {
                // the filter is unstable, do not modify the excitation
                aq[..NB_SUBFR as usize * stride].copy_from_slice(&aq_orig);
                return;
            }

            enr_lp_old = enr_lp_new;
        }
    }

    // Find the frequency representation of the excitation; do the excitation modification
    // according to the content; go back to the time domain, overwriting the excitation
    edct_16fx(exc2, &mut dct_exc_in, L_FRAME, 6);
    gs_dec_amr_wb(
        core_brate,
        seed_tcx,
        &dct_exc_in,
        q_exc2,
        &mut dct_exc_out,
        q_exc2,
        pitch_buf,
        lt_voice_fac,
        clas,
        coder_type,
    );

    edct_16fx(&dct_exc_out, exc2, L_FRAME, 6);

    // Redo the core synthesis at 12k8 Hz with the modified excitation
    copy(mem_tmp, mem_syn2, M);
    syn_12k8(L_FRAME, aq, exc2, syn, mem_syn2, 1, q_exc2, q_syn);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_energy_floor_of_a_silent_band_is_the_square_root_of_a_hundredth() {
        let spectrum = [0i16; L_FRAME as usize];
        let mut energies = [0i32; CRIT_NOIS_BAND as usize];
        ener_per_band(&spectrum, 6, &mut energies);
        // 0.01 under the root, 6554 = 0.1 in Q16 (1 times that in the reference's Q)
        assert!(energies.iter().all(|&energy| energy == energies[0]));
        assert!(energies[0] > 0);
    }

    #[test]
    fn the_noise_fill_moves_every_bin_of_every_band() {
        let mut spectrum = [0i16; L_FRAME as usize];
        let mut seed: i16 = 21845;
        noise_fill(&mut spectrum, &mut seed, CRIT_NOIS_BAND, 6);
        assert!(spectrum.iter().filter(|&&bin| bin != 0).count() > L_FRAME as usize / 2);
        assert_ne!(seed, 21845);
    }

    #[test]
    fn a_frame_that_is_not_modified_leaves_the_excitation_alone() {
        let mut seed: i16 = 1;
        let mut old_aq = [0i16; NB_SUBFR as usize * (M as usize + 1)];
        let mut aq = old_aq;
        let mut mem_syn2 = [0i16; M as usize];
        let mut exc2 = [123i16; L_FRAME as usize];
        let mem_tmp = [0i16; M as usize];
        let mut syn = [0i16; L_FRAME as usize];
        // an attack disables the modification
        improv_amr_wb_gs(
            UNVOICED_CLAS,
            INACTIVE,
            i32::from(ACELP_8K85),
            &mut seed,
            &mut old_aq,
            &mut mem_syn2,
            0,
            1,
            &mut aq,
            &mut exc2,
            0,
            &mem_tmp,
            &mut syn,
            0,
            &[64; 4],
            0,
            0,
            UNVOICED,
        );
        assert!(exc2.iter().all(|&sample| sample == 123));
        assert_eq!(seed, 1);
    }
}
