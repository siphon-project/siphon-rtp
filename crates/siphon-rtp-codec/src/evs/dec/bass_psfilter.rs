//! The low-frequency pitch enhancer ("bass post-filter") of the ACELP synthesis (TS 26.442
//! `lib_dec/bass_psfilter_fx.c`; TS 26.445 §6.1.4.2.2).
//!
//! `bass_psfilter_fx` computes, per subframe, the inter-harmonic error the long-term filter would
//! remove (`bpf_noise_buf`); `addBassPostFilterFx` subtracts it, low-passed, in the CLDFB domain.

use crate::evs::basop::{l_extract_lc, mpy_32_16_1};
use crate::evs::cnst::{CLDFB_NO_COL_MAX, L_FRAME16K, L_SUBFR, PIT16K_MAX, PIT_MAX};
use crate::evs::com::basop_util::limit_scale32;
use crate::evs::com::cldfb::{cldfb_analysis_filtering, CLDFB_ROW};
use crate::evs::com::deemph::deemph;
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::math_op::{frac_sqrt, isqrt, pow2};
use crate::evs::com::tools::{maximum, minimum, scale_sig32, set16, sum16};
use crate::evs::dec::state::{CldfbFilterBank, CldfbScaleFactor};
use crate::evs::rom::BPF_WEIGHTS_16_FX;
use crate::itu::basic_ops::{
    abs_s, add, div_s, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult, l_shl, l_shr, l_sub,
    mult, mult_r, norm_l, round_word, shl, shr, sub,
};
use crate::itu::oper_32b::l_comp;
use crate::itu::stl2009::{l_mac0, l_mult0, mac_r, msu_r};

/// `NBPSF_PIT_MAX` (`PIT16k_MAX + 1`): the synthesis history the filter keeps.
const NBPSF_PIT_MAX: usize = PIT16K_MAX as usize + 1;
/// `NBPSF_L_EXTRA` (`2 * L_FRAME16k / 4`): the length of the pitch-tracking correlation window
/// beyond its 120-sample look-back.
const NBPSF_L_EXTRA: i16 = 2 * L_FRAME16K / 4;
/// `BPF_STOP_STOPBAND_16`: CLDFB bands the post-filter reaches.
const BPF_STOP_STOPBAND_16: i16 = 16;
/// `L_TRACK_HIST`: frames of pitch-tracking / vibrato history.
const L_TRACK_HIST: usize = 10;
/// `L_FRAME_PLUS` is 2 · `L_FRAME16k` but the synthesis is at most one 16 kHz frame here.
const L_FRAME_MAX: usize = L_FRAME16K as usize;
/// The subframe length.
const SUBFR: usize = L_SUBFR as usize;

/// `bass_psfilter_init_fx`: clear the filter memories.
pub fn bass_psfilter_init(old_syn: &mut [i16], mem_deemph_err: &mut i16, lp_ener: &mut i16) {
    *mem_deemph_err = 0;
    *lp_ener = 0;
    set16(old_syn, 0, NBPSF_PIT_MAX as i16);
}

/// The memories of `bass_psfilter_fx` (all `Decoder_State_fx` fields).
#[derive(Debug)]
pub struct BassPsfilterState<'a> {
    /// `old_syn_fx[NBPSF_PIT_MAX]`: the synthesis history.
    pub old_syn: &'a mut [i16],
    /// `mem_deemph_err`: de-emphasis memory of the error.
    pub mem_deemph_err: &'a mut i16,
    /// `lp_ener`: long-term average energy of the error (log domain).
    pub lp_ener: &'a mut i16,
    /// `v_stab_smooth_fx`: smoothed stability factor.
    pub v_stab_smooth: &'a mut i16,
    /// `mem_mean_pit[L_TRACK_HIST]`: mean pitch of the last frames.
    pub mem_mean_pit: &'a mut [i16],
    /// `Track_on_hist[L_TRACK_HIST]`: pitch-tracking decisions of the last frames.
    pub track_on_hist: &'a mut [i16],
    /// `vibrato_hist[L_TRACK_HIST]`: vibrato decisions of the last frames.
    pub vibrato_hist: &'a mut [i16],
    /// `psf_att`: attenuation factor.
    pub psf_att: &'a mut i16,
}

/// `bass_psfilter_fx`: compute the bass post-filter's per-subframe correction of `synth_in`
/// (`l_frame` samples, Q`q_syn`) into `bpf_noise_buf`, from the pitch of each subframe
/// (`pitch_buf`, Q6; `None` or `bpf_off` disable the pitch path), the LSF stability `v_stab` and
/// `coder_type`. `opt_amr_wb` enables the pitch-halving tracker.
pub fn bass_psfilter(
    opt_amr_wb: i16,
    synth_in: &[i16],
    l_frame: i16,
    pitch_buf: Option<&[i16]>,
    st: &mut BassPsfilterState<'_>,
    bpf_off: i16,
    v_stab: i16,
    coder_type: i16,
    q_syn: i16,
    bpf_noise_buf: &mut [i16],
) {
    let mut v_stab = v_stab;
    let mut syn_buf = [0i16; NBPSF_PIT_MAX + L_FRAME_MAX + NBPSF_PIT_MAX];
    let mut syn2_buf = [0i16; L_FRAME_MAX];
    let mut t_sf = [0i16; 5];
    let mut t_update: usize = 0;
    let mut track_on: i16 = 0;
    // the frame is the 12.8 or 16 kHz core frame; the clamp only keeps the indexing in bounds
    let l_frame = l_frame.clamp(0, L_FRAME16K);
    let lf = l_frame as usize;
    let nb_subfr = shr(l_frame, 6);
    let q_syn2x = shl(q_syn, 1);

    syn_buf[..NBPSF_PIT_MAX].copy_from_slice(&st.old_syn[..NBPSF_PIT_MAX]);
    syn_buf[NBPSF_PIT_MAX..NBPSF_PIT_MAX + lf].copy_from_slice(&synth_in[..lf]);

    let pitch = pitch_buf.filter(|_| bpf_off == 0);
    let (vibrato, psf_att) = bass_psfilter_pitch_stats(pitch, l_frame, nb_subfr, coder_type, st);

    // extend the synthesis by one pitch period (or 80 samples without a pitch)
    let ext_at = NBPSF_PIT_MAX + lf;
    let back = match pitch {
        None => {
            t_update = 80;
            set16(&mut t_sf, 0, 5);
            t_update
        }
        Some(pitch) => {
            let mut i = 0usize;
            while i < nb_subfr.max(0) as usize {
                let tmp = add(pitch[i], 32);
                t_sf[i] = shr(tmp, 6);
                t_sf[i] = if sub(l_frame, L_FRAME16K) == 0 {
                    t_sf[i].min(NBPSF_PIT_MAX as i16)
                } else {
                    t_sf[i].min(PIT_MAX)
                };
                i += 1;
            }
            t_sf[i.saturating_sub(1)].max(0) as usize
        }
    };
    // a sample-by-sample copy: with a period below NBPSF_PIT_MAX it repeats the period
    for i in 0..NBPSF_PIT_MAX {
        syn_buf[ext_at + i] = syn_buf[ext_at + i - back];
    }

    let mut subfr_pos = 0usize;
    let mut i_subfr = 0usize;
    while i_subfr < lf {
        let syn_at = NBPSF_PIT_MAX + i_subfr;
        let syn2 = &mut syn2_buf[i_subfr..i_subfr + SUBFR];
        let mut t = t_sf[subfr_pos];
        if t != 0 {
            // pitch tracking: halve a lag whose half correlates nearly as well
            if sub(t, 34) >= 0 && opt_amr_wb != 0 {
                t = pit_track(&syn_buf, syn_at, t);
                if sub(t, t_sf[subfr_pos]) != 0 {
                    track_on = 1;
                }
            }
            let t = t as usize;
            for i in 0..SUBFR {
                syn2[i] = mac_r(
                    l_mult(syn_buf[syn_at - t + i], 16384),
                    syn_buf[syn_at + t + i],
                    16384,
                );
            }
            let mut err = [0i16; SUBFR];
            let alpha =
                bass_psfilter_alpha(&syn_buf[syn_at..], syn2, &mut err, *st.lp_ener, q_syn2x);
            let alpha = bass_psfilter_limit_alpha(alpha, psf_att, track_on, vibrato);
            // attenuate with the stability of the LSFs
            let tmp = mult(*st.v_stab_smooth, 6554);
            let tmp2 = mult(v_stab, 26214);
            *st.v_stab_smooth = add(tmp2, tmp);
            let tmp = sub(*st.v_stab_smooth, v_stab);
            let delta_v_stab = abs_s(tmp);
            v_stab = frac_sqrt(v_stab);
            let tmp = mult(2458, v_stab);
            let tmp = add(16384, tmp);
            let tmp = sub(tmp, delta_v_stab);
            let alpha = mult(tmp, alpha);
            for i in 0..SUBFR {
                let tmp = sub(syn_buf[syn_at + i], syn2[i]);
                syn2[i] = mult(alpha, shl(tmp, 1));
            }
            bass_psfilter_update_lp_ener(&mut err, st, q_syn2x);
        } else {
            for i in 0..SUBFR {
                syn2[i] = mac_r(
                    l_mult(syn_buf[syn_at + i - t_update], 16384),
                    syn_buf[syn_at + i + t_update],
                    16384,
                );
            }
            track_on = 0;
            if sub(coder_type, 5) == 0 {
                // AUDIO
                track_on = 1;
            }
            let mut err = [0i16; SUBFR];
            // the gain is computed as on the pitch path and then not used (alpha = 0)
            let _ = bass_psfilter_alpha(&syn_buf[syn_at..], syn2, &mut err, *st.lp_ener, q_syn2x);
            let tmp = mult(*st.v_stab_smooth, 6554);
            let tmp2 = mult(v_stab, 26214);
            *st.v_stab_smooth = add(tmp2, tmp);
            syn2.fill(0);
            bass_psfilter_update_lp_ener(&mut err, st, q_syn2x);
        }
        bpf_noise_buf[i_subfr..i_subfr + SUBFR].copy_from_slice(syn2);
        subfr_pos += 1;
        i_subfr += SUBFR;
    }

    // history of the pitch tracking and vibrato decisions
    for i in (1..L_TRACK_HIST).rev() {
        st.track_on_hist[i] = st.track_on_hist[i - 1];
        st.vibrato_hist[i] = st.vibrato_hist[i - 1];
    }
    st.track_on_hist[0] = track_on;
    st.vibrato_hist[0] = vibrato;
    st.old_syn[..NBPSF_PIT_MAX].copy_from_slice(&syn_buf[lf..lf + NBPSF_PIT_MAX]);
}

/// The mean-pitch history, the vibrato decision and the attenuation factor `psf_att`; returns
/// `(vibrato, psf_att)`.
fn bass_psfilter_pitch_stats(
    pitch: Option<&[i16]>,
    l_frame: i16,
    nb_subfr: i16,
    coder_type: i16,
    st: &mut BassPsfilterState<'_>,
) -> (i16, i16) {
    let mut vibrato: i16 = 0;
    if let Some(pitch) = pitch {
        for i in (1..L_TRACK_HIST).rev() {
            st.mem_mean_pit[i] = st.mem_mean_pit[i - 1];
        }
        let mut l_tmp = l_deposit_l(0);
        for &p in pitch.iter().take(nb_subfr.max(0) as usize) {
            l_tmp = l_mac(l_tmp, p, 8192);
        }
        let mut tmp = round_word(l_tmp);
        tmp = mult_r(tmp, 8192);
        if sub(nb_subfr, 5) == 0 {
            tmp = mult_r(tmp, 26214); // 4/5
        }
        st.mem_mean_pit[0] = tmp;
    }
    let mut loc_pit_min: i16 = 0;
    let mut loc_pit_max: i16 = 0;
    let idx_pit_min = minimum(st.mem_mean_pit, L_TRACK_HIST as i16, &mut loc_pit_min);
    let idx_pit_max = maximum(st.mem_mean_pit, L_TRACK_HIST as i16, &mut loc_pit_max);
    let dist_pit_diff = abs_s(sub(idx_pit_max, idx_pit_min));
    let mut diff_pit = sub(loc_pit_max, loc_pit_min);
    if sub(l_frame, L_FRAME16K) == 0 {
        diff_pit = mult_r(diff_pit, 26214); // 4/5
    }
    if coder_type != 0 // INACTIVE
        && sub(diff_pit, 2 << 4) >= 0
        && sub(diff_pit, 10 << 4) < 0
        && sub(dist_pit_diff, 3) >= 0
    {
        vibrato = 1;
    }
    let tmp = sum16(st.track_on_hist, L_TRACK_HIST as i16);
    let track_on_r = round_word(l_shl(l_mult0(tmp, 3277), 16));
    let mut vibrat_r = sum16(st.vibrato_hist, L_TRACK_HIST as i16);
    let mut alp_tmp = sub(32767, track_on_r);
    if vibrato != 0 {
        let tmp = round_word(l_shl(l_mult0(vibrat_r, vibrat_r), 16));
        let tmp = round_word(l_shl(l_mult(tmp, 18874), 9));
        vibrat_r = sub(32767, tmp);
        alp_tmp = mult_r(alp_tmp, vibrat_r);
    }
    alp_tmp = alp_tmp.max(3277);
    if sub(alp_tmp, *st.psf_att) > 0 {
        *st.psf_att = round_word(l_mac(l_mult(1638, alp_tmp), 31130, *st.psf_att));
    } else {
        *st.psf_att = round_word(l_mac(l_mult(13107, alp_tmp), 19661, *st.psf_att));
    }
    (vibrato, *st.psf_att)
}

/// The optimal gain of the long-term prediction `syn2` of `syn` (a subframe each), the error it
/// leaves (`err`), and from them the raw filter strength alpha (signed, Q14), against the
/// long-term error energy `lp_ener`.
fn bass_psfilter_alpha(
    syn: &[i16],
    syn2: &[i16],
    err: &mut [i16; SUBFR],
    lp_ener: i16,
    q_syn2x: i16,
) -> i16 {
    let mut lcorr = l_deposit_l(2);
    let mut lener = l_deposit_h(-32768);
    for j in (0..SUBFR).step_by(2) {
        let mut lcorr0 = l_mult0(syn[j], syn2[j]);
        let mut lener0 = l_mult0(syn2[j], syn2[j]);
        lcorr0 = l_mac0(lcorr0, syn[j + 1], syn2[j + 1]);
        lener0 = l_mac0(lener0, syn2[j + 1], syn2[j + 1]);
        lcorr = l_add(lcorr, l_shr(lcorr0, 4));
        lener = l_add(lener, l_shr(lener0, 4));
    }
    lcorr = l_shr(lcorr, 1);
    lener = l_shr(lener, 1);
    lener = l_add(lener, 0x4000_0001);

    let ltmp = l_abs(lcorr);
    let mut exp = norm_l(ltmp);
    let tmp = round_word(l_shl(ltmp, exp));
    let mut exp2 = norm_l(lener);
    let mut tmp2 = round_word(l_shl(lener, exp2));
    if sub(tmp, tmp2) > 0 {
        exp = sub(exp, 1);
    }
    exp2 = sub(exp, exp2);
    let mut gain = div_s(round_word(l_shl(ltmp, exp)), tmp2);
    if lcorr < 0 {
        gain = sub(0, gain);
    }
    for i in 0..SUBFR {
        err[i] = msu_r(l_shr(l_mult0(gain, syn2[i]), exp2), syn[i], 16384);
    }

    // alpha = corr / (ener + lp_ener)
    let (hi, lo) = l_extract_lc(mpy_32_16_1(2_786_635, lp_ener));
    let exp2 = lo;
    tmp2 = hi;
    let mut exp = norm_l(ltmp);
    tmp2 = sub(tmp2, 1 + 4);
    tmp2 = add(tmp2, q_syn2x);
    tmp2 = tmp2.clamp(0, 30);
    lener = l_add(lener, pow2(tmp2, exp2));
    let exp2 = norm_l(lener);
    let tmp2 = round_word(l_shl(lener, exp2));
    if sub(tmp, tmp2) > 0 {
        exp = sub(exp, 1);
    }
    let exp2 = sub(exp, exp2);
    let mut alpha = shr(div_s(round_word(l_shl(ltmp, exp)), tmp2), exp2);
    if lcorr < 0 {
        alpha = sub(0, alpha);
    }
    alpha
}

/// Limit alpha to [0, 0.5] (Q15), scale it by `psf_att`, and cap it further while the pitch
/// tracker is engaged or a vibrato is detected.
fn bass_psfilter_limit_alpha(alpha: i16, psf_att: i16, track_on: i16, vibrato: i16) -> i16 {
    let mut alpha = alpha.min(16384);
    alpha = mult_r(alpha, psf_att);
    if sub(alpha, 9830) > 0 && track_on != 0 {
        alpha = 9830;
    } else if sub(alpha, 13107) > 0 && vibrato != 0 {
        alpha = 13107;
    }
    alpha.max(0)
}

/// De-emphasise the error and fold its energy into the long-term energy `lp_ener` (log domain).
fn bass_psfilter_update_lp_ener(
    err: &mut [i16; SUBFR],
    st: &mut BassPsfilterState<'_>,
    q_syn2x: i16,
) {
    deemph(err, 29491, L_SUBFR, st.mem_deemph_err); // 0.9
    let mut lener = l_deposit_h(-32768);
    for &e in err.iter() {
        lener = l_mac0(lener, e, e);
    }
    let mut exp2: i16 = -1 - 2;
    if l_sub(lener, i32::MAX) == 0 {
        // saturated: sum again, scaled down
        lener = l_deposit_h(-32768);
        let half = SUBFR / 2;
        for i in 0..half {
            let lener0 = l_mult0(err[half + i], err[half + i]);
            lener = l_add(lener, l_shr(l_mac0(lener0, err[i], err[i]), 5));
        }
        exp2 = sub(exp2, 5);
    }
    lener = l_shr(lener, 1);
    lener = l_add(lener, 0x4000_0001);
    let tmp = norm_l(lener);
    let exp = log2_norm_lc(l_shl(lener, tmp));
    let mut tmp = sub(30, tmp);
    tmp = sub(tmp, q_syn2x);
    tmp = sub(tmp, exp2);
    lener = l_comp(tmp, exp);
    lener = mpy_32_16_1(lener, 31565); // 10·log10(2) / 4 · ... (Q15)
    lener = l_shl(lener, 3);
    *st.lp_ener = mac_r(lener, *st.lp_ener, 32440); // 0.99
}

/// `Pit_track_fx`: return half the lag `t` when the signal at `syn_buf[syn_at..]` correlates with
/// itself at `t / 2` at least as well as 0.95 (normalised), else `t`.
fn pit_track(syn_buf: &[i16], syn_at: usize, t: i16) -> i16 {
    const BLOCK: usize = ((NBPSF_L_EXTRA + 120) / 14) as usize;
    let t2 = shr(t, 1);
    let mut v1 = syn_at - 120;
    let mut v2 = syn_at - 120 - t2.max(0) as usize;
    let mut lener = l_deposit_h(-32768);
    let mut ltmp = l_deposit_h(-32768);
    let mut lcorr = l_deposit_l(2);
    for _ in 0..14 {
        let mut lener0 = l_mult0(syn_buf[v1], syn_buf[v1]);
        let mut ltmp0 = l_mult0(syn_buf[v2], syn_buf[v2]);
        let mut lcorr0 = l_mult0(syn_buf[v1], syn_buf[v2]);
        v1 += 1;
        v2 += 1;
        for _ in 1..BLOCK {
            lener0 = l_mac0(lener0, syn_buf[v1], syn_buf[v1]);
            ltmp0 = l_mac0(ltmp0, syn_buf[v2], syn_buf[v2]);
            lcorr0 = l_mac0(lcorr0, syn_buf[v1], syn_buf[v2]);
            v1 += 1;
            v2 += 1;
        }
        if l_sub(lener0, i32::MAX) == 0
            || l_sub(ltmp0, i32::MAX) == 0
            || l_sub(lcorr0, i32::MAX) == 0
            || l_sub(lcorr0, i32::MIN) == 0
        {
            // saturated: sum the block again, scaled down
            v1 -= BLOCK;
            v2 -= BLOCK;
            for _ in 0..BLOCK {
                lener = l_add(lener, l_shr(l_mult0(syn_buf[v1], syn_buf[v1]), 6));
                ltmp = l_add(ltmp, l_shr(l_mult0(syn_buf[v2], syn_buf[v2]), 6));
                lcorr = l_add(lcorr, l_shr(l_mult0(syn_buf[v1], syn_buf[v2]), 6));
                v1 += 1;
                v2 += 1;
            }
        } else {
            lener = l_add(lener, l_shr(lener0, 6));
            ltmp = l_add(ltmp, l_shr(ltmp0, 6));
            lcorr = l_add(lcorr, l_shr(lcorr0, 6));
        }
    }
    lener = l_shr(lener, 1);
    lener = l_add(lener, 0x4000_0001);
    ltmp = l_shr(ltmp, 1);
    ltmp = l_add(ltmp, 0x4000_0001);
    lcorr = l_shr(lcorr, 1);

    // corr / sqrt(ener1 · ener2)
    let mut exp1 = norm_l(lener);
    let mut exp2 = norm_l(ltmp);
    ltmp = l_mult0(
        round_word(l_shl(lener, exp1)),
        round_word(l_shl(ltmp, exp2)),
    );
    exp1 = add(exp1, exp2);
    exp2 = exp1 & 1;
    exp1 = sub(exp1, exp2);
    ltmp = l_shr(ltmp, exp2);
    ltmp = isqrt(ltmp);
    exp1 = mac_r((16 - 1) * 65536 - 0x8000, exp1, 16384);
    exp2 = norm_l(ltmp);
    ltmp = l_shl(ltmp, exp2);
    exp1 = sub(exp1, exp2);
    exp2 = norm_l(lcorr);
    lcorr = l_shl(lcorr, exp2);
    exp1 = sub(exp1, exp2);
    ltmp = mpy_32_16_1(lcorr, round_word(ltmp));
    ltmp = l_shl(ltmp, exp1);
    if l_sub(ltmp, 2_040_109_466) > 0 {
        // 0.95 in Q31
        return t2;
    }
    t
}

/// `addBassPostFilterFx`: subtract the CLDFB analysis of the bass post-filter correction
/// `harm_time_in` (exponent `time_in_e`, `n_time_slots` slots), weighted per band, from the
/// decoder's CLDFB buffers `r_analysis` / `i_analysis` (`n_time_slots_total` slots of
/// `n_bands_total` bands), rescaling them to the common exponent kept in `cldfb_scale`.
pub fn add_bass_post_filter(
    harm_time_in: &[i16],
    r_analysis: &mut [[i32; CLDFB_ROW]],
    i_analysis: &mut [[i32; CLDFB_ROW]],
    cldfb_bank_bpf: &mut CldfbFilterBank,
    time_in_e: i16,
    n_time_slots: i16,
    n_time_slots_total: i16,
    n_bands_total: i16,
    cldfb_scale: &mut CldfbScaleFactor,
) {
    let mut cldfb_buffer_real = [[0i32; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize];
    let mut cldfb_buffer_imag = [[0i32; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize];
    let mut scale = CldfbScaleFactor::zeroed();
    let n_chan = cldfb_bank_bpf.no_channels;
    let mut scale1: i16 = 0;
    let mut scale2: i16 = 0;
    let weights = &BPF_WEIGHTS_16_FX;
    let max_band = n_chan.clamp(0, BPF_STOP_STOPBAND_16) as usize;
    // the reference asserts n_chan <= 20 and n_time_slots <= CLDFB_NO_COL_MAX
    let n_time_slots = n_time_slots.min(CLDFB_NO_COL_MAX);

    cldfb_analysis_filtering(
        cldfb_bank_bpf,
        &mut cldfb_buffer_real,
        &mut cldfb_buffer_imag,
        &mut scale,
        harm_time_in,
        time_in_e,
        n_time_slots,
    );

    if n_time_slots > 0 {
        let b = cldfb_scale.lb_scale.max(scale.lb_scale);
        scale1 = limit_scale32(sub(cldfb_scale.lb_scale, b));
        scale2 = limit_scale32(sub(scale.lb_scale, b));
        cldfb_scale.lb_scale = b;
        // rescale the time slots the post-filter does not reach
        for i in n_time_slots.max(0) as usize..n_time_slots_total.max(0) as usize {
            scale_sig32(&mut r_analysis[i], n_bands_total, scale1);
            scale_sig32(&mut i_analysis[i], n_bands_total, scale1);
        }
    }

    for i in 0..n_time_slots.max(0) as usize {
        let r = &mut r_analysis[i];
        let im = &mut i_analysis[i];
        let tr = &cldfb_buffer_real[i];
        let ti = &cldfb_buffer_imag[i];
        // the first band is weighted twice
        r[0] = l_sub(
            l_shl(r[0], scale1),
            l_shl(mpy_32_16_1(tr[0], weights[0]), add(1, scale2)),
        );
        im[0] = l_sub(
            l_shl(im[0], scale1),
            l_shl(mpy_32_16_1(ti[0], weights[0]), add(1, scale2)),
        );
        for b in 1..max_band {
            r[b] = l_sub(
                l_shl(r[b], scale1),
                l_shr(mpy_32_16_1(tr[b], weights[b]), scale2),
            );
            im[b] = l_sub(
                l_shl(im[b], scale1),
                l_shr(mpy_32_16_1(ti[b], weights[b]), scale2),
            );
        }
        let rest = sub(n_bands_total, max_band as i16);
        scale_sig32(&mut r[max_band..], rest, scale1);
        scale_sig32(&mut im[max_band..], rest, scale1);
    }
}
