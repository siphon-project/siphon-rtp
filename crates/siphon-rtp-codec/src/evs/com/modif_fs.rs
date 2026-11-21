//! Sampling-rate conversion by all-pass polyphase filters (TS 26.442 `lib_com/modif_fs_fx.c`).
//! Ported so far: the polyphase resampler `modify_Fs_fx`, the 2:1 and 3:1 all-pass interpolators
//! the cubic interpolator `modify_Fs_intcub3m_sup_fx` and the post-filter memory resamplers
//! `retro_interp4_5_fx` / `retro_interp5_4_fx`.

use crate::evs::basop::div_32;
use crate::evs::cnst::{
    ALLPASSSECTIONS_STEEP, LEN_WIN_SSS, L_FILT_MAX, L_FRAME, L_FRAME16K, L_FRAME48K, M, RS_INV_FAC,
};
use crate::evs::com::basop_util::idiv1616;
use crate::evs::com::deemph::deemph;
use crate::evs::com::interpol::interpol_lc;
use crate::evs::com::lag_wind::{lag_wind, LAGW_STRONG};
use crate::evs::com::lpc_tools::{autocorr, e_lpc_lev_dur};
use crate::evs::com::math_op::i_mult2;
use crate::evs::com::preemph::preemph_copy_in_place;
use crate::evs::com::syn_filt::syn_kern_16;
use crate::evs::com::tools::copy_scale_sig;
use crate::evs::rom::{
    ResamplingCfgFx, AP1_STEEP_FX, AP2_STEEP_FX, CT2_FX, CU15_FX, CU4_FX, RESAMPLING_CFG_TBL_FX,
    WIND_SSS_FX,
};
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_abs, l_deposit_h, l_deposit_l, l_mac, l_msu, l_mult, l_negate, l_shl,
    l_sub, mult_r, norm_s, round_word, shl, shr, sub,
};
use crate::itu::oper_32b::l_comp;
use crate::itu::stl2009::{i_mult, lshr, mac_r};

/// The length of `modify_Fs_fx`'s working buffer: 2·L_FILT_MAX of memory, 1·L_FILT_MAX of future
/// prediction, and a 48 kHz frame.
const SIGNAL_TAB_LEN: usize = (3 * L_FILT_MAX + L_FRAME48K) as usize;

/// `modify_Fs_fx`: resample `sig_in[0..lg]` from `fin` to `fout` Hz into `sig_out`, with the
/// polyphase filter memory `mem` (2·filt_len samples); returns the output length. `nblp` selects
/// the NB 4 kHz low-pass configuration when going to 12.8 kHz.
pub fn modify_fs(
    sig_in: &[i16],
    lg: i16,
    fin: i32,
    sig_out: &mut [i16],
    fout: i32,
    mem: &mut [i16],
    nblp: i16,
) -> i16 {
    if fin == fout {
        // just copy the signal and quit
        let n = usize::try_from(lg).unwrap_or(0);
        sig_out[..n].copy_from_slice(&sig_in[..n]);
        return lg;
    }
    let mut signal_tab = [0i16; SIGNAL_TAB_LEN];
    let Some(setup) = modify_fs_setup(lg, fin, fout, nblp) else {
        return 0;
    };
    let n = usize::try_from(lg).unwrap_or(0);
    signal_tab[setup.signal_at + setup.mem_len..][..n].copy_from_slice(&sig_in[..n]);
    modify_fs_resample(&mut signal_tab, &setup, lg, fin, sig_out, mem)
}

/// `modify_Fs_fx` called with the same buffer as input and output, as `CNG_exc_fx` does: the
/// reference copies the input into its working buffer before it writes any output, so this is
/// exactly [`modify_fs`] on a copy of `sig`.
pub fn modify_fs_in_place(
    sig: &mut [i16],
    lg: i16,
    fin: i32,
    fout: i32,
    mem: &mut [i16],
    nblp: i16,
) -> i16 {
    if fin == fout {
        return lg;
    }
    let mut signal_tab = [0i16; SIGNAL_TAB_LEN];
    let Some(setup) = modify_fs_setup(lg, fin, fout, nblp) else {
        return 0;
    };
    let n = usize::try_from(lg).unwrap_or(0);
    signal_tab[setup.signal_at + setup.mem_len..][..n].copy_from_slice(&sig[..n]);
    modify_fs_resample(&mut signal_tab, &setup, lg, fin, sig, mem)
}

/// The resampling parameters `modify_Fs_fx` derives from its configuration.
struct ModifyFsSetup {
    cfg: &'static ResamplingCfgFx,
    flag_low_order: bool,
    lg_out: i16,
    filt_len: i16,
    plus_sample_in: i16,
    frac: i16,
    mem_len: usize,
    signal_at: usize,
}

/// `modify_Fs_fx`'s configuration lookup. `None` for a rate pair the table lacks, or when the
/// working buffer cannot hold the frame (no caller passes either; the reference would divide by
/// zero or index before its buffer).
fn modify_fs_setup(lg: i16, fin: i32, fout: i32, nblp: i16) -> Option<ModifyFsSetup> {
    // find the resampling configuration in the lookup table (it ends with an all-zero row)
    let find = |from: usize| -> usize {
        let mut k = from;
        while k + 1 < RESAMPLING_CFG_TBL_FX.len()
            && RESAMPLING_CFG_TBL_FX[k].fin_fx != 0
            && !(RESAMPLING_CFG_TBL_FX[k].fin_fx == fin && RESAMPLING_CFG_TBL_FX[k].fout_fx == fout)
        {
            k += 1;
        }
        k
    };
    let mut k = find(0);
    let mut flag_low_order = false;
    // find the configuration with the NB 4 kHz low-pass
    if nblp != 0 && fin > 8000 && fout == 12800 {
        flag_low_order = true;
        k = find((k + 1).min(RESAMPLING_CFG_TBL_FX.len() - 1));
    }
    let cfg = &RESAMPLING_CFG_TBL_FX[k];
    if cfg.fac_num_fx <= 0 || cfg.fac_den_fx <= 0 {
        // an unsupported rate pair: the reference runs into its table's terminator and divides by
        // zero; no caller asks for one
        return None;
    }
    let fac_num = cfg.fac_num_fx;
    let fac_den = cfg.fac_den_fx;
    let lg_out = if lg >= L_FRAME {
        cfg.lg_out
    } else {
        idiv1616(i_mult2(lg, fac_num), fac_den)
    };
    let filt_len = cfg.filt_len_fx;
    let (plus_sample_in, frac) = if fin == 8000 && fout == 12800 {
        (7, 4)
    } else {
        (0, 0)
    };
    let mem_len = shl(filt_len, 1);
    let signal_at = i32::from(2 * L_FILT_MAX) + i32::from(L_FRAME48K) - i32::from(add(mem_len, lg));
    let signal_at = usize::try_from(signal_at).ok()?;
    let mem_len = usize::try_from(mem_len).unwrap_or(0);
    if signal_at + mem_len + usize::try_from(lg).unwrap_or(0) + L_FILT_MAX as usize > SIGNAL_TAB_LEN
    {
        return None;
    }
    Some(ModifyFsSetup {
        cfg,
        flag_low_order,
        lg_out,
        filt_len,
        plus_sample_in,
        frac,
        mem_len,
        signal_at,
    })
}

/// `modify_Fs_fx` from the point the input sits in the working buffer (after the memory):
/// prepend the memory, pad by LP ringing for 8 → 12.8 kHz, interpolate, rescale, update the memory.
fn modify_fs_resample(
    signal_tab: &mut [i16; SIGNAL_TAB_LEN],
    setup: &ModifyFsSetup,
    lg: i16,
    fin: i32,
    sig_out: &mut [i16],
    mem: &mut [i16],
) -> i16 {
    let signal = &mut signal_tab[setup.signal_at..];
    let mem_len = setup.mem_len;
    let lgu = usize::try_from(lg).unwrap_or(0);
    // append the filter memory
    signal[..mem_len].copy_from_slice(&mem[..mem_len]);

    if setup.plus_sample_in > 0 {
        modify_fs_ringing(signal, mem_len, lgu, fin, setup.plus_sample_in);
    }

    // interpolation
    let cfg = setup.cfg;
    let fac_num = cfg.fac_num_fx;
    let fac_den = cfg.fac_den_fx;
    let datastep = shr(div_s(shl(fac_den, 8), shl(fac_num, 11)), 12);
    // equivalent to 'datastep = fac_den % fac_num'
    let temp_n = i_mult2(datastep, fac_num);
    let fracstep = sub(fac_den, temp_n);
    let mut sig_in_at = usize::try_from(add(setup.filt_len, setup.plus_sample_in)).unwrap_or(0);
    let filt_len_tmp = if setup.flag_low_order {
        shr(add(setup.filt_len, 1), 1)
    } else {
        setup.filt_len
    };
    let mut frac = setup.frac;
    let lg_out = setup.lg_out;
    for out in sig_out
        .iter_mut()
        .take(usize::try_from(lg_out).unwrap_or(0))
    {
        *out = round_word(interpol_lc(
            signal,
            sig_in_at,
            cfg.filter_fx,
            frac,
            fac_num,
            filt_len_tmp,
        ));
        frac = add(frac, fracstep);
        let j = sub(fac_num, frac);
        if j < 0 {
            frac = sub(frac, fac_num);
        }
        sig_in_at += usize::try_from(add(lshr(j, 15), datastep)).unwrap_or(0);
    }

    modify_fs_rescale(sig_out, lg_out, fin, cfg);

    // update the filter memory
    mem[..mem_len].copy_from_slice(&signal[lgu..lgu + mem_len]);
    lg_out
}

/// `modify_Fs_fx`'s 8 → 12.8 kHz padding: `plus_sample_in` samples of LP ringing past the input,
/// from an order-M LP model of the last LEN_WIN_SSS samples, pre-emphasised by their first
/// normalised autocorrelation.
fn modify_fs_ringing(signal: &mut [i16], mem_len: usize, lg: usize, fin: i32, plus_sample_in: i16) {
    let win = LEN_WIN_SSS as usize;
    let mut r_h = [0i16; (M + 1) as usize];
    let mut r_l = [0i16; (M + 1) as usize];
    let mut a = [0i16; (M + 1) as usize];
    let mut epsp = [0i32; (M + 1) as usize];
    let mut q_r = 0i16;
    let ana_at = mem_len + lg - win;
    autocorr(
        &signal[ana_at..],
        1,
        &mut r_h,
        &mut r_l,
        &mut q_r,
        LEN_WIN_SSS,
        &WIND_SSS_FX,
        0,
        0,
    );

    let t1 = l_comp(r_h[1], r_l[1]); // R[1] in Q31
    let t2 = l_abs(t1);
    let mut t0 = l_deposit_l(0);
    if r_h[0] != 0 {
        t0 = div_32(t2, r_h[0], r_l[0]); // R[1]/R[0] in Q31
    }
    if t1 < 0 {
        t0 = l_negate(t0);
    }
    let mu_preemph = extract_h(t0);
    let mut mem_preemph = signal[ana_at - 1];
    preemph_copy_in_place(
        &mut signal[ana_at..],
        mu_preemph,
        LEN_WIN_SSS,
        &mut mem_preemph,
    );

    // autocorrelations, lag windowing, Levinson-Durbin
    autocorr(
        &signal[ana_at..],
        M,
        &mut r_h,
        &mut r_l,
        &mut q_r,
        LEN_WIN_SSS,
        &WIND_SSS_FX,
        0,
        0,
    );
    lag_wind(&mut r_h, &mut r_l, M, fin, LAGW_STRONG);
    e_lpc_lev_dur(&r_h, &r_l, &mut a, Some(&mut epsp), M, None);
    let a_in = a;
    copy_scale_sig(&a_in, &mut a, M + 1, sub(norm_s(a_in[0]), 2));

    for i in 0..usize::try_from(plus_sample_in).unwrap_or(0) {
        let at = lg + mem_len + i;
        let mut l_tmp = syn_kern_16(0, &a, signal, at);
        l_tmp = l_shl(l_tmp, 3);
        signal[at] = round_word(l_tmp); // AZ ringing padding
    }
    let mut mem_preemph = signal[mem_len + lg - win - 1];
    deemph(
        &mut signal[mem_len + lg - win..],
        mu_preemph,
        LEN_WIN_SSS + plus_sample_in,
        &mut mem_preemph,
    );
}

/// `modify_Fs_fx`'s rescaling of the interpolated output by the conversion ratio.
fn modify_fs_rescale(sig_out: &mut [i16], lg_out: i16, fin: i32, cfg: &ResamplingCfgFx) {
    let fac_num = cfg.fac_num_fx;
    let fac_den = cfg.fac_den_fx;
    let n = usize::try_from(lg_out).unwrap_or(0);
    let inv = (i32::from(cfg.flags_fx) & RS_INV_FAC) != 0;
    if (fac_num > fac_den) == inv {
        if fac_num < fac_den {
            let mut num_den = div_s(fac_num, fac_den); // Q15
            if fin > 16000 && lg_out == 512 {
                for v in &mut sig_out[..n] {
                    *v = round_word(l_shl(l_mult(*v, num_den), 1));
                }
            } else {
                if fin > 16000 && (lg_out == L_FRAME || lg_out == L_FRAME16K || lg_out == 512) {
                    num_den = shl(num_den, 1);
                }
                for v in &mut sig_out[..n] {
                    *v = mult_r(*v, num_den);
                }
            }
        } else if fac_num == 8 {
            let num_den = 26214;
            for v in &mut sig_out[..n] {
                *v = mult_r(*v, num_den);
            }
        } else {
            let num_den = div_s(sub(fac_num, fac_den), fac_den); // Q15
            for v in &mut sig_out[..n] {
                *v = round_word(l_mac(l_deposit_h(*v), *v, num_den));
            }
        }
    } else if fac_num < fac_den && inv {
        for v in &mut sig_out[..n] {
            *v = mult_r(*v, 16384);
        }
    }
}

/// `Interpolate_allpass_steep_fx`: 2:1 interpolation of `in_fx[0..n]` into `out_fx[0..2n]` by two
/// three-section all-pass chains (odd outputs from the upper, even from the lower), with the
/// state `state_fx[0..2·ALLPASSSECTIONS_STEEP]`.
pub fn interpolate_allpass_steep(in_fx: &[i16], state_fx: &mut [i16], n: i16, out_fx: &mut [i16]) {
    const S: usize = ALLPASSSECTIONS_STEEP as usize;
    let n = n.max(0) as usize;

    // upper allpass filter chain
    for k in 0..n {
        let mut lacc = l_deposit_h(state_fx[0]);
        lacc = l_mac(lacc, AP2_STEEP_FX[0], in_fx[k]);
        let mut lacc1 = l_deposit_h(in_fx[k]);
        let temp1 = round_word(lacc);
        lacc1 = l_msu(lacc1, AP2_STEEP_FX[0], temp1);
        state_fx[0] = round_word(lacc1);

        lacc1 = l_deposit_h(state_fx[1]);
        lacc1 = l_mac(lacc1, AP2_STEEP_FX[1], temp1);
        lacc = l_deposit_h(temp1);
        let temp2 = round_word(lacc1);
        lacc = l_msu(lacc, AP2_STEEP_FX[1], temp2);
        state_fx[1] = round_word(lacc);

        lacc1 = l_deposit_h(temp2);
        lacc = l_deposit_h(state_fx[S - 1]);
        out_fx[2 * k + 1] = round_word(l_mac(lacc, AP2_STEEP_FX[S - 1], temp2));
        state_fx[S - 1] = round_word(l_msu(lacc1, AP2_STEEP_FX[S - 1], out_fx[2 * k + 1]));
    }

    // lower allpass filter chain
    for k in 0..n {
        let mut lacc = l_deposit_h(state_fx[S]);
        lacc = l_mac(lacc, AP1_STEEP_FX[0], in_fx[k]);
        let mut lacc1 = l_deposit_h(in_fx[k]);
        let temp1 = round_word(lacc);
        lacc1 = l_msu(lacc1, AP1_STEEP_FX[0], temp1);
        state_fx[S] = round_word(lacc1);

        lacc1 = l_deposit_h(state_fx[S + 1]);
        lacc1 = l_mac(lacc1, AP1_STEEP_FX[1], temp1);
        let temp2 = round_word(lacc1);
        lacc = l_deposit_h(temp1);
        lacc = l_msu(lacc, AP1_STEEP_FX[1], temp2);
        state_fx[S + 1] = round_word(lacc);

        lacc = l_deposit_h(state_fx[2 * S - 1]);
        lacc1 = l_deposit_h(temp2);
        out_fx[2 * k] = round_word(l_mac(lacc, AP1_STEEP_FX[S - 1], temp2));
        state_fx[2 * S - 1] = round_word(l_msu(lacc1, AP1_STEEP_FX[S - 1], out_fx[2 * k]));
    }
}

/// `interpolate_3_over_1_allpass_fx`: 3:1 interpolation of `input_fx[0..len]` into
/// `out_fx[0..3·len]` by three all-pass branches and a 4-tap low-pass, with the memory
/// `mem_fx[0..13]` (`INTERP_3_1_MEM_LEN`) and the branch coefficients `filt_coeff_fx[0..9]` (Q15).
pub fn interpolate_3_over_1_allpass(
    input_fx: &[i16],
    len: i16,
    out_fx: &mut [i16],
    mem_fx: &mut [i16],
    filt_coeff_fx: &[i16],
) {
    let len = len.max(0) as usize;
    let mut out1 = 0usize;
    for &input in &input_fx[..len] {
        // Upper branch
        let vu0 = add(mem_fx[0], mult_r(filt_coeff_fx[0], sub(input, mem_fx[1])));
        let vu1 = add(mem_fx[1], mult_r(filt_coeff_fx[1], sub(vu0, mem_fx[2])));
        mem_fx[3] = add(mem_fx[2], mult_r(filt_coeff_fx[2], sub(vu1, mem_fx[3])));
        mem_fx[1] = vu0;
        mem_fx[2] = vu1;
        out_fx[out1] = mem_fx[3];
        out1 += 1;

        // Middle branch
        let vm0 = add(mem_fx[0], mult_r(filt_coeff_fx[3], sub(input, mem_fx[4])));
        let vm1 = add(mem_fx[4], mult_r(filt_coeff_fx[4], sub(vm0, mem_fx[5])));
        mem_fx[6] = add(mem_fx[5], mult_r(filt_coeff_fx[5], sub(vm1, mem_fx[6])));
        mem_fx[4] = vm0;
        mem_fx[5] = vm1;
        out_fx[out1] = mem_fx[6];
        out1 += 1;

        // Lower branch
        let vl0 = add(mem_fx[0], mult_r(filt_coeff_fx[6], sub(input, mem_fx[7])));
        let vl1 = add(mem_fx[7], mult_r(filt_coeff_fx[7], sub(vl0, mem_fx[8])));
        mem_fx[9] = add(mem_fx[8], mult_r(filt_coeff_fx[8], sub(vl1, mem_fx[9])));
        mem_fx[0] = input;
        mem_fx[7] = vl0;
        mem_fx[8] = vl1;
        out_fx[out1] = mem_fx[9];
        out1 += 1;
    }
    // LPF
    for out in &mut out_fx[..len * 3] {
        let mem_temp = *out;
        *out = sub(
            mult_r(18768, add(mem_fx[12], mem_fx[11])), // 0.57276865021499168f Q15
            mult_r(2425, add(mem_temp, mem_fx[10])),    // 0.074004974641176793f Q15
        );
        mem_fx[10] = mem_fx[11];
        mem_fx[11] = mem_fx[12];
        mem_fx[12] = mem_temp;
    }
}

/// `QSR`: the right shift of the input that keeps the cubic coefficients from overflowing.
const QSR: i16 = 2;
/// The longest input [`modify_fs_intcub3m_sup`] takes (the reference `calloc`s `lg + 2`; its only
/// callers pass the 1.25 ms CLDFB delay, 16 or 20 samples).
const INTCUB_MAX_LG: usize = L_FRAME48K as usize;

/// The cubic coefficients `cc` (`d, c, b, a` of `a·s³ + b·s² + c·s + d`, `d` pre-divided by 3)
/// through the four samples `sr[at - 1 ..= at + 2]` of the shifted input.
fn intcub_coefficients(sr: &[i16], at: usize) -> [i16; 4] {
    let mut c = [0i16; 4];
    c[0] = mult_r(sr[at], 10923); // sigIn[0]/3
    c[2] = sub(shr(add(sr[at - 1], sr[at + 1]), 1), sr[at]); // (sigIn[-1]+sigIn[1])/2-sigIn[0]
    c[3] = sub(
        mult_r(
            sub(add(sr[at - 1], sr[at + 2]), add(sr[at], sr[at + 1])),
            5461,
        ),
        mult_r(c[2], 21845),
    );
    c[1] = sub(sub(sr[at + 1], sr[at]), add(c[3], c[2]));
    c
}

/// `vv32 += 8192·c[0] ± u[0]·c[1] + u[1]·c[2] ± u[2]·c[3]` (the minus signs when `negative`).
fn intcub_accumulate(vv32: i32, c: &[i16; 4], u: &[i16; 3], negative: bool) -> i32 {
    let mut vv32 = l_mac(vv32, 8192, c[0]);
    vv32 = if negative {
        l_msu(vv32, u[0], c[1])
    } else {
        l_mac(vv32, u[0], c[1])
    };
    vv32 = l_mac(vv32, u[1], c[2]);
    if negative {
        l_msu(vv32, u[2], c[3])
    } else {
        l_mac(vv32, u[2], c[3])
    }
}

/// `modify_Fs_intcub3m_sup_fx`: resample `sig_in[sig_in_at..sig_in_at + lg]` (with two samples of
/// memory before it, `sig_in[sig_in_at - 2..sig_in_at]`) from `fin` to `fout` by piecewise cubic
/// interpolation into `sig_out`, returning the output length; `delayout` receives the output
/// delay. Only the rates the reference tabulates (12.8 kHz to 8/16/32/48 kHz, 16 kHz to
/// 12.8/32/48 kHz) are supported; another pair has no table row (the C indexes `ct2_fx[-1]`), and
/// here produces no output.
pub fn modify_fs_intcub3m_sup(
    sig_in: &[i16],
    sig_in_at: usize,
    lg: i16,
    fin: i32,
    sig_out: &mut [i16],
    fout: i32,
    delayout: &mut i16,
) -> i16 {
    let mut k: i16 = 0; // to avoid compilation warnings
    let mut inc: i16 = 0;

    // check if fin and fout are the same
    if l_sub(fin, fout) == 0 {
        // just copy the signal and quit
        let lgu = lg.max(0) as usize;
        sig_out[..lgu].copy_from_slice(&sig_in[sig_in_at..sig_in_at + lgu]);
        *delayout = 0;
        return lg;
    }

    // shift right: Q0 -> Q(-QSR); sigin_sr[i] is sr[i + 2]. On a length that is not a whole
    // number of interpolation periods the C reads up to one period past its `lg + 2` samples
    // (heap garbage); the slack here reads zeros instead. The callers pass whole periods.
    let lgu = (lg.max(0) as usize).min(INTCUB_MAX_LG);
    let mut sr = [0i16; INTCUB_MAX_LG + 2 + 16];
    for (i, value) in sr.iter_mut().take(lgu + 2).enumerate() {
        *value = shr(sig_in[sig_in_at + i - 2], QSR);
    }
    let sig = |i: i16| sig_in[sig_in_at + i as usize];

    // coef inits using memory (indexes < 0): cc[2] on -2 -1 0 1, cc[3] on -1 0 1 2
    let mut cc = [[0i16; 4]; 4];
    cc[2] = intcub_coefficients(&sr, 1);
    cc[3] = intcub_coefficients(&sr, 2);

    let mut out: usize = 0;
    let cind: Option<usize> = match (fin, fout) {
        (12800, 8000) => Some(0),
        (12800, 16000) => Some(1),
        (12800, 32000) => Some(2),
        (12800, 48000) => Some(3),
        (16000, 12800) => Some(4),
        (16000, 32000) => Some(5),
        (16000, 48000) => Some(6),
        _ => None,
    };
    let Some(cind) = cind else {
        *delayout = 0;
        return 0;
    };
    let ctptr = &CT2_FX[cind];
    let lg_out = mult_r(shl(lg, 2), ctptr[13]);
    *delayout = ctptr[9];

    // every row is on the 15- or the 4-point raster
    let cu: &[[i16; 3]] = if sub(ctptr[12], 4) == 0 {
        &CU4_FX
    } else {
        &CU15_FX
    };

    let k2d = sub(ctptr[12], 1); // shift of index in cu with respect to the next sample
    let fk1 = shl(k2d, 1);
    let k3d = sub(fk1, 1); // index in cu with respect to the last sample, with - sign

    let mut kk: usize = 0;
    let mut i: i16 = 0;

    let lim = sub(lg, ctptr[11]);
    let lim2 = sub(lg, 3);
    let mut lim3 = ctptr[10];
    while sub(i, lim2) < 0 {
        if sub(i, lim) >= 0 {
            lim3 = sub(ctptr[11], 3); // last, incomplete period
        }
        sig_out[out] = sig(i);
        out += 1;
        k = 0;
        while k < lim3 {
            cc[kk] = intcub_coefficients(&sr, i as usize + 3);
            i = add(i, 1);

            let i2 = (kk + 2) % 4; // kk - 2
            let i1 = (kk + 3) % 4; // kk - 1
            inc = ctptr[8];
            let mut k1 = ctptr[k as usize];
            while k1 < fk1 {
                let k2 = sub(k1, k2d);
                let k3 = sub(k3d, k1);
                let c = &cc[i2];
                let mut vv32 = l_mult(8192, c[0]);
                vv32 = l_mac(vv32, cu[k1 as usize][0], c[1]);
                vv32 = l_mac(vv32, cu[k1 as usize][1], c[2]);
                vv32 = l_mac(vv32, cu[k1 as usize][2], c[3]); // Q13*Q(-QSR) -> Q(13-QSR+1)
                vv32 = intcub_accumulate(vv32, &cc[i1], &cu[k2 as usize], false);
                vv32 = intcub_accumulate(vv32, &cc[kk], &cu[k3 as usize], true);
                vv32 = l_shl(vv32, QSR + 2); // Q(13-QSR+1) -> Q16
                sig_out[out] = round_word(vv32); // Q16 -> Q0
                out += 1;
                k1 += inc;
            }

            kk += 1;
            if kk == 4 {
                kk = 0;
            }
            k += 1;
        }
    }

    kk = (kk + 3) % 4;

    if sub(ctptr[10], 1) == 0 {
        sig_out[out] = sig(i);
        out += 1;
    }

    // With no full period (lg <= 3) the C never sets inc and loops forever on these two tails;
    // here they are skipped instead.
    if inc > 0 {
        let mut k1 = ctptr[k as usize];
        while k1 < fk1 {
            let k2 = sub(k1, k2d);
            let mut vv32 = l_mult(8192, cc[kk][0]);
            vv32 = l_mac(vv32, cu[k2 as usize][0], cc[kk][1]);
            vv32 = l_mac(vv32, cu[k2 as usize][1], cc[kk][2]);
            vv32 = l_mac(vv32, cu[k2 as usize][2], cc[kk][3]);
            vv32 = l_shl(vv32, QSR + 2);
            sig_out[out] = i_mult(round_word(vv32), 3);
            out += 1;
            k1 += inc;
        }
    }

    if sub(ctptr[10], 3) < 0 {
        sig_out[out] = sig(add(i, 1));
        out += 1;
    }

    if inc > 0 {
        let mut k1 = ctptr[k as usize + 1];
        while k1 < fk1 {
            let mut vv32 = l_mult(8192, cc[kk][0]);
            vv32 = l_mac(vv32, cu[k1 as usize][0], cc[kk][1]);
            vv32 = l_mac(vv32, cu[k1 as usize][1], cc[kk][2]);
            vv32 = l_mac(vv32, cu[k1 as usize][2], cc[kk][3]);
            vv32 = l_shl(vv32, QSR + 2);
            sig_out[out] = i_mult(round_word(vv32), 3);
            out += 1;
            k1 += inc;
        }
    }

    if sub(ctptr[10], 1) == 0 {
        sig_out[out] = sig(add(i, 2));
    }

    lg_out
}

/// `NBPSF_PIT_MAX`: the length of the narrowband post-filter's synthesis memory (58 x 5).
const NBPSF_PIT_MAX: usize = 290;

/// `retro_interp4_5_fx`: resamples the post-filter memory `pst_old_syn` (290 samples) from 12.8 to
/// 16 kHz (4 samples to 5) in a reverse way to preserve time alignment; the first input sample
/// beyond the memory is `syn[0]`. The 5-sample groups are written at `5c`, the 4-sample groups read
/// from `58 + 4c`: late in the buffer the write position overtakes the read position, as in the
/// reference, so the reads see already rewritten samples.
pub fn retro_interp4_5(syn: &[i16], pst_old_syn: &mut [i16]) {
    let mut pf4 = 58;
    let mut pf5 = 0;
    for _ in 0..57 {
        pst_old_syn[pf5] = pst_old_syn[pf4];
        pst_old_syn[pf5 + 1] = mac_r(l_mult(6554, pst_old_syn[pf4]), 26214, pst_old_syn[pf4 + 1]);
        pst_old_syn[pf5 + 2] = mac_r(
            l_mult(13107, pst_old_syn[pf4 + 1]),
            19661,
            pst_old_syn[pf4 + 2],
        );
        pst_old_syn[pf5 + 3] = mac_r(
            l_mult(19661, pst_old_syn[pf4 + 2]),
            13107,
            pst_old_syn[pf4 + 3],
        );
        pst_old_syn[pf5 + 4] = mac_r(
            l_mult(26214, pst_old_syn[pf4 + 3]),
            6554,
            pst_old_syn[pf4 + 4],
        );
        pf5 += 5;
        pf4 += 4;
    }
    pst_old_syn[pf5] = pst_old_syn[pf4];
    pst_old_syn[pf5 + 1] = mac_r(l_mult(6554, pst_old_syn[pf4]), 26214, pst_old_syn[pf4 + 1]);
    pst_old_syn[pf5 + 2] = mac_r(
        l_mult(13107, pst_old_syn[pf4 + 1]),
        19661,
        pst_old_syn[pf4 + 2],
    );
    pst_old_syn[pf5 + 3] = mac_r(
        l_mult(19661, pst_old_syn[pf4 + 2]),
        13107,
        pst_old_syn[pf4 + 3],
    );
    pst_old_syn[pf5 + 4] = mac_r(l_mult(26214, pst_old_syn[pf4 + 3]), 6554, syn[0]);
    // all samples processed: NBPSF_PIT_MAX = 290 = (58*5)
}

/// `retro_interp5_4_fx`: resamples the post-filter memory `pst_old_syn` (290 samples) from 16 to
/// 12.8 kHz (5 samples to 4) in a reverse way to preserve time alignment, in place from the end.
pub fn retro_interp5_4(pst_old_syn: &mut [i16]) {
    let mut pf4 = NBPSF_PIT_MAX - 1;
    let mut pf5 = pf4;
    for _ in 0..58 {
        pst_old_syn[pf4] = mac_r(l_mult(24576, pst_old_syn[pf5]), 8192, pst_old_syn[pf5 - 1]);
        pst_old_syn[pf4 - 1] = mac_r(
            l_mult(16384, pst_old_syn[pf5 - 1]),
            16384,
            pst_old_syn[pf5 - 2],
        );
        pst_old_syn[pf4 - 2] = mac_r(
            l_mult(8192, pst_old_syn[pf5 - 2]),
            24576,
            pst_old_syn[pf5 - 3],
        );
        pst_old_syn[pf4 - 3] = pst_old_syn[pf5 - 4];
        // the last group ends at index 0: pf4 and pf5 are not used past it
        pf4 = pf4.wrapping_sub(4);
        pf5 = pf5.wrapping_sub(5);
    }
}
