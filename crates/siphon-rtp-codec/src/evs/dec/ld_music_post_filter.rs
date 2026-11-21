//! The low-delay music post-filter of the ACELP core: a noise-reduction style gain per DCT bin of
//! the excitation, applied to music frames at the low rates (TS 26.442
//! `lib_dec/LD_music_post_filter_fx.c`; TS 26.445 §6.1.4.2.3).
//!
//! `Prep_music_postP_fx` windows the (pitch-extended) excitation and transforms it,
//! `LD_music_post_filter_fx` shapes its spectrum, `Post_music_postP_fx` transforms back and
//! re-synthesises.

use crate::evs::basop::{madd_32_16, mult_32_16};
use crate::evs::cnst::{
    ACELP_12K65, ACELP_15K85, ACELP_6K60, ACELP_8K85, ACELP_9K60, AUDIO, BIN_16KDCT_FX, DCT_L_POST,
    HQ_CORE, L_FRAME, L_INTERPOL2, M, MBANDS_GN_LD, OFFSET2,
};
use crate::evs::com::edct::edct_16fx;
use crate::evs::com::log2::log2_norm_lc;
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::com::pred_lt4::pred_lt4;
use crate::evs::com::scale_mem::rescale_mem;
use crate::evs::com::stab_est::stab_est;
use crate::evs::com::syn_12k8::syn_12k8;
use crate::evs::com::tools::{scale_sig32, set16};
use crate::evs::dec::state::Pfstat;
use crate::evs::rom::{
    INV_MAX_SNR_TAB_FX, INV_MFREQ_BINDIV_LD_FX, INV_MFREQ_BINDIV_LD_M1_FX, MAX_SNR_SNR1_TAB_FX,
    MFREQ_BINDIV_LD, MFREQ_LOC_LD, MFREQ_LOC_LD_FX, PITCH_INTER4_2, POST_DCT_WIND_FX, SC_QNOISE_FX,
};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_deposit_l, l_mac, l_msu, l_mult, l_shl,
    l_shr, l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl, shr, shr_r, sub,
};
use crate::itu::oper_32b::mpy_32_16;
use crate::itu::stl2009::msu_r;

/// The DCT length.
const DCT: usize = DCT_L_POST as usize;
/// Gain bands.
const BANDS: usize = MBANDS_GN_LD as usize;
/// `BIN_1KHZ`, `BIN_2KHZ`, `BIN_4KHZ`: DCT bins below 1, 2 and 4 kHz.
const BIN_1KHZ: usize = (1000 / BIN_16KDCT_FX) as usize;
const BIN_2KHZ: usize = (2000 / BIN_16KDCT_FX) as usize;
const BIN_4KHZ: usize = (4000 / BIN_16KDCT_FX) as usize;
/// `MAXX_Q12_FX`: the ceiling of the normalised bin energies, 5 in Q12.
const MAXX_Q12_FX: i16 = 20480;
/// `BET_Q15_FX`.
const BET_Q15_FX: i16 = 30310;

/// The memories of `LD_music_post_filter_fx` (all `Decoder_State_fx` fields).
#[derive(Debug)]
pub struct LdMusicState<'a> {
    /// `LDm_last_music_flag`
    pub last_music_flag: &'a mut i16,
    /// `LDm_thres[4]`
    pub thresh: &'a mut [i16],
    /// `LDm_nb_thr_1`
    pub nb_thr_1: &'a mut i16,
    /// `LDm_nb_thr_3`
    pub nb_thr_3: &'a mut i16,
    /// `LDm_lt_diff_etot[MAX_LT]`
    pub lt_diff_etot: &'a mut [i16],
    /// `LDm_mem_etot`
    pub mem_etot: &'a mut i16,
    /// `LDm_bckr_noise[MBANDS_GN_LD]`
    pub bckr: &'a mut [i32],
    /// `LDm_enh_lf_EO[VOIC_BINS_HR]`
    pub lf_eo: &'a mut [i32],
    /// `LDm_enh_lp_gbin[VOIC_BINS_HR]`
    pub lp_gbin: &'a mut [i16],
    /// `filt_lfE[DCT_L_POST]`
    pub filt_lfe: &'a mut [i16],
    /// `last_nonfull_music`
    pub last_nonfull_music: &'a mut i16,
    /// `Old_ener_Q`
    pub old_ener_q: &'a mut i16,
}

/// `LD_music_post_filter_fx`, in place: every caller passes the same DCT buffer as `dtc_in` and
/// `dtc_out` (the reference's `Copy` between them is then a no-op, and the input is fully read
/// before the first write). `dtc` is the excitation DCT in Q`qdct`.
pub fn ld_music_post_filter(
    dtc: &mut [i16],
    core_brate: i32,
    st: &mut LdMusicState<'_>,
    min_ns_gain: i16,
    coder_type: i16,
    last_coder_type: i16,
    qdct: i16,
) {
    let mut fr_bands = [0i32; BANDS];
    let mut lf_e = [0i32; DCT];
    let mut lg_etot: i16 = 0;
    let mut min_band: i16 = 0;
    let mut local_min_gain = min_ns_gain;

    // frequency analysis
    analy_sp_dct(dtc, &mut fr_bands, &mut lf_e, &mut lg_etot, qdct);
    // rescale the previous frame's bin energies to this frame's Q
    let diff_sc = shl(sub(qdct, *st.old_ener_q), 1);
    *st.old_ener_q = qdct;
    scale_sig32(st.lf_eo, DCT_L_POST, diff_sc);

    // find signal stability, and the noise-reduction aggressiveness
    let mut music_flag2 = stab_est(
        lg_etot,
        st.lt_diff_etot,
        st.mem_etot,
        st.nb_thr_3,
        st.nb_thr_1,
        st.thresh,
        st.last_music_flag,
        1,
    );
    if l_sub(core_brate, i32::from(ACELP_6K60)) < 0 || sub(last_coder_type, AUDIO) != 0 {
        music_flag2 = 0;
    }
    *st.last_nonfull_music = add(*st.last_nonfull_music, 1);
    if sub(music_flag2, 4) < 0 {
        *st.last_nonfull_music = 0;
    }
    *st.last_nonfull_music = (*st.last_nonfull_music).min(51);

    // stability-dependent minimum gain and first band
    if sub(music_flag2, 3) > 0 {
        min_band = 2;
        local_min_gain = 8231; // 0.25119 Q15
    } else if sub(music_flag2, 3) == 0 {
        min_band = 3;
        local_min_gain = 8231;
    } else if sub(music_flag2, 2) == 0 {
        min_band = 4;
        local_min_gain = 11626; // 0.35481 Q15
    } else if sub(music_flag2, 1) == 0 {
        min_band = 4;
        local_min_gain = 16423; // 0.50119 Q15
    }
    min_band = add(min_band, 4);

    let mut max_gn: i16 = 1638; // 0.1 Q14
    if l_sub(core_brate, i32::from(ACELP_9K60)) > 0 {
        max_gn = 0;
    }
    if sub(coder_type, AUDIO) == 0 {
        min_band = min_band.min(3);
    }

    ld_music_post_filter_noise_estimate(&lf_e, st);

    let mut max_band = MBANDS_GN_LD;
    if sub(coder_type, AUDIO) == 0 {
        max_band = 16;
    }
    // (Copy(dtc_in, dtc_out, DCT_L_POST): the same buffer)
    spectrum_mod_dct(
        qdct,
        dtc,
        &lf_e,
        st.lf_eo,
        st.bckr,
        local_min_gain,
        st.lp_gbin,
        music_flag2,
        min_band,
        max_gn,
        max_band,
    );
    ld_music_post_filter_shape(dtc, core_brate, st, music_flag2, coder_type);
}

/// The background noise per band (the band's mean energy without its largest bin, scaled), and
/// the smoothed normalised bin energies `filt_lfE` that drive the high-band shaping.
fn ld_music_post_filter_noise_estimate(lf_e: &[i32; DCT], st: &mut LdMusicState<'_>) {
    let mut tmp_lfe = [0i16; DCT];
    let mut j = 0usize;
    let mut ltmp_max = l_deposit_l(0);
    for i in 0..BANDS {
        let mut ltmp = l_deposit_l(0);
        let mut max_val = l_deposit_l(0);
        let width = MFREQ_BINDIV_LD[i] as usize;
        for &e in &lf_e[j..j + width] {
            ltmp = l_add(e, ltmp);
            max_val = max_val.max(e);
        }
        ltmp_max = ltmp_max.max(max_val);
        ltmp = l_sub(ltmp, max_val);
        let m_ave = mult_32_16(ltmp, INV_MFREQ_BINDIV_LD_M1_FX[i]);
        st.bckr[i] = mult_32_16(m_ave, SC_QNOISE_FX[i]);
        j += width;
    }

    let exp1 = norm_l(ltmp_max);
    let mant = extract_h(l_shl(ltmp_max, exp1));
    let s_ave = div_s(16384, mant);
    let exp1 = sub(14 + 16, exp1);

    let mut old_tmp16 = norm_lfe(lf_e[0], s_ave, exp1).min(MAXX_Q12_FX);
    let mut tmp16 = norm_lfe(lf_e[1], s_ave, exp1).min(MAXX_Q12_FX);
    let mut old_tmp16_1 = tmp16;
    tmp_lfe[0] = round_word(l_mac(l_mult(16384, old_tmp16), 16384, tmp16));
    let mut i = 1usize;
    while i < DCT - 1 {
        // three-tap mean of the normalised energies
        let mut ltmp = l_mac(l_mult(10813, old_tmp16), 10813, old_tmp16_1);
        old_tmp16 = old_tmp16_1;
        tmp16 = norm_lfe(lf_e[i + 1], s_ave, exp1);
        old_tmp16_1 = tmp16.min(MAXX_Q12_FX);
        ltmp = l_mac(ltmp, 10813, old_tmp16_1);
        tmp_lfe[i] = round_word(ltmp);
        i += 1;
    }
    tmp16 = norm_lfe(lf_e[i], s_ave, exp1).min(MAXX_Q12_FX);
    tmp_lfe[i] = round_word(l_mac(l_mult(16384, old_tmp16), 16384, tmp16));

    for (i, (filt, &e)) in st.filt_lfe[..DCT].iter_mut().zip(&tmp_lfe).enumerate() {
        // slow smoothing below 4 kHz, faster above
        let (new, old) = if i < BIN_4KHZ {
            (1638, 31130)
        } else {
            (4915, 27853)
        };
        *filt = round_word(l_mac(l_mult(e, new), old, *filt));
    }
}

/// Weight the spectrum with the smoothed normalised energies, more strongly after a long run of
/// stable music frames.
fn ld_music_post_filter_shape(
    dtc: &mut [i16],
    core_brate: i32,
    st: &LdMusicState<'_>,
    music_flag2: i16,
    coder_type: i16,
) {
    let filt_lfe = &*st.filt_lfe;
    let scale = |x: i16, g: i16| round_word(l_shl(l_mult(x, g), 3));
    let mut i = 0usize;
    if sub(music_flag2, 1) >= 0 {
        while i < BIN_1KHZ {
            let tmp16 = filt_lfe[i].min(4096);
            dtc[i] = scale(dtc[i], tmp16);
            i += 1;
        }
    }
    if sub(*st.last_nonfull_music, 40) > 0 {
        let (mut max_ovf_2k, mut max_ovf_4k, mut max_ovf_6k) = (5120, 6144, 6144);
        let (mut min_g_2k, mut min_g_4k, mut min_g_6k) = (0, 0, 0);
        if sub(coder_type, AUDIO) == 0 {
            max_ovf_2k = 4096;
            max_ovf_4k = 4506;
            max_ovf_6k = 5120;
            min_g_2k = 3072;
            min_g_4k = 2048;
            min_g_6k = 2048;
            if l_sub(core_brate, i32::from(ACELP_9K60)) > 0 {
                max_ovf_4k = 4096;
                max_ovf_6k = 4710;
                min_g_2k = 3789;
                min_g_4k = 3379;
                min_g_6k = 3072;
            }
        } else if l_sub(core_brate, i32::from(ACELP_12K65)) >= 0 {
            max_ovf_2k = 4096;
            max_ovf_4k = 5120;
            if l_sub(core_brate, i32::from(ACELP_15K85)) > 0 {
                max_ovf_4k = 4096;
                max_ovf_6k = 5120;
                min_g_2k = 3072;
                min_g_4k = 2048;
                min_g_6k = 2048;
            }
        }
        while i < BIN_2KHZ {
            let tmp16 = filt_lfe[i].min(max_ovf_2k).max(min_g_2k);
            dtc[i] = scale(dtc[i], tmp16);
            i += 1;
        }
        while i < BIN_4KHZ {
            let tmp16 = filt_lfe[i].min(max_ovf_4k).max(min_g_4k);
            dtc[i] = scale(dtc[i], tmp16);
            i += 1;
        }
        if sub(coder_type, AUDIO) != 0 || l_sub(core_brate, i32::from(ACELP_8K85)) > 0 {
            while i < DCT {
                let tmp16 = filt_lfe[i].min(max_ovf_6k).max(min_g_6k);
                dtc[i] = scale(dtc[i], tmp16);
                i += 1;
            }
        }
    } else if sub(*st.last_nonfull_music, 25) > 0 {
        while i < DCT {
            let tmp16 = filt_lfe[i].min(4096);
            dtc[i] = scale(dtc[i], tmp16);
            i += 1;
        }
    }
}

/// `spectrum_mod_dct_fx`: the per-bin noise-reduction gain (smoothed into `lp_gbin`) applied to
/// `data` on music frames; otherwise the gains only relax towards 1.
fn spectrum_mod_dct(
    qdct: i16,
    data: &mut [i16],
    lf_e: &[i32; DCT],
    lf_eo: &mut [i32],
    noise_e: &[i32],
    min_gain: i16,
    lp_gbin: &mut [i16],
    music_flag: i16,
    min_band: i16,
    max_gn: i16,
    max_band: i16,
) {
    let mut bin_e = [0i32; DCT];
    let mut m_invno = [0i16; BANDS];
    let mut e_invno = [0i16; BANDS];
    let scaling = add(shl(qdct, 1), 10);
    let dot5_scaled = l_shl(1, sub(scaling, 1));

    // inverse of the noise energy per band
    for i in 0..BANDS {
        if noise_e[i] != 0 {
            e_invno[i] = norm_l(noise_e[i]);
            m_invno[i] = extract_h(l_shl(noise_e[i], e_invno[i]));
            e_invno[i] = sub(14, e_invno[i]);
            m_invno[i] = div_s(16384, m_invno[i]);
        } else {
            e_invno[i] = add(-16, qdct);
            m_invno[i] = 0x7fff;
        }
    }
    // smoothed bin energies, and the update of the previous frame's
    for i in 0..DCT {
        let ltmp = mult_32_16(lf_eo[i], 9830); // 0.3
        bin_e[i] = madd_32_16(ltmp, lf_e[i], 22938); // 0.7
    }
    lf_eo[..DCT].copy_from_slice(&lf_e[..]);

    let mut max_noise = noise_e[0].max(noise_e[1]);
    for &n in &noise_e[2..BANDS] {
        max_noise = max_noise.max(n);
    }

    if music_flag != 0 {
        let min_e = if l_sub(max_noise, l_shl(10, scaling)) <= 0 {
            18432 / 2
        } else {
            shr(mult_r(min_gain, min_gain), 1)
        };
        let mut pt = 0usize;
        let mut freq: i16 = 0;
        let min_band = min_band.clamp(0, MBANDS_GN_LD) as usize;
        for &loc in &MFREQ_LOC_LD_FX[..min_band] {
            while freq <= loc {
                pt += 1;
                lp_gbin[pt - 1] = 16384;
                freq += BIN_16KDCT_FX;
            }
        }
        for i in min_band..max_band.clamp(0, MBANDS_GN_LD) as usize {
            let tmp_snr = INV_MAX_SNR_TAB_FX[i];
            let ltmp = l_mult(tmp_snr, 16384);
            let slope = msu_r(ltmp, tmp_snr, min_e);
            let ltmp = l_mult(MAX_SNR_SNR1_TAB_FX[i], min_e);
            let lshift = l_shl(l_msu(ltmp, tmp_snr, 8192), 1);
            let tmp_n = mult(slope, m_invno[i]);
            let e_tmp = e_invno[i];
            while freq <= MFREQ_LOC_LD_FX[i] {
                let mut lgain = l_deposit_h(16384);
                if l_sub(noise_e[i], dot5_scaled) > 0 {
                    // gain = slope / noise · binE + shift
                    let mut e_bin_e = norm_l(bin_e[pt]);
                    let m_bin_e = extract_h(l_shl(bin_e[pt], e_bin_e));
                    let ltmp = l_mult(tmp_n, m_bin_e);
                    e_bin_e = sub(add(e_tmp, e_bin_e), 15);
                    let ltmp = l_shr(ltmp, e_bin_e);
                    lgain = l_add(ltmp, lshift);
                }
                let mut gain = round_word(lgain);
                gain = gain.max(min_e);
                gain = gain.min(add(16384, max_gn));
                // alpha = 2 · (1 - sqrt(gain))
                let mut e_gain = norm_s(gain);
                let ltmp = l_shl(i32::from(gain), add(16, e_gain));
                e_gain = negate(sub(e_gain, 1));
                let ltmp = isqrt_lc(ltmp, &mut e_gain);
                let wtmp = extract_h(ltmp);
                let mut sqrt_gain = div_s(16384, wtmp);
                sqrt_gain = shr(sqrt_gain, e_gain);
                let alpha = shl(sub(16384, sqrt_gain), 1);
                let ltmp = l_mult(gain, 32767);
                lp_gbin[pt] = round_word(l_mac(ltmp, alpha, lp_gbin[pt]));
                data[pt] = round_word(l_shl(l_mult(data[pt], lp_gbin[pt]), 1));
                pt += 1;
                freq += BIN_16KDCT_FX;
            }
        }
    } else {
        let mut freq: i16 = BIN_16KDCT_FX;
        let mut pt = 0usize;
        for &loc in &MFREQ_LOC_LD {
            while freq <= loc {
                lp_gbin[pt] = round_word(l_mac(l_mult(29491, lp_gbin[pt]), 32767, 1638));
                pt += 1;
                freq += BIN_16KDCT_FX;
            }
        }
    }
}

/// `analy_sp_dct_fx`: the bin and band energies of the DCT and the total energy in dB (Q8).
fn analy_sp_dct(
    dct_buf: &[i16],
    fr_bands: &mut [i32; BANDS],
    lf_e: &mut [i32; DCT],
    etot: &mut i16,
    qdct: i16,
) {
    let mut letot = l_deposit_l(0);
    find_enr_dct(
        dct_buf,
        fr_bands,
        lf_e,
        &mut letot,
        0,
        MBANDS_GN_LD,
        qdct,
        BIN_16KDCT_FX,
    );
    // 10·log10(Etot)
    let mut exp_etot = norm_l(letot);
    let frac_etot = log2_norm_lc(l_shl(letot, exp_etot));
    exp_etot = sub(30, exp_etot);
    exp_etot = sub(exp_etot, add(shl(qdct, 1), 10 + 1));
    let letot = mpy_32_16(exp_etot, frac_etot, 24660); // 10·log10(2) Q13
    *etot = extract_l(l_shr(letot, 14 - 8));
}

/// `find_enr_dct_fx`: the energy of each DCT bin (`pt_e`), of each band, and their total over
/// bands `min_band..=16`.
fn find_enr_dct(
    data: &[i16],
    band: &mut [i32; BANDS],
    pt_e: &mut [i32; DCT],
    etot: &mut i32,
    min_band: i16,
    max_band: i16,
    q_dct: i16,
    bin_freq: i16,
) {
    let le_min = l_shl(14680, sub(shl(q_dct, 1) + 10, 22)).max(1);
    let mut pt = 0usize;
    let mut freq: i16 = 0;
    for i in 0..max_band.clamp(0, MBANDS_GN_LD) as usize {
        band[i] = 0;
        let mut ltmp1 = l_deposit_l(0);
        while freq <= MFREQ_LOC_LD_FX[i] {
            let mut ltmp = l_mult(data[pt], data[pt]);
            ltmp = mult_32_16(ltmp, 26214); // 0.8
            ltmp = ltmp.max(le_min);
            pt_e[pt] = ltmp;
            ltmp1 = l_add(ltmp, ltmp1);
            pt += 1;
            freq += bin_freq;
        }
        band[i] = mult_32_16(ltmp1, INV_MFREQ_BINDIV_LD_FX[i]).max(le_min);
    }
    let mut ltmp = 0;
    for &b in &band[min_band.max(0) as usize..=16] {
        ltmp = l_add(b, ltmp);
    }
    *etot = ltmp;
}

/// `norm_lfe`: the bin energy `lfe` normalised by the frame maximum (`m_norm`, `e_norm`), plus a
/// floor, raised to the eighth power (Q12).
fn norm_lfe(lfe: i32, m_norm: i16, e_norm: i16) -> i16 {
    let mut ltmp = mult_32_16(lfe, m_norm);
    ltmp = l_add(ltmp, l_shl(i32::from(BET_Q15_FX), sub(e_norm, 15)));
    let mut exp2 = norm_l(ltmp);
    let mut tmp16 = extract_h(l_shl(ltmp, exp2));
    exp2 = add(e_norm, exp2);
    tmp16 = mult_r(tmp16, tmp16);
    tmp16 = mult_r(tmp16, tmp16);
    tmp16 = mult_r(tmp16, tmp16);
    let mut exp3 = sub(12 + 16, exp2);
    if sub(exp2, 31) != 0 {
        exp3 = sub(exp2, 12 + 16 - 3);
    }
    shl(tmp16, exp3)
}

/// `Prep_music_postP_fx`: extend the excitation `exc_buffer_in` (`DCT_L_POST` samples ending with
/// the current frame's look-ahead slot) by one pitch period past the frame, window both ends and
/// transform it into `dct_buffer_out` (Q`*qdct` = `q_exc`). After an HQ frame the gain memories
/// are reset and the start of the buffer is rebuilt from the pitch.
pub fn prep_music_post_p(
    exc_buffer_in: &mut [i16],
    dct_buffer_out: &mut [i16],
    filt_lfe: &mut [i16],
    last_core: i16,
    pitch_buf: &[i16],
    ldm_enh_lp_gbin: &mut [i16],
    q_exc: i16,
    qdct: &mut i16,
) {
    const O2: usize = OFFSET2 as usize;
    let mut exc16 = [0i16; DCT];
    let s_pit = shr(pitch_buf[3], 6);
    let fr_pit = shr(sub(pitch_buf[3], shl(s_pit, 6)), 4); // Q0 fractional part, 0..3

    if sub(last_core, HQ_CORE) == 0 {
        set16(filt_lfe, 4096, DCT_L_POST);
        set16(ldm_enh_lp_gbin, 16384, DCT_L_POST);
        // the samples before the frame, rebuilt backwards from one pitch period later
        let lag = shr_r(pitch_buf[0], 6).max(0) as usize;
        for k in (0..O2).rev() {
            exc_buffer_in[k] = exc_buffer_in[k + lag];
        }
    }

    // the samples after the frame, predicted with the last subframe's pitch
    let at = DCT - O2;
    pred_lt4(
        exc_buffer_in,
        at,
        s_pit,
        fr_pit,
        OFFSET2,
        &PITCH_INTER4_2,
        L_INTERPOL2,
        4,
    );

    // windowing at both ends
    for i in 0..O2 {
        exc16[at + i] = mult_r(exc_buffer_in[at + i], POST_DCT_WIND_FX[i]);
    }
    for i in 0..O2 {
        exc16[i] = mult_r(exc_buffer_in[i], POST_DCT_WIND_FX[O2 - 1 - i]);
    }
    exc16[O2..(L_FRAME + OFFSET2) as usize]
        .copy_from_slice(&exc_buffer_in[O2..(L_FRAME + OFFSET2) as usize]);

    edct_16fx(&exc16, dct_buffer_out, DCT_L_POST, 6);
    *qdct = q_exc;
}

/// Where `Post_music_postP_fx` takes its synthesis memory from, and what else it updates.
#[derive(Debug)]
pub struct PostMusicMemories<'a> {
    /// `mem_tmp`: the synthesis memory to restart from; `None` when the caller passes
    /// `st_mem_syn2` itself (the reference's `Copy` is then a no-op).
    pub mem_tmp: Option<&'a [i16]>,
    /// `st_mem_syn2`
    pub st_mem_syn2: &'a mut [i16],
    /// `mem_syn_clas_estim_fx`
    pub mem_syn_clas_estim: &'a mut [i16],
    /// `mem_deemph`
    pub mem_deemph: &'a mut i16,
    /// `st_pst_old_syn_fx`
    pub pst_old_syn: &'a mut [i16],
    /// `st_pst_mem_deemp_err_fx`
    pub pst_mem_deemp_err: &'a mut i16,
    /// `mem_agc`
    pub mem_agc: &'a mut i16,
    /// `pf_stat`
    pub pf_stat: &'a mut Pfstat,
    /// `mem_tmp2`: receives the rescaled synthesis memory (written only when `is_io == 0`).
    pub mem_tmp2: Option<&'a mut [i16]>,
}

/// `Post_music_postP_fx`: inverse-transform the filtered spectrum back to the frame's excitation
/// `exc2`, rescale the memories (`is_io == 0`) and re-synthesise `syn` with `aq`.
pub fn post_music_post_p(
    dct_buffer_in: &[i16],
    exc2: &mut [i16],
    mem: &mut PostMusicMemories<'_>,
    aq: &[i16],
    syn: &mut [i16],
    q_exc: &mut i16,
    prev_q_syn: &mut i16,
    q_syn: &mut i16,
    is_io: i16,
    tmp_buffer: Option<&[i16]>,
) {
    let mut exc16 = [0i16; DCT];
    edct_16fx(dct_buffer_in, &mut exc16, DCT_L_POST, 6);
    // retrieve the excitation and restart the synthesis from the saved memory
    exc2[..L_FRAME as usize]
        .copy_from_slice(&exc16[OFFSET2 as usize..(OFFSET2 + L_FRAME) as usize]);
    if let Some(mem_tmp) = mem.mem_tmp {
        mem.st_mem_syn2[..M as usize].copy_from_slice(&mem_tmp[..M as usize]);
    }
    if is_io == 0 {
        rescale_mem(
            *q_exc,
            prev_q_syn,
            q_syn,
            mem.st_mem_syn2,
            mem.mem_syn_clas_estim,
            4,
            mem.mem_deemph,
            mem.pst_old_syn,
            mem.pst_mem_deemp_err,
            mem.mem_agc,
            mem.pf_stat,
            1,
            0,
            tmp_buffer,
        );
        if let Some(mem_tmp2) = mem.mem_tmp2.as_deref_mut() {
            mem_tmp2[..M as usize].copy_from_slice(&mem.st_mem_syn2[..M as usize]);
        }
    }
    syn_12k8(L_FRAME, aq, exc2, syn, mem.st_mem_syn2, 1, *q_exc, *q_syn);
}
