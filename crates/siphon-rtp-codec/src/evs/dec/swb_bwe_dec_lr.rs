//! SWB bandwidth extension of the low-rate HQ (LR-MDCT) core (TS 26.442
//! `lib_dec/swb_bwe_dec_lr_fx.c`; TS 26.445 §6.2.3.3.2).
//!
//! The high band (above `swb_lowband`) is replicated from the coded low band: in the
//! `HQ_NORMAL` class by lag-indexed copies with per-subband gains, in the `HQ_HARMONIC` class
//! by harmonic noise generation plus tonal gap filling.

use crate::evs::basop::{l_extract_lc, mult_32_16};
use crate::evs::cnst::{HQ_HARMONIC, HQ_NORMAL};
use crate::evs::cnst::{L_FRAME32K, NB_SWB_SUBBANDS, N_NBIGGEST_SEARCH_LRG_B, SWB_HAR_RAN1};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::math_op::pow2;
use crate::evs::com::swb_bwe_com_lr::{
    convert_lag_indices_pls2smp, genhf_noise, get_synthesized_spec_thin_out, getlag_gains,
    gettonl_scalfact, har_est, hf_parinitiz, noise_extr_corcod, noiseinj_hf,
    spectrumsmooth_noiseton, ton_ene_est, GainItemFx,
};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    BITS_LAGINDICES_MODE0_HAR_FX, BITS_LAGINDICES_MODENORMAL_FX, GAIN_TABLE_SWB_BWE_FX,
    SUBBAND_OFFSETS_SUB5_13P2KBPS_HAR_FX, SUBBAND_SEARCH_OFFSETS_13P2KBPS_HAR_FX,
};
use crate::itu::basic_ops::{add, extract_l, l_deposit_l, l_mult, l_shl, l_shr, mult_r, shl, sub};

const FRAME: usize = L_FRAME32K as usize;
const SUBBANDS: usize = NB_SWB_SUBBANDS as usize;

/// `DecodeSWBGenericParameters_fx`: the lowband (lag) index of each searched subband.
pub fn decode_swb_generic_parameters(
    st: &mut DecoderState,
    lag_indices: &mut [i16],
    n_bands_search: i16,
    bands: i16,
    p2a_flags: &[i16],
    hq_swb_clas: i16,
) {
    // lag index for each subband (except last two)
    for sb in 0..n_bands_search.max(0) as usize {
        if sub(hq_swb_clas, HQ_HARMONIC) == 0 {
            lag_indices[sb] = get_next_indice(st, BITS_LAGINDICES_MODE0_HAR_FX[sb]) as i16;
        } else if p2a_flags[(bands - NB_SWB_SUBBANDS) as usize + sb] == 0 {
            lag_indices[sb] = get_next_indice(st, BITS_LAGINDICES_MODENORMAL_FX[sb]) as i16;
        } else {
            lag_indices[sb] = 0;
        }
    }
}

/// `DecodeSWBSubbands_fx`: replicate the high band of `l_spectra` (Q`qs_l`) from its low band.
/// The reference's `prev_frm_hfe2` / `prev_stab_hfe2` pointers are the decoder state's own
/// fields, read and written here through `st`.
pub fn decode_swb_subbands(
    st: &mut DecoderState,
    l_spectra: &mut [i32],
    qs_l: i16,
    f_len_low: i16,
    f_len_high: i16,
    n_bands: i16,
    sb_width: &[i16],
    subband_offsets: &[i16],
    lag_indices: &[i16],
    lag_gains: &mut [i16],
    qlag_gains: &mut [i16],
    bands: i16,
    band_start: &[i16],
    band_end: &[i16],
    l_band_energy: &[i32],
    qbe: i16,
    p2a_flags: &[i16],
    hqswb_clas: i16,
    har_bands: i16,
    subband_search_offset: &[i16],
    band_width: &[i16],
    l_spectra_ni: &[i32],
    ni_seed: &mut i16,
) {
    let mut sspectra = [0i16; FRAME];
    let mut sspectra_ni = [0i16; FRAME];
    let mut sspectra_diff = [0i16; FRAME];
    let mut l_xsynth_har = [0i32; FRAME]; // Qs
    let mut qss: i16 = 0;

    if sub(hqswb_clas, HQ_HARMONIC) == 0 {
        decode_swb_subbands_harmonic(
            st,
            l_spectra,
            qs_l,
            f_len_low,
            f_len_high,
            sb_width,
            subband_offsets,
            lag_indices,
            bands,
            band_start,
            band_end,
            l_band_energy,
            qbe,
            p2a_flags,
            har_bands,
            subband_search_offset,
            band_width,
            l_spectra_ni,
            &mut SubbandScratch {
                sspectra: &mut sspectra,
                sspectra_ni: &mut sspectra_ni,
                sspectra_diff: &mut sspectra_diff,
                l_xsynth_har: &mut l_xsynth_har,
                qss: &mut qss,
            },
        );
    } else if sub(hqswb_clas, HQ_NORMAL) == 0 {
        let mut lag_indices_real = [0i16; SUBBANDS];
        let mut l_th_g = [0i32; SUBBANDS];
        let ss_min = spectrumsmooth_noiseton(
            l_spectra,
            l_spectra_ni,
            &mut sspectra,
            &mut sspectra_diff,
            &mut sspectra_ni,
            &mut qss,
            f_len_low,
            ni_seed,
        );

        convert_lag_indices_pls2smp(
            lag_indices,
            n_bands,
            &mut lag_indices_real,
            &sspectra,
            sb_width,
            f_len_low,
        );
        let high = (bands - NB_SWB_SUBBANDS) as usize;
        for k in 0..n_bands.max(0) as usize {
            if sub(p2a_flags[high + k], 1) == 0 {
                lag_indices_real[k] = 0;
            }
        }

        getlag_gains(
            &sspectra_ni,
            qss,
            &l_band_energy[high..],
            qbe,
            n_bands,
            sb_width,
            &lag_indices_real,
            f_len_low,
            lag_gains,
            qlag_gains,
        );

        for k in 0..n_bands.max(0) as usize {
            if sub(p2a_flags[high + k], 1) == 0 {
                lag_gains[k] = 0;
                qlag_gains[k] = 15;
            } else {
                lag_gains[k] = mult_r(lag_gains[k], 29491); // lagGains[k]*0.9f;
            }
        }

        for k in 0..SUBBANDS {
            l_th_g[k] = l_deposit_l(0);
            if p2a_flags[high + k] == 0 {
                // QlagGain+Qss -> Qs
                l_th_g[k] = l_shl(
                    l_mult(lag_gains[k], ss_min),
                    sub(qs_l, add(add(qlag_gains[k], qss), 1)),
                );
            }
        }

        // Construct spectrum
        get_synthesized_spec_thin_out(
            &sspectra_ni,
            qss,
            &mut l_xsynth_har,
            qs_l,
            n_bands,
            sb_width,
            &lag_indices_real,
            lag_gains,
            qlag_gains,
            f_len_low,
        );

        // Level adjustment for the missing bands
        noiseinj_hf(
            &mut l_xsynth_har,
            qs_l,
            &l_th_g,
            l_band_energy,
            qbe,
            &mut st.prev_en_sb,
            p2a_flags,
            bands,
            band_start,
            band_end,
            f_len_low,
            f_len_high,
        );

        for k in sub(bands, NB_SWB_SUBBANDS)..bands {
            let k = k as usize;
            for i in band_start[k]..=band_end[k] {
                let i = i as usize;
                if p2a_flags[k] == 0 {
                    l_spectra[i] = l_xsynth_har[i - f_len_low as usize]; // QsL
                } else {
                    l_spectra[i] = l_spectra_ni[i];
                }
            }
        }
    }
}

/// The stack buffers of [`decode_swb_subbands`] its harmonic branch works in.
struct SubbandScratch<'a> {
    sspectra: &'a mut [i16; FRAME],
    sspectra_ni: &'a mut [i16; FRAME],
    sspectra_diff: &'a mut [i16; FRAME],
    l_xsynth_har: &'a mut [i32; FRAME],
    qss: &'a mut i16,
}

/// The `HQ_HARMONIC` branch of [`decode_swb_subbands`].
fn decode_swb_subbands_harmonic(
    st: &mut DecoderState,
    l_spectra: &mut [i32],
    qs_l: i16,
    f_len_low: i16,
    f_len_high: i16,
    sb_width: &[i16],
    subband_offsets: &[i16],
    lag_indices: &[i16],
    bands: i16,
    band_start: &[i16],
    band_end: &[i16],
    l_band_energy: &[i32],
    qbe: i16,
    p2a_flags: &[i16],
    har_bands: i16,
    subband_search_offset: &[i16],
    band_width: &[i16],
    l_spectra_ni: &[i32],
    s: &mut SubbandScratch<'_>,
) {
    let mut l_be_tonal = [0i32; SWB_HAR_RAN1 as usize];
    let mut pk_sf = [GainItemFx::default(); N_NBIGGEST_SEARCH_LRG_B as usize];
    let mut pul_res = [0i16; SUBBANDS];
    let mut qbe_l: i16 = 0;

    let mut har_freq_est1: i16 = 0;
    let mut har_freq_est2: i16 = 0;
    let mut flag_dis: i16 = 1;

    let pos_max_hfe2 = har_est(
        l_spectra,
        f_len_low,
        &mut har_freq_est1,
        &mut har_freq_est2,
        &mut flag_dis,
        &mut st.prev_frm_hfe2,
        subband_search_offset,
        sb_width,
        &mut st.prev_stab_hfe2,
    );

    noise_extr_corcod(
        l_spectra,
        l_spectra_ni,
        &mut s.sspectra[..],
        &mut s.sspectra_diff[..],
        &mut s.sspectra_ni[..],
        f_len_low,
        st.prev_hqswb_clas,
        &mut st.prev_ni_ratio,
        s.qss,
    );

    if flag_dis == 0
        && (sub(har_freq_est2, SWB_HAR_RAN1) != 0 || sub(har_freq_est2, st.prev_frm_hfe2) != 0)
    {
        har_freq_est2 = add(har_freq_est2, lag_indices[0]);
    }

    // Generate HF noise
    genhf_noise(
        &s.sspectra_diff[..],
        *s.qss,
        &mut s.l_xsynth_har[..],
        qs_l,
        &s.sspectra[..],
        bands,
        har_bands,
        har_freq_est2,
        pos_max_hfe2,
        &mut pul_res,
        &mut pk_sf,
        f_len_low,
        f_len_high,
        sb_width,
        lag_indices,
        subband_offsets,
        subband_search_offset,
    );

    // a 2-bit index into the 4-entry gain table
    let imin = get_next_indice(st, 2) as usize;
    // g = pow(10.0f, gain_table_SWB_BWE[imin])
    let mut l_temp = l_mult(GAIN_TABLE_SWB_BWE_FX[imin], 27213); // Q14+Q13+1=Q28 log(10)/log(2)=3.3219 27213.23(Q13)
    l_temp = l_shr(l_temp, 12); // Q28-Q12 -> Q16
    let (temp_hi, temp_lo) = l_extract_lc(l_temp);
    let qg = sub(14, temp_hi);
    let mut g = extract_l(pow2(14, temp_lo));
    g = shl(g, sub(11, qg));

    // tonal energy estimation
    ton_ene_est(
        &mut s.l_xsynth_har[..],
        qs_l,
        &mut l_be_tonal,
        &mut qbe_l,
        l_band_energy,
        qbe,
        band_start,
        band_end,
        band_width,
        f_len_low,
        f_len_high,
        bands,
        har_bands,
        g,
        &pk_sf,
        *s.qss,
        &pul_res,
    );

    // HF Spectrum Generation
    gettonl_scalfact(
        &mut s.l_xsynth_har[..],
        qs_l,
        l_spectra_ni,
        f_len_low,
        f_len_high,
        har_bands,
        bands,
        l_band_energy,
        qbe,
        band_start,
        band_end,
        p2a_flags,
        &l_be_tonal,
        qbe_l,
        &pk_sf,
        *s.qss,
        &pul_res,
    );

    if flag_dis == 0 {
        st.prev_frm_hfe2 = 0;
    } else {
        st.prev_frm_hfe2 = har_freq_est2;
    }

    for k in har_bands..bands {
        let k = k as usize;
        for i in band_start[k]..=band_end[k] {
            let i = i as usize;
            l_spectra[i] = s.l_xsynth_har[i - f_len_low as usize]; // QsL
        }
    }
}

/// `swb_bwe_dec_lr_fx`: main decoding routine of the SWB BWE for the LR MDCT core. `l_m` gets
/// the high band synthesised from the low band of `l_m_core` (Q`qs_l`), with the low band zeroed.
/// The reference's `prev_frm_hfe2` / `prev_stab_hfe2` arguments are always the decoder state's
/// own fields, so they are reached through `st`.
pub fn swb_bwe_dec_lr(
    st: &mut DecoderState,
    l_m_core: &[i32],
    qs_l: i16,
    l_m: &mut [i32],
    l_total_brate: i32,
    bands: i16,
    band_start: &[i16],
    band_end: &[i16],
    l_band_energy: &[i32],
    qbe: i16,
    p2a_flags: &[i16],
    hqswb_clas: i16,
    lowlength: i16,
    highlength: i16,
    har_bands: i16,
    band_width: &[i16],
    l_y2_ni: &[i32],
    ni_seed: &mut i16,
) {
    let mut w_bands = [0i16; SUBBANDS];
    let mut lag_indices = [0i16; SUBBANDS];
    let mut lag_gains = [0i16; SUBBANDS];
    let mut qlag_gains = [0i16; SUBBANDS];
    let mut n_bands: i16 = 0;
    let mut n_bands_search: i16 = 0;
    let mut swb_lowband: i16 = 0;
    let mut swb_highband: i16 = 0;

    let mut subband_search_offset: &'static [i16] = &SUBBAND_SEARCH_OFFSETS_13P2KBPS_HAR_FX;
    let mut subband_offsets: &'static [i16] = &SUBBAND_OFFSETS_SUB5_13P2KBPS_HAR_FX;

    hf_parinitiz(
        l_total_brate,
        hqswb_clas,
        lowlength,
        highlength,
        &mut w_bands,
        &mut subband_search_offset,
        &mut subband_offsets,
        &mut n_bands,
        &mut n_bands_search,
        &mut swb_lowband,
        &mut swb_highband,
    );
    let allband = add(swb_lowband, swb_highband);

    // Decoding of the SWB parameters
    decode_swb_generic_parameters(
        st,
        &mut lag_indices,
        n_bands_search,
        bands,
        p2a_flags,
        hqswb_clas,
    );

    // Copy WB synthesis for SWB decoding
    let all = allband.max(0) as usize;
    l_m[..all].copy_from_slice(&l_m_core[..all]);

    // Generic subband processing
    decode_swb_subbands(
        st,
        l_m,
        qs_l,
        swb_lowband,
        swb_highband,
        n_bands,
        &w_bands,
        subband_offsets,
        &lag_indices,
        &mut lag_gains,
        &mut qlag_gains,
        bands,
        band_start,
        band_end,
        l_band_energy,
        qbe,
        p2a_flags,
        hqswb_clas,
        har_bands,
        subband_search_offset,
        band_width,
        l_y2_ni,
        ni_seed,
    );

    // taper the last four lines: 0.0625, 0.125, 0.25, 0.5 (Q15)
    let last = sub(allband, 1) as usize;
    l_m[last] = mult_32_16(l_m[last], 2028);
    l_m[last - 1] = mult_32_16(l_m[last - 1], 4096);
    l_m[last - 2] = mult_32_16(l_m[last - 2], 8192);
    l_m[last - 3] = mult_32_16(l_m[last - 3], 16384);

    // set low frequencies to zero
    l_m[..swb_lowband.max(0) as usize].fill(0);
}
