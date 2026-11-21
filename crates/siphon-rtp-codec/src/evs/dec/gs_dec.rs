//! The generic signal (GSC) decoder of the ACELP core: audio and inactive frames at the low
//! rates, an adaptive (pitch) contribution in the low band plus a PVQ-coded, noise-filled DCT
//! spectrum (TS 26.442 `lib_dec/gs_dec_fx.c`; TS 26.445 §6.1.1.3).

use crate::evs::cnst::{
    ACELP_13K20, ACELP_8K00, ACELP_9K60, ACELP_CORE, AUDIO, BAND1K2, CFREQ_BITRATE, GENERIC,
    INACTIVE, INACTIVE_CLAS, L_FRAME, L_FRAME8K, L_SUBFR, MBANDS_GN, NB, NB_SFM, NB_SUBFR,
    NB_SUBFR16K, NOISE_LEVEL_SP0, NOISE_LEVEL_SP2, NOISE_LEVEL_SP3, Q_PVQ_OUT, SWB, SWNB_SUBFR,
    UNVOICED,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::edct::{edct_16fx, edct_16fx_in_place};
use crate::evs::com::gs_bitallocation::bands_and_bit_alloc;
use crate::evs::com::gs_gains::gsc_gaindec;
use crate::evs::com::gs_noisefill::{freq_dnw_scaling, highband_exc_dct_in};
use crate::evs::com::gs_preech::pre_echo_att;
use crate::evs::com::swb_tbe_com::interp_code_5over2;
use crate::evs::com::tools::{copy, mean, minimum, random, scale_sig, set16};
use crate::evs::dec::dec_pit_exc::dec_pit_exc;
use crate::evs::dec::gain_dec::es_pred_dec;
use crate::evs::dec::pvq_core_dec::pvq_core_dec;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    GSC_SFM_END, GSC_SFM_SIZE, GSC_SFM_START, MFREQ_BINDIV_LOC, MFREQ_LOC_DIV_25, SM_TABLE_FX,
};
use crate::itu::basic_ops::{
    add, extract_l, l_mac, l_mult, l_shl, l_shr, l_sub, mult_r, round_word, shl, shr, sub,
};

const FRAME: usize = L_FRAME as usize;
const BANDS: usize = MBANDS_GN as usize;

/// `decod_audio_fx`: decode an AUDIO or INACTIVE (GSC) frame of the 12.8 kHz core. Reads the
/// attack, noisy-speech, noise-level, subframe-count and pitch-band fields, decodes the adaptive
/// (pitch) excitation of the low band, then the GSC spectrum (`gsc_dec`), and returns to the time
/// domain: `exc` receives the excitation without the noise fill, `exc2` the total excitation,
/// `bwe_exc` its 5/2 interpolation and `dct_epit` the total excitation's DCT.
///
/// `exc[exc_at..]` and `bwe_exc[bwe_exc_at..]` are where the reference's `exc` and `bwe_exc`
/// point (both carry history before the frame, which the pitch decoder reads). `pitch_buf` and
/// `gain_buf` receive one value per 64-sample subframe, `voice_factors` is zeroed.
pub fn decod_audio(
    st: &mut DecoderState,
    dct_epit: &mut [i16],
    aq: &[i16],
    coder_type: i16,
    pitch_buf: &mut [i16],
    voice_factors: &mut [i16],
    exc: &mut [i16],
    exc_at: usize,
    exc2: &mut [i16],
    bwe_exc: &mut [i16],
    bwe_exc_at: usize,
    lsf_new: &[i16],
    gain_buf: &mut [i16],
) {
    let mut code = [0i16; L_SUBFR as usize];
    let mut last_bin: i16 = 0;
    let mut exc_wo_nf = [0i16; FRAME];

    // decode GSC attack flag (used to reduce possible pre-echo)
    let gsc_attack_flag = get_next_indice(st, 1) as i16;

    // decode GSC SWB speech flag
    if sub(coder_type, INACTIVE) != 0 && l_sub(st.total_brate, i32::from(ACELP_13K20)) >= 0 {
        st.gsc_noisy_speech = get_next_indice(st, 1) as i16;
    }

    // safety check in case of bit errors
    if st.gsc_noisy_speech != 0 && sub(st.bwidth, SWB) != 0 {
        st.ber_detect = 1;
        st.gsc_noisy_speech = 0;
    }

    let nb_subfr = decod_audio_energy_dynamics(st);
    let (mut pit_band_idx, mut diff_len) = decod_audio_pit_band(st, coder_type);

    // Decode adaptive (pitch) excitation contribution; reset unvaluable part of it
    if sub(pit_band_idx, BAND1K2) > 0 {
        (pit_band_idx, diff_len) = decod_audio_pitch_contribution(
            st,
            dct_epit,
            aq,
            coder_type,
            pitch_buf,
            &mut code,
            exc,
            exc_at,
            bwe_exc,
            bwe_exc_at,
            nb_subfr,
            gain_buf,
            pit_band_idx,
            diff_len,
        );
    } else {
        // No adaptive (pitch) excitation contribution
        st.bpf_off = 1;
        set16(dct_epit, 0, L_FRAME);
        set16(pitch_buf, shl(L_SUBFR, 6), NB_SUBFR);
        set16(gain_buf, 0, NB_SUBFR16K);
        st.bfi_pitch = shl(L_SUBFR, 6);
        st.bfi_pitch_frame = L_FRAME;
        st.lp_gainp = 0;
        st.lp_gainc = 0;
        st.tilt_code = 0;
        pit_band_idx = 0;
        diff_len = 0;
    }

    // GSC decoder: find the current total number of bits used
    let mut tmp_nb_bits_tot = st.next_bit_pos;
    if st.extl_brate > 0 {
        // subtract 1 bit for TBE/BWE BWE flag (bit counted in extl_brate)
        tmp_nb_bits_tot = sub(tmp_nb_bits_tot, 1);
    }
    if sub(coder_type, INACTIVE) == 0 && l_sub(st.core_brate, i32::from(ACELP_9K60)) <= 0 {
        tmp_nb_bits_tot = add(tmp_nb_bits_tot, 5);
    }

    let q_exc = st.q_exc;
    gsc_dec(
        st,
        dct_epit,
        pit_band_idx,
        diff_len,
        tmp_nb_bits_tot,
        nb_subfr,
        coder_type,
        &mut last_bin,
        lsf_new,
        Some(&mut exc_wo_nf),
        q_exc,
    );

    // iDCT transform
    edct_16fx(dct_epit, &mut exc[exc_at..], L_FRAME, 7);
    edct_16fx_in_place(&mut exc_wo_nf, L_FRAME, 7);

    // Remove potential pre-echo in case an onset has been detected
    pre_echo_att(
        &mut st.last_frame_ener,
        &mut exc[exc_at..],
        gsc_attack_flag,
        st.q_exc,
        st.last_coder_type,
    );

    // Update BWE excitation
    set16(voice_factors, 0, NB_SUBFR16K);
    interp_code_5over2(&exc[exc_at..], &mut bwe_exc[bwe_exc_at..], L_FRAME);

    // Updates
    copy(&exc[exc_at..], exc2, L_FRAME);
    copy(&exc_wo_nf, &mut exc[exc_at..], L_FRAME);

    // Channel aware mode parameters
    set16(&mut st.tilt_code_dec, 0, NB_SUBFR16K);
}

/// `decod_audio_fx`, the energy dynamics: the noise level, `cor_strong_limit` and the number of
/// subframes of the pitch contribution (returned).
fn decod_audio_energy_dynamics(st: &mut DecoderState) -> i16 {
    if sub(st.gsc_noisy_speech, 1) == 0 {
        st.cor_strong_limit = 0;
        st.noise_lev = NOISE_LEVEL_SP3;
        return NB_SUBFR;
    }
    if l_sub(st.core_brate, i32::from(ACELP_8K00)) <= 0 {
        st.noise_lev = add(get_next_indice(st, 2) as i16, NOISE_LEVEL_SP2);
    } else {
        st.noise_lev = add(get_next_indice(st, 3) as i16, NOISE_LEVEL_SP0);
    }

    // Decode number of subframes
    st.cor_strong_limit = 1;
    let mut nb_subfr = SWNB_SUBFR;
    if l_sub(st.core_brate, i32::from(ACELP_9K60)) >= 0 {
        let nb_frame_flg = get_next_indice(st, 1) as i16;
        if (nb_frame_flg & 0x1) == 0 {
            nb_subfr = 2 * SWNB_SUBFR;
            st.cor_strong_limit = 0;
        }
    }
    nb_subfr
}

/// `decod_audio_fx`, the last band where the adaptive (pitch) contribution is significant:
/// returns `(pit_band_idx, Diff_len)` and records the band in `Last_GSC_pit_band_idx`.
fn decod_audio_pit_band(st: &mut DecoderState, coder_type: i16) -> (i16, i16) {
    let mut diff_len: i16 = 0;
    let mut nbits: i16;
    if l_sub(st.core_brate, i32::from(CFREQ_BITRATE)) < 0 {
        nbits = 3;
        if l_sub(st.core_brate, i32::from(ACELP_9K60)) < 0 && sub(coder_type, INACTIVE) == 0 {
            nbits = 1;
        }
    } else {
        nbits = 4;
    }
    let mut pit_band_idx =
        if l_sub(st.core_brate, i32::from(ACELP_9K60)) < 0 && sub(coder_type, INACTIVE) != 0 {
            1
        } else {
            get_next_indice(st, nbits) as i16
        };

    if pit_band_idx != 0 {
        if l_sub(st.core_brate, i32::from(ACELP_9K60)) < 0 {
            // At low rate, if pitch model is chosen, then for to be use on extented and constant
            // frequency range
            pit_band_idx = 7 + BAND1K2;
        } else {
            pit_band_idx = add(pit_band_idx, BAND1K2);
        }

        // detect bit errors in the bitstream
        if sub(pit_band_idx, 13) > 0 {
            // The maximum decodable index is 10 + BAND1k2 (3) = 13
            pit_band_idx = 13;
            st.ber_detect = 1;
        }
        diff_len = MFREQ_LOC_DIV_25[pit_band_idx as usize];
    }
    st.last_gsc_pit_band_idx = pit_band_idx;
    (pit_band_idx, diff_len)
}

/// `decod_audio_fx`, the adaptive (pitch) contribution: decode it, take its DCT into `dct_epit`
/// and keep only the band below `Diff_len` (smoothed into the next 80 bins). Returns the updated
/// `(pit_band_idx, Diff_len)`.
fn decod_audio_pitch_contribution(
    st: &mut DecoderState,
    dct_epit: &mut [i16],
    aq: &[i16],
    coder_type: i16,
    pitch_buf: &mut [i16],
    code: &mut [i16],
    exc: &mut [i16],
    exc_at: usize,
    bwe_exc: &mut [i16],
    bwe_exc_at: usize,
    nb_subfr: i16,
    gain_buf: &mut [i16],
    mut pit_band_idx: i16,
    mut diff_len: i16,
) -> (i16, i16) {
    let mut es_pred: i16 = 0;
    if sub(st.gsc_noisy_speech, 1) == 0 && sub(nb_subfr, NB_SUBFR) == 0 {
        let core_brate = st.core_brate;
        es_pred = es_pred_dec(st, GENERIC, core_brate);
    }

    dec_pit_exc(
        st, aq, coder_type, es_pred, pitch_buf, code, exc, exc_at, bwe_exc, bwe_exc_at, nb_subfr,
        gain_buf,
    );

    if l_sub(st.core_brate, i32::from(ACELP_9K60)) < 0 {
        let mut low_pit: i16 = 0;
        minimum(pitch_buf, shr(L_FRAME, 6), &mut low_pit);
        low_pit = shr(low_pit, 6); // Q6 -> Q0

        if sub(low_pit, 64) < 0 {
            pit_band_idx = 9 + BAND1K2;
            if sub(st.bwidth, NB) == 0 {
                pit_band_idx = 7 + BAND1K2;
            }
        } else if sub(low_pit, 128) < 0 {
            pit_band_idx = 5 + BAND1K2;
        } else {
            pit_band_idx = 3 + BAND1K2;
        }

        diff_len = MFREQ_LOC_DIV_25[pit_band_idx as usize];
        st.last_gsc_pit_band_idx = pit_band_idx;
    }

    // DCT transform
    edct_16fx(&exc[exc_at..], dct_epit, L_FRAME, 7);

    // Reset unvaluable part of the adaptive (pitch) excitation contribution
    let mut max_len = sub(L_FRAME, diff_len);
    if sub(st.bwidth, NB) == 0 {
        max_len = sub(160, diff_len);
    }
    let len = if max_len < 80 { max_len } else { 80 };

    let diff = diff_len as usize;
    if l_sub(st.core_brate, i32::from(ACELP_8K00)) == 0 && sub(st.bwidth, NB) != 0 {
        for i in 0..max_len.max(0) as usize {
            dct_epit[i + diff] = 0;
        }
    } else {
        let len = len.max(0) as usize;
        for i in 0..len {
            dct_epit[i + diff] = mult_r(dct_epit[i + diff], SM_TABLE_FX[i]);
        }
        for i in len..max_len.max(0) as usize {
            dct_epit[i + diff] = 0;
        }
    }
    st.bfi_pitch = mean(pitch_buf, nb_subfr);
    st.bfi_pitch_frame = L_FRAME;

    diff_len = add(diff_len, 1);
    st.bpf_off = 0;
    (pit_band_idx, diff_len)
}

/// `gsc_dec_fx`: decode the GSC spectrum (band gains, then the PVQ-coded bands, or on a lost /
/// corrupted frame the previous spectrum) and noise-fill it into `exc_dct_in` (Q`q_exc`), which
/// holds the DCT of the pitch-only excitation on entry and the total excitation on return.
/// `exc_wo_nf`, when given, receives the same without the noise fill (the FEC caller passes
/// none). `last_bin` receives the last band of the bit allocation.
pub fn gsc_dec(
    st: &mut DecoderState,
    exc_dct_in: &mut [i16],
    pit_band_idx: i16,
    diff_len: i16,
    bits_used: i16,
    nb_subfr: i16,
    coder_type: i16,
    last_bin: &mut i16,
    lsf_new: &[i16],
    exc_wo_nf: Option<&mut [i16]>,
    q_exc: i16,
) {
    let mut bitallocation_band = [0i16; BANDS];
    // The reference leaves it uninitialised outside 8 kbit/s non-NB; it is only read there.
    let mut bitallocation_exc = [0i16; 2];
    let mut ener_per_bd_i_q = [0i16; BANDS];
    let mut exc_diff_q = [0i16; FRAME];
    let mbands_gn: i16 = 16;
    let qexc_diff_q = Q_PVQ_OUT;

    // Gain decoding
    if st.bfi != 0 || st.ber_detect != 0 {
        // copy old gain
        copy(&st.old_y_gain, &mut ener_per_bd_i_q, mbands_gn);
        let mean_gain = mult_r(st.lp_gainc, 3277); // Q3
        for value in ener_per_bd_i_q.iter_mut().take(mbands_gn as usize) {
            *value = add(*value, shl(mean_gain, 9)); // Q12
        }
        st.lp_gainc = mult_r(st.lp_gainc, 32112); // Q3
    } else {
        let (core_brate, bwidth) = (st.core_brate, st.bwidth);
        let mut old_y_gain = st.old_y_gain;
        let mean_gain = gsc_gaindec(
            st,
            &mut ener_per_bd_i_q,
            core_brate,
            &mut old_y_gain,
            coder_type,
            bwidth,
        );
        st.old_y_gain = old_y_gain;
        st.lp_gainc = mult_r(640, mean_gain); // 10 in Q6 x Q12 -> lp_gainc in Q3
    }

    *last_bin = 0;
    if l_sub(st.core_brate, i32::from(ACELP_8K00)) == 0 && sub(st.bwidth, NB) != 0 {
        bitallocation_exc = [0, 0];
    }
    set16(&mut bitallocation_band, 0, MBANDS_GN);

    if sub(st.bfi, 1) == 0 || st.ber_detect != 0 {
        // Copy old spectrum, reduce spectral dynamic, save spectrum
        if sub(st.last_good, INACTIVE_CLAS) == 0 || sub(st.last_gsc_noisy_speech_flag, 1) == 0 {
            for i in 0..FRAME {
                let mut l_tmp = l_shr(l_mult(random(&mut st.seed_tcx), 26214), 5); // Q10
                l_tmp = l_mac(l_tmp, st.last_gsc_spectrum[i], 6554);
                st.last_gsc_spectrum[i] = round_word(l_tmp); // Q10
            }
        }
        copy(&st.last_gsc_spectrum, &mut exc_diff_q, L_FRAME);
        for value in st.last_gsc_spectrum.iter_mut() {
            *value = mult_r(*value, 24576); // Q10
        }
    } else {
        gsc_dec_pvq(
            st,
            diff_len,
            bits_used,
            coder_type,
            &ener_per_bd_i_q,
            last_bin,
            &mut bitallocation_band,
            &mut bitallocation_exc,
            &mut exc_diff_q,
            qexc_diff_q,
        );
    }

    // Estimate noise level
    let (core_brate, noise_lev, last_coder_type, bfi, bwidth, gsc_noisy_speech) = (
        st.core_brate,
        st.noise_lev,
        st.last_coder_type,
        st.bfi,
        st.bwidth,
        st.gsc_noisy_speech,
    );
    highband_exc_dct_in(
        core_brate,
        &MFREQ_BINDIV_LOC,
        *last_bin,
        diff_len,
        noise_lev,
        pit_band_idx,
        &mut exc_diff_q,
        &mut st.seed_tcx,
        &mut ener_per_bd_i_q,
        nb_subfr,
        exc_dct_in,
        last_coder_type,
        &bitallocation_band,
        lsf_new,
        &mut st.last_exc_dct_in,
        &mut st.last_ener,
        &mut st.last_bitallocation_band,
        &bitallocation_exc,
        bfi,
        coder_type,
        bwidth,
        exc_wo_nf,
        qexc_diff_q,
        q_exc,
        gsc_noisy_speech,
        &mut st.lt_ener_per_band,
    );

    exc_dct_in[0] = 0;
}

/// `gsc_dec_fx`, the PVQ decoder of a good frame: allocate the bits over the bands, decode them,
/// reorder them into `exc_diff_q` (Q`qexc_diff_q`), seed the noise fill on a first audio frame,
/// save the spectrum and scale down the band above the pitch contribution.
fn gsc_dec_pvq(
    st: &mut DecoderState,
    diff_len: i16,
    bits_used: i16,
    coder_type: i16,
    ener_per_bd_i_q: &[i16],
    last_bin: &mut i16,
    bitallocation_band: &mut [i16; BANDS],
    bitallocation_exc: &mut [i16; 2],
    exc_diff_q: &mut [i16; FRAME],
    qexc_diff_q: i16,
) {
    let mut max_ener_band = [0i16; BANDS];
    let mut bits_per_bands = [0i16; BANDS];
    let mut concat_out = [0i16; FRAME];
    let mut inpulses_fx = [0i16; NB_SFM as usize];
    let mut imaxpulse_fx = [0i16; NB_SFM as usize];
    let mut q_tmp: i16 = 0;
    let mut bit = bits_used;

    let allocation = bands_and_bit_alloc(
        st.cor_strong_limit,
        st.noise_lev,
        st.core_brate,
        diff_len,
        bit,
        &mut bit,
        ener_per_bd_i_q,
        &mut max_ener_band,
        &mut bits_per_bands,
        None,
        coder_type,
        st.bwidth,
        st.gsc_noisy_speech,
    );
    // At most MBANDS_GN bands; the allocation never codes none (and the reference would read
    // gsc_sfm_end[-1] if it did).
    let nb_subbands = allocation.nb_subbands.clamp(0, MBANDS_GN);

    pvq_core_dec(
        st,
        &GSC_SFM_START,
        &GSC_SFM_END,
        &GSC_SFM_SIZE,
        &mut concat_out,
        &mut q_tmp,
        bit,
        nb_subbands,
        &mut bits_per_bands,
        None,
        &mut inpulses_fx,
        &mut imaxpulse_fx,
        ACELP_CORE,
    );
    if nb_subbands > 0 {
        scale_sig(
            &mut concat_out,
            GSC_SFM_END[nb_subbands as usize - 1],
            sub(Q_PVQ_OUT, q_tmp),
        );
    }

    let mut seed_init: i16 = 0;

    // Reorder Q bands
    for j in 0..nb_subbands as usize {
        // max_ener_band holds band indices 0..MBANDS_GN
        let band = (max_ener_band[j].clamp(0, MBANDS_GN - 1)) as usize;
        exc_diff_q[band * 16..band * 16 + 16].copy_from_slice(&concat_out[j * 16..j * 16 + 16]);
        *last_bin = (*last_bin).max(max_ener_band[j]);
        bitallocation_band[band] = 1;
        seed_init = add(seed_init, inpulses_fx[j]);
    }
    // First audio frame; last_coder_type == INACTIVE is overwritten in update_dec to UNVOICED
    if sub(st.last_coder_type, AUDIO) != 0 && sub(st.last_coder_type, UNVOICED) != 0 {
        for &value in concat_out.iter().take(shl(nb_subbands, 4) as usize) {
            if value > 0 {
                seed_init = extract_l(l_shl(i32::from(seed_init), 3));
            }
            if value < 0 {
                seed_init = add(seed_init, 3);
            }
        }
        st.seed_tcx = seed_init;
    }
    if l_sub(st.core_brate, i32::from(ACELP_8K00)) == 0 && sub(st.bwidth, NB) != 0 {
        if exc_diff_q[L_FRAME8K as usize - 2] != 0 {
            bitallocation_exc[0] = 1;
        }
        if exc_diff_q[L_FRAME8K as usize - 1] != 0 {
            bitallocation_exc[1] = 1;
        }
    }

    copy(exc_diff_q, &mut st.last_gsc_spectrum, L_FRAME);

    // Skip adaptive (pitch) contribution frequency band (no noise added over the time
    // contribution); find x pulses between 1.6-3.2kHz to code in the spectrum of the residual
    // signal; gain is based on the inter-correlation gain between the pulses found and residual
    // signal
    freq_dnw_scaling(
        st.cor_strong_limit,
        coder_type,
        st.noise_lev,
        st.core_brate,
        exc_diff_q,
        qexc_diff_q,
    );
}
