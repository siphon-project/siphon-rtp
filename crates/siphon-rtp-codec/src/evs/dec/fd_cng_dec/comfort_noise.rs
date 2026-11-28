//! The comfort noise and the masking noise of `lib_dec/fd_cng_dec.c`: `generateComfortNoise_dec`
//! (its LP-energy, TCX and ACELP overlap-add and CLDFB high-band parts) and `generate_masking_noise`
//! with its seed update and MDCT variant.

use super::{take_fd_cng, CldfbBuffers};
use crate::evs::basop::{mpy_32_16_1, mpy_32_32, mult_32_16};
use crate::evs::cnst::{
    ACELP_CORE, ACTIVE_FRAME, ALDO_WINDOW, AMR_WB_CORE, CLDFBINVSCALINGFACTOR_EXP, CLDFB_SCALING,
    CNG_NORM_RECIPROCAL_RANGE_SHIFT, CNG_RAND_GAUSS_SHIFT, FULL_OVERLAP, LD_DATA_SCALE,
    L_EXC_MEM_DEC, L_FRAME16K, M, MODE1, MODE2, NB, NOISE_HEADROOM, N_ZERO_MDCT_NS,
    TCX_IMDCT_HEADROOM, WB, WORD32_BITS,
};
use crate::evs::com::basop_util::{
    basop_util_log2, basop_util_norm_s_bands2shift, basop_util_pow2, dot_product_sq16_hq,
    get_norm_reciprocal_word16, isqrt32, sqrt32,
};
use crate::evs::com::cldfb::CLDFB_ROW;
use crate::evs::com::deemph::e_util_deemph2;
use crate::evs::com::fd_cng_com::{rand_gauss, synthesis_stft, StftOverlap, StftSpectrum};
use crate::evs::com::syn_filt::e_util_synthesis_in_place;
use crate::evs::com::tcx_utils::{
    tcx_windowing_synthesis_current_frame, tcx_windowing_synthesis_past_frame,
};
use crate::evs::dec::state::{DecoderState, FdCngCom};
use crate::evs::macros::ns2sa;
use crate::evs::rom::{ENR_ATT_FX, SCALETABLE_CN_ONLY, SCALETABLE_CN_ONLY_AMRWBIO};
use crate::itu::basic_ops::{
    abs_s, add, extract_h, l_abs, l_add, l_deposit_l, l_mult, l_negate, l_shl, l_shr, l_sub, mult,
    mult_r, negate, norm_s, shl, shr, shr_r, sub,
};

/// Gaussian noise of level `sqrt(level >> sn)` into a CLDFB band `j` over `num_slots` slots, real
/// then imaginary per slot (the seed order of the reference).
fn cldfb_band_noise(
    cldfb: &mut CldfbBuffers<'_>,
    j: usize,
    num_slots: i16,
    level: i32,
    scale_cldfb: i16,
    sn: i16,
    seed: &mut i16,
) {
    let mut s: i16 = 0;
    let sqrt_noise_level = sqrt32(l_shr(mpy_32_16_1(level, scale_cldfb), sn), &mut s);
    let slots = (num_slots.max(0) as usize)
        .min(cldfb.real.len())
        .min(cldfb.imag.len());
    for i in 0..slots {
        // Real part in CLDFB band
        cldfb.real[i][j] = l_shl(mpy_32_32(rand_gauss(seed), sqrt_noise_level), s);
        // Imaginary part in CLDFB band
        cldfb.imag[i][j] = l_shl(mpy_32_32(rand_gauss(seed), sqrt_noise_level), s);
    }
}

/// `generate_comfort_noise_dec`: one frame of comfort noise: Gaussian noise shaped by
/// `cngNoiseLevel` in the FFT bins, STFT synthesis into `timeDomainBuffer` (with the CNG
/// excitation for LP-CNG, `gen_exc`), the LP-CNG excitation energy `lp_ener` update, noise in the
/// CLDFB bands above the core, and in MODE2 the overlap-add with the last active frame.
///
/// The reference passes `Q_new` = `&stdec->Q_exc` at both call sites; here it is that field.
/// The FD-CNG state is `stdec.h_fd_cng_dec`.
pub fn generate_comfort_noise_dec(
    cldfb: Option<CldfbBuffers<'_>>,
    stdec: &mut DecoderState,
    gen_exc: i16,
) {
    let Some(mut std) = take_fd_cng(stdec) else {
        return;
    };
    if let Some(st) = std.h_fd_cng_com.as_deref_mut() {
        generate_comfort_noise_dec_on(cldfb, st, stdec, gen_exc);
    }
    stdec.h_fd_cng_dec = Some(std);
}

/// [`generate_comfort_noise_dec`] on the common state moved out of `stdec`.
fn generate_comfort_noise_dec_on(
    cldfb: Option<CldfbBuffers<'_>>,
    st: &mut FdCngCom,
    stdec: &mut DecoderState,
    gen_exc: i16,
) {
    let mut cng_noise_level_exp = st.cng_noise_level_exp;
    let mut level: usize = 0;

    // scaleCLDFB: CLDFBinvScalingFactor_EXP + 1
    let scale_cldfb = mult(st.inv_scaling_factor, CLDFB_SCALING);

    // Generate Gaussian random noise in real and imaginary parts of the FFT bins; amplitudes are
    // adjusted to the estimated noise level cngNoiseLevel in each bin; format Q3.29
    let mut sn: i16 = 0;
    if cng_noise_level_exp & 1 != 0 {
        sn = add(sn, 1);
        cng_noise_level_exp = add(cng_noise_level_exp, sn);
    }

    let rand_gauss_exp = CNG_RAND_GAUSS_SHIFT;
    let mut cnt = sub(st.stop_ff_tbin, st.start_band);
    let mut ptr_r: usize;
    if st.start_band == 0 {
        // DC component in FFT
        let mut s: i16 = 0;
        let sqrt_noise_level = sqrt32(l_shr(st.cng_noise_level[level], sn), &mut s);
        st.fft_buffer[0] = l_shl(mpy_32_32(rand_gauss(&mut st.seed), sqrt_noise_level), s);
        // Nyquist frequency is discarded
        st.fft_buffer[1] = l_deposit_l(0);
        level += 1;
        ptr_r = 2;
        cnt = sub(cnt, 1);
    } else {
        let start_band2 = shl(st.start_band, 1).max(0) as usize;
        st.fft_buffer[..start_band2].fill(0);
        ptr_r = start_band2;
    }

    sn = add(sn, 1);
    for _ in 0..cnt.max(0) {
        let mut s: i16 = 0;
        let sqrt_noise_level = sqrt32(l_shr(st.cng_noise_level[level], sn), &mut s);
        // Real part in FFT bins
        st.fft_buffer[ptr_r] = l_shl(mpy_32_32(rand_gauss(&mut st.seed), sqrt_noise_level), s);
        // Imaginary part in FFT bins
        st.fft_buffer[ptr_r + 1] = l_shl(mpy_32_32(rand_gauss(&mut st.seed), sqrt_noise_level), s);
        ptr_r += 2;
        level += 1;
    }

    // Remaining FFT bins are set to zero
    let stop_ff_tbin2 = shl(st.stop_ff_tbin, 1).max(0) as usize;
    let fl = (st.fftlen.max(0) as usize).min(st.fft_buffer.len());
    if stop_ff_tbin2 < fl {
        st.fft_buffer[stop_ff_tbin2..fl].fill(0);
    }

    let fft_buffer_exp = add(shr(cng_noise_level_exp, 1), rand_gauss_exp);

    // If previous frame is active, reset the overlap-add buffer
    let mut tcx_transition: i16 = 0;
    if st.frame_type_previous == ACTIVE_FRAME {
        st.olap_buffer_synth[..fl].fill(0);
        if (stdec.last_core_bfi > ACELP_CORE && stdec.codec_mode == MODE2)
            || stdec.codec_mode == MODE1
        {
            tcx_transition = 1;
        }
    }

    // Perform STFT synthesis (into timeDomainBuffer, through a copy: the synthesis reads the
    // state the buffer lives in)
    let mut time_domain_output = st.time_domain_buffer;
    let olap_win_syn = st.olap_win_syn;
    synthesis_stft(
        StftSpectrum::Common,
        fft_buffer_exp,
        &mut time_domain_output,
        StftOverlap::Common,
        olap_win_syn,
        tcx_transition,
        st,
        gen_exc,
        &mut stdec.q_exc,
    );
    st.time_domain_buffer = time_domain_output;

    generate_comfort_noise_dec_lp_ener(st, stdec);

    // Generate Gaussian random noise in real and imaginary parts of the CLDFB bands; amplitudes
    // are adjusted to the estimated noise level cngNoiseLevel in each band
    if let Some(mut cldfb) = cldfb {
        if sub(st.num_core_bands, st.regular_stop_band) < 0 {
            sn = sub(sn, 1);
            let sc = add(
                shr(
                    add(cng_noise_level_exp, CLDFBINVSCALINGFACTOR_EXP + 1 - 1),
                    1,
                ),
                rand_gauss_exp,
            );
            let from = st.num_core_bands.max(0) as usize;
            let to = (st.regular_stop_band.max(0) as usize).min(CLDFB_ROW);
            for j in from..to {
                // scaleCLDFB: CLDFBinvScalingFactor_EXP + 1
                cldfb_band_noise(
                    &mut cldfb,
                    j,
                    st.num_slots,
                    st.cng_noise_level[level],
                    scale_cldfb,
                    sn,
                    &mut st.seed,
                );
                level += 1;
            }
            if let Some(scale) = cldfb.scale {
                *scale = sub(sc, 15);
            }
        }
    }

    // Overlap-add when previous frame is active
    if st.frame_type_previous == ACTIVE_FRAME && stdec.codec_mode == MODE2 {
        if stdec.last_core_bfi > ACELP_CORE {
            generate_comfort_noise_dec_tcx_ola(st, stdec);
        } else {
            generate_comfort_noise_dec_acelp_ola(st, stdec);
        }
    }
}

/// The LP-CNG excitation energy update of `generate_comfort_noise_dec`:
/// `lp_ener = 0.8·lp_ener + 0.2·2^(log2(energy of exc_cng) - attenuation)`.
fn generate_comfort_noise_dec_lp_ener(st: &FdCngCom, stdec: &mut DecoderState) {
    // calculate the residual signal energy: enr = dotp(exc_cng, exc_cng, frameSize) / frameSize
    let mut exp: i16 = 0;
    let mut lener = dot_product_sq16_hq(1, &st.exc_cng, stdec.l_frame, &mut exp, &mut stdec.stl);
    exp = add(sub(shl(sub(15, stdec.q_exc), 1), 8), exp); // 8 = log2(256)

    // convert log2 of residual signal energy: (float)log10( enr + 0.1f ) / (float)log10( 2.0f )
    lener = basop_util_log2(lener);
    lener = l_add(
        lener,
        l_shl(l_deposit_l(exp), WORD32_BITS - 1 - LD_DATA_SCALE),
    ); // Q25
    if stdec.l_frame == L_FRAME16K {
        lener = l_sub(lener, 10_802_114); // log2(320) = 8.3219280949f, 0.3219280949f Q25
    }
    // decrease the energy in case of WB input
    if sub(stdec.bwidth, NB) != 0 {
        let att = if sub(stdec.bwidth, WB) == 0 {
            if stdec.cng_mode >= 0 {
                // Bitrate adapted attenuation
                let index = (stdec.cng_mode as usize).min(ENR_ATT_FX.len() - 1);
                l_shl(l_deposit_l(ENR_ATT_FX[index]), 17)
            } else {
                // Use least attenuation for higher bitrates
                l_shl(l_deposit_l(ENR_ATT_FX[4]), 17)
            }
        } else {
            384 << 17 // 1.5 Q8<<17=Q25
        };
        lener = l_sub(lener, att);
    }
    // lp_ener = 0.8f * lp_ener + 0.2f * pow( 2.0f, enr )
    lener = basop_util_pow2(lener, 6, &mut exp);
    lener = mult_32_16(lener, 6554); // 0.2f Q15
    exp = sub(25, exp);
    lener = l_shr(lener, exp); // Q6
    stdec.lp_ener = l_add(mult_32_16(stdec.lp_ener, 26214), lener); // 0.8f Q15, Q6
}

/// MODE2 transition from an active TCX frame: the TCX overlap windows over `timeDomainBuffer`
/// and the past frame's overlap added.
fn generate_comfort_noise_dec_tcx_ola(st: &mut FdCngCom, stdec: &mut DecoderState) {
    let n = st.frame_size;
    let cfg = &stdec.tcx_cfg;
    let mut left_overlap_mode = cfg.tcx_last_overlap_mode;
    if sub(left_overlap_mode, ALDO_WINDOW) == 0 {
        left_overlap_mode = FULL_OVERLAP;
    }

    tcx_windowing_synthesis_current_frame(
        &mut st.time_domain_buffer,
        cfg.tcx_mdct_window, // Keep sine windows for limiting Time modulation
        cfg.tcx_mdct_window_half,
        cfg.tcx_mdct_window_minimum,
        cfg.tcx_mdct_window_length,
        cfg.tcx_mdct_window_half_length,
        cfg.tcx_mdct_window_min_length,
        0,
        left_overlap_mode,
        None,
        &[],
        n / 2,
        // equivalent to: tcx_offset<0?-tcx_offset:0
        shr(sub(abs_s(cfg.tcx_offset), cfg.tcx_offset), 1),
        1,
        0,
        0,
    );

    if cfg.last_aldo != 0 {
        let zero = ns2sa(stdec.sr_core, N_ZERO_MDCT_NS);
        for i in 0..sub(st.frame_size, zero).max(0) as usize {
            st.time_domain_buffer[i] = add(
                st.time_domain_buffer[i],
                shr_r(stdec.old_out_lb[i + zero as usize], stdec.q_old_wtda_lb),
            );
        }
    } else {
        let cfg = &stdec.tcx_cfg;
        tcx_windowing_synthesis_past_frame(
            &mut stdec.syn_overl,
            cfg.tcx_mdct_window,
            cfg.tcx_mdct_window_half,
            cfg.tcx_mdct_window_minimum,
            cfg.tcx_mdct_window_length,
            cfg.tcx_mdct_window_half_length,
            cfg.tcx_mdct_window_min_length,
            cfg.tcx_last_overlap_mode,
        );

        for i in 0..stdec.tcx_cfg.tcx_mdct_window_length.max(0) as usize {
            // a plain C `+=`: the 16-bit store wraps
            st.time_domain_buffer[i] =
                st.time_domain_buffer[i].wrapping_add(shl(stdec.syn_overl[i], TCX_IMDCT_HEADROOM));
        }
    }
}

/// MODE2 transition from an active ACELP frame: random noise at the energy of the last half
/// frame's excitation, through the last LP synthesis filter and de-emphasis, faded in over the
/// overlap of `timeDomainBuffer`.
fn generate_comfort_noise_dec_acelp_ola(st: &mut FdCngCom, stdec: &DecoderState) {
    // the scaling of the LPCs (old_Aq) is Q12; of the deemphasized signals (old_syn) Q0; of the
    // excitation in the decoder Q_exc; of the preemphasized signals Q_syn
    let mut noise = [0i16; 640];
    let mut old_syn_pe_tmp = [0i16; 16];
    let mut seed_loc = st.seed;
    let n = st.frame_size;
    let n2 = shr(st.frame_size, 1);
    let nu = (n.max(0) as usize).min(noise.len());

    let lpcorder = M;
    let old_aq = &stdec.old_aq_12_8;
    let old_exc_at = sub(L_EXC_MEM_DEC, n2).max(0) as usize;
    let old_exc = &stdec.old_exc[old_exc_at..];
    let old_syn_pe = &stdec.mem_syn2;
    let old_syn = stdec.syn[lpcorder as usize];
    let preemph_fac = stdec.preemph_fac;
    let q_exc = stdec.q_exc;
    let q_syn = stdec.q_syn;

    // shift to be in the range of values supported by getNormReciprocalWord16()
    let n8 = shr(n2, CNG_NORM_RECIPROCAL_RANGE_SHIFT);

    let norm_fac_e = get_norm_reciprocal_word16(n8);
    let norm_shift_e = basop_util_norm_s_bands2shift(n8);
    let norm_shift_em1 = sub(norm_shift_e, 1);
    let mut norm_shift_p2 = add(norm_shift_e, CNG_NORM_RECIPROCAL_RANGE_SHIFT);

    let n2u = n2.max(0) as usize;
    let mut old_exc_ener = l_shr(l_mult(old_exc[0], old_exc[0]), norm_shift_p2);
    for &x in &old_exc[1..n2u] {
        old_exc_ener = l_add(old_exc_ener, l_shr(l_mult(x, x), norm_shift_p2));
    }
    old_exc_ener = l_shl(
        mpy_32_16_1(old_exc_ener, shl(norm_fac_e, norm_shift_em1)),
        1,
    );

    let mut old_exc_ener_exp: i16 = 0;
    old_exc_ener = sqrt32(old_exc_ener, &mut old_exc_ener_exp);
    old_exc_ener_exp = add(old_exc_ener_exp, sub(15, q_exc));

    // shift to be in the range of values supported by getNormReciprocalWord16()
    let n4 = shr(n, CNG_NORM_RECIPROCAL_RANGE_SHIFT);

    let norm_fac_g = get_norm_reciprocal_word16(n4);
    let norm_shift_g = basop_util_norm_s_bands2shift(n4);
    let norm_shift_gm1 = sub(norm_shift_g, 1);
    norm_shift_p2 = add(norm_shift_g, CNG_NORM_RECIPROCAL_RANGE_SHIFT);

    let mut gain = l_deposit_l(0);
    for value in &mut noise[..nu] {
        let noise32 = rand_gauss(&mut seed_loc);
        *value = extract_h(noise32);
        gain = l_add(gain, l_shr(l_mult(*value, *value), norm_shift_p2));
    }
    gain = l_shl(mpy_32_16_1(gain, shl(norm_fac_g, norm_shift_gm1)), 1);

    let mut gain_exp = 2 * CNG_RAND_GAUSS_SHIFT;
    gain = isqrt32(gain, &mut gain_exp);

    gain = mpy_32_32(old_exc_ener, gain);
    let gain16 = extract_h(gain);

    gain_exp = add(old_exc_ener_exp, gain_exp);
    let noise_exp = add(CNG_RAND_GAUSS_SHIFT, gain_exp);

    let s = sub(15 - NOISE_HEADROOM, noise_exp);
    for value in &mut noise[..nu] {
        *value = shr(mult(*value, gain16), s);
    }

    let s = sub(15 - NOISE_HEADROOM, sub(15, q_syn));
    for i in 0..lpcorder as usize {
        old_syn_pe_tmp[i] = shr(old_syn_pe[i], s);
    }

    e_util_synthesis_in_place(0, old_aq, &mut noise, n, &mut old_syn_pe_tmp, 0, lpcorder);

    let mut tmp = old_syn;

    e_util_deemph2(NOISE_HEADROOM, &mut noise, preemph_fac, n, &mut tmp);

    let n4u = n4.max(0) as usize;
    let win = st.olap_win_syn;
    for i in 0..n4u {
        let tmp = mult(noise[i], win[i].v.re);
        st.time_domain_buffer[i] = add(st.time_domain_buffer[i], tmp);
        let tmp = mult(noise[i + n4u], win[n4u - 1 - i].v.im);
        st.time_domain_buffer[i + n4u] = add(st.time_domain_buffer[i + n4u], tmp);
    }
}

/// `generate_comfort_noise_dec_hf`: comfort noise in the CLDFB bands above the core
/// (`numCoreBands..regularStopBand`) at the levels following the FFT bins in `cngNoiseLevel`.
/// The FD-CNG state is `stdec.h_fd_cng_dec`.
pub fn generate_comfort_noise_dec_hf(cldfb: CldfbBuffers<'_>, stdec: &mut DecoderState) {
    let Some(dec) = stdec.h_fd_cng_dec.as_deref_mut() else {
        return;
    };
    let Some(st) = dec.h_fd_cng_com.as_deref_mut() else {
        return;
    };
    let mut cldfb = cldfb;
    let mut level = sub(st.stop_ff_tbin, st.start_band).max(0) as usize;
    let mut cng_noise_level_exp = st.cng_noise_level_exp;

    // scaleCLDFB: CLDFBinvScalingFactor_EXP + 1
    let scale_cldfb = mult(st.inv_scaling_factor, CLDFB_SCALING);

    let mut sn: i16 = 0;
    if cng_noise_level_exp & 1 != 0 {
        sn = add(sn, 1);
        cng_noise_level_exp = add(cng_noise_level_exp, sn);
    }

    let rand_gauss_exp = CNG_RAND_GAUSS_SHIFT;

    if sub(st.num_core_bands, st.regular_stop_band) < 0 {
        let sc = add(
            shr(
                add(cng_noise_level_exp, CLDFBINVSCALINGFACTOR_EXP + 1 - 1),
                1,
            ),
            rand_gauss_exp,
        );
        let from = st.num_core_bands.max(0) as usize;
        let to = (st.regular_stop_band.max(0) as usize).min(CLDFB_ROW);
        for j in from..to {
            cldfb_band_noise(
                &mut cldfb,
                j,
                st.num_slots,
                st.cng_noise_level[level],
                scale_cldfb,
                sn,
                &mut st.seed,
            );
            level += 1;
        }
        if let Some(scale) = cldfb.scale {
            *scale = sub(sc, 15);
        }
    }
}

/// The comfort-noise scale of `generate_masking_noise` / `_mdct` for the CNG bandwidth and bit
/// rate (`scaleTable_cn_only`), or -1 when no row matches (the reference asserts).
fn masking_scale(st: &FdCngCom) -> i16 {
    for row in &SCALETABLE_CN_ONLY {
        if sub(st.cng_bandwidth, i16::from(row.bwmode)) == 0
            && l_sub(st.cng_bitrate, row.bitrate_from) >= 0
            && l_sub(st.cng_bitrate, row.bitrate_to) < 0
        {
            return row.scale;
        }
    }
    -1
}

/// `generate_masking_noise`: add comfort noise at the CNG level (scaled by the bit-rate table and
/// the noisy-speech likelihood) under the decoded `time_domain_buffer` (Q `q`, `length` samples
/// at most one frame), a kind of noise filling for noisy speech. `olap_buffer_synth2` is the
/// owning `FdCngDec`'s buffer `st.olap_buffer_synth2` points into (nothing is done without that
/// offset, which the reference asserts is set).
pub fn generate_masking_noise(
    time_domain_buffer: &mut [i16],
    q: i16,
    st: &mut FdCngCom,
    olap_buffer_synth2: &mut [i16],
    length: i16,
    core: i16,
) {
    let mut masking_noise = [0i16; L_FRAME16K as usize];
    let mut level: usize = 0;

    // Compute additional CN level
    let cng_noise_level_exp = st.cng_noise_level_exp;

    let mut scale: i16;
    if core != AMR_WB_CORE {
        scale = masking_scale(st);
    } else {
        scale = 0;
        for row in &SCALETABLE_CN_ONLY_AMRWBIO {
            if l_sub(st.cng_bitrate, i32::from(row[0])) >= 0 {
                scale = row[1];
                break;
            }
        }
    }

    // Exclude clean speech
    let s1 = norm_s(scale);
    let s2 = norm_s(st.likelihood_noisy_speech);

    // scaleTable_cn_only[i].scale is scaled by 1 bit
    let scale_exp = sub(1, add(s1, s2));
    scale = mult_r(shl(scale, s1), shl(st.likelihood_noisy_speech, s2));

    // add exponent of scale and cngNoiseLevel
    let mut fft_buffer_exp = add(scale_exp, cng_noise_level_exp);

    // even scalefactor needed for sqrt calculation
    let s = fft_buffer_exp & 1;
    fft_buffer_exp = add(fft_buffer_exp, s);

    // sqrt calculation => shift exponent
    fft_buffer_exp = shr(fft_buffer_exp, 1);

    // consider scaling of random noise
    fft_buffer_exp = add(fft_buffer_exp, CNG_RAND_GAUSS_SHIFT);

    let mut cnt = sub(st.stop_ff_tbin, st.start_band);
    // Generate Gaussian random noise in real and imaginary parts of the FFT bins; amplitudes are
    // adjusted to the estimated noise level cngNoiseLevel in each bin
    let mut fft: usize;
    if st.start_band == 0 {
        // random noise is scaled by CNG_RAND_GAUSS_SHIFT bits; DC component in FFT;
        // -s => consider scalefactor adaptation for sqrt calculation
        let mut sq = sub(0, s);
        let sqrt_noise_level = sqrt32(mpy_32_16_1(st.cng_noise_level[level], scale), &mut sq);
        st.fft_buffer[0] = l_shl(mpy_32_32(rand_gauss(&mut st.seed), sqrt_noise_level), sq);
        st.fft_buffer[1] = 0;

        fft = 2;
        level += 1;

        cnt = sub(cnt, 1);
    } else {
        let start_band2 = shl(st.start_band, 1).max(0) as usize;
        st.fft_buffer[..start_band2].fill(0);
        fft = start_band2;
    }

    for _ in 0..cnt.max(0) {
        // -1 => weighting with 0.5, -s => consider scalefactor adaptation for sqrt calculation
        let mut sq = sub(-1, s);
        let sqrt_noise_level = sqrt32(mpy_32_16_1(st.cng_noise_level[level], scale), &mut sq);

        // real part in FFT bins
        st.fft_buffer[fft] = l_shl(mpy_32_32(rand_gauss(&mut st.seed), sqrt_noise_level), sq);
        fft += 1;

        // imaginary part in FFT bins
        st.fft_buffer[fft] = l_shl(mpy_32_32(rand_gauss(&mut st.seed), sqrt_noise_level), sq);
        fft += 1;

        level += 1;
    }

    // remaining FFT bins are set to zero
    let stop_ff_tbin2 = shl(st.stop_ff_tbin, 1).max(0) as usize;
    let fl = (st.fftlen.max(0) as usize).min(st.fft_buffer.len());
    if stop_ff_tbin2 < fl {
        st.fft_buffer[stop_ff_tbin2..fl].fill(0);
    }

    // perform STFT synthesis
    let Some(olap_at) = st.olap_buffer_synth2 else {
        return;
    };
    let olap_win_syn = st.olap_win_syn;
    let mut unused_q: i16 = 0;
    synthesis_stft(
        StftSpectrum::Common,
        fft_buffer_exp,
        &mut masking_noise,
        StftOverlap::External(&mut olap_buffer_synth2[olap_at..]),
        olap_win_syn,
        0,
        st,
        0,
        &mut unused_q,
    );

    // add some comfort noise on top of decoded signal
    let n = if st.frame_size > length {
        length
    } else {
        st.frame_size
    };
    for i in 0..n.max(0) as usize {
        time_domain_buffer[i] = add(time_domain_buffer[i], shr_r(masking_noise[i], negate(q)));
    }
}

/// `generate_masking_noise_update_seed`: advance the noise seed as `generate_masking_noise`
/// would, for frames where it is not called.
pub fn generate_masking_noise_update_seed(st: &mut FdCngCom) {
    let mut cnt = sub(st.stop_ff_tbin, st.start_band);

    if st.start_band == 0 {
        rand_gauss(&mut st.seed);
        cnt = sub(cnt, 1);
    }

    for _ in 0..cnt.max(0) {
        rand_gauss(&mut st.seed);
        rand_gauss(&mut st.seed);
    }
}

/// `generate_masking_noise_mdct`: add comfort noise (kind of noise filling) to the MDCT spectrum
/// `mdct_buffer` (exponent `mdct_buffer_e`, `l_frame` lines), at the CNG level scaled as in
/// `generate_masking_noise` and re-normalised for the MDCT (`sqrt(NORM_MDCT_FACTOR)`).
pub fn generate_masking_noise_mdct(
    mdct_buffer: &mut [i32],
    mdct_buffer_e: &mut i16,
    st: &mut FdCngCom,
    l_frame: i16,
) {
    let mut masking_noise = [0i32; 2 * L_FRAME16K as usize];
    let mut level: usize = 0;

    // Compute additional CN level
    let cng_noise_level_exp = st.cng_noise_level_exp;
    let mut scale = masking_scale(st);

    // Exclude clean speech
    let s1 = norm_s(scale);
    let s2 = norm_s(st.likelihood_noisy_speech);

    // scaleTable_cn_only[i].scale is scaled by 1 bit
    let scale_exp = sub(1, add(s1, s2));
    scale = mult_r(shl(scale, s1), shl(st.likelihood_noisy_speech, s2));

    // add exponent of scale and cngNoiseLevel
    let mut masking_noise_exp = add(scale_exp, cng_noise_level_exp);

    // even scalefactor needed for sqrt calculation
    let s = masking_noise_exp & 1;
    masking_noise_exp = add(masking_noise_exp, s);

    // sqrt calculation => shift exponent
    masking_noise_exp = shr(masking_noise_exp, 1);

    // consider scaling of random noise
    masking_noise_exp = add(masking_noise_exp, CNG_RAND_GAUSS_SHIFT);

    let mut cnt = sub(st.stop_ff_tbin, st.start_band);

    // Generate Gaussian random noise in real and imaginary parts of the FFT bins; amplitudes are
    // adjusted to the estimated noise level cngNoiseLevel in each bin
    let mut at: usize;
    if st.start_band == 0 {
        // -1 => weighting with 0.5, -s => consider scalefactor adaptation for sqrt calculation
        let mut sq = sub(-1, s);
        let sqrt_noise_level = sqrt32(mpy_32_16_1(st.cng_noise_level[level], scale), &mut sq);
        masking_noise[0] = l_shl(mpy_32_32(rand_gauss(&mut st.seed), sqrt_noise_level), sq);

        at = 1;
        level += 1;

        cnt = sub(cnt, 1);
    } else {
        let start = st.start_band.max(0) as usize;
        masking_noise[..start].fill(0);
        at = start;
    }

    for _ in 0..cnt.max(0) {
        // -1 => weighting with 0.5, -s => consider scalefactor adaptation for sqrt calculation
        let mut sq = sub(-1, s);
        let sqrt_noise_level = sqrt32(mpy_32_16_1(st.cng_noise_level[level], scale), &mut sq);

        // real part in FFT bins; random noise is scaled by CNG_RAND_GAUSS_SHIFT bits
        masking_noise[at] = l_shl(mpy_32_32(rand_gauss(&mut st.seed), sqrt_noise_level), sq);
        at += 1;

        level += 1;
    }

    // re-normalization of energy level: 16 * 0.79056941504 = sqrt(NORM_MDCT_FACTOR); do weighting
    // with factor 0.79056941504 later
    masking_noise_exp = add(masking_noise_exp, 4);

    let s = (*mdct_buffer_e).max(masking_noise_exp);
    let s1 = sub(s, *mdct_buffer_e);
    let s2 = sub(s, masking_noise_exp);

    let stop = st.stop_ff_tbin.max(0) as usize;
    // avoid rescaling of mdct samples if no comfort noise is added
    if scale != 0 {
        // Add some comfort noise on top of decoded signal
        if s1 == 0 {
            for i in 0..stop {
                // If shifting negative noise values the lowest result is -1 but never 0. Shift
                // positive noise values to avoid unwanted amplification of these small values
                // later
                let mut noise = l_shr(mpy_32_16_1(l_abs(masking_noise[i]), 25905), s2); // 0.79056941504 Q15

                if masking_noise[i] < 0 {
                    noise = l_negate(noise);
                }

                mdct_buffer[i] = l_add(mdct_buffer[i], noise);
            }
        } else {
            for i in 0..stop {
                mdct_buffer[i] = l_add(
                    l_shr(mdct_buffer[i], s1),
                    mpy_32_16_1(masking_noise[i], 25905), // 0.79056941504 Q15
                );
            }
            for value in mdct_buffer
                .iter_mut()
                .take(l_frame.max(0) as usize)
                .skip(stop)
            {
                *value = l_shr(*value, s1);
            }
            *mdct_buffer_e = s;
        }
    }
}
