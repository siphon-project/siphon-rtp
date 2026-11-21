//! Frequency-domain comfort noise generation, the parts shared by encoder and decoder: partitions,
//! log-range compression, minimum-statistics noise estimation, STFT analysis / synthesis
//! (TS 26.442 `lib_com/fd_cng_com.c`; TS 26.445 §5.6.3, §6.7.3).
//!
//! `apply_scale` is not ported here (no decoder path reaches it).
//!
//! `olapBufferAna` / `olapBufferSynth2` are offsets into the owning `FdCngDec`'s buffers, so the
//! functions that use them take those buffers as parameters.

use crate::evs::basop::{mpy_32_16_1, mpy_32_16_r, mpy_32_32};
use crate::evs::cnst::{CNG_ISF_FACT_FX, INT_FS_16K_FX, L_FRAME, L_FRAME16K, L_SUBFR};
use crate::evs::com::basop_util::{
    basop_util_add_mant32_exp, basop_util_divide3232_scale, basop_util_divide3232_uu_1616_scale,
    basop_util_divide_mant_exp, basop_util_inv_log2, basop_util_log2, dotp_s,
    get_norm_reciprocal_word16, get_scale_factor32, sqrt32,
};
use crate::evs::com::fft::basop_rfft;
use crate::evs::com::lpc_tools::e_lpc_lev_dur;
use crate::evs::com::lsf_tools::{e_lpc_a_lsp_conversion, e_lpc_lsp_lsf_conversion, lsp2lsf};
use crate::evs::com::preemph::{e_util_f_preemph2, e_util_f_preemph3};
use crate::evs::com::residu::residu3;
use crate::evs::com::rom_basop_util::basop_get_tables;
use crate::evs::com::swb_tbe_com::{interp_code_4over2, interp_code_5over2};
use crate::evs::com::tools::copy_scale_sig_32_16;
use crate::evs::dec::state::FdCngCom;
use crate::evs::rom::types::PWord16;
use crate::evs::rom::{D_ARRAY, MSNOISESLOPEMAX, MSQEQINVAV_THRESH, M_ARRAY};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_msu,
    l_mult, l_negate, l_shl, l_shr, l_shr_r, l_sub, mult, mult_r, norm_l, norm_s, round_word, shl,
    shr, sub,
};
use crate::itu::oper_32b::l_extract;
use crate::itu::stl2009::{i_mult, l_mac0, l_msu0, l_mult0, mac_r};

/// `MAX_32`.
const MAX_32: i32 = 0x7FFF_FFFF;
/// `WORD32_BITS`, `WORD16_BITS`.
const WORD32_BITS: i16 = 32;
const WORD16_BITS: i16 = 16;
/// `MSNUMSUBFR`, `MSSUBFRLEN`, `MSBUFLEN`.
const MSNUMSUBFR: i16 = 6;
const MSSUBFRLEN: i16 = 12;
const MSBUFLEN: i16 = 5;
/// `NPART_SHAPING`: the most partitions any caller has.
const NPART_SHAPING: usize = 62;
/// `M`, the LP order of the CNG excitation filter.
const M: usize = 16;
/// `FFTLEN2`.
const FFTLEN2: usize = 320;

/// `createFdCngCom`: allocates the (zeroed) common FD-CNG state. Init time only.
pub fn create_fd_cng_com(h_fd_cng_com: &mut Option<Box<FdCngCom>>) {
    *h_fd_cng_com = Some(Box::new(FdCngCom::zeroed()));
}

/// `deleteFdCngCom`: releases the common FD-CNG state.
pub fn delete_fd_cng_com(h_fd_cng_com: &mut Option<Box<FdCngCom>>) {
    *h_fd_cng_com = None;
}

/// `initFdCngCom`: initialises the common FD-CNG state; `scale` is the core's scaling
/// (`mult(scale, scale)` must exceed 2048, which the reference asserts).
pub fn init_fd_cng_com(hs: &mut FdCngCom, scale: i16) {
    // Calculate CLDFB scaling factor
    hs.inv_scaling_factor = shl(mult(scale, scale), 1);
    hs.scaling_factor = div_s(0x4000, hs.inv_scaling_factor);

    // Initialize the overlap-add
    hs.time_domain_buffer.fill(0);
    hs.olap_buffer_ana = None;
    hs.olap_buffer_synth.fill(0);
    hs.olap_buffer_synth2 = None;

    // Initialize the comfort noise generation
    hs.fft_buffer.fill(0);
    hs.cng_noise_level.fill(0);

    // Initialize quantizer
    hs.sid_noise_est.fill(0);
    hs.a_cng.fill(0);
    hs.a_cng[0] = 4096; // 1.0 in Q12

    // Set some counters and flags
    hs.inactive_frame_counter = 0;
    hs.active_frame_counter = 0;
    hs.frame_type_previous = 0xFF; // ACTIVE_FRAME
    hs.flag_noisy_speech = 0;
    hs.likelihood_noisy_speech = 0;

    // Initialize noise estimation algorithm
    hs.num_core_bands = 0;
    hs.stop_band = 0;
    hs.start_band = 0;
    hs.stop_ff_tbin = 0;
    hs.frame_size = 0;
    hs.fftlen = 0;
    hs.periodog.fill(0);
    mhvals(MSNUMSUBFR * MSSUBFRLEN, &mut hs.ms_m_win);
    mhvals(MSSUBFRLEN, &mut hs.ms_m_subwin);
    hs.ms_periodog_sum = [0; 2];
    hs.ms_periodog_sum_exp = [0; 2];
    hs.ms_psd_sum = [0; 2];
    hs.ms_slope = [0; 2];
    hs.ms_qeq_inv_av = [0; 2];
    hs.ms_qeq_inv_av_exp = [0; 2];
    hs.ms_fr_cnt_init_counter = 0;
    hs.ms_fr_cnt_init_thresh = 1;
    hs.init_old = 0;
    hs.offsetflag = 0;
    hs.ms_fr_cnt = MSSUBFRLEN;
    hs.ms_min_buffer_ptr = 0;
    hs.ms_alpha_cor = [644_245_120; 2]; // 0.3 in Q31
    hs.exp_cldfb_periodog = 0;
}

/// `initPartitions`: the partition upper bounds `part_out` (relative to `start_band`) from the
/// table `part_in` (or one band per partition when `None`), every band below `stop_band_fr`
/// becoming its own partition; then their midbands and sizes ([`getmidbands`]).
pub fn init_partitions(
    part_in: Option<&[i16]>,
    npart_in: i16,
    start_band: i16,
    stop_band: i16,
    part_out: &mut [i16],
    npart_out: &mut i16,
    midband: &mut [i16],
    psize: &mut [i16],
    psize_norm: &mut [i16],
    psize_norm_exp: &mut i16,
    psize_inv: &mut [i16],
    stop_band_fr: i16,
) {
    let mut len_out: i16;
    if let Some(part_in) = part_in {
        len_out = 0;
        if sub(stop_band_fr, start_band) > 0 {
            len_out = sub(stop_band_fr, start_band);
            for (i, p) in part_out.iter_mut().take(len_out as usize).enumerate() {
                *p = i as i16;
            }
        }
        for &part in part_in.iter().take(npart_in.max(0) as usize) {
            if sub(part, stop_band) >= 0 {
                break;
            }
            let tmp16 = sub(part, start_band);
            if sub(part, stop_band_fr) >= 0 && tmp16 >= 0 {
                part_out[len_out as usize] = tmp16;
                len_out += 1;
            }
        }
    } else {
        len_out = sub(stop_band, start_band);
        for (i, p) in part_out
            .iter_mut()
            .take(len_out.max(0) as usize)
            .enumerate()
        {
            *p = i as i16;
        }
    }
    *npart_out = len_out;
    getmidbands(
        part_out,
        len_out,
        midband,
        psize,
        psize_norm,
        psize_norm_exp,
        psize_inv,
    );
}

/// `compress_range`: `out = log2(in + 1)` (Q10, at least 1) of energies `in` with exponent
/// `in_exp`.
pub fn compress_range(input: &[i32], in_exp: i16, out: &mut [i16], len: i16) {
    let len = len.max(0) as usize;
    if in_exp >= 0 {
        let one_s = l_shr(1_073_741_824, in_exp);
        let in_exp32 = l_shl(l_deposit_l(add(in_exp, 1)), WORD32_BITS - 1 - 6);
        for i in 0..len {
            let in_s = l_add(l_shr(input[i], 1), one_s);
            let l_tmp = l_add(basop_util_log2(in_s), in_exp32);
            if in_s == 0 {
                out[i] = 0;
            }
            if in_s != 0 {
                out[i] = extract_h(l_tmp);
            }
            if out[i] == 0 {
                out[i] = 1;
            }
        }
    } else {
        let in_exp = sub(in_exp, 1);
        let in_exp32 = l_shl(l_deposit_l(1), WORD32_BITS - 1 - 6);
        for i in 0..len {
            let l_tmp = l_add(
                basop_util_log2(l_add(l_shl(input[i], in_exp), 1_073_741_824)),
                in_exp32,
            );
            if input[i] == 0 {
                out[i] = 0;
            }
            if input[i] != 0 {
                out[i] = extract_h(l_tmp);
            }
            if out[i] == 0 {
                out[i] = 1;
            }
        }
    }
}

/// `expand_range`: `out = 2^in - 1` with a common exponent `out_exp`, the inverse of
/// [`compress_range`].
pub fn expand_range(input: &[i16], out: &mut [i32], out_exp: &mut i16, len: i16) {
    let len = len.max(0) as usize;
    let mut max_val: i16 = 0;
    for &v in &input[..len] {
        max_val = max_val.max(v);
    }
    let max_val2 = max_val;
    let mut s: i16 = 0;
    while max_val >= 0 {
        max_val = sub(max_val, 512); // 0.5 in Q10
        s = add(s, 1);
    }
    let tmp = sub(max_val2, max_val);
    let one_s = l_shr(1_073_741_824, sub(s, 1));
    let tmp32 = l_shr(726_941, s);
    for i in 0..len {
        out[i] = l_sub(basop_util_inv_log2(l_deposit_h(sub(input[i], tmp))), one_s);
        if out[i] == 0 {
            out[i] = tmp32;
        }
    }
    *out_exp = s;
}

/// The per-partition arrays `minimum_statistics` works on, gathered so its stages can be split.
struct MsBuffers<'a> {
    psize: &'a [i16],
    ms_periodog: &'a [i16],
    ms_noise_floor: &'a mut [i16],
    ms_noise_est: &'a mut [i16],
    ms_alpha: &'a mut [i32],
    ms_psd: &'a mut [i16],
    ms_psd_first_moment: &'a mut [i16],
    ms_psd_second_moment: &'a mut [i32],
    ms_min_buf: &'a mut [i32],
    ms_bmin_win: &'a mut [i32],
    ms_bmin_sub_win: &'a mut [i32],
    ms_current_min: &'a mut [i32],
    ms_current_min_out: &'a mut [i32],
    ms_current_min_sub_window: &'a mut [i32],
    ms_local_min_flag: &'a mut [i16],
    ms_new_min_flag: &'a mut [i16],
}

/// `minimum_statistics`: noise power estimation by minimum statistics (Martin), on the
/// log-compressed periodogram `ms_periodog` of `len` partitions (`len_fft` of them from the FFT,
/// the rest from the CLDFB). Updates the estimate `ms_noise_est` and every tracking buffer.
pub fn minimum_statistics(
    len: i16,
    len_fft: i16,
    psize: &[i16],
    ms_periodog: &[i16],
    ms_noise_floor: &mut [i16],
    ms_noise_est: &mut [i16],
    ms_alpha: &mut [i32],
    ms_psd: &mut [i16],
    ms_psd_first_moment: &mut [i16],
    ms_psd_second_moment: &mut [i32],
    ms_min_buf: &mut [i32],
    ms_bmin_win: &mut [i32],
    ms_bmin_sub_win: &mut [i32],
    ms_current_min: &mut [i32],
    ms_current_min_out: &mut [i32],
    ms_current_min_sub_window: &mut [i32],
    ms_local_min_flag: &mut [i16],
    ms_new_min_flag: &mut [i16],
    ms_periodog_buf: &mut [i16],
    ms_periodog_buf_ptr: &mut i16,
    st: &mut FdCngCom,
) {
    let lenu = len.max(0) as usize;
    if lenu > NPART_SHAPING || len_fft < 0 || len_fft > len {
        return;
    }
    let mut b = MsBuffers {
        psize,
        ms_periodog,
        ms_noise_floor,
        ms_noise_est,
        ms_alpha,
        ms_psd,
        ms_psd_first_moment,
        ms_psd_second_moment,
        ms_min_buf,
        ms_bmin_win,
        ms_bmin_sub_win,
        ms_current_min,
        ms_current_min_out,
        ms_current_min_sub_window,
        ms_local_min_flag,
        ms_new_min_flag,
    };

    if sub(st.ms_fr_cnt_init_counter, st.ms_fr_cnt_init_thresh) < 0 {
        minimum_statistics_init(len, len_fft, &mut b, st);
    } else {
        // Consider the FFT and CLDFB bands separately
        let mut cnt: usize = 0;
        let mut start: i16 = 0;
        let mut stop = len_fft;
        let mut totsize = sub(st.stop_ff_tbin, st.start_band);
        while sub(stop, start) > 0 {
            let (s, e) = (start as usize, stop as usize);
            minimum_statistics_smooth(cnt, s, e, &mut b, st);
            minimum_statistics_bias(cnt, s, e, totsize, &mut b, st);
            start = stop;
            stop = len;
            totsize = sub(st.stop_band, st.stop_ff_tbin);
            cnt += 1;
        }
        minimum_statistics_track(len, len_fft, &mut b, st);
        minimum_statistics_offset(len, len_fft, cnt, &mut b, st);

        // Increment frame counter at init and/or update the buffer pointer
        if sub(st.ms_fr_cnt, MSSUBFRLEN) == 0 {
            st.ms_fr_cnt = 1;
            st.ms_min_buffer_ptr = add(st.ms_min_buffer_ptr, 1);
            if sub(st.ms_min_buffer_ptr, MSNUMSUBFR) == 0 {
                st.ms_min_buffer_ptr = 0;
            }
        } else {
            st.ms_fr_cnt = add(st.ms_fr_cnt, 1);
        }

        // Smooth noise estimate during the CNG phases
        for j in 0..lenu {
            b.ms_noise_est[j] = round_word(l_mac(
                l_mult(31130, b.ms_noise_est[j]),
                1638,
                b.ms_noise_floor[j],
            ));
        }
    }

    // Collect buffers
    let at = lenu * (*ms_periodog_buf_ptr).max(0) as usize;
    if at + lenu > ms_periodog_buf.len() || MSBUFLEN as usize * lenu > ms_periodog_buf.len() {
        return;
    }
    ms_periodog_buf[at..at + lenu].copy_from_slice(&ms_periodog[..lenu]);
    *ms_periodog_buf_ptr = add(*ms_periodog_buf_ptr, 1);
    if sub(*ms_periodog_buf_ptr, MSBUFLEN) == 0 {
        *ms_periodog_buf_ptr = 0;
    }

    // Upper limit the noise floors with the averaged input energy
    for j in 0..lenu {
        let mut scalar = l_mult(ms_periodog_buf[j], 6554); // 0.2 in Q15
        let mut i = j + lenu;
        while i < MSBUFLEN as usize * lenu {
            scalar = l_mac(scalar, ms_periodog_buf[i], 6554);
            i += lenu;
        }
        let scalar16 = round_word(scalar);
        if sub(b.ms_noise_est[j], scalar16) > 0 {
            b.ms_noise_est[j] = scalar16;
        }
    }
}

/// `minimum_statistics`, the initial frames: everything starts from the periodogram.
fn minimum_statistics_init(len: i16, len_fft: i16, b: &mut MsBuffers<'_>, st: &mut FdCngCom) {
    let lenu = len as usize;
    let lf = len_fft as usize;
    let len2 = i_mult(MSNUMSUBFR, len).max(0) as usize;
    b.ms_psd[..lenu].copy_from_slice(&b.ms_periodog[..lenu]);
    b.ms_noise_floor[..lenu].copy_from_slice(&b.ms_periodog[..lenu]);
    b.ms_noise_est[..lenu].copy_from_slice(&b.ms_periodog[..lenu]);
    b.ms_psd_first_moment[..lenu].copy_from_slice(&b.ms_periodog[..lenu]);
    b.ms_psd_second_moment[..lenu].fill(0);
    st.ms_periodog_sum[0] = dotp_s(b.ms_periodog, b.psize, len_fft, 4);
    st.ms_psd_sum[0] = st.ms_periodog_sum[0];
    if sub(len_fft, len) < 0 {
        st.ms_periodog_sum[1] = dotp_s(&b.ms_periodog[lf..], &b.psize[lf..], sub(len, len_fft), 4);
        st.ms_psd_sum[1] = st.ms_periodog_sum[1];
    }
    // Increment frame counter at init
    // Some frames are sometimes zero at init => do not count them
    if sub(b.ms_periodog[0], st.init_old) < 0 {
        b.ms_current_min_out[..lenu].fill(MAX_32);
        b.ms_current_min[..lenu].fill(MAX_32);
        b.ms_min_buf[..len2].fill(MAX_32);
        b.ms_current_min_sub_window[..lenu].fill(MAX_32);
        st.ms_fr_cnt_init_counter = add(st.ms_fr_cnt_init_counter, 1);
    }
    st.init_old = b.ms_periodog[0];
}

/// `minimum_statistics`, per band group: the correction factor, the optimal smoothing parameter
/// and the smoothed PSD.
fn minimum_statistics_smooth(
    cnt: usize,
    start: usize,
    stop: usize,
    b: &mut MsBuffers<'_>,
    st: &mut FdCngCom,
) {
    let current_len = (stop - start) as i16;
    let ms_alpha_cor_alpha: i16 = 22938; // 0.7 Q15
    let ms_alpha_cor_alpha2: i16 = 9830; // 0.3 Q15

    // Compute smoothed correction factor for the PSD smoothing
    st.ms_periodog_sum[cnt] = dotp_s(&b.ms_periodog[start..], &b.psize[start..], current_len, 4);
    if st.ms_periodog_sum[cnt] == 0 {
        st.ms_alpha_cor[cnt] = mpy_32_16_1(st.ms_alpha_cor[cnt], ms_alpha_cor_alpha);
    } else {
        // calculate scalar2 = msPeriodogSum²/(msPsdSum - msPeriodogSum)² normalised
        let s1 = norm_l(st.ms_periodog_sum[cnt]);
        let ms_periodog_sum16 = round_word(l_shl(st.ms_periodog_sum[cnt], s1));
        let mut scalar = l_mult(ms_periodog_sum16, ms_periodog_sum16);

        let mut scalar2 = l_abs(l_sub(st.ms_psd_sum[cnt], st.ms_periodog_sum[cnt]));
        let mut s2 = WORD32_BITS - 1;
        if scalar2 != 0 {
            s2 = norm_l(scalar2);
        }
        let scalar216 = round_word(l_shl(scalar2, s2));
        scalar2 = l_mult(scalar216, scalar216);

        // calculate scalar3 = scalar + scalar2 aligned
        let tmp16_1 = sub(s1, s2);
        let tmp16 = shl(abs_s(tmp16_1), 1).min(WORD32_BITS - 1);
        if tmp16_1 < 0 {
            scalar2 = l_shr(scalar2, tmp16);
        }
        if tmp16_1 > 0 {
            scalar = l_shr(scalar, tmp16);
        }
        scalar = l_shr(scalar, 1);
        scalar2 = l_shr(scalar2, 1);
        let scalar3 = l_add(scalar, scalar2);

        // calculate scalar/scalar3
        let mut s3: i16 = 0;
        let mut scalar16 = basop_util_divide3232_uu_1616_scale(scalar, scalar3, &mut s3);
        s3 = s3.max(-(WORD16_BITS - 1));
        scalar16 = shl(scalar16, s3);
        scalar16 = scalar16.max(ms_alpha_cor_alpha2);

        st.ms_alpha_cor[cnt] = l_add(
            mpy_32_16_1(st.ms_alpha_cor[cnt], ms_alpha_cor_alpha),
            l_mult(scalar16, ms_alpha_cor_alpha2),
        );
    }

    // Compute SNR
    let snr = dotp_s(
        &b.ms_noise_floor[start..],
        &b.psize[start..],
        current_len,
        4,
    );
    let ms_alpha_hat_min2 = if l_sub(l_shr(mpy_32_16_1(st.ms_psd_sum[cnt], 18431), 13), snr) > 0 {
        let tmp0 = basop_util_log2(st.ms_psd_sum[cnt]);
        let mut tmp1 = basop_util_log2(snr);
        tmp1 = l_sub(tmp0, tmp1);
        tmp1 = mpy_32_16_1(tmp1, -10240);
        basop_util_inv_log2(tmp1)
    } else {
        107_374_184 // 0.05 Q31
    };

    let scalar = mpy_32_16_1(st.ms_alpha_cor[cnt], 31457); // 0.96 Q15
    for j in start..stop {
        // Compute optimal smoothing parameter for the PSD estimation
        if scalar == 0 || b.ms_noise_floor[j] == 0 {
            b.ms_alpha[j] = ms_alpha_hat_min2;
        } else {
            // calculate scalar2 = msNoiseFloor² normalised
            let mut s1 = WORD16_BITS - 1;
            if b.ms_noise_floor[j] != 0 {
                s1 = norm_s(b.ms_noise_floor[j]);
            }
            let ms_noise_floor16 = shl(b.ms_noise_floor[j], s1);
            let mut scalar2 = l_mult(ms_noise_floor16, ms_noise_floor16);

            // calculate scalar3 = (msPsd - msNoiseFloor)² normalised
            let mut scalar316 = abs_s(sub(b.ms_psd[j], b.ms_noise_floor[j]));
            let mut s2 = WORD16_BITS - 1;
            if scalar316 != 0 {
                s2 = norm_s(scalar316);
            }
            scalar316 = shl(scalar316, s2);
            let mut scalar3 = l_mult(scalar316, scalar316);

            // calculate scalar3 = scalar2 + scalar3 aligned
            let tmp16_1 = sub(s1, s2);
            let tmp16 = shl(abs_s(tmp16_1), 1).min(WORD32_BITS - 1);
            if tmp16_1 < 0 {
                scalar3 = l_shr(scalar3, tmp16);
            }
            if tmp16_1 > 0 {
                scalar2 = l_shr(scalar2, tmp16);
            }
            scalar2 = l_shr(scalar2, 1);
            scalar3 = l_shr(scalar3, 1);
            scalar3 = l_add(scalar2, scalar3);

            // calculate scalar2/scalar3
            let mut s3: i16 = 0;
            let tmp16 = basop_util_divide3232_uu_1616_scale(scalar2, scalar3, &mut s3);
            scalar2 = mpy_32_16_1(scalar, tmp16);
            s3 = s3.max(-(WORD32_BITS - 1));
            scalar2 = l_shl(scalar2, s3);
            b.ms_alpha[j] = scalar2.max(ms_alpha_hat_min2);
        }

        // Compute the PSD (smoothed periodogram) in each band
        b.ms_psd[j] = round_word(l_add(
            mpy_32_16_1(b.ms_alpha[j], b.ms_psd[j]),
            mpy_32_16_1(l_sub(MAX_32, b.ms_alpha[j]), b.ms_periodog[j]),
        ));
    }
    st.ms_psd_sum[cnt] = dotp_s(&b.ms_psd[start..], &b.psize[start..], current_len, 4);
}

/// `minimum_statistics`, per band group: the PSD's first and second moments, the bias
/// corrections and the new minima.
fn minimum_statistics_bias(
    cnt: usize,
    start: usize,
    stop: usize,
    totsize: i16,
    b: &mut MsBuffers<'_>,
    st: &mut FdCngCom,
) {
    let ms_m_win = st.ms_m_win;
    let ms_m_subwin = st.ms_m_subwin;
    let mut qeq_inv_av: i32 = 0;

    // scalar: 2.12 - 2·msM_win, scalar2: 2.75 - 2·msM_subwin, Q29
    let tmp: i32 = 1_191_182_336;
    let scalar = l_sub(tmp, l_mult(round_word(tmp), ms_m_win));
    let tmp: i32 = 1_476_395_008;
    let scalar2 = l_sub(tmp, l_mult(round_word(tmp), ms_m_subwin));

    for j in start..stop {
        // Compute the first and second moments of the PSD
        let mut tmp = b.ms_alpha[j].min(1_920_767_767);
        let mut s1 = WORD32_BITS - 1;
        if tmp != 0 {
            s1 = norm_l(tmp);
        }
        let s2 = shl(s1, 1).min(WORD32_BITS - 1);

        // beta = msAlpha²
        let tmp16 = round_word(l_shl(tmp, s1));
        let beta = mult_r(tmp16, tmp16);

        // scalar3 = msPsd - msPsdFirstMoment, normalised
        let mut scalar3 = l_sub(
            l_deposit_l(b.ms_psd[j]),
            l_deposit_l(b.ms_psd_first_moment[j]),
        );
        let s3 = norm_l(scalar3);
        scalar3 = l_shl(scalar3, s3);

        // msPsdFirstMoment = beta·msPsdFirstMoment + (1 - beta)·msPsd
        tmp = l_msu(l_mult(beta, b.ms_psd_first_moment[j]), beta, b.ms_psd[j]);
        b.ms_psd_first_moment[j] = add(round_word(l_shr(tmp, s2)), b.ms_psd[j]);

        // msPsdSecondMoment = beta·msPsdSecondMoment + (1 - beta)·scalar3²
        let tmp0 = l_shr(mpy_32_16_r(b.ms_psd_second_moment[j], beta), s2);
        let mut tmp1 = mpy_32_32(scalar3, scalar3);
        tmp1 = l_shr(
            l_sub(tmp1, l_shr(mpy_32_16_r(tmp1, beta), s2)),
            sub(shl(s3, 1), 32),
        );
        b.ms_psd_second_moment[j] = l_add(tmp0, tmp1);

        // Compute the bias correction Bmin for the minimum estimation
        let mut qeq_inv: i16 = 6554; // 0.2 Q15
        if b.ms_noise_floor[j] != 0 {
            let tmp = l_mult(b.ms_noise_floor[j], b.ms_noise_floor[j]);
            let mut s: i16 = 0;
            let tmp16 = basop_util_divide3232_uu_1616_scale(b.ms_psd_second_moment[j], tmp, &mut s);
            // Q15 with exponent s, the scaled 2·msPsdSecondMoment/msNoiseFloor²
            s = sub(s, 1).clamp(-(WORD16_BITS - 1), WORD16_BITS - 1);
            if s < 0 {
                qeq_inv = shl(tmp16, s);
            }
            qeq_inv = qeq_inv.min(6554);
        }
        qeq_inv_av = l_add(qeq_inv_av, l_mult(qeq_inv, b.psize[j]));

        // msBminWin = 1 + (msM_win - 1)·2·QeqInv/(1 - msM_win·QeqInv), Q27
        let tmp0 = mpy_32_16_1(scalar, qeq_inv);
        let tmp1 = l_sub(1_073_741_824, l_mult(ms_m_win, qeq_inv));
        let mut s: i16 = 0;
        let tmp16 = basop_util_divide3232_uu_1616_scale(tmp0, tmp1, &mut s);
        b.ms_bmin_win[j] = l_add(134_217_728, l_shl(l_deposit_h(tmp16), add(s, 7 - 4)));

        let tmp0 = mpy_32_16_1(scalar2, qeq_inv);
        let tmp1 = l_sub(1_073_741_824, l_mult(ms_m_subwin, qeq_inv));
        let tmp16 = basop_util_divide3232_uu_1616_scale(tmp0, tmp1, &mut s);
        b.ms_bmin_sub_win[j] = l_add(134_217_728, l_shl(l_deposit_h(tmp16), s));
    }

    let mut s: i16 = 0;
    let inv_totsize = basop_util_divide3232_uu_1616_scale(1, i32::from(totsize), &mut s);
    qeq_inv_av = mpy_32_16_1(qeq_inv_av, inv_totsize);
    qeq_inv_av = l_shl(qeq_inv_av, s);
    st.ms_qeq_inv_av[cnt] = qeq_inv_av;

    // New minimum?
    let mut s: i16 = 6 + 2 * 2; // exponent of QeqInvAv
    let mut bmin_corr = mpy_32_16_1(sqrt32(qeq_inv_av, &mut s), 17367); // 2.12·sqrt
    bmin_corr = l_shl(bmin_corr, sub(s, 1));
    bmin_corr = l_add(bmin_corr, 1_073_741_824); // 1 + ..., Q30

    for j in start..stop {
        let scalar = mpy_32_16_1(bmin_corr, b.ms_psd[j]);
        let scalar2 = mpy_32_32(scalar, b.ms_bmin_win[j]);
        b.ms_new_min_flag[j] = 0;
        if l_sub(scalar2, b.ms_current_min[j]) < 0 {
            b.ms_new_min_flag[j] = 1;
            // The minimum over the window, and over the sub-window
            b.ms_current_min[j] = scalar2;
            b.ms_current_min_sub_window[j] = l_shl(mpy_32_32(scalar, b.ms_bmin_sub_win[j]), 5);
        }
    }

    // This is used later to identify local minima
    if sub(st.ms_fr_cnt, MSSUBFRLEN) >= 0 {
        let mut i = 0;
        while i < 3 {
            if l_sub(
                st.ms_qeq_inv_av[cnt],
                l_shr(l_deposit_h(MSQEQINVAV_THRESH[i]), 6),
            ) < 0
            {
                break;
            }
            i += 1;
        }
        st.ms_slope[cnt] = MSNOISESLOPEMAX[i];
    }
}

/// `minimum_statistics`, after the band groups: tracks the minimum over the sub-windows and the
/// window, and updates the noise floor.
fn minimum_statistics_track(len: i16, len_fft: i16, b: &mut MsBuffers<'_>, st: &mut FdCngCom) {
    let lenu = len as usize;
    // Detect sudden offsets based on the FFT bins (core bandwidth)
    if sub(st.ms_fr_cnt, 1) > 0 && sub(st.ms_fr_cnt, MSSUBFRLEN) < 0 {
        // Update the noise floor between buffer updates
        for j in 0..lenu {
            if b.ms_new_min_flag[j] > 0 {
                b.ms_local_min_flag[j] = 1;
            }
            if l_sub(b.ms_current_min_sub_window[j], b.ms_current_min_out[j]) < 0 {
                b.ms_current_min_out[j] = b.ms_current_min_sub_window[j];
            }
        }
        copy_scale_sig_32_16(b.ms_current_min_out, b.ms_noise_floor, len, -16);
    } else if sub(st.ms_fr_cnt, MSSUBFRLEN) >= 0 {
        // Collect buffers and find the minimum over the window
        let at = lenu * st.ms_min_buffer_ptr.max(0) as usize;
        if at + lenu > b.ms_min_buf.len() {
            return;
        }
        b.ms_min_buf[at..at + lenu].copy_from_slice(&b.ms_current_min_sub_window[..lenu]);
        b.ms_current_min_out[..lenu].copy_from_slice(&b.ms_min_buf[..lenu]);
        let mut ptr = lenu;
        for _ in 1..MSNUMSUBFR {
            for j in 0..lenu {
                if l_sub(b.ms_min_buf[ptr], b.ms_current_min_out[j]) < 0 {
                    b.ms_current_min_out[j] = b.ms_min_buf[ptr];
                }
                ptr += 1;
            }
        }
        // Update the local minima
        let mut slope = st.ms_slope[0];
        for j in 0..lenu {
            if j == len_fft as usize {
                slope = st.ms_slope[1];
            }
            if b.ms_local_min_flag[j] != 0
                && b.ms_new_min_flag[j] == 0
                && l_sub(
                    l_shr(b.ms_current_min_sub_window[j], 1),
                    mpy_32_16_1(b.ms_current_min_out[j], slope),
                ) < 0
                && l_sub(b.ms_current_min_sub_window[j], b.ms_current_min_out[j]) > 0
            {
                b.ms_current_min_out[j] = b.ms_current_min_sub_window[j];
                let mut i = j;
                for _ in 0..MSNUMSUBFR {
                    b.ms_min_buf[i] = b.ms_current_min_out[j];
                    i += lenu;
                }
            }
        }
        // Reset
        b.ms_local_min_flag[..lenu].fill(0);
        b.ms_current_min[..lenu].fill(MAX_32);
        // Get the noise floor
        copy_scale_sig_32_16(b.ms_current_min_out, b.ms_noise_floor, len, -16);
    }
}

/// `minimum_statistics`: the reset after a sudden offset in the input energy.
fn minimum_statistics_offset(
    len: i16,
    len_fft: i16,
    cnt: usize,
    b: &mut MsBuffers<'_>,
    st: &mut FdCngCom,
) {
    let lenu = len as usize;
    if l_sub(mpy_32_16_1(st.ms_psd_sum[0], 655), st.ms_periodog_sum[0]) > 0 {
        if st.offsetflag > 0 {
            b.ms_psd[..lenu].copy_from_slice(&b.ms_periodog[..lenu]);
            for j in 0..lenu {
                b.ms_current_min_out[j] = l_deposit_h(b.ms_periodog[j]);
            }
            st.ms_alpha_cor[..cnt.min(2)].fill(MAX_32);
            b.ms_alpha[..lenu].fill(0);
            b.ms_psd_first_moment[..lenu].copy_from_slice(&b.ms_periodog[..lenu]);
            b.ms_psd_second_moment[..lenu].fill(0);
            st.ms_psd_sum[0] = dotp_s(b.ms_periodog, b.psize, len_fft, 4);
            if sub(len_fft, len) < 0 {
                let lf = len_fft as usize;
                st.ms_psd_sum[1] =
                    dotp_s(&b.ms_periodog[lf..], &b.psize[lf..], sub(len, len_fft), 4);
            }
        }
        st.offsetflag = 1;
    } else {
        st.offsetflag = 0;
    }
}

/// `bandcombinepow`: combines the `nband` band powers `bandpow` (exponent `exp_bandpow`) into
/// the `npart` partition powers `partpow` (mean over each partition), exponent `exp_partpow`.
pub fn bandcombinepow(
    bandpow: &[i32],
    exp_bandpow: i16,
    nband: i16,
    part: &[i16],
    npart: i16,
    psize_inv: &[i16],
    partpow: &mut [i32],
    exp_partpow: &mut i16,
) {
    let mut fac_tab_exp = [0i16; NPART_SHAPING];
    let smin: i16;
    if sub(nband, npart) == 0 {
        let n = nband.max(0) as usize;
        partpow[..n].copy_from_slice(&bandpow[..n]);
        smin = 0;
    } else {
        let np = (npart.max(0) as usize).min(NPART_SHAPING);
        // Determine the scaling factor for each partition
        let mut prev_part: i16 = -1;
        for p in 0..np {
            let len = sub(part[p], prev_part);
            let from = (prev_part + 1).max(0) as usize;
            fac_tab_exp[p] = get_scale_factor32(&bandpow[from..], len);
            prev_part = part[p];
        }
        let mut s = WORD32_BITS - 1;
        for &f in &fac_tab_exp[..np] {
            s = s.min(f);
        }
        smin = s;
        let mut i: usize = 0;
        for p in 0..np {
            let mut temp: i32 = 0;
            while i as i32 <= i32::from(part[p]) {
                temp = l_add(
                    temp,
                    mpy_32_16_1(l_shl(bandpow[i], fac_tab_exp[p]), psize_inv[p]),
                );
                i += 1;
            }
            partpow[p] = l_shr(temp, sub(fac_tab_exp[p], smin));
        }
    }
    *exp_partpow = sub(exp_bandpow, smin);
}

/// `scalebands`: interpolates the `npart` partition powers `partpow` back to the `nband` band
/// powers `bandpow`, linearly in the log domain between the partitions' midbands (the first
/// `nFFTpart` only when `flag_fft_en` is set).
pub fn scalebands(
    partpow: &[i32],
    part: &[i16],
    npart: i16,
    midband: &[i16],
    n_ff_tpart: i16,
    nband: i16,
    bandpow: &mut [i32],
    flag_fft_en: i16,
) {
    if sub(nband, npart) == 0 {
        let n = npart.max(0) as usize;
        bandpow[..n].copy_from_slice(&partpow[..n]);
        return;
    }
    let mut start_band: i16 = 0;
    let mut start_part: i16 = 0;
    let mut stop_part = n_ff_tpart;
    while sub(start_band, nband) < 0 {
        if stop_part <= 0 || stop_part > npart {
            // The reference would index before part / past the partitions here.
            return;
        }
        let stop_part_m1 = sub(stop_part, 1);
        if flag_fft_en != 0 || sub(start_part, n_ff_tpart) >= 0 {
            if start_part >= stop_part {
                // midband[startPart] would be read past the partitions.
                return;
            }
            scalebands_group(
                partpow, part, midband, start_band, start_part, stop_part, bandpow,
            );
        }
        let next = add(part[stop_part_m1 as usize], 1);
        if next <= start_band && stop_part == npart {
            // No progress: the reference would loop forever.
            return;
        }
        start_band = next;
        start_part = stop_part;
        stop_part = npart;
    }
}

/// One group of partitions of [`scalebands`]: flat up to the first midband, log-linear between
/// midbands, extrapolated after the last one.
fn scalebands_group(
    partpow: &[i32],
    part: &[i16],
    midband: &[i16],
    start_band: i16,
    start_part: i16,
    stop_part: i16,
    bandpow: &mut [i32],
) {
    let stop_part_m1 = (stop_part - 1) as usize;
    let stop_part = stop_part as usize;
    let mut j = start_part as usize;
    let mut i = start_band.max(0) as usize;
    let mut partpow_ld64_m1: i32 = 0;

    // first half partition
    while i as i32 <= i32::from(midband[j]) {
        bandpow[i] = partpow[j];
        i += 1;
    }
    j += 1;
    if j < stop_part {
        partpow_ld64_m1 = basop_util_log2(partpow[j - 1]);
    }

    // inner partitions
    let mut delta: i16 = 0x4000;
    let mut delta_cmp: i16 = 0x4000;
    let mut s1: i16 = 1;
    let mut s: i16 = 1;
    while j < stop_part {
        let nint = sub(midband[j], midband[j - 1]);
        // log-linear interpolation
        let partpow_ld64 = basop_util_log2(partpow[j]);
        let mut tmp = l_sub(partpow_ld64, partpow_ld64_m1);
        tmp = mpy_32_16_1(tmp, get_norm_reciprocal_word16(nint));
        // tmp = log2(delta) in Q25; delta in [1/2, 1] with exponent delta_s
        tmp = l_sub(tmp, 67_108_864);
        let mut delta_s: i16 = 2;
        while tmp > 0 {
            tmp = l_sub(tmp, 33_554_432);
            delta_s = add(delta_s, 1);
        }
        delta_cmp = shl(1, sub(WORD16_BITS - 1, delta_s).max(-15));
        tmp = basop_util_inv_log2(tmp);
        s = norm_l(tmp);
        s1 = sub(delta_s, s);
        delta = round_word(l_shl(tmp, s));
        // Choose scale such that the interpolation start and end point both are representable
        delta_s = sub(norm_l(partpow[j - 1]).min(norm_l(partpow[j])), 1);
        let mut val = l_shl(partpow[j - 1], delta_s);
        while (i as i32) < i32::from(midband[j]) {
            val = l_shl(mpy_32_16_1(val, delta), s1);
            bandpow[i] = l_shr(val, delta_s);
            i += 1;
        }
        bandpow[i] = partpow[j];
        i += 1;
        partpow_ld64_m1 = partpow_ld64;
        j += 1;
    }

    if sub(shr(delta, s), delta_cmp) > 0 {
        delta = 0x4000;
        s1 = 1;
    }

    // last half partition
    let mut val = partpow[stop_part_m1];
    while i as i32 <= i32::from(part[stop_part_m1]) {
        val = l_shl(mpy_32_16_1(val, delta), s1);
        bandpow[i] = val;
        i += 1;
    }
}

/// `getmidbands`: the midband, size, normalised size (exponent `psize_norm_exp`) and inverse
/// size of each of the `npart` partitions with upper bounds `part`.
pub fn getmidbands(
    part: &[i16],
    npart: i16,
    midband: &mut [i16],
    psize: &mut [i16],
    psize_norm: &mut [i16],
    psize_norm_exp: &mut i16,
    psize_inv: &mut [i16],
) {
    let np = npart.max(0) as usize;
    // first half partition
    midband[0] = part[0];
    psize[0] = add(part[0], 1);
    psize_inv[0] = get_norm_reciprocal_word16(psize[0]);
    // inner partitions
    for j in 1..np {
        midband[j] = shr(add(add(part[j - 1], 1), part[j]), 1);
        psize[j] = sub(part[j], part[j - 1]);
        psize_inv[j] = get_norm_reciprocal_word16(psize[j]);
    }
    let shift: i16 = 9;
    *psize_norm_exp = sub(15, shift);
    for j in 0..np {
        psize_norm[j] = shl(psize[j], shift);
    }
}

/// `AnalysisSTFT`: windows the overlap buffer and the new `frameSize` samples of
/// `time_domain_input` (shifted right by `q`) and takes their real FFT into `fft_buffer`
/// (exponent `fft_buffer_exp`).
///
/// `olap_buffer_ana` is the buffer `st.olap_buffer_ana` is an offset into (the decoder's
/// `FdCngDec::olap_buffer_ana`); nothing is done without that offset, which the reference asserts
/// is set. The window is `st.olap_win_ana`.
pub fn analysis_stft(
    time_domain_input: &[i16],
    q: i16,
    fft_buffer: &mut [i32],
    fft_buffer_exp: &mut i16,
    st: &FdCngCom,
    olap_buffer_ana: &mut [i16],
) {
    let Some(olap_at) = st.olap_buffer_ana else {
        return;
    };
    let olap_buffer = &mut olap_buffer_ana[olap_at..];
    let olap_win = st.olap_win_ana;

    *fft_buffer_exp = 1;
    let len = sub(st.fftlen, st.frame_size);
    if len < 0
        || len as usize > FFTLEN2
        || olap_win.len() < (len as usize / 2).max(st.frame_size.max(0) as usize / 2)
    {
        return;
    }
    let len = len as usize;

    // Window the signal
    let len2 = len / 2;
    for i in 0..len2 {
        fft_buffer[i] = l_mult(olap_buffer[i], mult_r(olap_win[i].v.im, 23170));
        fft_buffer[i + len2] = l_mult(
            olap_buffer[i + len2],
            mult_r(olap_win[len2 - 1 - i].v.re, 23170),
        );
    }
    let len2 = shr(st.frame_size, 1).max(0) as usize;
    for i in 0..len2 {
        fft_buffer[i + len] = l_mult(
            shr(time_domain_input[i], q),
            mult_r(olap_win[i].v.re, 23170),
        );
        fft_buffer[i + len + len2] = l_mult(
            shr(time_domain_input[i + len2], q),
            mult_r(olap_win[len2 - 1 - i].v.im, 23170),
        );
    }

    // Perform FFT
    basop_rfft(fft_buffer, st.fftlen, fft_buffer_exp, -1);

    let at = sub(st.frame_size, len as i16).max(0) as usize;
    for i in 0..len {
        olap_buffer[i] = shr(time_domain_input[at + i], q);
    }
}

/// The spectrum [`synthesis_stft`] transforms: a caller's buffer, or the state's own `fftBuffer`
/// (the reference passes `st->fftBuffer` together with `st`).
pub enum StftSpectrum<'a> {
    /// A spectrum outside the state.
    Local(&'a mut [i32]),
    /// `st.fft_buffer`.
    Common,
}

/// The overlap buffer [`synthesis_stft`] adds into: the state's own `olapBufferSynth`, or one
/// outside it (`olapBufferSynth2`, the owning `FdCngDec`'s buffer).
pub enum StftOverlap<'a> {
    /// `st.olap_buffer_synth`.
    Common,
    /// A buffer outside the state.
    External(&'a mut [i16]),
}

/// `SynthesisSTFT`: inverse real FFT of `fft_buffer` (exponent `fft_buffer_exp`), windowed
/// overlap-add into `olap_buffer`, `frameSize` output samples into `time_domain_output`.
/// `tcx_transition` skips the overlap with the previous frame. `gen_exc` 1 or 2 also computes the
/// CNG excitation `st.exc_cng` (the pre-emphasised output through `A_cng`), at the scaling
/// `q_new` (1: given, 2: chosen and written back).
pub fn synthesis_stft(
    fft_buffer: StftSpectrum<'_>,
    mut fft_buffer_exp: i16,
    time_domain_output: &mut [i16],
    olap_buffer: StftOverlap<'_>,
    olap_win: &[PWord16],
    tcx_transition: i16,
    st: &mut FdCngCom,
    gen_exc: i16,
    q_new: &mut i16,
) {
    let FdCngCom {
        fft_buffer: common_fft,
        olap_buffer_synth,
        fftlen,
        frame_size,
        fftlen_shift,
        fftlen_fac,
        a_cng,
        exc_cng,
        ..
    } = st;
    let fft: &mut [i32] = match fft_buffer {
        StftSpectrum::Local(buffer) => buffer,
        StftSpectrum::Common => &mut common_fft[..],
    };
    let olap: &mut [i16] = match olap_buffer {
        StftOverlap::Common => &mut olap_buffer_synth[..],
        StftOverlap::External(buffer) => buffer,
    };
    let (fftlen, frame_size, fftlen_shift, fftlen_fac) =
        (*fftlen, *frame_size, *fftlen_shift, *fftlen_fac);
    let fl = fftlen.max(0) as usize;
    let fs = frame_size.max(0) as usize;
    if fl > fft.len() || fl > olap.len() || 2 * fs > olap.len() {
        return;
    }

    // Perform IFFT
    let mut scale: i16 = 0;
    basop_rfft(fft, fftlen, &mut scale, 1);
    fft_buffer_exp = add(fft_buffer_exp, scale);
    fft_buffer_exp = add(fft_buffer_exp, fftlen_shift);
    let e = fft_buffer_exp.wrapping_sub(15);

    // Perform overlap-add
    olap.copy_within(fs..2 * fs, 0);
    olap[fs..2 * fs].fill(0);

    let len2 = shr(fftlen, 2) as usize;
    let len4 = shr(fftlen, 3) as usize;
    let len3 = len2 + len4;
    let mut len = fs + len4;
    if tcx_transition != 0 {
        for i in 0..len {
            olap[i] = round_word(l_shl(fft[i], e));
        }
    } else {
        for i in 0..len4 {
            olap[i + len4] = add(
                olap[i + len4],
                mult_r(round_word(l_shl(fft[i + len4], e)), olap_win[i].v.im),
            );
            olap[i + 2 * len4] = add(
                olap[i + 2 * len4],
                mult_r(
                    round_word(l_shl(fft[i + 2 * len4], e)),
                    olap_win[len4 - 1 - i].v.re,
                ),
            );
        }
        for i in len3..len {
            olap[i] = round_word(l_shl(fft[i], e));
        }
    }
    for i in 0..len4 {
        olap[i + 5 * len4] = mult_r(round_word(l_shl(fft[i + 5 * len4], e)), olap_win[i].v.re);
        olap[i + 6 * len4] = mult_r(
            round_word(l_shl(fft[i + 6 * len4], e)),
            olap_win[len4 - 1 - i].v.im,
        );
    }
    len += len2;
    for o in olap.iter_mut().take(fl).skip(len) {
        *o = 0;
    }

    // Get the output data
    for i in 0..fs {
        time_domain_output[i] = mult_r(olap[i + len4], fftlen_fac);
    }

    if gen_exc == 1 || gen_exc == 2 {
        // The output with M + 1 samples of history, pre-emphasised, through A_cng
        let mut buf = [0i16; M + 1 + FFTLEN2];
        let n = M + 1 + fs;
        if fs > FFTLEN2 || len4 < M + 1 {
            return;
        }
        for i in 0..n {
            buf[i] = mult_r(olap[i + len4 - M - 1], fftlen_fac);
        }
        let mut tmp = buf[0];
        let lg = (M + fs) as i16;
        if gen_exc == 1 {
            e_util_f_preemph2(q_new.wrapping_sub(1), &mut buf[1..], 22282, lg, &mut tmp);
        } else {
            *q_new = e_util_f_preemph3(&mut buf[1..], 22282, lg, &mut tmp, 1);
        }
        residu3(&a_cng[..], &buf, 1 + M, &mut exc_cng[..], frame_size, 1);
    }
}

/// `mhvals`: the minimum-statistics bias constant `M(d)` for a window of `d` frames (72 or 12),
/// interpolated in `sqrt(d)` between the tabulated points.
pub fn mhvals(d: i16, m: &mut i16) {
    let len = D_ARRAY.len();
    let mut i = 0usize;
    while i < len {
        if sub(d, D_ARRAY[i]) <= 0 {
            break;
        }
        i += 1;
    }
    let j = if i == len {
        i = len - 1;
        i
    } else {
        i.saturating_sub(1)
    };
    if sub(d, D_ARRAY[i]) == 0 {
        *m = M_ARRAY[i];
        return;
    }
    if i == 0 {
        // The reference would read d_array[-1]; d is 12 or 72 at every call site.
        *m = M_ARRAY[0];
        return;
    }
    // d_array[j] < d < d_array[i]
    let mut qj_e: i16 = 15;
    let mut qj_m = l_deposit_h(D_ARRAY[i - 1]);
    let mut qi_e: i16 = 15;
    let mut qi_m = l_deposit_h(D_ARRAY[i]);
    let mut q_e: i16 = 15;
    let mut q_m = l_deposit_h(d);

    qj_m = sqrt32(qj_m, &mut qj_e);
    qi_m = sqrt32(qi_m, &mut qi_e);
    q_m = sqrt32(q_m, &mut q_e);

    let mut tmp1_m = mpy_32_32(qi_m, qj_m);
    let mut tmp1_e = add(qi_e, qj_e);
    let mut shift: i16 = 0;
    tmp1_m = l_deposit_h(basop_util_divide3232_scale(tmp1_m, q_m, &mut shift));
    tmp1_e = sub(tmp1_e, q_e);
    tmp1_e = add(tmp1_e, shift);
    let tmp1_e_in = tmp1_e;
    tmp1_m = basop_util_add_mant32_exp(tmp1_m, tmp1_e_in, l_negate(qj_m), qj_e, &mut tmp1_e);

    let mut tmp2_e: i16 = 0;
    let mut tmp2_m = basop_util_add_mant32_exp(qi_m, qi_e, l_negate(qj_m), qj_e, &mut tmp2_e);
    let tmp1_w16_m_in = round_word(tmp2_m);
    let tmp1_w16_e_in = tmp2_e;
    let mut tmp1_w16_m: i16 = 0;
    let mut tmp1_w16_e: i16 = 0;
    basop_util_divide_mant_exp(
        sub(M_ARRAY[j], M_ARRAY[i]),
        0,
        tmp1_w16_m_in,
        tmp1_w16_e_in,
        &mut tmp1_w16_m,
        &mut tmp1_w16_e,
    );
    tmp2_m = mpy_32_16_1(tmp1_m, tmp1_w16_m);
    tmp2_e = add(tmp1_e, tmp1_w16_e);

    let tmp2_e_in = tmp2_e;
    tmp2_m = basop_util_add_mant32_exp(tmp2_m, tmp2_e_in, l_deposit_h(M_ARRAY[i]), 0, &mut tmp2_e);
    *m = extract_h(tmp2_m);
}

/// `rand_gauss`: an approximately Gaussian random number, the sum of three uniform 16-bit ones
/// shifted up by 14; `seed` advances three times.
pub fn rand_gauss(seed: &mut i16) -> i32 {
    let mut loc_seed = extract_l(l_mac0(13849, *seed, 31821));
    let mut temp = l_deposit_l(loc_seed);

    loc_seed = extract_l(l_mac0(13849, loc_seed, 31821));
    temp = l_msu0(temp, loc_seed, -1);

    loc_seed = extract_l(l_mac0(13849, loc_seed, 31821));
    temp = l_msu0(temp, loc_seed, -1);

    *seed = loc_seed;
    l_shl(temp, WORD16_BITS - 2)
}

/// `lpc_from_spectrum`: LP coefficients `a[0..=lpcorder]` (Q12) of the power spectrum
/// `powspec[0..stop - start]` (exponent `powspec_exp`, bins `start..stop` of an `fftlen` FFT): the
/// spectrum floored at a noise floor `1e-3`, pre-emphasised by `preemph_fac` (Q15; 0 for none),
/// inverse real FFT to the autocorrelation, a 1.0005 white-noise correction on lag 0, then
/// Levinson-Durbin.
pub fn lpc_from_spectrum(
    powspec: &[i32],
    powspec_exp: i16,
    start: i16,
    stop: i16,
    fftlen: i16,
    a: &mut [i16],
    lpcorder: i16,
    preemph_fac: i16,
) {
    let mut fft_buffer = [0i32; 2 * FFTLEN2];
    let mut r = [0i32; 32];
    let mut r_h = [0i16; 32];
    let mut r_l = [0i16; 32];
    let mut scale: i16 = 0;
    let fftlen_us = (fftlen.max(0) as usize).min(2 * FFTLEN2);
    let fftlen2 = shr(fftlen, 1);
    let fftlen4 = shr(fftlen, 2);
    let fftlen8 = shr(fftlen, 3).max(1) as usize;
    let order = (lpcorder.max(0) as usize).min(r.len() - 1);

    // Power Spectrum
    let mut max_val: i32 = 0;
    let len = sub(stop, start).max(0) as usize;
    for &value in &powspec[..len] {
        max_val = max_val.max(l_abs(value));
    }
    let s1 = norm_l(max_val);
    let nf = l_shr_r(1_099_511_680, add(sub(powspec_exp, s1), 9)); // 1e-3f Q40

    let start_us = start.max(0) as usize;
    let stop_us = stop.max(0) as usize;
    let half = (fftlen2.max(0) as usize).min(FFTLEN2);
    for i in 0..half {
        fft_buffer[2 * i] = if i < start_us || i >= stop_us {
            nf
        } else {
            nf.max(l_shl(powspec[i - start_us], s1))
        };
        fft_buffer[2 * i + 1] = l_deposit_l(0);
    }

    fft_buffer[1] = nf;

    // Pre-emphasis
    let table = basop_get_tables(fftlen4).twiddle;
    let tmp = round_word(l_shr(
        l_add(0x4000_0000, l_mult0(preemph_fac, preemph_fac)),
        1,
    ));
    let preemph_fac2 = shr(preemph_fac, 1);
    let re = |i: usize| shr(table[i].v.re, 1);
    let im = |i: usize| shr(table[i].v.im, 1);
    let mut ptr: usize = 0;
    fft_buffer[ptr] = mpy_32_16_1(fft_buffer[ptr], sub(tmp, preemph_fac2));
    ptr += 2;
    for i in 1..fftlen8 {
        fft_buffer[ptr] = mpy_32_16_1(
            fft_buffer[ptr],
            sub(tmp, mult_r(preemph_fac2, add(re(i - 1), re(i)))),
        );
        ptr += 2;
    }
    fft_buffer[ptr] = mpy_32_16_1(
        fft_buffer[ptr],
        sub(
            tmp,
            mult_r(preemph_fac2, add(re(fftlen8 - 1), im(fftlen8 - 1))),
        ),
    );
    ptr += 2;
    for i in 1..fftlen8 {
        fft_buffer[ptr] = mpy_32_16_1(
            fft_buffer[ptr],
            sub(
                tmp,
                mult_r(preemph_fac2, add(im(fftlen8 - i - 1), im(fftlen8 - i))),
            ),
        );
        ptr += 2;
    }
    fft_buffer[ptr] = mpy_32_16_1(fft_buffer[ptr], tmp);
    ptr += 2;
    for i in 1..fftlen8 {
        fft_buffer[ptr] = mpy_32_16_1(
            fft_buffer[ptr],
            add(tmp, mult_r(preemph_fac2, add(im(i - 1), im(i)))),
        );
        ptr += 2;
    }
    fft_buffer[ptr] = mpy_32_16_1(
        fft_buffer[ptr],
        add(
            tmp,
            mult_r(preemph_fac2, add(re(fftlen8 - 1), im(fftlen8 - 1))),
        ),
    );
    ptr += 2;
    for i in 1..fftlen8 {
        fft_buffer[ptr] = mpy_32_16_1(
            fft_buffer[ptr],
            add(
                tmp,
                mult_r(preemph_fac2, add(re(fftlen8 - i - 1), re(fftlen8 - i))),
            ),
        );
        ptr += 2;
    }
    fft_buffer[1] = mpy_32_16_1(fft_buffer[1], add(tmp, preemph_fac2));
    let mut max_val: i32 = 0;
    for &value in &fft_buffer[..fftlen_us] {
        max_val = max_val.max(l_abs(value));
    }
    let s2 = norm_l(max_val);
    for value in &mut fft_buffer[..fftlen_us] {
        *value = l_shl(*value, s2);
    }

    // Autocorrelation
    basop_rfft(&mut fft_buffer, fftlen, &mut scale, 1);

    let mut s3 = get_scale_factor32(&fft_buffer, add(lpcorder, 1));

    for i in 0..=order {
        r[i] = l_shl(fft_buffer[i], s3);
    }

    r[0] = mpy_32_32(r[0], 1_074_278_656); // 1.0005f Q30
    for value in &mut r[1..=order] {
        *value = mpy_32_32(*value, 1_073_741_824); // 1.f Q30
    }
    s3 = get_scale_factor32(&r, add(lpcorder, 1));

    for value in &mut r[..=order] {
        *value = l_shl(*value, s3);
    }

    for i in 0..=order {
        (r_h[i], r_l[i]) = l_extract(r[i]);
    }

    // LPC
    e_lpc_lev_dur(&r_h, &r_l, a, None, lpcorder, None);
}

/// `msvq_decoder`: the multi-stage VQ reconstruction `uq[0..n]` (Q9.7), the sum over `stages`
/// stages of codebook `cb[s]`'s vector `idx[s]` (vectors `max_n` apart). An index beyond its
/// codebook (the indices are bitstream fields sized to the codebooks) contributes nothing.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
pub fn msvq_decoder(cb: &[&[i16]], stages: i16, n: i16, max_n: i16, idx: &[i16], uq: &mut [i16]) {
    let n_us = n.max(0) as usize;
    let stages = (stages.max(0) as usize).min(cb.len());
    let entry = |s: usize, offset: i16, i: usize| -> i16 {
        usize::try_from(offset)
            .ok()
            .and_then(|offset| cb[s].get(offset + i))
            .copied()
            .unwrap_or(0)
    };

    let offset = i_mult(idx[0], max_n);
    for (i, value) in uq.iter_mut().take(n_us).enumerate() {
        *value = entry(0, offset, i);
    }

    for s in 1..stages {
        let offset = i_mult(idx[s], max_n);
        for (i, value) in uq.iter_mut().take(n_us).enumerate() {
            *value = add(*value, entry(s, offset, i));
        }
    }
}

/// `FdCng_exc`: the comfort-noise LP filter and excitation of an FD-CNG frame in the ACELP core.
/// `Aq` gets the CNG filter `A_cng` in every subframe, `lsp_new` / `lsf_new` its LSP / LSF
/// representation, `lsp_cng` the running low-pass of the LSPs (re-initialised from `lsp_old` on the
/// first CNG frame, `first_cng == 0`), `exc` and `exc2` the generated excitation and `bwe_exc` it
/// interpolated to the BWE rate (5/2 at 12.8 kHz, 4/2 at 16 kHz). `cng_mode` is set to -1.
pub fn fd_cng_exc(
    hs: &FdCngCom,
    cng_mode: &mut i16,
    l_frame: i16,
    lsp_old: &[i16],
    first_cng: i16,
    lsp_cng: &mut [i16],
    aq: &mut [i16],
    lsp_new: &mut [i16],
    lsf_new: &mut [i16],
    exc: &mut [i16],
    exc2: &mut [i16],
    bwe_exc: &mut [i16],
) {
    *cng_mode = -1;

    for i in 0..(l_frame / L_SUBFR).max(0) as usize {
        aq[i * (M + 1)..(i + 1) * (M + 1)].copy_from_slice(&hs.a_cng[..M + 1]);
    }

    e_lpc_a_lsp_conversion(aq, lsp_new, lsp_old, M as i16);

    if first_cng == 0 {
        lsp_cng[..M].copy_from_slice(&lsp_old[..M]);
    }
    for i in 0..M {
        // AR low-pass filter
        // Q15 (15 + 15 + 1 - 16)
        lsp_cng[i] = mac_r(
            l_mult(CNG_ISF_FACT_FX, lsp_cng[i]),
            (32768 - i32::from(CNG_ISF_FACT_FX)) as i16,
            lsp_new[i],
        );
    }

    if sub(l_frame, L_FRAME16K) == 0 {
        lsp2lsf(lsp_new, lsf_new, M as i16, i32::from(INT_FS_16K_FX));
    } else {
        e_lpc_lsp_lsf_conversion(lsp_new, lsf_new, M as i16);
    }
    let frame = l_frame.max(0) as usize;
    exc[..frame].copy_from_slice(&hs.exc_cng[..frame]);
    exc2[..frame].copy_from_slice(&hs.exc_cng[..frame]);

    if sub(l_frame, L_FRAME) == 0 {
        interp_code_5over2(exc2, bwe_exc, l_frame);
    } else {
        interp_code_4over2(exc2, bwe_exc, l_frame);
    }
}
