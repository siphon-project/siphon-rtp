//! Frequency-domain comfort noise generation, decoder side (TS 26.442 `lib_dec/fd_cng_dec.c`;
//! TS 26.445 §6.7.3): the decoder-side noise estimation, the SID decoding, the comfort noise and
//! the masking noise added under active speech.
//!
//! The reference passes the FD-CNG state next to the decoder state that owns it
//! (`ApplyFdCng(.., st_fx->hFdCngDec_fx, .., st_fx, ..)`), and some functions an exponent that lives
//! in the decoder state (`&st_fx->Q_exc`). Here a function that needs both takes the decoder state
//! alone, moves its `hFdCngDec_fx` box out for the duration of the call (a pointer move, no
//! allocation) and puts it back before returning.
//!
//! `olapBufferAna` / `olapBufferSynth2` are offsets into the `FdCngDec`'s buffers (see
//! `com::fd_cng_com`); a function on the common state alone takes the owning buffer as a parameter.

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    ACELP_13K20, ACELP_8K00, ACTIVE_FRAME, DELTA_EXPONENT, DELTA_MANTISSA_W32, FB, FD_CNG, FFTLEN,
    FFTLEN2, FRAME_NO_DATA, LD_DATA_SCALE, LP_CNG, L_FRAME, L_FRAME16K, M, MAXVAL_WORD16,
    MAXWORD32, MINVAL_WORD16, MODE2, MSBUFLEN, MSNUMSUBFR, NB, NB_LAST_BAND_SCALE, NPART,
    NPART_SHAPING, SID_2K40, SID_FRAME, SWB, SWB_13K2_LAST_BAND_SCALE, WB, WORD16_BITS,
    WORD32_BITS, ZERO_FRAME,
};
use crate::evs::com::basop_util::{
    basop_util_add_mant32_exp, basop_util_inv_log2, basop_util_log2, dot_word32_16_mant32_exp,
    get_scale_factor32, norm_ll_q31, sqrt32,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::cldfb::CLDFB_ROW;
use crate::evs::com::fd_cng_com::{
    analysis_stft, bandcombinepow, compress_range, create_fd_cng_com, delete_fd_cng_com,
    expand_range, init_fd_cng_com, init_partitions, lpc_from_spectrum, minimum_statistics,
    msvq_decoder, scalebands,
};
use crate::evs::com::lsf_tools::{e_lpc_a_lsp_conversion, lsp2lsf};
use crate::evs::com::rom_basop_util::basop_get_tables;
use crate::evs::dec::state::{DecoderState, FdCngCom, FdCngDec};
use crate::evs::rom::{
    BITS_37BITS, CDK_37BITS, FDCNGSETUP_NB, FDCNGSETUP_SWB1, FDCNGSETUP_SWB2, FDCNGSETUP_WB1,
    FDCNGSETUP_WB2, FDCNGSETUP_WB3, MAXN_37BITS, STAGES_37BITS, T_DIV_L_FRAME,
};
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult, l_shl, l_shr, l_shr_r,
    l_sub, norm_l, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_add_c, l_mac_ns, l_msu_ns, l_mult0, StlFlags};

mod comfort_noise;

pub use comfort_noise::{
    generate_comfort_noise_dec, generate_comfort_noise_dec_hf, generate_masking_noise,
    generate_masking_noise_mdct, generate_masking_noise_update_seed,
};
/// `-(WORD32_BITS - 1)`: the exponent given to a zero mantissa.
const ZERO_EXP: i16 = -(WORD32_BITS - 1);

/// The decoder state's FD-CNG instance taken out for a call; see the module documentation.
fn take_fd_cng(stdec: &mut DecoderState) -> Option<Box<FdCngDec>> {
    stdec.h_fd_cng_dec.take()
}

/// `createFdCngDec`: allocates the (zeroed) decoder FD-CNG state with its common part. Init time
/// only.
pub fn create_fd_cng_dec(h_fd_cng_dec: &mut Option<Box<FdCngDec>>) {
    let mut hs = Box::new(FdCngDec::zeroed());
    create_fd_cng_com(&mut hs.h_fd_cng_com);
    *h_fd_cng_dec = Some(hs);
}

/// `deleteFdCngDec`: releases the decoder FD-CNG state.
pub fn delete_fd_cng_dec(h_fd_cng_dec: &mut Option<Box<FdCngDec>>) {
    if let Some(hs) = h_fd_cng_dec.as_mut() {
        delete_fd_cng_com(&mut hs.h_fd_cng_com);
    }
    *h_fd_cng_dec = None;
}

/// `initFdCngDec`: initialise the decoder FD-CNG state (the common part with the CLDFB `scale`),
/// pointing the common part's analysis / second synthesis overlap buffers at this state's.
pub fn init_fd_cng_dec(hs: &mut FdCngDec, scale: i16) -> i16 {
    // Initialize common
    if let Some(com) = hs.h_fd_cng_com.as_deref_mut() {
        init_fd_cng_com(com, scale);
        com.olap_buffer_ana = Some(0);
        com.olap_buffer_synth2 = Some(0);
    }
    hs.olap_buffer_ana[..320].fill(0);
    hs.olap_buffer_synth2[..FFTLEN as usize].fill(0);

    // Set some counters and flags
    hs.flag_dtx_mode = 0;
    hs.lp_noise = -167_772_160; // -20.f Q23
    hs.lp_speech = 209_715_200; // 25.f Q23

    // Initialization of the noise estimation algorithm
    let np = NPART_SHAPING as usize;
    hs.band_noise_shape[..FFTLEN2 as usize].fill(0);
    hs.band_noise_shape_exp = 0;
    hs.part_noise_shape[..NPART as usize].fill(0);
    hs.part_noise_shape_exp = 0;
    hs.ms_periodog[..np].fill(0);
    hs.ms_periodog_exp = 0;
    hs.ms_alpha[..np].fill(0);
    hs.ms_bmin_win[..np].fill(0);
    hs.ms_bmin_sub_win[..np].fill(0);
    hs.ms_psd[..np].fill(0);
    hs.ms_noise_floor[..np].fill(0);
    hs.ms_noise_est[..np].fill(0);
    hs.ms_noise_est_exp = 0;
    hs.ms_min_buf[..(MSNUMSUBFR * NPART_SHAPING) as usize].fill(2_147_483_647); // 1.0 Q31
    hs.ms_current_min[..np].fill(2_147_483_647);
    hs.ms_current_min_out[..np].fill(2_147_483_647);
    hs.ms_current_min_sub_window[..np].fill(2_147_483_647);
    hs.ms_local_min_flag[..np].fill(0);
    hs.ms_new_min_flag[..np].fill(0);
    hs.ms_psd_first_moment[..np].fill(0);
    hs.ms_psd_second_moment[..np].fill(0);
    hs.ms_periodog_buf[..(MSBUFLEN * NPART_SHAPING) as usize].fill(0);
    hs.ms_periodog_buf_ptr = 0;
    hs.ms_log_periodog[..np].fill(0);
    hs.ms_log_noise_est[..np].fill(0);
    hs.psize_shaping[..np].fill(0);
    hs.n_ff_tpart_shaping = 0;

    0
}

/// `configureFdCngDec`: select the FFT / CLDFB layout for `bandwidth`, `bitrate` (the last active
/// bit rate is kept over SID / no-data frames) and `l_frame`, and derive the SID and shaping
/// partitions, the FFT scaling and the overlap windows.
pub fn configure_fd_cng_dec(hs_dec: &mut FdCngDec, bandwidth: i16, bitrate: i32, l_frame: i16) {
    let Some(hs_com) = hs_dec.h_fd_cng_com.as_deref_mut() else {
        return;
    };

    hs_com.cng_bandwidth = bandwidth;
    if sub(hs_com.cng_bandwidth, FB) == 0 {
        hs_com.cng_bandwidth = SWB;
    }
    if bitrate != i32::from(FRAME_NO_DATA) && l_sub(bitrate, i32::from(SID_2K40)) != 0 {
        hs_com.cng_bitrate = l_add(bitrate, 0);
    }
    hs_com.num_slots = 16;

    if bandwidth == NB {
        // NB configuration
        hs_com.fd_cng_setup = FDCNGSETUP_NB;
        hs_com.num_core_bands = 16;
        hs_com.regular_stop_band = 16;
    } else if sub(bandwidth, WB) == 0 {
        // WB configuration
        if l_sub(hs_com.cng_bitrate, i32::from(ACELP_8K00)) <= 0 && sub(l_frame, L_FRAME) == 0 {
            // FFT 6.4kHz, no CLDFB
            hs_com.fd_cng_setup = FDCNGSETUP_WB1;
            hs_com.num_core_bands = 16;
            hs_com.regular_stop_band = 16;
        } else if l_sub(hs_com.cng_bitrate, i32::from(ACELP_13K20)) <= 0
            || sub(l_frame, L_FRAME) == 0
        {
            // FFT 6.4kHz, CLDFB 8.0kHz
            hs_com.fd_cng_setup = FDCNGSETUP_WB2;
            hs_com.num_core_bands = 16;
            hs_com.regular_stop_band = 20;
            if sub(l_frame, L_FRAME16K) == 0 {
                hs_com.fd_cng_setup = FDCNGSETUP_WB2;
                hs_com.num_core_bands = 20;
                hs_com.regular_stop_band = 20;
                hs_com.fd_cng_setup.fftlen = 640;
                hs_com.fd_cng_setup.stop_fftbin = 256;
            }
        } else {
            // FFT 8.0kHz, no CLDFB
            hs_com.fd_cng_setup = FDCNGSETUP_WB3;
            hs_com.num_core_bands = 20;
            hs_com.regular_stop_band = 20;
        }
    } else if sub(l_frame, L_FRAME) == 0 {
        // SWB/FB configuration: FFT 6.4kHz, CLDFB 14kHz
        hs_com.fd_cng_setup = FDCNGSETUP_SWB1;
        hs_com.num_core_bands = 16;
        hs_com.regular_stop_band = 35;
    } else {
        // FFT 8.0kHz, CLDFB 16kHz
        hs_com.fd_cng_setup = FDCNGSETUP_SWB2;
        hs_com.num_core_bands = 20;
        hs_com.regular_stop_band = 40;
    }
    hs_com.fftlen = hs_com.fd_cng_setup.fftlen;
    hs_com.stop_ff_tbin = hs_com.fd_cng_setup.stop_fftbin;

    // Configure the SID quantizer and the Confort Noise Generator
    hs_com.start_band = 2;
    let sid_partitions = hs_com.fd_cng_setup.sid_partitions;
    let num_partitions = hs_com.fd_cng_setup.num_partitions;
    let last = usize::try_from(num_partitions - 1).unwrap_or(0);
    hs_com.stop_band = add(sid_partitions.get(last).copied().unwrap_or(0), 1);
    init_partitions(
        Some(sid_partitions),
        num_partitions,
        hs_com.start_band,
        hs_com.stop_band,
        &mut hs_com.part,
        &mut hs_com.npart,
        &mut hs_com.midband,
        &mut hs_com.psize,
        &mut hs_com.psize_norm,
        &mut hs_com.psize_norm_exp,
        &mut hs_com.psize_inv,
        0,
    );

    hs_com.n_ff_tpart = 21;
    if sub(hs_com.stop_ff_tbin, 256) == 0 {
        hs_com.n_ff_tpart = 20;
    }
    if sub(hs_com.stop_ff_tbin, 160) == 0 {
        hs_com.n_ff_tpart = 17;
    }

    hs_com.n_cldf_bpart = sub(hs_com.npart, hs_com.n_ff_tpart);
    let n_fft = hs_com.n_ff_tpart.max(0) as usize;
    let n_cldfb = (hs_com.n_cldf_bpart.max(0) as usize).min(hs_com.cldf_bpart.len());
    for j in 0..n_cldfb {
        hs_com.cldf_bpart[j] = sub(
            hs_com.part[j + n_fft],
            hs_com.stop_ff_tbin - hs_com.start_band,
        );
        hs_com.cldf_bpsize_inv[j] = hs_com.psize_inv[j + n_fft];
    }

    let mut stop_band_fr: i16 = 1000 / 25;
    if sub(stop_band_fr, hs_com.stop_ff_tbin) > 0 {
        stop_band_fr = hs_com.stop_ff_tbin;
    }
    init_partitions(
        Some(hs_com.fd_cng_setup.shaping_partitions),
        hs_com.fd_cng_setup.num_shaping_partitions,
        hs_com.start_band,
        hs_com.stop_ff_tbin,
        &mut hs_dec.part_shaping,
        &mut hs_dec.npart_shaping,
        &mut hs_dec.midband_shaping,
        &mut hs_dec.psize_shaping,
        &mut hs_dec.psize_shaping_norm,
        &mut hs_dec.psize_shaping_norm_exp,
        &mut hs_dec.psize_inv_shaping,
        stop_band_fr,
    );
    hs_dec.n_ff_tpart_shaping = hs_dec.npart_shaping;

    match hs_com.fftlen {
        512 => {
            hs_com.fftlen_shift = 8;
            hs_com.fftlen_fac = 32767; // 1.0 Q15
        }
        640 => {
            hs_com.fftlen_shift = 9;
            hs_com.fftlen_fac = 20480; // 0.625 Q15
        }
        // "Unsupported FFT length for FD-based CNG": every setup is 512 or 640
        _ => {}
    }
    hs_com.olap_win_ana = basop_get_tables(shr(hs_com.fftlen, 1)).twiddle;
    hs_com.olap_win_syn = basop_get_tables(shr(hs_com.fftlen, 2)).twiddle;
    hs_com.frame_size = shr(hs_com.fftlen, 1);
}

/// The CLDFB buffers of a frame, as `ApplyFdCng` and the comfort noise generators take them
/// (`Word32 **bufferReal`, `**bufferImag`, `*bufferScale`; each may be null in the reference).
pub struct CldfbBuffers<'a> {
    /// `bufferReal`: one row per time slot.
    pub real: &'a mut [[i32; CLDFB_ROW]],
    /// `bufferImag`
    pub imag: &'a mut [[i32; CLDFB_ROW]],
    /// `bufferScale`: written when bands are generated.
    pub scale: Option<&'a mut i16>,
}

/// `ApplyFdCng`: the FD-CNG of one decoded frame `time_domain_input` (Q `q`) of type
/// `m_frame_type`. On an active frame the decoder-side noise estimate is updated (unless the frame
/// is concealed, clipped, music, or in an LP-CNG DTX phase) and the CNG level follows it; on a SID
/// or no-data frame the SID levels are shaped by the estimated spectrum and, in MODE2, comfort
/// noise is generated into the CLDFB buffers. Returns 0, or -1 for an unknown frame type.
///
/// The FD-CNG state is `stdec.h_fd_cng_dec` (the reference passes both).
pub fn apply_fd_cng(
    time_domain_input: &[i16],
    q: i16,
    cldfb: Option<CldfbBuffers<'_>>,
    m_frame_type: i16,
    stdec: &mut DecoderState,
    conceal_whole_frame: i16,
    is_music: i16,
) -> i16 {
    let Some(mut st) = take_fd_cng(stdec) else {
        return 0;
    };
    let result = apply_fd_cng_on(
        time_domain_input,
        q,
        &mut st,
        m_frame_type,
        stdec,
        conceal_whole_frame,
        is_music,
    );
    stdec.h_fd_cng_dec = Some(st);
    match result {
        ApplyFdCngEnd::Done(value) => value,
        ApplyFdCngEnd::ComfortNoise => {
            // Generate comfort noise during SID or zero frames (the last step of the case, so it
            // runs with the state back in place)
            generate_comfort_noise_dec(cldfb, stdec, 2);
            0
        }
    }
}

/// How [`apply_fd_cng_on`] ends: with the return value, or with the MODE2 comfort noise still to
/// generate.
enum ApplyFdCngEnd {
    Done(i16),
    ComfortNoise,
}

/// [`apply_fd_cng`] with the FD-CNG state moved out of `stdec`.
fn apply_fd_cng_on(
    time_domain_input: &[i16],
    q: i16,
    st: &mut FdCngDec,
    m_frame_type: i16,
    stdec: &mut DecoderState,
    conceal_whole_frame: i16,
    is_music: i16,
) -> ApplyFdCngEnd {
    let Some(com) = st.h_fd_cng_com.as_deref_mut() else {
        return ApplyFdCngEnd::Done(0);
    };
    if sub(com.frame_type_previous, ACTIVE_FRAME) == 0 {
        com.inactive_frame_counter = 0;
    }

    let n_bins = sub(com.stop_ff_tbin, com.start_band);

    match m_frame_type {
        ACTIVE_FRAME => {
            apply_fd_cng_active(
                time_domain_input,
                q,
                st,
                stdec,
                conceal_whole_frame,
                is_music,
                n_bins,
            );
        }
        SID_FRAME | ZERO_FRAME => {
            if m_frame_type == SID_FRAME {
                st.flag_dtx_mode = 1;
            }
            if stdec.cng_type == LP_CNG {
                // Perform noise estimation on inactive phase at the decoder
                perform_noise_estimation_dec(time_domain_input, q, st);
                apply_fd_cng_follow_estimate(st, n_bins);
                if let Some(com) = st.h_fd_cng_com.as_deref_mut() {
                    apply_fd_cng_td_level(com, stdec);
                }
                return ApplyFdCngEnd::Done(0);
            }
            apply_fd_cng_inactive(st, m_frame_type, n_bins);

            if sub(stdec.codec_mode, MODE2) == 0 {
                return ApplyFdCngEnd::ComfortNoise;
            }
        }
        _ => return ApplyFdCngEnd::Done(-1),
    }
    ApplyFdCngEnd::Done(0)
}

/// `bandNoiseShape` from the latest noise estimate (`scalebands` over the shaping partitions).
fn apply_fd_cng_update_shape(st: &mut FdCngDec, n_bins: i16) {
    // Update the shaping parameters
    scalebands(
        &st.ms_noise_est,
        &st.part_shaping,
        st.n_ff_tpart_shaping,
        &st.midband_shaping,
        st.n_ff_tpart_shaping,
        n_bins,
        &mut st.band_noise_shape,
        1,
    );
    st.band_noise_shape_exp = st.ms_noise_est_exp;
}

/// The shaping update, then the CNG level set to the estimate until a SID update overwrites it.
fn apply_fd_cng_follow_estimate(st: &mut FdCngDec, n_bins: i16) {
    apply_fd_cng_update_shape(st, n_bins);
    let Some(com) = st.h_fd_cng_com.as_deref_mut() else {
        return;
    };
    let n = n_bins.max(0) as usize;
    com.cng_noise_level[..n].copy_from_slice(&st.band_noise_shape[..n]);
    com.cng_noise_level_exp = st.band_noise_shape_exp;
}

/// `cngTDLevel`: `sqrt(sum(cngNoiseLevel) / 2 · fftlen / L_frame)`, the sum taken to 64 bits
/// through the carry operators.
fn apply_fd_cng_td_level(com: &FdCngCom, stdec: &mut DecoderState) {
    let flags: &mut StlFlags = &mut stdec.stl;
    let tmp_loop = sub(com.stop_ff_tbin, com.start_band).max(0) as usize;
    let mut l_tmp = l_deposit_h(0);
    let mut l_c = l_deposit_h(0);
    for &level in &com.cng_noise_level[..tmp_loop] {
        flags.carry = false;
        l_tmp = l_add_c(l_tmp, level, flags);
        flags.overflow = false;

        if level < 0 {
            l_c = l_msu_ns(l_c, 0, 0, flags);
        }
        if level >= 0 {
            l_c = l_mac_ns(l_c, 0, 0, flags);
        }
    }
    let mut l_tmp_exp: i16 = 0;
    l_tmp = norm_ll_q31(l_c, l_tmp, &mut l_tmp_exp, flags);
    l_tmp_exp = sub(add(l_tmp_exp, com.cng_noise_level_exp), 1);

    l_tmp = mpy_32_16_1(l_tmp, com.fftlen); // Q16

    let index = l_shl(l_mac(-28000, stdec.l_frame, 95), 1 - 15);
    let index = (index.max(0) as usize).min(T_DIV_L_FRAME.len() - 1);
    l_tmp = mpy_32_16_1(l_tmp, T_DIV_L_FRAME[index]); // Q16,exp -7
    l_tmp_exp = add(l_tmp_exp, -7); // ->Q16, L_tmp_exp
    l_tmp_exp = add(l_tmp_exp, 31 - 16); // ->Q31, L_tmp_exp

    stdec.cng_td_level = round_word(sqrt32(l_tmp, &mut l_tmp_exp));
    stdec.cng_td_level_e = l_tmp_exp;
}

/// `num / denom` of a partition's SID level over its estimated shape, both with `DELTA` added
/// (as the float reference does, to avoid `num > denom`): the factor `fac_tab[k]` and its
/// exponent. `sid_normalised` normalises the SID mantissa before the addition (the active-frame
/// path); the SID-frame path adds to the raw mantissa, as the reference does.
fn shaping_factor(
    com: &FdCngCom,
    part_noise_shape: i32,
    part_noise_shape_exp: i16,
    k: usize,
    sid_normalised: bool,
) -> (i16, i16) {
    let mut l_tmp_exp: i16 = 0;
    let s1 = norm_l(com.sid_noise_est[k]);
    let mut l_tmp = l_shl(com.sid_noise_est[k], s1);
    let normalised_exp = sub(com.sid_noise_est_exp, s1);
    l_tmp = if sid_normalised {
        basop_util_add_mant32_exp(
            l_tmp,
            normalised_exp,
            DELTA_MANTISSA_W32,
            DELTA_EXPONENT,
            &mut l_tmp_exp,
        )
    } else {
        basop_util_add_mant32_exp(
            com.sid_noise_est[k],
            com.sid_noise_est_exp,
            DELTA_MANTISSA_W32,
            DELTA_EXPONENT,
            &mut l_tmp_exp,
        )
    };
    l_tmp = l_shr(l_tmp, 1);
    let mut s = add(l_tmp_exp, 1);
    let num = extract_h(l_tmp);

    let s1 = norm_l(part_noise_shape);
    let l_tmp = l_shl(part_noise_shape, s1);
    let exp_in = sub(part_noise_shape_exp, s1);
    let l_tmp = basop_util_add_mant32_exp(
        l_tmp,
        exp_in,
        DELTA_MANTISSA_W32,
        DELTA_EXPONENT,
        &mut l_tmp_exp,
    );
    s = sub(s, l_tmp_exp);
    let denom = extract_h(l_tmp);

    (div_s(num, denom), s)
}

/// Shape the SID noise levels in each FFT bin by the estimated spectrum: `cngNoiseLevel` per
/// FFT partition is `bandNoiseShape · facTab`, aligned to the largest factor exponent; with
/// `rescale_rest` the CLDFB part of the buffer is brought to the new exponent too (the active
/// path only does that when some factor is nonzero).
fn shape_sid_levels(st: &mut FdCngDec, sid_normalised: bool, rescale_always: bool) {
    let Some(com) = st.h_fd_cng_com.as_deref_mut() else {
        return;
    };
    let mut fac_tab = [0i16; NPART as usize];
    let mut fac_tab_exp = [0i16; NPART as usize];
    let n_fft = (com.n_ff_tpart.max(0) as usize).min(NPART as usize);

    let mut s2 = ZERO_EXP;
    for k in 0..n_fft {
        fac_tab[k] = 0;
        if st.part_noise_shape[k] != 0 {
            let (fac, exp) = shaping_factor(
                com,
                st.part_noise_shape[k],
                st.part_noise_shape_exp,
                k,
                sid_normalised,
            );
            fac_tab[k] = fac;
            fac_tab_exp[k] = exp;
        }
        // Set unique exponent, if mantissa is equal to zero
        if fac_tab[k] == 0 {
            fac_tab_exp[k] = ZERO_EXP;
        }
        s2 = s2.max(fac_tab_exp[k]);
    }

    let mut j: i32 = 0;
    for k in 0..n_fft {
        let s = sub(fac_tab_exp[k], s2).clamp(ZERO_EXP, WORD32_BITS - 1);
        while j <= i32::from(com.part[k]) {
            let ju = j as usize;
            com.cng_noise_level[ju] = l_shl(mpy_32_16_1(st.band_noise_shape[ju], fac_tab[k]), s);
            j += 1;
        }
    }

    // adapt scaling for rest of the buffer
    if rescale_always || sub(s2, ZERO_EXP) != 0 {
        let s = sub(com.cng_noise_level_exp, add(st.band_noise_shape_exp, s2));
        let npart = (com.npart.max(0) as usize).min(NPART as usize);
        for k in n_fft..npart {
            while j <= i32::from(com.part[k]) {
                let ju = j as usize;
                com.cng_noise_level[ju] = l_shl(com.cng_noise_level[ju], s);
                j += 1;
            }
        }
        com.cng_noise_level_exp = add(st.band_noise_shape_exp, s2);
    }
}

/// The `ACTIVE_FRAME` case of `ApplyFdCng`.
fn apply_fd_cng_active(
    time_domain_input: &[i16],
    q: i16,
    st: &mut FdCngDec,
    stdec: &mut DecoderState,
    conceal_whole_frame: i16,
    is_music: i16,
    n_bins: i16,
) {
    let Some(com) = st.h_fd_cng_com.as_deref_mut() else {
        return;
    };
    com.inactive_frame_counter = 0;
    com.sid_frame_counter = 0;
    let last = (com.frame_size - 1).max(0) as usize;

    // set noise estimation inactive during concealment, as no update with noise generated by
    // concealment should be performed.
    let first = i32::from(time_domain_input[0]);
    let final_sample = i32::from(time_domain_input[last]);
    if conceal_whole_frame == 0
        && first < MAXVAL_WORD16
        && first > MINVAL_WORD16
        && final_sample < MAXVAL_WORD16
        && final_sample > MINVAL_WORD16
        && !(st.flag_dtx_mode == 0 && stdec.vad != 0)
        && !(stdec.cng_type == LP_CNG && st.flag_dtx_mode != 0)
        && is_music == 0
        && stdec.ber_detect == 0
    {
        // Perform noise estimation at the decoder
        perform_noise_estimation_dec(time_domain_input, q, st);

        // Update CNG levels
        if st.flag_dtx_mode != 0 && stdec.cng_type == FD_CNG {
            apply_fd_cng_update_shape(st, n_bins);
            let Some(com) = st.h_fd_cng_com.as_deref_mut() else {
                return;
            };
            // This needs to be done only once per inactive phase
            bandcombinepow(
                &st.band_noise_shape,
                st.band_noise_shape_exp,
                n_bins,
                &com.part,
                com.n_ff_tpart,
                &com.psize_inv,
                &mut st.part_noise_shape,
                &mut st.part_noise_shape_exp,
            );
            shape_sid_levels(st, true, false);
        } else {
            // This sets the new CNG levels until a SID update overwrites it
            apply_fd_cng_follow_estimate(st, n_bins);
        }
        if let Some(com) = st.h_fd_cng_com.as_deref_mut() {
            apply_fd_cng_td_level(com, stdec);
        }
    }

    let Some(com) = st.h_fd_cng_com.as_deref_mut() else {
        return;
    };
    let mut l_tmp: i32 = 0;
    // A start at or past the stop band runs no iterations and touches no index, as the C loop does.
    let stop_band = com.stop_ff_tbin.max(0) as usize;
    let start_band = com.start_band.max(0) as usize;
    if start_band < stop_band {
        for &level in &com.cng_noise_level[start_band..stop_band] {
            l_tmp = l_add(l_tmp, l_shr(level, 16));
        }
    }
    let l_tmp_exp = add(com.cng_noise_level_exp, 16);
    if sub(conceal_whole_frame, 1) == 0
        && sub(stdec.nb_lost_cmpt, 1) == 0
        && l_shl(l_tmp, l_tmp_exp) > 21_474_836
    // 0.01f Q31
    {
        // update isf cng estimate for concealment. Do that during concealment, in order to avoid
        // addition clean channel complexity
        lpc_from_spectrum(
            &com.cng_noise_level,
            com.cng_noise_level_exp,
            com.start_band,
            com.stop_ff_tbin,
            com.fftlen,
            &mut com.a_cng,
            M,
            0,
        );
        let mut lsp_cng = [0i16; M as usize];
        e_lpc_a_lsp_conversion(&com.a_cng, &mut lsp_cng, &stdec.lspold_cng, M);
        stdec.lspold_cng = lsp_cng;

        lsp2lsf(&lsp_cng, &mut stdec.lsf_cng, M, stdec.sr_core);
        stdec.plc_background_noise_updated = 1;
    }
}

/// The `SID_FRAME` / `ZERO_FRAME` case of `ApplyFdCng` after the LP-CNG check: the partition
/// shape at the first inactive frame, then on a SID frame the bin levels interpolated from the SID
/// levels (at initialisation) or shaped by the estimated spectrum.
fn apply_fd_cng_inactive(st: &mut FdCngDec, m_frame_type: i16, n_bins: i16) {
    let Some(com) = st.h_fd_cng_com.as_deref_mut() else {
        return;
    };
    com.inactive_frame_counter = add(com.inactive_frame_counter, 1);

    // Detect first non-active frame
    if sub(com.inactive_frame_counter, 1) == 0 {
        // Compute the fine spectral structure of the comfort noise shape using the decoder-side
        // noise estimates
        bandcombinepow(
            &st.band_noise_shape,
            st.band_noise_shape_exp,
            n_bins,
            &com.part,
            com.n_ff_tpart,
            &com.psize_inv,
            &mut st.part_noise_shape,
            &mut st.part_noise_shape_exp,
        );
    }

    if sub(m_frame_type, SID_FRAME) != 0 {
        return;
    }
    if l_sub(
        i32::from(com.ms_fr_cnt_init_counter),
        l_deposit_l(com.ms_fr_cnt_init_thresh),
    ) < 0
    {
        // At initialization, interpolate the bin/band-wise levels from the partition levels
        scalebands(
            &com.sid_noise_est,
            &com.part,
            com.npart,
            &com.midband,
            com.n_ff_tpart,
            sub(com.stop_band, com.start_band),
            &mut com.cng_noise_level,
            1,
        );
        com.cng_noise_level_exp = com.sid_noise_est_exp;
    } else {
        // Interpolate the CLDFB band levels from the SID (partition) levels
        if sub(com.regular_stop_band, com.num_core_bands) > 0 {
            scalebands(
                &com.sid_noise_est,
                &com.part,
                com.npart,
                &com.midband,
                com.n_ff_tpart,
                sub(com.stop_band, com.start_band),
                &mut com.cng_noise_level,
                0,
            );
            com.cng_noise_level_exp = com.sid_noise_est_exp;
        }
        // Shape the SID noise levels in each FFT bin
        shape_sid_levels(st, false, true);
    }
}

/// `perform_noise_estimation_dec`: the decoder-side noise estimate of one frame: STFT analysis of
/// `time_domain_input` (Q `q`), the periodogram of bins `startBand..stopFFTbin` averaged over the
/// shaping partitions, then minimum statistics in the log domain.
pub fn perform_noise_estimation_dec(time_domain_input: &[i16], q: i16, st: &mut FdCngDec) {
    let Some(com) = st.h_fd_cng_com.as_deref_mut() else {
        return;
    };

    // variable initialization
    let start_band = com.start_band;
    let stop_ff_tbin = com.stop_ff_tbin;
    let npart = st.npart_shaping;
    let n_ff_tpart = st.n_ff_tpart_shaping;

    // Perform STFT analysis (into the state's fftBuffer, through a copy: the analysis reads the
    // state while it writes the buffer; it writes the first `fftlen` words only, so the copy
    // starts as the state's buffer and the words past `fftlen` stay as they were)
    let mut fft_buffer = com.fft_buffer;
    let mut fft_buffer_exp: i16 = 0;
    analysis_stft(
        time_domain_input,
        q,
        &mut fft_buffer,
        &mut fft_buffer_exp,
        com,
        &mut st.olap_buffer_ana,
    );
    com.fft_buffer = fft_buffer;

    fft_buffer_exp = add(fft_buffer_exp, WORD16_BITS - 1);

    let mut len = sub(stop_ff_tbin, start_band);

    let sb = start_band.max(0) as usize;
    let mut s = get_scale_factor32(&com.fft_buffer[2 * sb..], 2 * len);
    s = sub(s, 1);

    let mut per: usize = 0;
    let mut ptr_r: usize;
    if start_band == 0 {
        // DC component
        let tmp_r = extract_h(l_shl(com.fft_buffer[0], s));
        com.periodog[per] = l_mult(tmp_r, tmp_r);
        per += 1;
        ptr_r = 2;
        len = sub(len, 1);
    } else {
        ptr_r = 2 * sb;
    }

    for _ in 0..len.max(0) {
        let tmp_r = extract_h(l_shl(com.fft_buffer[ptr_r], s));
        let tmp_i = extract_h(l_shl(com.fft_buffer[ptr_r + 1], s));
        com.periodog[per] = l_mac(l_mult(tmp_r, tmp_r), tmp_i, tmp_i);
        ptr_r += 2;
        per += 1;
    }

    com.periodog_exp = shl(sub(fft_buffer_exp, s), 1);

    // Rescale
    let mut fac: i16 = 20972; // 0.64 Q15
    if sub(com.fftlen, 512) == 0 {
        fac = 16384; // 0.5 Q15
    }
    if sub(com.fftlen, 640) == 0 {
        s = 18;
    }
    if sub(com.fftlen, 512) == 0 {
        s = 17;
    }
    if sub(com.fftlen, 320) == 0 {
        s = 16;
    }

    let len = sub(stop_ff_tbin, start_band).max(0) as usize;
    for value in &mut com.periodog[..len] {
        *value = mpy_32_16_1(*value, fac);
    }
    com.periodog_exp = add(com.periodog_exp, sub(2, s));

    // Adjust to the desired frequency resolution by averaging over spectral partitions for SID
    // transmission
    bandcombinepow(
        &com.periodog,
        com.periodog_exp,
        sub(stop_ff_tbin, start_band),
        &st.part_shaping,
        npart,
        &st.psize_inv_shaping,
        &mut st.ms_periodog,
        &mut st.ms_periodog_exp,
    );

    st.ms_periodog_exp_fft = st.ms_periodog_exp;
    st.ms_periodog_exp_cldfb = st.ms_periodog_exp;

    // Compress MS inputs
    compress_range(
        &st.ms_periodog,
        st.ms_periodog_exp,
        &mut st.ms_log_periodog,
        npart,
    );

    // Call the minimum statistics routine for noise estimation
    minimum_statistics(
        npart,
        n_ff_tpart,
        &st.psize_shaping_norm,
        &st.ms_log_periodog,
        &mut st.ms_noise_floor,
        &mut st.ms_log_noise_est,
        &mut st.ms_alpha,
        &mut st.ms_psd,
        &mut st.ms_psd_first_moment,
        &mut st.ms_psd_second_moment,
        &mut st.ms_min_buf,
        &mut st.ms_bmin_win,
        &mut st.ms_bmin_sub_win,
        &mut st.ms_current_min,
        &mut st.ms_current_min_out,
        &mut st.ms_current_min_sub_window,
        &mut st.ms_local_min_flag,
        &mut st.ms_new_min_flag,
        &mut st.ms_periodog_buf,
        &mut st.ms_periodog_buf_ptr,
        com,
    );

    // Expand MS outputs
    expand_range(
        &st.ms_log_noise_est,
        &mut st.ms_noise_est,
        &mut st.ms_noise_est_exp,
        npart,
    );
}

/// `FdCng_decodeSID`: decode a FD-CNG SID frame: the MSVQ partition levels and the global gain
/// from the bitstream, the levels in the linear domain, interpolated to bins, and the CNG LP
/// filter. The reference passes `corest->hFdCngDec_fx->hFdCngCom` as `st` next to `corest`; here
/// both come from `corest`.
pub fn fd_cng_decode_sid(corest: &mut DecoderState) {
    let Some(mut dec) = take_fd_cng(corest) else {
        return;
    };
    if let Some(st) = dec.h_fd_cng_com.as_deref_mut() {
        fd_cng_decode_sid_on(st, corest);
    }
    corest.h_fd_cng_dec = Some(dec);
}

/// [`fd_cng_decode_sid`] on the common state moved out of `corest`.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
fn fd_cng_decode_sid_on(st: &mut FdCngCom, corest: &mut DecoderState) {
    let mut indices = [0i16; 32];
    let mut v16 = [0i16; 32];
    let mut v = [0i32; 32];

    let preemph_fac = corest.preemph_fac;
    let n = (st.npart.max(0) as usize).min(NPART as usize);

    st.sid_frame_counter = add(st.sid_frame_counter, 1);

    // Read bitstream
    for i in 0..STAGES_37BITS as usize {
        indices[i] = get_next_indice(corest, BITS_37BITS[i]) as i16;
    }
    let index = get_next_indice(corest, 7) as i16;

    // MSVQ decoder
    msvq_decoder(
        &CDK_37BITS,
        STAGES_37BITS,
        st.npart,
        MAXN_37BITS,
        &indices,
        &mut v16,
    );

    for i in 0..n {
        v[i] = l_deposit_h(v16[i]);
    }

    // decode gain, format gain: Q9.23
    let mut gain = l_shl(l_deposit_l(index), WORD32_BITS - 1 - 8);
    gain = l_sub(gain, 503_316_480); // 60.0 Q23
    gain = mpy_32_16_1(gain, 21845); // 2.0f/3.0f Q15

    // Apply gain and undo log; calculate worst case for scaling
    let mut max_val = l_add(i32::MIN, 0); // -1.0 Q31
    for &value in &v[..n] {
        max_val = max_val.max(value);
    }

    max_val = l_add(max_val, gain);
    max_val = l_shl(mpy_32_16_1(max_val, 21771), 1); // 0.66438561897 Q15

    let mut sid_noise_est_exp: i16 = 0;
    while max_val >= 0 {
        sid_noise_est_exp = add(sid_noise_est_exp, 1);
        max_val = max_val.wrapping_sub(33_554_432); // 0.015625 Q31
    }
    st.sid_noise_est_exp = sid_noise_est_exp;
    let e_exp_ld64 = l_shl(
        i32::from(sid_noise_est_exp),
        WORD32_BITS - 1 - LD_DATA_SCALE,
    );

    // format v: Q9.23, format sidNoiseEst: Q6.26, 0.66438561897 = log10(10)/log10(2.0) / 10.0 * 2.0
    for i in 0..n {
        let mut tmp = l_add(v[i], gain);
        tmp = l_shl(mpy_32_16_1(tmp, 21771), 1);
        tmp = l_sub(tmp, e_exp_ld64);
        st.sid_noise_est[i] = basop_util_inv_log2(tmp);
    }

    if n > 0 {
        // NB last band energy compensation
        if st.cng_bandwidth == NB {
            st.sid_noise_est[n - 1] = mpy_32_16_1(st.sid_noise_est[n - 1], NB_LAST_BAND_SCALE);
        }
        if st.cng_bandwidth == SWB && st.cng_bitrate <= i32::from(ACELP_13K20) {
            st.sid_noise_est[n - 1] =
                mpy_32_16_1(st.sid_noise_est[n - 1], SWB_13K2_LAST_BAND_SCALE);
        }
    }

    scalebands(
        &st.sid_noise_est,
        &st.part,
        st.npart,
        &st.midband,
        st.n_ff_tpart,
        st.stop_band - st.start_band,
        &mut st.cng_noise_level,
        1,
    );
    st.cng_noise_level_exp = st.sid_noise_est_exp;

    lpc_from_spectrum(
        &st.cng_noise_level,
        st.cng_noise_level_exp,
        st.start_band,
        st.stop_ff_tbin,
        st.fftlen,
        &mut st.a_cng,
        M,
        preemph_fac,
    );
}

/// `noisy_speech_detection`: track the long-term noise (`lp_noise`, from the noise estimate
/// `ms_noise_est` on inactive frames) and speech (`lp_speech`, from the frame energy on active
/// ones) levels in dB, scaled by `LD_DATA_SCALE + 2` bits, and flag noisy speech when they are
/// within 28 dB.
pub fn noisy_speech_detection(
    vad: i16,
    ftime_in_ptr: &[i16],
    frame_size: i16,
    q: i16,
    ms_noise_est: &[i32],
    ms_noise_est_exp: i16,
    psize_norm: &[i16],
    psize_norm_exp: i16,
    n_ff_tpart: i16,
    lp_noise: &mut i32,
    lp_speech: &mut i32,
    flag_noisy_speech: &mut i16,
) {
    if vad == 0 {
        let mut total_noise_exp: i16 = 0;
        let total_noise = dot_word32_16_mant32_exp(
            ms_noise_est,
            ms_noise_est_exp,
            psize_norm,
            psize_norm_exp,
            n_ff_tpart,
            &mut total_noise_exp,
        );

        // logTotalNoise = 10.0 * log10(totalNoise + DELTA), scaled by LD_DATA_SCALE+2;
        // -0.78125 = 10.0*log10(DELTA)/(1<<(LD_DATA_SCALE+2)),
        // 0.75257498916 = 10.0 * log10(2.0)/log10(10.0)/(1<<2)
        let log_total_noise = if total_noise == 0 {
            l_add(-1_677_721_600, 0) // -0.78125 Q31
        } else {
            let log = basop_util_log2(total_noise);
            let log_exp = l_shl(
                l_deposit_l(total_noise_exp),
                WORD32_BITS - 1 - LD_DATA_SCALE,
            );
            mpy_32_16_1(l_add(log, log_exp), 24660) // 0.75257498916 Q15
        };

        *lp_noise = l_add(
            mpy_32_16_1(*lp_noise, 32604),                 // 0.995 Q15
            l_shr(mpy_32_16_1(log_total_noise, 20972), 7), // 0.64 Q15
        );
    } else {
        let mut etot: i32 = 0;
        let mut etot_exp: i16 = 31;
        for &x in &ftime_in_ptr[..frame_size.max(0) as usize] {
            let mut tmp = l_shr_r(l_mult0(x, x), sub(etot_exp, 31));
            if l_sub(MAXWORD32, tmp) < etot {
                etot_exp = add(etot_exp, 1);
                etot = l_shr_r(etot, 1);
                tmp = l_shr_r(tmp, 1);
            }
            etot = l_add(etot, tmp);
        }
        etot_exp = sub(etot_exp, shl(q, 1));

        // logEtot = 10.0 * log10(totalNoise + DELTA), scaled by LD_DATA_SCALE+2
        let log_etot = if etot == 0 {
            l_add(-1_677_721_600, 0) // -0.78125 Q31
        } else {
            let log = basop_util_log2(etot);
            let log_exp = l_shl(l_deposit_l(etot_exp), WORD32_BITS - 1 - LD_DATA_SCALE);
            let log_etot = mpy_32_16_1(l_add(log, log_exp), 24660); // 0.75257498916 Q15
            if sub(frame_size, L_FRAME16K) == 0 {
                l_add(log_etot, -184_894_985) // -0.086098436822497 Q31
            } else {
                l_add(log_etot, -176_765_584) // -0.082312889439370 Q31
            }
        };

        *lp_speech = l_add(
            mpy_32_16_1(*lp_speech, 32604),         // 0.995 Q15
            l_shr(mpy_32_16_1(log_etot, 20972), 7), // 0.64 Q15
        );
    }

    let tmp = l_sub(*lp_speech, 377_487_360); // 45.0 Q23

    if l_sub(*lp_noise, tmp) < 0 {
        *lp_noise = tmp;
    }

    *flag_noisy_speech = 0;
    if l_sub(l_sub(*lp_speech, *lp_noise), 234_881_024) < 0 {
        // 28.0 Q23
        *flag_noisy_speech = 1;
    }
}
