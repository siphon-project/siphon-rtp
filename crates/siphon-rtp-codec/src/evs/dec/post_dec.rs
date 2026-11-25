//! Post-processing of the MODE2 decoder (TS 26.442 `lib_dec/post_dec.c`; TS 26.445 §6.1.4 (formant
//! and bass post-filter) and §6.3.x (bandwidth detection for AMR-WB IO)).
//!
//! `Overflow` and `Carry`: nothing in this file reads them.

use crate::evs::basop::{mpy_32_16_1, mult_32_16};
use crate::evs::cnst::{
    ACELP_CORE, AUDIO, CLDFB_NO_CHANNELS_MAX, GENERIC, LP_NOISE_THRESH, L_FRAME_MAX, L_SUBFR,
    L_SYN_MEM, M, NB, NBPSF_PIT_MAX, PIT_MAX_16K, SID_2K40, UNVOICED, WB,
};
use crate::evs::com::basop_util::{
    basop_util_divide3232_scale, basop_util_inv_log2, basop_util_log2, get_scale_factor16,
};
use crate::evs::com::cldfb::CLDFB_ROW;
use crate::evs::com::deemph::deemph;
use crate::evs::com::preemph::preemph_copy_in_place;
use crate::evs::com::residu::residu3;
use crate::evs::com::syn_filt::e_util_synthesis;
use crate::evs::com::tools::{set16, sum16};
use crate::evs::dec::dec_post::{blend_subfr2, formant_post_filt, nb_post_filt, scale_st};
use crate::evs::dec::state::{CldfbScaleFactor, DecoderState};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult, l_shl, l_shr,
    l_sub, mult_r, norm_l, norm_s, round_word, shl, sub,
};
use crate::itu::stl2009::{l_mac0, l_msu0, l_mult0, mac_r};

/// `M` as an index.
const MU: usize = M as usize;

/// `synth_buf2` of `post_decoder`: `PIT_MAX_16k + 1 + L_FRAME_MAX + M` samples.
const SYNTH_BUF2_LEN: usize = (PIT_MAX_16K + 1 + L_FRAME_MAX + M) as usize;

/// `post_decoder`: post-process one decoded frame. `synth_buf` holds `old_synth_len` samples of
/// history and then the `L_frame` samples of the frame (the TCX-only path overwrites the sixteen
/// samples before the frame and the start of the buffer, as the reference does); `pit_gain` and
/// `pitch` are the per-subframe pitch gain (Q14) and lag of the bass post-filter; the result goes
/// to `signal_out[..L_frame]` and the bass post-filter's harmonic signal to `bpf_noise_buf`.
pub fn post_decoder(
    st: &mut DecoderState,
    coder_type: i16,
    synth_buf: &mut [i16],
    pit_gain: &[i16],
    pitch: &[i16],
    signal_out: &mut [i16],
    bpf_noise_buf: &mut [i16],
) {
    let mut pitch_gain_adjust = [0i16; 5];
    let mut synth2_pe = [0i16; L_FRAME_MAX as usize];
    let mut synth_buf2 = [0i16; SYNTH_BUF2_LEN];

    let l_frame = st.l_frame;
    let frame = l_frame.max(0) as usize;
    let nb_subfr = st.nb_subfr;
    let pfstat_on_previous = st.pfstat.on;
    st.pfstat.on = 0;

    let mut bitrate = l_add(st.total_brate, 0);
    if st.core_brate <= i32::from(SID_2K40) {
        bitrate = l_add(st.last_active_brate, 0);
    }

    // Adapt Bpf: copy old and current adapt bpf parameters
    set16(&mut pitch_gain_adjust, st.bpf_gain_param, nb_subfr);

    // `synth` is `synth_buf[synth_at..]`, `synth2` is `synth_buf2[SYNTH2_AT..]`
    let synth_at = st.old_synth_len.max(0) as usize;
    const SYNTH2_AT: usize = NBPSF_PIT_MAX as usize;
    synth_buf2[..SYNTH2_AT].copy_from_slice(&st.pst_old_syn[..SYNTH2_AT]);

    if st.tcxonly != 0 {
        synth_buf2[SYNTH2_AT..SYNTH2_AT + frame]
            .copy_from_slice(&synth_buf[synth_at..synth_at + frame]);
        if pfstat_on_previous != 0 {
            let history = L_SYN_MEM as usize - MU;
            synth_buf[synth_at - MU..synth_at]
                .copy_from_slice(&st.pfstat.mem_pf_in[history..history + MU]);
            // `Residu3_fx(.., synth, synth_buf, ..)` writes the start of the buffer it reads the
            // frame from; they are `old_synth_len` (twice a TCX frame) samples apart, so the
            // residual is formed aside and stored.
            let mut residual = [0i16; L_SUBFR as usize];
            residu3(
                &st.old_aq_12_8,
                synth_buf,
                synth_at,
                &mut residual,
                L_SUBFR,
                1,
            );
            synth_buf[..L_SUBFR as usize].copy_from_slice(&residual);
            e_util_synthesis(
                1,
                &st.old_aq_12_8,
                &synth_buf[..L_SUBFR as usize],
                &mut synth_buf2[SYNTH2_AT..],
                L_SUBFR,
                &mut st.pfstat.mem_stp[L_SYN_MEM as usize - MU..],
                0,
                M,
            );
            scale_st(
                &synth_buf[synth_at..],
                &mut synth_buf2[SYNTH2_AT..],
                &mut st.pfstat.gain_prec,
                L_SUBFR,
            );
            // `blend_subfr2(synth2 + L_SUBFR/2, synth + L_SUBFR/2, synth2 + L_SUBFR/2)`: the
            // output is the first input, which is read first for every sample.
            let half = L_SUBFR as usize / 2;
            let mut first_input = [0i16; L_SUBFR as usize / 2];
            first_input.copy_from_slice(&synth_buf2[SYNTH2_AT + half..SYNTH2_AT + 2 * half]);
            blend_subfr2(
                &first_input,
                &synth_buf[synth_at + half..],
                &mut synth_buf2[SYNTH2_AT + half..],
            );
        }
    } else {
        post_decoder_filter(
            st,
            coder_type,
            synth_buf,
            synth_at,
            &mut synth2_pe,
            &mut synth_buf2,
            pfstat_on_previous,
            pitch,
            bitrate,
        );

        // Bass Post-filter
        let mut disable_bpf: i8 = 0;
        if l_sub(st.lp_noise, LP_NOISE_THRESH) > 0 && st.narrow_band != 0 {
            disable_bpf = 1;
        }
        bass_pf_1sf_delay(
            &synth_buf2,
            SYNTH2_AT,
            pitch,
            pit_gain,
            l_frame,
            L_SUBFR,
            bpf_noise_buf,
            &pitch_gain_adjust,
            disable_bpf,
            &mut st.lp_error_ener,
            &mut st.mem_error,
        );
    }

    // Output
    signal_out[..frame].copy_from_slice(&synth_buf2[SYNTH2_AT..SYNTH2_AT + frame]);

    // Update synth2 memory
    st.pst_old_syn[..SYNTH2_AT].copy_from_slice(&synth_buf2[frame..frame + SYNTH2_AT]);
}

/// The formant / NB post-filter half of `post_decoder` (the non-TCX-only path), from `synth`
/// (`synth_buf[synth_at..]`) into `synth2` (`synth_buf2[NBPSF_PIT_MAX..]`).
fn post_decoder_filter(
    st: &mut DecoderState,
    coder_type: i16,
    synth_buf: &mut [i16],
    synth_at: usize,
    synth2_pe: &mut [i16; L_FRAME_MAX as usize],
    synth_buf2: &mut [i16; SYNTH_BUF2_LEN],
    pfstat_on_previous: i16,
    pitch: &[i16],
    bitrate: i32,
) {
    const SYNTH2_AT: usize = NBPSF_PIT_MAX as usize;
    let l_frame = st.l_frame;
    let frame = l_frame.max(0) as usize;

    // Formant enhancement
    if sub(st.last_bwidth, NB) == 0 {
        synth2_pe[..frame].copy_from_slice(&synth_buf[synth_at..synth_at + frame]);
        let mut tmp = synth_buf[synth_at - 1];

        preemph_copy_in_place(&mut synth2_pe[..], st.preemph_fac, l_frame, &mut tmp);

        let mut disable_hpf: i16 = 0;
        if l_sub(st.lp_noise, LP_NOISE_THRESH) > 0
            || st.core != ACELP_CORE
            || sub(coder_type, UNVOICED) == 0
        {
            disable_hpf = 1;
        }

        if pfstat_on_previous == 0 {
            st.pfstat.reset = 1;
        }
        let mut tmp_noise: i16 = 0;
        if sub(st.bwidth, NB) == 0 {
            st.pfstat.on = 1;
            nb_post_filt(
                l_frame,
                &mut st.pfstat,
                &mut tmp_noise,
                0,
                &mut synth2_pe[..],
                &st.mem_aq,
                pitch,
                GENERIC,
                st.ber_detect,
                disable_hpf,
            );
        } else {
            st.pfstat.on = 0;
            nb_post_filt(
                l_frame,
                &mut st.pfstat,
                &mut tmp_noise,
                0,
                &mut synth2_pe[..],
                &st.mem_aq,
                pitch,
                AUDIO,
                st.ber_detect,
                disable_hpf,
            );
        }

        synth_buf2[SYNTH2_AT..SYNTH2_AT + frame].copy_from_slice(&synth2_pe[..frame]);

        let mut tmp = synth_buf2[SYNTH2_AT - 1];
        deemph(
            &mut synth_buf2[SYNTH2_AT..],
            st.preemph_fac,
            l_frame,
            &mut tmp,
        );
    } else {
        if pfstat_on_previous == 0 {
            st.pfstat.reset = 1;
        }
        if sub(st.last_bwidth, WB) >= 0 {
            st.pfstat.on = 1;
            formant_post_filt(
                &mut st.pfstat,
                synth_buf,
                synth_at,
                &st.mem_aq,
                &mut synth_buf2[SYNTH2_AT..],
                l_frame,
                st.lp_noise,
                bitrate,
                0,
            );
        } else {
            st.pfstat.on = 0;
            formant_post_filt(
                &mut st.pfstat,
                synth_buf,
                synth_at,
                &st.mem_aq,
                &mut synth_buf2[SYNTH2_AT..],
                l_frame,
                st.lp_noise,
                bitrate,
                1,
            );
        }
    }
}

/// `bass_pf_1sf_delay`: low-frequency (bass) post-filter with one subframe of delay: for every
/// `l_subfr` subframe of the 12.8 kHz synthesis `syn[syn_at..]` (with at least the maximum pitch
/// of history before `syn_at`), the harmonic signal that the post-filter removes is written to
/// `bpf_noise_buf` (zero where the filter is off). `lp_error_ener` (15Q16) and `mem_error` carry
/// the long-term error energy between frames.
pub fn bass_pf_1sf_delay(
    syn: &[i16],
    syn_at: usize,
    t_sf: &[i16],
    gain_t_sf: &[i16],
    l_frame: i16,
    l_subfr: i16,
    bpf_noise_buf: &mut [i16],
    gain_factor_param: &[i16],
    disable_bpf: i8,
    lp_error_ener: &mut i32,
    mem_error: &mut i32,
) {
    // `syn[i]` of the reference
    let at = |index: i32| syn[(syn_at as i32 + index) as usize];

    let mut sf: usize = 0;
    let mut lp_error = l_shl(*mem_error, 0);

    let mut i_subfr: i16 = 0;
    while i_subfr < l_frame {
        let t = t_sf[sf];

        let mut lg = sub(sub(l_frame, t), i_subfr);
        if lg < 0 {
            lg = 0;
        }
        if lg > l_subfr {
            lg = l_subfr;
        }

        let base = i32::from(i_subfr);
        let lag = i32::from(t);
        if disable_bpf == 0 && gain_t_sf[sf] > 0 {
            // get headroom for used part of syn
            let mut tmp16 = add(l_subfr, t);
            if lg > 0 {
                tmp16 = add(lg, shl(t, 1));
            }
            let first = (syn_at as i32 + base - lag) as usize;
            let mut s1 = get_scale_factor16(&syn[first..], tmp16);
            s1 = sub(s1, 3);

            let mut tmp = l_deposit_l(1);
            let mut nrg = l_deposit_l(1);

            if lg > 0 {
                for i in 0..i32::from(lg) {
                    let mut tmp32 = l_mult(at(i + base - lag), 0x4000);
                    tmp32 = l_mac(tmp32, at(i + base + lag), 0x4000);
                    // Q0+s1
                    let tmp16 = round_word(l_shl(tmp32, s1));

                    // Q0+2*s1
                    tmp = l_mac0(tmp, shl(at(i + base), s1), tmp16);
                    nrg = l_mac0(nrg, tmp16, tmp16);
                }
            }

            if sub(lg, l_subfr) < 0 {
                for i in i32::from(lg)..i32::from(l_subfr) {
                    // Q0+s1
                    let tmp16 = shl(at(i + base - lag), s1);
                    // Q0+2*s1
                    tmp = l_mac0(tmp, shl(at(i + base), s1), tmp16);
                    nrg = l_mac0(nrg, tmp16, tmp16);
                }
            }

            // gain = tmp/nrg;
            let mut scale: i16 = 0;
            let mut gain = basop_util_divide3232_scale(tmp, nrg, &mut scale);
            // Q15 (the reference silences the saturation warning)
            gain = shl(gain, scale);

            if gain < 0 {
                gain = 0;
            }

            let mut st = sub(norm_l(lp_error), 3);
            if sub(st, s1) < 0 && lp_error != 0 {
                s1 = st;
            }

            let mut ener2 = l_deposit_l(0);

            if lg > 0 {
                for i in 0..i32::from(lg) {
                    let mut tmp32 = l_msu0(0, gain, at(i + base - lag));
                    tmp32 = l_msu0(tmp32, gain, at(i + base + lag));
                    // Q0
                    let tmp16 = mac_r(tmp32, gain, at(i + base));

                    lp_error = mpy_32_16_1(lp_error, 29491);
                    // Q13
                    lp_error = l_mac(lp_error, tmp16, 0x1000);

                    // Q0+s1-3
                    let tmp16 = round_word(l_shl(lp_error, s1));
                    // Q0+(s1-3)*2
                    ener2 = l_mac0(ener2, tmp16, tmp16);
                }
            }

            if sub(lg, l_subfr) < 0 {
                for i in i32::from(lg)..i32::from(l_subfr) {
                    let mut tmp32 = l_mult0(gain, at(i + base));
                    // Q0
                    tmp32 = l_msu0(tmp32, gain, at(i + base - lag));
                    let tmp16 = round_word(tmp32);

                    lp_error = mpy_32_16_1(lp_error, 29491);
                    // Q13
                    lp_error = l_mac(lp_error, tmp16, 0x1000);

                    // Q0+s1-3
                    let tmp16 = round_word(l_shl(lp_error, s1));
                    // Q0+(s1-3)*2
                    ener2 = l_mac0(ener2, tmp16, tmp16);
                }
            }

            st = shl(sub(s1, 3), 1);

            if ener2 > 0 {
                // 15Q16
                ener2 = l_shr(basop_util_log2(ener2), 9);
                ener2 = l_add(ener2, l_deposit_h(sub(31, st)));
            } else {
                // log2(0.01) (15Q16)
                ener2 = l_add(0xFFF9_5B2C_u32 as i32, 0);
            }

            // 15Q16
            *lp_error_ener = l_add(mpy_32_16_1(l_sub(*lp_error_ener, ener2), 32440), ener2);

            st = add(st, 6);
            ener2 = l_sub(*lp_error_ener, l_deposit_h(sub(31, st)));
            if ener2 >= 0 {
                let tmp16 = add(extract_h(ener2), 1);
                ener2 = l_sub(ener2, l_deposit_h(tmp16));
                tmp = l_shr(tmp, tmp16);
                nrg = l_shr(nrg, tmp16);
            }
            // Q0+2*s1
            ener2 = basop_util_inv_log2(l_shl(ener2, 9));

            let mut tmp32 = l_add(l_shr(nrg, 1), l_shr(ener2, 1));
            if tmp32 == 0 {
                tmp32 = l_deposit_l(1);
            }
            let mut tmp16 = basop_util_divide3232_scale(tmp, tmp32, &mut st);
            // Q15 (the reference silences the saturation warning)
            tmp16 = shl(tmp16, sub(st, 2));

            if sub(tmp16, 16384) > 0 {
                tmp16 = 16384;
            }
            if tmp16 < 0 {
                tmp16 = 0;
            }

            // Adjust gain
            // full gain = gainLTP*0.5
            // adaptive gain = gainLTP*0.5*max(0.5f*gain_factor_param[sf],0.125f)
            let tmp16 = round_word(l_shl(
                l_mult0(tmp16, shl(gain_factor_param[sf], 2).max(1)),
                13,
            ));

            // calculate noise based on voiced pitch
            if lg > 0 {
                for i in 0..i32::from(lg) {
                    let mut tmp32 = l_msu0(0, tmp16, at(i + base - lag));
                    tmp32 = l_msu0(tmp32, tmp16, at(i + base + lag));
                    tmp32 = l_mac(tmp32, tmp16, at(i + base));
                    // Q0
                    bpf_noise_buf[(i + base) as usize] = round_word(tmp32);
                }
            }

            if sub(lg, l_subfr) < 0 {
                for i in i32::from(lg)..i32::from(l_subfr) {
                    let mut tmp32 = l_mult0(tmp16, at(i + base));
                    tmp32 = l_msu0(tmp32, tmp16, at(i + base - lag));
                    // Q0
                    bpf_noise_buf[(i + base) as usize] = round_word(tmp32);
                }
            }
        } else {
            set16(&mut bpf_noise_buf[i_subfr as usize..], 0, l_subfr);
        }

        sf += 1;
        i_subfr = i_subfr.wrapping_add(l_subfr);
    }

    *mem_error = lp_error;
}

/// `cldfb_synth_set_bandsToZero`: the bandwidth detection of the AMR-WB IO decoder: from the
/// energy of the CLDFB analysis of the output (`r_analysis`, `i_analysis`, `n_time_slots` slots)
/// it decides, with hysteresis over the last 20 active frames, whether the content is narrowband
/// and sets the synthesis bank's `bandsToZero` accordingly. Counters and the decision live in
/// the decoder state.
///
/// The reference dereferences `cldfbSyn_fx` unconditionally; without a synthesis bank (only a
/// decoder that never opened one) there is nothing to set and the call returns.
// indices mirror the reference's pointer walks
#[allow(clippy::needless_range_loop)]
pub fn cldfb_synth_set_bands_to_zero(
    st: &mut DecoderState,
    r_analysis: &[[i32; CLDFB_ROW]],
    i_analysis: &[[i32; CLDFB_ROW]],
    n_time_slots: i16,
    scale_factor: &CldfbScaleFactor,
) {
    let Some((no_channels, bands_to_zero)) = st
        .cldfb_syn
        .as_ref()
        .map(|bank| (bank.no_channels, bank.bands_to_zero))
    else {
        return;
    };
    let mut bands_to_zero = bands_to_zero;

    let mut nrg_band = [0i32; CLDFB_NO_CHANNELS_MAX as usize];
    let mut max_nrg: i32 = 0;

    let offset: i16 = 250;
    let wb_cnt: i16 = 20;
    // 0.80 in Q14
    let perc_miss: i16 = 13107;
    // 0.90 in Q14
    let perc_detect: i16 = 14746;

    if sub(i16::from(st.vad), 1) == 0 {
        st.active_frame_cnt_bwddec = add(st.active_frame_cnt_bwddec, 1);
        st.total_frame_cnt_bwddec = add(st.total_frame_cnt_bwddec, 1);
        if sub(st.active_frame_cnt_bwddec, 99) > 0 {
            st.active_frame_cnt_bwddec = 100;
        }
        if sub(st.total_frame_cnt_bwddec, 500) > 0 {
            st.total_frame_cnt_bwddec = 500;
        }

        let mut i: i16 = 0;
        while i < no_channels - bands_to_zero {
            let mut nrg_q31: i32 = 0;
            for k in 0..n_time_slots as usize {
                // use 16-bit precision of real and imag buffers
                let shift = 31 - (15 + scale_factor.lb_scale) + 3;
                let real_q1 = extract_l(l_shr(r_analysis[k][i as usize], shift));
                // Q(-3), headroom
                let imag_q1 = extract_l(l_shr(i_analysis[k][i as usize], shift));
                nrg_q31 = l_mac0(nrg_q31, real_q1, real_q1);
                // keep in Q(-6)
                nrg_q31 = l_mac0(nrg_q31, imag_q1, imag_q1);
            }
            nrg_band[i as usize] = nrg_q31;
            if l_sub(nrg_band[i as usize], max_nrg) > 0 && sub(i, 11) >= 0 {
                max_nrg = nrg_band[i as usize];
            }
            i += 1;
        }
        while i < no_channels {
            nrg_band[i as usize] = 0;
            i += 1;
        }

        let mut nrg_q31: i32 = 0;
        for i in 2..9 {
            nrg_q31 = l_add(nrg_q31, mult_32_16(nrg_band[i], 4681));
        }

        let temp_q31 = l_shr(nrg_q31, 9);

        // 0.99*avg_nrg_LT + 0.01*tempQ31
        st.avg_nrg_lt = l_add(mult_32_16(st.avg_nrg_lt, 32440), mult_32_16(temp_q31, 327));
        let mut update_perc: i16 = 1;
        if st.ini_frame >= 25 && temp_q31 < mult_32_16(st.avg_nrg_lt, 164) {
            update_perc = 0;
        }

        let mut flag: i16 = 1;
        if max_nrg >= temp_q31 {
            flag = 0;
        }

        for i in 0..(wb_cnt - 1) as usize {
            st.flag_buffer[i] = st.flag_buffer[i + 1];
        }
        st.flag_buffer[(wb_cnt - 1) as usize] = flag;

        // long term percentage
        if sub(update_perc, 1) == 0 {
            if flag != 0 {
                // Q14
                let tmp1 = sub(16384, st.perc_bwddec);

                let tmp = norm_s(st.active_frame_cnt_bwddec);
                // Qtmp
                let tmp3 = shl(st.active_frame_cnt_bwddec, tmp);

                // 1/active_frames in Q15 + Q14 - Qtmp = Q29 - Qtmp
                let mut tmp2 = div_s(16384, tmp3);
                // (1-perc)*(1/active_frames) in Q14 + Q29 - Qtmp - Q15 = Q28 - Qtmp
                tmp2 = mult_r(tmp2, tmp1);
                // Q14
                st.perc_bwddec = add(st.perc_bwddec, shl(tmp2, sub(tmp, 14)));
            } else {
                // Q14
                let tmp1 = st.perc_bwddec;

                let tmp = norm_s(st.active_frame_cnt_bwddec);
                // Qtmp
                let tmp3 = shl(st.active_frame_cnt_bwddec, tmp);

                // 1/active_frames in Q15 + Q14 - Qtmp = Q29 - Qtmp
                let mut tmp2 = div_s(16384, tmp3);
                // (perc)*(1/active_frames) in Q14 + Q29 - Qtmp - Q15 = Q28 - Qtmp
                tmp2 = mult_r(tmp2, tmp1);
                // Q14
                st.perc_bwddec = sub(st.perc_bwddec, shl(tmp2, sub(tmp, 14)));
            }
        }
        if sub(st.total_frame_cnt_bwddec, offset) > 0 && sub(st.active_frame_cnt_bwddec, 50) > 0 {
            // decision hysterysis
            if (st.perc_bwddec >= perc_detect
                || (st.perc_bwddec >= perc_miss && st.last_flag_filter_nb != 0))
                && sum16(&st.flag_buffer, wb_cnt) != 0
            {
                bands_to_zero = sub(no_channels, 10);
                // VAD processing must be dependent on hysterysis, as if hysterysis fails, but
                // threshold passes, we dont want next vad frames to have NB only
                st.last_flag_filter_nb = 1;
            } else {
                st.last_flag_filter_nb = 0;
            }
        } else {
            st.last_flag_filter_nb = 0;
        }
        if sum16(&st.flag_buffer, wb_cnt) == 0 {
            st.perc_bwddec = 0;
            st.active_frame_cnt_bwddec = 0;
            st.total_frame_cnt_bwddec = 0;
            st.last_flag_filter_nb = 0;
        }
    } else {
        if st.last_flag_filter_nb == 1 {
            bands_to_zero = st.last_active_bands_to_zero_bwdec;
        }
        st.total_frame_cnt_bwddec = add(st.total_frame_cnt_bwddec, 1);
        if sub(st.total_frame_cnt_bwddec, 500) > 0 {
            st.total_frame_cnt_bwddec = 500;
        }
    }

    if let Some(bank) = st.cldfb_syn.as_mut() {
        bank.bands_to_zero = bands_to_zero;
    }
    st.last_active_bands_to_zero_bwdec = bands_to_zero;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bass_post_filter_off_clears_the_noise_buffer() {
        let syn = vec![1000i16; 700];
        let mut noise = vec![77i16; 256];
        let (mut energy, mut memory) = (0, 0);
        bass_pf_1sf_delay(
            &syn,
            300,
            &[60; 4],
            &[0; 4],
            256,
            64,
            &mut noise,
            &[3; 4],
            0,
            &mut energy,
            &mut memory,
        );
        assert!(noise.iter().all(|&sample| sample == 0));
        assert_eq!((energy, memory), (0, 0));
    }

    #[test]
    fn bands_to_zero_stays_without_a_synthesis_bank() {
        let mut st = DecoderState::zeroed();
        st.vad = 1;
        let rows = [[0i32; CLDFB_ROW]; 16];
        cldfb_synth_set_bands_to_zero(&mut st, &rows, &rows, 16, &CldfbScaleFactor::zeroed());
        assert_eq!(st.active_frame_cnt_bwddec, 0);
    }
}
