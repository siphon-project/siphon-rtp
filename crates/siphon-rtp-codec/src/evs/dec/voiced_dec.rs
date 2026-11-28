//! The voiced (quarter-rate PPP) frame decoder of SC-VBR (TS 26.442 `lib_dec/voiced_dec_fx.c`;
//! TS 26.445 §6.1.2.3).

use crate::evs::cnst::{L_FRAME, MAXLAG_WI, MAX_LAG_PIT, NB, NB_SUBFR, PIT_MAX, SWB, UNVOICED, WB};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::log2::{log10, log2_norm_lc};
use crate::evs::com::ppp::interpol_delay;
use crate::evs::com::tools::{find_rem, find_remd, rint_new};
use crate::evs::com::wi::{
    dtfs_car2pol, dtfs_copy, dtfs_new, dtfs_set_engy_harm, dtfs_to_erb, dtfs_to_fs,
    get_sin_cos_tab, rshift_harm_band, wi_syn, DtfsStructure,
};
use crate::evs::dec::ppp_dec::ppp_quarter_decoder;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::FRAC_4SF_FX;
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_mult, l_shl, l_sub, mult, norm_l,
    norm_s, round_word, shl, shr, sub,
};

/// `S_fx` / `C_fx` hold `4 * PIT_MAX + 1` entries.
const SIN_COS_LEN: usize = 4 * PIT_MAX as usize + 1;
const LAG_CAPACITY: usize = MAXLAG_WI as usize;
use crate::itu::oper_32b::mpy_32_16;
use crate::itu::stl2009::l_mult0;

/// `ppp_voiced_decoder_fx`: decodes a quarter-rate PPP frame. Reads the lag delta, builds the
/// prototype of the previous frame (from the excitation history `exc` before `exc_at`, or from
/// the memory kept in the state when the last frame was PPP too), has `ppp_quarter_decoder`
/// dequantise the new one and synthesises the `L_FRAME` samples of `out` by waveform
/// interpolation through the LP filter `lpc2`. `pitch` receives the per-subframe pitch (Q6).
pub fn ppp_voiced_decoder(
    st: &mut DecoderState,
    out: &mut [i16],
    lpc2: &[i16],
    exc: &[i16],
    exc_at: usize,
    pitch: &mut [i16],
    bfi: i16,
) {
    let mut upper_cut_off_freq_of_interest: i16 = 0;
    let mut upper_cut_off_freq: i16 = 0;
    let mut s_fx = [0i16; SIN_COS_LEN];
    let mut c_fx = [0i16; SIN_COS_LEN];
    let mut pf_temp1 = [0i16; LAG_CAPACITY];
    let mut pf_temp2 = [0i16; LAG_CAPACITY];
    let mut pf_temp = [0i16; LAG_CAPACITY];
    let mut pf_n2 = [0i16; LAG_CAPACITY];

    if sub(st.bwidth, WB) == 0 || sub(st.bwidth, SWB) == 0 {
        upper_cut_off_freq_of_interest = 0x2800; // 4000 normalized to 12800 in Q15
        upper_cut_off_freq = 0x4000; // 6400 normalized to 12800 in Q15
    } else if sub(st.bwidth, NB) == 0 {
        upper_cut_off_freq_of_interest = 0x2100; // 3300 normalized to 12800 in Q15
        upper_cut_off_freq = 0x2800;
    }

    let mut temp_fs: i16 = 8000;
    if sub(st.bwidth, WB) == 0 {
        temp_fs = 16000;
    }

    // Initialization
    if st.first_time_voiceddec != 0 {
        st.first_time_voiceddec = 0;

        st.dtfs_dec_lag = 0;
        st.dtfs_dec_n_h = 0;
        st.dtfs_dec_n_h_4k_hz = 0;
        st.dtfs_dec_upper_cut_off_freq_of_interest = 3300;
        st.dtfs_dec_upper_cut_off_freq = 4000;

        st.dtfs_dec_a.fill(0);
        st.dtfs_dec_b.fill(0);
        st.dtfs_dec_q = 0;
    }

    let mut pl = rint_new(st.old_pitch_buf[2 * NB_SUBFR as usize - 1]).min(MAX_LAG_PIT);
    let delta_lag_d = get_next_indice(st, 5) as i16;

    let l = MAX_LAG_PIT.min(add(pl, sub(delta_lag_d, 11)));

    let temp_pl = pl;
    let temp_l = l;

    if sub(temp_pl, temp_l) != 0 {
        for k in 0..NB_SUBFR {
            // do the linear pitch interpolation to drive nb_post_filt
            let mut interp_delay = [0i16; 3];
            interpol_delay(&mut interp_delay, temp_pl, temp_l, k, &FRAC_4SF_FX);
            pitch[k as usize] = (MAX_LAG_PIT << 6).min((19 << 6).max(shl(interp_delay[0], 2)));
            // Q6
        }
    } else {
        pitch[..NB_SUBFR as usize].fill((MAX_LAG_PIT << 6).min((19 << 6).max(shl(temp_l, 6))));
        // Q6
    }

    if sub(st.last_coder_type, UNVOICED) == 0 {
        pl = l; // if the previous frame was silence / unvoiced
    }

    let mut temp = mult(shl(l, 3), 30310); // Q3 + 14 + 1 - 16 = Q2, 30310 is 1.85 in Q14
    temp = if temp >= 0 {
        add(temp, 2)
    } else {
        sub(temp, 2)
    };
    temp = shr(temp, 2); // Q0

    if sub(pl, temp) > 0 {
        pl = shr(pl, 1);
    }

    temp = mult(shl(l, 3), 8857); // Q3 + 14 + 1 - 16 = Q2, 8857 is 0.54 in Q14
    temp = if temp >= 0 {
        add(temp, 2)
    } else {
        sub(temp, 2)
    };
    temp = shr(temp, 2); // Q0

    if sub(shl(pl, 1), PIT_MAX) <= 0 && sub(pl, temp) <= 0 {
        pl = shl(pl, 1);
    }

    let mut dtfs_temp = dtfs_new();
    // Restoring the PPP memories when the last frame is non-PPP or full-rate PPP
    if sub(st.last_ppp_mode_dec, 1) != 0 {
        ppp_voiced_decoder_restore(
            st,
            &mut dtfs_temp,
            exc,
            exc_at,
            pl,
            temp_fs,
            upper_cut_off_freq_of_interest,
            upper_cut_off_freq,
            &mut s_fx,
            &mut c_fx,
        );
    } else {
        // Copy the DTFS related parameters from the state to dtfs_temp
        dtfs_temp.lag = st.dtfs_dec_lag;
        dtfs_temp.nh = st.dtfs_dec_n_h;
        dtfs_temp.nh_4khz = st.dtfs_dec_n_h_4k_hz;
        dtfs_temp.upper_cut_off_freq_of_interest = st.dtfs_dec_upper_cut_off_freq_of_interest;
        dtfs_temp.upper_cut_off_freq = st.dtfs_dec_upper_cut_off_freq;

        dtfs_temp.a.copy_from_slice(&st.dtfs_dec_a[..LAG_CAPACITY]);
        dtfs_temp.b.copy_from_slice(&st.dtfs_dec_b[..LAG_CAPACITY]);
        dtfs_temp.q = st.dtfs_dec_q;
    }

    let mut currp_q_d = dtfs_new();
    currp_q_d.lag = l;

    // safety check in case of bit errors
    if currp_q_d.lag <= 0 {
        currp_q_d.lag = 1;
        st.ber_detect = 1;
    }

    // compute nH for the lag
    let l_temp = l_shl(i32::from(upper_cut_off_freq), 13); // Q28
    let mut rem32 = 0;
    upper_cut_off_freq = find_remd(l_temp, 20971, &mut rem32) as i16; // denormalize upper_cut_off_freq

    let mut exp = norm_s(currp_q_d.lag);
    let mut tmp = div_s(shl(1, sub(14, exp)), currp_q_d.lag); // 29 - exp
    let mut l_tmp = l_shl(l_mult0(tmp, 12800), exp - 7);
    let temp32 = i32::from(round_word(l_tmp));
    let diff = round_word(l_shl(temp32, 16 - 6)); // Q0

    let mut rem: i16 = 0;
    currp_q_d.nh = find_rem(upper_cut_off_freq, diff, &mut rem); // Q0

    exp = norm_s(diff);
    tmp = div_s(shl(1, sub(14, exp)), diff); // 29 - exp
    l_tmp = l_shl(l_mult0(4000, tmp), exp - 7);
    let tempnh = extract_h(l_tmp);
    currp_q_d.nh_4khz = round_word(l_shl(i32::from(tempnh), 16 - 6)); // Q0

    if sub(
        sub(
            upper_cut_off_freq,
            shr(l_mult(diff, currp_q_d.nh) as i16, 1),
        ),
        diff,
    ) >= 0
    {
        currp_q_d.nh = add(currp_q_d.nh, 1);
    }
    let mut tempnh = l_mult0(extract_l(temp32), currp_q_d.nh_4khz);
    tempnh = l_sub(256000, tempnh); // Q6

    if l_sub(tempnh, temp32) >= 0 {
        currp_q_d.nh_4khz = add(currp_q_d.nh_4khz, 1);
    }

    currp_q_d.upper_cut_off_freq = dtfs_temp.upper_cut_off_freq;
    currp_q_d.upper_cut_off_freq_of_interest = dtfs_temp.upper_cut_off_freq_of_interest;
    get_sin_cos_tab(currp_q_d.lag, &mut s_fx, &mut c_fx);

    if bfi == 0 {
        let prev_lag = dtfs_temp.lag;
        ppp_quarter_decoder(&mut currp_q_d, prev_lag, bfi, &s_fx, &c_fx, &dtfs_temp, st);
    }

    wi_syn(
        dtfs_temp,
        &mut currp_q_d,
        lpc2,
        &mut st.ph_offset_d,
        out,
        L_FRAME,
        0,
        &s_fx,
        &c_fx,
        &mut pf_temp1,
        &mut pf_temp2,
        &mut pf_temp,
        &mut pf_n2,
    );

    dtfs_copy(&mut dtfs_temp, &currp_q_d);

    // Copy the DTFS related parameters from dtfs_temp to the state
    st.dtfs_dec_lag = dtfs_temp.lag;
    st.dtfs_dec_n_h = dtfs_temp.nh;
    st.dtfs_dec_n_h_4k_hz = dtfs_temp.nh_4khz;
    st.dtfs_dec_upper_cut_off_freq_of_interest = dtfs_temp.upper_cut_off_freq_of_interest;
    st.dtfs_dec_upper_cut_off_freq = dtfs_temp.upper_cut_off_freq;

    st.dtfs_dec_a[..LAG_CAPACITY].copy_from_slice(&dtfs_temp.a);
    st.dtfs_dec_b[..LAG_CAPACITY].copy_from_slice(&dtfs_temp.b);

    st.dtfs_dec_q = dtfs_temp.q;
}

/// `10 * log10(lag * band energy)` of a prototype band in Q11 as `ppp_voiced_decoder_fx` stores it
/// in `lastLgainD` / `lastHgainD`: `ltemp` is the band energy from `DTFS_setEngyHarm_fx`.
fn band_gain_q11(ltemp: i32, ltemp_q: i32, log_lag: i32) -> i16 {
    let ltemp = log10(ltemp); // 10 log10(eng), Q23
    let ltemp = l_add(l_sub(ltemp, ltemp_q), log_lag); // 10 log10(lag * eng), Q23
    round_word(l_shl(
        mpy_32_16(extract_h(ltemp), extract_l(ltemp), 0x6666),
        1,
    )) // Q11
}

/// `ppp_voiced_decoder_fx`'s restoring of the PPP memories when the last frame was not a PPP
/// frame: the prototype `dtfs_temp` of the last `pl` samples of excitation, the band gains
/// `last_lgain_d` / `last_hgain_d` and the ERB vector `lasterb_d` of its low and high band.
fn ppp_voiced_decoder_restore(
    st: &mut DecoderState,
    dtfs_temp: &mut DtfsStructure,
    exc: &[i16],
    exc_at: usize,
    pl: i16,
    temp_fs: i16,
    upper_cut_off_freq_of_interest: i16,
    upper_cut_off_freq: i16,
    s_fx: &mut [i16],
    c_fx: &mut [i16],
) {
    let mut ql: i16 = 0;
    let mut qh: i16 = 0;
    get_sin_cos_tab(pl, s_fx, c_fx);
    // `exc_fx - pl`: the last pl samples of excitation (pl <= PIT_MAX from the doubling test; the
    // history holds more)
    let from = exc_at.saturating_sub(pl.max(0) as usize);
    dtfs_to_fs(&exc[from..], pl, dtfs_temp, temp_fs, 0, s_fx, c_fx);

    st.ph_offset_d = 0;

    // Copy over PREV_CW_D into TMPDTFS
    let mut tmpdtfs = dtfs_new();
    dtfs_copy(&mut tmpdtfs, dtfs_temp);

    dtfs_car2pol(&mut tmpdtfs);

    // lastLgainD = log10(TMPDTFS->lag * DTFS_setEngyHarm(92.0, 1104.5, 0.0, 1104.5, 1.0, TMPDTFS))
    let mut l_tmp = l_deposit_h(tmpdtfs.lag); // Q16
    let mut exp = norm_l(l_tmp);
    let tmp = log2_norm_lc(l_shl(l_tmp, exp));
    exp = 30 - exp - 16;
    l_tmp = mpy_32_16(exp, tmp, 12330); // Q13, 10*log10(2) in Q12
    let log_lag = l_shl(l_tmp, 10); // Q23

    let ltemp_q = l_shl(l_mult(shl(tmpdtfs.q, 1), 24660), 9); // 2Q * 10log10(2), Q23
                                                              // Process the low band
    let ltemp = dtfs_set_engy_harm(236, 2828, 0, 2828, 1, 0, &mut ql, &mut tmpdtfs); // in 2 * TMP.Q
                                                                                     // Compensate for the Q factor of the energy to get log10(lag * eng)
    st.last_lgain_d = band_gain_q11(ltemp, ltemp_q, log_lag);

    // Process the high band
    let ltemp = dtfs_set_engy_harm(
        2828,
        upper_cut_off_freq_of_interest,
        2828,
        upper_cut_off_freq,
        1,
        0,
        &mut qh,
        &mut tmpdtfs,
    );
    st.last_hgain_d = band_gain_q11(ltemp, ltemp_q, log_lag);

    // Need to unify the Q factors of both bands
    tmpdtfs.q = ql.min(qh); // set the Q factor to the smaller one
    let n = sub(ql, qh); // compare the band Q factors

    // This logic adjusts the difference between the Q formats of both bands
    if n < 0 {
        rshift_harm_band(&mut tmpdtfs, 2828, upper_cut_off_freq, n);
    } else if n > 0 {
        rshift_harm_band(&mut tmpdtfs, 0, 2828, sub(qh, ql));
    }

    dtfs_to_erb(&tmpdtfs, &mut st.lasterb_d);
}
