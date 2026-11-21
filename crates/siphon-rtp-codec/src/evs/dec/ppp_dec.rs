//! Decoding of the quarter-rate PPP (prototype pitch period) prototype of SC-VBR (TS 26.442
//! `lib_dec/ppp_dec_fx.c`; TS 26.445 §6.1.2.3).

use crate::evs::cnst::L_FRAME;
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::tools::find_remd;
use crate::evs::com::tools::rint_new;
use crate::evs::com::wi::{
    copy_phase, dtfs_adjust_lag, dtfs_car2pol, dtfs_copy, dtfs_dequant_cw, dtfs_new, q2phase_shift,
    DtfsStructure,
};
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{div_s, extract_l, l_add, l_mult, l_shl, l_shr, norm_s, shl, sub};
use crate::itu::stl2009::lshr;

/// `ppp_quarter_decoder_fx`: reads the power index, the two amplitude-shape indices and the phase
/// index of a quarter-rate PPP frame and turns them into the prototype `currcw_q_dtfs`
/// (whose lag and cut-off frequencies the caller set): amplitudes dequantised against the
/// previous prototype `prev_cw_d` (lag `prev_cw_lag`), phases copied from it, rotated by the lag
/// change and by the transmitted phase offset. The band gains and ERB vector it updates are the
/// state's `last_lgain_d`, `last_hgain_d` and `lasterb_d` (the reference passes pointers to them).
/// `s` / `c` are the sine / cosine tables of the current lag. With `bfi` set nothing is read and the
/// amplitudes of `currcw_q_dtfs` are kept.
pub fn ppp_quarter_decoder(
    currcw_q_dtfs: &mut DtfsStructure,
    prev_cw_lag: i16,
    bfi: i16,
    s: &[i16],
    c: &[i16],
    prev_cw_d: &DtfsStructure,
    st: &mut DecoderState,
) {
    let mut prev_dtfs = dtfs_new();
    let mut amp_idx = [0i16; 2];
    let temp_pl = prev_cw_lag;
    let temp_l = currcw_q_dtfs.lag;
    let l = currcw_q_dtfs.lag;
    let mut num_erb: i16 = 24;

    if sub(currcw_q_dtfs.upper_cut_off_freq, 4000) == 0 {
        num_erb = 22;
    } else if sub(currcw_q_dtfs.upper_cut_off_freq, 6400) == 0 {
        num_erb = 24;
    }

    dtfs_copy(&mut prev_dtfs, prev_cw_d);
    if bfi == 0 {
        let power_idx = get_next_indice(st, 6) as i16;
        amp_idx[0] = get_next_indice(st, 6) as i16;
        amp_idx[1] = get_next_indice(st, 6) as i16;

        // Amplitude dequantisation. The normalisation and de-normalisation avoid a division by
        // 12800; the upper cut-off frequencies are multiplied by 2.56 (1/12800 in Q15) for
        // dequant_cw only, adjustLag needs them denormalised.
        let temp32n = l_mult(currcw_q_dtfs.upper_cut_off_freq, 10486); // Q0 + Q27 = Q28
        currcw_q_dtfs.upper_cut_off_freq = l_shr(temp32n, 13) as i16; // Q15
        let temp32n = l_mult(currcw_q_dtfs.upper_cut_off_freq_of_interest, 10486); // Q28
        currcw_q_dtfs.upper_cut_off_freq_of_interest = l_shr(temp32n, 13) as i16; // Q15

        dtfs_dequant_cw(
            prev_cw_lag,
            power_idx,
            &amp_idx,
            &mut st.last_lgain_d,
            &mut st.last_hgain_d,
            &mut st.lasterb_d,
            currcw_q_dtfs,
            num_erb,
        );
        // de-normalise the cut-off frequencies
        let mut temp32d = 0;
        let temp32n = l_shl(i32::from(currcw_q_dtfs.upper_cut_off_freq), 13); // Q28
        currcw_q_dtfs.upper_cut_off_freq = find_remd(temp32n, 20971, &mut temp32d) as i16;
        let temp32n = l_shl(i32::from(currcw_q_dtfs.upper_cut_off_freq_of_interest), 13); // Q28
        currcw_q_dtfs.upper_cut_off_freq_of_interest =
            find_remd(temp32n, 20971, &mut temp32d) as i16;
    }

    // Copying the phase spectrum over
    dtfs_adjust_lag(&mut prev_dtfs, l);

    let mut temp = sub(L_FRAME, temp_l); // Q0

    let mut exp = norm_s(temp_pl);
    let mut tmp = div_s(shl(1, sub(14, exp)), temp_pl); // Q(29 - exp)
    let mut l_tmp = l_mult(temp, tmp); // Q(31 - exp); +1 due to /2
    l_tmp = l_shl(l_tmp, sub(exp, 15)); // Q16

    exp = norm_s(temp_l);
    tmp = div_s(shl(1, sub(14, exp)), temp_l); // Q(29 - exp)
    let mut l_tmp1 = l_mult(temp, tmp); // Q(31 - exp); +1 due to /2
    l_tmp1 = l_shl(l_tmp1, sub(exp, 15)); // Q16

    l_tmp = l_add(l_tmp, l_tmp1); // Q16

    tmp = lshr(extract_l(l_tmp), 1); // Q15
    l_tmp = l_mult(temp_l, tmp); // Q16
    temp = rint_new(l_tmp);
    let erot = sub(temp_l, temp); // Q0

    q2phase_shift(&mut prev_dtfs, shl(erot, 2), currcw_q_dtfs.lag, s, c);
    if sub(bfi, 1) == 0 {
        dtfs_car2pol(currcw_q_dtfs);
    }
    // Phase copying is done through copy_phase instead of car2pol and pol2car
    let amplitudes = *currcw_q_dtfs;
    copy_phase(&prev_dtfs, amplitudes, currcw_q_dtfs);

    {
        let mut temp = get_next_indice(st, 3) as i16;

        temp = sub(temp, 3);
        temp = shl(temp, 2); // Q2
        let lag = currcw_q_dtfs.lag;
        q2phase_shift(currcw_q_dtfs, temp, lag, s, c);
    }
}
