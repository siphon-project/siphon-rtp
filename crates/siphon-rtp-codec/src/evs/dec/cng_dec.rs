//! Comfort-noise decoding of an inactive ACELP frame: the SID parameters (LSPs, energy, spectral
//! envelope) and the hangover averaging that smooths the transition from active speech (TS 26.442
//! `lib_dec/cng_dec_fx.c`; TS 26.445 §6.7.2). `swb_CNG_dec_fx` and its local `shb_CNG_decod_fx`
//! (the SWB TBE comfort noise) are in `cng_dec/swb_cng.rs`.

use crate::evs::basop::{l_extract_lc, mpy_32_16_1, mult_32_16};
use crate::evs::cnst::{
    ACELP_13K20, ACELP_16K40, ACELP_7K20, ACELP_8K00, ACELP_9K60, BUF_L_NRG_FX, CNG_ISF_FACT_FX,
    FRAME_NO_DATA, HO_HIST_SIZE, INACTIVE, INT_FS_16K_FX, INT_FS_FX, ISTEP_AMR_WB_SID_FX,
    ISTEP_SID_FX, L_FRAME, L_FRAME16K, L_SUBFR, M, MIN_ACT_CNG_UPD, NUM_ENV_CNG,
    ONE_OVER_BUF_H_NRG_FX, SID_1K75, SID_2K40, WB,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::cng_exc::{cng_envelope_band, cng_log2_frame_energy};
use crate::evs::com::enr_1_az::enr_1_az;
use crate::evs::com::isf_dec_amr_wb::isf_dec_amr_wb;
use crate::evs::com::lsf_tools::{e_lpc_f_isp_a_conversion, e_lpc_f_lsp_a_conversion, lsp2lsf};
use crate::evs::com::lsp_conv_poly::lsp_convert_poly;
use crate::evs::com::math_op::pow2;
use crate::evs::dec::lsf_dec::lsf_dec;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{CNG_DETAILS_CODEBOOK_FX, W_DTX_HO_FX};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_l, l_add, l_deposit_l, l_mult, l_shl, l_shr, l_sub, mult_r, norm_s,
    shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0, mac_r};

mod swb_cng;
pub use swb_cng::swb_cng_dec;

const ORDER: usize = M as usize;
const ENVELOPE_BANDS: usize = NUM_ENV_CNG as usize;
const HISTORY: usize = HO_HIST_SIZE as usize;

/// `CNG_dec_fx`: decodes the comfort-noise parameters of the frame. For a SID frame it dequantises
/// the LSFs (`lsf_new`, `lsp_new`) and the energy (`st.enew`, with the SWB-SID flag `sid_bw` and the
/// quantised envelope details `q_env` in a 2.4 kbit/s SID); any other inactive frame reuses the
/// last LSPs. It then updates the CNG LSP filter state `st.lsp_cng` and the hangover memories
/// (averaging the history after an active burst), sets `st.num_ho`, and writes the CNG filter
/// `A(z)` into every subframe of `aq`. `allow_cn_step` reports an energy step that the excitation
/// generator may follow at once.
pub fn cng_dec(
    st: &mut DecoderState,
    l_frame: i16,
    aq: &mut [i16],
    core_brate: i32,
    lsp_new: &mut [i16],
    lsf_new: &mut [i16],
    allow_cn_step: &mut i16,
    sid_bw: &mut i16,
    q_env: &mut [i32],
) {
    let sid_frame = core_brate == i32::from(SID_1K75) || core_brate == i32::from(SID_2K40);
    let mut burst_ho_cnt: i16 = 0;
    let mut m: i16 = 0;

    // Decode the CNG spectral envelope (only in a SID frame)
    if sid_frame {
        cng_dec_lsf(st, l_frame, aq, lsp_new, lsf_new);
    } else {
        // use the old LSP vector
        lsp_new[..ORDER].copy_from_slice(&st.lsp_old[..ORDER]);
        lsf_new[..ORDER].copy_from_slice(&st.lsf_old[..ORDER]);
    }

    // Initialize the CNG spectral envelope in case of the very first CNG frame
    if st.first_cng == 0 {
        st.lsp_cng = st.lsp_old;
    }

    // Decode the residual signal energy
    *allow_cn_step = 0;
    if sid_frame {
        burst_ho_cnt = cng_dec_energy(st, core_brate, allow_cn_step, sid_bw, q_env);
    }

    // CNG spectral envelope update
    if st.last_core_brate <= i32::from(SID_2K40) {
        // reset the hangover counter if not the first SID period
        if st.core_brate > i32::from(FRAME_NO_DATA) {
            st.num_ho = 0;
        }
        // update the LSPs if the last SID energy is not an outlier or there are too few hangover
        // frames
        if sub(st.num_ho, 3) < 0 || l_sub(mult_32_16(st.enew, 21845 /* 1/1.5 */), st.lp_ener) < 0 {
            for (cng, &new) in st.lsp_cng.iter_mut().zip(lsp_new.iter()) {
                // AR low-pass filter, Q15 (15 + 15 + 1 - 16)
                *cng = mac_r(
                    l_mult(CNG_ISF_FACT_FX, *cng),
                    (32768 - i32::from(CNG_ISF_FACT_FX)) as i16,
                    new,
                );
            }
        }
    } else {
        m = cng_dec_after_active(st, l_frame, lsp_new, burst_ho_cnt, allow_cn_step);
    }

    if st.core_brate == i32::from(SID_1K75) || st.core_brate == i32::from(SID_2K40) {
        cng_dec_update_hangover(
            st,
            l_frame,
            core_brate,
            lsp_new,
            *allow_cn_step,
            *sid_bw,
            q_env,
        );
        // Update the frame length memory
        st.last_cng_l_frame = st.l_frame;
        if core_brate != i32::from(SID_1K75) {
            st.num_ho = m;
        }
    }

    // Update the frame length memory
    st.last_cng_l_frame = st.l_frame;
    if core_brate != i32::from(SID_1K75) {
        st.num_ho = m;
    }

    if st.opt_amr_wb != 0 {
        e_lpc_f_isp_a_conversion(&st.lsp_cng, aq, M);
    } else {
        e_lpc_f_lsp_a_conversion(&st.lsp_cng, aq, M);
    }

    let tmp_loop = shr(l_frame, 6);
    for i in 1..tmp_loop.max(0) as usize {
        // L_frame / L_SUBFR
        aq.copy_within(0..ORDER + 1, i * (ORDER + 1));
    }
}

/// `CNG_dec_fx`'s dequantisation of the SID LSF vector (ISFs in the AMR-WB IO mode). A vector that
/// would give the synthesis filter too much energy is replaced by the old one.
fn cng_dec_lsf(
    st: &mut DecoderState,
    l_frame: i16,
    aq: &mut [i16],
    lsp_new: &mut [i16],
    lsf_new: &mut [i16],
) {
    let mut aq_tmp = [0i16; ORDER + 1];
    if st.opt_amr_wb != 0 {
        isf_dec_amr_wb(st, aq, lsf_new, lsp_new);
        // check if the ISPs may trigger too much synthesis energy
        e_lpc_f_isp_a_conversion(lsp_new, &mut aq_tmp, M);
    } else {
        let mut lsf_q_prediction: i16 = 0;
        let mut lsp_mid = [0i16; ORDER];
        let coder_type = INACTIVE;
        let bwidth = -1;
        lsf_dec(
            st,
            0,
            l_frame,
            coder_type,
            bwidth,
            aq,
            &mut lsf_q_prediction,
            lsf_new,
            lsp_new,
            &mut lsp_mid,
        );
        // check if the LSPs may trigger too much synthesis energy
        e_lpc_f_lsp_a_conversion(lsp_new, &mut aq_tmp, M);
    }
    let enr_new = enr_1_az(&aq_tmp, 2 * L_SUBFR);
    if shr(enr_new, 14) > 0 {
        // use the old LSP vector
        lsp_new[..ORDER].copy_from_slice(&st.lsp_old[..ORDER]);
        lsf_new[..ORDER].copy_from_slice(&st.lsf_old[..ORDER]);
    }
}

/// `CNG_dec_fx`'s decoding of the SID energy index into `st.enew` (Q6), with the step detection
/// and, in a 2.4 kbit/s SID, the hangover count (returned), the SWB-SID flag and the envelope
/// details.
fn cng_dec_energy(
    st: &mut DecoderState,
    core_brate: i32,
    allow_cn_step: &mut i16,
    sid_bw: &mut i16,
    q_env: &mut [i32],
) -> i16 {
    let mut burst_ho_cnt: i16 = 0;
    let mut istep = ISTEP_AMR_WB_SID_FX;
    if core_brate == i32::from(SID_2K40) {
        istep = ISTEP_SID_FX;
    }

    // initialize the energy quantization parameters
    let mut num_bits = 6;
    if st.opt_amr_wb == 0 {
        num_bits = 7;
    }

    // decode the energy index
    let mut l_enr_index = get_next_indice(st, num_bits) as i16;

    let tmp1 = if st.last_core_brate <= i32::from(SID_2K40) || sub(st.prev_bfi, 1) == 0 {
        add(st.old_enr_index, 20)
    } else {
        add(st.old_enr_index, 40)
    };
    if sub(l_enr_index, tmp1) > 0 && st.old_enr_index >= 0 {
        // likely a bit error and not the start-up
        l_enr_index = tmp1;
        l_enr_index = l_enr_index.min(127);
        if st.opt_amr_wb != 0 {
            l_enr_index = l_enr_index.min(63);
        }
    }

    if st.last_core_brate > i32::from(SID_1K75)
        && st.first_cng != 0
        && st.old_enr_index >= 0
        && sub(l_enr_index, add(st.old_enr_index, 1)) > 0
    {
        *allow_cn_step = 1;
    }

    st.old_enr_index = l_enr_index;
    if l_enr_index == 0 {
        l_enr_index = -5;
    }
    // Enew = L_enr_index / step - 2.0
    let l_ener = l_mult(l_enr_index, istep); // Q16 (0 + 15)
                                             // (the subtraction of 2 is not done, to leave the energy in Q2)

    // extract the integral and fractional parts
    let (ener_int, ener_fra) = l_extract_lc(l_ener);
    let ener_int = add(ener_int, 4); // Q2 to Q6

    // find the new energy value
    st.enew = pow2(ener_int, ener_fra);

    if core_brate == i32::from(SID_2K40) {
        burst_ho_cnt = get_next_indice(st, 3) as i16; // 3 bits

        *sid_bw = get_next_indice(st, 1) as i16;
        if *sid_bw == 0 {
            let env_idx = get_next_indice(st, 6) as usize;

            // get the quantised res_env_details
            for i in 0..ENVELOPE_BANDS {
                q_env[i] = l_deposit_l(CNG_DETAILS_CODEBOOK_FX[env_idx][i]);
            }
        }
    }
    // Reset the CNG history if the CNG frame length is changed
    if sub(st.bwidth, WB) == 0 && st.first_cng != 0 && sub(st.l_frame, st.last_cng_l_frame) != 0 {
        st.ho_hist_size = 0;
    }
    burst_ho_cnt
}

/// `CNG_dec_fx`'s update after an active period (the last frame was neither a SID nor a NO_DATA
/// frame): the CNG mode from the last active rate, the hangover history restored from the circular
/// buffers of the active frames, and the LSP / envelope averaging over it. Returns `m`, the number
/// of averaged history entries.
fn cng_dec_after_active(
    st: &mut DecoderState,
    l_frame: i16,
    lsp_new: &[i16],
    burst_ho_cnt: i16,
    allow_cn_step: &mut i16,
) -> i16 {
    // Update the CNG_mode if allowed
    if (st.opt_amr_wb != 0 || sub(st.bwidth, WB) == 0)
        && (st.first_cng == 0 || sub(st.act_cnt2, MIN_ACT_CNG_UPD) >= 0)
    {
        st.cng_mode = if st.last_active_brate > i32::from(ACELP_16K40) {
            -1
        } else if st.last_active_brate > i32::from(ACELP_13K20) {
            4
        } else if st.last_active_brate > i32::from(ACELP_9K60) {
            3
        } else if st.last_active_brate > i32::from(ACELP_8K00) {
            2
        } else if st.last_active_brate > i32::from(ACELP_7K20) {
            1
        } else {
            0
        };
    }

    // If this is the first SID after an active burst, update the LSF history from the circular
    // buffer
    let burst_ho_cnt = burst_ho_cnt.min(st.ho_circ_size);
    st.act_cnt = 0;
    cng_dec_restore_history(st, l_frame, burst_ho_cnt);

    if st.ho_hist_size > 0 {
        // can be -1 at init
        // allow_cn_step |= (ho_ener_hist[ho_hist_ptr] > 4.0 * lp_ener)
        let l_tmp1 = l_shr(st.ho_ener_hist[st.ho_hist_ptr as usize], 2);
        let l_tmp1 = l_sub(l_tmp1, st.lp_ener);
        if l_tmp1 > 0 {
            *allow_cn_step |= 1;
        }
    }
    if *allow_cn_step == 0 && st.ho_hist_size > 0 {
        cng_dec_average_history(st, lsp_new)
    } else {
        st.lsp_cng[..ORDER].copy_from_slice(&lsp_new[..ORDER]); // use the newly analysed ISFs
        0
    }
}

/// `CNG_dec_fx`'s copy of the last `burst_ho_cnt` active frames of the circular buffers
/// (`ho_*_circ`) into the hangover history (`ho_*_hist`), converting LSPs between the 12.8 and
/// 16 kHz internal rates where the frame length differs.
fn cng_dec_restore_history(st: &mut DecoderState, l_frame: i16, burst_ho_cnt: i16) {
    let mut s_ptr = add(sub(st.ho_circ_ptr, burst_ho_cnt), 1);
    if s_ptr < 0 {
        s_ptr = add(s_ptr, st.ho_circ_size);
    }

    let mut ll = burst_ho_cnt;
    while ll > 0 {
        st.ho_hist_ptr = add(st.ho_hist_ptr, 1);
        if sub(st.ho_hist_ptr, HO_HIST_SIZE) == 0 {
            st.ho_hist_ptr = 0;
        }
        let source = s_ptr as usize;
        let target = st.ho_hist_ptr as usize;

        // conversion between 12.8k and 16k LSPs
        if (sub(l_frame, L_FRAME16K) == 0 && st.ho_16k_lsp[source] == 0)
            || (sub(l_frame, L_FRAME) == 0 && sub(st.ho_16k_lsp[source], 1) == 0)
        {
            // conversion from 16k LSPs to 12k8
            lsp_convert_poly(&mut st.ho_lsp_circ[source * ORDER..], l_frame, 0);
        }
        // update the circular buffers
        let lsp: [i16; ORDER] = st.ho_lsp_circ[source * ORDER..(source + 1) * ORDER]
            .try_into()
            .unwrap_or([0; ORDER]);
        st.ho_lsp_hist[target * ORDER..(target + 1) * ORDER].copy_from_slice(&lsp);
        st.ho_ener_hist[target] = st.ho_ener_circ[source];
        st.ho_sid_bw = l_shl(st.ho_sid_bw & 0x3fff_ffff, 1);
        let env: [i32; ENVELOPE_BANDS] = st.ho_env_circ
            [source * ENVELOPE_BANDS..(source + 1) * ENVELOPE_BANDS]
            .try_into()
            .unwrap_or([0; ENVELOPE_BANDS]);
        st.ho_env_hist[target * ENVELOPE_BANDS..(target + 1) * ENVELOPE_BANDS]
            .copy_from_slice(&env);

        st.ho_hist_size = add(st.ho_hist_size, 1);
        if sub(st.ho_hist_size, HO_HIST_SIZE) > 0 {
            st.ho_hist_size = HO_HIST_SIZE;
        }

        s_ptr = add(s_ptr, 1);
        if sub(s_ptr, st.ho_circ_size) == 0 {
            s_ptr = 0;
        }
        ll -= 1;
    }
}

/// The LSP and envelope history entries `cng_dec_average_history` collects (`tmp`, `tmp_env`).
struct AveragedHistory {
    lsp: [i16; HISTORY * ORDER],
    envelope: [i32; HISTORY * ENVELOPE_BANDS],
    /// `m`: the number of LSP vectors collected.
    count: i16,
    /// `m1`: the number of envelopes collected.
    envelope_count: i16,
}

/// `CNG_dec_fx`'s energy-weighted selection of the hangover history: the entries whose energy
/// lies within [`BUF_L_NRG_FX`, 1/`ONE_OVER_BUF_H_NRG_FX`] of the latest one, with `st.lp_ener` set
/// to their weighted mean.
fn cng_dec_collect_history(st: &mut DecoderState) -> AveragedHistory {
    let mut collected = AveragedHistory {
        lsp: [0; HISTORY * ORDER],
        envelope: [0; HISTORY * ENVELOPE_BANDS],
        count: 0,
        envelope_count: 0,
    };
    // use the average of the energies below the last energy
    let mut ptr = st.ho_hist_ptr;
    let latest = st.ho_ener_hist[ptr as usize];
    let at = ptr as usize;
    collected.lsp[..ORDER].copy_from_slice(&st.ho_lsp_hist[at * ORDER..(at + 1) * ORDER]);
    let mut m1: i16 = 0;
    if st.ho_sid_bw & 0x1 == 0 {
        collected.envelope[..ENVELOPE_BANDS]
            .copy_from_slice(&st.ho_env_hist[at * ENVELOPE_BANDS..(at + 1) * ENVELOPE_BANDS]);
        m1 = 1;
    }
    let mut l_enr = mult_32_16(latest, W_DTX_HO_FX[0]); // Q6 + 15 - 15 -> Q6

    let mut weights = W_DTX_HO_FX[0]; // Q15

    let mut m: i16 = 1;
    for k in 1..st.ho_hist_size.max(0) {
        ptr = sub(ptr, 1);
        if ptr < 0 {
            ptr = HO_HIST_SIZE - 1;
        }
        let at = ptr as usize;
        let ener = st.ho_ener_hist[at];
        if l_sub(mult_32_16(ener, ONE_OVER_BUF_H_NRG_FX), latest) < 0
            && l_sub(ener, mult_32_16(latest, BUF_L_NRG_FX)) > 0
        {
            // enr += W_DTX_HO[k] * ho_ener_hist[ptr]
            let l_tmp1 = mult_32_16(ener, W_DTX_HO_FX[k as usize]); // Q6 + 15 - 15 -> Q6
            l_enr = l_add(l_enr, l_tmp1); // Q6

            // weights += W_DTX_HO[k]
            weights = add(weights, W_DTX_HO_FX[k as usize]); // Q15

            let slot = m as usize;
            collected.lsp[slot * ORDER..(slot + 1) * ORDER]
                .copy_from_slice(&st.ho_lsp_hist[at * ORDER..(at + 1) * ORDER]);
            if st.ho_sid_bw & l_shl(0x1, k) == 0 {
                let slot = m1 as usize;
                collected.envelope[slot * ENVELOPE_BANDS..(slot + 1) * ENVELOPE_BANDS]
                    .copy_from_slice(
                        &st.ho_env_hist[at * ENVELOPE_BANDS..(at + 1) * ENVELOPE_BANDS],
                    );
                m1 = add(m1, 1);
            }
            m = add(m, 1);
        }
    }

    // enr /= weights
    let exp = norm_s(weights);
    let tmp1 = div_s(shl(1, sub(14, exp)), weights); // Q(15 + 14 - exp - 15)
    let l_tmp1 = mult_32_16(l_enr, tmp1); // Q(14 - exp + 6 - 15) -> Q(5 - exp)
    l_enr = l_shl(l_tmp1, exp + 1); // Q6

    st.lp_ener = l_enr; // Q6
    collected.count = m;
    collected.envelope_count = m1;
    collected
}

/// `CNG_dec_fx`'s outlier-rejecting mean of the collected LSP vectors: the one (or two, from four
/// vectors on) with the largest spectral-distortion measure are left out. Returns the mean.
fn cng_dec_mean_lsp(st: &DecoderState, tmp: &[i16], m: i16) -> [i16; ORDER] {
    let mut lsf_tmp = [0i16; ORDER];
    let mut c = [0i32; HISTORY];
    let mut max = [0i32; 2];
    let mut max_idx = [0usize; 2];

    for i in 0..m.max(0) as usize {
        let ftmp;
        let mut l_tmp;
        if sub(st.l_frame, L_FRAME) == 0 {
            lsp2lsf(&tmp[i * ORDER..], &mut lsf_tmp, M, i32::from(INT_FS_FX));
            ftmp = 964; // X2.56
            let tmpv = sub(16384, add(lsf_tmp[ORDER - 1], ftmp)); // QX2.56
            l_tmp = l_mult0(tmpv, tmpv); // QX6.5536
        } else {
            lsp2lsf(&tmp[i * ORDER..], &mut lsf_tmp, M, i32::from(INT_FS_16K_FX));
            ftmp = 1205; // QX2.56
            let tmpv = sub(20480, add(lsf_tmp[ORDER - 1], ftmp)); // QX2.56
            l_tmp = l_mult0(tmpv, tmpv); // QX6.5536
        }

        let tmpv = sub(lsf_tmp[0], ftmp); // QX2.56
        l_tmp = l_mac0(l_tmp, tmpv, tmpv); // QX6.5536
        for j in 0..ORDER - 1 {
            let tmpv = sub(sub(lsf_tmp[j + 1], lsf_tmp[j]), ftmp); // QX2.56
            l_tmp = l_mac0(l_tmp, tmpv, tmpv); // QX6.5536
        }

        c[i] = mpy_32_16_1(l_tmp, 1928); // QX6.5536

        if l_sub(c[i], max[0]) > 0 {
            max[1] = max[0];
            max_idx[1] = max_idx[0];
            max[0] = c[i];
            max_idx[0] = i;
        } else if l_sub(c[i], max[1]) > 0 {
            max[1] = c[i];
            max_idx[1] = i;
        }
    }

    let mut lsp_tmp = [0i16; ORDER];
    if sub(m, 1) == 0 {
        lsp_tmp.copy_from_slice(&tmp[..ORDER]);
    } else if sub(m, 4) < 0 {
        for i in 0..ORDER {
            let mut l_tmp1 = 0;
            for j in 0..m as usize {
                l_tmp1 = l_add(l_tmp1, l_deposit_l(tmp[j * ORDER + i]));
            }
            l_tmp1 = l_sub(l_tmp1, l_deposit_l(tmp[max_idx[0] * ORDER + i]));
            let tmpv = div_s(1, sub(m, 1)); // Q15
            l_tmp1 = mpy_32_16_1(l_tmp1, tmpv); // Q15
            lsp_tmp[i] = extract_l(l_tmp1); // Q15
        }
    } else {
        for i in 0..ORDER {
            let mut l_tmp1 = 0;
            for j in 0..m as usize {
                l_tmp1 = l_add(l_tmp1, l_deposit_l(tmp[j * ORDER + i]));
            }
            l_tmp1 = l_sub(
                l_tmp1,
                l_add(
                    l_deposit_l(tmp[max_idx[0] * ORDER + i]),
                    l_deposit_l(tmp[max_idx[1] * ORDER + i]),
                ),
            ); // Q15
            let tmpv = div_s(1, sub(m, 2)); // Q15
            l_tmp1 = mpy_32_16_1(l_tmp1, tmpv); // Q15
            lsp_tmp[i] = extract_l(l_tmp1); // Q15
        }
    }
    lsp_tmp
}

/// `CNG_dec_fx`'s averaging of the hangover history into the CNG LSPs (`st.lsp_cng`) and envelope
/// (`st.lp_env`); returns `m`, the number of LSP vectors averaged.
fn cng_dec_average_history(st: &mut DecoderState, lsp_new: &[i16]) -> i16 {
    let collected = cng_dec_collect_history(st);
    let m = collected.count;
    let m1 = collected.envelope_count;
    let lsp_tmp = cng_dec_mean_lsp(st, &collected.lsp, m);

    let mut dist: i16 = 0; // Q15
    let mut max_dev: i16 = 0; // Q15
    for i in 0..ORDER {
        let dev = abs_s(sub(lsp_tmp[i], lsp_new[i])); // Q15
        dist = add(dist, dev); // Q15
        if sub(dev, max_dev) > 0 {
            max_dev = dev;
        }
    }

    if sub(dist, 13107) > 0 || sub(max_dev, 3277) > 0 {
        st.lsp_cng = lsp_tmp; // Q15
    } else {
        for i in 0..ORDER {
            // AR low-pass filter
            st.lsp_cng[i] = add(mult_r(26214, lsp_tmp[i]), mult_r(6554, lsp_new[i]));
        }
    }
    if m1 > 0 {
        let mut env = [0i32; ENVELOPE_BANDS];
        #[allow(clippy::needless_range_loop)] // `i` indexes `env` and the collected envelopes
        for i in 0..ENVELOPE_BANDS {
            let mut l_tmp = l_deposit_l(0);
            for j in 0..m1 as usize {
                // env[i] += tmp_env[j * NUM_ENV_CNG + i]
                l_tmp = l_add(l_tmp, collected.envelope[j * ENVELOPE_BANDS + i]);
            }
            // env[i] /= m1; env[i] = env[i] - 2 * lp_ener
            if sub(m1, 1) == 0 {
                l_tmp = l_sub(l_tmp, l_add(st.lp_ener, st.lp_ener));
            } else {
                let tmp1 = div_s(1, m1);
                l_tmp = mult_32_16(l_tmp, tmp1);
                l_tmp = l_sub(l_tmp, l_add(st.lp_ener, st.lp_ener));
            }
            env[i] = l_tmp;
        }
        st.lp_env = env;
    }
    m
}

/// `CNG_dec_fx`'s hangover memory update during CNG: a SID whose energy is no step up appends its
/// LSPs, energy and (for a non-SWB 2.4 kbit/s SID) envelope to the history.
fn cng_dec_update_hangover(
    st: &mut DecoderState,
    l_frame: i16,
    core_brate: i32,
    lsp_new: &[i16],
    allow_cn_step: i16,
    sid_bw: i16,
    q_env: &[i32],
) {
    // update the hangover memory during CNG
    if allow_cn_step == 0 && l_sub(st.enew, l_add(st.lp_ener, l_shr(st.lp_ener, 1))) < 0 {
        // update the pointer to the circular buffer of old LSP vectors
        st.ho_hist_ptr = add(st.ho_hist_ptr, 1);
        if sub(st.ho_hist_ptr, HO_HIST_SIZE) == 0 {
            st.ho_hist_ptr = 0;
        }
        let at = st.ho_hist_ptr as usize;

        // update the circular buffer of old LSP vectors with the new LSP vector
        st.ho_lsp_hist[at * ORDER..(at + 1) * ORDER].copy_from_slice(&lsp_new[..ORDER]);

        // update the hangover energy buffer
        st.ho_ener_hist[at] = st.enew;
        if core_brate == i32::from(SID_2K40) && sid_bw == 0 {
            // enr1 = log2(Enew * L_frame)
            let enr1 = cng_log2_frame_energy(st.enew, l_frame); // Q6
            let mut env = [0i32; ENVELOPE_BANDS];
            for i in 0..ENVELOPE_BANDS {
                // get the quantised envelope: env = 2^(enr1 - q_env) + 2 * Enew
                env[i] = cng_envelope_band(enr1, q_env[i]); // Q6
                let l_tmp = l_add(st.enew, st.enew);
                env[i] = l_add(env[i], l_tmp); // Q6
            }
            st.ho_sid_bw = l_shl(st.ho_sid_bw & 0x3fff_ffff, 1);
            st.ho_env_hist[at * ENVELOPE_BANDS..(at + 1) * ENVELOPE_BANDS].copy_from_slice(&env);
        } else if sid_bw != 0 {
            st.ho_sid_bw = l_shl(st.ho_sid_bw & 0x3fff_ffff, 1);
            st.ho_sid_bw |= 0x1;
        }

        st.ho_hist_size = add(st.ho_hist_size, 1);
        if sub(st.ho_hist_size, HO_HIST_SIZE) > 0 {
            st.ho_hist_size = HO_HIST_SIZE;
        }
    }
}
