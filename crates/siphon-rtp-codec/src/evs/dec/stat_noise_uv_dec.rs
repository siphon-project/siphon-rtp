//! Decoder side of the stationary-noise modification (TS 26.442
//! `lib_dec/stat_noise_uv_dec_fx.c`; TS 26.445 §6.1.1.3.3): reads the noisiness parameter, keeps
//! the comfort-noise LSP / energy averages of long unvoiced runs up to date, and runs
//! `stat_noise_uv_mod_fx` on the frame.

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{ACELP_9K60, INACTIVE, M, UNVOICED};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::stat_noise_uv_mod::stat_noise_uv_mod;
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{add, l_add, l_mult, l_sub, sub};
use crate::itu::stl2009::{l_mult0, mac_r};

/// `stat_noise_uv_dec_fx`: decode the noisiness parameter of an unvoiced / inactive frame and
/// modify the excitation `exc2` and the LP coefficients `aq` of a stationary-noise frame.
pub fn stat_noise_uv_dec(
    st: &mut DecoderState,
    coder_type: i16,
    lsp_new: &[i16],
    lsp_mid: &[i16],
    aq: &mut [i16],
    exc2: &mut [i16],
) {
    let mut noisiness: i16 = 0;

    // Decode the noisiness parameter.
    if sub(coder_type, UNVOICED) == 0
        || (sub(coder_type, INACTIVE) == 0 && l_sub(st.core_brate, i32::from(ACELP_9K60)) <= 0)
    {
        noisiness = get_next_indice(st, 5) as i16;
    }

    // Update the long-term LSP / energy averages of comfort noise in long unvoiced runs.
    if sub(coder_type, INACTIVE) == 0 {
        if sub(st.unv_cnt, 20) > 0 {
            // lp_ener = 0.7 · lp_ener + 0.3 · lp_gainc²
            let mut l_tmp = l_mult0(st.lp_gainc, st.lp_gainc); // Q6
            l_tmp = mult_32_16(l_tmp, 9830); // 0.3 in Q15
            st.lp_ener = l_add(mult_32_16(st.lp_ener, 22938), l_tmp); // 0.7 in Q15

            for (cng, &new) in st.lsp_cng.iter_mut().zip(&lsp_new[..M as usize]) {
                // lspCNG = 0.9 · lspCNG + 0.1 · lsp_new
                let l_tmp = l_mult(new, 3277);
                *cng = mac_r(l_tmp, *cng, 29491);
            }
        } else {
            st.unv_cnt = add(st.unv_cnt, 1);
        }
    } else {
        st.unv_cnt = 0;
    }

    // Modify the excitation signal in stationary noise segments.
    if st.opt_amr_wb == 0 {
        stat_noise_uv_mod(
            coder_type,
            noisiness,
            &st.lsp_old,
            lsp_new,
            lsp_mid,
            aq,
            exc2,
            st.q_exc,
            0,
            &mut st.ge_sm,
            &mut st.uv_count,
            &mut st.act_count,
            &mut st.lspold_s,
            &mut st.noimix_seed,
            &mut st.min_alpha,
            &mut st.exc_pe,
            st.core_brate,
            st.bwidth,
            &mut st.q_stat_noise,
            &mut st.q_stat_noise_ge,
        );
    }
}
