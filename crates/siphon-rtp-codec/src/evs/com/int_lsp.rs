//! Interpolation of the LSPs over the subframes of a frame (TS 26.442 `lib_com/int_lsp_fx.c`;
//! TS 26.445 §5.1.9.6 / §6.1.1.1).

use crate::evs::cnst::{L_FRAME, M16K};
use crate::evs::com::lsf_tools::{e_lpc_f_isp_a_conversion, e_lpc_f_lsp_a_conversion};
use crate::evs::rom::{
    INTERPOL_FRAC_16K_FX, INTERPOL_FRAC_MID_16K_FEC_FX, INTERPOL_FRAC_MID_16K_FX,
    INTERPOL_FRAC_MID_FEC_FX, INTERPOL_FRAC_MID_FX, INTERPOL_FRAC_MID_RELAXPREV_12K8_FX,
    INTERPOL_FRAC_MID_RELAXPREV_16K_FX, INTERPOL_FRAC_MID_RELAXPREV_PRED_12K8_FX,
    INTERPOL_FRAC_MID_RELAXPREV_PRED_16K_FX,
};
use crate::itu::basic_ops::{add, l_mac, l_mult, round_word, shr, sub};
use crate::itu::stl2009::mac_r;

/// `int_lsp4_fx`: the LP coefficients (Q12) of every subframe, `m + 1` per subframe into `aq`,
/// interpolated between the past frame's (`lsp_old`), the mid-frame (`lsp_mid`) and the current
/// end-frame (`lsp_new`) LSPs (Q15); the last subframe uses `lsp_new` as is.
///
/// `relax_prev_lsf_interp` picks the weights: 1 relaxes the past frame's weight, 2 is the FEC
/// set, -1 the relaxed predictive set, anything else the regular one.
pub fn int_lsp4(
    l_frame: i16,
    lsp_old: &[i16],
    lsp_mid: &[i16],
    lsp_new: &[i16],
    aq: &mut [i16],
    m: i16,
    relax_prev_lsf_interp: i16,
) {
    let mut lsp = [0i16; M16K as usize];

    let int_coeffs: &[i16] = if sub(l_frame, L_FRAME) == 0 {
        if sub(relax_prev_lsf_interp, 1) == 0 {
            &INTERPOL_FRAC_MID_RELAXPREV_12K8_FX
        } else if sub(relax_prev_lsf_interp, 2) == 0 {
            &INTERPOL_FRAC_MID_FEC_FX
        } else if sub(relax_prev_lsf_interp, -1) == 0 {
            &INTERPOL_FRAC_MID_RELAXPREV_PRED_12K8_FX
        } else {
            &INTERPOL_FRAC_MID_FX
        }
    } else if sub(relax_prev_lsf_interp, 1) == 0 {
        // L_frame == L_FRAME16k
        &INTERPOL_FRAC_MID_RELAXPREV_16K_FX
    } else if sub(relax_prev_lsf_interp, 2) == 0 {
        &INTERPOL_FRAC_MID_16K_FEC_FX
    } else if sub(relax_prev_lsf_interp, -1) == 0 {
        &INTERPOL_FRAC_MID_RELAXPREV_PRED_16K_FX
    } else {
        &INTERPOL_FRAC_MID_16K_FX
    };

    let order = m.max(0) as usize;
    let stride = order + 1;
    let k = sub(shr(l_frame, 6), 1).max(0) as usize;
    let mut pt_int_coeffs = 0usize;
    let mut aq_at = 0usize;
    for _ in 0..k {
        // Three weights per subframe; the tables hold exactly (subframes - 1) triples.
        let Some(&[c0, c1, c2]) = int_coeffs.get(pt_int_coeffs..pt_int_coeffs + 3) else {
            break;
        };
        for i in 0..order {
            let mut l_tmp = l_mult(lsp_old[i], c0); // Q31
            l_tmp = l_mac(l_tmp, lsp_mid[i], c1); // Q31
            lsp[i] = mac_r(l_tmp, lsp_new[i], c2);
        }
        pt_int_coeffs += 3;

        e_lpc_f_lsp_a_conversion(&lsp, &mut aq[aq_at..], m);
        aq_at += stride;
    }

    // Last subframe
    e_lpc_f_lsp_a_conversion(lsp_new, &mut aq[aq_at..], m);
}

/// `int_lsp_fx`: the LP coefficients (Q12) of every subframe, `m + 1` per subframe into `aq`,
/// interpolated between the past (`lsp_old`) and current (`lsp_new`) LSPs (Q15) with the weights
/// `int_coeffs` (Q15, one per subframe) at 12.8 kHz or `interpol_frac_16k` at 16 kHz. With
/// `opt_amr_wb` the vectors are ISPs and converted with `E_LPC_f_isp_a_conversion`.
pub fn int_lsp(
    l_frame: i16,
    lsp_old: &[i16],
    lsp_new: &[i16],
    aq: &mut [i16],
    m: i16,
    int_coeffs: &[i16],
    opt_amr_wb: i16,
) {
    let mut lsp = [0i16; M16K as usize];

    let tmp = shr(l_frame, 6);

    let pt_int_coeffs: &[i16] = if sub(l_frame, L_FRAME) == 0 {
        int_coeffs
    } else {
        // L_frame == L_FRAME16k
        &INTERPOL_FRAC_16K_FX
    };
    let order = (m.max(0) as usize).min(lsp.len());
    let stride = order + 1;
    let mut aq_at = 0usize;
    for k in 0..tmp.max(0) as usize {
        let Some(&fnew) = pt_int_coeffs.get(k) else {
            break;
        };
        let mut fold = sub(32767, fnew);
        if fold != 0 {
            fold = add(fold, 1);
        }
        for i in 0..order {
            let mut l_tmp = l_mult(lsp_old[i], fold);
            l_tmp = l_mac(l_tmp, lsp_new[i], fnew);
            if fold == 0 {
                l_tmp = l_mac(l_tmp, lsp_new[i], 1);
            }
            lsp[i] = round_word(l_tmp);
        }
        if opt_amr_wb != 0 {
            e_lpc_f_isp_a_conversion(&lsp, &mut aq[aq_at..], m);
        } else {
            e_lpc_f_lsp_a_conversion(&lsp, &mut aq[aq_at..], m);
        }
        aq_at += stride;
    }
}
