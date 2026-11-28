//! LSF estimation for a lost frame (TS 26.442 `lib_com/lsf_dec_bfi_fx.c`; TS 26.447 §5.4.2.1,
//! TS 26.445 §6.1.1.1): the concealed LSFs fade from the last good frame's towards an adaptive
//! mean at a rate set by the class of the last good frame, and the quantiser memories are
//! updated as if the concealed vector had been decoded.

use crate::evs::cnst::{
    _ALPHA_S_FX, _ALPHA_UT_FX, _ALPHA_UU_FX, _ALPHA_U_FX, _ALPHA_U_FX_X_2, _ALPHA_VT_FX,
    _ALPHA_V_FX, AUDIO, BETA_FEC_FX, FS_2, INACTIVE_CLAS, INT_FS_16K_FX, INT_FS_FX, ISF_GAP_FX,
    LSF_GAP_FX, L_FRAME, M, MODE1, MODE1_LSF_GAP_FX, MU_MA_FX, NB, ONSET, SIN_ONSET, UNVOICED,
    UNVOICED_CLAS, UNVOICED_TRANSITION, VOICED_CLAS,
};
use crate::evs::com::basop_util::inv16;
use crate::evs::com::lsf_tools::{reorder_isf, reorder_lsf};
use crate::evs::com::tools::copy;
use crate::evs::rom::{
    GENB_AVE_FX, GEWB2_AVE_FX, GEWB_AVE_FX, MEANS_SWB_CLEANSPEECH_LSF25K6,
    MEANS_SWB_CLEANSPEECH_LSF32K0, MEANS_WB_CLEANSPEECH_LSF16K0, MEAN_ISF_WB,
};
use crate::itu::basic_ops::{add, l_msu, l_mult, l_sub, mult, shl, shr, sub};
use crate::itu::stl2009::{i_mult, mac_r, msu_r};

/// `M` as an index.
const MU: usize = M as usize;

/// `lsf_dec_bfi`: the concealed LSFs `lsf` (Q(x2.56)) of a lost frame, faded from `lsfold`
/// towards a mean of `lsf_adaptive_mean` and a fixed long-term mean, and the AR (`mem_ar`) and
/// MA (`mem_ma`) predictor memories updated for the next frame.
///
/// `lsf_base` is the MODE2 mean (`PlcGetLsfBase`), unused in MODE1; MODE2 fades to `lsf_cng`
/// instead when `plc_background_noise_updated`. When `lsf_q_cng` is given, it receives the same
/// fade of `old_lsf_q_cng`, the background-noise LSFs. A MODE2 call without `lsf_base` (the
/// reference would dereference a null pointer) fades to the 12.8 kHz MODE1 mean.
pub fn lsf_dec_bfi(
    codec_mode: i16,
    lsf: &mut [i16],
    lsfold: &[i16],
    lsf_adaptive_mean: &[i16],
    lsf_base: Option<&[i16]>,
    mem_ma: &mut [i16],
    mem_ar: &mut [i16],
    stab_fac: i16,
    last_coder_type: i16,
    l_frame: i16,
    last_good: i16,
    nb_lost_cmpt: i16,
    plc_background_noise_updated: i8,
    mut lsf_q_cng: Option<&mut [i16]>,
    lsf_cng: Option<&[i16]>,
    old_lsf_q_cng: Option<&[i16]>,
    last_gsc_pit_band_idx: i16,
    opt_amr_wb: i16,
    tcxonly: i8,
    mode1_bwidth: i16,
) {
    let mut lsf_mean = [0i16; MU];

    // pt_meansForMemUpdate is lsf_mean (MODE1) or lsfBase (MODE2), so it is selected below
    let base: &[i16] = lsf_base.unwrap_or(&GEWB_AVE_FX);
    let pt_means_for_fading: &[i16] = if sub(codec_mode, MODE1) == 0 {
        // Update inital guess to something stable, with proper sampling frequency and format
        // (ISF/LSF)
        if opt_amr_wb != 0 {
            &MEAN_ISF_WB
        } else if sub(l_frame, L_FRAME) == 0 {
            // 12.8kHz ACELP sampling
            if sub(mode1_bwidth, NB) == 0 {
                &GENB_AVE_FX
            } else {
                &GEWB_AVE_FX
            }
        } else {
            // 16kHz ACELP sampling
            &GEWB2_AVE_FX
        }
    } else {
        match lsf_cng {
            Some(cng) if plc_background_noise_updated != 0 => cng,
            _ => base,
        }
    };

    let alpha = lsf_dec_bfi_alpha(
        stab_fac,
        last_coder_type,
        last_good,
        nb_lost_cmpt,
        last_gsc_pit_band_idx,
    );
    let beta: i16 = if sub(codec_mode, MODE1) == 0 {
        BETA_FEC_FX
    } else if plc_background_noise_updated != 0 {
        0 // 0.f Q15
    } else {
        8192 // 0.25f Q15
    };
    for i in 0..MU {
        lsf_mean[i] = mac_r(
            l_mult(beta, pt_means_for_fading[i]),
            sub(32767, beta),
            lsf_adaptive_mean[i],
        );
        lsf[i] = mac_r(l_mult(alpha, lsfold[i]), sub(32767, alpha), lsf_mean[i]);

        if let (Some(q_cng), Some(old_q_cng)) = (lsf_q_cng.as_deref_mut(), old_lsf_q_cng) {
            q_cng[i] = mac_r(
                l_mult(alpha.max(26214), old_q_cng[i]),
                sub(32767, alpha.max(26214)),
                pt_means_for_fading[i],
            );
        }
    }

    // check LSF stability through LSF ordering
    if opt_amr_wb != 0 {
        reorder_isf(lsf, ISF_GAP_FX, M, FS_2);
    } else if sub(l_frame, L_FRAME) == 0 {
        if sub(codec_mode, MODE1) == 0 {
            reorder_lsf(lsf, MODE1_LSF_GAP_FX, M, i32::from(INT_FS_FX));
        } else {
            reorder_lsf(lsf, LSF_GAP_FX, M, i32::from(INT_FS_FX));
        }
        if let Some(q_cng) = lsf_q_cng {
            reorder_lsf(q_cng, LSF_GAP_FX, M, i32::from(INT_FS_FX));
        }
    } else if tcxonly != 0 {
        let gap: i16 = if sub(l_frame, 320) == 0 {
            143
        } else if sub(l_frame, 512) == 0 {
            90
        } else if sub(l_frame, 640) == 0 {
            72
        } else {
            48
        };
        reorder_lsf(lsf, gap, M, i32::from(INT_FS_FX));
    } else {
        reorder_lsf(lsf, MODE1_LSF_GAP_FX, M, i32::from(i_mult(l_frame, 50)));
        if let Some(q_cng) = lsf_q_cng {
            reorder_lsf(q_cng, LSF_GAP_FX, M, i32::from(INT_FS_16K_FX));
        }
    }

    // update the AR memory to be used in the next frame
    copy(lsf, mem_ar, M);

    // update the MA memory to be used in the next frame
    let pt_means_for_mem_update: &[i16] = if sub(codec_mode, MODE1) == 0 {
        &lsf_mean
    } else {
        base
    };
    for i in 0..MU {
        // factor 0x4000 means 0.5. Together with /2 in mem_MA-assignment, this results in an
        // attenuation of the MA Q memory
        let tmp = l_msu(l_mult(lsf[i], 0x4000), pt_means_for_mem_update[i], 0x4000);
        // Update with quantized prediction error for MA model
        mem_ma[i] = msu_r(tmp, MU_MA_FX / 2, mem_ma[i]);
    }
}

/// The fading factor of `lsf_dec_bfi` (Q15): by the class of the last good frame for the first
/// three lost frames, `1 / nbLostCmpt` after that.
fn lsf_dec_bfi_alpha(
    stab_fac: i16,
    last_coder_type: i16,
    last_good: i16,
    nb_lost_cmpt: i16,
    last_gsc_pit_band_idx: i16,
) -> i16 {
    if sub(nb_lost_cmpt, 3) > 0 {
        let mut exp: i16 = 15;
        let alpha = inv16(nb_lost_cmpt, &mut exp); // 1.f/bfi_cnt;
        return shl(alpha, exp);
    }
    if sub(last_coder_type, UNVOICED) == 0 {
        // Clear unvoiced last good frame
        _ALPHA_UU_FX
    } else if sub(last_coder_type, AUDIO) == 0 || sub(last_good, INACTIVE_CLAS) == 0 {
        if last_gsc_pit_band_idx > 0 && sub(nb_lost_cmpt, 1) > 0 {
            26214 // 0.8f Q15
        } else {
            32604 // 0.995f Q15
        }
    } else if sub(last_good, UNVOICED_CLAS) == 0 {
        if sub(nb_lost_cmpt, 1) <= 0 {
            // If stable, do not flatten the spectrum in the 1st erased frame
            add(
                mult(stab_fac, (32768 - i32::from(_ALPHA_U_FX_X_2)) as i16),
                _ALPHA_U_FX_X_2,
            )
        } else if sub(nb_lost_cmpt, 2) == 0 {
            sub(_ALPHA_U_FX_X_2, shr(_ALPHA_U_FX, 1)) // 0.6
        } else {
            _ALPHA_U_FX // go rapidly to CNG spectrum
        }
    } else if sub(last_good, UNVOICED_TRANSITION) == 0 {
        _ALPHA_UT_FX
    } else if sub(last_good, VOICED_CLAS) == 0 || sub(last_good, ONSET) == 0 {
        // clearly voiced - mild convergence to the CNG spectrum for the first 3 erased frames
        _ALPHA_V_FX
    } else if sub(last_good, SIN_ONSET) == 0 {
        _ALPHA_S_FX
    } else {
        // rapid convergence to the CNG spectrum (long erasure, ONSETS)
        _ALPHA_VT_FX
    }
}

/// `PlcGetLsfBase`: the mean LSF vector the MODE2 concealment fades to, by the LPC quantiser in
/// use (`lpc_quantization` 0: the high-rate one, whose real mean is not available during PLC),
/// the core sampling rate and the bandwidth.
#[must_use]
pub fn plc_get_lsf_base(lpc_quantization: i16, narrow_band: i16, sr_core: i32) -> &'static [i16] {
    // Not correct BW
    if lpc_quantization == 0 {
        // high rates, return value is never used; the correct value changes dynamically and is
        // not available during PLC
        if l_sub(sr_core, 32000) == 0 {
            return &MEANS_SWB_CLEANSPEECH_LSF32K0;
        } else if l_sub(sr_core, 25600) == 0 {
            return &MEANS_SWB_CLEANSPEECH_LSF25K6;
        }
        return &MEANS_WB_CLEANSPEECH_LSF16K0;
    }

    // lpcQuntization == 1 is left
    if l_sub(sr_core, 16000) == 0 {
        return &GEWB2_AVE_FX;
    }

    // sr_core == 12.8k is left
    if narrow_band == 0 {
        return &GEWB_AVE_FX;
    }

    // narrowBand == 1 is left
    &GENB_AVE_FX
}
