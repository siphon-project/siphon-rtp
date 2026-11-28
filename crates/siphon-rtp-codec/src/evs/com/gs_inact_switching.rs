//! Energy matching of the excitation when switching to an inactive frame coded by GSC (TS 26.442
//! `lib_com/gs_inact_switching_fx.c`; TS 26.445 §6.1.1.3.6).

use crate::evs::basop::l_extract_lc;
use crate::evs::cnst::{ACELP_24K40, ACELP_CORE, AUDIO, GENERIC, INACTIVE, MBANDS_GN, MODE1};
use crate::evs::cnst::{TRANSITION, VOICED};
use crate::evs::com::edct::edct_16fx;
use crate::evs::com::gs_gains::ener_per_band_comp;
use crate::evs::com::math_op::pow2;
use crate::itu::basic_ops::{add, extract_l, l_mac, l_mult, l_shl, l_shr, l_sub, round_word, sub};

const ALPHA0_FX: i16 = 13107;
const BETA0_FX: i16 = (32768 - ALPHA0_FX as i32) as i16;

/// `Inac_swtch_ematch_fx`: on an AUDIO frame (or an active / non-ACELP / MODE2 predecessor) reset
/// the long-term energy per band `lt_ener_per_band` (Q12) to this frame's; on an INACTIVE frame at
/// or below 24.4 kbit/s smooth it and rescale the excitation `exc2` (Q`q_exc`) per band in the
/// DCT domain towards it. `dct_exc_tmp` is the excitation's DCT (an input on AUDIO frames,
/// scratch otherwise).
pub fn inac_swtch_ematch(
    exc2: &mut [i16],
    dct_exc_tmp: &mut [i16],
    lt_ener_per_band: &mut [i16],
    coder_type: i16,
    l_frame: i16,
    core_brate: i32,
    q_exc: i16,
    bfi: i16,
    last_core: i16,
    last_codec_mode: i16,
) {
    let mut ener_per_bd = [0i16; MBANDS_GN as usize];

    // average energy per band
    if sub(coder_type, AUDIO) == 0 && bfi == 0 {
        ener_per_band_comp(dct_exc_tmp, &mut ener_per_bd, q_exc, MBANDS_GN, 1);

        // reset long-term energy per band
        lt_ener_per_band[..MBANDS_GN as usize].copy_from_slice(&ener_per_bd);
    } else if sub(coder_type, VOICED) == 0
        || sub(coder_type, GENERIC) == 0
        || sub(coder_type, TRANSITION) == 0
        || sub(last_core, ACELP_CORE) != 0
        || sub(last_codec_mode, MODE1) != 0
    {
        // Find spectrum and energy per band for GC and VC frames
        edct_16fx(exc2, dct_exc_tmp, l_frame, 5);

        ener_per_band_comp(dct_exc_tmp, &mut ener_per_bd, q_exc, MBANDS_GN, 1);

        // reset long-term energy per band
        lt_ener_per_band[..MBANDS_GN as usize].copy_from_slice(&ener_per_bd);
    } else if sub(coder_type, INACTIVE) == 0 && l_sub(core_brate, i32::from(ACELP_24K40)) <= 0 {
        // Find spectrum and energy per band for inactive frames
        edct_16fx(exc2, dct_exc_tmp, l_frame, 5);
        ener_per_band_comp(dct_exc_tmp, &mut ener_per_bd, q_exc, MBANDS_GN, 1);

        // More agressive smoothing in the first 50 frames
        let mut pt_exc = 0usize;
        for i in 0..MBANDS_GN as usize {
            // Compute smoothing gain to apply with gain limitation
            let mut l_tmp = l_mult(ALPHA0_FX, lt_ener_per_band[i]); // Q(15+12+1)=Q(28)
            l_tmp = l_mac(l_tmp, BETA0_FX, ener_per_bd[i]); // Q28
            lt_ener_per_band[i] = round_word(l_tmp); // Q12

            let mut ftmp = sub(lt_ener_per_band[i], ener_per_bd[i]); // Q12

            // ftmp = (float)pow(10, ftmp);= pow(2,3.321928*ftmp);
            l_tmp = l_mult(27213, ftmp); // Q(13+12+1)=Q26 ; 27213=3.321928 in Q13
            l_tmp = l_shr(l_tmp, 10); // From Q26 to Q16
            let (exp, frac) = l_extract_lc(l_tmp); // Extract exponent of ftmp
                                                   // Put 14 as exponent so that output of Pow2() will be 16384 < Pow2() <= 32767
            ftmp = extract_l(pow2(14, frac));

            let exp = sub(exp, 14);
            let count = if i < 2 { 8 } else { 16 };
            for _ in 0..count {
                let mut l_tmp = l_mult(dct_exc_tmp[pt_exc], ftmp); // Q_exc*Q0 -> Q(Q_exc+1)
                l_tmp = l_shl(l_tmp, add(exp, 15)); // Q(Q_exc+1) -> Q(16+Q_exc)
                dct_exc_tmp[pt_exc] = round_word(l_tmp);
                pt_exc += 1;
            }
        }

        // Going back to time
        edct_16fx(dct_exc_tmp, exc2, l_frame, 5);
    }
}
