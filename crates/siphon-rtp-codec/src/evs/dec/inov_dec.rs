//! Decoding of the algebraic (innovative) codebook of one ACELP subframe (TS 26.442
//! `lib_dec/inov_dec_fx.c`; TS 26.445 §6.1.1.2.2).

use crate::evs::cnst::{
    ACELP_12K65, ACELP_14K25, ACELP_15K85, ACELP_18K25, ACELP_19K85, ACELP_6K60, ACELP_8K85,
    FORMANT_SHARPENING_G1, FORMANT_SHARPENING_G1_16K, FORMANT_SHARPENING_G2,
    FORMANT_SHARPENING_G2_16K, L_FRAME,
};
use crate::evs::com::bitstream::{bit_alloc_idx, bit_alloc_idx_16khz};
use crate::evs::com::cb_shape::cb_shape;
use crate::evs::dec::dec2t32::{dec_acelp_1t64, dec_acelp_2t32};
use crate::evs::dec::dec4t64::dec_acelp_4t64;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{FCB_BITS_16KHZ_TBL, FCB_BITS_TBL};
use crate::itu::basic_ops::{add, l_sub, shr, sub};
use crate::itu::stl2009::mac_r;

/// `table[index]` for a bit-allocation row the coder type and bit rate select; 0 past the table.
/// Every row a valid frame produces is inside its table; a corrupted coder type can point past it,
/// where the reference reads out of bounds.
fn at(table: &[i16], index: i32) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or(0)
}

/// `inov_decode_fx`: decodes the algebraic codevector `code` (`L_SUBFR` samples, Q12) of the
/// subframe at `i_subfr` and shapes it (pre-emphasis by `tilt_code`, pitch and formant
/// sharpening by `p_aq`). `pt_pitch` is the subframe's fractional pitch in Q6.
pub fn inov_decode(
    st: &mut DecoderState,
    core_brate: i32,
    opt_amr_wb: i16,
    l_frame: i16,
    coder_type: i16,
    sharp_flag: i16,
    i_subfr: i16,
    tc_subfr: i16,
    p_aq: &[i16],
    tilt_code: i16,
    pt_pitch: i16,
    code: &mut [i16],
) {
    let (g1, g2) = if sub(l_frame, L_FRAME) == 0 {
        (FORMANT_SHARPENING_G1, FORMANT_SHARPENING_G2)
    } else {
        (FORMANT_SHARPENING_G1_16K, FORMANT_SHARPENING_G2_16K)
    };

    if opt_amr_wb == 0 {
        // `TC_SUBFR2IDX_16KHZ_fx(x)` is `mac_r(1024L, x, 512)` and `TC_SUBFR2IDX_fx(x)` is
        // `add(s_min(3, s_max(0, sub(x, 1))), TC_SUBFR2IDX_16KHZ_fx(x))` (lib_com/cnst_fx.h).
        let tc_idx_16k = mac_r(1024, tc_subfr, 512);
        let n_bits = if sub(l_frame, L_FRAME) == 0 {
            let tc_idx = add(3.min(0.max(sub(tc_subfr, 1))), tc_idx_16k);
            at(
                &FCB_BITS_TBL,
                bit_alloc_idx(core_brate, coder_type, i_subfr, tc_idx),
            )
        } else {
            // L_frame == L_FRAME16k
            at(
                &FCB_BITS_16KHZ_TBL,
                bit_alloc_idx_16khz(core_brate, coder_type, i_subfr, tc_idx_16k),
            )
        };
        if sub(n_bits, 7) == 0 {
            dec_acelp_1t64(st, code);
        } else if sub(n_bits, 12) == 0 {
            dec_acelp_2t32(st, code);
        } else {
            dec_acelp_4t64(st, n_bits, code, opt_amr_wb);
        }
    } else if l_sub(core_brate, i32::from(ACELP_6K60)) == 0 {
        dec_acelp_2t32(st, code);
    } else if l_sub(core_brate, i32::from(ACELP_8K85)) == 0 {
        dec_acelp_4t64(st, 20, code, opt_amr_wb);
    } else if l_sub(core_brate, i32::from(ACELP_12K65)) == 0 {
        dec_acelp_4t64(st, 36, code, opt_amr_wb);
    } else if l_sub(core_brate, i32::from(ACELP_14K25)) == 0 {
        dec_acelp_4t64(st, 44, code, opt_amr_wb);
    } else if l_sub(core_brate, i32::from(ACELP_15K85)) == 0 {
        dec_acelp_4t64(st, 52, code, opt_amr_wb);
    } else if l_sub(core_brate, i32::from(ACELP_18K25)) == 0 {
        dec_acelp_4t64(st, 64, code, opt_amr_wb);
    } else if l_sub(core_brate, i32::from(ACELP_19K85)) == 0 {
        dec_acelp_4t64(st, 72, code, opt_amr_wb);
    } else {
        dec_acelp_4t64(st, 88, code, opt_amr_wb);
    }

    cb_shape(
        1,
        1,
        0,
        sharp_flag,
        0,
        g1,
        g2,
        p_aq,
        code,
        tilt_code,
        shr(add(pt_pitch, 26), 6),
        0,
        &mut st.stl,
    );
}
