//! Pitch estimate kept for frame-erasure concealment (TS 26.442 `lib_dec/FEC_pitch_estim_fx.c`).

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    HQ_CORE, L_FRAME, L_FRAME16K, MAX_UPD_CNT, NB_SUBFR, NB_SUBFR16K, TRANSITION, VOICED_CLAS,
    VOICED_TRANSITION,
};
use crate::itu::basic_ops::{l_shl, mult_r, round_word, shl, shr, sub};

/// `FEC_pitch_estim_fx`: update the concealment pitch `bfi_pitch` (Q6), the frame length it was
/// taken at and the update counter from this frame's subframe pitches `pitch_buf` (Q6) and the
/// previous frames' `old_pitch_buf` (15Q16, at least `2·NB_SUBFR16k` entries).
pub fn fec_pitch_estim(
    opt_amr_wb: i16,
    last_core: i16,
    l_frame: i16,
    clas: i16,
    last_good: i16,
    pitch_buf: &[i16],
    old_pitch_buf: &[i32],
    bfi_pitch: &mut i16,
    bfi_pitch_frame: &mut i16,
    upd_cnt: &mut i16,
    coder_type: i16,
) {
    let tmp = mult_r(pitch_buf[1], 22938); // 0.7 * pitch_buf[1]
    let tmp1 = shl(tmp, 1); // 1.4 * pitch_buf[1]
    let tmp2 = round_word(l_shl(
        mpy_32_16_1(old_pitch_buf[(2 * NB_SUBFR - 1) as usize], 22938),
        6,
    ));
    let tmp3 = shl(tmp2, 1);
    let tmp16k1 = round_word(l_shl(
        mpy_32_16_1(old_pitch_buf[(2 * NB_SUBFR16K - 1) as usize], 22938),
        6,
    ));
    let tmp16k2 = shl(tmp16k1, 1);
    // The last subframe: L_frame / 64 - 1 (3 at 12.8 kHz, 4 at 16 kHz).
    let last_subframe = (shr(l_frame, 6) - 1).max(0) as usize;

    if last_core == HQ_CORE {
        *bfi_pitch = pitch_buf[last_subframe];
        *bfi_pitch_frame = l_frame;
        *upd_cnt = MAX_UPD_CNT;
    }

    if (clas == VOICED_CLAS && sub(last_good, VOICED_TRANSITION) >= 0)
        || (opt_amr_wb != 0 && clas == VOICED_CLAS)
    {
        let stable_last = sub(pitch_buf[3], tmp1) < 0 && sub(pitch_buf[3], tmp) > 0;
        if (stable_last
            && sub(pitch_buf[1], tmp3) < 0
            && sub(pitch_buf[1], tmp2) > 0
            && l_frame == L_FRAME)
            || (stable_last
                && sub(pitch_buf[1], tmp16k2) < 0
                && sub(pitch_buf[1], tmp16k1) > 0
                && l_frame == L_FRAME16K)
            || coder_type == TRANSITION
        {
            *bfi_pitch = pitch_buf[last_subframe];
            *bfi_pitch_frame = l_frame;
            *upd_cnt = 0;
        }
    }
}
