//! Transition-coding (TC) decoding of the adaptive / glottal-shape excitation (TS 26.442
//! `lib_dec/transition_dec_fx.c`; TS 26.445 §6.1.1.2.4).
//!
//! The excitation buffers keep the reference's negative indexing: `exc[exc_at]` is the frame's
//! first sample with `L_EXC_MEM` (320) samples of history in front of it, and `bwe_exc[bwe_exc_at]`
//! the frame's first BWE excitation sample with `PIT16k_MAX * 2` (578) in front of it. The pitch
//! buffer pointer `**pt_pitch` is `pitch_buf[*pt_pitch]`.

use crate::evs::cnst::{
    L_EXC_MEM, L_FRAME, L_FRAME16K, L_IMPULSE, L_IMPULSE2, L_INTERPOL2, L_SUBFR, L_SUBFR_Q6, MODE1,
    PIT16K_FR2_EXTEND_10B, PIT16K_FR2_TC0_2SUBFR, PIT16K_MAX, PIT16K_MIN, PIT16K_MIN_EXTEND,
    PIT_MAX, PIT_MIN, PIT_UP_SAMP, TC_0_0, TC_0_128, TC_0_192, TC_0_64, TRANSITION,
};
use crate::evs::com::bitstream::{bit_alloc_idx, bit_alloc_idx_16khz, get_next_indice};
use crate::evs::com::limit_t0::limit_t0;
use crate::evs::com::math_op::i_mult2;
use crate::evs::com::pred_lt4::{pred_lt4, pred_lt4_tc};
use crate::evs::com::swb_tbe_com::{interp_code_4over2, interp_code_5over2, tbe_celp_exc_offset};
use crate::evs::dec::lp_exc_d::lp_filt_exc_dec;
use crate::evs::dec::pit_dec::{abs_pit_dec, delta_pit_dec, pit16k_q_dec, pit_q_dec};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    ACB_BITS_16KHZ_TBL, ACB_BITS_TBL, GLOTTAL_CDBK_FX, INTER4_2_FX, PITCH_INTER4_2,
    TBL_GAIN_TRANS_TC_FX,
};
use crate::itu::basic_ops::{add, l_mult, l_shl, negate, round_word, shl, shr, sub};
use crate::itu::stl2009::mac_r;

const SUBFR: usize = L_SUBFR as usize;

/// `TC_SUBFR2IDX_16KHZ_fx(x)` written out: -1 => 0, 0 => 0, 64 => 1, 128 => 2, 192 => 3, 256 => 4.
fn tc_subfr2idx_16khz_macro(x: i16) -> i16 {
    mac_r(1024, x, 512)
}

/// `ACB_bits_tbl[BIT_ALLOC_IDX_fx(core_brate, TRANSITION, i_subfr, TC_SUBFR2IDX_fx(tc_subfr))]`.
fn acb_bits_12k8(core_brate: i32, i_subfr: i16, tc_subfr: i16) -> i16 {
    // TC_SUBFR2IDX_fx(x) = add(s_min(3, s_max(0, sub(x, 1))), TC_SUBFR2IDX_16KHZ_fx(x))
    let tc = add(
        sub(tc_subfr, 1).clamp(0, 3),
        tc_subfr2idx_16khz_macro(tc_subfr),
    );
    let row = bit_alloc_idx(core_brate, TRANSITION, i_subfr, tc);
    usize::try_from(row)
        .ok()
        .and_then(|row| ACB_BITS_TBL.get(row))
        .copied()
        .unwrap_or(0)
}

/// `ACB_bits_16kHz_tbl[BIT_ALLOC_IDX_16KHZ_fx(core_brate, coder_type, i_subfr,
/// TC_SUBFR2IDX_16KHZ_fx(tc_subfr))]`.
fn acb_bits_16k(core_brate: i32, coder_type: i16, i_subfr: i16, tc_subfr: i16) -> i16 {
    let row = bit_alloc_idx_16khz(
        core_brate,
        coder_type,
        i_subfr,
        tc_subfr2idx_16khz_macro(tc_subfr),
    );
    usize::try_from(row)
        .ok()
        .and_then(|row| ACB_BITS_16KHZ_TBL.get(row))
        .copied()
        .unwrap_or(0)
}

/// The pitch of a subframe in Q6, as the pitch buffer stores it.
fn pitch_q6(t0: i16, t0_frac: i16) -> i16 {
    shl(add(shl(t0, 2), t0_frac), 4)
}

/// `(*pt_pitch) -= n` then `n` times `**pt_pitch = value; (*pt_pitch)++`: refill the `n` entries
/// before the pointer, which ends where it started.
fn fill_pitch_back(pitch_buf: &mut [i16], pt_pitch: usize, n: usize, value: i16) {
    let start = pt_pitch.saturating_sub(n);
    for slot in pitch_buf.iter_mut().take(pt_pitch).skip(start) {
        *slot = value;
    }
}

/// `pred_lt4` over subframe `i_subfr` (`L_SUBFR + 1` samples) and the matching copy of the BWE
/// excitation from `offset` samples back (`bwe_len` samples from `bwe_subfr_at`), as each pitch
/// branch of the reference does.
fn adaptive_excitation(
    exc: &mut [i16],
    exc_at: usize,
    i_subfr: i16,
    t0: i16,
    t0_frac: i16,
    l_frame: i16,
    bwe_exc: &mut [i16],
    bwe_subfr_at: usize,
    bwe_len: usize,
) {
    // Find the adaptive codebook vector - ACELP long-term prediction
    pred_lt4(
        exc,
        exc_at + i_subfr as usize,
        t0,
        t0_frac,
        L_SUBFR + 1,
        &PITCH_INTER4_2,
        L_INTERPOL2,
        PIT_UP_SAMP,
    );
    let offset = tbe_celp_exc_offset(t0, t0_frac, l_frame);
    // Sample by sample, in order: when `offset` is shorter than the subframe the copy repeats
    // itself, exactly as the reference's loop does. The decoded pitch bounds `offset` by the
    // history in front of `bwe_exc`; a source before the buffer (never on a decoded pitch) is
    // left alone.
    for i in 0..bwe_len {
        let destination = bwe_subfr_at + i;
        if let Some(source) = destination.checked_sub(offset.max(0) as usize) {
            bwe_exc[destination] = bwe_exc[source];
        }
    }
}

/// `transition_dec_fx`: build the adaptive (or glottal-shape) excitation of subframe `i_subfr` of
/// a TRANSITION frame whose glottal-shape codebook subframe is `tc_subfr`, decoding the pitch and
/// filling the pitch buffer.
///
/// `q_exc` is the excitation's Q (the reference reads it through `&st->Q_exc`).
pub fn transition_dec(
    st: &mut DecoderState,
    core_brate: i32,
    opt_amr_wb: i16,
    l_frame: i16,
    i_subfr: i16,
    coder_type: i16,
    tc_subfr: i16,
    jopt_flag: &mut i16,
    exc: &mut [i16],
    exc_at: usize,
    t0: &mut i16,
    t0_frac: &mut i16,
    t0_min: &mut i16,
    t0_max: &mut i16,
    pitch_buf: &mut [i16],
    pt_pitch: &mut usize,
    position: &mut i16,
    bwe_exc: &mut [i16],
    bwe_exc_at: usize,
    q_exc: i16,
) {
    let i_subfr_at = i_subfr.max(0) as usize;

    // Note: the adaptive codebook is used only in the subframes after the glottal-shape codebook.
    if sub(tc_subfr, add(i_subfr, TC_0_192)) > 0 {
        // The glottal-shape codebook is used in a later subframe: no adaptive contribution here.
        exc[exc_at + i_subfr_at..exc_at + i_subfr_at + SUBFR].fill(0);

        if sub(l_frame, L_FRAME) == 0 {
            // set past excitation buffer to 0
            let at = bwe_exc_at + i_subfr_at * 5 / 2;
            bwe_exc[at..at + SUBFR * 5 / 2].fill(0);
        } else {
            let at = bwe_exc_at + i_subfr_at * 2;
            bwe_exc[at..at + SUBFR * 2].fill(0);
        }
        *t0 = L_SUBFR;
        *t0_frac = 0;
        pitch_buf[*pt_pitch] = L_SUBFR_Q6;
    } else if sub(tc_subfr, i_subfr) >= 0 && sub(tc_subfr, i_subfr) <= TC_0_192 {
        // glottal-shape codebook in this subframe
        let history = L_EXC_MEM as usize;
        exc[exc_at - history..exc_at].fill(0); // set past excitation buffer to 0

        if sub(l_frame, L_FRAME) == 0 {
            let history = PIT_MAX as usize * 5 / 2;
            bwe_exc[bwe_exc_at - history..bwe_exc_at].fill(0);
        } else {
            let history = PIT16K_MAX as usize * 2;
            bwe_exc[bwe_exc_at - history..bwe_exc_at].fill(0);
        }

        // glottal shape codebook contribution construction
        tc_dec(
            st, l_frame, exc, exc_at, t0, t0_frac, i_subfr, tc_subfr, position, core_brate,
            bwe_exc, bwe_exc_at, q_exc,
        );

        pitch_buf[*pt_pitch] = pitch_q6(*t0, *t0_frac); // save subframe pitch values Q6

        *jopt_flag = 1;
    } else if sub(tc_subfr, i_subfr) < 0 {
        // Regular ACELP decoding using the GENERIC type decoder (all subframes following the one
        // with the glottal-shape codebook)
        if sub(l_frame, L_FRAME) == 0 {
            transition_dec_12k8(
                st, core_brate, opt_amr_wb, l_frame, i_subfr, coder_type, tc_subfr, jopt_flag, exc,
                exc_at, t0, t0_frac, t0_min, t0_max, pitch_buf, *pt_pitch, *position, bwe_exc,
                bwe_exc_at,
            );
        } else {
            transition_dec_16k(
                st, core_brate, opt_amr_wb, l_frame, i_subfr, coder_type, tc_subfr, jopt_flag, exc,
                exc_at, t0, t0_frac, t0_min, t0_max, pitch_buf, *pt_pitch, bwe_exc, bwe_exc_at,
            );
        }
    }
}

/// The 12.8 kHz core's regular subframes of [`transition_dec`]: the second glottal impulse search
/// when the first one is in the first subframe, then the pitch, the low-pass filter and the pitch
/// buffer.
fn transition_dec_12k8(
    st: &mut DecoderState,
    core_brate: i32,
    opt_amr_wb: i16,
    l_frame: i16,
    i_subfr: i16,
    coder_type: i16,
    tc_subfr: i16,
    jopt_flag: &mut i16,
    exc: &mut [i16],
    exc_at: usize,
    t0: &mut i16,
    t0_frac: &mut i16,
    t0_min: &mut i16,
    t0_max: &mut i16,
    pitch_buf: &mut [i16],
    pt_pitch: usize,
    position: i16,
    bwe_exc: &mut [i16],
    bwe_exc_at: usize,
) {
    let limit_flag: i16 = 0;
    let i_subfr_at = i_subfr.max(0) as usize;
    let bwe_subfr_at = bwe_exc_at + i_subfr_at * 5 / 2;
    let bwe_len = SUBFR * 5 / 2;

    *jopt_flag = 1;
    let mut pit_flag = if sub(sub(i_subfr, tc_subfr), L_SUBFR) >= 0
        && sub(sub(i_subfr, tc_subfr), L_SUBFR + TC_0_192) <= 0
    {
        0
    } else {
        L_SUBFR
    };
    if sub(tc_subfr, TC_0_0) == 0 {
        if sub(i_subfr, L_SUBFR) == 0 {
            (*t0_min, *t0_max) = limit_t0(L_FRAME, 8, pit_flag, limit_flag, *t0, 0);
        }
        pit_flag = 1;
    }

    // get number of bits for pitch decoding
    let n_bits = acb_bits_12k8(core_brate, i_subfr, tc_subfr);

    if sub(i_subfr, L_SUBFR) == 0 && sub(tc_subfr, TC_0_128) >= 0 {
        // first glottal impulse in the 1st subframe, the second in the 3rd or 4th:
        // build exc[] in the 2nd subframe
        *t0 = 2 * L_SUBFR;
        *t0_frac = 0;
        *jopt_flag = 0;

        // set adaptive part of exciation for curent subframe to 0
        exc[exc_at + i_subfr_at..exc_at + i_subfr_at + SUBFR + 1].fill(0);
        bwe_exc[bwe_subfr_at..bwe_subfr_at + bwe_len].fill(0);
    } else if sub(i_subfr, L_SUBFR) == 0 && sub(tc_subfr, TC_0_64) == 0 {
        // first glottal impulse in the 1st subframe, the second in the 2nd:
        // build exc[] in the 2nd subframe
        let mut pit_start = PIT_MIN;
        if sub(PIT_MIN, position) > 0 {
            pit_start = sub(L_SUBFR, position);
        }
        pit_start = pit_start.max(PIT_MIN);
        let _pit_limit = add(shl(pit_start, 1), position);

        // 7 bit pitch DECODER
        let index = get_next_indice(st, n_bits) as i16;

        *t0 = add(pit_start, shr(index, 1));
        *t0_frac = shl(sub(index, shl(sub(*t0, pit_start), 1)), 1);

        // find T0_min and T0_max
        (*t0_min, *t0_max) = limit_t0(L_FRAME, 8, pit_flag, limit_flag, *t0, 0);

        adaptive_excitation(
            exc,
            exc_at,
            i_subfr,
            *t0,
            *t0_frac,
            l_frame,
            bwe_exc,
            bwe_subfr_at,
            bwe_len,
        );
    } else if sub(i_subfr, 2 * L_SUBFR) == 0 && sub(tc_subfr, TC_0_128) == 0 {
        // first glottal impulse in the 1st subframe, the second in the 3rd:
        // build exc[] in the 3rd subframe
        let pit_start = sub(2 * L_SUBFR, position);

        // 7bit pitch DECODER
        let index = get_next_indice(st, n_bits) as i16;

        *t0 = add(pit_start, shr(index, 1));
        *t0_frac = shl(sub(index, shl(sub(*t0, pit_start), 1)), 1);

        // find T0_min and T0_max
        (*t0_min, *t0_max) = limit_t0(L_FRAME, 8, pit_flag, limit_flag, *t0, 0);

        adaptive_excitation(
            exc,
            exc_at,
            i_subfr,
            *t0,
            *t0_frac,
            l_frame,
            bwe_exc,
            bwe_subfr_at,
            bwe_len,
        );
    } else if sub(i_subfr, 2 * L_SUBFR) == 0 && sub(tc_subfr, TC_0_192) == 0 {
        // first glottal impulse in the 1st subframe, the second in the 4th:
        // build exc[] in the 3rd subframe
        *t0 = 4 * L_SUBFR;
        *t0_frac = 0;
        *jopt_flag = 0;

        // set adaptive part of exciation for curent subframe to 0
        exc[exc_at + i_subfr_at..exc_at + i_subfr_at + SUBFR + 1].fill(0);
        bwe_exc[bwe_subfr_at..bwe_subfr_at + bwe_len].fill(0);
    } else if sub(i_subfr, 3 * L_SUBFR) == 0 && sub(tc_subfr, TC_0_192) == 0 {
        // first glottal impulse in the 1st subframe, the second in the 4th:
        // build exc[] in the 4th subframe
        let pit_start = sub(3 * L_SUBFR, position);
        let pit_limit = sub(2 * L_FRAME - PIT_MAX, add(shl(position, 1), 2));

        let index = get_next_indice(st, n_bits) as i16;

        if sub(index, shl(sub(pit_limit, pit_start), 1)) < 0 {
            *t0 = add(pit_start, shr(index, 1));
            *t0_frac = shl(sub(index, shl(sub(*t0, pit_start), 1)), 1);
        } else {
            *t0 = add(index, sub(pit_limit, shl(sub(pit_limit, pit_start), 1)));
            *t0_frac = 0;
        }

        // biterror detection mechanism
        if sub(add(*t0 << 2, *t0_frac), add(PIT_MAX << 2, 2)) > 0 {
            *t0 = L_SUBFR;
            *t0_frac = 0;
            st.ber_detect = 1;
        }

        adaptive_excitation(
            exc,
            exc_at,
            i_subfr,
            *t0,
            *t0_frac,
            l_frame,
            bwe_exc,
            bwe_subfr_at,
            bwe_len,
        );
    } else if sub(i_subfr, 3 * L_SUBFR) == 0 && sub(tc_subfr, TC_0_128) == 0 {
        // second glottal impulse in the 3rd subframe: build exc[] in the 4th subframe
        let index = get_next_indice(st, n_bits) as i16;
        delta_pit_dec(2, index, t0, t0_frac, *t0_min);

        adaptive_excitation(
            exc,
            exc_at,
            i_subfr,
            *t0,
            *t0_frac,
            l_frame,
            bwe_exc,
            bwe_subfr_at,
            bwe_len,
        );
    } else {
        // first glottal impulse NOT in the 1st subframe, or two impulses in the 1st subframe
        let index = get_next_indice(st, n_bits) as i16;
        let mut ber_detect = st.ber_detect;
        pit_q_dec(
            0,
            index,
            n_bits,
            8,
            pit_flag,
            limit_flag,
            t0,
            t0_frac,
            t0_min,
            t0_max,
            &mut ber_detect,
        );
        st.ber_detect = ber_detect;

        adaptive_excitation(
            exc,
            exc_at,
            i_subfr,
            *t0,
            *t0_frac,
            l_frame,
            bwe_exc,
            bwe_subfr_at,
            bwe_len,
        );
    }

    // LP filtering of the adaptive excitation (if non-zero)
    if *jopt_flag != 0 {
        lp_filt_exc_dec(
            st, MODE1, core_brate, opt_amr_wb, coder_type, i_subfr, L_SUBFR, l_frame, 0, exc,
            exc_at,
        );
    }

    // fill the pitch buffer - needed for post-processing and FEC_clas_estim()
    let pitch = pitch_q6(*t0, *t0_frac); // save subframe pitch values Q6
    pitch_buf[pt_pitch] = pitch;
    if sub(tc_subfr, 2 * L_SUBFR) >= 0 && sub(i_subfr, 3 * L_SUBFR) == 0 {
        fill_pitch_back(pitch_buf, pt_pitch, 3, pitch);
    } else if sub(tc_subfr, L_SUBFR) == 0 && sub(i_subfr, 2 * L_SUBFR) == 0 {
        fill_pitch_back(pitch_buf, pt_pitch, 2, pitch);
    } else if sub(tc_subfr, TC_0_64) == 0 && sub(i_subfr, L_SUBFR) == 0 {
        fill_pitch_back(pitch_buf, pt_pitch, 1, pitch);
    } else if sub(tc_subfr, TC_0_128) == 0 && sub(i_subfr, 2 * L_SUBFR) == 0 {
        fill_pitch_back(pitch_buf, pt_pitch, 2, pitch);
    } else if sub(tc_subfr, TC_0_192) == 0 && sub(i_subfr, 3 * L_SUBFR) == 0 {
        fill_pitch_back(pitch_buf, pt_pitch, 3, pitch);
    }
}

/// The 16 kHz core's regular subframes of [`transition_dec`].
fn transition_dec_16k(
    st: &mut DecoderState,
    core_brate: i32,
    opt_amr_wb: i16,
    l_frame: i16,
    i_subfr: i16,
    coder_type: i16,
    tc_subfr: i16,
    jopt_flag: &mut i16,
    exc: &mut [i16],
    exc_at: usize,
    t0: &mut i16,
    t0_frac: &mut i16,
    t0_min: &mut i16,
    t0_max: &mut i16,
    pitch_buf: &mut [i16],
    pt_pitch: usize,
    bwe_exc: &mut [i16],
    bwe_exc_at: usize,
) {
    let i_subfr_at = i_subfr.max(0) as usize;
    let mut limit_flag: i16 = 0;
    if sub(i_subfr, 2 * L_SUBFR) >= 0 {
        limit_flag = 1;
    }

    // set limits
    if sub(sub(i_subfr, tc_subfr), L_SUBFR) == 0 {
        (*t0_min, *t0_max) = limit_t0(L_FRAME16K, 8, 0, limit_flag, *t0, *t0_frac);
    }

    // get number of bits and index for pitch decoding
    let n_bits = acb_bits_16k(core_brate, coder_type, i_subfr, tc_subfr);
    let mut index = get_next_indice(st, n_bits) as i16;

    // Find adaptive part of excitation, encode pitch period
    if sub(n_bits, 10) == 0 {
        let mut ber_detect = st.ber_detect;
        pit16k_q_dec(
            index,
            n_bits,
            limit_flag,
            t0,
            t0_frac,
            t0_min,
            t0_max,
            &mut ber_detect,
        );
        st.ber_detect = ber_detect;
    } else if sub(n_bits, 8) == 0 {
        // tc_subfr == 0 && i_subfr == L_SUBFR
        // PIT16k_MIN to PIT16k_FR2_TC0_2SUBFR-1 resolution 1/4 (frac = 0,1,2 or 3)
        // PIT16k_FR2_TC0_2SUBFR to 2*L_SUBFR resolution 1/2 (frac = 0 or 2)
        if sub(index, (PIT16K_FR2_TC0_2SUBFR - PIT16K_MIN) * 4) < 0 {
            *t0 = add(PIT16K_MIN, shr(index, 2));
            let temp = shl(sub(*t0, PIT16K_MIN), 2);
            *t0_frac = sub(index, temp);
        } else {
            index = sub(index, (PIT16K_FR2_TC0_2SUBFR - PIT16K_MIN) * 4);
            *t0 = add(PIT16K_FR2_TC0_2SUBFR, shr(index, 1));
            let temp = shl(sub(*t0, PIT16K_FR2_TC0_2SUBFR), 1);
            *t0_frac = shl(sub(index, temp), 1);
        }

        // biterror detection mechanism
        if sub(add(*t0 << 2, *t0_frac), (2 * L_SUBFR) << 2) > 0 {
            *t0 = L_SUBFR;
            *t0_frac = 0;
            st.ber_detect = 1;
        }
    } else if sub(n_bits, 6) == 0 {
        delta_pit_dec(4, index, t0, t0_frac, *t0_min);
    }
    if sub(n_bits, 6) == 0 {
        // find T0_min and T0_max
        (*t0_min, *t0_max) = limit_t0(L_FRAME16K, 8, L_SUBFR, limit_flag, *t0, *t0_frac);
    }

    // Find the adaptive codebook vector - ACELP long-term prediction
    if sub(i_subfr, L_SUBFR) == 0 && sub(*t0, 2 * L_SUBFR) == 0 {
        // The reference leaves Jopt_flag as it was here (unlike the 12.8 kHz core's zeroed
        // subframes).

        // set adaptive part of exciation for curent subframe to 0
        exc[exc_at + i_subfr_at..exc_at + i_subfr_at + SUBFR + 1].fill(0);

        get_next_indice(st, 1); // this bit is actually not needed

        let at = bwe_exc_at + i_subfr_at * 2;
        bwe_exc[at..at + SUBFR * 2].fill(0);
    } else {
        adaptive_excitation(
            exc,
            exc_at,
            i_subfr,
            *t0,
            *t0_frac,
            l_frame,
            bwe_exc,
            bwe_exc_at + i_subfr_at * 2,
            SUBFR * 2,
        );

        lp_filt_exc_dec(
            st, MODE1, core_brate, opt_amr_wb, coder_type, i_subfr, L_SUBFR, l_frame, 0, exc,
            exc_at,
        );

        *jopt_flag = 1;
    }

    // fill the pitch buffer - needed for post-processing and FEC_clas_estim()
    let pitch = pitch_q6(*t0, *t0_frac); // save subframe pitch values Q6
    pitch_buf[pt_pitch] = pitch;

    // first glottal impulse is in the 1st subframe
    if sub(sub(i_subfr, tc_subfr), L_SUBFR) == 0
        || (tc_subfr == 0 && sub(i_subfr, 2 * L_SUBFR) == 0)
    {
        let count = shr(i_subfr, 6).max(0) as usize;
        fill_pitch_back(pitch_buf, pt_pitch, count, pitch);
    }
}

/// `tc_dec_fx`: decode the TC subframe `i_subfr`: its pitch, then the glottal-shape impulse
/// (shape, position, sign, gain) built into `exc` and repeated by `pred_lt4_tc`, interpolated
/// into the BWE excitation; `position` receives the first impulse's position in the frame.
fn tc_dec(
    st: &mut DecoderState,
    l_frame: i16,
    exc: &mut [i16],
    exc_at: usize,
    t0: &mut i16,
    t0_frac: &mut i16,
    i_subfr: i16,
    tc_subfr: i16,
    position: &mut i16,
    core_brate: i32,
    bwe_exc: &mut [i16],
    bwe_exc_at: usize,
    q_exc: i16,
) {
    // find the number of bits
    let n_bits = if sub(l_frame, L_FRAME) == 0 {
        acb_bits_12k8(core_brate, i_subfr, tc_subfr)
    } else {
        // L_frame == L_FRAME16k
        acb_bits_16k(core_brate, TRANSITION, i_subfr, tc_subfr)
    };

    // decode parameter T0 (pitch period)
    if sub(l_frame, L_FRAME) == 0 {
        if (i_subfr == 0
            && (tc_subfr == 0
                || sub(tc_subfr, TC_0_64) == 0
                || sub(tc_subfr, TC_0_128) == 0
                || sub(tc_subfr, TC_0_192) == 0))
            || sub(tc_subfr, L_SUBFR) == 0
        {
            *t0 = L_SUBFR;
            *t0_frac = 0;
        } else if tc_subfr == 3 * L_SUBFR {
            let i = get_next_indice(st, n_bits) as i16;
            if sub(n_bits, 9) == 0 {
                abs_pit_dec(4, i, 0, t0, t0_frac);
            } else {
                abs_pit_dec(2, i, 0, t0, t0_frac);
            }
        } else {
            let i = get_next_indice(st, n_bits) as i16;
            if i == 0 {
                *t0 = L_SUBFR;
                *t0_frac = 0;
            } else if sub(tc_subfr, TC_0_0) == 0 {
                delta_pit_dec(2, i, t0, t0_frac, PIT_MIN - 1);
            } else {
                delta_pit_dec(0, i, t0, t0_frac, PIT_MIN - 1);
            }
        }
    } else {
        // L_frame == L_FRAME16k
        let i = get_next_indice(st, n_bits) as i16;
        if sub(n_bits, 10) == 0 {
            if sub(i, (PIT16K_FR2_EXTEND_10B - PIT16K_MIN_EXTEND) * 4) < 0 {
                *t0 = add(PIT16K_MIN_EXTEND, shr(i, 2));
                let temp = shl(sub(*t0, PIT16K_MIN_EXTEND), 2);
                *t0_frac = sub(i, temp);
            } else {
                let index = sub(i, shl(sub(PIT16K_FR2_EXTEND_10B, PIT16K_MIN_EXTEND), 2));
                *t0 = add(PIT16K_FR2_EXTEND_10B, shr(index, 1));
                *t0_frac = sub(index, shl(sub(*t0, PIT16K_FR2_EXTEND_10B), 1));
                *t0_frac = shl(*t0_frac, 1);
            }
        } else if sub(n_bits, 6) == 0 {
            *t0 = add(PIT16K_MIN, shr(i, 1));
            *t0_frac = sub(i, shl(sub(*t0, PIT16K_MIN), 1));
            *t0_frac = shl(*t0_frac, 1);
        }
    }

    // decode other TC parameters
    let imp_shape = get_next_indice(st, 3) as i16;
    let imp_pos = get_next_indice(st, 6) as i16;
    let imp_sign = get_next_indice(st, 1) as i16;
    let imp_gain = get_next_indice(st, 3) as i16;

    // restore gain_trans, build glottal codebook contribution
    let mut gain_trans = TBL_GAIN_TRANS_TC_FX[(imp_gain & 7) as usize];
    if imp_sign == 0 {
        gain_trans = negate(gain_trans);
    }

    // local max for scaling need
    // maximum of impulse always takes 15 bits (except impulse #7 wich is using 14 bits)
    let mut temp_s: i16 = 4;
    if sub(imp_gain, 3) <= 0 {
        temp_s = 7;
    }

    // build glottal codebook contribution
    let mut sc = add(13 - 15, temp_s); // scaling of curent exc
    sc = sub(q_exc, sc);

    // pt_shape = &Glottal_cdbk_fx[imp_shape*L_IMPULSE - imp_pos + L_IMPULSE2]; it is read only at
    // i >= imp_pos - L_IMPULSE2, i.e. from imp_shape*L_IMPULSE, never before the table.
    let pt_shape = isize::from(add(sub(i_mult2(imp_shape, L_IMPULSE), imp_pos), L_IMPULSE2));
    let subfr_at = exc_at + i_subfr.max(0) as usize;
    let j = sub(imp_pos, L_IMPULSE2).max(0);
    let mut i: i16 = 0;
    while i < j {
        exc[subfr_at + i as usize] = 0;
        i += 1;
    }
    let j = L_SUBFR.min(add(imp_pos, L_IMPULSE2));
    while i <= j {
        let shape = usize::try_from(pt_shape + isize::from(i))
            .ok()
            .and_then(|at| GLOTTAL_CDBK_FX.get(at))
            .copied()
            .unwrap_or(0);
        exc[subfr_at + i as usize] = round_word(l_shl(l_mult(shape, gain_trans), sc)); // (Qx * Q14)
        i += 1;
    }
    while i < L_SUBFR {
        exc[subfr_at + i as usize] = 0;
        i += 1;
    }

    // adapt. search of the second impulse in the same subframe (when appears)
    pred_lt4_tc(exc, exc_at, *t0, *t0_frac, &INTER4_2_FX, imp_pos, i_subfr);

    if sub(l_frame, L_FRAME) == 0 {
        let bwe_at = bwe_exc_at + i_subfr.max(0) as usize * 5 / 2;
        interp_code_5over2(&exc[subfr_at..], &mut bwe_exc[bwe_at..], L_SUBFR);
    } else {
        let bwe_at = bwe_exc_at + i_subfr.max(0) as usize * 2;
        interp_code_4over2(&exc[subfr_at..], &mut bwe_exc[bwe_at..], L_SUBFR);
    }

    *position = add(imp_pos, i_subfr);
}

/// `tc_classif_fx`: read the TC subframe (the subframe holding the glottal-shape codebook) of a
/// TRANSITION frame: on the 12.8 kHz core 0, 64, 128, 192 or one of `TC_0_0`..`TC_0_192` (both
/// impulses in the first subframe), on the 16 kHz core 0..256 in steps of 64.
pub fn tc_classif(st: &mut DecoderState, l_frame: i16) -> i16 {
    let tc_subfr: i16;
    if sub(l_frame, L_FRAME) == 0 {
        if get_next_indice(st, 1) != 0 {
            tc_subfr = TC_0_0;
        } else if get_next_indice(st, 1) != 0 {
            tc_subfr = if get_next_indice(st, 1) != 0 {
                TC_0_192
            } else if get_next_indice(st, 1) != 0 {
                TC_0_64
            } else {
                TC_0_128
            };
        } else if get_next_indice(st, 1) != 0 {
            tc_subfr = L_SUBFR;
        } else if get_next_indice(st, 1) != 0 {
            tc_subfr = 2 * L_SUBFR;
        } else {
            tc_subfr = 3 * L_SUBFR;
        }
    } else {
        let indice = get_next_indice(st, 2) as i16;
        if sub(indice, 3) < 0 {
            tc_subfr = shl(indice, 6);
        } else {
            tc_subfr = if get_next_indice(st, 1) == 0 {
                3 * L_SUBFR
            } else {
                4 * L_SUBFR
            };
        }
    }
    tc_subfr
}
