//! Gain shaping and overlap-add of the SHB / WB TBE synthesis (TS 26.442
//! `lib_com/swb_tbe_com_fx.c`; TS 26.445 §6.1.3.2).

use crate::evs::basop::{mult_32_16, mult_32_32};
use crate::evs::cnst::HILBERT_MEM_SIZE;
use crate::evs::com::math_op::i_mult2;
use crate::evs::rom::SKIP_BANDS_WB_TBE;
use crate::itu::basic_ops::{
    abs_s, add, l_mult, l_shl, mult_r, norm_l, norm_s, round_word, shl, sub,
};
use crate::itu::stl2009::{i_mult, l_mac0, l_mult0, mac_r};

/// The `mod_syn` buffer of the reference: one frame plus its look-ahead, at the SWB rate.
const MOD_SYN_LENGTH: usize = 320 + 20;

/// Which frame layout [`shape_subgains`] applied.
struct ShapedLayout {
    /// `l_frame`: the frame length at the band's rate (80 for WB, 320 for SWB).
    l_frame: usize,
    /// `l_shb_lahead`: the look-ahead (5 for WB, 20 for SWB).
    l_shb_lahead: usize,
}

/// The first half shared by `ScaleShapedSHB_fx` and `ScaleShapedWB_fx` (the two functions carry
/// the same code, with `i_mult2` or a plain `*` for the small subgain indices): applies the
/// sub-frame gains `subgain` to `syn_shb`, cross-fading neighbouring ones over `length` samples
/// with the window `subwin`, into the 32-bit `mod_syn`.
fn shape_subgains(
    length: i16,
    syn_shb: &[i16],
    subgain: &[i16],
    subwin: &[i16],
    mod_syn: &mut [i32; MOD_SYN_LENGTH],
) -> ShapedLayout {
    let length_u = length.max(0) as usize;
    if length == (320 - 20) / (16 - 1) / 2 {
        let skip = &SKIP_BANDS_WB_TBE;
        let half = length_u / 2;

        for k in 0..half {
            let sum_gain = mult_r(subwin[2 * k + 2], subgain[0]);
            mod_syn[skip[0] as usize + k] = l_mult(sum_gain, syn_shb[skip[0] as usize + k]);
            mod_syn[skip[0] as usize + k + half] =
                l_mult(subgain[0], syn_shb[skip[0] as usize + k + half]);
        }
        let mut i = 1usize;
        while i < 16 / 2 {
            for k in 0..length_u {
                let l_tmp = l_mult0(subwin[k + 1], subgain[i]);
                let sum_gain = round_word(l_mac0(l_tmp, subwin[length_u - k - 1], subgain[i - 1]));
                mod_syn[skip[i] as usize + k] =
                    l_shl(l_mult(sum_gain, syn_shb[skip[i] as usize + k]), 1);
            }
            i += 1;
        }
        for k in 0..half {
            let sum_gain = mult_r(subwin[length_u - 2 * k - 2], subgain[i - 1]);
            mod_syn[skip[i] as usize + k] = l_mult(sum_gain, syn_shb[skip[i] as usize + k]);
        }
        ShapedLayout {
            l_frame: 320 / 4,
            l_shb_lahead: 20 / 4,
        }
    } else {
        let num_join: i16 = 16 / 4;
        let join_length = i_mult2(num_join, length) as usize;
        let num_join_u = num_join as usize;

        let mut j = 0usize;
        for k in 0..length_u {
            let sum_gain = mult_r(subwin[k + 1], subgain[0]);
            mod_syn[j] = l_mult(syn_shb[j], sum_gain);
            j += 1;
        }
        for i in 0..4 - 1 {
            for _ in 0..join_length - length_u {
                mod_syn[j] = l_mult(syn_shb[j], subgain[i * num_join_u]);
                j += 1;
            }
            for k in 0..length_u {
                let l_tmp = l_mult0(subwin[k + 1], subgain[(i + 1) * num_join_u]);
                let sum_gain = round_word(l_mac0(
                    l_tmp,
                    subwin[length_u - k - 1],
                    subgain[i * num_join_u],
                ));
                mod_syn[j] = l_shl(l_mult(sum_gain, syn_shb[j]), 1);
                j += 1;
            }
        }
        for _ in 0..join_length - length_u {
            mod_syn[j] = l_mult(syn_shb[j], subgain[(4 - 1) * num_join_u]);
            j += 1;
        }
        for k in 0..length_u {
            let sum_gain = mult_r(subwin[length_u - k - 1], subgain[(4 - 1) * num_join_u]);
            mod_syn[j] = l_mult(syn_shb[j], sum_gain);
            j += 1;
        }
        ShapedLayout {
            l_frame: 320,
            l_shb_lahead: 20,
        }
    }
}

/// `ScaleShapedSHB_fx`: applies the sub-frame gains and the frame gain `frame_gain` to the SHB
/// synthesis `syn_shb` and overlap-adds it with the previous frame's tail `overlap` (20 samples,
/// rescaled to the new Q). `q_bwe_exc` is the excitation Q, updated, and `qx` receives the output
/// Q.
pub fn scale_shaped_shb(
    length: i16,
    syn_shb: &mut [i16],
    overlap: &mut [i16],
    subgain: &[i16],
    frame_gain: i32,
    win: &[i16],
    subwin: &[i16],
    q_bwe_exc: &mut i16,
    qx: &mut i16,
    n_mem3: i16,
    prev_q_bwe_syn2: i16,
) {
    let mut mod_syn = [0i32; MOD_SYN_LENGTH];
    let layout = shape_subgains(length, syn_shb, subgain, subwin, &mut mod_syn);
    let ShapedLayout {
        l_frame,
        l_shb_lahead,
    } = layout;

    let mut q_g_fr_norm = norm_l(frame_gain);
    if frame_gain == 0 {
        q_g_fr_norm = 31;
    }
    q_g_fr_norm = sub(q_g_fr_norm, 1);
    let gain_frame_q16 = round_word(l_shl(frame_gain, q_g_fr_norm));

    *q_bwe_exc = add(*q_bwe_exc, q_g_fr_norm);
    *q_bwe_exc = sub(*q_bwe_exc, 13);
    let tmp_q15 = add(prev_q_bwe_syn2, n_mem3);
    if sub(*q_bwe_exc, tmp_q15) > 0 {
        *q_bwe_exc = tmp_q15;
    }
    *qx = *q_bwe_exc;

    for value in overlap.iter_mut().take(20) {
        let temp2: i16 = if *value < 0 { -1 } else { 1 };
        let mut temp1 = abs_s(*value);
        // the shift count is a C `int` difference converted to the operator's `Word16` parameter
        temp1 = shl(
            temp1,
            (i32::from(*q_bwe_exc) - i32::from(prev_q_bwe_syn2)) as i16,
        );
        *value = i_mult(temp1, temp2);
    }

    let mut i = 0usize;
    while i < l_shb_lahead {
        let l_tmp = mult_32_16(mod_syn[i], gain_frame_q16);
        let l_tmp2 = mult_32_16(l_tmp, win[i]);
        syn_shb[i] = mac_r(l_tmp2, overlap[i], 0x7fff);
        syn_shb[i + l_shb_lahead] = round_word(l_tmp);
        i += 1;
    }
    while i < l_frame {
        let l_tmp = mult_32_16(mod_syn[i], gain_frame_q16);
        syn_shb[i] = round_word(l_tmp);
        i += 1;
    }
    let l_frame_tmp = l_frame + l_shb_lahead;
    while i < l_frame_tmp {
        let mut l_tmp = mult_32_16(mod_syn[i], gain_frame_q16);
        l_tmp = mult_32_16(l_tmp, win[l_frame + l_shb_lahead - 1 - i]);
        overlap[i - l_frame] = round_word(l_tmp);
        i += 1;
    }
}

/// `ScaleShapedWB_fx`: [`scale_shaped_shb`] for the WB TBE, with a frame gain applied as a 32-bit
/// product and the output scaled by a headroom-driven `shift` (`dynq` selects it; `qx` receives the
/// output Q, relative to the previous frame's `prev_qx`). `hilbert_mem` (21 words) is only read,
/// for the headroom estimate.
pub fn scale_shaped_wb(
    length: i16,
    syn_shb: &mut [i16],
    overlap: &mut [i16],
    subgain: &[i16],
    frame_gain: i32,
    win: &[i16],
    subwin: &[i16],
    q_bwe_exc: i16,
    l_frame_arg: i16,
    dynq: i16,
    qx: &mut i16,
    prev_qx: i16,
    hilbert_mem: &[i32],
) {
    let mut mod_syn = [0i32; MOD_SYN_LENGTH];
    let layout = shape_subgains(length, syn_shb, subgain, subwin, &mut mod_syn);
    let ShapedLayout {
        l_frame,
        l_shb_lahead,
    } = layout;

    let mut max: i16 = 0;
    for &value in &mod_syn[..l_frame + l_shb_lahead] {
        let abs_sig = abs_s(round_word(value));
        if sub(abs_sig, max) > 0 {
            max = abs_sig;
        }
    }
    for &value in &hilbert_mem[..HILBERT_MEM_SIZE as usize] {
        let abs_sig = abs_s(round_word(value));
        if sub(abs_sig, max) > 0 {
            max = abs_sig;
        }
    }
    let sc1 = norm_s(max);
    let sc2 = norm_s(round_word(frame_gain));

    let shift: i16;
    if dynq == 0 {
        shift = sub(13, q_bwe_exc);
        *qx = 0;
    } else if sub(l_frame_arg, 256) == 0 {
        let max_headroom = sub(add(sc1, sc2), 4);
        let min_shift = 2 - (q_bwe_exc + 3 - 16);
        let max_shift = 13 - (q_bwe_exc + 3 - 16);
        let max_shift2 = max_shift.min(max_headroom);
        shift = min_shift.min(max_shift2);
        *qx = (q_bwe_exc + 3) + shift - 16;
    } else {
        let max_headroom = sub(add(sc1, sc2), 1);
        let min_shift = 3 - (q_bwe_exc + 3 - 16);
        let max_shift = 13 - (q_bwe_exc + 3 - 16);
        let max_shift2 = max_shift.min(max_headroom);
        shift = min_shift.min(max_shift2);
        *qx = (q_bwe_exc + 3) + shift - 16;
    }

    for value in overlap.iter_mut().take(l_shb_lahead) {
        *value = shl(*value, (i32::from(*qx) - i32::from(prev_qx)) as i16);
    }

    let mut i = 0usize;
    while i < l_shb_lahead {
        let l_tmp = mult_32_32(mod_syn[i], frame_gain);
        syn_shb[i] = round_word(l_shl(mult_32_16(l_tmp, win[i]), shift));
        syn_shb[i] = add(syn_shb[i], overlap[i]);
        syn_shb[i + l_shb_lahead] = round_word(l_shl(l_tmp, shift));
        i += 1;
    }
    while i < l_frame {
        let l_tmp = mult_32_32(mod_syn[i], frame_gain);
        syn_shb[i] = round_word(l_shl(l_tmp, shift));
        i += 1;
    }
    let l_frame_tmp = l_frame + l_shb_lahead;
    while i < l_frame_tmp {
        let l_tmp = mult_32_32(mod_syn[i], frame_gain);
        overlap[i - l_frame] = round_word(l_shl(
            mult_32_16(l_tmp, win[l_frame + l_shb_lahead - 1 - i]),
            shift,
        ));
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_shaped_shb_of_silence_keeps_the_overlap_tail_silent() {
        let mut syn_shb = [0i16; 340];
        let mut overlap = [0i16; 20];
        let subgain = [8192i16; 16];
        let win = [16384i16; 20];
        let subwin = [16384i16; 24];
        let mut q_bwe_exc = 8;
        let mut qx = 0;
        scale_shaped_shb(
            20,
            &mut syn_shb,
            &mut overlap,
            &subgain,
            0,
            &win,
            &subwin,
            &mut q_bwe_exc,
            &mut qx,
            0,
            0,
        );
        assert_eq!(syn_shb, [0; 340]);
        assert_eq!(overlap, [0; 20]);
        assert_eq!(qx, q_bwe_exc);
    }

    #[test]
    fn scale_shaped_wb_without_dynamic_q_resets_qx() {
        let mut syn_shb = [0i16; 340];
        let mut overlap = [0i16; 20];
        let subgain = [8192i16; 16];
        let win = [16384i16; 20];
        let subwin = [16384i16; 24];
        let mut qx = 99;
        scale_shaped_wb(
            10,
            &mut syn_shb,
            &mut overlap,
            &subgain,
            0x4000_0000,
            &win,
            &subwin,
            4,
            320,
            0,
            &mut qx,
            0,
            &[0i32; 21],
        );
        assert_eq!(qx, 0);
    }
}
