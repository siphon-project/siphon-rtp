//! The forward MDCT of the HQ / BWE cores, after the windowing (TS 26.442
//! `lib_com/trans_direct_fx.c`; TS 26.445 §5.3.4.2.1).

use crate::evs::basop::{madd_32_16, mult_32_16};
use crate::evs::com::edct::edct;
use crate::evs::rom::{WSCW16Q15_16_FX, WSCW16Q15_32_FX, WSCW16Q15_8_FX, WSCW16Q15_FX};
use crate::itu::basic_ops::{extract_l, l_negate, l_shr, shr, sub};
use crate::itu::stl2009::l_mult0;

/// `NUM_TIME_SWITCHING_BLOCKS`: short blocks of a transient frame.
const NUM_TIME_SWITCHING_BLOCKS: usize = 4;
/// `L_FRAME48k`: the largest frame, sizing the scratch buffers.
const L_FRAME48K: usize = 960;

/// `direct_transform_fx`: the MDCT of the windowed, time-aliased `in32` (`l` samples, Q`*q`) into
/// `out32`. A transient frame is cut into four short blocks, each folded with the short window
/// and transformed separately; all four are then brought to the lowest of their Qs, which `*q`
/// returns.
pub fn direct_transform(in32: &[i32], out32: &mut [i32], is_transient: i16, l: i16, q: &mut i16) {
    if is_transient == 0 {
        edct(in32, out32, l, q);
        return;
    }
    // l is the configured frame length, never a bitstream value; the clamp only keeps the
    // scratch indexing in bounds
    let l = l.clamp(8, L_FRAME48K as i16);
    let segment_length = shr(l, 1);
    let segment_length2 = shr(segment_length, 1);
    let segment_length4 = shr(segment_length2, 1);
    let win: &[i16] = match l {
        960 => &WSCW16Q15_FX,
        640 => &WSCW16Q15_32_FX,
        160 => &WSCW16Q15_8_FX,
        _ => &WSCW16Q15_16_FX,
    };
    let mut dctin32 = [0i32; L_FRAME48K];
    let mut in32_r16 = [0i32; L_FRAME48K];
    let mut qs = [0i16; NUM_TIME_SWITCHING_BLOCKS];
    let mut qmin: i16 = 31;

    // time reversal of the two halves
    let lu = l as usize;
    for i in 0..segment_length as usize {
        in32_r16[i] = in32[lu - 1 - i];
        in32_r16[lu - 1 - i] = in32[i];
    }

    let s2 = segment_length2 as usize;
    let s4 = segment_length4 as usize;
    // iseg = in32_r16 - segment_length4: iseg[k] is in32_r16[iseg_at + k - s4]
    let mut iseg_at = 0usize;
    let mut oseg_at = 0usize;
    let shift = extract_l(l_mult0(3, segment_length4)) as usize;
    let iseg = |at: usize, k: usize| in32_r16[at + k - s4];

    // first block: its left half is zero (the window's flat part)
    for i in 0..s4 {
        let l_tmp = l_negate(mult_32_16(iseg(iseg_at, shift + i), win[s4 + i]));
        dctin32[i] = madd_32_16(l_tmp, iseg(iseg_at, shift - 1 - i), win[s4 - 1 - i]);
    }
    for (k, d) in dctin32[s4..s2].iter_mut().enumerate() {
        *d = l_negate(iseg(iseg_at, s2 - 1 - k));
    }
    qs[0] = *q;
    edct(&dctin32, &mut out32[oseg_at..], segment_length2, &mut qs[0]);
    qmin = qs[0].min(qmin);
    iseg_at += s2;
    oseg_at += s2;

    // middle blocks
    for qs_seg in &mut qs[1..NUM_TIME_SWITCHING_BLOCKS - 1] {
        for i in 0..s4 {
            let l_tmp = l_negate(mult_32_16(iseg(iseg_at, shift + i), win[s4 + i]));
            dctin32[i] = madd_32_16(l_tmp, iseg(iseg_at, shift - 1 - i), win[s4 - 1 - i]);
        }
        for (k, d) in dctin32[s4..s2].iter_mut().enumerate() {
            let l_tmp = mult_32_16(iseg(iseg_at, k), win[s2 - 1 - k]);
            *d = madd_32_16(l_tmp, iseg(iseg_at, s2 - 1 - k), win[k]);
        }
        *qs_seg = *q;
        edct(&dctin32, &mut out32[oseg_at..], segment_length2, qs_seg);
        qmin = (*qs_seg).min(qmin);
        iseg_at += s2;
        oseg_at += s2;
    }

    // last block: its right half is zero
    for (i, d) in dctin32[..s4].iter_mut().enumerate() {
        *d = l_negate(iseg(iseg_at, shift - 1 - i));
    }
    for (k, d) in dctin32[s4..s2].iter_mut().enumerate() {
        let l_tmp = mult_32_16(iseg(iseg_at, s2 - 1 - k), win[k]);
        *d = madd_32_16(l_tmp, iseg(iseg_at, k), win[s2 - 1 - k]);
    }
    let last = NUM_TIME_SWITCHING_BLOCKS - 1;
    qs[last] = *q;
    edct(
        &dctin32,
        &mut out32[oseg_at..],
        segment_length2,
        &mut qs[last],
    );
    qmin = qs[last].min(qmin);

    // bring every block to the common (lowest) Q
    *q = qmin;
    let mut o = 0usize;
    for qk in qs {
        let shift = sub(qk, *q);
        for _ in 0..s2 {
            out32[o] = l_shr(out32[o], shift);
            o += 1;
        }
    }
}
