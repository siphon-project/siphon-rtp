//! Q-scaling of the SHB / WB TBE decoder memories between frames (TS 26.442
//! `lib_dec/swb_tbe_dec_fx.c`): how far the memories can be shifted up (`find_max_mem_*`) and the
//! shift itself (`rescale_gen*_mem`).

use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::{abs_s, l_abs, l_shl, l_sub, norm_l, norm_s, shl, sub};
use crate::itu::stl2009::shl_r;

fn max_abs(values: &[i16], start: i16) -> i16 {
    values
        .iter()
        .fold(start, |max, &value| max.max(abs_s(value)))
}

/// `find_max_mem_dec`: the headroom, in bits, of the SHB decoder's memories: `n_mem` for the
/// excitation memories, `n_mem2` for the LPC synthesis ones and `n_mem3` for the synthesis-filter
/// ones (output rate dependent).
pub fn find_max_mem_dec(st: &DecoderState, n_mem: &mut i16, n_mem2: &mut i16, n_mem3: &mut i16) {
    let mut max = max_abs(&st.old_bwe_exc_extended[..12], 0);
    max = max_abs(&st.mem_gen_sh_bexc_filt_down_shb[..7], max);

    let mut max2 = max_abs(&st.state_lpc_syn[..10], 0);
    max2 = max_abs(&st.state_syn_shbexc[..20], max2);
    max2 = max_abs(&st.mem_stp_swb[..10], max2);

    *n_mem2 = norm_s(max2);
    if max2 == 0 {
        *n_mem2 = 15;
    }

    if l_sub(st.total_brate, 24400) < 0 {
        max = max.max(max2);
    }
    max = max.max(abs_s(st.tbe_demph));
    max = max.max(abs_s(st.tbe_premph));

    if sub(st.extl, 11) == 0 {
        max = max_abs(&st.fb_state_lpc_syn[..10], max);
        max = max.max(abs_s(st.fb_tbe_demph));
    }

    *n_mem = norm_s(max);
    if max == 0 {
        *n_mem = 15;
    }

    let l_max = l_abs(st.mem_csfilt[0]);
    let mut n_mem_32 = norm_l(l_max);
    if l_max == 0 {
        n_mem_32 = 31;
    }
    let temp = sub((*n_mem).min(n_mem_32), 1);
    *n_mem = temp.max(0);

    let mut max3 = max_abs(&st.syn_overlap[..20], 0);
    max3 = max_abs(&st.gen_sh_bsynth_state_lsyn_filt_shb_local[..2 * 3], max3);
    if l_sub(st.output_fs, 48000) == 0 {
        max3 = max_abs(&st.int_3_over_2_tbemem_dec[..15], max3);
    }
    if l_sub(st.output_fs, 16000) == 0 {
        max3 = max_abs(&st.mem_resamp_hb_32k[..2 * 3 + 1], max3);
    }
    *n_mem3 = norm_s(max3);
    if max3 == 0 {
        *n_mem3 = 15;
    }

    let mut l_max3: i32 = 0;
    if sub(st.l_frame, 256) == 0 {
        for &value in &st.gen_sh_bsynth_hilbert_mem[..5 + 2 * 4 + 2 * 4] {
            l_max3 = l_max3.max(l_abs(value));
        }
    }
    n_mem_32 = norm_l(l_max3);
    if l_max3 == 0 {
        n_mem_32 = 31;
    }
    let temp = sub((*n_mem3).min(n_mem_32), 2);
    *n_mem3 = temp.max(0);
}

/// `rescale_genSHB_mem_dec`: shifts the SHB decoder's memories up by `sf` bits.
pub fn rescale_gen_shb_mem_dec(st: &mut DecoderState, sf: i16) {
    for value in &mut st.old_bwe_exc_extended[..12] {
        *value = shl(*value, sf);
    }
    for value in &mut st.mem_gen_sh_bexc_filt_down_shb[..7] {
        *value = shl(*value, sf);
    }
    if l_sub(st.total_brate, 24400) < 0 {
        for value in &mut st.state_lpc_syn[..10] {
            *value = shl(*value, sf);
        }
        for value in &mut st.state_syn_shbexc[..20] {
            *value = shl(*value, sf);
        }
    }
    // for extl == FB_TBE the reference's block is empty
    st.mem_csfilt[0] = l_shl(st.mem_csfilt[0], sf);
    st.tbe_demph = shl_r(st.tbe_demph, sf);
    st.tbe_premph = shl_r(st.tbe_premph, sf);
}

/// `find_max_mem_wb`: the headroom, in bits, of the WB TBE decoder's memories.
pub fn find_max_mem_wb(st: &DecoderState, n_mem: &mut i16) {
    let mut max = max_abs(&st.old_bwe_exc_extended[..12], 0);
    max = max_abs(&st.mem_gen_sh_bexc_filt_down_shb[..7], max);
    max = max_abs(&st.mem_gen_sh_bexc_filt_down_wb2[..7], max);
    max = max_abs(&st.mem_gen_sh_bexc_filt_down_wb3[..7], max);
    max = max_abs(&st.state_lpc_syn[..10], max);
    max = max_abs(&st.state_syn_shbexc[..5], max);

    *n_mem = if max == 0 { 15 } else { norm_s(max) };

    let mut l_max: i32 = 0;
    for &value in &st.mem_csfilt[..2] {
        if l_abs(value) > l_max {
            l_max = l_abs(value);
        }
    }
    let n_mem_32 = if l_max == 0 { 31 } else { norm_l(l_max) };

    *n_mem = sub((*n_mem).min(n_mem_32), 1);
    *n_mem = (*n_mem).max(0);
}

/// `rescale_genWB_mem`: shifts the WB TBE decoder's memories up by `sf` bits.
pub fn rescale_gen_wb_mem(st: &mut DecoderState, sf: i16) {
    for value in &mut st.old_bwe_exc_extended[..12] {
        *value = shl(*value, sf);
    }
    for value in &mut st.state_lpc_syn[..10] {
        *value = shl(*value, sf);
    }
    for value in &mut st.state_syn_shbexc[..5] {
        *value = shl(*value, sf);
    }
    for value in &mut st.mem_gen_sh_bexc_filt_down_shb[..7] {
        *value = shl(*value, sf);
    }
    for value in &mut st.mem_gen_sh_bexc_filt_down_wb2[..7] {
        *value = shl(*value, sf);
    }
    for value in &mut st.mem_gen_sh_bexc_filt_down_wb3[..7] {
        *value = shl(*value, sf);
    }
    for value in &mut st.mem_csfilt[..2] {
        *value = l_shl(*value, sf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silent_memories_have_the_full_headroom_bounds() {
        let st = Box::new(DecoderState::zeroed());
        let (mut n_mem, mut n_mem2, mut n_mem3) = (0, 0, 0);
        find_max_mem_dec(&st, &mut n_mem, &mut n_mem2, &mut n_mem3);
        // all zero: 15 bits for the 16-bit memories, less the reference's guard bits
        assert_eq!((n_mem, n_mem2, n_mem3), (14, 15, 13));
        let mut n_mem_wb = 0;
        find_max_mem_wb(&st, &mut n_mem_wb);
        assert_eq!(n_mem_wb, 14);
    }

    #[test]
    fn rescale_shifts_the_listed_memories_only() {
        let mut st = Box::new(DecoderState::zeroed());
        st.old_bwe_exc_extended[3] = 100;
        st.mem_csfilt[0] = 1000;
        st.tbe_demph = 7;
        st.syn_overlap[0] = 5;
        rescale_gen_shb_mem_dec(&mut st, 2);
        assert_eq!(st.old_bwe_exc_extended[3], 400);
        assert_eq!(st.mem_csfilt[0], 4000);
        assert_eq!(st.tbe_demph, 28);
        assert_eq!(st.syn_overlap[0], 5);
    }

    #[test]
    fn wb_rescale_covers_both_csfilt_words() {
        let mut st = Box::new(DecoderState::zeroed());
        st.mem_csfilt = [3, 4];
        st.state_syn_shbexc[4] = 2;
        st.state_syn_shbexc[5] = 2;
        rescale_gen_wb_mem(&mut st, 1);
        assert_eq!(st.mem_csfilt, [6, 8]);
        assert_eq!((st.state_syn_shbexc[4], st.state_syn_shbexc[5]), (4, 2));
    }
}
