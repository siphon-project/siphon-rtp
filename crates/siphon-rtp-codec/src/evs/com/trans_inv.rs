//! The inverse MDCT of the HQ / BWE cores and the pre-echo reduction applied after it (TS 26.442
//! `lib_com/trans_inv_fx.c`; TS 26.445 §6.2.1.5, §6.2.1.6).
//!
//! Ported: `Inverse_Transform` (with its short-block transient path) and `preecho_sb_fx`, the
//! functions the MODE1 decoder executes.

use crate::evs::basop::mult_32_16;
use crate::evs::com::edct::{edct, iedct_short};
use crate::evs::com::math_op::frac_sqrt;
use crate::evs::rom::{
    INV_JP2, SHORT_WINDOW_16KHZ_FX, SHORT_WINDOW_32KHZ_FX, SHORT_WINDOW_48KHZ_FX,
    SHORT_WINDOW_8KHZ_FX,
};
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_add, l_mac, l_mult, l_shl, l_shr, l_sub, mult, mult_r, negate, norm_l,
    round_word, shl, shr, sub,
};
use crate::itu::stl2009::{i_mult, l_mac0, l_mult0, mac_r, mpy_32_16_ss};

/// `NUM_TIME_SWITCHING_BLOCKS`: short blocks of a transient frame.
const NUM_TIME_SWITCHING_BLOCKS: usize = 4;
/// `L_FRAME48k`: the largest frame, sizing the scratch buffers.
const L_FRAME48K: usize = 960;
/// `NUMSF`: sub-frames of the pre-echo analysis.
const NUMSF: usize = 8;

/// `Inverse_Transform`: the inverse MDCT of `in_mdct` (`l_inner` coded lines, Q`*q`) into the
/// `l` windowed time samples `out`. A transient frame is four short blocks, each inverse-transformed
/// and overlap-added with the short sine window; `*q` then becomes the output Q. `l` is the output
/// frame length (160, 320, 640 or 960).
pub fn inverse_transform(
    in_mdct: &[i32],
    q: &mut i16,
    out: &mut [i32],
    is_transient: i16,
    l: i16,
    l_inner: i16,
) {
    if is_transient == 0 {
        edct(in_mdct, out, l, q);
        return;
    }
    // the frame length is the configured output frame, never a bitstream value; the clamp only
    // keeps the scratch indexing in bounds
    let l = l.clamp(8, L_FRAME48K as i16);
    let segment_length = shr(l, 1);
    let segment_length_div2 = shr(l, 2);
    let segment_length_div4 = shr(l, 3);
    let win: &[i16] = match l {
        960 => &SHORT_WINDOW_48KHZ_FX,
        640 => &SHORT_WINDOW_32KHZ_FX,
        320 => &SHORT_WINDOW_16KHZ_FX,
        _ => &SHORT_WINDOW_8KHZ_FX,
    };
    let mut out_alias = [0i32; L_FRAME48K];
    let mut alias = [0i32; L_FRAME48K / 2];
    let mut in_mdct_modif = [0i32; L_FRAME48K];

    inverse_transform_modify_inner(in_mdct, &mut in_mdct_modif, l, l_inner, segment_length_div2);

    let seg_len = segment_length as usize;
    let div2 = segment_length_div2 as usize;
    let div4 = segment_length_div4 as usize;
    // out_segment = out_alias - segment_length_div4: out_segment[ta] is out_alias[os + ta - div4]
    let mut os = 0usize;
    let mut in_at = 0usize;

    let mut tmp = *q;
    iedct_short(
        &in_mdct_modif[in_at..],
        &mut tmp,
        &mut alias,
        segment_length,
    );
    let q_out;
    if sub(tmp, 9 + 1) > 0 {
        q_out = sub(tmp, 9 + 1);
        tmp = sub(tmp, q_out);
    } else {
        q_out = 0;
    }
    for ta in div4..div2 {
        out_alias[os + ta - div4] = l_shr(alias[ta], tmp);
    }
    // win2 walks the window down, up and down again across the blocks
    let mut win2 = div2;
    for ta in div2..seg_len {
        win2 -= 1;
        out_alias[os + ta - div4] = l_shr(mult_32_16(alias[ta], win[win2]), tmp);
    }
    os += div2;
    in_at += div2;

    for _seg in 1..NUM_TIME_SWITCHING_BLOCKS - 1 {
        let mut tmp = *q;
        iedct_short(
            &in_mdct_modif[in_at..],
            &mut tmp,
            &mut alias,
            segment_length,
        );
        tmp = sub(tmp, q_out);
        for ta in 0..div2 {
            let slot = &mut out_alias[os + ta - div4];
            *slot = l_add(*slot, l_shr(mult_32_16(alias[ta], win[win2]), tmp));
            win2 += 1;
        }
        for ta in div2..seg_len {
            win2 -= 1;
            let slot = &mut out_alias[os + ta - div4];
            *slot = l_add(*slot, l_shr(mult_32_16(alias[ta], win[win2]), tmp));
        }
        in_at += div2;
        os += div2;
    }

    let mut tmp = *q;
    iedct_short(
        &in_mdct_modif[in_at..],
        &mut tmp,
        &mut alias,
        segment_length,
    );
    tmp = sub(tmp, q_out);
    for ta in 0..div2 {
        let slot = &mut out_alias[os + ta - div4];
        *slot = l_add(*slot, l_shr(mult_32_16(alias[ta], win[win2]), tmp));
        win2 += 1;
    }
    let seg = add(segment_length_div2, shr(segment_length_div2, 1)) as usize;
    for ta in div2..seg {
        out_alias[os + ta - div4] = l_shr(alias[ta], tmp);
    }

    let l = l as usize;
    for ta in 0..seg_len {
        let l_temp = out_alias[ta];
        out[ta] = out_alias[l - 1 - ta];
        out[l - 1 - ta] = l_temp;
    }
    *q = q_out;
}

/// The transient path's spectrum reshaping: four short spectra of `l_inner / 4` lines each,
/// zero-padded (`l_inner < l`) or truncated (`l_inner > l`) to `l / 4` lines.
fn inverse_transform_modify_inner(
    in_mdct: &[i32],
    in_mdct_modif: &mut [i32],
    l: i16,
    l_inner: i16,
    segment_length_div2: i16,
) {
    let tmp16 = sub(l, l_inner);
    if tmp16 == 0 {
        in_mdct_modif[..l as usize].copy_from_slice(&in_mdct[..l as usize]);
    } else if tmp16 > 0 {
        let (mut src, mut dst) = (0usize, 0usize);
        for _seg in 0..NUM_TIME_SWITCHING_BLOCKS {
            for _ta in (0..l_inner.max(0)).step_by(4) {
                in_mdct_modif[dst] = in_mdct[src];
                dst += 1;
                src += 1;
            }
            for _ta in (0..tmp16).step_by(4) {
                in_mdct_modif[dst] = 0;
                dst += 1;
            }
        }
    } else {
        let (mut src, mut dst) = (0usize, 0usize);
        let skip = shr(sub(l_inner, l), 2) as usize;
        for _seg in 0..NUM_TIME_SWITCHING_BLOCKS {
            for _ta in 0..segment_length_div2.max(0) {
                in_mdct_modif[dst] = in_mdct[src];
                dst += 1;
                src += 1;
            }
            src += skip;
        }
    }
}

/// The state `preecho_sb_fx` carries from frame to frame (all `Decoder_State_fx` fields).
#[derive(Debug)]
pub struct PreechoState<'a> {
    /// `memfilt_lb_fx`: last sample of the low-band split filter.
    pub memfilt_lb: &'a mut i16,
    /// `mean_prev_hb_fx`: mean high-band sub-frame energy of the previous frame.
    pub mean_prev_hb: &'a mut i32,
    /// `smoothmem_fx`: gain at the end of the previous frame.
    pub smoothmem: &'a mut i16,
    /// `mean_prev_fx`: mean (attenuated) sub-frame energy of the previous frame.
    pub mean_prev: &'a mut i32,
    /// `mean_prev_nc_fx`: mean un-attenuated sub-frame energy of the previous frame.
    pub mean_prev_nc: &'a mut i32,
    /// `wmold_hb_fx`: high-band gain at the end of the previous frame.
    pub wmold_hb: &'a mut i16,
    /// `prevflag`: an attack was detected in the previous frame.
    pub prevflag: &'a mut i16,
    /// `pastpre`: frames since the reduction last ran.
    pub pastpre: &'a mut i16,
}

/// The locals `preecho_sb_fx` shares between its stages, named as in the reference.
struct PreechoWork {
    q16p1: i16,
    qmemp1: i16,
    framelength: usize,
    len3x_lp20: usize,
    limzcr: i16,
    smooth_len: i16,
    invsmoothlenp1: i16,
    limmaxnzcr: i16,
    num_subsubframes: i16,
    log2_num_subsubframes: i16,
    subframelength: i16,
    subsubframelength: i16,
    wmold: i16,
    lim16: i16,
    lim32: i16,
    mean_prev_loc: i32,
    mean_prev_hb_loc: i32,
    mean_prev_nc_loc: i32,
    imdct_mem: [i16; L_FRAME48K],
    rec_sig_lb: [i16; L_FRAME48K],
    rec_sig_hb: [i16; L_FRAME48K],
    zcr: [i16; NUMSF + 1],
    maxnzcr: [i16; NUMSF],
    es_mdct: [i32; NUMSF + 1],
    es_mdct_hb: [i32; NUMSF + 1],
    es_mdct_half: [i32; NUMSF + 1],
    es_mdct_quart: [i32; NUMSF + 1],
    max_es: i32,
    cnt2: i16,
    cnt5: i16,
    min_g: [i16; 13],
    gt: [i16; 13],
    min_g_hb: [i16; 13],
    gt_hb: [i16; 13],
    preechogain: [i16; L_FRAME48K + 20],
    preechogain_hb: [i16; L_FRAME48K],
    pre_g_ch_tab: [i16; NUMSF + 1],
}

/// `preecho_sb_fx`: pre-echo reduction of the HQ synthesis `rec_sig` (Q`q_sig16`, `framelength`
/// samples) at bit rates up to 32 kbit/s. The frame is split into a low and a high band, its
/// sub-frame energies are compared with the next frame's start (the windowed-out part of
/// `wtda_audio`, Q`q_sig32`), and the sub-frames before a detected attack are attenuated with
/// smoothed gains, separately per band. `bwidth == NB` selects the narrowband limits.
pub fn preecho_sb(
    brate: i32,
    wtda_audio: &[i32],
    q_sig32: i16,
    rec_sig: &mut [i16],
    q_sig16: i16,
    framelength: i16,
    state: &mut PreechoState<'_>,
    bwidth: i16,
) {
    if l_sub(brate, 32000) > 0 {
        return;
    }
    // framelength is the configured output frame (160, 320, 640 or 960), never a bitstream
    // value; the clamp only keeps the scratch indexing in bounds
    let framelength = framelength.clamp(160, L_FRAME48K as i16);
    let mut w = preecho_sb_setup(wtda_audio, q_sig32, q_sig16, framelength, state, bwidth);
    preecho_sb_split_bands(&mut w, rec_sig, q_sig16, state);
    preecho_sb_subframe_energies(&mut w, rec_sig);
    preecho_sb_next_frame_energies(&mut w, rec_sig);
    preecho_sb_attack(&mut w, state);
    let (ind2, ind2_sfl, adv, advmem) = preecho_sb_onset(&mut w, rec_sig, state);
    preecho_sb_apply(&mut w, rec_sig, state, ind2, ind2_sfl, adv, advmem);
    preecho_sb_update_means(&mut w, state, q_sig16, ind2);
}

/// Constants of the frame, the state read into locals, and `imdct_mem`: the time-reversed,
/// sign-flipped aliasing part of the next frame from `wtda_audio`.
fn preecho_sb_setup(
    wtda_audio: &[i32],
    q_sig32: i16,
    q_sig16: i16,
    framelength: i16,
    state: &mut PreechoState<'_>,
    bwidth: i16,
) -> PreechoWork {
    let q16p1 = add(q_sig16, 1);
    let mean_prev_loc = *state.mean_prev;
    let mean_prev_hb_loc = l_shl(*state.mean_prev_hb, shl(q_sig16, 1));
    let mean_prev_nc_loc = *state.mean_prev_nc;

    let nb_flag = bwidth == 0; // NB
    let (limzcr, smooth_len, invsmoothlenp1) = if nb_flag {
        (10, 20, 1560) // 1/(smooth_len+1) Q15
    } else {
        (16, 4, 6554)
    };
    let limmaxnzcr = mult(framelength, 1365); // 1/24
    let (num_subsubframes, log2_num_subsubframes) = if sub(framelength, 160) == 0 {
        (4, 2)
    } else {
        (8, 3)
    };
    let len3x_lp20 = mult_r(framelength, 7168); // 7*L/32

    let mut imdct_mem = [0i16; L_FRAME48K];
    let shift = 15 - q_sig32;
    let len3 = len3x_lp20.max(0) as usize;
    for i in 0..len3 {
        imdct_mem[i] = negate(extract_h(l_shl(wtda_audio[len3 - 1 - i], shift)));
    }
    let half = l_shr(i32::from(framelength), 1) as usize;
    for i in 0..half {
        imdct_mem[len3 + i] = negate(extract_h(l_shl(wtda_audio[i], shift)));
    }

    let subframelength = shr(framelength, 3);
    let subsubframelength = shr(subframelength, log2_num_subsubframes);
    let (mut lim16, mut lim32) = (3277, 328); // 0.1, 0.01 Q15
    if *state.pastpre == 0 {
        // no limits on the first frame of the reduction
        lim16 = 32767;
        lim32 = 32767;
    }
    *state.pastpre = 2;

    PreechoWork {
        q16p1,
        qmemp1: 0,
        framelength: framelength as usize,
        len3x_lp20: len3,
        limzcr,
        smooth_len,
        invsmoothlenp1,
        limmaxnzcr,
        num_subsubframes,
        log2_num_subsubframes,
        subframelength,
        subsubframelength,
        wmold: *state.smoothmem,
        lim16,
        lim32,
        mean_prev_loc,
        mean_prev_hb_loc,
        mean_prev_nc_loc,
        imdct_mem,
        rec_sig_lb: [0; L_FRAME48K],
        rec_sig_hb: [0; L_FRAME48K],
        zcr: [0; NUMSF + 1],
        maxnzcr: [0; NUMSF],
        es_mdct: [0; NUMSF + 1],
        es_mdct_hb: [0; NUMSF + 1],
        es_mdct_half: [0; NUMSF + 1],
        es_mdct_quart: [0; NUMSF + 1],
        max_es: 0,
        cnt2: 0,
        cnt5: 0,
        min_g: [0; 13],
        gt: [0; 13],
        min_g_hb: [0; 13],
        gt_hb: [0; 13],
        preechogain: [0; L_FRAME48K + 20],
        preechogain_hb: [0; L_FRAME48K],
        pre_g_ch_tab: [0; NUMSF + 1],
    }
}

/// Split `rec_sig` into a low band (the [1/4 1/2 1/4] smoothing filter) and the high-band rest.
fn preecho_sb_split_bands(
    w: &mut PreechoWork,
    rec_sig: &[i16],
    q_sig16: i16,
    state: &mut PreechoState<'_>,
) {
    let fl = w.framelength;
    let lb = &mut w.rec_sig_lb;
    let l_tmp = l_mult(shl(*state.memfilt_lb, q_sig16), 8192);
    let l_tmp = l_mac(l_tmp, rec_sig[1], 8192);
    lb[0] = mac_r(l_tmp, rec_sig[0], 16384);
    for k in 0..fl - 2 {
        let l_tmp = l_mult(rec_sig[k], 8192);
        let l_tmp = l_mac(l_tmp, rec_sig[k + 2], 8192);
        lb[k + 1] = mac_r(l_tmp, rec_sig[k + 1], 16384);
    }
    let l_tmp = l_mult(rec_sig[fl - 2], 8192);
    lb[fl - 1] = mac_r(l_tmp, rec_sig[fl - 1], 16384);
    for ((hb, &rec), &lb) in w.rec_sig_hb[..fl]
        .iter_mut()
        .zip(&rec_sig[..fl])
        .zip(&w.rec_sig_lb[..fl])
    {
        *hb = sub(rec, lb);
    }
    *state.memfilt_lb = shr(rec_sig[fl - 1], q_sig16);
}

/// The energies (full, first half, first three quarters, high band), zero-crossing counts and
/// longest zero-crossing-free runs of the eight sub-frames.
fn preecho_sb_subframe_energies(w: &mut PreechoWork, rec_sig: &[i16]) {
    let subframelength = w.subframelength;
    let subframelength_s2 = shr(subframelength, 1);
    let subframelength_s34 = mult(subframelength, 24576);
    let mut cntnzcr: i16 = -1;
    let mut firstnzcr: i16 = 0;
    let mut sptr1_loc: i16 = 0;
    let mut p = 0usize;
    for j in 0..NUMSF {
        let mut tmp_fx1 = shr(rec_sig[p], w.q16p1);
        let mut l1 = l_mac0(25, tmp_fx1, tmp_fx1);
        let mut l2 = l_mac0(100, w.rec_sig_hb[p], w.rec_sig_hb[p]);
        let mut sptr2_loc: i16 = 0;
        p += 1;
        for i in 1..subframelength {
            if sub(i, subframelength_s2) == 0 {
                w.es_mdct_half[j] = l1;
            }
            if sub(i, subframelength_s34) == 0 {
                w.es_mdct_quart[j] = l1;
            }
            tmp_fx1 = shr(rec_sig[p], w.q16p1);
            l1 = l_mac0(l1, tmp_fx1, tmp_fx1);
            l2 = l_mac0(l2, w.rec_sig_hb[p], w.rec_sig_hb[p]);
            cntnzcr = add(cntnzcr, 1);
            if l_mult0(rec_sig[p], rec_sig[p - 1]) <= 0 {
                sptr1_loc = add(sptr1_loc, 1);
                sptr2_loc = sptr2_loc.max(cntnzcr);
                // firstnzcr is 0 throughout the first sub-frame, so j - 1 is never -1 here
                if firstnzcr > 0 && j > 0 && sub(cntnzcr, w.maxnzcr[j - 1]) > 0 {
                    w.maxnzcr[j - 1] = cntnzcr;
                }
                firstnzcr = 0;
                cntnzcr = -1;
            }
            p += 1;
        }
        if j < NUMSF - 1 {
            cntnzcr = add(cntnzcr, 1);
        }
        sptr2_loc = sptr2_loc.max(cntnzcr);
        w.es_mdct_hb[j] = l2;
        w.zcr[j] = sptr1_loc;
        w.maxnzcr[j] = sptr2_loc;
        if firstnzcr > 0 && j > 0 && sub(cntnzcr, w.maxnzcr[j - 1]) > 0 {
            w.maxnzcr[j - 1] = cntnzcr;
        }
        sptr1_loc = 0;
        firstnzcr = 1;
        if j < NUMSF - 1 && l_mult0(rec_sig[p], rec_sig[p - 1]) <= 0 {
            sptr1_loc = add(sptr1_loc, 1);
            cntnzcr = -1;
            firstnzcr = 0;
        }
        w.es_mdct[j] = l1;
        if l_sub(w.es_mdct_half[j], l_shr(w.es_mdct[j], 1)) < 0 {
            l1 = l_shl(l_sub(w.es_mdct[j], w.es_mdct_half[j]), 1);
        }
        w.es_mdct_half[j] = l1;
    }
}

/// The energies and zero crossings of the next frame's start (`imdct_mem`), as sub-frame 8; its
/// high band continues the split filter across the frame boundary.
fn preecho_sb_next_frame_energies(w: &mut PreechoWork, rec_sig: &[i16]) {
    let mem = &w.imdct_mem;
    let len3 = w.len3x_lp20;
    let mut tmp_fx1 = shr(mem[0], w.qmemp1);
    let mut l1 = l_mac0(25, tmp_fx1, tmp_fx1);
    let mut sptr1_loc: i16 = 0;
    for i in 1..len3 {
        tmp_fx1 = shr(mem[i], w.qmemp1);
        l1 = l_mac0(l1, tmp_fx1, tmp_fx1);
        // a plain C int product here, not an STL operator
        if i32::from(mem[i]) * i32::from(mem[i - 1]) <= 0 {
            sptr1_loc = add(sptr1_loc, 1);
        }
    }
    w.es_mdct[NUMSF] = l1;
    w.zcr[NUMSF] = sptr1_loc;

    let tmp_fx3 = len3 - 1;
    let l_tmp = l_mult(rec_sig[w.framelength - 1], -8192);
    let l_tmp = l_mac(l_tmp, mem[1], -8192);
    tmp_fx1 = mac_r(l_tmp, mem[0], 16384);
    let mut l2 = l_mac0(100, tmp_fx1, tmp_fx1);
    for k in 0..tmp_fx3 - 1 {
        let l_tmp = l_mult(mem[k], -8192);
        let l_tmp = l_mac(l_tmp, mem[k + 2], -8192);
        tmp_fx1 = mac_r(l_tmp, mem[k + 1], 16384);
        l2 = l_mac0(l2, tmp_fx1, tmp_fx1);
    }
    let k = tmp_fx3 - 1;
    let l_tmp = l_mult(mem[k], -8192);
    tmp_fx1 = mac_r(l_tmp, mem[k + 1], 16384);
    w.es_mdct_hb[NUMSF] = l_mac0(l2, tmp_fx1, tmp_fx1);
}

/// Locate the attack (`maxind`, the loudest sub-frame unless it is not loud enough) and the gains
/// of the sub-frames before it.
fn preecho_sb_attack(w: &mut PreechoWork, state: &mut PreechoState<'_>) {
    // (the reference also tracks the loudest high-band sub-frame here, and never reads it)
    let mut max_es = w.es_mdct[0];
    let mut maxind: usize = 0;
    for (i, &energy) in w.es_mdct.iter().enumerate().take(NUMSF + 1).skip(1) {
        if l_sub(energy, max_es) >= 0 {
            max_es = energy;
            maxind = i;
        }
    }
    w.max_es = max_es;
    w.cnt2 = 0;
    w.cnt5 = 0;
    if *state.prevflag != 0 || l_sub(max_es, l_mult0(w.subframelength, 2500)) < 0 {
        maxind = 0;
    }
    if l_sub(max_es, l_shl(w.mean_prev_loc, 2)) < 0 {
        maxind = 0;
    }
    *state.prevflag = 0;

    // maxind can move inside the loop, and the bound is re-read every iteration
    let mut i = 0usize;
    while i < maxind {
        let mut g: i16 = 32767; // 1 Q15
        w.min_g[i] = 32767;
        w.min_g_hb[i] = 32767;
        let (l1, _) = mpy_32_16_ss(w.es_mdct_half[i], 328);
        let (l2, _) = mpy_32_16_ss(w.es_mdct_half[i], 3277);
        let (l3, _) = mpy_32_16_ss(w.es_mdct[i], 5461);
        let floor = l_add(w.mean_prev_nc_loc, 125000);
        if l_sub(l1, floor) > 0
            || (l_sub(l2, floor) > 0
                && (sub(w.zcr[i], w.limzcr) < 0 || l_sub(w.es_mdct_quart[i], l3) < 0))
        {
            // the attack is in this sub-frame (or in an earlier, not much quieter one)
            maxind = i;
            *state.prevflag = 1;
            for j in (0..i).rev() {
                if l_sub(w.es_mdct[j], l_shr(w.es_mdct[i], 1)) > 0 {
                    maxind = j;
                }
            }
        } else if l_sub(w.es_mdct[i], l_shr(max_es, 4)) < 0 {
            g = w.lim16;
            w.cnt5 = add(w.cnt5, 1);
            if l_sub(w.es_mdct[i], l_shr(max_es, 5)) < 0 {
                g = w.lim32;
                w.cnt2 = add(w.cnt2, 1);
            }
            if l_sub(w.mean_prev_loc, w.es_mdct[i]) < 0 {
                w.min_g[i] = preecho_sb_sqrt_ratio(w.mean_prev_loc, w.es_mdct[i]);
            }
            if l_sub(w.mean_prev_hb_loc, w.es_mdct_hb[i]) < 0 {
                w.min_g_hb[i] = preecho_sb_sqrt_ratio(w.mean_prev_hb_loc, w.es_mdct_hb[i]);
            }
            if sub(w.zcr[i], w.limzcr / 2) < 0 || sub(w.maxnzcr[i], w.limmaxnzcr) > 0 {
                if sub(w.min_g[i], 32767) < 0 {
                    // the previous frame's mean is too low: take this one
                    w.mean_prev_loc = w.es_mdct[i];
                }
                w.min_g[i] = 32767; // not noise-like: no limit
            }
        } else {
            if i > 0 && maxind < NUMSF {
                *state.prevflag = 1;
            }
            maxind = i; // no reduction from here on
        }
        w.gt[i] = g;
        w.gt_hb[i] = g;
        i += 1;
    }
    for i in maxind..=NUMSF {
        w.gt[i] = 32767;
        w.min_g[i] = 32767;
        w.gt_hb[i] = 32767;
        w.min_g_hb[i] = 32767;
    }
}

/// `Frac_sqrt(num / den)` for `0 <= num < den`, both normalised by `den`'s shift.
fn preecho_sb_sqrt_ratio(num: i32, den: i32) -> i16 {
    let tmp_fx1 = norm_l(den);
    let l1 = l_shl(den, tmp_fx1);
    let l2 = l_shl(num, tmp_fx1);
    let tmp_fx1 = round_word(l1);
    let tmp_fx2 = round_word(l2);
    frac_sqrt(div_s(tmp_fx2, tmp_fx1))
}

/// The attenuated sub-frames (`ind2`), their gains, and where the attack really starts within
/// the following sub-frame (`adv` samples ahead of its boundary); a high-band energy check can
/// cancel the reduction. Returns `(ind2, ind2_sfl, adv, advmem)`.
fn preecho_sb_onset(
    w: &mut PreechoWork,
    rec_sig: &[i16],
    state: &PreechoState<'_>,
) -> (i16, i16, i16, i16) {
    let mut ind2: i16 = 0;
    for (i, &gain) in w.gt.iter().enumerate().take(NUMSF) {
        if sub(gain, 32767) < 0 {
            ind2 = i as i16 + 1;
        }
    }
    if sub(w.wmold, 16384) > 0 && sub(add(w.cnt2, w.cnt5), 2) < 0 {
        ind2 = 0;
    }
    let ind2_m1 = sub(ind2, 1);
    let mut ind2_sfl = i_mult(w.subframelength, ind2);
    let numsf_ind2 = sub(NUMSF as i16, ind2);

    let smooth = w.smooth_len as usize;
    let sfl = w.subframelength as usize;
    let mut p1 = smooth;
    let mut p2 = 0usize;
    w.pre_g_ch_tab[0] = w.smooth_len;
    for i in 0..ind2 as usize {
        w.gt[i] = w.gt[i].max(w.min_g[i]);
        w.gt_hb[i] = w.gt_hb[i].max(w.min_g_hb[i]);
        for _ in 0..sfl {
            w.preechogain[p1] = w.gt[i];
            w.preechogain_hb[p2] = w.gt_hb[i];
            p1 += 1;
            p2 += 1;
        }
        w.pre_g_ch_tab[i + 1] = add(w.pre_g_ch_tab[i], w.subframelength);
    }

    let mut adv = w.smooth_len;
    let advmem = adv;
    let mut j: i16 = 0;
    if ind2 > 0 || sub(w.wmold, 32767) < 0 || sub(*state.wmold_hb, 32767) < 0 {
        j = preecho_sb_onset_search(w, rec_sig, state, ind2, ind2_m1, ind2_sfl, numsf_ind2);
        let tmp_fx3 = i_mult(j, w.subsubframelength);
        adv = sub(adv, tmp_fx3);
    }

    if ind2 > 0 {
        let ind3 = add(ind2, shr(j, w.log2_num_subsubframes));
        let (ind4, ind5, ind6) = (sub(ind3, 1), sub(ind3, 2), sub(ind3, 3));
        if ind4 > 0 {
            let hb = &w.es_mdct_hb;
            let (i3, i4, i5) = (ind3 as usize, ind4 as usize, ind5 as usize);
            let eshbmean2 = l_add(hb[i4], hb[i5]);
            let sxyhb2 = l_sub(hb[i4], hb[i5]);
            let mut cancel = false;
            if sub(ind3, 2) > 0 {
                let i6 = ind6 as usize;
                let (eshbmean3, _) = mpy_32_16_ss(l_add(eshbmean2, hb[i6]), 4369);
                let sxylb3 = l_sub(w.es_mdct[i4], w.es_mdct[i6]);
                let l1 = l_sub(hb[i4], hb[i6]);
                if l_sub(l1, eshbmean3) < 0 || sxylb3 < 0 {
                    cancel = true;
                }
            } else if sxyhb2 < 0 {
                cancel = true;
            }
            let (eshbmean3, _) = mpy_32_16_ss(l_add(eshbmean2, hb[i3]), 4369);
            let l1 = l_sub(hb[i3], hb[i5]);
            if l_sub(l1, eshbmean3) < 0 {
                cancel = true;
            }
            if cancel {
                ind2 = 0;
                ind2_sfl = 0;
                adv = advmem;
            }
        }
    }
    (ind2, ind2_sfl, adv, advmem)
}

/// The fine onset search over sub-sub-frames after the last attenuated sub-frame (or over the next
/// frame's start when all eight are attenuated); fills the gains up to the onset and returns its
/// sub-sub-frame index `j`.
fn preecho_sb_onset_search(
    w: &mut PreechoWork,
    rec_sig: &[i16],
    state: &PreechoState<'_>,
    ind2: i16,
    ind2_m1: i16,
    ind2_sfl: i16,
    numsf_ind2: i16,
) -> i16 {
    let mut plus_es_mdct = [0i32; 64];
    let mut mean_plus_es = [0i32; 65];
    let mut max_plus_es_mdct: i32 = 0;

    // the source: rec_sig from the onset sub-frame, or imdct_mem (Q0)
    let from_rec = numsf_ind2 > 0;
    let mut ptr = 0usize;
    let mut qtmp = w.qmemp1;
    let mut pluslim = w.num_subsubframes;
    if from_rec {
        ptr = ind2_sfl as usize;
        qtmp = w.q16p1;
        pluslim = i_mult(numsf_ind2, w.num_subsubframes);
    }
    let mut maxcrit = w.mean_prev_nc_loc;
    let mut sum_plus_es;
    let oldgain;
    let oldgain_hb;
    if ind2 == 0 {
        sum_plus_es = w.mean_prev_nc_loc; // 8 times the mean sub-frame energy
        pluslim = w.num_subsubframes;
        oldgain = w.wmold;
        oldgain_hb = *state.wmold_hb;
    } else {
        let m1 = ind2_m1 as usize;
        sum_plus_es = w.es_mdct[m1];
        oldgain = w.gt[m1];
        oldgain_hb = w.gt_hb[m1];
        let tmp_fx1 = mult_r(w.gt[m1], w.gt[m1]);
        maxcrit = mpy_32_16_ss(w.es_mdct[m1], tmp_fx1).0;
        let (l1, _) = mpy_32_16_ss(w.max_es, 410);
        if l_sub(l1, maxcrit) > 0 && sub(w.zcr[ind2 as usize], w.limzcr) > 0 {
            maxcrit = l1; // still 10 times smaller than the attack: limit to that
        }
    }

    let pluslim = pluslim.max(0) as usize;
    for j in 0..pluslim {
        let mut l1: i32 = 100;
        for _ in 0..w.subsubframelength {
            let sample = if from_rec {
                rec_sig[ptr]
            } else {
                w.imdct_mem[ptr]
            };
            let tmp_fx1 = shr(sample, qtmp);
            l1 = l_mac0(l1, tmp_fx1, tmp_fx1);
            ptr += 1;
        }
        if l_sub(l1, max_plus_es_mdct) > 0 {
            max_plus_es_mdct = l1;
        }
        sum_plus_es = l_add(sum_plus_es, l_shl(l1, 2));
        plus_es_mdct[j] = l1;
        let mean = mpy_32_16_ss(sum_plus_es, INV_JP2[j]).0;
        mean_plus_es[j + 1] = if l_sub(mean, maxcrit) < 0 {
            maxcrit
        } else {
            mean
        };
    }
    mean_plus_es[pluslim + 1] = -1;
    mean_plus_es[0] = plus_es_mdct[0];
    if l_sub(mean_plus_es[0], maxcrit) < 0 {
        mean_plus_es[0] = maxcrit;
    }

    // the loudest sub-sub-frame always ends the search (max < max / 8 is false), so j stays
    // below pluslim; the bound only makes that visible
    let mut j = 0usize;
    while j < pluslim
        && l_sub(plus_es_mdct[j], mean_plus_es[j]) < 0
        && l_sub(plus_es_mdct[j], max_plus_es_mdct / 8) < 0
    {
        j += 1;
    }
    let j = j as i16;
    let tmp_fx3 = i_mult(j, w.subsubframelength);
    if from_rec {
        let at = ind2_sfl as usize;
        let smooth = w.smooth_len as usize;
        for i in 0..tmp_fx3.max(0) as usize {
            w.preechogain[at + smooth + i] = oldgain;
            w.preechogain_hb[at + i] = oldgain_hb;
        }
    }
    j
}

/// Complete and smooth the two gain curves and apply them to the bands of `rec_sig`.
fn preecho_sb_apply(
    w: &mut PreechoWork,
    rec_sig: &mut [i16],
    state: &mut PreechoState<'_>,
    ind2: i16,
    ind2_sfl: i16,
    adv: i16,
    advmem: i16,
) {
    let fl = w.framelength;
    let ind2_m1 = sub(ind2, 1);
    let mut stind = sub(ind2_sfl, adv);
    let mut stind_hb = add(stind, advmem);
    if stind < 0 {
        stind = 0;
    }
    if stind_hb < 0 {
        stind_hb = 0;
    }
    let tmp_fx1 = add(stind, w.smooth_len);
    // A start at or past fl leaves nothing to fill and touches no index, as the C loop does.
    let start = tmp_fx1.max(0) as usize;
    if start < fl {
        w.preechogain[start..fl].fill(32767);
    }
    w.pre_g_ch_tab[ind2 as usize] = tmp_fx1.min(fl as i16);
    let start_hb = stind_hb as usize;
    if start_hb < fl {
        w.preechogain_hb[start_hb..fl].fill(32767);
    }
    let smooth = w.smooth_len as usize;
    w.preechogain[..smooth].fill(*state.smoothmem);
    let mut fattnext: i16 = 32767;
    if stind > fl as i16 {
        // the onset is beyond this frame: keep attenuating into the next one
        fattnext = w.gt[ind2_m1.max(0) as usize];
    }
    for i in 0..smooth {
        w.preechogain[fl + i] = fattnext;
    }
    // linear transitions of smooth_len samples at each gain change
    for i in 0..=ind2 as usize {
        let t1 = w.pre_g_ch_tab[i] as usize;
        let t2 = t1 - smooth;
        let tmp_fx3 = mult_r(sub(w.preechogain[t1], w.preechogain[t2]), w.invsmoothlenp1);
        let mut step = tmp_fx3;
        for g in &mut w.preechogain[t2..t2 + smooth] {
            *g = add(*g, step);
            step = add(step, tmp_fx3);
        }
    }
    *state.smoothmem = fattnext;
    *state.wmold_hb = w.preechogain_hb[fl - 1];

    for (i, out) in rec_sig[..fl].iter_mut().enumerate() {
        let l_tmp = l_mult(w.rec_sig_lb[i], w.preechogain[i]);
        *out = mac_r(l_tmp, w.rec_sig_hb[i], w.preechogain_hb[i]);
    }
}

/// The mean sub-frame energies of this frame, un-attenuated and attenuated (full and high band),
/// for the next frame's decisions.
fn preecho_sb_update_means(
    w: &mut PreechoWork,
    state: &mut PreechoState<'_>,
    q_sig16: i16,
    ind2: i16,
) {
    let mut savehalfe: i32 = 0;
    let mut savehalfe_hb: i32 = 0;
    let mut nc = w.es_mdct[0];
    for (i, &energy) in w.es_mdct.iter().enumerate().take(NUMSF).skip(1) {
        if i == NUMSF / 2 {
            savehalfe = nc;
        }
        nc = l_add(nc, energy);
    }
    if l_sub(savehalfe, l_shr(nc, 1)) < 0 {
        // more energy in the second half: count it twice
        nc = l_shl(l_sub(nc, savehalfe), 1);
    }
    nc = l_shr(nc, 3);

    for i in 0..ind2.max(0) as usize {
        let tmp_fx1 = mult_r(w.gt[i], w.gt[i]);
        w.es_mdct[i] = mpy_32_16_ss(w.es_mdct[i], tmp_fx1).0;
        let tmp_fx1 = mult_r(w.gt_hb[i], w.gt_hb[i]);
        w.es_mdct_hb[i] = mpy_32_16_ss(w.es_mdct_hb[i], tmp_fx1).0;
    }
    let mut mean_prev = l_shr(w.es_mdct[0], 3);
    let mut mean_prev_hb = l_shr(w.es_mdct_hb[0], 3);
    for i in 1..NUMSF {
        if i == NUMSF / 2 {
            savehalfe = mean_prev;
            savehalfe_hb = mean_prev_hb;
        }
        mean_prev = l_add(mean_prev, l_shr(w.es_mdct[i], 3));
        mean_prev_hb = l_add(mean_prev_hb, l_shr(w.es_mdct_hb[i], 3));
    }
    let l1 = l_sub(mean_prev, savehalfe);
    if l_sub(savehalfe, l_shr(mean_prev, 1)) < 0 {
        mean_prev = l_shl(l1, 1);
    }
    let l1 = l_sub(mean_prev_hb, savehalfe_hb);
    if l_sub(savehalfe_hb, l_shr(mean_prev_hb, 1)) < 0 {
        mean_prev_hb = l_shl(l1, 1);
    }
    let last2 = l_shr(l_add(w.es_mdct[NUMSF - 1], w.es_mdct[NUMSF - 2]), 1);
    let last2_hb = l_shr(l_add(w.es_mdct_hb[NUMSF - 1], w.es_mdct_hb[NUMSF - 2]), 1);
    if l_sub(last2, mean_prev) > 0 {
        mean_prev = last2;
    }
    if l_sub(last2_hb, mean_prev_hb) > 0 {
        mean_prev_hb = last2_hb;
    }
    *state.mean_prev = mean_prev;
    *state.mean_prev_hb = l_shr(mean_prev_hb, shl(q_sig16, 1));
    *state.mean_prev_nc = nc;
}
