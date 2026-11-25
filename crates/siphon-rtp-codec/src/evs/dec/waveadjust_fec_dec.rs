//! The TCX waveform-adjustment concealment (TS 26.442 `lib_dec/waveadjust_fec_dec.c`; TS 26.445
//! §6.2.4.2): pitch search on the last good output, waveform adjustment of the first lost frame
//! (periodic extension with an overlap-add), smoothing of the following lost frames and of the
//! recovery, and the bookkeeping that feeds them (zero crossings, energy, spectrum, tonality).
//!
//! Where the reference passes `st` only to read three scalars, the port takes the scalars
//! (`enable_plc_waveadjust`, `last_total_brate`, `last_codec_mode`), because the caller also holds
//! `st.plc_info` mutably. The reference's `OverlapBuf` / `outdata2` pointers are the second last
//! and last PCM output of the tonal concealment, which overlap in one buffer; they are passed as
//! that buffer plus the two offsets so a write through one is seen through the other.

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    DEC_STATE_LEN, EVS_LW_MIN, L_FRAME_MAX, MAX_POST_LEN, MODE2, TCX_NONTONAL,
    TCX_TONALITY_INIT_CNT,
};
use crate::evs::com::basop_util::basop_util_divide1616_scale;
use crate::evs::dec::state::TPLCInfo;
use crate::evs::rom::SQRT_TABLE_PITCH_SEARCH;
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult,
    l_negate, l_shl, l_shr, l_shr_r, l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl,
    shr, shr_r, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0, mac_r, mpy_32_16_ss};

/// `vadmin`: the smaller of two values.
#[must_use]
pub fn vadmin(a: i16, b: i16) -> i16 {
    a.min(b)
}

/// `set_state`: shift `state[0..n]` down by one and append `num`.
pub fn set_state(state: &mut [i16], num: i16, n: i16) {
    let tmp = sub(n, 1);
    for i in 0..tmp.max(0) as usize {
        state[i] = state[i + 1];
    }
    state[tmp as usize] = num;
}

/// `concealment_update_x`: keep the last good frame's spectrum (`invkoef`, scale `invkoef_scale`),
/// transient flags and tonality for the concealment of the next lost frame.
pub fn concealment_update_x(
    bfi: i16,
    curr_mode: i16,
    tonality: i16,
    invkoef: &[i32],
    invkoef_scale: i16,
    plc_info: &mut TPLCInfo,
) {
    let frame_size = plc_info.frame_size;
    let subframe = plc_info.subframe;
    if sub(curr_mode, 1) == 0 {
        set_state(&mut plc_info.transient, curr_mode, MAX_POST_LEN);

        let n = frame_size.max(0) as usize;
        plc_info.data_reci2[..n].copy_from_slice(&invkoef[..n]);
        plc_info.data_reci2_scale = invkoef_scale;
        if bfi == 0 {
            set_state(&mut plc_info.tcx_tonality, tonality, DEC_STATE_LEN);
        }
    } else {
        if subframe == 0 {
            set_state(&mut plc_info.transient, curr_mode, MAX_POST_LEN);

            if bfi == 0 {
                set_state(&mut plc_info.tcx_tonality, tonality, DEC_STATE_LEN);
            }
        }
        // don't store the second subframe during frameloss; in pitch_search_fx(), low_freq_rate
        // is derived on the last good TCX-10 spectrum
        if bfi == 0 || subframe == 0 {
            let frame_size2 = shr(frame_size, 1);
            let at = subframe.max(0) as usize;
            let n = frame_size2.max(0) as usize;
            plc_info.data_reci2[at..at + n].copy_from_slice(&invkoef[..n]);

            plc_info.data_reci2_scale = invkoef_scale;
        }
    }
}

/// `zero_pass_w32_x`: the number of sign changes of `s[0..n]`.
fn zero_pass_w32_x(s: &[i16], n: i16) -> i16 {
    let mut zp = l_deposit_l(0);
    for i in 1..n.max(0) as usize {
        let temp = l_mac0(-1, s[i], s[i - 1]);
        zp = l_sub(zp, l_shr(temp, 31));
    }
    extract_l(zp)
}

/// `Sqrt_x_fast`: square root of `value` by table look-up on its leading bits.
#[must_use]
pub fn sqrt_x_fast(value: i32) -> i16 {
    let norm = sub(23, norm_l(value));
    let index = extract_l(l_shr_r(value, add(norm, norm & 1)));
    // `index` is at most 256 for a non-negative `value`; the table has 257 entries
    shr(
        SQRT_TABLE_PITCH_SEARCH[index.clamp(0, 256) as usize],
        sub(11, shr(add(norm, 1), 1)),
    )
}

/// `dot_w32_accuracy_x`: `Σ (s1[i]·s2[i]) >> nbits` over `n` samples.
#[must_use]
pub fn dot_w32_accuracy_x(s1: &[i16], s2: &[i16], nbits: i16, n: i16) -> i32 {
    let mut eng = l_deposit_l(0);
    for i in 0..n.max(0) as usize {
        let temp = l_mult0(s1[i], s2[i]);
        eng = l_add(eng, l_shr(temp, nbits));
    }
    eng
}

/// `int_div_s_x`: `round(a / b)` by restoring division; 0 when `a < b` or `b == 0`.
#[must_use]
pub fn int_div_s_x(a: i16, b: i16) -> i16 {
    let mut a = a;
    let mut result: i16 = 0;
    if sub(a, b) < 0 || b == 0 {
        return 0;
    }
    a = add(a, shr(b, 1));
    let norm = sub(norm_s(b), norm_s(a));

    let mut i = norm;
    while i >= 0 {
        let left = shr(a, i);
        result = shl(result, 1);
        if sub(left, b) >= 0 {
            result = add(result, 1);
            let left = sub(left, b);
            a = add(shl(left, i), a & sub(shl(1, i), 1));
        }
        i -= 1;
    }
    result
}

/// `GetW32Norm_x`: the headroom of the largest magnitude in `s[0..n]`.
fn get_w32_norm_x(s: &[i32], n: i16) -> i16 {
    let mut smax = l_deposit_l(0);
    for &value in &s[..n.max(0) as usize] {
        smax |= l_abs(value);
    }
    norm_l(smax)
}

/// `harmo_x`: the share (Q15) of the spectral energy of `x[0..framesize]` in the bins around the
/// first eight harmonics of `pitch`.
#[must_use]
pub fn harmo_x(x: &[i32], framesize: i16, pitch: i16) -> i16 {
    let mut ener = l_deposit_l(0);
    let mut ener_harmo = l_deposit_l(0);
    let nbits = sub(15, norm_s(framesize));
    let mut norm1 = get_w32_norm_x(x, framesize);

    for k in 1..9 {
        let h = sub(int_div_s_x(extract_l(l_mult(k, framesize)), pitch), 1);

        // The reference reads x[-1] for a zero pitch (never passed: harmo_x runs for a pitch above
        // zero) and x[h + 1] past the frame for a pitch below a quarter of the frame, which the
        // pitch search rules out; both read 0 here.
        let at = |index: i16| -> i32 {
            usize::try_from(index)
                .ok()
                .and_then(|index| x.get(index))
                .copied()
                .unwrap_or(0)
        };
        let d1 = extract_h(l_shl(at(h), norm1));
        let d2 = extract_h(l_shl(at(add(h, 1)), norm1));

        ener_harmo = l_add(ener_harmo, l_shr(l_mac0(l_mult0(d1, d1), d2, d2), nbits));
    }

    for &value in &x[..framesize.max(0) as usize] {
        let d1 = extract_h(l_shl(value, norm1));
        ener = l_add(ener, l_shr(l_mult0(d1, d1), nbits));
    }

    norm1 = norm_l(ener);
    let ener_w = extract_h(l_shl(ener, norm1));
    let ener_harmo_w = extract_h(l_shl(ener_harmo, norm1));

    if l_sub(ener_harmo, ener) >= 0 {
        return 32767;
    }
    if ener_harmo_w <= 0 || ener_w <= 0 {
        return 0;
    }
    div_s(ener_harmo_w, ener_w)
}

/// `get_low_freq_eng_rate_x`: whether the energy below the first 30 bins (15 for TCX-10) of the
/// last good spectrum is under 2 % of its total.
fn get_low_freq_eng_rate_x(mdct_data: &[i32], curr_mode: i16, n: i16) -> i16 {
    let mut low_eng = l_deposit_l(0);
    let mut eng = l_deposit_l(0);
    let mut smax = l_deposit_l(0);
    let mut n1: i16 = 30;
    let mut n2: i16 = n;
    if sub(2, curr_mode) == 0 {
        n1 = shr(30, 1);
        n2 = shr(n, 1);
    }

    let nbits = sub(15, norm_s(n2));

    for &value in &mdct_data[..n2.max(0) as usize] {
        smax |= l_abs(value);
    }

    let norm = norm_l(smax);

    let (low_band, high_band) = mdct_data[..n2.max(0) as usize].split_at(n1.max(0) as usize);
    for &value in low_band {
        let temp = extract_h(l_shl(value, norm));
        low_eng = l_add(low_eng, l_shr(l_mult0(temp, temp), nbits));
    }

    for &value in high_band {
        let temp = extract_h(l_shl(value, norm));
        eng = l_add(eng, l_shr(l_mult0(temp, temp), nbits));
    }
    eng = l_add(low_eng, eng);

    // IF (low_eng<(eng+EPSILON)*0.02) return 1;ELSE return 0;
    smax = l_shr(mpy_32_16_1(eng, 5243), 3);

    i16::from(l_sub(low_eng, smax) <= 0)
}

/// `LpFilter2_x`: the two-pole low-pass `y = 0.18·x + 0.64·y[-1] + 0.18·y[-2]` of `x[0..n]`
/// (scaled up to full range first).
pub fn lp_filter2_x(x: &[i16], y: &mut [i16], n: i16) {
    let a1: i16 = 5898; // W16(0.18f)
    let a2: i16 = 20971; // W16(0.64f)
    let mut smax: i16 = 0;
    for &value in &x[..n.max(0) as usize] {
        smax |= abs_s(value);
    }
    let norm = norm_s(smax);

    y[0] = mult(shl(x[0], norm), a1);
    y[1] = add(mult(y[0], a2), mult(shl(x[1], norm), a1));

    for i in 2..n.max(0) as usize {
        // 5898*2+20971=32767 -->no overflow
        y[i] = add(
            mult(y[i - 2], a1),
            add(mult(y[i - 1], a2), mult(shl(x[i], norm), a1)),
        );
    }
}

/// `sig_tilt_x`: the energies `enr1` (lag-2 correlation) and `enr2` (energy) of the last three
/// quarters of `s[0..frame_size]`, for the spectral tilt test.
pub fn sig_tilt_x(s: &[i16], frame_size: i16, enr1: &mut i32, enr2: &mut i32) {
    let sub_frame_size = shr(frame_size, 2);
    let p1 = sub_frame_size as usize;
    let p2 = sub(sub_frame_size, 2) as usize;

    let shift = sub(frame_size, sub_frame_size);
    let nbits = sub(15, norm_s(shift));
    *enr1 = dot_w32_accuracy_x(&s[p1..], &s[p2..], nbits, shift);
    *enr2 = dot_w32_accuracy_x(&s[p1..], &s[p1..], nbits, shift);
}

/// `get_maxConv_and_pitch_x`: over the lags `s..e` find the lag after which the (length
/// normalised) autocorrelation of `s_lp` stops rising, with its value and the shift it carries.
pub fn get_max_conv_and_pitch_x(
    s_lp: &[i16],
    s: i16,
    e: i16,
    n: i16,
    max_conv: &mut i32,
    max_conv_bits: &mut i16,
    pitch: &mut i16,
) {
    let mut size = n;
    let mut cov_max_sigma = l_deposit_l(0);
    let mut tmp_pitch: i16 = 0;
    let mut tmp_sigma_last = l_deposit_l(0);
    let mut cov_size_last = n;
    let mut cov_max_sigma_tmp = l_deposit_l(0);
    let mut size_tmp = n;
    let nbits = sub(15, norm_s(sub(n, s)));

    for t in s..e {
        let cov_size = sub(n, t);
        let tmp_sigma = dot_w32_accuracy_x(s_lp, &s_lp[t as usize..], nbits, cov_size);

        if sub(t, s) > 0 {
            // don't use the first value
            let (r1_high, r1_low) = mpy_32_16_ss(tmp_sigma, cov_size_last);
            let (r2_high, r2_low) = mpy_32_16_ss(tmp_sigma_last, cov_size);
            // tmp_sigma > tmp_sigma_last
            if l_sub(r1_high, r2_high) > 0
                || (l_sub(r1_high, r2_high) == 0 && l_sub(i32::from(r1_low), i32::from(r2_low)) > 0)
            {
                // store the current cov, if it is larger than the last one
                cov_max_sigma_tmp = tmp_sigma;
                size_tmp = cov_size;
            } else {
                let (r1_high, r1_low) = mpy_32_16_ss(cov_max_sigma, size_tmp);
                let (r2_high, r2_low) = mpy_32_16_ss(cov_max_sigma_tmp, size);
                // cov_max_sigma < cov_max_sigma_tmp
                if l_sub(r1_high, r2_high) < 0
                    || (l_sub(r1_high, r2_high) == 0
                        && l_sub(i32::from(r1_low), i32::from(r2_low)) < 0)
                {
                    // use the last value of cov, being a max, and the last index as pitch
                    cov_max_sigma = cov_max_sigma_tmp;
                    size = cov_size;
                    tmp_pitch = sub(t, 1);
                }
            }
        }
        tmp_sigma_last = tmp_sigma;
        cov_size_last = cov_size;
    }
    *pitch = tmp_pitch;
    *max_conv = cov_max_sigma;
    *max_conv_bits = nbits;
}

/// `get_voicing_x`: the normalised correlation (Q15) at lag `pitch` of `s_lp[0..framesize]`.
#[must_use]
pub fn get_voicing_x(
    s_lp: &[i16],
    pitch: i16,
    cov_max: i32,
    max_conv_bits: i16,
    framesize: i16,
) -> i16 {
    if cov_max <= 0 {
        return 0;
    }
    let tmp_len = sub(framesize, pitch);
    let nbits = max_conv_bits;

    let mut eng1 = dot_w32_accuracy_x(s_lp, s_lp, nbits, tmp_len);
    let mut eng2 = dot_w32_accuracy_x(
        &s_lp[pitch as usize..],
        &s_lp[pitch as usize..],
        nbits,
        tmp_len,
    );

    let norm = sub(norm_l(eng1 | (eng2 | cov_max)), 1);
    eng1 = l_shl(eng1, norm);
    eng2 = l_shl(eng2, norm);
    let cov_max = l_shl(cov_max, norm);

    let eng1_w = sqrt_x_fast(eng1);
    let eng2_w = sqrt_x_fast(eng2);

    let eng1 = l_mult0(eng1_w, eng2_w);
    let norm = norm_l(eng1);
    let eng1_w = extract_h(l_shl(eng1, norm));
    let eng2_w = extract_h(l_shl(cov_max, norm));

    if l_sub(cov_max, eng1) >= 0 {
        return 32767;
    }
    if eng2_w <= 0 || eng1_w <= 0 {
        return 0;
    }
    div_s(eng2_w, eng1_w)
}

/// `pitch_modify_x`: halve the pitch when the half lag correlates better than `voicing`.
pub fn pitch_modify_x(s_lp: &[i16], voicing: &mut i16, pitch: &mut i16, frame_size: i16) {
    let shift = shr(*pitch, 1);

    let tmp_len = sub(frame_size, shift);
    let nbits = sub(15, norm_s(tmp_len));
    let at = shift as usize;

    let mut eng1 = dot_w32_accuracy_x(&s_lp[at..], &s_lp[at..], nbits, tmp_len);
    let mut eng2 = dot_w32_accuracy_x(s_lp, s_lp, nbits, tmp_len);
    let mut eng3 = dot_w32_accuracy_x(&s_lp[at..], s_lp, nbits, tmp_len);

    if eng3 <= 0 {
        return;
    }

    let norm = sub(norm_l(eng1 | (eng2 | eng3)), 1);
    eng1 = l_shl(eng1, norm);
    eng2 = l_shl(eng2, norm);
    eng3 = l_shl(eng3, norm);

    let eng1_w = sqrt_x_fast(eng1);
    let eng2_w = sqrt_x_fast(eng2);

    eng1 = l_mult0(eng1_w, eng2_w);

    let norm = norm_l(eng1);
    let eng1_w = extract_h(l_shl(eng1, norm));
    let eng2_w = extract_h(l_shl(eng3, norm));

    let voicing2 = if l_sub(eng3, eng1) >= 0 {
        32767
    } else if eng2_w <= 0 || eng1_w <= 0 {
        0
    } else {
        div_s(eng2_w, eng1_w)
    };

    if sub(voicing2, *voicing) > 0 {
        *pitch = shift;
        *voicing = voicing2;
    }
}

/// `Is_Periodic_x`: whether the last good frame is periodic enough to extend, from its
/// correlation `cov_max`, zero crossings `zp`, energy `ener` against the mean `ener_mean` (Q8)
/// and the harmonic share of its spectrum.
#[must_use]
pub fn is_periodic_x(
    mdct_data: &[i32],
    cov_max: i16,
    zp: i16,
    ener: i32,
    ener_mean: i32,
    pitch: i16,
    framesize: i16,
) -> i16 {
    if l_sub(ener, l_shl(50, 8)) < 0
        || (l_sub(ener, l_sub(ener_mean, l_shl(8, 8))) < 0 && sub(cov_max, 29491) < 0)
    {
        0
    } else if sub(cov_max, 26214) > 0 {
        1
    } else if sub(zp, 100) > 0 || l_sub(ener, l_sub(ener_mean, l_shl(6, 8))) < 0 {
        0
    } else if l_sub(ener, l_add(ener_mean, l_shl(1, 8))) > 0 && sub(cov_max, 19661) > 0 {
        1
    } else {
        let harm = harmo_x(mdct_data, framesize, pitch);
        i16::from(sub(harm, 22938) >= 0)
    }
}

/// `get_conv_relation_x`: the normalised correlation (Q15) of `s_lp[0..n]` with itself shifted by
/// `shift`.
#[must_use]
pub fn get_conv_relation_x(s_lp: &[i16], shift: i16, n: i16) -> i16 {
    let nbits = sub(15, norm_s(n));
    let at = shift as usize;
    let mut eng3 = dot_w32_accuracy_x(s_lp, &s_lp[at..], nbits, n);

    if eng3 <= 0 {
        return 0;
    }

    let mut eng1 = dot_w32_accuracy_x(&s_lp[at..], &s_lp[at..], nbits, n);
    let mut eng2 = dot_w32_accuracy_x(s_lp, s_lp, nbits, n);

    let norm = sub(norm_l(eng1 | (eng2 | eng3)), 1);
    eng1 = l_shl(eng1, norm);
    eng2 = l_shl(eng2, norm);
    eng3 = l_shl(eng3, norm);

    let eng1_w = sqrt_x_fast(eng1);
    let eng2_w = sqrt_x_fast(eng2);

    eng1 = l_mult0(eng1_w, eng2_w);

    let norm = norm_l(eng1);
    let eng1_w = extract_h(l_shl(eng1, norm));
    let eng2_w = extract_h(l_shl(eng3, norm));

    if l_sub(eng3, eng1) >= 0 {
        return 32767;
    }
    if eng2_w <= 0 || eng1_w <= 0 {
        return 0;
    }
    div_s(eng2_w, eng1_w)
}

/// `pitch_search_fx`: the pitch (0 when the last good frame is not periodic) of `s`, the last
/// good output (`lastPcmOut`), and its `voicing`; `outx_new` is the lost frame's IMDCT output and
/// `mdct_data` the last good spectrum.
pub fn pitch_search_fx(
    s: &[i16],
    outx_new: &[i16],
    framesize: i16,
    voicing: &mut i16,
    zp: i16,
    ener: i32,
    ener_mean: i32,
    mdct_data: &[i32],
    curr_mode: i16,
) -> i16 {
    let mut pitch: i16 = 0;
    let mut cov_max: i32 = l_deposit_l(0);
    let mut s_lp = [0i16; L_FRAME_MAX as usize];
    let mut cov_max_bits: i16 = 0;
    *voicing = 0;
    let mut curr_frmsize = framesize;
    if sub(2, curr_mode) == 0 {
        curr_frmsize = shr(framesize, 1);
    }

    let mut zp_current = zero_pass_w32_x(outx_new, curr_frmsize);

    if sub(2, curr_mode) == 0 {
        zp_current = shl(zp_current, 1);
    }
    if sub(framesize, 256) <= 0 {
        if sub(zp_current, 70) > 0 {
            return 0;
        }
    } else if sub(zp_current, 105) > 0 {
        return 0;
    }

    let mut mdct_at = 0usize;
    if sub(2, curr_mode) == 0 {
        mdct_at = shr(framesize, 1) as usize;
    }

    let low_freq_rate_result = get_low_freq_eng_rate_x(&mdct_data[mdct_at..], curr_mode, framesize);

    if low_freq_rate_result != 0 {
        return 0;
    }

    lp_filter2_x(s, &mut s_lp, framesize);
    let (mut tilt_enr1, mut tilt_enr2) = (0i32, 0i32);
    sig_tilt_x(&s_lp, framesize, &mut tilt_enr1, &mut tilt_enr2);
    if sub(framesize, 320) <= 0 {
        if tilt_enr2 == 0 || l_sub(tilt_enr1, l_shr(tilt_enr2, 1)) < 0 {
            return 0;
        }
    } else if tilt_enr2 == 0 || l_sub(tilt_enr1, mpy_32_16_1(tilt_enr2, 22938)) < 0 {
        return 0;
    }

    if sub(framesize, 320) <= 0 {
        let start_pos = extract_l(l_shr(l_mac0(0x80, 34, framesize), 8));
        let end_pos = extract_l(l_shr(l_mac0(0x2, 3, framesize), 2));
        get_max_conv_and_pitch_x(
            &s_lp,
            start_pos,
            end_pos,
            framesize,
            &mut cov_max,
            &mut cov_max_bits,
            &mut pitch,
        );
        *voicing = get_voicing_x(&s_lp, pitch, cov_max, cov_max_bits, framesize);
        pitch_modify_x(&s_lp, voicing, &mut pitch, framesize);
    } else {
        let mut s_tmp = [0i16; L_FRAME_MAX as usize];

        let framesize_tmp = shr(framesize, 1);
        for i in 0..framesize_tmp.max(0) as usize {
            s_tmp[i] = s_lp[2 * i];
        }

        let mut start_pos = extract_l(l_shr(l_mac0(0x80, 34, framesize_tmp), 8));
        let mut end_pos = extract_l(l_shr(l_mac0(0x2, 3, framesize_tmp), 2));

        cov_max = l_deposit_l(0);
        pitch = 0;
        get_max_conv_and_pitch_x(
            &s_tmp,
            start_pos,
            end_pos,
            framesize_tmp,
            &mut cov_max,
            &mut cov_max_bits,
            &mut pitch,
        );

        if pitch > 0 {
            let mut pitch_tmp = [0i16; 3];
            if sub(shl(pitch, 1), 1) > 0 {
                pitch_tmp[0] = sub(shl(pitch, 1), 1);
            }
            pitch_tmp[1] = shl(pitch, 1);
            pitch_tmp[2] = add(shl(pitch, 1), 1);
            start_pos = 0;
            pitch = 0;
            for &candidate in &pitch_tmp {
                let cov_size = sub(framesize, candidate);
                end_pos = get_conv_relation_x(&s_lp, candidate, cov_size);
                if sub(end_pos, start_pos) > 0 {
                    start_pos = end_pos;
                    pitch = candidate;
                }
            }
            *voicing = start_pos;
        }
    }

    let mut flag: i16 = 0;
    if pitch > 0 {
        flag = is_periodic_x(mdct_data, *voicing, zp, ener, ener_mean, pitch, framesize);
    }
    if flag == 0 {
        pitch = 0;
    }
    pitch
}

/// `concealment_init_x`: resets the waveform-adjustment concealment state for a TCX frame of `n`
/// samples.
pub fn concealment_init_x(n: i16, plc_info: &mut TPLCInfo) {
    plc_info.frame_size = n;
    plc_info.pitch = 0;
    plc_info.t_bfi = 0;
    plc_info.outx_new_n1 = 0;
    plc_info.nsapp_gain = 0;
    plc_info.nsapp_gain_n = 0;
    plc_info.ener_mean = 15213; // Q8 59.4260f*256
    plc_info.ener = 0;
    plc_info.zp = n;
    plc_info.recovery_gain = 0;
    plc_info.step_concealgain = 0;
    plc_info.concealment_method = TCX_NONTONAL;
    plc_info.subframe = 0;
    plc_info.nb_lost_cmpt = 0;
    plc_info.seed = 21845;

    let init_cnt = TCX_TONALITY_INIT_CNT as usize;
    plc_info.tcx_tonality[..init_cnt].fill(1);
    plc_info.tcx_tonality[init_cnt..DEC_STATE_LEN as usize].fill(0);
    plc_info.transient[..MAX_POST_LEN as usize].fill(1);
    plc_info.data_reci2[..L_FRAME_MAX as usize].fill(0);
}

/// `own_random_fix`: the concealment's linear congruential generator.
fn own_random_fix(seed: &mut i16) -> i16 {
    *seed = extract_l(l_mac0(13849, *seed, 31821));
    *seed
}

/// `concealment_decode_fix`: for a TCX-20 loss without tonal concealment, repeat the last good
/// spectrum with randomised signs.
pub fn concealment_decode_fix(
    curr_mode: i16,
    invkoef: &mut [i32],
    invkoef_scale: &mut i16,
    plc_info: &mut TPLCInfo,
) {
    let n = plc_info.frame_size;
    if plc_info.concealment_method == TCX_NONTONAL && sub(curr_mode, 1) == 0 {
        // copy the data of the last frame
        invkoef[..n.max(0) as usize].copy_from_slice(&plc_info.data_reci2[..n.max(0) as usize]);
        *invkoef_scale = plc_info.data_reci2_scale;
        // sign randomization
        for value in &mut invkoef[..n.max(0) as usize] {
            let sign = add(shl(shr(own_random_fix(&mut plc_info.seed), 15), 1), 1);
            if sub(sign, -1) == 0 {
                *value = l_negate(*value);
            }
        }
    }
}

/// `Spl_GetScalingSquare_x`: the right shift that keeps the sum of `times` squares of the vector
/// in 32 bits.
fn spl_get_scaling_square_x(in_vector: &[i16], in_vector_length: i16, times: i16) -> i16 {
    let mut nbits = sub(15, norm_s(times));
    let mut smax: i16 = -1;
    for &value in &in_vector[..in_vector_length.max(0) as usize] {
        smax = smax.max(abs_s(value));
    }

    let t = norm_l(l_mult0(smax, smax));

    if smax == 0 {
        return 0; // since norm(0) returns 0
    }
    nbits = sub(nbits, t);
    nbits.max(0)
}

/// `Spl_Energy_x`: the energy of the vector scaled down by `scale_factor` bits.
fn spl_energy_x(vector: &[i16], vector_length: i16, scale_factor: &mut i16) -> i32 {
    let mut en = l_deposit_l(0);
    let scaling = spl_get_scaling_square_x(vector, vector_length, vector_length);

    for &value in &vector[..vector_length.max(0) as usize] {
        en = l_add(en, l_shr(l_mult0(value, value), scaling));
    }

    *scale_factor = scaling;
    en
}

/// `fnLog2`: `log2` of a positive 32-bit value as a quadratic approximation.
fn fn_log2(l_input: i32) -> i32 {
    let sw_c0: i16 = -0x2b2a;
    let sw_c1: i16 = 0x7fc5;
    let sw_c2: i16 = -0x54d0;

    // normalize input and store shifts required
    let mut si_shift_cnt = norm_l(l_input);
    let mut lw_in = l_shl(l_input, si_shift_cnt);
    si_shift_cnt = add(si_shift_cnt, 1);
    si_shift_cnt = negate(si_shift_cnt);

    // calculate x*x*c0
    let sw_in = extract_h(lw_in);
    let sw_in_sqrd = mult_r(sw_in, sw_in);
    lw_in = l_mult(sw_in_sqrd, sw_c0);

    // add x*c1
    lw_in = l_mac(lw_in, sw_in, sw_c1);

    // add c2
    lw_in = l_add(lw_in, l_deposit_h(sw_c2));

    // apply *(4/32)
    lw_in = l_shr(lw_in, 3);
    lw_in &= 0x03ff_ffff;
    si_shift_cnt = shl(si_shift_cnt, 10);
    lw_in = l_add(lw_in, l_deposit_h(si_shift_cnt));

    lw_in
}

/// `fnLog10`: `log10(2)·log2(x)`.
fn fn_log10(l_input: i32) -> i32 {
    let scale: i16 = 9864; // 0.30103 = log10(2)
    let lw_in = fn_log2(l_input);
    mpy_32_16_1(lw_in, scale)
}

/// `con_Log10`: `log10` of `i_s32_val` read as Q`i_s16_q`, in Q25.
#[must_use]
pub fn con_log10(i_s32_val: i32, i_s16_q: i16) -> i32 {
    let s16_log10_2: i16 = 19728; // log10(2)~Q16

    if i_s32_val == 0 {
        return EVS_LW_MIN;
    }

    let mut s32_out = fn_log10(i_s32_val); // (2^26)*log10(a)

    let mut s32_correct = l_mult(sub(31, i_s16_q), s16_log10_2); // q = 17
    s32_correct = l_shl(s32_correct, 8); // q = 25
    s32_out = l_shr(s32_out, 1); // q = 25

    l_add(s32_out, s32_correct)
}

/// `Log10OfEnergy_x`: the energy of `s[0..len]` in dB/10 style Q8 (`-25600` for silence).
pub fn log10_of_energy_x(s: &[i16], enerlogval: &mut i32, len: i16) {
    let mut shfts: i16 = 0;
    let energy = spl_energy_x(s, len, &mut shfts); // Q:-shfts
    if energy > 0 {
        let log10_energy = con_log10(energy, negate(shfts)); // Q25
        let log10_len = con_log10(l_deposit_l(len), 0); // Q25
        let mut tmp2 = l_sub(log10_energy, log10_len); // Q25
        tmp2 = mpy_32_16_1(tmp2, 20480); // Q11->10   Q=25+11-15=21
        *enerlogval = l_shr(tmp2, 13); // Q8
    } else {
        *enerlogval = -25600;
    }
}

/// `concealment_update2_x`: update the zero crossing rate, the energy and its running mean from
/// a good frame's output.
pub fn concealment_update2_x(outx_new: &[i16], plc_info: &mut TPLCInfo, frame_size: i16) {
    plc_info.zp = zero_pass_w32_x(outx_new, frame_size);

    log10_of_energy_x(outx_new, &mut plc_info.ener, frame_size); // Q8
    if sub(plc_info.zp, 100) < 0 && l_sub(plc_info.ener, l_shl(50, 8)) > 0 {
        plc_info.ener_mean = l_add(
            mpy_32_16_1(plc_info.ener_mean, 32112), // 0.98 Q15
            mpy_32_16_1(plc_info.ener, 655),        // 0.02 Q15
        );
    }
}

/// `array_max_indx_fx`: the index of the first largest value of `s[0..n]`.
fn array_max_indx_fx(s: &[i16], n: i16) -> i16 {
    let mut indx: i16 = 0;
    for i in 0..n.max(0) {
        if sub(s[i as usize], s[indx as usize]) > 0 {
            indx = i;
        }
    }
    indx
}

/// `ffr_getSfWord16`: the headroom (0..15) of `x[0..len_x]`, 0 when it is all zero.
#[must_use]
pub fn ffr_get_sf_word16(x: &[i16], len_x: i16) -> i16 {
    let mut x_max: i16 = 0;
    let mut x_min: i16 = 0;
    for &value in &x[..len_x.max(0) as usize] {
        if value >= 0 {
            x_max = x_max.max(value);
        }
        if value < 0 {
            x_min = x_min.min(value);
        }
    }

    let mut i_max: i16 = 0x10;
    let mut i_min: i16 = 0x10;

    if x_max != 0 {
        i_max = norm_s(x_max);
    }

    if x_min != 0 {
        i_min = norm_s(x_min);
    }

    i_max.min(i_min) & 0xF
}

/// `OverlapAdd_fx`: cross-fade the 1.25-pitch cycle `pitch125_data` into `sbuf[n..]`; the new
/// write position `n + pitch` is returned.
fn overlap_add_fx(
    pitch125_data: &[i16],
    sbuf: &mut [i16],
    n: i16,
    pitch: i16,
    framesize: i16,
) -> i16 {
    let pitch125 = extract_l(l_shr(
        l_add(l_add(l_deposit_h(pitch), l_mult(pitch, 8192)), 32768),
        16,
    ));
    let mut loverlap = sub(pitch125, pitch);
    let framesize_sub_n = sub(framesize, n);

    let mut n1 = framesize_sub_n;
    let mut n2 = framesize_sub_n;
    if sub(loverlap, framesize_sub_n) < 0 {
        n1 = loverlap;
    }
    if sub(pitch125, framesize_sub_n) < 0 {
        n2 = pitch125;
    }
    let s16_max_coef_norm = sub(ffr_get_sf_word16(&sbuf[n as usize..], n1), 1);
    let s16_max_coef_norm2 = ffr_get_sf_word16(pitch125_data, n1);
    loverlap = loverlap.max(1);
    let mut s: i16 = 0;
    let tmp16 = basop_util_divide1616_scale(1, loverlap, &mut s);
    for i in 0..n1.max(0) {
        let dat = shl(sbuf[(n + i) as usize], s16_max_coef_norm);
        let tmp = extract_l(l_shl(l_mult0(i, tmp16), s)); // q15
        sbuf[(n + i) as usize] = round_word(l_add(
            l_shr(l_mult(dat, sub(32767, tmp)), s16_max_coef_norm),
            l_shr(
                l_mult(shl(pitch125_data[i as usize], s16_max_coef_norm2), tmp),
                s16_max_coef_norm2,
            ),
        ));
    }

    for i in n1.max(0)..n2.max(0) {
        sbuf[(n + i) as usize] = pitch125_data[i as usize];
    }

    add(n, pitch)
}

/// `add_noise`: add the noise-shaped (`1 - 0.68·z^-1`) `noise_seg[0..len]` to `sbuf`, with a gain
/// that drifts from `gain` towards `gain_n`; the last noise sample is kept in `outx_new_n1`.
fn add_noise(
    sbuf: &mut [i16],
    outx_new_n1: &mut i16,
    noise_seg: &[i16],
    len: i16,
    gain: &mut i16,
    gain_n: i16,
    first_frame: bool,
) {
    if !first_frame {
        let temp_out = sub(noise_seg[0], mult(*outx_new_n1, 22282)); // 0.68 Q15
        sbuf[0] = add(sbuf[0], mult(temp_out, *gain));
        *gain = mac_r(l_mult(32439, *gain), 328, gain_n); // 0.99, 0.01 Q15
    }

    let mut i: i16 = 1;
    while i < len {
        let temp_out = sub(
            noise_seg[i as usize],
            mult(noise_seg[(i - 1) as usize], 22282),
        );
        sbuf[i as usize] = add(sbuf[i as usize], mult(temp_out, *gain));
        *gain = mac_r(l_mult(32439, *gain), 328, gain_n);
        i += 1;
    }

    *outx_new_n1 = noise_seg[(i - 1) as usize]; // q0
}

/// `waveform_adj_fix`: waveform adjustment of the first lost frame. `pcm_out` holds the tonal
/// concealment's PCM history, in which `overlap_at` (the reference's `overlapbuf`) and
/// `outdata2_at` (the last good output) overlap; the pitch-extended last good signal is written
/// back to `overlapbuf` for the following lost frames. `outx_new` is replaced by the adjusted
/// frame and the new pitch returned (0 if the pitch is not usable).
pub fn waveform_adj_fix(
    pcm_out: &mut [i16],
    overlap_at: usize,
    outdata2_at: usize,
    outx_new: &mut [i16],
    data_noise: &mut [i16],
    outx_new_n1: &mut i16,
    nsapp_gain: &mut i16,
    nsapp_gain_n: &mut i16,
    framesize: i16,
    t_bfi: i8,
    voicing: i16,
    curr_mode: i16,
    pitch: i16,
) -> i16 {
    let mut pitch = pitch;
    let mut sbuf = [0i16; L_FRAME_MAX as usize];

    let framesizediv2 = shr(framesize, 1);
    let outdata2_len = framesize.max(0) as usize;
    let zp1 = zero_pass_w32_x(&pcm_out[outdata2_at..], framesizediv2);
    let zp2 = zero_pass_w32_x(
        &pcm_out[outdata2_at + framesizediv2.max(0) as usize..],
        framesizediv2,
    );

    // judge if the pitch is usable
    let mut tmp: i16 = 1;
    if sub(zp1, 1) > 0 {
        tmp = zp1;
    }
    if sub(shl(tmp, 2), zp2) < 0 {
        return 0;
    }

    // adjust the pitch value
    if t_bfi != 0
        && sub(pitch, framesizediv2) <= 0
        && sub(framesize, 256) > 0
        && sub(curr_mode, 1) == 0
    {
        let i1 = add(1, array_max_indx_fx(outx_new, pitch));
        let i2 = add(1, array_max_indx_fx(&outx_new[pitch as usize..], pitch));

        let pos1 = add(i2, sub(pitch, i1));
        let pos3 = add(pos1, mult(pos1, 8192)); // 0.25 Q15
        let pos2 = add(pitch, mult(pitch, 8192));

        if sub(pos1, pos2) < 0 && sub(pos3, pitch) > 0 && sub(pos1, framesizediv2) < 0 {
            pitch = add(i2, sub(pitch, i1));
        }
    }

    {
        let mut pitch125_data = [0i16; L_FRAME_MAX as usize];
        let outdata2 = &pcm_out[outdata2_at..];
        let pitch125 = extract_l(l_shr(
            l_add(l_add(l_deposit_h(pitch), l_mult(pitch, 8192)), 32768),
            16,
        ));
        let loverlap = sub(pitch125, pitch);
        for i in 0..pitch.max(0) as usize {
            pitch125_data[i] = outdata2[(framesize - pitch) as usize + i];
        }
        for i in 0..loverlap.max(0) as usize {
            pitch125_data[pitch as usize + i] = outx_new[i];
        }
        sbuf[..outdata2_len].copy_from_slice(&outx_new[..outdata2_len]);

        {
            // p_tmp = tmp_buf + 1
            let mut tmp_buf = [0i16; 2 * L_FRAME_MAX as usize];

            tmp_buf[1..=pitch125.max(0) as usize]
                .copy_from_slice(&pitch125_data[..pitch125.max(0) as usize]);

            tmp_buf[0] = outdata2[(framesize - pitch - 1) as usize];
            tmp_buf[pitch125 as usize + 1] = outx_new[loverlap as usize];
            let pitch125a1 = add(pitch125, 1);
            let s16_max_coef_norm = sub(ffr_get_sf_word16(&tmp_buf, pitch125a1), 1);
            for value in &mut tmp_buf[..pitch125a1.max(0) as usize] {
                *value = shl(*value, s16_max_coef_norm);
            }
            for i in 0..pitch125.max(0) as usize {
                pitch125_data[i] = round_word(l_shr(
                    l_add(
                        l_mult(tmp_buf[i + 1], 20972),
                        l_mac(l_mult(tmp_buf[i], 5898), tmp_buf[i + 2], 5898),
                    ),
                    s16_max_coef_norm,
                ));
            }
        }

        let mut n: i16 = 0;
        while sub(n, framesize) < 0 {
            // periodical extension
            n = overlap_add_fx(&pitch125_data, &mut sbuf, n, pitch, framesize);
        }

        // maximum pitch lag is 3/4 Framesize; pitch125_data is reused for temporary storage,
        // since outdata2 (holding the pcm data of the last good frame) is still needed and
        // overlapbuf overlaps outdata2
        let quarter = (framesize / 4) as usize;
        let three_quarters = ((3 * framesize) / 4) as usize;
        pitch125_data[..three_quarters].copy_from_slice(&sbuf[quarter..quarter + three_quarters]);

        *nsapp_gain = 0;
        *nsapp_gain_n = sub(32767, shr(voicing, 1)); // q15
                                                     // use last good signal for noise generation
        add_noise(
            &mut sbuf,
            outx_new_n1,
            outdata2,
            framesize,
            nsapp_gain,
            *nsapp_gain_n,
            true,
        );
        // save current (noisy) output from IMDCT
        data_noise[..outdata2_len].copy_from_slice(&outx_new[..outdata2_len]);
        // overlapbuf can now be filled with sbuf, needed for subsequently lost frames
        pcm_out[overlap_at + quarter..overlap_at + quarter + three_quarters]
            .copy_from_slice(&pitch125_data[..three_quarters]);
    }
    outx_new[..outdata2_len].copy_from_slice(&sbuf[..outdata2_len]);
    pitch
}

/// `waveform_adj2_fix`: smoothing of the 2nd to 4th lost frame (`bfi != 0`), or of the first good
/// frame after a loss, with the periodic extension of the last concealed frame in `overlapbuf`.
pub fn waveform_adj2_fix(
    overlapbuf: &mut [i16],
    outx_new: &mut [i16],
    data_noise: &mut [i16],
    outx_new_n1: &mut i16,
    nsapp_gain: &mut i16,
    nsapp_gain_n: &mut i16,
    recovery_gain: &mut i16,
    step_concealgain: i16,
    pitch: i16,
    framesize: i16,
    delay: i16,
    bfi_cnt: i16,
    bfi: i16,
) {
    let mut framesize = framesize;
    let mut sbuf = [0i16; L_FRAME_MAX as usize];

    let mut n: i16 = 0;
    let mut framesizesubn = sub(framesize, n);
    let framesizesubp = sub(framesize, pitch);
    if pitch > 0 {
        while framesizesubn > 0 {
            // periodical extension
            let tmp = vadmin(pitch, framesizesubn);
            for i in 0..tmp.max(0) {
                sbuf[(n + i) as usize] = overlapbuf[(framesizesubp + i) as usize];
            }
            n = add(n, pitch);
            framesizesubn = sub(framesize, n);
        }

        overlapbuf[..framesize.max(0) as usize].copy_from_slice(&sbuf[..framesize.max(0) as usize]);

        {
            // use last (noisy) output from IMDCT for noise generation
            add_noise(
                &mut sbuf,
                outx_new_n1,
                data_noise,
                framesize,
                nsapp_gain,
                *nsapp_gain_n,
                false,
            );

            // save current (noisy) output from IMDCT
            if bfi != 0 {
                data_noise[..framesize.max(0) as usize]
                    .copy_from_slice(&outx_new[..framesize.max(0) as usize]);
            }
        }
        if sub(bfi_cnt, 4) == 0 || bfi == 0 {
            let (tablescale, ptable): (i16, i16) = match framesize {
                160 => (8, 26214),  // (Word16)(32767*256/160.0+0.5); q7+15
                320 => (9, 26214),  // (Word16)(32767*256/320.0+0.5); q8+15
                512 => (10, 32767), // q9+15
                640 => (10, 26214), // (Word16)(32767*512/640.0+0.5); q9+15
                _ => (10, 17456),   // 960: (Word16)(32767*512/960.0); q9+15
            };
            if bfi == 0 {
                // overlap-and-add
                let mut gain_zero_start: i16 = 10000;

                if step_concealgain > 0 {
                    let mut s: i16 = 0;
                    gain_zero_start =
                        basop_util_divide1616_scale(*recovery_gain, step_concealgain, &mut s);
                    gain_zero_start = shl(gain_zero_start, sub(s, 14)); // q0
                    gain_zero_start = add(gain_zero_start, 1);
                }

                if delay > 0 {
                    framesize = sub(framesize, delay);
                }

                let s16_max_coef_norm = sub(ffr_get_sf_word16(&sbuf, framesize), 1);
                let s16_max_coef_norm2 = ffr_get_sf_word16(outx_new, framesize);
                let tmp16 = vadmin(gain_zero_start, framesize);
                for i in 0..tmp16.max(0) {
                    let ratio = extract_l(l_shr(l_mult(i, ptable), tablescale));
                    let dat = shl(sbuf[i as usize], s16_max_coef_norm);
                    let temp_out = mult(*recovery_gain, sub(32767, ratio));
                    outx_new[i as usize] = round_word(l_add(
                        l_shr(l_mult(temp_out, dat), s16_max_coef_norm - 1),
                        l_shr(
                            l_mult(shl(outx_new[i as usize], s16_max_coef_norm2), ratio),
                            s16_max_coef_norm2,
                        ),
                    ));
                    *recovery_gain = sub(*recovery_gain, shr_r(step_concealgain, 1));
                    // q14
                }
                for i in gain_zero_start.max(0)..framesize {
                    let ratio = extract_l(l_shr(l_mult(i, ptable), tablescale));
                    outx_new[i as usize] = round_word(l_shr(
                        l_mult(shl(outx_new[i as usize], s16_max_coef_norm2), ratio),
                        s16_max_coef_norm2,
                    ));
                }

                if *recovery_gain < 0 {
                    *recovery_gain = 0;
                }
            } else {
                // overlap-and-add
                let s16_max_coef_norm = sub(ffr_get_sf_word16(&sbuf, framesize), 1);
                let s16_max_coef_norm2 = ffr_get_sf_word16(outx_new, framesize);
                for i in 0..framesize.max(0) {
                    let dat = shl(sbuf[i as usize], s16_max_coef_norm);
                    let tmp = extract_l(l_shr(l_mult(i, ptable), tablescale));
                    outx_new[i as usize] = round_word(l_add(
                        l_shr(l_mult(dat, sub(32767, tmp)), s16_max_coef_norm),
                        l_shr(
                            l_mult(shl(outx_new[i as usize], s16_max_coef_norm2), tmp),
                            s16_max_coef_norm2,
                        ),
                    ));
                }
            }
        } else {
            outx_new[..framesize.max(0) as usize]
                .copy_from_slice(&sbuf[..framesize.max(0) as usize]);
        }
    }
}

/// `concealment_signal_tuning_fx`: apply the waveform adjustment to the IMDCT output `outx_new`
/// of a lost frame (`bfi`) or smooth the recovery after one. `pcm_out` is the tonal concealment's
/// PCM history with the offsets of `OverlapBuf` (second last output) and `outdata2` (last
/// output). `enable_plc_waveadjust`, `last_total_brate` and `last_codec_mode` are the
/// decoder state's fields of the same names.
pub fn concealment_signal_tuning_fx(
    bfi: i16,
    curr_mode: i16,
    outx_new: &mut [i16],
    plc_info: &mut TPLCInfo,
    nb_lost_cmpt: i16,
    pre_bfi: i16,
    pcm_out: &mut [i16],
    overlap_at: usize,
    past_core_mode: i16,
    outdata2_at: usize,
    enable_plc_waveadjust: i16,
    last_total_brate: i32,
    last_codec_mode: i16,
) {
    let frame_size = plc_info.frame_size;
    let pitch = plc_info.pitch;
    let mut voicing_fx: i16 = 0;
    if bfi != 0 {
        if enable_plc_waveadjust != 0 && plc_info.concealment_method == TCX_NONTONAL {
            if sub(nb_lost_cmpt, 1) == 0 {
                plc_info.pitch = pitch_search_fx(
                    &pcm_out[outdata2_at..],
                    outx_new,
                    frame_size,
                    &mut voicing_fx,
                    plc_info.zp,
                    plc_info.ener,
                    plc_info.ener_mean,
                    &plc_info.data_reci2,
                    curr_mode,
                );

                if plc_info.pitch != 0 {
                    // waveform adjustment for the first lost frame
                    plc_info.pitch = waveform_adj_fix(
                        pcm_out,
                        overlap_at,
                        outdata2_at,
                        outx_new,
                        &mut plc_info.data_noise,
                        &mut plc_info.outx_new_n1,
                        &mut plc_info.nsapp_gain,
                        &mut plc_info.nsapp_gain_n,
                        frame_size,
                        plc_info.t_bfi,
                        voicing_fx,
                        curr_mode,
                        plc_info.pitch,
                    );
                }
            } else if sub(nb_lost_cmpt, 5) < 0 {
                // waveform adjustment for the 2nd~4th lost frame
                waveform_adj2_fix(
                    &mut pcm_out[overlap_at..],
                    outx_new,
                    &mut plc_info.data_noise,
                    &mut plc_info.outx_new_n1,
                    &mut plc_info.nsapp_gain,
                    &mut plc_info.nsapp_gain_n,
                    &mut plc_info.recovery_gain,
                    plc_info.step_concealgain,
                    pitch,
                    frame_size,
                    0,
                    nb_lost_cmpt,
                    bfi,
                );
            }
        }
        plc_info.t_bfi = 1;
    } else if pre_bfi != 0
        && past_core_mode != 0
        && l_sub(last_total_brate, 48000) >= 0
        && sub(last_codec_mode, MODE2) == 0
    {
        if plc_info.concealment_method == TCX_NONTONAL && l_sub(plc_info.nb_lost_cmpt, 4) < 0 {
            // smoothing of the concealed signal with the good signal
            waveform_adj2_fix(
                &mut pcm_out[overlap_at..],
                outx_new,
                &mut plc_info.data_noise,
                &mut plc_info.outx_new_n1,
                &mut plc_info.nsapp_gain,
                &mut plc_info.nsapp_gain_n,
                &mut plc_info.recovery_gain,
                plc_info.step_concealgain,
                pitch,
                frame_size,
                0,
                add(extract_l(plc_info.nb_lost_cmpt), 1),
                bfi,
            );
        }
    } else {
        plc_info.t_bfi = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_div_s_x_rounds_and_rejects_a_zero_or_larger_divisor() {
        assert_eq!(int_div_s_x(100, 7), 14);
        assert_eq!(int_div_s_x(7, 100), 0);
        assert_eq!(int_div_s_x(5, 0), 0);
        assert_eq!(int_div_s_x(10, 10), 1);
    }

    #[test]
    fn sqrt_x_fast_follows_the_table_for_a_power_of_four() {
        // sqrt(2^20) = 2^10 at the table's scale
        let root = sqrt_x_fast(1 << 20);
        assert!(root > 0);
        assert_eq!(sqrt_x_fast(0), SQRT_TABLE_PITCH_SEARCH[0] >> 11);
    }

    #[test]
    fn set_state_shifts_the_history_and_appends() {
        let mut state = [1i16, 2, 3];
        set_state(&mut state, 9, 3);
        assert_eq!(state, [2, 3, 9]);
    }

    #[test]
    fn con_log10_of_zero_is_the_minimum() {
        assert_eq!(con_log10(0, 0), EVS_LW_MIN);
        // log10(2^30) = 9.03 in Q25, to the accuracy of the quadratic log2
        let value = con_log10(1 << 30, 0);
        assert!((value >> 25) == 9);
    }

    #[test]
    fn ffr_get_sf_word16_is_the_headroom_of_the_largest_value() {
        assert_eq!(ffr_get_sf_word16(&[0, 0, 0], 3), 0);
        assert_eq!(ffr_get_sf_word16(&[1, -1], 2), 14);
        assert_eq!(ffr_get_sf_word16(&[16384, -2], 2), 0);
    }

    #[test]
    fn concealment_init_x_sets_every_field_the_reference_sets() {
        let mut plc_info = TPLCInfo::zeroed();
        plc_info.pitch = 7;
        plc_info.t_bfi = 1;
        plc_info.outx_new_n1 = -3;
        plc_info.nsapp_gain = 5;
        plc_info.nsapp_gain_n = 6;
        plc_info.ener = 99;
        plc_info.recovery_gain = 4;
        plc_info.step_concealgain = 8;
        plc_info.concealment_method = 1;
        plc_info.subframe = 2;
        plc_info.nb_lost_cmpt = 12;
        plc_info.tcx_tonality.fill(5);
        plc_info.transient.fill(0);
        plc_info.data_reci2.fill(-1);
        plc_info.data_noise.fill(3);
        plc_info.data_reci2_scale = 9;

        concealment_init_x(640, &mut plc_info);

        assert_eq!(plc_info.frame_size, 640);
        assert_eq!(plc_info.zp, 640);
        assert_eq!(plc_info.pitch, 0);
        assert_eq!(plc_info.t_bfi, 0);
        assert_eq!(plc_info.outx_new_n1, 0);
        assert_eq!(plc_info.nsapp_gain, 0);
        assert_eq!(plc_info.nsapp_gain_n, 0);
        assert_eq!(plc_info.ener_mean, 15213);
        assert_eq!(plc_info.ener, 0);
        assert_eq!(plc_info.recovery_gain, 0);
        assert_eq!(plc_info.step_concealgain, 0);
        assert_eq!(plc_info.concealment_method, TCX_NONTONAL);
        assert_eq!(plc_info.subframe, 0);
        assert_eq!(plc_info.nb_lost_cmpt, 0);
        assert_eq!(plc_info.seed, 21845);
        assert_eq!(plc_info.tcx_tonality, [1, 1, 1, 1, 1, 1, 1, 0, 0, 0]);
        assert_eq!(plc_info.transient, [1, 1, 1]);
        assert!(plc_info.data_reci2.iter().all(|&v| v == 0));
        // untouched by the reference
        assert!(plc_info.data_noise.iter().all(|&v| v == 3));
        assert_eq!(plc_info.data_reci2_scale, 9);
    }
}
