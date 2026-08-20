//! AMR-NB ENCODER weighted-speech + open-loop-pitch tier — 3GPP TS 26.073 `pre_big.c`
//! (`Pre_Big`), `ol_ltp.c` (`ol_ltp`), `pitch_ol.c` (`Pitch_ol`, `Lag_max`), `p_ol_wgh.c`
//! (`Pitch_ol_wgh`, `Lag_max`), `calc_cor.c` (`comp_corr`) and `gmed_n.c` (`gmed_n`). Ported
//! bit-exact against the fixed-point reference.
//!
//! The perceptual weighting filter turns the whole 20 ms speech frame into weighted speech
//! `wsp[L_FRAME]`; the open-loop pitch analysis then finds the pitch lag(s) `T_op[2]` used to seed
//! the closed-loop pitch search (a later tier). DTX / VAD (`if (st->dtx)`) branches are omitted —
//! the NODTX reference never selects them, so `dtx = 0` everywhere and `vad_pitch_detection`,
//! `vad_tone_detection*`, `hp_max`, and the complex-background detector are never called.

use crate::amr::basic_ops::{
    extract_h, extract_l, l_mac, l_msu, l_shl, l_shr, mult, round_word, shl, shr, sub,
};
use crate::amr::nb::constants::{
    L_FRAME, L_FRAME_BY2, L_SUBFR, M, MP1, PIT_MAX, PIT_MIN as PIT_MIN_VALUE,
    PIT_MIN_MR122 as PIT_MIN_MR122_VALUE,
};
use crate::amr::nb::filters::{residu, syn_filt, weight_ai};
use crate::amr::nb::math_nb::inv_sqrt;
use crate::amr::oper_32b::{l_extract, mpy_32, mpy_32_16};
use crate::amr::AmrNbMode;

/// `gamma1[M]` — spectral expansion factor 1 (`cod_amr.c`), used by the weighting filter numerator
/// `A(z/gamma1)` for MR475..MR795.
pub(crate) const GAMMA1: [i16; M] = [
    30802, 28954, 27217, 25584, 24049, 22606, 21250, 19975, 18777, 17650,
];

/// `gamma1_12k2[M]` — spectral expansion factor 1 for EFR (`cod_amr.c`), used by the weighting
/// filter numerator for MR102 and MR122 (i.e. `mode > MR795`).
pub(crate) const GAMMA1_12K2: [i16; M] = [
    29491, 26542, 23888, 21499, 19349, 17414, 15672, 14105, 12694, 11425,
];

/// `gamma2[M]` — spectral expansion factor 2 (`cod_amr.c`), the weighting filter denominator
/// `A(z/gamma2)` for all modes.
pub(crate) const GAMMA2: [i16; M] = [19661, 11797, 7078, 4247, 2548, 1529, 917, 550, 330, 198];

/// `corrweight[251]` (`corrwght.tab`) — the correlation-weighting window for `Pitch_ol_wgh`.
const CORRWEIGHT: [i16; 251] = [
    20473, 20506, 20539, 20572, 20605, 20644, 20677, 20716, 20749, 20788, 20821, 20860, 20893,
    20932, 20972, 21011, 21050, 21089, 21129, 21168, 21207, 21247, 21286, 21332, 21371, 21417,
    21456, 21502, 21542, 21588, 21633, 21679, 21725, 21771, 21817, 21863, 21909, 21961, 22007,
    22059, 22105, 22158, 22210, 22263, 22315, 22367, 22420, 22472, 22531, 22584, 22643, 22702,
    22761, 22820, 22879, 22938, 23003, 23062, 23128, 23193, 23252, 23324, 23390, 23455, 23527,
    23600, 23665, 23744, 23816, 23888, 23967, 24045, 24124, 24202, 24288, 24366, 24451, 24537,
    24628, 24714, 24805, 24904, 24995, 25094, 25192, 25297, 25395, 25500, 25611, 25723, 25834,
    25952, 26070, 26188, 26313, 26444, 26575, 26706, 26844, 26988, 27132, 27283, 27440, 27597,
    27761, 27931, 28108, 28285, 28475, 28665, 28869, 29078, 29295, 29524, 29760, 30002, 30258,
    30527, 30808, 31457, 32767, 32767, 32767, 32767, 32767, 32767, 32767, 31457, 30808, 30527,
    30258, 30002, 29760, 29524, 29295, 29078, 28869, 28665, 28475, 28285, 28108, 27931, 27761,
    27597, 27440, 27283, 27132, 26988, 26844, 26706, 26575, 26444, 26313, 26188, 26070, 25952,
    25834, 25723, 25611, 25500, 25395, 25297, 25192, 25094, 24995, 24904, 24805, 24714, 24628,
    24537, 24451, 24366, 24288, 24202, 24124, 24045, 23967, 23888, 23816, 23744, 23665, 23600,
    23527, 23455, 23390, 23324, 23252, 23193, 23128, 23062, 23003, 22938, 22879, 22820, 22761,
    22702, 22643, 22584, 22531, 22472, 22420, 22367, 22315, 22263, 22210, 22158, 22105, 22059,
    22007, 21961, 21909, 21863, 21817, 21771, 21725, 21679, 21633, 21588, 21542, 21502, 21456,
    21417, 21371, 21332, 21286, 21247, 21207, 21168, 21129, 21089, 21050, 21011, 20972, 20932,
    20893, 20860, 20821, 20788, 20749, 20716, 20677, 20644, 20605, 20572, 20539, 20506, 20473,
    20434, 20401, 20369, 20336,
];

/// `THRESHOLD` (`pitch_ol.c`): 0.85 in Q15, favouring lower lag ranges.
const THRESHOLD: i16 = 27853;

/// Open-loop weighted-pitch search state (`p_ol_wgh.h` `pitchOLWghtState`). Only used by MR102, but
/// held unconditionally so the state layout matches `pitchOLWghtSt`.
#[derive(Debug, Clone)]
pub struct PitchOlWghtState {
    /// `old_T0_med` — median of past lags (reset seed 40).
    old_t0_med: i16,
    /// `ada_w` — adaptive weighting factor, Q15.
    ada_w: i16,
    /// `wght_flg` — whether the neighbourhood weighting is applied.
    wght_flg: i16,
}

impl Default for PitchOlWghtState {
    fn default() -> Self {
        Self::new()
    }
}

impl PitchOlWghtState {
    /// `p_ol_wgh_reset`: `old_T0_med = 40`, `ada_w = 0`, `wght_flg = 0`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            old_t0_med: 40,
            ada_w: 0,
            wght_flg: 0,
        }
    }
}

/// N-point median (`gmed_n.c` `gmed_n`) — returns the value of the median element. Valid for odd
/// `n <= 9`. Ties break toward the earlier index (`>=` in the max scan), exactly as the reference.
fn gmed_n(ind: &[i16], n: usize) -> i16 {
    const NMAX: usize = 9;
    let mut tmp2 = [0i16; NMAX];
    let mut tmp = [0usize; NMAX];
    tmp2[..n].copy_from_slice(&ind[..n]);

    for slot in tmp.iter_mut().take(n) {
        let mut max = -32767i16;
        let mut ix = 0usize;
        for (j, &v) in tmp2.iter().enumerate().take(n) {
            if sub(v, max) >= 0 {
                max = v;
                ix = j;
            }
        }
        tmp2[ix] = -32768;
        *slot = ix;
    }

    let median_index = tmp[n >> 1];
    ind[median_index]
}

/// Compute all correlations `<scal_sig[n], scal_sig[n-t]>` for `t = lag_min..=lag_max`
/// (`calc_cor.c` `comp_corr`). `scal_sig` is a slice whose logical index 0 is `base`; the negative
/// offsets `base - i` must be in range. `corr` is written at flat index `PIT_MAX - i` (mirroring the
/// reference `corr[-i]` where `corr` points at `&corr[pit_max]`).
fn comp_corr(
    scal_sig: &[i16],
    base: usize,
    l_frame: usize,
    lag_max: i16,
    lag_min: i16,
    corr: &mut [i32],
) {
    let mut i = lag_max;
    while i >= lag_min {
        let mut t0 = 0i32;
        for j in 0..l_frame {
            t0 = l_mac(t0, scal_sig[base + j], scal_sig[base + j - i as usize]);
        }
        corr[(PIT_MAX - i) as usize] = t0;
        i -= 1;
    }
}

/// `pitch_ol.c` `Lag_max` (non-VAD2 path, `dtx = 0`). Finds the lag of maximum normalized
/// correlation in `[lag_min, lag_max]`, writing the normalized correlation to `cor_max` and
/// returning the lag. `corr` is indexed as in [`comp_corr`] (`corr[PIT_MAX - i]`); `scal_sig`/`base`
/// index the scaled signal so `scal_sig[base - p_max + i]` is read.
#[allow(clippy::too_many_arguments)]
fn lag_max_pitch_ol(
    corr: &[i32],
    scal_sig: &[i16],
    base: usize,
    scal_fac: i16,
    scal_flag: bool,
    l_frame: usize,
    lag_max: i16,
    lag_min: i16,
    cor_max: &mut i16,
) -> i16 {
    let mut max = i32::MIN;
    let mut p_max = lag_max;

    let mut i = lag_max;
    while i >= lag_min {
        if corr[(PIT_MAX - i) as usize] >= max {
            max = corr[(PIT_MAX - i) as usize];
            p_max = i;
        }
        i -= 1;
    }

    // compute energy of scal_sig[-p_max ..]
    let mut t0 = 0i32;
    let start = base - p_max as usize;
    for k in 0..l_frame {
        t0 = l_mac(t0, scal_sig[start + k], scal_sig[start + k]);
    }

    // 1/sqrt(energy)
    let mut t0 = inv_sqrt(t0);

    if scal_flag {
        t0 = l_shl(t0, 1);
    }

    // max = max / sqrt(energy)
    let (max_h, max_l) = l_extract(max);
    let (ener_h, ener_l) = l_extract(t0);
    let mut t0 = mpy_32(max_h, max_l, ener_h, ener_l);

    if scal_flag {
        t0 = l_shr(t0, scal_fac);
        *cor_max = extract_h(l_shl(t0, 15)); // divide by 2
    } else {
        *cor_max = extract_l(t0);
    }

    p_max
}

/// `pitch_ol.c` `Pitch_ol` — open-loop pitch on the weighted speech. `signal`/`base` index the
/// weighted speech so `signal[base - pit_max .. base + l_frame - 1]` is valid. `is_mr122` selects
/// the EFR-compatible scaling in `Lag_max`.
fn pitch_ol(
    signal: &[i16],
    base: usize,
    pit_min: i16,
    pit_max: i16,
    l_frame: usize,
    is_mr122: bool,
) -> i16 {
    // energy over signal[-pit_max .. l_frame-1]
    let mut t0 = 0i32;
    let lo = base - pit_max as usize;
    let hi = base + l_frame; // exclusive
    for &s in &signal[lo..hi] {
        t0 = l_mac(t0, s, s);
    }

    // Scaling of the input signal, mirroring the reference. scaled_signal has PIT_MAX history
    // slots followed by l_frame samples; scal_sig points at &scaled_signal[pit_max].
    let mut scaled = [0i16; PIT_MAX as usize + L_FRAME];
    let sbase = pit_max as usize;
    let scal_fac: i16 = if t0 == i32::MAX {
        for (idx, k) in (lo..hi).enumerate() {
            scaled[idx] = shr(signal[k], 3);
        }
        3
    } else if t0 < 1_048_576 {
        for (idx, k) in (lo..hi).enumerate() {
            scaled[idx] = shl(signal[k], 3);
        }
        -3
    } else {
        for (idx, k) in (lo..hi).enumerate() {
            scaled[idx] = signal[k];
        }
        0
    };

    // correlations over the scaled signal
    let mut corr = [0i32; PIT_MAX as usize + 1];
    comp_corr(&scaled, sbase, l_frame, pit_max, pit_min, &mut corr);

    // mode-dependent scaling in Lag_max
    let scal_flag = is_mr122;

    let mut max1 = 0i16;
    let mut max2 = 0i16;
    let mut max3 = 0i16;

    // First section: pit_max downto 4*pit_min
    let j = shl(pit_min, 2);
    let mut p_max1 = lag_max_pitch_ol(
        &corr, &scaled, sbase, scal_fac, scal_flag, l_frame, pit_max, j, &mut max1,
    );

    // Second section: 4*pit_min-1 downto 2*pit_min
    let i = sub(j, 1);
    let j = shl(pit_min, 1);
    let p_max2 = lag_max_pitch_ol(
        &corr, &scaled, sbase, scal_fac, scal_flag, l_frame, i, j, &mut max2,
    );

    // Third section: 2*pit_min-1 downto pit_min
    let i = sub(j, 1);
    let p_max3 = lag_max_pitch_ol(
        &corr, &scaled, sbase, scal_fac, scal_flag, l_frame, i, pit_min, &mut max3,
    );

    // Compare the 3 sections' maxima, favouring small lag.
    if sub(mult(max1, THRESHOLD), max2) < 0 {
        max1 = max2;
        p_max1 = p_max2;
    }
    if sub(mult(max1, THRESHOLD), max3) < 0 {
        p_max1 = p_max3;
    }

    p_max1
}

/// `p_ol_wgh.c` `Lag_max` — weighted open-loop `Lag_max` (used only by MR102). Returns the lag and
/// sets the open-loop gain flag. `corr`/`scal_sig`/`base` are indexed as in [`pitch_ol`].
#[allow(clippy::too_many_arguments)]
fn lag_max_wgh(
    corr: &[i32],
    scal_sig: &[i16],
    base: usize,
    l_frame: usize,
    lag_max: i16,
    lag_min: i16,
    old_lag: i16,
    wght_flg: i16,
    gain_flg: &mut i16,
) -> i16 {
    // ww = &corrweight[250]; we = &corrweight[123 + lag_max - old_lag]
    let mut ww_idx: i32 = 250;
    let mut we_idx: i32 = 123 + lag_max as i32 - old_lag as i32;

    let mut max = i32::MIN;
    let mut p_max = lag_max;

    let mut i = lag_max;
    while i >= lag_min {
        // Weighting of the correlation function.
        let (t0_h, t0_l) = l_extract(corr[(PIT_MAX - i) as usize]);
        let mut t0 = mpy_32_16(t0_h, t0_l, CORRWEIGHT[ww_idx as usize]);
        ww_idx -= 1;
        if wght_flg > 0 {
            let (t0_h, t0_l) = l_extract(t0);
            t0 = mpy_32_16(t0_h, t0_l, CORRWEIGHT[we_idx as usize]);
            we_idx -= 1;
        }
        if t0 >= max {
            max = t0;
            p_max = i;
        }
        i -= 1;
    }

    // t0 = <s, s[-p_max]>, t1 = <s[-p_max], s[-p_max]>
    let mut t0 = 0i32;
    let mut t1 = 0i32;
    let p1 = base - p_max as usize;
    for k in 0..l_frame {
        t0 = l_mac(t0, scal_sig[base + k], scal_sig[p1 + k]);
        t1 = l_mac(t1, scal_sig[p1 + k], scal_sig[p1 + k]);
    }

    // gain flag: is t0/t1 > 0.4 ?
    *gain_flg = round_word(l_msu(t0, round_word(t1), 13107));

    p_max
}

/// `p_ol_wgh.c` `Pitch_ol_wgh` — open-loop pitch search with weighting (MR102 only). `signal`/`base`
/// index the weighted speech; `old_lags`/`ol_gain_flg` carry cross-subframe state.
#[allow(clippy::too_many_arguments)]
fn pitch_ol_wgh(
    st: &mut PitchOlWghtState,
    signal: &[i16],
    base: usize,
    pit_min: i16,
    pit_max: i16,
    l_frame: usize,
    old_lags: &mut [i16; 5],
    ol_gain_flg: &mut [i16; 2],
    idx: usize,
) -> i16 {
    // energy over signal[-pit_max .. l_frame-1]
    let mut t0 = 0i32;
    let lo = base - pit_max as usize;
    let hi = base + l_frame;
    for &s in &signal[lo..hi] {
        t0 = l_mac(t0, s, s);
    }

    let mut scaled = [0i16; PIT_MAX as usize + L_FRAME];
    let sbase = pit_max as usize;
    if t0 == i32::MAX {
        for (i, k) in (lo..hi).enumerate() {
            scaled[i] = shr(signal[k], 3);
        }
    } else if t0 < 1_048_576 {
        for (i, k) in (lo..hi).enumerate() {
            scaled[i] = shl(signal[k], 3);
        }
    } else {
        for (i, k) in (lo..hi).enumerate() {
            scaled[i] = signal[k];
        }
    }

    let mut corr = [0i32; PIT_MAX as usize + 1];
    comp_corr(&scaled, sbase, l_frame, pit_max, pit_min, &mut corr);

    let p_max1 = lag_max_wgh(
        &corr,
        &scaled,
        sbase,
        l_frame,
        pit_max,
        pit_min,
        st.old_t0_med,
        st.wght_flg,
        &mut ol_gain_flg[idx],
    );

    if ol_gain_flg[idx] > 0 {
        // Shift the 5-lag buffer and store the new lag; median of the 5.
        for i in (1..=4).rev() {
            old_lags[i] = old_lags[i - 1];
        }
        old_lags[0] = p_max1;
        st.old_t0_med = gmed_n(old_lags, 5);
        st.ada_w = 32767; // Q15 = 1.0
    } else {
        st.old_t0_med = p_max1;
        st.ada_w = mult(st.ada_w, 29491); // ada_w *= 0.9
    }

    if sub(st.ada_w, 9830) < 0 {
        st.wght_flg = 0;
    } else {
        st.wght_flg = 1;
    }

    p_max1
}

/// `pre_big.c` `Pre_Big` — perceptual weighting of the "big" subframe (2 subframes). Fills
/// `wsp[frame_offset .. frame_offset + 2*L_SUBFR]` from `speech`/`speech_base` (whose `M` history
/// samples before the current sample must be valid). `a_t`/`az_off` index the unquantized
/// interpolated LP filters; `mem_w` is the synthesis-filter memory carried across subframes.
#[allow(clippy::too_many_arguments)]
fn pre_big(
    mode: AmrNbMode,
    a_t: &[i16],
    frame_offset: usize,
    speech: &[i16],
    speech_base: usize,
    mem_w: &mut [i16],
    wsp: &mut [i16],
) {
    // g1 = gamma1 (mode <= MR795) else gamma1_12k2.
    let g1: &[i16] = if (mode as usize) <= (AmrNbMode::Mr795 as usize) {
        &GAMMA1
    } else {
        &GAMMA1_12K2
    };

    // aOffset = 2*MP1 if frameOffset > 0 else 0.
    let mut a_offset = if frame_offset > 0 { 2 * MP1 } else { 0 };
    let mut frame_off = frame_offset;

    let mut ap1 = [0i16; MP1];
    let mut ap2 = [0i16; MP1];

    for _ in 0..2 {
        weight_ai(&a_t[a_offset..a_offset + MP1], g1, &mut ap1);
        weight_ai(&a_t[a_offset..a_offset + MP1], &GAMMA2, &mut ap2);

        // Residu(Ap1, &speech[frameOffset], &wsp[frameOffset], L_SUBFR)
        // residu(a, x, base, y, lg) reads x[base - j]; here x = speech, base = speech_base+frame_off.
        let mut res = [0i16; L_SUBFR];
        residu(&ap1, speech, speech_base + frame_off, &mut res, L_SUBFR);
        wsp[frame_off..frame_off + L_SUBFR].copy_from_slice(&res);

        // Syn_filt(Ap2, &wsp[frameOffset], &wsp[frameOffset], L_SUBFR, mem_w, 1). syn_filt reads x
        // and writes y into disjoint buffers, so snapshot the input window into src first.
        let mut src = [0i16; L_SUBFR];
        src.copy_from_slice(&wsp[frame_off..frame_off + L_SUBFR]);
        let mut out = [0i16; L_SUBFR];
        syn_filt(&ap2, &src, &mut out, L_SUBFR, mem_w, true);
        wsp[frame_off..frame_off + L_SUBFR].copy_from_slice(&out);

        a_offset += MP1;
        frame_off += L_SUBFR;
    }
}

/// `ol_ltp.c` `ol_ltp` dispatch for one call (two subframes, or one 160-sample frame for
/// MR475/MR515). `wsp`/`wsp_base` index the weighted speech (with `PIT_MAX` history before
/// `wsp_base`). Returns the open-loop pitch lag; also maintains `ol_gain_flg`, `old_lags`, and the
/// weighted-pitch state for MR102.
#[allow(clippy::too_many_arguments)]
fn ol_ltp(
    st: &mut PitchOlWghtState,
    mode: AmrNbMode,
    wsp: &[i16],
    wsp_base: usize,
    old_lags: &mut [i16; 5],
    ol_gain_flg: &mut [i16; 2],
    idx: usize,
    l_frame: usize,
) -> i16 {
    // ol_gain_flg reset for all modes except MR102.
    if mode != AmrNbMode::Mr1020 {
        ol_gain_flg[0] = 0;
        ol_gain_flg[1] = 0;
    }

    // ol_ltp.c dispatch: MR475/MR515 (whole 160-sample frame) and every mode <= MR795 use the plain
    // Pitch_ol with PIT_MIN and non-EFR scaling; the reference splits MR475/515 out only to pass a
    // different L_frame, which the caller has already resolved into `l_frame` here — so both collapse
    // to the same call.
    let mode_i = mode as usize;
    if mode_i <= (AmrNbMode::Mr795 as usize) {
        pitch_ol(wsp, wsp_base, PIT_MIN_VALUE, PIT_MAX, l_frame, false)
    } else if mode == AmrNbMode::Mr1020 {
        pitch_ol_wgh(
            st,
            wsp,
            wsp_base,
            PIT_MIN_VALUE,
            PIT_MAX,
            l_frame,
            old_lags,
            ol_gain_flg,
            idx,
        )
    } else {
        // MR122: PIT_MIN_MR122, EFR-compatible scaling.
        pitch_ol(wsp, wsp_base, PIT_MIN_MR122_VALUE, PIT_MAX, l_frame, true)
    }
}

/// Compute weighted speech `wsp[L_FRAME]` and the open-loop pitch `T_op[2]` for one frame
/// (`cod_amr.c` lines ~443-502). `speech`/`speech_base` index the input speech with `M` history
/// samples valid before `speech_base`; `a_t` is the unquantized interpolated LP for the 4 subframes
/// (`AZ_SIZE`); `wsp`/`wsp_base` is the weighted-speech buffer with `PIT_MAX` history before
/// `wsp_base` (i.e. `wsp[wsp_base ..]` receives the frame's L_FRAME samples). `mem_w` is the
/// weighting-filter memory; `old_lags`/`ol_gain_flg`/`st` carry OL-pitch state.
///
/// This mirrors the subframe loop that runs `pre_big` twice (each 2 subframes), and the mode-split
/// `ol_ltp` calls: two 80-sample searches (non-MR475/515) or one 160-sample search (MR475/515,
/// with `T_op[1] = T_op[0]`).
#[allow(clippy::too_many_arguments)]
pub fn weighted_speech_and_ol_pitch(
    st: &mut PitchOlWghtState,
    mode: AmrNbMode,
    a_t: &[i16],
    speech: &[i16],
    speech_base: usize,
    mem_w: &mut [i16],
    wsp: &mut [i16],
    wsp_base: usize,
    old_lags: &mut [i16; 5],
    ol_gain_flg: &mut [i16; 2],
    t_op: &mut [i16; 2],
) {
    // Subframe loop: pre_big on each "big" subframe (always, both subframes), ol_ltp per pair
    // (non-MR475/515). `subfr_nr` drives the frame offset and the ol_ltp index too, not just `t_op`,
    // so an enumerate-over-t_op would obscure the reference structure.
    #[allow(clippy::needless_range_loop)]
    for subfr_nr in 0..2 {
        let i_subfr = subfr_nr * L_FRAME_BY2;
        pre_big(
            mode,
            a_t,
            i_subfr,
            speech,
            speech_base,
            mem_w,
            &mut wsp[wsp_base..],
        );

        if mode != AmrNbMode::Mr475 && mode != AmrNbMode::Mr515 {
            t_op[subfr_nr] = ol_ltp(
                st,
                mode,
                wsp,
                wsp_base + i_subfr,
                old_lags,
                ol_gain_flg,
                subfr_nr,
                L_FRAME_BY2,
            );
        }
    }

    if mode == AmrNbMode::Mr475 || mode == AmrNbMode::Mr515 {
        // One 160-sample search on the whole frame; idx = 1 in the reference.
        t_op[0] = ol_ltp(st, mode, wsp, wsp_base, old_lags, ol_gain_flg, 1, L_FRAME);
        t_op[1] = t_op[0];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gmed_n_five_point_median_of_constant_is_that_value() {
        assert_eq!(gmed_n(&[40, 40, 40, 40, 40], 5), 40);
    }

    #[test]
    fn gmed_n_five_point_median_picks_middle() {
        // Sorted: 10,20,30,40,50 -> median 30.
        assert_eq!(gmed_n(&[30, 10, 50, 20, 40], 5), 30);
    }

    #[test]
    fn pitch_ol_wght_state_reset_seed() {
        let st = PitchOlWghtState::new();
        assert_eq!(st.old_t0_med, 40);
        assert_eq!(st.ada_w, 0);
        assert_eq!(st.wght_flg, 0);
    }

    /// Full-frame oracle gate (run locally against the instrumented reference dump). Reads the
    /// per-frame `wsp[160]` + `T_op[2]` dump produced by the scratch C oracle and asserts every value
    /// matches over all 285 frames of T01.INP. Skips when the dump is absent (the oracle can't be
    /// committed — it is generated), so this is a developer-run proof, not a CI gate; the committed
    /// regression below pins the first-frame values instead.
    fn run_oracle_gate(mode: AmrNbMode, dump_rel: &str) -> Option<usize> {
        use crate::amr::nb::enc_main::EncoderState;

        let mut inp = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        inp.push("../../reference/amr-nb/testv/NODTX/T_INP/T01.INP");
        let dump = std::path::PathBuf::from(dump_rel);

        let (Some(pcm_bytes), Some(dump_text)) = (
            std::fs::read(&inp).ok(),
            std::fs::read_to_string(&dump).ok(),
        ) else {
            eprintln!("oracle dump / input absent — skipping full gate for {mode:?}");
            return None;
        };

        let pcm: Vec<i16> = pcm_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();

        // Parse the dump into (t_op[2], wsp[160]) per frame.
        let mut frames: Vec<([i16; 2], Vec<i16>)> = Vec::new();
        let mut lines = dump_text.lines();
        while let Some(header) = lines.next() {
            let mut it = header.split_whitespace();
            assert_eq!(it.next(), Some("FRAME"), "bad oracle header: {header}");
            let t0: i16 = it.next().unwrap().parse().unwrap();
            let t1: i16 = it.next().unwrap().parse().unwrap();
            let mut w = Vec::with_capacity(L_FRAME);
            for _ in 0..L_FRAME {
                w.push(lines.next().unwrap().trim().parse::<i16>().unwrap());
            }
            frames.push(([t0, t1], w));
        }

        let n_frames = pcm.len() / L_FRAME;
        assert_eq!(frames.len(), n_frames, "oracle frame count mismatch");

        let mut st = EncoderState::new();
        let mut prm = [0i16; 5];
        for (f, (want_top, want_wsp)) in frames.iter().enumerate() {
            let mut wsp = [0i16; L_FRAME];
            let mut t_op = [0i16; 2];
            st.analyze_frame(
                mode,
                &pcm[f * L_FRAME..(f + 1) * L_FRAME],
                &mut prm,
                &mut wsp,
                &mut t_op,
            );
            assert_eq!(&t_op, want_top, "T_op mismatch at frame {f} ({mode:?})");
            for (i, (&got, &want)) in wsp.iter().zip(want_wsp.iter()).enumerate() {
                assert_eq!(got, want, "wsp[{i}] mismatch at frame {f} ({mode:?})");
            }
        }
        Some(n_frames)
    }

    /// Committed regression: drive the real encoder over the first 11 frames of the reference input
    /// and pin frame 10's open-loop pitch and a spread of weighted-speech samples to the values the
    /// instrumented C reference produced (`wsp_top_mr*.txt`, oracle-verified above). The reference
    /// vectors are gitignored, so this skips gracefully when absent (matching the tier-1 LSF gate),
    /// but wherever the vectors exist it fails loudly on any drift in `pre_big`/`ol_ltp` — the two
    /// values the oracle proved bit-exact but that carry no transmitted parameter of their own.
    ///
    /// Frame 10 is chosen deliberately: it is well past the all-zero homing frame, so its `wsp[]` has
    /// real energy and its `T_op` is a genuine pitch estimate (141), exercising the correlation +
    /// normalization + section-compare path rather than the zero-signal degenerate case.
    #[allow(clippy::type_complexity)]
    fn frame10_regression(
        mode: AmrNbMode,
        want_top: [i16; 2],
        want_samples: &[(usize, i16)],
        want_sum: i64,
        want_sumsq: i64,
    ) {
        use crate::amr::nb::enc_main::EncoderState;

        let mut inp = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        inp.push("../../reference/amr-nb/testv/NODTX/T_INP/T01.INP");
        let Some(bytes) = std::fs::read(&inp).ok() else {
            eprintln!("AMR-NB reference input absent — skipping frame-10 regression for {mode:?}");
            return;
        };
        let pcm: Vec<i16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert!(
            pcm.len() >= 11 * L_FRAME,
            "need at least 11 frames of input"
        );

        let mut st = EncoderState::new();
        let mut prm = [0i16; 5];
        let mut wsp = [0i16; L_FRAME];
        let mut t_op = [0i16; 2];
        for f in 0..11 {
            st.analyze_frame(
                mode,
                &pcm[f * L_FRAME..(f + 1) * L_FRAME],
                &mut prm,
                &mut wsp,
                &mut t_op,
            );
        }
        // wsp / t_op now hold frame 10.
        assert_eq!(t_op, want_top, "frame-10 T_op drift ({mode:?})");
        for &(i, want) in want_samples {
            assert_eq!(wsp[i], want, "frame-10 wsp[{i}] drift ({mode:?})");
        }
        let sum: i64 = wsp.iter().map(|&v| i64::from(v)).sum();
        let sumsq: i64 = wsp.iter().map(|&v| i64::from(v) * i64::from(v)).sum();
        assert_eq!(sum, want_sum, "frame-10 wsp sum drift ({mode:?})");
        assert_eq!(sumsq, want_sumsq, "frame-10 wsp sumsq drift ({mode:?})");
    }

    #[test]
    fn mr122_frame10_matches_reference() {
        frame10_regression(
            AmrNbMode::Mr1220,
            [141, 141],
            &[
                (0, -488),
                (10, 2081),
                (40, -493),
                (79, 59),
                (80, 166),
                (120, -264),
                (159, 283),
            ],
            14512,
            888_515_028,
        );
    }

    #[test]
    fn mr475_frame10_matches_reference() {
        frame10_regression(
            AmrNbMode::Mr475,
            [141, 141],
            &[
                (0, -338),
                (10, 2547),
                (40, -505),
                (79, 110),
                (80, 139),
                (120, -222),
                (159, -45),
            ],
            13815,
            851_325_563,
        );
    }

    /// Silence in, silence out: an all-zero frame produces all-zero weighted speech (the residual +
    /// synthesis of a zero signal through zero-memory filters is zero). Self-contained (no vectors),
    /// so it guards the `pre_big` wiring even when the reference vectors are unavailable.
    #[test]
    fn silence_produces_zero_weighted_speech() {
        use crate::amr::nb::enc_main::EncoderState;
        let mut st = EncoderState::new();
        let mut prm = [0i16; 5];
        let mut wsp = [1i16; L_FRAME];
        let mut t_op = [0i16; 2];
        st.analyze_frame(
            AmrNbMode::Mr1220,
            &[0i16; L_FRAME],
            &mut prm,
            &mut wsp,
            &mut t_op,
        );
        assert!(
            wsp.iter().all(|&v| v == 0),
            "silence must yield zero weighted speech"
        );
    }

    #[test]
    fn oracle_gate_mr122_wsp_and_top_bit_exact() {
        if let Some(n) =
            run_oracle_gate(AmrNbMode::Mr1220, "/tmp/amr-nb-oracle-t2/wsp_top_mr122.txt")
        {
            eprintln!("MR122 oracle gate: {n} frames wsp+T_op bit-exact");
        }
    }

    #[test]
    fn oracle_gate_mr475_wsp_and_top_bit_exact() {
        if let Some(n) =
            run_oracle_gate(AmrNbMode::Mr475, "/tmp/amr-nb-oracle-t2/wsp_top_mr475.txt")
        {
            eprintln!("MR475 oracle gate: {n} frames wsp+T_op bit-exact");
        }
    }

    #[test]
    fn pitch_ol_finds_periodicity() {
        // Build a periodic signal (period 40) so the open-loop pitch locks onto a multiple of 40.
        const HIST: usize = PIT_MAX as usize;
        const N: usize = crate::amr::nb::constants::L_FRAME;
        let mut sig = vec![0i16; HIST + N];
        for (i, s) in sig.iter_mut().enumerate() {
            // period-40 impulse train scaled up so the correlation dominates
            *s = if i % 40 == 0 { 4000 } else { 0 };
        }
        let lag = pitch_ol(&sig, HIST, PIT_MIN_VALUE, PIT_MAX, N, false);
        // The strongest normalized correlation for this train is at a multiple of 40 in range.
        assert_eq!(
            lag % 40,
            0,
            "expected a multiple of the true period, got {lag}"
        );
    }
}
