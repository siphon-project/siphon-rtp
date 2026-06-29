// AMR-WB encoder — WORK IN PROGRESS: not yet wired into the codec factory or validated
// bit-exact. Ported from the 3GPP fixed-point C reference (index loops / manual slice
// copies mirror the C, plus not-yet-used WIP code); these style + dead-code lints are
// quieted module-wide until the encoder is complete and validated, then revisited.
#![allow(
    clippy::needless_range_loop,
    clippy::manual_memcpy,
    clippy::explicit_counter_loop,
    clippy::manual_div_ceil,
    clippy::unnecessary_to_owned,
    dead_code,
    unused
)]

//! AMR-WB encoder LP-analysis tier (3GPP TS 26.190 / TS 26.173 reference `coder.c` front end):
//! input HP50 + 16k→12.8k decimation (`decim54.c`) + pre-emphasis, then windowing
//! (`autocorr.c` `ham_wind.tab`), `Autocorr`, `Lag_window` (`lag_wind.tab`), `Levinson`
//! (`levinson.c`), `Az_isp` (`az_isp.c` `grid100.tab`), `Weight_a`/`Residu`/`LP_Decim2`, and the ISF
//! VQ quantizer search `Qpisf_2s_36b`/`Qpisf_2s_46b` (`qpisf_2s.c`).
//!
//! Ported bit-exact on the shared fixed-point operators ([`crate::amr::basic_ops`],
//! [`crate::amr::oper_32b`]). The decoder already owns the ISP↔ISF + Az conversions
//! ([`crate::amr::wb::lpc`]) and the ISF codebooks ([`crate::amr::wb::isf_tables`]); the quantizer
//! searches the same tables the dequantizer reads.

use crate::amr::basic_ops::{
    abs_s, add, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_mac, l_msu, l_mult, l_negate,
    l_shl, l_shr, l_sub, mult, mult_r, negate, norm_l, norm_s, round_word, shl, shr, shr_r, sub,
};
use crate::amr::oper_32b::{div_32, l_comp, l_extract, mpy_32, mpy_32_16};
use crate::amr::wb::constants::M;
use crate::amr::wb::isf_dequant::{dpisf_2s_36b, dpisf_2s_46b};
use crate::amr::wb::isf_tables::{
    DICO1_ISF, DICO21_ISF_36B, DICO21_ISF_46B, DICO22_ISF_36B, DICO22_ISF_46B, DICO23_ISF_36B,
    DICO23_ISF_46B, DICO24_ISF_46B, DICO25_ISF_46B, DICO2_ISF, MEAN_ISF,
};

/// LP analysis window length (`L_WINDOW`).
pub const L_WINDOW: usize = 384;
/// Total speech buffer (`L_TOTAL`).
pub const L_TOTAL: usize = 384;
/// Internal frame size at 12.8 kHz (`L_FRAME`).
pub const L_FRAME: usize = 256;
/// 16 kHz output frame size (`L_FRAME16k`).
pub const L_FRAME16K: usize = 320;
/// Subframe size at 12.8 kHz.
pub const L_SUBFR: usize = 64;
/// Down-sampling filter delay (`L_FILT16k`).
pub const L_FILT16K: usize = 15;
/// Up-sampling filter delay (`L_FILT`).
pub const L_FILT: usize = 12;
/// LP-analysis "next" lookahead (`L_NEXT`).
pub const L_NEXT: usize = 64;
/// Pre-emphasis factor (0.68 Q15).
pub const PREEMPH_FAC: i16 = 22282;
/// Weighting numerator (0.92 Q15).
pub const GAMMA1: i16 = 30147;
/// Tilt factor (denominator) (0.68 Q15).
pub const TILT_FAC: i16 = 22282;
/// Scaling max for the signal (`Q_MAX`, see `syn_filt_32`).
pub const Q_MAX: i16 = 8;
/// Down-sampling 4/5 ratio in Q15 (`DOWN_FAC`).
const DOWN_FAC: i16 = 26215;
/// Down-sampling filter half-length (`NB_COEF_DOWN`).
const NB_COEF_DOWN: usize = 15;
/// 1/4 resolution step for the down-sampler.
const FAC4_DOWN: i16 = 4;
const FAC5_DOWN: i16 = 5;

/// MA prediction factor for ISF (1/3 in Q15).
const MU: i16 = 10923;
/// Number of survivors in the 1st-stage ISF VQ search.
const N_SURV_MAX: usize = 4;

/// Codebook sizes (`qpisf_2s.tab`).
const SIZE_BK1: usize = 256;
const SIZE_BK2: usize = 256;
const SIZE_BK21: usize = 64;
const SIZE_BK22: usize = 128;
const SIZE_BK23: usize = 128;
const SIZE_BK24: usize = 32;
const SIZE_BK25: usize = 32;
const SIZE_BK21_36B: usize = 128;
const SIZE_BK22_36B: usize = 128;
const SIZE_BK23_36B: usize = 64;

/// Hamming-cos LP-analysis window, Q15 (`ham_wind.tab`).
#[rustfmt::skip]
static WINDOW: [i16; L_WINDOW] = [
    2621, 2622, 2626, 2632, 2640, 2650, 2662, 2677, 2694, 2714,
    2735, 2759, 2785, 2814, 2844, 2877, 2912, 2949, 2989, 3031,
    3075, 3121, 3169, 3220, 3273, 3328, 3385, 3444, 3506, 3569,
    3635, 3703, 3773, 3845, 3919, 3996, 4074, 4155, 4237, 4321,
    4408, 4496, 4587, 4680, 4774, 4870, 4969, 5069, 5171, 5275,
    5381, 5489, 5599, 5710, 5824, 5939, 6056, 6174, 6295, 6417,
    6541, 6666, 6793, 6922, 7052, 7185, 7318, 7453, 7590, 7728,
    7868, 8009, 8152, 8296, 8442, 8589, 8737, 8887, 9038, 9191,
    9344, 9499, 9655, 9813, 9971, 10131, 10292, 10454, 10617, 10781,
    10946, 11113, 11280, 11448, 11617, 11787, 11958, 12130, 12303, 12476,
    12650, 12825, 13001, 13178, 13355, 13533, 13711, 13890, 14070, 14250,
    14431, 14612, 14793, 14975, 15158, 15341, 15524, 15708, 15891, 16076,
    16260, 16445, 16629, 16814, 16999, 17185, 17370, 17555, 17740, 17926,
    18111, 18296, 18481, 18666, 18851, 19036, 19221, 19405, 19589, 19773,
    19956, 20139, 20322, 20504, 20686, 20867, 21048, 21229, 21408, 21588,
    21767, 21945, 22122, 22299, 22475, 22651, 22825, 22999, 23172, 23344,
    23516, 23686, 23856, 24025, 24192, 24359, 24525, 24689, 24853, 25016,
    25177, 25337, 25496, 25654, 25811, 25967, 26121, 26274, 26426, 26576,
    26725, 26873, 27019, 27164, 27308, 27450, 27590, 27729, 27867, 28003,
    28137, 28270, 28401, 28531, 28659, 28785, 28910, 29033, 29154, 29274,
    29391, 29507, 29622, 29734, 29845, 29953, 30060, 30165, 30268, 30370,
    30469, 30566, 30662, 30755, 30847, 30936, 31024, 31109, 31193, 31274,
    31354, 31431, 31506, 31579, 31651, 31719, 31786, 31851, 31914, 31974,
    32032, 32088, 32142, 32194, 32243, 32291, 32336, 32379, 32419, 32458,
    32494, 32528, 32560, 32589, 32617, 32642, 32664, 32685, 32703, 32719,
    32733, 32744, 32753, 32760, 32764, 32767, 32767, 32765, 32757, 32745,
    32727, 32705, 32678, 32646, 32609, 32567, 32520, 32468, 32411, 32349,
    32283, 32211, 32135, 32054, 31968, 31877, 31781, 31681, 31575, 31465,
    31351, 31231, 31107, 30978, 30844, 30706, 30563, 30415, 30263, 30106,
    29945, 29779, 29609, 29434, 29255, 29071, 28883, 28691, 28494, 28293,
    28087, 27878, 27664, 27446, 27224, 26997, 26767, 26533, 26294, 26052,
    25806, 25555, 25301, 25043, 24782, 24516, 24247, 23974, 23698, 23418,
    23134, 22847, 22557, 22263, 21965, 21665, 21361, 21054, 20743, 20430,
    20113, 19794, 19471, 19146, 18817, 18486, 18152, 17815, 17476, 17134,
    16789, 16442, 16092, 15740, 15385, 15028, 14669, 14308, 13944, 13579,
    13211, 12841, 12470, 12096, 11721, 11344, 10965, 10584, 10202, 9819,
    9433, 9047, 8659, 8270, 7879, 7488, 7095, 6701, 6306, 5910,
    5514, 5116, 4718, 4319, 3919, 3519, 3118, 2716, 2315, 1913,
    1510, 1108, 705, 302,
];

/// `1/4` down-sampling FIR (Q14) for 16k→12.8k decimation (`decim54.c` `fir_down`), 120 taps.
#[rustfmt::skip]
static FIR_DOWN: [i16; 120] = [
    -1, -3, -6, -5, 0, 9, 19, 24, 18, 0,
    -26, -50, -58, -41, 0, 54, 99, 111, 77, 0,
    -95, -170, -188, -128, 0, 153, 270, 294, 198, 0,
    -233, -408, -441, -295, 0, 344, 601, 649, 434, 0,
    -507, -888, -964, -647, 0, 770, 1366, 1505, 1030, 0,
    -1293, -2379, -2746, -1997, 0, 3034, 6575, 9894, 12254, 13107,
    12254, 9894, 6575, 3034, 0, -1997, -2746, -2379, -1293, 0,
    1030, 1505, 1366, 770, 0, -647, -964, -888, -507, 0,
    434, 649, 601, 344, 0, -295, -441, -408, -233, 0,
    198, 294, 270, 153, 0, -128, -188, -170, -95, 0,
    77, 111, 99, 54, 0, -41, -58, -50, -26, 0,
    18, 24, 19, 9, 0, -5, -6, -3, -1, 0,
];

/// Cosine grid for `Az_isp` Chebyshev search, Q15 (`grid100.tab`), 101 entries.
#[rustfmt::skip]
static GRID: [i16; 101] = [
    32767, 32751, 32703, 32622, 32509, 32364, 32187, 31978, 31738, 31466,
    31164, 30830, 30466, 30072, 29649, 29196, 28714, 28204, 27666, 27101,
    26509, 25891, 25248, 24579, 23886, 23170, 22431, 21669, 20887, 20083,
    19260, 18418, 17557, 16680, 15786, 14876, 13951, 13013, 12062, 11099,
    10125, 9141, 8149, 7148, 6140, 5126, 4106, 3083, 2057, 1029,
    0, -1029, -2057, -3083, -4106, -5126, -6140, -7148, -8149, -9141,
    -10125, -11099, -12062, -13013, -13951, -14876, -15786, -16680, -17557, -18418,
    -19260, -20083, -20887, -21669, -22431, -23170, -23886, -24579, -25248, -25891,
    -26509, -27101, -27666, -28204, -28714, -29196, -29649, -30072, -30466, -30830,
    -31164, -31466, -31738, -31978, -32187, -32364, -32509, -32622, -32703, -32751,
    -32760,
];
const GRID_POINTS: usize = 100;

/// Lag-window coefficients in DPF (`lag_wind.tab` `lag_h`/`lag_l`).
#[rustfmt::skip]
static LAG_H: [i16; M] = [
    32750, 32707, 32637, 32538, 32411, 32257, 32075, 31867,
    31633, 31374, 31089, 30780, 30449, 30094, 29718, 29321,
];
#[rustfmt::skip]
static LAG_L: [i16; M] = [
    16896, 30464, 2496, 4480, 12160, 3520, 24320, 24192,
    20736, 576, 18240, 31488, 128, 16704, 11520, 14784,
];

/// 50 Hz HP biquad numerator / denominator (Q12) shared with the synthesis HP50 (`hp50.c`).
const HP50_B: [i16; 3] = [4053, -8106, 4053];
const HP50_A: [i16; 3] = [8192, 16211, -8021];

/// 2nd-order half-band decimation-by-2 FIR for `LP_Decim2`, Q15 (`lp_dec2.c` `h_fir`).
const LP_DEC2_FIR: [i16; 5] = [4260, 7536, 9175, 7536, 4260];

/// Down-sampling fractional interpolation (`decim54.c` `Interpol`). `x` is a window into the input
/// signal whose centre is at index `center`; reads `x[center-NB_COEF+1 .. center+NB_COEF]`.
fn interpol_down(sig: &[i16], center: isize, frac: i16) -> i16 {
    let base = center - NB_COEF_DOWN as isize + 1;
    let mut l_sum = 0i32;
    let mut k = sub(sub(FAC4_DOWN, 1), frac);
    for i in 0..(2 * NB_COEF_DOWN) {
        let idx = (base + i as isize) as usize;
        l_sum = l_mac(l_sum, sig[idx], FIR_DOWN[k as usize]);
        k = add(k, FAC4_DOWN);
    }
    l_sum = l_shl(l_sum, 1);
    round_word(l_sum)
}

/// 16 kHz → 12.8 kHz decimation (`decim54.c` `Decim_12k8`). `sig16k` is `lg` input samples; `mem` is
/// the 2·NB_COEF_DOWN-sample filter history (carried). Writes `mult(lg, DOWN_FAC)` output samples.
pub fn decim_12k8(sig16k: &[i16], lg: usize, sig12k8: &mut [i16], mem: &mut [i16; 2 * NB_COEF_DOWN]) {
    // signal = [mem] ++ [sig16k(lg)]
    let mut signal = [0i16; L_FRAME16K + 2 * NB_COEF_DOWN];
    signal[..2 * NB_COEF_DOWN].copy_from_slice(mem);
    signal[2 * NB_COEF_DOWN..2 * NB_COEF_DOWN + lg].copy_from_slice(&sig16k[..lg]);

    let lg_down = mult(lg as i16, DOWN_FAC) as usize;

    // Down_samp over signal+NB_COEF_DOWN: pos in Q2 (1/4 resolution), +5/4 each output.
    let mut pos = 0i16;
    for out in sig12k8.iter_mut().take(lg_down) {
        let i = shr(pos, 2);
        let frac = pos & 3;
        // Interpol(&sig[NB_COEF_DOWN + i], ...): centre at NB_COEF_DOWN + i within `signal`.
        let center = NB_COEF_DOWN as isize + i as isize;
        *out = interpol_down(&signal, center, frac);
        pos = add(pos, FAC5_DOWN);
    }

    mem.copy_from_slice(&signal[lg..lg + 2 * NB_COEF_DOWN]);
}

/// 50 Hz HP biquad at 12.8 kHz (`hp50.c` `HP50_12k8`). `mem[6]` = `[y2_hi,y2_lo,y1_hi,y1_lo,x0,x1]`.
pub fn hp50_12k8(signal: &mut [i16], lg: usize, mem: &mut [i16; 6]) {
    let mut y2_hi = mem[0];
    let mut y2_lo = mem[1];
    let mut y1_hi = mem[2];
    let mut y1_lo = mem[3];
    let mut x0 = mem[4];
    let mut x1 = mem[5];

    for sample in signal.iter_mut().take(lg) {
        let x2 = x1;
        x1 = x0;
        x0 = *sample;

        let mut l_tmp = 16384i32;
        l_tmp = l_mac(l_tmp, y1_lo, HP50_A[1]);
        l_tmp = l_mac(l_tmp, y2_lo, HP50_A[2]);
        l_tmp = l_shr(l_tmp, 15);
        l_tmp = l_mac(l_tmp, y1_hi, HP50_A[1]);
        l_tmp = l_mac(l_tmp, y2_hi, HP50_A[2]);
        l_tmp = l_mac(l_tmp, x0, HP50_B[0]);
        l_tmp = l_mac(l_tmp, x1, HP50_B[1]);
        l_tmp = l_mac(l_tmp, x2, HP50_B[2]);
        l_tmp = l_shl(l_tmp, 2);

        y2_hi = y1_hi;
        y2_lo = y1_lo;
        (y1_hi, y1_lo) = l_extract(l_tmp);

        l_tmp = l_shl(l_tmp, 1);
        *sample = round_word(l_tmp);
    }

    *mem = [y2_hi, y2_lo, y1_hi, y1_lo, x0, x1];
}

/// Autocorrelation with Hamming windowing (`autocorr.c` `Autocorr`). `x` is `L_WINDOW` samples;
/// returns the M+1 autocorrelations in DPF (`r_h`/`r_l`).
pub fn autocorr(x: &[i16], m: usize, r_h: &mut [i16], r_l: &mut [i16]) {
    let mut y = [0i16; L_WINDOW];
    for i in 0..L_WINDOW {
        y[i] = mult_r(x[i], WINDOW[i]);
    }

    // calculate energy of signal
    let mut l_sum = l_deposit_h(16);
    for &v in y.iter().take(L_WINDOW) {
        let l_tmp = l_shr(l_mult(v, v), 8);
        l_sum = l_add(l_sum, l_tmp);
    }

    let mut norm = norm_l(l_sum);
    let mut shift = sub(4, shr(norm, 1));
    if shift < 0 {
        shift = 0;
    }
    for v in y.iter_mut().take(L_WINDOW) {
        *v = shr_r(*v, shift);
    }

    // Compute and normalize r[0]
    l_sum = 1;
    for &v in y.iter().take(L_WINDOW) {
        l_sum = l_mac(l_sum, v, v);
    }
    norm = norm_l(l_sum);
    l_sum = l_shl(l_sum, norm);
    (r_h[0], r_l[0]) = l_extract(l_sum);

    // r[1] to r[m]
    for i in 1..=m {
        let mut l_acc = 0i32;
        for j in 0..(L_WINDOW - i) {
            l_acc = l_mac(l_acc, y[j], y[j + i]);
        }
        l_acc = l_shl(l_acc, norm);
        (r_h[i], r_l[i]) = l_extract(l_acc);
    }
}

/// Lag-windowing of the autocorrelations (`lag_wind.c` `Lag_window`).
pub fn lag_window(r_h: &mut [i16], r_l: &mut [i16]) {
    for i in 1..=M {
        let x = mpy_32(r_h[i], r_l[i], LAG_H[i - 1], LAG_L[i - 1]);
        (r_h[i], r_l[i]) = l_extract(x);
    }
}

/// Levinson-Durbin recursion in double precision (`levinson.c` `Levinson`). Produces `a[0..=M]`
/// (Q12) and `rc[0..M]` (Q15); `mem[18]` carries the previous stable `A`/`rc` (unstable-filter
/// fallback). Returns nothing; on instability it copies the saved `A`.
pub fn levinson(r_h: &[i16], r_l: &[i16], a: &mut [i16], rc: &mut [i16], mem: &mut [i16; 18]) {
    const NC: usize = M / 2; // unused but kept for parity with the C #define
    let _ = NC;
    let mut a_h = [0i16; M + 1];
    let mut a_l = [0i16; M + 1];
    let mut an_h = [0i16; M + 1];
    let mut an_l = [0i16; M + 1];

    // old_A = mem[0..M], old_rc = mem[M..M+2]
    // K = A[1] = -R[1]/R[0]
    let t1 = l_comp(r_h[1], r_l[1]);
    let t2 = l_abs(t1);
    let mut t0 = div_32(t2, r_h[0], r_l[0]);
    if t1 > 0 {
        t0 = l_negate(t0);
    }
    let (mut kh, mut kl) = l_extract(t0);
    rc[0] = kh;
    t0 = l_shr(t0, 4);
    (a_h[1], a_l[1]) = l_extract(t0);

    // Alpha = R[0]*(1-K^2)
    let mut t0a = mpy_32(kh, kl, kh, kl);
    t0a = l_abs(t0a);
    t0a = l_sub(0x7fff_ffff, t0a);
    let (mut hi, mut lo) = l_extract(t0a);
    t0a = mpy_32(r_h[0], r_l[0], hi, lo);

    let mut alp_exp = norm_l(t0a);
    t0a = l_shl(t0a, alp_exp);
    let (mut alp_h, mut alp_l) = l_extract(t0a);

    for i in 2..=M {
        // t0 = sum(R[j]*A[i-j], j=1..i-1) + R[i]
        let mut s = 0i32;
        for j in 1..i {
            s = l_add(s, mpy_32(r_h[j], r_l[j], a_h[i - j], a_l[i - j]));
        }
        s = l_shl(s, 4);
        let tt = l_comp(r_h[i], r_l[i]);
        s = l_add(s, tt);

        // K = -t0/Alpha
        let mut tabs = l_abs(s);
        tabs = div_32(tabs, alp_h, alp_l);
        let mut t2k = if s > 0 { l_negate(tabs) } else { tabs };
        t2k = l_shl(t2k, alp_exp);
        (kh, kl) = l_extract(t2k);
        rc[i - 1] = kh;

        // unstable filter -> keep old A
        if sub(abs_s(kh), 32750) > 0 {
            a[0] = 4096;
            for j in 0..M {
                a[j + 1] = mem[j];
            }
            rc[0] = mem[M];
            rc[1] = mem[M + 1];
            return;
        }

        for j in 1..i {
            let mut tn = mpy_32(kh, kl, a_h[i - j], a_l[i - j]);
            tn = l_add(tn, l_comp(a_h[j], a_l[j]));
            (an_h[j], an_l[j]) = l_extract(tn);
        }
        t2k = l_shr(t2k, 4);
        (an_h[i], an_l[i]) = l_extract(t2k);

        // Alpha = Alpha*(1-K^2)
        let mut tk = mpy_32(kh, kl, kh, kl);
        tk = l_abs(tk);
        tk = l_sub(0x7fff_ffff, tk);
        (hi, lo) = l_extract(tk);
        tk = mpy_32(alp_h, alp_l, hi, lo);

        let jn = norm_l(tk);
        tk = l_shl(tk, jn);
        (alp_h, alp_l) = l_extract(tk);
        alp_exp = add(alp_exp, jn);

        for j in 1..=i {
            a_h[j] = an_h[j];
            a_l[j] = an_l[j];
        }
    }

    // Truncate A[i] Q27 -> Q12 with rounding
    a[0] = 4096;
    for i in 1..=M {
        let tt = l_comp(a_h[i], a_l[i]);
        let v = round_word(l_shl(tt, 1));
        mem[i - 1] = v;
        a[i] = v;
    }
    mem[M] = rc[0];
    mem[M + 1] = rc[1];
}

/// Chebyshev polynomial evaluation (`az_isp.c` `Chebps2`), result Q14.
fn chebps2(x: i16, f: &[i16], n: usize) -> i16 {
    let mut t0 = l_mult(f[0], 4096);
    let (mut b2_h, mut b2_l) = l_extract(t0);

    t0 = mpy_32_16(b2_h, b2_l, x);
    t0 = l_shl(t0, 1);
    t0 = l_mac(t0, f[1], 4096);
    let (mut b1_h, mut b1_l) = l_extract(t0);

    for &fi in f.iter().take(n).skip(2) {
        t0 = mpy_32_16(b1_h, b1_l, x);
        t0 = l_mac(t0, b2_h, -16384);
        t0 = l_mac(t0, fi, 2048);
        t0 = l_shl(t0, 1);
        t0 = l_msu(t0, b2_l, 1);
        let (b0_h, b0_l) = l_extract(t0);
        b2_l = b1_l;
        b2_h = b1_h;
        b1_l = b0_l;
        b1_h = b0_h;
    }

    t0 = mpy_32_16(b1_h, b1_l, x);
    t0 = l_mac(t0, b2_h, -32768);
    t0 = l_msu(t0, b2_l, 1);
    t0 = l_mac(t0, f[n], 2048);
    t0 = l_shl(t0, 6);
    let mut cheb = extract_h(t0);
    if sub(cheb, -32768) == 0 {
        cheb = -32767;
    }
    cheb
}

/// A(z) → ISP conversion (`az_isp.c` `Az_isp`). `a` is `a[0..=M]` (Q12); writes M ISPs to `isp`
/// (Q15). `old_isp` is the fallback if fewer than M-1 roots are found.
pub fn az_isp(a: &[i16], isp: &mut [i16], old_isp: &[i16]) {
    const NC: usize = M / 2;
    let mut f1 = [0i16; NC + 1];
    let mut f2 = [0i16; NC];

    for i in 0..NC {
        let t0 = l_mult(a[i], 16384);
        f1[i] = round_word(l_mac(t0, a[M - i], 16384));
        f2[i] = round_word(l_msu(t0, a[M - i], 16384));
    }
    f1[NC] = a[NC];

    for i in 2..NC {
        f2[i] = add(f2[i], f2[i - 2]);
    }

    let mut nf = 0usize;
    let mut ip = 0i16;

    // coef points to f1 (true) or f2 (false); order tracks NC / NC-1.
    let mut coef_is_f1 = true;
    let mut order = NC;

    let mut xlow = GRID[0];
    let mut ylow = chebps2(xlow, &f1, order);

    let mut j = 0usize;
    while nf < M - 1 && j < GRID_POINTS {
        j += 1;
        let mut xhigh = xlow;
        let mut yhigh = ylow;
        xlow = GRID[j];
        ylow = chebps2(xlow, if coef_is_f1 { &f1 } else { &f2 }, order);

        if l_mult(ylow, yhigh) <= 0 {
            for _ in 0..2 {
                let xmid = add(shr(xlow, 1), shr(xhigh, 1));
                let ymid = chebps2(xmid, if coef_is_f1 { &f1 } else { &f2 }, order);
                if l_mult(ylow, ymid) <= 0 {
                    yhigh = ymid;
                    xhigh = xmid;
                } else {
                    ylow = ymid;
                    xlow = xmid;
                }
            }

            let x = sub(xhigh, xlow);
            let y = sub(yhigh, ylow);

            let xint;
            if y == 0 {
                xint = xlow;
            } else {
                let sign = y;
                let mut yy = abs_s(y);
                let exp = norm_s(yy);
                yy = shl(yy, exp);
                yy = crate::amr::basic_ops::div_s(16383, yy);
                let mut t0 = l_mult(x, yy);
                t0 = l_shr(t0, sub(20, exp));
                let mut yq = extract_l(t0);
                if sign < 0 {
                    yq = negate(yq);
                }
                let mut t0b = l_mult(ylow, yq);
                t0b = l_shr(t0b, 11);
                xint = sub(xlow, extract_l(t0b));
            }

            isp[nf] = xint;
            xlow = xint;
            nf += 1;

            if ip == 0 {
                ip = 1;
                coef_is_f1 = false;
                order = NC - 1;
            } else {
                ip = 0;
                coef_is_f1 = true;
                order = NC;
            }
            ylow = chebps2(xlow, if coef_is_f1 { &f1 } else { &f2 }, order);
        }
    }

    if sub(nf as i16, (M - 1) as i16) < 0 {
        isp[..M].copy_from_slice(&old_isp[..M]);
    } else {
        isp[M - 1] = shl(a[M], 3);
    }
}

/// Spectral expansion of A(z) (`weight_a.c` `Weight_a`): `ap[i] = a[i]·gamma^i`.
pub fn weight_a(a: &[i16], ap: &mut [i16], gamma: i16, m: usize) {
    ap[0] = a[0];
    let mut fac = gamma;
    for i in 1..m {
        ap[i] = round_word(l_mult(a[i], fac));
        fac = round_word(l_mult(fac, gamma));
    }
    ap[m] = round_word(l_mult(a[m], fac));
}

/// LPC residual filtering (`residu.c` `Residu`): `y = A(z)·x`. `x` needs `x[-m..-1]`; `x_off` is the
/// index of `x[0]` in `x`. Writes `lg` samples to `y`.
pub fn residu(a: &[i16], m: usize, x: &[i16], x_off: usize, y: &mut [i16], lg: usize) {
    for i in 0..lg {
        let mut s = l_mult(x[x_off + i], a[0]);
        for j in 1..=m {
            s = l_mac(s, a[j], x[x_off + i - j]);
        }
        s = l_shl(s, 3 + 1);
        y[i] = round_word(s);
    }
}

/// Decimate a vector by 2 with a 2nd-order FIR (`lp_dec2.c` `LP_Decim2`). `x[0..l]` in place →
/// `x[0..l/2]`; `mem[3]` carries the filter state.
pub fn lp_decim2(x: &mut [i16], l: usize, mem: &mut [i16; 3]) {
    const L_MEM: usize = 3; // L_FIR-2
    let mut x_buf = [0i16; L_FRAME + L_MEM];
    x_buf[..L_MEM].copy_from_slice(&mem[..L_MEM]);
    for i in 0..l {
        x_buf[L_MEM + i] = x[i];
    }
    for i in 0..L_MEM {
        mem[i] = x[l - L_MEM + i];
    }

    let mut j = 0usize;
    let mut i = 0usize;
    while i < l {
        let mut l_tmp = 0i32;
        for k in 0..5 {
            l_tmp = l_mac(l_tmp, x_buf[i + k], LP_DEC2_FIR[k]);
        }
        x[j] = round_word(l_tmp);
        j += 1;
        i += 2;
    }
}

/// `Sub_VQ` (`qpisf_2s.c`): find the nearest codebook vector to `x[0..dim]`, return its index, set
/// `*distance` to the squared error, and overwrite `x[0..dim]` with the selected vector.
fn sub_vq(x: &mut [i16], dico: &[i16], dim: usize, dico_size: usize) -> (i16, i32) {
    let mut dist_min = i32::MAX;
    let mut index = 0i16;
    for i in 0..dico_size {
        let mut dist = 0i32;
        for j in 0..dim {
            let temp = sub(x[j], dico[i * dim + j]);
            dist = l_mac(dist, temp, temp);
        }
        if l_sub(dist, dist_min) < 0 {
            dist_min = dist;
            index = i as i16;
        }
    }
    let base = index as usize * dim;
    x[..dim].copy_from_slice(&dico[base..base + dim]);
    (index, dist_min)
}

/// `VQ_stage1` (`qpisf_2s.c`): keep the `surv` best survivors over the 1st-stage codebook.
fn vq_stage1(x: &[i16], dico: &[i16], dim: usize, dico_size: usize, index: &mut [i16], surv: usize) {
    let mut dist_min = [i32::MAX; N_SURV_MAX];
    for (i, slot) in index.iter_mut().enumerate().take(surv) {
        *slot = i as i16;
    }
    for i in 0..dico_size {
        let mut dist = 0i32;
        for j in 0..dim {
            let temp = sub(x[j], dico[i * dim + j]);
            dist = l_mac(dist, temp, temp);
        }
        for k in 0..surv {
            if l_sub(dist, dist_min[k]) < 0 {
                let mut l = surv - 1;
                while l > k {
                    dist_min[l] = dist_min[l - 1];
                    index[l] = index[l - 1];
                    l -= 1;
                }
                dist_min[k] = dist;
                index[k] = i as i16;
                break;
            }
        }
    }
}

/// 36-bit ISF quantizer (`qpisf_2s.c` `Qpisf_2s_36b`). Writes 5 indices to `indice[0..5]` and the
/// quantized ISF to `isf_q`; `past_isfq` (M) is the MA predictor (updated through the dequant call).
/// `isf_buf` is the L_MEANBUF·M ISF history (refreshed because `enc_dec=true`).
pub fn qpisf_2s_36b(
    isf1: &[i16],
    isf_q: &mut [i16],
    past_isfq: &mut [i16],
    isf_buf: &mut [i16],
    indice: &mut [i16],
    nb_surv: usize,
) {
    let mut isf = [0i16; M];
    for i in 0..M {
        isf[i] = sub(isf1[i], MEAN_ISF[i]);
        isf[i] = sub(isf[i], mult(MU, past_isfq[i]));
    }

    let mut surv1 = [0i16; N_SURV_MAX];
    let mut tmp_ind = [0i16; 5];
    let mut isf_stage2 = [0i16; M];

    vq_stage1(&isf[..9], &DICO1_ISF, 9, SIZE_BK1, &mut surv1, nb_surv);
    let mut distance = i32::MAX;
    for &s in surv1.iter().take(nb_surv) {
        for i in 0..9 {
            isf_stage2[i] = sub(isf[i], DICO1_ISF[i + s as usize * 9]);
        }
        let (i0, e0) = sub_vq(&mut isf_stage2[0..5], &DICO21_ISF_36B, 5, SIZE_BK21_36B);
        let mut temp = e0;
        let (i1, e1) = sub_vq(&mut isf_stage2[5..9], &DICO22_ISF_36B, 4, SIZE_BK22_36B);
        temp = l_add(temp, e1);
        tmp_ind[0] = i0;
        tmp_ind[1] = i1;
        if l_sub(temp, distance) < 0 {
            distance = temp;
            indice[0] = s;
            indice[2] = tmp_ind[0];
            indice[3] = tmp_ind[1];
        }
    }

    vq_stage1(&isf[9..16], &DICO2_ISF, 7, SIZE_BK2, &mut surv1, nb_surv);
    distance = i32::MAX;
    for &s in surv1.iter().take(nb_surv) {
        for i in 0..7 {
            isf_stage2[i] = sub(isf[9 + i], DICO2_ISF[i + s as usize * 7]);
        }
        let (i0, e0) = sub_vq(&mut isf_stage2[0..7], &DICO23_ISF_36B, 7, SIZE_BK23_36B);
        let temp = e0;
        if l_sub(temp, distance) < 0 {
            distance = temp;
            indice[1] = s;
            indice[4] = i0;
        }
    }

    dpisf_2s_36b(indice, isf_q, past_isfq, &isf_q.to_vec(), isf_buf, false, true);
}

/// 46-bit ISF quantizer (`qpisf_2s.c` `Qpisf_2s_46b`). Writes 7 indices to `indice[0..7]`.
pub fn qpisf_2s_46b(
    isf1: &[i16],
    isf_q: &mut [i16],
    past_isfq: &mut [i16],
    isf_buf: &mut [i16],
    indice: &mut [i16],
    nb_surv: usize,
) {
    let mut isf = [0i16; M];
    for i in 0..M {
        isf[i] = sub(isf1[i], MEAN_ISF[i]);
        isf[i] = sub(isf[i], mult(MU, past_isfq[i]));
    }

    let mut surv1 = [0i16; N_SURV_MAX];
    let mut tmp_ind = [0i16; 5];
    let mut isf_stage2 = [0i16; M];

    vq_stage1(&isf[..9], &DICO1_ISF, 9, SIZE_BK1, &mut surv1, nb_surv);
    let mut distance = i32::MAX;
    for &s in surv1.iter().take(nb_surv) {
        for i in 0..9 {
            isf_stage2[i] = sub(isf[i], DICO1_ISF[i + s as usize * 9]);
        }
        let (i0, e0) = sub_vq(&mut isf_stage2[0..3], &DICO21_ISF_46B, 3, SIZE_BK21);
        let mut temp = e0;
        let (i1, e1) = sub_vq(&mut isf_stage2[3..6], &DICO22_ISF_46B, 3, SIZE_BK22);
        temp = l_add(temp, e1);
        let (i2, e2) = sub_vq(&mut isf_stage2[6..9], &DICO23_ISF_46B, 3, SIZE_BK23);
        temp = l_add(temp, e2);
        tmp_ind[0] = i0;
        tmp_ind[1] = i1;
        tmp_ind[2] = i2;
        if l_sub(temp, distance) < 0 {
            distance = temp;
            indice[0] = s;
            indice[2] = tmp_ind[0];
            indice[3] = tmp_ind[1];
            indice[4] = tmp_ind[2];
        }
    }

    vq_stage1(&isf[9..16], &DICO2_ISF, 7, SIZE_BK2, &mut surv1, nb_surv);
    distance = i32::MAX;
    for &s in surv1.iter().take(nb_surv) {
        for i in 0..7 {
            isf_stage2[i] = sub(isf[9 + i], DICO2_ISF[i + s as usize * 7]);
        }
        let (i0, e0) = sub_vq(&mut isf_stage2[0..3], &DICO24_ISF_46B, 3, SIZE_BK24);
        let mut temp = e0;
        let (i1, e1) = sub_vq(&mut isf_stage2[3..7], &DICO25_ISF_46B, 4, SIZE_BK25);
        temp = l_add(temp, e1);
        if l_sub(temp, distance) < 0 {
            distance = temp;
            indice[1] = s;
            indice[5] = i0;
            indice[6] = i1;
        }
    }

    dpisf_2s_46b(indice, isf_q, past_isfq, &isf_q.to_vec(), isf_buf, false, true);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weight_a_is_geometric_expansion() {
        // ap[i] = a[i]·gamma^i. With a = [1,...], ap[1] = round(a[1]·gamma).
        let a = [4096i16, 2048, 1024, 512];
        let mut ap = [0i16; 4];
        weight_a(&a, &mut ap, GAMMA1, 3);
        assert_eq!(ap[0], 4096);
        assert_eq!(ap[1], round_word(l_mult(2048, GAMMA1)));
    }

    #[test]
    fn hp50_silent_on_zero() {
        let mut sig = [0i16; 64];
        let mut mem = [0i16; 6];
        hp50_12k8(&mut sig, 64, &mut mem);
        assert!(sig.iter().all(|&v| v == 0));
    }

    #[test]
    fn decim_zero_in_zero_out() {
        let mut out = [0i16; 256];
        let mut mem = [0i16; 2 * NB_COEF_DOWN];
        decim_12k8(&[0; 320], 320, &mut out, &mut mem);
        assert!(out.iter().all(|&v| v == 0));
    }

    #[test]
    fn autocorr_r0_is_largest() {
        // A simple ramp window: r[0] dominates.
        let x: Vec<i16> = (0..L_WINDOW).map(|i| (i as i16 % 50) - 25).collect();
        let mut r_h = [0i16; M + 1];
        let mut r_l = [0i16; M + 1];
        autocorr(&x, M, &mut r_h, &mut r_l);
        // r[0] msb is positive (energy).
        assert!(r_h[0] > 0);
    }

    #[test]
    fn residu_is_linear_filter() {
        // residu.c `Residu`: y[i] = round(L_shl(L_mult(x[i], a[0]) + Σ L_mac(a[j], x[i-j]), 3 + 1)).
        // With a = [4096, 0] (Q12 1.0, no prediction term): s = L_mult(x, 4096) = x·4096·2,
        // L_shl(s, 4) and round → 2·x. So the residual of a Q12-1.0 coefficient is 2× the input.
        // Ground truth from the fixed-point C reference (basicop2.c + residu.c).
        let a = [4096i16, 0];
        let x = [0i16, 0, 10, 20, 30, 40];
        let mut y = [0i16; 4];
        residu(&a, 1, &x, 2, &mut y, 4);
        assert_eq!(y, [20, 40, 60, 80]);
    }

    #[test]
    fn lp_decim2_halves_length() {
        let mut x = [100i16; 64];
        let mut mem = [0i16; 3];
        lp_decim2(&mut x, 64, &mut mem);
        // The decimated DC value approaches the input DC (filter sums to ~1.0).
        assert!((x[10] - 100).abs() < 5);
    }

    #[test]
    fn sub_vq_finds_exact_match() {
        // A 2-entry codebook of dim 2; the exact vector is index 1.
        let dico = [0i16, 0, 100, 200];
        let mut x = [100i16, 200];
        let (idx, dist) = sub_vq(&mut x, &dico, 2, 2);
        assert_eq!(idx, 1);
        assert_eq!(dist, 0);
        assert_eq!(x, [100, 200]);
    }
}
