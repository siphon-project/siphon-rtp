//! GSM 06.10 Full-Rate (RPE-LTP), RTP payload type 3 (RFC 3551 §4.5.8) — the classic GSM speech
//! codec. 160 samples (20 ms @ 8 kHz) → 260 bits packed into a 33-byte frame.
//!
//! RPE-LTP = Regular Pulse Excitation / Long-Term Prediction: pre-processing (offset compensation +
//! pre-emphasis), 8th-order LPC analysis (→ 8 Log-Area-Ratios), a short-term analysis filter, then
//! per 40-sample sub-frame a long-term predictor (lag + gain) and regular-pulse-excitation encoding
//! (grid selection + APCM of 13 pulses). All integer fixed-point, ported from the canonical
//! public-domain libgsm (Degener/Bormann) plain path — the bit-exact 3GPP TS 06.10 reference.
//!
//! Field/function names follow libgsm so each step maps onto TS 06.10 §4.2/§4.3. The fixed-point
//! contract is exact: `gsm_add`/`gsm_sub` saturate, `gsm_mult`/`gsm_mult_r` truncate (wrap) to 16
//! bits, `SASR` is an arithmetic shift. Like the other stateful codecs, one `GsmFr` instance is used
//! as *either* an encoder *or* a decoder (round-trip tests use two).

use crate::{CodecError, CodecParams, Decoder, Encoder};

const MIN_WORD: i32 = -32768;
const MAX_WORD: i32 = 32767;

/// 160 samples = one 20 ms GSM frame; 33 bytes on the wire.
const FRAME_SAMPLES: usize = 160;
const FRAME_BYTES: usize = 33;

// ---- TS 06.10 §4.4 constant tables (from libgsm `table.c`) ------------------------------------

const GSM_A: [i16; 8] = [20480, 20480, 20480, 20480, 13964, 15360, 8534, 9036];
const GSM_B: [i16; 8] = [0, 0, 2048, -2560, 94, -1792, -341, -1144];
const GSM_MIC: [i16; 8] = [-32, -32, -16, -16, -8, -8, -4, -4];
const GSM_MAC: [i16; 8] = [31, 31, 15, 15, 7, 7, 3, 3];
const GSM_INVA: [i16; 8] = [13107, 13107, 13107, 13107, 19223, 17476, 31454, 29708];
/// LAR-decode: B×2 per coefficient (the `STEP(B_TIMES_TWO, MIC, INVA)` first argument).
const GSM_B_TIMES_TWO: [i16; 8] = [0, 0, 4096, -5120, 188, -3584, -682, -2288];
const GSM_DLB: [i16; 4] = [6554, 16384, 26214, 32767];
const GSM_QLB: [i16; 4] = [3277, 11469, 21299, 32767];
const GSM_NRFAC: [i16; 8] = [29128, 26215, 23832, 21846, 20165, 18725, 17476, 16384];
const GSM_FAC: [i16; 8] = [18431, 20479, 22527, 24575, 26623, 28671, 30719, 32767];

// ---- Fixed-point basic operations (libgsm `add.c` / `private.h`) -------------------------------

/// Clamp an `i32` to the signed-16-bit range.
#[inline]
fn saturate(value: i32) -> i16 {
    value.clamp(MIN_WORD, MAX_WORD) as i16
}

/// Saturating 16-bit add (`GSM_ADD`).
#[inline]
fn gsm_add(a: i16, b: i16) -> i16 {
    saturate(i32::from(a) + i32::from(b))
}

/// Saturating 16-bit subtract (`GSM_SUB`).
#[inline]
fn gsm_sub(a: i16, b: i16) -> i16 {
    saturate(i32::from(a) - i32::from(b))
}

/// 16-bit multiply, `(a·b) >> 15`, truncating/wrapping (`GSM_MULT`).
#[inline]
fn gsm_mult(a: i16, b: i16) -> i16 {
    if a as i32 == MIN_WORD && b as i32 == MIN_WORD {
        MAX_WORD as i16
    } else {
        ((i32::from(a) * i32::from(b)) >> 15) as i16
    }
}

/// Rounded 16-bit multiply, `(a·b + 16384) >> 15`, truncating/wrapping (`GSM_MULT_R`).
#[inline]
fn gsm_mult_r(a: i16, b: i16) -> i16 {
    if a as i32 == MIN_WORD && b as i32 == MIN_WORD {
        MAX_WORD as i16
    } else {
        (((i32::from(a) * i32::from(b)) + 16384) >> 15) as i16
    }
}

/// 16-bit absolute value with `MIN_WORD → MAX_WORD` (`GSM_ABS`).
#[inline]
fn gsm_abs(a: i16) -> i16 {
    if a as i32 == MIN_WORD {
        MAX_WORD as i16
    } else {
        a.abs()
    }
}

/// Normalization shift count for a non-zero `i32` (`gsm_norm`): left-shifts to bring the value
/// just below the sign bit. Equivalent to the libgsm `bitoff`-table version.
fn gsm_norm(value: i32) -> i16 {
    debug_assert!(value != 0);
    let v = if value < 0 {
        if value <= -1_073_741_824 {
            return 0;
        }
        !value
    } else {
        value
    };
    v.leading_zeros() as i16 - 1
}

/// `(num << 15) / denum` by restoring division, with `0 <= num <= denum` (`gsm_div`).
fn gsm_div(num: i16, denum: i16) -> i16 {
    if num == 0 {
        return 0;
    }
    let mut l_num = i32::from(num);
    let l_denum = i32::from(denum);
    let mut div = 0i16;
    let mut k = 15;
    while k > 0 {
        k -= 1;
        div <<= 1;
        l_num <<= 1;
        if l_num >= l_denum {
            l_num -= l_denum;
            div += 1;
        }
    }
    div
}

/// Arithmetic shift right by a possibly-negative count (`gsm_asr`).
#[inline]
fn gsm_asr(a: i16, n: i32) -> i16 {
    if n >= 16 {
        return if a < 0 { -1 } else { 0 };
    }
    if n <= -16 {
        return 0;
    }
    if n < 0 {
        return ((i32::from(a)) << (-n)) as i16;
    }
    a >> n
}

/// Arithmetic shift left by a possibly-negative count (`gsm_asl`).
#[inline]
fn gsm_asl(a: i16, n: i32) -> i16 {
    if n >= 16 {
        return 0;
    }
    if n <= -16 {
        return if a < 0 { -1 } else { 0 };
    }
    if n < 0 {
        return gsm_asr(a, -n);
    }
    ((i32::from(a)) << n) as i16
}

// ---- Codec state (libgsm `gsm_state`) ----------------------------------------------------------

/// Persistent RPE-LTP state for one stream/direction.
#[derive(Debug, Clone)]
struct GsmState {
    /// Reconstructed short-term residual history (encoder `dp`, decoder `drp` = `&dp0[120]`).
    dp0: [i16; 280],
    /// Pre-processing: offset-compensation non-recursive state.
    z1: i16,
    /// Pre-processing: offset-compensation recursive (32-bit) state.
    l_z2: i32,
    /// Pre-processing: pre-emphasis state.
    mp: i16,
    /// Short-term analysis-filter lattice state.
    u: [i16; 8],
    /// Previous + current decoded LARs (for the 4-region interpolation).
    larpp: [[i16; 8]; 2],
    /// Index 0/1 into `larpp`, toggled each frame.
    j: usize,
    /// Long-term synthesis: last valid lag (init 40).
    nrp: i16,
    /// Short-term synthesis-filter lattice state.
    v: [i16; 9],
    /// Post-processing (de-emphasis) state.
    msr: i16,
}

impl GsmState {
    /// libgsm reset state: all zero except `nrp = 40`.
    const fn new() -> Self {
        Self {
            dp0: [0; 280],
            z1: 0,
            l_z2: 0,
            mp: 0,
            u: [0; 8],
            larpp: [[0; 8], [0; 8]],
            j: 0,
            nrp: 40,
            v: [0; 9],
            msr: 0,
        }
    }
}

/// The 76 quantized parameters of one GSM frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Frame {
    larc: [i16; 8],
    nc: [i16; 4],
    bc: [i16; 4],
    mc: [i16; 4],
    xmaxc: [i16; 4],
    xmc: [i16; 52],
}

impl Frame {
    const fn zero() -> Self {
        Self {
            larc: [0; 8],
            nc: [0; 4],
            bc: [0; 4],
            mc: [0; 4],
            xmaxc: [0; 4],
            xmc: [0; 52],
        }
    }
}

// ---- §4.2.0–4.2.3 Pre-processing ---------------------------------------------------------------

fn preprocess(state: &mut GsmState, s: &[i16], so: &mut [i16; FRAME_SAMPLES]) {
    let mut z1 = state.z1;
    let mut l_z2 = state.l_z2;
    let mut mp = state.mp;
    for k in 0..FRAME_SAMPLES {
        // 4.2.1 downscaling.
        let so_k = ((i32::from(s[k]) >> 3) << 2) as i16;
        // 4.2.2 offset compensation (high-pass).
        let s1 = (i32::from(so_k) - i32::from(z1)) as i16;
        z1 = so_k;
        let mut l_s2 = i32::from(s1) << 15;
        let msp = (l_z2 >> 15) as i16;
        let lsp = (l_z2 - (i32::from(msp) << 15)) as i16;
        l_s2 += i32::from(gsm_mult_r(lsp, 32735));
        let l_temp = i32::from(msp) * 32735;
        l_z2 = l_temp.saturating_add(l_s2);
        let l_temp = l_z2.saturating_add(16384);
        // 4.2.3 pre-emphasis.
        let msp = gsm_mult_r(mp, -28180);
        mp = (l_temp >> 15) as i16;
        so[k] = gsm_add(mp, msp);
    }
    state.z1 = z1;
    state.l_z2 = l_z2;
    state.mp = mp;
}

// ---- §4.2.4–4.2.7 LPC analysis -----------------------------------------------------------------

fn autocorrelation(s: &mut [i16; FRAME_SAMPLES], l_acf: &mut [i32; 9]) {
    let mut smax = 0i16;
    for &v in s.iter() {
        let temp = gsm_abs(v);
        if temp > smax {
            smax = temp;
        }
    }
    let scalauto = if smax == 0 {
        0
    } else {
        4 - gsm_norm(i32::from(smax) << 16)
    };
    if scalauto > 0 {
        let factor = 16384i16 >> (scalauto - 1);
        for v in s.iter_mut() {
            *v = gsm_mult_r(*v, factor);
        }
    }
    for acf in l_acf.iter_mut() {
        *acf = 0;
    }
    // Triangular warm-up (i = 0..7), then the steady-state 9-tap accumulation.
    for i in 0..FRAME_SAMPLES {
        let taps = (i + 1).min(9);
        for k in 0..taps {
            l_acf[k] += i32::from(s[i]) * i32::from(s[i - k]);
        }
    }
    for acf in l_acf.iter_mut() {
        *acf <<= 1;
    }
    if scalauto > 0 {
        for v in s.iter_mut() {
            *v = ((i32::from(*v)) << scalauto) as i16;
        }
    }
}

fn reflection_coefficients(l_acf: &[i32; 9], r: &mut [i16; 8]) {
    if l_acf[0] == 0 {
        *r = [0; 8];
        return;
    }
    let temp = gsm_norm(l_acf[0]);
    let mut acf = [0i16; 9];
    for i in 0..9 {
        acf[i] = ((l_acf[i] << temp) >> 16) as i16;
    }
    let mut k = [0i16; 9];
    let mut p = [0i16; 9];
    k[1..8].copy_from_slice(&acf[1..8]);
    p.copy_from_slice(&acf);

    for n in 1..=8usize {
        let mut temp = gsm_abs(p[1]);
        if p[0] < temp {
            for ri in r.iter_mut().take(8).skip(n - 1) {
                *ri = 0;
            }
            return;
        }
        let mut rn = gsm_div(temp, p[0]);
        if p[1] > 0 {
            rn = -rn;
        }
        r[n - 1] = rn;
        if n == 8 {
            return;
        }
        temp = gsm_mult_r(p[1], rn);
        p[0] = gsm_add(p[0], temp);
        for m in 1..=(8 - n) {
            let t1 = gsm_mult_r(k[m], rn);
            let pm = gsm_add(p[m + 1], t1);
            let t2 = gsm_mult_r(p[m + 1], rn);
            k[m] = gsm_add(k[m], t2);
            p[m] = pm;
        }
    }
}

fn transformation_to_lar(r: &mut [i16; 8]) {
    for ri in r.iter_mut() {
        let temp0 = gsm_abs(*ri);
        let temp = if temp0 < 22118 {
            temp0 >> 1
        } else if temp0 < 31130 {
            temp0 - 11059
        } else {
            ((i32::from(temp0) - 26112) << 2) as i16
        };
        *ri = if *ri < 0 { -temp } else { temp };
    }
}

fn quantization_and_coding(lar: &mut [i16; 8]) {
    for i in 0..8 {
        let mut temp = gsm_mult(GSM_A[i], lar[i]);
        temp = gsm_add(temp, GSM_B[i]);
        temp = gsm_add(temp, 256);
        temp >>= 9;
        lar[i] = if i32::from(temp) > i32::from(GSM_MAC[i]) {
            GSM_MAC[i] - GSM_MIC[i]
        } else if i32::from(temp) < i32::from(GSM_MIC[i]) {
            0
        } else {
            temp - GSM_MIC[i]
        };
    }
}

fn lpc_analysis(so: &mut [i16; FRAME_SAMPLES], larc: &mut [i16; 8]) {
    let mut l_acf = [0i32; 9];
    autocorrelation(so, &mut l_acf);
    reflection_coefficients(&l_acf, larc);
    transformation_to_lar(larc);
    quantization_and_coding(larc);
}

// ---- §4.2.8–4.2.10 Short-term filtering --------------------------------------------------------

fn decode_lar(larc: &[i16; 8], larpp: &mut [i16; 8]) {
    for i in 0..8 {
        // temp1 is a 16-bit register in libgsm: the `<< 10` truncates to i16.
        let mut temp1 = (i32::from(gsm_add(larc[i], GSM_MIC[i])) << 10) as i16;
        temp1 = gsm_sub(temp1, GSM_B_TIMES_TWO[i]);
        temp1 = gsm_mult_r(GSM_INVA[i], temp1);
        larpp[i] = gsm_add(temp1, temp1);
    }
}

/// Interpolate the previous/current decoded LARs to the per-region `LARp` (§4.2.9.1), for the four
/// sub-frame regions selected by `region` (0 = samples 0..12, 1 = 13..26, 2 = 27..39, 3 = 40..159).
fn interpolate_lar(prev: &[i16; 8], cur: &[i16; 8], region: usize, larp: &mut [i16; 8]) {
    for i in 0..8 {
        larp[i] = match region {
            0 => {
                let t = gsm_add(prev[i] >> 2, cur[i] >> 2);
                gsm_add(t, prev[i] >> 1)
            }
            1 => gsm_add(prev[i] >> 1, cur[i] >> 1),
            2 => {
                let t = gsm_add(prev[i] >> 2, cur[i] >> 2);
                gsm_add(t, cur[i] >> 1)
            }
            _ => cur[i],
        };
    }
}

fn larp_to_rp(larp: &mut [i16; 8]) {
    for lp in larp.iter_mut() {
        if *lp < 0 {
            let temp = if *lp as i32 == MIN_WORD {
                MAX_WORD as i16
            } else {
                -*lp
            };
            let mapped = if temp < 11059 {
                ((i32::from(temp)) << 1) as i16
            } else if temp < 20070 {
                temp + 11059
            } else {
                gsm_add(temp >> 2, 26112)
            };
            *lp = -mapped;
        } else {
            let temp = *lp;
            *lp = if temp < 11059 {
                ((i32::from(temp)) << 1) as i16
            } else if temp < 20070 {
                temp + 11059
            } else {
                gsm_add(temp >> 2, 26112)
            };
        }
    }
}

/// Short-term analysis lattice filter (§4.2.10): `s` in place becomes the residual `d`.
fn short_term_analysis_filter(u: &mut [i16; 8], rp: &[i16; 8], s: &mut [i16]) {
    for sample in s.iter_mut() {
        let mut di = *sample;
        let mut sav = *sample;
        for i in 0..8 {
            let ui = u[i];
            let rpi = rp[i];
            u[i] = sav;
            let zzz = gsm_mult_r(rpi, di);
            sav = gsm_add(ui, zzz);
            let zzz = gsm_mult_r(rpi, ui);
            di = gsm_add(di, zzz);
        }
        *sample = di;
    }
}

/// Short-term synthesis lattice filter (§4.3.4): `wt` → `s`.
fn short_term_synthesis_filter(v: &mut [i16; 9], rrp: &[i16; 8], wt: &[i16], s: &mut [i16]) {
    for (out, &w) in s.iter_mut().zip(wt.iter()) {
        let mut sri = w;
        for i in (0..8).rev() {
            let tmp2 = gsm_mult_r(rrp[i], v[i]);
            sri = gsm_sub(sri, tmp2);
            let tmp1 = gsm_mult_r(rrp[i], sri);
            v[i + 1] = gsm_add(v[i], tmp1);
        }
        v[0] = sri;
        *out = sri;
    }
}

// ---- §4.2.11–4.2.12 Long-term prediction (encoder) ---------------------------------------------

fn calc_ltp_params(d: &[i16], dp0: &[i16; 280], base: usize) -> (i16, i16) {
    let mut dmax = 0i16;
    for &v in d.iter().take(40) {
        let temp = gsm_abs(v);
        if temp > dmax {
            dmax = temp;
        }
    }
    let scal = if dmax == 0 {
        0
    } else {
        let temp = gsm_norm(i32::from(dmax) << 16);
        if temp > 6 {
            0
        } else {
            6 - temp
        }
    };
    let mut wt = [0i16; 40];
    for k in 0..40 {
        wt[k] = d[k] >> scal;
    }
    let mut l_max = 0i64;
    let mut nc = 40i16;
    for lambda in 40..=120usize {
        let mut l_result = 0i64;
        for k in 0..40 {
            l_result += i64::from(wt[k]) * i64::from(dp0[base + k - lambda]);
        }
        if l_result > l_max {
            nc = lambda as i16;
            l_max = l_result;
        }
    }
    l_max <<= 1;
    l_max >>= 6 - i64::from(scal);
    let mut l_power = 0i64;
    for k in 0..40 {
        let l_temp = i64::from(dp0[base + k - nc as usize] >> 3);
        l_power += l_temp * l_temp;
    }
    l_power <<= 1;
    if l_max <= 0 {
        return (nc, 0);
    }
    if l_max >= l_power {
        return (nc, 3);
    }
    let temp = gsm_norm(l_power as i32);
    let r = ((l_max << temp) >> 16) as i16;
    let s = ((l_power << temp) >> 16) as i16;
    let mut bc = 3i16;
    for cand in 0..=2i16 {
        if r <= gsm_mult(s, GSM_DLB[cand as usize]) {
            bc = cand;
            break;
        }
    }
    (nc, bc)
}

fn long_term_analysis_filtering(
    bc: i16,
    nc: i16,
    dp0: &mut [i16; 280],
    base: usize,
    d: &[i16],
    e: &mut [i16; 50],
) {
    let bp = GSM_QLB[bc as usize];
    for k in 0..40 {
        dp0[base + k] = gsm_mult_r(bp, dp0[base + k - nc as usize]);
        e[5 + k] = gsm_sub(d[k], dp0[base + k]);
    }
}

// ---- §4.2.13–4.2.17 RPE encoding ---------------------------------------------------------------

fn weighting_filter(e: &[i16; 50], x: &mut [i16; 40]) {
    // libgsm shifts the pointer back by 5 so `e[k+i]` reads e[k+i] in the 50-word buffer.
    const TAPS: [(usize, i32); 9] = [
        (0, -134),
        (1, -374),
        (3, 2054),
        (4, 5741),
        (5, 8192),
        (6, 5741),
        (7, 2054),
        (9, -374),
        (10, -134),
    ];
    for k in 0..40 {
        let mut l_result = 8192i32 >> 1;
        for &(i, h) in TAPS.iter() {
            l_result += i32::from(e[k + i]) * h;
        }
        l_result >>= 13;
        x[k] = saturate(l_result);
    }
}

fn rpe_grid_selection(x: &[i16; 40], xm: &mut [i16; 13], mc_out: &mut i16) {
    let mut em = 0i64;
    let mut mc = 0i16;
    for m in 0..4i16 {
        let mut l_result = 0i64;
        for i in 0..13usize {
            let temp = i64::from(x[m as usize + 3 * i] >> 2);
            l_result += temp * temp;
        }
        l_result <<= 1;
        if l_result > em {
            mc = m;
            em = l_result;
        }
    }
    for i in 0..13 {
        xm[i] = x[mc as usize + 3 * i];
    }
    *mc_out = mc;
}

fn xmaxc_to_exp_mant(xmaxc: i16) -> (i16, i16) {
    let mut exp = 0i16;
    if xmaxc > 15 {
        exp = (xmaxc >> 3) - 1;
    }
    let mut mant = xmaxc - (exp << 3);
    if mant == 0 {
        (-4, 7)
    } else {
        while mant <= 7 {
            mant = (mant << 1) | 1;
            exp -= 1;
        }
        mant -= 8;
        (exp, mant)
    }
}

fn apcm_quantization(xm: &[i16; 13], xmc: &mut [i16], xmaxc_out: &mut i16) {
    let mut xmax = 0i16;
    for &v in xm.iter() {
        let temp = gsm_abs(v);
        if temp > xmax {
            xmax = temp;
        }
    }
    let mut exp = 0i16;
    let mut temp = xmax >> 9;
    let mut itest = 0i16;
    for _ in 0..=5 {
        itest |= i16::from(temp <= 0);
        temp >>= 1;
        if itest == 0 {
            exp += 1;
        }
    }
    let temp = exp + 5;
    let xmaxc = gsm_add(xmax >> temp, exp << 3);
    let (exp, mant) = xmaxc_to_exp_mant(xmaxc);
    let temp1 = 6 - exp;
    let temp2 = GSM_NRFAC[mant as usize];
    for i in 0..13 {
        let t = ((i32::from(xm[i])) << temp1) as i16;
        let t = gsm_mult(t, temp2);
        xmc[i] = (t >> 12) + 4;
    }
    *xmaxc_out = xmaxc;
}

fn apcm_inverse_quantization(xmc: &[i16], mant: i16, exp: i16, xmp: &mut [i16; 13]) {
    let temp1 = GSM_FAC[mant as usize];
    let temp2 = gsm_sub(6, exp);
    let temp3 = gsm_asl(1, i32::from(gsm_sub(temp2, 1)));
    for i in 0..13 {
        let mut temp = (xmc[i] << 1) - 7; // restore sign
        temp = (i32::from(temp) << 12) as i16;
        temp = gsm_mult_r(temp1, temp);
        temp = gsm_add(temp, temp3);
        xmp[i] = gsm_asr(temp, i32::from(temp2));
    }
}

fn rpe_grid_positioning(mc: i16, xmp: &[i16; 13], ep: &mut [i16]) {
    for v in ep.iter_mut().take(40) {
        *v = 0;
    }
    for i in 0..13 {
        ep[mc as usize + 3 * i] = xmp[i];
    }
}

// ---- §4.3 Decoder ------------------------------------------------------------------------------

fn long_term_synthesis_filtering(state: &mut GsmState, ncr: i16, bcr: i16, erp: &[i16; 40]) {
    let nr = if !(40..=120).contains(&ncr) {
        state.nrp
    } else {
        ncr
    };
    state.nrp = nr;
    let brp = GSM_QLB[bcr as usize];
    for (k, &e) in erp.iter().enumerate() {
        let drpp = gsm_mult_r(brp, state.dp0[120 + k - nr as usize]);
        state.dp0[120 + k] = gsm_add(e, drpp);
    }
    state.dp0.copy_within(40..160, 0);
}

fn postprocess(state: &mut GsmState, s: &mut [i16]) {
    let mut msr = state.msr;
    for sample in s.iter_mut() {
        let tmp = gsm_mult_r(msr, 28180);
        msr = gsm_add(*sample, tmp);
        *sample = ((gsm_add(msr, msr) as u16) & 0xFFF8) as i16;
    }
    state.msr = msr;
}

// ---- Frame encode / decode ---------------------------------------------------------------------

/// Encode 160 PCM samples into the quantized parameter set (libgsm `Gsm_Coder`).
fn encode_frame(state: &mut GsmState, pcm: &[i16]) -> Frame {
    let mut so = [0i16; FRAME_SAMPLES];
    preprocess(state, pcm, &mut so);
    let mut frame = Frame::zero();
    lpc_analysis(&mut so, &mut frame.larc);

    // Short-term analysis filter (four interpolation regions) — `so` becomes the residual `d`.
    {
        let j = state.j;
        state.j ^= 1;
        let prev = state.larpp[state.j];
        let mut cur = state.larpp[j];
        decode_lar(&frame.larc, &mut cur);
        state.larpp[j] = cur;
        for (region, &(start, len)) in [(0usize, 13usize), (13, 14), (27, 13), (40, 120)]
            .iter()
            .enumerate()
        {
            let mut larp = [0i16; 8];
            interpolate_lar(&prev, &cur, region, &mut larp);
            larp_to_rp(&mut larp);
            short_term_analysis_filter(&mut state.u, &larp, &mut so[start..start + len]);
        }
    }

    let mut e = [0i16; 50];
    for k in 0..4 {
        let base = 120 + k * 40;
        let d = &so[k * 40..k * 40 + 40];
        let (nc, bc) = calc_ltp_params(d, &state.dp0, base);
        frame.nc[k] = nc;
        frame.bc[k] = bc;
        long_term_analysis_filtering(bc, nc, &mut state.dp0, base, d, &mut e);

        // RPE encoding of the LTP residual e[5..45].
        let mut x = [0i16; 40];
        weighting_filter(&e, &mut x);
        let mut xm = [0i16; 13];
        let mut mc = 0i16;
        rpe_grid_selection(&x, &mut xm, &mut mc);
        frame.mc[k] = mc;
        let mut xmaxc = 0i16;
        apcm_quantization(&xm, &mut frame.xmc[k * 13..k * 13 + 13], &mut xmaxc);
        frame.xmaxc[k] = xmaxc;
        let (exp, mant) = xmaxc_to_exp_mant(xmaxc);
        let mut xmp = [0i16; 13];
        apcm_inverse_quantization(&frame.xmc[k * 13..k * 13 + 13], mant, exp, &mut xmp);
        rpe_grid_positioning(mc, &xmp, &mut e[5..45]);

        // Reconstruct the short-term residual into the history (e[5+i] residual + prediction dpp).
        for i in 0..40 {
            state.dp0[base + i] = gsm_add(e[5 + i], state.dp0[base + i]);
        }
    }
    state.dp0.copy_within(160..280, 0);
    frame
}

/// Decode the quantized parameter set into 160 PCM samples (libgsm `Gsm_Decoder`).
fn decode_frame(state: &mut GsmState, frame: &Frame) -> [i16; FRAME_SAMPLES] {
    let mut wt = [0i16; FRAME_SAMPLES];
    for j in 0..4 {
        let (exp, mant) = xmaxc_to_exp_mant(frame.xmaxc[j]);
        let mut xmp = [0i16; 13];
        apcm_inverse_quantization(&frame.xmc[j * 13..j * 13 + 13], mant, exp, &mut xmp);
        let mut erp = [0i16; 40];
        rpe_grid_positioning(frame.mc[j], &xmp, &mut erp);
        long_term_synthesis_filtering(state, frame.nc[j], frame.bc[j], &erp);
        wt[j * 40..j * 40 + 40].copy_from_slice(&state.dp0[120..160]);
    }
    let mut s = [0i16; FRAME_SAMPLES];
    {
        let j = state.j;
        state.j ^= 1;
        let prev = state.larpp[state.j];
        let mut cur = state.larpp[j];
        decode_lar(&frame.larc, &mut cur);
        state.larpp[j] = cur;
        for (region, &(start, len)) in [(0usize, 13usize), (13, 14), (27, 13), (40, 120)]
            .iter()
            .enumerate()
        {
            let mut larp = [0i16; 8];
            interpolate_lar(&prev, &cur, region, &mut larp);
            larp_to_rp(&mut larp);
            short_term_synthesis_filter(
                &mut state.v,
                &larp,
                &wt[start..start + len],
                &mut s[start..start + len],
            );
        }
    }
    postprocess(state, &mut s);
    s
}

// ---- RFC 3551 §4.5.8 / TS 46.010 bit packing (260 bits + 0xD magic → 33 bytes, MSB-first) -------

fn pack(frame: &Frame) -> [u8; FRAME_BYTES] {
    let l = &frame.larc;
    let (nc, bc, mc, xx, x) = (&frame.nc, &frame.bc, &frame.mc, &frame.xmaxc, &frame.xmc);
    let mut c = [0u8; FRAME_BYTES];
    // Helper: low bits of a parameter.
    let b = |v: i16| v as u32;
    c[0] = (0xD << 4) | ((b(l[0]) >> 2) & 0xF) as u8;
    c[1] = (((b(l[0]) & 0x3) << 6) | (b(l[1]) & 0x3F)) as u8;
    c[2] = (((b(l[2]) & 0x1F) << 3) | ((b(l[3]) >> 2) & 0x7)) as u8;
    c[3] = (((b(l[3]) & 0x3) << 6) | ((b(l[4]) & 0xF) << 2) | ((b(l[5]) >> 2) & 0x3)) as u8;
    c[4] = (((b(l[5]) & 0x3) << 6) | ((b(l[6]) & 0x7) << 3) | (b(l[7]) & 0x7)) as u8;
    // Four sub-frames, 7 bytes each.
    for s in 0..4 {
        let o = 5 + s * 7;
        let xb = s * 13;
        let xc = |i: usize| b(x[xb + i]);
        c[o] = (((b(nc[s]) & 0x7F) << 1) | ((b(bc[s]) >> 1) & 0x1)) as u8;
        c[o + 1] =
            (((b(bc[s]) & 0x1) << 7) | ((b(mc[s]) & 0x3) << 5) | ((b(xx[s]) >> 1) & 0x1F)) as u8;
        c[o + 2] = (((b(xx[s]) & 0x1) << 7)
            | ((xc(0) & 0x7) << 4)
            | ((xc(1) & 0x7) << 1)
            | ((xc(2) >> 2) & 0x1)) as u8;
        c[o + 3] = (((xc(2) & 0x3) << 6) | ((xc(3) & 0x7) << 3) | (xc(4) & 0x7)) as u8;
        c[o + 4] = (((xc(5) & 0x7) << 5) | ((xc(6) & 0x7) << 2) | ((xc(7) >> 1) & 0x3)) as u8;
        c[o + 5] = (((xc(7) & 0x1) << 7)
            | ((xc(8) & 0x7) << 4)
            | ((xc(9) & 0x7) << 1)
            | ((xc(10) >> 2) & 0x1)) as u8;
        c[o + 6] = (((xc(10) & 0x3) << 6) | ((xc(11) & 0x7) << 3) | (xc(12) & 0x7)) as u8;
    }
    c
}

fn unpack(c: &[u8]) -> Frame {
    let mut f = Frame::zero();
    let g = |b: u8| u32::from(b);
    f.larc[0] = (((g(c[0]) & 0xF) << 2) | ((g(c[1]) >> 6) & 0x3)) as i16;
    f.larc[1] = (g(c[1]) & 0x3F) as i16;
    f.larc[2] = ((g(c[2]) >> 3) & 0x1F) as i16;
    f.larc[3] = (((g(c[2]) & 0x7) << 2) | ((g(c[3]) >> 6) & 0x3)) as i16;
    f.larc[4] = ((g(c[3]) >> 2) & 0xF) as i16;
    f.larc[5] = (((g(c[3]) & 0x3) << 2) | ((g(c[4]) >> 6) & 0x3)) as i16;
    f.larc[6] = ((g(c[4]) >> 3) & 0x7) as i16;
    f.larc[7] = (g(c[4]) & 0x7) as i16;
    for s in 0..4 {
        let o = 5 + s * 7;
        let xb = s * 13;
        f.nc[s] = ((g(c[o]) >> 1) & 0x7F) as i16;
        f.bc[s] = (((g(c[o]) & 0x1) << 1) | ((g(c[o + 1]) >> 7) & 0x1)) as i16;
        f.mc[s] = ((g(c[o + 1]) >> 5) & 0x3) as i16;
        f.xmaxc[s] = (((g(c[o + 1]) & 0x1F) << 1) | ((g(c[o + 2]) >> 7) & 0x1)) as i16;
        f.xmc[xb] = ((g(c[o + 2]) >> 4) & 0x7) as i16;
        f.xmc[xb + 1] = ((g(c[o + 2]) >> 1) & 0x7) as i16;
        f.xmc[xb + 2] = (((g(c[o + 2]) & 0x1) << 2) | ((g(c[o + 3]) >> 6) & 0x3)) as i16;
        f.xmc[xb + 3] = ((g(c[o + 3]) >> 3) & 0x7) as i16;
        f.xmc[xb + 4] = (g(c[o + 3]) & 0x7) as i16;
        f.xmc[xb + 5] = ((g(c[o + 4]) >> 5) & 0x7) as i16;
        f.xmc[xb + 6] = ((g(c[o + 4]) >> 2) & 0x7) as i16;
        f.xmc[xb + 7] = (((g(c[o + 4]) & 0x3) << 1) | ((g(c[o + 5]) >> 7) & 0x1)) as i16;
        f.xmc[xb + 8] = ((g(c[o + 5]) >> 4) & 0x7) as i16;
        f.xmc[xb + 9] = ((g(c[o + 5]) >> 1) & 0x7) as i16;
        f.xmc[xb + 10] = (((g(c[o + 5]) & 0x1) << 2) | ((g(c[o + 6]) >> 6) & 0x3)) as i16;
        f.xmc[xb + 11] = ((g(c[o + 6]) >> 3) & 0x7) as i16;
        f.xmc[xb + 12] = (g(c[o + 6]) & 0x7) as i16;
    }
    f
}

/// A GSM 06.10 Full-Rate codec instance (used as *either* a [`Decoder`] *or* an [`Encoder`]).
#[derive(Debug, Clone)]
pub struct GsmFr {
    params: CodecParams,
    state: GsmState,
}

impl GsmFr {
    /// Create a GSM-FR codec (8 kHz mono, fixed 20 ms framing).
    #[must_use]
    pub fn new() -> Self {
        Self {
            params: CodecParams {
                sample_rate_hz: 8_000,
                channels: 1,
                ptime_ms: 20, // GSM-FR is always 20 ms / 160 samples
            },
            state: GsmState::new(),
        }
    }

    /// The codec's parameters (8 kHz, mono).
    #[must_use]
    pub fn params(&self) -> CodecParams {
        self.params
    }

    /// Samples per frame (always 160).
    #[must_use]
    pub fn frame_samples(&self) -> usize {
        FRAME_SAMPLES
    }
}

impl Default for GsmFr {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for GsmFr {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        FRAME_SAMPLES
    }

    fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
        if !payload.len().is_multiple_of(FRAME_BYTES) {
            return Err(CodecError::Malformed(
                "GSM payload not a multiple of 33 bytes",
            ));
        }
        let frames = payload.len() / FRAME_BYTES;
        let samples = frames * FRAME_SAMPLES;
        if out.len() < samples {
            return Err(CodecError::OutputTooSmall {
                needed: samples,
                have: out.len(),
            });
        }
        for f in 0..frames {
            let frame = unpack(&payload[f * FRAME_BYTES..f * FRAME_BYTES + FRAME_BYTES]);
            let pcm = decode_frame(&mut self.state, &frame);
            out[f * FRAME_SAMPLES..f * FRAME_SAMPLES + FRAME_SAMPLES].copy_from_slice(&pcm);
        }
        Ok(samples)
    }

    fn conceal(&mut self, out: &mut [i16]) -> Result<usize, CodecError> {
        // Basic PLC: comfort silence (the project floor). A TS 06.11 substitution/muting frame is a
        // later refinement; the adaptive state is left untouched.
        let count = FRAME_SAMPLES.min(out.len());
        out[..count].fill(0);
        Ok(count)
    }
}

impl Encoder for GsmFr {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        FRAME_SAMPLES
    }

    fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, CodecError> {
        if !pcm.len().is_multiple_of(FRAME_SAMPLES) {
            return Err(CodecError::BadFrameSize {
                expected: FRAME_SAMPLES,
                got: pcm.len(),
            });
        }
        let frames = pcm.len() / FRAME_SAMPLES;
        let bytes = frames * FRAME_BYTES;
        if out.len() < bytes {
            return Err(CodecError::OutputTooSmall {
                needed: bytes,
                have: out.len(),
            });
        }
        for f in 0..frames {
            let frame = encode_frame(
                &mut self.state,
                &pcm[f * FRAME_SAMPLES..f * FRAME_SAMPLES + FRAME_SAMPLES],
            );
            out[f * FRAME_BYTES..f * FRAME_BYTES + FRAME_BYTES].copy_from_slice(&pack(&frame));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f64::consts::PI;

    fn band_limited(n: usize) -> Vec<i16> {
        (0..n)
            .map(|k| {
                let t = k as f64 / 8_000.0;
                let v = 0.4 * (2.0 * PI * 350.0 * t).sin() + 0.25 * (2.0 * PI * 1100.0 * t).sin();
                (v * 8_000.0) as i16
            })
            .collect()
    }

    #[test]
    fn reports_8k_160_sample_frames() {
        let codec = GsmFr::new();
        assert_eq!(codec.params().sample_rate_hz, 8_000);
        assert_eq!(codec.frame_samples(), 160);
        assert_eq!(Encoder::rtp_clock_rate_hz(&codec), 8_000);
    }

    #[test]
    fn encodes_160_samples_to_33_bytes() {
        let mut codec = GsmFr::new();
        let pcm = band_limited(160);
        let mut out = vec![0u8; 33];
        assert_eq!(codec.encode(&pcm, &mut out).expect("encode"), 33);
        // The first nibble carries the GSM magic 0xD (RFC 3551 §4.5.8 / TS 46.010).
        assert_eq!(out[0] >> 4, 0xD);
    }

    #[test]
    fn pack_unpack_roundtrips_parameters() {
        // A frame with structured parameter values must survive pack→unpack exactly (every field
        // width is respected).
        let mut frame = Frame::zero();
        frame.larc = [60, 1, 30, 28, 14, 13, 6, 5];
        frame.nc = [120, 90, 45, 100];
        frame.bc = [0, 1, 2, 3];
        frame.mc = [0, 1, 2, 3];
        frame.xmaxc = [63, 40, 1, 32];
        for (i, v) in frame.xmc.iter_mut().enumerate() {
            *v = (i % 8) as i16;
        }
        assert_eq!(unpack(&pack(&frame)), frame);
    }

    #[test]
    fn decode_produces_160_samples_per_frame() {
        let mut codec = GsmFr::new();
        let payload = vec![0u8; 33];
        let mut out = vec![0i16; 160];
        assert_eq!(codec.decode(&payload, &mut out).expect("decode"), 160);
    }

    #[test]
    fn encode_is_deterministic_across_fresh_instances() {
        let pcm = band_limited(320); // two frames
        let mut a = vec![0u8; 66];
        let mut b = vec![0u8; 66];
        GsmFr::new().encode(&pcm, &mut a).expect("a");
        GsmFr::new().encode(&pcm, &mut b).expect("b");
        assert_eq!(a, b, "no hidden global state");
    }

    #[test]
    fn roundtrip_reconstructs_band_limited_signal() {
        // GSM-FR is lossy but must clearly track a voiced signal. Use many frames so the predictors
        // converge, and measure steady-state SNR over the best alignment lag.
        let n = 160 * 25;
        let input = band_limited(n);
        let mut encoder = GsmFr::new();
        let mut payload = vec![0u8; (n / 160) * 33];
        encoder.encode(&input, &mut payload).expect("encode");
        let mut decoder = GsmFr::new();
        let mut output = vec![0i16; n];
        decoder.decode(&payload, &mut output).expect("decode");

        let region = 800..(n - 160);
        let signal: f64 = region.clone().map(|k| f64::from(input[k]).powi(2)).sum();
        let mut best = f64::NEG_INFINITY;
        for lag in 0..160usize {
            let error: f64 = region
                .clone()
                .map(|k| (f64::from(input[k]) - f64::from(output[k + lag])).powi(2))
                .sum();
            if error > 0.0 {
                best = best.max(10.0 * (signal / error).log10());
            }
        }
        assert!(best > 6.0, "GSM-FR round-trip SNR too low: {best:.1} dB");
    }

    #[test]
    fn encode_rejects_non_frame_length() {
        let mut codec = GsmFr::new();
        let pcm = [0i16; 100];
        let mut out = [0u8; 33];
        assert!(matches!(
            codec.encode(&pcm, &mut out),
            Err(CodecError::BadFrameSize { .. })
        ));
    }

    #[test]
    fn decode_rejects_bad_payload_length() {
        let mut codec = GsmFr::new();
        let payload = [0u8; 20];
        let mut out = [0i16; 160];
        assert!(matches!(
            codec.decode(&payload, &mut out),
            Err(CodecError::Malformed(_))
        ));
    }

    #[test]
    fn decodes_arbitrary_bytes_without_panicking() {
        // A hostile/truncated GSM frame must decode-or-error, never panic / index out of bounds.
        let mut codec = GsmFr::new();
        let payload: Vec<u8> = (0..33u32 * 8)
            .map(|k| (k.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let mut out = vec![0i16; payload.len() / 33 * 160];
        assert!(codec.decode(&payload, &mut out).is_ok());
    }

    // ---- ETSI / 3GPP TS 06.10 bit-exact conformance --------------------------------------------

    fn vector_path(name: &str) -> std::path::PathBuf {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../reference/gsm-fr/testv");
        path.push(name);
        path
    }

    fn read_i16_le(bytes: &[u8]) -> Vec<i16> {
        bytes
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect()
    }

    /// Parse a `.cod` test vector: 76 little-endian u16 parameters per frame, in `gsm_explode`
    /// order (LARc[0..7] then 4× Nc, bc, Mc, xmaxc, xMc[0..12]).
    fn parse_cod(bytes: &[u8]) -> Vec<Frame> {
        let words: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        words
            .chunks_exact(76)
            .map(|w| {
                let mut f = Frame::zero();
                for (dst, &src) in f.larc.iter_mut().zip(w[..8].iter()) {
                    *dst = src as i16;
                }
                for sf in 0..4 {
                    let o = 8 + sf * 17;
                    f.nc[sf] = w[o] as i16;
                    f.bc[sf] = w[o + 1] as i16;
                    f.mc[sf] = w[o + 2] as i16;
                    f.xmaxc[sf] = w[o + 3] as i16;
                    for i in 0..13 {
                        f.xmc[sf * 13 + i] = w[o + 4 + i] as i16;
                    }
                }
                f
            })
            .collect()
    }

    #[test]
    fn etsi_seq01_coder_bit_exact() {
        // Encode Seq01.inp (LE i16 PCM, 160/frame) and require the produced 76-parameter Frame to
        // match Seq01.cod exactly, frame by frame (ETSI TS 06.10, no tolerance). Gitignored vectors
        // → skip gracefully when absent.
        let (Ok(inp), Ok(cod)) = (
            std::fs::read(vector_path("Seq01.inp")),
            std::fs::read(vector_path("Seq01.cod")),
        ) else {
            eprintln!("GSM 06.10 vectors absent — skipping coder conformance");
            return;
        };
        let input = read_i16_le(&inp);
        let expected = parse_cod(&cod);
        assert_eq!(input.len() / 160, expected.len(), "Seq01 length mismatch");
        let mut state = GsmState::new();
        for (k, want) in expected.iter().enumerate() {
            let got = encode_frame(&mut state, &input[k * 160..k * 160 + 160]);
            assert_eq!(got, *want, "coder parameter mismatch at frame {k}");
        }
    }

    fn decoder_bit_exact(cod_name: &str, out_name: &str) {
        let (Ok(cod), Ok(out)) = (
            std::fs::read(vector_path(cod_name)),
            std::fs::read(vector_path(out_name)),
        ) else {
            eprintln!("GSM 06.10 vectors absent — skipping decoder conformance ({cod_name})");
            return;
        };
        let frames = parse_cod(&cod);
        let ref_pcm = read_i16_le(&out);
        assert_eq!(
            frames.len() * 160,
            ref_pcm.len(),
            "{cod_name} length mismatch"
        );
        let mut state = GsmState::new();
        for (k, frame) in frames.iter().enumerate() {
            let got = decode_frame(&mut state, frame);
            assert_eq!(
                &got[..],
                &ref_pcm[k * 160..k * 160 + 160],
                "decoder sample mismatch at frame {k} ({cod_name})"
            );
        }
    }

    #[test]
    fn etsi_seq01_decoder_bit_exact() {
        decoder_bit_exact("Seq01.cod", "Seq01.out");
    }

    #[test]
    fn etsi_seq05_decoder_bit_exact() {
        // Seq05 is a decode-only sequence.
        decoder_bit_exact("Seq05.cod", "Seq05.out");
    }
}
