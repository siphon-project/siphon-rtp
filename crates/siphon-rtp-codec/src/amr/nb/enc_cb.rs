//! AMR-NB ENCODER algebraic (fixed) codebook search tier — 3GPP TS 26.073.
//!
//! Ports the per-mode fixed-codebook search dispatch [`cbsearch`] (`cbsearch.c`) and its shared
//! helpers: `cor_h_x` (`cor_h.c` `cor_h_x`/`cor_h_x2` — the target×impulse-response correlation
//! `dn[]`), `cor_h` (`cor_h.c` `cor_h` — the sign-folded impulse-response autocorrelation matrix
//! `rr[][]`), `set_sign` / `set_sign12k2` (`set_sign.c` — the pulse sign vector + track maxima /
//! starting positions), and the per-mode searches ported so far:
//!  * MR122 (12.2 kbit/s): `c1035pf.c` `code_10i40_35bits` — 10 pulses / 5 tracks, depth-first via
//!    `s10_8pf.c` `search_10and8i40` (GSM-EFR flavour, `gsmefrFlag = 1`).
//!  * MR475 & MR515 (4.75 / 5.15 kbit/s): `c2_9pf.c` `code_2i40_9bits` — 2 pulses / 9-bit index.
//!  * MR59 (5.90 kbit/s): `c2_11pf.c` `code_2i40_11bits` — 2 pulses / 11-bit index (fixed 2×4 track
//!    grid). Shares the two-pulse inner search kernel with the 9-bit codebook.
//!  * MR67 (6.70 kbit/s): `c3_14pf.c` `code_3i40_14bits` — 3 pulses / 14-bit index. First user of the
//!    [`set_sign`] `dn2` per-track pruning (`n = 6`).
//!
//! The remaining modes' searches (`c4_17pf` MR74/MR795, `c8_31pf` MR102) are OUT OF SCOPE for this
//! tier — a later extension wires them into [`cbsearch`]'s dispatch (the shared
//! `cor_h_x`/`cor_h`/`set_sign` helpers already generalize).
//!
//! Everything is bit-exact against the fixed-point reference: all arithmetic goes through
//! [`crate::amr::basic_ops`] / `crate::amr::nb::math_nb`, never native integer arithmetic on the
//! DSP path.
//!
//! Pitch sharpening (the "pre/post CB" contribution the reference folds into `h1[]` and `code[]`)
//! is mode-dependent and matches `cbsearch.c` exactly:
//!  * MR122 sharpens with `gain_pit` (the closed-loop pitch gain), applied here in [`cbsearch`].
//!  * MR475/MR515 sharpen with `pitch_sharp` (the encoder's `sharp` state, Q14), applied *inside*
//!    `code_2i40_9bits` as the reference does.
//!
//! `pitch_sharp` is the persistent `st->sharp` (initialized to `SHARPMIN`, updated by tier 6's
//! `subframePostProc` — NOT here). These functions carry no state of their own.
//!
//! Not yet wired into [`crate::amr::nb::enc_main::EncoderState`]'s per-subframe loop — tier 6
//! assembles the loop. The public [`cbsearch`] entry mirrors the C
//! `cbsearch(xn2, h1, T0, sharp, gain_pit, res2, code, y2, &ana, mode, subfrNr)` call so the
//! tier-6 wiring is mechanical.

use crate::amr::basic_ops::{
    add, extract_h, extract_l, l_abs, l_mac, l_msu, l_mult, l_shl, l_shr, mult, negate, norm_l,
    round_word, shl, shr, sub,
};
use crate::amr::nb::constants::{L_CODE, NB_TRACK, STEP};
use crate::amr::nb::math_nb::inv_sqrt;
use crate::amr::AmrNbMode;
use crate::CodecError;

/// Number of pulses in the MR122 (10-pulse) search (`c1035pf.c` `NB_PULSE`).
const NB_PULSE_MR122: usize = 10;
/// Number of pulses in the MR475/MR515 (2-pulse) search (`c2_9pf.c` `NB_PULSE`).
const NB_PULSE_2I40: usize = 2;
/// Number of pulses in the MR67 (3-pulse) search (`c3_14pf.c` `NB_PULSE`).
const NB_PULSE_3I40: usize = 3;

/// `1/2` in Q15 (`(Word16)(32768/2)` = 16384). All these fractions fit a positive `Word16`.
const Q15_1_2: i16 = 16384;
/// `1/4` in Q15.
const Q15_1_4: i16 = 8192;
/// `1/8` in Q15.
const Q15_1_8: i16 = 4096;
/// `1/16` in Q15.
const Q15_1_16: i16 = 2048;
/// `1/32` in Q15.
const Q15_1_32: i16 = 1024;
/// `1/64` in Q15.
const Q15_1_64: i16 = 512;
/// `1/128` in Q15.
const Q15_1_128: i16 = 256;

/// Gray-encode table (`gray.tab` `gray[8]`). NOTE: this is the *encode* table (distinct from the
/// decoder's `dgray[8]` in [`crate::amr::nb::codebook`]).
const GRAY: [i16; 8] = [0, 1, 3, 2, 6, 4, 5, 7];

/// Track start positions for the 9-bit 2-pulse codebook (`c2_9pf.tab` `startPos[2*4*2]`).
#[rustfmt::skip]
const START_POS: [i16; 16] = [
    0, 2, 0, 3,
    0, 2, 0, 3,
    1, 3, 2, 4,
    1, 4, 1, 4,
];

// =============================================================================================
//  Correlation of target with impulse response (cor_h.c cor_h_x / cor_h_x2)
// =============================================================================================

/// `cor_h.c` `cor_h_x` → `cor_h_x2(h, x, dn, sf, NB_TRACK, STEP)` — correlation between the target
/// `x[]` and the impulse response `h[]`:
///   `d[n] = Σ_{i=n}^{L-1} x[i]·h[i-n]`, `n = 0..L_CODE`, normalized so the sum of the 5 per-track
/// maxima cannot saturate. `sf` is the scaling factor (2 for MR122, 1 for the other modes).
fn cor_h_x(h: &[i16], x: &[i16], dn: &mut [i16], sf: i16) {
    let mut y32 = [0i32; L_CODE];
    // tot = 5; accumulate ½·max per track.
    let mut tot: i32 = 5;

    for k in 0..NB_TRACK {
        let mut max: i32 = 0;
        let mut i = k;
        while i < L_CODE {
            let mut s: i32 = 0;
            for j in i..L_CODE {
                s = l_mac(s, x[j], h[j - i]);
            }
            y32[i] = s;
            let s_abs = l_abs(s);
            if crate::amr::basic_ops::l_sub(s_abs, max) > 0 {
                max = s_abs;
            }
            i += STEP;
        }
        tot = crate::amr::basic_ops::l_add(tot, l_shr(max, 1));
    }

    let j = sub(norm_l(tot), sf);
    for i in 0..L_CODE {
        dn[i] = round_word(l_shl(y32[i], j));
    }
}

// =============================================================================================
//  Sign vectors (set_sign.c)
// =============================================================================================

/// `set_sign.c` `set_sign` — build `sign[]` from `dn[]` (used by the non-MR122 searches). Also folds
/// the sign into `dn[]` (`dn[i] = |dn[i]|`) and keeps the `8-n` largest per-track maxima in `dn2[]`
/// (unused by the 2-pulse search — the reference passes `n = 8`, so no maxima are removed).
fn set_sign(dn: &mut [i16], sign: &mut [i16], dn2: &mut [i16], n: i16) {
    for i in 0..L_CODE {
        let mut val = dn[i];
        if val >= 0 {
            sign[i] = 32767;
        } else {
            sign[i] = -32767;
            val = negate(val);
        }
        dn[i] = val; // modify dn[] to carry the fixed sign
        dn2[i] = val;
    }

    // Keep (8-n) maxima per track; store the rest as -1 in dn2[]. (n=8 → no iterations.)
    let keep = sub(8, n);
    for i in 0..NB_TRACK {
        let mut k = 0i16;
        while k < keep {
            let mut min: i16 = 0x7fff;
            let mut pos = 0usize;
            let mut j = i;
            while j < L_CODE {
                if dn2[j] >= 0 {
                    let val = sub(dn2[j], min);
                    if val < 0 {
                        min = dn2[j];
                        pos = j;
                    }
                }
                j += STEP;
            }
            dn2[pos] = -1;
            k = add(k, 1);
        }
    }
}

/// `set_sign.c` `set_sign12k2` — build `sign[]` from `dn[]` and `cn[]` (MR122), fold the sign into
/// `dn[]`, and find the per-track maximum-correlation positions `pos_max[]` plus the starting pulse
/// positions `ipos[]`. `nb_track` = [`NB_TRACK`], `step` = [`STEP`] for MR122.
fn set_sign12k2(
    dn: &mut [i16],
    cn: &[i16],
    sign: &mut [i16],
    pos_max: &mut [i16],
    nb_track: usize,
    ipos: &mut [i16],
    step: usize,
) {
    let mut en = [0i16; L_CODE];

    // Energy normalization scales for cn[] and dn[].
    let mut s: i32 = 256;
    for &c in cn.iter().take(L_CODE) {
        s = l_mac(s, c, c);
    }
    let s = inv_sqrt(s);
    let k_cn = extract_h(l_shl(s, 5));

    let mut s: i32 = 256;
    for &d in dn.iter().take(L_CODE) {
        s = l_mac(s, d, d);
    }
    let s = inv_sqrt(s);
    let k_dn = extract_h(l_shl(s, 5));

    for i in 0..L_CODE {
        let mut val = dn[i];
        let mut cor = round_word(l_shl(l_mac(l_mult(k_cn, cn[i]), k_dn, val), 10));
        if cor >= 0 {
            sign[i] = 32767;
        } else {
            sign[i] = -32767;
            cor = negate(cor);
            val = negate(val);
        }
        dn[i] = val;
        en[i] = cor;
    }

    let mut max_of_all: i16 = -1;
    // `i` is the track index: it seeds the per-track scan (`j = i`), stores `pos_max[i]`, and may
    // become `ipos[0]` — a genuine multi-use index, so keep the range loop.
    #[allow(clippy::needless_range_loop)]
    for i in 0..nb_track {
        let mut max: i16 = -1;
        let mut pos = 0usize;
        let mut j = i;
        while j < L_CODE {
            let cor = en[j];
            if sub(cor, max) > 0 {
                max = cor;
                pos = j;
            }
            j += step;
        }
        pos_max[i] = pos as i16;
        if sub(max, max_of_all) > 0 {
            max_of_all = max;
            ipos[0] = i as i16; // starting position for i0
        }
    }

    // Set the starting position of each pulse.
    let mut pos = ipos[0];
    ipos[nb_track] = pos;
    for i in 1..nb_track {
        pos = add(pos, 1);
        if sub(pos, nb_track as i16) >= 0 {
            pos = 0;
        }
        ipos[i] = pos;
        ipos[add(i as i16, nb_track as i16) as usize] = pos;
    }
}

// =============================================================================================
//  Impulse-response autocorrelation with sign (cor_h.c cor_h)
// =============================================================================================

/// `cor_h.c` `cor_h` — the sign-folded autocorrelation matrix of `h[]`:
///   `rr[i][j] = (Σ_{n} h2[n-i]·h2[n-j]) · sign[i]·sign[j]` for `i >= j`, symmetric otherwise,
/// where `h2[]` is a precision-scaled copy of `h[]`. Written as a flat `L_CODE·L_CODE` matrix
/// (`rr[i*L_CODE + j]`).
fn cor_h(h: &[i16], sign: &[i16], rr: &mut [i16]) {
    let mut h2 = [0i16; L_CODE];

    // Scaling for maximum precision.
    let mut s: i32 = 2;
    for &hv in h.iter().take(L_CODE) {
        s = l_mac(s, hv, hv);
    }
    let j = sub(extract_h(s), 32767);
    if j == 0 {
        for i in 0..L_CODE {
            h2[i] = shr(h[i], 1);
        }
    } else {
        let s = l_shr(s, 1);
        let k = extract_h(l_shl(inv_sqrt(s), 7));
        let k = mult(k, 32440); // k = 0.99·k
        for i in 0..L_CODE {
            h2[i] = round_word(l_shl(l_mult(h[i], k), 9));
        }
    }

    // Diagonal: rr[i][i], i = L_CODE-1 down to 0 (i = L_CODE-1-k).
    let mut s: i32 = 0;
    for (k, &h2k) in h2.iter().enumerate().take(L_CODE) {
        s = l_mac(s, h2k, h2k);
        let i = L_CODE - 1 - k;
        rr[i * L_CODE + i] = round_word(s);
    }

    // Off-diagonals: for each `dec`, i = L_CODE-1-dec-k, j = L_CODE-1-k (symmetric fill).
    for dec in 1..L_CODE {
        let mut s: i32 = 0;
        for k in 0..(L_CODE - dec) {
            s = l_mac(s, h2[k], h2[k + dec]);
            let j = L_CODE - 1 - k;
            let i = j - dec;
            let v = mult(round_word(s), mult(sign[i], sign[j]));
            rr[j * L_CODE + i] = v;
            rr[i * L_CODE + j] = v;
        }
    }
}

// =============================================================================================
//  MR475 / MR515 : 2-pulse 9-bit search (c2_9pf.c)
// =============================================================================================

/// Shared inner search body for the two-pulse codebooks (`c2_9pf.c` / `c2_11pf.c` `search_2i40`):
/// given one track start pair `(ipos0, ipos1)`, scan pulse `i0` over its track and pulse `i1` over its
/// track (both stepping by [`STEP`]) and update the running best `(psk, alpk, codvec)` with the
/// division-free cross-multiply metric `L_msu(L_mult(alp, sq1), sq, alp_16) > 0` (strict `>0`,
/// first-found-wins). The two reference files share this body verbatim (same `_1_4`/`_1_2` weights);
/// only the set of `(ipos0, ipos1)` track pairs differs — MR475/MR515 (9-bit, subframe-dependent) vs
/// MR59 (11-bit, fixed 2×4 grid).
fn search_2i40_track_pair(
    ipos0: i16,
    ipos1: i16,
    dn: &[i16],
    rr: &[i16],
    psk: &mut i16,
    alpk: &mut i16,
    codvec: &mut [i16; NB_PULSE_2I40],
) {
    let rr = |i: usize, j: usize| -> i16 { rr[i * L_CODE + j] };

    // i0 loop: 8 positions.
    let mut i0 = ipos0;
    while (i0 as usize) < L_CODE {
        let ps0 = dn[i0 as usize];
        let alp0 = l_mult(rr(i0 as usize, i0 as usize), Q15_1_4);

        // i1 loop: 8 positions.
        let mut sq: i16 = -1;
        let mut alp: i16 = 1;
        let mut ix = ipos1;

        let mut i1 = ipos1;
        while (i1 as usize) < L_CODE {
            let ps1 = add(ps0, dn[i1 as usize]);
            // alp1 = alp0 + ¼·rr[i1][i1] + ½·rr[i0][i1].
            let mut alp1 = l_mac(alp0, rr(i1 as usize, i1 as usize), Q15_1_4);
            alp1 = l_mac(alp1, rr(i0 as usize, i1 as usize), Q15_1_2);

            let sq1 = mult(ps1, ps1);
            let alp_16 = round_word(alp1);

            let s = l_msu(l_mult(alp, sq1), sq, alp_16);
            if s > 0 {
                sq = sq1;
                alp = alp_16;
                ix = i1;
            }
            i1 += STEP as i16;
        }

        // Memorise the codevector if this one is better.
        let s = l_msu(l_mult(*alpk, sq), *psk, alp);
        if s > 0 {
            *psk = sq;
            *alpk = alp;
            codvec[0] = i0;
            codvec[1] = ix;
        }
        i0 += STEP as i16;
    }
}

/// `c2_9pf.c` `search_2i40` — MR475/MR515 (9-bit) 2-pulse search: 2 track pairs seeded from the
/// subframe-dependent `startPos[]` table.
fn search_2i40(sub_nr: i16, dn: &[i16], rr: &[i16], codvec: &mut [i16; NB_PULSE_2I40]) {
    let mut psk: i16 = -1;
    let mut alpk: i16 = 1;
    for (i, c) in codvec.iter_mut().enumerate() {
        *c = i as i16;
    }

    for track1 in 0i16..2 {
        let ipos0 = START_POS[(sub_nr * 2 + 8 * track1) as usize];
        let ipos1 = START_POS[(sub_nr * 2 + 1 + 8 * track1) as usize];
        search_2i40_track_pair(ipos0, ipos1, dn, rr, &mut psk, &mut alpk, codvec);
    }
}

/// `c2_11pf.c` `search_2i40` — MR59 (11-bit) 2-pulse search: a fixed 2×4 grid of track pairs
/// (`c2_11pf.tab` `startPos1[2]` × `startPos2[4]`), not subframe-dependent. `i0` ranges over 2×8
/// positions (tracks starting at 1, 3), `i1` over 4×8 (tracks starting at 0, 1, 2, 4).
fn search_2i40_11bits(dn: &[i16], rr: &[i16], codvec: &mut [i16; NB_PULSE_2I40]) {
    // c2_11pf.tab: startPos1[2] = {1, 3}; startPos2[4] = {0, 1, 2, 4}.
    const START_POS1: [i16; 2] = [1, 3];
    const START_POS2: [i16; 4] = [0, 1, 2, 4];

    let mut psk: i16 = -1;
    let mut alpk: i16 = 1;
    for (i, c) in codvec.iter_mut().enumerate() {
        *c = i as i16;
    }

    for &ipos0 in &START_POS1 {
        for &ipos1 in &START_POS2 {
            search_2i40_track_pair(ipos0, ipos1, dn, rr, &mut psk, &mut alpk, codvec);
        }
    }
}

/// `c2_9pf.c` `build_code` — build the innovation `cod[]`, filtered code `y[]`, the 2-pulse sign
/// word (`*sign`) and the position index (returned). `subNr` selects the track table.
fn build_code_2i40(
    sub_nr: i16,
    codvec: &[i16; NB_PULSE_2I40],
    dn_sign: &[i16],
    cod: &mut [i16],
    h: &[i16],
    y: &mut [i16],
    sign: &mut i16,
) -> i16 {
    // trackTable[4*5]: -1 == "do not code this position".
    #[rustfmt::skip]
    const TRACK_TABLE: [i16; 4 * 5] = [
        0, 1, 0, 1, -1, // subframe 1
        0, -1, 1, 0, 1, // subframe 2
        0, 1, 0, -1, 1, // subframe 3
        0, 1, -1, 0, 1, // subframe 4
    ];
    let pt_base = add(sub_nr, shl(sub_nr, 2)) as usize; // subNr*5

    for c in cod.iter_mut().take(L_CODE) {
        *c = 0;
    }

    let mut sign_pulses = [0i16; NB_PULSE_2I40];
    let mut indx: i16 = 0;
    let mut rsign: i16 = 0;
    for k in 0..NB_PULSE_2I40 {
        let i = codvec[k];
        let j = dn_sign[i as usize];

        let mut index = mult(i, 6554); // index = pos/5
        let track = sub(i, extract_l(l_shr(l_mult(index, 5), 1))); // track = pos%5
        let first = TRACK_TABLE[pt_base + track as usize];

        let track = if first == 0 {
            if k == 0 {
                0i16
            } else {
                index = shl(index, 3);
                1i16
            }
        } else if k == 0 {
            index = add(index, 64); // table bit is MSB
            0i16
        } else {
            index = shl(index, 3);
            1i16
        };

        if j > 0 {
            cod[i as usize] = 8191;
            sign_pulses[k] = 32767;
            rsign = add(rsign, shl(1, track));
        } else {
            cod[i as usize] = -8192;
            sign_pulses[k] = -32768; // (Word16)-32768
        }
        indx = add(indx, index);
    }
    *sign = rsign;

    // y[i] = round( Σ_k h[i - codvec[k]] · sign_pulses[k] ), reading h[n<0] as 0.
    let p0 = codvec[0];
    let p1 = codvec[1];
    for (i, yi) in y.iter_mut().enumerate().take(L_CODE) {
        let mut s: i32 = 0;
        let n0 = i as isize - p0 as isize;
        if n0 >= 0 {
            s = l_mac(s, h[n0 as usize], sign_pulses[0]);
        }
        let n1 = i as isize - p1 as isize;
        if n1 >= 0 {
            s = l_mac(s, h[n1 as usize], sign_pulses[1]);
        }
        *yi = round_word(s);
    }

    indx
}

/// `c2_9pf.c` `code_2i40_9bits` — MR475/MR515 fixed-codebook search over a 40-sample subframe with
/// 2 pulses. `h` is modified in place with the pitch-sharpening contribution (as the reference does),
/// so the caller must pass a writable copy. Returns the position index and writes the sign word to
/// `sign`.
#[allow(clippy::too_many_arguments)]
fn code_2i40_9bits(
    sub_nr: i16,
    x: &[i16],
    h: &mut [i16],
    t0: i16,
    pitch_sharp: i16,
    code: &mut [i16],
    y: &mut [i16],
    sign: &mut i16,
) -> i16 {
    let sharp = shl(pitch_sharp, 1);
    // Pre-CB pitch sharpening folded into h[] (MR475/MR515 do it here, not in cbsearch).
    if sub(t0, L_CODE as i16) < 0 {
        for i in (t0 as usize)..L_CODE {
            h[i] = add(h[i], mult(h[i - t0 as usize], sharp));
        }
    }

    let mut dn = [0i16; L_CODE];
    let mut dn2 = [0i16; L_CODE];
    let mut dn_sign = [0i16; L_CODE];
    let mut rr = [0i16; L_CODE * L_CODE];
    let mut codvec = [0i16; NB_PULSE_2I40];

    cor_h_x(h, x, &mut dn, 1);
    set_sign(&mut dn, &mut dn_sign, &mut dn2, 8);
    cor_h(h, &dn_sign, &mut rr);
    search_2i40(sub_nr, &dn, &rr, &mut codvec);
    let index = build_code_2i40(sub_nr, &codvec, &dn_sign, code, h, y, sign);

    // Post-CB pitch sharpening folded into code[].
    if sub(t0, L_CODE as i16) < 0 {
        for i in (t0 as usize)..L_CODE {
            code[i] = add(code[i], mult(code[i - t0 as usize], sharp));
        }
    }

    index
}

// =============================================================================================
//  MR59 : 2-pulse 11-bit search (c2_11pf.c)
// =============================================================================================

/// `c2_11pf.c` `build_code` — build the innovation `cod[]`, filtered code `y[]`, the 2-pulse sign word
/// (`*sign`) and the 9-bit position index (returned) for the 11-bit codebook. The index bit-packing
/// differs from the 9-bit codebook: pulse i0 (tracks 1, 3) occupies bits 0-3, pulse i1 (tracks 0, 1,
/// 2, 4) occupies bits 4-8 — see `d2_11pf.c` for the inverse.
fn build_code_2i40_11bits(
    codvec: &[i16; NB_PULSE_2I40],
    dn_sign: &[i16],
    cod: &mut [i16],
    h: &[i16],
    y: &mut [i16],
    sign: &mut i16,
) -> i16 {
    for c in cod.iter_mut().take(L_CODE) {
        *c = 0;
    }

    let mut sign_pulses = [0i16; NB_PULSE_2I40];
    let mut indx: i16 = 0;
    let mut rsign: i16 = 0;
    for k in 0..NB_PULSE_2I40 {
        let i = codvec[k];
        let j = dn_sign[i as usize];

        let mut index = mult(i, 6554); // index = pos/5
        let track = sub(i, extract_l(l_shr(l_mult(index, 5), 1))); // track = pos%5

        // Remap the raw track (pos%5) to the transmitted sign-track and finalize the position bits.
        let track = if track == 0 {
            index = shl(index, 6);
            1i16
        } else if track == 1 {
            if k == 0 {
                index = shl(index, 1);
                0i16
            } else {
                index = add(shl(index, 6), 16);
                1i16
            }
        } else if track == 2 {
            index = add(shl(index, 6), 32);
            1i16
        } else if track == 3 {
            index = add(shl(index, 1), 1);
            0i16
        } else {
            // track == 4
            index = add(shl(index, 6), 48);
            1i16
        };

        if j > 0 {
            cod[i as usize] = 8191;
            sign_pulses[k] = 32767;
            rsign = add(rsign, shl(1, track));
        } else {
            cod[i as usize] = -8192;
            sign_pulses[k] = -32768; // (Word16)-32768
        }
        indx = add(indx, index);
    }
    *sign = rsign;

    // y[i] = round( Σ_k h[i - codvec[k]] · sign_pulses[k] ), reading h[n<0] as 0.
    let p0 = codvec[0];
    let p1 = codvec[1];
    for (i, yi) in y.iter_mut().enumerate().take(L_CODE) {
        let mut s: i32 = 0;
        let n0 = i as isize - p0 as isize;
        if n0 >= 0 {
            s = l_mac(s, h[n0 as usize], sign_pulses[0]);
        }
        let n1 = i as isize - p1 as isize;
        if n1 >= 0 {
            s = l_mac(s, h[n1 as usize], sign_pulses[1]);
        }
        *yi = round_word(s);
    }

    indx
}

/// `c2_11pf.c` `code_2i40_11bits` — MR59 fixed-codebook search over a 40-sample subframe with 2
/// pulses (11-bit index). `h` is modified in place with the pitch-sharpening contribution (as the
/// reference does), so the caller must pass a writable copy. Returns the position index and writes
/// the sign word to `sign`. Unlike the 9-bit search this takes no subframe number.
fn code_2i40_11bits(
    x: &[i16],
    h: &mut [i16],
    t0: i16,
    pitch_sharp: i16,
    code: &mut [i16],
    y: &mut [i16],
    sign: &mut i16,
) -> i16 {
    let sharp = shl(pitch_sharp, 1);
    // Pre-CB pitch sharpening folded into h[] (as the reference does, before the search).
    if sub(t0, L_CODE as i16) < 0 {
        for i in (t0 as usize)..L_CODE {
            h[i] = add(h[i], mult(h[i - t0 as usize], sharp));
        }
    }

    let mut dn = [0i16; L_CODE];
    let mut dn2 = [0i16; L_CODE];
    let mut dn_sign = [0i16; L_CODE];
    let mut rr = [0i16; L_CODE * L_CODE];
    let mut codvec = [0i16; NB_PULSE_2I40];

    cor_h_x(h, x, &mut dn, 1);
    set_sign(&mut dn, &mut dn_sign, &mut dn2, 8); // dn2[] unused in this search (n = 8)
    cor_h(h, &dn_sign, &mut rr);
    search_2i40_11bits(&dn, &rr, &mut codvec);
    let index = build_code_2i40_11bits(&codvec, &dn_sign, code, h, y, sign);

    // Post-CB pitch sharpening folded into code[].
    if sub(t0, L_CODE as i16) < 0 {
        for i in (t0 as usize)..L_CODE {
            code[i] = add(code[i], mult(code[i - t0 as usize], sharp));
        }
    }

    index
}

// =============================================================================================
//  MR67 : 3-pulse 14-bit search (c3_14pf.c)
// =============================================================================================

/// `c3_14pf.c` `search_3i40` — MR67 (14-bit) 3-pulse search: pulse i0 on track 0 (positions
/// 0,5,…,35), i1 on tracks {1,3}, i2 on tracks {2,4}, over a 2×2 grid of starting tracks with a
/// 3-way cyclic permutation of the pulse-start positions. `dn2` carries the per-track pruning from
/// [`set_sign`] (called with `n = 6`): only i0 positions whose `dn2[i0] >= 0` (the 6 largest of each
/// track's 8) are searched.
fn search_3i40(dn: &[i16], dn2: &[i16], rr: &[i16], codvec: &mut [i16; NB_PULSE_3I40]) {
    let step = STEP as i16;
    let rr = |i: usize, j: usize| -> i16 { rr[i * L_CODE + j] };

    let mut psk: i16 = -1;
    let mut alpk: i16 = 1;
    for (i, c) in codvec.iter_mut().enumerate() {
        *c = i as i16;
    }

    let mut track1 = 1i16;
    while track1 < 4 {
        let mut track2 = 2i16;
        while track2 < 5 {
            let mut ipos = [0i16, track1, track2];

            // Try the 3 cyclic rotations of (ipos[0], ipos[1], ipos[2]).
            for _ in 0..NB_PULSE_3I40 {
                let mut i0 = ipos[0];
                while (i0 as usize) < L_CODE {
                    if dn2[i0 as usize] >= 0 {
                        let ps0 = dn[i0 as usize];
                        let alp0 = l_mult(rr(i0 as usize, i0 as usize), Q15_1_4);

                        // i1 loop: 8 positions.
                        let mut sq: i16 = -1;
                        let mut alp: i16 = 1;
                        let mut ps: i16 = 0;
                        let mut ix = ipos[1];
                        let mut i1 = ipos[1];
                        while (i1 as usize) < L_CODE {
                            let ps1 = add(ps0, dn[i1 as usize]);
                            let mut alp1 = l_mac(alp0, rr(i1 as usize, i1 as usize), Q15_1_4);
                            alp1 = l_mac(alp1, rr(i0 as usize, i1 as usize), Q15_1_2);
                            let sq1 = mult(ps1, ps1);
                            let alp_16 = round_word(alp1);
                            let s = l_msu(l_mult(alp, sq1), sq, alp_16);
                            if s > 0 {
                                sq = sq1;
                                ps = ps1;
                                alp = alp_16;
                                ix = i1;
                            }
                            i1 += step;
                        }
                        let i1 = ix;

                        // i2 loop: 8 positions.
                        let ps0 = ps;
                        let alp0 = l_mult(alp, Q15_1_4);
                        let mut sq: i16 = -1;
                        let mut alp: i16 = 1;
                        let mut ix = ipos[2];
                        let mut i2 = ipos[2];
                        while (i2 as usize) < L_CODE {
                            let ps1 = add(ps0, dn[i2 as usize]);
                            let mut alp1 = l_mac(alp0, rr(i2 as usize, i2 as usize), Q15_1_16);
                            alp1 = l_mac(alp1, rr(i1 as usize, i2 as usize), Q15_1_8);
                            alp1 = l_mac(alp1, rr(i0 as usize, i2 as usize), Q15_1_8);
                            let sq1 = mult(ps1, ps1);
                            let alp_16 = round_word(alp1);
                            let s = l_msu(l_mult(alp, sq1), sq, alp_16);
                            if s > 0 {
                                sq = sq1;
                                alp = alp_16;
                                ix = i2;
                            }
                            i2 += step;
                        }
                        let i2 = ix;

                        // Memorise the codevector if this one is better.
                        let s = l_msu(l_mult(alpk, sq), psk, alp);
                        if s > 0 {
                            psk = sq;
                            alpk = alp;
                            codvec[0] = i0;
                            codvec[1] = i1;
                            codvec[2] = i2;
                        }
                    }
                    i0 += step;
                }

                // Cyclic permutation of the 3 pulse-start positions.
                let pos = ipos[2];
                ipos[2] = ipos[1];
                ipos[1] = ipos[0];
                ipos[0] = pos;
            }
            track2 += 2;
        }
        track1 += 2;
    }
}

/// `c3_14pf.c` `build_code` — build the innovation `cod[]`, filtered code `y[]`, the 3-pulse sign word
/// (`*sign`) and the 11-bit position index (returned) for the 14-bit codebook. i0 (track 0) occupies
/// bits 0-2, i1 (tracks 1/3) bits 3-6, i2 (tracks 2/4) bits 7-10 — see `d3_14pf.c` for the inverse.
fn build_code_3i40_14bits(
    codvec: &[i16; NB_PULSE_3I40],
    dn_sign: &[i16],
    cod: &mut [i16],
    h: &[i16],
    y: &mut [i16],
    sign: &mut i16,
) -> i16 {
    for c in cod.iter_mut().take(L_CODE) {
        *c = 0;
    }

    let mut sign_pulses = [0i16; NB_PULSE_3I40];
    let mut indx: i16 = 0;
    let mut rsign: i16 = 0;
    for k in 0..NB_PULSE_3I40 {
        let i = codvec[k];
        let j = dn_sign[i as usize];

        let mut index = mult(i, 6554); // index = pos/5
        let track = sub(i, extract_l(l_shr(l_mult(index, 5), 1))); // track = pos%5

        // Remap the raw track (pos%5) to the transmitted sign-track and finalize the position bits.
        let track = if track == 1 {
            index = shl(index, 4);
            1i16
        } else if track == 2 {
            index = shl(index, 8);
            2i16
        } else if track == 3 {
            index = add(shl(index, 4), 8);
            1i16
        } else if track == 4 {
            index = add(shl(index, 8), 128);
            2i16
        } else {
            // track == 0: index (= pos/5) stays in bits 0-2, sign-track 0.
            0i16
        };

        if j > 0 {
            cod[i as usize] = 8191;
            sign_pulses[k] = 32767;
            rsign = add(rsign, shl(1, track));
        } else {
            cod[i as usize] = -8192;
            sign_pulses[k] = -32768; // (Word16)-32768
        }
        indx = add(indx, index);
    }
    *sign = rsign;

    // y[i] = round( Σ_k h[i - codvec[k]] · sign_pulses[k] ), reading h[n<0] as 0.
    let p0 = codvec[0];
    let p1 = codvec[1];
    let p2 = codvec[2];
    for (i, yi) in y.iter_mut().enumerate().take(L_CODE) {
        let mut s: i32 = 0;
        let n0 = i as isize - p0 as isize;
        if n0 >= 0 {
            s = l_mac(s, h[n0 as usize], sign_pulses[0]);
        }
        let n1 = i as isize - p1 as isize;
        if n1 >= 0 {
            s = l_mac(s, h[n1 as usize], sign_pulses[1]);
        }
        let n2 = i as isize - p2 as isize;
        if n2 >= 0 {
            s = l_mac(s, h[n2 as usize], sign_pulses[2]);
        }
        *yi = round_word(s);
    }

    indx
}

/// `c3_14pf.c` `code_3i40_14bits` — MR67 fixed-codebook search over a 40-sample subframe with 3
/// pulses (14-bit index). `h` is modified in place with the pitch-sharpening contribution (as the
/// reference does), so the caller must pass a writable copy. Returns the position index and writes
/// the sign word to `sign`.
fn code_3i40_14bits(
    x: &[i16],
    h: &mut [i16],
    t0: i16,
    pitch_sharp: i16,
    code: &mut [i16],
    y: &mut [i16],
    sign: &mut i16,
) -> i16 {
    let sharp = shl(pitch_sharp, 1);
    // Pre-CB pitch sharpening folded into h[] (as the reference does, before the search).
    if sub(t0, L_CODE as i16) < 0 {
        for i in (t0 as usize)..L_CODE {
            h[i] = add(h[i], mult(h[i - t0 as usize], sharp));
        }
    }

    let mut dn = [0i16; L_CODE];
    let mut dn2 = [0i16; L_CODE];
    let mut dn_sign = [0i16; L_CODE];
    let mut rr = [0i16; L_CODE * L_CODE];
    let mut codvec = [0i16; NB_PULSE_3I40];

    cor_h_x(h, x, &mut dn, 1);
    set_sign(&mut dn, &mut dn_sign, &mut dn2, 6); // n = 6 → keep 6 maxima per track in dn2[]
    cor_h(h, &dn_sign, &mut rr);
    search_3i40(&dn, &dn2, &rr, &mut codvec);
    let index = build_code_3i40_14bits(&codvec, &dn_sign, code, h, y, sign);

    // Post-CB pitch sharpening folded into code[].
    if sub(t0, L_CODE as i16) < 0 {
        for i in (t0 as usize)..L_CODE {
            code[i] = add(code[i], mult(code[i - t0 as usize], sharp));
        }
    }

    index
}

// =============================================================================================
//  MR122 : 10-pulse 35-bit search (c1035pf.c + s10_8pf.c)
// =============================================================================================

/// `s10_8pf.c` `search_10and8i40` for the GSM-EFR (10-pulse, `step = STEP`, `nb_tracks = NB_TRACK`)
/// case used by MR122. Depth-first over pulse pairs (i0 fixed on the correlation maximum).
fn search_10and8i40(
    dn: &[i16],
    rr: &[i16],
    ipos: &mut [i16],
    pos_max: &[i16],
    codvec: &mut [i16; NB_PULSE_MR122],
) {
    let step = STEP as i16;
    let nb_pulse = NB_PULSE_MR122 as i16;
    let nb_tracks = NB_TRACK as i16;
    let rr = |i: usize, j: usize| -> i16 { rr[i * L_CODE + j] };

    let mut rrv = [0i16; L_CODE];

    // Fix i0 on the maximum-correlation position.
    let i0 = pos_max[ipos[0] as usize];

    let mut psk: i16 = -1;
    let mut alpk: i16 = 1;
    for (i, c) in codvec.iter_mut().enumerate() {
        *c = i as i16;
    }

    for _outer in 1..nb_tracks {
        let i1 = pos_max[ipos[1] as usize];
        let ps0 = add(dn[i0 as usize], dn[i1 as usize]);
        let mut alp0 = l_mult(rr(i0 as usize, i0 as usize), Q15_1_16);
        alp0 = l_mac(alp0, rr(i1 as usize, i1 as usize), Q15_1_16);
        alp0 = l_mac(alp0, rr(i0 as usize, i1 as usize), Q15_1_8);

        // --- i2 & i3 loop ---
        {
            let mut i3 = ipos[3];
            while (i3 as usize) < L_CODE {
                let mut s = l_mult(rr(i3 as usize, i3 as usize), Q15_1_8);
                s = l_mac(s, rr(i0 as usize, i3 as usize), Q15_1_4);
                s = l_mac(s, rr(i1 as usize, i3 as usize), Q15_1_4);
                rrv[i3 as usize] = round_word(s);
                i3 += step;
            }
        }
        let mut sq: i16 = -1;
        let mut alp: i16 = 1;
        let mut ps: i16 = 0;
        let mut ia = ipos[2];
        let mut ib = ipos[3];

        let mut i2 = ipos[2];
        while (i2 as usize) < L_CODE {
            let ps1 = add(ps0, dn[i2 as usize]);
            let mut alp1 = l_mac(alp0, rr(i2 as usize, i2 as usize), Q15_1_16);
            alp1 = l_mac(alp1, rr(i0 as usize, i2 as usize), Q15_1_8);
            alp1 = l_mac(alp1, rr(i1 as usize, i2 as usize), Q15_1_8);

            let mut i3 = ipos[3];
            while (i3 as usize) < L_CODE {
                let ps2 = add(ps1, dn[i3 as usize]);
                let mut alp2 = l_mac(alp1, rrv[i3 as usize], Q15_1_2);
                alp2 = l_mac(alp2, rr(i2 as usize, i3 as usize), Q15_1_8);
                let sq2 = mult(ps2, ps2);
                let alp_16 = round_word(alp2);
                let s = l_msu(l_mult(alp, sq2), sq, alp_16);
                if s > 0 {
                    sq = sq2;
                    ps = ps2;
                    alp = alp_16;
                    ia = i2;
                    ib = i3;
                }
                i3 += step;
            }
            i2 += step;
        }
        let i2 = ia;
        let i3 = ib;

        // --- i4 & i5 loop ---
        let ps0 = ps;
        let alp0 = l_mult(alp, Q15_1_2);
        {
            let mut i5 = ipos[5];
            while (i5 as usize) < L_CODE {
                let mut s = l_mult(rr(i5 as usize, i5 as usize), Q15_1_8);
                s = l_mac(s, rr(i0 as usize, i5 as usize), Q15_1_4);
                s = l_mac(s, rr(i1 as usize, i5 as usize), Q15_1_4);
                s = l_mac(s, rr(i2 as usize, i5 as usize), Q15_1_4);
                s = l_mac(s, rr(i3 as usize, i5 as usize), Q15_1_4);
                rrv[i5 as usize] = round_word(s);
                i5 += step;
            }
        }
        let mut sq: i16 = -1;
        let mut alp: i16 = 1;
        let mut ps: i16 = 0;
        let mut ia = ipos[4];
        let mut ib = ipos[5];

        let mut i4 = ipos[4];
        while (i4 as usize) < L_CODE {
            let ps1 = add(ps0, dn[i4 as usize]);
            let mut alp1 = l_mac(alp0, rr(i4 as usize, i4 as usize), Q15_1_32);
            alp1 = l_mac(alp1, rr(i0 as usize, i4 as usize), Q15_1_16);
            alp1 = l_mac(alp1, rr(i1 as usize, i4 as usize), Q15_1_16);
            alp1 = l_mac(alp1, rr(i2 as usize, i4 as usize), Q15_1_16);
            alp1 = l_mac(alp1, rr(i3 as usize, i4 as usize), Q15_1_16);

            let mut i5 = ipos[5];
            while (i5 as usize) < L_CODE {
                let ps2 = add(ps1, dn[i5 as usize]);
                let mut alp2 = l_mac(alp1, rrv[i5 as usize], Q15_1_4);
                alp2 = l_mac(alp2, rr(i4 as usize, i5 as usize), Q15_1_16);
                let sq2 = mult(ps2, ps2);
                let alp_16 = round_word(alp2);
                let s = l_msu(l_mult(alp, sq2), sq, alp_16);
                if s > 0 {
                    sq = sq2;
                    ps = ps2;
                    alp = alp_16;
                    ia = i4;
                    ib = i5;
                }
                i5 += step;
            }
            i4 += step;
        }
        let i4 = ia;
        let i5 = ib;

        // --- i6 & i7 loop ---
        let ps0 = ps;
        let alp0 = l_mult(alp, Q15_1_2);
        {
            let mut i7 = ipos[7];
            while (i7 as usize) < L_CODE {
                let mut s = l_mult(rr(i7 as usize, i7 as usize), Q15_1_16);
                s = l_mac(s, rr(i0 as usize, i7 as usize), Q15_1_8);
                s = l_mac(s, rr(i1 as usize, i7 as usize), Q15_1_8);
                s = l_mac(s, rr(i2 as usize, i7 as usize), Q15_1_8);
                s = l_mac(s, rr(i3 as usize, i7 as usize), Q15_1_8);
                s = l_mac(s, rr(i4 as usize, i7 as usize), Q15_1_8);
                s = l_mac(s, rr(i5 as usize, i7 as usize), Q15_1_8);
                rrv[i7 as usize] = round_word(s);
                i7 += step;
            }
        }
        let mut sq: i16 = -1;
        let mut alp: i16 = 1;
        let mut ps: i16 = 0;
        let mut ia = ipos[6];
        let mut ib = ipos[7];

        let mut i6 = ipos[6];
        while (i6 as usize) < L_CODE {
            let ps1 = add(ps0, dn[i6 as usize]);
            let mut alp1 = l_mac(alp0, rr(i6 as usize, i6 as usize), Q15_1_64);
            alp1 = l_mac(alp1, rr(i0 as usize, i6 as usize), Q15_1_32);
            alp1 = l_mac(alp1, rr(i1 as usize, i6 as usize), Q15_1_32);
            alp1 = l_mac(alp1, rr(i2 as usize, i6 as usize), Q15_1_32);
            alp1 = l_mac(alp1, rr(i3 as usize, i6 as usize), Q15_1_32);
            alp1 = l_mac(alp1, rr(i4 as usize, i6 as usize), Q15_1_32);
            alp1 = l_mac(alp1, rr(i5 as usize, i6 as usize), Q15_1_32);

            let mut i7 = ipos[7];
            while (i7 as usize) < L_CODE {
                let ps2 = add(ps1, dn[i7 as usize]);
                let mut alp2 = l_mac(alp1, rrv[i7 as usize], Q15_1_4);
                alp2 = l_mac(alp2, rr(i6 as usize, i7 as usize), Q15_1_32);
                let sq2 = mult(ps2, ps2);
                let alp_16 = round_word(alp2);
                let s = l_msu(l_mult(alp, sq2), sq, alp_16);
                if s > 0 {
                    sq = sq2;
                    ps = ps2;
                    alp = alp_16;
                    ia = i6;
                    ib = i7;
                }
                i7 += step;
            }
            i6 += step;
        }
        let i6 = ia;
        let i7 = ib;

        // --- i8 & i9 loop (GSM-EFR only, gsmefrFlag == 1) ---
        let ps0 = ps;
        let alp0 = l_mult(alp, Q15_1_2);
        {
            let mut i9 = ipos[9];
            while (i9 as usize) < L_CODE {
                let mut s = l_mult(rr(i9 as usize, i9 as usize), Q15_1_16);
                s = l_mac(s, rr(i0 as usize, i9 as usize), Q15_1_8);
                s = l_mac(s, rr(i1 as usize, i9 as usize), Q15_1_8);
                s = l_mac(s, rr(i2 as usize, i9 as usize), Q15_1_8);
                s = l_mac(s, rr(i3 as usize, i9 as usize), Q15_1_8);
                s = l_mac(s, rr(i4 as usize, i9 as usize), Q15_1_8);
                s = l_mac(s, rr(i5 as usize, i9 as usize), Q15_1_8);
                s = l_mac(s, rr(i6 as usize, i9 as usize), Q15_1_8);
                s = l_mac(s, rr(i7 as usize, i9 as usize), Q15_1_8);
                rrv[i9 as usize] = round_word(s);
                i9 += step;
            }
        }
        let mut sq: i16 = -1;
        let mut alp: i16 = 1;
        let mut ia = ipos[8];
        let mut ib = ipos[9];

        let mut i8 = ipos[8];
        while (i8 as usize) < L_CODE {
            let ps1 = add(ps0, dn[i8 as usize]);
            let mut alp1 = l_mac(alp0, rr(i8 as usize, i8 as usize), Q15_1_128);
            alp1 = l_mac(alp1, rr(i0 as usize, i8 as usize), Q15_1_64);
            alp1 = l_mac(alp1, rr(i1 as usize, i8 as usize), Q15_1_64);
            alp1 = l_mac(alp1, rr(i2 as usize, i8 as usize), Q15_1_64);
            alp1 = l_mac(alp1, rr(i3 as usize, i8 as usize), Q15_1_64);
            alp1 = l_mac(alp1, rr(i4 as usize, i8 as usize), Q15_1_64);
            alp1 = l_mac(alp1, rr(i5 as usize, i8 as usize), Q15_1_64);
            alp1 = l_mac(alp1, rr(i6 as usize, i8 as usize), Q15_1_64);
            alp1 = l_mac(alp1, rr(i7 as usize, i8 as usize), Q15_1_64);

            let mut i9 = ipos[9];
            while (i9 as usize) < L_CODE {
                let ps2 = add(ps1, dn[i9 as usize]);
                let mut alp2 = l_mac(alp1, rrv[i9 as usize], Q15_1_8);
                alp2 = l_mac(alp2, rr(i8 as usize, i9 as usize), Q15_1_64);
                let sq2 = mult(ps2, ps2);
                let alp_16 = round_word(alp2);
                let s = l_msu(l_mult(alp, sq2), sq, alp_16);
                if s > 0 {
                    sq = sq2;
                    alp = alp_16;
                    ia = i8;
                    ib = i9;
                }
                i9 += step;
            }
            i8 += step;
        }

        // Test and memorise the best 10-pulse combination.
        let s = l_msu(l_mult(alpk, sq), psk, alp);
        if s > 0 {
            psk = sq;
            alpk = alp;
            codvec[0] = i0;
            codvec[1] = i1;
            codvec[2] = i2;
            codvec[3] = i3;
            codvec[4] = i4;
            codvec[5] = i5;
            codvec[6] = i6;
            codvec[7] = i7;
            codvec[8] = ia;
            codvec[9] = ib;
        }

        // Cyclic permutation of ipos[1..nb_pulse].
        let pos = ipos[1];
        let mut j = 1usize;
        let mut k = 2usize;
        while (k as i16) < nb_pulse {
            ipos[j] = ipos[k];
            j += 1;
            k += 1;
        }
        ipos[(nb_pulse - 1) as usize] = pos;
    }
}

/// `c1035pf.c` `q_p` — pack the pulse-position index for pulse `n` (Gray-encode the position field;
/// keep the sign bit for the first pulse of a track pair, `n < 5`).
fn q_p(ind: &mut i16, n: i16) {
    let tmp = *ind;
    if sub(n, 5) < 0 {
        *ind = (tmp & 0x8) | GRAY[(tmp & 0x7) as usize];
    } else {
        *ind = GRAY[(tmp & 0x7) as usize];
    }
}

/// `c1035pf.c` `build_code` — build the innovation `cod[]` (Q13), filtered code `y[]` (Q12) and the
/// 10 pulse indices (sign+position) for the MR122 codebook.
fn build_code_10i40(
    codvec: &[i16; NB_PULSE_MR122],
    sign: &[i16],
    cod: &mut [i16],
    h: &[i16],
    y: &mut [i16],
    indx: &mut [i16; NB_PULSE_MR122],
) {
    for c in cod.iter_mut().take(L_CODE) {
        *c = 0;
    }
    for slot in indx.iter_mut().take(NB_TRACK) {
        *slot = -1;
    }

    let mut sign_pulses = [0i16; NB_PULSE_MR122];
    for k in 0..NB_PULSE_MR122 {
        let i = codvec[k];
        let j = sign[i as usize];

        let mut index = mult(i, 6554); // index = pos/5
        let track = sub(i, extract_l(l_shr(l_mult(index, 5), 1))) as usize; // pos%5

        if j > 0 {
            cod[i as usize] = add(cod[i as usize], 4096);
            sign_pulses[k] = 8192;
        } else {
            cod[i as usize] = sub(cod[i as usize], 4096);
            sign_pulses[k] = -8192;
            index = add(index, 8);
        }

        if indx[track] < 0 {
            indx[track] = index;
        } else if ((index ^ indx[track]) & 8) == 0 {
            // sign of 1st pulse == sign of 2nd pulse
            if sub(indx[track], index) <= 0 {
                indx[track + 5] = index;
            } else {
                indx[track + 5] = indx[track];
                indx[track] = index;
            }
        } else {
            // sign of 1st pulse != sign of 2nd pulse
            if sub(indx[track] & 7, index & 7) <= 0 {
                indx[track + 5] = indx[track];
                indx[track] = index;
            } else {
                indx[track + 5] = index;
            }
        }
    }

    // y[i] = round( Σ_k h[i - codvec[k]] · sign_pulses[k] ), reading h[n<0] as 0.
    for (i, yi) in y.iter_mut().enumerate().take(L_CODE) {
        let mut s: i32 = 0;
        for k in 0..NB_PULSE_MR122 {
            let n = i as isize - codvec[k] as isize;
            if n >= 0 {
                s = l_mac(s, h[n as usize], sign_pulses[k]);
            }
        }
        *yi = round_word(s);
    }
}

/// `c1035pf.c` `code_10i40_35bits` — MR122 fixed-codebook search: 10 pulses / 5 tracks. Writes the
/// innovation `cod[]`, the filtered code `y[]` and the 10 packed indices `indx[]`.
fn code_10i40_35bits(
    x: &[i16],
    cn: &[i16],
    h: &[i16],
    cod: &mut [i16],
    y: &mut [i16],
    indx: &mut [i16; NB_PULSE_MR122],
) {
    let mut dn = [0i16; L_CODE];
    let mut sign = [0i16; L_CODE];
    let mut rr = [0i16; L_CODE * L_CODE];
    let mut ipos = [0i16; NB_PULSE_MR122];
    let mut pos_max = [0i16; NB_TRACK];
    let mut codvec = [0i16; NB_PULSE_MR122];

    cor_h_x(h, x, &mut dn, 2);
    set_sign12k2(
        &mut dn,
        cn,
        &mut sign,
        &mut pos_max,
        NB_TRACK,
        &mut ipos,
        STEP,
    );
    cor_h(h, &sign, &mut rr);
    search_10and8i40(&dn, &rr, &mut ipos, &pos_max, &mut codvec);
    build_code_10i40(&codvec, &sign, cod, h, y, indx);
    for (i, slot) in indx.iter_mut().enumerate().take(NB_PULSE_MR122) {
        q_p(slot, i as i16);
    }
}

// =============================================================================================
//  Public dispatch (cbsearch.c cbsearch)
// =============================================================================================

/// Result of [`cbsearch`] — the codebook parameters tier 6 appends to `ana` (in the order the
/// reference writes them via `*(*anap)++`), plus the mode's parameter count.
///
/// * MR122 (`code_10i40_35bits`): 10 params — the 10 packed pulse indices (`indx[0..10]`).
/// * MR475/MR515 (`code_2i40_9bits`), MR59 (`code_2i40_11bits`) and MR67 (`code_3i40_14bits`): 2
///   params — the position index, then the sign index.
#[derive(Debug, Clone)]
pub struct CbSearchResult {
    /// Codebook parameters, written in `*anap++` order. Only the first [`Self::num_params`] valid.
    pub params: [i16; 10],
    /// Number of valid entries in [`Self::params`] (2 for MR475/MR515/MR59/MR67, 10 for MR122).
    pub num_params: usize,
}

/// `cbsearch.c` `cbsearch` — fixed-codebook search dispatch for one subframe.
///
/// Mirrors the reference call `cbsearch(xn2, h1, T0, sharp, gain_pit, res2, code, y2, &ana, mode,
/// subfrNr)`:
///  * `xn2` — codebook-search target (from `cl_ltp`, Q0).
///  * `h1` — weighted-synthesis impulse response (Q12). **Modified in place** with the pitch
///    contribution (as the reference does — the caller must supply the working `h1`, which tier 6
///    already treats as scratch for the subframe).
///  * `t0` — pitch lag; `pitch_sharp` — the encoder's `sharp` state (Q14, from tier 6); `gain_pit` —
///    closed-loop pitch gain (Q14).
///  * `res2` — LTP residual (Q0), used as `cn[]` for MR122's sign selection.
///  * Outputs: `code` (innovation, Q13), `y2` (filtered code, Q12), and the returned
///    [`CbSearchResult`] carrying the `ana` params.
///
/// Only MR122, MR475/MR515, MR59 and MR67 are implemented so far; other modes return
/// [`CodecError::Unsupported`] (they are gated out of the encoder until their search files are
/// ported). The frame loop only ever calls the live modes.
#[allow(clippy::too_many_arguments)]
pub fn cbsearch(
    xn2: &[i16],
    h1: &mut [i16],
    t0: i16,
    pitch_sharp: i16,
    gain_pit: i16,
    res2: &[i16],
    code: &mut [i16],
    y2: &mut [i16],
    mode: AmrNbMode,
    sub_nr: i16,
) -> Result<CbSearchResult, CodecError> {
    let mut params = [0i16; 10];

    match mode {
        AmrNbMode::Mr475 | AmrNbMode::Mr515 => {
            let mut sign = 0i16;
            let index = code_2i40_9bits(sub_nr, xn2, h1, t0, pitch_sharp, code, y2, &mut sign);
            params[0] = index; // position index
            params[1] = sign; //  sign index
            Ok(CbSearchResult {
                params,
                num_params: 2,
            })
        }
        AmrNbMode::Mr590 => {
            let mut sign = 0i16;
            let index = code_2i40_11bits(xn2, h1, t0, pitch_sharp, code, y2, &mut sign);
            params[0] = index; // position index
            params[1] = sign; //  sign index
            Ok(CbSearchResult {
                params,
                num_params: 2,
            })
        }
        AmrNbMode::Mr670 => {
            let mut sign = 0i16;
            let index = code_3i40_14bits(xn2, h1, t0, pitch_sharp, code, y2, &mut sign);
            params[0] = index; // position index
            params[1] = sign; //  sign index
            Ok(CbSearchResult {
                params,
                num_params: 2,
            })
        }
        AmrNbMode::Mr1220 => {
            // Include the pitch contribution into the impulse response h1[] (MR122 uses gain_pit).
            let pit_sharp_tmp = shl(gain_pit, 1);
            if (t0 as usize) < L_CODE {
                for i in (t0 as usize)..L_CODE {
                    let temp = mult(h1[i - t0 as usize], pit_sharp_tmp);
                    h1[i] = add(h1[i], temp);
                }
            }

            let mut indx = [0i16; NB_PULSE_MR122];
            code_10i40_35bits(xn2, res2, h1, code, y2, &mut indx);
            params[..NB_PULSE_MR122].copy_from_slice(&indx);

            // Add the pitch contribution to code[].
            if (t0 as usize) < L_CODE {
                for i in (t0 as usize)..L_CODE {
                    let temp = mult(code[i - t0 as usize], pit_sharp_tmp);
                    code[i] = add(code[i], temp);
                }
            }
            Ok(CbSearchResult {
                params,
                num_params: NB_PULSE_MR122,
            })
        }
        _ => Err(CodecError::Unsupported(
            "AMR-NB codebook search: mode not yet ported (MR122 and MR475/MR515 only)",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn q15_fraction_constants_match_c_word16_wrap() {
        // (Word16)(32768/2) etc. all fit a positive Word16 (32768/2 = 16384, no wrap).
        assert_eq!(Q15_1_2, 16384);
        assert_eq!(Q15_1_4, 8192);
        assert_eq!(Q15_1_8, 4096);
        assert_eq!(Q15_1_16, 2048);
        assert_eq!(Q15_1_32, 1024);
        assert_eq!(Q15_1_64, 512);
        assert_eq!(Q15_1_128, 256);
    }

    #[test]
    fn q_p_low_pulse_keeps_sign_bit_and_gray_encodes() {
        // n < 5: (tmp & 0x8) | gray[tmp & 0x7].
        let mut ind = 0b1010; // sign bit set (0x8), position field = 0b010 = 2 -> gray[2] = 3
        q_p(&mut ind, 0);
        assert_eq!(ind, 0x8 | GRAY[2]); // 8 | 3 = 11
    }

    #[test]
    fn q_p_high_pulse_drops_sign_bit() {
        // n >= 5: gray[tmp & 0x7] only.
        let mut ind = 0b1010;
        q_p(&mut ind, 5);
        assert_eq!(ind, GRAY[2]); // gray[2] = 3
    }

    #[test]
    fn set_sign_folds_sign_and_records_positive() {
        let mut dn = [0i16; L_CODE];
        dn[0] = 100;
        dn[1] = -200;
        let mut sign = [0i16; L_CODE];
        let mut dn2 = [0i16; L_CODE];
        set_sign(&mut dn, &mut sign, &mut dn2, 8);
        assert_eq!(sign[0], 32767);
        assert_eq!(sign[1], -32767);
        assert_eq!(dn[0], 100);
        assert_eq!(dn[1], 200); // |dn| after fold
    }

    #[test]
    fn cor_h_x_zero_target_is_zero_correlation() {
        let h = [1234i16; L_CODE];
        let x = [0i16; L_CODE];
        let mut dn = [7i16; L_CODE];
        cor_h_x(&h, &x, &mut dn, 1);
        assert!(dn.iter().all(|&v| v == 0));
    }

    #[test]
    fn cor_h_symmetric_matrix() {
        // A simple impulse response and all-positive signs -> rr symmetric.
        let mut h = [0i16; L_CODE];
        h[0] = 4096;
        h[1] = 2048;
        h[2] = 1024;
        let sign = [32767i16; L_CODE];
        let mut rr = [0i16; L_CODE * L_CODE];
        cor_h(&h, &sign, &mut rr);
        for i in 0..L_CODE {
            for j in 0..L_CODE {
                assert_eq!(
                    rr[i * L_CODE + j],
                    rr[j * L_CODE + i],
                    "rr not symmetric at ({i},{j})"
                );
            }
        }
    }

    #[test]
    fn code_2i40_9bits_places_two_pulses_and_signs_roundtrip() {
        // Feed a target that peaks the correlation at known tracks; assert the built code has two
        // ±8191/-8192 pulses and the decoder reproduces them from the returned index/sign.
        use crate::amr::nb::codebook::decode_2i40_9bits;
        let mut h = [0i16; L_CODE];
        h[0] = 4096; // unit-ish impulse response
        let mut x = [0i16; L_CODE];
        x[0] = 8000;
        x[2] = -6000;
        let mut code = [0i16; L_CODE];
        let mut y = [0i16; L_CODE];
        let mut sign = 0i16;
        let index = code_2i40_9bits(0, &x, &mut h, 40, 0, &mut code, &mut y, &mut sign);

        // exactly two nonzero pulses at ±8191/-8192
        let nz: Vec<_> = code.iter().enumerate().filter(|(_, &v)| v != 0).collect();
        assert_eq!(nz.len(), 2);
        assert!(nz.iter().all(|&(_, &v)| v == 8191 || v == -8192));

        // decoder reconstructs the same pulse positions/signs
        let mut cod_dec = [0i16; L_CODE];
        decode_2i40_9bits(0, sign, index, &mut cod_dec);
        assert_eq!(code, cod_dec, "encoder/decoder codeword mismatch");
    }

    #[test]
    fn code_2i40_11bits_places_two_pulses_and_signs_roundtrip() {
        // MR59 11-bit codebook: build a code and confirm the 11-bit decoder twin reconstructs the
        // same two ±8191/-8192 pulses from the returned position/sign indices.
        use crate::amr::nb::codebook::decode_2i40_11bits;
        let mut h = [0i16; L_CODE];
        h[0] = 4096; // unit-ish impulse response
        let mut x = [0i16; L_CODE];
        x[1] = 8000; // peak on an i0 track (pos%5 == 1)
        x[5] = -6000; // peak on an i1 track (pos%5 == 0)
        let mut code = [0i16; L_CODE];
        let mut y = [0i16; L_CODE];
        let mut sign = 0i16;
        let index = code_2i40_11bits(&x, &mut h, 40, 0, &mut code, &mut y, &mut sign);

        // exactly two nonzero pulses at ±8191/-8192
        let nz: Vec<_> = code.iter().enumerate().filter(|(_, &v)| v != 0).collect();
        assert_eq!(nz.len(), 2);
        assert!(nz.iter().all(|&(_, &v)| v == 8191 || v == -8192));

        // decoder reconstructs the same pulse positions/signs
        let mut cod_dec = [0i16; L_CODE];
        decode_2i40_11bits(sign, index, &mut cod_dec);
        assert_eq!(code, cod_dec, "MR59 encoder/decoder codeword mismatch");
    }

    #[test]
    fn code_3i40_14bits_places_three_pulses_and_signs_roundtrip() {
        // MR67 14-bit codebook: build a code and confirm the 14-bit decoder twin reconstructs the
        // same three ±8191/-8192 pulses from the returned position/sign indices.
        use crate::amr::nb::codebook::decode_3i40_14bits;
        let mut h = [0i16; L_CODE];
        h[0] = 4096; // unit-ish impulse response
        let mut x = [0i16; L_CODE];
        x[0] = 8000; // peak on i0 track (pos%5 == 0)
        x[1] = -6000; // peak on an i1 track (pos%5 == 1)
        x[2] = 5000; // peak on an i2 track (pos%5 == 2)
        let mut code = [0i16; L_CODE];
        let mut y = [0i16; L_CODE];
        let mut sign = 0i16;
        let index = code_3i40_14bits(&x, &mut h, 40, 0, &mut code, &mut y, &mut sign);

        // exactly three nonzero pulses at ±8191/-8192
        let nz: Vec<_> = code.iter().enumerate().filter(|(_, &v)| v != 0).collect();
        assert_eq!(nz.len(), 3);
        assert!(nz.iter().all(|&(_, &v)| v == 8191 || v == -8192));

        // decoder reconstructs the same pulse positions/signs
        let mut cod_dec = [0i16; L_CODE];
        decode_3i40_14bits(sign, index, &mut cod_dec);
        assert_eq!(code, cod_dec, "MR67 encoder/decoder codeword mismatch");
    }

    #[test]
    fn cbsearch_mr670_emits_two_params() {
        let mut h = [0i16; L_CODE];
        h[0] = 4096;
        let mut xn2 = [0i16; L_CODE];
        xn2[0] = 5000;
        xn2[1] = -4000;
        xn2[2] = 3000;
        let res2 = xn2;
        let mut code = [0i16; L_CODE];
        let mut y2 = [0i16; L_CODE];
        let r = cbsearch(
            &xn2,
            &mut h,
            40,
            0,
            8192,
            &res2,
            &mut code,
            &mut y2,
            AmrNbMode::Mr670,
            0,
        )
        .expect("MR67 cbsearch");
        assert_eq!(r.num_params, 2);
    }

    #[test]
    fn cbsearch_mr590_emits_two_params() {
        let mut h = [0i16; L_CODE];
        h[0] = 4096;
        let mut xn2 = [0i16; L_CODE];
        xn2[1] = 5000;
        xn2[5] = -4000;
        let res2 = xn2;
        let mut code = [0i16; L_CODE];
        let mut y2 = [0i16; L_CODE];
        let r = cbsearch(
            &xn2,
            &mut h,
            40,
            0,
            8192,
            &res2,
            &mut code,
            &mut y2,
            AmrNbMode::Mr590,
            0,
        )
        .expect("MR59 cbsearch");
        assert_eq!(r.num_params, 2);
    }

    #[test]
    fn code_10i40_35bits_places_pulses_and_roundtrips_decoder() {
        use crate::amr::nb::codebook::dec_10i40_35bits;
        // A structured target so the search produces a non-degenerate codevector.
        let mut h = [0i16; L_CODE];
        h[0] = 4096;
        h[1] = 1500;
        let mut x = [0i16; L_CODE];
        for (i, xi) in x.iter_mut().enumerate() {
            *xi = (((i as i16) % 7) - 3) * 900;
        }
        let cn = x; // LTP residual proxy
        let mut cod = [0i16; L_CODE];
        let mut y = [0i16; L_CODE];
        let mut indx = [0i16; NB_PULSE_MR122];
        code_10i40_35bits(&x, &cn, &h, &mut cod, &mut y, &mut indx);

        // The decoder expands the same 10 indices; codeword must match bit-for-bit.
        let mut cod_dec = [0i16; L_CODE];
        dec_10i40_35bits(&indx, &mut cod_dec);
        assert_eq!(cod, cod_dec, "MR122 encoder/decoder codeword mismatch");
    }

    #[test]
    fn cbsearch_mr122_emits_ten_params() {
        let mut h = [0i16; L_CODE];
        h[0] = 4096;
        let mut xn2 = [0i16; L_CODE];
        xn2[0] = 5000;
        let res2 = xn2;
        let mut code = [0i16; L_CODE];
        let mut y2 = [0i16; L_CODE];
        let r = cbsearch(
            &xn2,
            &mut h,
            40,
            0,
            8192,
            &res2,
            &mut code,
            &mut y2,
            AmrNbMode::Mr1220,
            0,
        )
        .expect("MR122 cbsearch");
        assert_eq!(r.num_params, 10);
    }

    #[test]
    fn cbsearch_mr475_emits_two_params() {
        let mut h = [0i16; L_CODE];
        h[0] = 4096;
        let mut xn2 = [0i16; L_CODE];
        xn2[0] = 5000;
        xn2[2] = -4000;
        let res2 = xn2;
        let mut code = [0i16; L_CODE];
        let mut y2 = [0i16; L_CODE];
        let r = cbsearch(
            &xn2,
            &mut h,
            40,
            0,
            8192,
            &res2,
            &mut code,
            &mut y2,
            AmrNbMode::Mr475,
            0,
        )
        .expect("MR475 cbsearch");
        assert_eq!(r.num_params, 2);
    }

    // =========================================================================================
    //  Reference-oracle gate + committed regression
    // =========================================================================================
    //
    // The fixed-codebook outputs (code[], y2[], and the ana codebook params) are gated against an
    // instrumented copy of the 3GPP reference encoder (scratch `/tmp/amr-nb-oracle-t4`, whose `.COD`
    // output was proven byte-exact vs the official `T01_122.COD`/`T01_475.COD`). The generated dump
    // can't be committed, so the full-vector gate skips when absent and the committed regression
    // pins frame-10 subframe-0 for both MR122 and MR475 from byte-literal inputs.

    fn mode_from_index(m: i16) -> AmrNbMode {
        match m {
            0 => AmrNbMode::Mr475,
            1 => AmrNbMode::Mr515,
            2 => AmrNbMode::Mr590,
            3 => AmrNbMode::Mr670,
            4 => AmrNbMode::Mr740,
            5 => AmrNbMode::Mr795,
            6 => AmrNbMode::Mr1020,
            _ => AmrNbMode::Mr1220,
        }
    }

    /// One parsed subframe record from the cbsearch oracle dump.
    struct CbOracleSubfr {
        mode: AmrNbMode,
        sub_nr: i16,
        t0: i16,
        sharp: i16,
        gain_pit: i16,
        nparam: usize,
        xn2: Vec<i16>,
        h1: Vec<i16>,
        res2: Vec<i16>,
        param: Vec<i16>,
        code: Vec<i16>,
        y2: Vec<i16>,
    }

    fn parse_i16s(line: &str, tag: &str) -> Vec<i16> {
        let rest = line.strip_prefix(tag).expect("tag prefix");
        rest.split_whitespace()
            .map(|t| t.parse::<i16>().expect("i16"))
            .collect()
    }

    fn parse_cb_dump(text: &str) -> Vec<CbOracleSubfr> {
        let mut out = Vec::new();
        let mut lines = text.lines();
        while let Some(header) = lines.next() {
            if !header.starts_with("CBSUBFR") {
                continue;
            }
            let mut mode = 0i16;
            let mut sub_nr = 0i16;
            let mut t0 = 0i16;
            let mut sharp = 0i16;
            let mut gain_pit = 0i16;
            let mut nparam = 0usize;
            for tok in header.split_whitespace().skip(1) {
                let (k, v) = tok.split_once('=').expect("k=v");
                match k {
                    "mode" => mode = v.parse().expect("i16"),
                    "subfrNr" => sub_nr = v.parse().expect("i16"),
                    "T0" => t0 = v.parse().expect("i16"),
                    "sharp" => sharp = v.parse().expect("i16"),
                    "gain_pit" => gain_pit = v.parse().expect("i16"),
                    "nparam" => nparam = v.parse().expect("usize"),
                    _ => {}
                }
            }
            let xn2 = parse_i16s(lines.next().unwrap(), "CBXN2 ");
            let h1 = parse_i16s(lines.next().unwrap(), "CBH1 ");
            let res2 = parse_i16s(lines.next().unwrap(), "CBRES2 ");
            let param = parse_i16s(lines.next().unwrap(), "CBPARAM ");
            let code = parse_i16s(lines.next().unwrap(), "CBCODE ");
            let y2 = parse_i16s(lines.next().unwrap(), "CBY2 ");
            out.push(CbOracleSubfr {
                mode: mode_from_index(mode),
                sub_nr,
                t0,
                sharp,
                gain_pit,
                nparam,
                xn2,
                h1,
                res2,
                param,
                code,
                y2,
            });
        }
        out
    }

    fn replay_cb_subfr(rec: &CbOracleSubfr) -> Result<(), String> {
        let mut h1 = rec.h1.clone(); // cbsearch modifies h1 in place
        let mut code = [0i16; L_CODE];
        let mut y2 = [0i16; L_CODE];
        let result = cbsearch(
            &rec.xn2,
            &mut h1,
            rec.t0,
            rec.sharp,
            rec.gain_pit,
            &rec.res2,
            &mut code,
            &mut y2,
            rec.mode,
            rec.sub_nr,
        )
        .map_err(|e| format!("cbsearch error: {e:?}"))?;
        if result.num_params != rec.nparam {
            return Err(format!("nparam {} != {}", result.num_params, rec.nparam));
        }
        if result.params[..result.num_params] != rec.param[..] {
            return Err(format!(
                "param {:?} != {:?}",
                &result.params[..result.num_params],
                rec.param
            ));
        }
        if code[..] != rec.code[..] {
            return Err("code mismatch".to_string());
        }
        if y2[..] != rec.y2[..] {
            return Err("y2 mismatch".to_string());
        }
        Ok(())
    }

    /// Full oracle gate over every subframe of the dump. Skips when the (generated) dump is absent.
    fn run_cb_oracle_gate(dump_path: &str) -> Option<usize> {
        let text = std::fs::read_to_string(dump_path).ok()?;
        let records = parse_cb_dump(&text);
        assert!(
            !records.is_empty(),
            "empty cbsearch oracle dump: {dump_path}"
        );
        for (n, rec) in records.iter().enumerate() {
            if let Err(reason) = replay_cb_subfr(rec) {
                panic!(
                    "cbsearch oracle subframe #{n} (mode {:?}) FAILED: {reason}",
                    rec.mode
                );
            }
        }
        Some(records.len())
    }

    #[test]
    fn oracle_gate_mr122_all_subframes_bit_exact() {
        if let Some(n) = run_cb_oracle_gate("/tmp/amr-nb-oracle-t4/dump_mr122.txt") {
            eprintln!("MR122 cbsearch oracle gate: {n} subframes bit-exact");
        } else {
            eprintln!("MR122 cbsearch oracle dump absent — skipping full gate");
        }
    }

    #[test]
    fn oracle_gate_mr475_all_subframes_bit_exact() {
        if let Some(n) = run_cb_oracle_gate("/tmp/amr-nb-oracle-t4/dump_mr475.txt") {
            eprintln!("MR475 cbsearch oracle gate: {n} subframes bit-exact");
        } else {
            eprintln!("MR475 cbsearch oracle dump absent — skipping full gate");
        }
    }

    #[test]
    fn oracle_gate_mr515_all_subframes_bit_exact() {
        if let Some(n) = run_cb_oracle_gate("/tmp/amr-nb-oracle-t4/dump_mr515.txt") {
            eprintln!("MR515 cbsearch oracle gate: {n} subframes bit-exact");
        } else {
            eprintln!("MR515 cbsearch oracle dump absent — skipping full gate");
        }
    }

    #[test]
    fn oracle_gate_mr59_all_subframes_bit_exact() {
        if let Some(n) = run_cb_oracle_gate("/tmp/amr-nb-oracle-t4/dump_mr59.txt") {
            eprintln!("MR59 cbsearch oracle gate: {n} subframes bit-exact");
        } else {
            eprintln!("MR59 cbsearch oracle dump absent — skipping full gate");
        }
    }

    #[test]
    fn oracle_gate_mr67_all_subframes_bit_exact() {
        if let Some(n) = run_cb_oracle_gate("/tmp/amr-nb-oracle-t4/dump_mr67.txt") {
            eprintln!("MR67 cbsearch oracle gate: {n} subframes bit-exact");
        } else {
            eprintln!("MR67 cbsearch oracle dump absent — skipping full gate");
        }
    }

    /// Committed self-contained regression: feed the oracle-captured *inputs* of frame 10, subframe
    /// 0 (real pitch energy, non-zero `sharp` so the pitch-sharpening path is exercised) into
    /// [`cbsearch`] and pin the transmitted codebook params + `code`/`y2` (spot samples + sum/sumsq
    /// checksums) to the values the instrumented 3GPP reference produced. Fully self-contained
    /// (byte-literal inputs), so it always runs in CI even after the scratch oracle is deleted.
    #[allow(clippy::too_many_arguments)]
    fn frame10_subfr0_cb_regression(
        mode: AmrNbMode,
        sub_nr: i16,
        t0: i16,
        sharp: i16,
        gain_pit: i16,
        xn2: &[i16; L_CODE],
        h1: &[i16; L_CODE],
        res2: &[i16; L_CODE],
        want_param: &[i16],
        want_code: &[(usize, i16)],
        want_code_sums: (i64, i64),
        want_y2: &[(usize, i16)],
        want_y2_sums: (i64, i64),
    ) {
        let mut h1_work = *h1;
        let mut code = [0i16; L_CODE];
        let mut y2 = [0i16; L_CODE];
        let result = cbsearch(
            xn2,
            &mut h1_work,
            t0,
            sharp,
            gain_pit,
            res2,
            &mut code,
            &mut y2,
            mode,
            sub_nr,
        )
        .expect("cbsearch");

        let sums = |v: &[i16]| -> (i64, i64) {
            (
                v.iter().map(|&x| i64::from(x)).sum(),
                v.iter().map(|&x| i64::from(x) * i64::from(x)).sum(),
            )
        };

        assert_eq!(
            &result.params[..result.num_params],
            want_param,
            "{mode:?} param drift"
        );
        for &(i, want) in want_code {
            assert_eq!(code[i], want, "{mode:?} code[{i}] drift");
        }
        assert_eq!(sums(&code), want_code_sums, "{mode:?} code checksum drift");
        for &(i, want) in want_y2 {
            assert_eq!(y2[i], want, "{mode:?} y2[{i}] drift");
        }
        assert_eq!(sums(&y2), want_y2_sums, "{mode:?} y2 checksum drift");
    }

    #[test]
    fn mr122_frame10_subfr0_cbsearch_matches_reference() {
        frame10_subfr0_cb_regression(
            AmrNbMode::Mr1220,
            0,
            142,
            3276,
            14744,
            &[
                -186, 336, -441, 366, -150, 70, 44, 180, -68, -485, 605, -629, 365, -472, 49, 134,
                -497, 883, -885, 766, -1067, 473, 375, -883, 1400, -5958, 3751, 7254, -3384, 777,
                -490, 182, 592, -1955, 920, -837, -11, 225, -120, -581,
            ],
            &[
                4096, 1038, -623, 425, -240, 301, 10, -99, 50, -128, -33, -401, 62, 95, -158, 130,
                -114, 31, 51, -59, 79, -30, 60, -17, -28, 55, -52, 38, -12, -19, 30, -34, 20, -12,
                -2, 13, -21, 19, -12, 2,
            ],
            &[
                -96, 294, -501, 541, -432, 363, -241, 418, -303, -282, 578, -802, 711, -910, 598,
                -353, -129, 743, -1012, 1139, -1677, 1351, -578, -160, 1014, -6045, 5449, 4695,
                -2824, 1000, -773, 648, -474, -1059, 611, -768, -120, 556, 576, -1596,
            ],
            &[12, 4, 4, 12, 15, 4, 4, 4, 5, 6],
            &[
                (24, 4096),
                (25, -8192),
                (27, 8192),
                (33, -4096),
                (39, -4096),
            ],
            (0, 268_435_456),
            &[(24, 1024), (25, -1788), (27, 2985), (39, -736)],
            (67, 18_514_537),
        );
    }

    #[test]
    fn mr475_frame10_subfr0_cbsearch_matches_reference() {
        frame10_subfr0_cb_regression(
            AmrNbMode::Mr475,
            0,
            142,
            7391,
            13926,
            &[
                -174, 340, -665, 261, -361, 30, -17, -336, 319, -620, 418, -602, 193, -237, -142,
                306, -1334, -98, -1281, 1297, -741, -174, 602, -2432, 1824, -8185, -3940, 10254,
                4079, 2200, -595, 578, 2574, 295, 1974, 212, 563, 670, 1496, 607,
            ],
            &[
                4096, 769, -415, 180, -182, 232, -56, -151, 101, -110, -281, -128, 61, 7, 4, 8,
                -18, 51, 4, -2, 47, 17, 0, -12, -3, 1, -5, -2, -8, 1, -3, -7, 4, 0, 2, 1, 0, 2, -1,
                1,
            ],
            &[
                -116, 318, -708, 445, -558, 253, -189, -200, 279, -668, 585, -822, 457, -510, 95,
                142, -1292, 125, -1457, 1665, -1312, 388, 227, -2280, 2122, -8791, -1975, 9363,
                2756, 2210, -800, 1351, 1304, 362, 2074, -728, 677, 1053, 2164, 203,
            ],
            &[45, 2],
            &[(25, -8192), (27, 8191)],
            (-1, 134_201_345),
            &[(25, -4096), (27, 4511), (39, 57)],
            (-11, 38_595_193),
        );
    }

    #[test]
    fn mr515_frame10_subfr0_cbsearch_matches_reference() {
        // Same 9-bit 2-pulse codebook as MR475, but reached via the MR515 dispatch arm and driven by
        // the MR515 per-subframe input (real pitch energy, non-zero `sharp`). Pins the transmitted
        // params + code/y2 to the byte-exact encoder output (validated frame-for-frame against the
        // official T01_515.COD).
        frame10_subfr0_cb_regression(
            AmrNbMode::Mr515,
            0,
            141,
            3932,
            13926,
            &[
                526, 593, -538, 1644, -2163, 1326, -2233, -7380, 4207, 6381, 1059, -2645, 331,
                2494, 595, 2513, 336, 890, 981, 1335, 1619, -369, 988, -143, 601, 245, -276, 197,
                -973, 365, -361, -145, 144, -330, -425, -783, -223, -687, -149, -531,
            ],
            &[
                4096, 771, -305, 183, -195, 151, -165, -179, 91, -36, -228, -112, 63, -12, 23, 17,
                -5, 64, -5, -8, 30, 12, 2, -14, -2, -4, -5, -3, -9, 6, -1, -4, 3, 0, 4, 0, 0, 2,
                -1, 1,
            ],
            &[
                725, 328, -468, 1700, -2509, 1975, -2878, -6438, 4904, 5371, 501, -2800, 1152,
                1733, 228, 2946, -100, 505, 795, 2080, 1239, -475, 1196, -293, 961, 90, 14, 112,
                -818, 594, -521, 116, -12, -219, -472, -699, -124, -765, -11, -636,
            ],
            &[11, 1],
            &[(7, -8192), (15, 8191)],
            (-1, 134_201_345),
            &[(7, -4096), (15, 4005)],
            (17, 34_658_561),
        );
    }

    #[test]
    fn mr59_frame10_subfr0_cbsearch_matches_reference() {
        // MR59 11-bit 2-pulse codebook (`c2_11pf`). Pins the transmitted params + code/y2 of frame 10
        // subframe 0 (real pitch energy, non-zero `sharp` so the pitch-sharpening path runs) to the
        // byte-exact encoder output (validated frame-for-frame against the official T01_59.COD).
        frame10_subfr0_cb_regression(
            AmrNbMode::Mr590,
            0,
            141,
            10813,
            17191,
            &[
                -189, 315, 159, 1477, -3159, 2755, 1768, -6804, -1298, 1180, 1352, 963, 1655, 769,
                503, 2317, -1419, 520, 597, -94, 548, -563, 1025, -543, 214, -409, -863, 303, -161,
                668, -651, -40, -425, -788, -239, -467, 319, -389, 150, -285,
            ],
            &[
                4096, 1112, -632, 230, -18, -2, -201, -40, 15, -103, -87, -242, 52, 76, -63, 59, 4,
                45, 7, -11, 42, -7, 26, -21, -15, 19, -26, 6, -7, -3, 7, -12, 8, -4, 3, 4, -6, 8,
                -3, 1,
            ],
            &[
                210, 37, 264, 1338, -3530, 3924, -2, -5943, 7, 334, 1462, 718, 1811, -73, 829,
                1893, -1629, 1190, -500, 578, 379, -374, 1206, -858, 814, -854, -303, 46, -68, 767,
                -975, 401, -838, -365, -355, -387, 361, -612, 455, -598,
            ],
            &[102, 0],
            &[(7, -8192), (16, -8192)],
            (-16384, 134_217_728),
            &[(7, -4096), (8, -1112), (16, -3993)],
            (-8651, 36_462_871),
        );
    }

    #[test]
    fn mr67_frame10_subfr0_cbsearch_matches_reference() {
        // MR67 14-bit 3-pulse codebook (`c3_14pf`), the first mode to exercise the `set_sign` `dn2`
        // per-track pruning (`n = 6`). Frame 10 subframe 0 has `sharp == SHARPMAX` (13017), so the
        // pitch-sharpening path runs. Pinned to the byte-exact encoder output (validated frame-for-frame
        // against the official T01_67.COD).
        frame10_subfr0_cb_regression(
            AmrNbMode::Mr670,
            0,
            141,
            13017,
            15383,
            &[
                -372, 274, -379, 2168, -2843, 470, 1346, -4412, -493, -1093, 683, 2422, 911, -599,
                -848, 1025, -674, 1119, 221, 399, 1072, -807, 1181, -230, -181, 300, -334, 107,
                -50, 290, -719, 151, -148, -412, -314, -152, 604, -323, 459, -116,
            ],
            &[
                4096, 1112, -632, 230, -18, -2, -201, -40, 15, -103, -87, -242, 52, 76, -63, 59, 4,
                45, 7, -11, 42, -7, 26, -21, -15, 19, -26, 6, -7, -3, 7, -12, 8, -4, 3, 4, -6, 8,
                -3, 1,
            ],
            &[
                290, -140, -196, 2143, -3432, 1731, 172, -3956, 432, -1689, 1227, 1806, 847, -922,
                -454, 715, -832, 1618, -740, 1017, 535, -596, 1514, -798, 345, -39, -68, 17, 54,
                342, -853, 543, -551, -50, -438, -45, 573, -523, 720, -466,
            ],
            &[289, 3],
            &[(5, 8191), (7, -8192), (11, 8191)],
            (8190, 201_293_826),
            &[(5, 4096), (7, -4728), (11, 3913)],
            (4313, 58_464_855),
        );
    }
}
