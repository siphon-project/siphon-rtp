//! AMR-NB **encoder** gain quantization tier — 3GPP TS 26.073 `gain_q.c` (`gainQuant`),
//! `qua_gain.c` (`Qua_gain`), `qgain475.c` (`MR475_gain_quant` / `MR475_update_unq_pred`),
//! `q_gain_c.c` (`q_gain_code`), `g_code.c` (`G_code`), `calc_en.c`
//! (`calc_filt_energies` / `calc_target_energy`). Ported bit-exact.
//!
//! This is the last per-subframe DSP in the analysis-by-synthesis loop: given the target vectors,
//! the adaptive (`y1`) and filtered innovative (`y2`) codevectors and the pitch/code-gain
//! correlations, it jointly quantizes the pitch gain (Q14) and codebook gain (Q1) against a VQ and
//! emits the transmitted gain index/indices.
//!
//! Three paths are ported here (all modes except DTX/SID):
//!   * **standard per-subframe** — MR122 goes through [`g_code`] + `q_gain_code`; the medium-rate
//!     modes (MR59/MR515/MR67/MR74/MR102) go through `qua_gain`. One gain index per subframe.
//!   * **MR475 joint 2-subframe** — the even subframe *defers* (saving its `gc_pred`-predicted gain,
//!     energy coefficients and target energy in [`GainQuantState`]); the odd subframe runs the joint
//!     4-D quantizer `mr475_gain_quant` over **both** subframes, emitting a single joint index.
//!   * **MR795** (`MR795_gain_quant`) — pre-quantize the CB gain over three pitch-gain candidates
//!     (`mr795_gain_code_quant3`), compute the unfiltered energies + LTP coding gain, run the gain
//!     adaptor (`gain_adapt`), then the modified quantizer (`mr795_gain_code_quant_mod`). Emits two
//!     indices (pitch-gain then code-gain).
//!
//! The MA gain predictor ([`GcPredState`], [`gc_pred`], [`gc_pred_update`]) is **shared with the
//! decoder** ([`crate::amr::nb::gains`]) — reused here, never re-ported.

use crate::amr::basic_ops::{
    abs_s, add, div_s, extract_h, extract_l, l_add, l_deposit_h, l_deposit_l, l_mac, l_mult, l_shl,
    l_shr, l_sub, mult, negate, norm_l, round_word, shl, shr, shr_r, sub,
};
use crate::amr::math_op::{log2, pow2};
use crate::amr::nb::constants::L_SUBFR;
use crate::amr::nb::gain_tables::{QUA_GAIN_CODE, QUA_GAIN_PITCH};
use crate::amr::nb::gain_vq_tables::{TABLE_GAIN_HIGHRATES, TABLE_GAIN_LOWRATES, TABLE_GAIN_MR475};
use crate::amr::nb::gains::{gc_pred, gc_pred_update, GcPredState};
use crate::amr::nb::math_nb::sqrt_l_exp;
use crate::amr::oper_32b::{l_comp, l_extract, mpy_32_16};
use crate::amr::AmrNbMode;
use crate::CodecError;

/// `gains.tab` `NB_QUA_PITCH` — pitch-gain scalar quantizer size.
const NB_QUA_PITCH: usize = 16;
/// `g_adapt.h` `LTPG_MEM_SIZE` — LTP coding-gain history depth (+1; `[0]` is scratch for `gmed_n`).
const LTPG_MEM_SIZE: usize = 5;
/// `g_adapt.c` `LTP_GAIN_THR1` — 0.3322 Q13 (`1 / (10·log10 2)`).
const LTP_GAIN_THR1: i16 = 2721;
/// `g_adapt.c` `LTP_GAIN_THR2` — 0.6644 Q13 (`2 / (10·log10 2)`).
const LTP_GAIN_THR2: i16 = 5443;

/// Number of codebook-gain scalar quantizer entries (`gains.tab` `NB_QUA_CODE`).
const NB_QUA_CODE: usize = 32;
/// `table_gain_lowrates` entry count (`qua_gain.tab` `VQ_SIZE_LOWRATES`).
const VQ_SIZE_LOWRATES: usize = 64;
/// `table_gain_highrates` entry count (`qua_gain.tab` `VQ_SIZE_HIGHRATES`).
const VQ_SIZE_HIGHRATES: usize = 128;
/// `table_gain_MR475` row count (`qgain475.tab` `MR475_VQ_SIZE`).
const MR475_VQ_SIZE: usize = 256;

/// Minimum allowed gain-code prediction error (`qgain475.c` `MIN_QUA_ENER`), Q10 `log2(0.0251189)`.
const MIN_QUA_ENER: i16 = -5443;
/// Minimum allowed gain-code prediction error (`qgain475.c` `MIN_QUA_ENER_MR122`),
/// Q10 `20*log10(0.0251189)`.
const MIN_QUA_ENER_MR122: i16 = -32768;
/// Maximum allowed gain-code prediction error (`qgain475.c` `MAX_QUA_ENER`), Q10 `log2(7.8125)`.
const MAX_QUA_ENER: i16 = 3037;
/// Maximum allowed gain-code prediction error (`qgain475.c` `MAX_QUA_ENER_MR122`),
/// Q10 `20*log10(7.8125)`.
const MAX_QUA_ENER_MR122: i16 = 18284;

/// `Mac_32_16(L_32, hi, lo, n)` (`mac_32.c`): `L_32 + (hi*n)<<1 + ((lo*n)>>15)<<1`, saturating in
/// the reference order (two `L_mac`s — **not** `L_add(L_32, Mpy_32_16(..))`, which rounds
/// differently).
#[inline]
fn mac_32_16(l_32: i32, hi: i16, lo: i16, n: i16) -> i32 {
    let l_32 = l_mac(l_32, hi, n);
    l_mac(l_32, mult(lo, n), 1)
}

/// Copy the MA gain-predictor memories (`gc_pred.c` `gc_pred_copy`).
#[inline]
fn gc_pred_copy(src: &GcPredState, dest: &mut GcPredState) {
    dest.past_qua_en = src.past_qua_en;
    dest.past_qua_en_mr122 = src.past_qua_en_mr122;
}

/// Per-subframe energy coefficients from [`calc_filt_energies`] plus the (MR475/MR795-only) optimum
/// codebook gain, in DPF exponent/fraction form.
#[derive(Debug, Clone, Copy, Default)]
struct FiltEnergies {
    /// Energy coefficients, fraction part, Q15 (`frac_coeff[5]`).
    frac_coeff: [i16; 5],
    /// Energy coefficients, exponent part, Q0 (`exp_coeff[5]`).
    exp_coeff: [i16; 5],
    /// Optimum codebook gain, fraction, Q15 (`cod_gain_frac`) — MR475/MR795 only.
    cod_gain_frac: i16,
    /// Optimum codebook gain, exponent, Q0 (`cod_gain_exp`) — MR475/MR795 only.
    cod_gain_exp: i16,
}

/// Compute the five filtered-energy coefficients for gain quantization (`calc_en.c`
/// `calc_filt_energies`):
///
/// ```text
///   coeff[0] =    <y1 y1>   coeff[1] = -2 <xn y1>   coeff[2] =   <y2 y2>
///   coeff[3] = -2 <xn y2>   coeff[4] =  2 <y1 y2>
/// ```
///
/// `<y1 y1>`/`<xn y1>` come pre-computed in `g_coeff` (from `g_pitch`). For MR475/MR795 it also
/// computes the optimum codebook gain `gcu = <xn2 y2> / <y2 y2>`. `y2` is the filtered innovation
/// (Q12).
fn calc_filt_energies(
    mode: AmrNbMode,
    xn: &[i16],
    xn2: &[i16],
    y1: &[i16],
    filtered_y2: &[i16],
    g_coeff: &[i16; 4],
) -> FiltEnergies {
    let mut out = FiltEnergies::default();

    // ener_init: MR795/MR475 use 0, others 1 (avoid case of all zeros in norm_l).
    let ener_init: i32 = if mode == AmrNbMode::Mr795 || mode == AmrNbMode::Mr475 {
        0
    } else {
        1
    };

    // y2 = Y2 >> 3 (Q12 -> Q9).
    let mut y2 = [0i16; L_SUBFR];
    for (dst, &src) in y2.iter_mut().zip(filtered_y2.iter()) {
        *dst = shr(src, 3);
    }

    out.frac_coeff[0] = g_coeff[0];
    out.exp_coeff[0] = g_coeff[1];
    out.frac_coeff[1] = negate(g_coeff[2]); // coeff[1] = -2 xn y1
    out.exp_coeff[1] = add(g_coeff[3], 1);

    // <y2 y2>
    let mut s = l_mac(ener_init, y2[0], y2[0]);
    for &v in &y2[1..L_SUBFR] {
        s = l_mac(s, v, v);
    }
    let exp = norm_l(s);
    out.frac_coeff[2] = extract_h(l_shl(s, exp));
    out.exp_coeff[2] = sub(15 - 18, exp);

    // -2*<xn y2>
    let mut s = l_mac(ener_init, xn[0], y2[0]);
    for i in 1..L_SUBFR {
        s = l_mac(s, xn[i], y2[i]);
    }
    let exp = norm_l(s);
    out.frac_coeff[3] = negate(extract_h(l_shl(s, exp)));
    out.exp_coeff[3] = sub(15 - 9 + 1, exp);

    // 2*<y1 y2>
    let mut s = l_mac(ener_init, y1[0], y2[0]);
    for i in 1..L_SUBFR {
        s = l_mac(s, y1[i], y2[i]);
    }
    let exp = norm_l(s);
    out.frac_coeff[4] = extract_h(l_shl(s, exp));
    out.exp_coeff[4] = sub(15 - 9 + 1, exp);

    if mode == AmrNbMode::Mr475 || mode == AmrNbMode::Mr795 {
        // <xn2 y2>
        let mut s = l_mac(ener_init, xn2[0], y2[0]);
        for i in 1..L_SUBFR {
            s = l_mac(s, xn2[i], y2[i]);
        }
        let exp = norm_l(s);
        let frac = extract_h(l_shl(s, exp));
        let exp = sub(15 - 9, exp);

        if frac <= 0 {
            out.cod_gain_frac = 0;
            out.cod_gain_exp = 0;
        } else {
            // gcu = <xn2 y2>/c[2] = div_s(frac>>1, frac[2]) * 2^(exp-exp[2]-14)
            out.cod_gain_frac = div_s(shr(frac, 1), out.frac_coeff[2]);
            out.cod_gain_exp = sub(sub(exp, out.exp_coeff[2]), 14);
        }
    }

    out
}

/// Target energy `en = <xn xn>` in DPF exponent/fraction form (`calc_en.c` `calc_target_energy`).
/// Returns `(en_exp, en_frac)`.
fn calc_target_energy(xn: &[i16]) -> (i16, i16) {
    let mut s = l_mac(0, xn[0], xn[0]);
    for &v in &xn[1..L_SUBFR] {
        s = l_mac(s, v, v);
    }
    let exp = norm_l(s);
    let en_frac = extract_h(l_shl(s, exp));
    let en_exp = sub(16, exp);
    (en_exp, en_frac)
}

/// Innovative codebook gain `g = <xn2 y2> / <y2 y2>` (`g_code.c` `G_code`), Q1. Returns 0 when the
/// cross-correlation is non-positive.
#[must_use]
pub fn g_code(xn2: &[i16], y2: &[i16]) -> i16 {
    // Scale down y2 by 2 to avoid overflow.
    let mut scal_y2 = [0i16; L_SUBFR];
    for (dst, &src) in scal_y2.iter_mut().zip(y2.iter()) {
        *dst = shr(src, 1);
    }

    // <xn2, y2>  (seed 1 to avoid all-zeros).
    let mut s: i32 = 1;
    for i in 0..L_SUBFR {
        s = l_mac(s, xn2[i], scal_y2[i]);
    }
    let exp_xy = norm_l(s);
    let xy = extract_h(l_shl(s, exp_xy));

    if xy <= 0 {
        return 0;
    }

    // <y2, y2>
    let mut s: i32 = 0;
    for &v in &scal_y2 {
        s = l_mac(s, v, v);
    }
    let exp_yy = norm_l(s);
    let yy = extract_h(l_shl(s, exp_yy));

    // gain = xy/yy
    let xy = shr(xy, 1); // be sure xy < yy
    let gain = div_s(xy, yy);

    // denormalization of division: i = exp_xy + 5 - exp_yy
    let i = add(exp_xy, 5);
    let i = sub(i, exp_yy);

    shl(shr(gain, i), 1) // Q0 -> Q1
}

/// Scalar quantization of the innovative codebook gain (`q_gain_c.c` `q_gain_code`), MR122/MR795.
/// `gain` (Q1) is updated in place to the quantized value; returns the quantizer index plus
/// `(qua_ener_mr122, qua_ener)` (Q10) for the MA predictor update.
///
/// This tier only brings up MR122 in the dispatch; the MR795 arithmetic path is kept for parity.
#[must_use]
fn q_gain_code(
    mode: AmrNbMode,
    exp_gcode0: i16,
    frac_gcode0: i16,
    gain: &mut i16,
) -> (i16, i16, i16) {
    let is_mr122 = mode == AmrNbMode::Mr1220;

    let g_q0 = if is_mr122 { shr(*gain, 1) } else { 0 };

    // predicted gain gc0 = Pow2(exp_gcode0 + frac_gcode0)
    let mut gcode0 = extract_l(pow2(exp_gcode0, frac_gcode0));
    gcode0 = if is_mr122 {
        shl(gcode0, 4)
    } else {
        shl(gcode0, 5)
    };

    // Search for the best quantizer.
    let mut index = 0usize;
    let candidate = |i: usize| -> i16 {
        // qua_gain_code row i = (g_fac, qua_ener_MR122, qua_ener); step 3.
        let g_fac = QUA_GAIN_CODE[3 * i];
        if is_mr122 {
            abs_s(sub(g_q0, mult(gcode0, g_fac)))
        } else {
            abs_s(sub(*gain, mult(gcode0, g_fac)))
        }
    };
    let mut err_min = candidate(0);
    for i in 1..NB_QUA_CODE {
        let err = candidate(i);
        if sub(err, err_min) < 0 {
            err_min = err;
            index = i;
        }
    }

    let p = 3 * index;
    let g_fac = QUA_GAIN_CODE[p];
    *gain = if is_mr122 {
        shl(mult(gcode0, g_fac), 1)
    } else {
        mult(gcode0, g_fac)
    };

    let qua_ener_mr122 = QUA_GAIN_CODE[p + 1];
    let qua_ener = QUA_GAIN_CODE[p + 2];

    (index as i16, qua_ener_mr122, qua_ener)
}

/// Standard joint pitch+code gain VQ (`qua_gain.c` `Qua_gain`) for the medium-rate modes
/// (MR59/MR515/MR67/MR74/MR102). Chooses the table entry minimizing the reconstruction MSE subject
/// to the pitch-gain limit, writes `gain_pit` (Q14) / `gain_cod` (Q1), and returns the index plus
/// `(qua_ener_mr122, qua_ener)` (Q10) for the predictor update.
#[must_use]
fn qua_gain(
    mode: AmrNbMode,
    exp_gcode0: i16,
    frac_gcode0: i16,
    energies: &FiltEnergies,
    gp_limit: i16,
    gain_pit: &mut i16,
    gain_cod: &mut i16,
) -> (i16, i16, i16) {
    let (table_gain, table_len): (&[i16], usize) =
        if mode == AmrNbMode::Mr1020 || mode == AmrNbMode::Mr740 || mode == AmrNbMode::Mr670 {
            (&TABLE_GAIN_HIGHRATES, VQ_SIZE_HIGHRATES)
        } else {
            (&TABLE_GAIN_LOWRATES, VQ_SIZE_LOWRATES)
        };

    // gcode0 (Q14) = 2^14 * 2^frac_gcode0
    let gcode0 = extract_l(pow2(14, frac_gcode0));

    // scaling exponent for g_code: ec = ec0 - 11
    let exp_code = sub(exp_gcode0, 11);
    let frac_coeff = &energies.frac_coeff;
    let exp_coeff = &energies.exp_coeff;

    let mut exp_max = [0i16; 5];
    exp_max[0] = sub(exp_coeff[0], 13);
    exp_max[1] = sub(exp_coeff[1], 14);
    exp_max[2] = add(exp_coeff[2], add(15, shl(exp_code, 1)));
    exp_max[3] = add(exp_coeff[3], exp_code);
    exp_max[4] = add(exp_coeff[4], add(1, exp_code));

    let mut e_max = exp_max[0];
    for &e in exp_max.iter().skip(1) {
        if sub(e, e_max) > 0 {
            e_max = e;
        }
    }
    e_max = add(e_max, 1); // avoid overflow

    let mut coeff = [0i16; 5];
    let mut coeff_lo = [0i16; 5];
    for i in 0..5 {
        let j = sub(e_max, exp_max[i]);
        let l_tmp = l_shr(l_deposit_h(frac_coeff[i]), j);
        let (hi, lo) = l_extract(l_tmp);
        coeff[i] = hi;
        coeff_lo[i] = lo;
    }

    // Codebook search.
    let mut dist_min = i32::MAX;
    let mut index = 0usize;
    for i in 0..table_len {
        let base = i << 2;
        let g_pitch = table_gain[base];
        let g_code_raw = table_gain[base + 1];

        if sub(g_pitch, gp_limit) <= 0 {
            let g_code = mult(g_code_raw, gcode0);
            let g2_pitch = mult(g_pitch, g_pitch);
            let g2_code = mult(g_code, g_code);
            let g_pit_cod = mult(g_code, g_pitch);

            let mut l_tmp = mpy_32_16(coeff[0], coeff_lo[0], g2_pitch);
            l_tmp = l_add(l_tmp, mpy_32_16(coeff[1], coeff_lo[1], g_pitch));
            l_tmp = l_add(l_tmp, mpy_32_16(coeff[2], coeff_lo[2], g2_code));
            l_tmp = l_add(l_tmp, mpy_32_16(coeff[3], coeff_lo[3], g_code));
            l_tmp = l_add(l_tmp, mpy_32_16(coeff[4], coeff_lo[4], g_pit_cod));

            if crate::amr::basic_ops::l_sub(l_tmp, dist_min) < 0 {
                dist_min = l_tmp;
                index = i;
            }
        }
    }

    // Read quantized gains.
    let base = index << 2;
    *gain_pit = table_gain[base];
    let g_code_raw = table_gain[base + 1];
    let qua_ener_mr122 = table_gain[base + 2];
    let qua_ener = table_gain[base + 3];

    // gc = gc0 * g
    let l_tmp = l_mult(g_code_raw, gcode0);
    let l_tmp = l_shr(l_tmp, sub(10, exp_gcode0));
    *gain_cod = extract_h(l_tmp);

    (index as i16, qua_ener_mr122, qua_ener)
}

/// Update the "unquantized" MA predictor with the (bounded) optimum-CB-gain prediction error
/// (`qgain475.c` `MR475_update_unq_pred`). Used only on the MR475 even subframe.
fn mr475_update_unq_pred(
    pred_state: &mut GcPredState,
    exp_gcode0: i16,
    frac_gcode0: i16,
    cod_gain_exp: i16,
    cod_gain_frac: i16,
) {
    let (qua_ener, qua_ener_mr122);

    if cod_gain_frac <= 0 {
        // gcu <= 0 -> predErrFact = 0 < MIN_PRED_ERR_FACT
        qua_ener = MIN_QUA_ENER;
        qua_ener_mr122 = MIN_QUA_ENER_MR122;
    } else {
        // gcode0 in DPF -> normalized fraction (16384..32767); exp correction after div_s.
        let frac_gcode0_norm = extract_l(pow2(14, frac_gcode0));

        // ensure cod_gain_frac < frac_gcode0 for div_s.
        let (mut cod_gain_frac, mut cod_gain_exp) = (cod_gain_frac, cod_gain_exp);
        if sub(cod_gain_frac, frac_gcode0_norm) >= 0 {
            cod_gain_frac = shr(cod_gain_frac, 1);
            cod_gain_exp = add(cod_gain_exp, 1);
        }

        // predErrFact = div_s * 2^(cod_gain_exp - exp_gcode0 - 1)
        let frac = div_s(cod_gain_frac, frac_gcode0_norm);
        let tmp = sub(sub(cod_gain_exp, exp_gcode0), 1);

        let (mut exp, frac) = log2(l_deposit_l(frac));
        exp = add(exp, tmp);

        let mut qe_mr122 = shr_r(frac, 5);
        qe_mr122 = add(qe_mr122, shl(exp, 10));

        if sub(qe_mr122, MIN_QUA_ENER_MR122) < 0 {
            qua_ener = MIN_QUA_ENER;
            qua_ener_mr122 = MIN_QUA_ENER_MR122;
        } else if sub(qe_mr122, MAX_QUA_ENER_MR122) > 0 {
            qua_ener = MAX_QUA_ENER;
            qua_ener_mr122 = MAX_QUA_ENER_MR122;
        } else {
            let l_tmp = mpy_32_16(exp, frac, 24660); // 24660 Q12 ~= 20*log10(2)
            qua_ener = round_word(l_shl(l_tmp, 13)); // -> Q10
            qua_ener_mr122 = qe_mr122;
        }
    }

    gc_pred_update(pred_state, qua_ener_mr122, qua_ener);
}

/// Read a selected MR475 quantizer row (`qgain475.c` `MR475_quant_store_results`): store the pitch
/// gain (Q14) and final code gain (Q1), then update the real MA predictor with the row's derived
/// energy error. `table_off` is the `index*4 (+2 for sf1)` offset into `TABLE_GAIN_MR475`.
fn mr475_quant_store_results(
    pred_state: &mut GcPredState,
    table_off: usize,
    gcode0: i16,
    exp_gcode0: i16,
    gain_pit: &mut i16,
    gain_cod: &mut i16,
) {
    *gain_pit = TABLE_GAIN_MR475[table_off];
    let g_code = TABLE_GAIN_MR475[table_off + 1];

    // gc = gc0 * g
    let l_tmp = l_mult(g_code, gcode0);
    let l_tmp = l_shr(l_tmp, sub(10, exp_gcode0));
    *gain_cod = extract_h(l_tmp);

    // qua_ener = log2(g); qua_ener_MR122 = 20*log10(g). Log2(x Q12) = log2(x)+12.
    let (mut exp, frac) = log2(l_deposit_l(g_code));
    exp = sub(exp, 12);

    let tmp = shr_r(frac, 5);
    let qua_ener_mr122 = add(tmp, shl(exp, 10));

    let l_tmp = mpy_32_16(exp, frac, 24660); // 24660 Q12 ~= 20*log10(2)
    let qua_ener = round_word(l_shl(l_tmp, 13)); // Q13 -> Q10

    gc_pred_update(pred_state, qua_ener_mr122, qua_ener);
}

/// Deferred subframe-0 data for the MR475 joint gain quantizer (`gainQuantState` sf0_* fields).
#[derive(Debug, Clone, Copy, Default)]
struct Mr475Sf0 {
    exp_gcode0: i16,
    frac_gcode0: i16,
    exp_target_en: i16,
    frac_target_en: i16,
    frac_coeff: [i16; 5],
    exp_coeff: [i16; 5],
}

/// MR795 gain-adaptation state (`g_adapt.h` `GainAdaptState`). All fields reset to 0
/// (`gain_adapt_reset`). `ltpg_mem[0]` is scratch for the `gmed_n(.., 5)` call — the true history
/// depth is `LTPG_MEM_SIZE - 1`.
#[derive(Debug, Clone, Copy, Default)]
pub struct GainAdaptState {
    /// Onset state, Q0.
    onset: i16,
    /// Previous adaptor output (alpha), Q15.
    prev_alpha: i16,
    /// Previous code gain, Q1.
    prev_gc: i16,
    /// LTP coding-gain history, Q13 (`[0]` not used for history).
    ltpg_mem: [i16; LTPG_MEM_SIZE],
}

/// Encoder gain-quantizer state (`gain_q.h` `gainQuantState`). Holds the two MA gain predictors, the
/// MR475 deferred subframe-0 data, and the MR795 gain-adaptor sub-state.
///
/// Tier 6 owns exactly one of these per encoder and threads it across all subframes/frames; it is
/// reset (both predictors seeded to their minima, sf0 cleared, adaptor zeroed) at encoder init/homing.
#[derive(Debug, Clone)]
pub struct GainQuantState {
    /// "Real" (quantized) MA gain predictor (`gc_predSt`).
    pub gc_pred: GcPredState,
    /// "Unquantized" MA gain predictor, MR475 only (`gc_predUnqSt`).
    pub gc_pred_unq: GcPredState,
    /// Deferred subframe-0 data for the MR475 joint quantizer.
    sf0: Mr475Sf0,
    /// MR795 gain-adaptation sub-state (`adaptSt`).
    adapt: GainAdaptState,
}

impl Default for GainQuantState {
    fn default() -> Self {
        Self::new()
    }
}

impl GainQuantState {
    /// Reset both predictors to their minima, clear the MR475 deferred data and zero the MR795
    /// adaptor (`gainQuant_reset`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            gc_pred: GcPredState::new(),
            gc_pred_unq: GcPredState::new(),
            sf0: Mr475Sf0::default(),
            adapt: GainAdaptState::default(),
        }
    }
}

/// Result of [`gain_quant`]: the quantized gains for the current subframe plus the transmitted gain
/// index/indices for `ana`. For MR475 even subframes nothing is emitted (`num_params == 0`) and the
/// gains are the *unquantized* optimum; on the odd subframe the joint index is emitted
/// (`num_params == 1`) and both subframes' quantized gains are returned (`sf0_gain_*` carry
/// subframe 0's).
#[derive(Debug, Clone, Copy, Default)]
pub struct GainQuantResult {
    /// Quantized pitch gain for this subframe, Q14 (odd/standard) — MR475 even: unquantized optimum.
    pub gain_pit: i16,
    /// Quantized code gain for this subframe, Q1.
    pub gain_cod: i16,
    /// MR475 subframe-0 quantized pitch gain, Q14 (only meaningful on the odd subframe).
    pub sf0_gain_pit: i16,
    /// MR475 subframe-0 quantized code gain, Q1 (only meaningful on the odd subframe).
    pub sf0_gain_cod: i16,
    /// Transmitted gain index/indices for `ana` (in write order). MR795 emits two (pitch-gain then
    /// code-gain index); every other mode emits one.
    pub params: [i16; 2],
    /// Number of valid entries in `params` (0 for MR475 even subframe, 2 for MR795, else 1).
    pub num_params: usize,
}

/// Full encoder gain quantizer (`gain_q.c` `gainQuant`) — dispatches the standard per-subframe path
/// (MR122 → [`g_code`]+`q_gain_code`; medium rates → `qua_gain`), the MR475 joint 2-subframe path,
/// and the MR795 adaptive two-index path. Threads and updates the MA gain predictor state in `st`.
///
/// Inputs mirror the C `gainQuant(...)` call site:
///   * `res` — LP residual (Q0), `exc` — LTP excitation (Q0) — used by MR795 (`calc_unfilt_energies`).
///   * `code` — CB innovation (Q13 for medium rates, Q12 for MR122; unsharpened for MR475).
///   * `xn` / `xn2` — LTP / CB target vectors; `y1` — adaptive codebook; `y2` — filtered innovation
///     (Q12); `g_coeff` — `<xn y1>`/`<y1 y1>` correlations from `g_pitch`.
///   * `even_subframe` — 1 on subframes 0/2, 0 on 1/3 (drives the MR475 defer/quantize split).
///   * `gp_limit` — pitch-gain clip limit.
///   * `gain_pit` — closed-loop pitch gain (Q14), updated in place to the quantized value.
///
/// Every speech mode (MR475..MR122) is wired; only the DTX/SID path is out of scope.
#[allow(clippy::too_many_arguments)]
pub fn gain_quant(
    st: &mut GainQuantState,
    mode: AmrNbMode,
    res: &[i16],
    exc: &[i16],
    code: &[i16],
    xn: &[i16],
    xn2: &[i16],
    y1: &[i16],
    y2: &[i16],
    g_coeff: &[i16; 4],
    even_subframe: i16,
    gp_limit: i16,
    gain_pit: &mut i16,
) -> Result<GainQuantResult, CodecError> {
    let mut result = GainQuantResult::default();

    if mode == AmrNbMode::Mr475 {
        if even_subframe != 0 {
            // Save current predictor state; predict CB gain with the "unquantized" predictor.
            gc_pred_copy(&st.gc_pred, &mut st.gc_pred_unq);
            let pred = gc_pred(&st.gc_pred_unq, AmrNbMode::Mr475 as usize, code);
            st.sf0.exp_gcode0 = pred.exp_gcode0;
            st.sf0.frac_gcode0 = pred.frac_gcode0;

            // Energy coefficients for quantization (stored for the odd subframe).
            let energies = calc_filt_energies(mode, xn, xn2, y1, y2, g_coeff);
            st.sf0.frac_coeff = energies.frac_coeff;
            st.sf0.exp_coeff = energies.exp_coeff;

            // Optimum codebook gain (Q1): gain_cod = cod_gain_frac << (cod_gain_exp + 1).
            let gain_cod = shl(energies.cod_gain_frac, add(energies.cod_gain_exp, 1));

            let (en_exp, en_frac) = calc_target_energy(xn);
            st.sf0.exp_target_en = en_exp;
            st.sf0.frac_target_en = en_frac;

            // Update the "unquantized" predictor with the optimum CB gain.
            mr475_update_unq_pred(
                &mut st.gc_pred_unq,
                st.sf0.exp_gcode0,
                st.sf0.frac_gcode0,
                energies.cod_gain_exp,
                energies.cod_gain_frac,
            );

            // Even subframe: gains are the unquantized optimum, nothing transmitted yet.
            result.gain_cod = gain_cod;
            result.gain_pit = *gain_pit;
            result.num_params = 0;
        } else {
            // Odd subframe: predict CB gain (unquantized predictor) + energy coefficients.
            let pred = gc_pred(&st.gc_pred_unq, AmrNbMode::Mr475 as usize, code);
            let energies = calc_filt_energies(mode, xn, xn2, y1, y2, g_coeff);
            let (en_exp, en_frac) = calc_target_energy(xn);

            // Run the joint 4-D quantizer + update the real predictor.
            let (index, sf0_gp, sf0_gc, sf1_gp, sf1_gc) = mr475_gain_quant(
                &mut st.gc_pred,
                &st.sf0,
                code,
                pred.exp_gcode0,
                pred.frac_gcode0,
                &energies,
                en_exp,
                en_frac,
                gp_limit,
            );

            result.sf0_gain_pit = sf0_gp;
            result.sf0_gain_cod = sf0_gc;
            result.gain_pit = sf1_gp;
            result.gain_cod = sf1_gc;
            *gain_pit = sf1_gp;
            result.params[0] = index;
            result.num_params = 1;
        }
        return Ok(result);
    }

    // Standard per-subframe path: predict CB gain with the real predictor.
    let pred = gc_pred(&st.gc_pred, mode as usize, code);

    let (index, qua_ener_mr122, qua_ener);
    if mode == AmrNbMode::Mr1220 {
        let mut gc = g_code(xn2, y2);
        let (idx, qe122, qe) = q_gain_code(mode, pred.exp_gcode0, pred.frac_gcode0, &mut gc);
        result.gain_cod = gc;
        index = idx;
        qua_ener_mr122 = qe122;
        qua_ener = qe;
    } else if mode == AmrNbMode::Mr795 {
        // MR795: pre-quantize the CB gain over 3 pitch-gain candidates, run the gain adaptor, then
        // the modified quantizer. Emits TWO params (pitch-gain index then code-gain index); the CB
        // innovation energy `(exp_en, frac_en)` comes from `gc_pred` above.
        let energies = calc_filt_energies(mode, xn, xn2, y1, y2, g_coeff);
        let mut gain_cod = 0i16;
        let (gain_pit_index, gain_cod_index, qua_ener_mr122, qua_ener) = mr795_gain_quant(
            &mut st.adapt,
            res,
            exc,
            code,
            &energies.frac_coeff,
            &energies.exp_coeff,
            pred.exp_en,
            pred.frac_en,
            pred.exp_gcode0,
            pred.frac_gcode0,
            energies.cod_gain_frac,
            energies.cod_gain_exp,
            gp_limit,
            gain_pit,
            &mut gain_cod,
        );
        gc_pred_update(&mut st.gc_pred, qua_ener_mr122, qua_ener);
        result.gain_cod = gain_cod;
        result.gain_pit = *gain_pit;
        result.params[0] = gain_pit_index;
        result.params[1] = gain_cod_index;
        result.num_params = 2;
        return Ok(result);
    } else if matches!(
        mode,
        AmrNbMode::Mr590
            | AmrNbMode::Mr515
            | AmrNbMode::Mr670
            | AmrNbMode::Mr740
            | AmrNbMode::Mr1020
    ) {
        let energies = calc_filt_energies(mode, xn, xn2, y1, y2, g_coeff);
        let mut gain_cod = 0i16;
        let (idx, qe122, qe) = qua_gain(
            mode,
            pred.exp_gcode0,
            pred.frac_gcode0,
            &energies,
            gp_limit,
            gain_pit,
            &mut gain_cod,
        );
        result.gain_cod = gain_cod;
        result.gain_pit = *gain_pit;
        index = idx;
        qua_ener_mr122 = qe122;
        qua_ener = qe;
    } else {
        // Unreachable: every speech mode is handled above. Kept as a defensive fallback (the DTX/SID
        // path never calls the per-subframe gain quantizer).
        return Err(CodecError::Unsupported(
            "AMR-NB gain quantization: unexpected mode (all speech modes are wired)",
        ));
    }

    // Update the real predictor with the last quantized energy.
    gc_pred_update(&mut st.gc_pred, qua_ener_mr122, qua_ener);

    result.gain_pit = *gain_pit;
    result.params[0] = index;
    result.num_params = 1;
    Ok(result)
}

/// Joint 2-subframe MR475 gain quantizer (`qgain475.c` `MR475_gain_quant`). Searches
/// `TABLE_GAIN_MR475` (each row = `(sf0_gain_pit, sf0_g_code, sf1_gain_pit, sf1_g_code)`) for the
/// index minimizing the combined (energy-equalized) MSE of both subframes, then reads back the
/// quantized gains and threads the real MA predictor across the two subframes.
///
/// Returns `(index, sf0_gain_pit, sf0_gain_cod, sf1_gain_pit, sf1_gain_cod)`.
#[allow(clippy::too_many_arguments)]
fn mr475_gain_quant(
    pred_state: &mut GcPredState,
    sf0: &Mr475Sf0,
    sf1_code_nosharp: &[i16],
    sf1_exp_gcode0: i16,
    sf1_frac_gcode0: i16,
    sf1_energies: &FiltEnergies,
    sf1_exp_target_en: i16,
    sf1_frac_target_en: i16,
    gp_limit: i16,
) -> (i16, i16, i16, i16, i16) {
    let sf0_gcode0 = extract_l(pow2(14, sf0.frac_gcode0));
    let mut sf1_gcode0 = extract_l(pow2(14, sf1_frac_gcode0));

    let mut exp_max = [0i16; 10]; // 0..4: sf0, 5..9: sf1

    // sf0 scaling
    let exp = sub(sf0.exp_gcode0, 11);
    exp_max[0] = sub(sf0.exp_coeff[0], 13);
    exp_max[1] = sub(sf0.exp_coeff[1], 14);
    exp_max[2] = add(sf0.exp_coeff[2], add(15, shl(exp, 1)));
    exp_max[3] = add(sf0.exp_coeff[3], exp);
    exp_max[4] = add(sf0.exp_coeff[4], add(1, exp));

    // sf1 scaling
    let exp = sub(sf1_exp_gcode0, 11);
    exp_max[5] = sub(sf1_energies.exp_coeff[0], 13);
    exp_max[6] = sub(sf1_energies.exp_coeff[1], 14);
    exp_max[7] = add(sf1_energies.exp_coeff[2], add(15, shl(exp, 1)));
    exp_max[8] = add(sf1_energies.exp_coeff[3], exp);
    exp_max[9] = add(sf1_energies.exp_coeff[4], add(1, exp));

    // Gain search equalisation: normalize target-energy exponents, then bias sf0 by +/-1.
    let mut sf0_frac_target_en = sf0.frac_target_en;
    let mut sf1_frac_target_en = sf1_frac_target_en;
    let exp = sub(sf0.exp_target_en, sf1_exp_target_en);
    if exp > 0 {
        sf1_frac_target_en = shr(sf1_frac_target_en, exp);
    } else {
        sf0_frac_target_en = shl(sf0_frac_target_en, exp);
    }

    let mut exp = 0i16;
    let tmp = shr_r(sf1_frac_target_en, 1); // ceil(0.5*en(sf1))
    if sub(tmp, sf0_frac_target_en) > 0 {
        // en(sf1) > 2*en(sf0) -> scale up MSE(sf0) by 2
        exp = 1;
    } else {
        let tmp = shr(add(sf0_frac_target_en, 3), 2); // ceil(0.25*en(sf0))
        if sub(tmp, sf1_frac_target_en) > 0 {
            // en(sf1) < 0.25*en(sf0) -> scale down MSE(sf0) by 0.5
            exp = -1;
        }
    }
    for e in exp_max.iter_mut().take(5) {
        *e = add(*e, exp);
    }

    // Find maximum exponent (+1) for common re-scaling.
    let mut e_max = exp_max[0];
    for &e in exp_max.iter().skip(1) {
        if sub(e, e_max) > 0 {
            e_max = e;
        }
    }
    e_max = add(e_max, 1);

    let mut coeff = [0i16; 10];
    let mut coeff_lo = [0i16; 10];
    for i in 0..5 {
        let tmp = sub(e_max, exp_max[i]);
        let l_tmp = l_shr(l_deposit_h(sf0.frac_coeff[i]), tmp);
        let (hi, lo) = l_extract(l_tmp);
        coeff[i] = hi;
        coeff_lo[i] = lo;
    }
    for i in 5..10 {
        let tmp = sub(e_max, exp_max[i]);
        let l_tmp = l_shr(l_deposit_h(sf1_energies.frac_coeff[i - 5]), tmp);
        let (hi, lo) = l_extract(l_tmp);
        coeff[i] = hi;
        coeff_lo[i] = lo;
    }

    // Codebook search over both subframes jointly.
    let mut dist_min = i32::MAX;
    let mut index = 0usize;
    for i in 0..MR475_VQ_SIZE {
        let base = i << 2;

        // subframe 0
        let g_pitch0 = TABLE_GAIN_MR475[base];
        let g_code0 = mult(TABLE_GAIN_MR475[base + 1], sf0_gcode0);
        let g2_pitch0 = mult(g_pitch0, g_pitch0);
        let g2_code0 = mult(g_code0, g_code0);
        let g_pit_cod0 = mult(g_code0, g_pitch0);

        let mut l_tmp = mpy_32_16(coeff[0], coeff_lo[0], g2_pitch0);
        l_tmp = mac_32_16(l_tmp, coeff[1], coeff_lo[1], g_pitch0);
        l_tmp = mac_32_16(l_tmp, coeff[2], coeff_lo[2], g2_code0);
        l_tmp = mac_32_16(l_tmp, coeff[3], coeff_lo[3], g_code0);
        l_tmp = mac_32_16(l_tmp, coeff[4], coeff_lo[4], g_pit_cod0);

        let tmp = sub(g_pitch0, gp_limit);

        // subframe 1
        let g_pitch1 = TABLE_GAIN_MR475[base + 2];
        let g_code1_raw = TABLE_GAIN_MR475[base + 3];

        if tmp <= 0 && sub(g_pitch1, gp_limit) <= 0 {
            let g_code1 = mult(g_code1_raw, sf1_gcode0);
            let g2_pitch1 = mult(g_pitch1, g_pitch1);
            let g2_code1 = mult(g_code1, g_code1);
            let g_pit_cod1 = mult(g_code1, g_pitch1);

            l_tmp = mac_32_16(l_tmp, coeff[5], coeff_lo[5], g2_pitch1);
            l_tmp = mac_32_16(l_tmp, coeff[6], coeff_lo[6], g_pitch1);
            l_tmp = mac_32_16(l_tmp, coeff[7], coeff_lo[7], g2_code1);
            l_tmp = mac_32_16(l_tmp, coeff[8], coeff_lo[8], g_code1);
            l_tmp = mac_32_16(l_tmp, coeff[9], coeff_lo[9], g_pit_cod1);

            if crate::amr::basic_ops::l_sub(l_tmp, dist_min) < 0 {
                dist_min = l_tmp;
                index = i;
            }
        }
    }

    // Read quantized gains + thread the real predictor: sf0 first, then re-predict sf1 with the
    // now-updated quantized predictor.
    let base = index << 2;
    let mut sf0_gain_pit = 0i16;
    let mut sf0_gain_cod = 0i16;
    mr475_quant_store_results(
        pred_state,
        base,
        sf0_gcode0,
        sf0.exp_gcode0,
        &mut sf0_gain_pit,
        &mut sf0_gain_cod,
    );

    // Re-predict sf1 with the real (quantized) predictor.
    let pred = gc_pred(pred_state, AmrNbMode::Mr475 as usize, sf1_code_nosharp);
    let sf1_exp_gcode0 = pred.exp_gcode0;
    sf1_gcode0 = extract_l(pow2(14, pred.frac_gcode0));

    let mut sf1_gain_pit = 0i16;
    let mut sf1_gain_cod = 0i16;
    mr475_quant_store_results(
        pred_state,
        base + 2,
        sf1_gcode0,
        sf1_exp_gcode0,
        &mut sf1_gain_pit,
        &mut sf1_gain_cod,
    );

    (
        index as i16,
        sf0_gain_pit,
        sf0_gain_cod,
        sf1_gain_pit,
        sf1_gain_cod,
    )
}

// =============================================================================================
//  MR795 gain quantization (qgain795.c + g_adapt.c + q_gain_p.c + calc_en.c)
// =============================================================================================

/// `Mac_32(L_32, hi1, lo1, hi2, lo2)` (`mac_32.c`) — accumulate a 32×32 DPF product:
/// `L_32 + hi1·hi2·2 + (mult(hi1,lo2) + mult(lo1,hi2))·2`, in the reference's saturating order.
#[inline]
fn mac_32(l_32: i32, hi1: i16, lo1: i16, hi2: i16, lo2: i16) -> i32 {
    let l_32 = l_mac(l_32, hi1, hi2);
    let l_32 = l_mac(l_32, mult(hi1, lo2), 1);
    l_mac(l_32, mult(lo1, hi2), 1)
}

/// N-point median (`gmed_n.c` `gmed_n`) — the value of the median element (odd `n <= 9`), ties
/// breaking toward the earlier index (`>=` in the max scan), exactly as the reference.
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

/// `g_adapt.c` `gain_adapt` — the MR795 pitch/codebook gain adaptation factor `alpha` (Q15), plus
/// the adaptor-state update (onset detector + median-filtered LTP coding gain history).
fn gain_adapt(st: &mut GainAdaptState, ltpg: i16, gain_cod: i16) -> i16 {
    // basic adaptation (0 / 1 / 2 by LTP-gain thresholds)
    let mut adapt: i16 = if sub(ltpg, LTP_GAIN_THR1) <= 0 {
        0
    } else if sub(ltpg, LTP_GAIN_THR2) <= 0 {
        1
    } else {
        2
    };

    // onset indicator: cbGain / onFact (onFact = 2.0), 200 Q1 = 100.0
    let tmp = shr_r(gain_cod, 1);
    if sub(tmp, st.prev_gc) > 0 && sub(gain_cod, 200) > 0 {
        st.onset = 8;
    } else if st.onset != 0 {
        st.onset = sub(st.onset, 1);
    }

    // if onset, increase adaptor state
    if st.onset != 0 && sub(adapt, 2) < 0 {
        adapt = add(adapt, 1);
    }

    st.ltpg_mem[0] = ltpg;
    let filt = gmed_n(&st.ltpg_mem, 5); // median-filtered LTP coding gain, Q13

    let mut result: i16 = if adapt == 0 {
        if sub(filt, 5443) > 0 {
            0
        } else if filt < 0 {
            16384 // 0.5 Q15
        } else {
            // result = 0.5 - 0.75257499*filt = 16384 - 24660*(filt << 2)
            let filt = shl(filt, 2); // Q15
            sub(16384, mult(24660, filt))
        }
    } else {
        0
    };

    // if prevAlpha == 0: result = 0.5 * (result + prevAlpha)
    if st.prev_alpha == 0 {
        result = shr(result, 1);
    }

    let alpha = result;
    st.prev_alpha = result;
    st.prev_gc = gain_cod;
    for i in (1..LTPG_MEM_SIZE).rev() {
        st.ltpg_mem[i] = st.ltpg_mem[i - 1];
    }
    alpha
}

/// `q_gain_p.c` `q_gain_pitch` — MR795 branch: scalar-quantize the pitch gain against
/// [`QUA_GAIN_PITCH`] (respecting `gp_limit`), then build the three candidate gains/indices around
/// the found index (index and its two neighbours, shifted for the extreme cases). Sets `*gain` to
/// the quantized value and returns the found index.
fn q_gain_pitch_mr795(
    gp_limit: i16,
    gain: &mut i16,
    gain_cand: &mut [i16; 3],
    gain_cind: &mut [i16; 3],
) -> i16 {
    let mut err_min = abs_s(sub(*gain, QUA_GAIN_PITCH[0]));
    let mut index = 0i16;
    for (i, &cand) in QUA_GAIN_PITCH.iter().enumerate().take(NB_QUA_PITCH).skip(1) {
        if sub(cand, gp_limit) <= 0 {
            let err = abs_s(sub(*gain, cand));
            if sub(err, err_min) < 0 {
                err_min = err;
                index = i as i16;
            }
        }
    }

    // three gain_pit candidates around `index` (extreme cases shift by 2). The `index+1` read is
    // short-circuited when index == NB_QUA_PITCH-1 (matching the C `||`), so it never goes OOB.
    let mut ii: i16 = if index == 0 {
        index
    } else if sub(index, (NB_QUA_PITCH - 1) as i16) == 0
        || sub(QUA_GAIN_PITCH[(index + 1) as usize], gp_limit) > 0
    {
        sub(index, 2)
    } else {
        sub(index, 1)
    };

    for slot in 0..3 {
        gain_cind[slot] = ii;
        gain_cand[slot] = QUA_GAIN_PITCH[ii as usize];
        ii = add(ii, 1);
    }

    *gain = QUA_GAIN_PITCH[index as usize];
    index
}

/// `calc_en.c` `calc_unfilt_energies` — the four unfiltered-excitation energy coefficients and the
/// LTP coding gain for MR795:
/// `<res res>`, `<exc exc>`, `<exc code>`, `<lres lres>` (`lres = res - gain_pit·exc`), plus
/// `ltpg = log2(<res res> / <lres lres>)` Q13. Returns `(frac_en[4], exp_en[4], ltpg)`.
fn calc_unfilt_energies(
    res: &[i16],
    exc: &[i16],
    code: &[i16],
    gain_pit: i16,
) -> ([i16; 4], [i16; 4], i16) {
    let mut frac_en = [0i16; 4];
    let mut exp_en = [0i16; 4];

    // <res res>; ResEn := 0 if < 200.0 (= 400 Q1)
    let mut s = l_mac(0, res[0], res[0]);
    for &r in &res[1..L_SUBFR] {
        s = l_mac(s, r, r);
    }
    if l_sub(s, 400) < 0 {
        frac_en[0] = 0;
        exp_en[0] = -15;
    } else {
        let exp = norm_l(s);
        frac_en[0] = extract_h(l_shl(s, exp));
        exp_en[0] = sub(15, exp);
    }

    // <exc exc>
    let mut s = l_mac(0, exc[0], exc[0]);
    for &e in &exc[1..L_SUBFR] {
        s = l_mac(s, e, e);
    }
    let exp = norm_l(s);
    frac_en[1] = extract_h(l_shl(s, exp));
    exp_en[1] = sub(15, exp);

    // <exc code>
    let mut s = l_mac(0, exc[0], code[0]);
    for i in 1..L_SUBFR {
        s = l_mac(s, exc[i], code[i]);
    }
    let exp = norm_l(s);
    frac_en[2] = extract_h(l_shl(s, exp));
    exp_en[2] = sub(16 - 14, exp);

    // <lres lres>, lres = res - gain_pit*exc (Q0)
    let mut s: i32 = 0;
    for i in 0..L_SUBFR {
        let l_temp = l_shl(l_mult(exc[i], gain_pit), 1);
        let tmp = sub(res[i], round_word(l_temp));
        s = l_mac(s, tmp, tmp);
    }
    let exp = norm_l(s);
    let ltp_res_en = extract_h(l_shl(s, exp));
    let exp_lres = sub(15, exp);
    frac_en[3] = ltp_res_en;
    exp_en[3] = exp_lres;

    // LTP coding gain
    let ltpg = if ltp_res_en > 0 && frac_en[0] != 0 {
        let pred_gain = div_s(shr(frac_en[0], 1), ltp_res_en);
        let exp = sub(exp_lres, exp_en[0]);
        let l_temp = l_deposit_h(pred_gain);
        let l_temp = l_shr(l_temp, add(exp, 3));
        let (ltpg_exp, ltpg_frac) = log2(l_temp);
        let l_temp = l_comp(sub(ltpg_exp, 27), ltpg_frac);
        round_word(l_shl(l_temp, 13)) // Q13
    } else {
        0
    };

    (frac_en, exp_en, ltpg)
}

/// `qgain795.c` `MR795_gain_code_quant3` — pre-quantization of the codebook gain over the three
/// pitch-gain candidates (using the predicted CB gain). Chooses `(pit_ind, cod_ind)` minimizing the
/// 5-term MSE, writes `gain_pit`/`gain_pit_ind`/`gain_cod`/`gain_cod_ind` and returns
/// `(qua_ener_mr122, qua_ener)`.
#[allow(clippy::too_many_arguments)]
fn mr795_gain_code_quant3(
    exp_gcode0: i16,
    gcode0: i16,
    g_pitch_cand: &[i16; 3],
    g_pitch_cind: &[i16; 3],
    frac_coeff: &[i16; 5],
    exp_coeff: &[i16; 5],
    gain_pit: &mut i16,
    gain_pit_ind: &mut i16,
    gain_cod: &mut i16,
    gain_cod_ind: &mut i16,
) -> (i16, i16) {
    let exp_code = sub(exp_gcode0, 10);

    let mut exp_max = [0i16; 5];
    exp_max[0] = sub(exp_coeff[0], 13);
    exp_max[1] = sub(exp_coeff[1], 14);
    exp_max[2] = add(exp_coeff[2], add(15, shl(exp_code, 1)));
    exp_max[3] = add(exp_coeff[3], exp_code);
    exp_max[4] = add(exp_coeff[4], add(exp_code, 1));

    let mut e_max = exp_max[0];
    for &e in exp_max.iter().skip(1) {
        if sub(e, e_max) > 0 {
            e_max = e;
        }
    }
    e_max = add(e_max, 1);

    let mut coeff = [0i16; 5];
    let mut coeff_lo = [0i16; 5];
    for i in 0..5 {
        let j = sub(e_max, exp_max[i]);
        let l_tmp = l_shr(l_deposit_h(frac_coeff[i]), j);
        let (hi, lo) = l_extract(l_tmp);
        coeff[i] = hi;
        coeff_lo[i] = lo;
    }

    let mut dist_min = i32::MAX;
    let mut cod_ind = 0usize;
    let mut pit_ind = 0usize;

    for (j, &g_pitch) in g_pitch_cand.iter().enumerate() {
        let g2_pitch = mult(g_pitch, g_pitch);
        let l_tmp0 = mpy_32_16(coeff[0], coeff_lo[0], g2_pitch);
        let l_tmp0 = mac_32_16(l_tmp0, coeff[1], coeff_lo[1], g_pitch);

        for i in 0..NB_QUA_CODE {
            let g_code = mult(QUA_GAIN_CODE[3 * i], gcode0); // g_fac (Q11) · gcode0

            let l_tmp = l_mult(g_code, g_code);
            let (g2_code_h, g2_code_l) = l_extract(l_tmp);

            let l_tmp = l_mult(g_code, g_pitch);
            let (g_pit_cod_h, g_pit_cod_l) = l_extract(l_tmp);

            let l_tmp = mac_32(l_tmp0, coeff[2], coeff_lo[2], g2_code_h, g2_code_l);
            let l_tmp = mac_32_16(l_tmp, coeff[3], coeff_lo[3], g_code);
            let l_tmp = mac_32(l_tmp, coeff[4], coeff_lo[4], g_pit_cod_h, g_pit_cod_l);

            if l_sub(l_tmp, dist_min) < 0 {
                dist_min = l_tmp;
                cod_ind = i;
                pit_ind = j;
            }
        }
    }

    let p = 3 * cod_ind;
    let g_code = QUA_GAIN_CODE[p];
    let qua_ener_mr122 = QUA_GAIN_CODE[p + 1];
    let qua_ener = QUA_GAIN_CODE[p + 2];

    // gc = gc0 * g
    let l_tmp = l_mult(g_code, gcode0);
    let l_tmp = l_shr(l_tmp, sub(9, exp_gcode0));
    *gain_cod = extract_h(l_tmp);
    *gain_cod_ind = cod_ind as i16;
    *gain_pit = g_pitch_cand[pit_ind];
    *gain_pit_ind = g_pitch_cind[pit_ind];

    (qua_ener_mr122, qua_ener)
}

/// `qgain795.c` `MR795_gain_code_quant_mod` — modified quantization of the MR795 codebook gain using
/// the gain-adaptor factor `alpha` and the unfiltered energy coefficients. Searches the quantizer
/// table (with the `g_code >= gain_code` early break) for the lowest adaptor-weighted distance,
/// writes the quantized `gain_cod`, and returns `(index, qua_ener_mr122, qua_ener)`.
#[allow(clippy::too_many_arguments)]
fn mr795_gain_code_quant_mod(
    gain_pit: i16,
    exp_gcode0: i16,
    gcode0: i16,
    frac_en: &[i16; 4],
    exp_en: &[i16; 4],
    alpha: i16,
    gain_cod_unq: i16,
    gain_cod: &mut i16,
) -> (i16, i16, i16) {
    let gain_code = shl(*gain_cod, sub(10, exp_gcode0)); // Q1 -> Q11(-ec0)
    let g2_pitch = mult(gain_pit, gain_pit); // Q14 -> Q13
    let one_alpha = add(sub(32767, alpha), 1); // 32768 - alpha

    let mut coeff = [0i16; 5];
    let mut coeff_lo = [0i16; 5];
    let mut exp_coeff = [0i16; 5];

    // c[1] (stored directly in a 32-bit accumulator; alpha<=0.5 → ×2, compensated in exponent)
    let tmp = extract_h(l_shl(l_mult(alpha, frac_en[1]), 1));
    let mut l_t1 = l_mult(tmp, g2_pitch);
    exp_coeff[1] = sub(exp_en[1], 15);

    // c[2]
    let tmp = extract_h(l_shl(l_mult(alpha, frac_en[2]), 1));
    coeff[2] = mult(tmp, gain_pit);
    let exp = sub(exp_gcode0, 10);
    exp_coeff[2] = add(exp_en[2], exp);

    // c[3]
    coeff[3] = extract_h(l_shl(l_mult(alpha, frac_en[3]), 1));
    let exp = sub(shl(exp_gcode0, 1), 7);
    exp_coeff[3] = add(exp_en[3], exp);

    // c[4]
    coeff[4] = mult(one_alpha, frac_en[3]);
    exp_coeff[4] = add(exp_coeff[3], 1);

    // c[0] = sqrt(alpha·<res res>)
    let l_tmp = l_mult(alpha, frac_en[0]);
    let mut exp = 0i16;
    let mut l_t0 = sqrt_l_exp(l_tmp, &mut exp);
    exp = add(exp, 47);
    exp_coeff[0] = sub(exp_en[0], exp);

    // find max(e[1..4], e[0]+31)
    let mut e_max = add(exp_coeff[0], 31);
    for &e in exp_coeff.iter().take(5).skip(1) {
        if sub(e, e_max) > 0 {
            e_max = e;
        }
    }

    // scale c[1] (no further multiplication)
    let tmp = sub(e_max, exp_coeff[1]);
    l_t1 = l_shr(l_t1, tmp);

    // scale c[2..4]
    for i in 2..=4 {
        let tmp = sub(e_max, exp_coeff[i]);
        let l_tmp = l_shr(l_deposit_h(coeff[i]), tmp);
        let (hi, lo) = l_extract(l_tmp);
        coeff[i] = hi;
        coeff_lo[i] = lo;
    }

    // scale c[0]; correct by 1/sqrt(2) if the exponent difference is odd
    let exp = sub(e_max, 31);
    let tmp = sub(exp, exp_coeff[0]);
    l_t0 = l_shr(l_t0, shr(tmp, 1));
    if (tmp & 0x1) != 0 {
        let (hi, lo) = l_extract(l_t0);
        coeff[0] = hi;
        coeff_lo[0] = lo;
        l_t0 = mpy_32_16(coeff[0], coeff_lo[0], 23170); // 1/sqrt(2) Q15
    }

    let mut dist_min = i32::MAX;
    let mut index = 0usize;
    for i in 0..NB_QUA_CODE {
        let g_code = mult(QUA_GAIN_CODE[3 * i], gcode0);
        // only continue while gc[i] < 2.0*gc
        if sub(g_code, gain_code) >= 0 {
            break;
        }

        let l_tmp = l_mult(g_code, g_code);
        let (g2_code_h, g2_code_l) = l_extract(l_tmp);

        let tmp = sub(g_code, gain_cod_unq);
        let (d2_code_h, d2_code_l) = l_extract(l_mult(tmp, tmp));

        // t2, t3, t4
        let l_tmp = mac_32_16(l_t1, coeff[2], coeff_lo[2], g_code);
        let l_tmp = mac_32(l_tmp, coeff[3], coeff_lo[3], g2_code_h, g2_code_l);

        let mut exp = 0i16;
        let l_tmp = sqrt_l_exp(l_tmp, &mut exp);
        let l_tmp = l_shr(l_tmp, shr(exp, 1));

        // d2 = (sqrt(aExEn) - t[0])^2
        let tmp = round_word(l_sub(l_tmp, l_t0));
        let l_tmp = l_mult(tmp, tmp);

        // dist = d1 + d2
        let l_tmp = mac_32(l_tmp, coeff[4], coeff_lo[4], d2_code_h, d2_code_l);

        if l_sub(l_tmp, dist_min) < 0 {
            dist_min = l_tmp;
            index = i;
        }
    }

    let p = 3 * index;
    let g_code = QUA_GAIN_CODE[p];
    let qua_ener_mr122 = QUA_GAIN_CODE[p + 1];
    let qua_ener = QUA_GAIN_CODE[p + 2];

    let l_tmp = l_mult(g_code, gcode0);
    let l_tmp = l_shr(l_tmp, sub(9, exp_gcode0));
    *gain_cod = extract_h(l_tmp);

    (index as i16, qua_ener_mr122, qua_ener)
}

/// `qgain795.c` `MR795_gain_quant` — full MR795 pitch + codebook gain quantization. Pre-quantizes
/// over three pitch candidates, computes the unfiltered energies + LTP coding gain, runs the gain
/// adaptor, and (unless the signal is very low energy or `alpha <= 0`) runs the modified codebook
/// gain quantizer. Returns `(gain_pit_index, gain_cod_index, qua_ener_mr122, qua_ener)`; writes the
/// quantized `gain_pit`/`gain_cod` in place.
#[allow(clippy::too_many_arguments)]
fn mr795_gain_quant(
    adapt_st: &mut GainAdaptState,
    res: &[i16],
    exc: &[i16],
    code: &[i16],
    frac_coeff: &[i16; 5],
    exp_coeff: &[i16; 5],
    exp_code_en: i16,
    frac_code_en: i16,
    exp_gcode0: i16,
    frac_gcode0: i16,
    cod_gain_frac: i16,
    cod_gain_exp: i16,
    gp_limit: i16,
    gain_pit: &mut i16,
    gain_cod: &mut i16,
) -> (i16, i16, i16, i16) {
    // candidate quantized pitch gains + indices (the returned index is discarded — quant3 picks the
    // emitted pitch-gain index from the candidates)
    let mut g_pitch_cand = [0i16; 3];
    let mut g_pitch_cind = [0i16; 3];
    let mut gain_pit_index =
        q_gain_pitch_mr795(gp_limit, gain_pit, &mut g_pitch_cand, &mut g_pitch_cind);

    // gcode0 (Q14) = 2^14 · 2^frac_gcode0
    let gcode0 = extract_l(pow2(14, frac_gcode0));

    let mut gain_cod_index = 0i16;
    let (mut qua_ener_mr122, mut qua_ener) = mr795_gain_code_quant3(
        exp_gcode0,
        gcode0,
        &g_pitch_cand,
        &g_pitch_cind,
        frac_coeff,
        exp_coeff,
        gain_pit,
        &mut gain_pit_index,
        gain_cod,
        &mut gain_cod_index,
    );

    // unfiltered energies + LTP coding gain, then the gain adaptor (also updates its state)
    let (mut frac_en, mut exp_en, ltpg) = calc_unfilt_energies(res, exc, code, *gain_pit);
    let alpha = gain_adapt(adapt_st, ltpg, *gain_cod);

    // skip the modified quantizer for very low energy signals or alpha <= 0
    if frac_en[0] != 0 && alpha > 0 {
        // innovation energy <cod cod> was already computed in gc_pred (overwrites LtpResEn)
        frac_en[3] = frac_code_en;
        exp_en[3] = exp_code_en;

        // optimum codebook gain in Q(10-exp_gcode0)
        let exp = add(sub(cod_gain_exp, exp_gcode0), 10);
        let gain_cod_unq = shl(cod_gain_frac, exp);

        let (idx, qe122, qe) = mr795_gain_code_quant_mod(
            *gain_pit,
            exp_gcode0,
            gcode0,
            &frac_en,
            &exp_en,
            alpha,
            gain_cod_unq,
            gain_cod,
        );
        gain_cod_index = idx;
        qua_ener_mr122 = qe122;
        qua_ener = qe;
    }

    (gain_pit_index, gain_cod_index, qua_ener_mr122, qua_ener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mr122_gain_quant_runs_and_advances_predictor() {
        // MR122 standard path: G_code + q_gain_code. Sanity: index in range, predictor advanced.
        let mut st = GainQuantState::new();
        let before = st.gc_pred.past_qua_en;
        let code = [40i16; L_SUBFR];
        let xn2 = [100i16; L_SUBFR];
        let y2 = [200i16; L_SUBFR];
        let g_coeff = [1000i16, 5, 800, 6];
        let mut gain_pit = 8192i16;
        let res = [0i16; L_SUBFR];
        let exc = [0i16; L_SUBFR];
        let xn = [50i16; L_SUBFR];
        let y1 = [60i16; L_SUBFR];
        let out = gain_quant(
            &mut st,
            AmrNbMode::Mr1220,
            &res,
            &exc,
            &code,
            &xn,
            &xn2,
            &y1,
            &y2,
            &g_coeff,
            1,
            i16::MAX,
            &mut gain_pit,
        )
        .expect("MR122 gain quant");
        assert_eq!(out.num_params, 1);
        assert!(out.params[0] >= 0 && (out.params[0] as usize) < NB_QUA_CODE);
        assert_ne!(st.gc_pred.past_qua_en, before);
    }

    #[test]
    fn mr475_even_defers_odd_emits_joint_index() {
        // MR475: even subframe emits nothing (num_params == 0); the following odd subframe emits a
        // single joint index and returns both subframes' quantized gains.
        let mut st = GainQuantState::new();
        let code = [20i16; L_SUBFR];
        let xn = [80i16; L_SUBFR];
        let xn2 = [70i16; L_SUBFR];
        let y1 = [60i16; L_SUBFR];
        let y2 = [500i16; L_SUBFR];
        let g_coeff = [2000i16, 6, 1500, 7];
        let res = [0i16; L_SUBFR];
        let exc = [0i16; L_SUBFR];
        let mut gain_pit = 8192i16;

        let even = gain_quant(
            &mut st,
            AmrNbMode::Mr475,
            &res,
            &exc,
            &code,
            &xn,
            &xn2,
            &y1,
            &y2,
            &g_coeff,
            1,
            i16::MAX,
            &mut gain_pit,
        )
        .expect("MR475 even");
        assert_eq!(even.num_params, 0, "even subframe transmits no gain index");

        let odd = gain_quant(
            &mut st,
            AmrNbMode::Mr475,
            &res,
            &exc,
            &code,
            &xn,
            &xn2,
            &y1,
            &y2,
            &g_coeff,
            0,
            i16::MAX,
            &mut gain_pit,
        )
        .expect("MR475 odd");
        assert_eq!(odd.num_params, 1, "odd subframe transmits the joint index");
        assert!(odd.params[0] >= 0 && (odd.params[0] as usize) < MR475_VQ_SIZE);
    }

    #[test]
    fn mr795_emits_two_gain_params_and_advances_predictor() {
        // MR795 emits TWO gain indices (pitch-gain then code-gain); the pitch index is a valid
        // QUA_GAIN_PITCH slot and the code index a valid QUA_GAIN_CODE slot, and the predictor moves.
        let mut st = GainQuantState::new();
        let before = st.gc_pred.past_qua_en;
        let code = [40i16; L_SUBFR];
        let xn2 = [100i16; L_SUBFR];
        let y2 = [200i16; L_SUBFR];
        let g_coeff = [1000i16, 5, 800, 6];
        let res = [30i16; L_SUBFR];
        let exc = [25i16; L_SUBFR];
        let xn = [50i16; L_SUBFR];
        let y1 = [60i16; L_SUBFR];
        let mut gain_pit = 8192i16;
        let out = gain_quant(
            &mut st,
            AmrNbMode::Mr795,
            &res,
            &exc,
            &code,
            &xn,
            &xn2,
            &y1,
            &y2,
            &g_coeff,
            0,
            i16::MAX,
            &mut gain_pit,
        )
        .expect("MR795 gain quant");
        assert_eq!(out.num_params, 2, "MR795 transmits two gain indices");
        assert!(out.params[0] >= 0 && (out.params[0] as usize) < NB_QUA_PITCH);
        assert!(out.params[1] >= 0 && (out.params[1] as usize) < NB_QUA_CODE);
        assert_ne!(st.gc_pred.past_qua_en, before);
    }

    #[test]
    fn mac_32_16_matches_reference_decomposition() {
        // Mac_32_16(acc, hi, lo, n) == L_mac(L_mac(acc, hi, n), mult(lo, n), 1).
        let acc = 123_456i32;
        let (hi, lo, n) = (1234i16, -567i16, 890i16);
        let expected = l_mac(l_mac(acc, hi, n), mult(lo, n), 1);
        assert_eq!(mac_32_16(acc, hi, lo, n), expected);
    }

    // ---------------------------------------------------------------------------------------------
    // Oracle gate: replay the instrumented 3GPP reference `gainQuant` INPUTS/OUTPUTS captured per
    // subframe (T01.INP, MR122 & MR475) and assert bit-exactness of gain_pit, gain_code and the
    // transmitted gain index/indices across *every* subframe of *every* frame. gc_pred state
    // carries across subframes, so the gate seeds the predictor once (at the reference reset value)
    // and threads GainQuantState — the per-call dumped gc_pred is a cross-check if drift appears.
    // Skips when the (scratch, gitignored) dump is absent, exactly like the tier-3 cl-ltp gate.
    // ---------------------------------------------------------------------------------------------

    /// One instrumented subframe: gainQuant inputs + the reference's quantized outputs.
    struct GainRecord {
        even: i16,
        gp_limit: i16,
        gain_pit_in: i16,
        gc_pred: [i16; 4],
        gc_pred_mr122: [i16; 4],
        code: [i16; L_SUBFR],
        xn: [i16; L_SUBFR],
        xn2: [i16; L_SUBFR],
        y1: [i16; L_SUBFR],
        y2: [i16; L_SUBFR],
        g_coeff: [i16; 4],
        out_gain_pit: i16,
        out_gain_code: i16,
        out_gain_pit_sf0: i16,
        out_gain_code_sf0: i16,
        nidx: usize,
        joint_idx: i16,
        idx: Vec<i16>,
    }

    fn parse_vec40(line: &str) -> [i16; L_SUBFR] {
        let mut v = [0i16; L_SUBFR];
        for (slot, tok) in v.iter_mut().zip(line.split_whitespace().skip(1)) {
            *slot = tok.parse().expect("i16 token");
        }
        v
    }

    fn parse_vec4(line: &str) -> [i16; 4] {
        let mut v = [0i16; 4];
        for (slot, tok) in v.iter_mut().zip(line.split_whitespace().skip(1)) {
            *slot = tok.parse().expect("i16 token");
        }
        v
    }

    fn parse_gain_dump(text: &str) -> Vec<GainRecord> {
        let mut records = Vec::new();
        let mut lines = text.lines().peekable();
        while let Some(line) = lines.next() {
            if !line.starts_with("SF ") {
                continue;
            }
            // SF even=E gp_limit=G gain_pit_in=P
            let mut even = 0i16;
            let mut gp_limit = 0i16;
            let mut gain_pit_in = 0i16;
            for tok in line.split_whitespace().skip(1) {
                if let Some(v) = tok.strip_prefix("even=") {
                    even = v.parse().unwrap();
                } else if let Some(v) = tok.strip_prefix("gp_limit=") {
                    gp_limit = v.parse().unwrap();
                } else if let Some(v) = tok.strip_prefix("gain_pit_in=") {
                    gain_pit_in = v.parse().unwrap();
                }
            }
            let gc_pred = parse_vec4(lines.next().unwrap());
            let gc_pred_mr122 = parse_vec4(lines.next().unwrap());
            let _res = parse_vec40(lines.next().unwrap());
            let _exc = parse_vec40(lines.next().unwrap());
            let code = parse_vec40(lines.next().unwrap());
            let xn = parse_vec40(lines.next().unwrap());
            let xn2 = parse_vec40(lines.next().unwrap());
            let y1 = parse_vec40(lines.next().unwrap());
            let y2 = parse_vec40(lines.next().unwrap());
            let g_coeff = parse_vec4(lines.next().unwrap());
            let out = lines.next().unwrap();
            // OUT gain_pit=.. gain_code=.. gain_pit_sf0=.. gain_code_sf0=.. nidx=.. joint_idx=.. [idx..]
            let mut out_gain_pit = 0i16;
            let mut out_gain_code = 0i16;
            let mut out_gain_pit_sf0 = 0i16;
            let mut out_gain_code_sf0 = 0i16;
            let mut nidx = 0usize;
            let mut joint_idx = -1i16;
            let mut idx = Vec::new();
            let mut seen_joint = false;
            for tok in out.split_whitespace().skip(1) {
                if let Some(v) = tok.strip_prefix("gain_pit=") {
                    out_gain_pit = v.parse().unwrap();
                } else if let Some(v) = tok.strip_prefix("gain_code=") {
                    out_gain_code = v.parse().unwrap();
                } else if let Some(v) = tok.strip_prefix("gain_pit_sf0=") {
                    out_gain_pit_sf0 = v.parse().unwrap();
                } else if let Some(v) = tok.strip_prefix("gain_code_sf0=") {
                    out_gain_code_sf0 = v.parse().unwrap();
                } else if let Some(v) = tok.strip_prefix("nidx=") {
                    nidx = v.parse().unwrap();
                } else if let Some(v) = tok.strip_prefix("joint_idx=") {
                    joint_idx = v.parse().unwrap();
                    seen_joint = true;
                } else if seen_joint {
                    idx.push(tok.parse().unwrap());
                }
            }
            records.push(GainRecord {
                even,
                gp_limit,
                gain_pit_in,
                gc_pred,
                gc_pred_mr122,
                code,
                xn,
                xn2,
                y1,
                y2,
                g_coeff,
                out_gain_pit,
                out_gain_code,
                out_gain_pit_sf0,
                out_gain_code_sf0,
                nidx,
                joint_idx,
                idx,
            });
        }
        records
    }

    /// Replay the whole dump sequentially, threading one `GainQuantState`, asserting every output.
    /// Returns the number of subframes compared, or `None` if the dump is absent (skip).
    fn run_gain_gate(dump_path: &str, mode: AmrNbMode) -> Option<usize> {
        let text = std::fs::read_to_string(dump_path).ok()?;
        let records = parse_gain_dump(&text);
        assert!(!records.is_empty(), "empty gain dump: {dump_path}");

        let mut st = GainQuantState::new();
        let res = [0i16; L_SUBFR];
        let exc = [0i16; L_SUBFR];
        // Canonical predictor reset tuple (gc_pred_reset): the encoder-homing frame resets the
        // predictor AFTER coding (Speech_Encode_Frame homing), so the reference's pre-call state
        // snaps back to these minima at the frame following a homing frame.
        let reset_en = GcPredState::new().past_qua_en;
        let reset_en_mr122 = GcPredState::new().past_qua_en_mr122;

        for (n, rec) in records.iter().enumerate() {
            // Honor the reference's encoder-homing reset: when the dumped pre-call predictor is the
            // canonical reset tuple but our threaded state isn't, a homing reset happened between
            // frames — re-seed and continue (tier 6 owns this reset). Otherwise the threaded state
            // MUST equal the reference's — any divergence is real gain_quant drift.
            let is_reset = rec.gc_pred == reset_en && rec.gc_pred_mr122 == reset_en_mr122;
            if is_reset
                && (st.gc_pred.past_qua_en != reset_en
                    || st.gc_pred.past_qua_en_mr122 != reset_en_mr122)
            {
                st = GainQuantState::new();
            }
            assert_eq!(
                st.gc_pred.past_qua_en, rec.gc_pred,
                "gc_pred (20log10) drift before subframe #{n}"
            );
            assert_eq!(
                st.gc_pred.past_qua_en_mr122, rec.gc_pred_mr122,
                "gc_pred (log2) drift before subframe #{n}"
            );

            let mut gain_pit = rec.gain_pit_in;
            let out = gain_quant(
                &mut st,
                mode,
                &res,
                &exc,
                &rec.code,
                &rec.xn,
                &rec.xn2,
                &rec.y1,
                &rec.y2,
                &rec.g_coeff,
                rec.even,
                rec.gp_limit,
                &mut gain_pit,
            )
            .unwrap_or_else(|e| panic!("subframe #{n}: {e}"));

            assert_eq!(
                out.gain_pit, rec.out_gain_pit,
                "gain_pit mismatch at subframe #{n}"
            );
            assert_eq!(
                out.gain_cod, rec.out_gain_code,
                "gain_code mismatch at subframe #{n}"
            );

            if mode == AmrNbMode::Mr475 {
                if rec.even != 0 {
                    // Even subframe defers: nothing transmitted (the reference reserves the slot).
                    assert_eq!(
                        out.num_params, 0,
                        "MR475 even should defer at subframe #{n}"
                    );
                } else {
                    // Odd subframe emits the joint index (into the reserved slot) + both gains.
                    assert_eq!(out.num_params, 1, "MR475 odd should emit at subframe #{n}");
                    assert_eq!(
                        out.params[0], rec.joint_idx,
                        "MR475 joint index mismatch at subframe #{n}"
                    );
                    assert_eq!(
                        out.sf0_gain_pit, rec.out_gain_pit_sf0,
                        "MR475 sf0 gain_pit mismatch at subframe #{n}"
                    );
                    assert_eq!(
                        out.sf0_gain_cod, rec.out_gain_code_sf0,
                        "MR475 sf0 gain_code mismatch at subframe #{n}"
                    );
                }
            } else {
                // Standard path: exactly one index, matching the reference's ana slot.
                assert_eq!(
                    out.num_params, 1,
                    "standard path emits 1 index at subframe #{n}"
                );
                assert_eq!(rec.nidx, 1, "reference wrote 1 index at subframe #{n}");
                assert_eq!(
                    out.params[0], rec.idx[0],
                    "gain index mismatch at subframe #{n}"
                );
            }
        }
        Some(records.len())
    }

    #[test]
    fn gain_quant_bit_exact_mr122_oracle() {
        match run_gain_gate("/tmp/amr-nb-oracle-t5/gain_122.txt", AmrNbMode::Mr1220) {
            Some(n) => {
                assert!(n > 100, "expected many subframes, got {n}");
                eprintln!("MR122 gain gate: {n} subframes bit-exact");
            }
            None => eprintln!("MR122 gain oracle dump absent — skipping gain gate"),
        }
    }

    #[test]
    fn gain_quant_bit_exact_mr475_oracle() {
        match run_gain_gate("/tmp/amr-nb-oracle-t5/gain_475.txt", AmrNbMode::Mr475) {
            Some(n) => {
                assert!(n > 100, "expected many subframes, got {n}");
                eprintln!("MR475 gain gate: {n} subframes bit-exact");
            }
            None => eprintln!("MR475 gain oracle dump absent — skipping gain gate"),
        }
    }
}
